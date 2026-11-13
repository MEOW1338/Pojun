package db

import (
	"database/sql"
	"errors"
	"time"
)

// 自主推进（Autopilot）的持久层：开关、deadline 自动延长计数、事件留痕。
// 设计见 docs/自主推进.md / 计划文件。这里只放纯 SQL，判定逻辑在 server/autopilot.go。

// AutopilotTaskState 是一次看门狗扫描需要的全部信号（单条查询，避免 N×3 次往返）。
type AutopilotTaskState struct {
	TaskID         string
	IdleRounds     int
	LastRoundAt    time.Time // task_progress 最近一次规划轮时间；无记录时=任务创建时间
	Facts          int64
	Findings       int64
	Assets         int64 // 任务关联资产数（看门狗用「新资产/新漏洞」而不是纯事实数判进展）
	GoalsTotal     int
	GoalsMet       int
	OpenIntents    int
	RunningIntents int
}

// Unmet 表示目标尚未全部达成；total=0 视为未达成（还没有目标，不能算完成）。
func (s AutopilotTaskState) Unmet() bool { return s.GoalsMet < s.GoalsTotal || s.GoalsTotal == 0 }

// AutopilotTaskStates 扫描全部「自主推进中」的任务。只回有 autopilot 标记、
// 正在运行、未暂停未排队、未删除的任务——与看门狗候选条件保持一致。
func (d *DB) AutopilotTaskStates() (map[string]AutopilotTaskState, error) {
	rows, err := d.Query(`
SELECT t.id::text,
       COALESCE(p.idle_rounds,0),
       COALESCE(p.updated_at, t.created_at),
       COALESCE(p.fact_count,0),
       COALESCE(p.finding_count,0),
       COALESCE(a.cnt,0),
       COALESCE(g.total,0), COALESCE(g.met,0),
       COALESCE(i.open,0), COALESCE(i.running,0)
FROM tasks t
LEFT JOIN task_progress p ON p.task_id = t.id::text
LEFT JOIN LATERAL (
    SELECT count(*) AS cnt FROM task_asset_links l WHERE l.task_id = t.id
) a ON true
LEFT JOIN LATERAL (
    SELECT count(*) AS total, count(*) FILTER (WHERE n.state='met') AS met
    FROM exploration_nodes n
    WHERE n.exploration_id = t.exploration_id AND n.kind='goal'
) g ON true
LEFT JOIN LATERAL (
    SELECT count(*) FILTER (WHERE n.state='open')    AS open,
           count(*) FILTER (WHERE n.state='running') AS running
    FROM exploration_nodes n
    WHERE n.exploration_id = t.exploration_id AND n.kind='intent'
) i ON true
WHERE t.deleted_at IS NULL AND t.autopilot
  AND t.status='running' AND NOT t.paused AND NOT t.queued`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]AutopilotTaskState{}
	for rows.Next() {
		var s AutopilotTaskState
		if err := rows.Scan(&s.TaskID, &s.IdleRounds, &s.LastRoundAt, &s.Facts, &s.Findings, &s.Assets,
			&s.GoalsTotal, &s.GoalsMet, &s.OpenIntents, &s.RunningIntents); err != nil {
			return nil, err
		}
		out[s.TaskID] = s
	}
	return out, rows.Err()
}

// SetTaskAutopilot 持久化单任务开关。
func (d *DB) SetTaskAutopilot(id int64, on bool) error {
	res, err := d.Exec(`UPDATE tasks SET autopilot=$2 WHERE id=$1 AND deleted_at IS NULL`, id, on)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ExtendTaskDeadline 在「仍在跑、未暂停、autopilot、延长次数未用尽」的守卫下
// 把 deadline 推后 seconds 秒并累加计数。返回新 deadline、已用次数、是否成功。
//
// 用单条 guarded UPDATE 而不是先读后写：重启后旧协调器与新协调器可能同时到期，
// 只有一条能成功，避免同一任务被延长两次。
func (d *DB) ExtendTaskDeadline(id int64, seconds int, maxExtensions int) (time.Time, int, bool, error) {
	if seconds <= 0 || maxExtensions <= 0 {
		return time.Time{}, 0, false, nil
	}
	var deadline time.Time
	var used int
	// GREATEST(deadline_at, now())：只在原 deadline 基础上往后加，不能把还剩
	// 30 分钟的预算重置成 now+15。旧实现用 now()+ext，worker 的 TaskClock 在
	// run 启动时快照，deadline 被重置后会提前把长链掐断（实测大量「运行超时」）。
	err := d.QueryRow(`
UPDATE tasks
SET deadline_at = GREATEST(deadline_at, now()) + make_interval(secs => $2::double precision),
    autopilot_extensions = autopilot_extensions + 1
WHERE id=$1 AND deleted_at IS NULL AND status='running' AND NOT paused
  AND autopilot AND autopilot_extensions < $3
RETURNING deadline_at, autopilot_extensions`, id, float64(seconds), maxExtensions).Scan(&deadline, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, 0, false, nil
	}
	if err != nil {
		return time.Time{}, 0, false, err
	}
	return deadline, used, true, nil
}

// AutopilotEvent 是自主推进的决策留痕（任务详情页/排障用）。
type AutopilotEvent struct {
	ID        int64     `json:"id"`
	TaskID    string    `json:"task_id"`
	Kind      string    `json:"kind"`
	Detail    string    `json:"detail"`
	CreatedAt time.Time `json:"created_at"`
}

// InsertAutopilotEvent 写入一条事件。失败不阻断主流程（调用方只记日志）。
func (d *DB) InsertAutopilotEvent(taskID, kind, detail string) error {
	_, err := d.Exec(`INSERT INTO autopilot_events(task_id,kind,detail) VALUES($1,$2,$3)`,
		taskID, kind, detail)
	return err
}

// ListAutopilotEvents 按时间倒序读取某任务的事件。
func (d *DB) ListAutopilotEvents(taskID string, limit int) ([]AutopilotEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := d.Query(`SELECT id, task_id, kind, detail, created_at
FROM autopilot_events WHERE task_id=$1 ORDER BY id DESC LIMIT $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AutopilotEvent
	for rows.Next() {
		var e AutopilotEvent
		if err := rows.Scan(&e.ID, &e.TaskID, &e.Kind, &e.Detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DeleteAutopilotEvents 任务硬删除时清理。
func (d *DB) DeleteAutopilotEvents(taskID string) error {
	_, err := d.Exec(`DELETE FROM autopilot_events WHERE task_id=$1`, taskID)
	return err
}
