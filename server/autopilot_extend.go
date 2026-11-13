package server

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/db"
)

// autopilot 目标续杯（v0.6.7）。
//
// 现网问题（2026-11-07 任务 #5）：8 条目标被 planner 逐个 prove_goal 后，
// goal_met 触发 settle，任务 2 小时就 done——虽然还有 47 个范围内资产没测、
// 4 条 high 漏洞只做到「验证存在」没有取数/影响证明。自主推进的本意是
// 「一直打到没得打」，而不是「把这批固定目标打完就收」。
//
// 续杯规则（全部满足才续）：
//  1. 任务开着 autopilot，且 `autopilot_extend_waves`（默认 3，0=关闭）没用完；
//  2. deadline 还没到（留 5 分钟余量）；
//  3. 确有活可干：范围内还有未测资产，或已登记 high/critical 漏洞。
//
// 续杯动作：自动追加 1–2 条下一层目标（覆盖未测资产 / 高危利用链与影响证明），
// 挂到任务根下并唤醒 planner；本轮不取消在跑 worker、不 settle。
const (
	settingAutopilotExtendWaves  = "autopilot_extend_waves"
	defaultAutopilotExtendWaves  = 10
	autopilotExtendDeadlineGrace = 5 * time.Minute
)

func (e *Engine) maybeExtendAutopilot(t *Task) bool {
	if t == nil || !t.AutopilotEnabled() || e.m.pg == nil {
		return false
	}
	pg := e.m.pg
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	waves, ok := settingInt(pg, settingAutopilotExtendWaves)
	if !ok {
		waves = defaultAutopilotExtendWaves
	}
	if waves <= 0 || waves > 10 {
		if waves <= 0 {
			return false
		}
		waves = 10
	}
	waveKey := fmt.Sprintf("autopilot_wave_%d", taskID)
	used, _ := settingInt(pg, waveKey)
	if used >= waves {
		return false
	}
	if dl := t.lifecycleSnapshot().DeadlineAt; dl > 0 && time.Now().Add(autopilotExtendDeadlineGrace).Unix() >= dl {
		return false
	}

	untested := 0
	if e.m.assets != nil {
		if _, total, err := e.m.assets.ListUntestedAssetsWithSources(taskID, "", 1, 0); err == nil {
			untested = total
		}
	}
	var highFindings int
	_ = pg.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1 AND severity IN ('critical','high')`, taskID).Scan(&highFindings)
	if untested == 0 && highFindings == 0 {
		return false
	}

	// 进度闸：上一波续杯之后没有新增 fact/finding，说明「续了也没产出」，不再续——
	// 这是「不达目的不罢休」与「无限空转」的分界线（用户既要不设预算，也不要原地打转）。
	var facts, findings int
	_ = pg.QueryRow(`SELECT
	  (SELECT count(*) FROM exploration_nodes WHERE kind='fact' AND exploration_id=(SELECT exploration_id FROM tasks WHERE id=$1)),
	  (SELECT count(*) FROM findings WHERE task_id=$1)`, taskID).Scan(&facts, &findings)
	markKey := fmt.Sprintf("autopilot_ext_mark_%d", taskID)
	mark := fmt.Sprintf("f%d|n%d", facts, findings)
	// 进度闸只在「没有未测资产」时启用：只要范围内还有没测过的资产，就属于
	// 「还有一点能做的」——用户要求继续做（哪怕上一波没产出，也只说明打法不对，
	// 应该换打法而不是收工）。高危漏洞本身不会因时间消失，所以不能单靠它续杯。
	if used > 0 && untested == 0 {
		if prev, ok, _ := pg.GetSetting(markKey); ok && prev == mark {
			return false
		}
	}
	_ = pg.SetSetting(markKey, mark)

	// 续杯阶梯：每次续杯推进一层，避免反复加同一条「高危利用链」目标后又被判完成。
	ladder := []string{
		"对已登记的高危/严重漏洞完成利用链与影响面证明：不破坏业务的前提下做取数/权限提升/横向可达性验证，每条补一份影响证明（请求-响应或命令输出 + 影响描述）",
		"把已撕开的数据面打到最大：对已证明可达的接口做分页/时间窗/导出全量取证（只读、限速、逐批落盘并登记哈希）",
		"同族扩散：把已验证的机理应用到同集群/同框架/同批次的其他资产（同 C 段、同分发域、同后台模板），逐条验证并出报告",
		"未覆盖面清零：对范围内仍未测试的资产按漏洞矩阵逐类补测（未授权/越权/SQLi/XSS/SSRF/上传/命令执行/弱口令/CVE/逻辑）",
		"深挖已确认入口的下一层：从当前权限/凭据出发尝试横向、持久化可达性与更高价值数据（授权边界内，只读优先）",
	}
	stage := ladder[len(ladder)-1]
	if used < len(ladder) {
		stage = ladder[used]
	}
	txt := fmt.Sprintf("%s（续杯第 %d 波：已登记高危 %d 条、未测资产 %d 个）", stage, used+1, highFindings, untested)
	texts := []string{txt}

	of, _ := t.Store.OriginFactID()
	added := 0
	for _, txt := range texts {
		id, err := t.Store.AddGoal(map[string]any{"text": txt}, "autopilot")
		if err != nil {
			log.Printf("[autopilot] task %d 续杯目标写入失败: %v", taskID, err)
			continue
		}
		if of > 0 && id > 0 {
			_ = t.Store.Link(of, db.RelSpawns, id)
		}
		added++
	}
	if added == 0 {
		return false
	}
	_ = pg.SetSetting(waveKey, fmt.Sprintf("%d", used+1))
	_ = pg.InsertAutopilotEvent(t.ID, "extend_goals",
		fmt.Sprintf("目标达成后续杯第 %d/%d 波：未测资产 %d，高危漏洞 %d，追加 %d 条下一层目标",
			used+1, waves, untested, highFindings, added))
	t.NotifyGoal(texts)
	log.Printf("[autopilot] task %d 目标达成 → 续杯第 %d/%d 波（未测资产 %d，高危 %d，新增目标 %d 条）",
		taskID, used+1, waves, untested, highFindings, added)
	return true
}

// autopilotRelentlessFromPG 读「不达目的不罢休」开关（默认开）。
// 开：worker 不设单轮墙钟预算、不挂无增量收场、不注入意图 token 预算提醒；
// autopilot 的 auto_rounds 收尾也被抑制，goal_met 时只要还有活就自动续杯。
func autopilotRelentlessFromPG(pg interface {
	GetSetting(string) (string, bool, error)
}) bool {
	if pg == nil {
		return true
	}
	v, ok, err := pg.GetSetting("autopilot_relentless")
	if err != nil || !ok {
		return true
	}
	return v != "false" && v != "0"
}

// autopilotIntentMaxHoursFromPG 读单意图兜底墙钟（小时，默认 0=不限）。
// relentless 取消了所有“没进展”闸门；需要限时的任务可在设置里显式配置。
func autopilotIntentMaxHoursFromPG(pg interface {
	GetSetting(string) (string, bool, error)
}) int {
	if pg == nil {
		return 0
	}
	v, ok, err := pg.GetSetting("autopilot_intent_max_hours")
	if err != nil || !ok {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return 0
	}
	if n > 24 {
		return 24
	}
	return n
}

// autopilotExtendWavesFromPG 读续杯波次上限（默认 10，0=关闭）。
func autopilotExtendWavesFromPG(pg *db.DB) int {
	if n, ok := settingInt(pg, settingAutopilotExtendWaves); ok {
		if n < 0 {
			return 0
		}
		if n > 10 {
			return 10
		}
		return n
	}
	return defaultAutopilotExtendWaves
}

// autopilotExtendWave 读当前已用波次（供管理面/调试）。
func (e *Engine) autopilotExtendWave(taskID int64) int {
	n, _ := settingInt(e.m.pg, fmt.Sprintf("autopilot_wave_%d", taskID))
	return n
}
