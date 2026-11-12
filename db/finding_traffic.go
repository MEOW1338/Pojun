package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/notify"
)

var (
	ErrEvidenceConflict = errors.New("流量证据已变更，请刷新后重试")
	ErrFindingNotFound  = errors.New("漏洞不存在")
	ErrEvidenceNotFound = errors.New("流量证据不存在")
)

// This lock covers the evidence filesystem as well as its SQL references. All
// processes sharing the database use it, including readers, exports and GC.
const findingEvidenceLockKey int64 = 7337741004

func (d *DB) WithEvidenceTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, findingEvidenceLockKey); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

type TrafficRef struct {
	TrafficID string `json:"traffic_id"`
	Role      string `json:"role"`
	Note      string `json:"note"`
}

func NormalizeTrafficRefs(refs []TrafficRef) ([]TrafficRef, error) {
	out := make([]TrafficRef, 0, len(refs))
	seen := map[string]bool{}
	for _, ref := range refs {
		ref.TrafficID = strings.TrimSpace(ref.TrafficID)
		if ref.TrafficID == "" {
			return nil, errors.New("traffic_id 不能为空")
		}
		if ref.Role == "" {
			ref.Role = "supporting"
		}
		if !ValidTrafficRole(ref.Role) {
			return nil, fmt.Errorf("无效的流量用途 %q", ref.Role)
		}
		if !seen[ref.TrafficID] {
			out = append(out, ref)
			seen[ref.TrafficID] = true
		}
	}
	return out, nil
}

func ValidTrafficRole(role string) bool {
	return role == "baseline" || role == "proof" || role == "verification" || role == "supporting"
}

type TrafficEvidenceSnapshot struct {
	ID              string    `json:"id"`
	SourceTrafficID string    `json:"source_traffic_id"`
	CapturedAt      int64     `json:"captured_at"`
	URL             string    `json:"url"`
	Method          string    `json:"method"`
	Status          int       `json:"status"`
	ContentType     string    `json:"content_type"`
	ReqHead         string    `json:"req_head,omitempty"`
	RespHead        string    `json:"resp_head,omitempty"`
	ReqHash         string    `json:"req_hash"`
	RespHash        string    `json:"resp_hash"`
	ReqLen          int64     `json:"req_len"`
	RespLen         int64     `json:"resp_len"`
	CreatedAt       time.Time `json:"created_at"`
}

type FindingTrafficBinding struct {
	ID         int64                   `json:"id,string"`
	FindingID  int64                   `json:"finding_id,string"`
	SnapshotID string                  `json:"snapshot_id"`
	Role       string                  `json:"role"`
	Note       string                  `json:"note"`
	Position   int                     `json:"position"`
	CreatedAt  time.Time               `json:"created_at"`
	Snapshot   TrafficEvidenceSnapshot `json:"snapshot"`
}

type FindingTraffic struct {
	FindingID     int64                   `json:"finding_id,string"`
	Version       int64                   `json:"version"`
	ReportVersion int64                   `json:"report_version"`
	Bindings      []FindingTrafficBinding `json:"bindings"`
	// SkippedRefs 是本次请求里无法解析的流量引用。绑定是尽力而为:有效的
	// 照常挂上,无效的记在这里,已有的绑定不受影响。
	SkippedRefs []TrafficRef `json:"skipped_traffic_refs,omitempty"`
}

type PreparedTrafficEvidence struct {
	Ref      TrafficRef
	Snapshot TrafficEvidenceSnapshot
}

// Normalize makes the snapshot's text columns safe for PostgreSQL. URL and the
// head blocks come straight off the wire, so a target answering with a non-UTF-8
// header (a GBK `Content-Disposition: filename=…`, a NUL byte) would otherwise
// abort the INSERT and roll back the whole finding — losing a confirmed finding
// over a malformed response header. Applied before hashing so the ID always
// matches the bytes that actually land in the table.
func (s TrafficEvidenceSnapshot) Normalize() TrafficEvidenceSnapshot {
	s.SourceTrafficID = utf8Clean(s.SourceTrafficID)
	s.URL = utf8Clean(s.URL)
	s.Method = utf8Clean(s.Method)
	s.ContentType = utf8Clean(s.ContentType)
	s.ReqHead = utf8Clean(s.ReqHead)
	s.RespHead = utf8Clean(s.RespHead)
	return s
}

func TrafficSnapshotID(snapshot TrafficEvidenceSnapshot) string {
	snapshot = snapshot.Normalize()
	snapshot.ID = ""
	snapshot.CreatedAt = time.Time{}
	raw, _ := json.Marshal(snapshot)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// LockTaskEvidenceTx serializes writes with archive queueing (which locks the
// same task row). Once queued, its snapshot must not acquire new evidence.
func LockTaskEvidenceTx(tx *sql.Tx, taskID int64) error {
	if taskID == 0 {
		return nil
	}
	var deleted sql.NullTime
	if err := tx.QueryRow(`SELECT deleted_at FROM tasks WHERE id=$1 FOR UPDATE`, taskID).Scan(&deleted); err != nil {
		return err
	}
	if deleted.Valid {
		return ErrTaskArchiveState
	}
	var state string
	err := tx.QueryRow(`SELECT state FROM task_archives WHERE task_id=$1`, taskID).Scan(&state)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && state != ArchiveFailed {
		return ErrTaskArchiveState
	}
	return nil
}

func LockFindingEvidenceTx(tx *sql.Tx, findingID int64, version *int64) error {
	var taskID sql.NullInt64
	if err := tx.QueryRow(`SELECT task_id FROM findings WHERE id=$1`, findingID).Scan(&taskID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFindingNotFound
		}
		return err
	}
	if err := LockTaskEvidenceTx(tx, taskID.Int64); err != nil {
		return err
	}
	var current int64
	if err := tx.QueryRow(`SELECT evidence_version FROM findings WHERE id=$1 FOR UPDATE`, findingID).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFindingNotFound
		}
		return err
	}
	if version != nil && *version != current {
		return ErrEvidenceConflict
	}
	return nil
}

func InsertEvidenceSnapshotTx(tx *sql.Tx, s TrafficEvidenceSnapshot) error {
	if s.ID != TrafficSnapshotID(s) {
		return errors.New("证据快照元数据哈希不匹配")
	}
	// The ID was computed over the normalized form; store those same bytes.
	id := s.ID
	s = s.Normalize()
	s.ID = id
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	_, err := tx.Exec(`INSERT INTO traffic_evidence_snapshots
(id,source_traffic_id,captured_at,url,method,status,content_type,req_head,resp_head,req_hash,resp_hash,req_len,resp_len,created_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(id) DO NOTHING`,
		s.ID, s.SourceTrafficID, s.CapturedAt, s.URL, s.Method, s.Status, s.ContentType, s.ReqHead, s.RespHead, s.ReqHash, s.RespHash, s.ReqLen, s.RespLen, s.CreatedAt)
	return err
}

func AddFindingTrafficTx(tx *sql.Tx, findingID int64, prepared []PreparedTrafficEvidence) error {
	var position int
	if err := tx.QueryRow(`SELECT COALESCE(MAX(position)+1,0) FROM finding_traffic_bindings WHERE finding_id=$1`, findingID).Scan(&position); err != nil {
		return err
	}
	changed := false
	for _, item := range prepared {
		if err := InsertEvidenceSnapshotTx(tx, item.Snapshot); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE traffic_evidence_snapshots SET unreferenced_at=NULL WHERE id=$1`, item.Snapshot.ID); err != nil {
			return err
		}
		res, err := tx.Exec(`INSERT INTO finding_traffic_bindings(finding_id,snapshot_id,role,note,position)
VALUES($1,$2,$3,$4,$5) ON CONFLICT(finding_id,snapshot_id) DO NOTHING`, findingID, item.Snapshot.ID, item.Ref.Role, item.Ref.Note, position)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n > 0 {
			changed = true
			position++
		}
	}
	if changed {
		return bumpEvidenceVersionTx(tx, findingID)
	}
	return nil
}

func bumpEvidenceVersionTx(tx *sql.Tx, findingID int64) error {
	_, err := tx.Exec(`UPDATE findings SET evidence_version=evidence_version+1 WHERE id=$1`, findingID)
	return err
}

func FindingTrafficTx(tx *sql.Tx, findingID int64) (*FindingTraffic, error) {
	out := &FindingTraffic{FindingID: findingID, Bindings: []FindingTrafficBinding{}}
	if err := tx.QueryRow(`SELECT evidence_version,report_evidence_version FROM findings WHERE id=$1`, findingID).Scan(&out.Version, &out.ReportVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrFindingNotFound
		}
		return nil, err
	}
	rows, err := tx.Query(`SELECT b.id,b.finding_id,b.snapshot_id,b.role,b.note,b.position,b.created_at,to_jsonb(s)
FROM finding_traffic_bindings b JOIN traffic_evidence_snapshots s ON s.id=b.snapshot_id WHERE b.finding_id=$1 ORDER BY b.position,b.id`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var b FindingTrafficBinding
		var raw []byte
		if err := rows.Scan(&b.ID, &b.FindingID, &b.SnapshotID, &b.Role, &b.Note, &b.Position, &b.CreatedAt, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &b.Snapshot); err != nil {
			return nil, err
		}
		out.Bindings = append(out.Bindings, b)
	}
	return out, rows.Err()
}

func (d *DB) GetFindingTraffic(ctx context.Context, findingID int64) (out *FindingTraffic, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error { var e error; out, e = FindingTrafficTx(tx, findingID); return e })
	return
}

func (d *DB) EditFindingTraffic(ctx context.Context, findingID, bindingID, version int64, role, note *string, remove bool, order []int64) error {
	if role != nil && !ValidTrafficRole(*role) {
		return errors.New("无效的流量用途")
	}
	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockFindingEvidenceTx(tx, findingID, &version); err != nil {
			return err
		}
		if order != nil {
			current, err := FindingTrafficTx(tx, findingID)
			if err != nil {
				return err
			}
			if len(order) != len(current.Bindings) {
				return ErrEvidenceConflict
			}
			ids := map[int64]bool{}
			for _, b := range current.Bindings {
				ids[b.ID] = true
			}
			for position, id := range order {
				if !ids[id] {
					return ErrEvidenceConflict
				}
				delete(ids, id)
				if _, err := tx.Exec(`UPDATE finding_traffic_bindings SET position=$1 WHERE finding_id=$2 AND id=$3`, position, findingID, id); err != nil {
					return err
				}
			}
		} else {
			var res sql.Result
			var err error
			if remove {
				res, err = tx.Exec(`DELETE FROM finding_traffic_bindings WHERE finding_id=$1 AND id=$2`, findingID, bindingID)
			} else {
				res, err = tx.Exec(`UPDATE finding_traffic_bindings SET role=COALESCE($3,role),note=COALESCE($4,note) WHERE finding_id=$1 AND id=$2`, findingID, bindingID, role, note)
			}
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrEvidenceNotFound
			}
		}
		return bumpEvidenceVersionTx(tx, findingID)
	})
}

type RecordFindingInput struct {
	TaskID, ExplorationID, IntentID                      int64
	VulnClass, Name, Severity, Summary, Evidence, Worker string
	AssetIDs                                             []int64
	// v0.9 多键去重：同一根因的不同利用面/数据扩展应传同一个 RootCauseKey；
	// MergeIntoFindingID 显式指定合并目标（优先级最高）；SurfaceNote 描述本次
	// 利用面，写入更新记录。Endpoint/HTTPMethod/Parameter 可选，用于生成端点/参数键。
	RootCauseKey       string
	MergeIntoFindingID int64
	SurfaceNote        string
	Endpoint           string
	HTTPMethod         string
	Parameter          string
	// CrossTaskNotifyDedup（v0.6.18）：同指纹漏洞在其他任务已存在时，不再为本任务
	// 的这条重复记录插入推送事件（客户反馈：跨任务重复漏洞「一直播报」）。漏洞本身
	// 照常入库——各任务的发现记录相互独立，只是不重复打扰。
	CrossTaskNotifyDedup bool
}

type RecordedFinding struct {
	FindingID int64           `json:"finding_id,string"`
	NodeID    int64           `json:"finding_node_id,string"`
	Traffic   *FindingTraffic `json:"traffic"`
	// Duplicate=true 表示本次上报命中了同任务内已有的同指纹漏洞,证据已合并
	// 进原记录(而不是新建);调用方应据此提示模型停止重复上报。
	Duplicate bool `json:"-"`
	// CrossTaskDupTasks（v0.6.18）：非空 = 同指纹漏洞在其他任务也已存在（本次通知
	// 已按 CrossTaskNotifyDedup 抑制）。调用方据此在回执里提示模型「跨任务重复」。
	CrossTaskDupTasks []int64 `json:"-"`
	// SkippedRefs 是本次提交里无法解析(流量 ID 不存在/正文不可读)的引用。
	// 漏洞本身照常入库——猜错一个 ID 不该丢掉已确认的漏洞——但调用方要把
	// 这些 ID 原样回给模型,让它知道哪些证据没挂上。
	SkippedRefs []TrafficRef `json:"skipped_traffic_refs,omitempty"`
	// MergeCandidates 是弱键命中的「可能重复」记录（不自动合并），供页面人工复核。
	MergeCandidates []int64 `json:"merge_candidates,omitempty"`
}

// FindingFingerprint 归一化 (vulnclass, name, sorted asset_ids) 为上报指纹。
// 归一:小写、压缩空白;资产按 id 排序消除上报顺序差异。
// normalizeFindingName 去掉漏洞名称里的括注噪声与标点空白差异，作为指纹的一部分。
// 现网实测（任务 #11 交付体检）：同一漏洞换个「（完整证据）/（更新证据）/ (SQLite)」
// 后缀就绕过了指纹，22 条上报里 14 条是同一漏洞的换皮重复——报告页被刷屏，
// 客户侧观感极差。显示名保持原样，只有指纹用归一后的名称。
func normalizeFindingName(name string) string {
	s := findingBrackets.ReplaceAllString(name, " ")
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(s))), " ")
}

var findingBrackets = regexp.MustCompile(`[（(【\[][^）)】\]]*[）)】\]]`)

// findingLocator 从名称/证据里提取“定位键”（CVE、URL 路径、端口），用于指纹。
// 没有资产锚定时，旧指纹退化为「类别|名称」，不同端点/参数的同类漏洞会被合并；
// 有了定位键就能区分，同时仍把「同一漏洞换证据再报一次」合并掉。
var (
	findingCVERe  = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)
	findingURLRe  = regexp.MustCompile(`(?i)https?://[^\s"'<>）)，,]+`)
	findingPathRe = regexp.MustCompile(`(/[a-zA-Z0-9_\-./]{3,})`)
	findingPortRe = regexp.MustCompile(`(?i)(?:端口|port)\s*[:=]?\s*(\d{1,5})`)
)

func findingLocator(in RecordFindingInput) string {
	text := in.Name + " " + in.Summary + " " + in.Evidence
	if m := findingCVERe.FindString(text); m != "" {
		return strings.ToUpper(m)
	}
	if m := findingURLRe.FindString(text); m != "" {
		if u, err := url.Parse(m); err == nil && u.Host != "" {
			return strings.ToLower(u.Host + u.EscapedPath())
		}
		return strings.ToLower(m)
	}
	if m := findingPathRe.FindString(text); m != "" {
		return strings.ToLower(strings.TrimRight(m, "/."))
	}
	if m := findingPortRe.FindStringSubmatch(text); len(m) == 2 {
		return "port:" + m[1]
	}
	return ""
}

func FindingFingerprint(in RecordFindingInput) string {
	norm := func(s string) string { return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(s))), " ") }
	ids := append([]int64{}, in.AssetIDs...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	parts := make([]string, len(ids))
	for i, v := range ids {
		parts[i] = strconv.FormatInt(v, 10)
	}
	loc := findingLocator(in)
	// 无资产锚定且无定位键：指纹只剩「类别|名称」，合并会把不同端点的真实发现
	// 误并成一条。返回空串 = 不参与去重（RecordFindingTx 会跳过合并）。
	if len(ids) == 0 && loc == "" {
		return ""
	}
	namePart := normalizeFindingName(in.Name)
	// 同一 CVE 的标题常被换措辞（“Apache RCE”/“Apache RCE 二次确认”），以 CVE 为准，
	// 名称不参与指纹，避免同一漏洞被重复开行。
	if strings.HasPrefix(loc, "CVE-") {
		namePart = ""
	}
	raw := norm(in.VulnClass) + "|" + namePart + "|" + strings.Join(parts, ",") + "|" + loc
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:16]) // 128-bit 足够;避免长索引键
}

// ctx 由调用方传入本次事务所用的上下文（而非在内部取 context.Background）：
// 事务内新加的推送事件写入同样应受调用方的取消与超时约束。
func RecordFindingTx(ctx context.Context, tx *sql.Tx, in RecordFindingInput, prepared []PreparedTrafficEvidence) (*RecordedFinding, error) {
	if err := LockTaskEvidenceTx(tx, in.TaskID); err != nil {
		return nil, err
	}
	if in.TaskID > 0 {
		var expID int64
		if err := tx.QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1`, in.TaskID).Scan(&expID); err != nil {
			return nil, err
		}
		if expID != in.ExplorationID {
			return nil, errors.New("漏洞所属任务与探索记录不匹配")
		}
	}
	if in.IntentID > 0 {
		var ok bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='intent')`, in.IntentID, in.ExplorationID).Scan(&ok); err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("intent_id 必须是本任务的意图（关联任务意图只读）")
		}
	}
	// ── 同任务内指纹去重:同一 (vulnclass,name,assets) 视为同一漏洞的重复上报,
	// 证据合并进已有记录而不是再插一行——"报了 A 又把 A 重新报一遍"在写入层被
	// 硬性拦住,不依赖模型自觉。
	// v0.6.22：**不再要求带资产锚定**。现网实测（交付体检任务 #11）：worker 上报漏洞
	// 时普遍不带 asset_ids（资产写回为 0），旧逻辑因此整段跳过去重，同一指纹在
	// 一个任务里插了 4–7 行。指纹本身已包含资产集合（空集也参与哈希），同指纹即
	// 同一 (类,名,资产集) 三元组；无锚定时的「不同端口同名漏洞」歧义接受合并
	// （证据只增不丢），重复刷屏对客户的伤害远大于此。
	// resolved/fixed/false_positive/ignored 已是终态或人工结论,不参与合并
	// (修复后再复现 = 值得新开一条;误报后再证实 = 翻案)。
	// vulnclass 归一(变体写法→标准类别):写入即归一,聚合视图与指纹去重
	// 都基于标准值——SQLi 与 SQL注入 从此是同一类别、同一指纹。
	in.VulnClass = NormalizeVulnClass(in.VulnClass)
	fp := FindingFingerprint(in)
	keys := FindingDedupKeys(in, fp)
	// v0.9：多键合并。名称为空的样本不参与自动合并：空名 + 空资产时只有类别，
	// 会把「同一类别下的两条真实不同发现」误并（v0.6.22 全量测试实测）。
	if in.TaskID > 0 && strings.TrimSpace(in.Name) != "" {
		targetID, err := findFindingMergeTargetTx(tx, in, fp, keys)
		if err != nil {
			return nil, err
		}
		if targetID > 0 {
			out, err := mergeReportIntoTargetTx(ctx, tx, targetID, in, prepared, keys)
			if err != nil {
				return nil, err
			}
			return out, nil
		}
	}
	// 未命中强键：仍按旧指纹兜底（历史行可能没有 finding_keys），并把弱键候选
	// 一起返回给调用方做「可能重复」提示，不自动合并。
	var mergeCandidates []int64
	payload, _ := json.Marshal(map[string]any{"vulnclass": in.VulnClass, "name": in.Name, "severity": in.Severity, "summary": in.Summary, "evidence": map[string]any{"by": in.Worker, "poc": in.Evidence}})
	out := &RecordedFinding{}
	if err := tx.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin)
VALUES($1,'finding',$2,9,'confirmed',$3) RETURNING id`, in.ExplorationID, string(payload), in.Worker).Scan(&out.NodeID); err != nil {
		return nil, err
	}
	for _, asset := range in.AssetIDs {
		if _, err := tx.Exec(`INSERT INTO exploration_anchors(node_id,asset_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, out.NodeID, asset); err != nil {
			return nil, err
		}
	}
	if in.IntentID > 0 {
		if _, err := tx.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,$3,$4)`, in.ExplorationID, in.IntentID, RelYields, out.NodeID); err != nil {
			return nil, err
		}
	}
	assets := in.AssetIDs
	if assets == nil {
		assets = []int64{}
	}
	raw, _ := json.Marshal(assets)
	rootKey := normalizeRootCauseKey(in.RootCauseKey)
	if err := tx.QueryRow(`INSERT INTO findings(task_id,node_id,vulnclass,name,severity,summary,evidence,worker,asset_ids,fingerprint,root_cause_key)
VALUES(NULLIF($1,0),$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`, in.TaskID, out.NodeID, in.VulnClass, in.Name, in.Severity, in.Summary, in.Evidence, in.Worker, string(raw), fp, rootKey).Scan(&out.FindingID); err != nil {
		return nil, err
	}
	if err := insertFindingKeysTx(tx, out.FindingID, keys); err != nil {
		return nil, err
	}
	if err := insertFindingUpdateTx(tx, out.FindingID, "initial", 0, in, in.Summary, in.Evidence, prepared); err != nil {
		return nil, err
	}
	mergeCandidates = weakFindingCandidatesTx(tx, out.FindingID, keys)
	out.MergeCandidates = mergeCandidates
	// 在**同一事务**里登记一条推送事件：提交即保证「漏洞落库」与「推送任务存在」
	// 原子一致，不存在提交成功却没入队、消息永久丢失的窗口。
	// 这里的失败被隔离在保存点上、不影响漏洞写入（见函数注释），因此忽略返回值。
	// v0.6.18 跨任务去重：同指纹漏洞在其他未删除任务已存在时不再重复推送
	// （客户反馈跨任务重复漏洞「一直播报」）；漏洞记录本身照常保留。
	if in.CrossTaskNotifyDedup {
		var dupTasks []int64
		dupRows, dupErr := tx.Query(`SELECT f.task_id FROM findings f
JOIN tasks t ON t.id=f.task_id AND t.deleted_at IS NULL
WHERE f.fingerprint=$1 AND f.task_id<>$2
  AND EXISTS (SELECT 1 FROM findings f2 WHERE f2.task_id=f.task_id AND f2.fingerprint=$1
              AND f2.status IN ('pending','in_progress','confirmed'))
GROUP BY f.task_id ORDER BY f.task_id`, fp, in.TaskID)
		if dupErr == nil {
			for dupRows.Next() {
				var tid int64
				if _ = dupRows.Scan(&tid); tid > 0 {
					dupTasks = append(dupTasks, tid)
				}
			}
			_ = dupRows.Close()
		}
		if len(dupTasks) > 0 {
			out.CrossTaskDupTasks = dupTasks
		}
	}
	if in.CrossTaskNotifyDedup && len(out.CrossTaskDupTasks) > 0 {
		// 抑制推送：跨任务重复不再打扰（记录本身保留，页面可见）。
	} else {
		RecordNotificationEventTx(ctx, tx, notify.EventFindingCreated, out.FindingID, notify.Snapshot{
			Kind:      notify.EventFindingCreated,
			FindingID: out.FindingID,
			TaskID:    in.TaskID,
			VulnClass: in.VulnClass,
			Name:      in.Name,
			Severity:  in.Severity,
			Summary:   in.Summary,
			AssetIDs:  assets,
		})
	}
	if err := AddFindingTrafficTx(tx, out.FindingID, prepared); err != nil {
		return nil, err
	}
	var err error
	out.Traffic, err = FindingTrafficTx(tx, out.FindingID)
	return out, err
}

// RecordFinding is the atomic legacy/no-recorder path used by tools and tests.
func (s *ExplorationStore) RecordFinding(ctx context.Context, in RecordFindingInput) (out *RecordedFinding, err error) {
	in.ExplorationID = s.expID
	err = s.db.WithEvidenceTx(ctx, func(tx *sql.Tx) error { var e error; out, e = RecordFindingTx(ctx, tx, in, nil); return e })
	return
}

func (d *DB) FindingIDByNodeID(nodeID int64) (id int64, err error) {
	err = d.QueryRow(`SELECT id FROM findings WHERE node_id=$1`, nodeID).Scan(&id)
	return
}

// PopulateFindingTrafficIDs only enriches already-visible nodes. It performs no
// discovery or ID guessing, and leaves the legacy node ID unchanged.
func (s *ExplorationStore) PopulateFindingTrafficIDs(nodes []*Node) error {
	byID := map[int64]*Node{}
	var args []any
	var placeholders []string
	for _, n := range nodes {
		if n == nil || n.Kind != KindFinding || byID[n.ID] != nil {
			continue
		}
		byID[n.ID] = n
		args = append(args, n.ID)
		placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
	}
	if len(args) == 0 {
		return nil
	}
	rows, err := s.db.Query(`SELECT f.id,f.node_id,(SELECT count(*) FROM finding_traffic_bindings b WHERE b.finding_id=f.id) FROM findings f WHERE f.node_id IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var findingID, nodeID int64
		var count int
		if err := rows.Scan(&findingID, &nodeID, &count); err != nil {
			return err
		}
		n := byID[nodeID]
		n.FindingID, n.FindingNodeID, n.TrafficCount = findingID, nodeID, count
	}
	return rows.Err()
}

// SetFindingReportVersionByNodeID 写漏洞报告。入参既可以是探索节点 ID，也可以是
// findings 表主键——两者模型都拿得到（report_finding 返回首行是节点 ID，JSON 里是
// 记录 ID），现网 reporter 会先试记录 ID 再纠回节点 ID，白白废掉一轮。
// 解析顺序：先按 node_id 精确匹配，命中不了再把入参当 findings.id 反查 node_id。
func (d *DB) SetFindingReportVersionByNodeID(ctx context.Context, nodeID int64, report string, version *int64) (n int64, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		var id int64
		errLookup := tx.QueryRow(`SELECT id FROM findings WHERE node_id=$1`, nodeID).Scan(&id)
		if errors.Is(errLookup, sql.ErrNoRows) {
			// 兼容「传了 findings.id」：反查它对应的 node_id，后续按节点口径继续。
			var realNode sql.NullInt64
			if err := tx.QueryRow(`SELECT id,node_id FROM findings WHERE id=$1`, nodeID).Scan(&id, &realNode); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return nil
				}
				return err
			}
			if realNode.Valid {
				nodeID = realNode.Int64
			}
		} else if errLookup != nil {
			return errLookup
		}
		if err := LockFindingEvidenceTx(tx, id, version); err != nil {
			return err
		}
		res, err := tx.Exec(`UPDATE findings SET report=$2,report_evidence_version=COALESCE($3::bigint,CASE WHEN evidence_version=0 THEN 0 ELSE -1 END) WHERE id=$1`, id, report, version)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return
}
