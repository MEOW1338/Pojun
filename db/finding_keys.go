package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// v0.9 多键去重：一条 finding 可以携带多个身份键，强键自动合并、弱键只做候选。
//
// 设计取舍：
//   - root/cve/endpoint/param/legacy 是强键，命中即认为同一底层漏洞；
//   - asset_class/name 是弱键，只用于「可能重复」提示，绝不自动合并，
//     避免把同资产下两条真实不同的发现误并；
//   - 所有键都限定同任务。跨任务只在列表/详情提示，不自动改写。
const (
	FindingKeyRoot       = "root"
	FindingKeyCVE        = "cve"
	FindingKeyEndpoint   = "endpoint"
	FindingKeyParam      = "param"
	FindingKeyLegacy     = "legacy"
	FindingKeyAssetClass = "asset_class"
	FindingKeyName       = "name"
)

type FindingKey struct {
	Key  string `json:"key"`
	Kind string `json:"kind"`
}

func strongFindingKeyRank(kind string) int {
	switch kind {
	case FindingKeyRoot:
		return 1
	case FindingKeyCVE:
		return 2
	case FindingKeyParam:
		return 3
	case FindingKeyEndpoint:
		return 4
	case FindingKeyLegacy:
		return 5
	}
	return 99
}

func normalizeRootCauseKey(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return ""
	}
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == ':', r == '_', r == '-':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 96 {
		out = out[:96]
	}
	return out
}

// normalizeFindingEndpoint 把 URL 或路径归一到 host+path（小写 host、去 query/hash、
// 去尾斜杠）。路径保持大小写——HTTP 路径可能大小写敏感。
func normalizeFindingEndpoint(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			host := strings.ToLower(u.Host)
			path := strings.TrimRight(u.EscapedPath(), "/")
			if path == "" {
				path = "/"
			}
			return host + path
		}
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimRight(s, "/")
	if s == "" {
		s = "/"
	}
	return strings.ToLower(s)
}

// firstFindingURL 从名称/摘要/证据里取第一个 http(s) URL，作为端点键来源。
func firstFindingURL(in RecordFindingInput) string {
	for _, text := range []string{in.Endpoint, in.Name, in.Summary, in.Evidence} {
		if m := findingURLRe.FindString(text); m != "" {
			return m
		}
	}
	if strings.TrimSpace(in.Endpoint) != "" {
		return in.Endpoint
	}
	return ""
}

// FindingDedupKeys 生成本次上报的全部身份键（已去重）。
func FindingDedupKeys(in RecordFindingInput, fp string) []FindingKey {
	seen := map[string]bool{}
	out := make([]FindingKey, 0, 8)
	add := func(kind, key string) {
		key = strings.TrimSpace(key)
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, FindingKey{Key: key, Kind: kind})
	}

	if root := normalizeRootCauseKey(in.RootCauseKey); root != "" {
		add(FindingKeyRoot, "root:"+root)
	}
	text := in.Name + "\n" + in.Summary + "\n" + in.Evidence
	for _, cve := range findingCVERe.FindAllString(text, -1) {
		add(FindingKeyCVE, "cve:"+strings.ToUpper(cve))
	}
	endpoint := normalizeFindingEndpoint(firstFindingURL(in))
	if endpoint != "" {
		add(FindingKeyEndpoint, "endpoint:"+endpoint)
	}
	if param := strings.ToLower(strings.TrimSpace(in.Parameter)); param != "" && endpoint != "" {
		add(FindingKeyParam, "param:"+endpoint+":"+param)
	}
	if fp != "" {
		add(FindingKeyLegacy, "legacy:"+fp)
	}
	if name := normalizeFindingName(in.Name); name != "" {
		add(FindingKeyName, "name:"+name)
	}
	if len(in.AssetIDs) > 0 && strings.TrimSpace(in.VulnClass) != "" {
		ids := append([]int64{}, in.AssetIDs...)
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		parts := make([]string, 0, len(ids))
		for _, id := range ids {
			parts = append(parts, fmt.Sprintf("%d", id))
		}
		add(FindingKeyAssetClass, "asset_class:"+strings.Join(parts, ",")+":"+strings.ToLower(strings.TrimSpace(in.VulnClass)))
	}
	return out
}

func insertFindingKeysTx(tx *sql.Tx, findingID int64, keys []FindingKey) error {
	for _, k := range keys {
		if _, err := tx.Exec(`INSERT INTO finding_keys(finding_id,dedup_key,kind) VALUES($1,$2,$3)
ON CONFLICT (finding_id,dedup_key) DO NOTHING`, findingID, k.Key, k.Kind); err != nil {
			return err
		}
	}
	return nil
}

func findingUpdateAssetsJSON(ids []int64) string {
	if ids == nil {
		ids = []int64{}
	}
	b, _ := json.Marshal(ids)
	return string(b)
}

func findingUpdateTrafficJSON(prepared []PreparedTrafficEvidence) string {
	ids := make([]string, 0, len(prepared))
	for _, p := range prepared {
		if strings.TrimSpace(p.Ref.TrafficID) != "" {
			ids = append(ids, p.Ref.TrafficID)
		}
	}
	b, _ := json.Marshal(ids)
	return string(b)
}

func insertFindingUpdateTx(tx *sql.Tx, findingID int64, kind string, sourceID int64, in RecordFindingInput, summary, evidence string, prepared []PreparedTrafficEvidence) error {
	var source any
	if sourceID > 0 {
		source = sourceID
	}
	var intent any
	if in.IntentID > 0 {
		intent = in.IntentID
	}
	_, err := tx.Exec(`INSERT INTO finding_updates(finding_id,kind,source_id,worker,intent_id,summary,evidence,asset_ids,traffic_ids)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		findingID, kind, source, in.Worker, intent, summary, evidence,
		findingUpdateAssetsJSON(in.AssetIDs), findingUpdateTrafficJSON(prepared))
	return err
}

func lockFindingRowTx(tx *sql.Tx, id int64) (taskID sql.NullInt64, nodeID int64, status, rootKey, assetJSON string, err error) {
	err = tx.QueryRow(`SELECT task_id, COALESCE(node_id,0), status, COALESCE(root_cause_key,''), COALESCE(asset_ids::text,'[]')
FROM findings WHERE id=$1 FOR UPDATE`, id).Scan(&taskID, &nodeID, &status, &rootKey, &assetJSON)
	return
}

func resolveFindingMergeRootTx(tx *sql.Tx, id int64) (int64, error) {
	seen := map[int64]bool{}
	for id > 0 {
		if seen[id] {
			return 0, fmt.Errorf("漏洞合并链存在循环（finding_id=%d）", id)
		}
		seen[id] = true
		var merged sql.NullInt64
		if err := tx.QueryRow(`SELECT merged_into_id FROM findings WHERE id=$1`, id).Scan(&merged); err != nil {
			if err == sql.ErrNoRows {
				return 0, ErrFindingNotFound
			}
			return 0, err
		}
		if !merged.Valid || merged.Int64 == 0 || merged.Int64 == id {
			return id, nil
		}
		id = merged.Int64
	}
	return 0, ErrFindingNotFound
}

// findFindingMergeTargetTx 按强键寻找自动合并目标。优先级：
// 显式 merge_into > root > cve > param > endpoint > legacy。
// 只考虑同任务的 pending/in_progress/confirmed 记录。
func findFindingMergeTargetTx(tx *sql.Tx, in RecordFindingInput, fp string, keys []FindingKey) (int64, error) {
	if in.MergeIntoFindingID > 0 {
		root, err := resolveFindingMergeRootTx(tx, in.MergeIntoFindingID)
		if err != nil {
			return 0, err
		}
		var taskID sql.NullInt64
		if err := tx.QueryRow(`SELECT task_id FROM findings WHERE id=$1`, root).Scan(&taskID); err != nil {
			return 0, err
		}
		if in.TaskID > 0 && (!taskID.Valid || taskID.Int64 != in.TaskID) {
			return 0, fmt.Errorf("merge_into_finding_id 必须属于当前任务")
		}
		return root, nil
	}

	// 旧数据兼容：历史记录可能还没有 finding_keys，先按旧指纹精确匹配。
	if fp != "" {
		var id int64
		err := tx.QueryRow(`SELECT id FROM findings
WHERE task_id=$1 AND fingerprint=$2 AND status IN ('pending','in_progress','confirmed')
ORDER BY id LIMIT 1 FOR UPDATE`, in.TaskID, fp).Scan(&id)
		if err == nil {
			return id, nil
		}
		if err != sql.ErrNoRows {
			return 0, err
		}
	}

	strong := make([]FindingKey, 0, len(keys))
	for _, k := range keys {
		if strongFindingKeyRank(k.Kind) < 99 {
			strong = append(strong, k)
		}
	}
	if len(strong) == 0 {
		return 0, nil
	}
	args := []any{in.TaskID}
	ph := make([]string, 0, len(strong))
	for _, k := range strong {
		args = append(args, k.Key)
		ph = append(ph, fmt.Sprintf("$%d", len(args)))
	}
	q := `SELECT f.id, f.created_at,
       MIN(CASE fk.kind WHEN 'root' THEN 1 WHEN 'cve' THEN 2 WHEN 'param' THEN 3 WHEN 'endpoint' THEN 4 WHEN 'legacy' THEN 5 ELSE 99 END) AS prio
FROM finding_keys fk
JOIN findings f ON f.id=fk.finding_id
WHERE f.task_id=$1 AND f.status IN ('pending','in_progress','confirmed')
  AND fk.dedup_key IN (` + strings.Join(ph, ",") + `)
GROUP BY f.id, f.created_at
ORDER BY prio, f.created_at, f.id
LIMIT 10`
	rows, err := tx.Query(q, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var candidates []int64
	for rows.Next() {
		var id int64
		var created time.Time
		var prio int
		if err := rows.Scan(&id, &created, &prio); err != nil {
			return 0, err
		}
		candidates = append(candidates, id)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, id := range candidates {
		var status string
		if err := tx.QueryRow(`SELECT status FROM findings WHERE id=$1 FOR UPDATE`, id).Scan(&status); err != nil {
			if err == sql.ErrNoRows {
				continue
			}
			return 0, err
		}
		switch status {
		case FindingPending, FindingInProgress, FindingConfirmed:
			return id, nil
		}
	}
	return 0, nil
}

// mergeReportIntoTargetTx 把一次新上报合并进已有主记录：追加证据、提升严重度、
// 并集资产、迁移流量、写更新记录、补身份键。源数据不落新行。
func mergeReportIntoTargetTx(ctx context.Context, tx *sql.Tx, targetID int64, in RecordFindingInput, prepared []PreparedTrafficEvidence, keys []FindingKey) (*RecordedFinding, error) {
	_, nodeID, status, rootKey, assetJSON, err := lockFindingRowTx(tx, targetID)
	if err != nil {
		return nil, err
	}
	if status == FindingDuplicate {
		if root, err := resolveFindingMergeRootTx(tx, targetID); err == nil && root != targetID {
			targetID = root
			_, nodeID, _, rootKey, assetJSON, err = lockFindingRowTx(tx, targetID)
			if err != nil {
				return nil, err
			}
		}
	}
	stamp := time.Now().UTC().Format("2006-01-02 15:04")
	title := strings.TrimSpace(in.SurfaceNote)
	if title == "" {
		title = "二次确认"
	}
	appendix := fmt.Sprintf("\n\n--- %s(worker=%s, %s UTC) ---\n%s", title, in.Worker, stamp, in.Evidence)

	assets := mergeInt64JSON(assetJSON, in.AssetIDs)
	root := rootKey
	if root == "" {
		root = normalizeRootCauseKey(in.RootCauseKey)
	}
	if _, err := tx.Exec(`UPDATE findings SET evidence = evidence || $2,
  severity = CASE
    WHEN $3='critical' OR severity='critical' THEN 'critical'
    WHEN $3='high' OR severity='high' THEN 'high'
    WHEN $3='medium' OR severity='medium' THEN 'medium'
    WHEN $3='low' OR severity='low' THEN 'low'
    ELSE severity END,
  asset_ids = $4::jsonb,
  root_cause_key = CASE WHEN COALESCE(root_cause_key,'')='' THEN $5 ELSE root_cause_key END,
  merge_count = merge_count + 1,
  last_merged_at = now(),
  evidence_version = evidence_version + 1
WHERE id=$1`, targetID, appendix, in.Severity, assetsJSONString(assets), root); err != nil {
		return nil, err
	}
	if err := appendEvidenceToFindingNodeTx(tx, nodeID, appendix, in.Severity, assets); err != nil {
		return nil, err
	}
	if in.IntentID > 0 && nodeID > 0 {
		if _, err := tx.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id)
			SELECT $1,$2,$3,$4 WHERE NOT EXISTS(
				SELECT 1 FROM exploration_edges WHERE exploration_id=$1 AND src_id=$2 AND rel=$3 AND dst_id=$4)`,
			in.ExplorationID, in.IntentID, RelYields, nodeID); err != nil {
			return nil, err
		}
	}
	if err := insertFindingKeysTx(tx, targetID, keys); err != nil {
		return nil, err
	}
	summary := in.Summary
	if strings.TrimSpace(in.SurfaceNote) != "" {
		summary = in.SurfaceNote
	}
	if err := insertFindingUpdateTx(tx, targetID, "merge", 0, in, summary, in.Evidence, prepared); err != nil {
		return nil, err
	}
	if err := AddFindingTrafficTx(tx, targetID, prepared); err != nil {
		return nil, err
	}
	out := &RecordedFinding{FindingID: targetID, NodeID: nodeID, Duplicate: true}
	out.Traffic, err = FindingTrafficTx(tx, targetID)
	return out, err
}

func assetsJSONString(ids []int64) string {
	if ids == nil {
		ids = []int64{}
	}
	b, _ := json.Marshal(ids)
	return string(b)
}

func mergeInt64JSON(existing string, add []int64) []int64 {
	var cur []int64
	_ = json.Unmarshal([]byte(existing), &cur)
	return mergeInt64Slices(cur, add)
}

func mergeInt64Slices(existing, add []int64) []int64 {
	seen := map[int64]bool{}
	out := make([]int64, 0, len(existing)+len(add))
	for _, id := range existing {
		if id > 0 && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, id := range add {
		if id > 0 && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func appendEvidenceToFindingNodeTx(tx *sql.Tx, nodeID int64, appendix, severity string, assets []int64) error {
	if nodeID <= 0 {
		return nil
	}
	if _, err := tx.Exec(`UPDATE exploration_nodes
  SET payload = jsonb_set(
        jsonb_set(payload,'{severity}',to_jsonb($2::text),true),
        '{evidence,poc}', to_jsonb(COALESCE(payload->'evidence'->>'poc','') || $3), true)
WHERE id=$1`, nodeID, severity, appendix); err != nil {
		return err
	}
	for _, asset := range assets {
		if _, err := tx.Exec(`INSERT INTO exploration_anchors(node_id,asset_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, nodeID, asset); err != nil {
			return err
		}
	}
	return nil
}

// MergeFindings 人工合并：把 sourceIDs 合并进 targetID（必须同任务）。
// 源记录不物理删除，标记 duplicate + merged_into_id，便于审计与后续拆分。
func (d *DB) MergeFindings(ctx context.Context, taskID, targetID int64, sourceIDs []int64, reason string) (*DBFinding, error) {
	if targetID <= 0 || len(sourceIDs) == 0 {
		return nil, fmt.Errorf("target_id 与 source_ids 不能为空")
	}
	err := d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		root, err := resolveFindingMergeRootTx(tx, targetID)
		if err != nil {
			return err
		}
		targetID = root
		targetTask, targetNode, targetStatus, _, targetAssets, err := lockFindingRowTx(tx, targetID)
		if err != nil {
			return err
		}
		if taskID > 0 && (!targetTask.Valid || targetTask.Int64 != taskID) {
			return fmt.Errorf("目标漏洞不属于当前任务")
		}
		if !targetTask.Valid || targetTask.Int64 <= 0 {
			return fmt.Errorf("目标漏洞没有关联任务，不能合并")
		}
		taskID = targetTask.Int64
		if targetStatus == FindingDuplicate {
			return fmt.Errorf("目标漏洞已被合并，不能再作为合并目标")
		}
		assets := mergeInt64JSON(targetAssets, nil)
		bumped := false
		for _, sourceID := range sourceIDs {
			if sourceID <= 0 || sourceID == targetID {
				continue
			}
			srcID, err := resolveFindingMergeRootTx(tx, sourceID)
			if err != nil {
				return err
			}
			if srcID == targetID {
				continue
			}
			srcTask, srcNode, srcStatus, _, _, err := lockFindingRowTx(tx, srcID)
			if err != nil {
				return err
			}
			if taskID > 0 && (!srcTask.Valid || srcTask.Int64 != taskID) {
				return fmt.Errorf("漏洞 #%d 不属于当前任务，不能跨任务合并", srcID)
			}
			if srcStatus == FindingDuplicate {
				continue
			}
			var name, evidence, worker, report, srcSeverity string
			var sourceAssetIDs []int64
			var srcAssetJSON string
			if err := tx.QueryRow(`SELECT COALESCE(name,''), COALESCE(evidence,''),
COALESCE(worker,''), COALESCE(report,''), COALESCE(severity,''), COALESCE(asset_ids::text,'[]')
FROM findings WHERE id=$1`, srcID).Scan(&name, &evidence, &worker, &report, &srcSeverity, &srcAssetJSON); err != nil {
				return err
			}
			_ = json.Unmarshal([]byte(srcAssetJSON), &sourceAssetIDs)
			assets = mergeInt64Slices(assets, sourceAssetIDs)
			stamp := time.Now().UTC().Format("2006-01-02 15:04")
			header := strings.TrimSpace(reason)
			if header == "" {
				header = "人工合并"
			}
			appendix := fmt.Sprintf("\n\n--- 合并来源 #%d %s(worker=%s, %s UTC；%s) ---\n%s",
				srcID, name, worker, stamp, header, evidence)
			if _, err := tx.Exec(`UPDATE findings SET evidence = evidence || $2,
  severity = CASE
    WHEN severity='critical' THEN 'critical'
    WHEN $3='critical' THEN 'critical'
    WHEN severity='high' THEN 'high'
    WHEN $3='high' THEN 'high'
    WHEN severity='medium' THEN 'medium'
    WHEN $3='medium' THEN 'medium'
    ELSE 'low' END,
  asset_ids = $4::jsonb,
  report = CASE
    WHEN COALESCE($5,'')='' THEN report
    WHEN COALESCE(report,'')='' THEN $5
    ELSE report || E'\n\n--- 合并来源 #' || $6::text || ' ---\n' || $5 END,
  merge_count = merge_count + 1,
  last_merged_at = now(),
  evidence_version = evidence_version + 1
WHERE id=$1`, targetID, appendix, srcSeverity, assetsJSONString(assets), report, fmt.Sprintf("%d", srcID)); err != nil {
				return err
			}
			if err := appendEvidenceToFindingNodeTx(tx, targetNode, appendix, srcSeverity, assets); err != nil {
				return err
			}
			// 流量绑定迁移：按 snapshot 去重，position 续在目标末尾。
			if _, err := tx.Exec(`INSERT INTO finding_traffic_bindings(finding_id,snapshot_id,role,note,position,created_at)
SELECT $1, snapshot_id, role, note,
       position + COALESCE((SELECT MAX(position) FROM finding_traffic_bindings WHERE finding_id=$1), 0) + 1,
       created_at
FROM finding_traffic_bindings WHERE finding_id=$2
ON CONFLICT (finding_id,snapshot_id) DO NOTHING`, targetID, srcID); err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM finding_traffic_bindings WHERE finding_id=$1`, srcID); err != nil {
				return err
			}
			if srcNode > 0 && targetNode > 0 {
				if _, err := tx.Exec(`INSERT INTO exploration_anchors(node_id,asset_id)
SELECT $1, asset_id FROM exploration_anchors WHERE node_id=$2
ON CONFLICT DO NOTHING`, targetNode, srcNode); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(`INSERT INTO finding_keys(finding_id,dedup_key,kind)
SELECT $1, dedup_key, kind FROM finding_keys WHERE finding_id=$2
ON CONFLICT (finding_id,dedup_key) DO NOTHING`, targetID, srcID); err != nil {
				return err
			}
			in := RecordFindingInput{TaskID: taskID, ExplorationID: 0, Worker: worker, AssetIDs: sourceAssetIDs}
			if err := insertFindingUpdateTx(tx, targetID, "merge", srcID, in, header, evidence, nil); err != nil {
				return err
			}
			if _, err := tx.Exec(`UPDATE findings SET status=$2, merged_into_id=$3, last_merged_at=now() WHERE id=$1`,
				srcID, FindingDuplicate, targetID); err != nil {
				return err
			}
			bumped = true
		}
		if !bumped {
			return nil
		}
		return bumpEvidenceVersionTx(tx, targetID)
	})
	if err != nil {
		return nil, err
	}
	return d.GetFinding(targetID)
}

// weakFindingCandidatesTx 返回弱键命中的同任务候选 id（不含自身），只提示不合并。
func weakFindingCandidatesTx(tx *sql.Tx, findingID int64, keys []FindingKey) []int64 {
	var weak []string
	for _, k := range keys {
		if k.Kind == FindingKeyName || k.Kind == FindingKeyAssetClass {
			weak = append(weak, k.Key)
		}
	}
	if len(weak) == 0 || findingID <= 0 {
		return nil
	}
	args := []any{findingID}
	ph := make([]string, 0, len(weak))
	for _, k := range weak {
		args = append(args, k)
		ph = append(ph, fmt.Sprintf("$%d", len(args)))
	}
	rows, err := tx.Query(`SELECT DISTINCT fk2.finding_id
FROM finding_keys fk1
JOIN finding_keys fk2 ON fk2.dedup_key=fk1.dedup_key AND fk2.finding_id<>fk1.finding_id
JOIN findings f ON f.id=fk2.finding_id
WHERE fk1.finding_id=$1 AND fk1.kind IN ('name','asset_class')
  AND fk1.dedup_key IN (`+strings.Join(ph, ",")+`)
  AND f.status IN ('pending','in_progress','confirmed')
  AND f.task_id=(SELECT task_id FROM findings WHERE id=$1)
LIMIT 10`, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			out = append(out, id)
		}
	}
	return out
}

// FindingCrossTaskCandidates 返回其他任务中同键的记录，仅提示，不自动合并。
func (d *DB) FindingCrossTaskCandidates(ctx context.Context, findingID int64) ([]*DBFinding, error) {
	rows, err := d.QueryContext(ctx, `SELECT DISTINCT f2.id
FROM finding_keys fk1
JOIN finding_keys fk2 ON fk2.dedup_key=fk1.dedup_key AND fk2.finding_id<>fk1.finding_id
JOIN findings f2 ON f2.id=fk2.finding_id
JOIN findings f1 ON f1.id=fk1.finding_id
WHERE fk1.finding_id=$1 AND f2.task_id IS NOT NULL AND f2.task_id<>f1.task_id
  AND f2.status IN ('pending','in_progress','confirmed')
LIMIT 10`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]*DBFinding, 0, len(ids))
	for _, id := range ids {
		f, err := d.GetFinding(id)
		if err != nil {
			return nil, err
		}
		if f != nil {
			out = append(out, f)
		}
	}
	return out, nil
}

// FindingUpdates 返回漏洞更新记录（倒序）。
func (d *DB) FindingUpdates(ctx context.Context, findingID int64) ([]map[string]any, error) {
	rows, err := d.QueryContext(ctx, `SELECT id, kind, COALESCE(source_id,0), worker, COALESCE(intent_id,0),
COALESCE(summary,''), COALESCE(evidence,''), COALESCE(report,''), COALESCE(asset_ids::text,'[]'),
COALESCE(traffic_ids::text,'[]'), created_at
FROM finding_updates WHERE finding_id=$1 ORDER BY id DESC LIMIT 200`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]map[string]any, 0, 8)
	for rows.Next() {
		var id, sourceID, intentID int64
		var kind, worker, summary, evidence, report, assetsJSON, trafficJSON string
		var created time.Time
		if err := rows.Scan(&id, &kind, &sourceID, &worker, &intentID, &summary, &evidence, &report, &assetsJSON, &trafficJSON, &created); err != nil {
			return nil, err
		}
		var assets []int64
		var trafficIDs []string
		_ = json.Unmarshal([]byte(assetsJSON), &assets)
		_ = json.Unmarshal([]byte(trafficJSON), &trafficIDs)
		out = append(out, map[string]any{
			"id": id, "kind": kind, "source_id": sourceID, "worker": worker, "intent_id": intentID,
			"summary": summary, "evidence": evidence, "report": report,
			"asset_ids": assets, "traffic_ids": trafficIDs, "created_at": created,
		})
	}
	return out, rows.Err()
}

// FindingMergeCandidates 返回弱键命中的同任务候选（不含已合并/终态）。
func (d *DB) FindingMergeCandidates(ctx context.Context, findingID int64) ([]*DBFinding, error) {
	rows, err := d.QueryContext(ctx, `SELECT DISTINCT fk2.finding_id
FROM finding_keys fk1
JOIN finding_keys fk2 ON fk2.dedup_key=fk1.dedup_key AND fk2.finding_id<>fk1.finding_id
JOIN findings f ON f.id=fk2.finding_id
WHERE fk1.finding_id=$1 AND fk1.kind IN ('name','asset_class')
  AND f.status IN ('pending','in_progress','confirmed')
  AND f.task_id=(SELECT task_id FROM findings WHERE id=$1)
LIMIT 20`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]int64, 0, 8)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]*DBFinding, 0, len(ids))
	for _, id := range ids {
		f, err := d.GetFinding(id)
		if err != nil {
			return nil, err
		}
		if f != nil {
			out = append(out, f)
		}
	}
	return out, nil
}

// BackfillFindingKeys 为历史 findings 补身份键（幂等、分批）。升级后旧数据也能
// 参与新的多键合并；失败只返回错误，不阻塞启动。
func (d *DB) BackfillFindingKeys(ctx context.Context, limit int) error {
	if limit <= 0 {
		limit = 5000
	}
	rows, err := d.QueryContext(ctx, `SELECT f.id, COALESCE(f.task_id,0), COALESCE(f.vulnclass,''), COALESCE(f.name,''),
COALESCE(f.severity,''), COALESCE(f.summary,''), COALESCE(f.evidence,''), COALESCE(f.worker,''),
COALESCE(f.asset_ids::text,'[]'), COALESCE(f.fingerprint,''), COALESCE(f.root_cause_key,'')
FROM findings f
WHERE NOT EXISTS (SELECT 1 FROM finding_keys k WHERE k.finding_id=f.id)
ORDER BY f.id LIMIT $1`, limit)
	if err != nil {
		return err
	}
	type row struct {
		id                                      int64
		taskID                                  int64
		vulnclass, name, severity, summary, evi string
		worker, assetsJSON, fp, rootKey         string
	}
	var batch []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.taskID, &r.vulnclass, &r.name, &r.severity, &r.summary, &r.evi, &r.worker, &r.assetsJSON, &r.fp, &r.rootKey); err != nil {
			rows.Close()
			return err
		}
		batch = append(batch, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	return d.WithEvidenceTx(ctx, func(batchTx *sql.Tx) error {
		for _, r := range batch {
			var assets []int64
			_ = json.Unmarshal([]byte(r.assetsJSON), &assets)
			in := RecordFindingInput{
				TaskID: r.taskID, VulnClass: NormalizeVulnClass(r.vulnclass), Name: r.name,
				Severity: r.severity, Summary: r.summary, Evidence: r.evi, Worker: r.worker,
				AssetIDs: assets, RootCauseKey: r.rootKey,
			}
			keys := FindingDedupKeys(in, r.fp)
			// 历史记录的指纹可能来自旧算法；始终保留 legacy 键。
			if r.fp != "" {
				found := false
				for _, k := range keys {
					if k.Kind == FindingKeyLegacy {
						found = true
					}
				}
				if !found {
					keys = append(keys, FindingKey{Key: "legacy:" + r.fp, Kind: FindingKeyLegacy})
				}
			}
			if err := insertFindingKeysTx(batchTx, r.id, keys); err != nil {
				return err
			}
		}
		return nil
	})
}
