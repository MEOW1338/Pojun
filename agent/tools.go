package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/hosttools"
)

// compactIntents distills intents to {id, summary, state, asset_ids, parents,
// yields} so the planner sees both the direction and its LINEAGE — parents (the
// upstream nodes it derived from: facts/intents/findings) and yields (the facts/
// findings it produced) — without pulling full payloads. parentsOf/yieldsOf are
// built from the exploration edges in graph_overview. tokens (B7, optional) maps
// intent id → llm_usage 总 token, 给每条意图标「这个方向烧了多少」; nil = 不标。
func compactIntents(ns []*db.Node, parentsOf, yieldsOf map[int64][]int64, tokens map[int64]int64) []map[string]any {
	out := make([]map[string]any, 0, len(ns))
	for _, n := range ns {
		var p map[string]any
		_ = json.Unmarshal(n.Payload, &p)
		m := map[string]any{"id": n.ID, "summary": p["summary"], "state": n.State}
		if len(tokens) > 0 {
			if tok, ok := tokens[n.ID]; ok && tok > 0 {
				m["tokens"] = tok
			}
		}
		// stop_reason（B1）：终态意图「为什么停」。planner 提示词要求用它区分
		// 「接续 vs 换方向」（exhausted=手段穷尽可接续 / blocked=传输故障可重试 /
		// stopped=被 kill），此前该字段在 DB 列里但态势从不携带——planner 每轮
		// 要么猜、要么对每条意图多花 1-3 次 node_detail 读图。
		if n.BlockedReason != "" {
			m["stop_reason"] = n.BlockedReason
		}
		// wall_ms（v0.4.27）：意图墙钟（runIntent 结算时落 payload），planner 直接看到
		// 「这条方向烧了多久」，配合 tokens 判断该不该续派。
		if wm, ok := p["wall_ms"].(float64); ok && wm > 0 {
			m["wall_ms"] = int64(wm)
		}
		if n.Inherited {
			m["source_task_id"] = n.SourceTaskID
			m["inherited"] = true
		}
		// asset_ids is the structured "which assets this direction covers" signal for
		// dedup; fall back to legacy payload keys (target_ids plural, then target_id
		// single) so intents stored before the rename still surface their anchors.
		if tg, ok := p["asset_ids"]; ok && tg != nil {
			m["asset_ids"] = tg
		} else if tg, ok := p["target_ids"]; ok && tg != nil {
			m["asset_ids"] = tg
		} else if tg, ok := p["target_id"]; ok && tg != nil && tg != "" {
			m["asset_ids"] = []any{tg}
		}
		if ps := parentsOf[n.ID]; len(ps) > 0 {
			m["parents"] = ps // 上游：本意图派生自哪些节点（多个事实可共同产生一个意图）
		}
		if ys := yieldsOf[n.ID]; len(ys) > 0 {
			m["yields"] = ys // 下游：本意图产生了哪些事实/发现
		}
		out = append(out, m)
	}
	return out
}

// ToolSet exposes the PG-backed dual graph (asset + exploration) to an LLM agent.
// One ToolSet is created per planner/worker run; per-run signals live here.
type ToolSet struct {
	findingRecorder FindingRecorder
	// artifactRecorder 由 host 注入（v0.5.0 证据附件）；nil=当前环境不支持存档。
	artifactRecorder ArtifactRecorder
	// ── 授权边界守卫（v0.4.63）──
	// 三个开关由 server 在装配时从设置读取（scope_write_guard / scope_inherit_writes /
	// notify_cross_task_dedup），改动下一条意图生效。全部关闭=回到软约束旧行为。
	ScopeWriteGuard      bool // 写回锚定守卫：fact/finding 只能锚定自有范围资产（默认开）
	ScopeInheritWrites   bool // 继承/来源任务范围资产也可写（默认关；串资产根因开关）
	CrossTaskNotifyDedup bool // 跨任务同指纹漏洞不再重复推送（默认开）
	// egressProxy / egressCA 是原生 HTTP 执行器（http_request/session_login）的出口：
	// 与 Bash 的 HTTP_PROXY 同源（记录 MITM 或全局代理），保证流量留痕一致。
	egressProxy string
	egressCA    string
	// lastScopeWarnings 是最近一次 record_fact 中 source/foreign 资产的提示，
	// 只回传、不阻断写入。
	lastScopeWarnings []string
	// lastLowNovelty 是本轮 record_fact 中「低新颖度」条数（与最近事实高度相似或
	// 没有任何 evidence）。这类写回仍会入库，但不会重置意图租约的零写回计时。
	lastLowNovelty int
	// runDir 是本次运行的专属工作目录（worker 在这里产生截图/样本），
	// save_evidence 的相对路径基准；由 Worker.Execute 注入。
	runDir string
	as     *db.AssetStore   // asset store (optional; nil = asset tools not available)
	cs     *db.CompanyStore // company store (optional)
	ts     *db.ExplorationStore
	worker string
	taskID int64 // PG tasks.id; 0 when unknown (tests / orchestrator cross-task reads)
	// coverageDisabled mirrors tasks.coverage_enabled=false. Stored inverted so the
	// zero value (all existing ToolSet constructions) means ENABLED — matching the
	// DB default (true). When true: graphOverviewData drops the coverage block, the
	// auto-scope hook (insertAssets) is skipped, and add_task_scope/list_untested_assets
	// are filtered out of the agent's tool list. The scope field stays regardless.
	coverageDisabled bool
	// ownerNode is the exploration node that writes attach to: assets this run
	// touches get anchored to it as lineage/provenance (NOT visibility — the asset
	// graph is global and shared). Worker = its claimed intent; planner = begin root.
	ownerNode int64
	GoalMet   bool
	Reason    string
	writes    WriteCounts
	// lastMissingAssets holds the asset ids referenced by the most recent
	// record_fact call that do NOT exist in the asset table. The tool result
	// reports them back so the model stops reusing a fabricated id.
	lastMissingAssets []int64
	// ── 派发节流（v0.4.68）──
	// intentQueue 返回 (阈值, worker 数)；nil = 不限制（测试/主 agent 场景）。
	intentQueue func() (int, int)
	// intentAdded 是本次 ToolSet 生命周期内新增的意图数（每轮规划一个新 ToolSet）。
	intentAdded int
	// retiredThisRun 是本轮规划已退役的意图数（护栏：每轮 6 条）。
	retiredThisRun int
	// intentRequiresGate 控制 requires_intents 串行闸门是否生效（默认关）。
	intentRequiresGate bool
	// killWork, if set, terminates a running work by intent id (engine callback,
	// wired by the planner). nil = the kill_work tool reports unavailable.
	killWork func(intentID int64) error
	// steerWork, if set, queues a mid-run course-correction for the work running an
	// intent id (engine callback, wired by the planner): the worker injects it before
	// its next tool call and re-plans, without being killed. nil = tool unavailable.
	steerWork func(intentID int64, msg string) error
	// enrich, if set, receives async auto-completion triggers (DNS resolve for a
	// domain, HTTP probe for a site). nil = no engine enrichment.
	enrich EnrichTrigger
	// notify, if set, wakes the task's planner after a graph change that should be
	// re-planned promptly (currently: a new hint). nil = no wake (the hint is still
	// stored and read on the next round triggered by other events). debounced.
	notify func()
	// notifyFinding, if set, wakes the task's planner when this run reports a finding,
	// carrying (intentID, summary) so the round can spell out which intent found what.
	// Wired for workers; nil elsewhere → falls back to notify (bare wake).
	notifyFinding func(intentID int64, summary string)
	// resumeTask, if set, revives the task after a graph change that should make a
	// stopped task run again (currently: set_goals adds a goal). It flips a terminal/
	// paused task back to running and (re)starts the engine loops — a plain notify()
	// can't, because the planner's terminal gate swallows wakes. Wired ONLY for the
	// main agent (human steering); nil for the goals decomposer and workers.
	resumeTask func()
	// notifyGoal, if set, wakes the planner AND records ONE "人新增了 N 个目标：…" trigger
	// for a whole set_goals call (batch-aware — one call, one trigger, not one per goal)
	// so the next round spells out the added goals (instead of the planner having to
	// spot new open goals in the overview). Wired ONLY for the main agent; nil for the
	// goals decomposer (round-0 has no running planner to inform) and workers → those
	// fall back to the bare notify.
	notifyGoal func(texts []string)
	// notifyHint, if set, wakes the planner AND records ONE "人新增了 N 条战略提示：…"
	// trigger for a whole add_hint call (batch-aware — one call, one trigger) so the next
	// round is told the round was fired by a new hint and spells the hint out, instead of
	// the planner having to spot it folded into the graph overview. Wired for the main
	// agent + cross-task orchestration; nil elsewhere → falls back to the bare notify.
	notifyHint func(texts []string)
	// attributions, if set, returns Guard failure-attribution stats (ok/blocked/error
	// counts + B6 recent samples, guard/guard.go AttributionStats) for graph_overview
	// 的 guard_attributions 块——planner 由此看到「这个任务被 WAF/拦截打回了 N 次、
	// 最近被拦的是哪几条命令」并换打法（v0.3.88 体检 N5 + B6 样本补完）。nil = 块省略。
	attributions func() map[string]any
}

// SetAttributions wires the Guard failure-attribution reader (see ToolSet.attributions).
func (t *ToolSet) SetAttributions(fn func() map[string]any) { t.attributions = fn }

// SetNotifyGoal wires the goal-add trigger callback (see ToolSet.notifyGoal). Set only
// by the main-agent chat, so runtime-added goals are announced to the planner by name.
func (t *ToolSet) SetNotifyGoal(fn func([]string)) { t.notifyGoal = fn }

// SetNotifyHint wires the hint-add trigger callback (see ToolSet.notifyHint). Set by
// the main-agent chat and cross-task orchestration, so a runtime-added hint fires a
// planner round announced by name instead of a bare wake.
func (t *ToolSet) SetNotifyHint(fn func([]string)) { t.notifyHint = fn }

// SetResumeTask wires the task-revive callback (see ToolSet.resumeTask). Set only by
// the main-agent chat, so runtime-added goals can pull a finished task back to running.
func (t *ToolSet) SetResumeTask(fn func()) { t.resumeTask = fn }

// SetNotify wires the planner-wake callback (see ToolSet.notify). Set by callers
// that hold the task handle (main-agent chat, cross-task orchestration).
func (t *ToolSet) SetNotify(fn func()) { t.notify = fn }

// SetNotifyFinding wires the finding-wake callback (see ToolSet.notifyFinding).
func (t *ToolSet) SetNotifyFinding(fn func(int64, string)) { t.notifyFinding = fn }

// EnrichTrigger is the enrichment engine seen from the tool layer (see package
// enrich). Kept as an interface here to avoid coupling agent → enrich.
type EnrichTrigger interface {
	ResolveDomain(id int64, host string)
	ProbeSite(id int64, url string)
}

// WriteCounts breaks down what a worker persisted this run, by node kind, so the
// engine can log an accurate "wrote back" summary instead of lumping assets and
// findings under "facts" (record_fact → Facts, insert_assets → Assets,
// report_finding → Findings; each element of a batch counts once).
type WriteCounts struct {
	Facts    int
	Assets   int
	Findings int
}

// Total is every node persisted this run, regardless of kind — the
// "explored but persisted nothing" signal (Total == 0).
func (w WriteCounts) Total() int { return w.Facts + w.Assets + w.Findings }

// String renders the per-kind breakdown for logs, e.g. "事实1 资产25 漏洞0".
func (w WriteCounts) String() string {
	return fmt.Sprintf("事实%d 资产%d 漏洞%d", w.Facts, w.Assets, w.Findings)
}

// Writes reports what this run wrote back, split by node kind (so the engine can
// tell "explored but persisted nothing" apart from a completed intent, and log an
// honest breakdown instead of calling assets/findings "facts").
func (t *ToolSet) Writes() WriteCounts { return t.writes }

func NewToolSet(ts *db.ExplorationStore, worker string) *ToolSet {
	return &ToolSet{ts: ts, worker: worker}
}

// SetTaskID sets the PG task id on this ToolSet so that report_finding can
// dual-write to the standalone findings table (which survives task deletion).
func (t *ToolSet) SetTaskID(id int64) { t.taskID = id }

// SetArtifactRecorder 注入证据附件存储（host 实现）。
func (t *ToolSet) SetArtifactRecorder(r ArtifactRecorder) { t.artifactRecorder = r }

// SetRunDir 注入本次运行的工作目录（save_evidence 的相对路径基准）。
func (t *ToolSet) SetRunDir(dir string) { t.runDir = dir }

// SetScopeFlags（v0.4.63）：授权边界守卫与跨任务去重的三个开关，
// 由 server 在装配时从设置读取；改动下一条意图生效。全部关=回到软约束旧行为。
func (t *ToolSet) SetScopeFlags(scopeGuard, scopeInheritWrites, crossTaskNotifyDedup bool) {
	t.ScopeWriteGuard = scopeGuard
	t.ScopeInheritWrites = scopeInheritWrites
	t.CrossTaskNotifyDedup = crossTaskNotifyDedup
}

// SetCoverageEnabled records whether this task has the asset-coverage feature on
// (default enabled). Passing false makes graphOverviewData omit the coverage block
// and DropCoverageTools filter the two coverage-only tools out of the agent's tool
// list. It does NOT stop scope accumulation: insertAssets' auto-scope hook runs
// either way, because task_scope is the task's range boundary (the filter basis for
// asset queries), not merely a coverage denominator.
func (t *ToolSet) SetCoverageEnabled(enabled bool) { t.coverageDisabled = !enabled }

// CoverageDisabled reports whether the coverage feature is off for this task.
func (t *ToolSet) CoverageDisabled() bool { return t.coverageDisabled }

// coverageOnlyTools are the LLM tools that only make sense when asset coverage is
// on. When the feature is off they are filtered out of the agent's tool list so
// they neither pollute the prompt nor let the model build a disabled denominator.
// add_task_scope is deliberately NOT here: task_scope is the task's range boundary
// (the filter basis for asset queries), not merely a coverage denominator, so the
// agents that own范围定义 keep it either way — in lockstep with insertAssets'
// auto-scope hook, which also runs regardless of the switch.
var coverageOnlyTools = map[string]bool{"list_untested_assets": true}

// DropCoverageTools returns tools with the coverage-only ones removed when this
// task has the feature disabled; otherwise it returns tools unchanged.
func (t *ToolSet) DropCoverageTools(tools []actool.CoreTool) []actool.CoreTool {
	if !t.coverageDisabled {
		return tools
	}
	out := tools[:0:0]
	for _, tool := range tools {
		if coverageOnlyTools[tool.Name()] {
			continue
		}
		out = append(out, tool)
	}
	return out
}

// Cross-task reuse: exported accessors returning the per-task tool logic bound to
// THIS ToolSet's store. Host-side orchestration tools build a ToolSet for an
// arbitrary task, then Call these — so cross-task reads/hint reuse the exact
// same logic as the in-task tools. (readTool ignores ToolContext, so Call(…,nil)
// is safe; add_hint is a writeTool but also doesn't deref the context here.)
func (t *ToolSet) GraphOverviewTool() actool.CoreTool      { return t.graphOverview() }
func (t *ToolSet) ListFindingsTool() actool.CoreTool       { return t.listFindings() }
func (t *ToolSet) GetWorkerTraceTool() actool.CoreTool     { return t.getWorkerTrace() }
func (t *ToolSet) ListWorkerTracesTool() actool.CoreTool   { return t.listWorkerTraces() }
func (t *ToolSet) SearchWorkerTracesTool() actool.CoreTool { return t.searchAllWorkerTraces() }
func (t *ToolSet) NodeDetailTool() actool.CoreTool         { return t.nodeDetail() }
func (t *ToolSet) AddHintTool() actool.CoreTool            { return t.addHint() }

// SetEnrich wires the async enrichment engine (DNS/HTTP auto-completion).
func (t *ToolSet) SetEnrich(e EnrichTrigger) { t.enrich = e }

// SetOwnerNode sets the exploration node that writes anchor to (worker: its
// intent node; planner/main: the begin root). Assets created/referenced while
// ownerNode is set are anchored to it as lineage (not visibility).
func (t *ToolSet) SetOwnerNode(id int64) { t.ownerNode = id }

// anchorOwner records a lineage edge from this run's owner node to an asset
// (no-op if unset). Provenance only — the asset graph is global and shared, so
// this no longer affects which assets a task can read.
func (t *ToolSet) anchorOwner(assetID int64) {
	if t.ts != nil && t.ownerNode > 0 && assetID > 0 {
		_ = t.ts.Anchor(t.ownerNode, assetID)
	}
}

// pid parses an id that may arrive as a JSON number or string ("" / 0 → 0).
func pid(raw json.RawMessage) int64 {
	if len(raw) == 0 {
		return 0
	}
	var n int64
	if json.Unmarshal(raw, &n) == nil {
		return n
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		v, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		return v
	}
	return 0
}

// pidList parses a list of ids (number|string), dropping zeros/invalids.
func pidList(raw []json.RawMessage) []int64 {
	var out []int64
	for _, r := range raw {
		if v := pid(r); v > 0 {
			out = append(out, v)
		}
	}
	return out
}

// maxIntentSummaryRunes 是意图 summary 的长度上限（rune 数）。
//
// 为什么要限：线上实测 205 条意图的 summary 平均 737 字、最长 2267 字——
// 远超「一句话描述方向」的设计意图。超长带来两个具体问题：
//
//  1. **planner 的判断会失真**。planner 靠 summary 判断「这个方向是不是快
//     挖到了」——summary 越长、细节越多，planner 越容易觉得「信息这么丰富，
//     肯定快到了，再给一次机会」。而实测线上 exhausted(99) 远多于 done(18)，
//     接续链还出现了三代（#635→#578→#660）。长 summary → 更容易续派 → 意图更长
//     → summary 更长，这是个正反馈。
//  2. **写回被挤掉**。summary 越长，worker 花在组织语言上的 token 越多，
//     而 detail 字段才是放细节的地方。
//
// 400 字的由来：中文一句完整的技术描述大约 100-200 字，400 字足够写清
// 「目标 + 做什么 + 为什么值得做 + 上次到哪了」——还能带上一次接续的上下文。
// 超过这个长度的信息量，多出来的基本是重复叙述。
//
// 超限的处理是**截断并保留头部**（目标+做什么在开头），而不是拒绝——拒绝会让
// planner 白跑一轮拿不到任何意图，代价更大。截断后末尾追加标记，让 planner
// 知道这里被截过。
const maxIntentSummaryRunes = 400

// clampIntentSummary 把过长的 summary 截到上限，头部保留（目标+做什么在
// 开头），末尾追加截断标记。
func clampIntentSummary(s string) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= maxIntentSummaryRunes {
		return s
	}
	head := string([]rune(s)[:maxIntentSummaryRunes])
	return head + "…（summary 超长已截断，细节请写进 fact 的 detail）"
}

// maxContinuationDepth 是同一条方向上允许的最大接续代数。
//
// 3 的由来：接续不是坏事——一条方向被预算掐断、但确实有明确的下一步时，
// 接一次是对的（实测线上 205 条意图里 26 条是接续）。问题在于**没有闸**：
// 线上出现过三代接续（#635 → #578 → #660），每一代都从零重建上下文、重复读
// 同一批文件、重复扫同一批资产。
//
// 3 意味着：一条方向最多被接续 3 次（首探 + 3 次接续 = 4 代）。到这个数还
// 没拿到结果，说明问题不在「时间不够」而在「这条路本身不通」或「打法不对」，
// 该换方向了，不该继续接。
//
// 刻意不取 2：接续两次是常见且合理的（被重启打断 + 被预算掐断），卡太紧会
// 误杀正当的深挖。
const maxContinuationDepth = 3

// continuationDepthOf 读一个意图节点上记录的接续代数。
//
// 老的意图（功能上线前创建的）payload 里没有这个字段，返回 1（当作首探）——
// 它们本来就没有结构化的接续关系，不该被代数限制误伤。
func continuationDepthOf(n *db.Node) int {
	if n == nil {
		return 1
	}
	var p map[string]any
	if err := json.Unmarshal(n.Payload, &p); err != nil {
		return 1
	}
	switch v := p["continuation_depth"].(type) {
	case float64:
		if v >= 1 {
			return int(v)
		}
	case int:
		if v >= 1 {
			return v
		}
	}
	return 1
}

func obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}
func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func intp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}
func idp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func readTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

func writeTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

// readExpTool / writeExpTool build a domain tool whose handler dereferences the
// task-bound ExplorationStore. Two ToolSets carry a nil store: the catalog's
// seed-only shell (never called) and the server-level one behind buildDomainReg,
// which the tools table can bind to ANY agent — including ones that never run
// inside a task (auto/pentest/reporter/自定义 agent/旁路提问). Refusing there
// keeps a mis-bound tool a bad tool call; without the guard it was a nil deref,
// and tool handlers run on the harness's own goroutine, so the panic is out of
// reach of every recover() in the server and kills the whole process.
func (t *ToolSet) readExpTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return readTool(name, desc, schema, t.needExploration(name, run))
}

func (t *ToolSet) writeExpTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return writeTool(name, desc, schema, t.needExploration(name, run))
}

// needExploration wraps a handler so it only runs with an exploration store.
// Tools that degrade more usefully than "unavailable" (report_finding points at
// add_task_hint, set_goals/set_constraints at the task itself) keep their own
// bespoke guard instead.
func (t *ToolSet) needExploration(name string, run func(context.Context, json.RawMessage) (actool.Result, error)) func(context.Context, json.RawMessage) (actool.Result, error) {
	return func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		if t.ts == nil {
			return actool.Errorf(name + " 需要任务上下文（探索图）：当前 agent 不在某个任务内运行，取不到任务的探索图，该工具不可用。请在任务内使用它，或改用带 task_id 的跨任务读取工具（get_task_node_detail / list_task_findings / get_task_graph 等）。"), nil
		}
		return run(ctx, in)
	}
}

func jsonResult(v any) (actool.Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return actool.Text(string(b)), nil
}

// --- read tools (planner + worker) ---

func (t *ToolSet) graphOverview() actool.CoreTool {
	return t.readExpTool("graph_overview",
		"(探索链路图)探索态势蒸馏摘要：资产计数、无接口的站点、frontier、发现、hints(人类/主 agent 的战略提示，生成意图时须纳入)。规划时先调它。",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			return jsonResult(t.graphOverviewData())
		})
}

// graphOverviewData computes the distilled situational snapshot shared by the
// graph_overview tool and the planner's wake-up prompt (which pre-injects it so
// the model needn't spend a turn calling the tool — every plan round starts with
// an empty context and always needs this first).
func (t *ToolSet) graphOverviewData() map[string]any {
	out := map[string]any{}
	// goals summary folded in so the planner needn't call list_goals each round.
	goals, _ := t.ts.ListByKind(db.KindGoal, 100)
	gsum := make([]map[string]any, 0, len(goals))
	for _, g := range goals {
		var p map[string]any
		_ = json.Unmarshal(g.Payload, &p)
		gsum = append(gsum, map[string]any{"id": g.ID, "state": g.State, "text": p["text"]})
	}
	out["goals"] = gsum
	// hints: 人类/主 agent 通过 add_hint 挂上图的战略提示；folded in so the
	// planner reads them every round when generating intents (否则只写不读).
	hints, _ := t.ts.ListByKind(db.KindHint, 50)
	hsum := make([]map[string]any, 0, len(hints))
	for _, h := range hints {
		var p map[string]any
		_ = json.Unmarshal(h.Payload, &p)
		hint := map[string]any{"id": h.ID, "state": h.State, "text": p["text"]}
		if findingTrafficBindingEnabled() && p["traffic_refs"] != nil {
			hint["traffic_refs"] = p["traffic_refs"]
		}
		hsum = append(hsum, hint)
	}
	out["hints"] = hsum
	// lineage from the exploration edges: an intent's parents (what it
	// derived_from — possibly several facts combined) and its yields (the
	// facts/findings it produced). factFrom maps a fact → the intent that
	// produced it. This is the relationship layer the flat lists lacked.
	edges, _ := t.ts.Edges(5000)
	parentsOf := map[int64][]int64{}
	yieldsOf := map[int64][]int64{}
	factFrom := map[int64]int64{}
	for _, e := range edges {
		switch e.Rel {
		case db.RelDerivedFrom, db.RelSpawns: // upstream: derived_from (fact/finding/intent→intent) or spawns (origin fact→goal, legacy begin→intent)
			parentsOf[e.To] = append(parentsOf[e.To], e.From)
		case db.RelYields: // intent --yields--> fact/finding
			yieldsOf[e.From] = append(yieldsOf[e.From], e.To)
			factFrom[e.To] = e.From
		}
	}
	// cold-digest §6: members folded into an active digest are shown via cold_digests
	// (below), not the flat recent_* lists. `covered` maps member id → its digest id.
	// §6 render-time revival check: a covered member that has become hot again (a new
	// intent derived from it) must reappear this round — so `hidden` folds a member out
	// only when it is covered AND still cold.
	covered, _ := t.ts.CoveredMembers()
	// Render-time hot set (ancestor of a live intent / fact under a live intent).
	// §6 revival check: a covered member that revived (now hot) must NOT stay folded
	// — hidden() only folds a member out when it is covered AND still cold. Computed
	// every round (cheap for real graph sizes); nil map degrades safely.
	var hotAtRender map[int64]bool
	if cg, _, err := loadColdGraph(t.ts); err == nil {
		hotAtRender = cg.hotSet()
	}
	hidden := func(id int64) bool { _, c := covered[id]; return c && !hotAtRender[id] }
	// B7:意图级 token（llm_usage 按 session 后缀 i<n> 记账）。一次拉全图,给
	// open/running/recent_done 的每条意图标 tokens —— planner/人在环路直接看到
	// 「哪个方向烧了多少」,是判断该不该续派最直接的账。
	tokByIntent, _ := t.ts.TokenByIntent()
	tokens := make(map[int64]int64, len(tokByIntent))
	for _, it := range tokByIntent {
		tokens[it.IntentID] = it.InputTokens + it.OutputTokens
	}
	const openIntentsCap = 30
	fr, _ := t.ts.Frontier(openIntentsCap) // priority DESC, id ASC —— 优先级最高的前 N 条；真实总数见 frontier_open
	out["open_intents"] = compactIntents(fr, parentsOf, yieldsOf, tokens)
	all, _ := t.ts.ListByKind(db.KindIntent, 300)
	var running, recentDone []*db.Node
	for _, n := range all {
		switch n.State {
		case "running":
			running = append(running, n)
		case "done", "blocked", "exhausted":
			if hidden(n.ID) {
				continue // in a cold_digest and still cold — shown via cold_digests (§6.2)
			}
			recentDone = append(recentDone, n) // 最新在前（all 按 id 降序）；折叠的已剔除，输出时截最新 N
		}
	}
	out["running_intents"] = compactIntents(running, parentsOf, yieldsOf, tokens)
	// done_intents_total：已结束意图（done/blocked/exhausted）总数，与 recent_done_intents
	// 平行命名——后者只是它的最新窗口截断视图。两键并排即自描述："看到的是 N/总数"，
	// 让 planner 去重时别把"没显示"当成"没派过"，无需在提示词里另行解释。
	if dt, err := t.ts.CountFinishedIntents(); err == nil {
		out["done_intents_total"] = dt
	}
	// frontier_open：开放意图真实总数（open_intents 只是其中优先级最高的前 N 条截断视图）。
	if fo, err := t.ts.CountOpenIntents(); err == nil {
		out["frontier_open"] = fo
	} else {
		out["frontier_open"] = len(fr)
	}
	// findings (confirmed vulns) and facts (worker exploration results) are
	// now distinct node kinds. recent_facts surfaces fact summaries (esp.
	// negative results) so the planner sees them in one call; full content
	// via node_detail(id).
	vulnNodes, _ := t.ts.ListByKind(db.KindFinding, 1000)
	factNodes, _ := t.ts.ListByKind(db.KindFact, 1000) // newest first
	out["findings_total"] = len(vulnNodes)             // 确认漏洞总数（目标判定看它）；明细见 finding_list（最新一窗）
	out["facts"] = len(factNodes)                      // 探索事实/结论数（含否定结论）
	// findings 是任务里最高价值的产物 → 概览带最新一窗（≤10 条，vulnNodes 已按 id 降序即最新在前），
	// 让 planner 每轮判目标时一眼看到最近确认的漏洞；全量/更早的用 list_findings 取。
	// 每条只留 {id, summary, from_intent?}：from_intent 是产生本漏洞的意图。
	// evidence/assets/vulnclass/severity/state 等仍可用 list_findings / node_detail(id) 取。
	const findingListCap = 10
	findingList := make([]map[string]any, 0, findingListCap)
	for _, n := range vulnNodes {
		if len(findingList) >= findingListCap {
			break
		}
		var fp map[string]any
		_ = json.Unmarshal(n.Payload, &fp)
		m := map[string]any{"id": n.ID, "summary": fp["summary"]}
		if from := factFrom[n.ID]; from > 0 {
			m["from_intent"] = from // 本漏洞由哪个意图产生
		}
		findingList = append(findingList, m)
	}
	out["finding_list"] = findingList
	// recent_facts：非折叠事实里最新的一窗（≤N，factNodes 按 id 降序即最新在前）。已折进
	// digest 且仍冷的（hidden）走 cold_digests，不在此重复。每条 {id, summary, from_intent?,
	// confidence?}；evidence 等详情用 node_detail(id)。更早的用 list_facts 翻。
	const recentFactsCap = 20
	recentFacts := make([]map[string]any, 0, recentFactsCap)
	for _, n := range factNodes {
		if len(recentFacts) >= recentFactsCap {
			break
		}
		if hidden(n.ID) {
			continue // 已折进 digest 且仍冷 —— 见 cold_digests
		}
		m := compactNode(n)
		if from := factFrom[n.ID]; from > 0 {
			m["from_intent"] = from // 本事实由哪个意图产生
		}
		// confidence 带进概览：让规划者一眼看出哪条结论只是 inferred（尤其否定结论
		// 别当铁案）；evidence 较长，留给 node_detail(id)。
		var fp map[string]any
		if json.Unmarshal(n.Payload, &fp) == nil {
			if c, ok := fp["confidence"].(string); ok && c != "" {
				m["confidence"] = c
			}
		}
		recentFacts = append(recentFacts, m)
	}
	out["recent_facts"] = recentFacts
	// recent_done_intents：非折叠的已结束意图里最新的一窗（≤N，recentDone 已按 id 降序）。
	// 更早的看 done_intents_total 计数 + node_detail(id)。
	const recentDoneCap = 12
	if len(recentDone) > recentDoneCap {
		recentDone = recentDone[:recentDoneCap]
	}
	out["recent_done_intents"] = compactIntents(recentDone, parentsOf, yieldsOf, tokens)
	// 收官态势(边际收益):最近 N 轮规划后,全任务有没有新的 fact/finding 产出。
	// 连续 ≥3 轮零新产出且 frontier 空 → 提示用 goal_met 收官(预算保护:
	// 这时候继续派大概率烧 token 无产出)。程序算好放在这里,planner 不用自己数。
	if t.ts != nil && t.taskID > 0 {
		out["stall"] = t.stallOverview()
	}
	// Guard 归因(ok/blocked/error 计数):blocked 高=目标在防(WAF/拦截规则),继续
	// 同款打法是烧 token;error 高=工具/环境在坏。nil(未接线,如测试构造)=块省略。
	if t.attributions != nil {
		if att := t.attributions(); len(att) > 0 {
			out["guard_attributions"] = att
		}
	}
	// 宿主工具体检:本机 PATH 可直接经 Bash 调用的工具(可用/缺失+安装提示),
	// 派意图选手段以家底为准——二进制部署形态下系统里有什么就能用什么。
	out["tools"] = hosttools.Summary()
	// cold-digest §6.1: 折叠冷区的 digest body，按最新成员时间降序取前 N；被截的更旧 digest
	// 只给裸 id（仍可 expand_digest 展开），避免冷区唯一出口被无限拉长。
	const coldDigestsCap = 15
	if cds, more := coldDigestsRecent(t.ts, coldDigestsCap); len(cds) > 0 {
		out["cold_digests"] = cds // [{id, body, member_count}] —— 直接读 body (§6.1)
		if len(more) > 0 {
			out["cold_digests_more"] = more // 被截断的更旧 digest 的 id；用 expand_digest(id) 展开
		}
	}
	// the original task (root) so the planner always has it, not just the
	// decomposed goals.
	if description, goal, err := t.ts.Root(); err == nil {
		out["task"] = map[string]any{"description": description, "goal": goal}
	}
	// Direct source tasks are a live, read-only blackboard view. Keep their
	// summaries in a separate field so their intents never enter this task's
	// frontier or get mistaken for locally claimable work.
	out["related_tasks"] = t.relatedTaskOverviews()
	// coverage：粗略的资产测试覆盖度参考——范围(task_scope)内的资产里，被 fact 碰过的
	// 占比 + by_type(按类型的 总数/已测)。要看未测的具体资产由 agent 按需调 list_untested_assets 自行判断。仅任务上下文有。
	// 资产覆盖度功能关闭时(coverageDisabled)：只保留 host_count(目标主机数的感知信息)，
	// 丢弃 denominator/tested/pct/by_type/note 等覆盖度度量，避免污染上下文、也不诱导
	// 已隐藏的 add_task_scope/list_untested_assets。
	if t.as != nil && t.ts != nil && t.taskID > 0 {
		{
			m := map[string]any{}
			if !t.coverageDisabled {
				if cov, err := t.as.TaskCoverageWithSources(t.taskID); err == nil {
					m["denominator"] = cov.Denominator
					m["tested"] = cov.Tested
					m["by_type"] = cov.ByType
					m["note"] = "coverage资产测试覆盖度（包括接口等各种相关资产），粗略估计、仅供参考：包含当前任务与直接关联任务的 scope、事实锚点；关联 scope 只读。容器型资产/大量枚举会让它偏低，勿据此认为已测完；可用 add_task_scope 增补本任务范围、list_untested_assets 看未测资产【通常不调用list_untested_assets，按照任务推进即可】；"
					if cov.Denominator == 0 {
						m["pct"] = nil
						m["status"] = "范围未锚定"
					} else {
						m["pct"] = cov.Pct
					}
				}
			}
			if hosts, err := t.as.HostsByTaskWithSources(t.taskID); err == nil {
				// 只给主机总数，不再把 host 列表平铺进 graph_overview（大范围任务里那是每轮
				// 都重复携带的大量字符串，对规划决策价值有限）；具体主机按需 list_assets 查。
				m["host_count"] = len(hosts)
			}
			if len(m) > 0 {
				out["coverage"] = m
			}
		}
	}
	return out
}

// workerOverviewData is the worker-start lean situational snapshot. 任务 5 实测
// worker 占全部 token 的 76.8%、单意图均 ≈300 万 input——每个 worker 启动都全量
// 重建 planner 级态势（冷图×2、全血缘 edges、意图 token 台账、覆盖 CTE 算完即删、
// cold_digests 整 body），再原样注入启动消息，是最大的固定浪费。worker 只需要
// 「别人发现了什么」做去重与联想：goals/hints/计数/最新 findings/facts/根任务/
// host 工具家底。规划专用字段（frontier、running/recent_done intents、cold 折叠、
// stall、guard 归因、related_tasks、lineage、TokenByIntent、coverage）全部不进
// worker 视图——既省每次启动的重建计算，也把注入前缀压到最短。
func (t *ToolSet) workerOverviewData() map[string]any {
	out := map[string]any{}
	goals, _ := t.ts.ListByKind(db.KindGoal, 100)
	gsum := make([]map[string]any, 0, len(goals))
	for _, g := range goals {
		var p map[string]any
		_ = json.Unmarshal(g.Payload, &p)
		gsum = append(gsum, map[string]any{"id": g.ID, "state": g.State, "text": p["text"]})
	}
	out["goals"] = gsum
	hints, _ := t.ts.ListByKind(db.KindHint, 20)
	hsum := make([]map[string]any, 0, len(hints))
	for _, h := range hints {
		var p map[string]any
		_ = json.Unmarshal(h.Payload, &p)
		hsum = append(hsum, map[string]any{"id": h.ID, "state": h.State, "text": p["text"]})
	}
	out["hints"] = hsum
	vulnNodes, _ := t.ts.ListByKind(db.KindFinding, 1000)
	factNodes, _ := t.ts.ListByKind(db.KindFact, 1000)
	out["findings_total"] = len(vulnNodes)
	out["facts"] = len(factNodes)
	const findingListCap = 10
	findingList := make([]map[string]any, 0, findingListCap)
	for _, n := range vulnNodes {
		if len(findingList) >= findingListCap {
			break
		}
		var fp map[string]any
		_ = json.Unmarshal(n.Payload, &fp)
		findingList = append(findingList, map[string]any{"id": n.ID, "summary": fp["summary"]})
	}
	out["finding_list"] = findingList
	const recentFactsCap = 20
	recentFacts := make([]map[string]any, 0, recentFactsCap)
	for _, n := range factNodes {
		if len(recentFacts) >= recentFactsCap {
			break
		}
		m := compactNode(n)
		var fp map[string]any
		if json.Unmarshal(n.Payload, &fp) == nil {
			if c, ok := fp["confidence"].(string); ok && c != "" {
				m["confidence"] = c
			}
		}
		recentFacts = append(recentFacts, m)
	}
	out["recent_facts"] = recentFacts
	out["tools"] = hosttools.Summary()
	if t.as != nil && t.taskID > 0 {
		if hosts, err := t.as.HostsByTaskWithSources(t.taskID); err == nil {
			out["host_count"] = len(hosts)
		}
	}
	if description, goal, err := t.ts.Root(); err == nil {
		out["task"] = map[string]any{"description": description, "goal": goal}
	}
	return out
}

func inheritedMap(m map[string]any, sourceTaskID int64) map[string]any {
	m["source_task_id"] = sourceTaskID
	m["inherited"] = true
	return m
}

const (
	relatedOverviewTotalTextRunes      = 48_000
	relatedOverviewMaxTextPerSource    = 8_000
	relatedOverviewMaxGoalsPerSource   = 8
	relatedOverviewMaxHintsPerSource   = 6
	relatedOverviewMaxFactsPerSource   = 12
	relatedOverviewMaxFindingsPerTask  = 6
	relatedOverviewMaxIntentsPerTask   = 8
	relatedOverviewMaxScopePerSource   = 12
	relatedOverviewMaxDigestsPerSource = 6
)

// overviewTextBudget bounds inherited prompt text while preserving a fair slice
// for every direct source. Full evidence remains available through the on-demand
// read tools, so truncation here does not discard persisted blackboard data.
type overviewTextBudget struct {
	remaining int
	truncated bool
}

func relatedOverviewBudgetForSources(sourceCount int) int {
	if sourceCount <= 0 {
		return 0
	}
	if sourceCount > db.MaxTaskSourceCount {
		sourceCount = db.MaxTaskSourceCount
	}
	perSource := relatedOverviewTotalTextRunes / sourceCount
	if perSource > relatedOverviewMaxTextPerSource {
		perSource = relatedOverviewMaxTextPerSource
	}
	return perSource
}

func (b *overviewTextBudget) take(value any, fieldLimit int) string {
	var text string
	switch value := value.(type) {
	case string:
		text = strings.TrimSpace(value)
	case nil:
		return ""
	default:
		text = strings.TrimSpace(fmt.Sprint(value))
	}
	if text == "" {
		return ""
	}
	if b.remaining <= 0 || fieldLimit <= 0 {
		b.truncated = true
		return ""
	}
	runes := []rune(text)
	limit := fieldLimit
	if limit > b.remaining {
		limit = b.remaining
	}
	if len(runes) > limit {
		b.truncated = true
		if limit == 1 {
			text = "…"
		} else {
			text = string(runes[:limit-1]) + "…"
		}
		runes = []rune(text)
	}
	b.remaining -= len(runes)
	return text
}

func recentTerminalIntents(store *db.ExplorationStore, limit int) []*db.Node {
	if limit <= 0 {
		return []*db.Node{}
	}
	const batch = 300
	cursor := int64(0)
	out := make([]*db.Node, 0, limit)
	for len(out) < limit {
		page, more, err := store.ListByKindPage(db.KindIntent, cursor, batch)
		if err != nil || len(page) == 0 {
			break
		}
		for _, intent := range page {
			switch intent.State {
			case "done", "blocked", "exhausted", "stopped":
				out = append(out, intent)
			}
			if len(out) >= limit {
				break
			}
		}
		if !more {
			break
		}
		cursor = page[len(page)-1].ID
	}
	return out
}

// relatedTaskOverviews distills persistent blackboard state from direct source
// tasks. It intentionally reads each source's local store methods, never its own
// related sources, so inheritance is one level only.
func (t *ToolSet) relatedTaskOverviews() []map[string]any {
	sources, err := t.ts.DirectSourceStores()
	if err != nil {
		return []map[string]any{}
	}
	if len(sources) > db.MaxTaskSourceCount {
		sources = sources[:db.MaxTaskSourceCount]
	}
	perSourceTextBudget := relatedOverviewBudgetForSources(len(sources))
	out := make([]map[string]any, 0, len(sources))
	for _, source := range sources {
		ts := source.Store
		// §2 cross-task: render the source task's OWN folded view — fold out the
		// members it has already folded, and surface its cold_digests read-only.
		hidden := hiddenMembersFor(ts)
		budget := overviewTextBudget{remaining: perSourceTextBudget}
		item := map[string]any{
			"source_task_id": source.Task.TaskID,
			"inherited":      true,
			"task": map[string]any{
				"description": budget.take(source.Task.Description, 800),
				"goal":        budget.take(source.Task.Goal, 800),
				"status":      source.Task.Status,
			},
		}
		stats, statsErr := ts.Stats()

		edges, _ := ts.Edges(5000)
		parentsOf := map[int64][]int64{}
		yieldsOf := map[int64][]int64{}
		factFrom := map[int64]int64{}
		for _, edge := range edges {
			switch edge.Rel {
			case db.RelDerivedFrom, db.RelSpawns:
				parentsOf[edge.To] = append(parentsOf[edge.To], edge.From)
			case db.RelYields:
				yieldsOf[edge.From] = append(yieldsOf[edge.From], edge.To)
				factFrom[edge.To] = edge.From
			}
		}

		goals, _ := ts.ListByKind(db.KindGoal, relatedOverviewMaxGoalsPerSource)
		goalSummary := make([]map[string]any, 0, len(goals))
		for _, goal := range goals {
			var payload map[string]any
			_ = json.Unmarshal(goal.Payload, &payload)
			goalSummary = append(goalSummary, inheritedMap(map[string]any{
				"id": goal.ID, "state": goal.State, "text": budget.take(payload["text"], 400),
			}, source.Task.TaskID))
		}
		item["goals"] = goalSummary

		hints, _ := ts.ListByKind(db.KindHint, relatedOverviewMaxHintsPerSource)
		hintSummary := make([]map[string]any, 0, len(hints))
		for _, hint := range hints {
			var payload map[string]any
			_ = json.Unmarshal(hint.Payload, &payload)
			hintSummary = append(hintSummary, inheritedMap(map[string]any{
				"id": hint.ID, "state": hint.State, "text": budget.take(payload["text"], 400),
			}, source.Task.TaskID))
		}
		item["hints"] = hintSummary

		facts, _ := ts.ListByKind(db.KindFact, relatedOverviewMaxFactsPerSource)
		findings, _ := ts.ListByKind(db.KindFinding, relatedOverviewMaxFindingsPerTask)
		intentNodes, _ := ts.ListByKind(db.KindIntent, 300)
		terminalIntent := make(map[int64]bool, len(intentNodes))
		for _, intent := range intentNodes {
			terminalIntent[intent.ID] = inheritedIntentSummaryState(intent.State)
		}
		item["facts"] = len(facts)
		item["findings"] = len(findings)
		if statsErr == nil {
			item["facts"] = stats[db.KindFact]
			item["findings"] = stats[db.KindFinding]
			if stats[db.KindGoal] > len(goals) || stats[db.KindHint] > len(hints) ||
				stats[db.KindFact] > len(facts) || stats[db.KindFinding] > len(findings) {
				budget.truncated = true
			}
		}
		recentFindings := make([]map[string]any, 0, len(findings))
		for _, finding := range findings {
			entry := inheritedMap(compactFinding(finding), source.Task.TaskID)
			entry["summary"] = budget.take(entry["summary"], 400)
			recentFindings = append(recentFindings, entry)
		}
		item["recent_findings"] = recentFindings
		recentFacts := make([]map[string]any, 0, len(facts))
		for _, fact := range facts {
			if hidden(fact.ID) {
				continue // folded into this source's cold_digests — shown there (§2/§6.2)
			}
			m := inheritedMap(compactNode(fact), source.Task.TaskID)
			m["summary"] = budget.take(m["summary"], 400)
			if from := factFrom[fact.ID]; from > 0 && terminalIntent[from] {
				m["from_intent"] = from
			}
			var payload map[string]any
			if json.Unmarshal(fact.Payload, &payload) == nil {
				if confidence, ok := payload["confidence"].(string); ok && confidence != "" {
					m["confidence"] = confidence
				}
			}
			recentFacts = append(recentFacts, m)
		}
		item["recent_facts"] = recentFacts

		recentDoneRaw := recentTerminalIntents(ts, relatedOverviewMaxIntentsPerTask)
		recentDone := recentDoneRaw[:0] // in-place filter: drop this source's folded intents (§2)
		for _, intent := range recentDoneRaw {
			if hidden(intent.ID) {
				continue
			}
			recentDone = append(recentDone, intent)
		}
		for _, intent := range recentDone {
			intent.Inherited = true
			intent.SourceTaskID = source.Task.TaskID
		}
		intentResults := compactIntents(recentDone, parentsOf, yieldsOf, nil)
		for i, intent := range recentDone {
			intentResults[i]["summary"] = budget.take(intentResults[i]["summary"], 400)
			acts, _, err := ts.ActivityPageForTerminalIntent(intent.ID, 0, 20)
			if err != nil {
				continue
			}
			var resultSummary, textFallback string
			for _, activity := range acts {
				switch activity.Kind {
				case "result":
					resultSummary = activity.Summary
				case "text":
					textFallback = activity.Summary
				}
			}
			if resultSummary == "" {
				resultSummary = textFallback
			}
			if resultSummary != "" {
				intentResults[i]["result_summary"] = budget.take(resultSummary, 800)
			}
		}
		item["recent_intent_results"] = intentResults
		// §2 cross-task: the source task's folded cold region, read-only, newest-member
		// first & capped like the current task's. Members (and overflow digests) are
		// resolvable via expand_digest(id)/node_detail(id), which search source tasks.
		if cds, more := coldDigestsRecent(ts, relatedOverviewMaxDigestsPerSource); len(cds) > 0 {
			for _, cd := range cds {
				cd["inherited"] = true
				cd["source_task_id"] = source.Task.TaskID
			}
			item["cold_digests"] = cds
			if len(more) > 0 {
				item["cold_digests_more"] = more // 被截断的更旧 digest 的 id；expand_digest(id) 展开
			}
		}
		if statsErr == nil {
			item["node_stats"] = stats
		}

		if t.as != nil {
			if scopeRows, err := t.as.ListTaskScope(source.Task.TaskID); err == nil && len(scopeRows) > 0 {
				scopeCount := len(scopeRows)
				if len(scopeRows) > relatedOverviewMaxScopePerSource {
					scopeRows = scopeRows[:relatedOverviewMaxScopePerSource]
					budget.truncated = true
				}
				scope := make([]map[string]any, 0, len(scopeRows))
				for _, row := range scopeRows {
					entry := map[string]any{"kind": row.Kind, "source": budget.take(row.Source, 300)}
					switch {
					case row.Domain != "":
						entry["value"] = budget.take(row.Domain, 400)
					case row.Net != "":
						entry["value"] = budget.take(row.Net, 400)
					case row.Value != "":
						entry["value"] = budget.take(row.Value, 400)
					case row.CompanyID != nil:
						entry["company_id"] = *row.CompanyID
					}
					scope = append(scope, entry)
				}
				item["asset_scope"] = scope
				item["asset_scope_count"] = scopeCount
			}
			if coverage, err := t.as.TaskCoverage(source.Task.TaskID, source.Task.ExplorationID); err == nil {
				item["asset_coverage"] = map[string]any{
					"denominator": coverage.Denominator,
					"tested":      coverage.Tested,
					"pct":         coverage.Pct,
					"by_type":     coverage.ByType,
				}
			}
		}
		if budget.truncated {
			item["summary_truncated"] = true
		}
		out = append(out, item)
	}
	return out
}

func inheritedIntentSummaryState(state string) bool {
	switch state {
	case "done", "blocked", "exhausted", "stopped":
		return true
	default:
		return false
	}
}

// compactNode distills any exploration node to id + summary + state, dropping the
// big detail/evidence (fetch that on demand via node_detail).
func compactNode(n *db.Node) map[string]any {
	var p map[string]any
	_ = json.Unmarshal(n.Payload, &p)
	m := map[string]any{"id": n.ID, "state": n.State, "summary": p["summary"]}
	if n.Inherited {
		inheritedMap(m, n.SourceTaskID)
	}
	return m
}

// compactFinding is compactNode plus the vuln-specific vulnclass/severity.
func compactFinding(n *db.Node) map[string]any {
	var p map[string]any
	_ = json.Unmarshal(n.Payload, &p)
	m := map[string]any{"id": n.ID, "state": n.State, "summary": p["summary"]}
	if n.Inherited {
		inheritedMap(m, n.SourceTaskID)
	}
	if vc, ok := p["vulnclass"]; ok && vc != nil && vc != "" {
		m["vulnclass"] = vc
	}
	if sv, ok := p["severity"]; ok && sv != nil && sv != "" {
		m["severity"] = sv
	}
	return m
}

func (t *ToolSet) listFindings() actool.CoreTool {
	return t.readExpTool("list_findings", "列本任务及直接关联任务的【确认漏洞】(紧凑：id+task_id+intent_id+vulnclass+severity+摘要+状态)。关联任务条目带 source_task_id/inherited=true 且只读。这里只含漏洞；普通探索事实用 list_facts，详情用 node_detail(id)。",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			f, _ := t.ts.ListByKindWithSources(db.KindFinding, 500)
			if err := t.ts.PopulateFindingTrafficIDs(f); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			intentOf, _ := t.ts.FindingIntentsWithSources() // finding id -> 产生它的 intent id
			taskID := t.taskID
			if taskID <= 0 {
				taskID, _ = t.ts.TaskID()
			}
			out := make([]map[string]any, 0, len(f))
			for _, n := range f {
				m := compactFinding(n)
				if n.FindingID > 0 {
					m["finding_id"], m["finding_node_id"], m["traffic_count"] = n.FindingID, n.ID, n.TrafficCount
				}
				if n.Inherited {
					m["task_id"] = n.SourceTaskID
				} else {
					m["task_id"] = taskID
				}
				if iid, ok := intentOf[n.ID]; ok {
					m["intent_id"] = iid
				}
				out = append(out, m)
			}
			return jsonResult(out)
		})
}

// factsPageSize is the default page size for list_facts. Facts pile up on long
// tasks; returning all of them at once (the old behaviour) could blow up the
// context, so default to the newest page and let the agent page/filter for more.
const factsPageSize = 20

func (t *ToolSet) listFacts() actool.CoreTool {
	return t.readExpTool("list_facts", "分页列本任务及直接关联任务的【探索事实/结论】，最新在前(紧凑：id+摘要+状态，摘要过长会截断，全文用 node_detail(id))。参数均可选：limit(默认 20，上限 100)、before(游标，传上一页返回的 next_before 取更旧的一页；省略/0=最新一页)、q(按摘要关键词过滤)。返回 {facts, total, has_more, next_before}：total 是过滤后的总数，has_more=true 时用 next_before 继续翻页。关联任务条目带 source_task_id/inherited=true 且只读。漏洞看 list_findings。",
		obj(map[string]any{
			"limit":  intp("返回条数，默认 20，上限 100"),
			"before": intp("分页游标：只返回 id 小于该值的更旧事实；省略或 0 = 最新一页"),
			"q":      str("按事实摘要关键词过滤（不区分大小写）；省略 = 不过滤"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Limit  int    `json:"limit"`
				Before int64  `json:"before"`
				Q      string `json:"q"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 {
				limit = factsPageSize
			}
			if limit > 100 {
				limit = 100
			}
			f, hasMore, total, err := t.ts.ListByKindPageWithSources(db.KindFact, a.Before, limit, strings.TrimSpace(a.Q))
			if err != nil {
				return actool.Result{}, err
			}
			out := make([]map[string]any, 0, len(f))
			for _, n := range f {
				out = append(out, compactFact(n))
			}
			res := map[string]any{"facts": out, "total": total, "has_more": hasMore}
			if hasMore && len(f) > 0 {
				res["next_before"] = f[len(f)-1].ID // 传回它取下一页(更旧的)
			}
			return jsonResult(res)
		})
}

// factSummaryMax caps a fact summary in list_facts output. Facts carry one-line
// conclusions, but nothing enforces brevity; a runaway summary must not bloat a
// whole page. Full text stays available via node_detail(id).
const factSummaryMax = 160

// compactFact is compactNode with the summary rune-capped for list_facts, so a
// page of facts stays bounded regardless of how long any single summary grew.
func compactFact(n *db.Node) map[string]any {
	m := compactNode(n)
	if s, ok := m["summary"].(string); ok && len([]rune(s)) > factSummaryMax {
		m["summary"] = string([]rune(s)[:factSummaryMax]) + "…"
		m["summary_truncated"] = true
	}
	return m
}

func (t *ToolSet) nodeDetail() actool.CoreTool {
	return t.readExpTool("node_detail", "按 id 取本任务或直接关联任务的【探索图节点】完整内容。继承节点带 source_task_id/inherited=true 且只读。仅限 list_facts/list_findings/graph_overview 返回的探索节点 id；资产请用 list_assets/asset_neighbors。",
		obj(map[string]any{"id": idp("探索图节点 id(非资产 id)")}, "id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ID json.RawMessage `json:"id"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.ID)
			if id <= 0 {
				return actool.Errorf("id 必填"), nil
			}
			n, err := t.ts.GetNodeWithSources(id)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if n == nil {
				return actool.Errorf(fmt.Sprintf("未找到探索节点 %d。若你想查的是资产，请用 list_assets / asset_neighbors（资产与探索节点是不同的 id 空间，资产 id 不能传给 node_detail）。", id)), nil
			}
			if err := t.ts.PopulateFindingTrafficIDs([]*db.Node{n}); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(n) // full payload incl. detail / evidence, plus explicit finding IDs
		})
}

// --- planner write tools ---

// intentItem 是 add_intent 批量/单条的一条探索方向。
type intentItem struct {
	Summary   string            `json:"summary"`
	Dimension string            `json:"dimension,omitempty"` // 攻击链续跳：继任意图的维度（injection/authz/…）
	AssetIDs  []json.RawMessage `json:"asset_ids"`
	ParentIDs []json.RawMessage `json:"parent_ids"`
	Priority  int               `json:"priority"`
	// Continues 是本意图【接续】的上游意图 id（0/1/多个）。
	//
	// 为什么需要它：接续链此前只存在于 summary 的**自然语言**里（「接续被预算
	// 掐断的意图 #432」「接续两次被后端重启打断的 #635/#578」）。实测线上 205
	// 条意图里有 26 条是接续（12.7%），而 #660 的 summary 直接写着「接续两次」。
	//
	// 文字形态接续有两个坏处：
	//  1. **算不出代数**。#660 接续 #635、#635 接续 #578，但图里 #660 的 parent
	//     是 #14（一个 fact）——接续关系在数据层根本没表达，所以「这条链已经接了
	//     几代」无法回答。而接续代数正是防止无限续派的关键闸门。
	//  2. **查不了**。想找「所有接续自 #578 的意图」只能全表扫 summary 文本。
	//
	// 结构化之后：接续代数可算、可查、可限。parent_ids 语义不变（只能挂
	// fact/finding，意图必须锚在已确认知识上）——continues 是**额外**的接续
	// 标记，不替代 parent_ids。
	Continues []json.RawMessage `json:"continues"`
	// Hypothesis 本方向的假设（可选）：依据哪条 fact 的什么推测，引用 fact id。
	// worker 拿到后作为「definition of done」的验证目标（v0.3.95 B3）。
	Hypothesis string `json:"hypothesis"`
	// SuccessCriteria 怎么算成了/没成（可选）：期望拿到的 fact/finding 形态。
	SuccessCriteria string `json:"success_criteria"`
	// RequiresIntents 是严格串行链的先决意图 id（平台开关关闭时仅作记录）。
	RequiresIntents []json.RawMessage `json:"requires_intents"`
}

// addOneIntent 创建一条意图节点并连上游血缘，返回 id。
// 约束：意图只能锚在已确认知识上——每个 parent_id 必须是已存在的 fact/finding
// 节点（不能挂在别的意图/目标/提示上）。顶层全新方向留空 parent_ids，兜底连 origin fact。
// 这样"每个意图都连到 fact 节点、且是发现驱动而非凭空规划"从创建路径上被强制。
func (t *ToolSet) addOneIntent(it intentItem) (int64, error) {
	summary := clampIntentSummary(it.Summary)
	if strings.TrimSpace(summary) == "" {
		return 0, fmt.Errorf("summary 不能为空")
	}
	// 意图粒度闸门（v0.4.44）：意图 summary 不能是任务 description/goal 的复读——
	// 第一轮最常见错误就是 planner 把总目标原封不动包成一条意图派下去，worker
	// 收到等于收到整个任务。这里用「前缀匹配 + 长度」做确定性检测。
	if rootDesc, rootGoal, rootErr := t.ts.Root(); rootErr == nil {
		for _, src := range []string{rootDesc, rootGoal} {
			src = strings.TrimSpace(src)
			if len(src) < 40 {
				continue
			}
			// 取目标文本的前 60 字节做前缀匹配（足够区分「复读」和「正常引用」）
			probe := src
			if len(probe) > 60 {
				probe = probe[:60]
			}
			if strings.Contains(summary, probe) {
				return 0, fmt.Errorf(
					"意图 summary 是任务目标/描述的复读，不是可执行的子步骤。" +
						"请把它拆成 3–5 条具体意图（如「DNS 解析 + 子域名枚举」「端口扫描与服务识别」「未授权面探测」等），" +
						"每条 summary 写清【对哪个资产 + 做什么具体动作 + 期望产出】；总目标的完整背景留在任务描述里即可，不需要复述。")
			}
		}
	}
	// 先校验锚点（建节点前，避免坏锚点留下孤儿意图）。
	parents := pidList(it.ParentIDs)
	for _, pidv := range parents {
		n, err := t.ts.GetNodeWithSources(pidv)
		if err != nil || n == nil {
			return 0, fmt.Errorf("parent_id %d 不存在于本任务或直接关联任务：parent_ids 必须是已存在的【事实(fact)/发现(finding)】节点 id；顶层全新方向请留空 parent_ids", pidv)
		}
		if n.Kind != db.KindFact && n.Kind != db.KindFinding {
			return 0, fmt.Errorf("parent_id %d 是 %q 节点，不能作为意图锚点：意图只能锚在已确认的【事实(fact)/发现(finding)】上，不能挂在意图/目标/提示上；顶层全新方向请留空 parent_ids", pidv, n.Kind)
		}
	}
	priority := it.Priority
	if priority == 0 {
		priority = 5
	}
	// 接续校验 + 代数计算。
	//
	// 约束：continues 只能指向**已存在的意图**节点（接续的是一条探索方向，
	// 不是一条事实）。代数 = 1 + 上游接续链上的最大代数。
	//
	// 为什么要有代数上限：接续链一旦没有闸就会无限拉长。线上实测到三代接续
	// ——#635 → #578 → #660，摘要在说「接续两次被后端重启打断的 #635/#578 继续
	// 攻 ZStack 管理 API 凭据这条皇冠链（#635 上一轮已跑到 56 轮/28 分钟）」。
	// 每一代都从零重建上下文、重复读同一批文件、重复扫同一批资产，而接续的那
	// 条链可能压根不值得继续。
	continues := pidList(it.Continues)
	depth := 1
	for _, cid := range continues {
		cn, err := t.ts.GetNodeWithSources(cid)
		if err != nil || cn == nil {
			return 0, fmt.Errorf("continues %d 不存在：continues 只能填已存在的【意图】节点 id", cid)
		}
		if cn.Kind != db.KindIntent {
			return 0, fmt.Errorf("continues %d 是 %q 节点，不能作为接续来源：continues 只能填【意图】id（接续的是一条探索方向）", cid, cn.Kind)
		}
		// 接续不能从【正在跑】的意图出发——那是并行竞争。
		// open 允许：可能是暂停回退的意图，planner 认为需要换角度接续是合理的。
		if cn.State == "running" {
			return 0, fmt.Errorf("continues %d 正在执行中，不能接续：等它结束后再派接续意图", cid)
		}
		if d := continuationDepthOf(cn); d+1 > depth {
			depth = d + 1
		}
	}
	if depth > maxContinuationDepth {
		return 0, fmt.Errorf("接续代数已达上限（%d 代）：这条方向已经被接续了 %d 次，继续接下去大概率是在重复劳动。"+
			"请改为：①换一种本质不同的打法（换入口/换方法/换目标面）；②或直接放弃这个方向，转向尚未覆盖的方向",
			maxContinuationDepth, depth)
	}
	requires := pidList(it.RequiresIntents)
	for _, rid := range requires {
		rn, err := t.ts.GetNode(rid)
		if err != nil || rn == nil {
			return 0, fmt.Errorf("requires_intents %d 不存在于本任务：只能填本任务已存在的意图 id", rid)
		}
		if rn.Kind != db.KindIntent {
			return 0, fmt.Errorf("requires_intents %d 是 %q 节点：只能填意图 id（前置是某条探索方向）", rid, rn.Kind)
		}
		if rn.State == "deleted" {
			return 0, fmt.Errorf("requires_intents %d 已被删除，不能作为前置", rid)
		}
	}
	anchors := pidList(it.AssetIDs)
	// 资产拦截：意图绑定的资产若命中系统资产拦截规则，则禁止下发该意图。
	if t.as != nil && len(anchors) > 0 {
		hits, err := t.as.CheckAssetsIntercept(t.taskID, anchors)
		if err != nil {
			return 0, fmt.Errorf("资产拦截校验失败：%w", err)
		}
		if len(hits) > 0 {
			var b strings.Builder
			fmt.Fprintf(&b, "意图「%s」绑定的资产未通过测试范围校验，请停止对相关资产进行测试：", it.Summary)
			for _, h := range hits {
				fmt.Fprintf(&b, "\n - %s", h.Describe())
			}
			return 0, fmt.Errorf("%s", b.String())
		}
	}
	payload := map[string]any{"summary": summary}
	if h := strings.TrimSpace(it.Hypothesis); h != "" {
		payload["hypothesis"] = h
	}
	if sc := strings.TrimSpace(it.SuccessCriteria); sc != "" {
		payload["success_criteria"] = sc
	}
	if len(anchors) > 0 {
		payload["asset_ids"] = anchors
	}
	if len(continues) > 0 {
		// 存成结构化字段，接续代数可算可查（见 intentItem.Continues 的注释）。
		payload["continues"] = continues
		payload["continuation_depth"] = depth
	}
	if len(requires) > 0 {
		payload["requires_intents"] = requires
	}
	// 派发去重：同任务里已有高度相似的 open/running 意图就不再重复下发——两条并行
	// worker 干同一件事纯属浪费；planner 能看到提示并改写差异。
	if existID, existSum, similar, err := t.ts.FindSimilarOpenIntent(summary); err == nil && similar {
		return 0, fmt.Errorf("已存在高度相似的未完成意图 #%d「%s」，未重复下发；若确实要做不同的事，请在 summary 里写清区别",
			existID, firstLine(existSum, 60))
	}
	id, err := t.ts.AddIntent(payload, priority, anchors, "planner")
	if err != nil {
		return 0, err
	}
	// upstream lineage: link each (validated) fact/finding parent → this intent, so
	// "multiple facts combine into one new intent" is expressible.
	for _, parent := range parents {
		_ = t.ts.Link(parent, db.RelDerivedFrom, id)
	}
	// a top-level intent (no explicit parent) connects to the origin fact, so every
	// intent still traces back to a fact node — at task start the only fact is the
	// origin, and the first intents derive from it.
	if len(parents) == 0 {
		if origin, _ := t.ts.OriginFactID(); origin > 0 {
			_ = t.ts.Link(origin, db.RelDerivedFrom, id)
		}
	}
	return id, nil
}

// SetIntentQueueLimit 安装派发阈值 resolver（nil = 不限制）。
func (t *ToolSet) SetIntentQueueLimit(fn func() (int, int)) { t.intentQueue = fn }

// SetIntentRequiresGate 控制 requires_intents 串行闸门（默认关，只作记录）。
func (t *ToolSet) SetIntentRequiresGate(on bool) { t.intentRequiresGate = on }

// queueBudget 返回派发阈值与 worker 数；nil resolver = 0,0（不限制）。
func (t *ToolSet) queueBudget() (limit, workers int) {
	if t == nil || t.intentQueue == nil {
		return 0, 0
	}
	return t.intentQueue()
}

// intentRoundAddCap 返回本轮还能新增的意图数上限（-1=不限），以及当前积压与阈值。
//
// 阈值 T = max(limit, 2*workers)：
//   - active >= T      → 本轮 0 条（先等产出；规划轮本身照常跑，可读结果/证目标/写事实）
//   - active >= T-2    → 本轮 1 条（只补最关键的下一步）
//   - 其他              → 本轮 3 条
func (t *ToolSet) intentRoundAddCap() (capN, active, threshold int) {
	capN = -1
	if t.worker != "planner" {
		return
	}
	limit, workers := t.queueBudget()
	if limit <= 0 || t.ts == nil {
		return
	}
	n, err := t.ts.CountActiveIntents()
	if err != nil {
		return
	}
	active = n
	threshold = limit
	if 2*workers > threshold {
		threshold = 2 * workers
	}
	switch {
	case active >= threshold:
		capN = 0
	case active >= threshold-2:
		capN = 1
	default:
		capN = 3
	}
	return
}

func (t *ToolSet) addIntent() actool.CoreTool {
	return t.writeExpTool("add_intent", "生成【探索方向】写入 frontier，并连入探索链路。意图是开放的探索方向，不是固定类型——用 summary 一句话自由描述要探索/验证/利用什么。\n"+
		"★优先批量：一轮筛出的多个新方向放进 intents 数组一次提交（比逐条调用省往返）。返回 ids 数组，与 intents 等长同序（失败项 id=0，详情见 errors）。单条则省略 intents 直接给顶层 summary。",
		obj(map[string]any{
			"intents":          map[string]any{"type": "array", "description": "【优先用这个】要新增的探索方向数组，按顺序处理。每个元素字段同下方顶层字段（summary/asset_ids/parent_ids/priority）。返回 ids 与本数组等长、同序。", "items": map[string]any{"type": "object"}},
			"summary":          str("[单条] 一句话描述这个探索方向：做什么+为什么。已写清方向即可，不依赖资产 id。"),
			"asset_ids":        map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "本方向要测试/攻击的【目标资产 id】（**尽量传**，0/1/多个；是 list_assets 返回的资产 id，不是探索节点 id）：这条探索方向针对哪些资产（站点/接口/参数/主机等）。只要方向围绕某些具体资产就务必传上——它是「这条探索打哪些目标」的结构化标记，用于覆盖去重、把意图连入资产链路。仅当纯全局侦察、确实没有具体目标资产时才留空。"},
			"parent_ids":       map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "上游锚点 id（可选，0/1/多个）：本方向由哪些【已确认的事实(fact)/发现(finding)】综合得出。**只能填已存在的 fact/finding 节点 id,不能填意图/目标/提示**——意图必须锚在已确认知识上,发现驱动而非凭空规划。多个事实共同产生一个新意图就传多个;顶层全新侦察方向请留空（会自动挂到任务起点 origin fact）。"},
			"continues":        map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "【仅当本方向是接续某条旧方向时填】上游【意图】节点 id（0/1/多个）——即本方向要接着哪条被掐断/被收口的意图继续做。**只在 summary 里明说「接续/继续 #NNN」时才填**，且必须与 summary 里提到的意图 id 一致。接续代数有上限（最多接 3 次），超了会被拒绝——到那时请换一种本质不同的打法或转向别的方向，别再接。顶层全新方向留空。"},
			"priority":         intp("优先级 0-10，默认5。直接逼近目标的利用链步=8-10；新入口面首次探明=6-7；补覆盖/复核=3-4；纯情报=1-2。同轮多意图按价值区分，别全默认 5。"),
			"requires_intents": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "【仅严格串行链使用】本方向依赖的先决意图 id：这些意图跑出结果前，本意图不会被 worker 领取（平台开关关闭时仅作记录）。只在上一步的**实际产出**是下一步输入时填；平行覆盖类方向不要填，否则会白白等待。"},
			"hypothesis":       str("【建议填】本方向的假设：依据哪条 fact 的什么推测（引用 fact id）。worker 会以它为验证目标，你下轮判「有没有产出」也有对照锚。"),
			"success_criteria": str("【建议填】怎么算成了/没成：期望拿到的 fact/finding 形态（如「拿到 admin cookie 的请求响应」/「证实参数 X 不可注入的输出」）。"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Intents    []intentItem `json:"intents"`
				intentItem              // 单条模式：顶层 summary/asset_ids/parent_ids/priority
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Intents) > 0
			items := a.Intents
			if !batch {
				items = []intentItem{a.intentItem}
			}

			origLen := len(items)
			ids := make([]int64, origLen)
			errs := map[string]string{}
			createdAny := false
			capN, active, threshold := t.intentRoundAddCap()
			for i, it := range items {
				if capN >= 0 && t.intentAdded >= capN {
					errs[strconv.Itoa(i)] = fmt.Sprintf(
						"派发节流：本任务未完成意图 %d 条（阈值 %d），本轮不再新增（已新建 %d 条）。"+
							"先等 worker 产出再派，或把多个方向合并成一条；规划轮本身不受影响，"+
							"仍可读结果、prove_goal、写 fact。设置 intent_queue_limit=0 可关闭节流。",
						active, threshold, t.intentAdded)
					continue
				}
				id, err := t.addOneIntent(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
				t.intentAdded++
				createdAny = true
			}
			if len(items) < origLen {
				ids = ids[:len(items)]
			}

			// 人经主 agent 直投意图 → 若任务已 done（无 open 目标的 goalless 分支），把它
			// 拉回 running，worker 才能领这条意图执行。resumeTask 仅由主 agent 的 Chat 接入
			// (SetResumeTask)；planner 的 ToolSet 为 nil，故 planner 自己调 add_intent 时此段
			// no-op，不影响其正常产意图。意图节点已在上面建好(open)，复活时不会被误判抽干。
			if createdAny && t.resumeTask != nil {
				t.resumeTask()
			}

			if !batch { // 单条：保持原返回
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("intent created: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

func (t *ToolSet) retireIntent() actool.CoreTool {
	return t.writeExpTool("retire_intent",
		"退役【尚未开始】的排队意图（open）。当你的新事实已否定某条意图的前提时调用，例如目标被证实是死目标、"+
			"真实业务入口已在别处定位到、或该方向已被结论排除。退役不删除证据/血缘，只置为 deleted 并记录原因，"+
			"之后不会再被 worker 领取。正在执行的意图不能退役——先用 kill_work 终止。\n"+
			"护栏：每轮最多 6 条；因『重复』退役必须用 superseded_by 指明存活的替代意图（不能指向已退役的）；"+
			"声称『前提失效』时必须在 reason 里引用否定它的事实/finding 节点号。",
		obj(map[string]any{
			"ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "要退役的意图节点 id（必须是 open 状态，可多条；本轮累计最多 6 条）"},
			"reason": str("退役原因（必填）：写清哪条事实否定了它的前提，或为什么不再需要这条方向"),
			"superseded_by": map[string]any{"type": "array", "items": map[string]any{"type": "integer"},
				"description": "【因重复而退役时必填】替代它的存活意图 id（open/running/done）。禁止指向已 deleted 的意图——那会造成覆盖断链。前提失效类退役不需要填。"},
		}, "ids", "reason"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				IDs          []json.RawMessage `json:"ids"`
				Reason       string            `json:"reason"`
				SupersededBy []json.RawMessage `json:"superseded_by"`
			}
			_ = json.Unmarshal(in, &a)
			ids := pidList(a.IDs)
			reason := strings.TrimSpace(a.Reason)
			sup := pidList(a.SupersededBy)
			if len(ids) == 0 {
				return actool.Errorf("ids 不能为空"), nil
			}
			if reason == "" {
				return actool.Errorf("reason 必填：写清是哪条事实/结论否定了它的前提"), nil
			}
			if remaining := maxIntentRetirePerRun - t.retiredThisRun; remaining <= 0 {
				return actool.Errorf(fmt.Sprintf("本轮退役已达上限 %d 条：先让 worker 消化积压，下一轮再清理（避免一轮清空导致链式误伤）", maxIntentRetirePerRun)), nil
			} else if len(ids) > remaining {
				return actool.Errorf(fmt.Sprintf("本轮最多还能退役 %d 条，本次提交 %d 条：请分轮处理，优先保留证据更完整的替代方向", remaining, len(ids))), nil
			}
			if len(sup) > 0 {
				for _, sid := range sup {
					if sid <= 0 {
						continue
					}
					for _, id := range ids {
						if sid == id {
							return actool.Errorf(fmt.Sprintf("superseded_by 不能指向本次要退役的意图 #%d（自指替代等于没有覆盖）", sid)), nil
						}
					}
					sn, err := t.ts.GetNode(sid)
					if err != nil || sn == nil {
						return actool.Errorf(fmt.Sprintf("superseded_by #%d 不存在：替代必须是本任务已存在的意图", sid)), nil
					}
					if sn.Kind != db.KindIntent {
						return actool.Errorf(fmt.Sprintf("superseded_by #%d 是 %q 节点：只能是意图 id", sid, sn.Kind)), nil
					}
					switch sn.State {
					case "open", "running", "done":
						// 存活替代，可接受
					default:
						return actool.Errorf(fmt.Sprintf("superseded_by #%d 当前状态为 %s：替代已被退役/终止，禁止链式退役（请先确认该覆盖类仍有存活意图或事实兜底）", sid, sn.State)), nil
					}
				}
				reason += "；替代意图：" + joinNodeRefs(sup)
			}
			if reasonClaimsPremiseInvalid(reason) && !t.reasonCitesKnowledge(reason) {
				return actool.Errorf("reason 声称『前提失效/被否定』但没有引用任何现存 fact/finding 节点号：请写出否定它的事实 id，或改为 superseded_by 表达重复"), nil
			}
			retired := []int64{}
			errs := map[string]string{}
			for _, id := range ids {
				key := strconv.FormatInt(id, 10)
				n, err := t.ts.GetNode(id)
				if err != nil || n == nil {
					errs[key] = "意图不存在"
					continue
				}
				if n.Kind != db.KindIntent {
					errs[key] = "不是意图节点：" + n.Kind
					continue
				}
				switch n.State {
				case "open":
					// 可退役
				case "running", "paused":
					errs[key] = "正在执行：先用 kill_work 终止，再退役"
					continue
				default:
					errs[key] = "已是终态（" + n.State + "），无需退役"
					continue
				}
				if _, err := t.ts.SoftDeleteIntent(id, "planner 退役："+reason); err != nil {
					errs[key] = err.Error()
					continue
				}
				t.retiredThisRun++
				retired = append(retired, id)
			}
			out := map[string]any{"retired": retired, "retired_this_round": t.retiredThisRun, "round_limit": maxIntentRetirePerRun}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

const maxIntentRetirePerRun = 6

func reasonClaimsPremiseInvalid(reason string) bool {
	for _, w := range []string{"前提", "否定", "失效", "证伪", "已被回答", "死目标"} {
		if strings.Contains(reason, w) {
			return true
		}
	}
	return false
}

func (t *ToolSet) reasonCitesKnowledge(reason string) bool {
	for _, id := range nodeRefIDs(reason) {
		n, err := t.ts.GetNode(id)
		if err != nil || n == nil {
			continue
		}
		if n.Kind == db.KindFact || n.Kind == db.KindFinding {
			return true
		}
	}
	return false
}

func nodeRefIDs(s string) []int64 {
	var out []int64
	for i := 0; i < len(s); i++ {
		if s[i] != '#' {
			continue
		}
		j := i + 1
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j > i+1 {
			if n, err := strconv.ParseInt(s[i+1:j], 10, 64); err == nil && n > 0 && n < 1<<40 {
				out = append(out, n)
			}
		}
		i = j
	}
	return out
}

func joinNodeRefs(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, "#"+strconv.FormatInt(id, 10))
	}
	return strings.Join(parts, "/")
}

func (t *ToolSet) listGoals() actool.CoreTool {
	return t.readExpTool("list_goals", "列出本任务的目标节点及其状态（open/met），用于判断是否达成。",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			g, _ := t.ts.ListByKind(db.KindGoal, 100)
			return jsonResult(g)
		})
}

func (t *ToolSet) proveGoal() actool.CoreTool {
	return t.writeExpTool("prove_goal", "当你判断某个发现/事实证明了某个目标达成时调用：把证据节点连到目标节点，并标记目标 met。",
		obj(map[string]any{
			"goal_id":     idp("目标节点 id"),
			"evidence_id": idp("证明它的发现/事实节点 id"),
			"reason":      str("为什么这个证据满足该目标"),
		}, "goal_id", "evidence_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				GoalID     json.RawMessage `json:"goal_id"`
				EvidenceID json.RawMessage `json:"evidence_id"`
				Reason     string          `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			goal, ev := pid(a.GoalID), pid(a.EvidenceID)
			if goal == 0 || ev == 0 {
				return actool.Errorf("goal_id 和 evidence_id 必填"), nil
			}
			goalNode, err := t.ts.GetNode(goal)
			if err != nil || goalNode == nil || goalNode.Kind != db.KindGoal {
				return actool.Errorf("goal_id 必须是本任务的目标节点（关联任务目标只读）"), nil
			}
			evidenceNode, err := t.ts.GetNodeWithSources(ev)
			if err != nil || evidenceNode == nil || (evidenceNode.Kind != db.KindFact && evidenceNode.Kind != db.KindFinding) {
				return actool.Errorf("evidence_id 必须是本任务或直接关联任务的事实/漏洞节点"), nil
			}
			_ = t.ts.Link(ev, db.RelProves, goal)
			_ = t.ts.SetNodeState(goal, "met")
			// 每标记一个目标 met，就检查本任务是否【所有目标】都已 met；若是，自动判定
			// 任务完成（置 GoalMet），无需再依赖模型显式调 goal_met。
			if goals, err := t.ts.ListByKind(db.KindGoal, 1000); err == nil && len(goals) > 0 {
				allMet := true
				for _, g := range goals {
					if g.State != "met" {
						allMet = false
						break
					}
				}
				if allMet {
					t.GoalMet = true
					t.Reason = fmt.Sprintf("所有 %d 个目标均已 met（最后由 goal %d 触发）", len(goals), goal)
					return actool.Text(fmt.Sprintf("goal %d marked met；本任务所有目标均已达成，任务自动判定完成", goal)), nil
				}
			}
			return actool.Text(fmt.Sprintf("goal %d marked met", goal)), nil
		})
}

func (t *ToolSet) goalMet() actool.CoreTool {
	return writeTool("goal_met", "【立即结束整个任务】——仅当你确认任务的【全部目标都已真正达成、整体收官】时才调（注意是任务【整体】完成；仅仅达成了其中某一个目标/某一个 flag/某一个漏洞【不算】——那种情况用 prove_goal 标记该目标即可）。⚠️它不是用来“结束本轮规划”的：本轮没有新意图要派、或在等 worker 产出，都【直接结束本轮即可，不要调本工具】（0 个意图是完全正常的）。正常判定优先用 prove_goal 逐个证明目标；goal_met 只是绕过逐个证明、直接从全局收官的手段。",
		obj(map[string]any{"reason": str("达成理由（必须是目标真正达成的证据，不能是“本轮无新方向”这类结束本轮的理由）")}, "reason"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct{ Reason string }
			_ = json.Unmarshal(in, &a)
			// v0.6.31 内部版同款闸门：未达成/未证明的目标存在时禁止整体收官。
			// 旧实现允许 planner 以「边际收益耗尽」为由 goal_met 结束任务（目标被标 unverified），
			// 界面/报告却显示「已完成」——这正是「只完成一部分却自己判完成」的来源。
			if t.ts != nil {
				unmet := 0
				var ids []string
				if goals, err := t.ts.ListByKind(db.KindGoal, 1000); err == nil {
					for _, g := range goals {
						if g.State != "met" {
							unmet++
							if len(ids) < 5 {
								ids = append(ids, fmt.Sprintf("#%d", g.ID))
							}
						}
					}
				}
				if unmet > 0 {
					return actool.Errorf(fmt.Sprintf("还有 %d 个目标未达成（%s），禁止整体收官：goal_met 只能在全目标已用 prove_goal 证明后调用。请继续派深挖/利用链意图；若确认客观不可推进，把阻塞证据写成 fact（含已尝试手段与失败输出），任务会按超时/轮数上限以「未完成」收尾，而不是显示达成。", unmet, strings.Join(ids, "、"))), nil
				}
			}
			t.GoalMet = true
			t.Reason = a.Reason
			// 可审计：goal_met 是「整体声称达成」，没有走 prove_goal 的逐条证据链。
			// 把仍未 met 的目标打上未验证标记，报告与界面才能区分「被证明」和「被声称」，
			// 而不是让一次偷懒的收官看起来和验证过的达成一样。
			// t.ts 为 nil 时（无任务上下文的 ToolSet，如工具目录构造期）跳过：那条路径
			// 本来就调不到这里，但 nil 解引用会直接把进程带走，不值得赌。
			unproven := 0
			if t.ts != nil {
				if goals, err := t.ts.ListByKind(db.KindGoal, 1000); err == nil {
					for _, g := range goals {
						if g.State != "met" {
							unproven++
							_ = t.ts.MarkGoalUnverified(g.ID, a.Reason)
						}
					}
				}
			}
			return actool.Text(fmt.Sprintf("acknowledged: task marked complete（%d 个目标未经逐条证据证明，已留痕）", unproven)), nil
		})
}

// --- worker write tools ---

func (t *ToolSet) addFinding() actool.CoreTool {
	return writeTool("report_finding", "记录确认的漏洞，用 evidence 提供命令输出、日志等可验证证据。任务上下文传当前 intent_id。返回的 finding_id 是独立漏洞记录 ID，finding_node_id 是探索节点 ID（第一行保留该节点编号）。", obj(map[string]any{
		"vulnclass": str("漏洞类别,【必须】从标准类别里选:" + db.VulnClassPromptText() + "。具体 CVE/漏洞编号写进 name,类别选「已知漏洞」;实在不属于任何一类才用「其他」"), "name": str("漏洞名称"), "severity": str("critical|high|medium|low"), "summary": str("发现摘要"),
		"intent_id": idp("当前任务的意图 id"), "asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "受影响资产 id"},
		"evidence":         str("证据/PoC 文本"),
		"evidence_hint_id": idp("可选：本任务中对应此漏洞的提示节点 ID，自动携带其结构化 traffic_refs；不能引用继承提示或其他漏洞的提示"),
		"traffic_refs": map[string]any{"type": "array", "description": "可选；HTTP/HTTPS 漏洞先检索并逐条核实请求/响应确实支持漏洞结论，再按复现顺序填写真实 ID。TCP 等非 HTTP 漏洞、未采集或找不到确切记录时省略或传 []，不阻止上报；可在 evidence 说明原因并提供其他可验证证据。不要猜测 ID、按域名/时间推定关联或仅为补包重复探测。用途 baseline 正常对照 / proof 漏洞证明 / verification 补充验证 / supporting 辅助证据。若某个 ID 不存在，漏洞仍会正常入库，该 ID 会在返回值的 skipped_traffic_refs 里列出，可用 traffic_get 核实后用 bind_finding_traffic 补绑。",
			"items": obj(map[string]any{"traffic_id": str("traffic_search 返回的真实流量 ID"), "role": map[string]any{"type": "string", "enum": []string{"baseline", "proof", "verification", "supporting"}}, "note": str("该流量如何支持漏洞结论")}, "traffic_id")},
	}, "vulnclass", "severity", "summary"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			VulnClass, Name, Severity, Summary, Evidence string
			IntentID                                     json.RawMessage   `json:"intent_id"`
			AssetIDs                                     []json.RawMessage `json:"asset_ids"`
			TrafficRefs                                  []db.TrafficRef   `json:"traffic_refs"`
			EvidenceHintID                               json.RawMessage   `json:"evidence_hint_id"`
		}
		if err := json.Unmarshal(in, &a); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if t.ts == nil {
			return actool.Errorf("report_finding 需要任务上下文；平台对话请通过 add_task_hint 向对应任务交接漏洞，并在提示中携带已有的 traffic_refs，由任务 Agent 登记。已登记漏洞可用 bind_finding_traffic 补绑。"), nil
		}
		// 证据门槛（v0.4.5）：critical/high 需要足量可核验证据；不足时打回，
		// 模型可补证据或降级后重试，而不是让"一句话高危"进入报告。
		if msg := validateFindingEvidence(a.Severity, a.Evidence); msg != "" {
			return actool.Errorf(msg), nil
		}
		// 机械验证凭据校验（v0.4.52）：critical/high 必须附 HTTP 状态码/curl 输出/
		// 工具命中结果等可机械复现的验证凭据。纯版本匹配不通过。
		if msg := validateMechanicalEvidence(a.Severity, a.Evidence); msg != "" {
			return actool.Errorf(msg), nil
		}
		// 证据逐字回验（v0.4.29，P0b #2，PentestGPT 机制自研）：先告警后拦截。
		// 证据里至少要有一行能在本次 run 的真实工具回显里逐字找到出处——
		// 「none」且档位=block 时只打回 critical/high（误报代价最高的两档）。
		verifyNote := ""
		if ledger, mode := ToolOutputsFromContext(ctx); ledger != nil && mode != EvidenceVerifyOff && strings.TrimSpace(a.Evidence) != "" {
			matched, total := ledger.VerifyEvidence(a.Evidence)
			switch evidenceVerdict(matched, total) {
			case "none":
				if mode == EvidenceVerifyBlock && (a.Severity == "critical" || a.Severity == "high") {
					return actool.Errorf(fmt.Sprintf(
						"证据逐字回验未通过：evidence 里没有任何一行能在本次工具输出中找到出处（已比对 %d 行有效内容）。"+
							"critical/high 必须带本会话真实命令输出：请把工具回显中的关键行原样粘进 evidence（命令 + 输出特征），"+
							"或降级为 medium 后再报，或改用 record_fact 记为待验证线索。", total)), nil
				}
				verifyNote = fmt.Sprintf("⚠️ 证据出处核对：0/%d 行可在本次工具输出中逐字找到——报告读者将无法复核，建议补粘命令与输出原文。", total)
			case "partial":
				verifyNote = fmt.Sprintf("⚠️ 证据出处核对：仅 %d/%d 行可在本次工具输出中逐字找到，其余为转述；关键结论请引用原文。", matched, total)
			}
		}
		// Auto-binding off: ignore the evidence params instead of rejecting the call.
		// stripTrafficParameters already removes them from the advertised schema, but
		// models routinely emit fields anyway — failing here would discard a confirmed
		// finding over a stray parameter. The success path below reports evidence_status
		// "not_bound" with the "已关闭，可在页面人工关联" note, which is what the caller needs.
		if !findingTrafficBindingEnabled() {
			a.TrafficRefs, a.EvidenceHintID = nil, nil
		}
		if len(a.EvidenceHintID) > 0 && pid(a.EvidenceHintID) <= 0 {
			return actool.Errorf("evidence_hint_id 必须为有效的提示节点 ID；无交接提示时省略"), nil
		}
		// 漏洞资产自动锚定（v0.4.40，与 record_fact 同一策略）：模型没给 asset_ids
		// 时，从 summary/evidence 文本反查任务资产补上——归属链路保证 finding 能
		// 连到资产/意图，报告与按资产聚合才不缺项。
		if len(a.AssetIDs) == 0 {
			if auto := t.autoAnchorFact(map[string]any{
				"summary":  a.Summary,
				"detail":   a.Evidence,
				"evidence": a.Evidence,
			}); len(auto) > 0 {
				for _, id := range auto {
					if raw, err := json.Marshal(id); err == nil {
						a.AssetIDs = append(a.AssetIDs, raw)
					}
				}
			}
		}
		refs, err := t.findingRefsFromHint(pid(a.EvidenceHintID), a.TrafficRefs)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		// 授权边界守卫（v0.4.63）：finding 的 asset_ids 只能落在自有范围资产上。
		if msg := t.scopeGuardError(pidList(a.AssetIDs)); msg != "" {
			return actool.Errorf(msg), nil
		}
		input := db.RecordFindingInput{TaskID: t.taskID, ExplorationID: t.ts.ID(), IntentID: pid(a.IntentID), VulnClass: a.VulnClass, Name: a.Name, Severity: a.Severity, Summary: a.Summary, Evidence: a.Evidence, Worker: t.worker, AssetIDs: pidList(a.AssetIDs), CrossTaskNotifyDedup: t.CrossTaskNotifyDedup}
		var recorded *db.RecordedFinding
		if t.findingRecorder != nil {
			recorded, err = t.findingRecorder.Record(ctx, input, refs)
		} else if len(refs) > 0 {
			return actool.Errorf("流量证据存储不可用；未登记漏洞"), nil
		} else {
			recorded, err = t.ts.RecordFinding(ctx, input)
		}
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if t.notifyFinding != nil {
			iid := input.IntentID
			if iid <= 0 {
				iid = t.ownerNode
			}
			t.notifyFinding(iid, a.Summary)
		} else if t.notify != nil {
			t.notify()
		}
		t.writes.Findings++
		// Keep the first line's node-ID contract for existing reporter triggers.
		for i := range recorded.Traffic.Bindings {
			recorded.Traffic.Bindings[i].Snapshot.ReqHead = ""
			recorded.Traffic.Bindings[i].Snapshot.RespHead = ""
		}
		result := struct {
			*db.RecordedFinding
			EvidenceStatus     string `json:"evidence_status"`
			EvidenceNote       string `json:"evidence_note,omitempty"`
			EvidenceVerifyNote string `json:"evidence_verify_note,omitempty"`
			ChainIntentID      int64  `json:"chain_intent_id,omitempty"`
			ChainNote          string `json:"chain_note,omitempty"`
		}{RecordedFinding: recorded, EvidenceStatus: "bound", EvidenceVerifyNote: verifyNote}
		if len(recorded.CrossTaskDupTasks) > 0 {
			ids := make([]string, 0, len(recorded.CrossTaskDupTasks))
			for _, tid := range recorded.CrossTaskDupTasks {
				ids = append(ids, strconv.FormatInt(tid, 10))
			}
			result.EvidenceNote = (func(prev string) string {
				if prev != "" {
					return prev + " "
				}
				return ""
			})(result.EvidenceNote) + fmt.Sprintf(
				"◎ 跨任务提示：同指纹漏洞在任务 %s 中已存在，本次推送已按跨任务去重抑制（漏洞记录保留在本任务，页面可见）。"+
					"这通常意味着该资产属于其他任务的范围——请核对本任务授权边界，不要继续在其他任务的资产上深挖。", strings.Join(ids, "/"))
		}
		if len(recorded.Traffic.Bindings) == 0 {
			result.EvidenceStatus = "not_bound"
			result.EvidenceNote = "漏洞已保存，未绑定流量。TCP/无包情形可正常继续；若已有核实的 HTTP 流量，请用可用的 bind_finding_traffic 或漏洞页面补绑，再完成证据交接。不要重复创建漏洞。"
			if !findingTrafficBindingEnabled() {
				result.EvidenceNote = "漏洞已保存。Agent 自动绑定流量已关闭，可在页面人工关联流量。"
			}
		}
		if recorded.Duplicate {
			// 指纹命中:证据已合并进已有记录。硬闸语义必须讲清,否则模型会把
			// "重复"理解成失败而换个说法再报一遍。
			result.EvidenceNote = "★ 该漏洞此前已上报(finding_id=" + strconv.FormatInt(recorded.FindingID, 10) +
				"),本次证据已【合并】进原记录——这不是失败,无需再次 report_finding,更不要换标题/类别重报。" +
				"继续探索其它方向即可;若原记录的 severity 有变化,已在本次合并中更新。"
			if len(recorded.Traffic.Bindings) == 0 {
				result.EvidenceStatus = "merged"
			}
		}
		// 部分引用没挂上（流量 ID 不存在/正文不可读）：漏洞已入库，但要让模型
		// 知道哪几条证据没生效，否则它会以为证据齐全、报告里就少了这段。
		// 放在重复分支之后：两条提示都要留（先说合并，再补未生效的引用）。
		if len(recorded.SkippedRefs) > 0 {
			ids := make([]string, 0, len(recorded.SkippedRefs))
			for _, r := range recorded.SkippedRefs {
				ids = append(ids, r.TrafficID)
			}
			result.EvidenceStatus = "partially_bound"
			result.EvidenceNote += " ⚠ 以下流量引用未生效（ID 不存在或正文不可读）：" + strings.Join(ids, ", ") +
				"。已生效的引用已正常绑定；若这些 ID 确实存在，请用 traffic_get 核实真实 ID 后用 bind_finding_traffic 补绑。"
		}
		// 攻击链自动续跳（v0.4.63 红队批次下放）：只有新建的 finding 才续跳；重复上报（已合并）不派。
		if !recorded.Duplicate {
			if cid, note := t.dispatchChainIntent(a.VulnClass, a.Name, a.Summary, a.Severity,
				pidList(a.AssetIDs), recorded.NodeID, pid(a.IntentID)); cid > 0 || note != "" {
				result.ChainIntentID = cid
				result.ChainNote = note
			}
		}
		// 回溯归属（v0.4.47）：同一意图目录下所有 finding_id 为空的证据一次性归属。
		if bindIntent := pid(a.IntentID); bindIntent > 0 && t.taskID > 0 {
			if n, err := t.ts.RetroBindIntentEvidence(t.taskID, bindIntent, recorded.FindingID); err == nil && n > 0 {
				result.EvidenceNote += fmt.Sprintf(" ✨ 自动归属了本意图的 %d 条历史证据。", n)
			}
		}
		raw, _ := json.Marshal(result)
		return actool.Text(fmt.Sprintf("finding recorded: %d\n%s", recorded.NodeID, raw)), nil
	})
}

// recordFact writes a general exploration RESULT/conclusion (not a vuln, not a
// new asset) into the EXPLORATION graph, chained to the intent that produced it.
// This is the home for observations and — importantly — negative results
// ("port closed", "param not injectable", "no login found"). Such conclusions
// must NOT be stuffed into the asset graph via upsert_asset.
// factItem 是 record_fact 批量/单条的一条事实。
type factItem struct {
	Summary    string            `json:"summary"`
	Detail     string            `json:"detail"`
	Evidence   string            `json:"evidence"`   // 一行关键证据（命令+关键输出行），支撑结论、便于事后核对
	Confidence string            `json:"confidence"` // observed（直接看到）| inferred（据现象推断）
	IntentID   json.RawMessage   `json:"intent_id"`
	AssetIDs   []json.RawMessage `json:"asset_ids"`
}

// recordOneFact 写一条 fact 节点并连到意图（intent→yields→fact）。defaultIntent 为
// 批量时的默认意图（本条未给 intent_id 时用）。
func (t *ToolSet) recordOneFact(it factItem, defaultIntent int64) (int64, error) {
	if strings.TrimSpace(it.Summary) == "" {
		return 0, fmt.Errorf("summary 不能为空")
	}
	payload := map[string]any{"summary": it.Summary}
	if it.Detail != "" {
		payload["detail"] = it.Detail
	}
	if e := strings.TrimSpace(it.Evidence); e != "" {
		payload["evidence"] = e
	}
	if c := strings.TrimSpace(it.Confidence); c != "" {
		payload["confidence"] = c
	}
	intent := pid(it.IntentID)
	if intent <= 0 {
		intent = defaultIntent
	}
	if intent > 0 {
		node, err := t.ts.GetNode(intent)
		if err != nil || node == nil || node.Kind != db.KindIntent {
			return 0, fmt.Errorf("intent_id 必须是本任务的意图（关联任务意图只读）")
		}
	}
	// a fact is its OWN node kind (distinct from a vuln finding).
	assetIDs := pidList(it.AssetIDs)
	missing := t.missingAssetIDs(assetIDs)
	// 覆盖归账（v0.4.27）：模型没给 asset_ids 时，从事实文本里反查任务资产自动锚定。
	// 任务 5 实测 493 个 endpoint 只测到 30% 的主因不是没测——worker 大量用 Bash curl
	// 探测后 record_fact 不带 asset_ids，覆盖度对账不出来，规划者被误导继续扫面上。
	// 锚点是 provenance 边：自动锚定只影响覆盖统计与血缘展示，不改事实内容。
	if len(assetIDs) == 0 {
		if auto := t.autoAnchorFact(payload); len(auto) > 0 {
			assetIDs = auto
		}
	}
	// 授权边界守卫（v0.4.63）：fact 锚定只能落在自有范围资产上。
	if msg := t.scopeGuardError(assetIDs); msg != "" {
		return 0, fmt.Errorf("%s", msg)
	}
	id, err := t.ts.AddNode(db.KindFact, payload, 5, "confirmed", t.worker, assetIDs)
	if err != nil {
		return 0, err
	}
	if intent > 0 {
		_ = t.ts.Link(intent, db.RelYields, id) // chain: intent -> fact
	}
	t.writes.Facts++
	// 事实已经写下去了，但锚点里指向不存在资产的边被丢弃了。把这件事告诉模型，
	// 它下次就知道该 asset id 根本不存在——否则它会一直用同一个假 id，
	// 而 planner 看到的资产链路里会少掉本该关联的资产。
	if len(missing) > 0 {
		t.lastMissingAssets = append(t.lastMissingAssets, missing...)
	}
	return id, nil
}

// missingAssetIDs returns the subset of ids that do NOT exist in the asset
// table. Used to tell the model "this asset id is not real" instead of silently
// dropping the anchor.
func (t *ToolSet) missingAssetIDs(ids []int64) []int64 {
	if len(ids) == 0 || t.as == nil {
		return nil
	}
	found, err := t.as.GetByIDs(ids)
	if err != nil {
		return nil
	}
	have := make(map[int64]bool, len(found))
	for _, a := range found {
		if a != nil {
			have[a.ID] = true
		}
	}
	var missing []int64
	for _, id := range ids {
		if !have[id] {
			missing = append(missing, id)
		}
	}
	return missing
}

// scopeGuardError 是写回锚定的授权边界闸门（v0.4.63，跨任务串资产
// 防线的第④层硬化）：fact/finding 的 asset_ids 只允许「自有范围」资产——
//
//	own    ：匹配本任务自己的 scope，或本任务发现/登记（task_ids 含本任务）→ 放行；
//	source ：只匹配来源/继承任务的 scope → 默认拒绝（继承范围只读；确属授权时
//	         用 add_task_scope 显式纳入，或开启 scope_inherit_writes）；
//	foreign：完全越界 → 一律拒绝。
//
// 返回空串表示放行；非空是给模型的中文纠正提示（含资产标签，便于它自己纠正）。
// 查询失败 fail-open（返回空串）——闸门故障不能把正常任务全部卡死，由调用方记日志。
func (t *ToolSet) scopeGuardError(ids []int64) string {
	if !t.ScopeWriteGuard || t.as == nil || t.taskID <= 0 || len(ids) == 0 {
		return ""
	}
	own, source, foreign, err := t.as.ClassifyAssetsForTask(t.taskID, ids)
	if err != nil {
		return "" // fail-open：分类查询故障不阻断正常任务，由调用方日志兜底
	}
	_ = own
	if t.ScopeInheritWrites {
		source = nil
	}
	if len(source) == 0 && len(foreign) == 0 {
		return ""
	}
	label := func(ids []int64) string {
		assets, err := t.as.GetByIDs(ids)
		if err != nil {
			return ""
		}
		parts := make([]string, 0, len(assets))
		for i, a := range assets {
			if a == nil {
				continue
			}
			name := a.Domain
			if name == "" {
				name = a.URL
			}
			if name == "" {
				name = a.IP
			}
			if name == "" {
				name = a.AppName
			}
			if name == "" {
				name = a.RootDomain
			}
			if i >= 6 {
				parts = append(parts, fmt.Sprintf("…等 %d 个", len(assets)))
				break
			}
			parts = append(parts, fmt.Sprintf("#%d %s", a.ID, name))
		}
		return strings.Join(parts, "、")
	}
	var b strings.Builder
	b.WriteString("范围守卫：以下资产不属于本任务自有范围，禁止写回/上报：")
	if len(source) > 0 {
		b.WriteString(fmt.Sprintf("\n· 来源/继承任务范围（只读，默认不可写）：%s", label(source)))
	}
	if len(foreign) > 0 {
		b.WriteString(fmt.Sprintf("\n· 完全越界：%s", label(foreign)))
	}
	b.WriteString("\n处理方式（二选一）：① 把本条结论的 asset_ids 改成自有范围资产，或删掉 asset_ids 让系统只记结论本身；" +
		"② 若该资产确在本任务授权内，先用 add_task_scope 显式纳入本任务范围后重试。" +
		"跨域名归属类结论必须先在两个域各自取证复核（本域复验 200/内容一致），未复核一律按 inferred 写，不得标 observed。")
	return b.String()
}

var (
	factURLRe  = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+`)
	factHostRe = regexp.MustCompile(`(?i)\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b`)
)

// autoAnchorFact infers anchors for a fact that came in without asset_ids:
// pull URLs/hosts out of the fact text, match them against task-owned assets,
// cap the result (a fact name-dropping 20 hosts must not mark 20 assets tested).
// Best effort — any failure just yields no anchors, the fact is written anyway.
func (t *ToolSet) autoAnchorFact(payload map[string]any) []int64 {
	if t.as == nil || t.taskID <= 0 {
		return nil
	}
	parts := make([]string, 0, 3)
	for _, k := range []string{"summary", "detail", "evidence"} {
		if s, ok := payload[k].(string); ok && s != "" {
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return nil
	}
	text := strings.Join(parts, "\n")
	hostSet := map[string]bool{}
	var hosts []string
	for _, m := range factHostRe.FindAllString(text, 16) {
		h := strings.ToLower(m)
		if !hostSet[h] && net.ParseIP(h) == nil && strings.Contains(h, ".") {
			hostSet[h] = true
			hosts = append(hosts, h)
		}
		if len(hosts) >= 12 {
			break
		}
	}
	urlSet := map[string]bool{}
	var urls []string
	for _, m := range factURLRe.FindAllString(text, 16) {
		m = strings.TrimRight(m, ".,;，。；）)】")
		if u, err := url.Parse(m); err == nil && u.Host != "" {
			m = fmt.Sprintf("%s://%s%s", u.Scheme, strings.ToLower(u.Host), u.EscapedPath())
		}
		if !urlSet[m] {
			urlSet[m] = true
			urls = append(urls, m)
		}
		if len(urls) >= 12 {
			break
		}
	}
	if len(hosts) == 0 && len(urls) == 0 {
		return nil
	}
	ids, err := t.as.ResolveHostAssets(t.taskID, hosts, urls, 6)
	if err != nil {
		return nil
	}
	return ids
}

func (t *ToolSet) recordFact() actool.CoreTool {
	return t.writeExpTool("record_fact", "把探索【事实/结论】写入探索图，连到产生它的意图（intent_id）。用于记录探索结果——包括指纹/枚举等【正向结论】，和'端口关闭'/'参数不可注入'/'未发现登录入口'等【否定结论】。\n"+
		"⚠️一次探索的多个观察要【汇总成一条事实】，不要拆成多条，可以合并成一条事实的就尽量用一条事实表示：summary=对本次结论的总结性一句话，detail=相关细节（可含多个具体项）。例：指纹意图→一条事实 {summary:'识别了 X 站点的技术栈与响应特征', detail:'nginx 1.25 / Vue3 / 200 / title=.. / body_len=..'}，而不是状态码、指纹、标题各记一条。一条意图通常只产出一条事实，拆太碎会让图谱无限膨胀。\n"+
		"★facts 数组用于一次写多条【彼此不同】的结论（每条可省略 intent_id，默认用顶层 intent_id）。返回 ids 数组，与 facts 等长同序。\n"+
		"⚠️只写你在工具输出里【真实看到】的结论，不要脑补。evidence 与 confidence 用来防止不准确的结论污染图谱：\n"+
		"  · evidence=支撑本结论的【一行】关键证据（命令+最能证明的那一两行输出），**务必简洁**——细节已在 detail，这里不要再粘大段输出。\n"+
		"  · confidence=observed（输出里直接看到）| inferred（据现象推断）。\n"+
		"  · **否定类结论**（不可注入/端口关闭/未发现入口等）只写\"观察 + 试探性读法\"——陈述你实际看到什么，方向是否放弃由规划者综合全局定；务必给 evidence，手段没穷尽或证据弱（含只探一次、看起来像）标 inferred，确已穷尽且直接看到才标 observed。",
		obj(map[string]any{
			"facts":      map[string]any{"type": "array", "description": "【有多条不同结论时用】事实数组，元素字段同下方顶层字段（summary/detail/evidence/confidence/intent_id/asset_ids）；省略 intent_id 则用顶层 intent_id。返回 ids 与本数组等长、同序。", "items": map[string]any{"type": "object"}},
			"summary":    str("对本次探索结论的【总结性一句话】（是对 detail 的概括）"),
			"intent_id":  idp("产生本事实的意图 id（你领到的意图；批量时作为各条默认）"),
			"detail":     str("本事实的相关细节：把这次探索的多个观察事实都写进这里"),
			"evidence":   str("【一行】关键证据：命令 + 最能证明结论的那一两行输出。务必简洁，不要粘大段输出（细节放 detail）。"),
			"confidence": str("observed（输出里直接看到）| inferred（据现象推断）。否定结论务必如实标注。"),
			"asset_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "相关资产 id（可选，0/1/多个）：该事实涉及哪些资产"},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Facts    []factItem `json:"facts"`
				factItem            // 单条模式 + 批量默认 intent_id
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Facts) > 0
			items := a.Facts
			// 单次最多 10 条（v0.4.44）：防 worker 一次调用写几十条拆碎的事实，
			// 图谱会被灌爆。超限截断并在返回值里告知模型。
			if len(items) > 10 {
				items = items[:10]
			}
			if !batch {
				items = []factItem{a.factItem}
			}
			defaultIntent := pid(a.factItem.IntentID) // 顶层 intent_id = 批量默认

			ids := make([]int64, len(items))
			errs := map[string]string{}
			t.lastMissingAssets = nil
			for i, it := range items {
				id, err := t.recordOneFact(it, defaultIntent)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
			}
			missing := t.lastMissingAssets

			if !batch { // 单条：保持原返回
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(factRecordText(ids[0], missing)), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			if len(missing) > 0 {
				out["skipped_asset_ids"] = missing
				out["note"] = fmt.Sprintf("以下 asset id 不存在，锚点已跳过（事实本身已写入）：%v", missing)
			}
			return jsonResult(out)
		})
}

// factRecordText renders the record_fact single-item result. Missing asset ids
// are reported explicitly: silently dropping the anchor would leave the model
// convinced it linked the fact to an asset, and it would keep reusing the same
// fabricated id on every later write-back.
func factRecordText(id int64, missing []int64) string {
	if len(missing) == 0 {
		return fmt.Sprintf("fact recorded: %d", id)
	}
	return fmt.Sprintf("fact recorded: %d（注意：asset id %v 不存在，锚点已跳过；事实本身已保存。请用 list_assets 查真实 id）", id, missing)
}

type hintItem struct {
	Text        string            `json:"text"`
	AssetIDs    []json.RawMessage `json:"asset_ids"`
	TrafficRefs []db.TrafficRef   `json:"traffic_refs"`
}

// addOneHint 挂一条 hint 节点(active/human)到探索图,可锚定资产,返回 id。
func (t *ToolSet) addOneHint(it hintItem) (int64, error) {
	if len(it.TrafficRefs) > 0 && !findingTrafficBindingEnabled() {
		return 0, fmt.Errorf("Agent 自动绑定流量已关闭，未保存携带 traffic_refs 的提示；可在系统设置开启，或仅交接文字")
	}
	if strings.TrimSpace(it.Text) == "" {
		return 0, fmt.Errorf("text 不能为空")
	}
	var anchors []int64
	for _, raw := range it.AssetIDs {
		if tid := pid(raw); tid > 0 {
			anchors = append(anchors, tid)
		}
	}
	refs, err := db.NormalizeTrafficRefs(it.TrafficRefs)
	if err != nil {
		return 0, err
	}
	payload := map[string]any{"text": it.Text}
	if len(refs) > 0 {
		payload["traffic_refs"] = refs
	}
	// 唤醒 planner 不在此处逐条做——由 addHint 在整批写完后统一触发一次（带上提示文本），
	// 避免一次 add_hint 多条提示逐条刷屏 planner 的触发行。
	return t.ts.AddNode(db.KindHint, payload, 0, "active", "human", anchors)
}

type goalItem struct {
	Text      string `json:"text"`
	VulnClass string `json:"vulnclass"`
}

// addOneGoal 挂一条 goal 节点(open)到探索图:连到任务根(origin fact,rel spawns)。
// origin 取 t.worker(缺省 system):goals 拆解器写入的记 "goals"、主 agent 运行时记
// "human"。唤醒 planner 由 setGoals 在整批写完后统一做(见下),这里只负责落库。
func (t *ToolSet) addOneGoal(it goalItem) (int64, error) {
	text := strings.TrimSpace(it.Text)
	if text == "" {
		return 0, fmt.Errorf("text 不能为空")
	}
	payload := map[string]any{"text": text}
	if vc := db.NormalizeVulnClass(it.VulnClass); vc != "" {
		payload["vulnclass"] = vc
	}
	origin := t.worker
	if origin == "" {
		origin = "system"
	}
	id, err := t.ts.AddNode(db.KindGoal, payload, 0, "open", origin, nil)
	if err != nil {
		return 0, err
	}
	if of, _ := t.ts.OriginFactID(); of > 0 && id > 0 {
		_ = t.ts.Link(of, db.RelSpawns, id) // goals descend from the task root (origin fact)
	}
	return id, nil
}

// setGoals 给【本任务】新增探索目标(goal 节点)。既是目标拆解器的提交工具,也是主
// agent 运行时补目标的工具——同一个受管工具,可在 web 端改描述/schema、按 agent 绑定。
func (t *ToolSet) setGoals() actool.CoreTool {
	return writeTool("set_goals",
		"给【本任务】新增探索目标(goal)。目标=最终可交付/可核验的结果,不是攻击步骤或侦察动作。\n"+
			"★优先批量:多个目标放进 goals 数组一次提交,返回 ids 与之等长同序(失败项 id=0,详情见 errors)。单条则省略 goals 直接给顶层 text。\n"+
			"vulnclass 可选:对应漏洞类,标准类别:"+db.VulnClassPromptText()+";业务逻辑类目标留空。目标是否达成由系统判定标记 met,本工具只负责新增。",
		obj(map[string]any{
			"goals":     map[string]any{"type": "array", "description": "【优先用这个】要新增的目标数组,按顺序处理。每个元素:text(必填,一个独立可验证的最终目标)+ vulnclass(可选)。返回 ids 与本数组等长、同序。", "items": map[string]any{"type": "object"}},
			"text":      str("[单条] 一个独立可验证的最终目标"),
			"vulnclass": str("[单条] 对应漏洞类(若明确),标准类别:" + db.VulnClassPromptText() + ";业务逻辑目标可留空"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.ts == nil {
				return actool.Errorf("set_goals 未启用: ExplorationStore 未初始化"), nil
			}
			var a struct {
				Goals    []goalItem `json:"goals"`
				goalItem            // 单条模式:顶层 text/vulnclass
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Goals) > 0
			items := a.Goals
			if !batch {
				items = []goalItem{a.goalItem}
			}

			ids := make([]int64, len(items))
			errs := map[string]string{}
			var addedTexts []string
			for i, it := range items {
				id, err := t.addOneGoal(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
				addedTexts = append(addedTexts, strings.TrimSpace(it.Text))
			}
			if len(addedTexts) > 0 {
				// 唤醒 planner(整批一次)。优先 notifyGoal:一次 set_goals 记一条「人新增了
				// N 个目标:…」触发,不逐条刷屏;拆解器/worker 无此回调 → 退回纯 notify(拆解器
				// round-0 连 notify 也没接,即无操作,因为此时 planner 尚未启动)。
				switch {
				case t.notifyGoal != nil:
					t.notifyGoal(addedTexts)
				case t.notify != nil:
					t.notify()
				}
				// 主 agent 运行时新增目标 → 把已完成/暂停的任务拉回 running 继续跑(终态门会
				// 吞掉普通 notify,必须显式复活)。仅 mainagent 接了此回调;拆解器/worker 为 nil。
				if t.resumeTask != nil {
					t.resumeTask()
				}
			}

			if !batch { // 单条:保持原返回
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("goal added: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

type constraintItem struct {
	Text string `json:"text"`
	Type string `json:"type"` // allow | deny
}

// addOneConstraint 落一条操作约束到 task_constraints。origin 取 t.worker(缺省 system):
// 拆解器写 "goals"、主 agent 写 "human"。
func (t *ToolSet) addOneConstraint(it constraintItem) (int64, error) {
	text := strings.TrimSpace(it.Text)
	if text == "" {
		return 0, fmt.Errorf("text 不能为空")
	}
	kind := strings.TrimSpace(strings.ToLower(it.Type))
	if kind == "" {
		kind = "deny" // 默认按禁止处理:未标注类型时更保守
	}
	if kind != "allow" && kind != "deny" {
		return 0, fmt.Errorf("type 必须是 allow 或 deny")
	}
	return t.ts.AddConstraint(kind, text, t.worker)
}

// setConstraints 给【本任务】新增操作约束(allow=允许做什么 / deny=禁止做什么)。既是目标
// 拆解器 round-0 抽约束的提交工具,也是主 agent 运行时补约束的工具——同一受管工具,可在 web
// 端改描述/schema、按 agent 绑定。约束会被注入 planner/worker 的系统提示以约束探索边界。
func (t *ToolSet) setConstraints() actool.CoreTool {
	return writeTool("set_constraints",
		"给【本任务】新增操作约束,用来框定探索边界:type=allow(允许做的操作)或 deny(禁止做的操作)。\n"+
			"约束=对『可以/不可以做哪些操作』的规定(如『仅测当前端口,不扫其他端口』『禁止对生产库做写操作』『只允许被动侦察』),不是目标、也不是攻击步骤。\n"+
			"★优先批量:多条放进 constraints 数组一次提交,返回 ids 与之等长同序(失败项 id=0,详情见 errors)。单条则省略 constraints 直接给顶层 text/type。\n"+
			"只登记任务目标/描述里【明确写出】的约束,不要臆造;拿不准类型时用 deny(更保守)。",
		obj(map[string]any{
			"constraints": map[string]any{"type": "array", "description": "【优先用这个】要新增的约束数组,按顺序处理。每个元素:text(必填,一条约束)+ type(allow|deny)。返回 ids 与本数组等长、同序。", "items": map[string]any{"type": "object"}},
			"text":        str("[单条] 一条操作约束的内容"),
			"type":        str("[单条] allow(允许)或 deny(禁止);缺省按 deny 处理"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.ts == nil {
				return actool.Errorf("set_constraints 未启用: ExplorationStore 未初始化"), nil
			}
			var a struct {
				Constraints    []constraintItem `json:"constraints"`
				constraintItem                  // 单条模式:顶层 text/type
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Constraints) > 0
			items := a.Constraints
			if !batch {
				items = []constraintItem{a.constraintItem}
			}
			ids := make([]int64, len(items))
			errs := map[string]string{}
			for i, it := range items {
				id, err := t.addOneConstraint(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
			}
			if !batch { // 单条:保持简单返回
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("constraint added: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

func (t *ToolSet) addHint() actool.CoreTool {
	return t.writeExpTool("add_hint", "把人类/主 agent 的战略提示挂到探索图，规划者下次生成意图时会读到它。\n"+
		"★优先批量：多条提示放进 hints 数组一次提交（比逐条调用省往返）。返回 ids 数组，与 hints 等长同序（失败项 id=0，详情见 errors）。单条则省略 hints 直接给顶层 text。",
		obj(map[string]any{
			"hints":        map[string]any{"type": "array", "description": "【优先用这个】要新增的提示数组，按顺序处理。每个元素字段同下方顶层字段（text/asset_ids/traffic_refs）。返回 ids 与本数组等长、同序。", "items": obj(map[string]any{"text": str("提示内容"), "asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}}, "traffic_refs": HintTrafficSchema()})},
			"text":         str("[单条] 提示内容，如'重点挖认证后接口'"),
			"traffic_refs": HintTrafficSchema(),
			"asset_ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "锚定的资产 id（可选，0/1/多个）"},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Hints    []hintItem `json:"hints"`
				hintItem            // 单条模式：顶层 text/asset_ids
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Hints) > 0
			items := a.Hints
			if !batch {
				items = []hintItem{a.hintItem}
			}

			ids := make([]int64, len(items))
			errs := map[string]string{}
			var addedTexts []string
			for i, it := range items {
				id, err := t.addOneHint(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
				addedTexts = append(addedTexts, strings.TrimSpace(it.Text))
			}
			if len(addedTexts) > 0 {
				// 唤醒 planner（整批一次）。优先 notifyHint：一次 add_hint 记一条「人新增了
				// N 条战略提示：…」触发，让 planner 明确"本轮由新增 hint 触发"并看到提示内容；
				// 未接该回调时退回纯 notify（bare wake，hint 仍折在图里供其自行读取）。
				switch {
				case t.notifyHint != nil:
					t.notifyHint(addedTexts)
				case t.notify != nil:
					t.notify()
				}
			}

			if !batch { // 单条：保持原返回
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("hint added: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

// killWorkTool lets the planner terminate a single running work (by intent id).
func (t *ToolSet) killWorkTool() actool.CoreTool {
	return t.writeExpTool("kill_work", "终止一条正在运行的意图(work)。用于叫停跑偏/无意义的探索；被终止的意图标记为 stopped，不再自动重领。先用 get_worker_output 看看它在干嘛再决定。",
		obj(map[string]any{"intent_id": idp("要终止的意图 id（= work 句柄）")}, "intent_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.killWork == nil {
				return actool.Errorf("kill_work 当前不可用"), nil
			}
			var a struct {
				IntentID json.RawMessage `json:"intent_id"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id 必填"), nil
			}
			node, err := t.ts.GetNode(id)
			if err != nil || node == nil || node.Kind != db.KindIntent {
				return actool.Errorf("intent_id 必须是本任务的意图（关联任务意图只读）"), nil
			}
			if err := t.killWork(id); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("已向意图 %d 的 work 发送终止信号", id)), nil
		})
}

// steerWorkTool lets the planner inject a mid-run course-correction into a running
// work WITHOUT killing it: the message reaches the worker before its next tool call,
// which re-plans its next step (already-gathered context is kept). For in-intent
// nudges ("停做 X、聚焦 Y"); if the whole direction is wrong use kill_work + a new intent.
func (t *ToolSet) steerWorkTool() actool.CoreTool {
	return t.writeExpTool("steer_work", "给一条正在运行的意图(work)实时注入纠偏指令，不打断它、不丢已有进展：worker 会在下一步动作前收到你的指令并据此调整。用于'别再走 X、聚焦 Y'这类【意图内】纠偏；若方向整个错了应改用 kill_work 再下新意图。建议先用 get_worker_output 看它在干嘛。",
		obj(map[string]any{
			"intent_id": idp("要纠偏的意图 id（= work 句柄）"),
			"message":   str("给 worker 的纠偏指令，明确让它停止什么、转向什么"),
		}, "intent_id", "message"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.steerWork == nil {
				return actool.Errorf("steer_work 当前不可用"), nil
			}
			var a struct {
				IntentID json.RawMessage `json:"intent_id"`
				Message  string          `json:"message"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id 必填"), nil
			}
			node, err := t.ts.GetNode(id)
			if err != nil || node == nil || node.Kind != db.KindIntent {
				return actool.Errorf("intent_id 必须是本任务的意图（关联任务意图只读）"), nil
			}
			if strings.TrimSpace(a.Message) == "" {
				return actool.Errorf("message 必填"), nil
			}
			if err := t.steerWork(id, a.Message); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("已向意图 %d 的 work 注入纠偏指令（下一步生效）", id)), nil
		})
}

// getWorkerOutput returns a work's final (or截至中止时的) conclusion text by intent id.
func (t *ToolSet) getWorkerOutput() actool.CoreTool {
	return t.readExpTool("get_worker_output", "取本任务或直接关联任务某条意图(work)的最终输出结论。关联任务结果带 source_task_id/inherited=true 且只读。正常结束返回其总结；被终止(stopped)/异常的 work 返回其截至中止时的最后输出。",
		obj(map[string]any{"intent_id": idp("意图 id（= work 句柄）")}, "intent_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				IntentID json.RawMessage `json:"intent_id"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id 必填"), nil
			}
			intentNode, err := t.ts.GetNodeWithSources(id)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if intentNode == nil || intentNode.Kind != db.KindIntent {
				return actool.Errorf("intent_id 不属于本任务或其直接关联任务"), nil
			}
			acts, _, err := t.ts.ActivityListWithSources(id, 0, 1000)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var chosen, fallback *db.Activity
			for i := range acts {
				switch acts[i].Kind {
				case "result":
					chosen = &acts[i]
					fallback = &acts[i]
				case "text":
					fallback = &acts[i]
				}
			}
			pick := chosen
			if pick == nil {
				pick = fallback
			}
			if pick == nil {
				if intentNode.Inherited {
					return jsonResult(inheritedMap(map[string]any{
						"intent_id": id, "final_text": "（该 work 尚无任何输出）",
					}, intentNode.SourceTaskID))
				}
				return actool.Text("（该 work 尚无任何输出）"), nil
			}
			detail, _ := t.ts.ActivityDetailWithSources(pick.ID)
			if detail == "" {
				detail = pick.Summary
			}
			result := map[string]any{
				"intent_id": id, "final_text": detail,
				"summary": pick.Summary, "is_error": pick.IsError,
			}
			if intentNode.Inherited {
				inheritedMap(result, intentNode.SourceTaskID)
			}
			return jsonResult(result)
		})
}

// traceSteps renders summary-only trace rows, re-truncating each summary to 100
// chars — the stored summary is capped at 200 for the UI transcript; the trace
// tools want it tighter since a whole work's step list is many rows.
func traceSteps(acts []db.Activity) []map[string]any {
	steps := make([]map[string]any, 0, len(acts))
	for i := range acts {
		step := map[string]any{
			"step_id": acts[i].ID, "kind": acts[i].Kind, "tool": acts[i].Tool,
			"is_error": acts[i].IsError, "summary": firstLine(acts[i].Summary, 100),
		}
		if acts[i].Inherited {
			inheritedMap(step, acts[i].SourceTaskID)
		}
		steps = append(steps, step)
	}
	return steps
}

// getWorkerTrace exposes a work's execution PROCESS (not just its final output):
// list step summaries, keyword-search within one work, or pull full detail of a
// few specific steps. Thinking steps are excluded everywhere.
func (t *ToolSet) getWorkerTrace() actool.CoreTool {
	return t.readExpTool("get_worker_trace",
		"查看某条意图(work)的【执行过程】（区别于 get_worker_output 只给最终结论）。三种用法：\n"+
			"① 只传 intent_id → 返回该 work 每一步的摘要流（summary≤100字，含 step_id；只是动作轮廓，不含完整输出）；\n"+
			"② intent_id + q → 只返回命中关键字的步骤摘要（在摘要和完整输出里都搜；仍只给 summary，要看内容用③）；\n"+
			"③ intent_id + step_ids → 返回这些步骤的完整内容(detail)；一次最多取 5 个，超出只返回前 5 个并在 notice/omitted_step_ids 里告知未取的。\n"+
			"典型流程：先①/②定位可疑步骤的 step_id，再用③取其完整输出。不含思考(thinking)步骤。支持直接关联任务的历史 trace；其结果带 source_task_id/inherited=true 且只读。",
		obj(map[string]any{
			"intent_id": idp("意图 id（= work 句柄）"),
			"q":         str("关键字：只返回摘要/完整输出命中它的步骤（可选；与 step_ids 互斥）"),
			"step_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "要取完整内容的 step_id（来自①/②返回；一次最多取 5 个，多传只返回前 5 个，其余在 omitted_step_ids 里列出）"},
			"limit":     intp("摘要流/检索的返回上限（可选）"),
		}, "intent_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				IntentID json.RawMessage   `json:"intent_id"`
				Q        string            `json:"q"`
				StepIDs  []json.RawMessage `json:"step_ids"`
				Limit    int               `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id 必填"), nil
			}
			intentNode, nodeErr := t.ts.GetNodeWithSources(id)
			if nodeErr != nil {
				return actool.Errorf(nodeErr.Error()), nil
			}
			if intentNode == nil || intentNode.Kind != db.KindIntent {
				return actool.Errorf("intent_id 不属于本任务或其直接关联任务"), nil
			}
			// ③ detail drill-down by step ids, thinking excluded by the store.
			if len(a.StepIDs) > 0 {
				// Dedup + drop invalid ids first so garbage/duplicates don't eat into
				// the per-call cap. detail is returned in full (untruncated), so the
				// cap bounds one tool result; over the cap we serve the first N and
				// tell the model exactly which ids were deferred, instead of erroring
				// and forcing it to re-plan the call.
				const maxStepIDs = 5
				var ids []int64
				seen := make(map[int64]bool)
				for _, raw := range a.StepIDs {
					if v := pid(raw); v > 0 && !seen[v] {
						seen[v] = true
						ids = append(ids, v)
					}
				}
				var omitted []int64
				if len(ids) > maxStepIDs {
					omitted = append(omitted, ids[maxStepIDs:]...)
					ids = ids[:maxStepIDs]
				}
				acts, err := t.ts.ActivityByIDsWithSources(ids)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				steps := make([]map[string]any, 0, len(acts))
				for i := range acts {
					if acts[i].NodeID == nil || *acts[i].NodeID != id || acts[i].Inherited != intentNode.Inherited ||
						(acts[i].Inherited && acts[i].SourceTaskID != intentNode.SourceTaskID) {
						continue
					}
					step := map[string]any{
						"step_id": acts[i].ID, "kind": acts[i].Kind, "tool": acts[i].Tool,
						"is_error": acts[i].IsError, "detail": acts[i].Detail,
					}
					if acts[i].Inherited {
						inheritedMap(step, acts[i].SourceTaskID)
					}
					steps = append(steps, step)
				}
				result := map[string]any{"intent_id": id, "steps": steps, "returned_step_ids": ids}
				if len(omitted) > 0 {
					// returned_step_ids/omitted_step_ids let the model decide programmatically
					// whether another call is worth it; the notice states the same in prose.
					result["omitted_step_ids"] = omitted
					result["notice"] = fmt.Sprintf(
						"每次最多取 %d 个步骤的完整内容，本次已返回前 %d 个（%v），未取的 %d 个为 %v。"+
							"若这些内容已足够定位，则无需再取剩余步骤；确需继续时，用这些 step_id 再调一次。",
						maxStepIDs, len(ids), ids, len(omitted), omitted)
				}
				if intentNode.Inherited {
					inheritedMap(result, intentNode.SourceTaskID)
				}
				return jsonResult(result)
			}
			// ①/② summary stream, optionally keyword-filtered; 100-char summaries.
			var acts []db.Activity
			var err error
			if strings.TrimSpace(a.Q) != "" {
				acts, err = t.ts.ActivityTraceSearchWithSources(id, a.Q, a.Limit)
			} else {
				acts, err = t.ts.ActivityTraceWithSources(id, a.Limit)
			}
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			result := map[string]any{"intent_id": id, "steps": traceSteps(acts)}
			if intentNode.Inherited {
				inheritedMap(result, intentNode.SourceTaskID)
			}
			return jsonResult(result)
		})
}

// searchAllWorkerTraces keyword-searches EVERY work's process in this task — for
// finding what a worker saw but never wrote back as a fact. Returns only matching
// summaries (≤100 chars), each tagged with its intent_id for follow-up drill-down.
func (t *ToolSet) searchAllWorkerTraces() actool.CoreTool {
	return t.readExpTool("search_all_worker_traces",
		"【通常不推荐使用，因为系统中已经给了大部分信息了】在【本任务其他 work 的执行过程】里按关键字(q)检索——用于找回某个 worker 见过、却没写进 fact 的东西（某路径/token/报错等）。"+
			"已自动排除你自己这条意图的步骤（那些本就在你上下文里）。"+
			"只返回命中步骤的摘要(summary≤100字)，每条带 intent_id；据此再用 get_worker_trace(intent_id, step_ids=[...]) 取完整内容。",
		obj(map[string]any{
			"q":     str("关键字（在所有 work 步骤的摘要+完整输出里搜）"),
			"limit": intp("返回上限，默认 100（可选）"),
		}, "q"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Q     string `json:"q"`
				Limit int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Q) == "" {
				return actool.Errorf("q 必填"), nil
			}
			// 排除调用者自身这条意图的步骤（worker 的自有 trace 已在其上下文里）。
			acts, err := t.ts.ActivityTraceSearchAllWithSources(t.ownerNode, a.Q, a.Limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			hits := make([]map[string]any, 0, len(acts))
			for i := range acts {
				var intent int64
				if acts[i].NodeID != nil {
					intent = *acts[i].NodeID
				}
				hit := map[string]any{
					"intent_id": intent, "step_id": acts[i].ID, "worker": acts[i].Worker,
					"kind": acts[i].Kind, "tool": acts[i].Tool, "is_error": acts[i].IsError,
					"summary": firstLine(acts[i].Summary, 100),
				}
				if acts[i].Inherited {
					inheritedMap(hit, acts[i].SourceTaskID)
				}
				hits = append(hits, hit)
			}
			return jsonResult(map[string]any{"query": a.Q, "hits": hits})
		})
}

// listWorkerTraces gives planner/mainagent a lightweight index of the works in
// this task — intent_id + one-line summary + state — so they can DISCOVER which
// works to inspect via get_worker_trace during cross-work review. Registered in
// MainAgentTools only: workers get their per-intent context from the engine and
// must not wander the graph (tools_insert.go WorkerTools 注释)。Excludes
// still-open intents (not yet run → no process to inspect).
func (t *ToolSet) listWorkerTraces() actool.CoreTool {
	return t.readExpTool("list_worker_traces",
		"【通常不推荐使用，因为系统中已经给了大部分信息了】列出本任务里【已跑过的 work（意图）】索引：intent_id + 一句话方向(summary) + 状态。"+
			"你(mainagent/planner 视角)通常已能从 graph_overview 看到全局；需要逐 work 复盘执行过程时，用它先发现有哪些 work 值得翻看——再用 get_worker_trace(intent_id) 看其步骤、get_worker_trace(intent_id, step_ids=[...]) 取详情。"+
			"只列已执行的(running/done/exhausted/blocked/stopped)，不含还没跑的 open。",
		obj(map[string]any{
			"q":     str("按 summary 关键字过滤（可选）"),
			"limit": intp("返回上限，默认 50（可选）"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Q     string `json:"q"`
				Limit int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 {
				limit = 50
			}
			all, err := t.ts.ListByKindWithSources(db.KindIntent, 500)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			q := strings.ToLower(strings.TrimSpace(a.Q))
			out := make([]map[string]any, 0, limit)
			for _, n := range all {
				if n.Inherited && n.State == "running" {
					continue
				}
				switch n.State {
				case "running", "done", "exhausted", "blocked", "stopped": // has run → has a process
				default:
					continue
				}
				var p map[string]any
				_ = json.Unmarshal(n.Payload, &p)
				summary, _ := p["summary"].(string)
				if q != "" && !strings.Contains(strings.ToLower(summary), q) {
					continue
				}
				item := map[string]any{"intent_id": n.ID, "summary": summary, "state": n.State}
				if n.Inherited {
					inheritedMap(item, n.SourceTaskID)
				}
				out = append(out, item)
				if len(out) >= limit {
					break
				}
			}
			return jsonResult(map[string]any{"works": out})
		})
}

// PlannerTools is the read + intent-generation + goal-judgement tool set.
func (t *ToolSet) PlannerTools() []actool.CoreTool {
	return []actool.CoreTool{
		t.graphOverview(), t.listFindings(), t.listFacts(), t.nodeDetail(),
		// cold-digest §6.1: restore folded cold nodes (digest body → members → detail).
		t.expandDigest(),
		t.getWorkerOutput(), t.getWorkerTrace(), t.searchAllWorkerTraces(), t.listGoals(), t.addIntent(), t.retireIntent(), t.proveGoal(), t.goalMet(),
		t.killWorkTool(), t.steerWorkTool(),
		// report_finding：规划态势研判时若自身已确证漏洞，可直接登记（与 worker 同工具）。
		t.addFinding(),
		// list_companies：查看企业列表 + scope + 资产数（拿 company_id / 理解归属范围）。
		t.listCompanies(),
		// list_assets：规划时按 DSL 检索全资产库（配合 list_untested_assets 的"范围内未测"视角，
		// 补上"按域名/指纹/端口/状态码等条件在整库里查"的能力）。
		t.listAssets(),
		// add_company_scope：规划时可把域名/IP/CIDR/ICP/关键词纳入某公司的资产范围（自动认领命中资产）。
		t.addCompanyScope(),
		// add_task_scope：主动把整根域/整公司/某子域/IP 纳入本任务测试范围(覆盖度分母)。
		t.addTaskScope(),
		// list_untested_assets：按需查本任务范围内未测资产(类型+分页)，自行决定补测。
		t.listUntestedAssets(),
		// search_vulns / get_vuln：识别出目标组件后查公开已知漏洞（NVD+KEV），
		// 规划阶段把「有现成利用的方向」排进 todolist。
		t.searchVulns(), t.getVuln(), t.getPoc(), t.scanWithNuclei(), t.netContext(),
		// listener_*：回连接收器（红队 C2 前置）——start/stop 走 ask 审批，sessions 只读。
		t.listenerStart(), t.listenerStop(), t.listenerSessions(),
		// auth_request：用资产上已登记的凭据组装带认证的请求（横向/越权验证的前提）。
		t.authRequest(),
		// diff_responses：对比两个响应的结构性差异（越权/可枚举/状态机三类的共同基础）。
		t.diffResponses(),
		// api_contract：读目标暴露的 API 契约文件，拿到比爬虫更准的接口清单。
		t.apiContractTool(),
		// search_recent_critical：按【时间】查最近披露的高危漏洞（不需先知道组件名/CVE 号）。
		t.searchRecentCritical(),
	}
}

// stallOverview 计算本任务的"边际收益"态势:最近的产出轮是第几轮、
// 距今几轮无新 fact/finding(零产出即停)。读 activity 的 round/result
// 流水在 SQL 一把算,per-turn 开销受探索图 EXPLAIN的可控范围。
// 返回 nil 也有意义:任务还年轻,没到能谈收官的规模。
func (t *ToolSet) stallOverview() map[string]any {
	rounds, recentNew, openCnt, err := t.ts.StallOverview()
	if err != nil {
		return nil
	}
	out := map[string]any{"planner_rounds": rounds}
	if rounds < 5 {
		// 前几轮还在打底,谈边际收益太早
		return out
	}
	out["new_facts_findings_6h"] = recentNew
	out["open_intents_now"] = openCnt
	// 提示位:零新产出 + 无 open → 建议收官
	if recentNew == 0 && openCnt == 0 {
		out["hint"] = "最近 6 小时无新 fact/finding 且无 open 意图——边际收益可能已耗尽。若目标确已尽力," +
			"用 goal_met 收官(reason 写明边际收益耗尽的诚实小结);仍有未测方向就继续派意图。"
	}
	return out
}
