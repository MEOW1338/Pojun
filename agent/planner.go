package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/intercept"
)

// Planner is the event-driven LLM planner (docs §4.3): each time the asset or
// exploration graph changes (debounced), it reads the exploration route, queries
// assets, judges whether the task goal is met, and emits 0..N exploration intents
// into the frontier. It is the sole intent generator.
type Planner struct {
	findingRecorder FindingRecorder
	// 授权边界守卫开关（v0.4.63）：装配时从设置读取，传到 ToolSet。
	scopeGuard           bool
	scopeInheritWrites   bool
	crossTaskNotifyDedup bool
	prov                 llm.Provider
	model                string
	tx                   *transcript.Store                      // raw LLM conversation persistence (nil = off)
	window               int                                    // context window in tokens (for compaction)
	windowFn             func() int                             // optional dynamic task-chain minimum
	maxTurns             int                                    // max agent turns per run (0 = unlimited)
	killWork             func(intentID int64) error             // engine callback to terminate a running work (nil = off)
	steerWork            func(intentID int64, msg string) error // engine callback to steer a running work mid-run (nil = off)
	attributions         func() map[string]any                  // Guard 归因读取（nil = 概览不带 guard_attributions 块）
	proxyAddr            string                                 // recording proxy for WebFetch (empty = direct)
	proxyCACert          string                                 // recording proxy's CA cert path (HTTPS verify)
	webSearch            WebSearchOpts                          // web_search tool backend selection (off by default)
	workDir              string                                 // shared work dir (surfaced in prompt as artifact-output target)
	injectConstraints    func() bool                            // resolver: inject task operation constraints into system prompt? (nil = yes)
	nonStreamingFn       func() bool                            // resolver: use non-streaming (Complete) path? (nil = streaming)
	noaEnabledFn         func() bool                            // resolver: use experimental noa compaction? (nil = off)
	maxTokensFn          func() int                             // resolver: per-reply output cap (nil/0 = send no cap)
	compactor            *Compactor                             // cold-node compaction (§7); nil = disabled

	// todos keeps ONE plan-scratchpad per task (keyed by exploration id) so the
	// planner's multi-step plan survives across wake-ups — each Plan() is a fresh
	// session, but the shared store lets it record a serial exploit chain once and
	// dispatch it step-by-step over rounds instead of front-loading it in parallel.
	todoMu sync.Mutex
	todos  map[int64]*actool.TodoStore
}

func NewPlanner(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *Planner {
	return &Planner{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, todos: map[int64]*actool.TodoStore{}}
}

func (p *Planner) SetScopeFlags(scopeGuard, scopeInheritWrites, crossTaskNotifyDedup bool) {
	p.scopeGuard = scopeGuard
	p.scopeInheritWrites = scopeInheritWrites
	p.crossTaskNotifyDedup = crossTaskNotifyDedup
}

func (p *Planner) SetCompactionWindowResolver(fn func() int) { p.windowFn = fn }

// SetCompactor wires the cold-node compactor (cold-digest §7). Called each
// planner wake-up to advance the round counter, maintain cold stamps, and
// (off the hot path) fold cold nodes into digests. nil = feature disabled.
func (p *Planner) SetCompactor(c *Compactor) { p.compactor = c }

// SetNonStreaming wires a resolver deciding whether runs use the non-streaming
// model path (true = non-streaming). nil/unset = streaming (default).
func (p *Planner) SetNonStreaming(fn func() bool) { p.nonStreamingFn = fn }

func (p *Planner) nonStreaming() bool { return p.nonStreamingFn != nil && p.nonStreamingFn() }

// SetNoaEnabled wires a resolver deciding whether runs use the experimental noa
// context-compression mechanism. nil/unset = off (built-in compaction). Read per
// run so the settings toggle takes effect without rebuilding the agent.
func (p *Planner) SetNoaEnabled(fn func() bool) { p.noaEnabledFn = fn }

// SetMaxTokens wires a resolver for the per-reply output cap. nil/unset or 0 =
// send no cap and let the endpoint decide. Read per run, like nonStreaming.
func (p *Planner) SetMaxTokens(fn func() int) { p.maxTokensFn = fn }

func (p *Planner) maxTokens() int {
	if p.maxTokensFn == nil {
		return 0
	}
	return p.maxTokensFn()
}

func (p *Planner) compactionWindow() int {
	if p.windowFn != nil {
		return p.windowFn()
	}
	return p.window
}

// SetProxy points the planner's WebFetch at the recording proxy plus the CA cert
// it trusts to verify HTTPS through it (empty addr = direct).
func (p *Planner) SetProxy(addr, caCert string) { p.proxyAddr, p.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for the planner (off by default).
func (p *Planner) SetWebSearch(o WebSearchOpts) { p.webSearch = o }

// SetConstraintInject wires a resolver deciding whether this task's operation
// constraints get injected into the planner system prompt. Read per round so the
// settings toggle takes effect without rebuilding the agent. nil = inject (default).
func (p *Planner) SetConstraintInject(fn func() bool) { p.injectConstraints = fn }

// wantConstraints reports whether constraint injection is enabled (default yes).
func (p *Planner) wantConstraints() bool { return p.injectConstraints == nil || p.injectConstraints() }

// todoFor returns the task's persistent planning todo store, creating it on first
// use. Shared across all of this task's planner wake-ups.
func (p *Planner) todoFor(expID int64) *actool.TodoStore {
	p.todoMu.Lock()
	defer p.todoMu.Unlock()
	s := p.todos[expID]
	if s == nil {
		s = actool.NewTodoStore()
		p.todos[expID] = s
	}
	return s
}

// SetKillWork wires the engine's per-work terminate callback so the planner's
// kill_work tool can stop a single running worker.
func (p *Planner) SetKillWork(fn func(intentID int64) error) { p.killWork = fn }

// SetSteerWork wires the engine's per-work steering callback so the planner's
// steer_work tool can inject a mid-run course-correction into a running worker.
func (p *Planner) SetSteerWork(fn func(intentID int64, msg string) error) { p.steerWork = fn }

// SetAttributions wires the per-task Guard failure-attribution reader so
// graph_overview can carry guard_attributions (blocked/error 计数 → planner 换打法).
func (p *Planner) SetAttributions(fn func() map[string]any) { p.attributions = fn }

// renderPlannerTodos formats the persistent planning todo for injection into the
// wake-up prompt (empty when there are no todos yet — first wake-up).
func renderPlannerTodos(items []actool.Todo) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n【你的规划待办（跨唤醒保留，上一轮你写的）】：\n")
	for _, it := range items {
		mark := map[actool.TodoStatus]string{actool.TodoPending: "☐", actool.TodoInProgress: "▶", actool.TodoCompleted: "✔"}[it.Status]
		if mark == "" {
			mark = "☐"
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", mark, it.Content))
	}
	b.WriteString("据此推进：只对【前置步骤已完成 / 其依赖的 fact 已存在】的下一步派意图；用 TodoWrite 更新清单（把已被 fact 满足的步骤标 completed）。不要重复派已在清单里 pending/in_progress 的步骤。")
	return b.String()
}

// TriggerEvent describes what concretely caused this planning round to fire, so
// the planner looks first at the actual change instead of re-scanning the whole
// overview. Kind:
//
//	"done"    — a worker finished intent IntentID (its output conclusion is fetched).
//	"finding" — a worker reported a finding on intent IntentID (Detail = 摘要).
//	"goal"    — the human (via 主 agent 的 set_goals) added one OR MORE goals in a
//	            single call (Goals = 本次新增的目标文本，1+ 条；set_goals 支持批量).
//	"goal_deleted" — the human deleted a goal from 总览的目标管理 (Detail = 被删目标文本).
//	"goal_edited"  — the human edited a goal from 总览的目标管理 (OldGoal→NewGoal 文本).
//	"cancelled" — the human deleted intent IntentID (Detail = 删除原因). The intent is
//	            stopped (not deleted) and the reason is attached to it as a fact.
//	"review"   — intent IntentID ended exhausted with ZERO write-back (B2:「烧了一整轮
//	            却什么都没留下」). Detail = 该方向最近几步的实动作摘要，事件自带复盘指令。
type TriggerEvent struct {
	Kind     string
	IntentID int64
	Detail   string
	Summary  string   // Kind=="cancelled" 专用：删除前捕获的意图摘要（真删除后节点已不存在，无法再查）
	Goals    []string // Kind=="goal" 专用：本次 set_goals 新增的目标文本（1 条或多条）
	OldGoal  string   // Kind=="goal_edited" 专用：修改前的目标文本
	NewGoal  string   // Kind=="goal_edited" 专用：修改后的目标文本
	Hints    []string // Kind=="hint" 专用：本次 add_hint 新增的提示文本（1 条或多条）
}

// renderTriggers spells out the change(s) that fired this round: for a finished
// worker — which intent + its output conclusion; for a finding — which intent +
// what was found. Empty for time/heartbeat wakes. Reads the store (best-effort;
// a blank field never blocks the round).
func renderTriggers(ts *db.ExplorationStore, evs []TriggerEvent) string {
	if len(evs) == 0 || ts == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n【本次触发本轮的实际变动（先看这里，再决定是否补方向）】：")
	for _, ev := range evs {
		switch ev.Kind {
		case "goal":
			if len(ev.Goals) == 1 {
				b.WriteString(fmt.Sprintf("\n- 人（主 agent）新增了一个目标：%s —— 新的待达成目标，请据此补充探索方向（若尚无对应意图）。", ev.Goals[0]))
			} else {
				b.WriteString(fmt.Sprintf("\n- 人（主 agent）新增了 %d 个目标：%s —— 均为新的待达成目标，请逐一为尚无对应意图的目标补充探索方向。", len(ev.Goals), strings.Join(ev.Goals, "；")))
			}
		case "hint":
			if len(ev.Hints) == 1 {
				b.WriteString(fmt.Sprintf("\n- 人（主 agent）新增了一条战略提示：%s —— 已挂到探索图上，请据此调整/补充探索方向（若尚无对应意图）。", ev.Hints[0]))
			} else {
				b.WriteString(fmt.Sprintf("\n- 人（主 agent）新增了 %d 条战略提示：%s —— 均已挂到探索图上，请逐一据此调整/补充探索方向。", len(ev.Hints), strings.Join(ev.Hints, "；")))
			}
		case "goal_deleted":
			b.WriteString(fmt.Sprintf("\n- 人删除了该目标：%s —— 该目标已移除，请据此重判剩余目标/方向（不必再为它派意图）。", ev.Detail))
		case "goal_edited":
			b.WriteString(fmt.Sprintf("\n- 人修改了目标，由「%s」变为「%s」—— 请据新目标调整探索方向（原方向若已不适用请停派）。", ev.OldGoal, ev.NewGoal))
		case "finding":
			b.WriteString(fmt.Sprintf("\n- 意图 #%d（%s）的 worker 报告了一个 finding：%s", ev.IntentID, intentSummary(ts, ev.IntentID), ev.Detail))
		case "cancelled":
			// 意图内容优先用删除时捕获的 Summary（真删除后节点已不存在，intentSummary 查不到）。
			sm := ev.Summary
			if sm == "" {
				sm = intentSummary(ts, ev.IntentID)
			}
			b.WriteString(fmt.Sprintf("\n- 意图 #%d 由用户删除，意图内容是：%s、删除原因是：%s。该意图已删除（不再执行）；请据此重新规划。", ev.IntentID, sm, ev.Detail))
		case "review":
			// B2：exhausted 且零写回。指令内嵌在事件文本里（不为此加长 planner 种子提示词）；
			// 步骤摘要缺失时给出主动复盘的替代路径，不让指令变得空手。
			tail := strings.TrimSpace(ev.Detail)
			if tail == "" {
				tail = "（步骤摘要缺失，可用 get_worker_trace 拉取该意图的执行轨迹）"
			}
			b.WriteString(fmt.Sprintf("\n- 意图 #%d（%s）撞上限收场，但这轮没有写回任何东西（事实 0 / 资产 0 / 漏报 0）。它最近几步的实际动作是：%s。请勿直接丢弃这段尝试：先落一条 fact（derived_from 指向该意图，写清「试过什么、为何无效」），然后再判断这个方向还值不值得派。", ev.IntentID, intentSummary(ts, ev.IntentID), tail))
		default: // "done"
			b.WriteString(fmt.Sprintf("\n- 意图 #%d（%s）的 worker 结束，输出结论：%s", ev.IntentID, intentSummary(ts, ev.IntentID), workerOutput(ts, ev.IntentID)))
			// stop_reason 同步带出（B1）：exhausted=手段穷尽可接续、blocked=传输故障可重试、
			// stopped=被 kill——「接续 vs 换方向」的判断直接看它，不用再 node_detail。
			if n, err := ts.GetNode(ev.IntentID); err == nil && n != nil && n.BlockedReason != "" {
				b.WriteString(fmt.Sprintf("；收场原因 stop_reason=%s", n.BlockedReason))
			}
			if fids := factIDsYielded(ts, ev.IntentID); fids != "" {
				b.WriteString(fmt.Sprintf("；本意图新产生的事实 id：%s ", fids))
			}
		}
	}
	b.WriteString("\n（完整细节可 node_detail / get_worker_output / list_findings 再查。）")
	return b.String()
}

// factIDsYielded lists the fact ids an intent produced this run as "#12、#15", so the
// planner can jump straight to the round's incremental facts. Empty (best-effort) when
// the intent yielded no facts or the lookup fails.
func factIDsYielded(ts *db.ExplorationStore, id int64) string {
	ids, err := ts.FactsYielded(id)
	if err != nil || len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, fid := range ids {
		parts[i] = fmt.Sprintf("#%d", fid)
	}
	return strings.Join(parts, "、")
}

// intentSummary reads an intent node's one-line summary (best-effort, "?" on miss).
func intentSummary(ts *db.ExplorationStore, id int64) string {
	n, err := ts.GetNode(id)
	if err != nil || n == nil {
		return "?"
	}
	var p map[string]any
	if json.Unmarshal(n.Payload, &p) == nil {
		if s, ok := p["summary"].(string); ok && s != "" {
			return s
		}
	}
	return "?"
}

// workerOutput returns the finished worker's conclusion for an intent — the last
// 'result' (else 'text') activity's full detail, truncated. Same source get_worker_output uses.
func workerOutput(ts *db.ExplorationStore, id int64) string {
	acts, _, err := ts.ActivityList(&id, 0, 1000)
	if err != nil {
		return "(取输出失败)"
	}
	var pick *db.Activity
	for i := range acts {
		if acts[i].Kind == "result" {
			pick = &acts[i]
		} else if acts[i].Kind == "text" && pick == nil {
			pick = &acts[i]
		}
	}
	if pick == nil {
		return "(该 work 尚无输出记录)"
	}
	out, _ := ts.ActivityDetail(pick.ID)
	if out == "" {
		out = pick.Summary
	}
	return truncOutput(out, 800)
}

// truncOutput caps a worker-output blob so the trigger context doesn't bloat the
// system prompt every round; full text is one get_worker_output call away.
func truncOutput(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + " …（已截断，完整见 get_worker_output）"
}

// renderGraphOverview folds the pre-computed graph_overview snapshot into the
// wake-up prompt so the planner starts each round with the full situation in
// hand — saving the round-trip it would otherwise spend calling the tool. It is
// the exact same JSON graph_overview would return; deeper detail is still one
// tool call away (node_detail / list_facts / …).
func renderGraphOverview(data map[string]any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back to the model calling graph_overview itself
	}
	return "\n\n【本轮态势（graph_overview 预取，等同你调用该工具的返回；需要细节再按需调 node_detail/list_facts 等）】：\n" + string(b)
}

// plannerDefaultTmpl is the built-in EDITABLE body (段 [A]) of the planner prompt,
// seeded into agent_prompts. Goal is a {{.Goal}} template var; the 中间产物输出规约
// tail is code-owned (artifactSpec) and appended by plannerSystem after rendering.
const plannerDefaultTmpl = `你是一个网络安全平台授权渗透测试系统的"规划者"，被频繁唤醒（图一变就唤醒）。职责：读态势 → 判目标 → **只在确有未被覆盖的新方向时**补充探索意图。你是规划者、不是执行者：本轮所有产物只能是【生成/说清意图】或【判定目标】，绝不在 plan 里把活干了。

任务目标：{{.Goal}}

**本轮该产出几个意图（先想清楚这条）**：
- **硬底线（最高优先）**：只要【目标未达成】且【当前没有任何 open 或 running 意图】（frontier_open=0 且 running_intents 为空），本轮就【必须】产出至少一个向目标推进的意图——没有在跑的 work 可等、也没有在排队的方向时，产出 0 意图=任务停摆；哪怕已知方向都只在 recent_done 里，也要据下面 done/exhausted/blocked 的判断另开一条或续派一条。
- 硬底线之外，**产出 0 个意图是正常结果，但要有正当理由**（不是"少派更稳"的默认）：①**已覆盖**——你想到的方向都已被仍在 open/running 的意图处理（换措辞重复生成已存在的意图是严重错误）；②**等待依赖**——下一步依赖当前在跑 work 的产出、而它还没出来（此时硬派会让下游拿不到前置而空转，应等下次唤醒图更新后再派）。
- 反过来：确有【未覆盖、且不依赖在跑 work】的新方向，或目标未达成且范围内仍有未测面，就该派——别把 0 意图当偷懒的默认。

**每次唤醒的决策流程**：

1. **完整态势已附在本提示下方**（就是 graph_overview 的返回，无需再调它）：task（原始标题+目标/根节点）、goals+状态、open/running/recent_done 意图、frontier_open、facts（探索事实数，与漏洞是两类）、findings_total、recent_facts（{id,summary,confidence?}）、finding_list、recent_done_intents、coverage（有覆盖度统计时）、stall（收官态势）、cold_digests（冷区折叠摘要，expand_digest 展开）、guard_attributions（工具调用归因计数：blocked 高=目标在防——WAF/拦截规则在打回，继续同款打法是烧 token，换向量/换手段/先写意图明确绕行思路；error 高=工具或环境在坏，先诊断再派）。
   - **范围**：探索节点（goals/意图/facts/findings）只含本任务；**资产图全局共享**（多任务同一份，资产计数是全局在范围内的、非本任务独有）——出现非本任务相关的资产时忽略。
   - **血缘**：每个意图带 parents（上游：派生自哪些事实/意图）和 yields（下游：产生了哪些事实/发现），recent_facts 每条带 from_intent；据此理解"哪些事实来自哪个方向、能否综合出新方向"。
   - **否定/存疑观察**（recent_facts 里"端口关闭/不可注入"等）是 worker 的观察、不是定论：采信前先 node_detail(id) 看 evidence——evidence 扎实、confidence=observed 且手段已穷尽的才视为该方向暂时封住；evidence 缺失、只是"看起来像/只探一次"、或 confidence=inferred 的，按【尚未探明】处理，若在范围内且无其它意图覆盖，默认派一条复核意图去证实或推翻（**同一否定方向至多复核一次**；复核后仍为否定、且证据合理，就尊重该结论、不再派）。
   - **要更深细节才按需调**：list_facts（分页，最新在前，默认 20，可 q 过滤、before 翻页，带 total/has_more）、list_findings（全部漏洞）、node_detail(id)（完整证据/详情；列表/recent_facts 只给摘要）、list_assets（DSL 搜索、type 过滤、分页，或 id/ids 直取；找「已登记但还没测」的资产用 list_untested_assets 更省事）、asset_neighbors。资产全局共享，别默认拉全量。

2. **判目标（核心职责）**：goals 字段已含目标与状态；对已被某发现/事实证明的未达成目标，调 prove_goal(goal_id, evidence_id, reason) 标 met。**当你标记的恰是最后一个未完成目标时，系统自动判定整个任务完成**——收官只由逐个 prove_goal 驱动，没有别的"一键完成"手段。
   - ⚠️ **量化验收核对（严禁提前盖章）**：目标含可量化条件（覆盖度达 X%、拿 N 个 flag、获得某权限）时，prove_goal 前【必须】核对上方 graph_overview 的实测值（coverage.pct、findings_total 计数等）：未达标就【禁止】prove_goal，改派意图补差；不得以"大体达成/核心已拿下"为由提前标 met。例：要求覆盖度 100% 而实测 coverage.pct=40% → 未达成，继续派补测意图。
   - **独立复现（critical/high 必配，借鉴 pentest-ai 的 machine oracle）**：recent_facts/漏洞里出现 critical/high、但证据仅来自单一 worker、**没有独立复验事实**（换入口/换参数/换会话/换身份重新触发一次并写回 fact）时，派一条**只做复现、不扩大**的验证意图；已有独立复验事实的不重复派。复现失败 → 把严重性降级并写清原因，不许保留 critical/high。
   - **边际收益收官(目标模糊型任务)**：态势里 stall.hint 出现（连续多轮零新产出、无 open 意图）且目标描述中没有更多可量化缺口——用 goal_met 收官，reason 写「边际收益已耗尽：最近 6 小时无新 fact/finding,已覆盖 <列已测的主要面>」这类诚实小结,【不许】编造达成证据。收官比无产出空转更负责——空转每轮都在烧 token。

3. **（可选，仅开局、极轻量）探测理解**：仅当图里几乎还没有 fact（recent_facts 基本为空、任务刚开始）、仅凭态势无法把初始意图说具体时，才用 Bash 等对目标做极少量、只读的探测（如 1–2 次 curl 看首页/指纹）。**唯一合法产物是一句更精准的意图描述**——绝不是漏洞的发现/验证/利用，也不是端点/目录/参数的枚举结果（那些是 worker 的活，写成意图派下去）。三条硬边界：
   - 图里已有 worker 产出的 fact（facts>0 / recent_facts 非空）→【禁止】再自己探测，一切判断基于已有 fact，本轮产物只能是"派新意图"或"结束"；想深挖某线索 → 派意图让 worker 去查，不是自己 curl。
   - 即使开局也最多探 ≤3 次就收手，只为把初始意图说清；一旦发现自己在"深入查证"而非"快速定方向"（逐个枚举端点/目录、逐个试 id、解码链、反复探同一接口、任何注入/越权/漏洞的测试验证——全是 worker 的重活），立刻停手写成意图。
   - 能从现有事实/态势判断的，根本不必探测。

4. **决定补哪些新方向**：**这里的"克制"只指【不重复已存在的意图】，不是"能少派就少派"**——目标未达成时，默认追问是"为逼近目标，还有哪些更深、更狠、尚未覆盖的打法"，而不是"是否可以收尾"。意图是【开放的探索方向】（不是固定类型/菜单），结合已知事实、资产、目标自判方向，逐一与 open + running + recent_done 比对：
   - 已有 open/running 覆盖 → 不再生成（正在处理）。
   - 在 recent_done 里出现过 → **先看该意图的 state 与 stop_reason（每条都带）分辨怎么停的，再决定**：
     · **done（正常跑完）**：已覆盖 → 不原样重派；是否死路看它 yields 出的 fact 结论、而非 state。**特例：done 且零 yields（一条 fact 都没写回）= 被空转收场，与 exhausted-无增量同处理——方向无增量，不要接续、不要原样重派**。
     · **exhausted（中途收场）**：**分两种，含义完全相反，必须看 stop_reason 区分**：
       — stop_reason 含「产出率已归零 / 无增量」= **worker 探到边界了，这个方向本身没东西了** → **不要接续**，换方向；接续它只是让一个空方向再空转一轮。
       — stop_reason 含「步数上限 / 运行超时」= **还有明确的下一步，只是没时间** → 可以接续，但必须满足下面的接续纪律。
       — blocked（模型或网络失败）= 纯外部故障没跑成 → 直接重派同方向。
       **两种 exhausted 都要先用 get_worker_trace / get_worker_output 看它实际做到哪、卡在哪**，再决定是「接上次进度继续」还是「换打法/换方向」：接近突破被掐 → 接续；每次卡在同一处 → 这条路本身不通，换打法。依据永远是 trace 里的真实进度，不是 state 本身。
   - **接续纪律（避免接续链无限拉长）**：
     · 接续是**有代数上限的**（最多接 3 次，超了 add_intent 会被直接拒绝）。一条方向接了 3 次还没结果，说明问题不在「时间不够」而在「这条路本身不通」或「打法不对」——此时该换打法或换方向，不该再接。
     · **接续必须带增量承诺**：summary 里写清「上次做到 X，本次要拿到 Y；拿不到 Y 就收手」。写不出具体的 Y，说明你也不知道接下去能拿什么——那就别接。
     · **接续要把 continues 字段填上**（上游意图 id），否则接续关系只存在于文字里、代数算不出来、也查不了。
     · 接续优先【带着新信息接】而不是【从头接】：上次已确认的结论要在 summary 里引用（fact id），别让新 worker 把已知的再探一遍。
   - 完全无任何意图覆盖的全新方向 → 生成。
   - 所有已知方向都被仍在 open/running 的意图覆盖 → 不生成、直接结束（有在跑/在排队的 work，等它们推进）；但若只剩 recent_done 覆盖、已无 open/running 而目标未达成 → 按顶部硬底线必须另开或续派。
   - **深度优先于覆盖度**：coverage 是下限/验收项、不是探索目标本身；发现高价值入口（可能通向 RCE/提权/数据外泄）后，优先派意图把那条路【往深打穿】，而不是为拉平覆盖度去铺广、逐个资产浅测。
   - **深度与广度的仲裁（别摇摆）**：发现高价值入口后，允许把该入口的纵深派到 2 条以内（主线+绕行），此时新覆盖面意图暂停一轮；若该入口两轮无增量（stall 口径），恢复铺广铺覆盖。以「两轮无增量」为切换信号，不是凭感觉切换。
   - **【已知面】与【未知面】是两条不同的线，别只打一条**：「已知面」= 查情报库拿现成 CVE（search_vulns / search_recent_critical）——快、收益确定；「未知面」= 从目标自身行为里挖没公开过的漏洞（越权、逻辑缺陷、竞态、状态机绕过、资源假设错误）——慢、但常常是唯一能拿高价值的那条。当目标是「拿到高危漏洞/权限」这类、且已知面已经挖不动时，**应该往未知面派一条意图**。派这类意图前先看 vuln-hunting skill（有七个维度的挖掘方法论与每类手法的验证要点）——不要自己现编一个「试试越权」的模糊意图，那多半挖不到东西。
   - **【数据面扩展】意图族（v0.4.34）**：发现一个未授权/越权数据端点后，不要急着换目标——先派 1–2 条意图把它所在前缀的兄弟只读端点、分页全量、导出接口取干净（summary 写清端点族与时间窗/上限，例如"把 /mgr/test/* 全部只读端点按时间窗取全量并登记证据"）；报告/fact 里写了"具备某能力面但本轮未取到数据"的（如 akRegisterRecord 类），下一轮应优先派意图补取。非破坏铁律不变：写/删/改/发消息类端点只验证存在性、不触发；大批量取数要限速。
   - **【异常是线索，不是机制】**（v0.4.30，借鉴 PentestGPT supervisor 纪律重写）：某个异常响应、可疑参数、版本差异只是【线索】——最多派 1 条【有界】验证意图（summary 写清"只验证 X，看到 Y 算成立"），在同一条假设未决前，不要按"每个可疑点各派一条"铺开；同一目标面最多再加 2 个判别对照（换参数位 / 换身份 / 换方法），照不出差异就记 fact 收手、把线索交下轮。
   - **失败不原样重派**（借鉴 hackingBuddyGPT AD planner 纪律）：同一方向连续 2 次以**相同错误特征** blocked（同一 403/同一超时/同一 WAF 拦截），第三条不再原样重派——必须换实现路径（换工具/换协议/换入口/换身份），或在 summary 里写明与上次的本质差异；写不出差异就不要派。
   - **时间军规 / 升级阶梯（v0.4.35，借鉴 sapper-v2 竞赛军规）**：每条意图的 wall_ms 已在态势里。单条方向**累计 > 25 分钟且连续两轮零新增** → 不再接续，必须换本质不同的打法或换目标面；**> 45 分钟**仍未突破 → 直接放弃该方向并在 fact 里记录"已试穷尽+失败特征"，把资源转给未覆盖面；同一目标面被 park 后，除非有新证据（新 fact/凭据/入口），否则不再重开。**最后 1/4 时间预算**（任务带 deadline 时）优先收官：补齐已确认漏洞的证据与报告，不再开新长链。
   - **同族迁移（variant hunting，v0.4.35，借鉴 sapper-v2 情报广播）**：确认一个漏洞后 30 秒内自问——**同一产品/同版本/同框架/同资产族的其他地方是否同款？** 同族线索（同厂商组件、同网关后的 mib-*/同类测试控制器前缀、同 CMS 的其他站点、同批子域）优先派 1–2 条 variant 意图去验证同一机理；把已确认的 PoC/路径/参数写进 summary 作为可复用线索。variant 意图必须锚定 task_scope 内资产，不得借同族迁移越界。
   - **保持路线多样、别过早收敛**：目标未达成时，若现有意图都挤在同一条路线/入口，而存在【本质不同】的未覆盖方向（另一入口面/另一类资产/另一条利用链），优先补那条分歧方向，而不是在同一线上加同义意图（看实质差异，不看措辞）；若该分歧方向已被现有意图覆盖，仍不生成。理想是 2–3 条机理不同的路线并存（如"从上传链打"与"从认证绕过打"），某条交出【目标逼近】的证据后才把资源集中过去。**但多样性永远服从顶部【操作约束】**：被约束排除的入口面/端口/主机/操作，即使本质不同也绝不生成意图。

   **串行利用链：分步派，别拆成并行。** 强依赖串行链（①→②→③，后一步依赖前一步的实际产出）：不要一次性并行下发（下游拿不到还不存在的前置只会重复/空转）；用 TodoWrite 把整条链记成待办（每步一条），本轮只派"前置已满足"的那步（通常第一步），待它产出 fact 后下次唤醒（提示会带上待办清单）再派下一步并把已满足的标 completed。"同一件事"别拆两条（"确认触发点"和"触发触发点"是同一步）；只有【平行、互不依赖】的维度（如枚举多个不相关端点）才用多意图并行。

   - **⚠️ 意图粒度硬规则（v0.4.44）**：
     · 每条意图的 summary **必须是一个具体的、可执行的子步骤**——worker 拿到后知道第一步做什么。
     · **严禁**把任务 description / goal / 总目标文本原封不动或稍作包装后当作意图 summary——add_intent 会拒绝这类复读，即使绕过闸门，worker 收到也等于收到整个任务、不知道做什么。
     · **开局（无 fact）第一轮必须产出 3–5 条具体意图**，覆盖初始阶段的不同维度（如「DNS 解析+子域名枚举」「端口扫描+服务识别」「HTTP 指纹+未授权探测」「已知组件 CVE 匹配」），每条写清对哪个目标做什么。
     · 反面示例：「完成任务目标：对 XX 进行完整渗透测试…」 ← 这是复读不是意图。
     · 正面示例：「对 sxxyxyy.com 做子域名枚举（字典+证书透明度），产出子域名清单写回资产」 ← 这才是可执行的具体步骤。

5. **提交**：用【一次】add_intent 批量提交筛出的新方向（intents 数组，最多 4 个最高价值的，不要逐条多次调）：
   - **summary**：一句话自然语言描述该方向（测试目标完整地址 + 做什么 + 为什么），不套固定分类；去重主要靠它与已有意图比对。
   - **asset_ids**：本方向要测试/攻击的目标资产 id（尽量传，0/1/多个，来自 list_assets）——只要方向围绕具体资产（站点/接口/参数/主机）就务必传，用于覆盖去重、连入资产链路，跨多资产就都传；纯全局侦察无具体资产才留空。
   - **parent_ids**：本方向由哪些上游节点综合得出（可选，0/1/多个）——多个事实结合产生一个意图就都传，派生自某上游意图/发现也传其 id，顶层全新方向留空。
   - **priority**（0-10，决定 worker 领单顺序，frontier 按它降序）：**别全默认 5**。评分按四个可核对维度加权（v0.4.30，TDA 难度感知评分，借鉴 Excalibur 论文四维、自译）：
     ① **视野**（离目标还差几步）：已是最后一步=9-10；还需两步=7-8；方向未定=≤5；
     ② **证据置信**（依据的 fact 可靠度）：observed=高分、inferred=中、纯猜测=低（降 2-3 分）；
     ③ **历史成功率**：同类方向/同类资产在本任务里 done 且零产出的占比高 → 降 2-3 分（别把资源再倒进已证明没东西的面）；
     ④ **上下文负载**：需要大量既有事实才能起步的长链方向适当降分，优先短链快验。
     同轮多意图按价值区分，高价值链不与补测意图同权排队。
   - **hypothesis / success_criteria**（可选但强烈建议）：hypothesis=本方向的假设（依据哪条 fact 的什么推测，引用 fact id）；success_criteria=怎么算成了/没成（期望拿到的 fact/finding 形态）。写得出来，worker 就有了 definition of done，你下轮判「有没有产出」也有了对照锚。
   - **坏意图示例（对照着别这么写）**：①「再深入探测 admin 面看看有什么」——无地址、无依据、无产出承诺，worker 拿到只能盲扫；②「针对 #14 的 SQL 注入复核」——与 done 意图同措辞、零增量承诺，换措辞不算新方向。

不重复、不硬凑；但目标未达成、又有未覆盖且更深的打法时，该派就派。简洁、聚焦、高效。`

func plannerSystem(goal, dataDir, workDir string) string {
	body := renderSystem("planner", plannerDefaultTmpl, PlannerVars{Goal: goal, DataDir: dataDir, Now: nowStr()})
	// 作业硬尾巴（v0.4.63）：漏洞覆盖矩阵/纵深优先 + 授权边界复核。
	return body + artifactSpec(workDir) + coverageMatrixPlannerGuidance + scopeVerifyPlannerGuidance + execFacePlannerGuidance
}

// Plan runs one planning round. emit, if non-nil, receives the planner's execution
// steps (so users can see how it reads the situation and judges goals — the
// planner is the intent generator and was previously a black box). Returns whether
// the planner judged the goal met.
// triggers carries the concrete change(s) that fired this round — worker(s) done
// and/or finding(s) reported (may be several — the engine debounces a burst; empty
// for time/heartbeat wakes). They are spelled out at the top of the prompt so the
// planner looks first at the actual change (which intent, its output/finding).
func (p *Planner) Plan(ctx context.Context, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, goal string, triggers []TriggerEvent, emit func(db.Activity)) (met bool, reason string, err error) {
	// cold-digest §2.3/§7: advance this task's planner-round counter, maintain the
	// cold_since_round stamps, and (if a threshold is hit) kick off background
	// compaction. Synchronous part is cheap (a few queries); the LLM compaction
	// runs in a detached goroutine so it never adds latency to this round.
	p.compactor.OnPlannerRound(ctx, ts)
	tsx := NewToolSet(ts, "planner")
	tsx.SetFindingRecorder(p.findingRecorder)
	tsx.SetScopeFlags(p.scopeGuard, p.scopeInheritWrites, p.crossTaskNotifyDedup)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.SetCoverageEnabled(as == nil || as.CoverageEnabled(taskID))
	tsx.killWork = p.killWork         // enable kill_work tool (nil = unavailable)
	tsx.steerWork = p.steerWork       // enable steer_work tool (nil = unavailable)
	tsx.attributions = p.attributions // Guard 归因 → 概览 guard_attributions 块（nil = 省略）
	if origin, _ := ts.OriginFactID(); origin > 0 {
		tsx.SetOwnerNode(origin) // planner-side anchors default to the task root (origin fact)
	}
	// 领域工具 + 基础默认工具集（Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash）
	// 资产覆盖度功能关闭时剔除 add_task_scope/list_untested_assets（不入 prompt）。
	base := append(tsx.DropCoverageTools(tsx.PlannerTools()), actool.DefaultTools()...)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts), Kind: KindPlanner})
	tools, def, cleanup := AugmentTools(ctx, "planner", base)
	defer cleanup()
	// 关键态势（刚完成的意图 + 预取的完整图）改放【本轮 user 输入】(见下方 input)，system
	// 只留静态规划正文。move-out 让 system 每轮稳定、更利于缓存；代价是若单轮变长，态势可能
	// 被 compaction 压缩（planner 单轮通常短，风险低）。situational 会拼进下方 input。
	situational := renderTriggers(ts, triggers) + renderGraphOverview(tsx.graphOverviewData())
	// 任务级 deadline / 终局模式(经 ctx 注入,见 taskclock.go)。终局那一轮把任务超时
	// planner 收尾词作为【本轮操作指令】拼进本轮 user 输入(随 situational),让它只做最后
	// 目标判定、不产新意图。
	tc := taskClockFrom(ctx)
	if tc.Final {
		words := resolveTaskTimeoutWrapup("planner")
		if tc.FinalReason != "" && tc.FinalReason != "timeout" {
			words = AutoFinishWrapup("planner", tc.FinalReason)
		}
		situational += "\n\n【任务终局收尾（本轮特殊指令，覆盖上面的常规规划流程）】：" + words
	}
	// 本任务的工作目录 <workDir>/tasks/<taskID>，先建好。
	taskDir := ensureRunDir(p.workDir, taskID, 0)
	ctx = intercept.WithReviewContext(ctx, taskDir, intercept.ReviewBackground{})
	sysBody := plannerSystem(goal, p.workDir, taskDir)
	if p.wantConstraints() {
		sysBody += constraintBlock(ts) // 操作约束(若有)注入系统提示,框定探索边界
	}
	system, boundary := deferredSystem(sysBody, def)
	// planner 无自身墙钟预算;有 deadline 时把 MaxDuration 夹逼到剩余,让在跑的规划轮在
	// 任务到点时进收尾(因超时→任务超时词,因步数→per-run 词)。
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, 0)
	settle := wrapupSettlement("planner", nil)
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("planner", nil, clamped)
	}
	opts := agentcore.Options{
		Provider:        p.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // 走记录代理留痕；载入代理 CA 验证 MITM 重签的 HTTPS 证书
		WebFetchProxy:   p.proxyAddr,
		WebFetchCACert:  p.proxyCACert,
		// 联网搜索(可选)。ddgs 无需 key；brave-free 需 BraveKey；tavily 需 TavilyKey。
		// WebSearchProxy 是独立出口代理(http/https/socks5)，与记录流量的 MITM 代理无关；空则直连。
		EnableWebSearch:       p.webSearch.Enabled,
		WebSearchBackend:      p.webSearch.Backend,
		BraveSearchAPIKey:     p.webSearch.BraveKey,
		TavilySearchAPIKey:    p.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: p.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  p.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   p.webSearch.DeepSeekModel,
		WebSearchProxy:        p.webSearch.Proxy,
		BashEnv:               proxyEnv(p.proxyAddr, p.proxyCACert), // Bash 子命令默认走代理+信任 CA
		WorkingDir:            taskDir,                              // 本任务工作目录 <workDir>/tasks/<taskID>
		ToolOutputDir:         cmdOutDir(taskDir),
		MaxTurns:              p.maxTurns, // 0 = unlimited (configurable in agent management)
		MaxDuration:           maxDur,     // 0=不限;有 deadline 时=距 deadline 剩余
		Compaction:            compactionConfig(p.compactionWindow()),
		// 跨唤醒共享的规划待办：让串行链在多轮之间保留（session 是新的，store 不是）。
		Todos: p.todoFor(ts.ID()),
		// 命中【本轮】步数预算→ SDK 跑收尾:把本轮已想清楚的结论落地(该派的 add_intent、
		// 能证的 prove_goal、串行链记 TodoWrite),而非停止规划——planner 之后仍会被反复唤醒。
		// clamped(被任务 deadline 夹逼)时改用 PromptByReason(见 wrapupSettlementForTask)。
		Settlement:   settle,
		NonStreaming: p.nonStreaming(), // 该 profile 选非流式时走 Provider.Complete
		MaxTokens:    p.maxTokens(),    // 0 = 不发上限,由服务端默认值决定
		// 工具调用可观测：planner 的工具调用此前完全不可观测（journal 里只有心跳），
		// 无法从日志判断「planner 在干活」还是「planner 卡住不动」。纯旁路，不干预。
		Hooks: toolLogSink(KindPlanner),
	}
	if p.tx != nil { // persist raw LLM conversation; one accumulating file per task's planner
		opts.Transcript = p.tx
		opts.SessionID = fmt.Sprintf("exp%d-planner", ts.ID())
	}
	// 实验功能:开启后由 noa 接管上下文压缩(归档集中在 <workDir>/noa/<SessionID> 下,持久)。
	noaSession := fmt.Sprintf("exp%d-planner", ts.ID())
	enableNoa(&opts, p.noaEnabledFn, p.workDir, noaSession, noaWarn(noaSession))
	// 态势（刚完成的意图 + 完整图）现在拼进本轮 user 输入（见下方 input）。user 里还有
	// 指令 + 跨唤醒待办（todo 是模型自己的规划便签，可再生，放 user 即可）。
	// 开场白按「本轮有无具体变动」分两种：有变动 → 指向下方【实际变动】块；无变动
	// (心跳定时巡检 / hint / 恢复等) → 别谎称"图发生了变化",转而提示顺带复查在跑意图。
	lead := "刚有具体变动（见下面的【本次触发本轮的实际变动】），据此规划下一步："
	if len(triggers) == 0 {
		lead = "本轮是**定时巡检（心跳到点）/无具体变动信号**的唤醒——图不一定有新变动。顺带复查在跑意图：长时间无进展或跑偏的用 steer_work 纠偏、方向整个错的用 kill_work 止损；再判定目标、决定是否补方向："
		// 心跳/无变动唤醒时,若全图已无任何 open 或 running 意图 → 探索已停摆(没 worker 在跑、
		// 也没排队方向)。明确告知 planner 并强制其本轮补出新方向,别只复查在跑意图后空转一轮。
		if active, err := ts.HasActiveIntent(); err == nil && !active {
			lead = "本轮是**定时巡检（心跳到点）**的唤醒,且当前**已没有任何 open 或 running 的意图**——没有 worker 在跑、也没有排队中的方向,探索已停摆。你**必须**在本轮产出一个或多个向目标推进、且与图中既有意图**互不重复**的新意图(不得产出 0 意图);先据下面的态势判定目标是否已达成,未达成则立即补方向："
		}
	}
	// 硬底线在 system 顶部已完整声明（最高优先），user 里只压成一句提醒——
	// 整段重复每轮多烧 ~200 token 且两处措辞会日久漂移（体检 B8）。
	input := lead + situational + "\n\n据上面的态势，判定目标。目标已【真正达成】（已拿到目标成果/已确认目标漏洞）时用 prove_goal 逐个标记。硬底线提醒见 system 顶部：目标未达成且 frontier_open=0 且无 running 意图时，本轮必须产出意图。" +
		renderPlannerTodos(opts.Todos.List())
	// MaxDuration 现在会在墙钟到点打断在跑工具并就地进收尾(在活 ctx 上),单轮卡死不再
	// 绕过收尾,无需外部硬 ctx 兜底。ctx 只承载 pause / kill / shutdown。
	_, _, err = captureRun(ctx, opts, input,
		func(r db.Activity) {
			if emit != nil {
				r.Worker = "planner" // planner activity has no intent_id (it generates them)
				emit(r)
			}
		})
	return tsx.GoalMet, tsx.Reason, err
}
