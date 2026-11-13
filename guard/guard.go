// Package guard implements the safety boundary layer (docs §11): an audit log,
// user-configured intercept-rule evaluation, and Observer/G5 failure attribution.
// Every tool call passes through the PreToolUse hook before executing.
// (The RoE authorization-scope mechanism was removed; a replacement may be added
// later.) Destructive/exfil gating is no longer hard-coded here — it lives in the
// DB intercept rules (seeded as ordinary [内置] rules, so users can disable or
// delete them), evaluated via applyIntercept.
package guard

import (
	"context"
	"encoding/json"
	"regexp"
	"sync"
	"time"

	"github.com/chu0119/pojun/intercept"
	"github.com/Autumn-27/norma/hook"
)

// AuditEntry records one gated tool call.
type AuditEntry struct {
	TS      int64  `json:"ts"`
	Tool    string `json:"tool"`
	Action  string `json:"action"` // allow|block
	Reason  string `json:"reason,omitempty"`
	Command string `json:"command,omitempty"`
}

// Guard enforces the side-effect policy via agent-core hooks.
type Guard struct {
	mu          sync.Mutex
	audit       []AuditEntry
	attrib      map[string]int // failure attribution counts (Observer / G5)
	attribSamps map[string][]AttribSample
	reg         *hook.Registry
	interceptor *intercept.Interceptor // optional; nil disables user-configured rules
}

// AttribSample 是一条 blocked/error 归因的最近样本（B6）：planner 只看计数时对不上
// 「哪条命令被拦了」，复盘/换打法需要看实物。Command 截断到 attribSampleMax（防御
// 超长命令刷爆态势块），TS 用 Unix 秒便于展示时间。
type AttribSample struct {
	Tool    string `json:"tool"`
	Command string `json:"command,omitempty"`
	TS      int64  `json:"ts"`
}

// attribSampleMax 每类保留的样本条数（最近）。计数仍是全量的；样本只是「最近3条」。
const attribSampleMax = 3

// attribSampleMaxBytes 单条 command 的截断长度（字节）。
const attribSampleMaxBytes = 200

// New creates a Guard without user-configured intercept rules (used for pentest
// tasks where the Interceptor is not yet available).
func New() *Guard { return newGuard(nil) }

// NewWithInterceptor creates a Guard with user-configured intercept rules.
func NewWithInterceptor(ic *intercept.Interceptor) *Guard { return newGuard(ic) }

func newGuard(ic *intercept.Interceptor) *Guard {
	g := &Guard{attrib: map[string]int{}, attribSamps: map[string][]AttribSample{}, interceptor: ic}
	g.reg = hook.NewRegistry().
		On(hook.PreToolUse, g.preToolUse).
		On(hook.PostToolUse, g.postToolUse)
	return g
}

// Hooks returns the hook registry to attach to an agent session.
func (g *Guard) Hooks() *hook.Registry { return g.reg }

func (g *Guard) preToolUse(ctx context.Context, ev hook.Event) hook.Result {
	// Extract the shell-command surface for the audit log: Bash + the interactive-shell
	// tools (shell_open's command, shell_send's text). Destructive/exfil gating is no
	// longer hard-coded here — it now lives in the DB intercept rules, evaluated by
	// applyIntercept below. Other tools record an empty command.
	var cmd string
	switch ev.ToolName {
	case "Bash", "shell_open":
		var in struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Command
	case "shell_send":
		var in struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Text
	}
	// 审计只留一条：被拦截的调用由 block() 记 "block"，这里不再先记 "allow"，
	// 否则同一次调用在审计里既像放行又像拦截，复盘时无法区分。
	res := g.applyIntercept(ctx, ev)
	if res.Decision != "block" {
		g.record(ev.ToolName, "allow", "", cmd)
	}
	return res
}

// applyIntercept evaluates user-configured intercept rules against the tool call.
// Both rules and the fallback judge receive the complete tool input.
func (g *Guard) applyIntercept(ctx context.Context, ev hook.Event) hook.Result {
	if g.interceptor == nil {
		return hook.Result{}
	}
	if !g.interceptor.IsToolEnabled(ev.ToolName) {
		return hook.Result{}
	}
	ctx = intercept.WithCall(ctx, ev.ToolName, ev.Input)
	dec, matched := g.interceptor.Match(ev.ToolName, ev.Input)
	if !matched {
		// No rule matched. Ask the LLM fallback judge (if enabled); when it is off
		// or unwired, keep current behavior and allow.
		d, judged := g.interceptor.Judge(ctx, ev.ToolName, ev.Input)
		if !judged {
			return hook.Result{}
		}
		dec = d
	} else if dec.Action == "judge" {
		// 规则显式要求「Agent 研判」：不再取固定动作，交给模型裁决；裁决结果仍按
		// allow/deny/ask 走原有分支。保留触发它的 rule_id，审计里能看出是哪条规则
		// 把这次调用交给了模型。
		//
		// 规则自己的 timeout 声明要一起传下去：规则作者显式写了「我超时时怎么办」，
		// 那就以规则为准（否则规则上的 timeout_enabled/seconds/action 仍是死字段，
		// 界面显示的与实际生效的不一致）。规则没写就听全局的。
		ruleID := dec.RuleID
		rt := intercept.RuleTimeout{}
		if dec.TimeoutEnabled {
			rt = intercept.RuleTimeout{
				Enabled: true,
				Seconds: dec.TimeoutSeconds,
				Action:  dec.TimeoutAction,
			}
		}
		d, judged := g.interceptor.JudgeRuleWithTimeout(ctx, ev.ToolName, ev.Input, rt)
		if !judged {
			return hook.Result{}
		}
		d.RuleID = ruleID
		dec = d
	}
	switch dec.Action {
	case "deny":
		// 观测:deny 命中不阻塞审批,直接记一条 denied（历史/任务拦截页可见）。
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "denied")
		return g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
	case "allow":
		// Record explicit rule and model approvals so review details remain auditable.
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "allowed")
		return hook.Result{}
	case "ask":
		// If the worker context is already cancelled (task stopped / killed), block
		// immediately without creating a pending record — avoids orphaned DB entries
		// and makes execOne complete fast, reducing the race against drainSynthetic.
		if ctx.Err() != nil {
			return g.block(ev.ToolName, systemBlockMessage("工作已取消，平台安全管控阻止执行"), "")
		}
		convID := intercept.ConvIDFromContext(ctx)
		if !g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input) {
			return g.block(ev.ToolName, systemBlockMessage("人工审批未通过（用户拒绝或审批超时）"), "")
		}
		return hook.Result{}
	}
	return hook.Result{}
}

// systemBlockMessage frames an intercept block as an POJUN platform-governance
// decision so the agent does not mistake it for a target-side defense.
//
// The bare reasons ("禁止执行此工具" / "用户拒绝") read exactly like a WAF/403 on
// the target, so a pentest agent's instinct is to bypass them — rewrite the
// command, swap the payload, re-encode, retry. That is both futile (the platform
// blocks the class of action, not one string) and wrong (it's a policy decision,
// not an obstacle to defeat). This prefix states plainly that the block comes
// from the platform, is not the target's protection, and that the operation is
// forbidden — so the agent pivots to another approach instead of evading it.
// Audit/history rows keep the raw reason (see Interceptor.Log); only the
// model-facing tool_result carries this framing.
func systemBlockMessage(reason string) string {
	return "【POJUN 平台管控·非目标防御】此调用被平台拦截。" +
		"原因：" + reason + "。此操作被禁止。"
}

var reBlocked = regexp.MustCompile(`(?i)\b(403|forbidden|waf|blocked|rate.?limit|429|captcha|denied)\b`)

// postToolUse is the Observer failure-attribution hook (G5): it classifies tool
// results into blocked / error / ok so the planner can change strategy instead
// of giving up at a WAF.
func (g *Guard) postToolUse(_ context.Context, ev hook.Event) hook.Result {
	if ev.ToolName != "Bash" {
		return hook.Result{}
	}
	class := "ok"
	switch {
	case reBlocked.Match(ev.Result):
		class = "blocked"
	case ev.IsError:
		class = "error"
	}
	g.mu.Lock()
	g.attrib[class]++
	// B6:只留 blocked/error 的实物样本,ok 不占内存。每类环形保留最近 3 条。
	if class != "ok" {
		var input struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(ev.Input, &input)
		cmd := input.Command
		if len(cmd) > attribSampleMaxBytes {
			cmd = cmd[:attribSampleMaxBytes]
		}
		samps := append(g.attribSamps[class], AttribSample{Tool: ev.ToolName, Command: cmd, TS: time.Now().Unix()})
		if len(samps) > attribSampleMax {
			samps = samps[len(samps)-attribSampleMax:]
		}
		g.attribSamps[class] = samps
	}
	g.mu.Unlock()
	return hook.Result{}
}

// Attributions returns failure-attribution counts (Observer / G5).
func (g *Guard) Attributions() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int, len(g.attrib))
	for k, v := range g.attrib {
		out[k] = v
	}
	return out
}

// AttributionStats (B6) 是 Attributions 的态势版：计数之外附每类最近样本
// （samples."blocked"/"error" = [{tool,command,ts}...]，最多 3 条，command 截断）。
// planner 看到「blocked×7 + 最近命令列表」就能对上号换打法，而不是只知道「被拦了」。
// 供 graph_overview 的 guard_attributions 块直插使用。
func (g *Guard) AttributionStats() map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]any, len(g.attrib)+1)
	for k, v := range g.attrib {
		out[k] = v
	}
	samps := make(map[string]any, len(g.attribSamps))
	for k, v := range g.attribSamps {
		if len(v) > 0 {
			samps[k] = v
		}
	}
	if len(samps) > 0 {
		out["samples"] = samps
	}
	return out
}

func (g *Guard) block(tool, reason, cmd string) hook.Result {
	g.record(tool, "block", reason, cmd)
	return hook.Result{Decision: "block", Message: reason}
}

func (g *Guard) record(tool, action, reason, cmd string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.audit = append(g.audit, AuditEntry{TS: time.Now().Unix(), Tool: tool, Action: action, Reason: reason, Command: cmd})
	if len(g.audit) > 2000 {
		g.audit = g.audit[len(g.audit)-2000:]
	}
}

// Audit returns a snapshot of recent gated calls (most recent last).
func (g *Guard) Audit() []AuditEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]AuditEntry, len(g.audit))
	copy(out, g.audit)
	return out
}
