// Package intercept implements the user-configurable tool-call interception layer.
// Rules are loaded from the database, cached in memory, and evaluated in priority
// order (highest first) on every PreToolUse event. Three actions are supported:
//
//   - allow: immediately permits the call, skipping lower-priority rules.
//   - deny:  blocks the call and returns a message to the model.
//   - ask:   blocks the call, creates an intercept_pending record, writes an
//     activity to the active conversation, then waits for the user to approve or
//     deny via the /api/intercept/pending/{id}/decide endpoint.
//
// The timeout behaviour is configurable at runtime via SetTimeoutConfig.
package intercept

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chu0119/pojun/db"
)

// ctxKey is the unexported context key type to avoid collisions.
type ctxKey int

// ConvIDKey stores the active conversation ID in a context.Context so the
// interceptor can associate "ask" pending records with the right conversation.
const ConvIDKey ctxKey = 0

// WithConvID returns a child context carrying convID.
func WithConvID(ctx context.Context, convID int64) context.Context {
	return context.WithValue(ctx, ConvIDKey, convID)
}

// ConvIDFromContext extracts the conversation ID (0 if absent).
func ConvIDFromContext(ctx context.Context) int64 {
	v, _ := ctx.Value(ConvIDKey).(int64)
	return v
}

// taskCtxKey is a separate unexported key type for task context values.
type taskCtxKey int

const (
	taskInfoCtxKey taskCtxKey = 1
	taskEmitCtxKey taskCtxKey = 2
	// autopilotCtxKey 是自主推进开关的读取器（每次调用现查，中途关掉开关时
	// 下一次规划/执行就恢复普通任务语义）。
	autopilotCtxKey taskCtxKey = 3
)

// WithAutopilot 注入自主推进开关读取器（nil/返回 false = 普通任务）。
// 仅用于决定是否在系统提示末尾追加自主推进尾巴；不改变审批与拦截语义。
func WithAutopilot(ctx context.Context, enabled func() bool) context.Context {
	return context.WithValue(ctx, autopilotCtxKey, enabled)
}

// AutopilotFromContext 取回自主推进开关读取器；未注入时返回 nil。
func AutopilotFromContext(ctx context.Context) func() bool {
	f, _ := ctx.Value(autopilotCtxKey).(func() bool)
	return f
}

type taskCtxInfo struct{ taskID, agentName string }

// WithTaskContext injects task metadata and an emit function into ctx so that
// HandleAsk can tag pending records and write intercept_request activities to
// the task's exploration stream (making them appear inline in session transcripts).
func WithTaskContext(ctx context.Context, taskID, agentName string, emit func(db.Activity)) context.Context {
	ctx = context.WithValue(ctx, taskInfoCtxKey, taskCtxInfo{taskID, agentName})
	if emit != nil {
		ctx = context.WithValue(ctx, taskEmitCtxKey, emit)
	}
	return ctx
}

func taskInfoFromCtx(ctx context.Context) (taskID, agentName string) {
	if v, ok := ctx.Value(taskInfoCtxKey).(taskCtxInfo); ok {
		return v.taskID, v.agentName
	}
	return "", ""
}

func taskEmitFromCtx(ctx context.Context) func(db.Activity) {
	f, _ := ctx.Value(taskEmitCtxKey).(func(db.Activity))
	return f
}

// compiledRule is an InterceptRule with the regex pre-compiled (nil for string rules).
type compiledRule struct {
	db.InterceptRule
	re *regexp.Regexp
}

// pendingManager tracks in-flight "ask" requests via per-request channels.
type pendingManager struct {
	mu sync.Mutex
	ch map[int64]chan bool
}

func newPendingManager() *pendingManager { return &pendingManager{ch: map[int64]chan bool{}} }

func (p *pendingManager) add(id int64) chan bool {
	ch := make(chan bool, 1)
	p.mu.Lock()
	p.ch[id] = ch
	p.mu.Unlock()
	return ch
}

func (p *pendingManager) resolve(id int64, allowed bool) {
	p.mu.Lock()
	ch, ok := p.ch[id]
	delete(p.ch, id)
	p.mu.Unlock()
	if ok {
		ch <- allowed
	}
}

func (p *pendingManager) remove(id int64) {
	p.mu.Lock()
	delete(p.ch, id)
	p.mu.Unlock()
}

// Reviewer runs the LLM fallback judge for one tool call and returns its verdict
// as a Decision (Action ∈ allow|ask|deny; empty Action means the reply could not
// be parsed). It is injected by the server layer so the intercept package stays
// free of any llm dependency. profileID == 0 means "use the active/default profile".
type Reviewer func(ctx context.Context, profileID int64, prompt string, input ReviewInput) (Decision, error)

// Interceptor loads intercept rules from the database and evaluates them on
// tool calls. It is safe for concurrent use.
type Interceptor struct {
	db           *db.DB
	mu           sync.RWMutex
	cached       []compiledRule  // sorted by priority DESC; nil means not loaded yet
	enabledTools map[string]bool // nil means not loaded yet
	pending      *pendingManager
	reviewer     Reviewer // nil = LLM fallback judge not wired
}

// SetReviewer installs the LLM fallback judge callback. Passing nil disables it.
func (i *Interceptor) SetReviewer(r Reviewer) {
	i.mu.Lock()
	i.reviewer = r
	i.mu.Unlock()
}

// defaultEnabledTools is the hard-coded set of tools that enter the intercept
// rule system when no intercept_enabled_tools setting has been saved.
// goal_met 一句话终结整个任务且不走 prove_goal 证据链（v0.3.88 体检 S3）——
// 入集后可被规则命中（内置 judge 规则「goal_met 收官研判」随 V5 seed 落库）。
var defaultEnabledTools = []string{
	"Bash", "WebFetch", "web_search",
	"shell_open", "shell_send",
	"listener_start", "listener_stop",
	"goal_met",
	"Write", "Edit", "MultiEdit",
}

// New creates an Interceptor backed by d. The rule cache is lazy-loaded on
// first use.
func New(d *db.DB) *Interceptor {
	return &Interceptor{db: d, pending: newPendingManager()}
}

// Invalidate clears the in-memory rule cache and the enabled-tools cache.
// The next call to Match or IsToolEnabled will reload from the database.
// Call this after any CRUD operation on rules or tool config.
func (i *Interceptor) Invalidate() {
	i.mu.Lock()
	i.cached = nil
	i.enabledTools = nil
	i.mu.Unlock()
}

// SetRulesInMemory replaces the in-memory rule cache with the given rules.
//
// 用途：让「规则 → 裁决 → allow/deny/ask」这条链路可以在没有数据库的
// 情况下端到端验证（Match 的规则来源是 db.ListInterceptRules，而单测里
// 拿不到 PG）。生产路径不用它——规则仍然从库里加载。
//
// 传入的规则会按 priority DESC、id ASC 排序（与库里的加载顺序一致），
// 正则会预编译；编译失败的规则被跳过（与 loadLocked 的行为一致）。
func (i *Interceptor) SetRulesInMemory(rules []db.InterceptRule) {
	out := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		cr := compiledRule{InterceptRule: r}
		if r.MatchType == "regex" {
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				continue
			}
			cr.re = re
		}
		out = append(out, cr)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	i.mu.Lock()
	i.cached = out
	i.mu.Unlock()
}

func (i *Interceptor) loadLocked() error {
	// nil db（server 尚未接上数据库时）：没有规则可加载，但**不能 panic**——
	// 拦截在工具调用的同步路径上，一崩就是整个 agent 进程死掉。
	// judgeConfig 对 nil db 已有同样的保护，这里补上规则侧。
	if i == nil || i.db == nil {
		// 已用 SetRulesInMemory 注入过规则的话，**不要覆盖**它——那是为了
		// 在没有数据库的情况下验证「规则 → 裁决」链路而注入的。
		if i.cached == nil {
			i.cached = []compiledRule{}
		}
		m := make(map[string]bool, len(defaultEnabledTools))
		for _, n := range defaultEnabledTools {
			m[n] = true
		}
		i.enabledTools = m
		return nil
	}
	rules, err := i.db.ListInterceptRules()
	if err != nil {
		return err
	}
	var out []compiledRule
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		cr := compiledRule{InterceptRule: r}
		if r.MatchType == "regex" {
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				continue // skip rules with bad regex rather than crashing
			}
			cr.re = re
		}
		out = append(out, cr)
	}
	i.cached = out

	// Load enabled-tools set from settings, falling back to hard-coded defaults.
	val, ok, _ := i.db.GetSetting("intercept_enabled_tools")
	if !ok {
		m := make(map[string]bool, len(defaultEnabledTools))
		for _, n := range defaultEnabledTools {
			m[n] = true
		}
		i.enabledTools = m
	} else {
		var names []string
		if json.Unmarshal([]byte(val), &names) != nil {
			i.enabledTools = map[string]bool{}
		} else {
			m := make(map[string]bool, len(names))
			for _, n := range names {
				m[n] = true
			}
			i.enabledTools = m
		}
	}
	return nil
}

func (i *Interceptor) rules() ([]compiledRule, error) {
	i.mu.RLock()
	if i.cached != nil {
		out := i.cached
		i.mu.RUnlock()
		return out, nil
	}
	i.mu.RUnlock()

	i.mu.Lock()
	defer i.mu.Unlock()
	if i.cached != nil {
		return i.cached, nil
	}
	if err := i.loadLocked(); err != nil {
		return nil, err
	}
	return i.cached, nil
}

// IsToolEnabled returns true if the named tool is in the intercept-enabled set
// (i.e. it should enter the rule-matching path). Uses the same double-check lock
// pattern as rules().
func (i *Interceptor) IsToolEnabled(name string) bool {
	i.mu.RLock()
	if i.enabledTools != nil {
		v := i.enabledTools[name]
		i.mu.RUnlock()
		return v
	}
	i.mu.RUnlock()

	i.mu.Lock()
	defer i.mu.Unlock()
	if i.enabledTools == nil {
		_ = i.loadLocked()
	}
	return i.enabledTools[name]
}

// GetEnabledTools returns the ordered list of tool names that are currently
// configured to enter the intercept rule system. When the setting has never been
// saved the hard-coded default list is returned.
func (i *Interceptor) GetEnabledTools() ([]string, error) {
	val, ok, err := i.db.GetSetting("intercept_enabled_tools")
	if err != nil {
		return nil, err
	}
	if !ok {
		out := make([]string, len(defaultEnabledTools))
		copy(out, defaultEnabledTools)
		return out, nil
	}
	var names []string
	if err := json.Unmarshal([]byte(val), &names); err != nil {
		return []string{}, nil
	}
	return names, nil
}

// SetEnabledTools persists the list of tool names that should enter the intercept
// rule system, then invalidates the cache so the next call picks up the new list.
func (i *Interceptor) SetEnabledTools(tools []string) error {
	b, err := json.Marshal(tools)
	if err != nil {
		return err
	}
	if err := i.db.SetSetting("intercept_enabled_tools", string(b)); err != nil {
		return err
	}
	i.Invalidate()
	return nil
}

// Decision is the outcome of a successful rule match.
type Decision struct {
	ModelInput       json.RawMessage
	ModelInputDigest string
	ModelFallback    bool
	RuleName         string
	ConfigDigest     string
	ProfileID        int64
	Action           string // "allow" | "deny" | "ask"
	Message          string
	RuleID           int64
	TimeoutEnabled   bool
	TimeoutSeconds   int
	TimeoutAction    string // "deny" | "allow"
}

// --- LLM fallback judge ---

// Judge settings keys (stored in the settings KV table). See docs §3.
const (
	settingJudgeEnabled          = "llm_judge_enabled"
	settingJudgeProfileID        = "llm_judge_profile_id"
	settingJudgePrompt           = "llm_judge_prompt"
	settingJudgeTimeoutSecs      = "llm_judge_timeout_seconds"
	settingJudgeFailAction       = "llm_judge_fail_action"
	settingJudgeAskTimeoutSecs   = "llm_judge_ask_timeout_seconds"
	settingJudgeAskTimeoutAction = "llm_judge_ask_timeout_action"

	// ask 审批（规则未声明 timeout 时）的全局兜底上限。规则级 TimeoutEnabled
	// 之外的最后一道墙：审批人离场不能让 worker 无限挂死（v0.3.88 体检 S2）。
	settingAskDefaultTimeoutSecs = "intercept_ask_default_timeout_seconds"
)

// defaultAskTimeoutSecs：6 小时。语义与 judge 侧 180s 不同——这里是「规则
// 声明了要人拍板、但没人声明等多久」，等的是**操作员回来上班**，所以给足
// 一个工作日内的量级；到点按 deny 收口（拒绝永远是 ask 类规则的安全侧），
// 结果进审批历史（status=timeout）可追溯。

// Judge default values.
//
// 这套默认值是按「人不在电脑前」的场景定的：
//
//   - 裁决超时 90s（不是 15s）：开启思考的模型（MiniMax-M3.1 / Claude extended
//     thinking）思考本身就要十几秒，15s 会把「模型正在想」误判成失败，
//     于是每次裁决都掉进兜底策略——开启思考的场景下裁决等于没开。
//   - 裁决失败 → 转人工（不是 allow）：allow 意味着「模型挂了 → 关卡自动敞开」，
//     而模型挂掉的原因往往正是配置问题（thinking 不兼容、额度耗尽、上游 5xx），
//     这时自动放行等于让整套管控静默失效。
//   - 人工审批超时 → 放行（不是 deny）：ask 会**同步阻塞** worker 等人。
//     操作员不在电脑前时 deny 等于把任务卡死在这里，整条渗透链停摆；
//     放行只是让这一次调用继续，事后仍可在「拦截审批」页看到记录并追认。
//     真要防破坏，防线应该放在「规则命中 → 模型裁决」这一层，而不是
//     「人没及时点确认」这一层。
//   - 人工审批超时 180s：3 分钟，够操作员回来看一眼。
const (
	// defaultJudgeTimeoutSecs 是模型裁决的墙钟上限。
	//
	// 180 而非更短：思考型模型的裁决耗时随命令长度而变（实测短命令 4~26 秒，
	// 长命令——几百到上千字符的 shell 脚本——明显更久），而且正文为空时会
	// 升预算重试（32768 → 65536），重试要挤在同一个超时窗口内。时间给短了
	// 就会把「模型其实能裁决」误判成超时失败。
	defaultJudgeTimeoutSecs = 180
	defaultJudgeFailAction       = "ask"
	defaultJudgeAskTimeoutSecs   = 180
	defaultJudgeAskTimeoutAction = "allow"

	// ask 全局兜底上限：6h（见 settingAskDefaultTimeoutSecs 注释）。
	defaultAskTimeoutSecs = 6 * 60 * 60
)

// JudgeConfig is the resolved LLM-fallback-judge configuration. Prompt is always
// non-empty (falls back to DefaultJudgePrompt).
type JudgeConfig struct {
	Enabled           bool   `json:"enabled"`
	ProfileID         int64  `json:"profile_id"` // 0 = follow active/default
	Prompt            string `json:"prompt"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
	FailAction        string `json:"fail_action"` // allow|ask|deny
	AskTimeoutSeconds int    `json:"ask_timeout_seconds"`
	AskTimeoutAction  string `json:"ask_timeout_action"` // allow|deny
}

// judgeConfig reads the judge configuration from settings, applying defaults for
// missing/invalid keys. Read fresh on each fallback judgement — the LLM call that
// follows dwarfs a few KV reads, and freshness avoids a cache-invalidation path.
func (i *Interceptor) judgeConfig() JudgeConfig {
	// nil db（server 尚未接上数据库时）：全部走默认值。别在这里 panic——
	// 裁决在工具调用的同步路径上，一崩就是整个 agent 进程死掉。
	if i == nil || i.db == nil {
		return JudgeConfig{
			Enabled:           false,
			ProfileID:         0,
			Prompt:            DefaultJudgePrompt,
			TimeoutSeconds:    defaultJudgeTimeoutSecs,
			FailAction:        defaultJudgeFailAction,
			AskTimeoutSeconds: defaultJudgeAskTimeoutSecs,
			AskTimeoutAction:  defaultJudgeAskTimeoutAction,
		}
	}
	c := JudgeConfig{
		Enabled:           i.db.GetBool(settingJudgeEnabled, false),
		ProfileID:         int64(i.getSettingInt(settingJudgeProfileID, 0)),
		TimeoutSeconds:    i.getSettingInt(settingJudgeTimeoutSecs, defaultJudgeTimeoutSecs),
		FailAction:        i.getSettingChoice(settingJudgeFailAction, defaultJudgeFailAction, "allow", "ask", "deny"),
		AskTimeoutSeconds: i.getSettingInt(settingJudgeAskTimeoutSecs, defaultJudgeAskTimeoutSecs),
		AskTimeoutAction:  i.getSettingChoice(settingJudgeAskTimeoutAction, defaultJudgeAskTimeoutAction, "allow", "deny"),
	}
	// Prompt: stored value if non-empty, else the built-in template.
	if v, ok, _ := i.db.GetSetting(settingJudgePrompt); ok && strings.TrimSpace(v) != "" {
		c.Prompt = v
	} else {
		c.Prompt = DefaultJudgePrompt
	}
	if c.TimeoutSeconds <= 0 {
		c.TimeoutSeconds = defaultJudgeTimeoutSecs
	}
	if c.AskTimeoutSeconds <= 0 {
		c.AskTimeoutSeconds = defaultJudgeAskTimeoutSecs
	}
	return c
}

// DefaultJudgeTimeoutSeconds 返回裁决的默认墙钟上限（秒）。
//
// 导出给 server 层的测试断言用：思考型模型的裁决耗时随命令长度而变，
// 长命令明显更久，且正文为空时要升预算重试——超时给短了会把「模型其实
// 能裁决」误判成超时失败。
func DefaultJudgeTimeoutSeconds() int { return defaultJudgeTimeoutSecs }

func (i *Interceptor) getSettingInt(key string, def int) int {
	v, ok, err := i.db.GetSetting(key)
	if err != nil || !ok {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}

func (i *Interceptor) getSettingChoice(key, def string, allowed ...string) string {
	v, ok, err := i.db.GetSetting(key)
	if err != nil || !ok {
		return def
	}
	v = strings.TrimSpace(v)
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	return def
}

// GetJudgeConfig returns the resolved judge configuration for the API/UI. Prompt
// is the effective prompt (built-in template when unset), so the UI can prefill.
func (i *Interceptor) GetJudgeConfig() JudgeConfig { return i.judgeConfig() }

// SetJudgeConfig persists the judge configuration. An empty Prompt clears the
// override (the built-in template is used again).
func (i *Interceptor) SetJudgeConfig(c JudgeConfig) error {
	if err := i.db.SetBool(settingJudgeEnabled, c.Enabled); err != nil {
		return err
	}
	if err := i.db.SetSetting(settingJudgeProfileID, strconv.FormatInt(c.ProfileID, 10)); err != nil {
		return err
	}
	// Store the prompt only when it differs from the built-in template, so version
	// updates to DefaultJudgePrompt flow through for users who never customized it.
	promptToStore := ""
	if strings.TrimSpace(c.Prompt) != "" && strings.TrimSpace(c.Prompt) != strings.TrimSpace(DefaultJudgePrompt) {
		promptToStore = c.Prompt
	}
	if err := i.db.SetSetting(settingJudgePrompt, promptToStore); err != nil {
		return err
	}
	if err := i.db.SetSetting(settingJudgeTimeoutSecs, strconv.Itoa(c.TimeoutSeconds)); err != nil {
		return err
	}
	if err := i.db.SetSetting(settingJudgeFailAction, c.FailAction); err != nil {
		return err
	}
	if err := i.db.SetSetting(settingJudgeAskTimeoutSecs, strconv.Itoa(c.AskTimeoutSeconds)); err != nil {
		return err
	}
	if err := i.db.SetSetting(settingJudgeAskTimeoutAction, c.AskTimeoutAction); err != nil {
		return err
	}
	return nil
}

// Judge runs the LLM fallback judge for a tool call that matched no rule. It
// returns (Decision, true) when the judge produced a terminal verdict, or
// (Decision{}, false) when the fallback is disabled or not wired (caller then
// keeps the current behavior: allow). On model error or an unparseable reply it
// falls back to the configured FailAction. Ask verdicts carry the human-approval
// timeout so the existing HandleAsk consumes them unchanged.
func (i *Interceptor) Judge(ctx context.Context, tool string, arguments json.RawMessage) (Decision, bool) {
	return i.judge(ctx, tool, arguments, false, RuleTimeout{})
}

// RuleTimeout is a rule's explicit timeout declaration.
//
// 一条规则可以自己声明「我超时/失败后怎么办」——这是规则作者的显式声明，
// 优先于全局 judge 配置。零值（Enabled=false）表示「规则没说，听全局的」。
//
// 为什么要有这个：规则与裁决是两层。全局配置回答的是「模型兜底裁决这类调用
// 该怎么超时」，而一条「禁止破坏磁盘」的规则想要的是「模型没来得及答就
// 直接 deny」——前者是兜底策略，后者是安全策略。合成一个配置就没法同时
// 表达这两件事，于是 P0 之前规则上的这三个字段是死字段，界面显示的与实际
// 生效的不一致。
type RuleTimeout struct {
	// Enabled 为 true 时本声明生效，替代全局的 timeout + fail_action。
	Enabled bool
	// Seconds 是裁决的墙钟上限（秒）。
	Seconds int
	// Action 是裁决失败/超时后的动作："deny" | "allow"。
	Action string
}

// JudgeRule is Judge for a rule whose action is "judge": the rule itself asks
// for a model verdict, so the global llm_judge_enabled switch is ignored (a rule
// that silently did nothing would be worse than either fixed action). The
// configured fail action / timeout still apply.
func (i *Interceptor) JudgeRule(ctx context.Context, tool string, arguments json.RawMessage) (Decision, bool) {
	return i.judge(ctx, tool, arguments, true, RuleTimeout{})
}

// JudgeRuleWithTimeout is JudgeRule with the triggering rule's own timeout
// declaration applied. The rule's timeout_enabled/seconds/action override the
// global judge configuration when enabled; otherwise the global values apply.
//
// 语义（回归基线见 intercept/rule_timeout_test.go）：
//   - Enabled=false → 全局 llm_judge_timeout_seconds + 全局 llm_judge_fail_action
//   - Enabled=true  → 规则自己的 Seconds + Action
//
// Action 只在「模型裁决失败或超时」时起作用（那时没有裁决结果可用）；裁决
// 成功时以模型的动作（allow/ask/deny）为准。
func (i *Interceptor) JudgeRuleWithTimeout(ctx context.Context, tool string, arguments json.RawMessage, rt RuleTimeout) (Decision, bool) {
	return i.judge(ctx, tool, arguments, true, rt)
}

func (i *Interceptor) judge(ctx context.Context, tool string, arguments json.RawMessage, forced bool, rt RuleTimeout) (Decision, bool) {
	cfg := i.judgeConfig()
	// 规则级 timeout 覆盖全局：规则作者显式声明了「我超时时怎么办」，
	// 那就是这条规则的策略，不受全局兜底配置影响。
	if rt.Enabled {
		if rt.Seconds > 0 {
			cfg.TimeoutSeconds = rt.Seconds
		}
		switch rt.Action {
		case "allow", "deny", "ask":
			cfg.FailAction = rt.Action
		}
	}
	i.mu.RLock()
	rv := i.reviewer
	i.mu.RUnlock()
	if !forced && (!cfg.Enabled || rv == nil) {
		return Decision{}, false
	}
	if rv == nil {
		// 规则显式要求研判，但 server 没接上 reviewer（例如测试环境/初始化早期）：
		// 按配置的失败策略处理，而不是让规则变成无动作。
		return Decision{Action: cfg.FailAction, ModelFallback: true, Message: "[模型] 裁决未接线,按失败策略处理"}, true
	}

	cctx := ctx
	if cfg.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		cctx, cancel = context.WithTimeout(ctx, time.Duration(cfg.TimeoutSeconds)*time.Second)
		defer cancel()
	}

	input, contextErr := BuildReviewInput(cctx, tool, arguments)
	cfg.Prompt = EffectiveJudgePrompt(cfg.Prompt)
	var out Decision
	var err error
	var modelInput []byte
	if contextErr != nil {
		// Invalid current arguments cannot be reviewed faithfully, regardless of
		// the configured model-failure strategy. A human must resolve the input.
		out = Decision{Action: "ask", ModelFallback: true, Message: "审查上下文不完整，需要人工确认：" + contextErr.Error()}
	} else {
		modelInput, _ = json.Marshal(input)
		out, err = rv(cctx, cfg.ProfileID, cfg.Prompt, input)
	}
	if err != nil {
		out = Decision{ProfileID: out.ProfileID, ModelFallback: true, Action: cfg.FailAction, Message: "模型审批失败,按失败策略处理: " + err.Error()}
	}
	switch out.Action {
	case "allow", "ask", "deny":
		// valid verdict
	default:
		out = Decision{ProfileID: out.ProfileID, ModelFallback: true, Action: cfg.FailAction, Message: "模型输出无法解析,按失败策略处理"}
	}
	// A model verdict never carries a rule; keep RuleID 0 (→ NULL) for history.
	out.RuleID = 0
	if len(modelInput) > 0 {
		out.ModelInput = modelInput
		out.ModelInputDigest = digestInput(modelInput)
	}
	if out.ProfileID != 0 {
		cfg.ProfileID = out.ProfileID
	}
	out.ProfileID = cfg.ProfileID
	configJSON, _ := json.Marshal(cfg)
	out.ConfigDigest = digestInput(configJSON)
	if out.Message == "" {
		out.Message = "[模型] " + judgeActionLabel(out.Action)
	} else if !strings.HasPrefix(out.Message, "[模型]") {
		out.Message = "[模型] " + out.Message
	}
	if out.Action == "ask" {
		out.TimeoutEnabled = true
		out.TimeoutSeconds = cfg.AskTimeoutSeconds
		out.TimeoutAction = cfg.AskTimeoutAction
	}
	return out, true
}

func judgeActionLabel(action string) string {
	switch action {
	case "allow":
		return "放行"
	case "deny":
		return "拦截"
	case "ask":
		return "转人工审批"
	default:
		return action
	}
}

// Match evaluates the rule list (priority DESC) against a tool call.
// Returns (Decision, true) for the first matching enabled rule, or
// (Decision{}, false) if no rule matches.
func (i *Interceptor) Match(toolName string, input []byte) (Decision, bool) {
	rules, err := i.rules()
	if err != nil || len(rules) == 0 {
		return Decision{}, false
	}
	for _, r := range rules {
		if ruleMatches(r, toolName, input) {
			msg := r.Message
			if msg == "" {
				msg = defaultMessage(r.Action, r.Name)
			}
			configJSON, _ := json.Marshal(r.InterceptRule)
			return Decision{
				RuleName: r.Name, ConfigDigest: digestInput(configJSON),
				Action:         r.Action,
				Message:        msg,
				RuleID:         r.ID,
				TimeoutEnabled: r.TimeoutEnabled,
				TimeoutSeconds: r.TimeoutSeconds,
				TimeoutAction:  r.TimeoutAction,
			}, true
		}
	}
	return Decision{}, false
}

func ruleMatches(r compiledRule, toolName string, input []byte) bool {
	var subject string
	switch r.MatchTarget {
	case "tool_name":
		subject = toolName
	case "tool_input":
		subject = string(input)
	default:
		return false
	}
	if r.MatchType == "regex" {
		return r.re != nil && r.re.MatchString(subject)
	}
	return strings.Contains(subject, r.Pattern)
}

func defaultMessage(action, name string) string {
	switch action {
	case "deny":
		return "拦截规则 [" + name + "] 禁止执行此工具"
	case "ask":
		return "拦截规则 [" + name + "] 要求用户审批，请等待"
	default:
		return ""
	}
}

// Log records an allow/deny rule or model decision into intercept_pending as an ALREADY-decided
// row (status = "allowed" | "denied"), for observability. Unlike HandleAsk it does NOT
// block and needs no user action — it makes explicit review decisions visible on the history
// page (GET /api/intercept/history) and the task's intercept list. Best-effort: a DB
// error is swallowed so logging never changes the tool call's outcome. The pending list
// (status='pending') is unaffected, so it still shows only asks awaiting a decision.
func (i *Interceptor) Log(ctx context.Context, convID int64, dec Decision, toolName string, input []byte, status string) {
	// nil db（server 尚未接上数据库时）：没有地方可记，但**不能 panic**——
	// Log 在工具调用的同步路径上，崩了就是整个 agent 进程死掉。
	if i == nil || i.db == nil {
		return
	}
	taskID, agentName := taskInfoFromCtx(ctx)
	audit := auditFor(ctx, dec, input, status)
	id, err := i.db.CreateDecidedIntercept(dec.RuleID, convID, taskID, agentName, toolName, input, status, dec.Message, audit)
	if err == nil {
		i.bindResult(ctx, id, audit)
	}
}

// HandleAsk creates a pending approval record and blocks until the user decides
// (via /api/intercept/pending/{id}/decide) or the per-rule timeout elapses.
// Returns true if the user approved.
//
// convID == 0 means no active conversation (background pentest task). The
// pending record is still created (conversation_id = NULL) so the approvals
// page shows it and the sidebar badge lights up. The worker thread blocks just
// like in a chat session — the user must visit the approvals page to unblock it.
func (i *Interceptor) HandleAsk(ctx context.Context, convID int64, dec Decision, toolName string, input []byte) bool {
	// nil db（server 尚未接上数据库时）：没法建审批记录，也就没法等人批。
	// 此时按「拒绝」处理——不能因为没人能批就默认放行。
	if i == nil || i.db == nil {
		return false
	}
	ruleID := dec.RuleID
	taskID, agentName := taskInfoFromCtx(ctx)
	taskEmit := taskEmitFromCtx(ctx)

	audit := auditFor(ctx, dec, input, "pending")
	pendingID, err := i.db.CreateInterceptPending(ruleID, convID, taskID, agentName, toolName, input, dec.Message, audit)
	if err != nil {
		return false
	}

	i.bindResult(ctx, pendingID, audit)
	ch := i.pending.add(pendingID)
	defer i.pending.remove(pendingID)
	// Polling clients can decide after INSERT commits but before the channel is
	// registered. Re-read after registration so that decision cannot be lost;
	// later decisions will be delivered through ch.
	if saved, err := i.db.GetInterceptDetail(pendingID); err == nil && saved != nil && saved.Status != "pending" {
		return saved.Status == "allowed" || (saved.Audit != nil && saved.Audit.EffectiveAction == "allow")
	}

	detail, _ := json.Marshal(map[string]any{
		"pending_id": pendingID,
		"tool":       toolName,
		"input":      json.RawMessage(input),
	})
	activity := db.Activity{
		Kind:    "intercept_request",
		Summary: fmt.Sprintf("工具 %s 请求审批 (#%d)", toolName, pendingID),
		Detail:  string(detail),
	}

	if convID != 0 {
		// Chat session: write inline card to the conversation stream.
		_, _ = i.db.AppendConvActivity(convID, activity)
	} else if taskEmit != nil {
		// Task worker: emit to the exploration activity stream so it appears
		// inline in the session transcript (the emit fn stamps NodeID + Worker).
		taskEmit(activity)
	}

	if !dec.TimeoutEnabled {
		// 规则未声明超时 ≠ 无限等待：审批人离场时 worker 会挂死到任务超时，
		// 整个任务的预算跟着烧完（v0.3.88 体检 S2）。给一个全局兜底上限——
		// 到点按 deny 收口（ask 守的是能力边界变更，拒绝永远是安全侧），
		// 记日志让运维能在审批历史里看到「timeout」结果。上限可在系统设置
		// intercept_ask_default_timeout_seconds 覆盖（秒）。
		ceiling := i.getSettingInt(settingAskDefaultTimeoutSecs, defaultAskTimeoutSecs)
		if ceiling <= 0 {
			ceiling = defaultAskTimeoutSecs
		}
		timer := time.NewTimer(time.Duration(ceiling) * time.Second)
		defer timer.Stop()
		select {
		case allowed := <-ch:
			return allowed
		case <-timer.C:
			log.Printf("[intercept] ask 审批 #%d 超过全局兜底上限(%ds)无人处理，按 deny 收口", pendingID, ceiling)
			allowed := false
			action := "deny"
			resolved, err := i.db.ResolveIntercept(pendingID, "timeout", action, "审批超过兜底上限无人处理，按拒绝处理")
			if err != nil {
				return false
			}
			if !resolved {
				detail, err := i.db.GetInterceptDetail(pendingID)
				return err == nil && detail != nil && (detail.Status == "allowed" || (detail.Audit != nil && detail.Audit.EffectiveAction == "allow"))
			}
			return allowed
		case <-ctx.Done():
			_, _ = i.db.ResolveIntercept(pendingID, "denied", "deny", "工作已取消")
			_ = i.db.CompleteIntercept(pendingID, audit.RunID, audit.ToolUseID, "not_executed", "执行前工作已取消", false)
			return false
		}
	}

	secs := dec.TimeoutSeconds
	if secs <= 0 {
		secs = 60
	}
	timer := time.NewTimer(time.Duration(secs) * time.Second)
	defer timer.Stop()
	select {
	case allowed := <-ch:
		return allowed
	case <-timer.C:
		allowed := dec.TimeoutAction == "allow"
		action := "deny"
		if allowed {
			action = "allow"
		}
		resolved, err := i.db.ResolveIntercept(pendingID, "timeout", action, "审批超时，按超时策略处理")
		if err != nil {
			return false
		}
		if !resolved {
			detail, err := i.db.GetInterceptDetail(pendingID)
			return err == nil && detail != nil && (detail.Status == "allowed" || (detail.Audit != nil && detail.Audit.EffectiveAction == "allow"))
		}
		return allowed
	case <-ctx.Done():
		_, _ = i.db.ResolveIntercept(pendingID, "denied", "deny", "工作已取消")
		_ = i.db.CompleteIntercept(pendingID, audit.RunID, audit.ToolUseID, "not_executed", "执行前工作已取消", false)
		return false
	}
}

var ErrAlreadyDecided = errors.New("审批已处理或不存在，请刷新记录")

// Decide resolves a pending request. Called by the HTTP decide endpoint.
func (i *Interceptor) Decide(pendingID int64, allowed bool) error {
	status := "denied"
	if allowed {
		status = "allowed"
	}
	action, reason := "deny", "人工拒绝执行"
	if allowed {
		action, reason = "allow", "人工允许执行"
	}
	resolved, err := i.db.ResolveIntercept(pendingID, status, action, reason)
	if err != nil {
		return err
	}
	if !resolved {
		return ErrAlreadyDecided
	}
	i.pending.resolve(pendingID, allowed)
	return nil
}
