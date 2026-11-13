package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
	"github.com/chu0119/pojun/agent"
	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/llmrec"
)

type taskAgentBundle struct {
	runtime        *taskLLMRuntime // goal decomposition runtime
	plannerRuntime *taskLLMRuntime
	workerRuntime  *taskLLMRuntime
	mainRuntime    *taskLLMRuntime
	pl             *agent.Planner
	wk             *agent.Worker
	main           *agent.MainAgent
}

type llmAuditProfile struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Format string `json:"format"`
	Model  string `json:"model"`
}

type llmTransitionAudit struct {
	Mode     string           `json:"mode"` // automatic | manual | exhausted
	Reason   string           `json:"reason"`
	Previous *llmAuditProfile `json:"previous,omitempty"`
	Next     *llmAuditProfile `json:"next,omitempty"`
}

type llmActivityMetadata struct {
	LLMTransition llmTransitionAudit `json:"llm_transition"`
}

type taskLLMRuntime struct {
	s        *Server
	taskID   string
	agentKey string
	// pin > 0 时本 runtime 永远跑在该 profile 上（B10：压缩器等固定用途的场景），
	// 覆盖 agent 绑定和任务链；profile 失效（被删/无 key）时落回原链继续跑。
	// 不推进任务链的故障转移状态（绑定语义），也不参与链轮转。
	pin int64
}

type taskLLMError struct {
	taskID         string
	chainExhausted bool
	cause          error
}

func (e *taskLLMError) Error() string {
	if e.chainExhausted {
		return fmt.Sprintf("task %s LLM profile chain exhausted: %v", e.taskID, e.cause)
	}
	return e.cause.Error()
}

func (e *taskLLMError) Unwrap() error { return e.cause }

func isTaskLLMRuntimeError(err error) bool {
	var target *taskLLMError
	return errors.As(err, &target)
}

func isTaskLLMChainExhausted(err error) bool {
	var target *taskLLMError
	return errors.As(err, &target) && target.chainExhausted
}

// isQuotaExhaustedError is intentionally strict. A generic 429, auth error,
// network failure, or 5xx does not rotate providers; the response must explicitly
// identify quota, credits, billing balance, or payment exhaustion.
func isQuotaExhaustedError(err error) bool {
	return err != nil && agent.IsQuotaExhaustedMessage(err.Error())
}

type taskLLMSelection struct {
	task      *Task
	profileID int64
	revision  int64
	provider  llm.Provider
	// retry 是这次选中的配置解析出来的重试参数(profile 覆盖 → 全局策略 → 内置默认)。
	// 同 provider 安全窗口重试按它走,所以换了 profile 就换一套重试节奏。
	retry agent.RetryConfig
}

type taskLLMStreamHooks struct {
	current    func() (taskLLMSelection, error)
	exhaust    func(taskLLMSelection, error) (db.TaskLLMTransition, error)
	transition func(taskLLMSelection, db.TaskLLMTransition, error)
	// withoutThinking 解析一个**不发 thinking.type 字段**的等价 provider，
	// 供「模型拒收 thinking 参数」时降级重试（见 thinking_fallback.go）。
	//
	// 为什么需要它：thinking 参数是在 **provider 配置层**注入的（llm.Config
	// .ThinkingType），不在 llm.CompletionRequest 里——所以降级不能靠改请求，
	// 只能换一个 provider。
	//
	// nil = 不支持降级（此时 2013 会照常冒泡）。
	withoutThinking func() (llm.Provider, error)
}

// current resolves the provider this role runs on, by precedence:
// pinned profile (B10) → Agent 绑定 → 任务 LLM 配置链 → 全局/环境配置。
// pin 与绑定同语义：额度错误不推进任务链。绑定优先于任务链：某个角色被显式指定了模型，
// 就一直跑在那个模型上；绑定不存在或构建失败时才降级到任务链，任务链为空时再降级到全局配置。
// 返回的 profile id 只有走任务链时才非零 —— streamTaskLLM 以此判断额度错误是否
// 应该推进任务的故障转移状态（绑定/全局路径不改任务链状态，沿用既有语义）。
func (r *taskLLMRuntime) current() (taskLLMSelection, error) {
	// pin 方（B10 压缩器等固定用途）：指定 profile 有效就直接返回，省掉任务状态
	// 的 DB 读。profile 失效（被删/无 key）→ 落回下面的原链继续跑，不硬失败。
	if r.pin > 0 {
		if prov, cfg, ok := r.s.providerForProfile(r.pin); ok {
			return taskLLMSelection{provider: prov, retry: cfg.Retry}, nil
		}
	}
	taskNum, err := parseTaskID(r.taskID)
	if err != nil {
		return taskLLMSelection{}, err
	}
	pt, err := r.s.m.pg.GetTask(taskNum)
	if err != nil {
		return taskLLMSelection{}, err
	}
	if pt == nil {
		return taskLLMSelection{}, fmt.Errorf("task %s not found", r.taskID)
	}
	r.s.syncTaskLLMState(pt)
	t, _ := r.s.m.Task(r.taskID)
	sel := taskLLMSelection{task: t, revision: pt.LLMChainRevision}
	if prov, cfg, ok := r.s.agentBindingProvider(r.agentKey); ok {
		sel.provider, sel.retry = prov, cfg.Retry
		return sel, nil
	}
	if len(pt.LLMProfileIDs) > 0 {
		if pt.ActiveLLMProfileID == nil {
			return sel, &taskLLMError{taskID: r.taskID, chainExhausted: true, cause: errors.New("all selected profiles are quota exhausted")}
		}
		sel.profileID = *pt.ActiveLLMProfileID
		prov, cfg, ok := r.s.providerForProfile(sel.profileID)
		if !ok {
			return sel, fmt.Errorf("LLM profile #%d is missing or invalid", sel.profileID)
		}
		sel.provider, sel.retry = prov, cfg.Retry
		return sel, nil
	}
	prov, cfg, ok := r.s.globalProvider()
	if !ok {
		return sel, fmt.Errorf("task %s has no available fallback LLM provider", r.taskID)
	}
	sel.provider, sel.retry = prov, cfg.Retry
	return sel, nil
}

// activeCfg resolves the task's currently-active LLM config, mirroring current()'s
// source precedence (pin → agent binding → active chain profile → global). Read-only and
// best-effort: ok=false when nothing resolves, leaving the per-setting fallback to
// the caller. If failover switches profiles, the change takes effect on the next
// agent run (a fresh Session is built per run in captureRun).
func (r *taskLLMRuntime) activeCfg() (agent.Config, bool) {
	// pin 方（B10）：与 current() 的 pin 分支一致，优先取钉住的配置。
	if r.pin > 0 {
		if _, cfg, ok := r.s.providerForProfile(r.pin); ok {
			return cfg, true
		}
	}
	taskNum, err := parseTaskID(r.taskID)
	if err != nil {
		return agent.Config{}, false
	}
	pt, err := r.s.m.pg.GetTask(taskNum)
	if err != nil || pt == nil {
		return agent.Config{}, false
	}
	if _, cfg, ok := r.s.agentBindingProvider(r.agentKey); ok {
		return cfg, true
	}
	if len(pt.LLMProfileIDs) > 0 && pt.ActiveLLMProfileID != nil {
		if _, cfg, ok := r.s.providerForProfile(*pt.ActiveLLMProfileID); ok {
			return cfg, true
		}
	}
	if _, cfg, ok := r.s.globalProvider(); ok {
		return cfg, true
	}
	return agent.Config{}, false
}

// nonStreaming reports whether the task's currently-active LLM source is set to
// non-streaming. Unresolvable → streaming (false), the safe default.
func (r *taskLLMRuntime) nonStreaming() bool {
	cfg, ok := r.activeCfg()
	return ok && !cfg.Stream
}

// maxTokens returns the currently-active source's per-reply output cap.
// Unresolvable → 0, i.e. send no cap, matching the pre-setting behaviour.
func (r *taskLLMRuntime) maxTokens() int {
	cfg, _ := r.activeCfg() // 未解析出配置时是零值 0
	return cfg.MaxTokens
}

func parseTaskID(id string) (int64, error) {
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid task id %q", id)
	}
	return n, nil
}

// streamHooks builds the failover/exhaustion callbacks shared by Stream and
// Complete: how to read the current profile selection, how to mark it quota
// exhausted, and how to emit a failover transition.
func (r *taskLLMRuntime) streamHooks() taskLLMStreamHooks {
	return taskLLMStreamHooks{
		current: r.current,
		exhaust: func(selection taskLLMSelection, cause error) (db.TaskLLMTransition, error) {
			taskNum, _ := parseTaskID(r.taskID)
			transition, err := r.s.m.pg.MarkTaskLLMProfileQuotaExhaustedAtRevision(taskNum, selection.profileID, selection.revision, cause.Error())
			if err != nil {
				return transition, err
			}
			if pt, getErr := r.s.m.pg.GetTask(taskNum); getErr == nil && pt != nil {
				r.s.syncTaskLLMState(pt)
			}
			return transition, nil
		},
		transition: func(selection taskLLMSelection, transition db.TaskLLMTransition, cause error) {
			r.s.emitTaskLLMTransition(selection.task, transition, cause)
		},
		withoutThinking: r.withoutThinking,
	}
}

// configForSelection 解析 selection 对应的 LLM 配置（与 current() 的优先级一致）。
//
// current() 只把 provider 交出来；降级重试需要**配置本身**才能重建一个不带
// thinking 的 provider，所以这里按同样的顺序再解析一次。
//
// agentKey 传空 = 不走 agent 绑定这一级（调用方已经知道绑定的结果）。
func (s *Server) configForSelection(agentKey string, sel taskLLMSelection) (agent.Config, bool) {
	// 1) agent 绑定
	if agentKey != "" {
		if prov, cfg, ok := s.agentBindingProvider(agentKey); ok && prov != nil {
			return cfg, true
		}
	}
	// 2) 任务链的当前 profile
	if sel.profileID > 0 {
		if _, cfg, ok := s.providerForProfile(sel.profileID); ok {
			return cfg, true
		}
	}
	// 3) 全局
	if _, cfg, ok := s.globalProvider(); ok {
		return cfg, true
	}
	return agent.Config{}, false
}

// withoutThinking 解析一个不发 thinking.type 字段的等价 provider。
//
// 复用 current() 的解析路径（绑定 → 任务链 → 全局），只是把解析出的配置里的
// ThinkingType 清掉再重建 provider。重建出来的 provider **不进 provider 缓存**
// ——它只服务于这一次降级重试，缓存进去会让后续所有调用都丢掉 thinking 参数，
// 那等于悄悄改掉了用户的配置。
//
// 拿不到等价配置时（没有可解析的 profile）返回错误，调用方按原错误冒泡。
func (r *taskLLMRuntime) withoutThinking() (llm.Provider, error) {
	sel, err := r.current()
	if err != nil {
		return nil, err
	}
	// current() 已经把配置解析好了，但只把 provider 交出来；这里需要 cfg 本身
	// 才能重建。故按同样的优先级再解析一次配置。
	cfg, ok := r.s.configForSelection(r.agentKey, sel)
	if !ok {
		return nil, fmt.Errorf("无法解析 LLM 配置以降级重试（profile %d）", sel.profileID)
	}
	if cfg.ThinkingType == "" {
		// 本来就没发 thinking.type ——降级没有意义，让调用方按原错误冒泡。
		return nil, fmt.Errorf("当前配置未发送 thinking 参数，无法降级")
	}
	cfg.SuppressThinking = true
	prov, err := cfg.NewProvider()
	if err != nil {
		return nil, err
	}
	return prov, nil
}

func (r *taskLLMRuntime) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	ctx = llmrec.WithTaskID(ctx, r.taskID)
	return streamTaskLLM(ctx, r.taskID, req, r.streamHooks())
}

// Complete is the non-streaming counterpart of Stream. A non-streaming call is
// atomic — it never delivers partial output — so every failure is safe to retry
// on the same provider or fail over to the next profile without risking
// duplicated model output or tool execution (the "committed" bookkeeping the
// streaming path needs is unnecessary here).
func (r *taskLLMRuntime) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	ctx = llmrec.WithTaskID(ctx, r.taskID)
	return completeTaskLLM(ctx, r.taskID, req, r.streamHooks())
}

func completeTaskLLM(ctx context.Context, taskID string, req llm.CompletionRequest, hooks taskLLMStreamHooks) (llm.Message, string, llm.Usage, error) {
	// thinking 降级只做一次（与 streamTaskLLM 同理，见 thinking_fallback.go）。
	// 降级是【换 provider】而不是改请求——thinking 参数在 provider 配置层。
	downgradedProv, thinkingDowngraded := llm.Provider(nil), false
	for {
		selection, err := hooks.current()
		if err != nil {
			return llm.Message{}, "", llm.Usage{}, err
		}
		var (
			msg     llm.Message
			sr      string
			usage   llm.Usage
			callErr error
		)
		// 同 provider 安全窗口重试:非流式调用要么整体成功、要么整体失败,没有
		// 中途已交付输出的问题,所以任何瞬时失败都可原样重试。
		retries, backoffOf := sameProviderRetryPolicy(selection.retry)
		for attempt := 0; ; attempt++ {
			prov := selection.provider
			if downgradedProv != nil {
				prov = downgradedProv
			}
			msg, sr, usage, callErr = prov.Complete(ctx, req)
			// 模型拒收 thinking 参数 → 换一个不发 thinking 的 provider 重试一次。
			if callErr != nil && !thinkingDowngraded && ctx.Err() == nil &&
				hooks.withoutThinking != nil && isThinkingRejected(callErr) {
				alt, altErr := hooks.withoutThinking()
				if altErr == nil {
					thinkingDowngraded = true
					downgradedProv = alt
					log.Printf("[task-llm] task %s 模型拒收 thinking 参数,改用不带 thinking 的 provider 重试: %v", taskID, callErr)
					continue
				}
				log.Printf("[task-llm] task %s 模型拒收 thinking 参数,但无法降级(%v),按原错误处理", taskID, altErr)
			}
			if callErr != nil && ctx.Err() == nil &&
				attempt < retries && isRetryableStreamError(callErr) {
				backoff := backoffOf(attempt)
				log.Printf("[task-llm] task %s 非流式调用失败,%v 后同 provider 重试 (%d/%d): %v",
					taskID, backoff, attempt+1, retries, callErr)
				if sleepCtx(ctx, backoff) {
					break // 退避期间 ctx 取消 → 停止重试
				}
				continue
			}
			break
		}
		if callErr == nil {
			return msg, sr, usage, nil
		}
		// profileID=0: 显式链已被清空;非额度错误:透传。二者都不改任务 failover 状态。
		if selection.profileID == 0 || !isQuotaExhaustedError(callErr) {
			return llm.Message{}, "", llm.Usage{}, callErr
		}
		transition, markErr := hooks.exhaust(selection, callErr)
		if markErr != nil {
			return llm.Message{}, "", llm.Usage{}, fmt.Errorf("mark profile quota exhausted after %v: %w", callErr, markErr)
		}
		if transition.Advanced && !transition.Stale && hooks.transition != nil {
			hooks.transition(selection, transition, callErr)
		}
		if !transition.Stale && transition.NextProfileID == nil {
			return llm.Message{}, "", llm.Usage{}, &taskLLMError{taskID: taskID, chainExhausted: transition.ChainExhausted, cause: callErr}
		}
		// 没有任何输出交付给调用方,换下一个 profile 重放同一逻辑请求是安全的。
	}
}

func streamTaskLLM(ctx context.Context, taskID string, req llm.CompletionRequest, hooks taskLLMStreamHooks) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		// thinking 降级只做一次：模型拒收 thinking 参数时换 provider 重试。
		// 变量在闭包外声明，因为降级后的 provider 要贯穿整个 for 循环
		// （换 profile 之后用的也是这一份）。
		cur := req
		downgradedProv, thinkingDowngraded := llm.Provider(nil), false
		for {
			selection, err := hooks.current()
			if err != nil {
				yield(llm.StreamEvent{}, err)
				return
			}
			committed := false
			var pending []llm.StreamEvent
			var streamErr error
			retries, backoffOf := sameProviderRetryPolicy(selection.retry)
			// 同 provider 安全窗口重试:committed 之前(还没向调用方交付任何输出)
			// 的瞬时失败可以原样重放,不会重复模型输出或工具执行。committed 之后、
			// ctx 取消、或确定性/额度错误则跳出,交给下方原有的透传/故障转移逻辑。
			for attempt := 0; ; attempt++ {
				committed = false
				pending = nil
				streamErr = nil
				prov := selection.provider
				if downgradedProv != nil {
					prov = downgradedProv
				}
				for event, err := range prov.Stream(ctx, cur) {
					if err != nil {
						streamErr = err
						break
					}
					if !committed && !streamEventCommitsOutput(event) {
						pending = append(pending, event)
						continue
					}
					if !committed {
						for _, buffered := range pending {
							if !yield(buffered, nil) {
								return
							}
						}
						pending = nil
						committed = true
					}
					if !yield(event, nil) {
						return
					}
				}
				// 模型拒收 thinking 参数（adaptive thinking 模型不接受
				// thinking.type=disabled）→ 换一个不发 thinking 的 provider 重试一次。
				//
				// 为什么在这里兜底而不是让每个调用方自己小心：这个 400 在
				// POJUN 里已经踩了三次（裁决/压缩/旁路摘要），每次都是某个
				// 新的调用方硬编码了 thinking。放在统一入口，一处修好全局生效。
				//
				// 降级必须【换 provider】而不是改请求：thinking 参数在 provider
				// 配置层（llm.Config.ThinkingType），不在 llm.CompletionRequest 里
				// ——第一版实现改请求，条件恒为假、从不触发（实测 2013 出现 23 次
				// 而降级 0 次）。
				//
				// 只降级一次：换 provider 后再报同样的错，说明不是这个原因，
				// 继续重试只是浪费。
				if streamErr != nil && !committed && !thinkingDowngraded &&
					ctx.Err() == nil && hooks.withoutThinking != nil && isThinkingRejected(streamErr) {
					alt, altErr := hooks.withoutThinking()
					if altErr == nil {
						thinkingDowngraded = true
						downgradedProv = alt
						log.Printf("[task-llm] task %s 模型拒收 thinking 参数,改用不带 thinking 的 provider 重试: %v", taskID, streamErr)
						continue
					}
					log.Printf("[task-llm] task %s 模型拒收 thinking 参数,但无法降级(%v),按原错误处理", taskID, altErr)
				}
				if streamErr != nil && !committed && ctx.Err() == nil &&
					attempt < retries && isRetryableStreamError(streamErr) {
					backoff := backoffOf(attempt)
					log.Printf("[task-llm] task %s 提交前流失败,%v 后同 provider 重试 (%d/%d): %v",
						taskID, backoff, attempt+1, retries, streamErr)
					if sleepCtx(ctx, backoff) {
						break // 退避期间 ctx 取消 → 停止重试
					}
					continue
				}
				break
			}
			if streamErr == nil {
				for _, buffered := range pending {
					if !yield(buffered, nil) {
						return
					}
				}
				return
			}
			// profileID=0 means the explicit chain was cleared while this stable task
			// bundle was still in use. Agent/global fallback errors follow the legacy
			// behavior and never mutate task failover state.
			if selection.profileID == 0 || !isQuotaExhaustedError(streamErr) {
				for _, buffered := range pending {
					if !yield(buffered, nil) {
						return
					}
				}
				yield(llm.StreamEvent{}, streamErr)
				return
			}
			transition, markErr := hooks.exhaust(selection, streamErr)
			if markErr != nil {
				cause := fmt.Errorf("mark profile quota exhausted after %v: %w", streamErr, markErr)
				if committed {
					// Output may already have driven tool execution. Report the persistence
					// failure, but classify it as router-handled so the worker does not
					// replay the entire intent and duplicate those side effects.
					yield(llm.StreamEvent{}, &taskLLMError{taskID: taskID, cause: cause})
				} else {
					yield(llm.StreamEvent{}, cause)
				}
				return
			}
			if transition.Advanced && !transition.Stale && hooks.transition != nil {
				hooks.transition(selection, transition, streamErr)
			}
			if committed || (!transition.Stale && transition.NextProfileID == nil) {
				yield(llm.StreamEvent{}, &taskLLMError{taskID: taskID, chainExhausted: transition.ChainExhausted, cause: streamErr})
				return
			}
			// No event reached the caller, so replaying the same logical request on
			// the next profile cannot duplicate model output or tool execution.
		}
	}
}

func streamEventCommitsOutput(event llm.StreamEvent) bool {
	switch event.Type {
	case llm.SETextDelta, llm.SEThinkingDelta, llm.SEToolInputJSON:
		return event.Text != ""
	case llm.SEToolUseStart, llm.SEMessageDelta, llm.SEMessageStop:
		return true
	default:
		return false
	}
}

// 提交前安全窗口内、对同一 provider 的【默认】重试次数。SDK 的 doStream 只重试建连
// 阶段(拿到 200 之前);流一旦开始,中途断流 / overloaded / 流内 429 等瞬时故障会直接
// 冒泡成 model_error,零重试。只要一个 token 都还没交给调用方(!committed),重放
// 完全相同的请求就不会重复模型输出或工具副作用,因此这里补一层同 provider 退避重试,
// 把这类抖动挡在意图整体重跑之前。可被 LLM 配置的重试覆盖/全局重试策略改写。
const sameProviderStreamRetries = 2

// sameProviderRetryBackoff 是第 attempt 次重试前的【默认】退避(0.5s、1s…,上限 4s),
// 与 SDK 的指数梯度同风格但封顶更小,避免拖住 worker 的收尾/取消响应。
// 以变量形式暴露,便于测试将退避置零。
var sameProviderRetryBackoff = func(attempt int) time.Duration {
	return min(500*time.Millisecond*(1<<attempt), 4*time.Second)
}

// sameProviderRetryPolicy 解析这次调用用哪套同 provider 重试参数:配置里设了次数就
// 用配置的(负数 = 关掉这层重试),设了间隔就把指数退避换成固定间隔,两者都没设时
// 与改可配之前逐字节一致。
func sameProviderRetryPolicy(r agent.RetryConfig) (retries int, backoff func(int) time.Duration) {
	retries, backoff = sameProviderStreamRetries, sameProviderRetryBackoff
	if r.StreamAttempts != 0 {
		retries = max(r.StreamAttempts, 0)
	}
	if r.StreamInterval > 0 {
		d := r.StreamInterval
		backoff = func(int) time.Duration { return d }
	}
	return retries, backoff
}

// isRetryableStreamError 判断「提交前的流失败」是否值得在同一 provider 上重放。
// 瞬时的传输中断 / 供应商过载 / 限流会自行恢复,可安全重试;而以下三类不重试:
//   - 额度耗尽:交给 profile 故障转移处理,别在这里白烧重试
//   - 上下文过长:相同请求重放也没用,交给 harness 的 reactive 压缩兜底
//   - 4xx 确定性拒绝(400/401/403/404/422):到哪个 provider 都一样会失败
func isRetryableStreamError(err error) bool {
	if err == nil {
		return false
	}
	if isQuotaExhaustedError(err) {
		return false
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "too long") || strings.Contains(s, "context length") ||
		strings.Contains(s, "context_length") || strings.Contains(s, "maximum context") ||
		strings.Contains(s, "status 413") {
		return false
	}
	for _, code := range []string{"status 400", "status 401", "status 403", "status 404", "status 422"} {
		if strings.Contains(s, code) {
			return false
		}
	}
	// 其余(传输 reset/EOF/timeout、408/429/5xx、流内 error 事件如 anthropic
	// overloaded_error 等)一律视为瞬时,允许重试。
	return true
}

// CompactionWindow mirrors current()'s precedence so the context window always
// matches the provider the role will actually stream on.
func (r *taskLLMRuntime) CompactionWindow() int {
	if _, cfg, ok := r.s.agentBindingProvider(r.agentKey); ok {
		return cfg.CompactionWindow()
	}
	taskNum, err := parseTaskID(r.taskID)
	if err != nil {
		return (agent.Config{}).CompactionWindow()
	}
	chain, err := r.s.m.pg.TaskLLMProfiles(taskNum)
	if err != nil {
		return (agent.Config{}).CompactionWindow()
	}
	if len(chain) == 0 {
		if _, cfg, ok := r.s.globalProvider(); ok {
			return cfg.CompactionWindow()
		}
		return (agent.Config{}).CompactionWindow()
	}
	minimum := 0
	for _, entry := range chain {
		if cfg, ok := r.s.loadProfileConfig(entry.ProfileID); ok {
			window := cfg.CompactionWindow()
			if minimum == 0 || window < minimum {
				minimum = window
			}
		}
	}
	if minimum == 0 {
		return (agent.Config{}).CompactionWindow()
	}
	return minimum
}

// agentBindingProvider resolves the profile a role is explicitly bound to
// (agents.llm_profile_id) — the highest-precedence level for task agents. ok=false
// when the role has no binding or the bound profile no longer builds, so callers
// fall through to the task chain. A bound profile stays exclusive unless
// llm_pool_bind_fallback is on, which is what poolForBinding encodes.
func (s *Server) agentBindingProvider(agentKey string) (llm.Provider, agent.Config, bool) {
	id := s.effectiveProfileForAgent(agentKey, nil)
	if id == nil {
		return nil, agent.Config{}, false
	}
	prov, cfg, ok := s.providerForProfile(*id)
	if !ok {
		return nil, agent.Config{}, false
	}
	return s.poolForBinding(*id, prov, cfg), cfg, true
}

// globalProvider returns the process-wide provider (persisted active profile or
// environment config) — the last resort once a role has neither a binding nor a
// task chain.
func (s *Server) globalProvider() (llm.Provider, agent.Config, bool) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if !s.llmOn || s.llmProv == nil {
		return nil, agent.Config{}, false
	}
	return s.llmProv, s.llmCfg, true
}

// taskRuntimeAvailable reports whether every listed role can resolve a provider
// under the runtime precedence in current(): the role's own binding first, then
// the task chain, then global. An exhausted chain is a hard stop for unbound
// roles rather than a silent fall through to global — same as current().
func (s *Server) taskRuntimeAvailable(t *Task, agentKeys ...string) bool {
	if t == nil || len(agentKeys) == 0 {
		return false
	}
	state := t.llmStateSnapshot()
	unboundReady := false
	if len(state.ProfileIDs) > 0 {
		if state.ActiveID != nil {
			_, _, unboundReady = s.providerForProfile(*state.ActiveID)
		}
	} else {
		_, _, unboundReady = s.globalProvider()
	}
	for _, key := range agentKeys {
		if _, _, ok := s.agentBindingProvider(key); ok {
			continue
		}
		if !unboundReady {
			return false
		}
	}
	return true
}

func (s *Server) invalidateTaskAgents() {
	s.taskAgentMu.Lock()
	s.taskAgents = map[string]*taskAgentBundle{}
	s.taskAgentMu.Unlock()
}

func (s *Server) agentsForTask(t *Task) *taskAgentBundle {
	s.taskAgentMu.Lock()
	defer s.taskAgentMu.Unlock()
	if bundle := s.taskAgents[t.ID]; bundle != nil {
		return bundle
	}
	goalRuntime := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "goals"}
	plannerRuntime := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "planner"}
	workerRuntime := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "worker"}
	mainRuntime := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "mainagent"}
	tx := transcript.NewStore(filepath.Join(s.m.dir, "transcripts"))
	window := workerRuntime.CompactionWindow()
	// 授权边界守卫开关（v0.4.63）：每个 agent bundle 装配时读一次设置。
	var scopeGuard, scopeInherit, notifyDedup bool
	if s.m.PG() != nil {
		scopeGuard = s.m.PG().GetBool("scope_write_guard", true)
		scopeInherit = s.m.PG().GetBool("scope_inherit_writes", false)
		notifyDedup = s.m.PG().GetBool("notify_cross_task_dedup", true)
	} else {
		scopeGuard, notifyDedup = true, true
	}
	wk := agent.NewWorker(workerRuntime, "task-router", s.m.dir, tx, window, s.agentMaxTurns("worker"))
	wk.SetScopeFlags(scopeGuard, scopeInherit, notifyDedup)
	wk.SetFindingRecorder(s.evidenceStore())
	wk.SetArtifactRecorder(s) // v0.5.0 证据附件：save_evidence 落盘登记
	wk.SetCompactionWindowResolver(workerRuntime.CompactionWindow)
	wk.SetNonStreaming(workerRuntime.nonStreaming) // 按任务当前激活 profile 的流式开关(每轮读)
	wk.SetMaxTokens(workerRuntime.maxTokens)       // 同上,输出上限也跟随当前激活 profile
	wk.SetNoaEnabled(s.m.NoaCompactionEnabled)     // 实验功能:noa 上下文压缩(平台级开关,每 run 读)
	wk.SetRunTimeout(time.Duration(s.agentRunSeconds("worker")) * time.Second)
	wk.SetProxy(s.m.ProxyAddr(), s.m.ProxyCACert())
	wk.SetWebSearch(s.webSearchFor("worker"))
	wk.SetConstraintInject(s.constraintInjectWorker) // 操作约束注入 worker(可配置,默认开)
	// 任务级登录凭据（v0.4.8）：装配时读一次并注入 worker system prompt。
	// 认证配置当前只在创建任务时录入；若以后加编辑接口，需要在保存后 invalidate
	// 本任务的 agent bundle 让下一轮重新装配。
	if s.m.PG() != nil {
		if id64, err := strconv.ParseInt(t.ID, 10, 64); err == nil {
			if pgTask, err2 := s.m.PG().GetTask(id64); err2 == nil && pgTask != nil && pgTask.AuthConfig != nil && pgTask.AuthConfig.Enabled {
				wk.SetTaskAuthBlock(pgTask.AuthConfig.PromptBlock())
			}
		}
	}
	pl := agent.NewPlanner(plannerRuntime, "task-router", s.m.dir, tx, plannerRuntime.CompactionWindow(), s.agentMaxTurns("planner"))
	pl.SetScopeFlags(scopeGuard, scopeInherit, notifyDedup)
	pl.SetIntentQueueLimit(s.intentQueueBudget) // 派发节流（v0.4.68）：本轮新增上限
	pl.SetFindingRecorder(s.evidenceStore())
	pl.SetCompactionWindowResolver(plannerRuntime.CompactionWindow)
	pl.SetNonStreaming(plannerRuntime.nonStreaming)
	pl.SetMaxTokens(plannerRuntime.maxTokens)
	pl.SetNoaEnabled(s.m.NoaCompactionEnabled) // 实验功能:noa 上下文压缩(平台级开关,每 run 读)
	pl.SetKillWork(s.engine.KillWork)
	pl.SetSteerWork(s.engine.SteerWork)
	// Guard 归因 → graph_overview 的 guard_attributions 块（计数 + B6 最近样本，
	// planner 看到 blocked/error 计数与被拦命令后可换打法，v0.3.88 体检 N5）。
	// t.Guard 在 manager.go 建任务时必然创建。
	pl.SetAttributions(t.Guard.AttributionStats)
	pl.SetProxy(s.m.ProxyAddr(), s.m.ProxyCACert())
	pl.SetWebSearch(s.webSearchFor("planner"))
	pl.SetConstraintInject(s.constraintInjectPlanner) // 操作约束注入 planner(可配置,默认开)
	// cold-digest §7: 冷节点后台压缩。引擎经权威解析器实际驱动的就是这套 per-task planner
	// (agentsForTask),Compactor 必须接在这里。压缩用 Complete 一次性生成 body。
	// B10:压缩器默认与 planner 共用 runtime(同任务链,历史行为);设置了
	// compactor_profile_id 时给压缩器一个钉住该 profile 的独立 runtime——机械压缩
	// 一次一发,体感上适合低价高速模型,不必跟着 planner 的长会话模型烧额度。
	// pin 失效时 runtime 内部落回原链,不会有硬失败。设置在更新后只对新任务的
	// bundle 生效(putSettings 里 invalidateTaskAgents 让运行中任务的下一轮也拿到)。
	compactorRuntime := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "planner", pin: s.m.CompactorProfileID()}
	if compactorRuntime.pin > 0 {
		log.Printf("[compactor] task %s: 压缩器钉在 profile #%d", t.ID, compactorRuntime.pin)
	}
	compactor := agent.NewCompactor(compactorRuntime, "task-router")
	// 压缩的输出预算与墙钟上限从设置读(0=用包内默认)。这两个值必须给足:
	// 思考型模型的思考长度随 max_tokens 预算线性膨胀,预算给小了模型会一直想、
	// 正文一个字都吐不出来(实测 1500/2048/4096/8192 全部正文为空)。
	compactor.SetOutputTokens(s.m.CompactionTokens())
	if secs := s.m.CompactionTimeout(); secs > 0 {
		compactor.SetMaxDuration(time.Duration(secs) * time.Second)
	}
	compactor.SetMaxBlockMembers(s.m.CompactionMaxMembers())
	pl.SetCompactor(compactor)
	main := agent.NewMainAgent(mainRuntime, "task-router", s.m.dir, tx, mainRuntime.CompactionWindow(), s.agentMaxTurns("mainagent"))
	main.SetScopeFlags(scopeGuard, scopeInherit, notifyDedup)
	main.SetFindingRecorder(s.evidenceStore())
	main.SetCompactionWindowResolver(mainRuntime.CompactionWindow)
	main.SetNonStreaming(mainRuntime.nonStreaming)
	main.SetMaxTokens(mainRuntime.maxTokens)
	main.SetNoaEnabled(s.m.NoaCompactionEnabled) // 实验功能:noa 上下文压缩(平台级开关,每 run 读)
	main.SetProxy(s.m.ProxyAddr(), s.m.ProxyCACert())
	main.SetWebSearch(s.webSearchFor("mainagent"))
	main.SetSteerWork(s.engine.SteerWork)          // steer_work：人对运行中 work 实时纠偏
	main.SetAttributions(t.Guard.AttributionStats) // Guard 归因样本（B6）→ 概览（人在环路同享打回计数与实物）
	bundle := &taskAgentBundle{
		runtime: goalRuntime, plannerRuntime: plannerRuntime, workerRuntime: workerRuntime,
		mainRuntime: mainRuntime, pl: pl, wk: wk, main: main,
	}
	s.taskAgents[t.ID] = bundle
	return bundle
}

func (s *Server) syncTaskLLMState(pt *db.Task) {
	if pt == nil {
		return
	}
	id := fmt.Sprintf("%d", pt.ID)
	s.m.mu.Lock()
	if task := s.m.tasks[id]; task != nil {
		task.setLLMState(pt.LLMProfileID, pt.ActiveLLMProfileID, pt.LLMProfileIDs, pt.LLMChainRevision, pt.LLMFailoverState, pt.LLMFailoverReason)
	}
	s.m.mu.Unlock()
}

func (s *Server) emitTaskLLMTransition(t *Task, transition db.TaskLLMTransition, cause error) {
	if t == nil {
		return
	}
	previous := s.llmAuditProfile(transition.PreviousProfileID)
	var next *llmAuditProfile
	if transition.NextProfileID != nil {
		next = s.llmAuditProfile(*transition.NextProfileID)
	}
	mode := "automatic"
	kind := "llm_switch"
	summary := fmt.Sprintf("%s 额度不足", llmAuditProfileLabel(previous))
	if transition.NextProfileID != nil {
		summary += fmt.Sprintf("，后续调用切换到 %s", llmAuditProfileLabel(next))
	} else {
		mode = "exhausted"
		kind = "llm_failover"
		summary += "，配置链已耗尽"
	}
	metadata, _ := json.Marshal(llmActivityMetadata{LLMTransition: llmTransitionAudit{
		Mode: mode, Reason: cause.Error(), Previous: previous, Next: next,
	}})
	s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: kind, IsError: transition.ChainExhausted, Summary: summary, Detail: cause.Error(), Metadata: metadata})
	log.Printf("[llm-failover] task %s: %s", t.ID, summary)
}

func (s *Server) llmAuditProfile(id int64) *llmAuditProfile {
	if id <= 0 || s.m == nil || s.m.pg == nil {
		return nil
	}
	p, err := s.m.pg.ProfileByID(id)
	if err != nil || p == nil {
		return &llmAuditProfile{ID: id, Name: fmt.Sprintf("配置 #%d", id)}
	}
	return &llmAuditProfile{ID: p.ID, Name: p.Name, Format: p.Format, Model: p.Model}
}

func llmAuditProfileLabel(profile *llmAuditProfile) string {
	if profile == nil {
		return "默认配置"
	}
	name := profile.Name
	if name == "" {
		name = fmt.Sprintf("配置 #%d", profile.ID)
	}
	detail := []string{}
	if profile.Format != "" {
		detail = append(detail, profile.Format)
	}
	if profile.Model != "" {
		detail = append(detail, profile.Model)
	}
	if len(detail) == 0 {
		return name
	}
	return fmt.Sprintf("%s（%s）", name, strings.Join(detail, " / "))
}

func sameOptionalID(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func (s *Server) emitManualTaskLLMSwitch(t *Task, previousID, nextID *int64) db.Activity {
	previous := (*llmAuditProfile)(nil)
	next := (*llmAuditProfile)(nil)
	if previousID != nil {
		previous = s.llmAuditProfile(*previousID)
	}
	if nextID != nil {
		next = s.llmAuditProfile(*nextID)
	}
	summary := fmt.Sprintf("用户手动将任务 LLM 从 %s 切换到 %s", llmAuditProfileLabel(previous), llmAuditProfileLabel(next))
	metadata, _ := json.Marshal(llmActivityMetadata{LLMTransition: llmTransitionAudit{
		Mode: "manual", Reason: "用户手动切换任务 LLM", Previous: previous, Next: next,
	}})
	return s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "llm_switch", Summary: summary, Detail: summary, Metadata: metadata})
}
