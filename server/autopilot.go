package server

// 自主推进（Autopilot）：一键把任务交给系统自己推到完成。
//
// 三条腿（设计见计划文件 / docs）：
//  1. （公开版不自动放行审批：审批门与拦截规则照常生效，提示词要求 agent 绕开需要人工审批的动作）；
//  2. 停滞看门狗：本文件每 60s 扫一次「自主推进中」的任务，长时间无进展就唤醒 planner 重规划，
//     连续无进展则延长 deadline（次数落库、有上限）；
//  3. 完成优先：auto_finish 的 idle/coverage 判据对 autopilot 任务不生效（见 auto_finish.go），
//     只有 goal_met 与 auto_rounds（成本硬上限）能收尾。
//
// 关键事实（避免踩坑）：
//   - engine.LastActivity 会被 planner 心跳（≥600s 一轮）刷新，不能用来判断停滞；
//     这里用「图上事实/漏洞计数」做进度指纹（与 auto_finish 的 idle 口径一致）。
//   - 停滞唤醒必须用独立的 trigger kind（autopilot_stall），不能复用 hint——
//     hint 会被 freshDirection 当作新方向并重置 idle 计数，反过来污染收尾判定。
//   - 被抑制的收尾原因必须从 Task 上清掉并让本轮继续规划，否则 plannerLoop 会在
//     「有挂起收尾」分支里无条件 return，把整个任务卡死。

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/chu0119/pojun/db"
)

const (
	settingAutopilotDefault       = "autopilot_default"
	settingAutopilotStallMinutes  = "autopilot_stall_minutes"
	settingAutopilotMaxExtensions = "autopilot_max_extensions"

	defaultAutopilotStallMinutes = 8
	// v0.6.12：默认 10（原 2）。relentless 模式的语义是「只要还有活就一直干」，
	// deadline 延长次数若停在 2，长任务仍会在半路被 timeout 收掉；上限仍由
	// ExtendTaskDeadline 守卫、可在设置页 0–10 调整。
	defaultAutopilotMaxExtensions = 10

	// 延长一次至少 15 分钟；按原预算的一半延长；单次上限 6 小时，防止一次拉到天亮。
	autopilotExtendFloor = 15 * time.Minute
	autopilotExtendCap   = 6 * time.Hour

	// 连续多少次停滞唤醒无进展后触发一次预算延长。
	autopilotNudgesBeforeExtend = 2
)

type autopilotConfig struct {
	Default       bool
	StallMinutes  int
	MaxExtensions int
}

// autopilotConfigFromPG 读全局设置并夹逼到安全范围；读库失败用默认值，
// 绝不能因为设置查询失败让看门狗停摆。
func autopilotConfigFromPG(pg *db.DB) autopilotConfig {
	c := autopilotConfig{
		Default:       true,
		StallMinutes:  defaultAutopilotStallMinutes,
		MaxExtensions: defaultAutopilotMaxExtensions,
	}
	if pg == nil {
		return c
	}
	c.Default = pg.GetBool(settingAutopilotDefault, true)
	if n, ok := settingInt(pg, settingAutopilotStallMinutes); ok {
		c.StallMinutes = clampInt(n, 3, 120)
	}
	if n, ok := settingInt(pg, settingAutopilotMaxExtensions); ok {
		c.MaxExtensions = clampInt(n, 0, 10)
	}
	return c
}

// autopilotTrack 是单任务的看门狗内存状态（重启清零，可接受）。
type autopilotTrack struct {
	lastProgressAt time.Time
	lastNudgeAt    time.Time
	nudges         int
	baseline       int64 // facts+findings 指纹
}

// trackFor 取/建某任务的看门狗状态（仅 tick 协程访问，无需额外加锁）。
func (e *Engine) trackFor(taskID string) *autopilotTrack {
	v, _ := e.autoTrack.LoadOrStore(taskID, &autopilotTrack{})
	return v.(*autopilotTrack)
}

// startAutopilotLoop 启动看门狗。全进程一个，跟随 server 的 s.ctx 退出。
func (e *Engine) startAutopilotLoop(ctx context.Context) {
	const tick = 60 * time.Second
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			e.autopilotTick(now)
		}
	}
}

// autopilotTick 是一次完整扫描。now 可注入，便于单测。
func (e *Engine) autopilotTick(now time.Time) {
	pg := e.m.pg
	if pg == nil {
		return
	}
	states, err := pg.AutopilotTaskStates()
	if err != nil {
		log.Printf("[autopilot] 扫描任务失败: %v", err)
		return
	}
	cfg := autopilotConfigFromPG(pg)
	stall := time.Duration(cfg.StallMinutes) * time.Minute

	for id, st := range states {
		t, ok := e.m.Task(id)
		if !ok || t == nil || !t.AutopilotEnabled() {
			e.autoTrack.Delete(id)
			continue
		}
		// 预算只剩不到一半时**提前**延长：在跑的 run 的 TaskClock 是启动时快照的，
		// 真到点再延长救不回已经把 MaxDuration 夹到接近 0 的那批 worker（它们会照常
		// 进收尾）。提前延长的次数同样受 autopilot_extensions 守卫。
		// v0.7.6：阈值从 10% 提到 50%，单次延长从半预算改为整预算——30 分钟任务
		// 每 15 分钟就把在跑的长链掐断一次，实测产生大量「运行超时(exhausted)」。
		if st.Unmet() && cfg.MaxExtensions > 0 && t.TimeoutSeconds > 0 {
			if dl := e.taskDeadline(t); dl > 0 {
				budget := time.Duration(t.TimeoutSeconds) * time.Second
				if time.Until(time.Unix(dl, 0)) < budget/2 {
					e.tryAutopilotExtend(t, cfg)
				}
			}
		}
		// v0.6.23：有在跑意图/LLM 调用时不再一刀切跳过——慢模型或卡住的 worker 可以
		// 长时间「在跑但零写回」，旧逻辑永远不判定停滞，任务在 UI 上看着永久静止
		// （交付体检实测：免费模型下两条意图 20+ 分钟零新写回、无新派单）。
		// 现在：无在跑时按 stall 窗口判定；有在跑时窗口放宽到 2 倍（尊重 nmap 级别的
		// 长扫描），planner 只读态势补派/纠偏，不打断 worker。
		if !e.Started(id) || e.IsDeleting(id) || e.isSettling(id) {
			continue
		}
		inflight := e.inflightCount(id) > 0 || e.ActiveLLMCalls(id) > 0
		if !st.Unmet() { // 目标已全部达成：看门狗退场
			e.autoTrack.Delete(id)
			continue
		}
		// 进度指纹 = 事实 + 漏洞 + 资产。纯事实数会被「复述/拆碎」灌水；新资产与新
		// 漏洞才是真实推进（v0.7.0）。
		progress := st.Facts + st.Findings + st.Assets
		tr := e.trackFor(id)
		if tr.lastProgressAt.IsZero() || progress > tr.baseline {
			tr.baseline = progress
			tr.lastProgressAt = now
			tr.nudges = 0
			continue
		}
		if now.Sub(tr.lastProgressAt) < stall {
			continue
		}
		// v0.6.23：有 worker 在跑时把停滞窗口放宽到 2 倍——正在跑的长扫描不误判；
		// 但「在跑却超过两个窗口零写回」说明它们空转/卡死，必须唤醒 planner。
		if inflight && now.Sub(tr.lastProgressAt) < 2*stall {
			continue
		}
		if !tr.lastNudgeAt.IsZero() && now.Sub(tr.lastNudgeAt) < stall {
			continue // 冷却：一个停滞窗口只唤醒一次
		}

		detail := fmt.Sprintf("已 %d 分钟没有新事实/新漏洞/新资产，目标尚未全部达成（%d/%d）。立即派下一步或换方向；禁止以「探索完毕/信息不足」收场。",
			int(now.Sub(tr.lastProgressAt).Minutes()), st.GoalsMet, st.GoalsTotal)
		if inflight {
			detail = fmt.Sprintf("已 %d 分钟没有新事实/新漏洞/新资产（仍有 worker 在跑但没有产出写回），目标尚未全部达成（%d/%d）。检查在跑意图是否空转：立即补充方向/给在跑意图纠偏，或派下一步；禁止以「探索完毕/信息不足」收场。",
				int(now.Sub(tr.lastProgressAt).Minutes()), st.GoalsMet, st.GoalsTotal)
		}
		t.NotifyAutopilotStall(detail)
		tr.lastNudgeAt = now
		tr.nudges++
		_ = pg.InsertAutopilotEvent(id, "stall_nudge", detail)
		e.emitActivity(t, db.Activity{Worker: "autopilot", Kind: "text",
			Summary: "自主推进：检测到停滞，已唤醒 planner 重规划"})
		log.Printf("[autopilot] task %s 停滞 %s 无进展 → 唤醒 planner（第 %d 次）",
			id, now.Sub(tr.lastProgressAt).Round(time.Minute), tr.nudges)

		// 连续唤醒仍无进展 → 延长预算（有上限、次数落库、单次有封顶）。
		if tr.nudges >= autopilotNudgesBeforeExtend {
			if e.tryAutopilotExtend(t, cfg) {
				tr.lastProgressAt = now // 给新预算一个完整窗口
				tr.nudges = 0
			}
		}
	}
}

// tryAutopilotExtend 把任务的绝对 deadline 往后推。返回 true 表示已延长。
//
// 只对「有时间预算且已盖章 deadline」的任务生效：没有 deadline 的任务本来就不会
// 超时，无需延长。次数由 DB 的 autopilot_extensions 守卫，跨重启也不会无限延长。
func (e *Engine) tryAutopilotExtend(t *Task, cfg autopilotConfig) bool {
	if t == nil || cfg.MaxExtensions <= 0 || t.TimeoutSeconds <= 0 {
		return false
	}
	old := e.taskDeadline(t)
	if old <= 0 {
		return false
	}
	// v0.7.6：按整份任务预算延长（旧实现取一半）。半预算只够覆盖一次长链的
	// 中段，任务很快再次贴边；整预算让续杯后的 worker 有完整窗口跑完利用链。
	ext := time.Duration(t.TimeoutSeconds) * time.Second
	if ext < autopilotExtendFloor {
		ext = autopilotExtendFloor
	}
	if ext > autopilotExtendCap {
		ext = autopilotExtendCap
	}
	id, err := parseTaskID(t.ID)
	if err != nil {
		return false
	}
	dl, used, ok, err := e.m.pg.ExtendTaskDeadline(id, int(ext.Seconds()), cfg.MaxExtensions)
	if err != nil {
		log.Printf("[autopilot] task %s 延长 deadline 失败: %v", t.ID, err)
		return false
	}
	if !ok {
		return false
	}
	e.deadline.Store(t.ID, dl.Unix())
	t.updateLifecycle(func(s *taskLifecycleState) { s.DeadlineAt = dl.Unix() })
	detail := fmt.Sprintf("目标未达成且连续无进展，deadline 自动延长 %s（第 %d/%d 次）→ %s",
		ext.Round(time.Minute), used, cfg.MaxExtensions, dl.Format("15:04:05"))
	_ = e.m.pg.InsertAutopilotEvent(t.ID, "deadline_extended", detail)
	e.emitActivity(t, db.Activity{Worker: "autopilot", Kind: "text", Summary: "自主推进：" + detail})
	log.Printf("[autopilot] task %s %s", t.ID, detail)
	return true
}

// suppressAutopilotSettle 判断某收尾原因是否应被自主推进抑制。
// 只抑制「没进展」类判据；goal_met / timeout（延长用尽）照旧。
func suppressAutopilotSettle(t *Task, reason string) bool {
	if t == nil || !t.AutopilotEnabled() {
		return false
	}
	switch reason {
	case "auto_idle", "auto_coverage", "auto_rounds":
		// auto_rounds 是「规划轮数上限」成本硬上限。不达目的不罢休模式下它同样
		// 不该收尾——用户明确要求没有预算/套现上限，只有真正穷尽才结束。
		return true
	}
	return false
}
