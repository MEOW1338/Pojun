package agent

import "fmt"

// 派发节奏（v0.6 背压；v0.10 软建议；v0.9.6 改为「按轮限量」）：代码尾巴，永远在
// planner 提示里。
//
// 背景：现网任务 #4 在 24 分钟里堆出 12 条 open 意图，而 worker 只有 3 个；
// 任务 #20（2026-11-13 核查）积压到 71 条 open、生产:消费 ≈ 2.5:1、最老的排队 6 小时。
// v0.8 完全放开（只靠软建议）不足以约束，v0.6 的总量硬拒绝又会卡住适应性派发，
// 因此改为「本轮新增上限」：积压越高，本轮能补的越少，但规划轮本身照常跑。
func pacingPlannerGuidance(limit, workers, active int) string {
	if limit <= 0 {
		return fmt.Sprintf(`
【派发节奏（建议，不是硬上限）】
- 当前未完成意图（open+running）%d 条，worker %d 个；平台不拒绝新意图。
- 有在跑意图或积压时，本轮最多补 1–2 条；只有 frontier 为空且没有在跑意图时才允许一次派 3–5 条。
- 派新方向前先看最近完成意图的产出：能接续/深挖就不要另起新方向；同方向反复派会稀释 worker 注意力。
- 已有结论否定了某条排队意图的前提时，用 retire_intent 退役它（附原因），别让 worker 之后白跑。
- 退役护栏：每轮最多 6 条；因重复退役必须给 superseded_by（指向 open/running/done 的替代意图），禁止指向已退役的；
  声称「前提失效」时必须在 reason 里引用否定它的 fact/finding 节点号。`, active, workers)
	}
	return fmt.Sprintf(`
【派发节奏（本任务硬约束）】
- 当前未完成意图（open+running）%d 条，阈值 %d，worker %d 个。
- 达到阈值后，本轮 add_intent 会被平台拒绝（只限本轮新增，不冻结规划）：你仍可读结果、prove_goal、写 fact、retire_intent。
- 有在跑意图或积压时，本轮最多补 1–2 条；只有 frontier 为空且没有在跑意图时才允许一次派 3–5 条。
- 派新方向前先看最近完成意图的产出：能接续/深挖就不要另起新方向。
- 已有结论否定了某条排队意图的前提时，用 retire_intent 退役它（附原因）——积压里最老的前几条若已失效，应主动清理。
- 退役护栏：每轮最多 6 条；因重复退役必须给 superseded_by（指向 open/running/done 的替代意图），禁止指向已退役的；
  声称「前提失效」时必须在 reason 里引用否定它的 fact/finding 节点号。`, active, limit, workers)
}
