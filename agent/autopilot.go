package agent

import (
	"context"

	"github.com/chu0119/pojun/intercept"
)

// 自主推进（Autopilot）的提示词尾巴。
//
// 与 kb/domain 的尾巴同一套机制：**代码拼接、永远在场**，不受 UI 改提示词影响。
// 只在任务开启自主推进时追加（见 planner.go / worker.go 的 ctx resolver 调用），
// 普通任务完全看不到这些约束，行为保持原样。
//
// 写作口径：
//   - 只表达「必须继续推进、目标未达成不算完」，不重复知识库/黑灰产尾巴已有的内容；
//   - 必须让位给终局收尾指令：任务真到 deadline/预算上限时，收尾词优先，
//     否则模型会在收尾轮里继续硬推，和 wrapup 打架。

const autopilotPlannerGuidance = `
【自主推进模式（本任务已开启，以下约束优先于上面的常规收场习惯）】
- 完成优先：只要目标还没被判为达成，你就**不能**用「探索完毕 / 信息不足 / 边际收益低」作为收场理由。
  每一轮必须给出至少一个推进动作：派新意图、换方向重试、补充证据验证，或明确记录一条
  「这个方向为什么不可行」的事实后再换路。
- 无在跑意图且仍有未达成目标时，**必须**立即派意图（这是硬性下限，不是建议）。
- 停滞时先查知识库（kb_search）再换向量；不要原样重派刚刚失败的意图。
- 只有满足以下之一才允许结束任务：① 所有目标经 prove_goal/goal_met 判定达成；
  ② 收到明确的终局收尾指令（任务超时/预算上限）。除此之外不要自行收场。
`

const autopilotWorkerGuidance = `
【自主推进模式（本任务已开启）】
- 本条意图的假设必须被证实或证伪才算结束：写回支撑事实（fact/asset/finding/evidence）后再收手，
  不要在没有写回的情况下空转收场。
- 遇到阻碍先换向量（编码/路径/参数位置/请求方法/来源 IP/时间窗），并先 kb_search 查知识库；
  仍不通就把「试过什么、为什么无效」写成 fact，而不是只留一句结论。
- 不要执行会等待人工输入/审批的动作：审批需要人工响应，会让推进停摆；换一条不需要审批的等价路径（更小的验证动作/只读证明）继续，并留证据。
- 终局收尾指令优先：如果收到「任务超时/预算上限」的收尾词，按收尾词执行，不要再开新战场。
`

// autopilotTail 在任务开启自主推进时返回提示词尾巴，否则空串。
// 走 ctx resolver（intercept.WithAutopilot 注入），与审批放行共用同一个开关：
// 运行中关闭开关，下一次规划/执行就回到普通模式。
func autopilotTail(ctx context.Context, tail string) string {
	if ap := intercept.AutopilotFromContext(ctx); ap != nil && ap() {
		return tail
	}
	return ""
}
