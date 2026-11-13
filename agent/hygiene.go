package agent

import (
	"fmt"
	"strings"
	"time"

	"github.com/chu0119/pojun/db"
)

// renderBacklogHygiene 把「排太久」或「前提疑似失效」的 open 意图列进本轮规划输入，
// 要求规划者逐条裁决（保留 / retire_intent 退役 / 按新事实重派）。
//
// 为什么需要（2026-11-13 任务 20 核查）：规划者已经读到新结论（124/124 意图都锚定
// 既有 fact），但没有任何工具能把「已排队的旧意图」撤回——#5225/#5226 在目标被证伪
// 6 小时后仍是 open，worker 迟早会白跑。这里只做提示，退役动作仍由模型显式调用，
// 保留可追溯的原因，不做自动杀。
func renderBacklogHygiene(ts *db.ExplorationStore) string {
	if ts == nil {
		return ""
	}
	items, err := ts.OpenIntentHygiene(2*time.Hour, 40)
	if err != nil || len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n【积压治理（本轮必须处理）】：下列排队意图已排超过 2 小时，或其锚点事实已被后续结论否定。")
	b.WriteString("逐条裁决：仍有效→保留；前提已失效/方向已排除→调用 retire_intent（reason 里写清哪条 fact/finding 否定了它）；")
	b.WriteString("因重复→retire_intent 必须带 superseded_by 指向存活的替代意图（open/running/done），不允许指向已退役的；")
	b.WriteString("每轮最多退役 6 条，其余下一轮再处理——先把替代关系确认清楚，别为了清积压把整类能力删空。")
	const maxShow = 5
	for i, it := range items {
		if i == maxShow {
			fmt.Fprintf(&b, "\n- …另有 %d 条同类积压（见 graph_overview）", len(items)-maxShow)
			break
		}
		fmt.Fprintf(&b, "\n- #%d（排队 %.1f 小时，优先级 %d）：%s", it.ID, it.AgeHours, it.Priority, clampForPrompt(it.Summary, 70))
		for _, w := range it.Warnings {
			b.WriteString("\n  ⚠ " + clampForPrompt(w, 100))
		}
	}
	return b.String()
}

// clampForPrompt 截断提示词里的长文本（按 rune，保留原意开头）。
func clampForPrompt(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
