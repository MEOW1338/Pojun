package report

import (
	"encoding/json"

	"github.com/chu0119/pojun/db"
)

// GoalLine 是报告里的一个任务目标及其达成情况（v0.6.31）。
//
// 背景：任务可能只完成了部分目标，过去报告里只有原始 Goal 文本，读者看不出
// 「哪些目标被证明达成、哪些没做」。现在 Markdown/docx 都列出逐条目标与状态，
// 未全部达成时明确标注，避免交付材料看起来像「全部完成」。
type GoalLine struct {
	Text     string
	State    string // open | met（goal 节点的状态）
	Criteria string // 可核验的验收标准（可能为空）
}

// Met 表示该目标已由 prove_goal 逐条证明。
func (g GoalLine) Met() bool { return g.State == "met" }

// GoalLines 把 goal 节点转成报告行；nil/空输入返回 nil（报告省略该节）。
func GoalLines(nodes []*db.Node) []GoalLine {
	if len(nodes) == 0 {
		return nil
	}
	out := make([]GoalLine, 0, len(nodes))
	for _, n := range nodes {
		var p struct {
			Text     string `json:"text"`
			Criteria string `json:"criteria"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		if p.Text == "" {
			continue
		}
		out = append(out, GoalLine{Text: p.Text, State: n.State, Criteria: p.Criteria})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// GoalTally 返回（已达成, 总数）。
func GoalTally(goals []GoalLine) (met, total int) {
	for _, g := range goals {
		total++
		if g.Met() {
			met++
		}
	}
	return met, total
}
