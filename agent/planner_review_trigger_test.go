package agent

import (
	"strings"
	"testing"
)

// B2: a zero-write-back exhausted intent must surface as a "review" trigger that
// spells out the postmortem instruction + the last step summaries, so the planner
// folds the attempt into a fact instead of letting it vanish.
func TestRenderTriggersReviewCarriesPostmortem(t *testing.T) {
	d := testDB(t)
	task, err := d.CreateTask("review-trigger测试", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	tools := NewToolSet(store, "planner")
	tools.SetTaskID(task.ID)

	intentID, err := tools.addOneIntent(intentItem{Summary: "探 /api/import 的 fastjson 入口"})
	if err != nil {
		t.Fatal(err)
	}

	got := renderTriggers(store, []TriggerEvent{{
		Kind:     "review",
		IntentID: intentID,
		Detail:   "curl -s http://t/api/import 返回 403；换 POST 仍 403",
	}})
	for _, want := range []string{
		"没有写回任何东西",
		"curl -s http://t/api/import 返回 403",
		"hypothesis",
		"探 /api/import 的 fastjson 入口",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("review trigger missing %q in:\n%s", want, got)
		}
	}

	// 摘要缺失时也要给出主动复盘的替代路径（不让指令空手）。
	got = renderTriggers(store, []TriggerEvent{{Kind: "review", IntentID: intentID}})
	if !strings.Contains(got, "get_worker_trace") {
		t.Errorf("empty-detail review should point at get_worker_trace, got:\n%s", got)
	}
}
