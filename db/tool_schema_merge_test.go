package db

import (
	"encoding/json"
	"strings"
	"testing"
)

// 内置工具新增参数必须能补进已有行（SeedTool 只插不改）；补种只加缺失字段，不动用户编辑。
func TestMergeToolSchemaProperty(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()
	const key = "test_merge_prop"
	_, _ = d.Exec(`DELETE FROM tools WHERE key=$1`, key)
	defer d.Exec(`DELETE FROM tools WHERE key=$1`, key)

	old := json.RawMessage(`{"type":"object","properties":{"ids":{"type":"array"},"user_edit":{"type":"string"}}}`)
	if err := d.SeedTool(key, "old desc", old, json.RawMessage(`["planner"]`)); err != nil {
		t.Fatal(err)
	}
	props := map[string]any{"superseded_by": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}}}
	if err := d.MergeToolSchemaProperty(key, "superseded_by", props, "new desc"); err != nil {
		t.Fatal(err)
	}
	var schema, desc string
	if err := d.QueryRow(`SELECT schema::text, description FROM tools WHERE key=$1`, key).Scan(&schema, &desc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(schema, "superseded_by") || !strings.Contains(schema, "user_edit") {
		t.Fatalf("补种应新增字段且保留既有字段：%s", schema)
	}
	if desc != "new desc" {
		t.Fatalf("补种发生时应更新为代码默认描述：%q", desc)
	}
	// 幂等：再调一次不应报错，也不重复。
	if err := d.MergeToolSchemaProperty(key, "superseded_by", props, "new desc"); err != nil {
		t.Fatal(err)
	}
	var after string
	if err := d.QueryRow(`SELECT schema::text FROM tools WHERE key=$1`, key).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if strings.Count(after, "superseded_by") != 1 {
		t.Fatalf("重复补种不应产生重复字段：%s", after)
	}
}
