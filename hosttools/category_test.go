package hosttools

import "testing"

// 目录里每个工具都必须有分类：漏分类的会掉进「其他」组，页面分组就失去意义。
// 加新工具时这条测试会挡住——它会提示哪个工具没分类。
func TestEveryToolHasCategory(t *testing.T) {
	known := map[Category]bool{
		CatNetwork: true, CatWeb: true, CatDNS: true, CatCred: true,
		CatCode: true, CatPivot: true, CatOOB: true, CatExploit: true,
		CatMaterial: true, CatRuntime: true, CatMiddleware: true, CatMobile: true,
	}
	for _, tool := range catalog {
		if tool.Category == "" {
			t.Errorf("工具 %s 没有分类", tool.Name)
			continue
		}
		if !known[tool.Category] {
			t.Errorf("工具 %s 的分类 %q 不在已知分类集合里", tool.Name, tool.Category)
		}
	}
}

// 分类顺序必须覆盖全部已定义分类，且不重复——页面按 categoryOrder 渲染，
// 漏一个分类意味着该分类的工具永远不显示。
func TestCategoryOrderCoversAll(t *testing.T) {
	seen := map[Category]bool{}
	for _, c := range categoryOrder {
		if seen[c] {
			t.Errorf("categoryOrder 里 %q 重复", c)
		}
		seen[c] = true
	}
	for _, c := range []Category{
		CatNetwork, CatWeb, CatDNS, CatCred, CatCode,
		CatPivot, CatOOB, CatExploit, CatMaterial, CatRuntime, CatMiddleware,
	} {
		if !seen[c] {
			t.Errorf("分类 %q 没进 categoryOrder，页面会漏显示", c)
		}
	}
}

// 每个分类都要有标签（页面直接用标签做分组标题）。
func TestEveryCategoryHasLabel(t *testing.T) {
	for _, c := range categoryOrder {
		if CategoryLabel(c) == "" || CategoryLabel(c) == "其他" {
			t.Errorf("分类 %q 没有专属标签（拿到的是 %q）", c, CategoryLabel(c))
		}
	}
}

// 分类不是可有可无的装饰：目录里的工具应当分布在这 11 个分类里，
// 而不是全塞进一个。这个断言防止后来者把分类当成摆设。
func TestCategoriesActuallyPartitionCatalog(t *testing.T) {
	counts := map[Category]int{}
	for _, tool := range catalog {
		counts[tool.Category]++
	}
	if len(counts) < 8 {
		t.Errorf("工具只分布在 %d 个分类里（%v），分类形同虚设", len(counts), counts)
	}
	for _, c := range categoryOrder {
		if counts[c] == 0 {
			t.Errorf("分类 %q 没有任何工具——要么分类错了，要么工具没归类", c)
		}
	}
}
