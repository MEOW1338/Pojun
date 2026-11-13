package hosttools

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInventoryCoversCatalog(t *testing.T) {
	inv := Inventory()
	// 目录项数会随工具增补变化，这里只断言「不低于基线」并逐项检查字段完整性。
	if len(inv) < 22 {
		t.Fatalf("目录不应少于 22 项,得到 %d", len(inv))
	}
	// curl 在任何测试环境都该存在(Git/CI 镜像自带),用它验证探测为真
	foundCurl := false
	for _, t2 := range inv {
		if t2.Bin == "" {
			t.Errorf("%s: Bin 未回填", t2.Name)
		}
		if t2.Name == "curl" {
			foundCurl = true
			if !t2.Available {
				t.Error("curl 应被探测为可用")
			}
			if t2.Install != "" {
				t.Error("可用工具不应带安装提示")
			}
		}
	}
	if !foundCurl {
		t.Fatal("目录里没有 curl")
	}
}

func TestSummaryShape(t *testing.T) {
	s := Summary()
	avail, ok := s["available"].([]string)
	if !ok || len(avail) == 0 {
		t.Fatalf("available 应为非空字符串数组: %#v", s["available"])
	}
	// missing 只给名字：安装提示是给人看的（宿主环境页），模型既不能装
	// 也不需要知道怎么装，给它几十条安装命令只是每轮都在烧上下文。
	missing, ok := s["missing"].([]string)
	if !ok {
		t.Fatalf("missing 类型不对: %#v", s["missing"])
	}
	for _, m := range missing {
		if m == "" {
			t.Error("缺失项不应为空串")
		}
	}
	// available 每项都要带用途：模型只看到名字就用不对工具。
	for _, a := range avail {
		if !strings.Contains(a, ": ") {
			t.Errorf("available 项 %q 应带用途", a)
		}
	}
	if s["hint"] == "" {
		t.Fatal("hint 不能为空")
	}
}

func TestSummaryTextMarksAvailability(t *testing.T) {
	// 用一个临时 PATH 只含空目录,让全部工具缺失(不依赖环境)
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	txt := SummaryText()
	// PATH 类工具在空 PATH 下必然缺失；但 python:module 检测类工具（kombu/pymysql/redis）
	// 走 python3 -c import，不受 PATH 影响——只要本机装了模块就会显示可用。
	// 这里只断言 PATH 类工具不出现（按名匹配），不强求整串为空。
	for _, name := range []string{"curl", "nmap"} {
		if strings.Contains(txt, "✓ "+name+" ") || strings.Contains(txt, "✓ "+name+"\n") {
			t.Errorf("空 PATH 下不应出现 PATH 类工具 %s: %s", name, txt)
		}
	}
	// 有工具时必须带用途 —— 只给名字的话模型判断不出该在什么场景调哪个。
	dir2 := t.TempDir()
	fake := dir2 + string(os.PathSeparator) + "curl"
	if runtime.GOOS == "windows" {
		fake += ".exe"
	}
	if err := os.WriteFile(fake, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir2)
	txt2 := SummaryText()
	if !strings.Contains(txt2, "curl") {
		t.Errorf("有工具时应列出 curl: %s", txt2)
	}
	if !strings.Contains(txt2, "HTTP") {
		t.Errorf("可用项应带用途: %s", txt2)
	}
	if strings.Contains(txt2, "nmap") {
		t.Errorf("缺失的工具不该出现在清单里: %s", txt2)
	}
	// 放一个假 curl 进 PATH,应翻成可用(Windows 下 LookPath 只认 .exe 等可执行扩展)
	name := "curl"
	if runtime.GOOS == "windows" {
		name = "curl.exe"
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	txt = SummaryText()
	if !containsAll(txt, "✓ curl") {
		t.Errorf("假 curl 应被标记可用: %s", txt)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
