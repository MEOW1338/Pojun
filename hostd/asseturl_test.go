package hostd

import (
	"strings"
	"testing"

	"github.com/chu0119/pojun/hosttools"
)

// 各项目的 release 资产命名规范极不统一（架构在前/后、版本带不带 v、
// 扩展名 .zip/.tar.gz/.gz、架构名有 amd64/x86_64/x86/x64 四套）。
// 模板拼错的后果是「一键安装」下载 404，而用户只看到安装失败。
//
// 这里的断言值是 2026-10 实测 GitHub API 得到的真实资产名。
func TestAssetURLMatchesRealReleaseNames(t *testing.T) {
	cases := []struct {
		id   string
		tag  string
		want string
	}{
		{
			"nuclei", "v3.4.10",
			"https://github.com/projectdiscovery/nuclei/releases/download/v3.4.10/nuclei_3.4.10_linux_amd64.zip",
		},
		{
			"gitleaks", "v8.30.1",
			"https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
		},
		{
			"chisel", "v1.12.0",
			"https://github.com/jpillora/chisel/releases/download/v1.12.0/chisel_1.12.0_linux_amd64.gz",
		},
		{
			// amass 的资产名里没有版本号
			"amass", "v5.1.1",
			"https://github.com/OWASP/Amass/releases/download/v5.1.1/amass_linux_amd64.tar.gz",
		},
		{
			// dalfox 带 v 前缀、架构用 x86_64
			"dalfox", "v3.2.4",
			"https://github.com/hahwul/dalfox/releases/download/v3.2.4/dalfox-v3.2.4-linux-x86_64.tar.gz",
		},
		{
			// feroxbuster 架构在前
			"feroxbuster", "v2.13.1",
			"https://github.com/epi052/feroxbuster/releases/download/v2.13.1/x86_64-linux-feroxbuster.tar.gz",
		},
		{
			"notify", "v1.0.7",
			"https://github.com/projectdiscovery/notify/releases/download/v1.0.7/notify_1.0.7_linux_amd64.zip",
		},
		{
			"interactsh-client", "v1.4.1",
			"https://github.com/projectdiscovery/interactsh/releases/download/v1.4.1/interactsh-client_1.4.1_linux_amd64.zip",
		},
	}
	for _, c := range cases {
		tool, ok := hosttools.Lookup(c.id)
		if !ok {
			t.Errorf("%s 不在 catalog 里", c.id)
			continue
		}
		got := GitHubAssetURL(tool, c.tag)
		if got != c.want {
			t.Errorf("%s URL 不对:\n  得到 %s\n  期望 %s", c.id, got, c.want)
		}
	}
}

// 模板里不能有未实现的占位符——拼出来会带上字面量 "{archX}"，下载必然 404。
func TestNoUnknownPlaceholdersInTemplates(t *testing.T) {
	known := map[string]bool{
		"{ver}": true, "{verv}": true,
		"{arch}": true, "{arch2}": true, "{arch3}": true, "{arch4}": true, "{arch5}": true,
	}
	for _, tool := range hosttools.Catalog() {
		if tool.Kind != hosttools.KindGitHub {
			continue
		}
		for _, seg := range strings.Split(tool.AssetTmpl, "{")[1:] {
			end := strings.Index(seg, "}")
			if end < 0 {
				t.Errorf("%s 的模板 %q 里有未闭合的占位符", tool.Name, tool.AssetTmpl)
				continue
			}
			ph := "{" + seg[:end] + "}"
			if !known[ph] {
				t.Errorf("%s 的模板 %q 用了未知占位符 %s", tool.Name, tool.AssetTmpl, ph)
			}
		}
	}
}

// 每个 GitHub 配方都必须有 Repo 与资产模板，否则装不了。
func TestGitHubRecipesAreComplete(t *testing.T) {
	for _, tool := range hosttools.Catalog() {
		if tool.Kind != hosttools.KindGitHub {
			continue
		}
		if tool.Repo == "" {
			t.Errorf("%s 缺 Repo", tool.Name)
		}
		if tool.AssetTmpl == "" {
			t.Errorf("%s 缺 AssetTmpl", tool.Name)
		}
		if tool.Bin == "" {
			t.Errorf("%s 缺 Bin", tool.Name)
		}
	}
}
