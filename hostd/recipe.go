// Package hostd:POJUN 的特权安装助手(pojun-hostd)。
//
// 为什么需要它:主服务 systemd 单元带 NoNewPrivileges=true + ProtectSystem=strict
// + CapabilityBoundingSet=CAP_NET_BIND_SERVICE,进程无法提权、/usr 只读——所以
// 「一键安装」不可能由 Web 服务自己完成。hostd 以 root 常驻,只经一个 Unix socket
// 接受请求,且**只认 hosttools 白名单里的工具 id**,永远不接受自由命令。
//
// 攻击面收敛:无 TCP 端口(仅 AF_UNIX);socket 0600/0660 且归属运行用户;每个动作
// 都由 catalog 的固定 argv 拼出,代理地址经 URL 校验;所有执行的命令落审计日志。
package hostd

import (
	"fmt"
	"net/url"
	"os"
	"os/user"
	"strings"

	"github.com/chu0119/pojun/hosttools"
)

// PkgMgr 系统包管理器。
type PkgMgr string

const (
	PkgApt  PkgMgr = "apt"
	PkgDnf  PkgMgr = "dnf"
	PkgNone PkgMgr = ""
)

// DetectPkgMgr 探测本机包管理器(只认这两个;其它发行版走 GitHub/pip 配方)。
func DetectPkgMgr() PkgMgr {
	for _, p := range []struct {
		mgr  PkgMgr
		path string
	}{{PkgApt, "/usr/bin/apt-get"}, {PkgApt, "/usr/local/bin/apt-get"}, {PkgDnf, "/usr/bin/dnf"}} {
		if st, err := os.Stat(p.path); err == nil && !st.IsDir() {
			return p.mgr
		}
	}
	return PkgNone
}

// ValidateProxy 校验代理地址。只允许 http/https/socks5,且必须有 host:port——
// 因为代理串会作为 argv/env 传给 apt/子进程,必须挡住换行/空格等注入面。
func ValidateProxy(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if strings.ContainsAny(raw, "\n\r\t ") {
		return "", fmt.Errorf("代理地址含非法空白字符")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("代理地址无法解析: %v", err)
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return "", fmt.Errorf("代理仅支持 http/https/socks5,收到 %q", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("代理地址缺少 host:port")
	}
	return raw, nil
}

// APTProxyArgs 把代理转成 apt 的 Acquire 选项(不设全局 apt.conf,避免持久污染)。
func APTProxyArgs(proxy string) []string {
	if proxy == "" {
		return nil
	}
	return []string{
		"-o", "Acquire::http::Proxy=" + proxy,
		"-o", "Acquire::https::Proxy=" + proxy,
	}
}

// aptArgv 构造 apt 安装命令。pkg 来自 catalog(非用户输入),proxy 已校验。
func aptArgv(tool hosttools.Tool, mgr PkgMgr, proxy string) ([]string, error) {
	var pkg string
	switch mgr {
	case PkgApt:
		pkg = tool.Apt
	case PkgDnf:
		pkg = tool.Dnf
	default:
		return nil, fmt.Errorf("%s 需要系统包管理器(apt/dnf),本机未检测到", tool.Name)
	}
	if pkg == "" {
		return nil, fmt.Errorf("%s 没有适配本机包管理器的包名", tool.Name)
	}
	// 一个工具可能对应多个系统包（如 LibreOffice 三组件），包名字段允许空格分隔。
	pkgs := strings.Fields(pkg)
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("%s 没有适配本机包管理器的包名", tool.Name)
	}
	if mgr == PkgApt {
		argv := append([]string{"apt-get"}, APTProxyArgs(proxy)...)
		argv = append(argv, "install", "-y")
		return append(argv, pkgs...), nil
	}
	argv := []string{"dnf"}
	if proxy != "" {
		argv = append(argv, "--setopt=proxy="+proxy)
	}
	argv = append(argv, "install", "-y")
	return append(argv, pkgs...), nil
}

// aptUpdateArgv apt 索引刷新(apt 源随时间失效,装之前先 update 一次)。
func aptUpdateArgv(mgr PkgMgr, proxy string) []string {
	if mgr == PkgApt {
		argv := append([]string{"apt-get"}, APTProxyArgs(proxy)...)
		return append(argv, "update")
	}
	return []string{"dnf", "makecache"}
}

// pipArgv 构造 pip 安装命令。
//
// 两种模式：
//
//   - **纯库**（tool.PipLibrary=true）：走 `python3 -m pip install`。pipx 装不了
//     纯库——它会报 "No apps associated with package X ... pipx should not be
//     used"（2026-10-22 在 Kali 上实测：gmqtt/pika/pymongo/zeep 全部这样失败）。
//     用 --break-system-packages 是为了绕开 PEP668 的 externally-managed 限制
//     （Debian/Ubuntu/Kali 的系统 Python 都带这个标记）。
//
//   - **有 CLI 入口**（默认）：优先 pipx。隔离环境不污染系统 Python，正是
//     我们想要的；没有 pipx 就回落到 pip。
//
// tool.Pip 可以是**空格分隔的多个包**（中间件类工具常需一组库）。按空格拆成
// 多个 argv 元素——不拆的话 "pika amqpstorm" 会被当成一个包名，装不上。
func pipArgv(tool hosttools.Tool, proxy string) []string {
	pkgs := strings.Fields(tool.Pip)
	if len(pkgs) == 0 {
		pkgs = []string{tool.Name}
	}
	if !tool.PipLibrary {
		if _, err := os.Stat("/usr/bin/pipx"); err == nil {
			argv := []string{"pipx", "install"}
			// root 下必须 --global：否则入口脚本落 /root/.local/bin，
			// 服务用户 pojun 既穿不过 /root 也不在 PATH（install.sh 同款坑）。
			if runningAsRoot() {
				argv = append(argv, "--global")
			}
			pipArgs := "--no-cache-dir"
			if proxy != "" {
				pipArgs += " --proxy=" + proxy
			}
			argv = append(argv, "--pip-args="+pipArgs)
			return append(argv, pkgs...)
		}
	}
	argv := []string{"python3", "-m", "pip", "install", "--break-system-packages", "--no-cache-dir"}
	if proxy != "" {
		argv = append(argv, "--proxy", proxy)
	}
	return append(argv, pkgs...)
}

// GitHubAssetURL 由资产模板拼出下载地址。tag 形如 v3.4.10,资产名里不带 v。
//
// 模板占位符：
//
//	{ver}   版本号（不带 v），如 3.4.10
//	{verv}  版本号（带 v），如 v3.4.10
//	{arch}  架构，amd64 / arm64（Go 的 GOARCH 写法）
//	{arch2} 架构，x86_64 / aarch64（部分项目用这套，如 gitleaks/amass）
//	{arch3} 架构，x86 / arm（又一套，如 chisel 的部分资产）
//	{arch4}  架构，x64 / arm64（gitleaks 用这套）
//	{arch5}  架构，64bit / ARM64（trivy 用这套）
//
// 各项目的资产命名差异很大（架构在前/后、版本带不带 v、扩展名 .zip/.tar.gz/.gz），
// 所以模板必须能覆盖这些差异，否则「一键安装」只能对着一半项目有效。
func GitHubAssetURL(tool hosttools.Tool, tag string) string {
	ver := strings.TrimPrefix(tag, "v")
	asset := strings.ReplaceAll(tool.AssetTmpl, "{ver}", ver)
	asset = strings.ReplaceAll(asset, "{verv}", tag)
	asset = strings.ReplaceAll(asset, "{arch}", hosttools.Arch())
	asset = strings.ReplaceAll(asset, "{arch2}", hosttools.ArchAlt())
	asset = strings.ReplaceAll(asset, "{arch3}", hosttools.ArchShort())
	asset = strings.ReplaceAll(asset, "{arch4}", hosttools.ArchX64())
	asset = strings.ReplaceAll(asset, "{arch5}", hosttools.ArchLong())
	return fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", tool.Repo, tag, asset)
}

// GitHubAPITagURL 取最新 tag 的 API 地址。
func GitHubAPITagURL(tool hosttools.Tool) string {
	return fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", tool.Repo)
}

// runningAsRoot 判断当前宿主进程是否 root。hostd 由 systemd 以 root 启动；
// 非 root 时 pipx 不加 --global（保持用户级安装语义）。
func runningAsRoot() bool {
	u, err := user.Current()
	return err == nil && u.Uid == "0"
}
