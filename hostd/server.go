package hostd

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chu0119/pojun/hosttools"
	"github.com/chu0119/pojun/proxyprobe"
)

// State 任务状态。
// scriptInstallTimeout 是 script 类安装的墙钟上限。给足慢网络的空间（下载 +
// 解压 + 编译），但绝不允许无限挂起：超时后记失败，队列继续推进下一项。
const scriptInstallTimeout = "900"

type State string

const (
	StateQueued    State = "queued"
	StateRunning   State = "running"
	StateDone      State = "done"
	StateFailed    State = "failed"
	StateCancelled State = "cancelled"
)

const (
	maxLogBytes = 256 << 10 // 单个任务保留的最大日志(超出截尾)
	binDir      = "/usr/local/bin"
)

// Job 一次安装任务。
type Job struct {
	ID        string    `json:"id"`
	ToolID    string    `json:"tool_id"`
	ToolName  string    `json:"tool_name"`
	State     State     `json:"state"`
	ExitCode  int       `json:"exit_code"`
	Err       string    `json:"error,omitempty"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at,omitempty"`
	Log       string    `json:"log"`

	mu     sync.Mutex
	buf    bytes.Buffer
	cancel context.CancelFunc
}

func (j *Job) append(line string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.buf.WriteString(line)
	if j.buf.Len() > maxLogBytes {
		// 掐掉前半段,保留尾部(安装失败原因通常在最后)
		b := j.buf.Bytes()
		keep := b[len(b)-maxLogBytes:]
		j.buf.Reset()
		j.buf.WriteString("…(前段日志已截断)…\n")
		j.buf.Write(keep)
	}
	j.Log = j.buf.String()
}

func (j *Job) setState(s State) {
	j.mu.Lock()
	j.State = s
	j.mu.Unlock()
}

func (j *Job) setErr(err error) {
	if err == nil {
		return
	}
	j.mu.Lock()
	j.Err = err.Error()
	j.mu.Unlock()
}

// Server 任务管理器 + HTTP 接口。
type Server struct {
	mu     sync.Mutex
	jobs   map[string]*Job
	sem    chan struct{} // 串行执行:apt/dpkg 不允许并发
	pkgMgr PkgMgr
	logger *log.Logger
	// base 是任务的父 ctx。**绝不能**用 HTTP 请求的 ctx:handler 返回后它立刻被取消,
	// 排队中的任务会当场变成 cancelled(实测踩过)。
	base context.Context

	// Version 是助手的构建版本,SelfPath 是它自己的可执行文件(由 main 注入)。
	// 助手装在 root 拥有的 /usr/local/bin,主服务被 ProtectSystem=strict 锁死写不进去,
	// 所以「助手自身的升级」只能由助手自己做。
	Version  string
	SelfPath string

	upgrading atomic.Bool
}

// NewServer 构造。base 为进程级生命周期 ctx(随守护进程退出而取消);传 nil 用 Background。
func NewServer(base context.Context, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
	}
	if base == nil {
		base = context.Background()
	}
	return &Server{
		jobs:   map[string]*Job{},
		sem:    make(chan struct{}, 1),
		pkgMgr: DetectPkgMgr(),
		logger: logger,
		base:   base,
	}
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Start 发起一次安装。toolID 必须命中 hosttools 白名单,否则拒绝。
// parent 必须是进程级 ctx,不能传 HTTP 请求的 ctx(见 Server.base 注释)。
func (s *Server) Start(parent context.Context, toolID, proxy string) (*Job, error) {
	tool, ok := hosttools.Lookup(toolID)
	if !ok {
		return nil, fmt.Errorf("未知工具 id: %q(不在白名单内)", toolID)
	}
	if tool.Kind == hosttools.KindManual {
		return nil, fmt.Errorf("%s 官方只提供交互式安装器,不支持一键安装", tool.Name)
	}
	cleanProxy, err := ValidateProxy(proxy)
	if err != nil {
		return nil, err
	}
	if tool.AvailableInPath() {
		return nil, fmt.Errorf("%s 已安装", tool.Name)
	}

	ctx, cancel := context.WithCancel(parent)
	j := &Job{
		ID: newID(), ToolID: tool.ID, ToolName: tool.Name,
		State: StateQueued, StartedAt: time.Now(), cancel: cancel,
	}
	s.mu.Lock()
	s.jobs[j.ID] = j
	s.mu.Unlock()

	s.logger.Printf("[audit] install start job=%s tool=%s proxy=%q", j.ID, tool.ID, cleanProxy)
	go func() {
		defer cancel()
		s.sem <- struct{}{}
		defer func() { <-s.sem }()
		if ctx.Err() != nil {
			j.setState(StateCancelled)
			j.append("[cancel] 任务在排队时被取消\n")
			return
		}
		j.setState(StateRunning)
		code, err := s.run(ctx, j, tool, cleanProxy)
		j.mu.Lock()
		j.ExitCode = code
		j.EndedAt = time.Now()
		j.mu.Unlock()
		switch {
		case ctx.Err() != nil:
			j.setState(StateCancelled)
			j.append("[cancel] 已取消\n")
		case err != nil:
			j.setErr(err)
			j.setState(StateFailed)
			j.append(fmt.Sprintf("[fail] %v\n", err))
		default:
			j.setState(StateDone)
			j.append("[ok] 安装完成\n")
		}
		s.logger.Printf("[audit] install end job=%s tool=%s state=%s exit=%d err=%v",
			j.ID, tool.ID, j.State, code, err)
	}()
	return j, nil
}

// Get 取任务快照。
func (s *Server) Get(id string) (*Job, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	return j, ok
}

// List 全部任务(新→旧)。
func (s *Server) List() []*Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Job, 0, len(s.jobs))
	for _, j := range s.jobs {
		out = append(out, j)
	}
	return out
}

// Cancel 取消任务。
func (s *Server) Cancel(id string) bool {
	s.mu.Lock()
	j, ok := s.jobs[id]
	s.mu.Unlock()
	if !ok {
		return false
	}
	if j.cancel != nil {
		j.cancel()
		return true
	}
	return false
}

// ── 执行 ─────────────────────────────────────────

// run 按配方执行,返回退出码与错误。
func (s *Server) run(ctx context.Context, j *Job, tool hosttools.Tool, proxy string) (int, error) {
	switch tool.Kind {
	case hosttools.KindApt:
		return s.runApt(ctx, j, tool, proxy)
	case hosttools.KindGitHub:
		return s.runGitHub(ctx, j, tool, proxy)
	case hosttools.KindPip:
		return s.runPip(ctx, j, tool, proxy)
	case hosttools.KindScript:
		// 所有 script 类安装统一套 wall-clock 超时：catalog 的脚本里包含 GitHub/
		// 镜像下载，网络窗口差时 curl 没有内建超时会无限等待，把串行安装队列卡死
		// （实测 jadx 的 release 下载阻塞 install-all 15 分钟以上）。
		// timeout 命令来自 coreutils，Debian/Kali 默认自带；不存在时退回无超时。
		limit := scriptInstallTimeout
		if _, err := exec.LookPath("timeout"); err == nil {
			return s.execLogged(ctx, j, "timeout", []string{limit, "/bin/sh", "-c", tool.Script}, proxyEnv(proxy))
		}
		return s.execLogged(ctx, j, "/bin/sh", []string{"-c", tool.Script}, proxyEnv(proxy))
	}
	return 1, fmt.Errorf("不支持的安装方式: %s", tool.Kind)
}

// execLogged 执行一条命令,输出实时追加到任务日志。
func (s *Server) execLogged(ctx context.Context, j *Job, name string, argv []string, env []string) (int, error) {
	j.append(fmt.Sprintf("$ %s %s\n", name, strings.Join(argv, " ")))
	cmd := exec.CommandContext(ctx, name, argv...)
	cmd.Env = append(os.Environ(), env...)
	w := &logWriter{j: j}
	cmd.Stdout, cmd.Stderr = w, w
	err := cmd.Run()
	if ctx.Err() != nil {
		return -1, ctx.Err()
	}
	if err == nil {
		return 0, nil
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), fmt.Errorf("%s 退出码 %d", name, ee.ExitCode())
	}
	return 1, err
}

type logWriter struct{ j *Job }

func (w *logWriter) Write(p []byte) (int, error) {
	w.j.append(string(p))
	return len(p), nil
}

func (s *Server) runApt(ctx context.Context, j *Job, tool hosttools.Tool, proxy string) (int, error) {
	if s.pkgMgr == PkgNone {
		return 1, fmt.Errorf("本机未检测到 apt/dnf")
	}
	// 先刷新索引;失败不致命(可能只是某个源不可达),继续尝试安装
	if code, err := s.execLogged(ctx, j, firstWord(aptUpdateArgv(s.pkgMgr, proxy)),
		aptUpdateArgv(s.pkgMgr, proxy)[1:], []string{"DEBIAN_FRONTEND=noninteractive"}); err != nil {
		j.append(fmt.Sprintf("[warn] 索引刷新失败(退出码 %d),继续尝试安装\n", code))
	}
	argv, err := aptArgv(tool, s.pkgMgr, proxy)
	if err != nil {
		return 1, err
	}
	return s.execLogged(ctx, j, argv[0], argv[1:], []string{"DEBIAN_FRONTEND=noninteractive"})
}

func (s *Server) runPip(ctx context.Context, j *Job, tool hosttools.Tool, proxy string) (int, error) {
	argv := pipArgv(tool, proxy)
	code, err := s.execLogged(ctx, j, argv[0], argv[1:], proxyEnv(proxy))
	if err == nil {
		return code, nil
	}
	// 网络抖动重试两层：
	// 1) 原样重试 1 次（PyPI 连接重置是常态——实测 kube-hunter 手动第二次即成功，
	//    旧实现只重试一次 --ignore-installed，恰好落在抖动窗口里就漏装）；
	// 2) 仍失败再换 --ignore-installed（Debian/Ubuntu 的 dist-packages 没有 RECORD
	//    文件，pip 卸载会报 uninstall-no-record-file）。
	for attempt := 1; attempt <= 2; attempt++ {
		j.append(fmt.Sprintf("[warn] pip 安装失败，%ds 后重试（第 %d/2 次）\n", attempt*5, attempt))
		select {
		case <-ctx.Done():
			return code, err
		case <-time.After(time.Duration(attempt*5) * time.Second):
		}
		code, err = s.execLogged(ctx, j, argv[0], argv[1:], proxyEnv(proxy))
		if err == nil {
			return code, nil
		}
	}
	j.append("[warn] pip 仍失败，改用 --ignore-installed 重试\n")
	argv = appendIgnoreInstalled(argv)
	return s.execLogged(ctx, j, argv[0], argv[1:], proxyEnv(proxy))
}

// appendIgnoreInstalled 在 pip 的 install 子命令后插入 --ignore-installed。
func appendIgnoreInstalled(argv []string) []string {
	out := make([]string, 0, len(argv)+1)
	for _, a := range argv {
		out = append(out, a)
		if a == "install" {
			out = append(out, "--ignore-installed")
		}
	}
	return out
}

// proxyEnv 把已校验的代理注入子进程环境，供 curl/git/pip/gem 等脚本使用。
func proxyEnv(proxy string) []string {
	env := []string{
		"PIP_DISABLE_PIP_VERSION_CHECK=1",
		"DEBIAN_FRONTEND=noninteractive",
		// hostd 的 ProtectHome=true 会让 /root 不可写；pip/gem 默认把缓存写 HOME。
		"HOME=/var/lib/pojun-hostd",
		"XDG_CACHE_HOME=/var/cache/pojun-hostd",
		"PIP_CACHE_DIR=/var/cache/pojun-hostd/pip",
	}
	if proxy == "" {
		return env
	}
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		env = append(env, k+"="+proxy)
	}
	return append(env, "NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost")
}

// runGitHub 从 GitHub Release 取单文件二进制并装到 /usr/local/bin。
func (s *Server) runGitHub(ctx context.Context, j *Job, tool hosttools.Tool, proxy string) (int, error) {
	client := httpClient(proxy)

	j.append(fmt.Sprintf("[*] 解析 %s 最新版本…\n", tool.Repo))
	tag, err := latestTag(ctx, client, GitHubAPITagURL(tool))
	if err != nil {
		return 1, fmt.Errorf("解析最新版本失败(可配置安装代理后重试): %w", err)
	}
	u := GitHubAssetURL(tool, tag)
	j.append(fmt.Sprintf("[*] 下载 %s\n", u))

	var blob []byte
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		req.Header.Set("User-Agent", "pojun-hostd")
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			blob, err = io.ReadAll(io.LimitReader(resp.Body, 128<<20))
			resp.Body.Close()
			if err == nil && len(blob) > 0 {
				lastErr = nil
				break
			}
		} else if err == nil {
			err = fmt.Errorf("HTTP %d", resp.StatusCode)
			resp.Body.Close()
		}
		lastErr = err
		if attempt < 3 {
			j.append(fmt.Sprintf("[warn] 下载失败（%v），%d 秒后重试…\n", err, attempt*2))
			select {
			case <-ctx.Done():
				return 1, ctx.Err()
			case <-time.After(time.Duration(attempt*2) * time.Second):
			}
		}
	}
	if lastErr != nil {
		return 1, fmt.Errorf("下载失败: %w", lastErr)
	}
	j.append(fmt.Sprintf("[*] 已下载 %.1f MB,解压…\n", float64(len(blob))/(1<<20)))

	// 归档格式各家不一：ProjectDiscovery 系是 .zip，gitleaks/chisel/amass 是
	// .tar.gz 或 .gz，feroxbuster 是 .tar.gz。按内容嗅探决定走哪条解压路径，
	// 而不是靠资产名的后缀猜（后缀拼错就直接装不上）。
	return installFromArchive(j, blob, tool)
}

// installFromArchive 从归档里取出目标二进制装到 /usr/local/bin。
// 支持 zip / tar(.gz) / 单文件 gz 三种形态。
func installFromArchive(j *Job, blob []byte, tool hosttools.Tool) (int, error) {
	if tool.Raw {
		return installBinary(j, tool, blob)
	}
	want := tool.BinInZip
	if want == "" {
		want = tool.Bin
	}
	// zip: PK\x03\x04
	if len(blob) > 4 && blob[0] == 'P' && blob[1] == 'K' {
		zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
		if err != nil {
			return 1, fmt.Errorf("压缩包无法解析: %w", err)
		}
		return installFromZip(j, zr, tool)
	}
	// gzip: \x1f\x8b
	if len(blob) > 2 && blob[0] == 0x1f && blob[1] == 0x8b {
		gr, err := gzip.NewReader(bytes.NewReader(blob))
		if err != nil {
			return 1, fmt.Errorf("gzip 无法解析: %w", err)
		}
		defer gr.Close()
		// 单文件 gz（内部就是那个二进制）或 tar.gz
		raw, err := io.ReadAll(io.LimitReader(gr, 256<<20))
		if err != nil {
			return 1, err
		}
		// 可能是 tar.gz（多个条目），也可能是单文件 gz（内部就是那个二进制）。
		// 用「能否在 tar 流里找到目标文件」区分：找到就装 tar 里的那个，
		// 找不到就把解压结果整体当成那个二进制。
		if data, ok := findInTar(raw, tool); ok {
			return installBinary(j, tool, data)
		}
		return installBinary(j, tool, raw)
	}
	// 纯 tar
	if data, ok := findInTar(blob, tool); ok {
		return installBinary(j, tool, data)
	}
	return 1, fmt.Errorf("无法识别的归档格式")
}

// findInTar 在 tar（tar.gz 解压后）里找目标二进制的内容。
// 找不到返回 ok=false——调用方据此回退到「整个文件就是那个二进制」。
func findInTar(blob []byte, tool hosttools.Tool) ([]byte, bool) {
	want := tool.BinInZip
	if want == "" {
		want = tool.Bin
	}
	tr := tar.NewReader(bytes.NewReader(blob))
	for {
		hdr, err := tr.Next()
		if err != nil {
			return nil, false
		}
		if hdr.Typeflag != tar.TypeReg || path.Base(hdr.Name) != want {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, 256<<20))
		if err != nil {
			return nil, false
		}
		return data, true
	}
}

// installBinary 把二进制内容原子地装到 /usr/local/bin。
func installBinary(j *Job, tool hosttools.Tool, data []byte) (int, error) {
	want := tool.BinInZip
	if want == "" {
		want = tool.Bin
	}
	dst := tool.DestPath
	if dst == "" {
		dst = filepath.Join(binDir, tool.Bin)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return 1, fmt.Errorf("创建目录失败: %w", err)
	}
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return 1, fmt.Errorf("写入 %s 失败: %w", tmp, err)
	}
	if _, err := out.Write(data); err != nil {
		out.Close()
		os.Remove(tmp)
		return 1, err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return 1, err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		os.Remove(tmp)
		return 1, err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return 1, err
	}
	j.append(fmt.Sprintf("[ok] %s → %s\n", want, dst))
	return 0, nil
}

func installFromZip(j *Job, zr *zip.Reader, tool hosttools.Tool) (int, error) {
	want := tool.BinInZip
	if want == "" {
		want = tool.Bin
	}
	for _, f := range zr.File {
		if path.Base(f.Name) != want || f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return 1, err
		}
		defer rc.Close()
		dst := tool.DestPath
		if dst == "" {
			dst = filepath.Join(binDir, tool.Bin)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return 1, fmt.Errorf("创建目录失败: %w", err)
		}
		tmp := dst + ".tmp"
		out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return 1, fmt.Errorf("写入 %s 失败: %w", tmp, err)
		}
		if _, err := io.Copy(out, io.LimitReader(rc, 256<<20)); err != nil {
			out.Close()
			os.Remove(tmp)
			return 1, err
		}
		if err := out.Close(); err != nil {
			os.Remove(tmp)
			return 1, err
		}
		if err := os.Chmod(tmp, 0o755); err != nil {
			os.Remove(tmp)
			return 1, err
		}
		if err := os.Rename(tmp, dst); err != nil {
			os.Remove(tmp)
			return 1, err
		}
		j.append(fmt.Sprintf("[ok] %s → %s\n", want, dst))
		return 0, nil
	}
	return 1, fmt.Errorf("压缩包里找不到二进制 %q", want)
}

// ── 辅助 ─────────────────────────────────────────

func firstWord(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	return argv[0]
}

// httpClient 构造带代理的 HTTP 客户端。
//
// socks5 必须走 golang.org/x/net/proxy 的 SOCKS5 dialer：
// http.ProxyURL 只懂 HTTP CONNECT 代理，喂它 socks5:// 会得到
// "unsupported protocol scheme" —— 表现为「填了 socks 代理但下载照样失败」，
// 而用户完全看不出是协议不匹配。
//
// 客户端构造统一走 proxyprobe 包：运行期的自测 API 用的是同一套逻辑，
// 避免出现「装机说代理通了、运行期却连不上」的口径割裂。
func httpClient(proxy string) *http.Client {
	c, err := proxyprobe.ClientFor(proxy, 10*time.Minute)
	if err != nil {
		// 代理串不合法时退回直连：让安装继续，错误由调用方在日志里报出来，
		// 而不是整个客户端建不起来。
		return &http.Client{Timeout: 10 * time.Minute, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
	}
	return c
}

func latestTag(ctx context.Context, client *http.Client, apiURL string) (string, error) {
	// 通道 1：GitHub API。共享出口 IP 常被 403 限流（Kali 实测 5 个 PD 工具全挂在这）。
	tag, apiErr := latestTagViaAPI(ctx, client, apiURL)
	if apiErr == nil && tag != "" {
		return tag, nil
	}
	// 通道 2：releases/latest 的 302 Location——浏览器同款路径，不消耗 API 配额。
	// apiURL 形如 https://api.github.com/repos/<owner>/<repo>/releases/latest。
	if repo, ok := strings.CutPrefix(apiURL, "https://api.github.com/repos/"); ok {
		repo, _ = strings.CutSuffix(repo, "/releases/latest")
		if repo != "" {
			if tag, err := latestTagViaRedirect(ctx, client, "https://github.com/"+repo+"/releases/latest"); err == nil && tag != "" {
				return tag, nil
			}
		}
	}
	return "", apiErr
}

func latestTagViaAPI(ctx context.Context, client *http.Client, apiURL string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "pojun-hostd")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API HTTP %d", resp.StatusCode)
	}
	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return "", err
	}
	if payload.TagName == "" {
		return "", fmt.Errorf("响应里没有 tag_name")
	}
	return payload.TagName, nil
}

// latestTagViaRedirect 不跟随重定向，从 Location 路径末尾取 tag。
func latestTagViaRedirect(ctx context.Context, client *http.Client, url string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "pojun-hostd")
	// 不跟随：拿到 302 的 Location 即可（跟随后会落到 release 页 HTML）。
	noFollow := *client
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noFollow.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", fmt.Errorf("HTTP %d 且无 Location", resp.StatusCode)
	}
	if i := strings.LastIndex(loc, "/tag/"); i >= 0 {
		tag := strings.TrimSuffix(loc[i+len("/tag/"):], "/")
		if tag != "" {
			return tag, nil
		}
	}
	return "", fmt.Errorf("Location 里没有 tag: %s", loc)
}

// ── HTTP ─────────────────────────────────────────

// Handler 返回挂在 Unix socket 上的 mux。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"ok": true, "service": "pojun-hostd",
			"version": s.Version,
			"pkg_mgr": string(s.pkgMgr),
			"tools":   len(hosttools.Inventory()),
		})
	})

	// /version 供主服务做版本对齐：主程序自我升级后会拿自己的版本号来敲门，
	// 助手发现自己落后就自我换装（见 UpgradeSelf 的注释：只能由它自己来做）。
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"service": "pojun-hostd", "version": s.Version})
	})

	mux.HandleFunc("POST /self-upgrade", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Tag   string `json:"tag"`
			Proxy string `json:"proxy"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]any{"error": "请求体不是合法 JSON"})
			return
		}
		if !ValidVersionTag(req.Tag) {
			writeJSON(w, 400, map[string]any{"error": "版本号格式非法: " + req.Tag})
			return
		}
		cleanProxy, err := ValidateProxy(req.Proxy)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		if !s.upgrading.CompareAndSwap(false, true) {
			writeJSON(w, 409, map[string]any{"error": "已有一个自我换装在进行中"})
			return
		}
		writeJSON(w, 202, map[string]any{"ok": true, "target": req.Tag})
		// 用进程级 ctx：请求一返回它就被取消，下载会当场中断（同一课踩过一次）。
		go func() {
			if err := s.UpgradeSelf(s.base, req.Tag, cleanProxy); err != nil {
				log.Printf("[hostd] 自我换装失败：%v", err)
				s.upgrading.Store(false)
				return
			}
			log.Printf("[hostd] 已换装到 %s，退出由 systemd 重启", req.Tag)
			// 留一点时间把日志刷出去再退；Restart=always 会把新版本拉起来。
			time.Sleep(300 * time.Millisecond)
			os.Exit(0)
		}()
	})

	mux.HandleFunc("GET /tools", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"tools": hosttools.Inventory()})
	})

	mux.HandleFunc("POST /jobs", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ToolID string `json:"tool_id"`
			Proxy  string `json:"proxy"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]any{"error": "请求体不是合法 JSON"})
			return
		}
		job, err := s.Start(s.base, req.ToolID, req.Proxy)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 201, job)
	})

	mux.HandleFunc("GET /jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		job, ok := s.Get(r.PathValue("id"))
		if !ok {
			writeJSON(w, 404, map[string]any{"error": "任务不存在"})
			return
		}
		writeJSON(w, 200, job)
	})

	mux.HandleFunc("POST /jobs/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		if !s.Cancel(r.PathValue("id")) {
			writeJSON(w, 404, map[string]any{"error": "任务不存在"})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	})

	return mux
}

// Listen 建立 Unix socket 并设置权限(仅属主/属组可读写,杜绝本机其它用户触发安装)。
func Listen(socketPath string, mode os.FileMode, group string) (net.Listener, error) {
	_ = os.Remove(socketPath)
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socketPath, mode); err != nil {
		ln.Close()
		return nil, err
	}
	if group != "" {
		if g, err := lookupGID(group); err == nil {
			if err := os.Chown(socketPath, 0, g); err != nil {
				ln.Close()
				return nil, err
			}
		} else {
			ln.Close()
			return nil, fmt.Errorf("找不到属组 %q: %w", group, err)
		}
	}
	return ln, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// lookupGID 把属组名解析成 gid。
func lookupGID(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}
