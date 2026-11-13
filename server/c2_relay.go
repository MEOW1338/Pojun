// C2 出口配置（可选功能）：解决「回连地址怎么填」的问题。两种网络形态：
//
//	direct —— POJUN 主机与目标网络可达（本机有公网或同内网）：LHOST 用本机
//	          网卡地址（net_context 已有），LPORT = 监听端口。
//	ssh    —— POJUN 主机无公网，用户有一台公网中转机：POJUN 自动建立 SSH
//	          反向隧道（ssh -R 中转端口→本机监听端口），LHOST/LPORT 用中转机
//	          的公网地址。隧道由平台托管（断线重连），监听器停止时拆除。
//	manual —— 用户已手工在公网机上配好端口转发：平台只负责在回连信息里
//	          展示中转地址，不管理隧道。
//
// 全部可选项：不配置时等价 direct（回退到 net_context 的本机地址）。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// netInterfaceAddrs 列出指定网卡的地址（CIDR 形态）。
func netInterfaceAddrs(name string) ([]string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out, nil
}

// netDialUDP 建一条不出包的 UDP「连接」用于取默认路由源地址。
func netDialUDP(target string) (*net.UDPConn, error) {
	raddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return nil, err
	}
	return net.DialUDP("udp", nil, raddr)
}

// C2 出口设置键。
const (
	settingC2RelayMode  = "c2_relay_mode"  // direct | ssh | manual（默认 direct）
	settingC2RelayHost  = "c2_relay_host"  // 中转机公网地址（回连 LHOST）
	settingC2RelaySSH   = "c2_relay_ssh"   // SSH 反向隧道目标 "user@host:port"
	settingC2RelayPass  = "c2_relay_pass"  // SSH 密码（空=走 key）；脱敏回显
	settingC2RelayKey   = "c2_relay_key"   // SSH 私钥路径（可选，优先于密码）
	settingC2RelayIface = "c2_relay_iface" // direct 模式指定网卡（空=自动选默认路由网卡）
)

// ConnectBack 是给 agent 的回连参数（payload 里 LHOST/LPORT 该填什么）。
type ConnectBack struct {
	Mode  string `json:"mode"`  // direct | ssh | manual
	LHOST string `json:"lhost"` // 目标该连的地址
	LPORT int    `json:"lport"` // 目标该连的端口
	Via   string `json:"via,omitempty"`
}

// c2RelayCfg 是解析后的当前配置。
type c2RelayCfg struct {
	Mode  string
	Host  string
	SSH   string
	Pass  string
	Key   string
	Iface string
}

func (s *Server) c2RelayConfig() c2RelayCfg {
	cfg := c2RelayCfg{Mode: "direct"}
	if s.m == nil || s.m.pg == nil {
		return cfg
	}
	if v, _, _ := s.m.pg.GetSetting(settingC2RelayMode); strings.TrimSpace(v) != "" {
		cfg.Mode = strings.TrimSpace(v)
	}
	cfg.Host, _, _ = s.m.pg.GetSetting(settingC2RelayHost)
	cfg.SSH, _, _ = s.m.pg.GetSetting(settingC2RelaySSH)
	cfg.Pass, _, _ = s.m.pg.GetSetting(settingC2RelayPass)
	cfg.Key, _, _ = s.m.pg.GetSetting(settingC2RelayKey)
	cfg.Iface, _, _ = s.m.pg.GetSetting(settingC2RelayIface)
	return cfg
}

// ResolveConnectBack 把监听端口解析成目标应连的地址。
// ssh 模式：LPORT=本机监听端口（隧道按 1:1 转发到中转同号端口——规则简单，
// agent 与人工排查都不用对表）；LHOST=中转机公网地址。
func (s *Server) ResolveConnectBack(listenerPort int) ConnectBack {
	cfg := s.c2RelayConfig()
	switch strings.TrimSpace(cfg.Mode) {
	case "ssh", "manual":
		if strings.TrimSpace(cfg.Host) != "" {
			return ConnectBack{Mode: cfg.Mode, LHOST: strings.TrimSpace(cfg.Host), LPORT: listenerPort,
				Via: "中转 " + strings.TrimSpace(cfg.Host)}
		}
	}
	return ConnectBack{Mode: "direct", LHOST: s.localIPFor(cfg.Iface), LPORT: listenerPort}
}

// localIPFor 取本机出口地址（net_context 工具同款思路的精简版）：
// 指定网卡用其地址；否则拨 UDP 8.8.8.8:80 取默认路由源地址（不发包）；
// 全失败回落 127.0.0.1。
func (s *Server) localIPFor(iface string) string {
	if strings.TrimSpace(iface) != "" {
		if addrs, err := netInterfaceAddrs(iface); err == nil {
			for _, a := range addrs {
				if ip := strings.Split(a, "/")[0]; ip != "" && ip != "127.0.0.1" {
					return ip
				}
			}
		}
	}
	c, err := netDialUDP("8.8.8.8:80")
	if err == nil {
		defer func() { _ = c.Close() }()
		if addr := c.LocalAddr().String(); strings.Contains(addr, ":") {
			if ip := strings.Split(addr, ":")[0]; ip != "" {
				return ip
			}
		}
	}
	return "127.0.0.1"
}

// ── SSH 反向隧道托管 ────────────────────────────────────────────────

// relayTunnels 托管每监听器一条的 SSH 反向隧道进程。
type relayTunnels struct {
	mu      sync.Mutex
	byName  map[string]*exec.Cmd
	cancels map[string]context.CancelFunc
}

var relayTunnelMgr = &relayTunnels{byName: map[string]*exec.Cmd{}, cancels: map[string]context.CancelFunc{}}

// startRelayTunnel 为监听器建 SSH 反向隧道：中转 :port → 本机 127.0.0.1:port。
// ExitOnForwardFailure + ServerAlive 保活；进程退出由 goroutine 指数退避重连，
// 直到监听器停止（ctx 取消）。
func (s *Server) startRelayTunnel(name string, port int) error {
	cfg := s.c2RelayConfig()
	if strings.TrimSpace(cfg.SSH) == "" {
		return fmt.Errorf("ssh 中继未配置（c2_relay_ssh = user@host:port）")
	}
	userHost, sshPort := cfg.SSH, "22"
	if i := strings.LastIndex(cfg.SSH, ":"); i > 0 {
		userHost, sshPort = cfg.SSH[:i], cfg.SSH[i+1:]
	}
	key, pass := strings.TrimSpace(cfg.Key), strings.TrimSpace(cfg.Pass)
	// 每次重连都重建 Cmd：exec.Cmd 用过之后不可复用（也不能按值拷贝）。
	build := func() *exec.Cmd {
		args := []string{
			"-N", "-T",
			"-o", "ExitOnForwardFailure=yes",
			"-o", "ServerAliveInterval=15",
			"-o", "ServerAliveCountMax=4",
			"-o", "StrictHostKeyChecking=accept-new",
			"-p", sshPort,
			"-R", fmt.Sprintf("0.0.0.0:%d:127.0.0.1:%d", port, port),
		}
		var cmd *exec.Cmd
		switch {
		case key != "":
			args = append(args, "-i", key, "-o", "BatchMode=yes", userHost)
			cmd = exec.Command("ssh", args...)
		case pass != "":
			// 密码认证走 sshpass（Kali/Ubuntu 可 apt install sshpass）。
			args = append(args, userHost)
			cmd = exec.Command("sshpass", append([]string{"-e"}, args...)...)
			cmd.Env = append(cmd.Environ(), "SSHPASS="+pass)
		default:
			args = append(args, userHost)
			cmd = exec.Command("ssh", args...)
		}
		cmd.WaitDelay = time.Second
		return cmd
	}

	first := build()
	if err := first.Start(); err != nil {
		return fmt.Errorf("启动 SSH 中继失败: %w", err)
	}
	// 隧道生命周期跟随监听器，不绑 HTTP 请求 context（请求结束就 cancel 会把隧道杀掉）。
	tunnelCtx, cancel := context.WithCancel(context.Background())

	relayTunnelMgr.mu.Lock()
	relayTunnelMgr.byName[name] = first
	relayTunnelMgr.cancels[name] = cancel
	relayTunnelMgr.mu.Unlock()

	go func() {
		cmd := first
		backoff := 3 * time.Second
		for {
			waitErr := cmd.Wait()
			if tunnelCtx.Err() != nil {
				return // 监听器停止：正常退出
			}
			log.Printf("[c2] SSH 中继隧道断开（%s :%d）: %v，%s 后重连", name, port, waitErr, backoff)
			for {
				select {
				case <-tunnelCtx.Done():
					return
				case <-time.After(backoff):
				}
				if backoff < time.Minute {
					backoff *= 2
				}
				next := build()
				if err := next.Start(); err != nil {
					log.Printf("[c2] SSH 中继重连失败（%s :%d）: %v", name, port, err)
					continue
				}
				cmd = next
				relayTunnelMgr.mu.Lock()
				relayTunnelMgr.byName[name] = cmd
				relayTunnelMgr.mu.Unlock()
				break
			}
		}
	}()
	log.Printf("[c2] SSH 中继隧道已建立（%s）：中转 :%d → 本机 127.0.0.1:%d", name, port, port)
	return nil
}

// stopRelayTunnel 拆除监听器对应的隧道：先取消重连，再结束当前进程。
// 只 cancel 不 kill 会让 ssh 进程继续占着反向隧道（端口释放不了、重连的旧进程还会打架）。
func stopRelayTunnel(name string) {
	relayTunnelMgr.mu.Lock()
	cancel := relayTunnelMgr.cancels[name]
	cmd := relayTunnelMgr.byName[name]
	delete(relayTunnelMgr.byName, name)
	delete(relayTunnelMgr.cancels, name)
	relayTunnelMgr.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

// ── REST ────────────────────────────────────────────────────────────

// GET /api/c2/config — 回显当前 C2 出口配置（密码脱敏）。
func (s *Server) c2ConfigGet(w http.ResponseWriter, r *http.Request) {
	cfg := s.c2RelayConfig()
	writeJSON(w, 200, map[string]any{
		"mode":   cfg.Mode,
		"host":   cfg.Host,
		"ssh":    cfg.SSH,
		"key":    cfg.Key,
		"iface":  cfg.Iface,
		"has_pass": cfg.Pass != "",
	})
}

// PUT /api/c2/config — 保存 C2 出口配置。字段为 nil 时保持不变；mode 只收
// direct/ssh/manual；清空 password 用空串。
func (s *Server) c2ConfigPut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode  *string `json:"mode"`
		Host  *string `json:"host"`
		SSH   *string `json:"ssh"`
		Pass  *string `json:"password"`
		Key   *string `json:"key"`
		Iface *string `json:"iface"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if req.Mode != nil {
		m := strings.TrimSpace(*req.Mode)
		if m != "direct" && m != "ssh" && m != "manual" {
			writeErr(w, 400, "mode 只允许 direct/ssh/manual")
			return
		}
		if err := s.m.pg.SetSetting(settingC2RelayMode, m); err != nil {
			writeErr(w, 500, "保存 mode 失败: "+err.Error())
			return
		}
	}
	// 落库失败必须回错——配置写丢了用户却看到 200，下次重连回连地址就错了。
	put := func(key string, v *string) error {
		if v == nil {
			return nil
		}
		return s.m.pg.SetSetting(key, *v)
	}
	for _, kv := range []struct {
		key string
		val *string
	}{
		{settingC2RelayHost, req.Host},
		{settingC2RelaySSH, req.SSH},
		{settingC2RelayPass, req.Pass},
		{settingC2RelayKey, req.Key},
		{settingC2RelayIface, req.Iface},
	} {
		if err := put(kv.key, kv.val); err != nil {
			writeErr(w, 500, "保存 "+kv.key+" 失败: "+err.Error())
			return
		}
	}
	s.c2ConfigGet(w, r)
}

