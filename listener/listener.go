// Package listener implements TCP callback receivers (回连接收器) for red team
// operations: catch reverse-shell callbacks and OOB connections while the agent
// does other work, and record every session as evidence.
//
// 设计边界（刻意不做）：
//   - 不做交互式 shell 管理器（那是 C2 框架的事，Sliver/Mythic 是集成对象不是
//     竞争对象）。监听器负责「接住连接 + 留证据」；交互式操作由 agent 用 Bash
//     里的 nc/socat 自行完成。
//   - 捕获有上限（每会话 64KB 预览），防止目标把监听器当数据泵灌爆内存。
//   - 端口白名单默认 1024-65535（绑低端口需要 root，服务用户没有；真要 80/443
//     走 hostd 或端口转发）。
//
// 并发模型：每个 listener 一个 accept goroutine + 每连接一个读 goroutine；
// Manager.mu 保护 listeners map。Stop 优雅关闭（关 accept、关全部连接）。
package listener

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	// MaxCapturePerSession 是单个会话捕获的字节上限（防灌爆）。
	MaxCapturePerSession = 64 * 1024
	// MaxSessionsPerListener 是每个监听器保留的会话上限。监听器按设计对公网开放，
	// 不限量的话一个扫描器就能把会话列表和 goroutine 堆到内存耗尽。
	MaxSessionsPerListener = 2000
	// MinPort/MaxPort 是允许绑定的端口范围。
	MinPort = 1024
	MaxPort = 65535
)

// Session 是一次回连的记录。
type Session struct {
	ID          string    `json:"id"`
	Remote      string    `json:"remote"`
	ConnectedAt time.Time `json:"connected_at"`
	LastActive  time.Time `json:"last_active"`
	BytesIn     int64     `json:"bytes_in"`
	// Preview 是捕获的前 MaxCapturePerSession 字节（UTF-8 容错解码）。
	// 反弹 shell 的初始输出、OOB 请求行、banner 都在这里。
	Preview string `json:"preview"`
	Open    bool   `json:"open"`

	conn net.Conn // 会话超限被淘汰时用它断开，让读 goroutine 自然退出
}

// Listener 是一个运行中的回连接收器。
type Listener struct {
	Name      string     `json:"name"`
	Port      int        `json:"port"`
	StartedAt time.Time  `json:"started_at"`
	Sessions  []*Session `json:"sessions"`

	mu   sync.Mutex
	ln   net.Listener
	ctx  context.Context
	stop context.CancelFunc
}

// appendSession 记录新连接；会话数达到上限时先淘汰最老的已关闭会话，
// 若全都还开着则淘汰最老的一条并断开它，保证会话列表有界。
func (l *Listener) appendSession(s *Session) {
	var evicted *Session
	l.mu.Lock()
	if len(l.Sessions) >= MaxSessionsPerListener {
		drop := 0
		for i := range l.Sessions {
			if !l.Sessions[i].Open {
				drop = i
				break
			}
		}
		evicted = l.Sessions[drop]
		l.Sessions = append(l.Sessions[:drop], l.Sessions[drop+1:]...)
	}
	l.Sessions = append(l.Sessions, s)
	l.mu.Unlock()
	if evicted != nil && evicted.conn != nil {
		_ = evicted.conn.Close()
	}
}

// Snapshot 返回会话列表的拷贝（按连接时间倒序，最新的在前）。
func (l *Listener) Snapshot() []Session {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Session, 0, len(l.Sessions))
	for i := len(l.Sessions) - 1; i >= 0; i-- {
		out = append(out, *l.Sessions[i])
	}
	return out
}

// Manager 管理全部监听器（进程级单例，由 server 持有）。
type Manager struct {
	mu        sync.Mutex
	listeners map[string]*Listener
}

// NewManager 构造。
func NewManager() *Manager {
	return &Manager{listeners: map[string]*Listener{}}
}

// validateName 校验监听器名（防路径类注入，只是个键）。
func validateName(name string) error {
	if name == "" || len(name) > 64 {
		return fmt.Errorf("名称须为 1-64 字符")
	}
	for _, r := range name {
		ok := r == '-' || r == '_' || r == '.' ||
			(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !ok {
			return fmt.Errorf("名称只允许字母数字与 -_.")
		}
	}
	return nil
}

// Start 起一个监听器。端口必须在 MinPort-MaxPort；同名已存在则报错。
func (m *Manager) Start(name string, port int) (*Listener, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	if port < MinPort || port > MaxPort {
		return nil, fmt.Errorf("端口须在 %d-%d（低端口需要特权，走端口转发）", MinPort, MaxPort)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.listeners[name]; ok {
		return nil, fmt.Errorf("监听器 %q 已存在", name)
	}
	// 不同监听器抢同一端口在 net.Listen 处自然失败，无需额外查重。
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("绑定 :%d 失败: %w", port, err)
	}
	ctx, stop := context.WithCancel(context.Background())
	l := &Listener{Name: name, Port: port, StartedAt: time.Now(), ln: ln, ctx: ctx, stop: stop}
	m.listeners[name] = l
	go l.acceptLoop()
	return l, nil
}

// acceptLoop 接受回连，每个连接一个读 goroutine。
func (l *Listener) acceptLoop() {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return // 监听器已关闭
		}
		if l.ctx.Err() != nil {
			_ = conn.Close()
			return
		}
		go l.handleConn(conn)
	}
}

// handleConn 捕获一个会话：远端地址、时间、有界预览。连接保持打开（回连的
// shell/banner 通常保持连接），远端关闭或监听器停止时收尾。
func (l *Listener) handleConn(conn net.Conn) {
	s := &Session{
		ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
		Remote:      conn.RemoteAddr().String(),
		ConnectedAt: time.Now(),
		Open:        true,
		conn:        conn,
	}
	l.appendSession(s)
	defer func() {
		// 字段写入必须与 Snapshot 的读取同锁，否则悬空读（-race 会报）。
		l.mu.Lock()
		s.Open = false
		l.mu.Unlock()
		_ = conn.Close()
	}()
	buf := make([]byte, 4096)
	var captured int
	for {
		if l.ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			l.mu.Lock()
			s.LastActive = time.Now()
			s.BytesIn += int64(n)
			if captured < MaxCapturePerSession {
				take := n
				if captured+take > MaxCapturePerSession {
					take = MaxCapturePerSession - captured
				}
				s.Preview += string(buf[:take])
				// 丢弃非可打印垃圾的粗处理交给序列化端（JSON 会转义），这里不洗。
				captured += take
			}
			l.mu.Unlock()
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue // 读超时不是关闭：回连 shell 可能长时间静默
			}
			return // 远端关闭
		}
	}
}

// Stop 停一个监听器并返回它的最终会话快照。
func (m *Manager) Stop(name string) ([]Session, error) {
	m.mu.Lock()
	l, ok := m.listeners[name]
	if !ok {
		m.mu.Unlock()
		return nil, fmt.Errorf("监听器 %q 不存在", name)
	}
	delete(m.listeners, name)
	m.mu.Unlock()
	l.stop()
	_ = l.ln.Close()
	// 给读 goroutine 一点时间收尾标记 Open=false。
	time.Sleep(200 * time.Millisecond)
	return l.Snapshot(), nil
}

// Get 返回一个监听器的会话快照。
func (m *Manager) Get(name string) ([]Session, bool) {
	m.mu.Lock()
	l, ok := m.listeners[name]
	m.mu.Unlock()
	if !ok {
		return nil, false
	}
	return l.Snapshot(), true
}

// List 返回全部运行中的监听器（按名字排序）。
func (m *Manager) List() []*Listener {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Listener, 0, len(m.listeners))
	for _, l := range m.listeners {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
