package listener

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// 会话数达到上限后必须淘汰而不是无界增长；关闭的会话优先淘汰。
func TestAppendSessionCapsAndEvictsClosed(t *testing.T) {
	l := &Listener{}
	for i := 0; i < MaxSessionsPerListener; i++ {
		l.appendSession(&Session{ID: fmt.Sprintf("s%d", i), Open: false})
	}
	l.appendSession(&Session{ID: "newest", Open: true})
	snap := l.Snapshot()
	if len(snap) != MaxSessionsPerListener {
		t.Fatalf("sessions=%d，应恒为 %d", len(snap), MaxSessionsPerListener)
	}
	if snap[0].ID != "newest" {
		t.Fatalf("快照应按时间倒序，最新在前，实际首条 %q", snap[0].ID)
	}
	for _, s := range snap {
		if s.ID == "s0" {
			t.Fatal("最老的已关闭会话应先被淘汰")
		}
	}
}

// 全都还开着时淘汰最老的一条，并断开它的连接，避免会话和 goroutine 双泄漏。
func TestAppendSessionEvictsOpenAndClosesConn(t *testing.T) {
	l := &Listener{}
	peer, openConn := net.Pipe()
	defer peer.Close()
	victim := &Session{ID: "victim", Open: true, conn: openConn}
	l.appendSession(victim) // 最老的一条，且带连接
	for i := 0; i < MaxSessionsPerListener-1; i++ {
		l.appendSession(&Session{ID: fmt.Sprintf("open%d", i), Open: true})
	}
	l.appendSession(&Session{ID: "newest", Open: true})

	// 被淘汰会话的连接必须已关闭：对端读会立即失败而不是一直阻塞。
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err := peer.Read(buf); err == nil {
		t.Fatal("被淘汰会话的连接应已关闭")
	}
	snap := l.Snapshot()
	if len(snap) != MaxSessionsPerListener {
		t.Fatalf("sessions=%d，应恒为 %d", len(snap), MaxSessionsPerListener)
	}
	for _, s := range snap {
		if s.ID == "victim" {
			t.Fatal("最老的开着会话应被淘汰")
		}
	}
}
