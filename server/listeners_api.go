// 回连接收器 REST API：列出/启动/停止/查会话。授权面与全部业务 API 一致
//（JWT）；启停的 agent 侧审批由拦截规则「[内置] 启停回连接收器」（ask）负责。
package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/chu0119/pojun/listener"
)

type listenerView struct {
	Name      string             `json:"name"`
	Port      int                `json:"port"`
	StartedAt string             `json:"started_at"`
	Sessions  []listener.Session `json:"sessions"`
}

// GET /api/listeners — 全部运行中的监听器（含各自会话快照）。
func (s *Server) listenerList(w http.ResponseWriter, r *http.Request) {
	if s.listeners == nil {
		writeJSON(w, 200, map[string]any{"listeners": []listenerView{}})
		return
	}
	out := []listenerView{}
	for _, l := range s.listeners.List() {
		out = append(out, listenerView{
			Name:      l.Name,
			Port:      l.Port,
			StartedAt: l.StartedAt.UTC().Format("2006-01-02T15:04:05Z"),
			Sessions:  l.Snapshot(),
		})
	}
	writeJSON(w, 200, map[string]any{"listeners": out})
}

// POST /api/listeners — 启动 {"name","port"}。
func (s *Server) listenerStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Port int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if s.listeners == nil {
		writeErr(w, 503, "回连接收器未初始化")
		return
	}
	l, err := s.listeners.Start(strings.TrimSpace(req.Name), req.Port)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// ssh 中继模式：为该监听器托管一条 SSH 反向隧道（失败不回滚监听——
	// 本机端口已在收，隧道可后续修；错误随响应带出）。
	cb := s.ResolveConnectBack(l.Port)
	if s.c2RelayConfig().Mode == "ssh" {
		if terr := s.startRelayTunnel(l.Name, l.Port); terr != nil {
			cb.Via = "中继隧道建立失败: " + terr.Error()
		}
	}
	writeJSON(w, 200, map[string]any{
		"name": l.Name, "port": l.Port, "started_at": l.StartedAt.UTC().Format("2006-01-02T15:04:05Z"),
		"connect_back": cb,
	})
}

// GET /api/listeners/{name} — 会话快照。
func (s *Server) listenerSessions(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	sessions, ok := s.listeners.Get(name)
	if !ok {
		writeErr(w, 404, "监听器不存在: "+name)
		return
	}
	writeJSON(w, 200, map[string]any{"name": name, "sessions": sessions})
}

// POST /api/listeners/{name}/stop — 停止并返回最终快照。
func (s *Server) listenerStop(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	sessions, err := s.listeners.Stop(name)
	stopRelayTunnel(name) // ssh 中继隧道随监听器拆除（无隧道时为空操作）
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"stopped": name, "sessions": sessions})
}
