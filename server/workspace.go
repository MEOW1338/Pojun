package server

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// Workspace file manager — browse / view / edit / download / upload / delete the
// shared work dir (s.m.dir), where all agents write their artifacts. Every path is
// confined to the work dir root (traversal via ".." is neutralised). All routes sit
// behind requireAuth (see Handler()).

const (
	maxWorkspaceRead   = 2 << 20   // 2 MiB: files bigger than this aren't inlined for view/edit (download instead)
	maxWorkspaceUpload = 512 << 20 // 512 MiB per upload request
)

// workspaceProtectedDirs 是工作空间里**不可删除**的系统内部目录。
//
// 工作空间根目录就是 s.m.dir（data 目录），系统把运行时数据直接放在它下面。
// 文件管理器的路径约束只保证「不越出根目录」，但根目录里的这些子目录是
// 系统自己在用的：删掉之后要么不可再生，要么要花很久重建。
//
//   traffic          —— 流量采集库（实测 3.3G / 34 万条）。删了历史请求
//                       响应全丢，漏洞报告里的 HTTP 证据链随之断掉。
//   evidence         —— 漏洞绑定的流量正文（按 sha256 存 blob）。删了
//                       findings 里的绑定全部变成空指针。
//   nuclei-templates —— 漏洞模板库（实测 934M / 14077 个模板）。删了要
//                       重新 git clone 一遍。
//
// 任务数据（tasks / sessions / transcripts）**不在**这份名单里：它们属于
// 某个任务，要清就通过 DELETE /api/tasks/{id} 走正规路径，而不是在工作
// 空间里顺手删一棵目录树。
//
// 只拦删除，不禁读写——agent 仍要能往这些目录里写东西。
var workspaceProtectedDirs = []string{"traffic", "evidence", "nuclei-templates"}

// wsProtected reports whether an absolute path is one of the protected system
// directories (the directory itself, or anything under it).
func (s *Server) wsProtected(abs string) bool {
	for _, name := range workspaceProtectedDirs {
		if pathWithin(filepath.Join(s.m.dir, name), abs) {
			return true
		}
	}
	return false
}

// wsResolve maps a user-supplied relative path to an absolute path INSIDE the work
// dir. It returns ok=false if the path would escape the root. filepath.Clean on a
// rooted copy collapses any ".." so nothing can climb above the root.
func (s *Server) wsResolve(rel string) (string, bool) {
	base := filepath.Clean(s.m.dir)
	rel = strings.TrimPrefix(strings.TrimSpace(rel), "/")
	clean := filepath.Clean("/" + rel) // e.g. "/a/../../etc" → "/etc" (still rooted at "/")
	abs := filepath.Clean(filepath.Join(base, clean))
	if abs != base && !strings.HasPrefix(abs, base+string(os.PathSeparator)) {
		return "", false
	}
	// 符号链接需要第二道校验：Clean+HasPrefix 是词法判断，工作区内的链接
	// 仍可能指向 /etc 或 JWT key。已存在的目标解析真实路径；新目标则解析
	// 最近的存在父目录后再接受。这是 check-then-use 防护，非 openat 竞态修复。
	baseReal := base
	if resolved, err := filepath.EvalSymlinks(base); err == nil {
		baseReal = filepath.Clean(resolved)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		if !pathWithin(baseReal, resolved) {
			return "", false
		}
		return abs, true
	} else if !os.IsNotExist(err) {
		return "", false
	}
	// 目标尚不存在：校验最近存在的父目录，剩余后缀在已验证的真实父目录之下创建。
	parent := filepath.Dir(abs)
	for {
		if resolved, err := filepath.EvalSymlinks(parent); err == nil {
			return abs, pathWithin(baseReal, resolved)
		} else if !os.IsNotExist(err) {
			return "", false
		}
		next := filepath.Dir(parent)
		if next == parent {
			return "", false
		}
		parent = next
	}
}

func pathWithin(base, target string) bool {
	base = filepath.Clean(base)
	target = filepath.Clean(target)
	return target == base || strings.HasPrefix(target, base+string(os.PathSeparator))
}

// wsRel renders an absolute path back as a workspace-relative path (forward slashes).
func (s *Server) wsRel(abs string) string {
	base := filepath.Clean(s.m.dir)
	rel, err := filepath.Rel(base, abs)
	if err != nil || rel == "." {
		return ""
	}
	return filepath.ToSlash(rel)
}

type wsEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Dir   bool   `json:"dir"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"` // unix millis
}

// GET /api/workspace/list?path=<rel>
func (s *Server) wsList(w http.ResponseWriter, r *http.Request) {
	abs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "非法路径")
		return
	}
	fi, err := os.Stat(abs)
	if err != nil {
		writeErr(w, 404, "路径不存在")
		return
	}
	if !fi.IsDir() {
		writeErr(w, 400, "不是目录")
		return
	}
	ents, err := os.ReadDir(abs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]wsEntry, 0, len(ents))
	for _, e := range ents {
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, wsEntry{
			Name:  e.Name(),
			Path:  s.wsRel(filepath.Join(abs, e.Name())),
			Dir:   e.IsDir(),
			Size:  info.Size(),
			MTime: info.ModTime().UnixMilli(),
		})
	}
	// 目录在前，各自按名称排序。
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dir != out[j].Dir {
			return out[i].Dir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	writeJSON(w, 200, map[string]any{"path": s.wsRel(abs), "entries": out})
}

// GET /api/workspace/read?path=<rel> — inline text for view/edit. Binary or oversize
// files return {binary:true}/{too_large:true} with no content (use download instead).
func (s *Server) wsRead(w http.ResponseWriter, r *http.Request) {
	abs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "非法路径")
		return
	}
	fi, err := os.Stat(abs)
	if err != nil {
		writeErr(w, 404, "文件不存在")
		return
	}
	if fi.IsDir() {
		writeErr(w, 400, "是目录，不能作为文件读取")
		return
	}
	if fi.Size() > maxWorkspaceRead {
		writeJSON(w, 200, map[string]any{"path": s.wsRel(abs), "size": fi.Size(), "too_large": true, "binary": true})
		return
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		writeJSON(w, 200, map[string]any{"path": s.wsRel(abs), "size": fi.Size(), "binary": true})
		return
	}
	writeJSON(w, 200, map[string]any{"path": s.wsRel(abs), "size": fi.Size(), "binary": false, "content": string(data)})
}

// POST /api/workspace/write  {path, content} — create/overwrite a text file.
func (s *Server) wsWrite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	abs, ok := s.wsResolve(req.Path)
	if !ok || abs == filepath.Clean(s.m.dir) {
		writeErr(w, 400, "非法路径")
		return
	}
	// 覆盖系统数据目录里的文件同样会破坏数据（traffic 索引、证据 blob）。
	if s.wsProtected(abs) {
		writeErr(w, 403, "系统数据目录不可写入（"+strings.Join(workspaceProtectedDirs, " / ")+"）")
		return
	}
	if fi, err := os.Stat(abs); err == nil && fi.IsDir() {
		writeErr(w, 400, "目标是目录")
		return
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := os.WriteFile(abs, []byte(req.Content), 0o644); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "path": s.wsRel(abs)})
}

// POST /api/workspace/mkdir  {path}
func (s *Server) wsMkdir(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	abs, ok := s.wsResolve(req.Path)
	if !ok || abs == filepath.Clean(s.m.dir) {
		writeErr(w, 400, "非法路径")
		return
	}
	if s.wsProtected(abs) {
		writeErr(w, 403, "系统数据目录不可写入（"+strings.Join(workspaceProtectedDirs, " / ")+"）")
		return
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "path": s.wsRel(abs)})
}

// DELETE /api/workspace/delete?path=<rel> — removes a file or a directory tree
// (confined to the work dir; the root itself can't be deleted).
func (s *Server) wsDelete(w http.ResponseWriter, r *http.Request) {
	abs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "非法路径")
		return
	}
	if abs == filepath.Clean(s.m.dir) {
		writeErr(w, 400, "不能删除工作区根目录")
		return
	}
	if s.wsProtected(abs) {
		writeErr(w, 403, "系统数据目录不可删除（"+strings.Join(workspaceProtectedDirs, " / ")+"）")
		return
	}
	if _, err := os.Stat(abs); err != nil {
		writeErr(w, 404, "路径不存在")
		return
	}
	if err := os.RemoveAll(abs); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// GET /api/workspace/download?path=<rel> — stream a file as an attachment.
func (s *Server) wsDownload(w http.ResponseWriter, r *http.Request) {
	abs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "非法路径")
		return
	}
	fi, err := os.Stat(abs)
	if err != nil || fi.IsDir() {
		writeErr(w, 404, "文件不存在")
		return
	}
	name := filepath.Base(abs)
	// RFC 5987 filename* keeps non-ASCII names intact; plain filename is the fallback.
	w.Header().Set("Content-Disposition", "attachment; filename=\""+sanitizeFilename(name)+"\"; filename*=UTF-8''"+url.PathEscape(name))
	http.ServeFile(w, r, abs)
}

// POST /api/workspace/upload?path=<dir> — multipart form field "file" (one or more).
func (s *Server) wsUpload(w http.ResponseWriter, r *http.Request) {
	dirAbs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "非法路径")
		return
	}
	if s.wsProtected(dirAbs) {
		writeErr(w, 403, "系统数据目录不可写入（"+strings.Join(workspaceProtectedDirs, " / ")+"）")
		return
	}
	if fi, err := os.Stat(dirAbs); err != nil || !fi.IsDir() {
		writeErr(w, 400, "目标目录不存在")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxWorkspaceUpload)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, 400, "解析上传失败或超出大小限制："+err.Error())
		return
	}
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		writeErr(w, 400, "缺少上传文件(表单字段 file)")
		return
	}
	saved := 0
	for _, hdr := range files {
		name := filepath.Base(hdr.Filename) // strip any path component
		if name == "" || name == "." || name == ".." {
			continue
		}
		destAbs, okd := s.wsResolve(filepath.Join(s.wsRel(dirAbs), name))
		if !okd {
			continue
		}
		if err := saveUpload(hdr, destAbs); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		saved++
	}
	writeJSON(w, 200, map[string]any{"uploaded": saved})
}

func saveUpload(hdr *multipart.FileHeader, dest string) error {
	src, err := hdr.Open()
	if err != nil {
		return err
	}
	defer src.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, src)
	return err
}

// sanitizeFilename strips characters unsafe for a Content-Disposition filename token.
func sanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, "\"", "")
	name = strings.ReplaceAll(name, "\\", "")
	name = strings.ReplaceAll(name, "\n", "")
	name = strings.ReplaceAll(name, "\r", "")
	return name
}
