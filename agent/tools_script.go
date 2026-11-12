package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// 任务级共享脚本目录（v0.7.0）：tasks/<id>/shared/scripts。
// 每个意图的 runDir 是 tasks/<id>/i<intent>，默认下一个意图看不到上一个写的脚本；
// PoC/登录脚本因此无法复用。这里把脚本放到任务级 shared，跨意图可读可执行。
func (t *ToolSet) sharedDir() string {
	if t.runDir == "" {
		return ""
	}
	root := filepath.Dir(t.runDir)
	if filepath.Base(root) == "shared" {
		root = filepath.Dir(root)
	}
	dir := filepath.Join(root, "shared")
	if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o755); err != nil {
		return ""
	}
	return dir
}

func sanitizeScriptName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimPrefix(name, "/")
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			return r
		}
		return -1
	}, name)
	if clean == "" || clean == "." || clean == ".." || len(clean) > 120 {
		return ""
	}
	return clean
}

// saveScript 把一段脚本/PoC 写进任务级 shared/scripts，供后续意图复用。
func (t *ToolSet) saveScript() actool.CoreTool {
	return writeTool("save_script",
		"把脚本/PoC 写到任务级共享目录（tasks/<id>/shared/scripts），后续意图可直接 run_script 复用。"+
			"适合：登录脚本、签名/加密还原、批量探测、利用 PoC、数据解析。脚本原文会落盘并返回路径。",
		obj(map[string]any{
			"name":    str("文件名（字母数字-_.; 无扩展名时按 lang 自动补 .sh/.py）"),
			"content": str("脚本正文（≤256KB）。可含占位符；不要把凭据硬编码进脚本"),
			"lang":    str("bash|python，默认 bash"),
		}, "name", "content"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Name    string `json:"name"`
				Content string `json:"content"`
				Lang    string `json:"lang"`
			}
			_ = json.Unmarshal(in, &a)
			name := sanitizeScriptName(a.Name)
			if name == "" {
				return actool.Errorf("name 非法：只允许字母/数字/-/_/.，且不能包含路径分隔符"), nil
			}
			if strings.TrimSpace(a.Content) == "" {
				return actool.Errorf("content 不能为空"), nil
			}
			if len(a.Content) > 256<<10 {
				return actool.Errorf("脚本超过 256KB，请拆分或改为从工作目录读取数据文件"), nil
			}
			lang := strings.ToLower(strings.TrimSpace(a.Lang))
			if lang == "" {
				lang = "bash"
			}
			ext := strings.ToLower(filepath.Ext(name))
			switch {
			case lang == "python" || lang == "py":
				if ext == "" {
					name += ".py"
				}
				if !strings.HasPrefix(a.Content, "#!") {
					a.Content = "#!/usr/bin/env python3\n" + a.Content
				}
			default:
				if ext == "" {
					name += ".sh"
				}
				if !strings.HasPrefix(a.Content, "#!") {
					a.Content = "#!/usr/bin/env bash\nset -uo pipefail\n" + a.Content
				}
			}
			dir := t.sharedDir()
			if dir == "" {
				return actool.Errorf("任务共享目录不可用（runDir 未注入）"), nil
			}
			path := filepath.Join(dir, "scripts", name)
			if err := os.WriteFile(path, []byte(a.Content), 0o755); err != nil {
				return actool.Errorf("写入脚本失败: " + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"path": path,
				"name": name,
				"note": "脚本已落任务共享目录，后续任意意图可用 run_script 执行；报告引用时用相对路径。",
			})
		})
}

// runScript 生成一条执行共享脚本的命令（交给 Bash，保留 guard/流量/审计）。
func (t *ToolSet) runScript() actool.CoreTool {
	return readTool("run_script",
		"生成执行任务共享脚本的命令（只组命令不执行，交给 Bash）。脚本必须先在 tasks/<id>/shared/scripts 下"+
			"（用 save_script 写入）。支持参数与超时；返回可直接执行的命令。",
		obj(map[string]any{
			"path":    str("脚本路径（save_script 返回的 path，或相对 shared/scripts 的文件名）"),
			"args":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "参数列表（可选）"},
			"timeout": intp("超时秒数，默认 120，最大 1800"),
		}, "path"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Path    string   `json:"path"`
				Args    []string `json:"args"`
				Timeout int      `json:"timeout"`
			}
			_ = json.Unmarshal(in, &a)
			dir := t.sharedDir()
			if dir == "" {
				return actool.Errorf("任务共享目录不可用（runDir 未注入）"), nil
			}
			p := strings.TrimSpace(a.Path)
			if p == "" {
				return actool.Errorf("path 必填"), nil
			}
			if !filepath.IsAbs(p) {
				p = filepath.Join(dir, "scripts", sanitizeScriptName(p))
			}
			abs, err := filepath.Abs(p)
			if err != nil {
				return actool.Errorf("路径解析失败"), nil
			}
			scriptsRoot, _ := filepath.Abs(filepath.Join(dir, "scripts"))
			rel, err := filepath.Rel(scriptsRoot, abs)
			if err != nil || strings.HasPrefix(rel, "..") {
				return actool.Errorf("只允许执行 shared/scripts 下的脚本"), nil
			}
			if info, err := os.Stat(abs); err != nil || !info.Mode().IsRegular() {
				return actool.Errorf("脚本不存在: " + abs), nil
			}
			timeout := a.Timeout
			if timeout <= 0 {
				timeout = 120
			}
			if timeout > 1800 {
				timeout = 1800
			}
			q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
			parts := []string{"timeout", fmt.Sprint(timeout), "bash", q(abs)}
			for _, arg := range a.Args {
				parts = append(parts, q(arg))
			}
			return jsonResult(map[string]any{
				"run_with_bash": strings.Join(parts, " "),
				"timeout_sec":   timeout,
				"note":          "用 Bash 执行；输出过大时先重定向到 shared 目录再 grep。",
			})
		})
}
