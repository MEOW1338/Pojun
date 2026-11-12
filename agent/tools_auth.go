package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/chu0119/pojun/db"
	"os"
	"path/filepath"
)

// 凭据复用工具：把「资产上已经登记的凭据」变成「可直接执行的带认证请求」。
//
// ## 为什么需要它
//
// 资产表有 `auth` 字段（username / password / token / type / description），
// `list_assets` 也能把它读出来。但**读出来只是文本**——模型要自己判断哪个凭据
// 对应哪个站点、是账号密码还是 token、该放 Cookie 还是 Authorization 头，
// 然后手写 curl。格式错一个地方（`token` 该放 `Cookie: token=xxx` 还是
// `Authorization: Bearer xxx`）请求就 401，模型会误判成「凭据无效」。
//
// 而横向测试里**越权挖掘的前提就是「两个身份」**：拿到 A 的凭据去访问 B 的对象。
// 没有这个工具，模型只能手工搬运凭据字符串，既容易错也留不下证据。
//
// ## 设计原则
//
// **只组命令，不自己发请求**——与 scan_with_nuclei 同一个模式。命令交给 Bash
// 工具执行，于是流量录制、审批管控、审计全部自动生效；平台自己发请求会绕过
// 整条管控链。
//
// **凭据值默认不返回**。工具返回的是**可执行的命令**，凭据本身以 shell 变量的
// 形式出现在命令里（模型看得到，因为它要执行），但不会出现在结构化返回的
// 字段里——避免凭据被写进 fact/报告/图谱。
//
// **不猜、不补全**：资产上没有的凭据，工具不生成、不提示用户去猜，只如实说
// 「这个资产没有登记凭据」。

// authEntry 是资产上一条凭据记录（结构与 db.Asset.Auth 一致）。
type authEntry struct {
	Type        string `json:"type"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	Token       string `json:"token"`
	Description string `json:"description"`
}

// authRequest 组装一条带认证的请求命令。
func (t *ToolSet) authRequest() actool.CoreTool {
	return readTool(
		"auth_request",
		"用【资产上已登记的凭据】组装一条带认证的 HTTP 请求命令，交给 Bash 执行"+
			"（本工具只组命令不执行）。\n"+
			"场景：横向测试与越权验证——手上有一个身份，要用**另一个**身份（资产上登记过的）"+
			"去访问同一资源做对照；或者要复用一个已发现的 token 验证会话是否还有效。\n"+
			"输入 asset_id（凭据登记在哪个资产上）+ url（要访问的地址）+ 可选 method/"+
			"body/header/auth_index（用哪一条凭据）。\n"+
			"返回的是可直接粘进 Bash 执行的 curl 命令。**命令里含明文凭据**——执行后请勿把"+
			"命令原文写进 fact 或报告（把凭据用「资产#123 的 token」指代即可）。\n"+
			"没有凭据的资产会明确报「未登记凭据」，不会替你猜。",
		obj(map[string]any{
			"asset_id":   intp("凭据登记在哪个资产上（list_assets 返回的 service 类资产 id）"),
			"url":        str("要访问的 URL（绝对地址）"),
			"method":     str("HTTP 方法，默认 GET"),
			"body":       str("请求体（可选，POST/PUT 等）"),
			"header":     str("附加请求头（可选，格式 'Key: Value'，多行用 \\n 分隔）"),
			"auth_index": intp("用该资产上的第几条凭据（从 0 开始；不传则用第一条可用凭据）"),
		}, "asset_id", "url"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("auth_request 未启用: AssetStore 未初始化"), nil
			}
			var a struct {
				AssetID   int64  `json:"asset_id"`
				URL       string `json:"url"`
				Method    string `json:"method"`
				Body      string `json:"body"`
				Header    string `json:"header"`
				AuthIndex int    `json:"auth_index"`
			}
			_ = json.Unmarshal(in, &a)
			if a.AssetID <= 0 {
				return actool.Errorf("asset_id 必须为正整数"), nil
			}
			if strings.TrimSpace(a.URL) == "" {
				return actool.Errorf("url 不能为空"), nil
			}
			if !strings.HasPrefix(a.URL, "http://") && !strings.HasPrefix(a.URL, "https://") {
				return actool.Errorf("url 必须是绝对地址（http:// 或 https:// 开头）"), nil
			}

			// 取资产（限定在本任务范围内——不能拿别的任务的凭据）。
			assets, err := t.as.GetByIDsInScope(t.taskID, []int64{a.AssetID})
			if err != nil {
				return actool.Errorf("读取资产失败: " + err.Error()), nil
			}
			if len(assets) == 0 {
				return actool.Errorf(fmt.Sprintf("资产 %d 不在本任务范围内（或不存在）", a.AssetID)), nil
			}
			asset := assets[0]

			entries := parseAuthEntries(asset.Auth)
			if len(entries) == 0 {
				return actool.Errorf(fmt.Sprintf(
					"资产 %d 上没有登记凭据——先确认是否已采集到认证信息；本工具不猜、不生成凭据",
					a.AssetID)), nil
			}
			idx := a.AuthIndex
			if idx < 0 {
				idx = 0
			}
			if idx >= len(entries) {
				return actool.Errorf(fmt.Sprintf(
					"资产 %d 上只有 %d 条凭据，auth_index=%d 越界", a.AssetID, len(entries), idx)), nil
			}
			entry := entries[idx]

			method := strings.ToUpper(strings.TrimSpace(a.Method))
			if method == "" {
				method = "GET"
			}
			cmd, err := buildAuthCurl(a.URL, method, a.Body, a.Header, entry)
			if err != nil {
				return actool.Errorf("组装命令失败: " + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"run_with_bash": cmd,
				"auth_kind":     authKind(entry),
				"auth_source":   fmt.Sprintf("资产#%d 的第 %d 条凭据", a.AssetID, idx),
				"note": "用 Bash 工具执行上面这条命令。**命令含明文凭据**——不要把命令原文" +
					"写进 fact/报告，用「资产#<id> 的 <类型> 凭据」指代。响应 401/403 说明" +
					"凭据或认证方式不对，换资产上的另一条凭据试（auth_index）。",
			})
		},
	)
}

// parseAuthEntries 把资产上的 auth 字段转成结构化凭据列表。
//
// 资产上的 auth 是 []map[string]any（键名不固定，历史上用过 username/
// password/token/type/description）。这里做宽松解析：认得就用，不认得的
// 键忽略，但**至少要有一个可用字段**才算一条凭据。
func parseAuthEntries(raw []map[string]any) []authEntry {
	out := []authEntry{}
	for _, m := range raw {
		if m == nil {
			continue
		}
		var e authEntry
		for k, v := range m {
			s, _ := v.(string)
			s = strings.TrimSpace(s)
			switch strings.ToLower(k) {
			case "type", "kind", "auth_type":
				e.Type = s
			case "username", "user", "account", "login":
				e.Username = s
			case "password", "pass", "pwd":
				e.Password = s
			case "token", "session", "cookie", "jwt", "bearer":
				e.Token = s
			case "description", "desc", "note", "comment":
				e.Description = s
			}
		}
		if e.Username == "" && e.Password == "" && e.Token == "" {
			continue // 没有可用字段，不算一条凭据
		}
		out = append(out, e)
	}
	// 排序：token 优先（无需拼装），其次账号密码——默认 auth_index=0 拿到最省事的那条。
	sort.SliceStable(out, func(i, j int) bool {
		ti := out[i].Token != ""
		tj := out[j].Token != ""
		if ti != tj {
			return ti
		}
		return false
	})
	return out
}

// authKind 描述这条凭据的形态（用于返回结果里的说明，不含凭据值）。
func authKind(e authEntry) string {
	switch {
	case e.Token != "":
		if e.Type != "" {
			return e.Type + "(token)"
		}
		return "token"
	case e.Username != "" && e.Password != "":
		if e.Type != "" {
			return e.Type + "(账号密码)"
		}
		return "账号密码"
	case e.Username != "":
		return "仅用户名"
	default:
		return "未知形态"
	}
}

// buildAuthCurl 组装一条带认证的 curl 命令。
//
// 认证方式的选择：
//   - 有 token：默认放 `Authorization: Bearer <token>`；若 type 里出现
//     "cookie" 则放 `Cookie: <token>`（有些系统的会话值就是 cookie 值）。
//   - 只有账号密码：用 `-u user:pass`（curl 自己去协商 Basic/Digest/NTLM）。
//
// 转义：凭据与 URL 里的引号、反斜杠、$ 都要处理——凭据里出现 `'` 或 `$` 是
// 常态（密码生成器出来的），不做转义命令会跑错。
func buildAuthCurl(rawURL, method, body, extraHeader string, e authEntry) (string, error) {
	// 全部值用单引号包裹并转义内部单引号（POSIX sh 的标准做法：
	// ' -> '\''）。这样凭据里的 $ ` " \ 都不会被 shell 解释。
	q := func(s string) string {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	parts := []string{"curl", "-sS", "-i", "--max-time", "20"}
	parts = append(parts, "-X", q(method))
	parts = append(parts, q(rawURL))

	if e.Token != "" {
		lowerType := strings.ToLower(e.Type)
		if strings.Contains(lowerType, "cookie") || strings.Contains(lowerType, "session") {
			parts = append(parts, "-H", q("Cookie: "+e.Token))
		} else if strings.Contains(lowerType, "basic") {
			parts = append(parts, "-u", q(e.Token))
		} else {
			parts = append(parts, "-H", q("Authorization: Bearer "+e.Token))
		}
	} else if e.Username != "" && e.Password != "" {
		parts = append(parts, "-u", q(e.Username+":"+e.Password))
	} else if e.Username != "" {
		parts = append(parts, "-u", q(e.Username))
	}

	if strings.TrimSpace(extraHeader) != "" {
		for _, line := range strings.Split(extraHeader, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts = append(parts, "-H", q(line))
		}
	}
	if strings.TrimSpace(body) != "" {
		parts = append(parts, "--data-raw", q(body))
	}
	return strings.Join(parts, " "), nil
}

// 编译期确认 db 包被使用（authEntry 的字段与 db.Asset.Auth 对应）。
var _ = db.Asset{}

// sessionJarPath 返回任务级 cookie jar 路径（tasks/<id>/shared/sessions/<name>.jar）。
// 空 runDir / 非法会话名返回空串。跨意图复用同一任务目录，登录一次即可多处使用。
// （红队版 v0.7.0 同款实现，随 http_request/session_login 一并下放。）
func (t *ToolSet) sessionJarPath(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || t.runDir == "" {
		return ""
	}
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		}
		return -1
	}, name)
	if clean == "" || len(clean) > 64 {
		return ""
	}
	root := filepath.Dir(t.runDir)
	if filepath.Base(root) == "shared" {
		root = filepath.Dir(root)
	}
	dir := filepath.Join(root, "shared", "sessions")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ""
	}
	return filepath.Join(dir, clean+".jar")
}
