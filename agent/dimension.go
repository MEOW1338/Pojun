package agent

import (
	"encoding/json"
	"strings"
)

// 意图维度（v0.7.0）：用于「同资产×同手法零产出」的确定性去重。
// planner 可以显式给 dimension，也可以由 summary 推断；两者都归一到这里。
const (
	dimRecon      = "recon"
	dimAuthz      = "authz"
	dimInjection  = "injection"
	dimUpload     = "upload"
	dimSSRF       = "ssrf"
	dimRCE        = "rce"
	dimCredReuse  = "cred-reuse"
	dimDataExport = "data-export"
	dimPayment    = "payment"
	dimPrivesc    = "privesc"
	dimLateral    = "lateral"
)

var dimensionAliases = map[string]string{
	"recon": "recon", "reconnaissance": "recon", "侦察": "recon", "信息收集": "recon",
	"authz": "authz", "authorization": "authz", "idor": "authz", "越权": "authz", "权限": "authz",
	"injection": "injection", "sqli": "injection", "xss": "injection", "ssti": "injection", "注入": "injection",
	"upload": "upload", "上传": "upload", "文件上传": "upload",
	"ssrf": "ssrf", "ssrf-probe": "ssrf",
	"rce": "rce", "command": "rce", "exec": "rce", "命令执行": "rce", "代码执行": "rce",
	"cred-reuse": "cred-reuse", "cred": "cred-reuse", "credential": "cred-reuse", "凭据": "cred-reuse", "密码复用": "cred-reuse",
	"data-export": "data-export", "data": "data-export", "export": "data-export", "取数": "data-export", "数据导出": "data-export",
	"payment": "payment", "pay": "payment", "支付": "payment", "资金": "payment", "订单": "payment",
	"privesc": "privesc", "privilege": "privesc", "提权": "privesc",
	"lateral": "lateral", "横向": "lateral",
}

// dimensionInferRules 按优先级从高到低匹配 summary。
var dimensionInferRules = []struct {
	dim string
	kws []string
}{
	{dimPayment, []string{"支付", "改价", "回调", "结算", "资金", "退款", "payment", "checkout", "订单状态"}},
	{dimCredReuse, []string{"凭据", "口令", "密码", "复用", "ak/sk", "accesskey", "token", "credential", "login as"}},
	{dimPrivesc, []string{"提权", "root", "sudo", "suid", "系统权限", "privesc"}},
	{dimLateral, []string{"横向", "内网", "跳板", "lateral", "pivot"}},
	{dimUpload, []string{"上传", "upload", "文件包含", "解析"}},
	{dimRCE, []string{"命令执行", "代码执行", "rce", "getshell", "webshell", "反序列化", "模板注入", "ssti"}},
	{dimSSRF, []string{"ssrf", "元数据", "metadata", "内网探测", "回连"}},
	{dimInjection, []string{"注入", "sqli", "sql", "xss", "越权参数", "injection"}},
	{dimDataExport, []string{"取数", "导出", "批量数据", "未授权读", "数据面", "export", "dump"}},
	{dimAuthz, []string{"越权", "idor", "权限绕过", "未授权访问", "authz"}},
	{dimRecon, []string{"侦察", "枚举", "扫描", "指纹", "目录", "子域", "端口", "recon"}},
}

func normalizeDimension(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if d, ok := dimensionAliases[s]; ok {
		return d
	}
	// 允许 "authz/登录后越权" 这类复合值：取第一个能识别的 token。
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == '/' || r == ',' || r == '|' || r == ' ' }) {
		if d, ok := dimensionAliases[strings.TrimSpace(part)]; ok {
			return d
		}
	}
	return ""
}

func inferDimension(text string) string {
	low := strings.ToLower(text)
	for _, rule := range dimensionInferRules {
		for _, kw := range rule.kws {
			if strings.Contains(low, kw) {
				return rule.dim
			}
		}
	}
	return ""
}

// intentDimension 返回意图最终维度：显式值优先，否则从 summary 推断。
func intentDimension(explicit, summary string) string {
	if d := normalizeDimension(explicit); d != "" {
		return d
	}
	return inferDimension(summary)
}

// IsExploitDimension 判断该维度是否属于「利用/深挖」类：这类意图经常需要
// 连续几十次请求、多步链（拿凭据→登录→提权→取数），租约墙钟要放宽。
func IsExploitDimension(dim string) bool {
	switch dim {
	case dimInjection, dimUpload, dimSSRF, dimRCE, dimCredReuse, dimDataExport, dimPayment, dimPrivesc, dimLateral:
		return true
	}
	return false
}

// ExploitDimensionFromPayload 从意图节点 payload（JSON）取 dimension/summary 并判定。
// payload 解析失败时返回 false（保守：不放宽）。
func ExploitDimensionFromPayload(payload json.RawMessage) bool {
	if len(payload) == 0 {
		return false
	}
	var m map[string]any
	if json.Unmarshal(payload, &m) != nil {
		return false
	}
	explicit, _ := m["dimension"].(string)
	summary, _ := m["summary"].(string)
	if summary == "" {
		summary, _ = m["title"].(string)
	}
	return IsExploitDimension(intentDimension(explicit, summary))
}
