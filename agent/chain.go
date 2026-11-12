package agent

// 攻击链自动续跳（v0.7.0）：report_finding 成功后，按漏洞类别自动派一条
// 「继续打穿」的意图，把「漏洞存在」推进到「拿到影响」。
//
// ## 为什么需要它
//
// 客户反馈的核心缺陷是「到瓶颈就放弃，不会自己想办法打出利用」。现场事实：
// worker 能确认漏洞（267 次 report_finding），但确认之后**没有下一步**——
// planner 下一轮看到的是「已有漏洞」，容易转去补覆盖面，而不是利用它。
//
// 这里做确定性续跳：高风险漏洞入库后立刻生成一条继任意图（维度=下一跳），
// 锚在该 finding 节点上。规划者仍然掌握全局（可 steer/kill/改编排），但
// 「从存在到影响」这一步不再取决于模型是否想起来。

import (
	"encoding/json"
	"fmt"
	"strings"
)

// chainNext 返回某维度对应的下一跳维度与目标描述（空=不续跳）。
func chainNext(dim string) (string, string) {
	switch dim {
	case dimInjection:
		return dimDataExport, "用已确认的注入点导出数据/凭据（只读取证）：拿到可交付的库表、账号或配置证据，并评估影响范围"
	case dimUpload, dimRCE:
		return dimCredReuse, "利用已确认的命令执行/上传点在目标主机收集凭据与配置（只读），确认权限级别与内网可达面"
	case dimAuthz:
		return dimDataExport, "用已确认的越权点回读他人数据（限证明所需），并验证改状态/改价的业务影响"
	case dimSSRF:
		return dimRecon, "用 SSRF 探测内网服务与云元数据，找出下一跳可打的服务"
	case dimCredReuse:
		return dimLateral, "用已拿到的凭据尝试横向下一个系统（先确认授权边界内的目标）"
	case dimPayment:
		return dimDataExport, "验证支付/订单状态机被篡改后能产生多少实际影响（测试订单、金额、回调），取证后停止"
	case dimPrivesc:
		return dimDataExport, "提权后只读取证：确认可访问的敏感数据与持久化位置，不做破坏性操作"
	default:
		return "", ""
	}
}

// dispatchChainIntent 生成继任意图。返回 (intentID, note)。intentID<=0 时 note 说明原因。
func (t *ToolSet) dispatchChainIntent(vulnclass, name, summary, severity string, assetIDs []int64, findingNodeID, intentID int64) (int64, string) {
	sev := strings.ToLower(strings.TrimSpace(severity))
	if sev != "critical" && sev != "high" {
		return 0, ""
	}
	dim := inferDimension(vulnclass + " " + name + " " + summary)
	nextDim, goal := chainNext(dim)
	if nextDim == "" {
		return 0, ""
	}
	// 摘要必须具体：带上漏洞名与维度，避免和别的意图撞车被 dedupe 掉。
	// name 可能为空（模型只给了 summary），回落到 summary 前 40 字。
	label := strings.TrimSpace(name)
	if label == "" {
		label = trimForSummary(strings.TrimSpace(summary), 40)
	}
	sum := fmt.Sprintf("利用「%s」继续打穿：%s", trimForSummary(label, 40), goal)
	it := intentItem{Summary: sum, Dimension: nextDim, Priority: 8}
	for _, id := range assetIDs {
		if raw, err := json.Marshal(id); err == nil {
			it.AssetIDs = append(it.AssetIDs, raw)
		}
	}
	if findingNodeID > 0 {
		if raw, err := json.Marshal(findingNodeID); err == nil {
			it.ParentIDs = append(it.ParentIDs, raw)
		}
	}
	id, err := t.addOneIntent(it)
	if err != nil {
		return 0, "攻击链续跳未派： " + err.Error()
	}
	return id, fmt.Sprintf("已自动派继任意图 #%d（维度=%s）：从「漏洞存在」推进到「拿到影响」。", id, nextDim)
}

func trimForSummary(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}
