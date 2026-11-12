package report

// 报告导出的 docx 组装:任务总报告 + 单漏洞报告。
// 数据从 findings 表(ListFindingsForExport/GetFinding,含 report 正文与证据)来,
// 这里只负责排版;内置模板的两套版式见 BuildTaskDocx / BuildFindingDocx。

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/db"
)

// TaskDocxInput 是总报告的输入。
type TaskDocxInput struct {
	TaskID      int64
	Title       string
	Goal        string
	GeneratedAt time.Time
	AssetCounts map[string]int
	Findings    []*db.DBFinding
	// Goals 是逐条任务目标及其达成状态（红队版 v0.6.31 下放）；nil = 报告省略「目标达成情况」。
	Goals []GoalLine
	// AssetNames 资产 id → 可读名（域名/IP/URL）。nil/缺项回退 "id:N"（A8）。
	AssetNames map[int64]string
	// Retests finding id → 复测记录（最新在前）。报告带「复测记录」小节（A9）。
	Retests map[int64][]*db.FindingRetest
	// Customer 委托方（企业名，逗号连接；空 = 封面省略该行）。A12
	Customer string
	// TestWindow 测试窗口描述（如「2026-10-29 ~ 2026-10-31」；空 = 只给生成时间）。A12
	TestWindow string
	// AppendixAssets 附录资产清单：类型 → 可读名列表（A16；nil = 无附录）。
	AppendixAssets map[string][]string
	// Classification 密级/用途占位（空 = 默认「内部资料 · 仅限授权方」）。A12
	Classification string
	// PageHeader 页眉文字（空 = 「渗透测试报告」）。
	PageHeader string
	// ArtifactImage 证据附件图片解析器（v0.5.0）：Markdown 里
	// ![说明](artifact:<id>) 会内嵌为图片；nil = 降级为文字说明。
	ArtifactImage func(id int64) (data []byte, caption string, ok bool)
}

func sevRankKey(f *db.DBFinding) int {
	switch strings.ToLower(f.Severity) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// BuildTaskDocx 渲染任务总报告:
// 封面页（居中标题/委托方/密级/日期）→ 目录页（TOC 字段）→ 一、评估概览 →
// 二、测试范围与方法论 → 三、漏洞明细（按类别折叠分组+着色+复测+流量证据）→
// 四、修复优先级路线图 → 附录 A 资产清单。
// 同类漏洞×多主机的重复上报在类别层折叠呈现。
func BuildTaskDocx(in TaskDocxInput) *Docx {
	d := NewDocx()
	embedGongwenFonts(d) // 公文字体随文档嵌入（GB/T 9704 全链路）
	d.SetArtifactImageResolver(in.ArtifactImage)
	if in.PageHeader != "" {
		d.SetHeaderText(in.PageHeader)
	}

	// ── 封面页（A3）：居中大标题 + 元信息，替代原来的首行 H1 ──
	for i := 0; i < 6; i++ {
		d.CoverLine("", 0, false) // 垂直下压
	}
	d.CoverLine(in.Title, 52, true)
	d.CoverLine("", 0, false)
	if in.Customer != "" {
		d.CoverLine("委托方:"+in.Customer, 28, false)
	}
	classification := in.Classification
	if classification == "" {
		classification = "内部资料 · 仅限授权方"
	}
	d.CoverLine(classification, 24, false)
	d.CoverLine("", 0, false)
	d.CoverLine("报告生成时间:"+FormatTimeUTC(in.GeneratedAt), 24, false)
	d.CoverLine(fmt.Sprintf("漏洞总数:%d(严重 %d / 高危 %d / 中危 %d / 低危 %d)",
		len(in.Findings), countSev(in.Findings, "critical"), countSev(in.Findings, "high"),
		countSev(in.Findings, "medium"), countSev(in.Findings, "low")), 24, false)
	d.PageBreak()

	// ── 目录页（A4）：TOC 字段，settings.xml updateFields 打开自动刷新 ──
	d.TOC()
	d.PageBreak()

	// ── 一、评估概览 ──
	d.H1("一、评估概览")
	if len(in.AssetCounts) > 0 {
		types := make([]string, 0, len(in.AssetCounts))
		for k := range in.AssetCounts {
			types = append(types, k)
		}
		sort.Strings(types)
		rows := make([][]string, 0, len(types))
		total := 0
		for _, ty := range types {
			rows = append(rows, []string{assetTypeCN(ty), fmt.Sprint(in.AssetCounts[ty])})
			total += in.AssetCounts[ty]
		}
		d.Table([]string{"资产类型", "数量"}, rows)
		d.P(fmt.Sprintf("资产合计:%d", total))
	}
	// 严重度分布表（行底色随严重度，A2）
	d.H2("漏洞严重度分布")
	rows := make([][]string, 0, 4)
	fills := make([]string, 0, 4)
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		n := countSev(in.Findings, sev)
		if n > 0 {
			rows = append(rows, []string{SeverityCN(sev), fmt.Sprint(n)})
			fills = append(fills, SeverityHexSoft(sev))
		}
	}
	d.TableFills([]string{"严重度", "数量"}, rows, fills)

	// 漏洞类别分布(同类别多主机上报在这里折叠成一行——"永恒之蓝×16 主机"
	// 在总览就是一个数字,不用翻 16 页明细)
	if groups := groupByClass(in.Findings); len(groups) > 0 {
		d.H2("漏洞类别分布")
		rows := make([][]string, 0, len(groups))
		for _, g := range groups {
			rows = append(rows, []string{g.class, fmt.Sprint(len(g.items)), fmt.Sprint(len(g.assets))})
		}
		d.Table([]string{"漏洞类别", "条数", "涉及资产数"}, rows)
	}
	d.PageBreak()

	// ── 二、测试范围与方法论（A14：数据都在，组章即可）──
	d.H1("二、测试范围与方法论")
	if in.Goal != "" {
		d.H2("任务目标")
		d.P(in.Goal)
	}
	// 目标达成情况（红队版 v0.6.31 下放）：逐条列出是否被证明，未全部达成时明确标注。
	if len(in.Goals) > 0 {
		met, total := GoalTally(in.Goals)
		d.H2("目标达成情况")
		if met < total {
			d.P(fmt.Sprintf("共 %d 个任务目标，已证明达成 %d 个；未达成目标如实记录，本次任务按「未完成」归档。", total, met))
		} else {
			d.P(fmt.Sprintf("共 %d 个任务目标，全部已由可复现证据证明达成。", total))
		}
		rows := make([][]string, 0, len(in.Goals))
		for _, g := range in.Goals {
			state := "未达成"
			if g.Met() {
				state = "已达成"
			}
			rows = append(rows, []string{g.Text, state, nz(g.Criteria, "—")})
		}
		d.Table([]string{"目标", "状态", "验收标准"}, rows)
	}
	d.H2("测试窗口")
	if in.TestWindow != "" {
		d.P("测试执行窗口:" + in.TestWindow)
	}
	d.P("报告生成时间:" + FormatTimeUTC(in.GeneratedAt))
	if len(in.AssetCounts) > 0 {
		d.H2("测试范围")
		d.P("本次测试覆盖以下资产类型（明细见附录 A）:")
		types := make([]string, 0, len(in.AssetCounts))
		for k := range in.AssetCounts {
			types = append(types, k)
		}
		sort.Strings(types)
		parts := make([]string, 0, len(types))
		for _, ty := range types {
			parts = append(parts, fmt.Sprintf("%s ×%d", assetTypeCN(ty), in.AssetCounts[ty]))
		}
		d.Bullet(strings.Join(parts, "；"))
	}
	d.H2("方法论")
	d.P("本次评估由 AI 多 Agent 自主渗透平台 POJUN 执行:规划 Agent 依据目标与资产态势派发探" +
		"测意图,执行 Agent 以真实工具(nmap/httpx/nuclei/ffuf/sqlmap 等)完成侦察、漏洞验证" +
		"与利用,全程流量经记录代理留痕;漏洞结论均要求可复现证据(PoC 命令/请求响应)支撑," +
		"critical/high 级发现建议按复测记录进行独立复验。")
	d.P("严重度评定参照 CVSS v3.1 结合业务影响人工校准;修复优先级建议见第四章。")
	d.PageBreak()

	// ── 三、漏洞明细:按类别分组折叠(类内按严重度降序),类别按条数降序──
	d.H1("三、漏洞明细")
	groups := groupByClass(in.Findings)
	for gi, g := range groups {
		d.H2(fmt.Sprintf("3.%d %s(共 %d 条)", gi+1, g.class, len(g.items)))
		for fi, f := range g.items {
			// 严重度着色（A2）：标题颜色随级别，一眼分诊
			if hex := SeverityHex(f.Severity); hex != "" {
				d.headingColored(fmt.Sprintf("3.%d.%d [%s] %s", gi+1, fi+1, SeverityCN(f.Severity), findingTitle(f)), 3, hex)
			} else {
				d.H3(fmt.Sprintf("3.%d.%d [%s] %s", gi+1, fi+1, SeverityCN(f.Severity), findingTitle(f)))
			}
			d.P(fmt.Sprintf("漏洞类别:%s", nz(f.VulnClass, "未分类")))
			if len(f.AssetIDs) > 0 {
				d.P(fmt.Sprintf("影响资产:%s", assetNames(f.AssetIDs, in.AssetNames)))
			}
			d.P(fmt.Sprintf("发现时间:%s · 发现者:%s", FormatTimeUTC(f.CreatedAt), nz(f.Worker, "-")))
			if strings.TrimSpace(f.Summary) != "" {
				d.H4("摘要")
				d.P(f.Summary)
			}
			if body := strings.TrimSpace(f.Report); body != "" {
				d.H4("详细报告")
				writeMarkdownish(d, body)
			}
			if ev := strings.TrimSpace(f.Evidence); ev != "" {
				d.H4("证据 / PoC")
				d.Code(ev)
			}
			writeTrafficEvidenceDocx(d, f)
			writeRetestDocx(d, f, in.Retests)
			d.P("")
		}
	}
	d.PageBreak()

	// ── 四、修复优先级路线图（A15：立即/计划/择机三档）──
	d.H1("四、修复优先级路线图")
	writeRemediationRoadmap(d, in.Findings)

	// ── 附录 A：资产清单（A16）──
	if len(in.AppendixAssets) > 0 {
		d.PageBreak()
		d.H1("附录 A 资产清单")
		types := make([]string, 0, len(in.AppendixAssets))
		for k := range in.AppendixAssets {
			types = append(types, k)
		}
		sort.Strings(types)
		const appendixCap = 200 // 单类型最多列 200 条,超出提示去平台查看
		for _, ty := range types {
			names := in.AppendixAssets[ty]
			if len(names) == 0 {
				continue
			}
			d.H2(assetTypeCN(ty) + fmt.Sprintf("(共 %d)", len(names)))
			shown := names
			if len(shown) > appendixCap {
				shown = shown[:appendixCap]
			}
			rows := make([][]string, 0, len(shown))
			for i, n := range shown {
				rows = append(rows, []string{fmt.Sprint(i + 1), n})
			}
			d.Table([]string{"#", "资产"}, rows)
			if len(names) > appendixCap {
				d.P(fmt.Sprintf("（其余 %d 条略，可在平台「资产」页查看全部。）", len(names)-appendixCap))
			}
		}
	}
	return d
}

// writeRemediationRoadmap 修复优先级三档表（A15）。
// v1 用「清单+通用指引」形态——每条漏洞的专项修复建议已在详细报告正文的
// 「修复建议」节，这里解决的是“先修哪个”的排序问题。
func writeRemediationRoadmap(d *Docx, fs []*db.DBFinding) {
	tiers := []struct {
		title  string
		sevs   []string
		advice string
	}{
		{"立即整改(建议 7 天内)", []string{"critical", "high"},
			"存在被直接利用/造成数据泄露风险,建议立即安排修复并临时缓解(WAF 规则/下线/访问控制收紧)。",
		},
		{"近期计划(建议 30 天内)", []string{"medium"},
			"需特定条件利用或影响有限,纳入常规迭代修复,修复后走复测验证。",
		},
		{"择机安排", []string{"low", "info"},
			"风险较低或为加固建议,随版本迭代处理;涉及配置类项目可先行调整。",
		},
	}
	for _, tier := range tiers {
		var items []*db.DBFinding
		for _, f := range fs {
			for _, s := range tier.sevs {
				if strings.EqualFold(f.Severity, s) {
					items = append(items, f)
					break
				}
			}
		}
		d.H2(tier.title)
		if len(items) == 0 {
			d.P("本档暂无。")
			continue
		}
		d.P(tier.advice)
		sort.SliceStable(items, func(i, j int) bool { return sevRankKey(items[i]) < sevRankKey(items[j]) })
		rows := make([][]string, 0, len(items))
		for i, f := range items {
			rows = append(rows, []string{fmt.Sprint(i + 1), findingTitle(f), SeverityCN(f.Severity), statusCN(f.Status)})
		}
		d.TableFills([]string{"#", "漏洞", "严重度", "当前状态"}, rows, nil)
	}
}

// statusCN 分拣状态中文（路线图表用）。
func statusCN(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "pending":
		return "待处理"
	case "in_progress":
		return "处理中"
	case "confirmed":
		return "已确认"
	case "resolved":
		return "已处理"
	case "fixed":
		return "已修复"
	case "false_positive":
		return "误报"
	case "ignored":
		return "忽略"
	case "duplicate":
		return "重复"
	case "risk_accepted":
		return "风险接受"
	default:
		return nz(s, "-")
	}
}

// assetNames 资产 id 列表 → 可读名（A8）。缺映射的回退 "id:N"。
func assetNames(ids []int64, names map[int64]string) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		if n, ok := names[id]; ok && strings.TrimSpace(n) != "" {
			parts = append(parts, n)
			continue
		}
		parts = append(parts, fmt.Sprintf("id:%d", id))
	}
	return strings.Join(parts, ", ")
}

// retestVerdictCN 复测结论中文（A9）。
func retestVerdictCN(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "reproduced":
		return "已复现"
	case "fixed":
		return "已修复"
	case "inconclusive":
		return "无法定论"
	default:
		return nz(v, "-")
	}
}

// writeRetestDocx 复测记录小节（A9）：最新一次结论在前，历史条数附注。
func writeRetestDocx(d *Docx, f *db.DBFinding, retests map[int64][]*db.FindingRetest) {
	rs := retests[f.ID]
	if len(rs) == 0 {
		return
	}
	latest := rs[0]
	d.H4("复测记录")
	line := fmt.Sprintf("最近复测:%s · %s", retestVerdictCN(latest.Verdict), FormatTimeUTC(latest.CreatedAt))
	if s := strings.TrimSpace(latest.Summary); s != "" {
		line += " · " + s
	}
	d.P(line)
	if len(rs) > 1 {
		d.P(fmt.Sprintf("历史复测共 %d 次（可在平台「发现 → 复测」查看全过程）。", len(rs)))
	}
}

// trafficRoleCN 流量证据角色中文（A10）。
func trafficRoleCN(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "baseline":
		return "正常对照"
	case "proof":
		return "漏洞证明"
	case "verification":
		return "补充验证"
	case "supporting":
		return "辅助证据"
	default:
		return nz(role, "-")
	}
}

// writeTrafficEvidenceDocx 流量证据小节（A10）：md 导出（report/findings.go）已有
// 此逻辑，这里在 Word 侧同构呈现——绑定元信息 + 请求/响应头代码块。报文正文
// 体积大且含二进制形态，交付件保留头部与快照元信息（正文走 md 导出的附件文件）。
func writeTrafficEvidenceDocx(d *Docx, f *db.DBFinding) {
	if len(f.TrafficBindings) == 0 {
		return
	}
	stale := f.Report != "" && f.EvidenceVersion != f.ReportEvidenceVersion
	d.H4("关联流量证据")
	d.P(fmt.Sprintf("证据版本:%d · 绑定 %d 条", f.EvidenceVersion, len(f.TrafficBindings)))
	if stale {
		d.P("⚠ 证据已变更，详细报告待更新。")
	}
	for i, b := range f.TrafficBindings {
		d.P(fmt.Sprintf("%d. 证据 #%d · %s — %s %s · 状态码 %d",
			i+1, b.ID, trafficRoleCN(b.Role), nz(b.Snapshot.Method, "GET"), b.Snapshot.URL, b.Snapshot.Status))
		if n := strings.TrimSpace(b.Note); n != "" {
			d.PRich("   说明:" + n)
		}
		if h := strings.TrimSpace(b.Snapshot.ReqHead); h != "" {
			d.P("请求头:")
			d.Code(h)
		}
		if h := strings.TrimSpace(b.Snapshot.RespHead); h != "" {
			d.P("响应头:")
			d.Code(h)
		}
	}
}

// classGroup 同一漏洞类别的发现聚合(含去重资产集合)。
// 归一用 db.NormalizeVulnClass:写入层已归一新记录,历史变体(SQLi vs 注入)
// 在读取侧同样折叠,总报告不因旧数据开天窗。
type classGroup struct {
	class  string
	items  []*db.DBFinding
	assets map[int64]struct{}
}

func groupByClass(fs []*db.DBFinding) []classGroup {
	idx := map[string]*classGroup{}
	var order []string
	for _, f := range fs {
		c := db.NormalizeVulnClass(f.VulnClass)
		if c == "" {
			c = "未分类"
		}
		g, ok := idx[c]
		if !ok {
			g = &classGroup{class: c, assets: map[int64]struct{}{}}
			idx[c] = g
			order = append(order, c)
		}
		g.items = append(g.items, f)
		for _, a := range f.AssetIDs {
			g.assets[a] = struct{}{}
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		gi, gj := idx[order[i]], idx[order[j]]
		// 条数降序,同条数按类别名字典序保证稳定
		if len(gi.items) != len(gj.items) {
			return len(gi.items) > len(gj.items)
		}
		return gi.class < gj.class
	})
	out := make([]classGroup, 0, len(order))
	for _, c := range order {
		g := idx[c]
		sort.SliceStable(g.items, func(i, j int) bool { return sevRankKey(g.items[i]) < sevRankKey(g.items[j]) })
		out = append(out, *g)
	}
	return out
}

// FindingDocxInput 是单漏洞报告的输入（v0.4.0：与总报告同级的封面/页眉）。
type FindingDocxInput struct {
	Finding *db.DBFinding
	// ArtifactImage 证据附件图片解析器（v0.5.0，见 TaskDocxInput.ArtifactImage）。
	ArtifactImage  func(id int64) (data []byte, caption string, ok bool)
	GeneratedAt    time.Time
	AssetNameMap   map[int64]string
	Retests        []*db.FindingRetest
	Customer       string // 委托方（空 = 省略该行）
	Classification string // 密级占位（空 = 默认「内部资料 · 仅限授权方」）
}

// BuildFindingDocx 渲染单漏洞报告(复现步骤/证据/修复建议的自包含文档)。
// v0.4.0：补真封面页（居中标题/委托方/密级/日期）+ 页眉（漏洞名）——与总报告
// 同一交付标准；正文里的请求/响应/复测章节沿用 v0.3.93 的渲染。
func BuildFindingDocx(in FindingDocxInput) *Docx {
	f := in.Finding
	generatedAt := in.GeneratedAt
	d := NewDocx()
	embedGongwenFonts(d) // 公文字体随文档嵌入（GB/T 9704 全链路）
	d.SetArtifactImageResolver(in.ArtifactImage)
	d.SetHeaderText("渗透测试报告 — " + findingTitle(f))

	// 封面页（与总报告同版式）
	for i := 0; i < 6; i++ {
		d.CoverLine("", 0, false)
	}
	if hex := SeverityHex(f.Severity); hex != "" {
		d.CoverLineColored(fmt.Sprintf("[%s] %s", SeverityCN(f.Severity), findingTitle(f)), 44, hex, true)
	} else {
		d.CoverLine(fmt.Sprintf("[%s] %s", SeverityCN(f.Severity), findingTitle(f)), 44, true)
	}
	d.CoverLine("", 0, false)
	if in.Customer != "" {
		d.CoverLine("委托方:"+in.Customer, 28, false)
	}
	classification := in.Classification
	if classification == "" {
		classification = "内部资料 · 仅限授权方"
	}
	d.CoverLine(classification, 24, false)
	d.CoverLine("", 0, false)
	d.CoverLine("报告生成时间:"+FormatTimeUTC(generatedAt), 24, false)
	d.PageBreak()

	// 目录页（与总报告一致：TOC 字段，settings updateFields 打开自动刷新）
	d.TOC()
	d.PageBreak()

	d.P(fmt.Sprintf("漏洞类别:%s · 严重度:%s · 状态:%s", nz(f.VulnClass, "未分类"), SeverityCN(f.Severity), statusCN(f.Status)))
	if len(f.AssetIDs) > 0 {
		d.P(fmt.Sprintf("影响资产:%s", assetNames(f.AssetIDs, in.AssetNameMap)))
	}
	d.P(fmt.Sprintf("发现时间:%s · 发现者:%s", FormatTimeUTC(f.CreatedAt), nz(f.Worker, "-")))
	if s := strings.TrimSpace(f.Summary); s != "" {
		d.Hei1("一、漏洞概述")
		d.P(s)
	}
	if body := strings.TrimSpace(f.Report); body != "" {
		d.Hei1("二、详细报告")
		writeMarkdownish(d, body)
	}
	if ev := strings.TrimSpace(f.Evidence); ev != "" {
		d.Hei1("三、证据 / PoC")
		d.Code(ev)
	}
	// 四、流量证据 / 五、复测记录 —— 与总报告同源（A9/A10）
	writeTrafficEvidenceDocx(d, f)
	if len(in.Retests) > 0 {
		d.Hei1("复测记录")
		latest := in.Retests[0]
		line := fmt.Sprintf("最近复测:%s · %s", retestVerdictCN(latest.Verdict), FormatTimeUTC(latest.CreatedAt))
		if s := strings.TrimSpace(latest.Summary); s != "" {
			line += " · " + s
		}
		d.P(line)
		if len(in.Retests) > 1 {
			d.P(fmt.Sprintf("历史复测共 %d 次。", len(in.Retests)))
		}
	} else {
		// 未复测标注（v0.4.27）：pending 且没有任何复测记录的漏洞，报告里明确标出
		// 「待人工复核」，避免读报告的人把模型结论当成已验证事实。
		if strings.EqualFold(f.Status, "pending") {
			d.P("复测记录:未复测（待人工复核）")
		}
	}
	return d
}

// writeMarkdownish 把 finding.report 的 Markdown 排进 Word（A5 富渲染）：
// - '# '/'## '/'### ' → H3/H4/H4（漏洞标题已是 H3，正文小节不再压平）
// - '- '/'* ' → 项目符号（numbering.xml 修复后真实渲染）
// - '```' 围栏 → 代码块
// - '| |' 表格块 → 真 OOXML 表格（第二行分隔行自动剔除）
// - '**加粗**' → 富文本 run（段落与列表项都支持）
// 其余按段落。不追求 Markdown 完整性——报告正文是模型产物，覆盖常用子集即可。
func writeMarkdownish(d *Docx, md string) {
	lines := strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n")
	inCode := false
	// 表格块收集：连续的 | 开头行
	var tableBuf []string
	flushTable := func() {
		if len(tableBuf) == 0 {
			return
		}
		rows := make([][]string, 0, len(tableBuf))
		for _, ln := range tableBuf {
			cells := splitMarkdownRow(ln)
			if isTableSeparator(cells) {
				continue // |---|---| 分隔行
			}
			rows = append(rows, cells)
		}
		if len(rows) > 0 {
			header := rows[0]
			body := rows[1:]
			if len(body) == 0 {
				// 只有表头一行的退化表格按普通段落打出来
				d.P(strings.Join(header, " | "))
			} else {
				d.Table(header, body)
			}
		}
		tableBuf = tableBuf[:0]
	}
	// 围栏代码块收集：整块一个 Code 段落（行间 w:br）——逐行成段会让长
	// JSON/curl 被拆成几十个独立段落堆成一片（v0.4.1）。
	var codeBuf []string
	flushCode := func() {
		if len(codeBuf) > 0 {
			d.Code(strings.Join(codeBuf, "\n"))
			codeBuf = codeBuf[:0]
		}
	}
	for _, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if strings.HasPrefix(trimmed, "```") {
			flushTable()
			flushCode()
			inCode = !inCode
			continue
		}
		if inCode {
			codeBuf = append(codeBuf, ln)
			continue
		}
		if strings.HasPrefix(trimmed, "|") && strings.HasSuffix(trimmed, "|") {
			tableBuf = append(tableBuf, trimmed)
			continue
		}
		flushTable()
		// 证据附件图片：![说明](artifact:<id>) → 内嵌截图 + 图注（v0.5.0）。
		if artRe.MatchString(trimmed) {
			m := artRe.FindStringSubmatch(trimmed)
			alt, rawID := strings.TrimSpace(m[1]), m[2]
			id, _ := strconv.ParseInt(rawID, 10, 64)
			inserted := false
			if id > 0 && d.artifactImage != nil {
				if data, caption, ok := d.artifactImage(id); ok {
					if caption == "" {
						caption = alt
					}
					inserted = d.Image(data, caption)
				}
			}
			if !inserted {
				// 附件缺失/非图片/环境不支持：降级成一行说明，不中断报告。
				d.P("（证据图片：" + alt + "，附件缺失或不可嵌入）")
			}
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "### "):
			d.H4(strings.TrimPrefix(trimmed, "### "))
		case strings.HasPrefix(trimmed, "## "):
			// 公文二级标题：楷体三号（v0.4.3 对齐参考件）
			d.Kai2(strings.TrimPrefix(trimmed, "## "))
		case strings.HasPrefix(trimmed, "# "):
			// 公文一级标题：黑体三号（v0.4.3 对齐参考件）
			d.Hei1(strings.TrimPrefix(trimmed, "# "))
		case strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* "):
			// 嵌套列表：行首每 2 个空格一级（reporter 常写二级清单），ilvl 交给
			// numbering.xml 的多级定义；压平会让层级关系全丢（v0.4.0）。
			indent := len(ln) - len(strings.TrimLeft(ln, " 	"))
			lvl := indent / 2
			if lvl > 2 {
				lvl = 2
			}
			fmt.Fprintf(&d.buf, `<w:p><w:pPr><w:numPr><w:ilvl w:val="%d"/><w:numId w:val="1"/></w:numPr><w:ind w:firstLine="0" w:left="%d"/><w:jc w:val="both"/></w:pPr>`, lvl, 720+lvl*360)
			d.buf.WriteString(runsXML(parseRich(strings.TrimPrefix(strings.TrimPrefix(trimmed, "- "), "* "))))
			d.buf.WriteString(`</w:p>`)
		case trimmed == "":
			// 段间空行,段落间距已由样式给,跳过
		default:
			// 公文序号标题识别（v0.4.3 对齐参考件）：reporter 正文里常出现
			// 「一、排查经过」（黑体一级）与「（一）现场证据采集。」（楷体二级），
			// 短行按标题排版，长行仍按正文（避免误伤带内容的段落）。
			if gongwenHeiRe.MatchString(trimmed) && len([]rune(trimmed)) <= 40 {
				d.Hei1(trimmed)
				continue
			}
			if gongwenKaiRe.MatchString(trimmed) && len([]rune(trimmed)) <= 30 {
				d.Kai2(trimmed)
				continue
			}
			d.PRich(trimmed)
		}
	}
	flushTable()
	flushCode()
}

// 公文序号标题识别：一、/二、… 开头（黑体一级）、（一）/（二）… 开头（楷体二级）。
// 只对【整行短语】生效——带正文内容的段落不误伤。
var (
	gongwenHeiRe = regexp.MustCompile(`^[一二三四五六七八九十]{1,3}、`)
	gongwenKaiRe = regexp.MustCompile(`^（[一二三四五六七八九十]{1,3}）`)
	// artRe 匹配报告里的证据图片引用：![说明](artifact:12)
	artRe = regexp.MustCompile(`^!\[(.*?)\]\(artifact:(\d+)\)$`)
)

// splitMarkdownRow 拆一行 | a | b | → [a, b]。
func splitMarkdownRow(ln string) []string {
	trimmed := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(ln), "|"), "|")
	parts := strings.Split(trimmed, "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

// isTableSeparator 识别 |---|:---:| 分隔行。
func isTableSeparator(cells []string) bool {
	if len(cells) == 0 {
		return false
	}
	for _, c := range cells {
		t := strings.TrimSpace(c)
		if t == "" {
			return false
		}
		for _, r := range t {
			if r != '-' && r != ':' && r != ' ' {
				return false
			}
		}
	}
	return true
}

func countSev(fs []*db.DBFinding, sev string) int {
	n := 0
	for _, f := range fs {
		if strings.EqualFold(f.Severity, sev) {
			n++
		}
	}
	return n
}

// assetTypeCN 资产类型中文(概览表用)。
func assetTypeCN(ty string) string {
	switch ty {
	case "root_domain":
		return "根域名"
	case "subdomain":
		return "子域名"
	case "ip":
		return "IP"
	case "service":
		return "服务"
	case "endpoint":
		return "端点"
	case "app":
		return "应用"
	default:
		return ty
	}
}
