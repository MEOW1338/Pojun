// 报告导出 API:任务总报告(docx/md)与单漏洞报告(docx)。
// 内容取自 findings 表(含 report 正文/证据);docx 由 report 包内置模板渲染。
// v0.3.93 起:交付默认剔除误报/重复/忽略/风险接受(A7),资产可读名(A8)、
// 复测记录(A9)、流量证据(A10)一并接进 Word。
package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/report"
)

// exportExcludeStatuses 交付件默认剔除的分拣状态。
// false_positive/duplicate/ignored/risk_accepted 都是「不该出现在客户面前」的
// 三态;pending/in_progress/confirmed/resolved/fixed 正常交付。
var exportExcludeStatuses = []string{
	db.FindingFalsePositive, db.FindingDuplicate, db.FindingIgnored, db.FindingRiskAccepted,
}

// reportAssetNames 批量解析资产 id → 可读名（域名/IP/URL，A8）。
func (s *Server) reportAssetNames(findings []*db.DBFinding) map[int64]string {
	seen := map[int64]bool{}
	var ids []int64
	for _, f := range findings {
		for _, a := range f.AssetIDs {
			if a > 0 && !seen[a] {
				seen[a] = true
				ids = append(ids, a)
			}
		}
	}
	if len(ids) == 0 {
		return nil
	}
	list, err := s.m.pg.Assets().GetByIDs(ids)
	if err != nil {
		return nil
	}
	out := make(map[int64]string, len(list))
	for _, a := range list {
		out[a.ID] = assetDisplayName(a)
	}
	return out
}

// assetDisplayName 资产可读名:按类型取最有辨识度的字段。
func assetDisplayName(a *db.Asset) string {
	switch a.Type {
	case "endpoint", "app", "service":
		if a.URL != "" {
			return a.URL
		}
		if a.Domain != "" && a.Port != nil {
			return fmt.Sprintf("%s:%d", a.Domain, *a.Port)
		}
		if a.IP != "" && a.Port != nil {
			return fmt.Sprintf("%s:%d", a.IP, *a.Port)
		}
	case "subdomain", "root_domain":
		if a.Domain != "" {
			return a.Domain
		}
	case "ip":
		if a.IP != "" {
			return a.IP
		}
	}
	// 兜底:各类型还有值的字段依次试
	if a.URL != "" {
		return a.URL
	}
	if a.Domain != "" {
		return a.Domain
	}
	if a.IP != "" {
		return a.IP
	}
	if a.RootDomain != "" {
		return a.RootDomain
	}
	return ""
}

// reportRetests 批量取各 finding 的复测记录（A9；最新在前，ListFindingRetests 已按 id DESC）。
func (s *Server) reportRetests(findings []*db.DBFinding) map[int64][]*db.FindingRetest {
	out := make(map[int64][]*db.FindingRetest)
	for _, f := range findings {
		rs, err := s.m.pg.ListFindingRetests(f.ID)
		if err != nil || len(rs) == 0 {
			continue
		}
		out[f.ID] = rs
	}
	return out
}

// exportTaskDocx 任务总报告(Word)。
func (s *Server) exportTaskDocx(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeErr(w, 404, "no active task")
		return
	}
	findings, err := s.m.pg.ListFindingsForExport(db.FindingFilter{TaskID: t.ID, ExcludeStatuses: exportExcludeStatuses}, nil)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	counts := map[string]int{}
	appendix := map[string][]string{}
	for _, ty := range []string{"root_domain", "ip", "subdomain", "app", "service", "endpoint"} {
		ns, _ := s.m.Assets().QueryByType(ty, 100000, 0)
		if len(ns) == 0 {
			continue
		}
		counts[ty] = len(ns)
		names := make([]string, 0, len(ns)) // 附录 A 资产清单（A16）
		for _, a := range ns {
			if n := assetDisplayName(a); n != "" {
				names = append(names, n)
			}
		}
		appendix[ty] = names
	}
	goals, _ := t.Store.ListByKind(db.KindGoal, 1000)
	doc := report.BuildTaskDocx(report.TaskDocxInput{
		Title:          fmt.Sprintf("渗透测试报告 — %s", t.Description),
		Goal:           t.Goal,
		GeneratedAt:    time.Now(),
		AssetCounts:    counts,
		Findings:       findings,
		Goals:          report.GoalLines(goals),
		AssetNames:     s.reportAssetNames(findings),
		Retests:        s.reportRetests(findings),
		Customer:       s.taskCustomerNames(t),
		TestWindow:     taskTestWindow(t),
		AppendixAssets: appendix,
		PageHeader:     fmt.Sprintf("渗透测试报告 — %s", t.Description),
		ArtifactImage:  s.artifactImageResolver(t.ID, 0),
	})
	name := fmt.Sprintf("pojun-report-task%s-%s.docx", t.ID, time.Now().Format("20060102"))
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.WriteHeader(200)
	_ = doc.Encode(w)
}

// artifactImageResolver 构造证据附件图片解析器（v0.5.0）：只解析本任务内的
// 图片附件，非图片/跨任务/文件丢失都返回 ok=false（报告降级为文字说明）。
func (s *Server) artifactImageResolver(taskID string, onlyFindingID int64) func(int64) ([]byte, string, bool) {
	if taskID == "" {
		return nil
	}
	return func(id int64) ([]byte, string, bool) {
		pg := s.m.PG()
		if pg == nil {
			return nil, "", false
		}
		a, err := pg.GetTaskArtifact(id)
		if err != nil || a == nil || a.TaskID != taskID {
			return nil, "", false
		}
		// 单漏洞报告只嵌「该漏洞的图」：归属别的漏洞或任务级材料一律不嵌，
		// 避免张冠李戴。
		if onlyFindingID > 0 && a.FindingID != onlyFindingID {
			return nil, "", false
		}
		data, ok := s.artifactImageData(a)
		caption := a.Note
		if caption == "" {
			caption = a.Name
		}
		// 文档附件（v0.4.21）：引用文档时嵌入第一页预览图，让报告里也能“看到”。
		if !ok && a.PreviewState == "ready" && a.PreviewPages > 0 {
			p := filepath.Join(s.previewDir(a.TaskID, a.ID), "page-1.jpg")
			if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
				data, ok = b, true
				caption = caption + "（文档第 1 页预览）"
			}
		}
		if !ok {
			return nil, "", false
		}
		// 大图先压到 1600px JPEG：20MB 原图直接塞进 docx 会让报告膨胀到几十 MB。
		if len(data) > 2<<20 {
			if small, ok := s.shrinkDocxImage(data); ok {
				data = small
			}
		}
		return data, caption, true
	}
}

// shrinkDocxImage 把大图缩到长边 1600 的 JPEG；失败返回 false 由调用方用原图。
func (s *Server) shrinkDocxImage(data []byte) ([]byte, bool) {
	f, err := os.CreateTemp("", "pojun-embed-*.img")
	if err != nil {
		return nil, false
	}
	src := f.Name()
	defer os.Remove(src)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return nil, false
	}
	if err := f.Close(); err != nil {
		return nil, false
	}
	dst := src + ".jpg"
	defer os.Remove(dst)
	if err := writeThumbnail(src, dst, 1600); err != nil {
		return nil, false
	}
	out, err := os.ReadFile(dst)
	if err != nil || len(out) == 0 || len(out) >= len(data) {
		return nil, false
	}
	return out, true
}

// taskCustomerNames 任务关联企业名（封面「委托方」行；A12）。
func (s *Server) taskCustomerNames(t *Task) string {
	if len(t.CompanyIDs) == 0 {
		return ""
	}
	names := make([]string, 0, len(t.CompanyIDs))
	for _, id := range t.CompanyIDs {
		c, err := s.m.pg.Companies().GetCompany(id)
		if err != nil || c == nil {
			continue
		}
		names = append(names, c.Name)
	}
	return strings.Join(names, "、")
}

// taskTestWindow 测试窗口描述（封面/方法论章节；A12）。
func taskTestWindow(t *Task) string {
	if t.FirstRunAt <= 0 {
		return ""
	}
	start := time.Unix(t.FirstRunAt, 0).UTC().Format("2006-01-02 15:04 UTC")
	if t.CompletedAt > 0 {
		return start + " ~ " + time.Unix(t.CompletedAt, 0).UTC().Format("2006-01-02 15:04 UTC")
	}
	return start + " 起（任务未收尾，数据截至报告生成时刻）"
}

// exportFindingDocx 单漏洞报告(Word)。
func (s *Server) exportFindingDocx(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	f, err := s.m.pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	names := s.reportAssetNames([]*db.DBFinding{f})
	retests, _ := s.m.pg.ListFindingRetests(f.ID)
	customer := ""
	classification := ""
	if f.TaskID != nil && *f.TaskID > 0 {
		if t := s.m.ResolveTask(strconv.FormatInt(*f.TaskID, 10)); t != nil {
			customer = s.taskCustomerNames(t)
			classification = "内部资料 · 仅限授权方"
		}
	}
	doc := report.BuildFindingDocx(report.FindingDocxInput{
		Finding:        f,
		GeneratedAt:    time.Now(),
		AssetNameMap:   names,
		Retests:        retests,
		Customer:       customer,
		Classification: classification,
		ArtifactImage: func() func(int64) ([]byte, string, bool) {
			if f.TaskID == nil || *f.TaskID <= 0 {
				return nil
			}
			// 单漏洞报告严格只嵌归属本漏洞的图（v0.4.20）：不再回退任务级图；
			// 历史照片可在任务「证据附件」里批量改归属。
			return s.artifactImageResolver(strconv.FormatInt(*f.TaskID, 10), f.ID)
		}(),
	})
	name := fmt.Sprintf("pojun-finding-%d-%s.docx", f.ID, time.Now().Format("20060102"))
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.WriteHeader(200)
	_ = doc.Encode(w)
}
