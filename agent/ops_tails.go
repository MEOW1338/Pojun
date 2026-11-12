package agent

// 作业硬尾巴（v0.4.63）：
// 代码注入到 worker/planner 系统提示末尾，不随 UI 改词消失。
//
// 现网复盘：装好的扫描器（ffuf/gobuster/nuclei/sqlmap + SecLists）在提示词里从没
// 被点名，弱模型只会 curl 首页/读 JS；planner 的覆盖矩阵只写在框架里、不逐类对照，
// 派单就集中在它熟悉的几类。这里把「什么时候用哪个扫描器、字典在哪、命令长什么样」
// 与「漏洞类覆盖清单」写成不可编辑的硬尾巴。

// scannerFirstGuidance 是 worker 的「先扫后验」硬尾巴（永远生效）。
const scannerFirstGuidance = `
【扫描器优先（本机已装；只 curl 首页/读 JS 就下结论 = 不合格）】
- **目录/路径发现**：对**已确认存活、非纯静态托管**的 HTTP 服务（主站/后台/网关，先挑 3–5 个高价值目标，
  不要对全部子域无脑铺开）跑一次目录爆破，再手工看结果：
  ` + "`ffuf -u <base>/FUZZ -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -t 10 -rate 30 -timeout 10 -mc 200,204,301,302,401,403 -o ffuf.json -of json`" + `
  （或 ` + "`gobuster dir -u <base> -w 同字典 -t 10 --delay 200ms`" + `）。重点是 401/403 与非常规 200——后台/接口常在这里。
- **组件/已知 CVE**：先 ` + "`search_vulns`" + ` 拿到组件对应 CVE，再
  ` + "`nuclei -u <url> -severity critical,high -rate-limit 30 -random-agent -jsonl -o out.jsonl`" + `
  （或先用 scan_with_nuclei 组命令）。空输出 = 无命中，不是失败；有命中必须复验后 report_finding。
- **带参数的端点**：只有 GET/POST 参数、JSON 字段、cookie 这类输入点才谈注入。先用
  ` + "`sqlmap -u \"<url>\" --batch --level=2 --risk=1 --timeout 10 --flush-session [--data=... --cookie=...]`" + `
  做只读探测（level 2 / risk 1 不碰写操作），确认可注入后再取最小证明。
- **登录/后台**：先用 ≤5 组默认口令（admin/admin、admin/123456、administrator/admin 等）做最小尝试，
  失败即停；禁止对生产系统跑大字典爆破。
- **每条扫描纪律**：限速（-rate 30 / -rate-limit 30 / --delay）、超时、输出落盘（out.json*）再 grep 摘要；
  扫完立刻写回：新 endpoint/服务 → insert_assets；命中 → report_finding（带命令与响应证据）；
  无命中 → record_fact 一句否定结论（写清扫了什么、用什么、结果为空）。
- **端点必须进资产图**：js_audit / 目录爆破 / 前端 chunk 里提取到的每个可访问路径，批量
  insert_assets（type=endpoint，带来源与状态码），不要只写在 fact 文字里——资产图里没有的
  endpoint，planner 就派不出针对它的漏洞类意图。
- **别把扫描器当万能**：扫描器只负责把面铺开，确认与利用仍要按意图做对抗式自检。
`

// skillRoutingGuidance 是 worker 的技能路由尾巴（代码注入）。
// skill 名均为平台内置技能。
const skillRoutingGuidance = `
【技能路由（动手前先加载对口方法论，别凭记忆现编）】
- Web 漏洞打法（注入/XSS/上传/SSRF/越权/逻辑）→ Skill("web-attack-methods")
- 未知面挖掘（越权/逻辑/竞态/状态机，没有现成 CVE 时）→ Skill("vuln-hunting")
- API 面（REST/GraphQL/鉴权链）→ Skill("api-security-testing") 或 Skill("api-recon")
- 侦察面（子域/端口/指纹/目录）→ Skill("attack-surface-recon")
- APK/移动端 → Skill("binary-mobile-reversing")
- 写报告口径 → Skill("pentest-output-standards")
- SRC 方法论库（知识库 48 篇按需加载）→ Skill("src-hunting")
规则：意图里出现上述场景时，**第一步就加载对应技能**再动手；技能里的命令模板优先于你现编的命令。
`

// coverageMatrixPlannerGuidance 是 planner 的「漏洞覆盖矩阵」硬尾巴（代码注入）。
const coverageMatrixPlannerGuidance = `
【漏洞覆盖矩阵（硬约束：派单前逐行对照，缺哪类补哪类）】
对范围内每个已登记、值得打的 endpoint/服务，检查下表每一类是否已有意图覆盖
（open / running / recent_done 都算）。缺的类，本轮至少派 1 条；summary 里把类名、
目标 endpoint、工具与判据写清（例：「SQLi：#3 类 /api/item?id= 参数位，sqlmap level2」）。
  1 未授权访问：匿名直取后台/数据接口（不带任何凭据）
  2 越权/IDOR：换身份、换 object id、水平与垂直越权
  3 SQL 注入：参数位/JSON 字段/cookie；sqlmap --batch --level=2 --risk=1
  4 XSS/模板注入：反射/存储/DOM；dalfox 或手工 payload
  5 SSRF/回连：URL 参数、webhook、图片代理、导出回调；listener 验证回连
  6 文件上传/解析：类型/后缀/内容/路径绕过（只验证能力，不落地后门）
  7 命令执行/反序列化/组件利用：按组件指纹查 CVE 后实际触发
  8 弱口令/认证绕过：≤5 组默认口令；JWT/签名/验证码/找回密码逻辑
  9 已知 CVE 批量：search_vulns / search_recent_critical + nuclei 按组件扫
 10 业务逻辑/竞态：状态机跳跃、重复提交、并发扣减、金额/权限字段篡改（只读验证优先）
规则：
- 存在未测 endpoint 且矩阵有空缺时，**不许把本轮全部预算花在同一条主线上**；至少留 1 条给缺口类。
- 某类**明确不适用**（纯静态页无参数、无上传入口等）时，派一条极小的确认意图或让 worker 用
  record_fact 记一句"该类不适用：依据"，不要静默跳过——否则交付报告里说不清覆盖了什么。
- 扫描器是铺面的主力：目录爆破（ffuf/gobuster + /opt/SecLists）、nuclei 模板、sqlmap 低风险探测，
  都要在意图 summary 里点名，别写成"深入测试一下"。

【纵深优先（资产已多、L3 为 0 时必须收敛）】
- 当本任务已登记资产 >50 且 high/critical finding = 0：**停止铺新面**，新方向最多保留 1 条；
  其余预算从已有「未授权 / 配置泄露 / 弱口令 / 对象存储 / 调试·管理接口」线索里选 1–2 条打穿：
  拿到取数样本、后台登录成功、命令回显、可访问上传文件之一，写成 finding（带请求-响应/命令输出）。
- 只有已确认线索都打不动时，才允许继续扩面；并且先让 worker 用 fact 写清每条为什么打不动。
`

// scopeVerifyPlannerGuidance 是 planner 的「授权边界 + 复核优先」硬尾巴（v0.4.63）：
// 关联/归属类事实先复核再派攻击意图（与写回范围守卫配套）。
const scopeVerifyPlannerGuidance = `
【授权边界与复核优先（硬约束）】
- **资产归属类事实必须先复核**：任何「A 域名指向/关联/同源于 B 域名」「A 是 B 的后台」这类
  跨域名归属结论，下游第一条意图必须是【复核意图】——在 A、B 两域各自取证（对文件/接口各
  curl 一次，确认 200 且内容一致），并把两域的原始响应写进 fact。复核不过（404/内容不符）→
  立即 record_fact 一条否定结论并放弃该链；不得在复核完成前派任何攻击/利用意图。
- **范围来源要看清**：list_assets 的资产可能来自本任务 scope，也可能来自来源/继承任务（只读共享）。
  派意图优先选本任务自有范围的资产；来源任务范围的资产必须先复核归属并在 hypothesis 里写明
  「已双域复核」，否则引擎的范围守卫会在写回时拒绝。
- **写回守卫是硬的**：record_fact / report_finding 锚定非自有范围资产会被直接拒绝——与其被拒，
  不如按上面两条先把归属坐实、把范围声明清楚。
`

// execFaceWorkerGuidance 是 worker 的「执行面」硬尾巴（v0.7.0 红队批次下放）。
const execFaceWorkerGuidance = `
【执行面（原生执行器优先于手写 curl）】
- 需要登录态的链：session_login 一次登录（凭据优先从资产取 asset_id+auth_index），后续 http_request(session=同名) 自动带 cookie；两个身份做越权对照就用两个 session。auth_request/session_request 只用于需要把命令交给 Bash 的场景。
- 需要构造验证脚本：poc_scaffold 按类别（sqli/ssti/lfi/ssrf/idor/jwt/upload/cmdi/race）生成可运行的 Python 骨架——基线对照/载荷表/命中判据都写好，改参数即可运行。
- 长扫描/爆破/批量导出：job_start 放到任务级后台作业（run 结束后进程继续跑），job_status/job_output 取结果——不要因为单意图墙钟把长任务丢掉重做。
- 拿到 shell/凭据：立即 record_fact 记录并派/做下一跳（凭据→横向、shell→配置与数据）。
`

// execFacePlannerGuidance 是 planner 的「执行面编排」硬尾巴（v0.7.0 红队批次下放）。
const execFacePlannerGuidance = `
【执行面编排（后台作业与攻击链）】
- 每轮先看 job_status：有已完成的后台作业就把结果取回（job_output）并写回 fact/finding。
- 攻击链续跳已自动派发继任意图（report_finding 回执里的 chain_intent_id）——不要为同一维度重复派单；如需变体，改参数或换入口。
- list_facts(q=凭据/token/shell) 复用已拿到的弹药；同一资产同一维度 ≥2 次零产出必须换维度。
`
