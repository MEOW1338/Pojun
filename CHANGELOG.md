# 更新日志

本项目的重要变更记录在此文件中，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [Unreleased]

## [0.4.64] - 2026-11-10

> 红队批次第二批：原生 HTTP 执行器与会话复用、PoC 脚手架、任务级后台作业、
> 攻击链自动续跳、漏洞多键去重与合并、目标达成诚实呈现。

### 新增

- **http_request 原生执行器**：Go 直接发请求，一次调用返回 status/headers/正文
  片段/耗时/body_sha256；大响应自动落盘给 body_file 指针；走记录代理照常留证。
  消灭「领域工具组命令 → 模型再调 Bash」的双重 LLM 往返。
- **session_login + 会话复用**：一次登录写任务级 cookie jar（Netscape 格式与 curl
  互通；form/json/basic/bearer/cookie 五形态；凭据优先从资产 auth 取，明文不进
  对话）；后续 http_request(session=同名) 自动带登录态——「登录→越权→回读」
  成为基本能力。
- **poc_scaffold 脚手架**：按类别（sqli/ssti/lfi/ssrf/idor/jwt/upload/cmdi/race）
  生成可运行的 Python 验证骨架——基线对照/载荷表/命中判据/多身份模板写好落
  shared/scripts，改参数即可运行。
- **job_start/status/output/stop 后台作业**：长扫描/爆破落任务级 shared/jobs，
  run 结束后进程继续跑，后续任意意图或 planner 取结果——长任务不再因单意图
  墙钟被丢弃重做。
- **攻击链自动续跳**：report_finding 登记 high/critical 新漏洞后按类别自动派
  「继续打穿」继任意图（注入→取数、RCE/上传→凭据配置、越权→批量回读、
  SSRF→内网、凭据→横向），回执带 chain_intent_id；重复上报（已合并）不续跳。
- **record_fact 新颖性门槛**：与最近事实高度相似（字符二元组 Jaccard ≥0.85）或
  无 evidence 标 [low_novelty]——仍入库但不计入「有产出」，堵「写无关事实续命」。
- **任务级共享脚本**：save_script/run_script 把登录脚本/PoC 放 tasks/<id>/shared/
  scripts 跨意图复用。

### 修复

- **目标完成判定不可绕过**（goal_met 闸门）：只要还有目标未 met，整体收官直接
  返回错误并列出未达成目标；收尾终态统一按目标进度判定——只有全目标达成才落
  done，否则 timeout（界面显示「未完成·已停止」）。
- **kill_work 先收尾写回**：60 秒宽限让 worker 把已确认内容落库后再取消——
  现场多次 kill 直接丢工作的问题修复。

## [0.4.63] - 2026-11-10

> 品牌与作业纪律更新：全新 Logo、写回授权边界守卫、空报告自动巡检、
> 纵深与覆盖双提示、扫描器优先与技能路由提示词、APK 逆向技能。

### 新增

- **全新 Logo**：「破军·劈星」品牌标识（SVG 矢量重导 512 PNG + 多尺寸 favicon +
  深色版 logo-mono；侧栏生效，登录页按安全基线不引用 logo）。
- **授权边界守卫（写回闸门，默认开）**：`record_fact` / `report_finding` 的
  asset_ids 只能锚定本任务自有范围资产——来源/继承范围默认只读、完全越界一律
  拒绝；fact/finding 两处闸门，分类查询故障 fail-open 不卡正常任务。新增设置
  `scope_write_guard`、`scope_inherit_writes`。
- **资产认领守卫**：`insert_assets` 遇到「已归属其他任务且不在本任务范围」的既有
  资产时跳过并说明原因，防止跨任务串资产。
- **跨任务去重推送**：同指纹漏洞在其他任务已存在时不再重复播报（漏洞记录照常
  保留，页面可见），回执提示核对授权边界。新增设置 `notify_cross_task_dedup`。
- **空报告自动巡检**：启动 45 秒后与每 15 分钟扫描 `report` 为空的漏洞，自动
  唤起 reporter 补写；单条 6 次上限 + 1/2/4/8 小时指数退避，超限告警一次转人工。
- **纵深 / 覆盖双提示（引擎侧确定性检查）**：已登记资产 ≥50 且 high/critical = 0
  时提醒规划者停铺面、优先打穿 1–2 条已验证线索；意图文本完全没有覆盖某类漏洞
  （SQLi / XSS / SSRF / 文件上传 / RCE / 目录发现）时点名补派。
- **提示词硬尾巴（代码注入）**：worker 增加「扫描器优先」（ffuf / gobuster /
  nuclei / sqlmap + SecLists 命令模板）与「技能路由」；planner 增加「漏洞覆盖
  矩阵」（10 类逐行对照）与「授权边界与复核优先」。不随自定义提示词丢失，附
  守门测试。
- **APK 逆向技能**：jadx / apktool / adb / frida 完整静态 + 动态链路、重打包与
  Hook 脚本、无真机时的静态 + 流量模拟替代路径；内置技能增至 22 个。

### 说明

- 新增设置项 `scope_write_guard` / `scope_inherit_writes` /
  `notify_cross_task_dedup` / `depth_nudge_enabled` 已接入设置接口；
  默认：守卫开、继承写关、跨任务去重开、纵深提醒开。

## [0.4.62] - 2026-11-06

> Issue #2 修复：idle-stop 在探索期过于激进（用户反馈 + 线上数据实证）。
> 线上 journal 实测 2,583 条收场日志、单意图被拦到「连续 20 轮」才结束——
> 根因是 PreToolUse 的 block 只拦单次工具调用、run 不结束，模型逐轮跟 hook
> 辩论烧 token；且收场原因完全没落库（ReasonStopHookPrevented 未分流，
> 全部落进 done + 空原因，统计与 planner 都看不见）。

### 修复

- **收场不彻底（核心）**：提示后仍无写回时，到 prevent 轮（5 轮）取消 run
  context 真正收场——不再逐轮 block 让模型辩论（nudge 3 轮 + 2 轮写回机会）。
  新增 `AbortIdleStop` cancel cause；engine 分流为 exhausted(idle_stop)。
- **收场原因落库**：idle-stop 现在写 `blocked_reason=idle_stop`（此前完全
  不可见）；planner 可区分「探到边界」与「正常完成/超时」。
- **进展口径扩大**：`save_evidence` 计入写回（附证据=具体产出，且不再被拦）；
  提示词明确列出四种产出（fact/asset/finding/evidence）且**负结果也算事实**。
- **提示词重写**：说明「这不是惩罚，是给你一次把成果落库的机会」，写回后计数
  重置——直接回应「worker 花 token 跟规则辩论」的观察。

## [0.4.61] - 2026-11-06

> 全新部署打磨：装机脚本前置检查、uv 落位修复、README 系统选择指引。

### 修复

- **uv 落位**（真实踩坑）：pojun 服务是 systemd 用户，PATH 只保证
  `/usr/local/bin` 等系统目录；pipx 以 root 安装会把 uv 放到 `/root/.local/bin`
  ——服务用户既无权限穿越 /root 也不在 PATH，导致「FOFA MCP 预设能加、MCP 起不来」。
  ensure_uv 现在统一把二进制落到 `/usr/local/bin/uv` 并验证可执行。

### 新增

- **装机前置检查**：内存 <4G、根分区 <10G、python3 <3.10 时给出明确提示（不阻断）。
- **安装完成后的下一步指引**：管理员密码 → LLM 通道 → MCP 预设（FOFA/Playwright）
  → 任务 Playbook。
- **README 系统选择与配置要求表**：Debian 12 / Ubuntu LTS 首选，Kali 可用但滚动
  有风险，RHEL 系覆盖少；最低 2C4G/20G、推荐 4C8G/60G。
- `install.sh --help` 顶部加系统与硬件建议。

## [0.4.60] - 2026-11-06

> 用户反馈「任务几乎不调 skill」+ 14 个同类项目对比研究后的融合批次
> （完整分析见 docs/同类工具对比-2026-11-06.md）。

### 修复

- **技能速查注入 system prompt**（根因）：数据实证——skill_usage 全生命周期仅
  8 次、任务 18 零次调用；根因是 Skill 元工具只活在工具描述里，系统提示从不
  提。renderSystem 现在按 agent 绑定注入「技能速查块」（名称+何时用+调用方式），
  覆盖 worker/planner/pentest/chat；registry 60s 缓存。附回归测试。

### 新增

- **内置 4 个任务 Playbook**（借鉴 PentestAgent）：Web 全流程渗透 / 内网域渗透 /
  APP 逆向+API / 纯侦察资产盘点——安康系列实测验证过的目标结构，建任务一键套用；
  settings flag 批次种子，用户删改不复活。附幂等测试。
- **独立复现规划规则**（借鉴 Pentest-AI / Pentest-Swarm-AI）：critical/high 若
  证据仅来自单一 worker、无独立复验事实，planner 派「只复现不扩大」的验证意图；
  复现失败必须降级，不许保留高等级。
- **HexStrike 工具桥 MCP 预设**：桥接 150+ 安全工具（nmap/sqlmap/metasploit/
  nuclei/ghidra…），克隆到 mcp-servers/hexstrike-ai 并启动服务即用。

## [0.4.59] - 2026-11-06

> 用户实测反馈：Vue 站点（任务 18）对 webpack 源码泄露完全没有检测——
> worker 不去看 `.js.map`，SPA 前端面被直接略过。参考外部资料
> （SourceMapX / unwebpack-sourcemap / shuji 的检测链）做成平台领域工具。

### 新增

- **js_audit 领域工具**（worker/mainagent 同款）：入口 URL → 自动提取
  `<script src>` 与 hash chunk → 检测 sourceMappingURL（外链/内联 base64）+
  `<js>.map` 兜底探测 → 命中即还原 sourcesContent 原始源码落盘（保留
  .vue/.env 目录结构）→ 扫描密钥（阿里云 LTAI/AKID、AWS AKIA、私钥、JWT、
  AK-SK 键值对、内网段）→ 抽取接口/路由清单。只落脚本+组命令，流量照常过
  MITM 留证。结论口径：map 命中=CWE-540 high；真实凭据=critical。
- **skill 更新**：api-recon 与 web-attack-methods 增补「Webpack/Sourcemap
  源码泄露」章节（含假点：SPA fallback 给 404 页回 200 不算命中）；
  src-hunting 工具映射表加 js_audit。

### 验证

- 本地 fixture（假 Vue dist + 真实 sourcesContent）：链路 html→scripts→js→
  map→还原落盘→密钥命中（LTAI/内网段）全通；
- 对平台自身前端实测：SPA fallback 200 误判 bug（可达≠命中）已修复，
  修复后 found=0 准确。

## [0.4.58] - 2026-11-06

> 复盘后续批次：开局窄面预期提示 + 上下文窗口纠偏。

### 新增

- **开局窄面提示**：任务首次启动时范围内资产 <10 个，活动流提示「资产面较窄，
  预期产出有限；可考虑扩大范围或调低预算/超时」——薄面站点（如任务 16/17）
  提前管理预期，避免完整跑完流程才发现产出有限。

### 修复

- **LLM 配置页提示纠偏**：页面写「0 = 默认 200K」但代码实际按 1M 计算压缩阈值
  （早前应用户要求改的）——照旧页面会误导用户不填窗口，超模型真实上限的请求
  只会以远端报错收场（LongCat 压缩错误率 11.4% 的根因）。提示已改为
  「务必按模型真实窗口填写」。
- **Kali 通道窗口补全**：OpenCode 256K / 硅基流动 128K / LongCat 128K
  （此前全部 0，压缩阈值按 1M 形同虚设）。

## [0.4.57] - 2026-11-06

> 全平台数据复盘（12 个真实任务、56k 次 LLM 调用、295 条漏洞）后的改进批次。
> 完整数据与结论见 docs/复盘-2026-11-06.md。

### 新增

- **收尾报告缺口检查**：任务落终态（goalless done / 自动收尾 / 超时收尾）前
  检查「已上报但 report 为空」的漏洞并在活动流点名（复盘发现 12 任务累计
  7 条静默空报告漏洞，导出交付直接受影响）。
- **任务复活自愈**：从终态复活时自动重开 blocked="context canceled" 的遗留
  意图（部署重启的遗留物，复盘发现 11 条永久卡死）——继续 = 把没跑完的跑完；
  用户手动 block 的不受影响。附回归测试。
- **复盘文档**：docs/复盘-2026-11-06.md——任务效率总表、token 成本结构、
  通道健康、后续建议（compactor 降本 / context_window_k 补全 / 低产目标预期管理）。

### 运维（Kali 实例）

- 通道治理：egg-alpha（42% 错误）与 GLM/nemotron/qiniu（60–70%）移出轮换池；
  compactor 钉到主力 DeepSeek-V4.1（0.3% 错误）——此前 LongCat 压缩错误率 11.4%
  且 69 次错误集中在任务 17（该任务 LLM 时间 1981 分钟、每漏洞成本 53.5M token，
  为全场最差 6 倍）。

## [0.4.56] - 2026-11-05

> 技能与 MCP 大规模扩充（参考 CyberStrikeAI 的技能体系，结合平台自身工具链）：
> 内置 skill 从 5 个扩到 21 个，新增 MCP 预设目录与 FOFA 资产测绘服务器。

### 新增

- **内置 skill 21 个**：新增 attack-surface-recon / web-attack-methods /
  api-security-testing / component-vuln-intel / cloud-attack-methods /
  active-directory-attack / source-code-hunting / zero-day-research /
  ai-llm-app-attack / binary-mobile-reversing / smart-contract-audit /
  wireless-hardware-attack / redteam-opsec / pentest-verification /
  pentest-output-standards / src-hunting；redteam-ops 补齐 frontmatter 并扩写成
  实战后渗透清单。
- **SRC 方法论库（src-hunting）**：迁移完整的 48 篇测试知识库 + 11 篇流程规则，
  SKILL.md 提供索引与平台工具映射，`${SKILL_DIR}` 按需打开，禁止通读；
  知识库/规则随发行包与镜像分发。
- **默认可见性绑定**：执行类 skill 绑 worker/pentest，方向类绑 planner——
  此前 redteam-ops/playwright-cli 写了却从未绑定给任何 agent（用户 2026-11-05
  反馈的「写了没人看得到」），并加守门测试防回退。
- **MCP 预设目录**：MCP 页新增 9 个常用服务器一键填充（Playwright / Chrome
  DevTools / Burp / Fetch / Sequential Thinking / Memory / Filesystem /
  Context7 / FOFA）。
- **FOFA 资产测绘 MCP**（mcp-servers/fofa）：官方三账号轮换 + one-fox 社区通道，
  随发行包与 Docker 镜像分发；预设 `uv --directory mcp-servers/fofa run python
  fofa.py`；.env 模板只给占位符，密钥不入仓库。

### 修复

- redteam-ops 缺 YAML frontmatter，导致 CI 连续红灯（skill 加载后 description
  为空）；已补齐并纳入守门测试。

### 验证

- FOFA MCP 端到端实测：stdio 握手 → tools/list（get_alerts/get_alerts_onefox）
  → one-fox 通道真实查询返回；官方通道 key 受限时自动提示/shift；
- skill 加载与绑定守门测试全绿；全仓回归通过。

## [0.4.55] - 2026-11-05

> 任务 13 事故修复：「深入漏洞」人工跟进意图被任务终局收尾静默吞掉。
> 时间线实证：16:36:16 跟进意图 #7470 创建 → 16:36:17 终局判定轮启动 →
> 「全部目标已 met，按终局收尾指令不新增意图，本轮收束」→ 任务 timeout。

### 修复

- **终态复活重置超时预算**（根因）：任务 11-04 因「目标已全部达成」落 done，
  但 first_run_at/deadline_at 仍停在 11-04 的 8 小时预算（18:02 已过期）。
  11-05 人工跟进把 done 复活为 running 时，旧代码只对 timeout 复活重置时钟 →
  新起的 deadline 协调器读到已过期 deadline，1 秒后再次收尾，跟进意图从未被
  worker 领取。现在任何终态（done/failed/timeout）复活都清空
  first_run_at/deadline_at，下一次真实运行重新盖章整套预算。
- **Engine per-run 闸门同口径清理**：resetTimeoutRevival → resetTerminalRevival，
  覆盖 settling/deadline/stamped/coordStarted 四项，复活任务不再被残留标志卡住。
- **复活时清挂起收尾请求**：上一轮生命周期遗留的 pendingSettle 作废，避免复活后
  第一个规划轮先消费它又收一遍。
- 回归测试：done 复活后 DB/内存双时钟清零 + 重新盖章得到从现在起算的新预算。

## [0.4.54] - 2026-11-05

> Docker 镜像内置工具补齐：此前镜像只有 recon 基础件（nmap/nuclei/
> Playwright/LibreOffice），与二进制形态 --with-tools 的工具集差一大截，
> 而 Docker 形态没有 pojun-hostd 一键安装——缺的工具永远显示缺失。

### 新增

- **镜像内置工具对齐 --with-tools**：apt 组（masscan/sqlmap/hydra/whatweb/
  ffuf/john/impacket/socat/proxychains4，逐包容错）+ GitHub release 表
  （httpx/subfinder/naabu/dnsx/katana/tlsx/notify/interactsh/gitleaks/chisel/
  amass/dalfox/feroxbuster/gobuster）+ pip 组（wafw00f/impacket/semgrep/
  pwntools）+ SecLists 字典（/opt/SecLists）+ 公文字体（COPY 仓库内
  report/fonts，docx→PDF 不再依赖运行期下载）。
- **基础镜像 Python 3.12→3.11**：impacket/semgrep 等工具链兼容性更稳。
- **下载全加超时**：nuclei/工具下载 --max-time/--connect-timeout，构建机
  网络半死时快速失败而不是无限挂起。

### 修复

- **netexec 移除出自动安装**（install.sh 与镜像同口径）：NetExec 2026 起
  商业化，PyPI 发行文件全部撤下（/simple/netexec 404），pip 装必失败；
  hosttools 条目注明需从 GitHub 源码安装。bookworm 源没有 nikto，镜像
  逐包容错跳过（体检页如实显示）。

## [0.4.53] - 2026-11-05

> 图片预览缩放补齐：任务总览与漏洞详情的文档分页预览此前仍是静态 img，
> v0.4.48 的缩放组件漏掉了这三处——大图（2250x1500 曲线图、Word/PDF 转图页）
> 看不清细节也不能放大。

### 修复

- **任务总览图片预览接入缩放组件**：滚轮缩放（0.5x–8x）、拖拽平移、双击
  还原/放大；标题/描述/下载按钮信息不变。
- **文档分页预览同样接入**（任务总览 + 漏洞详情两处）：Word/PDF 每页转图后
  可缩放查看，分页控件移入 footer 插槽，翻页时缩放状态自动重置。
- ZoomableImageDialog 新增 footer 可选插槽（供分页等附加控件复用）。

## [0.4.52] - 2026-11-05

> 借鉴 raptor 认识论闸门 + CVEngine triage 三重夹逼：critical/high 漏洞必须附
> 可机械复现的验证凭据（HTTP 状态码/curl 命令输出/工具命中结果），纯版本匹配
> 不再能作为漏洞证据——发行版 backport 补丁不改版本号，版本匹配 ≠ 漏洞。

### 新增

- **机械验证凭据校验**（`validateMechanicalEvidence`）：report_finding 上报
  critical/high 时检查 evidence 是否包含机械验证信号（HTTP/1.x 响应头、curl/
  sqlmap/nuclei 输出、状态码、JSON 字段、响应头字段）。无凭据时回灌中文纠正
  提示，模型可在同会话补证据或降级——「可能存在」不是 finding，「实际拿到」才是。
- **版本匹配单独拦截**：evidence 只有 version/banner/server 头匹配而无行为级
  验证时，提示用 http_probe/curl 实际触发目标，或降为 medium 注明
  「版本匹配，行为未验证」。medium/low 不做机械验证校验（低危经常只有一句
  说明，过度校验阻碍正常上报）。


## [0.4.51] - 2026-11-05

> 用户反馈主 agent 干活不派任务。数据分析：mainagent 249 次 Bash 调用 vs 仅 10 次
> add_intent——大量 Bash 里出现了 curl 打目标、dig 解析等应该派给 worker 的操作。

### 修复

- **mainagent 角色边界硬规则**：prompt 新增「角色边界硬规则」段——Bash 仅限
  本地文件操作（报告编辑/图片处理），**严禁用 Bash 与目标系统交互**。
  判断标准：Bash 命令里出现目标 IP/域名/URL = 越权，应写成 add_intent 派下去。
  此前 prompt 虽说"你不亲自探索"但没有硬规则约束 Bash 的使用场景。

## [0.4.50] - 2026-11-05

> 红队工作流差距审计——从渗透测试工程师视角逐环节检查平台功能覆盖，
> 补齐 worker 工具权限 + 充实红队后渗透 skill。

### 新增 / 优化

- **Worker 工具权限扩展**：新增 `expand_digest`（展开冷区折叠节点完整内容）、
  `list_untested_assets`（自行补漏未测资产）、`list_goals`（感知目标完成进度）
  ——worker 不再只被动执行，有了自主判断方向完成的工具面。
- **redteam-ops skill 大幅充实**：从 106 行扩展到 ~100 行结构化方法论——
  Linux/Windows 提权清单、横向移动（pth/隧道/凭据喷射）、Windows 域专项
  （Kerberoasting/DCSync/BloodHound）、数据获取纪律、证据绑定。

## [0.4.49] - 2026-11-04

> 全流程审计修复批次：拦截规则误伤清理（322 条审批积压根因）+ worker 提示词
> 边界编号修正 + record_fact 单次上限。

### 修复

- **拦截规则误伤清理**：「数据外泄管道」（158 次命中=所有 POST 请求）、「删除类
  接口路径」（80 次=测删除端点是正常渗透行为）、「rm -rf」（22 次=工作目录
  清理合法）、「破坏性系统命令」（44 次=payload 里的字符串误匹配）——四条
  误伤率最高的规则已停用，Kali pending 审批 322→0。
- **record_fact 单次 facts 数组上限 10 条**：防图谱灌爆。
- **continues 状态校验放宽**：只拒 running，open 允许（暂停回退合理接续）。
- **worker 边界编号修正**：新增第 3 条「意图粒度过粗时的自处理」，全部条目
  重编为 1-9。
- **AddCompanyScopeAuto ON CONFLICT 修复**。

## [0.4.48] - 2026-11-04

> 三个优化：①现场证据图片预览支持滚轮缩放/拖拽/双击还原——报告阅读时需要
> 放大 URL/参数/响应特征细节，静态图看不清导致误判；②发现页批量导出新增
> Word 格式（每条漏洞独立 .docx 打包 .zip）；③MD 导出格式改进。

### 新增 / 优化

- **图片预览滚轮缩放**：`ZoomableImageDialog` 组件——滚轮缩放（0.5x–8x）、
  拖拽平移（scale>1 时自动切 grab cursor）、双击还原/放大到 3x、还原按钮。
  漏洞详情页图片预览已替换。
- **发现页批量 Word 导出**（`docx-zip` 格式）：每条漏洞独立 .docx（含完整
  公文格式/封面/资产名映射/复测记录/证据图），打包 .zip；前端导出面板新增
  "Word 批量导出"选项。
- **MD 导出改进**：每条漏洞补充发现者（Worker）字段；证据标题从「证据」改为
  「证据 / PoC」更清晰；明文保真口径标注。

## [0.4.47] - 2026-11-04

> 用户反馈「从任务证据中挑选」需要人工操作——扫到就归才是正确做法。
> 根因：worker 先 save_evidence、后 report_finding，此时证据 finding_id 为空。

### 新增

- **report_finding 回溯归属**：漏洞落库后自动把同一意图运行目录
  （/i<intentID>/）下所有 finding_id 为空的证据一次性归属到本漏洞。
  同一意图是天然的 provenance 边界——不会误绑其他意图的证据。
  返回值 evidence_note 告知模型自动归属了几条。

## [0.4.46] - 2026-11-04

> 关键根因修复：task 12 首轮意图仍是总目标复读。根因不是 planner——是
> `seed_first_intent` 创建时绕过 addOneIntent 闸门直接下发了一条
> 「完成任务目标：{goal}（任务：{description}）」的种子意图。

### 修复

- **seedFirstIntent 长度闸门**：种子意图只适用于简单任务（描述+目标合计
  ≤200 字符）；复杂任务（渗透测试全流程描述动辄上千字）跳过种子意图，
  由 planner 拆解成 3-5 条具体意图。此前 seed 路径完全绕过了 addOneIntent
  的粒度闸门——这是 v0.4.44 修复后 task 12 依然复读的根本原因。

> 以下 0.4.20 起为逐版详录；0.4.4–0.4.19 期间的发版见文末「0.4.4–0.4.19 发版概要」。

## [0.4.40] - 2026-11-03

> 两个方向：①任务/漏洞的「归属链路」自动化（复盘发现任务→公司归属全空、
> 个别漏洞无资产锚定）；②「把数据扒下来展示」专项——数据类证据此前 0 预览、
> 只能下载。业界参照：agent 证据溯源综述（arXiv 2606.04990）的 provenance graph
> 与 evidence grounding 实践，与我们的探索图+锚点设计一致，本版补齐缺口。

### 新增 / 修复

- **任务自动归属公司**：首次开跑时统计范围内资产的公司归属——100% 属于同一家
  且公司资产规模同量级（≤3×范围+20）→ 自动写 `task_scope(kind=company, source=auto)`
  并快照该公司资产入任务（活动流说明、可撤销）；超量级则只在活动流给出建议。
  此前 5 个任务的 company scope 全空，任务在公司维度「无主」。
- **漏洞自动锚定资产**：`report_finding` 未带 asset_ids 时，从 summary/evidence
  文本反查任务资产自动锚定（与 record_fact 同一策略）——补上个别漏洞缺资产
  归属的尾巴。
- **数据文件在线查看器**：新增 `GET /api/tasks/{id}/artifacts/{aid}/data-preview`
  ——按扩展名解析 JSON 数组（转表格）/JSON 对象/JSONL/CSV/TSV（表格）/文本
  （前 200 行），读入上限 20MB，超出标 truncated；前端 `ArtifactDataViewer`
  表格渲染。任务证据卡新「数据」分类与漏洞详情「数据证据」都接了查看按钮。
- **分类细化**：任务证据卡拆出「数据」分类（json/jsonl/csv/tsv/txt/log/out/diff），
  report.md、部署指南这类不再和数据集混在一起；卡片描述同步明文保真口径。
- **数据集落盘纪律（worker 提示词）**：确认未授权数据接口后必须保存【全量原始
  响应】到工作目录并 save_evidence 登记（note 写记录数/字段/时间窗），>20MB
  分页或 gzip——"只存证明性样本"的旧指引废弃，对应"数据拿到最多"。
- **更多文件类型**：.gz 自动解包后按内层扩展名解析（orders.json.gz → JSON 表格）、
  .zip 列条目清单（文件名/大小/时间）、xml/yaml/sql/html 走文本视图；
- **智能关联**：`POST /api/tasks/{id}/artifacts/auto-bind`——把任务级数据/日志
  证据按「主机交叉」自动归属到唯一命中的漏洞（name/note/source_url/storage 提取
  域名 × 漏洞锚定资产与报告文本的域名求交集；多命中歧义跳过）；证据卡新增
  「智能关联」按钮，实测任务 5 数据证据 21 条未挂的按主机归位。

## [0.4.39] - 2026-11-03

> 回退 v0.4.38 的自动复测：复测是**手动**机制（用户明确），平台不应自动触发，
> 收尾里的未复测提醒一并移除，恢复到原先的纯手动流程。

### 变更

- 移除任务收尾自动复测（队列、`Engine.SetOnSettled` 联动、设置键
  `auto_retest_*`、设置页卡片、`db.HasActiveFindingRetest`）；
- `startFindingRetest` 恢复为 handler 内原有实现（不再抽公共入口）；
- 移除收尾活动流里的「N 个 critical/high 未复测」提醒。

## [0.4.37] - 2026-11-03

> 全平台任务复盘（5 任务 222 个漏洞 / 29 条 blocked 意图 / 仅 1 条复测）后的
> 逻辑与数据展示修正：重启不再烧意图、任务状态不再卡 created、收尾提示复测缺口、
> 剩余脱敏全部移除（证据原样）。

### 修复 / 优化

- **服务重启不再把意图烧成 blocked**：进程停止/任务范围取消（非 pause、非收尾、
  非终态、非 kill）时，running 意图回 `open` 并记 `server_shutdown` 原因，恢复后
  重新领取。实测 5 个任务累计 29 条 `blocked=error: context canceled` 全部来自
  部署重启；此前按 worker 出错处理。
- **任务状态 created→running**：bootstrap 准入与首次 Engine.Run 都会把 `created`
  落成 `running`——线上任务跑了数小时 DB 仍显示 created。
- **收尾未复测提醒**：任务收尾时统计 pending 的 critical/high 并写进活动流
  （“N 个 critical、M 个 high 仍未复测，可在复测页批量复测”）。实测 222 个漏洞
  只有 1 条复测，报告会带着大量未验证结论交付。
- **剩余脱敏移除（明文保真）**：
  - 活动日志/工具摘要不再把命令里的口令/Token 替换成 ***（`cmdHead` 原样保留，
    仅截断）；
  - `diff_responses` 对凭据类字段仍标 `sensitive`，但预览值原样返回（不再抹成 ***）。

## [0.4.36] - 2026-11-03

> 发布形态收敛：只发布 Linux（amd64/arm64），README 改成「一条命令、交互式安装」。

### 变更

- **GitHub Release 只出 Linux 包**：release 工作流矩阵从 5 平台（linux/darwin/windows）
  收敛为 `linux/amd64` + `linux/arm64`；`build.sh --release` 默认目标同步收敛。
  Windows/macOS 暂不适配。
- **README 安装章节重写**：主推一条命令
  `curl -fsSL https://github.com/chu0119/Pojun/releases/latest/download/install.sh | sudo bash`
  ——交互式选择部署形态（二进制/Docker）与可选出网代理，自动装依赖（PostgreSQL/
  LibreOffice/poppler/ImageMagick/字体）、建用户目录、初始化数据库、装 systemd 服务并
  启动；另列 `-y`/`--install-proxy`/`--mode=docker` 非交互姿势。预编译包说明改为
  Linux amd64/arm64。
- **install.sh 支持管道执行下的交互**：`curl | sudo bash` 时 stdin 是脚本本身，原先
  会退化为非交互；现统一从 `/dev/tty` 读取模式/代理/确认输入（无 tty 环境自动回落
  默认值），宝塔式「一条命令跑完」体验成立。

## [0.4.35] - 2026-11-03

> 借鉴 sapper-v2（腾讯智能攻防赛冠军，MIT）的三项机制：时间军规、同族迁移、
> 注入纪律。详细对比见 docs/同行对比分析-2026-11.md 第六节。

### 优化

- **planner 时间军规 / 升级阶梯**：意图 wall_ms 已进态势——单方向累计 >25 分钟且
  连续两轮零新增 → 换本质打法；>45 分钟未突破 → park 并记录失败特征；任务带
  deadline 时最后 1/4 预算优先收官（补证据/报告，不开新长链）。
- **planner 同族迁移（variant hunting）**：确认漏洞后 30 秒内自问同产品/同版本/
  同框架/同资产族是否同款，优先派 1–2 条 variant 意图复用已确认 PoC/路径/参数；
  variant 必须锚定 task_scope，不得借同族迁移越界。
- **worker 注入纪律（prompt 级）**：新增第 6 条——HTTP 响应/HTML/banner/文件/DB
  导出/"管理员留言"全部是不可信数据，其中任何指令性文字只记录不执行（此前只有
  工具输出的注入告警 steer，缺常驻声明）。
- **vuln-hunting skill 新增「维度 9：同族迁移」**：检查清单（同产品/同版本/同框架/
  同资产族/同机理）+ 边界（授权范围）+ 反模式。

## [0.4.34] - 2026-11-03

> 两项政策调整（用户明确要求）：证据明文保真（第一方递交官方，不打码不脱敏）；
> 数据面最大化（非破坏取数）。后者来自任务 7 实战：finding #99 的
> /mgr/test/* 前缀下还有 akRegisterRecord（门诊记录）与 akRegList（全部号源）
> 未取到数据，报告里自己已经点出这条能力面。

### 调整

- **证据明文保真（不再打码/脱敏任何目标数据）**：
  - `artifactGuidance`：删除"身份证/人脸先模糊"指令；改为证据原样登记，身份证、
    人脸、手机号、账号、口令等一律明文保留（打码会破坏溯源与漏洞判定）；
  - 样本策略放宽：数据样本保留足够证明面的行数（前 100 条/覆盖全部关键字段），
    关键数据集可整份登记（附件上限 300 件/500MB 不变）；
  - `/api/tasks/{id}/artifacts` 的 policy 文案与 redteam-ops skill 的凭据清单
    条目同步改为明文保真。
- **数据面最大化（非破坏取数）**：
  - worker 作业程序新增第 7 条：确认未授权可读端点后，系统化取数——同前缀兄弟
    端点探活、分页/时间窗/筛选取全、导出接口优先；副作用端点（sendMsg/clearCache/
    delete/update/pay 等）只验证存在性不执行；分页间 sleep 0.3–1s 限速；
  - planner 新增【数据面扩展】意图族：发现数据端点后先派同前缀枚举/全量拉取/导出
    意图；报告里写"具备能力面但未取到数据"的，下一轮优先补取；
  - vuln-hunting skill 新增「维度 8：数据面最大化（非破坏）」完整检查清单与反模式。

## [0.4.33] - 2026-11-03

> 手机端功能走查 + 布局深修（390×844 实机视口，Kali 真实数据逐页验证）。
> 含 Word 导出移动端加固、任务详情两处布局重构、三个数据页表格列裁剪。

### 修复 / 优化

- **Word 导出移动端加固**（任务总报告 + 单漏洞）：
  - `triggerBlobDownload` 统一出口：`<a>` 挂入 DOM 再 click（部分移动浏览器对游离节点不触发）、
    `revokeObjectURL` 延迟 30s（Safari 立即 revoke 会拿到空 URL，表现为"点了没反应"）；
  - 按钮加 loading 态（"导出中…" + spinner），成功/失败均 toast 提示——此前 20–25MB
    的大文件下载在手机上无任何反馈，用户容易误以为失败或重复点击。
- **任务详情头部移动端重构**：标题不再被挤成"陕西步长…"；状态/模型切换/归档移到
  手机端第二行，目标描述两行显示，恢复/暂停按钮保留首行。
- **任务详情「发现」Tab 行重构**：手机端改为双行——首行 严重度+标题+摘要，次行
  流量证据/状态/详情；此前固定宽度徽标把标题列挤没、左侧严重度被裁。
- **Tab 栏渐隐提示**：任务详情 10 个 Tab 横向滚动时右缘渐隐，提示可滑动。
- **表格列裁剪（手机端）**：LLM 记录（隐藏 任务/Worker/Profile/延迟，Model 截断）、
  命令记录（隐藏 任务/Worker/工具，工具/Worker 移入输入副行）、企业列表（隐藏 资产数，
  名称单行截断）；此前三页表格 433–525px 超出 390 视口。

## [0.4.32] - 2026-11-03

> v0.4.31 的发布包内嵌了旧前端（构建时漏设 `NEXT_EXPORT=1`，`web/out` 未刷新）。
> 本版用正确的 `build:static` 重新导出前端，手机端改动（任务卡片/发现列裁剪/
> 流量工具栏/设置输入框/详情崩溃修复）首次真正进入发布产物。

## [0.4.31] - 2026-11-03

> 手机端专项：任务/发现/流量三个高频列表在 390px 宽度下从「表格横向滚动、
> 核心列看不见」改为移动端专用布局；设置页输入框、头部版本号、流量筛选工具
> 栏按断点重排；并修复任务详情页一个会导致整页白屏的运行时错误。

### 优化（手机端）

- **任务列表移动端卡片**（<md）：名称/状态/ID/创建时间/描述/目标进度/漏洞数/
  Worker/时长/Token 一屏可见，操作按钮保留；桌面表格 `hidden md:table`。
  任务名为空时回退显示描述（此前统一显示「未命名」）。
- **发现列表移动端列裁剪**：<md 隐藏 资产/所属任务/时间/操作 四列（详情页均有），
  保留 严重度/漏洞名称/状态 + 展开行；表格 `min-w-0 md:min-w-[60rem]`。
- **流量列表移动端**：<md 隐藏 时间/host/content-type/响应长度列；URL 两行折行 +
  第二行显示 content-type/大小；筛选工具栏输入框/下拉框改为占满整行。
- **设置页输入框**：数字输入 `w-full sm:w-40/48`（手机占满、桌面紧凑），
  压缩参数 Label 加 `shrink-0` 防挤压。
- **头部**：版本号在 <sm 隐藏（避免与图标按钮竞争宽度）。

### 修复

- **任务详情页整页崩溃**：SessionsTab 对 `taskCost.cost_usd` / `taskTokens.*`
  直接调 `toFixed/toLocaleString`，字段缺失（mock/旧接口）时抛 TypeError →
  整页进入错误边界。全部改为 `?? 0` / `Number.isFinite` 守卫。

## [0.4.30] - 2026-11-03

> 同行对比分析 P1 方法论批次（纯提示词，零结构性风险）：planner 难度感知评分与
> 三条反误报纪律、worker 工具使用纪律。全部自译重写，随 SeedPromptVersioned 下发
> （用户手改过的提示词不受影响）。

### 优化（planner）

- **priority 评分改为 TDA 四维**（借鉴 Excalibur 论文 arXiv 2602.17622，自译）：
  视野（离目标步数）/ 证据置信（observed vs inferred）/ 历史成功率（同类方向本任务
  done 且零产出的占比高则降分）/ 上下文负载（优先短链快验）。
- **异常是线索，不是机制**（PentestGPT supervisor 纪律）：一个异常最多派 1 条有界
  验证意图，同假设未决前不按"每个可疑点各派一条"铺开；同目标面最多 2 个判别对照，
  照不出差异就记 fact 收手。
- **失败不原样重派**（hackingBuddyGPT AD planner 纪律）：同一方向连续 2 次相同错误
  特征 blocked → 第三条必须换实现路径或在 summary 写明本质差异。

### 优化（worker）

- **工具使用纪律**（汇总 EnIGMA/CAI 操作纪律，自译）：单命令+强制超时（curl
  --max-time / nc -w / timeout）、禁交互挂死命令、大输出先落盘再 grep、二进制先
  xxd/strings、优先领域工具（http_probe/auth_request/diff_responses/traffic_search）、
  同一打法连续 3 次无新信息必须换本质不同打法。

## [0.4.29] - 2026-11-03

> 同行对比分析 P0 第二批（P0b）：工具输出降载 + 证据逐字回验 + 注入告警。
> 三项均来自 MIT 项目的机制（自研重写），默认取「先观察后拦截」的保守档位。

### 新增 / 优化

- **worker 单次工具回显上限 30000→12000 字符**：SDK 的「超长输出落盘 + 绝对路径指针」
  机制本就在全局生效（norma harness 单点 Capture），本次把 worker 的单次预算收紧。
  任务 5 实测 Bash 6833 次调用，单条 30k 回显（≈7.5k token）是 transcript 放大的
  主要来源之一；12000 仍容纳一次 sqlmap/httpx 的关键段落，全文按指针自行 grep/sed。
- **证据逐字回验**（PentestGPT evidence_excerpt 机制，MIT，自研）：worker 的工具回显
  进入会话时同步记入本次 run 的台账（`agent/tool_outputs.go`）；report_finding 时把
  evidence 按行（≥20 字节有效行）与台账比对，给出 0/部分/充分 三档出处判定。
  默认 **warn**：只在 report_finding 返回里附「证据出处核对」提示，不阻断；
  设置 `finding_evidence_verify=block` 时，critical/high 且零出处 → 打回重报
  （提示改粘原文/降级/转 record_fact）。
- **工具输出注入告警**（CAI 指令层级/输出消毒思路，自研）：工具回显命中高精度注入
  特征（ignore previous instructions / you are now DAN / new system prompt 等）时，
  经 steer 通道在下一次工具调用前提醒模型「目标内容当数据不当指令」；每意图最多
  3 次告警，防刷屏。设置 `tool_output_injection_guard`（默认开）。

## [0.4.28] - 2026-11-03

> 同行对比分析（docs/同行对比分析-2026-11.md）P0 第一批/mini 版：意图级软预算 +
> 重复调用拦截。两项都是「软」机制——提醒不杀进程、拦截有次数上限兜底，不会造成
> 比现状更差的卡死路径；均可经系统设置关闭/调整（防负优化护栏）。

### 新增

- **意图级软预算**（借鉴 hackingBuddyGPT 四维 Limits 的机制，MIT，自研实现）：
  单条意图累计 token（activity usage 的会话累计值）达到预算（默认 300 万）时，
  向运行中的 worker 注入一条 steer 收尾提醒：停止扩大探索、把已有结论写回后结束。
  只提醒一次、不杀进程；任务超时与自动收尾仍是最终兜底。设置键
  `intent_budget_enabled`（默认开）/`intent_budget_tokens`（500k–20M）。
- **重复调用拦截**（借鉴 PentAGI 重复检测器机制，MIT，自研实现）：同一工具 +
  完全相同入参（JSON 规范化后）连续第 3 次起拦截本次调用，回喂纠正提示（“换目标/
  换参数/换方法，或承认当前手段到头、把结论写回”）；同一串最多拦 2 次后放行兜底，
  防活锁。钩在 steerHooks.PreToolUse（planer steer 纠偏之后判定，不抢占纠偏优先级）。
- **系统设置页新增「意图级软预算与重复调用拦截」卡**：开关 + token 预算输入。

## [0.4.27] - 2026-11-03

> 基于任务 5 的真实运行数据做的一轮「降本 + 补盲」：20.8 小时 / 142 轮烧掉 12.1 亿
> input tokens（cache 命中 92.9%）、66 个漏洞里 64 个停在 pending、493 个 endpoint
> 只测到 30%。逐项归因后落地批次一（成本与遥测）与批次二（覆盖与复测闭环）。

### 新增

- **`http_probe` 批量探活工具**（worker + mainagent）：给一批 URL 返回一条可执行
  Bash 命令，每行一个紧凑 JSON（status/bytes/time_ms/title/server/content_type/
  redirect）。任务 5 实测 Bash 占全部 tool_use 的 57%（curl 探活 2750 次、响应全文
  进对话）——批量探活一次往返替代逐条手写 curl，响应从整页 HTML 压成一行摘要。
  沿用「只组命令不自己发请求」原则，流量录制/审批管控照常生效。
- **record_fact 自动锚定资产（覆盖归账）**：模型没给 `asset_ids` 时，从事实文本
  （summary/detail/evidence）里提取 URL/主机反查本任务资产自动锚定（URL 精确/
  前缀、domain/root_domain 匹配，封顶 6 条）。endpoint 覆盖卡在 30% 的主因不是
  「没测」而是「测了没归账」——Bash curl 探测后 record_fact 不带 asset_ids，
  覆盖度对账不出来。
- **未测资产清单重排序**（`list_untested_assets` / `ListUntestedAssetsWithSources`）：
  静态资源沉底、同路径前缀簇相邻。任务 5 实测 493 个未测 endpoint 里静态仅 5 个、
  /prod/prod-api（69）、/HRMS/api（52）等前缀簇高度集中——按 id 排序会把同簇接口
  摊散到不同轮次，规划者很难一次吃掉一簇。
- **意图墙钟遥测**：runIntent 结算时把 `wall_ms` + 终态写进 intent payload，
  planner 态势的每条意图直接携带「这条方向烧了多久」。
- **LLM 用量按角色聚合**：`UsageByWorkerTask` 返回单任务 worker/planner/main/
  compactor/judge/goals 各自的调用数与 input/output/cache_read（cache 单列，
  与计费口径一致）。任务 5 实测 worker 占 76.8%、planner 非意图调用占 23.4%。
- **批量复测**：`GET /api/tasks/{id}/retest-candidates` 返回本任务 pending 且无
  进行中复测的漏洞清单（默认 critical/high）+ 全部漏洞最新复测状态；复测 Tab 新增
  「批量复测」条（串行逐条排队、可随时停止、进度显示），漏洞列表带
  已修复/已复现/无法确认/复测中 徽标；单漏洞 Word 报告对未复测的 pending 漏洞
  标注「待人工复核」。任务 5 实测 64/66 停在 pending——复测闭环此前只靠手动逐条。

### 优化

- **worker 态势瘦身**（`workerOverviewData`）：worker 启动只注入「别人发现了什么」
  （goals/hints/计数/最新 findings/facts/工具家底/根任务），不再全量重建并携带
  planner 专用的冷图折叠、血缘 edges、意图 token 台账、coverage CTE、cold_digests、
  related_tasks 等——既省每次 worker 启动的重建计算，也把对话固定前缀压到最短
  （6928 次 worker 调用、平均 13.4 万 input/次，前缀每省 1K 都按轮次放大）。
- **瞬时 `context canceled` 自动重试**：worker run 内部流被取消（非用户暂停、非
  kill）造成的收场与 model_error 同待遇，退避重试 2 次后才落 blocked。任务 5 实测
  6 条意图以 blocked(error: context canceled) 白白收场，全是这种内部取消。

### 文档

- `docs/02-引擎与调度闭环.md` 补「覆盖归账与态势瘦身」节；复测手册补批量复测。

## [0.4.26] - 2026-11-02

> 任务 5 连续跑了十几小时仍在扫。根因：`goal_met` 只取消在跑 worker、不结束任务；
> 除任务超时外没有任何程序化收尾判据。本版给 planner 加明确的自动收尾规则。

### 新增

- **目标闭环收尾**：planner 调用 `goal_met`（明确判定目标达成）且无 open/running
  意图 → 直接 `done`，不再多跑一轮规划；`prove_goal` 全部 met 的原有 goalless
  路径保留。
- **连续无新增收尾**：每个规划轮记录 `facts / findings / tested assets` 快照；
  连续 N 轮零增长、无在跑意图且达到最少轮数 → 自动收尾（默认 N=3，最少 5 轮）。
- **覆盖率达标收尾**（可关闭）：覆盖率 ≥ 阈值且至少 1 轮零新增、无在跑意图
  （默认 0=关闭，可设 1–100）。
- **最大规划轮数**：硬上限（默认 80，0=不限），达到后即使仍有意图也先 drain
  再收尾。
- **用户新增目标/提示会重置计数**：避免刚加目标就被旧 idle 计数收掉；
  终态复活时进度重新开始。
- 收尾原因写入活动流，终态统一 `done`（超时仍保持 `met?done:timeout`）；
  自动收尾的终局 planner 使用“按策略收尾”提示词，不再误用“任务超时”文案。
- **系统设置页新增「任务自动收尾」**：开关 + 连续轮数/最少轮数/覆盖率阈值/
  最大轮数，全部即时生效（下一轮 planner 读取）。

### 修复

- `settleTask` 泛化为带原因的收尾入口，timeout 与自动收尾竞态时先到者赢；
  `settling` 现在记录原因。

## [0.4.25] - 2026-11-02

> 用户反馈「每个漏洞详情都显示暂无专属截图或文档」。核查后：绝大多数历史漏洞
> 只有 JSON/日志附件，且 53 张存储桶照片仍是任务级；不是功能回退。本版把空态
> 说清楚，并让用户不必离开漏洞页就能挑选证据。

### 新增/优化

- **空态区分附件类型**：本漏洞有数据/日志附件但无可视证据时，明确显示
  「有 N 个数据/日志附件，但没有可预览的图片或文档」，不再一律说“暂无”。
- **漏洞页直接挑选任务证据**：空态和标题栏新增「从任务证据中挑选 / 添加证据」，
  多选未归属的图片/文档 →「归属到本漏洞」，无需跳到任务总览。
- **任务证据卡增加「全选当前」**：配合图片/文档筛选，可一次把当前筛选结果
  选中再批量归属。

## [0.4.24] - 2026-11-02

### 新增

- **漏洞详情「现场证据」支持文档**：归属该漏洞的 Word/Excel/PPT/PDF 与图片分区
  展示，文档卡片直接显示首页预览，点击可翻页、下载原件；仍严格只显示
  `finding_id` 匹配的附件，任务级材料不出现。

## [0.4.23] - 2026-11-02

> 全流程实机测试（登录 → 证据卡 → 文档预览 → 漏洞页 → Word）发现两处问题并修复。

### 修复

- **新文档预览永远停在 pending**：`save_evidence` 先在记录上标 `pending` 再入队，
  而入队函数把 `pending` 当“已在队列”直接返回 → 队列根本没收到任务。现在只跳过
  `ready`（在途去重仍由内存表保证），并新增**启动恢复**：进程重启后把数据库里
  所有 `pending` 重新排队。
- **扫描补登记后 worker 无法再存证据**：扫描可超过 100 个附件上限，随后
  `save_evidence` 一直报“附件已达上限”。限额放宽为 **300 个 / 500MB**
  （服务端与 pojun-maint 一致），扫描单次仍限 60 个。
- 任务证据卡文档类型标签：老数据 `kind=data` 的 xlsx/csv 现在按扩展名显示
  “Excel/CSV / Word / PPT / PDF”，不再显示 `data`。

## [0.4.22] - 2026-11-02

> v0.4.21 文档预览在 Kali 实机（数据盘 + root 维护）暴露三处环境问题，本版修复。

### 修复

- **LibreOffice 转换 cwd**：`soffice` 包装脚本会 `cd` 回启动目录；维护工具以
  root 从 `/home/xxx` 启动再 `sudo -u pojun` 时，pojun 无权进入该目录直接失败。
  转换进程 cwd 固定到临时目录。
- **跨文件系统 rename（EXDEV）**：`pdftoppm` 先写 `/tmp`（tmpfs）再 rename 到
  数据盘会失败；改为在预览目录内的暂存子目录渲染，同文件系统内 rename。
- **预览文件权限**：目录 0755、JPEG 0644，root 维护工具生成的预览服务用户也能读。
- 清理一处文档预览的无用函数/导入。

## [0.4.21] - 2026-11-02

> 用户要求：抓到的 Word/Excel/PDF 等文档也要能“看见成果”。本版把文档取样
> 转成图片，任务证据卡与报告里直接预览；依赖随一键安装/Docker 装齐。

### 新增

- **文档转图片预览**：doc/docx/odt/rtf、xls/xlsx/ods/csv、ppt/pptx/odp、pdf
  自动取**前 3 页**渲染 JPEG（长边 1600、q82）。Office 先经 LibreOffice 转
  PDF，再走 poppler `pdftoppm`；PDF 直接渲染。
- **异步预览队列**：单 worker 串行（避免 LibreOffice profile 锁），登记附件后
  自动排队，不阻塞 `save_evidence`；前端每 4s 轮询生成状态。
- **存储与限额**：预览 sidecar 落 `artifacts/previews/<id>/page-N.jpg`，不占
  100 个附件限额，单独按任务 100MB 总量保护；失败/缺依赖写 `preview_error`。
- **任务证据卡文档画廊**：新增 全部/图片/文档/其他 筛选；文档卡片显示首页
  缩略图 + 类型/页数，点击可翻页看大图、下载原件；失败可单条重试。
- **报告嵌文档预览**：引用文档类附件时嵌入第一页预览图；大图嵌报告前压到
  1600px JPEG，避免 docx 体积膨胀（顺带解决 webp 无法嵌入）。
- **扫描补登记支持文档**：历史工作目录里的 Office/PDF 也会被扫描入证据库并
  自动生成预览。
- **离线补预览**：`pojun-maint previews --task <id>` / `--all`（`--force` 重建）。
- **API**：`GET /api/tasks/{id}/artifacts/{aid}/preview/{page}`、
  `POST .../preview` 手动重新生成；附件列表返回 `preview_state/pages/error`。

### 部署

- `install.sh` 默认安装 `libreoffice-writer/calc/impress` + `poppler-utils`；
  宿主环境页新增 `poppler` 条目，`libreoffice` 条目补全三组件；Docker 镜像内置。
- 旧任务补预览：`pojun-maint previews --config /opt/pojun/config.json --all`。

## [0.4.20] - 2026-11-02

> 用户反馈「加了照片之后，每个漏洞里都能看到同一批照片」。根因不是跨任务串数据
> （查询一直按 task_id 隔离），而是同一任务内漏洞页/单漏洞报告对任务级图片做了
> 无条件回退。本版先止血并补上历史数据整理入口。

### 修复

- **漏洞详情不再回退展示任务级照片**：只显示 `finding_id` 属于本漏洞的图片；
  没有专属图时显示空态并给「查看任务总览」链接（任务级证据统一在任务证据附件里看）。
- **单漏洞 Word 报告只嵌专属图**：删除「该漏洞无图时放开整个任务图片」的回退
  （原实现与注释意图不符，会把同任务其他漏洞/任务级图片嵌进单漏洞报告）。
- **reporter 的 `list_artifacts` 永远返回空**：reporter 是 chat agent，工具实例
  没有任务上下文（taskID=0）。现在支持 `list_artifacts {"finding_id": <id>}`
  反查所属任务，报告撰写提示词同步更新。

### 新增

- **附件归属可修改**：`PATCH /api/tasks/{id}/artifacts/{aid}`，`finding_id=0`
  表示任务级；校验漏洞必须属于本任务。
- **任务证据附件批量归属**：勾选图片/文件 → 选择漏洞 → 应用；用于整理历史任务
  里未关联漏洞的照片。
- **去重补绑**：同一图片先以任务级登记、之后带 `finding_id` 再登记时，自动补绑
  到漏洞（旧记录已归属其他漏洞则不抢占）。

## [0.4.3] - 2026-11-01

> 用户拿真实公文样本逐项对拍后的专项重修——上一版「公文格式」只有形没有神，
> 本版把排版参数逐项对齐真实公文。

### 修复的问题（逐项对齐真实公文样本）

- **标题加粗错误**：公文标题（文件标题/一级/二级）靠字体区分（黑体/楷体），
  **一律不加粗**——此前全部加粗，且 ascii 字体错用 Calibri（公文英文/数字用
  Times New Roman）。显式 `<w:b w:val="0"/>`。
- **正文字体名错误**：`仿宋_GB2312`（老字体名，新系统未必有）→ `仿宋`
  （参考件实际使用）；补显式 `color=000000` 与 `<w:b w:val="0"/>`。
- **正文缺两端对齐**：公文正文两端对齐（jc=both）+ 首行缩进 640 缇——此前
  Normal 无 jc 定义（左对齐）。
- **页边距**：1 英寸四边 → 公文标准（上 2098 / 右 1474 / 下 1984 / 左 1587
  缇）+ docGrid 360。
- **页码格式**：「第 N 页」→ 公文标准「— N —」（一字线夹注、三号）。
- **页眉移除**：公文无页眉（此前页眉带报告名+底边框）。
- **公文层次映射**：reporter 正文中的「一、xxx」独立短行 → 黑体一级标题；
  「（一）xxx」短行 → 楷体二级标题——markdown `##` 同步映射楷体二级
  （原压平为小四黑体）。单漏洞报告「一/二/三」章节同步升为黑体一级。
- **嵌套列表缩进**：列表段落显式清首行缩进并按层级设置左缩进（此前继承
  公文首行缩进导致列表错位）。

## [0.4.2] - 2026-11-01

### 修复的问题

- **报告正文里 ``` 围栏代码仍逐行成段**（v0.4.1 只合并了证据/PoC 整块，漏了
  详细报告 Markdown 渲染路径的围栏分支——本次 83 个 Code 段落的主要来源）。
  现在整块围栏合并为单一段落（行间 w:br），实测单漏洞报告总段落 175 → 44。

## [0.4.1] - 2026-11-01

> 用户实测 v0.4.0 导出的单漏洞 Word「不符合公文格式、内容堆到一块儿」的专项重修。
> 排版基线参照 GB/T 9704 公文风格：正文仿宋三号、标题黑体分级、首行缩进 2 字符、
> 固定行距 28 磅。

### 修复的问题

- **代码块散成一片**（「全堆到一块儿」的主因）：证据/PoC 与报告里的代码逐行成段
  ——长 JSON 被拆成上百个独立段落。现在整块合并为单一段落（行内 w:br 换行），
  样式升级为浅底纹 + 左竖线 + 紧行距，视觉成一个整块。
- **正文样式不符合公文规范**：docDefaults 重写为仿宋_GB2312 三号（16pt）+
  固定行距 28 磅 + 正文首行缩进 2 字符；一二三四级标题统一黑体分级
  （三号/四号/小四），正文与标题字体严格区分。
- **表格巨大变形**：正文字号升为三号后表格继承同字号——单元格文字固定 10pt
  紧行距，不再变形。
- **封面标题字体**：封面主标题（含严重度着色路径）统一黑体。

### 新增

- **单漏洞报告补目录页**：TOC 字段（打开自动刷新），与总报告一致。

## [0.4.0] - 2026-11-01

> 报告体验专项二期（用户实测反馈驱动）：证据/PoC 前端排版 + Word 导出全面专业化。
> 自 v0.3.93 报告一期以来，Word 交付已具备：封面/目录/页眉页脚/严重度着色/富
> Markdown/复测记录/流量证据/修复路线图/附录资产——对齐专业渗透报告交付标准。

### 修复的问题

- **证据 / PoC 卡片排版草率**（前端）：原来是一整块原始文本（curl 命令、`#`
  小节注释、超长 JSON 混排，长行溢出）。新 `EvidenceView` 组件分块渲染：
  `#` 小节标题带色分隔、超长 JSON 自动美化+折叠（超 12 行可展开）、列表与
  围栏代码分块、右上角一键复制原文。发现详情页与任务详情发现 tab 内联展开
  两处同步替换。
- **Word 报告正文压平/反引号裸奔**：详细报告里的**嵌套列表**（reporter 常写
  二级清单）此前被拍平到一级——现按缩进渲染多级项目符号；`` `内联代码` `` 
  此前原样输出反引号——现渲染为 Consolas 字体 run。
- **单漏洞 Word 报告缺封面/页眉**：与总报告对齐——真封面页（着色标题/委托方/
  密级占位/日期）+ 页眉（漏洞名）+ 元信息补状态与发现者。

## [0.3.99] - 2026-11-01

### 修复的问题

- **前端界面更新后浏览器可能仍显示旧版**（用户实测：新版功能上线后「看不见」，
  而新开浏览器正常）：内嵌前端此前**不带任何缓存头**（embed FS 无
  Last-Modified），浏览器走启发式缓存，一键更新后老用户的浏览器继续用旧
  HTML/JS 渲染旧界面。现在：`_next/static/*`（内容寻址文件名）→ 一年
  immutable；其余（HTML 入口等）→ `no-cache` 每次回源校验——更新后所有
  浏览器立即拿到新界面，不再需要手动强刷。

## [0.3.98] - 2026-11-01

### 修复的问题

- **发现详情页「关联流量」面板上移**（用户实测反馈：打开详情看不见流量查看入口）：
  面板从「证据/PoC（占近半屏）与超长详细报告之间」上移到摘要正下方——报文查看
  是详情页最高频操作，首屏即可点开请求/响应弹窗。

## [0.3.97] - 2026-11-01

### 修复的问题

- **任务详情 → 发现 tab 展开漏洞只有一坨 evidence JSON，看不到报文查看器**
  （用户实测反馈）：内联展开区现在直接内嵌「关联流量」面板——每条证据可点开
  请求/响应报文弹窗（与发现详情页同组件），原始 evidence JSON 折叠为可展开的
  次要信息。此前完整报文查看器只存在于「发现 → 详情」页，任务详情里的展开
  视图无法查看流量，观感上"流量变成 Markdown 里的一坨了"。

## [0.3.96] - 2026-11-01

> Kali 实测缺陷修复专项：漏洞情报「一直同步中，无法中断/重启」+ nuclei 模板库
> 「0 个模板」（克隆中断残留空 .git 壳，挂了 14 小时无法自愈）。

### 修复的问题

- **nuclei 模板树克隆失败不再留半成品**：clone/pull 失败（超时/网络断）会留下
  只有 .git 的空壳目录，下一轮对着残缺仓库 pull 永远修不好，状态页永远「0 个
  模板」且只能手工删目录。现在 clone 失败即清理残留；pull 失败且目录无 yaml
  同样清理重 clone；成功后校验 yaml 计数 >0（空树视为失败）。
- **模板树更新超时 5 分钟 → 15 分钟**：nuclei-templates depth-1 约 100-200MB，
  经慢代理 5 分钟必然超时——超时杀掉的 clone 正是「0 个模板」事故的根因。

### 新增

- **同步可中断**：新增 `POST /api/vulnintel/sync/cancel`——协作式取消，ctx 贯穿
  NVD/GHSA 请求与 nuclei git 子进程（到点杀 git/curl，进度游标保留，可立即重新
  发起）。此前一轮最长 45 分钟且零中断路径，卡住时既停不了也开不了新一轮。
- **同步阶段可见**：状态接口新增 `sync_phase`（漏洞情报同步中 / 资产指纹联动 /
  nuclei 模板树更新 / 已中断），前端「同步进行中」徽标显示当前阶段，不再只有
  一个转圈。
- **前端「中断同步」按钮**：同步进行中时可用（红色，位于「立即同步」旁）。

## [0.3.95] - 2026-10-31

> 深度优化方案第二期：Agent 判断力——从「机制完备、判断靠猜」到「判断有数据
> 供给」。方案见 [docs/深度优化方案-2026-10-31.md](docs/深度优化方案-2026-10-31.md) §二；
> 模型路由策略新增 [docs/模型路由策略.md](docs/模型路由策略.md)。

### 新增（Agent 认知升级）

- **stop_reason 进态势**（B1）：recent_done_intents 每条带 `stop_reason`
  （DB 列早已有、态势从不携带），worker 完成触发事件的文字也带——planner 判
  「接续 vs 换方向」从猜变成看，省每轮 1-3 次读图调用。
- **意图结构化：hypothesis / success_criteria**（B3）：add_intent 新增两个
  可选字段（本方向假设 / 成功判据），落进意图 payload 并在 worker 领单消息
  结构化渲染——worker 有了 definition of done，planner 下轮判「有没有产出」
  有对照锚。
- **worker 五步作业框架**（B4）：复述假设 → 列 2-3 条探测向量与判别信号 →
  边发现边写回 → 对抗自检 → 明确回答假设成立与否。附**最小绕过清单**（编码/
  大小写/参数位置/方法/Content-Type/分段），否定结论的 evidence 要逐条写明
  试过哪几类——「绕过手段走完」从口号变成可核对清单。
- **worker 自保护**（B5）：意图自相矛盾/缺前置时立即 record_fact 说明并结束，
  不硬着头皮绕到步数耗尽；收尾词补「未验证的猜测一律不写回」（收场路径上
  唯一的图谱质检口）。
- **续跑摘要**（B9）：exhausted/blocked 复跑时注入续跑上下文——上次状态、
  收场原因、图上已挂产出（fact 列表）；零写回的续跑被强制先复盘，不重复
  同样的路径。
- **提示词批改包**（B8）：planner——priority 评分标准（此前等价废字段）、
  done 零写回分支（与 exhausted-无增量同处理）、深度-广度仲裁规则（两轮
  无增量切换）、坏意图负面示例 ×2、硬底线去重（system 与 user 重复段收敛）；
  goals——空泛目标改写规则；judge——参数空/乱码 → ASK（不再默认 ALLOW）、
  D6 补脚本循环发包判据；compaction——压缩保留 intent 终态语义（exhausted
  「穷尽 vs 被掐断」可分辨）。
- **模型路由策略**（B11，文档）：planner/mainagent=强推理、worker=强执行
  中推理、judge/goals/compactor=非思考或便宜档；免费通道给 worker/goals/
  compactor，旗舰通道给 planner；judge 固定绑稳定通道不参与池子轮询。

## [0.3.94] - 2026-10-31

> 深度优化方案第一期（下）：报告结构升级。方案见
> [docs/深度优化方案-2026-10-31.md](docs/深度优化方案-2026-10-31.md) §1.3。

### 新增（报告结构升级）

- **真封面页**：居中大标题 + 委托方（任务关联企业名）+ 密级占位（默认「内部
  资料 · 仅限授权方」）+ 报告生成时间与漏洞计数——替代原来的首行 H1。
- **目录页**：TOC 字段（收 Heading1-3，漏洞小节不进目录）；`settings.xml`
  置 `updateFields`，Word 打开自动刷新。
- **页眉页脚**：页眉右侧报告名（底边框分隔线），页脚居中「第 N 页」（PAGE
  字段自动编号）。
- **「二、测试范围与方法论」章节**：任务目标 / 测试执行窗口（FirstRunAt→
  CompletedAt）/ 测试范围摘要 / 平台方法论声明（v0.3.94 数据全部来自任务与
  资产库，组章即可）。
- **「四、修复优先级路线图」**：立即整改（critical/high，7 天内）→ 近期计划
  （medium，30 天内）→ 择机安排（low）三档清单表，每档带处置指引；分拣状态
  同步展示。
- **附录 A 资产清单**：按类型列出全部测试范围内资产（单类型 200 条封顶）。
- 章节重编号：概览/方法论/漏洞明细/路线图 + 附录；漏洞明细组内编号 3.x。
- 页眉文字可自定义（PageHeader/Classification 字段），为品牌化交付留口。

## [0.3.93] - 2026-10-31

> 深度优化方案第一期（上）：报告交付质感——渲染层修复 + 数据面接通。
> 方案全文见 [docs/深度优化方案-2026-10-31.md](docs/深度优化方案-2026-10-31.md)。

### 修复的问题

- **Word 报告项目符号不渲染**（显性 bug）：docx 包引用 `numId=1` 但 zip 里
  从未打过 `word/numbering.xml` 部件——列表在 Word 里静默变纯文本。补齐
  numbering 部件、关系与 Content-Type 声明；测试新增全部件 XML 良构校验。

### 新增（报告导出升级）

- **严重度着色**：漏洞标题按级别着色（critical 红 / high 橙 / medium 琥珀 /
  low 蓝），严重度分布表行底色同色系——一眼分诊。
- **Markdown 富渲染**：reporter 写的详细报告正文不再压平——`##` 小节保留
  层级（新增 Heading4 样式）、`**加粗**` 转富文本 run、`| |` 表格转真 OOXML
  表格（分隔行自动剔除）。
- **影响资产可读名**：`影响资产 id:1,2,3` → 域名/IP/URL（按资产类型取最具
  辨识度字段，缺失回退 id）。
- **复测记录小节**：每条漏洞带最近复测结论（已复现/已修复/无法定论）+ 时间
  + 摘要，历史次数附注——复测闭环第一次进交付件。
- **关联流量证据进 Word**：baseline/proof/verification/supporting 四角色绑定
  在交付件中呈现（元信息 + 说明 + 请求/响应头代码块 + stale 提示）——此前只有
  md 导出带流量证据，客户要的 Word 反而没有。
- **交付分拣**：Word 导出默认剔除 false_positive/duplicate/ignored/
  risk_accepted 状态的发现（分析导出 md/csv/json 保持全量）。

## [0.3.92] - 2026-10-31

### 清理（体检批 4）

- 删除 24 个零引用死组件/死文件（date-range-picker、event-calendar-views、
  ui/calendar、nav-documents/nav-secondary、sidebar-support-card 含第三方
  模板作者链接、17 个零引用 shadcn 组件）——逐个 grep 全仓验证后删除。
- 删除顶栏 AccountSwitcher（与侧栏 NavUser 功能重复，恒单用户的多用户 UI 摆设）。
- not-found 页中文化（原全英文与全站文案相悖）。

## [0.3.91] - 2026-10-31

### 修复的问题（体检批 3）

- **冷启动无引导**：零 LLM 通道时空任务列表给出「去配置 LLM」引导卡；新建
  任务前拦截零通道提交（此前任务创建后跑到引擎才失败）。
- **拦截审批入口统一命名**：侧栏「审批记录」/任务 tab「拦截审批」/会话内嵌
  → 三处统一为「拦截审批」。
- **仪表盘全量拉取**：发现计数/严重度分布改走 `findingStats` 聚合端点，
  最近发现只拉 8 条分页——发现量大的部署首屏明显提速。

## [0.3.90] - 2026-10-31

> 体检批 2（红队主线补 UI + 可观测性），清单见
> [docs/产品全面体检-2026-10-31.md](docs/产品全面体检-2026-10-31.md) §三/§八。

### 新增

- **「监听器 / C2」系统页**（红队核心能力首次在 UI 可见——此前 6 条 API 只有
  手搓 curl 才能用）：
  - **C2 出口配置表单**：direct / ssh 中继托管 / manual 三形态切换，按形态
    显隐字段（中转机地址 / SSH 凭据 / 出口网卡），密码脱敏回显（留空不变更）。
  - **监听器管理**：启动（名称+端口，1024-65535 校验）、停止（带确认，说明
    会话留档与中继隧道拆除）、会话查看（在线状态/来源/接入时间/捕获字节，
    点开看 64KB 捕获内容——反弹 shell banner / OOB 请求行）。10s 自动轮询。
  - 启动响应里的 `connect_back`（回连地址）直接展示——payload 该连哪里以此为准。
- **Guard 归因回流 planner**（Observer 半成品的最后一公里）：`guard_attributions`
  （ok/blocked/error 计数）进入 graph_overview——planner 看到「被 WAF/拦截打回
  N 次」就换向量而不是继续烧 token；error 高=工具/环境在坏，先诊断。planner
  提示词同步解释该块含义；mainagent（人在环路）同样可见。
  - 新增 `SetAttributions` 回调链：engine per-task Guard → planner/mainagent → ToolSet。

## [0.3.89] - 2026-10-31

> 本版为「产品全面体检」批 1（P0 缺陷修复），体检全文见
> [docs/产品全面体检-2026-10-31.md](docs/产品全面体检-2026-10-31.md)。

### 修复的问题

**前端**

- **四处删除无确认**：MCP 服务器 / LLM 配置 / 自定义工具 / 通知渠道此前单击
  即删，与任务、漏洞等页的确认标准割裂，且误删直接影响运行中的 agent。统一
  补 AlertDialog 二次确认（对齐 skills 页既有模式）。
- **登录失败原因被吞**：网络断连、限流锁定、密码未初始化一律误报「用户名或
  密码错误」，诱导用户反复试密码（越试越锁）。按 HTTP 状态分型展示。
- **LLM 调用记录筛选变更不重置页码**：useEffect 依赖数组漏写，改筛选后停留
  旧页码导致列表看似为空。

**Agent 链路**

- **`list_worker_traces` 未注册进任何工具清单**——与 v0.3.87 listener 漏注册
  同类（实现/描述/清单三方向互斥）。归属 mainagent（跨 work 复盘入口）并注册，
  描述同步从 worker 视角改为 mainagent/planner 视角。
- **`expand_digest` 纯读工具误用 writeExpTool 注册**：丢 ReadOnly/Concurrent
  标记，被调度层串行化。改 readExpTool。
- **stall 收官提示引导调用不存在的 `finish_task`**（实际工具是 `goal_met`），
  恰在收官时刻触发一次工具报错。
- **planner 提示词与实际不符**：承诺的概览字段 `sites_without_endpoints` 从
  未产出；list_assets 参数描述陈旧（q/company_id → 实际 dsl/type/id/ids）。
  已对齐 graphOverviewData 真实字段清单。
- **终局规划轮无墙钟**：`runFinalPlannerRound` 直接同步调 Plan 且 ctx 无
  deadline——Plan 卡死（上游半开连接 / compactor 自死锁，均为线上发生过的事故）
  会让 settleTask 永卡 settling。复用普通规划轮的 goroutine + plannerRoundTimeout
  包装，超时按未达成继续收尾。

**后端 / 拦截**

- **C2 配置静默写失败**：`PUT /api/c2/config` 用 `_ = SetSetting(...)` 吞错，
  落库失败用户仍看到 200。失败回 500 + 日志。
- **ask 审批可无限等待**：规则未声明 timeout 时 HandleAsk 无限阻塞等人，
  审批人离场则 worker 挂死到任务超时。补全局兜底上限（默认 6 小时，到点按
  deny 收口，可经 `intercept_ask_default_timeout_seconds` 设置覆盖）。
- **`goal_met` 完全不进拦截体系**：一句话终结整个任务、只留「声称」痕迹且
  无任何管控。纳入默认拦截工具集 + 新增内置 judge 规则「goal_met 收官研判」
  （V5 seed，含已部署实例的按名补种与 enabled 工具集一次性合并）。

### 新增

- 内置拦截规则第 13 条：**[内置] goal_met 收官研判**（judge 类）——收官声明
  交模型核对「是否量化达标 / 是否边际收益诚实收官」，未经核对的提前盖章打回。

## [0.3.88] - 2026-10-30

### 修复的问题

- **Web UI 根路由（/）打开即 404**：`(external)/page.tsx` 用服务端
  `redirect()` 跳工作台，但 `next build` 静态导出（NEXT_EXPORT=1）不支持
  它——redirect 被静默丢弃，`out/index.html` 被导出成 not-found 页，
  `http://host:8787/` 第一眼就是「Page not found」。改为客户端
  `router.replace`（SSG 正常导出落地页，hydrate 后立即替换历史）。
- **listener_* 工具在 agent 侧未注册，正式版调不到**：v0.3.87 实现了
  `listenerStart/Stop/Sessions` 三个领域工具，但漏了把它们注册进
  planner/worker/mainagent 工具清单——发布二进制里 agent 在任务中无法
  调用回连接收器（开发机上带未提交改动测试通过，掩盖了缺陷）。补齐
  三处注册，并已验证编译与 ask 审批链路。
- **目标拆解无墙钟，任务可能永久卡在 created**（补记：修复随 0.3.87
  发布，条目漏记）：第 0 轮拆解继承任务级 exec ctx，任务未配
  `timeout_seconds` 时无 deadline——上游 LLM 连接挂起时拆解永不返回、
  无重试无日志（Kali 实测复现）。补 `goalsDecomposeTimeout`（5 分钟）：
  超时走「拆解无产出 → 原始目标作为单目标」回退并打日志，任务照常起跑。
  与 v0.3.61 的 plannerRoundTimeout 同思路。

## [0.3.87] - 2026-10-30

### 新增（红队能力专项）

- **回连接收器正式实现**（红队杀伤链的 C2 前置）：`listener/` 包接住反弹
  shell/OOB 回连，逐会话记录来源/时间/捕获内容（64KB 上限防灌爆）。REST
  `GET/POST /api/listeners`、agent 工具 `listener_start/stop/sessions`。
  ask 规则恢复且现在对应真实工具（启停转人工，只读查询不拦）。
- **C2 出口配置**（可选功能，三种网络形态）：`direct`（默认，本机可达，
  零配置）/ `ssh`（本机无公网+公网中转机：平台托管 SSH 反向隧道，断线
  重连）/ `manual`（已有手工转发）。`listener_start` 返回解析后的
  `connect_back={lhost,lport}`——payload 回连地址以此为准，agent 无需
  自行判断网络形态。入口：系统设置 API `/api/c2/config`。
- **redteam-ops skill**：六阶段后渗透方法论（落地稳定化→提权→权限保持→
  凭据获取→横向移动→数据获取与回传→收尾）+ 证据纪律，与平台工具
  （listener/impacket/netexec/chisel/ligolo）逐点衔接。
- **hosttools 红队补齐 9 件**：socat / proxychains4 / sshuttle / tcpdump /
  evil-winrm / responder（apt）+ ligolo-ng（nicocha30）/ pspy / linpeas
  （peass-ng）——资产名 2026-10-30 逐个 GitHub API 实测。
- **产品优化清单**（docs/产品优化清单-2026-10-29.md）与**红队能力建设
  路线图**（docs/红队能力建设-2026-10-30.md：杀伤链矩阵/竞品对照）。

## [0.3.86] - 2026-10-29

### 新增

- **宿主工具一键装齐**：宿主环境页新增「一键安装缺失（N）」与分组级「装齐本组」——
  批量发起后由特权助手串行排队执行，页签式进度面板逐工具显示状态与日志。
  此前每次只能装一个、装的时候全页禁用，缺 20 个工具要点 20 轮。
  后端新增 `POST /api/hostenv/install-batch`（逐项校验白名单，被拒项带原因返回，
  不影响其余项）。

### 移除

- **listener 死代码链**：`listener/` 包（占位 stub，`Start` 从未绑定过端口）、
  内置规则「[内置] 启停回连接收器」（匹配的 `listener_start/stop` 工具从未注册，
  规则永远不可能命中）、`listenerLifecycleToolPattern` 派生变量、v4 seed 的
  `listener_*` 工具白名单注入、默认拦截工具集里的 `listener_*`。已部署实例
  残留的该条规则行无害（永远匹配不到），可手动删除。
- **孤儿设置键**：`web_shell_enabled` 与 `c2_enabled`（Manager 有读写函数但无
  任何消费方与 UI 入口，从未接线）。

## [0.3.85] - 2026-10-29

### 新增（公网部署安全加固）

- **登录防爆破**：`/api/auth/login` 与 `/api/auth/init` 增加进程级限流——
  每 IP 10 分钟窗口内失败 5 次锁 15 分钟；全局 1 分钟 30 次失败兜底（防
  X-Forwarded-For 伪造与分布式低速爆破）；失败响应人为延迟 300ms 并记录
  来源 IP。IP 取反代覆写的 `X-Forwarded-For` 首段（**反代必须覆写该头**）。
- **`/api/version`（鉴权）**：返回 service 与版本，供更新卡轮询换装完成。

### 修复的问题

- **`/api/health` 裸奔版本指纹**：未鉴权返回 `service:"artex"` 与精确版本号。
  改为只回 `{"ok":true,"status":"ok"}`；版本查询改走鉴权的 `/api/version`。
- **改密码不吊销旧会话**：改密码成功即**轮换 JWT 签名 key**，全部旧 token
  立即失效（此前泄露的 token 能用到 7 天自然过期）。

### 变更

- **CORS 中间件移除**：替换为安全响应头（nosniff / DENY / no-referrer /
  `/api/*` 一律 `Cache-Control: no-store`）。
- **认证页与公开静态面去产品名指纹**：登录页整体重做、未鉴权可达页面文档
  标题中性化、favicon 换中性图标。完整说明见
  `docs/公网部署安全加固-2026-10-29.md`。

## [0.3.84] - 2026-10-29

### 新增

- **漏洞情报的 CWE 落库与方法论 skill 联动**（能力对比 M1 闭环的最后一环）：
  `vuln_cves` 新增 `cwes` 列（幂等迁移），NVD `weaknesses` 与 GHSA `cwes` 两源写入、
  合并去重；`search_vulns` / `get_vuln` 输出带出 CWE；server 启动时按 skill 的
  `tags.cwe` 构建 CWE→skill 倒排并注入 agent——命中带 CWE 的条目时，工具输出
  自动附 `related_skills` 提示对应方法论 skill（无联动时输出形状不变）。

### 修复的问题

- **NVD 限速闸门换 key 不重建**：原 `sync.Once` 实现把限速间隔固定在首次使用的
  key 上——先匿名跑过、之后在 UI 配置 API key 的实例，同步仍按匿名速率（6.5s/页）
  跑到重启为止。改为按当前 key 重建（同 key 复用同一实例，主同步与快通道的
  共享语义不变），并补回归测试。
- **evidence 证据子系统在 Windows 上不可用**：blob 落盘后对目录句柄 `d.Sync()`
  刷目录项，Windows 的目录句柄不支持 FlushFileBuffers（必然 Access is denied），
  evidence 全部 5 个测试因此在 Windows 挂。改为 `runtime.GOOS` 分支：Windows 跳过
  目录 fsync（NTFS 自行保证目录项），类 Unix 保持原持久化语义。
- **Windows 上 skill 文件的「列表→读取」回路断裂**：`walkSkillFiles` 用
  `filepath.Rel` 产出反斜杠相对路径，而 `skillRelPath` 的字符白名单拒绝反斜杠
  ——前端从列表拿到的路径回传读取时被 400 拒掉。skill 相对路径边界统一归一
  为正斜杠（`ToSlash`），与前端/zip 契约一致。
- **`isRecentCritical` 死参数**：`severity` 参数从未参与判定；快通道与 NVD 客户端
  两处判定函数统一为一个（`score *float64` 区分「分数缺失」），删除重复实现。

### 变更

- 「近期快通道」的分数/KEV 判定收拢到单一函数 `isRecentCritical(score, kev)`，
  行为不变（CVSS≥9.0 或 KEV；分数缺失不因 severity 字符串放行）。

## [0.3.83] - 2026-10-23

### 修复的问题

- **手机端适配**：Playwright 390×844 逐页排查修复 7 处——工具/LLM/工具详情/
  Agent 四处编辑弹层溢出（统一「手机全宽、`sm:` 起桌面宽度」）、代理池标题/
  Skill 统计栏/流量页录制徽章三处头部挤压。表格页按既定决策保持横滚保底。

## [0.3.82] - 2026-10-23

### 新增

- **挖掘能力批次**（对标 11 个开源同类后的第一批，见 `docs/漏洞挖掘能力对比.md`）：
  - `auth_request`：把资产上已登记的凭据组装成带认证的 curl 命令（只组命令不执行，
    保住流量录制与审批链；POSIX 单引号转义经真 shell 解析测试验证）；
  - `diff_responses`：两个 HTTP 响应的结构化差分（越权/可枚举/状态机共用），
    Go 与 Python 双实现真跑对照测试；
  - **GitHub Advisory Database 第二情报源**：补 NVD 对新披露 CVE 不填版本区间的
    缺口（复用 `vuln_cves` 不建新表；判定保守——解析不出一律「可能受影响」）；
  - `api_contract`：探测 OpenAPI/Swagger/Postman 契约并列出接口清单
    （需鉴权接口单列）；
  - **skill 标准化标签**（CWE/ATT&CK/class）：四个内置 skill 已打标，UI 显示
    徽章；norma 忽略未知字段，有守门测试保证兼容。

## [0.3.81] - 2026-10-22

### 修复的问题

- **启动失败不再静默重启循环**：`start.sh` 连续 5 次异常退出后放弃自拉起，
  systemd 如实显示 failed——之前数据库密码不一致这类永久性故障会崩溃在无限
  重试里，`systemctl status` 却显示 running。
- install.sh：下载重试覆盖全错误码、强制 SHA256SUMS 校验（取不到即拒绝安装）、
  数据库角色已存在时同步 `ALTER ROLE` 密码（否则全新安装必然起不来）。

## [0.3.80] - 2026-10-22

### 新增

- **`vuln-hunting` skill**：主动漏洞挖掘七维度方法论（对象换位/流程拆解/状态机/
  数据边界/资源假设/错误路径/组合）+ `reference.md` 命令模板。
- 修复 `scopesentry` skill 的 frontmatter（结束符误写为 `## name:` 导致 norma
  解析不出、skill 对模型隐身）。

## [0.3.79] - 2026-10-22

### 新增

- **「中间件协议」宿主工具分类**：15 个纯库工具（gmqtt/pika/pymongo/zeep/
  netmiko/napalm/confluent-kafka 等），走 `pip install --break-system-packages`。

## [0.3.78] - 2026-10-22

### 修复的问题

- **v0.3.77 规则迁移的参数错位**（真 PostgreSQL 才暴露，本地 SQLite 测不出）。
  **v0.3.77 不可用于全新安装**。

## [0.3.77] - 2026-10-22

### 变更

- **内置拦截规则全面重审**：从「21 条一律 deny」改为按「不可逆性 × 作用对象」
  三层——明令禁止 10 条（硬 deny，不调模型）/ 交 Agent 研判 12 条（规则命中后
  走模型裁决）/ 人工确认 1 条（listener 启停）。规则定义收拢到单一事实源
  （`db/intercept_builtin_rules.go`），每条带分类理由。
- **规则级 timeout 真正生效**（原 `timeout_enabled/seconds/action` 三列是死字段，
  界面显示与实际生效不一致）；一次性迁移按「旧默认指纹」判定，用户改过的规则不动。

## [0.3.76] - 2026-10-21

### 修复的问题

- **空转判据搬到 PreToolUse**：原实现只挂在 Stop hook 上，而持续干活的 worker
  每轮都调工具、Stop 永远不被触发——空转收场从未生效过。

## [0.3.75] - 2026-10-21

### 修复的问题

- 前端任务轮询对 404 空转：任务不存在时停止轮询（taskMissing 检查补齐，
  覆盖两个轮询循环）。

## [0.3.73] - 2026-10-21

### 修复的问题

- 前端任务轮询 404 空转的第一处修复（详见 0.3.75 的完整版）。

## [0.3.72] - 2026-10-21

### 修复的问题

- `agentRunSeconds` 兜底值回到 1200 并补 nil 保护。

## [0.3.71] - 2026-10-21

### 修复的问题

- 悬空 asset 锚点不再击穿整条节点写入（外键残留数据的防御）。

## [0.3.70] - 2026-10-21

### 修复的问题

- **规划轮跑在独立 goroutine**：单轮卡住时放弃这一轮等下次唤醒，不再堵死
  planner 循环（与 0.3.61 的墙钟上限互为双保险，根因见 0.3.69）。

## [0.3.69] - 2026-10-21

### 修复的问题

- **Compactor.tryStart 自死锁**（planner 永久哑火的真正根因）：tryStart 持有
  `c.mu` 时调用了会再次加锁的 `cooldownFor`——不可重入自死锁，ctx 取消救不了。
  第一次压缩跑完后的下一轮规划必死。SIGQUIT goroutine dump 定位。

## [0.3.68] - 2026-10-21

### 修复的问题

- reporter 的 seed 补齐缺失的触发器：老库存量实例升级后 `report_finding` 触发器
  缺失，漏洞上报不再自动触发报告 Agent。

## [0.3.67] - 2026-10-21

### 修复的问题

- **NVD 同步加页级游标**：一轮 MaxRuntime 跑不完的 120 天窗口，下次从断掉的那
  一页续跑，而不是整窗重跑——原实现下这种窗口永远完不成。

## [0.3.66] - 2026-10-21

### 修复的问题

- 工作空间文件接口不能删除系统数据目录（路径校验）。

## [0.3.65] - 2026-10-21

### 修复的问题

- vulnintel 的「直连」回退必须真的直连：显式 `transport.Proxy=nil`，否则继承
  服务进程的 `HTTP_PROXY` 环境变量，对 NVD/cisa 不通的代理照走。

## [0.3.64] - 2026-10-21

### 修复的问题

- vulnintel 代理传输失败时自动回退直连（代理对部分源不通时不该整轮失败）。

## [0.3.63] - 2026-10-21

### 修复的问题

- 创建/更新接口的参数校验前置化：DB 约束错误不再以 500 冒给用户。

## [0.3.62] - 2026-10-21

### 修复的问题

- **流量证据绑定整体空转：100 条发现的 HTTP 证据全靠文字字段撑着**。线上实测
  `traffic_evidence_snapshots` 与 `finding_traffic_bindings` **都是 0 条**，而 agent 明明
  调了 14–18 次 `traffic_search`、3.1G 流量也确实采集了。
  - **根因是唯一的断点**：`agent_traffic_binding` 这条设置在线上**根本不存在**，
    `GetBool` 取默认值 `false` → 自动绑定全程关闭 → 报告 Agent 既拿不到
    `traffic_search`/`traffic_get`，也没有 `bind_finding_traffic` 可用。
    链路上其余环节（reporter agent、`report_finding` 触发器、工具绑定、迁移标志）**全部齐备**，
    唯独开关是关的。
  - 开启前先修了两处**会导致已确认漏洞丢失**的缺陷（否则开关一开就是净损失）：

    1. **`report_finding` 的 `traffic_refs` 里任一 ID 无效 → 整个上报回滚**。模型猜错一个
       流量 ID，已确认的漏洞就直接从库里消失。这与代码里已有的语义（「关闭时忽略 evidence
       参数，绝不因多余参数丢掉已确认漏洞」）直接矛盾——是开启状态下的漏设计。
       改成**尽力而为**：逐条解析，ID 不存在的跳过并列入返回值的 `skipped_traffic_refs`，
       其余引用照常绑定，**漏洞本身照常入库**；报告 Agent 看到 `partially_bound` 就知道要去
       `traffic_get` 核实真实 ID 再补绑。**存储故障**（证据目录不可写、正文不可读、数据库不可用）
       仍整体失败——磁盘满时静默丢证据比报错更糟。
    2. **重复上报（指纹命中）不绑定任何流量**：二次确认常带着更新后的复现包（不同响应码/新载荷），
       但去重分支只并文字证据、把新带来的流量包整个丢弃。现在也挂到**原记录**上。

- **`bind_finding_traffic` 工具描述与实际行为不符**：描述写「同批引用全部成功或全部失败」，
  实际已改为尽力而为。描述与返回值同步更新（新增 `skipped_traffic_refs` 与说明）。

### 变更

- 开启「Agent 自动绑定流量」后，报告 Agent 在漏洞入库后自动核对并绑定流量，再按最新
  `evidence_version` 写报告。**Token 消耗上升**（要查阅请求/响应正文），这是换取报告里
  能给出真实请求/响应证据的代价。
- `db.RecordedFinding` / `db.FindingTraffic` 新增 `skipped_traffic_refs` 字段。

## [0.3.61] - 2026-10-20

### 修复的问题

- **planner 卡住后整个任务永久哑火**（实测事故）：planner 的 `MaxDuration` 来自
  `clampMaxDuration(deadline, 0)`——**任务没有 deadline 时就是 0 = 不限时**；而 SDK 的
  `MaxDuration` 只在**轮边界**检查、且只约束**工具执行**（LLM 调用用的是无 deadline 的
  `l.ctx`）。于是一次上游半开连接（连上了但永不返回）就让 `Plan()` 永不返回。
  - 而 `runRound` 是**串行**的：它没返回，后续所有唤醒（边沿 + 10 分钟心跳）就全堵在
    里面出不来 → **planner 永久哑火**。
  - **实测症状**：14:30 启动后 planner 跑到 14:42（任务 3）/ 15:45（任务 4）就没再出规划轮；
    worker 自己把剩余意图跑完（最后一个 exhausted 在 16:53）；此后 **6 小时零规划轮、零新意图**
    ——「运行中 Worker」恒为 0，任务状态仍是 `running` 却什么都不干。**重启服务立即恢复**。
  - **修复**：给规划轮本身加墙钟上限 `plannerRoundTimeout`（15 分钟，与任务 deadline 无关）。
    超时后 `Plan` 返回 ctx 错误、`runRound` 正常结束、planner 恢复响应——下次唤醒再规划一轮。
    实测一轮规划 3–5 分钟，15 分钟给三倍冗余，同时保证「上游卡死」最多浪费 15 分钟就自愈。
  - 超时单独打日志（「规划轮超时…本轮作废，等下次唤醒重试」），不混进「规划出错」分支。

- **界面看不出任务已经僵死**：「运行中 Worker」列在 0 时只显示一个灰色的 `0`，与「任务真的
  跑完了」没有任何区别。现在当任务仍是 `running`、但**超过 20 分钟无任何活动**（planner 心跳是
  10 分钟，20 分钟说明连心跳都没生效）时，该列显示「疑似卡住」并给出悬停说明。

## [0.3.60] - 2026-10-20

### 修复的问题

- **任务详情页「发现」页签的继承发现混在本任务发现里**：派生任务继承源任务**全部已结束的
  发现**——实测任务 4 的接口返回 273 条，其中 214 条 inherited（来自任务 3），只有 59 条是
  任务 4 自己报的。两条任务的名字又都以「安康职业技术学院」开头、在「所属任务」列被截断，
  肉眼根本分不清哪条是本任务报的、哪条是继承的。
  - 改成：继承的按来源任务折叠成「来自任务 #3 的历史发现（214 条 · 只读）」，默认收起；
    本任务自己的发现照常平铺。后台逻辑不动（继承本身有用：少干重复活、结论可复用）。
- **全局发现页的「所属任务」列显示不出区别**：只显示描述且列宽只有 w-32（128px），两条任务
  描述开头完全相同，看起来一模一样。现在显示 `#<id>` + 描述（id 不可截断），列宽加到 w-48。

## [0.3.59] - 2026-10-20

### 修复的问题

- **任务页的会话串号：session key 不含任务维度**。store / `reqTokenRef` / `loadingKeysRef` /
  `activeKeyRef` 全部按会话 key 索引，而 key 原本是 `main:<seg>` / `plan` / `system` /
  `intent:<id>`——**前三个不含任务维度**。于是任务 3 与任务 4 的主会话 key 字面上都是
  `"main:0"`。
  - 切任务时的实际路径：reset 把 `loadingKeysRef` 置成 `new Set(["main:0"])`（预留）→ boot 时
    若新任务当前段恰是 0 则 `delete("main:0")` 不执行、预留项留着 → 用户点开主会话时
    `loadSession("main:0")` 命中预留项**直接 return、不发请求** → 界面显示的是上一个任务
    的残留会话。
  - 所有 store key 改为 `t{taskId}:<key>`，不同任务的 key 永不相同，守卫/令牌/缓存自然隔离。
  - 发给后端的 session 参数剥掉任务前缀（后端 `parseActivitySession` 只认
    `main:N`/`plan`/`intent:ID`），故加 `wireSessionKey`。
  - 连带修一处同源问题：审批聚焦的 `source.session`（后端格式、无前缀）此前被直接当 store
    key 用，一并转成 task-scoped。
- **继承来的 worker 会话混在本任务会话里**：派生任务继承源任务**全部已结束的意图**——实测
  任务 4 的接口返回 224 条，其中 206 条 inherited（来自任务 3），只有 18 条是任务 4 自己的。
  这些继承条目以前和自家条目**混在同一列表里平铺**，只靠一个「来源 #3」小徽标区分。
  - 改成：继承的按来源任务折叠成「来自任务 #3 的历史（206 条）」，默认收起；本任务自己的
    照常平铺。

## [0.3.58] - 2026-10-20

### 修复的问题

- **v0.3.56 的 thinking 降级改错了层，从未触发过**。上一版降级改的是
  `llm.CompletionRequest.Thinking`——但 thinking 参数是在 **provider 配置层**注入的
  （`llm.Config.ThinkingType`，见 `agent/provider.go` 的 `NewProvider`），不在请求里。
  请求里的 `req.Thinking` 是「本次调用覆盖 profile 设置」用的请求级开关，默认恒为空，
  于是降级条件永远为假。
  - **实测证据**：把 profile 的 `thinking_type` 设成 `disabled` 后，2013 错误如期出现
    **23 次**，而降级日志 **0 次**。
  - 改为正确降级：**换 provider**。`agent.Config` 新增 `SuppressThinking`（强制不发
    `thinking.type`）；`taskLLMStreamHooks` 新增 `withoutThinking`，按 `current()` 同样的
    优先级（绑定 → 任务链 → 全局）解析配置后重建 provider。
  - 重建的 provider **不进 provider 缓存**——它只服务这一次降级重试，缓存进去等于
    悄悄改掉了用户的配置。
  - 降级后配置除 `ThinkingType` 外完全不变（BaseURL/APIKey/Model/ReasoningEffort/
    MaxTokens/ContextWindowK 都不动），有测试守着。

## [0.3.57] - 2026-10-20

### 修复的问题

- **任务页的会话串号：session key 不含任务维度**。store / `reqTokenRef` / `loadingKeysRef` / `activeKeyRef`
  全部按会话 key 索引，而 key 原本是 `main:<seg>` / `plan` / `system` / `intent:<id>`——**前三个不含任务维度**。
  于是任务 3 与任务 4 的主会话 key 字面上都是 `"main:0"`，切任务时：
  reset 把 `loadingKeysRef` 置成 `new Set(["main:0"])`（预留）→ boot 时若新任务当前段恰是 0 则
  `delete("main:0")` 不执行 → 用户点开主会话时 `loadSession("main:0")` 命中预留项**直接 return、不发请求**
  → 界面显示的是上一个任务的残留会话。
  - 所有 store key 改为 `t{taskId}:<key>`，不同任务的 key 永不相同，守卫/令牌/缓存自然隔离。
  - 发给后端的 session 参数剥掉任务前缀（后端 `parseActivitySession` 只认 `main:N`/`plan`/`intent:ID`）。
  - 审批聚焦的 `source.session`（后端格式、无前缀）此前被直接当 store key 用，一并转成 task-scoped。

### 架构调整：让 worker 自己知道什么时候该收手

实测数据（改动前，线上 205 条意图）：意图平均跑 1712–2365 秒、最长 6828 秒；终态分布
done 18 / exhausted 99 / blocked 82——**exhausted 是 done 的 5.5 倍**，说明绝大多数探测是**被掐断的**而不是跑完的；
意图 summary 平均 737 字、最长 2267 字；接续链出现过三代（#635 → #578 → #660）。

- **无增量自动收尾（新增 `agent/idlestop.go`）**：worker 连续 3 轮没有任何写回（fact/asset/finding）
  就主动收场。判据是**产出率而不是时长**——持续产出的 worker 不会被它打断（深度探索不受影响），
  空转的才会被收。
  - 第一次触发是**提示模型把已确认的结果写回**（`blocking` 机制，SDK 会注入成 user 消息再跑一轮），
    不是直接终止——直接终止会把模型手里「探到了但还没写回」的东西全丢掉。
  - 起跑 3 分钟宽限期：worker 刚起手的前几轮可能在做准备工作，不写回是正常的。
- **接续代数上限**：`add_intent` 新增 `continues` 字段（结构化记录接续自哪条意图）。
  此前接续关系只存在于 summary 的自然语言里（「接续被预算掐断的意图 #432」），**代数算不出来**——
  线上 #660 的 parent 是 #14（一个 fact），接续关系在数据层根本没表达。
  - 同一条方向最多接续 3 次，超了直接拒绝并提示换打法或换方向。
  - 接续代数落进 `continuation_depth` 字段，planner 能直接读。
- **意图 summary 长度上限 400 字**：超长截断并保留头部（目标+做什么在开头）。
  为什么要限：summary 越长 → planner 越容易觉得「信息这么丰富，快到了，再给一次机会」→
  续派 → 意图更长 → summary 更长，是个正反馈。细节该写进 fact 的 `detail`。
- **planner 提示词区分两种 exhausted**：「连续N轮无写回」（探到边界，**不要接续**）与
  「撞步数上限/运行超时」（还有明确的下一步，可以接续但须带增量承诺）。

## [0.3.56] - 2026-10-20

### 修复的问题

- **模型拒收 thinking 参数导致整条链路静默失效**（同一个坑的第三次复发+根治）：
  MiniMax-M3.1 这类**强制 adaptive thinking** 的模型会直接拒绝 `thinking.type="disabled"`，上游返回 400
  `requires adaptive thinking; thinking.type="disabled" (including reasoning.effort=none) is not allowed (2013)`。
  这个坑在 ARTEX 里已经踩了三次：裁决路径（`server/intercept.go`）、压缩路径（`agent/compaction.go`）、
  旁路摘要路径（`sidequestion/context.go`）——三处各自硬编码 thinking 参数，各修一次，但只要再有一处
  新代码带上 thinking 就会复发。
  - **根治**：在任务侧 LLM 调用的统一入口（`server/task_llm.go` 的 `streamTaskLLM` / `completeTaskLLM`）
    加了一层降级——检测到 thinking 拒绝就摘掉该参数原样重试一次。新增 `server/thinking_fallback.go`
    承载识别与摘除逻辑。这样「某个调用方忘了别写 thinking」不再等于「整条链路挂掉」。
  - **残留**：`sidequestion/context.go` 的摘要请求仍在硬编码 `Thinking: "disabled"`，一并去掉。
  - **实测代价**：线上一次模型切换后的两小时里，裁决失败 787 次、压缩失败 130 次，**全部是同一个 400**。
    裁决每次失败都走「按失败策略处理」，那两小时里这道关卡等于完全失效。

- **压缩子块串行执行必然撞墙钟上限**：一个 200 节点的连通块按 6 节点/块切出 32 个子块，
  实测单子块约 124 秒，串行是 32×124 ≈ 66 分钟，而单次后台压缩的墙钟上限只有 20 分钟——
  必然 `context deadline exceeded`。线上形态是一个块报「子块 15/32 压缩失败」，
  前 14 个子块已白烧 30 分钟 LLM 时间，整块作废。
  - 子块改为**并发**压缩，并发度上限 4（`compactionSubConcurrency`）：66 分钟压到约 17 分钟，
    稳稳落在 20 分钟上限内；不取 32 是因为上游是共享的限流网关，32 路并发会把它打爆反而全失败。
  - 单个子块失败仍然让整块失败（宁可重试也不要写半截摘要），语义不变。

### 其他

- 工具日志的 `logPre` 死代码清理（PreToolUse 改为内联记日志后已无调用方）。
- 旁路摘要请求的测试判别式从 `Thinking == "disabled"` 改为按 system prompt 识别
  （新增 `sidequestion.IsSummaryRequest`）。原来的判别式与「不要写 thinking」直接冲突：
  为了能被识别而写出一段会被模型拒收的代码。

## [0.3.55] - 2026-10-20

### 修复的问题

- **凭据脱敏把裸 `-p` 一律当口令，误伤了正常命令的路径**：0.3.53 的脱敏规则里 `-p` 的值只要不是纯端口就打码，但 `-p` 在不同命令里含义完全不同——`sshpass`/`mysql`/`psql` 的 `-p` 是口令，`mkdir`/`tar`/`cp` 的 `-p` 是 parents/preserve。实测 `mkdir -p /opt/pojun/data/tasks/3/i661 && pwd` 的整条路径被打成 `***`，日志里根本看不出 agent 在操作哪个目录。
  - 规则改为**按命令限定**：只有 `mysql`/`mysqldump`/`psql`/`pg_dump`/`mariadb` 这几条命令的 `-p` 才当口令，其余命令的 `-p` 一律放行。
  - 补回归用例：`mkdir -p`、`tar -p`、`cp -p` 三条必须原样保留；`mysql -h... -uroot -pTr0ub4dor`、`psql -h ... -p hunter2` 两条必须打码。

## [0.3.54] - 2026-10-20

### 修复的问题

- **工具日志的 blocked 判定混用了两种语义**：一是「平台自己拦了这次调用」（精确判据是 ARTEX 的固定前缀），二是「输出里有 WAF/403/denied 措辞」（启发式）。实测两个误判：`list_findings` 返回的 30KB 漏洞数据被判 blocked（漏洞描述里本来就有 403/denied），「生成漏洞报告」的 Bash 命令也被判 blocked。
  - 日志层改为**先转发拦截链再记日志**——拦截链返回的决定才是最可靠的判据，pre 行直接标 `BLOCKED`，不再靠猜。
  - 启发式拆成独立的 `waf` 档：`blocked` 只表示「被平台管控」，`waf` 表示「输出像被目标挡了」。两个信号都保留，但不再互相污染——此前 blocked 的计数因为误报完全失去意义。

## [0.3.53] - 2026-10-20

### 修复的问题

- **工具日志里的命令凭据明文进了 journal**：agent 的命令里带着真实口令（`sshpass -p 'xxx'`、mysql 的 `-p`、Authorization 头、URL 里的 `user:pass@host`），而工具日志会把命令摘要写进 journal——**口令就进了系统日志**（journal 默认所有用户可读、还会被 journalctl 导出、会被日志采集器送到别处）。实测 30 分钟内 12 行含凭据形态，其中抓到过 `sshpass -p 'dolphin!@#'` 原样进日志。
  - 脱敏只做「形状明确」的替换，不做通用密钥识别——宁可漏脱敏，也不能把正常参数误伤成 `***`（否则日志失去可读性）。覆盖形态：sshpass 的 `-p` / mysql、psql 的 `-p` / `key=value` / `Authorization: Bearer|Basic` / URL 里的 `user:pass@host`。
  - `-p` 这条要排除纯端口与端口列表（`nmap -p 80,443,8080` 是端口扫描，不是口令）。

## [0.3.52] - 2026-10-20

> 调优循环需要日志，但日志被一个后台任务的 debug 输出整个淹掉了。

### 修复的问题

- **journal 被 vulnintel 的 debug 日志刷掉 33 万行**：一次资产-CVE 匹配在 28 秒内写了 **3.2 万行**逐条 debug（对「每个资产的每个 tech × 每个 product」打一行），journald 随即 `Suppressed 332115 messages from artex.service`——**agent 自己的日志被连带丢弃**。实测一次 30 分钟观察窗里，journal 有 32565 行，其中 32465 行是 vulnintel 噪音，只有 64 行是 agent 的工具调用信号。调优循环因此形同闭眼调。
  - 逐条 debug 日志删除。
  - 匹配算法改成 **token 倒排索引**：原来是 O(资产 × tech × product) 三重嵌套，且 `cpeTokens(product)` 对每个 product 每轮都重算一遍；现在预建索引、每 product 只算一次，资产匹配退化成查表。
  - 顺带按「资产 × CVEID」去重——同一 product 有多个 cpeToken 时同一个 CVE 会多路命中，原实现会重复 append。
  - **匹配语义不变**：新增等价性测试用随机数据跑 40 轮，断言新算法与旧算法的命中集合完全一致；另两条测试守住「同一资产内去重」与「跨资产不去重」。
- **工具日志的 blocked 判定误伤数据类工具**：启发式判定（WAF/403/denied 措辞）原先对所有工具生效，而 `list_findings` 返回的漏洞数据里本来就含 "403"/"denied"——实测 30KB 的漏洞列表被判成 blocked。现在启发式只对 Bash 生效（与 guard 一致：Bash 是打目标的），平台拦截靠 ARTEX 自己的固定前缀精确识别，对任何工具都生效。

## [0.3.51] - 2026-10-20

> 没有可观测性，调优就是闭眼调——这条把「看得见」补上。

### 新增的能力

- **工具调用进 journal**：planner / worker / mainagent / chat 的每次工具调用现在都会记录到 journal（`[tool]` 前缀），含「谁调用了什么工具 + 结果是 ok/error/blocked + 本轮怎么收场」。
  - **此前完全没有**：journal 里只有 planner 的心跳和 vulnintel 的刷屏，worker 到底在不在干活、卡在哪一步、有没有报错，只能去翻 `transcripts/*.jsonl` 的文件 mtime 才能确认。
  - **实测缺口**：一次 30 分钟观察窗内 8 个 worker 的 transcript 都在更新，而 journal 记的 37 行里**没有一行反映 worker 的动作**。
  - 日志层是**纯旁路**：套在拦截链外侧（先记后转发），不影响 steer 纠偏与拦截裁决（有测试守住这条契约）。
  - 摘要而非原文：命令只取首行并限长 96 字符，工具输出只记字节数 + 三态分类，避免把 journal 撑爆。

### 顺带

- `RunInfo` 增 `Kind` 字段区分 planner / worker / main / chat —— 原有 id 三元组区分不出 planner 与 mainagent（都是 TaskID+ExplorationID 且无 IntentID），而「planner 20 分钟没调工具」和「mainagent 20 分钟没调工具」是两种不同的故障。

## [0.3.50] - 2026-10-20

### 修复的问题

- **DSL 的空值精确匹配查不到 NULL 的资产**：`field==""` 生成的是 `col = ''`，而资产库里**几乎所有字段用 NULL 而不是空串**（实测任务 3 的 4966 条资产里，空串几乎为 0，NULL 占绝大多数）——于是 `service_name==""` 一条都查不到。实测这批「服务已登记、service_name 为 NULL」的资产有 **2073 条**（占 2180 个 http 服务的 95%），agent 根本看不见它们。现在空值精确匹配生成 `(col IS NULL OR col = '')`，覆盖两种表示。**非空值的 `==` 语义不变**（仍是精确等值，不带 ILIKE）。

### 顺带

- `list_assets` 的工具描述补上「查空值用 `field==""`」与「找未测资产用 `list_untested_assets`」的指引。

## [0.3.49] - 2026-10-20

### 修复的问题

- **mainagent 也缺宿主工具清单**：它同样有 Bash 工具（基础默认工具集）、会自己动手查证后回答人，但 system prompt 里没有工具清单——和 worker 同样的问题，一并修掉。

## [0.3.48] - 2026-10-20

> 装了工具，模型却不知道该怎么用——清单根本没进 worker 的提示。

### 修复的问题

- **宿主工具清单没进 worker 的 system prompt**：清单（`hosttools.Summary()`）只注入了 **planner 的唤醒提示**（用于「派意图选手段时以家底为准」），而**真正动手执行命令的是 worker**——它压根不知道本机有哪些工具。实测工具使用画像：近 1 小时只有 python3(286)/curl(140)/ssh(81)/nmap(35) 在用，**新装的一批工具（dalfox/feroxbuster/chisel/gitleaks/amass/notify…）使用次数全部为 0**。现在 worker 的 system prompt 里也注入清单。
- **清单只有名字、没有用途**：`available` 原来只是 `["nmap","sqlmap",...]`，模型判断不出该在什么场景调哪个（chisel 是内网穿透、dalfox 是 XSS 扫描、feroxbuster 是目录爆破——名字完全看不出）。改成 `["nmap: 端口扫描/服务指纹", ...]`，并加了「别用 python3 从头造轮子」的提醒。
- **缺失工具的安装提示白占上下文**：`missing` 从 `[{name, install}]` 改成**纯名字数组**。安装提示是给人看的（宿主环境页），模型既不能装也不需要知道怎么装，给它 27 条安装命令只是每轮都在烧上下文。清单总体积 2848 → **1099 字节**（省 61%）。

### 新增

- `agent/worker_tools_test.go`：worker 的 system prompt 必须含工具清单；清单体积上限 4000 字节；每项必须带用途。
- `hosttools/summary_size_test.go`：同上两条（针对 `Summary()`）。

## [0.3.47] - 2026-10-20

### 变更

- **宿主工具清单带上用途**：`hosttools.Summary()`（注入 `graph_overview`）的 `available` 从纯二进制名改为「命令名: 用途」。目录里有 30+ 个工具，模型只看到名字判断不出该在什么场景调哪个，「派意图选手段以家底为准」才真正成立。同时 `missing` 从 `[{name, install}]` 改为纯名字数组——安装提示是给人看的（宿主环境页），模型既不能装也不需要知道怎么装。清单体积 2848 → 1099 字节。

## [0.3.46] - 2026-10-20

> 用户最初提的第四块（工具页/宿主环境页扩展）此前一直延期，现在基础设施齐了。

### 新增

- **宿主工具扩容 10 个**（GitHub Release 类）：`gitleaks`（代码/配置密钥扫描）、`chisel`（内网穿透与隧道）、`amass`（OWASP 子域名枚举）、`dalfox`（XSS 扫描与利用）、`feroxbuster`（Rust 版目录/文件爆破）、`notify`（外带数据接收，DNS/HTTP/TLS 多通道）、`interactsh-client`（OOB 回连客户端，配合 nuclei 的 oob 模板）；（pip 类）：`netexec`（SMB/WinRM 横移与凭据喷洒）、`semgrep`（SAST 规则扫描）、`pwntools`（利用脚本框架）。
- **安装器支持更多归档格式与架构命名**：各项目的 release 资产命名差异极大（架构在前/后、版本带不带 v、`.zip`/`.tar.gz`/`.gz` 三种格式、架构名有 amd64/x86_64/x86/x64 四套），原先的模板只认「`{tool}_{ver}_linux_{arch}.zip`」这一种，装另外一半项目必然 404。现在模板占位符扩到 `{ver}` `{verv}` `{arch}` `{arch2}`(x86_64) `{arch3}`(x86) `{arch4}`(x64)，hostd 的解包从只支持 zip 扩到 zip / tar(.gz) / 单文件 gz（**按内容嗅探，不靠后缀猜**——后缀拼错就直接装不上）。

### 测试

- `hostd/asseturl_test.go`：资产 URL 必须与**实测的真实 release 资产名**逐字一致；模板里不能出现未实现的占位符（拼出来会带字面量 `{archX}`）；每个 GitHub 配方都必须有 Repo + AssetTmpl + Bin。

## [0.3.45] - 2026-10-20

### 修复的问题

- **install.sh 写运行期装机代理一直失败**：两处 bash 写法叠加所致。① `eval "$(python3 ... <<'HEREDOC' ... HEREDOC\n)"`——heredoc 套在命令替换里，eval 静默失败、`db_pass` 变空串，psql 连不上，而外层只看到一句「写入失败」；② psql 的 `:'proxy'` 变量替换在 `-c` 参数里**不生效**（那是 `-f` 读文件或交互式会话才有的路径），报 `syntax error at or near :`。现在整个写入过程交给 Python：读 config.json 取连接参数、拼好并转义 SQL、调用 psql，中途不经 bash 变量传递。

## [0.3.44] - 2026-10-20

> 按实测数据继续调优压缩参数。

### 调整

- **压缩单块节点数上限 12 → 6**：逐档实测同一份 26 节点真实输入——26 节点/块给满 65536 预算也烧光（10 分钟不出正文）；9 节点/块 3 块里仍有 1 块失败；**6 节点/块 124 秒就正常收尾**（用 11733 token）。切得越碎，模型越容易收尾、耗时也越短。
- **压缩输出预算 32768 → 65536**：6 节点/块在 65536 下稳定成功。
- **压缩失败退避**：连续失败时该探索的冷却时间指数增长（60s → 2m → 4m …，封顶 30 分钟）。一次失败的压缩要烧几百秒 LLM 时间，而基础冷却只有 60 秒——不退避就会变成「每分钟烧一次 5 分钟」的无谓循环。压缩失败不阻塞主流程（没有 digest 时 planner 直接看原始节点），所以退避只是省资源。

### 新增

- `agent/compaction_backoff_test.go`：连续失败时冷却指数增长、成功即清零、退避封顶 30 分钟、各探索互不影响。

## [0.3.43] - 2026-10-20

> 用户反馈"很多任务都是预算或者中断"。实测定位到三个硬限制，全都是"给得太紧"。

### 修复的问题

- **单条意图的墙钟预算只有 20 分钟，导致大量意图预算耗尽**：实测生产环境里 **89 个意图 exhausted vs 8 个 done**，全部是「运行超时(exhausted)」而非轮次耗尽（`max_turns=0` 不限轮次）。exhausted 是**终态**、不会被自动重新领取，于是这条线索就断了（已发现的事实/资产/漏洞仍会写回，但没做完的部分没了）。默认预算提到 **60 分钟**（3600s），已部署实例由一次性迁移把仍是 1200 的改成 3600。
- **上下文窗口按 200K 算，而模型原生支持 1M**：profile 的 `context_window_k` 留空时，代码按 Claude 的默认值 200K 计算压缩阈值。而本平台常用的 `minimax-m3.1-flash-free` 原生上下文是 **1M**（模型自报 1000000）。结果是压缩在远未到上限时就触发——压缩本身要额外调一次 LLM（还要 32768 输出预算），白白吃掉预算、拖慢流程。默认值改为 **1000K（1M）**，压缩阈值从 ~174K 提到 ~930K。阈值数学在 1M 下是安全的（`effectiveWindow = 1M − 20K = 980K`，buffer 50K，norma 的分档支持 `>= 800000`）。已部署实例由一次性迁移把仍是 0（未设置）的 profile 显式设为 1000。
- **裁决超时从 90 秒放宽到 180 秒**（同 0.3.42）：思考型模型的裁决耗时随命令长度而变，长命令明显更久，且升预算重试要挤在同一个窗口内。

### 新增

- `agent/context_window_test.go`：默认上下文窗口为 1M、显式配置优先、越界时夹在 [32K, 1M]。

## [0.3.42] - 2026-10-20

> 用户反馈的两个问题：任务大量预算/中断中断；自动审批"结果没有内容"。

### 修复的问题

- **自动审批"结果没有内容"**（根因与上下文压缩失败同源）：模型裁决的输出预算被硬编码成 2048 token，而思考型模型（强制 adaptive thinking 的 `minimax-m3.1-flash-free`）**思考与正文共用同一份额度**。生产环境的裁决记录里能直接看到两种失败形态：
  - `原始回复 ""` —— 思考烧光，正文一个字没轮到（**长命令**最常见：几百到上千字符的 shell 脚本）；
  - `原始回复 "{\"decision\":\"al` —— JSON 写到一半被截断。

  修复：首次预算提到 **32768**；正文为空或解析不出时**升预算重试**（32768 → 65536 → 131072，每次都严格更大，不做同预算的无效重试）。
- **裁决超时从 90 秒放宽到 180 秒**：思考型模型的裁决耗时随命令长度而变（实测短命令 4~26 秒，长命令明显更久），且升预算重试要挤在同一个超时窗口内。90 秒会把「模型其实能判定」误判成超时失败——生产环境里已有 24 条这种超时记录。已部署实例由一次性迁移把仍是默认 90 的改成 180（用户自己调过的不动）。
- **裁决空回复的错误信息带上原始内容**：以前只有「格式无效」四个字，排查时无从下手。

### 新增

- `server/judge_budget_test.go`：裁决首次预算足够大、空回复触发升预算重试且预算严格递增、重试受 ctx 取消约束、超时默认值足够容纳重试。

## [0.3.41] - 2026-10-20

> 观察期实测：日志里 40 次压缩有 39 次失败，冷节点压缩基本从未落地。

### 修复的问题

- **上下文压缩 97.5% 失败**（`empty body from model`）：压缩调用的输出预算被硬编码成 1500 token，而模型是强制 adaptive thinking 的 `minimax-m3.1-flash-free`——**思考与正文共用同一额度**，1500 全被思考烧光，正文一个字都吐不出来。逐档实测同一份真实输入（26 节点，prompt 3084 token）：

  | max_tokens | finish_reason | 正文 | 耗时 |
  |---|---|---|---|
  | 1500（硬编码值） | length | 0 字 | 立即 |
  | 2048 / 4096 / 8192 | length | 0 字 | 立即 |
  | 32768 | length | 0 字 | 211 秒 |
  | 65536 | 超时 | — | 10 分钟未回 |

  同一模型把输入缩到 3 个节点（743 token）、预算 32768 时：`finish=stop`、正文 190 字、用 2134 token。**结论：能否收尾取决于「单次输入规模」，与输出预算大小无关**——思考型模型会按 max_tokens 预算持续思考，单纯加预算只会把失败推迟。
- **超大连通块不做切分**：一个连通分量可能有几十个节点，实测 26 节点必失败、9 节点正常（9 节点/块实测 `finish=stop`、正文 200 字、194 秒）。现在超限的块自动切分成若干子块分别压缩，多段 body 拼成一段摘要，语义与原来的一段等价。
- **单次压缩墙钟上限只有 5 分钟**：对长输入的思考型模型明显不够（实测 26 节点要跑 200 秒以上）。放宽到 20 分钟——压缩是**后台协程**，与 worker 领取意图并行（日志里可见两者交替），等久一点不影响主流程进度。
- **空正文错误不带任何诊断信息**：以前只回一句「empty body from model」，排查时无从下手。现在带 stop reason、内容块数、输入/输出 token、思考块数，一眼能分清「被截断」还是「只有思考没正文」。

### 新增

- **「系统 → 设置 → 上下文压缩参数」**：`compaction_max_tokens`（输出预算，默认 32768）、`compaction_timeout_seconds`（单次超时，默认 1200 秒）、`compaction_max_members`（单块节点数上限，默认 12）。填 0 即用默认值。

## [0.3.40] - 2026-10-20

> 装机代理交互式配置 + 全链路生效；SOCKS5 代理此前是坏的；宿主工具扩容。

### 修复的问题

- **SOCKS5 代理在「一键安装」里根本不工作**：`hostd` 的下载器用 `http.ProxyURL` 设置代理，而 `net/http` 的 ProxyURL 只懂 HTTP CONNECT 代理——喂它 `socks5://` 会得到 `unsupported protocol scheme`。表现是「填了 socks 代理但下载照样失败」，而报错完全指不到「协议不匹配」这个真因。改为按协议分流：`socks5://`/`socks5h://` 走 `golang.org/x/net/proxy` 的 SOCKS5 dialer，其余照旧。
- **install.sh 装 PostGIS/PostgreSQL 那处 apt 没走代理**：`apt-get install -y postgresql` 是硬依赖，apt 源在国内机器上常常要代理才拉得到，代理不通时整条装机流程断在这一步。改为与其他 apt 调用一样带 Acquire 代理选项（dnf 同理，且只在确实有代理时才加 `--setopt=proxy=`，避免把空串当成无效代理）。
- **install.sh 里的 curl 不认 `socks5://` URL**：curl 的 `-x` 接受不了这种 URL 形式（同样是 `unsupported protocol scheme`），它要的是 `--socks5-hostname host:port`。现在按协议构造 curl 参数，并在填了认证时补 `--socks5-basic -U`。
- **代理只在装机期生效，运行期各走各的**：装机时代理只作用于脚本自身，Web「宿主环境」页的「一键安装」和后台情报同步读的是数据库里的 `install_proxy` 设置，两者不联动——用户装完机器还得再手填一遍代理。现在 install.sh 会把代理写进数据库 setting（Docker 形态写 `.env` 并通过 `POJUN_INSTALL_PROXY` 透传），并在主服务与 hostd 两个 systemd 单元里都带上代理环境。

### 新增

- **install.sh 交互式代理配置**：跑脚本时询问「是否配置出网代理」，支持 `http://` / `https://` / `socks5://` / `socks5h://`（可带 `user:pass@`），裸 `host:port` 自动按 http 处理。填完自动验证（真实请求 GitHub API，与装机用途同源），通了才继续；不通会问要不要坚持。给了 `--install-proxy=` 也会走同一套校验与验证。
- **代理自测 API + 设置页「测试」按钮**：`POST /api/hostenv/proxy-check` 拿当前生效的代理做一次真实请求，返回可用性、延迟、出口 IP 与**可执行的修复建议**（协议不匹配/认证缺失/超时/DNS 失败分别给不同话术）。代理会失效，改完点一下就能知道，不用等装工具失败才发现。判定口径与 install.sh 装机期一致（统一走新的 `proxyprobe` 包）。
- **宿主工具扩容**：新增 ProjectDiscovery 系的 `naabu`（快速端口扫描）、`dnsx`（DNS 解析/爆破）、`katana`（Web 爬虫）、`tlsx`（TLS 证书提取），加上 `impacket`（SMB/NTLM 工具集，apt 包 `python3-impacket`）、`seclists`（通用字典集）、`gitleaks`（密钥扫描）。install.sh 的 `--with-tools` 现在一次装齐：apt 系工具 → GitHub Release 系（nuclei/httpx/subfinder/naabu/dnsx/katana/tlsx 走同一套发布格式，一个循环搞定）→ SecLists 浅克隆 → pip 工具 → Playwright MCP + chromium 预置。hostd 的「一键安装」页同步能装这些。
- **Playwright chromium 预置到 `/opt/ms-playwright`**：装到 `~/.cache` 的话，服务以 `artex` 用户运行时看不见（root 家目录里的缓存它读不到），首次启动 MCP 仍要联网下载。

## [0.3.39] - 2026-10-20

> 观察期实测：三处能力缺失导致 agent 大量无效调用，以及「一堆子任务中断但看不出原因」。

### 修复的问题

- **子任务中断原因完全不可见**（用户反馈「一大堆子任务异常中断」的直接根因）：意图只有 done/blocked/exhausted 三态，实测 94% 的意图以非 done 收场（exhausted 72 / blocked 40 / done 7），但**为什么**中断没有任何记录——轮次上限、任务超时、LLM 配额耗尽、超时、错误、被杀、任务完成这七种终止原因在库里都写成同一个 `blocked_reason=context_exhausted`。新增 `SetIntentStopReason` 写入真实原因，DTO 带出 `blocked_reason`，探索图的状态徽章悬停即见。
- **DSL 不支持网段查询**：`assets.ip` 是自由文本，DSL 里只能 `=`/`==`/`!=` 模糊匹配，agent 想查网段只能试 `ip >= 10.0.0.0`——实测 24 次「字符串字段 ip 不支持运算符 >=」加 11 次语法错误，全是这一个能力缺失逼出来的。新增 `cidr` 字段，用 Postgres inet 包含运算（`try_inet(ip) >>= 网段`），转换不出 inet 的行（主机名）自然被排除，不会让一条脏数据打挂整个查询。
- **DSL 错误不可执行**：`list_assets` 只回「DSL 错误: 字符串字段 ip 不支持运算符 >=」，agent 会再猜一次同样的写法（实测同类错误重复 42 次）。补上 `dslHint` 提示：告诉它字符串字段只支持 `=`/`==`/`!=`、要按数值比就用 `port`/`status_code`、要按网段查就用 `cidr=10.10.0.0/16`。
- **`search_vulns` 的 `limit` 参数类型写错**：误写成嵌套对象，校验器于是要求模型传 `limit: {}`，实测 41 次调用全部报 `invalid tool input: limit: expected object`——这个工具等于废了一半。改为整数参数。

### 其他

- `exploration-graph.tsx` 里两个裸 NUL 字节让 Git 把该文件当二进制，diff 审查全废。改成转义写法，行为不变。

## [0.3.38] - 2026-10-20

> 观察期发现的问题：MCP 连接失败刷屏、宿主环境缺 Node。

### 修复的问题

- **MCP 连接失败刷屏**：`wireAgentAugment` 每个 agent run 都会把「enabled 且对该 agent 可见」的 MCP 连一遍。一个连不上的 MCP（实测是 `browser`：用 `npx @playwright/mcp` 启动，而宿主上没装 Node）会在**每个 worker 启动时**刷一条错误——几十轮下来日志几乎全是它，真正的问题被淹掉，而且每次都要 fork 一个进程去等它失败。加了失败短路：失败后 10 分钟内直接跳过该 MCP；连上则清掉记录（所以装好依赖后无需重启服务，最多等一个窗口）。
- **MCP 连接失败给出可执行提示**：stdio 传输在连接前先 `exec.LookPath` 检查命令是否存在，报「命令 "npx" 不在 PATH 里：装上它，或在「MCP」页把该服务器停用」，而不是裸的 `exec: "npx": executable file not found in $PATH`。
- **宿主环境页新增 `nodejs` 工具项**（apt/dnf）：`npx` 随 nodejs 一起装，browser 这类基于 npx 的 MCP 服务器才有运行时可用；之前机器上没装 Node，那个 MCP 永远连不上。

## [0.3.37] - 2026-10-20

### 修复的问题

- **裁决解析仍把可用回复判成「格式无效」**：`ParseVerdict` 要求 JSON **恰好两个字段**（`len(fields) != 2` 即失败）——模型多给一个 `reason`/`explanation` 字段就整条作废。改为只要求 `decision` 与 `comment` 都在，多余字段忽略（同名重复仍判无效）。
- **补「三段无标签」的兜底**：模型偶尔写成「读取文件；返回内容；命中 A5」而漏掉标签，此时按全角「；」切成三段——只切分、不改写内容。**带标签但某段为空**仍然判无效（实测那是真失败，不是排版偏差），兜底只在「压根没有标签」时启用。
- **解析失败时把模型原始回复截 400 字带进错误信息**：只有「格式无效」四个字根本没法排查（缺三段？分隔符不对？被 max_tokens 截断？）。

## [0.3.36] - 2026-10-20

> 全量切 judge 后的实测修复：裁决模型 100% 失败 + 规则误报把任务打成一片。

### 修复的问题

- **裁决模型每次调用都失败（100%）**：裁决请求硬编码了 `thinking.type=disabled`，而 MiniMax-M3.1 这类**强制要求 adaptive thinking** 的模型会直接返回 400（`requires adaptive thinking; thinking.type="disabled" is not allowed`）。实测 16 次裁决全部落进失败策略，而失败策略默认 `allow` —— 等于这道关卡完全没生效。改为默认不发 thinking 字段（由 profile 的 `thinking_type` 决定）。同一问题也修在上下文压缩摘要与旁路提问摘要两处。
- **裁决的配套参数按「带思考的模型 + 人不在电脑前」重新标定**：
  - 裁决超时 15s → **90s**（带思考的模型思考本身就要十几秒，15s 会把「正在想」误判成失败）；
  - 裁决输出上限 1024 → **2048**（思考内容吃额度，1024 会被思考吃光、正文 JSON 反被截断成不可解析）；
  - 裁决失败策略 `allow` → **`ask`**（模型挂掉时静默放行 = 关卡自动敞开；转人工至少留下一条待办记录）；
  - 人工审批超时 `deny` → **`allow`**、300s → **180s**（人工审批会**同步阻塞** worker，操作员不在电脑前时 deny 等于把整条渗透链卡死；放行只影响这一条命令，事后仍可在「拦截审批」页追认）；
  - 规则级 ask 的超时同样改为放行 + 180s。
- **裁决回复的排版偏差不再判为「无法解析」**：模型偶尔用半角冒号/分号，或把三段写成三行。原先一律判失败、直接走失败策略。现在只做**排版归一**（标点与空白），三段缺一段仍然判无效 —— 语义不补。
- **两条内置规则的实测误报**（全部来自生产环境的真实拦截历史，都是合法探测）：
  - 「删除系统关键目录」的裸 `/` 分支把 `rm -f /tmp_out.$$`、`rm -f /usr/share/nmap/scripts/_t.nse` 这类正常清理全拦了 → 收窄为「删掉整个关键目录」，并新增一条单独覆盖「关键目录 + 通配」（`rm -rf /var/lib/*`）；
  - 「关机 / 重启」的裸 `\b` 把路径枚举里的 `/reboot`、`/reset` 当成关机命令 → 收窄为「必须出现在命令位置（行首 / `;` `&&` `|` 之后 / `sudo` 之后）」。
  - seed 是 first-insert only，改代码对已部署实例无效，所以加了一次性迁移同步 pattern（只改 pattern，不动 action/enabled/priority —— 用户自己改成 judge 或停用的实例行为保持）。
- 回归基线：把 8 条真实的生产命令固定成测试用例，断言「确定性破坏」类规则对它们**零命中**，同时真正的破坏行为（`rm -rf /etc`、`rm -rf /var/lib/*`、`sudo shutdown -h now`、`mkfs.ext4 /dev/sdb1` …）仍被抓住。

## [0.3.35] - 2026-10-20

### 修复的问题

- **代理地址校验太松，批量导入把乱码当合法代理**：`url.Parse` 对「坏行这不是地址」这类不含空格的垃圾串几乎不报错（它当成一个 path），批量导入实测 5 条里混进 1 条垃圾仍报 `added=5`。补主机名形状检查（只允许字母数字/点/横线/下划线，IPv6 走 `net.ParseIP`）与端口数字校验；单标签主机名（内网常见）仍放行，真正的通不通交给连通性验证判断。

## [0.3.34] - 2026-10-20

> 能力批次：拦截规则支持 Agent 研判、漏洞情报页可配可诊断、代理池支持批量导入与智能切换。

### 新增的功能

- **拦截规则新增「Agent 研判」动作**：规则的 action 从 allow/deny/ask 扩展到 `judge`——命中这类规则时不取固定动作，而是交给裁决模型判断这次调用是否越界（只读/正常渗透放行、直接破坏真实资产拦截、判不准转人工）。复用已有的裁决提示词、模型配置、超时与失败策略、judge 独立用量统计，不新增第二套裁决实现。规则显式要求研判时**不受全局兜底审批开关影响**（否则规则形同虚设）。
- **漏洞情报页从只读状态页改成可配置 + 可诊断**：暴露 NVD API Key、GitHub Token、同步专用代理、PoC 聚合开关、首次回填天数、单轮上限；新增「立即同步」与「测试连通性」（逐源真实探测 NVD/KEV/GitHub/模板树）；每个数据源可展开看完整错误 + 中文修复建议（403/限速/DNS/代理不可达/TLS 等各有对策）；新增 nuclei 模板树卡片（模板数、是否 git 仓库、最近更新、缺模板时的提示）。凭据只写不读，读取时只回掩码与 `*_set` 布尔。
- **代理池批量导入**：支持一行一个的常见导出格式（`host:port`、`http(s)://`、`socks5://user:pass@`、`host:port:user:pass`、`名字 | 地址`、`#` 注释），自动补 `http://`、按 URL 去重更新，逐行报告非法行与原因；支持追加/替换两种模式。
- **代理池连通性验证与一键筛选**：并发验证每个上游（经该代理请求探测地址），返回延迟、出口 IP、错误；不可用的立刻熔断，页面显示熔断剩余时间，可一键移除失效条目。
- **代理池主动健康检查**：后台协程按间隔（默认 10 分钟）巡检已启用上游，不通的立即熔断——不再等「连败 5 次」才反应。
- **代理池新增策略「按目标粘性（首次随机）」**：同一目标第一次随机选定一个出口并固定，跨目标分布随机；该出口熔断后自动改选。
- **Agent 侧代理池工具**：`proxy_status`（查池状态：策略、每条上游可用性/熔断/最近成功失败）与 `proxy_report`（上报「这个出口对这个目标被限速/不通」，平台立即熔断并换出口），默认绑定 worker 与 planner。出口选择始终由平台按策略做，Agent 只负责反馈「这个出口不好使」。

### 修复的问题

- **裁决配置在数据库未就绪时空指针崩溃**：`judgeConfig` 直接解引用 `i.db`，server 初始化早期或测试里会 panic——而裁决在工具调用的同步路径上，一崩就是整个 agent 进程死掉。改为 nil-safe 走默认值。
- **漏洞情报的 NVD Key / GitHub Token / PoC 开关 / 回填天数 / 专用代理全是死代码**：`vulnintel.Config` 支持这些字段，但同步循环只读了 NVD Key 与代理，其余配置无处可填。现已全部接通并可在页面配置。
- **nuclei 模板树同步与情报同步开关耦合**：关掉漏洞情报同步会让扫描模板也停更。现在模板树独立刷新（仍走维护出网代理）。

## [0.3.33] - 2026-10-20

### 修复的问题

- **手机打开任务详情页整页报错（电脑正常）**：移动端浏览器 / 国产内置浏览器（微信、QQ 的 X5 内核）与部分旧 Android WebView 缺少几个较新的浏览器 API，调用时抛异常，而项目**没有错误边界**，于是整页只剩一句 `Application error: a client-side exception has occurred`。本次把所有这类调用降级到等价的老 API：
  - `MediaQueryList.addEventListener/removeEventListener` → 不存在时回退 `addListener/removeListener`（任务详情页的会话/审批表格、侧边栏断点都走它）；
  - `ResizeObserver` → 不存在时只做一次性测量（会话记录里的自动滚动/居中）；
  - `Array.prototype.at`、`String.prototype.replaceAll`、`structuredClone` → 换成下标访问 / `split+join` / JSON 深拷贝。
- **新增全局错误边界**：`app/error.tsx` 与 `app/global-error.tsx`。以后再出客户端异常，页面会直接显示错误名、message 与 stack 前几行（可直接截图反馈），不再是一句无信息的白屏；同时 `console.error` 保留完整错误。

## [0.3.32] - 2026-10-19

### 修复的问题

- **Auto 把同一目标按阶段拆成多个并行任务**：一次「资产探测 + 服务识别 + 漏洞挖掘 + 出报告」的请求被拆成「资产探测与服务识别」和「漏洞挖掘与安全评估」两个任务同时开跑。两者其实严格串行（没有资产就无从挖洞），并行只会重复扫描同一批网段，而「挖洞」那个任务开局手上一个资产都没有。根因是上一版 Auto 提示词里那句「一次请求里有几件本质不同的事(如"先摸资产再打某站点")可以建多个任务」——例子本身就是有先后依赖的，等于直接教模型拆错。
- 提示词按上游原版的克制写法重写，明确 **任务按【目标】切、不按【阶段】切**：一个任务 = 一个目标 + 它从侦察到出报告的完整链路；同一目标的多阶段只建一个任务、按顺序写进 goal；只有多个互不依赖的目标才建多个任务。`spawn_task` 的工具描述同步加上这条约束（模型调用时看得到），并刷新已入库的工具 schema。

## [0.3.31] - 2026-10-19

### 修复的问题

- **CISA KEV 同步从未成功过**：`FetchKEV` 用 `NvdClient.Base` 拼 URL，而 `NewNvdClient` 把 Base 设成了 `services.nvd.nist.gov`，于是每轮都去请求 `services.nvd.nist.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` 并拿回一个 404 的 XHTML 错误页（日志里那句 `kev feed status 404: <!DOCTYPE html ...>`）。结果漏洞情报库的**「在野利用」标记一条都没有**，而 KEV 恰恰是 `search_vulns` 排序里权重最高的一档。KEV 固定走 cisa.gov，与 NVD 的 Base 解耦；加了一条回归测试盯住「生产客户端的默认 Base 下必须打 cisa.gov」。

## [0.3.30] - 2026-10-19

> 能力批次：让「对话里派活」真正走任务，并修好被加固挡死的渗透工具。

### 新增的功能

- **Agent「本地命令执行」开关（`local_exec`）**：关掉后该 Agent 不再拥有 Bash / Write / Edit / 交互式 Shell，只剩只读检查（Read/LS/Glob/Grep）与平台工具，**想把事情做成只能派任务**。Agent 配置页可开关；内置平台助手 **Auto 默认关闭**。此前 Auto 手里握着 Bash，用户一提渗透需求它就自己写脚本开扫（实测直接写了个 Python 扫描器扫穿 `10.10.0.0/16`，一个任务都没建），「用 spawn_task 派活」只是一句没人执行的提示词。
- **Auto 提示词重写**：明确「涉及对目标的任何真实动作，第一个动作必须是 spawn_task」，并要求把范围、交付要求、深度限制逐条写进 goal（任务里的规划者只看得到写下来的东西）；只有纯平台操作才不用建任务。
- **Bash 工具描述注入本机网络能力**：按运行时事实（euid + `CapEff`）说明 masscan / `nmap -sS` / ping / nuclei 能不能用、`nmap` 特权扫描要显式加 `--privileged`。此前 agent 为了搞清「masscan 为什么报 PF_PACKET not supported」「nmap -sS 为什么说需要 root」烧掉十几轮，最后退回自写脚本。
- **nuclei 模板树走维护出网代理**：`git clone/pull` 现在带上装机代理（回退全局代理、搜索代理）。此前直连 github.com 拉不下来，`scan_with_nuclei` 永远停在「模板树不可用」。模板树同步也从「漏洞情报同步开关」里解耦——关掉情报同步不该让扫描模板烂在原地。

### 修复的问题

- **服务单元的能力位把渗透工具全挡死了**：`MemoryDenyWriteExecute=true` 让 nuclei 启动即 panic（Go 的 sonic 加载器要 `mprotect(PROT_EXEC)`）；缺 `CAP_NET_RAW` 时 masscan 报 `PF_PACKET sockets not supported`、`nmap -sS` 报 `requires root privileges`；`RestrictAddressFamilies` 没有 `AF_PACKET` 连 raw socket 都建不出来。改为授予 `CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE` + 放行 `AF_PACKET/AF_NETLINK`，去掉 `MemoryDenyWriteExecute`，并把 `HOME` 指到安装目录（nuclei 的模板/缓存目录要可写）。其余加固（`ProtectSystem=strict` + `ReadWritePaths`、SystemCallErrorNumber=EPERM、`NoNewPrivileges`）保持不变，**仍然不是 root**。

## [0.3.29] - 2026-10-19

### 修复的问题

- **`SystemCallErrorAction` 这个指令根本不存在**：systemd 只会静默忽略（日志一行 `Unknown key ... ignoring`），于是超纲的系统调用走默认动作 `SIGSYS` 直接杀进程，而不是想要的「干净拒绝」。改为 `SystemCallErrorNumber=EPERM`。

## [0.3.28] - 2026-10-19

### 修复的问题

- **`net_context` 的回连说明只按容器写**：二进制部署下提示词仍在要求「用宿主/公网可达地址、端口必须已映射」，与实际相反。改为按 `selfupdate.InDocker()` 分两套说明：宿主部署直接用本机网卡 IP，端口随意绑。

## [0.3.27] - 2026-10-19

### 修复的问题

- **系统配置页被改乱**：回退到原版单列 masonry 布局；移除「回连配置（reverse shell / MSF）」卡片——回连地址交给 Agent 自己按运行环境判断，不再要求人去系统配置里填。

## [0.3.26] - 2026-10-19

> Agent 能力批次：提示词可随版本下发、worker 自检与记忆、意图去重、收官留痕。

### 新增的功能

- **内置提示词可随版本更新**：新增 `SeedPromptVersioned`，按 `updated_by` 区分归属——系统播种的（`system`）在内容变化时自动追加新版本并切换，用户编辑过的（`ui`）永不覆盖，旧版本留在 history 可回溯。此前 `SeedPromptIfEmpty` 只在空库播种，导致**代码里的提示词改进永远到不了已部署实例**。
- **worker 对抗式自检**：报漏洞前要求切换成怀疑者、用与首次**不同的路径或独立命令**再触发一次；未过自检就记为 inferred 事实而不是 finding（与独立渗透 agent 的纪律对齐）。
- **worker 目标资产记忆**：派发时按意图的 `asset_ids` 注入该资产上已登记的事实摘要（最近 8 条），避免重复探测，也能站在已有结论上继续推进。
- **意图派发去重**：同任务已有高度相似的 open/running 意图时不再重复下发（归一化后完全相同，或互相包含且都 ≥12 字），防止两条 worker 并行干同一件事空烧 token。
- **`goal_met` 收官留痕**：未经逐个 `prove_goal` 的整体收官，会给未达成目标打 `unverified` 标记，并在 GoalDTO 暴露 `unverified` / `unverified_reason`，报告与界面可区分「被证明」与「被声称」。

## [0.3.25] - 2026-10-19

### 文档

- 说明特权安装助手会自动跟随主程序升级；0.3.22 之前安装的老助手不具备该能力，重跑一次 `install.sh` 引导即可。

## [0.3.24] - 2026-10-19

### 修复的问题

- **助手自我换装报「仓库没有 0.3.23」**：`build.sh` 会剥掉版本号的 `v` 前缀（二进制里是 `0.3.23`），而 Release tag 是 `v0.3.23`，助手拿前者查 `/releases/tags/` 直接 404。`FetchByTag` 改为两种写法都试；版本号形态校验收进 `selfupdate`，避免两处规则漂移。

## [0.3.23] - 2026-10-19

### 修复的问题

- **重跑 `install.sh` 升级必然失败（ETXTBSY）**：`cp` 覆盖正在运行的二进制被内核拒绝（`Text file busy`），脚本宣称的「幂等：重复执行 = 升级」在服务运行状态下从未成功过。改为临时名 + rename（对运行中的可执行文件合法），并显式 `systemctl restart`——`enable --now` 不会重启已在跑的服务，新二进制不会被加载。
- **老助手无法自我换装时只有无声重试**：`/version` 是 0.3.22 才加的，更早的助手会被当成「不在」。改为回退探测 `/healthz`，并在宿主环境页显示「需重跑一次 install.sh 引导」。

## [0.3.22] - 2026-10-19

### 新增的功能

- **特权安装助手随主程序自动换装**：`pojun-hostd` 装在 root 拥有的 `/usr/local/bin`，主服务受 `ProtectSystem=strict` 限制写不进去，升级只能由助手自己完成——它从官方 Release 下载、按 `SHA256SUMS` 校验、冒烟测试后原子替换（旧版留 `.prev`），再由 systemd 拉起。主服务只负责发现版本不一致并通知，能影响的只有「装哪个已发布版本」，影响不到「装什么内容」。
- 抽出 `FetchVerifiedZip` / `ExtractMember` / `ReplaceBinary` / `SmokeTestBinary`，主程序与助手共用同一套校验逻辑。

### 修复的问题

- **指定 `--version=` 时安装脚本静默退出**：`[ "$VERSION" = "latest" ] || return` 在测试为假时返回退出码 1，`set -e` 当场终止脚本且不打印任何错误。
- **设置页分组后布局错乱**：CSS `columns` 让每个分组各自均衡，单卡片分组只占半宽、超高卡片被挤到旁列留下大片空白；改为 grid + `items-start`，单卡片与超高卡片通栏。

## [0.3.21] - 2026-10-19

### 修复的问题

- **apt 类工具全部装不上**：助手单元设了 `NoNewPrivileges=true`，systemd 会连带把 `CAP_SETUID`/`CAP_SETGID` 从有效能力集里摘掉（`CapEff` 末位由 `ff` 变 `7f`），而 apt 下载要降权到 `_apt` 用户，必然报 `seteuid 42 failed`。去掉该开关并显式声明 `CapabilityBoundingSet`。
- **安装任务刚发起就被取消**：任务的父 ctx 错用了 HTTP 请求的 ctx，handler 返回后立刻被取消，排队中的任务当场变 cancelled。改为挂在进程生命周期 ctx 上。
- **`install.sh` 的 SHA256 校验必然失败**：下载存成 `artex.zip`，却按 `SHA256SUMS` 里的原名去校验。
- 宿主环境页缺失项提示里的长 URL 把表格撑到横向溢出。

### 变更

- 系统配置页按语义分组：维护 / 网络与代理 / Agent 行为 / 运行时 / 实验功能，并补充一条「四条互不相干的出网路径」说明。

## [0.3.20] - 2026-10-19

> 前端回退 + 一键安装 + 部署脚本合一。

### 修复的问题

- **回退未完成的 vanilla 前端重构**：该重构只完成 2/30 页，且这 2 页也带语法错误（`api.js` 重复导出、`store.js` 重复声明 `stores`、`dashboard.js` 重复声明 `render`、`config.js` 被当静态文件返回未替换的 Go 模板变量、`app.js` 用了浏览器不存在的 `require`），任意一处都会让模块链整体加载失败、页面全白。恢复 Next.js 静态导出嵌入（30 页全部可用），仍是单二进制、运行时零 Node 依赖。
- **P0：服务写不了自己的数据目录**：`ProtectSystem=strict` 漏配 `ReadWritePaths`，流量索引 SQLite 全时段 2000+ 次 `attempt to write a readonly database`，任务产物、证据、transcripts 全部落不了盘，页面「一键更新」也换不动二进制。两条指令必须成对出现。

### 新增的功能

- **宿主工具体检 + 一键安装**：缺失工具可在宿主环境页直接安装，执行者是随包发布的特权助手 `pojun-hostd`（root 常驻、只监听一个 Unix socket、只认内置白名单工具 id）；体检清单与安装配方共用同一份 catalog，不存在「列了装不上」。
- **装机代理**：只作用于 apt 与 GitHub 下载，与目标流量代理、搜索代理、LLM 代理彼此独立。

### 变更

- 部署脚本合并为唯一入口 `install.sh`（运行后选二进制 / Docker），删除 `deploy-linux.sh` 与 `update.sh`；Docker 镜像默认改为 GHCR。
- `install.sh` 作为 Release 资产发布，`curl | bash -s -- --mode=binary` 可直接用。

## [0.3.19] - 2026-10-18

### 新增的功能

- **宿主工具体检**：二进制部署形态下把「本机装了哪些渗透工具」显式化——`exec.LookPath` 探测常用工具清单（可用/缺失+安装提示），注入 `graph_overview` 让模型知道家底，并通过 `/api/tools/inventory` 暴露给前端。
- 前端架构重构与部署加固（Phase A + B）。**注意：本次的 vanilla 前端重构未完成，已于 0.3.20 回退。**

### 修复的问题

- 移除未完成的 listener 功能与相关死代码。

## [0.3.18] - 2026-10-18

> 实战反馈批次:报告导出、重复上报治理、任务收官与漏洞类别标准化。

### 新增的功能

- **报告导出 Word(内置模板)**:
  - 手写最小 OOXML 生成器(零第三方依赖,单二进制哲学不破),内置中文报告模板(标题黑体分级/正文宋体/代码 Consolas 灰底/表格边框,Word 导航窗格可见大纲);
  - 任务总报告(`GET /api/report/export`):封面→资产/严重度/漏洞类别分布→漏洞明细;
  - 单漏洞报告(`GET /api/findings/{id}/export`):概述/详细报告/证据 PoC 自包含;
  - 报告 Tab 与发现详情页新增「导出 Word」按钮(fetch blob 下载,JWT 内联鉴权)。
- **报告按类别折叠聚合**:同一漏洞×多主机的重复上报在总报告层折叠——总览新增「漏洞类别分布」表(类别×条数×涉及资产数),明细按类别分组(类内按严重度降序、类别按条数降序);"永恒之蓝 16 条"在总览就是一行、在明细就是一段。
- **漏洞类别(vulnclass)标准枚举**:19 类白名单 + 中英变体别名归一表,写入层(`report_finding`/`set_goals`)落库前归一——聚合视图与指纹去重同基线(SQLi 与 SQL注入 从此同类、同指纹);提示词引导模型直接用标准类别;白名单外的输入原值保留不销毁。
- **任务收官门槛**:graph_overview 注入 stall 态势(连续轮次零新 fact/finding 且无 open 意图),planner 提示词新增"边际收益收官"段——态势明确且无量化缺口时诚实 goal_met(理由写明已覆盖面),不许编造达成证据;goal_met 默认绑定 planner。目标模糊型任务不再无限空转烧 token。
- **`net_context` 工具(Docker 回连排查)**:读取宿主/容器网卡 IP 与路由上下文,配合设置页新增的「回连配置」(egress_hint/egress_port_map),解决 MSF 等 payload 回连拿到容器地址而非业务地址的问题。

### 修复的问题

- **漏洞重复上报治理**:写入层指纹去重(归一 vulnclass+name+资产集合)——同一漏洞的重复上报不再插新行,证据以「二次确认」分段合并进原记录并补血缘边,上报方收到明确提示(合并不是失败,勿换标题重报);去重仅对带资产锚定的上报启用,防止误伤不同入口的同名漏洞;终态记录(resolved/fixed/误报)不参与合并。
- **KEV 同步被墙 404**:同步出网改为代理回退链(全局代理→搜索代理→直连),此前全局代理未配置时容器直连 cisa.gov 被网络拦截导致 KEV 卡片长期空。

## [0.3.17] - 2026-10-18

### 新增的功能

- **漏洞情报库(第二批)**:
  - **`get_poc` 工具**:GitHub 上引用该 CVE 的公开 PoC/利用仓库聚合(按星数排序),worker 确认漏洞后一键找现成弹药;同步器自动维护(KEV + 近期高危优先,失败熔断);
  - **资产图联动**:同步进来的 CVE 自动反向匹配资产的组件指纹(含 httpd→http_server 等 14 组缩写别名),受影响任务自动挂情报 hint(24h 判重防风暴),planner 下轮即读;
  - **`scan_with_nuclei` 工具**:nuclei-templates 模板树随同步自动 clone/更新,按 CVE 键控选模板组装扫描命令交 Bash 执行(走流量录制与审批门);Docker 镜像已内置 nuclei 二进制;
  - **系统 → 漏洞情报 状态页**:同步水位、CVE/KEV/PoC 库内计数一目了然;
  - **CPE 版本区间精确匹配**:`search_vulns` 输出结构化的 `version_in_range` 判断(解析 NVD versionStart/End 区间字段),不再只靠模型读原文猜。
- **代理池**:系统 → 代理池 页配置多上游出口(http/https/socks5,支持 user:pass),按请求轮换——轮询(按权重)/按目标粘性/随机三种策略;连败 5 次自动熔断 10 分钟、成功清零;池非空优先于全局出口代理,池空回退原行为;保存即热应用,重启自动恢复。
- **Linux 免 Docker 一键部署脚本**:`deploy-linux.sh`——预编译 Release(下载+SHA256 验证)+ 系统 PostgreSQL 自动安装建库 + systemd 常驻,幂等重跑即原地升级;适合服务器长期部署(升级仍可走页面一键更新)。

### 修复的问题

- **server 测试目录清理与异步写手竞争**(CI 三次复现):Manager/引擎的异步 goroutine 在 Close 后短暂存活写文件,`t.TempDir()` 严格清理误判测试失败;出过问题的测试改用宽松清理 helper。
- **资产联动 TEXT[] 读取缺陷**:PG 数组列直读是数组文本而非 JSON,解析错误被吞导致全部资产"无指纹"——改 SQL 侧 `array_to_json` 输出;补 httpd/http_server 等缩写别名匹配;E2E 测试补任务挂链。以上仅测试与匹配质量,不影响已发布功能。

## [0.3.16] - 2026-10-17

> 独立维护版首个正式版本。基于 v0.3.15 定版源码,本版起由维护者继续演进。

### 新增的功能

- **漏洞情报库（第一批）**：新增 `vulnintel` 子系统,定期同步 NVD CVE 与 CISA KEV 在野利用清单到本地 PostgreSQL。agent 新增 `search_vulns`（按组件名检索已知漏洞,KEV 优先排序 + 版本粗筛）与 `get_vuln`（完整描述/CVSS/CPE 版本区间/参考链接）两个工具,挂给 worker/planner/mainagent——worker 识别出目标组件后可直接查公开已知漏洞与现成利用,不再靠模型现想。首次启动自动全量回填（约 40.9 万条,匿名速率下分轮完成）,此后每 6 小时增量;`settings.vulnintel_enabled` 可关;可选配置 NVD API key 提升同步速率;出网走全局出口代理。版本是否落在影响区间由模型结合 CPE criteria 原文判断,结构化区间匹配与 PoC 聚合在后续批次。

### 修复的问题

- **norma 依赖解耦**：agent 全部基建此前单点依赖 `github.com/Autumn-27/norma`,该路径曾随原作者删库而不可解析。现 go.mod 以 `replace` 重定向到维护者 fork（`github.com/chu0119/Norma`,内容 = 上游 v0.4.4）,顺带升级 v0.3.15 所用的 v0.4.3 → v0.4.4。
- **llmrec 测试依赖服务启动副作用**：`llm_usage` 表由服务启动路径确保存在,测试在干净库上因缺表失败。测试改为自建,不再依赖运行时副作用。
- **删除断言已移除 API 的僵尸测试**：`TestGraphOverviewExpandsAssociatedCompanyScope` 断言的 `coverage.scope` 键在 graph_overview 上下文瘦身重构时已从生产代码移除,测试自上游 v0.3.6 起未同步,CI 必挂。

### 变更

- **CI 门禁**：新增 `ci.yml`——PostgreSQL service + `go build/vet/test`（含全部需要真库的测试,串行跑包消除跨包 PG 死锁）与前端 `build:static`。此前测试从未在干净环境验证过,本次共揪出并修复:llm_usage 副作用依赖、跨包死锁、僵尸测试、biome 与代码脱节等存量问题。
- **设计文档重建**:docs/ 新增双图架构、引擎与调度闭环、LLM 接入层、审批与拦截四篇设计文档(重建自 v0.3.15 代码);移除 `.gitignore` 的 `/docs/` 忽略规则——原作者的 8+ 篇设计文档因该规则从未进入版本控制,随原仓库删除而永久丢失。

## [0.3.15] - 2026-10-07

### 拦截

#### 新增的功能

- **新增内置拦截规则「删除类接口路径」**：此前内置的 HTTP 破坏性规则只认 DELETE **方法**，而多数应用的删除接口用 GET/POST 就能触发，`curl 'http://t/api/user/delete?id=1'` 这类调用会真实删掉目标数据。现补一条 `deny` 规则覆盖 `/delete /del /remove /unlink /erase /destroy`（动词后必须跟分隔符，`/delivery`、`/details`、`/delta` 不会误拦）。已有实例升级后也会拿到，可在「系统 → 命令拦截」里停用或删除。
- **模型兜底审批的 token 消耗可单独查看**：审批调用此前没有独立的计量归属，花了多少只能靠猜。现在它单独计量，「系统 → 命令拦截」的「模型兜底审批」开关下方新增用量卡片——调用次数、输入、输出、缓存读写五项累计统计，加一张近 30 天每日消耗的迷你柱图。

### 漏洞推送

#### 新增的功能

- **漏洞发现支持推送到 IM**：新增「系统 → 通知推送」页，可把扫描发现推送到**钉钉、飞书、企业微信、通用 Webhook、Telegram、邮件**六种渠道。同一类型可配任意多个实例，每个实例独立设启停、限流与过滤规则。
- **推送时机分实时与汇总两种模式**：实时模式命中即逐条发送；汇总模式按全局周期（默认 30 分钟）合并成一条消息，开头给出新增数量与级别分布。想做「高危实时、其余汇总」就建两个渠道分别配置。
- **过滤规则支持四个维度**：最低严重级别、限定任务 / 资产范围、漏洞类型关键词包含与排除（排除优先）、是否接收处置状态变更（默认关）。消息带「查看详情」按钮，目标地址由全局「回链地址」配置，留空则不带按钮。
- **投递历史与手动重发**：列出每条投递的状态、尝试次数、失败原因与所属渠道，可按渠道与状态筛选；失败项可一键重发（重发会清零重试计数）。
- **渠道凭据掩码回显**：Webhook 地址、加签密钥、Bot Token、SMTP 密码等只回显带尾号提示的掩码值；提交时原样回传表示「不修改」，清空输入框则删除该字段。

#### 修复的问题

> 本节是功能初版完成后一轮安全审计的结论，每条都先复现、再修、再补回归测试。

- **修复掩码可被「改目标地址、保留凭据」绕过（严重）**：配置合并对「未提及的键」一律保留库中原值，于是只改地址、对凭据避而不谈，就能让服务端把库里的真凭据发到任意地址，且完全静默。现规定目标地址一旦变化，每个凭据字段都必须显式表态——给新值，或显式留空表示不再需要。
- **修复 markdown 系渠道对不可信内容零转义**：漏洞标题与摘要来自模型输出、资产 URL 来自扫描结果，构造的标题会在钉钉 / 企业微信 / 飞书里渲染成可点击外链，图片语法则会在渲染时被客户端拉取并泄露阅读者 IP。现统一做单行化 + markdown 元字符转义，且转义发生在各渠道的渲染出口而非共用的标题函数。
- **修复投递地址的 SSRF 面**：此前环回、内网与云元数据地址一律可投递，而失败响应体前 200 字节会进 `last_error` 并被投递历史回显，构成一条半盲读原语。现改在**拨号阶段**设防，覆盖 DNS 重绑定，并拒绝跨主机重定向；环回与链路本地地址需显式设置 `POJUN_NOTIFY_ALLOW_LOCAL=1`，RFC1918 私网仍放行（内网自建 SMTP 中继很常见）。
- **修复推送凭据经错误信息外泄**：钉钉的 `access_token`、企业微信的 `key`、Telegram 的 bot token 都在 URL 里，而投递失败时完整 URL 会流入 `last_error`、投递历史、服务端日志与前端提示四处。现统一脱敏，只保留 `scheme://host` 与底层原因。
- **修复汇总消息被截断后整批标记已送达导致的静默丢失**：被截掉的漏洞既不在消息里、也不在失败列表里，投递历史却显示成功。现改为按**整条**打包，只标记装进本条的那些，其余回队列等下一条续发且不消耗重试次数，消息头部也写明还有多少条将在下一条继续。
- **修复最低级别门槛打错字会让过滤器静默失效**：`min_severity` 写成 `hgih` 这类笔误时未知级别序数为 0，判定退化成恒真，用户以为只收高危、实际全部漏洞都被灌进群里。现于写入路径校验取值并列出可选值。
- **修复 `rate_per_min = 0`（不限流）不可达**：写库这一层把显式 0 悄悄改成了默认值，操作者以为放开了限流、实际仍被卡着。默认值改到接口层在字段缺省时填。
- **修复汇总渠道完全绕过令牌桶**：`rate_per_min` 对 digest 模式此前没有任何作用。现在领取条数同时受本轮额度与内存上界两个约束。
- **修复失败处置按整批最大尝试次数判断，让老投递连坐新投递**：一个已重试两次的老投递会把同批里全新的投递一起拖进 failed，新漏洞一次重试都没用上就永久丢失。现改为逐条决定。
- **修复汇总批次中快照无法解析的投递被静默标记成功**：这类条目会被渲染阶段跳过，却随整批一起算作成功。现在显式判失败并给出原因。
- **修复单渠道每轮投递条数可能超出租约时长**：多实例部署下，租约过期的行会被重新领走、重复发送并双份递增尝试次数。现按「租约 / 单次超时」倒推每轮上限，并有断言把这几个常量的关系钉死。
- **修复 Telegram 截断可能切断 HTML 实体**：截断只避开了半截标签，没避开 `&amp` 这类实体残片，而解析器可能因此拒收**整条**消息。现在两者都回避。
- **修复邮件渠道把临时性 SMTP 失败判成永久失败**：灰名单 `450` 这类 4xx 是临时拒绝、本该稍后重试，此前一律判死，启用灰名单的服务器会让每条推送都在首次尝试后失败。现按应答码首位区分，4xx 可重试、5xx 永久失败。
- **修复提交嵌套结构时会真的把掩码字面量写进库**：像 `webhook.headers` 这种对象字段只能整体掩码或整体提交，把掩码哨兵塞进对象内部会被当真实值存下来、导致鉴权静默失效。现在这种提交被显式拒绝。

#### 设计说明

- **写漏洞的事务只做一次盲 INSERT**：`notification_events` 与漏洞在同一事务内写入，提交即保证两者原子一致。这条 INSERT 刻意不读渠道表、不跑用户的过滤规则，并由 `SAVEPOINT` 包住——否则一条配错的过滤条件就能中止事务，让高危漏洞存不进库。
- **投递用租约领取而非长事务**：`FOR UPDATE SKIP LOCKED` 领取后把行置为 `sending` 并把 `next_attempt_at` 推到未来作为租约，投递期间不持有数据库锁；进程崩溃留下的行会在租约到期后被重新领取，自愈且不会无限重试。
- **限流不消耗重试预算**：先按令牌桶算出本轮额度，再按这个数量去领取。顺序反过来会让被限流挡下的投递白计一次尝试次数，三次预算被纯等待耗光后落入失败。

### 测试基础设施

#### 修复的问题

- **修复公司 ICP 归属用例的清理顺序导致的资产永久残留**：`defer d.Close()` 在函数返回时先执行、`t.Cleanup` 在其后，于是清理语句全部落在已关闭的连接上，错误又被丢弃，测试资产与公司永久残留在库里，还会让其他按资产计数断言的用例莫名失败。现改为关闭连接也走 `t.Cleanup` 并注册在前，同时让清理失败显形。

### 流量

#### 新增的功能

- **流量列表支持内容检索、路径 / 状态码 / 长度筛选与列排序**：筛选行支持按**响应内容**（走全文索引）、**路径**、**状态码**（精确值或 `2xx` 这类分桶）、**响应长度范围**过滤，表头可按时间、状态码、响应长度排序，排序偏好记在本地。新增两个索引，已有实例升级后自动生效；Agent 工具的 query 契约未改动。
- **流量列表新增「清空全部」**：一次删除全部流量记录（忽略当前筛选），并清理索引已不再记录的历史 host 目录，清空后顺带做一次全量压实并提示实际释放了多少空间。已绑定到漏洞的流量证据存在独立的证据库中，不受影响。

#### 修复的问题

- **修复删除流量后磁盘空间不被释放**：索引库建库时没有启用 `auto_vacuum`，文件永不收缩；全文索引又是 `contentless_delete`，`DELETE` 只写 tombstone 而不回收原 postings——删流量反而让索引变大（实测抓 6MB 正文 → 索引 16MB，删光后仍是 16MB）。现在新建索引库启用 `auto_vacuum=incremental`，每次删除后在后台分块执行全文索引合并与增量回收，逐步把空间还给系统（同一场景回落到 104KB）；回收在块间释放写锁，不阻塞流量录制。

> 升级说明：`auto_vacuum` 只能在建库时设定，因此**已有实例的索引库仍是旧模式**，增量回收在其上是空操作（启动时会打印一行提示）。这类库升级后 tombstone 的增长已经止住，而已占用的体积用「清空全部」回收一次即可——那一步会把库转成增量回收模式，此后日常删除自行生效。

### LLM

#### 修复的问题

- **修复自定义会话头在「一次性 LLM 调用」路径上不生效**：目标拆解（第 0 轮）与冷节点压缩都是不挂 transcript store 的一次性调用，context 上没有 session id，网关侧因此读不到该头——对 opencode zen 这类缺头直接 400 的端点，表现为「第 0 轮失败、后续 planner 轮次却完全正常」。现为这两条路径显式挂上按探索稳定的 session id，顺带让 token 用量能正确归因到对应探索（此前完全记不到）。

### 工具

#### 修复的问题

- **修复 MCP 与自定义工具的输出截断不生效，大结果整段灌爆上下文**：MCP 工具的返回此前完全不经截断，HTTP 类自定义工具则因传入空的工具上下文，一直用写死的 6000 字符而非会话配置的上限。现两条路径统一走 `actool.Capture`：按会话 `MaxOutputChars`（默认 30000）截断，配了 `ToolOutputDir` 时把全量输出溢写到磁盘、消息里只留开头片段与文件指针。
- **升级 norma 到 v0.4.3**：harness 层统一执行 `CaptureOnce`，任何工具（含今后新增的）都不会再因为漏接截断而溢爆上下文。

### 部署

#### 修复的问题

- **修复反向代理部署下活动流连不上**：SSE 地址此前无条件拼成 `${hostname}:8787`，反代到 443 的部署里页面从 `https://域名/` 加载、SSE 却被指向未对公网开放的 8787 端口，表现为活动流反复重连。现按 `NODE_ENV` 区分：生产默认同源，仅 `next dev` 保留 `:8787` 以绕过 Next.js 对 SSE 的缓冲；`NEXT_PUBLIC_SSE_BASE` 覆盖口保留。README 补充了反向代理部署说明。

### 发现

#### 修复的问题

- **修复「按资产」视图资产列表溢出后没有滚动条**：外层卡片只给了 `max-height` 而没有确定高度，滚动视口的百分比高度解析不出来，于是资产多时列表要么撑破卡片、要么被截断且无法滚动。现把高度上限直接落到资产树的原生滚动容器上，随窗口高度自适应。

### 数据库

#### 修复的问题

- **为连接池设置上限**：`database/sql` 默认不限制应用自身可打开的连接数，池里没有空闲连接时会无条件新建，一路顶到 PostgreSQL 的 `max_connections`（默认 100）才被拒。现封顶 32 条，超额查询改为等待空闲连接，同样的负载下表现为变慢而不是报错；若 `max_connections` 调低过需同步下调。
- **提升连接复用率**：`MaxIdleConns` 的默认值是 2，并发超过 2 的连接用完即关、下次请求要重做 TCP 与 PostgreSQL 认证握手。现将空闲上限提到与总上限一致，并补上 30 分钟连接寿命与 5 分钟空闲淘汰，让池能自然换掉长期存活的坏连接。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.14] - 2026-09-24

### 任务列表

#### 新增的功能

- **任务列表新增「漏洞」列**：按严重度分档显示 严 / 高 / 中 / 低 的数量，非零档位按严重度着色，一眼看清每个任务的漏洞规模与分布。

#### 修改的功能

- **「描述 / 目标」两列宽度收窄**：超长内容省略显示，鼠标悬浮可查看全文，减少长文本挤占列表横向空间。

### 探索图与规划态势概览

#### 修改的功能

- **精简规划态势概览（graph_overview）并为各列表设定数量上限**：最近事实、已结束意图、待办意图、冷区摘要与确认漏洞明细均改为「最新一窗 + 计数兜底」，未展示的可按需查询；显著降低每轮 LLM 上下文体积、避免长任务上下文膨胀（关联任务概览的冷区一并限流）。

#### 修复的问题

- **折叠冷节点后消除探索图中 digest 与 finding 之间的反向重复边**。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.13] - 2026-09-19

### 资产拦截

#### 新增的功能

- **新增全局资产拦截规则（黑名单）**：支持录入全等与模糊匹配的域名 / IP / URL 以及 CIDR 网段，提供规则的增删改查与启用/停用，管理页位于「系统 → 资产拦截」；默认内置模糊拦截政府（`.gov` / `.gov.cn`）与教育（`.edu` / `.edu.cn`）网站。
- **资产拦截接入执行链**：Agent 在下发意图（`add_intent`）与插入资产（`insert_assets`）前先对目标资产做拦截判定——命中拦截的意图不下发、命中拦截的资产不插入，并向 Agent 返回资产信息与拦截原因。
- **新增任务级拦截 / 允许（白名单）规则**：独立于全局规则、仅对本任务生效，判定顺序为「先拦截后允许」——命中拦截即禁止；未命中拦截但本任务配置了允许规则且都不命中，则「不允许测试」；未配置允许规则时不启用白名单。可在创建任务时录入，也可在任务详情「总览」中增删改与启用/停用。
- **任务模板支持预设分类与任务级拦截/允许规则**：模板可保存任务分类与一组任务级规则，应用模板时一并带入新任务表单。

### 操作审查

#### 修复的问题

- **收紧模型裁判输出协议，减少截断导致的误放行**：将裁决说明（comment）上限由 500 汉字下调至 120 汉字并强制「只输出 JSON、不带前言或代码块」，避免裁决被 `MaxTokens` 截断后无法解析、进而按模型失败策略放行（fail-open）。

### 任务归档

#### 修复的问题

- **归档遇到符号链接时跳过而非整包失败**：归档格式端到端仅支持普通文件与目录，此前工作目录中出现任意符号链接都会导致整个任务归档失败；现改为跳过该符号链接并记录日志，其余文件正常归档（不跟随链接、不越出目录树）。

### 账户与合规

#### 新增的功能

- **登录前新增「使用须知与免责声明」弹窗**：需勾选同意后方可登录。

### 许可与依赖

#### 修改的功能

- **项目采用 AGPL-3.0 开源协议**，并完善 README 的许可与免责声明说明。
- **升级 norma 至 v0.4.1**。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.12] - 2026-09-17

### 探索链路播报板

#### 新增的功能

- **任务详情页新增「探索链路播报板」**（#144）：以时间轴流水视角呈现任务的探索节点（起点/目标/意图/事实/漏洞/提示/压缩），支持按类型筛选、关键字搜索、正序/倒序、分页与自动刷新；处于「最新在前的第一页」时为直播位、每轮刷新，离开该位时只累计未读计数、不打扰当前阅读，并以「N 条新播报 · 回到最新」一键返回。按天分组，长任务翻页也能认出「这是哪天的事」。
- **播报板每行显示节点 id**（#145），便于对照探索链路图与定位具体节点。
- **播报板节点详情展开显示上下游与锚定资产**（#147）：展开一条播报可见该节点的上游（由此而来）/下游（由此产生）关系，鼠标悬停关联条目弹出对应节点的名片（类型/状态/来源/时间/摘要/payload 片段）；并顺带列出该节点锚定的资产（类型标签 + 可辨识文本）。相关数据随播报页一并下发，展开不额外发请求。
- **播报板搜索支持按节点 id 筛选**（#150）：搜索框在「内容 / 来源」之外新增节点 id 匹配，输入纯数字或界面展示的「#41」形式即可精确定位对应节点。

### 意图管理

#### 新增的功能

- **意图删除支持「假删除 / 真删除」两种模式**（#149）：待领、运行中、已暂停的意图均可删除，删除需填写原因；删除模式在确认弹窗中选择。
  - **假删除（默认）**：意图置为「已删除」并把原因记入独立字段，保留意图节点与其全部产出、血缘。
  - **真删除**：物理移除该意图，以及「仅由它支撑」的独占子孙节点（沿产出 / 意图链级联到叶子），避免留下孤立数据；被删意图的 Token 计量按原始日期归档保留；共享节点（还被其它意图引用）、目标与任务根事实一律保留，真删除弹窗会展示预计级联影响的节点数。

  两种模式都会通知规划者「该意图由用户删除 + 原因」并据此重新规划。

### 操作审查

#### 新增的功能

- **审批记录支持按状态与判定来源筛选**（#139）：可按审批状态、判定来源过滤审批记录，快速定位目标记录。

#### 修复的问题

- **待处理审批请求独立于历史分页加载**（#133）：待处理请求不再受历史列表分页影响，翻阅历史记录时仍完整可见。

### Agent

#### 修改的功能

- **Worker 角色描述改为通用网络安全平台表述**（#138）。

#### 修复的问题

- **修复冷节点压缩从不触发**：给按任务运行的规划器接上 Compactor，冷节点压缩（cold-digest）此前因未接入而从不执行，现已恢复。

### 聊天

#### 新增的功能

- **聊天支持多类型记录的 @ 引用及滚动分页**（#135）：可在聊天中 @ 引用多种类型的记录，引用候选支持滚动分页加载。

#### 修复的问题

- **长消息气泡约束在会话面板内**（#137）：过长的消息气泡不再溢出会话区域。
- **修复新对话未创建时上传文件报「缺少上传文件」**：Composer 的文件选择在清空 input 之前先把 `FileList` 快照为数组再回调；此前草稿态需先异步创建会话，恢复执行时与 input 活绑定的 `FileList` 已被清空，导致上传缺少文件字段、后端返回 400。

### 流量

#### 修复的问题

- **流量录制代理默认只监听 127.0.0.1**（#129、#130）：避免默认配置下开放代理暴露在其它网络接口。

### Web

#### 修复的问题

- **修复静态导出版任务列表页丢失全局头部**。
- **补齐 demo 漏洞详情页关联流量 mock，修复白屏**。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)
- [@RuoJi6](https://github.com/RuoJi6)
- [@dingpotian](https://github.com/dingpotian)

## [0.3.11] - 2026-09-15

### 操作审查

#### 新增的功能

- **审批记录支持来源定位**（#125）：点审批记录的「来源」可跳回触发该次审批的那一次工具执行——打开原始完整会话、自动分页加载到目标位置、就地展开命令与结果并在滚动区居中高亮，前后消息保持可读；用户手动滚动时停止自动校正。跨普通对话、任务 Worker、规划器与主 Agent 分段会话，均通过持久化的 `tool_use_id` 与任务映射精确定位（新增作用域内调用 ID 索引），缺失、重复或关联不明确时显式提示而非跳到其他执行。会话被删除或任务归档/记录缺失时给出明确提示。
- **审批记录支持翻页**（#115）。

#### 修改的功能

- **精简模型审查输入**（#124、#125）：模型审查（规则未命中后的 LLM 裁判）输入收敛为「当前这一次完整工具调用 + 明确选定的简短背景 + 本机工作目录」的版本化 JSON。背景只取真实用户消息（聊天/任务主 Agent 的当前用户消息），Worker 不再附带意图摘要、也清除从上级 Agent 继承的背景；规划器与自动触发会话不补造用户消息。不再附带任务描述、目标、操作约束、全局探索态势、历史调用或 Worker 完整意图——这些仍按原逻辑用于 Agent 执行与独立会话审计，只是不进入操作审查。所有裁决要求输出 JSON 的 `decision`/`comment`，说明必须包含「实际操作、成功后的后果、命中规则」；参数或背景中的指令不能改变审查策略。保存实际发送给模型的输入快照及指纹，旧版快照保留并标注版本，不用当前数据补造旧输入。

#### 修复的问题

- **模型裁决被代码块包裹时不再静默放行**（#126）：模型返回的裁决 JSON 若被 ``` 代码块包裹，此前解析失败会经模型失败策略被静默放行；现在先剥离代码块围栏再解析，解析仍失败才按已配置的失败策略处理。

### Agent

#### 新增的功能

- **新增实验性 noa 上下文压缩**（norma 升级至 v0.4.0）：系统设置中可开启的实验功能，默认关闭。开启后由 noa（模型驱动的上下文压缩）接管主 Agent、规划器、Worker、聊天四类 Agent 的上下文压缩，替代内置压缩；压缩原文持久化归档，集中落在 `<workDir>/noa/<会话ID>/` 下（不分散在各任务目录内），按会话 ID 全局唯一分目录。接入失败自动回退内置压缩，不中断真实任务；开关每次运行读取一次，切换只影响之后启动的运行。

#### 修复的问题

- **探索图工具在无任务上下文时拒绝而非 nil 崩溃**：非任务上下文调用探索图相关工具时返回明确错误，不再因空存储解引用崩溃。

### MCP

#### 新增的功能

- **支持旧版 SSE MCP 服务**（#117）：兼容仅提供旧式 SSE 传输的 MCP 服务端。

### 流量

#### 修复的问题

- **流量检索按端口感知匹配记录的主机**（#114）：`traffic_search` 的主机匹配纳入端口，避免不同端口的同主机记录相互串扰。
- **`traffic_search` 描述迁移出错不再中断后续 reporter 迁移**：单条迁移失败被隔离，不影响后续迁移执行。

### Web

#### 修改的功能

- **任务复测漏洞选项增加分割线**（#122）：复测漏洞选择项之间增加分隔，视觉更清晰。

#### 修复的问题

- **修复 demo 任务详情页整页崩溃**：mock 模式下任务详情「会话」标签会去拉 `GET /api/tasks/<id>/side-questions`（旁路提问历史），但 mock handler 没有这条路由，被读兜底按“路径以 s 结尾即集合”返回了 `[]`，导致 `data.items` 为 `undefined`，旁路 hook 的 `merge()` 对其迭代抛 `TypeError: t is not iterable`；该异常发生在 `setItems` 的 updater 里、被 React 推迟到 render 阶段重抛，调用方 `catch` 接不住，整页被错误边界接管显示 “This page couldn't load”。现在 mock handler 显式返回空的旁路历史，`sideAPI.history` 也对返回值做归一化（`items` 非数组一律兜成 `[]`）作为防御纵深。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)
- [@RuoJi6](https://github.com/RuoJi6)

## [0.3.10] - 2026-09-13

### 网络

#### 新增的功能

- **网络搜索新增 DeepSeek 官方来源**：直接复用当前激活的 LLM 配置。它与其余三个来源性质不同——DeepSeek 没有可直接调用的搜索接口，搜索只存在于其 Anthropic 兼容接口内部（`web_search_20250305` 服务端工具），由 DeepSeek 服务端执行。因此它**仅支持 DeepSeek 官方端点 + anthropic 协议**（OpenAI 协议端点会直接拒绝服务端工具），且每次搜索会**额外消耗一次模型调用**、请求**不经过搜索出口代理**、也**不计入流量留痕**，返回结果**只有标题与链接**（无摘要，需正文时由 WebFetch 抓取）。设置页说明上述限制但**不做校验拦截**，是否满足由用户自行确认，可用「测试搜索」按钮实跑一次验证。

### Agent

#### 新增的功能

- **worker 获得跨 work 回看能力**：新增 `search_all_worker_traces`（不必先知道 intent_id，按关键字在本任务所有 work 的执行过程里全局检索命中步骤）与 `get_worker_trace`（锁定某条 work 后列步骤流、就地按关键字搜、按 step_id 取完整内容），用于复用别的 work 见过却没写进 fact 的观察、避免重复劳动。
- **`node_detail` 下放给 worker**：配合上面的回看工具，worker 拿到 intent_id / 节点 id 后可直接查该节点的完整详情。
- **`add_hint` 触发的规划轮会被显式播报**：此前新增提示只把 hint 折进态势总览、让规划者自己发现；现在一次 `add_hint` 会给规划者记一条「人新增了 N 条战略提示：…」触发（批量算一条，不逐条刷屏），规划者被明确告知“本轮由新增 hint 触发”并直接看到提示内容。

#### 修改的功能

- **全局态势提示改为“松绑”口吻**：鼓励探索发散、跨意图线索及时上报，而非过早收敛。
- **精简 worker 边界措辞**：初次受阻不代表探透，聚焦“把本意图内的绕过手段走完再下结论”。
- `insert_assets` 移除每条资产的 `related` 入参：它唯一的作用是决定要不要把这条资产加进本任务范围，值又不落库（同一资产被再次登记就作废、界面上也看不出谁被判为无关），实际只是让模型多做一次留不住的判断。
- **测试范围(`task_scope`)不再受资产覆盖度开关影响**：`insert_assets` 的自动入范围(`source='auto'`)无论覆盖度开启与否都执行，`add_task_scope` 也始终提供给 planner / 任务内主 Agent / 目标拆解 Agent。范围是任务的授权边界、资产查询的过滤基准，覆盖度开关只决定要不要拿它当分母算指标，不该决定要不要累积范围本身。此前关闭覆盖度会让 `auto`/`agent` 两条写入路径同时失效，`task_scope` 只剩界面手工添加的行。`list_untested_assets` 仍随覆盖度关闭而隐藏（它本身就是纯覆盖度视角）。

#### 修复的问题

- **修复任务间资产互串**（#59）：`list_assets` 此前把任务 id 写死为 0、裸查整个共享资产库，模型又无从写出范围过滤条件，于是把别的任务的资产（尤其 IP）当成本任务目标，测试方向被带偏。现在它只返回落在【本任务及直接关联任务】测试范围(`task_scope`)内的资产，按**归属**匹配而非字面值：范围里有某根域即可查到其名下全部子域/服务/接口，有某网段即可查到段内主机及服务；按 id 直取范围外资产同样取不到。非任务上下文(Auto/pentest)无范围可依，仍回退全库。顺带修复 IP 直连主机(如 `http://1.2.3.4/api`)无法被网段范围命中的归属盲区。UI 的「测试资产」视图（按任务生产者过滤）不受影响。
- **修复 worker 跨 work 回看工具被误删**：`search_all_worker_traces` / `get_worker_trace`（以及 `node_detail`）加进 worker 默认工具集后，被一段“收敛 worker 工具面”的旧迁移在启动时又解绑掉，导致 worker 实际拿不到这些工具。已把它们移出该解绑清单，并对已跑过旧迁移的库一次性补绑回 worker。
- **修复 `/btw` 旁路提问偶发入库失败**：side_question checkpoint 落库前剥除 JSONB 不支持的 NUL(`\u0000`) 转义，避免含该字符的内容写入报错。

### 触发器

#### 修复的问题

- **合并触发会话按任务去重任务描述/目标**：多任务合并触发时，同一任务的任务描述/目标不再重复拼进消息，避免长目标反复堆叠把上下文撑爆。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.9] - 2026-09-11

### Agent

#### 新增的功能

- 任务内主 Agent 支持**多会话**：可新建、切换、独立重置上下文，每个会话都能交互。
- 支持持久化的 `/btw` **旁路提问**：不打断主线追问，问答落库，重启后仍在。
- `spawn_task` 新增 `source_task_ids`，新任务可**只读继承**来源任务的资产与发现。

#### 修改的功能

- 关闭 worker 的跨 engagement 记忆并收敛其默认工具面：读上下文、跨 work 复盘属规划职责，worker 只管单条意图的执行与写回。
- 精简 worker 默认提示词；`get_worker_output` 移除 `terminated` 与 `worker_name` 字段；精简 `insert_assets` / `list_assets` 的描述。

#### 修复的问题

- 修复 work 因**空转回合**提前中断的问题：模型有时会用一整轮只输出思考，既不给正文也不调工具，此时 harness 看到的是一次自然结束（`end_turn` 且无 `tool_use`），直接以 `completed` + 空总结收场——一条还没做完的意图就断在半路，表现为「任务正常结束但没有任何文字总结」。五层 LLM 重试一层都够不着它：它不是错误，同 provider 安全窗口重试的入口是"流失败"，熔断在 `err == nil` 时直接判成功，意图重跑只认 `model_error`；SDK 的空响应重试也够不着，因为那层以"有没有 yield 过事件"判空，而思考增量本身就是事件。现在 work 的 Stop 钩子会识别这种回合并注入一条续跑指令，让模型带着已经产出的思考继续执行下一步——刻意不选"原样重发"，因为这类空转通常由提示词与上下文形状决定，是稳定行为而非随机抽风，重发只会让模型再想一遍。
- 次数复用 LLM 页「重试与退避」里的**空响应重试次数**（两者都在回答"模型完成了却没产出实质内容"，只是判据与手段不同），默认 2 次，填 `-1` 即关掉、退回原先"空转即收场"的行为。它是一条意图的**总量**上限而非连续次数：harness 自身已限死连续空转只推一次，只有真正发生过工具回合配额才刷新，所以这个数挡的是「工具 → 空转 → 推 → 工具 → 空转」这类循环把意图预算耗光。触发时日志记 `[work <worker> · #<意图>] 空转回合…注入续跑指令 (n/N)`。设计见 `docs/LLM重试设计.md` §1.1。
- 修复长对话下 `/btw` 的上下文预算与输入布局；非安全上下文（非 HTTPS 访问）降级生成旁路请求 ID。

### 流量

#### 新增的功能

- 漏洞支持**关联多条流量证据**，可排序、加备注、按角色区分（请求/响应/佐证）。
- 报告 Agent 会在写报告前**自动关联**相关流量证据。
- 新增 Agent **流量绑定开关**，并补齐证据在 Agent 之间的交接。

### 任务

#### 新增的功能

- 支持**会话级漏洞复测**：复测跑在独立 Agent 会话里，列表与详情显示运行状态。

### 拦截

#### 新增的功能

- 审批记录新增**详情与执行审计**：可查看工具请求上下文、模型/规则初判、执行输出与参数指纹。

### 资产

#### 新增的功能

- 任务测试资产支持 **DSL 搜索**。

### LLM

#### 修复的问题

- 修复测试连接未补发自定义会话头，导致 opencode zen 返回 400 的问题。

### 网络

#### 新增的功能

- MCP 的 HTTP 传输支持**跳过 TLS 证书校验**，便于接入自签证书的服务。

### UI

#### 新增的功能

- 会话列表按 Agent 分组，支持展开收起与独立置顶；对话支持按 Agent 筛选。
- 攻击链路图渲染压缩（digest）节点，并收缩其成员。

#### 修复的问题

- 修复登录凭据不同步导致的白屏。
- 拦截提示文案改为明确标示「平台管控」，避免被误读成目标侧的防御。

### 部署与更新

#### 新增的功能

- 支持**页面一键更新**：系统配置页新增「版本与更新」卡片，顶栏在有新版时亮出提示。流程为下载发布包 → 校验 `SHA256SUMS` → 冒烟测试 → 暂存 → 退出由守护脚本重新拉起完成换装，页面自动刷新。
- 新增守护启动脚本 `start.sh` / `start.bat` 作为正式启动入口（发布包与 Docker 镜像均已带上，`install.sh` 不变），按退出码决定是否重新拉起，并负责把 SIGTERM 转发给 artex。校验与换装逻辑都在 Go 里，脚本保持傻瓜化。
- 失败自动兜底：校验或冒烟不通过就丢弃、继续跑当前版本；新版连续 3 次启动失败则回滚上一版本。设置页另有手动回滚（注意数据库结构不会回退）。
- 更新只认 GitHub 域名且强制 HTTPS，发布源不可配置；开发构建禁用一键更新。GitHub 查询结果缓存 30 分钟，避免顶栏提示耗尽 API 配额。

#### 已知限制

- Docker 下只换程序、不换镜像：工具链不会跟着升级，且重建容器会退回镜像自带版本，需要时仍用 `docker compose pull artex`。
- 不同步发布包里的 `skills/`，新版新增的内置 skill 不会自动生效。
- 更新即重启，会中断正在运行的任务。

### 依赖

#### 修改的功能

- 升级 norma 至 v0.3.7。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)
- [@RuoJi6](https://github.com/RuoJi6)

## [0.3.8] - 2026-09-09

### LLM

#### 新增的功能

- LLM 页新增「重试与退避」标签页：五层重试的**次数**与**间隔**都可以配。一次模型调用的失败由内到外经过建连重试（SDK，流开始前的连接重置 / 超时 / 429 / 5xx）、空响应重试（SDK，正常结束却没有任何内容，仅 openai 格式）、同 provider 安全窗口重试（未向调用方交付任何输出前的断流重放）、轮询熔断（连续失败到阈值就冷却跳过）、意图重跑（worker 以 model_error 收场后整条意图重跑）五层，内层用尽才轮到外层。每层两个旋钮，语义统一：留空 = 用原本的默认次数与指数退避；填次数就用该次数；填间隔就把指数退避换成固定间隔；填 -1 = 关掉这层重试。前三层跟着端点走，可在每个模型配置里逐字段覆盖全局默认（只钉间隔的仍继承全局次数）；熔断与意图重跑是进程级语义，只有全局一份。保存后热生效，不需要重启。全部留空即当前行为，旧库升级后逐字节不变（新列默认 0、settings 键不存在即全默认）。连接测试刻意不带这些参数——它有 30s 硬超时，叠上用户配的重试只会把能用的端点测成超时失败。设计见 `docs/LLM重试设计.md`。
- 每个 LLM 配置支持自定义**会话头**（`session_header_key`）：非空时每次 LLM 请求都会带上该 HTTP 头，头值为当前运行的 session id（chat 会话为 `conv-<id>`、worker 为 `exp<x>-worker-i<intent>` 等），用于某些按 session-id 头做提示缓存 / 粘性路由的网关。实现上从请求 context 里读取 session id 注入，无需改 norma，同一共享 provider 也能按会话发出不同头值。旧库带迁移，前端 LLM 配置弹窗新增输入框。

#### 修复的问题

- 修复保存 LLM 配置时因会话头字段为空直接报 `23502` 的问题：该列是 `NOT NULL DEFAULT ''`，此前误套 `NULLIF($n,'')` 把未填写的会话头写成 NULL 触发非空约束，现按空串语义直接传参。

### Agent

#### 新增的功能

- 墙钟超时改为**就地收尾**：依赖 norma v0.3.6，`MaxDuration` 到点会打断正在跑的工具并在活 ctx 上按收尾轮数续跑（写回已识别内容 + 总结，终态为 timeout），不再依赖 worker/planner 各自的 `maxDur+90s` 外部硬 ctx 把卡住的 run 直接杀成 `aborted_tools`。chat 走同一 harness 自动获得同样行为，mainagent 无 `MaxDuration` 不受影响。
- 停摆兜底：planner 在心跳 / 无变动唤醒且全图已无任何 open 或 running 意图时，开场白改为停摆告警，明确告知无 worker 在跑、无排队方向，本轮必须产出一个或多个互不重复的新意图（不得产出 0 意图）。

#### 修改的功能

- worker 提示词重构：意图 / 启动指令 / 锚定资产原始 JSON 移入 system prompt，每轮重拼、绝不被 compaction 压掉，续跑也不依赖 transcript 首消息留存；启动 user 消息瘦身为仅全局态势 overview（可降级、容忍 stale）。代价是 system 混入 per-intent 数据、失去跨意图缓存复用，是「不丢意图」的刻意取舍。
- 精简 planner / worker 默认正文并修正若干实战问题：planner 对 `recent_done` 按状态区分（blocked/exhausted 先查 trace 再决定，不当死路也不无脑重跑）、否定结论改为「观察 / 存疑、非定论」且采信前看 evidence、目标未达成且无 open/running 意图必须产出（硬底线）、深度优先于覆盖度；worker 否定类结论只写「观察 + 试探性读法」、判决权归 planner，跨意图线索写进 fact 的 summary 交规划者、不自己追。reseed 会把新默认作为新版本追加并切过去，用户自定义 / 旧版本保留在历史可回滚。
- 收敛 work agent 默认工具集与资产写回提示：worker 只负责单条意图的执行与写回，读上下文 / 跨 work 复盘属规划职责，故从其默认工具移除 `list_facts` / `node_detail` / `list_companies` 及跨 work 检索（`search_all_worker_traces` / `list_worker_traces` / `get_worker_trace`），只留 `list_findings`（报漏洞前查重）+ `add_finding` / `record_fact` + `insert_assets` / `list_assets`；提示词删掉与 `insert_assets` schema 冲突的陈旧字段说明（`type=tech`/`on_url`/`props`）。旧库带一次性迁移剥离对应绑定，planner/main 的同名绑定不动。

### 探索图

#### 新增的功能

- **探索图冷节点压缩（cold-digest）**：把老且长期不活跃的意图 / 事实折叠成 digest 节点在 `graph_overview` 里展示，原始节点永久保留、按 id 可完整还原（存储无损、只压呈现、折叠可逆）。冷热判定按逆向可达 + 任一活分支即热，配 R=6 轮防抖与连通分量分组；后台压缩（minor 折未覆盖冷块、major 回源重压合并碎片）带活跃度复核与冷却互斥，绝不上热路径也绝不覆盖已复活节点。概览侧提供 `cold_digests` 与按资产索引的 `cold_index`，`expand_digest` / `expand_index` 负责还原。关联 / 继承任务的概览同样复用其自身折叠视图，`expand_digest` 支持跨任务只读还原。`expand_digest` / `expand_index` 只给 planner 与 main agent，不给 worker。均带旧库迁移。
- `graph_overview` 全量输出 `finding_list`：findings 是任务最高价值产物且单任务通常不多，改为在概览里全量带出（不像 facts 只给最近窗口），planner/worker 每轮即可一眼看全所有确认漏洞，无需再调 `list_findings`。每条精简为 `{id, summary, evidence?, from_intent?, assets?}`，其中受影响资产直接给可读内容（url / 域名 / ip:port）而非裸 id。

#### 修改的功能

- `graph_overview` 不再平铺 `hosts`：coverage 块移除 host 列表（大范围任务里每轮最多携带 500 个 host 字符串，对规划决策价值有限），只保留 `host_count`，具体主机按需 `list_assets` 查。新增顶层 `done_intents_total`（已结束意图总数），与被截断到 ≤15 的 `recent_done_intents` 平行，让 planner 去重时知道有无被截。

### 工具

#### 修改的功能

- `add_company_scope` 默认绑定由 worker 改为 planner：定义企业资产范围属规划 / 主控 / Auto 的职责，worker 只执行探索。新库 seed 默认绑定为 mainagent/planner/auto，老库带一次性迁移。
- planner 默认绑定 `list_assets`：现同时具备 `list_assets`（DSL 全库检索）与 `list_untested_assets`（范围内未测），老库一次性回填、不覆盖用户解绑。

### 任务

#### 新增的功能

- 任务列表新增「运行中 Worker」列：统计该任务下 `state='running'` 的意图节点数，口径与任务详情页概览的「运行中 Worker」完全一致，无运行中 Worker 时显示 0。

### 网络

#### 新增的功能

- 新增**全局出口代理**配置：所有目标流量可经统一的全局代理出网（http/https/socks5，支持 `user:pass`）。开启流量捕获时作为 MITM 记录代理的上游（流量照录再经代理出网，拦截与透传两条路径都走上游、不泄露源 IP）；关闭捕获时直接注入 agent 的 bash 环境与 WebFetch（`proxyEnv` 增加 `ALL_PROXY` 支持 socks5）。配置存于 settings KV 表（无需迁移），前端系统配置页新增「全局代理」卡片，与网络搜索代理、LLM 代理相互独立。

### UI

#### 修复的问题

- 修正意图状态标签的语义错误：`exhausted`「已穷尽」→「预算耗尽」（实为达步数 / 时间预算被中途掐断、只写回部分结果，并非该方向已探尽）、`blocked`「被拦截」→「执行出错」（实为模型 / API / 网络故障重试用尽、意图基本没真正探成，并非目标 / WAF 拦截），并补上此前缺失的 `stopped`「已停止」（用户手动停止的 work）。

### 依赖

#### 修改的功能

- 升级 norma 至 v0.3.4：MCP 工具输出增加截断与落盘（见 `651b961`），后续 v0.3.6 支撑墙钟就地收尾。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.7] - 2026-08-31

### LLM

#### 新增的功能

- 模型配置新增「输出上限」，并可选择上限用哪个请求字段名：上限限制单次回复最多生成多少 token，随每次请求发出，0（默认）= 不发送该字段、由服务端默认值决定；它与「上下文窗口」是两回事——后者是模型总容量，只在本地用来算压缩阈值，不出现在请求里。字段名开关仅对 `openai`（Chat Completions）格式有意义：空（默认）发 `max_tokens`，绝大多数兼容网关只认它；OpenAI 官方推理模型（o 系列 / GPT-5）反过来只认 `max_completion_tokens`，收到 `max_tokens` 会直接报 `unsupported_parameter`，这类端点需手动切到新字段。两种格式各自定死了字段名（Anthropic 为 `max_tokens`、Responses API 为 `max_output_tokens`），故非 openai 格式该开关置灰并在保存时清空。同时补上一条此前从未接通的链路：planner / worker / chat / 主 Agent / 目标拆解五处都没设过输出上限，openai 系压根不发、Anthropic 走 SDK 的 8192 兜底，光加配置项而不接这条线，填了数字也不会生效；现在取值与「流式输出」一样按配置每轮解析，故障转移切换后下一轮即生效。旧库升级后行为完全不变（新列默认 0 与空字段名）。
- 后台点「测试」时把每次 HTTP 尝试的状态码与网关原始响应体打进服务端日志（响应体裁到 4K），便于诊断 401、额度文案、空帧、返回 HTML 页面等情况，不再只能看到 UI 折叠后的 ok / err。该日志不依赖「LLM 记录」开关。

#### 修改的功能

- 任务 LLM 配置链改为任何状态都可修改，不再限制「运行中 / 暂停 / 配置链耗尽」：任务结束（done / failed / timeout）后主 Agent 对话仍走这条链，链上模型出问题时原先既不能改也就没法继续交互。后端 HTTP 与 DB 事务两处终态拦截一并去掉，前端弹窗对终态任务也开放编辑与保存。终态任务保存时不再重开额度阻塞意图（那些意图会被挪到 open，既没有 worker 执行、也不再满足「重跑意图」的条件），想继续跑仍走重跑意图 / 新增目标，由它们把任务重新拉回运行态。

### Agent

#### 修改的功能

- 「给运行中的 Worker 发消息调方向」改为复用已有的暂停 / 恢复 + transcript resume 机制，行为与主 Agent 对话一致：此前走的是一套自建的介入持久化协议，牵动调度屏障、恢复流程与十余处活动查询过滤。现在消息经下一轮输入注入，意图在专属 goroutine 里直接跑，不受 3 槽 worker 池限制、随发随跑；前端保留消息框并恢复「直接继续」按钮，发送改由 SSE 承载。无 DB schema 改动。取舍：消息仅存内存、不做崩溃恢复，且发消息时该任务可能瞬时超并发一个 worker（低频场景，可接受）。

### 任务

#### 修复的问题

- 修复归档大型任务时内存耗尽（OOM）崩溃的问题：归档改为流式写入快照，不再把整个任务一次性读进内存；同时补齐冷归档路径上的三处恢复缺口——现代安装的流量只存在 SQLite 里，此前在 PostgreSQL 提交与 SQLite 提交之间崩溃会让已归档任务的流量滞留在热存储且无从恢复，现在无论有无历史目录都会写暂存日志，缺失的 `journal.json` 也按可丢弃处理。
- 修复任务较多时系统卡顿的问题：加载对话与加载界面存在明显延迟。任务列表、任务上下文与探索记录的查询一并优化，前端的仪表盘、对话页与任务详情页同步减少了重复请求。

### 资产

#### 修改的功能

- 去掉企业资产范围「最多 256 条规则」的限制：逐个 IP / 域名录入范围的企业很容易撞上这个上限，撞上之后只能拆成多个企业，而范围本身并不因为条数多就更慢。前后端与 demo mock 三处上限一并移除，单条规则仍限 1024 字符，请求正文 2 MiB 的上限保留作兜底（约合四五万条规则）。

### 技能

#### 修复的问题

- 修复上传技能压缩包报「上传失败：zip: unsupported compression」的问题：Go 标准库只内置 Store / Deflate 两种解压器，压缩软件在非默认档位下写出的 bzip2、Zstandard 包一律解不开。现在补上这两种解压器（纯 Go 实现，不引新的外部依赖）；Deflate64 / LZMA / XZ / PPMd 等确实解不了的方式，以及加密压缩包，改为在解压前就报出中文提示，直接点名是哪个文件用了哪种压缩方式、该怎么重新打包，不再把底层英文错误甩给用户。
- 修复技能内文件名校验把中文文件名判为非法的问题：路径校验原先是 `[A-Za-z0-9-_./]` 的 ASCII 白名单，压缩包里只要有一个中文命名的文件（`参考/说明.md` 之类），整包上传就会以「压缩包含非法路径」失败。改为 Unicode 黑名单：允许各种语言的文件名与空格，仍然拒绝控制字符、非法 UTF-8、零宽与双向控制字符（RLO 文件名伪装）、`\ % # ? * : " < > |` 以及 `..` / 绝对路径 / 空路径段，防目录穿越的行为不变。技能名同样放开——ASCII 仍限小写字母、数字与连字符（agentskills.io 规范），中文等非 ASCII 字母可直接作技能名，但不接受空格、点和路径分隔符。
- 修复 Windows 压缩软件打出的中文包解压后文件名乱码或整包被拒的问题：这类 zip 不置 UTF-8 标志位、按 GBK 写文件名，现在按 GBK 兜底解码后再做路径校验。同时 `name: "中文技能"` 这种带引号的 frontmatter 也能正确取到技能名。

### UI

#### 新增的功能

- 发现页新增「全部发现」平铺视图并设为默认，与原「按任务分组」视图通过页头 Tab 切换：分组视图要逐个任务展开才看得到漏洞，只想跨任务扫一眼列表时反而绕路。平铺视图是一张跨任务大表（每页 10/20/50/100 条），行为与分组视图完全一致——勾选导出、行内展开看证据与详细报告、行内改名称/类别/严重度、改处置状态、深入、删除。两个视图共用统计卡片与筛选条，切换不丢筛选，当前视图与筛选项一并记在本地；轮询只打当前视图，行内改动会同步写两边缓存，切过去不会看到过期数据。
- 发现页新增「按资产」视图：左侧资产树（企业 → 根域名 / IP → 子域名 → 服务 → 接口，企业层只在资产确实有归属时才出现），右侧是选中节点整棵子树下的发现，与另外两个视图共用同一张表和同一批筛选条件。树只收有发现的资产，祖先链按需补齐（发现只挂在最深的接口上时，上面几层照样能拼出来），节点上的计数是子树聚合并按发现去重的；资产已删除或本就没关联资产的发现进「未关联资产」桶。与另外两个视图不同，资产视图不轮询——进入视图、改筛选、页内增删改发现、或点树上的刷新按钮时才查询，左树是导航结构，没必要每 5 秒重算。树上每层只显示相对上一层的增量（子域名去掉根域名后缀、服务显示 `https :443`、接口只显示路径），完整值在悬停提示与面包屑里；节点过多时整层丢弃接口/服务层级并给出提示，计数仍计入上层。

#### 修复的问题

- 修复手机端会话详情里会话记录被挤压看不全的问题：窄屏下折叠会话列表，把宽度让给记录本身。

### 依赖

#### 修改的功能

- 升级 norma v0.3.2 → v0.3.3：新增 `Config.MaxTokensField`，让 OpenAI Chat Completions 的输出上限可以改发 `max_completion_tokens`（推理模型只认这个键）。两个键互斥、只发其中一个，默认仍是 `max_tokens`。
- 升级 `golang.org/x/mod` v0.37.0 → v0.40.0，修复两处依赖安全告警。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)
- [@neouks](https://github.com/neouks)
- [@begininvoke](https://github.com/begininvoke)

## [0.3.6] - 2026-08-27

### LLM

#### 修复的问题

- 修复「非流式」开关保存后重新打开又变回「流式」的问题（#69）：配置列表接口的 DTO 漏了 `streaming` 字段，响应从不返回它，前端读到 `undefined` 后一律回落成默认流式；实际写入与 DB 存储本无问题，只是读不回来。DTO 补回该字段（不加 `omitempty`，`false` 也必须出现在响应里）。
- 测试连接改为校验模型确有回复、并按该配置真实的收发模式来测（#65）：此前只判 HTTP 是否成功，请求通但模型零回复（思考烧光预算 / 正文被安全策略吞掉 / 兼容层丢 `content`）也报「连接成功」，与会话里「不回话」的表现割裂；且测试恒走流式，非流式配置测的其实是另一条通道。现在空回复直接判失败、成功时在提示里展示模型回复，并把当前流式开关一并带入测试，让「测试通过」与「会话跑得通」保持一致。

### Agent

#### 修改的功能

- `list_facts` 改为分页 + 关键词过滤，避免事实多时单次调用撑爆上下文（#74）：默认返回最新 20 条，支持 `limit`（上限 100）/ `before` 游标 / `q` 摘要关键词，返回 `{facts, total, has_more, next_before}`；单条 summary 过长按字数截断（全文仍走 `node_detail`）。worker / planner 提示词同步为分页语义。旧库通过一次性迁移把新参数 schema 刷进工具目录表（`SeedTool` 首插入only，否则工具管理页显示「无参数」）。

### 工具

#### 新增的功能

- 「工具执行」页新增工具调用次数统计（#72）：工具栏「统计」按钮打开弹窗，按工具展示调用次数、占比与失败次数（次数降序）；沿用列表的任务 / 关键词筛选，统计整个结果集而非当前页，弹窗打开时才拉取。

### 依赖

#### 修改的功能

- 升级 norma v0.3.1 → v0.3.2：修复 OpenAI 系响应里被静默丢弃的 reasoning/refusal（Responses 补 `reasoning_text`）、reasoning 字段三名去重、空响应（零内容块）有界重试、压缩边界切断工具配对导致的网关 400（同时修复已烤进 transcript 的存量孤儿）。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.5] - 2026-08-25

### LLM

#### 新增的功能

- 每个 LLM 配置支持流式/非流式切换（默认流式）：开走流式 SSE；关走真·非流式（`stream:false`、一次性返回完整 JSON），可绕开部分网关糟糕的 SSE 实现（空帧、思考字段丢帧），代价是失去运行中的实时进度与实时 Token 计数。worker / planner / mainagent / chat / goals 均按当前激活配置动态取值；`llmpool` / `llmrec` / 任务运行时三层 Provider 包装均兼容非流式；`llm_profiles` 新增 `streaming` 列并 `ALTER` 补旧库（默认 `true`，旧配置无感）。
- 支持 OpenAI Responses API 格式的 LLM 配置：每个配置新增第三种格式 `openai-responses`（打 `POST /v1/responses`），与 Chat Completions / Anthropic 并列；`BaseURL` 归一化、默认模型 `gpt-5`；`llm_profiles` 的 `format` 约束加入 `openai-responses` 并幂等迁移补旧库；前端格式下拉新增「OpenAI (Responses API)」。依赖升级 norma v0.3.1（含 `reasoning_content` 回传修复）。
- 录制 LLM 请求/响应 HTTP 原文：在 HTTP transport 层捕获真实 wire body，保留归一化视图看不到的工具 schema、`tool_use` 块与原始 SSE 帧；norma 内部重试的多次尝试逐次保留；`llm_records` 新增 `raw_request` / `raw_response` 两列并 `ALTER` 补旧库；录制页详情面板增加「原文」视图切换与请求/响应复制按钮（兼容非安全上下文的 `execCommand` 回退）。

### 对话

#### 修改的功能

- 会话列表多选改为「多选」模式开关：默认列表不再常驻每行勾选框（观感更干净），表头改为「共 N 个 + 多选」按钮；点「多选」进入选择模式（勾选框、全选、批量删除），「完成」退出并清空选择，批量删除全部成功后自动退出（有失败则留在选择模式便于重试）；单条重命名 / 置顶 / 删除仍走每行 ⋯ 菜单。

### UI

#### 修改的功能

- 任务管理、会话操作与流量查看体验增强（#57）：任务列表列排序偏好可持久化记忆、行内重命名改用图标直接触发（不再经菜单）、抽屉（sheet）交互与流量查看细节优化。

#### 修复的问题

- Worker 资产标签只显示域名与 IP，并正确处理空标签的场景。

### Agent

#### 新增的功能

- planner 判目标时新增「量化验收核对」：目标含可量化验收条件（资产测试覆盖度达到 X%、拿到 N 个 flag、获得某权限）时，`prove_goal` 前必须核对 `graph_overview` 的实测值（`coverage.pct`、findings 计数等），实测未达标则禁止 `prove_goal`、改为派意图补足差距，不得以「主要部分已完成/大体达成」为由提前标 met。修复了目标要求覆盖度 100%、实测仅 40% 却被判完成的问题。

#### 修改的功能

- 重写 planner 提示词中「本轮 0 意图」的判定依据：原文将 0 意图描述为「最常见、最重要的原则」，会让规划者在目标未达成、范围内仍有未测面时过早收手。现改为只在两种具体情况下才应产出 0 意图——① 想到的方向都已被 open/running/recent_done 意图覆盖；② 下一步依赖当前正在运行的 work 的产出、而产出尚未出现（应等其跑完、图更新后的下一次唤醒再规划）。并补充反向约束：确有未被覆盖且不依赖在跑 work 的新方向、或目标未达成且仍有未测面时，不要因「0 意图常见」而收手。
- 强化 worker 提示词中「否定结论的证据门槛」：对「不可注入/端口关闭/无登录入口」等可能让规划者放弃一整条方向的否定结论，要求下结论前先穷尽该意图内的合理手段（换编码/参数/路径/方法）；手段未走完或证据偏弱一律标 `confidence=inferred`，避免用轻率的 `observed` 否定把整条路线焊死（任务早期的错误否定尤其会把方向带偏且难以自愈）。
- 上述 planner / worker 默认提示词变更通过一次性迁移（`reseedPlannerPrompt` / `reseedWorkerPrompt`，各带 settings flag 守卫）追加为新版本并切为当前版本；旧版本保留在版本历史中，自定义过提示词的用户可在版本记录里恢复。

### 运维

#### 新增的功能

- 新增 `reset-password.sh` 重置管理员（用户名固定 `ARTEX`）密码：支持 local / docker 两种部署，连接信息可显式指定或自动从 `--dsn`/`$POJUN_PG_DSN`/`config.json` 读取；在库内用 `pgcrypto` 生成与后端登录兼容的 bcrypt 哈希并写回 `settings.auth.password_hash`，重置后无需重启服务。密码经环境变量传入、不进入进程 argv，并做转义防注入。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)
- [@neouks](https://github.com/neouks)

## [0.3.4] - 2026-08-24

### UI

#### 新增的功能

- 任务列表勾选多个任务后可批量修改分类，目标分类支持「未分类」以将任务移出当前分类；整批写入在一个事务内完成，失败项只会是勾选后已被删除的任务。

#### 修改的功能

- 新建任务的「任务分类」由下拉选择改为可搜索输入框：输入即过滤已有分类，库里没有的名称回车（或点下拉里的「创建」）即时新建并选中，选中项以可移除的 tag 展示；仍限单个分类。

### 对话

#### 修复的问题

- 修复会话已选定 LLM 配置、但全局无激活配置时，发送消息被「LLM 未配置，无法对话」拦截的问题。发送前的检查原本只看全局激活配置，而实际执行会优先用会话所选配置，两处解析逻辑不一致；现统一为同一套（会话/Agent 绑定优先，全局兜底）。
- 无法对话时的提示按状态细分：完全没有配置提示「添加配置」，有配置但未激活提示「激活或为本会话指定一个配置」，不再一律显示「未配置」，便于定位。

### Agent

#### 新增的功能

- 目标已全部达成的任务，主 Agent 经 `add_intent` 下发的意图可被 Worker 直接领取执行、跑完即止：此时 Planner 不再运行（任务无 open 目标即不进规划），避免其重判目标达成而取消刚下发的意图；frontier 抽干后任务回到已完成。主 Agent 下发意图前会依据意图内容反问用户是否将其登记为正式目标，登记则任务恢复常规自主规划。

#### 修改的功能

- `get_worker_trace` / `get_task_worker_trace` 的 `step_ids` 超过一次上限（5 个）时不再直接报错，改为返回前 5 步的完整内容，并在结果中通过 `returned_step_ids` / `omitted_step_ids` / `notice` 告知本次取了哪些、还有哪些未取，并提示「若已足够则无需再取」。传入的重复与非法 id 会先去重、剔除后再计数。

#### 修复的问题

- 任务列表改为按任务 id 降序（最新创建在最前），替换原先的按创建时间排序。同一时刻创建的多个任务时间戳相同、排序不稳定，配合每 10 秒轮询和内存 map 的随机遍历，会导致它们在列表里频繁互换位置。

### 资产

#### 修复的问题

- 修复企业归属重算被单行脏数据打挂：`assets.ip` 存了主机名（Agent 或资产 API 写入）时，`a.ip::inet` 会抛 `22P02`，导致新增/修改企业资产范围和删除企业全部失败并回滚。改用安全转换 `try_inet()`，非法值跳过而不是中断整条语句。
- 无法解析的 `ip` 不再静默跳过：企业范围保存后会明确提示有多少条资产的 `ip` 不是合法 IP（含具体 id 和取值），提醒这些资产不会被 IP/CIDR 规则归属；同一信息也写入服务端日志，覆盖没有前端响应的路径（删除企业、scopesentry 同步、Agent 写入）。
- 任务测试范围的 IP/CIDR 匹配同步改用 `try_inet()`，替换原先只检查字符集的正则守卫（`abc.def` 这类全 hex 字母的主机名此前仍会漏过并触发同样的报错）。

#### 修改的功能

- `ip`、`service`、`endpoint` 资产的 `ip` 字段不再接受主机名：`insert_assets` 和资产 API 会逐条返回带 `index` 的错误，并直接给出改正方法（改用 `type=subdomain` 填 `domain`，或先解析 A/AAAA 记录），Agent 可据此自行修正后重插。同批次中的其他资产不受影响，照常入库。

### 贡献者

- [@neouks](https://github.com/neouks)

## [0.3.3] - 2026-08-23

### Worker

#### 新增的功能

- 运行中的 Worker 支持单项暂停、恢复和取消；暂停保留意图、事实与漏洞，取消会在执行退出后事务性清理当前意图及其直接产物。
- 增加 `paused` 意图状态、执行栅栏和具名终止原因，防止暂停、取消或任务删除后出现迟到黑板写入。
- 增加可选任务并发上限；新建、恢复、漏洞深入和队列补位统一通过持久化 FIFO 准入路径。

#### 修改的功能

- Worker 单次运行墙钟默认时长由 600 秒调整为 1200 秒；超时任务复活后在下一次真实执行时重新计时。
- Worker、Planner 和主 Agent 的真实执行状态统一驱动任务状态徽标，修复 Worker 运行时仍显示“空闲”的问题。
- Worker 会话保留单项控制和当前会话 Token 汇总，模型名称移动到当前会话标题右侧展示。

#### 删除的功能

- 删除 Worker 多选、全选及批量暂停/继续界面，同时移除 Worker 批量控制 API 和 Mock 契约。
- 删除 Worker 列表行中的 Token 徽标与 Tooltip，底层完整 Token 账本和任务聚合接口继续保留。

### LLM

#### 新增的功能

- 任务支持有序 LLM 配置链；明确识别供应商额度不足时自动切换下一配置，并持久化当前配置、耗尽状态和错误摘要。
- 运行中和暂停任务支持编辑完整配置链、调整顺序和手动切换当前配置，从下一次 LLM 调用生效。
- 自动切换、手动切换和全链耗尽写入结构化系统活动，并通过任务活动流弹出可去重提醒。
- 增加任务角色模型解析接口，统一解析 Main Agent、Planner 和 Worker 下一次调用使用的配置与模型。
- 增加可选的全局 LLM Pool，支持配置调用顺序、指定模型失败兜底、健康状态、冷却恢复和手动重置。
- 增加始终开启的 LLM 用量账本，按任务、会话、模型和配置聚合输入、输出及缓存 Token。

#### 修改的功能

- 目标拆解、Planner、Worker 和主 Agent 共享任务级 LLM runtime（解析优先级见下）。
- 故障转移只响应明确的额度、余额或账单错误；普通限流、鉴权、网络、服务端和上下文错误不会错误切换。
- LLM 配置页改为配置卡片列表和右侧抽屉编辑，并提供 Pool 轮询顺序、优先级、排除项、健康状态和恢复操作。
- 配置链耗尽信息支持窄屏换行；当前模型由会话列表图标改为当前会话标题旁的文字标签和完整 Tooltip。
- 任务内各角色解析 LLM 的顺序调整为「Agent 绑定 → 任务配置链 → 全局」：显式绑定模型的角色始终跑在该模型上，未绑定角色才落到任务链，任务链为空时再落到全局。
- 出站代理留空即直连，不再回退 `HTTP_PROXY`/`HTTPS_PROXY` 环境变量（显式 `POJUN_LLM_PROXY` 不受影响）；代理输入支持带账号密码的 `socks5://user:pass@host:port`。

#### 修复的问题

- 提交前（尚未产出任何输出）的瞬时流式失败在同一 provider 上安全退避重试，显著减少「只跑了一两个工具就中断、无总结、终态 `model_error`」的情况；额度耗尽、上下文过长和 4xx 确定性错误不重试，仍分别交由故障转移与压缩恢复处理。

#### 删除的功能

- 删除会话列表中的 LLM 图标式标识，避免与 Worker 状态图标混淆。

### UI

#### 新增的功能

- 任务支持全局分类的创建、重命名、删除和筛选；新建任务可直接选择分类。
- 增加全局任务模板 CRUD 和右侧管理抽屉；新建任务可加载预设描述与目标，也可将当前内容另存为模板。
- 新建任务支持关联多个来源任务和多个企业资产范围；企业范围通过单个多行文本框自动识别域名、URL、IP、CIDR、ICP 和企业关键词。
- 任务测试资产支持实时新增和删除，记录人工、企业、继承或 Agent 发现等来源；Worker 会话标题旁显示当前测试资产及来源摘要。
- 发现页按任务分组并提供组内独立分页，支持为漏洞填写描述并创建高优先级深入意图。
- 对话支持重命名、置顶、取消置顶和删除；任务列表支持当前页批量暂停与继续。
- 流量详情和工具执行详情改为右侧抽屉；HTTP 报文补齐 `Host` 并高亮请求行、状态码、Header、JSON 和标记语言正文。
- 任务列表操作列新增「详情」与「暂停/继续」按钮；会话发送键位可在系统设置中配置（`Enter` / `Cmd+Enter` 等），Web 搜索区新增代理输入框。
- 会话标题右侧徽标改为显示 LLM 配置名称，模型 ID 移至 hover Tooltip；任务可设置可选名称，任务列表新增名称列与搜索（空则回退到描述）。
- 技能页增加使用次数、最近使用时间和缺失依赖统计，便于定位未生效或未安装的技能。

#### 修改的功能

- 任务标题改为可聚焦详情链接；任务资产、企业资产、发现任务组和组内漏洞使用服务端真实分页、稳定排序与精确总数。
- 新增企业改用右侧抽屉，范围录入统一为多行文本并提供实时识别、校验和类型预览。
- 主 Agent 输入框支持自动增长、`Enter` 发送、`Shift+Enter` 换行，并避免中文输入法组合态误发送。
- Agent 预览、任务报告和相关详情统一使用共享 Markdown 渲染；删除确认、长错误和移动端抽屉宽度统一修复。
- 任务模板选择框以模板名称显示和搜索、以模板 ID 提交；恢复系统原始字体尺寸，应用版本统一显示为 `0.3.3`。
- 任务总计和当前会话 Token 只高亮输入、缓存读取和输出数值；发送按钮使用更简洁的上箭头图标。
- 任务总览的测试范围显示企业名称而非 ID。

#### 修复的问题

- 含点号的普通文本不再被误判为 ICP 备案号。
- 修复变量目录中与全局运行时变量（如 `{{.Now}}`）撞名，导致 Agent 编辑器变量列表渲染出重复 key 的问题。

#### 删除的功能

- 删除任务卡片独立“进入”按钮，统一点击任务标题进入详情。
- 删除仪表盘“新建任务”按钮、新增企业的 Logo URL 输入项，以及发现页顶部和任务分组中的漏洞数量 Badge。
- 撤销全局字体增大 10% 的样式，并删除会话列表中的 Worker 选择框、模型图标和行级 Token 统计。

### Agent

#### 新增的功能

- 新任务可直接关联多个已有任务，实时只读继承直接来源任务的目标、事实、漏洞、已完成意图、资产范围和黑板上下文。
- 黑板读取工具支持按需查询来源任务节点、事实、漏洞和执行轨迹；继承节点带来源标记且所有写工具拒绝修改。
- 企业范围工具支持域名、URL、IP、CIDR、ICP 和企业关键词；关键词仅作为 Agent 范围提示，不参与资产自动归属。
- 漏洞深入操作会在原任务创建带资产锚点和 `derived_from` 边的高优先级人工 Worker 意图。
- 总览新增「目标管理」卡片，支持人工查看、新增、修改和删除目标；新增或修改会通知 Planner 并复活任务，删除硬删目标节点（级联删边与锚点）但不复活。
- 主 Agent 默认获得 `steer_work` 工具，可对运行中的 Worker 实时注入纠偏指令而不打断、不丢失进展（仍校验意图归属本任务）。

#### 修改的功能

- 来源任务意图不进入新任务 frontier，新任务继续使用独立 exploration、执行队列、工作目录和对话历史。
- 删除运行中的意图不再销毁数据：改为停到 `stopped`、要求填写删除原因、把原因作为事实挂到该意图并写入 payload，规划者按 `cancelled` 触发感知（保留意图内容与原因）。
- 主 Agent 对话改为服务端活动流驱动，发送失败可恢复输入；打开会话时自动贴底并在详情懒加载后保持最后回复可见。
- 任务暂停会终止当前 Main Agent、Planner 和 Worker 调用，但不阻止暂停期间用户主动发起新的主 Agent 编排会话。
- 取消、关闭和流式中断统一保留真实终止原因、已生成内容、运行轮数、耗时、Token 与未返回工具调用。

#### 删除的功能

- 删除主 Agent 客户端乐观消息回显，避免暂停、失败或并发活动下出现重复消息和跨会话串流。

### 约束

#### 新增的功能

- 目标拆解阶段先抽取操作约束（allow/deny）再拆目标，主 Agent 运行时可补充；约束按最高优先级注入 Planner 与 Worker 系统提示，去偏后多样性与拓面探索显式服从约束。
- 总览新增「约束管理」卡片与增删改接口；约束注入范围可按 Planner / Worker 分别开关（默认都开，每轮读取、即时生效）。新表 `task_constraints` 使用 `CREATE TABLE IF NOT EXISTS`，旧库自动补建。

### 拦截

#### 新增的功能

- 命令拦截在正则/字符串规则之外新增模型兜底审批：一条规则都未命中时由模型做 `ALLOW`/`ASK`/`DENY` 语义判定，失败回退动作与审批超时动作可配置；拦截页拆分「拦截规则 / 模型配置」两个 Tab，模型判定结果标注 `[模型]` 前缀与理由。

#### 修复的问题

- 加固裁判输出解析，避免正确的 `DENY` 判定被误当作放行。

### 流量

#### 修改的功能

- 流量录制改为整条 exchange 落 SQLite（大正文溢出到按 hash 去重的 blob 桶），文本正文建 trigram 全文索引，支持任意子串与中文搜索；删除退化为单条 SQL 事务，从数小时降到毫秒级且期间不再停摆录制。新增大 body 流式下载与 `traffic_search` 全文参数；旧文件树数据免迁移，仍可读、可搜、可删。

### 任务与资产

#### 新增的功能

- 创建任务新增「资产覆盖度功能」开关（默认开）：关闭后不计算与展示覆盖度、态势图只显示资产、不自动累积 `task_scope`，相关工具从 Planner / 主 Agent 剔除；企业关联不受此开关影响。
- `insert_assets` 每条资产新增 `related` 标记（默认 `true`）：仅在开启覆盖度时生效，`false` 只入共享资产库、不计入本任务覆盖度（如顺带发现的旁站或无关资产）。
- 企业范围和任务测试资产统一支持域名、URL、IP、CIDR、ICP 与关键词文本识别；域名/IP 可创建或复用全局资产，CIDR/ICP/关键词保留为任务范围上下文。

### 构建

- `build.sh --release` 支持一次构建 Linux amd64/arm64、macOS amd64/arm64 和 Windows amd64，并生成带 `skills/`、配置示例和 README 的 zip 发布包。
- 使用 Go linker 去除调试信息并生成 zip 发布包；UPX 改为显式可选，避免其自解压 ELF 在部分 Linux 环境启动时发生段错误。
- Release Workflow 对 Linux amd64 二进制执行启动冒烟测试，并随发布包提供 `SHA256SUMS`。

### 贡献者

- [@neouks](https://github.com/neouks)

## [0.3.2] - 2026-08-20

### Added

- 新建任务支持关联多个已有任务，实时、只读继承直接来源任务的事实、漏洞、已完成意图、资产范围和黑板上下文；新任务仍使用独立的执行队列、工作目录和会话历史。
- 任务支持有序 LLM 配置链。明确识别到供应商额度不足时自动切换到下一配置，并持久化当前配置、耗尽状态和结构化审计活动。
- 运行中和暂停任务支持编辑 LLM 配置链、调整顺序及手动切换当前配置；自动切换、手动切换和全链耗尽会在任务详情页提示。
- 运行中的 Worker 支持暂停、恢复和取消。暂停保留黑板数据，取消会在 Worker 停止写入后事务性清理该意图及其直接产出的事实、漏洞和执行记录。
- 删除任务可选择同时清理关联资产、流量、漏洞和任务落地文件，并增加删除屏障、并发保护和可审计的删除统计。
- 增加可选的任务并发上限；达到上限的新任务按 FIFO 排队，并在运行槽位释放后自动启动。
- 增加任务资产分页、公司资产分页、任务分类统计及分页意图 Mock 契约。
- 增加 `build.sh` 单二进制构建脚本，支持静态前端导出、资源嵌入、跨平台目标和构建版本注入。

### Changed

- 任务级显式 LLM 配置链与现有全局 LLM Pool 并存；显式链继续采用严格的额度故障转移语义，无显式链时沿用 Agent 绑定和全局配置规则。
- 主 Agent 输入框支持自动增长的多行输入，`Enter` 发送、`Shift+Enter` 换行，并避免中文输入法组合态误发送。
- Planner、Worker 和主 Agent 共享任务级 LLM runtime；任务链使用候选模型中最小上下文窗口作为安全压缩阈值。
- 任务详情页按真实 LLM 调用状态展示运行、空闲和暂停状态；来源任务的事实、漏洞、意图、资产引用和图谱节点统一标记来源并保持只读。
- Agent 预览、任务报告和相关详情视图统一使用共享 Markdown 渲染组件。
- LLM 模型配置采用卡片和抽屉交互，模型列表在抽屉内支持独立滚动。
- 任务暂停不再拦截主 Agent 对话：主 Agent 编排会话独立于任务暂停，暂停中仍可继续发送新消息（暂停只终止当前进行中的那一轮）。
- Worker 单次 run 的墙钟默认时长由 600 秒调整为 1200 秒。

### Fixed

- 移除主 Agent 控制台的乐观回显，改为纯服务端数据渲染，修复暂停或发送失败等场景下消息错乱、串入其他会话内容的问题。
- 打开主 Agent 会话默认滚动到底并完整显示最后一条回复：最后一条回复的完整内容懒加载展开后自动贴底，不再被顶出屏幕。
- 修复暂停任务后主 Agent 会话仍继续运行，以及编排 Agent 暂停任务时未同步停止主 Agent 的问题。
- 修复任务完成、Planner、Worker 或主 Agent 实际运行时，任务状态徽标与操作按钮状态不同步的问题。
- 修复 Worker 取消、任务删除和并发写入之间可能产生迟到黑板写入或残留文件的问题。
- 修复 Markdown 预览失效、删除确认长文本溢出、移动端宽度和部分任务详情按钮未对齐的问题。
- 为所有 Agent 取消路径增加具名终止原因，活动详情可显示取消方、终态、运行轮数、耗时、Token 使用量和未返回的工具调用。
- 修复后端关闭时父 context 可能抢先覆盖具名 `shutdown` 原因的竞态，以及中文活动摘要按字节截断导致乱码的问题。
- 修复带部分流式输出的取消事件丢失真实终止原因的问题，同时保留取消前已生成的内容。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)
- [@neouks](https://github.com/neouks)

[Unreleased]: https://github.com/chu0119/Pojun/compare/v0.3.10...HEAD
[0.3.10]: https://github.com/chu0119/Pojun/compare/v0.3.9...v0.3.10
[0.3.9]: https://github.com/chu0119/Pojun/compare/v0.3.8...v0.3.9
[0.3.8]: https://github.com/chu0119/Pojun/compare/v0.3.7...v0.3.8
[0.3.7]: https://github.com/chu0119/Pojun/compare/v0.3.6...v0.3.7
[0.3.6]: https://github.com/chu0119/Pojun/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/chu0119/Pojun/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/chu0119/Pojun/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/chu0119/Pojun/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/chu0119/Pojun/compare/v0.3.1...v0.3.2

## 0.4.4 – 0.4.19 发版概要（2026-11-01 ~ 11-02）

> 逐版详录欠账，按主题归档；完整明细见各 tag 的 commit 历史（`git log v0.4.3..v0.4.19`）
> 与 Release Notes。

| 版本 | 主题 |
|---|---|
| v0.4.4 | 公文格式全链路：GB/T 9704 对齐 + 字体嵌入（odttf）+ document.xml.rels styles 根因修复 + Word/LibreOffice 双端验收 |
| v0.4.5 | Shannon 借鉴第一批：证据分级 L1–L4 / 三态判定 / severity 自查 |
| v0.4.6 | 证据纪律与流量绑定解耦（CI 红修复） |
| v0.4.7 | 任务成本展示（/api/tokens/cost + 前端 ≈$） |
| v0.4.8 | 任务级登录凭据 + 真实登录自检（TOTP 支持） |
| v0.4.9 | 证据附件地基：task_artifacts / save_evidence / Word 插图 / 前端展示 |
| v0.4.10 | 存储桶照片取证纪律 + 历史补登记 |
| v0.4.11 | 拼图配方重做（2 张并排 / 2×2）+ 流量卡折叠 + 版本小步走 |
| v0.4.12 | SQL 注入必须带实测 sqlmap 复测命令 |
| v0.4.13 | pojun-maint 维护工具 + hostd 随包分发 + 安装脚本补全 |
| v0.4.14 | Kali 部署修复（含 artex-maint，任务 5 自动恢复） |
| v0.4.15–0.4.16 | 证据卡交互重做 / 任务详情设置页 |
| v0.4.17–0.4.18 | 数据盘扩容迁移 / 附件 403 权限修复（0644 + fix-permissions） |
| v0.4.19 | 项目改名 Pojun：全局代码标识 / 二进制 / 目录 / 环境变量 / 镜像 / 仓库 |
