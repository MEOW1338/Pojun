#!/usr/bin/env bash
# POJUN 安装 / 部署脚本（唯一入口）
#
# 运行后选择部署形态，再走对应流程；也可用 --mode 直接指定。
#
#   sudo ./install.sh                     交互选择（二进制 / Docker）
#   sudo ./install.sh --mode=binary       二进制：单文件 + systemd + 系统 PostgreSQL
#                                         （macOS 上自动走 launchd + Homebrew PostgreSQL，
#                                          不需要 sudo：brew 与用户级 launchd 都是当前用户）
#   sudo ./install.sh --mode=docker       Docker Compose：容器 + 容器内 PostgreSQL
#   sudo ./install.sh --mode=binary --with-tools
#
#   curl -fsSL .../install.sh | sudo bash    # 一条命令，交互式（模式/代理均可在 /dev/tty 里选）
#
# 幂等：重复执行 = 升级程序，保留数据（config.json / jwt.key / data / 数据库 / .env）。
#
# 卸载：二进制 systemctl disable --now pojun && rm -rf /opt/pojun
#       Docker   cd /opt/pojun && docker compose down -v && rm -rf /opt/pojun
set -euo pipefail

REPO="chu0119/Pojun"
INSTALL_DIR="/opt/pojun"
SERVICE="pojun"
RUN_USER="pojun"
VERSION="latest"
MODE="${MODE:-}"
WITH_TOOLS=0
LISTEN_ADDR="${LISTEN_ADDR:-:8787}"
PROXY_ADDR="${PROXY_ADDR:-127.0.0.1:8788}"
PG_SUPER="${PG_SUPER:-postgres}"
# 安装期出网代理（apt / curl / go 下载走它）。留空 = 直连。
# 只作用于「装东西」，与运行期 Agent 的目标代理、LLM 代理互不相干。
INSTALL_PROXY="${INSTALL_PROXY:-${HTTPS_PROXY:-}}"
# macOS 自带 bash 3.2（不支持 ${var,,} 小写展开），用 tr 做兼容
IMAGE="ghcr.io/$(printf '%s' "$REPO" | tr '[:upper:]' '[:lower:]')"
ASSUME_YES=0
# 是否安装特权助手 pojun-hostd(提供「系统 → 宿主环境」页的一键安装)。
# 默认装;不想让 Web 端具备装包能力时用 --no-installer 关掉。
WITH_INSTALLER=1

# 管道执行（curl ... | sudo bash）时 stdin 是脚本本身，不能用来读输入。
# 只要 /dev/tty 可读，就仍可交互提问（宝塔式一键安装的关键）。
CAN_PROMPT=0
if [ -r /dev/tty ]; then CAN_PROMPT=1; fi

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

usage(){
  cat <<EOF
POJUN 安装脚本

用法: $0 [选项]

系统建议: Debian 12 / Ubuntu 22.04+ LTS（稳定）；Kali 适合开箱全套工具（滚动更新有风险）
          最低 2C4G/20G，推荐 4C8G/60G（含工具、字典与浏览器）

部署形态:
  --mode=binary|docker   二进制（默认，推荐）或 Docker。不给则交互选择
                         （管道执行 curl ... | bash 时同样会从 /dev/tty 交互）
  --with-tools           顺装常用渗透工具（Docker 形态下工具随镜像固定，见说明）

通用:
  --version=VER          版本，默认 latest（如 v0.3.20）
  --dir=PATH             安装目录（默认 /opt/pojun）
  --listen=ADDR          监听地址（默认 :8787）
  --proxy=ADDR           流量记录代理地址（默认 127.0.0.1:8788）
  --install-proxy=URL    安装期出网代理，如 http://10.0.0.14:7897（默认取 \$HTTPS_PROXY）
  -y, --yes              非交互，全部用默认值
  -h, --help             显示帮助

二进制形态专用:
  --user=NAME            运行用户（默认 pojun）
  --pg-super=NAME        PostgreSQL 超级用户（默认 postgres）
  --no-installer         不安装特权助手 pojun-hostd（关掉 Web 端的一键安装能力）

Docker 形态专用:
  --image=REF            镜像名（默认 $IMAGE）

示例:
  sudo ./install.sh --mode=binary --with-tools
  sudo ./install.sh --mode=docker --version=v0.3.20
  sudo ./install.sh --mode=binary --install-proxy=http://10.0.0.14:7897 --with-tools
EOF
}

# ── 参数 ─────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --mode=*)          MODE="${arg#--mode=}" ;;
    --with-tools)      WITH_TOOLS=1 ;;
    --version=*)       VERSION="${arg#--version=}" ;;
    --dir=*)           INSTALL_DIR="${arg#--dir=}"; DIR_EXPLICIT=1 ;;
    --listen=*)        LISTEN_ADDR="${arg#--listen=}" ;;
    --proxy=*)         PROXY_ADDR="${arg#--proxy=}" ;;
    --install-proxy=*) INSTALL_PROXY="${arg#--install-proxy=}" ;;
    --user=*)          RUN_USER="${arg#--user=}" ;;
    --pg-super=*)      PG_SUPER="${arg#--pg-super=}" ;;
    --image=*)         IMAGE="${arg#--image=}" ;;
    --no-installer)    WITH_INSTALLER=0 ;;
    -y|--yes)          ASSUME_YES=1 ;;
    -h|--help)         usage; exit 0 ;;
    *) die "未知参数: $arg（用 --help 查看帮助）" ;;
  esac
done

# ── 前置检查 ─────────────────────────────────────
DIR_EXPLICIT="${DIR_EXPLICIT:-0}"
IS_MAC=0
case "$(uname -s)" in
  Linux)  : ;;
  Darwin) IS_MAC=1 ;;
  *) die "仅支持 Linux / macOS" ;;
esac

ARCH="$(uname -m)"
if [ "$IS_MAC" = "1" ]; then
  # macOS：brew 与用户级 launchd 都是当前用户体系，全程不需要 sudo。
  # 显式用 sudo 反而坏事：root 的 brew/HOME 与用户不一致，服务会落在 root 的
  # LaunchAgents 里起不来。目录默认也放 $HOME/pojun（/opt 需要特权）。
  [ "$(id -u)" = "0" ] && die "macOS 请直接运行本脚本（不要加 sudo）"
  case "$ARCH" in
    arm64)  PKG_ARCH="darwin-arm64" ;;
    x86_64) PKG_ARCH="darwin-amd64" ;;
    *) die "不支持的 Mac 架构: $ARCH（支持 arm64/x86_64）" ;;
  esac
  # /opt 在 macOS 需要特权；默认装到家目录，显式 --dir 优先
  if [ "$DIR_EXPLICIT" != "1" ]; then
    INSTALL_DIR="$HOME/pojun"
  fi
else
  [ "$(id -u)" = "0" ] || die "请用 root/sudo 运行"
  case "$ARCH" in
    x86_64)  PKG_ARCH="linux-amd64" ;;
    aarch64) PKG_ARCH="linux-arm64" ;;
    *) die "不支持的架构: $ARCH（支持 x86_64/aarch64）" ;;
  esac
fi

# curl 是两种形态的公共依赖
if ! command -v curl >/dev/null 2>&1; then
  command -v apt-get >/dev/null 2>&1 && { apt-get update -qq || true; apt-get install -y curl >/dev/null || true; }
  command -v dnf >/dev/null 2>&1 && dnf install -y curl >/dev/null || true
fi
command -v curl >/dev/null 2>&1 || die "curl 安装失败，请手动安装"

# CA 证书是后续全部 HTTPS 的前提。极简系统（比如用 --no-install-recommends
# 装的 curl 不会带入 Recommends 的 ca-certificates）会出现 curl: (77)
# "error setting certificate file"，所有 HTTPS 请求全挂且报错指不到真因。
# 两大发行版的 CA 包位置都判一下，缺哪个补哪个；装不上也不阻断（真实新
# 机器几乎都自带，这里只兜极端裁剪过的系统）。
# macOS 的系统证书在 /etc/ssl/cert.pem（随系统自带），Linux 才需要下面的兜底安装
if [ "$IS_MAC" != "1" ] \
   [ ! -e /etc/ssl/certs/ca-certificates.crt ] && [ ! -e /etc/pki/tls/certs/ca-bundle.crt ]; then
  info "未检测到 CA 证书包，尝试安装 ca-certificates..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq >/dev/null 2>&1 || true
    apt-get install -y ca-certificates >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ca-certificates >/dev/null 2>&1 || true
  fi
  [ -e /etc/ssl/certs/ca-certificates.crt ] || [ -e /etc/pki/tls/certs/ca-bundle.crt ] \
    || die "CA 证书包缺失且自动安装失败，请手动安装 ca-certificates 后重试"
  ok "CA 证书包就绪"
fi

# ── 资源前置检查（只提醒不阻断）────────────────────
mem_kb="$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)"
if [ "${mem_kb:-0}" -gt 0 ] && [ "$mem_kb" -lt 3800000 ]; then
  warn "内存 < 4G：多 worker 并发 + 压缩器会吃紧（建议 4C8G 起）"
fi
disk_avail="$(df -Pk / 2>/dev/null | awk 'NR==2{print $4}')"
if [ -n "${disk_avail:-}" ] && [ "$disk_avail" -lt 10485760 ]; then
  warn "根分区可用 < 10G：装工具/SecLists(约2.5G)/nuclei 模板/chromium 可能不够（建议 ≥40G）"
fi
if command -v python3 >/dev/null 2>&1; then
  pyver="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo "0.0")"
  case "$pyver" in
    3.10|3.11|3.12|3.13|3.14) ;;
    *) warn "python3 版本 ${pyver}：内置 FOFA MCP 需要 ≥3.10（不影响主服务）" ;;
  esac
else
  warn "未检测到 python3：内置 FOFA MCP 需要 Python ≥3.10（不影响主服务）"
fi

# ── 出网代理：交互式配置 + 自动验证 ────────────────
#
# 为什么交互式：装机最常卡住的就是「这台机器连不上 GitHub / apt 源」。
# 让用户现场填一个标准格式的代理（http / https / socks5 / socks5h），
# 脚本自己验证通不通，验证过了再走流程——比让人事后自己去翻日志找
# "curl: (7) Failed to connect" 快得多。
#
# 填了代理后所有出网路径统一走它：apt / curl / npm / git / pip / go install。
# 验证不过时可以选择重填或跳过（跳过=直连，后面该失败的会失败）。
normalize_proxy(){
  local p="$1"
  p="$(printf '%s' "$p" | tr -d ' \t"'"'"'' | sed 's|/*$||')"
  [ -z "$p" ] && return 0
  # 裸 host:port → 默认按 http 处理（绝大多数本地代理是 http 混合端口）
  case "$p" in
    *://*) : ;;
    *) p="http://$p" ;;
  esac
  printf '%s' "$p"
}

# proxy_scheme_ok 校验协议：只有 http/https/socks5/socks5h 有效。
proxy_scheme_ok(){
  case "$1" in
    http://*|https://*|socks5://*|socks5h://*) return 0 ;;
    *) return 1 ;;
  esac
}

# proxy_has_hostport 校验 host:port 齐全。
proxy_has_hostport(){
  local rest="${1#*://}"
  rest="${rest%%/*}"
  case "$rest" in
    *@*) rest="${rest#*@}" ;;
  esac
  case "$rest" in
    *:*) [ -n "${rest%%:*}" ] && [ -n "${rest##*:}" ] ;;
    *) return 1 ;;
  esac
}

# proxy_curl_args 按协议拼出 curl 的代理参数。
# socks5:// 这种 URL 形式 curl 的 -x 不认（会报 "unsupported protocol
# scheme"），它要的是 --socks5-hostname host:port。硬塞 URL 的表现是
# 「填了 socks 代理但所有下载都失败」，而报错完全指不到真因。
#
# --socks5-hostname vs --socks5：前者把域名也交给代理解析（= socks5h），
# 后者在本地解析 DNS。国内环境里本地 DNS 常常解析不了境外域名，所以用前者。
proxy_curl_args(){
  local p="$1"
  case "$p" in
    socks5://*|socks5h://*)
      local _p="${p#*://}" _auth=""
      case "$_p" in
        *@*) _auth="${_p%%@*}"; _p="${_p#*@}" ;;
      esac
      _p="${_p%%/*}"
      printf '%s\n' --socks5-hostname "$_p"
      [ -n "$_auth" ] && printf '%s\n' --socks5-basic -U "$_auth"
      ;;
    *)
      printf '%s\n' -x "$p"
      ;;
  esac
}

# verify_proxy 拿代理真的发一个请求验证可用性。
# 用 GitHub API 做靶子：装机流程本来就要访问它，验证与用途一致。
verify_proxy(){
  local p="$1"
  local -a pargs=()
  while IFS= read -r line; do pargs+=("$line"); done < <(proxy_curl_args "$p")
  local code
  code="$(curl -fsSL "${pargs[@]}" -o /dev/null -w '%{http_code}' \
        --connect-timeout 8 --max-time 20 \
        https://api.github.com/repos/projectdiscovery/nuclei/releases/latest 2>/dev/null)" || code="000"
  case "$code" in
    200|301|302|403) return 0 ;;   # 403 = GitHub 限流，链路是通的
    *) return 1 ;;
  esac
}

# configure_proxy 交互式询问 + 规范化。
# 只做「问」与「格式校验」，验证单独放在 CURL 构造之后（verify_proxy 需要
# 按协议拼 curl 参数，而那依赖 INSTALL_PROXY 已定型）。
#
# 显式给了 --install-proxy 也走同一套校验：填错协议/端口是最常见的失败原因。
configure_proxy(){
  if [ -n "$INSTALL_PROXY" ]; then
    INSTALL_PROXY="$(normalize_proxy "$INSTALL_PROXY")"
    if ! proxy_scheme_ok "$INSTALL_PROXY"; then
      die "代理协议不支持: $INSTALL_PROXY（支持 http/https/socks5/socks5h）"
    fi
    if ! proxy_has_hostport "$INSTALL_PROXY"; then
      die "代理缺少 host:port: $INSTALL_PROXY"
    fi
    return 0
  fi

  # 非交互场景不打扰：直连。
  [ "$ASSUME_YES" = "1" ] && return 0
  [ "$CAN_PROMPT" = "0" ] && return 0

  printf '\n'
  printf '是否配置出网代理？\n'
  printf '  装机要访问 apt 源 / GitHub / npm / pypi；直连不通时在这里填一个代理最省事。\n'
  printf '  支持格式：http://host:port 、https://host:port 、socks5://host:port 、socks5h://host:port\n'
  printf '  带认证：http://user:pass@host:port ；留空 = 直连\n'
  printf '代理地址（留空直连）: '
  local ans=""
  read -r ans </dev/tty || ans=""
  ans="$(printf '%s' "$ans" | tr -d ' \t"'"'"'')"
  [ -z "$ans" ] && { info "使用直连"; return 0; }

  ans="$(normalize_proxy "$ans")"
  if ! proxy_scheme_ok "$ans"; then
    warn "协议不支持: $ans"
    warn "支持 http/https/socks5/socks5h"
    return 0
  fi
  if ! proxy_has_hostport "$ans"; then
    warn "缺少 host:port: $ans"
    return 0
  fi
  INSTALL_PROXY="$ans"
  return 0
}

configure_proxy

# ── curl 的代理参数：按协议分发 ───────────────────
#
# curl 不接受 socks5:// 这种 URL 形式的 -x（会报 "unsupported protocol
# scheme"），它要的是 --socks5-hostname host:port。照 URL 形式硬塞进去的
# 表现是「填了 socks 代理但所有下载都失败」，而报错完全指不到真因。
#
# --socks5-hostname vs --socks5：前者把域名也交给代理解析（= socks5h），
# 后者在本地解析 DNS。国内环境里本地 DNS 常常解析不了境外域名，所以用前者。
# --retry-all-errors：不加它，curl 的 --retry **只重试瞬时错误**（超时/429/5xx），
# SSL 中断（SSL_read: unexpected eof）这类传输错误直接失败——实测 2026-10-22
# 在一台真实服务器上经代理下载 17MB 发行包时，连接被切断后 curl 立刻放弃，
# 重试参数形同虚设。
#
# --retry-delay：重试之间退避，避免连着打同一个不稳的出口。
CURL=(curl -fsSL --retry 5 --retry-all-errors --retry-delay 3 --retry-max-time 1800)
if [ -n "$INSTALL_PROXY" ]; then
  while IFS= read -r _parg; do
    [ -n "$_parg" ] && CURL+=("$_parg")
  done < <(proxy_curl_args "$INSTALL_PROXY")
  info "安装期使用代理: $INSTALL_PROXY"

  # 代理必须验证过才能往下走：装机流程后面全靠它拉 GitHub 资产，
  # 代理不通时每一处下载都会失败并刷一堆看不懂的报错。
  printf '验证代理 ... '
  if verify_proxy "$INSTALL_PROXY"; then
    ok "代理可用"
  else
    printf '\n'
    warn "代理验证失败（GitHub API 不可达）"
    if [ "$ASSUME_YES" = "1" ] || [ "$CAN_PROMPT" = "0" ]; then
      die "代理不可用，中止安装（用 --install-proxy= 修正，或不传该参数走直连）"
    fi
    printf '仍然使用这个代理继续？(y/N) '
    local _ans=""; read -r _ans </dev/tty || _ans=""
    case "$_ans" in
      y|Y|yes|YES) : ;;
      *) die "已中止" ;;
    esac
  fi
fi

# 统一代理环境：git / npm / go / pip 这类工具只认 HTTP_PROXY/HTTPS_PROXY/
# ALL_PROXY，不认 curl 的 -x。导出后它们自动走同一个代理。
# socks5 用 ALL_PROXY（curl 那条路已单独处理，ALL_PROXY 给 git/npm 用）。
if [ -n "$INSTALL_PROXY" ]; then
  case "$INSTALL_PROXY" in
    socks5://*|socks5h://*)
      export ALL_PROXY="$INSTALL_PROXY"
      export all_proxy="$INSTALL_PROXY"
      ;;
    *)
      export HTTP_PROXY="$INSTALL_PROXY"  HTTPS_PROXY="$INSTALL_PROXY"
      export http_proxy="$INSTALL_PROXY"  https_proxy="$INSTALL_PROXY"
      ;;
  esac
  export NO_PROXY="localhost,127.0.0.1,::1"
  export no_proxy="$NO_PROXY"
fi

# systemd 单元里的代理环境行。hostd 是独立进程，不共享主服务环境，
# 所以主服务与 hostd 两个单元都要带这一行。
INSTALL_PROXY_ENV=""
if [ -n "$INSTALL_PROXY" ]; then
  case "$INSTALL_PROXY" in
    socks5://*|socks5h://*)
      INSTALL_PROXY_ENV="Environment=ALL_PROXY=${INSTALL_PROXY}"
      ;;
    *)
      INSTALL_PROXY_ENV="Environment=HTTP_PROXY=${INSTALL_PROXY}
Environment=HTTPS_PROXY=${INSTALL_PROXY}"
      ;;
  esac
fi

# ── 选择部署形态 ─────────────────────────────────
choose_mode(){
  if [ -n "$MODE" ]; then
    case "$MODE" in binary|docker) return ;; *) die "--mode 只能是 binary 或 docker"; esac
  fi
  if [ "$ASSUME_YES" = "1" ] || [ "$CAN_PROMPT" = "0" ]; then
    MODE="binary"
    info "非交互模式，默认使用二进制部署（--mode 可显式指定）"
    return
  fi
  printf '\n请选择部署形态：\n'
  printf '  1) 二进制部署（推荐）  单文件 + systemd + 系统 PostgreSQL，运行时零依赖\n'
  printf '  2) Docker 部署         容器编排，工具随镜像固定\n'
  printf '选择 [1]: '
  local pick=""
  read -r -t 60 pick </dev/tty || true
  case "${pick:-1}" in
    2|docker|D) MODE="docker" ;;
    *)          MODE="binary" ;;
  esac
  printf '\n'
}

choose_mode
ok "部署形态: $MODE  目标目录: $INSTALL_DIR"

# ── 解析版本 ─────────────────────────────────────
resolve_version(){
  # 注意：这里不能写成 `[ "$VERSION" = latest ] || return`——测试为假时 return 会带着
  # 测试的退出码 1 返回，set -e 会当场终止脚本。显式指定 --version 的调用必踩。
  if [ "$VERSION" != "latest" ]; then
    return 0
  fi
  VERSION="$("${CURL[@]}" "https://api.github.com/repos/$REPO/releases/latest" \
    | grep -oE '"tag_name": *"[^"]+"' | head -1 | cut -d'"' -f4)" || VERSION=""
  [ -n "$VERSION" ] || die "无法获取最新版本号（检查网络或用 --install-proxy 指定代理）"
}

# ── 下载并校验 Release 包（两种形态都要：二进制用程序，Docker 用 skills）──
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fetch_release(){
  resolve_version
  ok "目标版本: $VERSION"
  local zip="pojun-${VERSION#v}-${PKG_ARCH}.zip"
  info "下载 $zip"
  # 用原名落盘：SHA256SUMS 里写的就是这个名字，改名保存会让 sha256sum -c 找不到文件。
  #
  # -C - 是断点续传：17MB 的包经不稳的出口传输时断线是常态，续传比重下省时间
  # （实测一次安装因 SSL 中断白等了 40 分钟）。
  #
  # 下载失败必须在这里 die：原来不判就往下走，最后报「解压失败（需要 unzip）」
  # ——把网络问题误导成包损坏，用户会去查错方向。
  "${CURL[@]}" "https://github.com/$REPO/releases/download/$VERSION/$zip" -C - -o "$TMP/$zip" \
    || die "下载 $zip 失败（网络不通？代理不稳？可用 --install-proxy 指定代理）"

  # SHA256SUMS 是供应链校验的凭据：取不到就**没有校验**，此时继续装等于
  # 接受未经校验的二进制。原来只 warn 然后跳过校验——那是硬伤。
  "${CURL[@]}" "https://github.com/$REPO/releases/download/$VERSION/SHA256SUMS" -o "$TMP/SHA256SUMS" \
    || die "取不到 SHA256SUMS，无法校验 $zip（拒绝安装未经校验的二进制；可重试或用 --install-proxy 换出口）"
  ( cd "$TMP" && grep " $zip\$" SHA256SUMS | sha256sum -c - ) || die "SHA256 校验失败"
  ok "SHA256 校验通过"

  unzip -oq "$TMP/$zip" -d "$TMP/unpack" || die "解压失败（需要 unzip）"
}

# ══════════════════════════════════════════════════
# 二进制部署
# ══════════════════════════════════════════════════
deploy_binary(){
  if [ "$IS_MAC" = "1" ]; then deploy_binary_darwin; return; fi
  command -v systemctl >/dev/null 2>&1 || die "未检测到 systemd"
  command -v unzip   >/dev/null 2>&1 || { apt-get install -y unzip >/dev/null 2>&1 || dnf install -y unzip >/dev/null 2>&1 || die "需要 unzip"; }

  fetch_release
  local src="$TMP/unpack/pojun-${VERSION#v}-${PKG_ARCH}"
  [ -d "$src" ] || die "发行包结构异常: 找不到 $src"

  mkdir -p "$INSTALL_DIR"
  # 程序/skills 覆盖；config.json / jwt.key / data 不在 zip 里，天然不被动
  # 二进制不能直接 cp 覆盖正在运行的进程（Linux 报 ETXTBSY "Text file busy"），
  # 先落到同目录临时名再 rename——rename 对运行中的可执行文件是合法的。
  # 这一步之前漏了，导致「重跑 install.sh 即升级」在服务运行状态下必然失败。
  for b in pojun pojun-hostd pojun-maint; do
    [ -f "$src/$b" ] || continue
    cp "$src/$b" "$INSTALL_DIR/.$b.new"
    chmod +x "$INSTALL_DIR/.$b.new"
    mv -f "$INSTALL_DIR/.$b.new" "$INSTALL_DIR/$b"
  done
  # 其余文件（skills / README / start.sh / config.example.json）直接覆盖
  for f in "$src"/*; do
    base="$(basename "$f")"
    case "$base" in pojun|pojun-hostd|pojun-maint) continue ;; esac
    cp -r "$f" "$INSTALL_DIR/"
  done
  chmod +x "$INSTALL_DIR/start.sh"
  ok "程序就绪: $INSTALL_DIR/pojun"

  # 运行用户
  if ! id "$RUN_USER" >/dev/null 2>&1; then
    useradd --system --home "$INSTALL_DIR" --shell /usr/sbin/nologin "$RUN_USER"
    ok "已创建系统用户 $RUN_USER"
  fi
  chown -R "$RUN_USER:$RUN_USER" "$INSTALL_DIR"

  # PostgreSQL + config.json（仅首次）
  if [ ! -f "$INSTALL_DIR/config.json" ]; then
    info "配置 PostgreSQL..."
    if ! command -v psql >/dev/null 2>&1; then
      # 这处 apt 必须走代理：apt 源在国内机器上常常要代理才拉得到，
      # 而 postgres 是硬依赖，装不上整条流程就断了。
      if command -v apt-get >/dev/null 2>&1; then
        local PP=()
        [ -n "$INSTALL_PROXY" ] && PP=(-o "Acquire::http::Proxy=$INSTALL_PROXY" -o "Acquire::https::Proxy=$INSTALL_PROXY")
        apt-get "${PP[@]}" update -qq && apt-get "${PP[@]}" install -y postgresql
      elif command -v dnf >/dev/null 2>&1; then
        # dnf --setopt=proxy="" 会被当成"代理指向空地址"而不是"不设代理"，
        # 所以只在确实有代理时才加这个参数。
        local DP=()
        [ -n "$INSTALL_PROXY" ] && DP=(--setopt=proxy="$INSTALL_PROXY")
        dnf "${DP[@]}" install -y postgresql-server && postgresql-setup --initdb
      else
        die "未识别的包管理器，请手动安装 PostgreSQL"
      fi
      systemctl enable --now postgresql
    fi
    systemctl is-active --quiet postgresql || systemctl start postgresql
    local DB_PASS
    DB_PASS="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
    # 角色已存在时**必须同步密码**，不能只跳过。
    #
    # 踩过的坑（2026-10-22 真实安装）：机器上残留了旧的 pojun 角色（重装 /
    # 换端口 / 忘了删角色），脚本走「角色已存在 → 跳过创建」这条分支，
    # 于是 config.json 里写的是**新生成**的密码，而库里的角色还是**旧密码**
    # → 服务起来就反复 SASL 认证失败退出，而报错完全指不到真因。
    #
    # 同步密码是安全的：config.json 由本脚本独占写入（不覆盖已有安装），
    # 密码以它为准。角色已存在但 config.json 也在时，install.sh 根本不会
    # 走到这里（见上面的「仅首次」判断），所以不会误改既有安装的密码。
    if sudo -u "$PG_SUPER" psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='pojun'" | grep -q 1; then
      info "数据库角色 pojun 已存在，同步密码"
      sudo -u "$PG_SUPER" psql -c "ALTER ROLE pojun LOGIN PASSWORD '$DB_PASS'" >/dev/null
    else
      sudo -u "$PG_SUPER" psql -c "CREATE ROLE pojun LOGIN PASSWORD '$DB_PASS'"
    fi
    sudo -u "$PG_SUPER" psql -tAc "SELECT 1 FROM pg_database WHERE datname='pojun'" | grep -q 1 \
      || sudo -u "$PG_SUPER" createdb -O pojun pojun
    cat > "$INSTALL_DIR/config.json" <<JSON
{
  "database": {
    "host": "127.0.0.1",
    "port": 5432,
    "user": "pojun",
    "password": "$DB_PASS",
    "dbname": "pojun",
    "sslmode": "disable"
  }
}
JSON
    chown "$RUN_USER:$RUN_USER" "$INSTALL_DIR/config.json"
    chmod 600 "$INSTALL_DIR/config.json"
    ok "数据库 pojun 就绪（密码已写入 config.json，权限 600）"
  else
    ok "沿用既有 config.json（升级不覆盖）"
  fi

  # systemd 单元（加固版：够安全，但不再打断渗透工具）
  #
  # ProtectSystem=strict 必须配 ReadWritePaths，否则整个文件系统只读、服务写不了自己的
  # data 目录：流量索引(SQLite)、任务产物、证据、transcripts 会全部静默失败（日志刷
  # "attempt to write a readonly database"），页面「一键更新」也换不动二进制。
  #
  # 下面这组指令是逐条实测出来的，改动前请先读注释——这里踩过的坑都是"配上了但工具跑不了"：
  #   - MemoryDenyWriteExecute=true 会让 nuclei 启动即 panic（Go 的 sonic 加载器要做
  #     mprotect(PROT_EXEC)）。硬化收益远小于"扫描器不能用"，故不设。
  #   - 缺 CAP_NET_RAW 时 masscan 报 "PF_PACKET sockets not supported"、nmap -sS 报
  #     "requires root privileges"，agent 只能退回 -sT connect 扫描；RestrictAddressFamilies
  #     里也必须放行 AF_PACKET，否则连 raw socket 都建不出来。
  #   - 指令名是 SystemCallErrorNumber。写成不存在的 SystemCallErrorAction 时 systemd
  #     只会静默忽略（日志一行 "Unknown key ... ignoring"），超纲系统调用走默认动作
  #     SIGSYS 直接杀进程，而不是这里要的"干净拒绝"。
  #   - Environment=HOME 指到安装目录：ProtectHome + 家目录不可写会让 nuclei 的模板/缓存
  #     目录(~/nuclei-templates 等)写不进去。
  # 注：--dir 若指向 /home 或 /root 底下，ProtectHome=true 会把它整个藏起来，需自行去掉该项。
  cat > "/etc/systemd/system/${SERVICE}.service" <<UNIT
[Unit]
Description=POJUN - AI Autonomous Penetration Testing System
Documentation=https://github.com/${REPO}
After=network-online.target postgresql.service
Wants=network-online.target postgresql.service
# 反复失败要能被 systemd 判为 failed，而不是无限重启。
#
# start.sh 自己也有崩溃次数上限（连续 5 次异常退出就放弃自拉起并非 0 退出），
# 但那只是第一道防线：systemd 的 Restart=always 会立刻再拉起 start.sh，
# 于是又变成「status 显示 active (running)、实际全挂」的状态（start.sh 活着，
# pojun 本体在崩）。这里的 StartLimit 是第二道：达到上限后单元真正进入
# failed，运维一眼能看出服务是坏的，而不是被「running」骗过去。
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${INSTALL_DIR}
Environment=HOME=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/start.sh -addr ${LISTEN_ADDR} -proxy ${PROXY_ADDR}
# 装机代理：宿主环境页的「一键安装」和后台情报同步用。hostd 是独立进程，
# 不共享主服务环境，所以它自己的单元也要带（见下方 hostd 单元）。
${INSTALL_PROXY_ENV}
Restart=always
RestartSec=5
# 安全加固
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${INSTALL_DIR}
ProtectHome=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
RestrictNamespaces=true
RestrictRealtime=true
LockPersonality=true
# AF_PACKET/AF_NETLINK：masscan 与 nmap 的原始套接字要它们
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_PACKET AF_NETLINK
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
# 不是 root，但给足原始套接字能力：masscan / ping / AF_PACKET 直接用；nmap 按 euid 判断，
# 特权扫描需 --privileged（提示词里已写明）。CAP_NET_BIND_SERVICE 供 --listen 用低位端口。
# 注：加了能力就不该再加 NoNewPrivileges 之外的提权面；这三项是渗透扫描的最小集。
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable "$SERVICE" 2>/dev/null || true
  # 升级场景下服务可能已经在跑：enable --now 不会重启它，必须显式 restart
  # 才会用上新换的二进制。
  systemctl restart "$SERVICE"
  ok "systemd 服务已启动（${SERVICE}）"

  # 内置 MCP 服务器随包落地（FOFA 资产测绘），并把 uv 备好，预设开箱即用。
  if [ -d "$INSTALL_DIR/mcp-servers/fofa" ]; then
    ok "内置 MCP 服务器已安装（$INSTALL_DIR/mcp-servers/fofa）"
  fi
  ensure_uv

  if [ "$WITH_INSTALLER" = "1" ]; then install_hostd; fi
}

# ── 把代理写进运行期设置 ─────────────────────────
# 装机时代理只作用于脚本自身；Web「系统 → 宿主环境」页的「一键安装」和
# 后台的情报同步走的是数据库里的 install_proxy 设置。两者不联动的话，
# 用户装完机器后还得再手填一遍代理——正是用户说的「所有该走代理的就走代理」。
#
# 走数据库而不是 HTTP API：设置接口要 JWT，而管理员密码是用户首次访问
# 时自己设的，install.sh 拿不到。settings 表结构简单（key/value），
# 直接 UPSERT 最省事。
# ══════════════════════════════════════════════════
# 二进制部署 · macOS（launchd + Homebrew PostgreSQL）
# ══════════════════════════════════════════════════
# 与 Linux 版的差异（其余流程——下载/校验/解压/config.json/一键更新——完全复用）：
#   - 包管理器 apt/dnf → Homebrew；PostgreSQL 走 postgresql@16 formula，
#     superuser 就是当前用户（brew 不建 postgres 系统用户），psql 直连即可；
#   - 服务化 systemd → launchd：LaunchAgents plist 拉 start.sh（KeepAlive）。
#     start.sh 本身就是守护脚本（崩溃退避重拉 + 一键更新换装都在里面），
#     launchd 只负责「开机自启 + 意外退出拉起」，不重复实现守护逻辑；
#   - 不装 pojun-hostd（apt 体系工具安装不可用），不建系统用户；
#   - 全程当前用户，不需要 sudo（sudo 反而会破坏 brew/launchd 的一致性）。
deploy_binary_darwin(){
  # Homebrew：没有就装（官方安装器，需要交互确认一次密码给 /usr/local 写权限的
  # Intel 机器；Apple Silicon 装到 /opt/homebrew 不需要密码）
  if ! command -v brew >/dev/null 2>&1; then
    warn "未检测到 Homebrew，先安装它（可能要求输入密码/回车确认）..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"       || die "Homebrew 安装失败；也可手动安装后重跑本脚本"
    eval "$(/opt/homebrew/bin/brew shellenv 2>/dev/null || true)"
    eval "$(/usr/local/bin/brew shellenv 2>/dev/null || true)"
  fi
  command -v brew >/dev/null 2>&1 || die "brew 不可用（PATH 未包含？）"
  local BREW_PREFIX
  BREW_PREFIX="$(brew --prefix)"
  export PATH="$BREW_PREFIX/bin:$BREW_PREFIX/opt/postgresql@16/bin:$PATH"

  command -v unzip >/dev/null 2>&1 || brew install unzip >/dev/null 2>&1 || die "需要 unzip"

  # PostgreSQL 16（硬依赖）。按 formula 是否安装来判断，而不是 command -v psql：
  # 机器上可能有别的 psql（旧版 formula / 系统 CLI），会让我们误以为 @16 已就位。
  if ! brew list --formula 2>/dev/null | grep -q "^postgresql@16$"; then
    info "安装 PostgreSQL 16（brew，首次几分钟）..."
    brew install postgresql@16 || die "postgresql@16 安装失败"
  fi
  export PATH="$BREW_PREFIX/opt/postgresql@16/bin:$PATH"
  command -v psql >/dev/null 2>&1 || die "psql 不在 PATH（postgresql@16 是 keg-only，脚本已显式加 PATH，不应走到这）"
  if ! brew services list 2>/dev/null | grep -q "postgresql@16.*started"; then
    info "启动 PostgreSQL 服务（brew services = launchd）..."
    brew services start postgresql@16 || die "启动 PostgreSQL 失败"
  fi
  local i
  for i in $(seq 1 30); do pg_isready -q >/dev/null 2>&1 && break; sleep 2; done
  pg_isready -q >/dev/null 2>&1 || die "PostgreSQL 60s 内未就绪（brew services list 看状态）"
  ok "PostgreSQL 就绪"
  # psql 不带 -d 时默认连「与当前用户同名」的库（通常不存在）——显式钉到 postgres
  export PGDATABASE=postgres

  fetch_release
  local src="$TMP/unpack/pojun-${VERSION#v}-${PKG_ARCH}"
  [ -d "$src" ] || die "发行包结构异常: 找不到 $src"

  mkdir -p "$INSTALL_DIR"
  for b in pojun pojun-hostd pojun-maint; do
    [ -f "$src/$b" ] || continue
    cp "$src/$b" "$INSTALL_DIR/.$b.new"
    chmod +x "$INSTALL_DIR/.$b.new"
    mv -f "$INSTALL_DIR/.$b.new" "$INSTALL_DIR/$b"
  done
  local f base
  for f in "$src"/*; do
    base="$(basename "$f")"
    case "$base" in pojun|pojun-hostd|pojun-maint) continue ;; esac
    cp -r "$f" "$INSTALL_DIR/"
  done
  chmod +x "$INSTALL_DIR/start.sh"
  ok "程序就绪: $INSTALL_DIR/pojun"

  # config.json（仅首次；升级不覆盖）
  if [ ! -f "$INSTALL_DIR/config.json" ]; then
    local DB_PASS
    DB_PASS="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
    # brew 的 PostgreSQL superuser 就是当前用户，无需 sudo -u postgres
    if psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='pojun'" 2>/dev/null | grep -q 1; then
      info "数据库角色 pojun 已存在，同步密码"
      psql -c "ALTER ROLE pojun LOGIN PASSWORD '$DB_PASS'" >/dev/null
    else
      psql -c "CREATE ROLE pojun LOGIN PASSWORD '$DB_PASS'" >/dev/null
    fi
    psql -tAc "SELECT 1 FROM pg_database WHERE datname='pojun'" 2>/dev/null | grep -q 1       || createdb -O pojun pojun
    cat > "$INSTALL_DIR/config.json" <<JSON
{
  "database": {
    "host": "127.0.0.1",
    "port": 5432,
    "user": "pojun",
    "password": "$DB_PASS",
    "dbname": "pojun",
    "sslmode": "disable"
  }
}
JSON
    chmod 600 "$INSTALL_DIR/config.json"
    ok "数据库 pojun 就绪（密码已写入 config.json，权限 600）"
  else
    ok "沿用既有 config.json（升级不覆盖）"
  fi

  # launchd 用户级服务（开机自启 + KeepAlive 崩溃拉起）
  # 拆开声明：local 是命令，同一行 `local A=1 B=$A` 的 $A 在 A 赋值前展开，
  # set -u 下直接报 unbound variable
  local PLIST_LABEL="com.pojun"
  local PLIST_DIR="$HOME/Library/LaunchAgents"
  local PLIST="$PLIST_DIR/$PLIST_LABEL.plist"
  mkdir -p "$PLIST_DIR"
  cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$PLIST_LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>$INSTALL_DIR/start.sh</string>
  </array>
  <key>WorkingDirectory</key><string>$INSTALL_DIR</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$INSTALL_DIR/pojun.launchd.log</string>
  <key>StandardErrorPath</key><string>$INSTALL_DIR/pojun.launchd.log</string>
</dict>
</plist>
PLIST
  launchctl bootout "gui/$(id -u)/$PLIST_LABEL" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$PLIST" || die "launchd 注册失败（$PLIST）"
  ok "launchd 服务已注册（开机自启，崩溃自动拉起）"

  info "可选依赖（按需自装，不影响核心功能）："
  info "  brew install libreoffice --cask   # Word/证据渲染（装完 ln -sf "/Applications/LibreOffice.app/Contents/MacOS/soffice" "$BREW_PREFIX/bin/soffice"）"
  info "  brew install poppler imagemagick  # PDF/图片预览"
  info "  brew install nmap sqlmap nuclei ffuf ...  # 渗透工具按需装，缺失项在「宿主环境」页如实显示"
}

persist_install_proxy(){
  [ -n "$INSTALL_PROXY" ] || return 0
  [ -f "$INSTALL_DIR/config.json" ] || { warn "找不到 config.json，跳过写入运行期代理"; return 0; }
  command -v psql >/dev/null 2>&1 || { warn "没有 psql，跳过写入运行期代理"; return 0; }

  # 整个写入过程交给 Python 完成——不用 bash 变量在中间传递连接参数。
  #
  # 之前拆成两步（bash eval 读 config.json → 再传给 psql）踩了两个坑：
  #   1. `eval "$(python3 ... <<'HEREDOC' ... HEREDOC
  #      )"` 这种「heredoc 套在 $() 里」的写法，heredoc 体与命令替换的边界
  #      在 bash 里很难伺候——实测 eval 静默失败、db_pass 变空串，于是
  #      psql 连不上、整个写入失败而外层只看到「写入失败」。
  #   2. psql 的 `:'proxy'` 变量替换在 `-c` 参数里**不生效**（那是 -f 读文件
  #      或交互式会话才有的路径），会报 "syntax error at or near :"。
  # 现在：Python 读 config.json 取连接参数、拼好并转义 SQL、调用 psql。
  if python3 - "$INSTALL_DIR/config.json" "$INSTALL_PROXY" <<'PYEOF'
import json, os, subprocess, sys

cfg_path, proxy = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(cfg_path)).get("database", {}) or {}
except Exception:
    d = {}
host = str(d.get("host") or "127.0.0.1")
port = str(d.get("port") or 5432)
user = str(d.get("user") or "pojun")
dbname = str(d.get("dbname") or "pojun")
password = str(d.get("password") or "")

# SQL 字符串字面量转义:单引号翻倍。代理地址已过 URL 校验(仅 http/https/socks5
# 且必须带 host:port),不含控制字符。
lit = "'" + proxy.replace("'", "''") + "'"
sql = ("INSERT INTO settings(key, value) VALUES ('install_proxy', %s) "
       "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()" % lit)

env = dict(os.environ)
if password:
    env["PGPASSWORD"] = password
p = subprocess.run(
    ["psql", "-h", host, "-p", port, "-U", user, "-d", dbname,
     "-v", "ON_ERROR_STOP=1", "-c", sql],
    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
sys.exit(p.returncode)
PYEOF
  then
    ok "运行期装机代理已写入（宿主环境页的一键安装会沿用）"
  else
    warn "写入运行期装机代理失败，可在 Web「系统 → 宿主环境」页手动填一次"
  fi
}

# ── 特权安装助手 pojun-hostd ─────────────────────
# 主服务单元带 NoNewPrivileges + ProtectSystem=strict,进程无法提权、/usr 只读,
# 所以「一键安装」做不了——必须在外面用一个 root 助手。它只监听一个 Unix socket,
# 且只认 hosttools 里的白名单工具 id,不接受自由命令。
install_hostd(){
  if [ ! -f "$INSTALL_DIR/pojun-hostd" ]; then
    warn "发行包里没有 pojun-hostd（旧版本包），跳过；体检仍可用，一键安装不可用"
    return 0
  fi
  # 同上：目标可能是正在运行的助手，先落临时名再 rename 避免 ETXTBSY。
  install -m 0755 "$INSTALL_DIR/pojun-hostd" /usr/local/bin/.pojun-hostd.new
  mv -f /usr/local/bin/.pojun-hostd.new /usr/local/bin/pojun-hostd
  cat > "/etc/systemd/system/${SERVICE}-hostd.service" <<UNIT
[Unit]
Description=POJUN host tool installer (privileged helper)
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/pojun-hostd -socket /run/pojun/hostd.sock -socket-group ${RUN_USER}
${INSTALL_PROXY_ENV}
Restart=always
RestartSec=5
# /run/pojun 由 systemd 建好并随停止清理;socket 本身被助手下调成 0660 root:${RUN_USER}
RuntimeDirectory=pojun
RuntimeDirectoryMode=0755
# 助手要调 apt/dnf、写 /usr/local/bin,所以不能像主服务那样把根挂成只读。
#
# 这里**刻意不设 NoNewPrivileges**:实测它会连带把 CAP_SETUID/CAP_SETGID 从进程的
# 有效能力集里摘掉(CapEff 末位由 ff 变 7f),而 apt 下载时要降权到 _apt 用户,
# 于是必然报 "seteuid 42 failed - Operation not permitted",所有 apt 类工具都装不上。
# 助手的真实安全边界是「socket 权限 + 代码里的工具白名单」,不是这条开关。
#
# CapabilityBoundingSet 显式列出 apt/dpkg/维护脚本需要的项(顺带挡掉 CAP_SYS_ADMIN、
# CAP_SYS_PTRACE、CAP_NET_ADMIN 等安装用不到的)。若将来某个包的 postinst 需要更多,
# 按报错往里加即可。
PrivateTmp=true
ProtectHome=true
ProtectClock=true
ProtectHostname=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=true
# 刻意不设 SystemCallFilter：助手要以 root 调 apt/dpkg，而 dpkg 会执行包自带的任意
# 维护脚本，白名单永远赶不上它们的实际需要，一旦超纲就是 SIGSYS 硬杀——装到一半被
# 杀比安装报错更难排查。助手的真实安全边界是 socket 权限 + 代码里的工具白名单。
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_FSETID CAP_KILL CAP_SETGID CAP_SETUID CAP_SETPCAP CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SYS_CHROOT CAP_MKNOD CAP_AUDIT_WRITE CAP_SETFCAP
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable "${SERVICE}-hostd" 2>/dev/null || true
  # 同主服务：已在跑时要显式 restart 才会换成新装的二进制。
  systemctl restart "${SERVICE}-hostd"
  ok "安装助手已启动（${SERVICE}-hostd）→ socket /run/pojun/hostd.sock"
}

# ══════════════════════════════════════════════════
# Docker 部署
# ══════════════════════════════════════════════════
deploy_docker(){
  command -v docker >/dev/null 2>&1 || die "未检测到 docker（安装见 https://docs.docker.com/engine/install/）"
  docker compose version >/dev/null 2>&1 || die "未检测到 docker compose 插件（安装 docker-compose-plugin）"
  docker info >/dev/null 2>&1 || die "Docker 守护进程未运行（systemctl start docker）"
  command -v unzip >/dev/null 2>&1 || { apt-get install -y unzip >/dev/null 2>&1 || dnf install -y unzip >/dev/null 2>&1 || die "需要 unzip"; }

  # skills 要挂进容器：空目录挂载会覆盖镜像内置的 /app/skills，所以先从发行包取一份
  fetch_release
  local src="$TMP/unpack/pojun-${VERSION#v}-${PKG_ARCH}"
  mkdir -p "$INSTALL_DIR/data" "$INSTALL_DIR/skills"
  if [ ! -f "$INSTALL_DIR/skills/.keep" ] && [ -z "$(ls -A "$INSTALL_DIR/skills" 2>/dev/null)" ]; then
    [ -d "$src/skills" ] && cp -r "$src/skills/." "$INSTALL_DIR/skills/"
  fi
  touch "$INSTALL_DIR/skills/.keep"

  # .env（首次生成随机 PG 密码；升级不覆盖）
  if [ ! -f "$INSTALL_DIR/.env" ]; then
    local PG_PASS
    PG_PASS="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
    cat > "$INSTALL_DIR/.env" <<ENV
POSTGRES_USER=pojun
POSTGRES_PASSWORD=$PG_PASS
POSTGRES_DB=pojun
POJUN_IMAGE=$IMAGE
POJUN_TAG=$VERSION
POJUN_INSTALL_PROXY=$INSTALL_PROXY
ENV
    chmod 600 "$INSTALL_DIR/.env"
    ok "已生成 $INSTALL_DIR/.env（含随机数据库密码，权限 600）"
  else
    ok "沿用既有 .env（升级不覆盖）"
    # 但代理要跟着本次安装走：它不是"首次生成"的密钥，升级时也该同步，
    # 否则用户改了代理后重跑安装，旧 .env 里的旧代理还在生效。
    if [ -n "$INSTALL_PROXY" ]; then
      if grep -q '^POJUN_INSTALL_PROXY=' "$INSTALL_DIR/.env"; then
        sed -i "s|^POJUN_INSTALL_PROXY=.*|POJUN_INSTALL_PROXY=$INSTALL_PROXY|" "$INSTALL_DIR/.env"
      else
        printf 'POJUN_INSTALL_PROXY=%s\n' "$INSTALL_PROXY" >> "$INSTALL_DIR/.env"
      fi
      ok "已同步 .env 里的装机代理"
    fi
  fi

  local PORT="${LISTEN_ADDR##*:}" PROXY_PORT="${PROXY_ADDR##*:}"
  cat > "$INSTALL_DIR/docker-compose.yml" <<COMPOSE
# 由 install.sh 生成。数据在 ./data，skills 在 ./skills，数据库在卷 pgdata。
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: \${POSTGRES_USER:-pojun}
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD:?请在 .env 设置 POSTGRES_PASSWORD}
      POSTGRES_DB: \${POSTGRES_DB:-pojun}
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U \${POSTGRES_USER:-pojun} -d \${POSTGRES_DB:-pojun}"]
      interval: 5s
      timeout: 3s
      retries: 10
    restart: unless-stopped

  pojun:
    image: \${POJUN_IMAGE}:\${POJUN_TAG}
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      POJUN_PG_DSN: postgres://\${POSTGRES_USER:-pojun}:\${POSTGRES_PASSWORD}@postgres:5432/\${POSTGRES_DB:-pojun}?sslmode=disable
      ANTHROPIC_API_KEY: \${ANTHROPIC_API_KEY:-}
      OPENAI_API_KEY: \${OPENAI_API_KEY:-}
      POJUN_LLM_PROVIDER: \${POJUN_LLM_PROVIDER:-}
      POJUN_LLM_MODEL: \${POJUN_LLM_MODEL:-}
      POJUN_LLM_BASE_URL: \${POJUN_LLM_BASE_URL:-}
      POJUN_LLM_PROXY: \${POJUN_LLM_PROXY:-}
      # 装机代理：宿主环境页的「一键安装」和后台情报同步用。Docker 形态没有
      # config.json，只能走环境变量；服务端读它作为数据库 setting 的兜底。
      POJUN_INSTALL_PROXY: \${POJUN_INSTALL_PROXY:-}
    ports:
      - "${PORT}:8787"
      - "127.0.0.1:${PROXY_PORT}:8788"
      # 回连端口映射（按需放开）：容器内 MSF/listener 监听的端口要映射到宿主，
      # agent 才能收到 reverse shell。示例：
      # - "4444-4450:4444-4450"
    volumes:
      - ./data:/app/data
      - ./skills:/app/skills
    restart: unless-stopped

volumes:
  pgdata:
COMPOSE

  ok "已生成 $INSTALL_DIR/docker-compose.yml"
  info "拉取镜像 $IMAGE:$VERSION ..."
  ( cd "$INSTALL_DIR" && docker compose pull )
  ( cd "$INSTALL_DIR" && docker compose up -d )
  ok "容器已启动"
}

# ── --with-tools：宿主渗透工具 ───────────────────
install_tools(){
  if [ "$MODE" = "docker" ]; then
    warn "Docker 形态下工具固化在镜像里，不在运行时安装。"
    warn "需要更多工具时：基于官方镜像自建（见 README「Docker 部署」），或改用 --mode=binary。"
    return 0
  fi
  info "安装常用渗透工具（系统源内）..."
  local APT_PROXY=() DNF_PROXY=()
  if [ -n "$INSTALL_PROXY" ]; then
    APT_PROXY=(-o "Acquire::http::Proxy=$INSTALL_PROXY" -o "Acquire::https::Proxy=$INSTALL_PROXY")
    DNF_PROXY=(--setopt=proxy="$INSTALL_PROXY")
  fi
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get "${APT_PROXY[@]}" update -qq || warn "apt update 失败，继续尝试"
    # seclists 在 apt 源里没有稳定包名，单独克隆（见 install_wordlists）；
    # 其余一次装齐，缺的包不阻断整体（不同发行版源里包名有出入）。
    # imagemagick：报告证据拼图/文件名水印（v0.4.10 起依赖）；
    # libreoffice-writer/calc/impress + poppler-utils：文档证据转图片预览
    # （v0.4.21 起，Word/Excel/PPT→PDF→JPEG）。
    apt-get "${APT_PROXY[@]}" install -y nmap masscan sqlmap hydra whatweb nikto gobuster ffuf john \
      netcat-openbsd dnsutils whois unzip nodejs npm python3-impacket gitleaks imagemagick \
      libreoffice-writer libreoffice-calc libreoffice-impress poppler-utils \
      >/dev/null 2>&1 \
      || apt-get "${APT_PROXY[@]}" install -y nmap masscan sqlmap hydra whatweb nikto gobuster ffuf john \
           netcat-openbsd dnsutils whois unzip nodejs npm python3-impacket imagemagick \
           libreoffice-writer libreoffice-calc libreoffice-impress poppler-utils \
           >/dev/null \
      || warn "部分 apt 工具未装上"
  elif command -v dnf >/dev/null 2>&1; then
    dnf "${DNF_PROXY[@]}" install -y nmap masscan sqlmap hydra whatweb nikto john nmap-ncat bind-utils unzip \
      nodejs python3-impacket ImageMagick libreoffice-writer libreoffice-calc libreoffice-impress poppler-utils \
      || warn "dnf 部分包缺失，已装可用项"
  else
    warn "未识别的包管理器，跳过系统源工具安装"
  fi
  ok "系统源工具安装完成"

  # 非系统源工具（Go 系 / GitHub Release），装不上的在 Web「系统 → 宿主环境」页按需装
  install_github_tools
  install_wordlists
  install_pip_tools
  install_browser_mcp
  install_fonts
}

# ── 公文字体：报告 PDF 渲染 ────────────────────────
# docx 里字体已内嵌（odttf），Word/WPS 打开不需要系统字体；但 LibreOffice
# 转 PDF 时读系统字体，新机器不装会 fallback。从仓库 raw 拉三件套（ASCII
# 文件名，TTF 内部 family 名仍是仿宋_GB2312 等，docx 引用按内部名匹配）。
# 下载失败只告警——不影响 Word 导出。
install_fonts(){
  local dir="/usr/share/fonts/gongwen"
  mkdir -p "$dir" || { warn "无法创建 $dir，跳过公文字体"; return 0; }
  local base="https://raw.githubusercontent.com/${REPO}/main/report/fonts"
  local f
  for f in fangsong_gb2312.ttf kaiti_gb2312.ttf fzxiaobiaosong_gbk.ttf; do
    if [ ! -s "$dir/$f" ]; then
      "${CURL[@]}" -fsSL "$base/$f" -o "$dir/$f" >/dev/null 2>&1         || { rm -f "$dir/$f"; warn "  公文字体 $f 下载失败（仅影响本机 docx→PDF）"; }
    fi
  done
  command -v fc-cache >/dev/null 2>&1 && fc-cache -f "$dir" >/dev/null 2>&1 || true
  ok "公文字体就位（$dir）"
}

# ── GitHub Release 单文件工具 ───────────────────
# 表驱动：repo|资产名模板|二进制名。模板占位符 {ver}(不带v) {verv}(带v)
# {arch}(amd64/arm64) {arch2}(x86_64/aarch64) {arch3}(x86/arm) {arch4}(x64/arm64)。
#
# 各项目的资产命名差异很大（架构在前/后、版本带不带 v、扩展名 .zip/.tar.gz/.gz），
# 所以模板必须逐个按实测资产名写，不能指望一个通式。
#
# 不用 `go install`：宿主未必有 Go 工具链，而且 go install 每次都要下模块。
# 不用 apt 源：这些工具的 apt 包要么没有要么版本极旧。
install_github_tools(){
  local GOBIN_DIR="/usr/local/bin"
  local arch="amd64" arch2="x86_64" arch3="x86" arch4="x64" lin="x86_64"
  if [ "$ARCH" = "aarch64" ]; then
    arch="arm64"; arch2="aarch64"; arch3="arm"; arch4="arm64"; lin="arm64"
  fi

  # repo|资产模板|二进制名
  local specs="
projectdiscovery/nuclei|nuclei_{ver}_linux_{arch}.zip|nuclei
projectdiscovery/httpx|httpx_{ver}_linux_{arch}.zip|httpx
projectdiscovery/subfinder|subfinder_{ver}_linux_{arch}.zip|subfinder
projectdiscovery/naabu|naabu_{ver}_linux_{arch}.zip|naabu
projectdiscovery/dnsx|dnsx_{ver}_linux_{arch}.zip|dnsx
projectdiscovery/katana|katana_{ver}_linux_{arch}.zip|katana
projectdiscovery/tlsx|tlsx_{ver}_linux_{arch}.zip|tlsx
projectdiscovery/notify|notify_{ver}_linux_{arch}.zip|notify
projectdiscovery/interactsh|interactsh-client_{ver}_linux_{arch}.zip|interactsh-client
gitleaks/gitleaks|gitleaks_{ver}_linux_{arch4}.tar.gz|gitleaks
jpillora/chisel|chisel_{ver}_linux_{arch}.gz|chisel
OWASP/Amass|amass_linux_{arch}.tar.gz|amass
hahwul/dalfox|dalfox-{verv}-linux-{arch2}.tar.gz|dalfox
epi052/feroxbuster|{arch2}-linux-feroxbuster.tar.gz|feroxbuster
OJ/gobuster|gobuster_Linux_{lin}.tar.gz|gobuster
"
  local spec repo tmpl bin tag ver url asset file tmpd
  for spec in $specs; do
    repo="$(printf '%s' "$spec" | cut -d'|' -f1)"
    tmpl="$(printf '%s' "$spec" | cut -d'|' -f2)"
    bin="$(printf '%s' "$spec" | cut -d'|' -f3)"
    if command -v "$bin" >/dev/null 2>&1; then
      ok "  $bin 已存在"
      continue
    fi
    tag="$("${CURL[@]}" "https://api.github.com/repos/$repo/releases/latest" \
      | grep -oE '"tag_name": *"[^"]+"' | head -1 | cut -d'"' -f4)" || tag=""
    if [ -z "$tag" ]; then
      warn "  $bin 无法解析最新版本（GitHub API 受限，可加 --install-proxy）"
      continue
    fi
    ver="${tag#v}"
    asset="$tmpl"
    asset="${asset//\{ver\}/$ver}"
    asset="${asset//\{verv\}/$tag}"
    asset="${asset//\{arch\}/$arch}"
    asset="${asset//\{arch2\}/$arch2}"
    asset="${asset//\{arch3\}/$arch3}"
    asset="${asset//\{arch4\}/$arch4}"
    asset="${asset//\{lin\}/$lin}"
    url="https://github.com/$repo/releases/download/${tag}/${asset}"
    file="$TMP/$(basename "$asset")"
    tmpd="$TMP/ghtool"
    rm -rf "$tmpd"; mkdir -p "$tmpd"
    if ! "${CURL[@]}" "$url" -o "$file"; then
      warn "  $bin 下载失败（$url，可加 --install-proxy 走代理）"
      rm -rf "$file" "$tmpd"
      continue
    fi
    # 三种归档形态：.zip / .tar.gz / 单文件 .gz
    local extracted=""
    case "$asset" in
      *.zip)  unzip -oq "$file" -d "$tmpd" 2>/dev/null || true ;;
      *.tar.gz|*.tgz) tar -xzf "$file" -C "$tmpd" 2>/dev/null || true ;;
      *.gz)   gzip -dc "$file" > "$tmpd/$bin" 2>/dev/null || true ;;
    esac
    if [ -f "$tmpd/$bin" ]; then
      extracted="$tmpd/$bin"
    else
      # 归档里可能带一层目录，用 find 兜底
      local found
      found="$(find "$tmpd" -type f -name "$bin" 2>/dev/null | head -1)"
      [ -n "$found" ] && extracted="$found"
    fi
    if [ -n "$extracted" ] && [ -s "$extracted" ]; then
      mv "$extracted" "$GOBIN_DIR/$bin" && chmod +x "$GOBIN_DIR/$bin"
      ok "  $bin $tag → $GOBIN_DIR/$bin"
    else
      warn "  $bin 解压后找不到二进制（资产名可能变了：$url）"
    fi
    rm -rf "$file" "$tmpd"
  done
}

# SecLists：通用字典集(目录/参数/用户名爆破语料)。apt 源里没有稳定包名，
# 只能克隆。它有 2.5G，用 --depth 1 浅克隆。
install_wordlists(){
  local dir="/opt/SecLists"
  if [ -d "$dir" ] && [ -d "$dir/Discovery" ]; then
    ok "  SecLists 已存在 → $dir"
    return 0
  fi
  info "克隆 SecLists 字典集（浅克隆，约 2.5G）..."
  if command -v git >/dev/null 2>&1; then
    if git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$dir" >/dev/null 2>&1; then
      ok "  SecLists → $dir"
    else
      warn "  SecLists 克隆失败（可加 --install-proxy 走代理）"
    fi
  else
    warn "  未装 git，SecLists 跳过"
  fi
}

# uv：内置 MCP「FOFA 资产测绘」用它拉起 stdio server（相对路径 mcp-servers/fofa）。
#
# 关键点（真实踩坑）：pojun 服务是 systemd 用户，PATH 只保证
# /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin；pipx 以 root 安装
# 会把 uv 放到 /root/.local/bin（服务用户既无权穿越 /root 也不在 PATH）——必须
# 把二进制统一落到 /usr/local/bin，否则「预设能加、MCP 起不来」。best-effort：
# 装不上只提示，不影响主服务。
ensure_uv(){
  local cand=""
  for c in /usr/local/bin/uv /usr/bin/uv /root/.local/bin/uv "$HOME/.local/bin/uv"; do
    if [ -x "$c" ]; then cand="$c"; break; fi
  done
  if [ -z "$cand" ]; then
    if command -v pipx >/dev/null 2>&1; then
      pipx install --global uv >/dev/null 2>&1 || pipx install uv >/dev/null 2>&1 || true
    fi
    if [ -z "$cand" ] && command -v python3 >/dev/null 2>&1; then
      python3 -m pip install --break-system-packages -q uv >/dev/null 2>&1 || true
    fi
    for c in /usr/local/bin/uv /root/.local/bin/uv "$HOME/.local/bin/uv"; do
      if [ -x "$c" ]; then cand="$c"; break; fi
    done
  fi
  if [ -n "$cand" ] && [ "$cand" != "/usr/local/bin/uv" ]; then
    cp -f "$cand" /usr/local/bin/uv 2>/dev/null || true
    chmod 755 /usr/local/bin/uv 2>/dev/null || true
  fi
  if [ -x /usr/local/bin/uv ] && /usr/local/bin/uv --version >/dev/null 2>&1; then
    ok "uv 就绪（/usr/local/bin/uv，FOFA MCP 可用）"
  else
    warn "uv 未就绪：FOFA MCP 预设需要它（pip install uv 后复制到 /usr/local/bin）"
  fi
  return 0
}

# pip 工具：wafw00f(WAF 识别)、impacket 的部分脚本。
# 优先 pipx（隔离环境，不污染系统 Python，也不撞 PEP668 externally-managed），
# 没有 pipx 就退回 python3 -m pip --break-system-packages。
install_pip_tools(){
  command -v python3 >/dev/null 2>&1 || { warn "  没有 python3，pip 工具跳过"; return 0; }
  local PIPX=()
  if command -v pipx >/dev/null 2>&1; then
    PIPX=(pipx install)
  else
    PIPX=(python3 -m pip install --break-system-packages)
  fi
  local proxy_args=()
  [ -n "$INSTALL_PROXY" ] && proxy_args=(--proxy "$INSTALL_PROXY")
  # 包名|可执行文件名(空=该包不提供命令行)。已存在就跳过——
  # pipx 对已装的包会报错退出，不该当成"安装失败"。
  local specs="wafw00f|wafw00f
semgrep|semgrep
pwntools|pwntools
uv|uv"
  # netexec 不装：NetExec 2026 起商业化，PyPI 发行文件已撤下（装必失败）；
# 需要时从 GitHub 源码安装（hosttools netexec 条目有说明）。
  local spec pkg bin
  for spec in $specs; do
    pkg="$(printf '%s' "$spec" | cut -d'|' -f1)"
    bin="$(printf '%s' "$spec" | cut -d'|' -f2)"
    if [ -n "$bin" ] && command -v "$bin" >/dev/null 2>&1; then
      ok "  $bin 已存在"
      continue
    fi
    if "${PIPX[@]}" "${proxy_args[@]}" "$pkg" >/dev/null 2>&1; then
      ok "  $pkg ✓"
    else
      warn "  $pkg 安装失败"
    fi
  done
}

# Playwright MCP：browser MCP 用 `npx @playwright/mcp` 启动，需要 node+npx；
# 再预置 chromium 浏览器，否则首次启动还要联网下载。
#
# 浏览器装到 /opt/ms-playwright 而不是 ~/.cache/ms-playwright：
# 服务以 pojun 用户跑，root 家目录里的缓存它看不见。
install_browser_mcp(){
  command -v node >/dev/null 2>&1 || { warn "  没有 node，browser MCP 跳过"; return 0; }
  command -v npm >/dev/null 2>&1 || { warn "  没有 npm，browser MCP 跳过"; return 0; }

  # NPMENV 必须在两个分支外定义：set -u 下未定义变量会直接终止脚本。
  local NPMENV=()
  [ -n "$INSTALL_PROXY" ] && NPMENV=(HTTP_PROXY="$INSTALL_PROXY" HTTPS_PROXY="$INSTALL_PROXY")

  if ! npm ls -g @playwright/mcp >/dev/null 2>&1; then
    info "  安装 Playwright MCP（全局 npm）..."
    if env "${NPMENV[@]}" npm install -g @playwright/mcp@latest >/dev/null 2>&1; then
      ok "  @playwright/mcp ✓"
    else
      warn "  @playwright/mcp 安装失败"
    fi
  fi

  local BROWSER_DIR="/opt/ms-playwright"
  if [ -d "$BROWSER_DIR" ]; then
    ok "  chromium 已预置 → $BROWSER_DIR"
    return 0
  fi
  info "  预置 chromium 浏览器（首次约 150MB）..."
  if env "${NPMENV[@]}" PLAYWRIGHT_BROWSERS_PATH="$BROWSER_DIR" \
       npx --yes playwright@latest install --with-deps chromium >/dev/null 2>&1; then
    ok "  chromium → $BROWSER_DIR"
  else
    warn "  chromium 预置失败（首次启动 MCP 时仍可自动下载）"
  fi
}

# ── 执行部署 ─────────────────────────────────────
case "$MODE" in
  binary) deploy_binary ;;
  docker) deploy_docker ;;
  *) die "未知部署形态: $MODE" ;;
esac

if [ "$WITH_TOOLS" = "1" ]; then
  if [ "$IS_MAC" = "1" ]; then
    warn "--with-tools 在 macOS 不可用（工具安装器是 apt/dnf 体系）；请 brew install 按需装"
  else
    install_tools
  fi
fi

# 代理要落地到运行期设置，宿主环境页的「一键安装」才用同一个代理。
# 放在最后：此时服务已起、schema 已建。
persist_install_proxy

# ── 健康检查 ─────────────────────────────────────
PORT="${LISTEN_ADDR##*:}"
for _ in $(seq 1 30); do
  if curl -fsS -o /dev/null "http://127.0.0.1:${PORT}/api/health" 2>/dev/null; then
    HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
    ok "服务已就绪 → http://${HOST_IP:-127.0.0.1}:${PORT}（首次访问设置管理员密码）"
    info "下一步：①设置管理员密码 ②「LLM 配置」配通道 ③「系统→MCP」用预设接入 FOFA/Playwright ④建任务可套用内置 Playbook"
    if [ "$MODE" = "binary" ]; then
      if [ "$IS_MAC" = "1" ]; then
        tail -5 "$INSTALL_DIR/pojun.launchd.log" 2>/dev/null || true
        info "服务管理：launchctl kickstart -k gui/$(id -u)/com.pojun 重启 | launchctl bootout gui/$(id -u)/com.pojun 停止 | tail -f $INSTALL_DIR/pojun.launchd.log 看日志"
      else
        systemctl --no-pager status "$SERVICE" | head -5
      fi
    else
      ( cd "$INSTALL_DIR" && docker compose ps )
    fi
    exit 0
  fi
  sleep 2
done
if [ "$MODE" = "binary" ]; then
  if [ "$IS_MAC" = "1" ]; then
    warn "60s 内未就绪，查看日志: tail -n 50 $INSTALL_DIR/pojun.launchd.log"
  else
    warn "60s 内未就绪，查看日志: journalctl -u $SERVICE -n 50"
  fi
else
  warn "60s 内未就绪，查看日志: cd $INSTALL_DIR && docker compose logs --tail 50"
fi
exit 1
