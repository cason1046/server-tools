#!/usr/bin/env bash
###############################################################################
# setup-nginx.sh — 通用 nginx 网关检测 + 配置脚本（单层 TLS）
#
# 定位：
#   • 完全独立，不依赖任何项目代码，只负责系统 nginx 网关的检测与配置
#   • 单层 TLS：系统 nginx 终止 SSL，明文 HTTP 反代到 Docker nginx（更简洁高效，
#     不用维护两层证书）
#   • 非交互：所有输入靠命令行参数（交互由调用它的部署脚本负责）
#   • 既可直接执行，也可被部署脚本 `source` 后调用其中的函数
#
# 三种场景（自动检测 80/443 占用情况）：
#   场景1 干净服务器（80/443 空闲）  → 安装系统 nginx、删 default、启用 systemd
#                                       → 生成 site 配置 → MODE=gateway
#   场景2 系统 nginx 已在运行         → 不重装，仅生成 site → nginx -t && reload
#                                       → MODE=gateway
#   场景3 80/443 被 Docker 容器占用   → 不装、不生成 site → MODE=direct
#                                       → 提示去 Cloudflare 配 Origin Rules
#
# 两种用法：
#   1) 直接执行：
#      sudo bash setup-nginx.sh \
#        --instance-name trading \
#        --domains "cmstwn.com,cmstwnonline.com" \
#        --ssl-certs "/p/c1.pem:/p/k1.pem,/p/c2.pem:/p/k2.pem" \
#        --upstream-http-port 8080 \
#        --upstream-https-port 8443
#      # stdout 末行输出  MODE=gateway  或  MODE=direct
#
#   2) 被部署脚本 source：
#      curl -fsSL <url>/setup-nginx.sh -o /tmp/setup-nginx.sh
#      source /tmp/setup-nginx.sh
#      port=$(find_available_port 8080)
#      setup_nginx_main --instance-name ... （参数同上）
#      echo "$NGINX_MODE"      # gateway / direct
#
# 返回值约定：
#   • stdout 打印一行 "MODE=gateway" 或 "MODE=direct"
#   • 全局变量 NGINX_MODE 同步设置（供 source 方直接读取）
#   • 所有日志一律走 stderr，绝不污染 stdout 的 MODE 解析
#
# 备注：单层 TLS 下系统 nginx 只反代到 upstream 的 HTTP 端口；
#       --upstream-https-port 仅为接口兼容保留，本模式不使用。
#
# 可选参数（默认空 → 真正通用，不含任何项目专属硬编码）：
#   --csp-extra-domains "x.com,*.x.com"  CSP 额外放行域名（加进 script/style/img/
#                                        connect(含wss)/frame/font-src）；不传则 CSP 仅 'self'
#   --sse-paths "/api/sse/,/stream/"     为每个路径生成 proxy_buffering off + 长超时的
#                                        location；不传则不生成 SSE 块
###############################################################################

# ── 颜色 / 日志（全部 → stderr，避免污染 stdout 的 MODE 输出）──────────
_NG_RED='\033[0;31m'; _NG_GRN='\033[0;32m'; _NG_YLW='\033[1;33m'; _NG_CYN='\033[0;36m'; _NG_NC='\033[0m'
_ng_ok(){   echo -e "${_NG_GRN}✅ $*${_NG_NC}" >&2; }
_ng_info(){ echo -e "${_NG_CYN}ℹ️  $*${_NG_NC}" >&2; }
_ng_warn(){ echo -e "${_NG_YLW}⚠️  $*${_NG_NC}" >&2; }
_ng_err(){  echo -e "${_NG_RED}❌ $*${_NG_NC}" >&2; }

###############################################################################
# find_available_port <start_port>
#   用 ss -tlnp 检测端口占用，返回 >=start_port 的第一个空闲端口（仅打到 stdout）
#   供调用脚本使用。占用判断匹配本地地址列以 ":端口" 结尾的监听行
#   （兼容 0.0.0.0:8080 / 127.0.0.1:8080 / [::]:8080）。
###############################################################################
find_available_port(){
  local port="${1:-8080}"
  while [ "$port" -le 65535 ]; do
    if ! ss -tlnp 2>/dev/null | awk -v pat=":${port}\$" '$4 ~ pat {f=1} END{exit !f}'; then
      printf '%s\n' "$port"
      return 0
    fi
    port=$((port+1))
  done
  _ng_err "找不到可用端口（从 ${1:-8080} 到 65535 全部被占用）"
  return 1
}

# ── 内部：返回占用某端口的进程名（取第一条监听行的 users:(("名字"...)) ）──
_ng_port_owner(){
  local p="$1"
  ss -tlnp 2>/dev/null | awk -v pat=":${p}\$" '$4 ~ pat {print; exit}' \
    | sed -n 's/.*users:(("\([^"]*\)".*/\1/p'
}

###############################################################################
# detect_mode  → 打印 gateway-clean / gateway-running / direct
#   • 80 或 443 被 docker/containerd 占用            → direct
#   • 80 或 443 被系统 nginx 占用                     → gateway-running
#   • 80/443 都空闲                                   → gateway-clean
#   • 80/443 被其它非 nginx/docker 进程占用（如 apache）→ direct（无法做网关，
#     退化为让 Docker nginx 直接对外）
###############################################################################
detect_mode(){
  local o80 o443 both
  o80="$(_ng_port_owner 80)"
  o443="$(_ng_port_owner 443)"
  both="$o80 $o443"
  if echo "$both" | grep -qiE 'docker|containerd'; then
    echo "direct"; return
  fi
  if echo "$both" | grep -qi 'nginx'; then
    echo "gateway-running"; return
  fi
  if [ -z "$o80" ] && [ -z "$o443" ]; then
    echo "gateway-clean"; return
  fi
  _ng_warn "80/443 被非 nginx/docker 进程占用（80='${o80:-空}' 443='${o443:-空}'），退化为 direct" >&2
  echo "direct"
}

# ── 内部：安装系统 nginx（仅 apt 系），删 default site，启用 systemd ──────
_ng_install_nginx(){
  command -v apt-get >/dev/null 2>&1 || { _ng_err "仅支持 apt 系统自动安装 nginx，请手动安装后重试"; return 1; }
  export DEBIAN_FRONTEND=noninteractive
  if ! command -v nginx >/dev/null 2>&1; then
    _ng_info "apt 安装 nginx ..."
    apt-get update -y >/dev/null 2>&1 || _ng_warn "apt update 有警告（继续）"
    apt-get install -y nginx >/dev/null 2>&1 || { _ng_err "nginx 安装失败"; return 1; }
  else
    _ng_info "系统已存在 nginx 可执行文件，跳过安装"
  fi
  rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
  systemctl enable nginx >/dev/null 2>&1 || true
  _ng_ok "系统 nginx 已就绪（已删除 default site）"
}

# ── 内部：生成 site 配置（每个域名独立 server block + 独立证书）──────────
#    _ng_write_site <instance> <domains> <ssl-certs> <upstream-http-port>
_ng_write_site(){
  local instance="$1" domains="$2" certs="$3" up_http="$4" csp_extra="${5:-}" sse_paths="${6:-}"
  local conf="/etc/nginx/sites-available/${instance}.conf"
  mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled

  local _doms _certs
  IFS=',' read -ra _doms  <<< "$domains"
  IFS=',' read -ra _certs <<< "$certs"
  if [ "${#_doms[@]}" -ne "${#_certs[@]}" ]; then
    _ng_err "域名数(${#_doms[@]}) 与 证书对数(${#_certs[@]}) 不一致，必须一一配对"
    return 1
  fi

  # 所有域名共用一个 80→443 跳转块
  local all_names; all_names="$(echo "$domains" | tr ',' ' ' | tr -s ' ')"

  # CSP：base 只有 'self'；传了 --csp-extra-domains 才把这些域名加进各 src（含 connect 的 wss）
  local _csp_https="" _csp_wss="" _cd _cdarr
  if [ -n "$csp_extra" ]; then
    IFS=',' read -ra _cdarr <<< "$csp_extra"
    for _cd in "${_cdarr[@]}"; do
      _cd="$(echo "$_cd" | tr -d '[:space:]')"
      [ -z "$_cd" ] && continue
      _csp_https="${_csp_https} https://${_cd}"
      _csp_wss="${_csp_wss} wss://${_cd}"
    done
  fi
  local CSP="default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'${_csp_https}; style-src 'self' 'unsafe-inline'${_csp_https}; img-src 'self' data: blob:${_csp_https}; connect-src 'self'${_csp_https}${_csp_wss}; frame-src 'self'${_csp_https}; font-src 'self' data:${_csp_https};"

  {
    echo "# Generated by setup-nginx.sh — instance=${instance}"
    echo "# 单层 TLS：系统 nginx 终止 SSL → 明文反代 http://127.0.0.1:${up_http}（Docker nginx）"
    echo ""
    echo "# HTTP → HTTPS 跳转（所有域名共用）"
    echo "server {"
    echo "    listen 80;"
    echo "    listen [::]:80;"
    echo "    server_name ${all_names};"
    echo "    return 301 https://\$host\$request_uri;"
    echo "}"

    local i dom pair cert key
    for i in "${!_doms[@]}"; do
      dom="$(echo "${_doms[$i]}" | tr -d '[:space:]')"
      pair="$(echo "${_certs[$i]}" | tr -d '[:space:]')"
      cert="${pair%%:*}"
      key="${pair#*:}"
      [ -f "$cert" ] || _ng_warn "证书文件不存在：$cert（nginx -t 会失败）"
      [ -f "$key" ]  || _ng_warn "私钥文件不存在：$key（nginx -t 会失败）"
      echo ""
      echo "# 域名：${dom}"
      echo "server {"
      echo "    listen 443 ssl;"
      echo "    listen [::]:443 ssl;"
      echo "    http2 on;"
      echo "    server_name ${dom};"
      echo ""
      echo "    ssl_certificate     ${cert};"
      echo "    ssl_certificate_key ${key};"
      echo "    ssl_protocols TLSv1.2 TLSv1.3;"
      echo "    ssl_ciphers HIGH:!aNULL:!MD5;"
      echo ""
      echo "    server_tokens off;"
      echo "    client_max_body_size 10m;"
      echo ""
      echo "    # 安全响应头（系统 nginx 是公网边缘，安全头由它统一负责）"
      echo "    add_header X-Content-Type-Options \"nosniff\" always;"
      echo "    add_header X-Frame-Options \"SAMEORIGIN\" always;"
      echo "    add_header X-XSS-Protection \"1; mode=block\" always;"
      echo "    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;"
      echo "    add_header Content-Security-Policy \"${CSP}\" always;"
      # SSE：为每个 --sse-paths 路径生成关闭缓冲+长超时的 location（不传则不生成）
      if [ -n "$sse_paths" ]; then
        local _sp _sparr
        IFS=',' read -ra _sparr <<< "$sse_paths"
        for _sp in "${_sparr[@]}"; do
          _sp="$(echo "$_sp" | tr -d '[:space:]')"
          [ -z "$_sp" ] && continue
          echo ""
          echo "    # SSE：关闭缓冲 + 长超时（${_sp}）"
          echo "    location ${_sp} {"
          echo "        proxy_pass http://127.0.0.1:${up_http};"
          echo "        proxy_http_version 1.1;"
          echo "        proxy_set_header Host \$host;"
          echo "        proxy_set_header X-Real-IP \$http_cf_connecting_ip;"
          echo "        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;"
          echo "        proxy_set_header X-Forwarded-Proto \$scheme;"
          echo "        proxy_hide_header Content-Security-Policy;"
          echo "        proxy_buffering off;"
          echo "        proxy_cache off;"
          echo "        proxy_read_timeout 3600s;"
          echo "        proxy_send_timeout 3600s;"
          echo "        chunked_transfer_encoding off;"
          echo "    }"
        done
      fi
      echo ""
      echo "    location / {"
      echo "        proxy_pass http://127.0.0.1:${up_http};"
      echo "        proxy_set_header Host \$host;"
      echo "        proxy_set_header X-Real-IP \$http_cf_connecting_ip;"
      echo "        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;"
      echo "        proxy_set_header X-Forwarded-Proto \$scheme;"
      echo "        # 隐藏上游(Docker nginx)自带的 CSP，避免重复头；以本层为准"
      echo "        proxy_hide_header Content-Security-Policy;"
      echo "        proxy_buffering off;"
      echo "        proxy_read_timeout 3600s;"
      echo "    }"
      echo "}"
    done
  } > "$conf"
  _ng_ok "已生成 site 配置：$conf"
}

# ── 内部：软链到 sites-enabled，校验并 reload ───────────────────────────
_ng_enable_and_reload(){
  local instance="$1"
  ln -sf "/etc/nginx/sites-available/${instance}.conf" "/etc/nginx/sites-enabled/${instance}.conf"
  if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || true
    _ng_ok "nginx -t 通过，已 reload"
    return 0
  fi
  _ng_err "nginx -t 校验失败！配置详情如下："
  nginx -t >&2 2>&1 || true
  return 1
}

###############################################################################
# setup_nginx_main  — 主入口（解析参数 → 检测场景 → 配置 → 返回 MODE）
###############################################################################
setup_nginx_main(){
  local INSTANCE="" DOMAINS="" SSL_CERTS="" UP_HTTP="" UP_HTTPS="" CSP_EXTRA="" SSE_PATHS=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --instance-name)       INSTANCE="${2:-}"; shift 2;;
      --domains)             DOMAINS="${2:-}"; shift 2;;
      --ssl-certs)           SSL_CERTS="${2:-}"; shift 2;;
      --upstream-http-port)  UP_HTTP="${2:-}"; shift 2;;
      --upstream-https-port) UP_HTTPS="${2:-}"; shift 2;;   # 单层 TLS 下未使用，仅兼容
      --csp-extra-domains)   CSP_EXTRA="${2:-}"; shift 2;;  # CSP 额外放行域名，逗号分隔，默认空
      --sse-paths)           SSE_PATHS="${2:-}"; shift 2;;  # SSE 路径，逗号分隔，默认空（不生成）
      *) _ng_warn "忽略未知参数：$1"; shift;;
    esac
  done

  [ -n "$INSTANCE" ] || { _ng_err "缺少必填参数 --instance-name"; return 1; }
  [ -n "$UP_HTTP" ]  || { _ng_err "缺少必填参数 --upstream-http-port"; return 1; }

  local mode; mode="$(detect_mode)"
  _ng_info "场景检测结果：$mode"

  if [ "$mode" = "direct" ]; then
    NGINX_MODE="direct"
    _ng_warn "80/443 已被 Docker 或其它进程占用 → direct 模式"
    _ng_info "本机不安装系统 nginx，Docker nginx 将直接对外（0.0.0.0:分配端口，自带 SSL）"
    _ng_info "请到 Cloudflare → Rules → Origin Rules 配置：入站 443 → 源站 HTTPS 端口"
    echo "MODE=direct"
    return 0
  fi

  # 以下为 gateway 路径，需要 root + 域名 + 证书
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    _ng_err "gateway 模式需要 root（要安装 nginx / 写 /etc/nginx）。请用 sudo 运行"
    return 1
  fi
  [ -n "$DOMAINS" ]   || { _ng_err "gateway 模式需要 --domains"; return 1; }
  [ -n "$SSL_CERTS" ] || { _ng_err "gateway 模式需要 --ssl-certs"; return 1; }

  if [ "$mode" = "gateway-clean" ]; then
    _ng_info "80/443 空闲 → 安装系统 nginx 作为网关"
    _ng_install_nginx || return 1
  else
    _ng_info "系统 nginx 已在运行 → 不重装，仅生成 site 配置并 reload"
  fi

  _ng_write_site "$INSTANCE" "$DOMAINS" "$SSL_CERTS" "$UP_HTTP" "$CSP_EXTRA" "$SSE_PATHS" || return 1
  _ng_enable_and_reload "$INSTANCE" || return 1

  NGINX_MODE="gateway"
  _ng_ok "网关配置完成：系统 nginx 终止 SSL → 反代 http://127.0.0.1:${UP_HTTP}"
  echo "MODE=gateway"
  return 0
}

###############################################################################
# 仅在「直接执行」时自动跑 main；被 source 时只提供函数，不自动执行
###############################################################################
if [ "${BASH_SOURCE[0]:-$0}" = "${0}" ]; then
  set -uo pipefail
  setup_nginx_main "$@"
fi
