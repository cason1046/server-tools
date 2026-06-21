#!/usr/bin/env bash
###############################################################################
# harden.sh — 通用服务器安全加固 + 性能优化 + Telegram 通知（一键脚本）
#
# 特性：
#   • 完全独立，不依赖任何项目文件，可 scp 或 curl|bash 到任意 Ubuntu 18.04+
#   • 幂等可重复运行：检测已有配置 → 仅更新配置(保留数据) / 完全重装 / 退出
#   • 所有交互从 /dev/tty 读取，支持  curl -fsSL <url> | sudo bash
#   • Docker 友好：不破坏容器网络；集成 ufw-docker；Docker 日志轮转
#   • Cloudflare 友好：Web 端口仅放行 CF 回源 IP 段（每周自动刷新）
#
# 用法：  sudo bash harden.sh        或   curl -fsSL <url> | sudo bash
###############################################################################
set -uo pipefail   # 故意不加 -e：加固脚本应尽量跑完，关键步骤单独校验

CONF="/etc/server-hardening.conf"
STATE_DIR="/var/lib/server-harden"
CACHE_DIR="${STATE_DIR}/telegram_cache"
HISTORY_DIR="${CACHE_DIR}/history"
NOTIFY_BIN="/usr/local/bin/harden_tg_notify.sh"
SUMMARY_BIN="/usr/local/bin/harden_daily_summary.sh"
CFREFRESH_BIN="/usr/local/bin/refresh_cf_ips.sh"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'; NC='\033[0m'
ok(){   echo -e "${GRN}✅ $*${NC}"; }
info(){ echo -e "${CYN}ℹ️  $*${NC}"; }
warn(){ echo -e "${YLW}⚠️  $*${NC}"; }
err(){  echo -e "${RED}❌ $*${NC}" >&2; }
hr(){ echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; }

# ── 从 /dev/tty 读取（支持 curl|bash）──────────────────────────────
ask(){  # ask VARNAME "提示" "默认值"
  local __v="$1" __p="$2" __d="${3:-}" __in=""
  if [ -r /dev/tty ]; then
    if [ -n "$__d" ]; then printf "${CYN}%s [%s]: ${NC}" "$__p" "$__d" >/dev/tty
    else printf "${CYN}%s: ${NC}" "$__p" >/dev/tty; fi
    IFS= read -r __in </dev/tty || __in=""
  fi
  [ -z "$__in" ] && __in="$__d"
  printf -v "$__v" '%s' "$__in"
}
confirm(){  # confirm "提示" "默认y/n" → 返回0=yes
  local __ans=""; ask __ans "$1 (y/n)" "$2"
  [[ "${__ans,,}" =~ ^(y|yes)$ ]]
}

# ── 前置检查 ───────────────────────────────────────────────────────
[ "${EUID:-$(id -u)}" -eq 0 ] || { err "请用 root 运行：sudo bash $0"; exit 1; }
command -v apt-get >/dev/null 2>&1 || { err "本脚本仅支持 Ubuntu/Debian (apt)"; exit 1; }
export DEBIAN_FRONTEND=noninteractive

echo "======================================================================"
echo "   通用服务器加固 + 性能优化 + Telegram 通知  (harden.sh)"
echo "======================================================================"

###############################################################################
# 0. 幂等：检测已有配置，选择运行模式
###############################################################################
MODE="fresh"
if [ -f "$CONF" ]; then
  hr; echo "  检测到已有配置：$CONF"; hr
  # shellcheck disable=SC1090
  source "$CONF" 2>/dev/null || true
  echo "   SSH 端口: ${SSH_PORT:-?}   Web 端口: ${WEB_PORTS:-无}   时区: ${TIMEZONE:-?}"
  echo "   Telegram: $([ -n "${TELEGRAM_TOKEN:-}" ] && echo 已配置 || echo 未配置)"
  echo ""
  echo "   1) 仅更新配置（保留 fail2ban 统计/swap 等数据）【默认】"
  echo "   2) 完全重装（清空统计缓存，从零开始）"
  echo "   3) 退出"
  ans=""; ask ans "请选择" "1"
  case "$ans" in
    2) MODE="reinstall";;
    3) echo "已退出"; exit 0;;
    *) MODE="update";;
  esac
fi

###############################################################################
# 1. 交互输入
###############################################################################
hr; echo "  [1/7] 配置信息"; hr

# 自动探测 SSH 端口
DET_SSH="$(grep -E '^Port ' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)"
[ -z "$DET_SSH" ] && [ -n "${SSH_CONNECTION:-}" ] && DET_SSH="$(echo "$SSH_CONNECTION" | awk '{print $4}')"
[ -z "$DET_SSH" ] && DET_SSH="$(ss -tlnp 2>/dev/null | grep -i sshd | grep -oP ':\K[0-9]+' | head -1)"
[ -z "$DET_SSH" ] && DET_SSH="${SSH_PORT:-22}"

ask SSH_PORT       "SSH 端口"                         "$DET_SSH"
ask WEB_PORTS      "Web 端口列表(逗号分隔, 如 8080,8443; 留空=不放行)" "${WEB_PORTS:-}"
ask TIMEZONE       "时区(每日汇总时间基准)"           "${TIMEZONE:-Asia/Shanghai}"
ask TELEGRAM_TOKEN "Telegram Bot Token(留空=跳过通知)" "${TELEGRAM_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
if [ -n "$TELEGRAM_TOKEN" ]; then
  ask TELEGRAM_CHAT_ID "Telegram Chat ID" "${TELEGRAM_CHAT_ID:-}"
fi
DISABLE_PWD="n"
if confirm "是否禁用 SSH 密码登录(请确保已有公钥, 否则可能锁死)" "n"; then DISABLE_PWD="y"; fi

# 校验 SSH 端口
[[ "$SSH_PORT" =~ ^[0-9]+$ ]] && [ "$SSH_PORT" -ge 1 ] && [ "$SSH_PORT" -le 65535 ] || { err "SSH 端口非法"; exit 1; }
WEB_PORTS="$(echo "$WEB_PORTS" | tr -d '[:space:]')"
# 校验每个 Web 端口（非法端口会让 CF 放行规则静默失败）
if [ -n "$WEB_PORTS" ]; then
  IFS=',' read -ra _WP <<< "$WEB_PORTS"
  for _p in "${_WP[@]}"; do
    [[ "$_p" =~ ^[0-9]+$ ]] && [ "$_p" -ge 1 ] && [ "$_p" -le 65535 ] || { err "Web 端口非法：'$_p'（应为逗号分隔的数字，如 8080,8443）"; exit 1; }
  done
fi

echo ""; info "确认配置：SSH=$SSH_PORT  Web=[${WEB_PORTS:-无}]  TZ=$TIMEZONE  TG=$([ -n "$TELEGRAM_TOKEN" ] && echo 是 || echo 否)  禁密码=$DISABLE_PWD  模式=$MODE"
confirm "开始执行?" "y" || { echo "已取消"; exit 0; }

###############################################################################
# 2. 清理（reinstall 模式）+ 持久化配置
###############################################################################
if [ "$MODE" = "reinstall" ]; then
  info "完全重装：清理旧数据..."
  systemctl stop fail2ban 2>/dev/null || true
  rm -rf "$CACHE_DIR"
fi

mkdir -p "$STATE_DIR" "$CACHE_DIR" "$HISTORY_DIR"
chmod 750 "$STATE_DIR"
[ -f "${CACHE_DIR}/bans.json" ] || echo '{}' > "${CACHE_DIR}/bans.json"
[ -f "${CACHE_DIR}/ips.json" ]  || echo '{}' > "${CACHE_DIR}/ips.json"
chmod 600 "${CACHE_DIR}"/*.json 2>/dev/null || true

cat > "$CONF" <<EOF
# Generated by harden.sh
SSH_PORT="$SSH_PORT"
WEB_PORTS="$WEB_PORTS"
TIMEZONE="$TIMEZONE"
TELEGRAM_TOKEN="$TELEGRAM_TOKEN"
TELEGRAM_CHAT_ID="$TELEGRAM_CHAT_ID"
EOF
chmod 600 "$CONF"
ok "配置已写入 $CONF (600)"

# 主进程内的安全 Telegram 发送（token 藏在 -K 配置文件，ps aux 不可见）
tg_send(){
  [ -n "${TELEGRAM_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID:-}" ] || return 0
  local cfg; cfg="$(mktemp)"; chmod 600 "$cfg"
  printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "$TELEGRAM_TOKEN" > "$cfg"
  curl -s -K "$cfg" -d "chat_id=${TELEGRAM_CHAT_ID}" --data-urlencode "text=$1" >/dev/null 2>&1 || true
  rm -f "$cfg"
}

###############################################################################
# 3. 安装依赖
###############################################################################
hr; echo "  [2/7] 安装依赖"; hr
apt-get update -y || warn "apt update 有警告"
for p in curl jq fail2ban ufw rsyslog; do
  if dpkg -s "$p" >/dev/null 2>&1; then echo "   ✅ $p"; else
    info "安装 $p..."; apt-get install -y "$p" || warn "安装 $p 失败"
  fi
done

# 设置系统时区（让 systemd timer 的 00:00 与所选时区一致）
timedatectl set-timezone "$TIMEZONE" 2>/dev/null && ok "系统时区 → $TIMEZONE" || warn "时区设置失败(继续)"

###############################################################################
# 步骤 3：SSH 加固 + fail2ban (仅 sshd jail) + Telegram 通知脚本
###############################################################################
hr; echo "  [3/7] SSH 加固 + fail2ban + 通知"; hr

# SSH drop-in（兼容新版 Ubuntu）
# ⚠️ 用 00- 前缀：drop-in 按字典序加载，first-match 关键字「先出现者生效」，
#    必须排在 50-cloud-init.conf 之前，否则我们的 PasswordAuthentication 等会被云镜像默认值压住。
mkdir -p /etc/ssh/sshd_config.d
DROPIN="/etc/ssh/sshd_config.d/00-harden.conf"
{
  echo "# Generated by harden.sh"
  echo "Port $SSH_PORT"
  echo "PermitRootLogin prohibit-password"
  echo "MaxAuthTries 4"
  echo "LoginGraceTime 30"
  [ "$DISABLE_PWD" = "y" ] && echo "PasswordAuthentication no"
  [ "$DISABLE_PWD" = "y" ] && echo "KbdInteractiveAuthentication no"
} > "$DROPIN"
chmod 644 "$DROPIN"
# 确保主配置 include 了 drop-in 目录（老系统可能没有）
# ⚠️ 必须加在文件【开头】：sshd 对多数指令取「第一个」匹配值，
#    若主配置前面已有 Port/PasswordAuthentication 等，追加到末尾的 Include 不会生效。
if ! grep -qE '^\s*Include\s+/etc/ssh/sshd_config.d/' /etc/ssh/sshd_config 2>/dev/null; then
  tmpf="$(mktemp)"
  { echo "Include /etc/ssh/sshd_config.d/*.conf"; echo ""; cat /etc/ssh/sshd_config 2>/dev/null; } > "$tmpf"
  cat "$tmpf" > /etc/ssh/sshd_config   # 用 cat 覆盖以保留原文件权限/属主
  rm -f "$tmpf"
fi
# Port 是「累加」型指令（非首值生效）：主配置残留的 Port 会让 sshd 同时监听旧端口，
# 且与 drop-in 同值时可能重复绑定导致启动失败。注释掉主配置所有 Port 行，端口以 drop-in 为唯一来源。
sed -i -E 's/^([[:space:]]*Port[[:space:]]+[0-9]+.*)$/#\1  # disabled by harden.sh/' /etc/ssh/sshd_config 2>/dev/null || true
# 其他 drop-in（如 50-cloud-init.conf）里的 Port 同样会累加监听，一并注释（跳过自己的 00-harden.conf）
for _f in /etc/ssh/sshd_config.d/*.conf; do
  [ -f "$_f" ] || continue
  [ "$_f" = "$DROPIN" ] && continue
  sed -i -E 's/^([[:space:]]*Port[[:space:]]+[0-9]+.*)$/#\1  # disabled by harden.sh/' "$_f" 2>/dev/null || true
done
if sshd -t 2>/dev/null; then
  # 兼容 ssh / sshd 两种 unit 名
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || \
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
  ok "SSH 配置已应用 (drop-in: $DROPIN)"
else
  warn "sshd 配置校验失败，已保留 drop-in 但未重载，请手动检查"
fi

# SSH 端口监听验证 + 醒目警告（防止改端口后把自己锁死）
sleep 1
CUR_CONN_PORT="$(echo "${SSH_CONNECTION:-}" | awk '{print $4}')"
if ss -tlnp 2>/dev/null | grep -E 'LISTEN' | grep -qE "[:.]${SSH_PORT}([^0-9]|$)"; then
  ok "已确认 sshd 正在监听端口 ${SSH_PORT}"
else
  warn "未检测到 sshd 在端口 ${SSH_PORT} 监听！请勿断开当前会话，立即排查 sshd 状态。"
fi
if [ -n "$CUR_CONN_PORT" ] && [ "$CUR_CONN_PORT" != "$SSH_PORT" ]; then
  echo -e "${RED}"
  echo "════════════════════════════════════════════════════════════"
  echo "  ⚠️  SSH 端口已从 ${CUR_CONN_PORT} 改为 ${SSH_PORT}"
  echo "  请立刻【另开一个新终端】测试能否登录新端口："
  echo "        ssh -p ${SSH_PORT} <用户名>@<本机IP>"
  echo "  确认登录成功后，再关闭当前这个会话！"
  echo "  否则一旦新端口不通，你将被永久锁在服务器门外。"
  echo "════════════════════════════════════════════════════════════"
  echo -e "${NC}"
fi

# fail2ban telegram action（无 TG 也无害：notify 脚本自检后 no-op）
cat > /etc/fail2ban/action.d/telegram_notify.conf <<'ACTEOF'
[Definition]
actionstart =
actionstop =
actioncheck =
actionban   = /usr/local/bin/harden_tg_notify.sh <ip> <name> <bantime>
actionunban =
ACTEOF

# jail.local：仅 sshd，真实封禁(iptables-multiport) + 可选 telegram 通知
ACTION_BLOCK="action = %(action_)s"
if [ -n "$TELEGRAM_TOKEN" ]; then
  ACTION_BLOCK="action = %(action_)s
         telegram_notify"
fi
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
banaction = iptables-multiport
bantime   = 24h
findtime  = 10m
maxretry  = 5
usedns    = no
bantime.increment   = true
# 基础 bantime=24h，乘数封顶 maxtime(168h=7天)：24/48/96/168，去掉会超过上限的无效乘数
bantime.multipliers = 1 2 4 7
bantime.maxtime     = 168h
bantime.rndtime     = 5m
${ACTION_BLOCK}

[sshd]
enabled = true
port    = $SSH_PORT
filter  = sshd
backend = systemd
maxretry = 5
EOF
ok "fail2ban jail.local 已生成（封禁递增：24h→翻倍，上限 7 天）"

###############################################################################
# 步骤 3 (续)：Telegram 通知脚本 + 每日汇总（被 fail2ban / timer 调用）
###############################################################################
cat > "$NOTIFY_BIN" <<'NOTEOF'
#!/usr/bin/env bash
set -uo pipefail
IP="${1:-}"; JAIL="${2:-}"; BANTIME="${3:-0}"
DT="$(date '+%Y-%m-%d %H:%M:%S')"
[ -f /etc/server-hardening.conf ] || exit 0
# shellcheck disable=SC1090
source /etc/server-hardening.conf
[ -n "${TELEGRAM_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID:-}" ] || exit 0
[ -n "$IP" ] && [ "$BANTIME" != "0" ] || exit 0

CACHE_DIR="/var/lib/server-harden/telegram_cache"
IP_CACHE="${CACHE_DIR}/ips.json"
if [ "${TEST_MODE:-0}" = "1" ]; then BAN_CACHE="${CACHE_DIR}/bans_test.json"; else BAN_CACHE="${CACHE_DIR}/bans.json"; fi
mkdir -p "$CACHE_DIR"
[ -f "$IP_CACHE" ]  || echo '{}' > "$IP_CACHE"
[ -f "$BAN_CACHE" ] || echo '{}' > "$BAN_CACHE"

flag(){ local cc; cc="$(echo "${1:-}" | tr '[:lower:]' '[:upper:]')"
  [[ "$cc" =~ ^[A-Z]{2}$ ]] || { echo ""; return; }
  command -v python3 >/dev/null 2>&1 && python3 - "$cc" <<'PY' || echo ""
import sys; c=sys.argv[1]; sys.stdout.write(chr(0x1F1E6+ord(c[0])-65)+chr(0x1F1E6+ord(c[1])-65))
PY
}
LOC="$(jq -r --arg ip "$IP" '.[$ip].loc // empty' "$IP_CACHE" 2>/dev/null)"
if [ -z "$LOC" ]; then
  # ip-api.com：免费无需 key、无月度限制（免费版仅 http）
  GEO="$(curl -s --max-time 4 "http://ip-api.com/json/${IP}?fields=status,countryCode,country,city" || echo '{}')"
  CC="$(echo "$GEO" | jq -r '.countryCode // empty' 2>/dev/null)"
  COUNTRY="$(echo "$GEO" | jq -r '.country // empty' 2>/dev/null)"
  CITY="$(echo "$GEO" | jq -r '.city // empty' 2>/dev/null)"
  LOC="$(flag "$CC") ${COUNTRY:-${CC:-未知}} ${CITY:-}"
  tmp="$(mktemp)"; jq --arg ip "$IP" --arg l "$LOC" '. + {($ip):{loc:$l}}' "$IP_CACHE" > "$tmp" && mv "$tmp" "$IP_CACHE" || rm -f "$tmp"
fi
tmp="$(mktemp)"
jq --arg ip "$IP" --arg t "$DT" '(.[$ip] // {count:0,last:""}) as $e | . + {($ip): {count:($e.count+1), last:$t}}' "$BAN_CACHE" > "$tmp" && mv "$tmp" "$BAN_CACHE" || rm -f "$tmp"
COUNT="$(jq -r --arg ip "$IP" '.[$ip].count // 1' "$BAN_CACHE" 2>/dev/null)"
HOURS=$(( BANTIME / 3600 ))

MSG="🚨 安全警报：检测到攻击并已封禁
时间：${DT}
模块：${JAIL}
IP：${IP}
归属：${LOC}
封禁：${HOURS} 小时
累计封禁：${COUNT} 次"

cfg="$(mktemp)"; chmod 600 "$cfg"
printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "$TELEGRAM_TOKEN" > "$cfg"
curl -s -K "$cfg" -d "chat_id=${TELEGRAM_CHAT_ID}" --data-urlencode "text=${MSG}" >/dev/null 2>&1 || true
rm -f "$cfg"
exit 0
NOTEOF
chmod 755 "$NOTIFY_BIN"

cat > "$SUMMARY_BIN" <<'SUMEOF'
#!/usr/bin/env bash
set -uo pipefail
[ -f /etc/server-hardening.conf ] || exit 0
# shellcheck disable=SC1090
source /etc/server-hardening.conf
[ -n "${TELEGRAM_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID:-}" ] || exit 0
CACHE_DIR="/var/lib/server-harden/telegram_cache"
BAN_CACHE="${CACHE_DIR}/bans.json"; HISTORY_DIR="${CACHE_DIR}/history"
mkdir -p "$HISTORY_DIR"; [ -f "$BAN_CACHE" ] || echo '{}' > "$BAN_CACHE"
N="$(jq 'length' "$BAN_CACHE" 2>/dev/null || echo 0)"
if [ "$N" -gt 0 ]; then
  # 只取 Top 20：IP 太多会超过 Telegram 单条消息 4096 字符上限，导致静默发送失败
  REP="$(jq -r 'to_entries|sort_by(.value.count)|reverse|.[:20]|.[]|"  🔸 \(.key)  封禁\(.value.count)次  末次\(.value.last)"' "$BAN_CACHE" 2>/dev/null)"
  MSG="📝 每日安全汇总
今日被封 IP 共 ${N} 个（Top 20）：
${REP}

💡 数据每日 00:00 重置"
else
  MSG="✅ 每日安全汇总
🎉 今日无恶意攻击记录，服务器运行良好。"
fi
cfg="$(mktemp)"; chmod 600 "$cfg"
printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "$TELEGRAM_TOKEN" > "$cfg"
curl -s -K "$cfg" -d "chat_id=${TELEGRAM_CHAT_ID}" --data-urlencode "text=${MSG}" >/dev/null 2>&1 || true
rm -f "$cfg"
# 归档 + 保留7天 + 重置
if [ "$N" -gt 0 ]; then cp "$BAN_CACHE" "${HISTORY_DIR}/$(date +%F).json" 2>/dev/null || true; fi
find "$HISTORY_DIR" -name '*.json' -mtime +7 -delete 2>/dev/null || true
echo '{}' > "$BAN_CACHE"
exit 0
SUMEOF
chmod 755 "$SUMMARY_BIN"

cat > /etc/systemd/system/harden-daily-summary.service <<SVC
[Unit]
Description=Daily security summary (harden.sh)
[Service]
Type=oneshot
Environment=TZ=$TIMEZONE
ExecStart=$SUMMARY_BIN
SVC
cat > /etc/systemd/system/harden-daily-summary.timer <<'TMR'
[Unit]
Description=Daily timer for security summary (00:00 local)
[Timer]
OnCalendar=*-*-* 00:00:00
Persistent=true
[Install]
WantedBy=timers.target
TMR
systemctl daemon-reload
systemctl enable --now harden-daily-summary.timer >/dev/null 2>&1 || true
ok "Telegram 通知脚本 + 每日汇总 timer 就绪"

# 启动/重载 fail2ban
if systemctl is-active --quiet fail2ban; then systemctl restart fail2ban || true
else systemctl enable --now fail2ban || true; fi

###############################################################################
# 步骤 4：防火墙 UFW + ufw-docker + Cloudflare 回源 IP
###############################################################################
hr; echo "  [4/7] 防火墙 (UFW + ufw-docker + Cloudflare)"; hr

ufw default deny incoming  >/dev/null 2>&1 || true
ufw default allow outgoing >/dev/null 2>&1 || true
# 清理旧的 ssh-harden 规则（防止改过 SSH 端口后，旧端口的放行规则永久残留）
# [^0-9] 防止 22 误匹配 2222 等长端口；已建立的连接走 conntrack 不受删规则影响
while :; do
  _num="$(ufw status numbered 2>/dev/null | grep 'ssh-harden' | grep -vE "[^0-9]${SSH_PORT}/tcp" | head -1 | sed -E 's/^\[[ ]*([0-9]+).*/\1/')"
  [ -n "$_num" ] || break
  yes | ufw delete "$_num" >/dev/null 2>&1 || break
done
# SSH 对所有来源放行（防锁死；不做 CF 限制）
ufw allow "${SSH_PORT}/tcp" comment 'ssh-harden' >/dev/null 2>&1 || true
ok "已放行 SSH 端口 $SSH_PORT"

# 安装 ufw-docker（让 Docker 发布端口受 ufw route 管控，修复绕过问题）
if [ ! -x /usr/local/bin/ufw-docker ]; then
  info "安装 ufw-docker..."
  if curl -fsSL https://github.com/chaifeng/ufw-docker/raw/master/ufw-docker -o /usr/local/bin/ufw-docker; then
    chmod +x /usr/local/bin/ufw-docker
  elif command -v docker >/dev/null 2>&1; then
    err "ufw-docker 下载失败且本机有 Docker：容器发布的端口会绕过 UFW 直接暴露公网，「仅 CF 可访问」不生效！请手动下载 ufw-docker 后重跑本脚本"
  else
    warn "ufw-docker 下载失败（本机无 Docker 可忽略；Web 端口将走普通 ufw 规则）"
  fi
fi
if [ -x /usr/local/bin/ufw-docker ]; then
  /usr/local/bin/ufw-docker install >/dev/null 2>&1 && ok "ufw-docker 已集成到 after.rules" || warn "ufw-docker install 警告(继续)"
fi

ufw --force enable >/dev/null 2>&1 || true
ufw reload >/dev/null 2>&1 || true

# CF IP 刷新脚本（主流程与每周 timer 共用同一逻辑）
cat > "$CFREFRESH_BIN" <<'CFEOF'
#!/usr/bin/env bash
set -uo pipefail
[ -f /etc/server-hardening.conf ] || exit 0
# shellcheck disable=SC1090
source /etc/server-hardening.conf
[ -n "${WEB_PORTS:-}" ] || exit 0
DIR="/var/lib/server-harden"; mkdir -p "$DIR"
v4="$(curl -fsSL --max-time 10 https://www.cloudflare.com/ips-v4)"; [ -n "$v4" ] && printf '%s\n' "$v4" > "$DIR/cf-ips-v4"
v6="$(curl -fsSL --max-time 10 https://www.cloudflare.com/ips-v6)"; [ -n "$v6" ] && printf '%s\n' "$v6" > "$DIR/cf-ips-v6"
v4="$(cat "$DIR/cf-ips-v4" 2>/dev/null)"; v6="$(cat "$DIR/cf-ips-v6" 2>/dev/null)"
[ -n "$v4$v6" ] || { echo "无法获取 CF IP，且无缓存，跳过"; exit 0; }
# 删除旧的 cf-harden 规则（按编号倒序逐条删，规避重编号）
while :; do
  num="$(ufw status numbered 2>/dev/null | grep 'cf-harden' | head -1 | sed -E 's/^\[[ ]*([0-9]+).*/\1/')"
  [ -n "$num" ] || break
  yes | ufw delete "$num" >/dev/null 2>&1 || break
done
# 按 Web 端口逐段放行：
#   ufw route allow → 容器端口（经 ufw-docker 管控的 FORWARD 链）
#   ufw allow       → 宿主机直跑的服务（INPUT 链）；route 规则对它不生效
# 两种都加，Docker / 非 Docker 场景都能正确"仅 CF 可访问"
IFS=',' read -ra PORTS <<< "$WEB_PORTS"
for port in "${PORTS[@]}"; do
  port="$(echo "$port" | tr -d '[:space:]')"; [ -n "$port" ] || continue
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    ufw route allow proto tcp from "$c" to any port "$port" comment 'cf-harden' >/dev/null 2>&1
    ufw allow proto tcp from "$c" to any port "$port" comment 'cf-harden' >/dev/null 2>&1
  done <<< "$v4"
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    ufw route allow proto tcp from "$c" to any port "$port" comment 'cf-harden' >/dev/null 2>&1
    ufw allow proto tcp from "$c" to any port "$port" comment 'cf-harden' >/dev/null 2>&1
  done <<< "$v6"
done
ufw reload >/dev/null 2>&1 || true
echo "Cloudflare 回源 IP 规则已刷新（Web 端口: $WEB_PORTS）"
CFEOF
chmod 755 "$CFREFRESH_BIN"

if [ -n "$WEB_PORTS" ]; then
  info "放行 Web 端口给 Cloudflare 回源 IP 段..."
  "$CFREFRESH_BIN" && ok "Web 端口 [$WEB_PORTS] 仅对 Cloudflare 开放" || warn "CF 规则应用有问题"
  # 每周自动刷新 CF IP 段
  cat > /etc/systemd/system/harden-cf-refresh.service <<SVC
[Unit]
Description=Refresh Cloudflare origin IP allowlist (harden.sh)
After=network-online.target
[Service]
Type=oneshot
ExecStart=$CFREFRESH_BIN
SVC
  cat > /etc/systemd/system/harden-cf-refresh.timer <<'TMR'
[Unit]
Description=Weekly Cloudflare IP refresh
[Timer]
OnCalendar=weekly
Persistent=true
[Install]
WantedBy=timers.target
TMR
  systemctl daemon-reload
  systemctl enable --now harden-cf-refresh.timer >/dev/null 2>&1 || true
  ok "已启用每周 CF IP 自动刷新 timer"
else
  warn "未配置 Web 端口，跳过 Cloudflare 放行"
fi

###############################################################################
# 步骤 5：性能优化（按内存/CPU 自动分档）
###############################################################################
hr; echo "  [5/7] 性能优化 (按内存/CPU 自动分档)"; hr

# ── 探测硬件并选择档位 ─────────────────────────────────────────
MEM_MB="$(free -m | awk '/^Mem:/{print $2}')"; MEM_MB="${MEM_MB:-1024}"
CORES="$(nproc 2>/dev/null || echo 1)"
if   [ "$MEM_MB" -lt 2048 ]; then
  TIER="小型(<2G)";  SOMAXCONN=1024;  FILEMAX=262144;  BUF=4194304;  SYNBL=2048; NETDEV=4096;  SWAPPINESS=30; SWAP_GB=2; DLOG="10m"; DFILE=3
elif [ "$MEM_MB" -lt 8192 ]; then
  TIER="中型(2-8G)"; SOMAXCONN=8192;  FILEMAX=1048576; BUF=8388608;  SYNBL=4096; NETDEV=8192;  SWAPPINESS=10; SWAP_GB=0; DLOG="20m"; DFILE=3
else
  TIER="大型(≥8G)";  SOMAXCONN=65535; FILEMAX=2097152; BUF=16777216; SYNBL=8192; NETDEV=16384; SWAPPINESS=10; SWAP_GB=0; DLOG="50m"; DFILE=5
fi
# CPU 加权：核心多则放大网络队列/句柄上限
[ "$CORES" -ge 4 ] && NETDEV=$((NETDEV*2))
[ "$CORES" -ge 8 ] && { FILEMAX=$((FILEMAX*2)); SYNBL=$((SYNBL*2)); }
NOFILE=$(( FILEMAX/2 )); [ "$NOFILE" -gt 1048576 ] && NOFILE=1048576
info "检测到 内存 ${MEM_MB}MB / CPU ${CORES} 核 → 选用档位：${TIER}"

# (1) BBR + sysctl（参数随档位动态生成）
modprobe tcp_bbr 2>/dev/null || true
echo "tcp_bbr" > /etc/modules-load.d/bbr.conf
cat > /etc/sysctl.d/99-harden.conf <<SYSCTL
# Generated by harden.sh — tier=${TIER} RAM=${MEM_MB}MB CPU=${CORES}
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.somaxconn = ${SOMAXCONN}
net.ipv4.tcp_max_syn_backlog = ${SYNBL}
net.core.netdev_max_backlog = ${NETDEV}
net.ipv4.tcp_fastopen = 3
net.core.rmem_max = ${BUF}
net.core.wmem_max = ${BUF}
net.ipv4.tcp_rmem = 4096 87380 ${BUF}
net.ipv4.tcp_wmem = 4096 65536 ${BUF}
net.ipv4.tcp_tw_reuse = 1
vm.swappiness = ${SWAPPINESS}
fs.file-max = ${FILEMAX}
SYSCTL
sysctl --system >/dev/null 2>&1 || true
CC="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
[ "$CC" = "bbr" ] && ok "BBR 已启用" || warn "BBR 未生效(当前: ${CC:-?}，可能需新内核)"

# (2) 文件句柄上限（随档位）
cat > /etc/security/limits.d/99-nofile.conf <<LIM
* soft nofile ${NOFILE}
* hard nofile ${NOFILE}
root soft nofile ${NOFILE}
root hard nofile ${NOFILE}
LIM
mkdir -p /etc/systemd/system.conf.d
cat > /etc/systemd/system.conf.d/99-nofile.conf <<LIM2
[Manager]
DefaultLimitNOFILE=${NOFILE}
LIM2
ok "文件句柄上限已设为 ${NOFILE}"

# (3) 按需 Swap（仅小型档位创建，大小随档位）
if [ "$SWAP_GB" -gt 0 ] && ! swapon --show 2>/dev/null | grep -q . && [ ! -e /swapfile ]; then
  info "档位 ${TIER}：内存 ${MEM_MB}MB 且无 swap，创建 ${SWAP_GB}G swapfile..."
  fallocate -l "${SWAP_GB}G" /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=$((SWAP_GB*1024)) status=none
  chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile && \
  { grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab; } && ok "${SWAP_GB}G swap 已创建" || warn "swap 创建失败"
elif swapon --show 2>/dev/null | grep -q . || [ -e /swapfile ]; then
  info "已有 swap，跳过"
else
  info "档位 ${TIER}：内存充足，无需 swap"
fi

# (4) unattended-upgrades 自动安全更新
apt-get install -y unattended-upgrades >/dev/null 2>&1 || warn "安装 unattended-upgrades 失败"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'AUU'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
AUU
systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
ok "自动安全更新已启用"

# (5) Docker 日志轮转（交互确认后才重启 Docker）
if command -v docker >/dev/null 2>&1 || [ -d /etc/docker ]; then
  mkdir -p /etc/docker
  if [ -f /etc/docker/daemon.json ]; then
    tmp="$(mktemp)"
    if jq --arg ms "$DLOG" --arg mf "$DFILE" '. + {"log-driver":"json-file","log-opts":{"max-size":$ms,"max-file":$mf}}' /etc/docker/daemon.json > "$tmp" 2>/dev/null; then
      mv "$tmp" /etc/docker/daemon.json
    else rm -f "$tmp"; warn "daemon.json 非合法 JSON，未修改"; fi
  else
    cat > /etc/docker/daemon.json <<DJ
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "${DLOG}", "max-file": "${DFILE}" }
}
DJ
  fi
  ok "Docker 日志轮转配置已写入 (max-size ${DLOG}, max-file ${DFILE})"
  if systemctl is-active --quiet docker; then
    warn "该配置需重启 Docker 生效，会瞬断所有容器几秒"
    if confirm "现在重启 Docker?" "n"; then
      systemctl restart docker && ok "Docker 已重启" || warn "Docker 重启失败"
    else
      warn "稍后请手动执行：systemctl restart docker"
    fi
  fi
else
  info "未检测到 Docker，跳过日志轮转（安装 Docker 后重跑本脚本即可）"
fi

###############################################################################
# 步骤 6：日志轮转
###############################################################################
hr; echo "  [6/7] 日志轮转"; hr
cat > /etc/logrotate.d/fail2ban <<'LOGROT'
/var/log/fail2ban.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    missingok
    create 640 root adm
    postrotate
        systemctl reload fail2ban > /dev/null 2>&1 || true
    endscript
}
LOGROT
ok "fail2ban 日志轮转已配置（保留 7 天）"

###############################################################################
# 步骤 7：验证 + 可选模拟攻击测试
###############################################################################
hr; echo "  [7/7] 验证"; hr
PASS=0; FAIL=0
chk(){ if eval "$2" >/dev/null 2>&1; then ok "$1"; PASS=$((PASS+1)); else warn "$1 —— 未通过"; FAIL=$((FAIL+1)); fi; }
chk "fail2ban 运行中"        "systemctl is-active --quiet fail2ban"
chk "sshd jail 已启用"       "fail2ban-client status sshd"
chk "UFW 已启用"             "ufw status | grep -q 'Status: active'"
chk "SSH 端口已放行"         "ufw status | grep -q '${SSH_PORT}/tcp'"
chk "BBR 已生效"             "[ \"\$(sysctl -n net.ipv4.tcp_congestion_control)\" = bbr ]"
chk "每日汇总 timer"         "systemctl is-active --quiet harden-daily-summary.timer"
[ -n "$WEB_PORTS" ] && chk "CF 刷新 timer"  "systemctl is-active --quiet harden-cf-refresh.timer"
[ -f /etc/docker/daemon.json ] && chk "Docker 日志轮转配置" "grep -q max-size /etc/docker/daemon.json"

if [ -n "$TELEGRAM_TOKEN" ]; then
  if confirm "发送一条模拟攻击测试通知到 Telegram?" "y"; then
    TEST_MODE=1 "$NOTIFY_BIN" "203.0.113.50" "sshd" "86400" || true
    rm -f "${CACHE_DIR}/bans_test.json"
    ok "已发送测试通知，请在 Telegram 查看"
  fi
fi

###############################################################################
# 完成
###############################################################################
echo ""; echo "======================================================================"
ok "服务器加固完成！通过 $PASS 项$([ $FAIL -gt 0 ] && echo "，$FAIL 项需关注")"
echo "======================================================================"
cat <<EOF

  模式      : $MODE
  SSH 端口  : $SSH_PORT  $([ "$DISABLE_PWD" = y ] && echo "(已禁用密码登录)")
  Web 端口  : ${WEB_PORTS:-无}  $([ -n "$WEB_PORTS" ] && echo "(仅 Cloudflare 回源 IP 可访问)")
  时区      : $TIMEZONE
  配置文件  : $CONF
  统计缓存  : $CACHE_DIR

  性能档位  : ${TIER}   (探测到 内存 ${MEM_MB}MB / CPU ${CORES} 核)
    somaxconn=${SOMAXCONN}  file-max=${FILEMAX}  nofile=${NOFILE}
    tcp缓冲=${BUF}  syn_backlog=${SYNBL}  netdev_backlog=${NETDEV}
    swap=$([ "$SWAP_GB" -gt 0 ] && echo "${SWAP_GB}G" || echo "无")  Docker日志=${DLOG}×${DFILE}

  常用命令：
    fail2ban-client status sshd      # 查看 SSH 封禁
    ufw status numbered              # 查看防火墙规则
    sysctl net.ipv4.tcp_congestion_control   # 确认 BBR
    systemctl list-timers | grep harden      # 查看定时任务

  ⚠️ 重要：
    • 本脚本可重复运行（幂等）：再次运行可「仅更新配置」或「完全重装」。
    • Web 端口只对 Cloudflare 开放，直连 IP:端口 会被拒绝，请走域名。
    • 数据库等敏感端口请勿用 ufw 放行；deploy-new.sh 已将其绑定到 127.0.0.1。
$([ "$DISABLE_PWD" = y ] && echo "    • 已禁用 SSH 密码登录，务必确认公钥可用！")
EOF

tg_send "🛡️ 服务器加固完成
主机：$(hostname)
时间：$(date '+%Y-%m-%d %H:%M:%S')
SSH：${SSH_PORT}  Web：${WEB_PORTS:-无}(仅CF)
验证通过：${PASS} 项$([ $FAIL -gt 0 ] && echo "  需关注：${FAIL} 项")"

exit 0
