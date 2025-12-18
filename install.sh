#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="k2775739"
REPO_NAME="dnsunlock"
REPO_BRANCH="main"
REPO_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}.git"
TARBALL_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/${REPO_BRANCH}.tar.gz"

INSTALL_DIR="/opt/dnsunlock"
SERVICE_NAME="dnsunlock"
SYSTEMD_UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

log() { printf "[dnsunlock] %s\n" "$*"; }
warn() { printf "[dnsunlock] WARN: %s\n" "$*" >&2; }
die() { printf "[dnsunlock] ERROR: %s\n" "$*" >&2; exit 1; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "请使用 root 运行（例如：curl -fsSL https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_BRANCH}/install.sh | sudo bash）"
  fi
}

require_systemd() {
  if ! have_cmd systemctl; then
    die "未检测到 systemd（缺少 systemctl），无法配置开机自启。"
  fi
  if ! systemctl is-system-running >/dev/null 2>&1; then
    die "systemd 当前不可用（常见于容器/WSL），无法配置开机自启。"
  fi
}

prompt_yn() {
  local prompt="$1"
  local default="${2:-y}"
  local answer=""
  local hint="[y/N]"
  if [[ "$default" == "y" ]]; then hint="[Y/n]"; fi
  local input="/dev/stdin"
  if [[ ! -t 0 && -r /dev/tty ]]; then
    input="/dev/tty"
  fi

  while true; do
    if ! read -r -p "${prompt} ${hint} " answer <"$input"; then
      answer=""
    fi
    answer="$(echo "${answer:-}" | tr '[:upper:]' '[:lower:]' | xargs || true)"
    if [[ -z "$answer" ]]; then
      answer="$default"
    fi
    case "$answer" in
      y|yes) echo "y"; return 0 ;;
      n|no) echo "n"; return 0 ;;
      *) printf "请输入 y 或 n\n" ;;
    esac
  done
}

backup_path() {
  local src="$1"
  local ts
  ts="$(date +%Y%m%d%H%M%S)"
  echo "${src}.bak.${ts}"
}

ensure_user() {
  if id -u dnsunlock >/dev/null 2>&1; then
    return 0
  fi

  if have_cmd useradd; then
    useradd --system --no-create-home --shell /usr/sbin/nologin dnsunlock
    return 0
  fi

  if have_cmd adduser; then
    adduser --system --no-create-home --disabled-login --gecos "" dnsunlock
    return 0
  fi

  die "缺少 useradd/adduser，无法创建运行用户 dnsunlock。"
}

fetch_repo() {
  if [[ -e "$INSTALL_DIR" ]]; then
    local bak
    bak="$(backup_path "$INSTALL_DIR")"
    log "检测到已存在目录：$INSTALL_DIR"
    log "自动备份到：$bak"
    mv "$INSTALL_DIR" "$bak"
  fi

  mkdir -p "$(dirname "$INSTALL_DIR")"

  if have_cmd git; then
    log "使用 git 拉取代码：$REPO_URL"
    git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$INSTALL_DIR"
    return 0
  fi

  if ! have_cmd curl; then
    die "缺少 git/curl，无法从 GitHub 拉取代码。"
  fi
  if ! have_cmd tar; then
    die "缺少 tar，无法解压 GitHub 源码包。"
  fi

  log "使用 tarball 拉取代码：$TARBALL_URL"
  local tmp_dir
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT
  curl -fsSL "$TARBALL_URL" | tar -xz -C "$tmp_dir"
  mv "$tmp_dir/${REPO_NAME}-${REPO_BRANCH}" "$INSTALL_DIR"
  trap - EXIT
  rm -rf "$tmp_dir"
}

setup_venv() {
  if ! have_cmd python3; then
    die "缺少 python3。请先安装 Python 3。"
  fi

  log "创建 venv：$INSTALL_DIR/venv"
  if ! python3 -m venv "$INSTALL_DIR/venv" >/dev/null 2>&1; then
    die "python3 -m venv 失败。Debian/Ubuntu 请先安装：python3-venv"
  fi

  local vpy="$INSTALL_DIR/venv/bin/python"
  if ! "$vpy" -m pip --version >/dev/null 2>&1; then
    "$vpy" -m ensurepip --upgrade >/dev/null 2>&1 || die "无法初始化 pip。"
  fi

  log "安装依赖：$INSTALL_DIR/requirements.txt"
  "$vpy" -m pip install -U pip >/dev/null
  "$vpy" -m pip install -r "$INSTALL_DIR/requirements.txt" >/dev/null
}

generate_token() {
  python3 - <<'PY'
import secrets, string
alphabet = string.ascii_letters + string.digits
print("".join(secrets.choice(alphabet) for _ in range(24)))
PY
}

write_config() {
  local dns_port="$1"
  local token="$2"

  local cfg_path="$INSTALL_DIR/config.json"
  if [[ -e "$cfg_path" ]]; then
    local bak
    bak="$(backup_path "$cfg_path")"
    log "检测到已存在配置：$cfg_path"
    log "自动备份到：$bak"
    mv "$cfg_path" "$bak"
  fi

  cat >"$cfg_path" <<EOF
{
  "listen_host": "127.0.0.1",
  "web_host": "0.0.0.0",
  "dns_port": ${dns_port},
  "web_port": 8080,
  "timeout_ms": 2000,
  "ip_info_site": "netvigator",
  "clash_profile_source": "local",
  "clash_profile_url": "https://raw.githubusercontent.com/cutethotw/ClashRule/refs/heads/main/Customization/Andy120527.ini",
  "clash_cache_dir": "clash_cache",
  "clash_group_selection": {},
  "geoip_cn_url": "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt",
  "token": "${token}",
  "upstream_dns": "8.8.8.8",
  "upstream_dns_pool": [
    "1.1.1.1",
    "8.8.8.8"
  ],
  "ip_pool": [
    "1.1.1.1",
    "8.8.8.8",
    "9.9.9.9"
  ]
}
EOF
}

install_systemd_unit() {
  log "写入 systemd 单元：$SYSTEMD_UNIT_PATH"
  cat >"$SYSTEMD_UNIT_PATH" <<'EOF'
[Unit]
Description=DNSUnlock (Python DNS forwarder + Web UI)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=dnsunlock
Group=dnsunlock
WorkingDirectory=/opt/dnsunlock
ExecStart=/opt/dnsunlock/venv/bin/python /opt/dnsunlock/app.py
Restart=on-failure
RestartSec=2

# Allow binding to privileged ports like 53 (safe even if you use 5353)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/opt/dnsunlock

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
}

start_service() {
  local enable_on_boot="$1"

  if [[ "$enable_on_boot" == "y" ]]; then
    log "启用并启动服务：$SERVICE_NAME"
    systemctl enable --now "$SERVICE_NAME"
    return 0
  fi

  log "启动服务（不设置开机自启）：$SERVICE_NAME"
  systemctl restart "$SERVICE_NAME"
}

service_is_active() {
  systemctl is-active --quiet "$SERVICE_NAME"
}

setup_resolv_conf_lock() {
  local bak
  bak="$(backup_path "/etc/resolv.conf")"
  log "备份 /etc/resolv.conf -> $bak"
  cp -a /etc/resolv.conf "$bak" || true

  if have_cmd chattr; then
    chattr -i /etc/resolv.conf >/dev/null 2>&1 || true
  fi

  if [[ -L /etc/resolv.conf ]]; then
    rm -f /etc/resolv.conf
  fi

  printf "nameserver 127.0.0.1\n" > /etc/resolv.conf
  chmod 0644 /etc/resolv.conf || true

  if have_cmd chattr; then
    if chattr +i /etc/resolv.conf >/dev/null 2>&1; then
      log "已锁定 /etc/resolv.conf（chattr +i）"
    else
      warn "锁定 /etc/resolv.conf 失败（chattr +i）。已写入 nameserver 127.0.0.1，但可能会被系统覆盖。"
    fi
  else
    warn "未检测到 chattr，无法锁定 /etc/resolv.conf。已写入 nameserver 127.0.0.1，但可能会被系统覆盖。"
  fi

  log "如需恢复：先执行 chattr -i /etc/resolv.conf（如果可用），再用备份文件覆盖：cp -a $bak /etc/resolv.conf"
}

main() {
  require_root
  require_systemd

  log "DNSUnlock 一键安装脚本"
  log "安装目录：$INSTALL_DIR"

  local enable_autostart
  enable_autostart="$(prompt_yn "是否设置为开机自启（systemd）？" "y")"

  local set_system_dns
  set_system_dns="$(prompt_yn "是否将系统 DNS 设置为 127.0.0.1（仅此一项）并锁定 /etc/resolv.conf？" "n")"

  if [[ "$set_system_dns" == "y" && "$enable_autostart" != "y" ]]; then
    warn "你选择了修改系统 DNS，但未开启开机自启；重启后可能无法解析域名（断网风险）。"
    if [[ "$(prompt_yn "仍然继续修改系统 DNS 吗？" "n")" != "y" ]]; then
      set_system_dns="n"
    fi
  fi

  local dns_port="5353"
  if [[ "$set_system_dns" == "y" ]]; then
    dns_port="53"
  fi

  fetch_repo
  ensure_user
  setup_venv

  local token
  token="$(generate_token)"
  write_config "$dns_port" "$token"

  chown -R dnsunlock:dnsunlock "$INSTALL_DIR"

  install_systemd_unit
  start_service "$enable_autostart"

  if ! service_is_active; then
    warn "服务未处于 active 状态：$SERVICE_NAME"
    warn "请先执行：systemctl status $SERVICE_NAME --no-pager"
    warn "为避免断网，已跳过修改系统 DNS。"
    set_system_dns="n"
  fi

  if [[ "$set_system_dns" == "y" ]]; then
    setup_resolv_conf_lock
  fi

  log "安装完成"
  log "配置文件：$INSTALL_DIR/config.json"
  log "面板地址：http://127.0.0.1:8080/?token=${token}"
  log "服务管理：systemctl status|restart|stop|disable $SERVICE_NAME"
}

main "$@"
