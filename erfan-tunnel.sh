#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
#  ERFAN TUNNEL
#  Developed by @erfanessence
#
#  Menu-driven SIT (IPv6-in-IPv4) tunnel manager:
#   - IR: multi-OUT SIT tunnels + HAProxy TCP pass-through
#   - OUT: single SIT tunnel back to IR
#   - Anti-reboot systemd services
#   - High-load tuning for thousands of concurrent users
#   - Preflight test (ping/ping6/nc) before applying changes
#   - Status/Diagnostics + Full Cleanup
#
#  Logs:   /var/log/erfan-tunnel.log
#  Backs:  /root/.erfan-tunnel-backups/
# ==========================================================

APP_NAME="ERFAN TUNNEL"
APP_AUTHOR="Developed by @erfanessence"
APP_VER="2.0.0"

LOG_FILE="/var/log/erfan-tunnel.log"
BACKUP_DIR="/root/.erfan-tunnel-backups"
mkdir -p "$BACKUP_DIR"

# systemd units/scripts
SIT_ALL_SVC="/etc/systemd/system/erfan-sit-all.service"
SIT_IR_SVC="/etc/systemd/system/erfan-sit-ir.service"
SIT_ALL_SH="/usr/local/sbin/erfan-sit-all.sh"
SIT_IR_SH="/usr/local/sbin/erfan-sit-ir.sh"

# tuning files
SYSCTL_TCP="/etc/sysctl.d/99-erfan-highload-tcp.conf"
SYSCTL_CT="/etc/sysctl.d/99-erfan-conntrack.conf"
LIMITS_FILE="/etc/security/limits.d/99-erfan-production.conf"
HAP_DROPIN_DIR="/etc/systemd/system/haproxy.service.d"
HAP_DROPIN_FILE="${HAP_DROPIN_DIR}/erfan-limits.conf"
SYSTEMD_CONF="/etc/systemd/system.conf"

# haproxy
HAP_CFG="/etc/haproxy/haproxy.cfg"

# --------------- helpers ---------------
ts() { date +"%F %T"; }
_log() { echo -e "$(ts) | $*" >> "$LOG_FILE" 2>/dev/null || true; }
say() { echo -e "$*"; _log "$*"; }
warn() { echo -e "\n[WARN] $*"; _log "[WARN] $*"; }
die() { echo -e "\n[ERROR] $*"; _log "[ERROR] $*"; exit 1; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }

need_root() { [[ "$(id -u)" -eq 0 ]] || die "Run as root (sudo)."; }

pause() { read -r -p $'\nPress Enter to continue... ' _; }

confirm() {
  local prompt="${1:-Are you sure?}"
  read -r -p "$prompt (yes/no): " ans
  [[ "${ans:-}" == "yes" ]]
}

ask() {
  local prompt="$1"
  local default="${2:-}"
  local v
  if [[ -n "$default" ]]; then
    read -r -p "$prompt [$default]: " v
    echo "${v:-$default}"
  else
    read -r -p "$prompt: " v
    echo "$v"
  fi
}

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local b="${BACKUP_DIR}/$(basename "$f").$(date +%Y%m%d-%H%M%S).bak"
  cp -a "$f" "$b"
  echo "$b"
}

print_banner() {
  clear || true
  cat <<'BANNER'
  ______           __              ______                __
 / ____/________ _/ /_  ____      /_  __/_  ______  ____/ /__
/ __/ / ___/ __ `/ __ \/ __ \      / / / / / / __ \/ __  / _ \
/ /___/ /  / /_/ / / / / /_/ /     / / / /_/ / / / / /_/ /  __/
/_____/_/   \__,_/_/ /_/\____/     /_/  \__,_/_/ /_/\__,_/\___/

BANNER
  echo "====================== ${APP_NAME} v${APP_VER} ======================"
  echo "                 ${APP_AUTHOR}"
  echo "---------------------------------------------------------------------"
  echo "Log:     ${LOG_FILE}"
  echo "Backups: ${BACKUP_DIR}"
  echo "====================================================================="
}

install_pkgs() {
  say "\n==> Installing prerequisites"
  if has_cmd apt; then
    apt update -y >/dev/null || true
    apt install -y iproute2 iptables conntrack haproxy netcat-openbsd >/dev/null || true
  else
    warn "No apt found. Please install: iproute2 iptables conntrack haproxy netcat-openbsd"
  fi
}

ensure_conntrack() {
  say "\n==> Enabling conntrack module"
  modprobe nf_conntrack 2>/dev/null || true
  grep -qx 'nf_conntrack' /etc/modules 2>/dev/null || echo nf_conntrack >> /etc/modules
}

ipv6_disable_flags() {
  local a d l
  a="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 0)"
  d="$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null || echo 0)"
  l="$(sysctl -n net.ipv6.conf.lo.disable_ipv6 2>/dev/null || echo 0)"
  echo "$a $d $l"
}

ipv6_hint() {
  read -r a d l <<<"$(ipv6_disable_flags)"
  if [[ "$a" == "1" || "$d" == "1" || "$l" == "1" ]]; then
    warn "IPv6 seems DISABLED (disable_ipv6=1). SIT/ULA will not work until enabled."
    warn "Fix: remove disable_ipv6=1 from /etc/sysctl.conf and /etc/sysctl.d/*.conf then set to 0 and reboot."
  else
    say "IPv6 disable flags: all=$a default=$d lo=$l (OK)"
  fi
}

check_sit_support() {
  local tmp="__sit_test0"
  ip tunnel del "$tmp" 2>/dev/null || true
  if ip tunnel add "$tmp" mode sit remote 1.1.1.1 local 2.2.2.2 ttl 255 2>/dev/null; then
    ip tunnel del "$tmp" 2>/dev/null || true
    return 0
  fi
  return 1
}

public_ipv4_guess() {
  ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || true
}

# --------------- tuning (IR) ---------------
apply_tuning_ir() {
  install_pkgs
  ensure_conntrack

  say "\n==> Applying IR production tuning (2000+ concurrent users)"

  cat > "$LIMITS_FILE" <<'EOF'
* soft nofile 500000
* hard nofile 500000
root soft nofile 500000
root hard nofile 500000
EOF

  mkdir -p "$HAP_DROPIN_DIR"
  cat > "$HAP_DROPIN_FILE" <<'EOF'
[Service]
LimitNOFILE=500000
LimitNPROC=500000
EOF

  cat > "$SYSCTL_TCP" <<'EOF'
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 250000

net.ipv4.ip_local_port_range = 10000 65535

net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1

net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6

net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.ipv4.tcp_rmem = 4096 87380 268435456
net.ipv4.tcp_wmem = 4096 65536 268435456

net.ipv4.tcp_fastopen = 3
EOF

  cat > "$SYSCTL_CT" <<'EOF'
net.netfilter.nf_conntrack_max=1048576
net.netfilter.nf_conntrack_buckets=262144
EOF

  # systemd global limits (so SSH sessions aren't 1024 after reboot/login)
  sed -i '/^DefaultLimitNOFILE=/d;/^DefaultLimitNPROC=/d' "$SYSTEMD_CONF" 2>/dev/null || true
  printf "\nDefaultLimitNOFILE=500000\nDefaultLimitNPROC=500000\n" >> "$SYSTEMD_CONF"

  grep -q 'pam_limits.so' /etc/pam.d/common-session || echo 'session required pam_limits.so' >> /etc/pam.d/common-session

  sysctl --system >/dev/null || true
  systemctl daemon-reload
  systemctl restart haproxy >/dev/null 2>&1 || true
  systemctl daemon-reexec

  say "✅ Tuning applied. Recommended: reboot once (for all sessions to pick up new limits)."
}

# --------------- IR config ---------------
# ULA planning: base hex e.g. 41 => fd00:41::/64; i increments
ula_prefix_for() { local base_dec="$1" i="$2"; printf "fd00:%x::" "$((base_dec + i))"; }

write_haproxy_header() {
  cat > "$HAP_CFG" <<'EOF'
global
    maxconn 200000
    nbthread 4

defaults
    mode tcp
    option dontlognull
    timeout connect 10s
    timeout client  30m
    timeout server  30m

EOF
}

configure_ir() {
  install_pkgs

  local ir_ip_guess ir_ip n base_hex
  ir_ip_guess="$(public_ipv4_guess)"
  ir_ip="$(ask "IR public IPv4" "${ir_ip_guess:-}")"
  [[ -n "$ir_ip" ]] || die "IR IP is required."

  n="$(ask "Number of OUT servers" "1")"
  [[ "$n" =~ ^[0-9]+$ ]] || die "Please enter a valid number."

  base_hex="$(ask "ULA base (hex), e.g. 41 => fd00:41::/64" "41")"
  [[ "$base_hex" =~ ^[0-9a-fA-F]+$ ]] || die "ULA base must be hex."

  local base_dec=$((16#$base_hex))

  say "\n==> Backing up HAProxy config (if exists)"
  local hap_bak=""
  hap_bak="$(backup_file "$HAP_CFG" || true)"
  [[ -n "${hap_bak:-}" ]] && say "HAProxy backup: $hap_bak"

  say "\n==> Generating IR tunnel script: $SIT_ALL_SH"
  cat > "$SIT_ALL_SH" <<EOF
#!/usr/bin/env bash
set -euo pipefail
IR_IP="${ir_ip}"
EOF

  write_haproxy_header

  say "\n==> IR setup wizard"
  say "Tip: You can enter multiple ports like: 443,8883"
  echo ""

  for ((i=0; i<n; i++)); do
    local name out_ip ports tun_name prefix ir_ula out_ula

    name="$(ask "OUT #$((i+1)) name (e.g. DE1/NL/TR/FL)" "OUT$((i+1))")"
    out_ip="$(ask "OUT #$((i+1)) public IPv4" )"
    [[ -n "$out_ip" ]] || die "OUT IP is required."

    ports="$(ask "Ports (comma-separated, e.g. 443,8883)" )"
    ports="$(echo "$ports" | tr -d ' ' )"
    [[ -n "$ports" ]] || die "Ports cannot be empty."

    # validate ports
    IFS=',' read -ra _p <<<"$ports"
    for p in "${_p[@]}"; do
      [[ "$p" =~ ^[0-9]+$ ]] || die "Invalid port: $p"
      (( p >= 1 && p <= 65535 )) || die "Port out of range: $p"
    done

    tun_name="$(ask "Tunnel interface name on IR" "tun${name}")"
    [[ "$tun_name" =~ ^[a-zA-Z0-9_.-]+$ ]] || die "Invalid interface name."

    prefix="$(ula_prefix_for "$base_dec" "$i")"
    ir_ula="${prefix}1"
    out_ula="${prefix}2"

    # tunnel commands
    cat >> "$SIT_ALL_SH" <<EOF
ip tunnel del ${tun_name} 2>/dev/null || true
ip tunnel add ${tun_name} mode sit remote ${out_ip} local "\${IR_IP}" ttl 255
ip link set ${tun_name} up
ip -6 addr replace ${ir_ula}/64 dev ${tun_name}
ip link set ${tun_name} txqueuelen 20000
EOF

    # haproxy map per port
    for p in "${_p[@]}"; do
      cat >> "$HAP_CFG" <<EOF

frontend fe_${name}_${p}
    bind *:${p}
    default_backend be_${name}_${p}

backend be_${name}_${p}
    server ${name} [${out_ula}]:${p}

EOF
    done

    say "Planned ✅  ${name}  OUT=${out_ip}  IF=${tun_name}  ULA=${prefix}/64  IR=${ir_ula}  OUT=${out_ula}  PORTS=${ports}"
  done

  chmod +x "$SIT_ALL_SH"

  say "\n==> Installing anti-reboot service on IR"
  cat > "$SIT_ALL_SVC" <<EOF
[Unit]
Description=Erfan Tunnel (IR) - SIT tunnels
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash ${SIT_ALL_SH}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now erfan-sit-all

  systemctl restart haproxy

  say "\n✅ IR configured."
  say "Next step: run 'Configure OUT' on each outbound server using OUT ULA shown above."
}

# --------------- OUT config ---------------
configure_out() {
  install_pkgs

  local ir_ip out_ip out_ula tun_name
  ir_ip="$(ask "IR public IPv4" )"
  out_ip="$(ask "OUT public IPv4 (this server)" "$(public_ipv4_guess)")"
  out_ula="$(ask "OUT ULA (e.g. fd00:41::2)" )"
  tun_name="$(ask "Tunnel interface name on OUT" "tunIR")"

  [[ -n "$ir_ip" && -n "$out_ip" && -n "$out_ula" ]] || die "IR_IP, OUT_IP, OUT_ULA are required."

  cat > "$SIT_IR_SH" <<EOF
#!/usr/bin/env bash
set -euo pipefail
ip tunnel del ${tun_name} 2>/dev/null || true
ip tunnel add ${tun_name} mode sit remote ${ir_ip} local ${out_ip} ttl 255
ip link set ${tun_name} up
ip -6 addr replace ${out_ula}/64 dev ${tun_name}
EOF
  chmod +x "$SIT_IR_SH"

  cat > "$SIT_IR_SVC" <<EOF
[Unit]
Description=Erfan Tunnel (OUT) - SIT tunnel to IR
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash ${SIT_IR_SH}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now erfan-sit-ir

  say "✅ OUT configured."
}

# --------------- Preflight Test ---------------
# This is "full test": SIT support + ipv6 flags + ping peer v4 + (optional) ping6 ULA + nc port(s)
preflight_test() {
  install_pkgs

  say "\n==> Preflight / Test"
  say "Kernel: $(uname -r)"
  say "OS: $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
  say "Detected public IPv4: $(public_ipv4_guess)"
  ipv6_hint

  if check_sit_support; then
    say "SIT support: OK"
  else
    die "SIT support: FAILED (provider/kernel blocks 'ip tunnel mode sit')."
  fi

  ensure_conntrack
  if [[ -f /proc/sys/net/netfilter/nf_conntrack_max ]]; then
    say "Conntrack: max=$(cat /proc/sys/net/netfilter/nf_conntrack_max) count=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo N/A)"
  fi

  echo ""
  local role peer_ip
  role="$(ask "Role? (IR/OUT)" "IR")"
  role="$(echo "$role" | tr '[:lower:]' '[:upper:]')"
  [[ "$role" == "IR" || "$role" == "OUT" ]] || die "Role must be IR or OUT."

  if [[ "$role" == "IR" ]]; then
    peer_ip="$(ask "Outbound peer IPv4 to ping" )"
  else
    peer_ip="$(ask "Iran peer IPv4 to ping" )"
  fi
  [[ -n "$peer_ip" ]] || die "Peer IPv4 required."

  say "\n==> IPv4 ping to peer: $peer_ip"
  if ping -c 2 -W 2 "$peer_ip" >/dev/null 2>&1; then
    say "IPv4 ping: OK ✅"
  else
    die "IPv4 ping: FAILED ❌ (routing/firewall/provider)"
  fi

  local do_ula
  do_ula="$(ask "Test ULA IPv6 + ports now? (yes/no)" "yes")"
  if [[ "$do_ula" == "yes" ]]; then
    local peer_ula ports
    peer_ula="$(ask "Peer ULA IPv6 (e.g. fd00:41::2)" )"
    [[ -n "$peer_ula" ]] || die "Peer ULA required."

    say "\n==> IPv6 ping to peer ULA: $peer_ula"
    if ping6 -c 2 -W 2 "$peer_ula" >/dev/null 2>&1; then
      say "IPv6 ping: OK ✅"
    else
      die "IPv6 ping: FAILED ❌ (tunnel not up / IPv6 disabled / SIT blocked)"
    fi

    ports="$(ask "Ports to test via ULA (comma-separated, e.g. 443,8883)" )"
    ports="$(echo "$ports" | tr -d ' ' )"
    [[ -n "$ports" ]] || die "Ports required."

    IFS=',' read -ra parr <<<"$ports"
    for p in "${parr[@]}"; do
      [[ "$p" =~ ^[0-9]+$ ]] || die "Invalid port: $p"
      say "nc -6 -vz ${peer_ula} ${p}"
      if nc -6 -vz "$peer_ula" "$p" -w 2 >/dev/null 2>&1; then
        say "Port $p: OK ✅"
      else
        die "Port $p: FAILED ❌ (backend not listening or firewall)"
      fi
    done
  fi

  say "\n✅ Preflight PASSED. Ready to configure."
  if confirm "Run configuration now (based on role)?"; then
    if [[ "$role" == "IR" ]]; then
      configure_ir
    else
      configure_out
    fi
  else
    say "Ok. You can run Configure from menu anytime."
  fi
}

# --------------- status ---------------
status_diag() {
  say "\n==> Status / Diagnostics"

  echo "------ limits ------"
  echo "ulimit -n: $(ulimit -n 2>/dev/null || echo N/A)"
  echo "haproxy LimitNOFILE: $(systemctl show haproxy --property=LimitNOFILE 2>/dev/null | cut -d= -f2 || echo N/A)"

  echo "------ conntrack ------"
  [[ -f /proc/sys/net/netfilter/nf_conntrack_max ]] && echo "nf_conntrack_max: $(cat /proc/sys/net/netfilter/nf_conntrack_max)" || echo "nf_conntrack_max: N/A"
  [[ -f /proc/sys/net/netfilter/nf_conntrack_count ]] && echo "nf_conntrack_count: $(cat /proc/sys/net/netfilter/nf_conntrack_count)" || echo "nf_conntrack_count: N/A"

  echo "------ tunnels ------"
  ip -d tunnel show | sed 's/^/  /'

  echo "------ fd00 addrs ------"
  ip -6 addr | grep -E 'fd00:' || true

  echo "------ haproxy listens ------"
  ss -lntp | grep haproxy || true

  echo "------ services ------"
  systemctl status erfan-sit-all --no-pager 2>/dev/null || true
  systemctl status erfan-sit-ir --no-pager 2>/dev/null || true
}

# --------------- cleanup ---------------
cleanup_full() {
  warn "This will REMOVE ERFAN TUNNEL services/scripts and delete tunnel interfaces named tun*."
  warn "It will NOT touch sit0. HAProxy restore is optional."
  confirm "Proceed with FULL CLEANUP?" || { say "Cancelled."; return; }

  systemctl disable --now erfan-sit-all 2>/dev/null || true
  systemctl disable --now erfan-sit-ir 2>/dev/null || true

  rm -f "$SIT_ALL_SVC" "$SIT_IR_SVC" "$SIT_ALL_SH" "$SIT_IR_SH"
  systemctl daemon-reload

  # remove tun* only (safe)
  for t in $(ip -d tunnel show | awk -F: '/^tun/{print $1}' | tr -d ' '); do
    ip -6 addr flush dev "$t" 2>/dev/null || true
    ip tunnel del "$t" 2>/dev/null || true
  done

  say "\nBackups directory: $BACKUP_DIR"
  if [[ -f "$HAP_CFG" ]] && ls "$BACKUP_DIR"/haproxy.cfg.*.bak >/dev/null 2>&1; then
    echo "Latest HAProxy backups:"
    ls -1t "$BACKUP_DIR"/haproxy.cfg.*.bak | head -n 5
    if confirm "Restore latest haproxy.cfg backup?"; then
      local latest
      latest="$(ls -1t "$BACKUP_DIR"/haproxy.cfg.*.bak | head -n 1)"
      cp -a "$latest" "$HAP_CFG"
      systemctl restart haproxy || true
      say "Restored: $latest"
    fi
  fi

  if confirm "Remove tuning files created by ERFAN TUNNEL?"; then
    rm -f "$SYSCTL_TCP" "$SYSCTL_CT" "$LIMITS_FILE" "$HAP_DROPIN_FILE"
    sysctl --system >/dev/null || true
    systemctl daemon-reload
    systemctl restart haproxy || true
    say "Tuning files removed. (systemd DefaultLimit in $SYSTEMD_CONF remains unless edited manually.)"
  fi

  say "✅ Cleanup done."
}

# --------------- menu ---------------
menu() {
  print_banner
  echo "1) Test / Preflight (recommended first)"
  echo "2) Configure IR (tunnels + HAProxy + anti-reboot)"
  echo "3) Configure OUT (tunnel + anti-reboot)"
  echo "4) Tuning ONLY (IR) - 2000+ users"
  echo "5) Status / Diagnostics"
  echo "6) Full Cleanup / Uninstall"
  echo "0) Exit"
  echo ""
  local c
  c="$(ask "Select option" "1")"
  case "$c" in
    1) preflight_test ;;
    2) configure_ir ;;
    3) configure_out ;;
    4) apply_tuning_ir ;;
    5) status_diag ;;
    6) cleanup_full ;;
    0) exit 0 ;;
    *) warn "Invalid choice." ;;
  esac
}

main() {
  need_root
  touch "$LOG_FILE" 2>/dev/null || true
  while true; do
    menu
    pause
  done
}

main "$@"
