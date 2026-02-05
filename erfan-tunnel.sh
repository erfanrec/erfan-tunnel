#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
#  ERFAN TUNNEL (SITCTL)
#  Developed by @erfanessence
#  Public, interactive installer for:
#   - SIT tunnels (ip tunnel mode sit)
#   - ULA IPv6 (fd00::/64)
#   - HAProxy TCP passthrough
#   - systemd anti-reboot services
#   - IR tuning for high concurrency
# ==========================================================

APP_NAME="ERFAN TUNNEL"
APP_SUB="Developed by @erfanessence"
APP_VER="1.1.0"

LOG_FILE="/var/log/erfan-tunnel.log"
BACKUP_DIR="/root/.erfan-tunnel-backups"
mkdir -p "$BACKUP_DIR"

SIT_ALL_SERVICE="/etc/systemd/system/erfan-sit-all.service"
SIT_IR_SERVICE="/etc/systemd/system/erfan-sit-ir.service"
SIT_ALL_SCRIPT="/usr/local/sbin/erfan-sit-all.sh"
SIT_IR_SCRIPT="/usr/local/sbin/erfan-sit-ir.sh"

SYSCTL_TCP="/etc/sysctl.d/99-erfan-highload-tcp.conf"
SYSCTL_CT="/etc/sysctl.d/99-erfan-conntrack.conf"
LIMITS_FILE="/etc/security/limits.d/99-erfan-production.conf"

HAP_DROPIN_DIR="/etc/systemd/system/haproxy.service.d"
HAP_DROPIN_FILE="${HAP_DROPIN_DIR}/erfan-limits.conf"
SYSTEMD_CONF="/etc/systemd/system.conf"
HAP_CFG="/etc/haproxy/haproxy.cfg"

# ---------------- utils ----------------
ts() { date +"%F %T"; }
log() { echo -e "$(ts) | $*" | tee -a "$LOG_FILE" >/dev/null; }
say() { echo -e "$*"; log "$*"; }
warn() { echo -e "\n[WARN] $*" ; log "[WARN] $*"; }
die() { echo -e "\n[ERROR] $*" ; log "[ERROR] $*"; exit 1; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }

need_root() { [[ "$(id -u)" -eq 0 ]] || die "Run as root (use sudo)."; }

pause() { read -r -p $'\nPress Enter to continue... ' _; }

confirm() {
  local prompt="${1:-Are you sure?}"
  read -r -p "$prompt (yes/no): " ans
  [[ "${ans:-}" == "yes" ]]
}

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local b="${BACKUP_DIR}/$(basename "$f").$(date +%Y%m%d-%H%M%S).bak"
  cp -a "$f" "$b"
  echo "$b"
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

# ports: "443,8883" => "443|8883"
ask_ports() {
  local p
  p="$(ask "Ports (comma-separated, e.g. 443,8883)" )"
  p="$(echo "$p" | tr -d ' ' )"
  [[ -n "$p" ]] || die "Ports cannot be empty."
  # validate numeric
  IFS=',' read -ra arr <<<"$p"
  for x in "${arr[@]}"; do
    [[ "$x" =~ ^[0-9]+$ ]] || die "Invalid port: $x"
    (( x >= 1 && x <= 65535 )) || die "Port out of range: $x"
  done
  echo "$p" | tr ',' '|'
}

print_banner() {
  clear || true
  echo "=========================================================="
  echo "                  ${APP_NAME}  v${APP_VER}"
  echo "                 ${APP_SUB}"
  echo "=========================================================="
  echo " Log: ${LOG_FILE}"
  echo " Backups: ${BACKUP_DIR}"
  echo "----------------------------------------------------------"
}

install_pkgs() {
  say "\n==> Installing prerequisites"
  if has_cmd apt; then
    apt update -y >/dev/null || true
    apt install -y iproute2 iptables conntrack haproxy socat >/dev/null || true
  else
    warn "No apt found. Install manually: iproute2 iptables conntrack haproxy socat"
  fi
}

ensure_conntrack() {
  say "\n==> Enabling conntrack module"
  modprobe nf_conntrack 2>/dev/null || true
  grep -qx 'nf_conntrack' /etc/modules 2>/dev/null || echo nf_conntrack >> /etc/modules
}

ipv6_enable_hint() {
  local a d l
  a="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 0)"
  d="$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null || echo 0)"
  l="$(sysctl -n net.ipv6.conf.lo.disable_ipv6 2>/dev/null || echo 0)"
  if [[ "$a" == "1" || "$d" == "1" || "$l" == "1" ]]; then
    warn "IPv6 is disabled (sysctl disable_ipv6=1). SIT ULA will fail until enabled."
    warn "Fix: comment disable_ipv6=1 lines in /etc/sysctl.conf and /etc/sysctl.d/*.conf then set to 0 and reboot."
  fi
}

check_sit_support() {
  # If kernel supports "sit" tunnels, ip tunnel add ... mode sit should work.
  # We'll do a harmless dry attempt with a temporary name.
  local tmp="__sit_test0"
  ip tunnel del "$tmp" 2>/dev/null || true
  if ip tunnel add "$tmp" mode sit remote 1.1.1.1 local 2.2.2.2 ttl 255 2>/dev/null; then
    ip tunnel del "$tmp" 2>/dev/null || true
    return 0
  fi
  return 1
}

# ----------- TUNING (IR) -----------
apply_tuning_ir() {
  install_pkgs
  ensure_conntrack

  say "\n==> Applying IR tuning (2000+ concurrent users)"

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

  # systemd global limits so shells aren't 1024 after reboot/login
  sed -i '/^DefaultLimitNOFILE=/d;/^DefaultLimitNPROC=/d' "$SYSTEMD_CONF" || true
  printf "\nDefaultLimitNOFILE=500000\nDefaultLimitNPROC=500000\n" >> "$SYSTEMD_CONF"

  grep -q 'pam_limits.so' /etc/pam.d/common-session || echo 'session required pam_limits.so' >> /etc/pam.d/common-session

  sysctl --system >/dev/null || true
  systemctl daemon-reload
  systemctl restart haproxy >/dev/null 2>&1 || true
  systemctl daemon-reexec

  say "Tuning applied. Recommended: reboot once for all sessions to pick up limits."
}

# ----------- CONFIG IR -----------
# ULA planning: base hex, tunnel i => fd00:<base+i>::1 and ::2
ula_prefix_for() { local base_hex="$1" i="$2"; printf "fd00:%x::" "$((base_hex + i))"; }

configure_ir() {
  install_pkgs

  local ir_ip n base_hex
  ir_ip="$(ask "IR public IPv4" )"
  [[ -n "$ir_ip" ]] || die "IR IP required."

  n="$(ask "Number of OUT servers" "1")"
  [[ "$n" =~ ^[0-9]+$ ]] || die "Enter a number."

  base_hex="$(ask "ULA base (hex), e.g. 41 => fd00:41::/64" "41")"
  [[ "$base_hex" =~ ^[0-9a-fA-F]+$ ]] || die "Enter a hex value."

  local base_dec=$((16#$base_hex))

  say "\n==> Building IR tunnel script + HAProxy config"
  cat > "$SIT_ALL_SCRIPT" <<EOF
#!/usr/bin/env bash
set -euo pipefail
IR_IP="${ir_ip}"
EOF
  chmod +x "$SIT_ALL_SCRIPT"

  local hap_bak
  hap_bak="$(backup_file "$HAP_CFG" || true)"
  [[ -n "${hap_bak:-}" ]] && say "HAProxy config backup: $hap_bak"

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

  for ((i=0; i<n; i++)); do
    say ""
    local name out_ip ports tun_name
    name="$(ask "OUT #$((i+1)) name (e.g. DE1/NL/TR/FL)" "OUT$((i+1))")"
    out_ip="$(ask "OUT #$((i+1)) public IPv4" )"
    ports="$(ask_ports)"
    tun_name="$(ask "Tunnel interface name on IR" "tun${name}")"

    [[ -n "$out_ip" ]] || die "OUT IP required."

    local prefix ir_ula out_ula
    prefix="$(ula_prefix_for "$base_dec" "$i")"
    ir_ula="${prefix}1"
    out_ula="${prefix}2"

    cat >> "$SIT_ALL_SCRIPT" <<EOF
ip tunnel del ${tun_name} 2>/dev/null || true
ip tunnel add ${tun_name} mode sit remote ${out_ip} local "\${IR_IP}" ttl 255
ip link set ${tun_name} up
ip -6 addr replace ${ir_ula}/64 dev ${tun_name}
ip link set ${tun_name} txqueuelen 20000
EOF

    IFS='|' read -ra parr <<<"$ports"
    for p in "${parr[@]}"; do
      cat >> "$HAP_CFG" <<EOF

frontend fe_${name}_${p}
    bind *:${p}
    default_backend be_${name}_${p}

backend be_${name}_${p}
    server ${name} [${out_ula}]:${p}

EOF
    done

    say "Planned: ${name}  OUT=${out_ip}  ULA=${prefix}/64  IR=${ir_ula}  OUT=${out_ula}  IF=${tun_name}  PORTS=${ports//|/,}"
  done

  say "\n==> Installing systemd service (anti-reboot) for IR"
  cat > "$SIT_ALL_SERVICE" <<EOF
[Unit]
Description=Erfan SIT tunnels (IR)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash ${SIT_ALL_SCRIPT}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now erfan-sit-all

  systemctl restart haproxy

  say "\nIR configured."
  say "Next: run 'Configure OUT' on each OUT server using the OUT ULA shown above."
}

# ----------- CONFIG OUT -----------
configure_out() {
  install_pkgs

  local ir_ip out_ip out_ula tun_name
  ir_ip="$(ask "IR public IPv4" )"
  out_ip="$(ask "OUT public IPv4 (this server)" )"
  out_ula="$(ask "OUT ULA (e.g. fd00:41::2)" )"
  tun_name="$(ask "Tunnel interface name on OUT" "tunIR")"
  [[ -n "$ir_ip" && -n "$out_ip" && -n "$out_ula" ]] || die "All fields required."

  cat > "$SIT_IR_SCRIPT" <<EOF
#!/usr/bin/env bash
set -euo pipefail
ip tunnel del ${tun_name} 2>/dev/null || true
ip tunnel add ${tun_name} mode sit remote ${ir_ip} local ${out_ip} ttl 255
ip link set ${tun_name} up
ip -6 addr replace ${out_ula}/64 dev ${tun_name}
EOF
  chmod +x "$SIT_IR_SCRIPT"

  cat > "$SIT_IR_SERVICE" <<EOF
[Unit]
Description=Erfan SIT tunnel (OUT -> IR)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash ${SIT_IR_SCRIPT}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now erfan-sit-ir

  say "OUT configured."
}

# ----------- TEST / PREFLIGHT -----------
preflight_test() {
  install_pkgs

  say "\n==> Preflight checks"
  say "Kernel: $(uname -r)"
  say "OS: $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
  say "Public IPv4 (first global): $(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)"
  say "IPv6 disable flags:"
  say "  all=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo N/A) default=$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null || echo N/A) lo=$(sysctl -n net.ipv6.conf.lo.disable_ipv6 2>/dev/null || echo N/A)"
  ipv6_enable_hint

  if check_sit_support; then
    say "SIT support: OK"
  else
    die "SIT support: FAILED (ip tunnel mode sit not allowed). Provider/kernel may block it."
  fi

  ensure_conntrack
  if [[ -f /proc/sys/net/netfilter/nf_conntrack_max ]]; then
    say "Conntrack: max=$(cat /proc/sys/net/netfilter/nf_conntrack_max) count=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo N/A)"
  else
    warn "Conntrack sysctls not present yet."
  fi

  say "\nOptional connectivity test (IR -> OUT over ULA) after configuration:"
  say "  - Run Status/Diagnostics to see tunnels + fd00 addresses"
  say "  - Use: ping6 fd00:xx::2 and: nc -6 -vz fd00:xx::2 <port>"

  say "\nPreflight done."
}

# ----------- STATUS -----------
status_diag() {
  say "\n==> Status / Diagnostics"
  echo "------ limits ------"
  echo "ulimit -n: $(ulimit -n 2>/dev/null || echo N/A)"
  echo "haproxy LimitNOFILE: $(systemctl show haproxy --property=LimitNOFILE 2>/dev/null | cut -d= -f2 || echo N/A)"
  echo "------ conntrack ------"
  [[ -f /proc/sys/net/netfilter/nf_conntrack_max ]] && cat /proc/sys/net/netfilter/nf_conntrack_max || echo "nf_conntrack_max: N/A"
  [[ -f /proc/sys/net/netfilter/nf_conntrack_count ]] && cat /proc/sys/net/netfilter/nf_conntrack_count || echo "nf_conntrack_count: N/A"
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

# ----------- CLEANUP -----------
cleanup_full() {
  warn "This will remove ERFAN TUNNEL services/scripts and delete tunnel interfaces named tun*."
  confirm "Proceed with FULL CLEANUP?" || { say "Cancelled."; return; }

  systemctl disable --now erfan-sit-all 2>/dev/null || true
  systemctl disable --now erfan-sit-ir 2>/dev/null || true
  rm -f "$SIT_ALL_SERVICE" "$SIT_IR_SERVICE"
  rm -f "$SIT_ALL_SCRIPT" "$SIT_IR_SCRIPT"
  systemctl daemon-reload

  # Remove tun* tunnels only (safe)
  for t in $(ip -d tunnel show | awk -F: '/^tun/{print $1}' | tr -d ' '); do
    ip -6 addr flush dev "$t" 2>/dev/null || true
    ip tunnel del "$t" 2>/dev/null || true
  done

  say "\nBackups available at: $BACKUP_DIR"
  if [[ -f "$HAP_CFG" ]] && ls "$BACKUP_DIR"/haproxy.cfg.*.bak >/dev/null 2>&1; then
    echo "Latest HAProxy backups:"
    ls -1t "$BACKUP_DIR"/haproxy.cfg.*.bak | head -n 5
    if confirm "Restore latest haproxy.cfg backup?"; then
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
    say "Tuning files removed. (systemd DefaultLimit in $SYSTEMD_CONF remains unless edited manually)"
  fi

  say "Cleanup done."
}

# ----------- menu -----------
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
