# 🚀 ERFAN TUNNEL

**ERFAN TUNNEL** is a production-ready, interactive tool to build and manage  
**SIT (IPv6-in-IPv4 / 6to4 local) tunnels** between **Iran servers and outbound servers**,  
with automatic **HAProxy TCP pass-through**, **anti-reboot systemd services**,  
and **high-load kernel tuning** for thousands of concurrent users.

> Developed by **@erfanessence**

---

## ✨ Features

- 🔹 Interactive **menu-based installer**
- 🔹 Works on **Iran (IR)** and **Outbound (OUT)** servers
- 🔹 Local IPv6 ULA (`fd00::/64`) over IPv4 (SIT tunnel)
- 🔹 Automatic **HAProxy TCP forwarding** (no port change needed)
- 🔹 **Anti-reboot** tunnels using systemd
- 🔹 **High-concurrency tuning** (tested for 2000+ users)
- 🔹 Built-in **Preflight / Test** before applying changes
- 🔹 **Status & diagnostics** tools
- 🔹 **Full cleanup / uninstall** option
- 🔹 Safe backups for HAProxy config
- 🔹 Logs saved to `/var/log/erfan-tunnel.log`

---

## 🧠 Use Cases

- Bypass routing limitations using local IPv6 tunnels
- Keep original service ports (VLESS / Xray / etc.)
- Stable Iran ↔ Outbound connectivity without WireGuard
- Large-scale VPN or proxy setups
- Cloudflare DNS-only routing (TCP pass-through)

---

## ⚙️ Requirements

- Ubuntu / Debian (recommended: Ubuntu 20.04+ / 22.04+)
- Root access
- Kernel support for `ip tunnel mode sit`
- IPv4 connectivity on both sides

> ⚠️ Note: IPv6 must **not be disabled** at kernel level (`disable_ipv6=1`).

---

## 🚀 Quick Install (One Command)

Run this on **any server (Iran or Outbound)**:

```bash
curl -fsSL https://raw.githubusercontent.com/erfanrec/erfan-tunnel/main/erfan-tunnel.sh -o erfan-tunnel.sh
chmod +x erfan-tunnel.sh
sudo ./erfan-tunnel.sh
