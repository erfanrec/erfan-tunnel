# 🚀 ERFAN TUNNEL

**ERFAN TUNNEL** is a production-ready, interactive tool to build and manage  
**SIT (IPv6-in-IPv4 / “6to4 local”) tunnels** between **Iran (IR)** servers and **Outbound (OUT)** servers,  
with automatic **HAProxy TCP pass-through**, **anti-reboot systemd services**, and **high-load tuning**.

> Developed by **@erfanessence**

---

## ✨ Highlights

- ✅ **Menu-driven** (easy for beginners, powerful for pros)
- ✅ IR: **multiple outbound tunnels** + auto HAProxy config
- ✅ OUT: quick single tunnel back to IR
- ✅ **Preflight Test**: checks SIT support + pings (IPv4/IPv6) + port tests (nc)
- ✅ **Anti-reboot**: persistent tunnels with systemd
- ✅ **High-load tuning**: nofile, TCP tuning, conntrack (2000+ concurrent users)
- ✅ **Status/Diagnostics** and **Full Cleanup/Uninstall**
- ✅ Logs: `/var/log/erfan-tunnel.log`
- ✅ Backups: `/root/.erfan-tunnel-backups/`

---

## 🧠 When to use

- Keep your existing service ports (Xray/VLESS/Reality/…)
- Route traffic through Iran server while your services stay on OUT servers
- Avoid changing ports on configs
- High concurrency environments (1k–5k+ connections)

---

## ⚙️ Requirements

- Ubuntu/Debian recommended (Ubuntu 20.04+/22.04+)
- Root access
- Provider/kernel must allow **SIT tunnels** (`ip tunnel mode sit`)
- IPv6 must not be disabled via sysctl (`disable_ipv6=1`)

---

## 🚀 Install & Run

### ✅ One-liner (no chmod, no saved file)
```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/erfanrec/erfan-tunnel/main/erfan-tunnel.sh)"
