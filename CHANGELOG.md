# Changelog

## 2026-04-01 — Initial Setup
- VPS IONOS Linux XS+ · 1 vCore · 1GB RAM · 10GB SSD · 24 months
- OS: Ubuntu 24.04 LTS · EU Germany server · IP: 87.106.194.116
- Cowrie v2.9.16 installed via pip in a Python 3.12 virtual environment
- Dedicated user: cowrie
- systemd service configured (auto-start on reboot)
- IONOS firewall: ports 22 and 2223 open only

## 2026-04-01 — Port Configuration
- ssh.socket disabled to release control of the SSH port
- Admin SSH moved to port 2223
- Cowrie configured on port 22 via authbind
- Edited cowrie_plugin.py line 244: hardcoded default port 2222 → 22
- iptables flushed, firewall managed exclusively via IONOS

## 2026-04-01 — First Recorded Activity
- First bots detected < 2h after going live
- IP 2.57.122.208: crypto/trading-focused bot (validator, node, evm, evmbot, trader…)
- Interval between attempts: ~2 minutes (automated behavior)
- First successful login into the honeypot: 78.128.112.74 (root/welcome) at 12:03
