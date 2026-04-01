# Changelog

## 2026-04-01 — Mise en place initiale
- VPS IONOS Linux XS+ · 1 vCore · 1Go RAM · 10Go SSD · 24 mois
- OS : Ubuntu 24.04 LTS · Serveur EU Allemagne · IP : 87.106.194.116
- Cowrie v2.9.16 installé via pip en environnement virtuel Python 3.12
- Utilisateur dédié : cowrie
- Service systemd configuré (démarrage automatique au reboot)
- Pare-feu IONOS : ports 22 et 2223 ouverts uniquement

## 2026-04-01 — Configuration des ports
- ssh.socket désactivé pour libérer le contrôle du port SSH
- SSH admin déplacé sur port 2223
- Cowrie configuré sur port 22 via authbind
- Modification cowrie_plugin.py ligne 244 : port par défaut hardcodé 2222 → 22
- iptables vidé, pare-feu géré uniquement via IONOS

## 2026-04-01 — Première activité enregistrée
- Premiers bots détectés < 2h après mise en production
- IP 2.57.122.208 : bot spécialisé crypto/trading (validator, node, evm, evmbot, trader...)
- Intervalle entre tentatives : ~2 minutes (comportement automatisé)
- Première connexion réussie dans le honeypot : 78.128.112.74 (root/welcome) à 12h03
