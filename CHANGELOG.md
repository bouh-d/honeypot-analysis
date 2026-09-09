# Journal de bord

## 4 septembre 2026 — Outillage d'analyse

- Réécriture complète du script d'analyse : lecture en flux ligne par ligne au
  lieu du chargement intégral en mémoire. Les journaux dépassaient les 4 Go, la
  version précédente ne passait plus sur un VPS à 1 Go de RAM.
- Prise en charge des archives hebdomadaires `.gz` sans décompression préalable.
- Ajout d'une correspondance entre les commandes observées et les techniques
  MITRE ATT&CK (`analyse/mitre.py`).
- Séparation de l'agrégation (`analyse.py`) et de la mise en forme
  (`rapport.py`) : l'agrégat JSON est archivé, le HTML se régénère à volonté.
- Premier rapport sur cinq mois complets, du 1er avril au 4 septembre.
- Disque à 90 % d'occupation : purge des captures TTY de plus de 30 jours.

## 21 avril 2026 — Première passe d'analyse

- Script initial de comptage sur les journaux JSON et sortie HTML.
- Trois semaines de recul confirment que le volume est suffisant pour
  travailler sur des tendances et pas seulement sur des anecdotes.

## 1er avril 2026 — Première activité enregistrée

- Premiers bots détectés moins de deux heures après l'ouverture du port 22.
- IP 2.57.122.208 : bot orienté cryptomonnaie, il teste des identifiants du type
  `validator`, `node`, `evm`, `evmbot`, `trader`. Un essai toutes les deux
  minutes environ, comportement clairement automatisé.
- Première authentification acceptée par le honeypot : 78.128.112.74, couple
  `root` / `welcome`, à 12 h 03.

## 1er avril 2026 — Configuration des ports

- `ssh.socket` désactivé pour libérer le port 22 : tant qu'il est actif, il
  garde la main sur le port et `sshd_config` est ignoré.
- SSH d'administration déplacé sur un port dédié, ouvert au préalable dans le
  pare-feu IONOS.
- Cowrie configuré pour écouter sur le port 22 via `authbind`.
- Règles iptables locales vidées : le filtrage est géré uniquement côté IONOS
  pour éviter deux jeux de règles qui se contredisent.

## 1er avril 2026 — Mise en service

- VPS IONOS Linux XS+ : 1 vCore, 1 Go de RAM, 10 Go de SSD, engagement 24 mois.
- Ubuntu Server 24.04 LTS, datacenter en Allemagne.
- Cowrie 2.9.16 installé avec pip dans un environnement virtuel Python 3.12.
- Compte système dédié `cowrie`, sans mot de passe.
- Service systemd configuré pour redémarrer automatiquement au boot.
- Pare-feu IONOS : seuls le port 22 et le port d'administration sont ouverts.
