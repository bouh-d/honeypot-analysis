# Correspondance ATT&CK

Le honeypot ne fait que journaliser des lignes de commande. Pour en tirer
quelque chose de comparable d'un trimestre à l'autre, chaque commande est
confrontée à une liste d'expressions régulières qui la rattachent à une ou
plusieurs techniques de la matrice Enterprise (plateforme Linux).

Les règles sont dans [`analyse/mitre.py`](../analyse/mitre.py). Une commande
peut déclencher plusieurs techniques : les bots enchaînent souvent
reconnaissance et téléchargement dans une seule ligne.

## Règles appliquées

| Technique | Déclencheur (résumé) |
|---|---|
| T1082 System Information Discovery | `uname`, `lscpu`, `nproc`, `/proc/cpuinfo`, `free` |
| T1033 System Owner/User Discovery | `whoami`, `id`, `groups`, `last`, `w` |
| T1057 Process Discovery | `ps`, `top`, `pgrep` |
| T1083 File and Directory Discovery | `ls`, `find`, `du`, `df` |
| T1016 System Network Configuration Discovery | `ifconfig`, `netstat`, `ip a`, `route`, `arp` |
| T1105 Ingress Tool Transfer | `wget`, `curl`, `tftp`, `ftpget` |
| T1059.004 Unix Shell | `sh -c`, `bash -c`, `busybox -c` |
| T1098.004 SSH Authorized Keys | toute mention de `authorized_keys` |
| T1136.001 Create Account: Local Account | `useradd`, `adduser`, `usermod` |
| T1098 Account Manipulation | `passwd`, `/etc/shadow` |
| T1053.003 Scheduled Task/Job: Cron | `crontab`, `/etc/cron`, `systemctl enable` |
| T1070.004 Indicator Removal: File Deletion | `rm -rf`, `shred`, `history -c` |
| T1562.004 Disable or Modify System Firewall | `iptables`, `ufw`, `firewall-cmd` |
| T1496 Resource Hijacking | `xmrig`, `minerd`, `stratum+tcp`, `--donate-level` |
| T1489 Service Stop | `systemctl stop`, `service … stop`, `kill`, `pkill` |
| T1552.001 Unsecured Credentials: Credentials In Files | `id_rsa`, `id_ed25519`, `.aws/credentials` |
| T1222.002 File and Directory Permissions Modification | `chmod` |
| T1027 Obfuscated Files or Information | `base64`, `xxd`, `openssl enc` |

## Ce qui ressort du 1er avril au 4 septembre 2026

| Technique | Occurrences |
|---|---:|
| T1082 System Information Discovery | 124 683 |
| T1070.004 Indicator Removal: File Deletion | 43 583 |
| T1098.004 SSH Authorized Keys | 37 460 |
| T1033 System Owner/User Discovery | 8 833 |
| T1222.002 File and Directory Permissions Modification | 5 959 |
| T1059.004 Unix Shell | 5 936 |
| T1083 File and Directory Discovery | 3 187 |
| T1057 Process Discovery | 1 272 |
| T1489 Service Stop | 560 |
| T1053.003 Scheduled Task/Job: Cron | 547 |
| T1016 System Network Configuration Discovery | 503 |
| T1105 Ingress Tool Transfer | 297 |
| T1136.001 Create Account: Local Account | 186 |
| T1098 Account Manipulation | 67 |
| T1496 Resource Hijacking | 2 |

La forme du classement en dit plus que les valeurs absolues. La reconnaissance
système écrase tout le reste : la quasi-totalité des sessions se limite à un
`uname` et repart. Vient ensuite un bloc très homogène — suppression de `.ssh`,
pose d'une clé, `chmod` — qui correspond à une seule et même routine
d'installation de porte dérobée, comptée trois fois parce qu'elle déclenche
trois techniques.

À l'inverse, le téléchargement d'outils (T1105) et le minage (T1496) sont
marginaux. Deux explications possibles, que la suite de la collecte devrait
permettre de départager : soit la charge utile n'arrive qu'après une phase de
validation que le honeypot ne franchit pas de façon convaincante, soit les
opérateurs se contentent de collecter des accès pour les revendre.

## Limites

- Une expression régulière ne comprend pas ce qu'elle lit. `kill` compté comme
  T1489 est souvent un simple nettoyage de processus fils, pas un arrêt de
  service.
- Les one-liners longs, avec des dizaines de solutions de repli enchaînées par
  `||`, gonflent T1082 : la même intention est comptée autant de fois qu'il y a
  de variantes de `uname` dans la ligne.
- Rien n'est rattaché aux tactiques d'accès initial : côté honeypot, l'accès est
  toujours obtenu par force brute sur des identifiants (T1110), ce qui est
  mesuré à part dans les statistiques d'authentification.
