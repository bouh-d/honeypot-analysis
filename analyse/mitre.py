"""Correspondance entre les commandes vues dans le honeypot et ATT&CK.

Les regles sont volontairement simples : une expression reguliere par
technique, appliquee sur la ligne de commande brute. Une meme commande peut
declencher plusieurs techniques (c'est frequent avec les one-liners des bots,
qui enchainent reconnaissance et telechargement dans la meme ligne).

Source des identifiants : https://attack.mitre.org/matrices/enterprise/linux/
"""

import re

REGLES = [
    (r"\b(uname|lscpu|nproc|hostnamectl)\b|/proc/(cpuinfo|version|meminfo)",
     "T1082", "System Information Discovery"),
    (r"\b(whoami|id|groups|last|lastlog|\bw\b)\b",
     "T1033", "System Owner/User Discovery"),
    (r"\b(ps|top|pgrep)\b",
     "T1057", "Process Discovery"),
    (r"\b(ls|find|du|df)\b",
     "T1083", "File and Directory Discovery"),
    (r"\b(ifconfig|netstat|route|arp)\b|\bip\s+(a|addr|link|route)\b",
     "T1016", "System Network Configuration Discovery"),
    (r"\b(wget|curl|tftp|ftpget)\b",
     "T1105", "Ingress Tool Transfer"),
    (r"\b(sh|bash|dash|busybox)\s+-c\b",
     "T1059.004", "Unix Shell"),
    (r"authorized_keys",
     "T1098.004", "SSH Authorized Keys"),
    (r"\b(useradd|adduser|usermod)\b",
     "T1136.001", "Create Account: Local Account"),
    (r"\bpasswd\b|/etc/shadow",
     "T1098", "Account Manipulation"),
    (r"\b(crontab|systemctl\s+enable)\b|/etc/cron",
     "T1053.003", "Scheduled Task/Job: Cron"),
    (r"\brm\s+-[rf]{1,2}\b|\bshred\b|history\s+-c|/dev/null\s*>\s*\.bash_history",
     "T1070.004", "Indicator Removal: File Deletion"),
    (r"\b(iptables|ufw|firewall-cmd)\b",
     "T1562.004", "Impair Defenses: Disable or Modify System Firewall"),
    (r"\b(xmrig|minerd|cpuminer|stratum\+tcp)\b|--donate-level",
     "T1496", "Resource Hijacking"),
    (r"\bsystemctl\s+(stop|disable|mask)\b|\bservice\s+\S+\s+stop\b",
     "T1489", "Service Stop"),
    (r"\b(kill|killall|pkill)\b",
     "T1489", "Service Stop"),
    (r"id_rsa|id_ed25519|\.ssh/config|\.aws/credentials",
     "T1552.001", "Unsecured Credentials: Credentials In Files"),
    (r"\bchmod\s+\+?[0-7x]",
     "T1222.002", "File and Directory Permissions Modification"),
    (r"\b(base64|xxd|openssl\s+enc)\b",
     "T1027", "Obfuscated Files or Information"),
    (r"\bfree\b|\b/proc/meminfo\b|\bvmstat\b",
     "T1082", "System Information Discovery"),
]

REGLES_COMPILEES = [(re.compile(motif, re.IGNORECASE), tid, nom)
                    for motif, tid, nom in REGLES]


def techniques(commande):
    """Renvoie la liste des (identifiant, nom) declenches par une commande."""
    trouvees = []
    for motif, tid, nom in REGLES_COMPILEES:
        if motif.search(commande) and (tid, nom) not in trouvees:
            trouvees.append((tid, nom))
    return trouvees
