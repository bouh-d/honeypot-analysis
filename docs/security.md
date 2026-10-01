# Sécurité

Un honeypot est une machine que l'on expose délibérément à du trafic hostile. La
question n'est donc pas de l'empêcher d'être attaquée, mais de limiter ce qu'une
compromission permettrait, et d'éviter qu'elle serve contre des tiers.

Cette page sépare strictement ce qui est en place de ce qui ne l'est pas. Les
manques sont listés, pas dissimulés.

## En place

### Pas d'exécution réelle

Cowrie tourne en `backend = shell`. Il simule un shell, un faux système de
fichiers et des sorties plausibles, sans jamais lancer de processus sur l'hôte.
Une commande `wget` saisie par un attaquant est enregistrée et la charge est
récupérée pour analyse, mais rien n'est exécuté.

C'est le contrôle le plus important du dispositif, et il rend sans objet des
classes entières de risques : évasion de conteneur, exécution de code,
persistance réelle. La surface restante est Cowrie lui-même, c'est-à-dire du
code Python et Twisted.

### Aucun relais TCP

`forward_tunnel` et `forward_redirect` sont à `false`. Cowrie accepte la demande
d'ouverture de tunnel au niveau du protocole, l'enregistre, et n'achemine aucun
octet. Sur la période, 87 052 demandes ont été reçues, visant très majoritairement
des adresses sur le port 80 : des tests de connectivité, destinés à vérifier que
la machine peut servir de proxy. Aucune n'a abouti.

Ce point mérite d'être vérifié après toute mise à jour de Cowrie : laisser le
relais actif transformerait le honeypot en proxy ouvert, donc en instrument
d'attaque contre des tiers.

### Compte non privilégié

Le service tourne sous le compte système `cowrie`, sans mot de passe. Pour
écouter sur le port 22 sans être root, `authbind` accorde l'autorisation au seul
port nécessaire :

```bash
ls -l /etc/authbind/byport/22   # appartient à cowrie, mode 770
```

Le choix d'`authbind` plutôt qu'une redirection `iptables` est lisible :
l'autorisation se constate avec un `ls`, pas en déroulant une table de NAT.

### Séparation honeypot / administration

Le `sshd` du système écoute sur un port haut dédié, distinct du 22 servi par
Cowrie. `ssh.socket` est désactivé, sans quoi il garderait la main sur le port 22
et la configuration de `sshd` serait ignorée. Le numéro du port d'administration
n'est pas publié dans ce dépôt.

### Pas de secret sur la machine exposée

Un seul module de sortie est activé, `output_jsonlog`, qui écrit en local. Les
quarante autres sont désactivés, ce qui évite d'avoir à stocker des jetons
d'API, des identifiants de base de données ou des clés d'accès sur une machine
destinée à être attaquée.

Rien n'est non plus exfiltré : pas de syslog distant, pas d'export vers un tiers.

### Surface réduite

Telnet est désactivé. Seul SSH est exposé. Les seuls ports en écoute sont le 22,
servi par Cowrie, et le port d'administration.

### Mises à jour

`unattended-upgrades` est actif, avec mise à jour automatique des listes et
application des correctifs de sécurité.

## Absent

Ces points sont des manques réels, constatés à l'audit. Ils ne sont pas
implémentés.

### Aucune supervision

Rien ne surveille l'espace disque ni la fraîcheur des journaux. C'est la cause
directe de l'incident du 25 septembre 2026, pendant lequel le honeypot est resté
six jours en apparence actif sans rien collecter
(voir [exploitation.md](exploitation.md)).

C'est le manque le plus grave, parce qu'il est aussi exploitable : saturer le
disque est à la portée d'un attaquant, et cela suffit à aveugler le capteur.

### Aucun durcissement systemd

L'unité ne comporte aucune directive d'isolation ni aucune limite :

| Directive | Valeur actuelle |
|---|---|
| `NoNewPrivileges` | non définie |
| `ProtectSystem` | non définie |
| `PrivateTmp` | non définie |
| `MemoryMax` | illimité |
| `CPUQuota` | non définie |

Sur une machine à 1 Go de RAM dont le processus occupe déjà environ 290 Mo,
l'absence de `MemoryMax` signifie qu'une fuite ou une charge anormale peut
emporter la machine entière.

### Aucun pare-feu local, trafic sortant libre

`iptables` et `nftables` ont toutes leurs politiques à `ACCEPT`, sans aucune
règle. Le filtrage repose uniquement sur le pare-feu de l'hébergeur, qui ne
couvre que l'entrant.

L'impact immédiat est faible, puisque Cowrie n'exécute rien et ne relaie rien :
il n'y a pas de charge utile pour émettre du trafic. Mais il n'y a aucune
défense en profondeur. Une vulnérabilité dans Cowrie ou dans Twisted
permettrait de sortir librement.

### Taille des dépôts non bornée

`download_limit_size` n'est pas défini, ce qui vaut « aucune limite ». Un
attaquant peut donc faire déposer un fichier arbitrairement grand. Combiné à
l'absence de supervision du disque, cela constitue un déni de service simple à
déclencher.

### Administration par mot de passe

| Réglage | Valeur | Remarque |
|---|---|---|
| `PermitRootLogin` | `yes` | connexion directe en root |
| `PasswordAuthentication` | `yes` | mot de passe accepté |
| `authorized_keys` | vide | aucune clé publique installée |
| `MaxAuthTries` | 6 | |
| `X11Forwarding` | `yes` | inutile sur un serveur sans interface |
| `AllowTcpForwarding` | `yes` | inutile pour cet usage |

L'accès administrateur repose donc entièrement sur un mot de passe, en root. Le
port non standard limite le bruit de fond mais ne constitue pas une protection.
Il n'y a pas de `fail2ban`.

### Pas de sauvegarde hors machine

Les journaux et les artefacts n'existent qu'à un seul endroit. Une perte du VPS
emporte six mois de collecte.

## Cowrie est identifiable

Trois versions système incohérentes sont annoncées selon l'endroit où un
attaquant regarde :

| Source | Valeur annoncée | Époque |
|---|---|---|
| Bannière SSH (`[ssh] version`) | `OpenSSH_9.2p1 Debian-2+deb12u3` | Debian 12, 2023 |
| Shell simulé (`[shell] ssh_version`) | `OpenSSH_7.9p1` | Debian 10, 2018 |
| Noyau annoncé (`[shell] kernel_version`) | `3.2.0-4-amd64` | Debian 7, 2012 |

Par ailleurs `honeyfs/etc/hostname` contient toujours `svr04`, la valeur livrée
par défaut avec Cowrie, alors que `cowrie.cfg` définit `hostname = ubuntu-server`.
Le shell affiche donc un nom, et `cat /etc/hostname` en renvoie un autre, qui est
de surcroît une signature connue.

Ce n'est pas théorique. Les données montrent que 10 % des tentatives
d'authentification utilisent les chaînes `345gs5662d34` et `3245gs5662d34`, qui
servent uniquement à détecter un honeypot : un serveur qui les accepte se
dénonce. La détection fait partie de l'outillage courant, et ces incohérences la
rendent triviale.

Corriger ces valeurs est à faible risque et figure dans les suites du
[README](../README.md).

## Priorités

Dans l'ordre, en tenant compte du rapport entre effet et effort :

1. supervision de l'espace disque et de la fraîcheur des journaux, avec alerte ;
2. `MemoryMax` et durcissement systemd sur le service ;
3. clé publique pour l'administration, puis `PasswordAuthentication no` et
   désactivation de `X11Forwarding` et `AllowTcpForwarding` ;
4. `download_limit_size` borné ;
5. alignement des versions annoncées et du nom d'hôte du faux système de
   fichiers ;
6. sauvegarde des agrégats hors machine.
