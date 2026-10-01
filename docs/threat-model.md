# Modèle de menace

Le dispositif est volontairement exposé, donc l'hypothèse de départ est qu'il
sera attaqué en permanence. C'est le cas : environ 4 660 connexions hostiles par
jour. Ce document ne traite pas du risque d'être attaqué, mais de ce qu'une
attaque réussie permettrait.

Chaque mesure est marquée **en place** ou **absente**, conformément à ce qui a
été constaté à l'audit. Les mesures absentes ne sont pas des descriptions du
système, ce sont des recommandations.

## Biens à protéger

| Bien | Pourquoi il compte |
|---|---|
| Intégrité des données collectées | c'est le produit du projet ; six mois de collecte ne se refont pas |
| Disponibilité de la collecte | un capteur aveugle est inutile, et le silence ne se voit pas |
| Hôte VPS | une prise de contrôle réelle transformerait le capteur en plateforme d'attaque |
| Accès administrateur | sa compromission donne tout le reste |
| Réputation de l'adresse IP | si le serveur sert à attaquer des tiers, la responsabilité est celle du propriétaire |
| Artefacts capturés | 267 binaires hostiles, à ne pas exécuter ni redistribuer par inadvertance |

Il n'y a volontairement pas de donnée personnelle dans le périmètre, puisque
le honeypot ne traite aucun utilisateur légitime. Les seules données collectées
proviennent des attaquants eux-mêmes.

## Scénarios

### 1. Saturation du disque, aveuglement du capteur

**Réalisé le 24 septembre 2026.** Le disque est passé à 100 %, et le honeypot est
resté plus de six jours en apparence actif sans rien enregistrer. Un attaquant peut
provoquer la même chose intentionnellement, puisque les dépôts de fichiers ne
sont pas bornés et les transcriptions de terminal s'écrivent à chaque session.

Probabilité élevée, impact élevé sur la disponibilité de la collecte.

| Mesure | État |
|---|---|
| Compression des journaux, facteur 25 | **en place** |
| Compression automatique au-delà de 80 % d'occupation | **en place** |
| Alerte si la compression ne suffit pas | **en place** |
| Alerte sur la fraîcheur du dernier événement valide | **en place** |
| Purge des transcriptions anciennes | **absente**, commande documentée mais jamais exécutée |
| `download_limit_size` borné | **absente** |

La supervision ne couvre pas tout : elle tourne sur la machine qu'elle
surveille. Une panne de l'hôte entier ne serait signalée par rien.

### 2. Évasion vers l'hôte réel

Un attaquant cherche à sortir du shell simulé pour exécuter du code sur le VPS.

La voie la plus directe est fermée : `backend = shell` n'exécute jamais rien. Il
faudrait une vulnérabilité dans Cowrie ou Twisted, suivie d'une élévation depuis
le compte `cowrie`.

Probabilité faible, impact très élevé.

| Mesure | État |
|---|---|
| Aucune exécution réelle de commande | **en place** |
| Compte système dédié non privilégié | **en place** |
| `authbind` plutôt qu'un service lancé en root | **en place** |
| Correctifs de sécurité automatiques | **en place** |
| `NoNewPrivileges`, `ProtectSystem`, `PrivateTmp` | **absentes** |
| Isolation en conteneur ou machine virtuelle | **absente** |

### 3. Utilisation du honeypot contre un tiers

C'est le scénario le plus gênant juridiquement. La machine sert de relais ou
de plateforme pour attaquer quelqu'un d'autre. Les données montrent que c'est
recherché activement, avec 87 052 demandes d'ouverture de tunnel.

| Mesure | État |
|---|---|
| `forward_tunnel = false`, `forward_redirect = false` | **en place** |
| Aucune exécution de charge utile | **en place** |
| Filtrage du trafic sortant | **absent** |

Les deux premières mesures empêchent le relais et l'exécution, pas toute
émission. Pour capturer une charge, Cowrie la télécharge réellement, vers
l'adresse que l'attaquant a indiquée à `wget` ou `curl`. Un attaquant peut donc
faire envoyer au serveur une requête vers la destination de son choix, y
compris un tiers. L'abus reste limité, une requête par commande et sans relais
de trafic, mais rien n'en borne la destination. Le filtrage sortant manquant
rattraperait à la fois cet usage et une régression de configuration ou une
vulnérabilité.

### 4. Compromission de l'accès administrateur

L'administration se fait en root, par mot de passe, sur un port non standard.
Le port réduit le bruit de fond mais ne protège de rien, un simple balayage de
ports suffit à le trouver.

Probabilité faible à moyenne, impact total.

| Mesure | État |
|---|---|
| Port distinct de celui du honeypot | **en place** |
| `PermitEmptyPasswords no` | **en place** |
| Authentification par clé publique | **absente** |
| `PasswordAuthentication no` | **absente** |
| Limitation des tentatives (`fail2ban`) | **absente** |
| Désactivation de `X11Forwarding` et `AllowTcpForwarding` | **absente** |

C'est, avec la supervision, le chantier le plus rentable.

### 5. Épuisement des ressources de la machine

Une charge anormale sur un VPS à 1 vCore et 1 Go de RAM, dont le processus
occupe déjà 290 Mo. Pas besoin d'une attaque sophistiquée.

| Mesure | État |
|---|---|
| `idle_timeout` à 180 s, `authentication_timeout` à 120 s | **en place** |
| `MemoryMax`, `CPUQuota` | **absentes** |
| `Restart=on-failure` | **en place**, mais ne couvre pas le cas d'un processus vivant et bloqué |
| Contrôle de fraîcheur des journaux | **en place**, couvre justement ce cas |

### 6. Falsification des traces

Un attaquant qui voudrait effacer son passage. Les commandes de suppression sont
d'ailleurs très présentes dans les données : 50 299 occurrences de la technique
T1070.004.

Le risque est ici structurellement faible, car les commandes sont simulées :
`rm -rf` ne supprime rien, et les journaux sont écrits par le processus `cowrie`
dans une arborescence à laquelle le shell simulé n'a aucun accès réel.

| Mesure | État |
|---|---|
| Journaux hors d'atteinte du shell simulé | **en place** |
| Horodatage UTC uniforme | **en place** |
| Envoi des journaux vers un collecteur distant | **absent** |
| Sauvegarde hors machine | **absente** |

Sans copie distante, la perte du VPS reste une perte totale, même sans attaque.

### 7. Injection dans les journaux

Les identifiants, mots de passe et commandes sont des chaînes contrôlées par
l'attaquant, et elles finissent dans les journaux puis dans les rapports.

| Mesure | État |
|---|---|
| Sortie JSON, échappement assuré par la bibliothèque standard | **en place** |
| Échappement HTML de toute valeur dans le rapport (`html.escape`) | **en place** |
| Troncature des commandes à 200 caractères | **en place** |
| Lecture tolérante aux lignes illisibles | **en place** |

C'est traité. Le rapport HTML échappe systématiquement les valeurs issues des
journaux, y compris les noms d'utilisateur et les lignes de commande.

### 8. Détection du honeypot

Pas une atteinte au système, mais une atteinte à sa finalité : un attaquant qui
reconnaît le leurre s'en va, et la collecte perd en représentativité.

C'est mesuré : 10 % des tentatives sont des sondes de détection. Les
incohérences de version et le nom d'hôte resté au défaut rendent la
reconnaissance facile. Détail dans [security.md](security.md).

| Mesure | État |
|---|---|
| Écoute sur le port 22 plutôt que le 2222 par défaut | **en place** |
| `hostname` personnalisé dans `cowrie.cfg` | **en place** |
| Cohérence des versions annoncées | **absente** |
| `honeyfs/etc/hostname` aligné | **absent** |

## Hors périmètre

- Les attaques contre le pare-feu et l'hyperviseur de l'hébergeur.
- Le poste de travail depuis lequel l'administration est effectuée.
- Ce qui se passerait après l'exécution réelle d'une charge utile : par
  construction, un honeypot à faible interaction ne l'observe pas.

## Synthèse

Les risques de compromission réelle sont bas, et pour une raison simple :
l'absence d'exécution. Ce que l'audit met en évidence, ce n'est pas un problème
de confidentialité ou d'intégrité, c'est un problème de **disponibilité et de
supervision**. Le dispositif a déjà échoué une fois sur ce terrain, en silence,
pendant plus de six jours. Les deux alertes qui manquaient alors, sur le disque
et sur la fraîcheur des journaux, sont en place depuis. Restent la limite
mémoire sur `cowrie.service` et une sonde extérieure à la machine.
