# Honeypot SSH — Cowrie

Étude sur deux ans des attaques SSH réelles subies par un VPS exposé sur
Internet. Le honeypot tourne en continu depuis le 1er avril 2026 et enregistre
tout ce que les bots tentent : identifiants testés, commandes lancées une fois
« dans » la machine, fichiers déposés, tunnels ouverts.

Ce dépôt contient les scripts d'analyse des journaux, les notes de déploiement
et les résultats agrégés. Les journaux bruts et les binaires capturés restent
sur le serveur.

## Le dispositif

| | |
|---|---|
| Hébergeur | IONOS, datacenter Allemagne |
| Machine | 1 vCore, 1 Go de RAM, 10 Go de SSD |
| Système | Ubuntu Server 24.04 LTS |
| Honeypot | Cowrie 2.9.16 (Python 3.12), exposé sur le port 22 |
| Administration | SSH déplacé sur un autre port, ouvert dans le pare-feu IONOS |

La procédure complète est dans [docs/installation.md](docs/installation.md).

## Où en est la collecte

Chiffres arrêtés au 4 septembre 2026, soit 157 jours d'exposition continue.

| | |
|---|---|
| Connexions entrantes | 690 259 |
| Adresses IP distinctes | 15 400 |
| Tentatives d'authentification | 688 917 |
| Commandes exécutées dans le shell simulé | 308 969 |
| Sessions ayant réellement lancé des commandes | 208 094 |
| Fichiers déposés | 38 130 |
| Tentatives d'utilisation en relais TCP | 71 275 |

Soit environ 4 400 connexions par jour en moyenne, avec une progression nette :
68 000 connexions en avril contre 200 000 en août.

Analyse détaillée : [docs/rapport-2026-04_2026-08.md](docs/rapport-2026-04_2026-08.md).
Correspondance avec les techniques ATT&CK : [docs/mitre-attck.md](docs/mitre-attck.md).

## Contenu du dépôt

```
analyse/       scripts Python (lecture des journaux, rapport HTML, ATT&CK)
deploiement/   unité systemd et réglages Cowrie effectivement utilisés
docs/          installation, correspondance ATT&CK, rapports rédigés
resultats/     agrégats JSON et rapport HTML généré
```

## Utilisation

Aucune dépendance en dehors de la bibliothèque standard de Python 3.

```bash
# agreger les journaux (dossier ou liste de fichiers, .gz compris)
python3 analyse/analyse.py /home/cowrie/cowrie/var/log/cowrie -o resultats/stats.json

# construire le rapport HTML a partir de l'agregat
python3 analyse/rapport.py resultats/stats.json -o resultats/rapport.html
```

`analyse.py` lit les fichiers ligne par ligne et ne conserve que des compteurs :
les 4 Go de journaux accumulés depuis avril passent sans problème sur le VPS
à 1 Go de RAM.

## Ce que ça montre

`root` concentre 47 % des identifiants testés. Le reste de la liste tient en
quelques lignes : `admin`, `ubuntu`, `user`, `test`, `deploy`. Côté mots de
passe, c'est le mot de passe vide qui arrive en tête, suivi de `admin`,
`123456`, `123`, `1234`, `password`.

Deux chaînes reviennent en masse, `345gs5662d34` et `3245gs5662d34`, à elles
seules 10 % des tentatives. Ce sont des sondes de détection de honeypot : le
bot présente un identifiant qu'aucun système réel ne peut connaître, et si le
serveur l'accepte quand même, il sait qu'il parle à un leurre et s'en va.

Une fois la session ouverte, la commande la plus fréquente est
`echo -e "\x6F\x6B"` — soit « ok », un simple test de shell. Vient ensuite la
reconnaissance système (`uname`), puis la pose d'une clé SSH :
`rm -rf .ssh && mkdir .ssh && echo "ssh-rsa …" > .ssh/authorized_keys`,
37 000 fois, souvent précédée d'un `chattr -ia .ssh`. La clé déposée est
pratiquement toujours la même, ce qui laisse penser à une infrastructure unique
derrière des milliers d'adresses sources.

Enfin, l'activité ne dort jamais : entre l'heure la plus chargée (01 h UTC) et
la plus calme (14 h UTC), le rapport n'est que de 2,3. Rien à voir avec un
rythme humain. Et `SSH-2.0-Go` domine largement les bannières annoncées, devant
`libssh` et `libssh2` — un client OpenSSH standard est l'exception.

## Calendrier

| Période | État |
|---|---|
| Avril – juin 2026 | Déploiement, premiers relevés |
| Juillet – septembre 2026 | Outillage d'analyse, correspondance ATT&CK |
| Octobre 2026 – mars 2027 | Enrichissement géographique, croisement AbuseIPDB |
| Avril 2027 – mars 2028 | Comparaison année 1 / année 2, rapport final |

## Licence

Code sous licence MIT (voir [LICENSE](LICENSE)). Projet personnel, monté et
tenu à jour seul.
