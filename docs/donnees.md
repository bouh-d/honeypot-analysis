# Jeu de données

Les journaux du honeypot sont publiés en données ouvertes, sous licence
[CC BY 4.0](../LICENCE-DONNEES.md). Ils sont réutilisables librement, y compris à
des fins commerciales, à condition de citer la source.

## Téléchargement

Les fichiers sont joints à une *release* GitHub plutôt que versionnés dans le
dépôt : 130 Mo de fichiers compressés alourdiraient chaque clonage, pour
toujours.

[Release `donnees-2026-04-01-au-2026-10-01`](https://github.com/bouh-d/honeypot-analysis/releases/tag/donnees-2026-04-01-au-2026-10-01)

| Fichier | Contenu | Événements |
|---|---|---:|
| `cowrie-2026-04.tar` | 1er au 30 avril | 411 611 |
| `cowrie-2026-05.tar` | mai | 521 538 |
| `cowrie-2026-06.tar` | juin | 943 447 |
| `cowrie-2026-07.tar` | juillet | 1 238 729 |
| `cowrie-2026-08.tar` | août | 1 338 364 |
| `cowrie-2026-09.tar` | septembre, panne incluse | 941 342 |
| `cowrie-2026-10.tar` | 1er octobre | 67 232 |
| `SHA256SUMS` | empreintes des archives | |

```bash
sha256sum -c SHA256SUMS
for f in cowrie-2026-*.tar; do tar xf "$f"; done
```

Chaque archive contient un fichier par jour, `cowrie.json.AAAA-MM-JJ.gz` : un
événement JSON par ligne, compressé avec gzip. C'est le format qu'écrit Cowrie,
décrit dans [logging.md](logging.md).

## Ce que contient le jeu

| | |
|---|---|
| Période | du 1er avril au 1er octobre 2026 inclus, 184 jours, heures UTC |
| Événements | 5 462 263 |
| Connexions | 835 165 |
| Adresses IP sources distinctes | 17 987 |
| Tentatives d'authentification | 819 437 |
| Commandes saisies | 369 296 |
| Capteur | un seul : Cowrie 2.9.16, SSH sur le port 22, VPS en Allemagne |

Tous les types d'événements de Cowrie sont présents : connexions, bannières et
algorithmes des clients, tentatives d'authentification, commandes, dépôts de
fichiers avec leur empreinte SHA-256, demandes de tunnel et leur contenu.

## Ce qui a été modifié

Trois transformations, et aucune autre. Elles sont faites par
[`analyse/exporter.py`](../analyse/exporter.py), testé dans
[`tests/test_exporter.py`](../tests/test_exporter.py).

**L'adresse du capteur est remplacée par `192.0.2.1`**, une adresse réservée à
la documentation (RFC 5737). Le remplacement porte sur tous les champs, pas
seulement sur l'adresse de destination : certains outils d'attaque injectent
l'adresse visée ailleurs. Sur la période, elle a été remplacée dans
188 bannières de clients SSH, 12 mots de passe essayés et 3 commandes, en plus
des 835 165 connexions.

**Les champs `message`, `sensor` et `uuid` sont retirés.** `message` recopie les
autres champs sous forme de texte, adresse du capteur comprise. `sensor` et
`uuid` sont constants et propres à l'installation.

**Les lignes illisibles sont écartées.** Il y en a 12, presque toutes écrites
pendant la panne de septembre, quand le disque plein coupait les écritures en
plein milieu.

Tout le reste est publié tel qu'enregistré : adresses IP sources, identifiants
et mots de passe essayés, commandes, URL de téléchargement, empreintes.

## Ce qui n'est pas publié

| | Raison |
|---|---|
| Les 267 binaires capturés | programmes malveillants actifs ; leurs empreintes SHA-256 sont dans les événements |
| Les transcriptions de terminal | elles montrent l'adresse du capteur : le faux `ifconfig` de Cowrie l'affiche, et des attaquants la tapent eux-mêmes |
| Le journal applicatif `cowrie.log` | doublon du JSON, en texte, adresse du capteur comprise |
| Les fichiers `archive_*.json.gz` | doublons intégraux des fichiers quotidiens |

## Qualité des données

**La panne de septembre est dans le jeu.** Du 24 septembre à 21 h 40 au
1er octobre à 12 h 15, le disque était plein et la collecte quasi nulle. Seuls
quelques centaines d'événements par jour passaient, dans les minutes suivant le
basculement de minuit. Le 1er octobre entre minuit et 2 h 40, une rafale de
40 585 événements correspond vraisemblablement à des sessions qui échouaient
aussitôt ouvertes et à des bots qui se reconnectaient en boucle. Cette fenêtre
est à écarter de toute analyse de tendance. Chronologie détaillée dans
[exploitation.md](exploitation.md).

**Le taux d'authentification réussie est un réglage, pas une mesure.** Cowrie
accepte `root` avec presque n'importe quel mot de passe. Voir le
[rapport](rapport-2026-04_2026-09.md).

**Un seul capteur, une seule adresse, un seul hébergeur.** Les chiffres
décrivent ce qu'a reçu cette machine, pas l'ensemble d'Internet.

**Faible interaction.** Rien ne s'exécute : on observe les intentions, jamais ce
qui se passerait après l'exécution d'une charge.

## Adresses IP sources

Elles sont publiées telles qu'enregistrées. Une grande partie appartient
vraisemblablement à des machines compromises — box, caméras, serveurs mal
protégés — dont les propriétaires ignorent tout de cette activité. Une adresse
vue ici à une date donnée ne désigne pas forcément le même équipement, ni le
même propriétaire, aujourd'hui. Ces données sont destinées à la détection et à
la recherche.

## Retrouver les résultats publiés

Le rapport s'arrête au 24 septembre, avant la panne. À partir des fichiers
extraits, la commande suivante redonne à l'identique
[`resultats/stats-2026-04-01_2026-09-24.json`](../resultats/stats-2026-04-01_2026-09-24.json),
date de génération mise à part :

```bash
python3 analyse/analyse.py \
    cowrie.json.2026-0[4-8]-*.gz \
    cowrie.json.2026-09-[01]?.gz cowrie.json.2026-09-2[0-4].gz \
    -o stats.json
```

Ce contrôle a été fait avant publication.

## Citer

> bouh-d, *Honeypot SSH Cowrie : journaux du 1er avril au 1er octobre 2026*,
> https://github.com/bouh-d/honeypot-analysis, licence CC BY 4.0.

## Publier une nouvelle période

Sur le serveur, l'adresse du capteur étant passée en argument pour ne jamais
figurer dans le dépôt :

```bash
python3 analyse/exporter.py /home/cowrie/cowrie/var/log/cowrie \
    --adresse-capteur <adresse du serveur> \
    --debut 2026-10-02 --fin 2026-12-31 -o /tmp/export --par-mois
```

Les archives sont reproductibles : à journaux identiques, l'export redonne les
mêmes octets, donc les mêmes empreintes.
