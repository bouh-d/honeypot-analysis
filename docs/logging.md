# Journalisation

Cowrie écrit un objet JSON par ligne dans `var/log/cowrie/cowrie.json`. C'est
la seule sortie activée, et c'est la source unique de l'analyse.

Tous les exemples de cette page utilisent des adresses des plages réservées à la
documentation (RFC 5737) et des identifiants de session factices. Les mêmes
événements, exploitables par les tests, sont dans
[`sample-data/cowrie.json.exemple`](../sample-data/cowrie.json.exemple).

## Champs communs

Présents sur la quasi-totalité des événements :

| Champ | Type | Remarque |
|---|---|---|
| `eventid` | chaîne | type d'événement, préfixé `cowrie.` |
| `timestamp` | chaîne ISO 8601 | toujours en UTC, suffixe `Z`, précision microseconde |
| `session` | chaîne | identifiant hexadécimal, stable sur toute la session |
| `src_ip` | chaîne | adresse source |
| `message` | chaîne | version lisible de l'événement, destinée à l'humain |
| `sensor` | chaîne | nom du capteur, utile si plusieurs honeypots |
| `protocol` | chaîne | `ssh` ici, `telnet` étant désactivé |

Le champ `session` est la clé de jointure : il permet de reconstituer une visite
complète, de la connexion à la fermeture, en regroupant les lignes.

## Types d'événements

Observés sur la période, par ordre de fréquence décroissante :

| `eventid` | Signification | Champs utiles en plus |
|---|---|---|
| `cowrie.session.connect` | ouverture de connexion TCP | `src_port`, `dst_ip`, `dst_port` |
| `cowrie.session.closed` | fermeture, avec durée | `duration` |
| `cowrie.client.version` | bannière SSH annoncée par le client | `version` |
| `cowrie.client.kex` | algorithmes proposés à la négociation | `kexAlgs`, `encCS`, `macCS`, `hassh` |
| `cowrie.command.input` | commande saisie dans le shell simulé | `input` |
| `cowrie.login.failed` | tentative refusée | `username`, `password` |
| `cowrie.login.success` | tentative acceptée | `username`, `password` |
| `cowrie.session.params` | paramètres de terminal demandés | `arch` |
| `cowrie.direct-tcpip.request` | demande d'ouverture de tunnel TCP | `dst_ip`, `dst_port` |
| `cowrie.direct-tcpip.data` | données que le client voulait faire passer | `data` |
| `cowrie.direct-tcpip.ja4h` | empreinte JA4H de la requête tunnelée | `ja4h` |
| `cowrie.command.failed` | commande inconnue du shell simulé | `input` |
| `cowrie.session.file_download` | fichier déposé ou téléchargé | `url`, `outfile`, `shasum`, `destfile` |
| `cowrie.command.success` | commande reconnue et simulée | `input` |
| `cowrie.session.file_upload` | envoi par SFTP | `filename`, `shasum` |
| `cowrie.log.closed` | fin d'écriture de la transcription TTY | `ttylog`, `duration` |

Il n'y a pas de niveau de gravité dans `cowrie.json` : chaque ligne est un fait,
pas un diagnostic. Les notions de niveau (`INFO`, `ERROR`) n'existent que dans
`cowrie.log`, le journal applicatif en texte, qui sert au dépannage du service
et non à l'analyse.

## Exemples

Connexion entrante :

```json
{"eventid":"cowrie.session.connect","src_ip":"203.0.113.42","src_port":46474,
 "dst_ip":"198.51.100.10","dst_port":22,"session":"demo000000a1","protocol":"ssh",
 "message":"New connection: 203.0.113.42:46474 (198.51.100.10:22)",
 "sensor":"honeypot-demo","timestamp":"2026-09-14T21:35:17.102933Z"}
```

Tentative d'authentification acceptée :

```json
{"eventid":"cowrie.login.success","username":"root","password":"123456",
 "message":"login attempt [root/123456] succeeded","session":"demo000000a1",
 "src_ip":"203.0.113.42","protocol":"ssh","sensor":"honeypot-demo",
 "timestamp":"2026-09-14T21:35:18.441207Z"}
```

Commande saisie :

```json
{"eventid":"cowrie.command.input","input":"uname -a","session":"demo000000a1",
 "message":"CMD: uname -a","src_ip":"203.0.113.42","protocol":"ssh",
 "sensor":"honeypot-demo","timestamp":"2026-09-14T21:35:19.883010Z"}
```

Dépôt de fichier, avec empreinte :

```json
{"eventid":"cowrie.session.file_download","url":"http://203.0.113.77/charge.sh",
 "outfile":"var/lib/cowrie/downloads/0d1f...","shasum":"0d1f3c5b7a9e...",
 "session":"demo000000a1","src_ip":"203.0.113.42","protocol":"ssh",
 "sensor":"honeypot-demo","timestamp":"2026-09-14T21:35:24.004512Z"}
```

Demande de tunnel, enregistrée mais non relayée :

```json
{"eventid":"cowrie.direct-tcpip.request","dst_ip":"198.51.100.200","dst_port":80,
 "session":"demo000000a1","src_ip":"203.0.113.42","protocol":"ssh",
 "message":"direct-tcp connection request to 198.51.100.200:80",
 "sensor":"honeypot-demo","timestamp":"2026-09-14T21:35:30.117744Z"}
```

## Ce que l'analyse en fait

`analyse.py` ne conserve aucun événement. Il incrémente des compteurs selon
l'`eventid` :

| Agrégat | Construit à partir de |
|---|---|
| connexions, distribution par jour et par heure | `cowrie.session.connect` |
| IP distinctes, IP ayant obtenu une session | `src_ip` sur connexion et succès |
| tentatives, échecs, succès, classements d'identifiants | `cowrie.login.*` |
| commandes et correspondance ATT&CK | `cowrie.command.input` |
| fichiers déposés, empreintes, URL sources | `cowrie.session.file_download` |
| bannières clientes | `cowrie.client.version` |
| cibles de tunnel | `cowrie.direct-tcpip.request` |

Les lignes de commande sont tronquées à 200 caractères avant comptage. Certains
bots envoient des one-liners de plusieurs kilo-octets, avec des dizaines de
variantes de repli enchaînées par `||` ; les stocker en entier ferait gonfler la
mémoire sans améliorer le classement.

## Robustesse de lecture

Une ligne tronquée en fin de fichier est normale : elle correspond à un arrêt du
service, ou à un disque plein, survenu en pleine écriture.
`analyse.py` compte ces lignes, les signale sur la sortie d'erreur et continue.
C'est volontaire : refuser d'analyser cinq mois de données parce qu'une ligne
est coupée serait absurde.

Le cas s'est produit en vrai. La saturation du disque du 25 septembre 2026 a
laissé des écritures partielles, décrites dans [exploitation.md](exploitation.md).

## Rétention

| Donnée | Conservation |
|---|---|
| `cowrie.json.AAAA-MM-JJ` | conservés, compressés |
| `cowrie.log.AAAA-MM-JJ` | conservés, compressés |
| `downloads/` | conservés, nommés par SHA-256, jamais publiés |
| `tty/` | purgeables au-delà de 30 jours une fois les commandes extraites |
| agrégats `resultats/*.json` | versionnés dans ce dépôt |

Les journaux bruts ne quittent pas le serveur. Ce qui est publié, ce sont les
agrégats : ils pèsent une quinzaine de kilo-octets et restent comparables d'une
période à l'autre.
