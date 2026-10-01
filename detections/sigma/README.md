# Règles Sigma

Trois règles écrites à partir de comportements effectivement observés dans les
journaux, et non à partir d'un catalogue générique. Chacune correspond à un
schéma qui ressort des données entre avril et septembre 2026.

| Fichier | Détecte | Occurrences observées | Niveau |
|---|---|---:|---|
| `pose-cle-ssh-authorized-keys.yml` | persistance par clé SSH (T1098.004) | ~42 000 | high |
| `sonde-detection-honeypot.yml` | reconnaissance de leurre (T1592) | ~82 000 | informational |
| `telechargement-binaire-multi-architecture.yml` | charge Mirai multi-plateforme (T1105) | 29 URL servant un ELF | high |

## Source de journaux

Cowrie ne figure pas dans la taxonomie officielle Sigma. Les règles déclarent
donc une source personnalisée :

```yaml
logsource:
  product: cowrie
  service: ssh
```

Les champs utilisés sont ceux de `cowrie.json`, documentés dans
[../../docs/logging.md](../../docs/logging.md) : `eventid`, `input`, `username`,
`password`, `url`, `shasum`, `src_ip`, `session`, `timestamp`. Aucune
normalisation intermédiaire n'est appliquée, les règles s'écrivent directement
sur le format produit par Cowrie.

## Conversion

Les règles sont au format Sigma standard et se convertissent avec `sigma-cli` :

```bash
pip install sigma-cli
sigma convert -t lucene detections/sigma/        # Elasticsearch
sigma convert -t splunk detections/sigma/        # Splunk
```

La conversion suppose que les journaux ont été ingérés dans l'outil visé, en
conservant les noms de champs d'origine. Rien de tel n'est en place sur ce
dispositif : il n'y a ni Elasticsearch ni collecteur, l'analyse se fait hors
ligne avec les scripts du dépôt. Ces règles sont donc fournies comme traduction
réutilisable des observations, pas comme chaîne de détection opérationnelle.

## Ce que les règles ratent, mesuré

La règle de téléchargement a été confrontée aux 29 URL distinctes qui ont
réellement servi un binaire ELF sur la période.

| Version de la règle | Détectées |
|---|---:|
| suffixes classiques seuls (`.mips`, `.arm7`…) | 8 / 29 |
| suffixes et noms d'architecture sans séparateur | 27 / 29 |

La première version, fondée sur les seuls suffixes de la famille Mirai, ne
voyait qu'un binaire sur quatre. Les autres sont servis sous des noms comme
`krane_mips` ou `xnxnxnxnxnxnxnxnaarch64`, sans point. La version actuelle les
couvre.

Les deux URL qui échappent encore sont `…/meow`. Le nom ne contient aucune
indication d'architecture : aucune règle fondée sur le nom ne peut les
attraper. Pour ces cas, la détection par empreinte SHA-256 est la seule
fiable, mais elle ne reconnaît que ce qui est déjà connu.

## Limites communes

Les trois règles reposent sur de la correspondance de chaînes dans des champs
contrôlés par l'attaquant. Elles sont contournables par de l'obscurcissement
trivial : encodage en base64, variables shell, renommage. Le cas `meow`
ci-dessus montre que ce n'est pas théorique.

Le niveau `informational` de la règle de détection de honeypot est volontaire :
l'événement n'est pas une attaque, c'est de la reconnaissance. Son intérêt est de
mesurer la part de trafic que le dispositif ne retiendra pas.
