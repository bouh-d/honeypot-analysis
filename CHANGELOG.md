# Journal de bord

## 2 octobre 2026 — Retrait du rapport HTML

- Suppression de `rapport.py` et du rapport HTML qu'il générait. Les résultats
  sont présentés par le rapport rédigé en Markdown, et les visuels par des
  captures d'écran d'outils réels plutôt que par une page construite pour
  l'occasion.
- `analyse.py` neutralise désormais les caractères de contrôle des chaînes
  qu'il affiche au terminal : identifiants, mots de passe et commandes viennent
  des attaquants. Aucune séquence d'échappement dans les journaux de la
  période, mais 13 événements contiennent d'autres caractères de contrôle.
- Six captures d'écran dans `docs/captures/`, prises sur de vraies fenêtres :
  un terminal ouvert sur une session SSH au serveur, et l'application web de
  ntfy. Rejeu de deux sessions d'attaquants avec `playlog`, analyse en ligne de
  commande, supervision, alerte, et niveaux d'exposition mesurés par
  `systemd-analyze`. Aucune ne montre l'adresse du serveur ni le nom du canal
  d'alerte.

## 1er octobre 2026 — Incident disque, audit et remise à plat

### Incident

- Le disque a saturé le 24 septembre vers 21 h 40 UTC. Cowrie est resté actif
  mais ne pouvait plus écrire. Du 25 au 30 septembre, quelques centaines
  d'événements passaient encore chaque jour, tous dans les minutes suivant le
  basculement de minuit, puis plus rien. Le 1er octobre à 02 h 40,
  l'observateur de logs Twisted a cessé d'écrire toute ligne JSON valide.
- Panne détectée le 1er octobre à 12 h 15, plus de six jours plus tard. Rien ne
  l'a signalée. Chronologie complète dans
  [docs/exploitation.md](docs/exploitation.md).
- Espace libéré (cache APT), service redémarré, collecte vérifiée nominale.
- Compression de l'ensemble des journaux quotidiens : de 5,0 Go à 383 Mo,
  disque ramené de 100 % à 41 %. Script ajouté au dépôt
  (`scripts/compresser-journaux.sh`).
- La fenêtre du 24 septembre 21 h 40 au 1er octobre 12 h 15 est inexploitable.
  Le rapport de référence s'arrête au dernier événement enregistré avant la
  saturation.

### Supervision

- `scripts/surveiller.sh`, lancé toutes les quinze minutes par une minuterie
  systemd. Au-delà de 80 % d'occupation du disque, il compresse les journaux et
  n'alerte que si cela ne suffit pas. Il alerte aussi quand le dernier
  événement JSON valide a plus de trente minutes.
- Alertes poussées sur téléphone par ntfy, sans doublon : une à l'apparition
  de l'anomalie, un rappel toutes les six heures, un message au retour à la
  normale.
- Sept scénarios testés avant la mise en service, dont le cas exact de
  l'incident. Rejoué sur les journaux de la panne, le contrôle de fraîcheur se
  serait déclenché le 24 septembre à 22 h 10 UTC.
- Service confiné par systemd : niveau d'exposition de 3,8 selon
  `systemd-analyze security`, contre 9,2 pour `cowrie.service`.

### Correction d'un double comptage

- Les fichiers `archive_*.json.gz` produits à côté des journaux quotidiens se
  sont révélés être des doublons : 100 % de leurs événements figurent déjà
  dans le fichier quotidien correspondant. `analyse.py` les lisait tous les
  deux, ce qui gonflait les chiffres publiés d'environ 1 %. Ils sont désormais
  exclus.

### Corrections du code

- `rapport.py` plantait (`ValueError`) sur toute période sans connexion.
- `mitre.py` déclarait deux fois T1082 et T1489, et contenait deux expressions
  régulières sans effet (`\b` imbriqué, `\b` devant `/`).
- Clé composite `"%s|%s"` recollée puis redécoupée remplacée par un tuple.
- Diagnostics passés sur `logging`, annotations de type ajoutées.
- Comportement vérifié inchangé : ancienne et nouvelle version donnent des
  sorties strictement identiques sur les mêmes 180 fichiers.

### Dépôt

- Documentation d'architecture, d'exploitation, de journalisation, de sécurité
  et modèle de menace.
- Trois règles Sigma tirées des comportements observés.
- 44 tests, CI GitHub Actions (lint, tests, shellcheck, validation Sigma et
  Compose).
- Instance de démonstration en conteneur, non exposée.
- Jeu d'événements synthétiques en plages d'adresses de documentation.

### Constats d'audit non corrigés

Relevés mais laissés en l'état, parce qu'ils touchent la production et
demandent un redémarrage ou un changement d'accès. Détail dans
[docs/security.md](docs/security.md).

- Le port 22 est fixé par un patch du code source de Cowrie et non par la
  configuration, ce qui ne survivrait pas à une mise à jour.
- Une ligne `listen_endpoints` sous `[backend_pool]` est sans effet.
- Trois versions système incohérentes sont annoncées, et
  `honeyfs/etc/hostname` est resté à la valeur par défaut `svr04`.
- Aucun durcissement systemd ni limite de ressources.
- Administration en root par mot de passe.

## 4 septembre 2026 — Outillage d'analyse

- Réécriture complète du script d'analyse : lecture en flux ligne par ligne au
  lieu du chargement intégral en mémoire. Les journaux dépassaient les 4 Go, la
  version précédente ne passait plus sur un VPS à 1 Go de RAM.
- Prise en charge des fichiers `.gz` sans décompression préalable.
- Ajout d'une correspondance entre les commandes observées et les techniques
  MITRE ATT&CK (`analyse/mitre.py`).
- Séparation de l'agrégation (`analyse.py`) et de la mise en forme
  (`rapport.py`) : l'agrégat JSON est archivé, le HTML se régénère à volonté.
- Premier rapport, du 1er avril au 4 septembre. Ses chiffres incluaient le
  double comptage des archives, corrigé le 1er octobre.
- Disque à 90 % d'occupation, sans action à ce moment-là.

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
- Cowrie mis en écoute sur le port 22 via `authbind`.
- Valeur par défaut du port modifiée dans
  `src/twisted/plugins/cowrie_plugin.py`, ligne 244 : `2222` remplacé par `22`.
- Règles iptables locales vidées : le filtrage est géré uniquement côté IONOS
  pour éviter deux jeux de règles qui se contredisent.

## 1er avril 2026 — Mise en service

- VPS IONOS Linux XS+ : 1 vCore, 1 Go de RAM, 10 Go de SSD, engagement 24 mois.
- Ubuntu Server 24.04 LTS, datacenter en Allemagne.
- Cowrie 2.9.16 installé avec pip dans un environnement virtuel Python 3.12.
- Compte système dédié `cowrie`, sans mot de passe.
- Service systemd configuré pour redémarrer automatiquement au boot.
- Pare-feu IONOS : seuls le port 22 et le port d'administration sont ouverts.
