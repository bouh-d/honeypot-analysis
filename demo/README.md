# Instance de démonstration

Permet de voir fonctionner le dispositif et de produire des journaux au format
attendu, sans rien exposer sur Internet.

**Ce n'est pas la production.** Le honeypot réel tourne sans conteneur,
directement en service systemd sur un VPS, sur le port 22, avec `authbind`. Voir
[../docs/architecture.md](../docs/architecture.md). Les paramètres propres à
l'hôte exposé ne figurent pas dans ce dépôt.

## Lancer

```bash
cd demo
docker compose up -d
docker compose ps
```

Le port est lié à `127.0.0.1:2222`. Rien n'est joignable depuis l'extérieur de
la machine.

## Se connecter

Depuis la même machine, en jouant le rôle de l'attaquant :

```bash
ssh -p 2222 root@127.0.0.1
```

La configuration Cowrie par défaut accepte `root` avec presque n'importe quel
mot de passe. Vous obtenez une invite, un faux système de fichiers, et rien ne
s'exécute réellement. Essayez `uname -a`, `cat /proc/cpuinfo`, `wget`, ou la
routine de pose de clé relevée en production :

```bash
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa EXEMPLE" > .ssh/authorized_keys
```

## Récupérer les journaux et les analyser

```bash
docker compose cp cowrie-demo:/cowrie/cowrie-git/var/log/cowrie/cowrie.json ./cowrie.json
python3 ../analyse/analyse.py ./cowrie.json -o ./stats.json
python3 ../analyse/rapport.py ./stats.json -o ./rapport.html
```

Le `rapport.html` produit est autonome : ouvrez-le dans un navigateur.

Si vous préférez ne rien lancer du tout, des événements synthétiques
représentatifs sont fournis dans [../sample-data/](../sample-data/) et
s'analysent de la même façon.

## Arrêter et nettoyer

```bash
docker compose down          # arrête, conserve les volumes
docker compose down -v       # supprime aussi les journaux de la démonstration
```

## Durcissement appliqué

| Réglage | Raison |
|---|---|
| `127.0.0.1:2222` | aucune exposition réseau |
| UID 999 non root | fourni par l'image officielle |
| `cap_drop: ALL` | aucune capacité Linux nécessaire |
| `no-new-privileges` | empêche l'élévation via setuid |
| `mem_limit`, `cpus`, `pids_limit` | garde-fous, larges par rapport au besoin |
| rotation des journaux Docker | évite de remplir le disque de l'hôte |
| `healthcheck` | vérifie que le port répond, pas seulement que le conteneur vit |

`read_only: true` n'est pas activé : Cowrie écrit dans `var/` et la combinaison
n'a pas été vérifiée sur cette image. Livrer l'option sans l'avoir testée
donnerait une configuration qui ne démarre pas.

## Limite de cette démonstration

Le `docker-compose.yml` est validé syntaxiquement (`docker compose config`) mais
le conteneur n'a pas été exécuté de bout en bout dans l'environnement où ce
dépôt a été préparé. Si quelque chose ne démarre pas, c'est ici qu'il faut
chercher en premier.
