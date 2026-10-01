# Mise en place du honeypot

Notes prises pendant l'installation, en avril 2026, complétées après l'audit
d'octobre. Elles décrivent ce qui tourne réellement sur le VPS, y compris ce qui
n'a pas été fait de la meilleure façon.

Les paramètres propres à l'hôte exposé (adresse, port d'administration) ne
figurent pas ici. Pour voir le dispositif fonctionner sans rien exposer,
l'instance de [demo/](../demo/) est plus adaptée.

## Machine

VPS IONOS Linux XS+, 1 vCore, 1 Go de RAM, 10 Go de SSD, datacenter en
Allemagne. Ubuntu Server 24.04 LTS. Le choix du plus petit modèle est
volontaire : Cowrie n'exécute rien pour de vrai, il simule un shell, donc la
charge reste faible même quand les bots s'acharnent.

Le pare-feu est géré uniquement depuis l'interface IONOS. Seuls deux ports
sont ouverts : le 22 pour le honeypot, et un port haut pour l'administration.
J'ai vidé les règles iptables locales pour éviter d'avoir deux filtrages qui se
contredisent. La contrepartie, relevée depuis, est que le trafic sortant n'est
filtré nulle part (voir [security.md](security.md)).

## Déplacer le SSH d'administration

Le piège est de vouloir mettre Cowrie sur le port 22 alors que le vrai SSH y
est encore. Dans l'ordre :

```bash
PORT_ADMIN=xxxxx   # le port haut retenu pour l'administration

# 1. l'ouvrir dans le pare-feu IONOS AVANT de toucher a quoi que ce soit
# 2. changer le port du serveur SSH
sed -i "s/^#\?Port .*/Port $PORT_ADMIN/" /etc/ssh/sshd_config

# 3. sur Ubuntu 24.04 le service est active par socket : tant que ssh.socket
#    est active, il continue d'ecouter sur le 22 et sshd_config est ignore
systemctl disable --now ssh.socket
systemctl enable --now ssh

# 4. verifier depuis une DEUXIEME session avant de fermer la premiere
ss -tlnp | grep -E ":22\b|:$PORT_ADMIN"
```

C'est l'étape qui m'a pris le plus de temps : je modifiais `sshd_config` et le
port ne bougeait pas, parce que `ssh.socket` gardait la main sur le 22.

## Installation de Cowrie

```bash
adduser --disabled-password cowrie
su - cowrie
git clone https://github.com/cowrie/cowrie
cd cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -e .
cp etc/cowrie.cfg.dist etc/cowrie.cfg
```

Version installée : Cowrie 2.9.16, Python 3.12.3.

Les écarts entre la configuration en production et le fichier livré sont
recensés dans [`config/cowrie.cfg.extrait`](../config/cowrie.cfg.extrait).

## Faire écouter Cowrie sur le port 22

Cowrie écoute par défaut sur le 2222. Les bots qui scannent ce port savent
généralement qu'ils cherchent un honeypot, et le trafic intéressant arrive sur
le 22.

### Ce qui a été fait

Au déploiement, la valeur par défaut a été changée directement dans le code
source :

```bash
# src/twisted/plugins/cowrie_plugin.py, ligne 244
#   avant : get_endpoints_from_section(CowrieConfig, "ssh", 2222)
#   après : get_endpoints_from_section(CowrieConfig, "ssh", 22)
```

Ça fonctionne, et c'est toujours ce qui tourne en production. Mais c'est la
mauvaise méthode : la prochaine mise à jour de Cowrie écrasera le fichier, et le
honeypot repassera sur le 2222 sans prévenir.

### Ce qu'il faudrait faire

La configuration prévoit exactement ce besoin. Dans `etc/cowrie.cfg` :

```ini
[ssh]
listen_endpoints = tcp:22:interface=0.0.0.0
```

Le résultat est identique et survit aux mises à jour. Le changement n'a pas
encore été appliqué en production parce qu'il impose un redémarrage. Une
première tentative avait par erreur modifié la section `[backend_pool]`, qui
n'est lue qu'en mode proxy : la ligne y est toujours, sans effet.

## Écouter sur le port 22 sans être root

Cowrie tourne sous un compte non privilégié, il ne peut donc pas ouvrir un port
inférieur à 1024. J'utilise `authbind` plutôt que des redirections iptables,
c'est plus simple à relire six mois plus tard :

```bash
apt install authbind
touch /etc/authbind/byport/22
chown cowrie /etc/authbind/byport/22
chmod 770 /etc/authbind/byport/22
```

Le service systemd ([`config/cowrie.service`](../config/cowrie.service)) lance
ensuite `authbind --deep cowrie start`. Le `--deep` est nécessaire : sans lui,
seul le processus parent est autorisé et Twisted échoue quand il ouvre le
socket dans un enfant.

## Vérification

```bash
systemctl enable --now cowrie
systemctl status cowrie
ss -tlnp | grep ':22 '
tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json
```

Les premiers bots sont arrivés moins de deux heures après l'ouverture du port.
Aucune publication de l'adresse nulle part : les scanners de masse balaient en
continu les plages des hébergeurs connus.

`systemctl status` ne suffit pas à garantir que la collecte fonctionne. Le
service peut rester actif sans plus rien écrire, c'est ce qui s'est produit en
septembre. La bonne vérification est la fraîcheur du dernier événement,
décrite dans [exploitation.md](exploitation.md).

## Entretien

C'est le point qui a été sous-estimé au déploiement.

Cowrie bascule son journal chaque jour, mais ne compresse rien et ne purge rien.
Sur un disque de 10 Go, cela mène à la saturation en quatre mois environ. Rien
n'avait été prévu, et le disque a été plein le 25 septembre 2026.

Depuis, les journaux quotidiens sont compressés par le script du dépôt :

```bash
./scripts/compresser-journaux.sh --simulation   # pour voir ce qui serait fait
./scripts/compresser-journaux.sh
```

Le gain est d'un facteur 25 environ. Il n'est pas encore planifié : le lancer
régulièrement, ou l'inscrire dans une minuterie systemd, reste à faire.

Les binaires déposés par les attaquants sont conservés dans
`var/lib/cowrie/downloads/`, nommés par leur empreinte SHA-256. Ils ne sont pas
publiés dans ce dépôt.
