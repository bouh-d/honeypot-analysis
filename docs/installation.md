# Mise en place du honeypot

Notes prises pendant l'installation, en avril 2026. Elles décrivent ce qui
tourne réellement sur le VPS, pas une procédure théorique.

## Machine

VPS IONOS Linux XS+, 1 vCore, 1 Go de RAM, 10 Go de SSD, datacenter en
Allemagne. Ubuntu Server 24.04 LTS. Le choix du plus petit modèle est
volontaire : Cowrie n'exécute rien pour de vrai, il simule un shell, donc la
charge reste faible même quand les bots s'acharnent.

Le pare-feu est géré uniquement depuis l'interface IONOS. Seuls deux ports
sont ouverts : le 22 pour le honeypot, et un port haut pour l'administration.
J'ai vidé les règles iptables locales pour éviter d'avoir deux filtrages qui se
contredisent. Le port d'administration n'est pas indiqué ici, pas plus que dans
le reste du dépôt.

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

Les réglages modifiés dans `etc/cowrie.cfg` sont dans
[`deploiement/cowrie.cfg.extrait`](../deploiement/cowrie.cfg.extrait).

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

Le service systemd ([`deploiement/cowrie.service`](../deploiement/cowrie.service))
lance ensuite `authbind --deep cowrie start`. Le `--deep` est nécessaire :
sans lui, seul le processus parent est autorisé et Twisted échoue quand il
ouvre le socket dans un enfant.

## Vérification

```bash
systemctl enable --now cowrie
systemctl status cowrie
tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json
```

Les premiers bots sont arrivés moins de deux heures après l'ouverture du port.
Aucune publication de l'adresse nulle part : les scanners de masse balaient en
continu les plages des hébergeurs connus.

## Entretien

Cowrie fait tourner ses journaux tout seul (un fichier par jour, archive
hebdomadaire compressée). Sur un disque de 10 Go il faut quand même surveiller :
en cinq mois les journaux ont dépassé les 4 Go. Ce que je purge de temps en
temps :

```bash
du -sh /home/cowrie/cowrie/var/log/cowrie /home/cowrie/cowrie/var/lib/cowrie/*
# les captures TTY grossissent vite et n'apportent pas grand-chose une fois
# les commandes extraites des journaux JSON
find /home/cowrie/cowrie/var/lib/cowrie/tty -mtime +30 -delete
```

Les binaires déposés par les attaquants sont conservés dans
`var/lib/cowrie/downloads/`, nommés par leur empreinte SHA-256. Ils ne sont pas
publiés dans ce dépôt.
