#!/usr/bin/env python3
"""Agregation des journaux JSON de Cowrie.

Le honeypot produit un fichier par jour plus des archives hebdomadaires
compressees. Au bout de quelques mois ca represente plusieurs gigaoctets, donc
tout est lu ligne par ligne : on ne garde en memoire que des compteurs.

    python3 analyse.py /home/cowrie/cowrie/var/log/cowrie
    python3 analyse.py cowrie.json.2026-04-* -o resultats/avril.json

Le fichier de sortie est ensuite repris par rapport.py pour la version HTML.
"""

import argparse
import gzip
import io
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mitre

# Au-dela on ne garde que le debut : certains bots envoient des one-liners de
# plusieurs kilo-octets, inutile de les stocker en entier pour les compter.
TAILLE_MAX_COMMANDE = 200


def fichiers_journaux(chemins):
    """Developpe les dossiers passes en argument et trie le resultat."""
    trouves = []
    for chemin in chemins:
        if os.path.isdir(chemin):
            for nom in os.listdir(chemin):
                if nom.startswith(("cowrie.json", "archive_")):
                    trouves.append(os.path.join(chemin, nom))
        elif os.path.exists(chemin):
            trouves.append(chemin)
        else:
            print("fichier introuvable : %s" % chemin, file=sys.stderr)
    return sorted(trouves)


def ouvrir(chemin):
    if chemin.endswith(".gz"):
        return io.TextIOWrapper(gzip.open(chemin, "rb"), encoding="utf-8",
                                errors="replace")
    return open(chemin, encoding="utf-8", errors="replace")


def evenements(chemins):
    """Generateur sur tous les evenements, les lignes tronquees sont ignorees."""
    for chemin in chemins:
        illisibles = 0
        with ouvrir(chemin) as f:
            for ligne in f:
                ligne = ligne.strip()
                if not ligne:
                    continue
                try:
                    yield json.loads(ligne)
                except ValueError:
                    illisibles += 1
        if illisibles:
            print("  %s : %d ligne(s) illisible(s)"
                  % (os.path.basename(chemin), illisibles), file=sys.stderr)


def horodatage(valeur):
    try:
        return datetime.fromisoformat(valeur.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None


def collecte(chemins):
    c = {
        "connexions": 0,
        "echecs": 0,
        "succes": 0,
        "commandes": 0,
        "telechargements": 0,
        "tunnels": 0,
    }
    ip_vues = set()
    ip_avec_succes = set()
    ip = Counter()
    utilisateurs = Counter()
    mots_de_passe = Counter()
    combos = Counter()
    commandes = Counter()
    clients = Counter()
    empreintes = Counter()
    urls = Counter()
    cibles_tunnel = Counter()
    techniques = Counter()
    par_jour = Counter()
    par_heure = Counter()
    sessions_actives = set()

    premier = dernier = None

    for e in evenements(chemins):
        eid = e.get("eventid")
        source = e.get("src_ip")
        ts = horodatage(e.get("timestamp", ""))
        if ts:
            if premier is None or ts < premier:
                premier = ts
            if dernier is None or ts > dernier:
                dernier = ts

        if eid == "cowrie.session.connect":
            c["connexions"] += 1
            if source:
                ip_vues.add(source)
            if ts:
                par_jour[ts.date().isoformat()] += 1
                par_heure[ts.hour] += 1

        elif eid in ("cowrie.login.failed", "cowrie.login.success"):
            utilisateur = e.get("username", "")
            passe = e.get("password", "")
            if source:
                ip[source] += 1
            utilisateurs[utilisateur] += 1
            mots_de_passe[passe] += 1
            combos["%s / %s" % (utilisateur, passe)] += 1
            if eid == "cowrie.login.success":
                c["succes"] += 1
                if source:
                    ip_avec_succes.add(source)
            else:
                c["echecs"] += 1

        elif eid == "cowrie.command.input":
            c["commandes"] += 1
            entree = e.get("input", "")
            commandes[entree[:TAILLE_MAX_COMMANDE]] += 1
            for tid, nom in mitre.techniques(entree):
                techniques["%s|%s" % (tid, nom)] += 1
            if e.get("session"):
                sessions_actives.add(e["session"])

        elif eid == "cowrie.session.file_download":
            c["telechargements"] += 1
            if e.get("shasum"):
                empreintes[e["shasum"]] += 1
            if e.get("url"):
                urls[e["url"]] += 1

        elif eid == "cowrie.client.version":
            clients[e.get("version", "?")] += 1

        elif eid == "cowrie.direct-tcpip.request":
            c["tunnels"] += 1
            cibles_tunnel["%s:%s" % (e.get("dst_ip", "?"),
                                     e.get("dst_port", "?"))] += 1

    tentatives = c["echecs"] + c["succes"]
    taux = round(c["succes"] / tentatives * 100, 2) if tentatives else 0.0
    return {
        "genere_le": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "periode": {
            "debut": premier.isoformat() if premier else None,
            "fin": dernier.isoformat() if dernier else None,
            "jours": len(par_jour),
        },
        "totaux": dict(
            c,
            ip_uniques=len(ip_vues),
            ip_ayant_reussi=len(ip_avec_succes),
            tentatives=tentatives,
            sessions_avec_commandes=len(sessions_actives),
            taux_de_succes=taux,
        ),
        "par_jour": dict(sorted(par_jour.items())),
        "par_heure": [par_heure.get(h, 0) for h in range(24)],
        "top": {
            "ip": ip.most_common(25),
            "utilisateurs": utilisateurs.most_common(25),
            "mots_de_passe": mots_de_passe.most_common(25),
            "combos": combos.most_common(25),
            "commandes": commandes.most_common(25),
            "clients_ssh": clients.most_common(15),
            "empreintes": empreintes.most_common(15),
            "urls": urls.most_common(15),
            "cibles_tunnel": cibles_tunnel.most_common(15),
        },
        "mitre": [[cle.split("|")[0], cle.split("|")[1], n]
                  for cle, n in techniques.most_common()],
    }


def affiche(stats):
    t = stats["totaux"]
    p = stats["periode"]
    print()
    print("Periode analysee : %s -> %s (%d jours)"
          % ((p["debut"] or "?")[:10], (p["fin"] or "?")[:10], p["jours"]))
    print("-" * 60)
    print("Connexions                 %10d" % t["connexions"])
    print("Adresses IP uniques        %10d" % t["ip_uniques"])
    print("Tentatives d'authentif.    %10d" % t["tentatives"])
    print("  dont echouees            %10d" % t["echecs"])
    print("  dont reussies            %10d  (%.2f %%)"
          % (t["succes"], t["taux_de_succes"]))
    print("Commandes executees        %10d" % t["commandes"])
    print("Sessions avec commandes    %10d" % t["sessions_avec_commandes"])
    print("Fichiers telecharges       %10d" % t["telechargements"])
    print("Tentatives de tunnel       %10d" % t["tunnels"])

    tableaux = [
        ("IP les plus actives", stats["top"]["ip"]),
        ("Identifiants testes", stats["top"]["utilisateurs"]),
        ("Mots de passe testes", stats["top"]["mots_de_passe"]),
        ("Commandes les plus vues", stats["top"]["commandes"]),
        ("Clients SSH annonces", stats["top"]["clients_ssh"]),
    ]
    for titre, lignes in tableaux:
        print()
        print(titre)
        print("-" * 60)
        for valeur, n in lignes[:10]:
            print("%8d  %s" % (n, str(valeur)[:64]))

    if stats["mitre"]:
        print()
        print("Techniques ATT&CK observees")
        print("-" * 60)
        for tid, nom, n in stats["mitre"][:12]:
            print("%8d  %-11s %s" % (n, tid, nom))
    print()


def main():
    parseur = argparse.ArgumentParser(description="Agregation des journaux Cowrie")
    parseur.add_argument("chemins", nargs="*",
                         default=["/home/cowrie/cowrie/var/log/cowrie"],
                         help="fichiers ou dossier de journaux Cowrie")
    parseur.add_argument("-o", "--sortie", default="stats.json",
                         help="fichier JSON a ecrire (defaut: stats.json)")
    parseur.add_argument("-s", "--silencieux", action="store_true",
                         help="pas de resume dans le terminal")
    args = parseur.parse_args()

    chemins = fichiers_journaux(args.chemins)
    if not chemins:
        print("aucun journal trouve", file=sys.stderr)
        return 1
    print("%d fichier(s) a lire" % len(chemins), file=sys.stderr)

    stats = collecte(chemins)
    stats["fichiers_lus"] = len(chemins)

    with open(args.sortie, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=1)
    print("ecrit : %s" % args.sortie, file=sys.stderr)

    if not args.silencieux:
        affiche(stats)
    return 0


if __name__ == "__main__":
    sys.exit(main())
