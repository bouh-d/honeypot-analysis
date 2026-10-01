#!/usr/bin/env python3
"""Agrégation des journaux JSON de Cowrie.

Le honeypot écrit un fichier par jour, que l'on compresse ensuite (voir
scripts/compresser-journaux.sh). Au bout de quelques mois cela représente
plusieurs gigaoctets, donc tout est lu ligne par ligne : seuls des compteurs
restent en mémoire, jamais les événements.

    python3 analyse.py /home/cowrie/cowrie/var/log/cowrie
    python3 analyse.py cowrie.json.2026-04-* -o resultats/avril.json

Le fichier produit est repris par rapport.py pour la version HTML.
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import logging
import os
import sys
from collections import Counter
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import mitre

# Au-delà on ne garde que le début de la commande. Certains bots envoient des
# one-liners de plusieurs kilo-octets ; les compter en entier ferait gonfler la
# mémoire sans rien apporter au classement.
TAILLE_MAX_COMMANDE = 200

# On ne lit que les fichiers quotidiens. Les archive_*.json.gz produites à côté
# ont été vérifiées : 100 % de leurs événements sont déjà présents dans le
# fichier quotidien correspondant, les inclure revient à compter deux fois.
PREFIXES_JOURNAUX = ("cowrie.json",)

journal = logging.getLogger("analyse")


def fichiers_journaux(chemins: list[str]) -> list[str]:
    """Développe les dossiers passés en argument et trie le résultat."""
    trouves: list[str] = []
    for chemin in chemins:
        if os.path.isdir(chemin):
            trouves += [
                os.path.join(chemin, nom)
                for nom in os.listdir(chemin)
                if nom.startswith(PREFIXES_JOURNAUX)
            ]
        elif os.path.exists(chemin):
            trouves.append(chemin)
        else:
            journal.warning("fichier introuvable : %s", chemin)
    return sorted(trouves)


def ouvrir(chemin: str) -> io.TextIOBase:
    """Ouvre un journal, compressé ou non, en tolérant les octets invalides."""
    if chemin.endswith(".gz"):
        return io.TextIOWrapper(
            gzip.open(chemin, "rb"), encoding="utf-8", errors="replace"
        )
    return open(chemin, encoding="utf-8", errors="replace")


def evenements(chemins: list[str]) -> Iterator[dict[str, Any]]:
    """Parcourt tous les événements en ignorant les lignes illisibles.

    Une ligne tronquée en fin de fichier est normale : elle correspond à un
    arrêt du service, ou à un disque plein, en pleine écriture.
    """
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
            journal.warning(
                "%s : %d ligne(s) illisible(s)", os.path.basename(chemin), illisibles
            )


def horodatage(valeur: str) -> datetime | None:
    try:
        return datetime.fromisoformat(valeur.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None


def collecte(chemins: list[str]) -> dict[str, Any]:
    """Lit tous les journaux et renvoie les agrégats sous forme sérialisable."""
    totaux = {
        "connexions": 0,
        "echecs": 0,
        "succes": 0,
        "commandes": 0,
        "telechargements": 0,
        "tunnels": 0,
    }
    ip_vues: set[str] = set()
    ip_avec_succes: set[str] = set()
    sessions_actives: set[str] = set()

    tentatives_par_ip: Counter[str] = Counter()
    utilisateurs: Counter[str] = Counter()
    mots_de_passe: Counter[str] = Counter()
    combos: Counter[str] = Counter()
    commandes: Counter[str] = Counter()
    clients: Counter[str] = Counter()
    empreintes: Counter[str] = Counter()
    urls: Counter[str] = Counter()
    cibles_tunnel: Counter[str] = Counter()
    techniques: Counter[tuple[str, str]] = Counter()
    par_jour: Counter[str] = Counter()
    par_heure: Counter[int] = Counter()

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
            totaux["connexions"] += 1
            if source:
                ip_vues.add(source)
            if ts:
                par_jour[ts.date().isoformat()] += 1
                par_heure[ts.hour] += 1

        elif eid in ("cowrie.login.failed", "cowrie.login.success"):
            utilisateur = e.get("username", "")
            passe = e.get("password", "")
            if source:
                tentatives_par_ip[source] += 1
            utilisateurs[utilisateur] += 1
            mots_de_passe[passe] += 1
            combos[f"{utilisateur} / {passe}"] += 1
            if eid == "cowrie.login.success":
                totaux["succes"] += 1
                if source:
                    ip_avec_succes.add(source)
            else:
                totaux["echecs"] += 1

        elif eid == "cowrie.command.input":
            totaux["commandes"] += 1
            entree = e.get("input", "")
            commandes[entree[:TAILLE_MAX_COMMANDE]] += 1
            for technique in mitre.techniques(entree):
                techniques[technique] += 1
            if e.get("session"):
                sessions_actives.add(e["session"])

        elif eid == "cowrie.session.file_download":
            totaux["telechargements"] += 1
            if e.get("shasum"):
                empreintes[e["shasum"]] += 1
            if e.get("url"):
                urls[e["url"]] += 1

        elif eid == "cowrie.client.version":
            clients[e.get("version", "?")] += 1

        elif eid == "cowrie.direct-tcpip.request":
            # Cowrie journalise la demande mais ne relaie rien : forward_tunnel
            # et forward_redirect sont désactivés côté configuration.
            totaux["tunnels"] += 1
            cibles_tunnel[f"{e.get('dst_ip', '?')}:{e.get('dst_port', '?')}"] += 1

    tentatives = totaux["echecs"] + totaux["succes"]
    taux = round(totaux["succes"] / tentatives * 100, 2) if tentatives else 0.0

    return {
        "genere_le": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "periode": {
            "debut": premier.isoformat() if premier else None,
            "fin": dernier.isoformat() if dernier else None,
            "jours": len(par_jour),
        },
        "totaux": dict(
            totaux,
            ip_uniques=len(ip_vues),
            ip_ayant_reussi=len(ip_avec_succes),
            tentatives=tentatives,
            sessions_avec_commandes=len(sessions_actives),
            taux_de_succes=taux,
        ),
        "par_jour": dict(sorted(par_jour.items())),
        "par_heure": [par_heure.get(h, 0) for h in range(24)],
        "top": {
            "ip": tentatives_par_ip.most_common(25),
            "utilisateurs": utilisateurs.most_common(25),
            "mots_de_passe": mots_de_passe.most_common(25),
            "combos": combos.most_common(25),
            "commandes": commandes.most_common(25),
            "clients_ssh": clients.most_common(15),
            "empreintes": empreintes.most_common(15),
            "urls": urls.most_common(15),
            "cibles_tunnel": cibles_tunnel.most_common(15),
        },
        "mitre": [[tid, nom, n] for (tid, nom), n in techniques.most_common()],
    }


def affiche(stats: dict[str, Any]) -> None:
    """Résumé lisible dans le terminal, pour une vérification rapide."""
    t = stats["totaux"]
    p = stats["periode"]
    debut = (p["debut"] or "?")[:10]
    fin = (p["fin"] or "?")[:10]
    print()
    print(f"Periode analysee : {debut} -> {fin} ({p['jours']} jours)")
    print("-" * 60)
    print(f"Connexions                 {t['connexions']:10d}")
    print(f"Adresses IP uniques        {t['ip_uniques']:10d}")
    print(f"Tentatives d'authentif.    {t['tentatives']:10d}")
    print(f"  dont echouees            {t['echecs']:10d}")
    print(
        f"  dont reussies            {t['succes']:10d}  ({t['taux_de_succes']:.2f} %)"
    )
    print(f"Commandes executees        {t['commandes']:10d}")
    print(f"Sessions avec commandes    {t['sessions_avec_commandes']:10d}")
    print(f"Fichiers telecharges       {t['telechargements']:10d}")
    print(f"Tentatives de tunnel       {t['tunnels']:10d}")

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
            print(f"{n:8d}  {str(valeur)[:64]}")

    if stats["mitre"]:
        print()
        print("Techniques ATT&CK observees")
        print("-" * 60)
        for tid, nom, n in stats["mitre"][:12]:
            print(f"{n:8d}  {tid:<11} {nom}")
    print()


def main() -> int:
    parseur = argparse.ArgumentParser(description="Agrégation des journaux Cowrie")
    parseur.add_argument(
        "chemins",
        nargs="*",
        default=["/home/cowrie/cowrie/var/log/cowrie"],
        help="fichiers ou dossier de journaux Cowrie",
    )
    parseur.add_argument(
        "-o", "--sortie", default="stats.json", help="fichier JSON à écrire"
    )
    parseur.add_argument(
        "-s", "--silencieux", action="store_true", help="pas de résumé dans le terminal"
    )
    args = parseur.parse_args()

    logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.INFO)

    chemins = fichiers_journaux(args.chemins)
    if not chemins:
        journal.error("aucun journal trouvé")
        return 1
    journal.info("%d fichier(s) à lire", len(chemins))

    stats = collecte(chemins)
    stats["fichiers_lus"] = len(chemins)

    with open(args.sortie, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=1)
    journal.info("écrit : %s", args.sortie)

    if not args.silencieux:
        affiche(stats)
    return 0


if __name__ == "__main__":
    sys.exit(main())
