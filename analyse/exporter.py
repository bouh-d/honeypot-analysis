#!/usr/bin/env python3
"""Prépare les journaux de Cowrie pour leur publication en jeu de données ouvert.

    python3 exporter.py /home/cowrie/cowrie/var/log/cowrie \\
        --adresse-capteur <adresse du serveur> \\
        --debut 2026-04-01 --fin 2026-10-01 -o /tmp/export --par-mois

Chaque fichier quotidien de la période est recopié après trois traitements :

- l'adresse du capteur est remplacée partout par 192.0.2.1, une adresse
  réservée à la documentation (RFC 5737). Partout, car certains outils
  d'attaque l'injectent dans leur bannière, leurs mots de passe ou leurs
  commandes ;
- les champs message, sensor et uuid sont retirés. Le premier recopie les
  autres champs sous forme de texte, adresse du capteur comprise ; les deux
  autres sont constants et propres à l'installation ;
- les lignes illisibles, écrites au moment d'un arrêt ou d'un disque plein,
  sont écartées et comptées.

L'adresse du capteur n'est jamais écrite dans ce fichier : elle est passée en
argument, pour ne pas figurer dans le dépôt public.

Les fichiers produits gardent le nom des fichiers quotidiens de Cowrie, si bien
qu'analyse.py les relit directement. Les archives sont reproductibles : à
journaux identiques, octets identiques.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import logging
import os
import re
import sys
import tarfile
from collections import defaultdict
from datetime import date
from typing import Any

from analyse import ouvrir

ADRESSE_DOCUMENTATION = "192.0.2.1"
CHAMPS_RETIRES = ("message", "sensor", "uuid")
NOM_QUOTIDIEN = re.compile(r"^cowrie\.json\.(\d{4}-\d{2}-\d{2})(\.gz)?$")

journal = logging.getLogger("exporter")


def motif_adresse(adresse: str) -> re.Pattern[str]:
    """Reconnaît l'adresse seule, pas comme fragment d'une autre.

    Sans ces bornes, remplacer 1.2.3.4 abîmerait aussi 11.2.3.45.
    """
    return re.compile(r"(?<!\d)" + re.escape(adresse) + r"(?!\d)")


def masquer(valeur: Any, motif: re.Pattern[str]) -> Any:
    if isinstance(valeur, str):
        return motif.sub(ADRESSE_DOCUMENTATION, valeur)
    if isinstance(valeur, dict):
        return {cle: masquer(v, motif) for cle, v in valeur.items()}
    if isinstance(valeur, list):
        return [masquer(v, motif) for v in valeur]
    return valeur


def nettoyer(evenement: dict[str, Any], motif: re.Pattern[str]) -> dict[str, Any]:
    propre = {k: v for k, v in evenement.items() if k not in CHAMPS_RETIRES}
    return masquer(propre, motif)


def fichiers_de_la_periode(
    dossier: str, debut: date, fin: date
) -> list[tuple[date, str]]:
    """Fichiers quotidiens dont la date est dans [debut, fin], triés par date.

    Le fichier en cours d'écriture (cowrie.json) et les archives hebdomadaires,
    qui dupliquent les fichiers quotidiens, sont ignorés.
    """
    retenus = []
    for nom in os.listdir(dossier):
        m = NOM_QUOTIDIEN.match(nom)
        if not m:
            continue
        jour = date.fromisoformat(m.group(1))
        if debut <= jour <= fin:
            retenus.append((jour, os.path.join(dossier, nom)))
    return sorted(retenus)


def exporter_fichier(
    source: str, destination: str, motif: re.Pattern[str]
) -> tuple[int, int]:
    """Écrit la version publiable d'un fichier ; renvoie (écrits, écartés)."""
    ecrits = ecartes = 0
    # mtime=0 et nom vide dans l'en-tête gzip : la sortie ne dépend que du
    # contenu, ce qui rend les archives reproductibles.
    with ouvrir(source) as entree, open(destination, "wb") as brut:
        with gzip.GzipFile(filename="", mode="wb", fileobj=brut, mtime=0) as sortie:
            for ligne in entree:
                ligne = ligne.strip()
                if not ligne:
                    continue
                try:
                    evenement = json.loads(ligne)
                except ValueError:
                    ecartes += 1
                    continue
                if not isinstance(evenement, dict):
                    ecartes += 1
                    continue
                texte = json.dumps(
                    nettoyer(evenement, motif),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                sortie.write((texte + "\n").encode("utf-8"))
                ecrits += 1
    return ecrits, ecartes


def archiver_par_mois(fichiers: list[tuple[date, str]], dossier: str) -> list[str]:
    """Regroupe les fichiers exportés en une archive tar par mois."""
    par_mois: dict[str, list[str]] = defaultdict(list)
    for jour, chemin in fichiers:
        par_mois[jour.strftime("%Y-%m")].append(chemin)

    archives = []
    for mois, chemins in sorted(par_mois.items()):
        nom = os.path.join(dossier, f"cowrie-{mois}.tar")
        with tarfile.open(nom, "w", format=tarfile.PAX_FORMAT) as tar:
            for chemin in sorted(chemins):
                info = tar.gettarinfo(chemin, arcname=os.path.basename(chemin))
                # Métadonnées neutres : ni date, ni propriétaire du serveur.
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mode = 0o644
                with open(chemin, "rb") as f:
                    tar.addfile(info, f)
        archives.append(nom)
    return archives


def empreinte(chemin: str) -> str:
    h = hashlib.sha256()
    with open(chemin, "rb") as f:
        for bloc in iter(lambda: f.read(1 << 20), b""):
            h.update(bloc)
    return h.hexdigest()


def main() -> int:
    parseur = argparse.ArgumentParser(description="Export du jeu de données publiable")
    parseur.add_argument("journaux", help="dossier des journaux de Cowrie")
    parseur.add_argument(
        "--adresse-capteur",
        required=True,
        help="adresse IP publique du honeypot à masquer",
    )
    parseur.add_argument("--debut", required=True, type=date.fromisoformat)
    parseur.add_argument("--fin", required=True, type=date.fromisoformat)
    parseur.add_argument("-o", "--sortie", required=True, help="dossier de destination")
    parseur.add_argument(
        "--par-mois",
        action="store_true",
        help="regroupe les fichiers en archives mensuelles avec leurs empreintes",
    )
    args = parseur.parse_args()

    logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.INFO)

    fichiers = fichiers_de_la_periode(args.journaux, args.debut, args.fin)
    if not fichiers:
        journal.error("aucun fichier quotidien sur la période")
        return 1

    jours = os.path.join(args.sortie, "jours")
    os.makedirs(jours, exist_ok=True)
    motif = motif_adresse(args.adresse_capteur)

    exportes = []
    total_ecrits = total_ecartes = 0
    for jour, source in fichiers:
        destination = os.path.join(jours, f"cowrie.json.{jour}.gz")
        ecrits, ecartes = exporter_fichier(source, destination, motif)
        total_ecrits += ecrits
        total_ecartes += ecartes
        exportes.append((jour, destination))
        if ecartes:
            journal.warning("%s : %d ligne(s) illisible(s) écartée(s)", jour, ecartes)

    journal.info(
        "%d fichiers, %d événements exportés, %d lignes écartées",
        len(exportes),
        total_ecrits,
        total_ecartes,
    )

    if args.par_mois:
        archives = archiver_par_mois(exportes, args.sortie)
        with open(os.path.join(args.sortie, "SHA256SUMS"), "w", encoding="utf-8") as f:
            for nom in archives:
                f.write(f"{empreinte(nom)}  {os.path.basename(nom)}\n")
        journal.info("%d archives mensuelles et SHA256SUMS écrits", len(archives))
    return 0


if __name__ == "__main__":
    sys.exit(main())
