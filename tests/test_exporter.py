"""Vérifie la préparation du jeu de données publiable."""

import gzip
import json
from datetime import date

import exporter

# Adresse fictive tirée d'une plage de documentation : le vrai capteur n'apparaît
# jamais dans le dépôt.
CAPTEUR = "198.51.100.77"


def motif():
    return exporter.motif_adresse(CAPTEUR)


# --- masquage de l'adresse du capteur -----------------------------------------


def test_adresse_remplacee():
    assert exporter.masquer(f"connexion vers {CAPTEUR}:22", motif()) == (
        "connexion vers 192.0.2.1:22"
    )


def test_adresses_voisines_intactes():
    """Une adresse qui contient l'autre comme fragment ne doit pas être touchée."""
    voisines = "1" + CAPTEUR + " et " + CAPTEUR + "5"
    assert exporter.masquer(voisines, motif()) == voisines


def test_masquage_dans_les_structures_imbriquees():
    entree = {"a": [CAPTEUR, {"b": "x " + CAPTEUR}], "n": 22, "vide": None}
    assert exporter.masquer(entree, motif()) == {
        "a": ["192.0.2.1", {"b": "x 192.0.2.1"}],
        "n": 22,
        "vide": None,
    }


def test_adresse_injectee_par_un_attaquant():
    """Des outils d'attaque glissent l'adresse visée dans leurs mots de passe."""
    evenement = {
        "eventid": "cowrie.login.failed",
        "username": "root",
        "password": CAPTEUR,
        "src_ip": "203.0.113.9",
    }
    propre = exporter.nettoyer(evenement, motif())
    assert propre["password"] == "192.0.2.1"
    assert propre["src_ip"] == "203.0.113.9"


# --- champs retirés -----------------------------------------------------------


def test_champs_retires():
    evenement = {
        "eventid": "cowrie.session.connect",
        "message": f"New connection: 203.0.113.9:4444 ({CAPTEUR}:22)",
        "sensor": "ubuntu",
        "uuid": "531fe95c",
        "dst_ip": CAPTEUR,
    }
    propre = exporter.nettoyer(evenement, motif())
    assert set(propre) == {"eventid", "dst_ip"}
    assert propre["dst_ip"] == "192.0.2.1"


# --- sélection des fichiers ---------------------------------------------------


def test_fichiers_de_la_periode(tmp_path):
    for nom in [
        "cowrie.json.2026-03-31.gz",
        "cowrie.json.2026-04-01.gz",
        "cowrie.json.2026-04-02",
        "cowrie.json.2026-04-03.gz",
        "cowrie.json",
        "archive_202614.json.gz",
        "cowrie.log.2026-04-01.gz",
    ]:
        (tmp_path / nom).write_text("")
    retenus = exporter.fichiers_de_la_periode(
        str(tmp_path), date(2026, 4, 1), date(2026, 4, 2)
    )
    assert [j.isoformat() for j, _ in retenus] == ["2026-04-01", "2026-04-02"]


# --- export d'un fichier ------------------------------------------------------


def _journal(tmp_path, lignes):
    chemin = tmp_path / "cowrie.json.2026-04-01"
    chemin.write_text("\n".join(lignes) + "\n", encoding="utf-8")
    return str(chemin)


def test_export_ecarte_les_lignes_illisibles(tmp_path):
    source = _journal(
        tmp_path,
        [
            json.dumps({"eventid": "cowrie.session.connect", "dst_ip": CAPTEUR}),
            "ceci n'est pas du json",
            '{"eventid":"cowrie.session.cl',
            "[1, 2]",
        ],
    )
    destination = str(tmp_path / "sortie.gz")
    assert exporter.exporter_fichier(source, destination, motif()) == (1, 3)
    with gzip.open(destination, "rt", encoding="utf-8") as f:
        lignes = f.read().splitlines()
    assert lignes == ['{"eventid":"cowrie.session.connect","dst_ip":"192.0.2.1"}']


def test_aucune_trace_du_capteur_dans_la_sortie(tmp_path):
    source = _journal(
        tmp_path,
        [
            json.dumps(
                {
                    "eventid": "cowrie.client.version",
                    "version": f"SSH-2.0-scanner {CAPTEUR}",
                    "message": f"Remote SSH version: SSH-2.0-scanner {CAPTEUR}",
                }
            )
        ],
    )
    destination = str(tmp_path / "sortie.gz")
    exporter.exporter_fichier(source, destination, motif())
    with gzip.open(destination, "rb") as f:
        assert CAPTEUR.encode() not in f.read()


def test_export_reproductible(tmp_path):
    """Deux exports du même fichier donnent exactement les mêmes octets."""
    source = _journal(tmp_path, [json.dumps({"eventid": "x", "dst_ip": CAPTEUR})])
    a, b = str(tmp_path / "a.gz"), str(tmp_path / "b.gz")
    exporter.exporter_fichier(source, a, motif())
    exporter.exporter_fichier(source, b, motif())
    assert open(a, "rb").read() == open(b, "rb").read()


# --- archives mensuelles ------------------------------------------------------


def test_archives_par_mois_reproductibles(tmp_path):
    fichiers = []
    for jour in (date(2026, 4, 30), date(2026, 5, 1)):
        chemin = tmp_path / f"cowrie.json.{jour}.gz"
        chemin.write_bytes(b"contenu " + jour.isoformat().encode())
        fichiers.append((jour, str(chemin)))

    premier = tmp_path / "premier"
    second = tmp_path / "second"
    premier.mkdir()
    second.mkdir()
    a = exporter.archiver_par_mois(fichiers, str(premier))
    b = exporter.archiver_par_mois(fichiers, str(second))

    assert [p.rsplit("cowrie-", 1)[1] for p in a] == ["2026-04.tar", "2026-05.tar"]
    for x, y in zip(a, b, strict=True):
        assert exporter.empreinte(x) == exporter.empreinte(y)
