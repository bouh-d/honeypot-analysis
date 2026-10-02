"""Vérifie la lecture des journaux et l'agrégation."""

import gzip
import json

import pytest
from conftest import chemin_exemple

import analyse

# --- horodatage ---------------------------------------------------------------


def test_horodatage_cowrie():
    ts = analyse.horodatage("2026-09-14T21:35:17.102933Z")
    assert ts is not None
    assert (ts.year, ts.month, ts.day, ts.hour) == (2026, 9, 14, 21)


@pytest.mark.parametrize("valeur", ["", "pas une date", None, "2026-13-45T99:99:99Z"])
def test_horodatage_invalide(valeur):
    assert analyse.horodatage(valeur) is None


# --- selection des fichiers ---------------------------------------------------


def test_archives_exclues(tmp_path):
    """Les archive_*.json.gz dupliquent les fichiers quotidiens à 100 %."""
    (tmp_path / "cowrie.json.2026-04-01").write_text("")
    (tmp_path / "cowrie.json.2026-04-02.gz").write_text("")
    (tmp_path / "archive_202614.json.gz").write_text("")
    (tmp_path / "sans-rapport.txt").write_text("")

    noms = [
        f.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        for f in analyse.fichiers_journaux([str(tmp_path)])
    ]
    assert noms == ["cowrie.json.2026-04-01", "cowrie.json.2026-04-02.gz"]


def test_fichier_absent_ignore(tmp_path):
    assert analyse.fichiers_journaux([str(tmp_path / "inexistant")]) == []


# --- lecture ------------------------------------------------------------------


def test_lecture_gzip(tmp_path):
    chemin = tmp_path / "cowrie.json.2026-04-01.gz"
    with gzip.open(chemin, "wt", encoding="utf-8") as f:
        f.write(json.dumps({"eventid": "cowrie.session.connect"}) + "\n")
    assert [e["eventid"] for e in analyse.evenements([str(chemin)])] == [
        "cowrie.session.connect"
    ]


def test_lignes_illisibles_ignorees(tmp_path):
    """Une ligne tronquée en fin de fichier est normale (arrêt, disque plein)."""
    chemin = tmp_path / "cowrie.json.2026-04-01"
    chemin.write_text(
        '{"eventid":"cowrie.session.connect","src_ip":"203.0.113.1"}\n'
        "\n"
        "ceci n'est pas du json\n"
        '{"eventid":"cowrie.session.cl\n',
        encoding="utf-8",
    )
    assert len(list(analyse.evenements([str(chemin)]))) == 1


# --- agregation ---------------------------------------------------------------


@pytest.fixture(scope="module")
def stats():
    return analyse.collecte([chemin_exemple()])


def test_totaux_jeu_exemple(stats):
    t = stats["totaux"]
    assert t["connexions"] == 3
    assert t["ip_uniques"] == 3
    assert t["tentatives"] == 6
    assert t["echecs"] == 3
    assert t["succes"] == 3
    assert t["commandes"] == 5
    assert t["telechargements"] == 1
    assert t["tunnels"] == 1
    assert t["sessions_avec_commandes"] == 2


def test_taux_de_succes(stats):
    assert stats["totaux"]["taux_de_succes"] == pytest.approx(50.0)


def test_distribution_horaire_complete(stats):
    assert len(stats["par_heure"]) == 24
    assert sum(stats["par_heure"]) == stats["totaux"]["connexions"]


def test_periode(stats):
    assert stats["periode"]["debut"].startswith("2026-09-14")
    assert stats["periode"]["fin"].startswith("2026-09-15")
    assert stats["periode"]["jours"] == 2


def test_commande_tronquee(tmp_path):
    longue = "a" * (analyse.TAILLE_MAX_COMMANDE + 500)
    chemin = tmp_path / "cowrie.json.2026-04-01"
    chemin.write_text(
        json.dumps(
            {
                "eventid": "cowrie.command.input",
                "input": longue,
                "session": "s1",
                "timestamp": "2026-04-01T00:00:00Z",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    commande = analyse.collecte([str(chemin)])["top"]["commandes"][0][0]
    assert len(commande) == analyse.TAILLE_MAX_COMMANDE


def test_mitre_present(stats):
    identifiants = [tid for tid, _, _ in stats["mitre"]]
    assert "T1098.004" in identifiants  # pose de cle dans le jeu d'exemple
    assert "T1105" in identifiants  # wget dans le jeu d'exemple


def test_sortie_serialisable(stats):
    """Le JSON doit pouvoir être écrit puis relu sans perte de structure."""
    relu = json.loads(json.dumps(stats, ensure_ascii=False))
    assert relu["totaux"] == stats["totaux"]


def test_aucun_evenement(tmp_path):
    chemin = tmp_path / "cowrie.json.2026-04-01"
    chemin.write_text("", encoding="utf-8")
    stats = analyse.collecte([str(chemin)])
    assert stats["totaux"]["connexions"] == 0
    assert stats["totaux"]["taux_de_succes"] == 0.0
    assert stats["periode"]["debut"] is None


# --- affichage au terminal ----------------------------------------------------


def test_lisible_neutralise_les_sequences_d_echappement():
    """Une séquence ANSI dans un mot de passe ne doit pas atteindre le terminal."""
    assert analyse.lisible("\x1b[2Jroot") == r"\x1b[2Jroot"
    assert analyse.lisible("a\x00b\x7fc") == r"a\x00b\x7fc"


def test_lisible_conserve_le_texte_normal():
    assert analyse.lisible("éàü 123456 中文") == "éàü 123456 中文"


def test_lisible_tronque_avant_neutralisation():
    assert analyse.lisible("x" * 100) == "x" * 64


def test_affiche_ne_laisse_passer_aucun_caractere_de_controle(tmp_path, capsys):
    chemin = tmp_path / "cowrie.json.2026-04-01"
    chemin.write_text(
        json.dumps(
            {
                "eventid": "cowrie.login.failed",
                "username": "root",
                "password": "\x1b]0;titre\x07piege",
                "src_ip": "203.0.113.1",
                "timestamp": "2026-04-01T00:00:00Z",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    analyse.affiche(analyse.collecte([str(chemin)]))
    sortie = capsys.readouterr().out
    assert "\x1b" not in sortie and "\x07" not in sortie
    assert r"\x1b]0;titre\x07piege" in sortie
