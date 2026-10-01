"""Vérifie la génération du rapport HTML, y compris sur données dégénérées."""

import json

import analyse
import pytest
import rapport
from conftest import chemin_exemple


@pytest.fixture(scope="module")
def stats():
    return analyse.collecte([chemin_exemple()])


def test_formatage_milliers():
    assert rapport.espace(824801) == "824 801"
    assert rapport.espace(0) == "0"


def test_separateur_decimal_francais():
    assert rapport.virgule(41.08) == "41,1"
    assert rapport.virgule(1.76, 2) == "1,76"


# --- note horaire : c'est ici que se trouvait un plantage ---------------------


def test_note_horaire_normale():
    heures = [10] * 23 + [20]
    note = rapport.note_horaire(heures)
    assert "Maximum a 23 h" in note
    assert "2,0" in note


def test_note_horaire_sans_aucune_connexion():
    """Plantait avec ValueError: 1 is not in list avant correction."""
    note = rapport.note_horaire([0] * 24)
    assert "Aucune connexion" in note


def test_note_horaire_avec_heure_creuse_vide():
    """Évite une division par zéro quand une heure est à zéro."""
    heures = [0] + [5] * 23
    note = rapport.note_horaire(heures)
    assert "aucune connexion" in note


# --- page complete ------------------------------------------------------------


def test_aucun_marqueur_non_remplace(stats):
    page = rapport.construire(stats)
    assert "__" not in page


def test_page_bien_formee(stats):
    page = rapport.construire(stats)
    assert page.startswith("<!DOCTYPE html>")
    assert page.rstrip().endswith("</html>")
    assert page.count("<table") == page.count("</table>")
    assert 'lang="fr"' in page


def test_rapport_sur_jeu_vide(tmp_path):
    """Une période sans connexion doit produire une page, pas une exception."""
    chemin = tmp_path / "cowrie.json.2026-04-01"
    chemin.write_text("", encoding="utf-8")
    page = rapport.construire(analyse.collecte([str(chemin)]))
    assert "Aucune connexion" in page


# --- injection ----------------------------------------------------------------


def test_echappement_html(tmp_path):
    """Les identifiants viennent de l'attaquant et finissent dans le rapport."""
    charge = "<script>alert(1)</script>"
    chemin = tmp_path / "cowrie.json.2026-04-01"
    chemin.write_text(
        json.dumps(
            {
                "eventid": "cowrie.login.failed",
                "username": charge,
                "password": "x",
                "src_ip": "203.0.113.1",
                "timestamp": "2026-04-01T00:00:00Z",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    page = rapport.construire(analyse.collecte([str(chemin)]))
    assert "<script>" not in page
    assert "&lt;script&gt;" in page
