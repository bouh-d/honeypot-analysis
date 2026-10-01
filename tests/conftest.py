"""Rend le paquet analyse/ importable depuis les tests.

Les scripts sont conçus pour être lancés directement (python3 analyse/analyse.py),
cas où Python place leur dossier en tête de sys.path. Les tests doivent le faire
explicitement.
"""

import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE / "analyse"))


def chemin_exemple():
    return str(RACINE / "sample-data" / "cowrie.json.exemple")
