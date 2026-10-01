# Cibles courantes. Rien ici ne touche au serveur de production.

PYTHON ?= python3
EXEMPLE = sample-data/cowrie.json.exemple

.PHONY: aide test lint exemple demo demo-arret nettoyer

aide:
	@echo "make test        tests unitaires"
	@echo "make lint        ruff + shellcheck"
	@echo "make exemple     analyse et rapport sur le jeu synthetique"
	@echo "make demo        lance l instance de demonstration (127.0.0.1:2222)"
	@echo "make demo-arret  arrete la demonstration"
	@echo "make nettoyer    supprime les sorties generees"

test:
	$(PYTHON) -m pytest tests/ -q

lint:
	$(PYTHON) -m ruff check analyse/ tests/
	$(PYTHON) -m ruff format --check analyse/ tests/
	shellcheck scripts/*.sh

exemple:
	$(PYTHON) analyse/analyse.py $(EXEMPLE) -o stats.json
	$(PYTHON) analyse/rapport.py stats.json -o rapport.html

demo:
	cd demo && docker compose up -d

demo-arret:
	cd demo && docker compose down

nettoyer:
	rm -f stats.json rapport.html
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
