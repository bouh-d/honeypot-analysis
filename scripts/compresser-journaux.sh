#!/usr/bin/env bash
#
# Compresse les journaux quotidiens déjà basculés par Cowrie.
#
# Cowrie fait tourner ses fichiers chaque jour mais ne compresse rien et ne
# purge rien. Sur un disque de 10 Go cela mène à la saturation en quatre mois
# environ, ce qui s'est produit le 25 septembre 2026 : le service est resté
# actif six jours sans pouvoir écrire. Voir docs/exploitation.md.
#
# Gain mesuré : facteur 25 environ sur les fichiers JSON.
#
# Les fichiers en cours d'écriture (cowrie.json et cowrie.log, sans suffixe de
# date) ne sont jamais touchés : Cowrie y écrit en continu.
#
#   ./compresser-journaux.sh
#   ./compresser-journaux.sh --simulation
#   JOURNAUX=/autre/chemin ./compresser-journaux.sh

set -euo pipefail

JOURNAUX="${JOURNAUX:-/home/cowrie/cowrie/var/log/cowrie}"
SIMULATION=0

usage() {
    sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --simulation|-n) SIMULATION=1 ;;
        --aide|-h)       usage 0 ;;
        *) echo "option inconnue : $1" >&2; usage 1 ;;
    esac
    shift
done

if [ ! -d "$JOURNAUX" ]; then
    echo "dossier introuvable : $JOURNAUX" >&2
    exit 1
fi

espace_libre() {
    df -h "$JOURNAUX" | awk 'NR==2 {print $4" libre ("$5" utilise)"}'
}

echo "dossier : $JOURNAUX"
echo "avant   : $(espace_libre)"

# Uniquement les fichiers suffixés par une date : les fichiers vivants
# (cowrie.json, cowrie.log) ne correspondent pas à ce motif.
mapfile -t candidats < <(
    find "$JOURNAUX" -maxdepth 1 -type f \
        \( -name 'cowrie.json.????-??-??' -o -name 'cowrie.log.????-??-??' \) \
        | sort
)

if [ "${#candidats[@]}" -eq 0 ]; then
    echo "rien à compresser"
    exit 0
fi

echo "à traiter : ${#candidats[@]} fichier(s)"

if [ "$SIMULATION" -eq 1 ]; then
    for f in "${candidats[@]}"; do
        printf '  [simulation] gzip %s (%s)\n' "$(basename "$f")" "$(du -h "$f" | cut -f1)"
    done
    echo "aucune modification effectuée"
    exit 0
fi

traites=0
for f in "${candidats[@]}"; do
    # gzip écrit le .gz puis supprime l'original : le pic d'espace
    # supplémentaire est celui d'un seul fichier compressé.
    if nice -n 15 gzip -9 "$f"; then
        traites=$((traites + 1))
    else
        echo "échec sur $f, on continue" >&2
    fi
done

echo "compressés : $traites/${#candidats[@]}"
echo "après   : $(espace_libre)"

cat <<'FIN'

Les fichiers compressés restent directement exploitables :
analyse.py lit les .gz de façon transparente.

Pour récupérer davantage de place, les transcriptions de terminal anciennes
n'apportent plus rien une fois les commandes extraites des journaux JSON :
  find /home/cowrie/cowrie/var/lib/cowrie/tty -type f -mtime +30 -delete
FIN
