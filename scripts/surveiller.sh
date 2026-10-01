#!/usr/bin/env bash
#
# Supervision du honeypot : espace disque et fraîcheur des journaux.
#
# Lancé toutes les 15 minutes par config/honeypot-supervision.timer.
#
# Deux contrôles, nés de l'incident du 24 septembre 2026, où le disque plein a
# coupé la collecte plus de six jours sans que rien ne le signale :
#
#   disque     au-delà du seuil, compresse les journaux puis prévient ;
#              alerte si la compression ne suffit pas.
#   fraîcheur  alerte si le dernier événement JSON valide est trop ancien.
#              C'est le seul signal fiable : systemctl répondait « active »
#              pendant toute la panne.
#
# Une alerte n'est envoyée qu'au passage en anomalie, puis rappelée toutes les
# RAPPEL_HEURES tant qu'elle dure, et un message signale le retour à la normale.
#
#   surveiller.sh          vérification normale
#   surveiller.sh --test   envoie une notification de test et s'arrête

set -euo pipefail

CONF="${CONF:-/etc/honeypot-supervision.conf}"
ETAT="${STATE_DIRECTORY:-/var/lib/honeypot-supervision}"

# Valeurs par défaut, remplacées par celles du fichier de configuration.
JOURNAUX=/home/cowrie/cowrie/var/log/cowrie
SEUIL_DISQUE=80
SEUIL_FRAICHEUR_MIN=30
RAPPEL_HEURES=6
NTFY_SERVEUR=https://ntfy.sh
NTFY_TOPIC=
COMPRESSER=/opt/honeypot/compresser-journaux.sh

ECHEC_ENVOI=0

journal() {
    printf '%s\n' "$*"
}

# Le fichier est lu ligne à ligne plutôt que chargé avec « source » : seules
# les clés connues sont acceptées, et rien de ce qu'il contient n'est exécuté.
charger_configuration() {
    [ -r "$CONF" ] || { journal "configuration absente : $CONF"; return 0; }
    local cle valeur
    while IFS='=' read -r cle valeur || [ -n "$cle" ]; do
        case "$cle" in
            '' | \#*) ;;
            JOURNAUX | SEUIL_DISQUE | SEUIL_FRAICHEUR_MIN | RAPPEL_HEURES | \
            NTFY_SERVEUR | NTFY_TOPIC | COMPRESSER)
                printf -v "$cle" '%s' "$valeur" ;;
            *) journal "clé inconnue ignorée : $cle" ;;
        esac
    done < "$CONF"
}

# Publication au format JSON, qui accepte l'UTF-8 dans le titre, contrairement
# aux en-têtes HTTP. Priorités ntfy : 3 normale, 4 haute, 5 urgente.
notifier() {
    local priorite="$1" titre="$2" message="$3" tags="${4:-}"
    if [ -z "$NTFY_TOPIC" ]; then
        journal "NTFY_TOPIC vide, notification non envoyée : $titre"
        return 0
    fi
    local charge
    charge=$(TOPIC="$NTFY_TOPIC" TITRE="$titre" MSG="$message" \
             PRIO="$priorite" TAGS="$tags" python3 -c '
import json, os
print(json.dumps({
    "topic": os.environ["TOPIC"],
    "title": os.environ["TITRE"],
    "message": os.environ["MSG"],
    "priority": int(os.environ["PRIO"]),
    "tags": [t for t in os.environ["TAGS"].split(",") if t],
}))')
    if curl -fsS --max-time 15 -H "Content-Type: application/json" \
            -d "$charge" "$NTFY_SERVEUR" > /dev/null; then
        journal "notification envoyée : $titre"
    else
        journal "ÉCHEC d'envoi de la notification : $titre"
        ECHEC_ENVOI=1
        return 1
    fi
}

etat_lire() {
    cat "$ETAT/$1" 2> /dev/null || echo "ok 0"
}

etat_ecrire() {
    printf '%s\n' "$2" > "$ETAT/$1"
}

# Décide s'il faut prévenir, d'après l'état mémorisé du contrôle. Si l'envoi
# échoue, l'état n'est pas mis à jour : la tentative reprend au passage suivant.
evaluer() {
    local controle="$1" en_anomalie="$2" titre="$3" detail="$4" tags="$5"
    local titre_retour="$6"
    local etat derniere maintenant
    read -r etat derniere < <(etat_lire "$controle")
    maintenant=$(date +%s)

    if [ "$en_anomalie" -eq 1 ]; then
        if [ "$etat" != alerte ]; then
            notifier 5 "Honeypot : $titre" "$detail" "$tags,rotating_light" \
                && etat_ecrire "$controle" "alerte $maintenant"
        elif [ $((maintenant - derniere)) -ge $((RAPPEL_HEURES * 3600)) ]; then
            notifier 4 "Honeypot, toujours en cours : $titre" "$detail" "$tags" \
                && etat_ecrire "$controle" "alerte $maintenant"
        else
            journal "$controle : anomalie déjà signalée"
        fi
    elif [ "$etat" = alerte ]; then
        notifier 3 "Honeypot : $titre_retour" "$detail" "white_check_mark" \
            && etat_ecrire "$controle" "ok 0"
    else
        journal "$controle : normal ($detail)"
    fi
}

utilisation_disque() {
    df --output=pcent "$JOURNAUX" | tail -1 | tr -dc '0-9'
}

controler_disque() {
    local avant apres detail anomalie=0
    avant=$(utilisation_disque)
    detail="Disque à $avant %, seuil $SEUIL_DISQUE %."

    if [ "$avant" -ge "$SEUIL_DISQUE" ]; then
        journal "disque à $avant %, au-delà du seuil : compression des journaux"
        if [ -x "$COMPRESSER" ]; then
            JOURNAUX="$JOURNAUX" "$COMPRESSER" > /dev/null \
                || journal "la compression a échoué"
        else
            journal "script de compression introuvable : $COMPRESSER"
        fi
        apres=$(utilisation_disque)

        if [ "$apres" -ge "$SEUIL_DISQUE" ]; then
            anomalie=1
            detail="Disque à $apres % malgré la compression (seuil $SEUIL_DISQUE %). \
Intervention nécessaire : la collecte s'arrête à 100 %."
        else
            detail="Disque revenu à $apres %."
            notifier 3 "Honeypot : journaux compressés" \
                "Le disque avait atteint $avant %. Compression effectuée, retour à $apres %." \
                "package" || true
        fi
    fi
    evaluer disque "$anomalie" "disque presque plein" "$detail" "floppy_disk" \
        "espace disque revenu à la normale"
}

# Âge en secondes du dernier événement JSON valide. Seules les lignes qui se
# décodent comptent : pendant l'incident, le fichier continuait de grossir avec
# des écritures tronquées, et sa date de modification restait récente.
age_dernier_evenement() {
    python3 - "$JOURNAUX/cowrie.json" << 'PY'
import json, os, sys
from datetime import datetime, timezone

FENETRE = 262144
chemin = sys.argv[1]
try:
    with open(chemin, "rb") as f:
        f.seek(0, os.SEEK_END)
        taille = f.tell()
        f.seek(max(0, taille - FENETRE))
        lignes = f.read().splitlines()
except OSError:
    print("absent")
    sys.exit()

for brut in reversed(lignes):
    try:
        horodatage = json.loads(brut)["timestamp"]
        t = datetime.fromisoformat(horodatage.replace("Z", "+00:00"))
    except (ValueError, KeyError, TypeError, AttributeError):
        continue
    # max() absorbe un éventuel recul de l'horloge système.
    print(max(0, int((datetime.now(timezone.utc) - t).total_seconds())))
    sys.exit()

# Aucune ligne valide. Si le fichier est petit, il vient d'être basculé à
# minuit : on se fie à sa date de création. S'il est gros, c'est exactement le
# cas de l'incident, des écritures sans aucun événement exploitable.
if taille <= FENETRE:
    print(int(datetime.now().timestamp() - os.path.getmtime(chemin)))
else:
    print(10**9)
PY
}

controler_fraicheur() {
    local age anomalie=0 detail
    age=$(age_dernier_evenement)
    if [ "$age" = absent ]; then
        anomalie=1
        detail="cowrie.json introuvable dans $JOURNAUX."
    elif [ "$age" -ge $((SEUIL_FRAICHEUR_MIN * 60)) ]; then
        anomalie=1
        if [ "$age" -ge 1000000000 ]; then
            detail="Le journal grossit mais ne contient plus aucun événement valide."
        else
            detail="Aucun événement valide depuis $((age / 60)) minutes."
        fi
        detail="$detail Le service peut rester actif sans rien collecter : \
vérifier cowrie.log et l'espace disque."
    else
        detail="dernier événement il y a $((age / 60)) min"
    fi
    evaluer fraicheur "$anomalie" "collecte interrompue" "$detail" "warning" \
        "collecte rétablie"
}

main() {
    charger_configuration
    mkdir -p "$ETAT"

    if [ "${1:-}" = "--test" ]; then
        notifier 3 "Honeypot : notification de test" \
            "La supervision est en place. Disque à $(utilisation_disque) %." \
            "test_tube"
        exit "$ECHEC_ENVOI"
    fi

    controler_disque
    controler_fraicheur

    # Un envoi échoué fait échouer l'unité : elle apparaît alors dans
    # « systemctl --failed », second moyen de s'en apercevoir.
    exit "$ECHEC_ENVOI"
}

main "$@"
