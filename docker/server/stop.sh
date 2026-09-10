#!/bin/sh
# -----------------------------------------------------------------
# stop.sh — arresta i container del SERVER snap
# Autore: Daniele Speziale
# Data creazione: 2026-09-09
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
# Uso:
#   ./stop.sh                 arresta e rimuove i container. I DATI RESTANO.
#   ./stop.sh --keep-running  solo ferma i container, senza rimuoverli
#   ./stop.sh --remove-data   rimuove ANCHE i volumi: cancella la base dati. Chiede conferma.
#
# Per difetto i volumi NON si toccano: `docker compose down -v` cancellerebbe
# l'archivio, i report e la base dati PostgreSQL. Un arresto non deve poter
# distruggere i dati per distrazione.
set -eu

cd "$(dirname "$0")"

AZIONE="down"
for argomento in "$@"; do
    case "$argomento" in
        --keep-running) AZIONE="stop" ;;
        --remove-data)  AZIONE="purge" ;;
        *) echo "argomento non riconosciuto: $argomento" >&2; exit 2 ;;
    esac
done

echo ""
echo "=== snap server: arresto dei container ==="

command -v docker >/dev/null 2>&1 || { echo "ERRORE: docker non installato." >&2; exit 1; }
docker info --format '{{.ServerVersion}}' >/dev/null 2>&1 \
    || { echo "ERRORE: il daemon Docker non risponde: niente da arrestare." >&2; exit 1; }

case "$AZIONE" in
    stop)
        docker compose stop
        echo ""
        echo "Container fermati (non rimossi). Riavvio: docker compose start"
        ;;
    purge)
        echo ""
        echo "ATTENZIONE: con --remove-data vengono cancellati anche i VOLUMI:" >&2
        echo "  - la base dati PostgreSQL" >&2
        echo "  - l'archivio del server, i report e le copie di sicurezza" >&2
        echo "L'operazione NON e' reversibile." >&2
        echo ""
        printf "Scrivere CANCELLA per procedere: "
        read -r conferma
        if [ "$conferma" != "CANCELLA" ]; then
            echo "Annullato: nessun dato e' stato cancellato."
            exit 0
        fi
        docker compose down --volumes
        echo ""
        echo "Container e volumi rimossi."
        ;;
    *)
        docker compose down
        echo ""
        echo "Container arrestati e rimossi. I dati restano nei volumi."
        echo "Riavvio: ./start.sh"
        ;;
esac
