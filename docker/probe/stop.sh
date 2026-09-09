#!/bin/sh
# -----------------------------------------------------------------
# stop.sh — arresta i container della SONDA snap
# Autore: Daniele Speziale
# Data creazione: 2026-09-09
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
# Uso:
#   ./stop.sh                 arresta e rimuove i container. I DATI RESTANO.
#   ./stop.sh --keep-running  solo ferma i container, senza rimuoverli
#   ./stop.sh --remove-data   rimuove ANCHE il volume: cancella l'archivio locale.
#
# Il volume della sonda contiene la REGISTRAZIONE al server e la coda dei
# conferimenti non ancora spediti: cancellarlo significa registrare di nuovo la sonda
# e perdere la coda.
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
echo "=== snap probe: arresto dei container ==="

command -v docker >/dev/null 2>&1 || { echo "ERRORE: docker non installato." >&2; exit 1; }
docker info --format '{{.ServerVersion}}' >/dev/null 2>&1 \
    || { echo "ERRORE: il daemon Docker non risponde: niente da arrestare." >&2; exit 1; }

case "$AZIONE" in
    stop)
        docker compose stop
        echo ""
        echo "Container fermati (non rimossi). Riavvio: docker compose start"
        echo "Con la sonda ferma la rete non viene scansionata: la copertura si ferma."
        ;;
    purge)
        echo ""
        echo "ATTENZIONE: con --remove-data viene cancellato il volume della sonda:" >&2
        echo "  - la REGISTRAZIONE al server (andra' rifatta dalla console)" >&2
        echo "  - la coda dei conferimenti non ancora spediti" >&2
        echo "  - la password dell'interfaccia e le impostazioni locali" >&2
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
        echo "Container e volume rimossi: la sonda va registrata di nuovo."
        ;;
    *)
        docker compose down
        echo ""
        echo "Container arrestati e rimossi. Registrazione e coda restano nel volume."
        echo "Riavvio: ./start.sh"
        echo "Nota: a sonda ferma il server la vedra' non raggiungibile e, se le"
        echo "scansioni erano attive, avvisera' che la copertura si e' fermata."
        ;;
esac
