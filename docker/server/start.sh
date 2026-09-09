#!/bin/sh
# -----------------------------------------------------------------
# start.sh — avvia i container del SERVER snap (console + SIEM + PostgreSQL)
# Autore: Daniele Speziale
# Data creazione: 2026-09-09
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
# Uso:
#   ./start.sh              avvia (ricostruendo l'immagine se il codice e' cambiato)
#   ./start.sh --no-build   avvia senza ricostruire
#   ./start.sh --logs       avvia e resta in ascolto sui log
#
# Si controllano PRIMA le condizioni che fanno fallire un avvio in modo
# incomprensibile (daemon spento, .env mancante, certificato assente).
set -eu

# Si lavora nella cartella dello script: il compose e i percorsi relativi
# (./certs, ./nginx.conf) sono riferiti a questa.
cd "$(dirname "$0")"

BUILD=1
LOGS=0
for argomento in "$@"; do
    case "$argomento" in
        --no-build) BUILD=0 ;;
        --logs)     LOGS=1 ;;
        *) echo "argomento non riconosciuto: $argomento" >&2; exit 2 ;;
    esac
done

fermati() {
    echo ""
    echo "ERRORE: $1" >&2
    echo ""
    exit 1
}

echo ""
echo "=== snap server: avvio dei container ==="

# 1. Docker c'e' ed e' in ascolto?
command -v docker >/dev/null 2>&1 || fermati "docker non e' installato (o non e' nel PATH)."
docker info --format '{{.ServerVersion}}' >/dev/null 2>&1 \
    || fermati "il daemon Docker non risponde: avviare il servizio docker e riprovare."

# 2. La configurazione: senza .env il compose si ferma sui segreti obbligatori.
[ -f .env ] || fermati "manca il file .env. Copiarlo e compilarlo:  cp .env.example .env"
MANCANTI=""
for chiave in SNAP_SERVER_SECRET_KEY POSTGRES_PASSWORD SNAP_PG_APP_PASSWORD; do
    if ! grep -Eq "^[[:space:]]*${chiave}[[:space:]]*=[[:space:]]*[^[:space:]]" .env; then
        MANCANTI="${MANCANTI} ${chiave}"
    fi
done
if [ -n "$MANCANTI" ]; then
    echo "Da compilare in .env:${MANCANTI}" >&2
    echo "Generare i segreti con:" >&2
    echo "  python3 -c 'import secrets; print(secrets.token_urlsafe(48))'" >&2
    fermati "configurazione incompleta."
fi

# 3. Il certificato TLS: si monta, non sta nell'immagine.
if [ ! -f certs/server.crt ] || [ ! -f certs/server.key ]; then
    echo "Manca il certificato in ./certs/ (server.crt e server.key)." >&2
    echo "Per una prova interna se ne genera uno autofirmato (in esercizio usare un" >&2
    echo "certificato della propria CA, altrimenti il browser avvisa ogni volta):" >&2
    echo "" >&2
    echo "  mkdir -p certs && openssl req -x509 -newkey rsa:4096 -sha256 -days 730 -nodes \\" >&2
    echo "    -keyout certs/server.key -out certs/server.crt \\" >&2
    echo "    -subj '/CN=snap.example.local' \\" >&2
    echo "    -addext 'subjectAltName=DNS:snap.example.local,IP:10.20.10.42'" >&2
    echo "  chmod 600 certs/server.key" >&2
    fermati "certificato assente."
fi

# 4. Avvio.
if [ "$BUILD" -eq 1 ]; then
    docker compose up -d --build
else
    docker compose up -d
fi

echo ""
docker compose ps

# La porta pubblicata puo' essere stata cambiata in .env: si legge da la'.
PORTA="$(grep -E '^[[:space:]]*SNAP_HTTPS_PORT[[:space:]]*=' .env 2>/dev/null \
         | head -1 | sed 's/.*=[[:space:]]*//' | tr -d '\r')"
[ -n "${PORTA:-}" ] || PORTA=5500
# Con la 443 il numero non si scrive: e' la porta predefinita di https.
if [ "$PORTA" = "443" ]; then SUFFISSO=""; else SUFFISSO=":${PORTA}"; fi

echo ""
echo "Console: https://<indirizzo-del-server>${SUFFISSO}/"
echo "Ricordarsi, nella console: Amministrazione > Impostazioni Sistema >"
echo "Indirizzo pubblico del server, con https:// (entra nei pacchetti delle sonde,"
echo "nelle email ai nuovi utenti e nelle copertine dei report)."
echo ""
echo "Log:      docker compose logs -f"
echo "Arresto:  ./stop.sh"

if [ "$LOGS" -eq 1 ]; then
    echo ""
    docker compose logs -f
fi
