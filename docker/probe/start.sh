#!/bin/sh
# -----------------------------------------------------------------
# start.sh — avvia i container della SONDA snap
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
# La sonda usa la RETE HOST perche' deve vedere la rete del cliente: e' il caso
# normale su Linux, che e' dove la sonda va in esercizio.
set -eu

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
echo "=== snap probe: avvio dei container ==="

command -v docker >/dev/null 2>&1 || fermati "docker non e' installato (o non e' nel PATH)."
docker info --format '{{.ServerVersion}}' >/dev/null 2>&1 \
    || fermati "il daemon Docker non risponde: avviare il servizio docker e riprovare."

# Rete host: se il motore non e' Linux la sonda non vedrebbe la LAN. Va detto prima,
# non scoperto dopo con un inventario vuoto.
SISTEMA="$(docker info --format '{{.OSType}}' 2>/dev/null || echo '')"
if [ -n "$SISTEMA" ] && [ "$SISTEMA" != "linux" ]; then
    echo ""
    echo "AVVISO: il motore Docker non e' Linux (${SISTEMA}): la rete host non funziona"
    echo "come in esercizio e la sonda NON vedra' la rete del cliente."
fi

[ -f .env ] || fermati "manca il file .env. Copiarlo e compilarlo:  cp .env.example .env"
if ! grep -Eq '^[[:space:]]*SNAP_PROBE_SECRET_KEY[[:space:]]*=[[:space:]]*[^[:space:]]' .env; then
    echo "Da compilare in .env: SNAP_PROBE_SECRET_KEY" >&2
    echo "  python3 -c 'import secrets; print(secrets.token_urlsafe(48))'" >&2
    fermati "configurazione incompleta."
fi

if [ ! -f certs/probe.crt ] || [ ! -f certs/probe.key ]; then
    echo "Manca il certificato in ./certs/ (probe.crt e probe.key)." >&2
    echo "" >&2
    echo "  mkdir -p certs && openssl req -x509 -newkey rsa:4096 -sha256 -days 730 -nodes \\" >&2
    echo "    -keyout certs/probe.key -out certs/probe.crt \\" >&2
    echo "    -subj '/CN=sonda.example.local' \\" >&2
    echo "    -addext 'subjectAltName=DNS:sonda.example.local,IP:127.0.0.1'" >&2
    echo "  chmod 600 certs/probe.key" >&2
    fermati "certificato assente."
fi

if [ "$BUILD" -eq 1 ]; then
    docker compose up -d --build
else
    docker compose up -d
fi

echo ""
docker compose ps

echo ""
echo "Prima apertura: DALLA MACCHINA della sonda, aprire"
echo "  https://127.0.0.1:5510/primo-accesso"
echo "per scegliere la password. Dalla rete la PRIMA impostazione e' rifiutata (due"
echo "barriere: il controllo della sonda e una regola nel proxy): cosi' la sonda"
echo "appartiene a chi l'ha installata."
echo ""
echo "Poi si incolla il pacchetto SNAP1-... generato dalla console del server."
echo ""
echo "Log:      docker compose logs -f"
echo "Arresto:  ./stop.sh"

if [ "$LOGS" -eq 1 ]; then
    echo ""
    docker compose logs -f
fi
