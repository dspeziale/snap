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
#
# E su Docker Desktop c'e' un secondo effetto, piu' immediato: i container stanno in
# una macchina virtuale, quindi con la rete host le porte 5510/5512 restano dentro
# quella macchina e l'interfaccia risulta irraggiungibile dall'host (connessione
# rifiutata anche a container "healthy"). In quel caso si passa alla variante che
# PUBBLICA le porte -- serve a provare l'interfaccia, non a scansionare.
SISTEMA="$(docker info --format '{{.OSType}}' 2>/dev/null || echo '')"
DESKTOP=0
if [ -n "$SISTEMA" ] && [ "$SISTEMA" != "linux" ]; then
    DESKTOP=1
    echo ""
    echo "AVVISO: il motore Docker non e' Linux (${SISTEMA}): la rete host non funziona"
    echo "come in esercizio e la sonda NON vedra' la rete del cliente."
elif [ "$(uname -s 2>/dev/null || echo '')" = "Darwin" ]; then
    # Motore Linux ma host macOS: e' Docker Desktop, stesso limite.
    DESKTOP=1
    echo ""
    echo "AVVISO: Docker Desktop su macOS: la rete host passa da una macchina virtuale"
    echo "e la sonda vede quella rete, non quella del cliente. In esercizio: Linux."
fi

COMPOSE="docker compose"
if [ "$DESKTOP" -eq 1 ]; then
    COMPOSE="docker compose -f docker-compose.yml -f docker-compose.desktop.yml"
    echo ""
    echo "Si usa docker-compose.desktop.yml: le porte 5510/5512 vengono PUBBLICATE,"
    echo "altrimenti l'interfaccia resterebbe irraggiungibile dall'host."
fi

[ -f .env ] || fermati "manca il file .env. Copiarlo e compilarlo:  cp .env.example .env"
if ! grep -Eq '^[[:space:]]*SNAP_PROBE_SECRET_KEY[[:space:]]*=[[:space:]]*[^[:space:]]' .env; then
    echo "Da compilare in .env: SNAP_PROBE_SECRET_KEY" >&2
    echo "  python3 -c 'import secrets; print(secrets.token_urlsafe(48))'" >&2
    fermati "configurazione incompleta."
fi

# Le password della base dati sono dichiarate obbligatorie nel compose: senza, il
# contenitore non parte. Meglio dirlo qui che in mezzo all'avvio.
MANCANTI=""
for CHIAVE in PROBE_POSTGRES_PASSWORD PROBE_PG_APP_PASSWORD; do
    if ! grep -Eq "^[[:space:]]*${CHIAVE}[[:space:]]*=[[:space:]]*[^[:space:]]" .env; then
        MANCANTI="${MANCANTI} ${CHIAVE}"
    fi
done
if [ -n "$MANCANTI" ]; then
    echo "Da compilare in .env:${MANCANTI}" >&2
    echo "  python3 -c 'import secrets; print(secrets.token_urlsafe(32))'" >&2
    echo "Due password DIVERSE: proprietario della base dati e utente applicativo" >&2
    echo "sono due livelli di accesso distinti." >&2
    fermati "configurazione della base dati incompleta."
fi

if [ ! -f certs/probe.crt ] || [ ! -f certs/probe.key ]; then
    echo "Manca il certificato in ./certs/ (probe.crt e probe.key)." >&2
    echo "" >&2
    echo "  mkdir -p certs && openssl req -x509 -newkey rsa:4096 -sha256 -days 730 -nodes \\" >&2
    echo "    -keyout certs/probe.key -out certs/probe.crt \\" >&2
    echo "    -subj '/CN=sonda.example.local' \\" >&2
    echo "    -addext 'subjectAltName=DNS:sonda.example.local,IP:127.0.0.1,IP:<ip-macchina>'" >&2
    echo "  chmod 600 certs/probe.key" >&2
    echo "" >&2
    echo "Elencare nel SAN anche l'IP con cui si aprira' l'interfaccia: un certificato" >&2
    echo "valido solo per 127.0.0.1 fa avvisare il browser sull'IP." >&2
    fermati "certificato assente."
fi

if [ "$BUILD" -eq 1 ]; then
    $COMPOSE up -d --build
else
    $COMPOSE up -d
fi

echo ""
$COMPOSE ps

# L'indirizzo con cui gli altri vedono questa macchina: si configura la sonda anche
# puntando l'IP, non solo il loopback.
INDIRIZZO="$(hostname -I 2>/dev/null | awk '{print $1}')"

echo ""
echo "Prima apertura, per scegliere la password:"
[ -n "$INDIRIZZO" ] && echo "  https://${INDIRIZZO}:5510/primo-accesso"
echo "  https://127.0.0.1:5510/primo-accesso"
echo ""
if [ "$DESKTOP" -eq 1 ]; then
    echo "In questa variante di prova la prima impostazione e' ammessa dalle reti"
    echo "private (dietro il NAT di Docker il chiamante non e' il loopback)."
else
    echo "Dalla rete la PRIMA impostazione e' rifiutata (due barriere: il controllo"
    echo "della sonda e una regola nel proxy): cosi' la sonda appartiene a chi l'ha"
    echo "installata. Per configurarla puntando l'IP, aggiungere la propria postazione"
    echo "in allow-primo-accesso.conf e in SNAP_PROBE_FIRST_ACCESS_FROM (.env)."
fi
echo ""
echo "Poi si incolla il pacchetto SNAP1-... generato dalla console del server."
echo ""
echo "Log:      docker compose logs -f"
echo "Arresto:  ./stop.sh"

if [ "$LOGS" -eq 1 ]; then
    echo ""
    docker compose logs -f
fi
