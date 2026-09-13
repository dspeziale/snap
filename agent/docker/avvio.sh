#!/usr/bin/env sh
# -----------------------------------------------------------------
# avvio.sh — punto d'ingresso del container dell'agente
# Autore: Daniele Speziale
# Data creazione: 2026-09-13
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
#
# Fa una cosa sola che l'agente non puo' fare da se': REGISTRARSI AL PRIMO AVVIO.
# Il container si avvia una prima volta senza identita' e una seconda con la chiave
# gia' in mano; distinguere i due casi qui evita che chi installa debba eseguire due
# comandi diversi in due momenti diversi.
set -eu

CONFIG="${SNAP_AGENT_CONFIG:-/stato/snap-agent.json}"
AGENTE="/app/snap_agent.py"

mkdir -p "$(dirname "$CONFIG")"

# Un comando esplicito vince sul servizio: serve per guardare senza installare
# niente sulla macchina --
#   docker compose run --rm snap-agent prova --riassunto
#   docker compose exec snap-agent configura --gruppi minimo
if [ "$#" -gt 0 ]; then
    exec python "$AGENTE" --configurazione "$CONFIG" "$@"
fi

registrato() {
    python - "$CONFIG" <<'FINE'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as file:
        raise SystemExit(0 if json.load(file).get("agent") else 1)
except (OSError, ValueError):
    raise SystemExit(1)
FINE
}

if ! registrato; then
    if [ -z "${SNAP_AGENT_SONDA:-}" ] || [ -z "${SNAP_AGENT_TOKEN:-}" ]; then
        echo "non registrato, e mancano SNAP_AGENT_SONDA / SNAP_AGENT_TOKEN." >&2
        echo "Il token si emette dalla console della sonda, pagina Agenti: vale" >&2
        echo "un'ora e una volta sola. Metterlo nel file .env accanto al compose." >&2
        exit 4
    fi
    TLS=""
    if [ "${SNAP_AGENT_VERIFICA_TLS:-1}" = "0" ]; then
        TLS="--senza-verifica-tls"
    fi
    GRUPPI=""
    if [ -n "${SNAP_AGENT_GRUPPI:-}" ]; then
        GRUPPI="--gruppi ${SNAP_AGENT_GRUPPI}"
    fi
    echo "prima accensione: registro la macchina sulla sonda ${SNAP_AGENT_SONDA}"
    # shellcheck disable=SC2086
    python "$AGENTE" --configurazione "$CONFIG" $TLS \
        registra "$SNAP_AGENT_SONDA" "$SNAP_AGENT_TOKEN" $GRUPPI
    echo "registrata. Il token e' stato speso: toglierlo dal file .env."
fi

exec python "$AGENTE" --configurazione "$CONFIG" servizio
