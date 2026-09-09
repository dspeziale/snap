#!/bin/sh
# -----------------------------------------------------------------
# entrypoint.sh — inizializza i dati di base, poi avvia Gunicorn
# Autore: Daniele Speziale
# Data creazione: 2026-09-09
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
# Perche' questo passaggio esiste: `create_app()` crea lo SCHEMA (init_db), ma NON i
# dati iniziali -- tenant e utenze amministrative le popola `seed_initial_data()`, che
# nel percorso di sviluppo viene chiamato da `run.py --init`. Sotto Gunicorn quel
# percorso non passa mai: senza il seed il database resta con lo schema e ZERO utenze,
# e l'accesso risponde "credenziali errate" senza altra spiegazione.
#
# Il seed e' idempotente (verifica l'esistenza per email prima di inserire), quindi si
# esegue a ogni avvio: e' quello che serve anche dopo un aggiornamento dell'immagine.
set -eu

echo "snap: inizializzazione dei dati di base"

# L'ascolto syslog si spegne SOLO per questo passaggio: creando l'applicazione anche
# qui, il processo di inizializzazione legherebbe la 5514 per un istante e potrebbe
# non averla ancora rilasciata quando Gunicorn la richiede.
# Schema e dati iniziali si fanno con le credenziali del PROPRIETARIO: l'utenza con
# cui gira l'applicazione puo' solo leggere e scrivere i dati, non creare tabelle.
# Questo e' il solo momento in cui il proprietario viene usato.
if [ -z "${SNAP_SERVER_OWNER_DATABASE_URL:-}" ]; then
    echo "snap: manca SNAP_SERVER_OWNER_DATABASE_URL (credenziali del proprietario" \
         "della base dati): senza, lo schema non si puo' allineare." >&2
    exit 1
fi

SNAP_SERVER_SIEM_LISTENER=0 \
SNAP_SERVER_INIT_DB=1 \
SNAP_SERVER_DATABASE_URL="$SNAP_SERVER_OWNER_DATABASE_URL" \
python - <<'PY'
from snapserver import create_app
from snapserver.seed import seed_initial_data

# create_app() allinea lo schema (SNAP_SERVER_INIT_DB=1 solo qui); poi i dati iniziali.
app = create_app()
with app.app_context():
    for riga in seed_initial_data():
        print("  %s" % riga)
PY

echo "snap: avvio di Gunicorn sulla porta ${APP_PORT}"

# UN SOLO worker: nel processo vivono i servizi di fondo (notifiche, resoconto,
# regole, termini ACN, sonde bloccate, rilevazione SIEM) e ognuno deve esistere una
# volta sola. La concorrenza si ottiene con i thread.
exec gunicorn \
    --workers 1 \
    --threads 8 \
    --bind "0.0.0.0:${APP_PORT}" \
    --timeout 120 \
    --graceful-timeout 30 \
    --keep-alive 5 \
    --access-logfile - \
    --error-logfile - \
    'snapserver:create_app()'
