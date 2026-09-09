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
SNAP_SERVER_SIEM_LISTENER=0 python - <<'PY'
from snapserver import create_app
from snapserver.seed import seed_initial_data

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
