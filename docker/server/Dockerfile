# -----------------------------------------------------------------
# Dockerfile — immagine di esercizio del server snap
# Autore: Daniele Speziale
# Data creazione: 2026-09-09
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
# Immagine minimale, utente non-root, nessun segreto in build. Il TLS NON si termina
# qui: davanti c'e' un reverse proxy (vedi docker-compose.yml e nginx.conf), come
# prescrive l'architettura del progetto.
#
# Contesto di build: la RADICE del repository (serve `server/`), non questa cartella:
#   docker build -f docker/server/Dockerfile -t snap-server:1.2.8 .

# Stessa versione minore usata in sviluppo (3.13), per non scoprire in esercizio
# differenze che in sviluppo non si vedono.
FROM python:3.13-slim AS base

# Niente file .pyc, output non bufferizzato (i log arrivano subito al motore di
# container), pip senza cache (immagine piu' piccola e nessun residuo di build).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Aggiornamento dei pacchetti di base: una immagine di esercizio non parte con
# vulnerabilita' note della distribuzione. `curl` serve al healthcheck.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Prima le dipendenze, poi il codice: cosi' il livello delle dipendenze resta in cache
# quando cambia solo il codice.
COPY server/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY server/ /app/

# Utente non-root con un id fisso: i volumi montati devono appartenere a lui, e un id
# fisso rende il permesso ripetibile fra macchine diverse.
RUN groupadd --gid 10001 snap \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin snap \
    && mkdir -p /data /app/data \
    && chown -R 10001:10001 /data /app
USER 10001:10001

# I dati stanno in un volume, non nell'immagine: l'archivio, i report e le copie
# sopravvivono all'aggiornamento dell'immagine.
VOLUME ["/data"]

# Porta interna del processo applicativo: il proxy davanti espone il 5500 in HTTPS.
# Resta nel range assegnato al progetto (5500-5600) anche se non e' pubblicata.
#
# Archivio, report e copie stanno TUTTI sotto /data (il volume): l'aggiornamento
# dell'immagine non deve portarsi via i dati. `BEHIND_PROXY` accende ProxyFix, senza
# il quale l'applicazione dietro il proxy non vedrebbe ne' https ne' l'IP del client.
ENV APP_PORT=5500 \
    SNAP_SERVER_DATABASE=/data/snap_server.sqlite3 \
    SNAP_SERVER_SIEM_DATABASE=/data/snap_siem.sqlite3 \
    SNAP_SERVER_REPORT_DIR=/data/reports \
    SNAP_SERVER_BACKUP_DIR=/data/backups \
    SNAP_SERVER_BEHIND_PROXY=1
EXPOSE 5500

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${APP_PORT}/login" -o /dev/null || exit 1

# UN SOLO worker, non e' una scelta di prestazioni: il server avvia nel proprio
# processo i servizi di fondo (spedizione notifiche, resoconto quotidiano, valutatore
# delle regole, sorveglianza termini ACN e sonde, rilevazione SIEM). Ognuno deve
# esistere UNA volta sola: con due worker si spedirebbero due volte le notifiche e si
# aprirebbero due volte gli stessi allarmi. La concorrenza si ottiene con i thread.
CMD ["sh", "-c", "exec gunicorn --workers 1 --threads 8 \
     --bind 0.0.0.0:${APP_PORT} \
     --timeout 120 --graceful-timeout 30 --keep-alive 5 \
     --access-logfile - --error-logfile - \
     'snapserver:create_app()'"]
