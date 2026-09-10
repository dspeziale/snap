# -----------------------------------------------------------------
# Dockerfile — immagine di esercizio della SONDA snap
# Autore: Daniele Speziale
# Data creazione: 2026-09-09
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
# La sonda e' un motore di scansione: nell'immagine serve nmap, e serve che un
# processo NON-root possa aprire socket raw. Il TLS non si termina qui: davanti c'e'
# un reverse proxy (vedi docker-compose.yml e nginx.conf).
#
# Contesto di build: la RADICE del repository (serve `probe/`):
#   docker build -f docker/probe/Dockerfile -t snap-probe:1.2.8 .

# Stessa versione minore usata in sviluppo (3.13).
FROM python:3.13-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# nmap e' il motore della sonda, non un accessorio. `libcap2-bin` serve a `setcap`
# (sotto); `curl` al healthcheck. Niente altro: piu' pacchetti = piu' superficie.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends nmap libcap2-bin curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY probe/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY probe/ /app/

# Socket raw senza root. La scansione SYN (-sS) e il rilevamento del sistema
# operativo (-O) hanno bisogno di CAP_NET_RAW/CAP_NET_ADMIN. Con `cap_add` nel compose
# la capacita' entra nel container, ma un processo non-root la usa solo se e' scritta
# come capacita' DI FILE sull'eseguibile: senza questo `setcap`, nmap ripiegherebbe
# silenziosamente sulla scansione TCP connect (-sT) e non rileverebbe il sistema
# operativo. La sonda gestisce comunque il ripiego, ma qui la si mette in condizione
# di lavorare al meglio SENZA girare da root.
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap

RUN groupadd --gid 10002 snap \
    && useradd --uid 10002 --gid 10002 --no-create-home --shell /usr/sbin/nologin snap \
    && mkdir -p /data \
    && chown -R 10002:10002 /data /app
USER 10002:10002

# L'archivio locale della sonda (coda dei conferimenti, registrazione, impostazioni)
# sta in un volume: la sonda deve poter lavorare isolata e non perdere la coda quando
# l'immagine si aggiorna.
VOLUME ["/data"]

# La sonda ascolta SOLO sul loopback: l'interfaccia si raggiunge attraverso il proxy,
# che termina il TLS. Cosi' non esiste un canale in chiaro raggiungibile dalla rete.
ENV APP_PORT=5511 \
    SNAP_PROBE_STORE=/data/snap_probe.sqlite3 \
    SNAP_PROBE_BEHIND_PROXY=1
EXPOSE 5511

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${APP_PORT}/" -o /dev/null || exit 1

# UN SOLO worker: nel processo della sonda vive l'AGENTE (scoperta, scansione,
# controlli, conferimento). Con due worker due agenti scansionerebbero la stessa rete
# in parallelo, raddoppiando il carico sul cliente e duplicando i conferimenti. La
# concorrenza delle scansioni la governa l'agente con i propri thread, non Gunicorn.
CMD ["sh", "-c", "exec gunicorn --workers 1 --threads 4 \
     --bind 127.0.0.1:${APP_PORT} \
     --timeout 120 --graceful-timeout 30 \
     --access-logfile - --error-logfile - \
     'snapprobe:create_app()'"]
