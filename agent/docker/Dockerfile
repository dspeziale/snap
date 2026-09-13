# -----------------------------------------------------------------
# Dockerfile — l'agente snap in un container
# Autore: Daniele Speziale
# Data creazione: 2026-09-13
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
#
# IL VINCOLO DA CONOSCERE PRIMA DI COSTRUIRLO
# Un agente dentro un container misura IL CONTAINER: due processi, mezzo giga di
# memoria, un filesystem che non esiste sulla macchina. Sarebbe un dato esatto e
# inutile -- il modo peggiore di sbagliare, perche' sembra funzionare.
#
# Perche' misuri la MACCHINA servono tre cose, tutte nel docker-compose.yml accanto:
#   * `pid: host`      i processi sono quelli della macchina
#   * `network_mode: host`  le porte in ascolto e le interfacce sono quelle della
#                      macchina, e la sonda si raggiunge dalla sua rete
#   * `/:/hostfs:ro` + SNAP_AGENT_HOSTFS=/hostfs  il filesystem e /proc sono quelli
#                      della macchina
#
# CHE COSA RESTA FUORI ANCHE COSI', ed e' dichiarato invece che taciuto: i gruppi che
# hanno bisogno di uno STRUMENTO della macchina -- `systemctl` per i servizi,
# `journalctl` per gli accessi falliti, `dpkg`/`rpm` per il software installato,
# `apt`/`dnf` per gli aggiornamenti. Quegli strumenti stanno sulla macchina, non qui,
# e l'agente li dichiara come guasti di gruppo: la console scrivera' "non misurato".
#
# Per questo il container e' la forma buona per i SERVER di cui interessano carico,
# dischi, rete, porte in ascolto e processi; per l'inventario completo del software
# l'installazione nativa (installa.sh) vede tutto.
#
# Contesto di build: la cartella `agent/` del pacchetto.
#   docker build -f docker/Dockerfile -t snap-agent:1.2.2 .

FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # La radice della macchina ospite, montata in sola lettura dal compose. Senza
    # questa variabile l'agente misurerebbe il container.
    SNAP_AGENT_HOSTFS=/hostfs \
    SNAP_AGENT_CONFIG=/stato/snap-agent.json

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY snap_agent.py /app/snap_agent.py
COPY docker/avvio.sh /app/avvio.sh
RUN chmod +x /app/avvio.sh

# NON-ROOT non si puo': per leggere il /proc degli altri processi della macchina --
# cioe' per sapere QUALE processo tiene aperta una porta, che e' la ragione per cui
# questo agente esiste -- serve root. Il container pero' non ha alcuna capacita' in
# piu' del necessario (vedi `cap_drop` nel compose) e monta la macchina in SOLA
# LETTURA: puo' guardare, non toccare.
#
# Lo stato (la chiave di firma) sta in un volume dedicato, non nell'immagine:
# un'immagine che contenesse una credenziale sarebbe una credenziale pubblicata.
VOLUME ["/stato"]

HEALTHCHECK --interval=5m --timeout=30s --start-period=1m \
    CMD python /app/snap_agent.py --configurazione "$SNAP_AGENT_CONFIG" prova \
        --riassunto > /dev/null || exit 1

ENTRYPOINT ["/app/avvio.sh"]
