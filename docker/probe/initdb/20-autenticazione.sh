#!/bin/sh
# -----------------------------------------------------------------
# 20-autenticazione.sh — richiede la password anche dal loopback
# Autore: Daniele Speziale
# Data creazione: 2026-09-09
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
# Eseguito UNA sola volta, alla prima inizializzazione del volume.
#
# PERCHE' SERVE QUI E NON SUL SERVER. L'immagine ufficiale di PostgreSQL genera un
# pg_hba.conf che si fida senza password delle connessioni dal loopback:
#
#     host  all  all  127.0.0.1/32  trust
#     host  all  all  ::1/128       trust
#
# Sul server quel loopback e' quello INTERNO al contenitore, che nessun altro
# processo condivide: la regola e' irraggiungibile. La sonda invece gira in rete
# host, e la sua base dati ascolta sul loopback DELLA MACCHINA: con quelle righe
# qualunque processo locale sull'apparato potrebbe collegarsi come PROPRIETARIO
# della base dati senza conoscere alcuna password. Su un apparato lasciato in sede
# dal cliente non e' accettabile.
#
# Cosa resta a `trust`: le connessioni `local`, cioe' quelle sul socket unix. Quel
# socket vive nel filesystem del contenitore (/var/run/postgresql) e non e' esposto
# all'host, quindi non e' raggiungibile da fuori; e serve all'entrypoint
# dell'immagine, che si collega senza password per eseguire questi stessi script --
# togliendolo, l'inizializzazione si romperebbe.
#
# Il file viene riscritto per intero invece di essere corretto con `sed`: cosi' cio'
# che vale e' scritto qui, in chiaro, e non dipende da quali righe l'immagine
# generera' domani.
set -eu

cat > "$PGDATA/pg_hba.conf" <<'HBA'
# Riscritto da 20-autenticazione.sh alla prima inizializzazione.
# Vedi il commento in quello script per il perche' di ogni riga.

# Socket unix, interno al contenitore e non esposto all'host: serve
# all'entrypoint dell'immagine, che si collega senza password.
local   all             all                                     trust

# TCP dal loopback: e' il loopback della MACCHINA (rete host), condiviso con
# ogni processo locale. Password obbligatoria.
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             ::1/128                 scram-sha-256

# Qualunque altra origine: password obbligatoria. In pratica non si presenta,
# perche' il servizio ascolta solo su 127.0.0.1 (listen_addresses).
host    all             all             all                     scram-sha-256

# Replica: non prevista in questa installazione, e non la si apre "per comodita'".
local   replication     all                                     trust
HBA

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -c "SELECT pg_reload_conf()" > /dev/null

echo "snap: autenticazione richiesta anche dal loopback (pg_hba.conf riscritto)"
