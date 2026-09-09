#!/bin/sh
# -----------------------------------------------------------------
# backup-postgres.sh — copia della base dati con retention
# Autore: Daniele Speziale
# Data creazione: 2026-09-09
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
# Copia compressa della base dati e cancellazione delle copie oltre la retention.
# Pensato per essere schedulato dall'host (cron / Utilita' di pianificazione):
#
#   0 2 * * *  cd /opt/snap/docker/server && ./backup-postgres.sh >> /var/log/snap-backup.log 2>&1
#
# Gira DENTRO il container della base dati (`docker compose exec`), cosi' non serve
# pubblicare la porta di PostgreSQL sull'host ne' installare i client sull'host: il
# principio e' che la base dati parli solo con chi sta sulla sua rete.
#
# La copia contiene dati personali (indirizzi, utenze, log): la cartella di
# destinazione va tenuta con permessi restrittivi e, se lascia la macchina, cifrata
# (GDPR art. 32).
#
# NON E' LA STESSA COSA DELLA COPIA CHIESTA DALLA CONSOLE, e va saputo prima di
# averne bisogno:
#   * questo script scrive SQL compresso (.sql.gz) nel volume della base dati, si
#     ripristina con `psql` e nella console non compare;
#   * la console scrive un archivio pg_dump in formato personalizzato (.dump) nella
#     propria cartella delle copie, lo verifica e lo ripristina da se'.
# Sono due strade complementari -- una schedulata dall'host, una a richiesta -- e
# nessuna delle due sa ripristinare il file dell'altra. Chi imposta la continuita'
# operativa (NIS2) scelga quale delle due e' la copia ufficiale, e la provi.
set -eu

# Giorni di conservazione: sovrascrivibile dall'ambiente.
RETENTION_GIORNI="${SNAP_BACKUP_RETENTION_DAYS:-14}"
# Cartella DENTRO il container (volume `postgres-backups`).
DESTINAZIONE="/backups"

# Le credenziali si leggono da .env: non si scrivono qui e non si passano sulla riga
# di comando (sarebbero visibili nella lista dei processi).
if [ -f .env ]; then
    # shellcheck disable=SC1091
    . ./.env
fi

DB="${POSTGRES_DB:-snap}"
UTENTE="${POSTGRES_USER:-snap_owner}"
ISTANTE="$(date -u +%Y%m%d-%H%M%S)"
NOME="snap-${DB}-${ISTANTE}.sql.gz"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] copia di '${DB}' in ${DESTINAZIONE}/${NOME}"

# `pg_dump` in formato testo compresso: si rilegge con psql anche fra versioni
# diverse, che e' cio' che serve a una copia di continuita' operativa.
# PGPASSWORD arriva dall'ambiente del container, non dalla riga di comando.
docker compose exec -T \
    -e PGPASSWORD="${POSTGRES_PASSWORD:?password del proprietario mancante: vedi .env}" \
    postgres sh -c "pg_dump --username '${UTENTE}' --dbname '${DB}' --no-owner --no-privileges \
        | gzip -9 > '${DESTINAZIONE}/${NOME}'"

# Verifica che la copia non sia vuota: una copia da zero byte e' peggio di nessuna
# copia, perche' da' l'impressione che ci sia.
BYTE="$(docker compose exec -T postgres sh -c "stat -c %s '${DESTINAZIONE}/${NOME}' 2>/dev/null || echo 0")"
BYTE="$(printf '%s' "$BYTE" | tr -d '\r')"
if [ "${BYTE:-0}" -lt 100 ]; then
    echo "ERRORE: la copia ${NOME} risulta vuota (${BYTE} byte): non si cancella nulla." >&2
    exit 1
fi
echo "copia completata: ${BYTE} byte"

# Retention: si cancella solo DOPO aver verificato la copia nuova.
echo "cancellazione delle copie oltre ${RETENTION_GIORNI} giorni"
docker compose exec -T postgres sh -c \
    "find '${DESTINAZIONE}' -name 'snap-*.sql.gz' -type f -mtime +${RETENTION_GIORNI} -print -delete"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] fatto"
