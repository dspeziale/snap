#!/bin/sh
# -----------------------------------------------------------------
# 10-utente-applicativo.sh — crea l'utente con cui l'applicazione si collega
# Autore: Daniele Speziale
# Data creazione: 2026-09-09
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
# Eseguito UNA sola volta, alla prima inizializzazione del volume della base dati.
#
# Principio del minimo privilegio: l'applicazione NON si collega con il proprietario.
# Il proprietario (POSTGRES_USER) crea e migra lo schema; l'utente applicativo puo'
# soltanto leggere e scrivere i dati -- niente CREATE, niente DROP, niente superuser.
# Cosi' un difetto dell'applicazione non puo' cancellare lo schema, e una credenziale
# applicativa rubata non permette di riscrivere la base dati.
set -eu

# I nomi si passano come identificatori (%I) e la password come letterale (%L): li
# cita PostgreSQL, non la shell. Interpolare la password nel testo SQL a mano sarebbe
# un'iniezione in attesa di una password con un apice.
psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" \
     --set=app_user="$SNAP_PG_APP_USER" \
     --set=app_password="$SNAP_PG_APP_PASSWORD" \
     --set=db_name="$POSTGRES_DB" <<'SQL'

-- 1. L'utente applicativo, senza alcun privilegio amministrativo.
SELECT format(
    'CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION',
    :'app_user', :'app_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_user')
\gexec

-- 2. Nessun privilegio implicito per tutti: in PostgreSQL, per difetto, PUBLIC puo'
--    creare oggetti nello schema public. Si toglie: lo schema lo governa il
--    proprietario.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'db_name') \gexec

-- 3. All'applicazione: collegarsi, vedere lo schema, leggere e scrivere i dati.
--    NON creare oggetti: le migrazioni sono compito del proprietario.
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', :'db_name', :'app_user') \gexec
SELECT format('GRANT USAGE ON SCHEMA public TO %I', :'app_user') \gexec
SELECT format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %I',
              :'app_user') \gexec
SELECT format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %I',
              :'app_user') \gexec

-- 4. Le tabelle che il proprietario creera' in futuro (le migrazioni) devono essere
--    utilizzabili dall'applicazione senza rifare i permessi a mano: chi dimentica
--    questo passaggio scopre il problema al primo deploy, in esercizio.
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public'
              ' GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I',
              current_user, :'app_user')
\gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public'
              ' GRANT USAGE, SELECT ON SEQUENCES TO %I',
              current_user, :'app_user')
\gexec

SQL

echo "snap: utente applicativo '$SNAP_PG_APP_USER' creato con privilegi minimi"
