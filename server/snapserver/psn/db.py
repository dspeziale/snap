# -----------------------------------------------------------------
# psn/db.py — archivio del sottosistema PSN, separato da quello del prodotto
# Autore: Daniele Speziale
# Data creazione: 2026-09-11
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Connessione all'archivio PSN.

UN DATABASE PROPRIO, E NON UNO SCHEMA. La differenza conta: uno schema dentro il
database del prodotto si elimina con un `DROP SCHEMA`, ma finisce nelle copie di
sicurezza del prodotto, nei suoi conteggi di dimensione, nelle sue migrazioni. Un
database distinto si butta con un `DROP DATABASE` e non lascia traccia -- che e' la
condizione posta: si deve poter eliminare se il lavoro non convince.

DOVE PRENDE L'INDIRIZZO. In ordine:
  1. `SNAP_SERVER_PSN_DATABASE_URL`, se dichiarato;
  2. altrimenti lo DERIVA dal DSN del prodotto cambiando il solo nome del database
     (`snap` -> `snap_psn`). Cosi' un'installazione esistente non deve configurare
     niente, e le credenziali non si duplicano in un secondo segreto.

IL DATABASE SE LO CREA DA SE'. Un sottosistema che pretende un `createdb` a mano
prima di funzionare non e' installato, e' da installare. Alla prima apertura, se il
database non esiste, lo crea con l'utenza proprietaria (la stessa che migra lo schema
del prodotto) e ci applica il proprio schema.

remarks: Autore: Daniele Speziale - Data: 2026-09-11
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re
import threading
from pathlib import Path

from flask import current_app, g
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine

from ..db import Riga, _con_segnaposto, _legati

SCHEMA = Path(__file__).with_name("schema.sql")

# Nome predefinito del database, derivato da quello del prodotto.
SUFFISSO = "_psn"

_serratura = threading.Lock()


def _cambia_database(dsn: str, nome: str) -> str:
    """Sostituisce il nome del database in un DSN, lasciando tutto il resto."""
    # Si tocca solo l'ultimo segmento del percorso, prima di eventuali parametri:
    # l'host, la porta e le credenziali restano quelli del prodotto.
    return re.sub(r"/([^/?]+)(\?|$)", lambda m: "/%s%s" % (nome, m.group(2)), dsn, count=1)


def _nome_database(dsn: str) -> str:
    trovato = re.search(r"/([^/?]+)(\?|$)", dsn)
    return trovato.group(1) if trovato else ""


def dsn() -> str:
    """Indirizzo dell'archivio PSN. Vuoto se il prodotto non ha un archivio."""
    dichiarato = (current_app.config.get("PSN_DATABASE_URL") or "").strip()
    if dichiarato:
        return dichiarato
    base = (current_app.config.get("DATABASE_URL") or "").strip()
    if not base:
        return ""
    return _cambia_database(base, _nome_database(base) + SUFFISSO)


def dsn_proprietario() -> str:
    """Indirizzo con l'utenza che puo' CREARE il database e lo schema."""
    dichiarato = (current_app.config.get("PSN_OWNER_DATABASE_URL") or "").strip()
    if dichiarato:
        return dichiarato
    base = (current_app.config.get("OWNER_DATABASE_URL") or "").strip()
    if not base:
        # Senza un'utenza proprietaria si prova con quella applicativa: su
        # un'installazione di sviluppo sono la stessa, e fallire subito con un
        # messaggio chiaro e' meglio di non provare.
        base = (current_app.config.get("DATABASE_URL") or "").strip()
    if not base:
        return ""
    return _cambia_database(base, _nome_database(dsn()))


def _crea_database_se_manca() -> None:
    """Crea il database PSN se non esiste. Va eseguito con l'utenza proprietaria."""
    proprietario = dsn_proprietario()
    if not proprietario:
        raise RuntimeError(
            "Archivio PSN non configurabile: manca SNAP_SERVER_DATABASE_URL")
    nome = _nome_database(proprietario)
    # Per creare un database ci si collega a un ALTRO database: `postgres` esiste
    # sempre. Con `AUTOCOMMIT` perche' CREATE DATABASE non sta in una transazione.
    amministrativo = _cambia_database(proprietario, "postgres")
    motore = create_engine(amministrativo, isolation_level="AUTOCOMMIT",
                           pool_pre_ping=True, future=True)
    try:
        with motore.connect() as connessione:
            esistente = connessione.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :n"),
                {"n": nome}).first()
            if esistente is None:
                # Il nome viene da una configurazione, non da una richiesta web, ma
                # si valida comunque: e' interpolato in un comando che non ammette
                # segnaposto.
                if not re.fullmatch(r"[A-Za-z0-9_]{1,63}", nome):
                    raise RuntimeError("nome di database PSN non valido: %r" % nome)
                connessione.exec_driver_sql('CREATE DATABASE "%s"' % nome)
                current_app.logger.info("Archivio PSN creato: database %s", nome)
    finally:
        motore.dispose()


def _applica_schema() -> None:
    """Applica lo schema PSN. Idempotente: tutte le creazioni sono IF NOT EXISTS."""
    motore = create_engine(dsn_proprietario(), pool_pre_ping=True, future=True)
    try:
        with motore.begin() as connessione:
            connessione.exec_driver_sql(SCHEMA.read_text(encoding="utf-8"))
            # L'utenza applicativa deve poter leggere e scrivere i dati, non
            # cambiare la struttura: e' la stessa divisione del prodotto.
            utente = _utente_applicativo()
            if utente:
                connessione.exec_driver_sql(
                    "GRANT USAGE ON SCHEMA public TO \"%s\"" % utente)
                connessione.exec_driver_sql(
                    "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES"
                    " IN SCHEMA public TO \"%s\"" % utente)
                connessione.exec_driver_sql(
                    "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public"
                    " TO \"%s\"" % utente)
    finally:
        motore.dispose()


def _utente_applicativo() -> str:
    """L'utenza applicativa estratta dal DSN, per concederle i permessi sui dati."""
    trovato = re.search(r"//([^:/@]+)(?::[^@]*)?@", dsn())
    nome = trovato.group(1) if trovato else ""
    return nome if re.fullmatch(r"[A-Za-z0-9_]{1,63}", nome or "") else ""


def motore() -> Engine:
    """Motore dell'archivio PSN, uno per processo.

    Alla prima richiesta crea il database e applica lo schema: il sottosistema si
    installa aprendolo, non prima.
    """
    esistente = current_app.extensions.get("snap_psn_engine")
    if esistente is not None:
        return esistente

    indirizzo = dsn()
    if not indirizzo:
        raise RuntimeError(
            "Archivio PSN non configurato: manca SNAP_SERVER_DATABASE_URL"
            " (l'indirizzo dell'archivio PSN si deriva da quello del prodotto)")

    with _serratura:
        esistente = current_app.extensions.get("snap_psn_engine")
        if esistente is not None:
            return esistente
        _crea_database_se_manca()
        _applica_schema()
        nuovo = create_engine(
            indirizzo,
            pool_pre_ping=True,
            pool_recycle=int(current_app.config.get("DB_POOL_RECYCLE_SEC", 1800)),
            future=True,
        )
        current_app.extensions["snap_psn_engine"] = nuovo
        return nuovo


def get_db() -> Connection:
    """Connessione PSN associata alla richiesta corrente.

    Chiave diversa da quella del prodotto (`psn_db` invece di `db`): le due
    connessioni convivono nella stessa richiesta senza sapere l'una dell'altra.
    """
    if "psn_db" not in g:
        g.psn_db = motore().connect()
    return g.psn_db


def chiudi(_errore=None) -> None:
    connessione = g.pop("psn_db", None)
    if connessione is not None:
        connessione.close()


def azzera_motore() -> None:
    """Dimentica il motore. Serve ai test, che cambiano archivio fra una prova e l'altra."""
    motore_attuale = current_app.extensions.pop("snap_psn_engine", None)
    if motore_attuale is not None:
        motore_attuale.dispose()


# --------------------------------------------------------------------------- #
# Accesso ai dati: le stesse firme del prodotto, su questo archivio
# --------------------------------------------------------------------------- #
# Si riusano `Riga`, `_con_segnaposto` e `_legati` del prodotto: sono l'adattamento
# dei segnaposto `?` allo stile di SQLAlchemy, e riscriverli qui vorrebbe dire
# mantenere due volte la stessa conversione. E' l'unica cosa che questo modulo prende
# dal prodotto, e non e' uno stato condiviso: sono funzioni pure.
def query(sql: str, params: tuple | list = (), one: bool = False):
    risultato = get_db().execute(text(_con_segnaposto(sql)), _legati(params))
    righe = [Riga(r._mapping, tuple(r)) for r in risultato.all()]
    if one:
        return righe[0] if righe else None
    return righe


def execute(sql: str, params: tuple | list = ()) -> int:
    """Esegue una scrittura. Restituisce l'id inserito quando la INSERT lo produce."""
    testo = _con_segnaposto(sql)
    frase = sql.lstrip()[:6].upper()
    connessione = get_db()
    if frase == "INSERT" and "RETURNING" not in sql.upper():
        testo = testo.rstrip().rstrip(";") + " RETURNING id"
        try:
            risultato = connessione.execute(text(testo), _legati(params))
            riga = risultato.first()
            return int(riga[0]) if riga else 0
        except Exception:
            # Una tabella senza `id` non puo' restituirlo: si riesegue senza.
            connessione.rollback()
            connessione.execute(text(_con_segnaposto(sql)), _legati(params))
            return 0
    connessione.execute(text(testo), _legati(params))
    return 0


def commit() -> None:
    get_db().commit()


def rollback() -> None:
    get_db().rollback()
