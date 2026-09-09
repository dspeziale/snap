# -----------------------------------------------------------------
# store.py — archivio degli eventi SIEM: database dedicato, scritture a lotti
# Autore: Daniele Speziale
# Data creazione: 2026-09-02
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Dove vivono gli eventi dei log.

Gli eventi stanno in un file SQLite SEPARATO dal database della console
(`snap_siem.sqlite3`, accanto a quello principale): un flusso di migliaia di
righe al minuto non deve contendere il database a chi sta usando le pagine, e la
retention si applica con un DELETE su un solo file senza toccare il resto.

Le scritture avvengono A LOTTI (executemany dentro una transazione): e' cio' che
porta SQLite nell'ordine delle decine di migliaia di inserimenti al secondo, piu'
che sufficienti per il syslog di una rete di qualche migliaio di nodi. Ogni
operazione apre la propria connessione breve in WAL: il modulo viene usato sia
dalle richieste web sia dai thread di rilevazione e ascolto, e una connessione
condivisa tra thread e' esattamente il difetto che non si riesce piu' a trovare.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from contextlib import contextmanager

from flask import current_app

from ..db import Riga, days_ago_str, esegui, esegui_molti, motore

# Colonne accettate per un evento normalizzato: tutto il resto finisce in
# extra_json. Una allowlist, cosi' un campo inatteso non diventa una colonna.
_CAMPI = ("tenant_id", "source_id", "received_at", "event_time", "host", "app",
          "severity", "facility", "event_kind", "src_ip", "dst_ip", "src_port",
          "dst_port", "username", "action", "outcome", "message", "extra_json")

# Lo SCHEMA degli eventi non sta piu' qui: e' nello schema principale
# (server/snapserver/schema.sql), creato da `init_db()` come tutte le altre tabelle.
#
# Perche' e' cambiato: gli eventi stavano in un ARCHIVIO SEPARATO perche' su SQLite un
# flusso di migliaia di righe al minuto contendeva le pagine alle interrogazioni della
# console. Su PostgreSQL quella ragione non esiste -- i lettori non bloccano gli
# scrittori -- e un archivio separato costava una configurazione, una connessione e una
# cancellazione manuale in piu' (gli eventi non seguivano il tenant per vincolo: vedi
# `delete_tenant_events`). Ora sono nello stesso database e nella stessa transazione.


@contextmanager
def apri(path=None):
    """Connessione agli eventi, per la durata di un'operazione.

    Il parametro `path` sopravvive alla firma per non toccare i chiamanti, ma non ha
    piu' significato: l'archivio e' uno solo. Passarlo non fa nulla.

    Come il `with` di prima, la transazione si CHIUDE all'uscita: si conferma se il
    blocco e' andato a termine, si annulla se e' stata sollevata un'eccezione. Era il
    comportamento su cui contavano le funzioni di scrittura di questo modulo.
    """
    connessione = motore().connect()
    try:
        yield connessione
        connessione.commit()
    except Exception:
        connessione.rollback()
        raise
    finally:
        connessione.close()


def insert_events(righe: list[dict], path: Path | None = None) -> int:
    """Scrive un lotto di eventi normalizzati. Restituisce quanti ne ha scritti.

    Una sola transazione per lotto: e' la differenza tra decine e decine di
    migliaia di inserimenti al secondo.
    """
    if not righe:
        return 0
    valori = []
    for riga in righe:
        valori.append(tuple(riga.get(campo) for campo in _CAMPI))
    sql = ("INSERT INTO siem_events (%s) VALUES (%s)"
           % (", ".join(_CAMPI), ", ".join("?" * len(_CAMPI))))
    with apri(path) as connection:
        # Un solo invio per il lotto intero: e' la differenza fra decine e decine di
        # migliaia di inserimenti al secondo, e vale su PostgreSQL come valeva prima.
        esegui_molti(connection, sql, valori)
    return len(valori)


def _filtri_eventi(tenant_id: int, kind: str = "", host: str = "", src_ip: str = "",
                   text: str = "", severity: str = "", username: str = "",
                   since: str = "") -> tuple[list, list]:
    """Costruisce la clausola WHERE condivisa fra la ricerca e la cancellazione.

    Perche' condivisa: il pulsante "cancella" deve togliere ESATTAMENTE gli eventi
    che i filtri mostrano, non un insieme diverso. Un solo punto di verita' per i
    filtri evita che ricerca e cancellazione divergano nel tempo.
    """
    where = ["tenant_id = ?"]
    params: list = [int(tenant_id)]
    if kind:
        where.append("event_kind = ?")
        params.append(kind)
    if host:
        where.append("host = ?")
        params.append(host)
    if src_ip:
        where.append("src_ip = ?")
        params.append(src_ip)
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if username:
        where.append("username = ?")
        params.append(username)
    if text:
        where.append("(message LIKE ? OR username LIKE ? OR app LIKE ?)")
        params.extend(["%%%s%%" % text] * 3)
    if since:
        where.append("received_at >= ?")
        params.append(since)
    return where, params


def search(tenant_id: int, kind: str = "", host: str = "", src_ip: str = "",
           text: str = "", severity: str = "", username: str = "", since: str = "",
           limit: int = 1000, path: Path | None = None) -> list[dict]:
    """Gli eventi piu' recenti che rispondono ai filtri, dal piu' nuovo."""
    where, params = _filtri_eventi(tenant_id, kind, host, src_ip, text,
                                   severity, username, since)
    with apri(path) as connection:
        righe = esegui(connection,
            "SELECT * FROM siem_events WHERE " + " AND ".join(where)
            + " ORDER BY received_at DESC, id DESC LIMIT ?",
            params + [int(limit)]).mappings().all()
    return [dict(r) for r in righe]


def delete_events(tenant_id: int, kind: str = "", host: str = "", src_ip: str = "",
                  text: str = "", severity: str = "", username: str = "",
                  since: str = "", path: Path | None = None) -> int:
    """Cancella gli eventi che rispondono ai filtri (gli stessi della ricerca).

    Senza filtri cancella tutti gli eventi del tenant: e' l'operazione di svuotamento
    dell'archivio. I log contengono utenze e indirizzi: poterli cancellare a mano,
    oltre alla retention automatica, e' un requisito di minimizzazione (GDPR art. 5).
    """
    where, params = _filtri_eventi(tenant_id, kind, host, src_ip, text,
                                   severity, username, since)
    with apri(path) as connection:
        cursore = esegui(connection,
            "DELETE FROM siem_events WHERE " + " AND ".join(where), params)
    return cursore.rowcount


def summary(tenant_id: int, path: Path | None = None) -> dict:
    """I numeri del quadro: totale, ultime 24 ore, generi piu' frequenti, host
    visti di recente."""
    from ..db import hours_ago_str

    da_ieri = hours_ago_str(24)
    with apri(path) as connection:
        totale = esegui(connection,
            "SELECT COUNT(*) FROM siem_events WHERE tenant_id = ?",
            (tenant_id,)).scalar()
        recenti = esegui(connection,
            "SELECT COUNT(*) FROM siem_events WHERE tenant_id = ?"
            " AND received_at >= ?", (tenant_id, da_ieri)).scalar()
        generi = esegui(connection,
            "SELECT event_kind, COUNT(*) AS n FROM siem_events"
            " WHERE tenant_id = ? AND received_at >= ?"
            " GROUP BY event_kind ORDER BY n DESC LIMIT 8",
            (tenant_id, da_ieri)).mappings().all()
        host = esegui(connection,
            "SELECT host, COUNT(*) AS n, MAX(received_at) AS ultimo"
            " FROM siem_events WHERE tenant_id = ? AND received_at >= ?"
            " AND COALESCE(host, '') <> '' GROUP BY host ORDER BY n DESC LIMIT 10",
            (tenant_id, da_ieri)).mappings().all()
    return {
        "totale": int(totale),
        "ultime_24h": int(recenti),
        "generi": [dict(r) for r in generi],
        "host": [dict(r) for r in host],
    }


def unknown_hosts(tenant_id: int, conosciuti: set, since_hours: int = 72,
                  path: Path | None = None) -> list[dict]:
    """Gli host che mandano log ma non corrispondono a nessuna sorgente
    dichiarata: sono i candidati all'onboarding, non rumore da nascondere."""
    from ..db import hours_ago_str

    with apri(path) as connection:
        righe = esegui(connection,
            "SELECT host, COUNT(*) AS n, MAX(received_at) AS ultimo,"
            " MAX(COALESCE(app, '')) AS app"
            " FROM siem_events WHERE tenant_id = ? AND received_at >= ?"
            " AND source_id IS NULL AND COALESCE(host, '') <> ''"
            " GROUP BY host ORDER BY n DESC LIMIT 50",
            (tenant_id, hours_ago_str(since_hours))).mappings().all()
    return [dict(r) for r in righe if r["host"] not in conosciuti]


# Gravita' dalla piu' alla meno grave: serve a "gravita' minima" (>= significa
# "almeno grave quanto", cioe' indice minore-o-uguale).
_ORDINE_GRAVITA = ("critical", "high", "medium", "low", "info")


def window_groups(tenant_id: int, event_kind: str, group_by: str,
                  window_seconds: int, threshold: int, min_severity: str = "",
                  path: Path | None = None) -> list[dict]:
    """I gruppi che superano una soglia nella finestra: il cuore della rilevazione.

    `group_by` e' vincolato alle colonne previste (allowlist): non arriva mai
    dall'esterno senza passare dal vocabolario delle regole. `min_severity`, se
    indicato, conta solo gli eventi almeno cosi' gravi: e' cio' che permette a una
    regola di aprirsi su un singolo evento critico senza reagire a quelli minori.
    """
    if group_by not in ("src_ip", "username", "host"):
        raise ValueError("raggruppamento non previsto: %r" % group_by)
    from datetime import timedelta

    from ..db import utc_now, utc_str

    inizio = utc_str(utc_now() - timedelta(seconds=int(window_seconds)))
    condizioni = ["tenant_id = ?", "event_kind = ?", "received_at >= ?",
                  "COALESCE(%s, '') <> ''" % group_by]
    params: list = [tenant_id, event_kind, inizio]
    if min_severity and min_severity in _ORDINE_GRAVITA:
        ammesse = _ORDINE_GRAVITA[:_ORDINE_GRAVITA.index(min_severity) + 1]
        condizioni.append("severity IN (%s)" % ", ".join("?" * len(ammesse)))
        params.extend(ammesse)
    # group_by e' gia' vincolato all'allowlist qui sopra: l'interpolazione e' sicura.
    sql = (
        "SELECT {gb} AS gruppo, COUNT(*) AS n, MIN(received_at) AS primo,"
        " MAX(received_at) AS ultimo, MAX(COALESCE(host, '')) AS host,"
        " MAX(COALESCE(src_ip, '')) AS src_ip,"
        " MAX(COALESCE(username, '')) AS username,"
        " MAX(message) AS esempio"
        " FROM siem_events WHERE " + " AND ".join(condizioni)
        + " GROUP BY {gb} HAVING COUNT(*) >= ?").format(gb=group_by)
    with apri(path) as connection:
        righe = esegui(connection,
            sql, params + [int(threshold)]).mappings().all()
    return [dict(r) for r in righe]


def delete_tenant_events(tenant_id: int, path: Path | None = None) -> int:
    """Cancella tutti gli eventi di un tenant dall'archivio dedicato.

    Le tabelle di configurazione del SIEM stanno nel database della console e
    seguono il tenant per vincolo di chiave esterna (ON DELETE CASCADE); gli EVENTI
    stanno in un file separato, che nessuna chiave esterna puo' raggiungere. Vanno
    quindi cancellati esplicitamente quando il tenant e' eliminato: un tenant che se
    ne va non deve lasciare i propri log (GDPR).
    """
    with apri(path) as connection:
        cursore = esegui(connection,
            "DELETE FROM siem_events WHERE tenant_id = ?",
                                     (int(tenant_id),))
    return cursore.rowcount


def purge(retention_days: int, path: Path | None = None) -> int:
    """Cancella gli eventi oltre la retention. I log contengono utenze e
    indirizzi: tenerli per sempre non e' prudenza, e' una violazione (GDPR art. 5)."""
    if retention_days <= 0:
        return 0
    soglia = days_ago_str(int(retention_days))
    with apri(path) as connection:
        cursore = esegui(connection,
            "DELETE FROM siem_events WHERE received_at < ?", (soglia,))
    return cursore.rowcount


def link_source(tenant_id: int, source_id: int, match_host: str, match_ip: str,
                path: Path | None = None) -> int:
    """Attribuisce alla sorgente gli eventi gia' ricevuti che le corrispondono.

    Serve all'onboarding a posteriori: gli host comparsi PRIMA della
    dichiarazione della sorgente non restano orfani.
    """
    condizioni = []
    params: list = []
    if match_host:
        condizioni.append("host = ?")
        params.append(match_host)
    if match_ip:
        condizioni.append("src_ip = ?")
        params.append(match_ip)
    if not condizioni:
        return 0
    with apri(path) as connection:
        cursore = esegui(connection,
            "UPDATE siem_events SET source_id = ? WHERE tenant_id = ?"
            " AND source_id IS NULL AND (" + " OR ".join(condizioni) + ")",
            [int(source_id), int(tenant_id)] + params)
    return cursore.rowcount


def eventi_di_esempio(tenant_id: int, gruppo: str, event_kind: str, group_by: str,
                      limite: int = 5, path: Path | None = None) -> list[str]:
    """Qualche riga grezza a corredo di un allarme: l'evidenza si legge, non si
    ricostruisce."""
    if group_by not in ("src_ip", "username", "host"):
        return []
    with apri(path) as connection:
        righe = esegui(connection,
            "SELECT message FROM siem_events WHERE tenant_id = ? AND event_kind = ?"
            " AND %s = ? ORDER BY received_at DESC LIMIT ?" % group_by,
            (tenant_id, event_kind, gruppo, int(limite))).mappings().all()
    return [r["message"] for r in righe]


def normalizza_extra(extra: dict | None) -> str | None:
    """L'eccedenza non prevista dalle colonne, come JSON compatto."""
    if not extra:
        return None
    try:
        return json.dumps(extra, ensure_ascii=False, separators=(",", ":"))[:4000]
    except (TypeError, ValueError):
        return None
