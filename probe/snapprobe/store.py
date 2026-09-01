"""
snap probe - Archivio locale della sonda (SQLite).

Contiene tre insiemi di dati:
  * settings   configurazione e materiale crittografico ottenuto in registrazione;
  * spool      coda dei record raccolti in autonomia, in attesa di conferimento;
  * events     diario locale delle operazioni (utile in assenza di connettivita');
  * sync_log   esito dei conferimenti verso il server.

La coda e' l'elemento che consente il funzionamento autonomo: la sonda raccoglie
anche a server spento e si svuota soltanto dopo l'acknowledgement del server.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

UTC_FORMAT = "%Y-%m-%d %H:%M:%S"

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS spool (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT    NOT NULL,
    payload_json TEXT    NOT NULL,
    created_at   TEXT    NOT NULL,
    locked_batch TEXT
);
CREATE INDEX IF NOT EXISTS ix_spool_kind ON spool(kind, id);

CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    level      TEXT    NOT NULL DEFAULT 'info',
    message    TEXT    NOT NULL,
    created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_events_created ON events(created_at);

-- Stato delle fasi di scansione: pilota le cadenze e sopravvive ai riavvii.
CREATE TABLE IF NOT EXISTS scan_state (
    target      TEXT NOT NULL,
    stage       TEXT NOT NULL,
    last_run_at TEXT,
    last_status TEXT,
    last_detail TEXT,
    runs        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (target, stage)
);

-- Stato locale dei controlli periodici: quando ciascuno e' stato eseguito e con
-- quale esito. Le definizioni arrivano dal server a ogni contatto, lo stato resta
-- qui, cosi' che la cadenza valga anche dopo un riavvio.
CREATE TABLE IF NOT EXISTS check_state (
    check_id    INTEGER PRIMARY KEY,
    last_run_at TEXT,
    last_status TEXT,
    last_detail TEXT,
    runs        INTEGER NOT NULL DEFAULT 0
);

-- Nodi noti alla sonda. Lo stato 'candidate' e' il nodo vivo che non porta
-- ancora prove sostanziali: non viene conferito fino alla conferma.
CREATE TABLE IF NOT EXISTS local_nodes (
    ip            TEXT PRIMARY KEY,
    state         TEXT NOT NULL DEFAULT 'candidate',
    ttl           INTEGER,
    mac           TEXT,
    hostname      TEXT,
    open_ports    INTEGER NOT NULL DEFAULT 0,
    has_os        INTEGER NOT NULL DEFAULT 0,
    attempts      INTEGER NOT NULL DEFAULT 0,
    -- Prove accumulate e fasi svolte: il nodo viene conferito solo quando il
    -- profilo e' completo, non a ogni frammento raccolto.
    profile_json  TEXT    NOT NULL DEFAULT '{}',
    stages_done   TEXT    NOT NULL DEFAULT '',
    conferred_at  TEXT,
    -- Istante dell'ultima fusione di prove nel profilo: confrontato con
    -- conferred_at dice se c'e' qualcosa di nuovo da conferire.
    last_merge_at TEXT,
    -- Istante in cui il nodo e' stato scartato perche' privo di informazioni:
    -- per il periodo di attesa non viene ne' riproposto ne' riesaminato.
    discarded_at  TEXT,
    first_seen_at TEXT,
    last_seen_at  TEXT,
    -- Ultima verifica di raggiungibilita': governa la rotazione del monitoraggio,
    -- che parte dai nodi non verificati da piu' tempo.
    monitored_at  TEXT
);
CREATE INDEX IF NOT EXISTS ix_local_nodes_state ON local_nodes(state);

-- Prenotazioni dei bersagli di scansione. La chiave e' unica: l'acquisizione
-- e' atomica e nessun bersaglio puo' essere preso da due thread insieme.
CREATE TABLE IF NOT EXISTS scan_claims (
    key        TEXT PRIMARY KEY,
    owner      TEXT NOT NULL,
    stage      TEXT,
    claimed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_claims_owner ON scan_claims(owner);

CREATE TABLE IF NOT EXISTS sync_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_uid  TEXT    NOT NULL,
    records    INTEGER NOT NULL DEFAULT 0,
    status     TEXT    NOT NULL,
    detail     TEXT,
    created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_sync_created ON sync_log(created_at);
"""


def utc_now_str() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime(UTC_FORMAT)


def days_ago_str(days: int) -> str:
    moment = datetime.now(timezone.utc) - timedelta(days=days)
    return moment.strftime(UTC_FORMAT)


class ProbeStore:
    """Archivio locale con accesso serializzato (agente e interfaccia concorrono)."""

    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as connection:
            connection.executescript(SCHEMA)
            self._migrate(connection)

    # Colonne introdotte dopo la prima installazione: CREATE TABLE IF NOT EXISTS
    # non tocca una tabella esistente, quindi vanno aggiunte esplicitamente.
    MIGRATIONS = (
        ("local_nodes", "profile_json", "TEXT NOT NULL DEFAULT '{}'"),
        ("local_nodes", "stages_done", "TEXT NOT NULL DEFAULT ''"),
        ("local_nodes", "conferred_at", "TEXT"),
        ("local_nodes", "last_merge_at", "TEXT"),
        ("local_nodes", "discarded_at", "TEXT"),
        # Ultima verifica di raggiungibilita': governa la rotazione del
        # monitoraggio. Senza, ogni passata prendeva sempre i primi nodi e gli
        # altri non venivano mai riverificati.
        ("local_nodes", "monitored_at", "TEXT"),
    )

    def _migrate(self, connection) -> None:
        for tabella, colonna, tipo in self.MIGRATIONS:
            presente = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
                (tabella,),
            ).fetchone()
            if presente is None:
                continue
            colonne = {riga["name"] for riga in
                       connection.execute("PRAGMA table_info(%s)" % tabella).fetchall()}
            if colonna not in colonne:
                connection.execute("ALTER TABLE %s ADD COLUMN %s %s"
                                   % (tabella, colonna, tipo))

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    # -- configurazione ------------------------------------------------------
    def get_setting(self, key: str, default=None):
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value,"
                " updated_at = excluded.updated_at",
                (key, str(value), utc_now_str()),
            )

    def set_settings(self, values: dict) -> None:
        now = utc_now_str()
        with self._lock, self._connect() as connection:
            for key, value in values.items():
                connection.execute(
                    "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)"
                    " ON CONFLICT(key) DO UPDATE SET value = excluded.value,"
                    " updated_at = excluded.updated_at",
                    (key, "" if value is None else str(value), now),
                )

    def delete_setting(self, key: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM settings WHERE key = ?", (key,))

    def all_settings(self) -> dict:
        with self._lock, self._connect() as connection:
            rows = connection.execute("SELECT key, value FROM settings").fetchall()
        return {row["key"]: row["value"] for row in rows}

    def get_json(self, key: str, default=None):
        raw = self.get_setting(key)
        if not raw:
            return default
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            self.log("warning", "Impostazione '%s' non e' JSON valido: ignorata" % key)
            return default

    def set_json(self, key: str, value) -> None:
        self.set_setting(key, json.dumps(value, separators=(",", ":"), default=str))

    # -- coda dati -----------------------------------------------------------
    def enqueue(self, kind: str, payload: dict) -> int:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO spool (kind, payload_json, created_at) VALUES (?, ?, ?)",
                (kind, json.dumps(payload, separators=(",", ":"), default=str), utc_now_str()),
            )
            return int(cursor.lastrowid or 0)

    def queue_size(self) -> int:
        with self._lock, self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS n FROM spool").fetchone()
        return int(row["n"]) if row else 0

    def queue_breakdown(self) -> dict:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT kind, COUNT(*) AS n FROM spool GROUP BY kind"
            ).fetchall()
        return {row["kind"]: int(row["n"]) for row in rows}

    def oldest_queued_at(self) -> str | None:
        with self._lock, self._connect() as connection:
            row = connection.execute("SELECT MIN(created_at) AS oldest FROM spool").fetchone()
        return row["oldest"] if row and row["oldest"] else None

    def reserve_batch(self, batch_uid: str, limit: int = 400) -> list[dict]:
        """Marca i record piu' vecchi come appartenenti a un lotto e li restituisce.

        La prenotazione rende il conferimento ripetibile: se l'invio non riceve
        conferma, gli stessi record restano prenotati e vengono ritrasmessi con lo
        stesso batch_uid, che il server riconosce come duplicato.
        """
        with self._lock, self._connect() as connection:
            pending = connection.execute(
                "SELECT COUNT(*) AS n FROM spool WHERE locked_batch IS NOT NULL"
            ).fetchone()
            if pending and int(pending["n"]):
                rows = connection.execute(
                    "SELECT id, kind, payload_json, locked_batch FROM spool"
                    " WHERE locked_batch IS NOT NULL ORDER BY id"
                ).fetchall()
            else:
                connection.execute(
                    "UPDATE spool SET locked_batch = ? WHERE id IN"
                    " (SELECT id FROM spool WHERE locked_batch IS NULL ORDER BY id LIMIT ?)",
                    (batch_uid, limit),
                )
                rows = connection.execute(
                    "SELECT id, kind, payload_json, locked_batch FROM spool"
                    " WHERE locked_batch = ? ORDER BY id",
                    (batch_uid,),
                ).fetchall()

        records = []
        for row in rows:
            try:
                payload = json.loads(row["payload_json"])
            except json.JSONDecodeError:
                self.log("warning", "Record %d illeggibile: scartato" % row["id"])
                self.discard(int(row["id"]))
                continue
            records.append(
                {
                    "id": int(row["id"]),
                    "kind": row["kind"],
                    "payload": payload,
                    "batch_uid": row["locked_batch"],
                }
            )
        return records

    def commit_batch(self, batch_uid: str) -> int:
        """Elimina i record conferiti: e' lo svuotamento della coda locale."""
        with self._lock, self._connect() as connection:
            cursor = connection.execute("DELETE FROM spool WHERE locked_batch = ?", (batch_uid,))
            return int(cursor.rowcount or 0)

    def release_batch(self, batch_uid: str) -> None:
        """Sblocca un lotto non conferito (es. errore non ritentabile)."""
        with self._lock, self._connect() as connection:
            connection.execute(
                "UPDATE spool SET locked_batch = NULL WHERE locked_batch = ?", (batch_uid,)
            )

    def discard(self, record_id: int) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM spool WHERE id = ?", (record_id,))

    def clear_queue(self) -> int:
        with self._lock, self._connect() as connection:
            cursor = connection.execute("DELETE FROM spool")
            return int(cursor.rowcount or 0)

    def queue_preview(self, limit: int = 50) -> list[sqlite3.Row]:
        with self._lock, self._connect() as connection:
            return connection.execute(
                "SELECT id, kind, created_at, locked_batch, length(payload_json) AS size"
                " FROM spool ORDER BY id LIMIT ?",
                (limit,),
            ).fetchall()

    # -- diario e storico ----------------------------------------------------
    def log(self, level: str, message: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO events (level, message, created_at) VALUES (?, ?, ?)",
                (level, message[:1000], utc_now_str()),
            )
            # Il diario locale resta contenuto: si conservano gli ultimi 500 eventi.
            connection.execute(
                "DELETE FROM events WHERE id NOT IN"
                " (SELECT id FROM events ORDER BY id DESC LIMIT 500)"
            )

    def recent_events(self, limit: int = 100) -> list[sqlite3.Row]:
        with self._lock, self._connect() as connection:
            return connection.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()

    def record_sync(self, batch_uid: str, records: int, status: str, detail: str = "") -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO sync_log (batch_uid, records, status, detail, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (batch_uid, records, status, detail[:500], utc_now_str()),
            )
            connection.execute(
                "DELETE FROM sync_log WHERE id NOT IN"
                " (SELECT id FROM sync_log ORDER BY id DESC LIMIT 200)"
            )

    def recent_syncs(self, limit: int = 30) -> list[sqlite3.Row]:
        with self._lock, self._connect() as connection:
            return connection.execute(
                "SELECT * FROM sync_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()

    # -- stato di registrazione ---------------------------------------------
    # -- stato delle fasi di scansione --------------------------------------
    def scan_state(self, target: str, stage: str) -> dict | None:
        with self._lock, self._connect() as connection:
            riga = connection.execute(
                "SELECT * FROM scan_state WHERE target = ? AND stage = ?",
                (target, stage),
            ).fetchone()
        return dict(riga) if riga is not None else None

    def all_scan_states(self) -> list[dict]:
        with self._lock, self._connect() as connection:
            righe = connection.execute(
                "SELECT * FROM scan_state ORDER BY last_run_at DESC"
            ).fetchall()
        return [dict(r) for r in righe]

    def record_scan(self, target: str, stage: str, status: str, detail: str = "") -> None:
        """Annota l'esecuzione di una fase. Chiamata prima del conferimento, cosi'
        che un arresto della sonda non faccia ripetere il lavoro gia' svolto."""
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO scan_state (target, stage, last_run_at, last_status,"
                " last_detail, runs) VALUES (?, ?, ?, ?, ?, 1)"
                " ON CONFLICT(target, stage) DO UPDATE SET last_run_at = excluded.last_run_at,"
                " last_status = excluded.last_status, last_detail = excluded.last_detail,"
                " runs = runs + 1",
                (target, stage, utc_now_str(), status, detail[:400]),
            )

    # -- controlli periodici -------------------------------------------------
    def check_state(self, check_id: int) -> dict | None:
        with self._lock, self._connect() as connection:
            riga = connection.execute(
                "SELECT * FROM check_state WHERE check_id = ?", (int(check_id),)
            ).fetchone()
        return dict(riga) if riga is not None else None

    def check_last_run(self, check_id: int) -> str | None:
        stato = self.check_state(check_id)
        return stato.get("last_run_at") if stato else None

    def record_check_run(self, check_id: int, status: str, detail: str = "") -> None:
        """Annota l'esecuzione di un controllo, prima del conferimento.

        Come per le fasi di scansione: se la sonda si arresta fra l'esecuzione e il
        conferimento, il controllo non viene ripetuto subito -- l'esito e' in coda.
        """
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO check_state (check_id, last_run_at, last_status,"
                " last_detail, runs) VALUES (?, ?, ?, ?, 1)"
                " ON CONFLICT(check_id) DO UPDATE SET last_run_at = excluded.last_run_at,"
                " last_status = excluded.last_status, last_detail = excluded.last_detail,"
                " runs = runs + 1",
                (int(check_id), utc_now_str(), status, (detail or "")[:400]),
            )

    def forget_check_state(self, check_id: int = None) -> None:
        """Azzera lo stato dei controlli: la prossima passata riparte subito."""
        with self._lock, self._connect() as connection:
            if check_id is None:
                connection.execute("DELETE FROM check_state")
            else:
                connection.execute("DELETE FROM check_state WHERE check_id = ?",
                                   (int(check_id),))

    def forget_scan_state(self, target: str = None) -> None:
        """Azzera lo stato delle fasi: la prossima passata riparte da capo."""
        with self._lock, self._connect() as connection:
            if target is None:
                connection.execute("DELETE FROM scan_state")
            else:
                connection.execute("DELETE FROM scan_state WHERE target = ?", (target,))

    # -- nodi noti alla sonda -----------------------------------------------
    def upsert_local_node(self, ip: str, **campi) -> None:
        adesso = utc_now_str()
        ammessi = ("state", "ttl", "mac", "hostname", "open_ports", "has_os", "attempts",
                   "profile_json", "stages_done", "conferred_at", "last_merge_at",
                   "discarded_at")
        valori = {k: v for k, v in campi.items() if k in ammessi and v is not None}
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO local_nodes (ip, first_seen_at, last_seen_at)"
                " VALUES (?, ?, ?) ON CONFLICT(ip) DO UPDATE SET last_seen_at = excluded.last_seen_at",
                (ip, adesso, adesso),
            )
            if valori:
                assegnazioni = ", ".join("%s = ?" % k for k in valori)
                connection.execute(
                    "UPDATE local_nodes SET %s WHERE ip = ?" % assegnazioni,
                    tuple(valori.values()) + (ip,),
                )

    def local_node(self, ip: str) -> dict | None:
        """Legge un solo nodo: e' la lettura usata dai thread di scansione."""
        with self._lock, self._connect() as connection:
            riga = connection.execute(
                "SELECT * FROM local_nodes WHERE ip = ?", (ip,)
            ).fetchone()
        return dict(riga) if riga is not None else None

    # -- prenotazione dei bersagli ------------------------------------------
    def claim_keys(self, keys: list, owner: str, stage: str = None) -> list:
        """Prenota le chiavi indicate e restituisce quelle effettivamente ottenute.

        L'inserimento con chiave unica e' l'operazione atomica su cui si regge
        l'esclusione fra thread: se la riga esiste gia', la chiave e' di qualcun
        altro e non viene restituita.
        """
        adesso = utc_now_str()
        ottenute = []
        with self._lock, self._connect() as connection:
            for chiave in keys:
                cursore = connection.execute(
                    "INSERT OR IGNORE INTO scan_claims (key, owner, stage, claimed_at)"
                    " VALUES (?, ?, ?, ?)",
                    (chiave, owner, stage, adesso),
                )
                if cursore.rowcount:
                    ottenute.append(chiave)
        return ottenute

    def release_keys(self, keys: list, owner: str = None) -> int:
        """Rilascia le prenotazioni. Con `owner` rilascia solo le proprie."""
        if not keys:
            return 0
        segnaposto = ",".join("?" for _ in keys)
        with self._lock, self._connect() as connection:
            if owner is None:
                cursore = connection.execute(
                    "DELETE FROM scan_claims WHERE key IN (%s)" % segnaposto, tuple(keys))
            else:
                cursore = connection.execute(
                    "DELETE FROM scan_claims WHERE owner = ? AND key IN (%s)" % segnaposto,
                    (owner,) + tuple(keys))
            return cursore.rowcount

    def purge_stale_claims(self, max_age_seconds: int = 1800) -> int:
        """Libera le prenotazioni troppo vecchie.

        Serve al caso in cui un thread termini senza rilasciare: senza la scadenza
        il bersaglio resterebbe bloccato per sempre.
        """
        with self._lock, self._connect() as connection:
            cursore = connection.execute(
                "DELETE FROM scan_claims"
                " WHERE claimed_at < datetime('now', ?)",
                ("-%d seconds" % int(max_age_seconds),),
            )
            return cursore.rowcount

    def active_claims(self) -> list[dict]:
        with self._lock, self._connect() as connection:
            righe = connection.execute(
                "SELECT * FROM scan_claims ORDER BY claimed_at"
            ).fetchall()
        return [dict(r) for r in righe]

    def local_nodes(self, state: str = None) -> list[dict]:
        with self._lock, self._connect() as connection:
            if state is None:
                righe = connection.execute("SELECT * FROM local_nodes ORDER BY ip").fetchall()
            else:
                righe = connection.execute(
                    "SELECT * FROM local_nodes WHERE state = ? ORDER BY ip", (state,)
                ).fetchall()
        return [dict(r) for r in righe]

    def mark_monitored(self, ips) -> None:
        """Annota l'istante dell'ultima verifica di raggiungibilita'.

        Governa la rotazione: la passata successiva parte dai nodi non verificati da
        piu' tempo, cosi' l'intero inventario viene coperto a giri.
        """
        elenco = [ip for ip in (ips or ()) if ip]
        if not elenco:
            return
        adesso = utc_now_str()
        with self._lock, self._connect() as connection:
            connection.executemany(
                "UPDATE local_nodes SET monitored_at = ? WHERE ip = ?",
                [(adesso, ip) for ip in elenco])

    def local_node_count(self, state: str = None) -> int:
        with self._lock, self._connect() as connection:
            if state is None:
                return connection.execute("SELECT COUNT(*) FROM local_nodes").fetchone()[0]
            return connection.execute(
                "SELECT COUNT(*) FROM local_nodes WHERE state = ?", (state,)
            ).fetchone()[0]

    def drop_local_node(self, ip: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM local_nodes WHERE ip = ?", (ip,))

    def clear_local_nodes(self) -> int:
        with self._lock, self._connect() as connection:
            cursore = connection.execute("DELETE FROM local_nodes")
            connection.execute("DELETE FROM scan_state")
            connection.execute("DELETE FROM scan_claims")
            return cursore.rowcount

    # Tabelle dei dati raccolti, nell'ordine in cui si svuotano. L'elenco e'
    # esplicito e non ricavato da sqlite_master: una tabella nuova deve comparire
    # qui per scelta, non trovarsi cancellata per effetto collaterale.
    DATA_TABLES = ("scan_claims", "scan_state", "local_nodes", "check_state",
                   "spool", "sync_log", "events")

    def reset(self, keep_enrollment: bool = False) -> dict:
        """Azzera l'archivio. Restituisce quante righe sono state rimosse.

        `keep_enrollment` conserva il solo materiale di registrazione: al contatto
        successivo il server riconsegna perimetro, cadenze e controlli, e la sonda
        riparte dalla scoperta. Senza, l'archivio torna allo stato successivo
        all'installazione e la sonda va registrata di nuovo.

        Il conteggio viene fatto PRIMA della cancellazione: dopo non c'e' piu' nulla
        da contare, e un azzeramento che non dichiara cosa ha rimosso non e'
        verificabile.
        """
        conservate = dict(self.snapshot_enrollment()) if keep_enrollment else {}
        rimosse = {}
        with self._lock, self._connect() as connection:
            for tabella in self.DATA_TABLES:
                quante = connection.execute(
                    "SELECT COUNT(*) AS n FROM %s" % tabella).fetchone()["n"]
                connection.execute("DELETE FROM %s" % tabella)
                rimosse[tabella] = int(quante)
            rimosse["settings"] = connection.execute(
                "SELECT COUNT(*) AS n FROM settings").fetchone()["n"]
            connection.execute("DELETE FROM settings")

        if conservate:
            self.set_settings({k: v for k, v in conservate.items() if v})
            rimosse["settings"] -= len([v for v in conservate.values() if v])

        # Lo spazio non si libera da se': dopo aver cancellato migliaia di righe il
        # file resterebbe grande quanto prima, e un archivio "azzerato" di dieci
        # megabyte e' una contraddizione visibile.
        self.compact()

        # Il diario e' stato cancellato: la prima riga del nuovo diario dice cosa e'
        # accaduto, altrimenti l'archivio azzerato non ha memoria di esserlo.
        self.log("warning",
                 "Archivio azzerato (%s): rimosse %d righe di dati e %d impostazioni"
                 % ("registrazione conservata" if keep_enrollment
                    else "registrazione compresa",
                    sum(v for k, v in rimosse.items() if k != "settings"),
                    max(0, rimosse["settings"])))
        return rimosse

    def footprint(self) -> int:
        """Spazio occupato in totale dall'archivio, byte.

        Il conto comprende il giornale di scrittura (`-wal`) e il file di memoria
        condivisa (`-shm`): in modalita' WAL i dati appena scritti stanno nel
        giornale, e misurare il solo file principale porta a conclusioni sbagliate --
        misurato: 237 kB nel file principale contro 4,1 MB nel giornale.
        """
        totale = 0
        for suffisso in ("", "-wal", "-shm"):
            parte = self.path.with_name(self.path.name + suffisso)
            if parte.exists():
                totale += parte.stat().st_size
        return totale

    def compact(self) -> int:
        """Restituisce lo spazio liberato al sistema. Ritorna i byte recuperati.

        Tre passaggi, in questo ordine: il giornale viene riversato nel file
        principale, il file viene ricostruito senza le pagine libere, e il giornale
        viene troncato di nuovo -- perche' la ricostruzione stessa passa dal
        giornale, e senza l'ultimo passaggio resterebbe grande.

        VACUUM non puo' girare dentro una transazione: la connessione viene aperta
        fuori dal gestore di contesto usato altrove.
        """
        prima = self.footprint()
        with self._lock:
            connection = sqlite3.connect(str(self.path), timeout=30)
            try:
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                connection.execute("VACUUM")
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                connection.close()
        return max(0, prima - self.footprint())

    def is_enrolled(self) -> bool:
        return bool(self.get_setting("probe_uid") and self.get_setting("session_key"))

    ENROLLMENT_KEYS = (
        "probe_uid",
        "session_key",
        "api_key",
        "server_public_key",
        "probe_private_key",
        "probe_public_key",
        "enrolled_at",
        "probe_code",
        "probe_name",
        "tenant_code",
        "tenant_name",
        "tenant_timezone",
        "server_url",
    )

    def snapshot_enrollment(self) -> dict:
        """Copia del materiale di registrazione, per un eventuale ripristino."""
        return {key: self.get_setting(key) for key in self.ENROLLMENT_KEYS}

    def restore_enrollment(self, snapshot: dict) -> None:
        """Ripristina una registrazione precedente non andata a buon fine.

        Serve quando la sostituzione della registrazione fallisce: senza
        ripristino la sonda resterebbe priva di credenziali valide pur avendone
        una funzionante prima del tentativo.
        """
        self.set_settings({key: value for key, value in snapshot.items() if value})
        self.log("info", "Registrazione precedente ripristinata dopo un tentativo non riuscito")

    def reset_enrollment(self) -> None:
        """Dimentica il legame con il server mantenendo la coda dei dati."""
        for key in (
            "probe_uid",
            "session_key",
            "api_key",
            "server_public_key",
            "probe_private_key",
            "probe_public_key",
            "enrolled_at",
            "tenant_code",
            "tenant_name",
            "tenant_timezone",
        ):
            self.delete_setting(key)
        self.log("warning", "Registrazione azzerata: la sonda torna in stato non registrato")
