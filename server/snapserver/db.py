"""
snap server - Accesso al database PostgreSQL e helper temporali.

Il modulo espone una connessione per richiesta (pattern Flask `g`), la
inizializzazione dello schema e le funzioni di utilita' per il trattamento
uniforme dei timestamp: tutto viene scritto in UTC e convertito nel fuso orario
del tenant solo in fase di presentazione (requisito di normalizzazione oraria).

L'accesso passa da SQLAlchemy Core: le interrogazioni restano scritte in SQL, ma
i valori viaggiano SEMPRE come parametri legati e la connessione, il pool e le
migrazioni sono governati da un punto solo. I segnaposto storici `?` vengono
tradotti qui (vedi `_con_segnaposto`), cosi' le centinaia di interrogazioni
esistenti non sono state riscritte una per una -- riscriverle sarebbe stata la
strada piu' breve per introdurre una concatenazione di stringhe al posto di un
parametro.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import click
from flask import current_app, g
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine

UTC_FORMAT = "%Y-%m-%d %H:%M:%S"


# --------------------------------------------------------------------------- #
# Timestamp
# --------------------------------------------------------------------------- #
def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def utc_now_str() -> str:
    return utc_now().strftime(UTC_FORMAT)


def utc_str(moment: datetime) -> str:
    """Normalizza un datetime (naive = UTC) nella rappresentazione di persistenza."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime(UTC_FORMAT)


def parse_utc(value: str | None) -> datetime | None:
    """Converte un valore di database in datetime UTC; None se assente o illeggibile."""
    if not value:
        return None
    text = str(value).strip().replace("T", " ")
    if text.endswith("Z"):
        text = text[:-1]
    text = text.split(".")[0]
    for fmt in (UTC_FORMAT, "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def get_zone(timezone_name: str | None) -> ZoneInfo:
    """Restituisce il fuso del tenant, con ricaduta su UTC se il nome non e' valido."""
    try:
        return ZoneInfo(timezone_name or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def to_tenant_time(value: str | datetime | None, timezone_name: str | None) -> datetime | None:
    """Converte un istante UTC nel fuso orario del tenant."""
    moment = parse_utc(value) if not isinstance(value, datetime) else value
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(get_zone(timezone_name))


def hours_ago_str(hours: int) -> str:
    """Istante UTC di N ore fa, nella forma conservata in banca dati.

    Serve agli andamenti a grana oraria: una soglia in giorni non permette di
    guardare le ultime ventiquattro ore.
    """
    from datetime import timedelta

    return (utc_now() - timedelta(hours=int(hours))).strftime(UTC_FORMAT)


def days_ago_str(days: int) -> str:
    return (utc_now() - timedelta(days=days)).strftime(UTC_FORMAT)


# --------------------------------------------------------------------------- #
# Connessione
# --------------------------------------------------------------------------- #
class Riga(Mapping):
    """Riga di risultato leggibile per NOME e per POSIZIONE.

    Il codice del prodotto legge le righe in tre modi -- `riga["ip"]`, `riga[0]` e
    `dict(riga)` -- perche' era abituato a `sqlite3.Row`. Le righe di SQLAlchemy 2
    espongono i nomi solo attraverso `_mapping`: senza questo involucro sarebbero
    centinaia di punti da riscrivere, e ognuno un'occasione di sbagliare.

    UNA DIFFERENZA DA `sqlite3.Row`, che va conosciuta: qui vale il contratto dei
    Mapping, quindi **scorrere una riga da' i NOMI delle colonne**, non i valori
    (`sqlite3.Row` dava i valori). Per i valori: `riga.values()`. La differenza e'
    silenziosa -- non solleva nulla, restituisce stringhe plausibili -- e ha fatto
    esportare in CSV una riga di intestazioni al posto dei dati.
    """

    __slots__ = ("_valori", "_celle")

    def __init__(self, mappa, celle=None):
        self._valori = dict(mappa)
        # Due colonne di un SELECT possono avere lo STESSO nome: le espressioni senza
        # alias si chiamano tutte allo stesso modo (`coalesce`, `?column?`). In un
        # dizionario si sovrascrivono, e la riga perde celle -- una `COALESCE` per
        # nome host e una per etichetta diventano una sola. La tupla posizionale le
        # conserva tutte, nell'ordine del SELECT, e l'accesso per posizione resta
        # fedele a cio' che si e' chiesto.
        self._celle = (tuple(celle) if celle is not None
                       else tuple(self._valori.values()))

    def __getitem__(self, chiave):
        if isinstance(chiave, int):
            return self._celle[chiave]
        return self._valori[chiave]

    def celle(self) -> tuple:
        """Tutte le celle nell'ordine del SELECT, comprese quelle omonime.

        Serve a chi tratta la riga come una riga di tabella (esportazioni, viste
        tabellari). Per nome si usa `riga["colonna"]`; `values()` segue il contratto
        dei Mapping e quindi puo' averne di meno, se ci sono omonimie.
        """
        return self._celle

    def __iter__(self):
        return iter(self._valori)

    def __len__(self):
        return len(self._valori)

    def keys(self):
        return self._valori.keys()

    def __repr__(self) -> str:
        return "Riga(%r)" % self._valori


def _con_segnaposto(sql: str) -> str:
    """Traduce i segnaposto `?` nella forma con nome usata da SQLAlchemy.

    Il prodotto ha centinaia di interrogazioni scritte con `?` (paramstyle di
    SQLite). Tradurle qui, in un punto solo, evita di riscriverle tutte -- e
    soprattutto evita che qualcuno, riscrivendole, passi dai parametri legati alla
    concatenazione di stringhe: i valori restano SEMPRE parametri.

    I `?` dentro una stringa SQL (fra apici) non si toccano: sono dati, non
    segnaposto.
    """
    pezzi = []
    indice = 0
    in_stringa = False
    for carattere in sql:
        if carattere == "'":
            in_stringa = not in_stringa
            pezzi.append(carattere)
        elif carattere == "?" and not in_stringa:
            pezzi.append(":p%d" % indice)
            indice += 1
        else:
            pezzi.append(carattere)
    return "".join(pezzi)


def _legati(params) -> dict:
    """Parametri posizionali nella forma con nome attesa da `_con_segnaposto`."""
    return {"p%d" % i: v for i, v in enumerate(tuple(params or ()))}


def esegui(connection, sql: str, params: tuple | list = ()):
    """Esegue un'istruzione su una connessione GIA' aperta, con i segnaposto `?`.

    Serve alle funzioni che ricevono la connessione dall'esterno (inizializzazione,
    migrazioni, semina, manutenzione): quelle non passano da `get_db()` e senza
    questo aiuto dovrebbero costruire da sole `text()` e i parametri legati -- cioe'
    ripetere in dieci punti la stessa cosa, con dieci occasioni di sbagliarla.
    """
    return connection.execute(text(_con_segnaposto(sql)), _legati(params))


def righe(connection, sql: str, params: tuple | list = ()) -> list:
    """Come `esegui`, ma restituisce righe leggibili per nome e per posizione."""
    risultato = esegui(connection, sql, params)
    return [Riga(r._mapping, tuple(r)) for r in risultato.all()]


def esegui_molti(connection, sql: str, elenco) -> int:
    """Esegue la stessa istruzione su MOLTE serie di parametri, in un solo invio.

    Serve alle scritture a lotti (gli eventi SIEM): un invio per lotto invece di uno
    per riga e' la differenza fra decine e decine di migliaia di inserimenti al
    secondo. Sostituisce `executemany` mantenendo i segnaposto `?`.
    """
    serie = [_legati(p) for p in elenco]
    if not serie:
        return 0
    connection.execute(text(_con_segnaposto(sql)), serie)
    return len(serie)


def motore() -> Engine:
    """Motore di connessione, uno per processo.

    `pool_pre_ping` verifica la connessione prima di usarla e `pool_recycle` la
    rinnova: il contenitore della base dati puo' riavviarsi, e una connessione tenuta
    aperta per ore diventa inutilizzabile senza dirlo.
    """
    motore_attuale = current_app.extensions.get("snap_engine")
    if motore_attuale is not None:
        return motore_attuale

    dsn = (current_app.config.get("DATABASE_URL") or "").strip()
    if not dsn:
        # Meglio fermarsi subito e dirlo: senza archivio non c'e' niente da servire,
        # e un valore predefinito con credenziali dentro sarebbe un segreto nel codice.
        raise RuntimeError(
            "Archivio non configurato: manca SNAP_SERVER_DATABASE_URL"
            " (postgresql+psycopg://utente:password@host:5432/database)")

    motore_attuale = create_engine(
        dsn,
        pool_pre_ping=True,
        pool_recycle=int(current_app.config.get("DB_POOL_RECYCLE_SEC", 1800)),
        future=True,
    )
    current_app.extensions["snap_engine"] = motore_attuale
    return motore_attuale


def get_db() -> Connection:
    """Connessione associata alla richiesta corrente."""
    if "db" not in g:
        connection = motore().connect()
        # Attesa massima su un lock: e' il sostituto dichiarato del `busy_timeout`
        # che serviva su SQLite. Oltre questo tempo la richiesta riceve un errore
        # invece di restare appesa (vedi la cancellazione di una sonda).
        connection.exec_driver_sql(
            "SET lock_timeout = %d" % int(current_app.config["DB_LOCK_TIMEOUT_MS"]))
        g.db = connection
    return g.db


def close_db(_exception: BaseException | None = None) -> None:
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def _annulla_transazione(connessione) -> None:
    """Riporta la connessione a uno stato usabile dopo un errore.

    In PostgreSQL un'istruzione fallita ANNULLA la transazione: ogni istruzione
    successiva sulla stessa connessione risponde "current transaction is aborted",
    e la richiesta produce una cascata di errori che NASCONDE quello vero -- il
    primo. Poiche' la connessione vive per tutta la richiesta (`g`), senza questo
    annullamento la pagina fallisce su una query che non ha alcun difetto.
    """
    try:
        connessione.rollback()
    except Exception:  # noqa: BLE001 - se anche il rollback fallisce, non c'e' altro
        current_app.logger.exception("Annullamento della transazione non riuscito")


def query(sql: str, params: tuple | list = (), one: bool = False):
    connessione = get_db()
    try:
        risultato = connessione.execute(text(_con_segnaposto(sql)), _legati(params))
        righe = [Riga(r._mapping, tuple(r)) for r in risultato.all()]
    except Exception:
        _annulla_transazione(connessione)
        raise
    if one:
        return righe[0] if righe else None
    return righe


# Tabelle con una colonna `id`: serve a sapere se una INSERT puo' restituirlo.
# Si accerta una volta per processo interrogando il catalogo, non si indovina.
_TABELLE_CON_ID: dict[str, bool] = {}


def _ha_colonna_id(connection, tabella: str) -> bool:
    if tabella not in _TABELLE_CON_ID:
        trovata = connection.execute(text(
            "SELECT 1 FROM information_schema.columns"
            " WHERE table_schema = current_schema()"
            "   AND table_name = :t AND column_name = 'id'"), {"t": tabella}).first()
        _TABELLE_CON_ID[tabella] = trovata is not None
    return _TABELLE_CON_ID[tabella]


_INSERT_IN = re.compile(r"^\s*INSERT\s+INTO\s+\"?(\w+)\"?", re.I)


def execute(sql: str, params: tuple | list = ()) -> int:
    """Esegue una scrittura e restituisce l'id della riga inserita (0 se non c'e').

    PostgreSQL non ha un equivalente di `lastrowid`: l'id lo si chiede alla scrittura
    stessa con RETURNING. Si aggiunge solo a una INSERT su una tabella che ha davvero
    una colonna `id` (accertato sul catalogo): tentarlo alla cieca farebbe fallire
    l'istruzione e, in PostgreSQL, un errore annulla l'intera transazione.
    """
    connection = get_db()
    istruzione = sql
    riferimento = _INSERT_IN.match(sql)
    chiede_id = (riferimento is not None
                 and " RETURNING " not in sql.upper()
                 and _ha_colonna_id(connection, riferimento.group(1)))
    if chiede_id:
        istruzione = sql.rstrip().rstrip(";") + " RETURNING id"

    try:
        risultato = connection.execute(text(_con_segnaposto(istruzione)), _legati(params))
        nuovo_id = 0
        if chiede_id:
            riga = risultato.first()
            nuovo_id = int(riga[0]) if riga else 0
        connection.commit()
    except Exception:
        # Vedi `_annulla_transazione`: senza, il resto della richiesta fallirebbe
        # su istruzioni corrette.
        _annulla_transazione(connection)
        raise
    return nuovo_id


def scalar(sql: str, params: tuple | list = (), default=0):
    row = query(sql, params, one=True)
    if row is None:
        return default
    value = row[0]
    return default if value is None else value


# Colonne introdotte dopo la prima installazione. CREATE TABLE IF NOT EXISTS
# non tocca una tabella che esiste gia': senza queste istruzioni un database
# creato con una versione precedente resterebbe privo delle colonne nuove.
MIGRATIONS = [
    # Provenienza del MAC: "arp" (osservato dalla sonda sul proprio
    # segmento) oppure "snmp:<apparato>" (riferito da un apparato di rete).
    ("nodes", "mac_source", "TEXT"),
    # Dove il nodo e' attaccato: apparato e nome della porta fisica.
    ("nodes", "switch_device", "TEXT"),
    ("nodes", "switch_port", "TEXT"),
    ("ingest_batches", "records_json", "TEXT"),
    ("ingest_batches", "records_truncated", "INTEGER NOT NULL DEFAULT 0"),
    ("scan_runs", "batch_id", "INTEGER"),
    ("node_ports", "is_suspect", "INTEGER NOT NULL DEFAULT 0"),
    ("node_ports", "suspect_reason", "TEXT"),
    ("node_ports", "banner", "TEXT"),
    ("probes", "scan_enabled", "INTEGER NOT NULL DEFAULT 1"),
    ("probes", "scan_effort", "TEXT NOT NULL DEFAULT 'med'"),
    ("probes", "scan_host_timeout", "TEXT"),
    ("probes", "scan_discovery_days", "INTEGER NOT NULL DEFAULT 3"),
    ("probes", "scan_paused", "INTEGER NOT NULL DEFAULT 0"),
    ("probes", "scan_blocked_alerted_at", "TEXT"),
    # Istantanea della console della sonda e istante in cui e' stata composta: la
    # sonda non e' interrogabile (NAT), quindi lo stato arriva col battito.
    ("probes", "console_json", "TEXT"),
    ("probes", "console_at", "TEXT"),
    ("users", "pref_kpi_hidden", "TEXT NOT NULL DEFAULT ''"),
    ("users", "telegram_chat_id", "TEXT"),
    # Fatti dichiarati dalle pagine degli apparati (vedi web_facts nella sonda).
    ("node_web", "device_name", "TEXT"),
    ("node_web", "location", "TEXT"),
    ("node_web", "host_name", "TEXT"),
    ("node_web", "serial", "TEXT"),
    ("node_web", "firmware", "TEXT"),
    ("node_web", "contact", "TEXT"),
    ("node_web", "pages_read", "INTEGER NOT NULL DEFAULT 0"),
    ("node_web", "facts_locked", "INTEGER NOT NULL DEFAULT 0"),
    # Tutte le etichette che l'apparato dichiara di se', anche quelle senza una colonna
    # propria (i telefoni IP Cisco ne dichiarano una decina): il dettaglio del nodo le
    # mostra tutte. Solo il vocabolario riconosciuto, mai il corpo della pagina.
    ("node_web", "facts_json", "TEXT"),
    # Tutti i dati del certificato TLS, anche quelli senza colonna (serie, versione,
    # algoritmo di firma, chiave, impronte, SAN, usi): dove c'e' HTTPS si registra tutto.
    ("node_web", "cert_json", "TEXT"),
    # Impronte di somiglianza fra apparati: l'icona servita dal firmware e l'insieme
    # dei nomi delle intestazioni HTTP. Servono a riconoscere che due nodi sono lo
    # stesso modello quando la pagina non dichiara nulla (vedi _web_twins_evidence).
    ("node_web", "favicon_hash", "TEXT"),
    ("node_web", "favicon_bytes", "INTEGER"),
    ("node_web", "favicon_path", "TEXT"),
    ("node_web", "headers_hash", "TEXT"),
    ("node_web", "headers_names", "TEXT"),
    # Avvisi sui termini di comunicazione ad ACN (vedi acn_watch).
    # Incidenti registrati a mano (vedi acn.registra_incidente).
    ("check_incidents", "origin", "TEXT NOT NULL DEFAULT 'check'"),
    ("check_incidents", "title", "TEXT"),
    ("check_incidents", "subject", "TEXT"),
    ("check_incidents", "created_by", "INTEGER"),
    ("acn_communications", "alerted_at", "TEXT"),
    ("acn_communications", "overdue_alerted_at", "TEXT"),
    ("checks", "escalation_threshold", "INTEGER NOT NULL DEFAULT 6"),
    ("checks", "escalation_email", "TEXT"),
    ("check_incidents", "escalated_at", "TEXT"),
    ("check_incidents", "escalated_to", "TEXT"),
    # Ultimo promemoria "controllo rientrato, incidente ancora aperto": serve a NON
    # rimandare la stessa notifica a ogni giro del controllo (vedi checks.py).
    ("check_incidents", "recovered_notified_at", "TEXT"),
    ("notifications", "channel", "TEXT NOT NULL DEFAULT 'email'"),
    ("notifications", "body_html", "TEXT"),
    ("notifications", "attachment_path", "TEXT"),
    ("subnets", "zone", "TEXT NOT NULL DEFAULT ''"),
    # Rete senza fili: decide se la sonda le dedica la ricognizione breve e frequente
    # delle presenze (vedi presence.py nella sonda).
    ("subnets", "is_wifi", "INTEGER NOT NULL DEFAULT 0"),
    # Origine di un riscontro di sicurezza (vedi threat._apply_vuln).
    ("ti_findings", "source", "TEXT NOT NULL DEFAULT 'correlation'"),
    # TTL osservato: indizio della famiglia OS (vedi fingerprint).
    ("nodes", "ttl", "INTEGER"),
    # Tipo del dispositivo dichiarato dall'operatore (vedi inventory.declare_type).
    ("nodes", "device_type_source", "TEXT NOT NULL DEFAULT 'auto'"),
    ("nodes", "device_type_by", "TEXT"),
    ("nodes", "device_type_at", "TEXT"),
    ("nodes", "device_type_reason", "TEXT"),
    # Gravita' minima perche' un evento conti per una regola SIEM (vedi siem/detect).
    ("siem_rules", "min_severity", "TEXT"),
    # Ogni allarme SIEM e' anche un incidente in Controlli -> Incidenti (vedi
    # siem/incident.py): qui il legame verso quell'incidente.
    ("siem_alerts", "incident_id", "INTEGER"),
]


# Vincoli non piu' previsti dal modello. Su PostgreSQL si TOLGONO: `ALTER TABLE ...
# DROP CONSTRAINT` esiste, e la ricostruzione della tabella -- che serviva su SQLite,
# incapace di rimuovere un vincolo -- non e' piu' necessaria. Era anche la parte piu'
# rischiosa dell'avvio: copiava le righe in una tabella nuova a ogni aggiornamento.
STRUCTURAL_MIGRATIONS = [
    {
        "table": "ti_findings",
        "column": "technique_id",
        "references": "ti_technique",
        "why": "il vincolo verso il catalogo ATT&CK impediva di registrare le"
               " esposizioni prima che il catalogo fosse importato, cioe' al primo avvio",
    },
]


def _apply_structural_migrations(connection, _schema_sql: str = "") -> list[str]:
    """Rimuove i vincoli non piu' previsti dal modello.

    Si cerca il vincolo nel catalogo (`pg_constraint`) invece di riconoscerlo dal
    testo del DDL: il nome che PostgreSQL assegna non e' garantito, la relazione
    fra colonna e tabella referenziata si'.
    """
    applicate = []
    for voce in STRUCTURAL_MIGRATIONS:
        nomi = [riga[0] for riga in connection.execute(text("""
            SELECT c.conname
              FROM pg_constraint c
              JOIN pg_class      t ON t.oid = c.conrelid
              JOIN pg_class      r ON r.oid = c.confrelid
              JOIN pg_attribute  a ON a.attrelid = t.oid AND a.attnum = c.conkey[1]
             WHERE c.contype = 'f'
               AND t.relname = :tabella
               AND r.relname = :riferita
               AND a.attname = :colonna
        """), {"tabella": voce["table"], "riferita": voce["references"],
               "colonna": voce["column"]})]
        for nome in nomi:
            # Il nome viene dal catalogo, non dall'esterno; si cita comunque.
            connection.exec_driver_sql(
                'ALTER TABLE "%s" DROP CONSTRAINT "%s"' % (voce["table"], nome))
            applicate.append("%s.%s -> %s (%s)"
                             % (voce["table"], voce["column"], voce["references"],
                                voce["why"]))
    return applicate


def _apply_migrations(connection) -> list[str]:
    """Aggiunge le colonne mancanti alle tabelle esistenti.

    Il catalogo si interroga con `information_schema`, non piu' con `PRAGMA
    table_info`: e' lo standard e vale su PostgreSQL.
    """
    applicate = []
    for tabella, colonna, tipo in MIGRATIONS:
        presente = connection.execute(text(
            "SELECT 1 FROM information_schema.tables"
            " WHERE table_schema = current_schema() AND table_name = :t"),
            {"t": tabella}).first()
        if presente is None:
            continue  # la tabella verra' creata dallo schema con la colonna inclusa
        colonne = {riga[0] for riga in connection.execute(text(
            "SELECT column_name FROM information_schema.columns"
            " WHERE table_schema = current_schema() AND table_name = :t"),
            {"t": tabella})}
        if colonna in colonne:
            continue
        # Nome di tabella e colonna vengono da questo elenco, non dall'esterno: non
        # sono dati dell'utente. Il tipo idem. `ADD COLUMN IF NOT EXISTS` renderebbe
        # il controllo superfluo, ma il controllo serve a REGISTRARE cosa e' cambiato.
        connection.exec_driver_sql(
            'ALTER TABLE "%s" ADD COLUMN "%s" %s' % (tabella, colonna, tipo))
        applicate.append("%s.%s" % (tabella, colonna))
    return applicate


def _semina_zone(connection) -> int:
    """Copia le zone del prodotto nei tenant che non ne hanno ancora.

    Le zone sono nate come catalogo nel codice; da quando l'operatore le governa sono
    un dato, e un dato va creato. Si fa qui, all'inizializzazione, invece di
    aspettare che qualcuno apra la pagina: un'installazione aggiornata deve trovare
    il proprio contesto gia' dichiarato, non un elenco vuoto.

    Si scrive con la connessione in corso e non con le funzioni di `zone_admin`: qui
    non c'e' ancora un contesto di richiesta, e la migrazione dello schema non deve
    dipendere dal resto dell'applicazione.
    """
    import json as _json

    from .zones import SEME

    tenant = [riga[0] for riga in esegui(connection, "SELECT id FROM tenants")]
    if not tenant:
        return 0

    adesso = utc_now_str()
    seminati = 0
    for tenant_id in tenant:
        quante = esegui(connection,
            "SELECT COUNT(*) FROM network_zones WHERE tenant_id = ?", (tenant_id,)
        ).scalar()
        if quante:
            continue
        for ordine, voce in enumerate(SEME, start=1):
            esegui(connection,
                "INSERT INTO network_zones (tenant_id, key, name, description, icon,"
                " tone, expected_json, violated_json, is_builtin, sort_order,"
                " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
                (tenant_id, voce["chiave"], voce["nome"], voce["descrizione"],
                 voce["icona"], voce["tono"],
                 _json.dumps(voce["attese"], ensure_ascii=False),
                 _json.dumps(voce["violazioni"], ensure_ascii=False),
                 ordine * 10, adesso, adesso))
        seminati += 1
    return seminati


def _semina_regole_siem(connection) -> int:
    """Copia il catalogo delle regole di rilevazione SIEM nei tenant che non ne hanno.

    Come per le zone: un'installazione aggiornata deve trovare le regole gia'
    dichiarate, non un elenco vuoto la prima volta che si apre il SIEM.
    """
    from .siem.seed import semina_regole

    return semina_regole(connection, utc_now_str())


def _fill_cwe_links(connection) -> int:
    """Riempie ti_cve_cwe dalla colonna testuale, una volta sola.

    Il legame fra CVE e classi di debolezza e' nato dopo le CVE: su un archivio gia'
    popolato la tabella resterebbe vuota, e la scheda delle debolezze mostrerebbe
    zero ovunque finche' non si riscarica l'intero catalogo. Il dato c'e' gia' nella
    colonna `cwe_ids`: qui si ricava, senza contattare nessuno.
    """
    esistenti = esegui(connection, "SELECT COUNT(*) FROM ti_cve_cwe").scalar()
    if esistenti:
        return 0
    trovate = esegui(connection,
        "SELECT cve_id, cwe_ids FROM ti_cve WHERE cwe_ids IS NOT NULL AND cwe_ids <> ''"
    ).fetchall()
    legami = [(r[0], debolezza)
              for r in trovate
              for debolezza in (r[1] or "").replace(" ", "").split(",")
              if debolezza.startswith("CWE-")]
    if not legami:
        return 0
    # `INSERT OR IGNORE` e' SQLite: su PostgreSQL si dichiara il conflitto.
    for cve, cwe in legami:
        esegui(connection,
               "INSERT INTO ti_cve_cwe (cve_id, cwe_id) VALUES (?, ?)"
               " ON CONFLICT DO NOTHING", (cve, cwe))
    return len(legami)


def init_db() -> None:
    """Allinea lo schema (idempotente).

    Lo script crea le strutture assenti e rimuove quelle non piu' previste dal
    modello; le migrazioni aggiungono le colonne introdotte successivamente. Un
    database creato con una versione precedente viene adeguato senza interventi
    manuali.
    """
    schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
    connection = get_db()
    # LE COLONNE PRIMA DELLO SCHEMA. L'ordine e' stato invertito per una ragione
    # precisa: lo schema dichiara anche gli INDICI, e un indice su una colonna
    # introdotta da una migrazione non si poteva dichiarare la'. Su un database nuovo
    # funzionava (la tabella nasce completa), su uno esistente no -- `CREATE TABLE IF
    # NOT EXISTS` non tocca la tabella che c'e' gia', quindi la colonna arrivava dopo
    # l'indice che la usa, e l'avvio si fermava con "column ... does not exist".
    #
    # Su un database nuovo le migrazioni non hanno nulla da fare (le tabelle non
    # esistono ancora e vengono saltate), quindi anticiparle non cambia niente; su uno
    # esistente rende dichiarabile nello schema qualunque indice.
    aggiunte = _apply_migrations(connection)
    # Tutto il file in una sola istruzione: contiene un blocco `DO $$ ... $$` con
    # punti e virgola al proprio interno, e spezzarlo su ';' lo romperebbe. Senza
    # parametri, il driver accetta piu' istruzioni in un solo invio.
    connection.exec_driver_sql(schema)
    ricostruite = _apply_structural_migrations(connection, schema)
    riempiti = _fill_cwe_links(connection)
    seminate = _semina_zone(connection)
    regole_siem = _semina_regole_siem(connection)
    connection.commit()
    if regole_siem:
        current_app.logger.info("Regole SIEM del catalogo aggiunte: %d", regole_siem)
    if aggiunte:
        current_app.logger.info("Colonne aggiunte allo schema: %s", ", ".join(aggiunte))
    if ricostruite:
        current_app.logger.info("Tabelle ricostruite: %s", "; ".join(ricostruite))
    if riempiti:
        current_app.logger.info("Legami CVE-CWE ricostruiti: %d", riempiti)
    if seminate:
        current_app.logger.info("Zone di rete iniziali create per %d tenant", seminate)


@click.command("init-db")
def init_db_command() -> None:
    """Inizializza il database del server."""
    init_db()
    # La stringa di connessione contiene la password: si mostra solo il bersaglio.
    dsn = current_app.config.get("DATABASE_URL") or ""
    click.echo("Schema inizializzato su %s" % (dsn.rsplit("@", 1)[-1] or "(non indicato)"))


@click.command("backfill-check-metrics")
def backfill_check_metrics_command() -> None:
    """Ricava le metriche dagli esiti dei controlli che ne sono privi."""
    from .checks import backfill_metrics

    esito = backfill_metrics()
    click.echo("Esiti esaminati: %d, misure ricavate: %d"
               % (esito["results"], esito["metrics"]))


@click.command("seed-db")
def seed_db_command() -> None:
    """Crea i dati iniziali (tenant dimostrativo e amministratore di sistema)."""
    from .seed import seed_initial_data

    summary = seed_initial_data()
    for line in summary:
        click.echo(line)


def init_app(app) -> None:
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
    app.cli.add_command(seed_db_command)
    app.cli.add_command(backfill_check_metrics_command)


def paginate(base_sql: str, count_sql: str, params: tuple | list, page: int, per_page: int = 25) -> dict:
    """Esegue una query paginata restituendo righe e metadati di navigazione."""
    page = max(1, int(page or 1))
    # Il limite superiore accoglie la finestra ampia usata dalle viste con
    # impaginazione lato client, restando un argine ai volumi eccessivi.
    per_page = max(5, min(2000, int(per_page or 25)))
    total = int(scalar(count_sql, params, default=0))
    pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, pages)
    offset = (page - 1) * per_page
    rows = query(base_sql + " LIMIT ? OFFSET ?", list(params) + [per_page, offset])
    return {
        "rows": rows,
        "total": total,
        "page": page,
        "pages": pages,
        "per_page": per_page,
        "has_prev": page > 1,
        "has_next": page < pages,
    }
