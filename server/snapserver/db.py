"""
snap server - Accesso al database SQLite e helper temporali.

Il modulo espone una connessione per richiesta (pattern Flask `g`), la
inizializzazione dello schema e le funzioni di utilita' per il trattamento
uniforme dei timestamp: tutto viene scritto in UTC e convertito nel fuso orario
del tenant solo in fase di presentazione (requisito di normalizzazione oraria).

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import click
from flask import current_app, g

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
def get_db() -> sqlite3.Connection:
    """Connessione SQLite associata alla richiesta corrente."""
    if "db" not in g:
        path = Path(current_app.config["DATABASE"])
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(path), detect_types=sqlite3.PARSE_DECLTYPES)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        _registra_funzioni(connection)
        g.db = connection
    return g.db


def _valore_inet(indirizzo):
    """Valore numerico di un indirizzo IP, per ordinarlo come si legge.

    Ordinare gli indirizzi come TESTO mette 10.2.9.1 dopo 10.2.100.1 e prima di
    10.2.99.1: un elenco cosi' non e' sfogliabile, e su un documento consegnato al
    cliente l'errore si nota subito.

    Il nome e' quello di PostgreSQL di proposito: il giorno in cui il prodotto gira
    su Postgres, `ORDER BY inet(ip)` continua a valere -- la' e' il tipo `inet` a
    ordinare per valore, e la funzione diventa un cast.

    Un indirizzo illeggibile non fa cadere l'interrogazione: torna None e SQLite lo
    ordina per ultimo. Meglio una riga fuori posto che un elenco che non si apre.
    """
    if not indirizzo:
        return None
    try:
        import ipaddress

        return int(ipaddress.ip_address(str(indirizzo).strip()))
    except ValueError:
        return None


def _registra_funzioni(connection) -> None:
    """Funzioni SQL proprie del prodotto, disponibili in ogni interrogazione."""
    # deterministic=True: SQLite puo' usarla negli indici e nelle viste, e il valore
    # di un indirizzo non cambia fra due chiamate.
    connection.create_function("inet", 1, _valore_inet, deterministic=True)


def close_db(_exception: BaseException | None = None) -> None:
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def query(sql: str, params: tuple | list = (), one: bool = False):
    cursor = get_db().execute(sql, tuple(params))
    rows = cursor.fetchall()
    cursor.close()
    if one:
        return rows[0] if rows else None
    return rows


def execute(sql: str, params: tuple | list = ()) -> int:
    """Esegue una scrittura e restituisce l'id dell'ultima riga inserita."""
    connection = get_db()
    cursor = connection.execute(sql, tuple(params))
    connection.commit()
    last_id = cursor.lastrowid
    cursor.close()
    return int(last_id or 0)


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
    ("users", "pref_kpi_hidden", "TEXT NOT NULL DEFAULT ''"),
    # Fatti dichiarati dalle pagine degli apparati (vedi web_facts nella sonda).
    ("node_web", "device_name", "TEXT"),
    ("node_web", "location", "TEXT"),
    ("node_web", "host_name", "TEXT"),
    ("node_web", "serial", "TEXT"),
    ("node_web", "firmware", "TEXT"),
    ("node_web", "contact", "TEXT"),
    ("node_web", "pages_read", "INTEGER NOT NULL DEFAULT 0"),
    ("node_web", "facts_locked", "INTEGER NOT NULL DEFAULT 0"),
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
    ("notifications", "channel", "TEXT NOT NULL DEFAULT 'email'"),
    ("notifications", "body_html", "TEXT"),
    ("notifications", "attachment_path", "TEXT"),
    ("subnets", "zone", "TEXT NOT NULL DEFAULT ''"),
    # Origine di un riscontro di sicurezza (vedi threat._apply_vuln).
    ("ti_findings", "source", "TEXT NOT NULL DEFAULT 'correlation'"),
    # TTL osservato: indizio della famiglia OS (vedi fingerprint).
    ("nodes", "ttl", "INTEGER"),
    # Tipo del dispositivo dichiarato dall'operatore (vedi inventory.declare_type).
    ("nodes", "device_type_source", "TEXT NOT NULL DEFAULT 'auto'"),
    ("nodes", "device_type_by", "TEXT"),
    ("nodes", "device_type_at", "TEXT"),
    ("nodes", "device_type_reason", "TEXT"),
]


# Migrazioni strutturali: SQLite non sa togliere un vincolo, quindi la tabella si
# ricostruisce. Ogni voce dichiara la tabella, il pezzo di DDL da cui si riconosce la
# forma vecchia, e il perche' del cambiamento.
STRUCTURAL_MIGRATIONS = [
    {
        "table": "ti_findings",
        "marker": "REFERENCES ti_technique",
        "why": "il vincolo verso il catalogo ATT&CK impediva di registrare le"
               " esposizioni prima che il catalogo fosse importato, cioe' al primo avvio",
    },
]


def _rebuild_table(connection, tabella: str, schema_sql: str) -> None:
    """Ricostruisce una tabella con la definizione corrente, conservando le righe.

    Le colonne comuni fra vecchia e nuova forma vengono copiate; quelle scomparse si
    perdono per definizione, e quelle nuove restano al valore predefinito.
    """
    import re

    definizione = None
    for pezzo in re.findall(r"CREATE TABLE IF NOT EXISTS\s+%s\s*\((?:[^;])*\);"
                            % re.escape(tabella), schema_sql, re.S):
        definizione = pezzo
        break
    if definizione is None:
        return

    vecchie = {riga["name"] for riga in
               connection.execute("PRAGMA table_info(%s)" % tabella).fetchall()}
    connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute("ALTER TABLE %s RENAME TO %s_vecchia" % (tabella, tabella))
    connection.executescript(definizione)
    nuove = {riga["name"] for riga in
             connection.execute("PRAGMA table_info(%s)" % tabella).fetchall()}
    comuni = [c for c in nuove if c in vecchie]
    if comuni:
        elenco = ", ".join(comuni)
        connection.execute("INSERT INTO %s (%s) SELECT %s FROM %s_vecchia"
                           % (tabella, elenco, elenco, tabella))
    connection.execute("DROP TABLE %s_vecchia" % tabella)
    connection.execute("PRAGMA foreign_keys = ON")


def _apply_structural_migrations(connection, schema_sql: str) -> list[str]:
    """Ricostruisce le tabelle la cui forma e' cambiata oltre l'aggiunta di colonne."""
    applicate = []
    for voce in STRUCTURAL_MIGRATIONS:
        riga = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            (voce["table"],)).fetchone()
        if riga is None or not riga["sql"]:
            continue
        if voce["marker"] not in riga["sql"]:
            continue
        _rebuild_table(connection, voce["table"], schema_sql)
        applicate.append("%s (%s)" % (voce["table"], voce["why"]))
    return applicate


def _apply_migrations(connection) -> list[str]:
    """Aggiunge le colonne mancanti alle tabelle esistenti."""
    applicate = []
    for tabella, colonna, tipo in MIGRATIONS:
        presente = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", (tabella,)
        ).fetchone()
        if presente is None:
            continue  # la tabella verra' creata dallo schema con la colonna inclusa
        colonne = {riga["name"] for riga in
                   connection.execute("PRAGMA table_info(%s)" % tabella).fetchall()}
        if colonna in colonne:
            continue
        connection.execute("ALTER TABLE %s ADD COLUMN %s %s" % (tabella, colonna, tipo))
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

    tenant = [riga[0] for riga in connection.execute("SELECT id FROM tenants").fetchall()]
    if not tenant:
        return 0

    adesso = utc_now_str()
    seminati = 0
    for tenant_id in tenant:
        quante = connection.execute(
            "SELECT COUNT(*) FROM network_zones WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()[0]
        if quante:
            continue
        for ordine, voce in enumerate(SEME, start=1):
            connection.execute(
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


def _fill_cwe_links(connection) -> int:
    """Riempie ti_cve_cwe dalla colonna testuale, una volta sola.

    Il legame fra CVE e classi di debolezza e' nato dopo le CVE: su un archivio gia'
    popolato la tabella resterebbe vuota, e la scheda delle debolezze mostrerebbe
    zero ovunque finche' non si riscarica l'intero catalogo. Il dato c'e' gia' nella
    colonna `cwe_ids`: qui si ricava, senza contattare nessuno.
    """
    esistenti = connection.execute("SELECT COUNT(*) FROM ti_cve_cwe").fetchone()[0]
    if esistenti:
        return 0
    righe = connection.execute(
        "SELECT cve_id, cwe_ids FROM ti_cve WHERE cwe_ids IS NOT NULL AND cwe_ids <> ''"
    ).fetchall()
    legami = [(r[0], debolezza)
              for r in righe
              for debolezza in (r[1] or "").replace(" ", "").split(",")
              if debolezza.startswith("CWE-")]
    if not legami:
        return 0
    connection.executemany(
        "INSERT OR IGNORE INTO ti_cve_cwe (cve_id, cwe_id) VALUES (?, ?)", legami)
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
    connection.executescript(schema)
    aggiunte = _apply_migrations(connection)
    ricostruite = _apply_structural_migrations(connection, schema)
    riempiti = _fill_cwe_links(connection)
    seminate = _semina_zone(connection)
    connection.commit()
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
    click.echo("Schema inizializzato: %s" % current_app.config["DATABASE"])


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
