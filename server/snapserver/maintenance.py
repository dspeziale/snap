"""
snap server - Manutenzione dell'archivio: dimensione, conservazione, copia, ripristino.

Perche' queste tre cose stanno insieme
--------------------------------------
Sono la stessa domanda posta in tre momenti: quanto occupa cio' che conservo, per
quanto tempo devo conservarlo, e come lo riporto in vita se lo perdo. Tenerle
separate porta al caso classico: una politica di conservazione dichiarata che nessuno
applica, e una copia di sicurezza che nessuno ha mai provato a ripristinare.

Conservazione
-------------
La durata non e' unica per tutti i dati. I campioni di raggiungibilita' sono migliaia
al giorno e valgono giorni; il registro delle azioni vale anni, perche' e' cio' che si
mostra a un auditor. Ogni genere di dato ha percio' la propria durata, con un valore
predefinito motivato, e `0` significa "non scade".

Copia e ripristino
------------------
La copia usa l'API di backup di SQLite e non la copia del file: un file copiato mentre
il server scrive puo' essere incoerente, e un archivio incoerente e' peggio di nessun
archivio. Il ripristino, per lo stesso motivo, non sostituisce il file: riversa il
contenuto della copia DENTRO l'archivio in esercizio, in una transazione, cosi' le
connessioni aperte vedono i dati nuovi senza restare appese a un file cancellato.

Prima di ogni ripristino viene fatta una copia dello stato corrente: un ripristino
sbagliato non deve essere l'ultima operazione possibile.

Riservatezza: una copia dell'archivio contiene i dati di TUTTI i tenant, gli indirizzi
di rete e le credenziali di servizio conservate nelle impostazioni. Il file va trattato
come l'archivio stesso; l'operazione e' riservata all'amministratore di sistema ed e'
tracciata.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import current_app

from .audit import log_event
from .db import execute, get_db, motore, query, scalar, utc_now, utc_now_str, utc_str

# Estensione dei file di copia. Non si comprime: SQLite comprime male e una copia che
# richiede un passaggio in piu' per essere ispezionata viene ispezionata meno spesso.
BACKUP_SUFFIX = ".sqlite3"
BACKUP_PREFIX = "snap-"
# Quante copie tenere quando si chiede la rotazione. Serve un limite: la cartella
# delle copie cresce quanto l'archivio, moltiplicato per il numero di copie.
DEFAULT_KEEP = 10
# Tabelle che devono esistere in una copia perche' sia riconosciuta come archivio snap.
TABELLE_ATTESE = ("tenants", "users", "probes", "nodes", "system_settings")


class MaintenanceError(RuntimeError):
    """Errore di manutenzione. Il messaggio e' destinato all'operatore."""


# --------------------------------------------------------------------------- #
# Conservazione dei dati
# --------------------------------------------------------------------------- #
# (chiave, tabella, colonna temporale, etichetta, giorni predefiniti, motivazione)
RETENTION_TYPES = [
    ("monitor_samples", "monitor_samples", "checked_at",
     "Campioni di raggiungibilita'", 90,
     "Migliaia al giorno: sono la materia delle tendenze brevi, non della storia."),
    ("check_results", "check_results", "executed_at",
     "Esiti dei controlli", 365,
     "Un anno permette il confronto con lo stesso periodo dell'anno precedente."),
    ("check_metrics", "check_metrics", "measured_at",
     "Misure ricavate dagli esiti", 365,
     "Seguono gli esiti da cui sono ricavate: conservarle piu' a lungo sarebbe"
     " conservare numeri senza il contesto che li spiega."),
    ("node_changes", "node_changes", "created_at",
     "Variazioni dell'inventario", 365,
     "Sono la storia della rete: un anno copre il ciclo degli interventi."),
    ("scan_runs", "scan_runs", "created_at",
     "Passate di scansione", 180,
     "Servono a spiegare la qualita' della raccolta recente."),
    ("ingest_batches", "ingest_batches", "received_at",
     "Conferimenti delle sonde", 90,
     "Diagnostica del canale: oltre tre mesi non se ne fa nulla e occupano molto."),
    ("audit_events", "audit_events", "created_at",
     "Registro delle azioni", 730,
     "E' la prova che si mostra a un auditor: due anni per NIS2 e per il GDPR."),
    ("notifications", "notifications", "created_at",
     "Coda delle notifiche", 365,
     "Prova di cio' che e' stato comunicato e a chi."),
    ("rule_matches", "rule_matches", "created_at",
     "Eventi che hanno soddisfatto una regola", 365,
     "Storia delle notifiche automatiche, utile a capire una regola troppo larga."),
    ("probe_nonces", "probe_nonces", "seen_at",
     "Contrassegni antiripetizione", 7,
     "Servono solo a rifiutare una richiesta ripetuta: oltre la finestra sono inerti."),
    ("report_runs", "report_runs", "created_at",
     "Report prodotti", 0,
     "Non scadono: un report sopravvive ai dati che riassume, ed e' la memoria che"
     " resta quando gli esiti sono stati eliminati."),
]


def retention_key(chiave: str) -> str:
    return "retention_%s_days" % chiave


def _setting(key: str, default: str = "") -> str:
    riga = query("SELECT value FROM system_settings WHERE key = ?", (key,), one=True)
    if riga is None or riga["value"] is None:
        return default
    return str(riga["value"])


def _save_setting(key: str, value: str) -> None:
    execute("INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value,"
            " updated_at = excluded.updated_at", (key, value, utc_now_str()))


def retention_plan() -> list:
    """Politica di conservazione in vigore, con quanto e' scaduto adesso."""
    piano = []
    for chiave, tabella, colonna, etichetta, predefinito, motivo in RETENTION_TYPES:
        grezzo = _setting(retention_key(chiave), str(predefinito))
        giorni = int(grezzo) if str(grezzo).strip().lstrip("-").isdigit() else predefinito
        giorni = max(0, giorni)
        righe = scalar("SELECT COUNT(*) FROM %s" % tabella, (), default=0)
        scaduti = 0
        piu_vecchio = None
        if righe:
            piu_vecchio = scalar("SELECT MIN(%s) FROM %s" % (colonna, tabella), (),
                                 default=None)
            if giorni:
                limite = utc_str(utc_now() - timedelta(days=giorni))
                scaduti = scalar("SELECT COUNT(*) FROM %s WHERE %s < ?"
                                 % (tabella, colonna), (limite,), default=0)
        piano.append({
            "chiave": chiave, "tabella": tabella, "colonna": colonna,
            "etichetta": etichetta, "giorni": giorni, "predefinito": predefinito,
            "motivo": motivo, "righe": int(righe or 0), "scaduti": int(scaduti or 0),
            "piu_vecchio": piu_vecchio,
            "perenne": giorni == 0,
        })
    return piano


def save_retention(valori: dict) -> list:
    """Salva le durate indicate. Restituisce l'elenco di cio' che e' cambiato."""
    cambiati = []
    consentite = {c for c, *_ in RETENTION_TYPES}
    for chiave, valore in (valori or {}).items():
        if chiave not in consentite:
            continue
        testo = str(valore).strip()
        if not testo.isdigit():
            raise MaintenanceError("La durata di '%s' deve essere un numero di giorni"
                                   " (0 = non scade)." % chiave)
        giorni = int(testo)
        if giorni > 3650:
            raise MaintenanceError("La durata di '%s' non puo' superare 3650 giorni;"
                                   " per non far scadere i dati si indica 0." % chiave)
        if _setting(retention_key(chiave), "") != testo:
            _save_setting(retention_key(chiave), testo)
            cambiati.append("%s=%s" % (chiave, giorni))
    if cambiati:
        log_event("maintenance.retention",
                  "Conservazione aggiornata: %s" % ", ".join(cambiati),
                  severity="warning", entity="settings")
    return cambiati


def purge(dry_run: bool = True) -> dict:
    """Applica la politica di conservazione. Con `dry_run` conta senza cancellare.

    La prova a vuoto e' il modo di rispondere alla domanda "quanto libero?" prima di
    un'operazione che non si annulla.
    """
    esito = {"simulazione": bool(dry_run), "voci": [], "righe": 0}
    for voce in retention_plan():
        if voce["perenne"] or not voce["scaduti"]:
            continue
        limite = utc_str(utc_now() - timedelta(days=voce["giorni"]))
        if not dry_run:
            execute("DELETE FROM %s WHERE %s < ?" % (voce["tabella"], voce["colonna"]),
                    (limite,))
        esito["voci"].append({"tabella": voce["tabella"], "righe": voce["scaduti"],
                              "limite": limite, "giorni": voce["giorni"]})
        esito["righe"] += voce["scaduti"]

    if not dry_run and esito["righe"]:
        log_event("maintenance.purge",
                  "Conservazione applicata: %d righe eliminate (%s)"
                  % (esito["righe"], ", ".join("%s:%d" % (v["tabella"], v["righe"])
                                               for v in esito["voci"])),
                  severity="warning", entity="database")
    return esito


# --------------------------------------------------------------------------- #
# Dimensione dell'archivio
# --------------------------------------------------------------------------- #
def database_target() -> str:
    """Dove sta l'archivio, in forma mostrabile.

    Non e' piu' un percorso di file: la stringa di connessione contiene la password,
    quindi si mostra solo host, porta e nome del database.
    """
    dsn = current_app.config.get("DATABASE_URL") or ""
    return dsn.rsplit("@", 1)[-1] or "(non indicato)"


def database_size() -> dict:
    """Dimensione dell'archivio e occupazione per tabella.

    Su PostgreSQL i numeri sono migliori di quelli che si potevano dare su SQLite:
    l'occupazione per tabella e' un dato di catalogo (`pg_total_relation_size`,
    indici compresi) e non dipende da un modulo opzionale.

    Restano due voci che qui NON hanno un equivalente e valgono zero, dichiarato:
    il registro di scrittura anticipata (WAL) e la memoria condivisa sono
    dell'intero servizio, non di un singolo database, e attribuirne una parte a
    questo archivio sarebbe un numero inventato.
    """
    dimensione = int(scalar("SELECT pg_database_size(current_database())",
                            (), default=0) or 0)
    pagina = int(scalar("SELECT current_setting('block_size')::int", (), default=0) or 0)

    tabelle = []
    for riga in query(
            "SELECT c.relname AS tabella,"
            "       pg_total_relation_size(c.oid) AS byte,"
            "       COALESCE(s.n_live_tup, 0)     AS righe,"
            "       COALESCE(s.n_dead_tup, 0)     AS morte"
            "  FROM pg_class c"
            "  JOIN pg_namespace n ON n.oid = c.relnamespace"
            "  LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid"
            " WHERE c.relkind = 'r' AND n.nspname = current_schema()"
            " ORDER BY pg_total_relation_size(c.oid) DESC"):
        tabelle.append({"tabella": riga["tabella"], "righe": int(riga["righe"] or 0),
                        "byte": int(riga["byte"] or 0),
                        "morte": int(riga["morte"] or 0)})

    # Righe morte: versioni superate che attendono la pulizia. E' l'equivalente
    # onesto delle "pagine libere" di SQLite -- lo spazio che una compattazione
    # restituirebbe -- ma si conta in righe, non in byte, e si dichiara come tale.
    morte = sum(v["morte"] for v in tabelle)
    return {
        "percorso": database_target(),
        "file_byte": dimensione,
        "wal_byte": 0,
        "shm_byte": 0,
        "pagina_byte": pagina,
        "pagine": (dimensione // pagina) if pagina else 0,
        "pagine_libere": 0,
        "riutilizzabile_byte": 0,
        "righe_morte": morte,
        "tabelle": tabelle,
        "dettaglio_byte": True,
        "righe_totali": sum(v["righe"] for v in tabelle),
    }


def compact() -> dict:
    """Restituisce lo spazio delle righe non piu' necessarie.

    Un'operazione a se' e non un effetto dell'eliminazione: su un archivio grande
    dura. Deve essere una scelta di chi la fa.

    `VACUUM` non puo' girare dentro una transazione: serve una connessione in
    autocommit, non quella della richiesta. `ANALYZE` insieme aggiorna le statistiche
    del pianificatore, che dopo una grande eliminazione sono superate -- ed e' quello
    che rende lente le interrogazioni proprio dopo una pulizia.
    """
    prima = database_size()
    with motore().connect().execution_options(isolation_level="AUTOCOMMIT") as pulizia:
        pulizia.exec_driver_sql("VACUUM (ANALYZE)")
    dopo = database_size()
    log_event("maintenance.compact",
              "Archivio compattato: da %d a %d byte"
              % (prima["file_byte"], dopo["file_byte"]),
              severity="info", entity="database")
    return {"prima": prima["file_byte"], "dopo": dopo["file_byte"],
            "liberati": max(0, prima["file_byte"] - dopo["file_byte"])}


# --------------------------------------------------------------------------- #
# Copie di sicurezza
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# Copie e ripristino: non ancora portati su PostgreSQL
# --------------------------------------------------------------------------- #
# Queste operazioni usavano l'API di backup di SQLite -- un archivio in un file, che
# si copia e si riversa. Su PostgreSQL la copia si fa con `pg_dump` e il ripristino
# con `pg_restore`, ed e' un lavoro a se': va eseguito dove `pg_dump` esiste (non
# nell'immagine dell'applicazione), con la versione giusta del client, e il file
# prodotto non e' piu' un archivio ispezionabile con le stesse verifiche.
#
# Finche' non e' portato, queste funzioni SI FERMANO con un messaggio che dice cosa
# usare. La scelta e' deliberata: una copia che sembra riuscita e non e' ripristinabile
# e' peggio di nessuna copia, ed e' il modo classico di scoprire il problema il giorno
# in cui serve. Nel frattempo la copia si fa con lo script gia' pronto:
#
#     docker/server/backup-postgres.sh
def _non_ancora_portato(operazione: str):
    raise MaintenanceError(
        "%s non e' ancora disponibile con PostgreSQL. Nel frattempo la copia"
        " dell'archivio si esegue con lo script docker/server/backup-postgres.sh"
        " (pg_dump), che scrive nella cartella delle copie del servizio."
        % operazione)


def backup_dir() -> Path:
    """Cartella delle copie. Non si ricava piu' dal percorso dell'archivio (che su
    PostgreSQL non esiste): si usa quella configurata e, in mancanza,
    `server/data/backups` accanto al codice."""
    configurata = current_app.config.get("BACKUP_DIR")
    cartella = (Path(configurata) if configurata
                else Path(current_app.root_path).parent / "data" / "backups")
    cartella.mkdir(parents=True, exist_ok=True)
    return cartella


def _percorso_copia(momento: datetime = None) -> Path:
    """Percorso di una copia nuova, garantito libero.

    Il nome ha risoluzione al secondo, e due copie nello stesso secondo -- il caso del
    ripristino, che ne crea una subito prima di leggere la sorgente -- avrebbero lo
    stesso nome: la seconda sovrascriverebbe la prima, e si ripristinerebbe lo stato
    corrente credendo di tornare indietro. Il contatore chiude la finestra.
    """
    momento = momento or datetime.now(timezone.utc)
    base = "%s%s" % (BACKUP_PREFIX, momento.strftime("%Y%m%d-%H%M%S"))
    cartella = backup_dir()
    candidato = cartella / (base + BACKUP_SUFFIX)
    contatore = 1
    while candidato.exists():
        candidato = cartella / ("%s-%d%s" % (base, contatore, BACKUP_SUFFIX))
        contatore += 1
    return candidato


def backup_now(nota: str = "", keep: int = None) -> dict:
    """Copia coerente dell'intero archivio, tutti i tenant compresi."""
    _non_ancora_portato("La copia dell'archivio dalla console")
    destinazione = _percorso_copia()
    sorgente = get_db()
    sorgente.commit()
    try:
        copia = sqlite3.connect(str(destinazione))
        try:
            with copia:
                sorgente.backup(copia)
        finally:
            copia.close()
    except sqlite3.Error as errore:
        # Un file parziale sarebbe indistinguibile da una copia valida.
        destinazione.unlink(missing_ok=True)
        raise MaintenanceError("Copia non riuscita: %s" % errore) from errore

    dimensione = destinazione.stat().st_size
    integro = verify_backup(destinazione)
    if not integro["valida"]:
        destinazione.unlink(missing_ok=True)
        raise MaintenanceError("La copia prodotta non ha superato la verifica: %s"
                               % integro["motivo"])

    rimosse = rotate_backups(keep if keep is not None else DEFAULT_KEEP)
    log_event("maintenance.backup",
              "Copia dell'archivio creata: %s (%d byte)%s%s"
              % (destinazione.name, dimensione,
                 " - %s" % nota if nota else "",
                 " - %d copie piu' vecchie rimosse" % len(rimosse) if rimosse else ""),
              severity="warning", entity="database")
    return {"nome": destinazione.name, "percorso": str(destinazione),
            "byte": dimensione, "rimosse": rimosse, "verifica": integro}


def list_backups() -> list:
    voci = []
    for file in sorted(backup_dir().glob("%s*%s" % (BACKUP_PREFIX, BACKUP_SUFFIX)),
                       reverse=True):
        stato = file.stat()
        voci.append({
            "nome": file.name,
            "byte": stato.st_size,
            "creata": datetime.fromtimestamp(stato.st_mtime, timezone.utc)
                              .strftime("%Y-%m-%d %H:%M:%S"),
        })
    return voci


def backup_file(nome: str) -> Path:
    """File di copia con il nome indicato. Rifiuta qualunque percorso.

    Il nome arriva da una richiesta: accettarlo come percorso significherebbe
    consentire la lettura di qualunque file del server.
    """
    pulito = Path(str(nome or "")).name
    if not pulito.startswith(BACKUP_PREFIX) or not pulito.endswith(BACKUP_SUFFIX):
        raise MaintenanceError("Nome di copia non riconosciuto.")
    percorso = backup_dir() / pulito
    if not percorso.is_file():
        raise MaintenanceError("Copia non trovata: %s" % pulito)
    return percorso


def delete_backup(nome: str) -> str:
    percorso = backup_file(nome)
    percorso.unlink()
    log_event("maintenance.backup.deleted", "Copia eliminata: %s" % percorso.name,
              severity="warning", entity="database")
    return percorso.name


def rotate_backups(keep: int = DEFAULT_KEEP) -> list:
    """Tiene le `keep` copie piu' recenti. Restituisce i nomi rimossi."""
    if keep <= 0:
        return []
    copie = list_backups()
    rimosse = []
    for voce in copie[keep:]:
        (backup_dir() / voce["nome"]).unlink(missing_ok=True)
        rimosse.append(voce["nome"])
    return rimosse


def verify_backup(percorso) -> dict:
    """Verifica che un file sia un archivio snap coerente.

    Tre controlli: si apre, supera il controllo di integrita', contiene le tabelle del
    prodotto. Un ripristino da un file qualunque distruggerebbe l'archivio in
    esercizio.
    """
    _non_ancora_portato("La verifica di una copia")
    file = Path(percorso)
    if not file.is_file():
        return {"valida": False, "motivo": "file non trovato"}
    try:
        connessione = sqlite3.connect("file:%s?mode=ro" % file.as_posix(), uri=True)
    except sqlite3.Error as errore:
        return {"valida": False, "motivo": "non apribile: %s" % errore}
    try:
        esito = connessione.execute("PRAGMA integrity_check").fetchone()
        if not esito or esito[0] != "ok":
            return {"valida": False,
                    "motivo": "controllo di integrita' non superato: %s"
                              % (esito[0] if esito else "senza esito")}
        presenti = {r[0] for r in connessione.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'")}
        mancanti = [t for t in TABELLE_ATTESE if t not in presenti]
        if mancanti:
            return {"valida": False,
                    "motivo": "non e' un archivio snap: mancano %s"
                              % ", ".join(mancanti)}
        tenant = connessione.execute("SELECT COUNT(*) FROM tenants").fetchone()[0]
        utenti = connessione.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        nodi = connessione.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
    except sqlite3.Error as errore:
        return {"valida": False, "motivo": "lettura non riuscita: %s" % errore}
    finally:
        connessione.close()
    return {"valida": True, "motivo": "", "tenant": tenant, "utenti": utenti,
            "nodi": nodi, "byte": file.stat().st_size}


def restore_from(percorso, attore: str = "") -> dict:
    """Riversa una copia nell'archivio in esercizio, dopo averne salvato lo stato.

    Non sostituisce il file: usa l'API di backup nella direzione opposta, dentro una
    transazione. Le connessioni aperte -- le richieste in corso, i thread di servizio --
    continuano a vedere un archivio valido.
    """
    _non_ancora_portato("Il ripristino da una copia")
    candidato = Path(percorso)
    verifica = verify_backup(candidato)
    if not verifica["valida"]:
        raise MaintenanceError("Copia non ripristinabile: %s" % verifica["motivo"])

    prima = backup_now(nota="stato precedente al ripristino di %s" % candidato.name)

    destinazione = get_db()
    destinazione.commit()
    try:
        origine = sqlite3.connect("file:%s?mode=ro" % candidato.as_posix(), uri=True)
        try:
            with destinazione:
                origine.backup(destinazione)
        finally:
            origine.close()
    except sqlite3.Error as errore:
        raise MaintenanceError(
            "Ripristino non riuscito: %s. Lo stato precedente e' nella copia %s."
            % (errore, prima["nome"])) from errore

    log_event("maintenance.restore",
              "Archivio ripristinato dalla copia %s (%s tenant, %s utenti, %s nodi);"
              " stato precedente salvato in %s"
              % (candidato.name, verifica["tenant"], verifica["utenti"],
                 verifica["nodi"], prima["nome"]),
              severity="critical", entity="database")
    return {"da": candidato.name, "copia_precedente": prima["nome"],
            "verifica": verifica}


def store_uploaded(file_storage) -> Path:
    """Salva un file caricato nella cartella delle copie, per poterlo verificare.

    Non si ripristina da un file temporaneo: se il ripristino va male, il file da cui
    si e' partiti deve essere ancora la'.
    """
    nome = Path(getattr(file_storage, "filename", "") or "").name
    if not nome:
        raise MaintenanceError("Nessun file indicato.")
    if not nome.endswith((".sqlite3", ".sqlite", ".db")):
        raise MaintenanceError("Il file deve essere un archivio SQLite"
                               " (.sqlite3, .sqlite, .db).")
    destinazione = _percorso_copia()
    destinazione = destinazione.with_name(destinazione.name.replace(
        BACKUP_PREFIX, BACKUP_PREFIX + "caricata-", 1))
    file_storage.save(str(destinazione))
    return destinazione


def disk_free() -> dict:
    """Spazio libero sul volume delle COPIE.

    Prima si misurava il volume dell'archivio, che era un file accanto alle copie.
    Ora l'archivio sta su PostgreSQL, magari su un'altra macchina: il volume che
    conta, per sapere se una copia ci sta, e' quello dove la copia viene scritta.
    """
    uso = shutil.disk_usage(str(backup_dir()))
    return {"totale": uso.total, "usato": uso.used, "libero": uso.free}
