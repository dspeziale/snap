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
La copia e' un archivio `pg_dump` in formato personalizzato (`-Fc`): compresso,
selettivo nel ripristino e -- soprattutto -- ripristinabile con `pg_restore`, cioe'
con gli strumenti che chiunque amministri PostgreSQL conosce gia'. Il giorno in cui
serve, una copia che si apre solo con snap e' una copia in meno.

`pg_dump` produce una copia COERENTE: legge in una singola istantanea della base
dati, quindi non importa che il server stia scrivendo nel frattempo.

Il ripristino usa `pg_restore --clean --if-exists`: elimina e ricrea gli oggetti
dentro la base dati in esercizio, senza sostituire file e senza fermare il servizio.
Prima di ogni ripristino viene fatta una copia dello stato corrente.

VERSIONI. `pg_dump` sa leggere un server della propria versione o piu' vecchio, non
piu' nuovo. La compatibilita' si verifica PRIMA di ogni copia e di ogni ripristino, e
se il client e' piu' vecchio del server l'operazione si rifiuta: una copia prodotta
in quella condizione puo' essere incompleta senza dirlo.

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

import os
import re
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

from flask import current_app

from .audit import log_event
from .db import execute, get_db, motore, query, scalar, utc_now, utc_now_str, utc_str

# Estensione dei file di copia. Il formato personalizzato di `pg_dump` e' GIA'
# compresso e si ispeziona senza scompattarlo (`pg_restore --list`): non serve
# aggiungere un passaggio che renderebbe la copia meno esaminata.
BACKUP_SUFFIX = ".dump"
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
    ("presence_sessions", "presence_sessions", "last_seen_at",
     "Presenze sulle reti senza fili", 90,
     "La presenza di un apparato personale e' un dato personale (GDPR art. 5): si"
     " conserva il tempo che serve a leggere un andamento, non per sempre."),
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
    """Rende riutilizzabile lo spazio delle righe non piu' necessarie.

    Un'operazione a se' e non un effetto dell'eliminazione: su un archivio grande
    dura. Deve essere una scelta di chi la fa.

    COSA FA E COSA NON FA, perche' la differenza conta e su SQLite non c'era. Su
    SQLite `VACUUM` riscriveva il file e la dimensione sul disco CALAVA. Su PostgreSQL
    `VACUUM` non restituisce spazio al sistema operativo: marca come riutilizzabili le
    pagine occupate dalle righe morte, cosi' le scritture successive non fanno crescere
    i file. La dimensione dichiarata dal sistema puo' quindi restare identica, e con
    `ANALYZE` puo' perfino CRESCERE di poco (statistiche, mappe di visibilita' e di
    spazio libero): non e' un guasto, e' come funziona.

    Restituire spazio al disco richiederebbe `VACUUM FULL`, che riscrive ogni tabella
    tenendo un lock esclusivo: l'applicazione resterebbe ferma per tutta la durata.
    Da una console di esercizio non si fa, e non si offre un pulsante che lo faccia
    senza dirlo.

    `VACUUM` non puo' girare dentro una transazione: serve una connessione in
    autocommit, non quella della richiesta. `ANALYZE` insieme aggiorna le statistiche
    del pianificatore, che dopo una grande eliminazione sono superate -- ed e' quello
    che rende lente le interrogazioni proprio dopo una pulizia.
    """
    prima = database_size()
    with motore().connect().execution_options(isolation_level="AUTOCOMMIT") as pulizia:
        pulizia.exec_driver_sql("VACUUM (ANALYZE)")
    dopo = database_size()
    recuperate = max(0, prima["righe_morte"] - dopo["righe_morte"])
    log_event("maintenance.compact",
              "Archivio compattato: %d righe morte rese riutilizzabili;"
              " dimensione da %d a %d byte (PostgreSQL non la restituisce al disco)"
              % (recuperate, prima["file_byte"], dopo["file_byte"]),
              severity="info", entity="database")
    return {"prima": prima["file_byte"], "dopo": dopo["file_byte"],
            # Le righe morte rese riutilizzabili: e' cio' che l'operazione fa
            # davvero, ed e' l'unica misura che si puo' dichiarare senza mentire.
            "righe_recuperate": recuperate,
            "righe_morte_prima": prima["righe_morte"],
            "righe_morte_dopo": dopo["righe_morte"],
            # Conservato per compatibilita' con chi legge l'esito: su PostgreSQL e'
            # zero quasi sempre, e non e' un difetto (vedi la spiegazione sopra).
            "liberati": max(0, prima["file_byte"] - dopo["file_byte"])}


# --------------------------------------------------------------------------- #
# Copie di sicurezza
# --------------------------------------------------------------------------- #
# Gli eseguibili del client PostgreSQL. Sono nell'immagine (pacchetto
# `postgresql-client`): la copia si chiede dalla console, quindi lo strumento deve
# stare dove gira la console.
PG_DUMP = "pg_dump"
PG_RESTORE = "pg_restore"

# Tempo massimo concesso a una copia o a un ripristino. Un archivio grande richiede
# minuti; oltre mezz'ora e' piu' probabile che il comando sia appeso che lento, e una
# richiesta HTTP appesa per sempre non aiuta nessuno.
TIMEOUT_COMANDO_SEC = 1800


class DumpNonDisponibile(MaintenanceError):
    """Il client PostgreSQL non c'e' o non e' compatibile con il server."""


def _dsn_proprietario() -> str:
    """Credenziali con cui copiare e ripristinare.

    Serve il PROPRIETARIO, non l'utenza applicativa: la copia deve leggere ogni
    oggetto e il ripristino deve poterli ricreare. L'utenza applicativa ha di
    proposito i soli privilegi di lettura e scrittura sui dati, e con quella una copia
    sarebbe incompleta -- senza dirlo, che e' il modo peggiore.
    """
    dsn = (current_app.config.get("OWNER_DATABASE_URL")
           or os.environ.get("SNAP_SERVER_OWNER_DATABASE_URL") or "").strip()
    if not dsn:
        raise DumpNonDisponibile(
            "Le credenziali del proprietario della base dati non sono configurate"
            " (SNAP_SERVER_OWNER_DATABASE_URL): senza quelle una copia sarebbe"
            " incompleta e un ripristino impossibile.")
    return dsn


def _parti_dsn(dsn: str) -> dict:
    """Host, porta, base dati e credenziali da un DSN SQLAlchemy.

    La password NON finisce mai fra gli argomenti del comando: sulla riga di comando
    sarebbe visibile a chiunque possa elencare i processi. Viaggia in `PGPASSWORD`,
    nell'ambiente del solo processo figlio.
    """
    pezzi = urlsplit(dsn)
    return {
        "host": pezzi.hostname or "localhost",
        "porta": str(pezzi.port or 5432),
        "database": unquote((pezzi.path or "/").lstrip("/")) or "snap",
        "utente": unquote(pezzi.username or ""),
        "password": unquote(pezzi.password or ""),
    }


def _ambiente(parti: dict) -> dict:
    ambiente = dict(os.environ)
    if parti["password"]:
        ambiente["PGPASSWORD"] = parti["password"]
    # Messaggi del client in inglese: vengono riportati nel diario e nei messaggi
    # d'errore, e un testo tradotto dalla locale del container e' piu' difficile da
    # cercare quando serve capire cos'e' andato storto.
    ambiente["LC_ALL"] = "C"
    return ambiente


def _versione_client(eseguibile: str = PG_DUMP) -> int:
    """Versione major del client. Solleva se il client non c'e'."""
    if shutil.which(eseguibile) is None:
        raise DumpNonDisponibile(
            "Lo strumento %s non e' disponibile in questa installazione: la copia"
            " dell'archivio dalla console non puo' essere eseguita." % eseguibile)
    try:
        esito = subprocess.run([eseguibile, "--version"], capture_output=True,
                               text=True, timeout=30, check=True)
    except (OSError, subprocess.SubprocessError) as errore:
        raise DumpNonDisponibile("Impossibile interrogare %s: %s"
                                 % (eseguibile, errore)) from errore
    trovata = re.search(r"(\d+)\.\d+", esito.stdout or "")
    if not trovata:
        raise DumpNonDisponibile("Versione di %s non riconosciuta: %s"
                                 % (eseguibile, (esito.stdout or "").strip()))
    return int(trovata.group(1))


def _versione_server() -> int:
    """Versione major del server, chiesta al server stesso."""
    numero = scalar("SHOW server_version_num")
    return int(int(numero) // 10000)


def _verifica_compatibilita(per_ripristino: bool = False) -> dict:
    """Le versioni di client e server sono compatibili per cio' che si sta per fare.

    LE DUE REGOLE SONO DIVERSE, e la differenza e' stata misurata, non dedotta:

    * COPIA: `pg_dump` legge un server della propria versione o piu' VECCHIO. Un
      client piu' vecchio del server non conosce gli oggetti introdotti dopo di se'
      e produrrebbe una copia incompleta senza dirlo.
    * RIPRISTINO: `pg_restore` deve avere la STESSA versione major del server. Non
      riversa soltanto il contenuto dell'archivio: apre la sessione con le proprie
      impostazioni, e quelle di una versione piu' recente il server non le conosce.
      Misurato: `pg_restore` 17 verso un server 16 fallisce su
      `SET transaction_timeout = 0`, parametro introdotto con la 17. Consentire la
      copia e scoprire il problema il giorno del ripristino sarebbe il modo peggiore
      di scoprirlo.
    """
    client = _versione_client(PG_RESTORE if per_ripristino else PG_DUMP)
    server = _versione_server()
    if client < server:
        raise DumpNonDisponibile(
            "Il client PostgreSQL (%d) e' piu' vecchio del server (%d): una copia"
            " prodotta cosi' potrebbe essere incompleta. Serve il client della"
            " versione %d." % (client, server, server))
    if per_ripristino and client != server:
        raise DumpNonDisponibile(
            "Il ripristino richiede pg_restore della stessa versione del server:"
            " qui il client e' %d e il server %d. Con versioni diverse pg_restore"
            " imposta parametri di sessione che il server non riconosce e il"
            " ripristino si interrompe. Installare il client della versione %d."
            % (client, server, server))
    return {"client": client, "server": server}


def _esegui(argomenti: list, parti: dict, cosa: str) -> str:
    """Esegue un comando del client PostgreSQL. Restituisce lo standard output.

    Nessun `shell=True` e nessuna stringa da comporre: gli argomenti sono una lista,
    quindi un nome di base dati o di file non puo' diventare un comando.
    """
    try:
        esito = subprocess.run(argomenti, capture_output=True, text=True,
                               timeout=TIMEOUT_COMANDO_SEC, env=_ambiente(parti))
    except subprocess.TimeoutExpired as errore:
        raise MaintenanceError(
            "%s non completata entro %d minuti: l'operazione e' stata interrotta."
            % (cosa, TIMEOUT_COMANDO_SEC // 60)) from errore
    except OSError as errore:
        raise MaintenanceError("%s non eseguibile: %s" % (cosa, errore)) from errore
    if esito.returncode != 0:
        # Si riporta la sola ultima riga dell'errore del client: e' quella che dice
        # cosa e' andato storto, e il resto e' contesto che finirebbe in una pagina.
        righe = [r for r in (esito.stderr or "").strip().splitlines() if r.strip()]
        motivo = righe[-1] if righe else "esito %d" % esito.returncode
        raise MaintenanceError("%s non riuscita: %s" % (cosa, motivo))
    return esito.stdout or ""


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
    versioni = _verifica_compatibilita()
    parti = _parti_dsn(_dsn_proprietario())
    destinazione = _percorso_copia()

    argomenti = [
        PG_DUMP,
        "--host", parti["host"], "--port", parti["porta"],
        "--username", parti["utente"], "--dbname", parti["database"],
        "--no-password",          # la password sta in PGPASSWORD, non si chiede a un tty
        "--format=custom",        # compresso, e ripristinabile in modo selettivo
        "--compress=6",
        "--file", str(destinazione),
    ]
    try:
        _esegui(argomenti, parti, "Copia dell'archivio")
    except MaintenanceError:
        # Un file parziale sarebbe indistinguibile da una copia valida.
        destinazione.unlink(missing_ok=True)
        raise

    dimensione = destinazione.stat().st_size if destinazione.exists() else 0
    integro = verify_backup(destinazione)
    if not integro["valida"]:
        destinazione.unlink(missing_ok=True)
        raise MaintenanceError("La copia prodotta non ha superato la verifica: %s"
                               % integro["motivo"])

    rimosse = rotate_backups(keep if keep is not None else DEFAULT_KEEP)
    log_event("maintenance.backup",
              "Copia dell'archivio creata: %s (%d byte, pg_dump %d verso server %d)%s%s"
              % (destinazione.name, dimensione, versioni["client"], versioni["server"],
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
    """Verifica che un file sia un archivio snap ripristinabile.

    Tre controlli, gli stessi di prima tradotti negli strumenti di PostgreSQL: il
    file si apre come archivio (`pg_restore --list` legge l'indice e fallisce su un
    file corrotto o di altra natura), l'indice contiene le tabelle del prodotto, e la
    versione del client basta a leggerlo. Un ripristino da un file qualunque
    distruggerebbe l'archivio in esercizio.

    Non conta le righe: l'indice di un archivio dichiara gli OGGETTI, non i dati, e
    contarli richiederebbe di ripristinarlo. Cio' che si puo' affermare senza
    ripristinare, si afferma; il resto non si finge.
    """
    file = Path(percorso)
    if not file.is_file():
        return {"valida": False, "motivo": "file non trovato"}
    try:
        _versione_client(PG_RESTORE)
    except DumpNonDisponibile as errore:
        return {"valida": False, "motivo": str(errore)}
    try:
        indice = _esegui([PG_RESTORE, "--list", str(file)], {"password": ""},
                         "Verifica della copia")
    except MaintenanceError as errore:
        return {"valida": False, "motivo": "non e' un archivio leggibile: %s" % errore}

    # Le righe dell'indice hanno due forme, e servono entrambe: la definizione
    #   4321; 1259 16404 TABLE public nodes snap_owner
    # e i dati
    #   4322; 0 16404 TABLE DATA public nodes snap_owner
    # Una copia con le sole definizioni e senza dati e' un archivio valido ma
    # vuoto: si raccolgono i nomi da entrambe e si guarda che ci siano i dati.
    definite = set(re.findall(" TABLE +(?!DATA )[^ ]+ +([^ ]+)", indice))
    con_dati = set(re.findall(" TABLE +DATA +[^ ]+ +([^ ]+)", indice))
    tabelle = definite | con_dati
    mancanti = [t for t in TABELLE_ATTESE if t not in tabelle]
    if mancanti:
        return {"valida": False,
                "motivo": "non e' un archivio snap: mancano %s" % ", ".join(mancanti)}
    return {"valida": True, "motivo": "", "tabelle": len(tabelle),
            "byte": file.stat().st_size}


def restore_from(percorso, attore: str = "") -> dict:
    """Riversa una copia nell'archivio in esercizio, dopo averne salvato lo stato.

    Non sostituisce file e non ferma il servizio: `pg_restore --clean --if-exists`
    elimina e ricrea gli oggetti DENTRO la base dati in esercizio, in una sola
    transazione (`--single-transaction`), cosi' un ripristino interrotto a meta' non
    lascia un archivio mezzo vuoto.
    """
    versioni = _verifica_compatibilita(per_ripristino=True)
    candidato = Path(percorso)
    verifica = verify_backup(candidato)
    if not verifica["valida"]:
        raise MaintenanceError("Copia non ripristinabile: %s" % verifica["motivo"])

    prima = backup_now(nota="stato precedente al ripristino di %s" % candidato.name)
    parti = _parti_dsn(_dsn_proprietario())

    argomenti = [
        PG_RESTORE,
        "--host", parti["host"], "--port", parti["porta"],
        "--username", parti["utente"], "--dbname", parti["database"],
        "--no-password",
        "--clean", "--if-exists",   # si rifa' da zero, senza lamentarsi di cio' che manca
        "--single-transaction",     # tutto o niente: mai un archivio a meta'
        "--no-owner", "--no-privileges",  # i proprietari li stabilisce questa installazione
        str(candidato),
    ]
    try:
        _esegui(argomenti, parti, "Ripristino dell'archivio")
    except MaintenanceError as errore:
        raise MaintenanceError(
            "%s Lo stato precedente e' nella copia %s." % (errore, prima["nome"])
        ) from errore

    # Le connessioni del pool hanno in mano oggetti che il ripristino ha ricreato:
    # tenerle significherebbe lavorare su piani e cataloghi non piu' validi.
    motore().dispose()

    log_event("maintenance.restore",
              "Archivio ripristinato dalla copia %s (%s tabelle, pg_restore %d verso"
              " server %d); stato precedente salvato in %s"
              % (candidato.name, verifica.get("tabelle", "?"), versioni["client"],
                 versioni["server"], prima["nome"]),
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
    if not nome.endswith((BACKUP_SUFFIX, ".backup")):
        raise MaintenanceError("Il file deve essere un archivio pg_dump in formato"
                               " personalizzato (%s). Il contenuto viene comunque"
                               " verificato prima di qualunque ripristino."
                               % BACKUP_SUFFIX)
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
