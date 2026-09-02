"""
snap server - Controlli periodici: definizione, valutazione e workflow.

Chi fa che cosa
---------------
Il server DEFINISCE i controlli e ne GOVERNA gli esiti; la sonda li ESEGUE. I
bersagli stanno nella rete del cliente e il server non apre connessioni verso
l'interno (requisito R2): le definizioni viaggiano nella configurazione cifrata,
gli esiti tornano come record di conferimento.

Tre generi di controllo
-----------------------
  presence  il bersaglio risponde in rete
  ports     una o piu' porte risultano aperte
  http      un endpoint risponde, con verifiche sul contenuto JSON

Perche' le verifiche sul JSON sono dichiarative
-----------------------------------------------
Un endpoint di salute risponde 200 anche quando dichiara "database: disconnected":
il codice di stato non basta. Le verifiche sono percio' espresse come percorso,
operatore e valore atteso -- `database eq connected` -- e sono conservate con il
controllo, non scritte nel codice della sonda.

Workflow degli incidenti
------------------------
Un controllo che fallisce per un numero dichiarato di volte consecutive apre un
INCIDENTE. Da li' due strade, scelte per controllo:

  autonomo    l'incidente si chiude da se' quando il controllo torna a posto;
  con operatore  il ritorno alla normalita' viene annotato, ma l'incidente resta
                 aperto finche' una persona non lo prende in carico e lo risolve.

La distinzione esiste perche' non tutti i disservizi si esauriscono da soli: un
servizio che oscilla va guardato da qualcuno, e un incidente chiuso in automatico
sarebbe un difetto che nessuno ha visto.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import timedelta
from urllib.parse import urlparse

from .audit import log_event
from .db import execute, query, utc_now, utc_now_str, utc_str
from .notifications import incident_message, queue_notification

# Generi di controllo previsti, con l'etichetta mostrata all'operatore.
CHECK_KINDS = {
    "presence": "Presenza in rete",
    "ports": "Porte aperte",
    "http": "Endpoint HTTP",
}

# Esiti possibili di una esecuzione.
STATUS_OK = "ok"
STATUS_FAIL = "fail"
STATUS_ERROR = "error"
RESULT_STATUSES = (STATUS_OK, STATUS_FAIL, STATUS_ERROR)

# Stati dell'incidente.
INCIDENT_OPEN = "open"
INCIDENT_ACK = "acknowledged"
INCIDENT_RESOLVED = "resolved"

SEVERITIES = ("info", "warning", "critical")

# Limiti di esercizio. Non sono vincoli tecnici ma soglie oltre le quali un
# controllo periodico diventa un carico o una raccolta inutilizzabile.
MIN_INTERVAL_SECONDS = 30
MAX_INTERVAL_SECONDS = 86400
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 120
MAX_PORTS_PER_CHECK = 32
MAX_ASSERTIONS = 20
MAX_FAILURE_THRESHOLD = 20
# Soglia di attivazione dell'operatore, in fallimenti consecutivi. Il valore
# predefinito e' il doppio di quello di apertura: un disservizio che dura il doppio
# del tempo necessario ad aprire un incidente non si sta risolvendo da se'.
DEFAULT_ESCALATION_THRESHOLD = 6

# Ogni quanto ricordare che un incidente attivato dall'operatore e' rientrato ma resta
# aperto. Il controllo gira ogni pochi secondi: senza questa soglia la stessa notifica
# partirebbe a ogni giro (una mail o un Telegram ogni 30 secondi). Un promemoria ogni
# cinque minuti dice la stessa cosa senza sommergere la casella.
INTERVALLO_PROMEMORIA_RIENTRO_SECONDI = 300
MAX_ESCALATION_THRESHOLD = 200
# Le risposte si conservano accorciate: servono a capire cosa non torna, non a
# archiviare il traffico.
MAX_PAYLOAD_CHARS = 4000
# Punti di misura per esito. Il limite evita che una risposta prolissa riempia la
# serie storica di valori che nessuno guardera'.
MAX_METRICS_PER_RESULT = 60
MAX_METRIC_DEPTH = 6
MAX_METRIC_NAME_CHARS = 120
MAX_METRIC_TEXT_CHARS = 200
# Un testo piu' lungo di cosi' non e' un dato di stato, e' contenuto: resta nella
# risposta conservata e non diventa un punto di misura.
METRIC_TEXT_LIMIT = 80

# Operatori delle verifiche sul contenuto JSON.
ASSERTION_OPS = {
    "eq": "uguale a",
    "ne": "diverso da",
    "contains": "contiene",
    "gt": "maggiore di",
    "lt": "minore di",
    "exists": "presente",
    "absent": "assente",
}

HOSTNAME_PATTERN = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,62})"
                              r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*$")
# Controllo di forma sul recapito: non verifica che la casella esista, ma impedisce
# di salvare un valore che non e' un indirizzo.
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9]([A-Za-z0-9.-]{0,252})"
                           r"\.[A-Za-z]{2,24}$")


class CheckError(ValueError):
    """Definizione di controllo non valida. Il messaggio e' per l'operatore."""


# --------------------------------------------------------------------------- #
# Validazione delle definizioni
# --------------------------------------------------------------------------- #
def validate_address(address: str) -> str:
    """Indirizzo IP o nome host di un bersaglio.

    Si accettano entrambi: un controllo puo' riguardare un servizio raggiungibile
    solo per nome, che la scoperta della rete non censirebbe.
    """
    valore = (address or "").strip()
    if not valore:
        raise CheckError("Indicare un indirizzo IP o un nome host.")
    if len(valore) > 253:
        raise CheckError("L'indirizzo supera i 253 caratteri consentiti.")
    try:
        ipaddress.ip_address(valore)
        return valore
    except ValueError:
        pass  # non e' un indirizzo: si valuta come nome host

    # Un valore fatto di soli numeri e punti e' un indirizzo scritto male, non un
    # nome host: la sintassi dei nomi lo accetterebbe, ma chi lo digita intende un
    # indirizzo. Accettarlo significherebbe creare un controllo che non potra' mai
    # risolvere il proprio bersaglio.
    pezzi = valore.split(".")
    if len(pezzi) > 1 and all(pezzo.isdigit() for pezzo in pezzi):
        raise CheckError("%r non e' un indirizzo IP valido." % valore)

    if not HOSTNAME_PATTERN.match(valore):
        raise CheckError("%r non e' un indirizzo IP valido ne' un nome host valido."
                         % valore)
    return valore


def _validate_ports(config: dict) -> dict:
    grezze = config.get("ports")
    if isinstance(grezze, str):
        grezze = [p for p in re.split(r"[,\s]+", grezze) if p]
    if not grezze:
        raise CheckError("Indicare almeno una porta da verificare.")
    if len(grezze) > MAX_PORTS_PER_CHECK:
        raise CheckError("Non piu' di %d porte per controllo: indicate %d."
                         % (MAX_PORTS_PER_CHECK, len(grezze)))
    porte = []
    for voce in grezze:
        if isinstance(voce, dict):
            protocollo = (voce.get("protocol") or "tcp").strip().lower()
            numero = voce.get("port")
        else:
            testo = str(voce).strip().lower()
            protocollo = "tcp"
            if "/" in testo:
                protocollo, testo = testo.split("/", 1)
            numero = testo
        if protocollo not in ("tcp", "udp"):
            raise CheckError("Protocollo %r non previsto: attesi tcp o udp." % protocollo)
        try:
            numero = int(numero)
        except (TypeError, ValueError):
            raise CheckError("%r non e' un numero di porta." % (numero,)) from None
        if not 1 <= numero <= 65535:
            raise CheckError("La porta %d e' fuori dall'intervallo 1-65535." % numero)
        voce_pulita = {"protocol": protocollo, "port": numero}
        if voce_pulita not in porte:
            porte.append(voce_pulita)
    return {"ports": porte}


def _validate_assertions(grezze) -> list:
    if grezze in (None, "", []):
        return []
    if isinstance(grezze, str):
        try:
            grezze = json.loads(grezze)
        except ValueError as errore:
            raise CheckError("Le verifiche non sono un JSON valido: %s" % errore) from errore
    if not isinstance(grezze, list):
        raise CheckError("Le verifiche devono essere un elenco.")
    if len(grezze) > MAX_ASSERTIONS:
        raise CheckError("Non piu' di %d verifiche per controllo." % MAX_ASSERTIONS)
    verifiche = []
    for voce in grezze:
        if not isinstance(voce, dict):
            raise CheckError("Ogni verifica deve indicare percorso, operatore e valore.")
        percorso = (voce.get("path") or "").strip()
        operatore = (voce.get("op") or "eq").strip().lower()
        if not percorso:
            raise CheckError("Una verifica senza percorso non e' valutabile.")
        if operatore not in ASSERTION_OPS:
            raise CheckError("Operatore %r non previsto: attesi %s."
                             % (operatore, ", ".join(sorted(ASSERTION_OPS))))
        verifica = {"path": percorso, "op": operatore}
        if operatore not in ("exists", "absent"):
            if voce.get("value") in (None, ""):
                raise CheckError("La verifica su %r richiede un valore atteso." % percorso)
            verifica["value"] = voce.get("value")
        verifiche.append(verifica)
    return verifiche


def validate_metric_paths(grezzi) -> list:
    """Percorsi dei dati da conservare. Elenco vuoto: si conserva tutto.

    Si accetta sia una lista sia un testo con un percorso per riga: la pagina invia
    caselle di spunta, ma una configurazione scritta a mano resta leggibile.
    """
    if grezzi in (None, "", []):
        return []
    if isinstance(grezzi, str):
        grezzi = [r.strip() for r in grezzi.replace(",", "\n").split("\n")]
    percorsi = []
    for voce in grezzi:
        percorso = str(voce or "").strip()
        if not percorso:
            continue
        if len(percorso) > MAX_METRIC_NAME_CHARS:
            raise CheckError("Il percorso %r supera i %d caratteri consentiti."
                             % (percorso[:40], MAX_METRIC_NAME_CHARS))
        if percorso not in percorsi:
            percorsi.append(percorso)
    if len(percorsi) > MAX_METRICS_PER_RESULT:
        raise CheckError("Non piu' di %d dati per controllo: scelti %d."
                         % (MAX_METRICS_PER_RESULT, len(percorsi)))
    return percorsi


def _validate_http(config: dict) -> dict:
    url = (config.get("url") or "").strip()
    if not url:
        raise CheckError("Indicare l'URL dell'endpoint.")
    parti = urlparse(url)
    if parti.scheme not in ("http", "https"):
        raise CheckError("L'URL deve cominciare con http:// o https://.")
    if not parti.hostname:
        raise CheckError("L'URL non contiene un host.")
    metodo = (config.get("method") or "GET").strip().upper()
    if metodo not in ("GET", "HEAD"):
        # Un controllo periodico non deve poter modificare lo stato del bersaglio.
        raise CheckError("Sono previsti solo GET e HEAD: un controllo non modifica "
                         "lo stato del sistema verificato.")
    atteso = config.get("expect_status") or 200
    try:
        atteso = int(atteso)
    except (TypeError, ValueError):
        raise CheckError("Il codice di stato atteso deve essere un numero.") from None
    if not 100 <= atteso <= 599:
        raise CheckError("Il codice di stato atteso e' fuori dall'intervallo 100-599.")
    return {
        "url": url,
        "method": metodo,
        "expect_status": atteso,
        "assertions": _validate_assertions(config.get("assertions")),
        # Dati da conservare e mostrare. Elenco vuoto: tutti.
        "metrics": validate_metric_paths(config.get("metrics")),
    }


def validate_definition(kind: str, config: dict) -> dict:
    """Configurazione ripulita di un controllo, per genere."""
    genere = (kind or "").strip().lower()
    if genere not in CHECK_KINDS:
        raise CheckError("Genere di controllo %r non previsto." % kind)
    config = config or {}
    if genere == "presence":
        return {}
    if genere == "ports":
        return _validate_ports(config)
    return _validate_http(config)


def validate_escalation_email(email) -> str | None:
    """Recapito dell'operatore, se indicato.

    Vuoto non e' un errore: significa "usa l'email di riferimento del tenant", che e'
    il comportamento previsto quando nessuno indica un recapito specifico.
    """
    valore = (email or "").strip()
    if not valore:
        return None
    if len(valore) > 254 or not EMAIL_PATTERN.match(valore):
        raise CheckError("%r non e' un indirizzo di posta valido." % valore)
    return valore


def validate_schedule(interval_seconds, timeout_seconds, failure_threshold,
                      escalation_threshold=None) -> tuple:
    """Cadenza, tempo massimo, soglia di apertura e soglia di attivazione.

    La soglia di attivazione non puo' essere inferiore a quella di apertura: un
    operatore attivato prima che l'incidente esista non avrebbe nulla da guardare.
    """
    def intero(valore, nome, predefinito):
        if valore in (None, ""):
            return predefinito
        try:
            return int(valore)
        except (TypeError, ValueError):
            raise CheckError("%s deve essere un numero." % nome) from None

    cadenza = intero(interval_seconds, "La cadenza", 300)
    attesa = intero(timeout_seconds, "Il tempo massimo", 10)
    soglia = intero(failure_threshold, "La soglia di apertura", 3)

    if not MIN_INTERVAL_SECONDS <= cadenza <= MAX_INTERVAL_SECONDS:
        raise CheckError("La cadenza deve essere fra %d e %d secondi."
                         % (MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS))
    if not MIN_TIMEOUT_SECONDS <= attesa <= MAX_TIMEOUT_SECONDS:
        raise CheckError("Il tempo massimo deve essere fra %d e %d secondi."
                         % (MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS))
    if attesa >= cadenza:
        raise CheckError("Il tempo massimo (%d s) deve essere inferiore alla cadenza "
                         "(%d s): altrimenti un'esecuzione lenta si sovrappone alla "
                         "successiva." % (attesa, cadenza))
    if not 1 <= soglia <= MAX_FAILURE_THRESHOLD:
        raise CheckError("La soglia di apertura deve essere fra 1 e %d fallimenti."
                         % MAX_FAILURE_THRESHOLD)

    attivazione = intero(escalation_threshold, "La soglia di attivazione",
                         max(soglia, DEFAULT_ESCALATION_THRESHOLD))
    if attivazione < soglia:
        raise CheckError(
            "La soglia di attivazione dell'operatore (%d) non puo' essere inferiore a"
            " quella di apertura dell'incidente (%d): l'operatore verrebbe attivato"
            " prima che l'incidente esista." % (attivazione, soglia))
    if attivazione > MAX_ESCALATION_THRESHOLD:
        raise CheckError("La soglia di attivazione deve essere al massimo %d fallimenti."
                         % MAX_ESCALATION_THRESHOLD)
    return cadenza, attesa, soglia, attivazione


def describe(kind: str, config: dict) -> str:
    """Descrizione in una riga di cio' che il controllo verifica."""
    config = config or {}
    if kind == "presence":
        return "risponde in rete"
    if kind == "ports":
        return "porte " + ", ".join("%s/%s" % (p["protocol"], p["port"])
                                    for p in config.get("ports") or [])
    if kind == "http":
        verifiche = config.get("assertions") or []
        testo = "%s %s (atteso %s)" % (config.get("method", "GET"), config.get("url", ""),
                                       config.get("expect_status", 200))
        if verifiche:
            testo += ", " + " e ".join(
                "%s %s %s" % (v["path"], ASSERTION_OPS[v["op"]], v.get("value", ""))
                for v in verifiche).strip()
        return testo
    return kind


# --------------------------------------------------------------------------- #
# Definizioni consegnate alle sonde
# --------------------------------------------------------------------------- #
def checks_for_probe(tenant_id: int) -> list[dict]:
    """Controlli attivi del tenant, nella forma consegnata alla sonda.

    Le sonde di un tenant eseguono gli stessi controlli: il bersaglio e' un
    servizio del cliente, non della singola sonda. Una definizione illeggibile non
    viene consegnata a meta': si salta e si annota.
    """
    righe = query(
        "SELECT c.id, c.name, c.kind, c.config_json, c.interval_seconds,"
        " c.timeout_seconds, t.address, t.name AS target_name"
        " FROM checks c JOIN check_targets t ON t.id = c.target_id"
        " WHERE c.tenant_id = ? AND c.is_enabled = 1 AND t.is_enabled = 1"
        " ORDER BY c.id", (tenant_id,))
    definizioni = []
    for riga in righe:
        try:
            configurazione = json.loads(riga["config_json"] or "{}")
        except ValueError:
            # Non si consegna una definizione che non si e' potuta leggere.
            log_event("checks.definition.unreadable",
                      "Definizione del controllo %d illeggibile: non consegnata"
                      % riga["id"],
                      tenant_id=tenant_id, severity="warning", entity="check",
                      entity_id=riga["id"])
            continue
        definizioni.append({
            "id": int(riga["id"]),
            "name": riga["name"],
            "kind": riga["kind"],
            "address": riga["address"],
            "target_name": riga["target_name"],
            "interval_seconds": int(riga["interval_seconds"]),
            "timeout_seconds": int(riga["timeout_seconds"]),
            "config": configurazione,
        })
    return definizioni


# --------------------------------------------------------------------------- #
# Workflow: dagli esiti agli incidenti
# --------------------------------------------------------------------------- #
def metric_selection(config: dict) -> list:
    """Percorsi scelti nella configurazione di un controllo. Vuoto: tutti."""
    return list((config or {}).get("metrics") or [])


def _metric_selection(controllo) -> list:
    """Come sopra, a partire dalla riga del controllo."""
    try:
        return metric_selection(json.loads(controllo["config_json"] or "{}"))
    except (ValueError, TypeError, KeyError, IndexError):
        # Configurazione illeggibile: si conserva tutto, che e' il comportamento
        # predefinito. Perdere misure per un JSON rotto sarebbe il danno peggiore.
        return []


def _column(riga, nome, predefinito=None):
    """Valore di una colonna che potrebbe non esistere ancora.

    Gli archivi creati prima dell'introduzione dell'attivazione ricevono le colonne
    con una migrazione; leggerle in modo tollerante evita che un archivio non ancora
    migrato faccia cadere l'applicazione invece di dichiarare il problema.
    """
    try:
        return riga[nome]
    except (KeyError, IndexError):
        return predefinito


def flatten_metrics(payload, prefix: str = "", depth: int = 0) -> list:
    """Scompone una risposta in punti di misura (nome, numero, testo).

    Il nome usa il punto per la discesa negli oggetti e l'indice per gli elenchi,
    la stessa notazione delle verifiche: cosi' cio' che si controlla e cio' che si
    misura si chiamano nello stesso modo.
    """
    if depth > MAX_METRIC_DEPTH:
        return []
    punti = []
    if isinstance(payload, dict):
        for chiave, valore in payload.items():
            # Convenzione: una chiave che comincia con `_` porta informazione di
            # lettura per l'operatore, non una misura. Serve a tenere fuori dalle
            # serie i testi che cambiano a ogni esecuzione senza dire nulla di
            # nuovo, come "aperta in 9 ms" accanto alla misura del tempo.
            if str(chiave).startswith("_"):
                continue
            nome = "%s.%s" % (prefix, chiave) if prefix else str(chiave)
            punti.extend(flatten_metrics(valore, nome, depth + 1))
        return punti
    if isinstance(payload, list):
        for indice, valore in enumerate(payload):
            nome = "%s.%d" % (prefix, indice) if prefix else str(indice)
            punti.extend(flatten_metrics(valore, nome, depth + 1))
        return punti

    if not prefix:
        # Un valore senza nome non e' una misura: non si inventa un nome.
        return []
    nome = prefix[:MAX_METRIC_NAME_CHARS]
    if isinstance(payload, bool):
        # I booleani si contano: si conservano come numeri.
        return [(nome, 1.0 if payload else 0.0, "true" if payload else "false")]
    if isinstance(payload, (int, float)):
        return [(nome, float(payload), None)]
    if payload is None:
        return []
    testo = str(payload).strip()
    if not testo or len(testo) > METRIC_TEXT_LIMIT:
        # Contenuto, non stato: resta nella risposta conservata.
        return []
    return [(nome, None, testo[:MAX_METRIC_TEXT_CHARS])]


def store_metrics(tenant_id: int, check_id: int, result_id: int, measured_at: str,
                  payload, latency_ms=None, selection=None) -> int:
    """Conserva i punti di misura di un esito. Restituisce quanti ne ha scritti.

    La latenza si conserva sempre, per ogni genere di controllo: e' la misura
    disponibile anche quando la risposta non contiene numeri, ed e' quella che
    dice se un servizio sta peggiorando prima di cadere.
    """
    punti = []
    if latency_ms is not None:
        try:
            punti.append(("latency_ms", float(latency_ms), None))
        except (TypeError, ValueError):
            pass

    documento = payload
    if isinstance(documento, str):
        testo = documento.strip()
        if testo.startswith("{") or testo.startswith("["):
            try:
                documento = json.loads(testo)
            except ValueError:
                # Risposta non JSON: non ci sono punti di misura da ricavare, e la
                # risposta resta conservata come testo.
                documento = None
        else:
            documento = None
    if documento is not None and not isinstance(documento, str):
        ricavati = flatten_metrics(documento)
        if selection:
            # La scelta e' una lista bianca sui percorsi: cio' che non e' scelto non
            # entra in archivio. La latenza non passa da qui e resta sempre.
            ammessi = set(selection)
            ricavati = [voce for voce in ricavati if voce[0] in ammessi]
        punti.extend(ricavati)

    if len(punti) > MAX_METRICS_PER_RESULT:
        punti = punti[:MAX_METRICS_PER_RESULT]

    for nome, numero, testo in punti:
        execute("INSERT INTO check_metrics (tenant_id, check_id, result_id, name, value,"
                " text_value, measured_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (tenant_id, check_id, result_id, nome, numero, testo, measured_at))
    return len(punti)


def backfill_metrics(tenant_id: int = None, limit: int = 5000) -> dict:
    """Ricava le misure dagli esiti che ne sono privi. Ripetibile.

    Utile dopo l'introduzione delle metriche e dopo l'aggiunta di un nuovo genere
    di valore riconosciuto: gli esiti conservano la risposta, e i valori si possono
    ricavare invece di perderli.
    """
    condizione = "WHERE r.id NOT IN (SELECT DISTINCT result_id FROM check_metrics" \
                 " WHERE result_id IS NOT NULL)"
    parametri = []
    if tenant_id is not None:
        condizione += " AND r.tenant_id = ?"
        parametri.append(tenant_id)
    parametri.append(int(limit))

    righe = query("SELECT r.id, r.tenant_id, r.check_id, r.executed_at, r.latency_ms,"
                  " r.payload_json FROM check_results r " + condizione +
                  " ORDER BY r.id LIMIT ?", parametri)
    esiti = 0
    misure = 0
    # Selezione per controllo, letta una volta: il recupero non deve reintrodurre i
    # dati che l'operatore ha escluso.
    selezioni = {}
    for riga in righe:
        identificativo = int(riga["check_id"])
        if identificativo not in selezioni:
            controllo = query("SELECT config_json FROM checks WHERE id = ?",
                              (identificativo,), one=True)
            selezioni[identificativo] = _metric_selection(controllo) if controllo else []
        scritte = store_metrics(int(riga["tenant_id"]), identificativo,
                                int(riga["id"]), riga["executed_at"],
                                riga["payload_json"], riga["latency_ms"],
                                selection=selezioni[identificativo])
        esiti += 1
        misure += scritte
    return {"results": esiti, "metrics": misure}


def notify_workflow(tenant_id: int, event: str, incident_id: int, check: dict,
                    detail: str = "") -> None:
    """Notifica un momento del workflow ai recapiti competenti.

    I destinatari sono il recapito dell'operatore (indicato sul controllo oppure
    l'email di riferimento del tenant) e, se diverso, quello a cui l'incidente e'
    stato scalato: chi e' stato attivato deve sapere anche come e' finita.

    Un errore nella notifica non deve far cadere il workflow: l'incidente e' gia'
    stato registrato, e una notifica mancata si vede nella propria coda.
    """
    try:
        riga = query(
            "SELECT i.*, c.name AS check_name, t.address FROM check_incidents i"
            " JOIN checks c ON c.id = i.check_id"
            " JOIN check_targets t ON t.id = c.target_id"
            " WHERE i.id = ?", (incident_id,), one=True)
        if riga is None:
            return
        incidente = dict(riga)
        destinatari = {operator_contact(tenant_id, check), incidente.get("escalated_to")}
        oggetto, corpo = incident_message(event, incidente, detail)
        # La forma HTML e' l'alternativa, non il contenuto: il testo resta quello che
        # si legge su qualunque client e nelle notifiche di sistema.
        from .notifications import incident_html

        html = incident_html(event, incidente, detail, console_url=_indirizzo_console())
        queue_notification(tenant_id, event, [d for d in destinatari if d],
                           oggetto, corpo, incident_id=incident_id, body_html=html)
    except Exception as errore:  # la notifica non e' il workflow
        log_event("checks.notification.failed",
                  "Notifica %s non accodata per l'incidente %s: %s"
                  % (event, incident_id, errore),
                  tenant_id=tenant_id, severity="warning", entity="check_incident",
                  entity_id=incident_id)


def _indirizzo_console() -> str:
    """L'indirizzo pubblico della console, se e' stato impostato.

    Serve al pulsante dei messaggi: senza indirizzo il pulsante non si mostra, perche'
    un pulsante che non porta da nessuna parte e' peggio della sua assenza.
    """
    from .notifications import _setting

    return _setting("public_url", "")


def operator_contact(tenant_id: int, check: dict) -> str | None:
    """Recapito a cui attivare l'operatore.

    Prima quello indicato sul controllo; in mancanza, l'email di riferimento del
    tenant. Se non c'e' nemmeno quella, l'attivazione avviene comunque -- l'incidente
    resta in attesa di una persona -- ma senza recapito, e lo si dichiara: un
    incidente che aspetta qualcuno che nessuno ha avvisato e' peggio di un incidente
    senza recapito dichiarato.
    """
    proprio = (check.get("escalation_email") or "").strip()
    if proprio:
        return proprio
    riga = query("SELECT contact_email FROM tenants WHERE id = ?", (tenant_id,), one=True)
    contatto = (riga["contact_email"] or "").strip() if riga is not None else ""
    return contatto or None


def escalate_incident(tenant_id: int, check: dict, incident_id: int,
                      failures: int, detail: str) -> str | None:
    """Attiva un operatore sull'incidente. Restituisce il recapito usato.

    Da questo momento l'incidente non si chiude piu' da se': il rientro del
    controllo viene annotato, ma la chiusura spetta a una persona.
    """
    recapito = operator_contact(tenant_id, check)
    adesso = utc_now_str()
    execute("UPDATE check_incidents SET escalated_at = ?, escalated_to = ?,"
            " severity = ?, updated_at = ? WHERE id = ? AND escalated_at IS NULL",
            (adesso, recapito, "critical", adesso, incident_id))
    _incident_event(
        tenant_id, incident_id, "escalated", "system",
        "Operatore attivato dopo %d fallimenti consecutivi%s: %s"
        % (failures, " (%s)" % recapito if recapito else
           " -- nessun recapito configurato: indicarlo sul controllo o come email di"
           " riferimento del tenant", detail))
    notify_workflow(tenant_id, "incident.escalated", incident_id, check, detail)
    log_event("checks.incident.escalated",
              "Operatore attivato sull'incidente %d del controllo '%s'%s"
              % (incident_id, check.get("name"),
                 ": %s" % recapito if recapito else " (nessun recapito configurato)"),
              tenant_id=tenant_id, severity="critical", entity="check_incident",
              entity_id=incident_id)
    return recapito


def _incident_event(tenant_id: int, incident_id: int, action: str, actor: str,
                    note: str = None) -> None:
    execute("INSERT INTO check_incident_events (tenant_id, incident_id, action, actor,"
            " note, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (tenant_id, incident_id, action, actor, note, utc_now_str()))


def open_incident(tenant_id: int, check: dict, detail: str, failures: int) -> int:
    """Apre un incidente per il controllo, o ne aggiorna quello aperto."""
    aperto = query(
        "SELECT * FROM check_incidents WHERE check_id = ? AND status IN (?, ?)"
        " ORDER BY id DESC", (check["id"], INCIDENT_OPEN, INCIDENT_ACK), one=True)
    adesso = utc_now_str()
    if aperto is not None:
        execute("UPDATE check_incidents SET failure_count = failure_count + 1,"
                " last_detail = ?, updated_at = ? WHERE id = ?",
                (detail, adesso, aperto["id"]))
        return int(aperto["id"])

    identificativo = execute(
        "INSERT INTO check_incidents (tenant_id, check_id, status, severity, opened_at,"
        " first_detail, last_detail, failure_count, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (tenant_id, check["id"], INCIDENT_OPEN, check.get("severity") or "warning",
         adesso, detail, detail, failures, adesso))
    _incident_event(tenant_id, identificativo, "opened", "system",
                    "Aperto dopo %d fallimenti consecutivi: %s" % (failures, detail))
    log_event("checks.incident.opened",
              "Incidente aperto sul controllo '%s': %s" % (check.get("name"), detail),
              tenant_id=tenant_id, severity=check.get("severity") or "warning",
              entity="check_incident", entity_id=identificativo)
    notify_workflow(tenant_id, "incident.opened", identificativo, check, detail)
    return identificativo


def close_incident_automatically(tenant_id: int, check: dict, detail: str) -> int | None:
    """Chiude l'incidente aperto quando il controllo torna a posto.

    Il workflow e' sempre automatico: la chiusura avviene da se'. L'unica eccezione
    e' un incidente su cui e' stato ATTIVATO UN OPERATORE: un disservizio che ha
    superato la soglia di attivazione va guardato da una persona, e chiuderlo in
    automatico sarebbe un difetto che nessuno ha visto. In quel caso il rientro viene
    annotato e l'incidente resta aperto.
    """
    aperto = query(
        "SELECT * FROM check_incidents WHERE check_id = ? AND status IN (?, ?)"
        " ORDER BY id DESC", (check["id"], INCIDENT_OPEN, INCIDENT_ACK), one=True)
    if aperto is None:
        return None
    adesso = utc_now_str()
    if aperto["escalated_at"]:
        # Lo stato si aggiorna sempre; la NOTIFICA (e l'annotazione sulla cronologia)
        # partono solo se non ne e' gia' andata una da poco: altrimenti, con il controllo
        # che gira ogni pochi secondi, arriverebbe una mail o un Telegram ogni volta.
        execute("UPDATE check_incidents SET last_detail = ?, updated_at = ? WHERE id = ?",
                ("Controllo tornato a posto, in attesa di verifica: %s" % detail,
                 adesso, aperto["id"]))
        ultimo = _column(aperto, "recovered_notified_at")
        soglia = utc_str(utc_now() - timedelta(
            seconds=INTERVALLO_PROMEMORIA_RIENTRO_SECONDI))
        if not ultimo or ultimo < soglia:
            execute("UPDATE check_incidents SET recovered_notified_at = ? WHERE id = ?",
                    (adesso, aperto["id"]))
            _incident_event(tenant_id, int(aperto["id"]), "recovered", "system",
                            "Il controllo ha ripreso a rispondere correttamente: %s. "
                            "L'incidente resta aperto perche' era stato attivato un "
                            "operatore." % detail)
            notify_workflow(tenant_id, "incident.recovered", int(aperto["id"]), check,
                            detail)
        return int(aperto["id"])

    execute("UPDATE check_incidents SET status = ?, resolved_at = ?, resolution = ?,"
            " last_detail = ?, updated_at = ? WHERE id = ?",
            (INCIDENT_RESOLVED, adesso, "chiuso in automatico al ritorno alla normalita'",
             detail, adesso, aperto["id"]))
    _incident_event(tenant_id, int(aperto["id"]), "resolved", "system",
                    "Chiuso in automatico: il controllo e' tornato a posto (%s)" % detail)
    notify_workflow(tenant_id, "incident.resolved", int(aperto["id"]), check,
                    "chiuso in automatico al ritorno alla normalita'")
    log_event("checks.incident.autoresolved",
              "Incidente chiuso in automatico sul controllo '%s'" % check.get("name"),
              tenant_id=tenant_id, severity="info", entity="check_incident",
              entity_id=int(aperto["id"]))
    return int(aperto["id"])


def consecutive_failures(check_id: int, limit: int) -> int:
    """Fallimenti consecutivi piu' recenti, fino a `limit`.

    Si contano sugli esiti conservati invece di tenere un contatore: un contatore
    andrebbe fuori sincrono a ogni riavvio o conferimento fuori ordine, gli esiti
    no.
    """
    righe = query("SELECT status FROM check_results WHERE check_id = ?"
                  " ORDER BY executed_at DESC, id DESC LIMIT ?",
                  (check_id, max(1, int(limit))))
    conteggio = 0
    for riga in righe:
        if riga["status"] == STATUS_OK:
            break
        conteggio += 1
    return conteggio


def record_result(tenant_id: int, check_id: int, probe_id: int | None,
                  result: dict) -> dict:
    """Conserva un esito e ne governa le conseguenze sul workflow.

    Restituisce cosa e' stato deciso, cosi' che il chiamante possa dichiararlo:
    un esito che non produce effetti visibili e' indistinguibile da un esito
    perduto.
    """
    controllo = query(
        "SELECT c.*, t.address FROM checks c JOIN check_targets t ON t.id = c.target_id"
        " WHERE c.id = ? AND c.tenant_id = ?", (check_id, tenant_id), one=True)
    if controllo is None:
        # Il controllo e' stato rimosso mentre la sonda lo eseguiva: l'esito non ha
        # piu' un posto dove stare, e non e' un errore della sonda.
        return {"stored": False, "reason": "controllo non trovato"}

    stato = (result.get("status") or "").strip().lower()
    if stato not in RESULT_STATUSES:
        raise CheckError("Esito %r non previsto: attesi %s."
                         % (stato, ", ".join(RESULT_STATUSES)))

    carico = result.get("payload")
    if carico is not None and not isinstance(carico, str):
        carico = json.dumps(carico, ensure_ascii=False)
    if carico and len(carico) > MAX_PAYLOAD_CHARS:
        carico = carico[:MAX_PAYLOAD_CHARS] + "... (risposta accorciata)"

    latenza = result.get("latency_ms")
    try:
        latenza = float(latenza) if latenza is not None else None
    except (TypeError, ValueError):
        latenza = None

    quando = result.get("executed_at") or utc_now_str()
    result_id = execute(
        "INSERT INTO check_results (tenant_id, check_id, probe_id, executed_at,"
        " status, latency_ms, detail, payload_json, received_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (tenant_id, check_id, probe_id, quando, stato, latenza,
         (result.get("detail") or "")[:1000], carico, utc_now_str()))

    # I dati raccolti non restano dentro una risposta di testo: diventano punti di
    # misura interrogabili nel tempo. Si conserva anche il carico non accorciato
    # dell'esito, se presente, perche' l'accorciamento serve alla lettura, non alla
    # misura.
    misure = store_metrics(tenant_id, check_id, result_id, quando,
                           result.get("payload"), latenza,
                           selection=_metric_selection(controllo))

    definizione = {
        "id": int(controllo["id"]),
        "name": controllo["name"],
        "severity": controllo["severity"],
        "escalation_email": _column(controllo, "escalation_email"),
    }
    soglia = max(1, int(controllo["failure_threshold"]))
    attivazione = max(soglia, int(_column(controllo, "escalation_threshold")
                                 or DEFAULT_ESCALATION_THRESHOLD))
    if stato == STATUS_OK:
        incidente = close_incident_automatically(tenant_id, definizione,
                                                 result.get("detail") or "risposta corretta")
        return {"stored": True, "status": stato, "incident": incidente,
                "metrics": misure,
                "action": "recovered" if incidente else None}

    # Si contano i fallimenti fino alla soglia piu' alta: fermarsi a quella di
    # apertura non permetterebbe di sapere quando attivare l'operatore.
    consecutivi = consecutive_failures(check_id, attivazione)
    if consecutivi < soglia:
        # Sotto la soglia non si apre nulla: un singolo fallimento su una rete
        # reale e' rumore, e un incidente per ogni singhiozzo non verrebbe letto.
        return {"stored": True, "status": stato, "incident": None,
                "action": "below_threshold", "failures": consecutivi,
                "metrics": misure, "threshold": soglia}

    incidente = open_incident(tenant_id, definizione,
                              result.get("detail") or "controllo fallito", consecutivi)

    # Oltre la seconda soglia si attiva un operatore, una volta sola per incidente.
    scalato = query("SELECT escalated_at FROM check_incidents WHERE id = ?",
                    (incidente,), one=True)
    recapito = None
    if consecutivi >= attivazione and (scalato is None or not scalato["escalated_at"]):
        recapito = escalate_incident(tenant_id, definizione, incidente, consecutivi,
                                     result.get("detail") or "controllo fallito")
        return {"stored": True, "status": stato, "incident": incidente,
                "action": "escalated", "failures": consecutivi, "metrics": misure,
                "threshold": soglia, "escalation_threshold": attivazione,
                "operator": recapito}

    return {"stored": True, "status": stato, "incident": incidente,
            "action": "incident", "failures": consecutivi, "metrics": misure,
            "threshold": soglia, "escalation_threshold": attivazione}


def _check_of_incident(tenant_id: int, incident_id: int) -> dict:
    """Definizione del controllo a cui appartiene un incidente.

    Serve alle azioni dell'operatore, che partono dall'incidente e non dal
    controllo: il recapito a cui notificare sta sul controllo.
    """
    riga = query(
        "SELECT c.id, c.name, c.severity, c.escalation_email FROM check_incidents i"
        " JOIN checks c ON c.id = i.check_id WHERE i.id = ? AND i.tenant_id = ?",
        (incident_id, tenant_id), one=True)
    return dict(riga) if riga is not None else {}


def acknowledge_incident(tenant_id: int, incident_id: int, user_id: int,
                         note: str = None) -> bool:
    """Presa in carico da parte di un operatore."""
    incidente = query("SELECT * FROM check_incidents WHERE id = ? AND tenant_id = ?",
                      (incident_id, tenant_id), one=True)
    if incidente is None or incidente["status"] != INCIDENT_OPEN:
        return False
    adesso = utc_now_str()
    execute("UPDATE check_incidents SET status = ?, acknowledged_at = ?,"
            " acknowledged_by = ?, updated_at = ? WHERE id = ?",
            (INCIDENT_ACK, adesso, user_id, adesso, incident_id))
    _incident_event(tenant_id, incident_id, "acknowledged", "operator", note)
    notify_workflow(tenant_id, "incident.acknowledged", incident_id,
                    _check_of_incident(tenant_id, incident_id), note or "")
    log_event("checks.incident.acknowledged",
              "Incidente %d preso in carico" % incident_id,
              tenant_id=tenant_id, severity="info", entity="check_incident",
              entity_id=incident_id)
    return True


def resolve_incident(tenant_id: int, incident_id: int, user_id: int,
                     resolution: str) -> bool:
    """Chiusura da parte di un operatore, con la motivazione."""
    incidente = query("SELECT * FROM check_incidents WHERE id = ? AND tenant_id = ?",
                      (incident_id, tenant_id), one=True)
    if incidente is None or incidente["status"] == INCIDENT_RESOLVED:
        return False
    adesso = utc_now_str()
    execute("UPDATE check_incidents SET status = ?, resolved_at = ?, resolved_by = ?,"
            " resolution = ?, updated_at = ? WHERE id = ?",
            (INCIDENT_RESOLVED, adesso, user_id, resolution or "chiuso dall'operatore",
             adesso, incident_id))
    _incident_event(tenant_id, incident_id, "resolved", "operator", resolution)
    notify_workflow(tenant_id, "incident.resolved", incident_id,
                    _check_of_incident(tenant_id, incident_id), resolution or "")
    log_event("checks.incident.resolved",
              "Incidente %d risolto: %s" % (incident_id, resolution or ""),
              tenant_id=tenant_id, severity="info", entity="check_incident",
              entity_id=incident_id)
    return True
