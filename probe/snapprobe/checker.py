"""
snap probe - Esecuzione dei controlli periodici definiti dal server.

Perche' li esegue la sonda
--------------------------
I bersagli stanno nella rete del cliente e il server non apre connessioni verso
l'interno (requisito R2). Le definizioni arrivano nella configurazione cifrata e
gli esiti tornano come record di conferimento: la sonda non decide nulla su cosa
verificare, e il server non tocca la rete del cliente.

Sui bersagli
------------
Un bersaglio di controllo NON e' soggetto al perimetro di scansione: non e' una
scoperta di rete, e' un indirizzo o un nome host che l'operatore ha dichiarato
espressamente sul server, e che arriva firmato dentro il canale cifrato. Il
perimetro serve a impedire che la sonda esplori cio' che nessuno le ha chiesto;
qui l'incarico e' esplicito.

Tre generi
----------
  presence  raggiungibilita', accertata con nmap in modalita' di sola scoperta
  ports     apertura di porte: TCP con una connessione, UDP con nmap
  http      richiesta a un endpoint, con verifiche sul contenuto JSON

Cosa significa "fallito"
------------------------
  ok     la verifica e' passata
  fail   il bersaglio ha risposto, ma non come atteso (porta chiusa, stato HTTP
         diverso, verifica sul JSON non soddisfatta): e' un disservizio
  error  non e' stato possibile eseguire il controllo (nome non risolto, nmap
         assente, errore di rete): e' un problema della verifica, non
         necessariamente del bersaglio

La distinzione conta: un incidente aperto su un errore della sonda manderebbe un
operatore a cercare un guasto dove non c'e'.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from .nmap_runner import NmapError, NmapRunner, NmapTimeout

STATUS_OK = "ok"
STATUS_FAIL = "fail"
STATUS_ERROR = "error"

# Tempo massimo di riserva quando la definizione non lo indica.
DEFAULT_TIMEOUT_SECONDS = 10
# La risposta si conserva accorciata: serve a capire cosa non torna.
MAX_PAYLOAD_CHARS = 4000
# Un controllo non deve poter scaricare una risposta senza fine.
MAX_RESPONSE_BYTES = 256 * 1024


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _resolve(address: str, timeout: int) -> tuple:
    """Risolve il bersaglio. Restituisce (indirizzo, errore)."""
    socket.setdefaulttimeout(timeout)
    try:
        return (socket.gethostbyname(address), None)
    except socket.gaierror as errore:
        return (None, "nome non risolto: %s" % errore)
    except OSError as errore:
        return (None, "risoluzione non riuscita: %s" % errore)


# --------------------------------------------------------------------------- #
# Presenza in rete
# --------------------------------------------------------------------------- #
def check_presence(definition: dict, runner: NmapRunner) -> dict:
    """Il bersaglio risponde in rete.

    Si usa nmap in sola scoperta invece di una connessione TCP: la presenza non
    deve dipendere dall'apertura di una porta particolare, e un apparato che
    risponde al ping con tutte le porte chiuse e' presente.
    """
    attesa = int(definition.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS)
    bersaglio = definition["address"]
    avvio = time.monotonic()
    try:
        xml = runner.run(["-sn", "-PE", "-PS443,80,22", "-T4", "--host-timeout",
                          "%ds" % attesa], [bersaglio],
                         timeout=attesa + 15, label="controllo presenza %s" % bersaglio)
    except NmapTimeout:
        return {"status": STATUS_FAIL, "detail": "nessuna risposta entro %d s" % attesa,
                "latency_ms": (time.monotonic() - avvio) * 1000}
    except NmapError as errore:
        return {"status": STATUS_ERROR, "detail": "controllo non eseguibile: %s" % errore}

    latenza = (time.monotonic() - avvio) * 1000
    # Non si interpreta l'XML con il lettore delle scansioni: qui interessa una
    # sola informazione, e cercarla direttamente evita di legare i controlli al
    # formato dell'inventario.
    vivo = 'state="up"' in xml
    # La raggiungibilita' come 0/1 e' la misura di questo controllo: in serie
    # diventa la disponibilita' del bersaglio nel tempo.
    carico = {"reachable": 1 if vivo else 0}
    if vivo:
        return {"status": STATUS_OK, "detail": "risponde in rete",
                "latency_ms": latenza, "payload": carico}
    return {"status": STATUS_FAIL, "detail": "non risponde in rete",
            "latency_ms": latenza, "payload": carico}


# --------------------------------------------------------------------------- #
# Porte
# --------------------------------------------------------------------------- #
def _check_tcp_port(address: str, port: int, timeout: int) -> tuple:
    """(aperta, dettaglio, millisecondi) per una porta TCP, con una connessione.

    Il tempo di connessione e' restituito come numero e non sepolto nella frase:
    e' una misura, e come tale va messo in serie.
    """
    avvio = time.monotonic()
    try:
        with socket.create_connection((address, port), timeout=timeout):
            trascorso = (time.monotonic() - avvio) * 1000
            return (True, "aperta in %.0f ms" % trascorso, trascorso)
    except socket.timeout:
        return (False, "nessuna risposta entro %d s" % timeout, None)
    except ConnectionRefusedError:
        return (False, "connessione rifiutata", (time.monotonic() - avvio) * 1000)
    except OSError as errore:
        return (False, "non raggiungibile: %s" % errore, None)


def _check_udp_ports(address: str, porte: list, timeout: int,
                     runner: NmapRunner) -> dict:
    """Porte UDP con nmap: una connessione non prova nulla su UDP."""
    elenco = ",".join(str(p["port"]) for p in porte)
    try:
        xml = runner.run(["-sU", "-Pn", "-T4", "-p", elenco, "--host-timeout",
                          "%ds" % max(timeout, 15)], [address],
                         timeout=max(timeout, 15) + 20,
                         label="controllo porte UDP %s" % address)
    except NmapTimeout:
        return {p["port"]: (False, "nessuna risposta entro %d s" % timeout) for p in porte}
    except NmapError as errore:
        return {p["port"]: (None, "non verificabile: %s" % errore) for p in porte}

    esiti = {}
    for porta in porte:
        # L'XML dichiara lo stato accanto al numero di porta: si cerca la coppia.
        marcatore = 'portid="%d"' % porta["port"]
        posizione = xml.find(marcatore)
        if posizione < 0:
            esiti[porta["port"]] = (False, "nessuno stato restituito")
            continue
        frammento = xml[posizione:posizione + 300]
        aperta = 'state="open"' in frammento
        esiti[porta["port"]] = (aperta, "aperta" if aperta else "non aperta")
    return esiti


def check_ports(definition: dict, runner: NmapRunner) -> dict:
    """Tutte le porte dichiarate devono risultare aperte.

    Il controllo e' sull'insieme: se una sola non risponde, il servizio non e'
    quello che l'operatore ha dichiarato di volere.
    """
    configurazione = definition.get("config") or {}
    porte = configurazione.get("ports") or []
    if not porte:
        return {"status": STATUS_ERROR, "detail": "definizione senza porte"}

    attesa = int(definition.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS)
    indirizzo, errore = _resolve(definition["address"], attesa)
    if indirizzo is None:
        return {"status": STATUS_ERROR, "detail": errore}

    avvio = time.monotonic()
    chiuse = []
    non_verificabili = []
    # Le misure sono indicizzate per PORTA, non per posizione nell'elenco: una serie
    # indicizzata per posizione cambierebbe significato appena si aggiunge o si
    # toglie una porta dalla definizione.
    aperture = {}
    tempi = {}
    dettagli = {}
    aperte = 0

    udp = [p for p in porte if p.get("protocol") == "udp"]
    esiti_udp = _check_udp_ports(indirizzo, udp, attesa, runner) if udp else {}

    for porta in porte:
        numero = int(porta["port"])
        protocollo = porta.get("protocol", "tcp")
        chiave = "%s/%d" % (protocollo, numero)
        millisecondi = None
        if protocollo == "udp":
            aperta, dettaglio = esiti_udp.get(numero, (None, "non verificata"))
        else:
            aperta, dettaglio, millisecondi = _check_tcp_port(indirizzo, numero, attesa)

        dettagli[chiave] = dettaglio
        if aperta is None:
            non_verificabili.append(chiave)
            continue
        aperture[chiave] = 1 if aperta else 0
        if millisecondi is not None:
            tempi[chiave] = round(millisecondi, 2)
        if aperta:
            aperte += 1
        else:
            chiuse.append("%s (%s)" % (chiave, dettaglio))

    latenza = (time.monotonic() - avvio) * 1000
    carico = {
        # Misure: apertura per porta (0/1), tempo di connessione per porta, e la
        # sintesi del controllo nel suo insieme.
        "port": aperture,
        "port_latency_ms": tempi,
        "ports_open": aperte,
        "ports_total": len(porte),
        "all_open": 1 if aperte == len(porte) else 0,
        "resolved": indirizzo,
        # Sotto `_` sta cio' che serve alla lettura e non e' una misura.
        "_detail": dettagli,
    }
    if non_verificabili and not chiuse:
        return {"status": STATUS_ERROR, "latency_ms": latenza, "payload": carico,
                "detail": "porte non verificabili: %s" % ", ".join(non_verificabili)}
    if chiuse:
        return {"status": STATUS_FAIL, "latency_ms": latenza, "payload": carico,
                "detail": "non aperte: %s" % "; ".join(chiuse)}
    return {"status": STATUS_OK, "latency_ms": latenza, "payload": carico,
            "detail": "tutte le %d porte risultano aperte" % len(porte)}


# --------------------------------------------------------------------------- #
# Endpoint HTTP
# --------------------------------------------------------------------------- #
def extract(documento, path: str):
    """Valore in un documento JSON dato un percorso con i punti.

    Restituisce la coppia (trovato, valore): distinguere "assente" da "nullo"
    serve agli operatori `exists` e `absent`.
    """
    corrente = documento
    for pezzo in (path or "").split("."):
        if not pezzo:
            continue
        if isinstance(corrente, dict) and pezzo in corrente:
            corrente = corrente[pezzo]
            continue
        if isinstance(corrente, list):
            try:
                corrente = corrente[int(pezzo)]
                continue
            except (ValueError, IndexError):
                return (False, None)
        return (False, None)
    return (True, corrente)


def _confronto_numerico(valore, atteso) -> tuple:
    """(confrontabile, valore, atteso) come numeri."""
    try:
        return (True, float(valore), float(atteso))
    except (TypeError, ValueError):
        return (False, None, None)


def evaluate_assertion(documento, assertion: dict) -> tuple:
    """(soddisfatta, descrizione) per una verifica sul contenuto."""
    percorso = assertion.get("path") or ""
    operatore = (assertion.get("op") or "eq").lower()
    atteso = assertion.get("value")
    trovato, valore = extract(documento, percorso)

    if operatore == "exists":
        return (trovato, "%s %s" % (percorso, "presente" if trovato else "assente"))
    if operatore == "absent":
        return (not trovato, "%s %s" % (percorso, "assente" if not trovato else "presente"))
    if not trovato:
        return (False, "%s assente nella risposta" % percorso)

    if operatore == "eq":
        esito = str(valore) == str(atteso)
        return (esito, "%s = %r (atteso %r)" % (percorso, valore, atteso))
    if operatore == "ne":
        esito = str(valore) != str(atteso)
        return (esito, "%s = %r (atteso diverso da %r)" % (percorso, valore, atteso))
    if operatore == "contains":
        esito = str(atteso) in str(valore)
        return (esito, "%s = %r (atteso contenente %r)" % (percorso, valore, atteso))
    if operatore in ("gt", "lt"):
        confrontabile, numero, riferimento = _confronto_numerico(valore, atteso)
        if not confrontabile:
            return (False, "%s = %r non e' confrontabile con %r come numero"
                    % (percorso, valore, atteso))
        esito = numero > riferimento if operatore == "gt" else numero < riferimento
        return (esito, "%s = %s (atteso %s %s)"
                % (percorso, numero, "maggiore di" if operatore == "gt" else "minore di",
                   riferimento))
    return (False, "operatore %r non previsto" % operatore)


def check_http(definition: dict, runner: NmapRunner = None) -> dict:
    """Richiesta all'endpoint, con verifiche sul contenuto JSON."""
    configurazione = definition.get("config") or {}
    url = configurazione.get("url")
    if not url:
        return {"status": STATUS_ERROR, "detail": "definizione senza URL"}
    attesa = int(definition.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS)
    atteso = int(configurazione.get("expect_status") or 200)
    metodo = (configurazione.get("method") or "GET").upper()

    richiesta = urllib.request.Request(url, method=metodo)
    richiesta.add_header("User-Agent", "snap-probe/controlli")
    avvio = time.monotonic()
    corpo = b""
    try:
        with urllib.request.urlopen(richiesta, timeout=attesa) as risposta:
            codice = risposta.status
            corpo = risposta.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as errore:
        # Una risposta di errore E' una risposta: il codice va confrontato con
        # quello atteso, non trattato come impossibilita' di eseguire il controllo.
        codice = errore.code
        try:
            corpo = errore.read(MAX_RESPONSE_BYTES)
        except OSError:
            corpo = b""
    except urllib.error.URLError as errore:
        return {"status": STATUS_FAIL, "detail": "endpoint non raggiungibile: %s"
                % errore.reason, "latency_ms": (time.monotonic() - avvio) * 1000}
    except (OSError, ValueError) as errore:
        return {"status": STATUS_ERROR, "detail": "richiesta non eseguibile: %s" % errore}

    latenza = (time.monotonic() - avvio) * 1000
    testo = corpo.decode("utf-8", errors="replace")
    carico = testo[:MAX_PAYLOAD_CHARS]

    if codice != atteso:
        return {"status": STATUS_FAIL, "latency_ms": latenza, "payload": carico,
                "detail": "stato %d, atteso %d" % (codice, atteso)}

    verifiche = configurazione.get("assertions") or []
    if not verifiche:
        return {"status": STATUS_OK, "latency_ms": latenza, "payload": carico,
                "detail": "stato %d come atteso" % codice}

    try:
        documento = json.loads(testo) if testo.strip() else None
    except ValueError as errore:
        return {"status": STATUS_FAIL, "latency_ms": latenza, "payload": carico,
                "detail": "la risposta non e' JSON valido: %s" % errore}

    fallite = []
    passate = []
    for verifica in verifiche:
        soddisfatta, descrizione = evaluate_assertion(documento, verifica)
        (passate if soddisfatta else fallite).append(descrizione)
    if fallite:
        return {"status": STATUS_FAIL, "latency_ms": latenza, "payload": carico,
                "detail": "verifiche non soddisfatte: %s" % "; ".join(fallite)}
    return {"status": STATUS_OK, "latency_ms": latenza, "payload": carico,
            "detail": "stato %d e %d verifiche soddisfatte" % (codice, len(passate))}


EXECUTORS = {
    "presence": check_presence,
    "ports": check_ports,
    "http": check_http,
}


class CheckRunner:
    """Esegue i controlli scaduti e produce i record da conferire."""

    def __init__(self, store, runner: NmapRunner = None):
        self.store = store
        self.runner = runner or NmapRunner()

    def definitions(self) -> list:
        return self.store.get_json("checks", []) or []

    def due(self) -> list:
        """Controlli la cui cadenza e' scaduta."""
        scaduti = []
        for definizione in self.definitions():
            identificativo = definizione.get("id")
            if identificativo is None:
                continue
            cadenza = int(definizione.get("interval_seconds") or 300)
            ultimo = self.store.check_last_run(int(identificativo))
            if ultimo is None:
                scaduti.append(definizione)
                continue
            try:
                momento = datetime.strptime(ultimo, "%Y-%m-%d %H:%M:%S").replace(
                    tzinfo=timezone.utc)
            except (TypeError, ValueError):
                # Istante illeggibile: si riesegue, non si indovina.
                scaduti.append(definizione)
                continue
            if (datetime.now(timezone.utc) - momento).total_seconds() >= cadenza:
                scaduti.append(definizione)
        return scaduti

    def execute(self, definition: dict) -> dict:
        """Esegue un controllo e restituisce il record da conferire."""
        genere = definition.get("kind")
        esecutore = EXECUTORS.get(genere)
        avvio = _now_str()
        if esecutore is None:
            esito = {"status": STATUS_ERROR,
                     "detail": "genere di controllo %r non eseguibile da questa sonda"
                               % genere}
        else:
            try:
                esito = esecutore(definition, self.runner)
            except Exception as errore:  # nessun controllo deve fermare gli altri
                self.store.log("error", "Controllo %s (%s) interrotto da un errore: %s"
                               % (definition.get("id"), definition.get("name"), errore))
                esito = {"status": STATUS_ERROR, "detail": "errore imprevisto: %s" % errore}

        record = {
            "check_id": int(definition["id"]),
            "executed_at": avvio,
            "status": esito.get("status") or STATUS_ERROR,
            "detail": esito.get("detail") or "",
            "latency_ms": esito.get("latency_ms"),
            "payload": esito.get("payload"),
        }
        self.store.record_check_run(int(definition["id"]), record["status"],
                                    record["detail"])
        return record

    def run_due(self) -> list:
        """Esegue i controlli scaduti. Restituisce i record prodotti."""
        record = []
        scaduti = self.due()
        for definizione in scaduti:
            record.append(self.execute(definizione))
        if record:
            falliti = sum(1 for r in record if r["status"] != STATUS_OK)
            self.store.log(
                "info" if not falliti else "warning",
                "Controlli eseguiti: %d, di cui %d non superati" % (len(record), falliti))
        return record

    def status(self) -> dict:
        """Stato dei controlli, per l'interfaccia locale della sonda."""
        definizioni = self.definitions()
        stati = []
        for definizione in definizioni:
            ultimo = self.store.check_state(int(definizione.get("id") or 0))
            stati.append({
                "id": definizione.get("id"),
                "name": definizione.get("name"),
                "kind": definizione.get("kind"),
                "address": definizione.get("address"),
                "interval_seconds": definizione.get("interval_seconds"),
                "last_run_at": (ultimo or {}).get("last_run_at"),
                "last_status": (ultimo or {}).get("last_status"),
                "last_detail": (ultimo or {}).get("last_detail"),
            })
        return {
            "total": len(definizioni),
            "due": len(self.due()),
            "checks": stati,
        }
