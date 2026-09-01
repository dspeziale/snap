"""
snap server - Applicazione dei conferimenti (upload) provenienti dalle sonde.

Il payload di un conferimento e' un lotto (batch) autoconsistente prodotto dalla
sonda in modalita' autonoma. L'applicazione e' idempotente: un lotto gia'
acquisito viene riconosciuto tramite batch_uid e riconfermato senza duplicare i
dati, cosi' che la sonda possa svuotare la propria coda in sicurezza anche in
caso di ritrasmissione.

Tipi di record accettati, applicati nell'ordine di dichiarazione di
`_APPLICATORI` perche' l'ordine conta: i nodi devono esistere prima delle porte
che li riguardano.

  nodes      un nodo scoperto (indirizzo, MAC, nome host, raggiungibilita')
  ports      porte e servizi osservati su un nodo
  os         sistema operativo rilevato
  scripts    esiti degli script NSE, conservati come prove
  snmp       letture SNMP complete: testo degli script e riassunto
  web        letture delle interfacce web: cio' che la pagina dichiara di se'
  monitor    campioni di raggiungibilita' e latenza
  scan_runs  telemetria delle fasi di scansione
  events     annotazioni della sonda, che confluiscono nell'audit del tenant

La sonda invia PROVE, non verdetti: il tipo di dispositivo e' determinato qui
(`fingerprint.identify`) e conservato insieme alle prove che lo motivano, cosi'
da poter essere rideterminato quando il catalogo delle firme cambia.

Ogni scostamento fra lo stato precedente e quello nuovo genera una voce in
`node_changes`: e' l'unico punto del prodotto in cui la deriva viene scritta.

Cronologia. L'istante dichiarato dalla sonda viene conservato, non sostituito con
l'ora di ricezione: dopo un periodo di isolamento la sonda conferisce dati
raccolti in momenti diversi, e appiattirli sull'ora del rientro distruggerebbe la
storia di cio' che e' accaduto durante l'assenza del server.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json

from flask import current_app

from . import fingerprint
from .audit import log_event
from .db import execute, parse_utc, query, utc_now_str, utc_str

VALID_SEVERITIES = {"info", "warning", "critical"}
VALID_PROTOCOLS = {"tcp", "udp", "sctp"}
# Stati che testimoniano una risposta dell'host: anche una porta chiusa e' una
# risposta. Sono gli stessi che la sonda usa per ammettere un nodo.
PROBING_STATES = {"open", "closed", "filtered", "unfiltered"}
# Oltre questa dimensione il lotto viene conservato in estratto: la consultazione
# di "quello che la sonda ha inviato" non deve fare crescere il database senza
# limite.
MAX_STORED_RECORDS_BYTES = 256 * 1024

# Riconoscimento delle porte iniettate dalla rete.
#
# Un apparato intermedio (tipicamente un ALG SIP/H.323 o un proxy trasparente)
# puo' rispondere su alcune porte per OGNI indirizzo interrogato: quelle porte
# non appartengono ai nodi e falsano l'identificazione. Rilevato sul campo:
# tcp/2000 e tcp/5060 risultavano aperte sul 100% dei nodi, senza prodotto
# riconosciuto, su tre famiglie di sistema operativo diverse, e portavano a
# classificare come telefono VoIP trenta dispositivi su trentadue.
#
# Il criterio distintivo non e' la sola diffusione -- in una flotta omogenea
# porte come 445 sono legittimamente presenti quasi ovunque -- ma la diffusione
# unita all'ETEROGENEITA' dei sistemi operativi: una porta aperta quasi su tutto,
# su famiglie diverse, non e' un servizio dei nodi. Una porta per cui nmap ha
# riconosciuto un prodotto almeno una volta e' invece un servizio reale.
#
# Limite dichiarato: un servizio genuinamente presente su quasi tutti i nodi di
# una flotta eterogenea, e mai identificato per prodotto, viene marcato come
# iniettato. La marcatura resta visibile nella console con la propria
# motivazione proprio perche' l'operatore possa accorgersene.
SUSPECT_MIN_NODES = 8
SUSPECT_MIN_PREVALENCE = 0.95
SUSPECT_MIN_OS_FAMILIES = 3


class IngestError(Exception):
    """Payload non conforme al contratto di conferimento."""


# --------------------------------------------------------------------------- #
# Utilita' di normalizzazione
# --------------------------------------------------------------------------- #
def _clean(value, default: str = "", maximum: int = 512) -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text[:maximum] if text else default


def _integer(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _real(value, default=None):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _timestamp(value, fallback: str) -> str:
    """Normalizza un istante fornito dalla sonda; ricade sull'istante indicato.

    La ricaduta e' l'ora di ricezione soltanto quando l'istante dichiarato non e'
    interpretabile: un istante valido viene sempre conservato.
    """
    moment = parse_utc(value)
    return utc_str(moment) if moment else fallback


def _json_or_empty(value) -> dict:
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        letto = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return letto if isinstance(letto, dict) else {}


# --------------------------------------------------------------------------- #
# Deriva
# --------------------------------------------------------------------------- #
def _record_change(ctx, node_id, kind, subject=None, before=None, after=None, severity="info"):
    """Registra uno scostamento e aggiorna l'istante di ultimo cambiamento."""
    execute(
        "INSERT INTO node_changes (tenant_id, node_id, kind, subject, before_value,"
        " after_value, severity, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (ctx["tenant_id"], node_id, kind, _clean(subject, maximum=120),
         _clean(before, maximum=240), _clean(after, maximum=240), severity, ctx["now"]),
    )
    if node_id is not None:
        execute("UPDATE nodes SET last_change_at = ? WHERE id = ? AND tenant_id = ?",
                (ctx["now"], node_id, ctx["tenant_id"]))
    ctx["changes"] += 1


# --------------------------------------------------------------------------- #
# Applicatori
# --------------------------------------------------------------------------- #
def _node_by_ip(tenant_id: int, ip: str):
    return query("SELECT * FROM nodes WHERE tenant_id = ? AND ip = ?", (tenant_id, ip), one=True)


def _apply_node(ctx, record: dict) -> None:
    """Crea o aggiorna un nodo dell'inventario."""
    ip = _clean(record.get("ip"), maximum=64)
    if not ip:
        raise IngestError("record di tipo nodes senza indirizzo")

    from .subnets import subnet_of_address

    visto = _timestamp(record.get("seen_at"), ctx["now"])
    raggiungibile = bool(record.get("reachable", True))
    stato = "up" if raggiungibile else "down"
    hostname = _clean(record.get("hostname"), maximum=190) or None
    mac = _clean(record.get("mac"), maximum=32) or None
    vendor = _clean(record.get("mac_vendor"), maximum=190) or None
    latenza = _real(record.get("latency_ms"))
    ttl = _intero(record.get("ttl"))
    subnet_id = subnet_of_address(ctx["tenant_id"], ip)

    esistente = _node_by_ip(ctx["tenant_id"], ip)
    if esistente is None:
        node_id = execute(
            "INSERT INTO nodes (tenant_id, subnet_id, probe_id, ip, mac, mac_vendor, hostname,"
            " status, latency_ms, ttl, first_seen_at, last_seen_at, last_scan_at,"
            " created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ctx["tenant_id"], subnet_id, ctx["probe_id"], ip, mac, vendor, hostname,
             stato, latenza, ttl, visto, visto, visto, ctx["now"], ctx["now"]),
        )
        _record_change(ctx, node_id, "node.appeared", subject=ip, after=stato,
                       severity="warning")
        ctx["touched"].add(node_id)
        return

    node_id = int(esistente["id"])
    ctx["touched"].add(node_id)

    if esistente["status"] != stato:
        _record_change(ctx, node_id, "node.up" if raggiungibile else "node.down",
                       subject=ip, before=esistente["status"], after=stato,
                       severity="info" if raggiungibile else "warning")
    if hostname and esistente["hostname"] and hostname != esistente["hostname"]:
        _record_change(ctx, node_id, "hostname.changed", subject=ip,
                       before=esistente["hostname"], after=hostname)
    if mac and esistente["mac"] and mac.lower() != str(esistente["mac"]).lower():
        # Un indirizzo che cambia MAC merita attenzione: puo' essere una
        # riassegnazione DHCP oppure un dispositivo sostituito.
        _record_change(ctx, node_id, "mac.changed", subject=ip,
                       before=esistente["mac"], after=mac, severity="warning")

    execute(
        "UPDATE nodes SET subnet_id = COALESCE(?, subnet_id), probe_id = ?,"
        " mac = COALESCE(?, mac), mac_vendor = COALESCE(?, mac_vendor),"
        " hostname = COALESCE(?, hostname), status = ?, latency_ms = COALESCE(?, latency_ms),"
        " ttl = COALESCE(?, ttl),"
        " last_seen_at = MAX(last_seen_at, ?), last_scan_at = ?, updated_at = ?"
        " WHERE id = ? AND tenant_id = ?",
        (subnet_id, ctx["probe_id"], mac, vendor, hostname, stato, latenza, ttl,
         visto, visto, ctx["now"], node_id, ctx["tenant_id"]),
    )


def _apply_port(ctx, record: dict) -> None:
    """Registra una porta osservata su un nodo."""
    ip = _clean(record.get("ip"), maximum=64)
    nodo = _node_by_ip(ctx["tenant_id"], ip) if ip else None
    if nodo is None:
        # Il nodo non e' (ancora) in inventario: il record e' orfano. Non si crea
        # un nodo implicito, che aggirerebbe la regola di ammissione, e non si
        # rifiuta il lotto, che diventerebbe intrasmissibile quando viene
        # spezzato: si salta il record contandolo.
        ctx["orphans"].append("ports:" + (ip or "?"))
        return

    protocollo = _clean(record.get("protocol"), "tcp", 8).lower()
    if protocollo not in VALID_PROTOCOLS:
        raise IngestError("protocollo non ammesso: %s" % protocollo)
    numero = _integer(record.get("port"))
    if numero is None or not 0 < numero <= 65535:
        raise IngestError("porta non valida: %s" % record.get("port"))

    node_id = int(nodo["id"])
    ctx["touched"].add(node_id)
    stato = _clean(record.get("state"), "open", 24)
    visto = _timestamp(record.get("seen_at"), ctx["now"])
    servizio = _clean(record.get("service_name"), maximum=64) or None
    prodotto = _clean(record.get("product"), maximum=190) or None
    versione = _clean(record.get("version"), maximum=64) or None
    cpe = record.get("cpe")
    cpe_testo = ",".join(str(c) for c in cpe)[:400] if isinstance(cpe, (list, tuple)) else _clean(cpe, maximum=400) or None
    # Testo grezzo annunciato dal servizio: si conserva accorciato, perche' una
    # impronta di servizio non riconosciuta puo' essere molto lunga.
    banner = _clean(record.get("banner"), maximum=600) or None

    if stato == "open":
        ctx["seen_ports"].setdefault(node_id, set()).add((protocollo, numero))

    esistente = query(
        "SELECT * FROM node_ports WHERE node_id = ? AND protocol = ? AND port = ?",
        (node_id, protocollo, numero), one=True,
    )
    if esistente is None:
        execute(
            "INSERT INTO node_ports (tenant_id, node_id, protocol, port, state, service_name,"
            " product, version, extrainfo, cpe, method, confidence, banner,"
            " first_seen_at, last_seen_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ctx["tenant_id"], node_id, protocollo, numero, stato, servizio, prodotto,
             versione, _clean(record.get("extrainfo"), maximum=190) or None, cpe_testo,
             _clean(record.get("method"), maximum=24) or None,
             _integer(record.get("confidence")), banner, visto, visto),
        )
        if stato == "open":
            _record_change(ctx, node_id, "port.opened",
                           subject="%s/%d" % (protocollo, numero), after=servizio or "aperta",
                           severity="warning")
        return

    if stato == "open" and esistente["state"] != "open":
        _record_change(ctx, node_id, "port.opened", subject="%s/%d" % (protocollo, numero),
                       before=esistente["state"], after="open", severity="warning")
    precedente = "%s %s" % (esistente["product"] or "", esistente["version"] or "")
    attuale = "%s %s" % (prodotto or "", versione or "")
    if attuale.strip() and precedente.strip() and attuale.strip() != precedente.strip():
        _record_change(ctx, node_id, "service.changed",
                       subject="%s/%d" % (protocollo, numero),
                       before=precedente.strip(), after=attuale.strip())
    elif banner and esistente["banner"] and banner != esistente["banner"]:
        # Un banner che cambia segnala un aggiornamento o una sostituzione del
        # servizio anche quando nome e prodotto restano identici.
        _record_change(ctx, node_id, "service.changed",
                       subject="%s/%d" % (protocollo, numero),
                       before=esistente["banner"], after=banner)
    elif servizio and esistente["service_name"] and servizio != esistente["service_name"]:
        _record_change(ctx, node_id, "service.changed",
                       subject="%s/%d" % (protocollo, numero),
                       before=esistente["service_name"], after=servizio)

    execute(
        "UPDATE node_ports SET state = ?, service_name = COALESCE(?, service_name),"
        " product = COALESCE(?, product), version = COALESCE(?, version),"
        " cpe = COALESCE(?, cpe), method = COALESCE(?, method),"
        " confidence = COALESCE(?, confidence), banner = COALESCE(?, banner),"
        " last_seen_at = ?,"
        " closed_at = CASE WHEN ? = 'open' THEN NULL ELSE closed_at END"
        " WHERE id = ?",
        (stato, servizio, prodotto, versione, cpe_testo,
         _clean(record.get("method"), maximum=24) or None,
         _integer(record.get("confidence")), banner, visto, stato, int(esistente["id"])),
    )


def _apply_os(ctx, record: dict) -> None:
    """Registra il sistema operativo rilevato su un nodo."""
    ip = _clean(record.get("ip"), maximum=64)
    nodo = _node_by_ip(ctx["tenant_id"], ip) if ip else None
    if nodo is None:
        # Il nodo non e' (ancora) in inventario: il record e' orfano. Non si crea
        # un nodo implicito, che aggirerebbe la regola di ammissione, e non si
        # rifiuta il lotto, che diventerebbe intrasmissibile quando viene
        # spezzato: si salta il record contandolo.
        ctx["orphans"].append("os:" + (ip or "?"))
        return

    node_id = int(nodo["id"])
    ctx["touched"].add(node_id)
    nome = _clean(record.get("name"), maximum=190) or None
    if nome and nodo["os_name"] and nome != nodo["os_name"]:
        _record_change(ctx, node_id, "os.changed", subject=ip,
                       before=nodo["os_name"], after=nome, severity="warning")

    execute(
        "UPDATE nodes SET os_name = COALESCE(?, os_name), os_family = COALESCE(?, os_family),"
        " os_vendor = COALESCE(?, os_vendor), os_gen = COALESCE(?, os_gen),"
        " os_type = COALESCE(?, os_type), os_accuracy = COALESCE(?, os_accuracy),"
        " last_scan_at = ?, updated_at = ? WHERE id = ? AND tenant_id = ?",
        (nome, _clean(record.get("family"), maximum=64) or None,
         _clean(record.get("vendor"), maximum=64) or None,
         _clean(record.get("gen"), maximum=32) or None,
         _clean(record.get("type"), maximum=48) or None,
         _integer(record.get("accuracy")), ctx["now"], ctx["now"], node_id, ctx["tenant_id"]),
    )


def _apply_script(ctx, record: dict) -> None:
    """Conserva l'esito di uno script NSE fra le prove del nodo."""
    ip = _clean(record.get("ip"), maximum=64)
    nodo = _node_by_ip(ctx["tenant_id"], ip) if ip else None
    if nodo is None:
        # Il nodo non e' (ancora) in inventario: il record e' orfano. Non si crea
        # un nodo implicito, che aggirerebbe la regola di ammissione, e non si
        # rifiuta il lotto, che diventerebbe intrasmissibile quando viene
        # spezzato: si salta il record contandolo.
        ctx["orphans"].append("scripts:" + (ip or "?"))
        return

    nome = _clean(record.get("name"), maximum=64)
    if not nome:
        raise IngestError("record di tipo scripts senza nome")

    node_id = int(nodo["id"])
    ctx["touched"].add(node_id)
    conservato = _json_or_empty(nodo["fingerprint_json"])
    prove = conservato.setdefault("evidence", {})
    script = prove.setdefault("scripts", {})
    script[nome] = _clean(record.get("output"), maximum=2000)
    execute("UPDATE nodes SET fingerprint_json = ?, updated_at = ? WHERE id = ? AND tenant_id = ?",
            (json.dumps(conservato, ensure_ascii=False), ctx["now"], node_id, ctx["tenant_id"]))


def _apply_monitor(ctx, record: dict) -> None:
    """Registra un campione di raggiungibilita' e aggiorna lo stato del nodo."""
    ip = _clean(record.get("ip"), maximum=64)
    nodo = _node_by_ip(ctx["tenant_id"], ip) if ip else None
    if nodo is None:
        # Il nodo non e' (ancora) in inventario: il record e' orfano. Non si crea
        # un nodo implicito, che aggirerebbe la regola di ammissione, e non si
        # rifiuta il lotto, che diventerebbe intrasmissibile quando viene
        # spezzato: si salta il record contandolo.
        ctx["orphans"].append("monitor:" + (ip or "?"))
        return

    node_id = int(nodo["id"])
    raggiungibile = bool(record.get("reachable"))
    quando = _timestamp(record.get("checked_at"), ctx["now"])
    latenza = _real(record.get("latency_ms"))

    execute(
        "INSERT INTO monitor_samples (tenant_id, node_id, checked_at, reachable, latency_ms)"
        " VALUES (?, ?, ?, ?, ?)",
        (ctx["tenant_id"], node_id, quando, 1 if raggiungibile else 0, latenza),
    )

    stato = "up" if raggiungibile else "down"
    if nodo["status"] != stato:
        _record_change(ctx, node_id, "node.up" if raggiungibile else "node.down",
                       subject=ip, before=nodo["status"], after=stato,
                       severity="info" if raggiungibile else "warning")
    execute(
        "UPDATE nodes SET status = ?, latency_ms = COALESCE(?, latency_ms),"
        " last_seen_at = CASE WHEN ? = 1 THEN MAX(last_seen_at, ?) ELSE last_seen_at END,"
        " updated_at = ? WHERE id = ? AND tenant_id = ?",
        (stato, latenza, 1 if raggiungibile else 0, quando, ctx["now"], node_id,
         ctx["tenant_id"]),
    )


def _apply_scan_run(ctx, record: dict) -> None:
    """Registra la telemetria di una fase di scansione."""
    fase = _clean(record.get("stage"), maximum=32)
    if not fase:
        raise IngestError("record di tipo scan_runs senza fase")
    bersaglio = _clean(record.get("target"), maximum=190)
    inizio = _timestamp(record.get("started_at"), ctx["now"])
    fine = _timestamp(record.get("finished_at"), ctx["now"])

    execute(
        "INSERT INTO scan_runs (tenant_id, probe_id, batch_id, stage, target, status,"
        " started_at, finished_at, duration_ms, hosts_total, hosts_up, records,"
        " nmap_args, nmap_version, detail, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (ctx["tenant_id"], ctx["probe_id"], ctx.get("batch_id"), fase, bersaglio,
         _clean(record.get("status"), "completed", 24), inizio, fine,
         _integer(record.get("duration_ms")), _integer(record.get("hosts_total"), 0) or 0,
         _integer(record.get("hosts_up"), 0) or 0, _integer(record.get("records"), 0) or 0,
         _clean(record.get("nmap_args"), maximum=400) or None,
         _clean(record.get("nmap_version"), maximum=32) or None,
         _clean(record.get("detail"), maximum=400) or None, ctx["now"]),
    )

    # Una scoperta completata su una subnet dichiara implicitamente che i nodi di
    # quella subnet non visti in questa passata non hanno risposto.
    if fase == "discovery" and _clean(record.get("status"), "completed", 24) == "completed":
        ctx["discovery_targets"].append({"target": bersaglio, "started_at": inizio})


def node_has_information(tenant_id: int, node_id: int) -> tuple:
    """Verifica se il server ha informazioni proprie su un nodo.

    Restituisce (ha_informazioni, elenco delle informazioni trovate). Porte
    chiuse o filtrate non contano: provano che qualcosa ha risposto, non dicono
    nulla sul dispositivo.
    """
    nodo = query("SELECT * FROM nodes WHERE id = ? AND tenant_id = ?",
                 (node_id, tenant_id), one=True)
    if nodo is None:
        return (False, [])

    trovate = []
    if nodo["hostname"]:
        trovate.append("nome host")
    if nodo["mac"]:
        trovate.append("indirizzo MAC")
    if nodo["os_name"]:
        trovate.append("sistema operativo")
    if nodo["device_type"] and nodo["device_type"] != "unknown":
        trovate.append("tipo di dispositivo")
    if nodo["notes"] or int(nodo["is_managed"] or 0):
        # Annotato o marcato come gestito da una persona: non si cancella.
        trovate.append("annotazione dell'operatore")

    aperte = query(
        "SELECT protocol, port, banner FROM node_ports"
        " WHERE node_id = ? AND state = 'open' AND COALESCE(is_suspect, 0) = 0", (node_id,))
    if aperte:
        trovate.append("%d porte aperte" % len(aperte))
    elif any(p["banner"] for p in query(
            "SELECT banner FROM node_ports WHERE node_id = ?", (node_id,))):
        trovate.append("banner di servizio")

    return (bool(trovate), trovate)


def _apply_removal(ctx, record: dict) -> None:
    """Rimuove dall'inventario un nodo che la sonda dichiara privo di informazioni.

    La rimozione e' verificata: se il server ha dati propri sul nodo, viene
    rifiutata e dichiarata invece di cancellare informazioni esistenti.
    """
    ip = _clean(record.get("ip"), maximum=64)
    if not ip:
        raise IngestError("record di tipo removals senza indirizzo")

    nodo = _node_by_ip(ctx["tenant_id"], ip)
    if nodo is None:
        # Nulla da rimuovere: la sonda e il server possono essere in stati
        # diversi, e non e' una condizione di errore.
        ctx["removals_skipped"].append(ip)
        return

    node_id = int(nodo["id"])
    ha_dati, informazioni = node_has_information(ctx["tenant_id"], node_id)
    if ha_dati:
        ctx["removals_refused"].append("%s (%s)" % (ip, ", ".join(informazioni)))
        log_event(
            "node.removal.refused",
            "Rimozione del nodo %s rifiutata: il server ha informazioni proprie (%s)"
            % (ip, ", ".join(informazioni)),
            tenant_id=ctx["tenant_id"], severity="warning",
            entity="node", entity_id=node_id,
            actor="probe:%d" % ctx["probe_id"],
        )
        return

    motivo = _clean(record.get("reason"), maximum=400) or "nessuna informazione rilevata"
    execute("DELETE FROM nodes WHERE id = ? AND tenant_id = ?", (node_id, ctx["tenant_id"]))
    # La traccia sopravvive alla cancellazione: la deriva viene scritta senza
    # riferimento al nodo, che non esiste piu'.
    execute(
        "INSERT INTO node_changes (tenant_id, node_id, kind, subject, before_value,"
        " after_value, severity, created_at) VALUES (?, NULL, 'node.removed', ?, ?, ?, ?, ?)",
        (ctx["tenant_id"], ip, "in inventario", "rimosso", "warning", ctx["now"]),
    )
    ctx["changes"] += 1
    ctx["removals_applied"].append(ip)
    ctx["touched"].discard(node_id)
    log_event(
        "node.removed",
        "Nodo %s rimosso dall'inventario: %s" % (ip, motivo),
        tenant_id=ctx["tenant_id"], severity="info",
        entity="node", entity_id=node_id,
        actor="probe:%d" % ctx["probe_id"],
        created_at=_timestamp(record.get("decided_at"), ctx["now"]),
    )


def _record_probe_event(ctx, record: dict) -> None:
    """Registra nell'audit del tenant un'annotazione prodotta dalla sonda."""
    severity = _clean(record.get("severity"), "info", 16).lower()
    if severity not in VALID_SEVERITIES:
        severity = "info"

    descrizione = _clean(record.get("description"), maximum=1000)
    dettaglio = record.get("detail")
    if isinstance(dettaglio, dict) and dettaglio:
        # Il dettaglio strutturato viene conservato in forma leggibile.
        descrizione = "%s %s" % (
            descrizione,
            json.dumps(dettaglio, separators=(",", ":"), ensure_ascii=False),
        )

    log_event(
        event_type=_clean(record.get("type"), "probe.event", 64),
        description=descrizione[:1000],
        tenant_id=ctx["tenant_id"],
        severity=severity,
        entity="probe",
        entity_id=ctx["probe_id"],
        actor="probe:%d" % ctx["probe_id"],
        # L'istante dichiarato dalla sonda va conservato: i record raccolti
        # durante un periodo di isolamento non devono assumere l'ora del rientro.
        created_at=_timestamp(record.get("created_at"), ctx["now"]),
    )


# Tipi di record accettati dal conferimento. L'ordine e' significativo: i nodi
# devono esistere prima delle porte e del sistema operativo che li riguardano.
# L'aggiunta di un nuovo tipo si effettua qui, senza toccare il protocollo.
def _apply_check_result(ctx, record: dict) -> None:
    """Conserva l'esito di un controllo periodico e ne governa il workflow.

    La decisione sull'incidente sta nel dominio dei controlli, non qui: questo
    applicatore traduce il record e lascia al workflow la scelta di aprire,
    aggiornare o chiudere.
    """
    from .checks import CheckError, record_result

    try:
        check_id = int(record.get("check_id"))
    except (TypeError, ValueError):
        ctx["orphans"].append("check_results:senza-controllo")
        return

    try:
        esito = record_result(ctx["tenant_id"], check_id, ctx.get("probe_id"), record)
    except CheckError as errore:
        # Un esito malformato non rende intrasmissibile il lotto: si salta e si
        # conta, come gli altri record orfani.
        ctx["orphans"].append("check_results:%d (%s)" % (check_id, errore))
        return
    if not esito.get("stored"):
        # Controllo rimosso mentre la sonda lo eseguiva: l'esito non ha piu' posto.
        ctx["orphans"].append("check_results:%d" % check_id)


# Il testo di uno script SNMP puo' essere lungo: l'elenco delle interfacce di uno
# switch, o il software installato su un server, arrivano a decine di migliaia di
# caratteri. Si conserva molto piu' che nelle prove generali (2 kB), ma con un
# limite: un archivio non deve crescere per una tabella di processi.
MAX_SNMP_OUTPUT_CHARS = 40000
# Pagine per dispositivo e dimensione del dettaglio conservato: un apparato che
# espone otto interfacce web dice le stesse cose su tutte, e il dettaglio serve alla
# diagnosi, non all'archiviazione.
MAX_WEB_PAGES = 6
MAX_WEB_DETAILS = 4000
MAX_SNMP_SCRIPTS = 20


def _apply_snmp(ctx, record: dict) -> None:
    """Conserva le letture SNMP di un dispositivo.

    Perche' in una tabella propria e non nelle prove del profilo: nelle prove il
    testo viene troncato a 2 kB, e cio' che si perde e' esattamente l'informazione
    per cui si interroga SNMP -- interfacce, processi, software installato.
    """
    ip = _clean(record.get("ip"), maximum=64)
    nodo = _node_by_ip(ctx["tenant_id"], ip) if ip else None
    if nodo is None:
        # Vale la regola degli altri record: un nodo non ancora in inventario non
        # viene creato implicitamente, e il lotto non deve diventare intrasmissibile.
        ctx["orphans"].append("snmp:" + (ip or "?"))
        return

    letture = record.get("scripts")
    if not isinstance(letture, dict) or not letture:
        raise IngestError("record di tipo snmp senza letture")

    node_id = int(nodo["id"])
    ctx["touched"].add(node_id)
    scritte = 0
    for nome, testo in list(letture.items())[:MAX_SNMP_SCRIPTS]:
        script_id = _clean(nome, maximum=64)
        if not script_id:
            continue
        # Il testo si conserva com'e', senza ripulitura dei margini: nell'output
        # SNMP il rientro dice a quale voce appartiene una riga, e togliere quello
        # della prima riga cambierebbe la lettura dell'elenco.
        conservabile = str(testo or "")[:MAX_SNMP_OUTPUT_CHARS]
        if not conservabile.strip():
            continue
        execute(
            "INSERT INTO node_snmp (tenant_id, node_id, script_id, output, collected_at)"
            " VALUES (?, ?, ?, ?, ?)"
            " ON CONFLICT(tenant_id, node_id, script_id) DO UPDATE SET"
            " output = excluded.output, collected_at = excluded.collected_at",
            (ctx["tenant_id"], node_id, script_id, conservabile, ctx["now"]))
        scritte += 1

    riassunto = record.get("summary")
    if isinstance(riassunto, dict) and riassunto:
        execute(
            "INSERT INTO node_snmp (tenant_id, node_id, script_id, output, parsed_json,"
            " collected_at) VALUES (?, ?, 'summary', NULL, ?, ?)"
            " ON CONFLICT(tenant_id, node_id, script_id) DO UPDATE SET"
            " parsed_json = excluded.parsed_json, collected_at = excluded.collected_at",
            (ctx["tenant_id"], node_id,
             json.dumps(riassunto, ensure_ascii=False)[:8000], ctx["now"]))

        # Il riassunto non viene ricopiato nel profilo: le prove del nodo sono
        # ricostruite da build_evidence, che legge direttamente questa tabella.

    if scritte:
        ctx.setdefault("snmp_nodes", set()).add(node_id)


def _apply_smb(ctx, record: dict) -> None:
    """Conserva l'enumerazione SMB di un dispositivo (139/445).

    Come per SNMP, in una tabella propria: nelle prove del profilo il testo viene
    troncato, e cio' che si perde e' proprio l'elenco delle condivisioni e delle
    utenze per cui si interroga SMB.
    """
    ip = _clean(record.get("ip"), maximum=64)
    nodo = _node_by_ip(ctx["tenant_id"], ip) if ip else None
    if nodo is None:
        # Vale la regola degli altri record: un nodo non ancora in inventario non
        # viene creato implicitamente, e il lotto non deve diventare intrasmissibile.
        ctx["orphans"].append("smb:" + (ip or "?"))
        return

    letture = record.get("scripts")
    if not isinstance(letture, dict) or not letture:
        raise IngestError("record di tipo smb senza letture")

    node_id = int(nodo["id"])
    ctx["touched"].add(node_id)
    scritte = 0
    for nome, testo in list(letture.items())[:MAX_SNMP_SCRIPTS]:
        script_id = _clean(nome, maximum=64)
        if not script_id:
            continue
        # Il testo si conserva com'e': nell'output SMB il rientro dice a quale voce
        # appartiene una riga (condivisione, utente), e ripulirlo cambierebbe la
        # lettura dell'elenco.
        conservabile = str(testo or "")[:MAX_SNMP_OUTPUT_CHARS]
        if not conservabile.strip():
            continue
        execute(
            "INSERT INTO node_smb (tenant_id, node_id, script_id, output, collected_at)"
            " VALUES (?, ?, ?, ?, ?)"
            " ON CONFLICT(tenant_id, node_id, script_id) DO UPDATE SET"
            " output = excluded.output, collected_at = excluded.collected_at",
            (ctx["tenant_id"], node_id, script_id, conservabile, ctx["now"]))
        scritte += 1

    riassunto = record.get("summary")
    if isinstance(riassunto, dict) and riassunto:
        execute(
            "INSERT INTO node_smb (tenant_id, node_id, script_id, output, parsed_json,"
            " collected_at) VALUES (?, ?, 'summary', NULL, ?, ?)"
            " ON CONFLICT(tenant_id, node_id, script_id) DO UPDATE SET"
            " parsed_json = excluded.parsed_json, collected_at = excluded.collected_at",
            (ctx["tenant_id"], node_id,
             json.dumps(riassunto, ensure_ascii=False)[:8000], ctx["now"]))

    if scritte:
        ctx.setdefault("smb_nodes", set()).add(node_id)


def _apply_vuln(ctx, record: dict) -> None:
    """Registra i difetti che nmap ha verificato su un dispositivo.

    Li collega alla Threat Intelligence: ogni difetto diventa un riscontro di
    sicurezza con origine `nmap`, accanto a quelli della correlazione per versione.
    """
    ip = _clean(record.get("ip"), maximum=64)
    nodo = _node_by_ip(ctx["tenant_id"], ip) if ip else None
    if nodo is None:
        ctx["orphans"].append("vuln:" + (ip or "?"))
        return

    trovati = record.get("findings")
    if not isinstance(trovati, list):
        raise IngestError("record di tipo vuln senza elenco di difetti")

    node_id = int(nodo["id"])
    ctx["touched"].add(node_id)
    from .threat import import_vuln_findings

    esito = import_vuln_findings(ctx["tenant_id"], node_id, trovati)
    if esito["nuovi"] or esito["chiusi"]:
        ctx.setdefault("vuln_nodes", set()).add(node_id)


def _apply_web(ctx, record: dict) -> None:
    """Conserva le letture delle interfacce web di un dispositivo.

    Una riga per porta. Il corpo della pagina non arriva e non si conserva (vedi lo
    schema): quello che serve sono le etichette che la pagina dichiara di se' e il
    verdetto delle firme, con la firma che lo motiva.
    """
    ip = _clean(record.get("ip"), maximum=64)
    nodo = _node_by_ip(ctx["tenant_id"], ip) if ip else None
    if nodo is None:
        ctx["orphans"].append("web:" + (ip or "?"))
        return

    pagine = record.get("pages")
    if not isinstance(pagine, list) or not pagine:
        raise IngestError("record di tipo web senza pagine")

    node_id = int(nodo["id"])
    ctx["touched"].add(node_id)
    scritte = 0
    for pagina in pagine[:MAX_WEB_PAGES]:
        if not isinstance(pagina, dict):
            continue
        try:
            porta = int(pagina.get("port"))
        except (TypeError, ValueError):
            continue

        execute(
            "INSERT INTO node_web (tenant_id, node_id, port, scheme, status_code,"
            " title, server_header, generator, realm, brand, model, product, version,"
            " device_type, signature, cert_subject, cert_issuer, cert_expires,"
            " cert_selfsigned, tls_version, login_form, device_name, location,"
            " host_name, serial, firmware, contact, pages_read, facts_locked,"
            " body_hash, body_bytes, error, details_json, collected_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
            " ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(tenant_id, node_id, port) DO UPDATE SET"
            " scheme = excluded.scheme, status_code = excluded.status_code,"
            " title = excluded.title, server_header = excluded.server_header,"
            " generator = excluded.generator, realm = excluded.realm,"
            " brand = excluded.brand, model = excluded.model,"
            " product = excluded.product, version = excluded.version,"
            " device_type = excluded.device_type, signature = excluded.signature,"
            " cert_subject = excluded.cert_subject, cert_issuer = excluded.cert_issuer,"
            " cert_expires = excluded.cert_expires,"
            " cert_selfsigned = excluded.cert_selfsigned,"
            " tls_version = excluded.tls_version, login_form = excluded.login_form,"
            " device_name = excluded.device_name, location = excluded.location,"
            " host_name = excluded.host_name, serial = excluded.serial,"
            " firmware = excluded.firmware, contact = excluded.contact,"
            " pages_read = excluded.pages_read, facts_locked = excluded.facts_locked,"
            " body_hash = excluded.body_hash, body_bytes = excluded.body_bytes,"
            " error = excluded.error, details_json = excluded.details_json,"
            " collected_at = excluded.collected_at",
            (ctx["tenant_id"], node_id, porta,
             _clean(pagina.get("scheme"), maximum=8) or "http",
             _intero(pagina.get("stato")),
             _clean(pagina.get("titolo"), maximum=300),
             _clean(pagina.get("server"), maximum=200),
             _clean(pagina.get("generator"), maximum=200),
             _clean(pagina.get("www_authenticate"), maximum=200),
             _clean(pagina.get("marca"), maximum=80),
             _clean(pagina.get("modello"), maximum=80),
             _clean(pagina.get("prodotto"), maximum=120),
             _clean(pagina.get("versione"), maximum=40),
             _clean(pagina.get("tipo_probabile"), maximum=40),
             _clean(pagina.get("firma"), maximum=40),
             _clean(pagina.get("cert_soggetto"), maximum=200),
             _clean(pagina.get("cert_emittente"), maximum=200),
             _clean(pagina.get("cert_a"), maximum=20),
             1 if pagina.get("cert_autofirmato") else 0,
             _clean(pagina.get("tls_versione"), maximum=20),
             1 if pagina.get("modulo_accesso") else 0,
             # I fatti arrivano in un dizionario proprio: l'apparato che parla di se'
             # e' una fonte diversa dalle firme, e resta distinguibile.
             _fatto(pagina, "nome_dispositivo", 160),
             _fatto(pagina, "posizione", 160),
             _fatto(pagina, "nome_host", 120),
             _fatto(pagina, "seriale", 80),
             _fatto(pagina, "firmware", 80),
             _fatto(pagina, "contatto", 160),
             _intero(pagina.get("pagine_lette")) or 0,
             1 if pagina.get("fatti_protetti") else 0,
             _clean(pagina.get("corpo_impronta"), maximum=64),
             _intero(pagina.get("corpo_byte")),
             _clean(pagina.get("errore"), maximum=120),
             json.dumps(pagina, ensure_ascii=False)[:MAX_WEB_DETAILS],
             ctx["now"]))
        scritte += 1

    if scritte:
        ctx.setdefault("web_nodes", set()).add(node_id)


def _fatto(pagina: dict, chiave: str, massimo: int):
    """Un fatto dichiarato dalla pagina dell'apparato, ripulito.

    I fatti arrivano dentro `fatti` e non alla radice del record: cosi' non si possono
    confondere con cio' che hanno deciso le firme, e chi legge l'inventario sa se un
    modello e' stato letto dalla pagina o dedotto da un catalogo.
    """
    fatti = pagina.get("fatti")
    if not isinstance(fatti, dict):
        return None
    return _clean(fatti.get(chiave), maximum=massimo)


def _intero(valore):
    """Intero se lo e', altrimenti niente: un valore non numerico non va in colonna."""
    try:
        return int(valore)
    except (TypeError, ValueError):
        return None


_APPLICATORI = {
    "check_results": _apply_check_result,
    "nodes": _apply_node,
    "ports": _apply_port,
    "os": _apply_os,
    "scripts": _apply_script,
    "snmp": _apply_snmp,
    "smb": _apply_smb,
    "vuln": _apply_vuln,
    "web": _apply_web,
    "monitor": _apply_monitor,
    "scan_runs": _apply_scan_run,
    "events": _record_probe_event,
    # Le rimozioni si applicano per ultime: un nodo va valutato con tutte le
    # prove dello stesso lotto, non prima che siano state applicate.
    "removals": _apply_removal,
}


# --------------------------------------------------------------------------- #
# Passaggi conclusivi: chiusura delle porte, nodi scomparsi, fingerprinting
# --------------------------------------------------------------------------- #
def _close_missing_ports(ctx) -> None:
    """Chiude le porte che risultavano aperte e non sono state riviste.

    Si applica solo ai nodi per i quali il lotto dichiara un esame completo delle
    porte: altrimenti una scansione parziale chiuderebbe porte ancora aperte.
    """
    for node_id in ctx["ports_examined"]:
        viste = ctx["seen_ports"].get(node_id, set())
        aperte = query(
            "SELECT id, protocol, port, service_name FROM node_ports"
            " WHERE node_id = ? AND state = 'open'", (node_id,))
        for riga in aperte:
            chiave = (riga["protocol"], int(riga["port"]))
            if chiave in viste:
                continue
            execute("UPDATE node_ports SET state = 'closed', closed_at = ? WHERE id = ?",
                    (ctx["now"], int(riga["id"])))
            _record_change(ctx, node_id, "port.closed",
                           subject="%s/%d" % chiave,
                           before=riga["service_name"] or "aperta", after="chiusa",
                           severity="warning")


def _mark_disappeared(ctx) -> None:
    """Segna come non raggiungibili i nodi di una subnet non visti nella scoperta."""
    from .subnets import within_perimeter

    for bersaglio in ctx["discovery_targets"]:
        cidr = bersaglio["target"]
        righe = query(
            "SELECT id, ip, status, last_seen_at FROM nodes"
            " WHERE tenant_id = ? AND status = 'up'", (ctx["tenant_id"],))
        for riga in righe:
            if int(riga["id"]) in ctx["touched"]:
                continue
            if not within_perimeter([cidr], riga["ip"]):
                continue
            if (riga["last_seen_at"] or "") >= bersaglio["started_at"]:
                continue
            execute("UPDATE nodes SET status = 'down', updated_at = ? WHERE id = ?",
                    (ctx["now"], int(riga["id"])))
            _record_change(ctx, int(riga["id"]), "node.disappeared", subject=riga["ip"],
                           before="up", after="down", severity="warning")


def refresh_suspect_ports(tenant_id: int) -> dict:
    """Marca (o smarca) le porte iniettate dalla rete.

    Non cancella nulla: la porta resta visibile nella console con la propria
    motivazione, e viene soltanto esclusa dalle prove del fingerprinting. Se il
    quadro cambia -- per esempio perche' l'apparato intermedio viene rimosso --
    la marcatura si annulla da se' al conferimento successivo.
    """
    totale = query(
        "SELECT COUNT(*) AS n FROM nodes WHERE tenant_id = ?", (tenant_id,), one=True)
    nodi = int(totale["n"]) if totale else 0
    if nodi < SUSPECT_MIN_NODES:
        return {"marked": 0, "cleared": 0, "nodes": nodi}

    diffuse = query(
        "SELECT p.protocol, p.port, COUNT(DISTINCT p.node_id) AS nodi,"
        " COUNT(DISTINCT n.os_family) AS famiglie,"
        " SUM(CASE WHEN COALESCE(p.product, '') <> '' THEN 1 ELSE 0 END) AS con_prodotto"
        " FROM node_ports p JOIN nodes n ON n.id = p.node_id"
        " WHERE p.tenant_id = ? AND p.state = 'open'"
        " GROUP BY p.protocol, p.port", (tenant_id,))

    sospette = set()
    for riga in diffuse:
        prevalenza = int(riga["nodi"]) / float(nodi)
        if int(riga["con_prodotto"] or 0) > 0:
            # nmap ha riconosciuto un prodotto su quella porta almeno una volta:
            # e' un servizio reale, non la risposta di un apparato intermedio.
            continue
        if (prevalenza >= SUSPECT_MIN_PREVALENCE
                and int(riga["famiglie"] or 0) >= SUSPECT_MIN_OS_FAMILIES):
            sospette.add((riga["protocol"], int(riga["port"])))

    marcate = liberate = 0
    for riga in query("SELECT id, protocol, port, is_suspect FROM node_ports"
                      " WHERE tenant_id = ?", (tenant_id,)):
        chiave = (riga["protocol"], int(riga["port"]))
        deve_essere = 1 if chiave in sospette else 0
        if int(riga["is_suspect"] or 0) == deve_essere:
            continue
        motivo = None
        if deve_essere:
            motivo = ("aperta su almeno il %d%% dei nodi e su famiglie di sistema operativo"
                      " diverse: porta iniettata dalla rete, non del nodo"
                      % int(SUSPECT_MIN_PREVALENCE * 100))
        execute("UPDATE node_ports SET is_suspect = ?, suspect_reason = ? WHERE id = ?",
                (deve_essere, motivo, int(riga["id"])))
        if deve_essere:
            marcate += 1
        else:
            liberate += 1

    if marcate:
        log_event(
            "inventory.ports.suspect",
            "Riconosciute %d porte iniettate dalla rete (%s): escluse dalle prove"
            % (marcate, ", ".join("%s/%d" % s for s in sorted(sospette))),
            tenant_id=tenant_id,
            severity="warning",
            entity="node",
        )
    return {"marked": marcate, "cleared": liberate, "nodes": nodi,
            "ports": sorted("%s/%d" % s for s in sospette)}


# Quanto testo SNMP entra fra le prove del riconoscimento. Il testo intero resta in
# node_snmp: qui basta la parte che identifica l'apparato, e le regole cercano
# espressioni brevi nelle prime righe.
MAX_SNMP_EVIDENCE_CHARS = 4000


def _snmp_evidence(tenant_id: int, node_id: int) -> dict:
    """Riassunto SNMP conservato, per le prove e per la pagina del nodo."""
    riga = query(
        "SELECT parsed_json FROM node_snmp WHERE tenant_id = ? AND node_id = ?"
        " AND script_id = 'summary'", (tenant_id, node_id), one=True)
    if riga is None or not riga["parsed_json"]:
        return {}
    try:
        return json.loads(riga["parsed_json"])
    except json.JSONDecodeError:
        current_app.logger.warning(
            "riassunto SNMP illeggibile per il nodo %s (tenant %s)", node_id, tenant_id)
        return {}


def _smb_evidence(tenant_id: int, node_id: int) -> dict:
    """Riassunto SMB conservato, per le prove e per la pagina del nodo."""
    riga = query(
        "SELECT parsed_json FROM node_smb WHERE tenant_id = ? AND node_id = ?"
        " AND script_id = 'summary'", (tenant_id, node_id), one=True)
    if riga is None or not riga["parsed_json"]:
        return {}
    try:
        return json.loads(riga["parsed_json"])
    except json.JSONDecodeError:
        current_app.logger.warning(
            "riassunto SMB illeggibile per il nodo %s (tenant %s)", node_id, tenant_id)
        return {}


def _web_evidence(tenant_id: int, node_id: int) -> list:
    """Cio' che le pagine di gestione del dispositivo dichiarano di se'.

    E' la fonte piu' esplicita dopo SNMP: una pagina che scrive "HP LaserJet MFP
    M428" identifica l'apparato meglio di dieci porte aperte. Si passano al
    riconoscimento le sole etichette, non il corpo della pagina -- che non viene
    nemmeno conservato.
    """
    righe = query(
        "SELECT port, scheme, status_code, title, server_header, generator, realm,"
        " brand, model, product, version, device_type, signature, cert_subject,"
        " cert_issuer, login_form, device_name, location, host_name, serial, firmware,"
        " contact, pages_read, facts_locked"
        " FROM node_web WHERE tenant_id = ? AND node_id = ?"
        " ORDER BY port", (tenant_id, node_id))
    return [{
        "port": int(riga["port"]), "scheme": riga["scheme"],
        "status": riga["status_code"], "title": riga["title"],
        "server": riga["server_header"], "generator": riga["generator"],
        "realm": riga["realm"], "brand": riga["brand"], "model": riga["model"],
        "product": riga["product"], "version": riga["version"],
        "device_type": riga["device_type"], "signature": riga["signature"],
        "cert_subject": riga["cert_subject"], "cert_issuer": riga["cert_issuer"],
        "login_form": bool(riga["login_form"]),
        # I fatti dichiarati dall'apparato: il riconoscimento li usa come prova, e
        # sono la ragione per cui una multifunzione si riconosce dal proprio nome
        # invece che dalle porte aperte.
        "device_name": riga["device_name"], "location": riga["location"],
        "host_name": riga["host_name"], "serial": riga["serial"],
        "firmware": riga["firmware"], "contact": riga["contact"],
        "pages_read": riga["pages_read"], "facts_locked": bool(riga["facts_locked"]),
    } for riga in righe]


def _scripts_evidence(tenant_id: int, node_id: int, conservato: dict) -> dict:
    """Esiti degli script utili al riconoscimento, SNMP compreso.

    Le letture SNMP stanno in una tabella propria per non essere troncate, ma il
    riconoscimento le cerca fra gli script: qui si riuniscono. La descrizione di
    sistema viene accodata a `snmp-info` perche' e' li' che le regole del catalogo
    cercano cio' che l'apparato dichiara di essere.
    """
    esiti = dict((conservato.get("evidence") or {}).get("scripts") or {})
    letture = query(
        "SELECT script_id, output FROM node_snmp WHERE tenant_id = ? AND node_id = ?"
        " AND output IS NOT NULL", (tenant_id, node_id))
    descrizione = ""
    for riga in letture:
        testo = (riga["output"] or "")[:MAX_SNMP_EVIDENCE_CHARS]
        esiti[riga["script_id"]] = testo
        if riga["script_id"] == "snmp-sysdescr":
            descrizione = testo
    if descrizione:
        esiti["snmp-info"] = (esiti.get("snmp-info", "") + "\n" + descrizione).strip()

    # Gli esiti SMB entrano fra le prove: smb-os-discovery dichiara la versione di
    # Windows e l'appartenenza al dominio meglio del rilevamento del sistema
    # operativo, e il riconoscimento li cerca fra gli script.
    for riga in query(
            "SELECT script_id, output FROM node_smb WHERE tenant_id = ? AND node_id = ?"
            " AND output IS NOT NULL", (tenant_id, node_id)):
        esiti[riga["script_id"]] = (riga["output"] or "")[:MAX_SNMP_EVIDENCE_CHARS]
    return esiti


def build_evidence(tenant_id: int, node_id: int) -> dict:
    """Compone le prove di un nodo cosi' come sono conservate in banca dati.

    Ricostruire le prove dalla banca dati, invece di usare solo il lotto appena
    arrivato, permette di determinare il tipo anche quando le informazioni sono
    state raccolte in fasi diverse.
    """
    nodo = query("SELECT * FROM nodes WHERE id = ? AND tenant_id = ?",
                 (node_id, tenant_id), one=True)
    if nodo is None:
        return {}
    # Le porte riconosciute come iniettate dalla rete non sono prove del nodo.
    porte = query(
        "SELECT protocol, port, state, service_name, product, version, extrainfo, cpe, banner"
        " FROM node_ports WHERE node_id = ? AND state = 'open'"
        " AND COALESCE(is_suspect, 0) = 0", (node_id,))
    conservato = _json_or_empty(nodo["fingerprint_json"])
    return {
        "ip": nodo["ip"],
        "mac": nodo["mac"],
        "mac_vendor": nodo["mac_vendor"],
        "hostname": nodo["hostname"],
        "ttl": nodo["ttl"],
        "ports": [
            {"protocol": p["protocol"], "port": int(p["port"]), "state": p["state"],
             "service_name": p["service_name"], "product": p["product"],
             "version": p["version"], "extrainfo": p["extrainfo"],
             "banner": p["banner"],
             "cpe": (p["cpe"] or "").split(",") if p["cpe"] else []}
            for p in porte
        ],
        "os": {
            "name": nodo["os_name"], "family": nodo["os_family"], "vendor": nodo["os_vendor"],
            "gen": nodo["os_gen"], "type": nodo["os_type"], "accuracy": nodo["os_accuracy"],
        },
        "snmp": _snmp_evidence(tenant_id, node_id),
        "smb": _smb_evidence(tenant_id, node_id),
        "web": _web_evidence(tenant_id, node_id),
        "scripts": _scripts_evidence(tenant_id, node_id, conservato),
    }


def refresh_fingerprint(tenant_id: int, node_id: int, ctx=None) -> dict:
    """Determina il tipo di dispositivo di un nodo e ne registra il cambiamento.

    Se il tipo e' stato **dichiarato dall'operatore** il verdetto viene comunque
    calcolato e conservato -- serve a mostrare il disaccordo, che e' il modo in cui si
    scopre che il catalogo delle firme va corretto -- ma non sovrascrive la
    dichiarazione. Senza questa distinzione una dichiarazione durerebbe fino al
    conferimento successivo.
    """
    prove = build_evidence(tenant_id, node_id)
    if not prove:
        return {}
    verdetto = fingerprint.identify(prove)
    nodo = query(
        "SELECT device_type, device_label, COALESCE(device_type_source, 'auto')"
        " AS device_type_source FROM nodes WHERE id = ? AND tenant_id = ?",
        (node_id, tenant_id), one=True)
    adesso = ctx["now"] if ctx else utc_now_str()

    if nodo is not None and nodo["device_type_source"] == "manual":
        # Le prove si aggiornano, il verdetto no: il tipo lo ha detto una persona.
        execute(
            "UPDATE nodes SET catalog_version = ?, fingerprint_json = ?, updated_at = ?"
            " WHERE id = ? AND tenant_id = ?",
            (verdetto["catalog_version"],
             json.dumps({"verdict": verdetto, "evidence": prove}, ensure_ascii=False),
             adesso, node_id, tenant_id),
        )
        return dict(verdetto, applied=False, declared=True,
                    device_type=nodo["device_type"],
                    device_label=nodo["device_label"],
                    automatic_type=verdetto["device_type"],
                    automatic_label=verdetto["device_label"])

    if nodo is not None and nodo["device_type"] != verdetto["device_type"]:
        if ctx is not None:
            _record_change(ctx, node_id, "device_type.changed",
                           subject=prove.get("ip"),
                           before=nodo["device_label"], after=verdetto["device_label"])
        else:
            execute(
                "INSERT INTO node_changes (tenant_id, node_id, kind, subject, before_value,"
                " after_value, severity, created_at) VALUES (?, ?, ?, ?, ?, ?, 'info', ?)",
                (tenant_id, node_id, "device_type.changed", prove.get("ip"),
                 nodo["device_label"], verdetto["device_label"], adesso),
            )

    execute(
        "UPDATE nodes SET device_type = ?, device_label = ?, device_confidence = ?,"
        " catalog_version = ?, fingerprint_json = ?, updated_at = ?"
        " WHERE id = ? AND tenant_id = ?",
        (verdetto["device_type"], verdetto["device_label"], verdetto["confidence"],
         verdetto["catalog_version"],
         json.dumps({"verdict": verdetto, "evidence": prove}, ensure_ascii=False),
         adesso, node_id, tenant_id),
    )
    return dict(verdetto, applied=True, declared=False)


def refingerprint_tenant(tenant_id: int) -> dict:
    """Rideterminazione dell'intero inventario, senza nuove scansioni.

    Serve quando il catalogo delle firme cambia: le prove sono conservate, quindi
    il verdetto e' ricalcolabile (requisito SR-47).
    """
    # Il quadro delle porte iniettate va rivalutato prima dei verdetti.
    refresh_suspect_ports(tenant_id)
    nodi = query("SELECT id FROM nodes WHERE tenant_id = ?", (tenant_id,))
    cambiati = 0
    dichiarati = 0
    for riga in nodi:
        prima = query("SELECT device_type FROM nodes WHERE id = ?", (int(riga["id"]),), one=True)
        verdetto = refresh_fingerprint(tenant_id, int(riga["id"]))
        if verdetto and verdetto.get("declared"):
            # Il tipo lo ha dichiarato una persona: si dichiara quanti sono stati
            # rispettati, altrimenti l'operatore non sa se la rideterminazione li ha
            # travolti.
            dichiarati += 1
            continue
        if verdetto and prima and verdetto["device_type"] != prima["device_type"]:
            cambiati += 1
    return {"nodes": len(nodi), "changed": cambiati, "declared": dichiarati,
            "catalog_version": fingerprint.CATALOG_VERSION}


# --------------------------------------------------------------------------- #
# Applicazione del lotto
# --------------------------------------------------------------------------- #
def _store_records(records: dict) -> tuple:
    """Serializza i record conferiti per la consultazione, con un limite."""
    testo = json.dumps(records, ensure_ascii=False, separators=(",", ":"))
    if len(testo.encode("utf-8")) <= MAX_STORED_RECORDS_BYTES:
        return testo, 0
    estratto = {tipo: (elenco[:20] if isinstance(elenco, list) else elenco)
                for tipo, elenco in records.items()}
    estratto["_nota"] = ("lotto troppo grande per essere conservato integralmente: "
                         "primi 20 record per tipo")
    return json.dumps(estratto, ensure_ascii=False, separators=(",", ":")), 1


def apply_batch(tenant_id: int, probe_id: int, payload: dict, payload_bytes: int = 0) -> dict:
    """Applica un lotto di dati. Restituisce l'esito da inviare alla sonda."""
    batch_uid = _clean(payload.get("batch_uid"), maximum=64)
    if not batch_uid:
        raise IngestError("batch_uid mancante")

    existing = query(
        "SELECT id, record_count FROM ingest_batches WHERE probe_id = ? AND batch_uid = ?",
        (probe_id, batch_uid),
        one=True,
    )
    if existing is not None:
        # Ritrasmissione: si riconferma l'acquisizione senza riapplicare i dati.
        current_app.logger.info("Lotto %s gia' acquisito: ack ripetuto", batch_uid)
        return {
            "accepted": True,
            "duplicate": True,
            "batch_uid": batch_uid,
            "records": int(existing["record_count"]),
        }

    records = payload.get("records") or {}
    if not isinstance(records, dict):
        raise IngestError("il campo records deve essere un oggetto")

    sconosciuti = set(records) - set(_APPLICATORI)
    if sconosciuti:
        raise IngestError(
            "tipi di record non riconosciuti: %s" % ", ".join(sorted(sconosciuti))
        )

    adesso = utc_now_str()
    ctx = {
        "tenant_id": tenant_id,
        "probe_id": probe_id,
        "now": adesso,
        "touched": set(),
        "seen_ports": {},
        "ports_examined": set(),
        "discovery_targets": [],
        "changes": 0,
        "orphans": [],
        "removals_applied": [],
        "removals_refused": [],
        "removals_skipped": [],
    }

    # I nodi che dichiarano un esame completo delle porte abilitano la chiusura
    # di quelle non riviste.
    for record in records.get("nodes") or []:
        if isinstance(record, dict) and record.get("ports_examined"):
            ctx.setdefault("_examined_ips", set()).add(_clean(record.get("ip"), maximum=64))

    counters = {}
    for tipo, applicatore in _APPLICATORI.items():
        elementi = records.get(tipo) or []
        if not isinstance(elementi, list):
            raise IngestError("il campo %s deve essere una lista" % tipo)
        for elemento in elementi:
            if not isinstance(elemento, dict):
                raise IngestError("ogni elemento di %s deve essere un oggetto" % tipo)
            applicatore(ctx, elemento)
        counters[tipo] = len(elementi)

    for ip in ctx.get("_examined_ips", set()):
        nodo = _node_by_ip(tenant_id, ip)
        if nodo is not None:
            ctx["ports_examined"].add(int(nodo["id"]))

    _close_missing_ports(ctx)
    _mark_disappeared(ctx)
    # Prima di determinare i tipi: le porte iniettate non devono fare da prova.
    sospette = refresh_suspect_ports(tenant_id)

    verdetti = {}
    for node_id in sorted(ctx["touched"]):
        # I nodi rimossi sono stati rimossi da 'touched' dall'applicatore.
        verdetto = refresh_fingerprint(tenant_id, node_id, ctx)
        if verdetto:
            verdetti[verdetto["device_type"]] = verdetti.get(verdetto["device_type"], 0) + 1

    if ctx["orphans"]:
        # Condizione prevista quando un lotto viene spezzato: va vista, non
        # nascosta, perche' un numero alto indica una configurazione da rivedere.
        log_event(
            "probe.ingest.orphans",
            "Nel lotto %s sono stati saltati %d record riferiti a nodi non in inventario: %s"
            % (batch_uid, len(ctx["orphans"]), ", ".join(sorted(set(ctx["orphans"]))[:10])),
            tenant_id=tenant_id,
            severity="warning",
            entity="probe",
            entity_id=probe_id,
            actor="probe:%d" % probe_id,
        )

    if ctx["removals_applied"]:
        current_app.logger.info(
            "Rimossi %d nodi privi di informazioni: %s",
            len(ctx["removals_applied"]), ", ".join(ctx["removals_applied"][:10]))

    total = sum(counters.values())
    conservati, troncato = _store_records(records)
    batch_id = execute(
        "INSERT INTO ingest_batches (tenant_id, probe_id, batch_uid, record_count,"
        " payload_bytes, status, detail, records_json, records_truncated, received_at)"
        " VALUES (?, ?, ?, ?, ?, 'accepted', ?, ?, ?, ?)",
        (
            tenant_id,
            probe_id,
            batch_uid,
            total,
            payload_bytes,
            json.dumps(counters, separators=(",", ":")),
            conservati,
            troncato,
            adesso,
        ),
    )
    # La telemetria di scansione appena inserita viene collegata al lotto.
    execute("UPDATE scan_runs SET batch_id = ? WHERE tenant_id = ? AND batch_id IS NULL"
            " AND created_at = ?", (batch_id, tenant_id, adesso))

    return {
        "accepted": True,
        "duplicate": False,
        "batch_uid": batch_uid,
        "records": total,
        "detail": counters,
        "nodes_touched": len(ctx["touched"]),
        "changes": ctx["changes"],
        "orphans": len(ctx["orphans"]),
        "device_types": verdetti,
        "suspect_ports": sospette.get("ports", []),
        "removed": len(ctx["removals_applied"]),
        "removals_refused": len(ctx["removals_refused"]),
    }
