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
  presence   avvistamenti sulle reti senza fili: chi era qui e quando (presence.py)
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
# unita a una CORROBORAZIONE. Una porta per cui nmap ha riconosciuto un prodotto
# almeno una volta e' invece un servizio reale.
#
# LA DIFFUSIONE SI MISURA PER SUBNET, non sull'intero tenant. Un apparato
# intermedio inietta sul SEGMENTO che serve, non su tutto il patrimonio: misurato
# sul campo, la tcp/5060 risultava aperta sul 98% dei nodi di 10.2.1.0/24 e sul 3%
# di 10.20.10.0/24. Calcolata sul tenant la diffusione scendeva al 79%, sotto la
# soglia, e la rilevazione NON scattava: 98 nodi su 145 venivano classificati
# "Telefono VoIP" sulla base di quella sola porta.
#
# Due prove, di peso diverso:
#
#  a) DIFFUSIONE + ETEROGENEITA' dei sistemi operativi: una porta aperta quasi su
#     tutto, su famiglie diverse, non e' un servizio dei nodi. Richiede la soglia
#     di prevalenza;
#  b) RISPOSTA DA UN INDIRIZZO IMPOSSIBILE: se la porta risulta aperta
#     sull'indirizzo di rete o di broadcast della subnet, la' non puo' esserci un
#     host -- risponde per forza qualcun altro, e risponde PER IL SEGMENTO. E' una
#     prova accertata, non un indizio statistico: NON richiede la soglia di
#     prevalenza, e non richiede che la fase del sistema operativo sia passata.
#
#     Costato una seconda volta per questo: la soglia veniva applicata prima di
#     guardare l'indirizzo impossibile, quindi la prova forte non arrivava mai a
#     contare. Su 10.10.60.0/24 la tcp/5060 era aperta sul 53% dei nodi (sotto
#     soglia) e su entrambi gli indirizzi impossibili: 128 nodi classificati
#     "Telefono VoIP". La diffusione cresce durante la passata, quindi la
#     marcatura sarebbe arrivata solo a scansione conclusa.
#
# Limite dichiarato: un servizio genuinamente presente su quasi tutti i nodi di
# una subnet eterogenea, e mai identificato per prodotto, viene marcato come
# iniettato. La marcatura resta visibile nella console con la propria
# motivazione proprio perche' l'operatore possa accorgersene.
SUSPECT_MIN_NODES = 8
SUSPECT_MIN_PREVALENCE = 0.95
SUSPECT_MIN_OS_FAMILIES = 3

# SEGMENTO SERVITO DA UN APPARATO INTERMEDIO: quando l'indirizzo di rete o quello di
# broadcast della subnet RISPONDONO -- anche solo al ping -- la' non c'e' nessun host,
# quindi qualcuno risponde per il segmento. E' un fatto accertato sulla SUBNET, non su
# una porta, e arriva molto prima delle porte: basta la scoperta.
#
# Misurato sulla rete ospiti 10.10.60.0/24: 256 nodi "attivi" su 254 indirizzi
# possibili, nessun MAC, TTL identico su tutti. La tcp/5060 era aperta sul 53% dei
# nodi -- sotto la soglia ordinaria -- e produceva 128 "Telefono VoIP". Su un segmento
# cosi' la diffusione richiesta scende: una porta presente su metà del segmento non e'
# attribuibile a nessun host, perche' non si sa quali di quegli indirizzi siano host.
#
# Non scende a zero, e la ragione conta: dietro l'apparato intermedio ci sono anche
# apparati veri. Sulla stessa rete la 445 risponde su 12 nodi su 256 (il 4,7%) -- sono
# macchine Windows reali, e sopprimerle sarebbe il difetto opposto.
SUSPECT_PREVALENCE_SEGMENTO_SERVITO = 0.50


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
    # Provenienza del MAC. Allowlist: "arp" oppure "snmp:<apparato>" -- e'
    # un valore che finisce in una pagina e in un report, e arriva dalla rete.
    fonte_mac = _clean(record.get("mac_source"), maximum=80) or None
    if fonte_mac and not (fonte_mac == "arp" or fonte_mac.startswith("snmp:")):
        fonte_mac = None
    # Punto di attacco fisico: apparato e nome della porta, come li ha letti la sonda.
    apparato = _clean(record.get("switch_device"), maximum=80) or None
    porta_fisica = _clean(record.get("switch_port"), maximum=60) or None
    vendor = _clean(record.get("mac_vendor"), maximum=190) or None
    latenza = _real(record.get("latency_ms"))
    ttl = _intero(record.get("ttl"))
    subnet_id = subnet_of_address(ctx["tenant_id"], ip)

    esistente = _node_by_ip(ctx["tenant_id"], ip)
    if esistente is None:
        node_id = execute(
            "INSERT INTO nodes (tenant_id, subnet_id, probe_id, ip, mac, mac_source,"
            " switch_device, switch_port, mac_vendor, hostname,"
            " status, latency_ms, ttl, first_seen_at, last_seen_at, last_scan_at,"
            " created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ctx["tenant_id"], subnet_id, ctx["probe_id"], ip, mac, fonte_mac,
             apparato, porta_fisica, vendor, hostname,
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
        " mac = COALESCE(?, mac), mac_source = COALESCE(?, mac_source),"
        " switch_device = COALESCE(?, switch_device),"
        " switch_port = COALESCE(?, switch_port),"
        " mac_vendor = COALESCE(?, mac_vendor),"
        " hostname = COALESCE(?, hostname), status = ?, latency_ms = COALESCE(?, latency_ms),"
        " ttl = COALESCE(?, ttl),"
        " last_seen_at = GREATEST(last_seen_at, ?), last_scan_at = ?, updated_at = ?"
        " WHERE id = ? AND tenant_id = ?",
        (subnet_id, ctx["probe_id"], mac, fonte_mac, apparato, porta_fisica,
         vendor, hostname, stato, latenza, ttl,
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
        " last_seen_at = CASE WHEN ? = 1 THEN GREATEST(last_seen_at, ?) ELSE last_seen_at END,"
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
            " facts_json, cert_json, body_hash, body_bytes, favicon_hash, favicon_bytes,"
            " favicon_path, headers_hash, headers_names, web_year, web_year_source,"
            " web_year_evidence, web_age_years, web_years, error, details_json,"
            " collected_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
            " ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
            " ?, ?)"
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
            " facts_json = excluded.facts_json, cert_json = excluded.cert_json,"
            " body_hash = excluded.body_hash, body_bytes = excluded.body_bytes,"
            " favicon_hash = excluded.favicon_hash,"
            " favicon_bytes = excluded.favicon_bytes,"
            " favicon_path = excluded.favicon_path,"
            " headers_hash = excluded.headers_hash,"
            " headers_names = excluded.headers_names,"
            " web_year = excluded.web_year,"
            " web_year_source = excluded.web_year_source,"
            " web_year_evidence = excluded.web_year_evidence,"
            " web_age_years = excluded.web_age_years,"
            " web_years = excluded.web_years,"
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
             # Tutte le etichette riconosciute, non solo quelle con una colonna: sono
             # gia' un vocabolario chiuso (nessun corpo di pagina), quindi si conservano
             # per intero e il dettaglio del nodo le mostra.
             (json.dumps(pagina["fatti"], ensure_ascii=False)[:MAX_WEB_DETAILS]
              if isinstance(pagina.get("fatti"), dict) and pagina["fatti"] else None),
             # Tutti i dati del certificato: dove c'e' HTTPS si registra tutto cio' che
             # il certificato dichiara, non solo i pochi campi con una colonna propria.
             _certificato_json(pagina),
             _clean(pagina.get("corpo_impronta"), maximum=64),
             _intero(pagina.get("corpo_byte")),
             # Impronte di somiglianza: stanno in colonna, non solo nel dettaglio,
             # perche' il loro valore e' il CONFRONTO fra nodi diversi e un confronto
             # si fa con una interrogazione, non leggendo un JSON riga per riga.
             _clean(pagina.get("favicon_impronta"), maximum=64),
             _intero(pagina.get("favicon_byte")),
             _clean(pagina.get("favicon_percorso"), maximum=200),
             _clean(pagina.get("intestazioni_impronta"), maximum=64),
             _clean(pagina.get("intestazioni_nomi"), maximum=400),
             # L'ANNO DICHIARATO DALLA PAGINA e l'eta' che se ne deduce. La PROVA si
             # conserva accanto al numero: un anno senza il frammento da cui viene non
             # e' verificabile, e un indizio non verificabile non si puo' usare per
             # decidere di sostituire un apparato.
             _intero(pagina.get("anno")),
             _clean(pagina.get("anno_fonte"), maximum=24),
             _clean(pagina.get("anno_prova"), maximum=200),
             _intero(pagina.get("eta_anni")),
             _clean(pagina.get("anni_visti"), maximum=80),
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


def _certificato_json(pagina: dict):
    """Tutti i dati del certificato TLS e del canale, come JSON, o niente se non c'e'.

    Si raccolgono le chiavi `cert_*` e `tls_*` che la sonda ha estratto: sono gia' un
    insieme chiuso di campi tecnici (nessun contenuto di pagina), quindi si conservano
    per intero e il dettaglio del nodo li mostra dove l'apparato parla in HTTPS.
    """
    cert = {chiave: valore for chiave, valore in pagina.items()
            if (chiave.startswith("cert_") or chiave.startswith("tls_"))
            and valore not in (None, "", [], {})}
    if not cert:
        return None
    return json.dumps(cert, ensure_ascii=False)[:MAX_WEB_DETAILS]


def _intero(valore):
    """Intero se lo e', altrimenti niente: un valore non numerico non va in colonna."""
    try:
        return int(valore)
    except (TypeError, ValueError):
        return None


def _apply_presence(ctx, record: dict) -> None:
    """Registra un avvistamento su una rete senza fili.

    Arriva dalla ricognizione breve e frequente della sonda (una passata ogni pochi
    minuti). Non crea il nodo e non ne aggiorna il profilo: quello lo fanno i record
    di tipo `nodes` dello stesso lotto, applicati prima di questo. Qui si risponde a
    una domanda che l'inventario da solo non sa dare -- CHI era qui e QUANDO -- perche'
    su una rete Wi-Fi l'indirizzo non identifica un apparato (vedi presence.py).
    """
    from . import presence

    ip = _clean(record.get("ip"), maximum=64)
    if not ip:
        raise IngestError("record di tipo presence senza indirizzo")
    nodo = _node_by_ip(ctx["tenant_id"], ip)
    if nodo is None:
        # Un avvistamento senza il nodo corrispondente vuol dire che il lotto non
        # portava il record `nodes`: si dichiara come orfano invece di inventare un
        # nodo da un solo ping.
        ctx["orphans"].append("presence:" + ip)
        return

    node_id = int(nodo["id"])
    # Il MAC e il nome host si prendono dal NODO, non dal record: il nodo li ha
    # raccolti da tutte le fasi (ARP, SNMP, DNS), la ricognizione vede solo un ping.
    dati = {"ip": ip, "mac": nodo["mac"], "hostname": nodo["hostname"]}
    if not dati["mac"]:
        dati["mac"] = _clean(record.get("mac"), maximum=32) or None
    if not dati["hostname"]:
        dati["hostname"] = _clean(record.get("hostname"), maximum=190) or None

    esito = presence.registra_avvistamento(
        ctx["tenant_id"], dati,
        visto_a=_timestamp(record.get("seen_at"), ctx["now"]),
        seriale=_seriale_noto(ctx["tenant_id"], node_id),
        profilo=_impronta_debole(ctx["tenant_id"], node_id, nodo),
        subnet_id=(int(nodo["subnet_id"]) if nodo["subnet_id"] else None),
        node_id=node_id,
        etichetta=nodo["device_label"])
    if esito["nuova"]:
        ctx.setdefault("presence_new", []).append(ip)


def _seriale_noto(tenant_id: int, node_id: int) -> str | None:
    """Il numero di serie che l'apparato ha dichiarato, se ne ha dichiarato uno.

    E' la seconda identita' in ordine di certezza dopo il MAC, e su una stampante o
    un apparato di rete e' l'unica che non cambia mai.
    """
    riga = query(
        "SELECT serial FROM node_web WHERE tenant_id = ? AND node_id = ?"
        " AND serial IS NOT NULL AND serial <> '' ORDER BY port LIMIT 1",
        (tenant_id, node_id), one=True)
    return _clean(riga["serial"], maximum=80) if riga is not None else None


def _impronta_debole(tenant_id: int, node_id: int, nodo) -> str | None:
    """Impronta del profilo osservato: TTL, porte aperte, famiglia del sistema.

    Non identifica un apparato -- mille postazioni uguali la condividono -- ma se
    cambia sullo stesso indirizzo dice che l'indirizzo e' passato a un altro
    apparato. Quando il MAC non c'e', e' l'unico modo di accorgersene.
    """
    from . import presence

    porte = [int(r["port"]) for r in query(
        "SELECT port FROM node_ports WHERE node_id = ? AND state = 'open'"
        " AND COALESCE(is_suspect, 0) = 0 ORDER BY port LIMIT 40", (node_id,))]
    return presence.impronta_profilo(ttl=nodo["ttl"], porte=porte,
                                     famiglia_os=nodo["os_family"])


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
    # Le presenze dopo il web: l'identita' piu' forte dopo il MAC e' il numero di
    # serie, e quello lo dichiara la pagina dell'apparato.
    "presence": _apply_presence,
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
    """Marca (o smarca) le porte iniettate dalla rete, SUBNET PER SUBNET.

    Non cancella nulla: la porta resta visibile nella console con la propria
    motivazione, e viene soltanto esclusa dalle prove del fingerprinting. Se il
    quadro cambia -- per esempio perche' l'apparato intermedio viene rimosso --
    la marcatura si annulla da se' al conferimento successivo.

    La marcatura e' per (subnet, protocollo, porta) e non globale: un apparato
    intermedio serve un SEGMENTO, e la stessa porta su un'altra subnet puo' essere
    un servizio genuino. Misurato: la tcp/5060 era iniettata sul 98% di
    10.2.1.0/24 e presente sul 3% di 10.20.10.0/24 -- marcarla globalmente avrebbe
    soppresso l'unico telefono forse vero.
    """
    per_subnet = query(
        "SELECT n.subnet_id, COUNT(*) AS n,"
        # Un indirizzo di rete o di broadcast che RISPONDE: la' non c'e' un host, e
        # dunque risponde un apparato intermedio per tutto il segmento. Si guarda la
        # raggiungibilita', non le porte: e' un dato che la sola scoperta produce.
        " SUM(CASE WHEN s.cidr IS NOT NULL AND n.status = 'up'"
        "          AND (n.ip = host(network(s.cidr::cidr))"
        "               OR n.ip = host(broadcast(s.cidr::cidr)))"
        "     THEN 1 ELSE 0 END) AS impossibili_vivi"
        " FROM nodes n LEFT JOIN subnets s ON s.id = n.subnet_id"
        " WHERE n.tenant_id = ? GROUP BY n.subnet_id", (tenant_id,))
    quanti = {r["subnet_id"]: int(r["n"]) for r in per_subnet}
    serviti = {r["subnet_id"] for r in per_subnet
               if int(r["impossibili_vivi"] or 0) > 0}
    nodi = sum(quanti.values())
    if nodi < SUSPECT_MIN_NODES:
        return {"marked": 0, "cleared": 0, "nodes": nodi}

    # `host(network(...))` e `host(broadcast(...))` danno l'indirizzo di rete e
    # quello di broadcast della subnet come testo: se un nodo con quell'indirizzo
    # esiste ed espone la porta, la' non puo' esserci un host -- risponde per forza
    # un apparato intermedio. E' la prova piu' forte, e non richiede che la fase del
    # sistema operativo sia passata.
    diffuse = query(
        "SELECT n.subnet_id, p.protocol, p.port,"
        " COUNT(DISTINCT p.node_id) AS nodi,"
        " COUNT(DISTINCT n.os_family) AS famiglie,"
        " SUM(CASE WHEN COALESCE(p.product, '') <> '' THEN 1 ELSE 0 END) AS con_prodotto,"
        " SUM(CASE WHEN s.cidr IS NOT NULL"
        "          AND (n.ip = host(network(s.cidr::cidr))"
        "               OR n.ip = host(broadcast(s.cidr::cidr)))"
        "     THEN 1 ELSE 0 END) AS impossibili"
        " FROM node_ports p JOIN nodes n ON n.id = p.node_id"
        " LEFT JOIN subnets s ON s.id = n.subnet_id"
        " WHERE p.tenant_id = ? AND p.state = 'open'"
        " GROUP BY n.subnet_id, p.protocol, p.port", (tenant_id,))

    sospette = set()
    motivi = {}
    for riga in diffuse:
        subnet = riga["subnet_id"]
        totale_subnet = quanti.get(subnet) or 0
        if totale_subnet < SUSPECT_MIN_NODES:
            # Su una subnet con pochi nodi la diffusione non significa nulla.
            continue
        if int(riga["con_prodotto"] or 0) > 0:
            # nmap ha riconosciuto un prodotto su quella porta almeno una volta:
            # e' un servizio reale, non la risposta di un apparato intermedio.
            continue
        prevalenza = int(riga["nodi"]) / float(totale_subnet)
        impossibili = int(riga["impossibili"] or 0)
        famiglie = int(riga["famiglie"] or 0)
        # LA DIFFUSIONE SI CHIEDE SOLO SE MANCA LA PROVA DECISIVA, e l'ordine era
        # sbagliato: la soglia di prevalenza veniva applicata PRIMA di guardare
        # l'indirizzo impossibile, quindi la prova piu' forte non arrivava mai a
        # contare finche' la porta non era sul 95% dei nodi.
        #
        # Misurato su 10.10.60.0/24 (rete ospiti, 256 nodi): tcp/5060 aperta su 137
        # nodi -- il 53%, sotto soglia -- E sull'indirizzo di rete E su quello di
        # broadcast. Risultato: 128 nodi classificati "Telefono VoIP" da una porta
        # che un apparato intermedio serve per l'intero segmento. La diffusione
        # cresce durante la passata, quindi la marcatura sarebbe arrivata solo a
        # scansione conclusa -- e nel frattempo l'inventario era sbagliato.
        #
        # Se la porta risponde dove un host NON PUO' ESISTERE, il fatto e' accertato
        # e non ha bisogno di essere anche diffuso: chi risponde la' risponde per il
        # segmento. La conseguenza va detta: su quel segmento la porta non e' piu'
        # utilizzabile come prova nemmeno per un apparato che la offrisse davvero --
        # l'informazione e' indistinguibile, e dichiararla inutilizzabile e' piu'
        # onesto che attribuirla a 128 nodi.
        # La soglia di diffusione dipende da che cosa si sa del SEGMENTO: dove gli
        # indirizzi impossibili rispondono, non si sa nemmeno quali indirizzi siano
        # host, e pretendere il 95% vorrebbe dire attendere la fine della passata con
        # l'inventario sbagliato nel frattempo.
        soglia = (SUSPECT_PREVALENCE_SEGMENTO_SERVITO if subnet in serviti
                  else SUSPECT_MIN_PREVALENCE)
        if not impossibili and prevalenza < soglia:
            continue
        if impossibili:
            spiegazione = (
                "risponde sull'indirizzo di rete o di broadcast della subnet, dove"
                " non puo' esistere un host: la serve un apparato intermedio per"
                " tutto il segmento, non il nodo (aperta sul %d%% dei nodi)"
                % int(prevalenza * 100))
        elif subnet in serviti:
            spiegazione = (
                "su questa subnet l'indirizzo di rete o di broadcast risponde, dove"
                " non puo' esistere un host: un apparato intermedio risponde per tutto"
                " il segmento, e questa porta e' aperta sul %d%% dei nodi -- non e'"
                " attribuibile a nessuno di essi" % int(prevalenza * 100))
        elif famiglie >= SUSPECT_MIN_OS_FAMILIES:
            spiegazione = (
                "aperta sul %d%% dei nodi della subnet e su %d famiglie di sistema"
                " operativo diverse: porta iniettata dalla rete, non del nodo"
                % (int(prevalenza * 100), famiglie))
        else:
            continue
        chiave = (subnet, riga["protocol"], int(riga["port"]))
        sospette.add(chiave)
        motivi[chiave] = spiegazione

    marcate = liberate = 0
    for riga in query("SELECT p.id, p.protocol, p.port, p.is_suspect, n.subnet_id"
                      " FROM node_ports p JOIN nodes n ON n.id = p.node_id"
                      " WHERE p.tenant_id = ?", (tenant_id,)):
        chiave = (riga["subnet_id"], riga["protocol"], int(riga["port"]))
        deve_essere = 1 if chiave in sospette else 0
        if int(riga["is_suspect"] or 0) == deve_essere:
            continue
        execute("UPDATE node_ports SET is_suspect = ?, suspect_reason = ? WHERE id = ?",
                (deve_essere, motivi.get(chiave), int(riga["id"])))
        if deve_essere:
            marcate += 1
        else:
            liberate += 1

    etichette = sorted({"%s/%d" % (p, n) for _s, p, n in sospette})
    if marcate:
        log_event(
            "inventory.ports.suspect",
            "Riconosciute %d porte iniettate dalla rete (%s): escluse dalle prove"
            " del riconoscimento" % (marcate, ", ".join(etichette)),
            tenant_id=tenant_id,
            severity="warning",
            entity="node",
        )
    return {"marked": marcate, "cleared": liberate, "nodes": nodi,
            "ports": etichette}


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
        " contact, pages_read, facts_locked, favicon_hash, favicon_bytes, headers_hash,"
        " headers_names"
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
        # Le impronte di somiglianza. Da sole non dicono che cosa sia l'apparato: lo
        # dicono confrontate con quelle degli altri nodi (vedi `web_twins`).
        "favicon_hash": riga["favicon_hash"], "favicon_bytes": riga["favicon_bytes"],
        "headers_hash": riga["headers_hash"], "headers_names": riga["headers_names"],
    } for riga in righe]


# RICONOSCIMENTO PER SOMIGLIANZA: quanti gemelli si esaminano e quanto devono
# essere d'accordo.
#
# Un gruppo di somiglianza numeroso ma DISCORDE non e' un indizio: l'insieme delle
# intestazioni HTTP di nginx e' lo stesso su una telecamera e su un server, e da
# quel gruppo non si puo' concludere niente. Un gruppo CONCORDE si': se tutti i
# nodi che servono quell'icona sono stampanti, il nodo muto che la serve e' una
# stampante. La soglia e' alta perche' un errore qui si moltiplica su tutto il
# gruppo, che e' esattamente il modo in cui si producono 98 telefoni VoIP
# inesistenti.
MAX_GEMELLI_ESAMINATI = 200
ACCORDO_MINIMO_GEMELLI = 0.80
# Un gemello puo' fare da donatore solo se il suo tipo e' stato dichiarato da una
# persona o se lo ha guadagnato con prove PROPRIE. La soglia impedisce la
# circolarita': la somiglianza da sola vale al massimo 45 di confidenza (un genere
# solo, vedi CONFIDENZA_MASSIMA_UN_GENERE), quindi un nodo riconosciuto per
# somiglianza non puo' diventare donatore di un altro e propagare un'ipotesi come
# se fosse un'osservazione.
CONFIDENZA_MINIMA_DONATORE = 70


def _web_twins_evidence(tenant_id: int, node_id: int) -> list:
    """I nodi che rispondono in rete come questo, e cosa sono risultati essere.

    PERCHE' ESISTE
    La maggior parte degli apparati incorporati non dichiara nulla: un 401 nudo, una
    pagina di accesso senza titolo, nessun `Server`. Il testo non basta, ma la FORMA
    della risposta si': l'icona che l'apparato serve e' un file messo nel firmware dal
    costruttore -- identica su tutti gli esemplari di quel modello -- e l'insieme dei
    nomi delle intestazioni e' l'impronta del programma che risponde.

    Non e' una prova su questo nodo, e' una prova PRESA IN PRESTITO da un altro: per
    questo si dichiara da chi arriva, quanti sono d'accordo, e su quale impronta. Chi
    legge il verdetto deve poter vedere che quella riga dice "somiglia a", non "e'".
    """
    proprie = query(
        "SELECT favicon_hash, headers_hash FROM node_web"
        " WHERE tenant_id = ? AND node_id = ?", (tenant_id, node_id))
    impronte = []
    for riga in proprie:
        if riga["favicon_hash"]:
            impronte.append(("favicon", riga["favicon_hash"]))
        if riga["headers_hash"]:
            impronte.append(("headers", riga["headers_hash"]))

    gruppi = []
    for genere, impronta in dict.fromkeys(impronte):
        # Il nome della colonna viene da queste due righe di codice, non dall'esterno;
        # i valori restano parametri (nessuna concatenazione di dati in SQL).
        colonna = "favicon_hash" if genere == "favicon" else "headers_hash"
        gemelli = query(
            "SELECT w.brand, w.model, w.product, n.device_type, n.device_label,"
            " n.device_confidence, COALESCE(n.device_type_source, 'auto') AS fonte"
            " FROM node_web w JOIN nodes n ON n.id = w.node_id"
            " WHERE w.tenant_id = ? AND w." + colonna + " = ?"
            " AND w.node_id <> ? LIMIT ?",
            (tenant_id, impronta, node_id, MAX_GEMELLI_ESAMINATI))
        gruppo = _accordo_dei_gemelli(genere, impronta, gemelli)
        if gruppo:
            gruppi.append(gruppo)
    return gruppi


def _accordo_dei_gemelli(genere: str, impronta: str, gemelli) -> dict | None:
    """Il tipo su cui i gemelli sono d'accordo, o niente se non lo sono.

    Si contano i voti dei soli gemelli AMMESSI come donatori, e si accetta il tipo
    solo se ne raccoglie almeno `ACCORDO_MINIMO_GEMELLI`. Marca e modello si
    riportano solo se UNANIMI: due modelli diversi nello stesso gruppo vogliono dire
    che l'impronta e' del programma, non dell'apparato, e un modello sbagliato in una
    scheda e' peggio di un modello assente.
    """
    voti: dict[str, int] = {}
    etichette: dict[str, str] = {}
    marche: set[str] = set()
    modelli: set[str] = set()
    prodotti: set[str] = set()
    dichiarati = 0
    for riga in gemelli:
        tipo = (riga["device_type"] or "").strip()
        ammesso = riga["fonte"] == "manual" or (
            (riga["device_confidence"] or 0) >= CONFIDENZA_MINIMA_DONATORE)
        if not tipo or tipo == "unknown" or not ammesso:
            continue
        voti[tipo] = voti.get(tipo, 0) + 1
        etichette.setdefault(tipo, riga["device_label"] or tipo)
        if riga["fonte"] == "manual":
            dichiarati += 1
        if riga["brand"]:
            marche.add(riga["brand"].strip())
        if riga["model"]:
            modelli.add(riga["model"].strip())
        if riga["product"]:
            prodotti.add(riga["product"].strip())

    totale = sum(voti.values())
    if not totale:
        return None
    tipo, quanti = max(voti.items(), key=lambda voce: voce[1])
    accordo = quanti / float(totale)
    if accordo < ACCORDO_MINIMO_GEMELLI:
        return None
    return {
        "kind": genere,
        "hash": impronta,
        "device_type": tipo,
        "device_label": etichette.get(tipo, tipo),
        "nodes": totale,
        "agreement": round(accordo, 3),
        "declared": dichiarati,
        # Solo se unanimi: vedi la docstring.
        "brand": next(iter(marche)) if len(marche) == 1 else None,
        "model": next(iter(modelli)) if len(modelli) == 1 else None,
        "product": next(iter(prodotti)) if len(prodotti) == 1 else None,
    }


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


# Quanti campioni di raggiungibilita' si guardano per misurare la VARIABILITA' della
# latenza. Cinquanta bastano a distinguere un andamento stabile da uno a scatti, e
# tengono la ricostruzione delle prove rapida anche su un inventario grande.
MAX_CAMPIONI_LATENZA = 50


def _latenza_evidence(tenant_id: int, node_id: int, ultima) -> dict:
    """Latenza osservata: ultimo valore, minimo, massimo e scarto.

    Lo SCARTO e' il segnale che conta. Una latenza alta puo' venire da una rete
    carica; una latenza che oscilla fra pochi millisecondi e centinaia e' invece la
    firma di una radio in risparmio energetico -- cioe' di un apparato a batteria,
    telefono o tablet. Un apparato cablato ha un andamento stabile.
    """
    righe = query(
        "SELECT latency_ms FROM monitor_samples"
        " WHERE tenant_id = ? AND node_id = ? AND latency_ms IS NOT NULL"
        " ORDER BY id DESC LIMIT ?", (tenant_id, node_id, MAX_CAMPIONI_LATENZA))
    valori = [float(r["latency_ms"]) for r in righe if r["latency_ms"] is not None]
    if ultima is not None:
        try:
            valori.append(float(ultima))
        except (TypeError, ValueError):
            pass
    if not valori:
        return {}
    return {"ultima": float(ultima) if ultima is not None else None,
            "minima": min(valori), "massima": max(valori),
            "media": sum(valori) / len(valori), "campioni": len(valori)}


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
        # Il tempo di risposta e la sua VARIABILITA'. Non sono un dettaglio di
        # prestazione: su una rete locale distinguono un apparato cablato da uno
        # radio in risparmio energetico, che spegne la radio fra i beacon. Misurato
        # su questa installazione: stampanti 2,3 ms di media, postazioni e server
        # 16 ms, non identificati 216 ms con una coda a 2 secondi. Un PC cablato non
        # arriva mai a quei valori.
        "latency_ms": nodo["latency_ms"],
        "latenza": _latenza_evidence(tenant_id, node_id, nodo["latency_ms"]),
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
        # Prove prese in prestito dai nodi che rispondono come questo: l'unico indizio
        # su un apparato che non dichiara nulla di se' (vedi _web_twins_evidence).
        "web_twins": _web_twins_evidence(tenant_id, node_id),
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
