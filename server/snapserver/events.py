"""
snap server - Sorgenti di evento del sistema, in forma normalizzata.

A che serve
-----------
Le regole di notifica devono poter reagire a QUALUNQUE cosa accada: un nodo nuovo, una
porta che si apre, un controllo che fallisce, una sonda che tace, una scansione che non
finisce, un accesso alla console, un azzeramento dell'archivio di una sonda. Queste
cose sono gia' registrate, ma ognuna in una tabella con nomi propri.

Questo modulo le presenta tutte nella stessa forma:

    {
      "source": "node_changes", "source_id": 6947, "type": "port.opened",
      "severity": "warning", "subject": "tcp/2000", "detail": "...",
      "occurred_at": "2026-08-28 08:36:31", "tenant_id": 3,
      "attributi": {"node_ip": "10.2.34.1", "port": 2000, "protocol": "tcp",
                    "before": "", "after": "cisco-sccp", ...}
    }

Le condizioni delle regole si scrivono sugli attributi con lo stesso vocabolario delle
verifiche sui controlli (eq, ne, contains, gt, lt, exists, absent): chi ha imparato
l'uno sa usare l'altro.

Perche' si legge dalle tabelle e non si intercettano le scritture
-----------------------------------------------------------------
Gli eventi nascono in posti diversi -- il conferimento di un lotto, un'azione
dell'operatore, un thread di servizio -- e in alcuni casi in un processo che non ha un
contesto applicativo. Leggere le tabelle con un cursore rende il valutatore
indipendente da CHI ha prodotto l'evento, e sopravvive a un riavvio: un aggancio alle
scritture perderebbe tutto cio' che e' accaduto mentre il valutatore era spento.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from .db import query, utc_now_str

# Quanti eventi si leggono al massimo per ogni giro del valutatore. Una passata di
# scoperta ne produce migliaia: il lotto limitato evita che un giro monopolizzi il
# processo, e il cursore garantisce che il resto venga letto al giro successivo.
BATCH_SIZE = 500


def _porta_da_soggetto(soggetto: str) -> tuple:
    """"tcp/2000" -> ("tcp", 2000). Qualunque altra forma -> (None, None)."""
    testo = (soggetto or "").strip().lower()
    if "/" not in testo:
        return None, None
    protocollo, _, numero = testo.partition("/")
    if protocollo not in ("tcp", "udp") or not numero.isdigit():
        return None, None
    return protocollo, int(numero)


# --------------------------------------------------------------------------- #
# Normalizzatori: una funzione per sorgente
# --------------------------------------------------------------------------- #
def _da_node_changes(riga) -> dict:
    protocollo, porta = _porta_da_soggetto(riga["subject"])
    return {
        "type": riga["kind"],
        "severity": riga["severity"] or "info",
        "subject": riga["subject"],
        "detail": "%s -> %s" % (riga["before_value"] or "-", riga["after_value"] or "-"),
        "attributi": {
            "node_ip": riga["node_ip"],
            "node_hostname": riga["node_hostname"] or "",
            "node_type": riga["device_type"] or "",
            "node_os": riga["os_name"] or "",
            "subnet": riga["cidr"] or "",
            "protocol": protocollo or "",
            "port": porta,
            "before": riga["before_value"] or "",
            "after": riga["after_value"] or "",
            "service": riga["after_value"] or "" if riga["kind"].startswith("port.") else "",
        },
    }


def _da_check_results(riga) -> dict:
    return {
        "type": "check.%s" % riga["status"],
        "severity": "critical" if riga["status"] == "error" else "warning",
        "subject": riga["address"],
        "detail": (riga["detail"] or "")[:300],
        "attributi": {
            "check_name": riga["check_name"],
            "check_kind": riga["kind"],
            "address": riga["address"],
            "target": riga["target_name"] or "",
            "status": riga["status"],
            "latency_ms": riga["latency_ms"],
            "severity_check": riga["severity"] or "",
        },
    }


def _da_check_incident_events(riga) -> dict:
    return {
        "type": "incident.%s" % riga["action"],
        "severity": riga["severity"] or "warning",
        "subject": riga["address"],
        "detail": (riga["note"] or "")[:300],
        "attributi": {
            "incident_id": riga["incident_id"],
            "action": riga["action"],
            "actor": riga["actor"] or "",
            "check_name": riga["check_name"] or "",
            "address": riga["address"] or "",
            "severity_incident": riga["severity"] or "",
        },
    }


def _da_scan_runs(riga) -> dict:
    return {
        "type": "scan.%s" % riga["status"],
        "severity": "info" if riga["status"] == "completed" else "warning",
        "subject": "%s su %s" % (riga["stage"], riga["target"] or "perimetro"),
        "detail": (riga["detail"] or "")[:300],
        "attributi": {
            "stage": riga["stage"],
            "status": riga["status"],
            "probe": riga["probe_name"] or "",
            "hosts_total": riga["hosts_total"],
            "hosts_up": riga["hosts_up"],
            "records": riga["records"],
            "duration_ms": riga["duration_ms"],
        },
    }


def _da_ingest_batches(riga) -> dict:
    return {
        "type": "ingest.%s" % (riga["status"] or "unknown"),
        "severity": "info" if riga["status"] == "accepted" else "warning",
        "subject": riga["probe_name"] or "sonda",
        "detail": (riga["detail"] or "")[:300],
        "attributi": {
            "probe": riga["probe_name"] or "",
            "status": riga["status"] or "",
            "records": riga["record_count"],
            "bytes": riga["payload_bytes"],
        },
    }


def _da_ti_findings(riga) -> dict:
    return {
        "type": "threat.%s" % riga["kind"],
        "severity": riga["severity"] or "info",
        "subject": riga["ip"],
        "detail": (riga["title"] or "")[:300],
        "attributi": {
            "kind": riga["kind"],
            "cve_id": riga["cve_id"] or "",
            "technique_id": riga["technique_id"] or "",
            "kev": 1 if riga["kev"] else 0,
            "score": riga["score"],
            "node_ip": riga["ip"],
            "node_hostname": riga["hostname"] or "",
            "product": riga["product"] or "",
            "version": riga["version"] or "",
            "port": riga["port"],
            "protocol": riga["protocol"] or "",
            "confidence": riga["confidence"],
            "evidence": (riga["evidence"] or "")[:300],
        },
    }


def _da_audit_events(riga) -> dict:
    return {
        "type": riga["event_type"],
        "severity": riga["severity"] or "info",
        "subject": riga["actor"] or "sistema",
        "detail": (riga["description"] or "")[:300],
        "attributi": {
            "actor": riga["actor"] or "",
            "event_type": riga["event_type"],
            "entity": riga["entity"] or "",
            "entity_id": riga["entity_id"],
            "source_ip": riga["source_ip"] or "",
            "user": riga["full_name"] or "",
        },
    }


# --------------------------------------------------------------------------- #
# Registro delle sorgenti
# --------------------------------------------------------------------------- #
SOURCES = {
    "node_changes": {
        "etichetta": "Inventario: variazioni dei nodi",
        "descrizione": "Nodi comparsi o scomparsi, porte aperte o chiuse, cambi di"
                       " tipo, sistema operativo, nome host, indirizzo fisico.",
        "quando": "nc.created_at",
        "id": "nc.id",
        "tipo": "nc.kind",
        "sql": "SELECT nc.id, nc.tenant_id, nc.kind, nc.subject, nc.before_value,"
               " nc.after_value, nc.severity, nc.created_at, n.ip AS node_ip,"
               " n.hostname AS node_hostname, n.device_type, n.os_name, s.cidr"
               " FROM node_changes nc"
               " LEFT JOIN nodes n ON n.id = nc.node_id"
               " LEFT JOIN subnets s ON s.id = n.subnet_id",
        "normalizza": _da_node_changes,
        "tipi": ["node.appeared", "node.disappeared", "node.up", "node.down",
                 "port.opened", "port.closed", "device_type.changed", "os.changed",
                 "hostname.changed", "mac.changed", "service.changed"],
        "attributi": ["node_ip", "node_hostname", "node_type", "node_os", "subnet",
                      "protocol", "port", "before", "after", "service"],
    },
    "check_results": {
        "etichetta": "Controlli: esiti",
        "descrizione": "Ogni esito di un controllo periodico. Utile per reagire al"
                       " singolo fallimento senza attendere la soglia dell'incidente.",
        "quando": "r.executed_at",
        "id": "r.id",
        "tipo": "'check.' || r.status",
        "sql": "SELECT r.id, r.tenant_id, r.status, r.detail, r.latency_ms,"
               " r.executed_at AS created_at, c.name AS check_name, c.kind, c.severity,"
               " t.address, t.name AS target_name"
               " FROM check_results r JOIN checks c ON c.id = r.check_id"
               " JOIN check_targets t ON t.id = c.target_id",
        "normalizza": _da_check_results,
        "tipi": ["check.ok", "check.fail", "check.error"],
        "attributi": ["check_name", "check_kind", "address", "target", "status",
                      "latency_ms", "severity_check"],
    },
    "check_incident_events": {
        "etichetta": "Controlli: passaggi degli incidenti",
        "descrizione": "Apertura, attivazione dell'operatore, presa in carico,"
                       " rientro, risoluzione.",
        "quando": "e.created_at",
        "id": "e.id",
        "tipo": "'incident.' || e.action",
        "sql": "SELECT e.id, e.tenant_id, e.incident_id, e.action, e.actor, e.note,"
               " e.created_at, i.severity, c.name AS check_name, t.address"
               " FROM check_incident_events e"
               " LEFT JOIN check_incidents i ON i.id = e.incident_id"
               " LEFT JOIN checks c ON c.id = i.check_id"
               " LEFT JOIN check_targets t ON t.id = c.target_id",
        "normalizza": _da_check_incident_events,
        "tipi": ["incident.opened", "incident.escalated", "incident.acknowledged",
                 "incident.recovered", "incident.resolved"],
        "attributi": ["incident_id", "action", "actor", "check_name", "address",
                      "severity_incident"],
    },
    "scan_runs": {
        "etichetta": "Sonde: passate di scansione",
        "descrizione": "Esito di ogni passata: completata, fallita, scaduta. Serve a"
                       " sapere che l'inventario ha smesso di aggiornarsi.",
        "quando": "sr.created_at",
        "id": "sr.id",
        "tipo": "'scan.' || sr.status",
        "sql": "SELECT sr.id, sr.tenant_id, sr.stage, sr.status, sr.target, sr.detail,"
               " sr.hosts_total, sr.hosts_up, sr.records, sr.duration_ms,"
               " sr.created_at, p.name AS probe_name"
               " FROM scan_runs sr LEFT JOIN probes p ON p.id = sr.probe_id",
        "normalizza": _da_scan_runs,
        "tipi": ["scan.completed", "scan.failed", "scan.timeout", "scan.error"],
        "attributi": ["stage", "status", "probe", "hosts_total", "hosts_up",
                      "records", "duration_ms"],
    },
    "ingest_batches": {
        "etichetta": "Sonde: conferimenti",
        "descrizione": "Lotti ricevuti dalle sonde, compresi quelli rifiutati.",
        "quando": "b.received_at",
        "id": "b.id",
        "tipo": "'ingest.' || b.status",
        "sql": "SELECT b.id, b.tenant_id, b.status, b.detail, b.record_count,"
               " b.payload_bytes, b.received_at AS created_at, p.name AS probe_name"
               " FROM ingest_batches b LEFT JOIN probes p ON p.id = b.probe_id",
        "normalizza": _da_ingest_batches,
        "tipi": ["ingest.accepted", "ingest.rejected", "ingest.duplicate"],
        "attributi": ["probe", "status", "records", "bytes"],
    },
    "ti_findings": {
        "etichetta": "Threat intelligence: riscontri sui nodi",
        "descrizione": "Vulnerabilita' confermate, riscontri da verificare ed"
                       " esposizioni dei servizi, come li produce la correlazione con"
                       " il catalogo locale.",
        "quando": "f.first_seen_at",
        "id": "f.id",
        "tipo": "'threat.' || f.kind",
        "sql": "SELECT f.id, f.tenant_id, f.kind, f.cve_id, f.technique_id, f.severity,"
               " f.score, f.title, f.evidence, f.product, f.version, f.confidence,"
               " f.first_seen_at AS created_at, n.ip, n.hostname, p.port, p.protocol,"
               " c.kev FROM ti_findings f"
               " JOIN nodes n ON n.id = f.node_id"
               " LEFT JOIN node_ports p ON p.id = f.port_id"
               " LEFT JOIN ti_cve c ON c.cve_id = f.cve_id",
        "normalizza": _da_ti_findings,
        "tipi": ["threat.confirmed", "threat.potential", "threat.exposure"],
        "attributi": ["kind", "cve_id", "technique_id", "kev", "score", "node_ip",
                      "node_hostname", "product", "version", "port", "protocol",
                      "confidence", "evidence"],
    },
    "audit_events": {
        "etichetta": "Sistema: registro delle azioni",
        "descrizione": "Accessi riusciti e falliti, modifiche alla configurazione,"
                       " comandi alle sonde, azzeramenti dell'archivio, cancellazioni.",
        "quando": "a.created_at",
        "id": "a.id",
        "tipo": "a.event_type",
        "sql": "SELECT a.id, a.tenant_id, a.event_type, a.severity, a.actor,"
               " a.description, a.entity, a.entity_id, a.source_ip, a.created_at,"
               " u.full_name FROM audit_events a LEFT JOIN users u ON u.id = a.user_id",
        "normalizza": _da_audit_events,
        "tipi": ["auth.login", "auth.login.failed", "auth.logout",
                 "probe.enrolled", "probe.revoked", "probe.store.reset",
                 "settings.updated", "settings.notifications",
                 "tenant.created", "tenant.deleted", "user.created", "user.deleted",
                 "checks.check.created", "checks.check.deleted",
                 "checks.incident.opened", "report.daily.sent"],
        "attributi": ["actor", "event_type", "entity", "entity_id", "source_ip", "user"],
    },
}


def source_label(source: str) -> str:
    voce = SOURCES.get(source)
    return voce["etichetta"] if voce else source


def cursor_of(source: str) -> int:
    riga = query("SELECT last_id FROM event_cursors WHERE source = ?", (source,), one=True)
    return int(riga["last_id"]) if riga else 0


def set_cursor(source: str, last_id: int) -> None:
    from .db import execute

    execute("INSERT INTO event_cursors (source, last_id, updated_at) VALUES (?, ?, ?)"
            " ON CONFLICT(source) DO UPDATE SET last_id = excluded.last_id,"
            " updated_at = excluded.updated_at", (source, int(last_id), utc_now_str()))


def initialize_cursors() -> dict:
    """Porta i cursori alla fine dell'archivio, senza valutare nulla.

    Si chiama al primo avvio con le regole attive: diversamente il primo giro
    valuterebbe tutto lo storico -- 3131 variazioni -- e produrrebbe una raffica di
    notifiche su fatti vecchi di settimane.
    """
    posizioni = {}
    for source, voce in SOURCES.items():
        massimo = query("SELECT MAX(%s) AS m FROM (%s)"
                        % (voce["id"].split(".")[-1], voce["sql"]), (), one=True)
        ultimo = int(massimo["m"] or 0) if massimo else 0
        if ultimo > cursor_of(source):
            set_cursor(source, ultimo)
        posizioni[source] = ultimo
    return posizioni


def fetch_new(source: str, dopo: int = None, limit: int = BATCH_SIZE,
              tenant_id: int = None) -> list:
    """Eventi normalizzati successivi al cursore (o a `dopo`), in ordine di apparizione."""
    voce = SOURCES.get(source)
    if voce is None:
        raise ValueError("sorgente di evento non prevista: %r" % source)
    da = cursor_of(source) if dopo is None else int(dopo)

    condizioni = ["%s > ?" % voce["id"]]
    parametri = [da]
    if tenant_id is not None:
        condizioni.append("%s = ?" % _colonna_tenant(voce))
        parametri.append(tenant_id)
    parametri.append(int(limit))

    sql = "%s WHERE %s ORDER BY %s LIMIT ?" % (
        voce["sql"], " AND ".join(condizioni), voce["id"])
    return [_normalizza(source, voce, riga) for riga in query(sql, parametri)]


def fetch_recent(source: str, limit: int = 50, tenant_id: int = None) -> list:
    """Ultimi eventi della sorgente, per la prova di una regola sulla storia.

    La prova guarda il passato e non spedisce nulla: e' il modo di sapere che cosa una
    regola avrebbe fatto, prima di attivarla.
    """
    voce = SOURCES.get(source)
    if voce is None:
        raise ValueError("sorgente di evento non prevista: %r" % source)
    condizioni = []
    parametri = []
    if tenant_id is not None:
        condizioni.append("%s = ?" % _colonna_tenant(voce))
        parametri.append(tenant_id)
    parametri.append(int(limit))
    sql = "%s%s ORDER BY %s DESC LIMIT ?" % (
        voce["sql"], (" WHERE " + " AND ".join(condizioni)) if condizioni else "",
        voce["id"])
    return [_normalizza(source, voce, riga) for riga in query(sql, parametri)]


def _colonna_tenant(voce: dict) -> str:
    """Colonna del tenant qualificata con l'alias della sorgente."""
    alias = voce["id"].split(".")[0]
    return "%s.tenant_id" % alias if "." in voce["id"] else "tenant_id"


def _normalizza(source: str, voce: dict, riga) -> dict:
    normalizzato = voce["normalizza"](riga)
    normalizzato.update({
        "source": source,
        "source_id": int(riga["id"]),
        "tenant_id": int(riga["tenant_id"]) if riga["tenant_id"] is not None else None,
        "occurred_at": riga["created_at"],
    })
    return normalizzato


def event_fields(source: str) -> list:
    """Attributi su cui si possono scrivere condizioni, per la pagina."""
    voce = SOURCES.get(source) or {}
    comuni = ["type", "severity", "subject", "detail"]
    return comuni + list(voce.get("attributi", []))
