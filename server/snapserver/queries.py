"""
snap server - Query di lettura aggregate (dashboard e indicatori).

Tutte le funzioni ricevono esplicitamente il tenant su cui operare: nessuna
lettura di dominio e' possibile senza dichiarare il perimetro di isolamento.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from flask import current_app, g

from .tenancy import fmt_bytes
from .db import days_ago_str, parse_utc, query, scalar, utc_now

AUDIT_SEVERITY_LABELS = {
    "info": "Informativa",
    "warning": "Attenzione",
    "critical": "Critica",
}


# --------------------------------------------------------------------------- #
# Flotta sonde
# --------------------------------------------------------------------------- #
def probe_summary(tenant_id: int) -> dict:
    """Stato della flotta sonde: in contatto se il collegamento e' recente."""
    threshold = current_app.config["PROBE_OFFLINE_AFTER_SEC"]
    rows = query(
        "SELECT status, last_seen_at FROM probes WHERE tenant_id = ? AND revoked_at IS NULL",
        (tenant_id,),
    )
    online = 0
    pending = 0
    for row in rows:
        if row["status"] == "pending":
            pending += 1
            continue
        seen = parse_utc(row["last_seen_at"])
        if seen and (utc_now() - seen).total_seconds() <= threshold:
            online += 1
    total = len(rows)
    return {
        "total": total,
        "online": online,
        "offline": total - online - pending,
        "pending": pending,
    }


def probe_fleet(tenant_id: int) -> list[dict]:
    """Elenco sonde con stato di raggiungibilita' calcolato."""
    threshold = current_app.config["PROBE_OFFLINE_AFTER_SEC"]
    rows = query(
        "SELECT * FROM probes WHERE tenant_id = ? ORDER BY name COLLATE NOCASE", (tenant_id,)
    )
    fleet = []
    for row in rows:
        item = dict(row)
        seen = parse_utc(row["last_seen_at"])
        if row["revoked_at"]:
            item["health"] = "revoked"
        elif row["status"] == "pending":
            item["health"] = "pending"
        elif seen and (utc_now() - seen).total_seconds() <= threshold:
            item["health"] = "online"
        else:
            item["health"] = "offline"
        fleet.append(item)
    return fleet


# --------------------------------------------------------------------------- #
# Conferimenti e registro eventi
# --------------------------------------------------------------------------- #
def recent_batches(tenant_id: int, limit: int = 10) -> list[dict]:
    rows = query(
        "SELECT b.*, p.name AS probe_name, p.code AS probe_code FROM ingest_batches b"
        " LEFT JOIN probes p ON p.id = b.probe_id AND p.tenant_id = b.tenant_id"
        " WHERE b.tenant_id = ? ORDER BY b.received_at DESC LIMIT ?",
        (tenant_id, limit),
    )
    return [dict(row) for row in rows]


def recent_audit(tenant_id: int, limit: int = 8) -> list[dict]:
    rows = query(
        "SELECT * FROM audit_events WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?",
        (tenant_id, limit),
    )
    return [dict(row) for row in rows]


# --------------------------------------------------------------------------- #
# Indicatori
# --------------------------------------------------------------------------- #
def navbar_indicators() -> dict:
    """Indicatori sintetici mostrati nella barra superiore.

    Deve funzionare anche senza contesto tenant (pagine di accesso): in tal caso
    restituisce valori neutri.
    """
    tenant = getattr(g, "tenant", None)
    user = getattr(g, "user", None)
    if tenant is None or user is None:
        return {"available": False}

    tenant_id = int(tenant["id"])
    probes = probe_summary(tenant_id)
    last_sync = scalar(
        "SELECT MAX(received_at) FROM ingest_batches WHERE tenant_id = ?",
        (tenant_id,),
        default=None,
    )
    return {
        "available": True,
        "probes_online": probes["online"],
        "probes_total": probes["total"],
        "probes_pending": probes["pending"],
        "last_sync_at": last_sync,
        "pending_commands": scalar(
            "SELECT COUNT(*) FROM probe_commands WHERE tenant_id = ? AND status = 'pending'",
            (tenant_id,),
        ),
        "events_today": scalar(
            "SELECT COUNT(*) FROM audit_events WHERE tenant_id = ?"
            " AND severity IN ('warning', 'critical') AND created_at >= ?",
            (tenant_id, days_ago_str(1)),
        ),
        # Nodi in inventario: nel menu e' la misura di quanto il prodotto conosce
        # della rete, ed e' la prima cosa che si guarda dopo una scoperta.
        "nodes_total": scalar(
            "SELECT COUNT(*) FROM nodes WHERE tenant_id = ?", (tenant_id,),
        ),
        # Controlli attivi e incidenti aperti: il primo dice quanta sorveglianza e'
        # in vigore, il secondo se c'e' qualcosa da guardare adesso. Servono
        # entrambi, e nel menu compaiono con colori diversi.
        "checks_active": scalar(
            "SELECT COUNT(*) FROM checks WHERE tenant_id = ? AND is_enabled = 1",
            (tenant_id,),
        ),
        "incidents_open": scalar(
            "SELECT COUNT(*) FROM check_incidents WHERE tenant_id = ?"
            " AND status IN ('open', 'ack')", (tenant_id,),
        ),
        # Regole attive: nel menu dice quante notifiche automatiche sono in vigore,
        # perche' una regola dimenticata continua a spedire.
        "rules_active": scalar(
            "SELECT COUNT(*) FROM notify_rules WHERE tenant_id = ? AND is_enabled = 1",
            (tenant_id,),
        ),
        # Riscontri di threat intelligence: i confermati hanno la precedenza nel menu,
        # perche' sono gli unici di cui si possa dire che riguardano davvero un nodo.
        "threat_confirmed": scalar(
            "SELECT COUNT(*) FROM ti_findings WHERE tenant_id = ? AND status = 'open'"
            " AND kind = 'confirmed'", (tenant_id,),
        ),
        "threat_open": scalar(
            "SELECT COUNT(*) FROM ti_findings WHERE tenant_id = ? AND status = 'open'",
            (tenant_id,),
        ),
    }


def kpi_keys() -> set:
    """Chiavi di tutti gli indicatori dell'area indicatori.

    Serve come allowlist alla preferenza "nascondi": si ricava dagli indicatori
    stessi, cosi' non esiste un secondo elenco da tenere allineato a mano. Si
    calcola su un tenant inesistente -- i valori non contano, contano le chiavi.
    """
    from .inventory_queries import inventory_indicators

    voci = dashboard_indicators(0) + inventory_indicators(0)
    chiavi = [voce["key"] for voce in voci]
    # Guardia: due indicatori con la stessa chiave sono un difetto, e silenzioso.
    # Era gia' successo (copertura delle sonde e copertura del perimetro), e
    # l'effetto era che nasconderne uno ne nascondeva due.
    duplicate = {c for c in chiavi if chiavi.count(c) > 1}
    if duplicate:
        raise RuntimeError("indicatori con chiave duplicata: %s" % ", ".join(sorted(duplicate)))
    return set(chiavi)


def dashboard_indicators(tenant_id: int) -> list[dict]:
    """Indicatori della dashboard: flotta sonde, conferimenti e attivita'."""
    probes = probe_summary(tenant_id)

    batches_24h = scalar(
        "SELECT COUNT(*) FROM ingest_batches WHERE tenant_id = ? AND received_at >= ?",
        (tenant_id, days_ago_str(1)),
    )
    records_24h = scalar(
        "SELECT COALESCE(SUM(record_count), 0) FROM ingest_batches"
        " WHERE tenant_id = ? AND received_at >= ?",
        (tenant_id, days_ago_str(1)),
    )
    bytes_24h = scalar(
        "SELECT COALESCE(SUM(payload_bytes), 0) FROM ingest_batches"
        " WHERE tenant_id = ? AND received_at >= ?",
        (tenant_id, days_ago_str(1)),
    )
    comandi_attesa = scalar(
        "SELECT COUNT(*) FROM probe_commands WHERE tenant_id = ? AND status = 'pending'",
        (tenant_id,),
    )
    eventi_gravi_7g = scalar(
        "SELECT COUNT(*) FROM audit_events WHERE tenant_id = ?"
        " AND severity IN ('warning', 'critical') AND created_at >= ?",
        (tenant_id, days_ago_str(7)),
    )

    return [
        {
            "key": "coverage",
            "label": "Copertura sonde",
            "value": "%d/%d" % (probes["online"], probes["total"]),
            "hint": "sonde in contatto sul totale censito",
            "icon": "bi-broadcast-pin",
            "tone": "success" if probes["total"] and probes["online"] == probes["total"] else "warning",
        },
        {
            "key": "pending",
            "label": "In attesa di registrazione",
            "value": str(probes["pending"]),
            "hint": "token emessi e non ancora utilizzati",
            "icon": "bi-key",
            "tone": "warning" if probes["pending"] else "secondary",
        },
        {
            "key": "flow",
            "label": "Conferimenti 24h",
            "value": str(batches_24h),
            "hint": "%d record acquisiti" % records_24h,
            "icon": "bi-cloud-arrow-down",
            "tone": "info" if batches_24h else "warning",
        },
        {
            "key": "volume",
            "label": "Dati ricevuti 24h",
            "value": fmt_bytes(bytes_24h),
            "hint": "volume complessivo sul canale cifrato",
            "icon": "bi-hdd",
            "tone": "secondary",
        },
        {
            "key": "commands",
            "label": "Comandi in attesa",
            "value": str(comandi_attesa),
            "hint": "consegnati al prossimo contatto della sonda",
            "icon": "bi-terminal",
            "tone": "warning" if comandi_attesa else "secondary",
        },
        {
            "key": "events",
            "label": "Eventi rilevanti 7g",
            "value": str(eventi_gravi_7g),
            "hint": "voci di audit con gravita' alta",
            "icon": "bi-journal-text",
            "tone": "danger" if eventi_gravi_7g else "success",
        },
    ]
