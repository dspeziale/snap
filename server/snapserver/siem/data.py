# -----------------------------------------------------------------
# data.py — accesso alle tabelle di configurazione del SIEM (collettori, sorgenti,
#           regole, allarmi) nel database della console
# Autore: Daniele Speziale
# Data creazione: 2026-09-02
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Configurazione e stato del SIEM nel database della console.

Qui stanno le righe di GOVERNO (collettori, sorgenti dichiarate, regole, allarmi):
poche, consultate dalle pagine, appartengono al database principale come tutto il
resto della console. Gli EVENTI, che sono tanti e ad alta frequenza, stanno invece
nel database dedicato (`store.py`). La separazione e' voluta: qui si legge, la',
si scrive a valanga.
"""

from __future__ import annotations

from ..crypto import generate_api_key, token_fingerprint
from ..db import execute, query, utc_now_str


# --------------------------------------------------------------------------- #
# Collettori
# --------------------------------------------------------------------------- #
def create_collector(tenant_id: int, name: str, kind: str = "vector") -> tuple:
    """Crea un collettore e restituisce (id, token in chiaro).

    Il token si mostra UNA volta: viene conservato solo come impronta, come l'API
    key di una sonda. Chi lo perde lo rigenera, non lo rilegge.
    """
    token = generate_api_key()
    adesso = utc_now_str()
    collector_id = execute(
        "INSERT INTO siem_collectors (tenant_id, name, kind, token_hash, created_at,"
        " updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (tenant_id, name.strip(), kind, token_fingerprint(token), adesso, adesso))
    return collector_id, token


def rotate_collector_token(tenant_id: int, collector_id: int) -> str | None:
    """Rigenera il token di un collettore. Restituisce il nuovo token in chiaro."""
    riga = query("SELECT id FROM siem_collectors WHERE id = ? AND tenant_id = ?",
                 (collector_id, tenant_id), one=True)
    if riga is None:
        return None
    token = generate_api_key()
    execute("UPDATE siem_collectors SET token_hash = ?, updated_at = ? WHERE id = ?",
            (token_fingerprint(token), utc_now_str(), collector_id))
    return token


def collector_by_token(token: str) -> dict | None:
    """Il collettore che possiede questo token, se attivo. Il confronto e' sull'impronta."""
    if not token:
        return None
    riga = query("SELECT * FROM siem_collectors WHERE token_hash = ? AND is_enabled = 1",
                 (token_fingerprint(token),), one=True)
    return dict(riga) if riga else None


def touch_collector(collector_id: int, quanti: int) -> None:
    """Aggiorna ultimo contatto e conteggio del collettore dopo un lotto."""
    execute("UPDATE siem_collectors SET last_seen_at = ?, events_total = events_total + ?,"
            " updated_at = ? WHERE id = ?",
            (utc_now_str(), int(quanti), utc_now_str(), collector_id))


def manual_collector(tenant_id: int) -> dict:
    """Il collettore di servizio per l'inserimento manuale dei log, creato una volta.

    Serve alla finestra "Incolla log": e' un collettore come gli altri, cosi' gli
    eventi incollati passano dalla stessa pipeline e alimentano la stessa rilevazione.
    """
    riga = query("SELECT * FROM siem_collectors WHERE tenant_id = ? AND kind = 'manual'",
                 (tenant_id,), one=True)
    if riga:
        return dict(riga)
    adesso = utc_now_str()
    cid = execute(
        "INSERT INTO siem_collectors (tenant_id, name, kind, token_hash, created_at,"
        " updated_at) VALUES (?, 'Inserimento manuale', 'manual', ?, ?, ?)",
        (tenant_id, token_fingerprint(generate_api_key()), adesso, adesso))
    return dict(query("SELECT * FROM siem_collectors WHERE id = ?", (cid,), one=True))


def collectors(tenant_id: int) -> list:
    # I collettori di servizio (inserimento manuale, listener integrato) non si
    # elencano: non hanno un token da consegnare a nessuno.
    return [dict(r) for r in query(
        "SELECT * FROM siem_collectors WHERE tenant_id = ?"
        " AND kind NOT IN ('manual', 'listener') ORDER BY name", (tenant_id,))]


def delete_collector(tenant_id: int, collector_id: int) -> bool:
    riga = query("SELECT id FROM siem_collectors WHERE id = ? AND tenant_id = ?",
                 (collector_id, tenant_id), one=True)
    if riga is None:
        return False
    execute("DELETE FROM siem_collectors WHERE id = ?", (collector_id,))
    return True


# --------------------------------------------------------------------------- #
# Sorgenti
# --------------------------------------------------------------------------- #
def create_source(tenant_id: int, name: str, kind: str, vendor: str = "",
                  match_host: str = "", match_ip: str = "", node_id: int = None,
                  notes: str = "") -> int:
    adesso = utc_now_str()
    return execute(
        "INSERT INTO siem_sources (tenant_id, name, kind, vendor, match_host,"
        " match_ip, node_id, notes, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (tenant_id, name.strip(), kind, vendor.strip() or None,
         match_host.strip() or None, match_ip.strip() or None, node_id,
         notes.strip() or None, adesso, adesso))


def update_source(tenant_id: int, source_id: int, **campi) -> bool:
    riga = query("SELECT id FROM siem_sources WHERE id = ? AND tenant_id = ?",
                 (source_id, tenant_id), one=True)
    if riga is None:
        return False
    consentiti = ("name", "kind", "vendor", "match_host", "match_ip", "node_id",
                  "is_enabled", "notes")
    da_scrivere = {k: v for k, v in campi.items() if k in consentiti}
    if not da_scrivere:
        return True
    assegnazioni = ", ".join("%s = ?" % k for k in da_scrivere)
    execute("UPDATE siem_sources SET %s, updated_at = ? WHERE id = ?" % assegnazioni,
            list(da_scrivere.values()) + [utc_now_str(), source_id])
    return True


def delete_source(tenant_id: int, source_id: int) -> bool:
    riga = query("SELECT id FROM siem_sources WHERE id = ? AND tenant_id = ?",
                 (source_id, tenant_id), one=True)
    if riga is None:
        return False
    execute("DELETE FROM siem_sources WHERE id = ?", (source_id,))
    return True


def sources(tenant_id: int) -> list:
    return [dict(r) for r in query(
        "SELECT s.*, n.ip AS node_ip, n.hostname AS node_hostname"
        " FROM siem_sources s LEFT JOIN nodes n ON n.id = s.node_id"
        " WHERE s.tenant_id = ? ORDER BY s.name", (tenant_id,))]


def source(tenant_id: int, source_id: int) -> dict | None:
    riga = query("SELECT * FROM siem_sources WHERE id = ? AND tenant_id = ?",
                 (source_id, tenant_id), one=True)
    return dict(riga) if riga else None


def enabled_sources(tenant_id: int) -> list:
    """Le sorgenti attive, per attribuire gli eventi in ingestione. Poche righe,
    lette a ogni lotto: il chiamante le tiene in memoria per la durata del lotto."""
    return [dict(r) for r in query(
        "SELECT id, kind, match_host, match_ip, node_id FROM siem_sources"
        " WHERE tenant_id = ? AND is_enabled = 1", (tenant_id,))]


def touch_source(source_id: int, quanti: int, ultimo: str) -> None:
    execute("UPDATE siem_sources SET last_event_at = ?, events_total = events_total + ?,"
            " updated_at = ? WHERE id = ?", (ultimo, int(quanti), utc_now_str(), source_id))


# --------------------------------------------------------------------------- #
# Regole
# --------------------------------------------------------------------------- #
def rules(tenant_id: int, solo_attive: bool = False) -> list:
    clausola = " AND is_enabled = 1" if solo_attive else ""
    return [dict(r) for r in query(
        "SELECT * FROM siem_rules WHERE tenant_id = ?" + clausola
        + " ORDER BY severity, name", (tenant_id,))]


def rule(tenant_id: int, rule_id: int) -> dict | None:
    riga = query("SELECT * FROM siem_rules WHERE id = ? AND tenant_id = ?",
                 (rule_id, tenant_id), one=True)
    return dict(riga) if riga else None


def set_rule_enabled(tenant_id: int, rule_id: int, attiva: bool) -> bool:
    riga = query("SELECT id FROM siem_rules WHERE id = ? AND tenant_id = ?",
                 (rule_id, tenant_id), one=True)
    if riga is None:
        return False
    execute("UPDATE siem_rules SET is_enabled = ?, updated_at = ? WHERE id = ?",
            (1 if attiva else 0, utc_now_str(), rule_id))
    return True


def update_rule(tenant_id: int, rule_id: int, threshold: int,
                window_seconds: int, severity: str) -> bool:
    riga = query("SELECT id FROM siem_rules WHERE id = ? AND tenant_id = ?",
                 (rule_id, tenant_id), one=True)
    if riga is None:
        return False
    execute("UPDATE siem_rules SET threshold = ?, window_seconds = ?, severity = ?,"
            " updated_at = ? WHERE id = ?",
            (int(threshold), int(window_seconds), severity, utc_now_str(), rule_id))
    return True


# --------------------------------------------------------------------------- #
# Allarmi
# --------------------------------------------------------------------------- #
def alerts(tenant_id: int, status: str = "", severity: str = "", limit: int = 500) -> list:
    where = ["a.tenant_id = ?"]
    params: list = [tenant_id]
    if status:
        where.append("a.status = ?")
        params.append(status)
    if severity:
        where.append("a.severity = ?")
        params.append(severity)
    return [dict(r) for r in query(
        "SELECT a.*, n.ip AS node_ip, n.hostname AS node_hostname"
        " FROM siem_alerts a LEFT JOIN nodes n ON n.id = a.node_id"
        " WHERE " + " AND ".join(where)
        + " ORDER BY CASE a.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
        "   WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, a.last_event_at DESC"
        " LIMIT ?", params + [int(limit)])]


def alert(tenant_id: int, alert_id: int) -> dict | None:
    riga = query(
        "SELECT a.*, n.ip AS node_ip, n.hostname AS node_hostname"
        " FROM siem_alerts a LEFT JOIN nodes n ON n.id = a.node_id"
        " WHERE a.id = ? AND a.tenant_id = ?", (alert_id, tenant_id), one=True)
    return dict(riga) if riga else None


def alert_counts(tenant_id: int) -> dict:
    righe = query(
        "SELECT status, severity, COUNT(*) AS n FROM siem_alerts"
        " WHERE tenant_id = ? GROUP BY status, severity", (tenant_id,))
    per_stato: dict = {}
    per_gravita_aperti: dict = {}
    for r in righe:
        per_stato[r["status"]] = per_stato.get(r["status"], 0) + int(r["n"])
        if r["status"] in ("open", "ack"):
            per_gravita_aperti[r["severity"]] = (
                per_gravita_aperti.get(r["severity"], 0) + int(r["n"]))
    return {"per_stato": per_stato, "aperti_per_gravita": per_gravita_aperti,
            "aperti": per_stato.get("open", 0) + per_stato.get("ack", 0)}


def set_alert_status(tenant_id: int, alert_id: int, status: str, actor: str,
                     note: str = "") -> bool:
    from . import ALERT_STATUSES

    if status not in ALERT_STATUSES:
        return False
    riga = query("SELECT id FROM siem_alerts WHERE id = ? AND tenant_id = ?",
                 (alert_id, tenant_id), one=True)
    if riga is None:
        return False
    execute("UPDATE siem_alerts SET status = ?, note = COALESCE(?, note),"
            " decided_at = ?, updated_at = ? WHERE id = ?",
            (status, note.strip() or None, utc_now_str(), utc_now_str(), alert_id))
    return True
