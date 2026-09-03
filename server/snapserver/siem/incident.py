# -----------------------------------------------------------------
# incident.py — ponte fra gli allarmi SIEM e gli incidenti di Controlli
# Autore: Daniele Speziale
# Data creazione: 2026-09-03
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Ogni allarme SIEM diventa anche un incidente.

Un allarme di sicurezza rilevato dai log non deve restare in un elenco a parte: va
dove si guardano tutti gli incidenti, cioe' in **Controlli -> Incidenti**, con il
ciclo di vita completo (presa in carico, chiusura, comunicazione ACN). Qui si crea
e si tiene allineato quell'incidente.

Gli incidenti richiedono un controllo (`check_id NOT NULL`): come per gli incidenti
registrati a mano, si usa un controllo-CONTENITORE disattivato ("Allarme SIEM") che
non esegue verifiche ma da' agli allarmi un posto nel modello degli incidenti.
"""

from __future__ import annotations

from ..db import execute, query, utc_now_str

CONTROLLO_SIEM = "Allarme SIEM"
BERSAGLIO_SIEM = "siem"

# Le gravita' del SIEM (critical/high/medium/low/info) sulle tre degli incidenti.
_GRAVITA_INCIDENTE = {
    "critical": "critical", "high": "critical",
    "medium": "warning", "low": "info", "info": "info",
}


def _contenitore_siem(tenant_id: int) -> int:
    """Il controllo (disattivato) sotto cui vivono gli incidenti nati dagli allarmi
    SIEM. Creato una volta, come il contenitore degli incidenti manuali."""
    riga = query(
        "SELECT c.id FROM checks c JOIN check_targets t ON t.id = c.target_id"
        " WHERE c.tenant_id = ? AND c.name = ? LIMIT 1",
        (tenant_id, CONTROLLO_SIEM), one=True)
    if riga is not None:
        return int(riga["id"])

    adesso = utc_now_str()
    bersaglio = query("SELECT id FROM check_targets WHERE tenant_id = ? AND address = ?",
                      (tenant_id, BERSAGLIO_SIEM), one=True)
    target_id = int(bersaglio["id"]) if bersaglio is not None else execute(
        "INSERT INTO check_targets (tenant_id, address, name, description, is_enabled,"
        " created_at, updated_at) VALUES (?, ?, ?, ?, 0, ?, ?)",
        (tenant_id, BERSAGLIO_SIEM, "Allarmi SIEM",
         "Contenitore degli incidenti che nascono dagli allarmi del SIEM: eventi di"
         " sicurezza rilevati analizzando i log. Non esegue verifiche.", adesso, adesso))
    return int(execute(
        "INSERT INTO checks (tenant_id, target_id, name, kind, is_enabled,"
        " interval_seconds, timeout_seconds, severity, failure_threshold,"
        " escalation_threshold, created_at, updated_at)"
        " VALUES (?, ?, ?, 'presence', 0, 3600, 5, 'warning', 1, 1, ?, ?)",
        (tenant_id, target_id, CONTROLLO_SIEM, adesso, adesso)))


def apri_incidente(tenant_id: int, alarm: dict) -> int:
    """Crea l'incidente corrispondente a un allarme SIEM e ne restituisce l'id."""
    check_id = _contenitore_siem(tenant_id)
    adesso = utc_now_str()
    gravita = _GRAVITA_INCIDENTE.get(alarm.get("severity"), "warning")
    soggetto = (alarm.get("host") or alarm.get("src_ip") or alarm.get("group_value")
                or "origine ignota")
    dettaglio = (alarm.get("evidence") or alarm.get("title") or "")[:1000]
    incident_id = int(execute(
        "INSERT INTO check_incidents (tenant_id, check_id, status, severity, opened_at,"
        " first_detail, last_detail, failure_count, origin, title, subject, updated_at)"
        " VALUES (?, ?, 'open', ?, ?, ?, ?, 1, 'siem', ?, ?, ?)",
        (tenant_id, check_id, gravita, adesso, dettaglio, dettaglio,
         alarm.get("title") or "Allarme SIEM", soggetto, adesso)))
    execute("INSERT INTO check_incident_events (tenant_id, incident_id, action, actor,"
            " note, created_at) VALUES (?, ?, 'opened', 'siem', ?, ?)",
            (tenant_id, incident_id,
             "Allarme SIEM: %s" % (alarm.get("title") or ""), adesso))
    return incident_id


def aggiorna_incidente(tenant_id: int, incident_id: int, alarm: dict) -> None:
    """Riporta sull'incidente l'evoluzione dell'allarme (conteggio, gravita', evidenza).

    Non tocca un incidente gia' risolto: se un operatore lo ha chiuso, un nuovo giro
    del motore non lo riapre da se'."""
    riga = query("SELECT status FROM check_incidents WHERE id = ? AND tenant_id = ?",
                 (incident_id, tenant_id), one=True)
    if riga is None or riga["status"] == "resolved":
        return
    gravita = _GRAVITA_INCIDENTE.get(alarm.get("severity"), "warning")
    execute("UPDATE check_incidents SET severity = ?, last_detail = ?,"
            " failure_count = ?, updated_at = ? WHERE id = ?",
            (gravita, (alarm.get("evidence") or "")[:1000],
             int(alarm.get("events_count") or 1), utc_now_str(), incident_id))


def chiudi_incidente(tenant_id: int, incident_id: int, esito: str, attore: str) -> None:
    """Risolve l'incidente quando l'allarme SIEM viene chiuso o dichiarato falso
    positivo. Un incidente gia' risolto resta com'e'."""
    riga = query("SELECT status FROM check_incidents WHERE id = ? AND tenant_id = ?",
                 (incident_id, tenant_id), one=True)
    if riga is None or riga["status"] == "resolved":
        return
    adesso = utc_now_str()
    execute("UPDATE check_incidents SET status = 'resolved', resolved_at = ?,"
            " resolution = ?, updated_at = ? WHERE id = ?",
            (adesso, esito, adesso, incident_id))
    execute("INSERT INTO check_incident_events (tenant_id, incident_id, action, actor,"
            " note, created_at) VALUES (?, ?, 'resolved', ?, ?, ?)",
            (tenant_id, incident_id, attore or "siem", esito, adesso))
