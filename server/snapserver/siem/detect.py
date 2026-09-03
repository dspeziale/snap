# -----------------------------------------------------------------
# detect.py — motore di rilevazione: regole a soglia e correlazione con la TI
# Autore: Daniele Speziale
# Data creazione: 2026-09-02
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Dagli eventi agli allarmi, correlati alla threat intelligence.

A intervalli regolari, per ogni regola attiva di ogni tenant, si contano gli
eventi del suo genere nella finestra: dove un gruppo (un indirizzo, un'utenza, un
host) supera la soglia, nasce o si aggiorna un ALLARME. La deduplicazione e' nel
database: un solo allarme aperto per (regola, gruppo), cosi' un attacco che dura
un'ora e' un allarme che cresce, non centinaia di righe.

La correlazione con la threat intelligence e' il punto: l'indirizzo o l'host
coinvolto viene risolto a un nodo dell'inventario, e sui riscontri APERTI di quel
nodo si decide. Un tentativo di accesso ripetuto verso una macchina che porta gia'
una vulnerabilita' sfruttabile non e' lo stesso evento di uno verso una macchina
sana: la gravita' dell'allarme sale di un grado e l'allarme cita i riscontri, cosi'
chi guarda il quadro SOC vede subito l'attacco e l'esposizione insieme.

La notifica di un allarme rispetta lo stesso freno degli incidenti: un promemoria
al massimo ogni cinque minuti finche' resta aperto, non uno a ogni giro.
"""

from __future__ import annotations

import json
from datetime import timedelta

from ..db import execute, query, utc_now, utc_now_str, utc_str
from . import SEVERITIES, store
from . import data

# Cadenza del motore e freno delle notifiche di uno stesso allarme aperto.
TICK_SECONDS = 60
INTERVALLO_PROMEMORIA_SECONDI = 300


def _nodo_per_indirizzo(tenant_id: int, src_ip: str, host: str) -> dict | None:
    """Risolve l'indirizzo o l'host coinvolto a un nodo dell'inventario.

    E' il ponte verso la threat intelligence: senza il nodo non c'e' correlazione.
    Si prova prima l'indirizzo (piu' affidabile), poi il nome host.
    """
    if src_ip:
        riga = query("SELECT id, ip, hostname, device_label FROM nodes"
                     " WHERE tenant_id = ? AND ip = ? LIMIT 1", (tenant_id, src_ip),
                     one=True)
        if riga:
            return dict(riga)
    if host:
        riga = query("SELECT id, ip, hostname, device_label FROM nodes"
                     " WHERE tenant_id = ? AND hostname = ? LIMIT 1", (tenant_id, host),
                     one=True)
        if riga:
            return dict(riga)
    return None


def _riscontri_del_nodo(tenant_id: int, node_id: int) -> list:
    """I riscontri di sicurezza APERTI sul nodo, in forma compatta per l'allarme."""
    righe = query(
        "SELECT f.id, f.cve_id, f.severity, f.title, f.kind, COALESCE(c.kev, 0) AS kev"
        " FROM ti_findings f LEFT JOIN ti_cve c ON c.cve_id = f.cve_id"
        " WHERE f.tenant_id = ? AND f.node_id = ? AND f.status = 'open'"
        " ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
        "   WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, c.kev DESC LIMIT 20",
        (tenant_id, node_id))
    return [dict(r) for r in righe]


def _alza_gravita(base: str, riscontri: list) -> str:
    """La gravita' dell'allarme, alzata quando il nodo coinvolto e' gia' esposto.

    La correlazione e' proporzionata: un riscontro sfruttato attivamente (KEV) o
    critico alza di un grado; averne comunque di aperti non abbassa mai. Non si
    supera 'critical' e non si scende sotto la gravita' base della regola.
    """
    if base not in SEVERITIES:
        base = "medium"
    if not riscontri:
        return base
    peggiore = min((SEVERITIES.index(r["severity"]) for r in riscontri
                    if r["severity"] in SEVERITIES), default=len(SEVERITIES))
    kev = any(r.get("kev") for r in riscontri)
    critico_esposto = kev or peggiore <= SEVERITIES.index("high")
    if critico_esposto:
        return SEVERITIES[max(0, SEVERITIES.index(base) - 1)]
    return base


def _upsert_alert(tenant_id: int, regola: dict, gruppo: dict, adesso: str) -> dict:
    """Crea o aggiorna l'allarme per (regola, gruppo). Restituisce
    {id, nuovo, gravita, notificare}."""
    group_value = gruppo["gruppo"]
    src_ip = gruppo.get("src_ip") or (group_value if regola["group_by"] == "src_ip" else "")
    host = gruppo.get("host") or (group_value if regola["group_by"] == "host" else "")
    username = gruppo.get("username") or (group_value if regola["group_by"] == "username"
                                          else "")

    nodo = _nodo_per_indirizzo(tenant_id, src_ip, host)
    riscontri = _riscontri_del_nodo(tenant_id, nodo["id"]) if nodo else []
    gravita = _alza_gravita(regola["severity"], riscontri)
    ti_refs = json.dumps([{"id": r["id"], "cve": r["cve_id"], "severita": r["severity"]}
                          for r in riscontri], ensure_ascii=False) if riscontri else None

    correlato = (" - il nodo %s porta gia' %d riscontro/i di sicurezza aperto/i"
                 % ((nodo.get("ip") or nodo.get("hostname")), len(riscontri))
                 ) if riscontri else ""
    titolo = "%s (%s: %s)%s" % (regola["name"], regola["group_by"], group_value,
                                correlato)
    esempi = store.eventi_di_esempio(tenant_id, group_value, regola["event_kind"],
                                     regola["group_by"])
    evidenza = ("%d eventi '%s' in %d s. Esempi:\n%s"
                % (gruppo["n"], regola["event_kind"], regola["window_seconds"],
                   "\n".join(esempi[:5])))

    esistente = query(
        "SELECT id, events_count, notified_at FROM siem_alerts"
        " WHERE tenant_id = ? AND rule_code = ? AND IFNULL(group_value, '') = ?"
        " AND status IN ('open', 'ack')",
        (tenant_id, regola["code"], group_value), one=True)

    from . import incident as ponte_incidente

    if esistente:
        execute(
            "UPDATE siem_alerts SET events_count = ?, last_event_at = ?, severity = ?,"
            " ti_refs_json = ?, node_id = ?, evidence = ?, title = ?, updated_at = ?"
            " WHERE id = ?",
            (gruppo["n"], gruppo["ultimo"], gravita, ti_refs,
             nodo["id"] if nodo else None, evidenza, titolo, adesso, esistente["id"]))
        # L'incidente collegato segue l'allarme (conteggio, gravita', evidenza).
        collegato = query("SELECT incident_id FROM siem_alerts WHERE id = ?",
                          (esistente["id"],), one=True)
        if collegato and collegato["incident_id"]:
            ponte_incidente.aggiorna_incidente(
                tenant_id, collegato["incident_id"],
                {"severity": gravita, "evidence": evidenza, "events_count": gruppo["n"]})
        return {"id": esistente["id"], "nuovo": False, "gravita": gravita,
                "notified_at": esistente["notified_at"], "riscontri": len(riscontri)}

    alert_id = execute(
        "INSERT INTO siem_alerts (tenant_id, rule_id, rule_code, title, severity,"
        " status, event_kind, group_value, src_ip, username, host, node_id,"
        " ti_refs_json, evidence, events_count, first_event_at, last_event_at,"
        " created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (tenant_id, regola["id"], regola["code"], titolo, gravita, regola["event_kind"],
         group_value, src_ip or None, username or None, host or None,
         nodo["id"] if nodo else None, ti_refs, evidenza, gruppo["n"],
         gruppo["primo"], gruppo["ultimo"], adesso, adesso))
    # Ogni allarme SIEM diventa anche un incidente in Controlli -> Incidenti.
    incident_id = ponte_incidente.apri_incidente(tenant_id, {
        "title": titolo, "severity": gravita, "host": host, "src_ip": src_ip,
        "group_value": group_value, "evidence": evidenza})
    execute("UPDATE siem_alerts SET incident_id = ? WHERE id = ?", (incident_id, alert_id))
    return {"id": alert_id, "nuovo": True, "gravita": gravita, "notified_at": None,
            "riscontri": len(riscontri)}


def _notifica_allarme(tenant_id: int, titolo: str, gravita: str,
                      evidenza: str) -> None:
    """Accoda la notifica di un allarme ai recapiti del tenant, con lo stesso freno
    degli incidenti (un promemoria al massimo ogni cinque minuti)."""
    from ..notifications import queue_notification

    contatto = query("SELECT contact_email FROM tenants WHERE id = ?", (tenant_id,),
                     one=True)
    destinatario = (contatto["contact_email"] if contatto else "") or ""
    oggetto = "[SNAP SIEM] Allarme %s: %s" % (gravita.upper(), titolo[:120])
    corpo = ("Un evento di sicurezza e' stato rilevato dai log.\n\n%s\n\n"
             "Aprire il quadro SIEM della console per i dettagli e la correlazione con"
             " la threat intelligence." % evidenza)
    queue_notification(tenant_id, "siem.alert", [destinatario] if destinatario else [],
                       oggetto, corpo)


def run_once() -> dict:
    """Un giro di rilevazione su tutti i tenant. Restituisce il riepilogo."""
    adesso = utc_now_str()
    soglia_promemoria = utc_str(utc_now() - timedelta(seconds=INTERVALLO_PROMEMORIA_SECONDI))
    tenants = query("SELECT id FROM tenants WHERE is_active = 1", ())
    nuovi = 0
    aggiornati = 0
    notificati = 0

    for t in tenants:
        tenant_id = int(t["id"])
        for regola in data.rules(tenant_id, solo_attive=True):
            try:
                gruppi = store.window_groups(
                    tenant_id, regola["event_kind"], regola["group_by"],
                    regola["window_seconds"], regola["threshold"],
                    min_severity=regola.get("min_severity") or "")
            except ValueError:
                continue
            for gruppo in gruppi:
                esito = _upsert_alert(tenant_id, regola, gruppo, adesso)
                if esito["nuovo"]:
                    nuovi += 1
                else:
                    aggiornati += 1
                # Notifica: alla nascita, e poi come promemoria non piu' di una volta
                # ogni cinque minuti finche' l'allarme resta aperto.
                ultimo = esito["notified_at"]
                if esito["nuovo"] or not ultimo or ultimo < soglia_promemoria:
                    allarme = data.alert(tenant_id, esito["id"])
                    if allarme:
                        try:
                            _notifica_allarme(tenant_id, allarme["title"],
                                              esito["gravita"], allarme["evidence"])
                            execute("UPDATE siem_alerts SET notified_at = ? WHERE id = ?",
                                    (adesso, esito["id"]))
                            _traccia(tenant_id, esito["id"], allarme["title"],
                                     esito["gravita"], esito["nuovo"])
                            notificati += 1
                        except Exception as errore:  # la notifica non e' la rilevazione
                            from flask import current_app
                            current_app.logger.warning(
                                "Notifica allarme SIEM %s non accodata: %s",
                                esito["id"], errore)

    return {"nuovi": nuovi, "aggiornati": aggiornati, "notificati": notificati}


def _traccia(tenant_id: int, alert_id: int, titolo: str, gravita: str,
             nuovo: bool) -> None:
    from ..audit import log_event

    log_event("siem.alert.%s" % ("opened" if nuovo else "reminded"),
              "Allarme SIEM %s (%s): %s" % (alert_id, gravita, titolo[:150]),
              tenant_id=tenant_id, severity="warning" if gravita in ("critical", "high")
              else "info", entity="siem_alert", entity_id=alert_id)


# --------------------------------------------------------------------------- #
# Thread di rilevazione (compito del server, come il valutatore delle regole)
# --------------------------------------------------------------------------- #
import threading  # noqa: E402 - accanto a cio' che usa, non in cima

_thread: threading.Thread | None = None
_stop = threading.Event()


def start_detector(app) -> None:
    """Avvia il motore di rilevazione SIEM, se non e' gia' avviato."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return

    def giro():
        giri = 0
        while not _stop.wait(TICK_SECONDS):
            giri += 1
            try:
                with app.app_context():
                    esito = run_once()
                    if esito["nuovi"] or esito["notificati"]:
                        app.logger.info(
                            "SIEM: %d nuovi allarmi, %d aggiornati, %d notificati",
                            esito["nuovi"], esito["aggiornati"], esito["notificati"])
                    # La retention si applica di rado (circa ogni ora): cancellare a
                    # ogni giro sarebbe lavoro inutile su un file che cresce piano.
                    if giri % 60 == 0:
                        from flask import current_app

                        giorni = current_app.config.get("SIEM_RETENTION_DAYS", 90)
                        rimossi = store.purge(int(giorni or 0))
                        if rimossi:
                            app.logger.info("SIEM: %d eventi oltre la retention rimossi",
                                            rimossi)
            except Exception as errore:  # nessun errore ferma il thread
                app.logger.warning("Rilevazione SIEM non riuscita: %s", errore)

    _thread = threading.Thread(target=giro, name="snap-siem", daemon=True)
    _thread.start()
    app.logger.info("Motore di rilevazione SIEM avviato (ogni %d s)", TICK_SECONDS)


def stop_detector() -> None:
    _stop.set()
