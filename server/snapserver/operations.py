"""
snap server - Sale operative: quadro NOC e quadro SOC.

Due mestieri, due domande diverse, due pagine.

Il **NOC** chiede *che cosa non funziona adesso*: quali controlli sono in errore, da
quanto, che cosa balla (fallisce e torna, fallisce e torna), chi tace da troppo, e se
le sonde stanno lavorando. E' una pagina che si guarda in piedi, e deve dire in dieci
secondi se il turno e' tranquillo.

Il **SOC** chiede *che cosa e' cambiato nella superficie esposta*: porte aperte da
poco, dispositivi comparsi, identita' cambiate sullo stesso indirizzo, vulnerabilita'
confermate e sfruttate attivamente, servizi che espongono se stessi. Non e' lo stato:
e' la **variazione**, perche' una porta aperta da sempre e' architettura nota mentre
la stessa porta aperta ieri e' un evento (RP-12).

Nessuna delle due pagine inventa numeri: dove non c'e' misura si dichiara "non
misurato" e non si scrive zero (RP-05). Tutte le interrogazioni sono per tenant.

remarks: Autore: Daniele Speziale - Data: 2026-08-29
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from .checks import INCIDENT_ACK, INCIDENT_OPEN, STATUS_OK
from .db import days_ago_str, hours_ago_str, query, scalar
from .tenancy import fmt_grafico

# Quante righe portano gli elenchi delle sale operative. Sono pagine da leggere in
# piedi: oltre una ventina di righe non si guardano, si scorrono.
MAX_RIGHE = 25
MAX_RIGHE_LUNGHE = 60

# Un nodo che non risponde da piu' di questo tempo e' "in silenzio". Non e'
# necessariamente caduto: puo' essere spento di proposito, e per questo la pagina
# lo chiama silenzio e non guasto.
ORE_SILENZIO = 6


# --------------------------------------------------------------------------- #
# NOC
# --------------------------------------------------------------------------- #
def failing_now(tenant_id: int, limit: int = MAX_RIGHE) -> list[dict]:
    """Controlli il cui ultimo esito non e' riuscito, con da quando dura.

    L'ultimo esito e non "un esito fallito nelle ultime ore": la domanda del turno e'
    che cosa non funziona ADESSO, e un controllo che ha fallito alle tre ma alle
    quattro e' tornato a posto non e' un problema aperto.
    """
    return [dict(r) for r in query(
        "SELECT c.id AS check_id, c.name AS check_name, c.kind, c.severity,"
        " t.address, t.name AS target_name, r.status, r.detail, r.latency_ms,"
        " r.executed_at, i.id AS incident_id, i.opened_at, i.status AS incident_status,"
        " (SELECT COUNT(*) FROM check_results f WHERE f.check_id = c.id"
        "   AND f.status <> ? AND f.executed_at >= ?) AS falliti_24h"
        " FROM checks c"
        " JOIN check_targets t ON t.id = c.target_id"
        " JOIN check_results r ON r.id = ("
        "   SELECT id FROM check_results x WHERE x.check_id = c.id"
        "   ORDER BY x.executed_at DESC, x.id DESC LIMIT 1)"
        " LEFT JOIN check_incidents i ON i.check_id = c.id AND i.status IN (?, ?)"
        " WHERE c.tenant_id = ? AND c.is_enabled = 1 AND r.status <> ?"
        " ORDER BY CASE c.severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1"
        "   ELSE 2 END, r.executed_at DESC LIMIT ?",
        (STATUS_OK, days_ago_str(1), INCIDENT_OPEN, INCIDENT_ACK, tenant_id,
         STATUS_OK, int(limit)))]


def flapping(tenant_id: int, hours: int = 24, limit: int = MAX_RIGHE) -> list[dict]:
    """Controlli che cambiano stato di continuo: il caso peggiore da diagnosticare.

    Un servizio fermo si vede; un servizio che va e viene consuma il turno e non
    compare in nessun elenco di errori, perche' quando lo si guarda funziona. Qui si
    contano i **cambi di stato** nella finestra, non i fallimenti.
    """
    righe = query(
        "SELECT r.check_id, c.name AS check_name, t.address, r.status, r.executed_at"
        " FROM check_results r JOIN checks c ON c.id = r.check_id"
        " JOIN check_targets t ON t.id = c.target_id"
        " WHERE r.tenant_id = ? AND r.executed_at >= ?"
        " ORDER BY r.check_id, r.executed_at", (tenant_id, hours_ago_str(hours)))

    per_controllo = {}
    for riga in righe:
        voce = per_controllo.setdefault(riga["check_id"], {
            "check_id": riga["check_id"], "check_name": riga["check_name"],
            "address": riga["address"], "cambi": 0, "esiti": 0,
            "ultimo": riga["status"], "precedente": None, "ultimo_at": riga["executed_at"],
        })
        voce["esiti"] += 1
        stato = "ok" if riga["status"] == STATUS_OK else "ko"
        if voce["precedente"] is not None and stato != voce["precedente"]:
            voce["cambi"] += 1
        voce["precedente"] = stato
        voce["ultimo"] = riga["status"]
        voce["ultimo_at"] = riga["executed_at"]

    instabili = [v for v in per_controllo.values() if v["cambi"] >= 2]
    instabili.sort(key=lambda v: (-v["cambi"], v["check_name"]))
    return instabili[:limit]


# Colonne comuni ai due elenchi dei nodi che non rispondono o non sono stati
# interrogati: l'ultima verifica e il suo esito sono la differenza fra i due casi.
_COLONNE_NODI = (
    "SELECT n.id, n.ip, n.hostname, n.device_label,"
    " COALESCE(n.device_type_source, 'auto') AS device_type_source,"
    " n.status, n.last_seen_at, s.cidr AS subnet_cidr,"
    " (SELECT MAX(m.checked_at) FROM monitor_samples m WHERE m.node_id = n.id)"
    "   AS ultima_verifica,"
    " (SELECT m.reachable FROM monitor_samples m WHERE m.node_id = n.id"
    "   ORDER BY m.checked_at DESC, m.id DESC LIMIT 1) AS ultimo_esito,"
    " (SELECT COUNT(*) FROM check_targets t WHERE t.tenant_id = n.tenant_id"
    "   AND (t.address = n.ip OR t.address = n.hostname)) AS sorvegliato"
    " FROM nodes n LEFT JOIN subnets s ON s.id = n.subnet_id")


def silent_nodes(tenant_id: int, ore: int = ORE_SILENZIO,
                 limit: int = MAX_RIGHE_LUNGHE) -> list[dict]:
    """Nodi che sono stati interrogati e NON hanno risposto.

    Difetto misurato e corretto: guardando `last_seen_at` finivano in questo elenco
    dispositivi perfettamente vivi, solo non ancora ripassati dalla sorveglianza --
    su tremila nodi la rotazione impiega ore. "Non ha risposto" e "non gliel'abbiamo
    chiesto" sono due fatti diversi, e il secondo sta in `unchecked_nodes`.

    Si chiamano "in silenzio" e non "caduti" perche' un dispositivo spento di
    proposito e uno guasto danno lo stesso risultato: la pagina riporta il fatto, il
    giudizio spetta a chi conosce la rete.
    """
    return [dict(r) for r in query(
        _COLONNE_NODI +
        " WHERE n.tenant_id = ? AND ("
        # La prova diretta viene prima dello stato: se l'ultima verifica dice che il
        # nodo ha risposto, non e' in silenzio, qualunque cosa dica una colonna
        # aggiornata dai conferimenti. Lo stato vale solo dove una verifica non c'e'
        # mai stata.
        "   (SELECT m.reachable FROM monitor_samples m WHERE m.node_id = n.id"
        "     ORDER BY m.checked_at DESC, m.id DESC LIMIT 1) = 0"
        "   OR (NOT EXISTS (SELECT 1 FROM monitor_samples m WHERE m.node_id = n.id)"
        "       AND n.status <> 'up'))"
        " ORDER BY n.last_seen_at LIMIT ?", (tenant_id, int(limit)))]


def unchecked_nodes(tenant_id: int, ore: int = 24,
                    limit: int = MAX_RIGHE_LUNGHE) -> list[dict]:
    """Nodi che nella finestra non sono stati interrogati affatto.

    Non e' un guasto del nodo: e' copertura che manca. Su un perimetro ampio la
    sorveglianza ruota e qualche nodo resta indietro; se l'elenco e' lungo o cresce,
    la sonda non sta facendo il giro -- ed e' quello il problema da guardare, non i
    singoli indirizzi.
    """
    return [dict(r) for r in query(
        _COLONNE_NODI +
        " WHERE n.tenant_id = ? AND n.status = 'up' AND NOT EXISTS ("
        "   SELECT 1 FROM monitor_samples m WHERE m.node_id = n.id"
        "   AND m.checked_at >= ?)"
        " ORDER BY n.last_seen_at LIMIT ?",
        (tenant_id, hours_ago_str(ore), int(limit)))]


def probe_health(tenant_id: int) -> list[dict]:
    """Le sonde: quando hanno parlato l'ultima volta e quanto hanno portato."""
    return [dict(r) for r in query(
        "SELECT p.id, p.name, p.code, p.status, p.last_seen_at, p.agent_version,"
        " (SELECT COUNT(*) FROM ingest_batches b WHERE b.probe_id = p.id"
        "   AND b.received_at >= ?) AS lotti_24h,"
        " (SELECT COALESCE(SUM(b.record_count), 0) FROM ingest_batches b"
        "   WHERE b.probe_id = p.id AND b.received_at >= ?) AS record_24h,"
        " (SELECT COUNT(*) FROM probe_commands q WHERE q.probe_id = p.id"
        "   AND q.status = 'pending') AS comandi_attesa,"
        " (SELECT COUNT(*) FROM scan_runs r WHERE r.probe_id = p.id"
        "   AND r.started_at >= ?) AS scansioni_24h"
        " FROM probes p WHERE p.tenant_id = ? AND p.revoked_at IS NULL"
        " ORDER BY p.name", (days_ago_str(1), days_ago_str(1), days_ago_str(1),
                             tenant_id))]


def worst_latency(tenant_id: int, limit: int = MAX_RIGHE) -> list[dict]:
    """Bersagli piu' lenti nelle 24 ore: la lentezza precede spesso il guasto."""
    return [dict(r) for r in query(
        "SELECT c.name AS check_name, t.address, COUNT(*) AS esiti,"
        " ROUND(AVG(r.latency_ms), 1) AS media, MAX(r.latency_ms) AS massimo"
        " FROM check_results r JOIN checks c ON c.id = r.check_id"
        " JOIN check_targets t ON t.id = c.target_id"
        " WHERE r.tenant_id = ? AND r.executed_at >= ? AND r.latency_ms IS NOT NULL"
        " GROUP BY c.id HAVING COUNT(*) >= 3"
        " ORDER BY media DESC LIMIT ?", (tenant_id, days_ago_str(1), int(limit)))]


def noc_board(tenant_id: int) -> dict:
    """Tutto il quadro del turno, in una interrogazione sola per la pagina."""
    from .checks_queries import (availability_trend, checks_summary, incidents,
                                 incidents_daily, results_hourly)
    from .queries import probe_summary

    riepilogo = checks_summary(tenant_id)
    sonde = probe_summary(tenant_id)
    in_errore = failing_now(tenant_id)
    silenzi = silent_nodes(tenant_id)

    nodi = scalar("SELECT COUNT(*) FROM nodes WHERE tenant_id = ?", (tenant_id,),
                  default=0)
    attivi = scalar("SELECT COUNT(*) FROM nodes WHERE tenant_id = ? AND status = 'up'",
                    (tenant_id,), default=0)
    ultimo_lotto = scalar(
        "SELECT MAX(received_at) FROM ingest_batches WHERE tenant_id = ?",
        (tenant_id,), default=None)

    ore = results_hourly(tenant_id, hours=24)
    return {
        "riepilogo": riepilogo,
        "sonde": sonde,
        # I punti si preparano qui e non nel modello: un grafico che si costruisce
        # nella pagina lega la resa alla forma del dato, e cambiare l'una rompe l'altra.
        "punti_riuscita": [[fmt_grafico(v["hour"]), v["success_rate"]] for v in ore
                           if v["success_rate"] is not None],
        "punti_falliti": [[fmt_grafico(v["hour"]), v["failed"]] for v in ore],
        "flotta": probe_health(tenant_id),
        "in_errore": in_errore,
        "instabili": flapping(tenant_id),
        "silenzi": silenzi,
        "non_interrogati": unchecked_nodes(tenant_id),
        "lenti": worst_latency(tenant_id),
        "incidenti": incidents(tenant_id, status="aperti", limit=MAX_RIGHE),
        "andamento_ore": ore,
        "andamento_giorni": availability_trend(tenant_id, giorni=14),
        "incidenti_giorni": incidents_daily(tenant_id, days=14),
        "nodi": nodi,
        "nodi_attivi": attivi,
        "ultimo_lotto": ultimo_lotto,
        # Il turno e' tranquillo quando non c'e' nulla di aperto e nulla balla: e'
        # una frase, non un colore, perche' un colore da solo non si legge in fretta.
        "tranquillo": not in_errore and not riepilogo["incidents_open"],
    }


# --------------------------------------------------------------------------- #
# SOC
# --------------------------------------------------------------------------- #
def new_nodes(tenant_id: int, giorni: int = 7, limit: int = MAX_RIGHE) -> list[dict]:
    """Dispositivi comparsi di recente: un indirizzo nuovo e' sempre una domanda."""
    return [dict(r) for r in query(
        "SELECT n.id, n.ip, n.hostname, n.device_label, n.device_confidence,"
        " COALESCE(n.device_type_source, 'auto') AS device_type_source,"
        " n.first_seen_at, n.status, s.cidr AS subnet_cidr,"
        " (SELECT COUNT(*) FROM node_ports p WHERE p.node_id = n.id"
        "   AND p.state = 'open' AND COALESCE(p.is_suspect, 0) = 0) AS porte"
        " FROM nodes n LEFT JOIN subnets s ON s.id = n.subnet_id"
        " WHERE n.tenant_id = ? AND n.first_seen_at >= ?"
        " ORDER BY n.first_seen_at DESC LIMIT ?",
        (tenant_id, days_ago_str(giorni), int(limit)))]


def new_ports(tenant_id: int, giorni: int = 7, limit: int = MAX_RIGHE_LUNGHE) -> list:
    """Porte aperte di recente, con il servizio che ci risponde.

    E' la variazione che conta: la stessa porta aperta da sempre e' architettura
    nota, aperta ieri e' un evento da spiegare (RP-12).
    """
    return [dict(r) for r in query(
        "SELECT p.id, p.protocol, p.port, p.service_name, p.product, p.version,"
        " p.first_seen_at, n.id AS node_id, n.ip, n.hostname, n.device_label,"
        " COALESCE(n.device_type_source, 'auto') AS device_type_source"
        " FROM node_ports p JOIN nodes n ON n.id = p.node_id"
        " WHERE p.tenant_id = ? AND p.state = 'open'"
        " AND COALESCE(p.is_suspect, 0) = 0 AND p.first_seen_at >= ?"
        " ORDER BY p.first_seen_at DESC LIMIT ?",
        (tenant_id, days_ago_str(giorni), int(limit)))]


def identity_changes(tenant_id: int, giorni: int = 7, limit: int = MAX_RIGHE) -> list:
    """Identita' cambiate sullo stesso indirizzo.

    Un indirizzo che era una stampante e adesso e' un server Windows non e' un
    aggiornamento del catalogo: o l'indirizzo e' stato riassegnato, o qualcuno ha
    collegato un altro apparato. In entrambi i casi va guardato.
    """
    return [dict(r) for r in query(
        "SELECT c.id, c.kind, c.subject, c.before_value, c.after_value, c.severity,"
        " c.created_at, n.id AS node_id, n.ip, n.hostname"
        " FROM node_changes c JOIN nodes n ON n.id = c.node_id"
        " WHERE c.tenant_id = ? AND c.created_at >= ?"
        " AND c.kind IN ('device_type.changed', 'os.changed', 'hostname.changed',"
        "                'mac.changed')"
        " ORDER BY c.created_at DESC LIMIT ?",
        (tenant_id, days_ago_str(giorni), int(limit)))]


def failed_logins(tenant_id: int, giorni: int = 7, limit: int = MAX_RIGHE) -> list:
    """Accessi non riusciti alla console: chi bussa e non entra."""
    return [dict(r) for r in query(
        "SELECT created_at, actor, description, source_ip"
        " FROM audit_events WHERE tenant_id = ? AND event_type = 'auth.failed'"
        " AND created_at >= ? ORDER BY created_at DESC LIMIT ?",
        (tenant_id, days_ago_str(giorni), int(limit)))]


def rule_activity(tenant_id: int, giorni: int = 7, limit: int = MAX_RIGHE) -> list:
    """Regole di notifica che sono scattate: che cosa il sistema ha gia' segnalato."""
    return [dict(r) for r in query(
        "SELECT m.id, m.occurred_at, m.created_at, m.event_type, m.subject,"
        " m.severity, m.suppressed, m.notified, r.name AS rule_name, r.channels"
        " FROM rule_matches m JOIN notify_rules r ON r.id = m.rule_id"
        " WHERE m.tenant_id = ? AND m.created_at >= ?"
        " ORDER BY m.created_at DESC LIMIT ?",
        (tenant_id, days_ago_str(giorni), int(limit)))]


def zone_posture(tenant_id: int) -> dict:
    """Come si comporta la segmentazione dichiarata.

    La domanda del SOC non e' "quante esposizioni ho" ma "quante di queste sono
    normali dove si trovano": una rete ben segmentata ha molte esposizioni attese e
    poche violazioni, una rete piatta ha tutto aperto e niente di dichiarato.
    """
    from . import zones

    dichiarate = zones.per_chiave(tenant_id)

    subnet = query(
        "SELECT id, cidr, label, COALESCE(zone, '') AS zone,"
        " (SELECT COUNT(*) FROM nodes n WHERE n.subnet_id = subnets.id) AS nodi"
        " FROM subnets WHERE tenant_id = ? ORDER BY cidr", (tenant_id,))

    per_zona = {}
    for riga in subnet:
        # Catalogo del tenant, letto una volta sola: una zona creata
        # dall'operatore vale quanto una predefinita.
        chiave = riga["zone"] if riga["zone"] in dichiarate else ""
        voce = per_zona.setdefault(chiave, {
            "chiave": chiave,
            "nome": dichiarate[chiave]["nome"] if chiave else "Non dichiarata",
            "icona": (dichiarate[chiave]["icona"] if chiave
                      else "bi-question-circle"),
            "tono": dichiarate[chiave]["tono"] if chiave else "secondary",
            "subnet": 0, "nodi": 0, "aperte": 0, "attese": 0, "violazioni": 0,
        })
        voce["subnet"] += 1
        voce["nodi"] += int(riga["nodi"] or 0)

    conteggi = query(
        "SELECT COALESCE(s.zone, '') AS zone, f.status, f.evidence LIKE '%Violazione%'"
        "   AS violazione, COUNT(*) AS quanti"
        " FROM ti_findings f JOIN nodes n ON n.id = f.node_id"
        " LEFT JOIN subnets s ON s.id = n.subnet_id"
        " WHERE f.tenant_id = ? AND f.kind = 'exposure'"
        " GROUP BY s.zone, f.status, violazione", (tenant_id,))
    for riga in conteggi:
        chiave = riga["zone"] if riga["zone"] in dichiarate else ""
        voce = per_zona.setdefault(chiave, {
            "chiave": chiave, "nome": "Non dichiarata", "icona": "bi-question-circle",
            "tono": "secondary", "subnet": 0, "nodi": 0, "aperte": 0, "attese": 0,
            "violazioni": 0})
        if riga["status"] == "expected":
            voce["attese"] += int(riga["quanti"])
        elif riga["status"] == "open":
            voce["aperte"] += int(riga["quanti"])
            if riga["violazione"]:
                voce["violazioni"] += int(riga["quanti"])

    elenco = sorted(per_zona.values(),
                    key=lambda v: (-v["violazioni"], -v["aperte"], v["nome"]))
    return {
        "zone": elenco,
        "senza_zona": sum(v["subnet"] for v in elenco if not v["chiave"]),
        "attese": sum(v["attese"] for v in elenco),
        "violazioni": sum(v["violazioni"] for v in elenco),
        "catalogo": zones.catalogo(tenant_id),
    }


def attack_coverage(tenant_id: int, limit: int = 12) -> list:
    """Tecniche MITRE ATT&CK rappresentate dalle esposizioni aperte.

    Un elenco di porte dice che cosa e' aperto; un elenco di tecniche dice come
    verrebbe usato, ed e' la lingua con cui un SOC parla con il resto del mondo.
    """
    return [dict(r) for r in query(
        "SELECT f.technique_id, COALESCE(t.name, '') AS nome,"
        " COALESCE(t.tactics, '') AS tattiche, COALESCE(t.url, '') AS url,"
        " COUNT(*) AS riscontri, COUNT(DISTINCT f.node_id) AS nodi"
        " FROM ti_findings f LEFT JOIN ti_technique t ON t.technique_id = f.technique_id"
        " WHERE f.tenant_id = ? AND f.status = 'open' AND f.technique_id IS NOT NULL"
        " AND f.technique_id <> '' GROUP BY f.technique_id"
        " ORDER BY nodi DESC LIMIT ?", (tenant_id, int(limit)))]


def ports_opened(tenant_id: int, giorni: int = 7, limit: int = 12) -> list:
    """Quali servizi sono stati aperti di piu' nella finestra."""
    return [dict(r) for r in query(
        "SELECT p.protocol, p.port, COALESCE(p.service_name, '') AS servizio,"
        " COUNT(*) AS quante, COUNT(DISTINCT p.node_id) AS nodi"
        " FROM node_ports p WHERE p.tenant_id = ? AND p.state = 'open'"
        " AND COALESCE(p.is_suspect, 0) = 0 AND p.first_seen_at >= ?"
        " GROUP BY p.protocol, p.port ORDER BY nodi DESC LIMIT ?",
        (tenant_id, days_ago_str(giorni), int(limit)))]


def surface_trend(tenant_id: int, giorni: int = 30) -> list:
    """Porte aperte per giorno: la superficie si allarga o si restringe?

    I giorni senza aperture non compaiono: non sono uno zero da rappresentare, sono
    giorni in cui non e' cambiato nulla.
    """
    return [[r["giorno"], int(r["quante"])] for r in query(
        "SELECT substr(first_seen_at, 1, 10) AS giorno, COUNT(*) AS quante"
        " FROM node_ports WHERE tenant_id = ? AND state = 'open'"
        " AND COALESCE(is_suspect, 0) = 0 AND first_seen_at >= ?"
        " GROUP BY giorno ORDER BY giorno", (tenant_id, days_ago_str(giorni)))]


def soc_board(tenant_id: int, giorni: int = 7) -> dict:
    """Quadro della sicurezza: prima le variazioni, poi lo stato."""
    from .reports.dataset_wide import (exposure, out_of_perimeter, snmp_coverage,
                                       suspect_ports)

    riscontri = {"aperti": 0, "confermati": 0, "kev": 0, "esposizioni": 0,
                 "da_verificare": 0, "nodi": 0}
    nodi_a_rischio = []
    try:
        from .threat import nodes_with_findings, summary as threat_summary

        riscontri = threat_summary(tenant_id)
        nodi_a_rischio = nodes_with_findings(tenant_id, limit=MAX_RIGHE)
    except Exception:  # noqa: BLE001 - una sezione mancante non toglie la pagina
        pass

    porte_nuove = new_ports(tenant_id, giorni=giorni)
    nodi_nuovi = new_nodes(tenant_id, giorni=giorni)
    identita = identity_changes(tenant_id, giorni=giorni)

    return {
        "giorni": giorni,
        "riscontri": riscontri,
        "nodi_a_rischio": nodi_a_rischio,
        "porte_nuove": porte_nuove,
        "nodi_nuovi": nodi_nuovi,
        "identita_cambiate": identita,
        "superficie": exposure(tenant_id),
        "fuori_perimetro": out_of_perimeter(tenant_id),
        "porte_sospette": suspect_ports(tenant_id),
        "snmp": snmp_coverage(tenant_id),
        "zone": zone_posture(tenant_id),
        "tecniche": attack_coverage(tenant_id),
        "porte_top": ports_opened(tenant_id, giorni=giorni),
        "andamento_superficie": surface_trend(tenant_id, giorni=max(30, giorni)),
        "accessi_falliti": failed_logins(tenant_id, giorni=giorni),
        "regole_scattate": rule_activity(tenant_id, giorni=giorni),
        "eventi_gravi": [dict(r) for r in query(
            "SELECT created_at, event_type, severity, description, actor"
            " FROM audit_events WHERE tenant_id = ? AND severity IN ('warning',"
            " 'critical') AND created_at >= ? ORDER BY created_at DESC LIMIT ?",
            (tenant_id, days_ago_str(giorni), MAX_RIGHE))],
        # Il numero che riassume la giornata del SOC: quante cose sono CAMBIATE.
        "variazioni_totali": len(porte_nuove) + len(nodi_nuovi) + len(identita),
    }
