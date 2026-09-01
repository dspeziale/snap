"""
snap server - Interrogazioni dei controlli periodici e degli incidenti.

Tenute separate dal dominio (`checks.py`) come l'inventario tiene separate le
proprie: qui non si decide nulla, si legge. Ogni interrogazione porta il tenant
come primo filtro.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json

from .checks import (
    INCIDENT_ACK,
    INCIDENT_OPEN,
    STATUS_OK,
    describe,
)
from .db import days_ago_str, hours_ago_str, query, scalar
from .tenancy import fmt_grafico


def checks_summary(tenant_id: int) -> dict:
    """Sintesi per i riquadri della pagina dei controlli."""
    bersagli = scalar("SELECT COUNT(*) FROM check_targets WHERE tenant_id = ?", (tenant_id,))
    controlli = scalar("SELECT COUNT(*) FROM checks WHERE tenant_id = ?", (tenant_id,))
    attivi = scalar("SELECT COUNT(*) FROM checks WHERE tenant_id = ? AND is_enabled = 1",
                    (tenant_id,))
    aperti = scalar("SELECT COUNT(*) FROM check_incidents WHERE tenant_id = ?"
                    " AND status IN (?, ?)", (tenant_id, INCIDENT_OPEN, INCIDENT_ACK))
    da_prendere = scalar("SELECT COUNT(*) FROM check_incidents WHERE tenant_id = ?"
                         " AND status = ?", (tenant_id, INCIDENT_OPEN))
    esiti = scalar("SELECT COUNT(*) FROM check_results WHERE tenant_id = ? AND received_at >= ?",
                   (tenant_id, days_ago_str(1)))
    falliti = scalar("SELECT COUNT(*) FROM check_results WHERE tenant_id = ?"
                     " AND received_at >= ? AND status <> ?",
                     (tenant_id, days_ago_str(1), STATUS_OK))
    return {
        "targets": bersagli,
        "checks": controlli,
        "checks_enabled": attivi,
        "incidents_open": aperti,
        "incidents_unclaimed": da_prendere,
        "results_24h": esiti,
        "failures_24h": falliti,
        # La percentuale di riuscita e' l'informazione che dice se il servizio
        # sorvegliato sta in piedi, piu' del numero assoluto di esecuzioni.
        "success_rate_24h": (round(100.0 * (esiti - falliti) / esiti, 1) if esiti else None),
    }


# Giorni rappresentati in testa alla pagina dei controlli. Trenta e' l'orizzonte in cui
# una tendenza si vede senza che il tracciato diventi illeggibile.
GIORNI_ANDAMENTO = 30


def availability_trend(tenant_id: int, giorni: int = GIORNI_ANDAMENTO) -> dict:
    """Disponibilita' per giorno locale, pronta per il grafico.

    Riusa il calcolo dei report (`reports.dataset.trends`): la stessa domanda deve
    avere la stessa risposta nella console e nel PDF, altrimenti due numeri diversi
    per la stessa cosa costringono a chiedersi quale sia quello giusto.
    """
    from .reports.dataset import trends
    from .reports.windows import days_bounds, today_local, zone_of
    from .tenancy import current_timezone

    from datetime import timedelta

    zona = zone_of({"timezone": current_timezone()})
    ultimo_giorno = today_local(zona)
    inizio, fine = days_bounds(zona, giorni, fino_a=ultimo_giorno)
    andamento = trends(tenant_id, zona, inizio, fine)

    punti = [[voce["giorno"].strftime("%Y-%m-%d"), voce["disponibilita"]]
             for voce in andamento["giorni"]]
    misurati = [v for v in andamento["giorni"] if v["misurato"]]
    return {
        "punti": punti,
        # Estremi del periodo DICHIARATO, non di quello misurato: il grafico deve
        # rappresentare i trenta giorni richiesti, non stringersi sui due in cui e'
        # arrivato un esito -- altrimenti ventotto giorni senza misure sparirebbero
        # invece di restare un vuoto visibile (RP-05).
        "da": (ultimo_giorno - timedelta(days=giorni - 1)).strftime("%Y-%m-%d"),
        "a": ultimo_giorno.strftime("%Y-%m-%d"),
        "giorni": giorni,
        "misurati": len(misurati),
        "senza_misure": giorni - len(misurati),
        "media": (round(sum(v["disponibilita"] for v in misurati) / len(misurati), 2)
                  if misurati else None),
        "minimo": min((v["disponibilita"] for v in misurati), default=None),
        "esiti": sum(v["esiti"] for v in misurati),
    }


# Prefisso con cui gli endpoint raggruppano i propri contatori. Nelle etichette dei
# grafici non aggiunge nulla -- si sa che sono misure -- e ruba spazio al nome che
# distingue una serie dall'altra. Il nome completo resta quello vero: e' il percorso
# che si scrive nelle verifiche e che viaggia nei collegamenti.
METRIC_PREFIX = "metrics."


def metric_label(name: str) -> str:
    """Nome della misura come si mostra: senza il prefisso di raggruppamento.

    Si toglie solo se e' in TESTA: in `x.metrics.y` la parola non e' un prefisso ma
    parte del percorso, e cancellarla renderebbe il nome irriconoscibile.
    """
    testo = str(name or "")
    if testo.startswith(METRIC_PREFIX) and len(testo) > len(METRIC_PREFIX):
        return testo[len(METRIC_PREFIX):]
    return testo


def _decode(riga, campo: str = "config_json") -> dict:
    try:
        return json.loads(riga[campo] or "{}")
    except (ValueError, TypeError, IndexError, KeyError):
        # Una configurazione illeggibile non deve impedire di vedere la riga: la
        # pagina lo dichiara, invece di mostrare una tabella vuota.
        return {}


def targets(tenant_id: int) -> list[dict]:
    """Bersagli con il numero di controlli e lo stato piu' recente."""
    righe = query(
        "SELECT t.*,"
        " (SELECT COUNT(*) FROM checks c WHERE c.target_id = t.id) AS checks_total,"
        " (SELECT COUNT(*) FROM checks c WHERE c.target_id = t.id AND c.is_enabled = 1)"
        "   AS checks_enabled,"
        " (SELECT COUNT(*) FROM check_incidents i JOIN checks c ON c.id = i.check_id"
        "   WHERE c.target_id = t.id AND i.status IN (?, ?)) AS incidents_open,"
        " (SELECT MAX(r.executed_at) FROM check_results r JOIN checks c ON c.id = r.check_id"
        "   WHERE c.target_id = t.id) AS last_result_at"
        " FROM check_targets t WHERE t.tenant_id = ?"
        " ORDER BY t.name",
        (INCIDENT_OPEN, INCIDENT_ACK, tenant_id))
    return [dict(r) for r in righe]


def target(tenant_id: int, target_id: int) -> dict | None:
    riga = query("SELECT * FROM check_targets WHERE id = ? AND tenant_id = ?",
                 (target_id, tenant_id), one=True)
    return dict(riga) if riga is not None else None


def checks_of_target(tenant_id: int, target_id: int) -> list[dict]:
    """Controlli di un bersaglio, con l'ultimo esito e l'incidente aperto."""
    righe = query(
        "SELECT c.*,"
        " (SELECT r.status FROM check_results r WHERE r.check_id = c.id"
        "   ORDER BY r.executed_at DESC, r.id DESC LIMIT 1) AS last_status,"
        " (SELECT r.detail FROM check_results r WHERE r.check_id = c.id"
        "   ORDER BY r.executed_at DESC, r.id DESC LIMIT 1) AS last_detail,"
        " (SELECT r.executed_at FROM check_results r WHERE r.check_id = c.id"
        "   ORDER BY r.executed_at DESC, r.id DESC LIMIT 1) AS last_executed_at,"
        " (SELECT r.latency_ms FROM check_results r WHERE r.check_id = c.id"
        "   ORDER BY r.executed_at DESC, r.id DESC LIMIT 1) AS last_latency_ms,"
        " (SELECT i.id FROM check_incidents i WHERE i.check_id = c.id"
        "   AND i.status IN (?, ?) ORDER BY i.id DESC LIMIT 1) AS incident_id"
        " FROM checks c WHERE c.tenant_id = ? AND c.target_id = ?"
        " ORDER BY c.name",
        (INCIDENT_OPEN, INCIDENT_ACK, tenant_id, target_id))
    controlli = []
    for riga in righe:
        voce = dict(riga)
        voce["config"] = _decode(riga)
        voce["description"] = describe(voce["kind"], voce["config"])
        controlli.append(voce)
    return controlli


def check(tenant_id: int, check_id: int) -> dict | None:
    riga = query(
        "SELECT c.*, t.address, t.name AS target_name, t.id AS target_id"
        " FROM checks c JOIN check_targets t ON t.id = c.target_id"
        " WHERE c.id = ? AND c.tenant_id = ?", (check_id, tenant_id), one=True)
    if riga is None:
        return None
    voce = dict(riga)
    voce["config"] = _decode(riga)
    voce["description"] = describe(voce["kind"], voce["config"])
    return voce


def results(tenant_id: int, check_id: int, limit: int = 200) -> list[dict]:
    righe = query(
        "SELECT r.*, p.name AS probe_name FROM check_results r"
        " LEFT JOIN probes p ON p.id = r.probe_id"
        " WHERE r.tenant_id = ? AND r.check_id = ?"
        " ORDER BY r.executed_at DESC, r.id DESC LIMIT ?",
        (tenant_id, check_id, int(limit)))
    return [dict(r) for r in righe]


def recent_results(tenant_id: int, limit: int = 300, only_failures: bool = False) -> list[dict]:
    """Ultimi esiti di tutti i controlli del tenant."""
    condizione = "" if not only_failures else " AND r.status <> '%s'" % STATUS_OK
    righe = query(
        "SELECT r.*, c.name AS check_name, c.kind, t.address, t.name AS target_name,"
        " p.name AS probe_name FROM check_results r"
        " JOIN checks c ON c.id = r.check_id"
        " JOIN check_targets t ON t.id = c.target_id"
        " LEFT JOIN probes p ON p.id = r.probe_id"
        " WHERE r.tenant_id = ?" + condizione +
        " ORDER BY r.executed_at DESC, r.id DESC LIMIT ?",
        (tenant_id, int(limit)))
    return [dict(r) for r in righe]


def incidents(tenant_id: int, status: str = None, limit: int = 200) -> list[dict]:
    parametri = [tenant_id]
    condizione = ""
    if status == "aperti":
        condizione = " AND i.status IN (?, ?)"
        parametri.extend([INCIDENT_OPEN, INCIDENT_ACK])
    elif status:
        condizione = " AND i.status = ?"
        parametri.append(status)
    parametri.append(int(limit))
    righe = query(
        "SELECT i.*, c.name AS check_name, c.kind, c.escalation_threshold,"
        " c.escalation_email, t.address,"
        " t.name AS target_name, ua.email AS acknowledged_email,"
        " ur.email AS resolved_email"
        " FROM check_incidents i"
        " JOIN checks c ON c.id = i.check_id"
        " JOIN check_targets t ON t.id = c.target_id"
        " LEFT JOIN users ua ON ua.id = i.acknowledged_by"
        " LEFT JOIN users ur ON ur.id = i.resolved_by"
        " WHERE i.tenant_id = ?" + condizione +
        " ORDER BY CASE i.status WHEN 'open' THEN 0 WHEN 'acknowledged' THEN 1 ELSE 2 END,"
        " i.opened_at DESC LIMIT ?", parametri)
    return [dict(r) for r in righe]


def incident(tenant_id: int, incident_id: int) -> dict | None:
    riga = query(
        "SELECT i.*, c.name AS check_name, c.kind, c.escalation_threshold,"
        " c.escalation_email, c.config_json,"
        " t.address, t.name AS target_name, t.id AS target_id,"
        " ua.email AS acknowledged_email, ur.email AS resolved_email"
        " FROM check_incidents i"
        " JOIN checks c ON c.id = i.check_id"
        " JOIN check_targets t ON t.id = c.target_id"
        " LEFT JOIN users ua ON ua.id = i.acknowledged_by"
        " LEFT JOIN users ur ON ur.id = i.resolved_by"
        " WHERE i.id = ? AND i.tenant_id = ?", (incident_id, tenant_id), one=True)
    if riga is None:
        return None
    voce = dict(riga)
    voce["config"] = _decode(riga)
    return voce


def incident_events(tenant_id: int, incident_id: int) -> list[dict]:
    righe = query("SELECT * FROM check_incident_events WHERE tenant_id = ?"
                  " AND incident_id = ? ORDER BY created_at, id",
                  (tenant_id, incident_id))
    return [dict(r) for r in righe]


# --------------------------------------------------------------------------- #
# Metriche raccolte
# --------------------------------------------------------------------------- #
def available_metrics(tenant_id: int, check_id: int) -> list[dict]:
    """Dati che questo controllo puo' conservare, con il valore piu' recente.

    Due fonti: l'ULTIMA risposta ricevuta -- che mostra tutto cio' che l'endpoint
    restituisce, comprese le voci mai conservate -- e i nomi gia' in archivio, che
    coprono il caso di un endpoint che oggi risponde diversamente o non risponde.

    Senza questo elenco la scelta sarebbe un campo di testo in cui scrivere a memoria
    i nomi dei campi dentro un JSON scritto da altri: un percorso sbagliato non da'
    errore, semplicemente non conserva nulla.
    """
    from .checks import flatten_metrics

    disponibili = {}

    ultimo = query(
        "SELECT payload_json FROM check_results WHERE tenant_id = ? AND check_id = ?"
        " AND payload_json IS NOT NULL ORDER BY id DESC LIMIT 1",
        (tenant_id, check_id), one=True)
    if ultimo is not None:
        grezzo = (ultimo["payload_json"] or "").strip()
        if grezzo.startswith("{") or grezzo.startswith("["):
            try:
                documento = json.loads(grezzo)
            except ValueError:
                # Risposta non piu' interpretabile: l'elenco si limita all'archivio.
                documento = None
            if documento is not None:
                for nome, numero, testo in flatten_metrics(documento):
                    disponibili[nome] = {
                        "name": nome, "label": metric_label(nome),
                        "value": numero, "text_value": testo, "stored": False,
                        "numeric": numero is not None,
                    }

    for riga in query(
            "SELECT DISTINCT name FROM check_metrics WHERE tenant_id = ? AND check_id = ?"
            " ORDER BY name", (tenant_id, check_id)):
        voce = disponibili.setdefault(riga["name"], {
            "name": riga["name"], "label": metric_label(riga["name"]),
            "value": None, "text_value": None, "numeric": False})
        voce["stored"] = True

    # La latenza non viene dalla risposta ma dall'esecuzione: non si sceglie, resta.
    disponibili.pop("latency_ms", None)
    return [disponibili[nome] for nome in sorted(disponibili)]


def _filtra(voci: list, selezione, chiave: str = "name") -> list:
    """Tiene le voci scelte. Selezione vuota: tutte.

    Le misure escluse restano in archivio e vengono soltanto nascoste: distruggere
    uno storico per una preferenza di presentazione non sarebbe reversibile.
    """
    if not selezione:
        return voci
    ammessi = set(selezione) | {"latency_ms"}
    return [voce for voce in voci if voce[chiave] in ammessi]


def metrics_latest(tenant_id: int, check_id: int, selection=None) -> list[dict]:
    """Ultimo valore di ciascun punto di misura, con la sintesi delle 24 ore.

    La sintesi accanto al valore corrente e' cio' che rende la misura leggibile:
    un uptime di 98765 secondi non dice nulla; un uptime che nelle ultime 24 ore
    ha avuto minimo 12 e massimo 98765 dice che il servizio si e' riavviato.
    """
    righe = query(
        "SELECT m.name,"
        " (SELECT u.value FROM check_metrics u WHERE u.check_id = m.check_id"
        "   AND u.name = m.name ORDER BY u.measured_at DESC, u.id DESC LIMIT 1) AS value,"
        " (SELECT u.text_value FROM check_metrics u WHERE u.check_id = m.check_id"
        "   AND u.name = m.name ORDER BY u.measured_at DESC, u.id DESC LIMIT 1)"
        "   AS text_value,"
        " (SELECT u.measured_at FROM check_metrics u WHERE u.check_id = m.check_id"
        "   AND u.name = m.name ORDER BY u.measured_at DESC, u.id DESC LIMIT 1)"
        "   AS measured_at,"
        " COUNT(*) AS samples,"
        " MIN(CASE WHEN m.measured_at >= ? THEN m.value END) AS min_24h,"
        " MAX(CASE WHEN m.measured_at >= ? THEN m.value END) AS max_24h,"
        " AVG(CASE WHEN m.measured_at >= ? THEN m.value END) AS avg_24h,"
        " COUNT(DISTINCT m.text_value) AS distinct_texts"
        " FROM check_metrics m WHERE m.tenant_id = ? AND m.check_id = ?"
        " GROUP BY m.name ORDER BY m.name",
        (days_ago_str(1), days_ago_str(1), days_ago_str(1), tenant_id, check_id))
    return _filtra([dict(r) for r in righe], selection)


def metric_series(tenant_id: int, check_id: int, name: str,
                  limit: int = 500) -> list[dict]:
    """Serie storica di un punto di misura, dal piu' recente."""
    righe = query(
        "SELECT measured_at, value, text_value FROM check_metrics"
        " WHERE tenant_id = ? AND check_id = ? AND name = ?"
        " ORDER BY measured_at DESC, id DESC LIMIT ?",
        (tenant_id, check_id, name, int(limit)))
    return [dict(r) for r in righe]


# Numero massimo di serie rappresentate. Non e' una scelta di presentazione ma una
# guardia: un esito produce al massimo MAX_METRICS_PER_RESULT punti di misura, quindi
# le serie sono limitate alla fonte. Questo valore protegge soltanto dal caso di un
# controllo la cui definizione e' cambiata molte volte lasciando serie diverse.
MAX_CHART_SERIES = 200


def numeric_series(tenant_id: int, check_id: int, limit_per_series: int = 200,
                   max_series: int = MAX_CHART_SERIES, selection=None) -> list[dict]:
    """Serie numeriche del controllo, in ordine cronologico crescente.

    Crescente perche' e' l'ordine in cui un andamento si legge; le tabelle restano
    dal piu' recente, che e' l'ordine in cui si consultano.

    Una sola interrogazione per tutte le serie: una per serie significava sedici
    interrogazioni per un endpoint con quindici contatori, e il costo cresceva con
    le misure raccolte.
    """
    righe = query(
        "SELECT name, measured_at, value FROM check_metrics"
        " WHERE tenant_id = ? AND check_id = ? AND value IS NOT NULL"
        " ORDER BY name, measured_at DESC, id DESC",
        (tenant_id, check_id))

    # Raggruppamento in memoria: le righe arrivano ordinate per nome e, dentro
    # ciascun nome, dal piu' recente.
    per_nome = {}
    for riga in righe:
        punti = per_nome.setdefault(riga["name"], [])
        if len(punti) < int(limit_per_series):
            punti.append((riga["measured_at"], float(riga["value"])))

    serie = []
    for nome in sorted(per_nome):
        punti = per_nome[nome]
        if len(punti) < 2:
            continue  # con un punto solo non c'e' andamento da rappresentare
        if len(serie) >= int(max_series):
            break
        valori = [v for _, v in punti]
        minimo = min(valori) if valori else None
        massimo = max(valori) if valori else None
        # Una serie costante non ha andamento: dirlo in una riga e' piu' utile che
        # disegnare una retta orizzontale. Una serie binaria (aperta/chiusa,
        # raggiungibile/no) ha come informazione la percentuale di campioni
        # positivi, cioe' la disponibilita'.
        costante = minimo == massimo
        binaria = bool(valori) and set(valori) <= {0.0, 1.0}
        serie.append({
            "name": nome,
            "label": metric_label(nome),
            "samples": len(punti),
            # I punti arrivano dal piu' recente: si rovesciano per il disegno.
            # L'istante si converte nel fuso del tenant come ogni data mostrata:
            # un grafico in UTC accanto a una tabella nel fuso locale fa credere a
            # due misure diverse della stessa cosa.
            "points": [[fmt_grafico(quando), valore]
                       for quando, valore in reversed(punti)],
            "last": valori[0] if valori else None,
            "min": minimo,
            "max": massimo,
            "avg": (sum(valori) / len(valori)) if valori else None,
            "constant": costante,
            "binary": binaria,
            "positive_ratio": (round(100.0 * sum(valori) / len(valori), 1)
                               if binaria and valori else None),
        })
    # Prima cio' che varia: sono le serie da guardare. Le costanti chiudono
    # l'elenco, e la pagina le riduce a una riga.
    serie.sort(key=lambda s: (s["constant"], s["name"]))
    return _filtra(serie, selection)


def numeric_series_omitted(tenant_id: int, check_id: int,
                          max_series: int = MAX_CHART_SERIES, selection=None) -> int:
    """Quante serie numeriche non sono state rappresentate.

    Cio' che l'operatore ha escluso di proposito non e' "omesso": il conteggio si
    riferisce al limite di rappresentazione, non alla scelta.
    """
    if selection:
        nomi = query(
            "SELECT name FROM check_metrics WHERE tenant_id = ? AND check_id = ?"
            " AND value IS NOT NULL GROUP BY name HAVING COUNT(*) >= 2",
            (tenant_id, check_id))
        ammessi = set(selection) | {"latency_ms"}
        totali = len([r for r in nomi if r["name"] in ammessi])
    else:
        totali = scalar(
            "SELECT COUNT(*) FROM (SELECT name FROM check_metrics"
            " WHERE tenant_id = ? AND check_id = ? AND value IS NOT NULL"
            " GROUP BY name HAVING COUNT(*) >= 2)", (tenant_id, check_id))
    return max(0, int(totali or 0) - int(max_series))


def latency_points(tenant_id: int, check_id: int, limit: int = 60) -> list:
    """Andamento della latenza, per la miniatura accanto a ciascun controllo."""
    punti = query(
        "SELECT executed_at, latency_ms FROM check_results"
        " WHERE tenant_id = ? AND check_id = ? AND latency_ms IS NOT NULL"
        " ORDER BY executed_at DESC, id DESC LIMIT ?",
        (tenant_id, check_id, int(limit)))
    return [[fmt_grafico(p["executed_at"]), float(p["latency_ms"])]
            for p in reversed(punti)]


def metrics_recent(tenant_id: int, limit: int = 300) -> list[dict]:
    """Ultime misure di tutti i controlli del tenant."""
    righe = query(
        "SELECT m.*, c.name AS check_name, t.address, t.name AS target_name"
        " FROM check_metrics m JOIN checks c ON c.id = m.check_id"
        " JOIN check_targets t ON t.id = c.target_id"
        " WHERE m.tenant_id = ? ORDER BY m.measured_at DESC, m.id DESC LIMIT ?",
        (tenant_id, int(limit)))
    return [dict(r) for r in righe]


def results_hourly(tenant_id: int, hours: int = 24) -> list[dict]:
    """Esiti dei controlli raggruppati per ora, dal piu' vecchio al piu' recente.

    Le ore senza esecuzioni non compaiono: inventare uno zero dove non e' stato
    eseguito nulla farebbe leggere un crollo dove c'e' solo assenza di dati.
    """
    righe = query(
        "SELECT strftime('%Y-%m-%d %H:00:00', executed_at) AS ora,"
        " COUNT(*) AS totali,"
        " SUM(CASE WHEN status = ? THEN 0 ELSE 1 END) AS falliti"
        " FROM check_results WHERE tenant_id = ? AND executed_at >= ?"
        " GROUP BY ora ORDER BY ora",
        (STATUS_OK, tenant_id, hours_ago_str(hours)))
    andamento = []
    for riga in righe:
        totali = int(riga["totali"] or 0)
        falliti = int(riga["falliti"] or 0)
        andamento.append({
            "hour": riga["ora"],
            "total": totali,
            "failed": falliti,
            "success_rate": round(100.0 * (totali - falliti) / totali, 1) if totali else None,
        })
    return andamento


def incidents_daily(tenant_id: int, days: int = 14) -> list[dict]:
    """Incidenti aperti e risolti per giorno."""
    aperti = query(
        "SELECT substr(opened_at, 1, 10) AS giorno, COUNT(*) AS quanti"
        " FROM check_incidents WHERE tenant_id = ? AND opened_at >= ?"
        " GROUP BY giorno ORDER BY giorno", (tenant_id, days_ago_str(days)))
    risolti = query(
        "SELECT substr(resolved_at, 1, 10) AS giorno, COUNT(*) AS quanti"
        " FROM check_incidents WHERE tenant_id = ? AND resolved_at >= ?"
        " GROUP BY giorno ORDER BY giorno", (tenant_id, days_ago_str(days)))
    chiusi = {r["giorno"]: int(r["quanti"]) for r in risolti}
    return [{"day": r["giorno"], "opened": int(r["quanti"]),
             "resolved": chiusi.get(r["giorno"], 0)} for r in aperti]


def metrics_summary(tenant_id: int) -> dict:
    """Quante misure sono conservate e su quanti punti distinti."""
    totali = scalar("SELECT COUNT(*) FROM check_metrics WHERE tenant_id = ?", (tenant_id,))
    punti = scalar("SELECT COUNT(*) FROM (SELECT DISTINCT check_id, name"
                   " FROM check_metrics WHERE tenant_id = ?)", (tenant_id,))
    ultime = scalar("SELECT COUNT(*) FROM check_metrics WHERE tenant_id = ?"
                    " AND measured_at >= ?", (tenant_id, days_ago_str(1)))
    return {"total": totali, "series": punti, "last_24h": ultime}
