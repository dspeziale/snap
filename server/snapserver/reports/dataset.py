"""
snap server - Dati dei report: una funzione per sezione.

Ogni funzione riceve il tenant e una finestra e restituisce dati grezzi, senza
impaginazione: la stessa sezione alimenta il corpo dell'email e il PDF, cosi' un
numero che differisce fra i due e' impossibile per costruzione.

Regole che questo modulo fa rispettare (docs/08_REPORT.md):

* RP-05 l'assenza di dati non e' uno zero: le sezioni dichiarano `misurato: False`
  invece di restituire percentuali costruite su zero campioni;
* RP-12 la variazione e' il segnale: le variazioni sono la prima sezione degli eventi;
* RP-13 nei primi giorni di vita di un inventario le variazioni si contano ma non si
  elencano, altrimenti il primo resoconto sarebbe illeggibile e verrebbe ignorato per
  sempre;
* la variazione che riguarda oltre un quinto dei nodi diventa un fatto aggregato,
  perche' 264 nodi con la stessa porta aperta sono un apparato che risponde per altri.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from datetime import timedelta

from ..checks import (
    INCIDENT_ACK,
    INCIDENT_OPEN,
    INCIDENT_RESOLVED,
    STATUS_OK,
)
from ..db import parse_utc, query, scalar, utc_now, utc_str
from .windows import day_bounds, local_day_of, local_hhmm

# Una sonda che non parla da questo tempo e' un problema, non un ritardo: il battito
# nominale e' di un minuto e la tolleranza tiene conto di una scansione lunga.
SILENT_PROBE_MINUTES = 15
# Sotto questo numero di esiti non si dichiara "mai riuscito": due fallimenti possono
# essere l'avvio di un servizio.
NEVER_OK_MIN_RESULTS = 3
# Oltre questa quota di nodi coinvolti, una variazione e' un fatto aggregato.
AGGREGATE_RATIO = 0.20
# Giorni di rilevamento di base, durante i quali le variazioni non si elencano.
BASELINE_DAYS = 7
# Guardie: un resoconto non deve diventare un elenco, e una lettura non deve
# diventare una scansione integrale dell'archivio.
TOP_CHANGES = 10
TOP_OUTAGES = 8
TOP_ISSUES = 20
MAX_TREND_ROWS = 60000
MAX_OUTAGE_ROWS = 20000


# --------------------------------------------------------------------------- #
# Utilita'
# --------------------------------------------------------------------------- #
def _percentile(valori: list, quantile: float):
    """Percentile su una lista non vuota, con interpolazione al campione piu' vicino.

    Non si usa `statistics.quantiles`: su liste di due o tre campioni solleva o
    restituisce valori che non corrispondono a nessuna misura reale, e in un report
    un numero che non e' stato misurato e' peggio di un numero assente.
    """
    if not valori:
        return None
    ordinati = sorted(valori)
    if len(ordinati) == 1:
        return ordinati[0]
    posizione = int(round(quantile * (len(ordinati) - 1)))
    return ordinati[posizione]


def _minuti(dal: str, al: str) -> int:
    inizio, fine = parse_utc(dal), parse_utc(al)
    if inizio is None or fine is None:
        return 0
    return max(0, int((fine - inizio).total_seconds() // 60))


# --------------------------------------------------------------------------- #
# Stato dell'inventario
# --------------------------------------------------------------------------- #
def inventory(tenant_id: int) -> dict:
    riga = query(
        "SELECT COUNT(*) AS nodi, COALESCE(SUM(status = 'up'), 0) AS su,"
        " COALESCE(SUM(status = 'down'), 0) AS giu,"
        " COALESCE(SUM(device_type IS NULL OR device_type = ''), 0) AS senza_tipo,"
        " MIN(first_seen_at) AS primo"
        " FROM nodes WHERE tenant_id = ?", (tenant_id,), one=True)
    subnet = query(
        "SELECT COUNT(*) AS dichiarate, COALESCE(SUM(host_count), 0) AS teorici,"
        " COALESCE(SUM(is_enabled), 0) AS attive"
        " FROM subnets WHERE tenant_id = ?", (tenant_id,), one=True)
    dati = dict(riga or {})
    dati.update({"subnet_%s" % k: (subnet[k] if subnet else 0) for k in
                 ("dichiarate", "teorici", "attive")})
    teorici = int(dati.get("subnet_teorici") or 0)
    dati["occupazione"] = (round(100.0 * int(dati.get("nodi") or 0) / teorici, 1)
                           if teorici else None)
    return dati


def baseline(tenant_id: int, giorno, zona) -> dict:
    """Stato del rilevamento di base: primi giorni di vita dell'inventario.

    Il primo giro di scansione ha prodotto 1851 aperture di porta e 289 nodi comparsi:
    presentarle come novita' della giornata renderebbe il resoconto illeggibile.
    """
    primo = scalar("SELECT MIN(first_seen_at) FROM nodes WHERE tenant_id = ?",
                   (tenant_id,), default=None)
    inizio = parse_utc(primo) if primo else None
    if inizio is None:
        return {"attivo": False, "giorno": 0, "di": BASELINE_DAYS, "fine": None}
    primo_giorno = inizio.astimezone(zona).date()
    trascorsi = (giorno - primo_giorno).days
    return {
        "attivo": 0 <= trascorsi < BASELINE_DAYS,
        "giorno": trascorsi + 1,
        "di": BASELINE_DAYS,
        "fine": primo_giorno + timedelta(days=BASELINE_DAYS),
    }


# --------------------------------------------------------------------------- #
# Da risolvere
# --------------------------------------------------------------------------- #
def open_issues(tenant_id: int, zona) -> list:
    """Questioni aperte, in ordine di urgenza. E' la prima sezione del resoconto.

    Ordine: chi e' stato attivato e non ha risposto, poi gli incidenti aperti, poi le
    cause per cui il sistema potrebbe non vedere nulla (sonda muta, scansioni ferme),
    poi cio' che e' mal configurato, infine gli allarmi che non sono partiti.
    """
    questioni = []
    adesso = utc_now()
    soglia_sonda = utc_str(adesso - timedelta(minutes=SILENT_PROBE_MINUTES))

    incidenti = query(
        "SELECT i.id, i.status, i.severity, i.opened_at, i.escalated_at, i.escalated_to,"
        " i.acknowledged_at, i.failure_count, i.last_detail, c.name AS controllo,"
        " t.address FROM check_incidents i"
        " JOIN checks c ON c.id = i.check_id"
        " JOIN check_targets t ON t.id = c.target_id"
        " WHERE i.tenant_id = ? AND i.status IN (?, ?)"
        " ORDER BY (i.escalated_at IS NOT NULL AND i.acknowledged_at IS NULL) DESC,"
        " i.opened_at", (tenant_id, INCIDENT_OPEN, INCIDENT_ACK))
    for riga in incidenti:
        scalato_muto = bool(riga["escalated_at"]) and not riga["acknowledged_at"]
        questioni.append({
            "tipo": "incidente_scalato" if scalato_muto else "incidente",
            "gravita": "critical" if scalato_muto else (riga["severity"] or "warning"),
            "titolo": ("Incidente #%d scalato e non preso in carico" % riga["id"])
                      if scalato_muto else ("Incidente #%d aperto" % riga["id"]),
            "soggetto": "%s su %s" % (riga["controllo"], riga["address"]),
            "dettaglio": (riga["last_detail"] or "")[:200],
            "da": local_hhmm(riga["opened_at"], zona),
            "eta_minuti": _minuti(riga["opened_at"], utc_str(adesso)),
            "recapito": riga["escalated_to"] or "",
            "id": riga["id"],
        })

    mai_riusciti = query(
        "SELECT c.id, c.name, t.address, COUNT(r.id) AS esiti,"
        " COALESCE(SUM(r.status = ?), 0) AS riusciti,"
        " ROUND(AVG(r.latency_ms), 0) AS latenza, MAX(r.detail) AS dettaglio"
        " FROM checks c JOIN check_targets t ON t.id = c.target_id"
        " LEFT JOIN check_results r ON r.check_id = c.id"
        " WHERE c.tenant_id = ? AND c.is_enabled = 1"
        " GROUP BY c.id HAVING esiti >= ? AND riusciti = 0",
        (STATUS_OK, tenant_id, NEVER_OK_MIN_RESULTS))
    for riga in mai_riusciti:
        questioni.append({
            "tipo": "controllo_mai_riuscito",
            "gravita": "warning",
            "titolo": "Controllo mai riuscito: \"%s\"" % riga["name"],
            "soggetto": riga["address"],
            "dettaglio": "%d esiti, 0 riusciti, latenza media %s ms. %s"
                         % (riga["esiti"], riga["latenza"] or "?",
                            "Verificare la definizione: non e' un servizio caduto."),
            "id": riga["id"],
        })

    sonde = query(
        "SELECT name, last_seen_at FROM probes WHERE tenant_id = ? AND revoked_at IS NULL"
        " AND (last_seen_at IS NULL OR last_seen_at < ?)", (tenant_id, soglia_sonda))
    for riga in sonde:
        questioni.append({
            "tipo": "sonda_muta",
            "gravita": "critical",
            "titolo": "Sonda muta: \"%s\"" % riga["name"],
            "soggetto": "ultimo contatto %s" % (riga["last_seen_at"] or "mai"),
            "dettaglio": "Senza sonda la raccolta e' cieca e i controlli non vengono"
                         " eseguiti.",
        })

    scansioni = query(
        "SELECT stage, status, COUNT(*) AS n, MAX(detail) AS dettaglio FROM scan_runs"
        " WHERE tenant_id = ? AND status <> 'completed' AND created_at >= ?"
        " GROUP BY stage, status", (tenant_id, utc_str(adesso - timedelta(days=1))))
    for riga in scansioni:
        questioni.append({
            "tipo": "scansione_fallita",
            "gravita": "warning",
            "titolo": "Scansioni non completate: %s (%s)" % (riga["stage"], riga["status"]),
            "soggetto": "%d passate nelle ultime 24 ore" % riga["n"],
            "dettaglio": (riga["dettaglio"] or "Un inventario che non si aggiorna"
                          " invecchia in silenzio.")[:200],
        })

    notifiche = query(
        "SELECT COUNT(*) AS n, MAX(last_error) AS errore FROM notifications"
        " WHERE tenant_id = ? AND status = 'failed'", (tenant_id,), one=True)
    if notifiche and int(notifiche["n"] or 0) > 0:
        questioni.append({
            "tipo": "notifica_non_recapitata",
            "gravita": "warning",
            "titolo": "%d notifiche non recapitate" % int(notifiche["n"]),
            "soggetto": "coda di uscita",
            "dettaglio": (notifiche["errore"] or "")[:200] or
                         "Un allarme che non e' partito e' peggio di uno assente.",
        })

    return questioni[:TOP_ISSUES]


# --------------------------------------------------------------------------- #
# Disponibilita' dei servizi sorvegliati
# --------------------------------------------------------------------------- #
def availability(tenant_id: int, inizio: str, fine: str) -> dict:
    """Disponibilita' per controllo nella finestra, piu' il totale.

    `misurato` a falso significa che nella finestra non e' stata eseguita nessuna
    verifica: il resoconto lo dichiara invece di annunciare "disponibilita' 0%".
    """
    righe = query(
        "SELECT c.id, c.name, c.kind, t.address, COUNT(r.id) AS esiti,"
        " COALESCE(SUM(r.status = ?), 0) AS riusciti,"
        " ROUND(AVG(r.latency_ms), 1) AS latenza_media,"
        " ROUND(MAX(r.latency_ms), 0) AS latenza_massima"
        " FROM check_results r JOIN checks c ON c.id = r.check_id"
        " JOIN check_targets t ON t.id = c.target_id"
        " WHERE r.tenant_id = ? AND r.executed_at >= ? AND r.executed_at < ?"
        " GROUP BY c.id ORDER BY (1.0 * riusciti / esiti), t.address",
        (STATUS_OK, tenant_id, inizio, fine))

    voci = []
    esiti_totali = riusciti_totali = 0
    for riga in righe:
        esiti = int(riga["esiti"] or 0)
        riusciti = int(riga["riusciti"] or 0)
        esiti_totali += esiti
        riusciti_totali += riusciti
        voci.append({
            "check_id": riga["id"], "nome": riga["name"], "genere": riga["kind"],
            "indirizzo": riga["address"], "esiti": esiti, "riusciti": riusciti,
            "percentuale": round(100.0 * riusciti / esiti, 2) if esiti else None,
            "latenza_media": riga["latenza_media"],
            "latenza_massima": riga["latenza_massima"],
        })
    return {
        "misurato": esiti_totali > 0,
        "esiti": esiti_totali,
        "riusciti": riusciti_totali,
        "percentuale": (round(100.0 * riusciti_totali / esiti_totali, 2)
                        if esiti_totali else None),
        "controlli": voci,
    }


def outages(tenant_id: int, inizio: str, fine: str, zona) -> list:
    """Finestre di indisponibilita': serie consecutive di esiti non riusciti.

    Si ricavano in memoria e non in SQL: riconoscere una serie consecutiva richiede
    di guardare l'esito precedente, e farlo in SQLite significherebbe una funzione
    finestra per riga con un costo che cresce con l'archivio.
    """
    righe = query(
        "SELECT r.check_id, r.status, r.executed_at, r.detail, c.name, t.address"
        " FROM check_results r JOIN checks c ON c.id = r.check_id"
        " JOIN check_targets t ON t.id = c.target_id"
        " WHERE r.tenant_id = ? AND r.executed_at >= ? AND r.executed_at < ?"
        " ORDER BY r.check_id, r.executed_at LIMIT ?",
        (tenant_id, inizio, fine, MAX_OUTAGE_ROWS))

    finestre = []
    corrente = None
    for riga in righe:
        if riga["status"] == STATUS_OK:
            if corrente is not None:
                corrente["fine"] = riga["executed_at"]
                finestre.append(corrente)
                corrente = None
            continue
        if corrente is not None and corrente["check_id"] == riga["check_id"]:
            corrente["esiti"] += 1
            corrente["ultimo"] = riga["executed_at"]
            continue
        if corrente is not None:
            finestre.append(corrente)  # cambio di controllo: la serie resta aperta
        corrente = {
            "check_id": riga["check_id"], "nome": riga["name"],
            "indirizzo": riga["address"], "inizio": riga["executed_at"],
            "ultimo": riga["executed_at"], "fine": None, "esiti": 1,
            "dettaglio": (riga["detail"] or "")[:160],
        }
    if corrente is not None:
        finestre.append(corrente)

    for finestra in finestre:
        chiusura = finestra["fine"] or finestra["ultimo"]
        finestra["aperta"] = finestra["fine"] is None
        finestra["durata_minuti"] = _minuti(finestra["inizio"], chiusura)
        finestra["da"] = local_hhmm(finestra["inizio"], zona)
        finestra["a"] = local_hhmm(chiusura, zona)
    finestre.sort(key=lambda f: (-f["durata_minuti"], f["inizio"]))
    return finestre[:TOP_OUTAGES]


# --------------------------------------------------------------------------- #
# Incidenti del periodo
# --------------------------------------------------------------------------- #
def incidents(tenant_id: int, inizio: str, fine: str, zona) -> dict:
    aperti = query(
        "SELECT i.id, i.severity, i.opened_at, i.resolved_at, i.failure_count,"
        " i.escalated_at, i.acknowledged_at, i.status, c.name AS controllo, t.address"
        " FROM check_incidents i JOIN checks c ON c.id = i.check_id"
        " JOIN check_targets t ON t.id = c.target_id"
        " WHERE i.tenant_id = ? AND i.opened_at >= ? AND i.opened_at < ?"
        " ORDER BY i.opened_at", (tenant_id, inizio, fine))
    risolti = query(
        "SELECT i.id, i.opened_at, i.resolved_at FROM check_incidents i"
        " WHERE i.tenant_id = ? AND i.resolved_at >= ? AND i.resolved_at < ?",
        (tenant_id, inizio, fine))

    voci = []
    for riga in aperti:
        durata = (_minuti(riga["opened_at"], riga["resolved_at"])
                  if riga["resolved_at"] else None)
        voci.append({
            "id": riga["id"], "gravita": riga["severity"], "stato": riga["status"],
            "controllo": riga["controllo"], "indirizzo": riga["address"],
            "aperto": local_hhmm(riga["opened_at"], zona),
            "risolto": local_hhmm(riga["resolved_at"], zona) if riga["resolved_at"] else None,
            "durata_minuti": durata, "fallimenti": riga["failure_count"],
            "scalato": bool(riga["escalated_at"]),
            "preso_in_carico": bool(riga["acknowledged_at"]),
        })

    durate = [_minuti(r["opened_at"], r["resolved_at"]) for r in risolti
              if r["resolved_at"] and r["opened_at"]]
    return {
        "aperti": len(voci),
        "risolti": len(risolti),
        "voci": voci,
        "durata_media_minuti": int(sum(durate) / len(durate)) if durate else None,
        "durata_massima_minuti": max(durate) if durate else None,
    }


# --------------------------------------------------------------------------- #
# Variazioni dell'inventario
# --------------------------------------------------------------------------- #
def changes(tenant_id: int, inizio: str, fine: str, nodi_totali: int) -> dict:
    """Variazioni per genere, con l'elenco solo quando l'elenco e' informativo."""
    generi = query(
        "SELECT kind, severity, COUNT(*) AS n, COUNT(DISTINCT node_id) AS nodi"
        " FROM node_changes WHERE tenant_id = ? AND created_at >= ? AND created_at < ?"
        " GROUP BY kind ORDER BY n DESC", (tenant_id, inizio, fine))

    soglia = max(1, int(AGGREGATE_RATIO * max(1, nodi_totali)))
    voci = []
    for riga in generi:
        nodi = int(riga["nodi"] or 0)
        aggregato = nodi > soglia
        esempi = []
        if not aggregato:
            esempi = [{"soggetto": r["subject"], "da": r["before_value"],
                       "a": r["after_value"]}
                      for r in query(
                          "SELECT subject, before_value, after_value FROM node_changes"
                          " WHERE tenant_id = ? AND kind = ? AND created_at >= ?"
                          " AND created_at < ? ORDER BY created_at DESC LIMIT ?",
                          (tenant_id, riga["kind"], inizio, fine, TOP_CHANGES))]
        voci.append({
            "genere": riga["kind"], "gravita": riga["severity"],
            "eventi": int(riga["n"] or 0), "nodi": nodi,
            "aggregato": aggregato, "esempi": esempi,
        })
    return {
        "totale": sum(v["eventi"] for v in voci),
        "soglia_aggregazione": soglia,
        "generi": voci,
    }


# --------------------------------------------------------------------------- #
# Raccolta: sonde, scansioni, conferimenti
# --------------------------------------------------------------------------- #
def collection(tenant_id: int, inizio: str, fine: str, zona) -> dict:
    passate = query(
        "SELECT stage, status, COUNT(*) AS n, ROUND(AVG(duration_ms) / 1000.0, 1) AS secondi,"
        " COALESCE(SUM(hosts_up), 0) AS su, COALESCE(SUM(hosts_total), 0) AS totali"
        " FROM scan_runs WHERE tenant_id = ? AND created_at >= ? AND created_at < ?"
        " GROUP BY stage, status ORDER BY n DESC", (tenant_id, inizio, fine))
    lotti = query(
        "SELECT COUNT(*) AS lotti, COALESCE(SUM(record_count), 0) AS record,"
        " COALESCE(SUM(payload_bytes), 0) AS byte,"
        " COALESCE(SUM(status <> 'accepted'), 0) AS rifiutati"
        " FROM ingest_batches WHERE tenant_id = ? AND received_at >= ? AND received_at < ?",
        (tenant_id, inizio, fine), one=True)
    sonde = query(
        "SELECT name, status, last_seen_at, agent_version, scan_effort, scan_enabled"
        " FROM probes WHERE tenant_id = ? AND revoked_at IS NULL ORDER BY name",
        (tenant_id,))
    notifiche = query(
        "SELECT status, COUNT(*) AS n FROM notifications WHERE tenant_id = ?"
        " AND created_at >= ? AND created_at < ? GROUP BY status",
        (tenant_id, inizio, fine))

    return {
        "passate": [dict(r) for r in passate],
        "passate_totali": sum(int(r["n"]) for r in passate),
        "passate_fallite": sum(int(r["n"]) for r in passate if r["status"] != "completed"),
        "lotti": dict(lotti or {}),
        "sonde": [{"nome": r["name"], "stato": r["status"],
                   "ultimo_contatto": local_hhmm(r["last_seen_at"], zona),
                   "versione": r["agent_version"], "sforzo": r["scan_effort"],
                   "scansione_attiva": bool(r["scan_enabled"])} for r in sonde],
        "notifiche": {r["status"]: int(r["n"]) for r in notifiche},
    }


# --------------------------------------------------------------------------- #
# Tendenze
# --------------------------------------------------------------------------- #
def trends(tenant_id: int, zona, inizio: str, fine: str) -> dict:
    """Disponibilita' e latenza al 95esimo percentile, per giorno locale.

    I giorni senza esecuzioni restano nell'elenco con valori nulli e vengono
    dichiarati non misurati: e' la differenza fra "il servizio e' caduto" e "non
    abbiamo guardato" (RP-05).
    """
    righe = query(
        "SELECT executed_at, status, latency_ms FROM check_results"
        " WHERE tenant_id = ? AND executed_at >= ? AND executed_at < ?"
        " ORDER BY executed_at LIMIT ?", (tenant_id, inizio, fine, MAX_TREND_ROWS))

    per_giorno = {}
    for riga in righe:
        giorno = local_day_of(riga["executed_at"], zona)
        if giorno is None:
            continue
        voce = per_giorno.setdefault(giorno, {"esiti": 0, "ok": 0, "latenze": []})
        voce["esiti"] += 1
        if riga["status"] == STATUS_OK:
            voce["ok"] += 1
        if riga["latency_ms"] is not None:
            voce["latenze"].append(float(riga["latency_ms"]))

    giorni = []
    for giorno in sorted(per_giorno):
        voce = per_giorno[giorno]
        giorni.append({
            "giorno": giorno,
            "misurato": voce["esiti"] > 0,
            "esiti": voce["esiti"],
            "disponibilita": round(100.0 * voce["ok"] / voce["esiti"], 2)
                             if voce["esiti"] else None,
            "latenza_p95": (round(_percentile(voce["latenze"], 0.95), 0)
                            if voce["latenze"] else None),
        })
    return {
        "giorni": giorni,
        "troncato": len(righe) >= MAX_TREND_ROWS,
    }


# --------------------------------------------------------------------------- #
# Igiene
# --------------------------------------------------------------------------- #
def hygiene(tenant_id: int) -> dict:
    sospesi = query(
        "SELECT c.name, t.address FROM checks c JOIN check_targets t ON t.id = c.target_id"
        " WHERE c.tenant_id = ? AND c.is_enabled = 0 ORDER BY t.address", (tenant_id,))
    senza_controlli = query(
        "SELECT t.name, t.address FROM check_targets t"
        " LEFT JOIN checks c ON c.target_id = t.id"
        " WHERE t.tenant_id = ? GROUP BY t.id HAVING COUNT(c.id) = 0", (tenant_id,))
    return {
        "controlli_sospesi": [dict(r) for r in sospesi],
        "bersagli_senza_controlli": [dict(r) for r in senza_controlli],
        "nodi_non_identificati": scalar(
            "SELECT COUNT(*) FROM nodes WHERE tenant_id = ?"
            " AND (device_type IS NULL OR device_type = '')", (tenant_id,)),
        "porte_sospette": scalar(
            "SELECT COUNT(*) FROM node_ports WHERE tenant_id = ? AND is_suspect = 1",
            (tenant_id,)),
        "retention_giorni": scalar(
            "SELECT retention_days FROM tenants WHERE id = ?", (tenant_id,), default=None),
    }


# --------------------------------------------------------------------------- #
# Insieme completo per il resoconto e per il report NOC
# --------------------------------------------------------------------------- #
def daily(tenant: dict, giorno, zona, giorni_tendenza: int = 7) -> dict:
    """Tutte le sezioni per un giorno. E' l'unica funzione che i renderer chiamano."""
    from .windows import days_bounds, describe

    tenant_id = int(tenant["id"])
    inizio, fine = day_bounds(zona, giorno)
    inizio_tendenza, fine_tendenza = days_bounds(zona, giorni_tendenza, fino_a=giorno)

    inventario = inventory(tenant_id)
    dati = {
        "tenant": {"id": tenant_id, "nome": tenant["name"], "codice": tenant["code"],
                   "fuso": zona.key if hasattr(zona, "key") else str(zona)},
        "giorno": giorno,
        "intervallo": describe(giorno, zona),
        "inizio_utc": inizio,
        "fine_utc": fine,
        "inventario": inventario,
        "rilevamento_base": baseline(tenant_id, giorno, zona),
        "da_risolvere": open_issues(tenant_id, zona),
        "disponibilita": availability(tenant_id, inizio, fine),
        "indisponibilita": outages(tenant_id, inizio, fine, zona),
        "incidenti": incidents(tenant_id, inizio, fine, zona),
        "variazioni": changes(tenant_id, inizio, fine, int(inventario.get("nodi") or 0)),
        "raccolta": collection(tenant_id, inizio, fine, zona),
        "tendenze": trends(tenant_id, zona, inizio_tendenza, fine_tendenza),
        "igiene": hygiene(tenant_id),
        "generato_utc": utc_str(utc_now()),
    }
    # Un resoconto senza nulla da segnalare si spedisce comunque, in forma breve
    # (RP-06): il silenzio non si distingue da un guasto del reporting.
    dati["vuoto"] = (not dati["da_risolvere"]
                     and dati["incidenti"]["aperti"] == 0
                     and dati["variazioni"]["totale"] == 0
                     and not dati["disponibilita"]["misurato"])
    return dati


# I generi di variazione hanno nomi tecnici: la lettura richiede l'italiano.
CHANGE_LABELS = {
    "node.appeared": "nodi comparsi",
    "node.disappeared": "nodi scomparsi",
    "node.up": "nodi tornati raggiungibili",
    "node.down": "nodi non piu' raggiungibili",
    "port.opened": "porte aperte",
    "port.closed": "porte chiuse",
    "device_type.changed": "tipi di dispositivo assegnati",
    "os.changed": "sistemi operativi cambiati",
    "hostname.changed": "nomi host cambiati",
    "mac.changed": "indirizzi fisici cambiati",
    "service.changed": "servizi cambiati",
}


def change_label(genere: str) -> str:
    return CHANGE_LABELS.get(genere, (genere or "").replace(".", " "))
