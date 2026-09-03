"""
snap server - Menu SIEM: onboarding dei log, eventi di sicurezza e allarmi.

La pagina risponde a una domanda operativa: **di cio' che gli apparati raccontano
nei loro log, che cosa merita attenzione, e riguarda una macchina che ho gia'
segnalato come esposta?** L'onboarding dice al sistema quali apparati parlano e da
dove; la rilevazione trasforma le raffiche di eventi in allarmi; la correlazione
lega ogni allarme al nodo dell'inventario e ai suoi riscontri di threat
intelligence.

Permessi: consultazione a tutto il tenant; onboarding delle sorgenti, gestione dei
collettori, decisioni sugli allarmi e modifica delle regole agli analisti.

remarks: Autore: Daniele Speziale - Data: 2026-09-02
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from flask import (
    Blueprint,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from ..audit import log_event
from ..db import query
from ..security import ROLE_ANALYST, login_required, role_required
from ..tenancy import current_tenant_id
from ..siem import (
    ALERT_ACK,
    ALERT_CLOSED,
    ALERT_FALSE_POSITIVE,
    ALERT_STATUSES,
    EVENT_KINDS,
    SEVERITY_LABELS,
    SOURCE_KINDS,
    SYSLOG_PORT,
)
from ..siem import data, store

bp = Blueprint("siem", __name__, url_prefix="/siem")

SCHEDE = ("quadro", "sorgenti", "incolla", "eventi", "regole", "allarmi")


def _current_user_id():
    utente = getattr(g, "user", None)
    if utente is None:
        return None
    try:
        return int(utente["id"])
    except (KeyError, TypeError, IndexError):
        return getattr(utente, "id", None)


def _current_user_email() -> str:
    utente = getattr(g, "user", None)
    try:
        return utente["email"] if utente else "operatore"
    except (KeyError, TypeError, IndexError):
        return "operatore"


# --------------------------------------------------------------------------- #
# Quadro e pagine
# --------------------------------------------------------------------------- #
@bp.get("/")
@login_required
def index():
    tenant_id = current_tenant_id()
    scheda = request.args.get("scheda") or "quadro"
    if scheda not in SCHEDE:
        scheda = "quadro"

    from flask import current_app

    sorgenti = data.sources(tenant_id)
    conosciuti = {s["match_host"] for s in sorgenti if s.get("match_host")}
    # Con l'ascolto syslog integrato attivo, gli apparati inviano il syslog
    # direttamente al server: non serve creare un collettore ne' un token (che
    # servono solo al container Vector, sul canale HTTP).
    listener_attivo = bool(current_app.config.get("SIEM_LISTENER"))
    from ..siem.listener import porte_configurate
    contesto = {
        "scheda": scheda,
        "source_kinds": SOURCE_KINDS,
        "event_kinds": EVENT_KINDS,
        "severity_labels": SEVERITY_LABELS,
        "alert_statuses": ALERT_STATUSES,
        "syslog_port": SYSLOG_PORT,
        "listener_attivo": listener_attivo,
        "listener_porte": ", ".join(
            str(p) for p in porte_configurate(current_app)) if listener_attivo else "",
        "sources": sorgenti,
        "collectors": data.collectors(tenant_id),
        "rules": data.rules(tenant_id),
        "alert_counts": data.alert_counts(tenant_id),
    }

    if scheda == "quadro":
        contesto["eventi_sintesi"] = store.summary(tenant_id)
        contesto["host_ignoti"] = store.unknown_hosts(tenant_id, conosciuti)
        contesto["allarmi_recenti"] = data.alerts(tenant_id, status="open", limit=15)
    elif scheda == "eventi":
        contesto["eventi"] = store.search(
            tenant_id,
            kind=(request.args.get("kind") or "").strip(),
            host=(request.args.get("host") or "").strip(),
            src_ip=(request.args.get("ip") or "").strip(),
            text=(request.args.get("q") or "").strip(),
            limit=1000)
        contesto["filtri"] = {
            "kind": request.args.get("kind") or "",
            "host": request.args.get("host") or "",
            "ip": request.args.get("ip") or "",
            "q": request.args.get("q") or "",
        }
    elif scheda == "allarmi":
        contesto["alerts"] = data.alerts(
            tenant_id, status=(request.args.get("stato") or "").strip(),
            severity=(request.args.get("gravita") or "").strip())

    # Le sorgenti candidate all'onboarding: gli host che mandano log e non
    # corrispondono ancora a nessuna sorgente dichiarata. Utile in ogni scheda.
    if scheda in ("quadro", "sorgenti"):
        contesto["host_ignoti"] = store.unknown_hosts(tenant_id, conosciuti)

    # I nodi dell'inventario, per collegare una sorgente al suo dispositivo.
    contesto["nodi"] = [dict(r) for r in query(
        "SELECT id, ip, hostname, device_label FROM nodes WHERE tenant_id = ?"
        " ORDER BY ip LIMIT 2000", (tenant_id,))]

    return render_template("siem/index.html", **contesto)


# --------------------------------------------------------------------------- #
# Collettori
# --------------------------------------------------------------------------- #
@bp.post("/collectors")
@role_required(ROLE_ANALYST)
def create_collector():
    tenant_id = current_tenant_id()
    nome = (request.form.get("name") or "").strip()
    if not nome:
        flash("Indicare un nome per il collettore.", "warning")
        return redirect(url_for("siem.index", scheda="sorgenti"))
    _id, token = data.create_collector(tenant_id, nome)
    log_event("siem.collector.created", "Collettore SIEM creato: %s" % nome,
              tenant_id=tenant_id, severity="info", entity="siem_collector", entity_id=_id)
    # Il token si mostra una volta sola: viaggia nel flash, non viene riconservato.
    flash("Collettore \"%s\" creato. Token (mostrato una sola volta): %s" % (nome, token),
          "success")
    return redirect(url_for("siem.index", scheda="sorgenti"))


@bp.post("/collectors/<int:collector_id>/rotate")
@role_required(ROLE_ANALYST)
def rotate_collector(collector_id: int):
    tenant_id = current_tenant_id()
    token = data.rotate_collector_token(tenant_id, collector_id)
    if token is None:
        abort(404)
    log_event("siem.collector.rotated", "Token del collettore SIEM %d rigenerato"
              % collector_id, tenant_id=tenant_id, severity="warning",
              entity="siem_collector", entity_id=collector_id)
    flash("Nuovo token (mostrato una sola volta): %s" % token, "success")
    return redirect(url_for("siem.index", scheda="sorgenti"))


@bp.post("/collectors/<int:collector_id>/delete")
@role_required(ROLE_ANALYST)
def delete_collector(collector_id: int):
    tenant_id = current_tenant_id()
    if not data.delete_collector(tenant_id, collector_id):
        abort(404)
    log_event("siem.collector.deleted", "Collettore SIEM %d eliminato" % collector_id,
              tenant_id=tenant_id, severity="warning", entity="siem_collector",
              entity_id=collector_id)
    flash("Collettore eliminato.", "success")
    return redirect(url_for("siem.index", scheda="sorgenti"))


# --------------------------------------------------------------------------- #
# Inserimento manuale dei log (finestra "Incolla log")
# --------------------------------------------------------------------------- #
@bp.post("/paste")
@role_required(ROLE_ANALYST)
def paste_logs():
    """Ingerisce i log incollati a mano, finche' non c'e' un collettore.

    Il testo passa dalla stessa pipeline dei log raccolti dal collettore: viene
    riconosciuto, normalizzato, scritto e subito analizzato, cosi' un allarme
    (per esempio un allarme critico di apparato) compare immediatamente.
    """
    from ..siem import detect, ingest

    tenant_id = current_tenant_id()
    testo = (request.form.get("log") or "").strip()
    if not testo:
        flash("Incollare almeno una riga di log.", "warning")
        return redirect(url_for("siem.index", scheda="incolla"))

    # Se e' stata scelta una sorgente, i suoi riferimenti (indirizzo/host) si applicano
    # agli eventi incollati: cosi' si attribuiscono e si correlano con la threat
    # intelligence del nodo, esattamente come i log raccolti dal vivo.
    sorgente = None
    source_id = request.form.get("source_id")
    if source_id:
        try:
            sorgente = data.source(tenant_id, int(source_id))
        except (TypeError, ValueError):
            sorgente = None

    def _riferimenti():
        return {"src_ip": (sorgente or {}).get("match_ip"),
                "host": (sorgente or {}).get("match_host")}

    # Un dump di allarmi a blocchi (MX-ONE) e' UN messaggio che il parser spezza; i log
    # a righe sono UNA riga = un evento. Si distingue dalla firma dei blocchi.
    from ..siem import parsers

    if parsers.parse_mxone_alarms(testo):
        righe = [dict(_riferimenti(), message=testo)]
    else:
        righe = [dict(_riferimenti(), message=r)
                 for r in testo.splitlines() if r.strip()]

    collettore = data.manual_collector(tenant_id)
    try:
        esito = ingest.ingest_batch(collettore, righe)
    except ingest.IngestError as errore:
        flash("Log non acquisiti: %s" % errore, "warning")
        return redirect(url_for("siem.index", scheda="incolla"))

    # Analisi immediata: chi incolla un log vuole vedere subito se apre un allarme, non
    # aspettare il giro del motore.
    esito_rilevazione = detect.run_once()
    log_event("siem.paste", "Log incollati manualmente: %d eventi acquisiti"
              % esito["scritti"], tenant_id=tenant_id, severity="info",
              entity="siem", entity_id=collettore["id"])
    flash("Acquisiti %d eventi (%d attribuiti a una sorgente). Rilevazione: %d nuovi"
          " allarmi." % (esito["scritti"], esito["attribuiti"],
                         esito_rilevazione["nuovi"]),
          "success" if not esito_rilevazione["nuovi"] else "warning")
    return redirect(url_for("siem.index", scheda="eventi"))


# --------------------------------------------------------------------------- #
# Sorgenti (onboarding)
# --------------------------------------------------------------------------- #
@bp.post("/sources")
@role_required(ROLE_ANALYST)
def create_source():
    tenant_id = current_tenant_id()
    nome = (request.form.get("name") or "").strip()
    kind = (request.form.get("kind") or "other").strip()
    if not nome or kind not in SOURCE_KINDS:
        flash("Indicare nome e tipologia validi per la sorgente.", "warning")
        return redirect(url_for("siem.index", scheda="sorgenti"))
    match_host = (request.form.get("match_host") or "").strip()
    match_ip = (request.form.get("match_ip") or "").strip()
    if not match_host and not match_ip:
        flash("Indicare almeno l'host dichiarato o l'indirizzo di provenienza, per"
              " attribuire gli eventi a questa sorgente.", "warning")
        return redirect(url_for("siem.index", scheda="sorgenti"))
    # Nessun nodo dell'inventario: una sorgente di log puo' essere un sistema ESTERNO.
    # La correlazione con la threat intelligence avviene da se', dall'indirizzo
    # dell'evento, quando quell'indirizzo e' un nodo noto -- non da un legame dichiarato.
    source_id = data.create_source(
        tenant_id, nome, kind,
        vendor=request.form.get("vendor") or "",
        match_host=match_host, match_ip=match_ip,
        notes=request.form.get("notes") or "")
    # Onboarding a posteriori: gli eventi gia' arrivati da questo host/ip non restano
    # orfani, si attribuiscono subito alla sorgente appena dichiarata.
    riattribuiti = store.link_source(tenant_id, source_id, match_host, match_ip)
    log_event("siem.source.created", "Sorgente SIEM creata: %s (%s)" % (nome, kind),
              tenant_id=tenant_id, severity="info", entity="siem_source",
              entity_id=source_id)
    flash("Sorgente \"%s\" creata.%s" % (
        nome, " %d eventi gia' ricevuti attribuiti." % riattribuiti
        if riattribuiti else ""), "success")
    return redirect(url_for("siem.index", scheda="sorgenti"))


@bp.post("/sources/<int:source_id>/edit")
@role_required(ROLE_ANALYST)
def edit_source(source_id: int):
    """Modifica la configurazione di una sorgente esistente."""
    tenant_id = current_tenant_id()
    if data.source(tenant_id, source_id) is None:
        abort(404)
    nome = (request.form.get("name") or "").strip()
    kind = (request.form.get("kind") or "other").strip()
    if not nome or kind not in SOURCE_KINDS:
        flash("Indicare nome e tipologia validi per la sorgente.", "warning")
        return redirect(url_for("siem.index", scheda="sorgenti"))
    match_host = (request.form.get("match_host") or "").strip()
    match_ip = (request.form.get("match_ip") or "").strip()
    if not match_host and not match_ip:
        flash("Indicare almeno l'host dichiarato o l'indirizzo di provenienza.",
              "warning")
        return redirect(url_for("siem.index", scheda="sorgenti", modifica=source_id))
    data.update_source(tenant_id, source_id, name=nome, kind=kind,
                       vendor=request.form.get("vendor") or "",
                       match_host=match_host, match_ip=match_ip,
                       notes=request.form.get("notes") or "")
    # I riferimenti possono essere cambiati: si riattribuiscono gli eventi gia' ricevuti
    # che ora corrispondono a questa sorgente.
    riattribuiti = store.link_source(tenant_id, source_id, match_host, match_ip)
    log_event("siem.source.updated", "Sorgente SIEM %d modificata: %s" % (source_id, nome),
              tenant_id=tenant_id, severity="info", entity="siem_source",
              entity_id=source_id)
    flash("Sorgente \"%s\" aggiornata.%s" % (
        nome, " %d eventi riattribuiti." % riattribuiti if riattribuiti else ""),
        "success")
    return redirect(url_for("siem.index", scheda="sorgenti"))


@bp.post("/sources/<int:source_id>/toggle")
@role_required(ROLE_ANALYST)
def toggle_source(source_id: int):
    tenant_id = current_tenant_id()
    sorgente = data.source(tenant_id, source_id)
    if sorgente is None:
        abort(404)
    nuovo = 0 if sorgente["is_enabled"] else 1
    data.update_source(tenant_id, source_id, is_enabled=nuovo)
    flash("Sorgente %s." % ("attivata" if nuovo else "sospesa"), "success")
    return redirect(url_for("siem.index", scheda="sorgenti"))


@bp.post("/sources/<int:source_id>/delete")
@role_required(ROLE_ANALYST)
def delete_source(source_id: int):
    tenant_id = current_tenant_id()
    if not data.delete_source(tenant_id, source_id):
        abort(404)
    log_event("siem.source.deleted", "Sorgente SIEM %d eliminata" % source_id,
              tenant_id=tenant_id, severity="warning", entity="siem_source",
              entity_id=source_id)
    flash("Sorgente eliminata. Gli eventi gia' raccolti restano nell'archivio.",
          "success")
    return redirect(url_for("siem.index", scheda="sorgenti"))


# --------------------------------------------------------------------------- #
# Regole
# --------------------------------------------------------------------------- #
@bp.post("/rules/<int:rule_id>/toggle")
@role_required(ROLE_ANALYST)
def toggle_rule(rule_id: int):
    tenant_id = current_tenant_id()
    regola = data.rule(tenant_id, rule_id)
    if regola is None:
        abort(404)
    data.set_rule_enabled(tenant_id, rule_id, not regola["is_enabled"])
    flash("Regola %s." % ("attivata" if not regola["is_enabled"] else "sospesa"),
          "success")
    return redirect(url_for("siem.index", scheda="regole"))


@bp.post("/rules/<int:rule_id>")
@role_required(ROLE_ANALYST)
def update_rule(rule_id: int):
    tenant_id = current_tenant_id()
    from ..siem import SEVERITIES

    gravita = (request.form.get("severity") or "").strip()
    if gravita not in SEVERITIES:
        flash("Gravita' non valida.", "warning")
        return redirect(url_for("siem.index", scheda="regole"))
    try:
        soglia = max(1, int(request.form.get("threshold") or 1))
        finestra = max(30, int(request.form.get("window_seconds") or 300))
    except ValueError:
        flash("Soglia e finestra devono essere numeri.", "warning")
        return redirect(url_for("siem.index", scheda="regole"))
    if not data.update_rule(tenant_id, rule_id, soglia, finestra, gravita):
        abort(404)
    flash("Regola aggiornata.", "success")
    return redirect(url_for("siem.index", scheda="regole"))


# --------------------------------------------------------------------------- #
# Allarmi
# --------------------------------------------------------------------------- #
@bp.get("/alerts/<int:alert_id>")
@login_required
def alert(alert_id: int):
    tenant_id = current_tenant_id()
    allarme = data.alert(tenant_id, alert_id)
    if allarme is None:
        abort(404)
    import json

    riscontri = []
    if allarme.get("ti_refs_json"):
        try:
            riferimenti = json.loads(allarme["ti_refs_json"])
            for r in riferimenti:
                riga = query(
                    "SELECT f.id, f.title, f.severity, f.kind, f.cve_id, f.status"
                    " FROM ti_findings f WHERE f.id = ? AND f.tenant_id = ?",
                    (r.get("id"), tenant_id), one=True)
                if riga:
                    riscontri.append(dict(riga))
        except (ValueError, TypeError):
            riscontri = []
    # Gli eventi grezzi a corredo dell'allarme, dalla stessa origine e genere.
    eventi = store.search(
        tenant_id, kind=allarme.get("event_kind") or "",
        src_ip=allarme.get("src_ip") or "", host=allarme.get("host") or "", limit=100)
    return render_template("siem/alert.html", alert=allarme, riscontri=riscontri,
                           eventi=eventi, severity_labels=SEVERITY_LABELS,
                           alert_statuses=ALERT_STATUSES, event_kinds=EVENT_KINDS)


@bp.post("/alerts/<int:alert_id>/status")
@role_required(ROLE_ANALYST)
def set_alert_status(alert_id: int):
    tenant_id = current_tenant_id()
    stato = (request.form.get("status") or "").strip()
    if stato not in (ALERT_ACK, ALERT_CLOSED, ALERT_FALSE_POSITIVE):
        flash("Stato non previsto.", "warning")
        return redirect(url_for("siem.alert", alert_id=alert_id))
    allarme = data.alert(tenant_id, alert_id)
    ok = data.set_alert_status(tenant_id, alert_id, stato, _current_user_email(),
                               note=request.form.get("note") or "")
    if not ok:
        abort(404)
    # L'incidente collegato segue l'allarme: chiuderlo o dichiararlo falso positivo
    # risolve anche l'incidente in Controlli -> Incidenti.
    if allarme and allarme.get("incident_id") and stato in (ALERT_CLOSED,
                                                            ALERT_FALSE_POSITIVE):
        from ..siem import incident as ponte_incidente

        esito = ("chiuso dall'operatore" if stato == ALERT_CLOSED
                 else "falso positivo")
        ponte_incidente.chiudi_incidente(tenant_id, allarme["incident_id"], esito,
                                         _current_user_email())
    log_event("siem.alert.%s" % stato, "Allarme SIEM %d -> %s"
              % (alert_id, ALERT_STATUSES[stato]), tenant_id=tenant_id,
              severity="info", entity="siem_alert", entity_id=alert_id)
    flash("Allarme aggiornato: %s." % ALERT_STATUSES[stato], "success")
    return redirect(url_for("siem.index", scheda="allarmi"))
