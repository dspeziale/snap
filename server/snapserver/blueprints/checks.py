"""
snap server - Menu Controlli: onboarding dei bersagli, controlli e incidenti.

L'operatore dichiara un bersaglio (indirizzo IP o nome host) e vi associa uno o
piu' controlli periodici. L'esecuzione e' delle sonde: qui si definisce cosa
verificare, con quale cadenza, e si governa cio' che ne risulta.

Permessi: consultazione a tutti gli utenti del tenant; creazione e modifica agli
amministratori di tenant; presa in carico e risoluzione degli incidenti agli
analisti, che sono le persone che intervengono.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json

from flask import (
    Blueprint,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from ..audit import log_event
from ..checks import (
    ASSERTION_OPS,
    CHECK_KINDS,
    MAX_METRICS_PER_RESULT,
    MAX_PORTS_PER_CHECK,
    CheckError,
    SEVERITIES,
    metric_selection,
    acknowledge_incident,
    describe,
    resolve_incident,
    validate_address,
    validate_definition,
    validate_escalation_email,
    validate_schedule,
)
from ..notifications import (
    NOTIFY_EVENTS,
    dispatch_pending,
    is_configured,
    notifications_summary,
    recent_notifications,
)
from ..checks_queries import (
    available_metrics,
    check as check_detail,
    checks_of_target,
    availability_trend,
    checks_summary,
    incident as incident_detail,
    incident_events,
    incidents,
    latency_points,
    metric_label,
    metric_series,
    metrics_latest,
    metrics_recent,
    metrics_summary,
    numeric_series,
    numeric_series_omitted,
    recent_results,
    results,
    target as target_detail,
    targets,
)
from ..db import execute, query, utc_now_str
from ..security import ROLE_ANALYST, ROLE_TENANT_ADMIN, login_required, role_required
from ..tenancy import current_tenant_id, fmt_grafico

bp = Blueprint("checks", __name__, url_prefix="/checks")


def _current_user_id() -> int | None:
    utente = getattr(g, "user", None)
    if utente is None:
        return None
    return int(utente["id"]) if not isinstance(utente, dict) else int(utente.get("id"))


# --------------------------------------------------------------------------- #
# Elenco e onboarding dei bersagli
# --------------------------------------------------------------------------- #
@bp.get("/")
@login_required
def index():
    tenant_id = current_tenant_id()
    return render_template(
        "checks/index.html",
        targets=targets(tenant_id),
        summary=checks_summary(tenant_id),
        incidents=incidents(tenant_id, status="aperti", limit=50),
        results=recent_results(tenant_id, limit=200),
        metrics=metrics_recent(tenant_id, limit=300),
        metrics_summary=metrics_summary(tenant_id),
        availability=availability_trend(tenant_id),
        kinds=CHECK_KINDS,
    )


@bp.post("/targets")
@role_required(ROLE_TENANT_ADMIN)
def create_target():
    """Onboarding di un bersaglio: un indirizzo IP oppure un nome host."""
    tenant_id = current_tenant_id()
    nome = (request.form.get("name") or "").strip()
    if not nome:
        flash("Indicare un nome per il bersaglio.", "warning")
        return redirect(url_for("checks.index"))
    try:
        indirizzo = validate_address(request.form.get("address"))
    except CheckError as errore:
        flash(str(errore), "warning")
        return redirect(url_for("checks.index"))

    esistente = query("SELECT id FROM check_targets WHERE tenant_id = ? AND address = ?"
                      " AND name = ?", (tenant_id, indirizzo, nome), one=True)
    if esistente is not None:
        flash("Un bersaglio con questo nome e indirizzo esiste gia'.", "info")
        return redirect(url_for("checks.target", target_id=int(esistente["id"])))

    adesso = utc_now_str()
    identificativo = execute(
        "INSERT INTO check_targets (tenant_id, name, address, description, is_enabled,"
        " created_by, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?, ?)",
        (tenant_id, nome, indirizzo, (request.form.get("description") or "").strip() or None,
         _current_user_id(), adesso, adesso))
    log_event("checks.target.created",
              "Bersaglio '%s' (%s) aggiunto ai controlli" % (nome, indirizzo),
              tenant_id=tenant_id, severity="info", entity="check_target",
              entity_id=identificativo)
    flash("Bersaglio '%s' aggiunto. Ora vi si possono associare i controlli." % nome,
          "success")
    return redirect(url_for("checks.target", target_id=identificativo))


@bp.post("/onboard/node/<int:node_id>")
@role_required(ROLE_TENANT_ADMIN)
def onboard_node(node_id: int):
    """Porta un nodo dell'inventario fra i bersagli dei controlli.

    Le porte le ha trovate la scansione: ridigitarle a mano e' lavoro inutile e una
    fonte di errori. Restano fuori quelle marcate come iniettate da un apparato
    intermedio -- un controllo su quelle resterebbe verde anche a nodo spento.
    """
    tenant_id = current_tenant_id()
    nodo = query("SELECT * FROM nodes WHERE id = ? AND tenant_id = ?",
                 (node_id, tenant_id), one=True)
    if nodo is None:
        abort(404)

    # Il nome host sopravvive a un cambio di indirizzo: quando c'e', e' il bersaglio
    # migliore. L'operatore puo' comunque imporre l'indirizzo.
    per_nome = (request.form.get("use_hostname") or "").strip() == "on"
    indirizzo = (nodo["hostname"] or "").strip() if per_nome else ""
    if not indirizzo:
        indirizzo = nodo["ip"]
    try:
        indirizzo = validate_address(indirizzo)
    except CheckError as errore:
        flash("Bersaglio non valido: %s" % errore, "warning")
        return redirect(url_for("inventory.node", node_id=node_id))

    porte = query(
        "SELECT protocol, port, service_name, is_suspect FROM node_ports"
        " WHERE tenant_id = ? AND node_id = ? AND state = 'open'"
        " ORDER BY protocol, port", (tenant_id, node_id))
    aperte = [p for p in porte if not int(p["is_suspect"] or 0)]
    iniettate = [p for p in porte if int(p["is_suspect"] or 0)]
    troncate = 0
    if len(aperte) > MAX_PORTS_PER_CHECK:
        troncate = len(aperte) - MAX_PORTS_PER_CHECK
        aperte = aperte[:MAX_PORTS_PER_CHECK]

    adesso = utc_now_str()
    etichetta = (nodo["hostname"] or nodo["device_label"] or nodo["ip"])
    esistente = query("SELECT * FROM check_targets WHERE tenant_id = ? AND address = ?",
                      (tenant_id, indirizzo), one=True)
    if esistente is not None:
        target_id = int(esistente["id"])
        creato = False
    else:
        target_id = execute(
            "INSERT INTO check_targets (tenant_id, name, address, description,"
            " is_enabled, created_by, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, 1, ?, ?, ?)",
            (tenant_id, etichetta[:120], indirizzo,
             "Portato dall'inventario: nodo %s%s" % (
                 nodo["ip"], " (%s)" % nodo["device_label"] if nodo["device_label"] else ""),
             _current_user_id(), adesso, adesso))
        creato = True

    def genere_presente(genere):
        riga = query("SELECT id FROM checks WHERE tenant_id = ? AND target_id = ?"
                     " AND kind = ?", (tenant_id, target_id, genere), one=True)
        return riga is not None

    aggiunti = []
    if not genere_presente("presence"):
        execute(
            "INSERT INTO checks (tenant_id, target_id, name, kind, config_json,"
            " interval_seconds, timeout_seconds, is_enabled, severity,"
            " failure_threshold, escalation_threshold, created_by, created_at,"
            " updated_at) VALUES (?, ?, ?, 'presence', '{}', 300, 10, 1, 'warning',"
            " 3, 6, ?, ?, ?)",
            (tenant_id, target_id, "Presenza in rete: %s" % etichetta[:90],
             _current_user_id(), adesso, adesso))
        aggiunti.append("presenza in rete")

    if aperte and not genere_presente("ports"):
        configurazione = validate_definition("ports", {
            "ports": [{"protocol": p["protocol"], "port": int(p["port"])} for p in aperte]})
        execute(
            "INSERT INTO checks (tenant_id, target_id, name, kind, config_json,"
            " interval_seconds, timeout_seconds, is_enabled, severity,"
            " failure_threshold, escalation_threshold, created_by, created_at,"
            " updated_at) VALUES (?, ?, ?, 'ports', ?, 300, 10, 1, 'warning',"
            " 3, 6, ?, ?, ?)",
            (tenant_id, target_id,
             "Porte trovate aperte (%d)" % len(aperte),
             json.dumps(configurazione, ensure_ascii=False),
             _current_user_id(), adesso, adesso))
        aggiunti.append("%d porte (%s)" % (
            len(aperte), ", ".join("%s/%s" % (p["protocol"], p["port"])
                                   for p in aperte[:8])
            + (", ..." if len(aperte) > 8 else "")))

    log_event("checks.target.onboarded",
              "Nodo %s portato nei controlli come '%s'%s"
              % (nodo["ip"], indirizzo,
                 ": " + "; ".join(aggiunti) if aggiunti else " (nessun controllo nuovo)"),
              tenant_id=tenant_id, severity="info", entity="check_target",
              entity_id=target_id)

    if aggiunti:
        messaggio = "%s '%s': %s." % ("Bersaglio creato" if creato
                                      else "Bersaglio esistente aggiornato",
                                      indirizzo, "; ".join(aggiunti))
    else:
        messaggio = ("Il bersaglio '%s' era gia' sorvegliato: nessun controllo"
                     " aggiunto." % indirizzo)
    if iniettate:
        messaggio += (" Escluse %d porte marcate come iniettate da un apparato"
                      " intermedio (%s): un controllo su quelle resterebbe verde"
                      " anche a nodo spento."
                      % (len(iniettate),
                         ", ".join("%s/%s" % (p["protocol"], p["port"])
                                   for p in iniettate[:6])))
    if troncate:
        messaggio += (" %d porte oltre il massimo di %d non sono state incluse."
                      % (troncate, MAX_PORTS_PER_CHECK))
    if not aperte:
        messaggio += (" Nessuna porta aperta da portare: resta il controllo di"
                      " presenza.")
    flash(messaggio, "success" if aggiunti else "info")
    return redirect(url_for("checks.target", target_id=target_id))


@bp.get("/targets/<int:target_id>")
@login_required
def target(target_id: int):
    tenant_id = current_tenant_id()
    bersaglio = target_detail(tenant_id, target_id)
    if bersaglio is None:
        abort(404)
    controlli = checks_of_target(tenant_id, target_id)
    # Miniatura dell'andamento della latenza per ciascun controllo: e' la misura
    # sempre disponibile, e in un elenco dice a colpo d'occhio quale sta cedendo.
    for controllo in controlli:
        controllo["latency_points"] = latency_points(tenant_id, int(controllo["id"]))
    return render_template(
        "checks/target.html",
        target=bersaglio,
        checks=controlli,
        summary=checks_summary(tenant_id),
        kinds=CHECK_KINDS,
        severities=SEVERITIES,
        assertion_ops=ASSERTION_OPS,
    )


@bp.post("/targets/<int:target_id>/toggle")
@role_required(ROLE_TENANT_ADMIN)
def toggle_target(target_id: int):
    tenant_id = current_tenant_id()
    bersaglio = target_detail(tenant_id, target_id)
    if bersaglio is None:
        abort(404)
    nuovo = 0 if int(bersaglio["is_enabled"]) else 1
    execute("UPDATE check_targets SET is_enabled = ?, updated_at = ? WHERE id = ?"
            " AND tenant_id = ?", (nuovo, utc_now_str(), target_id, tenant_id))
    log_event("checks.target.enabled" if nuovo else "checks.target.disabled",
              "Bersaglio '%s' %s" % (bersaglio["name"],
                                     "attivato" if nuovo else "disattivato"),
              tenant_id=tenant_id, severity="info" if nuovo else "warning",
              entity="check_target", entity_id=target_id)
    flash("Bersaglio %s." % ("attivato" if nuovo else "disattivato: i suoi controlli "
                             "non vengono piu' eseguiti"),
          "success" if nuovo else "warning")
    return redirect(url_for("checks.target", target_id=target_id))


@bp.post("/targets/<int:target_id>/delete")
@role_required(ROLE_TENANT_ADMIN)
def delete_target(target_id: int):
    """Rimuove il bersaglio con i suoi controlli, esiti e incidenti.

    La conferma richiede di digitare l'indirizzo: con la rimozione se ne va anche
    lo storico, che e' cio' che rende il controllo utile.
    """
    tenant_id = current_tenant_id()
    bersaglio = target_detail(tenant_id, target_id)
    if bersaglio is None:
        abort(404)
    if (request.form.get("confirm") or "").strip() != bersaglio["address"]:
        flash("Rimozione annullata: la conferma non corrisponde all'indirizzo.", "warning")
        return redirect(url_for("checks.target", target_id=target_id))

    execute("DELETE FROM check_targets WHERE id = ? AND tenant_id = ?",
            (target_id, tenant_id))
    log_event("checks.target.deleted",
              "Bersaglio '%s' (%s) rimosso con i propri controlli e lo storico"
              % (bersaglio["name"], bersaglio["address"]),
              tenant_id=tenant_id, severity="warning", entity="check_target",
              entity_id=target_id)
    flash("Bersaglio rimosso con i suoi controlli e il relativo storico.", "success")
    return redirect(url_for("checks.index"))


# --------------------------------------------------------------------------- #
# Controlli
# --------------------------------------------------------------------------- #
def _assertions_from_form() -> list:
    """Verifiche sul JSON, dai campi paralleli del modulo.

    Il modulo presenta tre colonne (percorso, operatore, valore) ripetute: e' la
    forma piu' leggibile per chi non scrive JSON a mano.
    """
    percorsi = request.form.getlist("assert_path")
    operatori = request.form.getlist("assert_op")
    valori = request.form.getlist("assert_value")
    verifiche = []
    for indice, percorso in enumerate(percorsi):
        percorso = (percorso or "").strip()
        if not percorso:
            continue  # riga lasciata vuota: non e' un errore, e' una riga in meno
        voce = {"path": percorso,
                "op": (operatori[indice] if indice < len(operatori) else "eq") or "eq"}
        valore = valori[indice] if indice < len(valori) else ""
        if (valore or "").strip():
            voce["value"] = valore.strip()
        verifiche.append(voce)
    return verifiche


def _metrics_from_form() -> list:
    """Percorsi scelti nel modulo: caselle spuntate piu' righe scritte a mano.

    Le righe a mano servono per un dato che l'endpoint restituisce solo a volte --
    un errore, una coda -- e che quindi non compare nell'elenco delle caselle.
    """
    percorsi = list(request.form.getlist("metrics"))
    for riga in (request.form.get("metrics_extra") or "").splitlines():
        voce = riga.strip()
        if voce and voce not in percorsi:
            percorsi.append(voce)
    return percorsi


def _config_from_form(kind: str, current: dict = None) -> dict:
    if kind == "ports":
        return {"ports": request.form.get("ports")}
    if kind == "http":
        return {
            "url": request.form.get("url"),
            "method": request.form.get("method") or "GET",
            "expect_status": request.form.get("expect_status") or 200,
            "assertions": _assertions_from_form(),
            # Caselle spuntate nella pagina piu' i percorsi scritti a mano. Il modulo
            # dichiara di portare la scelta con `metrics_present`: uno che non la
            # contiene non la azzera, eredita quella in vigore. Altrimenti un
            # salvataggio da una maschera piu' vecchia cancellerebbe la scelta senza
            # che nessuno lo chieda.
            "metrics": (_metrics_from_form() if request.form.get("metrics_present")
                        else metric_selection(current)),
        }
    return {}


@bp.post("/targets/<int:target_id>/checks")
@role_required(ROLE_TENANT_ADMIN)
def create_check(target_id: int):
    tenant_id = current_tenant_id()
    bersaglio = target_detail(tenant_id, target_id)
    if bersaglio is None:
        abort(404)

    genere = (request.form.get("kind") or "").strip().lower()
    nome = (request.form.get("name") or "").strip()
    try:
        configurazione = validate_definition(genere, _config_from_form(genere))
        cadenza, attesa, soglia, attivazione = validate_schedule(
            request.form.get("interval_seconds"),
            request.form.get("timeout_seconds"),
            request.form.get("failure_threshold"),
            request.form.get("escalation_threshold"))
        recapito = validate_escalation_email(request.form.get("escalation_email"))
    except CheckError as errore:
        flash(str(errore), "warning")
        return redirect(url_for("checks.target", target_id=target_id))

    if not nome:
        nome = "%s: %s" % (CHECK_KINDS[genere], describe(genere, configurazione))[:120]
    gravita = (request.form.get("severity") or "warning").strip()
    if gravita not in SEVERITIES:
        gravita = "warning"

    adesso = utc_now_str()
    identificativo = execute(
        "INSERT INTO checks (tenant_id, target_id, name, kind, config_json,"
        " interval_seconds, timeout_seconds, is_enabled, severity, failure_threshold,"
        " escalation_threshold, escalation_email, created_by, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)",
        (tenant_id, target_id, nome, genere,
         json.dumps(configurazione, ensure_ascii=False), cadenza, attesa, gravita,
         soglia, attivazione, recapito, _current_user_id(), adesso, adesso))
    log_event("checks.check.created",
              "Controllo '%s' creato su %s: %s"
              % (nome, bersaglio["address"], describe(genere, configurazione)),
              tenant_id=tenant_id, severity="info", entity="check",
              entity_id=identificativo)
    flash("Controllo creato. Le sonde lo riceveranno al prossimo contatto.", "success")
    return redirect(url_for("checks.target", target_id=target_id))


@bp.get("/checks/<int:check_id>")
@login_required
def check(check_id: int):
    tenant_id = current_tenant_id()
    controllo = check_detail(tenant_id, check_id)
    if controllo is None:
        abort(404)
    # Serie di un singolo punto di misura, quando l'operatore ne chiede una: e'
    # la lettura che serve per capire un andamento, non l'elenco di tutto.
    serie_scelta = (request.args.get("metric") or "").strip() or None
    serie_valori = metric_series(tenant_id, check_id, serie_scelta) if serie_scelta else []
    # Dati scelti per questo controllo: elenco vuoto significa tutti.
    scelti = metric_selection(controllo.get("config"))
    disponibili = available_metrics(tenant_id, check_id)
    # Percorsi scelti che l'ultima risposta non contiene: un dato intermittente, o un
    # percorso sbagliato. Vanno mostrati come testo modificabile, altrimenti il
    # salvataggio successivo li perderebbe senza dirlo.
    fuori_elenco = [percorso for percorso in scelti
                    if percorso not in {voce["name"] for voce in disponibili}]
    return render_template(
        "checks/check.html",
        check=controllo,
        results=results(tenant_id, check_id, limit=300),
        incidents=incidents(tenant_id, limit=50),
        metrics=metrics_latest(tenant_id, check_id, selection=scelti),
        charts=numeric_series(tenant_id, check_id, selection=scelti),
        charts_omitted=numeric_series_omitted(tenant_id, check_id, selection=scelti),
        # Percorsi fra cui scegliere, e quelli scelti adesso.
        available_metrics=disponibili,
        selected_metrics=scelti,
        extra_metrics=fuori_elenco,
        # Punti della serie scelta, in ordine crescente: e' l'ordine del disegno.
        series_points=[[fmt_grafico(s["measured_at"]), float(s["value"])]
                       for s in reversed(serie_valori) if s["value"] is not None],
        series_name=serie_scelta,
        series_label=metric_label(serie_scelta) if serie_scelta else None,
        series=serie_valori,
        kinds=CHECK_KINDS,
        assertion_ops=ASSERTION_OPS,
        max_metrics=MAX_METRICS_PER_RESULT,
    )


@bp.post("/checks/<int:check_id>/run-now")
@role_required(ROLE_ANALYST)
def run_now(check_id: int):
    """Chiede alle sonde attive di eseguire subito il controllo.

    Il comando va a tutte le sonde attive del tenant: quale di esse veda il
    bersaglio non e' noto al server, ed e' proprio una delle cose che la prova
    accerta. Gli esiti arrivano distinti per sonda.
    """
    tenant_id = current_tenant_id()
    controllo = check_detail(tenant_id, check_id)
    if controllo is None:
        abort(404)
    if not int(controllo["is_enabled"]):
        flash("Il controllo e' sospeso: riattivarlo prima di provarlo.", "warning")
        return redirect(url_for("checks.check", check_id=check_id))

    sonde = query("SELECT id, name FROM probes WHERE tenant_id = ? AND status = 'active'",
                  (tenant_id,))
    if not sonde:
        flash("Nessuna sonda attiva in questo tenant: la prova non puo' essere eseguita.",
              "warning")
        return redirect(url_for("checks.check", check_id=check_id))

    adesso = utc_now_str()
    for sonda in sonde:
        execute(
            "INSERT INTO probe_commands (tenant_id, probe_id, command, payload_json,"
            " status, created_by, created_at) VALUES (?, ?, 'check_now', ?, 'pending', ?, ?)",
            (tenant_id, int(sonda["id"]), json.dumps({"check_id": check_id}),
             _current_user_id(), adesso))
    log_event("checks.check.run_requested",
              "Prova immediata richiesta per il controllo '%s' su %d sonde"
              % (controllo["name"], len(sonde)),
              tenant_id=tenant_id, entity="check", entity_id=check_id)
    flash("Prova richiesta a %d sonda/e: l'esito compare qui entro pochi secondi."
          % len(sonde), "info")
    return redirect(url_for("checks.check", check_id=check_id, attesa=1))


@bp.get("/checks/<int:check_id>/latest.json")
@login_required
def latest_result(check_id: int):
    """Ultimo esito del controllo, per l'attesa della prova nella pagina."""
    tenant_id = current_tenant_id()
    if check_detail(tenant_id, check_id) is None:
        abort(404)
    ultimi = results(tenant_id, check_id, limit=1)
    if not ultimi:
        return jsonify({"presente": False})
    ultimo = ultimi[0]
    return jsonify({
        "presente": True,
        "id": int(ultimo["id"]),
        "stato": ultimo["status"],
        "eseguito_alle": ultimo["executed_at"],
        "dettaglio": ultimo["detail"],
        "latenza_ms": ultimo["latency_ms"],
    })


@bp.post("/checks/<int:check_id>/toggle")
@role_required(ROLE_TENANT_ADMIN)
def toggle_check(check_id: int):
    tenant_id = current_tenant_id()
    controllo = check_detail(tenant_id, check_id)
    if controllo is None:
        abort(404)
    nuovo = 0 if int(controllo["is_enabled"]) else 1
    execute("UPDATE checks SET is_enabled = ?, updated_at = ? WHERE id = ? AND tenant_id = ?",
            (nuovo, utc_now_str(), check_id, tenant_id))
    log_event("checks.check.enabled" if nuovo else "checks.check.disabled",
              "Controllo '%s' %s" % (controllo["name"],
                                     "attivato" if nuovo else "sospeso"),
              tenant_id=tenant_id, severity="info" if nuovo else "warning",
              entity="check", entity_id=check_id)
    flash("Controllo %s." % ("attivato" if nuovo else "sospeso"), "success")
    return redirect(url_for("checks.target", target_id=int(controllo["target_id"])))


@bp.post("/checks/<int:check_id>/update")
@role_required(ROLE_TENANT_ADMIN)
def update_check(check_id: int):
    """Aggiorna la configurazione di un controllo.

    Si cambia tutto tranne il GENERE: quello e' cio' che il controllo misura, e
    cambiarlo terrebbe insieme lo storico di due verifiche diverse rendendo le serie
    di misure incomparabili. Per cambiare genere si crea un controllo nuovo.

    Cancellare e ricreare non e' un'alternativa: con la cancellazione se ne andrebbero
    esiti, misure e incidenti, cioe' proprio lo storico che rende il controllo utile.
    """
    tenant_id = current_tenant_id()
    controllo = check_detail(tenant_id, check_id)
    if controllo is None:
        abort(404)

    genere = controllo["kind"]
    try:
        configurazione = validate_definition(
            genere, _config_from_form(genere, controllo.get("config")))
        cadenza, attesa, soglia, attivazione = validate_schedule(
            request.form.get("interval_seconds"),
            request.form.get("timeout_seconds"),
            request.form.get("failure_threshold"),
            request.form.get("escalation_threshold"))
        recapito = validate_escalation_email(request.form.get("escalation_email"))
    except CheckError as errore:
        flash(str(errore), "warning")
        return redirect(url_for("checks.check", check_id=check_id))

    nome = (request.form.get("name") or "").strip()
    if not nome:
        nome = ("%s: %s" % (CHECK_KINDS[genere], describe(genere, configurazione)))[:120]
    gravita = (request.form.get("severity") or controllo["severity"]).strip()
    if gravita not in SEVERITIES:
        gravita = controllo["severity"]
    attivo = 1 if request.form.get("is_enabled") else 0

    execute(
        "UPDATE checks SET name = ?, config_json = ?, interval_seconds = ?,"
        " timeout_seconds = ?, severity = ?, failure_threshold = ?,"
        " escalation_threshold = ?, escalation_email = ?, is_enabled = ?,"
        " updated_at = ? WHERE id = ? AND tenant_id = ?",
        (nome, json.dumps(configurazione, ensure_ascii=False), cadenza, attesa,
         gravita, soglia, attivazione, recapito, attivo, utc_now_str(),
         check_id, tenant_id))

    log_event("checks.check.updated",
              "Controllo '%s' modificato: %s, cadenza %d s, incidente a %d,"
              " operatore a %d%s"
              % (nome, describe(genere, configurazione), cadenza, soglia, attivazione,
                 " (%s)" % recapito if recapito else " (email del tenant)"),
              tenant_id=tenant_id, severity="info", entity="check", entity_id=check_id)
    flash("Controllo aggiornato. Le sonde ricevono la nuova definizione al prossimo"
          " contatto; lo storico degli esiti e delle misure resta.", "success")
    return redirect(url_for("checks.check", check_id=check_id, scheda="definizione"))


@bp.post("/checks/<int:check_id>/delete")
@role_required(ROLE_TENANT_ADMIN)
def delete_check(check_id: int):
    tenant_id = current_tenant_id()
    controllo = check_detail(tenant_id, check_id)
    if controllo is None:
        abort(404)
    execute("DELETE FROM checks WHERE id = ? AND tenant_id = ?", (check_id, tenant_id))
    log_event("checks.check.deleted",
              "Controllo '%s' rimosso con i propri esiti" % controllo["name"],
              tenant_id=tenant_id, severity="warning", entity="check", entity_id=check_id)
    flash("Controllo rimosso.", "success")
    return redirect(url_for("checks.target", target_id=int(controllo["target_id"])))


# --------------------------------------------------------------------------- #
# Incidenti: il workflow
# --------------------------------------------------------------------------- #
@bp.get("/notifications")
@login_required
def notifications():
    """Coda delle notifiche del workflow: cosa e' stato inviato e cosa no."""
    tenant_id = current_tenant_id()
    return render_template(
        "checks/notifications.html",
        notifications=recent_notifications(tenant_id),
        summary=notifications_summary(tenant_id),
        events=NOTIFY_EVENTS,
        configured=is_configured(),
    )


@bp.post("/notifications/dispatch")
@role_required(ROLE_ANALYST)
def dispatch_notifications():
    """Tenta subito la spedizione di quanto e' in attesa.

    La spedizione avviene comunque da se' ogni pochi secondi: questo comando serve
    a verificare la configurazione senza attendere.
    """
    esito = dispatch_pending(limit=50)
    if esito.get("reason"):
        flash("Spedizione non tentata: %s." % esito["reason"], "warning")
    elif not esito["sent"] and not esito["failed"]:
        flash("Nessuna notifica in attesa.", "info")
    else:
        flash("Spedizione tentata: %d inviate, %d non riuscite."
              % (esito["sent"], esito["failed"]),
              "success" if not esito["failed"] else "warning")
    return redirect(url_for("checks.notifications"))


@bp.get("/incidents")
@login_required
def incident_list():
    tenant_id = current_tenant_id()
    stato = request.args.get("status") or "aperti"
    return render_template(
        "checks/incidents.html",
        incidents=incidents(tenant_id, status=None if stato == "tutti" else stato),
        summary=checks_summary(tenant_id),
        selected=stato,
    )


@bp.get("/incidents/<int:incident_id>")
@login_required
def incident(incident_id: int):
    tenant_id = current_tenant_id()
    voce = incident_detail(tenant_id, incident_id)
    if voce is None:
        abort(404)
    return render_template(
        "checks/incident.html",
        incident=voce,
        events=incident_events(tenant_id, incident_id),
        results=results(tenant_id, int(voce["check_id"]), limit=100),
    )


@bp.post("/incidents/<int:incident_id>/acknowledge")
@role_required(ROLE_ANALYST)
def acknowledge(incident_id: int):
    tenant_id = current_tenant_id()
    fatto = acknowledge_incident(tenant_id, incident_id, _current_user_id(),
                                 (request.form.get("note") or "").strip() or None)
    if not fatto:
        flash("L'incidente non e' aperto: non c'e' nulla da prendere in carico.", "info")
    else:
        flash("Incidente preso in carico.", "success")
    return redirect(url_for("checks.incident", incident_id=incident_id))


@bp.post("/incidents/<int:incident_id>/resolve")
@role_required(ROLE_ANALYST)
def resolve(incident_id: int):
    tenant_id = current_tenant_id()
    motivazione = (request.form.get("resolution") or "").strip()
    if not motivazione:
        flash("Indicare come e' stato risolto: senza motivazione lo storico non serve.",
              "warning")
        return redirect(url_for("checks.incident", incident_id=incident_id))
    fatto = resolve_incident(tenant_id, incident_id, _current_user_id(), motivazione)
    if not fatto:
        flash("L'incidente risulta gia' risolto.", "info")
    else:
        flash("Incidente risolto.", "success")
    return redirect(url_for("checks.incident", incident_id=incident_id))
