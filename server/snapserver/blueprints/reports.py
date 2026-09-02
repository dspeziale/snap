"""
snap server - Menu Report: resoconto quotidiano e report NOC.

Il resoconto viene spedito dal pianificatore del server senza intervento di nessuno.
Questa pagina serve a tre cose: vedere che cosa e' stato spedito, leggere in anteprima
il resoconto di un giorno senza spedirlo, e chiederne la spedizione o la generazione
del PDF fuori orario.

Permessi: consultazione a tutto il tenant; spedizione e generazione agli analisti;
configurazione agli amministratori di tenant (in Amministrazione).

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from flask import (
    Blueprint,
    abort,
    flash,
    render_template,
    request,
    send_file,
    url_for,
)
from flask import redirect

import re

from ..audit import log_event
from ..channels import (
    CHANNEL_EMAIL,
    CHANNEL_TELEGRAM,
    CHANNELS,
    available_channels,
)
from ..checks import EMAIL_PATTERN
from ..db import query
from ..notifications import queue_notification
from ..reports import KIND_DAILY, KIND_NOC, REPORT_KINDS
from ..reports import daily as resoconto
from ..reports import storage
from ..reports.render_pdf import font_status
from ..reports.windows import WindowError, zone_of
from ..security import (
    ROLE_ANALYST,
    ROLE_TENANT_ADMIN,
    has_role,
    login_required,
    role_required,
)
from ..tenancy import current_tenant_id

bp = Blueprint("reports", __name__, url_prefix="/reports")


def _tenant():
    tenant_id = current_tenant_id()
    riga = query("SELECT id, code, name, timezone, contact_email FROM tenants"
                 " WHERE id = ?", (tenant_id,), one=True)
    if riga is None:
        abort(404)
    return dict(riga)


def _current_user_id():
    from flask import g

    utente = getattr(g, "user", None)
    if utente is None:
        return None
    try:
        return int(utente["id"])
    except (KeyError, TypeError, IndexError):
        return getattr(utente, "id", None)


@bp.get("/")
@login_required
def index():
    from ..reports import REPORT_CATALOG
    from ..reports.generate import allowed_days, default_days

    tenant = _tenant()
    impostazioni = resoconto.settings()
    zona = zone_of(tenant)
    catalogo = [
        dict(voce, chiave=chiave, titolo=REPORT_KINDS[chiave],
             periodi=allowed_days(chiave), predefinito=default_days(chiave))
        for chiave, voce in REPORT_CATALOG.items()
    ]
    incidenti_recenti = [dict(r) for r in query(
        "SELECT i.id, i.severity, i.status, i.opened_at, c.name AS controllo,"
        " t.address FROM check_incidents i JOIN checks c ON c.id = i.check_id"
        " JOIN check_targets t ON t.id = c.target_id WHERE i.tenant_id = ?"
        " ORDER BY i.id DESC LIMIT 30", (int(tenant["id"]),))]
    return render_template(
        "reports/index.html",
        tenant=tenant,
        settings=impostazioni,
        catalog=catalogo,
        incidents=incidenti_recenti,
        kinds=REPORT_KINDS,
        reports=storage.recent(int(tenant["id"]), limit=200),
        footprint=storage.footprint(int(tenant["id"])),
        channels=available_channels(),
        # Capacita' di invio a richiesta: qui il recapito si scrive sul momento, quindi
        # basta che il canale sia configurato (server di posta / token del bot).
        invio=_capacita_invio(),
        fonts=font_status(),
        recipients=resoconto.recipients_for(tenant, impostazioni, "email"),
        # Ieri e' il giorno predefinito di ogni azione: e' quello di cui si conoscono
        # tutti gli eventi.
        default_day=resoconto.yesterday_local(zona).isoformat(),
        zone=zona.key if hasattr(zona, "key") else str(zona),
    )


@bp.get("/daily/preview")
@login_required
def preview():
    """Anteprima del resoconto di un giorno. Non spedisce nulla."""
    tenant = _tenant()
    try:
        giorno = resoconto.parse_requested_day(request.args.get("day"), tenant)
    except WindowError as errore:
        flash(str(errore), "warning")
        return redirect(url_for("reports.index"))

    composto = resoconto.build(tenant, giorno)
    formato = (request.args.get("format") or "html").strip().lower()
    if formato == "text":
        return render_template("reports/preview.html", tenant=tenant, day=giorno,
                               composed=composto, as_text=True)
    return render_template("reports/preview.html", tenant=tenant, day=giorno,
                           composed=composto, as_text=False)


@bp.post("/daily/send")
@role_required(ROLE_ANALYST)
def send_daily():
    """Spedizione a richiesta, fuori orario. Ripete anche un resoconto gia' spedito."""
    tenant = _tenant()
    try:
        giorno = resoconto.parse_requested_day(request.form.get("day"), tenant)
    except WindowError as errore:
        flash(str(errore), "warning")
        return redirect(url_for("reports.index"))

    esito = resoconto.send_for(tenant, giorno, requested_by=_current_user_id(),
                               force=True)
    if esito["inviato"]:
        flash("Resoconto del %s accodato (%d questioni aperte). La spedizione avviene"
              " entro il giro successivo della coda."
              % (giorno.strftime("%d/%m/%Y"), esito["questioni"]), "success")
    else:
        flash("Resoconto non accodato: %s"
              % esito.get("motivo", "nessun canale configurato o destinatario mancante"),
              "warning")
    return redirect(url_for("reports.index"))


@bp.post("/noc")
@role_required(ROLE_ANALYST)
def generate_noc():
    """Genera il report NOC in PDF per un giorno."""
    tenant = _tenant()
    try:
        giorno = resoconto.parse_requested_day(request.form.get("day"), tenant)
    except WindowError as errore:
        flash(str(errore), "warning")
        return redirect(url_for("reports.index"))

    try:
        percorso = resoconto.generate_noc(tenant, giorno,
                                          requested_by=_current_user_id())
    except OSError as errore:
        # Un errore di scrittura non deve restare senza spiegazione: la cartella dei
        # report puo' essere piena o non scrivibile.
        flash("Report non generato: %s" % errore, "danger")
        return redirect(url_for("reports.index"))

    flash("Report NOC del %s generato." % giorno.strftime("%d/%m/%Y"), "success")
    return redirect(url_for("reports.index", generato=percorso))


@bp.post("/generate")
@role_required(ROLE_ANALYST)
def generate():
    """Genera un report del catalogo: esecutivo, inventario, NOC, SOC, conformita'.

    I report per la direzione e il fascicolo di conformita' richiedono
    l'amministratore di tenant: contengono valutazioni destinate a circolare fuori dal
    gruppo operativo.
    """
    from ..reports import REPORT_CATALOG, REPORT_KINDS
    from ..reports.generate import ReportError, generate as produci

    tenant = _tenant()
    genere = (request.form.get("kind") or "").strip()
    voce = REPORT_CATALOG.get(genere)
    if voce is None:
        flash("Genere di report non previsto.", "warning")
        return redirect(url_for("reports.index", scheda="catalogo"))
    if voce["ruolo"] == "tenant_admin" and not has_role(ROLE_TENANT_ADMIN):
        flash("Il report \"%s\" e' riservato agli amministratori di tenant: contiene"
              " valutazioni destinate a circolare fuori dal gruppo operativo."
              % REPORT_KINDS[genere], "warning")
        return redirect(url_for("reports.index", scheda="catalogo"))

    try:
        giorno = resoconto.parse_requested_day(request.form.get("day"), tenant)
        percorso = produci(genere, tenant, giorno, request.form.get("days"),
                           requested_by=_current_user_id())
    except (WindowError, ReportError) as errore:
        flash(str(errore), "warning")
        return redirect(url_for("reports.index", scheda="catalogo"))
    except OSError as errore:
        flash("Report non generato: %s" % errore, "danger")
        return redirect(url_for("reports.index", scheda="catalogo"))

    from pathlib import Path

    flash("%s generato: %s" % (REPORT_KINDS[genere], Path(percorso).name), "success")
    return redirect(url_for("reports.index"))


@bp.post("/incident/<int:incident_id>")
@role_required(ROLE_ANALYST)
def generate_incident(incident_id: int):
    """Rapporto di un incidente: base per un post-mortem e per la notifica NIS2."""
    from ..reports.generate import ReportError, generate_incident as produci

    tenant = _tenant()
    try:
        percorso = produci(tenant, incident_id, requested_by=_current_user_id())
    except ReportError as errore:
        flash(str(errore), "warning")
        return redirect(url_for("checks.incident_list"))

    from pathlib import Path

    flash("Rapporto dell'incidente #%d generato: %s"
          % (incident_id, Path(percorso).name), "success")
    return redirect(url_for("reports.index"))


@bp.post("/device/<int:node_id>")
@role_required(ROLE_ANALYST)
def generate_device_sheet(node_id: int):
    """Scheda PDF di un singolo apparato, chiesta dalla sua pagina."""
    from pathlib import Path
    from ..reports.generate import ReportError, generate_device

    tenant = _tenant()
    try:
        percorso = generate_device(tenant, node_id, requested_by=_current_user_id())
    except ReportError as errore:
        flash(str(errore), "warning")
        return redirect(url_for("inventory.node", node_id=node_id))
    flash("Scheda dell'apparato prodotta: %s. E' nell'archivio dei report."
          % Path(percorso).name, "success")
    return redirect(url_for("reports.index"))


# Identificativo di una chat Telegram: numerico (anche negativo per i gruppi) oppure
# un nome pubblico @nome (da 5 a 32 caratteri, lettere, cifre e underscore). Una
# allowlist, non una blocklist: si accetta solo cio' che ha la forma giusta.
_TELEGRAM_CHAT = re.compile(r"^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$")


def _capacita_invio() -> dict:
    """Su quali canali si puo' inviare adesso indicando il recapito sul momento.

    A differenza del resoconto quotidiano, qui il destinatario si scrive al momento:
    non serve un recapito gia' configurato, serve solo la CAPACITA' del canale -- un
    server di posta per l'email, il token del bot per Telegram. La chat Telegram
    predefinita nelle impostazioni non e' richiesta: la si indica nel modulo.
    """
    from ..channels import telegram_config
    from ..notifications import is_configured, smtp_config

    posta = smtp_config()
    telegram = telegram_config()
    if not posta["enabled"]:
        motivo = "notifiche disattivate in Amministrazione"
        return {CHANNEL_EMAIL: {"pronto": False, "motivo": motivo},
                CHANNEL_TELEGRAM: {"pronto": False, "motivo": motivo}}
    return {
        CHANNEL_EMAIL: {
            "pronto": is_configured(posta),
            "motivo": "" if is_configured(posta) else "manca il server di posta o il mittente",
        },
        CHANNEL_TELEGRAM: {
            "pronto": bool(telegram["enabled"] and telegram["token"]),
            "motivo": "" if (telegram["enabled"] and telegram["token"])
                      else "manca il token del bot o il canale e' disattivato",
        },
    }


@bp.post("/send")
@role_required(ROLE_ANALYST)
def send_report():
    """Invia a richiesta un report gia' prodotto verso recapiti indicati sul momento.

    I recapiti (email e/o chat Telegram) si scrivono qui, non si prendono da una
    configurazione: si puo' indicarne uno o entrambi. Il file non viene spedito dalla
    richiesta ma ACCODATO con il suo allegato, un invio per canale, e parte al giro
    successivo della coda; cosi' un canale lento non blocca la pagina e ogni tentativo
    (con il suo esito) resta nel registro delle notifiche.
    """
    tenant = _tenant()
    tenant_id = int(tenant["id"])
    try:
        report_id = int(request.form.get("report_id") or 0)
    except (TypeError, ValueError):
        report_id = 0
    percorso = storage.report_file(tenant_id, report_id)
    if percorso is None:
        flash("Il file del report non e' piu' disponibile: non c'e' nulla da inviare.",
              "warning")
        return redirect(url_for("reports.index"))

    email = (request.form.get("email") or "").strip()
    chat = (request.form.get("telegram") or "").strip()
    if not email and not chat:
        flash("Indicare almeno un recapito: un indirizzo di posta, una chat Telegram o"
              " entrambi.", "warning")
        return redirect(url_for("reports.index"))

    riga = query("SELECT kind, period_key FROM report_runs WHERE id = ? AND tenant_id = ?",
                 (report_id, tenant_id), one=True)
    genere = REPORT_KINDS.get(riga["kind"], riga["kind"]) if riga else "Report"
    periodo = riga["period_key"] if riga else ""
    oggetto = "%s - %s (%s)" % (genere, periodo, tenant["name"])
    corpo = ("In allegato il report \"%s\" relativo a %s del tenant %s, inviato dalla"
             " console SNAP su richiesta di un operatore." % (genere, periodo, tenant["name"]))

    capacita = _capacita_invio()
    # Ogni recapito indicato diventa un invio sul proprio canale. Una richiesta puo'
    # riuscire in parte: si accoda cio' che e' valido e configurato, e si dice con
    # chiarezza che cosa non e' partito.
    canali = []
    if email:
        canali.append((CHANNEL_EMAIL, email))
    if chat:
        canali.append((CHANNEL_TELEGRAM, chat))

    accodati = []
    problemi = []
    for canale, recapito in canali:
        if not capacita[canale]["pronto"]:
            problemi.append("%s non disponibile (%s)"
                            % (CHANNELS[canale], capacita[canale]["motivo"]))
            continue
        if canale == CHANNEL_EMAIL and (len(recapito) > 254
                                        or not EMAIL_PATTERN.match(recapito)):
            problemi.append("%r non e' un indirizzo di posta valido" % recapito)
            continue
        if canale == CHANNEL_TELEGRAM and not _TELEGRAM_CHAT.match(recapito):
            problemi.append("%r non e' una chat Telegram valida (id numerico o @nome)"
                            % recapito)
            continue
        esito = queue_notification(tenant_id, "report.delivery", [recapito], oggetto,
                                   corpo, channel=canale, attachment=percorso)
        if esito is None:
            problemi.append("notifiche disattivate: %s non accodato" % CHANNELS[canale])
            continue
        accodati.append((canale, recapito))
        log_event("report.sent",
                  "Report %s (%s) accodato per %s via %s"
                  % (genere, periodo, recapito, CHANNELS[canale]),
                  tenant_id=tenant_id, severity="info", entity="report",
                  entity_id=report_id)

    if accodati:
        dettaglio = ", ".join("%s via %s" % (rec, CHANNELS[c]) for c, rec in accodati)
        coda = (" Non inviato: %s." % "; ".join(problemi)) if problemi else ""
        flash("Report \"%s\" accodato per %s. Parte al giro successivo della coda;"
              " l'esito compare fra le notifiche.%s" % (genere, dettaglio, coda),
              "success" if not problemi else "warning")
    else:
        flash("Report non inviato: %s." % "; ".join(problemi), "warning")
    return redirect(url_for("reports.index"))


@bp.get("/download/<int:report_id>")
@login_required
def download(report_id: int):
    tenant = _tenant()
    percorso = storage.report_file(int(tenant["id"]), report_id)
    if percorso is None:
        flash("Il file del report non e' piu' disponibile.", "warning")
        return redirect(url_for("reports.index"))
    log_event("report.downloaded", "Report scaricato: %s" % percorso.name,
              tenant_id=int(tenant["id"]), severity="info", entity="report",
              entity_id=report_id)
    return send_file(percorso, as_attachment=True, download_name=percorso.name,
                     mimetype="application/pdf")


@bp.post("/<int:report_id>/delete")
@role_required(ROLE_ANALYST)
def delete(report_id: int):
    """Elimina un report dall'archivio, file compreso."""
    tenant = _tenant()
    esito = storage.remove(int(tenant["id"]), report_id)
    if esito is None:
        abort(404)
    if esito.get("errore"):
        flash("Il file del report non e' stato cancellato (%s): la riga resta"
              " nell'archivio, che continua a dire il vero." % esito["errore"],
              "danger")
        return redirect(url_for("reports.index"))

    log_event("report.deleted",
              "Report eliminato: %s (%s)" % (esito.get("nome_file")
                                             or esito.get("file_path") or report_id,
                                             esito.get("kind")),
              tenant_id=int(tenant["id"]), severity="warning", entity="report",
              entity_id=report_id)
    flash("Report eliminato dall'archivio%s."
          % (" con il suo file" if esito["file_rimosso"] else ""), "success")
    return redirect(url_for("reports.index"))


@bp.post("/run-scheduler")
@role_required(ROLE_ANALYST)
def run_scheduler():
    """Esegue subito un giro del pianificatore. Serve a verificare la configurazione."""
    esito = resoconto.run_once()
    flash("Pianificatore eseguito: %d spediti, %d saltati, %d errori.%s"
          % (esito.get("spediti", 0), esito.get("saltati", 0), esito.get("errori", 0),
             " " + "; ".join(esito.get("dettagli", [])) if esito.get("dettagli") else ""),
          "info" if not esito.get("errori") else "warning")
    return redirect(url_for("reports.index"))
