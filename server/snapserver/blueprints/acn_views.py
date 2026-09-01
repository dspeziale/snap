# -----------------------------------------------------------------
# acn_views.py — pagine del percorso di comunicazione ad ACN
# Autore: Daniele Speziale
# Data creazione: 2026-08-31
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Il percorso di una comunicazione ad ACN, dalla console.

Una pagina sola con l'elenco delle comunicazioni dovute e il loro stato, e per ciascuna
i tre passaggi che l'operatore compie davvero:

1. **prepara** -- si compone il fascicolo (PDF con i campi da copiare e le prove);
2. **registra l'invio** -- dopo aver inviato dal portale, si annota il numero di
   protocollo restituito: senza quello l'invio non e' dimostrabile;
3. **annota il riscontro** -- cio' che l'autorita' risponde.

Chi puo': il percorso e' riservato all'**amministratore del tenant**. Non e' una
gerarchia per gusto -- la comunicazione all'autorita' e' un atto che impegna il
soggetto, e chi la registra dichiara che e' avvenuta.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from .. import acn
from ..db import query, utc_now_str
from ..inventory_queries import inventory_summary
from ..security import ROLE_TENANT_ADMIN, login_required, role_required
from ..tenancy import current_tenant_id

bp = Blueprint("acn", __name__, url_prefix="/acn")


def _attore() -> str:
    utente = getattr(g, "user", None)
    return (utente["email"] if utente else "") or ""


@bp.get("/")
@login_required
@role_required(ROLE_TENANT_ADMIN)
def index():
    """Elenco delle comunicazioni dovute, dalla piu' urgente."""
    tenant_id = current_tenant_id()
    voci = acn.comunicazioni(tenant_id)
    # Gli incidenti aperti senza fascicolo: sono la domanda che la pagina deve porre
    # per prima -- "questo va notificato?" -- e non si vede da nessun'altra parte.
    senza_fascicolo = [dict(r) for r in query(
        "SELECT i.id, i.severity, i.opened_at, i.first_detail,"
        " COALESCE(i.origin, 'check') AS origine,"
        " COALESCE(NULLIF(i.title, ''), c.name) AS controllo,"
        " COALESCE(NULLIF(i.subject, ''), t.address) AS bersaglio"
        " FROM check_incidents i JOIN checks c ON c.id = i.check_id"
        " JOIN check_targets t ON t.id = c.target_id"
        " WHERE i.tenant_id = ? AND i.status = 'open'"
        "   AND NOT EXISTS (SELECT 1 FROM acn_communications a"
        "                   WHERE a.incident_id = i.id)"
        " ORDER BY i.opened_at DESC LIMIT 50", (tenant_id,))]

    return render_template(
        "acn/index.html",
        comunicazioni=voci,
        senza_fascicolo=senza_fascicolo,
        registro=acn.registro(tenant_id),
        stadi=acn.STADI,
        stati=acn.STATI,
        canali=acn.CANALI,
        portale=acn.PORTALE,
        criteri=acn.CRITERI,
        soglie=acn.SOGLIE,
        gravita=acn.GRAVITA,
        adesso_utc=utc_now_str(),
        summary=inventory_summary(tenant_id),
    )


@bp.post("/incidenti")
@login_required
@role_required(ROLE_TENANT_ADMIN)
def registra():
    """Registra un incidente che non nasce da un controllo.

    Gli incidenti che contano di piu' non li rileva una sonda: li porta una telefonata,
    una segnalazione del CSIRT, un riscatto comparso su uno schermo.
    """
    tenant_id = current_tenant_id()
    utente = getattr(g, "user", None)
    try:
        incident_id = acn.registra_incidente(
            tenant_id,
            titolo=request.form.get("titolo") or "",
            soggetto=request.form.get("soggetto") or "",
            gravita=(request.form.get("gravita") or "warning").strip(),
            conosciuto_alle=request.form.get("conosciuto_alle") or "",
            descrizione=request.form.get("descrizione") or "",
            utente_id=int(utente["id"]) if utente else None,
            attore=_attore())
    except acn.AcnError as errore:
        flash(str(errore), "danger")
        return redirect(url_for("acn.index"))

    flash("Incidente registrato. Ora si valuta se e' significativo: aprire il fascicolo"
          " fa partire i termini.", "warning")
    return redirect(url_for("acn.incidente", incident_id=incident_id))


@bp.post("/incidenti/<int:incident_id>/elimina")
@login_required
@role_required(ROLE_TENANT_ADMIN)
def elimina(incident_id: int):
    """Elimina un incidente registrato a mano, se nulla e' stato comunicato."""
    tenant_id = current_tenant_id()
    try:
        esito = acn.elimina_incidente(tenant_id, incident_id, attore=_attore())
    except acn.AcnError as errore:
        flash(str(errore), "danger")
        return redirect(url_for("acn.index"))

    flash("Incidente \"%s\" eliminato%s." % (
        esito["titolo"],
        " con %d comunicazioni mai inviate" % esito["comunicazioni"]
        if esito["comunicazioni"] else ""), "info")
    return redirect(url_for("acn.index"))


@bp.get("/incidenti/<int:incident_id>")
@login_required
@role_required(ROLE_TENANT_ADMIN)
def incidente(incident_id: int):
    """La valutazione di significativita' di un incidente, prima di aprire il fascicolo."""
    tenant_id = current_tenant_id()
    voce = acn.incidente(tenant_id, incident_id)
    if voce is None:
        abort(404)
    return render_template(
        "acn/valutazione.html",
        incidente=dict(voce),
        valutazione=acn.valuta(dict(voce)),
        criteri=acn.CRITERI,
        soglie=acn.SOGLIE,
        stadi=acn.STADI,
        portale=acn.PORTALE,
        comunicazioni=acn.comunicazioni(tenant_id, incident_id),
        # Il campo del modulo si scrive in UTC: il nome lo dichiara.
        conoscenza_utc=voce["opened_at"],
        summary=inventory_summary(tenant_id),
    )


@bp.post("/incidenti/<int:incident_id>/apri")
@login_required
@role_required(ROLE_TENANT_ADMIN)
def apri(incident_id: int):
    """Apre il fascicolo: crea gli stadi con le loro scadenze."""
    tenant_id = current_tenant_id()
    voce = acn.incidente(tenant_id, incident_id)
    if voce is None:
        abort(404)

    conosciuto = (request.form.get("conosciuto_alle") or "").strip()
    try:
        acn.apri_fascicolo(tenant_id, incident_id,
                           conosciuto_alle=conosciuto or None,
                           valutazione=acn.valuta(dict(voce)),
                           attore=_attore())
    except acn.AcnError as errore:
        flash(str(errore), "danger")
        return redirect(url_for("acn.incidente", incident_id=incident_id))

    flash("Fascicolo aperto: preallarme entro 24 ore, notifica entro 72, relazione"
          " finale entro un mese dalla conoscenza dell'incidente.", "warning")
    return redirect(url_for("acn.index"))


@bp.post("/incidenti/<int:incident_id>/aggiornamento")
@login_required
@role_required(ROLE_TENANT_ADMIN)
def aggiornamento(incident_id: int):
    tenant_id = current_tenant_id()
    try:
        acn.aggiungi_aggiornamento(tenant_id, incident_id,
                                   motivo=(request.form.get("motivo") or "").strip())
    except acn.AcnError as errore:
        flash(str(errore), "danger")
    else:
        flash("Aggiornamento aggiunto al fascicolo.", "success")
    return redirect(url_for("acn.index"))


@bp.get("/comunicazioni/<int:comunicazione_id>")
@login_required
@role_required(ROLE_TENANT_ADMIN)
def dettaglio(comunicazione_id: int):
    """I campi da copiare nel portale e le prove, a schermo."""
    tenant_id = current_tenant_id()
    try:
        dati = acn.fascicolo(tenant_id, comunicazione_id)
    except acn.AcnError:
        abort(404)
    return render_template("acn/dettaglio.html", **dati, stati=acn.STATI,
                           summary=inventory_summary(tenant_id))


@bp.get("/comunicazioni/<int:comunicazione_id>/fascicolo.pdf")
@login_required
@role_required(ROLE_TENANT_ADMIN)
def fascicolo_pdf(comunicazione_id: int):
    """Il PDF da allegare al portale. Prepararlo porta la comunicazione a "preparata"."""
    from ..reports.render_acn import acn_report

    tenant_id = current_tenant_id()
    try:
        dati = acn.fascicolo(tenant_id, comunicazione_id)
    except acn.AcnError:
        abort(404)
    dati["generato_utc"] = utc_now_str()

    cartella = Path(tempfile.gettempdir()) / "snap-acn"
    cartella.mkdir(parents=True, exist_ok=True)
    nome = "snap-acn-%s-incidente-%s.pdf" % (dati["comunicazione"]["stage"],
                                             dati["incidente"]["id"])
    percorso = cartella / nome
    acn_report(percorso, dati)

    # La prima composizione porta lo stadio a "preparata": e' un fatto, non una
    # etichetta -- il fascicolo esiste e si puo' allegare.
    if dati["comunicazione"]["status"] == acn.DA_PREPARARE:
        try:
            acn.cambia_stato(tenant_id, comunicazione_id, acn.PREPARATA,
                             attore=_attore(), percorso=str(percorso))
        except acn.AcnError as errore:  # non deve impedire lo scarico
            current_app.logger.warning("Stato della comunicazione ACN %s non"
                                       " aggiornato: %s", comunicazione_id, errore)

    return send_file(percorso, mimetype="application/pdf", as_attachment=True,
                     download_name=nome)


@bp.post("/comunicazioni/<int:comunicazione_id>/inviata")
@login_required
@role_required(ROLE_TENANT_ADMIN)
def inviata(comunicazione_id: int):
    """Registra l'invio avvenuto dal portale, con il numero di protocollo."""
    tenant_id = current_tenant_id()
    try:
        acn.cambia_stato(
            tenant_id, comunicazione_id, acn.INVIATA, attore=_attore(),
            protocollo=(request.form.get("protocollo") or "").strip(),
            note=(request.form.get("note") or "").strip())
    except acn.AcnError as errore:
        flash(str(errore), "danger")
    else:
        flash("Invio registrato con il protocollo del portale.", "success")
    return redirect(url_for("acn.index"))


@bp.post("/comunicazioni/<int:comunicazione_id>/riscontro")
@login_required
@role_required(ROLE_TENANT_ADMIN)
def riscontro(comunicazione_id: int):
    tenant_id = current_tenant_id()
    try:
        acn.cambia_stato(tenant_id, comunicazione_id, acn.RISCONTRO,
                         attore=_attore(),
                         note=(request.form.get("note") or "").strip())
    except acn.AcnError as errore:
        flash(str(errore), "danger")
    else:
        flash("Riscontro annotato.", "success")
    return redirect(url_for("acn.index"))


@bp.post("/comunicazioni/<int:comunicazione_id>/non-dovuta")
@login_required
@role_required(ROLE_TENANT_ADMIN)
def non_dovuta(comunicazione_id: int):
    """Dichiara che lo stadio non e' dovuto. La motivazione e' obbligatoria."""
    tenant_id = current_tenant_id()
    try:
        acn.cambia_stato(tenant_id, comunicazione_id, acn.NON_DOVUTA,
                         attore=_attore(),
                         note=(request.form.get("motivo") or "").strip())
    except acn.AcnError as errore:
        flash(str(errore), "danger")
    else:
        flash("Stadio dichiarato non dovuto: la motivazione resta nel fascicolo.",
              "info")
    return redirect(url_for("acn.index"))
