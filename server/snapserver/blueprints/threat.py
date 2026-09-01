"""
snap server - Menu Threat Intelligence: catalogo, correlazione, riscontri.

La pagina risponde a una domanda sola: **di cio' che ho in rete, che cosa e' noto per
essere un problema?** Le tre classi di risposta (confermato, da verificare, esposizione)
sono sempre distinte, perche' un elenco che le mescola non e' utilizzabile: chi lo legge
non sa quali righe sono fatti e quali ipotesi.

Permessi: consultazione a tutto il tenant; correlazione e decisioni sui riscontri agli
analisti; aggiornamento del catalogo e importazione da file agli amministratori di
tenant, perche' comportano traffico verso l'esterno e scrivono conoscenza condivisa fra
i tenant.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from .. import threat
from .. import threat_sources as sorgenti
from ..security import (ROLE_ANALYST, ROLE_SUPERADMIN, ROLE_TENANT_ADMIN,
                        login_required, role_required)
from ..tenancy import current_tenant_id

bp = Blueprint("threat", __name__, url_prefix="/threat")

# Schede della pagina. L'elenco sta qui e non nel modello perche' decide anche
# quali dati la vista prepara: sono la stessa decisione.
SCHEDE = ("riscontri", "catalogo", "cwe", "attack", "sorgenti")

# Quanti dispositivi si portano nella pagina. Su un inventario reale i riscontri sono
# migliaia ma i dispositivi sono centinaia: raccolti per nodo l'elenco si legge, e
# oltre questo numero restano le schede per classe e i filtri.
MAX_NODI_IN_PAGINA = 300


def _current_user_id():
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
    tenant_id = current_tenant_id()
    genere = (request.args.get("classe") or "").strip()
    stato = (request.args.get("stato") or threat.STATUS_OPEN).strip()
    gravita = (request.args.get("gravita") or "").strip()

    # Una scheda per volta. Preparare tutto a ogni apertura significava impaginare
    # cinquecento riscontri, duecento CVE, centotrenta CWE e settecento tecniche --
    # 1,7 MB -- per mostrarne una parte sola. Una chiave non prevista non e' un
    # errore: vale la scheda predefinita.
    scheda = (request.args.get("scheda") or "riscontri").strip()
    if scheda not in SCHEDE:
        scheda = "riscontri"

    contesto = {
        "scheda": scheda,
        "summary": threat.summary(tenant_id),
        "catalog": threat.catalog_summary(),
        "settings": sorgenti.public_settings(),
        "running": sorgenti.running_sync(),
        "kinds": threat.KINDS,
        "statuses": threat.STATUSES,
        "severities": threat.SEVERITIES,
        "sources": sorgenti.SORGENTI,
        "filtro": {"classe": genere, "stato": stato, "gravita": gravita,
                   "cerca": request.args.get("cerca") or ""},
        # Valori neutri per le schede non richieste: il modello non deve sapere
        # quale scheda e' aperta per non cadere.
        "nodes": [], "cves": [], "cwes": [], "exposures": [], "techniques": [],
        "syncs": [], "products": [],
    }

    if scheda == "riscontri":
        # L'elenco e' per DISPOSITIVO: lo stesso apparato compariva in venti righe,
        # e la domanda di chi lavora e' da quale cominciare.
        contesto["nodes"] = threat.nodes_with_findings(
            tenant_id, kind=genere, status=stato, severita=gravita,
            limit=MAX_NODI_IN_PAGINA)
        contesto["limite_elenco"] = MAX_NODI_IN_PAGINA
    elif scheda == "catalogo":
        contesto["cves"] = threat.search_cve(request.args.get("cerca") or "",
                                             request.args.get("cve_gravita") or "",
                                             bool(request.args.get("solo_kev")))
    elif scheda == "cwe":
        contesto["cwes"] = threat.cwe_list()
    elif scheda == "attack":
        contesto["exposures"] = threat.exposure_catalog()
        contesto["techniques"] = threat.techniques()
    elif scheda == "sorgenti":
        contesto["syncs"] = sorgenti.recent_syncs()
        contesto["products"] = sorgenti.inventory_products(tenant_id)[:40]

    return render_template("threat/index.html", **contesto)


@bp.get("/cve/<cve_id>")
@login_required
def cve(cve_id: str):
    tenant_id = current_tenant_id()
    voce = threat.cve(cve_id)
    if voce is None:
        flash("La CVE %s non e' nel catalogo locale: aggiornare il catalogo oppure"
              " importarla da file." % cve_id.upper(), "warning")
        return redirect(url_for("threat.index", scheda="catalogo"))
    return render_template(
        "threat/cve.html",
        cve=voce,
        affected=threat.affected_nodes(tenant_id, voce["cve_id"]),
        kinds=threat.KINDS,
        statuses=threat.STATUSES,
    )


@bp.post("/correlate")
@role_required(ROLE_ANALYST)
def correlate():
    """Rivaluta l'inventario contro il catalogo locale. Non contatta nessuno."""
    tenant_id = current_tenant_id()
    esito = threat.correlate(tenant_id, _current_user_id())
    flash("Correlazione eseguita su %d osservazioni: %d riscontri nuovi, %d aggiornati,"
          " %d chiusi. Confermati %d, da verificare %d, esposizioni %d.%s"
          % (esito["esaminati"], esito["nuovi"], esito["aggiornati"], esito["chiusi"],
             esito["confermati"], esito["da_verificare"], esito["esposizioni"],
             " Elenco troncato: troppi riscontri in una passata."
             if esito["troncato"] else ""),
          "success")
    return redirect(url_for("threat.index"))


@bp.post("/findings/<int:finding_id>/decide")
@role_required(ROLE_ANALYST)
def decide(finding_id: int):
    tenant_id = current_tenant_id()
    stato = (request.form.get("stato") or "").strip()
    try:
        trovato = threat.decide(tenant_id, finding_id, stato,
                                request.form.get("note") or "", _current_user_id())
    except threat.ThreatError as errore:
        flash(str(errore), "warning")
        return redirect(request.referrer or url_for("threat.index"))
    if not trovato:
        abort(404)
    flash("Riscontro aggiornato: %s." % threat.STATUSES.get(stato, stato), "success")
    return redirect(request.referrer or url_for("threat.index"))


@bp.post("/sync/<operazione>")
@role_required(ROLE_TENANT_ADMIN)
def sync(operazione: str):
    """Avvia l'aggiornamento del catalogo in secondo piano."""
    consentite = ("targeted", "window", "kev", "cwe", "attack", "tutto")
    if operazione not in consentite:
        flash("Aggiornamento non previsto.", "warning")
        return redirect(url_for("threat.index", scheda="sorgenti"))

    giorni = request.form.get("giorni")
    avviato = sorgenti.start_background(
        current_app._get_current_object(), operazione,
        tenant_id=current_tenant_id(), requested_by=_current_user_id(),
        giorni=int(giorni) if (giorni or "").isdigit() else None)
    if not avviato:
        flash("Un aggiornamento e' gia' in corso: attendere che finisca. Lo stato e'"
              " nella scheda Sorgenti.", "warning")
    else:
        flash("Aggiornamento avviato in secondo piano (%s). La NVD limita le richieste,"
              " quindi l'interrogazione per l'inventario dura alcuni minuti: la scheda"
              " Sorgenti mostra l'avanzamento." % operazione, "info")
    return redirect(url_for("threat.index", scheda="sorgenti"))


@bp.post("/settings/api-key")
@role_required(ROLE_SUPERADMIN)
def save_api_key():
    """Registra la chiave API della NVD.

    Riservata all'amministratore di sistema e non all'amministratore di tenant: il
    catalogo delle vulnerabilita' e' unico per tutto il server, quindi la chiave e'
    una credenziale dell'installazione e non di un cliente.
    """
    try:
        esito = sorgenti.save_api_key(request.form.get("api_key") or "",
                                      _current_user_id())
    except sorgenti.SourceError as errore:
        flash(str(errore), "warning")
        return redirect(url_for("threat.index", scheda="sorgenti"))

    if esito == "rimossa":
        flash("Chiave API rimossa: gli aggiornamenti tornano a 5 richieste ogni 30"
              " secondi.", "info")
    else:
        flash("Chiave API registrata: gli aggiornamenti passano a 50 richieste ogni 30"
              " secondi, e l'interrogazione per l'inventario da alcuni minuti scende a"
              " pochi secondi.", "success")
    return redirect(url_for("threat.index", scheda="sorgenti"))


@bp.post("/import")
@role_required(ROLE_TENANT_ADMIN)
def import_catalog():
    """Importa un catalogo da file: e' la via per le reti senza uscita."""
    documento = request.files.get("file")
    if documento is None or not documento.filename:
        flash("Nessun file indicato.", "warning")
        return redirect(url_for("threat.index", scheda="sorgenti"))
    try:
        contenuto = documento.read()
        esito = sorgenti.import_file(contenuto, documento.filename,
                                     _current_user_id())
    except sorgenti.SourceError as errore:
        flash("Importazione non riuscita: %s" % errore, "danger")
        return redirect(url_for("threat.index", scheda="sorgenti"))
    except OSError as errore:
        flash("File non leggibile: %s" % errore, "danger")
        return redirect(url_for("threat.index", scheda="sorgenti"))

    flash("Importazione completata da %s: %s"
          % (documento.filename[:80],
             ", ".join("%s %s" % (v, k) for k, v in esito.items())), "success")
    return redirect(url_for("threat.index", scheda="sorgenti"))
