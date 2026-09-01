"""
snap server - Menu Regole: notifiche su qualunque evento del sistema.

L'operatore dichiara che cosa vuole sapere e su quale canale. La valutazione e' del
server: un thread legge gli eventi nuovi di ogni sorgente e applica le regole attive.

La prova sulla storia e' parte del percorso di creazione, non un extra: attivare una
regola senza sapere quante volte avrebbe scattato ieri significa scoprirlo dal numero
di messaggi che arrivano.

Permessi: consultazione a tutto il tenant; creazione, modifica e prova agli
amministratori di tenant, perche' una regola spedisce messaggi a nome
dell'organizzazione.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
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

from .. import rules as motore
from ..channels import CHANNELS, available_channels
from ..checks import ASSERTION_OPS, SEVERITIES
from ..events import SOURCES, event_fields
from ..security import ROLE_TENANT_ADMIN, login_required, role_required
from ..tenancy import current_tenant_id

bp = Blueprint("rules", __name__, url_prefix="/rules")


def _current_user_id():
    utente = getattr(g, "user", None)
    if utente is None:
        return None
    try:
        return int(utente["id"])
    except (KeyError, TypeError, IndexError):
        return getattr(utente, "id", None)


def _catalogo() -> list:
    """Sorgenti di evento con tipi e attributi, per le maschere."""
    voci = []
    for chiave, voce in SOURCES.items():
        voci.append({
            "chiave": chiave,
            "etichetta": voce["etichetta"],
            "descrizione": voce["descrizione"],
            "tipi": voce["tipi"],
            "attributi": event_fields(chiave),
        })
    return voci


def _definizione_da_modulo() -> dict:
    """Definizione della regola dal modulo, comprese le condizioni a righe."""
    condizioni = []
    campi = request.form.getlist("condition_field")
    operatori = request.form.getlist("condition_op")
    valori = request.form.getlist("condition_value")
    for indice, campo in enumerate(campi):
        if not (campo or "").strip():
            continue
        condizioni.append({
            "field": campo,
            "op": operatori[indice] if indice < len(operatori) else "eq",
            "value": valori[indice] if indice < len(valori) else "",
        })
    return {
        "name": request.form.get("name"),
        "description": request.form.get("description"),
        "source": request.form.get("source"),
        "event_type": request.form.get("event_type"),
        "conditions": condizioni,
        "severity": request.form.get("severity"),
        "channels": request.form.getlist("channels"),
        "recipients": request.form.get("recipients"),
        "telegram_chat_id": request.form.get("telegram_chat_id"),
        "window_seconds": request.form.get("window_seconds"),
        "max_per_window": request.form.get("max_per_window"),
        "digest_only": request.form.get("digest_only"),
    }


@bp.get("/")
@login_required
def index():
    tenant_id = current_tenant_id()
    return render_template(
        "rules/index.html",
        rules=motore.rules_of(tenant_id),
        summary=motore.summary(tenant_id),
        matches=motore.matches_of(tenant_id, limit=200),
        catalog=_catalogo(),
        channels=available_channels(),
        channel_labels=CHANNELS,
        ops=ASSERTION_OPS,
        severities=SEVERITIES,
        suggestions=SUGGERIMENTI,
    )


@bp.post("/")
@role_required(ROLE_TENANT_ADMIN)
def create():
    tenant_id = current_tenant_id()
    try:
        definizione = motore.validate_rule(_definizione_da_modulo())
        identificativo = motore.create_rule(tenant_id, definizione,
                                            _current_user_id())
    except motore.RuleError as errore:
        flash(str(errore), "warning")
        return redirect(url_for("rules.index", scheda="nuova"))
    flash("Regola creata e attiva. Vale sugli eventi che accadranno da adesso: per"
          " sapere che cosa avrebbe fatto ieri, usare la prova sulla storia.", "success")
    return redirect(url_for("rules.rule", rule_id=identificativo))


@bp.get("/<int:rule_id>")
@login_required
def rule(rule_id: int):
    tenant_id = current_tenant_id()
    regola = motore.rule(tenant_id, rule_id)
    if regola is None:
        abort(404)
    return render_template(
        "rules/rule.html",
        rule=regola,
        matches=motore.matches_of(tenant_id, rule_id=rule_id, limit=200),
        catalog=_catalogo(),
        channels=available_channels(),
        channel_labels=CHANNELS,
        ops=ASSERTION_OPS,
        severities=SEVERITIES,
    )


@bp.post("/<int:rule_id>/update")
@role_required(ROLE_TENANT_ADMIN)
def update(rule_id: int):
    tenant_id = current_tenant_id()
    if motore.rule(tenant_id, rule_id) is None:
        abort(404)
    try:
        definizione = motore.validate_rule(_definizione_da_modulo())
        motore.update_rule(tenant_id, rule_id, definizione)
    except motore.RuleError as errore:
        flash(str(errore), "warning")
        return redirect(url_for("rules.rule", rule_id=rule_id))
    flash("Regola aggiornata.", "success")
    return redirect(url_for("rules.rule", rule_id=rule_id))


@bp.post("/<int:rule_id>/toggle")
@role_required(ROLE_TENANT_ADMIN)
def toggle(rule_id: int):
    if not motore.toggle_rule(current_tenant_id(), rule_id):
        abort(404)
    flash("Stato della regola aggiornato.", "success")
    return redirect(request.referrer or url_for("rules.index"))


@bp.post("/<int:rule_id>/delete")
@role_required(ROLE_TENANT_ADMIN)
def delete(rule_id: int):
    if not motore.delete_rule(current_tenant_id(), rule_id):
        abort(404)
    flash("Regola eliminata. Lo storico delle corrispondenze e' stato rimosso con lei.",
          "success")
    return redirect(url_for("rules.index"))


@bp.post("/test")
@role_required(ROLE_TENANT_ADMIN)
def test():
    """Prova una definizione sugli ultimi eventi, senza spedire nulla."""
    tenant_id = current_tenant_id()
    try:
        definizione = motore.validate_rule(_definizione_da_modulo())
        esito = motore.test_rule(tenant_id, definizione,
                                 limit=int(request.form.get("limit") or 200))
    except motore.RuleError as errore:
        flash(str(errore), "warning")
        return redirect(url_for("rules.index", scheda="nuova"))
    except ValueError:
        flash("Numero di eventi da esaminare non valido.", "warning")
        return redirect(url_for("rules.index", scheda="nuova"))

    return render_template(
        "rules/test.html",
        definition=definizione,
        result=esito,
        channel_labels=CHANNELS,
    )


@bp.post("/<int:rule_id>/test")
@role_required(ROLE_TENANT_ADMIN)
def test_existing(rule_id: int):
    tenant_id = current_tenant_id()
    regola = motore.rule(tenant_id, rule_id)
    if regola is None:
        abort(404)
    definizione = {
        "name": regola["name"], "description": regola["description"],
        "source": regola["source"], "event_type": regola["event_type"],
        "conditions": regola["conditions"], "severity": regola["severity"],
        "channels": regola["channel_list"], "recipients": regola["recipients"],
        "telegram_chat_id": regola["telegram_chat_id"],
        "window_seconds": regola["window_seconds"],
        "max_per_window": regola["max_per_window"],
        "digest_only": regola["digest_only"],
    }
    esito = motore.test_rule(tenant_id, definizione,
                             limit=int(request.form.get("limit") or 200))
    return render_template("rules/test.html", definition=definizione, result=esito,
                           channel_labels=CHANNELS, rule=regola)


@bp.post("/evaluate")
@role_required(ROLE_TENANT_ADMIN)
def evaluate():
    """Esegue subito un giro del valutatore: utile dopo aver creato una regola."""
    esito = motore.run_once()
    flash("Valutatore eseguito: %d eventi, %d corrispondenze, %d notifiche accodate,"
          " %d soppresse dall'anti-alluvione."
          % (esito["eventi"], esito["corrispondenze"], esito["notifiche"],
             esito["soppresse"]), "info")
    return redirect(url_for("rules.index"))


# Regole pronte, offerte nella pagina. Non sono create automaticamente: una notifica
# che nessuno ha chiesto e' rumore, e la scelta di che cosa sapere e' dell'operatore.
SUGGERIMENTI = [
    {
        "nome": "Nodo nuovo in rete",
        "descrizione": "Un dispositivo mai visto prima compare nel perimetro.",
        "source": "node_changes", "event_type": "node.appeared",
        "conditions": [], "severity": "warning",
        "window_seconds": 900, "max_per_window": 5,
    },
    {
        "nome": "Amministrazione remota esposta",
        "descrizione": "Si apre una porta di amministrazione remota (RDP).",
        "source": "node_changes", "event_type": "port.opened",
        "conditions": [{"field": "port", "op": "eq", "value": "3389"}],
        "severity": "critical", "window_seconds": 900, "max_per_window": 10,
    },
    {
        "nome": "SMB esposto su un nodo nuovo",
        "descrizione": "Condivisione file raggiungibile: propagazione tipica dei"
                       " ransomware.",
        "source": "node_changes", "event_type": "port.opened",
        "conditions": [{"field": "port", "op": "eq", "value": "445"}],
        "severity": "critical", "window_seconds": 3600, "max_per_window": 10,
    },
    {
        "nome": "Telnet, protocollo in chiaro",
        "descrizione": "Una porta 23 aperta e' una credenziale che viaggia in chiaro.",
        "source": "node_changes", "event_type": "port.opened",
        "conditions": [{"field": "port", "op": "eq", "value": "23"}],
        "severity": "critical", "window_seconds": 3600, "max_per_window": 5,
    },
    {
        "nome": "Nodo scomparso",
        "descrizione": "Un dispositivo che c'era non risponde piu' da una passata.",
        "source": "node_changes", "event_type": "node.disappeared",
        "conditions": [], "severity": "warning",
        "window_seconds": 1800, "max_per_window": 5,
    },
    {
        "nome": "Scansione non completata",
        "descrizione": "L'inventario ha smesso di aggiornarsi.",
        "source": "scan_runs", "event_type": "scan.failed",
        "conditions": [], "severity": "warning",
        "window_seconds": 3600, "max_per_window": 3,
    },
    {
        "nome": "Accesso alla console fallito",
        "descrizione": "Tentativo di accesso non riuscito: da guardare se si ripete.",
        "source": "audit_events", "event_type": "auth.login.failed",
        "conditions": [], "severity": "warning",
        "window_seconds": 900, "max_per_window": 5,
    },
    {
        "nome": "Archivio di una sonda azzerato",
        "descrizione": "Operazione distruttiva su una sonda: va saputa sempre.",
        "source": "audit_events", "event_type": "probe.store.reset",
        "conditions": [], "severity": "critical",
        "window_seconds": 3600, "max_per_window": 5,
    },
    {
        "nome": "Controllo in errore",
        "descrizione": "Un controllo non ha potuto essere eseguito: non e' un servizio"
                       " degradato, e' un impedimento.",
        "source": "check_results", "event_type": "check.error",
        "conditions": [], "severity": "warning",
        "window_seconds": 1800, "max_per_window": 5,
    },
    {
        "nome": "Latenza oltre il secondo",
        "descrizione": "Un esito riuscito ma lento: degrado prima del guasto.",
        "source": "check_results", "event_type": "check.ok",
        "conditions": [{"field": "latency_ms", "op": "gt", "value": "1000"}],
        "severity": "info", "window_seconds": 3600, "max_per_window": 3,
    },
    {
        "nome": "Conferimento rifiutato",
        "descrizione": "Una sonda ha inviato un lotto che il server non ha accettato.",
        "source": "ingest_batches", "event_type": "ingest.rejected",
        "conditions": [], "severity": "warning",
        "window_seconds": 3600, "max_per_window": 5,
    },
    {
        "nome": "Vulnerabilita' confermata su un nodo",
        "descrizione": "La correlazione ha stabilito che un nodo ha un prodotto e una"
                       " versione interessati da una CVE: e' un fatto, non un'ipotesi.",
        "source": "ti_findings", "event_type": "threat.confirmed",
        "conditions": [], "severity": "critical",
        "window_seconds": 3600, "max_per_window": 10,
    },
    {
        "nome": "Vulnerabilita' sfruttata attivamente",
        "descrizione": "Riscontro confermato su una CVE presente nel catalogo CISA KEV:"
                       " fra due vulnerabilita' con lo stesso punteggio, questa va prima.",
        "source": "ti_findings", "event_type": "threat.confirmed",
        "conditions": [{"field": "kev", "op": "eq", "value": "1"}],
        "severity": "critical", "window_seconds": 3600, "max_per_window": 20,
    },
    {
        "nome": "Banca dati esposta",
        "descrizione": "Si apre una porta di banca dati (Oracle 1521).",
        "source": "node_changes", "event_type": "port.opened",
        "conditions": [{"field": "port", "op": "eq", "value": "1521"}],
        "severity": "critical", "window_seconds": 3600, "max_per_window": 10,
    },
]
