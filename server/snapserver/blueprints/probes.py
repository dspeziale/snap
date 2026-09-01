"""
snap server - Gestione della flotta di sonde.

Il server non contatta mai la sonda: la registrazione avviene per iniziativa
della sonda che presenta un token monouso generato qui. Le variazioni di
configurazione vengono accodate come comandi e consegnate al primo contatto
utile (heartbeat o conferimento).

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import base64
import json
import re
import uuid
from datetime import timedelta

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from ..audit import log_event
from ..crypto import (
    derive_enrollment_key,
    generate_enrollment_token,
    token_fingerprint,
)
from ..db import execute, query, utc_now, utc_now_str
from ..blueprints.api_probe import (
    DISCOVERY_DAYS_MAX,
    DISCOVERY_DAYS_MIN,
    HOST_TIMEOUTS,
    SCAN_EFFORTS,
)
from ..queries import probe_fleet
from ..security import ROLE_ANALYST, ROLE_TENANT_ADMIN, login_required, role_required
from ..tenancy import current_tenant_id

bp = Blueprint("probes", __name__, url_prefix="/probes")

CODE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
AVAILABLE_COMMANDS = {
    "flush": "Conferimento immediato della coda",
    "reconfigure": "Ricarica della configurazione",
    "pause": "Sospensione della raccolta",
    "resume": "Ripresa della raccolta",
    "wipe": "Svuotamento della coda locale",
    "reset": "Azzeramento del contatore dei cicli",
    "scan": "Esecuzione immediata di una fase di scansione",
    "scan_pause": "Sospensione delle scansioni di rete",
    "scan_resume": "Ripresa delle scansioni di rete",
}


def _public_base_url() -> str:
    """URL con cui la sonda raggiunge il server: da impostazioni o dalla richiesta."""
    row = query("SELECT value FROM system_settings WHERE key = 'public_url'", (), one=True)
    if row and row["value"]:
        return str(row["value"]).rstrip("/")
    return request.host_url.rstrip("/")


def _enrollment_bundle(code: str, token: str) -> str:
    """Pacchetto copiabile che la sonda accetta in un unico campo."""
    payload = {"url": _public_base_url(), "code": code, "token": token}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return "SNAP1-" + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _load_probe(probe_id: int, tenant_id: int):
    probe = query(
        "SELECT * FROM probes WHERE id = ? AND tenant_id = ?", (probe_id, tenant_id), one=True
    )
    if probe is None:
        abort(404)
    return probe


def _issue_token(probe_id: int, code: str) -> str:
    """Genera un token di registrazione e memorizza solo impronta e chiave derivata."""
    token = generate_enrollment_token()
    expires = utc_now() + timedelta(hours=current_app.config["ENROLLMENT_TTL_HOURS"])
    execute(
        "UPDATE probes SET enrollment_token_hash = ?, enrollment_key = ?,"
        " enrollment_expires_at = ?, updated_at = ? WHERE id = ?",
        (
            token_fingerprint(token),
            derive_enrollment_key(token, code),
            expires.strftime("%Y-%m-%d %H:%M:%S"),
            utc_now_str(),
            probe_id,
        ),
    )
    return token


@bp.get("/")
@login_required
def index():
    tenant_id = current_tenant_id()
    return render_template(
        "probes/index.html",
        fleet=probe_fleet(tenant_id),
        offline_after=current_app.config["PROBE_OFFLINE_AFTER_SEC"],
    )


@bp.route("/new", methods=["GET", "POST"])
@role_required(ROLE_TENANT_ADMIN)
def create():
    tenant_id = current_tenant_id()
    if request.method == "POST":
        code = (request.form.get("code") or "").strip().lower()
        name = (request.form.get("name") or "").strip()
        if not CODE_PATTERN.match(code):
            flash(
                "Codice sonda non valido: usare 3-32 caratteri fra lettere minuscole,"
                " cifre, punto, trattino e underscore.",
                "warning",
            )
            return render_template("probes/new.html", form=request.form)
        if not name:
            flash("Indicare il nome della sonda.", "warning")
            return render_template("probes/new.html", form=request.form)

        existing = query(
            "SELECT id FROM probes WHERE tenant_id = ? AND code = ?", (tenant_id, code), one=True
        )
        if existing is not None:
            flash("Esiste gia' una sonda con questo codice per il tenant corrente.", "danger")
            return render_template("probes/new.html", form=request.form)

        try:
            interval = max(30, min(86400, int(request.form.get("scan_interval_sec") or 300)))
        except ValueError:
            interval = 300

        now = utc_now_str()
        probe_id = execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, description, site,"
            " status, scan_interval_sec, config_json, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, '{}', ?, ?)",
            (
                tenant_id,
                uuid.uuid4().hex,
                code,
                name,
                (request.form.get("description") or "").strip() or None,
                (request.form.get("site") or "").strip() or None,
                interval,
                now,
                now,
            ),
        )
        token = _issue_token(probe_id, code)
        log_event(
            "probe.created",
            "Sonda %s creata in attesa di registrazione" % code,
            entity="probe",
            entity_id=probe_id,
        )
        return render_template(
            "probes/credentials.html",
            probe=_load_probe(probe_id, tenant_id),
            token=token,
            bundle=_enrollment_bundle(code, token),
            server_url=_public_base_url(),
        )

    return render_template("probes/new.html", form={})


@bp.get("/<int:probe_id>")
@login_required
def detail(probe_id: int):
    tenant_id = current_tenant_id()
    probe = _load_probe(probe_id, tenant_id)
    batches = query(
        "SELECT * FROM ingest_batches WHERE probe_id = ? AND tenant_id = ?"
        " ORDER BY received_at DESC LIMIT 15",
        (probe_id, tenant_id),
    )
    commands = query(
        "SELECT * FROM probe_commands WHERE probe_id = ? AND tenant_id = ?"
        " ORDER BY created_at DESC LIMIT 15",
        (probe_id, tenant_id),
    )
    try:
        options = json.loads(probe["config_json"] or "{}")
    except json.JSONDecodeError:
        options = {}

    return render_template(
        "probes/detail.html",
        probe=probe,
        batches=batches,
        commands=commands,
        options_json=json.dumps(options, indent=2, ensure_ascii=False),
        available_commands=AVAILABLE_COMMANDS,
        offline_after=current_app.config["PROBE_OFFLINE_AFTER_SEC"],
    )


@bp.post("/<int:probe_id>/token")
@role_required(ROLE_TENANT_ADMIN)
def regenerate_token(probe_id: int):
    """Emette un nuovo token: usato per re-registrare una sonda reinstallata."""
    tenant_id = current_tenant_id()
    probe = _load_probe(probe_id, tenant_id)
    execute(
        "UPDATE probes SET status = 'pending', enrolled_at = NULL, session_key = NULL,"
        " api_key_hash = NULL, probe_public_key = NULL, server_private_key = NULL,"
        " server_public_key = NULL, revoked_at = NULL, updated_at = ? WHERE id = ?",
        (utc_now_str(), probe_id),
    )
    token = _issue_token(probe_id, probe["code"])
    log_event(
        "probe.token.reissued",
        "Nuovo token di registrazione per la sonda %s" % probe["code"],
        severity="warning",
        entity="probe",
        entity_id=probe_id,
    )
    return render_template(
        "probes/credentials.html",
        probe=_load_probe(probe_id, tenant_id),
        token=token,
        bundle=_enrollment_bundle(probe["code"], token),
        server_url=_public_base_url(),
    )


@bp.post("/<int:probe_id>/config")
@role_required(ROLE_TENANT_ADMIN)
def update_config(probe_id: int):
    """Aggiorna la configurazione e accoda il comando di ricarica."""
    tenant_id = current_tenant_id()
    probe = _load_probe(probe_id, tenant_id)

    try:
        interval = max(30, min(86400, int(request.form.get("scan_interval_sec") or 300)))
    except ValueError:
        flash("Intervallo di raccolta non valido.", "warning")
        return redirect(url_for("probes.detail", probe_id=probe_id))

    raw_options = (request.form.get("options_json") or "{}").strip() or "{}"
    try:
        options = json.loads(raw_options)
        if not isinstance(options, dict):
            raise ValueError("l'oggetto di configurazione deve essere un dizionario")
    except (json.JSONDecodeError, ValueError) as exc:
        flash("Configurazione JSON non valida: %s" % exc, "danger")
        return redirect(url_for("probes.detail", probe_id=probe_id))

    execute(
        "UPDATE probes SET scan_interval_sec = ?, name = ?, description = ?, site = ?,"
        " config_json = ?, updated_at = ? WHERE id = ? AND tenant_id = ?",
        (
            interval,
            (request.form.get("name") or probe["name"]).strip(),
            (request.form.get("description") or "").strip() or None,
            (request.form.get("site") or "").strip() or None,
            json.dumps(options, separators=(",", ":")),
            utc_now_str(),
            probe_id,
            tenant_id,
        ),
    )
    _enqueue_command(tenant_id, probe_id, "reconfigure", {})
    log_event(
        "probe.config.updated",
        "Configurazione della sonda %s aggiornata" % probe["code"],
        entity="probe",
        entity_id=probe_id,
    )
    flash("Configurazione salvata: sara' applicata al prossimo contatto della sonda.", "success")
    return redirect(url_for("probes.detail", probe_id=probe_id))


@bp.post("/<int:probe_id>/command")
@role_required(ROLE_ANALYST)
def send_command(probe_id: int):
    tenant_id = current_tenant_id()
    probe = _load_probe(probe_id, tenant_id)
    command = (request.form.get("command") or "").strip()
    if command not in AVAILABLE_COMMANDS:
        flash("Comando non riconosciuto.", "warning")
        return redirect(url_for("probes.detail", probe_id=probe_id))
    if probe["status"] == "pending":
        flash("La sonda non e' ancora registrata: comando non accodabile.", "warning")
        return redirect(url_for("probes.detail", probe_id=probe_id))

    _enqueue_command(tenant_id, probe_id, command, {})
    log_event(
        "probe.command",
        "Comando '%s' accodato per la sonda %s" % (command, probe["code"]),
        entity="probe",
        entity_id=probe_id,
    )
    flash("Comando accodato: verra' consegnato al prossimo contatto della sonda.", "success")
    return redirect(url_for("probes.detail", probe_id=probe_id))


@bp.post("/<int:probe_id>/effort")
@role_required(ROLE_ANALYST)
def set_effort(probe_id: int):
    """Imposta il profilo di sforzo della sonda."""
    tenant_id = current_tenant_id()
    probe = _load_probe(probe_id, tenant_id)
    valore = (request.form.get("effort") or "").strip().lower()
    if valore not in SCAN_EFFORTS:
        flash("Profilo di sforzo non riconosciuto: ammessi %s." % ", ".join(SCAN_EFFORTS),
              "warning")
        return redirect(url_for("probes.detail", probe_id=probe_id))

    execute("UPDATE probes SET scan_effort = ?, updated_at = ? WHERE id = ? AND tenant_id = ?",
            (valore, utc_now_str(), probe_id, tenant_id))
    log_event("probe.scan.effort",
              "Profilo di sforzo della sonda %s portato a %s" % (probe["code"], valore),
              tenant_id=tenant_id, entity="probe", entity_id=probe_id)
    flash("Profilo di sforzo della sonda %s: %s. La sonda lo recepisce al prossimo contatto."
          % (probe["code"], valore), "success")
    return redirect(url_for("probes.detail", probe_id=probe_id))


@bp.post("/<int:probe_id>/discovery-days")
@role_required(ROLE_ANALYST)
def set_discovery_days(probe_id: int):
    """Imposta ogni quanti giorni la scoperta ricensisce il perimetro."""
    tenant_id = current_tenant_id()
    probe = _load_probe(probe_id, tenant_id)
    try:
        giorni = int((request.form.get("days") or "").strip())
    except ValueError:
        giorni = None
    if giorni is None or not DISCOVERY_DAYS_MIN <= giorni <= DISCOVERY_DAYS_MAX:
        flash("Cadenza della scoperta non valida: indicare un numero di giorni fra %d e %d."
              % (DISCOVERY_DAYS_MIN, DISCOVERY_DAYS_MAX), "warning")
        return redirect(url_for("probes.detail", probe_id=probe_id))

    execute("UPDATE probes SET scan_discovery_days = ?, updated_at = ?"
            " WHERE id = ? AND tenant_id = ?",
            (giorni, utc_now_str(), probe_id, tenant_id))
    log_event("probe.scan.discovery_days",
              "Cadenza della scoperta della sonda %s: ogni %d giorni" % (probe["code"], giorni),
              tenant_id=tenant_id, entity="probe", entity_id=probe_id)
    flash("La sonda %s ricensira' il perimetro ogni %d giorni. Il valore e' recepito al "
          "prossimo contatto." % (probe["code"], giorni), "success")
    return redirect(url_for("probes.detail", probe_id=probe_id))


@bp.post("/<int:probe_id>/host-timeout")
@role_required(ROLE_ANALYST)
def set_host_timeout(probe_id: int):
    """Imposta il tempo massimo per host, o lo riporta a quello del profilo."""
    tenant_id = current_tenant_id()
    probe = _load_probe(probe_id, tenant_id)
    valore = (request.form.get("host_timeout") or "").strip()
    if valore and valore not in HOST_TIMEOUTS:
        flash("Tempo massimo per host non ammesso: valori possibili %s, oppure vuoto per "
              "quello del profilo di sforzo." % ", ".join(HOST_TIMEOUTS), "warning")
        return redirect(url_for("probes.detail", probe_id=probe_id))

    execute("UPDATE probes SET scan_host_timeout = ?, updated_at = ?"
            " WHERE id = ? AND tenant_id = ?",
            (valore or None, utc_now_str(), probe_id, tenant_id))
    log_event("probe.scan.host_timeout",
              "Tempo massimo per host della sonda %s: %s"
              % (probe["code"], valore or "quello del profilo di sforzo"),
              tenant_id=tenant_id, entity="probe", entity_id=probe_id)
    flash("Tempo massimo per host della sonda %s: %s. La sonda lo recepisce al prossimo "
          "contatto." % (probe["code"], valore or "quello del profilo di sforzo"), "success")
    return redirect(url_for("probes.detail", probe_id=probe_id))


@bp.post("/<int:probe_id>/scanning")
@role_required(ROLE_ANALYST)
def toggle_scanning(probe_id: int):
    """Abilita o disabilita le scansioni di una sonda.

    L'interruttore viaggia nella configurazione cifrata: la sonda lo recepisce al
    contatto successivo e non puo' aggirarlo.
    """
    tenant_id = current_tenant_id()
    probe = _load_probe(probe_id, tenant_id)
    try:
        attuale = int(probe["scan_enabled"])
    except (KeyError, IndexError, TypeError, ValueError):
        attuale = 1
    nuovo = 0 if attuale else 1
    execute("UPDATE probes SET scan_enabled = ?, updated_at = ? WHERE id = ? AND tenant_id = ?",
            (nuovo, utc_now_str(), probe_id, tenant_id))
    log_event(
        "probe.scan.enabled" if nuovo else "probe.scan.disabled",
        "Scansioni %s per la sonda %s" % ("abilitate" if nuovo else "disabilitate", probe["code"]),
        tenant_id=tenant_id, severity="info" if nuovo else "warning",
        entity="probe", entity_id=probe_id,
    )
    flash("Scansioni %s per la sonda %s: la sonda lo recepisce al prossimo contatto."
          % ("abilitate" if nuovo else "disabilitate", probe["code"]),
          "success" if nuovo else "warning")
    return redirect(url_for("probes.detail", probe_id=probe_id))


@bp.post("/<int:probe_id>/revoke")
@role_required(ROLE_TENANT_ADMIN)
def revoke(probe_id: int):
    """Revoca le credenziali: la sonda non potra' piu' conferire dati."""
    tenant_id = current_tenant_id()
    probe = _load_probe(probe_id, tenant_id)
    execute(
        "UPDATE probes SET revoked_at = ?, status = 'revoked', session_key = NULL,"
        " api_key_hash = NULL, updated_at = ? WHERE id = ? AND tenant_id = ?",
        (utc_now_str(), utc_now_str(), probe_id, tenant_id),
    )
    log_event(
        "probe.revoked",
        "Sonda %s revocata" % probe["code"],
        severity="critical",
        entity="probe",
        entity_id=probe_id,
    )
    flash("Sonda revocata.", "warning")
    return redirect(url_for("probes.detail", probe_id=probe_id))


@bp.post("/<int:probe_id>/delete")
@role_required(ROLE_TENANT_ADMIN)
def delete(probe_id: int):
    tenant_id = current_tenant_id()
    probe = _load_probe(probe_id, tenant_id)
    execute("DELETE FROM probes WHERE id = ? AND tenant_id = ?", (probe_id, tenant_id))
    log_event(
        "probe.deleted",
        "Sonda %s eliminata" % probe["code"],
        severity="critical",
        entity="probe",
        entity_id=probe_id,
    )
    flash("Sonda eliminata.", "info")
    return redirect(url_for("probes.index"))


def _enqueue_command(tenant_id: int, probe_id: int, command: str, payload: dict) -> int:
    from flask import g

    user = getattr(g, "user", None)
    return execute(
        "INSERT INTO probe_commands (tenant_id, probe_id, command, payload_json, status,"
        " created_by, created_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)",
        (
            tenant_id,
            probe_id,
            command,
            json.dumps(payload, separators=(",", ":")),
            int(user["id"]) if user is not None else None,
            utc_now_str(),
        ),
    )
