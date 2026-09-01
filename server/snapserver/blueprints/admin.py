"""
snap server - Amministrazione: tenant, utenti, impostazioni di sistema, manutenzione.

Isolamento: la gestione dei tenant e' riservata all'amministratore di sistema;
la gestione degli utenti e' consentita all'amministratore del tenant ma solo
sul proprio perimetro. Ogni operazione e' tracciata nel registro di audit.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re
import secrets
from zoneinfo import available_timezones

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from ..audit import log_event
from ..db import days_ago_str, execute, query, scalar, utc_now_str
from ..security import (
    ROLE_ANALYST,
    ROLE_LABELS,
    ROLE_SUPERADMIN,
    ROLE_TENANT_ADMIN,
    ROLE_VIEWER,
    hash_password,
    is_superadmin,
    password_policy_errors,
    role_required,
)
from ..tenancy import current_tenant_id, require_tenant_access

bp = Blueprint("admin", __name__, url_prefix="/admin")

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.IGNORECASE)
TENANT_CODE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")
ASSIGNABLE_ROLES = [ROLE_VIEWER, ROLE_ANALYST, ROLE_TENANT_ADMIN]


def _timezones() -> list[str]:
    """Elenco fusi orari validi, con i piu' usati in testa."""
    preferred = ["Europe/Rome", "Europe/London", "UTC", "America/New_York", "Asia/Tokyo"]
    everything = sorted(available_timezones())
    return preferred + [zone for zone in everything if zone not in preferred]


# --------------------------------------------------------------------------- #
# Tenant
# --------------------------------------------------------------------------- #
@bp.get("/tenants")
@role_required(ROLE_SUPERADMIN)
def tenants():
    rows = query(
        "SELECT t.*,"
        " (SELECT COUNT(*) FROM users u WHERE u.tenant_id = t.id) AS user_count,"
        " (SELECT COUNT(*) FROM probes p WHERE p.tenant_id = t.id) AS probe_count,"
        " (SELECT COUNT(*) FROM ingest_batches b WHERE b.tenant_id = t.id) AS batch_count,"
        " (SELECT COUNT(*) FROM audit_events e WHERE e.tenant_id = t.id) AS event_count"
        " FROM tenants t ORDER BY t.name COLLATE NOCASE"
    )
    return render_template("admin/tenants.html", tenants=rows, timezones=_timezones())


@bp.post("/tenants")
@role_required(ROLE_SUPERADMIN)
def create_tenant():
    code = (request.form.get("code") or "").strip().lower()
    name = (request.form.get("name") or "").strip()
    timezone_name = (request.form.get("timezone") or "Europe/Rome").strip()

    if not TENANT_CODE_PATTERN.match(code):
        flash("Codice tenant non valido (2-32 caratteri, minuscoli).", "warning")
        return redirect(url_for("admin.tenants"))
    if not name:
        flash("Indicare la ragione sociale del tenant.", "warning")
        return redirect(url_for("admin.tenants"))
    if timezone_name not in available_timezones():
        flash("Fuso orario non riconosciuto.", "warning")
        return redirect(url_for("admin.tenants"))
    if query("SELECT id FROM tenants WHERE code = ?", (code,), one=True) is not None:
        flash("Codice tenant gia' in uso.", "danger")
        return redirect(url_for("admin.tenants"))

    try:
        retention = max(30, min(3650, int(request.form.get("retention_days") or 365)))
    except ValueError:
        retention = 365

    now = utc_now_str()
    tenant_id = execute(
        "INSERT INTO tenants (code, name, timezone, locale, contact_email, retention_days,"
        " is_active, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
        (
            code,
            name,
            timezone_name,
            (request.form.get("locale") or "it_IT").strip(),
            (request.form.get("contact_email") or "").strip() or None,
            retention,
            (request.form.get("notes") or "").strip() or None,
            now,
            now,
        ),
    )
    # Le zone di rete sono un dato del tenant: un tenant nuovo deve trovare il
    # proprio contesto gia' dichiarato, non un elenco vuoto (docs/12).
    from ..zone_admin import semina_se_serve

    semina_se_serve(tenant_id)

    log_event(
        "tenant.created",
        "Tenant %s (%s) creato" % (name, code),
        tenant_id=tenant_id,
        entity="tenant",
        entity_id=tenant_id,
    )
    flash("Tenant creato, con le zone di rete predefinite.", "success")
    return redirect(url_for("admin.tenants"))


@bp.post("/tenants/<int:tenant_id>/update")
@role_required(ROLE_SUPERADMIN)
def update_tenant(tenant_id: int):
    tenant = query("SELECT * FROM tenants WHERE id = ?", (tenant_id,), one=True)
    if tenant is None:
        abort(404)

    timezone_name = (request.form.get("timezone") or tenant["timezone"]).strip()
    if timezone_name not in available_timezones():
        flash("Fuso orario non riconosciuto.", "warning")
        return redirect(url_for("admin.tenants"))

    try:
        retention = max(30, min(3650, int(request.form.get("retention_days") or tenant["retention_days"])))
    except ValueError:
        retention = int(tenant["retention_days"])

    execute(
        "UPDATE tenants SET name = ?, timezone = ?, locale = ?, contact_email = ?,"
        " retention_days = ?, is_active = ?, notes = ?, updated_at = ? WHERE id = ?",
        (
            (request.form.get("name") or tenant["name"]).strip(),
            timezone_name,
            (request.form.get("locale") or tenant["locale"]).strip(),
            (request.form.get("contact_email") or "").strip() or None,
            retention,
            1 if request.form.get("is_active") else 0,
            (request.form.get("notes") or "").strip() or None,
            utc_now_str(),
            tenant_id,
        ),
    )
    log_event(
        "tenant.updated",
        "Tenant %s aggiornato (fuso orario %s)" % (tenant["code"], timezone_name),
        tenant_id=tenant_id,
        entity="tenant",
        entity_id=tenant_id,
    )
    flash("Tenant aggiornato.", "success")
    return redirect(url_for("admin.tenants"))


@bp.post("/tenants/<int:tenant_id>/delete")
@role_required(ROLE_SUPERADMIN)
def delete_tenant(tenant_id: int):
    """Eliminazione definitiva: richiede la digitazione del codice come conferma."""
    tenant = query("SELECT * FROM tenants WHERE id = ?", (tenant_id,), one=True)
    if tenant is None:
        abort(404)
    if (request.form.get("confirm_code") or "").strip().lower() != tenant["code"]:
        flash(
            "Per eliminare il tenant digitare esattamente il suo codice: %s."
            " Nessuna modifica effettuata." % tenant["code"],
            "warning",
        )
        return redirect(url_for("admin.tenants"))

    execute("DELETE FROM tenants WHERE id = ?", (tenant_id,))

    # Se il tenant eliminato era quello in uso, il contesto operativo va
    # abbandonato: alla richiesta successiva ne viene scelto un altro.
    if session.get("tenant_id") == tenant_id:
        session.pop("tenant_id", None)
    log_event(
        "tenant.deleted",
        "Tenant %s (%s) eliminato con tutti i dati associati" % (tenant["name"], tenant["code"]),
        severity="critical",
        entity="tenant",
        entity_id=tenant_id,
        global_event=True,
    )
    flash("Tenant e dati associati eliminati.", "info")
    return redirect(url_for("admin.tenants"))


# --------------------------------------------------------------------------- #
# Utenti
# --------------------------------------------------------------------------- #
@bp.get("/users")
@role_required(ROLE_TENANT_ADMIN)
def users():
    tenant_id = current_tenant_id()
    rows = query(
        "SELECT u.*, t.code AS tenant_code FROM users u"
        " LEFT JOIN tenants t ON t.id = u.tenant_id"
        " WHERE u.tenant_id = ? ORDER BY u.email",
        (tenant_id,),
    )
    system_users = []
    if is_superadmin():
        system_users = query(
            "SELECT * FROM users WHERE tenant_id IS NULL ORDER BY email"
        )
    return render_template(
        "admin/users.html",
        users=rows,
        system_users=system_users,
        roles=ASSIGNABLE_ROLES,
        role_labels=ROLE_LABELS,
    )


@bp.post("/users")
@role_required(ROLE_TENANT_ADMIN)
def create_user():
    tenant_id = current_tenant_id()
    email = (request.form.get("email") or "").strip().lower()
    role = (request.form.get("role") or ROLE_VIEWER).strip()
    password = request.form.get("password") or ""

    if not EMAIL_PATTERN.match(email):
        flash("Indirizzo email non valido.", "warning")
        return redirect(url_for("admin.users"))
    if role not in ASSIGNABLE_ROLES:
        flash("Ruolo non assegnabile.", "warning")
        return redirect(url_for("admin.users"))
    if query("SELECT id FROM users WHERE lower(email) = ?", (email,), one=True) is not None:
        flash("Email gia' presente a sistema.", "danger")
        return redirect(url_for("admin.users"))

    if not password:
        password = secrets.token_urlsafe(9) + "A1"
        generated = True
    else:
        generated = False
        errors = password_policy_errors(password)
        if errors:
            for error in errors:
                flash(error, "warning")
            return redirect(url_for("admin.users"))

    now = utc_now_str()
    user_id = execute(
        "INSERT INTO users (tenant_id, email, password_hash, full_name, role, is_active,"
        " must_change_pwd, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, 1, ?, ?)",
        (
            tenant_id,
            email,
            hash_password(password),
            (request.form.get("full_name") or "").strip(),
            role,
            now,
            now,
        ),
    )
    log_event(
        "user.created",
        "Utente %s creato con ruolo %s" % (email, role),
        entity="user",
        entity_id=user_id,
    )
    # La password provvisoria va a chi dovra' usarla, non a chi crea l'utente: una
    # credenziale comunicata a mano finisce in chat, che e' il posto peggiore in cui
    # possa stare. Se la posta non parte, la password torna a schermo con la ragione:
    # una credenziale che nessuno riceve e nessuno vede e' un utente inutilizzabile.
    from ..notifications import _setting, invia_credenziali

    esito = invia_credenziali(
        email, password, nome=(request.form.get("full_name") or "").strip(),
        ruolo=ROLE_LABELS.get(role, role), tenant_id=tenant_id,
        console_url=_setting("public_url", ""))

    if esito["inviata"]:
        flash("Utente creato: le credenziali provvisorie sono state spedite a %s."
              % email, "success")
    elif generated:
        flash("Utente creato, ma le credenziali NON sono state spedite (%s)."
              " Password provvisoria da comunicare: %s" % (esito["motivo"], password),
              "warning")
    else:
        flash("Utente creato. Credenziali non spedite (%s): la password e' quella"
              " che hai indicato." % esito["motivo"], "info")
    return redirect(url_for("admin.users"))


def _load_manageable_user(user_id: int):
    user = query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if user is None:
        abort(404)
    if user["tenant_id"] is None:
        # Gli account di sistema sono modificabili solo dal superadmin.
        if not is_superadmin():
            abort(403)
    else:
        require_tenant_access(int(user["tenant_id"]))
    return user


@bp.post("/users/<int:user_id>/update")
@role_required(ROLE_TENANT_ADMIN)
def update_user(user_id: int):
    user = _load_manageable_user(user_id)
    role = (request.form.get("role") or user["role"]).strip()

    if user["role"] == ROLE_SUPERADMIN:
        role = ROLE_SUPERADMIN  # il ruolo di sistema non e' declassabile dall'interfaccia
    elif role not in ASSIGNABLE_ROLES:
        flash("Ruolo non assegnabile.", "warning")
        return redirect(url_for("admin.users"))

    is_active = 1 if request.form.get("is_active") else 0
    if int(user["id"]) == int(g.user["id"]) and not is_active:
        flash("Non e' possibile disattivare la propria utenza.", "warning")
        return redirect(url_for("admin.users"))

    execute(
        "UPDATE users SET full_name = ?, role = ?, is_active = ?, updated_at = ? WHERE id = ?",
        (
            (request.form.get("full_name") or user["full_name"]).strip(),
            role,
            is_active,
            utc_now_str(),
            user_id,
        ),
    )
    log_event(
        "user.updated",
        "Utente %s aggiornato (ruolo %s, attivo %d)" % (user["email"], role, is_active),
        tenant_id=user["tenant_id"],
        entity="user",
        entity_id=user_id,
    )
    flash("Utente aggiornato.", "success")
    return redirect(url_for("admin.users"))


@bp.post("/users/<int:user_id>/password")
@role_required(ROLE_TENANT_ADMIN)
def reset_password(user_id: int):
    user = _load_manageable_user(user_id)
    password = secrets.token_urlsafe(9) + "A1"
    execute(
        "UPDATE users SET password_hash = ?, must_change_pwd = 1, failed_logins = 0,"
        " locked_until = NULL, updated_at = ? WHERE id = ?",
        (hash_password(password), utc_now_str(), user_id),
    )
    log_event(
        "user.password.reset",
        "Password reimpostata per %s" % user["email"],
        tenant_id=user["tenant_id"],
        severity="warning",
        entity="user",
        entity_id=user_id,
    )
    flash("Password provvisoria per %s: %s" % (user["email"], password), "info")
    return redirect(url_for("admin.users"))


@bp.post("/users/<int:user_id>/mfa-reset")
@role_required(ROLE_TENANT_ADMIN)
def reset_mfa(user_id: int):
    """Azzera il secondo fattore (dispositivo smarrito)."""
    user = _load_manageable_user(user_id)
    execute(
        "UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, mfa_confirmed_at = NULL,"
        " updated_at = ? WHERE id = ?",
        (utc_now_str(), user_id),
    )
    log_event(
        "user.mfa.reset",
        "MFA azzerata per %s" % user["email"],
        tenant_id=user["tenant_id"],
        severity="warning",
        entity="user",
        entity_id=user_id,
    )
    flash("Secondo fattore azzerato: l'utente dovra' riconfigurarlo.", "warning")
    return redirect(url_for("admin.users"))


@bp.post("/users/<int:user_id>/delete")
@role_required(ROLE_TENANT_ADMIN)
def delete_user(user_id: int):
    user = _load_manageable_user(user_id)
    if int(user["id"]) == int(g.user["id"]):
        flash("Non e' possibile eliminare la propria utenza.", "warning")
        return redirect(url_for("admin.users"))

    execute("DELETE FROM users WHERE id = ?", (user_id,))
    log_event(
        "user.deleted",
        "Utente %s eliminato" % user["email"],
        tenant_id=user["tenant_id"],
        severity="warning",
        entity="user",
        entity_id=user_id,
    )
    flash("Utente eliminato.", "info")
    return redirect(url_for("admin.users"))


# --------------------------------------------------------------------------- #
# Impostazioni e manutenzione
# --------------------------------------------------------------------------- #
def _setting(key: str, default: str = "") -> str:
    row = query("SELECT value FROM system_settings WHERE key = ?", (key,), one=True)
    return str(row["value"]) if row else default


@bp.get("/settings")
@role_required(ROLE_TENANT_ADMIN)
def settings():
    tenant_id = current_tenant_id()
    stats = {
        "probes": scalar("SELECT COUNT(*) FROM probes WHERE tenant_id = ?", (tenant_id,)),
        "users": scalar("SELECT COUNT(*) FROM users WHERE tenant_id = ?", (tenant_id,)),
        "batches": scalar("SELECT COUNT(*) FROM ingest_batches WHERE tenant_id = ?", (tenant_id,)),
        "records": scalar(
            "SELECT COALESCE(SUM(record_count), 0) FROM ingest_batches WHERE tenant_id = ?",
            (tenant_id,),
        ),
        "commands": scalar(
            "SELECT COUNT(*) FROM probe_commands WHERE tenant_id = ?", (tenant_id,)
        ),
        "audit": scalar("SELECT COUNT(*) FROM audit_events WHERE tenant_id = ?", (tenant_id,)),
    }
    from ..channels import (
        available_channels,
        is_telegram_configured,
        masked_token,
        telegram_config,
    )
    from ..maintenance import (
        RETENTION_TYPES,
        database_size,
        disk_free,
        list_backups,
        retention_plan,
    )
    from ..notifications import NOTIFY_EVENTS, enabled_events, is_configured, smtp_config
    from ..reports.daily import settings as impostazioni_resoconto

    posta = smtp_config()
    telegram = telegram_config()
    return render_template(
        "admin/settings.html",
        # Manutenzione dell'archivio: dimensione, conservazione, copie. La dimensione
        # e' la domanda che si pone prima di qualunque altra: senza, la conservazione
        # e' una politica senza conseguenze visibili.
        database=database_size(),
        retention=retention_plan(),
        retention_types=RETENTION_TYPES,
        backups=list_backups(),
        disk=disk_free(),
        telegram=telegram,
        telegram_configured=is_telegram_configured(telegram),
        telegram_token_masked=masked_token(telegram["token"]),
        channels=available_channels(),
        report_settings=impostazioni_resoconto(),
        public_url=_setting("public_url", request.host_url.rstrip("/")),
        smtp=posta,
        smtp_configured=is_configured(posta),
        # Se la password e' impostata lo si dice, ma non la si mostra: un campo
        # precompilato con una password e' una password esposta.
        smtp_password_set=bool(_setting("smtp_password")),
        notify_events=NOTIFY_EVENTS,
        notify_enabled=enabled_events(),
        timezones=_timezones(),
        stats=stats,
        config={
            "database": current_app.config["DATABASE"],
            "enrollment_ttl": current_app.config["ENROLLMENT_TTL_HOURS"],
            "offline_after": current_app.config["PROBE_OFFLINE_AFTER_SEC"],
            "version": current_app.config["APP_VERSION"],
        },
    )


@bp.post("/settings")
@role_required(ROLE_SUPERADMIN)
def save_settings():
    public_url = (request.form.get("public_url") or "").strip().rstrip("/")
    if public_url and not public_url.startswith(("http://", "https://")):
        flash("L'URL pubblico deve iniziare con http:// oppure https://", "warning")
        return redirect(url_for("admin.settings"))

    execute(
        "INSERT INTO system_settings (key, value, updated_at) VALUES ('public_url', ?, ?)"
        " ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (public_url, utc_now_str()),
    )
    log_event("settings.updated", "URL pubblico impostato a '%s'" % public_url)
    flash("Impostazioni salvate.", "success")
    return redirect(url_for("admin.settings"))


SMTP_KEYS = ("smtp_host", "smtp_port", "smtp_security", "smtp_username",
             "smtp_sender", "smtp_sender_name")


def _save_setting(key: str, value: str) -> None:
    execute(
        "INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)"
        " ON CONFLICT(key) DO UPDATE SET value = excluded.value,"
        " updated_at = excluded.updated_at",
        (key, value, utc_now_str()),
    )


@bp.post("/settings/notifications")
@role_required(ROLE_TENANT_ADMIN)
def save_notification_settings():
    """Configurazione della posta e scelta dei momenti da notificare."""
    from ..notifications import NOTIFY_EVENTS

    sicurezza = (request.form.get("smtp_security") or "none").strip().lower()
    if sicurezza not in ("none", "starttls", "ssl"):
        flash("Modalita' di sicurezza della posta non prevista.", "warning")
        return redirect(url_for("admin.settings"))

    porta = (request.form.get("smtp_port") or "25").strip()
    if not porta.isdigit() or not 1 <= int(porta) <= 65535:
        flash("La porta del server di posta deve essere un numero fra 1 e 65535.",
              "warning")
        return redirect(url_for("admin.settings"))

    for chiave in SMTP_KEYS:
        if chiave == "smtp_security":
            _save_setting(chiave, sicurezza)
        elif chiave == "smtp_port":
            _save_setting(chiave, porta)
        else:
            _save_setting(chiave, (request.form.get(chiave) or "").strip())

    # La password si sostituisce solo se ne viene indicata una nuova: un campo
    # lasciato vuoto significa "non cambiarla", non "cancellala".
    nuova = request.form.get("smtp_password") or ""
    if nuova:
        _save_setting("smtp_password", nuova)
    if request.form.get("smtp_password_clear"):
        _save_setting("smtp_password", "")

    _save_setting("notifications_enabled",
                  "1" if request.form.get("notifications_enabled") else "0")
    scelti = [e for e in request.form.getlist("notify_events") if e in NOTIFY_EVENTS]
    _save_setting("notify_events", ",".join(scelti))

    log_event("settings.notifications",
              "Configurazione delle notifiche aggiornata (%d momenti attivi)"
              % len(scelti))
    flash("Configurazione delle notifiche salvata.", "success")
    return redirect(url_for("admin.settings"))


@bp.post("/settings/notifications/test")
@role_required(ROLE_TENANT_ADMIN)
def test_notification():
    """Invia un messaggio di prova all'indirizzo indicato.

    L'invio e' immediato e non passa dalla coda: si vuole sapere subito se la
    configurazione funziona, e l'errore del server di posta va mostrato per esteso --
    "non funziona" non aiuta nessuno a capire cosa sistemare.
    """
    import smtplib
    import ssl as ssl_module

    from ..notifications import is_configured, send_now, smtp_config

    destinatario = (request.form.get("recipient") or "").strip()
    if not destinatario:
        flash("Indicare un indirizzo a cui inviare la prova.", "warning")
        return redirect(url_for("admin.settings"))

    config = smtp_config()
    if not is_configured(config):
        flash("Posta non configurata: indicare almeno server e mittente.", "warning")
        return redirect(url_for("admin.settings"))

    try:
        send_now(config, destinatario, "[snap] messaggio di prova",
                 "Questo messaggio conferma che snap riesce a inviare le notifiche"
                 " del workflow dei controlli.\n\nServer di posta: %s:%d (%s)\n"
                 % (config["host"], config["port"], config["security"]))
    except (smtplib.SMTPException, OSError, ssl_module.SSLError) as errore:
        log_event("settings.notifications.test",
                  "Prova di invio non riuscita verso %s: %s" % (destinatario, errore),
                  severity="warning")
        flash("Prova non riuscita: %s" % errore, "danger")
        return redirect(url_for("admin.settings"))

    log_event("settings.notifications.test",
              "Prova di invio riuscita verso %s" % destinatario)
    flash("Messaggio di prova inviato a %s." % destinatario, "success")
    return redirect(url_for("admin.settings"))


@bp.post("/maintenance/retention")
@role_required(ROLE_TENANT_ADMIN)
def apply_retention():
    """Applica la politica di conservazione del tenant corrente."""
    tenant_id = current_tenant_id()
    tenant = query("SELECT * FROM tenants WHERE id = ?", (tenant_id,), one=True)
    if tenant is None:
        abort(404)

    cutoff = days_ago_str(int(tenant["retention_days"]))
    removed = {
        "audit": scalar(
            "SELECT COUNT(*) FROM audit_events WHERE tenant_id = ? AND created_at < ?",
            (tenant_id, cutoff),
        ),
        "batches": scalar(
            "SELECT COUNT(*) FROM ingest_batches WHERE tenant_id = ? AND received_at < ?",
            (tenant_id, cutoff),
        ),
    }
    execute("DELETE FROM audit_events WHERE tenant_id = ? AND created_at < ?", (tenant_id, cutoff))
    execute(
        "DELETE FROM ingest_batches WHERE tenant_id = ? AND received_at < ?", (tenant_id, cutoff)
    )

    log_event(
        "maintenance.retention",
        "Conservazione applicata (%d giorni): %s" % (int(tenant["retention_days"]), removed),
        severity="warning",
    )
    flash(
        "Conservazione applicata: %d eventi e %d conferimenti rimossi."
        % (removed["audit"], removed["batches"]),
        "info",
    )
    return redirect(url_for("admin.settings"))


# --------------------------------------------------------------------------- #
# Canale Telegram
# --------------------------------------------------------------------------- #
TELEGRAM_KEYS = ("telegram_chat_id",)


@bp.post("/settings/telegram")
@role_required(ROLE_TENANT_ADMIN)
def save_telegram_settings():
    """Configurazione del bot Telegram.

    Il token e' una credenziale: si sostituisce solo se ne viene indicato uno nuovo, e
    non viene mai rimandato alla pagina.
    """
    _save_setting("telegram_chat_id", (request.form.get("telegram_chat_id") or "").strip())
    _save_setting("telegram_enabled", "1" if request.form.get("telegram_enabled") else "0")

    nuovo = (request.form.get("telegram_bot_token") or "").strip()
    if nuovo:
        _save_setting("telegram_bot_token", nuovo)
    if request.form.get("telegram_token_clear"):
        _save_setting("telegram_bot_token", "")

    log_event("settings.telegram",
              "Canale Telegram %s"
              % ("attivato" if request.form.get("telegram_enabled") else "disattivato"),
              severity="warning", entity="settings")
    flash("Configurazione del bot Telegram salvata.", "success")
    return redirect(url_for("admin.settings"))


@bp.post("/settings/telegram/test")
@role_required(ROLE_TENANT_ADMIN)
def test_telegram():
    """Prova il canale: chiede l'identita' del bot e manda un messaggio alla chat."""
    from ..channels import ChannelError, send_telegram, telegram_config, telegram_identity

    config = telegram_config()
    try:
        identita = telegram_identity(config)
        send_telegram(config, config["chat_id"],
                      "snap: messaggio di prova del canale Telegram. Se lo leggi, il"
                      " canale funziona.")
    except ChannelError as errore:
        log_event("settings.telegram.test", "Prova del canale Telegram non riuscita: %s"
                  % errore, severity="warning", entity="settings")
        flash("Prova non riuscita: %s" % errore, "danger")
        return redirect(url_for("admin.settings"))

    log_event("settings.telegram.test",
              "Messaggio di prova recapitato al bot @%s" % (identita.get("username") or "?"),
              severity="info", entity="settings")
    flash("Messaggio di prova recapitato dal bot @%s alla chat %s."
          % (identita.get("username") or "?", config["chat_id"]), "success")
    return redirect(url_for("admin.settings"))


# --------------------------------------------------------------------------- #
# Resoconto quotidiano
# --------------------------------------------------------------------------- #
@bp.post("/settings/report")
@role_required(ROLE_TENANT_ADMIN)
def save_report_settings():
    """Ora, canali, destinatari e allegato del resoconto quotidiano."""
    from ..channels import CHANNELS
    from ..reports.daily import DEFAULT_TIME, _valid_time

    ora = (request.form.get("report_daily_time") or DEFAULT_TIME).strip()
    if not _valid_time(ora):
        flash("L'ora del resoconto va indicata come HH:MM (24 ore).", "warning")
        return redirect(url_for("admin.settings"))

    canali = [c for c in request.form.getlist("report_daily_channels") if c in CHANNELS]
    if not canali:
        flash("Indicare almeno un canale per il resoconto.", "warning")
        return redirect(url_for("admin.settings"))

    giorni = (request.form.get("report_daily_trend_days") or "7").strip()
    if not giorni.isdigit() or not 2 <= int(giorni) <= 92:
        flash("I giorni delle tendenze devono essere fra 2 e 92.", "warning")
        return redirect(url_for("admin.settings"))

    _save_setting("report_daily_enabled",
                  "1" if request.form.get("report_daily_enabled") else "0")
    _save_setting("report_daily_time", ora)
    _save_setting("report_daily_channels", ",".join(canali))
    _save_setting("report_daily_recipients",
                  (request.form.get("report_daily_recipients") or "").strip())
    _save_setting("report_daily_attach",
                  "1" if request.form.get("report_daily_attach") else "0")
    _save_setting("report_daily_trend_days", giorni)

    log_event("settings.report",
              "Resoconto quotidiano: %s alle %s su %s%s"
              % ("attivo" if request.form.get("report_daily_enabled") else "sospeso",
                 ora, ", ".join(canali),
                 ", con allegato PDF" if request.form.get("report_daily_attach") else ""),
              severity="info", entity="settings")
    flash("Configurazione del resoconto salvata.", "success")
    return redirect(url_for("admin.settings"))


# --------------------------------------------------------------------------- #
# Manutenzione dell'archivio: conservazione, dimensione, copia, ripristino
# --------------------------------------------------------------------------- #
@bp.post("/settings/retention")
@role_required(ROLE_SUPERADMIN)
def save_retention():
    """Durata di conservazione per genere di dato.

    Riservata all'amministratore di sistema: la conservazione riguarda l'archivio nel
    suo insieme, tutti i tenant compresi, ed e' una scelta con conseguenze legali
    (GDPR art. 5(1)(e), NIS2 sulla tracciabilita').
    """
    from ..maintenance import MaintenanceError, RETENTION_TYPES, save_retention as salva

    valori = {}
    for chiave, *_ in RETENTION_TYPES:
        valore = request.form.get("retention_%s" % chiave)
        if valore is not None:
            valori[chiave] = valore
    try:
        cambiati = salva(valori)
    except MaintenanceError as errore:
        flash(str(errore), "warning")
        return redirect(url_for("admin.settings"))

    flash("Conservazione salvata%s."
          % (": %s" % ", ".join(cambiati) if cambiati else " (nessuna modifica)"),
          "success")
    return redirect(url_for("admin.settings"))


@bp.post("/settings/retention/apply")
@role_required(ROLE_SUPERADMIN)
def apply_retention_plan():
    """Applica la conservazione per genere di dato. Con `simula` conta senza eliminare.

    Distinta da `apply_retention`, che applica la sola politica del tenant corrente al
    registro di audit e ai conferimenti: questa riguarda tutti i generi di dato e tutti
    i tenant, ed e' per questo riservata all'amministratore di sistema.
    """
    from ..maintenance import purge

    simulazione = bool(request.form.get("simula"))
    esito = purge(dry_run=simulazione)
    if not esito["righe"]:
        flash("Nessun dato oltre la conservazione dichiarata.", "info")
        return redirect(url_for("admin.settings"))

    dettaglio = ", ".join("%s: %d" % (v["tabella"], v["righe"]) for v in esito["voci"])
    if simulazione:
        flash("Simulazione: verrebbero eliminate %d righe (%s). Lo spazio si libera"
              " davvero solo compattando l'archivio."
              % (esito["righe"], dettaglio), "info")
    else:
        flash("Conservazione applicata: %d righe eliminate (%s). Per restituire lo"
              " spazio al disco, compattare l'archivio."
              % (esito["righe"], dettaglio), "success")
    return redirect(url_for("admin.settings"))


@bp.post("/settings/database/compact")
@role_required(ROLE_SUPERADMIN)
def compact_database():
    from ..maintenance import compact

    esito = compact()
    flash("Archivio compattato: da %.2f a %.2f MB, %.2f MB restituiti al disco."
          % (esito["prima"] / 1048576, esito["dopo"] / 1048576,
             esito["liberati"] / 1048576), "success")
    return redirect(url_for("admin.settings"))


@bp.post("/settings/backup")
@role_required(ROLE_SUPERADMIN)
def create_backup():
    """Copia completa dell'archivio, tutti i tenant compresi."""
    from ..maintenance import MaintenanceError, backup_now

    try:
        esito = backup_now(nota=(request.form.get("nota") or "").strip()[:200])
    except MaintenanceError as errore:
        flash("Copia non riuscita: %s" % errore, "danger")
        return redirect(url_for("admin.settings"))

    flash("Copia creata: %s (%.2f MB, %s tenant, %s utenti, %s nodi)%s"
          % (esito["nome"], esito["byte"] / 1048576, esito["verifica"]["tenant"],
             esito["verifica"]["utenti"], esito["verifica"]["nodi"],
             ". Rimosse %d copie piu' vecchie." % len(esito["rimosse"])
             if esito["rimosse"] else "."), "success")
    return redirect(url_for("admin.settings"))


@bp.get("/settings/backup/<nome>/download")
@role_required(ROLE_SUPERADMIN)
def download_backup(nome: str):
    """Scarica una copia. Contiene i dati di tutti i tenant: si tratta come l'archivio."""
    from flask import send_file

    from ..maintenance import MaintenanceError, backup_file

    try:
        percorso = backup_file(nome)
    except MaintenanceError as errore:
        flash(str(errore), "warning")
        return redirect(url_for("admin.settings"))

    log_event("maintenance.backup.downloaded", "Copia scaricata: %s" % percorso.name,
              severity="warning", entity="database")
    return send_file(percorso, as_attachment=True, download_name=percorso.name,
                     mimetype="application/octet-stream")


@bp.post("/settings/backup/<nome>/delete")
@role_required(ROLE_SUPERADMIN)
def remove_backup(nome: str):
    from ..maintenance import MaintenanceError, delete_backup

    try:
        eliminata = delete_backup(nome)
    except MaintenanceError as errore:
        flash(str(errore), "warning")
        return redirect(url_for("admin.settings"))
    flash("Copia eliminata: %s" % eliminata, "success")
    return redirect(url_for("admin.settings"))


@bp.post("/settings/restore")
@role_required(ROLE_SUPERADMIN)
def restore_database():
    """Ripristina l'archivio da una copia esistente o da un file caricato.

    Conferma digitata obbligatoria: e' l'operazione piu' distruttiva del prodotto, e un
    clic per errore sostituirebbe i dati di tutti i tenant. Prima del ripristino viene
    comunque salvato lo stato corrente.
    """
    from ..maintenance import (
        MaintenanceError,
        backup_file,
        restore_from,
        store_uploaded,
        verify_backup,
    )

    conferma = (request.form.get("conferma") or "").strip()
    if conferma != "RIPRISTINA":
        flash("Ripristino annullato: per procedere digitare RIPRISTINA nel campo di"
              " conferma.", "warning")
        return redirect(url_for("admin.settings"))

    documento = request.files.get("file")
    nome = (request.form.get("nome") or "").strip()
    try:
        if documento is not None and getattr(documento, "filename", ""):
            percorso = store_uploaded(documento)
        elif nome:
            percorso = backup_file(nome)
        else:
            raise MaintenanceError("Indicare una copia esistente oppure caricare un file.")

        verifica = verify_backup(percorso)
        if not verifica["valida"]:
            raise MaintenanceError(verifica["motivo"])
        if request.form.get("solo_verifica"):
            flash("Copia valida: %s tenant, %s utenti, %s nodi, %.2f MB. Nessun"
                  " ripristino eseguito."
                  % (verifica["tenant"], verifica["utenti"], verifica["nodi"],
                     verifica["byte"] / 1048576), "info")
            return redirect(url_for("admin.settings"))

        esito = restore_from(percorso)
    except MaintenanceError as errore:
        flash("Ripristino non eseguito: %s" % errore, "danger")
        return redirect(url_for("admin.settings"))

    flash("Archivio ripristinato da %s. Lo stato precedente e' nella copia %s."
          " Anche il registro delle azioni e' tornato a quello della copia: gli eventi"
          " successivi non ci sono piu'. Riavviare il servizio se qualcosa non risponde"
          " come previsto."
          % (esito["da"], esito["copia_precedente"]), "success")
    return redirect(url_for("admin.settings"))
