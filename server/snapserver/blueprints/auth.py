"""
snap server - Autenticazione, secondo fattore, profilo e preferenze di interfaccia.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re

from flask import (
    Blueprint,
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
from ..db import execute, query, utc_now_str
from ..security import (
    generate_mfa_secret,
    hash_password,
    is_locked,
    login_required,
    login_user,
    logout_user,
    mfa_provisioning_uri,
    mfa_qr_data_uri,
    password_policy_errors,
    register_failed_login,
    verify_password,
    verify_totp,
)
from ..tenancy import switch_tenant

bp = Blueprint("auth", __name__)

VALID_THEMES = {"light", "dark"}
VALID_FONT_SIZES = {"small", "normal", "large", "xlarge"}
VALID_LAYOUTS = {"narrow", "wide"}


def _safe_next(target: str | None) -> str:
    """Evita redirect verso host esterni (open redirect)."""
    if not target or not target.startswith("/") or target.startswith("//"):
        return url_for("dashboard.index")
    return target


@bp.route("/login", methods=["GET", "POST"])
def login():
    if getattr(g, "user", None) is not None and session.get("mfa_ok"):
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        user = query("SELECT * FROM users WHERE lower(email) = ?", (email,), one=True)

        if user is None or not verify_password(user["password_hash"], password):
            if user is not None:
                locked = register_failed_login(user)
                log_event(
                    "auth.login.failed",
                    "Credenziali errate per %s%s" % (email, " - utenza bloccata" if locked else ""),
                    tenant_id=user["tenant_id"],
                    severity="warning",
                    entity="user",
                    entity_id=user["id"],
                    actor=email,
                )
            else:
                log_event(
                    "auth.login.unknown",
                    "Tentativo di accesso con email non censita: %s" % email,
                    severity="warning",
                    actor=email,
                )
            flash("Credenziali non valide.", "danger")
            return render_template("auth/login.html", email=email), 401

        if not int(user["is_active"] or 0):
            flash("Utenza disattivata: contattare l'amministratore.", "warning")
            return render_template("auth/login.html", email=email), 403

        if is_locked(user):
            flash("Utenza temporaneamente bloccata per troppi tentativi falliti.", "warning")
            return render_template("auth/login.html", email=email), 403

        if user["tenant_id"] is not None:
            tenant = query(
                "SELECT is_active FROM tenants WHERE id = ?", (user["tenant_id"],), one=True
            )
            if tenant is None or not int(tenant["is_active"] or 0):
                flash("Il tenant associato all'utenza non e' attivo.", "warning")
                return render_template("auth/login.html", email=email), 403

        login_user(user)
        if int(user["mfa_enabled"] or 0):
            session["pending_user_email"] = user["email"]
            return redirect(url_for("auth.mfa_challenge", next=request.form.get("next")))

        # g.user non e' ancora popolato (lo fa before_request): l'attore va
        # dichiarato esplicitamente, altrimenti l'evento risulta di sistema.
        log_event(
            "auth.login",
            "Accesso effettuato",
            tenant_id=user["tenant_id"],
            entity="user",
            entity_id=user["id"],
            actor=user["email"],
        )
        return redirect(_safe_next(request.form.get("next")))

    return render_template("auth/login.html", email="")


@bp.route("/mfa", methods=["GET", "POST"])
def mfa_challenge():
    """Verifica del secondo fattore per una sessione autenticata ma non completa."""
    if getattr(g, "user", None) is None:
        return redirect(url_for("auth.login"))
    if session.get("mfa_ok"):
        return redirect(url_for("dashboard.index"))

    user = g.user
    if request.method == "POST":
        code = request.form.get("code") or ""
        if verify_totp(user["mfa_secret"] or "", code):
            session["mfa_ok"] = True
            session.pop("pending_user_email", None)
            log_event(
                "auth.mfa.ok",
                "Secondo fattore verificato",
                tenant_id=user["tenant_id"],
                entity="user",
                entity_id=user["id"],
                actor=user["email"],
            )
            return redirect(_safe_next(request.form.get("next")))
        log_event(
            "auth.mfa.failed",
            "Codice MFA non valido",
            tenant_id=user["tenant_id"],
            severity="warning",
            entity="user",
            entity_id=user["id"],
        )
        flash("Codice di verifica non valido.", "danger")

    return render_template("auth/mfa.html")


@bp.post("/logout")
def logout():
    user = getattr(g, "user", None)
    if user is not None:
        log_event(
            "auth.logout",
            "Uscita dalla sessione",
            tenant_id=user["tenant_id"],
            entity="user",
            entity_id=user["id"],
        )
    logout_user()
    flash("Sessione terminata.", "info")
    return redirect(url_for("auth.login"))


@bp.post("/switch-tenant")
@login_required
def switch_tenant_route():
    """Commutazione del contesto tenant (solo amministratore di sistema)."""
    try:
        tenant_id = int(request.form.get("tenant_id") or 0)
    except ValueError:
        tenant_id = 0

    if tenant_id and switch_tenant(tenant_id):
        log_event(
            "tenant.switch",
            "Contesto tenant commutato",
            tenant_id=tenant_id,
            entity="tenant",
            entity_id=tenant_id,
        )
        flash("Contesto tenant aggiornato.", "success")
    else:
        flash("Cambio tenant non consentito.", "danger")
    return redirect(request.referrer or url_for("dashboard.index"))


# --------------------------------------------------------------------------- #
# Profilo utente
# --------------------------------------------------------------------------- #
@bp.get("/diagnostics/session")
def session_diagnostics():
    """Diagnostica dell'accesso: dichiara se il cookie di sessione arriva.

    Non espone dati riservati: serve a distinguere un problema di credenziali da
    un cookie scartato dal browser (contesto incorporato, blocco dei cookie,
    accesso alternato a nomi host differenti).
    """
    received = current_app.config["SESSION_COOKIE_NAME"] in request.cookies
    authenticated = session.get("user_id") is not None

    if received and authenticated:
        suggerimento = (
            "Cookie ricevuto e sessione valida: la richiesta ripetuta delle"
            " credenziali non dipende dal trasporto della sessione."
        )
    elif received:
        suggerimento = (
            "Cookie ricevuto ma senza utente: la sessione e' scaduta oppure la"
            " chiave di firma del server e' stata rigenerata. Eseguire di nuovo"
            " l'accesso; se il modulo segnala un token scaduto, ricaricare la"
            " pagina con Ctrl+Maiusc+R."
        )
    else:
        suggerimento = (
            "Nessun cookie di sessione nella richiesta. E' normale se l'accesso"
            " non e' ancora stato effettuato. Se invece accade durante la"
            " navigazione: mantenere sempre lo stesso nome host (127.0.0.1"
            " oppure localhost), verificare il blocco dei cookie o le estensioni"
            " del browser e, con la console aperta in una cornice (browser"
            " integrato nell'editor), avviare il server con"
            " SNAP_SERVER_EMBEDDED=1 oppure usare un browser esterno."
        )

    return {
        "cookie_ricevuto": received,
        "sessione_con_utente": authenticated,
        "secondo_fattore_superato": bool(session.get("mfa_ok", False)),
        "host_richiesto": request.host,
        "nome_cookie": current_app.config["SESSION_COOKIE_NAME"],
        "samesite_configurato": current_app.config.get("SESSION_COOKIE_SAMESITE"),
        "cookie_solo_https": current_app.config.get("SESSION_COOKIE_SECURE"),
        "durata_sessione_minuti": int(
            current_app.config["PERMANENT_SESSION_LIFETIME"].total_seconds() // 60
        ),
        "suggerimento": suggerimento,
    }


@bp.get("/profile")
@login_required
def profile():
    return render_template("auth/profile.html")


@bp.post("/profile/password")
@login_required
def change_password():
    current = request.form.get("current_password") or ""
    new_password = request.form.get("new_password") or ""
    confirm = request.form.get("confirm_password") or ""

    if not verify_password(g.user["password_hash"], current):
        flash("La password attuale non e' corretta.", "danger")
        return redirect(url_for("auth.profile"))
    if new_password != confirm:
        flash("Le due password non coincidono.", "danger")
        return redirect(url_for("auth.profile"))

    errors = password_policy_errors(new_password)
    if errors:
        for error in errors:
            flash(error, "warning")
        return redirect(url_for("auth.profile"))

    execute(
        "UPDATE users SET password_hash = ?, must_change_pwd = 0, updated_at = ? WHERE id = ?",
        (hash_password(new_password), utc_now_str(), int(g.user["id"])),
    )
    log_event(
        "user.password.changed",
        "Password aggiornata dall'utente",
        tenant_id=g.user["tenant_id"],
        entity="user",
        entity_id=g.user["id"],
    )
    flash("Password aggiornata.", "success")
    return redirect(url_for("auth.profile"))


# Un identificativo di chat Telegram e' un intero: positivo per una chat personale,
# eventualmente negativo per un gruppo. Si accetta con una allowlist, non si indovina.
_TELEGRAM_CHAT = re.compile(r"^-?\d{5,15}$")


@bp.post("/profile/telegram")
@login_required
def save_telegram():
    """Salva (o cancella) l'identificativo Telegram personale dell'utente."""
    grezzo = (request.form.get("telegram_chat_id") or "").strip()
    if grezzo and not _TELEGRAM_CHAT.match(grezzo):
        flash("L'ID Telegram deve essere un numero (es. 123456789). Per trovarlo,"
              " scrivi /start al bot @userinfobot su Telegram.", "warning")
        return redirect(url_for("auth.profile"))
    execute("UPDATE users SET telegram_chat_id = ?, updated_at = ? WHERE id = ?",
            (grezzo or None, utc_now_str(), int(g.user["id"])))
    log_event("user.telegram.updated",
              "ID Telegram personale %s" % ("impostato" if grezzo else "rimosso"),
              tenant_id=g.user["tenant_id"], entity="user", entity_id=g.user["id"])
    flash("Notifiche personali via Telegram %s."
          % ("attivate" if grezzo else "disattivate"), "success")
    return redirect(url_for("auth.profile"))


@bp.post("/profile/telegram/test")
@login_required
def test_telegram():
    """Invia un messaggio di prova alla chat Telegram personale dell'utente.

    Serve a verificare, dalla pagina, che l'ID sia giusto e che l'utente abbia gia'
    avviato una conversazione con il bot (Telegram non consente al bot di scrivere per
    primo a chi non lo ha mai contattato)."""
    from ..channels import ChannelError, is_telegram_configured, send_telegram, telegram_config

    chat_id = (g.user["telegram_chat_id"] or "").strip() if g.user["telegram_chat_id"] else ""
    if not chat_id:
        flash("Prima salva il tuo ID Telegram, poi invia la prova.", "warning")
        return redirect(url_for("auth.profile"))
    configurazione = telegram_config()
    if not is_telegram_configured(configurazione) or not configurazione["enabled"]:
        flash("Il bot Telegram del sistema non e' configurato o e' disattivato:"
              " la prova non puo' partire. Rivolgiti a un amministratore.", "warning")
        return redirect(url_for("auth.profile"))
    try:
        send_telegram(configurazione, chat_id,
                      "snap: messaggio di prova. Se lo leggi, le notifiche personali"
                      " sono configurate correttamente.")
    except ChannelError as errore:
        flash("Invio non riuscito: %s Se non hai mai scritto al bot, aprilo su"
              " Telegram e premi Avvia, poi riprova." % errore, "danger")
        return redirect(url_for("auth.profile"))
    flash("Messaggio di prova inviato: controlla Telegram.", "success")
    return redirect(url_for("auth.profile"))


@bp.get("/profile/mfa/setup")
@login_required
def mfa_setup():
    """Genera (o riusa) il segreto TOTP e mostra il QR per Google Authenticator."""
    secret = session.get("mfa_setup_secret")
    if not secret:
        secret = generate_mfa_secret()
        session["mfa_setup_secret"] = secret

    issuer = "%s - %s" % (
        current_app.config["APP_NAME"],
        g.tenant["code"] if getattr(g, "tenant", None) else "system",
    )
    return render_template(
        "auth/mfa_setup.html",
        secret=secret,
        qr_data_uri=mfa_qr_data_uri(secret, g.user["email"], issuer),
        provisioning_uri=mfa_provisioning_uri(secret, g.user["email"], issuer),
    )


@bp.post("/profile/mfa/enable")
@login_required
def mfa_enable():
    secret = session.get("mfa_setup_secret")
    code = request.form.get("code") or ""
    if not secret:
        flash("Sessione di configurazione MFA scaduta: ripetere la procedura.", "warning")
        return redirect(url_for("auth.mfa_setup"))
    if not verify_totp(secret, code):
        flash("Codice non valido: verificare l'orologio del dispositivo.", "danger")
        return redirect(url_for("auth.mfa_setup"))

    execute(
        "UPDATE users SET mfa_enabled = 1, mfa_secret = ?, mfa_confirmed_at = ?,"
        " updated_at = ? WHERE id = ?",
        (secret, utc_now_str(), utc_now_str(), int(g.user["id"])),
    )
    session.pop("mfa_setup_secret", None)
    session["mfa_ok"] = True
    log_event(
        "user.mfa.enabled",
        "Secondo fattore attivato",
        tenant_id=g.user["tenant_id"],
        entity="user",
        entity_id=g.user["id"],
    )
    flash("Autenticazione a due fattori attivata.", "success")
    return redirect(url_for("auth.profile"))


@bp.post("/profile/mfa/disable")
@login_required
def mfa_disable():
    """La disattivazione richiede un codice valido: evita disabilitazioni indebite."""
    code = request.form.get("code") or ""
    if not verify_totp(g.user["mfa_secret"] or "", code):
        flash("Codice non valido: MFA non disattivata.", "danger")
        return redirect(url_for("auth.profile"))

    execute(
        "UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, mfa_confirmed_at = NULL,"
        " updated_at = ? WHERE id = ?",
        (utc_now_str(), int(g.user["id"])),
    )
    log_event(
        "user.mfa.disabled",
        "Secondo fattore disattivato",
        tenant_id=g.user["tenant_id"],
        severity="warning",
        entity="user",
        entity_id=g.user["id"],
    )
    flash("Autenticazione a due fattori disattivata.", "warning")
    return redirect(url_for("auth.profile"))


@bp.post("/preferences/indicatori")
@login_required
def kpi_preferences():
    """Indicatori che l'utente non vuole vedere sulla dashboard.

    La scelta e' PERSONALE e persistente: sta sull'utente, non nella sessione e non
    nel browser. Chi nasconde un indicatore lo fa perche' non gli serve nel proprio
    lavoro, e quel giudizio non deve valere per i colleghi ne' scadere al prossimo
    accesso.

    Si conservano le chiavi NASCOSTE e non quelle visibili: cosi' un indicatore
    aggiunto da una versione successiva compare a tutti, che e' il verso giusto --
    un indicatore nuovo che nessuno vede perche' non era nel proprio elenco sarebbe
    un lavoro fatto e mai mostrato.
    """
    from ..queries import kpi_keys

    ammesse = kpi_keys()
    if request.form.get("azione") == "mostra_tutti":
        nascoste = []
    else:
        richieste = request.form.getlist("nascosti") or []
        singola = (request.form.get("nascondi") or "").strip()
        if singola:
            # Chiusura di un singolo indicatore dalla sua crocetta: si aggiunge a
            # quelli gia' nascosti invece di sostituirli.
            richieste = list(_kpi_nascosti(g.user)) + [singola]
        # Allowlist: una chiave che non appartiene a nessun indicatore non entra.
        # Senza questo, il campo diventerebbe un deposito di testo arbitrario.
        nascoste = sorted({c.strip() for c in richieste if c.strip() in ammesse})

    execute("UPDATE users SET pref_kpi_hidden = ?, updated_at = ? WHERE id = ?",
            (",".join(nascoste), utc_now_str(), int(g.user["id"])))

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return {"ok": True, "nascosti": nascoste}
    if nascoste:
        flash("Indicatori nascosti: %d. Si riattivano da *Indicatori da mostrare*."
              % len(nascoste), "info")
    else:
        flash("Tutti gli indicatori sono di nuovo visibili.", "success")
    return redirect(request.referrer or url_for("dashboard.index"))


def _kpi_nascosti(utente) -> tuple:
    """Chiavi nascoste dell'utente, come tupla."""
    grezzo = ""
    if utente is not None and "pref_kpi_hidden" in utente.keys():
        grezzo = utente["pref_kpi_hidden"] or ""
    return tuple(c for c in (v.strip() for v in grezzo.split(",")) if c)


@bp.post("/preferences")
@login_required
def preferences():
    """Salva tema, dimensione carattere e larghezza pagina dell'utente."""
    theme = request.form.get("theme") or g.user["pref_theme"]
    font_size = request.form.get("font_size") or g.user["pref_font_size"]
    layout = request.form.get("layout") or g.user["pref_layout"]

    if theme not in VALID_THEMES or font_size not in VALID_FONT_SIZES or layout not in VALID_LAYOUTS:
        flash("Preferenza di interfaccia non riconosciuta.", "warning")
        return redirect(request.referrer or url_for("dashboard.index"))

    execute(
        "UPDATE users SET pref_theme = ?, pref_font_size = ?, pref_layout = ?,"
        " updated_at = ? WHERE id = ?",
        (theme, font_size, layout, utc_now_str(), int(g.user["id"])),
    )
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return {"ok": True, "theme": theme, "font_size": font_size, "layout": layout}
    return redirect(request.referrer or url_for("dashboard.index"))
