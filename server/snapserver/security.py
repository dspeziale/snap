"""
snap server - Autenticazione, autorizzazione e MFA.

Modello di accesso:
  * identificazione con la sola email (nessuno username), password con hash
    PBKDF2 (Werkzeug);
  * secondo fattore opzionale TOTP compatibile con Google Authenticator;
  * ruoli gerarchici: superadmin > tenant_admin > analyst > viewer;
  * il superadmin non appartiene a nessun tenant e puo' commutare il contesto
    di tenant; ogni altro utente e' vincolato al proprio tenant.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import base64
import io
from functools import wraps

import pyotp
import qrcode
from flask import current_app, flash, g, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from .db import execute, query, utc_now, utc_now_str

ROLE_SUPERADMIN = "superadmin"
ROLE_TENANT_ADMIN = "tenant_admin"
ROLE_ANALYST = "analyst"
# Operatore SIEM: figura specializzata sul SIEM e sugli incidenti. Opera il SIEM a
# pieno (stesso livello dell'analista, cosi' le azioni gia' protette da
# `role_required(ROLE_ANALYST)` -- sorgenti, regole, decisioni sugli allarmi -- valgono
# anche per lui) ma resta sotto l'amministrazione del tenant, e il menu gli mostra solo
# cio' che gli serve. Il livello e' condiviso con l'analista: e' una specializzazione,
# non un gradino gerarchico.
ROLE_SIEM_OPERATOR = "siem_operator"
ROLE_VIEWER = "viewer"

# Livelli usati per i confronti di autorizzazione.
ROLE_LEVELS = {
    ROLE_VIEWER: 10,
    ROLE_SIEM_OPERATOR: 20,
    ROLE_ANALYST: 20,
    ROLE_TENANT_ADMIN: 30,
    ROLE_SUPERADMIN: 40,
}

ROLE_LABELS = {
    ROLE_VIEWER: "Consultazione",
    ROLE_SIEM_OPERATOR: "Operatore SIEM",
    ROLE_ANALYST: "Analista",
    ROLE_TENANT_ADMIN: "Amministratore Tenant",
    ROLE_SUPERADMIN: "Amministratore di Sistema",
}

MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15


# --------------------------------------------------------------------------- #
# Password
# --------------------------------------------------------------------------- #
def hash_password(plain: str) -> str:
    return generate_password_hash(plain, method="pbkdf2:sha256:260000")


def verify_password(password_hash: str, plain: str) -> bool:
    return check_password_hash(password_hash, plain)


def password_policy_errors(password: str) -> list[str]:
    """Verifica la robustezza minima della password; lista vuota se conforme."""
    errors: list[str] = []
    if len(password) < 10:
        errors.append("La password deve contenere almeno 10 caratteri.")
    if not any(char.isupper() for char in password):
        errors.append("La password deve contenere almeno una lettera maiuscola.")
    if not any(char.islower() for char in password):
        errors.append("La password deve contenere almeno una lettera minuscola.")
    if not any(char.isdigit() for char in password):
        errors.append("La password deve contenere almeno una cifra.")
    return errors


# --------------------------------------------------------------------------- #
# MFA / TOTP
# --------------------------------------------------------------------------- #
def generate_mfa_secret() -> str:
    return pyotp.random_base32()


def mfa_provisioning_uri(secret: str, email: str, issuer: str = "snap") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def mfa_qr_data_uri(secret: str, email: str, issuer: str = "snap") -> str:
    """QR code dell'URI otpauth:// come data URI PNG, per Google Authenticator."""
    image = qrcode.make(mfa_provisioning_uri(secret, email, issuer))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return "data:image/png;base64,%s" % encoded


def verify_totp(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    # valid_window=1 tollera uno scarto di 30 secondi fra dispositivo e server.
    return pyotp.TOTP(secret).verify(code.strip().replace(" ", ""), valid_window=1)


# --------------------------------------------------------------------------- #
# Utente corrente
# --------------------------------------------------------------------------- #
def load_current_user() -> None:
    """Popola g.user a partire dalla sessione (hook before_request)."""
    user_id = session.get("user_id")
    g.user = None
    if user_id is None:
        return
    row = query("SELECT * FROM users WHERE id = ? AND is_active = 1", (user_id,), one=True)
    if row is None:
        # L'utenza in sessione non esiste piu' o e' stata disattivata: la sessione
        # viene invalidata. L'evento e' registrato perche' e' l'unico caso in cui
        # una sessione valida decade durante la navigazione.
        current_app.logger.warning(
            "Sessione invalidata: utenza %s non trovata o disattivata", user_id
        )
        session.clear()
        return
    g.user = row


def login_user(user_row, remember_mfa: bool = False) -> None:
    session.clear()
    session["user_id"] = int(user_row["id"])
    session["mfa_ok"] = bool(remember_mfa) or not int(user_row["mfa_enabled"] or 0)
    session.permanent = True
    if user_row["tenant_id"] is not None:
        session["tenant_id"] = int(user_row["tenant_id"])
    execute(
        "UPDATE users SET last_login_at = ?, failed_logins = 0, locked_until = NULL,"
        " updated_at = ? WHERE id = ?",
        (utc_now_str(), utc_now_str(), int(user_row["id"])),
    )


def logout_user() -> None:
    session.clear()


def register_failed_login(user_row) -> bool:
    """Incrementa i tentativi falliti e blocca l'utenza oltre la soglia."""
    failed = int(user_row["failed_logins"] or 0) + 1
    locked_until = None
    if failed >= MAX_FAILED_LOGINS:
        from datetime import timedelta

        locked_until = (utc_now() + timedelta(minutes=LOCKOUT_MINUTES)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    execute(
        "UPDATE users SET failed_logins = ?, locked_until = ?, updated_at = ? WHERE id = ?",
        (failed, locked_until, utc_now_str(), int(user_row["id"])),
    )
    return locked_until is not None


def is_locked(user_row) -> bool:
    from .db import parse_utc

    locked_until = parse_utc(user_row["locked_until"])
    return locked_until is not None and locked_until > utc_now()


# --------------------------------------------------------------------------- #
# Autorizzazione
# --------------------------------------------------------------------------- #
def role_level(role: str | None) -> int:
    return ROLE_LEVELS.get(role or "", 0)


def has_role(minimum: str) -> bool:
    user = getattr(g, "user", None)
    if user is None:
        return False
    return role_level(user["role"]) >= role_level(minimum)


def is_superadmin() -> bool:
    user = getattr(g, "user", None)
    return user is not None and user["role"] == ROLE_SUPERADMIN


def login_required(view):
    """Richiede una sessione autenticata e, se attivo, il secondo fattore."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        if getattr(g, "user", None) is None:
            return redirect(url_for("auth.login", next=request.full_path))
        if not session.get("mfa_ok", False):
            return redirect(url_for("auth.mfa_challenge"))
        return view(*args, **kwargs)

    return wrapper


def role_required(minimum: str):
    """Richiede un ruolo di livello almeno pari a `minimum`."""

    def decorator(view):
        @wraps(view)
        @login_required
        def wrapper(*args, **kwargs):
            if not has_role(minimum):
                current_app.logger.warning(
                    "Accesso negato a %s per l'utente %s (ruolo %s)",
                    request.path,
                    g.user["email"],
                    g.user["role"],
                )
                flash("Privilegi insufficienti per l'operazione richiesta.", "danger")
                return redirect(url_for("dashboard.index"))
            return view(*args, **kwargs)

        return wrapper

    return decorator
