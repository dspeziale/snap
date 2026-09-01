"""
snap server - Factory dell'applicazione Flask.

Il server e' il punto di raccolta: non contatta mai le sonde, si limita ad
accettare le loro connessioni cifrate. L'interfaccia web comprende dashboard,
gestione delle sonde, registro di audit e amministrazione multi-tenant.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from flask import Flask, flash, g, redirect, render_template, request, url_for

from .settings import Config


def _apri_diario(app) -> None:
    """Aggiunge un diario su file, se la configurazione ne indica uno.

    Si AGGIUNGE al diario a schermo, non lo sostituisce: chi avvia il prodotto deve
    vedere cosa accade nella propria finestra, e chi lo diagnostica il giorno dopo
    deve poterlo rileggere. Un errore nell'apertura del file non impedisce l'avvio
    del servizio -- il diario e' un aiuto, non un requisito -- ma viene dichiarato,
    perche' un diario che si crede attivo e non lo e' e' peggio della sua assenza.
    """
    percorso = (app.config.get("LOG_FILE") or "").strip()
    if not percorso:
        return

    radice = logging.getLogger()
    atteso = str(Path(percorso).resolve())
    for gestore in radice.handlers:
        if isinstance(gestore, logging.FileHandler) and gestore.baseFilename == atteso:
            return  # con il ricaricatore attivo create_app viene chiamata due volte

    try:
        Path(percorso).parent.mkdir(parents=True, exist_ok=True)
        gestore = logging.FileHandler(percorso, encoding="utf-8")
    except OSError as errore:
        radice.warning("Diario su file non disponibile (%s): %s", percorso, errore)
        return

    gestore.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    radice.addHandler(gestore)


def create_app(config_object=Config) -> Flask:
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(config_object)

    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.DEBUG if app.config.get("DEBUG") else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    _apri_diario(app)

    from . import db as db_module
    from .tenancy import register_template_filters

    db_module.init_app(app)
    register_template_filters(app)

    with app.app_context():
        db_module.init_db()

    _register_blueprints(app)

    # Spedizione delle notifiche: un thread a se', avviato solo quando serve. Nei
    # test l'avvio e' disattivato, perche' un thread che apre connessioni di posta
    # non ha nulla a che fare con una verifica.
    #
    # Con il ricaricatore automatico attivo l'applicazione viene costruita due volte:
    # nel processo che sorveglia i file e in quello che serve le richieste. Solo il
    # secondo deve spedire, altrimenti due thread pescherebbero dalla stessa coda e
    # la stessa notifica potrebbe partire due volte.
    servizio_effettivo = (not app.debug) or os.environ.get("WERKZEUG_RUN_MAIN") == "true"
    if not app.config.get("TESTING") and servizio_effettivo:
        from .acn_watch import start_watcher
        from .notifications import start_dispatcher
        from .reports.daily import start_scheduler
        from .rules import start_evaluator

        start_dispatcher(app)
        # Il resoconto quotidiano e le regole sono compito del SERVER: i due thread
        # vivono nel processo dell'applicazione e non richiedono che qualcuno sia
        # collegato. Valgono le stesse ragioni del dispatcher: uno solo per processo.
        start_scheduler(app)
        start_evaluator(app)
        # I termini dell'art. 23 NIS2 cadono di notte e di sabato: la sorveglianza
        # vive nel processo del server e non richiede che qualcuno sia collegato.
        start_watcher(app)
    _register_csrf(app)
    _register_hooks(app)
    _register_error_handlers(app)
    _register_context(app)
    return app


def _register_blueprints(app: Flask) -> None:
    from .blueprints.acn_views import bp as acn_bp
    from .blueprints.admin import bp as admin_bp
    from .blueprints.api_probe import bp as api_probe_bp
    from .blueprints.auth import bp as auth_bp
    from .blueprints.audit_views import bp as audit_bp
    from .blueprints.checks import bp as checks_bp
    from .blueprints.dashboard import bp as dashboard_bp
    from .blueprints.guide import bp as guide_bp
    from .blueprints.inventory import bp as inventory_bp
    from .blueprints.monitor import bp as monitor_bp
    from .blueprints.operations import bp as operations_bp
    from .blueprints.probes import bp as probes_bp
    from .blueprints.reports import bp as reports_bp
    from .blueprints.rules_views import bp as rules_bp
    from .blueprints.threat import bp as threat_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(probes_bp)
    app.register_blueprint(inventory_bp)
    app.register_blueprint(monitor_bp)
    app.register_blueprint(checks_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(rules_bp)
    app.register_blueprint(threat_bp)
    app.register_blueprint(operations_bp)
    app.register_blueprint(guide_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(acn_bp)
    app.register_blueprint(api_probe_bp)


def _safe_referrer() -> str | None:
    """Pagina di provenienza, solo se interna all'applicazione.

    Il valore proviene da un'intestazione controllabile dal chiamante: viene
    accettato unicamente se punta allo stesso host, per non trasformare il
    rinvio in un reindirizzamento verso l'esterno.
    """
    from urllib.parse import urlparse

    referrer = request.referrer
    if not referrer:
        return None
    parsed = urlparse(referrer)
    if parsed.netloc and parsed.netloc != request.host:
        return None
    if not parsed.path.startswith("/"):
        return None
    return parsed.path + (("?" + parsed.query) if parsed.query else "")


def _register_csrf(app: Flask) -> None:
    """Protezione CSRF sui form dell'interfaccia.

    Il canale sonde e' escluso: e' autenticato e integro per costruzione (busta
    AES-GCM con AAD e nonce anti-replay) e non usa cookie di sessione.
    """
    from flask_wtf.csrf import CSRFError, CSRFProtect

    from .blueprints.api_probe import bp as api_probe_bp

    csrf = CSRFProtect(app)
    csrf.exempt(api_probe_bp)

    @app.errorhandler(CSRFError)
    def _csrf_error(error):
        app.logger.warning("Richiesta rifiutata per token CSRF non valido: %s", error.description)

        # Il token puo' risultare scaduto per una pagina rimasta aperta o per una
        # sessione rinnovata: nessuna modifica e' stata applicata, quindi la via
        # utile e' riportare l'utente dove si trovava, con un token nuovo.
        if request.endpoint in {"auth.login", "auth.mfa_challenge"}:
            flash(
                "La pagina era aperta da troppo tempo e il token di sicurezza e'"
                " scaduto: ripetere l'inserimento delle credenziali.",
                "warning",
            )
            return redirect(url_for("auth.login")), 303

        destinazione = _safe_referrer()
        if destinazione:
            flash(
                "La pagina era aperta da troppo tempo e il token di sicurezza e'"
                " scaduto: nessuna modifica applicata, ripetere l'operazione.",
                "warning",
            )
            return redirect(destinazione), 303

        return render_template(
            "errors/error.html",
            code=400,
            title="Richiesta non valida",
            message="Il token di sicurezza del modulo e' scaduto: ricaricare la pagina.",
        ), 400


def _register_hooks(app: Flask) -> None:
    from .security import load_current_user
    from .tenancy import load_tenant_context

    @app.before_request
    def _prepare_request_context() -> None:
        # Il canale sonde non ha sessione utente; i file statici non devono
        # aprirla affatto: una pagina ne carica diversi in parallelo e ogni
        # risposta che tocca la sessione riscrive il cookie, con il rischio che
        # una risposta tardiva ne sovrascriva una piu' recente.
        if request.path.startswith("/api/v1/") or request.endpoint == "static":
            g.user = None
            g.tenant = None
            return
        load_current_user()
        load_tenant_context()

        if app.config.get("TRACE_SESSION") and not request.path.startswith("/static/"):
            from flask import session

            raw = request.cookies.get(app.config["SESSION_COOKIE_NAME"])
            app.logger.info(
                "TRACE %s %s | cookie=%s (%d byte) | sessione=%s | utente=%s | mfa_ok=%s",
                request.method,
                request.full_path,
                "presente" if raw else "ASSENTE",
                len(raw or ""),
                sorted(session.keys()) or "VUOTA",
                session.get("user_id"),
                session.get("mfa_ok"),
            )

    @app.after_request
    def _trace_response(response):
        if app.config.get("TRACE_SESSION") and not request.path.startswith("/static/"):
            emesso = [
                value for key, value in response.headers.items()
                if key.lower() == "set-cookie" and value.startswith("session=")
            ]
            if emesso:
                app.logger.info(
                    "TRACE %s -> %s | nuovo cookie emesso (%d byte)",
                    request.path,
                    response.status_code,
                    len(emesso[0]),
                )
            elif response.status_code in (301, 302, 303):
                app.logger.info(
                    "TRACE %s -> %s | rinvio a %s",
                    request.path,
                    response.status_code,
                    response.headers.get("Location"),
                )
        return response

    @app.after_request
    def _security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        frame_options = app.config.get("FRAME_OPTIONS", "DENY")
        if frame_options and frame_options.upper() != "NONE":
            response.headers.setdefault("X-Frame-Options", frame_options)
        return response


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(403)
    def _forbidden(error):
        return render_template("errors/error.html", code=403,
                               title="Accesso negato",
                               message="Non si possiedono i privilegi necessari."), 403

    @app.errorhandler(404)
    def _not_found(error):
        return render_template("errors/error.html", code=404,
                               title="Risorsa non trovata",
                               message="La pagina richiesta non esiste."), 404

    @app.errorhandler(500)
    def _server_error(error):
        app.logger.exception("Errore interno non gestito")
        return render_template("errors/error.html", code=500,
                               title="Errore interno",
                               message="Si e' verificato un errore inatteso."), 500


def _register_context(app: Flask) -> None:
    from .queries import navbar_indicators
    from .security import ROLE_LABELS, has_role, is_superadmin

    @app.context_processor
    def _inject_globals() -> dict:
        return {
            "app_name": app.config["APP_NAME"],
            "app_version": app.config["APP_VERSION"],
            "app_subtitle": app.config["APP_SUBTITLE"],
            "current_user": getattr(g, "user", None),
            "current_tenant": getattr(g, "tenant", None),
            "available_tenants": getattr(g, "available_tenants", []),
            "role_labels": ROLE_LABELS,
            "has_role": has_role,
            "is_superadmin": is_superadmin(),
            "indicators": navbar_indicators(),
        }
