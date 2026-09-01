"""
snap probe - Factory dell'applicativo sonda.

L'interfaccia locale copre soltanto registrazione, configurazione e diagnostica;
la funzione della sonda (raccolta e conferimento) e' svolta dall'agente in un
thread dedicato, indipendente dall'interfaccia.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import logging
from pathlib import Path

from flask import Flask, render_template

from .settings import Config


def _apri_diario(app) -> None:
    """Diario su file in aggiunta a quello a schermo, se la configurazione lo indica.

    Stessa scelta del server: la finestra mostra cosa accade, il file lo conserva.
    Un file non apribile non impedisce l'avvio della sonda, ma viene dichiarato.
    """
    percorso = (app.config.get("LOG_FILE") or "").strip()
    if not percorso:
        return

    radice = logging.getLogger()
    atteso = str(Path(percorso).resolve())
    for gestore in radice.handlers:
        if isinstance(gestore, logging.FileHandler) and gestore.baseFilename == atteso:
            return

    try:
        Path(percorso).parent.mkdir(parents=True, exist_ok=True)
        gestore = logging.FileHandler(percorso, encoding="utf-8")
    except OSError as errore:
        radice.warning("Diario su file non disponibile (%s): %s", percorso, errore)
        return

    gestore.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    radice.addHandler(gestore)


def create_app(config_object=Config, start_agent: bool | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_object)

    logging.basicConfig(
        level=logging.DEBUG if app.config.get("DEBUG") else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    _apri_diario(app)

    from .agent import ProbeAgent
    from .store import ProbeStore

    store = ProbeStore(app.config["STORE_PATH"])
    store.set_setting("agent_version", app.config["APP_VERSION"])
    if not store.get_setting("scan_interval_sec"):
        store.set_setting("scan_interval_sec", app.config["DEFAULT_SCAN_INTERVAL"])
    if not store.get_setting("paused"):
        store.set_setting("paused", "0")

    agent = ProbeAgent(
        store,
        agent_version=app.config["APP_VERSION"],
        tick_seconds=app.config["AGENT_TICK_SECONDS"],
    )
    app.extensions["snap_store"] = store
    app.extensions["snap_agent"] = agent

    from flask_wtf.csrf import CSRFError, CSRFProtect

    CSRFProtect(app)

    @app.errorhandler(CSRFError)
    def _csrf_error(error):
        # Come sul server: un token scaduto non deve chiudere la strada, si
        # torna alla pagina di provenienza con un avviso e un token nuovo.
        from urllib.parse import urlparse

        from flask import flash, redirect, request, url_for

        app.logger.warning("Richiesta rifiutata per token non valido: %s", error.description)
        flash(
            "La pagina era aperta da troppo tempo e il token di sicurezza e' scaduto:"
            " nessuna modifica applicata, ripetere l'operazione.",
            "warning",
        )

        referrer = request.referrer
        if referrer:
            parsed = urlparse(referrer)
            if (not parsed.netloc or parsed.netloc == request.host) and parsed.path.startswith("/"):
                return redirect(parsed.path), 303
        return redirect(url_for("probe.index")), 303

    from .timefmt import register_template_filters

    register_template_filters(app, store)

    from .auth import bp as auth_bp
    from .views import bp as views_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(views_bp)

    # La guardia si installa DOPO le rotte: protegge tutto cio' che e' registrato,
    # e cio' che verra' registrato in futuro, tranne l'elenco dichiarato in auth.py.
    from .auth import registra_guardia

    registra_guardia(app)

    @app.context_processor
    def _inject_globals() -> dict:
        from .auth import autenticato, password_impostata

        return {
            "app_name": app.config["APP_NAME"],
            "app_version": app.config["APP_VERSION"],
            "app_subtitle": app.config["APP_SUBTITLE"],
            "settings": store.all_settings(),
            "agent_status": agent.status(),
            "accesso_aperto": autenticato(),
            "password_impostata": password_impostata(),
        }

    @app.errorhandler(404)
    def _not_found(_error):
        return render_template(
            "error.html", code=404, title="Pagina non trovata",
            message="La risorsa richiesta non esiste nell'interfaccia della sonda.",
        ), 404

    @app.errorhandler(500)
    def _server_error(_error):
        app.logger.exception("Errore interno della sonda")
        return render_template(
            "error.html", code=500, title="Errore interno",
            message="Si e' verificato un errore inatteso: consultare il diario locale.",
        ), 500

    should_start = (
        app.config.get("AUTOSTART_AGENT", True) if start_agent is None else start_agent
    )
    if should_start:
        agent.start()

    return app
