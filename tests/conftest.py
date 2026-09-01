"""
snap - Configurazione comune dei test.

I due applicativi vivono in directory separate e non condividono codice: i test
li importano entrambi aggiungendo le rispettive radici al percorso di ricerca.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SERVER_DIR = ROOT / "server"
PROBE_DIR = ROOT / "probe"

for directory in (SERVER_DIR, PROBE_DIR):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))


@pytest.fixture()
def server_app(tmp_path, monkeypatch):
    """Applicazione server con database temporaneo e schema inizializzato."""
    import importlib

    monkeypatch.setenv("SNAP_SERVER_DATABASE", str(tmp_path / "server.sqlite3"))
    monkeypatch.setenv("SNAP_SERVER_REPORT_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("SNAP_SERVER_SECRET_KEY", "test-secret-key")

    import snapserver
    import snapserver.settings as server_settings

    importlib.reload(server_settings)
    importlib.reload(snapserver)

    application = snapserver.create_app(server_settings.TestConfig)
    application.config["DATABASE"] = str(tmp_path / "server.sqlite3")
    application.config["REPORT_DIR"] = str(tmp_path / "reports")

    with application.app_context():
        from snapserver.db import init_db
        from snapserver.seed import seed_initial_data

        init_db()
        seed_initial_data()

    yield application


@pytest.fixture()
def server_client(server_app):
    return server_app.test_client()


@pytest.fixture()
def logged_client(server_app):
    """Client del server autenticato come amministratore di sistema."""
    client = server_app.test_client()
    response = client.post(
        "/login",
        data={
            "email": server_app.config["BOOTSTRAP_ADMIN_EMAIL"],
            "password": server_app.config["BOOTSTRAP_ADMIN_PASSWORD"],
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    return client


@pytest.fixture()
def probe_store(tmp_path):
    """Archivio locale della sonda su file temporaneo."""
    from snapprobe.store import ProbeStore

    return ProbeStore(str(tmp_path / "probe.sqlite3"))

# --------------------------------------------------------------------------- #
# Accesso all'interfaccia della sonda
# --------------------------------------------------------------------------- #
# L'interfaccia della sonda richiede l'accesso (DEC-11). Le prove che guardano le
# pagine partono da una sessione aperta, altrimenti verificherebbero tutte la stessa
# pagina di accesso. L'aiuto sta qui e non nei singoli file perche' il preparatore
# della sonda e' duplicato in tre di essi: con la regola in un punto solo, un
# quarto file non puo' dimenticarsene.
PASSWORD_SONDA = "SondaProva2026"


def prepara_accesso_sonda(applicazione):
    """Imposta la password della sonda e apre la sessione dei client di prova.

    `applicazione.test_client()` restituisce un client gia' autenticato;
    `applicazione.test_client(anonimo=True)` uno senza sessione, per le prove che
    verificano l'accesso in se'.
    """
    with applicazione.app_context():
        from snapprobe.auth import imposta_password

        imposta_password(PASSWORD_SONDA)

    costruttore = applicazione.test_client

    def test_client(*argomenti, anonimo: bool = False, **parametri):
        client = costruttore(*argomenti, **parametri)
        if not anonimo:
            with client.session_transaction() as sessione:
                sessione["ui_autenticata"] = True
        return client

    applicazione.test_client = test_client
    return applicazione
