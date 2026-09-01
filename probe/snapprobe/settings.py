"""
snap probe - Configurazione dell'applicativo sonda (modulo interno al pacchetto).

Sovrascrivibile da variabili d'ambiente con prefisso SNAP_PROBE_.
L'interfaccia locale ascolta per impostazione predefinita solo su 127.0.0.1:
serve unicamente alla registrazione e alla configurazione della sonda.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import os
import secrets
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
INSTANCE_DIR = BASE_DIR / "instance"


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on", "si"}


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def load_secret_key() -> str:
    from_env = os.environ.get("SNAP_PROBE_SECRET_KEY")
    if from_env:
        return from_env

    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    key_file = INSTANCE_DIR / "secret_key"
    if key_file.exists():
        content = key_file.read_text(encoding="utf-8").strip()
        if content:
            return content
    generated = secrets.token_urlsafe(48)
    key_file.write_text(generated, encoding="utf-8")
    return generated


class Config:
    """Configurazione di base della sonda."""

    APP_NAME = "SNAP probe"
    APP_VERSION = "1.0.0"
    APP_SUBTITLE = "Sonda di raccolta - canale cifrato SNAP-SEC/1"

    SECRET_KEY = load_secret_key()
    STORE_PATH = os.environ.get("SNAP_PROBE_STORE", str(DATA_DIR / "snap_probe.sqlite3"))

    # Diario su file, in aggiunta a quello a schermo (vedi l'avvio assistito).
    LOG_FILE = os.environ.get("SNAP_PROBE_LOG_FILE", "")

    HOST = os.environ.get("SNAP_PROBE_HOST", "127.0.0.1")
    PORT = _int("SNAP_PROBE_PORT", 5510)
    DEBUG = _bool("SNAP_PROBE_DEBUG", False)

    # Durata della sessione dell'interfaccia. Otto ore coprono un turno: la sonda
    # si configura e si osserva, non si presidia.
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=_int("SNAP_PROBE_SESSION_MINUTES", 480))
    # Nome distinto da quello del server: i cookie non distinguono la porta e
    # le due interfacce convivono sullo stesso host.
    SESSION_COOKIE_NAME = os.environ.get("SNAP_PROBE_COOKIE_NAME", "snap_probe_session")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_REFRESH_EACH_REQUEST = False

    # Cadenza del ciclo dell'agente: quanto spesso valuta raccolta e conferimento.
    AGENT_TICK_SECONDS = _int("SNAP_PROBE_TICK_SECONDS", 15)
    # Intervallo di raccolta iniziale, poi imposto dal server alla registrazione.
    DEFAULT_SCAN_INTERVAL = _int("SNAP_PROBE_SCAN_INTERVAL", 300)
    HTTP_TIMEOUT = _int("SNAP_PROBE_HTTP_TIMEOUT", 15)


class TestConfig(Config):
    """Configurazione per i test (archivio temporaneo, agente non avviato)."""

    TESTING = True
    WTF_CSRF_ENABLED = False
    SECRET_KEY = "test-secret-key"
    AUTOSTART_AGENT = False
