"""
snap server - Configurazione applicativa (modulo interno al pacchetto).

I valori possono essere sovrascritti da variabili d'ambiente con prefisso
SNAP_SERVER_ (es. SNAP_SERVER_PORT=5501). La chiave di sessione, se non
fornita, viene generata e persistita in `instance/secret_key` in modo che le
sessioni sopravvivano ai riavvii senza esporre segreti nel codice.

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
    except ValueError:  # configurazione errata: si preferisce il default noto
        return default


def load_secret_key() -> str:
    """Chiave di sessione persistente: da ambiente oppure da file di istanza."""
    from_env = os.environ.get("SNAP_SERVER_SECRET_KEY")
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
    """Configurazione di base (ambiente di esercizio)."""

    APP_NAME = "SNAP"
    APP_VERSION = "1.2.4"
    APP_SUBTITLE = "Secure Network Assessment Platform"

    SECRET_KEY = load_secret_key()
    DATABASE = os.environ.get("SNAP_SERVER_DATABASE", str(DATA_DIR / "snap_server.sqlite3"))
    # Archivio degli eventi SIEM: un file separato dal database della console, cosi'
    # un flusso di migliaia di log al minuto non contende le pagine. Vuoto significa
    # "accanto al database principale" (snap_siem.sqlite3), che e' il caso di sviluppo.
    SIEM_DATABASE = os.environ.get("SNAP_SERVER_SIEM_DATABASE", "")
    # Giorni di conservazione degli eventi SIEM. I log contengono utenze e indirizzi:
    # tenerli per sempre e' una violazione (GDPR art. 5). La purga gira col motore.
    SIEM_RETENTION_DAYS = _int("SNAP_SERVER_SIEM_RETENTION_DAYS", 90)
    # Ascolto syslog integrato: alternativa al container Vector per chi non ha Docker.
    # Spento per difetto (secure by default): si accende esplicitamente. La porta sta
    # nel range del progetto (5500-5600).
    SIEM_LISTENER = _bool("SNAP_SERVER_SIEM_LISTENER", False)
    # Una o piu' porte (separate da virgola) su cui ascoltare il syslog, in UDP e TCP.
    # Il valore predefinito 5514 sta nel range del progetto; si puo' aggiungere la 514
    # standard per gli apparati che inviano solo a quella (es. "514,5514").
    SIEM_LISTENER_PORT = os.environ.get("SNAP_SERVER_SIEM_LISTENER_PORT", "5514")
    SIEM_LISTENER_HOST = os.environ.get("SNAP_SERVER_SIEM_LISTENER_HOST", "0.0.0.0")

    # Diario su file, in aggiunta a quello a schermo. Serve all'avvio assistito:
    # la finestra mostra cio' che accade, il file lo conserva per una diagnosi a
    # posteriori. Vuoto significa "solo a schermo", che e' il caso dell'avvio
    # manuale e dei test.
    LOG_FILE = os.environ.get("SNAP_SERVER_LOG_FILE", "")

    HOST = os.environ.get("SNAP_SERVER_HOST", "127.0.0.1")
    PORT = _int("SNAP_SERVER_PORT", 5500)
    DEBUG = _bool("SNAP_SERVER_DEBUG", False)

    # Sessione
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=_int("SNAP_SERVER_SESSION_MINUTES", 120))
    # I cookie sono definiti per dominio e non distinguono la porta: server e
    # sonda convivono su 127.0.0.1 e con il nome predefinito ("session") si
    # sovrascriverebbero a vicenda, invalidando la sessione dell'altro.
    SESSION_COOKIE_NAME = os.environ.get("SNAP_SERVER_COOKIE_NAME", "snap_server_session")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = _bool("SNAP_SERVER_COOKIE_SECURE", False)
    # Il cookie viene inviato solo quando la sessione cambia: il rinnovo a ogni
    # risposta esporrebbe la sessione a sovrascritture da parte di risposte
    # concorrenti (per esempio i file statici di una stessa pagina).
    SESSION_REFRESH_EACH_REQUEST = False

    # SameSite=Lax e' il valore corretto per l'uso in un browser ordinario. I
    # browser integrati negli editor servono la pagina in un contesto
    # incorporato di origine diversa: in quel caso il cookie con Lax non viene
    # inviato e ogni pagina rimanda al modulo di accesso. Con
    # SNAP_SERVER_EMBEDDED=1 si passa a SameSite=None e si consente
    # l'inclusione in cornice.
    EMBEDDED_MODE = _bool("SNAP_SERVER_EMBEDDED", False)
    # Tracciamento diagnostico della sessione: da attivare solo per l'analisi di
    # un accesso che viene richiesto ripetutamente.
    TRACE_SESSION = _bool("SNAP_SERVER_TRACE_SESSION", False)
    SESSION_COOKIE_SAMESITE = os.environ.get(
        "SNAP_SERVER_COOKIE_SAMESITE", "None" if EMBEDDED_MODE else "Lax"
    )
    # I browser accettano SameSite=None solo su connessione sicura: la
    # combinazione va dichiarata esplicitamente da chi la usa.
    FRAME_OPTIONS = os.environ.get(
        "SNAP_SERVER_FRAME_OPTIONS", "SAMEORIGIN" if EMBEDDED_MODE else "DENY"
    )

    # Canale sonde
    ENROLLMENT_TTL_HOURS = _int("SNAP_SERVER_ENROLLMENT_TTL_HOURS", 24)
    PROBE_OFFLINE_AFTER_SEC = _int("SNAP_SERVER_PROBE_OFFLINE_AFTER_SEC", 900)
    NONCE_RETENTION_HOURS = _int("SNAP_SERVER_NONCE_RETENTION_HOURS", 24)
    MAX_CONTENT_LENGTH = _int("SNAP_SERVER_MAX_UPLOAD_MB", 32) * 1024 * 1024
    MAX_UPLOAD_MB = _int("SNAP_SERVER_MAX_UPLOAD_MB", 32)

    # Cartelle dei documenti prodotti e delle copie dell'archivio. Accanto al database
    # per difetto: stanno insieme cio' che si salva e cio' da cui si riparte.
    REPORTS_DIR = os.environ.get("SNAP_SERVER_REPORT_DIR", "")
    BACKUP_DIR = os.environ.get("SNAP_SERVER_BACKUP_DIR", "")

    # Credenziali iniziali usate dal comando `seed-db`
    BOOTSTRAP_ADMIN_EMAIL = os.environ.get("SNAP_SERVER_ADMIN_EMAIL", "admin@snap.local")
    BOOTSTRAP_ADMIN_PASSWORD = os.environ.get("SNAP_SERVER_ADMIN_PASSWORD", "Snap!Admin2026")


class TestConfig(Config):
    """Configurazione per i test automatici (database temporaneo, sessioni brevi)."""

    TESTING = True
    DEBUG = True
    WTF_CSRF_ENABLED = False
    SECRET_KEY = "test-secret-key"
