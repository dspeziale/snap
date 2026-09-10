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

import logging
import os
import secrets
from datetime import timedelta
from ipaddress import IPv4Network, IPv6Network, ip_network
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


def _networks(name: str) -> tuple[IPv4Network | IPv6Network, ...]:
    """Elenco di indirizzi o reti (separati da virgola) letto dall'ambiente.

    Si accetta SOLO cio' che e' un indirizzo o una rete valida (allowlist): una voce
    malformata viene scartata con un avviso, non interpretata alla meglio. Un singolo
    indirizzo diventa una rete /32 (o /128), cosi' il confronto e' uno solo.
    """
    raw = os.environ.get(name, "")
    reti = []
    for voce in raw.split(","):
        voce = voce.strip()
        if not voce:
            continue
        try:
            reti.append(ip_network(voce, strict=False))
        except ValueError:
            logging.getLogger("snapprobe").warning(
                "%s: voce ignorata perche' non e' un indirizzo o una rete valida", name)
    return tuple(reti)


def _existing_file(name: str) -> str:
    """Percorso di un file che deve esistere ed essere leggibile.

    Se e' indicato ma non si trova, si avvisa e si restituisce vuoto: si torna cioe'
    alla verifica con gli archivi di sistema, che fallira'. E' il verso giusto in cui
    sbagliare -- un percorso errato non deve tradursi in "nessuna verifica".
    """
    percorso = (os.environ.get(name) or "").strip()
    if not percorso:
        return ""
    if not Path(percorso).is_file():
        logging.getLogger("snapprobe").warning(
            "%s: il file indicato non esiste, la verifica TLS usera' gli archivi di"
            " sistema", name)
        return ""
    return percorso


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
    # Versione del PRODOTTO, la stessa della console: un solo numero per la coppia
    # server+sonda (prima la sonda aveva una numerazione propria e l'immagine di
    # distribuzione un'altra, e in assistenza non si capiva quale contasse).
    APP_VERSION = "1.3.1"
    APP_SUBTITLE = "Sonda di raccolta - canale cifrato SNAP-SEC/1"
    # Vedi la nota omonima nel server: distingue le due interfacce, che ora hanno la
    # stessa struttura. Un solo valore per il marchio e per il piede.
    APP_COMPONENT = "probe"

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
    # Cookie solo su canale cifrato: si accende dove il TLS c'e' davvero (in esercizio,
    # dietro il reverse proxy). Predefinito spento perche' in sviluppo l'interfaccia
    # gira in chiaro su 127.0.0.1 e un cookie "Secure" non verrebbe mai inviato --
    # l'accesso risulterebbe impossibile senza dire perche'.
    SESSION_COOKIE_SECURE = _bool("SNAP_PROBE_COOKIE_SECURE", False)

    # Dietro un reverse proxy che termina il TLS (esercizio in container). Qui non e'
    # solo una questione di redirezioni: la sonda concede la PRIMA impostazione della
    # password solo a chi arriva dall'indirizzo locale, e quel controllo legge
    # l'indirizzo del client. Senza fidarsi di X-Forwarded-For vedrebbe sempre il
    # proxy, e nessuno potrebbe scegliere la password.
    BEHIND_PROXY = _bool("SNAP_PROBE_BEHIND_PROXY", False)
    SESSION_REFRESH_EACH_REQUEST = False

    # Indirizzi, OLTRE al loopback, ammessi alla prima impostazione della password.
    # Serve quando l'interfaccia si apre puntando l'IP della macchina e non
    # 127.0.0.1: in quel caso l'indirizzo del client non e' il loopback e la
    # barriera scatterebbe. Vuoto per impostazione predefinita: chi installa la
    # sonda deve dichiarare da dove intende configurarla, non ereditare un permesso.
    FIRST_ACCESS_FROM = _networks("SNAP_PROBE_FIRST_ACCESS_FROM")

    # Cadenza del ciclo dell'agente: quanto spesso valuta raccolta e conferimento.
    AGENT_TICK_SECONDS = _int("SNAP_PROBE_TICK_SECONDS", 15)
    # Intervallo di raccolta iniziale, poi imposto dal server alla registrazione.
    DEFAULT_SCAN_INTERVAL = _int("SNAP_PROBE_SCAN_INTERVAL", 300)
    HTTP_TIMEOUT = _int("SNAP_PROBE_HTTP_TIMEOUT", 15)

    # Ancora di fiducia per il canale verso il server: file PEM con il certificato
    # della CA che ha firmato quello del server -- oppure il certificato stesso del
    # server, se autofirmato.
    #
    # Serve perche' il certificato di un server interno non e' firmato da una CA
    # pubblica: senza questo file la verifica TLS della sonda fallisce (ed e' giusto
    # che fallisca -- il canale porta le chiavi della registrazione). Indicare qui il
    # certificato del server e' PIU' forte della fiducia in una CA pubblica: si
    # accetta quel certificato e nessun altro.
    #
    # Non esiste un interruttore per disattivare la verifica: su questo canale
    # significherebbe accettare qualunque interlocutore si metta in mezzo.
    SERVER_CA = _existing_file("SNAP_PROBE_SERVER_CA")


class TestConfig(Config):
    """Configurazione per i test (archivio temporaneo, agente non avviato)."""

    TESTING = True
    WTF_CSRF_ENABLED = False
    SECRET_KEY = "test-secret-key"
    AUTOSTART_AGENT = False
