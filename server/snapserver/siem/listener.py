# -----------------------------------------------------------------
# listener.py — ascolto syslog integrato (UDP e TCP): il SIEM senza container
# Autore: Daniele Speziale
# Data creazione: 2026-09-02
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Ricezione del syslog dentro il processo del server.

E' l'alternativa al container Vector per chi non ha Docker: si ascolta il syslog
degli apparati sia in **UDP** sia in **TCP** (molti apparati inviano in TCP, e su
UDP i messaggi lunghi si perdono), lo si mette in una coda condivisa e un unico
scodatore lo consegna a piccoli lotti alla stessa pipeline di ingestione.

Robustezza: ricevitori e scodatore sono thread separati e nessun errore isolato li
ferma; una connessione TCP che cade non tocca le altre; la coda ha un tetto, cosi'
una raffica non consuma memoria senza limite.

Attribuzione al tenant: su un server dedicato a un solo tenant (il caso tipico di
snap) il tenant e' quello unico. Con piu' tenant l'ascolto integrato non puo'
distinguere da quale rete arriva un pacchetto, quindi si usa il container per
tenant; qui, in caso di ambiguita', si rifiuta di indovinare e lo si dichiara nel
diario. Gli eventi vengono attribuiti a un collettore di servizio "listener
integrato", creato una volta.
"""

from __future__ import annotations

import queue
import socket
import threading

from ..db import query, utc_now_str
from . import SYSLOG_PORT
from . import ingest

_stop = threading.Event()
_threads: list[threading.Thread] = []
# Coda condivisa fra i ricevitori (UDP/TCP) e lo scodatore. Il tetto protegge la
# memoria: oltre il limite i messaggi piu' nuovi si scartano dichiarandolo, invece di
# gonfiare il processo. Ogni elemento e' (messaggio, indirizzo_di_provenienza).
_coda: "queue.Queue[tuple]" = queue.Queue(maxsize=50000)
_scartati = 0

_LOTTO_MAX = 500
_FLUSH_SECONDS = 2.0
_TCP_BACKLOG = 50
_RECV_BYTES = 65535


def _accoda(messaggio: str, ip: str) -> None:
    global _scartati
    testo = (messaggio or "").strip()
    if not testo:
        return
    try:
        _coda.put_nowait((testo, ip))
    except queue.Full:
        _scartati += 1


def _ricevi_udp(app, porta: int, indirizzo: str) -> None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((indirizzo, porta))
        sock.settimeout(1.0)
    except OSError as errore:
        app.logger.warning("Ascolto syslog UDP non avviato (porta %d): %s", porta, errore)
        return
    app.logger.info("Ascolto syslog SIEM integrato: UDP su %s:%d", indirizzo, porta)
    while not _stop.is_set():
        try:
            dati, mittente = sock.recvfrom(_RECV_BYTES)
            _accoda(dati.decode("utf-8", "replace"), mittente[0])
        except socket.timeout:
            continue
        except OSError:
            break
    sock.close()


def _gestisci_tcp(conn: socket.socket, ip: str) -> None:
    """Legge da una connessione TCP il syslog delimitato da fine riga.

    Il syslog su TCP separa i messaggi con un a-capo (framing "non trasparente",
    il piu' diffuso): si accumula fino all'a-capo e si accoda ogni riga.
    """
    conn.settimeout(30.0)
    resto = b""
    try:
        while not _stop.is_set():
            try:
                blocco = conn.recv(_RECV_BYTES)
            except socket.timeout:
                continue
            if not blocco:
                break  # l'apparato ha chiuso
            resto += blocco
            while b"\n" in resto:
                riga, resto = resto.split(b"\n", 1)
                _accoda(riga.decode("utf-8", "replace"), ip)
    except OSError:
        pass
    finally:
        # Un'ultima riga senza a-capo finale non va persa.
        if resto.strip():
            _accoda(resto.decode("utf-8", "replace"), ip)
        try:
            conn.close()
        except OSError:
            pass


def _ricevi_tcp(app, porta: int, indirizzo: str) -> None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((indirizzo, porta))
        sock.listen(_TCP_BACKLOG)
        sock.settimeout(1.0)
    except OSError as errore:
        app.logger.warning("Ascolto syslog TCP non avviato (porta %d): %s", porta, errore)
        return
    app.logger.info("Ascolto syslog SIEM integrato: TCP su %s:%d", indirizzo, porta)
    while not _stop.is_set():
        try:
            conn, mittente = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        # Una connessione per thread: un apparato lento non blocca gli altri.
        t = threading.Thread(target=_gestisci_tcp, args=(conn, mittente[0]),
                             name="snap-siem-tcp", daemon=True)
        t.start()
    sock.close()


def _tenant_unico() -> int | None:
    righe = query("SELECT id FROM tenants WHERE is_active = 1", ())
    return int(righe[0]["id"]) if len(righe) == 1 else None


def _collettore_di_servizio(tenant_id: int) -> dict | None:
    riga = query("SELECT * FROM siem_collectors WHERE tenant_id = ? AND kind = 'listener'",
                 (tenant_id,), one=True)
    if riga:
        return dict(riga)
    from ..crypto import generate_api_key, token_fingerprint
    from ..db import execute

    adesso = utc_now_str()
    cid = execute(
        "INSERT INTO siem_collectors (tenant_id, name, kind, token_hash, created_at,"
        " updated_at) VALUES (?, 'Listener integrato', 'listener', ?, ?, ?)",
        (tenant_id, token_fingerprint(generate_api_key()), adesso, adesso))
    return dict(query("SELECT * FROM siem_collectors WHERE id = ?", (cid,), one=True))


def _scodatore(app) -> None:
    """Svuota la coda a lotti e li consegna alla pipeline di ingestione."""
    global _scartati
    while not _stop.is_set():
        righe = []
        try:
            primo = _coda.get(timeout=_FLUSH_SECONDS)
            righe.append(primo)
        except queue.Empty:
            continue
        while len(righe) < _LOTTO_MAX:
            try:
                righe.append(_coda.get_nowait())
            except queue.Empty:
                break
        _consegna(app, righe)
        if _scartati:
            app.logger.warning("Ascolto syslog: coda piena, %d messaggi scartati", _scartati)
            _scartati = 0


def _consegna(app, righe: list) -> None:
    if not righe:
        return
    try:
        with app.app_context():
            tenant_id = _tenant_unico()
            if tenant_id is None:
                app.logger.warning(
                    "Ascolto syslog integrato: piu' tenant attivi, impossibile"
                    " attribuire %d righe. Usare il container per tenant.", len(righe))
                return
            collettore = _collettore_di_servizio(tenant_id)
            if collettore:
                ingest.ingest_batch(collettore,
                                    [{"message": m, "src_ip": ip} for m, ip in righe])
    except Exception as errore:  # l'ascolto non deve cadere per un lotto
        app.logger.warning("Ascolto syslog integrato: lotto non elaborato: %s", errore)


def porte_configurate(app) -> list[int]:
    """Le porte su cui ascoltare, dalla configurazione (una o piu', separate da
    virgola). I valori non numerici o fuori range si scartano dichiarandolo."""
    grezzo = str(app.config.get("SIEM_LISTENER_PORT", SYSLOG_PORT))
    porte = []
    for pezzo in grezzo.split(","):
        pezzo = pezzo.strip()
        if not pezzo:
            continue
        try:
            numero = int(pezzo)
        except ValueError:
            app.logger.warning("Porta di ascolto syslog non valida, ignorata: %r", pezzo)
            continue
        if 1 <= numero <= 65535 and numero not in porte:
            porte.append(numero)
    return porte or [SYSLOG_PORT]


def start_listener(app) -> None:
    """Avvia l'ascolto syslog integrato (UDP + TCP su ciascuna porta), se richiesto e
    non gia' attivo."""
    global _threads
    if any(t.is_alive() for t in _threads):
        return
    _stop.clear()
    indirizzo = app.config.get("SIEM_LISTENER_HOST", "0.0.0.0")
    porte = porte_configurate(app)
    _threads = [threading.Thread(target=_scodatore, args=(app,),
                                name="snap-siem-scodatore", daemon=True)]
    for porta in porte:
        _threads.append(threading.Thread(
            target=_ricevi_udp, args=(app, porta, indirizzo),
            name="snap-siem-udp-%d" % porta, daemon=True))
        _threads.append(threading.Thread(
            target=_ricevi_tcp, args=(app, porta, indirizzo),
            name="snap-siem-tcp-%d" % porta, daemon=True))
    for t in _threads:
        t.start()
    app.logger.info("Ascolto syslog SIEM integrato avviato su %s, porte %s (UDP e TCP)",
                    indirizzo, ", ".join(str(p) for p in porte))


def stop_listener() -> None:
    _stop.set()
