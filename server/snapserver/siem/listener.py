# -----------------------------------------------------------------
# listener.py — ascolto syslog integrato: il SIEM senza container
# Autore: Daniele Speziale
# Data creazione: 2026-09-02
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Ricezione del syslog dentro il processo del server.

E' l'alternativa al container Vector per chi non ha Docker: due socket (UDP e TCP)
sulla porta del syslog raccolgono le righe, le bufferizzano e le consegnano alla
stessa pipeline di ingestione a piccoli lotti. E' piu' lento di Vector -- un thread
Python invece di un motore in Rust -- ma non aggiunge dipendenze e regge senza
problemi il syslog di una rete di dimensioni medie.

Attribuzione al tenant: su un server dedicato a un solo tenant (il caso tipico di
snap) il tenant e' quello unico. Con piu' tenant l'ascolto integrato non puo'
distinguere da quale rete arriva un pacchetto UDP, quindi si usa il container per
tenant; qui, in caso di ambiguita', si rifiuta di indovinare e lo si dichiara nel
diario. Gli eventi vengono attribuiti a un collettore di servizio "listener
integrato", creato una volta.
"""

from __future__ import annotations

import socket
import threading

from ..db import query, utc_now_str
from . import SYSLOG_PORT
from . import ingest

_thread: threading.Thread | None = None
_stop = threading.Event()
_BUF_MAX = 500
_FLUSH_SECONDS = 2.0


def _tenant_unico() -> int | None:
    """L'unico tenant attivo, se e' uno solo. Con piu' tenant l'ascolto integrato
    non sa attribuire e non deve indovinare."""
    righe = query("SELECT id FROM tenants WHERE is_active = 1", ())
    return int(righe[0]["id"]) if len(righe) == 1 else None


def _collettore_di_servizio(tenant_id: int) -> dict | None:
    """Il collettore 'listener integrato' del tenant, creato una volta sola."""
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


def start_listener(app) -> None:
    """Avvia l'ascolto syslog integrato, se richiesto e non gia' attivo."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return
    porta = int(app.config.get("SIEM_LISTENER_PORT", SYSLOG_PORT))
    indirizzo = app.config.get("SIEM_LISTENER_HOST", "0.0.0.0")

    def raccogli():
        try:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            udp.bind((indirizzo, porta))
            udp.settimeout(_FLUSH_SECONDS)
        except OSError as errore:
            app.logger.warning("Ascolto syslog integrato non avviato (porta %d): %s",
                               porta, errore)
            return
        app.logger.info("Ascolto syslog SIEM integrato avviato su %s:%d (UDP)",
                        indirizzo, porta)
        buffer: list = []
        while not _stop.is_set():
            try:
                dati, mittente = udp.recvfrom(65535)
                riga = dati.decode("utf-8", "replace").strip()
                if riga:
                    buffer.append({"message": riga, "src_ip": mittente[0]})
            except socket.timeout:
                pass
            except OSError:
                break
            # Si consegna a ogni scadenza del timeout (ogni ~2 s) o quando il buffer
            # e' pieno: un compromesso fra latenza e numero di transazioni.
            if buffer:
                _consegna(app, buffer)
                buffer = []
        udp.close()

    _thread = threading.Thread(target=raccogli, name="snap-siem-listener", daemon=True)
    _thread.start()


def _consegna(app, righe: list) -> None:
    """Consegna un lotto alla pipeline, dentro un contesto applicativo."""
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
                ingest.ingest_batch(collettore, righe)
    except Exception as errore:  # l'ascolto non deve cadere per un lotto
        app.logger.warning("Ascolto syslog integrato: lotto non elaborato: %s", errore)


def stop_listener() -> None:
    _stop.set()
