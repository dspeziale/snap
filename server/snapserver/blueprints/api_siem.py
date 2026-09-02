"""
snap server - Canale di ingestione dei log per il SIEM.

Il collettore (il container Vector, o il listener syslog integrato) consegna qui i
log a lotti, autenticandosi con un token di sola scrittura (nell'intestazione
Authorization: Bearer, oppure X-Snap-Collector). Il token e' conservato solo come
impronta: non si puo' rileggere, si rigenera.

Il canale e' distinto da quello delle sonde (che e' cifrato punto-punto): qui
l'integrita' e la riservatezza in transito sono responsabilita' del trasporto
(TLS del reverse proxy in esercizio), come per qualunque collettore syslog. Il
token limita chi puo' scrivere e a quale tenant gli eventi appartengono.

remarks: Autore: Daniele Speziale - Data: 2026-09-02
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from ..siem import data, ingest

bp = Blueprint("api_siem", __name__, url_prefix="/api/siem")

HEADER_COLLECTOR = "X-Snap-Collector"


def _token_dalla_richiesta() -> str:
    """Il token del collettore, dall'intestazione Bearer o da quella dedicata."""
    autorizzazione = request.headers.get("Authorization", "")
    if autorizzazione.lower().startswith("bearer "):
        return autorizzazione[7:].strip()
    return (request.headers.get(HEADER_COLLECTOR) or "").strip()


@bp.post("/ingest")
def ingest_logs():
    """Riceve un lotto di righe di log da un collettore autenticato.

    Corpo JSON accettato in due forme, cosi' Vector puo' spedire quella piu' comoda:
      {"events": ["<riga grezza>", ...]}
      {"events": [{"message": "...", "host": "...", "src_ip": "..."}, ...]}
    """
    collector = data.collector_by_token(_token_dalla_richiesta())
    if collector is None:
        # Nessun dettaglio: un token sbagliato non deve sapere perche' e' sbagliato.
        return jsonify({"error": "non autorizzato"}), 401

    corpo = request.get_json(silent=True)
    if not isinstance(corpo, dict) or "events" not in corpo:
        return jsonify({"error": "corpo non valido: atteso {\"events\": [...]}"}), 400

    try:
        esito = ingest.ingest_batch(collector, corpo["events"])
    except ingest.IngestError as errore:
        return jsonify({"error": str(errore)}), 400
    except Exception as errore:  # noqa: BLE001 - l'ingestione non deve rivelare interni
        current_app.logger.warning("Ingestione SIEM non riuscita per il collettore %s: %s",
                                   collector["id"], errore)
        return jsonify({"error": "errore interno di ingestione"}), 500

    return jsonify({"ok": True, **esito}), 200


@bp.get("/health")
def health():
    """Verifica che un token e' valido, senza scrivere nulla. Serve al collettore per
    provare la configurazione all'avvio."""
    collector = data.collector_by_token(_token_dalla_richiesta())
    if collector is None:
        return jsonify({"error": "non autorizzato"}), 401
    return jsonify({"ok": True, "collector": collector["name"]}), 200
