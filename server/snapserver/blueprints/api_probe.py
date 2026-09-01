"""
snap server - Canale cifrato di raccolta dati dalle sonde (SNAP-SEC/1).

Principio architetturale: il server e' passivo. Non conosce ne' l'indirizzo ne'
la topologia della sonda, non apre mai connessioni verso di essa e non conserva
dati di rete che ne consentano il contatto. Ogni scambio e' iniziato dalla
sonda; i comandi di configurazione viaggiano in piggyback sulle risposte.

Rotte (tutte POST, corpo JSON contenente una busta AES-256-GCM):
  /api/v1/enroll       registrazione con token monouso
  /api/v1/heartbeat    presenza, configurazione e coda comandi
  /api/v1/ingest       conferimento dei lotti di dati
  /api/v1/command-ack  conferma di esecuzione di un comando
  /api/v1/ping         verifica di raggiungibilita' in chiaro (nessun dato)

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json
import uuid

from flask import Blueprint, current_app, jsonify, request

from ..audit import log_event
from ..crypto import (
    CryptoError,
    PROTOCOL_VERSION,
    constant_time_equals,
    derive_session_key,
    generate_api_key,
    generate_keypair,
    open_envelope,
    seal,
    token_fingerprint,
)
from ..db import days_ago_str, execute, parse_utc, query, utc_now, utc_now_str
from ..ingest import IngestError, apply_batch

bp = Blueprint("api_probe", __name__, url_prefix="/api/v1")

HEADER_PROBE = "X-Snap-Probe"

# Cadenze predefinite delle fasi di scansione, in secondi. La scoperta e' rapida
# e leggera; il rilevamento del sistema operativo e l'approfondimento sono
# costosi e vanno ripetuti raramente.
# Profili di sforzo ammessi. Il significato operativo e' definito sulla sonda
# (snapprobe.scanner.EFFORT_PROFILES): qui si valida soltanto il valore.
SCAN_EFFORTS = ("min", "med", "max")

# Tempi massimi per host proposti nella console. L'elenco e' il medesimo che la
# sonda propone nella propria interfaccia (snapprobe.scanner.HOST_TIMEOUT_CHOICES):
# i due applicativi non condividono codice, quindi va mantenuto allineato.
HOST_TIMEOUTS = ("30s", "60s", "120s", "180s", "300s", "600s")

# Ogni quanti giorni la scoperta ricensisce il perimetro. Il limite superiore
# evita che un perimetro resti non verificato per mesi; quello inferiore evita di
# tornare alla scoperta continua.
DISCOVERY_DAYS_DEFAULT = 3
DISCOVERY_DAYS_MIN = 1
DISCOVERY_DAYS_MAX = 90

DEFAULT_SCAN_CADENCES = {
    # La scoperta ricensisce il perimetro: il valore effettivo viene dal campo
    # scan_discovery_days della sonda, questo e' solo la ricaduta.
    "discovery": 3 * 24 * 3600,
    "ports": 21600,          # 6 ore
    "services": 43200,       # 12 ore
    "os": 259200,            # 3 giorni
    "deep": 604800,          # 7 giorni
    "monitor": 120,          # 2 minuti
}


# --------------------------------------------------------------------------- #
# Utility di protocollo
# --------------------------------------------------------------------------- #
def _protocol_error(message: str, status: int = 400, code: str = "protocol_error"):
    """Errore restituito in chiaro: la chiave di sessione non e' disponibile o valida."""
    current_app.logger.warning("Canale sonde - %s (%s)", message, code)
    return jsonify({"error": code, "detail": message, "v": PROTOCOL_VERSION}), status


def _json_body() -> dict:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise CryptoError("corpo della richiesta non JSON")
    return body


def _consume_nonce(probe_id: int, nonce: str) -> bool:
    """Registra il nonce; False se era gia' stato usato (replay)."""
    try:
        execute(
            "INSERT INTO probe_nonces (probe_id, nonce, seen_at) VALUES (?, ?, ?)",
            (probe_id, nonce, utc_now_str()),
        )
    except Exception as exc:  # violazione di UNIQUE: replay accertato
        current_app.logger.warning("Nonce ripetuto per la sonda %s: %s", probe_id, exc)
        return False
    return True


def _purge_nonces() -> None:
    hours = current_app.config["NONCE_RETENTION_HOURS"]
    execute("DELETE FROM probe_nonces WHERE seen_at < ?", (days_ago_str(max(1, hours // 24 or 1)),))


def _load_probe_for_session(probe_uid: str):
    return query(
        "SELECT * FROM probes WHERE probe_uid = ?",
        (probe_uid,),
        one=True,
    )


def _open_session_request(path: str):
    """Autentica e decifra una richiesta di sessione.

    Restituisce (probe_row, payload) oppure solleva CryptoError. L'autenticazione
    si basa su due fattori indipendenti: la capacita' di produrre una busta
    valida con la chiave di sessione e la API key trasportata dentro la busta.
    """
    probe_uid = request.headers.get(HEADER_PROBE, "").strip()
    if not probe_uid:
        raise CryptoError("intestazione %s assente" % HEADER_PROBE)

    probe = _load_probe_for_session(probe_uid)
    if probe is None:
        raise CryptoError("sonda non riconosciuta")
    if probe["revoked_at"]:
        raise CryptoError("sonda revocata")
    if not probe["session_key"]:
        raise CryptoError("sonda non ancora registrata")

    payload, envelope = open_envelope(
        probe["session_key"], _json_body(), path, expected_probe_id=probe_uid
    )

    api_key = str(payload.get("auth") or "")
    if not api_key or not constant_time_equals(
        token_fingerprint(api_key), probe["api_key_hash"] or ""
    ):
        raise CryptoError("credenziale di sonda non valida")

    if not _consume_nonce(int(probe["id"]), envelope.nonce):
        raise CryptoError("nonce gia' utilizzato (possibile replay)")

    return probe, payload


def _sealed_response(probe_row, path: str, payload: dict, status: int = 200):
    envelope = seal(probe_row["session_key"], probe_row["probe_uid"], path, payload)
    return jsonify(envelope), status


def _tenant_of(probe_row) -> dict:
    tenant = query("SELECT * FROM tenants WHERE id = ?", (probe_row["tenant_id"],), one=True)
    return dict(tenant) if tenant else {}


def _scan_enabled(probe_row) -> bool:
    """Legge l'interruttore della scansione, tollerando basi dati non migrate."""
    try:
        return bool(int(probe_row["scan_enabled"]))
    except (KeyError, IndexError, TypeError, ValueError):
        # Colonna assente su un database non ancora migrato: si considera attiva,
        # che e' il comportamento precedente all'introduzione dell'interruttore.
        return True


def _scan_effort(probe_row) -> str:
    """Profilo di sforzo della sonda, con ricaduta sul valore medio."""
    try:
        valore = str(probe_row["scan_effort"] or "").strip().lower()
    except (KeyError, IndexError, TypeError):
        valore = ""
    return valore if valore in SCAN_EFFORTS else "med"


def _scan_host_timeout(probe_row) -> str:
    """Tempo massimo per host della sonda; stringa vuota se non impostato."""
    try:
        valore = str(probe_row["scan_host_timeout"] or "").strip()
    except (KeyError, IndexError, TypeError):
        valore = ""
    return valore if valore in HOST_TIMEOUTS else ""


def _discovery_days(probe_row) -> int:
    """Giorni fra due censimenti del perimetro, con ricaduta sul predefinito."""
    try:
        valore = int(probe_row["scan_discovery_days"])
    except (KeyError, IndexError, TypeError, ValueError):
        return DISCOVERY_DAYS_DEFAULT
    if not DISCOVERY_DAYS_MIN <= valore <= DISCOVERY_DAYS_MAX:
        return DISCOVERY_DAYS_DEFAULT
    return valore


def _probe_config(probe_row, tenant: dict) -> dict:
    """Configurazione operativa consegnata alla sonda a ogni contatto."""
    try:
        extra = json.loads(probe_row["config_json"] or "{}")
    except json.JSONDecodeError:
        current_app.logger.warning(
            "config_json non valido per la sonda %s: si usa la configurazione vuota",
            probe_row["probe_uid"],
        )
        extra = {}
    from ..checks import checks_for_probe
    from ..subnets import active_subnets

    # Cadenze delle fasi di scansione, in secondi. Sono sovrascrivibili per sonda
    # attraverso config_json: un impianto lento o una rete delicata possono
    # richiedere passi piu' radi di quelli predefiniti.
    cadenze = dict(DEFAULT_SCAN_CADENCES)
    # La scoperta segue il valore in giorni impostato per la sonda.
    cadenze["discovery"] = _discovery_days(probe_row) * 86400
    for fase, valore in (extra.get("cadences") or {}).items():
        if fase in cadenze:
            try:
                cadenze[fase] = max(60, int(valore))
            except (TypeError, ValueError):
                current_app.logger.warning(
                    "Cadenza non valida per la fase %s della sonda %s: si usa il valore "
                    "predefinito", fase, probe_row["probe_uid"])

    return {
        "scan_interval_sec": int(probe_row["scan_interval_sec"] or 300),
        "tenant_code": tenant.get("code"),
        "tenant_name": tenant.get("name"),
        "tenant_timezone": tenant.get("timezone"),
        "probe_name": probe_row["name"],
        # Perimetro vincolante: la sonda scansiona solo questi indirizzi.
        "subnets": active_subnets(int(probe_row["tenant_id"])),
        # Interruttore autoritativo della scansione.
        "scan_enabled": bool(_scan_enabled(probe_row)),
        # Profilo di sforzo: quanti thread e quanto in profondita' si scansiona.
        "scan_effort": _scan_effort(probe_row),
        # Tempo massimo per host; vuoto significa quello del profilo.
        "scan_host_timeout": _scan_host_timeout(probe_row),
        "cadences": cadenze,
        "discovery_days": _discovery_days(probe_row),
        # Controlli periodici da eseguire: bersagli dichiarati dall'operatore, non
        # scoperti dalla rete. Viaggiano qui perche' la sonda non deve interrogare
        # il server per sapere cosa fare.
        "checks": checks_for_probe(int(probe_row["tenant_id"])),
        "options": extra,
    }


def _pending_commands(probe_row) -> list[dict]:
    rows = query(
        "SELECT id, command, payload_json FROM probe_commands"
        " WHERE probe_id = ? AND status = 'pending' ORDER BY created_at LIMIT 20",
        (int(probe_row["id"]),),
    )
    commands = []
    for row in rows:
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except json.JSONDecodeError:
            payload = {}
        commands.append({"id": int(row["id"]), "command": row["command"], "payload": payload})
        execute(
            "UPDATE probe_commands SET status = 'delivered', delivered_at = ? WHERE id = ?",
            (utc_now_str(), int(row["id"])),
        )
    return commands


def _touch_probe(probe_row, agent_version: str | None = None, synced: bool = False) -> None:
    now = utc_now_str()
    if synced:
        execute(
            "UPDATE probes SET last_seen_at = ?, last_sync_at = ?, status = 'active',"
            " agent_version = COALESCE(?, agent_version), updated_at = ? WHERE id = ?",
            (now, now, agent_version, now, int(probe_row["id"])),
        )
    else:
        execute(
            "UPDATE probes SET last_seen_at = ?, status = 'active',"
            " agent_version = COALESCE(?, agent_version), updated_at = ? WHERE id = ?",
            (now, agent_version, now, int(probe_row["id"])),
        )


# --------------------------------------------------------------------------- #
# Rotte
# --------------------------------------------------------------------------- #
@bp.get("/ping")
def ping():
    """Verifica di raggiungibilita': non espone alcun dato di tenant."""
    return jsonify(
        {
            "service": current_app.config["APP_NAME"],
            "protocol": PROTOCOL_VERSION,
            "server_time": utc_now_str(),
        }
    )


@bp.post("/enroll")
def enroll():
    """Registrazione della sonda tramite token monouso.

    La sonda dichiara in chiaro solo l'impronta del token (token_hint), che il
    server usa come indice; il contenuto e' cifrato con la chiave derivata dal
    token stesso, quindi solo il legittimo possessore del token puo' registrarsi.
    """
    path = "/api/v1/enroll"
    try:
        body = _json_body()
    except CryptoError as exc:
        return _protocol_error(str(exc))

    token_hint = str(body.get("token_hint") or "").strip()
    envelope = body.get("envelope")
    if not token_hint or not isinstance(envelope, dict):
        return _protocol_error("richiesta di enrollment incompleta")

    probe = query(
        "SELECT * FROM probes WHERE enrollment_token_hash = ?", (token_hint,), one=True
    )
    if probe is None:
        return _protocol_error("token di registrazione non riconosciuto", 403, "enroll_unknown")
    if probe["revoked_at"]:
        return _protocol_error("sonda revocata", 403, "probe_revoked")
    if probe["enrolled_at"]:
        return _protocol_error("token di registrazione gia' utilizzato", 409, "enroll_used")

    expires = parse_utc(probe["enrollment_expires_at"])
    if expires is not None and expires < utc_now():
        return _protocol_error("token di registrazione scaduto", 403, "enroll_expired")
    if not probe["enrollment_key"]:
        return _protocol_error("materiale di registrazione assente", 500, "enroll_broken")

    try:
        payload, _env = open_envelope(
            probe["enrollment_key"], envelope, path, expected_probe_id=probe["code"]
        )
    except CryptoError as exc:
        log_event(
            "probe.enroll.failed",
            "Registrazione rifiutata per la sonda %s: %s" % (probe["code"], exc),
            tenant_id=int(probe["tenant_id"]),
            severity="warning",
            entity="probe",
            entity_id=probe["id"],
            actor="probe:%s" % probe["code"],
        )
        return _protocol_error("busta di enrollment non valida: %s" % exc, 403, "enroll_crypto")

    probe_public_key = str(payload.get("probe_public_key") or "")
    if not probe_public_key:
        return _protocol_error("chiave pubblica della sonda assente", 400, "enroll_nokey")

    server_private, server_public = generate_keypair()
    try:
        session_key = derive_session_key(server_private, probe_public_key)
    except CryptoError as exc:
        return _protocol_error("scambio di chiavi non riuscito: %s" % exc, 400, "enroll_kex")

    api_key = generate_api_key()
    probe_uid = probe["probe_uid"] or uuid.uuid4().hex
    now = utc_now_str()
    execute(
        "UPDATE probes SET probe_uid = ?, status = 'active', enrolled_at = ?,"
        " probe_public_key = ?, server_private_key = ?, server_public_key = ?,"
        " session_key = ?, api_key_hash = ?, agent_version = ?, last_seen_at = ?,"
        " enrollment_key = NULL, updated_at = ? WHERE id = ?",
        (
            probe_uid,
            now,
            probe_public_key,
            server_private,
            server_public,
            session_key,
            token_fingerprint(api_key),
            str(payload.get("agent_version") or "")[:32] or None,
            now,
            now,
            int(probe["id"]),
        ),
    )

    tenant = _tenant_of(probe)
    log_event(
        "probe.enrolled",
        "Sonda %s registrata (piattaforma dichiarata: %s)"
        % (probe["code"], str(payload.get("platform") or "n.d.")[:64]),
        tenant_id=int(probe["tenant_id"]),
        entity="probe",
        entity_id=probe["id"],
        actor="probe:%s" % probe["code"],
    )

    response_payload = {
        "probe_uid": probe_uid,
        "api_key": api_key,
        "server_public_key": server_public,
        "server_time": now,
        "config": _probe_config(probe, tenant),
    }
    # La risposta viaggia ancora sotto la chiave di enrollment: la sonda non
    # possiede la chiave di sessione fino a quando non riceve la chiave pubblica.
    envelope_out = seal(probe["enrollment_key"], probe["code"], path, response_payload)
    return jsonify(envelope_out), 200


@bp.post("/heartbeat")
def heartbeat():
    """Presenza periodica della sonda: consegna configurazione e comandi."""
    path = "/api/v1/heartbeat"
    try:
        probe, payload = _open_session_request(path)
    except CryptoError as exc:
        return _protocol_error(str(exc), 403, "auth_failed")

    _touch_probe(probe, str(payload.get("agent_version") or "") or None)
    _purge_nonces()

    tenant = _tenant_of(probe)
    probe = _load_probe_for_session(probe["probe_uid"])
    response = {
        "server_time": utc_now_str(),
        "config": _probe_config(probe, tenant),
        "commands": _pending_commands(probe),
        "queue_ack": int(payload.get("queue_size") or 0),
    }
    return _sealed_response(probe, path, response)


@bp.post("/ingest")
def ingest():
    """Conferimento di un lotto di dati raccolti in autonomia dalla sonda."""
    path = "/api/v1/ingest"
    try:
        probe, payload = _open_session_request(path)
    except CryptoError as exc:
        return _protocol_error(str(exc), 403, "auth_failed")

    try:
        result = apply_batch(
            tenant_id=int(probe["tenant_id"]),
            probe_id=int(probe["id"]),
            payload=payload,
            payload_bytes=request.content_length or 0,
        )
    except IngestError as exc:
        log_event(
            "probe.ingest.rejected",
            "Lotto rifiutato dalla sonda %s: %s" % (probe["code"], exc),
            tenant_id=int(probe["tenant_id"]),
            severity="warning",
            entity="probe",
            entity_id=probe["id"],
            actor="probe:%s" % probe["code"],
        )
        return _sealed_response(probe, path, {"accepted": False, "error": str(exc)}, 200)

    _touch_probe(probe, str(payload.get("agent_version") or "") or None, synced=True)
    probe = _load_probe_for_session(probe["probe_uid"])
    result["server_time"] = utc_now_str()
    return _sealed_response(probe, path, result)


@bp.post("/command-ack")
def command_ack():
    """Conferma di esecuzione di un comando consegnato in precedenza."""
    path = "/api/v1/command-ack"
    try:
        probe, payload = _open_session_request(path)
    except CryptoError as exc:
        return _protocol_error(str(exc), 403, "auth_failed")

    acknowledged = []
    for item in payload.get("results") or []:
        try:
            command_id = int(item.get("id"))
        except (TypeError, ValueError):
            continue
        row = query(
            "SELECT id FROM probe_commands WHERE id = ? AND probe_id = ?",
            (command_id, int(probe["id"])),
            one=True,
        )
        if row is None:
            continue  # comando non appartenente alla sonda: ignorato
        execute(
            "UPDATE probe_commands SET status = ?, result_json = ?, acked_at = ? WHERE id = ?",
            (
                "completed" if item.get("ok") else "failed",
                json.dumps(item, separators=(",", ":"), default=str)[:4000],
                utc_now_str(),
                command_id,
            ),
        )
        acknowledged.append(command_id)

    _touch_probe(probe)
    probe = _load_probe_for_session(probe["probe_uid"])
    return _sealed_response(probe, path, {"acknowledged": acknowledged})
