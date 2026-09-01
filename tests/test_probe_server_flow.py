"""
snap - Test del percorso completo sonda -> server.

Copre: emissione del token, registrazione cifrata, funzionamento autonomo con
server assente, conferimento al ritorno del server, svuotamento della coda,
idempotenza delle ritrasmissioni, consegna dei comandi e revoca.

Il trasporto HTTP e' sostituito da un adattatore sul client di test Flask del
server: le due applicazioni restano separate e dialogano solo tramite il
protocollo.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re

import pytest

from snapprobe.agent import ProbeAgent
from snapprobe.client import ServerClient

SERVER_BASE = "http://server.test"


class _Response:
    """Risposta minimale compatibile con l'uso fatto dal client della sonda."""

    def __init__(self, status_code: int, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("nessun corpo JSON")
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP %d" % self.status_code)


class FlaskTransport:
    """Instrada le richieste della sonda sul client di test del server."""

    class RequestException(RuntimeError):
        pass

    def __init__(self, flask_client):
        self.client = flask_client
        self.available = True
        self.calls = []

    def _path(self, url: str) -> str:
        return url[len(SERVER_BASE):] if url.startswith(SERVER_BASE) else url

    def post(self, url, json=None, timeout=None, headers=None):
        if not self.available:
            raise self.RequestException("server non disponibile (simulato)")
        path = self._path(url)
        self.calls.append(("POST", path))
        response = self.client.post(path, json=json, headers=headers or {})
        return _Response(response.status_code, response.get_json(silent=True))

    def get(self, url, timeout=None, headers=None):
        if not self.available:
            raise self.RequestException("server non disponibile (simulato)")
        path = self._path(url)
        self.calls.append(("GET", path))
        response = self.client.get(path, headers=headers or {})
        return _Response(response.status_code, response.get_json(silent=True))


@pytest.fixture()
def transport(server_app, monkeypatch):
    import snapprobe.client as client_module

    adapter = FlaskTransport(server_app.test_client())
    monkeypatch.setattr(client_module, "requests", adapter)
    return adapter


def _create_probe(logged_client, code: str = "sonda-collaudo") -> tuple[str, str]:
    """Crea la sonda dalla console del server e restituisce (bundle, token)."""
    response = logged_client.post(
        "/probes/new",
        data={
            "code": code,
            "name": "Sonda di collaudo",
            "site": "Laboratorio",
            "scan_interval_sec": "60",
            "description": "Creata dal test automatico",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    body = response.data.decode("utf-8")
    bundle = re.search(r'id="bundle">([^<]+)<', body).group(1).strip()
    token = re.search(r'id="token">([^<]+)<', body).group(1).strip()
    return bundle, token


def _bundle_with_test_host(bundle: str) -> str:
    """Riscrive l'URL del pacchetto sull'host virtuale usato dai test."""
    import base64
    import json

    encoded = bundle[len("SNAP1-"):]
    padding = "=" * (-len(encoded) % 4)
    payload = json.loads(base64.urlsafe_b64decode(encoded + padding).decode("utf-8"))
    payload["url"] = SERVER_BASE
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return "SNAP1-" + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _agent(probe_store) -> ProbeAgent:
    probe_store.set_setting("scan_interval_sec", 60)
    probe_store.set_setting("paused", "0")
    return ProbeAgent(probe_store, agent_version="1.0.0-test", tick_seconds=1)


# --------------------------------------------------------------------------- #
# Registrazione
# --------------------------------------------------------------------------- #
def test_enrollment_establishes_encrypted_channel(server_app, logged_client, probe_store, transport):
    bundle, _token = _create_probe(logged_client)
    client = ServerClient(probe_store, "1.0.0-test")
    from snapprobe.client import parse_bundle

    client.enroll(**parse_bundle(_bundle_with_test_host(bundle)))

    assert probe_store.is_enrolled()
    assert probe_store.get_setting("session_key")

    # Lato server la sonda risulta registrata e la chiave di sessione coincide;
    # la sonda ha ricevuto il fuso orario del proprio tenant.
    with server_app.app_context():
        from snapserver.db import query

        row = query(
            "SELECT p.*, t.timezone FROM probes p JOIN tenants t ON t.id = p.tenant_id"
            " WHERE p.code = 'sonda-collaudo'",
            (),
            one=True,
        )
        assert row["status"] == "active"
        assert row["session_key"] == probe_store.get_setting("session_key")
        assert row["enrollment_key"] is None  # materiale monouso consumato
        assert probe_store.get_setting("tenant_timezone") == row["timezone"]


def test_enrollment_token_cannot_be_reused(server_app, logged_client, probe_store, transport):
    bundle, _token = _create_probe(logged_client)
    from snapprobe.client import ProtocolError, parse_bundle

    parameters = parse_bundle(_bundle_with_test_host(bundle))
    ServerClient(probe_store, "1.0.0-test").enroll(**parameters)

    probe_store.reset_enrollment()
    with pytest.raises(ProtocolError):
        ServerClient(probe_store, "1.0.0-test").enroll(**parameters)


def test_enrollment_with_wrong_token_is_rejected(server_app, logged_client, probe_store, transport):
    bundle, _token = _create_probe(logged_client)
    from snapprobe.client import ProtocolError, parse_bundle

    parameters = parse_bundle(_bundle_with_test_host(bundle))
    parameters["enrollment_token"] = "token-non-valido"
    with pytest.raises(ProtocolError):
        ServerClient(probe_store, "1.0.0-test").enroll(**parameters)


# --------------------------------------------------------------------------- #
# Autonomia e conferimento
# --------------------------------------------------------------------------- #
def test_probe_works_offline_then_uploads_and_empties_queue(
    server_app, logged_client, probe_store, transport
):
    bundle, _token = _create_probe(logged_client)
    from snapprobe.client import parse_bundle

    agent = _agent(probe_store)
    agent.client.enroll(**parse_bundle(_bundle_with_test_host(bundle)))

    # Server non raggiungibile: la sonda continua a raccogliere in autonomia.
    transport.available = False
    agent.run_once()
    probe_store.set_setting("last_collection_at", "")
    agent.collector.collect()
    queued = probe_store.queue_size()
    assert queued > 0, "la sonda deve accumulare dati anche senza server"
    assert agent.online is False

    # Ritorno del server: la coda viene conferita e svuotata.
    transport.available = True
    outcome = agent.flush_queue()
    assert outcome["records"] == queued
    assert probe_store.queue_size() == 0, "la coda locale deve svuotarsi dopo l'ack"

    with server_app.app_context():
        from snapserver.db import query, scalar

        tenant_id = int(
            query("SELECT tenant_id FROM probes WHERE code = 'sonda-collaudo'", (), one=True)[
                "tenant_id"
            ]
        )
        assert scalar("SELECT COUNT(*) FROM ingest_batches WHERE tenant_id = ?", (tenant_id,)) > 0
        # Le annotazioni conferite confluiscono nel registro di audit del tenant.
        assert scalar(
            "SELECT COUNT(*) FROM audit_events WHERE tenant_id = ? AND event_type = 'probe.cycle'",
            (tenant_id,),
        ) > 0


def test_retransmission_is_idempotent(server_app, logged_client, probe_store, transport):
    """Un lotto ritrasmesso non duplica i dati sul server."""
    bundle, _token = _create_probe(logged_client)
    from snapprobe.client import parse_bundle

    agent = _agent(probe_store)
    agent.client.enroll(**parse_bundle(_bundle_with_test_host(bundle)))
    agent.collector.collect()

    batch_uid = "collaudo-idempotenza"
    reserved = probe_store.reserve_batch(batch_uid, 500)
    records = {"events": [item["payload"] for item in reserved]}

    first = agent.client.send_batch(batch_uid, records, "2026-08-26 12:00:00")
    second = agent.client.send_batch(batch_uid, records, "2026-08-26 12:00:00")

    assert first["accepted"] and not first["duplicate"]
    assert second["accepted"] and second["duplicate"]

    with server_app.app_context():
        from snapserver.db import scalar

        assert scalar("SELECT COUNT(*) FROM ingest_batches WHERE batch_uid = ?", (batch_uid,)) == 1


def test_server_commands_are_delivered_on_probe_contact(
    server_app, logged_client, probe_store, transport
):
    bundle, _token = _create_probe(logged_client)
    from snapprobe.client import parse_bundle

    agent = _agent(probe_store)
    agent.client.enroll(**parse_bundle(_bundle_with_test_host(bundle)))

    with server_app.app_context():
        from snapserver.db import query

        probe_id = int(query("SELECT id FROM probes WHERE code = 'sonda-collaudo'", (), one=True)["id"])

    response = logged_client.post(
        "/probes/%d/command" % probe_id, data={"command": "pause"}, follow_redirects=True
    )
    assert response.status_code == 200

    answer = agent.client.heartbeat()
    assert any(command["command"] == "pause" for command in answer["commands"])

    # Il comando viene eseguito e confermato: la raccolta risulta sospesa.
    results = agent._execute_commands(answer["commands"])
    assert results and results[0]["ok"]
    assert probe_store.get_setting("paused") == "1"

    with server_app.app_context():
        from snapserver.db import query

        row = query(
            "SELECT status FROM probe_commands WHERE probe_id = ? ORDER BY id DESC",
            (probe_id,),
            one=True,
        )
        assert row["status"] == "completed"


def test_revoked_probe_cannot_upload(server_app, logged_client, probe_store, transport):
    bundle, _token = _create_probe(logged_client)
    from snapprobe.client import ProtocolError, parse_bundle

    agent = _agent(probe_store)
    agent.client.enroll(**parse_bundle(_bundle_with_test_host(bundle)))

    with server_app.app_context():
        from snapserver.db import query

        probe_id = int(query("SELECT id FROM probes WHERE code = 'sonda-collaudo'", (), one=True)["id"])

    logged_client.post("/probes/%d/revoke" % probe_id, follow_redirects=True)

    with pytest.raises(ProtocolError):
        agent.client.heartbeat()


def test_replayed_envelope_is_refused(server_app, logged_client, probe_store, transport):
    """La ripetizione di una busta valida viene bloccata dal registro dei nonce."""
    bundle, _token = _create_probe(logged_client)
    from snapprobe import crypto as probe_crypto
    from snapprobe.client import parse_bundle

    agent = _agent(probe_store)
    agent.client.enroll(**parse_bundle(_bundle_with_test_host(bundle)))

    path = "/api/v1/heartbeat"
    envelope = probe_crypto.seal(
        probe_store.get_setting("session_key"),
        probe_store.get_setting("probe_uid"),
        path,
        {"auth": probe_store.get_setting("api_key"), "queue_size": 0},
    )
    headers = {"X-Snap-Probe": probe_store.get_setting("probe_uid")}
    client = server_app.test_client()

    first = client.post(path, json=envelope, headers=headers)
    second = client.post(path, json=envelope, headers=headers)

    assert first.status_code == 200
    assert second.status_code == 403
    assert "nonce" in (second.get_json() or {}).get("detail", "")


def test_probe_without_enrollment_still_collects(probe_store):
    """Senza registrazione la sonda raccoglie comunque e nulla viene perduto."""
    agent = _agent(probe_store)
    outcome = agent.run_once()
    assert outcome["collected"] is not None
    assert probe_store.queue_size() > 0
    assert agent.flush_queue()["records"] == 0
