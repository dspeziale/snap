"""
snap probe - Client del canale cifrato verso il server.

Tutte le richieste sono in uscita dalla sonda: registrazione, presenza
(heartbeat), conferimento dei lotti e conferma dei comandi. Il server non ha
alcun modo di iniziare una connessione verso la sonda.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import base64
import json
import platform
import socket

import requests

from . import crypto
from .store import ProbeStore, utc_now_str

BUNDLE_PREFIX = "SNAP1-"


class TransportError(Exception):
    """Il server non e' raggiungibile o ha risposto in modo non utilizzabile."""


class ProtocolError(Exception):
    """Il server ha risposto con un errore applicativo definitivo."""


def parse_bundle(text: str) -> dict:
    """Decodifica il pacchetto di registrazione emesso dal server."""
    value = (text or "").strip()
    if not value.startswith(BUNDLE_PREFIX):
        raise ValueError("il pacchetto deve iniziare con %s" % BUNDLE_PREFIX)

    encoded = value[len(BUNDLE_PREFIX):]
    padding = "=" * (-len(encoded) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(encoded + padding).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("pacchetto di registrazione illeggibile: %s" % exc) from exc

    for field in ("url", "code", "token"):
        if not payload.get(field):
            raise ValueError("pacchetto incompleto: manca il campo '%s'" % field)
    return {
        "server_url": str(payload["url"]).rstrip("/"),
        "probe_code": str(payload["code"]),
        "enrollment_token": str(payload["token"]),
    }


class ServerClient:
    """Trasporto SNAP-SEC/1 lato sonda."""

    def __init__(self, store: ProbeStore, agent_version: str, timeout: int = 15):
        self.store = store
        self.agent_version = agent_version
        self.timeout = timeout

    # -- utilita' ------------------------------------------------------------
    def _url(self, path: str) -> str:
        base = (self.store.get_setting("server_url") or "").rstrip("/")
        if not base:
            raise ProtocolError("URL del server non configurato")
        return base + path

    def _post(self, path: str, body: dict) -> dict:
        try:
            response = requests.post(
                self._url(path),
                json=body,
                timeout=self.timeout,
                headers=self._headers(),
            )
        except requests.RequestException as exc:
            raise TransportError("server non raggiungibile: %s" % exc) from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise ProtocolError(
                "risposta non JSON dal server (HTTP %d)" % response.status_code
            ) from exc

        if response.status_code >= 400:
            detail = payload.get("detail") or payload.get("error") or "errore non specificato"
            raise ProtocolError("HTTP %d - %s" % (response.status_code, detail))
        return payload

    def _headers(self) -> dict:
        headers = {"User-Agent": "snap-probe/%s" % self.agent_version}
        probe_uid = self.store.get_setting("probe_uid")
        if probe_uid:
            headers["X-Snap-Probe"] = probe_uid
        return headers

    # -- verifica di raggiungibilita' ---------------------------------------
    def ping(self) -> dict:
        try:
            response = requests.get(self._url("/api/v1/ping"), timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, ValueError) as exc:
            raise TransportError("verifica del server non riuscita: %s" % exc) from exc

    # -- registrazione -------------------------------------------------------
    def enroll(self, server_url: str, probe_code: str, enrollment_token: str) -> dict:
        """Esegue la registrazione e memorizza il materiale crittografico ottenuto."""
        path = "/api/v1/enroll"
        private_key, public_key = crypto.generate_keypair()
        enrollment_key = crypto.derive_enrollment_key(enrollment_token, probe_code)

        payload = {
            "probe_code": probe_code,
            "probe_public_key": public_key,
            "agent_version": self.agent_version,
            "platform": "%s %s" % (platform.system(), platform.release()),
            "hostname": socket.gethostname(),
            "requested_at": utc_now_str(),
        }
        envelope = crypto.seal(enrollment_key, probe_code, path, payload)

        self.store.set_setting("server_url", server_url.rstrip("/"))
        response = self._post(
            path,
            {"token_hint": crypto.token_fingerprint(enrollment_token), "envelope": envelope},
        )

        answer = crypto.open_envelope(
            enrollment_key, response, path, expected_probe_id=probe_code
        )
        server_public_key = str(answer.get("server_public_key") or "")
        probe_uid = str(answer.get("probe_uid") or "")
        api_key = str(answer.get("api_key") or "")
        if not (server_public_key and probe_uid and api_key):
            raise ProtocolError("risposta di registrazione incompleta")

        session_key = crypto.derive_session_key(private_key, server_public_key)
        config = answer.get("config") or {}

        self.store.set_settings(
            {
                "probe_code": probe_code,
                "probe_uid": probe_uid,
                "api_key": api_key,
                "probe_private_key": private_key,
                "probe_public_key": public_key,
                "server_public_key": server_public_key,
                "session_key": session_key,
                "enrolled_at": utc_now_str(),
                "tenant_code": config.get("tenant_code", ""),
                "tenant_name": config.get("tenant_name", ""),
                "tenant_timezone": config.get("tenant_timezone", "UTC"),
                "scan_interval_sec": int(config.get("scan_interval_sec") or 300),
                "probe_name": config.get("probe_name", probe_code),
                "last_contact_at": utc_now_str(),
            }
        )
        self.store.set_json("server_options", config.get("options") or {})
        self.store.log(
            "info",
            "Registrazione completata presso %s per il tenant %s"
            % (server_url, config.get("tenant_name") or config.get("tenant_code") or "n.d."),
        )
        return answer

    # -- scambi di sessione --------------------------------------------------
    def _sealed_exchange(self, path: str, payload: dict) -> dict:
        probe_uid = self.store.get_setting("probe_uid")
        session_key = self.store.get_setting("session_key")
        api_key = self.store.get_setting("api_key")
        if not (probe_uid and session_key and api_key):
            raise ProtocolError("sonda non registrata: eseguire prima la registrazione")

        payload = dict(payload)
        payload["auth"] = api_key
        payload["agent_version"] = self.agent_version

        envelope = crypto.seal(session_key, probe_uid, path, payload)
        response = self._post(path, envelope)
        answer = crypto.open_envelope(
            session_key, response, path, expected_probe_id=probe_uid
        )
        self.store.set_setting("last_contact_at", utc_now_str())
        return answer

    def heartbeat(self) -> dict:
        return self._sealed_exchange(
            "/api/v1/heartbeat",
            {
                "queue_size": self.store.queue_size(),
                "paused": self.store.get_setting("paused", "0") == "1",
                "hostname": socket.gethostname(),
            },
        )

    def send_batch(self, batch_uid: str, records: dict, generated_at: str) -> dict:
        return self._sealed_exchange(
            "/api/v1/ingest",
            {"batch_uid": batch_uid, "generated_at": generated_at, "records": records},
        )

    def acknowledge_commands(self, results: list[dict]) -> dict:
        return self._sealed_exchange("/api/v1/command-ack", {"results": results})
