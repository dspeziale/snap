"""
snap - Test del canale cifrato SNAP-SEC/1.

Verifica l'interoperabilita' fra le due implementazioni indipendenti (server e
sonda) e le proprieta' di sicurezza attese: legame con il contesto di trasporto,
rilevazione della manomissione, rifiuto delle buste scadute.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import time

import pytest

from snapprobe import crypto as probe_crypto
from snapserver import crypto as server_crypto


def test_ecdh_produces_identical_session_key():
    """Le due implementazioni derivano la stessa chiave dallo scambio X25519."""
    probe_private, probe_public = probe_crypto.generate_keypair()
    server_private, server_public = server_crypto.generate_keypair()

    probe_side = probe_crypto.derive_session_key(probe_private, server_public)
    server_side = server_crypto.derive_session_key(server_private, probe_public)

    assert probe_side == server_side
    assert len(probe_crypto.b64d(probe_side)) == 32


def test_enrollment_key_is_reproducible_on_both_sides():
    token = server_crypto.generate_enrollment_token()
    assert server_crypto.derive_enrollment_key(token, "sonda-01") == \
        probe_crypto.derive_enrollment_key(token, "sonda-01")
    # Un codice sonda diverso produce una chiave diversa: il token e' legato alla sonda.
    assert server_crypto.derive_enrollment_key(token, "sonda-02") != \
        probe_crypto.derive_enrollment_key(token, "sonda-01")


def test_probe_seals_and_server_opens():
    key = probe_crypto.b64e(b"k" * 32)
    contenuto = {"records": {"events": [{"type": "probe.cycle"}]}}
    envelope = probe_crypto.seal(key, "probe-1", "/api/v1/ingest", contenuto)
    payload, meta = server_crypto.open_envelope(
        key, envelope, "/api/v1/ingest", expected_probe_id="probe-1"
    )
    assert payload == contenuto
    assert meta.version == server_crypto.PROTOCOL_VERSION


def test_server_seals_and_probe_opens():
    key = server_crypto.b64e(b"z" * 32)
    envelope = server_crypto.seal(key, "probe-1", "/api/v1/heartbeat", {"commands": []})
    payload = probe_crypto.open_envelope(
        key, envelope, "/api/v1/heartbeat", expected_probe_id="probe-1"
    )
    assert payload == {"commands": []}


def test_envelope_is_bound_to_request_path():
    """Una busta valida non puo' essere riutilizzata su un'altra rotta."""
    key = probe_crypto.b64e(b"k" * 32)
    envelope = probe_crypto.seal(key, "probe-1", "/api/v1/ingest", {"x": 1})
    with pytest.raises(server_crypto.CryptoError):
        server_crypto.open_envelope(key, envelope, "/api/v1/heartbeat")


def test_envelope_is_bound_to_probe_identity():
    key = probe_crypto.b64e(b"k" * 32)
    envelope = probe_crypto.seal(key, "probe-1", "/api/v1/ingest", {"x": 1})
    with pytest.raises(server_crypto.CryptoError):
        server_crypto.open_envelope(key, envelope, "/api/v1/ingest", expected_probe_id="probe-2")


def test_tampered_ciphertext_is_rejected():
    key = probe_crypto.b64e(b"k" * 32)
    envelope = probe_crypto.seal(key, "probe-1", "/api/v1/ingest", {"x": 1})
    tampered = dict(envelope)
    tampered["data"] = envelope["data"][:-4] + "AAAA"
    with pytest.raises(server_crypto.CryptoError):
        server_crypto.open_envelope(key, tampered, "/api/v1/ingest")


def test_wrong_key_is_rejected():
    envelope = probe_crypto.seal(probe_crypto.b64e(b"k" * 32), "p", "/api/v1/ingest", {"x": 1})
    with pytest.raises(server_crypto.CryptoError):
        server_crypto.open_envelope(server_crypto.b64e(b"j" * 32), envelope, "/api/v1/ingest")


def test_stale_envelope_is_rejected():
    """Una busta piu' vecchia della finestra ammessa non viene accettata."""
    key = probe_crypto.b64e(b"k" * 32)
    envelope = probe_crypto.seal(key, "probe-1", "/api/v1/ingest", {"x": 1})
    envelope["ts"] = int(time.time()) - (server_crypto.MAX_CLOCK_SKEW + 60)
    with pytest.raises(server_crypto.CryptoError):
        server_crypto.open_envelope(key, envelope, "/api/v1/ingest")


def test_token_fingerprint_never_reveals_token():
    token = server_crypto.generate_enrollment_token()
    fingerprint = server_crypto.token_fingerprint(token)
    assert fingerprint == probe_crypto.token_fingerprint(token)
    assert token not in fingerprint
    assert len(fingerprint) == 64
