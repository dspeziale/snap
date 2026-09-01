"""
snap probe - Modulo crittografico lato sonda (protocollo SNAP-SEC/1).

Implementazione autonoma e speculare a quella del server: le due componenti sono
distribuite separatamente e non condividono codice, per cui il protocollo e' qui
reimplementato sulle stesse primitive (X25519 + HKDF-SHA256 + AES-256-GCM).

La sonda e' l'unica parte che conosce l'indirizzo dell'altra: apre sempre lei la
connessione e non espone alcun servizio verso il server.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL_VERSION = "SNAP-SEC/1"

_INFO_ENROLL = b"snap-sec/1|enrollment-transport"
_INFO_SESSION = b"snap-sec/1|session-data"
_SALT = b"snap-sec/1|static-salt"

NONCE_LEN = 12
KEY_LEN = 32
MAX_CLOCK_SKEW = 300


class CryptoError(Exception):
    """Errore di protocollo o di autenticazione della busta cifrata."""


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except (ValueError, TypeError) as exc:
        raise CryptoError("base64 non valido: %s" % exc) from exc


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def token_fingerprint(token: str) -> str:
    """Impronta del token dichiarata in chiaro al server come indice di ricerca."""
    return sha256_hex(token.encode("utf-8"))


def generate_keypair() -> tuple[str, str]:
    private = X25519PrivateKey.generate()
    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64e(private_raw), b64e(public_raw)


def derive_session_key(private_b64: str, peer_public_b64: str) -> str:
    try:
        private = X25519PrivateKey.from_private_bytes(b64d(private_b64))
        peer = X25519PublicKey.from_public_bytes(b64d(peer_public_b64))
    except (ValueError, CryptoError) as exc:
        raise CryptoError("materiale di chiave non valido: %s" % exc) from exc

    shared = private.exchange(peer)
    key = HKDF(
        algorithm=hashes.SHA256(), length=KEY_LEN, salt=_SALT, info=_INFO_SESSION
    ).derive(shared)
    return b64e(key)


def derive_enrollment_key(enrollment_token: str, probe_code: str) -> str:
    material = ("%s|%s" % (enrollment_token, probe_code)).encode("utf-8")
    key = HKDF(
        algorithm=hashes.SHA256(), length=KEY_LEN, salt=_SALT, info=_INFO_ENROLL
    ).derive(material)
    return b64e(key)


@dataclass(frozen=True)
class Envelope:
    version: str
    probe_id: str
    nonce: str
    timestamp: int
    ciphertext: str

    def to_dict(self) -> dict:
        return {
            "v": self.version,
            "probe": self.probe_id,
            "nonce": self.nonce,
            "ts": self.timestamp,
            "data": self.ciphertext,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "Envelope":
        try:
            return cls(
                version=str(payload["v"]),
                probe_id=str(payload["probe"]),
                nonce=str(payload["nonce"]),
                timestamp=int(payload["ts"]),
                ciphertext=str(payload["data"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CryptoError("busta malformata: %s" % exc) from exc


def _aad(version: str, probe_id: str, nonce: str, timestamp: int, path: str) -> bytes:
    return ("%s|%s|%s|%d|%s" % (version, probe_id, nonce, timestamp, path)).encode("utf-8")


def seal(key_b64: str, probe_id: str, path: str, payload: dict) -> dict:
    key = b64d(key_b64)
    if len(key) != KEY_LEN:
        raise CryptoError("lunghezza chiave di sessione non valida")

    nonce_raw = os.urandom(NONCE_LEN)
    nonce = b64e(nonce_raw)
    timestamp = int(time.time())
    aad = _aad(PROTOCOL_VERSION, probe_id, nonce, timestamp, path)
    plaintext = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce_raw, plaintext, aad)

    return Envelope(
        version=PROTOCOL_VERSION,
        probe_id=probe_id,
        nonce=nonce,
        timestamp=timestamp,
        ciphertext=b64e(ciphertext),
    ).to_dict()


def open_envelope(
    key_b64: str,
    envelope: dict,
    path: str,
    expected_probe_id: str | None = None,
    max_skew: int = MAX_CLOCK_SKEW,
) -> dict:
    """Verifica e decifra la risposta del server."""
    env = Envelope.from_dict(envelope)

    if env.version != PROTOCOL_VERSION:
        raise CryptoError("versione di protocollo non supportata: %s" % env.version)
    if expected_probe_id is not None and env.probe_id != expected_probe_id:
        raise CryptoError("identita' nella busta non corrispondente alla sonda")

    skew = abs(int(time.time()) - env.timestamp)
    if skew > max_skew:
        raise CryptoError("timestamp del server fuori finestra (%ds)" % skew)

    nonce_raw = b64d(env.nonce)
    if len(nonce_raw) != NONCE_LEN:
        raise CryptoError("nonce di lunghezza non valida")

    aad = _aad(env.version, env.probe_id, env.nonce, env.timestamp, path)
    try:
        plaintext = AESGCM(b64d(key_b64)).decrypt(nonce_raw, b64d(env.ciphertext), aad)
    except InvalidTag as exc:
        raise CryptoError("risposta non autentica (tag GCM non valido)") from exc

    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CryptoError("risposta non decodificabile: %s" % exc) from exc
    if not isinstance(payload, dict):
        raise CryptoError("la risposta deve essere un oggetto JSON")
    return payload
