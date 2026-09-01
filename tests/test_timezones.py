"""
snap - Test della normalizzazione oraria.

Copre i due lati del sistema: presentazione del server e presentazione della
sonda, verificando che ogni istante sia mostrato nel fuso orario del tenant e
che l'ora legale sia applicata per singolo istante.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest

from conftest import prepara_accesso_sonda


# --------------------------------------------------------------------------- #
# Utility
# --------------------------------------------------------------------------- #
def _set_timezone(server_app, code: str, zone: str) -> int:
    with server_app.app_context():
        from snapserver.db import execute, query

        tenant = query("SELECT id FROM tenants WHERE code = ?", (code,), one=True)
        execute("UPDATE tenants SET timezone = ? WHERE id = ?", (zone, int(tenant["id"])))
        return int(tenant["id"])


def _login(server_app, email: str, password: str = "Snap!Tenant2026"):
    client = server_app.test_client()
    response = client.post(
        "/login", data={"email": email, "password": password}, follow_redirects=True
    )
    assert response.status_code == 200
    return client


# --------------------------------------------------------------------------- #
# Server: presentazione
# --------------------------------------------------------------------------- #
def _seed_probe(server_app, tenant_id: int, code: str, moment: str) -> None:
    """Sonda con istanti noti, usata per osservare la presentazione oraria."""
    with server_app.app_context():
        from snapserver.db import execute

        execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, enrolled_at,"
            " last_seen_at, last_sync_at, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)",
            (tenant_id, "uid-" + code, code, "Sonda " + code, moment, moment, moment,
             moment, moment),
        )


@pytest.mark.parametrize(
    "zone,atteso",
    [
        ("Europe/Rome", "15/01/2026 13:00"),
        ("America/New_York", "15/01/2026 07:00"),
        ("Asia/Tokyo", "15/01/2026 21:00"),
        ("UTC", "15/01/2026 12:00"),
    ],
)
def test_probe_dates_follow_tenant_timezone(server_app, zone, atteso):
    tenant_id = _set_timezone(server_app, "ised", zone)
    _seed_probe(server_app, tenant_id, "tz-sonda", "2026-01-15 12:00:00")

    body = _login(server_app, "admin@ised.local").get("/probes/").data.decode("utf-8")
    assert atteso in body, "atteso l'orario %s per il fuso %s" % (atteso, zone)


def test_daylight_saving_is_applied(server_app):
    """L'ora legale e' gestita per singolo istante, non con uno scarto fisso."""
    tenant_id = _set_timezone(server_app, "ised", "Europe/Rome")
    # Gennaio: UTC+1; luglio: UTC+2.
    _seed_probe(server_app, tenant_id, "inverno", "2026-01-15 12:00:00")
    _seed_probe(server_app, tenant_id, "estate", "2026-07-15 12:00:00")

    body = _login(server_app, "admin@ised.local").get("/probes/").data.decode("utf-8")
    assert "15/01/2026 13:00" in body, "gennaio: atteso UTC+1"
    assert "15/07/2026 14:00" in body, "luglio: atteso UTC+2 (ora legale)"


# --------------------------------------------------------------------------- #
# Sonda: presentazione locale
# --------------------------------------------------------------------------- #
@pytest.fixture()
def probe_app(tmp_path, monkeypatch):
    """Applicativo sonda con archivio temporaneo e agente non avviato."""
    import importlib

    monkeypatch.setenv("SNAP_PROBE_STORE", str(tmp_path / "probe.sqlite3"))
    monkeypatch.setenv("SNAP_PROBE_SECRET_KEY", "test-secret-key")

    import snapprobe
    import snapprobe.settings as probe_settings

    importlib.reload(probe_settings)
    importlib.reload(snapprobe)

    application = snapprobe.create_app(probe_settings.TestConfig, start_agent=False)
    application.config["STORE_PATH"] = str(tmp_path / "probe.sqlite3")
    # L'interfaccia richiede l'accesso: vedi prepara_accesso_sonda in conftest.py.
    return prepara_accesso_sonda(application)


@pytest.mark.parametrize(
    "zone,atteso",
    [
        ("Europe/Rome", "15/01/2026 13:00"),
        ("America/New_York", "15/01/2026 07:00"),
        ("Asia/Tokyo", "15/01/2026 21:00"),
    ],
)
def test_probe_interface_uses_tenant_timezone(probe_app, zone, atteso):
    """Anche la sonda presenta gli istanti nel fuso del tenant, non in UTC."""
    store = probe_app.extensions["snap_store"]
    store.set_settings(
        {
            "tenant_timezone": zone,
            "tenant_name": "Tenant di prova",
            "probe_code": "sonda-tz",
            "probe_uid": "uid-tz",
            "session_key": "chiave-finta",
            "api_key": "api-finta",
            "enrolled_at": "2026-01-15 12:00:00",
            "last_contact_at": "2026-01-15 12:00:00",
            "last_sync_at": "2026-01-15 12:00:00",
        }
    )
    store.record_sync("lotto-tz", 3, "accepted", "prova")

    body = probe_app.test_client().get("/").data.decode("utf-8")
    assert atteso in body, "atteso %s nel fuso %s" % (atteso, zone)
    assert zone in body, "il fuso in uso deve essere dichiarato nell'interfaccia"


def test_probe_declares_utc_when_not_enrolled(probe_app):
    """Senza registrazione il fuso del tenant non e' noto: si dichiara UTC."""
    body = probe_app.test_client().get("/").data.decode("utf-8")
    assert "UTC" in body
    assert "non noto" in body


def test_probe_queue_and_diary_dates_are_converted(probe_app):
    store = probe_app.extensions["snap_store"]
    store.set_setting("tenant_timezone", "Asia/Tokyo")
    store.enqueue("asset", {"asset_uid": "a-1"})
    store.log("info", "Evento di prova")

    client = probe_app.test_client()
    for path in ("/configuration", "/diary"):
        body = client.get(path).data.decode("utf-8")
        assert "Asia/Tokyo" in body or "JST" in body, "fuso non dichiarato in %s" % path
        # Nessuna data nel formato di persistenza (aaaa-mm-gg) deve raggiungere la pagina.
        import re

        grezze = re.findall(r"<td[^>]*>\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s*<", body)
        assert not grezze, "date non convertite in %s: %s" % (path, grezze)
