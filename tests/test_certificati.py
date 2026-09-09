# -----------------------------------------------------------------
# test_certificati.py — ricerca dei certificati TLS scaduti/in scadenza e resoconto
# Autore: Daniele Speziale
# Data creazione: 2026-09-04
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""I certificati raccolti dai web server si cercano per stato (scaduti, in scadenza) e
la sintesi finisce nel resoconto quotidiano."""

from __future__ import annotations

from datetime import date, timedelta


def _tenant_id(server_app) -> int:
    with server_app.app_context():
        from snapserver.db import query

        return int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])


def _nodo_con_certificati(server_app, tenant_id):
    """Un nodo con tre web server HTTPS: uno scaduto, uno in scadenza, uno valido."""
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        node_id = execute(
            "INSERT INTO nodes (tenant_id, ip, hostname, status, first_seen_at,"
            " last_seen_at, created_at, updated_at)"
            " VALUES (?, '10.9.0.7', 'web.local', 'up', ?, ?, ?, ?)",
            (tenant_id, adesso, adesso, adesso, adesso))
        scadenze = {
            443: date.today() - timedelta(days=10),   # scaduto
            8443: date.today() + timedelta(days=15),  # in scadenza (entro 30)
            9443: date.today() + timedelta(days=400),  # valido
        }
        for porta, scad in scadenze.items():
            execute(
                "INSERT INTO node_web (tenant_id, node_id, port, scheme, cert_subject,"
                " cert_issuer, cert_expires, cert_selfsigned, tls_version, collected_at)"
                " VALUES (?, ?, ?, 'https', ?, 'CA di prova', ?, 0, 'TLSv1.3', ?)",
                (tenant_id, node_id, porta, "CN=web.local:%d" % porta,
                 scad.strftime("%Y-%m-%d"), adesso))
        return node_id


def test_i_certificati_hanno_i_giorni_alla_scadenza(server_app):
    tenant_id = _tenant_id(server_app)
    _nodo_con_certificati(server_app, tenant_id)
    with server_app.app_context():
        from snapserver.inventory_queries import web_certificates

        tutti = web_certificates(tenant_id)
    per_porta = {c["port"]: c for c in tutti}
    assert per_porta[443]["scaduto"] is True and per_porta[443]["giorni"] < 0
    assert 0 <= per_porta[8443]["giorni"] <= 30 and not per_porta[8443]["scaduto"]
    assert per_porta[9443]["giorni"] > 30


def test_si_filtra_per_scaduti_e_in_scadenza(server_app):
    tenant_id = _tenant_id(server_app)
    _nodo_con_certificati(server_app, tenant_id)
    with server_app.app_context():
        from snapserver.inventory_queries import web_certificates

        scaduti = web_certificates(tenant_id, stato="scaduti")
        in_scadenza = web_certificates(tenant_id, stato="in_scadenza")
        validi = web_certificates(tenant_id, stato="validi")
    assert [c["port"] for c in scaduti] == [443]
    assert [c["port"] for c in in_scadenza] == [8443]
    assert [c["port"] for c in validi] == [9443]


def test_la_pagina_certificati_si_apre_e_conta_gli_scaduti(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    _nodo_con_certificati(server_app, tenant_id)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)
    corpo = logged_client.get("/inventory/certificates?stato=scaduti").get_data(
        as_text=True)
    assert "Certificati TLS" in corpo
    assert "scaduto" in corpo
    assert "10.9.0.7" in corpo


def test_il_menu_ha_la_voce_certificati(logged_client):
    corpo = logged_client.get("/", follow_redirects=True).get_data(as_text=True)
    assert "Certificati TLS" in corpo
    assert "/inventory/certificates" in corpo


def test_il_resoconto_quotidiano_riporta_i_certificati(server_app):
    tenant_id = _tenant_id(server_app)
    _nodo_con_certificati(server_app, tenant_id)
    with server_app.app_context():
        from snapserver.db import query
        from snapserver.reports import dataset, render_mail
        from snapserver.reports.windows import today_local, zone_of

        tenant = dict(query("SELECT * FROM tenants WHERE id = ?", (tenant_id,), one=True))
        zona = zone_of(tenant)
        dati = dataset.daily(tenant, today_local(zona), zona)
        cert = dati["certificati"]
        assert cert["n_scaduti"] >= 1 and cert["n_in_scadenza"] >= 1
        testo = render_mail.text_body(dati)
    assert "CERTIFICATI TLS" in testo
    assert "Scaduti:" in testo
