# -----------------------------------------------------------------
# test_export_subnet.py — esportazione delle subnet di un tenant in .txt
# Autore: Daniele Speziale
# Data creazione: 2026-09-04
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""Da Impostazioni Sistema si esportano le subnet di un tenant in un file di testo,
un CIDR per riga, in ordine numerico."""

from __future__ import annotations


def _tenant_id(server_app) -> int:
    with server_app.app_context():
        from snapserver.db import query

        return int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])


def _subnet(server_app, tenant_id, *cidr):
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        for c in cidr:
            execute("INSERT INTO subnets (tenant_id, cidr, host_count, is_enabled,"
                    " created_at, updated_at) VALUES (?, ?, 254, 1, ?, ?)",
                    (tenant_id, c, adesso, adesso))


def test_esporta_le_subnet_in_txt_riga_per_riga(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    _subnet(server_app, tenant_id, "10.2.100.0/24", "10.2.20.0/24", "10.10.1.0/24")

    r = logged_client.get("/admin/tenants/%d/subnets.txt" % tenant_id)
    assert r.status_code == 200
    assert r.mimetype == "text/plain"
    assert "attachment" in r.headers.get("Content-Disposition", "")

    righe = [x for x in r.get_data(as_text=True).splitlines() if x]
    # Un CIDR per riga, in ordine NUMERICO (non alfabetico: .20 prima di .100).
    assert righe == ["10.2.20.0/24", "10.2.100.0/24", "10.10.1.0/24"]


def test_un_tenant_senza_subnet_produce_un_file_vuoto(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    r = logged_client.get("/admin/tenants/%d/subnets.txt" % tenant_id)
    assert r.status_code == 200
    assert r.get_data(as_text=True) == ""


def test_la_pagina_impostazioni_offre_l_esportazione(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    _subnet(server_app, tenant_id, "10.0.0.0/24")
    corpo = logged_client.get("/admin/settings").get_data(as_text=True)
    assert "Esporta le subnet" in corpo
    assert "/subnets.txt" in corpo, "il collegamento di esportazione deve comparire"
