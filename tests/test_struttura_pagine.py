"""
snap - Struttura delle pagine con le schede.

Un div di chiusura in eccesso non solleva alcun errore: rompe il resto della pagina in
silenzio. Con quindici pagine riorganizzate a schede questo controllo e' l'unico modo
di sapere che la marcatura resta sana -- e ha trovato un difetto preesistente nel
dettaglio della sonda, che chiudeva un contenitore mai aperto.

Si verifica su cio' che l'applicazione RENDE davvero, non sui modelli: le condizioni
Jinja producono marcature diverse a seconda dei permessi e dei dati presenti.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re

import pytest


def _prepara(server_app) -> dict:
    """Dati minimi perche' ogni pagina abbia qualcosa da mostrare."""
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.db import execute, query, utc_now_str

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
        adesso = utc_now_str()
        target_id = execute(
            "INSERT INTO check_targets (tenant_id, name, address, is_enabled,"
            " created_at, updated_at) VALUES (?, 'Bersaglio', 'collaudo.local', 1, ?, ?)",
            (tenant_id, adesso, adesso))
        check_id = execute(
            "INSERT INTO checks (tenant_id, target_id, name, kind, config_json,"
            " interval_seconds, timeout_seconds, is_enabled, severity,"
            " failure_threshold, escalation_threshold, created_at, updated_at)"
            " VALUES (?, ?, 'salute', 'http', ?, 300, 10, 1, 'warning', 2, 4, ?, ?)",
            (tenant_id, target_id,
             '{"url": "http://x.local/h", "expect_status": 200}', adesso, adesso))
        probe_id = execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status,"
            " scan_interval_sec, created_at, updated_at)"
            " VALUES (?, 'uid-s', 'P-S', 'Sonda', 'active', 300, ?, ?)",
            (tenant_id, adesso, adesso))
        subnet_id = execute(
            "INSERT INTO subnets (tenant_id, cidr, host_count, is_enabled, imported_at,"
            " created_at, updated_at) VALUES (?, '192.0.2.0/24', 254, 1, ?, ?, ?)",
            (tenant_id, adesso, adesso, adesso))
        node_id = execute(
            "INSERT INTO nodes (tenant_id, subnet_id, probe_id, ip, status, device_type,"
            " device_confidence, first_seen_at, last_seen_at, created_at, updated_at)"
            " VALUES (?, ?, ?, '192.0.2.10', 'up', 'server', 80, ?, ?, ?, ?)",
            (tenant_id, subnet_id, probe_id, adesso, adesso, adesso, adesso))
        batch_id = execute(
            "INSERT INTO ingest_batches (tenant_id, probe_id, batch_uid, record_count,"
            " status, received_at) VALUES (?, ?, 'lotto-s', 3, 'accepted', ?)",
            (tenant_id, probe_id, adesso))

        for stato in ("ok", "fail", "fail"):
            record_result(tenant_id, check_id, None,
                          {"status": stato, "latency_ms": 12.0,
                           "payload": {"metrics": {"cpu": 3, "ram": 44}}})
        incidente = query("SELECT id FROM check_incidents ORDER BY id DESC", (), one=True)

    return {"tenant": tenant_id, "target": target_id, "check": check_id,
            "probe": probe_id, "node": node_id, "batch": batch_id,
            "incident": int(incidente["id"]) if incidente else None}


@pytest.fixture()
def pagine(logged_client, server_app):
    """Client autenticato nel tenant, con i dati di prova e i percorsi da visitare."""
    dati = _prepara(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": dati["tenant"]},
                       follow_redirects=True)
    percorsi = [
        "/", "/checks/", "/checks/notifications", "/checks/incidents",
        "/checks/targets/%d" % dati["target"],
        "/checks/checks/%d" % dati["check"],
        "/checks/checks/%d?metric=metrics.cpu" % dati["check"],
        "/checks/checks/%d?scheda=definizione" % dati["check"],
        "/inventory/nodes", "/inventory/nodes/%d" % dati["node"],
        "/inventory/subnets", "/inventory/deliveries",
        "/inventory/deliveries/%d" % dati["batch"],
        "/monitor/", "/monitor/changes",
        "/probes/", "/probes/%d" % dati["probe"], "/probes/new",
        "/admin/settings", "/admin/users", "/profile",
    ]
    if dati["incident"]:
        percorsi.append("/checks/incidents/%d" % dati["incident"])
    return logged_client, percorsi


def test_nessuna_pagina_ha_div_scompensati(pagine):
    """Un div in eccesso o mancante rompe il resto della pagina in silenzio."""
    client, percorsi = pagine
    scompensate = []
    for percorso in percorsi:
        risposta = client.get(percorso)
        assert risposta.status_code == 200, "pagina non raggiungibile: %s" % percorso
        testo = risposta.get_data(as_text=True)
        aperti = len(re.findall(r"<div\b", testo))
        chiusi = testo.count("</div>")
        if aperti != chiusi:
            scompensate.append("%s (%+d)" % (percorso, aperti - chiusi))
    assert not scompensate, "pagine con div scompensati: %s" % scompensate


def test_ogni_scheda_ha_il_proprio_riquadro(pagine):
    """Un pulsante senza riquadro non apre nulla; un riquadro senza pulsante e'
    contenuto irraggiungibile."""
    client, percorsi = pagine
    problemi = []
    for percorso in percorsi:
        testo = client.get(percorso).get_data(as_text=True)
        pulsanti = sorted(set(re.findall(r'data-bs-target="#(pane-[a-z0-9_-]+)"', testo)))
        riquadri = sorted(set(re.findall(
            r'class="tab-pane[^"]*"\s*[^>]{0,60}?id="(pane-[a-z0-9_-]+)"', testo)))
        if pulsanti and pulsanti != riquadri:
            problemi.append("%s: pulsanti %s, riquadri %s"
                            % (percorso, pulsanti, riquadri))
    assert not problemi, "schede spaiate: %s" % problemi


def test_ogni_gruppo_di_schede_ne_ha_una_sola_aperta(pagine):
    """Zero schede aperte lascia il gruppo vuoto; due si sovrappongono.

    Il conteggio e' per GRUPPO e non per pagina: le pagine delle impostazioni hanno un
    secondo livello di schede dentro il primo, e in quel caso le schede aperte sono
    tante quante le barre -- una per ciascun livello.
    """
    client, percorsi = pagine
    problemi = []
    for percorso in percorsi:
        testo = client.get(percorso).get_data(as_text=True)
        if 'data-bs-toggle="tab"' not in testo:
            continue
        barre = len(re.findall(r'<ul class="nav nav-(?:tabs|pills)', testo))
        attivi = len(re.findall(r'class="tab-pane[^"]*\bactive\b', testo))
        if attivi != barre:
            problemi.append("%s: %d barre, %d schede aperte" % (percorso, barre, attivi))
        # Dentro ogni barra un solo pulsante attivo: due pulsanti attivi mostrano una
        # scheda e ne evidenziano un'altra.
        for barra in re.findall(r'<ul class="nav nav-(?:tabs|pills).*?</ul>', testo,
                                re.S):
            attivi_barra = len(re.findall(r'class="nav-link\s+active', barra))
            if attivi_barra != 1:
                problemi.append("%s: barra con %d pulsanti attivi"
                                % (percorso, attivi_barra))
    assert not problemi, "schede aperte non corrette: %s" % problemi


def test_le_pagine_che_impilavano_ora_usano_le_schede(pagine):
    """Le pagine con piu' contenuti distinti non devono richiedere scorrimento."""
    client, percorsi = pagine
    attese = {
        "/checks/targets/": ["pane-controlli", "pane-nuovo"],
        "/checks/checks/": ["pane-andamento", "pane-definizione", "pane-misure",
                            "pane-esiti", "pane-incidenti"],
        "/inventory/nodes/": ["pane-identita", "pane-porte", "pane-storia"],
        "/inventory/subnets": ["pane-subnet", "pane-carica"],
        "/inventory/deliveries": ["pane-lotti", "pane-fasi"],
        "/admin/settings": ["pane-notifiche", "pane-istanza"],
        "/admin/users": ["pane-tenant"],
    }
    for prefisso, riquadri in attese.items():
        percorso = next((p for p in percorsi
                         if p.startswith(prefisso) and "?" not in p), None)
        assert percorso, "nessun percorso per %s" % prefisso
        testo = client.get(percorso).get_data(as_text=True)
        for riquadro in riquadri:
            assert 'id="%s"' % riquadro in testo, "%s: manca %s" % (percorso, riquadro)


def test_un_filtro_resta_nella_scheda_della_propria_tabella(pagine):
    """In un'altra scheda la tabella sembrerebbe non filtrata, ed e' un modo sicuro
    di leggere numeri sbagliati."""
    client, _ = pagine
    for percorso, riquadro in (("/inventory/nodes", "pane-nodi"),
                               ("/inventory/deliveries", "pane-lotti")):
        testo = client.get(percorso).get_data(as_text=True)
        inizio = testo.find('id="%s"' % riquadro)
        assert inizio > 0, "%s: riquadro %s assente" % (percorso, riquadro)
        successivo = testo.find('class="tab-pane', inizio + 10)
        scheda = testo[inizio:successivo if successivo > inizio else len(testo)]
        assert "Filtr" in scheda, (
            "%s: il filtro non sta nella scheda della propria tabella" % percorso)
