"""
snap - Test del dato grezzo di un dispositivo in JSON.

L'interfaccia presenta cio' che il prodotto ha CAPITO; questo documento serve al
contrario: tutto quello che c'e', senza interpretazione. Le prove qui verificano le
tre cose per cui esiste -- verificare un verdetto, portare fuori un dispositivo,
capire un difetto -- e i due limiti che non deve violare: niente dati di altri
tenant, niente segreti.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json


def _tenant_id(server_app):
    with server_app.app_context():
        from snapserver.db import query

        return int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])


def _nodo_completo(server_app, tenant_id, ip="10.8.0.7"):
    """Un dispositivo con addosso tutto cio' che il prodotto sa conservare."""
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        subnet_id = execute(
            "INSERT INTO subnets (tenant_id, cidr, label, host_count, is_enabled, zone,"
            " imported_at, created_at, updated_at)"
            " VALUES (?, '10.8.0.0/24', 'sede', 254, 1, 'datacenter', ?, ?, ?)",
            (tenant_id, adesso, adesso, adesso))
        node_id = execute(
            "INSERT INTO nodes (tenant_id, subnet_id, ip, hostname, mac, mac_vendor,"
            " status, os_name, device_type, device_label, device_confidence,"
            " fingerprint_json, catalog_version, first_seen_at, last_seen_at,"
            " created_at, updated_at)"
            " VALUES (?, ?, ?, 'srv.local', 'AA:BB:CC:DD:EE:FF', 'Dell Inc.', 'up',"
            " 'Linux 5.x', 'server', 'Server Linux', 88, ?, '3', ?, ?, ?, ?)",
            (tenant_id, subnet_id, ip,
             json.dumps({"verdict": {"device_type": "server", "confidence": 88},
                         "evidence": [{"kind": "port", "value": "tcp/22", "weight": 4}]}),
             adesso, adesso, adesso, adesso))
        execute("INSERT INTO node_ports (tenant_id, node_id, protocol, port, state,"
                " service_name, product, version, is_suspect, first_seen_at, last_seen_at)"
                " VALUES (?, ?, 'tcp', 22, 'open', 'ssh', 'OpenSSH', '8.9', 0, ?, ?)",
                (tenant_id, node_id, adesso, adesso))
        execute("INSERT INTO node_snmp (tenant_id, node_id, script_id, output,"
                " collected_at) VALUES (?, ?, 'snmp-info', 'sysDescr: Linux srv', ?)",
                (tenant_id, node_id, adesso))
        execute("INSERT INTO node_changes (tenant_id, node_id, kind, subject,"
                " before_value, after_value, severity, created_at)"
                " VALUES (?, ?, 'port.opened', 'tcp/22', '', 'ssh', 'warning', ?)",
                (tenant_id, node_id, adesso))
        execute("INSERT INTO monitor_samples (tenant_id, node_id, checked_at, reachable,"
                " latency_ms) VALUES (?, ?, ?, 1, 4.2)", (tenant_id, node_id, adesso))
        execute("INSERT INTO ti_findings (tenant_id, node_id, kind, severity, title,"
                " status, evidence, first_seen_at, last_seen_at)"
                " VALUES (?, ?, 'exposure', 'medium', 'Accesso remoto SSH raggiungibile',"
                " 'open', 'tcp/22 aperta', ?, ?)",
                (tenant_id, node_id, adesso, adesso))
        return node_id


def _documento(server_app, tenant_id, node_id):
    with server_app.app_context():
        from snapserver.node_json import documento

        return documento(tenant_id, node_id)


# --------------------------------------------------------------------------- #
# Contenuto
# --------------------------------------------------------------------------- #
def test_il_documento_raccoglie_tutto_cio_che_si_conserva(server_app):
    tenant_id = _tenant_id(server_app)
    node_id = _nodo_completo(server_app, tenant_id)

    dati = _documento(server_app, tenant_id, node_id)

    assert dati["formato"] == "snap.node/1", "il formato e' dichiarato e versionato"
    assert dati["identita"]["ip"] == "10.8.0.7"
    assert dati["identita"]["mac_vendor"] == "Dell Inc."
    assert dati["collocazione"]["subnet"] == "10.8.0.0/24"
    assert dati["collocazione"]["zona_nome"] == "Datacenter", (
        "la zona non e' una chiave da decifrare: si scrive anche il nome")
    assert dati["porte"][0]["port"] == 22
    assert dati["riscontri"][0]["title"].startswith("Accesso remoto SSH")
    assert dati["letture_snmp"][0]["script"] == "snmp-info"
    assert dati["variazioni"][0]["kind"] == "port.opened"
    assert dati["campioni_di_raggiungibilita"][0]["reachable"] == 1


def test_il_documento_porta_le_prove_del_verdetto(server_app):
    """E' la ragione principale per cui esiste: se il prodotto dice "server all'88%",
    la domanda successiva e' "in base a che cosa"."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo_completo(server_app, tenant_id, ip="10.8.0.8")

    dati = _documento(server_app, tenant_id, node_id)

    riconoscimento = dati["riconoscimento"]
    assert riconoscimento["confidenza"] == 88
    assert riconoscimento["etichetta"] == "Server Linux"
    assert riconoscimento["prove"]["evidence"][0]["value"] == "tcp/22"
    assert riconoscimento["versione_catalogo"] == "3", (
        "con quale catalogo e' stato deciso: un verdetto cambia se il catalogo cambia")


def test_i_conteggi_dicono_quanto_c_e(server_app):
    tenant_id = _tenant_id(server_app)
    node_id = _nodo_completo(server_app, tenant_id, ip="10.8.0.9")

    dati = _documento(server_app, tenant_id, node_id)

    assert dati["conteggi"]["porte"] == 1
    assert dati["conteggi"]["porte_aperte"] == 1
    assert dati["conteggi"]["riscontri"] == 1
    assert dati["conteggi"]["letture_snmp"] == 1
    assert dati["limiti"]["porte"] > 0, "i limiti sono dichiarati, non impliciti"


def test_un_campo_illeggibile_viene_dichiarato_non_nascosto(server_app):
    """Cio' che non si puo' leggere e' un'informazione: nasconderlo renderebbe il
    documento piu' pulito e meno vero."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo_completo(server_app, tenant_id, ip="10.8.0.10")
    with server_app.app_context():
        from snapserver.db import execute

        execute("UPDATE nodes SET fingerprint_json = '{rotto' WHERE id = ?", (node_id,))

    dati = _documento(server_app, tenant_id, node_id)

    prove = dati["riconoscimento"]["prove"]
    assert prove["_illeggibile"] == "nodes.fingerprint_json"
    assert prove["_motivo"], "si dice anche perche' non si e' potuto leggere"


def test_il_documento_non_porta_segreti(server_app):
    """Si allega a una segnalazione: non deve portare fuori chiavi ne' community."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo_completo(server_app, tenant_id, ip="10.8.0.11")

    with server_app.app_context():
        from snapserver.node_json import testo

        contenuto = testo(tenant_id, node_id)

    minuscolo = contenuto.lower()
    for parola in ('"community"', '"token"', '"api_key"', '"password"',
                   '"session_key"', '"secret"'):
        assert parola not in minuscolo, "il documento contiene %s" % parola
    assert "nessuna scansione" in contenuto, (
        "va detto che il documento viene dall'archivio, non da una scansione appena"
        " fatta")


# --------------------------------------------------------------------------- #
# Isolamento e accesso
# --------------------------------------------------------------------------- #
def test_un_dispositivo_di_un_altro_tenant_non_esiste(server_app):
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        altro = execute(
            "INSERT INTO tenants (code, name, timezone, locale, retention_days,"
            " is_active, created_at, updated_at)"
            " VALUES ('altrojson', 'Altro', 'UTC', 'it', 365, 1, ?, ?)", (adesso, adesso))
    estraneo = _nodo_completo(server_app, altro, ip="10.99.0.1")

    assert _documento(server_app, tenant_id, estraneo) is None


def test_la_rotta_serve_il_documento_e_lo_scarico(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    node_id = _nodo_completo(server_app, tenant_id, ip="10.8.0.12")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.get("/inventory/nodes/%d/json" % node_id)
    assert risposta.status_code == 200
    assert risposta.mimetype == "application/json"
    assert json.loads(risposta.get_data(as_text=True))["identita"]["ip"] == "10.8.0.12"

    scarico = logged_client.get("/inventory/nodes/%d/json?download=1" % node_id)
    assert scarico.status_code == 200
    assert "attachment" in scarico.headers["Content-Disposition"]
    assert "10-8-0-12" in scarico.headers["Content-Disposition"], (
        "il nome del file porta l'indirizzo: dieci allegati chiamati nodo.json non si"
        " distinguono")


def test_lo_scarico_resta_nel_registro(logged_client, server_app):
    """Un documento che esce dal prodotto lascia una traccia di chi l'ha portato
    fuori (NIS2, tracciabilita')."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo_completo(server_app, tenant_id, ip="10.8.0.13")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    logged_client.get("/inventory/nodes/%d/json?download=1" % node_id)

    with server_app.app_context():
        from snapserver.db import query

        tracce = query("SELECT description FROM audit_events"
                       " WHERE event_type = 'node.json.downloaded'", ())
    assert tracce, "lo scarico va registrato"
    assert "10.8.0.13" in tracce[0]["description"]


def test_la_lettura_nel_browser_non_viene_registrata(logged_client, server_app):
    """Aprire una pagina non e' portare fuori un file: registrare ogni sguardo
    riempirebbe il registro e renderebbe invisibili le estrazioni vere."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo_completo(server_app, tenant_id, ip="10.8.0.14")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    logged_client.get("/inventory/nodes/%d/json" % node_id)

    with server_app.app_context():
        from snapserver.db import query

        tracce = query("SELECT description FROM audit_events"
                       " WHERE event_type = 'node.json.downloaded'"
                       " AND description LIKE '%10.8.0.14%'", ())
    assert not tracce


def test_serve_l_accesso(server_client, server_app):
    tenant_id = _tenant_id(server_app)
    node_id = _nodo_completo(server_app, tenant_id, ip="10.8.0.15")

    risposta = server_client.get("/inventory/nodes/%d/json" % node_id)

    assert risposta.status_code in (302, 401)


def test_il_pulsante_sta_nella_pagina_del_dispositivo(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    node_id = _nodo_completo(server_app, tenant_id, ip="10.8.0.16")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/nodes/%d" % node_id).get_data(as_text=True)

    assert "/json" in pagina
    assert "download=1" in pagina, "si puo' anche salvare, non solo guardare"
