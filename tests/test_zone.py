"""
snap - Zone di rete: il contesto che decide se un'esposizione e' un problema.

La proprieta' centrale e' che lo stesso servizio riceve giudizi diversi a seconda di
dove si trova, e che nulla viene cancellato: un'esposizione attesa resta in archivio
con la sua motivazione, e se la zona cambia torna aperta da se'.

remarks: Autore: Daniele Speziale - Data: 2026-08-29
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations


# --------------------------------------------------------------------------- #
# Preparazione
# --------------------------------------------------------------------------- #
def _tenant_id(server_app):
    with server_app.app_context():
        from snapserver.db import query

        return int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])


def _subnet(server_app, tenant_id, cidr="10.9.0.0/24", zona=""):
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        return execute(
            "INSERT INTO subnets (tenant_id, cidr, zone, host_count, is_enabled,"
            " imported_at, created_at, updated_at) VALUES (?, ?, ?, 254, 1, ?, ?, ?)",
            (tenant_id, cidr, zona, adesso, adesso, adesso))


def _nodo_con_porta(server_app, tenant_id, subnet_id, ip, porta, servizio="ssh",
                    protocollo="tcp"):
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        node_id = execute(
            "INSERT INTO nodes (tenant_id, subnet_id, ip, status, device_type,"
            " device_label, device_confidence, first_seen_at, last_seen_at,"
            " created_at, updated_at)"
            " VALUES (?, ?, ?, 'up', 'server', 'Server Linux', 90, ?, ?, ?, ?)",
            (tenant_id, subnet_id, ip, adesso, adesso, adesso, adesso))
        execute(
            "INSERT INTO node_ports (tenant_id, node_id, protocol, port, state,"
            " service_name, is_suspect, first_seen_at, last_seen_at)"
            " VALUES (?, ?, ?, ?, 'open', ?, 0, ?, ?)",
            (tenant_id, node_id, protocollo, porta, servizio, adesso, adesso))
        return node_id


def _correla(server_app, tenant_id):
    with server_app.app_context():
        from snapserver import threat

        return threat.correlate(tenant_id)


def _riscontri(server_app, tenant_id, node_id):
    with server_app.app_context():
        from snapserver.db import query

        return [dict(r) for r in query(
            "SELECT kind, title, severity, status, evidence FROM ti_findings"
            " WHERE tenant_id = ? AND node_id = ?", (tenant_id, node_id))]


# --------------------------------------------------------------------------- #
# Catalogo delle zone
# --------------------------------------------------------------------------- #
def test_una_zona_non_dichiarata_vale_come_la_piu_severa():
    """Il silenzio non deve valere come giustificazione."""
    from snapserver import zones

    assert zones.valida("") == zones.ZONA_PREDEFINITA
    assert zones.valida("inventata") == zones.ZONA_PREDEFINITA
    assert zones.valida("datacenter") == "datacenter"
    assert zones.zona("")["chiave"] == "utenza"


def test_lo_stesso_servizio_riceve_giudizi_diversi():
    """SSH in un datacenter e' il modo in cui i sistemi si amministrano; SSH in una
    rete ospiti significa che qualcosa e' finito nella rete sbagliata."""
    from snapserver import zones

    ssh = "Accesso remoto SSH raggiungibile"
    assert zones.giudizio("datacenter", ssh) == zones.ATTESA
    assert zones.giudizio("gestione", ssh) == zones.ATTESA
    assert zones.giudizio("utenza", ssh) == zones.NORMALE
    assert zones.giudizio("ospiti", ssh) == zones.VIOLAZIONE
    assert zones.giudizio("dmz", ssh) == zones.VIOLAZIONE


def test_una_violazione_alza_la_gravita_e_non_la_abbassa_mai():
    from snapserver import zones

    esito, gravita, motivo = zones.applica("ospiti", "Telnet: credenziali in chiaro",
                                           "high")
    assert esito == zones.VIOLAZIONE
    assert gravita == "critical"
    assert "Violazione" in motivo

    esito, gravita, motivo = zones.applica("datacenter",
                                           "Accesso remoto SSH raggiungibile", "medium")
    assert esito == zones.ATTESA
    assert gravita == "medium", "l'attesa non cambia la gravita', cambia lo stato"
    assert "Atteso in zona" in motivo


# --------------------------------------------------------------------------- #
# Effetto sulla correlazione
# --------------------------------------------------------------------------- #
def test_in_un_datacenter_ssh_non_conta_fra_i_riscontri_aperti(server_app):
    tenant_id = _tenant_id(server_app)
    subnet_id = _subnet(server_app, tenant_id, "10.9.1.0/24", "datacenter")
    node_id = _nodo_con_porta(server_app, tenant_id, subnet_id, "10.9.1.10", 22)
    _correla(server_app, tenant_id)

    riscontri = _riscontri(server_app, tenant_id, node_id)
    assert len(riscontri) == 1
    voce = riscontri[0]
    assert voce["status"] == "expected", "atteso nel contesto, non aperto"
    assert "Atteso in zona datacenter" in voce["evidence"], (
        "la motivazione deve essere leggibile nel riscontro")

    with server_app.app_context():
        from snapserver.threat import summary

        riepilogo = summary(tenant_id)
    assert riepilogo["esposizioni"] == 0, "non conta fra le aperte"
    assert riepilogo["attesi"] == 1
    assert riepilogo["attesi_per_zona"].get("datacenter") == 1


def test_nella_rete_di_utenza_lo_stesso_servizio_resta_aperto(server_app):
    tenant_id = _tenant_id(server_app)
    subnet_id = _subnet(server_app, tenant_id, "10.9.2.0/24", "utenza")
    node_id = _nodo_con_porta(server_app, tenant_id, subnet_id, "10.9.2.10", 22)
    _correla(server_app, tenant_id)

    voce = _riscontri(server_app, tenant_id, node_id)[0]
    assert voce["status"] == "open"
    assert "Atteso in zona" not in voce["evidence"]


def test_in_una_rete_ospiti_lo_stesso_servizio_e_una_violazione(server_app):
    tenant_id = _tenant_id(server_app)
    subnet_id = _subnet(server_app, tenant_id, "10.9.3.0/24", "ospiti")
    node_id = _nodo_con_porta(server_app, tenant_id, subnet_id, "10.9.3.10", 22)
    _correla(server_app, tenant_id)

    voce = _riscontri(server_app, tenant_id, node_id)[0]
    assert voce["status"] == "open"
    assert voce["severity"] == "high", "la gravita' sale rispetto a medium"
    assert "Violazione della zona" in voce["evidence"]


def test_cambiare_zona_riapre_i_riscontri_che_non_sono_piu_attesi(server_app):
    """Non si cancella nulla: se la zona cambia, la rivalutazione riapre da se'."""
    tenant_id = _tenant_id(server_app)
    subnet_id = _subnet(server_app, tenant_id, "10.9.4.0/24", "datacenter")
    node_id = _nodo_con_porta(server_app, tenant_id, subnet_id, "10.9.4.10", 22)
    _correla(server_app, tenant_id)
    assert _riscontri(server_app, tenant_id, node_id)[0]["status"] == "expected"

    with server_app.app_context():
        from snapserver.db import execute

        execute("UPDATE subnets SET zone = 'utenza' WHERE id = ?", (subnet_id,))
    _correla(server_app, tenant_id)

    assert _riscontri(server_app, tenant_id, node_id)[0]["status"] == "open"


def test_una_decisione_di_persona_resta_piu_forte_della_zona(server_app):
    """Rischio accettato e falso positivo sono giudizi: la zona e' una regola, e una
    regola non sovrascrive un giudizio (TI-13)."""
    tenant_id = _tenant_id(server_app)
    subnet_id = _subnet(server_app, tenant_id, "10.9.5.0/24", "utenza")
    node_id = _nodo_con_porta(server_app, tenant_id, subnet_id, "10.9.5.10", 22)
    _correla(server_app, tenant_id)

    with server_app.app_context():
        from snapserver import threat
        from snapserver.db import query

        riscontro = query("SELECT id FROM ti_findings WHERE node_id = ?", (node_id,),
                          one=True)
        threat.decide(tenant_id, int(riscontro["id"]), threat.STATUS_ACCEPTED,
                      "accettato in attesa della segmentazione")
    _correla(server_app, tenant_id)

    assert _riscontri(server_app, tenant_id, node_id)[0]["status"] == "accepted"


# --------------------------------------------------------------------------- #
# Pagine e report
# --------------------------------------------------------------------------- #
def test_la_zona_si_dichiara_dalla_pagina_del_perimetro(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    subnet_id = _subnet(server_app, tenant_id, "10.9.6.0/24")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/subnets").get_data(as_text=True)
    assert "Zone di rete" in pagina
    assert "Datacenter" in pagina

    logged_client.post("/inventory/subnets/%d/zone" % subnet_id,
                       data={"zone": "dmz"}, follow_redirects=True)
    with server_app.app_context():
        from snapserver.db import query

        assert query("SELECT zone FROM subnets WHERE id = ?", (subnet_id,),
                     one=True)["zone"] == "dmz"

    # Allowlist: una zona inventata non viene scritta.
    logged_client.post("/inventory/subnets/%d/zone" % subnet_id,
                       data={"zone": "inventata"}, follow_redirects=True)
    with server_app.app_context():
        from snapserver.db import query

        assert query("SELECT zone FROM subnets WHERE id = ?", (subnet_id,),
                     one=True)["zone"] == "utenza"


def test_i_nodi_si_filtrano_per_zona(server_app):
    from snapserver.inventory_queries import nodes_list

    tenant_id = _tenant_id(server_app)
    dentro = _subnet(server_app, tenant_id, "10.9.7.0/24", "datacenter")
    fuori = _subnet(server_app, tenant_id, "10.9.8.0/24", "")
    _nodo_con_porta(server_app, tenant_id, dentro, "10.9.7.10", 22)
    _nodo_con_porta(server_app, tenant_id, fuori, "10.9.8.10", 22)

    with server_app.app_context():
        assert [r["ip"] for r in nodes_list(tenant_id, zone="datacenter")] == ["10.9.7.10"]
        assert [r["ip"] for r in nodes_list(tenant_id, zone="senza")] == ["10.9.8.10"]


def test_il_quadro_soc_misura_la_segmentazione(server_app):
    from snapserver.operations import zone_posture

    tenant_id = _tenant_id(server_app)
    datacenter = _subnet(server_app, tenant_id, "10.9.9.0/24", "datacenter")
    ospiti = _subnet(server_app, tenant_id, "10.9.10.0/24", "ospiti")
    _nodo_con_porta(server_app, tenant_id, datacenter, "10.9.9.10", 22)
    _nodo_con_porta(server_app, tenant_id, ospiti, "10.9.10.10", 22)
    _correla(server_app, tenant_id)

    with server_app.app_context():
        postura = zone_posture(tenant_id)

    per_nome = {z["nome"]: z for z in postura["zone"]}
    assert per_nome["Datacenter"]["attese"] == 1
    assert per_nome["Rete ospiti"]["violazioni"] == 1
    assert postura["attese"] == 1 and postura["violazioni"] == 1


def test_il_report_della_segmentazione_si_genera(server_app):
    from test_report import _testo_pdf

    tenant_id = _tenant_id(server_app)
    datacenter = _subnet(server_app, tenant_id, "10.9.11.0/24", "datacenter")
    _nodo_con_porta(server_app, tenant_id, datacenter, "10.9.11.10", 22)
    _correla(server_app, tenant_id)

    with server_app.app_context():
        from snapserver.db import query
        from snapserver.reports import KIND_SEGMENTATION
        from snapserver.reports.generate import generate
        from snapserver.reports.windows import today_local, zone_of

        tenant = dict(query("SELECT * FROM tenants WHERE id = ?", (tenant_id,),
                            one=True))
        zona = zone_of(tenant)
        percorso = generate(KIND_SEGMENTATION, tenant, today_local(zona), 30)

    testo = _testo_pdf(percorso)
    assert "SEGMENTAZIONE" in testo
    assert "Le zone dichiarate" in testo
    assert "Datacenter" in testo
