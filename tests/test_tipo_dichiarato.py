"""
snap - Test del tipo di dispositivo dichiarato dall'operatore.

Il riconoscimento pesa le prove, e su un apparato che non parla di se' le prove possono
non bastare: chi conosce la rete sa che quel silenzio e' un PLC di linea. Il prodotto
deve quindi permettere di **dichiarare** il tipo, e la dichiarazione deve resistere a
tutto cio' che ricalcola il verdetto -- ogni conferimento e la rideterminazione
dell'intero inventario. Una dichiarazione che durasse fino alla scansione successiva
sarebbe peggio di non poterla fare: farebbe credere di aver corretto l'inventario.

Le prove qui verificano, nell'ordine: che si possa dichiarare, che la dichiarazione
resista, che si possa tornare all'automatico, che il verdetto automatico continui a
essere calcolato e restare consultabile, e che i limiti (allowlist dei tipi, tenant,
ruolo) tengano.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json

import pytest


@pytest.fixture()
def contesto(server_app):
    """Tenant di lavoro."""
    with server_app.app_context():
        from snapserver.db import query

        return int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])


def _nodo(server_app, tenant_id, ip="10.44.1.10", tipo="unknown",
          etichetta="Non identificato", confidenza=20, porte=(("tcp", 9100),)):
    """Un nodo con qualche porta aperta: le porte servono al riconoscimento."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        adesso = utc_now_str()
        subnet = query("SELECT id FROM subnets WHERE tenant_id = ?", (tenant_id,),
                       one=True)
        subnet_id = int(subnet["id"]) if subnet else execute(
            "INSERT INTO subnets (tenant_id, cidr, host_count, is_enabled, imported_at,"
            " created_at, updated_at) VALUES (?, '10.44.1.0/24', 254, 1, ?, ?, ?)",
            (tenant_id, adesso, adesso, adesso))
        node_id = execute(
            "INSERT INTO nodes (tenant_id, subnet_id, ip, status, device_type,"
            " device_label, device_confidence, first_seen_at, last_seen_at,"
            " created_at, updated_at)"
            " VALUES (?, ?, ?, 'up', ?, ?, ?, ?, ?, ?, ?)",
            (tenant_id, subnet_id, ip, tipo, etichetta, confidenza, adesso, adesso,
             adesso, adesso))
        for protocollo, porta in porte:
            execute(
                "INSERT INTO node_ports (tenant_id, node_id, protocol, port, state,"
                " is_suspect, first_seen_at, last_seen_at)"
                " VALUES (?, ?, ?, ?, 'open', 0, ?, ?)",
                (tenant_id, node_id, protocollo, porta, adesso, adesso))
        return node_id


def _riga(server_app, node_id):
    with server_app.app_context():
        from snapserver.db import query

        return dict(query("SELECT * FROM nodes WHERE id = ?", (node_id,), one=True))


def _entra(logged_client, tenant_id):
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)


# --------------------------------------------------------------------------- #
# Dichiarare
# --------------------------------------------------------------------------- #
def test_il_tipo_si_dichiara_e_vale_cento(logged_client, server_app, contesto):
    """Risponde una persona, non una somma di indizi: il nodo deve uscire dai filtri
    "da verificare", che e' il motivo per cui lo si dichiara."""
    node_id = _nodo(server_app, contesto)
    _entra(logged_client, contesto)

    risposta = logged_client.post(
        "/inventory/nodes/%d/type" % node_id,
        data={"device_type": "plc_industrial",
              "reason": "verificato di persona: PLC di linea 2"},
        follow_redirects=True)
    assert risposta.status_code == 200

    riga = _riga(server_app, node_id)
    assert riga["device_type"] == "plc_industrial"
    assert riga["device_label"] == "Apparato industriale / PLC"
    assert riga["device_confidence"] == 100
    assert riga["device_type_source"] == "manual"
    assert "@" in (riga["device_type_by"] or ""), "chi ha dichiarato deve restare"
    assert riga["device_type_at"]
    assert riga["device_type_reason"] == "verificato di persona: PLC di linea 2"


def test_la_dichiarazione_entra_nella_storia_del_nodo_e_nel_registro(
        logged_client, server_app, contesto):
    """Chi legge i cambiamenti deve vedere anche quelli decisi da una persona."""
    node_id = _nodo(server_app, contesto)
    _entra(logged_client, contesto)
    logged_client.post("/inventory/nodes/%d/type" % node_id,
                       data={"device_type": "ups"}, follow_redirects=True)

    with server_app.app_context():
        from snapserver.db import query

        cambiamento = query(
            "SELECT * FROM node_changes WHERE node_id = ? AND kind = ?",
            (node_id, "device_type.declared"), one=True)
        evento = query("SELECT * FROM audit_events WHERE event_type = ?",
                       ("node.type.declared",), one=True)

    assert cambiamento is not None
    assert cambiamento["before_value"] == "Non identificato"
    assert cambiamento["after_value"] == "Gruppo di continuita'"
    assert evento is not None and "10.44.1.10" in evento["description"]


def test_un_tipo_inventato_viene_rifiutato(logged_client, server_app, contesto):
    """Il tipo alimenta filtri, conteggi e report: un valore fuori catalogo li
    romperebbe in silenzio. Allowlist, non blocklist."""
    node_id = _nodo(server_app, contesto)
    _entra(logged_client, contesto)

    risposta = logged_client.post("/inventory/nodes/%d/type" % node_id,
                                  data={"device_type": "tostapane"},
                                  follow_redirects=True)

    assert "non previsto" in risposta.get_data(as_text=True)
    assert _riga(server_app, node_id)["device_type_source"] == "auto"


def test_la_motivazione_non_supera_la_lunghezza_prevista(
        logged_client, server_app, contesto):
    node_id = _nodo(server_app, contesto)
    _entra(logged_client, contesto)
    logged_client.post("/inventory/nodes/%d/type" % node_id,
                       data={"device_type": "nas", "reason": "x" * 500},
                       follow_redirects=True)

    assert len(_riga(server_app, node_id)["device_type_reason"]) == 300


# --------------------------------------------------------------------------- #
# Resistere ai ricalcoli: e' la ragione per cui la funzione esiste
# --------------------------------------------------------------------------- #
def test_la_dichiarazione_resiste_al_ricalcolo_del_verdetto(
        logged_client, server_app, contesto):
    """La porta 9100 farebbe dire "stampante" al riconoscimento: dopo la
    dichiarazione il tipo non deve piu' cambiare."""
    node_id = _nodo(server_app, contesto)
    _entra(logged_client, contesto)
    logged_client.post("/inventory/nodes/%d/type" % node_id,
                       data={"device_type": "plc_industrial"}, follow_redirects=True)

    with server_app.app_context():
        from snapserver.ingest import refresh_fingerprint

        verdetto = refresh_fingerprint(contesto, node_id)

    riga = _riga(server_app, node_id)
    assert riga["device_type"] == "plc_industrial", (
        "il ricalcolo ha travolto la dichiarazione: durerebbe fino alla scansione"
        " successiva")
    assert riga["device_confidence"] == 100
    assert verdetto.get("declared") is True and verdetto.get("applied") is False


def test_il_verdetto_automatico_continua_a_essere_calcolato_e_conservato(
        logged_client, server_app, contesto):
    """Mostrare il disaccordo e' il modo in cui si scopre che il catalogo delle firme
    va corretto: nasconderlo trasformerebbe un difetto in un dato."""
    node_id = _nodo(server_app, contesto)
    _entra(logged_client, contesto)
    logged_client.post("/inventory/nodes/%d/type" % node_id,
                       data={"device_type": "plc_industrial"}, follow_redirects=True)

    with server_app.app_context():
        from snapserver.ingest import refresh_fingerprint

        refresh_fingerprint(contesto, node_id)

    conservato = json.loads(_riga(server_app, node_id)["fingerprint_json"] or "{}")
    assert conservato.get("verdict"), "le prove e il verdetto automatico devono restare"
    assert conservato["verdict"]["device_type"] == "printer", (
        "il riconoscimento deve continuare a dire cio' che pensa")

    pagina = logged_client.get("/inventory/nodes/%d" % node_id).get_data(as_text=True)
    assert "dichiarato dall'operatore" in pagina
    assert "Il riconoscimento automatico direbbe" in pagina
    assert "Stampante / multifunzione" in pagina


def test_la_rideterminazione_dell_inventario_rispetta_le_dichiarazioni(
        logged_client, server_app, contesto):
    """E' il caso che rende inutile tutto il resto se sbagliato: la rideterminazione
    passa su tutti i nodi."""
    dichiarato = _nodo(server_app, contesto, ip="10.44.1.11")
    automatico = _nodo(server_app, contesto, ip="10.44.1.12")
    _entra(logged_client, contesto)
    logged_client.post("/inventory/nodes/%d/type" % dichiarato,
                       data={"device_type": "plc_industrial"}, follow_redirects=True)

    with server_app.app_context():
        from snapserver.ingest import refingerprint_tenant

        esito = refingerprint_tenant(contesto)

    assert _riga(server_app, dichiarato)["device_type"] == "plc_industrial"
    assert esito["declared"] >= 1, (
        "il numero dei tipi rispettati va dichiarato: senza, l'operatore non sa se le"
        " sue dichiarazioni sono state travolte")
    assert _riga(server_app, automatico)["device_type"] == "printer", (
        "un nodo senza dichiarazione deve continuare a essere rideterminato")


# --------------------------------------------------------------------------- #
# Tornare all'automatico
# --------------------------------------------------------------------------- #
def test_si_torna_al_riconoscimento_automatico_e_il_tipo_viene_ricalcolato(
        logged_client, server_app, contesto):
    """Una pagina che dicesse "automatico" mostrando ancora il tipo dichiarato
    mentirebbe: il ricalcolo avviene subito."""
    node_id = _nodo(server_app, contesto)
    _entra(logged_client, contesto)
    logged_client.post("/inventory/nodes/%d/type" % node_id,
                       data={"device_type": "plc_industrial", "reason": "prova"},
                       follow_redirects=True)

    risposta = logged_client.post("/inventory/nodes/%d/type" % node_id,
                                  data={"device_type": "__auto__"},
                                  follow_redirects=True)
    assert risposta.status_code == 200

    riga = _riga(server_app, node_id)
    assert riga["device_type_source"] == "auto"
    assert riga["device_type_by"] is None and riga["device_type_at"] is None
    assert riga["device_type_reason"] is None
    assert riga["device_type"] == "printer", "il verdetto va ricalcolato subito"

    with server_app.app_context():
        from snapserver.db import query

        evento = query("SELECT * FROM audit_events WHERE event_type = ?",
                       ("node.type.reverted",), one=True)
    assert evento is not None


def test_tornare_all_automatico_su_un_nodo_gia_automatico_non_e_un_errore(
        logged_client, server_app, contesto):
    node_id = _nodo(server_app, contesto)
    _entra(logged_client, contesto)

    risposta = logged_client.post("/inventory/nodes/%d/type" % node_id,
                                  data={"device_type": "__auto__"},
                                  follow_redirects=True)

    assert risposta.status_code == 200
    assert "gia' deciso dal riconoscimento" in risposta.get_data(as_text=True).replace(
        "&#39;", "'")


# --------------------------------------------------------------------------- #
# Limiti
# --------------------------------------------------------------------------- #
def test_il_nodo_di_un_altro_tenant_non_si_dichiara(logged_client, server_app,
                                                    contesto):
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        execute("INSERT INTO tenants (code, name, created_at, updated_at)"
                " VALUES ('cliente-tipo', 'Cliente tipo', ?, ?)",
                (utc_now_str(), utc_now_str()))
        altro = int(query("SELECT id FROM tenants WHERE code = 'cliente-tipo'",
                          (), one=True)["id"])

    altrui = _nodo(server_app, altro, ip="10.44.9.9")
    _entra(logged_client, contesto)

    risposta = logged_client.post("/inventory/nodes/%d/type" % altrui,
                                 data={"device_type": "nas"})

    assert risposta.status_code == 404
    assert _riga(server_app, altrui)["device_type_source"] == "auto"


def test_il_dato_grezzo_dichiara_chi_ha_deciso_il_tipo(logged_client, server_app,
                                                       contesto):
    """Una confidenza 100 senza questa indicazione sarebbe indistinguibile da una
    certezza automatica."""
    node_id = _nodo(server_app, contesto)
    _entra(logged_client, contesto)
    logged_client.post("/inventory/nodes/%d/type" % node_id,
                       data={"device_type": "nas", "reason": "Synology del piano 2"},
                       follow_redirects=True)

    with server_app.app_context():
        from snapserver.node_json import documento

        doc = documento(contesto, node_id)

    assert doc["riconoscimento"]["deciso_da"] == "operatore"
    assert doc["riconoscimento"]["dichiarato_perche"] == "Synology del piano 2"
    assert "@" in doc["riconoscimento"]["dichiarato_da"]


def test_l_elenco_dei_nodi_distingue_un_tipo_dichiarato(logged_client, server_app,
                                                        contesto):
    node_id = _nodo(server_app, contesto)
    _entra(logged_client, contesto)
    logged_client.post("/inventory/nodes/%d/type" % node_id,
                       data={"device_type": "ip_camera"}, follow_redirects=True)

    pagina = logged_client.get("/inventory/nodes").get_data(as_text=True)
    assert "Tipo dichiarato dall'operatore" in pagina, (
        "senza il segno, una dichiarazione e una certezza automatica si leggono uguali")


def test_la_scheda_pdf_dichiara_che_il_tipo_e_stato_dichiarato(
        logged_client, server_app, contesto):
    """Il foglio si allega a una richiesta di intervento: chi lo legge non ha la
    console davanti, e un "(100%)" gli farebbe credere a una misura."""
    node_id = _nodo(server_app, contesto)
    _entra(logged_client, contesto)
    logged_client.post("/inventory/nodes/%d/type" % node_id,
                       data={"device_type": "plc_industrial",
                             "reason": "PLC di linea 2"},
                       follow_redirects=True)

    with server_app.app_context():
        from snapserver.db import query
        from snapserver.reports import dataset_wide

        tenant = dict(query("SELECT * FROM tenants WHERE id = ?", (contesto,),
                            one=True))
        dati = dataset_wide.device_sheet(tenant, tenant.get("timezone"), node_id)

    nodo = dati["nodo"]
    assert (nodo.get("device_type_source") or "auto") == "manual", (
        "il dato del report deve portare la fonte del tipo")
    assert nodo.get("device_type_reason") == "PLC di linea 2"
