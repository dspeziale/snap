"""
snap - Il collegamento per aprire l'interfaccia di un apparato.

Richiesta dell'operatore: nella scheda di un nodo, accanto alla porta 80 o 443, un
collegamento che apra l'interfaccia in una nuova finestra. Senza, si ricopia
l'indirizzo a mano -- ed e' il gesto successivo naturale a vedere quella porta aperta.

Cio' che questi controlli difendono: il collegamento appare SOLO dove porta a
qualcosa (una pagina di errore e' peggio di nessun collegamento), lo schema e' quello
giusto, e la finestra che si apre non puo' agire su quella della console.

remarks: Autore: Daniele Speziale - Data: 2026-09-10
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest

from snapserver.web_presentation import indirizzo_web


def _porta(numero, protocollo="tcp", stato="open", servizio=""):
    return {"protocol": protocollo, "port": numero, "state": stato,
            "service_name": servizio}


# --------------------------------------------------------------------------- #
# Quali porte sono un'interfaccia web
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("numero,servizio,atteso", [
    (80, "http", "http://10.0.0.5/"),
    (443, "https", "https://10.0.0.5/"),
    (8080, "http-proxy", "http://10.0.0.5:8080/"),
    (8443, "http", "https://10.0.0.5:8443/"),
    (10443, "", "https://10.0.0.5:10443/"),
])
def test_le_porte_web_danno_l_indirizzo_giusto(numero, servizio, atteso):
    """La porta predefinita non si scrive nell'indirizzo: resta quello che
    l'operatore avrebbe digitato."""
    assert indirizzo_web("10.0.0.5", _porta(numero, servizio=servizio)) == atteso


def test_una_porta_su_una_porta_inattesa_si_riconosce_dal_servizio():
    """Un apparato puo' esporre la propria pagina di gestione dove vuole: se nmap
    dice che quel servizio e' http, il collegamento serve."""
    assert indirizzo_web("10.0.0.5", _porta(7070, servizio="http-alt")) == (
        "http://10.0.0.5:7070/")


def test_lo_schema_cifrato_si_riconosce_anche_dal_nome_del_servizio():
    assert indirizzo_web("10.0.0.5", _porta(9999, servizio="ssl/http")).startswith(
        "https://")


# --------------------------------------------------------------------------- #
# Dove il collegamento NON deve comparire
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("porta,perche", [
    (_porta(9100, servizio="jetdirect"), "stampa diretta: non e' una pagina"),
    (_porta(22, servizio="ssh"), "ssh non si apre nel browser"),
    (_porta(445, servizio="microsoft-ds"), "condivisione file"),
    (_porta(161, protocollo="udp", servizio="snmp"), "UDP non ha interfaccia web"),
    (_porta(80, stato="closed", servizio="http"), "porta chiusa"),
    (_porta(80, stato="filtered", servizio="http"), "porta filtrata"),
])
def test_dove_non_porta_a_nulla_non_c_e_collegamento(porta, perche):
    """Un collegamento che apre una pagina di errore e' peggio di nessun
    collegamento: fa credere che l'apparato risponda."""
    assert indirizzo_web("10.0.0.5", porta) is None, perche


def test_senza_indirizzo_non_si_compone_nulla():
    assert indirizzo_web("", _porta(80, servizio="http")) is None
    assert indirizzo_web(None, _porta(80, servizio="http")) is None


def test_una_porta_illeggibile_non_solleva():
    assert indirizzo_web("10.0.0.5", {"protocol": "tcp", "port": "ottanta",
                                      "state": "open"}) is None


# --------------------------------------------------------------------------- #
# Nella pagina
# --------------------------------------------------------------------------- #
def test_la_scheda_del_nodo_offre_il_collegamento(logged_client, server_app):
    """E la finestra che si apre non deve poter agire su quella della console:
    `noopener` e `noreferrer` non sono decorazioni."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        adesso = utc_now_str()
        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
        node_id = execute(
            "INSERT INTO nodes (tenant_id, ip, status, device_type, device_label,"
            " device_confidence, first_seen_at, last_seen_at, created_at, updated_at)"
            " VALUES (?, '10.0.0.77', 'up', 'printer', 'Stampante', 90, ?, ?, ?, ?)",
            (tenant_id, adesso, adesso, adesso, adesso))
        for protocollo, numero, servizio in (("tcp", 443, "https"),
                                             ("tcp", 9100, "jetdirect")):
            execute(
                "INSERT INTO node_ports (tenant_id, node_id, protocol, port, state,"
                " service_name, is_suspect, first_seen_at, last_seen_at)"
                " VALUES (?, ?, ?, ?, 'open', ?, 0, ?, ?)",
                (tenant_id, node_id, protocollo, numero, servizio, adesso, adesso))

    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)
    pagina = logged_client.get("/inventory/nodes/%d" % node_id).get_data(as_text=True)

    assert 'href="https://10.0.0.77/"' in pagina, "la 443 deve essere apribile"
    assert 'target="_blank"' in pagina
    assert 'rel="noopener noreferrer"' in pagina
    # E la porta di stampa no: non e' una pagina.
    assert 'href="http://10.0.0.77:9100/"' not in pagina
