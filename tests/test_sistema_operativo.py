"""
snap - Test del sistema operativo ricavato per approssimazioni successive.

PERCHE' ESISTE
La colonna "Sistema operativo" dell'elenco mostrava il solo rilevamento di nmap, che
per riuscire ha bisogno di almeno una porta aperta e una chiusa, di socket raw e di
apparati che rispondano in modo canonico. Su una rete di PA riesce raramente: la
colonna restava vuota per la maggior parte dei nodi, e una colonna vuota non dice
"non si sa" -- sembra un guasto.

Vuota, in realta', significava che si stava guardando UNA fonte su otto. Questi test
fissano la cascata (chi vince su chi, e perche') e le due proprieta' che contano per
chi legge: non resta MAI vuota, e un'ipotesi non si presenta come una certezza.

remarks: Autore: Daniele Speziale - Data: 2026-09-10
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest

from snapserver.os_guess import indovina

# Un nodo su cui non si sa niente: le prove si aggiungono di volta in volta.
MUTO = {"os_name": None, "os_family": None, "os_gen": None, "os_accuracy": None,
        "os_vendor": None, "ttl": None, "device_type": "unknown",
        "mac_vendor": None, "web_vendor": None}


def nodo(**campi):
    return dict(MUTO, **campi)


# --------------------------------------------------------------------------- #
# La proprieta' che il committente ha chiesto: mai vuoto
# --------------------------------------------------------------------------- #
def test_non_resta_mai_vuoto():
    """Anche di un nodo su cui non si sa NIENTE si dice qualcosa: il motivo per cui
    non si sa. Il vuoto lascia chi legge a chiedersi se il prodotto ha funzionato."""
    esito = indovina(nodo())

    assert esito["testo"], "nessun caso produce una cella vuota"
    assert esito["testo"] == "non determinato"
    assert esito["certezza"] == "ignota"
    assert "nessun indizio" in esito["spiegazione"]


@pytest.mark.parametrize("prove", [
    {},
    {"ttl": 128},
    {"os_family": "Windows"},
    {"device_type": "printer", "mac_vendor": "Kyocera Document Solutions"},
])
def test_ogni_esito_dichiara_da_dove_viene(prove):
    esito = indovina(nodo(**prove))

    assert esito["testo"]
    assert esito["fonte"]
    assert esito["certezza"] in ("dichiarata", "rilevata", "ipotesi", "ignota")
    assert esito["spiegazione"], "un dato senza la sua provenienza non e' verificabile"


# --------------------------------------------------------------------------- #
# L'ordine della cascata
# --------------------------------------------------------------------------- #
def test_il_rilevamento_di_nmap_viene_per_primo():
    esito = indovina(nodo(os_name="Windows 10 22H2", os_accuracy=98, ttl=128),
                     smb_os="OS: Windows Server 2016")

    assert esito["testo"] == "Windows 10 22H2"
    assert esito["fonte"] == "nmap"
    assert "98%" in esito["spiegazione"]


def test_smb_vince_su_tutto_il_resto_quando_nmap_tace():
    """E' l'apparato che dichiara la propria versione: non e' dedotta, e' detta."""
    esito = indovina(nodo(ttl=128), smb_os="OS: Windows Server 2016 Standard 14393",
                     porte=[445, 139])

    assert esito["testo"].startswith("Windows Server 2016")
    assert esito["fonte"] == "SMB"
    assert esito["certezza"] == "dichiarata"


def test_la_parte_ripetuta_fra_parentesi_non_finisce_in_colonna():
    """nmap scrive "Windows Server 2016 Standard 14393 (Windows Server 2016 Standard
    6.3)": la seconda meta' ripete la prima e in una cella non ci sta."""
    esito = indovina(nodo(), smb_os="OS: Windows 10 Pro 19041 (Windows 10 Pro 6.3)")

    assert esito["testo"] == "Windows 10 Pro 19041"


@pytest.mark.parametrize("valore", ["OS: unknown", "OS: <unknown>", "OS: n/a", "", "Computer name: PC1"])
def test_una_dichiarazione_smb_vuota_non_conta(valore):
    """"unknown" e' l'assenza del dato scritta a parole: metterlo in colonna sarebbe
    peggio del vuoto."""
    esito = indovina(nodo(ttl=64), smb_os=valore)

    assert esito["fonte"] != "SMB"


def test_la_descrizione_snmp_riconosce_l_apparato():
    esito = indovina(nodo(), snmp_descr="Cisco IOS Software, C2960X Software"
                                        " Version 15.2(4)E10")

    assert esito["testo"] == "Cisco IOS"
    assert esito["fonte"] == "SNMP"


def test_la_famiglia_rilevata_vale_quando_il_nome_manca():
    esito = indovina(nodo(os_family="Linux", os_gen="3.X"))

    assert esito["testo"] == "Linux 3.X"
    assert "versione precisa non e' stata determinata" in esito["spiegazione"]


@pytest.mark.parametrize("banner,atteso", [
    ("Apache/2.4.52 (Ubuntu)", "Linux (Ubuntu)"),
    ("Apache/2.4.6 (CentOS) OpenSSL/1.0.2k", "Linux (CentOS)"),
    ("Microsoft-IIS/10.0", "Windows"),
    ("Microsoft-HTTPAPI/2.0", "Windows"),
])
def test_il_banner_web_dichiara_o_implica_il_sistema(banner, atteso):
    """IIS non nomina Windows, ma gira solo la': implicare non e' indovinare."""
    esito = indovina(nodo(), web_server=banner)

    assert esito["testo"] == atteso
    assert esito["fonte"] == "pagina web"


def test_le_porte_di_windows_sono_un_ipotesi_non_una_certezza():
    esito = indovina(nodo(), porte=[445, 139, 3389])

    assert esito["testo"] == "Windows (probabile)"
    assert esito["certezza"] == "ipotesi"
    assert "445" in esito["spiegazione"]


def test_ssh_senza_i_servizi_di_windows_e_un_sistema_tipo_unix():
    esito = indovina(nodo(), porte=[22])

    assert "Unix" in esito["testo"]
    assert esito["certezza"] == "ipotesi"


def test_ssh_su_una_macchina_windows_non_la_rende_unix():
    """OpenSSH su Windows esiste: la presenza di SMB e' la prova piu' forte."""
    esito = indovina(nodo(), porte=[22, 445])

    assert esito["testo"] == "Windows (probabile)"


@pytest.mark.parametrize("ttl,atteso", [
    (64, "Unix"), (57, "Unix"), (128, "Windows"), (117, "Windows"),
    (255, "apparato di rete"), (250, "apparato di rete"),
])
def test_il_ttl_distingue_la_famiglia_e_nient_altro(ttl, atteso):
    """Ogni instradamento decrementa il TTL: si arrotonda in su al valore iniziale.
    Non dice la versione, e la spiegazione lo scrive."""
    esito = indovina(nodo(ttl=ttl))

    assert atteso in esito["testo"]
    assert esito["certezza"] == "ipotesi"
    assert "non la versione" in esito["spiegazione"]


def test_di_una_stampante_il_sistema_e_il_firmware():
    """Dire "Linux" di una stampante e' vero e inutile: chi legge l'inventario vuole
    sapere con chi parlare per aggiornarla."""
    esito = indovina(nodo(device_type="printer",
                          mac_vendor="Kyocera Document Solutions Inc."))

    assert "firmware della stampante" in esito["testo"]
    assert "Kyocera" in esito["testo"]
    assert esito["fonte"] == "classe"


def test_un_ttl_non_valido_non_produce_un_ipotesi():
    for valore in (0, -1, "molti", None, ""):
        esito = indovina(nodo(ttl=valore))
        assert esito["fonte"] != "TTL", valore


# --------------------------------------------------------------------------- #
# La colonna Info: cio' che l'apparato dichiara nelle proprie pagine
# --------------------------------------------------------------------------- #
def test_l_info_web_mette_davanti_cio_che_identifica():
    from snapserver.web_presentation import riassunto_web

    voci = riassunto_web([
        {"port": 80, "title": "Web Image Monitor", "model": "MP C4504ex",
         "location": "UFFICIO 12 - PIANO 1"},
    ])

    assert [v["campo"] for v in voci][:2] == ["model", "location"]
    assert voci[1]["icona"] == "bi-geo-alt", "la posizione fisica si vede"


def test_l_info_web_non_ripete_la_stessa_cosa_su_due_porte():
    """Una multifunzione con la 80 e la 443 dichiara due volte le stesse cose: in un
    elenco quella ripetizione occupa la riga senza aggiungere niente."""
    from snapserver.web_presentation import riassunto_web

    voci = riassunto_web([
        {"port": 80, "title": "FortiGate", "product": "Fortinet FortiOS"},
        {"port": 443, "title": "FortiGate", "product": "Fortinet FortiOS"},
    ])

    assert len(voci) == 2
    assert len({v["valore"] for v in voci}) == 2


def test_l_info_web_sta_in_una_cella():
    from snapserver.web_presentation import (MAX_TESTO_INFO, MAX_VOCI_INFO,
                                             riassunto_web)

    voci = riassunto_web([{
        "port": 80, "title": "t" * 200, "product": "p" * 200, "model": "m" * 200,
        "device_name": "d" * 200, "location": "l" * 200, "firmware": "f" * 200,
        "server_header": "s" * 200,
    }])

    assert len(voci) == MAX_VOCI_INFO
    assert all(len(v["valore"]) <= MAX_TESTO_INFO for v in voci)
    assert all(v["completo"] for v in voci), "il testo intero resta nel suggerimento"


def test_senza_letture_web_l_info_e_vuota_e_la_pagina_lo_dice():
    from snapserver.web_presentation import riassunto_web

    assert riassunto_web([]) == []
    assert riassunto_web(None) == []


# --------------------------------------------------------------------------- #
# L'elenco vero, dalla banca dati
# --------------------------------------------------------------------------- #
def test_l_elenco_porta_le_due_colonne_derivate(server_app):
    """Le due colonne si compongono con poche interrogazioni per l'intera pagina:
    questo test verifica che arrivino al template, non solo che il modulo funzioni."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str
        from snapserver.inventory_queries import con_colonne_derivate, nodes_list

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
        adesso = utc_now_str()
        sonda = query("SELECT id FROM probes WHERE tenant_id = ?", (tenant_id,),
                      one=True)
        probe_id = int(sonda["id"]) if sonda else execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, created_at,"
            " updated_at) VALUES (?, 'uid-os', 'sonda-os', 'Sonda', 'active', ?, ?)",
            (tenant_id, adesso, adesso))
        node_id = execute(
            "INSERT INTO nodes (tenant_id, probe_id, ip, status, ttl, first_seen_at,"
            " last_seen_at, created_at, updated_at)"
            " VALUES (?, ?, '10.44.0.10', 'up', 128, ?, ?, ?, ?)",
            (tenant_id, probe_id, adesso, adesso, adesso, adesso))
        execute(
            "INSERT INTO node_web (tenant_id, node_id, port, scheme, status_code,"
            " title, model, location, collected_at)"
            " VALUES (?, ?, 80, 'http', 200, 'Web Image Monitor', 'MP C4504ex',"
            " 'UFFICIO 12', ?)", (tenant_id, node_id, adesso))

        righe = con_colonne_derivate(nodes_list(tenant_id))

    riga = [r for r in righe if r["ip"] == "10.44.0.10"][0]
    assert riga["os_guess"]["testo"] == "Windows (dal TTL)"
    assert [v["campo"] for v in riga["info_web"]][:2] == ["model", "location"]


def test_un_elenco_vuoto_non_interroga_la_banca_dati(server_app):
    """`dati_accessori` compone una IN con un segnaposto per nodo: con zero nodi
    quella IN sarebbe SQL non valido."""
    with server_app.app_context():
        from snapserver.inventory_queries import con_colonne_derivate, dati_accessori

        assert dati_accessori([]) == {}
        assert con_colonne_derivate([]) == []
