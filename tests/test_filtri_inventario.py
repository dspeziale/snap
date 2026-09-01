"""
snap - Filtri dell'inventario: trovare un nodo per cio' che espone.

Su una rete reale l'elenco dei nodi conta centinaia di righe: filtrarlo per subnet e
per tipo risponde a "dove sta" e "che cos'e'", non alla domanda vera di chi lavora --
"chi ha SNMP aperto?", "quali apparati hanno un'interfaccia web?", "dove manca ancora
la lettura?". Questi test verificano che ogni filtro selezioni cio' che dichiara e
nient'altro, e che i filtri si combinino.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest


# --------------------------------------------------------------------------- #
# Preparazione
# --------------------------------------------------------------------------- #
def _tenant_id(server_app):
    with server_app.app_context():
        from snapserver.db import query

        return int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])


def _nodo(server_app, tenant_id, ip, porte=(), hostname=None, device_type="server",
          confidenza=90, mac_vendor=None, giorni_fa=0):
    """Un nodo con le sue porte aperte. `porte` e' una lista (protocollo, porta)."""
    with server_app.app_context():
        from datetime import timedelta

        from snapserver.db import execute, query, utc_now, utc_now_str, utc_str

        adesso = utc_now_str()
        visto = utc_str(utc_now() - timedelta(days=giorni_fa)) if giorni_fa else adesso
        subnet = query("SELECT id FROM subnets WHERE tenant_id = ?", (tenant_id,),
                       one=True)
        subnet_id = int(subnet["id"]) if subnet else execute(
            "INSERT INTO subnets (tenant_id, cidr, host_count, is_enabled, imported_at,"
            " created_at, updated_at) VALUES (?, '10.9.0.0/24', 254, 1, ?, ?, ?)",
            (tenant_id, adesso, adesso, adesso))
        node_id = execute(
            "INSERT INTO nodes (tenant_id, subnet_id, ip, hostname, status, device_type,"
            " device_label, device_confidence, mac_vendor, first_seen_at, last_seen_at,"
            " created_at, updated_at)"
            " VALUES (?, ?, ?, ?, 'up', ?, ?, ?, ?, ?, ?, ?, ?)",
            (tenant_id, subnet_id, ip, hostname, device_type, device_type, confidenza,
             mac_vendor, adesso, visto, adesso, adesso))
        for protocollo, porta in porte:
            execute(
                "INSERT INTO node_ports (tenant_id, node_id, protocol, port, state,"
                " is_suspect, first_seen_at, last_seen_at)"
                " VALUES (?, ?, ?, ?, 'open', 0, ?, ?)",
                (tenant_id, node_id, protocollo, porta, adesso, adesso))
        return node_id


def _cerca(server_app, tenant_id, **filtri):
    with server_app.app_context():
        from snapserver.inventory_queries import nodes_list

        return [r["ip"] for r in nodes_list(tenant_id, **filtri)]


# --------------------------------------------------------------------------- #
# Famiglie di servizio
# --------------------------------------------------------------------------- #
def test_si_trovano_i_nodi_per_cio_che_espongono(server_app):
    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.10", [("tcp", 443)])
    _nodo(server_app, tenant_id, "10.9.0.11", [("udp", 161)])
    _nodo(server_app, tenant_id, "10.9.0.12", [("tcp", 3389)])
    _nodo(server_app, tenant_id, "10.9.0.13", [("tcp", 9100)])

    assert _cerca(server_app, tenant_id, service="web") == ["10.9.0.10"]
    assert _cerca(server_app, tenant_id, service="snmp") == ["10.9.0.11"]
    assert _cerca(server_app, tenant_id, service="remoto") == ["10.9.0.12"]
    assert _cerca(server_app, tenant_id, service="stampa") == ["10.9.0.13"]


def test_una_famiglia_inesistente_non_filtra_di_nascosto(server_app):
    """Un filtro non riconosciuto deve essere ignorato, non restituire il vuoto: un
    elenco vuoto sembrerebbe una rete vuota."""
    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.20", [("tcp", 443)])
    assert _cerca(server_app, tenant_id, service="inventata") == ["10.9.0.20"]


def test_le_porte_iniettate_dalla_rete_non_fanno_trovare_un_nodo(server_app):
    """Un apparato intermedio che risponde per altri (ALG SIP su tcp/2000) non rende
    quel nodo un telefono: le porte marcate come iniettate restano fuori dai filtri,
    come restano fuori dalle prove del riconoscimento."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id, "10.9.0.30", [("tcp", 5060)])
    with server_app.app_context():
        from snapserver.db import execute

        execute("UPDATE node_ports SET is_suspect = 1 WHERE node_id = ?", (node_id,))

    assert _cerca(server_app, tenant_id, service="telefonia") == []


# --------------------------------------------------------------------------- #
# Porta esatta
# --------------------------------------------------------------------------- #
def test_la_porta_si_cerca_col_numero_e_col_protocollo(server_app):
    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.40", [("udp", 161)])
    _nodo(server_app, tenant_id, "10.9.0.41", [("tcp", 161)])

    assert sorted(_cerca(server_app, tenant_id, port="161")) == ["10.9.0.40", "10.9.0.41"]
    assert _cerca(server_app, tenant_id, port="udp/161") == ["10.9.0.40"]
    assert _cerca(server_app, tenant_id, port="tcp/161") == ["10.9.0.41"]


def test_una_porta_scritta_male_non_restituisce_il_vuoto(server_app):
    """Chi digita "tre" in un campo numerico non deve vedere una rete vuota."""
    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.42", [("tcp", 80)])
    assert _cerca(server_app, tenant_id, port="tre") == ["10.9.0.42"]
    assert _cerca(server_app, tenant_id, port="99999") == ["10.9.0.42"]


@pytest.mark.parametrize("scritto,atteso", [
    ("161", (None, 161)),
    ("udp/161", ("udp", 161)),
    ("tcp 80", ("tcp", 80)),
    ("TCP/443", ("tcp", 443)),
    ("", (None, None)),
    ("abc", (None, None)),
    ("70000", (None, None)),
])
def test_la_porta_si_legge_nelle_forme_che_una_persona_scrive(server_app, scritto, atteso):
    with server_app.app_context():
        from snapserver.inventory_queries import parse_port_filter

        assert parse_port_filter(scritto) == atteso


# --------------------------------------------------------------------------- #
# Ricerca libera
# --------------------------------------------------------------------------- #
def test_la_ricerca_libera_guarda_indirizzo_nome_e_costruttore(server_app):
    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.50", hostname="stampante-piano2.local")
    _nodo(server_app, tenant_id, "10.9.0.51", mac_vendor="Cisco Systems")
    _nodo(server_app, tenant_id, "10.9.0.52")

    assert _cerca(server_app, tenant_id, text="piano2") == ["10.9.0.50"]
    assert _cerca(server_app, tenant_id, text="cisco") == ["10.9.0.51"]
    assert sorted(_cerca(server_app, tenant_id, text="10.9.0.5")) == [
        "10.9.0.50", "10.9.0.51", "10.9.0.52"]


# --------------------------------------------------------------------------- #
# Lettura SNMP, sicurezza, identificazione, ultimo contatto
# --------------------------------------------------------------------------- #
def test_si_distingue_chi_e_stato_letto_da_chi_e_da_leggere(server_app):
    """Serve a sapere dove manca ancora la lettura: la fase SNMP ha una cadenza
    propria, e "non letto" non e' un guasto ma un lavoro in coda."""
    tenant_id = _tenant_id(server_app)
    letto = _nodo(server_app, tenant_id, "10.9.0.60", [("udp", 161)])
    _nodo(server_app, tenant_id, "10.9.0.61", [("udp", 161)])
    _nodo(server_app, tenant_id, "10.9.0.62", [("tcp", 80)])
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        execute("INSERT INTO node_snmp (tenant_id, node_id, script_id, output,"
                " collected_at) VALUES (?, ?, 'snmp-info', 'enterprise: cisco', ?)",
                (tenant_id, letto, utc_now_str()))

    assert _cerca(server_app, tenant_id, snmp="letto") == ["10.9.0.60"]
    assert _cerca(server_app, tenant_id, snmp="da_leggere") == ["10.9.0.61"]


def test_si_distingue_chi_ha_l_enumerazione_smb_da_chi_e_da_enumerare(server_app):
    """Come per SNMP: gia' enumerato, oppure porta SMB aperta e mai enumerato. Vale
    per la 139 e per la 445, e un nodo senza porte SMB non compare in nessuno dei due."""
    tenant_id = _tenant_id(server_app)
    enumerato = _nodo(server_app, tenant_id, "10.9.0.63", [("tcp", 445)])
    _nodo(server_app, tenant_id, "10.9.0.64", [("tcp", 139)])
    _nodo(server_app, tenant_id, "10.9.0.65", [("tcp", 80)])
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        execute("INSERT INTO node_smb (tenant_id, node_id, script_id, output,"
                " collected_at) VALUES (?, ?, 'smb-os-discovery', 'OS: Windows', ?)",
                (tenant_id, enumerato, utc_now_str()))

    assert _cerca(server_app, tenant_id, smb="letto") == ["10.9.0.63"]
    assert _cerca(server_app, tenant_id, smb="da_leggere") == ["10.9.0.64"]


def test_si_trovano_i_nodi_con_riscontri_di_sicurezza(server_app):
    tenant_id = _tenant_id(server_app)
    con_riscontro = _nodo(server_app, tenant_id, "10.9.0.70", [("tcp", 3389)])
    _nodo(server_app, tenant_id, "10.9.0.71", [("tcp", 80)])
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        execute(
            "INSERT INTO ti_findings (tenant_id, node_id, kind, severity, title,"
            " evidence, confidence, status, first_seen_at, last_seen_at)"
            " VALUES (?, ?, 'exposure', 'high', 'RDP raggiungibile', 'porta aperta',"
            " 80, 'open', ?, ?)", (tenant_id, con_riscontro, adesso, adesso))

    assert _cerca(server_app, tenant_id, risk="aperti") == ["10.9.0.70"]
    # Un'esposizione non e' una vulnerabilita' confermata: le classi restano distinte
    # anche nei filtri.
    assert _cerca(server_app, tenant_id, risk="confermati") == []


def test_si_radunano_i_nodi_da_verificare(server_app):
    """Sotto la soglia il verdetto e' un'ipotesi: sono i nodi su cui serve guardare."""
    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.80", confidenza=95)
    _nodo(server_app, tenant_id, "10.9.0.81", confidenza=30)
    _nodo(server_app, tenant_id, "10.9.0.82", device_type="unknown", confidenza=0)

    assert sorted(_cerca(server_app, tenant_id, identified="incerto")) == [
        "10.9.0.81", "10.9.0.82"]
    assert _cerca(server_app, tenant_id, identified="certo") == ["10.9.0.80"]


def test_si_trovano_i_nodi_muti_da_giorni(server_app):
    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.90")
    _nodo(server_app, tenant_id, "10.9.0.91", giorni_fa=20)

    assert _cerca(server_app, tenant_id, seen="24h") == ["10.9.0.90"]
    assert _cerca(server_app, tenant_id, seen="silenzio") == ["10.9.0.91"]
    assert sorted(_cerca(server_app, tenant_id, seen="30g")) == ["10.9.0.90", "10.9.0.91"]


def test_i_filtri_si_combinano(server_app):
    """Ogni filtro restringe: due insieme non allargano mai il risultato."""
    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.100", [("tcp", 443)], confidenza=20)
    _nodo(server_app, tenant_id, "10.9.0.101", [("tcp", 443)], confidenza=95)

    assert _cerca(server_app, tenant_id, service="web",
                  identified="incerto") == ["10.9.0.100"]


# --------------------------------------------------------------------------- #
# Pagina
# --------------------------------------------------------------------------- #
def test_la_pagina_offre_i_filtri_e_conserva_la_scelta(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.110", [("udp", 161)])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/nodes").get_data(as_text=True)
    for campo in ("servizio", "porta", "cerca", "snmp", "rischio", "identificazione",
                  "visto"):
        assert 'name="%s"' % campo in pagina, "manca il filtro %s" % campo

    scelto = logged_client.get("/inventory/nodes?servizio=snmp&porta=udp/161"
                               "&cerca=10.9").get_data(as_text=True)
    assert 'value="udp/161"' in scelto, "il filtro applicato deve restare nel modulo"
    assert 'value="10.9"' in scelto
    assert "10.9.0.110" in scelto


# --------------------------------------------------------------------------- #
# Mappa della rete ad albero
# --------------------------------------------------------------------------- #
def test_l_albero_raggruppa_per_sonda_e_per_subnet(server_app):
    """La struttura che il prodotto conosce e' gerarchica -- chi osserva, dentro
    quale perimetro, quali dispositivi -- e non un grafo di adiacenze: quelle, su una
    rete commutata, una scansione non le puo' dedurre."""
    from snapserver.inventory_queries import network_tree

    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.1", [("tcp", 443)])
    _nodo(server_app, tenant_id, "10.9.0.2", [("udp", 161)])

    with server_app.app_context():
        albero = network_tree(tenant_id)

    assert albero["nodi"] == 2
    assert len(albero["sonde"]) == 1
    subnet = albero["sonde"][0]["subnet"][0]
    assert subnet["totale"] == 2
    assert [n["ip"] for n in subnet["nodi"]] == ["10.9.0.1", "10.9.0.2"]
    # Il riepilogo per tipo dice piu' di duecento indirizzi.
    assert subnet["per_tipo"], "ogni ramo dichiara che cosa contiene"


def test_l_albero_puo_mostrare_i_soli_dispositivi_attivi(server_app):
    from snapserver.inventory_queries import network_tree

    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.3")
    spento = _nodo(server_app, tenant_id, "10.9.0.4")
    with server_app.app_context():
        from snapserver.db import execute

        execute("UPDATE nodes SET status = 'down' WHERE id = ?", (spento,))
        completo = network_tree(tenant_id)
        attivi = network_tree(tenant_id, solo_attivi=True)

    assert completo["nodi"] == 2 and completo["attivi"] == 1
    assert attivi["nodi"] == 1


def test_la_pagina_della_mappa_e_un_albero_di_testo(logged_client, server_app):
    """Non un disegno: un albero apribile, che si cerca con il browser, si stampa e
    si copia come testo."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id, "10.9.0.5", [("tcp", 22)])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/map").get_data(as_text=True)
    assert "snap-albero" in pagina
    assert "<details" in pagina and "<summary" in pagina
    assert "10.9.0.5" in pagina
    assert "/inventory/nodes/%d" % node_id in pagina, "dalla foglia si apre il nodo"
    # Nessuna libreria di grafica: l'albero e' marcatura e fogli di stile.
    assert "canvas" not in pagina and "svg" not in pagina.lower().split("</head>")[-1][:200]


def test_la_mappa_e_raggiungibile_dal_menu(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)
    corpo = logged_client.get("/").get_data(as_text=True)
    menu = corpo[corpo.index("app-sidebar"):corpo.index("</aside>")]
    assert "/inventory/map" in menu and "Mappa della rete" in menu


# --------------------------------------------------------------------------- #
# La vista per zona parte dal perimetro dichiarato
# --------------------------------------------------------------------------- #
def _subnet_dichiarata(server_app, tenant_id, cidr, zona=""):
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        return execute(
            "INSERT INTO subnets (tenant_id, cidr, host_count, is_enabled, zone,"
            " imported_at, created_at, updated_at) VALUES (?, ?, 254, 1, ?, ?, ?, ?)",
            (tenant_id, cidr, zona, adesso, adesso, adesso))


def test_una_subnet_dichiarata_in_zona_compare_anche_senza_dispositivi(server_app):
    """Difetto segnalato: due subnet appena assegnate a una zona non comparivano in
    "Per zona di rete". La vista si ricavava dall'albero dei dispositivi, e una subnet
    senza dispositivi non esiste in quell'albero -- ma e' proprio quella che si va a
    cercare subito dopo averla dichiarata."""
    from snapserver.inventory_queries import network_tree

    tenant_id = _tenant_id(server_app)
    _subnet_dichiarata(server_app, tenant_id, "10.77.0.0/24", "datacenter")

    with server_app.app_context():
        albero = network_tree(tenant_id)

    datacenter = next(z for z in albero["zone"] if z["chiave"] == "datacenter")
    cidr = [s["cidr"] for s in datacenter["subnet"]]
    assert "10.77.0.0/24" in cidr
    voce = next(s for s in datacenter["subnet"] if s["cidr"] == "10.77.0.0/24")
    assert voce["nodi"] == 0
    assert "nessun dispositivo" in voce["sonda"], (
        "zero dispositivi e' un'informazione: dice che la rete e' dichiarata e non"
        " ancora osservata")


def test_i_conteggi_delle_subnet_osservate_restano_quelli_dell_albero(server_app):
    from snapserver.inventory_queries import network_tree

    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.21")
    _nodo(server_app, tenant_id, "10.9.0.22")
    with server_app.app_context():
        from snapserver.db import execute

        execute("UPDATE subnets SET zone = 'gestione' WHERE tenant_id = ?", (tenant_id,))
        albero = network_tree(tenant_id)

    gestione = next(z for z in albero["zone"] if z["chiave"] == "gestione")
    voce = next(s for s in gestione["subnet"] if s["cidr"] == "10.9.0.0/24")
    assert voce["nodi"] == 2
    assert gestione["nodi"] == 2
    assert voce["sonda"] and "nessun dispositivo" not in voce["sonda"]


def test_una_subnet_senza_zona_resta_nel_gruppo_senza_dichiarazione(server_app):
    from snapserver.inventory_queries import network_tree

    tenant_id = _tenant_id(server_app)
    _subnet_dichiarata(server_app, tenant_id, "10.78.0.0/24")

    with server_app.app_context():
        albero = network_tree(tenant_id)

    senza = next(z for z in albero["zone"] if z["chiave"] == "")
    assert "10.78.0.0/24" in [s["cidr"] for s in senza["subnet"]]
    assert "10.78.0.0/24" in [s["cidr"] for s in albero["senza_zona"]]


def test_una_zona_dichiarata_e_mai_usata_compare_comunque(server_app):
    """Una zona dichiarata e mai usata e' un'informazione, non un vuoto da nascondere."""
    from snapserver.inventory_queries import network_tree

    tenant_id = _tenant_id(server_app)

    with server_app.app_context():
        albero = network_tree(tenant_id)

    industriale = next(z for z in albero["zone"] if z["chiave"] == "industriale")
    assert industriale["subnet"] == []
    assert industriale["nodi"] == 0


def test_una_subnet_non_si_conta_due_volte(server_app):
    """La subnet compare nel perimetro E nell'albero: se le due fonti si sommassero,
    i dispositivi risulterebbero il doppio."""
    from snapserver.inventory_queries import network_tree

    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.31")
    with server_app.app_context():
        albero = network_tree(tenant_id)

    apparizioni = [s for z in albero["zone"] for s in z["subnet"]
                   if s["cidr"] == "10.9.0.0/24"]
    assert len(apparizioni) == 1
    assert sum(z["nodi"] for z in albero["zone"]) == albero["nodi"]


def test_la_pagina_della_mappa_mostra_la_subnet_appena_dichiarata(logged_client,
                                                                  server_app):
    tenant_id = _tenant_id(server_app)
    _subnet_dichiarata(server_app, tenant_id, "10.79.0.0/24", "dmz")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/map").get_data(as_text=True)

    assert "10.79.0.0/24" in pagina


def test_la_pagina_della_mappa_dichiara_quante_subnet_non_hanno_prodotto_nulla(
        logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    _subnet_dichiarata(server_app, tenant_id, "10.84.0.0/24")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/map").get_data(as_text=True)

    assert "SUBNET SENZA DISPOSITIVI" in pagina
    assert "10.84.0.0/24" in pagina
    assert "Perimetro dichiarato" in pagina


def test_il_perimetro_senza_dispositivi_non_e_una_sonda(server_app):
    """Il perimetro e' del TENANT e viene consegnato a tutte le sonde: metterlo accanto
    a loro lo faceva perfino contare fra le sonde che osservano."""
    from snapserver.inventory_queries import network_tree

    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.41")
    _subnet_dichiarata(server_app, tenant_id, "10.81.0.0/24")

    with server_app.app_context():
        albero = network_tree(tenant_id)

    assert len(albero["sonde"]) == 1, "una sonda, non due"
    assert not any(s.get("solo_perimetro") for s in albero["sonde"])
    assert albero["subnet"] == 1, "le subnet con dispositivi restano quelle"
    assert albero["perimetro_muto"]["totale"] == 1


def test_le_subnet_senza_dispositivi_si_raggruppano_per_blocco(server_app):
    """Trecentotrentasei righe con "0 nodi" non sono un raggruppamento: sono rumore.
    Il blocco /16 e' la lettura che gli operatori hanno in testa -- "la 10.10"."""
    from snapserver.inventory_queries import network_tree

    tenant_id = _tenant_id(server_app)
    for terzo in (1, 2, 3):
        _subnet_dichiarata(server_app, tenant_id, "10.90.%d.0/24" % terzo)
    _subnet_dichiarata(server_app, tenant_id, "10.91.7.0/24")

    with server_app.app_context():
        muto = network_tree(tenant_id)["perimetro_muto"]

    per_rete = {b["rete"]: b for b in muto["blocchi"]}
    assert len(per_rete["10.90.0.0/16"]["subnet"]) == 3
    assert len(per_rete["10.91.0.0/16"]["subnet"]) == 1
    assert muto["blocchi"][0]["rete"] == "10.90.0.0/16", "prima i blocchi piu' grossi"
    assert per_rete["10.90.0.0/16"]["indirizzi"] == 3 * 254


def test_ogni_subnet_muta_dichiara_perche_e_muta(server_app):
    """La ragione del silenzio e' l'unica cosa che rende utile questo elenco: "spenta",
    "non ancora scansionata" e "sospesa" portano a tre azioni diverse."""
    from snapserver.inventory_queries import network_tree

    tenant_id = _tenant_id(server_app)
    mai = _subnet_dichiarata(server_app, tenant_id, "10.92.1.0/24")
    scansionata = _subnet_dichiarata(server_app, tenant_id, "10.92.2.0/24")
    sospesa = _subnet_dichiarata(server_app, tenant_id, "10.92.3.0/24")
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        execute("UPDATE subnets SET is_enabled = 0 WHERE id = ?", (sospesa,))
        execute("INSERT INTO scan_runs (tenant_id, stage, target, status, started_at,"
                " finished_at, hosts_total, hosts_up, records, created_at)"
                " VALUES (?, 'discovery', '10.92.2.0/24', 'completed', ?, ?, 254, 0, 0, ?)",
                (tenant_id, utc_now_str(), utc_now_str(), utc_now_str()))
        muto = network_tree(tenant_id)["perimetro_muto"]

    stati = {v["cidr"]: v["stato"] for v in muto["subnet"]}
    assert stati["10.92.1.0/24"] == "mai scansionata"
    assert stati["10.92.2.0/24"] == "scansionata senza esiti"
    assert stati["10.92.3.0/24"] == "sospesa"
    assert muto["mai_scansionate"] == 1
    assert muto["senza_esiti"] == 1
    assert muto["sospese"] == 1


def test_una_subnet_con_dispositivi_non_e_muta(server_app):
    from snapserver.inventory_queries import network_tree

    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.44")

    with server_app.app_context():
        muto = network_tree(tenant_id)["perimetro_muto"]

    assert "10.9.0.0/24" not in [v["cidr"] for v in muto["subnet"]]


def test_una_subnet_muta_compare_una_volta_per_vista(server_app):
    """Sta nel perimetro muto E nella propria zona: se le due viste si sommassero, il
    conteggio delle subnet sarebbe il doppio."""
    from snapserver.inventory_queries import network_tree

    tenant_id = _tenant_id(server_app)
    _subnet_dichiarata(server_app, tenant_id, "10.83.0.0/24", "gestione")

    with server_app.app_context():
        albero = network_tree(tenant_id)

    nei_rami = [s["cidr"] for r in albero["sonde"] for s in r["subnet"]]
    nel_muto = [v["cidr"] for v in albero["perimetro_muto"]["subnet"]]
    nelle_zone = [s["cidr"] for z in albero["zone"] for s in z["subnet"]]

    assert nei_rami.count("10.83.0.0/24") == 0, "nessuna sonda l'ha osservata"
    assert nel_muto.count("10.83.0.0/24") == 1
    assert nelle_zone.count("10.83.0.0/24") == 1


def test_la_pagina_raccoglie_il_perimetro_muto_in_una_sezione(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    _subnet_dichiarata(server_app, tenant_id, "10.84.0.0/24")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/map").get_data(as_text=True)

    assert "Perimetro dichiarato senza dispositivi" in pagina
    assert "10.84.0.0/16" in pagina, "il blocco che raggruppa"
    assert "SUBNET SENZA DISPOSITIVI" in pagina


# --------------------------------------------------------------------------- #
# Pulsante "Enumera SMB su tutti"
# --------------------------------------------------------------------------- #
def _sonda_attiva(server_app, tenant_id, uid="uid-smb-all", codice="P-SMB"):
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        execute("INSERT INTO probes (tenant_id, probe_uid, code, name, status,"
                " scan_enabled, created_at, updated_at)"
                " VALUES (?, ?, ?, 'Sonda SMB', 'active', 1, ?, ?)",
                (tenant_id, uid, codice, utc_now_str(), utc_now_str()))
        return int(query("SELECT id FROM probes WHERE probe_uid = ?", (uid,),
                         one=True)["id"])


def test_il_pulsante_enumera_smb_su_tutti_accoda_alle_sonde(logged_client, server_app):
    from snapserver.db import query

    with server_app.app_context():
        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
    _nodo(server_app, tenant_id, "10.9.0.80", [("tcp", 445)])
    _nodo(server_app, tenant_id, "10.9.0.81", [("tcp", 139)])
    probe_id = _sonda_attiva(server_app, tenant_id)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.post("/inventory/smb/enumerate-all", follow_redirects=True)
    assert risposta.status_code == 200

    with server_app.app_context():
        import json as _json

        cmd = query("SELECT * FROM probe_commands WHERE command = 'scan'"
                    " AND probe_id = ?", (probe_id,), one=True)
        assert cmd is not None
        assert _json.loads(cmd["payload_json"]) == {"stage": "smb", "target": "@all"}
        evento = query("SELECT * FROM audit_events WHERE event_type = ?",
                       ("inventory.smb.enumerate_all",), one=True)
        assert evento is not None


def test_senza_nodi_smb_il_pulsante_non_accoda_nulla(logged_client, server_app):
    from snapserver.db import query

    with server_app.app_context():
        from snapserver.db import execute, utc_now_str
        execute("INSERT INTO tenants (code, name, created_at, updated_at)"
                " VALUES ('smb-vuoto', 'SMB vuoto', ?, ?)",
                (utc_now_str(), utc_now_str()))
        tenant_id = int(query("SELECT id FROM tenants WHERE code = 'smb-vuoto'",
                              (), one=True)["id"])
    _sonda_attiva(server_app, tenant_id, uid="uid-vuoto", codice="P-V")
    _nodo(server_app, tenant_id, "10.9.0.90", [("tcp", 80)])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.post("/inventory/smb/enumerate-all", follow_redirects=True)
    assert "Nessun nodo" in risposta.get_data(as_text=True)
    with server_app.app_context():
        assert query("SELECT COUNT(*) AS n FROM probe_commands WHERE tenant_id = ?",
                     (tenant_id,), one=True)["n"] == 0
