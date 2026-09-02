"""
snap - Test della mappa grafica della rete.

La mappa grafica disegna la stessa gerarchia della mappa ad albero -- quale sonda
osserva, in quale rete dichiarata, quali dispositivi -- ma con le icone dei tipi. La
disposizione la calcola il server (`map_graphic`), non il browser: cosi' la pagina non
carica librerie di grafi, non ha script inline (politica di sicurezza dei contenuti) e
la posizione di ogni icona e' il risultato verificabile di una funzione.

Le prove verificano: che ogni elemento resti dentro il piano logico; che le icone
vengano dal catalogo delle firme; che i dispositivi con riscontri stiano sugli anelli
interni (se qualcosa viene troncato non e' cio' che ha un problema); e che la pagina
risponda senza script inline.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest


@pytest.fixture()
def contesto(server_app):
    with server_app.app_context():
        from snapserver.db import query

        return int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])


def _rete_con_nodi(server_app, tenant_id, cidr="10.60.0.0/24", quanti=30,
                   tipo="printer", con_riscontri=0):
    """Una subnet con dispositivi, alcuni con riscontri aperti."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        adesso = utc_now_str()
        probe_id = query("SELECT id FROM probes WHERE tenant_id = ?", (tenant_id,),
                         one=True)
        probe_id = int(probe_id["id"]) if probe_id else execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, created_at,"
            " updated_at) VALUES (?, 'uid-mappa', 'PM', 'Sonda mappa', 'active', ?, ?)",
            (tenant_id, adesso, adesso))
        subnet_id = execute(
            "INSERT INTO subnets (tenant_id, cidr, host_count, is_enabled, imported_at,"
            " created_at, updated_at) VALUES (?, ?, 254, 1, ?, ?, ?)",
            (tenant_id, cidr, adesso, adesso, adesso))
        base = cidr.rsplit(".", 1)[0]
        for i in range(quanti):
            node_id = execute(
                "INSERT INTO nodes (tenant_id, subnet_id, probe_id, ip, status,"
                " device_type, device_label, device_confidence, first_seen_at,"
                " last_seen_at, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, 'up', ?, ?, 80, ?, ?, ?, ?)",
                (tenant_id, subnet_id, probe_id, "%s.%d" % (base, i + 1),
                 tipo, "Stampante", adesso, adesso, adesso, adesso))
            if i < con_riscontri:
                execute(
                    "INSERT INTO ti_findings (tenant_id, node_id, kind, title,"
                    " evidence, severity, status, first_seen_at, last_seen_at)"
                    " VALUES (?, ?, 'exposure', 'x', 'x', 'high', 'open', ?, ?)",
                    (tenant_id, node_id, adesso, adesso))
        return subnet_id


# --------------------------------------------------------------------------- #
# Il modulo di disposizione
# --------------------------------------------------------------------------- #
def test_ogni_icona_resta_dentro_il_piano(server_app, contesto):
    """Un'icona fuori dal piano logico sarebbe tagliata dal riquadro."""
    from snapserver.inventory_queries import network_tree
    from snapserver import map_graphic

    subnet_id = _rete_con_nodi(server_app, contesto, quanti=90)
    with server_app.app_context():
        albero = network_tree(contesto)
    vista = map_graphic.rete(albero, subnet_id)
    assert vista is not None
    for nodo in vista["nodi"]:
        assert 0 <= nodo["x"] <= map_graphic.LARGHEZZA, nodo
        assert 0 <= nodo["y"] <= map_graphic.ALTEZZA, nodo


def test_il_panorama_tiene_le_reti_dentro_il_piano(server_app, contesto):
    from snapserver.inventory_queries import network_tree
    from snapserver import map_graphic

    for n in range(12):
        _rete_con_nodi(server_app, contesto, cidr="10.%d.0.0/24" % (70 + n), quanti=5)
    with server_app.app_context():
        albero = network_tree(contesto)
    panorama = map_graphic.panorama(albero)
    assert panorama["isole"], "il panorama deve avere almeno un'isola"
    for isola in panorama["isole"]:
        for rete in isola["reti"]:
            assert 0 <= rete["x"] <= map_graphic.LARGHEZZA
            assert 0 <= rete["y"] <= map_graphic.ALTEZZA


def test_le_icone_vengono_dal_catalogo_delle_firme():
    """La mappa non tiene un secondo elenco di icone: si disallineerebbe al primo
    cambiamento del catalogo."""
    from snapserver import map_graphic
    from snapserver.fingerprint import DEVICE_CLASSES

    for classe in DEVICE_CLASSES:
        assert map_graphic.icona(classe["key"]) == classe["icon"]
    # Un tipo ignoto non rompe: ha la sua icona di ripiego.
    assert map_graphic.icona("tipo-inventato") == map_graphic.ICONA_IGNOTO
    assert map_graphic.icona(None) == map_graphic.ICONA_IGNOTO


def test_i_dispositivi_con_riscontri_stanno_sugli_anelli_interni(server_app, contesto):
    """Se qualcosa viene troncato non deve essere cio' che ha un problema: i nodi con
    riscontri aperti vanno disegnati per primi (anelli interni)."""
    from snapserver.inventory_queries import network_tree
    from snapserver import map_graphic

    subnet_id = _rete_con_nodi(server_app, contesto, quanti=200, con_riscontri=5)
    with server_app.app_context():
        albero = network_tree(contesto)
    vista = map_graphic.rete(albero, subnet_id)
    assert vista["non_disegnati"] > 0, "la rete deve superare il tetto per la prova"
    con_riscontri = [n for n in vista["nodi"] if n["riscontri"]]
    assert len(con_riscontri) == 5, "tutti i nodi con riscontri restano disegnati"
    assert all(n["stato"] == "critico" for n in con_riscontri)


def test_la_legenda_elenca_solo_i_tipi_presenti(server_app, contesto):
    from snapserver.inventory_queries import network_tree
    from snapserver import map_graphic

    _rete_con_nodi(server_app, contesto, tipo="printer", quanti=4)
    with server_app.app_context():
        albero = network_tree(contesto)
    legenda = map_graphic.legenda(albero)
    tipi = {v["tipo"] for v in legenda}
    assert "printer" in tipi
    assert "hypervisor" not in tipi, "la legenda non elenca i tipi assenti"


def test_una_rete_inesistente_non_ha_disposizione(server_app, contesto):
    from snapserver.inventory_queries import network_tree
    from snapserver import map_graphic

    with server_app.app_context():
        albero = network_tree(contesto)
    assert map_graphic.rete(albero, 999999) is None


# --------------------------------------------------------------------------- #
# Mappa per zone: la griglia di pannelli (una zona per pannello)
# --------------------------------------------------------------------------- #
def _rete_zona(server_app, tenant_id, cidr, zona, quanti=10, con_riscontri=0):
    """Una subnet assegnata a una zona, con dispositivi (alcuni con riscontri)."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        adesso = utc_now_str()
        probe = query("SELECT id FROM probes WHERE tenant_id = ?", (tenant_id,), one=True)
        probe_id = int(probe["id"]) if probe else execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, created_at,"
            " updated_at) VALUES (?, 'uid-zona', 'PZ', 'Sonda zona', 'active', ?, ?)",
            (tenant_id, adesso, adesso))
        subnet_id = execute(
            "INSERT INTO subnets (tenant_id, cidr, zone, host_count, is_enabled,"
            " imported_at, created_at, updated_at) VALUES (?, ?, ?, 254, 1, ?, ?, ?)",
            (tenant_id, cidr, zona, adesso, adesso, adesso))
        base = cidr.rsplit(".", 1)[0]
        for i in range(quanti):
            node_id = execute(
                "INSERT INTO nodes (tenant_id, subnet_id, probe_id, ip, status,"
                " device_type, device_label, device_confidence, first_seen_at,"
                " last_seen_at, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, 'up', 'workstation_windows', 'Postazione Windows',"
                " 80, ?, ?, ?, ?)",
                (tenant_id, subnet_id, probe_id, "%s.%d" % (base, i + 1),
                 adesso, adesso, adesso, adesso))
            if i < con_riscontri:
                execute(
                    "INSERT INTO ti_findings (tenant_id, node_id, kind, title, evidence,"
                    " severity, status, first_seen_at, last_seen_at)"
                    " VALUES (?, ?, 'exposure', 'x', 'x', 'high', 'open', ?, ?)",
                    (tenant_id, node_id, adesso, adesso))
        return subnet_id


def test_ogni_zona_dichiarata_ha_il_suo_pannello_a_prescindere_dai_nodi(
        server_app, contesto):
    """Il difetto che rendeva la mappa inutile: le zone dichiarate con pochi nodi
    sparivano. Ora una zona con dodici nodi e una con venti sono entrambe pannelli
    leggibili, non fette proporzionali."""
    from snapserver.inventory_queries import network_tree
    from snapserver import map_graphic

    _rete_zona(server_app, contesto, "10.50.0.0/24", "datacenter", quanti=3,
               con_riscontri=2)
    _rete_zona(server_app, contesto, "10.1.0.0/24", "utenza", quanti=20)
    _rete_zona(server_app, contesto, "10.2.0.0/24", "utenza", quanti=8)
    with server_app.app_context():
        albero = network_tree(contesto)
    mappa = map_graphic.mappa_zone(albero)

    per_nome = {z["nome"]: z for z in mappa["zone"]}
    assert "Datacenter" in per_nome, "una zona con pochi nodi resta un pannello"
    assert per_nome["Rete di utenza"]["n_reti"] == 2, "le due subnet nello stesso pannello"
    dc = per_nome["Datacenter"]
    assert any(r["stato"] == "critico" for r in dc["reti"]), "i riscontri colorano la rete"
    assert dc["riscontri"] == 2


def test_le_subnet_dichiarate_senza_dispositivi_compaiono_come_vuote(
        server_app, contesto):
    """Il caso che ha fatto arrabbiare: una subnet a cui si e' data una zona ma non
    ancora osservata DEVE comparire nel pannello della sua zona, marcata 'vuota'. Prima
    spariva del tutto."""
    from snapserver.inventory_queries import network_tree
    from snapserver import map_graphic
    from snapserver.db import execute, utc_now_str

    with server_app.app_context():
        adesso = utc_now_str()
        execute("INSERT INTO subnets (tenant_id, cidr, zone, host_count, is_enabled,"
                " imported_at, created_at, updated_at)"
                " VALUES (?, '10.80.0.0/24', 'dmz', 254, 1, ?, ?, ?)",
                (contesto, adesso, adesso, adesso))
        albero = network_tree(contesto)
    mappa = map_graphic.mappa_zone(albero)

    per_nome = {z["nome"]: z for z in mappa["zone"]}
    assert "DMZ" in per_nome, "la zona con una sola subnet vuota compare comunque"
    dmz = per_nome["DMZ"]
    assert dmz["n_reti"] == 1 and dmz["n_vuote"] == 1
    assert dmz["reti"][0]["stato"] == "vuota", "la subnet non osservata e' 'vuota'"
    assert dmz["reti"][0]["cidr"] == "10.80.0.0/24"


def test_la_zona_senza_dichiarazione_sta_in_fondo(server_app, contesto):
    """La grande zona residua non deve stare in cima e schiacciare le dichiarate."""
    from snapserver.inventory_queries import network_tree
    from snapserver import map_graphic

    _rete_zona(server_app, contesto, "10.50.0.0/24", "datacenter", quanti=5)
    _rete_con_nodi(server_app, contesto, cidr="10.99.0.0/24", quanti=40)  # senza zona
    with server_app.app_context():
        albero = network_tree(contesto)
    mappa = map_graphic.mappa_zone(albero)

    assert mappa["zone"][-1]["senza_zona"] is True, (
        "la zona senza dichiarazione e' l'ultimo pannello")
    assert mappa["zone"][0]["senza_zona"] is False


def test_una_zona_con_troppe_subnet_ne_tronca_l_elenco(server_app, contesto):
    """La zona senza dichiarazione, sulla rete reale, ha centinaia di subnet: si
    disegnano le prime, il resto si dichiara e si apre nell'inventario."""
    from snapserver.inventory_queries import network_tree
    from snapserver import map_graphic

    for i in range(map_graphic.MAX_RETI_PER_ZONA + 15):
        _rete_con_nodi(server_app, contesto, cidr="10.%d.0.0/24" % (120 + i), quanti=2)
    with server_app.app_context():
        albero = network_tree(contesto)
    mappa = map_graphic.mappa_zone(albero)

    senza = next(z for z in mappa["zone"] if z["senza_zona"])
    assert len(senza["reti"]) == map_graphic.MAX_RETI_PER_ZONA
    assert senza["non_disegnate"] >= 15
    assert senza["n_reti"] > map_graphic.MAX_RETI_PER_ZONA, "il conteggio resta completo"


def test_la_pagina_della_mappa_per_zone_risponde(logged_client, server_app, contesto):
    _rete_zona(server_app, contesto, "10.50.0.0/24", "datacenter", quanti=10)
    logged_client.post("/switch-tenant", data={"tenant_id": contesto},
                       follow_redirects=True)
    pagina = logged_client.get("/inventory/map/zone").get_data(as_text=True)

    assert "snap-zona-card" in pagina, "il pannello della zona"
    assert "snap-zchip" in pagina, "la pastiglia della subnet"
    assert "Datacenter" in pagina
    assert "10.50.0.0/24" in pagina, "la subnet compare con il suo CIDR"
    assert "<script>" not in pagina, "la CSP vieta il JavaScript in pagina"


def test_la_guida_spiega_i_riscontri_ben_in_vista(logged_client):
    """La parola ricorre ovunque: la guida deve definirla, in una sezione propria e con
    un richiamo in evidenza in cima."""
    pagina = logged_client.get("/guida/").get_data(as_text=True)

    assert 'id="riscontri"' in pagina, "serve una sezione ancorata sui riscontri"
    assert "Che cosa sono i" in pagina and "riscontri" in pagina
    assert "vulnerabilita" in pagina.lower() and "esposizione" in pagina.lower()
    assert "#riscontri" in pagina, "il richiamo in cima porta alla sezione"


# --------------------------------------------------------------------------- #
# La pagina
# --------------------------------------------------------------------------- #
def test_la_pagina_risponde_col_panorama(logged_client, server_app, contesto):
    _rete_con_nodi(server_app, contesto, quanti=6)
    logged_client.post("/switch-tenant", data={"tenant_id": contesto},
                       follow_redirects=True)
    pagina = logged_client.get("/inventory/map/grafica").get_data(as_text=True)
    assert "snap-mappa" in pagina
    assert "snap-mappa-rete" in pagina, "il panorama disegna le reti come bolle"
    # Nessuno script inline: la CSP del progetto vieta il JavaScript in pagina.
    assert "<script>" not in pagina


def test_la_pagina_disegna_una_rete_scelta(logged_client, server_app, contesto):
    subnet_id = _rete_con_nodi(server_app, contesto, quanti=8)
    logged_client.post("/switch-tenant", data={"tenant_id": contesto},
                       follow_redirects=True)
    pagina = logged_client.get(
        "/inventory/map/grafica?subnet=%d" % subnet_id).get_data(as_text=True)
    assert "snap-mappa-nodo" in pagina, "i dispositivi si disegnano uno per uno"
    assert "bi-printer" in pagina, "l'icona del tipo compare"


def test_una_subnet_di_un_altro_tenant_ricade_sul_panorama(logged_client, server_app,
                                                           contesto):
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        execute("INSERT INTO tenants (code, name, created_at, updated_at)"
                " VALUES ('cliente-mappa', 'Cliente mappa', ?, ?)",
                (utc_now_str(), utc_now_str()))
        altro = int(query("SELECT id FROM tenants WHERE code = 'cliente-mappa'",
                          (), one=True)["id"])
    altrui = _rete_con_nodi(server_app, altro, cidr="10.90.0.0/24", quanti=3)
    logged_client.post("/switch-tenant", data={"tenant_id": contesto},
                       follow_redirects=True)
    risposta = logged_client.get("/inventory/map/grafica?subnet=%d" % altrui,
                                 follow_redirects=True)
    assert risposta.status_code == 200
    assert "viene mostrato il panorama" in risposta.get_data(as_text=True)


def test_la_mappa_grafica_si_stampa(logged_client, server_app, contesto):
    """La mappa deve essere stampabile in A4/A3: la barra offre i formati, la pagina
    fissa la dimensione del foglio, e un pulsante avvia la stampa (senza script in
    linea: il gestore sta in un file esterno)."""
    _rete_con_nodi(server_app, contesto, quanti=6)
    logged_client.post("/switch-tenant", data={"tenant_id": contesto},
                       follow_redirects=True)
    pagina = logged_client.get("/inventory/map/grafica").get_data(as_text=True)
    for etichetta in ("A4 orizzontale", "A4 verticale", "A3 orizzontale", "A3 verticale"):
        assert etichetta in pagina, etichetta
    assert "@page" in pagina and "data-print" in pagina
    # Il formato scelto governa @page.
    a3 = logged_client.get("/inventory/map/grafica?foglio=a3-landscape").get_data(
        as_text=True)
    assert "A3 landscape" in a3


def test_un_formato_di_stampa_inventato_ricade_sul_predefinito(logged_client,
                                                               server_app, contesto):
    _rete_con_nodi(server_app, contesto, quanti=3)
    logged_client.post("/switch-tenant", data={"tenant_id": contesto},
                       follow_redirects=True)
    pagina = logged_client.get("/inventory/map/grafica?foglio=a5-x").get_data(
        as_text=True)
    assert "A4 landscape" in pagina, "un valore fuori allowlist ricade sull'A4 orizzontale"
