"""
snap - Sala operativa: quadro NOC, quadro SOC, ricerca nella base dati.

Le tre pagine rispondono a tre domande diverse, e le prove insistono sulla differenza:
il NOC guarda l'ULTIMO esito (che cosa non va adesso) e non un errore qualunque delle
ultime ore; il SOC guarda la VARIAZIONE (che cosa e' cambiato) e non lo stato; la
ricerca non accetta SQL da fuori e non restituisce nulla di un altro tenant.

remarks: Autore: Daniele Speziale - Data: 2026-08-29
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from datetime import timedelta

import pytest


# --------------------------------------------------------------------------- #
# Preparazione
# --------------------------------------------------------------------------- #
def _tenant_id(server_app):
    with server_app.app_context():
        from snapserver.db import query

        return int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])


def _bersaglio_e_controllo(server_app, tenant_id, nome="servizio"):
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        target_id = execute(
            "INSERT INTO check_targets (tenant_id, name, address, is_enabled,"
            " created_at, updated_at) VALUES (?, ?, 'servizio.local', 1, ?, ?)",
            (tenant_id, nome, adesso, adesso))
        check_id = execute(
            "INSERT INTO checks (tenant_id, target_id, name, kind, config_json,"
            " interval_seconds, timeout_seconds, is_enabled, severity,"
            " failure_threshold, escalation_threshold, created_at, updated_at)"
            " VALUES (?, ?, ?, 'http', '{}', 300, 10, 1, 'critical', 2, 6, ?, ?)",
            (tenant_id, target_id, nome, adesso, adesso))
        return check_id, target_id


def _esiti(server_app, tenant_id, check_id, stati):
    """Esiti in ordine cronologico: l'ultimo della lista e' il piu' recente."""
    with server_app.app_context():
        from snapserver.db import execute, utc_now, utc_str

        adesso = utc_now()
        for indice, stato in enumerate(stati):
            quando = utc_str(adesso - timedelta(minutes=(len(stati) - indice) * 5))
            execute(
                "INSERT INTO check_results (tenant_id, check_id, probe_id, executed_at,"
                " status, latency_ms, detail, received_at)"
                " VALUES (?, ?, NULL, ?, ?, 120, 'prova', ?)",
                (tenant_id, check_id, quando, stato, quando))


def _nodo(server_app, tenant_id, ip, porte=(), giorni_fa=0, ultimo_contatto=0):
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now, utc_now_str, utc_str

        adesso = utc_now_str()
        primo = utc_str(utc_now() - timedelta(days=giorni_fa))
        visto = utc_str(utc_now() - timedelta(hours=ultimo_contatto))
        subnet = query("SELECT id FROM subnets WHERE tenant_id = ?", (tenant_id,),
                       one=True)
        subnet_id = int(subnet["id"]) if subnet else execute(
            "INSERT INTO subnets (tenant_id, cidr, host_count, is_enabled, imported_at,"
            " created_at, updated_at) VALUES (?, '10.9.0.0/24', 254, 1, ?, ?, ?)",
            (tenant_id, adesso, adesso, adesso))
        node_id = execute(
            "INSERT INTO nodes (tenant_id, subnet_id, ip, status, device_type,"
            " device_label, device_confidence, first_seen_at, last_seen_at,"
            " created_at, updated_at)"
            " VALUES (?, ?, ?, ?, 'server', 'Server Linux', 90, ?, ?, ?, ?)",
            (tenant_id, subnet_id, ip, "up" if ultimo_contatto < 6 else "down",
             primo, visto, adesso, adesso))
        for protocollo, porta in porte:
            execute(
                "INSERT INTO node_ports (tenant_id, node_id, protocol, port, state,"
                " service_name, is_suspect, first_seen_at, last_seen_at)"
                " VALUES (?, ?, ?, ?, 'open', 'servizio', 0, ?, ?)",
                (tenant_id, node_id, protocollo, porta, primo, adesso))
        return node_id


# --------------------------------------------------------------------------- #
# NOC
# --------------------------------------------------------------------------- #
def test_il_noc_guarda_l_ultimo_esito_non_un_errore_qualunque(server_app):
    """Un controllo che ha fallito alle tre ma alle quattro e' tornato a posto non e'
    un problema aperto: la domanda del turno e' che cosa non funziona ADESSO."""
    from snapserver.operations import failing_now

    tenant_id = _tenant_id(server_app)
    rotto, _ = _bersaglio_e_controllo(server_app, tenant_id, "rotto")
    guarito, _ = _bersaglio_e_controllo(server_app, tenant_id, "guarito")
    _esiti(server_app, tenant_id, rotto, ["ok", "timeout", "timeout"])
    _esiti(server_app, tenant_id, guarito, ["timeout", "timeout", "ok"])

    with server_app.app_context():
        in_errore = failing_now(tenant_id)

    assert [r["check_name"] for r in in_errore] == ["rotto"]
    assert in_errore[0]["falliti_24h"] == 2, "il conteggio delle 24 ore resta"


def test_il_noc_riconosce_cio_che_va_e_viene(server_app):
    """Un servizio fermo si vede; uno che va e viene consuma il turno e non compare
    in nessun elenco di errori, perche' quando lo si guarda funziona."""
    from snapserver.operations import flapping

    tenant_id = _tenant_id(server_app)
    ballerino, _ = _bersaglio_e_controllo(server_app, tenant_id, "ballerino")
    stabile, _ = _bersaglio_e_controllo(server_app, tenant_id, "stabile")
    _esiti(server_app, tenant_id, ballerino,
           ["ok", "timeout", "ok", "timeout", "ok"])
    _esiti(server_app, tenant_id, stabile, ["ok", "ok", "ok", "ok"])

    with server_app.app_context():
        instabili = flapping(tenant_id)

    assert [r["check_name"] for r in instabili] == ["ballerino"]
    assert instabili[0]["cambi"] == 4


def test_il_noc_elenca_chi_tace_da_ore(server_app):
    from snapserver.operations import silent_nodes

    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.1", ultimo_contatto=0)
    _nodo(server_app, tenant_id, "10.9.0.2", ultimo_contatto=48)

    with server_app.app_context():
        silenzi = silent_nodes(tenant_id)

    assert [n["ip"] for n in silenzi] == ["10.9.0.2"]


def test_il_quadro_del_turno_dice_se_e_tranquillo(server_app):
    from snapserver.operations import noc_board

    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        quadro = noc_board(tenant_id)
    assert quadro["tranquillo"] is True

    rotto, _ = _bersaglio_e_controllo(server_app, tenant_id, "rotto")
    _esiti(server_app, tenant_id, rotto, ["timeout"])
    with server_app.app_context():
        quadro = noc_board(tenant_id)
    assert quadro["tranquillo"] is False
    assert quadro["in_errore"]


def test_la_pagina_del_noc_si_apre_e_dice_lo_stato(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    rotto, _ = _bersaglio_e_controllo(server_app, tenant_id, "portale")
    _esiti(server_app, tenant_id, rotto, ["ok", "timeout"])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/ops/noc").get_data(as_text=True)
    assert "Quadro NOC" in pagina
    assert "Non funziona adesso" in pagina
    assert "portale" in pagina
    assert "controlli in errore" in pagina


# --------------------------------------------------------------------------- #
# SOC
# --------------------------------------------------------------------------- #
def test_il_soc_apre_con_le_variazioni(server_app):
    """Una porta aperta da sempre e' architettura nota, la stessa aperta ieri e' un
    evento (RP-12)."""
    from snapserver.operations import soc_board

    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.10", [("tcp", 3389)], giorni_fa=0)
    _nodo(server_app, tenant_id, "10.9.0.11", [("tcp", 80)], giorni_fa=90)

    with server_app.app_context():
        quadro = soc_board(tenant_id, giorni=7)

    assert [p["ip"] for p in quadro["porte_nuove"]] == ["10.9.0.10"]
    assert [n["ip"] for n in quadro["nodi_nuovi"]] == ["10.9.0.10"]
    assert quadro["variazioni_totali"] == 2


def test_la_finestra_del_soc_cambia_cio_che_si_vede(server_app):
    from snapserver.operations import soc_board

    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.12", [("tcp", 22)], giorni_fa=15)

    with server_app.app_context():
        settimana = soc_board(tenant_id, giorni=7)
        mese = soc_board(tenant_id, giorni=30)

    assert settimana["nodi_nuovi"] == []
    assert [n["ip"] for n in mese["nodi_nuovi"]] == ["10.9.0.12"]


def test_il_soc_segnala_le_identita_cambiate(server_app):
    """Un indirizzo che era una stampante e adesso e' un server non e' un
    aggiornamento del catalogo."""
    from snapserver.operations import identity_changes

    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id, "10.9.0.13")
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        execute(
            "INSERT INTO node_changes (tenant_id, node_id, kind, subject, before_value,"
            " after_value, severity, created_at)"
            " VALUES (?, ?, 'device_type.changed', '10.9.0.13', 'Stampante',"
            " 'Server Windows', 'warning', ?)", (tenant_id, node_id, utc_now_str()))
        cambi = identity_changes(tenant_id)

    assert len(cambi) == 1 and cambi[0]["after_value"] == "Server Windows"


def test_la_pagina_del_soc_si_apre_con_le_finestre(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.14", [("tcp", 445)])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/ops/soc").get_data(as_text=True)
    assert "Quadro SOC" in pagina
    assert "variazioni" in pagina.lower()
    assert "10.9.0.14" in pagina

    # Una finestra non prevista non e' un errore: vale quella predefinita.
    inventata = logged_client.get("/ops/soc?giorni=999").get_data(as_text=True)
    assert "7 giorni" in inventata or "Quadro SOC" in inventata


# --------------------------------------------------------------------------- #
# Ricerca
# --------------------------------------------------------------------------- #
def test_la_ricerca_libera_guarda_in_piu_generi_di_dato(server_app):
    from snapserver.searchdb import global_search

    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.20", [("tcp", 22)])

    with server_app.app_context():
        esito = global_search(tenant_id, "10.9.0.20")

    generi = {g["chiave"] for g in esito["generi"]}
    assert "nodi" in generi
    assert esito["totale"] >= 1


def test_una_ricerca_troppo_corta_non_restituisce_mezzo_inventario(server_app):
    from snapserver.searchdb import global_search

    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.21")

    with server_app.app_context():
        esito = global_search(tenant_id, "1")

    assert esito["troppo_corto"] is True
    assert esito["generi"] == []


def test_la_ricerca_non_esce_dal_tenant(server_app):
    """Un altro tenant non e' raggiungibile nemmeno cercando il suo indirizzo."""
    from snapserver.searchdb import global_search

    primo = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        secondo = execute(
            "INSERT INTO tenants (code, name, timezone, locale, retention_days,"
            " is_active, created_at, updated_at)"
            " VALUES ('altro', 'Altro', 'UTC', 'it', 365, 1, ?, ?)", (adesso, adesso))
    _nodo(server_app, secondo, "10.99.0.1")

    with server_app.app_context():
        esito = global_search(primo, "10.99.0.1")

    assert esito["totale"] == 0


@pytest.mark.parametrize("chiave", [
    "desktop_remoto", "in_chiaro", "banche_dati", "con_versione", "non_identificati",
    "comparsi", "spariti", "porte_diffuse", "prodotti", "snmp_aperti", "kev",
    "controlli_peggiori", "latenza", "copertura", "eventi_gravi", "conferimenti",
])
def test_ogni_interrogazione_pronta_gira(server_app, chiave):
    """Un'interrogazione che non gira si scopre in demo: qui si scopre prima."""
    from snapserver.searchdb import run_saved

    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.30", [("tcp", 3389), ("tcp", 23)])

    with server_app.app_context():
        esito = run_saved(tenant_id, chiave)

    assert esito, "l'interrogazione %s deve esistere" % chiave
    assert esito["colonne"], "ogni interrogazione dichiara le sue colonne"
    for riga in esito["righe"]:
        assert len(riga) == len(esito["colonne"]), (
            "%s: riga con un numero di celle diverso dalle colonne" % chiave)


def test_un_interrogazione_inventata_non_esegue_nulla(server_app):
    """Nessun SQL arriva da fuori: la chiave deve esistere nel catalogo."""
    from snapserver.searchdb import run_saved

    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        assert run_saved(tenant_id, "'; DROP TABLE nodes; --") == {}
        assert run_saved(tenant_id, "inventata") == {}


def test_l_esportazione_csv_e_tracciata(logged_client, server_app):
    """Un CSV finisce in una cartella condivisa e puo' contenere indirizzi e nomi
    host: chi lo ha chiesto e quante righe si e' portato via restano nel registro."""
    tenant_id = _tenant_id(server_app)
    _nodo(server_app, tenant_id, "10.9.0.31", [("tcp", 3389)])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.get("/ops/search/export/desktop_remoto")
    assert risposta.status_code == 200
    assert "text/csv" in risposta.headers["Content-Type"]
    assert "attachment" in risposta.headers["Content-Disposition"]
    corpo = risposta.get_data(as_text=True)
    assert "10.9.0.31" in corpo
    assert ";" in corpo.splitlines()[0], "separatore per i fogli di calcolo italiani"

    with server_app.app_context():
        from snapserver.db import query

        tracce = query("SELECT description FROM audit_events"
                       " WHERE event_type = 'search.exported'", ())
    assert tracce, "l'esportazione deve lasciare traccia"


def test_l_esportazione_di_una_chiave_inventata_non_produce_file(logged_client,
                                                                 server_app):
    tenant_id = _tenant_id(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)
    assert logged_client.get("/ops/search/export/inventata").status_code == 404


def test_la_pagina_di_ricerca_offre_le_domande_pronte(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/ops/search").get_data(as_text=True)
    assert "Ricerca nella base dati" in pagina
    assert "Domande gia' scritte" in pagina or "Domande gia&#39; scritte" in pagina
    assert "Chi espone il desktop remoto" in pagina


def test_la_sala_operativa_ha_il_suo_menu(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)
    corpo = logged_client.get("/").get_data(as_text=True)
    menu = corpo[corpo.index("app-sidebar"):corpo.index("</aside>")]

    assert 'data-snap-gruppo="sala"' in menu
    for voce, indirizzo in (("Quadro NOC", "/ops/noc"), ("Quadro SOC", "/ops/soc"),
                            ("Ricerca", "/ops/search")):
        assert voce in menu and indirizzo in menu


# --------------------------------------------------------------------------- #
# Silenzio e copertura sono due fatti diversi
# --------------------------------------------------------------------------- #
def _campione(server_app, node_id, ore_fa, risponde):
    """Un campione di raggiungibilita' nel passato."""
    from datetime import timedelta

    with server_app.app_context():
        from snapserver.db import execute, utc_now, utc_str

        quando = utc_str(utc_now() - timedelta(hours=ore_fa))
        execute("INSERT INTO monitor_samples (tenant_id, node_id, checked_at,"
                " reachable, latency_ms) VALUES ("
                " (SELECT tenant_id FROM nodes WHERE id = ?), ?, ?, ?, 5.0)",
                (node_id, node_id, quando, 1 if risponde else 0))


def test_un_nodo_che_ha_risposto_non_e_in_silenzio(server_app):
    """Difetto misurato su 10.20.10.1: stato `up`, ultima verifica del giorno prima e
    RAGGIUNGIBILE, eppure la pagina lo dichiarava in silenzio, perche' guardava
    l'ultima volta in cui era stato VISTO. Su tremila nodi la sorveglianza ruota, e
    "non ha risposto" non e' "non gliel'abbiamo chiesto"."""
    from snapserver.operations import silent_nodes, unchecked_nodes

    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id, "10.9.1.1", ultimo_contatto=1)
    _campione(server_app, node_id, ore_fa=30, risponde=True)

    with server_app.app_context():
        silenzi = silent_nodes(tenant_id)
        mancanti = unchecked_nodes(tenant_id)

    assert [n["ip"] for n in silenzi] == [], "ha risposto: non e' in silenzio"
    assert [n["ip"] for n in mancanti] == ["10.9.1.1"], (
        "non e' stato interrogato nelle ultime 24 ore: e' copertura che manca")


def test_un_nodo_che_non_ha_risposto_e_in_silenzio(server_app):
    from snapserver.operations import silent_nodes

    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id, "10.9.1.2", ultimo_contatto=2)
    _campione(server_app, node_id, ore_fa=1, risponde=False)

    with server_app.app_context():
        silenzi = silent_nodes(tenant_id)

    assert [n["ip"] for n in silenzi] == ["10.9.1.2"]
    assert silenzi[0]["ultimo_esito"] == 0


def test_la_pagina_distingue_i_due_casi(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id, "10.9.1.3", ultimo_contatto=1)
    _campione(server_app, node_id, ore_fa=30, risponde=True)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/ops/noc").get_data(as_text=True)
    assert "NON INTERROGATI" in pagina
    assert "non hanno un guasto" in pagina
    assert "10.9.1.3" in pagina
