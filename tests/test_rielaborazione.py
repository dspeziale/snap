"""
snap - Test della rielaborazione dei dati raccolti e della rimozione in blocco.

Due funzioni chieste dall'operatore, con la stessa radice: il prodotto conserva le
prove e ne ricava giudizi, quindi deve poter riapplicare le regole di oggi a cio' che
e' stato raccolto ieri -- altrimenti ogni miglioramento vale solo per il futuro, e
l'inventario si legge con due criteri diversi senza che nulla lo dichiari.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest


def _tenant_id(server_app):
    with server_app.app_context():
        from snapserver.db import query

        return int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])


def _subnet(server_app, tenant_id, cidr, zona=""):
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        return execute(
            "INSERT INTO subnets (tenant_id, cidr, host_count, is_enabled, zone,"
            " imported_at, created_at, updated_at) VALUES (?, ?, 254, 1, ?, ?, ?, ?)",
            (tenant_id, cidr, zona, adesso, adesso, adesso))


def _nodo(server_app, tenant_id, subnet_id, ip, porta=None, servizio=None):
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        node_id = execute(
            "INSERT INTO nodes (tenant_id, subnet_id, ip, status, first_seen_at,"
            " last_seen_at, created_at, updated_at)"
            " VALUES (?, ?, ?, 'up', ?, ?, ?, ?)",
            (tenant_id, subnet_id, ip, adesso, adesso, adesso, adesso))
        if porta:
            execute(
                "INSERT INTO node_ports (tenant_id, node_id, protocol, port, state,"
                " service_name, is_suspect, first_seen_at, last_seen_at)"
                " VALUES (?, ?, 'tcp', ?, 'open', ?, 0, ?, ?)",
                (tenant_id, node_id, porta, servizio or "", adesso, adesso))
        return node_id


# --------------------------------------------------------------------------- #
# Rielaborazione
# --------------------------------------------------------------------------- #
def test_la_rielaborazione_dichiara_i_propri_passi():
    """Chi apre il menu deve poter decidere se gli serve: ogni passo dice che cosa fa
    e perche' sta in quella posizione."""
    from snapserver.rielabora import CHIAVI, descrizione_passi

    passi = descrizione_passi()

    assert [p["chiave"] for p in passi] == list(CHIAVI)
    assert CHIAVI == ("porte", "riconoscimento", "correlazione", "zone"), (
        "l'ordine non e' un dettaglio: ogni passo usa il risultato del precedente")
    assert all(p["titolo"] and p["spiegazione"] for p in passi)


def test_rielaborare_non_avvia_scansioni(server_app):
    """E' la ragione per cui si puo' eseguire in orario di lavoro: rilegge l'archivio
    e non contatta nessuno."""
    tenant_id = _tenant_id(server_app)
    subnet_id = _subnet(server_app, tenant_id, "10.5.0.0/24")
    _nodo(server_app, tenant_id, subnet_id, "10.5.0.9", porta=22, servizio="ssh")

    with server_app.app_context():
        from snapserver.db import query
        from snapserver.rielabora import rielabora

        prima = query("SELECT COUNT(*) AS n FROM scan_runs WHERE tenant_id = ?",
                      (tenant_id,), one=True)["n"]
        esito = rielabora(tenant_id)
        dopo = query("SELECT COUNT(*) AS n FROM scan_runs WHERE tenant_id = ?",
                     (tenant_id,), one=True)["n"]

    assert dopo == prima, "nessuna scansione registrata: non ne e' stata avviata"
    assert esito["nodi"] >= 1
    assert set(esito["passi"]) == {"porte", "riconoscimento", "correlazione", "zone"}


def test_ogni_passo_riferisce_con_numeri(server_app):
    """"Fatto" non e' una risposta: chi rielabora vuole sapere che cosa e' cambiato."""
    tenant_id = _tenant_id(server_app)
    subnet_id = _subnet(server_app, tenant_id, "10.5.1.0/24")
    _nodo(server_app, tenant_id, subnet_id, "10.5.1.9", porta=3389, servizio="ms-wbt-server")

    with server_app.app_context():
        from snapserver.rielabora import rielabora

        esito = rielabora(tenant_id)

    for chiave, dati in esito["passi"].items():
        assert dati.get("riassunto"), "il passo %s non riferisce nulla" % chiave
    assert esito["passi"]["riconoscimento"]["dispositivi"] >= 1
    assert isinstance(esito["durata_s"], float)


def test_si_puo_rielaborare_un_passo_solo(server_app):
    tenant_id = _tenant_id(server_app)
    subnet_id = _subnet(server_app, tenant_id, "10.5.2.0/24")
    _nodo(server_app, tenant_id, subnet_id, "10.5.2.9", porta=445, servizio="microsoft-ds")

    with server_app.app_context():
        from snapserver.rielabora import rielabora

        esito = rielabora(tenant_id, passi=["riconoscimento"])

    assert set(esito["passi"]) == {"riconoscimento"}


def test_un_passo_non_previsto_viene_ignorato(server_app):
    """Allowlist: un nome arbitrario non deve poter guidare la rielaborazione."""
    tenant_id = _tenant_id(server_app)

    with server_app.app_context():
        from snapserver.rielabora import CHIAVI, rielabora

        esito = rielabora(tenant_id, passi=["cancella_tutto", "riconoscimento"])

    assert set(esito["passi"]) == {"riconoscimento"}
    assert "cancella_tutto" not in CHIAVI


def test_la_rielaborazione_riapplica_il_giudizio_delle_zone(server_app):
    """E' il caso per cui la funzione e' stata chiesta: dichiaro una zona oggi, e i
    riscontri di ieri devono essere rivalutati senza aspettare la prossima scansione."""
    tenant_id = _tenant_id(server_app)
    subnet_id = _subnet(server_app, tenant_id, "10.5.3.0/24")
    _nodo(server_app, tenant_id, subnet_id, "10.5.3.9", porta=22, servizio="ssh")

    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str
        from snapserver.rielabora import rielabora
        from snapserver.threat import STATUS_EXPECTED

        rielabora(tenant_id)
        aperti_prima = query(
            "SELECT COUNT(*) AS n FROM ti_findings WHERE tenant_id = ? AND status = 'open'"
            " AND kind = 'exposure'", (tenant_id,), one=True)["n"]

        # La subnet viene dichiarata datacenter: SSH vi e' atteso.
        execute("UPDATE subnets SET zone = 'datacenter', updated_at = ? WHERE id = ?",
                (utc_now_str(), subnet_id))
        esito = rielabora(tenant_id)

        attesi = query("SELECT COUNT(*) AS n FROM ti_findings WHERE tenant_id = ?"
                       " AND status = ?", (tenant_id, STATUS_EXPECTED), one=True)["n"]

    assert aperti_prima >= 1, "senza zona l'esposizione SSH e' aperta"
    assert attesi >= 1, "dichiarata la zona, l'esposizione diventa attesa"
    assert esito["passi"]["zone"]["esposizioni_attese"] == attesi


def test_la_rielaborazione_resta_nel_registro(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.post("/inventory/reprocess", follow_redirects=True)

    assert risposta.status_code == 200
    assert "Rielaborazione conclusa" in risposta.get_data(as_text=True)
    with server_app.app_context():
        from snapserver.db import query

        tracce = query("SELECT description FROM audit_events"
                       " WHERE event_type = 'inventory.reprocessed'", ())
    assert tracce, "la rielaborazione va registrata: cambia i giudizi su tutta la rete"


def test_un_passo_che_cade_non_ferma_gli_altri(server_app, monkeypatch):
    """Un errore in un passo si dichiara e la rielaborazione continua: fermare tutto
    lascerebbe l'archivio a meta', letto con due criteri diversi."""
    tenant_id = _tenant_id(server_app)

    with server_app.app_context():
        import snapserver.ingest as ingest
        from snapserver.rielabora import rielabora

        def esplode(_tenant_id):
            raise RuntimeError("guasto simulato")

        monkeypatch.setattr(ingest, "refingerprint_tenant", esplode)
        esito = rielabora(tenant_id)

    assert esito["passi"]["riconoscimento"]["errore"] == "RuntimeError"
    assert esito["passi"]["riconoscimento"]["riassunto"] == "non eseguito"
    assert "correlazione" in esito["passi"], "i passi successivi vengono eseguiti"


# --------------------------------------------------------------------------- #
# Rimozione in blocco delle subnet
# --------------------------------------------------------------------------- #
def test_si_rimuovono_le_subnet_scelte(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    prima = _subnet(server_app, tenant_id, "10.4.1.0/24")
    seconda = _subnet(server_app, tenant_id, "10.4.2.0/24")
    terza = _subnet(server_app, tenant_id, "10.4.3.0/24")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.post("/inventory/subnets/delete-selected", data={
        "subnet_ids_csv": "%d,%d" % (prima, seconda), "confirm": "2",
    }, follow_redirects=True)

    assert risposta.status_code == 200
    with server_app.app_context():
        from snapserver.db import query

        restanti = [r["id"] for r in query("SELECT id FROM subnets WHERE tenant_id = ?",
                                           (tenant_id,))]
    assert prima not in restanti and seconda not in restanti
    assert terza in restanti, "si rimuove cio' che e' stato scelto, non il resto"


def test_la_conferma_e_il_numero_delle_subnet_scelte(logged_client, server_app):
    """Trenta CIDR da ricopiare non sono una conferma ma un ostacolo, e un ostacolo si
    aggira smettendo di leggere: si chiede il numero, che chi sbaglia selezione ha
    davanti agli occhi."""
    tenant_id = _tenant_id(server_app)
    prima = _subnet(server_app, tenant_id, "10.4.4.0/24")
    seconda = _subnet(server_app, tenant_id, "10.4.5.0/24")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.post("/inventory/subnets/delete-selected", data={
        "subnet_ids_csv": "%d,%d" % (prima, seconda), "confirm": "1",
    }, follow_redirects=True)

    assert "Conferma non corrispondente" in risposta.get_data(as_text=True)
    with server_app.app_context():
        from snapserver.db import query

        assert query("SELECT id FROM subnets WHERE id = ?", (prima,), one=True) is not None


def test_i_dispositivi_non_si_cancellano_col_perimetro(logged_client, server_app):
    """Cancellare l'inventario insieme al perimetro sarebbe distruggere una raccolta
    di mesi per una modifica di configurazione."""
    tenant_id = _tenant_id(server_app)
    subnet_id = _subnet(server_app, tenant_id, "10.4.6.0/24")
    node_id = _nodo(server_app, tenant_id, subnet_id, "10.4.6.9")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.post("/inventory/subnets/delete-selected", data={
        "subnet_ids_csv": str(subnet_id), "confirm": "1",
    }, follow_redirects=True)

    assert "restano in" in risposta.get_data(as_text=True)
    with server_app.app_context():
        from snapserver.db import query

        nodo = query("SELECT id, subnet_id FROM nodes WHERE id = ?", (node_id,), one=True)
    assert nodo is not None, "il dispositivo resta in inventario"


def test_senza_scelte_non_si_rimuove_nulla(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    subnet_id = _subnet(server_app, tenant_id, "10.4.7.0/24")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    logged_client.post("/inventory/subnets/delete-selected",
                       data={"subnet_ids_csv": "", "confirm": "0"},
                       follow_redirects=True)

    with server_app.app_context():
        from snapserver.db import query

        assert query("SELECT id FROM subnets WHERE id = ?", (subnet_id,), one=True) is not None


def test_una_subnet_di_un_altro_tenant_non_si_rimuove(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        altro = execute(
            "INSERT INTO tenants (code, name, timezone, locale, retention_days,"
            " is_active, created_at, updated_at)"
            " VALUES ('altrosub', 'Altro', 'UTC', 'it', 365, 1, ?, ?)", (adesso, adesso))
    estranea = _subnet(server_app, altro, "10.4.8.0/24")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    logged_client.post("/inventory/subnets/delete-selected",
                       data={"subnet_ids_csv": str(estranea), "confirm": "1"},
                       follow_redirects=True)

    with server_app.app_context():
        from snapserver.db import query

        assert query("SELECT id FROM subnets WHERE id = ?", (estranea,), one=True) is not None


def test_la_rimozione_in_blocco_richiede_il_ruolo(server_app):
    tenant_id = _tenant_id(server_app)
    subnet_id = _subnet(server_app, tenant_id, "10.4.9.0/24")

    with server_app.app_context():
        from snapserver.db import execute, utc_now_str
        from snapserver.security import hash_password

        adesso = utc_now_str()
        execute(
            "INSERT INTO users (tenant_id, email, password_hash, full_name, role,"
            " is_active, created_at, updated_at) VALUES (?, 'analista.sub@ised.local',"
            " ?, 'Analista', 'analyst', 1, ?, ?)",
            (tenant_id, hash_password("Analista!2026"), adesso, adesso))

    client = server_app.test_client()
    client.post("/login", data={"email": "analista.sub@ised.local",
                                "password": "Analista!2026"}, follow_redirects=True)
    risposta = client.post("/inventory/subnets/delete-selected",
                           data={"subnet_ids_csv": str(subnet_id), "confirm": "1"})

    assert risposta.status_code in (302, 403)
    with server_app.app_context():
        from snapserver.db import query

        assert query("SELECT id FROM subnets WHERE id = ?", (subnet_id,), one=True) is not None


@pytest.mark.parametrize("pagina,atteso", [
    ("/inventory/subnets", "Rimuovi scelte"),
    ("/inventory/nodes", "Riapplica ai dati raccolti"),
])
def test_i_comandi_sono_nelle_pagine(logged_client, server_app, pagina, atteso):
    tenant_id = _tenant_id(server_app)
    _subnet(server_app, tenant_id, "10.4.10.0/24")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    assert atteso in logged_client.get(pagina).get_data(as_text=True)
