"""
snap - Test del governo delle zone di rete e della loro presenza nella mappa.

Le zone erano un catalogo chiuso nel codice (decisione AD-15). Su richiesta
dell'operatore diventano un dato del tenant: "rete di collaudo", "rete fornitori",
"rete di cantiere" nessuno le puo' prevedere dal prodotto. Cio' che resta nel codice
e' quello che il cliente non deve poter inventare: le FAMIGLIE di esposizione, che
sono i titoli delle regole di correlazione -- una famiglia scritta a mano non
corrisponderebbe a nessuna regola e sembrerebbe attiva senza fare nulla.

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


def _subnet(server_app, tenant_id, cidr="10.7.0.0/24", zona=""):
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        return execute(
            "INSERT INTO subnets (tenant_id, cidr, host_count, is_enabled, zone,"
            " imported_at, created_at, updated_at) VALUES (?, ?, 254, 1, ?, ?, ?, ?)",
            (tenant_id, cidr, zona, adesso, adesso, adesso))


# --------------------------------------------------------------------------- #
# Il seme
# --------------------------------------------------------------------------- #
def test_un_tenant_nuovo_trova_le_zone_del_prodotto(server_app):
    """Un'installazione aggiornata deve trovare il proprio contesto gia' dichiarato,
    non un elenco vuoto: le sei zone del prodotto sono il punto di partenza."""
    with server_app.app_context():
        from snapserver import zones

        catalogo = zones.catalogo(_tenant_id(server_app))

    chiavi = [voce["chiave"] for voce in catalogo]
    assert "datacenter" in chiavi and "utenza" in chiavi
    assert len(chiavi) == len(zones.SEME)
    assert all(voce["predefinita"] for voce in catalogo)


def test_le_famiglie_vengono_dalle_regole_non_da_un_secondo_elenco(server_app):
    """Due elenchi divergono: il primo sintomo sarebbe una zona che dichiara qualcosa
    su una famiglia che non esiste piu', senza che nulla lo segnali."""
    with server_app.app_context():
        from snapserver import zones
        from snapserver.threat import EXPOSURE_RULES

        famiglie = zones.famiglie_esposizione()

    assert famiglie == sorted({r["titolo"] for r in EXPOSURE_RULES})
    assert famiglie, "senza famiglie una zona non potrebbe dichiarare nulla"


# --------------------------------------------------------------------------- #
# Creazione, modifica, eliminazione
# --------------------------------------------------------------------------- #
def test_si_crea_una_zona_propria(server_app):
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver import zone_admin, zones

        chiave = zone_admin.crea(
            tenant_id, nome="Rete di collaudo",
            descrizione="Ambiente di prova, isolato dalla produzione.",
            icona="bi-beaker", tono="info",
            attese=["Accesso remoto SSH raggiungibile"],
            violazioni=["Banca dati raggiungibile dalla rete"])
        voce = zones.zona(chiave, tenant_id)

    assert chiave == "rete-di-collaudo", "la chiave si ricava dal nome"
    assert voce["nome"] == "Rete di collaudo"
    assert voce["attese"] == ["Accesso remoto SSH raggiungibile"]
    assert not voce["predefinita"]


def test_la_chiave_si_ricava_dal_nome_e_resta_unica(server_app):
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver import zone_admin

        prima = zone_admin.crea(tenant_id, nome="Rete ospiti")
        seconda = zone_admin.crea(tenant_id, nome="Rete ospiti")

    assert prima != seconda, "due zone non possono avere la stessa chiave"
    assert seconda.startswith("rete-ospiti")


def test_una_famiglia_inventata_non_entra(server_app):
    """Allowlist: una famiglia che non corrisponde a nessuna regola non produrrebbe
    nessun giudizio pur sembrando attiva."""
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver import zone_admin, zones

        chiave = zone_admin.crea(
            tenant_id, nome="Zona con famiglie finte",
            attese=["Porta magica aperta", "Accesso remoto SSH raggiungibile"],
            violazioni=["<script>alert(1)</script>"])
        voce = zones.zona(chiave, tenant_id)

    assert voce["attese"] == ["Accesso remoto SSH raggiungibile"]
    assert voce["violazioni"] == []


def test_una_famiglia_non_puo_essere_attesa_e_violazione(server_app):
    """Sarebbe una regola che contraddice se stessa, e il giudizio dipenderebbe
    dall'ordine di lettura."""
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver import zone_admin, zones

        chiave = zone_admin.crea(
            tenant_id, nome="Zona contraddittoria",
            attese=["SNMP leggibile"], violazioni=["SNMP leggibile"])
        voce = zones.zona(chiave, tenant_id)

    assert voce["attese"] == ["SNMP leggibile"]
    assert voce["violazioni"] == [], "in caso di conflitto vince l'attesa"


@pytest.mark.parametrize("icona", ["<script>", "javascript:alert(1)", "bi", "immagine.png"])
def test_un_icona_non_riconosciuta_viene_rifiutata(server_app, icona):
    """Il valore finisce in `class="..."`: un testo arbitrario non entra."""
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver.zone_admin import ZonaError, crea

        with pytest.raises(ZonaError):
            crea(tenant_id, nome="Zona con icona strana", icona=icona)


def test_un_colore_non_previsto_viene_rifiutato(server_app):
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver.zone_admin import ZonaError, crea

        with pytest.raises(ZonaError):
            crea(tenant_id, nome="Zona colorata", tono="fucsia")


def test_anche_una_zona_predefinita_si_puo_modificare(server_app):
    """Su una rete reale "datacenter" puo' voler dire cose diverse: imporre la nostra
    idea avrebbe come solo effetto che l'operatore smette di usare la funzione."""
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver import zone_admin, zones

        zone_admin.aggiorna(tenant_id, "datacenter", nome="Centro elaborazione dati",
                            descrizione="Sala macchine di sede.", icona="bi-hdd-rack",
                            tono="primary", attese=["SNMP leggibile"], violazioni=[])
        voce = zones.zona("datacenter", tenant_id)

    assert voce["nome"] == "Centro elaborazione dati"
    assert voce["attese"] == ["SNMP leggibile"]
    assert voce["predefinita"], "resta marcata come predefinita: il ripristino la conosce"


def test_il_ripristino_riporta_le_predefinite_e_non_tocca_le_altre(server_app):
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver import zone_admin, zones

        mia = zone_admin.crea(tenant_id, nome="Rete di cantiere")
        zone_admin.aggiorna(tenant_id, "datacenter", nome="Stravolta", descrizione="",
                            icona="bi-x", tono="dark", attese=[], violazioni=[])

        zone_admin.semina(tenant_id, forzando=True)

        datacenter = zones.zona("datacenter", tenant_id)
        cantiere = zones.zona(mia, tenant_id)

    assert datacenter["nome"] == "Datacenter", "la predefinita torna all'origine"
    assert datacenter["attese"], "torna con le sue famiglie attese"
    assert cantiere["nome"] == "Rete di cantiere", "la zona creata non viene toccata"


# --------------------------------------------------------------------------- #
# Eliminazione: dove finiscono le subnet
# --------------------------------------------------------------------------- #
def test_eliminando_una_zona_le_subnet_restano_senza_contesto(server_app):
    """Eliminando il contesto si perde la giustificazione, non la si eredita: senza
    zona vale come rete di utenza, cioe' il giudizio piu' severo."""
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver import zone_admin
        from snapserver.db import query

        chiave = zone_admin.crea(tenant_id, nome="Rete temporanea")
    _subnet(server_app, tenant_id, "10.7.1.0/24", zona=chiave)

    with server_app.app_context():
        from snapserver import zone_admin
        from snapserver.db import query

        esito = zone_admin.elimina(tenant_id, chiave)
        riga = query("SELECT zone FROM subnets WHERE cidr = '10.7.1.0/24'", (), one=True)

    assert esito["subnet_riassegnate"] == 1
    assert (riga["zone"] or "") == ""


def test_eliminando_una_zona_le_subnet_si_possono_riassegnare(server_app):
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver import zone_admin

        chiave = zone_admin.crea(tenant_id, nome="Rete provvisoria")
    _subnet(server_app, tenant_id, "10.7.2.0/24", zona=chiave)

    with server_app.app_context():
        from snapserver import zone_admin
        from snapserver.db import query

        esito = zone_admin.elimina(tenant_id, chiave, riassegna_a="datacenter")
        riga = query("SELECT zone FROM subnets WHERE cidr = '10.7.2.0/24'", (), one=True)

    assert esito["destinazione"] == "datacenter"
    assert riga["zone"] == "datacenter"


def test_una_zona_eliminata_non_giudica_piu(server_app):
    """E' il punto che conta: il catalogo governa i giudizi, quindi eliminando una
    zona i riscontri delle sue subnet cambiano valutazione."""
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver import zone_admin, zones

        chiave = zone_admin.crea(tenant_id, nome="Rete tollerante",
                                 attese=["Accesso remoto SSH raggiungibile"])
        prima = zones.giudizio(chiave, "Accesso remoto SSH raggiungibile", tenant_id)

        zone_admin.elimina(tenant_id, chiave)
        dopo = zones.giudizio(chiave, "Accesso remoto SSH raggiungibile", tenant_id)

    assert prima == zones.ATTESA
    assert dopo == zones.NORMALE, "senza la zona vale la gravita' della regola"


# --------------------------------------------------------------------------- #
# Le pagine
# --------------------------------------------------------------------------- #
def test_la_pagina_elenca_le_zone_con_i_loro_numeri(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    _subnet(server_app, tenant_id, "10.7.3.0/24", zona="datacenter")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/zones").get_data(as_text=True)

    assert "Zone di rete" in pagina
    assert "Datacenter" in pagina
    assert "Perimetro senza zona" in pagina
    assert 'name="attese"' in pagina, "le famiglie si scelgono da un elenco chiuso"


def test_si_crea_una_zona_dalla_pagina(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.post("/inventory/zones/create", data={
        "nome": "Rete fornitori", "tono": "warning", "icona": "bi-truck",
        "descrizione": "Apparati di terzi, non gestiti da noi.",
        "attese": ["Accesso remoto SSH raggiungibile"],
    }, follow_redirects=True)

    assert risposta.status_code == 200
    with server_app.app_context():
        from snapserver import zones

        assert "rete-fornitori" in zones.per_chiave(tenant_id)


def test_la_mappa_mostra_le_zone(logged_client, server_app):
    """Un albero dice DOVE sta una cosa; la zona dice CHE COSA e' quel posto."""
    tenant_id = _tenant_id(server_app)
    subnet_id = _subnet(server_app, tenant_id, "10.7.4.0/24", zona="datacenter")
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        execute("INSERT INTO nodes (tenant_id, subnet_id, ip, status, first_seen_at,"
                " last_seen_at, created_at, updated_at)"
                " VALUES (?, ?, '10.7.4.9', 'up', ?, ?, ?, ?)",
                (tenant_id, subnet_id, adesso, adesso, adesso, adesso))
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/map").get_data(as_text=True)

    assert "Per zona di rete" in pagina, "la mappa si legge anche per contesto"
    assert "SUBNET SENZA ZONA" in pagina, "il perimetro non descritto e' un numero in vista"
    assert "Datacenter" in pagina


def test_la_mappa_dichiara_le_subnet_senza_zona(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    subnet_id = _subnet(server_app, tenant_id, "10.7.5.0/24", zona="")
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        execute("INSERT INTO nodes (tenant_id, subnet_id, ip, status, first_seen_at,"
                " last_seen_at, created_at, updated_at)"
                " VALUES (?, ?, '10.7.5.9', 'up', ?, ?, ?, ?)",
                (tenant_id, subnet_id, adesso, adesso, adesso, adesso))
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/map").get_data(as_text=True)

    assert "Senza zona dichiarata" in pagina
    assert "senza zona" in pagina


def test_governare_le_zone_richiede_il_ruolo(server_app):
    """Un analista legge, un amministratore di tenant dichiara: il contesto cambia i
    giudizi su tutta la rete."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str
        from snapserver.security import hash_password

        adesso = utc_now_str()
        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
        execute(
            "INSERT INTO users (tenant_id, email, password_hash, full_name, role,"
            " is_active, created_at, updated_at) VALUES (?, 'analista.zone@ised.local', ?,"
            " 'Analista', 'analyst', 1, ?, ?)",
            (tenant_id, hash_password("Analista!2026"), adesso, adesso))

    client = server_app.test_client()
    client.post("/login", data={"email": "analista.zone@ised.local",
                                "password": "Analista!2026"}, follow_redirects=True)

    assert client.get("/inventory/zones").status_code == 200, "la lettura e' consentita"
    risposta = client.post("/inventory/zones/create", data={"nome": "Zona abusiva"})
    assert risposta.status_code in (302, 403)
    with server_app.app_context():
        from snapserver import zones

        assert "zona-abusiva" not in zones.per_chiave(tenant_id)


# --------------------------------------------------------------------------- #
# Ereditarieta' fra zone, e tabella piatta
# --------------------------------------------------------------------------- #
def test_una_zona_nuova_puo_ereditare_da_un_altra(server_app):
    """Chi dichiara "rete di collaudo" ha in mente qualcosa di simile al datacenter,
    con una differenza o due. Una zona nuova con gli elenchi vuoti non giudica
    niente: sembra dichiarata e non fa nulla."""
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver import zone_admin, zones

        datacenter = zones.zona("datacenter", tenant_id)
        chiave = zone_admin.crea(tenant_id, nome="Rete di collaudo",
                                 eredita_da="datacenter")
        nuova = zones.zona(chiave, tenant_id)

    assert nuova["attese"] == sorted(datacenter["attese"])
    assert nuova["violazioni"] == sorted(datacenter["violazioni"])


def test_cio_che_si_scegle_vince_sull_ereditarieta(server_app):
    """Altrimenti una spunta togliuta tornerebbe da sola."""
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver import zone_admin, zones

        chiave = zone_admin.crea(tenant_id, nome="Rete mista",
                                 eredita_da="datacenter",
                                 attese=["SNMP leggibile"])
        nuova = zones.zona(chiave, tenant_id)

    assert nuova["attese"] == ["SNMP leggibile"]
    assert nuova["violazioni"] == [], "non si eredita a meta'"


def test_ereditare_da_una_zona_che_non_esiste_e_un_errore(server_app):
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver.zone_admin import ZonaError, crea

        with pytest.raises(ZonaError):
            crea(tenant_id, nome="Zona orfana", eredita_da="non-esiste")


def test_il_modulo_offre_le_zone_da_cui_partire(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/zones").get_data(as_text=True)

    assert 'name="eredita_da"' in pagina
    assert "data-attese=" in pagina, (
        "le famiglie viaggiano nella pagina: si spuntano subito, senza un giro al server")
    assert "snap-zone.js" in pagina


def test_la_tabella_delle_zone_resta_piatta(server_app):
    """Difetto segnalato: dentro il corpo di una tabella interattiva una riga con una
    sola cella in `colspan` rompe il modello delle colonne -- DataTables chiede la
    colonna 1 e non la trova. I moduli stanno fuori dalla tabella."""
    from pathlib import Path as _Path

    sorgente = (_Path(__file__).resolve().parent.parent
                / "server/snapserver/templates/inventory/zones.html").read_text(
                    encoding="utf-8")

    tabella = sorgente[sorgente.index("<tbody>"):sorgente.index("</tbody>")]
    assert "colspan" not in tabella, "nessuna riga con colspan dentro la tabella"
    assert 'class="collapse"' not in tabella, "nessuna riga collassabile nella tabella"
    # I pannelli esistono, fuori dalla tabella.
    assert 'id="zona-{{ voce.chiave }}"' in sorgente
    assert 'id="elimina-{{ voce.chiave }}"' in sorgente


# --------------------------------------------------------------------------- #
# Una zona creata si vede in tutti gli elenchi, non solo nella propria pagina
# --------------------------------------------------------------------------- #
def _zona_nuova(server_app, tenant_id, nome="Rete di cantiere"):
    with server_app.app_context():
        from snapserver import zone_admin

        return zone_admin.crea(tenant_id, nome=nome)


def test_la_zona_creata_compare_nel_perimetro_di_scansione(logged_client, server_app):
    """Difetto segnalato: nel Perimetro si vedevano solo le predefinite. Una zona che
    non si puo' assegnare a una subnet e' una zona che non esiste."""
    tenant_id = _tenant_id(server_app)
    chiave = _zona_nuova(server_app, tenant_id)
    # Serve una subnet: la zona si assegna dove la subnet vive, ed e' quel menu che
    # all'operatore risultava incompleto.
    _subnet(server_app, tenant_id, cidr="10.8.0.0/24")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/subnets").get_data(as_text=True)

    assert 'value="%s"' % chiave in pagina, "si deve poter assegnare alla subnet"
    assert pagina.count("Rete di cantiere") >= 2, "nel menu e nella legenda delle zone"


def test_la_zona_creata_compare_nel_filtro_dei_dispositivi(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    chiave = _zona_nuova(server_app, tenant_id, nome="Rete fornitori")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/nodes").get_data(as_text=True)

    assert chiave in pagina
    assert "Rete fornitori" in pagina


def test_una_zona_eliminata_non_resta_negli_elenchi(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    chiave = _zona_nuova(server_app, tenant_id, nome="Rete provvisoria")
    with server_app.app_context():
        from snapserver import zone_admin, zones

        zone_admin.elimina(tenant_id, chiave, riassegna_a=None)
        zones.dimentica_catalogo()
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/subnets").get_data(as_text=True)

    assert "Rete provvisoria" not in pagina


def test_la_postura_conosce_le_zone_del_tenant(server_app):
    """La sala operativa raggruppa per zona: con il seme al posto del catalogo, una
    subnet dichiarata in una zona creata risultava "non dichiarata"."""
    tenant_id = _tenant_id(server_app)
    chiave = _zona_nuova(server_app, tenant_id, nome="Rete di collaudo")
    _subnet(server_app, tenant_id, cidr="10.9.0.0/24", zona=chiave)

    with server_app.app_context():
        from snapserver import zones
        from snapserver.operations import zone_posture

        zones.dimentica_catalogo()
        postura = zone_posture(tenant_id)

    nomi = [voce["nome"] for voce in postura["zone"]]
    assert "Rete di collaudo" in nomi, "la subnet non deve risultare non dichiarata"
    assert chiave in [voce["chiave"] for voce in postura["catalogo"]]


def test_cambiando_la_zona_il_prodotto_dice_come_rivalutare(logged_client, server_app):
    """La mappa e i filtri mostrano la zona subito; i riscontri gia' registrati no.
    "Alla prossima correlazione" da solo lascia l'operatore a chiedersi se deve
    aspettare: il messaggio dice anche come farlo adesso."""
    tenant_id = _tenant_id(server_app)
    subnet_id = _subnet(server_app, tenant_id, cidr="10.11.0.0/24")
    chiave = _zona_nuova(server_app, tenant_id, nome="Rete di produzione")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.post("/inventory/subnets/%d/zone" % subnet_id,
                                  data={"zone": chiave}, follow_redirects=True)
    testo = risposta.get_data(as_text=True)

    assert "Rete di produzione" in testo
    assert "mappa della rete" in testo
    # L'apostrofo esce come entita' HTML: si cerca la parte che non ne ha.
    assert "Riapplica ai dati" in testo and "raccolti" in testo


def test_la_mappa_mostra_subito_la_zona_appena_assegnata(logged_client, server_app):
    """La mappa non si ricostruisce: legge la zona dalla subnet a ogni apertura."""
    tenant_id = _tenant_id(server_app)
    subnet_id = _subnet(server_app, tenant_id, cidr="10.12.0.0/24")
    chiave = _zona_nuova(server_app, tenant_id, nome="Rete di collaudo web")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)
    logged_client.post("/inventory/subnets/%d/zone" % subnet_id,
                       data={"zone": chiave}, follow_redirects=True)

    mappa = logged_client.get("/inventory/map").get_data(as_text=True)

    assert "Rete di collaudo web" in mappa
