"""
snap - Test dello storico delle presenze sulle reti senza fili.

PERCHE' ESISTE
Su una rete cablata un indirizzo e' quasi un apparato. Su una rete senza fili no: il
DHCP riassegna, un telefono prende `.55` oggi e `.78` domani, e `.55` intanto e' di un
portatile. Un inventario che confonde indirizzo e apparato, la', afferma tre cose
false: che l'apparato di ieri e' ancora qui, che quello di oggi c'e' da sempre, e che
sono lo stesso.

La parte difficile e' l'IDENTITA', e questi test la fissano per intero: quale fonte
vince, che cosa succede quando non ce n'e' nessuna (non si finge di sapere: si
dichiara `address`), e come si usa l'unica cosa che resta -- il profilo osservato --
per accorgersi che un indirizzo e' passato a un altro apparato.

remarks: Autore: Daniele Speziale - Data: 2026-09-10
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import uuid

import pytest


# --------------------------------------------------------------------------- #
# L'identita': quale fonte, e con quanta certezza
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("nodo,seriale,attesa,fonte", [
    ({"ip": "10.2.3.55", "mac": "AA:BB:CC:11:22:33", "hostname": "tel-01"}, "SN9",
     "mac:aa:bb:cc:11:22:33", "mac"),
    ({"ip": "10.2.3.55", "mac": None, "hostname": "tel-01"}, "SN9", "serial:sn9",
     "serial"),
    ({"ip": "10.2.3.55", "mac": None, "hostname": "TEL-01"}, None, "host:tel-01",
     "hostname"),
    ({"ip": "10.2.3.55", "mac": None, "hostname": None}, None, "addr:10.2.3.55",
     "address"),
])
def test_l_identita_segue_l_ordine_della_certezza(nodo, seriale, attesa, fonte):
    """Il MAC identifica la scheda, il numero di serie l'apparato, il nome host e'
    probabile, l'indirizzo non identifica niente. L'ordine e' quello."""
    from snapserver.presence import identita

    assert identita(nodo, seriale) == (attesa, fonte)


@pytest.mark.parametrize("scritto", [
    "AA:BB:CC:11:22:33", "aa-bb-cc-11-22-33", "aabbcc112233", "AABB.CC11.2233",
])
def test_lo_stesso_mac_scritto_in_modi_diversi_e_la_stessa_identita(scritto):
    """Due scritture dello stesso MAC darebbero due apparati diversi: e' esattamente
    il difetto che questo modulo esiste per evitare."""
    from snapserver.presence import identita

    chiave, fonte = identita({"ip": "10.0.0.1", "mac": scritto})

    assert chiave == "mac:aa:bb:cc:11:22:33"
    assert fonte == "mac"


@pytest.mark.parametrize("non_valido", ["", None, "aa:bb", "non-un-mac", "zz:zz:zz:zz:zz:zz"])
def test_un_mac_non_valido_non_diventa_un_identita(non_valido):
    from snapserver.presence import identita, normalizza_mac

    assert normalizza_mac(non_valido) is None
    assert identita({"ip": "10.0.0.9", "mac": non_valido})[1] != "mac"


def test_l_incertezza_dell_identita_e_dichiarata():
    """Chi legge lo storico deve poter sapere quanto vale: "solo l'indirizzo" non e'
    un apparato riconosciuto, e la pagina non deve farlo sembrare tale."""
    from snapserver.presence import FONTI

    assert FONTI["mac"]["certezza"] == "certa"
    assert FONTI["hostname"]["certezza"] == "probabile"
    assert FONTI["address"]["certezza"] == "nessuna"
    for voce in FONTI.values():
        assert voce["spiegazione"], "ogni fonte spiega perche' vale quanto vale"


# --------------------------------------------------------------------------- #
# L'impronta debole: non identifica, ma dice quando l'indirizzo ha cambiato inquilino
# --------------------------------------------------------------------------- #
def test_lo_stesso_profilo_da_la_stessa_impronta():
    from snapserver.presence import impronta_profilo

    una = impronta_profilo(ttl=64, porte=[80, 443, 22], famiglia_os="Linux")
    altra = impronta_profilo(ttl=64, porte=[443, 22, 80], famiglia_os="linux")

    assert una == altra, "l'insieme delle porte conta, l'ordine no"


def test_un_profilo_diverso_da_un_impronta_diversa():
    from snapserver.presence import impronta_profilo

    assert (impronta_profilo(ttl=64, porte=[80])
            != impronta_profilo(ttl=128, porte=[80]))


def test_senza_niente_da_osservare_non_si_inventa_un_impronta():
    """Un host che risponde al solo ping non ha profilo: un'impronta costante
    raggrupperebbe tutti gli host muti della rete come se fossero uno."""
    from snapserver.presence import impronta_profilo

    assert impronta_profilo() is None
    assert impronta_profilo(ttl=None, porte=[], famiglia_os="") is None


# --------------------------------------------------------------------------- #
# Le permanenze
# --------------------------------------------------------------------------- #
def _tenant(server_app):
    """Il tenant che i client di prova hanno davanti.

    Non "il primo per identificativo": l'utente con cui si apre la sessione e'
    amministratore di sistema, e per lui il contesto predefinito e' il primo tenant
    IN ORDINE DI NOME (vedi tenancy.py). Il preparatore ne crea due, quindi scrivere
    i dati in uno mentre la pagina guarda l'altro e' un test che fallisce per la
    ragione sbagliata -- ed e' esattamente quello che e' successo scrivendolo.
    """
    with server_app.app_context():
        from snapserver.db import query

        return int(query("SELECT id FROM tenants ORDER BY name", (), one=True)["id"])


def _vedi(server_app, tenant_id, nodo, **extra):
    with server_app.app_context():
        from snapserver.presence import registra_avvistamento

        return registra_avvistamento(tenant_id, nodo, **extra)


def _storico(server_app, tenant_id, **filtri):
    with server_app.app_context():
        from snapserver.presence import storico

        return storico(tenant_id, **filtri)


def test_due_avvistamenti_vicini_sono_la_stessa_permanenza(server_app):
    tenant_id = _tenant(server_app)
    nodo = {"ip": "10.2.3.55", "mac": "AA:BB:CC:00:00:01"}

    primo = _vedi(server_app, tenant_id, nodo, visto_a="2026-09-10 09:00:00")
    secondo = _vedi(server_app, tenant_id, nodo, visto_a="2026-09-10 09:02:00")

    assert primo["nuova"] is True and primo["motivo"] == "prima"
    assert secondo["nuova"] is False
    assert primo["session_id"] == secondo["session_id"]
    righe = [r for r in _storico(server_app, tenant_id)
             if r["identity_key"] == "mac:aa:bb:cc:00:00:01"]
    assert len(righe) == 1
    assert righe[0]["sightings"] == 2
    assert righe[0]["last_seen_at"] == "2026-09-10 09:02:00"


def test_lo_stesso_apparato_su_un_altro_indirizzo_apre_una_permanenza(server_app):
    """E' il fatto interessante di una rete senza fili, e senza il MAC non si
    vedrebbe: lo stesso telefono, un indirizzo nuovo."""
    tenant_id = _tenant(server_app)
    mac = "AA:BB:CC:00:00:02"

    _vedi(server_app, tenant_id, {"ip": "10.2.3.55", "mac": mac},
          visto_a="2026-09-10 09:00:00")
    secondo = _vedi(server_app, tenant_id, {"ip": "10.2.3.78", "mac": mac},
                    visto_a="2026-09-10 09:04:00")

    assert secondo["nuova"] is True
    assert secondo["motivo"] == "indirizzo"
    righe = [r for r in _storico(server_app, tenant_id)
             if r["identity_key"] == "mac:aa:bb:cc:00:00:02"]
    assert len(righe) == 2
    assert {r["ip"] for r in righe} == {"10.2.3.55", "10.2.3.78"}


def test_un_ritorno_dopo_una_lunga_assenza_e_un_altra_visita(server_app):
    tenant_id = _tenant(server_app)
    nodo = {"ip": "10.2.3.60", "mac": "AA:BB:CC:00:00:03"}

    _vedi(server_app, tenant_id, nodo, visto_a="2026-09-10 09:00:00")
    dopo = _vedi(server_app, tenant_id, nodo, visto_a="2026-09-10 14:00:00")

    assert dopo["nuova"] is True
    assert dopo["motivo"] == "assenza"


def test_senza_identita_il_cambio_di_profilo_dichiara_un_altro_apparato(server_app):
    """LA RISPOSTA AL CASO SENZA MAC. Non si sa chi sia, ma si sa che non e' lo
    stesso: le porte e il TTL su quell'indirizzo sono cambiati."""
    tenant_id = _tenant(server_app)
    nodo = {"ip": "10.2.3.90", "mac": None, "hostname": None}

    _vedi(server_app, tenant_id, nodo, visto_a="2026-09-10 09:00:00",
          profilo="aaaa1111")
    dopo = _vedi(server_app, tenant_id, nodo, visto_a="2026-09-10 09:06:00",
                 profilo="bbbb2222")

    assert dopo["nuova"] is True
    assert dopo["motivo"] == "profilo"
    assert dopo["identity_source"] == "address"


def test_con_il_mac_un_cambio_di_profilo_non_spezza_la_permanenza(server_app):
    """Un telefono che apre una porta resta quel telefono: il profilo e' un indizio
    di ripiego, e dove c'e' un'identita' vera non ha voce in capitolo."""
    tenant_id = _tenant(server_app)
    nodo = {"ip": "10.2.3.91", "mac": "AA:BB:CC:00:00:04"}

    _vedi(server_app, tenant_id, nodo, visto_a="2026-09-10 09:00:00",
          profilo="aaaa1111")
    dopo = _vedi(server_app, tenant_id, nodo, visto_a="2026-09-10 09:06:00",
                 profilo="bbbb2222")

    assert dopo["nuova"] is False


def test_lo_storico_dichiara_quanto_vale(server_app):
    tenant_id = _tenant(server_app)
    _vedi(server_app, tenant_id, {"ip": "10.2.3.92", "mac": None, "hostname": None},
          visto_a="2026-09-10 09:00:00")

    riga = [r for r in _storico(server_app, tenant_id)
            if r["ip"] == "10.2.3.92"][0]

    assert riga["identity_source"] == "address"
    assert riga["identity_certainty"] == "nessuna"
    assert "identita'" in riga["identity_explained"]
    assert riga["opened_label"] == "primo avvistamento"


def test_il_riepilogo_dice_se_lo_storico_e_affidabile(server_app):
    """Se meta' delle permanenze e' riconosciuta solo dall'indirizzo, la rete non
    fornisce i MAC: chi legge deve saperlo, non dedurlo."""
    tenant_id = _tenant(server_app)
    _vedi(server_app, tenant_id, {"ip": "10.2.4.1", "mac": "AA:BB:CC:00:01:01"})
    _vedi(server_app, tenant_id, {"ip": "10.2.4.2", "mac": None, "hostname": None})

    with server_app.app_context():
        from snapserver.presence import riepilogo

        dati = riepilogo(tenant_id)

    assert dati["permanenze"] >= 2
    assert dati["con_mac"] >= 1
    assert dati["senza_identita"] >= 1


def test_lo_storico_ha_un_termine(server_app):
    """La presenza di un apparato personale e' un dato personale: la conservazione ha
    un termine e si applica da se' (GDPR art. 5(1)(e)).

    Il termine sta fra i tipi di conservazione del prodotto, non in un meccanismo
    proprio delle presenze: una seconda politica di cancellazione sarebbe una politica
    che qualcuno dimentica di applicare.
    """
    tenant_id = _tenant(server_app)
    _vedi(server_app, tenant_id, {"ip": "10.2.5.1", "mac": "AA:BB:CC:00:02:01"},
          visto_a="2020-01-01 00:00:00")
    _vedi(server_app, tenant_id, {"ip": "10.2.5.2", "mac": "AA:BB:CC:00:02:02"})

    with server_app.app_context():
        from snapserver.maintenance import RETENTION_TYPES, purge, save_retention

        dichiarato = [v for v in RETENTION_TYPES if v[1] == "presence_sessions"]
        assert dichiarato, "le presenze devono avere un termine dichiarato"
        assert dichiarato[0][2] == "last_seen_at", (
            "il termine si misura dall'ultima volta che l'apparato e' stato visto,"
            " non dalla prima")
        save_retention({"presence_sessions": "30"})
        esito = purge(dry_run=False)

    restano = {r["ip"] for r in _storico(server_app, tenant_id)}
    assert any(v["tabella"] == "presence_sessions" for v in esito["voci"])
    assert "10.2.5.1" not in restano
    assert "10.2.5.2" in restano


# --------------------------------------------------------------------------- #
# Il conferimento dalla sonda
# --------------------------------------------------------------------------- #
def _sonda(server_app, tenant_id):
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        riga = query("SELECT id FROM probes WHERE tenant_id = ?", (tenant_id,), one=True)
        if riga is not None:
            return int(riga["id"])
        adesso = utc_now_str()
        return int(execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, created_at,"
            " updated_at) VALUES (?, 'uid-pres', 'sonda-pres', 'Sonda', 'active', ?, ?)",
            (tenant_id, adesso, adesso)))


def test_un_avvistamento_conferito_diventa_una_permanenza(server_app):
    tenant_id = _tenant(server_app)
    probe_id = _sonda(server_app, tenant_id)

    with server_app.app_context():
        from snapserver.ingest import apply_batch

        apply_batch(tenant_id, probe_id, {
            "batch_uid": "pres-%s" % uuid.uuid4().hex[:8],
            "records": {
                "nodes": [{"ip": "10.2.9.20", "mac": "AA:BB:CC:0F:00:01",
                           "reachable": True}],
                "presence": [{"ip": "10.2.9.20", "seen_at": "2026-09-10 09:00:00"}],
            }})

    righe = [r for r in _storico(server_app, tenant_id) if r["ip"] == "10.2.9.20"]
    assert len(righe) == 1
    assert righe[0]["identity_source"] == "mac"
    assert righe[0]["node_id"] is not None


def test_un_avvistamento_senza_il_nodo_non_inventa_un_nodo(server_app):
    """Un ping da solo non e' un dispositivo dell'inventario: si dichiara orfano,
    come per ogni altro genere di record."""
    tenant_id = _tenant(server_app)
    probe_id = _sonda(server_app, tenant_id)

    with server_app.app_context():
        from snapserver.ingest import apply_batch

        esito = apply_batch(tenant_id, probe_id, {
            "batch_uid": "pres-%s" % uuid.uuid4().hex[:8],
            "records": {"presence": [{"ip": "10.2.9.99"}]}})

    # L'esito del conferimento CONTA gli orfani (non li elenca): il dettaglio sta nel
    # lotto conservato. Quello che conta qui e' che nessuna permanenza sia nata.
    assert int(esito.get("orphans") or 0) >= 1
    assert [r for r in _storico(server_app, tenant_id) if r["ip"] == "10.2.9.99"] == []


# --------------------------------------------------------------------------- #
# La pagina
# --------------------------------------------------------------------------- #
def test_la_pagina_delle_presenze_si_apre(logged_client):
    risposta = logged_client.get("/inventory/presenze")

    assert risposta.status_code == 200
    testo = risposta.get_data(as_text=True)
    assert "Presenze" in testo


def test_senza_reti_dichiarate_la_pagina_dice_come_si_attiva(logged_client):
    """Una pagina vuota senza spiegazione fa pensare a un guasto: qui si dice che la
    ricognizione si attiva per dichiarazione, e si offre il collegamento per farlo."""
    testo = logged_client.get("/inventory/presenze").get_data(as_text=True)

    assert "Nessuna rete dichiarata senza fili" in testo
    assert "/inventory/subnets" in testo


def test_la_pagina_dichiara_quando_lo_storico_non_e_affidabile(server_app, logged_client):
    """Se la maggior parte delle permanenze e' riconosciuta solo dall'indirizzo, la
    pagina lo dice invece di lasciarlo dedurre."""
    tenant_id = _tenant(server_app)
    for ultimo in range(3):
        _vedi(server_app, tenant_id,
              {"ip": "10.2.77.%d" % ultimo, "mac": None, "hostname": None})

    testo = logged_client.get("/inventory/presenze").get_data(as_text=True)

    assert "va letto per quello che e'" in testo
    assert "solo dall'indirizzo" in testo


def test_una_subnet_si_dichiara_senza_fili(server_app, logged_client):
    """Il flag non e' un'etichetta: e' cio' che accende la ricognizione. Deve poter
    essere messo e togliato dalla pagina del perimetro."""
    tenant_id = _tenant(server_app)
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        subnet_id = int(execute(
            "INSERT INTO subnets (tenant_id, cidr, label, host_count, created_at,"
            " updated_at) VALUES (?, '10.2.88.0/24', 'wifi ospiti', 254, ?, ?)",
            (tenant_id, adesso, adesso)))

    logged_client.post("/inventory/subnets/%d/wifi" % subnet_id,
                       data={"csrf_token": "x"}, follow_redirects=True)

    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT is_wifi FROM subnets WHERE id = ?", (subnet_id,), one=True)
    assert int(riga["is_wifi"]) == 1

    logged_client.post("/inventory/subnets/%d/wifi" % subnet_id,
                       data={"csrf_token": "x"}, follow_redirects=True)
    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT is_wifi FROM subnets WHERE id = ?", (subnet_id,), one=True)
    assert int(riga["is_wifi"]) == 0, "si deve poter tornare indietro"


def test_il_perimetro_consegnato_alla_sonda_porta_il_flag(server_app):
    """La sonda decide da qui quali reti osservare spesso: senza il campo nel
    perimetro la dichiarazione dell'operatore non arriverebbe mai a destinazione."""
    tenant_id = _tenant(server_app)
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str
        from snapserver.subnets import active_subnets

        adesso = utc_now_str()
        execute("INSERT INTO subnets (tenant_id, cidr, label, host_count, is_wifi,"
                " created_at, updated_at)"
                " VALUES (?, '10.2.99.0/24', 'wifi', 254, 1, ?, ?)",
                (tenant_id, adesso, adesso))
        perimetro = active_subnets(tenant_id)

    voce = [v for v in perimetro if v["cidr"] == "10.2.99.0/24"][0]
    assert voce["wifi"] is True
    assert all("wifi" in v for v in perimetro), "il campo c'e' su ogni voce"


# --------------------------------------------------------------------------- #
# L'andamento: quanti apparati, quando, e per quanto ciascuno
# --------------------------------------------------------------------------- #
def _adesso_meno(ore=0, minuti=0):
    from datetime import datetime, timedelta, timezone

    momento = datetime.now(timezone.utc) - timedelta(hours=ore, minutes=minuti)
    return momento.strftime("%Y-%m-%d %H:%M:%S")


def _andamento(server_app, tenant_id, **filtri):
    with server_app.app_context():
        from snapserver.presence import andamento

        return andamento(tenant_id, **filtri)


def _fasce(server_app, tenant_id, **filtri):
    with server_app.app_context():
        from snapserver.presence import fasce

        return fasce(tenant_id, **filtri)


def test_il_periodo_non_dichiarato_e_quello_predefinito():
    """La chiave arriva dall'URL: quello che non e' in elenco non deve comporre un
    intervallo su un valore inventato."""
    from snapserver.presence import PERIODO_PREDEFINITO, periodo

    assert periodo(None)["chiave"] == PERIODO_PREDEFINITO
    assert periodo("")["chiave"] == PERIODO_PREDEFINITO
    assert periodo("qualunque-cosa")["chiave"] == PERIODO_PREDEFINITO
    assert periodo("24h")["chiave"] == "24h"


def test_ogni_periodo_ha_un_passo_leggibile():
    """Contare per ora su trenta giorni darebbe 720 punti -- rumore, non andamento --
    e per giorno su ventiquattro ore ne darebbe uno."""
    from snapserver.presence import PERIODI

    for voce in PERIODI:
        punti = voce["ore"] * 60 / voce["passo_min"]
        assert 12 <= punti <= 200, "%s: %d punti" % (voce["chiave"], punti)


def test_l_andamento_conta_gli_apparati_presenti(server_app):
    tenant_id = _tenant(server_app)
    _vedi(server_app, tenant_id, {"ip": "10.3.0.1", "mac": "AA:BB:CC:10:00:01"},
          visto_a=_adesso_meno(minuti=30))
    _vedi(server_app, tenant_id, {"ip": "10.3.0.2", "mac": "AA:BB:CC:10:00:02"},
          visto_a=_adesso_meno(minuti=20))

    dati = _andamento(server_app, tenant_id, chiave_periodo="24h")

    assert dati["apparati"] == 2
    assert dati["massimo"] == 2
    assert dati["punti"], "il periodo si copre per intero, anche dove non c'era nessuno"
    assert dati["punti"][0][1] == 0, "ventiquattro ore fa non c'era nessuno"
    assert dati["punti"][-1][1] == 2


def test_una_permanenza_iniziata_prima_del_periodo_conta_comunque(server_app):
    """Ignorarla direbbe che l'apparato non c'era: e' presente da ieri e c'e' ancora."""
    tenant_id = _tenant(server_app)
    _vedi(server_app, tenant_id, {"ip": "10.3.1.1", "mac": "AA:BB:CC:11:00:01"},
          visto_a=_adesso_meno(ore=40))
    with server_app.app_context():
        from snapserver.db import execute

        # La stessa permanenza, prolungata fino ad adesso.
        execute("UPDATE presence_sessions SET last_seen_at = ? WHERE ip = ?",
                (_adesso_meno(minuti=1), "10.3.1.1"))

    dati = _andamento(server_app, tenant_id, chiave_periodo="24h")

    assert dati["massimo"] == 1
    assert dati["punti"][0][1] == 1, "c'era anche all'inizio della finestra"


def test_un_apparato_andato_via_non_conta_piu(server_app):
    tenant_id = _tenant(server_app)
    _vedi(server_app, tenant_id, {"ip": "10.3.2.1", "mac": "AA:BB:CC:12:00:01"},
          visto_a=_adesso_meno(ore=10))

    dati = _andamento(server_app, tenant_id, chiave_periodo="24h")

    assert dati["punti"][-1][1] == 0, "adesso non c'e'"
    assert dati["massimo"] == 1, "ma dieci ore fa c'era"


def test_l_andamento_di_una_rete_sola(server_app):
    """Il filtro per rete serve: su un impianto con piu' reti senza fili l'andamento
    complessivo nasconde quello della singola rete."""
    tenant_id = _tenant(server_app)
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        subnet_id = int(execute(
            "INSERT INTO subnets (tenant_id, cidr, label, host_count, is_wifi,"
            " created_at, updated_at)"
            " VALUES (?, '10.3.3.0/24', 'wifi', 254, 1, ?, ?)",
            (tenant_id, adesso, adesso)))
    _vedi(server_app, tenant_id, {"ip": "10.3.3.5", "mac": "AA:BB:CC:13:00:01"},
          subnet_id=subnet_id)
    _vedi(server_app, tenant_id, {"ip": "10.3.4.5", "mac": "AA:BB:CC:13:00:02"})

    dentro = _andamento(server_app, tenant_id, chiave_periodo="24h",
                        subnet_id=subnet_id)
    tutte = _andamento(server_app, tenant_id, chiave_periodo="24h")

    assert dentro["apparati"] == 1
    assert tutte["apparati"] == 2


def test_le_fasce_danno_posizione_e_larghezza_in_percentuale(server_app):
    """La pagina le disegna cosi' come arrivano: nessun calcolo nel markup, nessuno
    script (politica dei contenuti del progetto)."""
    tenant_id = _tenant(server_app)
    _vedi(server_app, tenant_id, {"ip": "10.3.5.1", "mac": "AA:BB:CC:15:00:01"},
          visto_a=_adesso_meno(ore=6))

    dati = _fasce(server_app, tenant_id, chiave_periodo="24h")

    assert len(dati["righe"]) == 1
    riga = dati["righe"][0]
    assert riga["fasce"], "una permanenza disegna almeno una fascia"
    fascia = riga["fasce"][0]
    assert 0 <= fascia["sinistra"] <= 100
    assert 0 < fascia["larghezza"] <= 100
    assert fascia["sinistra"] + fascia["larghezza"] <= 100.5
    assert 70 <= fascia["sinistra"] <= 80, "sei ore fa su ventiquattro: tre quarti"


def test_una_permanenza_brevissima_resta_visibile(server_app):
    """Venti minuti su trenta giorni sarebbero larghi zero: una fascia invisibile
    direbbe "mai stato qui", che e' il contrario del vero."""
    tenant_id = _tenant(server_app)
    _vedi(server_app, tenant_id, {"ip": "10.3.6.1", "mac": "AA:BB:CC:16:00:01"},
          visto_a=_adesso_meno(ore=2))

    dati = _fasce(server_app, tenant_id, chiave_periodo="30g")

    assert dati["righe"][0]["fasce"][0]["larghezza"] > 0


def test_le_fasce_dichiarano_i_piu_indirizzi_di_uno_stesso_apparato(server_app):
    """E' il fatto che questa pagina esiste per mostrare, e senza un'identita' stabile
    non si vedrebbe."""
    tenant_id = _tenant(server_app)
    mac = "AA:BB:CC:17:00:01"
    _vedi(server_app, tenant_id, {"ip": "10.3.7.1", "mac": mac},
          visto_a=_adesso_meno(ore=5))
    _vedi(server_app, tenant_id, {"ip": "10.3.7.2", "mac": mac},
          visto_a=_adesso_meno(ore=1))

    riga = _fasce(server_app, tenant_id, chiave_periodo="24h")["righe"][0]

    assert sorted(riga["indirizzi"]) == ["10.3.7.1", "10.3.7.2"]
    assert len(riga["fasce"]) == 2, "due permanenze, due fasce sulla stessa riga"


def test_le_tacche_coprono_il_periodo(server_app):
    """Senza riferimenti temporali una fascia larga il 12% non direbbe di quando si
    tratta."""
    tenant_id = _tenant(server_app)
    _vedi(server_app, tenant_id, {"ip": "10.3.8.1", "mac": "AA:BB:CC:18:00:01"})

    tacche = _fasce(server_app, tenant_id, chiave_periodo="24h")["tacche"]

    assert tacche[0]["posizione"] == 0.0
    assert tacche[-1]["posizione"] == 100.0
    assert all(t["etichetta"] for t in tacche)


def test_le_fasce_hanno_un_tetto_e_lo_dichiarano(server_app):
    """Oltre qualche decina di righe la pagina diventa un muro: si mostrano i piu'
    recenti e si dice quanti restano fuori."""
    tenant_id = _tenant(server_app)
    for ultimo in range(6):
        _vedi(server_app, tenant_id,
              {"ip": "10.3.9.%d" % ultimo, "mac": "AA:BB:CC:19:00:%02d" % ultimo},
              visto_a=_adesso_meno(minuti=ultimo))

    dati = _fasce(server_app, tenant_id, chiave_periodo="24h", massimo=4)

    assert len(dati["righe"]) == 4
    assert dati["esclusi"] == 2
    assert dati["totale"] == 6


def test_un_apparato_visto_adesso_compare(server_app):
    """DIFETTO TROVATO DA UN TEST, e vale la pena ricordarlo: la finestra si chiudeva
    al minuto in corso, quindi un apparato visto trenta secondi fa cadeva DOPO la sua
    fine e spariva sia dal conteggio sia dalle fasce -- proprio quello che si guarda
    per primo. Ora la finestra si chiude al minuto successivo, e gli estremi di una
    permanenza si riportano dentro invece di scartarla (l'orologio di una sonda puo'
    essere qualche secondo avanti)."""
    tenant_id = _tenant(server_app)
    _vedi(server_app, tenant_id, {"ip": "10.3.10.1", "mac": "AA:BB:CC:1A:00:01"})

    dati = _andamento(server_app, tenant_id, chiave_periodo="24h")
    strisce = _fasce(server_app, tenant_id, chiave_periodo="24h")

    assert dati["punti"][-1][1] == 1, "e' presente adesso"
    assert len(strisce["righe"]) == 1
    assert strisce["righe"][0]["fasce"], "e ha una fascia disegnabile"


def test_un_avvistamento_nel_futuro_non_fa_sparire_l_apparato(server_app):
    """Una sonda con l'orologio avanti dichiara un istante nel futuro: e' un dato
    imperfetto, non un apparato inesistente."""
    tenant_id = _tenant(server_app)
    _vedi(server_app, tenant_id, {"ip": "10.3.11.1", "mac": "AA:BB:CC:1B:00:01"},
          visto_a=_adesso_meno(ore=-2))

    strisce = _fasce(server_app, tenant_id, chiave_periodo="24h")

    assert len(strisce["righe"]) == 1
    fascia = strisce["righe"][0]["fasce"][0]
    assert fascia["sinistra"] + fascia["larghezza"] <= 100.5, (
        "la fascia resta dentro il disegno")


def test_senza_presenze_l_andamento_non_solleva(server_app):
    tenant_id = _tenant(server_app)

    dati = _andamento(server_app, tenant_id, chiave_periodo="7g")
    fasce_vuote = _fasce(server_app, tenant_id, chiave_periodo="7g")

    assert dati["apparati"] == 0
    assert dati["massimo"] == 0
    assert all(p[1] == 0 for p in dati["punti"])
    assert fasce_vuote["righe"] == []


def test_la_pagina_dell_andamento_si_apre(logged_client):
    risposta = logged_client.get("/inventory/presenze/andamento")

    assert risposta.status_code == 200
    testo = risposta.get_data(as_text=True)
    assert "Andamento delle Presenze" in testo
    assert "data-snap-grafico" in testo, "il grafico si dichiara al modulo dei grafici"


def test_il_bottone_dell_andamento_e_sulla_pagina_delle_presenze(logged_client):
    """La richiesta era proprio questa: dall'elenco si arriva all'andamento con un
    clic, senza cercarlo nel menu."""
    testo = logged_client.get("/inventory/presenze").get_data(as_text=True)

    assert "/inventory/presenze/andamento" in testo
    assert "Storico dell" in testo


@pytest.mark.parametrize("scelta", ["24h", "48h", "7g", "30g", "inventato"])
def test_ogni_periodo_offerto_apre_la_pagina(logged_client, scelta):
    risposta = logged_client.get("/inventory/presenze/andamento?periodo=%s" % scelta)

    assert risposta.status_code == 200
