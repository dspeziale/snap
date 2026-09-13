"""
snap - Test dell'indicatore di attivita' della sonda e della dashboard a schede.

Due esigenze opposte, risolte in modo diverso:

  * sulla SONDA serviva capire a colpo d'occhio se una scansione e' in corso: lo
    stato arriva da una rotta in JSON interrogata ogni pochi secondi, perche' una
    pagina che si ricarica ogni trenta non dice se il lavoro procede;
  * sul SERVER serviva ridurre l'altezza della pagina: inventario, monitoraggio,
    sonde, conferimenti ed eventi stanno in schede, e resta visibile una sola
    striscia di riquadri sintetici.

E il perimetro sulla sonda non deve piu' occupare la pagina: con trecentottanta
subnet l'elenco per esteso era un muro.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re

import pytest

from conftest import prepara_accesso_sonda


# --------------------------------------------------------------------------- #
# Sonda: rotta di stato
# --------------------------------------------------------------------------- #
@pytest.fixture()
def sonda_client(probe_store, monkeypatch, tmp_path):
    """Interfaccia locale della sonda sull'archivio del preparatore comune."""
    import importlib

    from snapprobe import db as probe_db

    # L'applicativo deve aprire LO STESSO archivio del preparatore `probe_store`:
    # l'indirizzo e' quello, e il motore va dimenticato perche' `create_app` lo
    # riapra su questo database.
    monkeypatch.setenv("SNAP_PROBE_DATABASE_URL", probe_db.dsn())
    monkeypatch.setenv("SNAP_PROBE_SECRET_KEY", "test-probe")

    import snapprobe
    import snapprobe.settings as impostazioni

    importlib.reload(impostazioni)
    importlib.reload(snapprobe)
    applicazione = snapprobe.create_app(impostazioni.TestConfig)
    # L'interfaccia richiede l'accesso: vedi prepara_accesso_sonda in conftest.py.
    return prepara_accesso_sonda(applicazione).test_client()


CHIAVI_ATTESE = (
    "attiva", "consentita", "motivo_sospensione", "scansioni_in_corso", "thread",
    "thread_massimi", "sforzo", "fasi_in_corso", "prossima_fase", "perimetro_subnet",
    "perimetro_scoperte", "perimetro_percento", "profili_conferiti", "profili_in_attesa",
    "profili_percento", "nodi_confermati", "nodi_candidati", "coda", "online",
    "riquadri", "aggiornato_alle",
)


def test_la_rotta_di_stato_dichiara_tutte_le_voci_previste(sonda_client):
    esito = sonda_client.get("/status.json")
    assert esito.status_code == 200
    stato = esito.get_json()
    for chiave in CHIAVI_ATTESE:
        assert chiave in stato, "la rotta di stato non dichiara %s" % chiave


def test_la_rotta_di_stato_rimanda_i_riquadri_gia_pronti(sonda_client):
    """I riquadri di sintesi arrivano gia' calcolati -- valore, colore, nota -- cosi'
    il client aggiorna i contatori senza ricaricare e senza rifare la logica."""
    stato = sonda_client.get("/status.json").get_json()
    riquadri = {r["key"]: r for r in stato["riquadri"]}

    for chiave in ("canale", "coda", "raccolta", "nodi_confermati", "scansione",
                   "ultimo_conferimento"):
        assert chiave in riquadri, "manca il riquadro %s" % chiave
        for campo in ("valore", "tono", "nota"):
            assert campo in riquadri[chiave], "il riquadro %s non ha %s" % (chiave, campo)


def test_la_dashboard_della_sonda_ha_gli_appigli_per_l_aggiornamento(sonda_client):
    """Le schede di sintesi e i badge portano gli attributi data-* con cui lo script
    aggiorna i contatori sul posto."""
    pagina = sonda_client.get("/").data.decode("utf-8")

    for marcatore in ("data-snap-riquadri", 'data-card="coda"',
                      'data-card="nodi_confermati"', "data-card-val", "data-card-tono",
                      'data-stat="nodi_confermati"', "data-scan-badge"):
        assert marcatore in pagina, "manca l'appiglio %s" % marcatore


def test_lo_script_aggiorna_i_contatori_e_non_ricarica_piu_la_pagina():
    """I contatori si aggiornano via AJAX dai riquadri della rotta di stato: il
    ricaricamento completo della pagina non deve piu' esistere."""
    from pathlib import Path

    radice = Path(__file__).resolve().parent.parent
    script = (radice / "probe" / "snapprobe" / "static" / "js" / "probe.js").read_text(
        encoding="utf-8")

    assert "data-card" in script and "riquadri" in script, "non aggiorna i riquadri"
    assert "location.reload" not in script, "non deve piu' ricaricare la pagina intera"


def test_le_percentuali_dello_stato_restano_nei_limiti(sonda_client, probe_store):
    probe_store.set_json("scan_subnets", [{"cidr": "192.0.2.0/24", "hosts": 254}])
    probe_store.upsert_local_node("192.0.2.1", state="confirmed",
                                  conferred_at="2026-08-27 09:00:00")
    probe_store.upsert_local_node("192.0.2.2", state="candidate")
    stato = sonda_client.get("/status.json").get_json()
    assert 0 <= stato["perimetro_percento"] <= 100
    assert 0 <= stato["profili_percento"] <= 100
    assert stato["perimetro_scoperte"] <= stato["perimetro_subnet"]


def test_lo_stato_dichiara_la_sospensione_e_il_motivo(sonda_client, probe_store):
    probe_store.set_setting("scan_paused", "1")
    stato = sonda_client.get("/status.json").get_json()
    assert stato["consentita"] is False
    assert "sonda" in stato["motivo_sospensione"]


def test_lo_stato_dichiara_i_thread_concessi_dal_profilo(sonda_client, probe_store):
    from snapprobe.scanner import MAX_WORKERS

    probe_store.set_setting("scan_effort", "max")
    stato = sonda_client.get("/status.json").get_json()
    assert stato["sforzo"] == "max"
    assert stato["thread"] == MAX_WORKERS
    assert stato["thread_massimi"] == MAX_WORKERS


def test_la_pagina_della_sonda_contiene_gli_elementi_dell_indicatore(sonda_client):
    pagina = sonda_client.get("/").data.decode("utf-8")
    for marcatore in ("data-snap-stato", "data-spia", "data-barra-attivita",
                      "data-perimetro-barra", "data-profili-barra", "data-stato-testo"):
        assert marcatore in pagina, "manca l'elemento %s" % marcatore
    # La spia non e' l'unico segnale: accanto c'e' sempre il testo dello stato.
    assert "in attesa" in pagina


def test_lo_script_dell_indicatore_interroga_la_rotta_di_stato():
    from pathlib import Path

    radice = Path(__file__).resolve().parent.parent
    script = (radice / "probe" / "snapprobe" / "static" / "js" / "probe.js").read_text(
        encoding="utf-8")
    assert "status.json" in script
    assert "setInterval" in script
    # Un errore di rete non va ignorato: deve essere dichiarato all'operatore.
    assert "catch" in script and "non riuscito" in script


# --------------------------------------------------------------------------- #
# Sonda: perimetro compatto
# --------------------------------------------------------------------------- #
def test_il_perimetro_ampio_non_riempie_la_pagina(sonda_client, probe_store):
    """Con molte subnet si mostra la sintesi, non l'elenco per esteso."""
    perimetro = [{"cidr": "10.%d.0.0/24" % i, "label": "", "hosts": 254} for i in range(200)]
    probe_store.set_json("scan_subnets", perimetro)

    pagina = sonda_client.get("/").data.decode("utf-8")
    inizio = pagina.find("Perimetro ricevuto")
    blocco = pagina[inizio:pagina.find("</dd>", inizio)]

    assert "<details" in blocco, "l'elenco deve essere apribile a richiesta"
    assert blocco.count("badge") == 0, "nessun badge: l'elenco e' in forma compatta"
    assert "200" in blocco, "la sintesi deve dichiarare quante subnet"
    assert "e altre 197" in blocco, "la sintesi deve dichiarare quante non sono elencate"


def test_un_perimetro_assente_lo_dichiara(sonda_client, probe_store):
    probe_store.set_json("scan_subnets", [])
    pagina = sonda_client.get("/").data.decode("utf-8")
    assert "nessuna subnet" in pagina


# --------------------------------------------------------------------------- #
# Server: dashboard a schede
# --------------------------------------------------------------------------- #


def test_la_dashboard_mette_in_ordine_di_urgenza(logged_client):
    """La pagina si legge dall'alto in basso, e l'ordine non e' estetico.

    Prima cio' che chiede un intervento adesso (gli incidenti), poi il giudizio
    (i semafori), poi i numeri, poi il dettaglio. Un'altra disposizione farebbe
    scorrere per trovare la cosa urgente, che e' il difetto che questa pagina
    esiste per evitare.
    """
    pagina = logged_client.get("/").data.decode("utf-8")
    postura = pagina.find("snap-postura")
    numeri = pagina.find("snap-stat-label")
    dettaglio = pagina.find("Composizione del parco")
    indicatori = pagina.find("I tuoi indicatori")

    assert -1 not in (postura, numeri, dettaglio, indicatori), (
        "manca una delle sezioni della dashboard")
    assert postura < numeri < dettaglio < indicatori, (
        "l'ordine della pagina non e' quello dichiarato")
    if "incidenti aperti sui controlli" in pagina:
        assert pagina.find("incidenti aperti sui controlli") < postura


def test_niente_si_nasconde_dietro_un_clic(logged_client):
    """Le schede tenevano la pagina in uno schermo, ma un numero che si vede solo
    dopo aver scelto la scheda giusta, in pratica, non si vede. La dashboard mostra
    tutto: si scorre."""
    pagina = logged_client.get("/").data.decode("utf-8")
    nascosti = re.findall(r'class="tab-pane(?! fade show active)', pagina)

    assert not nascosti, (
        "%d blocchi della dashboard sono dietro una scheda" % len(nascosti))


def test_la_striscia_sintetica_resta_sempre_visibile(logged_client):
    """I numeri essenziali non devono stare dentro una scheda.

    Fra questi ci sono quelli dei controlli: lo stato dei servizi sorvegliati e gli
    incidenti aperti sono cio' che si guarda per primo, e cercarli dentro una
    scheda vanificherebbe la dashboard.
    """
    pagina = logged_client.get("/").data.decode("utf-8")
    intestazione = pagina[:pagina.find('class="tab-content"')]
    assert intestazione.count("snap-stat-label") >= 6, (
        "la striscia deve mostrare i riquadri fuori dalle schede"
    )
    for atteso in ("CONTROLLI ATTIVI", "INCIDENTI APERTI", "RIUSCITA CONTROLLI 24H"):
        assert atteso in intestazione, "manca %r nella striscia" % atteso


def test_le_tabelle_della_dashboard_sono_attrezzate(server_app, logged_client):
    """Ordinamento e paginazione valgono anche qui: una tabella che si comporta in un
    modo su una pagina e in un altro su quella accanto costringe a imparare due volte
    la stessa cosa.

    Le tabelle della dashboard compaiono solo quando hanno righe -- una tabella vuota
    occuperebbe la parte migliore dello schermo per non dire nulla -- quindi se ne
    crea una per avere che cosa verificare.
    """
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        tenant = query("SELECT id FROM tenants ORDER BY name", (), one=True)
        nodo = execute(
            "INSERT INTO nodes (tenant_id, ip, status, first_seen_at, last_seen_at,"
            " created_at, updated_at) VALUES (?, '10.4.4.4', 'up', ?, ?, ?, ?)",
            (tenant["id"], utc_now_str(), utc_now_str(), utc_now_str(), utc_now_str()))
        execute(
            "INSERT INTO ti_findings (tenant_id, node_id, kind, severity,"
            " title, evidence, confidence, status, source, first_seen_at,"
            " last_seen_at) VALUES (?, ?, 'exposure', 'critical',"
            " 'riscontro di prova', 'prodotto dichiarato', 80, 'open',"
            " 'prova', ?, ?)",
            (tenant["id"], nodo, utc_now_str(), utc_now_str()))

    pagina = logged_client.get("/").data.decode("utf-8")
    tabelle = re.findall(r"<table[^>]*>", pagina)

    assert tabelle, "con un riscontro registrato la dashboard deve mostrare una tabella"
    for tabella in tabelle:
        assert "data-snap-table" in tabella, (
            "tabella senza funzioni interattive: %s" % tabella[:60])



def test_le_tabelle_si_riadattano_alla_comparsa_della_scheda():
    """Una tabella in una scheda nascosta non conosce la propria larghezza."""
    from pathlib import Path

    radice = Path(__file__).resolve().parent.parent
    for cartella in ("server/snapserver", "probe/snapprobe"):
        script = (radice / cartella / "static" / "js" / "snap-tables.js").read_text(
            encoding="utf-8")
        assert "shown.bs.tab" in script, "%s non riadatta le tabelle" % cartella
        assert "columns.adjust" in script
