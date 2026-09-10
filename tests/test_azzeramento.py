"""
snap - Test dell'azzeramento dell'archivio della sonda.

Il difetto che questi test presidiano e' stato osservato sull'impianto reale: usando
i comandi di manutenzione esistenti -- azzera registrazione, svuota coda, azzera
contatore -- restavano 1752 nodi locali, 119 stati di fase, 200 righe di storico e
500 righe di diario. La sonda sembrava azzerata e ripartiva con la memoria di prima.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json

import pytest

from conftest import prepara_accesso_sonda


def _popola(store) -> None:
    """Riempie l'archivio come dopo qualche ora di esercizio."""
    store.set_settings({
        "probe_uid": "uid-di-prova",
        "session_key": "k" * 43,
        "api_key": "chiave-api",
        "server_url": "http://127.0.0.1:5500",
        "server_public_key": "x" * 43,
        "probe_private_key": "p" * 43,
        "probe_public_key": "q" * 43,
        "enrolled_at": "2026-08-28 07:00:00",
        "probe_code": "P-PROVA",
        "probe_name": "Sonda di prova",
        "tenant_code": "ised",
        "tenant_name": "ISED S.p.a.",
        "tenant_timezone": "Europe/Rome",
        "scan_effort": "max",
        "scan_host_timeout": "300s",
        "collection_cycle": "42",
    })
    store.set_json("scan_subnets", [{"cidr": "192.0.2.0/24"}])
    store.set_json("nmap_capabilities", {"available": True, "raw_sockets": True})
    store.set_json("checks", [{"id": 1, "name": "prova", "kind": "presence",
                               "address": "127.0.0.1", "interval_seconds": 60,
                               "timeout_seconds": 5, "config": {}}])
    for indice in range(5):
        store.upsert_local_node("192.0.2.%d" % (indice + 1), state="confirmed",
                                stages_done="ports", profile_json=json.dumps({"ip": "x"}))
    store.record_scan("192.0.2.0/24", "discovery", "completed", "prova")
    store.record_check_run(1, "ok", "risponde")
    store.claim_keys(["ports:192.0.2.1"], "proprietario", "ports")
    for indice in range(3):
        store.enqueue("events", {"level": "info", "message": "record %d" % indice})
    store.record_sync("lotto-di-prova", 3, "accepted", "")
    store.log("info", "riga di diario")


def _consistenza(store) -> dict:
    """Quante righe ci sono in ciascuna tabella.

    Si interroga l'archivio dalla sua stessa connessione: non e' piu' un file da
    aprire di lato.
    """
    tabelle = tuple(store.DATA_TABLES) + ("settings",)
    with store._connect() as connessione:
        return {t: connessione.execute(
            "SELECT COUNT(*) AS n FROM %s" % t).fetchone()["n"] for t in tabelle}


# --------------------------------------------------------------------------- #
# Archivio
# --------------------------------------------------------------------------- #
def test_l_azzeramento_dei_dati_non_lascia_nulla_indietro(probe_store):
    """E' il difetto osservato: i nodi locali sopravvivevano a tutti i comandi."""
    _popola(probe_store)
    prima = _consistenza(probe_store)
    assert prima["local_nodes"] == 5 and prima["events"] > 0

    rimosse = probe_store.reset(keep_enrollment=True)

    dopo = _consistenza(probe_store)
    for tabella in ("local_nodes", "scan_state", "scan_claims", "spool",
                    "sync_log", "check_state"):
        assert dopo[tabella] == 0, "la tabella %s non e' stata azzerata" % tabella
    assert rimosse["local_nodes"] == 5, "il conteggio dichiarato deve corrispondere"
    # Il diario riparte con una riga sola: quella che dichiara l'azzeramento.
    assert dopo["events"] == 1
    diario = probe_store.recent_events(5)
    assert "Archivio azzerato" in diario[0]["message"]


def test_l_azzeramento_dei_dati_conserva_la_registrazione(probe_store):
    _popola(probe_store)
    assert probe_store.is_enrolled()

    probe_store.reset(keep_enrollment=True)

    assert probe_store.is_enrolled(), "la sonda doveva restare registrata"
    assert probe_store.get_setting("probe_uid") == "uid-di-prova"
    assert probe_store.get_setting("server_url") == "http://127.0.0.1:5500"
    # Cio' che il server riconsegna comunque non viene conservato: perimetro,
    # cadenze, controlli e capacita' rilevate.
    assert probe_store.get_json("scan_subnets", None) is None
    assert probe_store.get_json("checks", None) is None
    assert probe_store.get_json("nmap_capabilities", None) is None
    assert probe_store.get_setting("collection_cycle") is None


def test_l_azzeramento_completo_rimuove_anche_la_registrazione(probe_store):
    _popola(probe_store)

    probe_store.reset(keep_enrollment=False)

    assert not probe_store.is_enrolled(), "la sonda doveva tornare non registrata"
    impostazioni = probe_store.all_settings()
    # Resta solo cio' che l'azzeramento stesso ha scritto: nulla di configurato.
    assert "probe_uid" not in impostazioni
    assert "server_url" not in impostazioni
    assert "scan_subnets" not in impostazioni


def test_l_azzeramento_svuota_le_tabelle_e_dichiara_cosa_recupera(probe_store):
    """CAMBIATA LA PROMESSA, perche' la precedente non era piu' vera.

    Con SQLite l'azzeramento riduceva il FILE: si misurava l'ingombro e doveva
    dimezzarsi. Su PostgreSQL un `VACUUM` ordinario non restituisce spazio al sistema
    operativo -- rende riutilizzabile quello delle righe morte dentro il database --
    quindi la dimensione misurata spesso non cala. Pretenderlo qui vorrebbe dire
    scrivere un test che passa solo se il prodotto promette una cosa falsa.

    Cio' che deve valere e' che i DATI non ci siano piu': quello si verifica, ed e'
    la sostanza dell'azzeramento.
    """
    for indice in range(400):
        probe_store.upsert_local_node("10.0.%d.%d" % (indice // 250, indice % 250 + 1),
                                      state="confirmed",
                                      profile_json=json.dumps({"riempimento": "x" * 400}))

    probe_store.reset(keep_enrollment=False)

    residuo = _consistenza(probe_store)
    for tabella in probe_store.DATA_TABLES:
        if tabella == "events":
            # L'azzeramento scrive la propria riga di diario DOPO aver svuotato: e'
            # voluto -- un archivio che si azzera senza lasciare traccia dell'azzeramento
            # e' un archivio che non si puo' ricostruire. Deve restare solo quella.
            assert residuo[tabella] == 1, "resta la sola riga dell'azzeramento"
            continue
        assert residuo[tabella] == 0, "%s: %d righe sopravvissute" % (
            tabella, residuo[tabella])
    # E l'ingombro si sa dire: e' un numero, non una promessa di riduzione.
    assert probe_store.footprint() > 0


def test_una_tabella_nuova_deve_essere_dichiarata_esplicitamente(probe_store):
    """L'elenco delle tabelle da svuotare e' esplicito per scelta: una tabella
    aggiunta in futuro non deve trovarsi cancellata per effetto collaterale, ne'
    sopravvivere in silenzio a un azzeramento."""
    # Il catalogo si interroga con `information_schema`, che e' lo standard: era
    # `sqlite_master`, e l'archivio della sonda non e' piu' quello.
    with probe_store._connect() as connessione:
        presenti = {r["table_name"] for r in connessione.execute(
            "SELECT table_name FROM information_schema.tables"
            " WHERE table_schema = current_schema()").fetchall()}

    dichiarate = set(probe_store.DATA_TABLES) | {"settings"}
    assert presenti == dichiarate, (
        "tabelle non dichiarate nell'azzeramento: %s" % (presenti - dichiarate))


# --------------------------------------------------------------------------- #
# Quiescenza prima di cancellare
# --------------------------------------------------------------------------- #
def test_l_azzeramento_ferma_prima_le_scansioni_in_corso(probe_store):
    """Una scansione in corso scriverebbe i propri record subito dopo la
    cancellazione, e l'archivio azzerato ripartirebbe con dei residui."""
    from snapprobe.agent import ProbeAgent

    _popola(probe_store)
    agente = ProbeAgent(probe_store, "1.0.0-test")

    fermati = {"quante": 0}

    class RunnerFinto:
        def stop_all(self):
            fermati["quante"] += 1
            return 2

        def resume(self):
            fermati["ripreso"] = True

        def detect_capabilities(self, force=False):
            return {"available": False, "detail": "esecutore di prova"}

    agente.scanner.runner = RunnerFinto()

    rimosse = agente.reset_store(keep_enrollment=True)

    assert fermati["quante"] == 1, "i processi di nmap non sono stati terminati"
    assert fermati.get("ripreso") is True, "le esecuzioni non sono state riabilitate"
    assert rimosse["nmap_terminati"] == 2
    assert probe_store.get_setting("scan_paused") == "0", (
        "dopo l'azzeramento la scansione deve poter riprendere")


def test_una_sospensione_precedente_resta_valida(probe_store):
    """Non e' l'azzeramento a decidere se si scansiona."""
    from snapprobe.agent import ProbeAgent

    _popola(probe_store)
    probe_store.set_setting("scan_paused", "1")
    agente = ProbeAgent(probe_store, "1.0.0-test")

    agente.reset_store(keep_enrollment=True)

    assert probe_store.get_setting("scan_paused") == "1", (
        "la sospensione decisa prima dell'azzeramento doveva restare")


def test_lo_scanner_dimentica_le_cache_in_memoria(probe_store):
    """Senza questo, il perimetro compilato sopravviverebbe alla cancellazione."""
    from snapprobe.agent import ProbeAgent

    _popola(probe_store)
    agente = ProbeAgent(probe_store, "1.0.0-test")
    assert agente.scanner._compiled_perimeter(), "il perimetro doveva essere compilato"
    agente.scanner._reported_outside.add("10.99.0.1")

    agente.reset_store(keep_enrollment=True)

    assert agente.scanner._perimeter_networks is None
    assert agente.scanner._reported_outside == set()
    assert agente.scanner.perimeter() == [], "il perimetro e' stato cancellato"


# --------------------------------------------------------------------------- #
# Interfaccia
# --------------------------------------------------------------------------- #
@pytest.fixture()
def sonda_web(tmp_path, monkeypatch, database_di_prova):
    """Interfaccia locale della sonda, con archivio popolato."""
    import importlib

    from snapprobe import db as probe_db

    # L'archivio della sonda e' PostgreSQL: ogni prova ha il proprio database, come
    # quelle del server. Il motore e' unico per processo e va dimenticato fra una
    # prova e l'altra, altrimenti la seconda scriverebbe nel database della prima --
    # che intanto e' stato distrutto.
    monkeypatch.setenv("SNAP_PROBE_DATABASE_URL", database_di_prova)
    probe_db.azzera_motore()
    monkeypatch.setenv("SNAP_PROBE_SECRET_KEY", "test-secret-key")

    import snapprobe
    import snapprobe.settings as probe_settings

    importlib.reload(probe_settings)
    importlib.reload(snapprobe)

    applicazione = snapprobe.create_app(probe_settings.TestConfig, start_agent=False)
    from snapprobe.views import _store

    with applicazione.app_context():
        archivio = _store()
        _popola(archivio)
    # L'interfaccia richiede l'accesso: vedi prepara_accesso_sonda in conftest.py.
    return prepara_accesso_sonda(applicazione), archivio


def test_la_pagina_offre_entrambi_i_livelli_di_azzeramento(sonda_web):
    applicazione, _ = sonda_web
    pagina = applicazione.test_client().get("/configuration").get_data(as_text=True)
    assert "Azzeramento dell'archivio" in pagina
    assert "AZZERA I DATI" in pagina
    assert "AZZERA TUTTO" in pagina
    # La differenza fra i due va detta prima di premere.
    assert "va registrata di nuovo" in pagina
    assert "inventario sul server non viene toccato" in pagina


def test_senza_la_parola_di_conferma_non_si_cancella_nulla(sonda_web):
    applicazione, archivio = sonda_web
    client = applicazione.test_client()

    for ambito, sbagliata in (("dati", "AZZERA"), ("tutto", "AZZERA I DATI"), ("dati", "")):
        risposta = client.post("/actions/reset",
                               data={"scope": ambito, "confirm": sbagliata},
                               follow_redirects=True)
        assert risposta.status_code == 200
        assert _consistenza(archivio)["local_nodes"] == 5, (
            "conferma %r sull'ambito %r: non doveva cancellare nulla" % (sbagliata, ambito))
        assert archivio.is_enrolled()


def test_un_ambito_non_previsto_viene_rifiutato(sonda_web):
    applicazione, archivio = sonda_web
    risposta = applicazione.test_client().post(
        "/actions/reset", data={"scope": "meta", "confirm": "AZZERA TUTTO"},
        follow_redirects=True)
    assert "non riconosciuto" in risposta.get_data(as_text=True)
    assert _consistenza(archivio)["local_nodes"] == 5


def test_l_azzeramento_dei_dati_dalla_pagina(sonda_web):
    applicazione, archivio = sonda_web
    risposta = applicazione.test_client().post(
        "/actions/reset", data={"scope": "dati", "confirm": "azzera i dati"},
        follow_redirects=True)
    assert risposta.status_code == 200
    testo = risposta.get_data(as_text=True)
    assert "Archivio azzerato" in testo
    assert "registrazione e&#39; stata conservata" in testo or "conservata" in testo
    assert _consistenza(archivio)["local_nodes"] == 0
    assert archivio.is_enrolled(), "la registrazione doveva restare"


def test_l_azzeramento_completo_dalla_pagina_porta_alla_registrazione(sonda_web):
    applicazione, archivio = sonda_web
    risposta = applicazione.test_client().post(
        "/actions/reset", data={"scope": "tutto", "confirm": "AZZERA TUTTO"},
        follow_redirects=True)
    assert risposta.status_code == 200
    assert _consistenza(archivio)["local_nodes"] == 0
    assert not archivio.is_enrolled()
    # Si viene portati dove serve andare: la pagina di registrazione.
    assert "Registrazione" in risposta.get_data(as_text=True)
