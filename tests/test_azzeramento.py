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
    """Quante righe ci sono in ciascuna tabella."""
    import sqlite3

    connessione = sqlite3.connect(str(store.path))
    connessione.row_factory = sqlite3.Row
    try:
        return {t: connessione.execute("SELECT COUNT(*) AS n FROM %s" % t).fetchone()["n"]
                for t in ("local_nodes", "scan_state", "scan_claims", "spool",
                          "sync_log", "check_state", "events", "settings")}
    finally:
        connessione.close()


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


def test_l_azzeramento_restituisce_lo_spazio_al_sistema(probe_store):
    """Un archivio azzerato che pesa come prima e' una contraddizione visibile."""
    for indice in range(400):
        probe_store.upsert_local_node("10.0.%d.%d" % (indice // 250, indice % 250 + 1),
                                      state="confirmed",
                                      profile_json=json.dumps({"riempimento": "x" * 400}))
    # Si misura l'ingombro COMPLESSIVO: in modalita' WAL i dati appena scritti
    # stanno nel giornale, e il solo file principale cresce durante il riversamento.
    prima = probe_store.footprint()
    probe_store.reset(keep_enrollment=False)
    dopo = probe_store.footprint()
    assert dopo < prima / 2, (
        "l'archivio non e' stato compattato (%d -> %d byte)" % (prima, dopo))


def test_una_tabella_nuova_deve_essere_dichiarata_esplicitamente(probe_store):
    """L'elenco delle tabelle da svuotare e' esplicito per scelta: una tabella
    aggiunta in futuro non deve trovarsi cancellata per effetto collaterale, ne'
    sopravvivere in silenzio a un azzeramento."""
    import sqlite3

    connessione = sqlite3.connect(str(probe_store.path))
    try:
        presenti = {r[0] for r in connessione.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
            " AND name NOT LIKE 'sqlite_%'")}
    finally:
        connessione.close()

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
def sonda_web(tmp_path, monkeypatch):
    """Interfaccia locale della sonda, con archivio popolato."""
    import importlib

    monkeypatch.setenv("SNAP_PROBE_STORE", str(tmp_path / "probe.sqlite3"))
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
