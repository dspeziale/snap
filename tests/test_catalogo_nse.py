"""
snap - Test del catalogo degli script NSE: un nome sbagliato non ferma una fase.

IL GUASTO CHE QUESTI TEST DIFENDONO, misurato in esercizio.

Il catalogo della raffica elencava `ipp-info` e `pgsql-info`. Nessuno dei due esiste
in nmap 7.99, e la conseguenza non era che quei due script non partivano: nmap non
partiva affatto.

    NSE: failed to initialize the script engine:
    nse_main.lua:829: 'ipp-info' did not match a category, filename, or directory
    QUITTING!

Il diario diceva "0 host, 0 record in 3,9 s" per ogni bersaglio. Una fase che
finiva presto e non trovava nulla, senza dire perche': il difetto peggiore di questo
prodotto, perche' non si vede cio' che non c'e'.

remarks: Autore: Daniele Speziale - Data: 2026-09-10
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest

INDICE_FINTO = """Entry { filename = "http-title.nse", categories = { "default", "discovery", "safe", } }
Entry { filename = "ssl-cert.nse", categories = { "default", "safe", } }
Entry { filename = "cups-info.nse", categories = { "discovery", "safe", } }
Entry { filename = "smb-os-discovery.nse", categories = { "default", "discovery", "safe", } }
"""


@pytest.fixture()
def indice(tmp_path, monkeypatch):
    """Un indice degli script noto, cosi' la prova non dipende dall'nmap installato."""
    from snapprobe import nmap_runner

    percorso = tmp_path / "script.db"
    percorso.write_text(INDICE_FINTO, encoding="utf-8")
    monkeypatch.setenv("SNAP_PROBE_NMAP_SCRIPT_DB", str(percorso))
    nmap_runner.azzera_script_conosciuti()
    try:
        yield percorso
    finally:
        nmap_runner.azzera_script_conosciuti()


# --------------------------------------------------------------------------- #
# Lettura dell'indice
# --------------------------------------------------------------------------- #
def test_l_indice_di_nmap_si_legge(indice):
    from snapprobe.nmap_runner import percorso_script_db, script_conosciuti

    noti = script_conosciuti()

    assert "http-title" in noti and "cups-info" in noti
    assert len(noti) == 4
    assert percorso_script_db() == str(indice)


def test_l_indice_si_legge_una_volta_sola(indice):
    """E' un file su disco letto da trentadue thread di scansione: rileggerlo a ogni
    processo nmap sarebbe lavoro inutile a ogni bersaglio."""
    from snapprobe.nmap_runner import script_conosciuti

    primo = script_conosciuti()
    indice.write_text("", encoding="utf-8")

    assert script_conosciuti() is primo


def test_un_indice_assente_non_e_un_errore(tmp_path, monkeypatch):
    """Un'installazione con nmap altrove non deve fermarsi: si torna al comportamento
    di prima -- nessuna verifica, nmap protesta se un nome e' sbagliato."""
    from snapprobe import nmap_runner

    monkeypatch.setenv("SNAP_PROBE_NMAP_SCRIPT_DB", str(tmp_path / "non-esiste.db"))
    monkeypatch.setattr(nmap_runner, "PERCORSI_SCRIPT_DB", ())
    monkeypatch.setattr(nmap_runner, "find_nmap", lambda *a, **k: None)
    nmap_runner.azzera_script_conosciuti()
    try:
        assert nmap_runner.script_conosciuti() == frozenset()
    finally:
        nmap_runner.azzera_script_conosciuti()


# --------------------------------------------------------------------------- #
# Il filtro
# --------------------------------------------------------------------------- #
def test_i_nomi_inesistenti_si_scartano(indice):
    from snapprobe.nmap_runner import filtra_script

    tenuti, scartati = filtra_script(
        ["default", "+http-title", "ipp-info", "pgsql-info", "+ssl-cert"])

    assert tenuti == ["default", "+http-title", "+ssl-cert"]
    assert scartati == ["ipp-info", "pgsql-info"]


def test_il_prefisso_piu_si_conserva(indice):
    """Il `+` forza lo script dove nmap non riconosce il servizio atteso: questo
    prodotto trova interfacce web sulla 7070 e sulla 8443, e senza il `+` gli script
    non partirebbero proprio dove servono."""
    from snapprobe.nmap_runner import filtra_script

    tenuti, _ = filtra_script(["+smb-os-discovery"])

    assert tenuti == ["+smb-os-discovery"]


def test_le_categorie_non_sono_script_e_restano(indice):
    """`default`, `safe`, `discovery` sono insiemi: non stanno nell'indice degli
    script e scartarli svuoterebbe la raffica del set che `-A` porta con se'."""
    from snapprobe.nmap_runner import filtra_script

    tenuti, scartati = filtra_script(["default", "safe", "discovery", "version",
                                      "auth", "vuln"])

    assert scartati == []
    assert len(tenuti) == 6


def test_senza_indice_non_si_scarta_nulla(tmp_path, monkeypatch):
    """Meglio nmap che protesta di una fase svuotata in silenzio perche' non si e'
    trovato un file: un elenco ridotto senza dirlo e' una perdita di dati invisibile."""
    from snapprobe import nmap_runner

    monkeypatch.setattr(nmap_runner, "PERCORSI_SCRIPT_DB", ())
    monkeypatch.setattr(nmap_runner, "find_nmap", lambda *a, **k: None)
    monkeypatch.delenv("SNAP_PROBE_NMAP_SCRIPT_DB", raising=False)
    nmap_runner.azzera_script_conosciuti()
    try:
        tenuti, scartati = nmap_runner.filtra_script(["ipp-info", "non-esiste"])
        assert tenuti == ["ipp-info", "non-esiste"]
        assert scartati == []
    finally:
        nmap_runner.azzera_script_conosciuti()


def test_le_voci_vuote_si_ignorano(indice):
    from snapprobe.nmap_runner import filtra_script

    tenuti, scartati = filtra_script(["", "  ", None, "+http-title"])

    assert tenuti == ["+http-title"] and scartati == []


# --------------------------------------------------------------------------- #
# L'uso nel motore
# --------------------------------------------------------------------------- #
def test_la_raffica_non_chiede_a_nmap_uno_script_che_non_ha(probe_store, indice):
    """E' il punto del guasto: qui l'elenco che finisce sulla riga di comando deve
    contenere solo nomi che quell'nmap conosce."""
    from snapprobe.scanner import NetworkScanner

    scanner = NetworkScanner(probe_store, _EsecutoreMuto(), "prova")
    argomenti = scanner._arguments_for("raffica", {"raw_sockets": True},
                                       scanner.effort_profile(), ["10.0.0.1"])

    elenco = argomenti[argomenti.index("--script") + 1].split(",")
    assert "ipp-info" not in elenco and "pgsql-info" not in elenco
    assert "default" in elenco, "il set portato da -A non si deve perdere"
    # `malware` resta: e' una CATEGORIA di nmap, non uno script, e non sta
    # nell'indice -- scartarla priverebbe la raffica del rilevamento delle backdoor.
    assert all(v.lstrip("+") in {"default", "malware", "http-title", "ssl-cert",
                                 "cups-info", "smb-os-discovery"}
               for v in elenco), elenco


def test_cio_che_si_scarta_finisce_nel_diario(probe_store, indice):
    """Un elenco ridotto in silenzio sarebbe una perdita di dati invisibile: chi
    guarda il diario deve poter vedere che il catalogo e' piu' ricco dell'nmap
    installato."""
    from snapprobe.scanner import NetworkScanner

    scanner = NetworkScanner(probe_store, _EsecutoreMuto(), "prova")
    scanner._arguments_for("raffica", {"raw_sockets": True},
                           scanner.effort_profile(), ["10.0.0.1"])

    diario = " ".join(r["message"] for r in probe_store.recent_events(10))
    assert "non esistono in questo nmap" in diario
    assert "raffica" in diario


def test_lo_si_dice_una_volta_per_fase(probe_store, indice):
    """A ogni bersaglio ci sono trentadue processi: una riga per processo renderebbe
    il diario illeggibile proprio quando serve."""
    from snapprobe.scanner import NetworkScanner

    scanner = NetworkScanner(probe_store, _EsecutoreMuto(), "prova")
    for _ in range(5):
        scanner._arguments_for("raffica", {"raw_sockets": True},
                               scanner.effort_profile(), ["10.0.0.1"])

    righe = [r for r in probe_store.recent_events(30)
             if "non esistono in questo nmap" in r["message"]]
    assert len(righe) == 1


def test_il_catalogo_del_prodotto_non_contiene_nomi_inventati():
    """Il filtro e' una rete di sicurezza, non un permesso di scrivere nomi a caso:
    il catalogo va tenuto corretto. Questo test lo verifica contro l'indice
    dell'nmap installato, e si salta dove nmap non c'e'."""
    from snapprobe.nmap_runner import INSIEMI_NON_SCRIPT, script_conosciuti
    from snapprobe.scanner import ENRICHMENT_SCRIPTS, SCRIPT_RAFFICA, SNMP_SCRIPTS

    noti = script_conosciuti()
    if not noti:
        pytest.skip("nmap non installato: l'indice degli script non e' leggibile")

    inesistenti = []
    for elenco in (SCRIPT_RAFFICA, tuple(ENRICHMENT_SCRIPTS.split(",")),
                   tuple(SNMP_SCRIPTS.split(","))):
        for voce in elenco:
            nome = (voce or "").strip().lstrip("+")
            if nome and nome not in noti and nome not in INSIEMI_NON_SCRIPT:
                inesistenti.append(nome)
    assert not inesistenti, (
        "script inesistenti nel catalogo del prodotto: %s. Un solo nome sbagliato"
        " fa uscire nmap prima di scansionare." % ", ".join(sorted(set(inesistenti))))


class _EsecutoreMuto:
    """Esecutore che non avvia nmap: qui si guardano gli argomenti, non l'esito."""

    def available(self) -> bool:
        return True

    def detect_capabilities(self) -> dict:
        return {"available": True, "raw_sockets": True, "os_detection": True}

    def run(self, *args, **kwargs):
        raise AssertionError("nessun processo nmap deve partire in questa prova")
