"""
snap - Test dell'esclusione di porte dalla scansione.

Perche' esiste: su tre postazioni di amministrazione girava MobaXterm, che tiene un
X server in ascolto sulla 6000. Ogni passata della sonda apriva sul PC dell'operatore
una finestra "un'applicazione su <indirizzo> vuole accedere al server X: consenti?".
Una scansione di inventario non deve interrompere chi lavora.

L'esclusione e' configurabile e si applica a TUTTE le fasi che scansionano porte: il
valore aggiunto in un punto solo (`_arguments_for`) e' cio' che impedisce a una fase
nuova di dimenticarselo, e questi test lo verificano fase per fase.

remarks: Autore: Daniele Speziale - Data: 2026-09-09
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest

CAPACITA = {"raw_sockets": True, "os_detection": True}
# Le fasi che scansionano porte. `discovery` e `monitor` non ci sono: sono sweep di
# raggiungibilita' (`-sn`) e non aprono connessioni verso una porta.
FASI_CON_PORTE = ("ports", "services", "os", "vuln", "smb", "deep")


@pytest.fixture()
def scanner(probe_store):
    from snapprobe.scanner import NetworkScanner

    return NetworkScanner(probe_store, None, "1.0.0-test")


def test_ogni_fase_che_scansiona_porte_riceve_l_esclusione(scanner):
    for fase in FASI_CON_PORTE:
        argomenti = scanner._arguments_for(fase, CAPACITA, hosts=["10.0.0.1"])
        assert "--exclude-ports" in argomenti, (
            "la fase %s scansiona porte e deve ricevere l'esclusione" % fase)
        valore = argomenti[argomenti.index("--exclude-ports") + 1]
        assert valore == scanner.excluded_ports()


def test_gli_sweep_di_raggiungibilita_non_la_ricevono(scanner):
    """A uno sweep `-sn` l'opzione non serve: non scansiona porte."""
    for fase in ("discovery", "monitor"):
        scanner.store.upsert_local_node("10.0.0.1", state="confirmed")
        argomenti = scanner._arguments_for(fase, CAPACITA, hosts=["10.0.0.1"])
        assert "--exclude-ports" not in argomenti


def test_l_intervallo_degli_x_server_e_escluso_per_difetto(scanner):
    """E' il caso misurato: la 6000 apriva una finestra sul PC dell'operatore."""
    assert "6000" in scanner.excluded_ports()


def test_si_puo_riattivare_la_rilevazione(scanner):
    """Vuoto significa "nessuna esclusione": la scelta e' reversibile senza toccare
    il codice, perche' un X server esposto sulla rete resta un'esposizione vera."""
    scanner.store.set_setting("scan_exclude_ports", "")

    assert scanner.excluded_ports() == ""
    argomenti = scanner._arguments_for("ports", CAPACITA, hosts=["10.0.0.1"])
    assert "--exclude-ports" not in argomenti


def test_un_valore_non_valido_non_arriva_alla_riga_di_comando(scanner):
    """Il valore finisce sulla riga di comando di nmap: si valida con un'allowlist
    (solo numeri, virgole, trattini) e in caso di rifiuto si torna al predefinito,
    dichiarandolo nel diario."""
    from snapprobe.scanner import DEFAULT_EXCLUDED_PORTS

    for cattivo in ("6000; rm -rf /", "$(whoami)", "abc", "6000 --script vuln"):
        scanner.store.set_setting("scan_exclude_ports", cattivo)
        assert scanner.excluded_ports() == DEFAULT_EXCLUDED_PORTS

    diario = " ".join(e["message"] for e in scanner.store.recent_events(20))
    assert "non utilizzabili" in diario


def test_un_elenco_valido_viene_usato_come_scritto(scanner):
    scanner.store.set_setting("scan_exclude_ports", "6000-6009, 5900")

    # Gli spazi si tolgono: nmap non li accetta in un elenco di porte.
    assert scanner.excluded_ports() == "6000-6009,5900"
