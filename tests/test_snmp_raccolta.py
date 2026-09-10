"""
snap - Test della raccolta SNMP dagli apparati e dell'arricchimento del MAC.

Perche' esiste: il MAC si ottiene con ARP, che non attraversa un router. Per i nodi
delle subnet instradate l'unico modo di averlo e' chiederlo a un apparato di quel
segmento. Questi test verificano le tre proprieta' che rendono quel dato usabile:

* la PROVENIENZA e' sempre registrata (un MAC senza fonte non e' verificabile);
* cio' che si e' OSSERVATO vince su cio' che e' stato RIFERITO;
* una corrispondenza vecchia NON si usa (gli indirizzi si riassegnano).

remarks: Autore: Daniele Speziale - Data: 2026-09-09
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest


@pytest.fixture()
def sonda(probe_store):
    return probe_store


def _attiva(store, apparati="10.20.10.1|Router sede", community="segreta"):
    from snapprobe import snmp_raccolta

    store.set_settings({snmp_raccolta.CHIAVE_APPARATI: apparati,
                        snmp_raccolta.CHIAVE_COMMUNITY: community,
                        snmp_raccolta.CHIAVE_ATTIVA: "1"})


# --------------------------------------------------------------------------- #
# Dichiarazione degli apparati
# --------------------------------------------------------------------------- #
def test_l_elenco_accetta_etichette_e_commenti(sonda):
    from snapprobe import snmp_raccolta

    sonda.set_setting(snmp_raccolta.CHIAVE_APPARATI,
                      "10.20.10.1|Router sede\n"
                      "# questa riga si ignora\n"
                      "\n"
                      "10.60.0.1\n")

    assert snmp_raccolta.apparati_dichiarati(sonda) == [
        {"indirizzo": "10.20.10.1", "etichetta": "Router sede"},
        {"indirizzo": "10.60.0.1", "etichetta": "10.60.0.1"},
    ]


def test_un_indirizzo_non_valido_si_scarta_dichiarandolo(sonda):
    """L'indirizzo finisce in una connessione di rete: si valida, non si spera."""
    from snapprobe import snmp_raccolta

    sonda.set_setting(snmp_raccolta.CHIAVE_APPARATI,
                      "non-un-indirizzo\n10.20.10.1|buono\n$(whoami)")

    assert snmp_raccolta.apparati_dichiarati(sonda) == [
        {"indirizzo": "10.20.10.1", "etichetta": "buono"}]
    diario = " ".join(e["message"] for e in sonda.recent_events(20))
    assert "non e' un indirizzo" in diario


def test_senza_community_la_raccolta_non_e_attiva(sonda):
    """Attivarla senza credenziali non interrogherebbe nulla: meglio dirlo subito."""
    from snapprobe import snmp_raccolta

    sonda.set_settings({snmp_raccolta.CHIAVE_ATTIVA: "1",
                        snmp_raccolta.CHIAVE_COMMUNITY: ""})
    assert snmp_raccolta.attiva(sonda) is False


# --------------------------------------------------------------------------- #
# Raccolta
# --------------------------------------------------------------------------- #
def test_un_apparato_muto_non_ferma_gli_altri(sonda, monkeypatch):
    """Su una rete vera un apparato spento o con un'altra community e' la norma."""
    from snapprobe import snmp, snmp_raccolta

    _attiva(sonda, "10.20.10.1|Router sede\n10.60.0.1|Router filiale")

    def finto(host, community, **opzioni):
        if host == "10.20.10.1":
            raise snmp.SnmpError("non risponde")
        return {"10.60.0.7": "aa:bb:cc:dd:ee:01"}

    monkeypatch.setattr(snmp, "arp_table", finto)
    esito = snmp_raccolta.raccogli(sonda)

    assert esito["apparati"] == 2
    assert esito["interrogati"] == 1
    assert esito["falliti"] == 1
    assert esito["coppie"] == 1
    assert sonda.mac_da_snmp("10.60.0.7")["mac"] == "aa:bb:cc:dd:ee:01"


def test_la_provenienza_e_l_etichetta_dell_apparato(sonda, monkeypatch):
    from snapprobe import snmp, snmp_raccolta

    _attiva(sonda)
    monkeypatch.setattr(snmp, "arp_table",
                        lambda *a, **k: {"10.20.10.9": "aa:bb:cc:dd:ee:02"})
    snmp_raccolta.raccogli(sonda)

    assert sonda.mac_da_snmp("10.20.10.9")["fonte"] == "Router sede"


def test_una_corrispondenza_vecchia_non_si_usa(sonda):
    """Gli indirizzi si riassegnano: oltre la finestra si preferisce NESSUN MAC a un
    MAC probabilmente sbagliato."""
    from snapprobe.store import days_ago_str

    sonda.salva_arp_snmp({"10.20.10.9": "aa:bb:cc:dd:ee:03"}, "Router sede")
    # Si invecchia la voce oltre la finestra di validita'.
    with sonda._connect() as connessione:
        connessione.execute("UPDATE snmp_arp SET letto_at = ?",
                            (days_ago_str(40),))

    assert sonda.mac_da_snmp("10.20.10.9", entro_giorni=7) is None


# --------------------------------------------------------------------------- #
# Arricchimento del record del nodo
# --------------------------------------------------------------------------- #
def test_il_mac_osservato_vince_su_quello_riferito(sonda):
    """Cio' che la sonda ha VISTO (risposta ARP sul proprio segmento) e' un dato
    diretto; cio' che un apparato RIFERISCE puo' essere scaduto."""
    from snapprobe.scanner import NetworkScanner

    sonda.salva_arp_snmp({"10.20.10.9": "aa:bb:cc:dd:ee:04"}, "Router sede")
    scanner = NetworkScanner(sonda, None, "1.0.0-test")

    record = scanner._node_record(
        {"ip": "10.20.10.9", "mac": "11:22:33:44:55:66", "reachable": True}, True)

    assert record["mac"] == "11:22:33:44:55:66"
    assert record["mac_source"] == "arp"


def test_senza_mac_osservato_si_usa_quello_riferito_con_la_fonte(sonda):
    from snapprobe.scanner import NetworkScanner

    sonda.salva_arp_snmp({"10.60.0.7": "aa:bb:cc:dd:ee:05"}, "Router filiale")
    scanner = NetworkScanner(sonda, None, "1.0.0-test")

    record = scanner._node_record({"ip": "10.60.0.7", "reachable": True}, True)

    assert record["mac"] == "aa:bb:cc:dd:ee:05"
    assert record["mac_source"] == "snmp:Router filiale"


def test_senza_nessuna_delle_due_fonti_il_mac_resta_assente(sonda):
    """Nessun MAC inventato: un campo vuoto si vede, un campo sbagliato no."""
    from snapprobe.scanner import NetworkScanner

    scanner = NetworkScanner(sonda, None, "1.0.0-test")
    record = scanner._node_record({"ip": "10.99.0.1", "reachable": True}, True)

    assert record["mac"] is None
    assert record["mac_source"] is None


# --------------------------------------------------------------------------- #
# Porta fisica: dove il nodo e' ATTACCATO
# --------------------------------------------------------------------------- #
def test_la_porta_fisica_accompagna_il_mac_nel_record(sonda):
    """Il collegamento passa dal MAC: la tabella di forwarding di uno switch parla
    di MAC e non sa nulla di indirizzi IP. Senza MAC la porta non e' ricavabile."""
    from snapprobe.scanner import NetworkScanner

    sonda.salva_arp_snmp({"10.60.0.7": "aa:bb:cc:dd:ee:07"}, "Router filiale")
    sonda.salva_porte_snmp({"aa:bb:cc:dd:ee:07": "Gi1/0/12"}, "Switch piano 2")
    scanner = NetworkScanner(sonda, None, "1.0.0-test")

    record = scanner._node_record({"ip": "10.60.0.7", "reachable": True}, True)

    assert record["mac"] == "aa:bb:cc:dd:ee:07"
    assert record["mac_source"] == "snmp:Router filiale"
    assert record["switch_device"] == "Switch piano 2"
    assert record["switch_port"] == "Gi1/0/12"


def test_senza_mac_la_porta_resta_ignota(sonda):
    from snapprobe.scanner import NetworkScanner

    sonda.salva_porte_snmp({"aa:bb:cc:dd:ee:08": "Gi1/0/13"}, "Switch piano 2")
    scanner = NetworkScanner(sonda, None, "1.0.0-test")

    record = scanner._node_record({"ip": "10.99.9.9", "reachable": True}, True)

    assert record["switch_port"] is None
    assert record["switch_device"] is None


def test_una_porta_letta_troppo_tempo_prima_non_si_usa(sonda):
    """Un apparato si sposta di porta: una lettura di settimane fa direbbe dove ERA."""
    from snapprobe.store import days_ago_str

    sonda.salva_porte_snmp({"aa:bb:cc:dd:ee:09": "Gi1/0/14"}, "Switch piano 2")
    with sonda._connect() as connessione:
        connessione.execute("UPDATE snmp_porta SET letto_at = ?", (days_ago_str(30),))

    assert sonda.porta_da_snmp("aa:bb:cc:dd:ee:09", entro_giorni=7) is None
