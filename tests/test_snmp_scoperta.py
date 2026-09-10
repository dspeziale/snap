"""
snap - Test della scoperta automatica degli apparati di rete.

Perche' esiste: le tabelle ARP degli apparati sono l'unico modo di avere il MAC dei
nodi su subnet instradate, ma dichiarare gli apparati a mano non regge su decine di
subnet -- e un elenco scritto a mano nessuno lo tiene aggiornato.

La proprieta' che questi test difendono e' una sola, ed e' quella che rende la
popolazione automatica sicura: **nell'elenco entra solo cio' che ha superato la
prova** (risponde in SNMP e ha una tabella ARP). Un apparato che "sembra" un router
ma non risponde non serve a niente, e uno senza tabella ARP non aggiunge dati.

remarks: Autore: Daniele Speziale - Data: 2026-09-09
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json

import pytest


@pytest.fixture()
def scanner(probe_store):
    from snapprobe.scanner import NetworkScanner
    from snapprobe import snmp_raccolta

    probe_store.set_setting(snmp_raccolta.CHIAVE_COMMUNITY, "vera")
    probe_store.set_json("scan_subnets", [{"cidr": "10.20.10.0/24"}])
    return NetworkScanner(probe_store, None, "1.0.0-test")


def _nodo_con_porte(store, ip, porte):
    profilo = {"ip": ip, "ports_index": {
        "udp/%d" % p if p == 161 else "tcp/%d" % p: {
            "protocol": "udp" if p == 161 else "tcp", "port": p, "state": "open"}
        for p in porte}}
    store.upsert_local_node(ip, state="confirmed", open_ports=len(porte),
                            profile_json=json.dumps(profilo))


# --------------------------------------------------------------------------- #
# Scelta dei candidati
# --------------------------------------------------------------------------- #
def test_i_gateway_del_perimetro_sono_candidati(scanner):
    from snapprobe import snmp_scoperta

    indirizzi = {c["indirizzo"] for c in snmp_scoperta.candidati(scanner)}

    assert "10.20.10.1" in indirizzi      # primo utilizzabile
    assert "10.20.10.254" in indirizzi    # ultimo utilizzabile


def test_un_nodo_con_la_161_aperta_e_candidato_per_osservazione(scanner):
    """Non e' una congettura come il gateway: la 161 e' stata VISTA aperta."""
    from snapprobe import snmp_scoperta

    _nodo_con_porte(scanner.store, "10.20.10.77", [161])

    candidato = next(c for c in snmp_scoperta.candidati(scanner)
                     if c["indirizzo"] == "10.20.10.77")
    assert "161/UDP osservata aperta" in candidato["motivi"]


def test_i_candidati_osservati_vengono_prima_delle_congetture(scanner):
    """Se il limite taglia, deve tagliare le congetture, non le osservazioni."""
    from snapprobe import snmp_scoperta

    _nodo_con_porte(scanner.store, "10.20.10.77", [161])
    elenco = snmp_scoperta.candidati(scanner)

    primo = elenco[0]
    assert not any(m.startswith("gateway") for m in primo["motivi"])


# --------------------------------------------------------------------------- #
# La prova: e' l'unico criterio di ammissione all'elenco
# --------------------------------------------------------------------------- #
def test_si_aggiunge_solo_chi_risponde_e_ha_tabella_arp(scanner, monkeypatch):
    from snapprobe import snmp, snmp_raccolta, snmp_scoperta

    def finta_arp(host, community, **opzioni):
        if community != "vera":
            raise snmp.SnmpError("community non valida")
        if host == "10.20.10.1":
            return {"10.20.10.5": "aa:bb:cc:00:00:01"}   # risponde, ha voci
        if host == "10.20.10.254":
            return {}                                     # risponde, nessuna voce
        raise snmp.SnmpError("non risponde")

    monkeypatch.setattr(snmp, "arp_table", finta_arp)
    monkeypatch.setattr(snmp, "identifica",
                        lambda h, c, **k: {"nome": "router-sede"})

    esito = snmp_scoperta.scopri(scanner)

    assert [a["indirizzo"] for a in esito["aggiunti"]] == ["10.20.10.1"]
    assert [v["indirizzo"] for v in esito["senza_arp"]] == ["10.20.10.254"]
    # L'elenco contiene solo l'apparato provato, con il nome che si e' dichiarato.
    assert snmp_raccolta.apparati_dichiarati(scanner.store) == [
        {"indirizzo": "10.20.10.1", "etichetta": "router-sede"}]


def test_la_community_di_fabbrica_si_segnala_e_non_si_aggiunge(scanner, monkeypatch):
    """Un apparato che risponde con 'public' e' un'esposizione. Va detto -- e non
    va messo nell'elenco, perche' il prodotto conserva una community sola e non
    quella del singolo apparato."""
    from snapprobe import snmp, snmp_raccolta, snmp_scoperta

    def finta_arp(host, community, **opzioni):
        if host == "10.20.10.1" and community == "public":
            return {"10.20.10.5": "aa:bb:cc:00:00:02"}
        raise snmp.SnmpError("non risponde")

    monkeypatch.setattr(snmp, "arp_table", finta_arp)
    monkeypatch.setattr(snmp, "identifica", lambda h, c, **k: {})

    esito = snmp_scoperta.scopri(scanner)

    assert esito["aggiunti"] == []
    assert [(v["indirizzo"], v["community"]) for v in esito["di_fabbrica"]] == [
        ("10.20.10.1", "public")]
    assert snmp_raccolta.apparati_dichiarati(scanner.store) == []
    diario = " ".join(e["message"] for e in scanner.store.recent_events(30))
    assert "community di fabbrica" in diario
    assert "esposizione" in diario


def test_un_apparato_gia_in_elenco_non_si_duplica(scanner, monkeypatch):
    from snapprobe import snmp, snmp_raccolta, snmp_scoperta

    scanner.store.set_setting(snmp_raccolta.CHIAVE_APPARATI, "10.20.10.1|Router sede")
    monkeypatch.setattr(snmp, "arp_table",
                        lambda h, c, **k: {"10.20.10.5": "aa:bb:cc:00:00:03"}
                        if h == "10.20.10.1" else {})
    monkeypatch.setattr(snmp, "identifica", lambda h, c, **k: {"nome": "altro-nome"})

    snmp_scoperta.scopri(scanner)

    elenco = snmp_raccolta.apparati_dichiarati(scanner.store)
    assert [a["indirizzo"] for a in elenco].count("10.20.10.1") == 1


def test_il_nome_dell_apparato_si_ripulisce(scanner, monkeypatch):
    """Il nome finisce in un elenco a righe con separatore '|': un nome che
    contiene quel carattere o un ritorno a capo spezzerebbe l'elenco."""
    from snapprobe import snmp, snmp_raccolta, snmp_scoperta

    monkeypatch.setattr(snmp, "arp_table",
                        lambda h, c, **k: {"10.20.10.5": "aa:bb:cc:00:00:04"}
                        if h == "10.20.10.1" else {})
    monkeypatch.setattr(snmp, "identifica",
                        lambda h, c, **k: {"nome": "sw|core\nsede   principale"})

    snmp_scoperta.scopri(scanner)

    elenco = snmp_raccolta.apparati_dichiarati(scanner.store)
    assert elenco == [{"indirizzo": "10.20.10.1",
                       "etichetta": "sw core sede principale"}]


# --------------------------------------------------------------------------- #
# Scoperta AUTOMATICA: se la scansione trova SNMP aperto, si interroga
# --------------------------------------------------------------------------- #
# Richiesta dell'operatore: "se nella scansione trovi snmp aperto fai anche una
# scansione per quello". Prima l'elenco degli apparati si popolava SOLO col pulsante
# "Scopri e popola l'elenco": un apparato trovato dalla scansione restava invisibile
# alla raccolta, e i MAC delle sue subnet non arrivavano mai.
def _agente(probe_store):
    """Agente con lo scanner della fixture, senza avviare nulla."""
    import snapprobe.agent as modulo

    agente = modulo.ProbeAgent.__new__(modulo.ProbeAgent)
    agente.store = probe_store
    from snapprobe.scanner import NetworkScanner

    agente.scanner = NetworkScanner(probe_store, None, "1.0.0-test")
    return agente


def test_un_apparato_con_snmp_aperto_entra_da_se_nell_elenco(scanner, monkeypatch):
    """E' la richiesta: trovata la 161 aperta, si prova e -- se risponde -- si
    interroga, senza che nessuno prema un pulsante."""
    from snapprobe import snmp, snmp_raccolta

    _nodo_con_porte(scanner.store, "10.20.10.77", [161, 22])
    monkeypatch.setattr(snmp, "arp_table",
                        lambda h, c, **k: {"10.20.10.5": "aa:bb:cc:00:00:01"}
                        if h == "10.20.10.77" else {})
    monkeypatch.setattr(snmp, "identifica", lambda h, c, **k: {"nome": "switch-piano1"})

    agente = _agente(scanner.store)
    scoperti = agente._scopri_apparati_snmp()

    assert "10.20.10.77" in scoperti
    dichiarati = [a["indirizzo"] for a in snmp_raccolta.apparati_dichiarati(scanner.store)]
    assert "10.20.10.77" in dichiarati


def test_senza_community_non_si_aggiunge_nulla(scanner, monkeypatch):
    """La PROVA e' il criterio di ammissione, e senza community non si puo' provare:
    aggiungere alla cieca riempirebbe l'elenco di apparati muti."""
    from snapprobe import snmp, snmp_raccolta

    scanner.store.set_setting(snmp_raccolta.CHIAVE_COMMUNITY, "")
    _nodo_con_porte(scanner.store, "10.20.10.78", [161])
    chiamate = []
    monkeypatch.setattr(snmp, "arp_table",
                        lambda h, c, **k: chiamate.append(h) or {})

    agente = _agente(scanner.store)

    assert agente._scopri_apparati_snmp() == []
    assert not chiamate, "senza community non si deve interrogare nessuno"


def test_un_apparato_gia_dichiarato_non_si_duplica(scanner, monkeypatch):
    """La scoperta si esegue per intero a ogni ciclo -- costa 8 s per una /24 e
    verifica anche che gli apparati noti rispondano ancora -- quindi un apparato
    dichiarato viene riprovato. Cio' che non deve accadere e' che finisca due volte
    nell'elenco.
    """
    from snapprobe import snmp, snmp_raccolta

    _nodo_con_porte(scanner.store, "10.20.10.79", [161])
    scanner.store.set_setting(snmp_raccolta.CHIAVE_APPARATI, "10.20.10.79|switch")
    monkeypatch.setattr(snmp, "arp_table",
                        lambda h, c, **k: {"10.20.10.5": "aa:bb:cc:00:00:01"}
                        if h == "10.20.10.79" else {})
    monkeypatch.setattr(snmp, "identifica", lambda h, c, **k: {"nome": "switch"})

    agente = _agente(scanner.store)
    agente._scopri_apparati_snmp()
    agente._scopri_apparati_snmp()

    dichiarati = [a["indirizzo"] for a
                  in snmp_raccolta.apparati_dichiarati(scanner.store)]
    assert dichiarati.count("10.20.10.79") == 1, (
        "l'apparato e' stato dichiarato piu' volte: %s" % dichiarati)


def test_si_interrogano_tutti_gli_host_vivi_non_solo_quelli_con_la_161(scanner):
    """La 161 e' UDP, e un port scan UDP non distingue "aperta" da "nessuna
    risposta": nmap risponde `open|filtered` su 32 indirizzi su 32, quindi come
    indizio non vale nulla. Una GET di sysDescr invece risponde o non risponde.

    Chiedere a tutti gli host vivi costa 8 s per una /24 (misurato, 64 fili) ed e'
    piu' semplice E piu' affidabile che indovinare a chi chiedere.
    """
    from snapprobe import snmp_scoperta

    # Un host vivo SENZA la 161 fra le porte note.
    _nodo_con_porte(scanner.store, "10.20.10.90", [80, 443])

    indirizzi = {v["indirizzo"] for v in snmp_scoperta.candidati(scanner)}

    assert "10.20.10.90" in indirizzi


def test_l_ordine_mette_prima_cio_che_si_e_osservato(scanner):
    """Quando il tetto taglia, deve tagliare le congetture: prima gli indirizzi su
    cui si e' visto qualcosa, poi i gateway probabili, infine il resto."""
    from snapprobe import snmp_scoperta

    _nodo_con_porte(scanner.store, "10.20.10.90", [80])          # host qualunque
    _nodo_con_porte(scanner.store, "10.20.10.91", [161])         # osservato
    elenco = snmp_scoperta.candidati(scanner)
    posizioni = {v["indirizzo"]: i for i, v in enumerate(elenco)}

    assert posizioni["10.20.10.91"] < posizioni["10.20.10.90"]


def test_un_errore_della_scoperta_non_ferma_la_raccolta(scanner, monkeypatch):
    """E' un arricchimento dell'arricchimento: se fallisce, la raccolta dai
    apparati gia' noti deve proseguire."""
    from snapprobe import snmp_scoperta

    _nodo_con_porte(scanner.store, "10.20.10.80", [161])

    def esplode(*_a, **_k):
        raise RuntimeError("rete irraggiungibile")

    monkeypatch.setattr(snmp_scoperta, "candidati", esplode)

    agente = _agente(scanner.store)

    assert agente._scopri_apparati_snmp() == []
    righe = " ".join(r["message"] for r in scanner.store.recent_events(10))
    assert "Scoperta automatica" in righe, "il fallimento va dichiarato nel diario"
