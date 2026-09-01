"""
snap - Test della lettura dell'XML di nmap e della regola di ammissione.

Le fixture non sono inventate: provengono da scansioni reali eseguite su una /24
raggiunta per routing, con gli indirizzi sostituiti dall'intervallo di
documentazione RFC 5737. Sono quindi la prova del comportamento su cui la regola
di ammissione e' stata progettata:

  * nella fase di scoperta tutti gli host risultavano vivi per il solo
    'echo-reply', senza MAC ne' nome host: scartarli li' avrebbe cancellato
    otto dispositivi reali;
  * nella fase successiva quegli stessi host hanno mostrato porte, servizi e
    sistema operativo, confermando di essere reali.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from snapprobe import nmap_xml

FIXTURES = Path(__file__).parent / "fixtures"


def leggi(nome: str) -> str:
    return (FIXTURES / nome).read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Lettura dell'XML
# --------------------------------------------------------------------------- #
def test_la_scoperta_viene_riconosciuta_come_fase_senza_esame_delle_porte():
    esito = nmap_xml.parse_scan(leggi("nmap_scoperta.xml"))
    assert esito["run"]["ports_examined"] is False
    assert esito["run"]["nmap_version"] == "7.99"


def test_la_fase_delle_porte_viene_riconosciuta_come_tale():
    esito = nmap_xml.parse_scan(leggi("nmap_porte_servizi_os.xml"))
    assert esito["run"]["ports_examined"] is True
    assert "syn" in esito["run"]["scan_types"]


def test_le_prove_di_porta_sono_normalizzate():
    esito = nmap_xml.parse_scan(leggi("nmap_porte_servizi_os.xml"))
    porte = [p for nodo in esito["nodes"] for p in nodo["ports"]]
    assert porte, "nessuna porta letta"
    stampa = [p for p in porte if p["port"] == 9100 and p["state"] == "open"]
    assert stampa, "la porta di stampa non e' stata letta"
    assert stampa[0]["service_name"] == "jetdirect"
    for p in porte:
        assert p["protocol"] in ("tcp", "udp", "sctp")
        assert isinstance(p["port"], int)
        assert isinstance(p["cpe"], list)


def test_il_sistema_operativo_e_la_sua_classe_sono_letti():
    esito = nmap_xml.parse_scan(leggi("nmap_porte_servizi_os.xml"))
    con_os = [n for n in esito["nodes"] if n["os"].get("name")]
    assert len(con_os) >= 5, "attesi piu' nodi con sistema operativo rilevato"
    for nodo in con_os:
        assert isinstance(nodo["os"]["accuracy"], int)


def test_il_ttl_della_risposta_viene_conservato():
    esito = nmap_xml.parse_scan(leggi("nmap_scoperta.xml"))
    nodi = esito["nodes"] + esito["candidates"]
    assert all(n["ttl"] is not None for n in nodi)
    # TTL diversi provengono da host genuinamente diversi.
    assert nmap_xml.distinct_ttls(nodi) >= 3


def test_un_xml_illeggibile_solleva_un_errore_esplicito():
    with pytest.raises(nmap_xml.NmapXmlError):
        nmap_xml.parse_scan("<nmaprun><host>")
    with pytest.raises(nmap_xml.NmapXmlError):
        nmap_xml.parse_scan("<altro/>")


# --------------------------------------------------------------------------- #
# Regola di ammissione
# --------------------------------------------------------------------------- #
def test_un_host_vivo_e_nulla_piu_dopo_le_porte_viene_scartato():
    """La regola richiesta: vivo senza altre informazioni e' un errore di rete."""
    esito = nmap_xml.parse_scan(leggi("nmap_host_fantasma.xml"))
    assert esito["nodes"] == [], "un host senza informazioni e' stato registrato"
    assert len(esito["discarded"]) == 1
    scartato = esito["discarded"][0]
    assert scartato["ip"] == "192.0.2.240"
    assert "errore di rete" in scartato["assessment_reason"]


def test_nella_scoperta_lo_stesso_host_resta_candidato_e_non_viene_scartato():
    """Applicare la regola alla scoperta cancellerebbe host reali.

    Verificato sul campo: otto dispositivi reali si presentavano in questo modo.
    """
    esito = nmap_xml.parse_scan(leggi("nmap_scoperta.xml"))
    assert esito["discarded"] == [], "la scoperta non deve scartare nulla"
    assert len(esito["candidates"]) == 8
    assert all(c["assessment"] == nmap_xml.CANDIDATO for c in esito["candidates"])
    assert all("in attesa di conferma" in c["assessment_reason"] for c in esito["candidates"])


def test_gli_stessi_host_diventano_registrabili_dopo_l_esame_delle_porte():
    scoperta = nmap_xml.parse_scan(leggi("nmap_scoperta.xml"))
    approfondita = nmap_xml.parse_scan(leggi("nmap_porte_servizi_os.xml"))
    candidati = {c["ip"] for c in scoperta["candidates"]}
    registrati = {n["ip"] for n in approfondita["nodes"]}
    assert candidati == registrati, (
        "i candidati della scoperta non coincidono con i nodi confermati"
    )
    assert approfondita["discarded"] == []


def test_una_porta_chiusa_basta_a_dimostrare_che_l_host_esiste():
    """Anche una porta chiusa e' una risposta: prova che qualcuno ha risposto."""
    prove = {"reachable": True, "status_reason": "echo-reply",
             "ports": [{"protocol": "tcp", "port": 80, "state": "closed"}],
             "port_states": {}, "os": {}, "scripts": {}}
    stato, motivo = nmap_xml.assess_host(prove, ports_examined=True)
    assert stato == nmap_xml.REGISTRABILE
    assert "porta" in motivo


def test_gli_stati_aggregati_delle_porte_sono_prova_sufficiente():
    """Il caso reale: 196 porte chiuse riassunte in <extraports>."""
    prove = {"reachable": True, "status_reason": "echo-reply", "ports": [],
             "port_states": {"closed": 196}, "os": {}, "scripts": {}}
    stato, _ = nmap_xml.assess_host(prove, ports_examined=True)
    assert stato == nmap_xml.REGISTRABILE


def test_un_mac_noto_basta_a_registrare_il_nodo():
    prove = {"reachable": True, "mac": "B8:27:EB:11:22:33", "status_reason": "arp-response",
             "ports": [], "port_states": {}, "os": {}, "scripts": {}}
    stato, motivo = nmap_xml.assess_host(prove, ports_examined=False)
    assert stato == nmap_xml.REGISTRABILE
    assert "MAC" in motivo


def test_un_host_non_raggiungibile_non_viene_registrato():
    prove = {"reachable": False, "ports": [], "port_states": {}, "os": {}, "scripts": {}}
    stato, motivo = nmap_xml.assess_host(prove, ports_examined=True)
    assert stato == nmap_xml.SCARTATO
    assert "non raggiungibile" in motivo


def test_ogni_esito_porta_sempre_la_propria_motivazione():
    for nome in ("nmap_scoperta.xml", "nmap_porte_servizi_os.xml", "nmap_host_fantasma.xml"):
        esito = nmap_xml.parse_scan(leggi(nome))
        for nodo in esito["nodes"] + esito["candidates"] + esito["discarded"]:
            assert nodo["assessment"] in (nmap_xml.REGISTRABILE, nmap_xml.CANDIDATO,
                                          nmap_xml.SCARTATO)
            assert nodo["assessment_reason"], "%s: esito senza motivazione" % nodo["ip"]


def test_le_fixture_non_contengono_indirizzi_reali():
    """Le fixture usano l'intervallo di documentazione RFC 5737."""
    for nome in ("nmap_scoperta.xml", "nmap_porte_servizi_os.xml", "nmap_host_fantasma.xml"):
        testo = leggi(nome)
        assert "10.50.9." not in testo, "%s contiene indirizzi reali" % nome
        assert "192.0.2." in testo


def test_l_host_abbandonato_per_scadenza_viene_riconosciuto():
    """nmap lo dichiara con timedout="true": e' la differenza fra "non ha nulla"
    e "non c'e' stato tempo di guardare". Senza leggerlo, una fase che non produce
    nulla non si distingue da una rete silenziosa."""
    letto = nmap_xml.parse_scan(leggi("nmap_host_scaduto.xml"))
    tutti = letto["nodes"] + letto["candidates"] + letto["discarded"]
    assert len(tutti) == 1
    assert tutti[0]["timed_out"] is True
    assert tutti[0]["ip"] == "192.0.2.61"


def test_un_host_concluso_non_risulta_scaduto():
    letto = nmap_xml.parse_scan(leggi("nmap_porte_servizi_os.xml"))
    tutti = letto["nodes"] + letto["candidates"] + letto["discarded"]
    assert tutti, "il file di prova doveva contenere host"
    assert all(p["timed_out"] is False for p in tutti)
