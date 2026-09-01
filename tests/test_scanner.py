"""
snap - Test dell'orchestratore della scansione progressiva.

L'esecutore di nmap e' sostituito da un esecutore finto che restituisce le
fixture reali: i test verificano le decisioni dell'orchestratore, non il
funzionamento di nmap.

Proprieta' verificate: perimetro vincolante, progressione delle fasi con le
rispettive cadenze, regola di ammissione (candidato, conferma, scarto), stato
persistito prima del conferimento, ricaduta su scansione per connessione quando
l'accesso raw non e' disponibile.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from snapprobe import scanner as modulo_scanner
from snapprobe.nmap_runner import NmapTimeout
from snapprobe.scanner import NetworkScanner, PerimeterViolation

FIXTURES = Path(__file__).parent / "fixtures"
PERIMETRO = [{"cidr": "192.0.2.0/24", "label": "Rete di prova"}]


class EsecutoreFinto:
    """Restituisce un XML preparato e registra come e' stato invocato."""

    def __init__(self, xml: str = "", capacita: dict = None, errore: Exception = None):
        self.xml = xml
        self.errore = errore
        self.chiamate = []
        self._capacita = capacita or {
            "available": True, "executable": "nmap-finto", "nmap_version": "7.99",
            "raw_sockets": True, "os_detection": True, "detail": "esecutore di prova",
        }

    def detect_capabilities(self, force: bool = False) -> dict:
        return self._capacita

    def run(self, arguments, targets, timeout=None, label=None) -> str:
        # `label` descrive la fase in corso per l'indicatore: qui non serve,
        # ma la firma deve corrispondere a quella del runner vero.
        self.chiamate.append({"arguments": list(arguments), "targets": list(targets)})
        if self.errore is not None:
            raise self.errore
        return self.xml


def leggi(nome: str) -> str:
    return (FIXTURES / nome).read_text(encoding="utf-8")


@pytest.fixture()
def sonda(probe_store):
    """Archivio con perimetro dichiarato."""
    probe_store.set_json("scan_subnets", PERIMETRO)
    return probe_store


# --------------------------------------------------------------------------- #
# Perimetro
# --------------------------------------------------------------------------- #
def test_senza_perimetro_non_si_scansiona(probe_store):
    scanner = NetworkScanner(probe_store, EsecutoreFinto(leggi("nmap_scoperta.xml")))
    assert scanner.next_due() is None
    with pytest.raises(PerimeterViolation):
        scanner.run_stage("discovery", "192.0.2.0/24")


def test_una_subnet_non_dichiarata_viene_rifiutata(sonda):
    esecutore = EsecutoreFinto(leggi("nmap_scoperta.xml"))
    scanner = NetworkScanner(sonda, esecutore)
    with pytest.raises(PerimeterViolation):
        scanner.run_stage("discovery", "10.99.0.0/24")
    assert esecutore.chiamate == [], "nmap non deve essere invocato fuori dal perimetro"
    eventi = [e for e in sonda.recent_events(20) if "perimetro" in e["message"]]
    assert eventi, "il rifiuto deve essere annotato nel diario"


def test_il_rifiuto_fuori_perimetro_produce_un_evento_di_gravita_alta(sonda):
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_scoperta.xml")))
    with pytest.raises(PerimeterViolation):
        scanner.run_stage("discovery", "10.99.0.0/24")
    conferiti = sonda.reserve_batch("prova-rifiuto")
    rifiuti = [r["payload"] for r in conferiti
               if r["payload"].get("type") == "probe.perimeter.refused"]
    assert rifiuti, "il rifiuto deve essere conferito al server"
    assert rifiuti[0]["severity"] == "critical"


def test_un_nodo_fuori_perimetro_non_viene_scansionato(sonda):
    """La garanzia: nulla fuori dal perimetro dichiarato viene scansionato.

    Il nodo non viene piu' scelto dalla pianificazione. Prima l'intero compito
    veniva rifiutato, e un solo nodo uscito dal perimetro -- una subnet
    disattivata sul server -- annullava anche i bersagli legittimi che lo
    accompagnavano, fase dopo fase.
    """
    sonda.upsert_local_node("10.99.0.5", state="confirmed")
    esecutore = EsecutoreFinto(leggi("nmap_porte_servizi_os.xml"))
    scanner = NetworkScanner(sonda, esecutore)

    esito = scanner.run_stage("ports", "*")
    assert esecutore.chiamate == [], "nmap non deve essere invocato fuori dal perimetro"
    assert esito["status"] == "skipped"
    diario = " ".join(e["message"] for e in sonda.recent_events(10))
    assert "non e' piu' fra quelle dichiarate dal server" in diario


def test_i_nodi_legittimi_non_pagano_per_quello_fuori_perimetro(sonda):
    """Un nodo uscito dal perimetro non deve trascinare con se' gli altri."""
    sonda.upsert_local_node("192.0.2.20", state="confirmed")
    sonda.upsert_local_node("10.99.0.5", state="confirmed")
    esecutore = EsecutoreFinto(leggi("nmap_porte_servizi_os.xml"))
    scanner = NetworkScanner(sonda, esecutore)

    scanner.run_stage("ports", "*")
    assert esecutore.chiamate, "il bersaglio legittimo doveva essere scansionato"
    bersagli = esecutore.chiamate[-1]["targets"]
    assert "192.0.2.20" in bersagli
    assert "10.99.0.5" not in bersagli


def test_il_controllo_dentro_il_compito_resta_l_ultima_difesa(sonda):
    """Se un bersaglio fuori perimetro arrivasse comunque al compito, si rifiuta."""
    esecutore = EsecutoreFinto(leggi("nmap_porte_servizi_os.xml"))
    scanner = NetworkScanner(sonda, esecutore)
    with pytest.raises(PerimeterViolation):
        scanner._run_task({"stage": "ports", "target": "*", "hosts": ["10.99.0.5"]},
                          scanner.capabilities(), scanner.effort_profile())
    assert esecutore.chiamate == []


# --------------------------------------------------------------------------- #
# Regola di ammissione
# --------------------------------------------------------------------------- #
def test_la_scoperta_tiene_i_nodi_nudi_come_candidati(sonda):
    """Gli 8 host della fixture reale hanno solo 'echo-reply': restano candidati."""
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_scoperta.xml")))
    esito = scanner.run_stage("discovery", "192.0.2.0/24")

    assert esito["records"].get("nodes") is None, "nessun nodo va conferito dalla sola scoperta"
    assert sonda.local_node_count("candidate") == 8
    assert sonda.local_node_count("confirmed") == 0


def test_l_esame_delle_porte_conferma_i_candidati_ma_non_conferisce(sonda):
    """La conferma non basta: il conferimento attende il profilo completo."""
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_scoperta.xml")))
    scanner.run_stage("discovery", "192.0.2.0/24")

    scanner.runner = EsecutoreFinto(leggi("nmap_porte_servizi_os.xml"))
    esito = scanner.run_stage("ports", "*")

    assert sonda.local_node_count("confirmed") == 8
    assert sonda.local_node_count("candidate") == 0
    assert "nodes" not in esito["records"], (
        "con il solo esame delle porte il profilo e' incompleto: nulla va conferito"
    )
    # Le prove restano nell'archivio locale, in attesa delle fasi mancanti.
    locali = sonda.local_nodes("confirmed")
    assert all("ports" in (n["stages_done"] or "") for n in locali)
    assert all(n["conferred_at"] is None for n in locali)


def test_un_candidato_mai_confermato_viene_scartato(sonda):
    """La regola richiesta: vivo senza informazioni e' un errore di rete."""
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_host_fantasma.xml")))
    sonda.upsert_local_node("192.0.2.240", state="candidate")

    scanner.run_stage("ports", "*")
    assert sonda.local_node_count("candidate") == 1, "primo tentativo: si insiste"

    scanner.run_stage("ports", "*")
    assert sonda.local_node_count() == 0, "secondo tentativo: si scarta"
    conferiti = sonda.reserve_batch("prova-scarto")
    scartati = [r["payload"] for r in conferiti
                if r["payload"].get("type") == "probe.node.discarded"]
    assert scartati, "lo scarto deve essere riferito al server"
    assert scartati[0]["detail"]["indirizzo"] == "192.0.2.240"


def test_il_conferimento_avviene_quando_il_profilo_e_completo(sonda):
    """Regola richiesta: si invia al server a scoperta del dispositivo completata.

    Le tre fasi del profilo (porte, servizi, sistema operativo) devono essere
    tutte svolte; solo allora il dispositivo viene conferito, intero.
    """
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_porte_servizi_os.xml")))
    for indirizzo in ("192.0.2.1", "192.0.2.12", "192.0.2.18"):
        sonda.upsert_local_node(indirizzo, state="confirmed")

    assert "nodes" not in scanner.run_stage("ports", "*")["records"]
    assert "nodes" not in scanner.run_stage("services", "*")["records"]
    esito = scanner.run_stage("os", "*")

    tipi = set(esito["records"])
    assert {"nodes", "ports", "os"} <= tipi, "il profilo completo va conferito intero"
    assert esito["records"]["scan_runs"][0]["stage"] == "os"
    stampanti = [p for p in esito["records"]["ports"] if p["port"] == 9100]
    assert stampanti, "la porta di stampa della fixture non e' stata conferita"
    assert all(n["ports_examined"] for n in esito["records"]["nodes"]), (
        "a profilo completo le porte non riviste possono essere chiuse dal server"
    )
    # Conferito. Le fasi svolte NON si azzerano: azzerarle rimetterebbe il nodo
    # fra quelli in attesa di profilo e la scoperta non avanzerebbe piu'.
    locali = sonda.local_nodes("confirmed")
    assert all(n["conferred_at"] for n in locali)
    assert all("ports" in (n["stages_done"] or "") for n in locali)

    # E senza prove nuove non si riconferisce: un secondo giro non produce nodi.
    assert "nodes" not in scanner._confer_complete_profiles()


def test_senza_rilevamento_del_sistema_operativo_il_profilo_si_completa_prima(sonda):
    """Se l'accesso raw manca, porte e servizi bastano a dichiarare il profilo."""
    esecutore = EsecutoreFinto(
        leggi("nmap_porte_servizi_os.xml"),
        capacita={"available": True, "executable": "nmap-finto", "nmap_version": "7.99",
                  "raw_sockets": False, "os_detection": False, "detail": "senza raw"},
    )
    scanner = NetworkScanner(sonda, esecutore)
    sonda.upsert_local_node("192.0.2.12", state="confirmed")

    assert scanner._required_stages() == ("ports", "services")
    assert "nodes" not in scanner.run_stage("ports", "*")["records"]
    esito = scanner.run_stage("services", "*")
    assert "nodes" in esito["records"], "senza la fase del sistema operativo il profilo e' completo"


def test_scoperta_e_profili_avanzano_insieme(sonda):
    """Nessuna delle due attivita' deve morire di fame.

    Con la priorita' assoluta ai profili la scoperta non avanzava: su una rete di
    centinaia di subnet i nodi da profilare non finiscono mai. Ora la scoperta
    scaduta ha un posto garantito nel ciclo, e i profili occupano i restanti.
    """
    sonda.set_json("scan_subnets", [{"cidr": "192.0.2.0/24"}, {"cidr": "192.0.2.128/25"}])
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_scoperta.xml")))
    sonda.set_setting("scan_effort", "max")
    scanner.run_stage("discovery", "192.0.2.0/24")

    compiti = scanner.plan_tasks()
    fasi = [c["stage"] for c in compiti]
    assert "discovery" in fasi, "la scoperta deve avere un posto garantito"
    assert any(f in ("ports", "services", "os") for f in fasi), (
        "i profili devono avanzare nello stesso ciclo"
    )


def test_un_nodo_conferito_non_e_piu_in_attesa_di_profilo(sonda):
    """Era la causa dello stallo: il nodo conferito tornava in attesa e la
    scoperta non avanzava piu'."""
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_porte_servizi_os.xml")))
    sonda.upsert_local_node("192.0.2.12", state="confirmed")
    for fase in ("ports", "services", "os"):
        scanner.run_stage(fase, "*")

    assert sonda.local_nodes("confirmed")[0]["conferred_at"]
    assert scanner.pending_nodes() == [], "un nodo conferito non attende piu' il profilo"
    for fase in ("ports", "services", "os"):
        assert scanner.pending_nodes(fase) == []


def test_il_monitoraggio_riguarda_solo_i_nodi_gia_conferiti(sonda):
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_scoperta.xml")))
    sonda.upsert_local_node("192.0.2.1", state="confirmed")          # mai conferito
    sonda.upsert_local_node("192.0.2.12", state="confirmed", conferred_at="2026-08-27 09:00:00")
    esito = scanner.run_stage("monitor", "*")
    indirizzi = {c["ip"] for c in esito["records"].get("monitor", [])}
    assert "192.0.2.1" not in indirizzi, "un campione per un nodo ignoto arriverebbe orfano"


# --------------------------------------------------------------------------- #
# Progressione e cadenze
# --------------------------------------------------------------------------- #
def test_la_scoperta_e_la_prima_fase_dovuta(sonda):
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_scoperta.xml")))
    assert scanner.next_due() == ("discovery", "192.0.2.0/24")


def test_una_fase_appena_eseguita_non_e_piu_dovuta(sonda):
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_scoperta.xml")))
    scanner.run_stage("discovery", "192.0.2.0/24")
    dovuta = scanner.next_due()
    assert dovuta is None or dovuta[0] != "discovery"


def test_dopo_la_scoperta_tocca_alle_porte(sonda):
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_scoperta.xml")))
    scanner.run_stage("discovery", "192.0.2.0/24")
    assert scanner.next_due() == ("ports", "*")


def test_lo_stato_della_fase_e_persistito(sonda):
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_scoperta.xml")))
    scanner.run_stage("discovery", "192.0.2.0/24")
    stato = sonda.scan_state("192.0.2.0/24", "discovery")
    assert stato["last_status"] == "completed"
    assert stato["runs"] == 1
    assert stato["last_run_at"]


def test_una_fase_senza_bersagli_viene_saltata_senza_invocare_nmap(sonda):
    esecutore = EsecutoreFinto(leggi("nmap_porte_servizi_os.xml"))
    scanner = NetworkScanner(sonda, esecutore)
    esito = scanner.run_stage("monitor", "*")
    assert esito["status"] == "skipped"
    assert esecutore.chiamate == []


def test_le_cadenze_del_server_prevalgono_su_quelle_predefinite(sonda):
    sonda.set_json("scan_cadences", {"discovery": 9999})
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_scoperta.xml")))
    assert scanner.cadences()["discovery"] == 9999


# --------------------------------------------------------------------------- #
# Capacita' e ricadute
# --------------------------------------------------------------------------- #
def test_senza_accesso_raw_si_ricade_sulla_scansione_per_connessione(sonda):
    esecutore = EsecutoreFinto(
        leggi("nmap_porte_servizi_os.xml"),
        capacita={"available": True, "executable": "nmap-finto", "nmap_version": "7.99",
                  "raw_sockets": False, "os_detection": False,
                  "detail": "accesso raw non disponibile"},
    )
    scanner = NetworkScanner(sonda, esecutore)
    sonda.upsert_local_node("192.0.2.12", state="confirmed")
    scanner.run_stage("ports", "*")
    assert "-sT" in esecutore.chiamate[0]["arguments"]
    assert "-sS" not in esecutore.chiamate[0]["arguments"]


def test_senza_rilevamento_del_sistema_operativo_la_fase_non_e_dovuta(sonda):
    esecutore = EsecutoreFinto(
        leggi("nmap_porte_servizi_os.xml"),
        capacita={"available": True, "executable": "nmap-finto", "nmap_version": "7.99",
                  "raw_sockets": False, "os_detection": False, "detail": "senza raw"},
    )
    scanner = NetworkScanner(sonda, esecutore)
    sonda.upsert_local_node("192.0.2.12", state="confirmed", open_ports=6, has_os=1)
    sonda.record_scan("192.0.2.0/24", "discovery", "completed")
    sonda.record_scan("*", "ports", "completed")
    sonda.record_scan("*", "monitor", "completed")
    sonda.record_scan("*", "services", "completed")
    dovuta = scanner.next_due()
    assert dovuta is None or dovuta[0] != "os"


def test_nmap_assente_impedisce_la_scansione_con_messaggio_esplicito(sonda):
    esecutore = EsecutoreFinto(
        "", capacita={"available": False, "executable": None, "nmap_version": None,
                      "raw_sockets": False, "os_detection": False,
                      "detail": "nmap non installato"})
    scanner = NetworkScanner(sonda, esecutore)
    with pytest.raises(Exception) as errore:
        scanner.run_stage("discovery", "192.0.2.0/24")
    assert "nmap" in str(errore.value)


def test_il_tempo_massimo_scaduto_non_e_un_guasto(sonda):
    esecutore = EsecutoreFinto("", errore=NmapTimeout("scaduto dopo 20 secondi"))
    scanner = NetworkScanner(sonda, esecutore)
    esito = scanner.run_stage("discovery", "192.0.2.0/24")
    assert esito["status"] == "timeout"
    stato = sonda.scan_state("192.0.2.0/24", "discovery")
    assert stato["last_status"] == "timeout"


# --------------------------------------------------------------------------- #
# Approfondimento
# --------------------------------------------------------------------------- #
def test_l_approfondimento_riguarda_solo_i_nodi_incerti(sonda):
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_porte_servizi_os.xml")))
    sonda.upsert_local_node("192.0.2.12", state="confirmed", open_ports=8, has_os=1)
    sonda.upsert_local_node("192.0.2.99", state="confirmed", open_ports=1, has_os=0)
    incerti = [n["ip"] for n in scanner._uncertain_nodes()]
    assert incerti == ["192.0.2.99"]


def test_la_fase_di_approfondimento_usa_udp_e_script_mirati(sonda):
    esecutore = EsecutoreFinto(leggi("nmap_porte_servizi_os.xml"))
    scanner = NetworkScanner(sonda, esecutore)
    sonda.upsert_local_node("192.0.2.99", state="confirmed", open_ports=0, has_os=0)
    scanner.run_stage("deep", "*")
    argomenti = " ".join(esecutore.chiamate[0]["arguments"])
    assert "-sU" in argomenti
    assert "--script" in argomenti
    assert modulo_scanner.UDP_IDENTIFYING_PORTS in argomenti


# --------------------------------------------------------------------------- #
# Stato per l'interfaccia
# --------------------------------------------------------------------------- #
def test_lo_stato_riassume_perimetro_capacita_e_nodi(sonda):
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_scoperta.xml")))
    scanner.run_stage("discovery", "192.0.2.0/24")
    stato = scanner.status()
    assert [s["cidr"] for s in stato["perimeter"]] == ["192.0.2.0/24"]
    assert stato["nodes_candidate"] == 8
    assert stato["capabilities"]["nmap_version"] == "7.99"
    assert stato["states"], "lo stato delle fasi deve essere esposto"


# --------------------------------------------------------------------------- #
# Traduzione della coda locale nei tipi di record del contratto
# --------------------------------------------------------------------------- #
def test_ogni_genere_accodato_ha_un_tipo_di_record_corrispondente():
    """Senza questa traduzione i nodi finirebbero fra le annotazioni.

    E' il difetto emerso alla prima prova sul campo: la coda veniva conferita
    interamente come 'events' e l'inventario restava vuoto.
    """
    from snapprobe.agent import RECORD_TYPES, record_type_of
    from snapprobe.scanner import STAGES

    assert record_type_of("event") == "events"
    for genere in ("nodes", "ports", "os", "scripts", "monitor", "scan_runs"):
        assert record_type_of(genere) == genere
    assert record_type_of("genere-inventato") is None
    assert record_type_of("snmp") == "snmp"
    # La lettura delle interfacce web e' arrivata dopo, ed e' il difetto che questa
    # prova ha intercettato: la fase accodava record di genere "web" che il
    # conferimento non sapeva tradurre, quindi li SCARTAVA dichiarandolo nel diario.
    # Sul server la tabella delle letture restava vuota senza che nulla apparisse rotto.
    assert record_type_of("web") == "web"
    # L'enumerazione SMB (139/445) e' arrivata dopo, con la stessa forma della lettura
    # SNMP: la fase accoda record di genere "smb" che il conferimento deve saper
    # tradurre, o li scarterebbe come accadeva per "web".
    assert record_type_of("smb") == "smb"
    # La ricerca di vulnerabilita' con nmap accoda record di genere "vuln", che la
    # Threat Intelligence del server traduce in riscontri.
    assert record_type_of("vuln") == "vuln"
    assert set(RECORD_TYPES) >= {"events", "nodes", "ports", "os", "scripts", "snmp",
                                 "smb", "vuln", "monitor", "scan_runs", "web"}
    assert set(STAGES) == {"discovery", "ports", "services", "os", "deep", "monitor",
                           "snmp", "smb", "vuln", "web"}


def test_i_generi_prodotti_dallo_scanner_sono_tutti_traducibili(sonda):
    """Nessuna fase deve accodare un genere che il conferimento non sa tradurre."""
    from snapprobe.agent import record_type_of

    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_scoperta.xml")))
    scanner.run_stage("discovery", "192.0.2.0/24")
    scanner.runner = EsecutoreFinto(leggi("nmap_porte_servizi_os.xml"))
    scanner.run_stage("ports", "*")
    scanner.run_stage("monitor", "*")

    conferiti = sonda.reserve_batch("prova-generi")
    assert conferiti, "la coda non deve essere vuota"
    for record in conferiti:
        assert record_type_of(record["kind"]) is not None, (
            "genere non traducibile in coda: %s" % record["kind"]
        )


def test_un_nodo_attende_una_fase_solo_se_le_precedenti_sono_svolte(sonda):
    """Vincolo che rende sicura la priorita' alle fasi finali.

    Senza di esso un nodo appena scoperto risulta in attesa di ogni fase, e la
    pianificazione ne interrogherebbe i servizi prima di conoscerne le porte.
    """
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_scoperta.xml")))
    sonda.upsert_local_node("192.0.2.90", state="confirmed", stages_done="")

    def indirizzi(fase):
        return [n["ip"] for n in scanner.pending_nodes(fase)]

    assert indirizzi("ports") == ["192.0.2.90"]
    assert indirizzi("services") == [], "i servizi non precedono le porte"
    assert indirizzi("os") == []

    sonda.upsert_local_node("192.0.2.90", state="confirmed", stages_done="ports")
    assert indirizzi("ports") == []
    assert indirizzi("services") == ["192.0.2.90"]
    assert indirizzi("os") == []

    sonda.upsert_local_node("192.0.2.90", state="confirmed", stages_done="ports,services")
    assert indirizzi("services") == []
    assert indirizzi("os") == ["192.0.2.90"]

    # Senza fase indicata conta solo che il profilo non sia ancora conferito.
    assert [n["ip"] for n in scanner.pending_nodes()] == ["192.0.2.90"]


# --------------------------------------------------------------------------- #
# La fase dei servizi parte dalle porte gia' trovate
# --------------------------------------------------------------------------- #
def test_i_servizi_interrogano_le_porte_gia_trovate(sonda):
    """Difetto reale: la fase ripartiva dalle prime duecento porte e scadeva.

    Misurato sul campo: sedici bersagli, oltre duecento secondi di processo e
    "0 host, 0 record", perche' ogni host esauriva il proprio tempo prima di
    concludere il riconoscimento.
    """
    import json as _json

    profilo = {"ip": "192.0.2.30", "ports_index": {
        "tcp/22": {"protocol": "tcp", "port": 22, "state": "open"},
        "tcp/443": {"protocol": "tcp", "port": 443, "state": "open"},
        "tcp/8080": {"protocol": "tcp", "port": 8080, "state": "closed"},
        "udp/161": {"protocol": "udp", "port": 161, "state": "open"},
    }}
    sonda.upsert_local_node("192.0.2.30", state="confirmed", stages_done="ports",
                            profile_json=_json.dumps(profilo))
    esecutore = EsecutoreFinto(leggi("nmap_porte_servizi_os.xml"))
    scanner = NetworkScanner(sonda, esecutore)

    scanner.run_stage("services", "*")
    argomenti = esecutore.chiamate[-1]["arguments"]
    assert "-p" in argomenti, "la fase doveva interrogare le porte note: %s" % argomenti
    elenco = argomenti[argomenti.index("-p") + 1]
    # Le porte sono qualificate per protocollo: senza il prefisso nmap applicherebbe
    # lo stesso elenco a TCP e UDP. La porta SNMP entra sempre.
    assert elenco == "T:22,443,U:161", (
        "solo le porte TCP risultate aperte, piu' udp/161: %s" % elenco)
    assert "-sU" in argomenti, "udp/161 richiede la scansione UDP"
    assert "--top-ports" not in argomenti


def test_senza_porte_note_si_torna_alle_prime_porte(sonda):
    """Un bersaglio di cui non si sa nulla ha bisogno di una ricognizione."""
    sonda.upsert_local_node("192.0.2.31", state="confirmed", stages_done="ports")
    esecutore = EsecutoreFinto(leggi("nmap_porte_servizi_os.xml"))
    scanner = NetworkScanner(sonda, esecutore)

    scanner.run_stage("services", "*")
    argomenti = esecutore.chiamate[-1]["arguments"]
    elenco = argomenti[argomenti.index("-p") + 1]
    # Senza porte note si sondano le prime porte per frequenza: l'elenco e' esplicito
    # perche' --top-ports non si combina con la selezione per protocollo.
    assert elenco.startswith("T:1-") and elenco.endswith(",U:161"), elenco


def test_un_profilo_illeggibile_non_ferma_la_fase(sonda):
    sonda.upsert_local_node("192.0.2.32", state="confirmed", stages_done="ports",
                            profile_json="{non-json")
    esecutore = EsecutoreFinto(leggi("nmap_porte_servizi_os.xml"))
    scanner = NetworkScanner(sonda, esecutore)

    scanner.run_stage("services", "*")
    assert esecutore.chiamate, "la fase doveva essere svolta comunque"
    diario = " ".join(e["message"] for e in sonda.recent_events(10))
    assert "illeggibile" in diario, "il profilo illeggibile va dichiarato, non taciuto"


def test_l_esclusione_dal_perimetro_si_annota_una_volta_sola(sonda):
    """Un avviso ripetuto a ogni ciclo seppellisce il diario invece di informare."""
    sonda.upsert_local_node("10.99.0.7", state="confirmed")
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_porte_servizi_os.xml")))

    for _ in range(4):
        scanner.pending_nodes("ports")
    avvisi = [e for e in sonda.recent_events(30)
              if "non e' piu' fra quelle dichiarate" in e["message"]]
    assert len(avvisi) == 1, "l'avviso doveva comparire una volta sola: %d" % len(avvisi)


def test_un_nodo_fuori_perimetro_non_conta_fra_i_profili_in_attesa(sonda):
    """Non e' lavoro in attesa: non e' scansionabile."""
    sonda.upsert_local_node("192.0.2.40", state="confirmed")
    sonda.upsert_local_node("10.99.0.8", state="confirmed")
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_porte_servizi_os.xml")))

    indirizzi = [n["ip"] for n in scanner.pending_nodes("ports")]
    assert indirizzi == ["192.0.2.40"]


def test_il_perimetro_si_compila_una_volta_e_si_aggiorna_quando_cambia(sonda):
    """Rileggere il perimetro dal database per ogni indirizzo costava 4 ms a nodo:
    su 1752 nodi erano 7 secondi, e `status.json` superava i trenta secondi.

    La compilazione si conserva; si rifa' quando l'agente riceve una configurazione
    dal server, che e' il momento in cui il perimetro puo' essere cambiato.
    """
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_scoperta.xml")))
    prime = scanner._compiled_perimeter()
    assert prime is scanner._compiled_perimeter(), "il perimetro non era conservato"

    sonda.set_json("scan_subnets", [{"cidr": "203.0.113.0/24"}])
    assert scanner._compiled_perimeter() is prime, (
        "senza invalidazione la compilazione conservata deve valere")

    scanner.invalidate_perimeter()
    dopo = scanner._compiled_perimeter()
    assert dopo is not prime, "dopo l'invalidazione il perimetro va ricompilato"
    assert scanner._in_perimeter("203.0.113.9") is True
    assert scanner._in_perimeter("192.0.2.9") is False


def test_il_filtro_del_perimetro_non_rilegge_il_database_per_ogni_indirizzo(sonda):
    """Difetto misurato: 4 ms per indirizzo, tutti spesi in letture ripetute."""
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_scoperta.xml")))
    letture = {"n": 0}
    originale = sonda.get_json

    def contando(chiave, predefinito=None):
        if chiave == "scan_subnets":
            letture["n"] += 1
        return originale(chiave, predefinito)

    sonda.get_json = contando
    try:
        for ultimo in range(200):
            scanner._in_perimeter("192.0.2.%d" % (ultimo % 250 + 1))
    finally:
        sonda.get_json = originale
    assert letture["n"] <= 2, (
        "il perimetro e' stato riletto %d volte per 200 indirizzi" % letture["n"])


def test_una_subnet_illeggibile_nel_perimetro_viene_dichiarata(sonda):
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_scoperta.xml")))
    sonda.set_json("scan_subnets", [{"cidr": "192.0.2.0/24"}, {"cidr": "non-una-rete"}])

    assert scanner._in_perimeter("192.0.2.5") is True
    diario = " ".join(e["message"] for e in sonda.recent_events(10))
    assert "non interpretabile nel perimetro" in diario


def test_anche_l_approfondimento_e_limitato_al_perimetro(sonda):
    """Osservato dal vivo: la fase deep veniva rifiutata a ogni ciclo perche' fra i
    nodi incerti c'erano indirizzi di subnet non piu' dichiarate."""
    import json as _json

    profilo = {"ip": "10.99.0.9", "ports_index": {
        "tcp/80": {"protocol": "tcp", "port": 80, "state": "open"}}}
    sonda.upsert_local_node("10.99.0.9", state="confirmed", stages_done="ports,services,os",
                            profile_json=_json.dumps(profilo))
    esecutore = EsecutoreFinto(leggi("nmap_porte_servizi_os.xml"))
    scanner = NetworkScanner(sonda, esecutore)

    assert scanner._targets_for("deep") == []


# --------------------------------------------------------------------------- #
# SNMP: la porta entra sempre, la lettura completa solo quando risponde
# --------------------------------------------------------------------------- #
def test_gli_script_snmp_si_aggiungono_solo_se_la_porta_ha_risposto(sonda):
    """Gli script SNMP costano tempo: al primo giro la porta viene sondata, dal
    secondo -- se ha risposto -- si legge tutto."""
    import json as _json

    from snapprobe.scanner import SNMP_SCRIPTS

    sonda.upsert_local_node("192.0.2.50", state="confirmed", stages_done="ports",
                            profile_json=_json.dumps({"ip": "192.0.2.50", "ports_index": {
                                "tcp/80": {"protocol": "tcp", "port": 80, "state": "open"}}}))
    esecutore = EsecutoreFinto(leggi("nmap_porte_servizi_os.xml"))
    scanner = NetworkScanner(sonda, esecutore)

    from snapprobe.scanner import ENRICHMENT_SCRIPTS

    scanner.run_stage("services", "*")
    script = esecutore.chiamate[-1]["arguments"]
    valore = script[script.index("--script") + 1]
    # La fase dei servizi porta il banner e il set curato di arricchimento (auto-limitato
    # per porta da nmap): senza SNMP aperto non si aggiungono gli script SNMP.
    assert valore == "banner," + ENRICHMENT_SCRIPTS
    assert "ssl-cert" in valore and "rdp-ntlm-info" in valore
    assert "snmp-" not in valore, "senza la 161 aperta non si legge SNMP"

    # Ora la porta risulta aperta: la passata successiva legge tutto anche via SNMP.
    sonda.upsert_local_node("192.0.2.50", state="confirmed", stages_done="ports",
                            profile_json=_json.dumps({"ip": "192.0.2.50", "ports_index": {
                                "tcp/80": {"protocol": "tcp", "port": 80, "state": "open"},
                                "udp/161": {"protocol": "udp", "port": 161,
                                            "state": "open"}}}))
    scanner.run_stage("services", "*")
    script = esecutore.chiamate[-1]["arguments"]
    valore = script[script.index("--script") + 1]
    assert valore.startswith("banner,")
    assert "snmp-sysdescr" in valore and "snmp-interfaces" in valore
    assert valore.endswith(SNMP_SCRIPTS)


def test_nessuno_script_snmp_tenta_credenziali(sonda):
    """Un inventario non forza serrature: snmp-brute indovina le community."""
    from snapprobe.scanner import (ENRICHMENT_SCRIPTS, NSE_SCRIPTS, SMB_SCRIPTS,
                                   SNMP_SCRIPTS)

    for elenco in (SNMP_SCRIPTS, NSE_SCRIPTS, SMB_SCRIPTS, ENRICHMENT_SCRIPTS):
        assert "brute" not in elenco, "nessuno script indovina credenziali"
        assert "-set" not in elenco, "nessuno script di scrittura"
    # Il set di arricchimento e' di sola lettura: niente exploit, dos, o forzatura.
    for proibito in ("brute", "exploit", "dos", "-enum-domains"):
        assert proibito not in ENRICHMENT_SCRIPTS, proibito


def test_l_approfondimento_legge_snmp_quando_la_porta_e_aperta(sonda):
    import json as _json

    sonda.upsert_local_node("192.0.2.51", state="confirmed",
                            stages_done="ports,services,os",
                            profile_json=_json.dumps({"ip": "192.0.2.51", "ports_index": {
                                "udp/161": {"protocol": "udp", "port": 161,
                                            "state": "open"}}}))
    esecutore = EsecutoreFinto(leggi("nmap_porte_servizi_os.xml"))
    scanner = NetworkScanner(sonda, esecutore)

    scanner.run_stage("deep", "*")
    argomenti = esecutore.chiamate[-1]["arguments"]
    valore = argomenti[argomenti.index("--script") + 1]
    assert "snmp-sysdescr" in valore, "con la porta aperta si legge tutto SNMP"


# --------------------------------------------------------------------------- #
# Raggiungibilita': non si dichiara assente chi non e' stato interrogato
# --------------------------------------------------------------------------- #
def test_il_monitoraggio_parla_solo_dei_nodi_che_ha_interrogato(sonda):
    """Difetto misurato: 154 nodi su 170 risultavano assenti a ogni passata, perche'
    si marcava "non raggiungibile" ogni nodo conferito non visto nello sweep --
    compresi quelli che il compito non aveva nemmeno interrogato."""
    for indice in range(5):
        sonda.upsert_local_node("192.0.2.%d" % (60 + indice), state="confirmed",
                                conferred_at="2026-08-28 08:00:00")
    esecutore = EsecutoreFinto(leggi("nmap_scoperta.xml"))
    scanner = NetworkScanner(sonda, esecutore)

    # Un compito su due soli bersagli non deve dire nulla degli altri tre.
    esito = scanner._run_task(
        {"stage": "monitor", "target": "*", "hosts": ["192.0.2.60", "192.0.2.61"]},
        scanner.capabilities(), scanner.effort_profile())
    campioni = esito["records"].get("monitor") or []
    indirizzi = {c["ip"] for c in campioni}
    assert indirizzi <= {"192.0.2.60", "192.0.2.61"}, (
        "il monitoraggio ha parlato di nodi non interrogati: %s" % indirizzi)


def test_prima_di_dichiarare_assente_si_prova_sulle_porte_note(sonda):
    """Su una rete che blocca ICMP un nodo vivo non risponde allo sweep: prima di
    dichiararlo assente si riprova sulle sue porte."""
    import json as _json

    sonda.upsert_local_node("192.0.2.70", state="confirmed",
                            conferred_at="2026-08-28 08:00:00",
                            profile_json=_json.dumps({"ip": "192.0.2.70", "ports_index": {
                                "tcp/445": {"protocol": "tcp", "port": 445,
                                            "state": "open"}}}))

    class EsecutoreDueFasi:
        """Sweep senza risposte, seconda verifica con una porta che risponde."""

        def __init__(self):
            self.chiamate = []

        def detect_capabilities(self, force=False):
            return {"available": True, "raw_sockets": True, "os_detection": True,
                    "nmap_version": "7.99", "detail": "esecutore di prova"}

        def run(self, arguments, targets, timeout=None, label=None):
            self.chiamate.append({"arguments": list(arguments), "targets": list(targets)})
            if "-sn" in arguments:
                return leggi("nmap_host_fantasma.xml")   # nessun host restituito
            return leggi("nmap_porte_servizi_os.xml")    # host con porte

    esecutore = EsecutoreDueFasi()
    scanner = NetworkScanner(sonda, esecutore)
    scanner.store.set_json("scan_subnets", [{"cidr": "192.0.2.0/24"}])

    esito = scanner._run_task(
        {"stage": "monitor", "target": "*", "hosts": ["192.0.2.70"]},
        scanner.capabilities(), scanner.effort_profile())

    assert len(esecutore.chiamate) == 2, "il secondo tentativo non e' stato eseguito"
    secondo = esecutore.chiamate[1]["arguments"]
    assert "-Pn" in secondo, "il secondo tentativo non deve dipendere dal ping"
    assert "445" in secondo[secondo.index("-p") + 1], (
        "si riprova sulle porte note del nodo: %s" % secondo)
    diario = " ".join(e["message"] for e in sonda.recent_events(10))
    assert "sono vivi sulle proprie porte" in diario


def test_lo_sweep_usa_le_porte_che_i_nodi_hanno_aperte(sonda):
    """Tre porte fisse non bastano: un nodo con sole 135, 139 e 445 non risponde a un
    SYN su 443, 80 o 22, e su una rete che blocca ICMP finirebbe dato per assente."""
    import json as _json

    sonda.upsert_local_node("192.0.2.80", state="confirmed",
                            conferred_at="2026-08-28 08:00:00",
                            profile_json=_json.dumps({"ip": "192.0.2.80", "ports_index": {
                                "tcp/445": {"protocol": "tcp", "port": 445, "state": "open"},
                                "tcp/139": {"protocol": "tcp", "port": 139, "state": "open"}}}))
    esecutore = EsecutoreFinto(leggi("nmap_scoperta.xml"))
    scanner = NetworkScanner(sonda, esecutore)

    scanner.run_stage("monitor", "*")
    sweep = " ".join(esecutore.chiamate[0]["arguments"])
    assert "-PS139,445" in sweep or "-PS445,139" in sweep, sweep
    argomenti = sweep
    assert "-PA" in argomenti, "l'ACK passa filtri che scartano i SYN"
    assert "-PE" in argomenti, "l'echo resta, dove funziona"


def test_senza_porte_note_lo_sweep_usa_un_elenco_di_riserva(sonda):
    from snapprobe.scanner import MONITOR_FALLBACK_PORTS

    sonda.upsert_local_node("192.0.2.81", state="confirmed",
                            conferred_at="2026-08-28 08:00:00")
    esecutore = EsecutoreFinto(leggi("nmap_scoperta.xml"))
    scanner = NetworkScanner(sonda, esecutore)

    scanner.run_stage("monitor", "*")
    sweep = " ".join(esecutore.chiamate[0]["arguments"])
    assert "-PS" + MONITOR_FALLBACK_PORTS in sweep, sweep


def test_una_porta_filtrata_non_prova_la_presenza(sonda):
    """`filtered` e' il silenzio di un firewall: non e' una risposta dell'host."""
    from snapprobe.scanner import ALIVE_PORT_STATES

    assert "open" in ALIVE_PORT_STATES and "closed" in ALIVE_PORT_STATES
    assert "filtered" not in ALIVE_PORT_STATES


def test_il_monitoraggio_ruota_sui_nodi_meno_recenti(sonda):
    """Senza rotazione ogni passata prendeva gli stessi primi nodi: i restanti non
    venivano mai riverificati e restavano dichiarati assenti per sempre."""
    esecutore = EsecutoreFinto(leggi("nmap_scoperta.xml"))
    scanner = NetworkScanner(sonda, esecutore)
    per_passata = scanner.effort_profile()["hosts_per_task"]

    # Due passate esatte: cosi' la copertura completa e' verificabile senza
    # ambiguita' sulle ripetizioni.
    for indice in range(per_passata * 2):
        sonda.upsert_local_node("192.0.2.%d" % (100 + indice), state="confirmed",
                                conferred_at="2026-08-28 08:00:00")

    prima = scanner._targets_for("monitor")
    assert len(prima) == per_passata

    # I nodi verificati vengono annotati: la passata successiva prende gli altri.
    sonda.mark_monitored(prima)
    seconda = scanner._targets_for("monitor")
    assert not (set(prima) & set(seconda)), (
        "la seconda passata ha ripreso nodi appena verificati: %s"
        % sorted(set(prima) & set(seconda)))
    assert len(set(prima) | set(seconda)) == per_passata * 2, (
        "in due passate l'inventario deve essere coperto tutto")

    # Coperti tutti, si ricomincia dai piu' vecchi: nessun nodo resta indietro.
    sonda.mark_monitored(seconda)
    terza = scanner._targets_for("monitor")
    assert set(terza) == set(prima), (
        "la rotazione deve tornare ai nodi verificati per primi")


def test_un_nodo_mai_verificato_ha_la_precedenza(sonda):
    sonda.upsert_local_node("192.0.2.200", state="confirmed",
                            conferred_at="2026-08-28 08:00:00")
    sonda.mark_monitored(["192.0.2.200"])
    sonda.upsert_local_node("192.0.2.201", state="confirmed",
                            conferred_at="2026-08-28 08:00:00")

    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_scoperta.xml")))
    bersagli = scanner._targets_for("monitor")
    assert bersagli[0] == "192.0.2.201", (
        "il nodo mai verificato deve venire prima: %s" % bersagli)
