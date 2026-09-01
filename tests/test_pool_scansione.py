"""
snap - Test del pool di scansione parallelo.

Verificano le tre condizioni che rendono i thread innocui l'uno per l'altro:

  1. bersagli disgiunti: nessun indirizzo compare in due compiti dello stesso
     ciclo, e nessun indirizzo viene esaminato da due thread insieme;
  2. prenotazione atomica: la stessa chiave non puo' essere ottenuta due volte,
     nemmeno da thread in corsa fra loro, e scade se nessuno la rilascia;
  3. coordinamento a valle: il conferimento avviene una volta sola, nel thread
     coordinatore, e non viene ripetuto dai compiti.

Piu' il resto del contratto: il limite di quattro esecuzioni contemporanee, i
profili di sforzo, l'isolamento degli errori e l'interruzione su sospensione.

Nota: nessuna esecuzione reale di nmap: l'esecutore e' sostituito da un
esecutore finto che registra le chiamate e simula la durata.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from snapprobe.nmap_runner import NmapError, NmapTimeout
from snapprobe.scanner import EFFORT_PROFILES, MAX_WORKERS, NetworkScanner

FIXTURES = Path(__file__).parent / "fixtures"
PERIMETRO = [{"cidr": "192.0.2.0/24", "label": "Rete di prova"}]


class EsecutoreConcorrente:
    """Esecutore finto che misura la concorrenza effettiva.

    Registra ogni invocazione, quante ne sono in corso nello stesso istante e il
    massimo raggiunto: e' il modo per verificare che il pool rispetti il limite
    senza dipendere da nmap.
    """

    def __init__(self, xml: str, durata: float = 0.15, errore: Exception = None,
                 errore_su: str = None):
        self.xml = xml
        self.durata = durata
        self.errore = errore
        self.errore_su = errore_su
        self.chiamate = []
        self.bersagli_visti = []
        self._in_corso = 0
        self._massimo = 0
        self._lock = threading.Lock()

    def detect_capabilities(self, force: bool = False) -> dict:
        return {"available": True, "executable": "nmap-finto", "nmap_version": "7.99",
                "raw_sockets": True, "os_detection": True, "detail": "esecutore di prova"}

    def running_count(self) -> int:
        with self._lock:
            return self._in_corso

    @property
    def concorrenza_massima(self) -> int:
        with self._lock:
            return self._massimo

    def run(self, arguments, targets, timeout=None, label=None) -> str:
        # `label` descrive la fase in corso per l'indicatore: qui non serve,
        # ma la firma deve corrispondere a quella del runner vero.
        with self._lock:
            self._in_corso += 1
            self._massimo = max(self._massimo, self._in_corso)
            self.chiamate.append({"arguments": list(arguments), "targets": list(targets)})
            self.bersagli_visti.append(tuple(targets))
        try:
            time.sleep(self.durata)
            if self.errore is not None and (
                    self.errore_su is None or self.errore_su in targets):
                raise self.errore
            return self.xml
        finally:
            with self._lock:
                self._in_corso -= 1


def leggi(nome: str) -> str:
    return (FIXTURES / nome).read_text(encoding="utf-8")


@pytest.fixture()
def sonda(probe_store):
    probe_store.set_json("scan_subnets", PERIMETRO)
    return probe_store


def con_nodi(sonda, quanti: int, stato: str = "candidate"):
    """Popola l'archivio locale con nodi da ispezionare."""
    indirizzi = ["192.0.2.%d" % (i + 1) for i in range(quanti)]
    for ip in indirizzi:
        sonda.upsert_local_node(ip, state=stato)
    return indirizzi


# --------------------------------------------------------------------------- #
# Profili di sforzo
# --------------------------------------------------------------------------- #
def test_i_tre_profili_esistono_e_sono_ordinati():
    assert set(EFFORT_PROFILES) == {"min", "med", "max"}
    assert EFFORT_PROFILES["min"]["workers"] == 1
    assert EFFORT_PROFILES["med"]["workers"] == 2
    assert EFFORT_PROFILES["max"]["workers"] == 4
    for chiave in ("timing", "top_ports", "version_intensity", "host_timeout",
                   "hosts_per_task", "udp_ports", "label"):
        for nome, profilo in EFFORT_PROFILES.items():
            assert chiave in profilo, "il profilo %s non dichiara %s" % (nome, chiave)
    # Lo sforzo crescente non deve mai diminuire il lavoro richiesto.
    assert (EFFORT_PROFILES["min"]["top_ports"] < EFFORT_PROFILES["med"]["top_ports"]
            < EFFORT_PROFILES["max"]["top_ports"])


def test_nessun_profilo_supera_il_limite_di_thread():
    for nome, profilo in EFFORT_PROFILES.items():
        assert profilo["workers"] <= MAX_WORKERS, "il profilo %s chiede troppi thread" % nome


def test_uno_sforzo_non_riconosciuto_ricade_sul_medio_dichiarandolo(sonda):
    scanner = NetworkScanner(sonda, EsecutoreConcorrente(leggi("nmap_scoperta.xml")))
    sonda.set_setting("scan_effort", "turbo")
    assert scanner.effort() == "med"
    diario = " ".join(e["message"] for e in sonda.recent_events(5))
    assert "turbo" in diario


def test_lo_sforzo_governa_gli_argomenti_di_nmap(sonda):
    esecutore = EsecutoreConcorrente(leggi("nmap_porte_servizi_os.xml"))
    scanner = NetworkScanner(sonda, esecutore)
    con_nodi(sonda, 2, "confirmed")

    sonda.set_setting("scan_effort", "min")
    scanner.run_stage("ports", "*")
    minimo = " ".join(esecutore.chiamate[-1]["arguments"])

    sonda.set_setting("scan_effort", "max")
    scanner.run_stage("ports", "*")
    massimo = " ".join(esecutore.chiamate[-1]["arguments"])

    assert "-T2" in minimo and "-T4" in massimo
    assert "--top-ports 100" in minimo and "--top-ports 1000" in massimo


def test_lo_sforzo_arriva_dalla_configurazione_del_server(probe_store):
    from snapprobe.agent import ProbeAgent

    agente = ProbeAgent(probe_store, "1.0.0")
    agente._apply_server_config({"subnets": PERIMETRO, "scan_effort": "max"})
    assert probe_store.get_setting("scan_effort") == "max"


# --------------------------------------------------------------------------- #
# Prenotazione atomica
# --------------------------------------------------------------------------- #
def test_la_stessa_chiave_non_puo_essere_prenotata_due_volte(sonda):
    prima = sonda.claim_keys(["node:192.0.2.1"], "uno", "ports")
    seconda = sonda.claim_keys(["node:192.0.2.1"], "due", "ports")
    assert prima == ["node:192.0.2.1"]
    assert seconda == []


def test_la_prenotazione_regge_la_corsa_fra_molti_thread(sonda):
    chiavi = ["node:192.0.2.%d" % i for i in range(1, 41)]
    ottenute = {}
    barriera = threading.Barrier(8)

    def lavora(numero):
        barriera.wait()
        ottenute[numero] = sonda.claim_keys(chiavi, "thread-%d" % numero, "ports")

    fili = [threading.Thread(target=lavora, args=(i,)) for i in range(8)]
    for filo in fili:
        filo.start()
    for filo in fili:
        filo.join()

    tutte = [c for elenco in ottenute.values() for c in elenco]
    assert len(tutte) == len(set(tutte)), "una chiave e' stata assegnata due volte"
    assert set(tutte) == set(chiavi)


def test_una_prenotazione_scaduta_viene_liberata(sonda):
    import sqlite3

    sonda.claim_keys(["node:192.0.2.7"], "morto", "ports")
    # Si retrodata la prenotazione, come se il thread fosse morto un'ora prima.
    connessione = sqlite3.connect(str(sonda.path))
    connessione.execute("UPDATE scan_claims SET claimed_at = datetime('now', '-2 hours')")
    connessione.commit()
    connessione.close()

    liberate = sonda.purge_stale_claims(1800)
    assert liberate == 1
    assert sonda.claim_keys(["node:192.0.2.7"], "nuovo", "ports") == ["node:192.0.2.7"]


def test_le_prenotazioni_vengono_rilasciate_alla_fine_del_ciclo(sonda):
    esecutore = EsecutoreConcorrente(leggi("nmap_porte_servizi_os.xml"), durata=0.02)
    scanner = NetworkScanner(sonda, esecutore)
    con_nodi(sonda, 6)
    sonda.set_setting("scan_effort", "max")

    assert scanner.run_cycle() is not None
    assert sonda.active_claims() == [], "nessuna prenotazione deve sopravvivere al ciclo"


def test_le_prenotazioni_si_rilasciano_anche_se_un_compito_fallisce(sonda):
    esecutore = EsecutoreConcorrente(leggi("nmap_porte_servizi_os.xml"), durata=0.02,
                                     errore=NmapError("guasto simulato"))
    scanner = NetworkScanner(sonda, esecutore)
    con_nodi(sonda, 6)
    sonda.set_setting("scan_effort", "max")

    scanner.run_cycle()
    assert sonda.active_claims() == []


# --------------------------------------------------------------------------- #
# Parallelismo e disgiunzione
# --------------------------------------------------------------------------- #
def test_il_ciclo_esegue_piu_compiti_in_parallelo(sonda):
    esecutore = EsecutoreConcorrente(leggi("nmap_porte_servizi_os.xml"), durata=0.3)
    scanner = NetworkScanner(sonda, esecutore)
    sonda.set_setting("scan_effort", "max")
    con_nodi(sonda, EFFORT_PROFILES["max"]["hosts_per_task"] * 4)

    esito = scanner.run_cycle()
    assert esito is not None
    assert esito["tasks"] >= 2, "il ciclo deve comporre piu' di un compito"
    assert esecutore.concorrenza_massima >= 2, (
        "le scansioni non sono state eseguite in parallelo (massimo %d)"
        % esecutore.concorrenza_massima
    )


def test_il_parallelismo_non_supera_mai_il_limite(sonda):
    esecutore = EsecutoreConcorrente(leggi("nmap_porte_servizi_os.xml"), durata=0.25)
    scanner = NetworkScanner(sonda, esecutore)
    sonda.set_setting("scan_effort", "max")
    con_nodi(sonda, EFFORT_PROFILES["max"]["hosts_per_task"] * 6)

    scanner.run_cycle()
    assert esecutore.concorrenza_massima <= MAX_WORKERS, (
        "superato il limite di %d esecuzioni contemporanee: %d"
        % (MAX_WORKERS, esecutore.concorrenza_massima)
    )


def test_con_sforzo_minimo_si_esegue_una_scansione_per_volta(sonda):
    esecutore = EsecutoreConcorrente(leggi("nmap_porte_servizi_os.xml"), durata=0.15)
    scanner = NetworkScanner(sonda, esecutore)
    sonda.set_setting("scan_effort", "min")
    con_nodi(sonda, 40)

    scanner.run_cycle()
    assert esecutore.concorrenza_massima == 1


def test_nessun_indirizzo_compare_in_due_compiti_dello_stesso_ciclo(sonda):
    scanner = NetworkScanner(sonda, EsecutoreConcorrente(leggi("nmap_porte_servizi_os.xml")))
    sonda.set_setting("scan_effort", "max")
    con_nodi(sonda, 60)

    compiti = scanner.plan_tasks()
    visti = []
    for compito in compiti:
        visti.extend(compito["hosts"])
    assert len(visti) == len(set(visti)), "un indirizzo e' stato assegnato a due compiti"


def test_i_bersagli_effettivamente_scansionati_sono_disgiunti(sonda):
    esecutore = EsecutoreConcorrente(leggi("nmap_porte_servizi_os.xml"), durata=0.05)
    scanner = NetworkScanner(sonda, esecutore)
    sonda.set_setting("scan_effort", "max")
    con_nodi(sonda, 50)

    scanner.run_cycle()
    tutti = [b for gruppo in esecutore.bersagli_visti for b in gruppo]
    assert len(tutti) == len(set(tutti)), (
        "lo stesso indirizzo e' stato scansionato da due compiti"
    )


def test_una_subnet_per_compito_nella_scoperta(sonda):
    sonda.set_json("scan_subnets", [{"cidr": "192.0.2.0/25"}, {"cidr": "192.0.2.128/25"}])
    scanner = NetworkScanner(sonda, EsecutoreConcorrente(leggi("nmap_scoperta.xml")))
    sonda.set_setting("scan_effort", "max")

    compiti = [c for c in scanner.plan_tasks() if c["stage"] == "discovery"]
    assert len(compiti) == 2
    assert {c["target"] for c in compiti} == {"192.0.2.0/25", "192.0.2.128/25"}
    assert all(len(c["hosts"]) == 1 for c in compiti)


# --------------------------------------------------------------------------- #
# Coordinamento a valle
# --------------------------------------------------------------------------- #
def test_il_conferimento_avviene_una_sola_volta_nel_coordinatore(sonda, monkeypatch):
    esecutore = EsecutoreConcorrente(leggi("nmap_porte_servizi_os.xml"), durata=0.05)
    scanner = NetworkScanner(sonda, esecutore)
    sonda.set_setting("scan_effort", "max")
    con_nodi(sonda, 40)

    chiamate = []
    originale = scanner._confer_complete_profiles

    def contato():
        chiamate.append(threading.current_thread().name)
        return originale()

    monkeypatch.setattr(scanner, "_confer_complete_profiles", contato)
    scanner.run_cycle()

    assert len(chiamate) == 1, "il conferimento e' stato eseguito %d volte" % len(chiamate)
    assert not chiamate[0].startswith("snap-scan"), (
        "il conferimento non deve avvenire in un thread di scansione"
    )


def test_i_compiti_non_conferiscono_da_soli(sonda):
    """L'ispezione accumula nel profilo e non produce record di nodo."""
    esecutore = EsecutoreConcorrente(leggi("nmap_porte_servizi_os.xml"), durata=0.02)
    scanner = NetworkScanner(sonda, esecutore)
    con_nodi(sonda, 3, "confirmed")

    esito = scanner._run_task({"stage": "ports", "target": "*",
                               "hosts": ["192.0.2.1", "192.0.2.2", "192.0.2.3"]},
                              esecutore.detect_capabilities(), scanner.effort_profile())
    assert "nodes" not in esito["records"]


def test_il_ciclo_conferisce_i_profili_completati_da_thread_diversi(sonda):
    """Le prove raccolte in parallelo si ricompongono in dispositivi interi."""
    esecutore = EsecutoreConcorrente(leggi("nmap_porte_servizi_os.xml"), durata=0.02)
    scanner = NetworkScanner(sonda, esecutore)
    sonda.set_setting("scan_effort", "max")
    indirizzi = ["192.0.2.1", "192.0.2.12", "192.0.2.18"]
    for ip in indirizzi:
        sonda.upsert_local_node(ip, state="confirmed")

    conferiti = []
    for _ in range(6):
        esito = scanner.run_cycle()
        if esito is None:
            break
        conferiti.append(esito["conferred"])
        if sum(conferiti):
            break

    assert sum(conferiti) > 0, "nessun dispositivo conferito dopo i cicli di ispezione"
    locali = sonda.local_nodes("confirmed")
    assert any(n["conferred_at"] for n in locali)


# --------------------------------------------------------------------------- #
# Robustezza
# --------------------------------------------------------------------------- #
def test_un_compito_che_fallisce_non_ferma_gli_altri(sonda):
    esecutore = EsecutoreConcorrente(leggi("nmap_porte_servizi_os.xml"), durata=0.05,
                                     errore=NmapError("guasto simulato"),
                                     errore_su="192.0.2.1")
    scanner = NetworkScanner(sonda, esecutore)
    sonda.set_setting("scan_effort", "max")
    con_nodi(sonda, 40)

    esito = scanner.run_cycle()
    assert esito is not None
    stati = {r["status"] for r in esito["results"]}
    assert "failed" in stati, "il guasto simulato non e' stato riportato"
    assert stati - {"failed"}, "gli altri compiti devono avere concluso"


def test_un_tempo_massimo_scaduto_non_ferma_il_ciclo(sonda):
    esecutore = EsecutoreConcorrente(leggi("nmap_porte_servizi_os.xml"), durata=0.02,
                                     errore=NmapTimeout("scaduto"))
    scanner = NetworkScanner(sonda, esecutore)
    sonda.set_setting("scan_effort", "med")
    con_nodi(sonda, 20)

    esito = scanner.run_cycle()
    assert esito is not None
    assert all(r["status"] in ("timeout", "failed", "completed", "skipped")
               for r in esito["results"])


def test_un_errore_inatteso_in_un_compito_viene_isolato(sonda, monkeypatch):
    esecutore = EsecutoreConcorrente(leggi("nmap_porte_servizi_os.xml"), durata=0.02)
    scanner = NetworkScanner(sonda, esecutore)
    sonda.set_setting("scan_effort", "med")
    con_nodi(sonda, 20)

    def esplode(*_argomenti, **_chiavi):
        raise RuntimeError("errore inatteso")

    monkeypatch.setattr(scanner, "_run_task", esplode)
    esito = scanner.run_cycle()
    assert esito is not None
    assert all(r["status"] == "error" for r in esito["results"])
    assert sonda.active_claims() == []
    diario = " ".join(e["message"] for e in sonda.recent_events(10))
    assert "inatteso" in diario


def test_a_scansione_sospesa_il_ciclo_non_parte(sonda):
    esecutore = EsecutoreConcorrente(leggi("nmap_porte_servizi_os.xml"))
    scanner = NetworkScanner(sonda, esecutore)
    con_nodi(sonda, 10)
    sonda.set_setting("scan_paused", "1")

    assert scanner.run_cycle() is None
    assert esecutore.chiamate == []
    assert sonda.active_claims() == []


def test_lo_stato_dichiara_sforzo_thread_e_prenotazioni(sonda):
    scanner = NetworkScanner(sonda, EsecutoreConcorrente(leggi("nmap_scoperta.xml")))
    sonda.set_setting("scan_effort", "max")
    stato = scanner.status()
    assert stato["effort"] == "max"
    assert stato["workers"] == 4
    assert stato["max_workers"] == MAX_WORKERS
    assert stato["effort_label"]
    assert stato["active_claims"] == 0


# --------------------------------------------------------------------------- #
# Interruzione delle esecuzioni in corso
# --------------------------------------------------------------------------- #
def test_l_esecutore_reale_registra_e_ferma_i_processi():
    """stop_all deve poter terminare le esecuzioni in corso."""
    from snapprobe.nmap_runner import NmapAborted, NmapRunner

    runner = NmapRunner()
    assert runner.running_count() == 0
    runner.stop_all()
    with pytest.raises(NmapAborted):
        runner.run(["-sn"], ["127.0.0.1"])
    runner.resume()
    assert runner.running_count() == 0


def test_il_rilevamento_delle_capacita_avviene_una_volta_sola_con_piu_thread():
    """Il lock del rilevamento evita verifiche ripetute e concorrenti."""
    from snapprobe.nmap_runner import NmapRunner

    runner = NmapRunner()
    conteggio = {"chiamate": 0}
    reale = runner.version

    def contato():
        conteggio["chiamate"] += 1
        return reale()

    runner.version = contato
    esiti = []
    barriera = threading.Barrier(4)

    def lavora():
        barriera.wait()
        esiti.append(runner.detect_capabilities())

    fili = [threading.Thread(target=lavora) for _ in range(4)]
    for filo in fili:
        filo.start()
    for filo in fili:
        filo.join()

    assert len(esiti) == 4
    assert all(e == esiti[0] for e in esiti), "i thread hanno visto capacita' diverse"
    if esiti[0]["available"]:
        assert conteggio["chiamate"] == 1, (
            "il rilevamento e' stato eseguito %d volte" % conteggio["chiamate"])


# --------------------------------------------------------------------------- #
# Prenotazioni orfane: lo stallo trovato in esercizio
# --------------------------------------------------------------------------- #
def test_un_ciclo_senza_compiti_prenotabili_lo_dichiara(sonda):
    """Difetto reale: la sonda restava ferma mezz'ora in silenzio.

    Un processo terminato mentre un ciclo era in corso lasciava le proprie
    prenotazioni in banca dati; i cicli successivi non riuscivano a prenotare
    nulla e restituivano None senza dire niente, mentre lo stato dichiarava
    attivita'.
    """
    esecutore = EsecutoreConcorrente(leggi("nmap_porte_servizi_os.xml"), durata=0.02)
    scanner = NetworkScanner(sonda, esecutore)
    indirizzi = con_nodi(sonda, 10)
    # La scoperta non e' scaduta: restano solo i compiti sui nodi.
    sonda.record_scan("192.0.2.0/24", "discovery", "completed")
    # Un altro proprietario tiene tutti i bersagli.
    sonda.claim_keys(["node:%s" % ip for ip in indirizzi], "processo-morto", "ports")

    assert scanner.run_cycle() is None
    assert esecutore.chiamate == []
    diario = " ".join(e["message"] for e in sonda.recent_events(10))
    assert "prenotati" in diario, "lo stallo deve essere annotato"


def test_le_prenotazioni_orfane_non_bloccano_la_scoperta(sonda):
    """La scoperta ha un posto garantito: non la ferma un bersaglio prenotato."""
    esecutore = EsecutoreConcorrente(leggi("nmap_scoperta.xml"), durata=0.02)
    scanner = NetworkScanner(sonda, esecutore)
    indirizzi = con_nodi(sonda, 10)
    sonda.claim_keys(["node:%s" % ip for ip in indirizzi], "processo-morto", "ports")

    esito = scanner.run_cycle()
    assert esito is not None
    assert any(r["stage"] == "discovery" for r in esito["results"])


def test_l_avvio_dell_agente_libera_le_prenotazioni_orfane(probe_store):
    """Un solo processo per archivio: all'avvio nessuna prenotazione e' legittima."""
    from snapprobe.agent import ProbeAgent

    probe_store.claim_keys(["node:10.0.0.1", "node:10.0.0.2"], "processo-morto", "ports")
    assert len(probe_store.active_claims()) == 2

    agente = ProbeAgent(probe_store, "1.0.0")
    agente.start()
    try:
        assert probe_store.active_claims() == [], "le prenotazioni orfane non sono state liberate"
        diario = " ".join(e["message"] for e in probe_store.recent_events(5))
        assert "processo precedente" in diario
    finally:
        agente.stop()


def test_lo_stato_non_dichiara_attivita_senza_esecuzioni(sonda):
    """L'attivita' vera e' il numero di esecuzioni di nmap, non le prenotazioni."""
    scanner = NetworkScanner(sonda, EsecutoreConcorrente(leggi("nmap_scoperta.xml")))
    sonda.claim_keys(["node:192.0.2.5"], "processo-morto", "ports")
    stato = scanner.status()
    assert stato["running_scans"] == 0
    assert stato["active_claims"] == 1
