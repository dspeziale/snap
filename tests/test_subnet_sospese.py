# -----------------------------------------------------------------
# test_subnet_sospese.py — una subnet sospesa non viene contattata, da nessun cammino
# Autore: Daniele Speziale
# Data creazione: 2026-09-14
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap - Sospendere una subnet significa NON CONTATTARLA. Verificato cammino per cammino.

La promessa e' semplice da enunciare e facile da rompere: sospendo una subnet, faccio
ripartire le scansioni, e quella subnet non riceve un pacchetto. E' facile da rompere
perche' i cammini che escono dalla sonda sono piu' di uno, e non passano tutti dallo
stesso punto:

| Cammino | Chi lo ferma |
|---|---|
| pianificazione delle fasi | `plan_tasks` filtra con `_within_perimeter_only` |
| esecuzione di un compito | `_run_task` verifica OGNI bersaglio e solleva |
| ricognizione senza fili | legge le reti da `scanner.perimeter()` |
| scoperta SNMP | `snmp_scoperta.candidati` (corretto qui) |
| lettura SNMP degli apparati | `snmp_raccolta.raccogli` (corretto qui) |

I DUE CAMMINI SNMP ERANO APERTI, e in silenzio. Non passano da nmap, quindi non
incontravano il guardiano di `_run_task`: pescavano dai nodi gia' in archivio e da un
elenco di apparati conservato nelle impostazioni -- due insiemi che sopravvivono alla
sospensione, e devono sopravvivere, perche' sospendere non cancella. Il risultato era
che una subnet sospesa continuava a ricevere GET di sysDescr.

L'ultima prova di questo file e' quella che conta davvero: si registra OGNI bersaglio
che uscirebbe dalla sonda, in un ciclo completo, e non ne deve comparire uno solo
della subnet sospesa.

remarks: Autore: Daniele Speziale - Data: 2026-09-14
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json

import pytest

ATTIVA = "10.20.10.0/24"
SOSPESA = "10.58.7.0/24"


def _nodo(store, ip: str, porte=(80,), stato: str = "confirmed") -> None:
    """Un nodo confermato con porte aperte note, come dopo una scansione vera."""
    indice = {}
    for porta in porte:
        protocollo = "udp" if porta == 161 else "tcp"
        indice["%s/%d" % (protocollo, porta)] = {
            "protocol": protocollo, "port": porta, "state": "open"}
    store.upsert_local_node(
        ip, state=stato, stages_done="ports,services,os",
        conferred_at="2026-09-01 00:00:00",
        profile_json=json.dumps({"ip": ip, "ports_index": indice}))


@pytest.fixture()
def sonda(probe_store):
    """Due subnet nel perimetro e nodi in entrambe: poi una viene sospesa.

    I nodi della subnet sospesa RESTANO in archivio, ed e' il punto: sospendere non
    cancella, quindi ogni cammino che pesca dall'archivio deve filtrare da se'.
    """
    from snapprobe.scanner import NetworkScanner

    probe_store.set_json("scan_subnets", [{"cidr": ATTIVA, "hosts": 254},
                                          {"cidr": SOSPESA, "hosts": 254}])
    for ip in ("10.20.10.5", "10.20.10.6"):
        _nodo(probe_store, ip, porte=(80, 161, 445))
    for ip in ("10.58.7.5", "10.58.7.6", "10.58.7.7"):
        _nodo(probe_store, ip, porte=(80, 161, 445))

    scanner = NetworkScanner(probe_store, None, "prova")

    # La sospensione, come la fa il server: la subnet esce dal perimetro consegnato.
    probe_store.set_json("scan_subnets", [{"cidr": ATTIVA, "hosts": 254}])
    scanner.invalidate_perimeter()
    return scanner


def _sospesi(bersagli) -> list:
    return [b for b in bersagli if str(b).startswith("10.58.7.")]


# --------------------------------------------------------------------------- #
# La pianificazione
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("fase", ["discovery", "ports", "services", "os", "deep",
                                  "monitor", "snmp", "smb", "vuln", "web"])
def test_nessuna_fase_pianifica_un_bersaglio_sospeso(sonda, fase):
    """Una fase per volta, tutte quelle che esistono: se domani se ne aggiunge una e
    non passa dal filtro, questo elenco la lascia scoperta -- per questo c'e' anche
    la prova che l'elenco sia completo."""
    # Niente `hasattr`: se il metodo cambia nome, questa prova deve ROMPERSI, non
    # passare a vuoto. La prima stesura lo aveva, e passava senza provare niente.
    bersagli = sonda._targets_for(fase) or []
    assert not _sospesi(bersagli), (
        "la fase %s ha pianificato un bersaglio in una subnet sospesa: %s"
        % (fase, _sospesi(bersagli)))


def test_l_elenco_delle_fasi_provate_e_completo():
    """La prova sopra vale quanto il suo elenco: se una fase nuova non compare qui,
    nessuno se ne accorge. Si confronta con le cadenze dichiarate dallo scanner."""
    from snapprobe.scanner import DEFAULT_CADENCES

    provate = {"discovery", "ports", "services", "os", "deep", "monitor",
               "snmp", "smb", "vuln", "web"}
    # `raffica` non e' una fase a bersaglio proprio (copre ports+services+os in un
    # processo solo) e `presence` ha un cammino suo, provato piu' sotto.
    dichiarate = set(DEFAULT_CADENCES) - {"raffica", "presence"}

    assert dichiarate <= provate, (
        "fasi non coperte dalla prova sulle subnet sospese: %s"
        % sorted(dichiarate - provate))


def test_i_nodi_sospesi_restano_in_inventario(sonda, probe_store):
    """Sospendere non cancella: e' la meta' che rende difficile l'altra meta'."""
    ip = {n["ip"] for n in probe_store.local_nodes()}

    assert "10.58.7.5" in ip
    assert "10.20.10.5" in ip


# --------------------------------------------------------------------------- #
# Il guardiano finale
# --------------------------------------------------------------------------- #
def test_un_compito_su_una_subnet_sospesa_viene_rifiutato(sonda):
    """Se un compito arrivasse comunque -- un comando dal server, una coda vecchia,
    un difetto futuro nel pianificatore -- l'ultima barriera lo ferma PRIMA di
    chiamare nmap."""
    from snapprobe.scanner import PerimeterViolation

    with pytest.raises(PerimeterViolation):
        sonda._run_task({"stage": "ports", "target": "*", "hosts": ["10.58.7.5"]},
                        {"raw_sockets": True}, sonda.effort_profile())


def test_basta_un_bersaglio_fuori_perimetro_a_fermare_il_compito(sonda):
    """Si verificano TUTTI i bersagli, non il primo: un compito misto non deve
    passare per i nodi leciti che contiene."""
    from snapprobe.scanner import PerimeterViolation

    with pytest.raises(PerimeterViolation):
        sonda._run_task({"stage": "ports", "target": "*",
                         "hosts": ["10.20.10.5", "10.58.7.5"]},
                        {"raw_sockets": True}, sonda.effort_profile())


def test_senza_perimetro_non_si_scansiona_niente(probe_store):
    """Perimetro vuoto significa NESSUNA scansione, non tutte: e' la differenza fra
    una sonda che tace e una sonda che scansiona il mondo."""
    from snapprobe.scanner import NetworkScanner, PerimeterViolation

    probe_store.set_json("scan_subnets", [])
    scanner = NetworkScanner(probe_store, None, "prova")

    with pytest.raises(PerimeterViolation):
        scanner._run_task({"stage": "ports", "target": "*", "hosts": ["10.20.10.5"]},
                          {"raw_sockets": True}, scanner.effort_profile())


# --------------------------------------------------------------------------- #
# I due cammini SNMP: quelli che erano aperti
# --------------------------------------------------------------------------- #
def test_la_scoperta_snmp_non_prova_una_subnet_sospesa(sonda, probe_store):
    """Pescava da `local_nodes("confirmed")`, che contiene ancora i nodi sospesi."""
    from snapprobe import snmp_scoperta

    candidati = snmp_scoperta.candidati(sonda)
    indirizzi = [v["indirizzo"] for v in candidati]

    assert not _sospesi(indirizzi), (
        "la scoperta SNMP proverebbe %s" % _sospesi(indirizzi))
    assert "10.20.10.5" in indirizzi, "e non deve nemmeno smettere di provare i leciti"


def test_la_lettura_snmp_salta_un_apparato_fuori_perimetro(sonda, probe_store,
                                                           monkeypatch):
    """Un apparato dichiarato resta nell'elenco delle impostazioni anche dopo la
    sospensione della sua subnet: l'elenco non e' il perimetro.

    Qui si registra ogni interrogazione DAVVERO tentata: e' l'unico modo di
    distinguere "saltato" da "interrogato e non ha risposto".
    """
    from snapprobe import snmp, snmp_raccolta

    probe_store.set_setting(snmp_raccolta.CHIAVE_ATTIVA, "1")
    probe_store.set_setting(snmp_raccolta.CHIAVE_COMMUNITY, "publictest")
    probe_store.set_setting(snmp_raccolta.CHIAVE_APPARATI,
                            "10.20.10.1|Gateway attivo\n10.58.7.1|Gateway sospeso")

    interrogati = []

    def finto_arp(indirizzo, community, timeout=None, tentativi=None):
        interrogati.append(indirizzo)
        return []

    monkeypatch.setattr(snmp, "arp_table", finto_arp)
    esito = snmp_raccolta.raccogli(probe_store)

    assert not _sospesi(interrogati), (
        "e' stato contattato un apparato in una subnet sospesa: %s"
        % _sospesi(interrogati))
    assert esito["fuori_perimetro"] == 1, "il salto dev'essere contato, non taciuto"
    # Il motivo sta nel dettaglio: un apparato saltato non e' un apparato guasto.
    saltati = [v for v in esito["dettagli"] if v.get("esito") == "saltato"]
    assert saltati and "perimetro" in saltati[0]["motivo"]


def test_la_lettura_snmp_continua_sugli_apparati_leciti(sonda, probe_store,
                                                        monkeypatch):
    """Il contrario del difetto sarebbe altrettanto grave: smettere di leggere tutto."""
    from snapprobe import snmp, snmp_raccolta

    probe_store.set_setting(snmp_raccolta.CHIAVE_ATTIVA, "1")
    probe_store.set_setting(snmp_raccolta.CHIAVE_COMMUNITY, "publictest")
    probe_store.set_setting(snmp_raccolta.CHIAVE_APPARATI,
                            "10.20.10.1|Gateway attivo\n10.58.7.1|Gateway sospeso")

    interrogati = []
    monkeypatch.setattr(snmp, "arp_table",
                        lambda ip, c, timeout=None, tentativi=None:
                        interrogati.append(ip) or [])
    snmp_raccolta.raccogli(probe_store)

    assert "10.20.10.1" in interrogati


def test_senza_perimetro_non_si_interroga_nessun_apparato(probe_store, monkeypatch):
    from snapprobe import snmp, snmp_raccolta

    probe_store.set_json("scan_subnets", [])
    probe_store.set_setting(snmp_raccolta.CHIAVE_ATTIVA, "1")
    probe_store.set_setting(snmp_raccolta.CHIAVE_COMMUNITY, "publictest")
    probe_store.set_setting(snmp_raccolta.CHIAVE_APPARATI, "10.20.10.1|Gateway")

    interrogati = []
    monkeypatch.setattr(snmp, "arp_table",
                        lambda ip, c, timeout=None, tentativi=None:
                        interrogati.append(ip) or [])
    snmp_raccolta.raccogli(probe_store)

    assert interrogati == []


# --------------------------------------------------------------------------- #
# La ricognizione senza fili
# --------------------------------------------------------------------------- #
def test_la_ricognizione_senza_fili_segue_il_perimetro(probe_store):
    """Ha un thread proprio e una cadenza di due minuti: se leggesse un elenco suo,
    continuerebbe a sondare una rete sospesa ogni due minuti."""
    from snapprobe.presence import PresenceWatcher
    from snapprobe.scanner import NetworkScanner

    probe_store.set_json("scan_subnets", [{"cidr": ATTIVA, "wifi": True},
                                          {"cidr": SOSPESA, "wifi": True}])
    scanner = NetworkScanner(probe_store, None, "prova")
    ricognizione = PresenceWatcher(probe_store, scanner)
    assert SOSPESA in [str(r) for r in ricognizione.reti()]

    probe_store.set_json("scan_subnets", [{"cidr": ATTIVA, "wifi": True}])
    scanner.invalidate_perimeter()

    reti = [str(r) for r in ricognizione.reti()]
    assert SOSPESA not in reti, "la ricognizione sonderebbe una rete sospesa"
    assert ATTIVA in reti


# --------------------------------------------------------------------------- #
# La prova che conta: un ciclo intero, ogni bersaglio registrato
# --------------------------------------------------------------------------- #
def test_in_un_ciclo_intero_nessun_pacchetto_esce_verso_la_subnet_sospesa(
        sonda, probe_store, monkeypatch):
    """Non si prova un cammino per volta: si prova che NIENTE esce.

    L'esecutore di nmap viene sostituito con uno che registra i bersagli invece di
    scansionarli, e le fasi si pianificano tutte. Se un cammino futuro aggirasse i
    filtri, comparirebbe qui un indirizzo 10.58.7.x -- ed e' esattamente la domanda
    a cui questo file deve saper rispondere.
    """
    usciti = []

    class EsecutoreCheRegistra:
        def run(self, argomenti, bersagli, timeout=None, label=None, **altro):
            usciti.extend(str(b) for b in (bersagli or []))
            raise RuntimeError("nessuna scansione vera in prova")

        def running_count(self):
            return 0

        def running_executions(self):
            return []

        def detect_capabilities(self, force=False):
            return {"raw_sockets": True, "nmap_version": "prova"}

    sonda.runner = EsecutoreCheRegistra()

    # I candidati di ogni fase: e' cio' da cui i compiti vengono composti.
    for fase in ("discovery", "ports", "services", "os", "deep", "monitor",
                 "snmp", "smb", "vuln", "web"):
        usciti.extend(str(b) for b in (sonda._targets_for(fase) or []))

    # E i compiti veri, come li compone il ciclo: `plan_tasks` prende un LIMITE, non
    # una fase, e sceglie da se' che cosa e' dovuto. Si chiama piu' volte perche' a
    # ogni giro prenota cio' che ha scelto e al successivo passa ad altro.
    for _giro in range(6):
        compiti = sonda.plan_tasks(8) or []
        if not compiti:
            break
        for compito in compiti:
            usciti.extend(str(b) for b in (compito.get("hosts") or []))
            if compito.get("target") and compito["target"] != "*":
                usciti.append(str(compito["target"]))

    assert not _sospesi(usciti), (
        "in un ciclo completo sono usciti bersagli verso la subnet sospesa: %s"
        % sorted(set(_sospesi(usciti))))
    # E la controprova: qualcosa DEVE essere uscito, altrimenti la prova sopra passa
    # perche' la sonda non stava facendo niente.
    assert [b for b in usciti if b.startswith("10.20.10.")], (
        "nessun bersaglio lecito pianificato: la prova non ha provato nulla")
