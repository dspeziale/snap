"""
snap - Test della ricognizione delle presenze sulla sonda.

PERCHE' ESISTE
Il ciclo di scansione e' tarato su una rete cablata: la scoperta ripassa il perimetro
ogni tre giorni. Su una rete senza fili quel ritmo non vede niente -- un telefono resta
agganciato dieci minuti -- quindi la ricognizione delle presenze e' un processo a
parte, con un thread proprio e una cadenza di minuti.

Le proprieta' che questi test fissano sono quelle da cui dipende il senso della cosa:
si osservano SOLO le reti dichiarate senza fili (mai per supposizione), chi compare
passa in TESTA alla coda dell'esame delle porte (in fondo verrebbe esaminato quando
non c'e' piu'), e la ricognizione non dichiara di aver fatto lavoro che non ha fatto.

Nessuna esecuzione reale di nmap: l'esecutore e' finto.

remarks: Autore: Daniele Speziale - Data: 2026-09-10
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from snapprobe.nmap_runner import NmapError, NmapTimeout
from snapprobe.presence import (CHIAVE_PRIORITA, MAX_PRIORITA, PresenceWatcher,
                                subnet_senza_fili)
from snapprobe.scanner import NetworkScanner

FIXTURES = Path(__file__).parent / "fixtures"
WIFI = {"cidr": "192.0.2.0/24", "label": "Ospiti", "wifi": True}
CABLATA = {"cidr": "198.51.100.0/24", "label": "Uffici"}


class EsecutoreFinto:
    """Il minimo che la ricognizione usa dell'esecutore di nmap."""

    def __init__(self, xml: str = "", errore: Exception = None):
        self.xml = xml
        self.errore = errore
        self.chiamate = []

    def detect_capabilities(self, force: bool = False) -> dict:
        return {"available": True, "executable": "nmap-finto", "nmap_version": "7.99",
                "raw_sockets": True, "os_detection": True, "detail": "prova"}

    def running_count(self) -> int:
        return 0

    def run(self, arguments, targets, timeout=None, label=None, diagnostica=None) -> str:
        self.chiamate.append({"arguments": list(arguments), "targets": list(targets),
                              "timeout": timeout, "label": label})
        if self.errore is not None:
            raise self.errore
        return self.xml


def sorveglianza(store, perimetro=(WIFI, CABLATA), xml=None, errore=None):
    """Una ricognizione pronta, con il perimetro dichiarato e un nmap finto."""
    store.set_json("scan_subnets", list(perimetro))
    if xml is None:
        xml = (FIXTURES / "nmap_scoperta.xml").read_text(encoding="utf-8")
    esecutore = EsecutoreFinto(xml, errore=errore)
    scanner = NetworkScanner(store, esecutore, "prova")
    return PresenceWatcher(store, scanner), esecutore


# --------------------------------------------------------------------------- #
# Solo le reti dichiarate
# --------------------------------------------------------------------------- #
def test_si_osservano_solo_le_reti_dichiarate_senza_fili():
    assert subnet_senza_fili([WIFI, CABLATA]) == ["192.0.2.0/24"]


def test_una_voce_senza_il_campo_non_e_senza_fili():
    """Una sonda che parla con un server piu' vecchio non riceve il campo: nessun
    comportamento nuovo per omissione. La ricognizione si attiva per dichiarazione."""
    assert subnet_senza_fili([{"cidr": "10.0.0.0/24"}]) == []


@pytest.mark.parametrize("voce", [
    {"cidr": "", "wifi": True},
    {"cidr": "non-una-rete", "wifi": True},
    {"cidr": "10.0.0.0/33", "wifi": True},
    "10.0.0.0/24",
    None,
])
def test_una_riga_corrotta_non_diventa_un_bersaglio(voce):
    assert subnet_senza_fili([voce]) == []


def test_senza_reti_senza_fili_la_ricognizione_non_e_dovuta(probe_store):
    guardia, esecutore = sorveglianza(probe_store, perimetro=(CABLATA,))

    assert guardia.due() is False
    assert guardia.run_once()["subnets"] == 0
    assert esecutore.chiamate == [], "nessuna esecuzione di nmap"


def test_con_le_scansioni_sospese_non_si_ricognisce(probe_store):
    guardia, esecutore = sorveglianza(probe_store)
    probe_store.set_setting("scan_paused", "1")

    assert guardia.due() is False
    esito = guardia.run_once()

    assert esecutore.chiamate == []
    assert "sospes" in (esito.get("detail") or "")


# --------------------------------------------------------------------------- #
# La cadenza
# --------------------------------------------------------------------------- #
def test_la_prima_volta_e_sempre_dovuta(probe_store):
    guardia, _ = sorveglianza(probe_store)

    assert guardia.due() is True


def test_dopo_una_passata_non_e_subito_dovuta(probe_store):
    guardia, _ = sorveglianza(probe_store)

    guardia.run_once()

    assert guardia.due() is False, "due passate di seguito misurerebbero la prima"


def test_la_cadenza_viene_dal_server_con_un_minimo(probe_store):
    """Sotto la soglia due passate si sovrappongono su una rete lenta: il minimo non
    e' prudenza generica."""
    guardia, _ = sorveglianza(probe_store)

    probe_store.set_json("scan_cadences", {"presence": 600})
    assert guardia.intervallo() == 600

    probe_store.set_json("scan_cadences", {"presence": 5})
    assert guardia.intervallo() == 30

    probe_store.set_json("scan_cadences", {"presence": "molti"})
    assert guardia.intervallo() == 120, "un valore illeggibile non ferma la sonda"


# --------------------------------------------------------------------------- #
# La passata
# --------------------------------------------------------------------------- #
def test_la_ricognizione_chiede_solo_chi_risponde(probe_store):
    """Niente porte, niente sistema operativo: e' cio' che la rende breve."""
    guardia, esecutore = sorveglianza(probe_store)

    guardia.run_once()

    argomenti = esecutore.chiamate[0]["arguments"]
    assert "-sn" in argomenti
    assert not any(a.startswith("-sS") or a.startswith("-sT") for a in argomenti)
    assert "-O" not in argomenti
    assert "-sV" not in argomenti
    assert esecutore.chiamate[0]["targets"] == ["192.0.2.0/24"]


def test_la_ricognizione_produce_avvistamenti_e_nodi(probe_store):
    guardia, _ = sorveglianza(probe_store)

    esito = guardia.run_once()

    assert esito["subnets"] == 1
    assert esito["seen"] > 0
    assert len(esito["records"]["presence"]) == esito["seen"]
    assert len(esito["records"]["nodes"]) == esito["seen"]
    avvistamento = esito["records"]["presence"][0]
    assert avvistamento["subnet"] == "192.0.2.0/24"
    assert avvistamento["seen_at"]


def test_la_ricognizione_non_dichiara_lavoro_che_non_ha_fatto(probe_store):
    """Il record di nodo non deve promettere porte esaminate: l'arricchimento resta
    del ciclo ordinario, e un profilo dichiarato completo non verrebbe piu' guardato."""
    guardia, _ = sorveglianza(probe_store)

    record = guardia.run_once()["records"]["nodes"][0]

    assert record["ports_examined"] is False
    assert record["reachable"] is True
    assert "switch_port" not in record and "switch_device" not in record
    assert "ports" not in record


def test_una_rete_che_non_risponde_non_ferma_le_altre(probe_store):
    """Una rete di utenza che non risponde e' una condizione di esercizio."""
    guardia, _ = sorveglianza(probe_store, errore=NmapTimeout("oltre il tempo"))

    esito = guardia.run_once()

    assert esito["seen"] == 0
    assert esito["new"] == []


def test_un_errore_di_nmap_non_solleva(probe_store):
    guardia, _ = sorveglianza(probe_store, errore=NmapError("nmap assente"))

    assert guardia.run_once()["seen"] == 0


def test_un_esito_illeggibile_non_solleva(probe_store):
    guardia, _ = sorveglianza(probe_store, xml="<non-e-xml")

    assert guardia.run_once()["seen"] == 0


def test_le_reti_meno_recenti_si_ripassano_per_prime(probe_store):
    """Con piu' reti di quante ne stiano in una passata, girare sempre dalla prima
    lascerebbe l'ultima mai osservata."""
    reti = [{"cidr": "192.0.%d.0/24" % i, "wifi": True} for i in range(6)]
    guardia, esecutore = sorveglianza(probe_store, perimetro=reti)

    guardia.run_once()
    primo_giro = {c["targets"][0] for c in esecutore.chiamate}
    probe_store.set_setting("presence_last_run_at", None)
    esecutore.chiamate.clear()
    guardia.run_once()
    secondo_giro = {c["targets"][0] for c in esecutore.chiamate}

    assert len(primo_giro) == 4, "quattro reti per passata"
    # La proprieta' che conta e' questa: una rete MAI osservata viene osservata al
    # giro successivo. Che fra le quattro del secondo giro ricompaia una del primo e'
    # legittimo -- le quattro del primo giro hanno tutte lo stesso istante, quindi
    # fra loro l'ordine e' indifferente.
    mai_viste = {"192.0.4.0/24", "192.0.5.0/24"}
    assert mai_viste <= secondo_giro, "nessuna rete deve restare mai osservata"
    assert len(secondo_giro) == 4


# --------------------------------------------------------------------------- #
# La precedenza: la ragione per cui la ricognizione serve a qualcosa
# --------------------------------------------------------------------------- #
def test_chi_compare_per_la_prima_volta_va_in_coda_prioritaria(probe_store):
    guardia, _ = sorveglianza(probe_store)

    esito = guardia.run_once()

    assert esito["new"], "la prima passata trova tutto nuovo"
    assert probe_store.get_json(CHIAVE_PRIORITA, []) == esito["new"][:MAX_PRIORITA]


def test_chi_era_gia_noto_non_torna_in_coda(probe_store):
    guardia, _ = sorveglianza(probe_store)
    guardia.run_once()
    # Le porte dei nodi trovati risultano esaminate: escono dalla coda.
    for ip in guardia.priorita():
        probe_store.upsert_local_node(ip, stages_done="ports")
    probe_store.set_setting("presence_last_run_at", None)

    esito = guardia.run_once()

    assert esito["new"] == [], "nessuno e' nuovo alla seconda passata"
    assert guardia.priorita() == [], "e la coda si e' svuotata"


def test_un_nodo_scartato_che_ricompare_conta_come_nuovo(probe_store):
    """Su una rete senza fili l'apparato di prima non e' quello di adesso: un
    indirizzo scartato che torna a rispondere va riesaminato."""
    guardia, _ = sorveglianza(probe_store)
    probe_store.upsert_local_node("192.0.2.12", state="discarded")

    esito = guardia.run_once()

    assert "192.0.2.12" in esito["new"]


def test_i_piu_recenti_stanno_davanti(probe_store):
    guardia, _ = sorveglianza(probe_store)

    guardia.segna_priorita(["10.0.0.1", "10.0.0.2"])
    guardia.segna_priorita(["10.0.0.9"])

    assert guardia.priorita()[0] == "10.0.0.9", (
        "l'apparato appena comparso e' quello che si rischia di perdere")


def test_la_coda_prioritaria_ha_un_tetto(probe_store):
    """Su una rete di utenza affollata si presentano decine di apparati: se la coda
    diventasse l'intera coda, "prioritario" non significherebbe piu' niente."""
    guardia, _ = sorveglianza(probe_store)

    guardia.segna_priorita(["10.1.%d.%d" % (i // 250, i % 250)
                            for i in range(MAX_PRIORITA + 60)])

    assert len(guardia.priorita()) == MAX_PRIORITA


def test_un_indirizzo_non_si_ripete_nella_coda(probe_store):
    guardia, _ = sorveglianza(probe_store)

    guardia.segna_priorita(["10.0.0.1"])
    guardia.segna_priorita(["10.0.0.1"])

    assert guardia.priorita() == ["10.0.0.1"]


def test_il_pianificatore_esamina_prima_i_prioritari(probe_store):
    """La coda la scrive la ricognizione, ma serve solo se il pianificatore la
    rispetta: il ciclo dedica UN compito per giro all'esame delle porte."""
    probe_store.set_json("scan_subnets", [WIFI])
    scanner = NetworkScanner(probe_store, EsecutoreFinto(""), "prova")
    for ultimo in range(1, 30):
        probe_store.upsert_local_node("192.0.2.%d" % ultimo, state="candidate")
    probe_store.set_json(CHIAVE_PRIORITA, ["192.0.2.29"])

    compiti = scanner.plan_tasks(limit=8)
    # La fase che profila un candidato e' la RAFFICA (un processo per nodo); la fase
    # porte resta per i nodi che la raffica non ha ancora preso.
    profilanti = [c for c in compiti if c["stage"] in ("raffica", "ports")]

    assert profilanti, "il pianificatore riserva posti al profilo dei candidati"
    assert profilanti[0]["hosts"][0] == "192.0.2.29"


def test_senza_coda_prioritaria_l_ordine_non_cambia(probe_store):
    probe_store.set_json("scan_subnets", [WIFI])
    scanner = NetworkScanner(probe_store, EsecutoreFinto(""), "prova")
    nodi = [{"ip": "192.0.2.%d" % i} for i in (5, 3, 9)]

    assert scanner._in_ordine_di_priorita(nodi) == nodi


# --------------------------------------------------------------------------- #
# Lo stato, per la pagina della sonda
# --------------------------------------------------------------------------- #
def test_lo_stato_dice_che_cosa_si_sta_osservando(probe_store):
    guardia, _ = sorveglianza(probe_store)

    guardia.run_once()
    stato = guardia.stato()

    assert stato["subnets_wifi"] == ["192.0.2.0/24"]
    assert stato["interval_sec"] == 120
    assert stato["seen"] > 0
    assert stato["priority_queue"] > 0
    assert stato["at"]
