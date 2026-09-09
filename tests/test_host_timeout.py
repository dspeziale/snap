"""
snap - Test del tempo massimo per host selezionabile.

Il valore governa `--host-timeout` di nmap nelle fasi di ispezione. Due proprieta'
sono facili da perdere e vengono fissate qui:

  * il tempo massimo del PROCESSO nmap deve crescere con il tempo per host e con
    il numero di bersagli: un limite fisso ucciderebbe la scansione prima della
    fine, e il nodo resterebbe senza profilo senza che nulla lo dichiari;
  * scoperta e monitoraggio conservano i propri tempi brevi, perche' sono sweep
    su interi intervalli e un tempo per host lungo si moltiplicherebbe per ogni
    indirizzo morto.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from snapprobe.scanner import (
    EFFORT_PROFILES,
    HOST_TIMEOUT_CHOICES,
    HOST_TIMEOUT_MAX_SECONDS,
    HOST_TIMEOUT_MIN_SECONDS,
    PROCESS_TIMEOUT_MAX_SECONDS,
    NetworkScanner,
    parse_timeout,
)

FIXTURES = Path(__file__).parent / "fixtures"
PERIMETRO = [{"cidr": "192.0.2.0/24", "label": "Rete di prova", "hosts": 254}]


class EsecutoreFinto:
    def __init__(self, xml: str):
        self.xml = xml
        self.chiamate = []

    def detect_capabilities(self, force: bool = False) -> dict:
        return {"available": True, "executable": "nmap-finto", "nmap_version": "7.99",
                "raw_sockets": True, "os_detection": True, "detail": "prova"}

    def running_count(self) -> int:
        return 0

    def run(self, arguments, targets, timeout=None, label=None) -> str:
        # `label` descrive la fase in corso per l'indicatore: qui non serve,
        # ma la firma deve corrispondere a quella del runner vero.
        self.chiamate.append({"arguments": list(arguments), "targets": list(targets),
                              "timeout": timeout})
        return self.xml


@pytest.fixture()
def sonda(probe_store):
    probe_store.set_json("scan_subnets", PERIMETRO)
    return probe_store


def scanner_di(sonda, fixture="nmap_porte_servizi_os.xml"):
    esecutore = EsecutoreFinto((FIXTURES / fixture).read_text(encoding="utf-8"))
    return NetworkScanner(sonda, esecutore), esecutore


# --------------------------------------------------------------------------- #
# Conversione dei valori
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("valore,atteso", [
    ("60s", 60), ("120s", 120), ("2m", 120), ("300", 300), ("10m", 600), ("30s", 30),
])
def test_i_tempi_validi_vengono_convertiti(valore, atteso):
    assert parse_timeout(valore) == atteso


@pytest.mark.parametrize("valore", ["", None, "abc", "0s", "1s", "2h", "500ms", "-5s", "1e3"])
def test_i_tempi_non_utilizzabili_sono_rifiutati(valore):
    assert parse_timeout(valore) is None


def test_i_valori_proposti_sono_tutti_utilizzabili():
    for valore in HOST_TIMEOUT_CHOICES:
        secondi = parse_timeout(valore)
        assert secondi is not None, "il valore proposto %s non e' utilizzabile" % valore
        assert HOST_TIMEOUT_MIN_SECONDS <= secondi <= HOST_TIMEOUT_MAX_SECONDS


def test_i_valori_proposti_dai_due_applicativi_coincidono(server_app):
    """I due applicativi non condividono codice: gli elenchi vanno allineati."""
    with server_app.app_context():
        from snapserver.blueprints.api_probe import HOST_TIMEOUTS

    assert tuple(HOST_TIMEOUTS) == tuple(HOST_TIMEOUT_CHOICES)


# --------------------------------------------------------------------------- #
# Applicazione del valore scelto
# --------------------------------------------------------------------------- #
def test_senza_scelta_si_usa_quello_del_profilo(sonda):
    scanner, _ = scanner_di(sonda)
    for sforzo in ("min", "med", "max"):
        sonda.set_setting("scan_effort", sforzo)
        assert scanner.host_timeout() is None
        assert scanner.effort_profile()["host_timeout"] == EFFORT_PROFILES[sforzo]["host_timeout"]


def test_il_valore_scelto_prevale_sul_profilo(sonda):
    scanner, _ = scanner_di(sonda)
    sonda.set_setting("scan_effort", "min")
    sonda.set_setting("scan_host_timeout", "600s")
    assert scanner.host_timeout() == "600s"
    assert scanner.effort_profile()["host_timeout"] == "600s"


def test_il_valore_scelto_arriva_negli_argomenti_di_nmap(sonda):
    scanner, esecutore = scanner_di(sonda)
    sonda.upsert_local_node("192.0.2.12", state="confirmed")
    sonda.set_setting("scan_host_timeout", "300s")

    scanner.run_stage("ports", "*")
    argomenti = esecutore.chiamate[-1]["arguments"]
    assert "--host-timeout" in argomenti
    assert argomenti[argomenti.index("--host-timeout") + 1] == "300s"


def test_un_valore_non_utilizzabile_viene_rifiutato_dichiarandolo(sonda):
    scanner, _ = scanner_di(sonda)
    sonda.set_setting("scan_effort", "med")
    sonda.set_setting("scan_host_timeout", "3h")
    assert scanner.host_timeout() is None
    assert scanner.effort_profile()["host_timeout"] == EFFORT_PROFILES["med"]["host_timeout"]
    diario = " ".join(e["message"] for e in sonda.recent_events(5))
    assert "3h" in diario and "non utilizzabile" in diario


def test_la_scoperta_conserva_il_proprio_tempo_breve(sonda):
    """Uno sweep su una subnet non deve ereditare un tempo per host lungo."""
    scanner, esecutore = scanner_di(sonda, "nmap_scoperta.xml")
    sonda.set_setting("scan_host_timeout", "600s")

    scanner.run_stage("discovery", "192.0.2.0/24")
    argomenti = esecutore.chiamate[-1]["arguments"]
    assert argomenti[argomenti.index("--host-timeout") + 1] == "20s"


# --------------------------------------------------------------------------- #
# Tempo massimo del processo
# --------------------------------------------------------------------------- #
def test_il_tempo_del_processo_cresce_con_il_tempo_per_host(sonda):
    scanner, esecutore = scanner_di(sonda)
    for ip in ("192.0.2.1", "192.0.2.12", "192.0.2.18"):
        sonda.upsert_local_node(ip, state="confirmed")

    sonda.set_setting("scan_host_timeout", "60s")
    scanner.run_stage("ports", "*")
    breve = esecutore.chiamate[-1]["timeout"]

    sonda.set_setting("scan_host_timeout", "600s")
    scanner.run_stage("ports", "*")
    lungo = esecutore.chiamate[-1]["timeout"]

    assert lungo > breve, "il tempo del processo non e' cresciuto con quello per host"


def test_il_tempo_del_processo_cresce_con_le_ondate_non_con_i_bersagli(sonda):
    """Requisito cambiato, dichiarato invece di lasciato implicito.

    Prima il tempo massimo del processo era `tempo per host x numero di bersagli`. Non
    e' cosi' che nmap lavora: con `--min-hostgroup` gli host di un compito si
    scansionano in PARALLELO, a ondate di al massimo MAX_HOSTGROUP. Moltiplicare per i
    bersagli portava il limite a migliaia di secondi e un compito appeso teneva
    bloccato il ciclo -- e, non concludendosi, non faceva scattare nemmeno la resa
    per fase.

    La proprieta' giusta e' quindi: entro un'ondata il tempo NON cresce (gli host sono
    in parallelo), oltre l'ondata cresce.
    """
    from snapprobe.scanner import MAX_HOSTGROUP

    scanner, _ = scanner_di(sonda)
    profilo = dict(EFFORT_PROFILES["med"], host_timeout="120s")

    una_ondata = scanner._process_timeout("ports", MAX_HOSTGROUP, profilo)
    meta_ondata = scanner._process_timeout("ports", MAX_HOSTGROUP // 2, profilo)
    due_ondate = scanner._process_timeout("ports", MAX_HOSTGROUP + 1, profilo)

    assert meta_ondata == una_ondata, (
        "entro un'ondata gli host sono in parallelo: il tempo non deve crescere")
    assert due_ondate > una_ondata, (
        "oltre l'ondata nmap serializza: il tempo deve crescere")


def test_il_tempo_del_processo_non_supera_il_limite(sonda):
    scanner, _ = scanner_di(sonda)
    profilo = dict(EFFORT_PROFILES["max"], host_timeout="600s")
    calcolato = scanner._process_timeout("ports", 500, profilo)
    assert calcolato <= PROCESS_TIMEOUT_MAX_SECONDS


def test_il_tempo_del_processo_copre_il_lavoro_richiesto(sonda):
    """Deve coprire le ONDATE che nmap eseguira' davvero (vedi il test sopra per il
    perche' non si moltiplica piu' per i bersagli): almeno il tempo per host per
    ciascuna ondata, altrimenti il compito viene ucciso mentre sta ancora lavorando e
    la fase non produce nulla."""
    from snapprobe.scanner import MAX_HOSTGROUP

    scanner, _ = scanner_di(sonda)
    profilo = dict(EFFORT_PROFILES["med"], host_timeout="120s")
    for bersagli in (1, 10, MAX_HOSTGROUP, MAX_HOSTGROUP * 3 + 5):
        ondate = -(-bersagli // MAX_HOSTGROUP)
        calcolato = scanner._process_timeout("ports", bersagli, profilo)
        assert calcolato >= 120 * ondate, (
            "con %d bersagli nmap fa %d ondate: il tempo non le copre"
            % (bersagli, ondate))


def test_le_fasi_di_raggiungibilita_non_moltiplicano_il_tempo(sonda):
    scanner, _ = scanner_di(sonda)
    profilo = dict(EFFORT_PROFILES["med"], host_timeout="120s")
    ispezione = scanner._process_timeout("ports", 24, profilo)
    scoperta = scanner._process_timeout("discovery", 24, profilo)
    assert scoperta < ispezione


# --------------------------------------------------------------------------- #
# Comando dal server
# --------------------------------------------------------------------------- #
def test_il_tempo_per_host_viaggia_nella_configurazione(server_app):
    with server_app.app_context():
        from snapserver.blueprints.api_probe import _probe_config
        from snapserver.db import execute, query, utc_now_str

        tenant = query("SELECT * FROM tenants ORDER BY id", (), one=True)
        adesso = utc_now_str()
        execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, scan_interval_sec,"
            " config_json, created_at, updated_at)"
            " VALUES (?, 'uid-ht', 'sonda-ht', 'Sonda', 'active', 300, '{}', ?, ?)",
            (int(tenant["id"]), adesso, adesso),
        )
        sonda = query("SELECT * FROM probes WHERE probe_uid = 'uid-ht'", (), one=True)
        assert _probe_config(sonda, dict(tenant))["scan_host_timeout"] == ""

        execute("UPDATE probes SET scan_host_timeout = '300s' WHERE probe_uid = 'uid-ht'")
        sonda = query("SELECT * FROM probes WHERE probe_uid = 'uid-ht'", (), one=True)
        assert _probe_config(sonda, dict(tenant))["scan_host_timeout"] == "300s"

        # Un valore non ammesso non viene consegnato.
        execute("UPDATE probes SET scan_host_timeout = '9h' WHERE probe_uid = 'uid-ht'")
        sonda = query("SELECT * FROM probes WHERE probe_uid = 'uid-ht'", (), one=True)
        assert _probe_config(sonda, dict(tenant))["scan_host_timeout"] == ""


def test_la_sonda_recepisce_il_tempo_dal_server(probe_store):
    from snapprobe.agent import ProbeAgent

    agente = ProbeAgent(probe_store, "1.0.0")
    agente._apply_server_config({"subnets": PERIMETRO, "scan_host_timeout": "180s"})
    assert probe_store.get_setting("scan_host_timeout") == "180s"

    agente._apply_server_config({"subnets": PERIMETRO, "scan_host_timeout": ""})
    assert probe_store.get_setting("scan_host_timeout") == ""


def test_lo_stato_dichiara_il_tempo_in_uso_e_le_scelte(sonda):
    scanner, _ = scanner_di(sonda)
    sonda.set_setting("scan_effort", "med")
    stato = scanner.status()
    assert stato["host_timeout"] == EFFORT_PROFILES["med"]["host_timeout"]
    assert stato["host_timeout_chosen"] is None
    assert stato["host_timeout_choices"] == list(HOST_TIMEOUT_CHOICES)

    sonda.set_setting("scan_host_timeout", "600s")
    stato = scanner.status()
    assert stato["host_timeout"] == "600s"
    assert stato["host_timeout_chosen"] == "600s"


# --------------------------------------------------------------------------- #
# Cadenza della scoperta
# --------------------------------------------------------------------------- #
def test_la_scoperta_non_e_piu_continua():
    """Una rete non cambia ogni cinque minuti: il censimento e' ogni pochi giorni."""
    from snapprobe.scanner import DEFAULT_CADENCES

    assert DEFAULT_CADENCES["discovery"] == 3 * 24 * 3600


def test_la_cadenza_della_scoperta_arriva_dal_server(server_app):
    with server_app.app_context():
        from snapserver.blueprints.api_probe import (
            DISCOVERY_DAYS_DEFAULT,
            _probe_config,
        )
        from snapserver.db import execute, query, utc_now_str

        tenant = query("SELECT * FROM tenants ORDER BY id", (), one=True)
        adesso = utc_now_str()
        execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, scan_interval_sec,"
            " config_json, created_at, updated_at)"
            " VALUES (?, 'uid-gg', 'sonda-gg', 'Sonda', 'active', 300, '{}', ?, ?)",
            (int(tenant["id"]), adesso, adesso),
        )
        sonda = query("SELECT * FROM probes WHERE probe_uid = 'uid-gg'", (), one=True)
        configurazione = _probe_config(sonda, dict(tenant))
        assert configurazione["discovery_days"] == DISCOVERY_DAYS_DEFAULT
        assert configurazione["cadences"]["discovery"] == DISCOVERY_DAYS_DEFAULT * 86400

        execute("UPDATE probes SET scan_discovery_days = 7 WHERE probe_uid = 'uid-gg'")
        sonda = query("SELECT * FROM probes WHERE probe_uid = 'uid-gg'", (), one=True)
        assert _probe_config(sonda, dict(tenant))["cadences"]["discovery"] == 7 * 86400

        # Un valore fuori dai limiti ricade sul predefinito.
        execute("UPDATE probes SET scan_discovery_days = 999 WHERE probe_uid = 'uid-gg'")
        sonda = query("SELECT * FROM probes WHERE probe_uid = 'uid-gg'", (), one=True)
        assert _probe_config(sonda, dict(tenant))["discovery_days"] == DISCOVERY_DAYS_DEFAULT


def test_la_sonda_rispetta_la_cadenza_ricevuta(sonda):
    scanner, esecutore = scanner_di(sonda, "nmap_scoperta.xml")
    sonda.set_json("scan_cadences", {"discovery": 3 * 24 * 3600})

    scanner.run_stage("discovery", "192.0.2.0/24")
    # Appena censita, la subnet non e' piu' dovuta.
    dovute = [c for c in scanner.plan_tasks() if c["stage"] == "discovery"]
    assert dovute == [], "la scoperta e' stata ripianificata subito dopo l'esecuzione"


def test_lo_stato_dichiara_la_cadenza_in_giorni(sonda):
    scanner, _ = scanner_di(sonda)
    sonda.set_json("scan_cadences", {"discovery": 5 * 24 * 3600})
    assert scanner.status()["discovery_days"] == 5.0


# --------------------------------------------------------------------------- #
# Minimo per host nelle fasi di ispezione
# --------------------------------------------------------------------------- #
def test_le_fasi_di_ispezione_hanno_un_minimo_per_host(sonda):
    """Difetto reale: con 30s per host la fase dei servizi non produceva nulla.

    Misurato sul campo su due nodi: con 30s nmap dichiarava entrambi scaduti e
    l'XML era privo di porte; con 120s trovava 26 porte. I nodi restavano quindi
    senza la fase e il profilo non si completava mai.
    """
    from snapprobe.scanner import MIN_HOST_TIMEOUT_INSPECTION, STAGES_NEEDING_TIME

    scanner, _ = scanner_di(sonda)
    sonda.set_setting("scan_host_timeout", "30s")
    profilo = scanner.effort_profile()

    for fase in STAGES_NEEDING_TIME:
        assert scanner._host_timeout_for(fase, profilo) == "%ds" % MIN_HOST_TIMEOUT_INSPECTION, (
            "la fase %s non ha ricevuto il minimo" % fase
        )
    # Scoperta, porte e monitoraggio rispettano la scelta dell'operatore.
    for fase in ("discovery", "ports", "monitor"):
        assert scanner._host_timeout_for(fase, profilo) == "30s"


def test_un_valore_generoso_non_viene_abbassato(sonda):
    scanner, _ = scanner_di(sonda)
    sonda.set_setting("scan_host_timeout", "300s")
    profilo = scanner.effort_profile()
    for fase in ("ports", "services", "os", "deep"):
        assert scanner._host_timeout_for(fase, profilo) == "300s"


def test_il_minimo_arriva_negli_argomenti_della_fase_servizi(sonda):
    from snapprobe.scanner import MIN_HOST_TIMEOUT_INSPECTION

    scanner, esecutore = scanner_di(sonda)
    sonda.upsert_local_node("192.0.2.12", state="confirmed")
    sonda.set_setting("scan_host_timeout", "30s")

    scanner.run_stage("services", "*")
    argomenti = esecutore.chiamate[-1]["arguments"]
    assert argomenti[argomenti.index("--host-timeout") + 1] == "%ds" % MIN_HOST_TIMEOUT_INSPECTION


def test_una_fase_senza_host_lo_dichiara(sonda):
    """Senza questa annotazione il blocco resta invisibile."""
    scanner, _ = scanner_di(sonda, "nmap_host_fantasma.xml")
    sonda.upsert_local_node("192.0.2.240", state="confirmed")
    scanner.run_stage("ports", "*")
    diario = " ".join(e["message"] for e in sonda.recent_events(10))
    assert "nessun host restituito" in diario


def test_i_nodi_piu_avanzati_arrivano_al_proprio_turno(sonda):
    """La scoperta aggiunge nodi nuovi: senza una garanzia le fasi finali non
    arrivavano mai al proprio turno e i profili si accumulavano a meta'.

    Il requisito era "il nodo piu' avanzato viene pianificato PER PRIMO". E'
    cambiato, e va dichiarato: adesso ogni frontiera ha un POSTO RISERVATO nel ciclo
    -- uno per l'esame delle porte dei candidati, uno per il completamento del
    profilo. Il motivo e' una misura opposta e altrettanto reale: mettendo davanti il
    completamento, le PORTE dei candidati non venivano mai esaminate e il conteggio
    "in lavorazione" restava fermo per ore con migliaia di host scoperti e mai
    profilati. Nessuna delle due frontiere puo' stare dietro all'altra: devono
    avanzare insieme, ed e' questo che il test verifica.
    """
    scanner, _ = scanner_di(sonda)
    # Un nodo nuovo (nessuna fase) e uno che attende solo il sistema operativo. Il
    # secondo ha una porta aperta: senza, la sonda lo considera gia' esaminato del
    # tutto e non sarebbe in attesa di alcuna fase.
    sonda.upsert_local_node("192.0.2.10", state="confirmed", stages_done="")
    sonda.upsert_local_node("192.0.2.11", state="confirmed",
                            stages_done="ports,services", open_ports=3)
    sonda.record_scan("192.0.2.0/24", "discovery", "completed")

    compiti = scanner.plan_tasks()
    fasi = [c["stage"] for c in compiti]

    assert "os" in fasi, (
        "il completamento del profilo deve avere un posto riservato: %s" % fasi)
    assert "ports" in fasi, (
        "l'esame delle porte dei candidati deve avere un posto riservato: %s" % fasi)
    compito_os = next(c for c in compiti if c["stage"] == "os")
    assert "192.0.2.11" in compito_os["hosts"]
