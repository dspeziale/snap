"""
snap - Test della regola: un host abbandonato per scadenza non e' un host vuoto.

Difetto segnalato dall'operatore su un apparato reale. 10.10.5.42 e' stato scartato
dall'inventario con "dichiarato vivo ma senza alcuna informazione dopo 2 esami delle
porte". Interrogato a mano, nmap risponde in due secondi e mezzo con **undici porte
aperte**: e' una multifunzione (ftp, http, https, printer, ipp, jetdirect, sip).

La causa: quando nmap abbandona un host perche' e' scaduto il tempo per host
(`--host-timeout`), lo restituisce nell'XML con `timedout="true"` e senza porte. Il
lettore lo segnava e la fase lo scriveva nel diario, ma la regola di ammissione lo
trattava come host ESAMINATO e trovato vuoto: contava il tentativo e al secondo
scartava il nodo.

Dedurre l'assenza dal proprio tempo scaduto e' il modo piu' rapido di perdere un
apparato.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json

import pytest

from snapprobe.scanner import NetworkScanner


@pytest.fixture()
def scanner(probe_store):
    return NetworkScanner(probe_store, None, "1.0.0")


def _locale(store, ip: str) -> dict:
    voce = store.local_node(ip)
    return dict(voce) if voce else {}


# --------------------------------------------------------------------------- #
# La regola di ammissione
# --------------------------------------------------------------------------- #
def test_un_host_scaduto_non_consuma_un_tentativo(scanner, probe_store):
    """E' la correzione del difetto: la scadenza misura il nostro tempo, non l'host."""
    probe_store.upsert_local_node("10.10.5.42", state="candidate", attempts=1)

    scanner._handle_unconfirmed({"ip": "10.10.5.42", "timed_out": True,
                                 "status_reason": "user-set"})

    voce = _locale(probe_store, "10.10.5.42")
    assert voce, "l'host non viene rimosso"
    assert voce["state"] == "candidate"
    assert int(voce["attempts"] or 0) == 1, "il tentativo non e' stato consumato"


def test_un_host_scaduto_non_si_scarta_mai(scanner, probe_store):
    """Anche al decimo giro: se non e' stato esaminato, non si puo' concludere niente."""
    probe_store.upsert_local_node("10.10.5.42", state="candidate", attempts=9)

    for _ in range(10):
        scanner._handle_unconfirmed({"ip": "10.10.5.42", "timed_out": True})

    voce = _locale(probe_store, "10.10.5.42")
    assert voce and voce["state"] == "candidate"


def test_la_scadenza_si_conta_sul_nodo(scanner, probe_store):
    """Il conteggio serve alla decisione successiva: piu' tempo, non lo stesso."""
    probe_store.upsert_local_node("10.10.5.42", state="candidate")

    scanner._handle_unconfirmed({"ip": "10.10.5.42", "timed_out": True})
    scanner._handle_unconfirmed({"ip": "10.10.5.42", "timed_out": True})

    profilo = json.loads(_locale(probe_store, "10.10.5.42")["profile_json"])
    assert profilo["timeout_count"] == 2
    assert profilo["timed_out_at"]


def test_un_host_esaminato_e_vuoto_resta_scartabile(scanner, probe_store):
    """La regola di ammissione non si indebolisce: un host DAVVERO esaminato e senza
    nulla da dire viene scartato come prima, altrimenti l'inventario si riempirebbe di
    falsi positivi del ping."""
    from snapprobe.scanner import MAX_CANDIDATE_ATTEMPTS

    probe_store.upsert_local_node("10.10.5.99", state="candidate",
                                  attempts=MAX_CANDIDATE_ATTEMPTS - 1)

    scanner._handle_unconfirmed({"ip": "10.10.5.99", "timed_out": False,
                                 "status_reason": "user-set"})

    assert _locale(probe_store, "10.10.5.99") == {}, "scartato, come previsto"


def test_lo_scarto_resta_annunciato_nel_diario(scanner, probe_store):
    from snapprobe.scanner import MAX_CANDIDATE_ATTEMPTS

    probe_store.upsert_local_node("10.10.5.98", state="candidate",
                                  attempts=MAX_CANDIDATE_ATTEMPTS - 1)
    scanner._handle_unconfirmed({"ip": "10.10.5.98", "status_reason": "user-set"})

    diario = " ".join(r["message"] for r in probe_store.recent_events(50))
    assert "10.10.5.98" in diario and "scartato" in diario


def test_la_scadenza_si_annuncia_nel_diario(scanner, probe_store):
    """Chi legge il diario deve capire che l'host non e' stato perduto.

    La formulazione e' cambiata quando e' arrivata l'attesa progressiva: prima
    diceva "il tentativo non conta", ora dice che l'host resta candidato -- ignoto,
    non assente -- e quando verra' riprovato. Il fatto da comunicare e' lo stesso e
    il controllo verifica quello, non le parole di allora.
    """
    probe_store.upsert_local_node("10.10.5.42", state="candidate")

    scanner._handle_unconfirmed({"ip": "10.10.5.42", "timed_out": True})

    diario = " ".join(r["message"] for r in probe_store.recent_events(50))
    assert "abbandonato" in diario
    assert "resta candidato" in diario.lower()
    assert "ignoto, non assente" in diario
    # E il nodo e' davvero ancora la', non scartato: e' cio' che la riga promette.
    assert _locale(probe_store, "10.10.5.42").get("state") == "candidate"


# --------------------------------------------------------------------------- #
# Piu' tempo a chi e' gia' scaduto
# --------------------------------------------------------------------------- #
def test_chi_e_scaduto_viene_riesaminato_con_piu_tempo(scanner, probe_store):
    """Insistere con lo stesso tempo darebbe lo stesso esito, e l'host verrebbe
    scartato per un limite nostro."""
    from snapprobe.scanner import MAX_HOST_TIMEOUT_RETRY

    profilo = dict(scanner.effort_profile())
    profilo["host_timeout"] = "60s"

    normale = scanner._host_timeout_for("ports", profilo, hosts=["10.10.5.1"])
    probe_store.upsert_local_node(
        "10.10.5.42", state="candidate",
        profile_json=json.dumps({"ip": "10.10.5.42", "timeout_count": 1}))
    dopo = scanner._host_timeout_for("ports", profilo, hosts=["10.10.5.42"])

    assert normale == "60s"
    assert dopo == "120s"
    assert int(dopo.rstrip("s")) <= MAX_HOST_TIMEOUT_RETRY


def test_il_raddoppio_ha_un_tetto(scanner, probe_store):
    """Il tetto limita l'AUMENTO, non riduce cio' che l'operatore ha scelto.

    Con un tempo per host di 120 s il raddoppio si fermerebbe a 240; con 200 s si
    ferma al tetto (300) invece di arrivare a 400. E con 600 s -- scelta
    dell'operatore, gia' sopra il tetto -- il valore resta 600: un tetto che
    accorciasse il tempo scelto peggiorerebbe proprio il caso che deve risolvere.
    """
    from snapprobe.scanner import MAX_HOST_TIMEOUT_RETRY

    probe_store.upsert_local_node(
        "10.10.5.42", state="candidate",
        profile_json=json.dumps({"ip": "10.10.5.42", "timeout_count": 3}))
    profilo = dict(scanner.effort_profile())

    profilo["host_timeout"] = "200s"
    assert scanner._host_timeout_for("ports", profilo, hosts=["10.10.5.42"]) == (
        "%ds" % MAX_HOST_TIMEOUT_RETRY)

    profilo["host_timeout"] = "600s"
    assert scanner._host_timeout_for("ports", profilo, hosts=["10.10.5.42"]) == "600s"


def test_il_minimo_delle_fasi_lente_resta_valido(scanner):
    """La correzione non tocca il minimo misurato sul campo per le fasi che
    interrogano i servizi."""
    from snapprobe.scanner import MIN_HOST_TIMEOUT_INSPECTION

    profilo = dict(scanner.effort_profile())
    profilo["host_timeout"] = "30s"

    assert scanner._host_timeout_for("services", profilo) == (
        "%ds" % MIN_HOST_TIMEOUT_INSPECTION)
    assert scanner._host_timeout_for("discovery", profilo) == "30s"


def test_gli_argomenti_di_nmap_portano_il_tempo_maggiorato(scanner, probe_store):
    """Il raddoppio "seconda occasione" per un host gia' scaduto vale nelle fasi che
    un tetto per host lo ricevono ancora.

    La fase delle porte non ne riceve piu' (motore riprogettato: gli host di un
    gruppo si dividono il budget di pacchetti del processo, quindi un tetto per host
    li fa scadere tutti). Il controllo usa `deep`, dove il tetto esiste, protegge da
    uno script appeso su un singolo apparato e il raddoppio si applica -- servizi e
    sistema operativo ne sono esclusi di proposito (STAGES_PROFILE_COMPLETION: si
    arrendono dopo una scadenza e conferiscono il nodo con cio' che ha).
    """
    from snapprobe.scanner import MAX_HOST_TIMEOUT_RETRY

    probe_store.upsert_local_node(
        "10.10.5.42", state="candidate",
        profile_json=json.dumps({"ip": "10.10.5.42", "timeout_count": 1}))
    profilo = dict(scanner.effort_profile())
    profilo["host_timeout"] = "120s"

    argomenti = scanner._arguments_for("deep", {"raw_sockets": True}, profilo,
                                       hosts=["10.10.5.42"])

    assert "--host-timeout" in argomenti
    maggiorato = int(argomenti[argomenti.index("--host-timeout") + 1].rstrip("s"))
    assert maggiorato > 120, "un host gia' scaduto va riesaminato con piu' tempo"
    assert maggiorato <= MAX_HOST_TIMEOUT_RETRY

    # E la fase delle porte non lo riceve affatto.
    porte = scanner._arguments_for("ports", {"raw_sockets": True}, profilo,
                                   hosts=["10.10.5.42"])
    assert "--host-timeout" not in porte


# --------------------------------------------------------------------------- #
# L'attesa progressiva: un host non esaminabile non blocca gli altri
# --------------------------------------------------------------------------- #
# Difetto misurato sul campo, e costoso: la scansione di una /24 non finiva MAI.
# Il diario riportava "nmap ha abbandonato l'esame per scadenza (66 volta/e)" sugli
# stessi 24 indirizzi, con ondate da 257 s che restituivano zero host. Non scartare
# un host abbandonato e' giusto (non e' stato esaminato: e' ignoto, non assente), ma
# senza una contropartita gli stessi indirizzi rientravano in ogni ciclo e la coda
# non si svuotava.
def _candidato_scaduto(store, ip: str, quante: int, quando: str) -> None:
    store.upsert_local_node(
        ip, state="candidate",
        profile_json=json.dumps({"ip": ip, "timeout_count": quante,
                                 "timed_out_at": quando}))


def _istante(secondi_fa: int) -> str:
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc) - timedelta(seconds=secondi_fa)).strftime(
        "%Y-%m-%d %H:%M:%S")


def test_un_host_appena_abbandonato_non_rientra_subito_in_coda(scanner, probe_store):
    """E' la correzione del ciclo infinito: riprovarlo adesso, con gli stessi mezzi,
    darebbe lo stesso esito e occuperebbe il posto di un host esaminabile."""
    _candidato_scaduto(probe_store, "10.10.5.42", quante=1, quando=_istante(60))

    in_attesa = [n["ip"] for n in scanner.pending_nodes("ports")]

    assert "10.10.5.42" not in in_attesa


def test_passata_l_attesa_l_host_torna_in_coda(scanner, probe_store):
    """Deprioritizzare non e' rinunciare: l'host resta candidato e torna."""
    probe_store.set_json("scan_subnets", [{"cidr": "10.10.5.0/24", "hosts": 254}])
    _candidato_scaduto(probe_store, "10.10.5.42", quante=1, quando=_istante(3 * 3600))

    in_attesa = [n["ip"] for n in scanner.pending_nodes("ports")]

    assert "10.10.5.42" in in_attesa


def test_l_attesa_raddoppia_a_ogni_abbandono(scanner, probe_store):
    """Un host che scade sempre si guarda sempre piu' di rado, fino al tetto: e'
    cio' che libera la coda senza buttare via un indirizzo ignoto."""
    from snapprobe.scanner import (
        ATTESA_RITENTATIVO_BASE_SEC,
        ATTESA_RITENTATIVO_TETTO_SEC,
    )

    # Due abbandoni: l'attesa e' il doppio della base. A un'ora e mezza e' passata,
    # a mezz'ora no.
    _candidato_scaduto(probe_store, "10.10.5.42", quante=2,
                       quando=_istante(ATTESA_RITENTATIVO_BASE_SEC * 2 - 60))
    assert scanner._scadenza_troppo_recente(dict(probe_store.local_node("10.10.5.42")))

    _candidato_scaduto(probe_store, "10.10.5.42", quante=2,
                       quando=_istante(ATTESA_RITENTATIVO_BASE_SEC * 2 + 60))
    assert not scanner._scadenza_troppo_recente(
        dict(probe_store.local_node("10.10.5.42")))

    # Sessantasei abbandoni -- il caso reale -- non danno un'attesa infinita: il
    # tetto la ferma, altrimenti l'host sparirebbe di fatto dall'inventario.
    _candidato_scaduto(probe_store, "10.10.5.42", quante=66,
                       quando=_istante(ATTESA_RITENTATIVO_TETTO_SEC + 60))
    assert not scanner._scadenza_troppo_recente(
        dict(probe_store.local_node("10.10.5.42")))


def test_un_nodo_confermato_non_viene_deprioritizzato(scanner, probe_store):
    """L'attesa riguarda i soli CANDIDATI. Un nodo confermato ha gia' risposto: il
    suo conteggio viene dalla fase di candidato ed e' superato."""
    probe_store.upsert_local_node(
        "10.10.5.50", state="confirmed",
        profile_json=json.dumps({"ip": "10.10.5.50", "timeout_count": 9,
                                 "timed_out_at": _istante(10)}))

    assert not scanner._scadenza_troppo_recente(
        dict(probe_store.local_node("10.10.5.50")))


def test_il_diario_dice_fra_quanto_riprovera(scanner, probe_store):
    """"Riprovato fra sei ore" e "rinunciato" non sono la stessa cosa: chi legge il
    diario deve poterle distinguere."""
    probe_store.upsert_local_node("10.10.5.42", state="candidate")
    scanner._annota_scadenza("10.10.5.42", dict(probe_store.local_node("10.10.5.42")))

    righe = [r["message"] for r in probe_store.recent_events(20)]
    scadenza = [r for r in righe if "abbandonato l'esame per scadenza" in r]
    assert scadenza, "l'abbandono va annunciato"
    assert "riprovato fra" in scadenza[0]
    assert "ignoto, non assente" in scadenza[0]
