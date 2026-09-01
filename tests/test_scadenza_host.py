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
    """Chi legge il diario deve capire che il tentativo non e' andato perduto."""
    probe_store.upsert_local_node("10.10.5.42", state="candidate")

    scanner._handle_unconfirmed({"ip": "10.10.5.42", "timed_out": True})

    diario = " ".join(r["message"] for r in probe_store.recent_events(50))
    assert "abbandonato" in diario
    assert "non conta" in diario


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
    probe_store.upsert_local_node(
        "10.10.5.42", state="candidate",
        profile_json=json.dumps({"ip": "10.10.5.42", "timeout_count": 1}))
    profilo = dict(scanner.effort_profile())
    profilo["host_timeout"] = "60s"

    argomenti = scanner._arguments_for("ports", {"raw_sockets": True}, profilo,
                                       hosts=["10.10.5.42"])

    assert "--host-timeout" in argomenti
    assert argomenti[argomenti.index("--host-timeout") + 1] == "120s"
