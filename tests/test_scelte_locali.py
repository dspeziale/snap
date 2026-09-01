"""
snap - Test della persistenza delle scelte fatte sulla sonda.

Difetto corretto: il server ri-afferma la propria configurazione a ogni contatto,
e il recepimento confrontava il valore consegnato con quello IN USO. Qualunque
scelta fatta in sede veniva quindi annullata entro un ciclo dell'agente, e nel
diario si leggeva il rimbalzo fra la scelta locale e quella centrale.

Regola fissata qui: il valore del server si applica solo quando il server lo
CAMBIA. La sonda ricorda l'ultimo valore ricevuto e confronta con quello.

Eccezione voluta: `scan_enabled` resta autoritativo a ogni contatto, perche' e'
una misura di sicurezza e deve valere anche contro una manomissione locale.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest

PERIMETRO = [{"cidr": "192.0.2.0/24", "label": "", "hosts": 254}]


@pytest.fixture()
def agente(probe_store):
    from snapprobe.agent import ProbeAgent

    return ProbeAgent(probe_store, "1.0.0")


def configurazione(**valori):
    base = {"subnets": PERIMETRO, "scan_effort": "max", "scan_host_timeout": "300s",
            "scan_enabled": True}
    base.update(valori)
    return base


# --------------------------------------------------------------------------- #
# Primo approvvigionamento
# --------------------------------------------------------------------------- #
def test_al_primo_contatto_si_applica_la_configurazione_del_server(agente, probe_store):
    agente._apply_server_config(configurazione())
    assert probe_store.get_setting("scan_effort") == "max"
    assert probe_store.get_setting("scan_host_timeout") == "300s"


def test_l_ultimo_valore_ricevuto_viene_conservato(agente, probe_store):
    """E' il confronto con questo, non con il valore in uso, che salva la scelta locale."""
    agente._apply_server_config(configurazione())
    assert probe_store.get_setting("scan_effort_from_server") == "max"
    assert probe_store.get_setting("scan_host_timeout_from_server") == "300s"


# --------------------------------------------------------------------------- #
# La scelta locale sopravvive
# --------------------------------------------------------------------------- #
def test_lo_sforzo_scelto_in_sede_non_viene_sovrascritto(agente, probe_store):
    agente._apply_server_config(configurazione())
    probe_store.set_setting("scan_effort", "med")

    for _ in range(5):
        agente._apply_server_config(configurazione())

    assert probe_store.get_setting("scan_effort") == "med", (
        "la scelta fatta sulla sonda e' stata annullata dal server"
    )


def test_il_tempo_per_host_scelto_in_sede_non_viene_sovrascritto(agente, probe_store):
    agente._apply_server_config(configurazione())
    probe_store.set_setting("scan_host_timeout", "30s")

    for _ in range(5):
        agente._apply_server_config(configurazione())

    assert probe_store.get_setting("scan_host_timeout") == "30s"


def test_la_scelta_locale_non_lascia_traccia_nel_diario_a_ogni_contatto(agente, probe_store):
    """Il rimbalzo si vedeva nel diario: non deve piu' accadere."""
    agente._apply_server_config(configurazione())
    probe_store.set_setting("scan_effort", "min")
    prima = len(probe_store.recent_events(200))

    for _ in range(5):
        agente._apply_server_config(configurazione())

    dopo = len(probe_store.recent_events(200))
    assert dopo == prima, "il recepimento continua ad annotare cambiamenti inesistenti"


def test_anche_il_valore_vuoto_del_server_e_un_valore(agente, probe_store):
    """Vuoto significa 'quello del profilo', e va distinto da 'non ancora ricevuto'.

    Si verifica il comportamento, non la forma in cui il valore e' memorizzato:
    assente e stringa vuota significano entrambi 'nessuna scelta esplicita'.
    """
    from snapprobe.scanner import NetworkScanner

    agente._apply_server_config(configurazione(scan_host_timeout=""))
    assert NetworkScanner(probe_store).host_timeout() is None
    # Il valore ricevuto viene comunque ricordato, altrimenti la scelta locale
    # successiva verrebbe annullata al primo contatto utile.
    assert probe_store.get_setting("scan_host_timeout_from_server") == ""

    probe_store.set_setting("scan_host_timeout", "60s")
    for _ in range(3):
        agente._apply_server_config(configurazione(scan_host_timeout=""))
    assert NetworkScanner(probe_store).host_timeout() == "60s"


# --------------------------------------------------------------------------- #
# Un cambio deciso dal server prevale
# --------------------------------------------------------------------------- #
def test_un_cambio_dello_sforzo_sul_server_prevale(agente, probe_store):
    agente._apply_server_config(configurazione())
    probe_store.set_setting("scan_effort", "med")
    agente._apply_server_config(configurazione(scan_effort="min"))
    assert probe_store.get_setting("scan_effort") == "min"


def test_un_cambio_del_tempo_sul_server_prevale(agente, probe_store):
    agente._apply_server_config(configurazione())
    probe_store.set_setting("scan_host_timeout", "30s")
    agente._apply_server_config(configurazione(scan_host_timeout="600s"))
    assert probe_store.get_setting("scan_host_timeout") == "600s"


def test_il_cambio_del_server_viene_annotato(agente, probe_store):
    agente._apply_server_config(configurazione())
    agente._apply_server_config(configurazione(scan_effort="min"))
    diario = " ".join(e["message"] for e in probe_store.recent_events(10))
    assert "dal server" in diario and "min" in diario


# --------------------------------------------------------------------------- #
# L'interruttore di sicurezza resta autoritativo
# --------------------------------------------------------------------------- #
def test_l_interruttore_del_server_vale_a_ogni_contatto(agente, probe_store):
    """Non e' una preferenza: e' una misura di sicurezza."""
    agente._apply_server_config(configurazione(scan_enabled=False))
    assert probe_store.get_setting("scan_enabled") == "0"

    # Manomissione locale: il contatto successivo la annulla.
    probe_store.set_setting("scan_enabled", "1")
    agente._apply_server_config(configurazione(scan_enabled=False))
    assert probe_store.get_setting("scan_enabled") == "0"


def test_la_sospensione_locale_non_viene_toccata_dal_server(agente, probe_store):
    """Il controllo locale e' un'impostazione distinta: il server non la governa."""
    probe_store.set_setting("scan_paused", "1")
    for _ in range(3):
        agente._apply_server_config(configurazione(scan_enabled=True))
    assert probe_store.get_setting("scan_paused") == "1"


# --------------------------------------------------------------------------- #
# Il perimetro resta governato dal server
# --------------------------------------------------------------------------- #
def test_il_perimetro_resta_deciso_dal_server(agente, probe_store):
    agente._apply_server_config(configurazione())
    assert probe_store.get_json("scan_subnets") == PERIMETRO
    nuovo = [{"cidr": "10.0.0.0/24", "label": "", "hosts": 254}]
    agente._apply_server_config(configurazione(subnets=nuovo))
    assert probe_store.get_json("scan_subnets") == nuovo


# --------------------------------------------------------------------------- #
# Lo stato dichiara entrambe le volonta'
# --------------------------------------------------------------------------- #
def test_lo_stato_dichiara_anche_cio_che_chiede_il_server(agente, probe_store):
    from snapprobe.scanner import NetworkScanner

    agente._apply_server_config(configurazione())
    probe_store.set_setting("scan_effort", "med")
    probe_store.set_setting("scan_host_timeout", "30s")

    stato = NetworkScanner(probe_store).status()
    assert stato["effort"] == "med"
    assert stato["effort_from_server"] == "max"
    assert stato["host_timeout_chosen"] == "30s"
    assert stato["host_timeout_from_server"] == "300s"
