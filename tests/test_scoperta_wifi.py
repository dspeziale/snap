# -----------------------------------------------------------------
# test_scoperta_wifi.py — le reti senza fili si ricensiscono per conto proprio
# Autore: Daniele Speziale
# Data creazione: 2026-09-15
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap - Una cadenza a parte per le reti senza fili.

PERCHE'. Il perimetro si ricensisce ogni tre giorni, ed e' giusto per una rete
cablata: un indirizzo la' e' quasi un apparato. Su una rete senza fili no -- il DHCP
riassegna, gli apparati entrano ed escono nell'arco di una giornata -- e una scoperta
ogni tre giorni fotografa un momento spacciandolo per lo stato.

DA NON CONFONDERE con la ricognizione delle presenze, che gia' esisteva: quella gira
ogni due minuti ed e' leggera, e risponde a "chi c'e' adesso". Questa e' una scoperta
vera, con le porte e il riconoscimento, e risponde a "che cosa c'e' su questa rete".

remarks: Autore: Daniele Speziale - Data: 2026-09-15
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

RADICE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RADICE / "server"))

PERIMETRO = [
    {"cidr": "10.1.0.0/24", "label": "uffici", "wifi": False},
    {"cidr": "10.2.0.0/24", "label": "senza fili ospiti", "wifi": True},
    {"cidr": "10.3.0.0/24", "label": "senza fili interna", "wifi": True},
]


@pytest.fixture()
def scanner(probe_store):
    from snapprobe.scanner import NetworkScanner

    probe_store.set_json("scan_subnets", PERIMETRO)
    return NetworkScanner(probe_store)


# --------------------------------------------------------------------------- #
# Quali sono, e con che cadenza
# --------------------------------------------------------------------------- #
def test_riconosce_le_reti_senza_fili_dal_perimetro(scanner):
    """Il flag viaggia col perimetro da sempre; lo scanner non lo guardava affatto,
    ed e' tutto cio' che mancava perche' le due cose si potessero separare."""
    assert scanner.reti_senza_fili() == {"10.2.0.0/24", "10.3.0.0/24"}


def test_una_rete_senza_fili_si_ricensisce_piu_spesso_di_una_cablata(scanner):
    cablata = scanner.cadenza_scoperta("10.1.0.0/24")
    senza_fili = scanner.cadenza_scoperta("10.2.0.0/24")

    assert senza_fili < cablata, (
        "una rete che cambia in ore non puo' avere la cadenza di una che cambia in"
        " settimane")


def test_la_cadenza_arriva_dal_server_e_prevale(scanner, probe_store):
    """E' il server a decidere ogni quanto: la sonda ha solo una ricaduta."""
    probe_store.set_json("scan_cadences", {"discovery_wifi": 900})

    assert scanner.cadenza_scoperta("10.2.0.0/24") == 900
    # E non tocca le cablate.
    assert scanner.cadenza_scoperta("10.1.0.0/24") == scanner.cadences()["discovery"]


def test_senza_cadenza_dichiarata_si_usa_la_ricaduta(scanner, probe_store):
    """Un elenco di cadenze che non la nomina non deve far passare `None` al calcolo
    della scadenza: sarebbe una scoperta che non scade mai, o che scade sempre."""
    probe_store.set_json("scan_cadences", {"discovery": 999})

    valore = scanner.cadenza_scoperta("10.2.0.0/24")

    assert isinstance(valore, int) and valore > 0


def test_una_subnet_fuori_dal_perimetro_non_e_senza_fili(scanner):
    """Nel dubbio si usa la cadenza prudente: ricensire troppo spesso una rete che
    non lo chiede e' lavoro buttato sulla rete del cliente."""
    assert scanner.cadenza_scoperta("10.9.9.0/24") == scanner.cadences()["discovery"]


# --------------------------------------------------------------------------- #
# Le due meta'
# --------------------------------------------------------------------------- #
def test_il_server_manda_la_cadenza_che_la_sonda_aspetta():
    """Una cadenza che il server non manda resta alla ricaduta della sonda per
    sempre, e nessuno se ne accorge."""
    from snapprobe.scanner import DEFAULT_CADENCES
    from snapserver.blueprints.api_probe import DEFAULT_SCAN_CADENCES

    assert "discovery_wifi" in DEFAULT_SCAN_CADENCES
    assert "discovery_wifi" in DEFAULT_CADENCES


def test_la_scoperta_delle_senza_fili_e_piu_frequente_anche_nei_valori_del_server():
    from snapserver.blueprints.api_probe import DEFAULT_SCAN_CADENCES

    assert (DEFAULT_SCAN_CADENCES["discovery_wifi"]
            < DEFAULT_SCAN_CADENCES["discovery"])


def test_resta_distinta_dalla_ricognizione_delle_presenze():
    """Sono due cose diverse e devono restarlo: le presenze dicono chi c'e' adesso, la
    scoperta che cosa c'e'. Unirle darebbe una scansione vera ogni due minuti."""
    from snapserver.blueprints.api_probe import DEFAULT_SCAN_CADENCES

    assert (DEFAULT_SCAN_CADENCES["presence"]
            < DEFAULT_SCAN_CADENCES["discovery_wifi"])
