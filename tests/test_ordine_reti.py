# -----------------------------------------------------------------
# test_ordine_reti.py — le reti in elenco si ordinano per indirizzo, non per testo
# Autore: Daniele Speziale
# Data creazione: 2026-09-15
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap - L'ordine di un elenco di reti.

Ordinare i CIDR come stringhe mette `10.10.0.0/24` PRIMA di `10.2.0.0/24`, perche' il
carattere `1` viene prima di `2`. In un elenco di trenta reti questo significa che
quella che si cerca non e' dove la si cerca -- e chi guarda conclude che non ci sia.

Il selettore della mappa grafica aveva un difetto in piu': era ordinato per NUMERO DI
DISPOSITIVI. Nessuno apre quel menu chiedendosi quale sia la rete piu' popolosa: si sa
gia' quale rete si vuole disegnare, e la si cerca dove starebbe in un elenco di
indirizzi.

remarks: Autore: Daniele Speziale - Data: 2026-09-15
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import sys
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RADICE / "server"))


def _ordina(cidrs):
    from snapserver.subnets import chiave_ordinamento

    return sorted(cidrs, key=chiave_ordinamento)


def test_l_ordine_e_quello_degli_indirizzi_non_quello_del_testo():
    """E' il difetto: alfabeticamente `10.10` viene prima di `10.2`."""
    assert _ordina(["10.10.0.0/24", "10.2.0.0/24", "10.1.0.0/24"]) == [
        "10.1.0.0/24", "10.2.0.0/24", "10.10.0.0/24"]


def test_regge_i_numeri_a_tre_cifre():
    """E' il caso che rende il difetto evidente su una rete vera."""
    assert _ordina(["10.200.0.0/24", "10.3.0.0/24", "10.99.0.0/24"]) == [
        "10.3.0.0/24", "10.99.0.0/24", "10.200.0.0/24"]


def test_due_reti_dallo_stesso_indirizzo_hanno_un_ordine_stabile():
    """Senza, l'elenco cambierebbe ordine fra due aperture della stessa pagina."""
    assert _ordina(["10.0.0.0/16", "10.0.0.0/8"]) == ["10.0.0.0/8", "10.0.0.0/16"]


def test_le_reti_ipv4_e_ipv6_non_si_mescolano():
    ordinate = _ordina(["fd00::/8", "10.1.0.0/24", "2001:db8::/32", "192.168.1.0/24"])

    assert ordinate[:2] == ["10.1.0.0/24", "192.168.1.0/24"]


def test_cio_che_non_si_interpreta_finisce_in_fondo():
    """Un elenco non deve sollevare per una riga storta, ma nemmeno fingere di saperla
    collocare."""
    ordinate = _ordina(["10.1.0.0/24", "non-una-rete", "10.2.0.0/24"])

    assert ordinate[-1] == "non-una-rete"


def test_la_mappa_grafica_non_ordina_piu_per_numero_di_dispositivi():
    """Nessuno apre quel menu chiedendosi quale sia la rete piu' popolosa."""
    sorgente = (RADICE / "server" / "snapserver" / "blueprints"
                / "inventory.py").read_text(encoding="utf-8")
    inizio = sorgente.index("def network_map_graphic")
    corpo = sorgente[inizio:sorgente.index("def ", inizio + 10)]

    assert "chiave_ordinamento" in corpo
    assert '-v["totale"]' not in corpo
