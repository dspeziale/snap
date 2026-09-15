# -----------------------------------------------------------------
# test_ricerca_mac.py — un MAC si cerca comunque lo si scriva
# Autore: Daniele Speziale
# Data creazione: 2026-09-15
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap - Cercare un indirizzo fisico.

UN MAC SI SCRIVE IN TRE MODI -- `80:3f:5d:ff:2e:31`, `80-3f-5d-ff-2e-31`,
`803f5dff2e31` -- a seconda di dove lo si e' letto: l'etichetta sotto un apparato usa
quasi sempre il formato compatto, la pagina di amministrazione di un router i
trattini, nmap i due punti.

La ricerca libera dei nodi confrontava il testo com'e' scritto: due ricerche su tre
non trovavano niente. E il modo in cui falliva era il peggiore possibile -- "nessun
risultato", indistinguibile da "quell'apparato non e' in inventario".

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

MAC = "80:3F:5D:FF:2E:31"


@pytest.fixture()
def nodo(server_app):
    """Un nodo con un MAC scritto come lo scrive nmap: con i due punti."""
    from snapserver.db import execute, query, utc_now_str

    with server_app.app_context():
        tenant = query("SELECT id FROM tenants ORDER BY id LIMIT 1", (), one=True)
        execute(
            "INSERT INTO nodes (tenant_id, ip, mac, mac_vendor, status, first_seen_at,"
            " last_seen_at, created_at, updated_at)"
            " VALUES (?, '10.20.10.77', ?, 'Wistron', 'up', ?, ?, ?, ?)",
            (int(tenant["id"]), MAC, utc_now_str(), utc_now_str(), utc_now_str(),
             utc_now_str()))
        return int(tenant["id"])


def _cerca(tenant_id, testo):
    from snapserver.inventory_queries import nodes_list

    return nodes_list(tenant_id, text=testo)


# --------------------------------------------------------------------------- #
# Comunque lo si scriva
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("scritto", [
    "80:3F:5D:FF:2E:31",       # come lo scrive nmap
    "80-3f-5d-ff-2e-31",       # come lo scrive la pagina di un router
    "803f5dff2e31",            # come sta sull'etichetta sotto l'apparato
    "803F5D",                  # il solo prefisso del costruttore
    "ff:2e:31",                # la coda, che e' cio' che si legge da lontano
])
def test_lo_trova_comunque_sia_scritto(server_app, nodo, scritto):
    with server_app.app_context():
        esito = _cerca(nodo, scritto)

    indirizzi = [r["ip"] for r in esito]
    assert "10.20.10.77" in indirizzi, "cercando %r non si trova" % scritto


def test_la_ricerca_per_nome_continua_a_funzionare(server_app, nodo):
    """Spogliare della punteggiatura una ricerca per "Wistron" non avrebbe senso: la
    ricerca normale resta quella di prima, e quella sui MAC si aggiunge."""
    with server_app.app_context():
        esito = _cerca(nodo, "Wistron")

    assert [r["ip"] for r in esito] == ["10.20.10.77"]


def test_un_mac_di_un_altro_apparato_non_si_trova(server_app, nodo):
    """La ricerca deve restare una ricerca: se trovasse tutto sarebbe inutile."""
    with server_app.app_context():
        esito = _cerca(nodo, "aa:bb:cc:dd:ee:ff")

    assert list(esito) == []


def test_un_testo_corto_non_diventa_una_ricerca_di_mac(server_app, nodo):
    """`_solo_esadecimali` toglie la punteggiatura da qualunque testo: senza una
    soglia, cercare "ab" confronterebbe due lettere con le cifre di ogni indirizzo
    fisico in inventario."""
    from snapserver.inventory_queries import _solo_esadecimali

    assert _solo_esadecimali("ab") == "AB"
    assert len(_solo_esadecimali("ab")) < 4


def test_cio_che_non_e_esadecimale_non_produce_una_condizione(server_app, nodo):
    from snapserver.inventory_queries import _solo_esadecimali

    assert _solo_esadecimali("stampante") == "AAE"     # le sole a, a ed e
    assert _solo_esadecimali("") == ""
    assert _solo_esadecimali(None) == ""


# --------------------------------------------------------------------------- #
# La ricerca nel catalogo dei costruttori
# --------------------------------------------------------------------------- #
def test_la_pagina_cerca_un_mac_nel_catalogo(logged_client, server_app):
    from snapserver.mac_costruttori import importa_testo

    with server_app.app_context():
        importa_testo("803F5D     (base 16)\t\tWistron Neweb Corporation", "MA-L")

    testo = logged_client.get(
        "/inventory/reti-pubbliche?mac=803f5dff2e31").get_data(as_text=True)

    assert "Wistron Neweb Corporation" in testo


def test_un_mac_sconosciuto_spiega_perche(logged_client):
    """Un esito vuoto non dice se il prefisso non esista o se il catalogo non sia
    stato caricato: chi guarda deve poter distinguere."""
    testo = logged_client.get(
        "/inventory/reti-pubbliche?mac=aabbccddeeff").get_data(as_text=True)

    assert "non presente nel catalogo" in testo
    assert "amministrato localmente" in testo


def test_un_testo_che_non_e_un_mac_lo_dice(logged_client):
    testo = logged_client.get(
        "/inventory/reti-pubbliche?mac=stampante").get_data(as_text=True)

    assert "Non sembra un indirizzo fisico" in testo
