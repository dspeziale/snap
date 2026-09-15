# -----------------------------------------------------------------
# test_sforzi_scansione.py — i profili di sforzo, e le due meta' che devono coincidere
# Autore: Daniele Speziale
# Data creazione: 2026-09-15
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap - Quanti host in parallelo, e chi lo dice a chi.

I profili li ESEGUE la sonda; il server li OFFRE in un menu e li spedisce col comando.
Sono due meta' della stessa cosa, e devono combaciare: un valore che il server accetta
e la sonda non conosce diventa una scelta che non fa niente, e nessuno se ne accorge
finche' qualcuno non va a misurare la scansione.

ERANO DIVERGENTI. Il menu del server dichiarava "medio (2 thread)" e "massimo (4
thread)" mentre i profili della sonda erano 16 e 32: chi sceglieva dal server credeva
di raddoppiare il carico sulla rete del cliente e lo moltiplicava per otto. Nessuna
prova confrontava le due meta', quindi la bugia e' rimasta li'.

remarks: Autore: Daniele Speziale - Data: 2026-09-15
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import sys
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RADICE / "server"))


def _profili():
    from snapprobe.scanner import EFFORT_PROFILES

    return EFFORT_PROFILES


def _server():
    from snapserver.blueprints.api_probe import (
        SCAN_EFFORT_LABELS,
        SCAN_EFFORT_WORKERS,
        SCAN_EFFORTS,
    )

    return SCAN_EFFORTS, SCAN_EFFORT_WORKERS, SCAN_EFFORT_LABELS


# --------------------------------------------------------------------------- #
# I profili chiesti esistono
# --------------------------------------------------------------------------- #
def test_ci_sono_anche_quattro_e_otto_host_in_parallelo():
    """Fra "una per volta" e "sedici" il salto era troppo grande: su una rete piccola
    o delicata sedici sono troppi, uno e' inutilmente lento."""
    profili = _profili()

    assert profili["four"]["workers"] == 4
    assert profili["eight"]["workers"] == 8


def test_i_profili_crescono_davvero():
    """Un elenco che si presenta come una scala deve esserlo: due voci con lo stesso
    numero di processi sarebbero due modi di scrivere la stessa scelta."""
    _, numeri, _ = _server()
    valori = [numeri[chiave] for chiave in _server()[0]]

    assert valori == sorted(valori), valori
    assert len(set(valori)) == len(valori), "due profili con lo stesso parallelismo"


# --------------------------------------------------------------------------- #
# Le due meta' combaciano
# --------------------------------------------------------------------------- #
def test_il_server_offre_esattamente_cio_che_la_sonda_sa_eseguire():
    """Un valore che il server accetta e la sonda non conosce e' una scelta che non
    fa niente: la sonda ricade sul predefinito e nessuno lo dice."""
    ammessi, _, _ = _server()

    assert set(ammessi) == set(_profili()), (
        "il server offre %s, la sonda conosce %s"
        % (sorted(ammessi), sorted(_profili())))


def test_i_numeri_del_menu_sono_quelli_veri():
    """E' il difetto trovato: il menu diceva 2 e 4 dove la sonda ne usa 16 e 32. Chi
    sceglie deve sapere che carico mette sulla rete del cliente."""
    _, numeri, _ = _server()
    profili = _profili()

    for chiave, quanti in numeri.items():
        assert profili[chiave]["workers"] == quanti, (
            "il server dice %d processi per %r, la sonda ne usa %d"
            % (quanti, chiave, profili[chiave]["workers"]))


def test_ogni_profilo_ha_un_etichetta_che_dice_il_parallelismo():
    """L'etichetta e' l'unica cosa che chi sceglie legge: se non dice quanti host in
    parallelo, la scelta si fa alla cieca."""
    ammessi, numeri, etichette = _server()

    for chiave in ammessi:
        assert chiave in etichette, "manca l'etichetta di %r" % chiave
        assert str(numeri[chiave]) in etichette[chiave], (
            "l'etichetta di %r non dice quanti host: %r" % (chiave, etichette[chiave]))


def test_ogni_profilo_della_sonda_si_descrive():
    """La sonda mostra la propria etichetta nella pagina di stato."""
    for chiave, voce in _profili().items():
        assert voce.get("label"), "il profilo %r non si descrive" % chiave
        assert voce["hosts_per_task"] == 1, (
            "un host per compito: e' l'assunto su cui e' tarato il parallelismo")


# --------------------------------------------------------------------------- #
# Il menu non riscrive a mano cio' che gia' esiste
# --------------------------------------------------------------------------- #
def test_il_menu_non_scrive_a_mano_le_etichette():
    """E' cosi' che le due meta' erano divergute: due elenchi, uno dei quali
    dimenticato."""
    modello = (RADICE / "server" / "snapserver" / "templates" / "probes"
               / "detail.html").read_text(encoding="utf-8")

    assert "etichette_sforzo" in modello
    # Si cerca la FORMA con cui erano scritte a mano -- l'elenco di coppie dentro il
    # `for` -- e non la parola "thread", che compare nel commento che spiega perche'
    # quell'elenco e' stato tolto.
    corpo = modello.split("{% for valore in sforzi %}")[0]
    assert "('min'," not in corpo and '("min",' not in corpo, (
        "il menu torna a elencare a mano i profili, che e' come si sono scollati")
