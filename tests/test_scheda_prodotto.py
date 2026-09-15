# -----------------------------------------------------------------
# test_scheda_prodotto.py — la scheda di prodotto sta in quattro pagine
# Autore: Daniele Speziale
# Data creazione: 2026-09-15
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap - La scheda che si consegna alla direzione.

E' stata chiesta di quattro pagine, e un limite dichiarato e non verificato e'
un'intenzione: qui si genera il documento e si CONTANO le pagine. Se domani qualcuno
aggiunge una sezione, se ne accorge questo invece del destinatario.

L'altra proprieta' che vale la pena difendere: e' un documento di PRODOTTO, quindi
non contiene i dati di nessuna rete. Il pie' di pagina lo dichiara, e lo dichiara
perche' la cornice dei report cambia avvertenza quando il tenant e' vuoto.

remarks: Autore: Daniele Speziale - Data: 2026-09-15
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

RADICE = Path(__file__).resolve().parent.parent


def _scheda(tmp_path):
    sys.path.insert(0, str(RADICE / "tools"))
    import genera_scheda_prodotto

    percorso = tmp_path / "scheda.pdf"
    genera_scheda_prodotto.scheda(percorso, "9.9.9")
    return percorso, genera_scheda_prodotto


def test_la_scheda_sta_nel_numero_di_pagine_chiesto(tmp_path):
    """Quattro pagine chieste, quattro consegnate."""
    pypdf = pytest.importorskip("pypdf")
    percorso, modulo = _scheda(tmp_path)

    pagine = len(pypdf.PdfReader(str(percorso)).pages)

    assert pagine <= modulo.PAGINE_MASSIME, (
        "la scheda occupa %d pagine, il massimo dichiarato e' %d"
        % (pagine, modulo.PAGINE_MASSIME))
    # E non deve essere diventata una paginetta: se una sezione sparisce, qui si vede.
    assert pagine >= 3, "la scheda si e' accorciata: manca qualcosa?"


def test_la_scheda_non_contiene_dati_di_rete(tmp_path):
    """E' un documento di prodotto e lo dichiara nel pie' di pagina: la cornice dei
    report cambia avvertenza quando il tenant e' vuoto, e qui deve essere quella."""
    pypdf = pytest.importorskip("pypdf")
    percorso, _ = _scheda(tmp_path)

    testo = "\n".join((p.extract_text() or "")
                      for p in pypdf.PdfReader(str(percorso)).pages)

    assert "non contiene dati di rete" in testo
    assert "Documento riservato" not in testo


def test_la_scheda_dichiara_la_versione_del_prodotto(tmp_path):
    """Un documento che si consegna senza dire di quale versione parla invecchia
    senza che nessuno se ne accorga."""
    pypdf = pytest.importorskip("pypdf")
    percorso, _ = _scheda(tmp_path)

    testo = "\n".join((p.extract_text() or "")
                      for p in pypdf.PdfReader(str(percorso)).pages)

    assert "9.9.9" in testo, "la versione passata non compare nel documento"


def test_la_scheda_dice_anche_i_limiti(tmp_path):
    """La sezione che di solito manca in un documento commerciale, ed e' quella per
    cui questo prodotto viene scelto: i limiti sono scritti, non taciuti."""
    pypdf = pytest.importorskip("pypdf")
    percorso, _ = _scheda(tmp_path)

    testo = "\n".join((p.extract_text() or "")
                      for p in pypdf.PdfReader(str(percorso)).pages)

    assert "limiti dichiarati" in testo
    assert "nessuna intrusione" in testo


def test_le_tabelle_in_prosa_non_usano_il_monospazio(tmp_path):
    """Il monospazio della prima colonna serve a incolonnare indirizzi IP. In una
    tabella di prosa fa l'effetto opposto, e la cornice ora permette di spegnerlo
    per una singola tabella -- senza cambiarlo per i report, che lo vogliono."""
    sys.path.insert(0, str(RADICE / "server"))
    from snapserver.reports.render_pdf import Foglio

    foglio = Foglio(tmp_path / "prova.pdf", kind="executive", titolo="P",
                    tenant="", intervallo="p", generato="2026-09-15 00:00:00")
    foglio.tabella(["A", "B"], [["uno", "due"]], mono_prima=False)
    # Dopo la tabella il valore predefinito torna: la scelta vale per una sola
    # tabella, altrimenti cambierebbe l'aspetto di tutte quelle che seguono.
    assert foglio._mono_prima is True
    foglio.salva()
