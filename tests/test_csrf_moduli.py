"""
snap - Test: ogni modulo che scrive porta il proprio token anti-CSRF.

PERCHE' ESISTE
Segnalato da chi lo usava: «sono appena entrato con la password, non e' vero che la
pagina era aperta da troppo tempo». Aveva ragione. Quattro moduli aggiunti da poco --
i tre della pagina Agenti e quello dell'osservazione del traffico -- non avevano MAI
avuto un token: non erano scaduti, non c'erano proprio, e nessuno dei quattro poteva
funzionare.

E' un difetto che si nasconde bene:

* il modulo si disegna, si preme il bottone, e la pagina torna con un avviso
  plausibile;
* l'avviso incolpava la pagina rimasta aperta, cioe' la sola causa che NON era;
* i test che guardano la pagina (`GET`) passano tutti, perche' il modulo c'e';
* e i test che PROVANO le rotte passano anche loro, perche' in `TestConfig`
  `WTF_CSRF_ENABLED = False` -- giustamente, o ogni test dovrebbe procurarsi un token
  prima di poter provare qualunque cosa. Dodici prove sulle rotte degli agenti
  passavano su moduli che nel browser non funzionavano.

Per questo il controllo e' sui MODELLI e non sulle risposte: con la protezione spenta
nei test, il solo posto dove il difetto e' visibile e' il file del modello.

CHE COSA CONTROLLA
Che ogni `<form method="post">` dei modelli di entrambi gli applicativi contenga un
`csrf_token()`. Le eccezioni non esistono: se un giorno servisse un modulo esente,
andrebbe esentato esplicitamente in `CSRFProtect`, e allora il controllo qui si
aggiornerebbe con il motivo scritto accanto.

remarks: Autore: Daniele Speziale - Data: 2026-09-13
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

RADICE = Path(__file__).resolve().parent.parent

CARTELLE = (
    "server/snapserver/templates",
    "probe/snapprobe/templates",
)

# Un `<form ...>` con il suo contenuto fino alla chiusura. Non `.*?` sul file intero:
# servono i confini del modulo, altrimenti un token di un modulo vicino sembrerebbe
# appartenere a questo.
RE_FORM = re.compile(r"<form\b[^>]*>(.*?)</form>", re.S | re.I)
RE_METODO = re.compile(r'method\s*=\s*["\']post["\']', re.I)


def _moduli_che_scrivono():
    """`(file, riga, apertura, corpo)` per ogni modulo POST dei modelli."""
    trovati = []
    for cartella in CARTELLE:
        for modello in sorted((RADICE / cartella).rglob("*.html")):
            testo = modello.read_text(encoding="utf-8")
            for trovato in RE_FORM.finditer(testo):
                apertura = testo[trovato.start():trovato.start() + 200]
                if not RE_METODO.search(apertura.split(">", 1)[0]):
                    continue
                riga = testo.count("\n", 0, trovato.start()) + 1
                trovati.append((modello, riga, apertura.split(">", 1)[0],
                                trovato.group(1)))
    return trovati


def test_ci_sono_moduli_da_controllare():
    """Se l'espressione smettesse di trovarli, il test passerebbe senza guardare
    niente: e' il modo piu' silenzioso di perdere una protezione."""
    assert len(_moduli_che_scrivono()) > 15


def test_ogni_modulo_che_scrive_porta_il_token():
    """Un modulo senza token non e' un modulo che a volte fallisce: e' un modulo che
    non funziona mai, e l'avviso che riceve chi lo usa punta altrove."""
    mancanti = []
    for modello, riga, apertura, corpo in _moduli_che_scrivono():
        if "csrf_token()" not in corpo:
            mancanti.append("%s:%d %s" % (modello.name, riga, apertura[:60]))
    assert not mancanti, (
        "moduli POST senza token anti-CSRF:\n  " + "\n  ".join(mancanti))


def test_il_token_sta_dentro_al_modulo_non_accanto():
    """Un `csrf_token()` scritto fuori dal `<form>` non viene inviato.

    Sembra ovvio e non lo e': il modello ha il token, la ricerca nel file lo trova, e
    il modulo continua a non funzionare.
    """
    for modello, riga, apertura, corpo in _moduli_che_scrivono():
        if "csrf_token()" not in corpo:
            continue
        assert re.search(r'name\s*=\s*["\']csrf_token["\']', corpo), (
            "%s:%d il token non e' un campo inviato con il modulo" % (modello.name, riga))


# --------------------------------------------------------------------------- #
# Il messaggio non deve dare per certa una causa che non conosce
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("modulo", ("server/snapserver/__init__.py",
                                    "probe/snapprobe/__init__.py"))
def test_il_messaggio_non_incolpa_la_pagina_aperta_da_troppo_tempo(modulo):
    """Il token puo' mancare per almeno tre motivi. Dichiararne uno solo manda a
    cercare dalla parte sbagliata -- ed e' successo: la segnalazione che ha fatto
    nascere questo file diceva «sono appena entrato con la password»."""
    testo = (RADICE / modulo).read_text(encoding="utf-8")
    assert "aperta da troppo tempo e il token" not in testo, (
        "%s dichiara come certa una causa che non conosce" % modulo)
