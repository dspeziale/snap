# -----------------------------------------------------------------
# test_fuso_orario_pagine.py — nessuna pagina stampa un istante in UTC
# Autore: Daniele Speziale
# Data creazione: 2026-09-15
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap - Gli istanti si conservano in UTC e si convertono solo in presentazione.

La conversione sta tutta nei filtri (`dt`, `dts`, `d`, `dtz`, `dtm`, `hms`, `ago`,
`giorno`, `grafico`). Una data stampata senza filtro esce com'e' nell'archivio --
due ore indietro d'estate, una d'inverno -- e NESSUNO SE NE ACCORGE, perche' un
orario sbagliato ha esattamente l'aspetto di un orario giusto. Ci si accorge quando
si confrontano due pagine, o peggio quando si cerca un evento nel punto sbagliato di
un tracciato.

Questo controllo cerca, in ogni modello del server e della sonda, le stampe di un
valore il cui NOME dice che e' un istante e che non passa da nessuno di quei filtri.

L'elenco delle eccezioni e' esplicito e motivato una per una. Un'eccezione senza
motivo scritto e' un difetto rimandato: chi la trova fra sei mesi non sa se fosse una
decisione o una dimenticanza.

remarks: Autore: Daniele Speziale - Data: 2026-09-15
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent

MODELLI = (RADICE / "server" / "snapserver" / "templates",
           RADICE / "probe" / "snapprobe" / "templates")

# I filtri che fanno la conversione. `ago` e `durata` non stampano un'ora ma una
# distanza, e una distanza non dipende dal fuso: contano comunque come trattamento.
FILTRI = ("dt", "dts", "dtz", "dtm", "d", "hms", "ago", "giorno", "grafico",
          "durata", "ora")

# Un nome che, in questo prodotto, contiene un istante.
NOMI_DI_ISTANTE = re.compile(
    r"(^|[._])(at|quando|created|updated|visto|eseguito|inviato|ricevuto|"
    r"ultimo_invio|ultimo_accesso|ultima_at|memoria_dal|timestamp)($|[._])", re.I)

STAMPA = re.compile(r"\{\{(.+?)\}\}", re.S)

# --------------------------------------------------------------------------- #
# Le eccezioni, una per una, con il motivo.
# --------------------------------------------------------------------------- #
AMMESSE = {
    # Il changelog porta una data senza ora ("2026-09-15"): non c'e' un istante da
    # spostare, e mostrarla nel fuso del tenant non cambierebbe un carattere.
    ("base.html", "voce.date"),
    # Idem sulla sonda.
    ("base.html", "voce.date"),
}


def _filtri_di(espressione: str) -> set:
    """Tutti i filtri applicati nell'espressione, anche dentro i rami.

    Una condizionale -- "x|dt if x else 'mai'" -- porta il filtro DENTRO un ramo e
    non in coda: guardare solo la catena di primo livello segnalerebbe come scoperte
    decine di date che sono convertite.
    """
    return set(re.findall(r"\|\s*([a-z_]+)", espressione))


def _scoperte(cartella: Path) -> list:
    trovate = []
    for percorso in sorted(cartella.rglob("*.html")):
        for numero, riga in enumerate(
                percorso.read_text(encoding="utf-8").splitlines(), 1):
            for pezzo in STAMPA.findall(riga):
                espressione = pezzo.strip()
                radice = espressione.split("|")[0].strip()
                nome = re.split(r"[\s(\[]", radice)[0]
                if not NOMI_DI_ISTANTE.search(nome):
                    continue
                if _filtri_di(espressione) & set(FILTRI):
                    continue
                if (percorso.name, espressione) in AMMESSE:
                    continue
                trovate.append("%s:%d  %s" % (
                    percorso.relative_to(RADICE).as_posix(), numero, espressione))
    return trovate


def test_nessuna_pagina_stampa_un_istante_senza_convertirlo():
    scoperte = []
    for cartella in MODELLI:
        scoperte.extend(_scoperte(cartella))

    assert not scoperte, (
        "istanti stampati senza conversione al fuso del tenant:\n  "
        + "\n  ".join(scoperte))


def test_l_ora_dei_pacchetti_non_si_ritaglia_dalla_stringa():
    """E' il difetto da cui si e' partiti: `visto_at[11:19]` prende i caratteri
    dell'ora UTC prima che qualcuno la converta. Su quella pagina l'ora e' l'unica
    colonna che permetta di dire "questo e' successo mentre facevo la prova"."""
    modello = (RADICE / "probe" / "snapprobe" / "templates"
               / "pacchetti.html").read_text(encoding="utf-8")

    assert "[11:19]" not in modello, (
        "un'ora ritagliata dalla stringa salta la conversione al fuso")
    assert "|hms" in modello


def test_il_filtro_delle_date_di_macchina_dichiara_cio_che_non_converte():
    """Nasconderla perderebbe l'unica informazione disponibile; mostrarla senza dire
    niente la farebbe leggere come se fosse nel fuso di chi guarda."""
    import sys

    sys.path.insert(0, str(RADICE / "server"))
    from snapserver.tenancy import fmt_datetime_macchina

    assert fmt_datetime_macchina("") == "-"
    # Una forma che non si interpreta si mostra, dicendolo.
    assert "ora della macchina" in fmt_datetime_macchina("15/09/2026 11:23:44")


def test_l_agente_normalizza_l_ultimo_accesso_alla_fonte():
    """E' l'unico posto che conosca il fuso di quella macchina: convertirla dopo
    significherebbe indovinarlo."""
    sorgente = (RADICE / "agent" / "snap_agent.py").read_text(encoding="utf-8")

    assert "ToUniversalTime()" in sorgente, (
        "LastLogon torna nell'ora locale della macchina osservata")
