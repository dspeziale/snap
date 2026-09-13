"""
snap - Test della coerenza delle versioni.

PERCHE' ESISTE
Un numero di versione e' scritto in sette posti: il modulo di configurazione, il
changelog, il file `.env` e il suo esempio, il `docker-compose.yml`, il commento del
Dockerfile, l'intestazione dei documenti. Sette copie dello stesso numero divergono, e
quella sbagliata e' sempre quella che si legge in esercizio.

E' successo: il `docker-compose.yml` del SERVER ripiegava su `snap-server:1.2.8`, cioe'
il numero della SONDA. Un `docker compose up` senza un file `.env` avrebbe costruito
un'immagine del server con la versione della sonda scritta sopra, e in assistenza
nessuno avrebbe capito che cosa stava guardando.

CHE COSA NON VERIFICA
Che il numero sia quello "giusto": nessun test puo' saperlo. Verifica che i posti in
cui e' scritto dicano tutti la stessa cosa, e che il changelog parli della versione in
vigore -- che e' la regola di progetto (vedi la memoria "changelog al cambio versione").

remarks: Autore: Daniele Speziale - Data: 2026-09-13
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

RADICE = Path(__file__).resolve().parent.parent

# (nome, versione dichiarata dall'applicativo, file dove quel numero si ripete)
#
# L'agente non ha un `.env` obbligatorio ne' un compose di esercizio: il suo numero
# vive nel sorgente, nell'esempio, nel compose del pacchetto e nel LEGGIMI.
APPLICATIVI = ("console", "sonda", "agente")


def _versione_console() -> str:
    from snapserver.settings import Config

    return Config.APP_VERSION


def _versione_sonda() -> str:
    from snapprobe.settings import Config

    return Config.APP_VERSION


def _versione_agente() -> str:
    sorgente = (RADICE / "agent" / "snap_agent.py").read_text(encoding="utf-8")
    trovato = re.search(r'^VERSIONE = "([^"]+)"', sorgente, re.M)
    assert trovato, "l'agente non dichiara una versione"
    return trovato.group(1)


VERSIONE = {
    "console": _versione_console,
    "sonda": _versione_sonda,
    "agente": _versione_agente,
}

# Dove lo stesso numero e' ripetuto, e con quale espressione lo si trova.
RIPETIZIONI = {
    "console": (
        ("docker/server/.env.example", r"SNAP_VERSION=(\S+)"),
        ("docker/server/docker-compose.yml",
         r"image: snap-server:\$\{SNAP_VERSION:-([^}]+)\}"),
        ("docker/server/Dockerfile", r"-t snap-server:(\S+) \."),
    ),
    "sonda": (
        ("docker/probe/.env.example", r"SNAP_VERSION=(\S+)"),
        ("docker/probe/docker-compose.yml",
         r"image: snap-probe:\$\{SNAP_VERSION:-([^}]+)\}"),
        ("docker/probe/Dockerfile", r"-t snap-probe:(\S+) \."),
    ),
    "agente": (
        ("agent/docker/.env.example", r"SNAP_AGENT_VERSIONE=(\S+)"),
        ("agent/docker/docker-compose.yml",
         r"image: snap-agent:\$\{SNAP_AGENT_VERSIONE:-([^}]+)\}"),
        ("agent/docker/Dockerfile", r"-t snap-agent:(\S+) \."),
        ("agent/LEGGIMI.md", r"\| Contiene \| agente (\S+),"),
    ),
}


def _versione_nel_file(percorso: str, espressione: str) -> str:
    testo = (RADICE / percorso).read_text(encoding="utf-8")
    trovato = re.search(espressione, testo, re.M)
    assert trovato, "%s: non si trova la versione con %r" % (percorso, espressione)
    return trovato.group(1)


# --------------------------------------------------------------------------- #
# Lo stesso numero, ovunque sia scritto
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("applicativo", APPLICATIVI)
def test_la_versione_e_la_stessa_in_ogni_file(applicativo):
    """Sette copie dello stesso numero divergono; quella sbagliata e' quella che si
    legge in esercizio."""
    attesa = VERSIONE[applicativo]()
    discordanti = []
    for percorso, espressione in RIPETIZIONI[applicativo]:
        trovata = _versione_nel_file(percorso, espressione)
        if trovata != attesa:
            discordanti.append("%s dice %s" % (percorso, trovata))
    assert not discordanti, (
        "%s e' alla %s, ma: %s" % (applicativo, attesa, "; ".join(discordanti)))


@pytest.mark.parametrize("applicativo", ("console", "sonda", "agente"))
def test_la_versione_ha_la_forma_attesa(applicativo):
    assert re.fullmatch(r"\d+\.\d+\.\d+", VERSIONE[applicativo]()), (
        "%s: versione in forma inattesa" % applicativo)


# --------------------------------------------------------------------------- #
# Il compose di ciascuno nomina il PROPRIO applicativo
# --------------------------------------------------------------------------- #
def test_ogni_compose_nomina_la_propria_immagine():
    """La deriva che ha motivato questo file: il compose del server ripiegava sul
    numero della sonda, e nessun test se ne accorgeva."""
    coppie = (
        ("docker/server/docker-compose.yml", "snap-server"),
        ("docker/probe/docker-compose.yml", "snap-probe"),
        ("agent/docker/docker-compose.yml", "snap-agent"),
    )
    for percorso, immagine in coppie:
        testo = (RADICE / percorso).read_text(encoding="utf-8")
        assert "image: %s:" % immagine in testo, (
            "%s non costruisce un'immagine %s" % (percorso, immagine))


# --------------------------------------------------------------------------- #
# Il changelog parla della versione in vigore
# --------------------------------------------------------------------------- #
def test_il_changelog_della_console_apre_con_la_versione_in_vigore():
    """Regola di progetto: quando cambia APP_VERSION si aggiunge la voce in cima."""
    from snapserver.changelog import CHANGELOG

    assert CHANGELOG[0]["version"] == _versione_console()


def test_il_changelog_della_sonda_apre_con_la_versione_in_vigore():
    from snapprobe.changelog import CHANGELOG

    assert CHANGELOG[0]["version"] == _versione_sonda()


@pytest.mark.parametrize("modulo", ("snapserver", "snapprobe"))
def test_ogni_voce_di_changelog_dice_che_cosa_e_cambiato(modulo):
    """Una voce senza contenuto e' un numero che avanza senza motivo: chi cerca
    quando una cosa e' cambiata non deve trovare una riga vuota."""
    import importlib

    changelog = importlib.import_module("%s.changelog" % modulo).CHANGELOG
    for voce in changelog:
        assert voce.get("date"), voce["version"]
        assert len(voce.get("abstract", "")) > 40, voce["version"]
        assert voce.get("changes"), voce["version"]


def test_le_versioni_non_si_ripetono():
    """Due voci con lo stesso numero significano che una delle due e' stata
    dimenticata, e la seconda non si leggerebbe mai."""
    from snapprobe.changelog import CHANGELOG as SONDA
    from snapserver.changelog import CHANGELOG as CONSOLE

    for nome, changelog in (("console", CONSOLE), ("sonda", SONDA)):
        numeri = [v["version"] for v in changelog]
        ripetuti = {n for n in numeri if numeri.count(n) > 1}
        assert not ripetuti, "%s: versioni ripetute %s" % (nome, sorted(ripetuti))


# --------------------------------------------------------------------------- #
# I documenti dichiarano che cosa documentano
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("documento", ("docs/16_INSTALLAZIONE_DA_ZERO.md",
                                       "docs/17_IDS_E_AGENTI.md"))
def test_i_documenti_dichiarano_le_versioni_in_vigore(documento):
    """Un manuale che documenta una versione precedente e' un manuale che descrive
    pagine che non esistono piu'."""
    testo = (RADICE / documento).read_text(encoding="utf-8")
    trovato = re.search(r"Versione documentata \| console (\S+), sonda (\S+),"
                        r" agente (\S+) \|", testo)
    assert trovato, "%s non dichiara le versioni documentate" % documento
    assert trovato.group(1) == _versione_console(), documento
    assert trovato.group(2) == _versione_sonda(), documento
    assert trovato.group(3) == _versione_agente(), documento
