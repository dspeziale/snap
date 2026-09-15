# -----------------------------------------------------------------
# test_mac_costruttori_server.py — dal MAC al costruttore, sul server
# Autore: Daniele Speziale
# Data creazione: 2026-09-15
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap - Il catalogo IEEE dei prefissi, e le due trappole che nasconde.

PRIMA TRAPPOLA: I PREFISSI NON SONO TUTTI LUNGHI UGUALE. Lo IEEE assegna blocchi
grandi (MA-L, 6 cifre), medi (MA-M, 7) e piccoli (MA-S, 9). Un blocco piccolo e'
CONDIVISO fra molte aziende, e guardare i soli primi tre byte darebbe il nome di chi
ha rivenduto il blocco invece di quello dell'azienda. Si cerca dal piu' lungo.

SECONDA TRAPPOLA: I MAC ARRIVANO SCRITTI IN TUTTI I MODI -- due punti, trattini,
punti ogni quattro cifre, maiuscoli, minuscoli. Confrontarli senza normalizzarli
significa non trovare niente per meta' delle sorgenti, e la meta' che fallisce cambia
a seconda di chi ha raccolto il dato.

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

# Il formato vero del registro IEEE, com'e' nel file.
OUI_GRANDE = """
OUI Organization
company_id Organization
           Address

803F5D     (base 16)\t\tWistron Neweb Corporation
0050C2     (base 16)\t\tIEEE Registration Authority
"""

# Un blocco piccolo, NEL FORMATO VERO del file `oui36.txt`: il record sta su DUE
# righe -- l'OUI di 24 bit sulla prima, l'intervallo assegnato dentro di esso sulla
# seconda. Il prefisso vero e' la somma: `0050C2` + `ED0`.
#
# Scritto cosi' perche' il formato l'avevo indovinato, e sbagliato: cercando il
# prefisso su una riga sola i due file piu' specifici caricavano ZERO voci.
OUI_PICCOLO = """
OUI-36 Organization
company_id Organization

00-50-C2   (hex)\t\tOfficina Elettronica Esempio
ED0000-ED0FFF     (base 16)\t\tOfficina Elettronica Esempio
"""

# Un blocco medio: un solo carattere fisso invece di tre. Quanti ne siano lo dice
# l'INTERVALLO, non il nome del file.
OUI_MEDIO = """
OUI-28 Organization

C8-5C-E2   (hex)\t\tSynergy Systems
700000-7FFFFF     (base 16)\t\tSynergy Systems
"""


@pytest.fixture()
def catalogo(server_app):
    from snapserver import mac_costruttori

    with server_app.app_context():
        mac_costruttori.importa_testo(OUI_GRANDE, "MA-L")
        mac_costruttori.importa_testo(OUI_MEDIO, "MA-M")
        mac_costruttori.importa_testo(OUI_PICCOLO, "MA-S")
        yield mac_costruttori


# --------------------------------------------------------------------------- #
# Si legge il registro
# --------------------------------------------------------------------------- #
def test_carica_le_voci_del_registro(catalogo):
    assert catalogo.stato()["prefissi"] == 4


def test_compone_il_prefisso_dei_blocchi_a_due_righe(catalogo):
    """Nei file dei blocchi medi e piccoli il prefisso sta su DUE righe: l'OUI sulla
    prima, l'intervallo assegnato sulla seconda. Cercandolo su una riga sola non se ne
    trovava nessuno, e i due cataloghi piu' specifici restavano vuoti -- cioe' proprio
    quelli che servono a non rispondere "IEEE Registration Authority"."""
    assert catalogo.costruttore("c8:5c:e2:7a:bb:cc") == "Synergy Systems"


def test_la_lunghezza_del_prefisso_la_dice_l_intervallo(catalogo):
    """Un carattere fisso per i blocchi medi, tre per i piccoli. Ricavarlo
    dall'intervallo invece che dal nome del file significa che i due formati si
    leggono con lo stesso codice."""
    from snapserver.mac_costruttori import _parte_fissa

    assert _parte_fissa("700000", "7FFFFF") == "7"
    assert _parte_fissa("ED0000", "ED0FFF") == "ED0"


def test_trova_il_costruttore_di_un_mac(catalogo):
    assert catalogo.costruttore("80:3f:5d:ff:2e:31") == "Wistron Neweb Corporation"


@pytest.mark.parametrize("scritto", [
    "80:3F:5D:FF:2E:31",
    "80-3f-5d-ff-2e-31",
    "803f.5dff.2e31",
    "803F5DFF2E31",
    " 80:3f:5d:ff:2e:31 ",
])
def test_lo_trova_comunque_sia_scritto(catalogo, scritto):
    """I MAC arrivano da nmap, da SNMP, dal traffico e dagli agenti, ciascuno con la
    propria punteggiatura: confrontarli senza normalizzarli significa non trovare
    niente per meta' delle sorgenti."""
    assert catalogo.costruttore(scritto) == "Wistron Neweb Corporation"


# --------------------------------------------------------------------------- #
# Il prefisso piu' lungo vince
# --------------------------------------------------------------------------- #
def test_un_blocco_piccolo_vince_sul_blocco_grande(catalogo):
    """`0050C2` e' il blocco che lo IEEE tiene per riassegnarlo a pezzi: fermarsi li'
    darebbe "IEEE Registration Authority" per ogni apparato che ne fa parte, cioe' un
    nome che non dice niente al posto di quello vero."""
    assert catalogo.costruttore("00:50:c2:ed:01:23") == "Officina Elettronica Esempio"


def test_fuori_dal_blocco_piccolo_resta_quello_grande(catalogo):
    """La ricerca deve essere PIU' SPECIFICA, non semplicemente diversa."""
    assert catalogo.costruttore("00:50:c2:11:22:33") == "IEEE Registration Authority"


# --------------------------------------------------------------------------- #
# Quando non si sa
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("valore", ["", None, "non-un-mac", "zz:zz", "12:34"])
def test_cio_che_non_e_un_mac_non_da_un_nome(catalogo, valore):
    assert catalogo.costruttore(valore) == ""


def test_un_prefisso_non_assegnato_non_si_inventa(catalogo):
    """Un nome inventato e' peggio di nessun nome: chi legge lo userebbe per decidere
    che tipo di apparato e'."""
    assert catalogo.costruttore("ff:ee:dd:cc:bb:aa") == ""


def test_senza_catalogo_non_fallisce_niente(server_app):
    """Su un server senza uscita verso internet il catalogo puo' non essere mai stato
    caricato: i MAC si mostrano come si sono sempre mostrati."""
    from snapserver.mac_costruttori import costruttore

    with server_app.app_context():
        assert costruttore("80:3f:5d:ff:2e:31") == ""


# --------------------------------------------------------------------------- #
# Il caricamento da file, che e' il caso che conta
# --------------------------------------------------------------------------- #
def test_si_puo_caricare_da_un_file_senza_internet(server_app):
    """E' il modo di popolarlo dove il server non ha uscita: si porta il file a mano.
    Un prodotto che funziona solo con internet non e' utilizzabile in mezza PA."""
    from snapserver.mac_costruttori import importa_testo

    with server_app.app_context():
        quante = importa_testo(OUI_GRANDE, "MA-L")

    assert quante == 2


def test_il_comando_esiste():
    """Senza un comando, "si carica a mano" resta una frase."""
    from snapserver.db import carica_oui_command

    assert carica_oui_command.name == "carica-oui"


# --------------------------------------------------------------------------- #
# La pagina
# --------------------------------------------------------------------------- #
def test_la_pagina_dichiara_se_il_catalogo_manca(logged_client):
    testo = logged_client.get("/inventory/reti-pubbliche").get_data(as_text=True)

    assert "Catalogo non ancora caricato" in testo
    assert "carica-oui" in testo
