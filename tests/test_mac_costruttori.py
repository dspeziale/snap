"""
snap - Test del catalogo dei costruttori ricavati dal prefisso del MAC.

Perche' esiste: i MAC riferiti dalla tabella ARP di un apparato non passano da nmap,
quindi arrivavano senza il nome del costruttore -- che e' la parte del MAC che serve
davvero al riconoscimento di un apparato muto. Il catalogo e' quello che nmap
distribuisce con se', cosi' un MAC osservato e uno riferito ottengono la stessa
risposta e non due nomi diversi per la stessa scheda.

Proprieta' verificate: si legge il formato di `nmap-mac-prefixes` (commenti compresi);
il prefisso si riconosce in qualunque scrittura del MAC; un prefisso sconosciuto da'
`None` invece di un nome inventato; l'assenza del catalogo non e' un errore.

remarks: Autore: Daniele Speziale - Data: 2026-09-09
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest

from snapprobe import mac_costruttori


CATALOGO = """\
# Questo file e' un elenco di prefissi: commento da ignorare.
000000 XEROX CORPORATION
B827EB Raspberry Pi Foundation
0018FE Hewlett Packard
"""


@pytest.fixture(autouse=True)
def catalogo_finto(tmp_path, monkeypatch):
    """Un catalogo scritto qui, non quello della macchina: il test non deve
    dipendere da quale nmap sia installato dove gira."""
    percorso = tmp_path / "nmap-mac-prefixes"
    percorso.write_text(CATALOGO, encoding="utf-8")
    monkeypatch.setenv("SNAP_PROBE_NMAP_MAC_PREFIXES", str(percorso))
    # Il catalogo si carica una volta sola: fra un test e l'altro va dimenticato.
    monkeypatch.setattr(mac_costruttori, "_catalogo", None)
    monkeypatch.setattr(mac_costruttori, "_percorso_usato", None)
    return percorso


def test_si_legge_il_formato_di_nmap():
    assert mac_costruttori.quanti_prefissi() == 3
    assert mac_costruttori.catalogo_disponibile() is True


@pytest.mark.parametrize("scritto", [
    "B8:27:EB:1A:2B:3C",
    "b8:27:eb:1a:2b:3c",
    "B8-27-EB-1A-2B-3C",
    "b827eb1a2b3c",
    "B827.EB1A.2B3C",
])
def test_il_prefisso_si_riconosce_in_qualunque_scrittura(scritto):
    """Gli apparati scrivono il MAC in modi diversi: due punti, trattini, punti,
    maiuscole o minuscole. E' lo stesso indirizzo, e deve dare lo stesso nome."""
    assert mac_costruttori.costruttore(scritto) == "Raspberry Pi Foundation"


def test_un_prefisso_sconosciuto_non_si_inventa():
    """I MAC amministrati localmente (macchine virtuali) non hanno un costruttore
    da dichiarare: meglio il campo vuoto di un nome sbagliato."""
    assert mac_costruttori.costruttore("02:42:AC:11:00:02") is None


@pytest.mark.parametrize("non_valido", [None, "", "aa:bb", "xyz"])
def test_un_indirizzo_non_valido_non_solleva(non_valido):
    assert mac_costruttori.costruttore(non_valido) is None


def test_le_righe_di_commento_non_diventano_prefissi():
    assert mac_costruttori.costruttore("00:00:00:11:22:33") == "XEROX CORPORATION"
    assert "#" not in "".join(mac_costruttori._carica().keys())


def test_senza_catalogo_si_resta_senza_costruttore(monkeypatch, tmp_path):
    """Se nmap non e' installato dove gira la sonda, il MAC resta senza nome: e' un
    dato in meno, non un guasto."""
    monkeypatch.setenv("SNAP_PROBE_NMAP_MAC_PREFIXES", str(tmp_path / "assente"))
    monkeypatch.setattr(mac_costruttori, "_catalogo", None)
    monkeypatch.setattr(mac_costruttori, "find_nmap", lambda *a, **k: None)
    monkeypatch.setattr(mac_costruttori, "PERCORSI_CATALOGO", ())
    assert mac_costruttori.costruttore("B8:27:EB:1A:2B:3C") is None
    assert mac_costruttori.catalogo_disponibile() is False
