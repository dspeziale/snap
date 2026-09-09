# -----------------------------------------------------------------
# mac_costruttori.py — costruttore di una scheda di rete dal prefisso del MAC
# Autore: Daniele Speziale
# Data creazione: 2026-09-09
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap probe - Da un indirizzo MAC al nome del costruttore.

PERCHE' SERVE
-------------
Quando nmap vede un MAC sul proprio segmento, dichiara anche il costruttore: lo
ricava dal prefisso (i primi tre byte, l'OUI assegnato dallo IEEE). I MAC che
arrivano dalla tabella ARP di un apparato interrogato in SNMP, invece, non passano
da nmap: si otteneva l'indirizzo senza il nome di chi ha fatto la scheda.

E' proprio il nome del costruttore la parte utile del MAC per il riconoscimento: su
un apparato muto -- nessun banner, nessuna porta parlante -- "Ricoh" o "Cisco" e'
spesso l'unico indizio sul tipo. Un MAC senza costruttore vale molto meno.

COME
----
Si legge `nmap-mac-prefixes`, il catalogo che nmap distribuisce con se' (52.091
prefissi): e' lo stesso dato che nmap userebbe, quindi un MAC riferito da un
apparato e uno osservato dalla sonda ottengono la STESSA risposta, e non due nomi
diversi per la stessa scheda. Nessuna dipendenza nuova, nessuna interrogazione in
rete a servizi OUI esterni -- che su una rete di PA senza uscita non funzionerebbero
e sarebbero comunque una fuga di informazioni sull'inventario.

Il catalogo si cerca accanto all'eseguibile di nmap (che la sonda sa individuare)
e nei percorsi consueti delle distribuzioni. Se non c'e', la funzione risponde
`None`: il MAC resta senza costruttore, come prima, e non si inventa nulla.
"""

from __future__ import annotations

import os
import re
import threading

from .nmap_runner import find_nmap

# Percorsi in cui nmap tiene i propri cataloghi, oltre a quelli ricavati
# dall'eseguibile. Su Windows il catalogo sta nella cartella d'installazione.
PERCORSI_CATALOGO = (
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
    "/opt/homebrew/share/nmap/nmap-mac-prefixes",
    r"C:\Program Files (x86)\Nmap\nmap-mac-prefixes",
    r"C:\Program Files\Nmap\nmap-mac-prefixes",
)

# Una riga utile: sei cifre esadecimali, spazio, nome del costruttore.
RIGA = re.compile(r"^([0-9A-Fa-f]{6})\s+(.+?)\s*$")

_catalogo: dict[str, str] | None = None
_serratura = threading.Lock()
_percorso_usato: str | None = None


def _percorsi_possibili() -> list[str]:
    """Dove cercare il catalogo, dal piu' attendibile al piu' generico."""
    percorsi = []
    dalla_configurazione = os.environ.get("SNAP_PROBE_NMAP_MAC_PREFIXES")
    if dalla_configurazione:
        percorsi.append(dalla_configurazione)
    eseguibile = find_nmap()
    if eseguibile:
        cartella = os.path.dirname(os.path.abspath(eseguibile))
        # Installazione all'uso di Unix (`bin/` e `share/`) e installazione
        # monocartella di Windows: si provano entrambe senza sapere quale sia.
        percorsi.append(os.path.join(cartella, "nmap-mac-prefixes"))
        percorsi.append(os.path.join(os.path.dirname(cartella), "share", "nmap",
                                     "nmap-mac-prefixes"))
    percorsi.extend(PERCORSI_CATALOGO)
    return percorsi


def _carica() -> dict[str, str]:
    """Legge il catalogo una volta sola. Un catalogo assente da' una mappa vuota."""
    global _catalogo, _percorso_usato
    if _catalogo is not None:
        return _catalogo
    with _serratura:
        if _catalogo is not None:  # un altro filo ha finito mentre si attendeva
            return _catalogo
        mappa: dict[str, str] = {}
        for percorso in _percorsi_possibili():
            if not percorso or not os.path.isfile(percorso):
                continue
            try:
                with open(percorso, "r", encoding="utf-8", errors="replace") as f:
                    for riga in f:
                        if not riga or riga[0] == "#":
                            continue
                        trovata = RIGA.match(riga)
                        if trovata:
                            mappa[trovata.group(1).upper()] = trovata.group(2)
            except OSError as errore:
                # Il catalogo c'e' ma non si legge (permessi, disco): si dichiara e
                # si prova il percorso successivo. Non e' fatale -- si resta senza
                # costruttore -- ma non deve restare muto.
                import logging

                logging.getLogger("snapprobe").warning(
                    "Catalogo dei prefissi MAC non leggibile (%s): %s",
                    percorso, errore)
                continue
            if mappa:
                _percorso_usato = percorso
                break
        _catalogo = mappa
        return _catalogo


def catalogo_disponibile() -> bool:
    """Se il catalogo dei prefissi e' stato trovato e contiene voci."""
    return bool(_carica())


def percorso_catalogo() -> str | None:
    """Da quale file si sta leggendo: serve a dirlo nella pagina di stato."""
    _carica()
    return _percorso_usato


def quanti_prefissi() -> int:
    return len(_carica())


def costruttore(mac: str | None) -> str | None:
    """Il costruttore della scheda, o `None` se il prefisso non e' nel catalogo.

    Un prefisso sconosciuto non e' un errore: i MAC amministrati localmente (le
    macchine virtuali, per esempio) non hanno alcun costruttore da dichiarare, e
    inventarne uno sarebbe peggio che lasciare il campo vuoto.
    """
    if not mac:
        return None
    cifre = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(cifre) < 6:
        return None
    return _carica().get(cifre[:6].upper())
