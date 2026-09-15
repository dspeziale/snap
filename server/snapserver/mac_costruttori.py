# -----------------------------------------------------------------
# mac_costruttori.py — chi ha fatto una scheda di rete, dal prefisso del MAC
# Autore: Daniele Speziale
# Data creazione: 2026-09-15
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Dal MAC al costruttore, con una cache che si alimenta da sola.

A CHE COSA SERVE. `80:3f:5d:ff:2e:31` non dice niente. Sapere che i primi tre byte
sono di Wistron, di Cisco o di Ricoh cambia la lettura della riga: su un apparato muto
-- nessun banner, nessuna porta parlante -- il costruttore della scheda e' spesso
l'unico indizio sul TIPO di apparato. E un MAC che compare in un allarme senza un nome
accanto e' un allarme che non si sa valutare.

PERCHE' ANCHE SUL SERVER, se la sonda lo fa gia'. La sonda usa il catalogo che nmap
distribuisce con se', e funziona finche' nmap c'e': su una sonda senza nmap, e per
ogni MAC che non passa da una scansione -- quelli osservati nel traffico, quelli
riferiti da un apparato in SNMP, quelli delle presenze senza fili -- il nome non
arriva. Il server e' il punto in cui TUTTI i MAC del prodotto si incontrano, ed e' il
solo posto in cui rispondere una volta per tutte.

LA SORGENTE E' `oui.txt`, il registro dello IEEE: e' l'originale da cui derivano tutti
gli altri cataloghi, compreso quello di nmap. Si prende da `standards-oui.ieee.org`,
oppure si carica a mano -- ed e' il caso che conta, perche' in una rete di PA senza
uscita verso internet il download non si puo' fare e il prodotto deve funzionare lo
stesso.

LA CACHE E' IL CATALOGO. A differenza delle reti pubbliche, qui non si interroga
nessuno per singolo indirizzo: il registro e' UN FILE, si legge tutto in una volta e
si tiene in tabella. Un MAC nuovo non costa nessuna richiesta -- e' una ricerca su un
prefisso di sei caratteri. E' la ragione per cui questa cache non ha bisogno di una
coda, di tentativi o di un thread.

I PREFISSI NON SONO TUTTI DI TRE BYTE. Lo IEEE assegna blocchi grandi (MA-L, 24 bit),
medi (MA-M, 28) e piccoli (MA-S, 36): un blocco piccolo e' condiviso fra molte
aziende, e guardare i soli primi tre byte darebbe il nome del rivenditore del blocco
invece di quello dell'azienda. Si cerca percio' dal prefisso PIU' LUNGO al piu' corto.

remarks: Autore: Daniele Speziale - Data: 2026-09-15
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request

from .db import execute, query, utc_now_str

USER_AGENT = "snap-mac-costruttori/1.0"
HTTP_TIMEOUT = 120

# Il registro ufficiale dello IEEE. Sono tre file: i blocchi grandi, medi e piccoli.
# Si prendono tutti e tre, perche' un apparato piccolo sta quasi sempre in un blocco
# piccolo -- ed e' proprio quello che il catalogo di nmap risolve peggio.
SORGENTI = (
    ("MA-L", "https://standards-oui.ieee.org/oui/oui.txt"),
    ("MA-M", "https://standards-oui.ieee.org/oui28/mam.txt"),
    ("MA-S", "https://standards-oui.ieee.org/oui36/oui36.txt"),
)

# Il file intero e' qualche megabyte. Oltre questo c'e' un errore di indirizzo o una
# sorgente cambiata, non un registro piu' grande.
MAX_FILE_BYTE = 32 * 1024 * 1024

# I TRE FILE NON HANNO LO STESSO FORMATO, e la differenza non e' cosmetica.
#
# In `oui.txt` (blocchi grandi) il prefisso sta tutto su una riga:
#     803F5D     (base 16)<tab><tab>Wistron Neweb Corporation
#
# In `mam.txt` e `oui36.txt` (blocchi medi e piccoli) il record e' su DUE righe e il
# prefisso va composto:
#     C8-5C-E2   (hex)<tab><tab>SYNERGY SYSTEMS AND SOLUTIONS
#     700000-7FFFFF     (base 16)<tab><tab>SYNERGY SYSTEMS AND SOLUTIONS
# La prima porta l'OUI di 24 bit, la seconda l'INTERVALLO di suffissi assegnato
# dentro quell'OUI. Il prefisso vero e' l'OUI piu' la parte FISSA dell'intervallo --
# qui `C85CE2` + `7` -- e quanti caratteri siano fissi lo dice l'intervallo stesso,
# senza bisogno di sapere se si tratti di un blocco medio o piccolo.
RIGA_OUI = re.compile(r"^\s*([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){2})\s+\(hex\)")
RIGA_SEMPLICE = re.compile(r"^\s*([0-9A-Fa-f]{6,9})\s+\(base 16\)\s*(.*?)\s*$")
RIGA_INTERVALLO = re.compile(
    r"^\s*([0-9A-Fa-f]+)-([0-9A-Fa-f]+)\s+\(base 16\)\s*(.*?)\s*$")


def _parte_fissa(inizio: str, fine: str) -> str:
    """I caratteri iniziali che i due estremi dell'intervallo hanno in comune.

    E' quanto dell'intervallo e' ASSEGNATO: in `700000-7FFFFF` e' il solo `7` (blocco
    medio, 28 bit), in `AFA000-AFAFFF` sono `AFA` (blocco piccolo, 36 bit). Ricavarlo
    dall'intervallo invece di dedurlo dal nome del file significa che i due formati si
    leggono con lo stesso codice, e che un terzo taglio futuro non rompe niente.
    """
    comune = []
    for a, b in zip(inizio, fine):
        if a != b:
            break
        comune.append(a)
    return "".join(comune)

# Le lunghezze di prefisso in uso, dalla piu' specifica alla piu' generica. Si cerca
# in quest'ordine: un blocco piccolo e' condiviso, e fermarsi ai primi tre byte
# darebbe il nome di chi ha rivenduto il blocco invece di quello dell'azienda.
LUNGHEZZE = (9, 7, 6)


def normalizza(mac: str | None) -> str:
    """Le sole cifre esadecimali, maiuscole. Stringa vuota se non e' un MAC.

    I MAC arrivano scritti in tutti i modi: con i due punti, con i trattini, con i
    punti ogni quattro cifre, maiuscoli o minuscoli. Confrontarli senza normalizzarli
    significa non trovare mai niente per meta' delle sorgenti.
    """
    if not mac:
        return ""
    pulito = re.sub(r"[^0-9A-Fa-f]", "", str(mac)).upper()
    return pulito if len(pulito) >= 6 else ""


def costruttore(mac: str | None) -> str:
    """Chi ha fatto questa scheda. Stringa vuota se non si sa.

    Non solleva e non interroga nessuno: e' una ricerca su un prefisso, e sta nel
    percorso di una richiesta.
    """
    pulito = normalizza(mac)
    if not pulito:
        return ""
    # Dal prefisso piu' LUNGO al piu' corto: il primo che si trova e' il piu'
    # specifico, cioe' quello giusto.
    prefissi = [pulito[:n] for n in LUNGHEZZE if len(pulito) >= n]
    if not prefissi:
        return ""
    segnaposto = ", ".join("?" for _ in prefissi)
    righe = query(
        "SELECT prefix, vendor FROM mac_vendors WHERE prefix IN (%s)" % segnaposto,
        tuple(prefissi))
    trovati = {r["prefix"]: r["vendor"] for r in righe}
    for prefisso in prefissi:          # gia' in ordine di specificita'
        if prefisso in trovati:
            return trovati[prefisso] or ""
    return ""


def _analizza(testo: str, blocco: str) -> list:
    """Le coppie (prefisso, costruttore) di un file del registro.

    Regge entrambi i formati: quello di `oui.txt`, in cui il prefisso sta su una riga
    sola, e quello di `mam.txt`/`oui36.txt`, in cui va composto con l'OUI della riga
    precedente.
    """
    voci = []
    oui_corrente = ""
    for riga in testo.splitlines():
        intestazione = RIGA_OUI.match(riga)
        if intestazione:
            oui_corrente = intestazione.group(1).replace("-", "").upper()
            continue

        # Blocchi medi e piccoli: l'intervallo assegnato dentro l'OUI appena letto.
        intervallo = RIGA_INTERVALLO.match(riga)
        if intervallo:
            nome = intervallo.group(3).strip()
            fisso = _parte_fissa(intervallo.group(1).upper(),
                                 intervallo.group(2).upper())
            # Senza l'OUI della riga precedente il prefisso sarebbe monco: si salta
            # invece di comporne uno sbagliato, che attribuirebbe il nome di
            # un'azienda alle schede di un'altra.
            if nome and oui_corrente and fisso:
                voci.append((oui_corrente + fisso, nome, blocco))
            continue

        # Blocchi grandi: il prefisso e' gia' completo.
        semplice = RIGA_SEMPLICE.match(riga)
        if semplice:
            nome = semplice.group(2).strip()
            if nome:
                voci.append((semplice.group(1).upper(), nome, blocco))
    return voci


def importa_testo(testo: str, blocco: str = "MA-L") -> int:
    """Carica in tabella il contenuto di un file del registro. Torna quante voci.

    Esiste separata dallo scaricamento perche' e' il modo di popolare il catalogo
    dove il server non ha uscita verso internet: si porta il file a mano e si carica.
    Un prodotto che funziona solo con internet non e' utilizzabile in mezza PA.
    """
    voci = _analizza(testo, blocco)
    if not voci:
        return 0
    adesso = utc_now_str()
    for prefisso, nome, tipo in voci:
        esistente = query("SELECT prefix FROM mac_vendors WHERE prefix = ?",
                          (prefisso,), one=True)
        if esistente:
            execute("UPDATE mac_vendors SET vendor = ?, block = ?, imported_at = ?"
                    " WHERE prefix = ?", (nome, tipo, adesso, prefisso))
        else:
            execute("INSERT INTO mac_vendors (prefix, vendor, block, imported_at)"
                    " VALUES (?, ?, ?, ?)", (prefisso, nome, tipo, adesso))
    return len(voci)


def scarica(blocchi=None) -> dict:
    """Scarica dal registro IEEE e carica. Dichiara che cosa non e' riuscito.

    Un blocco che non si scarica non ferma gli altri: meglio un catalogo parziale --
    che si sa essere parziale -- di nessun catalogo.
    """
    scelti = [(t, u) for t, u in SORGENTI if not blocchi or t in blocchi]
    esito = {"caricate": 0, "blocchi": {}, "errori": {}}
    for tipo, indirizzo in scelti:
        try:
            richiesta = urllib.request.Request(
                indirizzo, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(richiesta, timeout=HTTP_TIMEOUT) as risposta:
                grezzo = risposta.read(MAX_FILE_BYTE + 1)
            if len(grezzo) > MAX_FILE_BYTE:
                raise ValueError("file piu' grande di %d byte" % MAX_FILE_BYTE)
            quante = importa_testo(grezzo.decode("utf-8", "replace"), tipo)
            esito["blocchi"][tipo] = quante
            esito["caricate"] += quante
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError,
                OSError) as errore:
            esito["errori"][tipo] = str(errore)
    return esito


def stato() -> dict:
    """Quanto e' pieno il catalogo, e di quando e'."""
    riga = query("SELECT count(*) AS n, max(imported_at) AS quando FROM mac_vendors",
                 (), one=True) or {}
    per_blocco = query(
        "SELECT block, count(*) AS n FROM mac_vendors GROUP BY block ORDER BY block",
        ())
    return {
        "prefissi": int((riga.get("n") if hasattr(riga, "get") else riga["n"]) or 0),
        "aggiornato_at": (riga.get("quando") if hasattr(riga, "get")
                          else riga["quando"]),
        "per_blocco": [dict(r) for r in per_blocco],
    }
