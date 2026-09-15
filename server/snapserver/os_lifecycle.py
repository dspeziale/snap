# -----------------------------------------------------------------
# os_lifecycle.py — ciclo di vita dei sistemi operativi: fine supporto e stato
# Autore: Daniele Speziale
# Data creazione: 2026-09-14
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Da una stringa di sistema operativo alla sua data di fine supporto.

PERCHE' ESISTE
Un sistema fuori supporto non riceve piu' correzioni di sicurezza: le vulnerabilita'
che escono da quel giorno restano aperte per sempre. E' il dato che serve per
pianificare gli aggiornamenti, ed e' un obbligo di gestione del rischio (NIS2 art.
21(2)(e), e CRA per i prodotti con elementi digitali). Sapere che una macchina
"ha Windows" non aiuta nessuno; sapere che ha Windows 10 22H2, fuori supporto dal
14/10/2025, dice cosa fare e quando.

IL PUNTO DIFFICILE: UN'IMPRONTA NON E' UNA RELEASE
-------------------------------------------------
nmap non riconosce le release, riconosce **intervalli**. Misurato sull'inventario di
una rete reale:

    "Linux 4.0 - 4.4"                    729 nodi
    "Microsoft Windows 10 1903 - 22H2"   148 nodi
    "Linux 3.11 - 4.9"                   364 nodi

"Windows 10 1903 - 22H2" copre release la cui fine supporto dista **cinque anni**
(1903: 08/12/2020; 22H2: 14/10/2025). Scegliere un estremo darebbe un allarme
inventato o una rassicurazione inventata -- lo stesso errore nelle due direzioni.
"Linux 4.0 - 4.4" e' peggio ancora: e' un **kernel**, e il supporto lo da' la
distribuzione, non il kernel. Debian 12 e Ubuntu 22.04 hanno kernel diversi e
scadenze diverse; due macchine con lo stesso kernel possono stare una dentro e una
fuori supporto.

Da qui la regola di questo modulo: **si risponde solo quando si sa**, e si dichiara
sempre da dove viene la risposta. Gli esiti possibili sono cinque e sono distinti:

| Esito | Significato |
|---|---|
| `supportato` | riconosciuto, con una data di fine supporto futura |
| `in_scadenza` | riconosciuto, fine supporto entro la soglia (180 giorni) |
| `fuori_supporto` | riconosciuto, fine supporto passata |
| `ambiguo` | l'osservazione copre piu' release con scadenze diverse |
| `non_determinabile` | l'osservazione non identifica un prodotto (kernel nudo, apparato) |

`ambiguo` e `non_determinabile` NON sono la stessa cosa e non si scrivono allo stesso
modo: il primo si risolve installando l'agente o leggendo SMB su quella macchina, il
secondo no. Dirlo permette a chi guarda di sapere che cosa fare.

LE FONTI, IN ORDINE DI FIDUCIA
------------------------------
1. **agente** -- legge il sistema da dentro (`/etc/os-release`, edizione e build di
   Windows): e' una dichiarazione della macchina, non una deduzione;
2. **SMB** -- `smb-os-discovery` da' versione e build di Windows;
3. **SNMP** -- `sysDescr` porta spesso la release per esteso;
4. **nmap** -- impronta di rete: e' una stima, spesso un intervallo.

Il catalogo e' **locale**, come quello della threat intelligence e per la stessa
ragione: la correlazione deve funzionare in una rete senza uscita verso internet.
L'aggiornamento e' un'operazione esplicita e tracciata, e accetta un file caricato a
mano (`endoflife.date` espone JSON per prodotto).

LE DATE DI QUESTO CATALOGO
--------------------------
Sono quelle pubblicate dai produttori, verificate al **maggio 2026** e dichiarate
nella pagina insieme al dato. Una data di fine supporto e' un impegno annunciato con
anni di anticipo e cambia di rado, ma cambia: per questo il catalogo si aggiorna, e
per questo la pagina scrive sempre a quando risale.

remarks: Autore: Daniele Speziale - Data: 2026-09-14
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re
from datetime import date, datetime, timezone

# A quando risalgono le date scritte qui sotto. Si mostra accanto a ogni verdetto:
# un dato di ciclo di vita senza la propria data di verifica invecchia in silenzio.
VERIFICATO_AL = "2026-05"

# Quanto vale la fonte del dato. Non e' un dettaglio di presentazione: cambia che
# cosa si puo' fare del verdetto.
#
# IL CASO CHE L'HA IMPOSTA, misurato su una rete reale: 307 nodi riportati da nmap
# come "Microsoft Windows 11 21H2". La 21H2 e' fuori supporto dal 10/10/2023 -- ma
# nmap non legge la release: riconosce un'IMPRONTA di rete, e l'impronta porta il
# nome della versione con cui e' stata raccolta. Quelle 307 macchine possono essere
# 24H2 aggiornate ieri. Aprire trecento pratiche di migrazione su quella base
# significa bruciare la credibilita' dello strumento al primo controllo.
#
# Percio' un verdetto "stimato" si mostra come da confermare, e la pagina dice come
# si conferma: installando l'agente, o leggendo SMB su quella macchina.
FIDUCIA = {
    "agente": ("dichiarato", "letto dentro la macchina dall'agente"),
    "smb": ("dichiarato", "dichiarato dalla macchina via SMB"),
    "snmp": ("dichiarato", "dichiarato dall'apparato via SNMP"),
    "nmap": ("stimato", "impronta di rete: nmap riconosce la famiglia, e nomina la"
                        " release da cui l'impronta fu raccolta. Da confermare"),
}
FIDUCIA_PREDEFINITA = ("stimato", "origine del dato non dichiarata")

# Entro quanti giorni dalla fine supporto un sistema e' "in scadenza". Sei mesi sono
# il tempo minimo per pianificare, approvare e svolgere una migrazione in una PA:
# avvisare a trenta giorni significa avvisare quando non si fa piu' in tempo.
GIORNI_DI_PREAVVISO = 180

# --------------------------------------------------------------------------- #
# Il catalogo
# --------------------------------------------------------------------------- #
# Ogni voce: (prodotto, release, nome esteso, rilascio, fine supporto, fine supporto
# esteso o None, nota).
#
# "fine supporto esteso" e' il supporto a pagamento o prolungato (ESU di Microsoft,
# LTS di Debian, ESM di Ubuntu, ELS di Red Hat). Sta in una colonna propria perche'
# NON e' la stessa cosa: vale solo per chi lo ha acquistato o attivato, e dare per
# scontato che ci sia trasformerebbe un sistema scoperto in un sistema coperto.
CATALOGO = [
    # -- Windows, client ---------------------------------------------------- #
    ("Windows", "XP", "Windows XP", "2001-10-25", "2014-04-08", None,
     "Fuori supporto da oltre un decennio."),
    ("Windows", "Vista", "Windows Vista", "2007-01-30", "2017-04-11", None, ""),
    ("Windows", "7", "Windows 7", "2009-10-22", "2020-01-14", "2023-01-10",
     "ESU a pagamento fino al 2023."),
    ("Windows", "8.1", "Windows 8.1", "2013-11-13", "2023-01-10", None, ""),
    ("Windows", "10 1507", "Windows 10 versione 1507", "2015-07-29", "2017-05-09",
     "2025-10-14", "LTSB 2015: supporto esteso fino al 2025."),
    ("Windows", "10 1607", "Windows 10 versione 1607", "2016-08-02", "2018-04-10",
     "2026-10-13", "LTSB 2016: supporto esteso fino al 2026."),
    ("Windows", "10 1703", "Windows 10 versione 1703", "2017-04-05", "2018-10-09",
     "2019-10-08", ""),
    ("Windows", "10 1709", "Windows 10 versione 1709", "2017-10-17", "2019-04-09",
     "2020-10-13", "La data estesa vale per Enterprise ed Education."),
    ("Windows", "10 1803", "Windows 10 versione 1803", "2018-04-30", "2019-11-12",
     "2021-05-11", "La data estesa vale per Enterprise ed Education."),
    ("Windows", "10 1809", "Windows 10 versione 1809", "2018-11-13", "2020-11-10",
     "2029-01-09", "LTSC 2019: supporto esteso fino al 2029."),
    ("Windows", "10 1903", "Windows 10 versione 1903", "2019-05-21", "2020-12-08",
     None, ""),
    ("Windows", "10 1909", "Windows 10 versione 1909", "2019-11-12", "2021-05-11",
     "2022-05-10", "La data estesa vale per Enterprise ed Education."),
    ("Windows", "10 2004", "Windows 10 versione 2004", "2020-05-27", "2021-12-14",
     None, ""),
    ("Windows", "10 20H2", "Windows 10 versione 20H2", "2020-10-20", "2022-05-10",
     "2023-05-09", "La data estesa vale per Enterprise ed Education."),
    ("Windows", "10 21H1", "Windows 10 versione 21H1", "2021-05-18", "2022-12-13",
     None, ""),
    ("Windows", "10 21H2", "Windows 10 versione 21H2", "2021-11-16", "2023-06-13",
     "2027-01-12", "LTSC 2021: supporto esteso fino al 2027."),
    ("Windows", "10 22H2", "Windows 10 versione 22H2", "2022-10-18", "2025-10-14",
     "2028-10-10", "Ultima versione di Windows 10. ESU per utenti e imprese fino al 2028."),
    ("Windows", "11 21H2", "Windows 11 versione 21H2", "2021-10-04", "2023-10-10",
     "2024-10-08", "La data estesa vale per Enterprise ed Education."),
    ("Windows", "11 22H2", "Windows 11 versione 22H2", "2022-09-20", "2024-10-08",
     "2025-10-14", "La data estesa vale per Enterprise ed Education."),
    ("Windows", "11 23H2", "Windows 11 versione 23H2", "2023-10-31", "2025-11-11",
     "2026-11-10", "La data estesa vale per Enterprise ed Education."),
    ("Windows", "11 24H2", "Windows 11 versione 24H2", "2024-10-01", "2026-10-13",
     "2027-10-12", "La data estesa vale per Enterprise ed Education."),
    ("Windows", "11 25H2", "Windows 11 versione 25H2", "2025-09-30", "2027-10-12",
     "2028-10-10", "La data estesa vale per Enterprise ed Education."),

    # -- Windows, server ---------------------------------------------------- #
    ("Windows Server", "2003", "Windows Server 2003", "2003-05-28", "2015-07-14",
     None, ""),
    ("Windows Server", "2008", "Windows Server 2008", "2008-05-06", "2020-01-14",
     "2023-01-10", "ESU a pagamento fino al 2023 (2024 su Azure)."),
    ("Windows Server", "2008 R2", "Windows Server 2008 R2", "2009-10-22",
     "2020-01-14", "2023-01-10", "ESU a pagamento fino al 2023 (2024 su Azure)."),
    ("Windows Server", "2012", "Windows Server 2012", "2012-10-30", "2023-10-10",
     "2026-10-13", "ESU a pagamento fino al 2026."),
    ("Windows Server", "2012 R2", "Windows Server 2012 R2", "2013-11-25",
     "2023-10-10", "2026-10-13", "ESU a pagamento fino al 2026."),
    ("Windows Server", "2016", "Windows Server 2016", "2016-10-15", "2027-01-12",
     None, "Supporto mainstream concluso l'11/01/2022; la data indicata e' quella esteso."),
    ("Windows Server", "2019", "Windows Server 2019", "2018-11-13", "2029-01-09",
     None, "Supporto mainstream concluso il 09/01/2024; la data indicata e' quella esteso."),
    ("Windows Server", "2022", "Windows Server 2022", "2021-08-18", "2031-10-14",
     None, "Supporto mainstream fino al 13/10/2026."),
    ("Windows Server", "2025", "Windows Server 2025", "2024-11-01", "2034-10-10",
     None, "Supporto mainstream fino al 09/10/2029."),

    # -- Debian -------------------------------------------------------------- #
    ("Debian", "8", "Debian 8 (jessie)", "2015-04-25", "2018-06-17", "2020-06-30",
     "La data estesa e' quella del progetto LTS."),
    ("Debian", "9", "Debian 9 (stretch)", "2017-06-17", "2020-07-06", "2022-06-30",
     "La data estesa e' quella del progetto LTS."),
    ("Debian", "10", "Debian 10 (buster)", "2019-07-06", "2022-09-10", "2024-06-30",
     "La data estesa e' quella del progetto LTS."),
    ("Debian", "11", "Debian 11 (bullseye)", "2021-08-14", "2024-08-14", "2026-08-31",
     "La data estesa e' quella del progetto LTS."),
    ("Debian", "12", "Debian 12 (bookworm)", "2023-06-10", "2026-06-10", "2028-06-30",
     "La data estesa e' quella del progetto LTS."),
    ("Debian", "13", "Debian 13 (trixie)", "2025-08-09", "2028-08-09", "2030-06-30",
     "La data estesa e' quella del progetto LTS."),

    # -- Ubuntu (solo LTS: le interim durano nove mesi e non si trovano in una PA) #
    ("Ubuntu", "14.04", "Ubuntu 14.04 LTS (Trusty Tahr)", "2014-04-17", "2019-04-25",
     "2024-04-25", "La data estesa e' quella di Ubuntu Pro (ESM)."),
    ("Ubuntu", "16.04", "Ubuntu 16.04 LTS (Xenial Xerus)", "2016-04-21", "2021-04-30",
     "2026-04-23", "La data estesa e' quella di Ubuntu Pro (ESM)."),
    ("Ubuntu", "18.04", "Ubuntu 18.04 LTS (Bionic Beaver)", "2018-04-26", "2023-05-31",
     "2028-04-26", "La data estesa e' quella di Ubuntu Pro (ESM)."),
    ("Ubuntu", "20.04", "Ubuntu 20.04 LTS (Focal Fossa)", "2020-04-23", "2025-05-31",
     "2030-04-23", "La data estesa e' quella di Ubuntu Pro (ESM)."),
    ("Ubuntu", "22.04", "Ubuntu 22.04 LTS (Jammy Jellyfish)", "2022-04-21",
     "2027-06-01", "2032-04-21", "La data estesa e' quella di Ubuntu Pro (ESM)."),
    ("Ubuntu", "24.04", "Ubuntu 24.04 LTS (Noble Numbat)", "2024-04-25", "2029-05-31",
     "2034-04-25", "La data estesa e' quella di Ubuntu Pro (ESM)."),

    # -- Red Hat e derivate --------------------------------------------------- #
    ("RHEL", "6", "Red Hat Enterprise Linux 6", "2010-11-10", "2020-11-30",
     "2024-06-30", "La data estesa e' quella degli ELS."),
    ("RHEL", "7", "Red Hat Enterprise Linux 7", "2014-06-10", "2024-06-30",
     "2028-06-30", "La data estesa e' quella degli ELS."),
    ("RHEL", "8", "Red Hat Enterprise Linux 8", "2019-05-07", "2029-05-31",
     "2032-05-31", "La data estesa e' quella degli ELS."),
    ("RHEL", "9", "Red Hat Enterprise Linux 9", "2022-05-17", "2032-05-31", None, ""),
    ("RHEL", "10", "Red Hat Enterprise Linux 10", "2025-05-20", "2035-05-31", None, ""),
    ("CentOS", "6", "CentOS 6", "2011-07-10", "2020-11-30", None, ""),
    ("CentOS", "7", "CentOS 7", "2014-07-07", "2024-06-30", None, ""),
    ("CentOS", "8", "CentOS 8", "2019-09-24", "2021-12-31", None,
     "Chiusa in anticipo: il progetto e' passato a CentOS Stream."),

    # -- SUSE ---------------------------------------------------------------- #
    ("SLES", "12", "SUSE Linux Enterprise Server 12", "2014-10-27", "2024-10-31",
     "2027-10-31", "La data estesa e' quella dell'LTSS."),
    ("SLES", "15", "SUSE Linux Enterprise Server 15", "2018-07-16", "2031-07-31",
     None, "Le date dei singoli Service Pack sono piu' brevi."),

    # -- Virtualizzazione ------------------------------------------------------ #
    ("ESXi", "6.5", "VMware ESXi 6.5", "2016-11-15", "2022-10-15", None, ""),
    ("ESXi", "6.7", "VMware ESXi 6.7", "2018-04-17", "2022-10-15", None, ""),
    ("ESXi", "7.0", "VMware ESXi 7.0", "2020-04-02", "2025-04-02", "2027-04-02",
     "La data estesa e' quella del supporto tecnico prolungato."),
    ("ESXi", "8.0", "VMware ESXi 8.0", "2022-10-11", "2027-10-11", "2029-10-11",
     "La data estesa e' quella del supporto tecnico prolungato."),

    ("ESXi", "4.0", "VMware ESXi 4.0", "2009-05-21", "2014-05-21", None, ""),
    ("ESXi", "4.1", "VMware ESXi 4.1", "2010-07-13", "2014-05-21", None, ""),
    ("ESXi", "5.0", "VMware ESXi 5.0", "2011-08-24", "2016-08-24", None, ""),
    ("ESXi", "5.1", "VMware ESXi 5.1", "2012-09-10", "2016-08-24", None, ""),
    ("ESXi", "5.5", "VMware ESXi 5.5", "2013-09-22", "2018-09-19", None, ""),
    ("ESXi", "6.0", "VMware ESXi 6.0", "2015-03-12", "2020-03-12", None, ""),

    # -- BSD ------------------------------------------------------------------- #
    ("FreeBSD", "6", "FreeBSD 6", "2005-11-04", "2010-11-30", None, ""),
    ("FreeBSD", "7", "FreeBSD 7", "2008-02-27", "2013-02-28", None, ""),
    ("FreeBSD", "8", "FreeBSD 8", "2009-11-25", "2015-08-01", None, ""),
    ("FreeBSD", "9", "FreeBSD 9", "2012-01-10", "2016-12-31", None, ""),
    ("FreeBSD", "10", "FreeBSD 10", "2014-01-20", "2018-10-31", None, ""),
    ("FreeBSD", "11", "FreeBSD 11", "2016-10-10", "2021-09-30", None, ""),
    ("FreeBSD", "12", "FreeBSD 12", "2018-12-11", "2023-12-31", None, ""),
    ("FreeBSD", "13", "FreeBSD 13", "2021-04-13", "2026-01-31", None, ""),
    ("FreeBSD", "14", "FreeBSD 14", "2023-11-20", "2028-11-30", None, ""),
]

# Prodotti per i quali una fine supporto **non esiste in questa forma**, e dirlo e'
# meglio che tacere. Sono gli apparati di rete: il ciclo di vita e' del MODELLO
# (annuncio, ultima vendita, ultimo supporto), non della versione del sistema, e due
# switch con lo stesso IOS possono avere date diverse. Un catalogo per versione
# darebbe una risposta sbagliata con l'aria di essere giusta.
SENZA_CATALOGO_PER_VERSIONE = {
    "IOS": "Cisco pubblica il ciclo di vita per MODELLO di apparato, non per versione"
           " di IOS: la data va cercata sull'avviso di fine vita del modello.",
    "ArubaOS-Switch": "HPE Aruba pubblica il ciclo di vita per modello di apparato.",
    "ArubaOS": "HPE Aruba pubblica il ciclo di vita per modello di apparato.",
    "IOS-XE": "Cisco pubblica il ciclo di vita per modello di apparato.",
    "NX-OS": "Cisco pubblica il ciclo di vita per modello di apparato.",
    "JUNOS": "Juniper pubblica il ciclo di vita per modello e per release train.",
    "FortiOS": "Fortinet pubblica il ciclo di vita per modello di apparato.",
    "OpenBSD": "OpenBSD sostiene le ultime DUE release: una di esse esce ogni sei"
               " mesi, quindi una release ha circa un anno di vita e la data si"
               " ricava dal calendario dei rilasci, non da un catalogo.",
    "lwIP": "Stack di rete di un dispositivo incorporato: non ha un ciclo di vita"
            " pubblicato: lo ha il prodotto che lo incorpora.",
    "embedded": "Sistema incorporato in un apparato: il ciclo di vita e' quello"
                " dell'apparato, e lo pubblica il suo produttore.",
}


# --------------------------------------------------------------------------- #
# Riconoscimento
# --------------------------------------------------------------------------- #
# Ogni regola: (espressione, prodotto, come si ricava la release dai gruppi).
# L'ordine conta: la prima che corrisponde vince, quindi le piu' specifiche stanno
# prima (Windows Server prima di Windows, altrimenti "Windows Server 2019"
# diventerebbe un Windows client chiamato "Server 2019").
REGOLE = (
    # Windows Server: "Microsoft Windows Server 2019", "Windows Server 2012 R2"
    (re.compile(r"windows\s+server\s+(\d{4})(\s*r2)?", re.I),
     "Windows Server", lambda m: (m.group(1) + (" R2" if m.group(2) else "")).strip()),
    # Windows client con versione esplicita: "Windows 10 22H2", "Windows 11 24H2"
    (re.compile(r"windows\s+(10|11)\s+(\d{4}|\d{2}h\d)", re.I),
     "Windows", lambda m: "%s %s" % (m.group(1), m.group(2).upper())),
    # Windows client senza versione: "Windows 11 Pro", "Windows 7"
    (re.compile(r"windows\s+(xp|vista|7|8\.1|8|10|11)\b", re.I),
     "Windows", lambda m: m.group(1).capitalize() if not m.group(1).isdigit()
     else m.group(1)),
    # Distribuzioni Linux, dichiarate: sono le sole che portano una fine supporto.
    (re.compile(r"\bdebian\D*(\d+)", re.I), "Debian", lambda m: m.group(1)),
    (re.compile(r"\bubuntu\D*(\d+\.\d+)", re.I), "Ubuntu", lambda m: m.group(1)),
    (re.compile(r"red\s*hat[^0-9]*(\d+)", re.I), "RHEL", lambda m: m.group(1)),
    (re.compile(r"\brhel\D*(\d+)", re.I), "RHEL", lambda m: m.group(1)),
    (re.compile(r"\bcentos\D*(\d+)", re.I), "CentOS", lambda m: m.group(1)),
    (re.compile(r"\bsles\D*(\d+)", re.I), "SLES", lambda m: m.group(1)),
    (re.compile(r"suse\s+linux\s+enterprise[^0-9]*(\d+)", re.I), "SLES",
     lambda m: m.group(1)),
    (re.compile(r"esxi?\s*(\d+\.\d+)", re.I), "ESXi", lambda m: m.group(1)),
    (re.compile(r"vmware\s+esxi?\s*(\d+\.\d+)", re.I), "ESXi", lambda m: m.group(1)),
    (re.compile(r"freebsd\s*(\d+)", re.I), "FreeBSD", lambda m: m.group(1)),
)

# Un'osservazione che copre un INTERVALLO: "Windows 10 1903 - 22H2", "Linux 4.0 - 4.4".
# Si riconosce per dire che e' ambigua, non per sceglierne un estremo.
RE_INTERVALLO = re.compile(r"\d[\w.]*\s*-\s*\d[\w.]*")

# Un kernel Linux nudo, senza distribuzione: "Linux 4.0 - 4.4", "Linux 2.6.32".
# La fine supporto la da' la DISTRIBUZIONE, e da qui non si ricava.
RE_KERNEL_NUDO = re.compile(r"^linux\s+[\d.]+", re.I)


# Dalla BUILD di Windows alla versione. E' l'unico modo di sapere con certezza quale
# versione di Windows gira su una macchina: il nome ("Windows 11") non ha una fine
# supporto, ce l'ha la singola versione, e dal nome non si ricava. L'agente riporta
# il numero, qui si traduce.
#
# 26100 compare DUE volte -- Windows 11 24H2 e Windows Server 2025 hanno la stessa
# build -- quindi la tabella e' divisa per prodotto: senza, un server 2025 sarebbe
# letto come una postazione.
BUILD_WINDOWS = {
    "Windows": {
        "10240": "10 1507", "10586": "10 1511", "14393": "10 1607",
        "15063": "10 1703", "16299": "10 1709", "17134": "10 1803",
        "17763": "10 1809", "18362": "10 1903", "18363": "10 1909",
        "19041": "10 2004", "19042": "10 20H2", "19043": "10 21H1",
        "19044": "10 21H2", "19045": "10 22H2",
        "22000": "11 21H2", "22621": "11 22H2", "22631": "11 23H2",
        "26100": "11 24H2", "26200": "11 25H2",
    },
    "Windows Server": {
        "14393": "2016", "17763": "2019", "20348": "2022", "26100": "2025",
        "9200": "2012", "9600": "2012 R2", "7601": "2008 R2",
    },
}


def da_build_windows(build: str, server: bool = False) -> dict | None:
    """La voce di catalogo corrispondente a una build di Windows, se nota.

    Restituisce `None` quando la build non e' in tabella: una build sconosciuta e'
    una versione uscita dopo questo catalogo, e inventarne la fine supporto sarebbe
    peggio che dire "non la conosco".
    """
    prodotto = "Windows Server" if server else "Windows"
    release = BUILD_WINDOWS.get(prodotto, {}).get(str(build or "").strip())
    if not release:
        return None
    return PER_CHIAVE.get((prodotto, release))


def _voci_per_prodotto() -> dict:
    esito = {}
    for prodotto, release, nome, rilascio, fine, esteso, nota in CATALOGO:
        esito.setdefault(prodotto, []).append(
            {"prodotto": prodotto, "release": release, "nome": nome,
             "rilascio": rilascio, "fine_supporto": fine,
             "fine_supporto_esteso": esteso, "nota": nota})
    return esito


PER_PRODOTTO = _voci_per_prodotto()
PER_CHIAVE = {(v["prodotto"], v["release"]): v
              for voci in PER_PRODOTTO.values() for v in voci}


def sistemi_dichiarati(tenant_id: int) -> dict:
    """Per ogni nodo con un agente: il sistema come lo dichiara la macchina.

    Restituisce {node_id: stringa}. Un nodo assente dal risultato non ha un agente, o
    ne ha uno che non dichiara il proprio sistema: in entrambi i casi il verdetto su
    quel nodo resta una STIMA, e va scritto come tale.

    L'abbinamento e' per `node_id` e, in mancanza, per indirizzo. Non per nome del
    sistema: quello e' il difetto che questa funzione sostituisce -- confrontava
    l'impronta di nmap con cio' che la macchina dice di se', due stringhe che non
    combaciano mai, e produceva uno zero che sembrava una misura.

    LA STRINGA PREFERITA e' la distribuzione per esteso (`PRETTY_NAME` di
    `/etc/os-release`, oppure edizione e build di Windows): e' l'unica da cui si
    ricavi una release, e quindi una fine supporto. Il campo `sistema` da solo dice
    "Linux 6.1.0-18-amd64", che e' un kernel e non porta a nessuna data.
    """
    import json

    from .db import query

    esito = {}
    for riga in query(
            "SELECT a.node_id, a.ip, a.sistema, a.inventario_json,"
            "       (SELECT n.id FROM nodes n WHERE n.tenant_id = a.tenant_id"
            "          AND n.ip = a.ip LIMIT 1) AS nodo_per_ip"
            "  FROM agent_hosts a WHERE a.tenant_id = ?", (int(tenant_id),)):
        nodo = riga["node_id"] or riga["nodo_per_ip"]
        if not nodo:
            # L'agente non e' ancora stato ricondotto a un nodo dell'inventario: non
            # si inventa un abbinamento, e quel nodo resta una stima.
            continue
        dichiarato = ""
        try:
            identita = (json.loads(riga["inventario_json"] or "{}")
                        .get("identita") or {})
        except (TypeError, ValueError):
            identita = {}
        distribuzione = identita.get("distribuzione") or {}
        if isinstance(distribuzione, dict):
            dichiarato = (distribuzione.get("completo") or "").strip()
        if not dichiarato:
            # Windows prima dell'agente 1.2.4: edizione e build stanno separate.
            edizione = (identita.get("edizione") or "").strip()
            build = str(identita.get("build") or "").strip()
            if edizione and build:
                dichiarato = "%s build %s" % (edizione, build)
        if not dichiarato:
            dichiarato = (riga["sistema"] or "").strip()
        if dichiarato:
            esito[int(nodo)] = dichiarato
    return esito


def stato_di(fine_supporto: str, oggi: date = None) -> tuple:
    """(stato, giorni residui) data una fine supporto. Giorni negativi se passata."""
    oggi = oggi or datetime.now(timezone.utc).date()
    try:
        fine = datetime.strptime(fine_supporto, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return ("non_determinabile", None)
    giorni = (fine - oggi).days
    if giorni < 0:
        return ("fuori_supporto", giorni)
    if giorni <= GIORNI_DI_PREAVVISO:
        return ("in_scadenza", giorni)
    return ("supportato", giorni)


def riconosci(osservato: str, famiglia: str = "", sorgente: str = "nmap",
              oggi: date = None) -> dict:
    """Da una stringa di sistema operativo al suo ciclo di vita.

    Restituisce sempre un dizionario con `stato`, `perche'` e `sorgente`: non
    restituisce mai `None`, perche' "non lo so" e' una risposta che la pagina deve
    poter mostrare per esteso invece di lasciare una cella vuota.
    """
    testo = (osservato or "").strip()
    fiducia, perche_fiducia = FIDUCIA.get(sorgente, FIDUCIA_PREDEFINITA)
    esito = {
        "osservato": testo, "sorgente": sorgente, "verificato_al": VERIFICATO_AL,
        "fiducia": fiducia, "fiducia_perche": perche_fiducia,
        "prodotto": None, "release": None, "nome": None, "rilascio": None,
        "fine_supporto": None, "fine_supporto_esteso": None, "nota": "",
        "stato": "non_determinabile", "giorni": None, "perche": "",
    }
    if not testo:
        esito["perche"] = "nessun sistema operativo rilevato su questo nodo."
        return esito

    # 1. Prodotti il cui ciclo di vita non e' per versione: si dice, non si tace.
    for chiave, spiegazione in SENZA_CATALOGO_PER_VERSIONE.items():
        if chiave.lower() in (famiglia or "").lower() or chiave.lower() in testo.lower():
            esito["perche"] = spiegazione
            return esito

    # 2. Kernel nudo: e' la meta' dei nodi di una rete reale, e va spiegato bene.
    if RE_KERNEL_NUDO.match(testo):
        esito["perche"] = (
            "e' una versione di KERNEL, non una distribuzione: il supporto lo da' la"
            " distribuzione (Debian, Ubuntu, RHEL...), che dalla rete non si vede."
            " Si ottiene installando l'agente su questa macchina.")
        return esito

    # 3. Riconoscimento del prodotto.
    for espressione, prodotto, estrai in REGOLE:
        trovato = espressione.search(testo)
        if not trovato:
            continue
        release = estrai(trovato)

        # 3a. Osservazione a INTERVALLO: si guarda PRIMA di cercare la release nel
        #     catalogo. Cercarla prima era il difetto trovato sui dati veri: di
        #     "Windows 10 1903 - 22H2" l'espressione estrae "10 1903", che nel
        #     catalogo c'e', e il verdetto diventava la fine supporto del PRIMO
        #     estremo -- cioe' l'allarme piu' grave fra quelli possibili, scelto a
        #     caso. Su 148 nodi reali.
        if RE_INTERVALLO.search(testo):
            candidate = _candidate_dell_intervallo(prodotto, testo)
            if candidate:
                return _ambiguo(esito, prodotto, candidate, oggi)

        voce = PER_CHIAVE.get((prodotto, release))

        # 3b. Prodotto riconosciuto ma release non in catalogo (release nuova, o
        #     una variante che il catalogo non elenca).
        if voce is None:
            altre = PER_PRODOTTO.get(prodotto) or []
            esito["prodotto"] = prodotto
            esito["release"] = release
            esito["perche"] = (
                "prodotto riconosciuto (%s) ma la release %r non e' nel catalogo"
                " verificato al %s: il catalogo ne elenca %d. Va aggiornato."
                % (prodotto, release, VERIFICATO_AL, len(altre)))
            return esito

        # 3c. Riconosciuto.
        esito.update({k: voce[k] for k in
                      ("prodotto", "release", "nome", "rilascio",
                       "fine_supporto", "fine_supporto_esteso", "nota")})
        esito["stato"], esito["giorni"] = stato_di(voce["fine_supporto"], oggi)
        return esito

    esito["perche"] = ("il sistema non corrisponde a nessun prodotto del catalogo:"
                       " puo' essere un apparato, un sistema incorporato, o un"
                       " prodotto che il catalogo non conosce ancora.")
    return esito


def _candidate_dell_intervallo(prodotto: str, testo: str) -> list:
    """Le release del catalogo che l'intervallo osservato potrebbe indicare.

    Si fa per NUMERO di release nominate nel testo, non interpolando: "Windows 10
    1903 - 22H2" nomina due estremi, e cio' che sta in mezzo lo sa il catalogo.
    """
    voci = PER_PRODOTTO.get(prodotto) or []
    nominate = [v for v in voci
                if re.search(re.escape(v["release"].split()[-1]), testo, re.I)]
    if len(nominate) < 2:
        return []
    ordinate = sorted(voci, key=lambda v: v["rilascio"])
    primo = min(ordinate.index(v) for v in nominate)
    ultimo = max(ordinate.index(v) for v in nominate)
    return ordinate[primo:ultimo + 1]


def _ambiguo(esito: dict, prodotto: str, candidate: list, oggi: date) -> dict:
    """L'osservazione copre piu' release: si dice quante e quanto distano.

    Si riportano ANCHE gli estremi, perche' "fra il 2020 e il 2025" e' comunque
    un'informazione: dice che la macchina potrebbe essere fuori supporto da anni, e
    che vale la pena andare a vedere.
    """
    prima = min(candidate, key=lambda v: v["fine_supporto"])
    ultima = max(candidate, key=lambda v: v["fine_supporto"])
    esito["prodotto"] = prodotto
    esito["stato"] = "ambiguo"
    esito["release"] = "%s - %s" % (prima["release"], ultima["release"])
    esito["fine_supporto"] = prima["fine_supporto"]
    esito["fine_supporto_estremo"] = ultima["fine_supporto"]
    stato_prima = stato_di(prima["fine_supporto"], oggi)[0]
    stato_ultima = stato_di(ultima["fine_supporto"], oggi)[0]
    esito["perche"] = (
        "l'impronta di rete copre %d release, dal %s al %s come fine supporto:"
        " %s. Per sapere quale sia si legge il sistema da dentro (agente) o via SMB."
        % (len(candidate), prima["fine_supporto"], ultima["fine_supporto"],
           "sono tutte fuori supporto" if stato_prima == stato_ultima == "fuori_supporto"
           else "alcune sono fuori supporto e altre no"))
    # Quando TUTTE le release possibili sono fuori supporto, l'ambiguita' non
    # impedisce il giudizio: qualunque sia quella vera, e' fuori supporto. E' il caso
    # in cui un "non so" sarebbe una scusa per non guardare.
    if stato_prima == stato_ultima == "fuori_supporto":
        esito["stato"] = "fuori_supporto"
        # La data mostrata e' la PIU' RECENTE fra quelle possibili, non la piu'
        # vecchia: e' il caso migliore, ed e' l'unico numero difendibile davanti a
        # chi chiede "da quando?" -- "anche nell'ipotesi piu' favorevole, da questa".
        esito["fine_supporto"] = ultima["fine_supporto"]
        esito["fine_supporto_estremo"] = prima["fine_supporto"]
        esito["giorni"] = stato_di(ultima["fine_supporto"], oggi)[1]
        esito["perche"] = (
            "l'impronta copre %d release (dal %s al %s), ma sono TUTTE fuori"
            " supporto: qualunque sia quella vera, questa macchina non riceve piu'"
            " correzioni di sicurezza."
            % (len(candidate), prima["release"], ultima["release"]))
    return esito
