# -----------------------------------------------------------------
# os_guess.py — il sistema operativo di un nodo, per approssimazioni successive
# Autore: Daniele Speziale
# Data creazione: 2026-09-10
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Che sistema c'e' dentro, e quanto lo si sa.

IL PROBLEMA
-----------
La colonna "Sistema operativo" dell'elenco mostrava `os_name`, cioe' il solo
rilevamento di nmap. Su una rete di PA quel rilevamento riesce raramente: richiede
almeno una porta aperta e una chiusa, socket raw, e apparati che rispondano in modo
canonico. Il risultato era una colonna vuota per la maggior parte dei nodi -- una
colonna che non dice niente e che sembra un guasto.

Vuota, pero', non significa "non si sa": significa che si stava guardando UNA sola
fonte. Di quasi ogni nodo il prodotto ha raccolto abbastanza per dire qualcosa, con
diversi livelli di precisione: SMB dichiara la versione esatta di Windows, un banner
web dichiara la distribuzione, un TTL a 128 dice "Windows" e non altro.

COME
----
Una cascata di approssimazioni, dalla piu' precisa alla piu' grossolana. Si prende la
prima che risponde, e si DICHIARA sempre da dove viene e quanto vale:

1. **rilevamento di nmap** (`os_name`) -- la piu' precisa quando c'e';
2. **SMB** (`smb-os-discovery`) -- su una macchina Windows e' l'apparato che dichiara
   la propria versione: piu' attendibile del rilevamento;
3. **SNMP** (descrizione di sistema) -- l'apparato che parla di se';
4. **famiglia rilevata** (`os_family` + `os_gen`) -- meno preciso del nome;
5. **banner web** -- "Apache/2.4 (Ubuntu)" dichiara la distribuzione, "Microsoft-IIS"
   dichiara Windows;
6. **profilo di porte** -- 445+139 e' Windows, 22 senza 445 e' un sistema tipo Unix;
7. **TTL osservato** -- 64/128/255 distinguono tre famiglie e nient'altro;
8. **classe dell'apparato** -- di una stampante o di uno switch il "sistema operativo"
   e' il firmware del costruttore, e dirlo cosi' e' piu' onesto che dire Linux.

L'ultima riga della cascata non e' il vuoto: e' "non determinato" con il motivo. Una
colonna non deve mai lasciare l'operatore a chiedersi se il dato manca o se il
prodotto non ha funzionato.

ONESTA' DELLA PRESENTAZIONE
---------------------------
Un'ipotesi dal TTL e una versione dichiarata da SMB non sono la stessa cosa, e
mostrarle allo stesso modo sarebbe una bugia tipografica. Ogni esito porta con se'
`certezza` ('dichiarata', 'rilevata', 'ipotesi') e la pagina la usa: le ipotesi sono
in corsivo e spiegate nel suggerimento.
"""

from __future__ import annotations

import re

# Porte che, aperte, dicono qualcosa sulla famiglia del sistema. Non sono un catalogo
# di servizi: sono le sole per cui il legame con il sistema e' forte.
PORTE_WINDOWS = frozenset({445, 139, 135, 3389})
PORTE_UNIX = frozenset({22})

# TTL iniziali e la famiglia che suggeriscono. Il TTL osservato si arrotonda in su:
# ogni instradamento lo decrementa.
TTL_FAMIGLIE = (
    (64, "sistema tipo Unix (Linux, macOS, Android, iOS)"),
    (128, "Windows"),
    (255, "apparato di rete"),
)

# Classi per cui "sistema operativo" significa firmware del costruttore: dire "Linux"
# di una stampante e' vero e inutile, dire "firmware della stampante" e' utile e vero.
CLASSI_A_FIRMWARE = {
    "printer": "firmware della stampante",
    "switch_managed": "firmware dell'apparato di rete",
    "router_gateway": "firmware dell'apparato di rete",
    "firewall": "firmware dell'apparato di sicurezza",
    "access_point": "firmware dell'access point",
    "ip_camera": "firmware della telecamera",
    "voip_phone": "firmware del telefono",
    "ups": "firmware del gruppo di continuita'",
    "building_automation": "firmware dell'apparato di edificio",
    "pbx": "firmware del centralino",
    "nas": "sistema del NAS",
}

# Sistemi riconoscibili dentro un banner o una descrizione. L'ordine conta: il primo
# che corrisponde vince, quindi i piu' specifici stanno prima.
DA_TESTO = (
    (r"(?i)\bwindows\s+server\s+(\d{4}(?:\s*r2)?)", "Windows Server %s"),
    (r"(?i)\bwindows\s+(11|10|8\.1|8|7)\b", "Windows %s"),
    (r"(?i)\bwindows\b", "Windows"),
    (r"(?i)\bubuntu\b", "Linux (Ubuntu)"),
    (r"(?i)\bdebian\b", "Linux (Debian)"),
    (r"(?i)\b(?:red\s*hat|rhel)\b", "Linux (Red Hat)"),
    (r"(?i)\bcentos\b", "Linux (CentOS)"),
    (r"(?i)\balmalinux\b", "Linux (AlmaLinux)"),
    (r"(?i)\brocky\s*linux\b", "Linux (Rocky)"),
    (r"(?i)\bsuse\b", "Linux (SUSE)"),
    (r"(?i)\bopenwrt\b", "Linux (OpenWrt)"),
    (r"(?i)\bfreebsd\b", "FreeBSD"),
    (r"(?i)\bvmware\s+esxi?\b", "VMware ESXi"),
    (r"(?i)\bproxmox\b", "Proxmox VE (Linux)"),
    (r"(?i)\bcisco\s+ios[- ]?xe\b", "Cisco IOS-XE"),
    (r"(?i)\bcisco\s+ios\b", "Cisco IOS"),
    (r"(?i)\bjunos\b", "Juniper Junos"),
    (r"(?i)\bfortios\b", "FortiOS"),
    (r"(?i)\bpan-os\b", "PAN-OS"),
    (r"(?i)\bios\s*xr\b", "Cisco IOS-XR"),
    (r"(?i)\blinux\b", "Linux"),
    (r"(?i)\bandroid\b", "Android"),
    (r"(?i)\b(?:iphone|ipados|\bios\s+\d)", "iOS"),
    (r"(?i)\bmac\s*os\s*x?\b|\bdarwin\b", "macOS"),
)

# Banner di server web che implicano il sistema pur senza nominarlo.
SERVER_IMPLICITO = (
    (r"(?i)microsoft-iis", "Windows", "il server web IIS gira solo su Windows"),
    (r"(?i)microsoft-httpapi", "Windows",
     "HTTP.sys e' il servizio HTTP di Windows"),
)


def _da_testo(testo: str) -> str | None:
    """Il sistema nominato in un testo libero, o `None`."""
    if not testo:
        return None
    for espressione, forma in DA_TESTO:
        trovato = re.search(espressione, testo)
        if not trovato:
            continue
        if "%s" in forma:
            gruppo = (trovato.group(1) or "").strip()
            if not gruppo:
                continue
            return forma % re.sub(r"\s+", " ", gruppo).title()
        return forma
    return None


def _os_da_smb(testo: str) -> str | None:
    """La riga `OS:` di `smb-os-discovery`, che e' l'apparato che si dichiara."""
    if not testo:
        return None
    trovato = re.search(r"(?:^|\n)\s*OS\s*:\s*(.+)", testo, re.I)
    if not trovato:
        return None
    valore = re.sub(r"(?:\\x00)+", "", trovato.group(1)).strip()
    # nmap scrive "Windows Server 2016 Standard 14393 (Windows Server 2016
    # Standard 6.3)": la parte fra parentesi ripete, e la riga in una colonna
    # deve stare.
    valore = re.sub(r"\s*\(.*$", "", valore).strip()
    if not valore or valore.lower() in ("unknown", "<unknown>", "n/a"):
        return None
    return valore[:80]


def _arrotonda_ttl(ttl) -> tuple:
    """`(iniziale, descrizione)` del TTL piu' vicino verso l'alto, o `(None, None)`."""
    try:
        valore = int(ttl)
    except (TypeError, ValueError):
        return (None, None)
    if valore <= 0:
        return (None, None)
    for iniziale, descrizione in TTL_FAMIGLIE:
        if valore <= iniziale:
            return (iniziale, descrizione)
    return (None, None)


def indovina(nodo, *, smb_os: str = None, snmp_descr: str = None,
             web_server: str = None, web_testo: str = None,
             porte=()) -> dict:
    """Il sistema operativo del nodo per approssimazioni successive.

    Restituisce sempre un dizionario con `testo`, `fonte`, `certezza` e
    `spiegazione`: la colonna non resta mai vuota, e cio' che vale poco e' dichiarato
    per quello che e'.
    """
    def esito(testo, fonte, certezza, spiegazione):
        return {"testo": testo, "fonte": fonte, "certezza": certezza,
                "spiegazione": spiegazione}

    leggi = (lambda chiave: (nodo.get(chiave) if hasattr(nodo, "get")
                             else nodo[chiave]))

    # 1. Il rilevamento di nmap, quando c'e'.
    nome = (leggi("os_name") or "").strip()
    if nome:
        precisione = leggi("os_accuracy")
        spiega = "rilevamento del sistema operativo di nmap"
        if precisione:
            spiega += " (precisione dichiarata %s%%)" % int(precisione)
        return esito(nome, "nmap", "rilevata", spiega)

    # 2. SMB: l'apparato dichiara la propria versione. Piu' attendibile di un
    #    rilevamento, perche' non e' dedotta.
    dichiarato = _os_da_smb(smb_os or "")
    if dichiarato:
        return esito(dichiarato, "SMB", "dichiarata",
                     "dichiarato dall'apparato stesso via SMB (smb-os-discovery)")

    # 3. SNMP: la descrizione di sistema e' scritta dal costruttore.
    dalla_descrizione = _da_testo(snmp_descr or "")
    if dalla_descrizione:
        return esito(dalla_descrizione, "SNMP", "dichiarata",
                     "riconosciuto nella descrizione di sistema dichiarata in SNMP")

    # 4. La famiglia rilevata, quando il nome preciso non c'e'.
    famiglia = (leggi("os_family") or "").strip()
    if famiglia:
        generazione = (leggi("os_gen") or "").strip()
        testo = ("%s %s" % (famiglia, generazione)).strip()
        return esito(testo, "nmap", "rilevata",
                     "famiglia rilevata da nmap; la versione precisa non e' stata"
                     " determinata")

    # 5. Il banner web: a volte nomina la distribuzione, a volte implica il sistema.
    dal_banner = _da_testo(web_server or "") or _da_testo(web_testo or "")
    if dal_banner:
        return esito(dal_banner, "pagina web", "dichiarata",
                     "riconosciuto in cio' che l'interfaccia web dichiara di se'")
    for espressione, sistema, perche in SERVER_IMPLICITO:
        if web_server and re.search(espressione, web_server):
            return esito(sistema, "pagina web", "rilevata", perche)

    # 6. Il profilo di porte. Vale come famiglia, non come versione.
    aperte = {int(p) for p in (porte or ()) if str(p).isdigit()}
    if aperte & PORTE_WINDOWS:
        quali = sorted(aperte & PORTE_WINDOWS)
        return esito("Windows (probabile)", "porte", "ipotesi",
                     "espone %s: sono servizi di Windows"
                     % ", ".join(str(p) for p in quali))
    if (aperte & PORTE_UNIX) and not (aperte & PORTE_WINDOWS):
        return esito("sistema tipo Unix (probabile)", "porte", "ipotesi",
                     "espone SSH e nessun servizio di Windows")

    # 7. Il TTL: tre famiglie, niente di piu'. E' l'ultimo indizio osservato.
    iniziale, descrizione = _arrotonda_ttl(leggi("ttl"))
    if iniziale:
        return esito(descrizione + " (dal TTL)", "TTL", "ipotesi",
                     "TTL osservato %s, compatibile con un TTL iniziale di %d:"
                     " distingue la famiglia, non la versione"
                     % (leggi("ttl"), iniziale))

    # 8. La classe dell'apparato: di una stampante il sistema e' il firmware.
    classe = (leggi("device_type") or "").strip()
    if classe in CLASSI_A_FIRMWARE:
        marca = (leggi("web_vendor") if hasattr(nodo, "get") else None) or \
                (leggi("mac_vendor") or "")
        testo = CLASSI_A_FIRMWARE[classe]
        if marca:
            testo += " %s" % marca.split()[0]
        return esito(testo, "classe", "ipotesi",
                     "di questa classe di apparati il \"sistema operativo\" e' il"
                     " firmware del costruttore, che non viene dichiarato in rete")

    # Ultima riga: non il vuoto, ma il motivo.
    return esito("non determinato", "nessuna", "ignota",
                 "nessun indizio: l'apparato non ha porte parlanti, non dichiara"
                 " nulla e non e' stato possibile rilevarne il sistema")
