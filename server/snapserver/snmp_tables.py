"""
snap server - Letture SNMP in forma di tabella.

Gli script SNMP di nmap restituiscono testo pensato per essere letto da una persona
in un terminale: interfacce, processi, connessioni e software installato arrivano
come blocchi rientrati. Un elenco di ottanta connessioni in un riquadro di testo non
si legge, non si ordina e non si cerca; le stesse ottanta righe in tabella si'.

Il testo integrale resta la fonte: e' cio' che l'apparato ha davvero risposto, e
resta consultabile. L'interpretazione avviene **alla lettura**, non alla raccolta,
cosi' come per il riconoscimento dei dispositivi (SR-47): migliorare un parser non
richiede di riscansionare la rete, e cio' che oggi non si riconosce resta comunque
conservato.

Ogni parser restituisce sempre la stessa forma:

    {"kind": "tabella" | "coppie" | "elenco" | "testo",
     "titolo": str, "colonne": [str], "righe": [[valore]], "nota": str}

`kind` dice alla pagina come impaginare; `nota` spiega che cosa si sta guardando.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re

# Oltre questo numero di righe una tabella diventa un archivio: il resto e' nel testo
# integrale, che resta conservato e consultabile.
MAX_RIGHE = 400


def _righe_utili(testo: str) -> list[str]:
    return [r.rstrip() for r in (testo or "").splitlines() if r.strip()]


def _rientro(riga: str) -> int:
    return len(riga) - len(riga.lstrip())


def _blocchi(testo: str) -> list[tuple[str, list[str]]]:
    """Divide un esito annidato in (intestazione, righe di dettaglio).

    nmap stampa il nome della voce a un livello di rientro e i suoi dettagli a uno
    piu' profondo, e toglie il rientro alla prima riga dell'esito: la prima riga e'
    sempre un'intestazione, e il livello delle altre si legge dal resto.
    """
    righe = _righe_utili(testo)
    if not righe:
        return []
    rientri = [_rientro(r) for r in righe[1:]]
    utili = [n for n in rientri if n > 0]
    livello = min(utili) if utili else 0

    blocchi: list[tuple[str, list[str]]] = []
    for indice, riga in enumerate(righe):
        if indice == 0 or _rientro(riga) <= livello:
            blocchi.append((riga.strip(), []))
        elif blocchi:
            blocchi[-1][1].append(riga.strip())
    return blocchi


def _campo(righe: list[str], etichetta: str) -> str:
    """Valore di "Etichetta: valore" fra le righe di dettaglio di un blocco."""
    for riga in righe:
        trovato = re.match(r"%s\s*:\s*(.+)" % re.escape(etichetta), riga, re.I)
        if trovato:
            return trovato.group(1).strip()
    return ""


def _due_campi(righe: list[str], primo: str, secondo: str) -> tuple[str, str]:
    """Due etichette sulla stessa riga: "Type: X  Speed: Y"."""
    for riga in righe:
        trovato = re.search(r"%s\s*:\s*(.+?)\s\s+%s\s*:\s*(.+)"
                            % (re.escape(primo), re.escape(secondo)), riga, re.I)
        if trovato:
            return trovato.group(1).strip(), trovato.group(2).strip()
    return _campo(righe, primo), _campo(righe, secondo)


# --------------------------------------------------------------------------- #
# Parser per script
# --------------------------------------------------------------------------- #
def _interfacce(testo: str) -> dict:
    righe = []
    for nome, dettagli in _blocchi(testo):
        indirizzo = _campo(dettagli, "IP address")
        maschera = ""
        if indirizzo:
            # "IP address: 10.2.104.12  Netmask: 255.255.255.0" sulla stessa riga.
            indirizzo, maschera = _due_campi(dettagli, "IP address", "Netmask")
        mac = _campo(dettagli, "MAC address")
        tipo, velocita = _due_campi(dettagli, "Type", "Speed")
        stato = _campo(dettagli, "Status")
        traffico = _campo(dettagli, "Traffic stats")
        inviato, ricevuto = "", ""
        misurato = re.match(r"(.+?)\s+sent,\s*(.+?)\s+received", traffico or "")
        if misurato:
            inviato, ricevuto = misurato.group(1), misurato.group(2)
        righe.append([nome, indirizzo, maschera, mac, tipo, velocita, stato,
                      inviato, ricevuto])
    return {
        "kind": "tabella",
        "titolo": "Interfacce di rete",
        "colonne": ["INTERFACCIA", "INDIRIZZO", "MASCHERA", "MAC", "TIPO",
                    "VELOCITA'", "STATO", "INVIATO", "RICEVUTO"],
        "righe": righe[:MAX_RIGHE],
        "nota": "Un apparato con piu' indirizzi appartiene a piu' reti: le interfacce"
                " dicono a quali, e sono la mappa fisica che l'inventario da solo non"
                " vede.",
    }


ETICHETTE_INFO = {
    "enterprise": "Costruttore dichiarato",
    "engineIDFormat": "Formato dell'identificativo del motore",
    "engineIDData": "Identificativo del motore SNMP",
    "snmpEngineBoots": "Riavvii del motore SNMP",
    "snmpEngineTime": "Tempo dall'ultimo riavvio",
    "snmpEngineID": "Identificativo del motore SNMP",
    "System name": "Nome del sistema",
    "Location": "Collocazione dichiarata",
    "Contact": "Riferimento amministrativo",
    "Uptime": "Tempo di accensione",
    "System uptime": "Tempo di accensione",
}


def _coppie_etichettate(testo: str, titolo: str, nota: str) -> dict:
    righe = []
    for riga in _righe_utili(testo):
        trovato = re.match(r"([A-Za-z][\w \-]*?)\s*[:=]\s*(.+)", riga.strip())
        if not trovato:
            continue
        chiave = trovato.group(1).strip()
        righe.append([ETICHETTE_INFO.get(chiave, chiave), trovato.group(2).strip()])
    return {"kind": "coppie", "titolo": titolo, "colonne": ["CAMPO", "VALORE"],
            "righe": righe[:MAX_RIGHE], "nota": nota}


def _sysdescr(testo: str) -> dict:
    righe = _righe_utili(testo)
    if not righe:
        return _vuoto("Descrizione del sistema")
    voci = [["Descrizione dichiarata", righe[0].strip()]]
    for riga in righe[1:]:
        trovato = re.match(r"([A-Za-z][\w ]*?)\s*:\s*(.+)", riga.strip())
        if trovato:
            voci.append([ETICHETTE_INFO.get(trovato.group(1).strip(),
                                            trovato.group(1).strip()),
                         trovato.group(2).strip()])

    # Molti apparati impacchettano nella descrizione l'elenco dei firmware separati da
    # virgola o punto e virgola: separarli rende leggibile cio' che altrimenti e' una
    # riga di duecento caratteri.
    componenti = [p.strip() for p in re.split(r"[;,]", righe[0]) if p.strip()]
    if len(componenti) > 2:
        for parte in componenti[1:]:
            voci.append(["Componente dichiarato", parte])
    return {"kind": "coppie", "titolo": "Descrizione del sistema",
            "colonne": ["CAMPO", "VALORE"], "righe": voci[:MAX_RIGHE],
            "nota": "E' la riga che identifica l'apparato meglio di qualunque altra"
                    " prova: modello, versione del firmware, sistema operativo."}


def _netstat(testo: str) -> dict:
    righe = []
    for riga in _righe_utili(testo):
        trovato = re.match(r"(TCP|UDP)\s+(\S+?):(\d+)\s+(\S+?):(\d+)", riga.strip(),
                           re.I)
        if trovato:
            righe.append([trovato.group(1).upper(), trovato.group(2),
                          trovato.group(3), trovato.group(4), trovato.group(5)])
    return {
        "kind": "tabella",
        "titolo": "Connessioni e porte in ascolto",
        "colonne": ["PROTOCOLLO", "INDIRIZZO LOCALE", "PORTA", "INDIRIZZO REMOTO",
                    "PORTA REMOTA"],
        "righe": righe[:MAX_RIGHE],
        "nota": "Le porte in ascolto qui elencate sono quelle che l'apparato dichiara"
                " di se': comprendono anche quelle che una scansione dall'esterno non"
                " raggiunge, perche' filtrate o legate a un'altra interfaccia.",
    }


def _processi(testo: str) -> dict:
    righe = []
    for intestazione, dettagli in _blocchi(testo):
        trovato = re.match(r"(\d+)\s*:\s*(.*)", intestazione)
        identificativo = trovato.group(1) if trovato else ""
        comando = (trovato.group(2) if trovato else intestazione).strip()
        righe.append([identificativo,
                      _campo(dettagli, "Name") or comando,
                      _campo(dettagli, "Path"),
                      _campo(dettagli, "Params")])
    return {
        "kind": "tabella",
        "titolo": "Processi in esecuzione",
        "colonne": ["PID", "NOME", "PERCORSO", "PARAMETRI"],
        "righe": righe[:MAX_RIGHE],
        "nota": "Che cosa sta girando sull'apparato. Su un sistema di produzione e'"
                " anche l'elenco di cio' che va tenuto acceso.",
    }


def _software(testo: str) -> dict:
    righe = []
    for riga in _righe_utili(testo):
        parti = [p.strip() for p in riga.strip().split(";")]
        nome = parti[0] if parti else ""
        if not nome:
            continue  # righe senza nome: l'apparato le riempie di segnaposti
        quando = parti[-1] if len(parti) > 1 else ""
        if quando.startswith("0-00-00"):
            quando = ""  # data non impostata: dirlo e' meglio che mostrare uno zero
        righe.append([nome, quando])
    return {
        "kind": "tabella",
        "titolo": "Software installato",
        "colonne": ["SOFTWARE", "INSTALLATO IL"],
        "righe": righe[:MAX_RIGHE],
        "nota": "Il software dichiarato dall'apparato. E' la lista su cui la"
                " correlazione con le vulnerabilita' note lavora meglio, perche'"
                " porta con se' le versioni.",
    }


def _blocchi_nome_dettagli(testo: str, titolo: str, colonne: list, campi: list,
                           nota: str) -> dict:
    righe = []
    for nome, dettagli in _blocchi(testo):
        righe.append([nome] + [_campo(dettagli, campo) for campo in campi])
    return {"kind": "tabella", "titolo": titolo, "colonne": colonne,
            "righe": righe[:MAX_RIGHE], "nota": nota}


def _elenco_semplice(testo: str, titolo: str, colonna: str, nota: str) -> dict:
    righe = [[riga.strip()] for riga in _righe_utili(testo) if riga.strip()]
    return {"kind": "elenco", "titolo": titolo, "colonne": [colonna],
            "righe": righe[:MAX_RIGHE], "nota": nota}


def _vuoto(titolo: str) -> dict:
    return {"kind": "testo", "titolo": titolo, "colonne": [], "righe": [], "nota": ""}


PARSER = {
    "snmp-interfaces": _interfacce,
    "snmp-sysdescr": _sysdescr,
    "snmp-netstat": _netstat,
    "snmp-processes": _processi,
    "snmp-win32-software": _software,
    "snmp-info": lambda t: _coppie_etichettate(
        t, "Motore SNMP e costruttore",
        "Il costruttore dichiarato dall'agente SNMP: non e' il modello, ma dice di chi"
        " e' l'implementazione che risponde."),
    "snmp-win32-shares": lambda t: _blocchi_nome_dettagli(
        t, "Condivisioni di rete", ["CONDIVISIONE", "PERCORSO", "COMMENTO"],
        ["Path", "Comment"],
        "Le condivisioni raggiungibili sono la strada su cui si propagano i"
        " ransomware: qui l'apparato le elenca da se'."),
    "snmp-win32-services": lambda t: _elenco_semplice(
        t, "Servizi di sistema", "SERVIZIO",
        "I servizi dichiarati dal sistema, compresi quelli che non espongono una porta."),
    "snmp-win32-users": lambda t: _elenco_semplice(
        t, "Utenze locali", "UTENZA",
        "Nomi di utenza: possono essere dati personali quando identificano una"
        " persona, e come tali vanno trattati (GDPR art. 4)."),
    "snmp-hh3c-logins": lambda t: _elenco_semplice(
        t, "Accessi all'apparato", "VOCE",
        "Accessi amministrativi dichiarati dall'apparato."),
}

# Nomi leggibili per gli script di cui non si interpreta l'esito: il testo integrale
# resta comunque mostrato, con la sua intestazione.
TITOLI = {
    "snmp-brute": "Tentativi di community (non eseguito da questo prodotto)",
    "summary": "Riassunto",
}


def parse_script(script_id: str, output: str) -> dict:
    """Interpreta l'esito di uno script SNMP. Non solleva: cio' che non si riconosce
    resta testo, che e' comunque conservato e leggibile."""
    parser = PARSER.get(script_id)
    if parser is None:
        return {"kind": "testo", "titolo": TITOLI.get(script_id, script_id),
                "colonne": [], "righe": [], "nota": ""}
    try:
        tabella = parser(output or "")
    except (re.error, ValueError, TypeError, AttributeError):
        # Un formato inatteso non deve togliere la pagina: si mostra il testo.
        return {"kind": "testo", "titolo": TITOLI.get(script_id, script_id),
                "colonne": [], "righe": [], "nota": ""}
    if not tabella.get("righe"):
        tabella["kind"] = "testo"
    tabella["script_id"] = script_id
    return tabella


def parse_all(letture: list) -> list:
    """Interpreta un elenco di righe di `node_snmp` conservandone l'ordine utile.

    L'ordine e' quello di lettura di una persona: prima che cos'e' l'apparato, poi
    come e' collegato, poi che cosa ci gira sopra.
    """
    ordine = ["snmp-sysdescr", "snmp-info", "snmp-interfaces", "snmp-netstat",
              "snmp-processes", "snmp-win32-software", "snmp-win32-services",
              "snmp-win32-shares", "snmp-win32-users", "snmp-hh3c-logins"]

    def posizione(voce) -> int:
        script_id = voce["script_id"] if isinstance(voce, dict) else voce
        return ordine.index(script_id) if script_id in ordine else len(ordine)

    risultato = []
    for voce in sorted(letture, key=posizione):
        tabella = parse_script(voce["script_id"], voce.get("output") or "")
        tabella["output"] = voce.get("output") or ""
        tabella["collected_at"] = voce.get("collected_at")
        risultato.append(tabella)
    return risultato
