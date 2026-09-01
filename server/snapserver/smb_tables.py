# -----------------------------------------------------------------
# smb_tables.py — enumerazione SMB in forma di tabella
# Autore: Daniele Speziale
# Data creazione: 2026-08-31
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""Interpretazione dell'output degli script SMB di nmap in tabelle leggibili.

Gli script `smb-os-discovery`, `smb-enum-shares`, `smb-enum-users` e
`smb-security-mode` restituiscono testo pensato per una persona: qui se ne estraggono
i campi e le voci, per mostrarli come tabelle nella pagina del nodo. L'interpretazione
e' **tollerante** -- il formato cambia fra le versioni di nmap -- e non solleva mai:
cio' che non si riconosce resta testo, che e' comunque conservato e consultabile.

Rispecchia `snmp_tables`: stessa forma del risultato (`kind`, `titolo`, `colonne`,
`righe`, `nota`), cosi' il template li rende con lo stesso codice.
"""

from __future__ import annotations

import re

TITOLI = {
    "smb-os-discovery": "Sistema operativo e dominio",
    "smb-enum-shares": "Condivisioni pubblicate",
    "smb-enum-users": "Utenze locali e di dominio",
    "smb-security-mode": "Modalita' di sicurezza SMB",
    "smb-protocols": "Versioni del protocollo SMB",
    "smb2-security-mode": "Firma dei messaggi (SMB2)",
    "smb2-capabilities": "Capacita' SMB2",
}


def _righe_utili(testo: str) -> list[str]:
    return [r.rstrip() for r in (testo or "").splitlines() if r.strip()]


def _vuoto(titolo: str) -> dict:
    return {"kind": "testo", "titolo": titolo, "colonne": [], "righe": [], "nota": ""}


def _os_discovery(testo: str) -> dict:
    """I campi d'identita' come coppie etichetta/valore, nell'ordine che si legge."""
    etichette = [
        ("OS", "Sistema operativo"),
        ("OS CPE", "Identificativo CPE"),
        ("Computer name", "Nome del computer"),
        ("NetBIOS computer name", "Nome NetBIOS"),
        ("Domain name", "Dominio"),
        ("Forest name", "Foresta"),
        ("FQDN", "Nome pienamente qualificato"),
        ("Workgroup", "Gruppo di lavoro"),
        ("System time", "Ora di sistema dell'apparato"),
    ]
    righe = []
    for chiave, etichetta in etichette:
        trovato = re.search(r"(?:^|\n)\s*" + re.escape(chiave) + r"\s*:\s*(.+)",
                            testo, re.I)
        if not trovato:
            continue
        valore = re.sub(r"(?:\\x00)+$", "", trovato.group(1).strip()).strip()
        if valore and valore.lower() not in ("unknown", "<unknown>", "n/a"):
            righe.append([etichetta, valore])
    if not righe:
        return _vuoto(TITOLI["smb-os-discovery"])
    return {"kind": "coppie", "titolo": TITOLI["smb-os-discovery"],
            "colonne": ["Campo", "Valore"], "righe": righe,
            "nota": "Dichiarato dall'apparato tramite SMB: identifica la versione di"
                    " Windows e l'appartenenza al dominio."}


def _enum_shares(testo: str) -> dict:
    """Una riga per condivisione, con tipo, commento e accesso, quando dichiarati.

    Il formato di nmap annida i dettagli sotto il nome della condivisione:

        \\\\host\\ADMIN$:
          Type: STYPE_DISKTREE_HIDDEN
          Comment: Remote Admin
          Anonymous access: <none>
          Current user access: READ/WRITE
    """
    righe_txt = _righe_utili(testo)
    condivisioni = []
    corrente = None
    account = ""
    for riga in righe_txt:
        rientrata = riga[:1].isspace()
        contenuto = riga.strip()
        if not rientrata:
            testa = contenuto.lower()
            if testa.startswith(("error:", "error ", "false", "smb:")):
                continue
            if testa.startswith("account_used"):
                account = contenuto.split(":", 1)[1].strip() if ":" in contenuto else ""
                continue
            # Nuova condivisione: il nome e' cio' che precede i due punti finali.
            nome = contenuto.rstrip(":").strip()
            corrente = {"nome": nome, "tipo": "", "commento": "",
                        "anonimo": "", "utente": ""}
            condivisioni.append(corrente)
        elif corrente is not None and ":" in contenuto:
            chiave, valore = (p.strip() for p in contenuto.split(":", 1))
            mappa = {"type": "tipo", "comment": "commento",
                     "anonymous access": "anonimo", "current user access": "utente"}
            campo = mappa.get(chiave.lower())
            if campo:
                corrente[campo] = valore
    if not condivisioni:
        return _vuoto(TITOLI["smb-enum-shares"])
    righe = [[c["nome"], _tipo_condivisione(c["tipo"]), c["commento"],
              c["anonimo"] or "-", c["utente"] or "-"] for c in condivisioni]
    nota = "Condivisioni SMB pubblicate dall'apparato."
    if account:
        nota += " Enumerate con l'utenza: %s." % account
    return {"kind": "tabella", "titolo": TITOLI["smb-enum-shares"],
            "colonne": ["Condivisione", "Tipo", "Commento",
                        "Accesso anonimo", "Accesso utente"],
            "righe": righe, "nota": nota}


def _tipo_condivisione(grezzo: str) -> str:
    """Traduce le costanti STYPE_ di nmap in qualcosa di leggibile."""
    g = (grezzo or "").upper()
    if not g:
        return ""
    parti = []
    if "DISKTREE" in g:
        parti.append("disco")
    elif "PRINTQ" in g:
        parti.append("stampa")
    elif "IPC" in g:
        parti.append("IPC")
    elif "DEVICE" in g:
        parti.append("dispositivo")
    else:
        parti.append(grezzo)
    if "HIDDEN" in g:
        parti.append("nascosta")
    return " ".join(parti)


def _enum_users(testo: str) -> dict:
    """Una riga per utenza, con il RID e i flag dell'account.

    Il formato di nmap:

        DOMINIO\\Administrator (RID: 500)
          Flags:       Normal user account, Password does not expire
    """
    righe_txt = _righe_utili(testo)
    utenti = []
    corrente = None
    for riga in righe_txt:
        rientrata = riga[:1].isspace()
        contenuto = riga.strip()
        if not rientrata:
            if contenuto.lower().startswith(("error:", "error ", "false", "smb:")):
                continue
            nome = contenuto
            rid = ""
            trovato = re.search(r"\(RID:\s*(\d+)\)", contenuto)
            if trovato:
                rid = trovato.group(1)
                nome = contenuto[:trovato.start()].strip()
            corrente = {"nome": nome, "rid": rid, "flag": ""}
            utenti.append(corrente)
        elif corrente is not None:
            trovato = re.search(r"Flags?\s*:\s*(.+)", contenuto, re.I)
            if trovato:
                corrente["flag"] = trovato.group(1).strip()
    if not utenti:
        return _vuoto(TITOLI["smb-enum-users"])
    righe = [[u["nome"], u["rid"] or "-", _flag_leggibili(u["flag"])] for u in utenti]
    return {"kind": "tabella", "titolo": TITOLI["smb-enum-users"],
            "colonne": ["Utenza", "RID", "Stato dell'account"], "righe": righe,
            "nota": "Utenze enumerate via SMB. Un RID 500 e' l'amministratore locale;"
                    " un account abilitato con password che non scade e' un punto da"
                    " verificare."}


def _flag_leggibili(grezzo: str) -> str:
    """Rende i flag di nmap in italiano, tenendo cio' che non si riconosce."""
    if not grezzo:
        return "-"
    traduzioni = [
        ("account disabled", "disabilitato"),
        ("password does not expire", "password che non scade"),
        ("password not required", "password non richiesta"),
        ("normal user account", "utente normale"),
        ("account locked", "bloccato"),
        ("interdomain trust account", "trust interdominio"),
        ("workstation trust account", "trust di postazione"),
        ("server trust account", "trust di server"),
    ]
    testo = grezzo
    for inglese, italiano in traduzioni:
        testo = re.sub(re.escape(inglese), italiano, testo, flags=re.I)
    return testo


def _security_mode(testo: str) -> dict:
    """La firma dei messaggi: richiesta, oppure no (che e' un riscontro)."""
    righe = []
    for chiave, etichetta in (("message_signing", "Firma dei messaggi"),
                              ("account_used", "Utenza usata")):
        trovato = re.search(r"(?:^|\n)\s*" + chiave + r"\s*:\s*(.+)", testo, re.I)
        if trovato:
            righe.append([etichetta, trovato.group(1).strip()])
    if not righe:
        return _vuoto(TITOLI["smb-security-mode"])
    return {"kind": "coppie", "titolo": TITOLI["smb-security-mode"],
            "colonne": ["Campo", "Valore"], "righe": righe,
            "nota": "La firma dei messaggi non richiesta espone a manomissione delle"
                    " sessioni SMB (relay)."}


def _protocols(testo: str) -> dict:
    """I dialetti SMB supportati. La presenza di SMBv1 e' un riscontro di sicurezza."""
    dialetti = re.findall(
        r"(?:^|\n)\s*(NT LM 0\.12|SMBv[123]|[0-9]+\.[0-9]+(?:\.[0-9]+)?)", testo)
    if not dialetti:
        return _vuoto(TITOLI["smb-protocols"])
    visti = list(dict.fromkeys(dialetti))
    v1 = any(d in ("NT LM 0.12", "SMBv1") for d in visti)
    righe = [[d, "SMBv1 -- obsoleto e insicuro, andrebbe disabilitato"
              if d in ("NT LM 0.12", "SMBv1") else ""] for d in visti]
    nota = "Dialetti SMB che l'apparato accetta."
    if v1:
        nota += (" Attenzione: SMBv1 e' abilitato -- e' il protocollo sfruttato da"
                 " WannaCry, disabilitato per difetto sui sistemi recenti.")
    return {"kind": "tabella", "titolo": TITOLI["smb-protocols"],
            "colonne": ["Dialetto", "Note"], "righe": righe, "nota": nota}


PARSER = {
    "smb-os-discovery": _os_discovery,
    "smb-enum-shares": _enum_shares,
    "smb-enum-users": _enum_users,
    "smb-security-mode": _security_mode,
    "smb2-security-mode": _security_mode,
    "smb-protocols": _protocols,
}


def parse_script(script_id: str, output: str) -> dict:
    """Interpreta l'esito di uno script SMB. Non solleva: cio' che non si riconosce
    resta testo, che e' comunque conservato e leggibile."""
    parser = PARSER.get(script_id)
    if parser is None:
        return {"kind": "testo", "titolo": TITOLI.get(script_id, script_id),
                "colonne": [], "righe": [], "nota": ""}
    try:
        tabella = parser(output or "")
    except (re.error, ValueError, TypeError, AttributeError):
        return {"kind": "testo", "titolo": TITOLI.get(script_id, script_id),
                "colonne": [], "righe": [], "nota": ""}
    if not tabella.get("righe"):
        tabella["kind"] = "testo"
    tabella["script_id"] = script_id
    return tabella


def parse_all(letture: list) -> list:
    """Interpreta le righe di `node_smb` nell'ordine di lettura di una persona:
    prima che macchina e', poi che cosa pubblica, poi chi ci accede."""
    ordine = ["smb-os-discovery", "smb-protocols", "smb-security-mode",
              "smb2-security-mode", "smb-enum-shares", "smb-enum-users"]

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
