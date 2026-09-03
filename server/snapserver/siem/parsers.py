# -----------------------------------------------------------------
# parsers.py — riconoscimento e normalizzazione dei log per famiglia di apparato
# Autore: Daniele Speziale
# Data creazione: 2026-09-02
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Da una riga di log a un evento normalizzato.

Ogni apparato scrive a modo suo. Qui una riga di syslog diventa un evento del
vocabolario comune (`EVENT_KINDS`): prima si legge l'involucro syslog (RFC 5424 o
il vecchio 3164), poi si applica il parser della famiglia che riconosce la riga.

Il riconoscimento e' per FIRME, con prima corrispondenza vincente, come per le
pagine web degli apparati: una firma e' una coppia (espressione, funzione che
estrae i campi). Una riga che nessuna firma riconosce resta un evento 'other' col
suo testo integrale: un log non capito e' comunque un log conservato e cercabile,
mai un log perduto.

Nessuna dipendenza esterna: solo `re`. Le regexp sono compilate una volta sola.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

# --------------------------------------------------------------------------- #
# Involucro syslog
# --------------------------------------------------------------------------- #
# Priorita' iniziale <PRI>: facility*8 + severity. Comune a 3164 e 5424.
_PRI = re.compile(r"^<(\d{1,3})>")
# RFC 5424: <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID ...
_5424 = re.compile(
    r"^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$", re.S)
# RFC 3164: <PRI>MMM dd hh:mm:ss HOST TAG: MSG
_3164 = re.compile(
    r"^<(\d{1,3})>([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$",
    re.S)

_SEVERITA_SYSLOG = {
    0: "critical", 1: "critical", 2: "critical", 3: "high",
    4: "medium", 5: "low", 6: "info", 7: "info",
}


def _severita_da_pri(pri: int) -> tuple:
    """(facility, severita' normalizzata) dalla priorita' syslog."""
    facility = pri // 8
    livello = pri % 8
    return str(facility), _SEVERITA_SYSLOG.get(livello, "info")


def _app_e_messaggio(tag: str, resto: str) -> tuple:
    """Dalla coppia TAG/MSG del 3164 ricava app e messaggio: 'sshd[1234]: testo'."""
    trovato = re.match(r"^([\w\-/.]+)(?:\[\d+\])?:\s*(.*)$", resto, re.S)
    if trovato:
        return trovato.group(1), trovato.group(2)
    return tag, resto


def parse_syslog(riga: str) -> dict:
    """Legge l'involucro syslog. Restituisce sempre un dizionario: una riga che non
    e' syslog valido diventa un messaggio nudo, non un errore."""
    riga = (riga or "").strip()
    base = {"host": None, "app": None, "event_time": None, "severity": "info",
            "facility": None, "message": riga}
    if not riga:
        return base

    m = _5424.match(riga)
    if m:
        pri, _ver, ts, host, app, _pid, _msgid, msg = m.groups()
        facility, severita = _severita_da_pri(int(pri))
        base.update({
            "host": None if host == "-" else host,
            "app": None if app == "-" else app,
            "event_time": _tempo_5424(ts),
            "severity": severita, "facility": facility,
            "message": msg.strip(),
        })
        return base

    m = _3164.match(riga)
    if m:
        pri, ts, host, resto = m.groups()
        facility, severita = _severita_da_pri(int(pri))
        app, msg = _app_e_messaggio(host, resto)
        base.update({
            "host": host, "app": app, "event_time": _tempo_3164(ts),
            "severity": severita, "facility": facility, "message": msg.strip(),
        })
        return base

    # Nessun involucro riconosciuto: se c'e' almeno la priorita', la si toglie.
    pri = _PRI.match(riga)
    if pri:
        facility, severita = _severita_da_pri(int(pri.group(1)))
        base.update({"severity": severita, "facility": facility,
                     "message": riga[pri.end():].strip()})
    return base


def _tempo_5424(ts: str) -> str | None:
    """ISO 8601 del 5424 nella forma di persistenza UTC."""
    if ts == "-":
        return None
    testo = ts.replace("Z", "+00:00")
    try:
        momento = datetime.fromisoformat(testo)
    except ValueError:
        return None
    if momento.tzinfo is not None:
        momento = momento.astimezone(timezone.utc)
    return momento.strftime("%Y-%m-%d %H:%M:%S")


def _tempo_3164(ts: str) -> str | None:
    """Il 3164 non porta l'anno: si assume quello corrente. Approssimazione nota e
    innocua -- l'istante autorevole resta il momento di ricezione."""
    try:
        parziale = datetime.strptime(ts, "%b %d %H:%M:%S")
    except ValueError:
        try:
            parziale = datetime.strptime(re.sub(r"\s+", " ", ts), "%b %d %H:%M:%S")
        except ValueError:
            return None
    adesso = datetime.now(timezone.utc)
    return parziale.replace(year=adesso.year).strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# Estrazione di campi comuni
# --------------------------------------------------------------------------- #
_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _primo_ip(testo: str) -> str | None:
    m = _IP.search(testo or "")
    return m.group(1) if m else None


def _campo_kv(testo: str, *chiavi: str) -> str | None:
    """Valore di una coppia chiave=valore (Fortinet, Windows via NXLog): il primo
    che compare fra le chiavi indicate. Accetta valori fra virgolette."""
    for chiave in chiavi:
        m = re.search(r"(?i)\b%s=(?:\"([^\"]*)\"|(\S+))" % re.escape(chiave), testo or "")
        if m:
            return (m.group(1) or m.group(2) or "").strip() or None
    return None


# --------------------------------------------------------------------------- #
# Firme per famiglia. Ogni voce: (regex/predicato, funzione -> aggiornamenti)
# La funzione riceve (messaggio, base_syslog) e torna un dizionario di campi
# normalizzati; almeno 'event_kind'. Prima corrispondenza vincente.
# --------------------------------------------------------------------------- #
def _windows(msg: str, base: dict) -> dict | None:
    # Eventi di sicurezza inoltrati via NXLog/WEF. Si riconoscono per EventID.
    eid = _campo_kv(msg, "EventID") or _numero_evento(msg)
    if not eid:
        return None
    utente = _campo_kv(msg, "TargetUserName", "SubjectUserName", "AccountName")
    ip = _campo_kv(msg, "IpAddress") or _primo_ip(msg)
    mappa = {
        "4625": ("auth_failure", "logon fallito"),
        "4624": ("auth_success", "logon riuscito"),
        "4740": ("auth_lockout", "utenza bloccata"),
        "4720": ("user_change", "utenza creata"),
        "4722": ("user_change", "utenza abilitata"),
        "4724": ("user_change", "reimpostazione password"),
        "4728": ("user_change", "aggiunta a gruppo privilegiato"),
        "4732": ("user_change", "aggiunta a gruppo locale"),
        "1102": ("log_cleared", "registro di sicurezza cancellato"),
        "4688": ("system", "nuovo processo creato"),
    }
    genere, azione = mappa.get(str(eid), ("system", "evento Windows %s" % eid))
    return {"event_kind": genere, "username": utente, "src_ip": ip,
            "action": azione, "outcome": "failure" if genere == "auth_failure"
            else ("success" if genere == "auth_success" else None)}


def _numero_evento(msg: str) -> str | None:
    m = re.search(r"(?i)\bEvent\s*ID[:\s]+(\d{3,5})\b", msg)
    return m.group(1) if m else None


def _cisco_asa(msg: str, base: dict) -> dict | None:
    m = re.search(r"%ASA-\d-(\d{6})", msg)
    if not m:
        return None
    codice = m.group(1)
    ip = _primo_ip(msg)
    mappa = {
        "106023": ("conn_denied", "connessione negata dalla ACL"),
        "106001": ("conn_denied", "connessione TCP negata"),
        "113012": ("auth_success", "autenticazione VPN riuscita"),
        "113005": ("auth_failure", "autenticazione VPN fallita"),
        "111008": ("config_change", "comando di configurazione eseguito"),
        "605005": ("auth_success", "accesso amministrativo riuscito"),
        "308001": ("auth_failure", "accesso amministrativo negato"),
    }
    genere, azione = mappa.get(codice, ("system", "messaggio ASA %s" % codice))
    return {"event_kind": genere, "src_ip": ip, "action": azione,
            "extra": {"asa_code": codice}}


def _fortinet(msg: str, base: dict) -> dict | None:
    # Fortigate: coppie chiave=valore con type/subtype/action.
    tipo = _campo_kv(msg, "type")
    if not tipo and "devname=" not in msg and "logid=" not in msg:
        return None
    azione = _campo_kv(msg, "action")
    utente = _campo_kv(msg, "user", "unauth_user")
    ip = _campo_kv(msg, "srcip") or _primo_ip(msg)
    dst = _campo_kv(msg, "dstip")
    sub = _campo_kv(msg, "subtype")
    if tipo == "event" and sub in ("vpn", "user"):
        genere = "auth_failure" if azione in ("login-failed", "failed") else "auth_success"
    elif azione in ("deny", "blocked", "dropped"):
        genere = "conn_denied"
    elif azione in ("accept", "allowed"):
        genere = "conn_allowed"
    elif sub == "virus" or tipo == "utm":
        genere = "malware"
    elif azione in ("edit", "add", "delete") and sub == "system":
        genere = "config_change"
    else:
        genere = "other"
    return {"event_kind": genere, "src_ip": ip, "dst_ip": dst, "username": utente,
            "action": azione, "extra": {"forti_type": tipo, "forti_subtype": sub}}


def _pfsense(msg: str, base: dict) -> dict | None:
    # filterlog: CSV con il verdetto in quinta colonna (pass/block).
    if (base.get("app") or "") != "filterlog" and "filterlog" not in msg:
        return None
    pezzi = msg.split(",")
    verdetto = pezzi[6] if len(pezzi) > 6 else ""
    genere = "conn_denied" if verdetto == "block" else "conn_allowed"
    ip = pezzi[18] if len(pezzi) > 19 else _primo_ip(msg)
    dst = pezzi[19] if len(pezzi) > 19 else None
    return {"event_kind": genere, "src_ip": ip, "dst_ip": dst, "action": verdetto}


def _linux(msg: str, base: dict) -> dict | None:
    app = (base.get("app") or "").lower()
    ip = _primo_ip(msg)
    if app.startswith("sshd") or "sshd" in msg[:8]:
        if "Failed password" in msg or "Invalid user" in msg or "authentication failure" in msg:
            utente = _dopo(msg, r"(?:invalid user |for (?:invalid user )?)(\S+)")
            return {"event_kind": "auth_failure", "username": utente, "src_ip": ip,
                    "action": "accesso SSH fallito", "outcome": "failure"}
        if "Accepted password" in msg or "Accepted publickey" in msg:
            utente = _dopo(msg, r"for (\S+)")
            return {"event_kind": "auth_success", "username": utente, "src_ip": ip,
                    "action": "accesso SSH riuscito", "outcome": "success"}
    if app.startswith("sudo") or " sudo:" in msg:
        if "authentication failure" in msg or "incorrect password" in msg:
            return {"event_kind": "auth_failure", "src_ip": ip,
                    "username": _dopo(msg, r"user=(\S+)"), "action": "sudo negato"}
        if "COMMAND=" in msg:
            return {"event_kind": "auth_success", "action": "comando via sudo",
                    "username": _dopo(msg, r"^\s*(\S+)\s*:")}
    if "pam_" in msg and ("authentication failure" in msg or "session opened" in msg):
        genere = "auth_success" if "session opened" in msg else "auth_failure"
        return {"event_kind": genere, "username": _dopo(msg, r"user=(\S+)"), "src_ip": ip}
    if app.startswith("useradd") or app.startswith("usermod") or "new user" in msg:
        return {"event_kind": "user_change", "action": "utenza modificata",
                "username": _dopo(msg, r"name=(\S+)")}
    return None


def _rete(msg: str, base: dict) -> dict | None:
    # Apparati di rete: Cisco IOS %SYS/%SEC, MikroTik, config e link.
    ip = _primo_ip(msg)
    if re.search(r"%SEC(?:_LOGIN)?-\d-LOGIN_FAILED", msg):
        return {"event_kind": "auth_failure", "src_ip": ip, "action": "login negato"}
    if re.search(r"%SYS-\d-CONFIG_I", msg) or "configured from" in msg:
        utente = _dopo(msg, r"by (\S+)")
        return {"event_kind": "config_change", "username": utente,
                "action": "configurazione modificata"}
    if re.search(r"%LINK-\d-UPDOWN|%LINEPROTO-\d-UPDOWN", msg):
        return {"event_kind": "port_change", "action": "stato collegamento cambiato"}
    if re.search(r"%SEC_LOGIN-\d-LOGIN_SUCCESS|login success", msg, re.I):
        return {"event_kind": "auth_success", "src_ip": ip, "action": "login riuscito"}
    # MikroTik: "user admin logged in", "login failure for user"
    if "logged in" in msg:
        return {"event_kind": "auth_success", "src_ip": ip,
                "username": _dopo(msg, r"user (\S+)"), "action": "accesso riuscito"}
    if "login failure" in msg:
        return {"event_kind": "auth_failure", "src_ip": ip,
                "username": _dopo(msg, r"user (\S+)"), "action": "accesso fallito"}
    return None


def _dopo(testo: str, pattern: str) -> str | None:
    m = re.search(pattern, testo or "")
    return m.group(1) if m else None


# Le firme per famiglia dichiarata. La sorgente sceglie quale insieme provare;
# 'other' e le sorgenti sconosciute provano tutte, in ordine di specificita'.
FIRME = {
    "windows": [_windows],
    "firewall": [_cisco_asa, _fortinet, _pfsense],
    "linux": [_linux],
    "network": [_rete],
}
_TUTTE = [_windows, _cisco_asa, _fortinet, _pfsense, _linux, _rete]


# --------------------------------------------------------------------------- #
# Allarmi a blocchi di un centralino Ericsson MX-ONE / MD110
# --------------------------------------------------------------------------- #
# Non e' syslog: e' un dump testuale in cui ogni allarme e' un blocco di righe
# "Campo ...: valore" separate da righe vuote. Va riconosciuto e spezzato in un
# evento per allarme, perche' un blocco intero in una riga sola non e' cercabile ne'
# correlabile. Un blocco comincia sempre con "Alarm handle".
_MXONE_INIZIO = re.compile(r"(?im)^\s*Alarm handle\b")
# Una riga "Etichetta ...: valore": l'etichetta comincia e finisce con una lettera,
# i puntini sono riempimento, il valore e' tutto cio' che segue i due punti.
_MXONE_RIGA = re.compile(r"^\s*([A-Za-z][A-Za-z /]*[A-Za-z])\s*\.*\s*:\s*(.*?)\s*$")

# Severita' Ericsson: si legge la parola dopo "=", con ricaduta sul numero.
_MXONE_SEVERITA = {
    "cleared": "info", "indeterminate": "low", "warning": "medium",
    "minor": "medium", "alert": "high", "major": "high", "critical": "critical",
}
_MXONE_SEVERITA_NUM = {"0": "info", "1": "low", "2": "medium", "3": "high",
                       "4": "critical", "5": "high"}


def _e_un_dump_mxone(testo: str) -> bool:
    """Vero se il testo e' un dump di allarmi MX-ONE (ha l'inizio e la struttura)."""
    return bool(_MXONE_INIZIO.search(testo or "")) and "Alarm code" in (testo or "")


def _severita_mxone(valore: str) -> tuple:
    """(gravita' normalizzata, testo grezzo) dal campo Severity dell'allarme.

    Il campo puo' dire "0 = cleared, was: 4 = critical": conta lo stato ATTUALE, che
    e' il primo (cleared), non quello precedente.
    """
    grezzo = (valore or "").strip()
    parola = re.search(r"=\s*([A-Za-z]+)", grezzo)
    if parola and parola.group(1).lower() in _MXONE_SEVERITA:
        return _MXONE_SEVERITA[parola.group(1).lower()], grezzo
    numero = re.match(r"\s*(\d)", grezzo)
    if numero:
        return _MXONE_SEVERITA_NUM.get(numero.group(1), "info"), grezzo
    return "info", grezzo


def _tempo_mxone(valore: str) -> str | None:
    """L'istante UTC di un campo "First at": "2026-09-02 04:59:52.504997 (UTC)"."""
    m = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", valore or "")
    return m.group(1) if m else None


def parse_mxone_alarms(testo: str) -> list[dict]:
    """Spezza un dump di allarmi MX-ONE in un evento normalizzato per allarme.

    Restituisce una lista vuota se il testo non e' un dump riconoscibile: il
    chiamante (l'ingestione) allora tratta la riga come un evento normale.
    """
    if not _e_un_dump_mxone(testo):
        return []
    # Ogni blocco comincia con "Alarm handle": si taglia prima di ciascuno.
    tagli = [m.start() for m in _MXONE_INIZIO.finditer(testo)]
    blocchi = [testo[inizio:fine] for inizio, fine in zip(tagli, tagli[1:] + [len(testo)])]
    eventi = []
    for blocco in blocchi:
        campi: dict = {}
        for riga in blocco.splitlines():
            m = _MXONE_RIGA.match(riga)
            if m and m.group(2):
                campi.setdefault(m.group(1).strip(), m.group(2).strip())
        if "Alarm code" not in campi:
            continue
        gravita, sev_grezza = _severita_mxone(campi.get("Severity", ""))
        codice = campi.get("Alarm code", "")
        apparato = campi.get("Faulty Equipment") or campi.get("Faulty unit") or ""
        dettaglio = campi.get("Additional text") or campi.get("Additional info") or ""
        # L'utenza, se il testo dell'allarme la dichiara ("User: eri_sn_d").
        utente = None
        u = re.search(r"User:\s*([^\s,]+)", campi.get("Additional text", ""))
        if u:
            utente = u.group(1)
        # Un host per raggruppare: il "Remote Host" se dichiarato, altrimenti
        # l'apparato guasto (MGW 1A, 2A-2-10-0...). Senza una chiave di
        # raggruppamento un allarme non potrebbe far scattare una regola.
        host = None
        h = re.search(r"Remote Host:\s*([^\s,]+)", campi.get("Additional text", ""))
        if h:
            host = h.group(1)
        elif apparato:
            host = apparato
        # Un allarme "cleared" (rientrato) non e' un guasto in corso: lo si annota.
        rientrato = "Cleared at" in campi or gravita == "info"
        sommario = "Allarme MX-ONE %s%s%s [%s]" % (
            codice,
            (" - %s" % apparato) if apparato else "",
            (" - %s" % dettaglio) if dettaglio else "",
            "rientrato" if rientrato else (sev_grezza.split("=")[-1].strip() or gravita))
        eventi.append({
            "event_kind": "equipment_alarm",
            "severity": gravita,
            "event_time": _tempo_mxone(campi.get("First at", "")),
            "host": host,
            "app": "MX-ONE",
            "username": utente,
            "action": codice,
            "outcome": "cleared" if rientrato else "active",
            "message": sommario,
            "extra": {
                "alarm_handle": campi.get("Alarm handle"),
                "alarm_domain": campi.get("Alarm domain"),
                "alarm_code": codice,
                "severity_raw": sev_grezza,
                "sender_lim": campi.get("Sender LIM"),
                "sender_unit": campi.get("Sender unit"),
                "faulty_equipment": campi.get("Faulty Equipment"),
                "faulty_unit": campi.get("Faulty unit"),
                "cleared_at": campi.get("Cleared at"),
                "count": campi.get("Count"),
            },
        })
    return eventi


def classify(riga: str, kind: str = "") -> dict:
    """Da una riga grezza a un evento normalizzato completo.

    `kind` e' la famiglia dichiarata della sorgente: se c'e', si provano prima le
    sue firme; poi, per non perdere un evento riconoscibile scritto da un apparato
    misto, si prova comunque il resto. Una riga senza firma resta 'other'.
    """
    base = parse_syslog(riga)
    candidate = list(FIRME.get(kind, [])) + [f for f in _TUTTE
                                             if f not in FIRME.get(kind, [])]
    for firma in candidate:
        try:
            esito = firma(base["message"], base)
        except (re.error, ValueError, IndexError):
            esito = None
        if esito:
            extra = esito.pop("extra", None)
            evento = dict(base)
            evento.update({k: v for k, v in esito.items() if v is not None})
            evento["_extra"] = extra
            return evento
    evento = dict(base)
    evento["event_kind"] = "other"
    evento["_extra"] = None
    return evento
