"""
snap server - Regole di notifica: qualunque evento, una condizione, un canale.

Perche' le regole stanno nel database e non nel codice
-----------------------------------------------------
Cio' che merita una notifica cambia da cliente a cliente e cambia nel tempo. Una porta
3389 che si apre e' un evento in una rete e la normalita' in un'altra; un accesso
fallito e' rumore fino al giorno in cui e' il primo di venti. Scrivere queste scelte
nel codice significherebbe una versione nuova del prodotto per ogni cliente.

Forma di una regola
-------------------
    sorgente        dove guardare (variazioni dei nodi, esiti, incidenti, ...)
    tipo di evento  quale evento, oppure '*' per tutti quelli della sorgente
    condizioni      elenco di (attributo, operatore, valore), tutte da soddisfare
    canali          posta elettronica, bot Telegram, o entrambi
    finestra        anti-alluvione: quanti messaggi al massimo in quanti secondi

L'anti-alluvione non e' un dettaglio: la prima passata di scoperta ha prodotto 1851
aperture di porta. Una regola su `port.opened` senza limite avrebbe spedito 1851
messaggi, e il canale sarebbe stato silenziato dal destinatario entro cinque minuti.
Gli eventi oltre il limite non si perdono: vengono registrati come soppressi e contati
nel primo messaggio successivo.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json
import threading
from datetime import timedelta

from .audit import log_event
from .channels import CHANNEL_EMAIL, CHANNEL_TELEGRAM, CHANNELS, telegram_config
from .checks import ASSERTION_OPS, SEVERITIES
from .db import execute, query, utc_now, utc_now_str, utc_str
from .events import SOURCES, cursor_of, fetch_new, fetch_recent, set_cursor
from .notifications import queue_notification

EVENT = "rule.match"

# Cadenza del valutatore: gli eventi arrivano a lotti dai conferimenti delle sonde, e
# mezzo minuto e' abbastanza pronto per una notifica operativa senza far girare a
# vuoto il processo.
TICK_SECONDS = 30
# Guardie di configurazione.
MAX_CONDITIONS = 12
MAX_NAME_CHARS = 120
MAX_RECIPIENTS = 10
MIN_WINDOW_SECONDS = 60
MAX_WINDOW_SECONDS = 86400
MAX_PER_WINDOW = 100
# Quante regole per tenant: oltre, la valutazione di ogni evento diventa costosa e
# nessuno sa piu' quale regola ha prodotto un messaggio.
MAX_RULES_PER_TENANT = 100


class RuleError(ValueError):
    """Errore di definizione di una regola. Il messaggio e' per l'operatore."""


# --------------------------------------------------------------------------- #
# Validazione
# --------------------------------------------------------------------------- #
def validate_conditions(grezze) -> list:
    """Condizioni della regola: (attributo, operatore, valore atteso).

    Si accetta una lista di dizionari oppure il JSON equivalente. Tutte le condizioni
    devono essere soddisfatte: la disgiunzione si esprime con due regole, che e' anche
    piu' leggibile di un albero di operatori in una pagina web.
    """
    if grezze in (None, "", []):
        return []
    if isinstance(grezze, str):
        try:
            grezze = json.loads(grezze)
        except ValueError as errore:
            raise RuleError("Le condizioni non sono un JSON valido: %s" % errore) from errore
    if not isinstance(grezze, list):
        raise RuleError("Le condizioni devono essere un elenco.")

    condizioni = []
    for voce in grezze:
        if not isinstance(voce, dict):
            raise RuleError("Ogni condizione deve avere campo, operatore e valore.")
        campo = str(voce.get("field") or voce.get("path") or "").strip()
        operatore = str(voce.get("op") or "").strip().lower()
        if not campo:
            continue
        if operatore not in ASSERTION_OPS:
            raise RuleError("Operatore non previsto: %r" % operatore)
        valore = voce.get("value")
        if operatore not in ("exists", "absent") and (valore is None or valore == ""):
            raise RuleError("La condizione su %r richiede un valore atteso." % campo)
        condizioni.append({"field": campo, "op": operatore,
                           "value": None if valore is None else str(valore)})
    if len(condizioni) > MAX_CONDITIONS:
        raise RuleError("Non piu' di %d condizioni per regola." % MAX_CONDITIONS)
    return condizioni


def validate_channels(grezzi) -> list:
    if isinstance(grezzi, str):
        grezzi = [c.strip() for c in grezzi.replace(";", ",").split(",")]
    canali = [c for c in dict.fromkeys(grezzi or []) if c in CHANNELS]
    if not canali:
        raise RuleError("Indicare almeno un canale di recapito.")
    return canali


def validate_recipients(grezzi) -> str:
    if isinstance(grezzi, str):
        grezzi = grezzi.replace(";", ",").split(",")
    indirizzi = [r.strip() for r in (grezzi or []) if (r or "").strip()]
    if len(indirizzi) > MAX_RECIPIENTS:
        raise RuleError("Non piu' di %d destinatari per regola." % MAX_RECIPIENTS)
    for indirizzo in indirizzi:
        if "@" not in indirizzo or indirizzo.startswith("@") or indirizzo.endswith("@"):
            raise RuleError("Recapito non valido: %r" % indirizzo)
    return ", ".join(indirizzi)


def validate_rule(dati: dict) -> dict:
    """Valida la definizione di una regola. Solleva RuleError con il motivo."""
    nome = (dati.get("name") or "").strip()
    if not nome:
        raise RuleError("Indicare un nome per la regola: serve a riconoscerla nei"
                        " messaggi che spedisce.")
    if len(nome) > MAX_NAME_CHARS:
        raise RuleError("Il nome non puo' superare %d caratteri." % MAX_NAME_CHARS)

    sorgente = (dati.get("source") or "").strip()
    if sorgente not in SOURCES:
        raise RuleError("Sorgente di evento non prevista: %r" % sorgente)

    tipo = (dati.get("event_type") or "*").strip() or "*"
    gravita = (dati.get("severity") or "warning").strip()
    if gravita not in SEVERITIES:
        gravita = "warning"

    finestra = _intero(dati.get("window_seconds"), 900)
    if not MIN_WINDOW_SECONDS <= finestra <= MAX_WINDOW_SECONDS:
        raise RuleError("La finestra deve essere fra %d e %d secondi."
                        % (MIN_WINDOW_SECONDS, MAX_WINDOW_SECONDS))
    massimo = _intero(dati.get("max_per_window"), 5)
    if not 1 <= massimo <= MAX_PER_WINDOW:
        raise RuleError("I messaggi per finestra devono essere fra 1 e %d."
                        % MAX_PER_WINDOW)

    canali = validate_channels(dati.get("channels"))
    chat = (dati.get("telegram_chat_id") or "").strip()
    if CHANNEL_TELEGRAM in canali and not chat and not telegram_config()["chat_id"]:
        raise RuleError("Per il canale Telegram indicare la chat sulla regola oppure"
                        " configurare la chat predefinita del bot.")

    return {
        "name": nome,
        "description": (dati.get("description") or "").strip()[:500],
        "source": sorgente,
        "event_type": tipo,
        "conditions": validate_conditions(dati.get("conditions")),
        "severity": gravita,
        "channels": canali,
        "recipients": validate_recipients(dati.get("recipients")),
        "telegram_chat_id": chat,
        "window_seconds": finestra,
        "max_per_window": massimo,
        "digest_only": 1 if dati.get("digest_only") else 0,
    }


def _intero(valore, predefinito: int) -> int:
    try:
        return int(str(valore).strip())
    except (TypeError, ValueError):
        return predefinito


# --------------------------------------------------------------------------- #
# Persistenza
# --------------------------------------------------------------------------- #
def _decode(riga) -> dict:
    voce = dict(riga)
    try:
        voce["conditions"] = json.loads(riga["conditions_json"] or "[]")
    except (TypeError, ValueError):
        # Condizioni illeggibili: la regola non deve far cadere la pagina, ma non deve
        # nemmeno passare per "senza condizioni", che notificherebbe tutto.
        voce["conditions"] = []
        voce["broken"] = True
    voce["channel_list"] = [c for c in (riga["channels"] or "").split(",") if c]
    return voce


def rules_of(tenant_id: int, only_enabled: bool = False) -> list:
    condizione = " AND is_enabled = 1" if only_enabled else ""
    return [_decode(r) for r in query(
        "SELECT * FROM notify_rules WHERE tenant_id = ?" + condizione
        + " ORDER BY source, name", (tenant_id,))]


def rule(tenant_id: int, rule_id: int):
    riga = query("SELECT * FROM notify_rules WHERE id = ? AND tenant_id = ?",
                 (rule_id, tenant_id), one=True)
    return _decode(riga) if riga is not None else None


def create_rule(tenant_id: int, definizione: dict, created_by: int = None) -> int:
    quante = query("SELECT COUNT(*) AS n FROM notify_rules WHERE tenant_id = ?",
                   (tenant_id,), one=True)
    if int(quante["n"] or 0) >= MAX_RULES_PER_TENANT:
        raise RuleError("Raggiunto il massimo di %d regole." % MAX_RULES_PER_TENANT)
    adesso = utc_now_str()
    identificativo = execute(
        "INSERT INTO notify_rules (tenant_id, name, description, source, event_type,"
        " conditions_json, severity, channels, recipients, telegram_chat_id,"
        " window_seconds, max_per_window, digest_only, is_enabled, created_by,"
        " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
        (tenant_id, definizione["name"], definizione["description"],
         definizione["source"], definizione["event_type"],
         json.dumps(definizione["conditions"], ensure_ascii=False),
         definizione["severity"], ",".join(definizione["channels"]),
         definizione["recipients"], definizione["telegram_chat_id"],
         definizione["window_seconds"], definizione["max_per_window"],
         definizione["digest_only"], created_by, adesso, adesso))
    log_event("rules.created",
              "Regola '%s' creata su %s/%s" % (definizione["name"],
                                               definizione["source"],
                                               definizione["event_type"]),
              tenant_id=tenant_id, severity="info", entity="rule",
              entity_id=identificativo)
    return identificativo


def update_rule(tenant_id: int, rule_id: int, definizione: dict) -> None:
    execute(
        "UPDATE notify_rules SET name = ?, description = ?, source = ?, event_type = ?,"
        " conditions_json = ?, severity = ?, channels = ?, recipients = ?,"
        " telegram_chat_id = ?, window_seconds = ?, max_per_window = ?,"
        " digest_only = ?, updated_at = ? WHERE id = ? AND tenant_id = ?",
        (definizione["name"], definizione["description"], definizione["source"],
         definizione["event_type"],
         json.dumps(definizione["conditions"], ensure_ascii=False),
         definizione["severity"], ",".join(definizione["channels"]),
         definizione["recipients"], definizione["telegram_chat_id"],
         definizione["window_seconds"], definizione["max_per_window"],
         definizione["digest_only"], utc_now_str(), rule_id, tenant_id))
    log_event("rules.updated", "Regola '%s' modificata" % definizione["name"],
              tenant_id=tenant_id, severity="info", entity="rule", entity_id=rule_id)


def toggle_rule(tenant_id: int, rule_id: int) -> bool:
    corrente = rule(tenant_id, rule_id)
    if corrente is None:
        return False
    nuovo = 0 if corrente["is_enabled"] else 1
    execute("UPDATE notify_rules SET is_enabled = ?, updated_at = ?"
            " WHERE id = ? AND tenant_id = ?", (nuovo, utc_now_str(), rule_id, tenant_id))
    log_event("rules.toggled",
              "Regola '%s' %s" % (corrente["name"], "attivata" if nuovo else "sospesa"),
              tenant_id=tenant_id, severity="info", entity="rule", entity_id=rule_id)
    return True


def delete_rule(tenant_id: int, rule_id: int) -> bool:
    corrente = rule(tenant_id, rule_id)
    if corrente is None:
        return False
    execute("DELETE FROM notify_rules WHERE id = ? AND tenant_id = ?",
            (rule_id, tenant_id))
    log_event("rules.deleted", "Regola '%s' eliminata" % corrente["name"],
              tenant_id=tenant_id, severity="warning", entity="rule", entity_id=rule_id)
    return True


# --------------------------------------------------------------------------- #
# Valutazione
# --------------------------------------------------------------------------- #
def _valore(evento: dict, campo: str):
    """Valore di un attributo dell'evento. `None` se assente."""
    if campo in ("type", "severity", "subject", "detail", "source", "occurred_at"):
        return evento.get(campo)
    return (evento.get("attributi") or {}).get(campo)


def _confronta(valore, operatore: str, atteso) -> bool:
    """Vocabolario identico a quello delle verifiche sui controlli."""
    if operatore == "exists":
        return valore is not None
    if operatore == "absent":
        return valore is None
    if valore is None:
        return False
    testo = str(valore)
    atteso_testo = "" if atteso is None else str(atteso)
    if operatore == "eq":
        return testo.strip().lower() == atteso_testo.strip().lower()
    if operatore == "ne":
        return testo.strip().lower() != atteso_testo.strip().lower()
    if operatore == "contains":
        return atteso_testo.strip().lower() in testo.lower()
    if operatore in ("gt", "lt"):
        try:
            sinistra, destra = float(testo), float(atteso_testo)
        except (TypeError, ValueError):
            # Un confronto numerico su un valore non numerico non e' soddisfatto: e'
            # la stessa scelta delle verifiche sui controlli.
            return False
        return sinistra > destra if operatore == "gt" else sinistra < destra
    return False


def matches(regola: dict, evento: dict) -> bool:
    """Vero se l'evento soddisfa la regola."""
    if regola.get("broken"):
        return False
    if regola["source"] != evento["source"]:
        return False
    tipo = regola["event_type"] or "*"
    if tipo != "*":
        atteso = tipo.strip().lower()
        effettivo = (evento.get("type") or "").strip().lower()
        # Un tipo che finisce con '.' e' un prefisso: `port.` prende aperture e chiusure.
        if atteso.endswith("."):
            if not effettivo.startswith(atteso):
                return False
        elif effettivo != atteso:
            return False
    for condizione in regola["conditions"]:
        if not _confronta(_valore(evento, condizione["field"]), condizione["op"],
                          condizione.get("value")):
            return False
    return True


def _recenti_notificate(rule_id: int, finestra: int) -> int:
    da = utc_str(utc_now() - timedelta(seconds=int(finestra)))
    riga = query("SELECT COUNT(*) AS n FROM rule_matches WHERE rule_id = ?"
                 " AND notified = 1 AND created_at >= ?", (rule_id, da), one=True)
    return int(riga["n"] or 0)


def _soppresse_da_contare(rule_id: int) -> int:
    riga = query("SELECT COUNT(*) AS n FROM rule_matches WHERE rule_id = ?"
                 " AND suppressed = 1 AND notification_id IS NULL", (rule_id,), one=True)
    return int(riga["n"] or 0)


def _registra(tenant_id: int, regola: dict, evento: dict, notificato: bool,
              soppresso: bool, notification_id: int = None) -> int:
    adesso = utc_now_str()
    identificativo = execute(
        "INSERT INTO rule_matches (tenant_id, rule_id, source, source_id, event_type,"
        " subject, detail, severity, occurred_at, notified, suppressed, notification_id,"
        " created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (tenant_id, regola["id"], evento["source"], evento.get("source_id"),
         evento.get("type") or "", (evento.get("subject") or "")[:200],
         (evento.get("detail") or "")[:500], regola["severity"],
         evento.get("occurred_at") or adesso, 1 if notificato else 0,
         1 if soppresso else 0, notification_id, adesso))
    execute("UPDATE notify_rules SET matches_total = matches_total + 1,"
            " last_matched_at = ?, updated_at = ? WHERE id = ?",
            (adesso, adesso, regola["id"]))
    return identificativo


def _html_regola(regola: dict, evento: dict, soppressi: int = 0) -> str:
    """Il messaggio di una regola, nella forma condivisa.

    Il nome della regola e' in evidenza per una ragione pratica: chi riceve il
    messaggio e non lo vuole piu' deve sapere dove andare per spegnerlo.
    """
    from . import mail_layout as m
    from .notifications import _setting

    attributi = evento.get("attributi") or {}
    console = _setting("public_url", "")
    coppie = [
        ("Regola", regola["name"]),
        ("Sorgente", evento.get("source") or "-"),
        ("Soggetto", evento.get("subject") or "-"),
        ("Gravita'", evento.get("severity") or "-"),
        ("Quando", "%s UTC" % (evento.get("created_at") or "-")),
    ]
    coppie += [(str(chiave), str(valore)) for chiave, valore in
               list(attributi.items())[:8]]

    blocchi = [
        m.paragrafo(evento.get("description") or ""),
        m.fatti(coppie),
    ]
    if soppressi:
        blocchi.append(m.avviso(
            "Altri %d eventi corrispondono alla stessa regola in questa finestra e non"
            " sono stati notificati singolarmente: sono contati qui." % soppressi,
            "informativo"))
    blocchi.append(m.bottone("Apri le regole nella console",
                             "%s/rules/" % console.rstrip("/") if console else "",
                             "regola"))
    blocchi.append(m.paragrafo(
        "Questo messaggio arriva perche' la regola \"%s\" lo prevede: si modifica o si"
        " disattiva dalla console." % regola["name"]))

    return m.messaggio(
        titolo="Regola soddisfatta: %s" % regola["name"],
        sottotitolo=evento.get("subject") or "",
        genere="regola",
        preintestazione="%s - %s" % (regola["name"], evento.get("subject") or ""),
        blocchi=blocchi,
        perche="Ricevi questo messaggio perche' sei fra i destinatari della regola.",
        console_url=console,
    )


def message_for(regola: dict, evento: dict, soppressi: int = 0) -> tuple:
    """(oggetto, corpo) del messaggio di una regola.

    Il corpo dice che cosa e' accaduto, su che cosa, e quale regola ha deciso di
    dirlo: senza il nome della regola, chi riceve il messaggio non sa dove andare per
    non riceverlo piu'.
    """
    attributi = evento.get("attributi") or {}
    oggetto = "snap %s: %s" % (regola["name"], evento.get("subject") or
                               evento.get("type"))
    righe = [
        "Regola: %s" % regola["name"],
        "Evento: %s (%s)" % (evento.get("type"), evento.get("source")),
        "Soggetto: %s" % (evento.get("subject") or "-"),
        "Gravita': %s" % regola["severity"],
        "Quando: %s UTC" % evento.get("occurred_at"),
    ]
    if evento.get("detail"):
        righe.append("Dettaglio: %s" % evento["detail"])
    interessanti = [(k, v) for k, v in attributi.items()
                    if v not in (None, "", [])]
    if interessanti:
        righe.append("")
        righe.append("Attributi:")
        righe.extend("  %-16s %s" % (chiave, valore) for chiave, valore in interessanti)
    if regola.get("description"):
        righe.append("")
        righe.append(regola["description"])
    if soppressi:
        righe.append("")
        righe.append("Nella finestra precedente altri %d eventi hanno soddisfatto questa"
                     " regola e non sono stati notificati singolarmente (limite di %d"
                     " messaggi ogni %d secondi)."
                     % (soppressi, regola["max_per_window"], regola["window_seconds"]))
    return oggetto, "\n".join(righe)


def notify(tenant_id: int, regola: dict, evento: dict) -> dict:
    """Notifica un evento secondo una regola, rispettando l'anti-alluvione."""
    if regola["digest_only"]:
        # Registrata e non spedita: comparira' nel resoconto quotidiano.
        return {"notificato": False, "motivo": "solo resoconto",
                "match_id": _registra(tenant_id, regola, evento, False, False)}

    if _recenti_notificate(regola["id"], regola["window_seconds"]) >= regola["max_per_window"]:
        return {"notificato": False, "motivo": "limite della finestra raggiunto",
                "match_id": _registra(tenant_id, regola, evento, False, True)}

    soppressi = _soppresse_da_contare(regola["id"])
    oggetto, corpo = message_for(regola, evento, soppressi)
    identificativi = []
    for canale in regola["channel_list"]:
        if canale == CHANNEL_TELEGRAM:
            destinatari = [regola["telegram_chat_id"] or telegram_config()["chat_id"]]
        else:
            destinatari = [r.strip() for r in (regola["recipients"] or "").split(",")
                           if r.strip()] or _fallback_email(tenant_id)
        html = (_html_regola(regola, evento, soppressi)
                if canale == CHANNEL_EMAIL else None)
        identificativo = queue_notification(tenant_id, EVENT, destinatari, oggetto,
                                           corpo, channel=canale, body_html=html)
        if identificativo:
            identificativi.append(identificativo)

    primo = identificativi[0] if identificativi else None
    match_id = _registra(tenant_id, regola, evento, bool(identificativi), False, primo)
    if primo and soppressi:
        # Gli eventi soppressi sono stati contati in questo messaggio: si legano, cosi'
        # non vengono contati due volte.
        execute("UPDATE rule_matches SET notification_id = ? WHERE rule_id = ?"
                " AND suppressed = 1 AND notification_id IS NULL", (primo, regola["id"]))
    return {"notificato": bool(identificativi), "notifiche": identificativi,
            "match_id": match_id, "soppressi_contati": soppressi}


def _fallback_email(tenant_id: int) -> list:
    contatto = query("SELECT contact_email FROM tenants WHERE id = ?", (tenant_id,),
                     one=True)
    return [contatto["contact_email"]] if contatto and contatto["contact_email"] else []


# --------------------------------------------------------------------------- #
# Giro del valutatore
# --------------------------------------------------------------------------- #
def run_once(limit_per_source: int = None) -> dict:
    """Valuta gli eventi nuovi di tutte le sorgenti. Da chiamare in un contesto app.

    Il cursore avanza anche quando nessuna regola e' soddisfatta: diversamente, alla
    riaccensione si rileggerebbe tutto l'archivio.
    """
    from .events import BATCH_SIZE

    limite = limit_per_source or BATCH_SIZE
    esito = {"eventi": 0, "corrispondenze": 0, "notifiche": 0, "soppresse": 0}
    regole_per_tenant = {}

    for sorgente in SOURCES:
        eventi = fetch_new(sorgente, limit=limite)
        if not eventi:
            continue
        ultimo = cursor_of(sorgente)
        for evento in eventi:
            esito["eventi"] += 1
            ultimo = max(ultimo, int(evento["source_id"]))
            tenant_id = evento.get("tenant_id")
            if tenant_id is None:
                continue
            if tenant_id not in regole_per_tenant:
                regole_per_tenant[tenant_id] = rules_of(tenant_id, only_enabled=True)
            for regola in regole_per_tenant[tenant_id]:
                if not matches(regola, evento):
                    continue
                esito["corrispondenze"] += 1
                risultato = notify(tenant_id, regola, evento)
                if risultato["notificato"]:
                    esito["notifiche"] += len(risultato.get("notifiche", []))
                else:
                    esito["soppresse"] += 1
        set_cursor(sorgente, ultimo)
    return esito


def test_rule(tenant_id: int, definizione: dict, limit: int = 100) -> dict:
    """Che cosa avrebbe fatto la regola sugli ultimi eventi. Non spedisce nulla.

    E' il solo modo onesto di attivare una regola: senza la prova, la si attiva e si
    scopre dal numero di messaggi se era giusta.
    """
    finta = dict(definizione)
    finta.setdefault("id", 0)
    finta["channel_list"] = definizione.get("channels") or [CHANNEL_EMAIL]
    eventi = fetch_recent(definizione["source"], limit=limit, tenant_id=tenant_id)
    corrispondenti = [e for e in eventi if matches(finta, e)]
    return {
        "esaminati": len(eventi),
        "corrispondenti": len(corrispondenti),
        "esempi": corrispondenti[:20],
        "stima_messaggi": min(len(corrispondenti), definizione.get("max_per_window", 5)),
    }


def matches_of(tenant_id: int, rule_id: int = None, limit: int = 200) -> list:
    condizione = "" if rule_id is None else " AND m.rule_id = ?"
    parametri = [tenant_id] + ([rule_id] if rule_id is not None else []) + [int(limit)]
    return [dict(r) for r in query(
        "SELECT m.*, r.name AS rule_name, n.status AS notifica_stato,"
        " n.channel AS notifica_canale FROM rule_matches m"
        " JOIN notify_rules r ON r.id = m.rule_id"
        " LEFT JOIN notifications n ON n.id = m.notification_id"
        " WHERE m.tenant_id = ?" + condizione
        + " ORDER BY m.id DESC LIMIT ?", parametri)]


def summary(tenant_id: int) -> dict:
    righe = query("SELECT COUNT(*) AS regole, COALESCE(SUM(is_enabled), 0) AS attive,"
                  " COALESCE(SUM(matches_total), 0) AS corrispondenze"
                  " FROM notify_rules WHERE tenant_id = ?", (tenant_id,), one=True)
    ultime = query("SELECT COUNT(*) AS n FROM rule_matches WHERE tenant_id = ?"
                   " AND created_at >= ?",
                   (tenant_id, utc_str(utc_now() - timedelta(days=1))), one=True)
    return {
        "regole": int(righe["regole"] or 0),
        "attive": int(righe["attive"] or 0),
        "corrispondenze": int(righe["corrispondenze"] or 0),
        "ultime_24h": int(ultime["n"] or 0),
    }


_thread: threading.Thread | None = None
_stop = threading.Event()


def start_evaluator(app) -> None:
    """Avvia il valutatore delle regole, se non e' gia' avviato."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return

    def giro():
        while not _stop.wait(TICK_SECONDS):
            try:
                with app.app_context():
                    esito = run_once()
                    if esito["corrispondenze"]:
                        app.logger.info(
                            "Regole: %d eventi, %d corrispondenze, %d notifiche,"
                            " %d soppresse", esito["eventi"], esito["corrispondenze"],
                            esito["notifiche"], esito["soppresse"])
            except Exception as errore:  # nessun errore deve fermare il thread
                app.logger.warning("Valutazione delle regole non riuscita: %s", errore)

    _thread = threading.Thread(target=giro, name="snap-regole", daemon=True)
    _thread.start()
    app.logger.info("Valutatore delle regole avviato (ogni %d s)", TICK_SECONDS)


def stop_evaluator() -> None:
    _stop.set()
