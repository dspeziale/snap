"""
snap server - Notifiche dei momenti del workflow.

Cosa notifica
-------------
Ogni passaggio del workflow di un incidente:

    incident.opened        l'incidente si e' aperto (soglia di apertura superata)
    incident.escalated     e' stato attivato un operatore (seconda soglia)
    incident.recovered     il controllo e' rientrato ma l'incidente resta aperto
    incident.resolved      l'incidente e' stato chiuso, da se' o da una persona
    incident.acknowledged  un operatore lo ha preso in carico

Perche' una coda di uscita e non un invio diretto
-------------------------------------------------
Le notifiche nascono dentro il conferimento di un lotto: un server di posta lento
bloccherebbe l'ingest di una sonda per secondi, e un server di posta irraggiungibile
lo farebbe fallire. Le notifiche vengono percio' SCRITTE in una coda e spedite da un
thread a se', con ritentativi. Una notifica non recapitata resta visibile con il
proprio errore: una notifica persa in silenzio e' peggio di una non inviata.

Dipendenze
----------
Nessuna aggiunta: `smtplib` e `email` sono nella libreria standard. Senza SMTP
configurato le notifiche vengono comunque accodate e restano in attesa -- cosi' il
workflow e' completo e tracciato anche prima che qualcuno configuri la posta.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import mimetypes
import smtplib
import ssl
import threading
from email.message import EmailMessage
from email.utils import formataddr, formatdate
from pathlib import Path

from flask import current_app

from .channels import (
    CHANNEL_EMAIL,
    CHANNEL_TELEGRAM,
    CHANNELS,
    ChannelError,
    is_telegram_configured,
    send_telegram,
    telegram_config,
)
from .db import execute, query, utc_now_str

# Momenti del workflow che producono una notifica, con l'etichetta mostrata.
NOTIFY_EVENTS = {
    "incident.opened": "Incidente aperto",
    "incident.escalated": "Operatore attivato",
    "incident.recovered": "Controllo rientrato, incidente ancora aperto",
    "incident.acknowledged": "Incidente preso in carico",
    "incident.resolved": "Incidente risolto",
    "report.daily": "Resoconto quotidiano",
    "rule.match": "Regola soddisfatta",
    # La credenziale provvisoria di un utente appena creato. Non e' un momento del
    # workflow degli incidenti: non passa dalla scelta in Amministrazione, perche'
    # trovarsela disattivata significherebbe un utente che non riceve le proprie
    # credenziali senza che nessuno se ne accorga.
    "user.created": "Utente creato: credenziali provvisorie",
    # Termini di legge per la comunicazione ad ACN. Come le credenziali, NON passano
    # dalla scelta in Amministrazione: un termine di legge disattivato per una scelta
    # fatta anni prima e' esattamente il modo in cui si perde una scadenza.
    "acn.deadline.approaching": "Termine ACN in avvicinamento",
    "acn.deadline.passed": "Termine ACN superato",
}

# Solo i momenti del workflow degli incidenti sono soggetti alla scelta in
# Amministrazione: il resoconto quotidiano e le regole hanno un proprio interruttore,
# e trovarsi il resoconto silenziosamente disattivato perche' anni prima qualcuno ha
# ristretto l'elenco degli incidenti da notificare sarebbe una sorpresa.
FILTERED_EVENTS = {
    "incident.opened", "incident.escalated", "incident.recovered",
    "incident.acknowledged", "incident.resolved",
}

# Stati di una notifica in coda.
PENDING = "pending"
SENT = "sent"
FAILED = "failed"
SKIPPED = "skipped"

# Oltre questo numero di tentativi la notifica non si ritenta piu': un indirizzo
# sbagliato non diventa giusto al decimo invio, e la coda non deve crescere per
# sempre. L'errore resta visibile.
MAX_ATTEMPTS = 5
# Tempo massimo di attesa del server di posta. Un valore alto bloccherebbe il thread
# di spedizione su un solo messaggio.
SMTP_TIMEOUT_SECONDS = 15
# Cadenza del thread di spedizione.
DISPATCH_INTERVAL_SECONDS = 20


# --------------------------------------------------------------------------- #
# Configurazione
# --------------------------------------------------------------------------- #
def _setting(key: str, default: str = "") -> str:
    riga = query("SELECT value FROM system_settings WHERE key = ?", (key,), one=True)
    if riga is None or riga["value"] is None:
        return default
    return str(riga["value"])


def smtp_config() -> dict:
    """Configurazione della posta, dalle impostazioni di sistema."""
    porta = _setting("smtp_port", "25")
    try:
        porta = int(porta)
    except (TypeError, ValueError):
        porta = 25
    return {
        "host": _setting("smtp_host").strip(),
        "port": porta,
        "security": (_setting("smtp_security", "none") or "none").strip().lower(),
        "username": _setting("smtp_username").strip(),
        "password": _setting("smtp_password"),
        "sender": _setting("smtp_sender").strip(),
        "sender_name": _setting("smtp_sender_name", "snap").strip() or "snap",
        "enabled": _setting("notifications_enabled", "1") != "0",
    }


def is_configured(config: dict = None) -> bool:
    """Vero se la posta e' configurata a sufficienza per tentare un invio."""
    config = config or smtp_config()
    return bool(config["host"] and config["sender"])


def enabled_events() -> set:
    """Momenti del workflow per i quali si notifica.

    In mancanza di una scelta esplicita si notifica tutto: un workflow che tace su
    un passaggio importante e' una sorpresa, e chi non vuole una notifica la
    disattiva.
    """
    grezzo = _setting("notify_events", "").strip()
    if not grezzo:
        return set(NOTIFY_EVENTS)
    scelti = {v.strip() for v in grezzo.split(",") if v.strip()}
    return {e for e in scelti if e in NOTIFY_EVENTS}


# --------------------------------------------------------------------------- #
# Coda di uscita
# --------------------------------------------------------------------------- #
def queue_notification(tenant_id: int, event: str, recipients, subject: str,
                       body: str, incident_id: int = None,
                       channel: str = CHANNEL_EMAIL, body_html: str = None,
                       attachment=None) -> int | None:
    """Accoda una notifica su un canale. Restituisce l'identificativo, None se non si
    accoda.

    Non si accoda quando: le notifiche sono disattivate, il momento del workflow non
    e' fra quelli scelti, oppure il canale indicato non esiste. Quando manca il
    destinatario la notifica viene invece REGISTRATA come saltata: resta la traccia di
    cio' che non e' stato inviato, che e' l'informazione utile.
    """
    if event not in NOTIFY_EVENTS:
        raise ValueError("momento del workflow non previsto: %r" % event)
    if channel not in CHANNELS:
        raise ValueError("canale di recapito non previsto: %r" % channel)

    if isinstance(recipients, str):
        recipients = [recipients]
    destinatari = ", ".join(sorted({(r or "").strip() for r in (recipients or []) if r}))

    config = smtp_config()
    if not config["enabled"]:
        return None
    if event in FILTERED_EVENTS and event not in enabled_events():
        return None

    allegato = str(attachment) if attachment else None
    adesso = utc_now_str()
    if not destinatari:
        return execute(
            "INSERT INTO notifications (tenant_id, incident_id, event, channel,"
            " recipients, subject, body, body_html, attachment_path, status, attempts,"
            " last_error, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, '', ?, ?, ?, ?, ?, 0, ?, ?, ?)",
            (tenant_id, incident_id, event, channel, subject, body, body_html,
             allegato, SKIPPED,
             "nessun destinatario: indicare un recapito sul controllo, l'email di"
             " riferimento del tenant oppure la chat del bot", adesso, adesso))

    return execute(
        "INSERT INTO notifications (tenant_id, incident_id, event, channel, recipients,"
        " subject, body, body_html, attachment_path, status, attempts, created_at,"
        " updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
        (tenant_id, incident_id, event, channel, destinatari, subject, body, body_html,
         allegato, PENDING, adesso, adesso))


def pending_notifications(limit: int = 50) -> list:
    return [dict(r) for r in query(
        "SELECT * FROM notifications WHERE status = ? AND attempts < ?"
        " ORDER BY id LIMIT ?", (PENDING, MAX_ATTEMPTS, int(limit)))]


def recent_notifications(tenant_id: int, limit: int = 200) -> list:
    return [dict(r) for r in query(
        "SELECT * FROM notifications WHERE tenant_id = ?"
        " ORDER BY id DESC LIMIT ?", (tenant_id, int(limit)))]


def notifications_summary(tenant_id: int) -> dict:
    righe = query("SELECT status, COUNT(*) AS n FROM notifications WHERE tenant_id = ?"
                  " GROUP BY status", (tenant_id,))
    conteggi = {r["status"]: int(r["n"]) for r in righe}
    canali = query("SELECT channel, COUNT(*) AS n FROM notifications"
                   " WHERE tenant_id = ? GROUP BY channel", (tenant_id,))
    return {
        "sent": conteggi.get(SENT, 0),
        "pending": conteggi.get(PENDING, 0),
        "failed": conteggi.get(FAILED, 0),
        "skipped": conteggi.get(SKIPPED, 0),
        "configured": is_configured(),
        "telegram_configured": is_telegram_configured(),
        "per_channel": {r["channel"]: int(r["n"]) for r in canali},
    }


# --------------------------------------------------------------------------- #
# Spedizione
# --------------------------------------------------------------------------- #
def _connect(config: dict):
    """Connessione al server di posta, secondo la sicurezza richiesta."""
    if config["security"] == "ssl":
        connessione = smtplib.SMTP_SSL(config["host"], config["port"],
                                       timeout=SMTP_TIMEOUT_SECONDS,
                                       context=ssl.create_default_context())
    else:
        connessione = smtplib.SMTP(config["host"], config["port"],
                                   timeout=SMTP_TIMEOUT_SECONDS)
        if config["security"] == "starttls":
            connessione.starttls(context=ssl.create_default_context())
    if config["username"]:
        connessione.login(config["username"], config["password"])
    return connessione


def compose(config: dict, recipients: str, subject: str, body: str,
            body_html: str = None, attachment=None) -> EmailMessage:
    """Messaggio di posta: testo sempre, HTML come alternativa, allegato se indicato.

    Il testo semplice non e' un ripiego: e' la forma che si legge su qualunque client
    e nelle notifiche di sistema. L'HTML e' l'alternativa, non il contenuto.
    """
    messaggio = EmailMessage()
    messaggio["From"] = formataddr((config["sender_name"], config["sender"]))
    messaggio["To"] = recipients
    messaggio["Subject"] = subject
    messaggio["Date"] = formatdate(localtime=True)
    # Intestazione propria: permette ai filtri di posta del destinatario di
    # riconoscere queste notifiche senza affidarsi all'oggetto.
    messaggio["X-Snap-Notification"] = "workflow"
    messaggio.set_content(body)
    if body_html:
        messaggio.add_alternative(body_html, subtype="html")
    if attachment:
        percorso = Path(attachment)
        if not percorso.is_file():
            raise FileNotFoundError("allegato non trovato: %s" % percorso)
        tipo = mimetypes.guess_type(percorso.name)[0] or "application/octet-stream"
        principale, _, secondario = tipo.partition("/")
        messaggio.add_attachment(percorso.read_bytes(), maintype=principale,
                                 subtype=secondario or "octet-stream",
                                 filename=percorso.name)
    return messaggio


def send_now(config: dict, recipients: str, subject: str, body: str,
             body_html: str = None, attachment=None) -> None:
    """Spedisce un messaggio. Solleva in caso di errore: decide il chiamante."""
    with _connect(config) as connessione:
        connessione.send_message(compose(config, recipients, subject, body,
                                         body_html, attachment))


def _deliver(notifica: dict, posta: dict, telegram: dict) -> None:
    """Recapita una notifica sul proprio canale. Solleva se non riesce.

    Un canale non configurato non e' un fallimento del messaggio: e' una
    configurazione mancante, e viene distinta perche' i ritentativi non la
    risolverebbero.
    """
    canale = (notifica.get("channel") or CHANNEL_EMAIL).strip()
    if canale == CHANNEL_TELEGRAM:
        if not is_telegram_configured(telegram) or not telegram["enabled"]:
            raise ChannelError("canale Telegram non configurato o disattivato")
        send_telegram(telegram, notifica["recipients"], notifica["body"],
                      attachment=notifica.get("attachment_path"))
        return
    if not posta["enabled"] or not is_configured(posta):
        raise ChannelError("posta non configurata: indicare almeno server e mittente")
    send_now(posta, notifica["recipients"], notifica["subject"], notifica["body"],
             notifica.get("body_html"), notifica.get("attachment_path"))


def dispatch_pending(limit: int = 20) -> dict:
    """Tenta la spedizione delle notifiche in attesa, ciascuna sul proprio canale.

    Restituisce il riepilogo di cio' che e' accaduto: e' l'informazione che serve
    per capire, dalla pagina, se il recapito funziona.
    """
    posta = smtp_config()
    telegram = telegram_config()
    if not posta["enabled"]:
        return {"sent": 0, "failed": 0, "skipped": 0, "reason": "notifiche disattivate"}
    if not is_configured(posta) and not is_telegram_configured(telegram):
        return {"sent": 0, "failed": 0, "skipped": 0,
                "reason": "nessun canale configurato: indicare la posta oppure il bot"
                          " Telegram"}

    inviate = 0
    fallite = 0
    for notifica in pending_notifications(limit):
        adesso = utc_now_str()
        try:
            _deliver(notifica, posta, telegram)
        except (smtplib.SMTPException, OSError, ssl.SSLError, ChannelError,
                FileNotFoundError) as errore:
            fallite += 1
            tentativi = int(notifica["attempts"]) + 1
            stato = FAILED if tentativi >= MAX_ATTEMPTS else PENDING
            execute("UPDATE notifications SET attempts = ?, status = ?, last_error = ?,"
                    " updated_at = ? WHERE id = ?",
                    (tentativi, stato, str(errore)[:500], adesso, notifica["id"]))
            continue
        inviate += 1
        execute("UPDATE notifications SET status = ?, attempts = attempts + 1,"
                " sent_at = ?, last_error = NULL, updated_at = ? WHERE id = ?",
                (SENT, adesso, adesso, notifica["id"]))
    return {"sent": inviate, "failed": fallite, "skipped": 0, "reason": ""}


# --------------------------------------------------------------------------- #
# Thread di spedizione
# --------------------------------------------------------------------------- #
_dispatcher: threading.Thread | None = None
_stop = threading.Event()


def start_dispatcher(app) -> None:
    """Avvia il thread che svuota la coda, se non e' gia' avviato.

    Il thread e' un demone: non trattiene l'arresto del processo. Ogni giro apre il
    proprio contesto applicativo, perche' fuori da una richiesta non ce n'e' uno.
    """
    global _dispatcher
    if _dispatcher is not None and _dispatcher.is_alive():
        return

    def giro():
        while not _stop.wait(DISPATCH_INTERVAL_SECONDS):
            try:
                with app.app_context():
                    dispatch_pending()
            except Exception as errore:  # nessun errore deve fermare il thread
                app.logger.warning("Spedizione delle notifiche non riuscita: %s", errore)

    _dispatcher = threading.Thread(target=giro, name="snap-notifiche", daemon=True)
    _dispatcher.start()
    app.logger.info("Spedizione delle notifiche avviata (ogni %d s)",
                    DISPATCH_INTERVAL_SECONDS)


def stop_dispatcher() -> None:
    _stop.set()


# --------------------------------------------------------------------------- #
# Testi delle notifiche
# --------------------------------------------------------------------------- #
# Genere della fascia per ciascun momento del workflow: un incidente aperto e un
# incidente rientrato non devono avere lo stesso colore, altrimenti la fascia non
# aggiunge niente.
GENERE_MOMENTO = {
    "incident.opened": "critico",
    "incident.escalated": "critico",
    "incident.recovered": "attenzione",
    "incident.acknowledged": "informativo",
    "incident.resolved": "sereno",
    "rule.match": "regola",
    "user.created": "credenziali",
    "acn.deadline.approaching": "acn",
    "acn.deadline.passed": "acn",
    "report.daily": "resoconto",
}


def incident_html(event: str, incident: dict, detail: str = "",
                  console_url: str = "") -> str:
    """La forma HTML della notifica di un incidente.

    Gli stessi fatti del testo, nella forma che si legge su un telefono: la fascia dice
    subito di che momento si tratta, la tabella dice su cosa, il pulsante porta dove si
    agisce.
    """
    from . import mail_layout as m

    etichetta = NOTIFY_EVENTS.get(event, event)
    nome = incident.get("check_name") or "controllo"
    bersaglio = incident.get("address") or "-"
    genere = GENERE_MOMENTO.get(event, "informativo")

    blocchi = [
        m.fatti([
            ("Controllo", nome),
            ("Bersaglio", bersaglio),
            ("Incidente", "#%s" % (incident.get("id") or "-")),
            ("Gravita'", incident.get("severity") or "-"),
            ("Aperto il", "%s UTC" % (incident.get("opened_at") or "-")),
            ("Fallimenti consecutivi", incident.get("failure_count") or "-"),
            ("Preso in carico", incident.get("acknowledged_at") or "non ancora"),
            ("Risolto il", incident.get("resolved_at") or "ancora aperto"),
        ]),
    ]
    if detail:
        blocchi.append(m.titolo_sezione("Dettaglio della verifica"))
        blocchi.append(m.paragrafo(detail))

    if event == "incident.escalated":
        blocchi.append(m.avviso(
            "E' stato attivato un operatore: da questo momento l'incidente NON si"
            " chiude piu' da se'. Va preso in carico e risolto dalla console, anche se"
            " il controllo torna a rispondere correttamente.", "critico"))
    elif event == "incident.recovered":
        blocchi.append(m.avviso(
            "Il controllo ha ripreso a rispondere, ma l'incidente resta aperto perche'"
            " era stato attivato un operatore: la chiusura e' una decisione di una"
            " persona.", "attenzione"))
    elif event == "incident.resolved":
        blocchi.append(m.avviso(
            "L'incidente e' chiuso. La sua storia -- apertura, presa in carico,"
            " risoluzione -- resta nel registro con gli istanti di ciascun passaggio.",
            "sereno"))

    blocchi.append(m.bottone("Apri l'incidente nella console",
                             "%s/checks/incidents" % console_url.rstrip("/")
                             if console_url else "", genere))

    return m.messaggio(
        titolo=etichetta,
        sottotitolo="%s su %s" % (nome, bersaglio),
        genere=genere,
        preintestazione="%s - %s su %s" % (etichetta, nome, bersaglio),
        blocchi=blocchi,
        quando="%s UTC" % (incident.get("opened_at") or ""),
        perche="Ricevi questo messaggio perche' sei il recapito indicato per questo"
               " controllo o per il tenant.",
        console_url=console_url,
    )


def incident_message(event: str, incident: dict, detail: str = "") -> tuple:
    """(oggetto, corpo) della notifica per un momento del workflow.

    Il corpo dice cosa e' accaduto, su cosa, e cosa si aspetta da chi legge: una
    notifica che non dice cosa fare costringe ad aprire la console per scoprirlo.
    """
    etichetta = NOTIFY_EVENTS.get(event, event)
    nome = incident.get("check_name") or "controllo"
    bersaglio = incident.get("address") or "-"
    oggetto = "[snap] %s - %s su %s" % (etichetta, nome, bersaglio)

    righe = [
        "%s." % etichetta,
        "",
        "Controllo:   %s" % nome,
        "Bersaglio:   %s" % bersaglio,
        "Incidente:   %s" % incident.get("id"),
        "Gravita':    %s" % (incident.get("severity") or "-"),
        "Aperto il:   %s UTC" % (incident.get("opened_at") or "-"),
        "Fallimenti:  %s consecutivi" % (incident.get("failure_count") or "-"),
    ]
    if detail:
        righe += ["", "Dettaglio:   %s" % detail]

    if event == "incident.escalated":
        righe += [
            "",
            "E' stato attivato un operatore: da questo momento l'incidente NON si",
            "chiude piu' da se'. Va preso in carico e risolto dalla console, anche se",
            "il controllo torna a rispondere correttamente.",
        ]
    elif event == "incident.recovered":
        righe += [
            "",
            "Il controllo ha ripreso a rispondere, ma l'incidente resta aperto perche'",
            "era stato attivato un operatore: serve una verifica prima di chiuderlo.",
        ]
    elif event == "incident.opened":
        righe += [
            "",
            "Il workflow e' automatico: se il controllo torna a posto prima della soglia",
            "di attivazione, l'incidente si chiude da se' e non serve alcun intervento.",
        ]
    elif event == "incident.resolved":
        righe += ["", "Nessun intervento richiesto.",
                  "Motivazione:  %s" % (incident.get("resolution") or "-")]
    elif event == "incident.acknowledged":
        righe += ["", "L'incidente e' stato preso in carico e attende la risoluzione."]

    indirizzo = _setting("public_url").strip()
    if indirizzo:
        righe += ["", "Console: %s/checks/incidents/%s" % (indirizzo.rstrip("/"),
                                                           incident.get("id"))]
    righe += ["", "-- ", "snap - notifica automatica del workflow dei controlli"]
    return oggetto, "\n".join(righe)


# --------------------------------------------------------------------------- #
# Credenziali di un utente appena creato
# --------------------------------------------------------------------------- #
def _credenziali_html(indirizzo: str, password: str, saluto: str, ruolo: str,
                      dove: str) -> str:
    """Il messaggio delle credenziali provvisorie, nella forma condivisa.

    La password sta in un riquadro da cui si copia: una password in mezzo a un
    paragrafo si seleziona male, e chi la seleziona male la incolla con uno spazio.
    """
    from . import mail_layout as m

    return m.messaggio(
        titolo="Accesso a snap",
        sottotitolo="Credenziali provvisorie: al primo accesso viene chiesto di"
                    " cambiarle",
        genere="credenziali",
        preintestazione="Le credenziali provvisorie per accedere alla console snap",
        blocchi=[
            m.paragrafo(saluto),
            m.paragrafo("e' stato creato un accesso a snap a suo nome."),
            m.fatti([
                ("Indirizzo della console", dove),
                ("Utenza", indirizzo),
                ("Ruolo", ruolo or "-"),
            ]),
            m.titolo_sezione("Password provvisoria"),
            m.codice(password),
            m.avviso("Al primo accesso viene chiesto di cambiarla. Se non ha richiesto"
                     " questo accesso, avvisi l'amministratore: la credenziale va"
                     " sostituita.", "credenziali"),
            m.bottone("Apri la console", dove if dove.startswith("http") else "",
                      "credenziali"),
            m.paragrafo("Questo messaggio viene inviato una volta sola, alla creazione"
                        " dell'utenza: snap non invia password per posta in nessun"
                        " altro caso. E' cio' che permette di riconoscere un messaggio"
                        " falso."),
        ],
        perche="Ricevi questo messaggio perche' e' stata creata un'utenza con questo"
               " indirizzo.",
        console_url=dove,
    )


def invia_credenziali(email: str, password: str, nome: str = "", ruolo: str = "",
                      tenant_id: int = None, console_url: str = "") -> dict:
    """Spedisce la password provvisoria a chi dovra' usarla.

    Restituisce l'esito -- `{"inviata": bool, "motivo": str}` -- e NON solleva: chi
    crea l'utente deve poter vedere la password a schermo quando la posta non parte,
    altrimenti resterebbe un utente che nessuno puo' usare.

    La password viaggia nel corpo del messaggio. E' un compromesso dichiarato: la
    posta interna e' cifrata in transito (TLS obbligatorio, vedi `_connect`) ma non
    a riposo, e la credenziale e' **provvisoria con obbligo di cambio** al primo
    accesso -- il che limita la finestra di esposizione a quel primo accesso.
    """
    config = smtp_config()
    if not config.get("enabled"):
        return {"inviata": False, "motivo": "posta non configurata"}

    indirizzo = (email or "").strip()
    if not indirizzo:
        return {"inviata": False, "motivo": "indirizzo mancante"}

    saluto = ("Buongiorno %s," % nome.strip()) if nome and nome.strip() else "Buongiorno,"
    dove = console_url.strip() or "(indirizzo della console: chiedere all'amministratore)"
    corpo = "\n".join([
        saluto,
        "",
        "e' stato creato un accesso a snap a suo nome.",
        "",
        "  Indirizzo della console : %s" % dove,
        "  Utenza                  : %s" % indirizzo,
        "  Password provvisoria    : %s" % password,
        "  Ruolo                   : %s" % (ruolo or "-"),
        "",
        "La password e' provvisoria: al primo accesso viene chiesto di cambiarla.",
        "Se non ha richiesto questo accesso, avvisi l'amministratore: la credenziale",
        "va sostituita.",
        "",
        "Questo messaggio e' stato inviato una volta sola, alla creazione dell'utenza.",
        "snap non invia password per posta in nessun altro caso.",
    ])

    from .audit import log_event

    html = _credenziali_html(indirizzo, password, saluto, ruolo, dove)
    try:
        send_now(config, indirizzo, "snap - credenziali di accesso provvisorie", corpo,
                 body_html=html)
    except Exception as errore:  # noqa: BLE001 - l'esito torna al chiamante
        current_app.logger.warning("Credenziali non spedite a %s: %s",
                                   indirizzo, type(errore).__name__)
        # Il registro dice CHE COSA non e' partito, non la password: un segreto nel
        # registro degli eventi resta la' per tutta la conservazione.
        log_event("user.credentials.failed",
                  "Credenziali provvisorie non spedite a %s (%s)"
                  % (indirizzo, type(errore).__name__),
                  tenant_id=tenant_id, severity="warning", entity="user")
        return {"inviata": False, "motivo": type(errore).__name__}

    log_event("user.credentials.sent",
              "Credenziali provvisorie spedite a %s" % indirizzo,
              tenant_id=tenant_id, severity="info", entity="user")
    return {"inviata": True, "motivo": ""}
