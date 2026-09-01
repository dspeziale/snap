"""
snap server - Resoconto quotidiano: pianificatore autonomo e spedizione.

Il resoconto e' prodotto e spedito dall'APPLICAZIONE. Il pianificatore vive nel
processo del server come il thread delle notifiche: si sveglia ogni minuto, guarda
l'ora locale di ciascun tenant e, quando e' il momento, compone il resoconto del
giorno precedente e lo accoda. Non serve che qualcuno sia collegato, e non c'e' nulla
di manuale nel percorso.

Perche' il risveglio e' al minuto e non alle 07:00 esatte: un processo che dorme fino
a un istante preciso salta l'appuntamento se in quell'istante era in riavvio. Il
controllo periodico con marcatore sul database e' l'unica forma che sopravvive ai
riavvii, e la garanzia di unicita' e' l'indice sul periodo (RP-08, SR-105).

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import threading
from datetime import date, datetime, timedelta
from pathlib import Path

from ..audit import log_event
from ..channels import CHANNEL_EMAIL, CHANNEL_TELEGRAM, CHANNELS
from ..db import query, utc_now_str
from ..notifications import queue_notification
from . import KIND_DAILY, KIND_NOC
from . import render_mail, render_pdf, storage
from . import dataset as dati_mod
from .windows import (
    day_bounds,
    describe,
    parse_day,
    period_key,
    yesterday_local,
    zone_of,
)

EVENT = "report.daily"
# Cadenza del pianificatore. Un minuto e' la risoluzione dell'ora configurata: non
# serve piu' fine, e piu' grossolano rischierebbe di saltare la finestra.
TICK_SECONDS = 60
# Finestra di recupero: se il server era spento all'ora prevista, il resoconto viene
# comunque spedito quando torna, purche' entro queste ore. Oltre non si spedisce: un
# resoconto di ieri che arriva a sera si legge come se fosse fresco, e nessuno guarda
# l'intervallo stampato in fondo. Il periodo viene registrato come saltato, con il
# motivo, cosi' la mancanza e' visibile invece di essere silenziosa.
DEFAULT_TIME = "07:00"
DEFAULT_CATCHUP_HOURS = 6
DEFAULT_TREND_DAYS = 7

SETTING_KEYS = {
    "report_daily_enabled": "1",
    "report_daily_time": DEFAULT_TIME,
    "report_daily_recipients": "",
    "report_daily_channels": CHANNEL_EMAIL,
    "report_daily_attach": "0",
    "report_daily_trend_days": str(DEFAULT_TREND_DAYS),
    "report_daily_catchup_hours": str(DEFAULT_CATCHUP_HOURS),
}


def _setting(key: str, default: str = "") -> str:
    riga = query("SELECT value FROM system_settings WHERE key = ?", (key,), one=True)
    if riga is None or riga["value"] is None:
        return default
    return str(riga["value"])


def settings() -> dict:
    """Impostazioni del resoconto, con i valori predefiniti se non configurato."""
    ora = (_setting("report_daily_time", DEFAULT_TIME) or DEFAULT_TIME).strip()
    if not _valid_time(ora):
        ora = DEFAULT_TIME
    giorni = _setting("report_daily_trend_days", str(DEFAULT_TREND_DAYS))
    canali = [c.strip() for c in
              (_setting("report_daily_channels", CHANNEL_EMAIL) or "").split(",")
              if c.strip() in CHANNELS]
    recupero = _setting("report_daily_catchup_hours", str(DEFAULT_CATCHUP_HOURS))
    return {
        "enabled": _setting("report_daily_enabled", "1") != "0",
        "time": ora,
        "catchup_hours": (int(recupero) if str(recupero).isdigit() and 0 < int(recupero) <= 24
                          else DEFAULT_CATCHUP_HOURS),
        "recipients": [r.strip() for r in
                       (_setting("report_daily_recipients") or "").replace(";", ",")
                       .split(",") if r.strip()],
        "channels": canali or [CHANNEL_EMAIL],
        "attach": _setting("report_daily_attach", "0") == "1",
        "trend_days": int(giorni) if str(giorni).isdigit() and int(giorni) > 0
                      else DEFAULT_TREND_DAYS,
    }


def _valid_time(valore: str) -> bool:
    pezzi = (valore or "").split(":")
    if len(pezzi) != 2 or not all(p.isdigit() for p in pezzi):
        return False
    ore, minuti = int(pezzi[0]), int(pezzi[1])
    return 0 <= ore <= 23 and 0 <= minuti <= 59


def recipients_for(tenant, impostazioni: dict, channel: str) -> list:
    """Destinatari del canale indicato.

    Per la posta: l'elenco configurato, in mancanza l'email di riferimento del tenant
    -- lo stesso criterio del workflow degli incidenti, cosi' non ci sono due regole
    da ricordare. Per Telegram: la chat configurata nelle impostazioni del bot.
    """
    if channel == CHANNEL_TELEGRAM:
        from ..channels import telegram_config

        chat = telegram_config()["chat_id"]
        return [chat] if chat else []
    if impostazioni["recipients"]:
        return list(impostazioni["recipients"])
    contatto = None
    try:
        contatto = tenant["contact_email"]
    except (KeyError, IndexError, TypeError):
        contatto = None
    return [contatto] if contatto else []


def active_tenants() -> list:
    return [dict(r) for r in query(
        "SELECT id, code, name, timezone, contact_email FROM tenants"
        " WHERE is_active = 1 ORDER BY id")]


def already_sent(tenant_id: int, giorno: date) -> bool:
    return storage.existing(tenant_id, KIND_DAILY, period_key(KIND_DAILY, giorno)) is not None


def window_state(tenant: dict, impostazioni: dict = None, adesso=None) -> dict:
    """Stato della finestra di spedizione: se e' il momento, se e' passata, per quale
    giorno.

    Tre esiti distinti, perche' richiedono tre comportamenti diversi: non ancora
    (aspettare), dentro la finestra (spedire), finestra passata (registrare il salto,
    senza spedire un resoconto arretrato che si leggerebbe come fresco).
    """
    impostazioni = impostazioni or settings()
    zona = zone_of(tenant)
    locale = adesso or datetime.now(zona)
    ore, minuti = (int(p) for p in impostazioni["time"].split(":"))
    previsto = locale.replace(hour=ore, minute=minuti, second=0, microsecond=0)
    limite = previsto + timedelta(hours=impostazioni["catchup_hours"])
    # Il resoconto delle 07:00 di oggi copre IERI: e' il giorno di cui si conoscono
    # tutti gli eventi.
    giorno = locale.date() - timedelta(days=1)
    return {
        "giorno": giorno,
        "gia_spedito": already_sent(int(tenant["id"]), giorno),
        "prima": locale < previsto,
        "scaduta": locale > limite,
        "previsto": previsto,
        "limite": limite,
    }


def due(tenant: dict, impostazioni: dict = None, adesso=None) -> bool:
    """Vero se al tenant va spedito adesso il resoconto di ieri."""
    impostazioni = impostazioni or settings()
    if not impostazioni["enabled"]:
        return False
    stato = window_state(tenant, impostazioni, adesso)
    if stato["prima"] or stato["scaduta"] or stato["gia_spedito"]:
        return False
    return True


def build(tenant: dict, giorno: date, impostazioni: dict = None) -> dict:
    """Dati e testi del resoconto, senza spedire nulla: serve anche all'anteprima."""
    impostazioni = impostazioni or settings()
    zona = zone_of(tenant)
    dati = dati_mod.daily(tenant, giorno, zona, impostazioni["trend_days"])
    console = _setting("public_url", "")
    return {
        "dati": dati,
        "oggetto": render_mail.subject(dati),
        "testo": render_mail.text_body(dati, console),
        "html": render_mail.html_body(dati, console),
        "intervallo": describe(giorno, zona),
    }


def send_for(tenant: dict, giorno: date = None, requested_by: int = None,
             force: bool = False, impostazioni: dict = None) -> dict:
    """Compone e accoda il resoconto di un giorno. Restituisce l'esito.

    `force` serve alla spedizione a richiesta dalla console: senza, un resoconto gia'
    spedito non si ripete, che e' esattamente cio' che si vuole dal pianificatore.
    """
    impostazioni = impostazioni or settings()
    zona = zone_of(tenant)
    giorno = giorno or yesterday_local(zona)
    tenant_id = int(tenant["id"])
    chiave = period_key(KIND_DAILY, giorno)

    if not force and storage.existing(tenant_id, KIND_DAILY, chiave) is not None:
        return {"inviato": False, "motivo": "resoconto del %s gia' spedito" % giorno}

    composto = build(tenant, giorno, impostazioni)
    dati = composto["dati"]

    allegato = None
    if impostazioni["attach"]:
        # L'allegato e' facoltativo e spento per difetto: un inventario che finisce in
        # una casella esterna e' un problema di riservatezza, non di comodita'.
        allegato = generate_noc(tenant, giorno, dati=dati, requested_by=requested_by)

    notifiche = []
    for canale in impostazioni["channels"]:
        destinatari = recipients_for(tenant, impostazioni, canale)
        identificativo = queue_notification(
            tenant_id, EVENT, destinatari, composto["oggetto"],
            composto["testo"], channel=canale,
            body_html=composto["html"] if canale == CHANNEL_EMAIL else None,
            attachment=allegato)
        if identificativo:
            notifiche.append(identificativo)

    storage.register(
        tenant_id, KIND_DAILY, chiave, dati["inizio_utc"], dati["fine_utc"],
        file_path=allegato, file_bytes=_dimensione(allegato),
        status=storage.STATO_OK if notifiche else storage.STATO_ERRORE,
        detail="" if notifiche else "nessuna notifica accodata: canale non configurato"
                                    " oppure destinatario mancante",
        notification_id=notifiche[0] if notifiche else None,
        requested_by=requested_by)

    log_event("report.daily.sent",
              "Resoconto del %s accodato su %s (%d questioni aperte, %s esiti)"
              % (giorno.strftime("%d/%m/%Y"), ", ".join(impostazioni["channels"]),
                 len(dati["da_risolvere"]), dati["disponibilita"]["esiti"]),
              tenant_id=tenant_id, severity="info", entity="report")
    return {
        "inviato": bool(notifiche),
        "notifiche": notifiche,
        "giorno": giorno,
        "allegato": allegato,
        "oggetto": composto["oggetto"],
        "questioni": len(dati["da_risolvere"]),
    }


def _dimensione(percorso) -> int:
    if not percorso:
        return 0
    file = Path(percorso)
    return file.stat().st_size if file.is_file() else 0


def generate_noc(tenant: dict, giorno: date, dati: dict = None,
                 requested_by: int = None, impostazioni: dict = None) -> str:
    """Genera il report NOC in PDF per un giorno e lo registra."""
    impostazioni = impostazioni or settings()
    zona = zone_of(tenant)
    dati = dati or dati_mod.daily(tenant, giorno, zona, impostazioni["trend_days"])
    percorso = storage.file_for(tenant["code"], KIND_NOC, giorno)
    metodologia = {
        "versione": _setting("app_version", ""),
        "sonde": ", ".join("%s (sforzo %s)" % (s["nome"], s["sforzo"])
                           for s in dati["raccolta"]["sonde"]),
    }
    render_pdf.noc_report(percorso, dati, metodologia)
    storage.register(
        int(tenant["id"]), KIND_NOC, period_key(KIND_NOC, giorno),
        dati["inizio_utc"], dati["fine_utc"], file_path=percorso,
        file_bytes=_dimensione(percorso), requested_by=requested_by)
    log_event("report.noc.generated",
              "Report NOC del %s generato (%s)"
              % (giorno.strftime("%d/%m/%Y"), percorso.name),
              tenant_id=int(tenant["id"]), severity="info", entity="report")
    return str(percorso)


def run_once() -> dict:
    """Un giro del pianificatore. Da chiamare dentro un contesto applicativo."""
    impostazioni = settings()
    esito = {"spediti": 0, "saltati": 0, "errori": 0}
    if not impostazioni["enabled"]:
        esito["motivo"] = "resoconto disattivato"
        return esito

    for tenant in active_tenants():
        try:
            stato = window_state(tenant, impostazioni)
            if stato["scaduta"] and not stato["gia_spedito"]:
                # Finestra perduta: si registra il salto con il motivo, cosi' la
                # mancanza si vede nell'elenco dei report invece di essere silenziosa.
                # Il resoconto resta ottenibile a richiesta.
                storage.register(
                    int(tenant["id"]), KIND_DAILY,
                    period_key(KIND_DAILY, stato["giorno"]),
                    *day_bounds(zone_of(tenant), stato["giorno"]),
                    status=storage.STATO_ERRORE,
                    detail="finestra di spedizione perduta: prevista alle %s, recupero"
                           " fino alle %s"
                           % (stato["previsto"].strftime("%H:%M"),
                              stato["limite"].strftime("%H:%M")))
                esito["saltati"] += 1
                continue
            if not due(tenant, impostazioni):
                esito["saltati"] += 1
                continue
            risultato = send_for(tenant, stato["giorno"], impostazioni=impostazioni)
            esito["spediti" if risultato["inviato"] else "errori"] += 1
        except Exception as errore:  # noqa: BLE001 - un tenant non deve fermare gli altri
            esito["errori"] += 1
            esito.setdefault("dettagli", []).append(
                "%s: %s" % (tenant.get("code"), errore))
    return esito


_thread: threading.Thread | None = None
_stop = threading.Event()


def start_scheduler(app) -> None:
    """Avvia il pianificatore del resoconto, se non e' gia' avviato."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return

    def giro():
        while not _stop.wait(TICK_SECONDS):
            try:
                with app.app_context():
                    esito = run_once()
                    if esito.get("spediti"):
                        app.logger.info("Resoconto quotidiano: %d spediti",
                                        esito["spediti"])
                    if esito.get("errori"):
                        app.logger.warning("Resoconto quotidiano: %d errori (%s)",
                                           esito["errori"],
                                           "; ".join(esito.get("dettagli", [])))
            except Exception as errore:  # nessun errore deve fermare il thread
                app.logger.warning("Pianificatore del resoconto non riuscito: %s",
                                   errore)

    _thread = threading.Thread(target=giro, name="snap-resoconto", daemon=True)
    _thread.start()
    app.logger.info("Pianificatore del resoconto avviato (ogni %d s, ora %s)",
                    TICK_SECONDS, settings_time_safe(app))


def settings_time_safe(app) -> str:
    """Ora configurata, letta senza far fallire l'avvio se il database non c'e'."""
    try:
        with app.app_context():
            return settings()["time"]
    except Exception:  # noqa: BLE001 - l'avvio non deve dipendere da una lettura
        return DEFAULT_TIME


def stop_scheduler() -> None:
    _stop.set()


def parse_requested_day(valore: str, tenant: dict) -> date:
    """Giorno indicato dall'operatore, nel fuso del tenant."""
    return parse_day(valore, zone_of(tenant))
