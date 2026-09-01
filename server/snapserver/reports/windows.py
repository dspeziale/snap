"""
snap server - Finestre temporali dei report, nel fuso del tenant.

Perche' un modulo per una sottrazione di date: "ieri" per chi lavora a Roma non e'
"ieri" in UTC, e le due letture differiscono di due ore d'estate -- due ore che
contengono i turni di notte. Tutti i timestamp sono conservati in UTC (vedi db.py):
la finestra si calcola sui confini locali e si traduce in UTC per interrogare.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from datetime import date, datetime, time, timedelta

from ..db import get_zone, utc_str

# Massimo numero di giorni di una finestra: oltre, le interrogazioni per il resoconto
# smettono di essere sostenibili e il documento cambia natura (diventa un report
# periodico, non un resoconto).
MAX_WINDOW_DAYS = 92


class WindowError(ValueError):
    """Finestra temporale non ammissibile."""


def zone_of(tenant) -> "ZoneInfo":  # noqa: F821 - tipo restituito da get_zone
    """Fuso del tenant; UTC se il tenant non lo dichiara o lo dichiara sbagliato."""
    nome = None
    if tenant is not None:
        try:
            nome = tenant["timezone"]
        except (KeyError, IndexError, TypeError):
            nome = tenant.get("timezone") if hasattr(tenant, "get") else None
    return get_zone(nome)


def local_now(zona) -> datetime:
    """Adesso, nel fuso indicato."""
    return datetime.now(zona)


def today_local(zona) -> date:
    return local_now(zona).date()


def yesterday_local(zona) -> date:
    return today_local(zona) - timedelta(days=1)


def day_bounds(zona, giorno: date) -> tuple:
    """Confini UTC dell'intervallo locale `[00:00, 24:00)` del giorno indicato.

    Intervallo chiuso a sinistra e aperto a destra: un esito registrato a mezzanotte
    esatta appartiene al giorno che comincia, non a quello che finisce, e non deve
    comparire in due resoconti.
    """
    inizio = datetime.combine(giorno, time(0, 0), tzinfo=zona)
    fine = datetime.combine(giorno + timedelta(days=1), time(0, 0), tzinfo=zona)
    return utc_str(inizio), utc_str(fine)


def days_bounds(zona, giorni: int, fino_a: date = None) -> tuple:
    """Confini UTC degli ultimi `giorni` giorni locali, compreso `fino_a`."""
    if giorni < 1 or giorni > MAX_WINDOW_DAYS:
        raise WindowError("La finestra deve essere fra 1 e %d giorni." % MAX_WINDOW_DAYS)
    ultimo = fino_a or today_local(zona)
    primo = ultimo - timedelta(days=giorni - 1)
    inizio, _ = day_bounds(zona, primo)
    _, fine = day_bounds(zona, ultimo)
    return inizio, fine


def local_day_of(momento_utc: str, zona) -> date | None:
    """Giorno locale a cui appartiene un timestamp conservato in UTC."""
    from ..db import parse_utc

    quando = parse_utc(momento_utc)
    if quando is None:
        return None
    return quando.astimezone(zona).date()


def local_hhmm(momento_utc: str, zona) -> str:
    """Ora e minuti locali di un timestamp UTC, per la lettura nel resoconto."""
    from ..db import parse_utc

    quando = parse_utc(momento_utc)
    if quando is None:
        return "--:--"
    return quando.astimezone(zona).strftime("%H:%M")


def parse_day(valore: str, zona) -> date:
    """Interpreta un giorno indicato dall'operatore (`YYYY-MM-DD`).

    Un giorno futuro viene rifiutato: un report su dati non ancora raccolti sarebbe
    vuoto senza che la pagina sappia spiegare perche'.
    """
    testo = (valore or "").strip()
    if not testo:
        return yesterday_local(zona)
    try:
        giorno = datetime.strptime(testo, "%Y-%m-%d").date()
    except ValueError as errore:
        raise WindowError("Il giorno va indicato come AAAA-MM-GG.") from errore
    if giorno > today_local(zona):
        raise WindowError("Il giorno indicato e' nel futuro.")
    return giorno


def describe(giorno: date, zona) -> str:
    """Etichetta leggibile dell'intervallo, con il fuso: serve a RP-03."""
    return "%s 00:00 - 24:00 (%s)" % (giorno.strftime("%d/%m/%Y"), zona.key
                                      if hasattr(zona, "key") else str(zona))


def describe_range(giorno_fine: date, giorni: int, zona) -> str:
    """Etichetta di un intervallo di piu' giorni, con il fuso (RP-03).

    L'intervallo stampato in testa e' cio' che rende il documento una prova: senza, due
    esecuzioni con numeri diversi sembrano un errore del sistema.
    """
    primo = giorno_fine - timedelta(days=giorni - 1)
    return "%s - %s (%d giorni, %s)" % (
        primo.strftime("%d/%m/%Y"), giorno_fine.strftime("%d/%m/%Y"), giorni,
        zona.key if hasattr(zona, "key") else str(zona))


def period_key(kind: str, giorno: date, giorni: int = 1) -> str:
    """Chiave del periodo, con cui si garantisce un solo report per periodo.

    Comprende l'ampiezza: la sintesi mensile del 31/08 e quella trimestrale dello
    stesso giorno sono due documenti diversi, e devono poter convivere.
    """
    if giorni and int(giorni) > 1:
        return "%s:%s:%dg" % (kind, giorno.isoformat(), int(giorni))
    return "%s:%s" % (kind, giorno.isoformat())
