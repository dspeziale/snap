"""
snap probe - Normalizzazione oraria dell'interfaccia locale.

La sonda persiste ogni istante in UTC (formato 'YYYY-MM-DD HH:MM:SS') e lo
converte in presentazione nel fuso orario del tenant, ricevuto dal server in
fase di registrazione e riallineato a ogni contatto. Se la sonda non e' ancora
registrata il fuso non e' noto: si dichiara e si utilizza UTC.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

UTC_FORMAT = "%Y-%m-%d %H:%M:%S"


def parse_utc(value) -> datetime | None:
    """Interpreta un istante persistito; None se assente o illeggibile."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not value:
        return None

    text = str(value).strip().replace("T", " ")
    if text.endswith("Z"):
        text = text[:-1]
    text = text.split(".")[0]
    for fmt in (UTC_FORMAT, "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def get_zone(timezone_name: str | None) -> ZoneInfo:
    """Fuso del tenant, con ricaduta su UTC se il nome non e' utilizzabile."""
    try:
        return ZoneInfo(timezone_name or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def to_zone(value, timezone_name: str | None) -> datetime | None:
    moment = parse_utc(value)
    if moment is None:
        return None
    return moment.astimezone(get_zone(timezone_name))


def register_template_filters(app, store) -> None:
    """Registra i filtri di presentazione legati al fuso del tenant.

    Il fuso e' letto dall'archivio a ogni chiamata: cambia quando il server
    aggiorna la configurazione della sonda, senza necessita' di riavvio.
    """

    def tenant_timezone() -> str:
        return store.get_setting("tenant_timezone") or "UTC"

    def filter_datetime(value, fmt: str = "%d/%m/%Y %H:%M") -> str:
        moment = to_zone(value, tenant_timezone())
        return moment.strftime(fmt) if moment else "-"

    def filter_datetime_tz(value) -> str:
        """Come il precedente, con l'indicazione esplicita del fuso."""
        moment = to_zone(value, tenant_timezone())
        if moment is None:
            return "-"
        return "%s (%s)" % (moment.strftime("%d/%m/%Y %H:%M"), moment.tzname() or "UTC")

    def filter_time(value) -> str:
        moment = to_zone(value, tenant_timezone())
        return moment.strftime("%H:%M:%S") if moment else "-"

    def filter_relative(value) -> str:
        """Distanza dall'istante corrente; indipendente dal fuso scelto."""
        moment = parse_utc(value)
        if moment is None:
            return "mai"
        delta = int((datetime.now(timezone.utc) - moment).total_seconds())
        if delta < 0:
            return "in programma"
        if delta < 60:
            return "%d s fa" % delta
        if delta < 3600:
            return "%d min fa" % (delta // 60)
        if delta < 86400:
            return "%d h fa" % (delta // 3600)
        return "%d gg fa" % (delta // 86400)

    def filter_bytes(value) -> str:
        """Dimensione nell'unita' che la rende leggibile.

        "38040576 byte" costringe a contare le cifre; "36,3 MB" no.
        """
        try:
            quantita = float(value)
        except (TypeError, ValueError):
            return "-"
        if quantita < 0:
            return "-"
        for unita in ("byte", "kB", "MB", "GB"):
            if quantita < 1024 or unita == "GB":
                if unita == "byte":
                    return "%d byte" % int(quantita)
                testo = ("%.2f" % quantita).rstrip("0").rstrip(".")
                return "%s %s" % (testo.replace(".", ","), unita)
            quantita /= 1024.0
        return "-"

    def filter_intero(value) -> str:
        """Intero con il punto delle migliaia, come si scrive in italiano."""
        try:
            numero = int(value)
        except (TypeError, ValueError):
            return "-"
        return "{:,}".format(numero).replace(",", ".")

    def filter_durata(value) -> str:
        """Una quantita' di secondi, in forma leggibile.

        UN NEGATIVO NON DIVENTA ZERO: "scaduta da 6 h" e "scade adesso" non sono la
        stessa notizia, e appiattire il primo sul secondo nasconde proprio il
        ritardo che chi guarda la pagina sta cercando. `None` resta `None`: significa
        "mai eseguita", che non e' una durata.
        """
        if value is None:
            return "-"
        try:
            secondi = float(value)
        except (TypeError, ValueError):
            return "-"
        prefisso = "da " if secondi < 0 else ""
        secondi = abs(secondi)
        if secondi < 60:
            return "%s%d s" % (prefisso, int(secondi))
        if secondi < 3600:
            return "%s%d min" % (prefisso, int(secondi // 60))
        if secondi < 86400:
            ore, resto = divmod(int(secondi), 3600)
            return "%s%d h %02d min" % (prefisso, ore, resto // 60)
        giorni, resto = divmod(int(secondi), 86400)
        return "%s%d g %02d h" % (prefisso, giorni, resto // 3600)

    app.jinja_env.filters["bytes"] = filter_bytes
    app.jinja_env.filters["intero"] = filter_intero
    app.jinja_env.filters["durata"] = filter_durata
    app.jinja_env.filters["dt"] = filter_datetime
    app.jinja_env.filters["dtz"] = filter_datetime_tz
    app.jinja_env.filters["hms"] = filter_time
    app.jinja_env.filters["ago"] = filter_relative

    @app.context_processor
    def _inject_timezone() -> dict:
        """Espone il fuso in uso e la sua provenienza all'interfaccia."""
        name = tenant_timezone()
        reference = to_zone(datetime.now(timezone.utc), name)
        return {
            "display_timezone": name,
            "display_timezone_label": reference.tzname() if reference else "UTC",
            "display_timezone_known": bool(store.get_setting("tenant_timezone")),
        }
