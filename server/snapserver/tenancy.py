"""
snap server - Contesto multi-tenant e normalizzazione oraria.

Regole di isolamento:
  * ogni richiesta autenticata risolve un tenant corrente (g.tenant);
  * un utente non superadmin puo' operare esclusivamente sul proprio tenant:
    ogni tentativo di forzare un altro tenant viene ignorato e tracciato;
  * tutte le query di dominio passano il tenant corrente come primo filtro;
  * ogni istante mostrato all'utente e' convertito nel fuso del tenant.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from flask import abort, current_app, g, session

from .db import query, to_tenant_time
from .security import is_superadmin

DEFAULT_TIMEZONE = "Europe/Rome"


def _remember_tenant(tenant_id: int) -> None:
    """Annota il tenant in sessione solo se il valore cambia.

    Ogni scrittura marca la sessione come modificata e provoca l'invio di un
    nuovo cookie: riscriverla a ogni richiesta moltiplica senza motivo le
    occasioni in cui una risposta tardiva sovrascrive lo stato piu' recente.
    """
    if session.get("tenant_id") != tenant_id:
        session["tenant_id"] = tenant_id


def load_tenant_context() -> None:
    """Popola g.tenant in base alla sessione e al ruolo (hook before_request)."""
    g.tenant = None
    g.available_tenants = []
    user = getattr(g, "user", None)
    if user is None:
        return

    if is_superadmin():
        g.available_tenants = query(
            "SELECT * FROM tenants ORDER BY name COLLATE NOCASE"
        )
        tenant_id = session.get("tenant_id")
        tenant = None
        if tenant_id is not None:
            tenant = query("SELECT * FROM tenants WHERE id = ?", (tenant_id,), one=True)
        if tenant is None and g.available_tenants:
            tenant = g.available_tenants[0]
            _remember_tenant(int(tenant["id"]))
        g.tenant = tenant
        return

    # Utente di tenant: il contesto e' immutabile e coincide con la sua anagrafica.
    tenant = query(
        "SELECT * FROM tenants WHERE id = ? AND is_active = 1",
        (user["tenant_id"],),
        one=True,
    )
    if tenant is None:
        current_app.logger.warning(
            "Utente %s associato a un tenant inesistente o disattivato", user["email"]
        )
        return
    g.tenant = tenant
    g.available_tenants = [tenant]
    _remember_tenant(int(tenant["id"]))


def switch_tenant(tenant_id: int) -> bool:
    """Cambia il tenant corrente: consentito solo al superadmin."""
    if not is_superadmin():
        current_app.logger.warning("Tentativo di cambio tenant non autorizzato")
        return False
    tenant = query("SELECT * FROM tenants WHERE id = ?", (tenant_id,), one=True)
    if tenant is None:
        return False
    session["tenant_id"] = int(tenant["id"])
    g.tenant = tenant
    return True


def current_tenant_id() -> int:
    """Id del tenant corrente; 400 se il contesto non e' determinato."""
    tenant = getattr(g, "tenant", None)
    if tenant is None:
        abort(400, "Contesto tenant non determinato: selezionare un tenant.")
    return int(tenant["id"])


def current_timezone() -> str:
    tenant = getattr(g, "tenant", None)
    if tenant is None:
        return DEFAULT_TIMEZONE
    return tenant["timezone"] or DEFAULT_TIMEZONE


def require_tenant_access(tenant_id: int) -> None:
    """Verifica che il tenant richiesto sia accessibile all'utente corrente."""
    if is_superadmin():
        return
    user = getattr(g, "user", None)
    if user is None or user["tenant_id"] is None or int(user["tenant_id"]) != int(tenant_id):
        current_app.logger.warning(
            "Violazione di isolamento bloccata: utente %s verso tenant %s",
            user["email"] if user else "anonimo",
            tenant_id,
        )
        abort(403)


# --------------------------------------------------------------------------- #
# Filtri di presentazione (registrati in app.jinja_env)
# --------------------------------------------------------------------------- #
def fmt_datetime(value, fmt: str = "%d/%m/%Y %H:%M") -> str:
    """Formatta un istante UTC nel fuso del tenant corrente."""
    moment = to_tenant_time(value, current_timezone())
    return moment.strftime(fmt) if moment else "-"


def fmt_grafico(value) -> str:
    """Istante nel fuso del tenant nella forma che il componente dei grafici legge.

    I grafici ricevono l'istante in forma ISO e lo formattano da se': in questo modo
    la stessa serie puo' essere disegnata per ore o per giorni, e l'ascissa puo'
    essere un calendario invece di una fila di etichette gia' composte. La
    conversione al fuso resta qui, dov'e' per ogni altra data mostrata: un andamento
    letto con l'ora sbagliata porta a conclusioni sbagliate.
    """
    return fmt_datetime(value, "%Y-%m-%d %H:%M:%S")


def fmt_date(value) -> str:
    return fmt_datetime(value, "%d/%m/%Y")


def fmt_datetime_tz(value) -> str:
    """Come fmt_datetime ma con l'indicazione esplicita del fuso orario."""
    moment = to_tenant_time(value, current_timezone())
    if not moment:
        return "-"
    return "%s (%s)" % (moment.strftime("%d/%m/%Y %H:%M"), moment.tzname() or "UTC")


def fmt_relative(value) -> str:
    """Distanza dall'istante corrente in forma leggibile (es. '3 min fa')."""
    from .db import parse_utc, utc_now

    moment = parse_utc(value)
    if moment is None:
        return "mai"
    delta = int((utc_now() - moment).total_seconds())
    if delta < 0:
        return "in programma"
    if delta < 60:
        return "%d s fa" % delta
    if delta < 3600:
        return "%d min fa" % (delta // 60)
    if delta < 86400:
        return "%d h fa" % (delta // 3600)
    return "%d gg fa" % (delta // 86400)


# Scala delle unita' binarie: un kB qui e' 1024 byte, come lo conta il sistema
# operativo su cui gira il prodotto. Oltre il terabyte non si sale: un lotto di
# conferimento di quella dimensione sarebbe un difetto, non un dato.
UNITA_BYTE = ("B", "kB", "MB", "GB", "TB")


def fmt_bytes(valore) -> str:
    """Dimensione nell'unita' che la rende leggibile, con al massimo due decimali.

    "1289,4 kB" costringe a una divisione a mente; "1,26 MB" no. I byte non prendono
    decimali -- mezzo byte non esiste -- e gli zeri finali si tolgono, perche'
    "3 MB" e "3,00 MB" dicono la stessa cosa e il primo si legge prima.
    """
    try:
        quantita = float(valore)
    except (TypeError, ValueError):
        return "-"
    if quantita < 0:
        return "-"

    indice = 0
    while quantita >= 1024 and indice < len(UNITA_BYTE) - 1:
        quantita /= 1024.0
        indice += 1

    if indice == 0:
        return "%d B" % int(quantita)
    # Due decimali sotto le dieci unita', uno sotto le cento, nessuno oltre: e' la
    # precisione che serve a leggere, non quella che l'archivio conosce.
    decimali = 2 if quantita < 10 else (1 if quantita < 100 else 0)
    testo = "%.*f" % (decimali, quantita)
    if "." in testo:
        # Solo dopo la virgola: senza questa guardia "100" diventava "1", perche' lo
        # zero finale di un intero e' una cifra e non un decimale superfluo.
        testo = testo.rstrip("0").rstrip(".")
    return "%s %s" % (testo.replace(".", ","), UNITA_BYTE[indice])


def fmt_intero(valore) -> str:
    """Numero intero con il punto delle migliaia, come si scrive in italiano.

    "2446" e "2.446" contengono lo stesso dato, ma il secondo si legge senza
    contare le cifre -- ed e' l'unica ragione per cui i separatori esistono.
    """
    try:
        numero = int(valore)
    except (TypeError, ValueError):
        return "-"
    return "{:,}".format(numero).replace(",", ".")


def fmt_giorno_semplice(value) -> str:
    """Una DATA di calendario, formattata e non convertita.

    Le date del catalogo delle vulnerabilita' -- inserimento nel KEV, scadenza per la
    correzione -- non sono istanti: non hanno un fuso, e convertirle puo' spostarle di
    un giorno. Qui si formatta soltanto, per non mostrare un ISO in mezzo a date
    italiane.
    """
    from datetime import datetime

    if not value:
        return "-"
    testo = str(value).strip()
    for forma in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(testo[:len(forma) + 2].strip(), forma).strftime(
                "%d/%m/%Y")
        except ValueError:
            continue
    # Non e' una data riconoscibile: si restituisce il testo, non un suo pezzo.
    return testo[:20]


def fmt_datetime_sec(value) -> str:
    """Istante nel fuso del tenant CON i secondi. Serve dove il secondo conta -- per
    esempio gli eventi del syslog, che possono arrivare a raffica nello stesso minuto."""
    return fmt_datetime(value, "%d/%m/%Y %H:%M:%S")


def register_template_filters(app) -> None:
    app.jinja_env.filters["dt"] = fmt_datetime
    app.jinja_env.filters["dts"] = fmt_datetime_sec
    app.jinja_env.filters["d"] = fmt_date
    app.jinja_env.filters["dtz"] = fmt_datetime_tz
    app.jinja_env.filters["ago"] = fmt_relative
    # Data di calendario: si formatta, non si converte (vedi fmt_giorno_semplice).
    app.jinja_env.filters["giorno"] = fmt_giorno_semplice
    app.jinja_env.filters["bytes"] = fmt_bytes
    app.jinja_env.filters["intero"] = fmt_intero

    def da_json(valore):
        """Legge un campo JSON conservato. Un JSON rotto non deve rompere la pagina."""
        import json

        if not valore:
            return []
        try:
            return json.loads(valore)
        except (TypeError, ValueError):
            return []

    app.jinja_env.filters["from_json"] = da_json
