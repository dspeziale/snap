# -----------------------------------------------------------------
# probe_scan_watch.py — avvisa quando una sonda ha le scansioni bloccate
# Autore: Daniele Speziale
# Data creazione: 2026-09-09
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Sorveglianza delle sonde ferme.

Una sonda con le scansioni bloccate smette di raccogliere in silenzio: la copertura
si ferma senza che nessuno se ne accorga, ed e' il difetto peggiore per uno strumento
il cui compito e' proprio guardare la rete. Quindi un avviso, una volta sola per
episodio, quando una sonda risulta bloccata; la traccia del ripristino resta nel
diario, senza un secondo avviso.

Una sonda e' bloccata quando:
* le scansioni sono **disabilitate dal server** (`scan_enabled = 0`): lo sa il server;
* le scansioni sono **sospese sulla sonda** (pausa locale del tecnico), come riportato
  dall'ultimo heartbeat -- e vale solo se la sonda si e' fatta viva di recente, perche'
  su una sonda offline il dato e' vecchio e l'assenza e' un altro problema.

Il canale e' quello che esiste gia' (posta): un modulo di avviso che si fabbrica un
canale proprio finirebbe per non essere configurato.

remarks: Autore: Daniele Speziale - Data: 2026-09-09
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import threading

from .audit import log_event
from .db import execute, parse_utc, query, utc_now, utc_now_str

TICK_SECONDI = 300

EVENTO_BLOCCATA = "probe.scan.blocked"
EVENTO_RIPRESA = "probe.scan.resumed"

_stop = threading.Event()
_thread = None


def _recente(last_seen_at: str, offline_after: int) -> bool:
    """Vero se la sonda si e' fatta viva entro la soglia di 'non raggiungibile'."""
    istante = parse_utc(last_seen_at) if last_seen_at else None
    if istante is None:
        return False
    return (utc_now() - istante).total_seconds() <= offline_after


def _blocco(riga: dict, offline_after: int) -> tuple:
    """(bloccata, motivo). La disabilitazione dal server vale sempre; la pausa locale
    solo se la sonda e' online, perche' altrimenti il dato dell'heartbeat e' vecchio."""
    if not int(riga.get("scan_enabled") or 0):
        return True, "scansioni disabilitate dal server"
    if _recente(riga.get("last_seen_at"), offline_after) and int(riga.get("scan_paused") or 0):
        return True, "scansioni sospese sulla sonda"
    return False, ""


def _destinatari(tenant_id: int) -> list:
    """Recapito del tenant e amministratori (di tenant e di sistema). Non un elenco a
    parte da tenere aggiornato: un secondo elenco invecchia, e un avviso che non arriva
    e' peggio di un avviso che arriva a qualcuno in piu'."""
    recapiti = set()
    tenant = query("SELECT contact_email FROM tenants WHERE id = ?", (tenant_id,),
                   one=True)
    if tenant is not None and tenant["contact_email"]:
        recapiti.add(tenant["contact_email"].strip())
    for riga in query("SELECT email FROM users WHERE tenant_id = ?"
                      " AND role IN ('tenant_admin', 'superadmin')", (tenant_id,)):
        if riga["email"]:
            recapiti.add(riga["email"].strip())
    return sorted(r for r in recapiti if r)


def _testo(riga: dict, motivo: str) -> tuple:
    nome = riga.get("name") or riga.get("code")
    oggetto = "snap - sonda \"%s\": scansioni bloccate" % nome
    corpo = [
        "Le scansioni della sonda \"%s\" (%s) risultano bloccate." % (nome, riga["code"]),
        "",
        "  Motivo         : %s" % motivo,
        "  Sede           : %s" % (riga.get("site") or "-"),
        "  Ultimo contatto: %s (UTC)" % (riga.get("last_seen_at") or "-"),
        "",
        "Finche' restano bloccate la sonda non raccoglie: la copertura di questa parte",
        "di rete e' ferma. Le scansioni si riattivano dalla console (Sonde) se sono",
        "disabilitate dal server, oppure dall'interfaccia della sonda se sono state",
        "sospese sul posto.",
    ]
    return oggetto, "\n".join(corpo)


def _html(riga: dict, motivo: str) -> str:
    from . import mail_layout as m
    from .notifications import _setting

    nome = riga.get("name") or riga.get("code")
    console = _setting("public_url", "")
    return m.messaggio(
        titolo="Sonda \"%s\": scansioni bloccate" % nome,
        sottotitolo="La raccolta di questa parte di rete e' ferma",
        genere="attenzione",
        preintestazione="Le scansioni della sonda %s sono bloccate" % nome,
        blocchi=[
            m.avviso("Finche' le scansioni restano bloccate la sonda non raccoglie:"
                     " la copertura si ferma senza altri segnali. %s." % motivo.capitalize(),
                     "attenzione"),
            m.fatti([
                ("Sonda", "%s (%s)" % (nome, riga["code"])),
                ("Motivo", motivo),
                ("Sede", riga.get("site") or "-"),
                ("Ultimo contatto", "%s UTC" % (riga.get("last_seen_at") or "-")),
            ]),
            m.bottone("Apri le sonde nella console",
                      "%s/probes/" % console.rstrip("/") if console else "", "critico"),
            m.paragrafo("Le scansioni si riattivano dalla console se sono disabilitate"
                        " dal server, o dall'interfaccia della sonda se sono state"
                        " sospese sul posto."),
        ],
        perche="Ricevi questo messaggio perche' sei un amministratore del tenant o il"
               " recapito di riferimento: una sonda ferma e' un buco nella copertura.",
        console_url=console,
    )


def _avvisa(riga: dict, motivo: str) -> bool:
    """Accoda l'avviso e segna l'episodio come notificato. Torna True se accodato."""
    from .notifications import queue_notification

    oggetto, corpo = _testo(riga, motivo)
    destinatari = _destinatari(int(riga["tenant_id"]))
    try:
        queue_notification(int(riga["tenant_id"]), EVENTO_BLOCCATA, destinatari,
                           oggetto, corpo, body_html=_html(riga, motivo))
    except Exception as errore:  # noqa: BLE001 - l'avviso non deve fermare il giro
        from flask import current_app

        current_app.logger.warning("Avviso sonda bloccata non accodato per %s: %s",
                                   riga["code"], type(errore).__name__)
        return False

    execute("UPDATE probes SET scan_blocked_alerted_at = ?, updated_at = ? WHERE id = ?",
            (utc_now_str(), utc_now_str(), int(riga["id"])))
    log_event(EVENTO_BLOCCATA,
              "Sonda %s con scansioni bloccate: %s" % (riga["code"], motivo),
              tenant_id=int(riga["tenant_id"]), entity="probe",
              entity_id=int(riga["id"]), severity="warning")
    return True


def _ripristina(riga: dict) -> None:
    """La sonda ha ripreso: si azzera l'avviso (cosi' un blocco futuro riavvisa) e si
    lascia la traccia nel diario, senza un secondo messaggio."""
    execute("UPDATE probes SET scan_blocked_alerted_at = NULL, updated_at = ? WHERE id = ?",
            (utc_now_str(), int(riga["id"])))
    log_event(EVENTO_RIPRESA, "Sonda %s: scansioni riprese" % riga["code"],
              tenant_id=int(riga["tenant_id"]), entity="probe",
              entity_id=int(riga["id"]), severity="info")


def giro() -> dict:
    """Un passaggio di sorveglianza. Restituisce quanti avvisi e ripristini ha prodotto."""
    from flask import current_app

    offline_after = int(current_app.config.get("PROBE_OFFLINE_AFTER_SEC", 900))
    righe = [dict(r) for r in query(
        "SELECT id, tenant_id, code, name, site, last_seen_at, scan_enabled,"
        " scan_paused, scan_blocked_alerted_at FROM probes"
        " WHERE enrolled_at IS NOT NULL AND revoked_at IS NULL")]

    avvisi = ripristini = 0
    for riga in righe:
        bloccata, motivo = _blocco(riga, offline_after)
        gia_avvisato = bool(riga.get("scan_blocked_alerted_at"))
        if bloccata and not gia_avvisato:
            if _avvisa(riga, motivo):
                avvisi += 1
        elif not bloccata and gia_avvisato:
            _ripristina(riga)
            ripristini += 1
    return {"esaminate": len(righe), "avvisi": avvisi, "ripristini": ripristini}


def start_watcher(app) -> None:
    """Avvia la sorveglianza in un thread proprio, come gli altri servizi di fondo."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return

    def ciclo():
        while not _stop.wait(TICK_SECONDI):
            try:
                with app.app_context():
                    esito = giro()
                    if esito["avvisi"] or esito["ripristini"]:
                        app.logger.warning(
                            "Sonde: %d avvisi di scansioni bloccate, %d ripristini",
                            esito["avvisi"], esito["ripristini"])
            except Exception as errore:  # nessun errore deve fermare il thread
                app.logger.warning("Sorveglianza delle sonde bloccate non riuscita: %s",
                                   errore)

    _thread = threading.Thread(target=ciclo, name="snap-probe-scan-watch", daemon=True)
    _thread.start()
    app.logger.info("Sorveglianza delle sonde con scansioni bloccate avviata (ogni %d s)",
                    TICK_SECONDI)


def stop_watcher() -> None:
    _stop.set()
