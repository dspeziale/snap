# -----------------------------------------------------------------
# acn_watch.py — sorveglianza dei termini di comunicazione ad ACN
# Autore: Daniele Speziale
# Data creazione: 2026-08-31
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Avvisare prima che un termine di legge scada.

Un termine che scade in silenzio e' il difetto peggiore che questa parte del prodotto
possa avere: le 24 ore del preallarme cadono di notte, di sabato, durante un incidente
che sta occupando tutti. Quindi due avvisi, e solo due:

* **in avvicinamento**: quando restano meno di `ORE_AVVISO` ore (predefinite: 6). Uno
  per comunicazione, non uno per giro: un avviso ripetuto ogni cinque minuti diventa
  rumore, e il rumore si silenzia;
* **termine superato**: una volta, quando il termine e' passato. Serve a chi arriva
  dopo, perche' da quel momento la domanda non e' piu' "quando inviamo" ma "come lo
  scriviamo nel fascicolo".

Il canale e' quello che esiste gia' (posta e messaggistica): un modulo di avviso che si
fabbrica un canale proprio finirebbe per non essere configurato.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import threading

from . import acn
from .audit import log_event
from .db import execute, query, utc_now_str

# Quanto prima si avvisa. Sei ore su ventiquattro lasciano il tempo di reagire anche di
# notte; su settantadue sono un margine ampio, e non e' un difetto: il preallarme e'
# quello che stringe.
ORE_AVVISO = 6.0
TICK_SECONDI = 300

_stop = threading.Event()
_thread = None

EVENTO_AVVISO = "acn.deadline.approaching"
EVENTO_SUPERATO = "acn.deadline.passed"


def _testo(voce: dict, superato: bool) -> tuple:
    stadio = acn.STADI_PER_CHIAVE.get(voce["stage"], {})
    nome = stadio.get("nome", voce["stage"])
    residuo = voce.get("residuo_ore")
    if superato:
        oggetto = "snap - termine ACN SUPERATO: %s, incidente #%s" % (
            nome, voce["incident_id"])
        corpo = [
            "Il termine per la comunicazione ad ACN e' passato.",
            "",
            "  Stadio       : %s (%s)" % (nome, stadio.get("termine", "")),
            "  Incidente    : #%s" % voce["incident_id"],
            "  Scadenza     : %s (UTC)" % (voce.get("deadline_at") or "-"),
            "  Ore oltre    : %.1f" % abs(residuo or 0),
            "",
            "Da questo momento la domanda non e' piu' quando inviare, ma come",
            "scriverlo nel fascicolo: la comunicazione va inviata comunque e la",
            "motivazione del ritardo va registrata.",
        ]
    else:
        oggetto = "snap - termine ACN fra %.1f ore: %s, incidente #%s" % (
            residuo or 0, nome, voce["incident_id"])
        corpo = [
            "Una comunicazione dovuta ad ACN sta per scadere.",
            "",
            "  Stadio       : %s (%s)" % (nome, stadio.get("termine", "")),
            "  Incidente    : #%s" % voce["incident_id"],
            "  Scadenza     : %s (UTC)" % (voce.get("deadline_at") or "-"),
            "  Ore restanti : %.1f" % (residuo or 0),
            "",
            "Il fascicolo si prepara dalla console (Sicurezza > Comunicazioni ACN).",
            "L'invio avviene dal portale con identita' digitale del punto di contatto:",
            "dopo l'invio va registrato il numero di protocollo.",
        ]
    return oggetto, "\n".join(corpo)


def _html(voce: dict, superato: bool) -> str:
    """L'avviso sul termine, nella forma condivisa dei messaggi."""
    from . import mail_layout as m
    from .notifications import _setting

    stadio = acn.STADI_PER_CHIAVE.get(voce["stage"], {})
    nome = stadio.get("nome", voce["stage"])
    residuo = voce.get("residuo_ore") or 0
    console = _setting("public_url", "")

    if superato:
        titolo = "Termine superato: %s" % nome
        blocco = m.avviso(
            "Il termine per questa comunicazione e' passato da %.1f ore. Da questo"
            " momento la domanda non e' piu' quando inviare, ma come scriverlo nel"
            " fascicolo: la comunicazione va inviata comunque e la motivazione del"
            " ritardo va registrata." % abs(residuo), "critico")
    else:
        titolo = "Termine fra %.1f ore: %s" % (residuo, nome)
        blocco = m.avviso(
            "Una comunicazione dovuta all'Agenzia per la Cybersicurezza Nazionale sta"
            " per scadere. Il fascicolo si prepara dalla console; l'invio avviene dal"
            " portale con identita' digitale del punto di contatto.", "acn")

    return m.messaggio(
        titolo=titolo,
        sottotitolo="Incidente #%s - art. 23 della direttiva (UE) 2022/2555"
                    % voce["incident_id"],
        genere="acn",
        preintestazione=titolo,
        blocchi=[
            blocco,
            m.fatti([
                ("Stadio", nome),
                ("Termine di legge", stadio.get("termine", "-")),
                ("Scadenza", "%s UTC" % (voce.get("deadline_at") or "-")),
                ("Conoscenza dell'incidente", "%s UTC" % (voce.get("known_at") or "-")),
                ("Ore %s" % ("oltre il termine" if superato else "restanti"),
                 "%.1f" % abs(residuo)),
                ("Stato", acn.STATI.get(voce.get("status"), voce.get("status"))),
            ]),
            m.bottone("Apri il fascicolo nella console",
                      "%s/acn/" % console.rstrip("/") if console else "", "acn"),
            m.paragrafo("Dopo l'invio va registrato in console il numero di protocollo"
                        " restituito dal portale: e' cio' che dimostra i tempi in"
                        " un'ispezione."),
        ],
        perche="Ricevi questo messaggio perche' sei un amministratore del tenant o il"
               " recapito di riferimento: i termini di legge non si possono"
               " disattivare.",
        console_url=console,
    )


def _destinatari(tenant_id: int) -> list:
    """A chi va l'avviso: il recapito del tenant e gli amministratori del tenant.

    Non e' un elenco configurabile a parte: un secondo elenco di recapiti da tenere
    aggiornato e' un elenco che invecchia, e un avviso che non arriva e' peggio di un
    avviso che arriva a qualcuno in piu'.
    """
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


def _avvisa(voce: dict, superato: bool) -> bool:
    """Accoda l'avviso sui canali configurati. Torna True se e' stato accodato."""
    from .notifications import queue_notification

    oggetto, corpo = _testo(voce, superato)
    evento = EVENTO_SUPERATO if superato else EVENTO_AVVISO
    destinatari = _destinatari(int(voce["tenant_id"]))
    html = _html(voce, superato)
    try:
        accodate = queue_notification(int(voce["tenant_id"]), evento, destinatari,
                                      oggetto, corpo,
                                      incident_id=int(voce["incident_id"]),
                                      body_html=html)
    except Exception as errore:  # noqa: BLE001 - l'avviso non deve fermare il giro
        from flask import current_app

        current_app.logger.warning("Avviso ACN non accodato per la comunicazione %s:"
                                   " %s", voce["id"], type(errore).__name__)
        return False

    colonna = "overdue_alerted_at" if superato else "alerted_at"
    execute("UPDATE acn_communications SET %s = ?, updated_at = ? WHERE id = ?"
            % colonna, (utc_now_str(), utc_now_str(), int(voce["id"])))
    log_event(evento,
              "Termine ACN %s per lo stadio %s dell'incidente #%s"
              % ("superato" if superato else "in avvicinamento",
                 voce.get("stadio_nome") or voce["stage"], voce["incident_id"]),
              tenant_id=int(voce["tenant_id"]), entity="incident",
              entity_id=int(voce["incident_id"]),
              severity="critical" if superato else "warning")
    return bool(accodate) or True


def giro(ore: float = None) -> dict:
    """Un passaggio di sorveglianza. Restituisce quanti avvisi ha prodotto."""
    ore = ORE_AVVISO if ore is None else ore
    righe = [dict(r) for r in query(
        "SELECT * FROM acn_communications"
        " WHERE status IN (?, ?) AND COALESCE(deadline_at, '') <> ''",
        (acn.DA_PREPARARE, acn.PREPARATA))]

    avvisi = superati = 0
    for riga in righe:
        residuo = acn.residuo_ore(riga.get("deadline_at") or "")
        if residuo is None:
            continue
        riga["residuo_ore"] = residuo
        riga["stadio_nome"] = acn.STADI_PER_CHIAVE.get(riga["stage"], {}).get(
            "nome", riga["stage"])
        if residuo < 0:
            if not riga.get("overdue_alerted_at"):
                superati += 1 if _avvisa(riga, True) else 0
            continue
        if residuo <= ore and not riga.get("alerted_at"):
            avvisi += 1 if _avvisa(riga, False) else 0
    return {"esaminate": len(righe), "avvisi": avvisi, "superati": superati}


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
                    if esito["avvisi"] or esito["superati"]:
                        app.logger.warning(
                            "Termini ACN: %d avvisi, %d termini superati",
                            esito["avvisi"], esito["superati"])
            except Exception as errore:  # nessun errore deve fermare il thread
                app.logger.warning("Sorveglianza dei termini ACN non riuscita: %s",
                                   errore)

    _thread = threading.Thread(target=ciclo, name="snap-acn", daemon=True)
    _thread.start()
    app.logger.info("Sorveglianza dei termini ACN avviata (ogni %d s, avviso a %.0f"
                    " ore dal termine)", TICK_SECONDI, ORE_AVVISO)


def stop_watcher() -> None:
    _stop.set()
