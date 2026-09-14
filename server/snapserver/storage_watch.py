# -----------------------------------------------------------------
# storage_watch.py — misura l'occupazione dell'archivio e avvisa se sta finendo
# Autore: Daniele Speziale
# Data creazione: 2026-09-14
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Sorveglianza dello spazio.

DUE COMPITI, E UNO SOLO NON BASTAVA. Il primo e' misurare: una volta al giorno si
registra quanto occupa l'archivio. Il secondo e' avvisare: se a questo ritmo lo
spazio libero finisce entro la soglia, si apre un episodio nel registro delle azioni
(il perche' non sia una mail e' scritto piu' sotto).

Perche' la misura non la fa chi apre la pagina. Se la facesse, la storia
dell'occupazione esisterebbe solo per gli archivi che qualcuno guarda -- e quello
dimenticato, l'unico che riempie davvero un disco, non ne avrebbe alcuna proprio il
giorno in cui servirebbe. La crescita e' una DIFFERENZA fra due misure: senza
qualcuno che le prenda con regolarita', non esiste affatto.

Perche' l'avviso. Un archivio pieno non degrada: si ferma. PostgreSQL rifiuta le
scritture, i conferimenti delle sonde restano in coda, e il prodotto smette di
raccogliere senza che nessuna pagina lo dica -- lo stesso difetto che
`probe_scan_watch` sorveglia sulle sonde. Con una previsione in giorni l'avviso
arriva quando c'e' ancora tempo per fare qualcosa: applicare la conservazione,
compattare, o aggiungere disco. Continuita' operativa, NIS2 art. 21(2)(c).

Si avvisa UNA VOLTA per episodio, come per le sonde bloccate: la previsione peggiora
di ora in ora, e un messaggio a ogni giro sarebbe un messaggio ignorato. Quando la
previsione torna sopra la soglia -- spazio aggiunto, dati cancellati -- l'episodio si
chiude e un peggioramento futuro avvisa di nuovo.

PERCHE' L'AVVISO NON PARTE PER POSTA, e non e' una dimenticanza. La coda delle
notifiche e' di un tenant: `notifications.tenant_id` e' NOT NULL con chiave esterna
verso `tenants`. L'archivio invece e' UNO SOLO per tutti i tenant, la sua dimensione
non e' attribuibile a nessuno di essi, e le tre strade per forzare il vincolo erano
tutte peggiori del male: mandarlo a ogni tenant (lo stesso messaggio N volte, a chi
non puo' farci niente), attaccarlo a un tenant scelto a caso (un'attribuzione
inventata che resta scritta nel registro), o rendere la colonna annullabile (una
modifica a una tabella centrale per una funzione che non e' stata chiesta).
L'episodio finisce percio' nel REGISTRO DELLE AZIONI, che e' di sistema e non di
tenant, ed e' visibile in Amministrazione insieme al resto. Aggiungere il recapito
per posta e' una decisione separata: vuole una notifica di sistema, che oggi non
esiste.

remarks: Autore: Daniele Speziale - Data: 2026-09-14
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import threading

from .audit import log_event
from .db import query

# Ogni ora. La misura vera e' quotidiana (`maintenance.STORIA_INTERVALLO_ORE`): questo
# e' solo il passo con cui si va a vedere se e' ora, e serve a non dipendere dall'ora
# esatta in cui il servizio e' stato avviato.
TICK_SECONDI = 3600

# Sotto questa previsione si avvisa. Sessanta giorni non sono una cifra tonda a caso:
# sono il tempo che serve in una PA per far approvare l'ampliamento di un volume.
GIORNI_DI_ALLARME = 60
# Si rientra sopra questa, non sopra la soglia di allarme: senza distanza fra le due,
# una previsione che oscilla intorno ai sessanta giorni manderebbe un avviso e un
# rientro al giorno.
GIORNI_DI_RIENTRO = 90

CHIAVE_ALLARME = "storage.full.alerted_at"
# Nomi degli episodi nel registro delle azioni (non momenti del workflow delle
# notifiche: vedi la ragione in cima al modulo).
EVENTO_ALLARME = "storage.full.warning"
EVENTO_RIENTRO = "storage.full.resolved"

_stop = threading.Event()
_thread = None


def _impostazione(chiave: str) -> str:
    riga = query("SELECT value FROM system_settings WHERE key = ?", (chiave,), one=True)
    return (riga or {}).get("value") or ""


def _scrivi_impostazione(chiave: str, valore: str) -> None:
    from .db import execute, utc_now_str

    execute("INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value,"
            " updated_at = excluded.updated_at",
            (chiave, valore, utc_now_str()))


def giro() -> dict:
    """Un passaggio: misura se e' ora, poi valuta la previsione.

    Restituisce che cosa ha fatto, cosi' il registro dice se il giro e' servito.
    """
    from flask import current_app

    from . import maintenance

    esito = {"misurata": False, "avviso": False, "rientro": False,
             "giorni_al_riempimento": None}
    try:
        esito["misurata"] = maintenance.storage_sample()
    except Exception as errore:  # noqa: BLE001 - la misura non deve fermare l'avviso
        current_app.logger.warning("Misura dell'occupazione non riuscita: %s", errore)

    tendenza = maintenance.storage_trend()
    giorni = tendenza.get("giorni_al_riempimento")
    esito["giorni_al_riempimento"] = giorni
    gia_avvisato = bool(_impostazione(CHIAVE_ALLARME))

    # Previsione assente: non e' una buona notizia e non e' una cattiva notizia. Con
    # meno di due misure non si sa, e non si sa nemmeno se rientrare da un allarme
    # aperto: si lascia tutto com'e'.
    if giorni is None:
        return esito

    if giorni < GIORNI_DI_ALLARME and not gia_avvisato:
        esito["avviso"] = _avvisa(giorni)
    elif giorni > GIORNI_DI_RIENTRO and gia_avvisato:
        _scrivi_impostazione(CHIAVE_ALLARME, "")
        log_event(EVENTO_RIENTRO,
                  "Spazio dell'archivio: previsione tornata a %d giorni" % int(giorni),
                  entity="database", severity="info")
        esito["rientro"] = True
    return esito


def _avvisa(giorni: float) -> bool:
    """Apre l'episodio nel registro delle azioni. Vero se l'ha aperto.

    Il messaggio dice anche COSA FARE: un avviso che comunica solo il problema
    costringe chi lo legge a cercare da solo la pagina giusta, e in quel momento non
    ha tempo.
    """
    from . import maintenance
    from .db import utc_now_str

    misura = maintenance.database_size()
    disco = maintenance.disk_free()
    log_event(
        EVENTO_ALLARME,
        "Spazio dell'archivio: circa %d giorni al riempimento. L'archivio occupa"
        " %.1f MB, restano %.1f GB liberi sul volume delle copie. Si interviene da"
        " Amministrazione > Impostazioni > Archivio: applicare la conservazione,"
        " compattare, oppure aggiungere spazio."
        % (int(giorni), misura.get("file_byte", 0) / 1048576.0,
           disco.get("libero", 0) / 1073741824.0),
        entity="database", severity="warning")
    _scrivi_impostazione(CHIAVE_ALLARME, utc_now_str())
    return True


def start_watcher(app) -> None:
    """Avvia la sorveglianza in un thread proprio, come gli altri servizi di fondo."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return

    def ciclo():
        # Il PRIMO giro subito, non fra un'ora: un archivio senza alcuna misura non ne
        # avrebbe nessuna per tutta la prima ora di esercizio, e un riavvio ogni
        # cinquanta minuti lo lascerebbe senza storia per sempre.
        primo = True
        while primo or not _stop.wait(TICK_SECONDI):
            primo = False
            try:
                with app.app_context():
                    esito = giro()
                    if esito["avviso"]:
                        app.logger.warning(
                            "Spazio dell'archivio: avviso inviato (%d giorni)",
                            int(esito["giorni_al_riempimento"] or 0))
                    elif esito["misurata"]:
                        app.logger.info("Occupazione dell'archivio misurata")
            except Exception as errore:  # nessun errore deve fermare il thread
                app.logger.warning("Sorveglianza dello spazio non riuscita: %s", errore)
            if _stop.is_set():
                break

    _thread = threading.Thread(target=ciclo, name="snap-storage-watch", daemon=True)
    _thread.start()
    app.logger.info("Sorveglianza dello spazio dell'archivio avviata (ogni %d s)",
                    TICK_SECONDI)


def stop_watcher() -> None:
    _stop.set()
