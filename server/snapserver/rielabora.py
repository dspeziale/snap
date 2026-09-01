"""
snap server - Riapplicare il prodotto ai dati gia' raccolti.

Il problema, dichiarato: questo prodotto **conserva le prove** e ne ricava giudizi.
Quando i giudizi migliorano -- una firma nuova, una zona dichiarata, una regola di
esposizione aggiunta, un catalogo di vulnerabilita' aggiornato -- i dati raccolti
ieri restano validi ma **le conclusioni tratte da essi no**. Senza un modo di
rielaborare, il miglioramento vale solo per cio' che si scansiona domani, e su una
rete che si ricensisce ogni tre giorni significa aspettare tre giorni per vedere il
lavoro fatto. Peggio: le due meta' dell'inventario -- quella vecchia e quella nuova
-- si leggerebbero con criteri diversi senza che nulla lo dichiari.

Che cosa si rielabora, e in che ordine. L'ordine non e' un dettaglio: ogni passo usa
il risultato del precedente.

  1. **porte iniettate**   una porta attribuita da un apparato intermedio non e' una
                           prova del nodo, e va esclusa prima di ogni verdetto;
  2. **riconoscimento**    il tipo di dispositivo dalle prove conservate (porte,
                           sistema operativo, script, SNMP e ora le letture web);
  3. **correlazione**      vulnerabilita' ed esposizioni, che dipendono dal prodotto
                           e dalla versione riconosciuti al passo 2;
  4. **zone**              il giudizio contestuale sulle esposizioni prodotte al
                           passo 3.

Che cosa NON fa: **nessuna scansione**. Non contatta i dispositivi, non interroga le
sonde, non esce verso internet. Rilegge cio' che c'e' in archivio e ne trae le
conclusioni con le regole di oggi -- ed e' esattamente per questo che si puo'
eseguire in orario di lavoro.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import time

from flask import current_app

from .audit import log_event
from .db import query

# I passi, nell'ordine in cui si applicano. Ciascuno dichiara che cosa fa e perche'
# sta in quella posizione: chi legge la pagina deve poter decidere se gli serve.
PASSI = (
    {
        "chiave": "porte",
        "titolo": "Porte attribuite dalla rete",
        "spiegazione": "Rivaluta quali porte sono state annunciate da un apparato"
                       " intermedio invece che dal dispositivo. Va per prima: una"
                       " porta che non appartiene al nodo non deve pesare su nessun"
                       " verdetto successivo.",
    },
    {
        "chiave": "riconoscimento",
        "titolo": "Riconoscimento dei dispositivi",
        "spiegazione": "Ricalcola tipo, etichetta e confidenza dalle prove"
                       " conservate: porte, sistema operativo, script, letture SNMP"
                       " e pagine di gestione. Serve dopo ogni aggiunta al catalogo"
                       " delle firme.",
    },
    {
        "chiave": "correlazione",
        "titolo": "Vulnerabilita' ed esposizioni",
        "spiegazione": "Rifa' la correlazione fra inventario e catalogo delle"
                       " vulnerabilita', e rivaluta le esposizioni di servizio."
                       " Dipende dal passo precedente, perche' prodotto e versione"
                       " riconosciuti decidono che cosa e' attribuibile.",
    },
    {
        "chiave": "zone",
        "titolo": "Giudizio delle zone di rete",
        "spiegazione": "Riapplica il contesto: cio' che e' atteso in una zona non"
                       " conta fra i riscontri aperti, cio' che la viola sale di"
                       " gravita'. Si applica alle esposizioni del passo precedente.",
    },
)

CHIAVI = tuple(passo["chiave"] for passo in PASSI)


def descrizione_passi() -> tuple:
    return PASSI


def rielabora(tenant_id: int, passi=None, attore: str = None) -> dict:
    """Riapplica al dato conservato le regole di oggi. Nessuna scansione.

    `passi` limita il lavoro a un sottoinsieme (allowlist su CHIAVI); vuoto significa
    tutti. Restituisce un resoconto per passo: e' cio' che si mostra all'operatore, e
    dire "fatto" senza numeri non sarebbe una risposta.
    """
    scelti = [c for c in (passi or CHIAVI) if c in CHIAVI] or list(CHIAVI)
    avvio = time.monotonic()
    esito = {"passi": {}, "ordine": scelti}

    if "porte" in scelti:
        esito["passi"]["porte"] = _porte(tenant_id)
    if "riconoscimento" in scelti:
        esito["passi"]["riconoscimento"] = _riconoscimento(tenant_id)
    if "correlazione" in scelti:
        esito["passi"]["correlazione"] = _correlazione(tenant_id)
    if "zone" in scelti:
        esito["passi"]["zone"] = _zone(tenant_id)

    esito["durata_s"] = round(time.monotonic() - avvio, 1)
    esito["nodi"] = _quanti_nodi(tenant_id)

    log_event(
        "inventory.reprocessed",
        "Rielaborazione dei dati raccolti (%s) in %s s: %s"
        % (", ".join(scelti), esito["durata_s"], _riassunto(esito)),
        tenant_id=tenant_id, severity="info", entity="inventory", actor=attore)
    return esito


def _riassunto(esito: dict) -> str:
    pezzi = []
    for chiave, dati in esito["passi"].items():
        if isinstance(dati, dict) and dati.get("riassunto"):
            pezzi.append("%s: %s" % (chiave, dati["riassunto"]))
    return "; ".join(pezzi) or "nessuna modifica"


def _quanti_nodi(tenant_id: int) -> int:
    riga = query("SELECT COUNT(*) AS n FROM nodes WHERE tenant_id = ?",
                 (tenant_id,), one=True)
    return int(riga["n"] or 0) if riga is not None else 0


# --------------------------------------------------------------------------- #
# I passi
# --------------------------------------------------------------------------- #
def _porte(tenant_id: int) -> dict:
    from .ingest import refresh_suspect_ports

    try:
        quante = refresh_suspect_ports(tenant_id)
    except Exception as errore:  # noqa: BLE001 - un passo che cade non ferma gli altri
        current_app.logger.exception("Rielaborazione delle porte non riuscita")
        return {"errore": type(errore).__name__, "riassunto": "non eseguito"}

    # refresh_suspect_ports puo' restituire un intero o un dizionario, secondo la
    # versione: si normalizza qui invece di supporre.
    marcate = quante if isinstance(quante, int) else int((quante or {}).get("suspect") or 0)
    return {"porte_attribuite_alla_rete": marcate,
            "riassunto": "%d porte attribuite alla rete" % marcate}


def _riconoscimento(tenant_id: int) -> dict:
    from .ingest import refingerprint_tenant

    try:
        esito = refingerprint_tenant(tenant_id)
    except Exception as errore:  # noqa: BLE001
        current_app.logger.exception("Rideterminazione dei dispositivi non riuscita")
        return {"errore": type(errore).__name__, "riassunto": "non eseguito"}

    return {"dispositivi": esito.get("nodes", 0),
            "cambiati": esito.get("changed", 0),
            "versione_catalogo": esito.get("catalog_version"),
            "riassunto": "%d dispositivi riesaminati, %d cambiati"
                         % (esito.get("nodes", 0), esito.get("changed", 0))}


def _correlazione(tenant_id: int) -> dict:
    from .threat import correlate

    try:
        esito = correlate(tenant_id)
    except Exception as errore:  # noqa: BLE001
        current_app.logger.exception("Correlazione non riuscita")
        return {"errore": type(errore).__name__, "riassunto": "non eseguito"}

    confermate = esito.get("confermati", 0)
    esposizioni = esito.get("esposizioni", 0)
    return {"riscontri": esito, "riassunto": "%s confermate, %s esposizioni"
                                             % (confermate, esposizioni)}


def _zone(tenant_id: int) -> dict:
    """Il giudizio delle zone si riapplica insieme alla correlazione.

    Non e' un passo separato nel codice -- le zone entrano nella correlazione -- ma lo
    e' per chi legge: "ho cambiato una zona, che cosa devo rieseguire?" ha una
    risposta sola, e questo passo la rende esplicita contando come stanno le cose
    dopo il lavoro.
    """
    from . import zones
    from .threat import STATUS_EXPECTED

    subnet = query("SELECT COALESCE(zone, '') AS zone FROM subnets WHERE tenant_id = ?",
                   (tenant_id,))
    sintesi = zones.summary(subnet, tenant_id)
    attesi = query(
        "SELECT COUNT(*) AS n FROM ti_findings WHERE tenant_id = ? AND status = ?",
        (tenant_id, STATUS_EXPECTED), one=True)
    aperti = query(
        "SELECT COUNT(*) AS n FROM ti_findings WHERE tenant_id = ? AND status = 'open'"
        " AND kind = 'exposure'", (tenant_id,), one=True)

    quanti_attesi = int(attesi["n"] or 0) if attesi is not None else 0
    quanti_aperti = int(aperti["n"] or 0) if aperti is not None else 0
    return {
        "subnet_con_zona": sintesi["dichiarate"],
        "subnet_senza_zona": sintesi["senza_zona"],
        "esposizioni_attese": quanti_attesi,
        "esposizioni_aperte": quanti_aperti,
        "riassunto": "%d esposizioni attese nel contesto, %d restano aperte"
                     % (quanti_attesi, quanti_aperti),
    }
