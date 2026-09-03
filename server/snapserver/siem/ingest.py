# -----------------------------------------------------------------
# ingest.py — pipeline di ingestione: dalle righe grezze agli eventi normalizzati
# Autore: Daniele Speziale
# Data creazione: 2026-09-02
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - L'ingestione dei log: veloce, a lotti, senza perdere nulla.

Il collettore (Vector, o il listener integrato) consegna un lotto di righe grezze
con il proprio token. Qui ogni riga viene:

  1. riconosciuta per firma di apparato e normalizzata (`parsers.classify`);
  2. attribuita a una sorgente dichiarata, per hostname o indirizzo di provenienza;
  3. accodata al lotto da scrivere in un colpo solo nel database degli eventi.

Non c'e' rilevazione in linea: separare la scrittura (che deve essere velocissima)
dall'analisi (che gira a intervalli, in `detect.py`) e' cio' che permette di
reggere le raffiche senza perdere eventi ne' rallentare la pagina.
"""

from __future__ import annotations

from ..db import utc_now_str
from . import MAX_EVENTS_PER_BATCH, MAX_MESSAGE_BYTES
from . import data, parsers, store


class IngestError(ValueError):
    """Lotto malformato. Il messaggio e' per chi ha configurato il collettore."""


def _attribuzione(sorgenti: list) -> tuple:
    """Prepara due indici (per host, per ip) per attribuire in fretta, senza una
    query per evento."""
    per_host = {}
    per_ip = {}
    for s in sorgenti:
        if s.get("match_host"):
            per_host[s["match_host"]] = s
        if s.get("match_ip"):
            per_ip[s["match_ip"]] = s
    return per_host, per_ip


def ingest_batch(collector: dict, righe: list) -> dict:
    """Elabora un lotto di righe grezze per conto di un collettore.

    `righe` e' una lista di stringhe oppure di dizionari {message, host?, src_ip?}:
    Vector puo' gia' aver estratto host e provenienza dall'involucro di trasporto, e
    in tal caso li si preferisce a quelli dedotti dal testo.
    """
    if not isinstance(righe, list):
        raise IngestError("il lotto deve essere una lista di righe")
    if len(righe) > MAX_EVENTS_PER_BATCH:
        raise IngestError("lotto troppo grande: massimo %d righe" % MAX_EVENTS_PER_BATCH)

    tenant_id = int(collector["tenant_id"])
    sorgenti = data.enabled_sources(tenant_id)

    # Un SIEM non configurato non raccoglie log alla cieca: l'ascolto syslog integrato
    # (collettore interno "listener") NON acquisisce finche' il tenant non ha dichiarato
    # nulla -- ne' una sorgente ne' un collettore Vector. L'inserimento manuale (incolla)
    # e il container Vector sono invece azioni esplicite/dichiarate e acquisiscono sempre.
    if (collector.get("kind") == "listener" and not sorgenti
            and not data.collectors(tenant_id)):
        return {"ricevuti": len(righe), "scritti": 0, "attribuiti": 0,
                "senza_sorgente": 0, "non_configurato": True}

    per_host, per_ip = _attribuzione(sorgenti)
    adesso = utc_now_str()

    da_scrivere = []
    conteggi_sorgente: dict = {}
    for grezza in righe:
        if isinstance(grezza, dict):
            testo = str(grezza.get("message") or "")
            host_trasporto = grezza.get("host")
            ip_trasporto = grezza.get("src_ip") or grezza.get("source_ip")
            kind_dichiarato = grezza.get("kind") or ""
        else:
            testo = str(grezza)
            host_trasporto = ip_trasporto = None
            kind_dichiarato = ""
        if not testo.strip():
            continue

        # Un dump di allarmi a blocchi (centralino MX-ONE) contiene PIU' eventi in un
        # solo messaggio: va spezzato in un evento per allarme, altrimenti un blocco
        # intero in una riga non e' cercabile ne' correlabile. Gli altri log sono una
        # riga = un evento e passano dal riconoscimento a firme.
        blocchi = parsers.parse_mxone_alarms(testo)
        if blocchi:
            eventi = blocchi
        else:
            eventi = [parsers.classify(testo[:MAX_MESSAGE_BYTES],
                                       kind_dichiarato or "")]

        for evento in eventi:
            host = host_trasporto or evento.get("host")
            ip = ip_trasporto or evento.get("src_ip")
            sorgente = None
            if host and host in per_host:
                sorgente = per_host[host]
            if sorgente is None and ip and ip in per_ip:
                sorgente = per_ip[ip]

            riga = {
                "tenant_id": tenant_id,
                "source_id": sorgente["id"] if sorgente else None,
                "received_at": adesso,
                "event_time": evento.get("event_time"),
                "host": host,
                "app": evento.get("app"),
                "severity": evento.get("severity") or "info",
                "facility": evento.get("facility"),
                "event_kind": evento.get("event_kind") or "other",
                "src_ip": evento.get("src_ip") or ip,
                "dst_ip": evento.get("dst_ip"),
                "src_port": _intero(evento.get("src_port")),
                "dst_port": _intero(evento.get("dst_port")),
                "username": evento.get("username"),
                "action": evento.get("action"),
                "outcome": evento.get("outcome"),
                "message": evento["message"][:MAX_MESSAGE_BYTES],
                # I fatti aggiuntivi arrivano come '_extra' dalle firme e come 'extra'
                # dal parser a blocchi: si accetta l'uno o l'altro.
                "extra_json": store.normalizza_extra(
                    evento.get("_extra") or evento.get("extra")),
            }
            da_scrivere.append(riga)
            if sorgente:
                conteggi_sorgente[sorgente["id"]] = (
                    conteggi_sorgente.get(sorgente["id"], 0) + 1)

    scritti = store.insert_events(da_scrivere)
    data.touch_collector(int(collector["id"]), scritti)
    for source_id, quanti in conteggi_sorgente.items():
        data.touch_source(source_id, quanti, adesso)

    return {"ricevuti": len(righe), "scritti": scritti,
            "attribuiti": sum(conteggi_sorgente.values()),
            "senza_sorgente": scritti - sum(conteggi_sorgente.values())}


def _intero(valore) -> int | None:
    try:
        return int(valore) if valore not in (None, "") else None
    except (TypeError, ValueError):
        return None
