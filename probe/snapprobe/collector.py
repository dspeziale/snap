"""
snap probe - Raccolta dati.

In questa fase la sonda non esegue rilevazioni sulla rete: produce annotazioni
diagnostiche sul proprio funzionamento (ciclo eseguito, stato della coda,
ambiente di esecuzione). Sono sufficienti a esercitare l'intero percorso
raccolta -> coda locale -> conferimento cifrato -> registro del server, e
mantengono il meccanismo pronto per le funzioni di raccolta che verranno
definite.

Un solo tipo di record e' previsto, `event`, che il server registra nell'audit
del tenant. Per introdurre nuovi tipi occorre aggiungerli qui e nel
corrispondente applicatore del server (`snapserver.ingest`).

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import platform
import socket
from datetime import datetime, timezone

from .store import ProbeStore, utc_now_str


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _fmt(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S")


class Collector:
    """Generatore dei record di raccolta."""

    def __init__(self, store: ProbeStore):
        self.store = store

    def _cycle(self) -> int:
        """Numero progressivo del ciclo di raccolta, conservato localmente."""
        try:
            corrente = int(self.store.get_setting("collection_cycle", "0") or 0)
        except ValueError:
            corrente = 0
        successivo = corrente + 1
        self.store.set_setting("collection_cycle", successivo)
        return successivo

    def collect(self) -> dict:
        """Esegue un ciclo di raccolta e accoda i record prodotti."""
        momento = _now()
        ciclo = self._cycle()
        in_coda = self.store.queue_size()

        evento = {
            "type": "probe.cycle",
            "severity": "info",
            "description": "Ciclo di raccolta %d eseguito dalla sonda" % ciclo,
            "created_at": _fmt(momento),
            "detail": {
                "ciclo": ciclo,
                "record_in_coda": in_coda,
                "intervallo_sec": int(self.store.get_setting("scan_interval_sec", "300") or 300),
                "piattaforma": "%s %s" % (platform.system(), platform.release()),
                "host": socket.gethostname(),
                "versione_agente": self.store.get_setting("agent_version", "n.d."),
            },
        }
        self.store.enqueue("event", evento)

        self.store.set_setting("last_collection_at", utc_now_str())
        self.store.log(
            "info",
            "Raccolta completata: ciclo %d, coda a %d record"
            % (ciclo, self.store.queue_size()),
        )
        return {"events": 1, "cycle": ciclo}

    def reset(self) -> None:
        """Azzera il conteggio dei cicli di raccolta."""
        self.store.set_setting("collection_cycle", 0)
        self.store.log("warning", "Conteggio dei cicli di raccolta azzerato")
