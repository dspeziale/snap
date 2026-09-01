"""
Stato del collegamento dichiarato dalla sonda.

Difetto osservato: la sonda mostrava "server non raggiungibile" mentre i lotti
venivano conferiti regolarmente. Il giro dell'agente svolgeva la scansione prima
del battito, e una fase di ispezione dura minuti: per tutto quel tempo, dopo un
riavvio, nessun contatto era ancora avvenuto. Inoltre un conferimento riuscito non
riaccendeva l'indicatore, che pero' l'errore di trasporto spegneva.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from snapprobe.agent import CONTACT_FRESH_SECONDS, ProbeAgent
from snapprobe.client import TransportError


def _momento(scarto_secondi: int) -> str:
    istante = datetime.now(timezone.utc) + timedelta(seconds=scarto_secondi)
    return istante.strftime("%Y-%m-%d %H:%M:%S")


class ClienteFinto:
    """Cliente del server che registra l'ordine delle chiamate."""

    def __init__(self, ordine: list, battito_fallisce: bool = False):
        self.ordine = ordine
        self.battito_fallisce = battito_fallisce
        self.lotti = []

    def heartbeat(self):
        self.ordine.append("battito")
        if self.battito_fallisce:
            raise TransportError("collegamento rifiutato")
        return {"config": {}, "commands": []}

    def send_batch(self, uid, records, momento):
        self.ordine.append("conferimento")
        self.lotti.append((uid, records))
        return {"accepted": True, "detail": "accettato"}


class ScansioneFinta:
    """Fase di scansione che registra il proprio turno."""

    def __init__(self, ordine: list):
        self.ordine = ordine
        self.svolte = 0

    def esegui(self):
        self.ordine.append("scansione")
        self.svolte += 1
        return {"stage": "services", "records": 0}


@pytest.fixture()
def agente(probe_store, monkeypatch):
    """Agente registrato, con cliente e scansione finti."""
    # La registrazione e' riconosciuta dalla presenza dell'identificativo e della
    # chiave di sessione: senza entrambi il giro si fermerebbe prima del contatto.
    probe_store.set_setting("probe_uid", "sonda-di-prova")
    probe_store.set_setting("session_key", "k" * 43)
    probe_store.set_setting("api_key", "chiave-di-prova")
    probe_store.set_setting("server_url", "http://127.0.0.1:5500")
    probe_store.set_setting("server_public_key", "x" * 43)
    assert probe_store.is_enrolled(), "l'archivio di prova deve risultare registrato"

    return ProbeAgent(probe_store, "1.0.0-test")


def test_il_battito_precede_la_scansione(agente, probe_store):
    """I comandi viaggiano nella risposta al battito: rimandarlo a dopo una fase
    di ispezione li ritarderebbe di minuti."""
    ordine: list = []
    agente.client = ClienteFinto(ordine)
    scansione = ScansioneFinta(ordine)
    agente._run_due_scan = scansione.esegui

    agente.run_once()

    assert ordine[0] == "battito", "il battito deve venire per primo: %s" % ordine
    assert "scansione" in ordine
    assert ordine.index("battito") < ordine.index("scansione")


def test_il_conferimento_segue_la_scansione(agente, probe_store):
    """Cio' che la scansione produce deve partire nello stesso giro."""
    ordine: list = []
    agente.client = ClienteFinto(ordine)
    agente._run_due_scan = ScansioneFinta(ordine).esegui
    probe_store.enqueue("events", {"level": "info", "message": "prova"})

    agente.run_once()

    assert "conferimento" in ordine, "la coda non e' stata svuotata: %s" % ordine
    assert ordine.index("scansione") < ordine.index("conferimento")


def test_la_scansione_prosegue_se_il_server_non_risponde(agente):
    """L'autonomia della sonda non dipende dal server."""
    ordine: list = []
    agente.client = ClienteFinto(ordine, battito_fallisce=True)
    scansione = ScansioneFinta(ordine)
    agente._run_due_scan = scansione.esegui

    agente.run_once()

    assert scansione.svolte == 1, "la scansione doveva essere svolta comunque"
    assert agente.online is False
    assert "conferimento" not in ordine


def test_un_lotto_accettato_riaccende_l_indicatore(agente, probe_store):
    """L'indicatore si spegneva sull'errore di trasporto ma non si riaccendeva
    su un conferimento riuscito: non descriveva lo stato del collegamento."""
    ordine: list = []
    agente.client = ClienteFinto(ordine)
    agente._run_due_scan = lambda: None
    agente._online = False
    probe_store.enqueue("events", {"level": "info", "message": "prova"})

    agente.flush_queue()

    assert agente.online is True
    assert agente.last_error == ""


def test_all_avvio_vale_l_ultimo_contatto_recente(probe_store):
    """Prima del primo battito il collegamento non e' stato provato: dichiararlo
    interrotto sarebbe un'affermazione non verificata."""
    probe_store.set_setting("last_contact_at", _momento(-30))
    assert ProbeAgent(probe_store, "1.0.0-test").online is True

    probe_store.set_setting("last_contact_at", _momento(-(CONTACT_FRESH_SECONDS + 60)))
    assert ProbeAgent(probe_store, "1.0.0-test").online is False

    probe_store.set_setting("last_contact_at", "non-una-data")
    assert ProbeAgent(probe_store, "1.0.0-test").online is False, (
        "un valore illeggibile non si indovina")
