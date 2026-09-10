# -----------------------------------------------------------------
# test_dietro_proxy.py — comportamento dietro il reverse proxy che termina il TLS
# Autore: Daniele Speziale
# Data creazione: 2026-09-09
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""In esercizio i due componenti stanno dietro nginx, che termina il TLS. Senza
fidarsi delle intestazioni X-Forwarded-* l'applicazione vedrebbe l'indirizzo del
proxy invece di quello del client -- e sulla sonda quella differenza decide chi puo'
scegliere la password.

Le prove verificano le DUE direzioni:
* con `BEHIND_PROXY` spento l'intestazione viene IGNORATA (predefinito prudente);
* con `BEHIND_PROXY` acceso l'intestazione vale, ed e' cio' che rende usabile il
  container -- la sua non falsificabilita' la garantisce nginx, che la sovrascrive.
"""

from __future__ import annotations

import pytest

DA_PROXY = {"REMOTE_ADDR": "172.20.0.2"}   # l'indirizzo del container nginx
DA_RETE = {"REMOTE_ADDR": "10.20.10.9"}


def _sonda(tmp_path, monkeypatch, dietro_proxy: bool, database_di_prova: str):
    """Sonda con archivio temporaneo e SENZA password: lo stato di prima apertura."""
    import importlib

    from snapprobe import db as probe_db

    # L'archivio della sonda e' PostgreSQL: ogni prova ha il proprio database, come
    # quelle del server. Il motore e' unico per processo e va dimenticato fra una
    # prova e l'altra, altrimenti la seconda scriverebbe nel database della prima --
    # che intanto e' stato distrutto.
    monkeypatch.setenv("SNAP_PROBE_DATABASE_URL", database_di_prova)
    probe_db.azzera_motore()
    monkeypatch.setenv("SNAP_PROBE_SECRET_KEY", "test-secret-key")

    import snapprobe
    import snapprobe.settings as impostazioni

    importlib.reload(impostazioni)
    importlib.reload(snapprobe)

    class Configurazione(impostazioni.TestConfig):
        BEHIND_PROXY = dietro_proxy

    return snapprobe.create_app(Configurazione, start_agent=False)


def test_senza_proxy_l_intestazione_non_vale(tmp_path, monkeypatch, database_di_prova):
    """Predefinito prudente: chi arriva dalla rete non diventa "locale" dichiarandolo."""
    app = _sonda(tmp_path, monkeypatch, False, database_di_prova)
    risposta = app.test_client().get(
        "/primo-accesso",
        headers={"X-Forwarded-For": "127.0.0.1"},
        environ_base=DA_RETE)
    assert risposta.status_code == 403, (
        "senza BEHIND_PROXY l'intestazione va ignorata: la sonda non deve concedere"
        " la prima password a chi la dichiara")


def test_dietro_proxy_vale_l_indirizzo_scritto_dal_proxy(tmp_path, monkeypatch, database_di_prova):
    """Con il proxy davanti, l'indirizzo del client e' quello che il proxy dichiara:
    e' l'unico modo per far funzionare la prima apertura in container."""
    app = _sonda(tmp_path, monkeypatch, True, database_di_prova)
    cliente = app.test_client()

    dalla_postazione = cliente.get(
        "/primo-accesso",
        headers={"X-Forwarded-For": "127.0.0.1"},
        environ_base=DA_PROXY)
    assert dalla_postazione.status_code == 200, (
        "dalla postazione della sonda la pagina deve aprirsi anche dietro il proxy")

    dalla_rete = cliente.get(
        "/primo-accesso",
        headers={"X-Forwarded-For": "10.20.10.9"},
        environ_base=DA_PROXY)
    assert dalla_rete.status_code == 403, (
        "dalla rete resta rifiutata: la sonda appartiene a chi l'ha installata")


def test_il_server_dietro_proxy_si_sa_in_https(tmp_path, monkeypatch,
                                               database_di_prova):
    """Senza questo, l'applicazione si crederebbe in chiaro e costruirebbe
    collegamenti http:// dentro un sito servito in https."""
    import importlib

    monkeypatch.setenv("SNAP_SERVER_DATABASE_URL", database_di_prova)
    monkeypatch.setenv("SNAP_SERVER_SECRET_KEY", "test-secret-key")

    import snapserver
    import snapserver.settings as impostazioni

    importlib.reload(impostazioni)
    importlib.reload(snapserver)

    class Configurazione(impostazioni.TestConfig):
        BEHIND_PROXY = True

    app = snapserver.create_app(Configurazione)

    from flask import request

    @app.route("/_prova-schema")
    def _prova_schema():
        return "%s|%s" % (request.scheme, request.remote_addr)

    corpo = app.test_client().get(
        "/_prova-schema",
        headers={"X-Forwarded-Proto": "https", "X-Forwarded-For": "203.0.113.7"},
        environ_base=DA_PROXY).get_data(as_text=True)

    schema, indirizzo = corpo.split("|")
    assert schema == "https", "il server deve sapere di essere servito in https"
    assert indirizzo == "203.0.113.7", (
        "nel diario e nei blocchi per indirizzo deve finire il client, non il proxy")
