"""
snap - Test della tenuta della sessione durante la navigazione.

La sessione e' custodita in un cookie firmato. Ogni risposta che tocca la
sessione ne provoca il reinvio: poiche' una pagina carica diversi file statici
in parallelo, una risposta tardiva puo' sovrascrivere lo stato piu' recente e
far cadere la sessione. I test seguenti fissano il comportamento che impedisce
questa condizione.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest

PAGINE = [
    "/",
    "/probes/",
    "/probes/new",
    "/audit/",
    "/admin/tenants",
    "/admin/users",
    "/admin/settings",
    "/profile",
]

STATICI = [
    "/static/css/snap.css",
    "/static/js/snap.js",
    "/static/js/snap-tables.js",
    "/static/js/snap-dialogs.js",
    "/static/vendor/bootstrap/bootstrap.min.css",
    "/static/vendor/adminlte/adminlte.min.css",
    "/static/vendor/awn/style.css",
    "/static/vendor/datatables/dataTables.min.js",
]


@pytest.fixture()
def admin_client(server_app):
    client = server_app.test_client()
    risposta = client.post(
        "/login",
        data={
            "email": server_app.config["BOOTSTRAP_ADMIN_EMAIL"],
            "password": server_app.config["BOOTSTRAP_ADMIN_PASSWORD"],
        },
        follow_redirects=True,
    )
    assert risposta.status_code == 200
    return client


def _cookie_di_sessione(risposta, nome: str = None) -> str | None:
    """Restituisce l'intestazione Set-Cookie della sessione, se presente.

    Il nome del cookie e' configurabile (server e sonda ne usano uno diverso):
    si accetta il nome effettivo, con il predefinito di Flask come ricaduta.
    """
    attesi = (nome,) if nome else ("snap_server_session", "session")
    for intestazione, valore in risposta.headers.items():
        if intestazione.lower() != "set-cookie":
            continue
        if any(valore.startswith(atteso + "=") for atteso in attesi):
            return valore
    return None


# --------------------------------------------------------------------------- #
# Il cookie non deve essere riscritto senza motivo
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("risorsa", STATICI)
def test_i_file_statici_non_riscrivono_la_sessione(admin_client, risorsa):
    """Una pagina ne carica molti in parallelo: non devono toccare la sessione."""
    risposta = admin_client.get(risorsa)
    assert risposta.status_code == 200
    nome = admin_client.application.config["SESSION_COOKIE_NAME"]
    assert _cookie_di_sessione(risposta, nome) is None, (
        "%s riscrive il cookie di sessione" % risorsa
    )


@pytest.mark.parametrize("percorso", PAGINE)
def test_le_pagine_non_riscrivono_una_sessione_invariata(admin_client, percorso):
    """La sola consultazione non modifica la sessione: nessun nuovo cookie."""
    assert admin_client.get(percorso).status_code == 200  # primo accesso: contesto risolto
    risposta = admin_client.get(percorso)
    nome = admin_client.application.config["SESSION_COOKIE_NAME"]
    assert _cookie_di_sessione(risposta, nome) is None, (
        "%s riscrive il cookie pur non modificando la sessione" % percorso
    )


def test_il_cookie_viene_emesso_quando_la_sessione_cambia(server_app):
    """All'accesso e al cambio di tenant il cookie deve essere aggiornato."""
    client = server_app.test_client()
    accesso = client.post(
        "/login",
        data={
            "email": server_app.config["BOOTSTRAP_ADMIN_EMAIL"],
            "password": server_app.config["BOOTSTRAP_ADMIN_PASSWORD"],
        },
    )
    nome = server_app.config["SESSION_COOKIE_NAME"]
    assert _cookie_di_sessione(accesso, nome) is not None, "l'accesso deve emettere il cookie"

    with server_app.app_context():
        from snapserver.db import query

        altro = query("SELECT id FROM tenants ORDER BY id DESC", (), one=True)

    cambio = client.post("/switch-tenant", data={"tenant_id": int(altro["id"])})
    assert _cookie_di_sessione(cambio, nome) is not None, "il cambio tenant deve emettere il cookie"


# --------------------------------------------------------------------------- #
# Tenuta della sessione
# --------------------------------------------------------------------------- #
def test_la_sessione_regge_la_navigazione_ripetuta(admin_client):
    """Tre giri su tutte le pagine, con i file statici a ogni giro."""
    for _ in range(3):
        for percorso in PAGINE:
            risposta = admin_client.get(percorso, follow_redirects=False)
            assert risposta.status_code == 200, (
                "sessione persa su %s (risposta %s)" % (percorso, risposta.status_code)
            )
        for risorsa in STATICI:
            admin_client.get(risorsa)


def test_il_modulo_resta_valido_dopo_la_navigazione(admin_client):
    """Il token di sicurezza di una pagina deve funzionare dopo altre richieste."""
    import re

    server_app = admin_client.application
    server_app.config["WTF_CSRF_ENABLED"] = True
    try:
        pagina = admin_client.get("/admin/tenants").data.decode("utf-8")
        token = re.search(r'name="csrf_token" value="([^"]+)"', pagina).group(1)

        for percorso in PAGINE:
            admin_client.get(percorso)
        for risorsa in STATICI:
            admin_client.get(risorsa)

        with server_app.app_context():
            from snapserver.db import query

            tenant = query("SELECT id FROM tenants ORDER BY id", (), one=True)

        risposta = admin_client.post(
            "/switch-tenant",
            data={"csrf_token": token, "tenant_id": int(tenant["id"])},
            follow_redirects=False,
        )
        assert risposta.status_code == 302, (
            "il modulo e' stato rifiutato dopo la navigazione (risposta %s)"
            % risposta.status_code
        )
    finally:
        server_app.config["WTF_CSRF_ENABLED"] = False


def test_la_diagnostica_dichiara_lo_stato_della_sessione(admin_client):
    esito = admin_client.get("/diagnostics/session").get_json()
    assert esito["cookie_ricevuto"] is True
    assert esito["sessione_con_utente"] is True
    assert esito["secondo_fattore_superato"] is True
    assert esito["durata_sessione_minuti"] > 0


# --------------------------------------------------------------------------- #
# Convivenza delle due interfacce sullo stesso host
# --------------------------------------------------------------------------- #
def test_i_due_applicativi_usano_cookie_con_nomi_distinti():
    """I cookie non distinguono la porta: nomi uguali si sovrascrivono a vicenda.

    Server e sonda convivono su 127.0.0.1 con porte diverse. Con il nome
    predefinito di Flask ("session") la visita a una delle due interfacce
    invaliderebbe la sessione dell'altra.
    """
    import importlib

    import snapprobe.settings as impostazioni_sonda
    import snapserver.settings as impostazioni_server

    importlib.reload(impostazioni_server)
    importlib.reload(impostazioni_sonda)

    nome_server = impostazioni_server.Config.SESSION_COOKIE_NAME
    nome_sonda = impostazioni_sonda.Config.SESSION_COOKIE_NAME

    assert nome_server != "session", "il server usa ancora il nome predefinito"
    assert nome_sonda != "session", "la sonda usa ancora il nome predefinito"
    assert nome_server != nome_sonda, (
        "server e sonda condividono il nome del cookie (%s)" % nome_server
    )


def test_il_cookie_emesso_porta_il_nome_configurato(server_app):
    client = server_app.test_client()
    risposta = client.post(
        "/login",
        data={
            "email": server_app.config["BOOTSTRAP_ADMIN_EMAIL"],
            "password": server_app.config["BOOTSTRAP_ADMIN_PASSWORD"],
        },
    )
    atteso = server_app.config["SESSION_COOKIE_NAME"]
    intestazioni = [v for k, v in risposta.headers.items() if k.lower() == "set-cookie"]
    assert any(v.startswith(atteso + "=") for v in intestazioni), (
        "il cookie emesso non porta il nome %s: %s" % (atteso, intestazioni)
    )


def test_un_cookie_della_sonda_non_invalida_la_sessione_del_server(server_app, admin_client):
    """La presenza del cookie della sonda non deve disturbare il server."""
    import snapprobe.settings as impostazioni_sonda

    # Si simula il contenitore di cookie del browser, che tiene entrambi.
    admin_client.set_cookie(
        impostazioni_sonda.Config.SESSION_COOKIE_NAME,
        "valore-firmato-da-un-altro-applicativo",
        domain="localhost",
    )

    for percorso in PAGINE:
        risposta = admin_client.get(percorso, follow_redirects=False)
        assert risposta.status_code == 200, (
            "il cookie della sonda ha invalidato la sessione su %s" % percorso
        )


def test_la_diagnostica_dichiara_il_nome_del_cookie(admin_client, server_app):
    esito = admin_client.get("/diagnostics/session").get_json()
    assert esito["nome_cookie"] == server_app.config["SESSION_COOKIE_NAME"]
