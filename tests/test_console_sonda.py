"""
snap - Test della console della sonda vista dal server.

PERCHE' ESISTE
La sonda vive nella rete del cliente e apre lei la comunicazione, ogni quindici
secondi: il server NON puo' raggiungerla -- c'e' un NAT, e in mezzo un firewall che
non lascia entrare niente. Una console remota, quindi, non puo' essere un
collegamento: e' un rispecchiamento. Lo stato arriva con il battito e il server mostra
l'ultima istantanea consegnata.

Le proprieta' che questi test fissano sono quelle da cui dipende l'onesta' della
pagina: l'istantanea si conserva solo se e' leggibile e di misura ragionevole, la
pagina dichiara SEMPRE di quando e' il dato che mostra, e una sonda che non manda
l'istantanea non risulta guasta -- resta una sonda senza console.

remarks: Autore: Daniele Speziale - Data: 2026-09-10
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json

import pytest


# --------------------------------------------------------------------------- #
# L'istantanea composta dalla sonda
# --------------------------------------------------------------------------- #
def _agente(probe_store):
    from snapprobe.agent import ProbeAgent

    return ProbeAgent(probe_store, "1.4.0")


def test_l_istantanea_porta_cio_che_si_vede_sulla_sonda(probe_store):
    """Non un sottoinsieme arbitrario: le stesse cose che si leggono aprendo
    l'interfaccia locale, che e' il senso di una console remota."""
    probe_store.set_json("scan_subnets", [{"cidr": "192.0.2.0/24", "wifi": True}])
    probe_store.log("info", "prova di diario")

    istantanea = _agente(probe_store).console_snapshot()

    assert istantanea["at"], "l'istante e' obbligatorio: dice di quando e' il dato"
    assert "agent" in istantanea and "scan" in istantanea
    assert istantanea["agent"]["queue_size"] == 0
    assert "presence" in istantanea["agent"], "la ricognizione delle presenze"
    assert istantanea["scan"]["effort"], "il profilo di sforzo in vigore"
    assert any(r["message"] == "prova di diario" for r in istantanea["diary"])


def test_l_istantanea_non_porta_lo_stato_di_tutte_le_fasi(probe_store):
    """Con centinaia di subnet lo stato delle fasi e' migliaia di righe: nel battito,
    che parte ogni quindici secondi, non ci sta. Si manda il conteggio e le ultime."""
    for indice in range(60):
        probe_store.record_scan("10.%d.0.0/24" % indice, "discovery", "completed", "ok")

    istantanea = _agente(probe_store).console_snapshot()

    assert "states" not in istantanea["scan"], "l'elenco completo non viaggia"
    assert istantanea["scan"]["states_count"] == 60, "il conteggio si'"
    assert len(istantanea["scan"]["states_recent"]) <= 20


def test_il_perimetro_non_torna_indietro(probe_store):
    """Lo ha mandato il server: rimandarglielo e' traffico a vuoto, ed era 30 dei 37
    kilobyte della prima istantanea con 380 subnet dichiarate."""
    probe_store.set_json("scan_subnets", [{"cidr": "10.%d.0.0/24" % i}
                                          for i in range(200)])

    istantanea = _agente(probe_store).console_snapshot()

    assert "perimeter" not in istantanea["scan"]
    assert istantanea["scan"]["perimeter_count"] == 200, "il conteggio resta"
    assert len(istantanea["scan"]["perimeter_head"]) == 12, "e le prime, per riconoscerlo"


def test_l_istantanea_sta_in_pochi_kilobyte(probe_store):
    """Il tetto non e' prudenza generica: una busta che cresce con l'archivio locale
    finirebbe per costare piu' del conferimento dei dati veri."""
    for indice in range(300):
        probe_store.log("info", "riga di diario numero %d" % indice)
        probe_store.record_scan("10.%d.0.0/24" % indice, "ports", "completed", "x" * 300)

    testo = json.dumps(_agente(probe_store).console_snapshot(), ensure_ascii=False)

    assert len(testo) < 64 * 1024, "istantanea di %d byte" % len(testo)


def test_l_istantanea_non_contiene_segreti(probe_store):
    """Viaggia in una busta cifrata verso il server, ma il principio resta: cio' che
    non serve alla console non parte. Nessuna chiave, nessun token, nessuna
    community SNMP."""
    probe_store.set_setting("enroll_token", "SNAP1-TOKEN-SEGRETO")
    probe_store.set_setting("snmp_community", "community-segreta")
    probe_store.set_setting("session_key", "chiave-di-sessione")

    testo = json.dumps(_agente(probe_store).console_snapshot(), ensure_ascii=False)

    for segreto in ("SNAP1-TOKEN-SEGRETO", "community-segreta", "chiave-di-sessione"):
        assert segreto not in testo, "l'istantanea non deve contenere %s" % segreto


# --------------------------------------------------------------------------- #
# La conservazione sul server
# --------------------------------------------------------------------------- #
def _sonda(server_app):
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        tenant_id = int(query("SELECT id FROM tenants ORDER BY name", (), one=True)["id"])
        adesso = utc_now_str()
        riga = query("SELECT id FROM probes WHERE tenant_id = ?", (tenant_id,), one=True)
        if riga is not None:
            return tenant_id, int(riga["id"])
        probe_id = int(execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status,"
            " agent_version, last_seen_at, created_at, updated_at)"
            " VALUES (?, 'uid-console', 'sonda-console', 'Sonda console', 'active',"
            " '1.4.0', ?, ?, ?)", (tenant_id, adesso, adesso, adesso)))
        return tenant_id, probe_id


def _memorizza(server_app, probe_id, console):
    with server_app.app_context():
        from snapserver.blueprints.api_probe import _store_console
        from snapserver.db import query

        probe = query("SELECT * FROM probes WHERE id = ?", (probe_id,), one=True)
        _store_console(probe, console)
        return query("SELECT console_json, console_at FROM probes WHERE id = ?",
                     (probe_id,), one=True)


def test_l_istantanea_si_conserva_con_il_proprio_istante(server_app):
    _tenant, probe_id = _sonda(server_app)

    riga = _memorizza(server_app, probe_id, {
        "at": "2026-09-10 12:00:00", "agent": {"queue_size": 3}, "scan": {},
        "diary": [], "syncs": []})

    assert riga["console_at"] == "2026-09-10 12:00:00"
    assert json.loads(riga["console_json"])["agent"]["queue_size"] == 3


def test_un_battito_senza_istantanea_non_cancella_quella_precedente(server_app):
    """Una sonda di versione precedente non manda il campo: non deve per questo far
    sparire l'ultimo stato noto, ne' risultare guasta."""
    _tenant, probe_id = _sonda(server_app)
    _memorizza(server_app, probe_id, {"at": "2026-09-10 12:00:00", "agent": {},
                                      "scan": {}, "diary": [], "syncs": []})

    riga = _memorizza(server_app, probe_id, None)

    assert riga["console_json"] is not None
    assert riga["console_at"] == "2026-09-10 12:00:00"


@pytest.mark.parametrize("non_valida", [None, "", [], "una stringa", 42, {}])
def test_un_istantanea_non_valida_viene_ignorata(server_app, non_valida):
    _tenant, probe_id = _sonda(server_app)

    riga = _memorizza(server_app, probe_id, non_valida)

    assert riga["console_json"] is None


def test_un_istantanea_troppo_grande_viene_rifiutata(server_app):
    """Meglio mostrare l'istantanea precedente col proprio istante che conservarne una
    che arriva ogni quindici secondi e pesa come un archivio."""
    _tenant, probe_id = _sonda(server_app)
    from snapserver.blueprints.api_probe import MAX_CONSOLE_JSON

    riga = _memorizza(server_app, probe_id, {
        "at": "2026-09-10 12:00:00",
        "diary": [{"at": "2026-09-10 12:00:00", "level": "info",
                   "message": "x" * 1000}] * (MAX_CONSOLE_JSON // 1000 + 10)})

    assert riga["console_json"] is None


def test_un_istante_inventato_non_viene_creduto(server_app):
    """L'istante lo dichiara la sonda: se non e' nella forma dell'archivio si usa
    quello del server, altrimenti la pagina direbbe una data qualunque."""
    _tenant, probe_id = _sonda(server_app)

    riga = _memorizza(server_app, probe_id, {"at": "domani mattina", "agent": {}})

    assert riga["console_at"] != "domani mattina"
    assert len(riga["console_at"]) == 19


# --------------------------------------------------------------------------- #
# La pagina
# --------------------------------------------------------------------------- #
def test_la_console_mostra_lo_stato_e_il_suo_istante(server_app, logged_client):
    _tenant, probe_id = _sonda(server_app)
    _memorizza(server_app, probe_id, {
        "at": "2026-09-10 12:00:00",
        "agent": {"queue_size": 7, "enrolled": True, "last_error": "",
                  "presence": {"subnets_wifi": ["10.10.60.0/24"], "interval_sec": 120,
                               "seen": 256, "new": 0, "priority_queue": 0,
                               "at": "2026-09-10 11:59:00"}},
        # Le chiavi sono quelle vere di scanner.status(): un preparatore che ne
        # inventa di proprie proverebbe un template che nessuna sonda alimenta.
        "scan": {"effort": "max", "effort_label": "massimo", "workers": 32,
                 "max_workers": 32, "nodes_confirmed": 600, "nodes_candidate": 16,
                 "perimeter_count": 380, "capabilities": {"nmap_version": "7.95",
                                                          "raw_sockets": True},
                 "scanning_allowed": True, "host_timeout": "120s",
                 "discovery_days": 3.0,
                 "states_recent": [], "phases_in_flight": ["ports"]},
        "diary": [{"at": "2026-09-10 11:58:00", "level": "warning",
                   "message": "una riga del diario locale"}],
        "syncs": [],
    })

    testo = logged_client.get("/probes/%d/console" % probe_id).get_data(as_text=True)

    assert "una riga del diario locale" in testo, (
        "il diario locale e' la parte che finora si leggeva SOLO in sede")
    assert "10.10.60.0/24" in testo
    assert "616" in testo, "600 confermati + 16 candidati"
    assert "380" in testo, "il perimetro ricevuto"
    assert "7.95" in testo, "la versione di nmap sulla sonda"
    assert "10/09/2026" in testo, "l'istante dell'istantanea si dichiara"


def test_una_console_vecchia_lo_dice(server_app, logged_client):
    """Una fotografia presentata come diretta e' una bugia: se il battito non arriva,
    la pagina deve dire che quello e' l'ultimo stato noto."""
    _tenant, probe_id = _sonda(server_app)
    _memorizza(server_app, probe_id, {
        "at": "2020-01-01 00:00:00", "agent": {"queue_size": 0},
        "scan": {"scanning_allowed": True, "states_recent": []},
        "diary": [], "syncs": []})

    testo = logged_client.get("/probes/%d/console" % probe_id).get_data(as_text=True)

    # Si verifica il SEGNO, non la frase: una prosa cercata alla lettera si rompe al
    # primo ritorno a capo e non dice niente sul comportamento.
    assert "non quello attuale" in testo
    assert "text-bg-warning" in testo, "l'istante si presenta come un avviso"


def test_una_console_fresca_non_avvisa(server_app, logged_client):
    """Il contrario del test precedente: senza questo, una pagina che avvisa SEMPRE
    passerebbe la prova e l'avviso non significherebbe niente."""
    from snapserver.db import utc_now_str

    _tenant, probe_id = _sonda(server_app)
    with server_app.app_context():
        adesso = utc_now_str()
    _memorizza(server_app, probe_id, {
        "at": adesso, "agent": {"queue_size": 0},
        "scan": {"scanning_allowed": True, "states_recent": []},
        "diary": [], "syncs": []})

    testo = logged_client.get("/probes/%d/console" % probe_id).get_data(as_text=True)

    assert "non quello attuale" not in testo


def test_senza_istantanea_la_console_spiega_perche(server_app, logged_client):
    """Una pagina vuota fa pensare a un guasto: qui si dice che l'istantanea arriva
    col battito e quale versione della sonda la manda."""
    _tenant, probe_id = _sonda(server_app)

    testo = logged_client.get("/probes/%d/console" % probe_id).get_data(as_text=True)

    assert "Nessuno stato ricevuto" in testo
    assert "1.4.0" in testo


def test_la_console_di_una_sonda_di_un_altro_tenant_non_si_apre(server_app,
                                                                logged_client):
    """L'isolamento vale anche qui: la console e' una pagina di sola lettura, ma
    quello che mostra e' l'interno della rete di un cliente."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        adesso = utc_now_str()
        altro = int(execute(
            "INSERT INTO tenants (code, name, timezone, is_active, created_at,"
            " updated_at) VALUES ('zzz-altro', 'Altro Cliente', 'Europe/Rome', 1, ?, ?)",
            (adesso, adesso)))
        estranea = int(execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, created_at,"
            " updated_at) VALUES (?, 'uid-estranea', 'estranea', 'Estranea', 'active',"
            " ?, ?)", (altro, adesso, adesso)))

    risposta = logged_client.get("/probes/%d/console" % estranea)

    assert risposta.status_code == 404


def test_un_istantanea_illeggibile_non_rompe_la_pagina(server_app, logged_client):
    """Una pagina di sola lettura non deve rispondere 500 per un dato corrotto."""
    _tenant, probe_id = _sonda(server_app)
    with server_app.app_context():
        from snapserver.db import execute

        execute("UPDATE probes SET console_json = ?, console_at = ? WHERE id = ?",
                ("{non e' json", "2026-09-10 12:00:00", probe_id))

    risposta = logged_client.get("/probes/%d/console" % probe_id)

    assert risposta.status_code == 200
    assert "Nessuno stato ricevuto" in risposta.get_data(as_text=True)


def test_dall_elenco_delle_sonde_si_arriva_alla_console(server_app, logged_client):
    _tenant, probe_id = _sonda(server_app)

    testo = logged_client.get("/probes/").get_data(as_text=True)

    assert "/probes/%d/console" % probe_id in testo
