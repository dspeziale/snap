"""
snap - Test del modulo SIEM: riconoscimento dei log, ingestione, rilevazione e
correlazione con la threat intelligence.

remarks: Autore: Daniele Speziale - Data: 2026-09-02
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest


# --------------------------------------------------------------------------- #
# Riconoscimento dei log (parser): senza database, sono funzioni pure
# --------------------------------------------------------------------------- #
def test_riconosce_un_accesso_ssh_fallito():
    from snapserver.siem import parsers

    riga = "<38>Sep  2 10:11:00 srv1 sshd[111]: Failed password for root from 10.1.2.3 port 2200 ssh2"
    e = parsers.classify(riga, "linux")
    assert e["event_kind"] == "auth_failure"
    assert e["username"] == "root"
    assert e["src_ip"] == "10.1.2.3"


def test_riconosce_un_logon_windows_fallito():
    from snapserver.siem import parsers

    riga = '<13>1 2026-09-02T10:00:00Z host - - - - EventID=4625 TargetUserName=mrossi IpAddress=10.4.5.6'
    e = parsers.classify(riga, "windows")
    assert e["event_kind"] == "auth_failure"
    assert e["username"] == "mrossi"
    assert e["src_ip"] == "10.4.5.6"


def test_riconosce_una_connessione_negata_cisco_asa():
    from snapserver.siem import parsers

    riga = "<134>Sep  2 10:00:00 asa1 %ASA-4-106023: Deny tcp src outside:1.2.3.4/44 dst inside:10.0.0.1/22"
    e = parsers.classify(riga, "firewall")
    assert e["event_kind"] == "conn_denied"


def test_riconosce_una_modifica_di_configurazione_di_rete():
    from snapserver.siem import parsers

    riga = "<189>Sep  2 10:00:00 sw1 %SYS-5-CONFIG_I: Configured from console by admin on vty0"
    e = parsers.classify(riga, "network")
    assert e["event_kind"] == "config_change"
    assert e["username"] == "admin"


def test_un_log_non_riconosciuto_resta_conservato_come_altro():
    from snapserver.siem import parsers

    e = parsers.classify("<14>Sep  2 10:00:00 host qualcosa di non previsto", "")
    assert e["event_kind"] == "other"
    assert "non previsto" in e["message"]


# --------------------------------------------------------------------------- #
# Ingestione e attribuzione (con database)
# --------------------------------------------------------------------------- #
def _tenant_id(server_app) -> int:
    with server_app.app_context():
        from snapserver.db import query

        return int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])


def test_l_ingestione_scrive_e_attribuisce_alla_sorgente(server_app):
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver.siem import data, ingest, store

        _cid, token = data.create_collector(tenant_id, "test")
        collettore = data.collector_by_token(token)
        data.create_source(tenant_id, "FW", "firewall", match_ip="10.9.9.9")

        righe = ["<38>Sep  2 10:%02d:00 fw sshd[1]: Failed password for a from 10.9.9.9 port 1 ssh2"
                 % (10 + i) for i in range(5)]
        esito = ingest.ingest_batch(collettore, righe)
        assert esito["scritti"] == 5
        assert esito["attribuiti"] == 5
        eventi = store.search(tenant_id, src_ip="10.9.9.9")
    assert len(eventi) == 5
    assert all(e["event_kind"] == "auth_failure" for e in eventi)


def test_un_token_sbagliato_non_da_accesso(server_app):
    with server_app.app_context():
        from snapserver.siem import data

        assert data.collector_by_token("non-esiste") is None


# --------------------------------------------------------------------------- #
# Rilevazione e deduplicazione
# --------------------------------------------------------------------------- #
def _prepara_bruteforce(server_app, ip="10.7.7.7", quanti=15):
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver.siem import data, ingest

        _cid, token = data.create_collector(tenant_id, "c")
        collettore = data.collector_by_token(token)
        data.create_source(tenant_id, "S", "linux", match_ip=ip)
        righe = ["<38>Sep  2 10:%02d:00 h sshd[1]: Failed password for root from %s port 1 ssh2"
                 % (10 + i, ip) for i in range(quanti)]
        ingest.ingest_batch(collettore, righe)
    return tenant_id


def test_una_soglia_superata_apre_un_allarme(server_app):
    tenant_id = _prepara_bruteforce(server_app)
    with server_app.app_context():
        from snapserver.siem import data, detect

        detect.run_once()
        allarmi = data.alerts(tenant_id)
    codici = {a["rule_code"] for a in allarmi}
    assert "bruteforce_ip" in codici, "15 accessi falliti dallo stesso IP devono aprire un allarme"


def test_un_attacco_che_continua_aggiorna_l_allarme_non_lo_duplica(server_app):
    tenant_id = _prepara_bruteforce(server_app)
    with server_app.app_context():
        from snapserver.siem import data, detect

        detect.run_once()
        detect.run_once()  # secondo giro: stesso attacco
        allarmi = [a for a in data.alerts(tenant_id) if a["rule_code"] == "bruteforce_ip"]
    assert len(allarmi) == 1, "un attacco in corso e' un allarme che si aggiorna, non due"


# --------------------------------------------------------------------------- #
# Correlazione con la threat intelligence
# --------------------------------------------------------------------------- #
def test_un_allarme_su_un_nodo_esposto_sale_di_gravita(server_app):
    """Il punto del SIEM: un attacco verso una macchina gia' esposta pesa di piu'.
    La regola 'bruteforce_ip' e' 'high'; con un riscontro aperto sul nodo diventa
    'critical', e l'allarme cita la correlazione."""
    ip = "10.8.8.8"
    tenant_id = _prepara_bruteforce(server_app, ip=ip)
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str
        from snapserver.siem import data, detect

        now = utc_now_str()
        node_id = execute(
            "INSERT INTO nodes (tenant_id, ip, status, first_seen_at, last_seen_at,"
            " created_at, updated_at) VALUES (?, ?, 'up', ?, ?, ?, ?)",
            (tenant_id, ip, now, now, now, now))
        execute(
            "INSERT INTO ti_findings (tenant_id, node_id, kind, severity, title,"
            " evidence, first_seen_at, last_seen_at, status)"
            " VALUES (?, ?, 'confirmed', 'high', 'CVE sfruttabile', 'x', ?, ?, 'open')",
            (tenant_id, node_id, now, now))

        detect.run_once()
        allarme = [a for a in data.alerts(tenant_id) if a["rule_code"] == "bruteforce_ip"][0]
    assert allarme["severity"] == "critical", "la gravita' sale di un grado sul nodo esposto"
    assert allarme["node_id"] == node_id, "l'allarme e' legato al nodo dell'inventario"
    assert allarme["ti_refs_json"] and allarme["ti_refs_json"] not in ("null", "[]"), (
        "l'allarme cita i riscontri di threat intelligence")


def test_un_allarme_su_un_nodo_sano_resta_alla_gravita_della_regola(server_app):
    tenant_id = _prepara_bruteforce(server_app, ip="10.6.6.6")
    with server_app.app_context():
        from snapserver.siem import data, detect

        detect.run_once()
        allarme = [a for a in data.alerts(tenant_id) if a["rule_code"] == "bruteforce_ip"][0]
    assert allarme["severity"] == "high", "senza esposizione la gravita' resta quella della regola"


# --------------------------------------------------------------------------- #
# API di ingestione e pagine
# --------------------------------------------------------------------------- #
def test_l_api_di_ingestione_rifiuta_senza_token(server_app):
    client = server_app.test_client()
    r = client.post("/api/siem/ingest", json={"events": ["x"]})
    assert r.status_code == 401


def test_l_api_di_ingestione_accetta_con_token(server_app):
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver.siem import data

        _cid, token = data.create_collector(tenant_id, "api")
    client = server_app.test_client()
    r = client.post("/api/siem/ingest",
                    json={"events": ["<14>Sep  2 10:00:00 h app: prova"]},
                    headers={"Authorization": "Bearer %s" % token})
    assert r.status_code == 200
    assert r.get_json()["scritti"] == 1


@pytest.fixture()
def admin_client(server_app):
    client = server_app.test_client()
    client.post("/login", data={
        "email": server_app.config["BOOTSTRAP_ADMIN_EMAIL"],
        "password": server_app.config["BOOTSTRAP_ADMIN_PASSWORD"],
    }, follow_redirects=True)
    return client


@pytest.mark.parametrize("scheda", ["quadro", "sorgenti", "eventi", "regole", "allarmi"])
def test_le_schede_del_siem_si_aprono(admin_client, scheda):
    r = admin_client.get("/siem/?scheda=%s" % scheda)
    assert r.status_code == 200


def test_il_menu_mostra_la_voce_siem(admin_client):
    corpo = admin_client.get("/", follow_redirects=True).get_data(as_text=True)
    assert 'data-snap-gruppo="siem"' in corpo
    assert "/siem/?scheda=quadro" in corpo or "scheda=quadro" in corpo
