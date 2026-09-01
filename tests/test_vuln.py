"""
snap - Test della ricerca di vulnerabilita' con nmap e del legame con la Threat
Intelligence.

Alle passate di arricchimento si aggiunge una fase `vuln` che verifica con nmap i
difetti piu' gravi e diffusi, in **sola rilevazione** (mai sfruttamento). Cio' che
risulta vulnerabile diventa un riscontro di sicurezza accanto a quelli della
correlazione per versione, con origine `nmap`.

Le prove verificano: che la fase usi solo script di rilevazione (niente exploit/dos/
brute) e riguardi i soli nodi a rischio; che l'interpretazione estragga verdetto, CVE
e gravita'; che i difetti diventino riscontri confermati; che la correlazione per
versione NON chiuda i riscontri di nmap; e che un difetto sanato venga chiuso.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json

import pytest

from snapprobe.scanner import (DEFAULT_CADENCES, VULN_HOST_TIMEOUT, VULN_SCRIPTS,
                               STAGES, NetworkScanner, vuln_findings)
from test_scanner import EsecutoreFinto, leggi

PERIMETRO = [{"cidr": "192.0.2.0/24", "label": "Rete di prova"}]

HEARTBLEED = ("\n  VULNERABLE:\n  The Heartbleed Bug is a serious vulnerability\n"
              "    State: VULNERABLE\n    Risk factor: High\n    References:\n"
              "      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160")
MS17 = ("\n  VULNERABLE:\n  Remote Code Execution vulnerability in Microsoft SMBv1"
        " servers (ms17-010)\n    State: VULNERABLE\n    IDs:  CVE:CVE-2017-0143\n"
        "    Risk factor: HIGH")


@pytest.fixture()
def sonda(probe_store):
    probe_store.set_json("scan_subnets", PERIMETRO)
    return probe_store


def _nodo_a_rischio(store, ip="192.0.2.51", porta="tcp/443"):
    protocollo, numero = porta.split("/")
    porte = {porta: {"protocol": protocollo, "port": int(numero), "state": "open"}}
    store.upsert_local_node(ip, state="confirmed", stages_done="ports,services,os",
                            profile_json=json.dumps({"ip": ip, "ports_index": porte}))


# --------------------------------------------------------------------------- #
# La fase: sola rilevazione, sui soli nodi a rischio
# --------------------------------------------------------------------------- #
def test_la_fase_vuln_e_prevista_e_ha_una_cadenza():
    assert "vuln" in STAGES
    assert DEFAULT_CADENCES["vuln"] > 0


def test_gli_script_di_vulnerabilita_sono_di_sola_rilevazione():
    """Un inventario accerta, non attacca: niente exploit, dos o forzatura."""
    for proibito in ("exploit", "-dos", "dos-", "brute", "slowloris"):
        assert proibito not in VULN_SCRIPTS, proibito
    # I difetti coperti sono quelli attesi.
    assert "ssl-heartbleed" in VULN_SCRIPTS and "smb-vuln-ms17-010" in VULN_SCRIPTS


def test_la_fase_riguarda_solo_i_nodi_con_una_porta_a_rischio(sonda):
    _nodo_a_rischio(sonda, "192.0.2.51", "tcp/443")
    sonda.upsert_local_node("192.0.2.52", state="confirmed", stages_done="ports",
                            profile_json=json.dumps({"ip": "192.0.2.52", "ports_index": {
                                "tcp/22": {"protocol": "tcp", "port": 22,
                                           "state": "open"}}}))
    esecutore = EsecutoreFinto(leggi("nmap_vuln.xml"))
    NetworkScanner(sonda, esecutore).run_stage("vuln", "*")
    assert esecutore.chiamate[-1]["targets"] == ["192.0.2.51"]


def test_gli_argomenti_della_fase_vuln(sonda):
    _nodo_a_rischio(sonda)
    esecutore = EsecutoreFinto(leggi("nmap_vuln.xml"))
    NetworkScanner(sonda, esecutore).run_stage("vuln", "*")
    argomenti = esecutore.chiamate[-1]["arguments"]
    valore = argomenti[argomenti.index("--script") + 1]
    assert valore == VULN_SCRIPTS
    assert argomenti[argomenti.index("--host-timeout") + 1] == VULN_HOST_TIMEOUT


def test_la_fase_vuln_produce_un_record_conferibile(sonda):
    from snapprobe.agent import record_type_of

    _nodo_a_rischio(sonda)
    esecutore = EsecutoreFinto(leggi("nmap_vuln.xml"))
    esito = NetworkScanner(sonda, esecutore).run_stage("vuln", "*")
    assert "vuln" in esito["records"] and record_type_of("vuln") == "vuln"
    difetti = esito["records"]["vuln"][0]["findings"]
    script = {d["script"] for d in difetti}
    assert "ssl-heartbleed" in script and "smb-vuln-ms17-010" in script


# --------------------------------------------------------------------------- #
# Interpretazione
# --------------------------------------------------------------------------- #
def test_interpretazione_estrae_verdetto_cve_e_gravita():
    trovati = vuln_findings({"ssl-heartbleed": HEARTBLEED, "smb-vuln-ms17-010": MS17,
                             "ssl-poodle": "\n  NOT VULNERABLE", "http-title": "Casa"})
    assert len(trovati) == 2
    per = {t["script"]: t for t in trovati}
    assert per["ssl-heartbleed"]["cves"] == ["CVE-2014-0160"]
    assert per["ssl-heartbleed"]["severity"] == "high"
    assert per["ssl-heartbleed"]["state"] == "confirmed"
    assert per["smb-vuln-ms17-010"]["cves"] == ["CVE-2017-0143"]


def test_un_esito_non_vulnerabile_non_produce_riscontri():
    assert vuln_findings({"ssl-poodle": "\n  NOT VULNERABLE"}) == []
    assert vuln_findings({}) == []


def test_un_esito_likely_e_solo_probabile():
    likely = "\n  LIKELY VULNERABLE:\n    State: LIKELY VULNERABLE\n    Risk factor: Medium"
    r = vuln_findings({"ssl-dh-params": likely})
    assert r and r[0]["state"] == "likely" and r[0]["severity"] == "medium"


# --------------------------------------------------------------------------- #
# Legame con la Threat Intelligence (lato server)
# --------------------------------------------------------------------------- #
def _tenant_con_nodo(ip="192.0.2.51"):
    from snapserver.db import execute, utc_now_str

    adesso = utc_now_str()
    tenant_id = execute(
        "INSERT INTO tenants (code, name, timezone, locale, retention_days,"
        " is_active, created_at, updated_at) VALUES ('vuln','V','UTC','it',365,1,?,?)",
        (adesso, adesso))
    probe_id = execute(
        "INSERT INTO probes (tenant_id, probe_uid, code, name, status, created_at,"
        " updated_at) VALUES (?, 'uid-vuln', 'P1', 'sonda', 'active', ?, ?)",
        (tenant_id, adesso, adesso))
    subnet_id = execute(
        "INSERT INTO subnets (tenant_id, cidr, host_count, is_enabled, imported_at,"
        " created_at, updated_at) VALUES (?, '192.0.2.0/24', 254, 1, ?, ?, ?)",
        (tenant_id, adesso, adesso, adesso))
    node_id = execute(
        "INSERT INTO nodes (tenant_id, subnet_id, probe_id, ip, status, first_seen_at,"
        " last_seen_at, created_at, updated_at) VALUES (?, ?, ?, ?, 'up', ?, ?, ?, ?)",
        (tenant_id, subnet_id, probe_id, ip, adesso, adesso, adesso, adesso))
    return tenant_id, probe_id, node_id


def _conferisci_vuln(tenant_id, probe_id, ip="192.0.2.51", findings=None, uid="lv"):
    from snapserver.ingest import apply_batch

    findings = findings if findings is not None else [
        {"script": "ssl-heartbleed", "state": "confirmed", "title": "Heartbleed",
         "cves": ["CVE-2014-0160"], "severity": "high"},
        {"script": "smb-vuln-ms17-010", "state": "confirmed", "title": "EternalBlue",
         "cves": ["CVE-2017-0143"], "severity": "high"}]
    return apply_batch(tenant_id, probe_id, {
        "batch_uid": uid, "records": {"vuln": [{"ip": ip, "findings": findings}]}})


def test_i_difetti_diventano_riscontri_confermati(server_app):
    from snapserver.db import query

    with server_app.app_context():
        tenant_id, probe_id, node_id = _tenant_con_nodo()
        esito = _conferisci_vuln(tenant_id, probe_id)
        assert esito["accepted"]

        righe = query("SELECT kind, source, severity, title, cve_id, evidence"
                      " FROM ti_findings WHERE tenant_id = ? AND node_id = ?",
                      (tenant_id, node_id))
        assert len(righe) == 2
        for r in righe:
            assert r["kind"] == "confirmed"
            assert r["source"] == "nmap"
            assert "nmap" in r["evidence"].lower()


def test_la_correlazione_per_versione_non_chiude_i_riscontri_di_nmap(server_app):
    """La riconciliazione della correlazione tocca solo i propri riscontri: quelli
    verificati da nmap hanno un ciclo di vita a se'."""
    from snapserver.db import query
    from snapserver.threat import correlate

    with server_app.app_context():
        tenant_id, probe_id, node_id = _tenant_con_nodo()
        _conferisci_vuln(tenant_id, probe_id)
        correlate(tenant_id)  # nessuna osservazione di versione: chiuderebbe tutto

        aperti = query("SELECT COUNT(*) AS n FROM ti_findings WHERE tenant_id = ?"
                       " AND source = 'nmap' AND status = 'open'",
                       (tenant_id,), one=True)
        assert int(aperti["n"]) == 2, "i riscontri di nmap non vanno chiusi"


def test_un_difetto_sanato_viene_chiuso_alla_verifica_successiva(server_app):
    from snapserver.db import query

    with server_app.app_context():
        tenant_id, probe_id, node_id = _tenant_con_nodo()
        _conferisci_vuln(tenant_id, probe_id, uid="lv1")
        # Seconda verifica: Heartbleed sanato, resta solo EternalBlue.
        _conferisci_vuln(tenant_id, probe_id, uid="lv2", findings=[
            {"script": "smb-vuln-ms17-010", "state": "confirmed", "title": "EternalBlue",
             "cves": ["CVE-2017-0143"], "severity": "high"}])

        stati = {r["title"]: r["status"] for r in query(
            "SELECT title, status FROM ti_findings WHERE tenant_id = ?", (tenant_id,))}
        eternal = [s for tit, s in stati.items() if "CVE-2017-0143" in tit or "EternalBlue" in tit]
        heart = [s for tit, s in stati.items() if "CVE-2014-0160" in tit or "Heartbleed" in tit]
        assert eternal and eternal[0] == "open"
        assert heart and heart[0] == "fixed", "il difetto sanato va chiuso"


def test_una_cve_non_catalogata_resta_nel_titolo(server_app):
    """Se la CVE non e' nel catalogo locale non si lega (il vincolo la rifiuterebbe),
    ma resta leggibile nel titolo."""
    from snapserver.db import query

    with server_app.app_context():
        tenant_id, probe_id, node_id = _tenant_con_nodo()
        _conferisci_vuln(tenant_id, probe_id, findings=[
            {"script": "ssl-heartbleed", "state": "confirmed", "title": "Heartbleed",
             "cves": ["CVE-2099-9999"], "severity": "high"}])
        r = query("SELECT cve_id, title FROM ti_findings WHERE tenant_id = ?",
                  (tenant_id,), one=True)
        assert r["cve_id"] is None
        assert "CVE-2099-9999" in r["title"]
