"""
snap - Threat Intelligence: catalogo locale, correlazione, riscontri.

Le prove insistono sulla cosa che rende utilizzabile una correlazione di vulnerabilita':
**non affermare cio' che non si puo' dimostrare**. Un elenco di CVE prodotto per nome di
prodotto, senza versione, sarebbe lungo, spaventoso e falso; qui la classe del riscontro
lo dichiara sempre, e una versione fuori intervallo non produce nulla.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json

import pytest


# --------------------------------------------------------------------------- #
# Preparazione
# --------------------------------------------------------------------------- #
def _tenant_id(server_app):
    with server_app.app_context():
        from snapserver.db import query

        return int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])


def _nodo(server_app, tenant_id, ip="10.9.0.5", os_name=None):
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        adesso = utc_now_str()
        subnet = query("SELECT id FROM subnets WHERE tenant_id = ?", (tenant_id,),
                       one=True)
        subnet_id = int(subnet["id"]) if subnet else execute(
            "INSERT INTO subnets (tenant_id, cidr, host_count, is_enabled, imported_at,"
            " created_at, updated_at) VALUES (?, '10.9.0.0/24', 254, 1, ?, ?, ?)",
            (tenant_id, adesso, adesso, adesso))
        return execute(
            "INSERT INTO nodes (tenant_id, subnet_id, ip, status, os_name, first_seen_at,"
            " last_seen_at, created_at, updated_at)"
            " VALUES (?, ?, ?, 'up', ?, ?, ?, ?, ?)",
            (tenant_id, subnet_id, ip, os_name, adesso, adesso, adesso, adesso))


def _porta(server_app, tenant_id, node_id, protocollo="tcp", porta=22,
           servizio="ssh", prodotto=None, versione=None, cpe=None, stato="open"):
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        return execute(
            "INSERT INTO node_ports (tenant_id, node_id, protocol, port, state,"
            " service_name, product, version, cpe, is_suspect, first_seen_at,"
            " last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
            (tenant_id, node_id, protocollo, porta, stato, servizio, prodotto,
             versione, cpe, adesso, adesso))


def _cve(server_app, identificativo, prodotto="openssh", vendor="openbsd",
         inizio="8.0", fine="9.0", punteggio=9.8, gravita="CRITICAL", kev=False,
         versione_fissa=None):
    """Scrive una CVE nel catalogo nella forma della NVD."""
    corrispondenza = {"vulnerable": True,
                      "criteria": "cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*"
                                  % (vendor, prodotto, versione_fissa or "*")}
    if versione_fissa is None:
        if inizio:
            corrispondenza["versionStartIncluding"] = inizio
        if fine:
            corrispondenza["versionEndExcluding"] = fine
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str
        from snapserver.threat_sources import store_cve

        store_cve({
            "id": identificativo,
            "published": "2099-01-01T00:00:00",
            "lastModified": "2099-01-02T00:00:00",
            "descriptions": [{"lang": "en", "value": "Difetto in %s." % prodotto}],
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": punteggio, "baseSeverity": gravita,
                "vectorString": "AV:N/AC:L", "version": "3.1"}}]},
            "weaknesses": [{"description": [{"value": "CWE-287"}]}],
            "configurations": [{"nodes": [{"cpeMatch": [corrispondenza]}]}],
            "references": [{"url": "https://example.invalid/%s" % identificativo}],
        })
        if kev:
            execute("UPDATE ti_cve SET kev = 1, kev_added_at = ? WHERE cve_id = ?",
                    (utc_now_str(), identificativo))


# --------------------------------------------------------------------------- #
# CPE e versioni
# --------------------------------------------------------------------------- #
def test_si_leggono_i_cpe_nelle_due_forme(server_app):
    """nmap emette la forma 2.2, la NVD usa la 2.3: leggerne una sola lascerebbe fuori
    meta' dell'inventario."""
    with server_app.app_context():
        from snapserver.threat import parse_cpe

        assert parse_cpe("cpe:/a:openbsd:openssh:8.9") == {
            "part": "a", "vendor": "openbsd", "product": "openssh", "version": "8.9"}
        assert parse_cpe("cpe:2.3:a:apache:http_server:2.4.62:*:*:*:*:*:*:*") == {
            "part": "a", "vendor": "apache", "product": "http_server",
            "version": "2.4.62"}
        # I segnaposto della notazione CPE non sono versioni.
        assert parse_cpe("cpe:/o:microsoft:windows")["version"] == ""
        assert parse_cpe("cpe:2.3:a:x:y:*:*:*:*:*:*:*:*")["version"] == ""
        assert parse_cpe("non un cpe") is None
        assert parse_cpe("") is None


def test_le_versioni_si_ordinano_per_numero_non_per_testo(server_app):
    """1.10 viene dopo 1.9: un confronto alfabetico direbbe il contrario, e su un
    intervallo di applicabilita' sarebbe un falso positivo o un falso negativo."""
    with server_app.app_context():
        from snapserver.threat import compare_versions

        assert compare_versions("1.9", "1.10") == -1
        assert compare_versions("2.4.62", "2.4.7") == 1
        assert compare_versions("8.9", "8.9") == 0
        assert compare_versions("1.0", "1.0p1") == -1


def test_una_versione_non_confrontabile_viene_dichiarata_incerta(server_app):
    """nmap restituisce "2.2.X - 2.3.X": un confronto su quella stringa darebbe un
    esito inventato."""
    with server_app.app_context():
        from snapserver.threat import version_uncertain

        assert version_uncertain("2.2.X - 2.3.X") is True
        assert version_uncertain("") is True
        assert version_uncertain("1.2 or 1.3") is True
        assert version_uncertain("8.9p1") is False


def test_l_applicabilita_rispetta_gli_estremi_dichiarati(server_app):
    with server_app.app_context():
        from snapserver.threat import version_in_range

        voce = {"version": "", "version_start": "8.0", "version_start_incl": 1,
                "version_end": "9.0", "version_end_incl": 0}
        assert version_in_range("8.0", voce) is True, "inizio incluso"
        assert version_in_range("8.9", voce) is True
        assert version_in_range("9.0", voce) is False, "fine esclusa"
        assert version_in_range("7.9", voce) is False
        # Nessun vincolo: la CVE riguarda tutte le versioni del prodotto.
        assert version_in_range("1.0", {"version": "", "version_start": "",
                                        "version_end": ""}) is True
        # Versione fissa: solo quella.
        fissa = {"version": "2.4.7", "version_start": "", "version_end": ""}
        assert version_in_range("2.4.7", fissa) is True
        assert version_in_range("2.4.8", fissa) is False


# --------------------------------------------------------------------------- #
# Correlazione: le tre classi
# --------------------------------------------------------------------------- #
def test_una_versione_dentro_l_intervallo_produce_un_riscontro_confermato(server_app):
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _porta(server_app, tenant_id, node_id, porta=22, prodotto="OpenSSH",
           versione="8.9", cpe="cpe:/a:openbsd:openssh")
    _cve(server_app, "CVE-2099-0001")

    with server_app.app_context():
        from snapserver import threat

        esito = threat.correlate(tenant_id)
        confermati = threat.findings(tenant_id, kind=threat.KIND_CONFIRMED)

    assert esito["confermati"] == 1
    assert len(confermati) == 1
    voce = confermati[0]
    assert voce["cve_id"] == "CVE-2099-0001"
    assert voce["severity"] == "critical"
    assert voce["version"] == "8.9"
    assert "rientra nell'applicabilita'" in voce["evidence"]
    # La versione qui viene dal banner del servizio, non dal CPE: il riscontro vale,
    # ma va verificato sull'apparato, e la confidenza lo dice.
    assert 60 <= voce["confidence"] < 80
    assert "annunciata dal servizio" in voce["evidence"]


def test_una_versione_fuori_intervallo_non_produce_nulla(server_app):
    """E' la prova piu' importante: un correlatore che segnala tutto cio' che ha il nome
    giusto e' un generatore di falsi positivi."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _porta(server_app, tenant_id, node_id, porta=22, prodotto="OpenSSH",
           versione="9.6", cpe="cpe:/a:openbsd:openssh")
    _cve(server_app, "CVE-2099-0001", inizio="8.0", fine="9.0")

    with server_app.app_context():
        from snapserver import threat

        esito = threat.correlate(tenant_id)
        cve_trovate = [f for f in threat.findings(tenant_id, status="") if f["cve_id"]]

    assert esito["confermati"] == 0
    assert esito["da_verificare"] == 0
    assert cve_trovate == [], "nessun riscontro: la versione e' fuori dall'intervallo"


def test_senza_versione_il_riscontro_resta_da_verificare(server_app):
    """La CVE riguarda il prodotto, ma l'istanza non e' verificabile: dirlo e' l'unica
    cosa onesta, e non va contato fra le vulnerabilita'."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _porta(server_app, tenant_id, node_id, porta=389, servizio="ldap",
           prodotto="OpenLDAP", cpe="cpe:/a:openldap:openldap")
    _cve(server_app, "CVE-2099-0002", prodotto="openldap", vendor="openldap",
         inizio="", fine="", punteggio=7.5, gravita="HIGH")

    with server_app.app_context():
        from snapserver import threat

        esito = threat.correlate(tenant_id)
        riscontri = threat.findings(tenant_id, kind=threat.KIND_POTENTIAL)
        riepilogo = threat.summary(tenant_id)

    assert esito["da_verificare"] == 1 and esito["confermati"] == 0
    voce = riscontri[0]
    assert voce["severity"] == "info", "senza versione non si eredita la gravita' CVSS"
    assert "non e' verificabile" in voce["evidence"]
    assert riepilogo["confermati"] == 0
    assert riepilogo["da_verificare"] == 1


def test_una_versione_incerta_non_diventa_una_conferma(server_app):
    """nmap dice "2.2.X - 2.3.X": non e' una versione, e non deve produrre certezze."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _porta(server_app, tenant_id, node_id, porta=389, servizio="ldap",
           prodotto="OpenLDAP", versione="2.2.X - 2.3.X",
           cpe="cpe:/a:openldap:openldap")
    _cve(server_app, "CVE-2099-0002", prodotto="openldap", vendor="openldap",
         inizio="2.0", fine="3.0")

    with server_app.app_context():
        from snapserver import threat

        esito = threat.correlate(tenant_id)
    assert esito["confermati"] == 0
    assert esito["da_verificare"] == 1


def test_le_esposizioni_non_dipendono_dal_catalogo(server_app):
    """Su un inventario senza versioni sono la classe che porta piu' informazione, e
    devono funzionare anche con il catalogo CVE vuoto."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    for porta, servizio in ((3389, "ms-wbt-server"), (445, "microsoft-ds"),
                            (23, "telnet")):
        _porta(server_app, tenant_id, node_id, porta=porta, servizio=servizio)

    with server_app.app_context():
        from snapserver import threat

        assert threat.catalog_summary()["cve"] == 0, "catalogo volutamente vuoto"
        esito = threat.correlate(tenant_id)
        esposizioni = threat.findings(tenant_id, kind=threat.KIND_EXPOSURE)

    assert esito["esposizioni"] == 3
    tecniche = {v["technique_id"] for v in esposizioni}
    assert "T1021.001" in tecniche, "RDP e' T1021.001"
    assert "T1021.002" in tecniche, "SMB e' T1021.002"
    assert all(v["evidence"] for v in esposizioni), (
        "ogni esposizione dichiara perche' conta")
    assert all(v["severity"] in ("high", "medium", "low") for v in esposizioni)


def test_l_esposizione_funziona_senza_il_catalogo_attack(server_app):
    """Difetto trovato cosi': un vincolo verso il catalogo ATT&CK impediva di registrare
    le esposizioni prima che il catalogo fosse importato, cioe' al primo avvio."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _porta(server_app, tenant_id, node_id, porta=23, servizio="telnet")

    with server_app.app_context():
        from snapserver.db import query
        from snapserver import threat

        assert query("SELECT COUNT(*) AS n FROM ti_technique", (), one=True)["n"] == 0
        esito = threat.correlate(tenant_id)
        voce = threat.findings(tenant_id, kind=threat.KIND_EXPOSURE)[0]

    assert esito["esposizioni"] == 1
    assert voce["technique_id"] == "T1040"
    assert not voce["tecnica_nome"], "senza catalogo resta l'identificativo, senza nome"


def test_il_prodotto_dedotto_dal_nome_ha_confidenza_ridotta(server_app):
    """Ricavare il CPE dal nome annunciato dal servizio e' euristica: va dichiarato, e
    non puo' valere quanto un CPE dichiarato dalla sonda."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _porta(server_app, tenant_id, node_id, porta=22, prodotto="OpenSSH",
           versione="8.9")  # nessun CPE: si passa dall'alias
    _cve(server_app, "CVE-2099-0001")

    with server_app.app_context():
        from snapserver import threat

        threat.correlate(tenant_id)
        voce = threat.findings(tenant_id, kind=threat.KIND_CONFIRMED)[0]

    assert "euristica" in voce["evidence"]
    assert voce["confidence"] < 80, "l'euristica non vale quanto un CPE dichiarato"


def test_un_riscontro_non_piu_osservato_si_chiude_senza_essere_cancellato(server_app):
    """La storia di cio' che era esposto e' informazione: cancellarla renderebbe
    impossibile dire quando e' stato chiuso."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    port_id = _porta(server_app, tenant_id, node_id, porta=23, servizio="telnet")

    with server_app.app_context():
        from snapserver.db import execute
        from snapserver import threat

        threat.correlate(tenant_id)
        assert len(threat.findings(tenant_id, status=threat.STATUS_OPEN)) == 1

        execute("UPDATE node_ports SET state = 'closed' WHERE id = ?", (port_id,))
        esito = threat.correlate(tenant_id)
        aperti = threat.findings(tenant_id, status=threat.STATUS_OPEN)
        chiusi = threat.findings(tenant_id, status=threat.STATUS_FIXED)

    assert esito["chiusi"] == 1
    assert aperti == []
    assert len(chiusi) == 1
    assert "non piu' osservato" in chiusi[0]["note"]


def test_la_seconda_correlazione_non_duplica(server_app):
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _porta(server_app, tenant_id, node_id, porta=3389, servizio="ms-wbt-server")

    with server_app.app_context():
        from snapserver.db import query
        from snapserver import threat

        threat.correlate(tenant_id)
        secondo = threat.correlate(tenant_id)
        quanti = query("SELECT COUNT(*) AS n FROM ti_findings", (), one=True)["n"]

    assert secondo["nuovi"] == 0 and secondo["aggiornati"] == 1
    assert quanti == 1, "la rivalutazione aggiorna, non duplica"


def test_gli_eventi_di_un_altro_tenant_non_entrano(server_app):
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        altro = execute("INSERT INTO tenants (code, name, timezone, locale,"
                        " retention_days, is_active, created_at, updated_at)"
                        " VALUES ('altro', 'Altro', 'UTC', 'it_IT', 365, 1, ?, ?)",
                        (adesso, adesso))
    node_id = _nodo(server_app, altro, ip="10.99.0.1")
    _porta(server_app, altro, node_id, porta=23, servizio="telnet")

    with server_app.app_context():
        from snapserver import threat

        esito = threat.correlate(tenant_id)
    assert esito["esaminati"] == 0 and esito["nuovi"] == 0


# --------------------------------------------------------------------------- #
# Decisioni dell'operatore
# --------------------------------------------------------------------------- #
def test_accettare_un_rischio_richiede_una_motivazione(server_app):
    """Senza motivazione, fra sei mesi nessuno sapra' perche' quel riscontro e' stato
    messo da parte."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _porta(server_app, tenant_id, node_id, porta=22, servizio="ssh")

    with server_app.app_context():
        from snapserver import threat

        threat.correlate(tenant_id)
        voce = threat.findings(tenant_id)[0]
        with pytest.raises(threat.ThreatError):
            threat.decide(tenant_id, int(voce["id"]), threat.STATUS_ACCEPTED, "")
        assert threat.decide(tenant_id, int(voce["id"]), threat.STATUS_ACCEPTED,
                             "rete di amministrazione separata") is True
        accettati = threat.findings(tenant_id, status=threat.STATUS_ACCEPTED)

    assert len(accettati) == 1
    assert "amministrazione separata" in accettati[0]["note"]


def test_una_decisione_non_viene_sovrascritta_dalla_correlazione(server_app):
    """Un riscontro riconfermato torna a essere visto, non riaperto: diversamente ogni
    passata cancellerebbe il lavoro dell'operatore."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _porta(server_app, tenant_id, node_id, porta=22, servizio="ssh")

    with server_app.app_context():
        from snapserver import threat

        threat.correlate(tenant_id)
        voce = threat.findings(tenant_id)[0]
        threat.decide(tenant_id, int(voce["id"]), threat.STATUS_FALSE_POSITIVE,
                      "e' la sonda stessa")
        threat.correlate(tenant_id)
        stato = threat.findings(tenant_id, status=threat.STATUS_FALSE_POSITIVE)

    assert len(stato) == 1, "la decisione resta"


# --------------------------------------------------------------------------- #
# Catalogo e sorgenti
# --------------------------------------------------------------------------- #
def test_una_cve_della_nvd_si_scrive_con_la_sua_applicabilita(server_app):
    with server_app.app_context():
        from snapserver.threat import cve as leggi_cve

        _cve(server_app, "CVE-2099-0007", punteggio=8.1, gravita="HIGH")
        voce = leggi_cve("CVE-2099-0007")

    assert voce["cvss_score"] == 8.1 and voce["severity"] == "high"
    assert voce["cvss_version"] == "3.1"
    assert voce["cwe_ids"] == "CWE-287"
    assert len(voce["cpe"]) == 1
    assert voce["cpe"][0]["version_start"] == "8.0"
    assert voce["cpe"][0]["version_end"] == "9.0"
    assert json.loads(voce["references_json"])


def test_il_catalogo_kev_marca_le_vulnerabilita_sfruttate(server_app):
    """Il singolo dato piu' azionabile che esista su una vulnerabilita'."""
    contenuto = json.dumps({
        "catalogVersion": "2026.08.28",
        "vulnerabilities": [
            {"cveID": "CVE-2099-0001", "vendorProject": "OpenBSD",
             "product": "OpenSSH", "shortDescription": "Sfruttata in campagne.",
             "dateAdded": "2026-08-01", "dueDate": "2026-08-22",
             "knownRansomwareCampaignUse": "Known"},
            {"cveID": "CVE-2099-9999", "vendorProject": "Altro", "product": "Altro",
             "shortDescription": "Mai vista prima.", "dateAdded": "2026-08-02",
             "dueDate": "2026-08-23", "knownRansomwareCampaignUse": "Unknown"},
        ]}).encode("utf-8")

    _cve(server_app, "CVE-2099-0001")
    with server_app.app_context():
        from snapserver.threat import cve as leggi_cve
        from snapserver.threat_sources import sync_kev

        esito = sync_kev(contenuto=contenuto)
        marcata = leggi_cve("CVE-2099-0001")
        nuova = leggi_cve("CVE-2099-9999")

    assert esito["kev"] == 2
    assert marcata["kev"] == 1 and marcata["kev_ransomware"] == 1
    assert marcata["description"].startswith("Difetto"), (
        "la descrizione della NVD non viene sostituita da quella del KEV")
    assert nuova is not None, (
        "una CVE sfruttata attivamente entra in catalogo anche se la NVD non e' stata"
        " ancora interrogata")
    assert nuova["kev"] == 1


def test_l_importazione_da_file_riconosce_il_formato_dal_contenuto(server_app):
    """Un file rinominato non deve essere importato nella tabella sbagliata."""
    kev = json.dumps({"catalogVersion": "x", "vulnerabilities": [
        {"cveID": "CVE-2099-1234", "shortDescription": "prova",
         "dateAdded": "2026-01-01", "dueDate": "2026-02-01"}]}).encode("utf-8")
    nvd = json.dumps({"vulnerabilities": [{"cve": {
        "id": "CVE-2099-5678",
        "descriptions": [{"lang": "en", "value": "prova nvd"}],
        "metrics": {}, "configurations": []}}]}).encode("utf-8")
    attack = json.dumps({"type": "bundle", "objects": [{
        "type": "attack-pattern", "name": "Prova tecnica",
        "description": "descrizione",
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack",
                               "phase_name": "lateral-movement"}],
        "external_references": [{"source_name": "mitre-attack",
                                 "external_id": "T9999",
                                 "url": "https://attack.invalid/T9999"}]}]}).encode("utf-8")

    with server_app.app_context():
        from snapserver.threat import catalog_summary
        from snapserver.threat_sources import SourceError, import_file

        assert import_file(kev, "qualsiasi.txt")["kev"] == 1
        assert import_file(nvd, "altro.bin")["cve"] == 1
        assert import_file(attack, "tecniche")["tecniche"] == 1
        with pytest.raises(SourceError):
            import_file(b"non e' niente di riconoscibile", "x.json")
        riepilogo = catalog_summary()

    assert riepilogo["cve"] == 2
    assert riepilogo["tecniche"] == 1
    assert riepilogo["cve_kev"] == 1


def test_i_prodotti_da_interrogare_vengono_dall_inventario(server_app):
    """Scaricare 250.000 CVE per correlarne trenta e' lavoro inutile: si interroga la
    NVD solo sui prodotti che esistono in rete."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _porta(server_app, tenant_id, node_id, porta=22, prodotto="OpenSSH",
           versione="8.9", cpe="cpe:/a:openbsd:openssh")
    _porta(server_app, tenant_id, node_id, porta=389, servizio="ldap",
           prodotto="OpenLDAP")
    _porta(server_app, tenant_id, node_id, porta=3389, servizio="ms-wbt-server")

    with server_app.app_context():
        from snapserver.threat_sources import inventory_products

        prodotti = inventory_products(tenant_id)

    nomi = {p["product"] for p in prodotti}
    assert "openssh" in nomi, "dal CPE dichiarato"
    assert "openldap" in nomi, "dall'alias sul nome del prodotto"
    assert len(prodotti) == 2, "la porta senza prodotto non produce interrogazioni"


def test_il_registro_degli_aggiornamenti_dichiara_l_esito(server_app):
    """Un catalogo di cui non si sa quanto e' vecchio non e' utilizzabile."""
    with server_app.app_context():
        from snapserver.threat_sources import recent_syncs, sync_cwe

        sync_cwe(contenuto=b"CWE-ID,Name,Weakness Abstraction,Status,Description\n"
                           b"79,Cross-site Scripting,Base,Stable,Descrizione\n")
        registro = recent_syncs()

    assert registro and registro[0]["source"] == "cwe"
    assert registro[0]["status"] == "ok" and registro[0]["items"] == 1


# --------------------------------------------------------------------------- #
# Pagine
# --------------------------------------------------------------------------- #
def test_la_pagina_dichiara_che_cosa_si_puo_affermare(logged_client, server_app):
    """Con 2540 porte aperte e 7 versioni, dire "nessuna vulnerabilita'" sarebbe
    fuorviante: la pagina dichiara la qualita' del dato."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _porta(server_app, tenant_id, node_id, porta=22, servizio="ssh")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/threat/").get_data(as_text=True)
    assert "Threat Intelligence" in pagina
    # La misura sta in testa, sempre visibile; la spiegazione si apre a richiesta,
    # perche' e' una premessa che si legge una volta e non a ogni apertura.
    assert "Qualita' del dato" in pagina
    assert "porte aperte" in pagina
    assert "con identificativo di prodotto" in pagina
    assert "con la versione" in pagina
    assert "che cosa comporta" in pagina, "la spiegazione deve restare raggiungibile"
    assert "solo conoscendo la" in pagina
    assert "Catalogo vuoto" in pagina, (
        "senza CVE in archivio la pagina lo dice, invece di sembrare tutto a posto")


def test_la_correlazione_si_avvia_dalla_pagina(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _porta(server_app, tenant_id, node_id, porta=3389, servizio="ms-wbt-server")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.post("/threat/correlate", follow_redirects=True)
    testo = risposta.get_data(as_text=True)
    assert "Correlazione eseguita" in testo
    assert "Desktop remoto (RDP) raggiungibile" in testo


def test_il_dettaglio_di_una_cve_mostra_i_nodi_e_il_motivo(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _porta(server_app, tenant_id, node_id, porta=22, prodotto="OpenSSH",
           versione="8.9", cpe="cpe:/a:openbsd:openssh")
    _cve(server_app, "CVE-2099-0001", kev=True)
    with server_app.app_context():
        from snapserver import threat

        threat.correlate(tenant_id)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/threat/cve/CVE-2099-0001").get_data(as_text=True)
    assert "CVE-2099-0001" in pagina
    assert "Sfruttata attivamente" in pagina
    assert "10.9.0.5" in pagina, "il nodo interessato deve comparire"
    assert "Applicabilita" in pagina
    assert "CWE-287" in pagina


def test_una_cve_non_in_catalogo_non_produce_un_errore(logged_client):
    risposta = logged_client.get("/threat/cve/CVE-1999-0001", follow_redirects=True)
    assert risposta.status_code == 200
    assert "non e' nel catalogo locale" in risposta.get_data(as_text=True).replace(
        "&#39;", "'")


def test_la_scheda_del_nodo_mostra_i_riscontri(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _porta(server_app, tenant_id, node_id, porta=445, servizio="microsoft-ds")
    with server_app.app_context():
        from snapserver import threat

        threat.correlate(tenant_id)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/nodes/%d" % node_id).get_data(as_text=True)
    assert "Vulnerabilita ed esposizioni" in pagina
    assert "Condivisione file Windows (SMB) raggiungibile" in pagina
    assert "T1021.002" in pagina


def test_un_riscontro_diventa_evento_per_le_regole(server_app):
    """La threat intelligence non serve se nessuno la guarda: i riscontri sono una
    sorgente di evento come le altre, quindi possono far scattare una notifica."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _porta(server_app, tenant_id, node_id, porta=22, prodotto="OpenSSH",
           versione="8.9", cpe="cpe:/a:openbsd:openssh")
    _cve(server_app, "CVE-2099-0001", kev=True)

    with server_app.app_context():
        from snapserver import rules, threat
        from snapserver.events import fetch_recent

        threat.correlate(tenant_id)
        eventi = fetch_recent("ti_findings", limit=20, tenant_id=tenant_id)
        confermati = [e for e in eventi if e["type"] == "threat.confirmed"]
        assert confermati, "un riscontro confermato e' un evento"
        evento = confermati[0]
        assert evento["attributi"]["cve_id"] == "CVE-2099-0001"
        assert evento["attributi"]["kev"] == 1

        regola = rules.validate_rule({
            "name": "Vulnerabilita' sfruttata attivamente",
            "source": "ti_findings", "event_type": "threat.confirmed",
            "conditions": [{"field": "kev", "op": "eq", "value": "1"}],
            "channels": ["email"], "recipients": "turno@ised.local"})
        finta = dict(regola, id=0, channel_list=["email"])
        assert rules.matches(finta, evento) is True


# --------------------------------------------------------------------------- #
# Report delle vulnerabilita'
# --------------------------------------------------------------------------- #
def _rete_con_riscontri(server_app, tenant_id):
    """Un nodo con una vulnerabilita' confermata, una da verificare, un'esposizione."""
    from snapserver import threat

    node_id = _nodo(server_app, tenant_id, ip="10.9.0.7")
    _porta(server_app, tenant_id, node_id, porta=22, servizio="ssh",
           prodotto="OpenSSH", versione="7.4",
           cpe="cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*")
    _porta(server_app, tenant_id, node_id, porta=3389, servizio="ms-wbt-server")
    _porta(server_app, tenant_id, node_id, porta=1521, servizio="oracle-tns",
           prodotto="Oracle Database")
    _cve(server_app, "CVE-2018-15473", inizio="7.0", fine="7.7")
    with server_app.app_context():
        threat.correlate(tenant_id)
    return node_id


def _genera_report(server_app, tenant, giorni=30):
    with server_app.app_context():
        from snapserver.reports import KIND_THREAT
        from snapserver.reports.generate import generate
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        return generate(KIND_THREAT, tenant, today_local(zona), giorni)


def _tenant(server_app):
    with server_app.app_context():
        from snapserver.db import query

        return dict(query("SELECT * FROM tenants ORDER BY id", (), one=True))


def test_il_report_delle_vulnerabilita_distingue_sempre_le_tre_classi(server_app):
    """Un totale che sommi vulnerabilita' accertate, ipotesi da verificare ed
    esposizioni di servizio non significa niente (TI-02): il documento le tiene
    separate dal primo riquadro all'ultima tabella."""
    from test_report import _testo_pdf

    tenant = _tenant(server_app)
    _rete_con_riscontri(server_app, int(tenant["id"]))
    testo = _testo_pdf(_genera_report(server_app, tenant))

    assert "VULNERABILITA'" in testo, "manca l'etichetta del genere"
    for parola in ("confermate", "da verificare", "esposizioni di servizio"):
        assert parola in testo, "manca la classe %r fra gli indicatori" % parola
    assert "CVE-2018-15473" in testo, "la vulnerabilita' confermata deve comparire"
    assert "Desktop remoto (RDP) raggiungibile" in testo
    # L'attribuzione della tecnica e' nostra e va dichiarata come tale (TI-11).
    assert "non e' di MITRE" in testo or "e' nostra e non di MITRE" in testo


def test_il_report_dichiara_la_qualita_del_dato(server_app):
    """Con pochissime versioni rilevate, "nessuna vulnerabilita' confermata" e' la
    risposta vera: il documento deve permettere di distinguerla da un guasto."""
    from test_report import _testo_pdf

    tenant = _tenant(server_app)
    _rete_con_riscontri(server_app, int(tenant["id"]))
    testo = _testo_pdf(_genera_report(server_app, tenant))

    assert "Qualita' del dato" in testo
    assert "Porte aperte nell'inventario" in testo
    assert "Con versione rilevata" in testo


def test_il_report_raggruppa_le_esposizioni_per_tipo(server_app):
    """Un elenco per nodo ripeterebbe la stessa frase per ogni dispositivo: il fatto
    da riportare e' su quanti dispositivi un servizio rischioso e' raggiungibile."""
    from snapserver.reports import dataset_wide

    tenant = _tenant(server_app)
    tenant_id = int(tenant["id"])
    _rete_con_riscontri(server_app, tenant_id)
    # Un secondo nodo con la stessa esposizione: il gruppo deve contarli entrambi.
    secondo = _nodo(server_app, tenant_id, ip="10.9.0.8")
    _porta(server_app, tenant_id, secondo, porta=3389, servizio="ms-wbt-server")
    with server_app.app_context():
        from snapserver import threat
        from snapserver.reports.windows import today_local, zone_of

        threat.correlate(tenant_id)
        zona = zone_of(tenant)
        dati = dataset_wide.threat(tenant, zona, today_local(zona), 30)

    gruppi = {g["titolo"]: g for g in dati["esposizioni"]}
    rdp = gruppi["Desktop remoto (RDP) raggiungibile"]
    assert rdp["quanti"] == 2, "i due nodi vanno nello stesso gruppo"
    assert rdp["tecnica"] == "T1021.001"
    # La motivazione e l'azione appartengono alla regola, non alla riga.
    assert rdp["motivo"] and rdp["raccomandazione"]


def test_il_report_ordina_i_dispositivi_per_quanto_hanno_da_sistemare(server_app):
    """La domanda operativa e' "da quale dispositivo comincio": un elenco per
    vulnerabilita' non la risponde, perche' lo stesso apparato compare in venti righe."""
    from snapserver.reports import dataset_wide

    tenant = _tenant(server_app)
    tenant_id = int(tenant["id"])
    _rete_con_riscontri(server_app, tenant_id)
    tranquillo = _nodo(server_app, tenant_id, ip="10.9.0.9")
    _porta(server_app, tenant_id, tranquillo, porta=22, servizio="ssh")
    with server_app.app_context():
        from snapserver import threat
        from snapserver.reports.windows import today_local, zone_of

        threat.correlate(tenant_id)
        zona = zone_of(tenant)
        dati = dataset_wide.threat(tenant, zona, today_local(zona), 30)

    nodi = dati["nodi"]
    assert nodi, "l'elenco dei dispositivi da cui cominciare non puo' essere vuoto"
    assert nodi[0]["ip"] == "10.9.0.7", (
        "il nodo con una vulnerabilita' confermata viene prima di uno con la sola"
        " esposizione SSH")
    assert nodi[0]["confermati"] >= 1


def test_il_report_si_genera_anche_senza_catalogo(server_app):
    """Su un'installazione nuova il catalogo e' vuoto: il documento deve dirlo, non
    fallire ne' far credere che la rete sia a posto."""
    from test_report import _testo_pdf

    tenant = _tenant(server_app)
    node_id = _nodo(server_app, int(tenant["id"]), ip="10.9.0.11")
    _porta(server_app, int(tenant["id"]), node_id, porta=23, servizio="telnet")
    with server_app.app_context():
        from snapserver import threat

        threat.correlate(int(tenant["id"]))

    testo = _testo_pdf(_genera_report(server_app, tenant))
    assert "Il catalogo delle vulnerabilita' e' vuoto" in testo
    # Le esposizioni non dipendono dal catalogo e devono esserci lo stesso.
    assert "Telnet" in testo


def test_il_report_delle_vulnerabilita_e_nel_catalogo_dei_report(server_app):
    with server_app.app_context():
        from snapserver.reports import KIND_THREAT, REPORT_CATALOG, REPORT_KINDS
        from snapserver.reports.generate import GENERATORI, allowed_days

        assert KIND_THREAT in REPORT_CATALOG, "il report va offerto nella pagina"
        assert KIND_THREAT in GENERATORI
        assert REPORT_KINDS[KIND_THREAT]
        assert 30 in allowed_days(KIND_THREAT)


# --------------------------------------------------------------------------- #
# Chiave API della NVD
# --------------------------------------------------------------------------- #
CHIAVE_VALIDA = "11111111-2222-3333-4444-555555555555"


def test_la_chiave_api_si_registra_e_cambia_il_ritmo(server_app):
    """Con la chiave la NVD concede 50 richieste ogni 30 secondi invece di 5: e' la
    ragione per cui registrarla, e la pagina deve poterlo dire."""
    from snapserver import threat_sources as sorgenti

    with server_app.app_context():
        senza = sorgenti.settings()
        assert not senza["has_api_key"]
        assert senza["richieste_per_finestra"] == 5

        assert sorgenti.save_api_key(CHIAVE_VALIDA) == "registrata"
        con = sorgenti.settings()
        assert con["has_api_key"]
        assert con["richieste_per_finestra"] == 50
        assert con["pausa"] < senza["pausa"]


def test_la_chiave_non_torna_mai_in_chiaro_alla_pagina(server_app):
    """Una chiave in un modulo precompilato finisce in una cronologia, in una stampa,
    in una schermata condivisa: si mostrano le ultime quattro cifre e basta."""
    from snapserver import threat_sources as sorgenti

    with server_app.app_context():
        sorgenti.save_api_key(CHIAVE_VALIDA)
        mascherata = sorgenti.settings()["api_key_masked"]

    assert CHIAVE_VALIDA not in mascherata
    assert mascherata.endswith(CHIAVE_VALIDA[-4:])


def test_la_chiave_non_entra_nel_contesto_della_pagina(server_app):
    """Un valore nel contesto e' a un'espressione di distanza dall'essere stampato
    per sbaglio, e compare in ogni traccia di debug della resa."""
    from snapserver import threat_sources as sorgenti

    with server_app.app_context():
        sorgenti.save_api_key(CHIAVE_VALIDA)
        pubbliche = sorgenti.public_settings()

    assert "api_key" not in pubbliche
    assert pubbliche["has_api_key"] is True
    assert pubbliche["api_key_masked"].endswith(CHIAVE_VALIDA[-4:])


def test_una_chiave_malformata_viene_rifiutata_subito(server_app):
    """Un incolla parziale, senza controllo, si scoprirebbe con un 403 dopo dieci
    minuti di aggiornamento."""
    from snapserver import threat_sources as sorgenti

    with server_app.app_context():
        with pytest.raises(sorgenti.SourceError):
            sorgenti.save_api_key("11111111-2222-3333")
        assert not sorgenti.settings()["has_api_key"]


def test_una_chiave_vuota_la_rimuove(server_app):
    from snapserver import threat_sources as sorgenti

    with server_app.app_context():
        sorgenti.save_api_key(CHIAVE_VALIDA)
        assert sorgenti.save_api_key("") == "rimossa"
        assert not sorgenti.settings()["has_api_key"]


def test_la_chiave_non_finisce_nel_registro_di_audit(server_app):
    """Un segreto in un registro di audit e' un segreto compromesso."""
    from snapserver import threat_sources as sorgenti

    with server_app.app_context():
        from snapserver.db import query

        sorgenti.save_api_key(CHIAVE_VALIDA)
        righe = query("SELECT description FROM audit_events"
                      " WHERE event_type LIKE 'threat.apikey%'", ())
    assert righe, "la registrazione della chiave va tracciata"
    for riga in righe:
        assert CHIAVE_VALIDA not in (riga["description"] or "")


def test_solo_l_amministratore_di_sistema_registra_la_chiave(logged_client, server_app):
    """Il catalogo e' unico per tutto il server: la chiave e' una credenziale
    dell'installazione, non di un cliente."""
    from snapserver import threat_sources as sorgenti

    risposta = logged_client.post("/threat/settings/api-key",
                                  data={"api_key": CHIAVE_VALIDA},
                                  follow_redirects=True)
    assert risposta.status_code == 200
    with server_app.app_context():
        assert sorgenti.settings()["has_api_key"], (
            "l'amministratore di sistema deve poterla registrare")


# --------------------------------------------------------------------------- #
# Legame CVE-CWE precalcolato
# --------------------------------------------------------------------------- #
def test_le_debolezze_contano_le_cve_dal_legame_conservato(server_app):
    """Il conteggio veniva da un confronto testuale su tutte le CVE per ciascuna
    delle 130 debolezze: 14,3 secondi a ogni apertura della pagina. Ora e' un
    legame scritto quando la CVE si scrive."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        execute("INSERT INTO ti_cwe (cwe_id, name, imported_at) VALUES (?, ?, ?)",
                ("CWE-287", "Improper Authentication", utc_now_str()))

    _cve(server_app, "CVE-2026-0001")
    _cve(server_app, "CVE-2026-0002")

    with server_app.app_context():
        from snapserver.db import query
        from snapserver.threat import cwe_list

        legami = query("SELECT cve_id, cwe_id FROM ti_cve_cwe ORDER BY cve_id", ())
        assert [r["cwe_id"] for r in legami] == ["CWE-287", "CWE-287"]

        voci = {r["cwe_id"]: r for r in cwe_list()}
        assert voci["CWE-287"]["cve_collegate"] == 2


def test_riscrivere_una_cve_non_duplica_il_legame(server_app):
    """Una CVE aggiornata riscrive il proprio legame, non ne aggiunge un altro."""
    _cve(server_app, "CVE-2026-0003")
    _cve(server_app, "CVE-2026-0003")

    with server_app.app_context():
        from snapserver.db import query

        righe = query("SELECT * FROM ti_cve_cwe WHERE cve_id = 'CVE-2026-0003'", ())
    assert len(righe) == 1


def test_un_archivio_gia_popolato_si_riempie_all_avvio(server_app):
    """Il legame e' nato dopo le CVE: senza riempimento la scheda delle debolezze
    mostrerebbe zero finche' non si riscarica l'intero catalogo."""
    _cve(server_app, "CVE-2026-0004")

    with server_app.app_context():
        from snapserver.db import execute, init_db, query

        # Si simula l'archivio precedente: la colonna testuale c'e', il legame no.
        execute("DELETE FROM ti_cve_cwe", ())
        init_db()

        righe = query("SELECT cwe_id FROM ti_cve_cwe WHERE cve_id = 'CVE-2026-0004'", ())
    assert [r["cwe_id"] for r in righe] == ["CWE-287"]


# --------------------------------------------------------------------------- #
# Schede della pagina
# --------------------------------------------------------------------------- #
def _pagina(logged_client, tenant_id, indirizzo="/threat/"):
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)
    return logged_client.get(indirizzo).get_data(as_text=True)


def test_ogni_scheda_carica_soltanto_cio_che_mostra(logged_client, server_app):
    """La pagina costruiva insieme riscontri, catalogo, CWE, tecniche e registro --
    1,7 MB -- per mostrarne una parte sola."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _porta(server_app, tenant_id, node_id, porta=3389, servizio="ms-wbt-server")
    _cve(server_app, "CVE-2026-1000")
    with server_app.app_context():
        from snapserver import threat

        threat.correlate(tenant_id)

    riscontri = _pagina(logged_client, tenant_id, "/threat/?scheda=riscontri")
    assert "Desktop remoto (RDP) raggiungibile" in riscontri
    assert "Catalogo CVE locale" not in riscontri, (
        "il catalogo appartiene alla sua scheda e non va costruito qui")

    catalogo = _pagina(logged_client, tenant_id, "/threat/?scheda=catalogo")
    assert "CVE-2026-1000" in catalogo
    assert "Riscontri sui nodi" in catalogo, "la barra delle schede resta"


def test_le_schede_sono_collegamenti_e_dichiarano_quale_e_aperta(logged_client,
                                                                 server_app):
    tenant_id = _tenant_id(server_app)
    pagina = _pagina(logged_client, tenant_id, "/threat/?scheda=cwe")
    assert 'href="/threat/?scheda=attack"' in pagina
    assert 'class="nav-link active"' in pagina


def test_una_scheda_inventata_apre_quella_predefinita(logged_client, server_app):
    """Una chiave non prevista non e' un errore da mostrare: vale la predefinita."""
    tenant_id = _tenant_id(server_app)
    pagina = _pagina(logged_client, tenant_id, "/threat/?scheda=inventata")
    assert "Riscontri sui nodi" in pagina


def test_i_riscontri_si_dividono_per_classe(logged_client, server_app):
    """Un elenco che mescola le tre classi non e' utilizzabile: chi lo legge non sa
    quali righe sono fatti e quali ipotesi (TI-02)."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _porta(server_app, tenant_id, node_id, porta=3389, servizio="ms-wbt-server")
    with server_app.app_context():
        from snapserver import threat

        threat.correlate(tenant_id)

    esposizioni = _pagina(logged_client, tenant_id,
                          "/threat/?scheda=riscontri&classe=exposure")
    assert "Desktop remoto (RDP) raggiungibile" in esposizioni

    confermate = _pagina(logged_client, tenant_id,
                         "/threat/?scheda=riscontri&classe=confirmed")
    assert "Desktop remoto (RDP) raggiungibile" not in confermate, (
        "un'esposizione non e' una vulnerabilita' confermata")


def test_le_schede_interne_hanno_un_solo_pannello_aperto(logged_client, server_app):
    """Ogni gruppo di schede apre un pannello e uno solo: due pannelli aperti nello
    stesso gruppo si sovrappongono."""
    import re

    tenant_id = _tenant_id(server_app)
    for indirizzo, gruppi in (("/threat/?scheda=attack", 2),
                              ("/threat/?scheda=sorgenti", 2),
                              ("/threat/?scheda=cwe", 1)):
        pagina = _pagina(logged_client, tenant_id, indirizzo)
        aperti = len(re.findall(r"tab-pane fade show active", pagina))
        assert aperti == gruppi, "%s: %d pannelli aperti invece di %d" % (
            indirizzo, aperti, gruppi)


def test_la_scheda_delle_sorgenti_divide_aggiornamento_chiave_e_registro(
        logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    pagina = _pagina(logged_client, tenant_id, "/threat/?scheda=sorgenti")
    for scheda in ("src-aggiornamento", "src-chiave", "src-importazione",
                   "src-prodotti", "src-registro"):
        assert 'id="tab-%s"' % scheda in pagina, "manca la scheda %s" % scheda


def test_la_scheda_attack_divide_esposizioni_e_catalogo(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    pagina = _pagina(logged_client, tenant_id, "/threat/?scheda=attack")
    assert 'id="tab-atk-esposizioni"' in pagina
    assert 'id="tab-atk-catalogo"' in pagina
    assert "Esposizioni e tecniche corrispondenti" in pagina


# --------------------------------------------------------------------------- #
# I riscontri si guardano per dispositivo
# --------------------------------------------------------------------------- #
def test_l_elenco_dei_riscontri_e_per_dispositivo(server_app):
    """Lo stesso apparato compariva in venti righe -- una per porta e per CVE -- e la
    domanda di chi lavora e' "da quale dispositivo comincio"."""
    from snapserver.threat import nodes_with_findings

    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id, ip="10.9.0.30")
    for porta, servizio in ((3389, "ms-wbt-server"), (445, "microsoft-ds"),
                            (23, "telnet")):
        _porta(server_app, tenant_id, node_id, porta=porta, servizio=servizio)
    altro = _nodo(server_app, tenant_id, ip="10.9.0.31")
    _porta(server_app, tenant_id, altro, porta=22, servizio="ssh")

    with server_app.app_context():
        from snapserver import threat

        threat.correlate(tenant_id)
        elenco = nodes_with_findings(tenant_id)

    assert [v["ip"] for v in elenco] == ["10.9.0.30", "10.9.0.31"], (
        "prima il dispositivo che ha piu' da sistemare")
    primo = elenco[0]
    assert primo["riscontri"] == 3 and primo["esposizioni"] == 3
    assert primo["porte"] == 3
    assert primo["peggiore"] == "high"
    assert len(primo["titoli"]) <= 3


def test_un_titolo_con_virgole_non_si_spezza_in_due_voci(server_app):
    """I titoli dei riscontri contengono virgole ("50 CVE note per il prodotto,
    versione non rilevata"): con la virgola come separatore diventavano due."""
    from snapserver.threat import nodes_with_findings

    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id, ip="10.9.0.32")
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        execute(
            "INSERT INTO ti_findings (tenant_id, node_id, kind, severity, title,"
            " evidence, confidence, status, first_seen_at, last_seen_at)"
            " VALUES (?, ?, 'potential', 'info', 'openssh: 50 CVE note, versione non"
            " rilevata', 'prova', 40, 'open', ?, ?)", (tenant_id, node_id, adesso, adesso))
        elenco = nodes_with_findings(tenant_id)

    assert elenco[0]["titoli"] == ["openssh: 50 CVE note, versione non rilevata"]


def test_la_tabella_della_pagina_e_ip_centrica(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id, ip="10.9.0.33")
    _porta(server_app, tenant_id, node_id, porta=3389, servizio="ms-wbt-server")
    with server_app.app_context():
        from snapserver import threat

        threat.correlate(tenant_id)

    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)
    pagina = logged_client.get("/threat/").get_data(as_text=True)
    assert "INDIRIZZO" in pagina and "DISPOSITIVO" in pagina
    assert "10.9.0.33" in pagina
    assert "/inventory/nodes/%d" % node_id in pagina, (
        "dall'indirizzo si arriva al dispositivo")


def test_la_decisione_si_prende_nella_pagina_del_nodo(logged_client, server_app):
    """L'elenco generale e' per dispositivo e non porta piu' i singoli riscontri: le
    decisioni (rischio accettato, falso positivo) restano dove si vede il nodo."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id, ip="10.9.0.34")
    _porta(server_app, tenant_id, node_id, porta=23, servizio="telnet")
    with server_app.app_context():
        from snapserver import threat

        threat.correlate(tenant_id)

    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)
    pagina = logged_client.get("/inventory/nodes/%d" % node_id).get_data(as_text=True)
    assert "/threat/findings/" in pagina and "decide" in pagina
    assert 'placeholder="motivazione"' in pagina, "la motivazione resta obbligatoria"
