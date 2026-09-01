"""
snap - Test dell'arricchimento dalle interfacce web dei dispositivi.

Su una rete reale la meta' degli apparati non si identifica dalle porte: una 443
aperta e' una 443 aperta. Ma il loro pannello di gestione si presenta da solo -- "HP
LaserJet MFP M428", "Synology DiskStation", "FortiGate" -- ed e' la fonte piu'
esplicita dopo SNMP, oltre a dichiarare spesso prodotto e VERSIONE, che e' cio' che
rende una vulnerabilita' attribuibile a un'istanza.

Queste prove coprono le tre parti: che cosa il lettore ricava da una pagina, che cosa
il server conserva (e che cosa NON conserva), e come la lettura entra nel
riconoscimento.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest


# --------------------------------------------------------------------------- #
# Il lettore: quali porte, e che cosa ne ricava
# --------------------------------------------------------------------------- #
def test_si_leggono_solo_le_porte_web_aperte():
    from snapprobe.web_probe import porte_web

    porte = [
        {"protocol": "tcp", "port": 80, "state": "open", "service_name": "http"},
        {"protocol": "tcp", "port": 443, "state": "open", "service_name": "https"},
        {"protocol": "tcp", "port": 22, "state": "open", "service_name": "ssh"},
        {"protocol": "tcp", "port": 8080, "state": "closed", "service_name": "http-alt"},
        {"protocol": "udp", "port": 161, "state": "open", "service_name": "snmp"},
    ]

    scelte = porte_web(porte)

    assert (80, False) in scelte
    assert (443, True) in scelte, "la 443 si legge in cifrato"
    assert not any(p == 22 for p, _ in scelte), "SSH non e' un'interfaccia web"
    assert not any(p == 8080 for p, _ in scelte), "una porta chiusa non si interroga"
    assert not any(p == 161 for p, _ in scelte), "UDP non si legge con una GET"


def test_un_servizio_dichiarato_non_web_su_porta_web_non_si_legge():
    """Un SSH spostato sulla 8080: una GET la' non serve a nessuno."""
    from snapprobe.web_probe import porte_web

    scelte = porte_web([{"protocol": "tcp", "port": 8080, "state": "open",
                         "service_name": "ssh"}])

    assert scelte == []


def test_una_porta_tcpwrapped_su_porta_web_si_legge_lo_stesso():
    """"tcpwrapped" non e' una dichiarazione di servizio: e' nmap che dice "apre e
    chiude, non so cosa sia". Sugli apparati che limitano i tentativi -- un telefono IP
    Cisco espone cosi' la 80 -- trattarlo come non-web faceva saltare la lettura."""
    from snapprobe.web_probe import porte_web

    scelte = porte_web([{"protocol": "tcp", "port": 80, "state": "open",
                         "service_name": "tcpwrapped"}])

    assert (80, False) in scelte


@pytest.mark.parametrize("dichiarazione,attesi", [
    ({"titolo": "HP LaserJet MFP M428 Series"},
     {"marca": "HP", "tipo_probabile": "printer"}),
    ({"titolo": "FortiGate - login"}, {"marca": "Fortinet", "tipo_probabile": "firewall"}),
    ({"titolo": "Synology DiskStation"}, {"marca": "Synology", "tipo_probabile": "nas"}),
    ({"titolo": "iDRAC9 - Dell"}, {"marca": "Dell", "tipo_probabile": "server"}),
    # Web card Vertiv/Emerson IntelliSlot del gruppo frigo: e' infrastruttura di
    # alimentazione/raffreddamento, non una telecamera.
    ({"titolo": "Emerson Network Power IntelliSlot Web Card"},
     {"marca": "Vertiv", "tipo_probabile": "building_automation"}),
    # Telefono IP Cisco: la marca dal titolo/corpo, la classe esatta voip_phone.
    ({"titolo": "Cisco Systems, Inc.",
      "fatti": {"modello": "CP-7962G", "nome_host": "SEP001122334455"}},
     {"marca": "Cisco", "tipo_probabile": "voip_phone", "modello": "CP-7962G"}),
    # UPS HP con scheda MGE/Eaton: il genere si riconosce gia' dal titolo (il modello,
    # scritto in grassetto nel corpo, e' coperto dalla prova di lettura completa).
    ({"titolo": "HP UPS Network Module"}, {"tipo_probabile": "ups"}),
    ({"server": "Microsoft-IIS/10.0"},
     {"prodotto": "Microsoft IIS", "versione": "10.0"}),
    ({"server": "nginx/1.24.0"}, {"prodotto": "nginx", "versione": "1.24.0"}),
])
def test_le_firme_riconoscono_cio_che_la_pagina_dichiara(dichiarazione, attesi):
    from snapprobe.web_probe import riconosci

    trovato = riconosci(dichiarazione)

    for chiave, valore in attesi.items():
        assert trovato.get(chiave) == valore, (
            "da %r attendevo %s=%r, ottenuto %r"
            % (dichiarazione, chiave, valore, trovato.get(chiave)))
    assert trovato.get("firma"), "un verdetto senza la firma che lo motiva non e' verificabile"


def test_una_pagina_muta_non_produce_verdetti():
    """Meglio nessun verdetto che uno inventato: senza etichette non si conclude."""
    from snapprobe.web_probe import riconosci

    assert riconosci({"stato": 200}) == {}


def test_il_web_card_vertiv_non_e_scambiato_per_una_telecamera():
    """La vecchia firma hikvision (`dvr.*web` a distanza illimitata) agganciava pagine
    piene di JavaScript dove "web" abbonda: un gruppo frigo Vertiv finiva 'telecamera'.
    La firma Vertiv, piu' specifica, viene prima; e la distanza di hikvision e' limitata."""
    from snapprobe.web_probe import riconosci

    corpo = ('var fwLabel = "IS-UNITY_5.0.0.0_91932"; '
             'redirect to default.html for UMS device; dvr not related here ... '
             + "web " * 40)
    trovato = riconosci({"titolo": "Emerson Network Power IntelliSlot Web Card"},
                        corpo=corpo)
    assert trovato["firma"] == "vertiv-intellislot"
    assert trovato["tipo_probabile"] == "building_automation"
    assert trovato["marca"] == "Vertiv"


def test_la_versione_estratta_e_quella_che_rende_attribuibile_una_cve():
    from snapprobe.web_probe import riconosci

    trovato = riconosci({"titolo": "Grafana", "generator": ""}, corpo="Grafana v10.2.3")

    assert trovato["prodotto"] == "Grafana"
    assert trovato["versione"] == "10.2.3"


def test_le_redirezioni_verso_altri_host_non_si_seguono():
    """Un apparato che rimanda al portale del fornitore non e' quel portale, e quel
    portale non e' nel perimetro dichiarato."""
    from snapprobe.web_probe import _redirezione_interna

    assert _redirezione_interna("http://10.0.0.1/", "/login", "10.0.0.1") == \
        "http://10.0.0.1/login"
    assert _redirezione_interna("http://10.0.0.1/", "https://10.0.0.1/x", "10.0.0.1")
    assert _redirezione_interna("http://10.0.0.1/", "https://esempio.invalido/", "10.0.0.1") is None


# --------------------------------------------------------------------------- #
# Il certificato TLS
# --------------------------------------------------------------------------- #
def _certificato_di_prova(scaduto=False):
    """Un certificato autofirmato costruito a tavolino, come DER."""
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    chiave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nome = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "device.local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Acme SpA"),
    ])
    ora = datetime.datetime.now(datetime.timezone.utc)
    fine = ora - datetime.timedelta(days=1) if scaduto else ora + datetime.timedelta(days=100)
    cert = (x509.CertificateBuilder().subject_name(nome).issuer_name(nome)
            .public_key(chiave.public_key()).serial_number(0x1234ABCD)
            .not_valid_before(ora - datetime.timedelta(days=10)).not_valid_after(fine)
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("device.local"),
                x509.IPAddress(ipaddress.ip_address("10.0.0.5"))]), False)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(chiave, hashes.SHA256()))
    return cert.public_bytes(Encoding.DER)


def test_di_un_certificato_https_si_leggono_tutte_le_informazioni():
    """Dove c'e' HTTPS si registra tutto cio' che il certificato dichiara: non solo chi
    e per quanto, ma numero di serie, algoritmo di firma, chiave, impronte, nomi
    alternativi e usi -- e gli esiti di sicurezza (autofirmato, scaduto)."""
    from snapprobe.web_probe import dettagli_certificato

    d = dettagli_certificato(_certificato_di_prova())

    assert d["cert_soggetto"] == "device.local"
    assert "O=Acme SpA" in d["cert_soggetto_dn"]
    assert d["cert_autofirmato"] is True
    assert d["cert_scaduto"] is False
    assert d["cert_seriale"] == "1234ABCD"
    assert d["cert_versione"] == "v3"
    assert d["cert_algoritmo_firma"] == "sha256"
    assert d["cert_chiave"] == "RSA 2048 bit"
    assert len(d["cert_sha256"]) == 64 and len(d["cert_sha1"]) == 40
    assert "device.local" in d["cert_nomi"]
    assert d["cert_nomi_ip"] == ["10.0.0.5"]
    assert "firma digitale" in d["cert_uso"] and "cifratura chiave" in d["cert_uso"]
    assert d["cert_uso_esteso"] == ["autenticazione server"]


def test_un_certificato_scaduto_e_dichiarato_tale():
    from snapprobe.web_probe import dettagli_certificato

    d = dettagli_certificato(_certificato_di_prova(scaduto=True))

    assert d["cert_scaduto"] is True
    assert d["cert_giorni_residui"] < 0


def test_un_certificato_malformato_non_solleva():
    """I byte illeggibili non devono far perdere il resto della lettura: si annota
    l'errore e basta."""
    from snapprobe.web_probe import dettagli_certificato

    d = dettagli_certificato(b"non e' un certificato")

    assert "cert_errore" in d


# --------------------------------------------------------------------------- #
# La fase nella sonda
# --------------------------------------------------------------------------- #
def test_la_fase_web_esiste_con_la_sua_cadenza():
    from snapprobe.scanner import DEFAULT_CADENCES, STAGES

    assert "web" in STAGES
    assert DEFAULT_CADENCES["web"] > 0


def test_la_fase_web_non_usa_nmap(probe_store):
    """E' la prima fase che non passa da nmap: chiedere argomenti per essa sarebbe un
    errore silenzioso, e qui si dichiara che il percorso e' un altro."""
    from pathlib import Path

    sorgente = (Path(__file__).resolve().parent.parent
                / "probe/snapprobe/scanner.py").read_text(encoding="utf-8")

    assert '_run_web_task' in sorgente
    assert 'if stage == "web":' in sorgente
    assert "lettura HTTP interna" in sorgente, (
        "la telemetria deve dire che non c'e' stato nessun processo esterno")


# --------------------------------------------------------------------------- #
# Il server: che cosa conserva e che cosa no
# --------------------------------------------------------------------------- #
def _tenant_e_nodo(server_app, ip="10.6.0.5"):
    """Un tenant, una sonda e un dispositivo: il conferimento richiede tutti tre."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
        adesso = utc_now_str()
        sonda = query("SELECT id FROM probes WHERE tenant_id = ?", (tenant_id,), one=True)
        probe_id = int(sonda["id"]) if sonda else execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, created_at,"
            " updated_at) VALUES (?, 'uid-web', 'sonda-web', 'Sonda web', 'active', ?, ?)",
            (tenant_id, adesso, adesso))
        node_id = execute(
            "INSERT INTO nodes (tenant_id, probe_id, ip, status, first_seen_at,"
            " last_seen_at, created_at, updated_at)"
            " VALUES (?, ?, ?, 'up', ?, ?, ?, ?)",
            (tenant_id, probe_id, ip, adesso, adesso, adesso, adesso))
        return tenant_id, node_id


def _applica_web(server_app, tenant_id, ip, pagine, uid="lotto-web"):
    """Conferisce un lotto con le sole letture web, come farebbe la sonda."""
    import uuid

    with server_app.app_context():
        from snapserver.db import query
        from snapserver.ingest import apply_batch

        sonda = query("SELECT id FROM probes WHERE tenant_id = ?", (tenant_id,), one=True)
        return apply_batch(tenant_id, int(sonda["id"]), {
            "batch_uid": "%s-%s" % (uid, uuid.uuid4().hex[:8]),
            "records": {"web": [{"ip": ip, "pages": pagine}]}})


def test_la_lettura_web_si_conserva_per_porta(server_app):
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.0.5")

    _applica_web(server_app, tenant_id, "10.6.0.5", [
        {"port": 443, "scheme": "https", "stato": 200, "titolo": "FortiGate",
         "marca": "Fortinet", "prodotto": "Fortinet FortiOS", "firma": "fortigate",
         "tipo_probabile": "firewall", "cert_soggetto": "FGT60F", "cert_a": "2027-01-01",
         "cert_autofirmato": True, "tls_versione": "TLSv1.3", "modulo_accesso": True,
         "corpo_impronta": "abc123", "corpo_byte": 4096},
        {"port": 80, "scheme": "http", "stato": 302},
    ])

    with server_app.app_context():
        from snapserver.db import query

        righe = query("SELECT * FROM node_web WHERE node_id = ? ORDER BY port",
                      (node_id,))

    assert len(righe) == 2
    assert righe[0]["port"] == 80
    cifrata = righe[1]
    assert cifrata["brand"] == "Fortinet"
    assert cifrata["signature"] == "fortigate"
    assert cifrata["cert_selfsigned"] == 1
    assert cifrata["login_form"] == 1
    assert cifrata["tls_version"] == "TLSv1.3"


def test_il_corpo_della_pagina_non_si_conserva(server_app):
    """Una pagina interna puo' contenere nomi e recapiti: dati personali di cui il
    prodotto non ha bisogno (GDPR art. 5, minimizzazione)."""
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.0.6")

    _applica_web(server_app, tenant_id, "10.6.0.6", [
        {"port": 80, "stato": 200, "titolo": "Intranet",
         "corpo_impronta": "f00", "corpo_byte": 8192},
    ])

    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT * FROM node_web WHERE node_id = ?", (node_id,), one=True)

    colonne = riga.keys()
    assert "body_hash" in colonne and riga["body_hash"] == "f00"
    assert riga["body_bytes"] == 8192
    assert not any(c in colonne for c in ("body", "corpo", "html", "content")), (
        "nessuna colonna conserva il contenuto della pagina")


def test_una_seconda_lettura_aggiorna_la_riga_non_la_duplica(server_app):
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.0.7")

    _applica_web(server_app, tenant_id, "10.6.0.7",
                 [{"port": 443, "stato": 200, "titolo": "prima"}])
    _applica_web(server_app, tenant_id, "10.6.0.7",
                 [{"port": 443, "stato": 401, "titolo": "seconda"}])

    with server_app.app_context():
        from snapserver.db import query

        righe = query("SELECT title, status_code FROM node_web WHERE node_id = ?",
                      (node_id,))

    assert len(righe) == 1, "una riga per porta: la lettura si aggiorna"
    assert righe[0]["title"] == "seconda"
    assert righe[0]["status_code"] == 401


def test_una_lettura_per_un_nodo_sconosciuto_non_crea_il_nodo(server_app):
    """Vale la regola degli altri record: un nodo non in inventario non viene creato
    implicitamente, e il lotto non diventa intrasmissibile."""
    # Il preparatore crea tenant e sonda; il nodo di cui si parla non esiste.
    tenant_id, _ = _tenant_e_nodo(server_app, "10.6.98.1")

    esito = _applica_web(server_app, tenant_id, "10.6.99.99",
                         [{"port": 80, "stato": 200}])

    assert esito["orphans"], "l'orfano viene dichiarato"
    with server_app.app_context():
        from snapserver.db import query

        assert query("SELECT id FROM nodes WHERE ip = '10.6.99.99'", (), one=True) is None


# --------------------------------------------------------------------------- #
# Il riconoscimento
# --------------------------------------------------------------------------- #
def test_la_pagina_di_gestione_decide_il_tipo_di_dispositivo():
    """Una pagina che si presenta con marca e modello e' una dichiarazione
    dell'apparato, non un indizio: vale come una lettura SNMP."""
    from snapserver.fingerprint import identify

    verdetto = identify({
        "ip": "10.6.0.8",
        "ports": [{"protocol": "tcp", "port": 443, "state": "open"}],
        "web": [{"port": 443, "device_type": "printer", "brand": "HP",
                 "model": "LaserJet MFP M428", "title": "HP LaserJet"}],
    })

    assert verdetto["device_type"] == "printer"
    assert verdetto["confidence"] >= 90
    assert "interfaccia web" in verdetto["evidence"][0]["prova"]
    assert "HP" in verdetto["evidence"][0]["prova"], (
        "il verdetto dichiara su che cosa poggia")


def test_una_pagina_senza_genere_riconosciuto_non_decide_da_sola():
    """Un server web generico non dice che tipo di dispositivo c'e' dietro: nginx gira
    su un NAS come su un router."""
    from snapserver.fingerprint import identify

    verdetto = identify({
        "ip": "10.6.0.9",
        "ports": [{"protocol": "tcp", "port": 80, "state": "open"}],
        "web": [{"port": 80, "product": "nginx", "version": "1.24.0"}],
    })

    assert verdetto["device_type"] != "printer"
    assert verdetto["confidence"] < 93 or verdetto["device_type"] == "unknown"


def test_le_prove_del_nodo_comprendono_le_letture_web(server_app):
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.0.10")
    _applica_web(server_app, tenant_id, "10.6.0.10", [
        {"port": 443, "stato": 200, "titolo": "Synology DiskStation",
         "marca": "Synology", "tipo_probabile": "nas", "firma": "synology"},
    ])

    with server_app.app_context():
        from snapserver.ingest import build_evidence

        prove = build_evidence(tenant_id, node_id)

    assert prove["web"], "le letture web stanno fra le prove"
    assert prove["web"][0]["brand"] == "Synology"


def test_le_letture_web_entrano_nel_documento_json(server_app):
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.0.11")
    _applica_web(server_app, tenant_id, "10.6.0.11",
                 [{"port": 8443, "scheme": "https", "stato": 200, "titolo": "iLO 5",
                   "marca": "HPE", "firma": "ilo", "tipo_probabile": "server"}])

    with server_app.app_context():
        from snapserver.node_json import documento

        dati = documento(tenant_id, node_id)

    assert dati["conteggi"]["letture_web"] == 1
    assert dati["letture_web"][0]["brand"] == "HPE"


def test_la_scheda_delle_interfacce_web_compare_nella_pagina(logged_client, server_app):
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.0.12")
    _applica_web(server_app, tenant_id, "10.6.0.12",
                 [{"port": 80, "stato": 200, "titolo": "Stampante di reparto",
                   "marca": "Kyocera", "firma": "kyocera", "tipo_probabile": "printer"}])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/nodes/%d" % node_id).get_data(as_text=True)

    assert "Interfacce web" in pagina
    assert "Kyocera" in pagina
    assert "contenuto della" in pagina, (
        "va detto che il contenuto della pagina non viene conservato")


# --------------------------------------------------------------------------- #
# Il contratto fra le due parti
# --------------------------------------------------------------------------- #
def test_ogni_genere_che_la_sonda_confierisce_la_console_lo_sa_applicare():
    """Le due estremita' del conferimento devono conoscere gli stessi generi.

    E' il difetto emerso con la lettura delle interfacce web: la sonda accodava record
    di genere "web", il contratto non li prevedeva e venivano scartati. Un genere in
    piu' da una parte sola non fa rumore -- semplicemente il dato non arriva mai.
    """
    from snapprobe.agent import RECORD_TYPES
    from snapserver.ingest import _APPLICATORI

    mancanti = set(RECORD_TYPES) - set(_APPLICATORI)
    assert not mancanti, "la console non sa applicare: %s" % sorted(mancanti)


def test_le_letture_web_arrivano_alla_console_come_record_propri():
    """La traduzione del genere e' il passaggio che mancava."""
    from snapprobe.agent import record_type_of

    assert record_type_of("web") == "web"


# --------------------------------------------------------------------------- #
# Dalla pagina all'inventario
# --------------------------------------------------------------------------- #
LETTURA_RICOH = {
    "port": 80, "scheme": "http", "stato": 200, "titolo": "Web Image Monitor",
    "server": "Web-Server/3.0", "marca": "Ricoh", "modello": "MP C4504ex",
    "prodotto": "Ricoh (Web Image Monitor)", "firma": "ricoh",
    "tipo_probabile": "printer", "modulo_accesso": False,
    "corpo_impronta": "014d47b592a7", "corpo_byte": 577, "pagine_lette": 4,
    "fatti": {"nome_dispositivo": "RICOH MP C4504ex",
              "posizione": "UFFICIO 12 - PIANO 1",
              "nome_host": "stampante-piano1"},
    "pagine": [{"percorso": "/", "origine": "radice", "stato": 200},
               {"percorso": "/web/guest/it/websys/webArch/topPage.cgi",
                "origine": "frame", "stato": 200}],
}


def test_i_fatti_dichiarati_finiscono_in_colonna(server_app):
    """Nel dettaglio JSON c'erano gia'; in colonna si possono cercare, ordinare e
    mettere in un report -- ed e' cio' che se ne fa."""
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.21")

    _applica_web(server_app, tenant_id, "10.6.9.21", [LETTURA_RICOH])

    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT device_name, location, host_name, model, pages_read,"
                     " facts_locked FROM node_web WHERE node_id = ?",
                     (node_id,), one=True)
    assert riga["device_name"] == "RICOH MP C4504ex"
    assert riga["location"] == "UFFICIO 12 - PIANO 1"
    assert riga["host_name"] == "stampante-piano1"
    assert riga["model"] == "MP C4504ex"
    assert riga["pages_read"] == 4
    assert riga["facts_locked"] == 0


def test_la_posizione_fisica_e_l_unico_dato_che_nessun_altra_fase_ricava(server_app):
    """Non sta in rete: sta scritta sull'apparato da chi lo ha installato."""
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.22")

    _applica_web(server_app, tenant_id, "10.6.9.22", [LETTURA_RICOH])

    with server_app.app_context():
        from snapserver.ingest import build_evidence

        prove = build_evidence(tenant_id, node_id)
    voce = prove["web"][0]
    assert voce["location"] == "UFFICIO 12 - PIANO 1"
    assert voce["device_name"] == "RICOH MP C4504ex"


def test_il_riconoscimento_cita_il_nome_che_l_apparato_dichiara(server_app):
    """Una motivazione si verifica aprendo quella pagina: per questo dice il nome
    testualmente invece di "si presenta come una stampante"."""
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.23")
    _applica_web(server_app, tenant_id, "10.6.9.23", [LETTURA_RICOH])

    with server_app.app_context():
        from snapserver.fingerprint import identify
        from snapserver.ingest import build_evidence

        verdetto = identify(build_evidence(tenant_id, node_id))

    assert verdetto["device_type"] == "printer"
    assert verdetto["confidence"] >= 95
    motivi = " ".join(prova["prova"] for prova in verdetto["evidence"])
    assert "RICOH MP C4504ex" in motivi


LETTURA_CISCO_PHONE = {
    "port": 80, "scheme": "http", "stato": 200, "titolo": "Cisco Systems, Inc.",
    "marca": "Cisco", "modello": "CP-7962G", "prodotto": "Cisco Unified IP Phone",
    "firma": "cisco-ip-phone", "tipo_probabile": "voip_phone", "pagine_lette": 3,
    "corpo_impronta": "cf01", "corpo_byte": 900,
    "fatti": {"mac": "001122334455", "nome_host": "SEP001122334455",
              "numero_interno": "1000", "carico_software": "jar42sccp.9-4-2ES26.sbn",
              "carico_avvio": "tnp62.8-3-1-21a.bin", "firmware": "*SCCP42.9-4-2SR3-1S*",
              "revisione_hw": "13.0", "seriale": "ABC1234567X", "modello": "CP-7962G",
              "gestore_chiamate": "10.0.0.101 Attivo", "server_tftp": "10.0.0.101"},
    "pagine": [{"percorso": "/", "origine": "radice", "stato": 200},
               {"percorso": "/NetworkConfigurationX", "origine": "percorso noto",
                "stato": 200},
               {"percorso": "/DeviceInformationX", "origine": "percorso noto",
                "stato": 200}],
}


def test_del_telefono_cisco_si_conservano_tutte_le_etichette(server_app):
    """L'apparato dichiara una decina di dati tecnici: quelli con una colonna vanno in
    colonna, tutti gli altri (interno, carichi, gestore chiamate, server TFTP) restano
    nel campo dei fatti, cosi' il dettaglio li puo' mostrare."""
    import json

    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.30")
    _applica_web(server_app, tenant_id, "10.6.9.30", [LETTURA_CISCO_PHONE])

    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT model, host_name, serial, firmware, facts_json"
                     " FROM node_web WHERE node_id = ?", (node_id,), one=True)
    assert riga["model"] == "CP-7962G"
    assert riga["host_name"] == "SEP001122334455"
    assert riga["serial"] == "ABC1234567X"
    assert riga["firmware"] == "*SCCP42.9-4-2SR3-1S*"
    fatti = json.loads(riga["facts_json"])
    assert fatti["numero_interno"] == "1000"
    assert fatti["gestore_chiamate"].startswith("10.0.0.101")
    assert fatti["carico_software"] == "jar42sccp.9-4-2ES26.sbn"


def test_i_dati_del_telefono_cisco_compaiono_nel_dettaglio(logged_client, server_app):
    """Nel dettaglio del nodo, oltre a modello e serie, si vedono i dati aggiuntivi che
    non hanno una colonna propria: l'interno, i carichi, il gestore chiamate."""
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.31")
    _applica_web(server_app, tenant_id, "10.6.9.31", [LETTURA_CISCO_PHONE])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/nodes/%d" % node_id).get_data(as_text=True)

    assert "Numero interno" in pagina and "1000" in pagina
    assert "Gestore chiamate (CUCM)" in pagina
    assert "Carico software (app)" in pagina


def test_la_pagina_del_telefono_cisco_ne_decide_il_tipo(server_app):
    """La firma emette la chiave esatta della classe (voip_phone): la regola decisiva
    scatta e il nodo si classifica come Telefono VoIP citando marca e modello."""
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.32")
    _applica_web(server_app, tenant_id, "10.6.9.32", [LETTURA_CISCO_PHONE])

    with server_app.app_context():
        from snapserver.fingerprint import identify
        from snapserver.ingest import build_evidence

        verdetto = identify(build_evidence(tenant_id, node_id))

    assert verdetto["device_type"] == "voip_phone"
    assert verdetto["confidence"] >= 93
    motivi = " ".join(prova["prova"] for prova in verdetto["evidence"])
    assert "CP-7962G" in motivi


LETTURA_HTTPS = {
    "port": 443, "scheme": "https", "stato": 200, "titolo": "iDRAC9",
    "marca": "Dell", "prodotto": "Dell iDRAC", "firma": "idrac",
    "tipo_probabile": "server", "modulo_accesso": True,
    "corpo_impronta": "aa11", "corpo_byte": 2048,
    # I campi del certificato come li produce la sonda.
    "tls_versione": "TLSv1.3", "tls_cifrario": "TLS_AES_256_GCM_SHA384",
    "cert_soggetto": "idrac-XYZ.local", "cert_emittente": "Dell CA",
    "cert_soggetto_dn": "CN=idrac-XYZ.local,O=Dell",
    "cert_emittente_dn": "CN=Dell CA,O=Dell",
    "cert_a": "2027-01-01", "cert_valido_da": "2025-01-01 00:00:00 UTC",
    "cert_valido_a": "2027-01-01 00:00:00 UTC", "cert_autofirmato": True,
    "cert_scaduto": False, "cert_giorni_residui": 400, "cert_seriale": "1A2B3C",
    "cert_versione": "v3", "cert_algoritmo_firma": "sha256", "cert_chiave": "RSA 2048 bit",
    "cert_sha256": "a" * 64, "cert_sha1": "b" * 40,
    "cert_nomi": ["idrac-XYZ.local", "10.6.9.40"], "cert_uso": ["firma digitale"],
    "cert_uso_esteso": ["autenticazione server"],
    "pagine": [{"percorso": "/", "origine": "radice", "stato": 200}],
}


def test_di_un_https_si_conservano_tutti_i_dati_del_certificato(server_app):
    """Dove c'e' HTTPS si registra tutto: i pochi campi con colonna vanno in colonna,
    tutti gli altri (serie, algoritmo, chiave, impronte, SAN, usi) nel campo del
    certificato, cosi' il dettaglio li puo' mostrare."""
    import json

    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.40")
    _applica_web(server_app, tenant_id, "10.6.9.40", [LETTURA_HTTPS])

    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT cert_subject, cert_expires, cert_selfsigned, tls_version,"
                     " cert_json FROM node_web WHERE node_id = ?", (node_id,), one=True)
    assert riga["cert_subject"] == "idrac-XYZ.local"
    assert riga["cert_selfsigned"] == 1
    assert riga["tls_version"] == "TLSv1.3"
    cert = json.loads(riga["cert_json"])
    assert cert["cert_seriale"] == "1A2B3C"
    assert cert["cert_algoritmo_firma"] == "sha256"
    assert cert["cert_chiave"] == "RSA 2048 bit"
    assert cert["cert_sha256"] == "a" * 64
    assert cert["cert_uso_esteso"] == ["autenticazione server"]


def test_il_certificato_completo_compare_nel_dettaglio(logged_client, server_app):
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.41")
    _applica_web(server_app, tenant_id, "10.6.9.41", [LETTURA_HTTPS])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/nodes/%d" % node_id).get_data(as_text=True)

    assert "Certificato TLS" in pagina
    assert "Numero di serie" in pagina and "1A2B3C" in pagina
    assert "Algoritmo di firma" in pagina and "sha256" in pagina
    assert "RSA 2048 bit" in pagina
    assert "autofirmato" in pagina, "l'esito di sicurezza va visto a colpo d'occhio"


def test_una_pagina_protetta_si_conserva_come_tale(server_app):
    """La pagina con i dati esiste ma chiede le credenziali: va detto, altrimenti
    sembra che l'apparato non dichiari niente."""
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.24")

    _applica_web(server_app, tenant_id, "10.6.9.24", [
        {"port": 80, "scheme": "http", "stato": 200, "titolo": "IP Phone",
         "tipo_probabile": "voip", "firma": "telefono-ip", "fatti_protetti": True,
         "pagine_lette": 2}])

    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT facts_locked, device_name, pages_read FROM node_web"
                     " WHERE node_id = ?", (node_id,), one=True)
    assert riga["facts_locked"] == 1
    assert riga["device_name"] is None
    assert riga["pages_read"] == 2


def test_un_record_senza_fatti_non_scrive_colonne_vuote(server_app):
    """Le vecchie letture non hanno il dizionario dei fatti: il conferimento deve
    accettarle senza inventare valori."""
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.25")

    _applica_web(server_app, tenant_id, "10.6.9.25", [
        {"port": 8080, "scheme": "http", "stato": 200, "titolo": "Grafana"}])

    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT device_name, location, pages_read FROM node_web"
                     " WHERE node_id = ?", (node_id,), one=True)
    assert riga["device_name"] is None
    assert riga["location"] is None
    assert riga["pages_read"] == 0


def test_i_fatti_compaiono_nella_scheda_del_dispositivo(logged_client, server_app):
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.26")
    _applica_web(server_app, tenant_id, "10.6.9.26", [LETTURA_RICOH])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/nodes/%d" % node_id).get_data(as_text=True)

    assert "Dichiarato dall'apparato" in pagina
    assert "UFFICIO 12 - PIANO 1" in pagina
    assert "stampante-piano1" in pagina
    assert "4 pagine lette" in pagina


def test_i_fatti_compaiono_nel_documento_json(logged_client, server_app):
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.27")
    _applica_web(server_app, tenant_id, "10.6.9.27", [LETTURA_RICOH])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.get("/inventory/nodes/%d/json" % node_id)
    documento = risposta.get_json()

    voce = documento["letture_web"][0] if "letture_web" in documento else None
    if voce is None:  # il documento nomina la sezione in un altro modo
        voce = (documento.get("web") or [{}])[0]
    assert voce.get("location") == "UFFICIO 12 - PIANO 1"
    assert voce.get("device_name") == "RICOH MP C4504ex"


# --------------------------------------------------------------------------- #
# Il produttore nell'elenco dei nodi
# --------------------------------------------------------------------------- #
def test_il_produttore_dichiarato_dalla_pagina_arriva_nell_elenco(server_app):
    """"Stampante" dice cosa fa il dispositivo; "Ricoh" dice con chi si parla per
    farla aggiornare. Nell'elenco servono entrambe le cose."""
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.30")
    _applica_web(server_app, tenant_id, "10.6.9.30", [LETTURA_RICOH])

    with server_app.app_context():
        from snapserver.inventory_queries import nodes_list

        nodi = {r["ip"]: r for r in nodes_list(tenant_id)}
    assert nodi["10.6.9.30"]["web_vendor"] == "Ricoh"


def test_senza_lettura_web_il_produttore_resta_vuoto(server_app):
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.31")

    with server_app.app_context():
        from snapserver.inventory_queries import nodes_list

        nodi = {r["ip"]: r for r in nodes_list(tenant_id)}
    assert nodi["10.6.9.31"]["web_vendor"] is None


def test_la_pagina_dei_nodi_mostra_il_produttore(logged_client, server_app):
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.32")
    _applica_web(server_app, tenant_id, "10.6.9.32", [LETTURA_RICOH])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/nodes").get_data(as_text=True)

    assert "Ricoh" in pagina
    assert "Dichiarato dalla pagina di gestione" in pagina, (
        "le tre fonti del produttore non valgono lo stesso: la fonte si dichiara")


def test_una_pagina_senza_marca_non_inventa_un_produttore(server_app):
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.33")
    _applica_web(server_app, tenant_id, "10.6.9.33", [
        {"port": 80, "scheme": "http", "stato": 200, "titolo": "Object Store"}])

    with server_app.app_context():
        from snapserver.inventory_queries import nodes_list

        nodi = {r["ip"]: r for r in nodes_list(tenant_id)}
    assert nodi["10.6.9.33"]["web_vendor"] is None


# --------------------------------------------------------------------------- #
# Il produttore nella scheda del dispositivo
# --------------------------------------------------------------------------- #
def test_il_produttore_dichiarato_vince_sul_costruttore_del_mac(server_app):
    """Il MAC dice chi ha fatto la SCHEDA DI RETE, non sempre chi ha fatto l'apparato,
    e manca quasi sempre: si vede solo se la sonda sta nello stesso segmento."""
    with server_app.app_context():
        from snapserver.blueprints.inventory import _produttore

        esito = _produttore({"mac_vendor": "Intel Corporate", "os_vendor": ""},
                            [{"brand": "Kyocera", "model": "ECOSYS M5526cdn"}])

    assert esito["nome"] == "Kyocera"
    assert esito["fonte"] == "dichiarato dall'apparato"
    assert esito["modello"] == "ECOSYS M5526cdn"
    assert esito["scheda_di_rete"] == "Intel Corporate", (
        "un apparato con la scheda di rete di un altro costruttore e' un fatto")


def test_senza_dichiarazione_vale_il_mac_e_lo_dice(server_app):
    with server_app.app_context():
        from snapserver.blueprints.inventory import _produttore

        esito = _produttore({"mac_vendor": "Hewlett Packard", "os_vendor": ""}, [])

    assert esito["nome"] == "Hewlett Packard"
    assert "MAC" in esito["fonte"]


def test_senza_mac_vale_il_rilevamento_del_sistema(server_app):
    """E' il caso segnalato: il produttore mancava perche' si guardava solo il MAC."""
    with server_app.app_context():
        from snapserver.blueprints.inventory import _produttore

        esito = _produttore({"mac_vendor": "", "os_vendor": "Cisco"}, [])

    assert esito["nome"] == "Cisco"
    assert "sistema operativo" in esito["fonte"]


def test_la_stessa_marca_non_si_ripete(server_app):
    with server_app.app_context():
        from snapserver.blueprints.inventory import _produttore

        esito = _produttore({"mac_vendor": "Kyocera Document Solutions",
                             "os_vendor": ""}, [{"brand": "Kyocera"}])

    assert esito["scheda_di_rete"] == ""


def test_senza_nessuna_fonte_non_si_inventa_niente(server_app):
    with server_app.app_context():
        from snapserver.blueprints.inventory import _produttore

        esito = _produttore({"mac_vendor": "", "os_vendor": ""}, [])

    assert esito["nome"] == "" and esito["fonte"] == ""


def test_la_scheda_del_nodo_mostra_il_produttore_dichiarato(logged_client, server_app):
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.40")
    _applica_web(server_app, tenant_id, "10.6.9.40", [LETTURA_RICOH])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/nodes/%d" % node_id).get_data(as_text=True)

    assert "dichiarato dall" in pagina, "la fonte si dichiara"
    assert "MP C4504ex" in pagina


# --------------------------------------------------------------------------- #
# Il PDF della lettura
# --------------------------------------------------------------------------- #
def test_il_pdf_della_lettura_si_scarica(logged_client, server_app):
    """Si allega a una richiesta di intervento: dice che apparato e', dove sta e da
    quali pagine lo si e' saputo."""
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.50")
    _applica_web(server_app, tenant_id, "10.6.9.50", [LETTURA_RICOH])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.get("/inventory/nodes/%d/web.pdf" % node_id)

    assert risposta.status_code == 200
    assert risposta.mimetype == "application/pdf"
    assert risposta.data[:5] == b"%PDF-"
    assert len(risposta.data) > 2000


def test_il_pdf_della_lettura_porta_i_fatti_e_il_percorso(logged_client, server_app):
    pypdf = pytest.importorskip("pypdf")
    import io

    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.51")
    _applica_web(server_app, tenant_id, "10.6.9.51", [LETTURA_RICOH])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    dati = logged_client.get("/inventory/nodes/%d/web.pdf" % node_id).data
    lettore = pypdf.PdfReader(io.BytesIO(dati))
    testo = "\n".join((p.extract_text() or "") for p in lettore.pages)

    assert "UFFICIO 12 - PIANO 1" in testo
    assert "RICOH MP C4504ex" in testo
    assert "topPage.cgi" in testo, "il percorso delle pagine rende verificabile il dato"
    assert "non c" in testo and "immagine della pagina" in testo, (
        "il documento dice perche' non contiene l'immagine della pagina")


def test_lo_scarico_del_pdf_resta_nel_registro(logged_client, server_app):
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.52")
    _applica_web(server_app, tenant_id, "10.6.9.52", [LETTURA_RICOH])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    logged_client.get("/inventory/nodes/%d/web.pdf" % node_id)

    with server_app.app_context():
        from snapserver.db import query

        tracce = query("SELECT description FROM audit_events"
                       " WHERE event_type = 'node.web.pdf'", ())
    assert tracce and "10.6.9.52" in tracce[-1]["description"]


def test_senza_letture_non_c_e_niente_da_stampare(logged_client, server_app):
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.53")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    assert logged_client.get("/inventory/nodes/%d/web.pdf" % node_id).status_code == 404


def test_il_pdf_di_un_nodo_di_un_altro_tenant_non_si_scarica(logged_client, server_app):
    tenant_id, node_id = _tenant_e_nodo(server_app, "10.6.9.54")
    _applica_web(server_app, tenant_id, "10.6.9.54", [LETTURA_RICOH])
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        altro = execute("INSERT INTO tenants (name, code, timezone, created_at,"
                        " updated_at) VALUES ('Altro', 'altro-pdf', 'Europe/Rome', ?, ?)",
                        (utc_now_str(), utc_now_str()))
    logged_client.post("/switch-tenant", data={"tenant_id": altro},
                       follow_redirects=True)

    risposta = logged_client.get("/inventory/nodes/%d/web.pdf" % node_id)

    assert risposta.status_code in (403, 404)
