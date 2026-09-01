"""
snap - Test del motore di identificazione del tipo di dispositivo.

Verificano tre proprieta' che il progetto dichiara e che sono facili da perdere
con l'evoluzione del catalogo:
  * correttezza: dispositivi tipici riconosciuti, casi ambigui dichiarati incerti;
  * robustezza: le prove contrarie impediscono le classificazioni per accumulo;
  * efficienza: lo stadio indicizzato produce gli stessi punteggi di una
    valutazione esaustiva del catalogo (l'indice e' un'ottimizzazione, non un
    cambio di semantica).

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re

import pytest

from snapserver import fingerprint as fp


# --------------------------------------------------------------------------- #
# Costruzione delle prove
# --------------------------------------------------------------------------- #
def prove(ports=(), os=None, mac=None, mac_vendor=None, hostname=None, scripts=None,
          ttl=None):
    """Compone l'insieme di prove nel formato conferito dalla sonda."""
    return {
        "ip": "10.10.0.9",
        "ttl": ttl,
        "mac": mac,
        "mac_vendor": mac_vendor,
        "hostname": hostname,
        "ports": [
            {
                "protocol": p[0], "port": p[1], "state": "open",
                "service_name": p[2] if len(p) > 2 else None,
                "product": p[3] if len(p) > 3 else None,
                "version": p[4] if len(p) > 4 else None,
                "cpe": [],
            }
            for p in ports
        ],
        "os": os or {},
        "scripts": scripts or {},
    }


# --------------------------------------------------------------------------- #
# Integrita' del catalogo
# --------------------------------------------------------------------------- #
def test_le_chiavi_delle_classi_sono_uniche():
    chiavi = [c["key"] for c in fp.DEVICE_CLASSES]
    assert len(chiavi) == len(set(chiavi)), "chiavi duplicate: %s" % chiavi
    assert fp.UNKNOWN["key"] not in chiavi, "'unknown' non e' una classe del catalogo"


def test_ogni_classe_dichiara_etichetta_e_icona():
    for classe in fp.DEVICE_CLASSES:
        assert classe.get("label"), "classe %s senza etichetta" % classe["key"]
        assert str(classe.get("icon", "")).startswith("bi-"), (
            "classe %s senza icona Bootstrap" % classe["key"]
        )


def test_i_pesi_hanno_il_segno_corretto():
    for classe in fp.DEVICE_CLASSES:
        for genere in ("ports", "services", "os_types", "os_families"):
            for prova, peso in classe.get(genere, {}).items():
                assert peso >= 0, "%s: peso negativo in %s (%s)" % (classe["key"], genere, prova)
        for porta, peso in classe.get("negative_ports", {}).items():
            assert peso < 0, "%s: prova contraria con peso non negativo (%s)" % (classe["key"], porta)


def test_tutte_le_espressioni_del_catalogo_sono_valide():
    for classe in fp.DEVICE_CLASSES:
        for genere in ("products", "mac_vendors", "hostnames"):
            for espressione, _ in classe.get(genere, ()):
                re.compile(espressione)  # solleva se non valida
        for _, espressione, _ in classe.get("scripts", ()):
            re.compile(espressione)


def test_il_verdetto_dichiara_sempre_la_versione_del_catalogo():
    esito = fp.identify(prove(ports=[("tcp", 22, "ssh")]))
    assert esito["catalog_version"] == fp.CATALOG_VERSION


# --------------------------------------------------------------------------- #
# Riconoscimento di dispositivi tipici
# --------------------------------------------------------------------------- #
CASI = [
    (
        "stampante di rete",
        prove(ports=[("tcp", 9100, "jetdirect", "HP LaserJet 4250"), ("tcp", 80, "http"),
                     ("udp", 161, "snmp")],
              mac_vendor="Hewlett Packard", hostname="NPI4A2B3C"),
        "printer",
    ),
    (
        "NAS Synology",
        prove(ports=[("tcp", 5000, "http", "Synology DiskStation"), ("tcp", 445, "microsoft-ds"),
                     ("tcp", 22, "ssh"), ("tcp", 2049, "nfs")],
              mac_vendor="Synology Incorporated", hostname="nas-sede"),
        "nas",
    ),
    (
        "switch gestito Cisco",
        prove(ports=[("tcp", 22, "ssh"), ("tcp", 23, "telnet"), ("udp", 161, "snmp")],
              os={"type": "switch", "family": "IOS", "vendor": "Cisco"},
              mac_vendor="Cisco Systems", hostname="sw-core-01"),
        "switch_managed",
    ),
    (
        "telecamera IP",
        prove(ports=[("tcp", 554, "rtsp", "Hikvision DS-2CD"), ("tcp", 80, "http")],
              mac_vendor="Hangzhou Hikvision Digital Technology", hostname="cam-ingresso"),
        "ip_camera",
    ),
    (
        "telefono VoIP",
        prove(ports=[("udp", 5060, "sip", "Yealink SIP-T46S"), ("tcp", 80, "http")],
              mac_vendor="Yealink Network Technology"),
        "voip_phone",
    ),
    (
        "controllore industriale",
        prove(ports=[("tcp", 102, "iso-tsap", "Siemens SIMATIC S7")],
              mac_vendor="Siemens AG"),
        "plc_industrial",
    ),
    (
        "gruppo di continuita'",
        prove(ports=[("tcp", 80, "http"), ("udp", 161, "snmp")],
              mac_vendor="American Power Conversion", hostname="ups-ced",
              scripts={"snmp-info": "APC Smart-UPS 3000 PowerChute"}),
        "ups",
    ),
    (
        "server Windows con Active Directory",
        prove(ports=[("tcp", 389, "ldap"), ("tcp", 88, "kerberos-sec"), ("tcp", 445, "microsoft-ds"),
                     ("tcp", 3389, "ms-wbt-server"), ("tcp", 53, "domain")],
              os={"family": "Windows", "name": "Windows Server 2022", "type": "general purpose"},
              hostname="dc01"),
        "server_windows",
    ),
    (
        "server Linux con banca dati",
        prove(ports=[("tcp", 22, "ssh", "OpenSSH 9.2"), ("tcp", 443, "https", "nginx 1.24"),
                     ("tcp", 5432, "postgresql", "PostgreSQL 15")],
              os={"family": "Linux", "name": "Linux 5.15", "type": "general purpose"},
              hostname="db-app-01"),
        "server_unix",
    ),
    (
        "postazione Windows",
        prove(ports=[("tcp", 135, "msrpc"), ("tcp", 139, "netbios-ssn"), ("tcp", 445, "microsoft-ds"),
                     ("tcp", 5357, "wsdapi")],
              os={"family": "Windows", "name": "Windows 11 24H2", "type": "general purpose"},
              hostname="PC-UFFICIO-12"),
        "workstation_windows",
    ),
    (
        "postazione macOS",
        prove(ports=[("tcp", 22, "ssh"), ("tcp", 548, "afp"), ("tcp", 5900, "rfb"),
                     ("udp", 5353, "mdns")],
              os={"family": "Mac OS X", "name": "Apple macOS 14", "type": "general purpose"},
              mac_vendor="Apple, Inc."),
        "workstation_mac",
    ),
    (
        "scheda a basso costo",
        prove(ports=[("tcp", 22, "ssh", "OpenSSH 9.2")],
              os={"family": "Linux", "type": "general purpose"},
              mac="B8:27:EB:1A:2B:3C", mac_vendor="Raspberry Pi Foundation",
              hostname="raspberrypi"),
        "sbc",
    ),
    (
        "ipervisore",
        prove(ports=[("tcp", 443, "https", "VMware ESXi 8.0"), ("tcp", 902, "vmware-auth")],
              hostname="esxi-01"),
        "hypervisor",
    ),
    (
        "dispositivo multimediale",
        prove(ports=[("tcp", 1400, "http", "Sonos"), ("udp", 1900, "upnp")],
              mac_vendor="Sonos, Inc.", hostname="sonos-salotto"),
        "media_device",
    ),
]


@pytest.mark.parametrize("descrizione,evidenze,atteso", CASI, ids=[c[0] for c in CASI])
def test_i_dispositivi_tipici_sono_riconosciuti(descrizione, evidenze, atteso):
    esito = fp.identify(evidenze)
    assert esito["device_type"] == atteso, (
        "%s classificato come %s (punteggi: %s)"
        % (descrizione, esito["device_type"], esito["scores"])
    )


@pytest.mark.parametrize("descrizione,evidenze,atteso", CASI, ids=[c[0] for c in CASI])
def test_ogni_verdetto_porta_le_proprie_prove(descrizione, evidenze, atteso):
    """Nessun verdetto senza motivazione (requisito di spiegabilita' NFR-22)."""
    esito = fp.identify(evidenze)
    assert esito["evidence"], "%s: verdetto senza prove" % descrizione
    assert esito["decided_by"] in ("regola decisiva", "punteggio")


# --------------------------------------------------------------------------- #
# Robustezza
# --------------------------------------------------------------------------- #
def test_le_prove_contrarie_impediscono_la_classificazione_per_accumulo():
    """Un server Windows che espone una porta di stampa non e' una stampante."""
    esito = fp.identify(prove(
        ports=[("tcp", 9100, "jetdirect"), ("tcp", 3389, "ms-wbt-server"),
               ("tcp", 445, "microsoft-ds"), ("tcp", 1433, "ms-sql-s"),
               ("tcp", 389, "ldap")],
        os={"family": "Windows", "name": "Windows Server 2019", "type": "general purpose"},
        hostname="srv-print-01"))
    assert esito["device_type"] != "printer", (
        "la porta di stampa ha prevalso sulle prove contrarie: %s" % esito["scores"]
    )
    assert esito["device_type"] == "server_windows"


def test_prove_scarse_producono_un_verdetto_incerto():
    esito = fp.identify(prove(ports=[("tcp", 80, "http")]))
    assert esito["device_type"] == fp.UNKNOWN["key"]
    assert esito["confidence"] == 0
    assert fp.needs_deep_scan(esito) is True


def test_un_nodo_senza_prove_non_solleva_eccezioni():
    esito = fp.identify({"ip": "10.0.0.1"})
    assert esito["device_type"] == fp.UNKNOWN["key"]
    assert esito["virtualization"]["virtualized"] is False


def test_la_confidenza_cresce_con_le_prove():
    scarso = fp.identify(prove(ports=[("tcp", 9100, "jetdirect")]))
    ricco = fp.identify(prove(
        ports=[("tcp", 9100, "jetdirect", "HP LaserJet"), ("tcp", 515, "printer"),
               ("tcp", 631, "ipp"), ("udp", 161, "snmp")],
        mac_vendor="Hewlett Packard", hostname="NPI112233",
        scripts={"snmp-info": "HP LaserJet MFP"}))
    assert ricco["confidence"] > scarso["confidence"]


def test_un_nodo_ambiguo_viene_mandato_all_approfondimento():
    """Confidenza bassa significa: le prove non bastano, servira' la fase 5."""
    esito = fp.identify(prove(ports=[("tcp", 22, "ssh"), ("tcp", 80, "http")],
                              os={"family": "Linux"}))
    assert fp.needs_deep_scan(esito) is True, "confidenza %d" % esito["confidence"]


# --------------------------------------------------------------------------- #
# Virtualizzazione: attributo del nodo, non tipo di dispositivo
# --------------------------------------------------------------------------- #
def test_la_virtualizzazione_e_un_attributo_e_non_una_classe():
    esito = fp.identify(prove(
        ports=[("tcp", 22, "ssh"), ("tcp", 443, "https", "nginx"), ("tcp", 3306, "mysql")],
        os={"family": "Linux", "type": "general purpose"},
        mac="00:0C:29:AB:CD:EF", mac_vendor="VMware, Inc.", hostname="web-01"))
    assert esito["device_type"] == "server_unix", "la virtualizzazione ha alterato il tipo"
    assert esito["virtualization"]["virtualized"] is True
    assert esito["virtualization"]["platform"] == "VMware"


def test_un_nodo_fisico_non_viene_dichiarato_virtuale():
    esito = fp.identify(prove(ports=[("tcp", 22, "ssh")], mac="B8:27:EB:00:11:22",
                              mac_vendor="Raspberry Pi Foundation"))
    assert esito["virtualization"]["virtualized"] is False


# --------------------------------------------------------------------------- #
# Efficienza: l'indice non cambia la semantica
# --------------------------------------------------------------------------- #
def _punteggi_esaustivi(evidenze):
    """Valutazione di riferimento: attraversa tutto il catalogo, senza indici."""
    aperte = fp._open_ports(evidenze)
    servizi = fp._service_names(evidenze)
    sistema = evidenze.get("os") or {}
    tipo = (sistema.get("type") or "").strip().lower()
    famiglia = (sistema.get("family") or "").strip().lower()

    punteggi = {}
    for classe in fp.DEVICE_CLASSES:
        totale = 0.0
        for porta, peso in classe.get("ports", {}).items():
            if porta in aperte:
                totale += peso
        for porta, peso in classe.get("negative_ports", {}).items():
            if porta in aperte:
                totale += peso
        for nome, peso in classe.get("services", {}).items():
            if nome.lower() in servizi:
                totale += peso
        for valore, peso in classe.get("os_types", {}).items():
            if tipo and valore.lower() == tipo:
                totale += peso
        for valore, peso in classe.get("os_families", {}).items():
            if famiglia and valore.lower() == famiglia:
                totale += peso
        if totale:
            punteggi[classe["key"]] = totale
    return punteggi


@pytest.mark.parametrize("descrizione,evidenze,atteso", CASI, ids=[c[0] for c in CASI])
def test_lo_stadio_indicizzato_coincide_con_la_valutazione_esaustiva(descrizione, evidenze, atteso):
    """L'indice e' un'ottimizzazione: i punteggi indicizzati devono coincidere.

    Il confronto riguarda i soli generi di regola indicizzati; le regole a
    espressione sono per costruzione valutate solo sulle candidate.
    """
    aperte = fp._open_ports(evidenze)
    servizi = fp._service_names(evidenze)
    indicizzati = {}
    for porta in aperte:
        for chiave, peso in fp.PORT_INDEX.get(porta, ()):
            indicizzati[chiave] = indicizzati.get(chiave, 0.0) + peso
        for chiave, peso in fp.NEGATIVE_INDEX.get(porta, ()):
            indicizzati[chiave] = indicizzati.get(chiave, 0.0) + peso
    for nome in servizi:
        for chiave, peso in fp.SERVICE_INDEX.get(nome, ()):
            indicizzati[chiave] = indicizzati.get(chiave, 0.0) + peso
    sistema = evidenze.get("os") or {}
    tipo = (sistema.get("type") or "").strip().lower()
    if tipo:
        for chiave, peso in fp.OSTYPE_INDEX.get(tipo, ()):
            indicizzati[chiave] = indicizzati.get(chiave, 0.0) + peso
    famiglia = (sistema.get("family") or "").strip().lower()
    if famiglia:
        for chiave, peso in fp.OSFAMILY_INDEX.get(famiglia, ()):
            indicizzati[chiave] = indicizzati.get(chiave, 0.0) + peso

    assert indicizzati == _punteggi_esaustivi(evidenze), descrizione


def test_gli_indici_coprono_tutte_le_regole_del_catalogo():
    """Nessuna regola indicizzabile deve essere rimasta fuori dagli indici."""
    attese = sum(len(c.get(g, {})) for c in fp.DEVICE_CLASSES
                 for g in ("ports", "services", "os_types", "os_families", "negative_ports"))
    presenti = sum(len(v) for indice in (fp.PORT_INDEX, fp.SERVICE_INDEX, fp.OSTYPE_INDEX,
                                         fp.OSFAMILY_INDEX, fp.NEGATIVE_INDEX)
                   for v in indice.values())
    assert presenti == attese, "%d regole indicizzate su %d dichiarate" % (presenti, attese)


def test_nessuna_espressione_contiene_caratteri_di_controllo():
    """Guardia contro gli escape mangiati dagli strumenti di scrittura.

    Un `\b` passato attraverso un heredoc di shell diventa un carattere di
    backspace: il pattern resta valido ma non corrisponde piu' a nulla, e il
    difetto e' invisibile alla lettura. E' accaduto davvero.
    """
    controllo = set(chr(c) for c in range(32)) - {"\n", "\t"}

    def verifica(espressione, dove):
        trovati = controllo & set(espressione)
        assert not trovati, "%s contiene caratteri di controllo %r: %r" % (
            dove, sorted(trovati), espressione)

    for espressione, classe, _ in fp.FIRMWARE_RULES:
        verifica(espressione, "regola di firmware %s" % classe)
    for classe in fp.DEVICE_CLASSES:
        for genere in ("products", "mac_vendors", "hostnames"):
            for espressione, _ in classe.get(genere, ()):
                verifica(espressione, "%s/%s" % (classe["key"], genere))
        for _, espressione, _ in classe.get("scripts", ()):
            verifica(espressione, "%s/scripts" % classe["key"])


def test_i_firmware_inequivocabili_decidono_da_soli():
    """Un apparato con solo ssh esposto resta identificabile dal firmware."""
    casi = [
        ("OpenWrt Chaos Calmer (Linux 3.18)", "router_gateway"),
        ("MikroTik RouterOS 6.48", "router_gateway"),
        ("pfSense 2.7", "firewall"),
        ("IPFire 2.25 firewall", "firewall"),
        ("QNAP QTS 4.2.0 (Linux 3.16)", "nas"),
        ("Synology DiskStation Manager 7", "nas"),
        ("Cisco IOS 15.1", "switch_managed"),
        ("Ubiquiti AirOS 6", "access_point"),
    ]
    for sistema, atteso in casi:
        esito = fp.identify(prove(
            ports=[("tcp", 22, "ssh")],
            os={"name": sistema, "family": "Linux", "type": "general purpose", "accuracy": 95}))
        assert esito["device_type"] == atteso, "%s classificato come %s" % (
            sistema, esito["device_type"])
        assert esito["confidence"] >= 90
        assert esito["decided_by"] == "regola decisiva"


def test_un_sistema_generico_non_scatena_le_regole_di_firmware():
    esito = fp.identify(prove(
        ports=[("tcp", 22, "ssh"), ("tcp", 443, "https")],
        os={"name": "Linux 5.15", "family": "Linux", "type": "general purpose"}))
    assert esito["decided_by"] == "punteggio"
    assert esito["device_type"] == "server_unix"


# --------------------------------------------------------------------------- #
# Banner annunciati dai servizi
# --------------------------------------------------------------------------- #
def prove_con_banner(porte, os=None, hostname=None):
    """Prove in cui ogni porta porta il proprio banner."""
    return {
        "ip": "10.10.0.9", "mac": None, "mac_vendor": None, "hostname": hostname,
        "ports": [{"protocol": "tcp", "port": p[0], "state": "open", "service_name": p[1],
                   "product": None, "version": None, "banner": p[2], "cpe": []} for p in porte],
        "os": os or {}, "scripts": {},
    }


BANNER = [
    ("stampante", [(9100, "jetdirect", "HP LaserJet 4250 printer ready")], None, "printer"),
    ("switch gestito", [(23, "telnet", "User Access Verification\nPassword:")], None,
     "switch_managed"),
    ("scheda a basso costo", [(22, "ssh", "SSH-2.0-OpenSSH_9.2p1 Raspbian-2")],
     {"family": "Linux"}, "sbc"),
    ("NAS", [(22, "ssh", "SSH-2.0-OpenSSH_8.4 QNAP")], {"family": "Linux"}, "nas"),
    ("apparato di rete", [(22, "ssh", "SSH-2.0-dropbear_2019.78 OpenWrt")],
     {"family": "Linux"}, "router_gateway"),
    ("gruppo di continuita'", [(80, "http", "APC Smart-UPS Network Management Card")],
     None, "ups"),
    ("telecamera", [(554, "rtsp", "RTSP/1.0 200 OK Server: Hikvision")], None, "ip_camera"),
]


@pytest.mark.parametrize("descrizione,porte,sistema,atteso", BANNER,
                         ids=[c[0] for c in BANNER])
def test_il_banner_identifica_il_dispositivo(descrizione, porte, sistema, atteso):
    """Il banner e' spesso l'unico testo che dichiara la natura dell'apparato."""
    esito = fp.identify(prove_con_banner(porte, sistema))
    assert esito["device_type"] == atteso, "%s classificato come %s (punteggi %s)" % (
        descrizione, esito["device_type"], esito["scores"])


def test_il_banner_compare_fra_le_prove_come_genere_proprio():
    esito = fp.identify(prove_con_banner(
        [(9100, "jetdirect", "HP LaserJet 4250 printer ready")]))
    generi = {v.get("genere") for v in esito["evidence"]}
    assert "banner" in generi or esito["decided_by"] == "regola decisiva"


def test_il_banner_entra_nel_testo_valutato_dalle_regole_di_prodotto():
    prove_https = prove_con_banner([(443, "https", "Server: nginx/1.24.0")])
    assert "nginx" in fp._product_text(prove_https)
    assert "nginx" in fp._banner_text(prove_https)


def test_un_banner_assente_non_altera_il_verdetto():
    """Il banner e' un'informazione in piu', non un requisito."""
    esito = fp.identify(prove_con_banner([(9100, "jetdirect", None), (515, "printer", None)]))
    assert esito["device_type"] == "printer"


def test_le_espressioni_sui_banner_sono_valide_e_pulite():
    controllo = set(chr(c) for c in range(32)) - {"\n", "\t"}
    for classe in fp.DEVICE_CLASSES:
        for espressione, peso in classe.get("banners", ()):
            re.compile(espressione)
            assert peso > 0, "%s: peso non positivo su un banner" % classe["key"]
            assert not (controllo & set(espressione)), (
                "%s: caratteri di controllo nell'espressione del banner" % classe["key"])


# --------------------------------------------------------------------------- #
# Agenti di sicurezza per endpoint riconosciuti dal banner
# --------------------------------------------------------------------------- #
# Banner reale osservato sulla porta tcp/161 di un nodo: a rispondere non e' SNMP
# ma il modulo web di Bitdefender, con la propria pagina di blocco.
BANNER_BITDEFENDER = (
    'SF-Port161-TCP:V=7.99%I=7%D=8/27%Time=6A902EA6%P=i686-pc-windows-windows'
    '%r(FourOhFourRequest,52054,"HTTP/1.1 403 Bitdefender Endpoint Security Tools '
    'blocked this page Content-Type: text/html; charset=utf-8 '
    '<title>Pagina avvisi di Bitdefender</title>'
)


ENDPOINT = ("workstation_windows", "server_windows", "workstation_mac", "server_unix")


def prove_161(banner, os=None):
    """Nodo con la porta 161 aperta, con o senza il banner dell'agente.

    Il sistema operativo e' assente per impostazione predefinita: e' il caso in
    cui il banner conta davvero, perche' senza di esso restano solo le porte e i
    nomi di servizio, e su quella porta il nome e' falso.
    """
    return {
        "ip": "10.50.9.99", "mac": None, "mac_vendor": None, "hostname": None,
        "ports": [
            {"protocol": "tcp", "port": 161, "state": "open", "service_name": "snmp",
             "product": None, "version": None, "banner": banner, "cpe": []},
            {"protocol": "tcp", "port": 80, "state": "open", "service_name": "http",
             "product": None, "version": None, "banner": None, "cpe": []},
        ],
        "os": os or {},
        "scripts": {},
    }


def test_l_agente_di_sicurezza_viene_riconosciuto_dal_banner():
    esito = fp.detect_security_agent(prove_161(BANNER_BITDEFENDER))
    assert esito["detected"] is True
    assert "Bitdefender" in esito["agent"]
    assert esito["ports"] == ["tcp/161"]


def test_senza_banner_non_si_dichiara_nessun_agente():
    esito = fp.detect_security_agent(prove_161(None))
    assert esito["detected"] is False
    assert esito["agent"] is None


def test_la_porta_intercettata_non_conta_come_prova():
    """L'etichetta 'snmp' su quella porta e' falsa: risponde l'agente."""
    con = prove_161(BANNER_BITDEFENDER)
    assert ("tcp", 161) not in fp._open_ports(con)
    assert ("tcp", 80) in fp._open_ports(con)
    # Il nome di servizio della porta intercettata non entra fra le prove.
    senza = prove_161(None)
    assert "snmp" in fp._service_names(senza)
    assert "snmp" not in fp._service_names(con)


def test_il_banner_dell_agente_corregge_un_verdetto_sbagliato():
    """Era il caso reale: la 161 etichettata 'snmp' portava verso gli apparati."""
    sbagliato = fp.identify(prove_161(None))
    corretto = fp.identify(prove_161(BANNER_BITDEFENDER))

    assert sbagliato["device_type"] not in ENDPOINT, (
        "senza il banner il verdetto e' fuorviato dall'etichetta della porta, "
        "invece e' %s" % sbagliato["device_type"]
    )
    assert corretto["device_type"] in ENDPOINT, (
        "con il banner il nodo va riconosciuto come endpoint: %s" % corretto["device_type"]
    )


def test_il_banner_dell_agente_conferma_il_sistema_operativo():
    """Con il sistema operativo noto, il banner rafforza il verdetto giusto."""
    esito = fp.identify(prove_161(
        BANNER_BITDEFENDER,
        os={"family": "Windows", "name": "Windows 11 24H2", "type": "general purpose"}))
    assert esito["device_type"] == "workstation_windows"
    generi = {v.get("genere") for v in esito["evidence"]}
    assert "banner" in generi


def test_il_verdetto_dichiara_l_agente_riconosciuto():
    esito = fp.identify(prove_161(BANNER_BITDEFENDER))
    assert esito["security_agent"]["detected"] is True
    assert "Bitdefender" in esito["security_agent"]["agent"]


def test_un_agente_esclude_gli_apparati_incorporati():
    """Una stampante non esegue un antivirus per endpoint."""
    prove = {
        "ip": "10.50.9.98", "mac": None, "mac_vendor": None, "hostname": None,
        "ports": [
            {"protocol": "tcp", "port": 9100, "state": "open", "service_name": "jetdirect",
             "product": None, "version": None, "banner": None, "cpe": []},
            {"protocol": "tcp", "port": 443, "state": "open", "service_name": "https",
             "product": None, "version": None, "banner": BANNER_BITDEFENDER, "cpe": []},
        ],
        "os": {"family": "Windows", "name": "Windows 10", "type": "general purpose"},
        "scripts": {},
    }
    esito = fp.identify(prove)
    assert esito["device_type"] != "printer", (
        "l'agente di sicurezza doveva escludere la stampante: %s" % esito["scores"]
    )


@pytest.mark.parametrize("banner,atteso", [
    ("ESET Endpoint Security blocked", "ESET"),
    ("Sophos Web Protection", "Sophos"),
    ("Kaspersky Endpoint Security for Windows", "Kaspersky"),
    ("CrowdStrike Falcon sensor", "CrowdStrike"),
    ("FortiClient Web Filter blocked", "FortiClient"),
])
def test_gli_altri_agenti_sono_riconosciuti(banner, atteso):
    esito = fp.detect_security_agent(prove_161(banner))
    assert esito["detected"] is True
    assert atteso.lower() in esito["agent"].lower()


def test_l_espressione_composta_degli_agenti_e_valida():
    """Il flag di insensibilita' va all'inizio: unendo i pezzi si perdeva."""
    re.compile(fp.AGENT_BANNER_PATTERN)
    assert fp.AGENT_BANNER_PATTERN.startswith("(?i)")
    assert "(?i)" not in fp.AGENT_BANNER_PATTERN[4:]


# --------------------------------------------------------------------------- #
# Indizio dal TTL: 64 unix, 128 Windows, 255 apparato di rete
# --------------------------------------------------------------------------- #
def test_il_ttl_si_arrotonda_al_valore_iniziale():
    assert fp.os_family_from_ttl(128)["descrizione"].startswith("Windows")
    assert fp.os_family_from_ttl(117)["descrizione"].startswith("Windows")   # 128 - 11 hop
    assert fp.os_family_from_ttl(64)["descrizione"].startswith("Linux")
    assert fp.os_family_from_ttl(52)["descrizione"].startswith("Linux")      # 64 - 12 hop
    assert "rete" in fp.os_family_from_ttl(255)["descrizione"]
    assert "rete" in fp.os_family_from_ttl(244)["descrizione"]
    assert fp.os_family_from_ttl(None) is None
    assert fp.os_family_from_ttl(0) is None and fp.os_family_from_ttl(300) is None


def test_il_ttl_nudge_la_famiglia_quando_le_prove_scarseggiano():
    """Un nodo quasi muto con TTL 128 e una porta SMB pende verso Windows; con TTL 64
    verso unix. Il TTL da solo resta sotto la soglia: non decide, ma inclina."""
    win = fp.identify(prove(ports=[("tcp", 445, "microsoft-ds")], ttl=120))
    assert win["device_type"] in ("workstation_windows", "server_windows")
    prove_win = [x["prova"] for x in win.get("evidence", [])]
    assert any("TTL" in x for x in prove_win)


def test_il_ttl_non_scavalca_il_sistema_operativo_di_nmap():
    """Se nmap ha determinato la famiglia, il TTL non entra: e' un ripiego, non un
    concorrente di una misura piu' forte."""
    ev = prove(ports=[("tcp", 22, "ssh")], os={"family": "linux"}, ttl=120)
    esito = fp.identify(ev)
    prove_usate = [x.get("prova", "") for x in esito.get("evidence", [])]
    assert not any("TTL" in x for x in prove_usate), (
        "il TTL non deve contribuire quando nmap ha gia' la famiglia")


def test_il_ttl_da_solo_non_classifica():
    """Un TTL senza altre prove non basta: il segnale e' debole (NAT e firewall lo
    riscrivono), e resta sotto la soglia minima."""
    esito = fp.identify(prove(ttl=120))
    assert esito["device_type"] == fp.UNKNOWN["key"]
