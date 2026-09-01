"""
snap - Test della lettura SNMP: fase dedicata, interpretazione, archiviazione.

Dove la porta 161 risponde, SNMP racconta piu' di dieci porte TCP: nome e
descrizione del sistema, interfacce, processi, software installato. Questi test
verificano le tre proprieta' che rendono utile quella lettura.

Proprieta' verificate: la fase interroga SOLO i nodi con la 161 aperta e con
script di sola lettura; il riassunto conta le voci degli elenchi e non le righe
dei loro dettagli; il testo integrale sopravvive all'archiviazione e le prove
SNMP restano disponibili al riconoscimento anche dopo un ricalcolo del profilo.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json

import pytest

from snapprobe.scanner import (DEFAULT_CADENCES, SNMP_HOST_TIMEOUT, SNMP_PORT,
                               SNMP_SCRIPTS, STAGES, NetworkScanner, snmp_summary)
from test_scanner import EsecutoreFinto, leggi

PERIMETRO = [{"cidr": "192.0.2.0/24", "label": "Rete di prova"}]

# Estratto reale di uno switch: il nome della voce a un livello di rientro, i
# suoi dettagli a uno piu' profondo. E' la forma che confonde i conteggi.
INTERFACCE = """Vlan1
    IP address: 192.0.2.51  Netmask: 255.255.255.0
    MAC address: 00:11:22:33:44:55 (Cisco Systems)
    Type: ethernetCsmacd  Speed: 1 Gbps
  GigabitEthernet0/1
    MAC address: 00:11:22:33:44:56 (Cisco Systems)
    Type: ethernetCsmacd  Speed: 1 Gbps
  GigabitEthernet0/2
    MAC address: 00:11:22:33:44:57 (Cisco Systems)
    Type: ethernetCsmacd  Speed: unknown
"""

SYSDESCR = ("Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M),"
            " Version 15.0(2)SE11, RELEASE SOFTWARE (fc2)\n"
            "  System uptime: 402 days, 5:12:33.00\n")

INFO = """  enterprise: cisco
  engineIDFormat: unknown
  snmpEngineID: 0x80000009030000112233
  System name: sw-piano2.esempio.local
  Location: Armadio piano 2
  Contact: reti@esempio.local
"""

SOFTWARE = """  1; Microsoft SQL Server 2019; 2021-04-02
  2; Adobe Acrobat Reader DC; 2022-11-14
"""


@pytest.fixture()
def sonda(probe_store):
    probe_store.set_json("scan_subnets", PERIMETRO)
    return probe_store


def _nodo_snmp(store, ip="192.0.2.51", altre_porte=None):
    """Nodo confermato con la porta SNMP aperta."""
    porte = {"udp/161": {"protocol": "udp", "port": SNMP_PORT, "state": "open"}}
    porte.update(altre_porte or {})
    store.upsert_local_node(ip, state="confirmed", stages_done="ports,services,os",
                            profile_json=json.dumps({"ip": ip, "ports_index": porte}))


# --------------------------------------------------------------------------- #
# La fase esiste e riguarda i soli nodi che espongono SNMP
# --------------------------------------------------------------------------- #
def test_la_fase_snmp_e_prevista_e_ha_una_cadenza():
    assert "snmp" in STAGES
    assert DEFAULT_CADENCES["snmp"] > 0


def test_la_fase_snmp_interroga_solo_i_nodi_con_la_porta_aperta(sonda):
    """Interrogare via SNMP un nodo che non espone la 161 significa attendere il
    tempo pieno per host senza ottenere nulla."""
    _nodo_snmp(sonda, "192.0.2.51")
    sonda.upsert_local_node("192.0.2.52", state="confirmed", stages_done="ports",
                            profile_json=json.dumps({"ip": "192.0.2.52", "ports_index": {
                                "tcp/80": {"protocol": "tcp", "port": 80,
                                           "state": "open"}}}))
    esecutore = EsecutoreFinto(leggi("nmap_porte_servizi_os.xml"))
    scanner = NetworkScanner(sonda, esecutore)

    scanner.run_stage("snmp", "*")
    assert esecutore.chiamate[-1]["targets"] == ["192.0.2.51"]


def test_senza_nodi_snmp_la_fase_non_viene_programmata(sonda):
    sonda.upsert_local_node("192.0.2.52", state="confirmed", stages_done="ports",
                            profile_json=json.dumps({"ip": "192.0.2.52", "ports_index": {
                                "tcp/80": {"protocol": "tcp", "port": 80,
                                           "state": "open"}}}))
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_scoperta.xml")))
    compiti = scanner.plan_tasks(limit=10)
    assert not [c for c in compiti if c["stage"] == "snmp"]


def test_la_fase_snmp_viene_programmata_quando_la_porta_e_aperta(sonda):
    _nodo_snmp(sonda)
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_scoperta.xml")))
    compiti = [c for c in scanner.plan_tasks(limit=10) if c["stage"] == "snmp"]
    assert compiti and "192.0.2.51" in compiti[0]["hosts"]


def test_un_nodo_mai_letto_ha_la_precedenza_sulla_cadenza(sonda):
    """La cadenza governa le ri-letture, non la prima: con una sola scadenza per
    tutti i bersagli, una passata da sedici nodi bloccava la fase per dodici ore, e
    su duecento apparati servivano giorni per leggerli la prima volta."""
    _nodo_snmp(sonda, "192.0.2.51")
    esecutore = EsecutoreFinto(leggi("nmap_porte_servizi_os.xml"))
    scanner = NetworkScanner(sonda, esecutore)
    scanner.run_stage("snmp", "*")

    # La fase risulta eseguita, ma un secondo nodo non ancora letto la rende dovuta.
    _nodo_snmp(sonda, "192.0.2.52")
    compiti = [c for c in scanner.plan_tasks(limit=10) if c["stage"] == "snmp"]
    assert compiti, "un nodo mai letto non attende la cadenza"
    assert compiti[0]["hosts"] == ["192.0.2.52"], (
        "si legge il nodo mancante, non si rilegge quello gia' fatto")


def test_gli_argomenti_della_fase_snmp_sono_di_sola_lettura(sonda):
    _nodo_snmp(sonda)
    esecutore = EsecutoreFinto(leggi("nmap_porte_servizi_os.xml"))
    NetworkScanner(sonda, esecutore).run_stage("snmp", "*")

    argomenti = esecutore.chiamate[-1]["arguments"]
    assert "-sU" in argomenti and str(SNMP_PORT) in argomenti
    valore = argomenti[argomenti.index("--script") + 1]
    assert valore == SNMP_SCRIPTS
    assert "brute" not in valore, "un inventario non indovina le community"
    assert "-set" not in valore, "nessuno script di scrittura"
    # Un apparato lento risponde in minuti: il tempo per host e' dichiarato.
    assert argomenti[argomenti.index("--host-timeout") + 1] == SNMP_HOST_TIMEOUT


def test_la_fase_snmp_rispetta_il_perimetro(sonda):
    """Un nodo fuori perimetro non viene interrogato nemmeno se espone SNMP."""
    _nodo_snmp(sonda, "198.51.100.7")
    esecutore = EsecutoreFinto(leggi("nmap_porte_servizi_os.xml"))
    scanner = NetworkScanner(sonda, esecutore)

    scanner.run_stage("snmp", "*")
    assert not esecutore.chiamate, "nessuna interrogazione fuori dal perimetro"


# --------------------------------------------------------------------------- #
# Interpretazione: si contano le voci, non le righe
# --------------------------------------------------------------------------- #
def test_il_riassunto_estrae_cio_che_identifica_l_apparato():
    riassunto = snmp_summary({"snmp-sysdescr": SYSDESCR, "snmp-info": INFO})
    assert riassunto["sysdescr"].startswith("Cisco IOS Software")
    assert riassunto["sysname"] == "sw-piano2.esempio.local"
    assert riassunto["uptime"] == "402 days, 5:12:33.00"
    assert riassunto["location"] == "Armadio piano 2"
    assert riassunto["contact"] == "reti@esempio.local"
    assert riassunto["enterprise"] == "cisco"
    # La community con cui si e' ottenuta risposta e' essa stessa un riscontro.
    assert riassunto["community"]


def test_le_interfacce_si_contano_per_voce_non_per_riga():
    """Difetti misurati su apparati veri: contando ogni riga rientrata, tre
    interfacce con i loro indirizzi e MAC diventavano dodici; contando le sole
    righe al rientro minimo si perdeva la prima, che nmap stampa senza rientro."""
    riassunto = snmp_summary({"snmp-interfaces": INTERFACCE})
    assert riassunto["interfacce"] == 3


def test_gli_elenchi_piatti_si_contano_con_la_loro_forma():
    riassunto = snmp_summary({"snmp-win32-software": SOFTWARE})
    assert riassunto["software"] == 2


def test_un_elenco_vuoto_non_produce_un_conteggio():
    """RP-05: l'assenza di dato non e' uno zero da mostrare."""
    riassunto = snmp_summary({"snmp-sysdescr": SYSDESCR, "snmp-interfaces": ""})
    assert "interfacce" not in riassunto


def test_senza_letture_snmp_il_riassunto_e_vuoto():
    assert snmp_summary({}) == {}
    assert snmp_summary({"banner": "SSH-2.0"}) == {}


def test_il_riassunto_dichiara_quali_script_hanno_risposto():
    riassunto = snmp_summary({"snmp-info": INFO, "snmp-interfaces": INTERFACCE})
    assert riassunto["scripts"] == ["snmp-info", "snmp-interfaces"]


# --------------------------------------------------------------------------- #
# Archiviazione: il testo integrale si conserva
# --------------------------------------------------------------------------- #
def _tenant_con_nodo(ip="192.0.2.51"):
    """Tenant, sonda e un nodo in inventario. Da usare in un contesto d'app."""
    from snapserver.db import execute, utc_now_str

    adesso = utc_now_str()
    tenant_id = execute(
        "INSERT INTO tenants (code, name, timezone, locale, retention_days,"
        " is_active, created_at, updated_at) VALUES ('snmp','SNMP','UTC','it',365,1,?,?)",
        (adesso, adesso))
    probe_id = execute(
        "INSERT INTO probes (tenant_id, probe_uid, code, name, status, created_at,"
        " updated_at) VALUES (?, 'uid-snmp', 'P1', 'sonda', 'active', ?, ?)",
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


def _conferisci(tenant_id, probe_id, ip="192.0.2.51", uid="lotto-snmp", letture=None):
    from snapserver.ingest import apply_batch

    letture = letture if letture is not None else {
        "snmp-sysdescr": SYSDESCR, "snmp-info": INFO, "snmp-interfaces": INTERFACCE}
    return apply_batch(tenant_id, probe_id, {
        "batch_uid": uid,
        "records": {"snmp": [{"ip": ip, "scripts": letture,
                              "summary": snmp_summary(letture)}]}})


def test_il_conferimento_conserva_il_testo_integrale(server_app):
    """Nelle prove del profilo il testo viene troncato a 2 kB: cio' che si
    perderebbe e' esattamente l'informazione per cui si interroga SNMP."""
    from snapserver.db import query

    with server_app.app_context():
        tenant_id, probe_id, node_id = _tenant_con_nodo()
        esito = _conferisci(tenant_id, probe_id)
        assert esito["accepted"] and not esito["orphans"]

        righe = {r["script_id"]: r for r in query(
            "SELECT script_id, output, parsed_json FROM node_snmp WHERE node_id = ?",
            (node_id,))}
        assert set(righe) == {"snmp-sysdescr", "snmp-info", "snmp-interfaces", "summary"}
        assert righe["snmp-interfaces"]["output"] == INTERFACCE
        riassunto = json.loads(righe["summary"]["parsed_json"])
        assert riassunto["interfacce"] == 3


def test_una_nuova_lettura_sostituisce_la_precedente(server_app):
    """Una riga per script e per nodo: l'archivio non cresce a ogni passata."""
    from snapserver.db import query

    with server_app.app_context():
        tenant_id, probe_id, node_id = _tenant_con_nodo()
        _conferisci(tenant_id, probe_id, uid="lotto-1")
        _conferisci(tenant_id, probe_id, uid="lotto-2", letture={
            "snmp-sysdescr": "Nuovo firmware 16.0", "snmp-info": INFO})

        righe = {r["script_id"]: r["output"] for r in query(
            "SELECT script_id, output FROM node_snmp WHERE node_id = ?", (node_id,))}
        assert righe["snmp-sysdescr"] == "Nuovo firmware 16.0"


def test_le_letture_di_un_nodo_ignoto_non_bloccano_il_lotto(server_app):
    """Come per gli altri record: un nodo non in inventario non viene creato
    implicitamente, e il lotto resta trasmissibile."""
    with server_app.app_context():
        tenant_id, probe_id, _ = _tenant_con_nodo()
        esito = _conferisci(tenant_id, probe_id, ip="192.0.2.200", uid="lotto-orfano")
        assert esito["accepted"] and esito["orphans"] == 1


def test_un_record_snmp_senza_letture_e_rifiutato(server_app):
    from snapserver.ingest import IngestError, apply_batch

    with server_app.app_context():
        tenant_id, probe_id, _ = _tenant_con_nodo()
        with pytest.raises(IngestError):
            apply_batch(tenant_id, probe_id, {
                "batch_uid": "lotto-vuoto",
                "records": {"snmp": [{"ip": "192.0.2.51", "scripts": {}}]}})


def test_le_prove_snmp_restano_dopo_un_ricalcolo_del_profilo(server_app):
    """Il riconoscimento ricostruisce le prove dalla banca dati: le letture SNMP
    devono essere fra quelle, altrimenti una rideterminazione le perderebbe."""
    from snapserver.ingest import build_evidence, refingerprint_tenant

    with server_app.app_context():
        tenant_id, probe_id, node_id = _tenant_con_nodo()
        _conferisci(tenant_id, probe_id)
        refingerprint_tenant(tenant_id)

        prove = build_evidence(tenant_id, node_id)
        assert prove["snmp"]["sysname"] == "sw-piano2.esempio.local"
        assert "snmp-interfaces" in prove["scripts"]
        # La descrizione di sistema e' dove le regole del catalogo la cercano.
        assert "Cisco IOS" in prove["scripts"]["snmp-info"]


def test_snmp_da_solo_riconosce_l_apparato(server_app):
    """Un apparato senza alcuna porta TCP aperta resta non identificato: con la
    sola descrizione di sistema diventa uno switch gestito."""
    from snapserver.db import query

    with server_app.app_context():
        tenant_id, probe_id, node_id = _tenant_con_nodo()
        _conferisci(tenant_id, probe_id)

        nodo = query("SELECT device_type, device_confidence FROM nodes WHERE id = ?",
                     (node_id,), one=True)
        assert nodo["device_type"] == "switch_managed"
        assert nodo["device_confidence"] >= 60


def test_la_pagina_del_nodo_mostra_la_lettura_snmp(server_app, logged_client):
    with server_app.app_context():
        tenant_id, probe_id, node_id = _tenant_con_nodo()
        _conferisci(tenant_id, probe_id)

    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)
    testo = logged_client.get("/inventory/nodes/%d" % node_id).get_data(as_text=True)
    assert "Lettura SNMP" in testo
    assert "sw-piano2.esempio.local" in testo
    # Il testo integrale resta consultabile, non solo il riassunto.
    assert "GigabitEthernet0/1" in testo


# --------------------------------------------------------------------------- #
# Da testo di terminale a tabella
# --------------------------------------------------------------------------- #
# Estratti reali, nella forma in cui nmap li restituisce.
NETSTAT = """TCP  0.0.0.0:80           0.0.0.0:0
  TCP  0.0.0.0:445          0.0.0.0:0
  UDP  10.2.101.60:161      0.0.0.0:0
"""

PROCESSI = """1:
    Name: OS
  2:
    Name: Print
"""

SOFTWARE_XEROX = """; 0-00-00T00:00:00
  FIN D 15.37.0; 0-00-00T00:00:00
  Xerox Versant 3100 Press;; 2023-11-20T14:51:07
"""

SYSDESCR_XEROX = ("Xerox VersaLink C7000; System 56.64.11, Controller 1.70.4,"
                  " IOT 65.4.0\n"
                  "  System uptime: 134d11h21m32.00s (1161849200 timeticks)\n")


def test_le_interfacce_diventano_una_tabella():
    """Un elenco di interfacce in un riquadro di testo non si ordina e non si cerca."""
    from snapserver.snmp_tables import parse_script

    tabella = parse_script("snmp-interfaces", INTERFACCE)
    assert tabella["kind"] == "tabella"
    assert tabella["colonne"][0] == "INTERFACCIA"
    assert len(tabella["righe"]) == 3
    prima = tabella["righe"][0]
    assert prima[0] == "Vlan1"
    assert prima[1] == "192.0.2.51" and prima[2] == "255.255.255.0"
    assert "00:11:22:33:44:55" in prima[3]
    assert prima[4] == "ethernetCsmacd" and prima[5] == "1 Gbps"


def test_le_connessioni_si_scompongono_in_indirizzo_e_porta():
    from snapserver.snmp_tables import parse_script

    tabella = parse_script("snmp-netstat", NETSTAT)
    assert [r[0] for r in tabella["righe"]] == ["TCP", "TCP", "UDP"]
    assert tabella["righe"][2][1:3] == ["10.2.101.60", "161"]


def test_i_processi_portano_il_proprio_numero():
    from snapserver.snmp_tables import parse_script

    tabella = parse_script("snmp-processes", PROCESSI)
    assert [r[0] for r in tabella["righe"]] == ["1", "2"]
    assert [r[1] for r in tabella["righe"]] == ["OS", "Print"]


def test_il_software_senza_nome_non_diventa_una_riga_vuota():
    """Alcuni apparati riempiono l'elenco di segnaposti: una riga senza nome non e'
    software installato, e in tabella sarebbe rumore."""
    from snapserver.snmp_tables import parse_script

    tabella = parse_script("snmp-win32-software", SOFTWARE_XEROX)
    nomi = [r[0] for r in tabella["righe"]]
    assert nomi == ["FIN D 15.37.0", "Xerox Versant 3100 Press"]
    # Una data non impostata non si mostra come se fosse una data.
    assert tabella["righe"][0][1] == ""
    assert tabella["righe"][1][1].startswith("2023-11-20")


def test_la_descrizione_si_scompone_nei_componenti_dichiarati():
    """Molti apparati impacchettano l'elenco dei firmware in una riga sola."""
    from snapserver.snmp_tables import parse_script

    tabella = parse_script("snmp-sysdescr", SYSDESCR_XEROX)
    assert tabella["kind"] == "coppie"
    campi = {r[0]: r[1] for r in tabella["righe"]}
    assert campi["Descrizione dichiarata"].startswith("Xerox VersaLink C7000")
    assert campi["Tempo di accensione"].startswith("134d11h")
    componenti = [r[1] for r in tabella["righe"] if r[0] == "Componente dichiarato"]
    assert "Controller 1.70.4" in componenti


def test_un_esito_non_riconosciuto_resta_testo_e_non_fa_cadere_la_pagina():
    from snapserver.snmp_tables import parse_script

    assert parse_script("snmp-inventato", "qualcosa")["kind"] == "testo"
    assert parse_script("snmp-interfaces", "")["kind"] == "testo"
    assert parse_script("snmp-netstat", "riga che non c'entra")["kind"] == "testo"


def test_le_letture_si_ordinano_come_le_leggerebbe_una_persona():
    """Prima che cos'e' l'apparato, poi come e' collegato, poi cosa ci gira sopra."""
    from snapserver.snmp_tables import parse_all

    letture = [{"script_id": "snmp-processes", "output": PROCESSI},
               {"script_id": "snmp-sysdescr", "output": SYSDESCR_XEROX},
               {"script_id": "snmp-interfaces", "output": INTERFACCE}]
    assert [v["script_id"] for v in parse_all(letture)] == [
        "snmp-sysdescr", "snmp-interfaces", "snmp-processes"]


def test_la_scheda_del_nodo_mostra_le_tabelle_non_il_testo_grezzo(server_app,
                                                                 logged_client):
    tenant_id, probe_id, node_id = None, None, None
    with server_app.app_context():
        tenant_id, probe_id, node_id = _tenant_con_nodo()
        _conferisci(tenant_id, probe_id, letture={
            "snmp-sysdescr": SYSDESCR_XEROX, "snmp-interfaces": INTERFACCE,
            "snmp-netstat": NETSTAT})

    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)
    pagina = logged_client.get("/inventory/nodes/%d" % node_id).get_data(as_text=True)
    assert "Interfacce di rete" in pagina
    assert "Connessioni e porte in ascolto" in pagina
    assert "INTERFACCIA" in pagina and "PORTA REMOTA" in pagina
    # Il testo integrale resta consultabile: e' la fonte.
    assert "Testo restituito dall'apparato" in pagina


# --------------------------------------------------------------------------- #
# Riassunto: difetti visti sui dati veri
# --------------------------------------------------------------------------- #
def test_il_nome_del_sistema_non_viene_da_un_processo():
    """Difetto misurato su cinque stampanti: l'identita' veniva cercata nel testo di
    tutti gli script uniti, e "Name: OS" del primo processo diventava il nome del
    sistema. Un dato falso e' peggio di un dato mancante."""
    riassunto = snmp_summary({"snmp-processes": PROCESSI,
                              "snmp-sysdescr": SYSDESCR_XEROX})
    assert "sysname" not in riassunto
    assert riassunto["sysdescr"].startswith("Xerox VersaLink")


def test_processi_e_connessioni_si_contano_nella_forma_di_nmap():
    """Le espressioni precedenti pretendevano uno spazio dopo il numero del processo
    e un indirizzo a inizio riga: non contavano mai nulla."""
    riassunto = snmp_summary({"snmp-processes": PROCESSI, "snmp-netstat": NETSTAT})
    assert riassunto["processi"] == 2
    assert riassunto["connessioni"] == 3
