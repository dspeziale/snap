"""
snap - Test dell'enumerazione SMB: fase dedicata, interpretazione, archiviazione.

Dove la 139 (NetBIOS) o la 445 (SMB diretto) rispondono, SMB racconta di una macchina
Windows piu' di quanto direbbe il rilevamento del sistema operativo: versione esatta,
dominio, condivisioni pubblicate, utenze. E' il comando che l'operatore ha chiesto:

    nmap -p 139,445 --script smb-os-discovery,smb-enum-shares,smb-enum-users <ip>

Le prove verificano le proprieta' che rendono utile e sicura quella lettura: la fase
interroga solo i nodi con SMB aperto e con soli script di enumerazione (niente brute
forcing); il riassunto conta le voci degli elenchi; il testo integrale sopravvive
all'archiviazione; e smb-os-discovery contribuisce al riconoscimento di Windows.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json

import pytest

from snapprobe.scanner import (DEFAULT_CADENCES, SMB_HOST_TIMEOUT, SMB_PORTS,
                               SMB_SCRIPTS, STAGES, NetworkScanner, smb_summary)
from test_scanner import EsecutoreFinto, leggi

PERIMETRO = [{"cidr": "192.0.2.0/24", "label": "Rete di prova"}]


@pytest.fixture()
def sonda(probe_store):
    probe_store.set_json("scan_subnets", PERIMETRO)
    return probe_store


OS_DISCOVERY = (
    "OS: Windows Server 2019 Standard 17763\n"
    "Computer name: dc01\n"
    "NetBIOS computer name: DC01\\x00\n"
    "Domain name: contoso.local\n"
    "Forest name: contoso.local\n"
    "FQDN: dc01.contoso.local\n"
    "System time: 2026-08-31T21:40:00+02:00")
SHARES = (
    "account_used: guest\n"
    "\\\\192.0.2.51\\ADMIN$:\n  Type: STYPE_DISKTREE_HIDDEN\n  Comment: Remote Admin\n"
    "\\\\192.0.2.51\\C$:\n  Type: STYPE_DISKTREE_HIDDEN\n"
    "\\\\192.0.2.51\\Dati:\n  Type: STYPE_DISKTREE\n  Anonymous access: READ")
USERS = (
    "CONTOSO\\Administrator (RID: 500)\n  Flags:       Normal user account\n"
    "CONTOSO\\Guest (RID: 501)\n  Flags:       Account disabled\n"
    "CONTOSO\\svc_backup (RID: 1108)\n  Flags:       Normal user account")
SECURITY = "message_signing: disabled (dangerous, but default)"


def _nodo_smb(store, ip="192.0.2.51", porta="tcp/139"):
    """Nodo confermato con una porta SMB aperta."""
    protocollo, numero = porta.split("/")
    porte = {porta: {"protocol": protocollo, "port": int(numero), "state": "open"}}
    store.upsert_local_node(ip, state="confirmed", stages_done="ports,services,os",
                            profile_json=json.dumps({"ip": ip, "ports_index": porte}))


# --------------------------------------------------------------------------- #
# La fase esiste e riguarda i soli nodi che espongono SMB
# --------------------------------------------------------------------------- #
def test_la_fase_smb_e_prevista_e_ha_una_cadenza():
    assert "smb" in STAGES
    assert DEFAULT_CADENCES["smb"] > 0


def test_la_fase_smb_interroga_solo_i_nodi_con_la_porta_aperta(sonda):
    """Interrogare via SMB un nodo che non espone ne' la 139 ne' la 445 significa
    attendere il tempo pieno per host per nulla."""
    _nodo_smb(sonda, "192.0.2.51", "tcp/139")
    sonda.upsert_local_node("192.0.2.52", state="confirmed", stages_done="ports",
                            profile_json=json.dumps({"ip": "192.0.2.52", "ports_index": {
                                "tcp/80": {"protocol": "tcp", "port": 80,
                                           "state": "open"}}}))
    esecutore = EsecutoreFinto(leggi("nmap_smb.xml"))
    NetworkScanner(sonda, esecutore).run_stage("smb", "*")
    assert esecutore.chiamate[-1]["targets"] == ["192.0.2.51"]


def test_la_fase_smb_riguarda_anche_chi_espone_solo_la_445(sonda):
    """La 139 e' il trigger indicato, ma su Windows recenti spesso e' aperta la sola
    445: escludere la 445 lascerebbe fuori gran parte dei server."""
    _nodo_smb(sonda, "192.0.2.60", "tcp/445")
    esecutore = EsecutoreFinto(leggi("nmap_smb.xml"))
    compiti = [c for c in NetworkScanner(sonda, esecutore).plan_tasks(limit=10)
               if c["stage"] == "smb"]
    assert compiti and "192.0.2.60" in compiti[0]["hosts"]


def test_senza_nodi_smb_la_fase_non_viene_programmata(sonda):
    sonda.upsert_local_node("192.0.2.52", state="confirmed", stages_done="ports",
                            profile_json=json.dumps({"ip": "192.0.2.52", "ports_index": {
                                "tcp/80": {"protocol": "tcp", "port": 80,
                                           "state": "open"}}}))
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_scoperta.xml")))
    assert not [c for c in scanner.plan_tasks(limit=10) if c["stage"] == "smb"]


def test_un_nodo_mai_letto_ha_la_precedenza_sulla_cadenza(sonda):
    _nodo_smb(sonda, "192.0.2.51")
    esecutore = EsecutoreFinto(leggi("nmap_smb.xml"))
    scanner = NetworkScanner(sonda, esecutore)
    scanner.run_stage("smb", "*")

    _nodo_smb(sonda, "192.0.2.52")
    compiti = [c for c in scanner.plan_tasks(limit=10) if c["stage"] == "smb"]
    assert compiti and compiti[0]["hosts"] == ["192.0.2.52"], (
        "si legge il nodo mancante, non si rilegge quello gia' fatto")


def test_gli_argomenti_della_fase_smb_sono_il_comando_chiesto(sonda):
    """Esattamente il comando indicato dall'operatore, e di sola lettura."""
    _nodo_smb(sonda)
    esecutore = EsecutoreFinto(leggi("nmap_smb.xml"))
    NetworkScanner(sonda, esecutore).run_stage("smb", "*")

    argomenti = esecutore.chiamate[-1]["arguments"]
    assert "-p" in argomenti and SMB_PORTS in argomenti
    valore = argomenti[argomenti.index("--script") + 1]
    assert valore == SMB_SCRIPTS
    assert "smb-os-discovery" in valore and "smb-enum-shares" in valore
    assert "smb-enum-users" in valore
    assert "brute" not in valore, "un inventario non indovina le credenziali"
    assert argomenti[argomenti.index("--host-timeout") + 1] == SMB_HOST_TIMEOUT


def test_la_fase_smb_rispetta_il_perimetro(sonda):
    _nodo_smb(sonda, "198.51.100.7")
    esecutore = EsecutoreFinto(leggi("nmap_smb.xml"))
    NetworkScanner(sonda, esecutore).run_stage("smb", "*")
    assert not esecutore.chiamate, "nessuna interrogazione fuori dal perimetro"


def test_la_lettura_smb_produce_un_record_conferibile(sonda):
    """La fase deve accodare un record di genere 'smb', o il conferimento lo
    scarterebbe -- il difetto che aveva colpito la fase web."""
    from snapprobe.agent import record_type_of

    _nodo_smb(sonda)
    esecutore = EsecutoreFinto(leggi("nmap_smb.xml"))
    esito = NetworkScanner(sonda, esecutore).run_stage("smb", "*")
    assert "smb" in esito["records"], "la fase non ha prodotto record SMB"
    assert record_type_of("smb") == "smb"
    voce = esito["records"]["smb"][0]
    assert voce["ip"] == "192.0.2.51"
    assert voce["summary"]["computer_name"] == "dc01"


# --------------------------------------------------------------------------- #
# Interpretazione: si contano le voci, si estrae l'identita'
# --------------------------------------------------------------------------- #
def test_il_riassunto_estrae_l_identita_della_macchina():
    r = smb_summary({"smb-os-discovery": OS_DISCOVERY})
    assert r["os"].startswith("Windows Server 2019")
    assert r["computer_name"] == "dc01"
    assert r["netbios_name"] == "DC01", "il terminatore \\x00 va tolto"
    assert r["domain"] == "contoso.local"
    assert r["fqdn"] == "dc01.contoso.local"


def test_il_riassunto_conta_condivisioni_e_utenti():
    r = smb_summary({"smb-enum-shares": SHARES, "smb-enum-users": USERS})
    assert r["condivisioni"] == 3, "account_used non e' una condivisione"
    assert r["utenti"] == 3


def test_il_riassunto_segnala_la_firma_non_richiesta():
    r = smb_summary({"smb-security-mode": SECURITY})
    assert r["firma_messaggi"] == "non richiesta"


def test_senza_letture_smb_il_riassunto_e_vuoto():
    assert smb_summary({}) == {}
    assert smb_summary({"snmp-info": "x"}) == {}


# --------------------------------------------------------------------------- #
# Archiviazione e riconoscimento (lato server)
# --------------------------------------------------------------------------- #
def _tenant_con_nodo(ip="192.0.2.51", porte=(("tcp", 445),)):
    from snapserver.db import execute, utc_now_str

    adesso = utc_now_str()
    tenant_id = execute(
        "INSERT INTO tenants (code, name, timezone, locale, retention_days,"
        " is_active, created_at, updated_at) VALUES ('smb','SMB','UTC','it',365,1,?,?)",
        (adesso, adesso))
    probe_id = execute(
        "INSERT INTO probes (tenant_id, probe_uid, code, name, status, created_at,"
        " updated_at) VALUES (?, 'uid-smb', 'P1', 'sonda', 'active', ?, ?)",
        (tenant_id, adesso, adesso))
    subnet_id = execute(
        "INSERT INTO subnets (tenant_id, cidr, host_count, is_enabled, imported_at,"
        " created_at, updated_at) VALUES (?, '192.0.2.0/24', 254, 1, ?, ?, ?)",
        (tenant_id, adesso, adesso, adesso))
    node_id = execute(
        "INSERT INTO nodes (tenant_id, subnet_id, probe_id, ip, status, first_seen_at,"
        " last_seen_at, created_at, updated_at) VALUES (?, ?, ?, ?, 'up', ?, ?, ?, ?)",
        (tenant_id, subnet_id, probe_id, ip, adesso, adesso, adesso, adesso))
    for protocollo, numero in porte:
        execute(
            "INSERT INTO node_ports (tenant_id, node_id, protocol, port, state,"
            " is_suspect, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, 'open', 0, ?, ?)",
            (tenant_id, node_id, protocollo, numero, adesso, adesso))
    return tenant_id, probe_id, node_id


def _conferisci(tenant_id, probe_id, ip="192.0.2.51", uid="lotto-smb", letture=None):
    from snapserver.ingest import apply_batch

    letture = letture if letture is not None else {
        "smb-os-discovery": OS_DISCOVERY, "smb-enum-shares": SHARES,
        "smb-enum-users": USERS, "smb-security-mode": SECURITY}
    return apply_batch(tenant_id, probe_id, {
        "batch_uid": uid,
        "records": {"smb": [{"ip": ip, "scripts": letture,
                             "summary": smb_summary(letture)}]}})


def test_il_conferimento_conserva_il_testo_integrale(server_app):
    from snapserver.db import query

    with server_app.app_context():
        tenant_id, probe_id, node_id = _tenant_con_nodo()
        esito = _conferisci(tenant_id, probe_id)
        assert esito["accepted"] and not esito["orphans"]

        righe = {r["script_id"]: r for r in query(
            "SELECT script_id, output, parsed_json FROM node_smb WHERE node_id = ?",
            (node_id,))}
        assert "summary" in righe and "smb-enum-shares" in righe
        assert righe["smb-enum-shares"]["output"] == SHARES
        riassunto = json.loads(righe["summary"]["parsed_json"])
        assert riassunto["condivisioni"] == 3 and riassunto["utenti"] == 3


def test_una_nuova_lettura_sostituisce_la_precedente(server_app):
    from snapserver.db import query

    with server_app.app_context():
        tenant_id, probe_id, node_id = _tenant_con_nodo()
        _conferisci(tenant_id, probe_id, uid="lotto-1")
        _conferisci(tenant_id, probe_id, uid="lotto-2", letture={
            "smb-os-discovery": "OS: Windows 11 Pro 22631\nComputer name: pc42"})

        righe = {r["script_id"]: r["output"] for r in query(
            "SELECT script_id, output FROM node_smb WHERE node_id = ?", (node_id,))}
        assert "Windows 11" in righe["smb-os-discovery"]


def test_le_letture_di_un_nodo_ignoto_non_bloccano_il_lotto(server_app):
    with server_app.app_context():
        tenant_id, probe_id, _ = _tenant_con_nodo()
        esito = _conferisci(tenant_id, probe_id, ip="192.0.2.200", uid="orfano")
        assert esito["accepted"] and esito["orphans"] == 1


def test_un_record_smb_senza_letture_e_rifiutato(server_app):
    from snapserver.ingest import IngestError, apply_batch

    with server_app.app_context():
        tenant_id, probe_id, _ = _tenant_con_nodo()
        with pytest.raises(IngestError):
            apply_batch(tenant_id, probe_id, {
                "batch_uid": "vuoto",
                "records": {"smb": [{"ip": "192.0.2.51", "scripts": {}}]}})


def test_smb_os_discovery_identifica_windows_server(server_app):
    """smb-os-discovery entra fra le prove: un nodo con sole 139/445 aperte, che il
    rilevamento del sistema operativo lascerebbe incerto, diventa Server Windows."""
    from snapserver.ingest import build_evidence, refresh_fingerprint

    with server_app.app_context():
        tenant_id, probe_id, node_id = _tenant_con_nodo(
            porte=(("tcp", 139), ("tcp", 445)))
        _conferisci(tenant_id, probe_id)

        prove = build_evidence(tenant_id, node_id)
        assert "smb-os-discovery" in prove["scripts"], (
            "l'output SMB deve entrare fra le prove del riconoscimento")
        assert prove["smb"].get("domain") == "contoso.local"

        verdetto = refresh_fingerprint(tenant_id, node_id)
    assert verdetto["device_type"] == "server_windows", verdetto["device_type"]


def test_il_dato_grezzo_riporta_le_letture_smb(server_app):
    from snapserver.node_json import documento

    with server_app.app_context():
        tenant_id, probe_id, node_id = _tenant_con_nodo()
        _conferisci(tenant_id, probe_id)
        doc = documento(tenant_id, node_id)

    script = {v["script"] for v in doc["letture_smb"]}
    assert "smb-enum-shares" in script and "summary" in script
    assert doc["conteggi"]["letture_smb"] >= 4


# --------------------------------------------------------------------------- #
# SMBv2: dove SMBv1 e' disabilitato, gli script moderni danno comunque dati
# --------------------------------------------------------------------------- #
def test_il_riassunto_legge_gli_script_smb2():
    """Sugli host recenti SMBv1 e' spento e smb-os-discovery non risponde: gli script
    smb2-* e smb-protocols devono comunque fornire firma e dialetti."""
    r = smb_summary({
        "smb2-security-mode": "Message signing enabled but not required",
        "smb-protocols": "dialects:\n  2.0.2\n  2.1\n  3.0\n  3.1.1"})
    assert r["firma_messaggi"] == "non richiesta"
    assert "3.1.1" in r["dialetti_smb"] and "2.0.2" in r["dialetti_smb"]
    assert "smbv1" not in r


def test_il_riassunto_segnala_smbv1_abilitato():
    """SMBv1 abilitato e' un riscontro di sicurezza (il protocollo di WannaCry)."""
    r = smb_summary({"smb-protocols": "dialects:\n  NT LM 0.12\n  2.0.2"})
    assert r.get("smbv1") is True


def test_la_firma_supportata_ma_non_richiesta_e_un_rischio():
    """"supported" significa disponibile ma non imposta: le sessioni restano esposte
    al relay, quindi va trattata come non richiesta."""
    r = smb_summary({"smb-security-mode": "message_signing: supported"})
    assert r["firma_messaggi"] == "non richiesta"


def test_la_richiesta_su_un_nodo_specifico_enumera_quel_nodo(sonda):
    """Il bottone 'ripeti l'enumerazione SMB' passa l'indirizzo del nodo: la fase deve
    eseguire su QUEL nodo, anche se e' gia' stato letto -- non su altri mai letti."""
    _nodo_smb(sonda, "192.0.2.51")
    _nodo_smb(sonda, "192.0.2.99")
    esecutore = EsecutoreFinto(leggi("nmap_smb.xml"))
    scanner = NetworkScanner(sonda, esecutore)
    # Prima lettura di entrambi, poi si rifa' esplicitamente solo il .51.
    scanner.run_stage("smb", "*")
    esecutore.chiamate.clear()
    scanner.run_stage("smb", "192.0.2.51")
    assert esecutore.chiamate[-1]["targets"] == ["192.0.2.51"], (
        "la richiesta su un nodo specifico deve enumerare quel solo nodo")

# --------------------------------------------------------------------------- #
# Enumerazione su TUTTI i nodi: la priorita' del pulsante "Enumera SMB su tutti"
# --------------------------------------------------------------------------- #
def test_la_priorita_smb_prevale_sul_lavoro_di_profilo(sonda):
    """Con la priorita' attiva l'SMB riempie i posti liberi anche quando ci sarebbe
    lavoro di profilo (porte/servizi) a contendere il ciclo: senza, la fase SMB
    prenderebbe un solo posto per ciclo."""
    # Nodi SMB gia' profilati (da enumerare) e nodi che attendono ancora le porte.
    for i in range(40):
        _nodo_smb(sonda, "192.0.2.%d" % (10 + i))
    for i in range(20):
        sonda.upsert_local_node("192.0.2.%d" % (100 + i), state="confirmed",
                                stages_done="", profile_json="{}")
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_smb.xml")))

    scanner.enable_smb_boost()
    lotti = [c for c in scanner.plan_tasks(limit=6) if c["stage"] == "smb"]
    assert len(lotti) >= 2, (
        "la priorita' deve riempire piu' posti con l'SMB, non uno solo")


def test_la_priorita_si_spegne_quando_non_restano_nodi_da_leggere(sonda):
    """Quando ogni nodo SMB e' stato letto, la priorita' si spegne da se'."""
    _nodo_smb(sonda, "192.0.2.51")
    scanner = NetworkScanner(sonda, EsecutoreFinto(leggi("nmap_smb.xml")))
    scanner.enable_smb_boost()
    assert scanner.smb_boost_active()

    scanner.run_stage("smb", "*")   # legge l'unico nodo -> niente piu' pending
    scanner.plan_tasks(limit=8)     # il pianificatore si accorge e spegne
    assert not scanner.smb_boost_active()


def test_il_comando_all_attiva_la_priorita_senza_bloccare():
    """Il bersaglio '@all' non esegue una passata bloccante: attiva la priorita'."""
    import inspect

    from snapprobe.agent import ProbeAgent

    sorgente = inspect.getsource(ProbeAgent._run_command)
    assert '"@all"' in sorgente or "'@all'" in sorgente
    assert "enable_smb_boost" in sorgente
