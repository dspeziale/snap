"""
snap - Test della sospensione delle scansioni.

Due interruttori indipendenti, perche' rispondono a esigenze diverse: il server
ferma una sonda o tutte le sonde di un tenant senza accedere ai dispositivi; il
tecnico in sede ferma le scansioni immediatamente, per esempio durante una
lavorazione sulla rete. Il piu' restrittivo prevale.

La sospensione riguarda la scansione della rete, non il dialogo con il server: la
coda continua a essere conferita.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from snapprobe.scanner import NetworkScanner, ScanSuspended

FIXTURES = Path(__file__).parent / "fixtures"
PERIMETRO = [{"cidr": "192.0.2.0/24", "label": "Rete di prova"}]


class EsecutoreFinto:
    def __init__(self, xml: str):
        self.xml = xml
        self.chiamate = []

    def detect_capabilities(self, force: bool = False) -> dict:
        return {"available": True, "executable": "nmap-finto", "nmap_version": "7.99",
                "raw_sockets": True, "os_detection": True, "detail": "esecutore di prova"}

    def run(self, arguments, targets, timeout=None, label=None) -> str:
        # `label` descrive la fase in corso per l'indicatore: qui non serve,
        # ma la firma deve corrispondere a quella del runner vero.
        self.chiamate.append({"arguments": list(arguments), "targets": list(targets)})
        return self.xml


@pytest.fixture()
def sonda(probe_store):
    probe_store.set_json("scan_subnets", PERIMETRO)
    return probe_store


def scanner_di(sonda):
    xml = (FIXTURES / "nmap_scoperta.xml").read_text(encoding="utf-8")
    esecutore = EsecutoreFinto(xml)
    return NetworkScanner(sonda, esecutore), esecutore


# --------------------------------------------------------------------------- #
# Interruttore locale della sonda
# --------------------------------------------------------------------------- #
def test_la_sospensione_locale_ferma_la_pianificazione(sonda):
    scanner, _ = scanner_di(sonda)
    assert scanner.next_due() is not None
    sonda.set_setting("scan_paused", "1")
    assert scanner.next_due() is None


def test_la_sospensione_locale_impedisce_anche_una_fase_richiesta(sonda):
    """La sospensione non si aggira con un comando dalla console."""
    scanner, esecutore = scanner_di(sonda)
    sonda.set_setting("scan_paused", "1")
    with pytest.raises(ScanSuspended):
        scanner.run_stage("discovery", "192.0.2.0/24")
    assert esecutore.chiamate == [], "nmap non deve essere invocato"


def test_la_sospensione_viene_annotata_fra_gli_stati_delle_fasi(sonda):
    scanner, _ = scanner_di(sonda)
    sonda.set_setting("scan_paused", "1")
    with pytest.raises(ScanSuspended):
        scanner.run_stage("discovery", "192.0.2.0/24")
    stato = sonda.scan_state("192.0.2.0/24", "discovery")
    assert stato["last_status"] == "suspended"
    assert "sonda" in stato["last_detail"]


def test_la_ripresa_locale_riabilita_la_pianificazione(sonda):
    scanner, _ = scanner_di(sonda)
    sonda.set_setting("scan_paused", "1")
    assert scanner.next_due() is None
    sonda.set_setting("scan_paused", "0")
    assert scanner.next_due() is not None


# --------------------------------------------------------------------------- #
# Interruttore del server
# --------------------------------------------------------------------------- #
def test_l_interruttore_del_server_ferma_le_scansioni(sonda):
    scanner, _ = scanner_di(sonda)
    sonda.set_setting("scan_enabled", "0")
    assert scanner.next_due() is None
    with pytest.raises(ScanSuspended):
        scanner.run_stage("ports", "*")


def test_il_motivo_della_sospensione_distingue_i_due_interruttori(sonda):
    scanner, _ = scanner_di(sonda)
    sonda.set_setting("scan_enabled", "0")
    consentito, motivo = scanner.scanning_allowed()
    assert consentito is False
    assert "server" in motivo

    sonda.set_setting("scan_enabled", "1")
    sonda.set_setting("scan_paused", "1")
    consentito, motivo = scanner.scanning_allowed()
    assert consentito is False
    assert "sonda" in motivo


def test_lo_stato_espone_i_due_interruttori(sonda):
    scanner, _ = scanner_di(sonda)
    sonda.set_setting("scan_paused", "1")
    stato = scanner.status()
    assert stato["scanning_allowed"] is False
    assert stato["paused_locally"] is True
    assert stato["enabled_by_server"] is True
    assert stato["suspended_reason"]


def test_la_sonda_recepisce_l_interruttore_dalla_configurazione(probe_store):
    """Il valore arriva nella configurazione cifrata, come il perimetro."""
    from snapprobe.agent import ProbeAgent

    agente = ProbeAgent(probe_store, "1.0.0")
    agente._apply_server_config({"subnets": PERIMETRO, "scan_enabled": False})
    assert probe_store.get_setting("scan_enabled") == "0"
    agente._apply_server_config({"subnets": PERIMETRO, "scan_enabled": True})
    assert probe_store.get_setting("scan_enabled") == "1"


def test_i_comandi_del_server_sospendono_e_riprendono(probe_store):
    from snapprobe.agent import ProbeAgent

    agente = ProbeAgent(probe_store, "1.0.0")
    esito = agente._run_command("scan_pause", {})
    assert probe_store.get_setting("scan_paused") == "1"
    assert "sospese" in esito
    esito = agente._run_command("scan_resume", {})
    assert probe_store.get_setting("scan_paused") == "0"
    assert "riprese" in esito


# --------------------------------------------------------------------------- #
# La sospensione non ferma il conferimento
# --------------------------------------------------------------------------- #
def test_la_coda_resta_conferibile_a_scansioni_sospese(sonda):
    """Si sospende la scansione della rete, non il dialogo con il server."""
    sonda.enqueue("event", {"type": "probe.cycle", "description": "prova",
                            "created_at": "2026-08-27 09:00:00"})
    sonda.set_setting("scan_paused", "1")
    assert sonda.queue_size() == 1
    conferibili = sonda.reserve_batch("prova-sospensione")
    assert len(conferibili) == 1


# --------------------------------------------------------------------------- #
# Comandi ammessi sul server
# --------------------------------------------------------------------------- #
def test_i_comandi_di_sospensione_sono_fra_quelli_disponibili(server_app):
    with server_app.app_context():
        from snapserver.blueprints.probes import AVAILABLE_COMMANDS

    assert "scan_pause" in AVAILABLE_COMMANDS
    assert "scan_resume" in AVAILABLE_COMMANDS


def test_l_interruttore_di_una_sonda_si_riflette_nella_configurazione(server_app):
    with server_app.app_context():
        from snapserver.blueprints.api_probe import _probe_config
        from snapserver.db import execute, query, utc_now_str

        tenant = query("SELECT * FROM tenants ORDER BY id", (), one=True)
        adesso = utc_now_str()
        execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, scan_interval_sec,"
            " config_json, created_at, updated_at)"
            " VALUES (?, 'uid-sosp', 'sonda-sosp', 'Sonda', 'active', 300, '{}', ?, ?)",
            (int(tenant["id"]), adesso, adesso),
        )
        sonda = query("SELECT * FROM probes WHERE probe_uid = 'uid-sosp'", (), one=True)
        assert _probe_config(sonda, dict(tenant))["scan_enabled"] is True

        execute("UPDATE probes SET scan_enabled = 0 WHERE probe_uid = 'uid-sosp'")
        sonda = query("SELECT * FROM probes WHERE probe_uid = 'uid-sosp'", (), one=True)
        assert _probe_config(sonda, dict(tenant))["scan_enabled"] is False


def test_la_console_sospende_tutte_le_sonde_del_tenant(logged_client, server_app):
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        tenant = query("SELECT id FROM tenants ORDER BY id", (), one=True)
        adesso = utc_now_str()
    # Il superadmin apre sul primo tenant per NOME, non per id: il contesto va
    # portato esplicitamente sul tenant in cui si creano le sonde.
    logged_client.post("/switch-tenant", data={"tenant_id": int(tenant["id"])},
                       follow_redirects=True)
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        adesso = utc_now_str()
        for numero in range(3):
            execute(
                "INSERT INTO probes (tenant_id, probe_uid, code, name, status,"
                " scan_interval_sec, config_json, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, 'active', 300, '{}', ?, ?)",
                (int(tenant["id"]), "uid-%d" % numero, "sonda-%d" % numero,
                 "Sonda %d" % numero, adesso, adesso),
            )

    risposta = logged_client.post("/inventory/scanning", follow_redirects=True)
    assert risposta.status_code == 200

    with server_app.app_context():
        from snapserver.db import query

        attive = query("SELECT COUNT(*) AS n FROM probes WHERE tenant_id = ?"
                       " AND COALESCE(scan_enabled, 1) = 1", (int(tenant["id"]),), one=True)
        assert int(attive["n"]) == 0, "tutte le sonde del tenant devono essere sospese"
        evento = query("SELECT * FROM audit_events WHERE event_type = 'tenant.scan.disabled'",
                       (), one=True)
        assert evento is not None and evento["severity"] == "warning"
