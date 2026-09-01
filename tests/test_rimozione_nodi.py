"""
snap - Test della rimozione dei nodi privi di informazioni.

Regola: se dopo tutte le fasi applicabili -- porte, servizi, sistema operativo e
approfondimento -- un nodo non porta alcuna informazione utile, non e' un
dispositivo da inventariare ma un indirizzo che risponde al ping, e va rimosso.

La decisione e' della sonda, che sa quali fasi ha svolto; l'applicazione e' del
server, che rimuove solo dopo aver verificato di non avere dati propri. Cancellare
informazioni esistenti sulla parola di un solo osservatore sarebbe sbagliato.

Cautela verificata: dopo la rimozione l'indirizzo continua a rispondere al ping,
quindi la scoperta successiva non deve farlo rientrare subito.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from snapprobe.scanner import (
    NO_INFORMATION_COOLDOWN_SECONDS,
    STAGES_BEFORE_REMOVAL,
    NetworkScanner,
)

FIXTURES = Path(__file__).parent / "fixtures"
PERIMETRO = [{"cidr": "192.0.2.0/24", "label": "", "hosts": 254}]


class EsecutoreFinto:
    def __init__(self, xml: str = ""):
        self.xml = xml
        self.chiamate = []

    def detect_capabilities(self, force: bool = False) -> dict:
        return {"available": True, "executable": "nmap-finto", "nmap_version": "7.99",
                "raw_sockets": True, "os_detection": True, "detail": "prova"}

    def running_count(self) -> int:
        return 0

    def run(self, arguments, targets, timeout=None, label=None) -> str:
        # `label` descrive la fase in corso per l'indicatore: qui non serve,
        # ma la firma deve corrispondere a quella del runner vero.
        self.chiamate.append({"arguments": list(arguments), "targets": list(targets)})
        return self.xml


@pytest.fixture()
def sonda(probe_store):
    probe_store.set_json("scan_subnets", PERIMETRO)
    return probe_store


def nodo_locale(sonda, ip, profilo, fasi):
    """Prepara un nodo con un profilo e un insieme di fasi svolte."""
    sonda.upsert_local_node(ip, state="confirmed",
                            profile_json=json.dumps(profilo),
                            stages_done=",".join(sorted(fasi)),
                            last_merge_at="2026-08-27 09:00:00")


PROFILO_VUOTO = {
    "ip": "192.0.2.50", "reachable": True,
    "ports_index": {"tcp/80": {"protocol": "tcp", "port": 80, "state": "closed"},
                    "tcp/443": {"protocol": "tcp", "port": 443, "state": "closed"}},
}
PROFILO_CON_PORTA = {
    "ip": "192.0.2.51", "reachable": True,
    "ports_index": {"tcp/22": {"protocol": "tcp", "port": 22, "state": "open",
                               "service_name": "ssh"}},
}


# --------------------------------------------------------------------------- #
# Valutazione del profilo
# --------------------------------------------------------------------------- #
def test_le_porte_chiuse_non_sono_informazione():
    """Provano che qualcosa ha risposto, non dicono nulla sul dispositivo."""
    assert NetworkScanner.profile_has_information(PROFILO_VUOTO) is False


@pytest.mark.parametrize("aggiunta", [
    {"hostname": "stampante-1"},
    {"mac": "B8:27:EB:11:22:33"},
    {"mac_vendor": "Raspberry Pi Foundation"},
    {"os": {"name": "Linux 5.15"}},
    {"scripts": {"snmp-info": "qualcosa"}},
])
def test_qualunque_informazione_salva_il_nodo(aggiunta):
    profilo = dict(PROFILO_VUOTO, **aggiunta)
    assert NetworkScanner.profile_has_information(profilo) is True


def test_una_porta_aperta_e_informazione():
    assert NetworkScanner.profile_has_information(PROFILO_CON_PORTA) is True


def test_un_banner_su_porta_chiusa_e_informazione():
    profilo = dict(PROFILO_VUOTO)
    profilo["ports_index"] = {"tcp/80": {"protocol": "tcp", "port": 80, "state": "closed",
                                         "banner": "Server: nginx"}}
    assert NetworkScanner.profile_has_information(profilo) is True


def test_un_profilo_vuoto_o_assente_non_ha_informazioni():
    assert NetworkScanner.profile_has_information({}) is False
    assert NetworkScanner.profile_has_information(None) is False


# --------------------------------------------------------------------------- #
# Scarto sulla sonda
# --------------------------------------------------------------------------- #
def test_il_nodo_viene_scartato_solo_dopo_tutte_le_fasi(sonda):
    scanner = NetworkScanner(sonda, EsecutoreFinto())
    # Manca l'approfondimento: non si scarta ancora.
    nodo_locale(sonda, "192.0.2.50", PROFILO_VUOTO, ("ports", "services", "os"))
    assert scanner._drop_without_information() == []
    assert sonda.local_node("192.0.2.50")["state"] == "confirmed"

    # Con l'approfondimento svolto, si scarta.
    nodo_locale(sonda, "192.0.2.50", PROFILO_VUOTO, STAGES_BEFORE_REMOVAL)
    rimozioni = scanner._drop_without_information()
    assert [r["ip"] for r in rimozioni] == ["192.0.2.50"]
    assert sonda.local_node("192.0.2.50")["state"] == "discarded"


def test_un_nodo_con_informazioni_non_viene_scartato(sonda):
    scanner = NetworkScanner(sonda, EsecutoreFinto())
    nodo_locale(sonda, "192.0.2.51", PROFILO_CON_PORTA, STAGES_BEFORE_REMOVAL)
    assert scanner._drop_without_information() == []
    assert sonda.local_node("192.0.2.51")["state"] == "confirmed"


def test_il_record_di_rimozione_dichiara_il_motivo_e_le_fasi(sonda):
    scanner = NetworkScanner(sonda, EsecutoreFinto())
    nodo_locale(sonda, "192.0.2.50", PROFILO_VUOTO, STAGES_BEFORE_REMOVAL)
    rimozione = scanner._drop_without_information()[0]
    assert "nessuna informazione" in rimozione["reason"]
    assert set(rimozione["stages"]) == set(STAGES_BEFORE_REMOVAL)
    assert rimozione["decided_at"]


def test_lo_scarto_viene_annotato_nel_diario(sonda):
    scanner = NetworkScanner(sonda, EsecutoreFinto())
    nodo_locale(sonda, "192.0.2.50", PROFILO_VUOTO, STAGES_BEFORE_REMOVAL)
    scanner._drop_without_information()
    diario = " ".join(e["message"] for e in sonda.recent_events(5))
    assert "192.0.2.50" in diario and "scartato" in diario


def test_le_rimozioni_finiscono_fra_i_record_conferiti(sonda):
    scanner = NetworkScanner(sonda, EsecutoreFinto())
    nodo_locale(sonda, "192.0.2.50", PROFILO_VUOTO, STAGES_BEFORE_REMOVAL)
    record = scanner._confer_complete_profiles()
    assert "removals" in record
    assert record["removals"][0]["ip"] == "192.0.2.50"


def test_un_profilo_illeggibile_non_provoca_lo_scarto(sonda):
    """Nel dubbio non si cancella: si dichiara e si lascia il nodo."""
    scanner = NetworkScanner(sonda, EsecutoreFinto())
    sonda.upsert_local_node("192.0.2.52", state="confirmed",
                            profile_json="{non è json",
                            stages_done=",".join(sorted(STAGES_BEFORE_REMOVAL)))
    assert scanner._drop_without_information() == []
    assert sonda.local_node("192.0.2.52")["state"] == "confirmed"
    diario = " ".join(e["message"] for e in sonda.recent_events(5))
    assert "illeggibile" in diario


# --------------------------------------------------------------------------- #
# Periodo di attesa: il nodo non rientra subito
# --------------------------------------------------------------------------- #
def test_un_nodo_scartato_non_torna_con_la_scoperta_successiva(sonda):
    scanner = NetworkScanner(sonda, EsecutoreFinto(
        (FIXTURES / "nmap_scoperta.xml").read_text(encoding="utf-8")))
    # 192.0.2.1 e' fra gli host della fixture di scoperta.
    nodo_locale(sonda, "192.0.2.1", PROFILO_VUOTO, STAGES_BEFORE_REMOVAL)
    scanner._drop_without_information()
    assert sonda.local_node("192.0.2.1")["state"] == "discarded"

    scanner.run_stage("discovery", "192.0.2.0/24")
    assert sonda.local_node("192.0.2.1")["state"] == "discarded", (
        "la scoperta ha fatto rientrare un nodo appena scartato"
    )


def test_un_nodo_scartato_resta_fuori_dai_bersagli(sonda):
    scanner = NetworkScanner(sonda, EsecutoreFinto())
    nodo_locale(sonda, "192.0.2.50", PROFILO_VUOTO, STAGES_BEFORE_REMOVAL)
    scanner._drop_without_information()
    assert "192.0.2.50" not in scanner._targets_for("ports")
    assert scanner.pending_nodes() == []


def test_il_periodo_di_attesa_e_dichiarato_ed_esteso():
    """Sette giorni: abbastanza perche' il giro non si ripeta di continuo."""
    assert NO_INFORMATION_COOLDOWN_SECONDS >= 24 * 3600


def test_scaduto_il_periodo_di_attesa_il_nodo_puo_tornare(sonda):
    import sqlite3

    scanner = NetworkScanner(sonda, EsecutoreFinto())
    nodo_locale(sonda, "192.0.2.50", PROFILO_VUOTO, STAGES_BEFORE_REMOVAL)
    scanner._drop_without_information()

    connessione = sqlite3.connect(str(sonda.path))
    connessione.execute("UPDATE local_nodes SET discarded_at = datetime('now', '-30 days')")
    connessione.commit()
    connessione.close()

    assert scanner._still_in_cooldown(sonda.local_node("192.0.2.50")) is False


# --------------------------------------------------------------------------- #
# Applicazione sul server
# --------------------------------------------------------------------------- #
@pytest.fixture()
def inventario(server_app):
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str
        from snapserver.subnets import import_subnets

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
        import_subnets(tenant_id, "10.50.9.0/24 Sede\n", "perimetro.txt")
        adesso = utc_now_str()
        probe_id = execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, scan_interval_sec,"
            " config_json, created_at, updated_at)"
            " VALUES (?, ?, 'sonda-1', 'Sonda 1', 'active', 300, '{}', ?, ?)",
            (tenant_id, uuid.uuid4().hex, adesso, adesso),
        )
        yield {"tenant_id": tenant_id, "probe_id": probe_id}


def conferisci(inventario, records: dict) -> dict:
    from snapserver.ingest import apply_batch

    return apply_batch(tenant_id=inventario["tenant_id"], probe_id=inventario["probe_id"],
                       payload={"batch_uid": uuid.uuid4().hex, "records": records},
                       payload_bytes=512)


NODO = {"ip": "10.50.9.77", "reachable": True, "seen_at": "2026-08-27 09:00:00"}


def test_il_server_rimuove_il_nodo_privo_di_informazioni(server_app, inventario):
    with server_app.app_context():
        from snapserver.db import query

        conferisci(inventario, {"nodes": [NODO]})
        assert query("SELECT COUNT(*) AS n FROM nodes", (), one=True)["n"] == 1

        esito = conferisci(inventario, {"removals": [
            {"ip": NODO["ip"], "reason": "nessuna informazione dopo tutte le fasi",
             "stages": ["ports", "services", "os", "deep"],
             "decided_at": "2026-08-27 09:30:00"}]})
        assert esito["removed"] == 1
        assert query("SELECT COUNT(*) AS n FROM nodes", (), one=True)["n"] == 0


def test_la_rimozione_lascia_traccia_dopo_la_cancellazione(server_app, inventario):
    with server_app.app_context():
        from snapserver.db import query

        conferisci(inventario, {"nodes": [NODO]})
        conferisci(inventario, {"removals": [{"ip": NODO["ip"], "reason": "vuoto"}]})

        deriva = query("SELECT * FROM node_changes WHERE kind = 'node.removed'", (), one=True)
        assert deriva is not None
        assert deriva["node_id"] is None, "la traccia deve sopravvivere al nodo"
        assert deriva["subject"] == NODO["ip"]

        evento = query("SELECT * FROM audit_events WHERE event_type = 'node.removed'",
                       (), one=True)
        assert evento is not None
        assert NODO["ip"] in evento["description"]


def test_il_server_rifiuta_la_rimozione_se_ha_dati_propri(server_app, inventario):
    """Non si cancellano informazioni esistenti sulla parola di un osservatore."""
    with server_app.app_context():
        from snapserver.db import query

        conferisci(inventario, {
            "nodes": [dict(NODO, ports_examined=True)],
            "ports": [{"ip": NODO["ip"], "protocol": "tcp", "port": 22, "state": "open",
                       "service_name": "ssh"}],
        })
        esito = conferisci(inventario, {"removals": [{"ip": NODO["ip"], "reason": "vuoto"}]})

        assert esito["removed"] == 0
        assert esito["removals_refused"] == 1
        assert query("SELECT COUNT(*) AS n FROM nodes", (), one=True)["n"] == 1
        rifiuto = query("SELECT * FROM audit_events WHERE event_type = 'node.removal.refused'",
                        (), one=True)
        assert rifiuto is not None
        assert rifiuto["severity"] == "warning"


def test_un_nodo_annotato_dall_operatore_non_viene_rimosso(server_app, inventario):
    with server_app.app_context():
        from snapserver.db import execute, query

        conferisci(inventario, {"nodes": [NODO]})
        execute("UPDATE nodes SET notes = 'da verificare' WHERE ip = ?", (NODO["ip"],))
        esito = conferisci(inventario, {"removals": [{"ip": NODO["ip"], "reason": "vuoto"}]})
        assert esito["removed"] == 0
        assert query("SELECT COUNT(*) AS n FROM nodes", (), one=True)["n"] == 1


def test_una_rimozione_per_un_nodo_inesistente_non_e_un_errore(server_app, inventario):
    with server_app.app_context():
        esito = conferisci(inventario, {"removals": [{"ip": "10.50.9.200", "reason": "vuoto"}]})
        assert esito["accepted"] is True
        assert esito["removed"] == 0


def test_una_rimozione_senza_indirizzo_viene_rifiutata(server_app, inventario):
    with server_app.app_context():
        from snapserver.ingest import IngestError

        with pytest.raises(IngestError):
            conferisci(inventario, {"removals": [{"reason": "vuoto"}]})


def test_le_porte_sospette_non_salvano_un_nodo_dalla_rimozione(server_app, inventario):
    """Una porta iniettata dalla rete non e' un'informazione sul nodo."""
    with server_app.app_context():
        from snapserver.db import execute, query
        from snapserver.ingest import node_has_information

        conferisci(inventario, {
            "nodes": [dict(NODO, ports_examined=True)],
            "ports": [{"ip": NODO["ip"], "protocol": "tcp", "port": 5060, "state": "open",
                       "service_name": "sip"}],
        })
        from snapserver.ingest import refresh_fingerprint

        nodo = query("SELECT id FROM nodes WHERE ip = ?", (NODO["ip"],), one=True)
        execute("UPDATE node_ports SET is_suspect = 1 WHERE port = 5060")
        # Nel flusso reale il riconoscimento delle porte iniettate precede il
        # fingerprinting: senza la rideterminazione il verdetto precedente
        # resterebbe, ed e' quello a valere come informazione.
        refresh_fingerprint(inventario["tenant_id"], int(nodo["id"]))
        ha_dati, informazioni = node_has_information(inventario["tenant_id"], int(nodo["id"]))
    assert ha_dati is False, "informazioni trovate: %s" % informazioni
