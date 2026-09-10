"""
snap - Test dell'applicazione dei conferimenti dell'inventario.

Verificano il contratto esteso (nodi, porte, sistema operativo, script,
monitoraggio, telemetria), il calcolo della deriva e due proprieta' che si
perdono facilmente:

  * la cronologia dei dati raccolti durante un periodo di isolamento, che non
    deve essere appiattita sull'ora del conferimento;
  * la rideterminazione del tipo di dispositivo dalle prove conservate, senza
    nuove scansioni.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import uuid

import pytest


@pytest.fixture()
def inventario(server_app):
    """Tenant con perimetro e una sonda registrata, dentro il contesto applicativo."""
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


def conferisci(inventario, records: dict, uid: str = None) -> dict:
    from snapserver.ingest import apply_batch

    return apply_batch(
        tenant_id=inventario["tenant_id"],
        probe_id=inventario["probe_id"],
        payload={"batch_uid": uid or uuid.uuid4().hex, "records": records},
        payload_bytes=1024,
    )


NODO = {"ip": "10.50.9.18", "hostname": "stampante-1", "reachable": True,
        "latency_ms": 3.5, "seen_at": "2026-08-27 09:00:00"}


# --------------------------------------------------------------------------- #
# Nodi
# --------------------------------------------------------------------------- #
def test_un_nodo_conferito_entra_in_inventario_e_genera_la_comparsa(server_app, inventario):
    with server_app.app_context():
        from snapserver.db import query

        esito = conferisci(inventario, {"nodes": [NODO]})
        assert esito["accepted"] is True
        assert esito["detail"]["nodes"] == 1

        nodo = query("SELECT * FROM nodes WHERE ip = '10.50.9.18'", (), one=True)
        assert nodo is not None
        assert nodo["status"] == "up"
        assert nodo["hostname"] == "stampante-1"
        # Il nodo viene collegato alla subnet dichiarata.
        assert nodo["subnet_id"] is not None

        cambiamenti = query("SELECT * FROM node_changes WHERE node_id = ?", (nodo["id"],))
        generi = {c["kind"] for c in cambiamenti}
        assert "node.appeared" in generi


def test_il_conferimento_e_idempotente(server_app, inventario):
    with server_app.app_context():
        from snapserver.db import query

        uid = uuid.uuid4().hex
        conferisci(inventario, {"nodes": [NODO]}, uid=uid)
        ripetuto = conferisci(inventario, {"nodes": [NODO]}, uid=uid)
        assert ripetuto["duplicate"] is True
        assert len(query("SELECT * FROM nodes", ())) == 1


def test_una_porta_senza_il_proprio_nodo_viene_saltata_senza_creare_nodi(server_app, inventario):
    """Il record orfano non crea un nodo implicito e non fa cadere il lotto.

    Un lotto puo' essere spezzato quando supera il numero massimo di record: le
    porte di un nodo possono arrivare separate dal nodo. Rifiutare il lotto lo
    renderebbe intrasmissibile per sempre; creare il nodo aggirerebbe la regola
    di ammissione. Si salta contando, e la scansione successiva lo riproporra'.
    """
    with server_app.app_context():
        from snapserver.db import query

        esito = conferisci(inventario, {"ports": [{"ip": "10.50.9.99", "protocol": "tcp",
                                                   "port": 80, "state": "open"}]})
        assert esito["accepted"] is True
        assert esito["orphans"] == 1
        assert query("SELECT COUNT(*) AS n FROM nodes", (), one=True)["n"] == 0
        # La condizione va vista, non nascosta.
        avviso = query("SELECT * FROM audit_events WHERE event_type = 'probe.ingest.orphans'",
                       (), one=True)
        assert avviso is not None
        assert avviso["severity"] == "warning"


def test_un_tipo_di_record_sconosciuto_viene_rifiutato_per_nome(server_app, inventario):
    with server_app.app_context():
        from snapserver.ingest import IngestError

        with pytest.raises(IngestError) as errore:
            conferisci(inventario, {"pinguini": [{"ip": "10.50.9.1"}]})
        assert "pinguini" in str(errore.value)


# --------------------------------------------------------------------------- #
# Porte, servizi e deriva
# --------------------------------------------------------------------------- #
def test_le_porte_vengono_registrate_e_la_deriva_annota_l_apertura(server_app, inventario):
    with server_app.app_context():
        from snapserver.db import query

        conferisci(inventario, {
            "nodes": [dict(NODO, ports_examined=True)],
            "ports": [{"ip": NODO["ip"], "protocol": "tcp", "port": 9100, "state": "open",
                       "service_name": "jetdirect", "product": "HP LaserJet"}],
        })
        porta = query("SELECT * FROM node_ports WHERE port = 9100", (), one=True)
        assert porta["state"] == "open"
        assert porta["service_name"] == "jetdirect"
        assert "port.opened" in {c["kind"] for c in query("SELECT * FROM node_changes", ())}


def test_una_porta_non_piu_vista_viene_chiusa_e_annotata(server_app, inventario):
    with server_app.app_context():
        from snapserver.db import query

        conferisci(inventario, {
            "nodes": [dict(NODO, ports_examined=True)],
            "ports": [{"ip": NODO["ip"], "protocol": "tcp", "port": 9100, "state": "open"},
                      {"ip": NODO["ip"], "protocol": "tcp", "port": 515, "state": "open"}],
        })
        # Seconda passata: la 515 non c'e' piu'.
        conferisci(inventario, {
            "nodes": [dict(NODO, ports_examined=True)],
            "ports": [{"ip": NODO["ip"], "protocol": "tcp", "port": 9100, "state": "open"}],
        })
        chiusa = query("SELECT * FROM node_ports WHERE port = 515", (), one=True)
        assert chiusa["state"] == "closed"
        assert chiusa["closed_at"] is not None
        assert "port.closed" in {c["kind"] for c in query("SELECT * FROM node_changes", ())}


def test_una_scansione_parziale_non_chiude_le_porte(server_app, inventario):
    """Senza dichiarazione di esame completo, le porte non viste restano aperte."""
    with server_app.app_context():
        from snapserver.db import query

        conferisci(inventario, {
            "nodes": [dict(NODO, ports_examined=True)],
            "ports": [{"ip": NODO["ip"], "protocol": "tcp", "port": 9100, "state": "open"},
                      {"ip": NODO["ip"], "protocol": "tcp", "port": 515, "state": "open"}],
        })
        conferisci(inventario, {"nodes": [NODO]})  # nessun esame delle porte
        assert query("SELECT * FROM node_ports WHERE port = 515", (), one=True)["state"] == "open"


def test_il_cambio_di_versione_di_un_servizio_e_annotato(server_app, inventario):
    with server_app.app_context():
        from snapserver.db import query

        base = {"ip": NODO["ip"], "protocol": "tcp", "port": 443, "state": "open",
                "service_name": "https", "product": "nginx"}
        conferisci(inventario, {"nodes": [NODO], "ports": [dict(base, version="1.24")]})
        conferisci(inventario, {"nodes": [NODO], "ports": [dict(base, version="1.26")]})
        cambio = query("SELECT * FROM node_changes WHERE kind = 'service.changed'", (), one=True)
        assert cambio is not None
        assert "1.24" in cambio["before_value"]
        assert "1.26" in cambio["after_value"]


def test_il_cambio_di_sistema_operativo_e_annotato(server_app, inventario):
    with server_app.app_context():
        from snapserver.db import query

        conferisci(inventario, {"nodes": [NODO],
                                "os": [{"ip": NODO["ip"], "name": "Linux 5.15",
                                        "family": "Linux", "accuracy": 96}]})
        conferisci(inventario, {"nodes": [NODO],
                                "os": [{"ip": NODO["ip"], "name": "Linux 6.1",
                                        "family": "Linux", "accuracy": 98}]})
        cambio = query("SELECT * FROM node_changes WHERE kind = 'os.changed'", (), one=True)
        assert cambio is not None
        assert cambio["severity"] == "warning"


def test_il_passaggio_a_non_raggiungibile_e_annotato(server_app, inventario):
    with server_app.app_context():
        from snapserver.db import query

        conferisci(inventario, {"nodes": [NODO]})
        conferisci(inventario, {"monitor": [{"ip": NODO["ip"], "reachable": False,
                                             "checked_at": "2026-08-27 09:10:00"}]})
        nodo = query("SELECT * FROM nodes WHERE ip = ?", (NODO["ip"],), one=True)
        assert nodo["status"] == "down"
        assert "node.down" in {c["kind"] for c in query("SELECT * FROM node_changes", ())}


# --------------------------------------------------------------------------- #
# Cronologia
# --------------------------------------------------------------------------- #
def test_l_istante_dichiarato_dalla_sonda_viene_conservato(server_app, inventario):
    """Un campione raccolto tre ore prima non deve assumere l'ora del conferimento."""
    with server_app.app_context():
        from snapserver.db import query

        conferisci(inventario, {"nodes": [NODO]})
        conferisci(inventario, {"monitor": [{"ip": NODO["ip"], "reachable": True,
                                             "latency_ms": 2.0,
                                             "checked_at": "2026-08-27 06:00:00"}]})
        campione = query("SELECT * FROM monitor_samples", (), one=True)
    assert campione["checked_at"] == "2026-08-27 06:00:00"


def test_la_cronologia_degli_eventi_della_sonda_viene_conservata(server_app, inventario):
    """Era il difetto trovato sul campo: l'ora di raccolta veniva scartata."""
    with server_app.app_context():
        from snapserver.db import query

        conferisci(inventario, {"events": [{
            "type": "probe.cycle",
            "description": "Ciclo eseguito durante l'isolamento",
            "created_at": "2026-08-27 05:48:16",
            "severity": "info",
        }]})
        evento = query("SELECT * FROM audit_events WHERE event_type = 'probe.cycle'",
                       (), one=True)
    assert evento["created_at"] == "2026-08-27 05:48:16"


def test_un_istante_illeggibile_ricade_sull_ora_di_ricezione(server_app, inventario):
    with server_app.app_context():
        from snapserver.db import query

        conferisci(inventario, {"events": [{"type": "probe.cycle", "description": "x",
                                            "created_at": "non-una-data"}]})
        evento = query("SELECT * FROM audit_events WHERE event_type = 'probe.cycle'",
                       (), one=True)
    assert evento["created_at"] and evento["created_at"] != "non-una-data"


# --------------------------------------------------------------------------- #
# Fingerprinting
# --------------------------------------------------------------------------- #
def test_il_tipo_di_dispositivo_viene_determinato_dalle_prove(server_app, inventario):
    with server_app.app_context():
        from snapserver.db import query

        conferisci(inventario, {
            "nodes": [dict(NODO, ports_examined=True)],
            "ports": [
                {"ip": NODO["ip"], "protocol": "tcp", "port": 9100, "state": "open",
                 "service_name": "jetdirect", "product": "HP LaserJet P4014"},
                {"ip": NODO["ip"], "protocol": "tcp", "port": 515, "state": "open",
                 "service_name": "printer"},
                {"ip": NODO["ip"], "protocol": "tcp", "port": 631, "state": "open",
                 "service_name": "ipp"},
            ],
        })
        nodo = query("SELECT * FROM nodes WHERE ip = ?", (NODO["ip"],), one=True)
    assert nodo["device_type"] == "printer"
    assert nodo["device_confidence"] > 60
    assert nodo["catalog_version"]
    # Le prove restano conservate: e' cio' che permette la rideterminazione.
    assert "evidence" in nodo["fingerprint_json"]


def test_gli_esiti_degli_script_diventano_prove(server_app, inventario):
    with server_app.app_context():
        from snapserver.db import query

        conferisci(inventario, {
            "nodes": [NODO],
            "ports": [{"ip": NODO["ip"], "protocol": "udp", "port": 161, "state": "open",
                       "service_name": "snmp"}],
            "scripts": [{"ip": NODO["ip"], "name": "snmp-info",
                         "output": "APC Smart-UPS 3000 PowerChute"}],
        })
        nodo = query("SELECT * FROM nodes WHERE ip = ?", (NODO["ip"],), one=True)
    # La regola decisiva sul gruppo di continuita' scatta grazie allo script.
    assert nodo["device_type"] == "ups"


def test_la_rideterminazione_non_richiede_nuove_scansioni(server_app, inventario):
    with server_app.app_context():
        from snapserver.db import execute, query
        from snapserver.ingest import refingerprint_tenant

        conferisci(inventario, {
            "nodes": [dict(NODO, ports_examined=True)],
            "ports": [{"ip": NODO["ip"], "protocol": "tcp", "port": 9100, "state": "open",
                       "service_name": "jetdirect"}],
        })
        # Si altera il verdetto in banca dati: la rideterminazione deve ripristinarlo
        # partendo dalle sole prove conservate.
        execute("UPDATE nodes SET device_type = 'unknown', device_label = 'Non identificato'"
                " WHERE ip = ?", (NODO["ip"],))
        esito = refingerprint_tenant(inventario["tenant_id"])
        nodo = query("SELECT * FROM nodes WHERE ip = ?", (NODO["ip"],), one=True)
    assert esito["nodes"] == 1
    assert esito["changed"] == 1
    assert nodo["device_type"] == "printer"


def test_il_cambio_di_tipo_viene_annotato(server_app, inventario):
    with server_app.app_context():
        from snapserver.db import query

        conferisci(inventario, {"nodes": [NODO],
                                "ports": [{"ip": NODO["ip"], "protocol": "tcp", "port": 22,
                                           "state": "open", "service_name": "ssh"}]})
        conferisci(inventario, {"nodes": [NODO],
                                "ports": [{"ip": NODO["ip"], "protocol": "tcp", "port": 9100,
                                           "state": "open", "service_name": "jetdirect"},
                                          {"ip": NODO["ip"], "protocol": "tcp", "port": 515,
                                           "state": "open", "service_name": "printer"}]})
        cambi = query("SELECT * FROM node_changes WHERE kind = 'device_type.changed'", ())
    assert cambi, "il cambio di tipo non e' stato annotato"


# --------------------------------------------------------------------------- #
# Telemetria e consultazione
# --------------------------------------------------------------------------- #
def test_la_telemetria_di_scansione_e_collegata_al_lotto(server_app, inventario):
    with server_app.app_context():
        from snapserver.db import query

        conferisci(inventario, {"scan_runs": [{
            "stage": "discovery", "target": "10.50.9.0/24", "status": "completed",
            "started_at": "2026-08-27 09:00:00", "finished_at": "2026-08-27 09:00:08",
            "duration_ms": 7350, "hosts_total": 256, "hosts_up": 8,
            "nmap_args": "-sn -PE", "nmap_version": "7.99",
        }]})
        run = query("SELECT * FROM scan_runs", (), one=True)
        lotto = query("SELECT * FROM ingest_batches", (), one=True)
    assert run["batch_id"] == lotto["id"]
    assert run["hosts_up"] == 8


def test_i_record_conferiti_sono_conservati_per_la_consultazione(server_app, inventario):
    with server_app.app_context():
        from snapserver.db import query

        conferisci(inventario, {"nodes": [NODO]})
        lotto = query("SELECT * FROM ingest_batches", (), one=True)
    assert lotto["records_json"], "il contenuto del lotto non e' stato conservato"
    assert NODO["ip"] in lotto["records_json"]
    assert int(lotto["records_truncated"]) == 0


def test_un_lotto_molto_grande_viene_conservato_in_estratto(server_app, inventario):
    with server_app.app_context():
        from snapserver.db import query

        # Il limite di conservazione e' 256 kB: servono record abbondantemente
        # oltre quella soglia perche' l'estratto entri in gioco.
        molti = [{"ip": "10.50.9.%d" % (i % 250 + 1), "hostname": "nodo-%d" % i,
                  "reachable": True, "seen_at": "2026-08-27 09:00:00",
                  "note": "x" * 1200} for i in range(500)]
        conferisci(inventario, {"nodes": molti})
        lotto = query("SELECT * FROM ingest_batches", (), one=True)
    assert int(lotto["records_truncated"]) == 1
    assert "_nota" in lotto["records_json"]


def test_un_nodo_non_piu_visto_nella_scoperta_risulta_scomparso(server_app, inventario):
    with server_app.app_context():
        from snapserver.db import execute, query

        conferisci(inventario, {"nodes": [NODO]})
        # Si retrodata l'ultimo avvistamento, poi arriva una scoperta che non lo vede.
        execute("UPDATE nodes SET last_seen_at = '2026-08-27 08:00:00' WHERE ip = ?",
                (NODO["ip"],))
        conferisci(inventario, {"scan_runs": [{
            "stage": "discovery", "target": "10.50.9.0/24", "status": "completed",
            "started_at": "2026-08-27 09:00:00", "finished_at": "2026-08-27 09:00:08",
        }]})
        nodo = query("SELECT * FROM nodes WHERE ip = ?", (NODO["ip"],), one=True)
        generi = {c["kind"] for c in query("SELECT * FROM node_changes", ())}
    assert nodo["status"] == "down"
    assert "node.disappeared" in generi


# --------------------------------------------------------------------------- #
# Porte iniettate dalla rete
# --------------------------------------------------------------------------- #
def test_le_porte_aperte_su_tutti_i_nodi_e_su_sistemi_diversi_sono_riconosciute(
        server_app, inventario):
    """Difetto reale: un ALG SIP rispondeva su 2000 e 5060 per ogni indirizzo.

    Trenta dispositivi su trentadue venivano classificati come telefono VoIP.
    Le porte iniettate vanno marcate ed escluse dalle prove, non cancellate.
    """
    with server_app.app_context():
        from snapserver.db import query

        famiglie = ["Linux", "Windows", "IOS", "QTS"]
        nodi, porte, sistemi = [], [], []
        for indice in range(12):
            ip = "10.50.9.%d" % (indice + 20)
            nodi.append({"ip": ip, "reachable": True, "seen_at": "2026-08-27 09:00:00",
                         "ports_examined": True})
            # Porte iniettate dalla rete su ogni nodo.
            for numero, servizio in ((2000, "cisco-sccp"), (5060, "sip")):
                porte.append({"ip": ip, "protocol": "tcp", "port": numero, "state": "open",
                              "service_name": servizio})
            # Una porta propria, presente solo su una parte dei nodi.
            if indice % 2 == 0:
                porte.append({"ip": ip, "protocol": "tcp", "port": 22, "state": "open",
                              "service_name": "ssh", "product": "OpenSSH"})
            sistemi.append({"ip": ip, "name": "%s di prova" % famiglie[indice % 4],
                            "family": famiglie[indice % 4], "accuracy": 95})

        esito = conferisci(inventario, {"nodes": nodi, "ports": porte, "os": sistemi})
        assert "tcp/2000" in esito["suspect_ports"]
        assert "tcp/5060" in esito["suspect_ports"]
        assert "tcp/22" not in esito["suspect_ports"], (
            "una porta presente solo su una parte dei nodi non e' un'iniezione"
        )

        # Marcate, non cancellate, e con la motivazione.
        marcata = query("SELECT * FROM node_ports WHERE port = 5060 LIMIT 1", (), one=True)
        assert int(marcata["is_suspect"]) == 1
        assert marcata["suspect_reason"]
        assert marcata["state"] == "open", "la porta resta visibile come aperta"

        # Nessun nodo classificato come telefono per effetto delle porte iniettate.
        tipi = {r["device_type"] for r in query("SELECT device_type FROM nodes", ())}
        assert "voip_phone" not in tipi


def test_le_prove_del_fingerprinting_escludono_le_porte_iniettate(server_app, inventario):
    with server_app.app_context():
        from snapserver.db import execute, query
        from snapserver.ingest import build_evidence

        conferisci(inventario, {
            "nodes": [dict(NODO, ports_examined=True)],
            "ports": [{"ip": NODO["ip"], "protocol": "tcp", "port": 5060, "state": "open",
                       "service_name": "sip"},
                      {"ip": NODO["ip"], "protocol": "tcp", "port": 22, "state": "open",
                       "service_name": "ssh"}],
        })
        nodo = query("SELECT id FROM nodes WHERE ip = ?", (NODO["ip"],), one=True)
        execute("UPDATE node_ports SET is_suspect = 1 WHERE port = 5060")
        prove = build_evidence(inventario["tenant_id"], int(nodo["id"]))

    numeri = {p["port"] for p in prove["ports"]}
    assert 5060 not in numeri, "la porta iniettata non deve entrare fra le prove"
    assert 22 in numeri


def test_una_porta_con_prodotto_riconosciuto_non_viene_marcata(server_app, inventario):
    """Se nmap ha identificato il prodotto, e' un servizio reale.

    E' la salvaguardia contro i falsi positivi del riconoscimento per diffusione.
    """
    with server_app.app_context():
        famiglie = ["Linux", "Windows", "IOS", "QTS"]
        nodi, porte, sistemi = [], [], []
        for indice in range(12):
            ip = "10.50.9.%d" % (indice + 40)
            nodi.append({"ip": ip, "reachable": True, "seen_at": "2026-08-27 09:00:00",
                         "ports_examined": True})
            # Presente su tutti i nodi e su tutte le famiglie, ma identificata.
            porte.append({"ip": ip, "protocol": "tcp", "port": 443, "state": "open",
                          "service_name": "https",
                          "product": "nginx" if indice == 0 else None})
            sistemi.append({"ip": ip, "name": "%s di prova" % famiglie[indice % 4],
                            "family": famiglie[indice % 4], "accuracy": 95})
        esito = conferisci(inventario, {"nodes": nodi, "ports": porte, "os": sistemi})
    assert "tcp/443" not in esito["suspect_ports"]


def test_una_porta_che_risponde_dove_non_puo_esistere_un_host_e_iniettata_subito(
        server_app, inventario):
    """IL CASO DELLA RETE OSPITI, misurato in esercizio.

    Su 10.10.60.0/24 la tcp/5060 risultava aperta sul 53% dei nodi -- sotto la soglia
    di diffusione -- E sull'indirizzo di rete E su quello di broadcast, dove un host
    non puo' esistere. La soglia veniva applicata PRIMA di guardare l'indirizzo
    impossibile, quindi la prova forte non arrivava mai a contare: 128 nodi
    classificati "Telefono VoIP" da una porta che un apparato intermedio serve per
    tutto il segmento.

    Peggio della classificazione sbagliata: la diffusione CRESCE durante la passata,
    quindi la marcatura sarebbe arrivata solo a scansione conclusa. Nel frattempo
    l'inventario era sbagliato e sembrava giusto.

    Se la porta risponde dove un host non puo' esistere, il fatto e' accertato e non
    ha bisogno di essere anche diffuso.
    """
    with server_app.app_context():
        from snapserver.db import query

        nodi, porte = [], []
        # Meta' dei nodi espone la 5060: sotto la soglia di diffusione.
        for indice in range(12):
            ip = "10.50.9.%d" % (indice + 100)
            nodi.append({"ip": ip, "reachable": True, "ports_examined": True,
                         "seen_at": "2026-09-10 09:00:00"})
            if indice % 2 == 0:
                porte.append({"ip": ip, "protocol": "tcp", "port": 5060,
                              "state": "open", "service_name": "sip"})
        # L'indirizzo di rete e quello di broadcast rispondono anche loro: la' non
        # c'e' nessun host, quindi risponde un apparato intermedio.
        for ip in ("10.50.9.0", "10.50.9.255"):
            nodi.append({"ip": ip, "reachable": True, "ports_examined": True,
                         "seen_at": "2026-09-10 09:00:00"})
            porte.append({"ip": ip, "protocol": "tcp", "port": 5060, "state": "open",
                          "service_name": "sip"})

        esito = conferisci(inventario, {"nodes": nodi, "ports": porte})

        assert "tcp/5060" in esito["suspect_ports"], (
            "la prova dell'indirizzo impossibile non deve dipendere dalla diffusione")
        marcate = query(
            "SELECT COUNT(*) AS n FROM node_ports WHERE port = 5060"
            " AND COALESCE(is_suspect, 0) = 1", (), one=True)
        assert int(marcate["n"]) == 8, "marcata su tutti i nodi del segmento"
        motivo = query(
            "SELECT suspect_reason FROM node_ports WHERE port = 5060"
            " AND COALESCE(is_suspect, 0) = 1 LIMIT 1", (), one=True)
        assert "non puo' esistere un host" in motivo["suspect_reason"]

        # E il verdetto: nessun telefono inventato da quella sola porta.
        tipi = {r["device_type"] for r in query(
            "SELECT device_type FROM nodes WHERE ip LIKE '10.50.9.1%'", ())}
        assert "voip_phone" not in tipi


def test_senza_indirizzo_impossibile_la_diffusione_resta_necessaria(
        server_app, inventario):
    """Il contrario del test precedente, e serve: senza la prova accertata una porta
    presente su meta' dei nodi e' solo una porta presente su meta' dei nodi. Marcarla
    sopprimerebbe servizi veri -- il difetto opposto, e piu' difficile da notare."""
    with server_app.app_context():
        from snapserver.db import query

        nodi, porte = [], []
        for indice in range(12):
            ip = "10.50.9.%d" % (indice + 150)
            nodi.append({"ip": ip, "reachable": True, "ports_examined": True,
                         "seen_at": "2026-09-10 09:00:00"})
            if indice % 2 == 0:
                porte.append({"ip": ip, "protocol": "tcp", "port": 8443,
                              "state": "open", "service_name": "https-alt"})

        esito = conferisci(inventario, {"nodes": nodi, "ports": porte})

        assert "tcp/8443" not in esito["suspect_ports"]
        marcate = query(
            "SELECT COUNT(*) AS n FROM node_ports WHERE port = 8443"
            " AND COALESCE(is_suspect, 0) = 1", (), one=True)
        assert int(marcate["n"]) == 0


def test_su_un_segmento_servito_da_un_apparato_intermedio_basta_meta_diffusione(
        server_app, inventario):
    """LA RETE OSPITI, come si presentava davvero.

    Su 10.10.60.0/24 rispondevano 256 indirizzi su 254 possibili -- compresi quello di
    rete e quello di broadcast -- senza un solo MAC e con TTL identico su tutti. Le
    porte degli indirizzi impossibili non erano ancora state esaminate, quindi la
    prova "porta aperta dove non puo' esserci un host" non era disponibile; la
    tcp/5060, aperta sul 53% dei nodi, restava sotto la soglia ordinaria e produceva
    128 "Telefono VoIP".

    Il segnale che c'era, e arriva con la SOLA SCOPERTA: se l'indirizzo di rete o
    quello di broadcast RISPONDONO, la' non c'e' nessun host e qualcuno risponde per
    il segmento. Su un segmento cosi' non si sa nemmeno quali indirizzi siano host, e
    una porta presente su meta' di essi non e' attribuibile a nessuno.
    """
    with server_app.app_context():
        from snapserver.db import query

        nodi, porte = [], []
        # L'indirizzo di rete e quello di broadcast rispondono al ping, e basta: nessuna
        # porta esaminata su di loro.
        for ip in ("10.50.9.0", "10.50.9.255"):
            nodi.append({"ip": ip, "reachable": True,
                         "seen_at": "2026-09-10 09:00:00"})
        # La 5060 su 12 nodi di 22: il 54%, la stessa proporzione misurata sulla rete
        # ospiti (137 su 256). Sopra la soglia del segmento servito, largamente sotto
        # quella ordinaria del 95%.
        for indice in range(20):
            ip = "10.50.9.%d" % (indice + 60)
            nodi.append({"ip": ip, "reachable": True, "ports_examined": True,
                         "seen_at": "2026-09-10 09:00:00"})
            if indice < 12:
                porte.append({"ip": ip, "protocol": "tcp", "port": 5060,
                              "state": "open", "service_name": "sip"})
            # Una porta di pochi nodi: sono macchine vere dietro l'apparato
            # intermedio, e sopprimerle sarebbe il difetto opposto.
            if indice == 19:
                porte.append({"ip": ip, "protocol": "tcp", "port": 445,
                              "state": "open", "service_name": "microsoft-ds"})

        esito = conferisci(inventario, {"nodes": nodi, "ports": porte})

        assert "tcp/5060" in esito["suspect_ports"]
        assert "tcp/445" not in esito["suspect_ports"], (
            "una porta su pochi nodi resta del nodo: dietro l'apparato intermedio ci"
            " sono anche apparati veri")
        motivo = query(
            "SELECT suspect_reason FROM node_ports WHERE port = 5060"
            " AND COALESCE(is_suspect, 0) = 1 LIMIT 1", (), one=True)
        assert "risponde per tutto il segmento" in motivo["suspect_reason"]

        tipi = {r["device_type"] for r in query(
            "SELECT device_type FROM nodes WHERE ip LIKE '10.50.9.6%'", ())}
        assert "voip_phone" not in tipi


def test_un_segmento_normale_conserva_la_soglia_alta(server_app, inventario):
    """Senza indirizzi impossibili che rispondono, la soglia resta quella ordinaria:
    abbassarla su una rete sana sopprimerebbe servizi veri e diffusi."""
    with server_app.app_context():
        from snapserver.db import query

        nodi, porte = [], []
        for indice in range(20):
            ip = "10.50.9.%d" % (indice + 180)
            nodi.append({"ip": ip, "reachable": True, "ports_examined": True,
                         "seen_at": "2026-09-10 09:00:00"})
            if indice % 2 == 0:
                porte.append({"ip": ip, "protocol": "tcp", "port": 3389,
                              "state": "open", "service_name": "ms-wbt-server"})

        esito = conferisci(inventario, {"nodes": nodi, "ports": porte})

        assert "tcp/3389" not in esito["suspect_ports"]
        marcate = query(
            "SELECT COUNT(*) AS n FROM node_ports WHERE port = 3389"
            " AND COALESCE(is_suspect, 0) = 1", (), one=True)
        assert int(marcate["n"]) == 0
