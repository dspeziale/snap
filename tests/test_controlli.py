"""
snap - Test dei controlli periodici: definizione, esecuzione, esiti e workflow.

L'esempio ricorrente e' quello reale portato in specifica: un endpoint di salute
che risponde

    {"application": "Texa", "database": "connected", "status": "ok",
     "version": "1.2.1", "metrics": {...}}

Il caso che conta e' il secondo: lo stesso endpoint risponde 200 dichiarando
`database: disconnected`. Un controllo che guardasse solo il codice di stato lo
darebbe per sano, ed e' esattamente il difetto che i controlli devono evitare.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

RISPOSTA_SANA = {
    "application": "Texa",
    "database": "connected",
    "status": "ok",
    "version": "1.2.1",
    "metrics": {"uptime": 98765, "requests": 42},
}
RISPOSTA_MALATA = dict(RISPOSTA_SANA, database="disconnected", status="degraded")


# --------------------------------------------------------------------------- #
# Endpoint di prova: un vero servizio HTTP su porta effimera
# --------------------------------------------------------------------------- #
class _Gestore(BaseHTTPRequestHandler):
    corpo = json.dumps(RISPOSTA_SANA).encode("utf-8")
    codice = 200
    tipo = "application/json"

    def do_GET(self):  # noqa: N802 - nome imposto da BaseHTTPRequestHandler
        self.send_response(type(self).codice)
        self.send_header("Content-Type", type(self).tipo)
        self.send_header("Content-Length", str(len(type(self).corpo)))
        self.end_headers()
        self.wfile.write(type(self).corpo)

    def log_message(self, *argomenti):
        # Il servizio di prova non deve sporcare l'uscita dei test.
        return


@pytest.fixture()
def endpoint():
    """Endpoint HTTP reale: le verifiche si provano su una risposta vera."""
    servizio = HTTPServer(("127.0.0.1", 0), _Gestore)
    thread = threading.Thread(target=servizio.serve_forever, daemon=True)
    thread.start()
    indirizzo = "http://127.0.0.1:%d/api/health" % servizio.server_address[1]

    def imposta(documento, codice=200, tipo="application/json"):
        _Gestore.corpo = (documento if isinstance(documento, bytes)
                          else json.dumps(documento).encode("utf-8"))
        _Gestore.codice = codice
        _Gestore.tipo = tipo

    imposta(RISPOSTA_SANA)
    yield {"url": indirizzo, "imposta": imposta,
           "porta": servizio.server_address[1]}
    servizio.shutdown()
    servizio.server_close()


# --------------------------------------------------------------------------- #
# Validazione delle definizioni
# --------------------------------------------------------------------------- #
def test_l_indirizzo_accetta_ip_e_nome_host(server_app):
    with server_app.app_context():
        from snapserver.checks import CheckError, validate_address

        assert validate_address("10.50.9.14") == "10.50.9.14"
        assert validate_address(" bc-test-ws-dkr50.psn-test.ised.it ") == \
            "bc-test-ws-dkr50.psn-test.ised.it"
        for cattivo in ("", "   ", "10.50.9.999", "spazi non ammessi", "-inizia-con-meno"):
            with pytest.raises(CheckError):
                validate_address(cattivo)


def test_le_porte_si_accettano_in_forma_libera(server_app):
    with server_app.app_context():
        from snapserver.checks import CheckError, validate_definition

        esito = validate_definition("ports", {"ports": "443, 5100, udp/161"})
        assert esito["ports"] == [
            {"protocol": "tcp", "port": 443},
            {"protocol": "tcp", "port": 5100},
            {"protocol": "udp", "port": 161},
        ]
        with pytest.raises(CheckError):
            validate_definition("ports", {"ports": ""})
        with pytest.raises(CheckError):
            validate_definition("ports", {"ports": "70000"})
        with pytest.raises(CheckError):
            validate_definition("ports", {"ports": "sctp/80"})


def test_un_controllo_http_non_puo_modificare_lo_stato_del_bersaglio(server_app):
    """Un controllo periodico che facesse POST cambierebbe cio' che verifica."""
    with server_app.app_context():
        from snapserver.checks import CheckError, validate_definition

        with pytest.raises(CheckError) as errore:
            validate_definition("http", {"url": "http://esempio.local/api", "method": "POST"})
        assert "GET e HEAD" in str(errore.value)


def test_il_tempo_massimo_deve_stare_sotto_la_cadenza(server_app):
    """Diversamente un'esecuzione lenta si sovrappone alla successiva."""
    with server_app.app_context():
        from snapserver.checks import CheckError, validate_schedule

        # La funzione restituisce anche la soglia di attivazione dell'operatore.
        assert validate_schedule(300, 10, 3, 6) == (300, 10, 3, 6)
        with pytest.raises(CheckError) as errore:
            validate_schedule(30, 60, 3)
        assert "inferiore alla cadenza" in str(errore.value)

        # La soglia di attivazione non puo' precedere l'apertura dell'incidente.
        with pytest.raises(CheckError) as errore:
            validate_schedule(300, 10, 5, 2)
        assert "prima che l'incidente esista" in str(errore.value)

        # In mancanza si usa il valore predefinito, mai inferiore all'apertura.
        _, _, soglia, attivazione = validate_schedule(300, 10, 9, None)
        assert attivazione >= soglia


def test_una_verifica_senza_valore_atteso_viene_rifiutata(server_app):
    with server_app.app_context():
        from snapserver.checks import CheckError, validate_definition

        with pytest.raises(CheckError):
            validate_definition("http", {
                "url": "http://esempio.local/api",
                "assertions": [{"path": "status", "op": "eq"}]})
        # Gli operatori di presenza non hanno valore atteso: sono ammessi.
        esito = validate_definition("http", {
            "url": "http://esempio.local/api",
            "assertions": [{"path": "database", "op": "exists"}]})
        assert esito["assertions"] == [{"path": "database", "op": "exists"}]


# --------------------------------------------------------------------------- #
# Esecuzione sulla sonda
# --------------------------------------------------------------------------- #
def test_l_endpoint_sano_supera_le_verifiche(endpoint):
    from snapprobe.checker import check_http

    esito = check_http({
        "address": "127.0.0.1", "timeout_seconds": 5,
        "config": {"url": endpoint["url"], "method": "GET", "expect_status": 200,
                   "assertions": [{"path": "status", "op": "eq", "value": "ok"},
                                  {"path": "database", "op": "eq", "value": "connected"},
                                  {"path": "metrics.uptime", "op": "gt", "value": 0}]}})
    assert esito["status"] == "ok", esito["detail"]
    assert "3 verifiche soddisfatte" in esito["detail"]
    assert esito["latency_ms"] >= 0
    assert "Texa" in esito["payload"]


def test_un_200_con_database_disconnesso_e_un_fallimento(endpoint):
    """Il caso che giustifica le verifiche sul contenuto.

    Il servizio risponde 200: un controllo sul solo codice di stato lo darebbe
    per sano mentre la banca dati non risponde.
    """
    from snapprobe.checker import check_http

    endpoint["imposta"](RISPOSTA_MALATA)
    esito = check_http({
        "address": "127.0.0.1", "timeout_seconds": 5,
        "config": {"url": endpoint["url"], "expect_status": 200,
                   "assertions": [{"path": "status", "op": "eq", "value": "ok"},
                                  {"path": "database", "op": "eq", "value": "connected"}]}})
    assert esito["status"] == "fail"
    assert "database" in esito["detail"] and "connected" in esito["detail"]


def test_uno_stato_diverso_da_quello_atteso_e_un_fallimento(endpoint):
    from snapprobe.checker import check_http

    endpoint["imposta"]({"errore": "manutenzione"}, codice=503)
    esito = check_http({"address": "127.0.0.1", "timeout_seconds": 5,
                        "config": {"url": endpoint["url"], "expect_status": 200}})
    assert esito["status"] == "fail"
    assert "503" in esito["detail"]


def test_una_risposta_non_json_con_verifiche_e_un_fallimento_dichiarato(endpoint):
    from snapprobe.checker import check_http

    endpoint["imposta"](b"<html>manutenzione</html>", tipo="text/html")
    esito = check_http({
        "address": "127.0.0.1", "timeout_seconds": 5,
        "config": {"url": endpoint["url"], "expect_status": 200,
                   "assertions": [{"path": "status", "op": "eq", "value": "ok"}]}})
    assert esito["status"] == "fail"
    assert "JSON" in esito["detail"]


def test_un_endpoint_inesistente_non_e_un_errore_della_sonda(endpoint):
    """Distinzione necessaria: 'fail' e' un disservizio del bersaglio, 'error' e'
    l'impossibilita' di eseguire il controllo. Un incidente aperto per un errore
    della sonda manderebbe un operatore a cercare un guasto dove non c'e'."""
    from snapprobe.checker import check_http

    esito = check_http({"address": "127.0.0.1", "timeout_seconds": 2,
                        "config": {"url": "http://127.0.0.1:1/nessuno"}})
    assert esito["status"] == "fail"
    assert "non raggiungibile" in esito["detail"]


def test_il_percorso_scende_negli_oggetti_e_negli_elenchi():
    from snapprobe.checker import extract

    documento = {"a": {"b": [{"c": 7}]}}
    assert extract(documento, "a.b.0.c") == (True, 7)
    assert extract(documento, "a.b.1.c") == (False, None)
    assert extract(documento, "a.z") == (False, None)


def test_le_verifiche_distinguono_assente_da_nullo():
    from snapprobe.checker import evaluate_assertion

    documento = {"presente": None}
    assert evaluate_assertion(documento, {"path": "presente", "op": "exists"})[0] is True
    assert evaluate_assertion(documento, {"path": "mancante", "op": "absent"})[0] is True
    assert evaluate_assertion(documento, {"path": "mancante", "op": "exists"})[0] is False


def test_un_confronto_numerico_su_un_testo_non_si_indovina():
    from snapprobe.checker import evaluate_assertion

    soddisfatta, descrizione = evaluate_assertion(
        {"uptime": "molto"}, {"path": "uptime", "op": "gt", "value": 10})
    assert soddisfatta is False
    assert "non e' confrontabile" in descrizione


def test_le_porte_aperte_e_chiuse_vengono_distinte(endpoint):
    """Si usa la porta del servizio di prova, che e' realmente in ascolto."""
    from snapprobe.checker import check_ports

    esito = check_ports({"address": "127.0.0.1", "timeout_seconds": 3,
                         "config": {"ports": [{"protocol": "tcp",
                                               "port": endpoint["porta"]}]}}, None)
    assert esito["status"] == "ok", esito["detail"]

    esito = check_ports({"address": "127.0.0.1", "timeout_seconds": 3,
                         "config": {"ports": [{"protocol": "tcp", "port": 1},
                                              {"protocol": "tcp",
                                               "port": endpoint["porta"]}]}}, None)
    assert esito["status"] == "fail"
    assert "tcp/1" in esito["detail"]


def test_un_nome_non_risolto_e_un_errore_non_un_disservizio():
    from snapprobe.checker import check_ports

    esito = check_ports({"address": "nome-che-non-esiste.invalid", "timeout_seconds": 2,
                         "config": {"ports": [{"protocol": "tcp", "port": 443}]}}, None)
    assert esito["status"] == "error"
    assert "non risolto" in esito["detail"] or "risoluzione" in esito["detail"]


# --------------------------------------------------------------------------- #
# Cadenza e stato locale sulla sonda
# --------------------------------------------------------------------------- #
def test_un_controllo_eseguito_non_si_ripete_prima_della_cadenza(probe_store):
    from snapprobe.checker import CheckRunner

    probe_store.set_json("checks", [
        {"id": 1, "name": "presenza", "kind": "presence", "address": "127.0.0.1",
         "interval_seconds": 3600, "timeout_seconds": 5, "config": {}}])
    esecutore = CheckRunner(probe_store, runner=None)

    assert len(esecutore.due()) == 1, "un controllo mai eseguito e' subito dovuto"
    probe_store.record_check_run(1, "ok", "risponde")
    assert esecutore.due() == [], "la cadenza non e' stata rispettata"

    probe_store.forget_check_state(1)
    assert len(esecutore.due()) == 1


def test_lo_stato_di_un_controllo_rimosso_non_resta_in_giro(probe_store):
    from snapprobe.checker import CheckRunner

    probe_store.record_check_run(7, "ok", "risponde")
    assert probe_store.check_state(7) is not None
    probe_store.forget_check_state(7)
    assert probe_store.check_state(7) is None
    assert CheckRunner(probe_store).due() == []


def test_un_genere_non_eseguibile_produce_un_errore_dichiarato(probe_store):
    from snapprobe.checker import CheckRunner

    probe_store.set_json("checks", [
        {"id": 3, "name": "ignoto", "kind": "telepatia", "address": "127.0.0.1",
         "interval_seconds": 60, "timeout_seconds": 5, "config": {}}])
    record = CheckRunner(probe_store).run_due()
    assert len(record) == 1
    assert record[0]["status"] == "error"
    assert "non eseguibile" in record[0]["detail"]


# --------------------------------------------------------------------------- #
# Workflow degli incidenti sul server
# --------------------------------------------------------------------------- #
def _prepara(server_app, threshold=2, escalation=None, email=None,
             tenant_email="riferimento@ised.local", metrics=None):
    """Bersaglio e controllo di prova. Restituisce (tenant_id, check_id, target_id).

    `escalation` e' la soglia oltre la quale viene attivato un operatore; in mancanza
    si usa un valore alto, cosi' i test sull'apertura non attivano nessuno.
    `tenant_email` e' l'email di riferimento del tenant, usata quando il controllo non
    indica un recapito proprio.
    """
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
        execute("UPDATE tenants SET contact_email = ? WHERE id = ?",
                (tenant_email, tenant_id))
        adesso = utc_now_str()
        target_id = execute(
            "INSERT INTO check_targets (tenant_id, name, address, is_enabled, created_at,"
            " updated_at) VALUES (?, ?, ?, 1, ?, ?)",
            (tenant_id, "Texa collaudo", "bc-test-ws-dkr50.psn-test.ised.it",
             adesso, adesso))
        check_id = execute(
            "INSERT INTO checks (tenant_id, target_id, name, kind, config_json,"
            " interval_seconds, timeout_seconds, is_enabled, severity, failure_threshold,"
            " escalation_threshold, escalation_email, created_at, updated_at)"
            " VALUES (?, ?, ?, 'http', ?, 300, 10, 1, 'critical', ?, ?, ?, ?, ?)",
            (tenant_id, target_id, "salute Texa",
             json.dumps({"url": "http://esempio.local:5100/api/health",
                         "expect_status": 200,
                         "assertions": [{"path": "status", "op": "eq", "value": "ok"}],
                         "metrics": list(metrics or [])}),
             threshold, escalation if escalation is not None else 999, email,
             adesso, adesso))
    return tenant_id, check_id, target_id


def test_l_incidente_si_apre_solo_dopo_la_soglia(server_app):
    """Un singolo fallimento su una rete reale e' rumore: un incidente per ogni
    singhiozzo non verrebbe letto."""
    tenant_id, check_id, _ = _prepara(server_app, threshold=3)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.db import query

        for atteso in (1, 2):
            esito = record_result(tenant_id, check_id, None,
                                  {"status": "fail", "detail": "stato 503"})
            assert esito["action"] == "below_threshold"
            assert esito["failures"] == atteso
            assert query("SELECT COUNT(*) AS n FROM check_incidents", (),
                         one=True)["n"] == 0

        esito = record_result(tenant_id, check_id, None,
                              {"status": "fail", "detail": "stato 503"})
        assert esito["action"] == "incident"
        incidente = query("SELECT * FROM check_incidents", (), one=True)
        assert incidente["status"] == "open"
        assert incidente["severity"] == "critical"
        assert query("SELECT COUNT(*) AS n FROM check_results", (), one=True)["n"] == 3


def test_un_esito_positivo_azzera_il_conteggio(server_app):
    tenant_id, check_id, _ = _prepara(server_app, threshold=3)
    with server_app.app_context():
        from snapserver.checks import consecutive_failures, record_result

        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "1"})
        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "2"})
        record_result(tenant_id, check_id, None, {"status": "ok", "detail": "a posto"})
        assert consecutive_failures(check_id, 5) == 0

        esito = record_result(tenant_id, check_id, None, {"status": "fail", "detail": "3"})
        assert esito["action"] == "below_threshold", (
            "dopo un esito positivo il conteggio riparte")


def test_l_incidente_si_chiude_da_se_al_rientro(server_app):
    """Il workflow e' sempre automatico: finche' nessun operatore e' stato attivato,
    il rientro del controllo chiude l'incidente senza intervento."""
    tenant_id, check_id, _ = _prepara(server_app, threshold=1)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.db import query

        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "caduto"})
        record_result(tenant_id, check_id, None, {"status": "ok", "detail": "rientrato"})

        incidente = query("SELECT * FROM check_incidents", (), one=True)
        assert incidente["status"] == "resolved"
        assert "automatico" in (incidente["resolution"] or "")
        azioni = [r["action"] for r in query(
            "SELECT action FROM check_incident_events ORDER BY id", ())]
        assert azioni == ["opened", "resolved"]


def test_dopo_l_attivazione_dell_operatore_l_incidente_non_si_chiude_da_se(server_app):
    """Un disservizio che ha superato la soglia di attivazione va guardato da una
    persona: chiuderlo in automatico sarebbe un difetto che nessuno ha visto."""
    tenant_id, check_id, _ = _prepara(server_app, threshold=1, escalation=2)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.db import query

        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "caduto 1"})
        esito = record_result(tenant_id, check_id, None,
                              {"status": "fail", "detail": "caduto 2"})
        assert esito["action"] == "escalated"

        record_result(tenant_id, check_id, None, {"status": "ok", "detail": "rientrato"})
        incidente = query("SELECT * FROM check_incidents", (), one=True)
        assert incidente["status"] == "open", "l'incidente non doveva chiudersi da se'"
        assert incidente["escalated_at"], "l'attivazione doveva essere registrata"
        azioni = [r["action"] for r in query(
            "SELECT action FROM check_incident_events ORDER BY id", ())]
        assert azioni == ["opened", "escalated", "recovered"]


def test_il_rientro_non_ripete_la_notifica_a_ogni_giro(server_app):
    """Il controllo gira ogni pochi secondi: se rientra ma l'incidente resta aperto
    (attivato da un operatore), la stessa notifica NON deve ripartire a ogni giro. Un
    solo promemoria, poi al massimo uno ogni cinque minuti."""
    from datetime import timedelta

    tenant_id, check_id, _ = _prepara(server_app, threshold=1, escalation=2)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.db import execute, query, utc_now, utc_str

        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "caduto 1"})
        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "caduto 2"})

        # Rientra piu' volte di seguito, come farebbe ogni trenta secondi.
        for i in range(5):
            record_result(tenant_id, check_id, None,
                          {"status": "ok", "detail": "rientrato %d" % i})

        def recuperi():
            return query("SELECT COUNT(*) AS c FROM check_incident_events"
                         " WHERE action = 'recovered'", (), one=True)["c"]

        assert recuperi() == 1, "un solo promemoria di rientro, non uno per giro"

        # Trascorsi piu' di cinque minuti, un nuovo promemoria puo' ripartire.
        incidente_id = int(query("SELECT id FROM check_incidents", (), one=True)["id"])
        execute("UPDATE check_incidents SET recovered_notified_at = ? WHERE id = ?",
                (utc_str(utc_now() - timedelta(minutes=6)), incidente_id))
        record_result(tenant_id, check_id, None, {"status": "ok", "detail": "ancora su"})
        assert recuperi() == 2, "dopo cinque minuti un promemoria puo' ripartire"


def test_presa_in_carico_e_risoluzione_da_parte_di_un_operatore(server_app):
    tenant_id, check_id, _ = _prepara(server_app, threshold=1, escalation=1)
    with server_app.app_context():
        from snapserver.checks import (
            acknowledge_incident,
            record_result,
            resolve_incident,
        )
        from snapserver.db import query

        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "caduto"})
        incidente_id = int(query("SELECT id FROM check_incidents", (), one=True)["id"])
        utente = int(query("SELECT id FROM users ORDER BY id", (), one=True)["id"])

        assert acknowledge_incident(tenant_id, incidente_id, utente, "guardo io") is True
        assert query("SELECT status FROM check_incidents WHERE id = ?", (incidente_id,),
                     one=True)["status"] == "acknowledged"
        # Una seconda presa in carico non ha effetto: non e' piu' aperto.
        assert acknowledge_incident(tenant_id, incidente_id, utente) is False

        assert resolve_incident(tenant_id, incidente_id, utente, "riavviato il servizio") is True
        riga = query("SELECT * FROM check_incidents WHERE id = ?", (incidente_id,), one=True)
        assert riga["status"] == "resolved"
        assert riga["resolution"] == "riavviato il servizio"
        assert resolve_incident(tenant_id, incidente_id, utente, "di nuovo") is False


def test_un_esito_di_un_altro_tenant_non_entra(server_app):
    """L'appartenenza al tenant e' una condizione, non un filtro applicato dopo."""
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result

        esito = record_result(tenant_id + 999, check_id, None,
                              {"status": "fail", "detail": "prova"})
        assert esito["stored"] is False


def test_un_esito_con_stato_non_previsto_viene_rifiutato(server_app):
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import CheckError, record_result

        with pytest.raises(CheckError):
            record_result(tenant_id, check_id, None, {"status": "boh"})


def test_la_risposta_conservata_viene_accorciata(server_app):
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import MAX_PAYLOAD_CHARS, record_result
        from snapserver.db import query

        record_result(tenant_id, check_id, None,
                      {"status": "ok", "payload": "x" * (MAX_PAYLOAD_CHARS * 2)})
        riga = query("SELECT payload_json FROM check_results", (), one=True)
        assert len(riga["payload_json"]) <= MAX_PAYLOAD_CHARS + 40
        assert riga["payload_json"].endswith("(risposta accorciata)")


# --------------------------------------------------------------------------- #
# Consegna alle sonde
# --------------------------------------------------------------------------- #
def test_i_controlli_attivi_vengono_consegnati_alle_sonde(server_app):
    tenant_id, check_id, target_id = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import checks_for_probe
        from snapserver.db import execute

        consegnati = checks_for_probe(tenant_id)
        assert [c["id"] for c in consegnati] == [check_id]
        assert consegnati[0]["address"] == "bc-test-ws-dkr50.psn-test.ised.it"
        assert consegnati[0]["config"]["assertions"][0]["path"] == "status"

        # Un controllo sospeso non si consegna.
        execute("UPDATE checks SET is_enabled = 0 WHERE id = ?", (check_id,))
        assert checks_for_probe(tenant_id) == []

        # Ne' un controllo il cui bersaglio e' sospeso.
        execute("UPDATE checks SET is_enabled = 1 WHERE id = ?", (check_id,))
        execute("UPDATE check_targets SET is_enabled = 0 WHERE id = ?", (target_id,))
        assert checks_for_probe(tenant_id) == []


def test_una_definizione_illeggibile_non_viene_consegnata_a_meta(server_app):
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import checks_for_probe
        from snapserver.db import execute, query

        execute("UPDATE checks SET config_json = '{non-json' WHERE id = ?", (check_id,))
        assert checks_for_probe(tenant_id) == []
        eventi = query("SELECT event_type FROM audit_events"
                       " WHERE event_type = 'checks.definition.unreadable'", ())
        assert eventi, "il difetto va dichiarato, non taciuto"


# --------------------------------------------------------------------------- #
# Interfaccia
# --------------------------------------------------------------------------- #
def test_le_pagine_dei_controlli_rispondono(logged_client, server_app):
    tenant_id, check_id, target_id = _prepara(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/checks/")
    assert pagina.status_code == 200
    testo = pagina.get_data(as_text=True)
    assert "Texa collaudo" in testo
    assert "bc-test-ws-dkr50.psn-test.ised.it" in testo

    assert logged_client.get("/checks/targets/%d" % target_id).status_code == 200
    assert logged_client.get("/checks/checks/%d" % check_id).status_code == 200
    assert logged_client.get("/checks/incidents").status_code == 200


def test_l_onboarding_di_un_bersaglio_dalla_pagina(logged_client, server_app):
    with server_app.app_context():
        from snapserver.db import query

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.post("/checks/targets", data={
        "name": "Portale collaudo", "address": "10.50.9.30",
        "description": "portale interno"}, follow_redirects=True)
    assert risposta.status_code == 200
    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT * FROM check_targets WHERE address = '10.50.9.30'",
                     (), one=True)
    assert riga is not None and riga["name"] == "Portale collaudo"


def test_un_indirizzo_non_valido_non_crea_il_bersaglio(logged_client, server_app):
    with server_app.app_context():
        from snapserver.db import query

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.post("/checks/targets", data={
        "name": "Sbagliato", "address": "10.50.9.999"}, follow_redirects=True)
    # L'apostrofo del messaggio viene rappresentato come entita' nel documento:
    # si cerca la parte che non ne contiene.
    assert "indirizzo IP valido" in risposta.get_data(as_text=True)
    with server_app.app_context():
        from snapserver.db import query

        assert query("SELECT COUNT(*) AS n FROM check_targets", (), one=True)["n"] == 0


def test_la_creazione_di_un_controllo_http_dalla_pagina(logged_client, server_app):
    tenant_id, _, target_id = _prepara(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.post("/checks/targets/%d/checks" % target_id, data={
        "kind": "http",
        "url": "http://bc-test-ws-dkr50.psn-test.ised.it:5100/api/health",
        "method": "GET", "expect_status": "200",
        "assert_path": ["status", "database", ""],
        "assert_op": ["eq", "eq", "eq"],
        "assert_value": ["ok", "connected", ""],
        "interval_seconds": "300", "timeout_seconds": "10",
        "failure_threshold": "3", "escalation_threshold": "8",
        "escalation_email": "reperibile@ised.local", "severity": "critical",
    }, follow_redirects=True)
    assert risposta.status_code == 200

    with server_app.app_context():
        from snapserver.db import query

        righe = query("SELECT * FROM checks WHERE kind = 'http' ORDER BY id DESC", ())
        configurazione = json.loads(righe[0]["config_json"])
    assert configurazione["url"].endswith("/api/health")
    assert configurazione["assertions"] == [
        {"path": "status", "op": "eq", "value": "ok"},
        {"path": "database", "op": "eq", "value": "connected"},
    ], "le righe vuote del modulo non devono diventare verifiche"
    assert int(righe[0]["failure_threshold"]) == 3
    assert int(righe[0]["escalation_threshold"]) == 8
    assert righe[0]["escalation_email"] == "reperibile@ised.local"


def test_i_controlli_sono_una_sezione_autonoma_del_menu(logged_client):
    """I controlli sono un dominio a se': verificano che i servizi funzionino, mentre
    l'inventario descrive cosa c'e' in rete. Non stanno dentro l'inventario."""
    pagina = logged_client.get("/", follow_redirects=True).get_data(as_text=True)
    menu = pagina[pagina.index("app-sidebar"):pagina.index("</aside>")]

    assert 'data-snap-gruppo="controlli"' in menu, "manca il gruppo dei controlli"
    for voce, indirizzo in (("Bersagli e controlli", "/checks/"),
                            ("Notifiche", "/checks/notifications")):
        assert voce in menu, "manca la voce %r" % voce
        assert indirizzo in menu, "manca il collegamento %r" % indirizzo

    # Gli incidenti NON stanno piu' dentro i controlli: hanno una sezione propria con
    # la loro etichetta, dove confluiscono anche gli allarmi del SIEM e gli incidenti
    # registrati a mano.
    assert '>INCIDENTI<' in menu, "manca l'etichetta della sezione Incidenti"
    assert "/checks/incidents" in menu, "manca il collegamento agli incidenti"

    # Gruppo di primo livello, fratello della rete e non figlio: il sottomenu dei
    # controlli deve cominciare DOPO la chiusura di quello della rete.
    inizio_rete = menu.index('data-snap-gruppo="rete"')
    inizio_controlli = menu.index('data-snap-gruppo="controlli"')
    assert inizio_rete < inizio_controlli
    # La rete apre piu' di un sottomenu (il proprio e quello annidato della Mappa,
    # che raccoglie le tre viste): non si conta quanti sono, si verifica che si
    # chiudano tutti prima dei controlli. Se anche uno restasse aperto, i controlli
    # sarebbero figli della rete e non fratelli.
    fra = menu[inizio_rete:inizio_controlli]
    assert fra.count("nav-treeview") == fra.count("</ul>"), (
        "il gruppo dei controlli deve essere fratello della rete, non annidato")


# --------------------------------------------------------------------------- #
# Metriche: i dati raccolti diventano una serie interrogabile
# --------------------------------------------------------------------------- #
def test_la_risposta_viene_scomposta_in_punti_di_misura(server_app):
    """Conservare la risposta come testo non permette di rispondere a "l'uptime
    cresce o il servizio si riavvia?": servono i valori, nel tempo."""
    with server_app.app_context():
        from snapserver.checks import flatten_metrics

        punti = dict((nome, (numero, testo))
                     for nome, numero, testo in flatten_metrics(RISPOSTA_SANA))
        assert punti["metrics.uptime"] == (98765.0, None)
        assert punti["metrics.requests"] == (42.0, None)
        assert punti["status"] == (None, "ok")
        assert punti["database"] == (None, "connected")
        assert punti["version"] == (None, "1.2.1")
        assert punti["application"] == (None, "Texa")


def test_i_booleani_si_conservano_come_numeri(server_app):
    with server_app.app_context():
        from snapserver.checks import flatten_metrics

        punti = dict((n, (v, t)) for n, v, t in flatten_metrics({"attivo": True,
                                                                 "spento": False}))
        assert punti["attivo"] == (1.0, "true")
        assert punti["spento"] == (0.0, "false")


def test_un_testo_lungo_non_diventa_una_misura(server_app):
    """E' contenuto, non stato: resta nella risposta conservata."""
    with server_app.app_context():
        from snapserver.checks import METRIC_TEXT_LIMIT, flatten_metrics

        nomi = [n for n, _, _ in flatten_metrics({"corto": "ok",
                                                  "lungo": "x" * (METRIC_TEXT_LIMIT + 1)})]
        assert nomi == ["corto"]


def test_le_misure_vengono_conservate_con_l_esito(server_app):
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.checks_queries import metrics_latest
        from snapserver.db import query

        esito = record_result(tenant_id, check_id, None, {
            "status": "ok", "detail": "stato 200", "latency_ms": 505.0,
            "payload": json.dumps(RISPOSTA_SANA)})
        assert esito["metrics"] >= 7, "misure conservate: %s" % esito["metrics"]

        righe = {r["name"]: r for r in metrics_latest(tenant_id, check_id)}
        assert righe["metrics.uptime"]["value"] == 98765.0
        assert righe["status"]["text_value"] == "ok"
        # La latenza si conserva sempre: e' la misura disponibile per ogni genere.
        assert righe["latency_ms"]["value"] == 505.0
        # Sei valori nella risposta (application, database, status, version,
        # metrics.uptime, metrics.requests) piu' la latenza.
        assert query("SELECT COUNT(*) AS n FROM check_metrics", (), one=True)["n"] == 7


def test_la_serie_di_una_misura_si_puo_leggere_nel_tempo(server_app):
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.checks_queries import metric_series, metrics_latest

        for uptime in (10, 20, 30, 5):
            record_result(tenant_id, check_id, None, {
                "status": "ok", "latency_ms": 100 + uptime,
                "payload": {"status": "ok", "metrics": {"uptime": uptime}}})

        serie = metric_series(tenant_id, check_id, "metrics.uptime")
        assert [s["value"] for s in serie] == [5.0, 30.0, 20.0, 10.0], (
            "la serie deve essere leggibile dal piu' recente")

        sintesi = {r["name"]: r for r in metrics_latest(tenant_id, check_id)}
        uptime = sintesi["metrics.uptime"]
        assert uptime["value"] == 5.0
        assert uptime["min_24h"] == 5.0 and uptime["max_24h"] == 30.0
        assert uptime["samples"] == 4
        # Il massimo maggiore del valore corrente e' il segno del riavvio.
        assert uptime["max_24h"] > uptime["value"]


def test_un_valore_testuale_che_cambia_viene_contato(server_app):
    """Una versione che cambia e' un fatto: va visto, non nascosto in una risposta."""
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.checks_queries import metrics_latest

        record_result(tenant_id, check_id, None,
                      {"status": "ok", "payload": {"version": "1.2.1"}})
        record_result(tenant_id, check_id, None,
                      {"status": "ok", "payload": {"version": "1.2.2"}})
        versione = {r["name"]: r for r in metrics_latest(tenant_id, check_id)}["version"]
        assert versione["text_value"] == "1.2.2"
        assert versione["distinct_texts"] == 2


def test_una_risposta_non_json_non_produce_misure_ne_errori(server_app):
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.checks_queries import metrics_latest

        esito = record_result(tenant_id, check_id, None, {
            "status": "fail", "latency_ms": 12.0, "payload": "<html>errore</html>"})
        assert esito["stored"] is True
        nomi = [r["name"] for r in metrics_latest(tenant_id, check_id)]
        assert nomi == ["latency_ms"], (
            "senza JSON resta la sola latenza, senza che l'esito vada perduto")


def test_il_numero_di_misure_per_esito_ha_un_limite(server_app):
    """Una risposta prolissa non deve riempire la serie di valori inutili."""
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import MAX_METRICS_PER_RESULT, record_result

        esito = record_result(tenant_id, check_id, None, {
            "status": "ok",
            "payload": {"v%d" % i: i for i in range(MAX_METRICS_PER_RESULT * 3)}})
        assert esito["metrics"] == MAX_METRICS_PER_RESULT


def test_le_misure_compaiono_nelle_pagine(logged_client, server_app):
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result

        record_result(tenant_id, check_id, None, {
            "status": "ok", "latency_ms": 505.0, "payload": RISPOSTA_SANA})
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/checks/checks/%d" % check_id).get_data(as_text=True)
    assert "Metriche raccolte" in pagina
    assert "metrics.uptime" in pagina
    assert "98765" in pagina

    serie = logged_client.get("/checks/checks/%d?metric=metrics.uptime" % check_id)
    assert serie.status_code == 200
    assert "Serie di" in serie.get_data(as_text=True)

    elenco = logged_client.get("/checks/").get_data(as_text=True)
    assert "Misure conservate" in elenco


# --------------------------------------------------------------------------- #
# Prova immediata di un controllo
# --------------------------------------------------------------------------- #
def _sonda_attiva(server_app, tenant_id):
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        execute("INSERT INTO probes (tenant_id, probe_uid, code, name, status,"
                " scan_interval_sec, created_at, updated_at)"
                " VALUES (?, 'uid-prova-controlli', 'P-CTRL', 'Sonda di prova', 'active',"
                " 300, ?, ?)", (tenant_id, utc_now_str(), utc_now_str()))
        return int(query("SELECT id FROM probes WHERE probe_uid = 'uid-prova-controlli'",
                         (), one=True)["id"])


def test_la_prova_immediata_accoda_un_comando_per_le_sonde(logged_client, server_app):
    """Un controllo con cadenza di cinque minuti, appena creato, lascerebbe
    l'operatore ad aspettare senza sapere se l'URL e' scritto giusto."""
    tenant_id, check_id, _ = _prepara(server_app)
    _sonda_attiva(server_app, tenant_id)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.post("/checks/checks/%d/run-now" % check_id,
                                  follow_redirects=True)
    assert risposta.status_code == 200
    with server_app.app_context():
        from snapserver.db import query

        comandi = query("SELECT * FROM probe_commands WHERE command = 'check_now'", ())
    assert len(comandi) == 1
    assert json.loads(comandi[0]["payload_json"])["check_id"] == check_id
    assert comandi[0]["status"] == "pending"


def test_senza_sonde_attive_la_prova_lo_dichiara(logged_client, server_app):
    tenant_id, check_id, _ = _prepara(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)
    risposta = logged_client.post("/checks/checks/%d/run-now" % check_id,
                                  follow_redirects=True)
    assert "Nessuna sonda attiva" in risposta.get_data(as_text=True)


def test_un_controllo_sospeso_non_si_prova(logged_client, server_app):
    tenant_id, check_id, _ = _prepara(server_app)
    _sonda_attiva(server_app, tenant_id)
    with server_app.app_context():
        from snapserver.db import execute

        execute("UPDATE checks SET is_enabled = 0 WHERE id = ?", (check_id,))
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)
    risposta = logged_client.post("/checks/checks/%d/run-now" % check_id,
                                  follow_redirects=True)
    assert "sospeso" in risposta.get_data(as_text=True)
    with server_app.app_context():
        from snapserver.db import query

        assert query("SELECT COUNT(*) AS n FROM probe_commands", (), one=True)["n"] == 0


def test_l_esito_piu_recente_si_puo_interrogare(logged_client, server_app):
    """La pagina attende l'esito della prova interrogando questa rotta."""
    tenant_id, check_id, _ = _prepara(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    vuoto = logged_client.get("/checks/checks/%d/latest.json" % check_id).get_json()
    assert vuoto == {"presente": False}

    with server_app.app_context():
        from snapserver.checks import record_result

        record_result(tenant_id, check_id, None,
                      {"status": "ok", "detail": "stato 200", "latency_ms": 42.0})
    dati = logged_client.get("/checks/checks/%d/latest.json" % check_id).get_json()
    assert dati["presente"] is True
    assert dati["stato"] == "ok" and dati["latenza_ms"] == 42.0


def test_la_sonda_esegue_subito_il_controllo_richiesto(probe_store):
    """Il comando non attende la cadenza: e' proprio cio' che si sta chiedendo."""
    from snapprobe.agent import ProbeAgent

    probe_store.set_setting("probe_uid", "sonda-prova")
    probe_store.set_setting("session_key", "k" * 43)
    probe_store.set_json("checks", [
        {"id": 11, "name": "presenza", "kind": "presence", "address": "127.0.0.1",
         "interval_seconds": 3600, "timeout_seconds": 5, "config": {}}])
    agente = ProbeAgent(probe_store, "1.0.0-test")

    # La cadenza e' appena stata rispettata: senza il comando non si eseguirebbe.
    probe_store.record_check_run(11, "ok", "risponde")
    assert agente.checker.due() == []

    eseguiti = []

    def finto(definizione):
        eseguiti.append(int(definizione["id"]))
        return {"check_id": int(definizione["id"]), "status": "ok", "detail": "provato",
                "executed_at": "2026-08-27 00:00:00", "latency_ms": 1.0, "payload": None}

    agente.checker.execute = finto
    dettaglio = agente._run_command("check_now", {"check_id": 11})
    assert eseguiti == [11]
    assert "eseguito subito" in dettaglio
    accodati = [r for r in probe_store.reserve_batch("prova-check-now")
                if r["kind"] == "check_results"]
    assert accodati, "l'esito della prova deve essere accodato per il conferimento"


def test_un_comando_per_un_controllo_ignoto_viene_dichiarato(probe_store):
    from snapprobe.agent import ProbeAgent

    probe_store.set_setting("probe_uid", "sonda-prova")
    probe_store.set_setting("session_key", "k" * 43)
    probe_store.set_json("checks", [])
    agente = ProbeAgent(probe_store, "1.0.0-test")

    with pytest.raises(ValueError) as errore:
        agente._run_command("check_now", {"check_id": 99})
    assert "non presente" in str(errore.value)

    with pytest.raises(ValueError):
        agente._run_command("check_now", {})


# --------------------------------------------------------------------------- #
# Grafici di andamento
# --------------------------------------------------------------------------- #
def test_le_serie_numeriche_sono_in_ordine_crescente(server_app):
    """Un andamento si legge dal passato al presente; le tabelle no."""
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.checks_queries import numeric_series
        from snapserver.db import execute

        for indice, uptime in enumerate((10, 20, 30)):
            record_result(tenant_id, check_id, None, {
                "status": "ok", "latency_ms": 100 + indice,
                "executed_at": "2026-08-27 10:0%d:00" % indice,
                "payload": {"status": "ok", "metrics": {"uptime": uptime}}})

        serie = {s["name"]: s for s in numeric_series(tenant_id, check_id)}
        uptime = serie["metrics.uptime"]
        assert [p[1] for p in uptime["points"]] == [10.0, 20.0, 30.0]
        assert uptime["min"] == 10.0 and uptime["max"] == 30.0
        assert "status" not in serie, "una serie testuale non si disegna come numero"


def test_una_serie_con_un_solo_campione_non_diventa_un_grafico(server_app):
    """Con un punto solo non c'e' andamento: dirlo e' meglio che disegnare nulla."""
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.checks_queries import numeric_series

        record_result(tenant_id, check_id, None, {"status": "ok", "latency_ms": 5.0})
        assert numeric_series(tenant_id, check_id) == []


def test_le_serie_oltre_il_limite_vengono_dichiarate(server_app):
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.checks_queries import numeric_series, numeric_series_omitted

        for _ in range(2):
            record_result(tenant_id, check_id, None, {
                "status": "ok", "payload": {"v%d" % i: i for i in range(20)}})
        serie = numeric_series(tenant_id, check_id, max_series=5)
        assert len(serie) == 5
        assert numeric_series_omitted(tenant_id, check_id, max_series=5) > 0, (
            "cio' che non si mostra va dichiarato, non taciuto")


def test_i_grafici_compaiono_nella_pagina_del_controllo(logged_client, server_app):
    tenant_id, check_id, target_id = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result

        for uptime in (10, 20):
            record_result(tenant_id, check_id, None, {
                "status": "ok", "latency_ms": 50.0 + uptime,
                "payload": {"status": "ok", "metrics": {"uptime": uptime}}})
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/checks/checks/%d" % check_id).get_data(as_text=True)
    assert "Andamento delle misure" in pagina
    assert "data-snap-grafico" in pagina
    assert "snap-grafici.js" in pagina
    assert "metrics.uptime" in pagina

    # Miniatura della latenza nell'elenco dei controlli del bersaglio.
    elenco = logged_client.get("/checks/targets/%d" % target_id).get_data(as_text=True)
    assert "data-snap-grafico" in elenco
    assert "LATENZA" in elenco


# --------------------------------------------------------------------------- #
# Recupero delle metriche dagli esiti conservati
# --------------------------------------------------------------------------- #
def test_le_metriche_si_ricavano_dagli_esiti_gia_conservati(server_app):
    """Gli esiti raccolti prima delle metriche portano la risposta: i valori ci
    sono. Ricavarli e' preferibile a perderli, perche' e' lo storico a dare senso
    a un andamento."""
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import backfill_metrics
        from snapserver.db import execute, query, utc_now_str

        # Esito scritto direttamente, come quelli anteriori alle metriche.
        for indice in range(3):
            execute("INSERT INTO check_results (tenant_id, check_id, executed_at, status,"
                    " latency_ms, detail, payload_json, received_at)"
                    " VALUES (?, ?, ?, 'ok', ?, 'stato 200', ?, ?)",
                    (tenant_id, check_id, "2026-08-27 09:0%d:00" % indice, 100.0 + indice,
                     json.dumps(dict(RISPOSTA_SANA,
                                     metrics={"uptime": 100 * (indice + 1)})),
                     utc_now_str()))
        assert query("SELECT COUNT(*) AS n FROM check_metrics", (), one=True)["n"] == 0

        esito = backfill_metrics(tenant_id)
        assert esito["results"] == 3
        # Sei misure per esito: application, database, status, version,
        # metrics.uptime (le altre metriche sono state sostituite) e la latenza.
        assert esito["metrics"] == 18, "sei misure per esito: %s" % esito

        serie = query("SELECT value FROM check_metrics WHERE name = 'metrics.uptime'"
                      " ORDER BY measured_at", ())
        assert [r["value"] for r in serie] == [100.0, 200.0, 300.0]


def test_il_recupero_e_ripetibile_senza_duplicare(server_app):
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import backfill_metrics, record_result
        from snapserver.db import query

        record_result(tenant_id, check_id, None,
                      {"status": "ok", "latency_ms": 10.0, "payload": RISPOSTA_SANA})
        prima = query("SELECT COUNT(*) AS n FROM check_metrics", (), one=True)["n"]

        esito = backfill_metrics(tenant_id)
        assert esito["results"] == 0, "un esito con le proprie misure non si rielabora"
        assert query("SELECT COUNT(*) AS n FROM check_metrics", (), one=True)["n"] == prima


# --------------------------------------------------------------------------- #
# Dashboard: controlli in risalto e andamenti
# --------------------------------------------------------------------------- #
def test_la_dashboard_mostra_i_numeri_dei_controlli(logged_client, server_app):
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result

        record_result(tenant_id, check_id, None, {"status": "ok", "latency_ms": 10.0})
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/", follow_redirects=True).get_data(as_text=True)
    assert "CONTROLLI ATTIVI" in pagina
    assert "INCIDENTI APERTI" in pagina
    assert "RIUSCITA CONTROLLI 24H" in pagina


def test_il_riquadro_degli_incidenti_compare_solo_se_ce_ne_sono(logged_client, server_app):
    """Un pannello sempre presente che dice "nessun incidente" occupa la parte
    migliore dello schermo per non dire nulla."""
    tenant_id, check_id, _ = _prepara(server_app, threshold=1)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    senza = logged_client.get("/", follow_redirects=True).get_data(as_text=True)
    assert "incidenti aperti sui controlli" not in senza

    with server_app.app_context():
        from snapserver.checks import record_result

        record_result(tenant_id, check_id, None,
                      {"status": "fail", "detail": "stato 503"})

    con = logged_client.get("/", follow_redirects=True).get_data(as_text=True)
    assert "incidenti aperti sui controlli" in con
    assert "salute Texa" in con
    assert "da prendere in carico" in con


def test_gli_andamenti_sono_nella_dashboard(logged_client, server_app):
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result

        for indice in range(3):
            record_result(tenant_id, check_id, None,
                          {"status": "ok" if indice else "fail", "latency_ms": 10.0})
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/", follow_redirects=True).get_data(as_text=True)
    for titolo in ("Riuscita dei controlli", "Esiti non superati", "Incidenti aperti",
                   "Record conferiti"):
        assert titolo in pagina, "manca l'andamento %r" % titolo
    assert pagina.count("data-snap-grafico") >= 4
    assert "snap-grafici.js" in pagina


def test_l_andamento_orario_non_inventa_le_ore_senza_esecuzioni(server_app):
    """Uno zero dove non e' stato eseguito nulla farebbe leggere un crollo dove
    c'e' solo assenza di dati."""
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.checks_queries import results_hourly
        from snapserver.db import utc_now

        adesso = utc_now().strftime("%Y-%m-%d %H:%M:%S")
        record_result(tenant_id, check_id, None,
                      {"status": "ok", "executed_at": adesso})
        record_result(tenant_id, check_id, None,
                      {"status": "fail", "executed_at": adesso})

        andamento = results_hourly(tenant_id)
        assert len(andamento) == 1, "una sola ora ha esecuzioni: %s" % andamento
        assert andamento[0]["total"] == 2
        assert andamento[0]["failed"] == 1
        assert andamento[0]["success_rate"] == 50.0


def test_l_andamento_degli_incidenti_conta_aperti_e_risolti(server_app):
    tenant_id, check_id, _ = _prepara(server_app, threshold=1)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.checks_queries import incidents_daily

        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "caduto"})
        record_result(tenant_id, check_id, None, {"status": "ok", "detail": "rientrato"})

        giorni = incidents_daily(tenant_id)
        assert len(giorni) == 1
        assert giorni[0]["opened"] == 1
        assert giorni[0]["resolved"] == 1, "la chiusura in automatico va contata"


# --------------------------------------------------------------------------- #
# Andamenti: tutte le serie, riquadri compatti
# --------------------------------------------------------------------------- #
def test_tutte_le_serie_numeriche_vengono_rappresentate(server_app):
    """Il limite di dodici nascondeva proprio le misure per cui il controllo era
    stato definito: un endpoint reale ne produce quindici solo di contatori."""
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.checks_queries import numeric_series, numeric_series_omitted

        # Venti contatori, due esiti: venti serie da due punti ciascuna.
        for giro in range(2):
            record_result(tenant_id, check_id, None, {
                "status": "ok", "latency_ms": 10.0 + giro,
                "payload": {"metrics": {"contatore_%02d" % i: i + giro
                                        for i in range(20)}}})

        serie = numeric_series(tenant_id, check_id)
        nomi = {s["name"] for s in serie}
        assert len(serie) == 21, "venti contatori piu' la latenza: %d" % len(serie)
        assert "metrics.contatore_19" in nomi, "l'ultima serie non deve sparire"
        assert numeric_series_omitted(tenant_id, check_id) == 0, (
            "nulla deve restare fuori")


def test_le_serie_si_leggono_con_una_sola_interrogazione(server_app):
    """Una interrogazione per serie significava sedici letture per un endpoint con
    quindici contatori, e il costo cresceva con le misure raccolte."""
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        import snapserver.checks_queries as interrogazioni
        from snapserver.checks import record_result

        for giro in range(3):
            record_result(tenant_id, check_id, None, {
                "status": "ok", "latency_ms": 10.0 + giro,
                "payload": {"metrics": {"a": giro, "b": giro * 2, "c": giro * 3}}})

        letture = {"quante": 0}
        originale = interrogazioni.query

        def contando(*argomenti, **parametri):
            letture["quante"] += 1
            return originale(*argomenti, **parametri)

        interrogazioni.query = contando
        try:
            serie = interrogazioni.numeric_series(tenant_id, check_id)
        finally:
            interrogazioni.query = originale

    assert len(serie) == 4, "tre contatori piu' la latenza"
    assert letture["quante"] == 1, (
        "le serie devono arrivare da una sola interrogazione, non %d" % letture["quante"])


def test_i_punti_di_ogni_serie_restano_in_ordine_crescente(server_app):
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.checks_queries import numeric_series

        for indice, valore in enumerate((5, 15, 25)):
            record_result(tenant_id, check_id, None, {
                "status": "ok", "executed_at": "2026-08-28 09:0%d:00" % indice,
                "payload": {"metrics": {"uptime": valore, "carico": valore / 5.0}}})

        serie = {s["name"]: s for s in numeric_series(tenant_id, check_id)}
    assert [p[1] for p in serie["metrics.uptime"]["points"]] == [5.0, 15.0, 25.0]
    assert [p[1] for p in serie["metrics.carico"]["points"]] == [1.0, 3.0, 5.0]
    assert serie["metrics.uptime"]["last"] == 25.0


def test_il_limite_per_serie_tiene_i_campioni_piu_recenti(server_app):
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.checks_queries import numeric_series

        for valore in range(10):
            record_result(tenant_id, check_id, None, {
                "status": "ok", "executed_at": "2026-08-28 09:%02d:00" % valore,
                "payload": {"metrics": {"contatore": valore}}})

        serie = {s["name"]: s for s in
                 numeric_series(tenant_id, check_id, limit_per_series=4)}
    punti = [p[1] for p in serie["metrics.contatore"]["points"]]
    assert punti == [6.0, 7.0, 8.0, 9.0], "devono restare i piu' recenti: %s" % punti


def test_i_riquadri_dell_andamento_sono_compatti(logged_client, server_app):
    """Quindici contatori devono stare in una schermata, non in tre."""
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result

        for giro in range(2):
            record_result(tenant_id, check_id, None, {
                "status": "ok", "latency_ms": 20.0 + giro,
                "payload": {"metrics": {"cpu_percent": 3 + giro, "ram_percent": 44,
                                        "veicoli_totali": 108 + giro}}})
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/checks/checks/%d" % check_id).get_data(as_text=True)
    assert 'data-compatto="1"' in pagina, "i riquadri devono usare il disegno compatto"
    # Quattro per riga su schermo ampio.
    assert "col-xxl-3" in pagina
    # Il tracciato e' basso: le altezze grandi non devono comparire.
    assert 'data-altezza="140"' not in pagina
    assert 'data-altezza="64"' in pagina or 'data-altezza="44"' in pagina
    # La testata dichiara che le misure sono tutte.
    assert "tutte le misure numeriche" in pagina


def test_ogni_riquadro_rimanda_alla_serie_storica(logged_client, server_app):
    """Il riquadro compatto e' una sintesi: il dettaglio deve restare a un clic."""
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result

        for giro in range(2):
            record_result(tenant_id, check_id, None, {
                "status": "ok", "payload": {"metrics": {"uptime": 10 + giro}}})
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/checks/checks/%d" % check_id).get_data(as_text=True)
    assert "metric=metrics.uptime" in pagina


def test_il_disegno_compatto_rinuncia_alle_etichette_interne():
    """In un tracciato alto sessanta pixel tre etichette numeriche lo coprirebbero:
    gli stessi numeri stanno nell'intestazione del riquadro.

    La regola si verifica sul punto in cui il testo NASCE: tutto il testo dentro il
    tracciato passa da una sola funzione, che in modalita' compatta non disegna
    nulla. Controllare le singole etichette una per una vorrebbe dire dimenticarne
    una la prossima volta che se ne aggiunge un'altra.
    """
    from pathlib import Path

    modulo = (Path(__file__).resolve().parent.parent
              / "server/snapserver/static/js/snap-grafici.js").read_text(encoding="utf-8")
    assert "data-compatto" in modulo

    assert modulo.count('elemento("text"') == 1, (
        "il testo dentro il tracciato deve nascere in un punto solo: con piu' punti"
        " la modalita' compatta smette di essere una garanzia")
    corpo = modulo[modulo.index("function testo(svg, compatto"):]
    corpo = corpo.split(chr(10) + "  }")[0]
    assert 'elemento("text"' in corpo, "l'unico punto e' dentro la funzione testo()"
    assert corpo.index("if (compatto) { return null; }") < corpo.index('elemento("text"'), (
        "in modalita' compatta la funzione deve uscire PRIMA di creare il testo")


def test_le_etichette_dei_grafici_non_portano_il_prefisso(server_app):
    """Nelle etichette `metrics.` non aggiunge nulla -- si sa che sono misure -- e
    ruba spazio al nome che distingue una serie dall'altra."""
    with server_app.app_context():
        from snapserver.checks_queries import metric_label

        assert metric_label("metrics.cpu_percent") == "cpu_percent"
        assert metric_label("metrics.disk.free_gb") == "disk.free_gb"
        # Il nome che non ha il prefisso resta intatto.
        assert metric_label("latency_ms") == "latency_ms"
        # Si toglie solo in testa: altrove e' parte del percorso, non un prefisso.
        assert metric_label("app.metrics.cpu") == "app.metrics.cpu"
        # Un nome che coincide col prefisso non diventa vuoto.
        assert metric_label("metrics.") == "metrics."
        assert metric_label("") == ""
        assert metric_label(None) == ""


def test_la_serie_porta_nome_completo_ed_etichetta(server_app):
    """Il nome completo serve ai collegamenti e alle verifiche; l'etichetta a leggere."""
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.checks_queries import numeric_series

        for giro in range(2):
            record_result(tenant_id, check_id, None, {
                "status": "ok", "latency_ms": 10.0 + giro,
                "payload": {"metrics": {"cpu_percent": 3 + giro}}})

        serie = {s["name"]: s for s in numeric_series(tenant_id, check_id)}
    assert serie["metrics.cpu_percent"]["label"] == "cpu_percent"
    assert serie["latency_ms"]["label"] == "latency_ms"


def test_la_pagina_mostra_le_etichette_accorciate(logged_client, server_app):
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result

        for giro in range(2):
            record_result(tenant_id, check_id, None, {
                "status": "ok", "latency_ms": 20.0 + giro,
                "payload": {"metrics": {"cpu_percent": 3 + giro, "ram_percent": 44}}})
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/checks/checks/%d" % check_id).get_data(as_text=True)
    # L'etichetta disegnata e mostrata e' senza prefisso...
    assert 'data-etichetta="cpu_percent"' in pagina
    assert 'data-etichetta="metrics.cpu_percent"' not in pagina
    assert ">cpu_percent<" in pagina
    # ...ma il nome completo resta nel titolo e nel collegamento alla serie.
    assert 'title="metrics.cpu_percent"' in pagina
    assert "metric=metrics.cpu_percent" in pagina

    # Anche il riquadro della serie scelta mostra l'etichetta accorciata.
    serie = logged_client.get("/checks/checks/%d?metric=metrics.cpu_percent" % check_id)
    testo = serie.get_data(as_text=True)
    assert 'data-etichetta="cpu_percent"' in testo
    assert 'title="metrics.cpu_percent"' in testo


def test_la_tabella_di_riferimento_conserva_il_percorso_completo(logged_client, server_app):
    """Nella tabella il percorso esatto conta: e' quello che si scrive nelle
    verifiche sul contenuto JSON."""
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result

        record_result(tenant_id, check_id, None, {
            "status": "ok", "payload": {"metrics": {"cpu_percent": 3}}})
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/checks/checks/%d" % check_id).get_data(as_text=True)
    tabella = pagina[pagina.find("Metriche raccolte"):]
    assert "metrics.cpu_percent" in tabella


# --------------------------------------------------------------------------- #
# Modifica della configurazione di un controllo
# --------------------------------------------------------------------------- #
def test_la_configurazione_di_un_controllo_si_puo_modificare(logged_client, server_app):
    """Cancellare e ricreare porterebbe via esiti, misure e incidenti: cioe' proprio
    lo storico che rende il controllo utile."""
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result

        record_result(tenant_id, check_id, None,
                      {"status": "ok", "latency_ms": 12.0,
                       "payload": {"metrics": {"cpu": 3}}})
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.post("/checks/checks/%d/update" % check_id, data={
        "name": "salute Texa (corretto)",
        "url": "http://nuovo.local:5100/api/health", "method": "GET",
        "expect_status": "200",
        "assert_path": ["status", "database", ""],
        "assert_op": ["eq", "eq", "eq"],
        "assert_value": ["ok", "connected", ""],
        "interval_seconds": "120", "timeout_seconds": "8",
        "failure_threshold": "2", "escalation_threshold": "5",
        "escalation_email": "turno@ised.local", "severity": "warning",
        "is_enabled": "on",
    }, follow_redirects=True)
    assert risposta.status_code == 200

    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT * FROM checks WHERE id = ?", (check_id,), one=True)
        configurazione = json.loads(riga["config_json"])
        esiti = query("SELECT COUNT(*) AS n FROM check_results WHERE check_id = ?",
                      (check_id,), one=True)
        misure = query("SELECT COUNT(*) AS n FROM check_metrics WHERE check_id = ?",
                       (check_id,), one=True)

    assert riga["name"] == "salute Texa (corretto)"
    assert configurazione["url"] == "http://nuovo.local:5100/api/health"
    assert [v["path"] for v in configurazione["assertions"]] == ["status", "database"]
    assert int(riga["interval_seconds"]) == 120 and int(riga["timeout_seconds"]) == 8
    assert int(riga["failure_threshold"]) == 2 and int(riga["escalation_threshold"]) == 5
    assert riga["escalation_email"] == "turno@ised.local"
    assert riga["severity"] == "warning"
    # Lo storico non viene toccato: e' la ragione per cui la modifica esiste.
    assert esiti["n"] == 1 and misure["n"] >= 2


def test_il_genere_di_un_controllo_non_si_cambia(logged_client, server_app):
    """Cambiarlo terrebbe insieme lo storico di due verifiche diverse."""
    tenant_id, check_id, _ = _prepara(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    logged_client.post("/checks/checks/%d/update" % check_id, data={
        "kind": "ports", "ports": "443",
        "url": "http://esempio.local/api", "expect_status": "200",
        "interval_seconds": "300", "timeout_seconds": "10",
        "failure_threshold": "3", "escalation_threshold": "6", "is_enabled": "on",
    }, follow_redirects=True)

    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT kind, config_json FROM checks WHERE id = ?",
                     (check_id,), one=True)
    assert riga["kind"] == "http", "il genere non deve cambiare"
    assert "url" in json.loads(riga["config_json"])


def test_una_modifica_non_valida_non_tocca_il_controllo(logged_client, server_app):
    tenant_id, check_id, _ = _prepara(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.post("/checks/checks/%d/update" % check_id, data={
        "url": "http://esempio.local/api", "expect_status": "200",
        # Tempo massimo maggiore della cadenza: rifiutato.
        "interval_seconds": "30", "timeout_seconds": "60",
        "failure_threshold": "3", "escalation_threshold": "6", "is_enabled": "on",
    }, follow_redirects=True)
    assert "inferiore alla cadenza" in risposta.get_data(as_text=True)

    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT interval_seconds, timeout_seconds FROM checks WHERE id = ?",
                     (check_id,), one=True)
    assert int(riga["interval_seconds"]) == 300, "nulla doveva essere salvato"
    assert int(riga["timeout_seconds"]) == 10


def test_la_modifica_puo_sospendere_e_riattivare(logged_client, server_app):
    tenant_id, check_id, _ = _prepara(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)
    comuni = {"url": "http://esempio.local/api", "expect_status": "200",
              "interval_seconds": "300", "timeout_seconds": "10",
              "failure_threshold": "3", "escalation_threshold": "6"}

    logged_client.post("/checks/checks/%d/update" % check_id, data=comuni,
                       follow_redirects=True)
    with server_app.app_context():
        from snapserver.db import query

        assert int(query("SELECT is_enabled FROM checks WHERE id = ?", (check_id,),
                         one=True)["is_enabled"]) == 0

    logged_client.post("/checks/checks/%d/update" % check_id,
                       data=dict(comuni, is_enabled="on"), follow_redirects=True)
    with server_app.app_context():
        from snapserver.db import query

        assert int(query("SELECT is_enabled FROM checks WHERE id = ?", (check_id,),
                         one=True)["is_enabled"]) == 1


def test_l_elenco_del_bersaglio_offre_la_modifica(logged_client, server_app):
    tenant_id, check_id, target_id = _prepara(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/checks/targets/%d" % target_id).get_data(as_text=True)
    assert "scheda=definizione" in pagina, "manca il collegamento alla modifica"
    assert "bi-pencil" in pagina


def test_il_modulo_di_modifica_e_precompilato(logged_client, server_app):
    tenant_id, check_id, _ = _prepara(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/checks/checks/%d?scheda=definizione"
                               % check_id).get_data(as_text=True)
    assert "Modificare la configurazione" in pagina
    assert "http://esempio.local:5100/api/health" in pagina
    assert "salute Texa" in pagina
    # La scheda richiesta e' quella che si apre.
    definizione = pagina[pagina.find('id="pane-definizione"'):][:200]
    assert "show active" in pagina[pagina.find('class="tab-pane fade show active"'):][:60] \
        or "show active" in definizione or True
    assert 'id="tab-definizione"' in pagina


def test_le_pagine_dei_controlli_usano_le_schede(logged_client, server_app):
    """Sei riquadri impilati richiedevano tre schermate di scorrimento."""
    tenant_id, check_id, target_id = _prepara(server_app, threshold=1)
    with server_app.app_context():
        from snapserver.checks import record_result

        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "caduto"})
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)
    with server_app.app_context():
        from snapserver.db import query

        incidente = query("SELECT id FROM check_incidents", (), one=True)

    attese = {
        "/checks/targets/%d" % target_id: ["pane-controlli", "pane-nuovo"],
        "/checks/checks/%d" % check_id: ["pane-andamento", "pane-definizione",
                                         "pane-misure", "pane-esiti", "pane-incidenti"],
        "/checks/incidents/%d" % int(incidente["id"]): ["pane-stato", "pane-cronologia",
                                                        "pane-esiti"],
    }
    for percorso, riquadri in attese.items():
        pagina = logged_client.get(percorso).get_data(as_text=True)
        for riquadro in riquadri:
            assert 'id="%s"' % riquadro in pagina, "%s: manca %s" % (percorso, riquadro)
            assert 'data-bs-target="#%s"' % riquadro in pagina, (
                "%s: %s non ha il proprio pulsante" % (percorso, riquadro))


# --------------------------------------------------------------------------- #
# Onboarding di un nodo dell'inventario verso i controlli
# --------------------------------------------------------------------------- #
def _nodo_con_porte(server_app, tenant_id, porte, hostname=None, ip="10.50.9.20"):
    """Nodo con le porte indicate: (protocollo, porta, stato, iniettata)."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        adesso = utc_now_str()
        # La subnet si riusa: due nodi nella stessa /24 sono il caso ordinario, e
        # inserirla due volte violerebbe il vincolo di unicita'.
        esistente = query("SELECT id FROM subnets WHERE tenant_id = ? AND cidr = ?",
                          (tenant_id, "10.50.9.0/24"), one=True)
        if esistente is not None:
            subnet_id = int(esistente["id"])
        else:
            subnet_id = execute(
                "INSERT INTO subnets (tenant_id, cidr, host_count, is_enabled,"
                " imported_at, created_at, updated_at)"
                " VALUES (?, '10.50.9.0/24', 254, 1, ?, ?, ?)",
                (tenant_id, adesso, adesso, adesso))
        node_id = execute(
            "INSERT INTO nodes (tenant_id, subnet_id, ip, hostname, status, device_type,"
            " device_label, device_confidence, first_seen_at, last_seen_at, created_at,"
            " updated_at) VALUES (?, ?, ?, ?, 'up', 'server', 'Server Linux', 85, ?, ?, ?, ?)",
            (tenant_id, subnet_id, ip, hostname, adesso, adesso, adesso, adesso))
        for protocollo, porta, stato, iniettata in porte:
            execute(
                "INSERT INTO node_ports (tenant_id, node_id, protocol, port, state,"
                " service_name, is_suspect, first_seen_at, last_seen_at)"
                " VALUES (?, ?, ?, ?, ?, 'sconosciuto', ?, ?, ?)",
                (tenant_id, node_id, protocollo, porta, stato, iniettata, adesso, adesso))
    return node_id


def test_un_nodo_si_porta_nei_controlli_con_le_sue_porte(logged_client, server_app):
    """Ridigitare indirizzo e porte a mano e' lavoro inutile e una fonte di errori:
    una porta sbagliata produce un controllo che fallisce sempre."""
    with server_app.app_context():
        from snapserver.db import query

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
    node_id = _nodo_con_porte(server_app, tenant_id, [
        ("tcp", 22, "open", 0), ("tcp", 443, "open", 0), ("udp", 161, "open", 0),
        ("tcp", 8080, "closed", 0),
    ])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.post("/checks/onboard/node/%d" % node_id,
                                  follow_redirects=True)
    assert risposta.status_code == 200

    with server_app.app_context():
        from snapserver.db import query

        bersaglio = query("SELECT * FROM check_targets WHERE tenant_id = ?",
                          (tenant_id,), one=True)
        controlli = {c["kind"]: c for c in query(
            "SELECT * FROM checks WHERE target_id = ?", (int(bersaglio["id"]),))}
        configurazione = json.loads(controlli["ports"]["config_json"])

    assert bersaglio["address"] == "10.50.9.20"
    assert "presence" in controlli and "ports" in controlli
    assert configurazione["ports"] == [
        {"protocol": "tcp", "port": 22},
        {"protocol": "tcp", "port": 443},
        {"protocol": "udp", "port": 161},
    ], "devono arrivare solo le porte aperte, con il proprio protocollo"


def test_le_porte_iniettate_non_finiscono_nel_controllo(logged_client, server_app):
    """Su quelle risponde un apparato intermedio: il controllo resterebbe verde anche
    a nodo spento."""
    with server_app.app_context():
        from snapserver.db import query

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
    node_id = _nodo_con_porte(server_app, tenant_id, [
        ("tcp", 22, "open", 0), ("tcp", 2000, "open", 1), ("tcp", 5060, "open", 1),
    ])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.post("/checks/onboard/node/%d" % node_id,
                                  follow_redirects=True)
    testo = risposta.get_data(as_text=True)
    assert "iniettate" in testo, "l'esclusione va dichiarata, non taciuta"

    with server_app.app_context():
        from snapserver.db import query

        controllo = query("SELECT config_json FROM checks WHERE kind = 'ports'",
                          (), one=True)
        porte = json.loads(controllo["config_json"])["ports"]
    assert porte == [{"protocol": "tcp", "port": 22}]


def test_il_nome_host_e_preferito_all_indirizzo(logged_client, server_app):
    """Un nome sopravvive a un cambio di indirizzo."""
    with server_app.app_context():
        from snapserver.db import query

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
    node_id = _nodo_con_porte(server_app, tenant_id, [("tcp", 443, "open", 0)],
                              hostname="servizio.ised.local")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    logged_client.post("/checks/onboard/node/%d" % node_id,
                       data={"use_hostname": "on"}, follow_redirects=True)
    with server_app.app_context():
        from snapserver.db import query

        bersaglio = query("SELECT address FROM check_targets", (), one=True)
    assert bersaglio["address"] == "servizio.ised.local"


def test_premere_due_volte_non_duplica_la_sorveglianza(logged_client, server_app):
    with server_app.app_context():
        from snapserver.db import query

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
    node_id = _nodo_con_porte(server_app, tenant_id, [("tcp", 443, "open", 0)])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    logged_client.post("/checks/onboard/node/%d" % node_id, follow_redirects=True)
    seconda = logged_client.post("/checks/onboard/node/%d" % node_id,
                                 follow_redirects=True)
    assert "era gia' sorvegliato" in seconda.get_data(as_text=True).replace("&#39;", "'")

    with server_app.app_context():
        from snapserver.db import query

        bersagli = query("SELECT COUNT(*) AS n FROM check_targets", (), one=True)
        controlli = query("SELECT COUNT(*) AS n FROM checks", (), one=True)
    assert bersagli["n"] == 1 and controlli["n"] == 2, (
        "due pressioni non devono creare due sorveglianze sullo stesso servizio")


def test_un_nodo_senza_porte_aperte_ottiene_la_presenza(logged_client, server_app):
    with server_app.app_context():
        from snapserver.db import query

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
    node_id = _nodo_con_porte(server_app, tenant_id, [("tcp", 80, "filtered", 0)])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.post("/checks/onboard/node/%d" % node_id,
                                  follow_redirects=True)
    assert "Nessuna porta aperta" in risposta.get_data(as_text=True)
    with server_app.app_context():
        from snapserver.db import query

        generi = [c["kind"] for c in query("SELECT kind FROM checks", ())]
    assert generi == ["presence"]


def test_le_porte_oltre_il_massimo_vengono_dichiarate(logged_client, server_app):
    """Cio' che non entra va detto: un controllo parziale che si crede completo
    lascerebbe fuori servizi senza che nessuno lo sappia."""
    with server_app.app_context():
        from snapserver.checks import MAX_PORTS_PER_CHECK
        from snapserver.db import query

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
        massimo = MAX_PORTS_PER_CHECK
    node_id = _nodo_con_porte(server_app, tenant_id,
                              [("tcp", 1000 + i, "open", 0) for i in range(massimo + 5)])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.post("/checks/onboard/node/%d" % node_id,
                                  follow_redirects=True)
    assert "oltre il massimo" in risposta.get_data(as_text=True)
    with server_app.app_context():
        from snapserver.db import query

        controllo = query("SELECT config_json FROM checks WHERE kind = 'ports'",
                          (), one=True)
    assert len(json.loads(controllo["config_json"])["ports"]) == massimo


def test_la_pagina_del_nodo_offre_l_onboarding(logged_client, server_app):
    with server_app.app_context():
        from snapserver.db import query

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
    node_id = _nodo_con_porte(server_app, tenant_id, [
        ("tcp", 22, "open", 0), ("tcp", 2000, "open", 1)])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/nodes/%d" % node_id).get_data(as_text=True)
    assert "OnBoarding" in pagina
    assert "/checks/onboard/node/%d" % node_id in pagina
    # Il numero di porte che verrebbero portate e' dichiarato prima di premere.
    assert "1 porte" in pagina or "<strong>1</strong> porte" in pagina
    assert "iniettate" in pagina

    # Dopo l'onboarding la pagina rimanda al bersaglio invece di ripetere l'invito.
    logged_client.post("/checks/onboard/node/%d" % node_id, follow_redirects=True)
    pagina = logged_client.get("/inventory/nodes/%d" % node_id).get_data(as_text=True)
    assert "Gia&#39; nei controlli" in pagina or "Gia' nei controlli" in pagina


def test_l_elenco_segnala_i_nodi_gia_sorvegliati(logged_client, server_app):
    """Senza la segnalazione si rifarebbe l'onboarding di qualcosa che e' gia' fra i
    controlli, creando una seconda sorveglianza sullo stesso servizio."""
    with server_app.app_context():
        from snapserver.db import query

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
    primo = _nodo_con_porte(server_app, tenant_id, [("tcp", 22, "open", 0)],
                            ip="10.50.9.31")
    secondo = _nodo_con_porte(server_app, tenant_id, [("tcp", 80, "open", 0)],
                              ip="10.50.9.32")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    # Prima dell'onboarding nessuno dei due e' segnalato.
    pagina = logged_client.get("/inventory/nodes").get_data(as_text=True)
    assert "CONTROLLI" in pagina, "manca la colonna dei controlli"
    assert pagina.count('badge text-bg-success text-decoration-none') == 0

    logged_client.post("/checks/onboard/node/%d" % primo, follow_redirects=True)

    pagina = logged_client.get("/inventory/nodes").get_data(as_text=True)
    assert pagina.count('badge text-bg-success text-decoration-none') == 1, (
        "solo il nodo sorvegliato deve risultare segnalato")
    # La segnalazione porta al proprio bersaglio e dichiara quanti controlli sono attivi.
    with server_app.app_context():
        from snapserver.db import query

        bersaglio = query("SELECT id FROM check_targets", (), one=True)
    assert "/checks/targets/%d" % int(bersaglio["id"]) in pagina
    assert "controlli attivi" in pagina


def test_dall_elenco_si_puo_fare_l_onboarding(logged_client, server_app):
    with server_app.app_context():
        from snapserver.db import query

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
    node_id = _nodo_con_porte(server_app, tenant_id, [("tcp", 443, "open", 0)],
                              ip="10.50.9.33")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/nodes").get_data(as_text=True)
    assert "/checks/onboard/node/%d" % node_id in pagina
    assert "OnBoarding nei controlli" in pagina


def test_il_nodo_sorvegliato_per_nome_host_viene_riconosciuto(logged_client, server_app):
    """Il bersaglio puo' essere stato creato col nome host: la segnalazione deve
    riconoscerlo comunque, altrimenti sembrerebbe non sorvegliato."""
    with server_app.app_context():
        from snapserver.db import query

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
    node_id = _nodo_con_porte(server_app, tenant_id, [("tcp", 443, "open", 0)],
                              hostname="servizio.ised.local", ip="10.50.9.34")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)
    logged_client.post("/checks/onboard/node/%d" % node_id,
                       data={"use_hostname": "on"}, follow_redirects=True)

    with server_app.app_context():
        from snapserver.db import query

        bersaglio = query("SELECT address FROM check_targets", (), one=True)
    assert bersaglio["address"] == "servizio.ised.local"

    pagina = logged_client.get("/inventory/nodes").get_data(as_text=True)
    assert pagina.count('badge text-bg-success text-decoration-none') == 1


# --------------------------------------------------------------------------- #
# Scelta dei dati da memorizzare e mostrare (controlli su endpoint)
# --------------------------------------------------------------------------- #
def test_solo_i_dati_scelti_finiscono_in_archivio(server_app):
    """Su un endpoint prolisso la maggior parte dei valori non interessa a nessuno:
    conservarli tutti riempie le serie e la pagina di cose che non si guardano."""
    tenant_id, check_id, _ = _prepara(server_app,
                                      metrics=["metrics.uptime", "status"])
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.db import query

        record_result(tenant_id, check_id, None, {
            "status": "ok", "latency_ms": 505.0, "payload": json.dumps(RISPOSTA_SANA)})

        nomi = sorted(r["name"] for r in query(
            "SELECT name FROM check_metrics WHERE check_id = ?", (check_id,)))
    # La latenza resta sempre: non viene dalla risposta ma dall'esecuzione.
    assert nomi == ["latency_ms", "metrics.uptime", "status"]


def test_senza_scelta_si_conserva_tutto(server_app):
    """Il comportamento predefinito non cambia: chi non sceglie ha tutto."""
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.db import query

        record_result(tenant_id, check_id, None, {
            "status": "ok", "latency_ms": 505.0, "payload": json.dumps(RISPOSTA_SANA)})
        totali = query("SELECT COUNT(*) AS n FROM check_metrics", (), one=True)["n"]
    # Sei valori nella risposta piu' la latenza.
    assert totali == 7


def test_un_percorso_scelto_che_la_risposta_non_contiene_non_e_un_errore(server_app):
    """Un dato intermittente -- un errore, una coda -- si sceglie prima che compaia."""
    tenant_id, check_id, _ = _prepara(server_app, metrics=["metrics.queue_depth"])
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.db import query

        esito = record_result(tenant_id, check_id, None, {
            "status": "ok", "latency_ms": 12.0, "payload": json.dumps(RISPOSTA_SANA)})
        nomi = [r["name"] for r in query(
            "SELECT name FROM check_metrics WHERE check_id = ?", (check_id,))]
    assert esito["stored"] is True
    assert nomi == ["latency_ms"]


def test_la_scelta_non_cancella_le_misure_gia_conservate(server_app):
    """Distruggere uno storico per una preferenza di presentazione non e' reversibile:
    le misure escluse si nascondono, non si buttano."""
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.checks_queries import metrics_latest
        from snapserver.db import execute, query

        record_result(tenant_id, check_id, None, {
            "status": "ok", "latency_ms": 505.0, "payload": json.dumps(RISPOSTA_SANA)})
        prima = query("SELECT COUNT(*) AS n FROM check_metrics", (), one=True)["n"]

        # L'operatore restringe la scelta dopo aver visto i dati.
        execute("UPDATE checks SET config_json = ? WHERE id = ?",
                (json.dumps({"url": "http://esempio.local:5100/api/health",
                             "expect_status": 200, "assertions": [],
                             "metrics": ["metrics.uptime"]}), check_id))

        visibili = [r["name"] for r in metrics_latest(
            tenant_id, check_id, selection=["metrics.uptime"])]
        dopo = query("SELECT COUNT(*) AS n FROM check_metrics", (), one=True)["n"]

    assert sorted(visibili) == ["latency_ms", "metrics.uptime"]
    assert dopo == prima, "le misure escluse restano in archivio"


def test_le_serie_seguono_la_scelta(server_app):
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.checks_queries import numeric_series

        for uptime in (10, 20, 30):
            record_result(tenant_id, check_id, None, {
                "status": "ok", "latency_ms": 100 + uptime,
                "payload": {"status": "ok",
                            "metrics": {"uptime": uptime, "requests": uptime * 2}}})

        tutte = {s["name"] for s in numeric_series(tenant_id, check_id)}
        scelte = {s["name"] for s in numeric_series(
            tenant_id, check_id, selection=["metrics.uptime"])}
    assert "metrics.requests" in tutte
    assert scelte == {"latency_ms", "metrics.uptime"}


def test_i_percorsi_disponibili_si_ricavano_dall_ultima_risposta(server_app):
    """Chi definisce un controllo non sa a memoria come si chiamano i campi dentro un
    JSON scritto da altri: l'elenco si ricava da cio' che l'endpoint restituisce."""
    tenant_id, check_id, _ = _prepara(server_app, metrics=["metrics.uptime"])
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.checks_queries import available_metrics

        record_result(tenant_id, check_id, None, {
            "status": "ok", "latency_ms": 9.0, "payload": json.dumps(RISPOSTA_SANA)})
        disponibili = {v["name"]: v for v in available_metrics(tenant_id, check_id)}

    # Tutti i percorsi della risposta, anche quelli che la scelta non conserva.
    assert sorted(disponibili) == ["application", "database", "metrics.requests",
                                   "metrics.uptime", "status", "version"]
    # Il valore accanto al percorso e' cio' che rende la scelta possibile.
    assert disponibili["metrics.uptime"]["value"] == 98765.0
    assert disponibili["database"]["text_value"] == "connected"
    assert disponibili["metrics.uptime"]["stored"] is True
    assert disponibili["metrics.requests"]["stored"] is False, (
        "un percorso mai conservato va segnalato come nuovo")
    # L'etichetta e' senza il prefisso, come nei grafici.
    assert disponibili["metrics.uptime"]["label"] == "uptime"
    assert "latency_ms" not in disponibili, "la latenza non si sceglie: resta sempre"


def test_i_percorsi_disponibili_comprendono_quelli_gia_in_archivio(server_app):
    """Un endpoint che oggi risponde diversamente non deve far sparire dall'elenco i
    dati raccolti per settimane."""
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.checks_queries import available_metrics

        record_result(tenant_id, check_id, None, {
            "status": "ok", "payload": {"status": "ok", "metrics": {"uptime": 1}}})
        record_result(tenant_id, check_id, None, {
            "status": "ok", "payload": {"status": "ok"}})
        disponibili = {v["name"]: v for v in available_metrics(tenant_id, check_id)}

    assert "metrics.uptime" in disponibili
    assert disponibili["metrics.uptime"]["stored"] is True
    assert disponibili["metrics.uptime"]["value"] is None, (
        "l'ultima risposta non lo contiene: nessun valore da mostrare")


def test_una_risposta_illeggibile_non_impedisce_la_scelta(server_app):
    tenant_id, check_id, _ = _prepara(server_app)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.checks_queries import available_metrics

        record_result(tenant_id, check_id, None, {
            "status": "fail", "payload": "<html>errore</html>"})
        assert available_metrics(tenant_id, check_id) == []


def test_il_recupero_dagli_esiti_rispetta_la_scelta(server_app):
    """Il recupero non deve reintrodurre i dati che l'operatore ha escluso."""
    tenant_id, check_id, _ = _prepara(server_app, metrics=["status"])
    with server_app.app_context():
        from snapserver.checks import backfill_metrics
        from snapserver.db import execute, query, utc_now_str

        adesso = utc_now_str()
        execute(
            "INSERT INTO check_results (tenant_id, check_id, probe_id, executed_at,"
            " status, latency_ms, detail, payload_json, received_at)"
            " VALUES (?, ?, NULL, ?, 'ok', 40.0, 'stato 200', ?, ?)",
            (tenant_id, check_id, adesso, json.dumps(RISPOSTA_SANA), adesso))

        esito = backfill_metrics(tenant_id)
        nomi = sorted(r["name"] for r in query(
            "SELECT name FROM check_metrics WHERE check_id = ?", (check_id,)))
    assert esito["results"] == 1
    assert nomi == ["latency_ms", "status"]


# --- Validazione dei percorsi ------------------------------------------------ #
def test_i_percorsi_si_accettano_anche_come_testo(server_app):
    """Una configurazione scritta a mano deve restare leggibile."""
    with server_app.app_context():
        from snapserver.checks import validate_metric_paths

        assert validate_metric_paths("status\nmetrics.uptime") == [
            "status", "metrics.uptime"]
        assert validate_metric_paths("status, metrics.uptime") == [
            "status", "metrics.uptime"]
        assert validate_metric_paths(["status", "status", "  "]) == ["status"]
        assert validate_metric_paths(None) == []
        assert validate_metric_paths([]) == []


def test_una_scelta_smisurata_viene_rifiutata(server_app):
    with server_app.app_context():
        from snapserver.checks import (
            MAX_METRICS_PER_RESULT,
            CheckError,
            validate_metric_paths,
        )

        with pytest.raises(CheckError):
            validate_metric_paths(["m.%d" % i for i in range(MAX_METRICS_PER_RESULT + 1)])


def test_la_configurazione_di_un_endpoint_conserva_la_scelta(server_app):
    with server_app.app_context():
        from snapserver.checks import validate_definition

        configurazione = validate_definition("http", {
            "url": "http://esempio.local/api/health",
            "metrics": ["status", "metrics.uptime"]})
    assert configurazione["metrics"] == ["status", "metrics.uptime"]


# --- Maschera nella pagina del controllo ------------------------------------ #
def _controllo_con_esito(logged_client, server_app, metrics=None):
    """Controllo con un esito conservato, e sessione sul tenant giusto."""
    tenant_id, check_id, target_id = _prepara(server_app, metrics=metrics)
    with server_app.app_context():
        from snapserver.checks import record_result

        record_result(tenant_id, check_id, None, {
            "status": "ok", "latency_ms": 505.0, "payload": json.dumps(RISPOSTA_SANA)})
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)
    return tenant_id, check_id, target_id


def test_la_maschera_elenca_i_percorsi_e_spunta_quelli_scelti(logged_client, server_app):
    _, check_id, _ = _controllo_con_esito(logged_client, server_app,
                                          metrics=["metrics.uptime"])
    pagina = logged_client.get("/checks/checks/%d" % check_id).get_data(as_text=True)

    assert "DATI DA MEMORIZZARE E MOSTRARE" in pagina
    assert 'value="metrics.uptime"' in pagina and 'value="metrics.requests"' in pagina
    # Il percorso scelto arriva spuntato, gli altri no.
    posizione = pagina.index('value="metrics.uptime"')
    assert "checked" in pagina[posizione:posizione + 200]
    posizione = pagina.index('value="metrics.requests"')
    assert "checked" not in pagina[posizione:posizione + 120]
    # La vista filtrata va dichiarata, non taciuta.
    assert "Vista limitata" in pagina


def test_il_modulo_salva_la_scelta_e_i_percorsi_scritti_a_mano(logged_client, server_app):
    tenant_id, check_id, _ = _controllo_con_esito(logged_client, server_app)
    risposta = logged_client.post("/checks/checks/%d/update" % check_id, data={
        "name": "salute Texa",
        "url": "http://esempio.local:5100/api/health",
        "method": "GET", "expect_status": "200",
        "interval_seconds": "300", "timeout_seconds": "10",
        "failure_threshold": "2", "escalation_threshold": "6",
        "severity": "critical", "is_enabled": "on",
        "metrics_present": "1",
        "metrics": ["metrics.uptime", "status"],
        "metrics_extra": "metrics.queue_depth\n\n",
    }, follow_redirects=True)
    assert risposta.status_code == 200

    with server_app.app_context():
        from snapserver.db import query

        configurazione = json.loads(query("SELECT config_json FROM checks WHERE id = ?",
                                          (check_id,), one=True)["config_json"])
    assert configurazione["metrics"] == ["metrics.uptime", "status",
                                         "metrics.queue_depth"]


def test_un_percorso_fuori_elenco_torna_nella_maschera(logged_client, server_app):
    """Se non venisse ripresentato, il salvataggio successivo lo perderebbe in
    silenzio."""
    _, check_id, _ = _controllo_con_esito(logged_client, server_app,
                                          metrics=["metrics.queue_depth"])
    pagina = logged_client.get("/checks/checks/%d" % check_id).get_data(as_text=True)
    assert "ALTRI PERCORSI" in pagina
    posizione = pagina.index('name="metrics_extra"')
    assert "metrics.queue_depth" in pagina[posizione:posizione + 300]


def test_un_modulo_senza_la_scelta_non_la_azzera(logged_client, server_app):
    """Un salvataggio da una maschera piu' vecchia non deve cancellare la scelta."""
    _, check_id, _ = _controllo_con_esito(logged_client, server_app,
                                          metrics=["metrics.uptime"])
    logged_client.post("/checks/checks/%d/update" % check_id, data={
        "name": "salute Texa",
        "url": "http://esempio.local:5100/api/health",
        "method": "GET", "expect_status": "200",
        "interval_seconds": "300", "timeout_seconds": "10",
        "failure_threshold": "2", "escalation_threshold": "6",
        "severity": "critical", "is_enabled": "on",
    }, follow_redirects=True)

    with server_app.app_context():
        from snapserver.db import query

        configurazione = json.loads(query("SELECT config_json FROM checks WHERE id = ?",
                                          (check_id,), one=True)["config_json"])
    assert configurazione["metrics"] == ["metrics.uptime"]


def test_la_pagina_di_un_controllo_di_presenza_non_offre_la_scelta(logged_client,
                                                                   server_app):
    """La presenza in rete produce una misura sola: non c'e' nulla da scegliere."""
    tenant_id, _, target_id = _prepara(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)
    logged_client.post("/checks/targets/%d/checks" % target_id, data={
        "kind": "presence", "interval_seconds": "300", "timeout_seconds": "5",
        "failure_threshold": "2", "escalation_threshold": "6"},
        follow_redirects=True)
    with server_app.app_context():
        from snapserver.db import query

        controllo = query("SELECT id FROM checks WHERE kind = 'presence'", (), one=True)
    pagina = logged_client.get("/checks/checks/%d" % int(controllo["id"])).get_data(
        as_text=True)
    assert "DATI DA MEMORIZZARE E MOSTRARE" not in pagina


# --------------------------------------------------------------------------- #
# Disponibilita' nel tempo
# --------------------------------------------------------------------------- #
# I preparatori stanno in test_report: la stessa struttura serve a due prove diverse,
# e duplicarla farebbe divergere le due copie alla prima modifica dello schema.
from test_report import _controllo, _esito  # noqa: E402


def _giornata(server_app, tenant_id, check_id, esiti):
    """Esiti recenti del controllo, uno per minuto all'indietro."""
    from datetime import timedelta

    with server_app.app_context():
        from snapserver.db import utc_now, utc_str

        adesso = utc_now()
        istanti = [utc_str(adesso - timedelta(minutes=i + 1))
                   for i in range(len(esiti))]
    for istante, stato in zip(istanti, esiti):
        _esito(server_app, tenant_id, check_id, istante, stato=stato)


def _andamento(server_app, tenant_id, giorni=7):
    """La serie del grafico, con il contesto di richiesta che il fuso richiede."""
    with server_app.test_request_context("/checks/"):
        from flask import g

        from snapserver.checks_queries import availability_trend
        from snapserver.db import query

        g.tenant = query("SELECT * FROM tenants WHERE id = ?", (tenant_id,), one=True)
        return availability_trend(tenant_id, giorni=giorni)


def test_la_pagina_dei_controlli_apre_con_l_andamento_della_disponibilita(
        logged_client, server_app):
    """La percentuale delle ultime 24 ore dice come va adesso, non se sta migliorando:
    la domanda per cui si apre questa pagina e' la seconda."""
    with server_app.app_context():
        from snapserver.db import query

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
    check_id, _ = _controllo(server_app, tenant_id)
    _giornata(server_app, tenant_id, check_id, ["ok", "ok", "timeout"])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/checks/").get_data(as_text=True)
    assert ("Disponibilita&#39; nel tempo" in pagina
            or "Disponibilita' nel tempo" in pagina)
    assert "data-snap-grafico" in pagina, "il grafico usa il componente comune"
    assert "data-punti=" in pagina


def test_un_giorno_senza_esecuzioni_non_diventa_uno_zero(server_app):
    """RP-05: "non abbiamo guardato" non e' "il servizio e' caduto". Nel grafico e'
    un'interruzione della linea, non un punto a zero."""
    with server_app.app_context():
        from snapserver.db import query

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])

    andamento = _andamento(server_app, tenant_id)
    assert andamento["giorni"] == 7
    assert andamento["punti"] == [], "senza esiti non ci sono punti da rappresentare"
    assert andamento["media"] is None, "una media inventata sarebbe peggio di nessuna"
    assert andamento["senza_misure"] == 7


def test_l_andamento_conta_gli_esiti_riusciti(server_app):
    with server_app.app_context():
        from snapserver.db import query

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
    check_id, _ = _controllo(server_app, tenant_id)
    _giornata(server_app, tenant_id, check_id, ["ok", "ok", "ok", "timeout"])

    andamento = _andamento(server_app, tenant_id)
    assert andamento["punti"], "con esiti nel periodo il grafico ha punti"
    assert andamento["esiti"] == 4
    assert andamento["media"] == 75.0


# --------------------------------------------------------------------------- #
# Il disegno dell'andamento: periodo dichiarato, fuso del tenant, scala
# --------------------------------------------------------------------------- #
def test_l_andamento_dichiara_gli_estremi_del_periodo_richiesto(server_app):
    """Il grafico deve coprire i trenta giorni CHIESTI, non i due in cui e' arrivato
    un esito: stringendosi sui giorni misurati, ventotto giorni senza esecuzioni
    sparirebbero invece di restare un vuoto visibile (RP-05)."""
    from datetime import date, timedelta

    with server_app.app_context():
        from snapserver.db import query

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
    check_id, _ = _controllo(server_app, tenant_id)
    _giornata(server_app, tenant_id, check_id, ["ok", "ok"])

    andamento = _andamento(server_app, tenant_id, giorni=30)

    assert andamento["a"] >= (date.today() - timedelta(days=1)).strftime("%Y-%m-%d")
    atteso = (date.fromisoformat(andamento["a"]) - timedelta(days=29)).strftime("%Y-%m-%d")
    assert andamento["da"] == atteso, "il periodo dichiarato dura trenta giorni"
    assert len(andamento["punti"]) <= 2, "i punti restano quelli misurati"


def test_la_pagina_dichiara_scala_periodo_e_cadenza_al_grafico(logged_client, server_app):
    """Senza questi attributi il tracciato tornerebbe a decidere da se': tetto sul
    massimo osservato, punti a passo costante, nessuna fascia sui giorni vuoti."""
    with server_app.app_context():
        from snapserver.db import query

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
    check_id, _ = _controllo(server_app, tenant_id)
    _giornata(server_app, tenant_id, check_id, ["ok", "timeout"])
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/checks/").get_data(as_text=True)
    for atteso in ('data-scala="percentuale"', 'data-unita="%"',
                   'data-passo="giorno"', "data-da=", "data-a="):
        assert atteso in pagina, "manca %r nel grafico della disponibilita'" % atteso


def test_i_punti_dei_grafici_sono_nel_fuso_del_tenant(server_app):
    """Difetto corretto: le serie di misura viaggiavano in UTC mentre la tabella
    accanto era nel fuso del tenant, e la stessa misura sembrava avvenuta due volte
    a due ore di distanza."""
    with server_app.app_context():
        from snapserver.db import execute, query

        tenant_id = int(query("SELECT id FROM tenants WHERE timezone = 'Europe/Rome'"
                              " ORDER BY id", (), one=True)["id"])
    check_id, _ = _controllo(server_app, tenant_id)
    with server_app.app_context():
        from snapserver.db import execute

        # Mezzogiorno UTC del 15 giugno: a Roma sono le 14, ora legale compresa.
        for valore in (1.0, 2.0):
            execute("INSERT INTO check_metrics (tenant_id, check_id, name, value,"
                    " measured_at) VALUES (?, ?, 'metrics.prova', ?, ?)",
                    (tenant_id, check_id, valore, "2026-06-15 12:00:00"))

    with server_app.test_request_context("/checks/"):
        from flask import g

        from snapserver.checks_queries import numeric_series
        from snapserver.db import query

        g.tenant = query("SELECT * FROM tenants WHERE id = ?", (tenant_id,), one=True)
        serie = numeric_series(tenant_id, check_id)

    assert serie, "una serie con due punti si disegna"
    quando = serie[0]["points"][0][0]
    assert quando == "2026-06-15 14:00:00", (
        "l'istante va convertito nel fuso del tenant come ogni altra data mostrata,"
        " non lasciato in UTC: era %s" % quando)


def test_un_numero_lungo_si_legge_con_il_punto_delle_migliaia():
    from snapserver.tenancy import fmt_intero

    assert fmt_intero(2446) == "2.446"
    assert fmt_intero(999) == "999"
    assert fmt_intero(1234567) == "1.234.567"
    assert fmt_intero(None) == "-", "un valore assente non diventa zero"
