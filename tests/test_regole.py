"""
snap - Regole di notifica su qualunque evento del sistema.

Le prove coprono le tre cose che rendono utilizzabile un motore di regole: che le
condizioni facciano quello che dicono, che il cursore non faccia rileggere il passato a
ogni riavvio, e che l'anti-alluvione impedisca a una passata di scoperta di produrre
migliaia di messaggi.

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
        from snapserver.db import execute, query

        riga = query("SELECT id FROM tenants ORDER BY id", (), one=True)
        tenant_id = int(riga["id"])
        execute("UPDATE tenants SET contact_email = 'turno@ised.local' WHERE id = ?",
                (tenant_id,))
        return tenant_id


def _abilita_posta(server_app):
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        for chiave, valore in (("smtp_host", "smtp.local"),
                               ("smtp_sender", "snap@local"),
                               ("notifications_enabled", "1")):
            execute("INSERT INTO system_settings (key, value, updated_at)"
                    " VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET"
                    " value = excluded.value", (chiave, valore, adesso))


def _nodo(server_app, tenant_id, ip="10.4.0.7", hostname="stampante.local"):
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        adesso = utc_now_str()
        subnet = query("SELECT id FROM subnets WHERE tenant_id = ?", (tenant_id,),
                       one=True)
        if subnet is None:
            subnet_id = execute(
                "INSERT INTO subnets (tenant_id, cidr, host_count, is_enabled,"
                " imported_at, created_at, updated_at)"
                " VALUES (?, '10.4.0.0/24', 254, 1, ?, ?, ?)",
                (tenant_id, adesso, adesso, adesso))
        else:
            subnet_id = int(subnet["id"])
        return execute(
            "INSERT INTO nodes (tenant_id, subnet_id, ip, hostname, status,"
            " device_type, first_seen_at, last_seen_at, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, 'up', 'stampante', ?, ?, ?, ?)",
            (tenant_id, subnet_id, ip, hostname, adesso, adesso, adesso, adesso))


def _variazione(server_app, tenant_id, node_id, kind="port.opened",
                subject="tcp/3389", after="ms-wbt-server", severity="warning"):
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        return execute(
            "INSERT INTO node_changes (tenant_id, node_id, kind, subject, before_value,"
            " after_value, severity, created_at) VALUES (?, ?, ?, ?, '', ?, ?, ?)",
            (tenant_id, node_id, kind, subject, after, severity, utc_now_str()))


def _regola(server_app, tenant_id, **modifiche):
    dati = {
        "name": "Amministrazione remota",
        "source": "node_changes",
        "event_type": "port.opened",
        "conditions": [{"field": "port", "op": "eq", "value": "3389"}],
        "channels": ["email"],
        "recipients": "turno@ised.local",
        "severity": "critical",
        "window_seconds": "900",
        "max_per_window": "5",
    }
    dati.update(modifiche)
    with server_app.app_context():
        from snapserver import rules

        definizione = rules.validate_rule(dati)
        return rules.create_rule(tenant_id, definizione)


# --------------------------------------------------------------------------- #
# Validazione
# --------------------------------------------------------------------------- #
def test_una_regola_senza_nome_viene_rifiutata(server_app):
    """Il nome compare in ogni messaggio: senza, chi lo riceve non sa dove andare per
    non riceverlo piu'."""
    with server_app.app_context():
        from snapserver.rules import RuleError, validate_rule

        with pytest.raises(RuleError) as errore:
            validate_rule({"name": "  ", "source": "node_changes",
                           "channels": ["email"]})
        assert "nome" in str(errore.value)


def test_una_sorgente_inesistente_viene_rifiutata(server_app):
    with server_app.app_context():
        from snapserver.rules import RuleError, validate_rule

        with pytest.raises(RuleError):
            validate_rule({"name": "prova", "source": "tabella_inventata",
                           "channels": ["email"]})


def test_serve_almeno_un_canale(server_app):
    with server_app.app_context():
        from snapserver.rules import RuleError, validate_rule

        with pytest.raises(RuleError):
            validate_rule({"name": "prova", "source": "node_changes", "channels": []})


def test_il_canale_telegram_richiede_una_chat(server_app):
    """Un canale scelto senza recapito produrrebbe messaggi che nessuno riceve."""
    with server_app.app_context():
        from snapserver.rules import RuleError, validate_rule

        with pytest.raises(RuleError) as errore:
            validate_rule({"name": "prova", "source": "node_changes",
                           "channels": ["telegram"]})
        assert "Telegram" in str(errore.value)


def test_le_condizioni_illeggibili_vengono_rifiutate(server_app):
    with server_app.app_context():
        from snapserver.rules import RuleError, validate_conditions

        with pytest.raises(RuleError):
            validate_conditions("{non un json}")
        with pytest.raises(RuleError):
            validate_conditions([{"field": "port", "op": "inventato", "value": "1"}])
        with pytest.raises(RuleError):
            validate_conditions([{"field": "port", "op": "eq"}])


def test_una_condizione_di_presenza_non_richiede_valore(server_app):
    with server_app.app_context():
        from snapserver.rules import validate_conditions

        condizioni = validate_conditions([{"field": "node_hostname", "op": "exists"}])
    assert condizioni == [{"field": "node_hostname", "op": "exists", "value": None}]


def test_la_finestra_ha_dei_limiti(server_app):
    with server_app.app_context():
        from snapserver.rules import RuleError, validate_rule

        base = {"name": "prova", "source": "node_changes", "channels": ["email"]}
        with pytest.raises(RuleError):
            validate_rule(dict(base, window_seconds="10"))
        with pytest.raises(RuleError):
            validate_rule(dict(base, max_per_window="0"))


# --------------------------------------------------------------------------- #
# Corrispondenza
# --------------------------------------------------------------------------- #
def _evento(**modifiche):
    evento = {
        "source": "node_changes", "source_id": 1, "type": "port.opened",
        "severity": "warning", "subject": "tcp/3389", "detail": "-> ms-wbt-server",
        "occurred_at": "2026-08-28 10:00:00", "tenant_id": 1,
        "attributi": {"port": 3389, "protocol": "tcp", "node_ip": "10.4.0.7",
                      "node_hostname": "stampante.local", "after": "ms-wbt-server"},
    }
    evento.update(modifiche)
    return evento


def _finta(**modifiche):
    regola = {
        "source": "node_changes", "event_type": "port.opened",
        "conditions": [], "severity": "warning",
    }
    regola.update(modifiche)
    return regola


def test_il_tipo_di_evento_deve_corrispondere(server_app):
    with server_app.app_context():
        from snapserver.rules import matches

        assert matches(_finta(), _evento()) is True
        assert matches(_finta(event_type="port.closed"), _evento()) is False
        assert matches(_finta(event_type="*"), _evento()) is True


def test_un_tipo_che_finisce_con_il_punto_e_un_prefisso(server_app):
    """`port.` prende aperture e chiusure: e' la forma piu' breve di dire "tutte le
    variazioni delle porte"."""
    with server_app.app_context():
        from snapserver.rules import matches

        regola = _finta(event_type="port.")
        assert matches(regola, _evento(type="port.opened")) is True
        assert matches(regola, _evento(type="port.closed")) is True
        assert matches(regola, _evento(type="node.appeared")) is False


def test_una_sorgente_diversa_non_corrisponde(server_app):
    with server_app.app_context():
        from snapserver.rules import matches

        assert matches(_finta(source="check_results"), _evento()) is False


def test_le_condizioni_valgono_tutte_insieme(server_app):
    with server_app.app_context():
        from snapserver.rules import matches

        regola = _finta(conditions=[
            {"field": "port", "op": "eq", "value": "3389"},
            {"field": "protocol", "op": "eq", "value": "tcp"}])
        assert matches(regola, _evento()) is True
        regola["conditions"][1]["value"] = "udp"
        assert matches(regola, _evento()) is False


def test_gli_operatori_si_comportano_come_nelle_verifiche(server_app):
    with server_app.app_context():
        from snapserver.rules import matches

        def con(campo, operatore, valore, evento=None):
            return matches(_finta(conditions=[{"field": campo, "op": operatore,
                                               "value": valore}]),
                           evento or _evento())

        assert con("subject", "contains", "3389") is True
        assert con("port", "gt", "1024") is True
        assert con("port", "lt", "1024") is False
        assert con("node_hostname", "exists", None) is True
        assert con("node_os", "absent", None) is True
        assert con("subject", "ne", "tcp/445") is True
        # Un confronto numerico su un valore non numerico non e' soddisfatto.
        assert con("node_ip", "gt", "5") is False


def test_una_regola_con_condizioni_rotte_non_scatta(server_app):
    """Meglio silenziosa che indiscriminata: senza condizioni notificherebbe tutto."""
    tenant_id = _tenant_id(server_app)
    rule_id = _regola(server_app, tenant_id)
    with server_app.app_context():
        from snapserver import rules
        from snapserver.db import execute

        execute("UPDATE notify_rules SET conditions_json = 'non-json' WHERE id = ?",
                (rule_id,))
        regola = rules.rule(tenant_id, rule_id)
        assert regola["broken"] is True
        assert rules.matches(regola, _evento()) is False


# --------------------------------------------------------------------------- #
# Sorgenti di evento
# --------------------------------------------------------------------------- #
def test_una_variazione_di_porta_porta_protocollo_e_numero(server_app):
    """Le condizioni si scrivono su `port` e `protocol`: se il normalizzatore non li
    ricava, una regola sulla porta 3389 non potrebbe esistere."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _variazione(server_app, tenant_id, node_id)
    with server_app.app_context():
        from snapserver.events import fetch_recent

        eventi = fetch_recent("node_changes", limit=10, tenant_id=tenant_id)

    assert eventi, "la variazione deve essere leggibile come evento"
    evento = eventi[0]
    assert evento["type"] == "port.opened"
    assert evento["attributi"]["port"] == 3389
    assert evento["attributi"]["protocol"] == "tcp"
    assert evento["attributi"]["node_ip"] == "10.4.0.7"
    assert evento["attributi"]["subnet"] == "10.4.0.0/24"


def test_il_cursore_impedisce_di_rileggere_il_passato(server_app):
    """Senza cursore, alla riaccensione si spedirebbe una notifica per ogni evento mai
    registrato."""
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _variazione(server_app, tenant_id, node_id)
    with server_app.app_context():
        from snapserver.events import cursor_of, fetch_new, set_cursor

        primi = fetch_new("node_changes")
        assert len(primi) == 1
        set_cursor("node_changes", primi[-1]["source_id"])
        assert cursor_of("node_changes") == primi[-1]["source_id"]
        assert fetch_new("node_changes") == [], "gli eventi gia' visti non tornano"


def test_i_cursori_si_possono_portare_alla_fine(server_app):
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    for _ in range(3):
        _variazione(server_app, tenant_id, node_id)
    with server_app.app_context():
        from snapserver.events import fetch_new, initialize_cursors

        posizioni = initialize_cursors()
        assert posizioni["node_changes"] >= 3
        assert fetch_new("node_changes") == []


def test_un_esito_di_controllo_e_un_evento(server_app):
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str
        from snapserver.events import fetch_recent

        adesso = utc_now_str()
        target_id = execute(
            "INSERT INTO check_targets (tenant_id, name, address, is_enabled,"
            " created_at, updated_at) VALUES (?, 'Collaudo', 'servizio.local', 1, ?, ?)",
            (tenant_id, adesso, adesso))
        check_id = execute(
            "INSERT INTO checks (tenant_id, target_id, name, kind, config_json,"
            " interval_seconds, timeout_seconds, is_enabled, severity,"
            " failure_threshold, escalation_threshold, created_at, updated_at)"
            " VALUES (?, ?, 'salute', 'http', '{}', 300, 10, 1, 'critical', 2, 6, ?, ?)",
            (tenant_id, target_id, adesso, adesso))
        execute("INSERT INTO check_results (tenant_id, check_id, probe_id, executed_at,"
                " status, latency_ms, detail, received_at)"
                " VALUES (?, ?, NULL, ?, 'fail', 9000.0, 'tempo scaduto', ?)",
                (tenant_id, check_id, adesso, adesso))

        eventi = fetch_recent("check_results", limit=5, tenant_id=tenant_id)

    assert eventi[0]["type"] == "check.fail"
    assert eventi[0]["attributi"]["latency_ms"] == 9000.0
    assert eventi[0]["attributi"]["address"] == "servizio.local"


# --------------------------------------------------------------------------- #
# Notifica e anti-alluvione
# --------------------------------------------------------------------------- #
def test_una_regola_soddisfatta_accoda_una_notifica(server_app):
    _abilita_posta(server_app)
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _variazione(server_app, tenant_id, node_id)
    _regola(server_app, tenant_id)

    with server_app.app_context():
        from snapserver import rules
        from snapserver.db import query

        esito = rules.run_once()
        notifica = query("SELECT * FROM notifications WHERE event = 'rule.match'",
                         (), one=True)
        corrispondenza = query("SELECT * FROM rule_matches", (), one=True)

    assert esito["corrispondenze"] == 1 and esito["notifiche"] == 1
    assert notifica["recipients"] == "turno@ised.local"
    assert "Amministrazione remota" in notifica["subject"]
    assert "tcp/3389" in notifica["body"]
    assert "port" in notifica["body"], "gli attributi dell'evento sono nel corpo"
    assert corrispondenza["notified"] == 1


def test_una_regola_che_non_corrisponde_non_notifica(server_app):
    _abilita_posta(server_app)
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _variazione(server_app, tenant_id, node_id, subject="tcp/445", after="microsoft-ds")
    _regola(server_app, tenant_id)

    with server_app.app_context():
        from snapserver import rules
        from snapserver.db import query

        esito = rules.run_once()
        quante = query("SELECT COUNT(*) AS n FROM notifications", (), one=True)["n"]

    assert esito["eventi"] >= 1
    assert esito["corrispondenze"] == 0
    assert quante == 0


def test_una_regola_sospesa_non_scatta(server_app):
    _abilita_posta(server_app)
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    rule_id = _regola(server_app, tenant_id)
    with server_app.app_context():
        from snapserver import rules

        rules.toggle_rule(tenant_id, rule_id)
    _variazione(server_app, tenant_id, node_id)

    with server_app.app_context():
        from snapserver import rules

        assert rules.run_once()["corrispondenze"] == 0


def test_l_anti_alluvione_sopprime_oltre_il_limite(server_app):
    """La prima passata di scoperta ha prodotto 1851 aperture di porta: senza limite il
    canale verrebbe silenziato dal destinatario entro cinque minuti."""
    _abilita_posta(server_app)
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _regola(server_app, tenant_id, max_per_window="2")
    for _ in range(5):
        _variazione(server_app, tenant_id, node_id)

    with server_app.app_context():
        from snapserver import rules
        from snapserver.db import query

        esito = rules.run_once()
        notifiche = query("SELECT COUNT(*) AS n FROM notifications", (), one=True)["n"]
        soppresse = query("SELECT COUNT(*) AS n FROM rule_matches WHERE suppressed = 1",
                          (), one=True)["n"]

    assert esito["corrispondenze"] == 5
    assert notifiche == 2, "solo due messaggi nella finestra"
    assert soppresse == 3, "gli altri sono registrati, non perduti"


def test_gli_eventi_soppressi_vengono_contati_nel_messaggio_successivo(server_app):
    _abilita_posta(server_app)
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    rule_id = _regola(server_app, tenant_id, max_per_window="1")
    for _ in range(3):
        _variazione(server_app, tenant_id, node_id)

    with server_app.app_context():
        from snapserver import rules
        from snapserver.db import execute, query

        rules.run_once()
        # Finestra scaduta: la corrispondenza notificata invecchia.
        execute("UPDATE rule_matches SET created_at = '2020-01-01 00:00:00'"
                " WHERE notified = 1")
        _v = None
        regola = rules.rule(tenant_id, rule_id)
        esito = rules.notify(tenant_id, regola, _evento(tenant_id=tenant_id))
        corpo = query("SELECT body FROM notifications ORDER BY id DESC LIMIT 1",
                      (), one=True)["body"]

    assert esito["notificato"] is True
    assert esito["soppressi_contati"] == 2
    assert "altri 2 eventi" in corpo


def test_una_regola_solo_resoconto_non_spedisce(server_app):
    _abilita_posta(server_app)
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _regola(server_app, tenant_id, digest_only="1")
    _variazione(server_app, tenant_id, node_id)

    with server_app.app_context():
        from snapserver import rules
        from snapserver.db import query

        rules.run_once()
        notifiche = query("SELECT COUNT(*) AS n FROM notifications", (), one=True)["n"]
        registrate = query("SELECT COUNT(*) AS n FROM rule_matches", (), one=True)["n"]

    assert notifiche == 0
    assert registrate == 1, "la corrispondenza resta, per il resoconto"


def test_la_prova_sulla_storia_non_spedisce_nulla(server_app):
    """E' il solo modo onesto di attivare una regola: l'alternativa e' attivarla e
    scoprirlo dal numero di messaggi."""
    _abilita_posta(server_app)
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    for _ in range(3):
        _variazione(server_app, tenant_id, node_id)
    _variazione(server_app, tenant_id, node_id, subject="tcp/445")

    with server_app.app_context():
        from snapserver import rules
        from snapserver.db import query

        definizione = rules.validate_rule({
            "name": "prova", "source": "node_changes", "event_type": "port.opened",
            "conditions": [{"field": "port", "op": "eq", "value": "3389"}],
            "channels": ["email"], "recipients": "turno@ised.local"})
        esito = rules.test_rule(tenant_id, definizione)
        notifiche = query("SELECT COUNT(*) AS n FROM notifications", (), one=True)["n"]
        corrispondenze = query("SELECT COUNT(*) AS n FROM rule_matches", (),
                               one=True)["n"]

    assert esito["esaminati"] == 4
    assert esito["corrispondenti"] == 3
    assert notifiche == 0 and corrispondenze == 0


def test_gli_eventi_di_un_altro_tenant_non_scattano(server_app):
    _abilita_posta(server_app)
    tenant_id = _tenant_id(server_app)
    _regola(server_app, tenant_id)
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        altro = execute("INSERT INTO tenants (code, name, timezone, locale,"
                        " retention_days, is_active, created_at, updated_at)"
                        " VALUES ('altro', 'Altro', 'UTC', 'it_IT', 365, 1, ?, ?)",
                        (adesso, adesso))
    node_id = _nodo(server_app, altro, ip="10.99.0.1")
    _variazione(server_app, altro, node_id)

    with server_app.app_context():
        from snapserver import rules

        esito = rules.run_once()
    assert esito["eventi"] >= 1
    assert esito["corrispondenze"] == 0, "le regole valgono nel perimetro del tenant"


# --------------------------------------------------------------------------- #
# Pagine
# --------------------------------------------------------------------------- #
def test_la_pagina_delle_regole_si_apre(logged_client):
    pagina = logged_client.get("/rules/").get_data(as_text=True)
    assert "Regole di Notifica" in pagina
    assert "Regole pronte" in pagina
    assert "Amministrazione remota esposta" in pagina, (
        "le regole pronte sono l'unico modo di cominciare senza documentazione")


def test_una_regola_pronta_si_crea_dalla_pagina(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)
    risposta = logged_client.post("/rules/", data={
        "name": "Nodo nuovo in rete", "source": "node_changes",
        "event_type": "node.appeared", "channels": "email",
        "severity": "warning", "window_seconds": "900", "max_per_window": "5",
    }, follow_redirects=True)
    assert risposta.status_code == 200

    with server_app.app_context():
        from snapserver.db import query

        regola = query("SELECT * FROM notify_rules", (), one=True)
    assert regola["name"] == "Nodo nuovo in rete"
    assert regola["is_enabled"] == 1
    assert json.loads(regola["conditions_json"]) == []


def test_la_prova_dalla_pagina_mostra_gli_esempi(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    node_id = _nodo(server_app, tenant_id)
    _variazione(server_app, tenant_id, node_id)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.post("/rules/test", data={
        "name": "prova", "source": "node_changes", "event_type": "port.opened",
        "condition_field": "port", "condition_op": "eq", "condition_value": "3389",
        "channels": "email", "window_seconds": "900", "max_per_window": "5",
    }).get_data(as_text=True)

    assert "Prova sulla Storia" in pagina
    assert "Nessun messaggio e' stato spedito" in pagina.replace("&#39;", "'")
    assert "tcp/3389" in pagina


def test_una_regola_si_sospende_e_si_elimina(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    rule_id = _regola(server_app, tenant_id)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    logged_client.post("/rules/%d/toggle" % rule_id, follow_redirects=True)
    with server_app.app_context():
        from snapserver.db import query

        assert query("SELECT is_enabled FROM notify_rules WHERE id = ?",
                     (rule_id,), one=True)["is_enabled"] == 0

    logged_client.post("/rules/%d/delete" % rule_id, follow_redirects=True)
    with server_app.app_context():
        from snapserver.db import query

        assert query("SELECT COUNT(*) AS n FROM notify_rules", (), one=True)["n"] == 0


def test_la_pagina_di_una_regola_mostra_la_maschera_di_modifica(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    rule_id = _regola(server_app, tenant_id)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)
    pagina = logged_client.get("/rules/%d" % rule_id).get_data(as_text=True)
    assert "Modificare la regola" in pagina
    assert 'value="3389"' in pagina, "le condizioni tornano precompilate"
    assert "Anti-alluvione" in pagina
