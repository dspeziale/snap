"""
snap - Test dell'attivazione dell'operatore e delle notifiche del workflow.

Regola verificata qui, stabilita in specifica: il workflow e' SEMPRE automatico, e
una seconda soglia -- piu' alta di quella di apertura -- attiva un operatore. Dal
momento dell'attivazione l'incidente non si chiude piu' da se'. Il recapito e' quello
indicato sul controllo; in mancanza, l'email di riferimento del tenant.

Nessun invio reale: la spedizione viene sostituita, perche' un test che apre
connessioni verso un server di posta verifica la rete, non il programma.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json
import smtplib

import pytest


def _controllo(server_app, threshold=1, escalation=2, email=None,
               tenant_email="riferimento@ised.local"):
    """Bersaglio e controllo con le due soglie. Restituisce (tenant_id, check_id)."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
        execute("UPDATE tenants SET contact_email = ? WHERE id = ?",
                (tenant_email, tenant_id))
        adesso = utc_now_str()
        target_id = execute(
            "INSERT INTO check_targets (tenant_id, name, address, is_enabled,"
            " created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)",
            (tenant_id, "Servizio di collaudo", "collaudo.ised.local", adesso, adesso))
        check_id = execute(
            "INSERT INTO checks (tenant_id, target_id, name, kind, config_json,"
            " interval_seconds, timeout_seconds, is_enabled, severity,"
            " failure_threshold, escalation_threshold, escalation_email,"
            " created_at, updated_at)"
            " VALUES (?, ?, 'salute', 'http', ?, 300, 10, 1, 'warning', ?, ?, ?, ?, ?)",
            (tenant_id, target_id,
             json.dumps({"url": "http://collaudo.ised.local/api/health",
                         "expect_status": 200}),
             threshold, escalation, email, adesso, adesso))
    return tenant_id, check_id


def _notifiche(server_app, tenant_id):
    with server_app.app_context():
        from snapserver.notifications import recent_notifications

        return recent_notifications(tenant_id)


# --------------------------------------------------------------------------- #
# Soglia di attivazione
# --------------------------------------------------------------------------- #
def test_l_operatore_si_attiva_solo_oltre_la_seconda_soglia(server_app):
    tenant_id, check_id = _controllo(server_app, threshold=1, escalation=3)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.db import query

        primo = record_result(tenant_id, check_id, None, {"status": "fail", "detail": "1"})
        assert primo["action"] == "incident", "la prima soglia apre l'incidente"
        assert query("SELECT escalated_at FROM check_incidents", (),
                     one=True)["escalated_at"] is None

        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "2"})
        terzo = record_result(tenant_id, check_id, None, {"status": "fail", "detail": "3"})
        assert terzo["action"] == "escalated"
        assert terzo["failures"] == 3
        assert query("SELECT escalated_at FROM check_incidents", (),
                     one=True)["escalated_at"] is not None


def test_l_attivazione_avviene_una_volta_sola(server_app):
    """Un incidente non si scala due volte: l'operatore e' gia' stato avvisato."""
    tenant_id, check_id = _controllo(server_app, threshold=1, escalation=1)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.db import query

        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "1"})
        secondo = record_result(tenant_id, check_id, None, {"status": "fail", "detail": "2"})
        assert secondo["action"] == "incident", "la seconda volta non riscala"

        attivazioni = query("SELECT COUNT(*) AS n FROM check_incident_events"
                            " WHERE action = 'escalated'", (), one=True)
        assert attivazioni["n"] == 1


def test_l_attivazione_alza_la_gravita_a_critica(server_app):
    """Un disservizio che richiede una persona non e' piu' un avviso."""
    tenant_id, check_id = _controllo(server_app, threshold=1, escalation=1)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.db import query

        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "caduto"})
        incidente = query("SELECT * FROM check_incidents", (), one=True)
        assert incidente["severity"] == "critical"


def test_una_soglia_non_indicata_non_attiva_prima_dell_apertura(server_app):
    with server_app.app_context():
        from snapserver.checks import CheckError, validate_schedule

        with pytest.raises(CheckError):
            validate_schedule(300, 10, 8, 3)
        _, _, soglia, attivazione = validate_schedule(300, 10, 8)
        assert attivazione >= soglia


# --------------------------------------------------------------------------- #
# Recapito dell'operatore
# --------------------------------------------------------------------------- #
def test_senza_recapito_sul_controllo_si_usa_l_email_del_tenant(server_app):
    tenant_id, check_id = _controllo(server_app, threshold=1, escalation=1, email=None,
                                     tenant_email="reperibile@ised.local")
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.db import query

        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "caduto"})
        incidente = query("SELECT * FROM check_incidents", (), one=True)
    assert incidente["escalated_to"] == "reperibile@ised.local"


def test_il_recapito_del_controllo_prevale_su_quello_del_tenant(server_app):
    tenant_id, check_id = _controllo(server_app, threshold=1, escalation=1,
                                     email="turno@ised.local",
                                     tenant_email="riferimento@ised.local")
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.db import query

        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "caduto"})
        incidente = query("SELECT * FROM check_incidents", (), one=True)
    assert incidente["escalated_to"] == "turno@ised.local"


def test_senza_alcun_recapito_l_attivazione_avviene_e_lo_dichiara(server_app):
    """Un incidente che aspetta qualcuno che nessuno ha avvisato e' peggio di un
    incidente senza recapito dichiarato."""
    tenant_id, check_id = _controllo(server_app, threshold=1, escalation=1, email=None,
                                     tenant_email=None)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.db import query

        esito = record_result(tenant_id, check_id, None,
                              {"status": "fail", "detail": "caduto"})
        assert esito["action"] == "escalated"
        incidente = query("SELECT * FROM check_incidents", (), one=True)
        assert incidente["escalated_at"] is not None
        assert not incidente["escalated_to"]
        note = " ".join(r["note"] or "" for r in query(
            "SELECT note FROM check_incident_events WHERE action = 'escalated'", ()))
    assert "nessun recapito" in note


def test_un_recapito_malformato_viene_rifiutato(server_app):
    with server_app.app_context():
        from snapserver.checks import CheckError, validate_escalation_email

        assert validate_escalation_email("  turno@ised.local ") == "turno@ised.local"
        # Vuoto significa "usa l'email del tenant": non e' un errore.
        assert validate_escalation_email("") is None
        assert validate_escalation_email(None) is None
        for cattivo in ("senza-chiocciola", "due@@chiocciole.it", "spazio nel@nome.it",
                        "manca@dominio"):
            with pytest.raises(CheckError):
                validate_escalation_email(cattivo)


# --------------------------------------------------------------------------- #
# Notifiche: coda
# --------------------------------------------------------------------------- #
def test_ogni_momento_del_workflow_produce_una_notifica(server_app):
    tenant_id, check_id = _controllo(server_app, threshold=1, escalation=2)
    with server_app.app_context():
        from snapserver.checks import record_result

        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "1"})
        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "2"})
        record_result(tenant_id, check_id, None, {"status": "ok", "detail": "rientrato"})

    momenti = [n["event"] for n in _notifiche(server_app, tenant_id)]
    assert "incident.opened" in momenti
    assert "incident.escalated" in momenti
    assert "incident.recovered" in momenti


def test_la_notifica_dice_cosa_e_accaduto_e_cosa_si_aspetta(server_app):
    """Una notifica che non dice cosa fare costringe ad aprire la console per
    scoprirlo."""
    tenant_id, check_id = _controllo(server_app, threshold=1, escalation=1)
    with server_app.app_context():
        from snapserver.checks import record_result

        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "stato 503"})

    attivazione = [n for n in _notifiche(server_app, tenant_id)
                   if n["event"] == "incident.escalated"][0]
    assert "Operatore attivato" in attivazione["subject"]
    assert "collaudo.ised.local" in attivazione["subject"]
    assert "salute" in attivazione["body"]
    assert "stato 503" in attivazione["body"]
    assert "NON si" in attivazione["body"], "va detto che non si chiude piu' da se'"
    assert attivazione["recipients"] == "riferimento@ised.local"


def test_la_chiusura_automatica_viene_notificata(server_app):
    tenant_id, check_id = _controllo(server_app, threshold=1, escalation=99)
    with server_app.app_context():
        from snapserver.checks import record_result

        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "caduto"})
        record_result(tenant_id, check_id, None, {"status": "ok", "detail": "rientrato"})

    momenti = [n["event"] for n in _notifiche(server_app, tenant_id)]
    assert momenti.count("incident.resolved") == 1
    assert "incident.recovered" not in momenti, (
        "senza attivazione il rientro chiude: non e' un semplice rientro")


def test_le_azioni_dell_operatore_vengono_notificate(server_app):
    tenant_id, check_id = _controllo(server_app, threshold=1, escalation=1)
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
        acknowledge_incident(tenant_id, incidente_id, utente, "guardo io")
        resolve_incident(tenant_id, incidente_id, utente, "riavviato il servizio")

    momenti = [n["event"] for n in _notifiche(server_app, tenant_id)]
    assert "incident.acknowledged" in momenti
    assert "incident.resolved" in momenti


def test_un_momento_disattivato_non_produce_notifiche(server_app):
    """Chi non vuole una notifica la disattiva: il workflow resta invariato."""
    tenant_id, check_id = _controllo(server_app, threshold=1, escalation=99)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.db import execute, utc_now_str

        execute("INSERT INTO system_settings (key, value, updated_at)"
                " VALUES ('notify_events', 'incident.escalated', ?)", (utc_now_str(),))
        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "caduto"})

    assert _notifiche(server_app, tenant_id) == []


def test_le_notifiche_si_possono_disattivare_del_tutto(server_app):
    tenant_id, check_id = _controllo(server_app, threshold=1, escalation=1)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.db import execute, query, utc_now_str

        execute("INSERT INTO system_settings (key, value, updated_at)"
                " VALUES ('notifications_enabled', '0', ?)", (utc_now_str(),))
        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "caduto"})

        # Il workflow prosegue comunque: le notifiche non sono il workflow.
        incidente = query("SELECT * FROM check_incidents", (), one=True)
        assert incidente["escalated_at"] is not None
    assert _notifiche(server_app, tenant_id) == []


def test_una_notifica_senza_destinatari_resta_tracciata(server_app):
    """Cio' che non e' stato inviato deve restare visibile, con la ragione."""
    tenant_id, check_id = _controllo(server_app, threshold=1, escalation=1,
                                     email=None, tenant_email=None)
    with server_app.app_context():
        from snapserver.checks import record_result

        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "caduto"})

    saltate = [n for n in _notifiche(server_app, tenant_id) if n["status"] == "skipped"]
    assert saltate, "una notifica senza destinatari deve comparire come saltata"
    assert "nessun destinatario" in saltate[0]["last_error"]


# --------------------------------------------------------------------------- #
# Notifiche: spedizione
# --------------------------------------------------------------------------- #
def _configura_posta(server_app, **valori):
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        predefiniti = {"smtp_host": "posta.ised.local", "smtp_port": "25",
                       "smtp_sender": "snap@ised.local", "smtp_security": "none"}
        predefiniti.update(valori)
        for chiave, valore in predefiniti.items():
            execute("INSERT INTO system_settings (key, value, updated_at)"
                    " VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value,"
                    " updated_at = excluded.updated_at", (chiave, valore, utc_now_str()))


def test_senza_posta_configurata_la_coda_resta_in_attesa(server_app):
    """Nulla va perduto: le notifiche partono quando la configurazione e' completa."""
    tenant_id, check_id = _controllo(server_app, threshold=1, escalation=99)
    with server_app.app_context():
        from snapserver.checks import record_result
        from snapserver.notifications import dispatch_pending

        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "caduto"})
        esito = dispatch_pending()
        assert esito["sent"] == 0
        # Il motivo parla di canali: la posta non e' piu' l'unico recapito possibile.
        assert "nessun canale configurato" in esito["reason"]

    in_attesa = [n for n in _notifiche(server_app, tenant_id) if n["status"] == "pending"]
    assert in_attesa, "la notifica doveva restare in attesa"


def test_la_spedizione_riuscita_marca_le_notifiche(server_app, monkeypatch):
    tenant_id, check_id = _controllo(server_app, threshold=1, escalation=99)
    _configura_posta(server_app)

    inviati = []

    def finto(config, recipients, subject, body, body_html=None, attachment=None):
        inviati.append((recipients, subject))

    with server_app.app_context():
        import snapserver.notifications as notifiche
        from snapserver.checks import record_result

        monkeypatch.setattr(notifiche, "send_now", finto)
        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "caduto"})
        esito = notifiche.dispatch_pending()

    assert esito["sent"] == 1 and esito["failed"] == 0
    assert inviati and inviati[0][0] == "riferimento@ised.local"
    inviata = _notifiche(server_app, tenant_id)[0]
    assert inviata["status"] == "sent" and inviata["sent_at"]


def test_una_spedizione_non_riuscita_si_ritenta_e_poi_si_arrende(server_app, monkeypatch):
    """Un indirizzo sbagliato non diventa giusto al decimo invio, e la coda non deve
    crescere per sempre. L'errore resta visibile."""
    tenant_id, check_id = _controllo(server_app, threshold=1, escalation=99)
    _configura_posta(server_app)

    def sempre_male(config, recipients, subject, body, body_html=None, attachment=None):
        raise smtplib.SMTPRecipientsRefused({recipients: (550, b"casella inesistente")})

    with server_app.app_context():
        import snapserver.notifications as notifiche
        from snapserver.checks import record_result

        monkeypatch.setattr(notifiche, "send_now", sempre_male)
        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "caduto"})

        for tentativo in range(notifiche.MAX_ATTEMPTS + 2):
            notifiche.dispatch_pending()

        coda = notifiche.recent_notifications(tenant_id)
    assert coda[0]["status"] == "failed"
    assert coda[0]["attempts"] == notifiche.MAX_ATTEMPTS
    assert "casella inesistente" in coda[0]["last_error"]


def test_il_messaggio_composto_ha_mittente_oggetto_e_corpo(server_app):
    with server_app.app_context():
        from snapserver.notifications import compose

        config = {"sender": "snap@ised.local", "sender_name": "snap collaudo"}
        messaggio = compose(config, "turno@ised.local", "[snap] prova", "corpo")
    assert messaggio["To"] == "turno@ised.local"
    assert "snap collaudo" in messaggio["From"] and "snap@ised.local" in messaggio["From"]
    assert messaggio["Subject"] == "[snap] prova"
    assert messaggio["X-Snap-Notification"] == "workflow"
    assert "corpo" in messaggio.get_content()


def test_un_errore_nella_notifica_non_ferma_il_workflow(server_app, monkeypatch):
    """L'incidente e' il fatto; la notifica e' il racconto. Se il racconto fallisce,
    il fatto resta registrato."""
    tenant_id, check_id = _controllo(server_app, threshold=1, escalation=1)

    with server_app.app_context():
        import snapserver.checks as dominio
        from snapserver.db import query

        def rotta(*argomenti, **parametri):
            raise RuntimeError("coda non disponibile")

        monkeypatch.setattr(dominio, "queue_notification", rotta)
        esito = dominio.record_result(tenant_id, check_id, None,
                                      {"status": "fail", "detail": "caduto"})
        assert esito["action"] == "escalated"
        incidente = query("SELECT * FROM check_incidents", (), one=True)
        assert incidente["escalated_at"] is not None
        # Il problema della notifica viene dichiarato nell'audit.
        eventi = query("SELECT * FROM audit_events"
                       " WHERE event_type = 'checks.notification.failed'", ())
    assert eventi, "una notifica non accodata va dichiarata"


# --------------------------------------------------------------------------- #
# Interfaccia
# --------------------------------------------------------------------------- #
def test_la_pagina_delle_notifiche_mostra_la_coda(logged_client, server_app):
    tenant_id, check_id = _controllo(server_app, threshold=1, escalation=1)
    with server_app.app_context():
        from snapserver.checks import record_result

        record_result(tenant_id, check_id, None, {"status": "fail", "detail": "caduto"})
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/checks/notifications")
    assert pagina.status_code == 200
    testo = pagina.get_data(as_text=True)
    assert "Notifiche del Workflow" in testo
    assert "riferimento@ised.local" in testo
    assert "Operatore attivato" in testo
    # Senza posta configurata lo dice, invece di far credere che sia stato inviato.
    assert "Posta non configurata" in testo


def test_la_configurazione_della_posta_si_salva(logged_client, server_app):
    logged_client.post("/admin/settings/notifications", data={
        "smtp_host": "posta.ised.local", "smtp_port": "587",
        "smtp_security": "starttls", "smtp_username": "snap",
        "smtp_password": "segreta", "smtp_sender": "snap@ised.local",
        "smtp_sender_name": "snap", "notifications_enabled": "on",
        "notify_events": ["incident.opened", "incident.escalated"],
    }, follow_redirects=True)

    with server_app.app_context():
        from snapserver.notifications import enabled_events, is_configured, smtp_config

        config = smtp_config()
        assert config["host"] == "posta.ised.local" and config["port"] == 587
        assert config["security"] == "starttls"
        assert is_configured(config)
        assert enabled_events() == {"incident.opened", "incident.escalated"}


def test_la_password_della_posta_non_viene_mostrata(logged_client, server_app):
    """Un campo precompilato con una password e' una password esposta."""
    logged_client.post("/admin/settings/notifications", data={
        "smtp_host": "posta.ised.local", "smtp_port": "25", "smtp_security": "none",
        "smtp_password": "segretissima", "smtp_sender": "snap@ised.local",
    }, follow_redirects=True)

    pagina = logged_client.get("/admin/settings").get_data(as_text=True)
    assert "segretissima" not in pagina
    assert "impostata" in pagina, "va detto che una password e' presente"


def test_una_porta_non_valida_viene_rifiutata(logged_client, server_app):
    risposta = logged_client.post("/admin/settings/notifications", data={
        "smtp_host": "posta.ised.local", "smtp_port": "99999",
        "smtp_security": "none", "smtp_sender": "snap@ised.local",
    }, follow_redirects=True)
    assert "fra 1 e 65535" in risposta.get_data(as_text=True)
    with server_app.app_context():
        from snapserver.notifications import smtp_config

        assert smtp_config()["host"] != "posta.ised.local", "nulla doveva essere salvato"


def test_la_prova_di_invio_riporta_l_errore_per_esteso(logged_client, server_app,
                                                       monkeypatch):
    """"Non funziona" non aiuta nessuno a capire cosa sistemare."""
    _configura_posta(server_app)

    import snapserver.notifications as notifiche

    def rifiutato(config, recipients, subject, body):
        raise smtplib.SMTPAuthenticationError(535, b"credenziali non accettate")

    monkeypatch.setattr(notifiche, "send_now", rifiutato)
    risposta = logged_client.post("/admin/settings/notifications/test",
                                  data={"recipient": "turno@ised.local"},
                                  follow_redirects=True)
    testo = risposta.get_data(as_text=True)
    assert "Prova non riuscita" in testo
    assert "credenziali non accettate" in testo
