"""
snap - Test dell'azzeramento delle informazioni RACCOLTE di un tenant.

Cio' che questi test difendono e' un CONFINE, non una funzione: il bottone butta
quello che le sonde hanno osservato e NON quello che una persona ha dichiarato o
quello che vale come prova. Un bottone che sbaglia quel confine e' peggio di nessun
bottone -- porta via una configurazione di giorni, o la prova di una comunicazione
dovuta all'autorita', e nessuno se ne accorge finche' non serve.

remarks: Autore: Daniele Speziale - Data: 2026-09-10
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re

import pytest


# --------------------------------------------------------------------------- #
# Semina
# --------------------------------------------------------------------------- #
def _tenant(server_app, code: str = "ised") -> int:
    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT id FROM tenants WHERE code = ?", (code,), one=True)
        assert riga is not None, "tenant %s assente nei dati iniziali" % code
        return int(riga["id"])


def _semina(server_app, tenant_id: int, con_acn: bool = True) -> dict:
    """Un tenant con del raccolto e della configurazione, per poterli distinguere.

    Si semina in TUTTE le tabelle radice: un azzeramento che ne dimenticasse una
    lascerebbe righe orfane, e un test che semina solo i nodi non lo vedrebbe.
    """
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        adesso = utc_now_str()
        riferimenti = {}

        # --- configurazione: deve sopravvivere ---
        riferimenti["subnet"] = execute(
            "INSERT INTO subnets (tenant_id, cidr, label, created_at, updated_at)"
            " VALUES (?, '10.20.10.0/24', 'perimetro dichiarato', ?, ?)",
            (tenant_id, adesso, adesso))
        riferimenti["probe"] = execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status,"
            " console_json, console_at, created_at, updated_at)"
            " VALUES (?, ?, ?, 'Sonda seminata', 'active',"
            " '{\"diario\": []}', ?, ?, ?)",
            (tenant_id, "uid-semina-%d" % tenant_id, "sonda-semina-%d" % tenant_id,
             adesso, adesso, adesso))
        riferimenti["target"] = execute(
            "INSERT INTO check_targets (tenant_id, name, address, created_at,"
            " updated_at) VALUES (?, 'bersaglio', '10.20.10.31', ?, ?)",
            (tenant_id, adesso, adesso))
        riferimenti["check"] = execute(
            "INSERT INTO checks (tenant_id, target_id, name, kind, created_at,"
            " updated_at) VALUES (?, ?, 'controllo', 'tcp', ?, ?)",
            (tenant_id, riferimenti["target"], adesso, adesso))
        riferimenti["regola"] = execute(
            "INSERT INTO notify_rules (tenant_id, name, source, created_at,"
            " updated_at) VALUES (?, 'regola', 'inventory', ?, ?)",
            (tenant_id, adesso, adesso))
        execute(
            "INSERT INTO notifications (tenant_id, event, subject, body, created_at,"
            " updated_at) VALUES (?, 'prova', 'oggetto', 'corpo', ?, ?)",
            (tenant_id, adesso, adesso))
        execute(
            "INSERT INTO report_runs (tenant_id, kind, period_key, period_start,"
            " period_end, created_at) VALUES (?, 'mensile', '2026-09',"
            " '2026-09-01', '2026-09-30', ?)",
            (tenant_id, adesso))

        # --- raccolto: deve sparire ---
        riferimenti["nodo"] = execute(
            "INSERT INTO nodes (tenant_id, ip, subnet_id, first_seen_at, last_seen_at,"
            " created_at, updated_at) VALUES (?, '10.20.10.31', ?, ?, ?, ?, ?)",
            (tenant_id, riferimenti["subnet"], adesso, adesso, adesso, adesso))
        execute(
            "INSERT INTO node_ports (tenant_id, node_id, protocol, port, state,"
            " first_seen_at, last_seen_at) VALUES (?, ?, 'tcp', 80, 'open', ?, ?)",
            (tenant_id, riferimenti["nodo"], adesso, adesso))
        execute(
            "INSERT INTO node_changes (tenant_id, node_id, kind, created_at)"
            " VALUES (?, ?, 'port.opened', ?)",
            (tenant_id, riferimenti["nodo"], adesso))
        execute(
            "INSERT INTO monitor_samples (tenant_id, node_id, checked_at)"
            " VALUES (?, ?, ?)", (tenant_id, riferimenti["nodo"], adesso))
        execute(
            "INSERT INTO ti_findings (tenant_id, node_id, kind, title, evidence,"
            " first_seen_at, last_seen_at) VALUES (?, ?, 'exposure', 'titolo',"
            " 'prova', ?, ?)",
            (tenant_id, riferimenti["nodo"], adesso, adesso))
        execute(
            "INSERT INTO scan_runs (tenant_id, stage, target, created_at)"
            " VALUES (?, 'ports', '10.20.10.0/24', ?)", (tenant_id, adesso))
        execute(
            "INSERT INTO ingest_batches (tenant_id, probe_id, batch_uid, received_at)"
            " VALUES (?, ?, 'lotto-semina', ?)",
            (tenant_id, riferimenti["probe"], adesso))
        execute(
            "INSERT INTO presence_sessions (tenant_id, identity_key, identity_source,"
            " ip, subnet_id, node_id, first_seen_at, last_seen_at, created_at)"
            " VALUES (?, 'mac:aa:bb:cc:dd:ee:ff', 'mac', '10.20.10.99', ?, ?, ?, ?, ?)",
            (tenant_id, riferimenti["subnet"], riferimenti["nodo"], adesso, adesso,
             adesso))
        riferimenti["esito"] = execute(
            "INSERT INTO check_results (tenant_id, check_id, executed_at, status,"
            " received_at) VALUES (?, ?, ?, 'ok', ?)",
            (tenant_id, riferimenti["check"], adesso, adesso))
        execute(
            "INSERT INTO check_metrics (tenant_id, check_id, result_id, name, value,"
            " measured_at) VALUES (?, ?, ?, 'latenza', 12.5, ?)",
            (tenant_id, riferimenti["check"], riferimenti["esito"], adesso))
        execute(
            "INSERT INTO rule_matches (tenant_id, rule_id, source, event_type,"
            " occurred_at, created_at) VALUES (?, ?, 'inventory', 'node.new', ?, ?)",
            (tenant_id, riferimenti["regola"], adesso, adesso))
        execute(
            "INSERT INTO siem_events (tenant_id, received_at, message)"
            " VALUES (?, ?, 'riga di log')", (tenant_id, adesso))
        execute(
            "INSERT INTO siem_alerts (tenant_id, rule_code, title, evidence,"
            " first_event_at, last_event_at, created_at, updated_at)"
            " VALUES (?, 'R1', 'avviso', 'prova', ?, ?, ?, ?)",
            (tenant_id, adesso, adesso, adesso, adesso))

        # Due incidenti: uno nudo, uno da cui e' nata una comunicazione ad ACN.
        riferimenti["incidente_nudo"] = execute(
            "INSERT INTO check_incidents (tenant_id, check_id, title, opened_at,"
            " updated_at) VALUES (?, ?, 'incidente senza atti', ?, ?)",
            (tenant_id, riferimenti["check"], adesso, adesso))
        execute(
            "INSERT INTO check_incident_events (tenant_id, incident_id, action,"
            " created_at) VALUES (?, ?, 'opened', ?)",
            (tenant_id, riferimenti["incidente_nudo"], adesso))
        if con_acn:
            riferimenti["incidente_acn"] = execute(
                "INSERT INTO check_incidents (tenant_id, check_id, title, opened_at,"
                " updated_at) VALUES (?, ?, 'incidente comunicato', ?, ?)",
                (tenant_id, riferimenti["check"], adesso, adesso))
            riferimenti["comunicazione"] = execute(
                "INSERT INTO acn_communications (tenant_id, incident_id, stage,"
                " known_at, created_at, updated_at)"
                " VALUES (?, ?, 'notifica', ?, ?, ?)",
                (tenant_id, riferimenti["incidente_acn"], adesso, adesso, adesso))
        return riferimenti


def _conta(server_app, tabella: str, tenant_id: int) -> int:
    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT COUNT(*) AS n FROM %s WHERE tenant_id = ?" % tabella,
                     (tenant_id,), one=True)
        return int((riga or {"n": 0})["n"] or 0)


def _azzera(logged_client, server_app, tenant_id: int, codice: str = None):
    with server_app.app_context():
        from snapserver.db import query

        if codice is None:
            codice = query("SELECT code FROM tenants WHERE id = ?",
                           (tenant_id,), one=True)["code"]
    return logged_client.post(
        "/admin/tenants/%d/purge-collected" % tenant_id,
        data={"confirm_code": codice}, follow_redirects=True)


# --------------------------------------------------------------------------- #
# Il confine
# --------------------------------------------------------------------------- #
def test_il_raccolto_sparisce(logged_client, server_app):
    tenant_id = _tenant(server_app)
    _semina(server_app, tenant_id)

    risposta = _azzera(logged_client, server_app, tenant_id)

    assert risposta.status_code == 200
    for tabella in ("nodes", "node_ports", "node_changes", "monitor_samples",
                    "ti_findings", "scan_runs", "ingest_batches",
                    "presence_sessions", "check_results", "check_metrics",
                    "rule_matches", "siem_events", "siem_alerts"):
        assert _conta(server_app, tabella, tenant_id) == 0, tabella


def test_la_configurazione_resta(logged_client, server_app):
    """E' la meta' del confine che nessuno pensa a verificare: qui il tenant RESTA,
    e con lui tutto cio' che una persona ha dichiarato."""
    tenant_id = _tenant(server_app)
    _semina(server_app, tenant_id)

    _azzera(logged_client, server_app, tenant_id)

    for tabella in ("users", "probes", "subnets", "check_targets", "checks",
                    "notify_rules", "notifications", "report_runs"):
        assert _conta(server_app, tabella, tenant_id) > 0, tabella
    with server_app.app_context():
        from snapserver.db import query

        assert query("SELECT id FROM tenants WHERE id = ?", (tenant_id,),
                     one=True) is not None, "il tenant deve restare in piedi"


def test_il_perimetro_non_si_perde(logged_client, server_app):
    """La subnet e' referenziata dai nodi e dalle presenze che si cancellano: se il
    vincolo fosse in cascata nella direzione sbagliata, il perimetro se ne andrebbe
    con loro e la sonda si troverebbe senza bersagli."""
    tenant_id = _tenant(server_app)
    _semina(server_app, tenant_id)

    _azzera(logged_client, server_app, tenant_id)

    with server_app.app_context():
        from snapserver.db import query

        righe = query("SELECT cidr FROM subnets WHERE tenant_id = ?", (tenant_id,))
        assert [r["cidr"] for r in righe] == ["10.20.10.0/24"]


def test_un_incidente_comunicato_ad_acn_non_si_cancella(logged_client, server_app):
    """Una comunicazione all'autorita' e' un atto dovuto (D.lgs. 138/2024 art. 25):
    la sua prova non puo' sparire con un bottone."""
    tenant_id = _tenant(server_app)
    riferimenti = _semina(server_app, tenant_id)

    _azzera(logged_client, server_app, tenant_id)

    with server_app.app_context():
        from snapserver.db import query

        rimasti = [int(r["id"]) for r in
                   query("SELECT id FROM check_incidents WHERE tenant_id = ?",
                         (tenant_id,))]
        assert rimasti == [riferimenti["incidente_acn"]]
        assert _conta(server_app, "acn_communications", tenant_id) == 1


def test_un_incidente_senza_atti_si_cancella(logged_client, server_app):
    tenant_id = _tenant(server_app)
    _semina(server_app, tenant_id, con_acn=False)

    _azzera(logged_client, server_app, tenant_id)

    assert _conta(server_app, "check_incidents", tenant_id) == 0
    assert _conta(server_app, "check_incident_events", tenant_id) == 0


def test_l_istantanea_della_console_si_azzera(logged_client, server_app):
    """Contiene il diario e lo stato delle fasi: lasciarla mostrerebbe il riassunto
    di un inventario che non esiste piu'. La sonda ne manda una nuova col battito."""
    tenant_id = _tenant(server_app)
    _semina(server_app, tenant_id)

    _azzera(logged_client, server_app, tenant_id)

    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT console_json, console_at FROM probes"
                     " WHERE tenant_id = ? AND code = ?",
                     (tenant_id, "sonda-semina-%d" % tenant_id), one=True)
        assert riga["console_json"] is None and riga["console_at"] is None


# --------------------------------------------------------------------------- #
# La conferma
# --------------------------------------------------------------------------- #
def test_senza_il_codice_non_si_cancella_nulla(logged_client, server_app):
    tenant_id = _tenant(server_app)
    _semina(server_app, tenant_id)
    prima = _conta(server_app, "nodes", tenant_id)

    risposta = _azzera(logged_client, server_app, tenant_id, codice="sbagliato")

    assert _conta(server_app, "nodes", tenant_id) == prima
    assert "digitare esattamente il codice" in risposta.data.decode("utf-8")


def test_un_tenant_inesistente_da_404(logged_client, server_app):
    assert logged_client.post("/admin/tenants/99999/purge-collected",
                              data={"confirm_code": "x"}).status_code == 404


def test_solo_l_amministratore_di_sistema(server_app):
    """L'azzeramento e' riservato al superadmin come l'eliminazione del tenant: chi
    amministra un tenant non deve poter buttare il raccolto del proprio."""
    tenant_id = _tenant(server_app)
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str
        from snapserver.security import ROLE_TENANT_ADMIN, hash_password

        adesso = utc_now_str()
        execute(
            "INSERT INTO users (tenant_id, email, password_hash, full_name, role,"
            " is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
            (tenant_id, "capo@ised.local", hash_password("Snap!Tenant2026"),
             "Amministratore di tenant", ROLE_TENANT_ADMIN, adesso, adesso))

    client = server_app.test_client()
    client.post("/login", data={"email": "capo@ised.local",
                                "password": "Snap!Tenant2026"},
                follow_redirects=True)
    risposta = client.post("/admin/tenants/%d/purge-collected" % tenant_id,
                           data={"confirm_code": "ised"})
    assert risposta.status_code in (302, 403)
    if risposta.status_code == 302:
        assert "/admin/tenants" not in risposta.headers.get("Location", "")


# --------------------------------------------------------------------------- #
# Isolamento e tracciabilita'
# --------------------------------------------------------------------------- #
def test_il_raccolto_di_un_altro_tenant_non_si_tocca(logged_client, server_app):
    from test_multitenancy import _crea_secondo_tenant

    primo = _tenant(server_app)
    secondo = _crea_secondo_tenant(server_app)
    _semina(server_app, primo)
    _semina(server_app, secondo)

    _azzera(logged_client, server_app, primo)

    assert _conta(server_app, "nodes", primo) == 0
    assert _conta(server_app, "nodes", secondo) > 0, "violazione di isolamento"
    assert _conta(server_app, "siem_events", secondo) > 0


def test_l_azzeramento_resta_nel_registro_di_audit(logged_client, server_app):
    """La traccia sta SUL tenant, che sopravvive: chi lo amministra deve poter vedere
    nel proprio registro che il raccolto e' stato azzerato, da chi e quando."""
    tenant_id = _tenant(server_app)
    _semina(server_app, tenant_id)

    _azzera(logged_client, server_app, tenant_id)

    with server_app.app_context():
        from snapserver.db import query

        riga = query(
            "SELECT * FROM audit_events WHERE event_type = 'tenant.collected.purged'"
            " AND tenant_id = ? ORDER BY id DESC", (tenant_id,), one=True)
        assert riga is not None, "l'azzeramento non ha lasciato traccia"
        assert riga["severity"] == "critical"
        assert re.search(r"\d+ record eliminati", riga["description"])


def test_il_registro_di_audit_non_viene_cancellato(logged_client, server_app):
    tenant_id = _tenant(server_app)
    _semina(server_app, tenant_id)
    prima = _conta(server_app, "audit_events", tenant_id)

    _azzera(logged_client, server_app, tenant_id)

    assert _conta(server_app, "audit_events", tenant_id) > prima


# --------------------------------------------------------------------------- #
# Le sonde
# --------------------------------------------------------------------------- #
def test_alle_sonde_si_chiede_di_ricominciare(logged_client, server_app):
    """Senza questo il bottone sembrerebbe rotto: la sonda ricorda quali fasi ha
    svolto, e un nodo che il server ha dimenticato non tornerebbe fino alla scadenza
    della cadenza -- giorni."""
    tenant_id = _tenant(server_app)
    _semina(server_app, tenant_id)

    _azzera(logged_client, server_app, tenant_id)

    with server_app.app_context():
        from snapserver.db import query

        righe = query("SELECT command, status FROM probe_commands"
                      " WHERE tenant_id = ?", (tenant_id,))
        comandi = [r["command"] for r in righe]
        assert "forget" in comandi
        assert all(r["status"] == "pending" for r in righe if r["command"] == "forget")


def test_non_si_accodano_due_richieste_uguali(logged_client, server_app):
    tenant_id = _tenant(server_app)
    _semina(server_app, tenant_id)

    _azzera(logged_client, server_app, tenant_id)
    _azzera(logged_client, server_app, tenant_id)

    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT COUNT(*) AS n FROM probe_commands"
                     " WHERE tenant_id = ? AND command = 'forget'",
                     (tenant_id,), one=True)
        assert int(riga["n"]) == 1, "una richiesta in coda non va ripetuta"


def test_la_sonda_sa_eseguire_il_comando_forget(probe_store):
    """Il comando lo manda il server: se la sonda non lo conoscesse, l'azzeramento
    lascerebbe la sonda convinta di avere gia' profilato tutto. E' la terza volta che
    un elenco su un lato del contratto manca di una voce presente sull'altro."""
    from snapprobe.agent import ProbeAgent

    probe_store.upsert_local_node("10.20.10.31", state="up", stages_done="ports",
                                  conferred_at="2026-09-10 10:00:00")
    agente = ProbeAgent(probe_store, "1.5.0", 5)

    esito = agente._run_command("forget")

    assert "riparte dalla scoperta" in esito
    assert probe_store.local_node_count() == 0


def test_ogni_comando_offerto_dal_server_e_eseguibile_dalla_sonda(probe_store):
    """Contratto fra i due lati: il server offre un elenco di comandi nella console
    delle sonde, e la sonda deve saperli eseguire tutti. Enumerarli a mano nei due
    posti e' esattamente il modo in cui si perde una voce."""
    from snapprobe.agent import ProbeAgent
    from snapserver.blueprints.probes import AVAILABLE_COMMANDS

    agente = ProbeAgent(probe_store, "1.5.0", 5)
    non_riconosciuti = []
    for nome in AVAILABLE_COMMANDS:
        if nome == "scan":
            continue  # ha bisogno di un carico proprio: lo provano i test del pool
        try:
            agente._run_command(nome)
        except ValueError as errore:
            if "non supportato" in str(errore):
                non_riconosciuti.append(nome)
    assert not non_riconosciuti, (
        "comandi offerti dal server e non eseguibili dalla sonda: %s"
        % ", ".join(non_riconosciuti))


# --------------------------------------------------------------------------- #
# Il confine e' completo
# --------------------------------------------------------------------------- #
def test_ogni_tabella_del_tenant_e_classificata():
    """OGNI tabella con `tenant_id` deve stare da un lato o dall'altro del confine.

    E' il test che serve fra sei mesi: chi aggiunge una tabella con dati raccolti e
    non la dichiara scoprirebbe altrimenti che l'azzeramento la lascia intatta --
    cioe' che il bottone mente. Il fallimento va risolto CLASSIFICANDO la tabella,
    non allargando l'elenco delle eccezioni.
    """
    import io
    import re as espressioni

    from snapserver import purge

    schema = io.open("server/snapserver/schema.sql", encoding="utf-8").read()
    con_tenant = set()
    for nome, corpo in espressioni.findall(
            r"CREATE TABLE (?:IF NOT EXISTS )?(\w+)\s*\((.*?)\n\);", schema,
            espressioni.S):
        if "tenant_id" in corpo:
            con_tenant.add(nome)

    dichiarate = {t for t, _e, _r in purge.TABELLE_RACCOLTE}
    dichiarate |= set(purge.TABELLE_CONSERVATE)
    assert con_tenant - dichiarate == set(), (
        "tabelle con tenant_id non classificate in purge.py: %s"
        % ", ".join(sorted(con_tenant - dichiarate)))


def test_le_due_meta_del_confine_non_si_sovrappongono():
    from snapserver import purge

    raccolte = {t for t, _e, _r in purge.TABELLE_RACCOLTE}
    assert raccolte & set(purge.TABELLE_CONSERVATE) == set(), (
        "una tabella non puo' essere insieme raccolta e conservata")


def test_il_riepilogo_dice_quanto_si_sta_per_perdere(server_app):
    """La conferma mostra il numero: una conferma che non lo dice non e' informata."""
    tenant_id = _tenant(server_app)
    _semina(server_app, tenant_id)

    with server_app.app_context():
        from snapserver import purge

        riepilogo = purge.riepilogo(tenant_id)
        assert riepilogo["totale"] > 0
        etichette = {v["etichetta"] for v in riepilogo["voci"]}
        assert "Nodi dell'inventario" in etichette
        # Le voci sono ordinate dalla piu' consistente: chi guarda vede subito che
        # cosa pesa.
        conti = [v["record"] for v in riepilogo["voci"]]
        assert conti == sorted(conti, reverse=True)


def test_il_riepilogo_per_tenant_costa_una_query_per_tabella(server_app):
    """La pagina mostra il conto per ogni riga: con un conteggio per tenant il costo
    crescerebbe col numero dei tenant senza motivo."""
    from test_multitenancy import _crea_secondo_tenant

    primo = _tenant(server_app)
    secondo = _crea_secondo_tenant(server_app)
    _semina(server_app, primo)
    _semina(server_app, secondo)

    with server_app.app_context():
        from snapserver import purge

        tutti = purge.riepiloghi()
        assert tutti[primo]["totale"] > 0
        assert tutti[secondo]["totale"] > 0
        assert tutti[primo]["totale"] == purge.riepilogo(primo)["totale"]


# --------------------------------------------------------------------------- #
# La pagina
# --------------------------------------------------------------------------- #
def test_la_pagina_dei_tenant_offre_il_bottone(logged_client, server_app):
    tenant_id = _tenant(server_app)
    _semina(server_app, tenant_id)

    corpo = logged_client.get("/admin/tenants").data.decode("utf-8")

    assert "purge-collected" in corpo
    assert "Azzeramento delle informazioni raccolte" in corpo
    # La differenza fra i due bottoni adiacenti va scritta, non lasciata all'icona.
    assert "resta" in corpo and "Viene conservato" in corpo


def test_la_pagina_dice_quanto_c_e_da_perdere(logged_client, server_app):
    tenant_id = _tenant(server_app)
    _semina(server_app, tenant_id)

    corpo = logged_client.get("/admin/tenants").data.decode("utf-8")

    assert "RACCOLTO" in corpo
    # Etichetta senza apostrofo: Jinja lo sostituisce con `&#39;`, e un'asserzione
    # sul testo con l'apostrofo fallirebbe pur essendo la pagina giusta.
    assert "Presenze sulle reti senza fili" in corpo
    assert "Porte" in corpo


def test_la_pagina_regge_un_tenant_senza_raccolto(logged_client, server_app):
    """Un tenant appena creato non ha nulla: la pagina non deve rompersi ne' offrire
    un azzeramento che sembra avere qualcosa da fare."""
    from test_multitenancy import _crea_secondo_tenant

    _crea_secondo_tenant(server_app)

    risposta = logged_client.get("/admin/tenants")

    assert risposta.status_code == 200
    assert "Non c'e' nulla di raccolto" in risposta.data.decode("utf-8")


def test_azzerare_un_tenant_vuoto_non_e_un_errore(logged_client, server_app):
    from test_multitenancy import _crea_secondo_tenant

    secondo = _crea_secondo_tenant(server_app)

    risposta = _azzera(logged_client, server_app, secondo)

    assert risposta.status_code == 200
    assert "0 record eliminati" in risposta.data.decode("utf-8")
