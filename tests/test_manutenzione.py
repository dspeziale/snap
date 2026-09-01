"""
snap - Manutenzione dell'archivio: dimensione, conservazione, copia, ripristino.

Le prove insistono su due cose che nei sistemi reali si scoprono tardi: che la copia
sia davvero ripristinabile, e che il ripristino non distrugga cio' da cui si e'
partiti. La verifica di una copia fa parte della copia, non e' un extra.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest


# --------------------------------------------------------------------------- #
# Preparazione
# --------------------------------------------------------------------------- #
def _tenant_id(server_app):
    with server_app.app_context():
        from snapserver.db import query

        return int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])


def _campioni_vecchi(server_app, tenant_id, quanti=5, quando="2020-01-01 00:00:00"):
    """Campioni di raggiungibilita' oltre qualunque conservazione ragionevole."""
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        subnet_id = execute(
            "INSERT INTO subnets (tenant_id, cidr, host_count, is_enabled, imported_at,"
            " created_at, updated_at) VALUES (?, '10.6.0.0/24', 254, 1, ?, ?, ?)",
            (tenant_id, adesso, adesso, adesso))
        node_id = execute(
            "INSERT INTO nodes (tenant_id, subnet_id, ip, status, first_seen_at,"
            " last_seen_at, created_at, updated_at)"
            " VALUES (?, ?, '10.6.0.1', 'up', ?, ?, ?, ?)",
            (tenant_id, subnet_id, adesso, adesso, adesso, adesso))
        for _ in range(quanti):
            execute("INSERT INTO monitor_samples (tenant_id, node_id, checked_at,"
                    " reachable, latency_ms) VALUES (?, ?, ?, 1, 5.0)",
                    (tenant_id, node_id, quando))
        return node_id


# --------------------------------------------------------------------------- #
# Conservazione
# --------------------------------------------------------------------------- #
def test_la_conservazione_ha_una_durata_per_genere_di_dato(server_app):
    """Una durata unica per tutti i dati e' o troppo corta per il registro delle azioni
    o troppo lunga per i campioni di raggiungibilita'."""
    with server_app.app_context():
        from snapserver.maintenance import retention_plan

        piano = {v["chiave"]: v for v in retention_plan()}

    assert piano["monitor_samples"]["giorni"] == 90
    assert piano["audit_events"]["giorni"] == 730, "e' la prova per un auditor"
    assert piano["report_runs"]["perenne"] is True, (
        "un report sopravvive ai dati che riassume")
    assert all(v["motivo"] for v in piano.values()), (
        "una durata senza motivazione non e' una politica")


def test_i_dati_oltre_soglia_vengono_contati(server_app):
    tenant_id = _tenant_id(server_app)
    _campioni_vecchi(server_app, tenant_id, quanti=7)
    with server_app.app_context():
        from snapserver.maintenance import retention_plan

        voce = {v["chiave"]: v for v in retention_plan()}["monitor_samples"]
    assert voce["righe"] == 7
    assert voce["scaduti"] == 7
    assert voce["piu_vecchio"].startswith("2020-01-01")


def test_la_simulazione_non_cancella(server_app):
    """La prova a vuoto e' il modo di rispondere a "quanto libero?" prima di
    un'operazione che non si annulla."""
    tenant_id = _tenant_id(server_app)
    _campioni_vecchi(server_app, tenant_id, quanti=4)
    with server_app.app_context():
        from snapserver.db import query
        from snapserver.maintenance import purge

        esito = purge(dry_run=True)
        restanti = query("SELECT COUNT(*) AS n FROM monitor_samples", (), one=True)["n"]

    assert esito["simulazione"] is True and esito["righe"] == 4
    assert restanti == 4, "la simulazione non deve toccare nulla"


def test_l_applicazione_elimina_solo_cio_che_e_scaduto(server_app):
    tenant_id = _tenant_id(server_app)
    node_id = _campioni_vecchi(server_app, tenant_id, quanti=3)
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str
        from snapserver.maintenance import purge

        execute("INSERT INTO monitor_samples (tenant_id, node_id, checked_at, reachable,"
                " latency_ms) VALUES (?, ?, ?, 1, 3.0)",
                (tenant_id, node_id, utc_now_str()))
        esito = purge(dry_run=False)
        restanti = query("SELECT COUNT(*) AS n FROM monitor_samples", (), one=True)["n"]

    assert esito["righe"] == 3
    assert restanti == 1, "il campione recente resta"


def test_le_durate_si_salvano_e_vengono_validate(server_app):
    with server_app.app_context():
        from snapserver.maintenance import (
            MaintenanceError,
            retention_plan,
            save_retention,
        )

        cambiati = save_retention({"monitor_samples": "30"})
        assert cambiati == ["monitor_samples=30"]
        piano = {v["chiave"]: v for v in retention_plan()}
        assert piano["monitor_samples"]["giorni"] == 30

        with pytest.raises(MaintenanceError):
            save_retention({"monitor_samples": "molti"})
        with pytest.raises(MaintenanceError):
            save_retention({"monitor_samples": "9999"})


def test_una_durata_a_zero_non_fa_scadere_nulla(server_app):
    tenant_id = _tenant_id(server_app)
    _campioni_vecchi(server_app, tenant_id, quanti=3)
    with server_app.app_context():
        from snapserver.maintenance import purge, retention_plan, save_retention

        save_retention({"monitor_samples": "0"})
        piano = {v["chiave"]: v for v in retention_plan()}
        assert piano["monitor_samples"]["perenne"] is True
        assert purge(dry_run=True)["righe"] == 0


# --------------------------------------------------------------------------- #
# Dimensione
# --------------------------------------------------------------------------- #
def test_la_dimensione_dichiara_lo_spazio_riutilizzabile(server_app):
    """Dopo un'eliminazione il file non si riduce: senza questa voce sembra che la
    conservazione non abbia funzionato."""
    with server_app.app_context():
        from snapserver.maintenance import database_size

        dimensione = database_size()

    assert dimensione["file_byte"] > 0
    assert dimensione["pagine"] > 0 and dimensione["pagina_byte"] > 0
    assert "riutilizzabile_byte" in dimensione
    assert dimensione["righe_totali"] >= 1
    nomi = {t["tabella"] for t in dimensione["tabelle"]}
    assert {"tenants", "nodes", "report_runs", "notify_rules"} <= nomi


def test_la_compattazione_restituisce_lo_spazio(server_app):
    tenant_id = _tenant_id(server_app)
    _campioni_vecchi(server_app, tenant_id, quanti=200)
    with server_app.app_context():
        from snapserver.maintenance import compact, purge

        purge(dry_run=False)
        esito = compact()

    assert esito["dopo"] <= esito["prima"]
    assert esito["liberati"] >= 0


# --------------------------------------------------------------------------- #
# Copie
# --------------------------------------------------------------------------- #
def test_una_copia_viene_verificata_appena_prodotta(server_app):
    with server_app.app_context():
        from snapserver.maintenance import backup_now

        esito = backup_now(nota="prova")

    assert esito["verifica"]["valida"] is True
    assert esito["verifica"]["tenant"] >= 1
    assert esito["byte"] > 0
    assert esito["nome"].startswith("snap-") and esito["nome"].endswith(".sqlite3")


def test_due_copie_nello_stesso_secondo_non_si_sovrascrivono(server_app):
    """Il nome ha risoluzione al secondo: senza contatore la seconda copia
    cancellerebbe la prima, e il ripristino leggerebbe lo stato corrente credendo di
    tornare indietro."""
    with server_app.app_context():
        from snapserver.maintenance import backup_now, list_backups

        prima = backup_now()
        seconda = backup_now()
        elenco = [c["nome"] for c in list_backups()]

    assert prima["nome"] != seconda["nome"]
    assert prima["nome"] in elenco and seconda["nome"] in elenco


def test_la_rotazione_tiene_le_copie_piu_recenti(server_app):
    with server_app.app_context():
        from snapserver.maintenance import backup_now, list_backups

        for _ in range(4):
            backup_now(keep=2)
        elenco = list_backups()

    assert len(elenco) == 2


def test_una_copia_estranea_non_e_ripristinabile(server_app, tmp_path):
    """Un ripristino da un file qualunque distruggerebbe l'archivio in esercizio."""
    estraneo = tmp_path / "altro.sqlite3"
    connessione = sqlite3.connect(str(estraneo))
    connessione.execute("CREATE TABLE cose (id INTEGER)")
    connessione.commit()
    connessione.close()

    testo = tmp_path / "non-un-database.sqlite3"
    testo.write_text("questo non e' un archivio", encoding="utf-8")

    with server_app.app_context():
        from snapserver.maintenance import MaintenanceError, restore_from, verify_backup

        esito = verify_backup(estraneo)
        assert esito["valida"] is False
        assert "archivio snap" in esito["motivo"]

        assert verify_backup(testo)["valida"] is False
        assert verify_backup(tmp_path / "inesistente.sqlite3")["valida"] is False

        with pytest.raises(MaintenanceError):
            restore_from(estraneo)


def test_il_nome_di_una_copia_non_puo_essere_un_percorso(server_app):
    with server_app.app_context():
        from snapserver.maintenance import MaintenanceError, backup_file

        for tentativo in ("../../server.sqlite3", "snap-../../fuori.sqlite3",
                          "qualunque.txt", ""):
            with pytest.raises(MaintenanceError):
                backup_file(tentativo)


# --------------------------------------------------------------------------- #
# Ripristino
# --------------------------------------------------------------------------- #
def test_il_ripristino_riporta_i_dati_e_salva_lo_stato_precedente(server_app):
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str
        from snapserver.maintenance import backup_file, backup_now, restore_from

        adesso = utc_now_str()
        execute("INSERT INTO check_targets (tenant_id, name, address, is_enabled,"
                " created_at, updated_at) VALUES (?, 'Prima', 'prima.local', 1, ?, ?)",
                (tenant_id, adesso, adesso))
        copia = backup_now(nota="con un bersaglio")

        # Modifica successiva alla copia: deve sparire col ripristino.
        execute("INSERT INTO check_targets (tenant_id, name, address, is_enabled,"
                " created_at, updated_at) VALUES (?, 'Dopo', 'dopo.local', 1, ?, ?)",
                (tenant_id, adesso, adesso))
        assert query("SELECT COUNT(*) AS n FROM check_targets", (), one=True)["n"] == 2

        esito = restore_from(backup_file(copia["nome"]))
        indirizzi = [r["address"] for r in query("SELECT address FROM check_targets", ())]

    assert indirizzi == ["prima.local"], "il ripristino riporta lo stato della copia"
    assert esito["copia_precedente"] != copia["nome"], (
        "lo stato corrente va salvato in una copia distinta")

    with server_app.app_context():
        from snapserver.maintenance import backup_file, verify_backup

        # La copia dello stato precedente contiene i due bersagli: si puo' tornare.
        precedente = verify_backup(backup_file(esito["copia_precedente"]))
    assert precedente["valida"] is True


def test_il_ripristino_e_tracciato_e_riporta_anche_il_registro(server_app):
    """Proprieta' intrinseca, non un difetto: ripristinare un archivio ripristina anche
    il suo registro di audit, quindi gli eventi successivi alla copia scompaiono. Cio'
    che resta e' l'evento del ripristino, scritto dopo: e' l'unica traccia che spiega
    perche' il registro sembra tornato indietro."""
    with server_app.app_context():
        from snapserver.db import query
        from snapserver.maintenance import backup_file, backup_now, restore_from

        copia = backup_now()
        prima = query("SELECT COUNT(*) AS n FROM audit_events WHERE event_type ="
                      " 'maintenance.backup'", (), one=True)["n"]
        assert prima >= 1, "la copia viene tracciata quando avviene"

        restore_from(backup_file(copia["nome"]))
        eventi = [r["event_type"] for r in query(
            "SELECT event_type FROM audit_events ORDER BY id DESC LIMIT 5", ())]
        copie_tracciate = query("SELECT COUNT(*) AS n FROM audit_events WHERE"
                                " event_type = 'maintenance.backup'", (), one=True)["n"]

    assert "maintenance.restore" in eventi
    assert copie_tracciate == 0, (
        "gli eventi successivi alla copia tornano indietro con l'archivio")


# --------------------------------------------------------------------------- #
# Pagine e permessi
# --------------------------------------------------------------------------- #
def test_l_amministratore_di_sistema_vede_copie_e_ripristino(logged_client):
    pagina = logged_client.get("/admin/settings").get_data(as_text=True)
    assert "Copie di sicurezza" in pagina
    assert "Ripristino" in pagina
    assert "digitare RIPRISTINA" in pagina


def test_una_copia_si_crea_dalla_pagina(logged_client, server_app):
    risposta = logged_client.post("/admin/settings/backup", data={"nota": "dalla pagina"},
                                  follow_redirects=True)
    assert risposta.status_code == 200
    assert "Copia creata" in risposta.get_data(as_text=True)

    with server_app.app_context():
        from snapserver.maintenance import list_backups

        assert len(list_backups()) == 1


def test_il_ripristino_richiede_la_conferma_digitata(logged_client, server_app):
    with server_app.app_context():
        from snapserver.maintenance import backup_now

        copia = backup_now()

    risposta = logged_client.post("/admin/settings/restore",
                                  data={"nome": copia["nome"], "conferma": "si"},
                                  follow_redirects=True)
    testo = risposta.get_data(as_text=True)
    assert "Ripristino annullato" in testo
    assert "RIPRISTINA" in testo


def test_la_verifica_dalla_pagina_non_ripristina(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str
        from snapserver.maintenance import backup_now

        copia = backup_now()
        adesso = utc_now_str()
        execute("INSERT INTO check_targets (tenant_id, name, address, is_enabled,"
                " created_at, updated_at) VALUES (?, 'Dopo', 'dopo.local', 1, ?, ?)",
                (tenant_id, adesso, adesso))

    risposta = logged_client.post("/admin/settings/restore",
                                  data={"nome": copia["nome"], "conferma": "RIPRISTINA",
                                        "solo_verifica": "1"},
                                  follow_redirects=True)
    assert "Copia valida" in risposta.get_data(as_text=True)

    with server_app.app_context():
        from snapserver.db import query

        assert query("SELECT COUNT(*) AS n FROM check_targets", (), one=True)["n"] == 1, (
            "la sola verifica non deve toccare l'archivio")


def test_un_amministratore_di_tenant_non_puo_copiare_ne_ripristinare(server_app):
    """La copia contiene i dati di tutti i tenant: non e' un'operazione di tenant."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str
        from snapserver.security import hash_password

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
        adesso = utc_now_str()
        execute("INSERT INTO users (tenant_id, email, password_hash, full_name, role,"
                " is_active, must_change_pwd, created_at, updated_at)"
                " VALUES (?, 'capo@ised.local', ?, 'Capo Tenant', 'tenant_admin', 1, 0,"
                " ?, ?)",
                (tenant_id, hash_password("Snap!Tenant2026"), adesso, adesso))

    client = server_app.test_client()
    client.post("/login", data={"email": "capo@ised.local",
                                "password": "Snap!Tenant2026"}, follow_redirects=True)

    for percorso, dati in (("/admin/settings/backup", {}),
                           ("/admin/settings/restore", {"conferma": "RIPRISTINA"}),
                           ("/admin/settings/retention", {}),
                           ("/admin/settings/retention/apply", {}),
                           ("/admin/settings/database/compact", {})):
        risposta = client.post(percorso, data=dati)
        assert risposta.status_code in (302, 403), (
            "%s deve essere negato a un amministratore di tenant" % percorso)
        if risposta.status_code == 302:
            assert "/login" not in risposta.headers.get("Location", ""), (
                "la sessione e' valida: il rifiuto deve essere di autorizzazione")

    with server_app.app_context():
        from snapserver.maintenance import list_backups

        assert list_backups() == [], "nessuna copia deve essere stata creata"
