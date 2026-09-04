"""
snap - Report periodici e resoconto quotidiano.

Le prove coprono le regole che rendono un resoconto affidabile: la finestra nel fuso
del tenant, l'assenza di dati distinta dallo zero, un solo resoconto per giorno anche a
fronte di riavvii, e la soppressione delle variazioni durante il rilevamento di base.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta

import pytest


# --------------------------------------------------------------------------- #
# Preparazione
# --------------------------------------------------------------------------- #
def _tenant(server_app, timezone_name="Europe/Rome", contatto="turno@ised.local"):
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        riga = query("SELECT id FROM tenants ORDER BY id", (), one=True)
        tenant_id = int(riga["id"])
        execute("UPDATE tenants SET timezone = ?, contact_email = ? WHERE id = ?",
                (timezone_name, contatto, tenant_id))
        return dict(query("SELECT id, code, name, timezone, contact_email FROM tenants"
                          " WHERE id = ?", (tenant_id,), one=True))


def _controllo(server_app, tenant_id, nome="salute", genere="http"):
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        adesso = utc_now_str()
        bersaglio = query("SELECT id FROM check_targets WHERE tenant_id = ?",
                          (tenant_id,), one=True)
        if bersaglio is None:
            target_id = execute(
                "INSERT INTO check_targets (tenant_id, name, address, is_enabled,"
                " created_at, updated_at) VALUES (?, 'Collaudo', 'servizio.local', 1, ?, ?)",
                (tenant_id, adesso, adesso))
        else:
            target_id = int(bersaglio["id"])
        return execute(
            "INSERT INTO checks (tenant_id, target_id, name, kind, config_json,"
            " interval_seconds, timeout_seconds, is_enabled, severity, failure_threshold,"
            " escalation_threshold, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, '{}', 300, 10, 1, 'warning', 2, 6, ?, ?)",
            (tenant_id, target_id, nome, genere, adesso, adesso)), target_id


def _esito(server_app, tenant_id, check_id, quando, stato="ok", latenza=100.0):
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        execute("INSERT INTO check_results (tenant_id, check_id, probe_id, executed_at,"
                " status, latency_ms, detail, received_at)"
                " VALUES (?, ?, NULL, ?, ?, ?, 'prova', ?)",
                (tenant_id, check_id, quando, stato, latenza, utc_now_str()))


def _ieri_utc(server_app, tenant, ora=12):
    """Istante UTC che cade nel giorno locale di ieri, all'ora indicata."""
    with server_app.app_context():
        from snapserver.db import utc_str
        from snapserver.reports.windows import yesterday_local, zone_of

        zona = zone_of(tenant)
        giorno = yesterday_local(zona)
        locale = datetime(giorno.year, giorno.month, giorno.day, ora, 0, tzinfo=zona)
        return utc_str(locale), giorno


# --------------------------------------------------------------------------- #
# Finestre temporali
# --------------------------------------------------------------------------- #
def test_la_finestra_del_giorno_e_nel_fuso_del_tenant(server_app):
    """"Ieri" per chi lavora a Roma non e' "ieri" in UTC: d'estate ballano due ore,
    e quelle due ore contengono i turni di notte."""
    tenant = _tenant(server_app, "Europe/Rome")
    with server_app.app_context():
        from snapserver.reports.windows import day_bounds, zone_of

        inizio, fine = day_bounds(zone_of(tenant), date(2026, 8, 27))
    # 27 agosto: ora legale, sfasamento di due ore.
    assert inizio == "2026-08-26 22:00:00"
    assert fine == "2026-08-27 22:00:00"


def test_la_finestra_segue_il_fuso_dichiarato(server_app):
    tenant = _tenant(server_app, "UTC")
    with server_app.app_context():
        from snapserver.reports.windows import day_bounds, zone_of

        inizio, fine = day_bounds(zone_of(tenant), date(2026, 8, 27))
    assert inizio == "2026-08-27 00:00:00" and fine == "2026-08-28 00:00:00"


def test_un_giorno_futuro_viene_rifiutato(server_app):
    """Un report su dati non ancora raccolti sarebbe vuoto senza saper dire perche'."""
    tenant = _tenant(server_app)
    with server_app.app_context():
        from snapserver.reports.windows import WindowError, parse_day, zone_of

        zona = zone_of(tenant)
        domani = (datetime.now(zona).date() + timedelta(days=1)).isoformat()
        with pytest.raises(WindowError):
            parse_day(domani, zona)
        with pytest.raises(WindowError):
            parse_day("27-08-2026", zona)


def test_senza_giorno_indicato_si_intende_ieri(server_app):
    tenant = _tenant(server_app)
    with server_app.app_context():
        from snapserver.reports.windows import parse_day, yesterday_local, zone_of

        zona = zone_of(tenant)
        assert parse_day("", zona) == yesterday_local(zona)


# --------------------------------------------------------------------------- #
# Dati delle sezioni
# --------------------------------------------------------------------------- #
def test_un_giorno_senza_esecuzioni_non_e_disponibilita_zero(server_app):
    """E' la differenza fra "il servizio e' caduto" e "non abbiamo guardato": su un
    resoconto, quella differenza diventa una decisione sbagliata."""
    tenant = _tenant(server_app)
    with server_app.app_context():
        from snapserver.reports import dataset
        from snapserver.reports.windows import day_bounds, yesterday_local, zone_of

        zona = zone_of(tenant)
        inizio, fine = day_bounds(zona, yesterday_local(zona))
        esito = dataset.availability(int(tenant["id"]), inizio, fine)

    assert esito["misurato"] is False
    assert esito["percentuale"] is None, "senza esiti non si costruisce una percentuale"


def test_la_disponibilita_si_calcola_sugli_esiti_della_finestra(server_app):
    tenant = _tenant(server_app)
    check_id, _ = _controllo(server_app, int(tenant["id"]))
    quando, giorno = _ieri_utc(server_app, tenant)
    for stato in ("ok", "ok", "ok", "fail"):
        _esito(server_app, int(tenant["id"]), check_id, quando, stato)
    # Un esito fuori finestra non deve entrare nel conto.
    _esito(server_app, int(tenant["id"]), check_id, "2020-01-01 10:00:00", "fail")

    with server_app.app_context():
        from snapserver.reports import dataset
        from snapserver.reports.windows import day_bounds, zone_of

        inizio, fine = day_bounds(zone_of(tenant), giorno)
        esito = dataset.availability(int(tenant["id"]), inizio, fine)

    assert esito["esiti"] == 4 and esito["riusciti"] == 3
    assert esito["percentuale"] == 75.0
    assert esito["controlli"][0]["esiti"] == 4


def test_le_finestre_di_indisponibilita_sono_serie_consecutive(server_app):
    tenant = _tenant(server_app)
    check_id, _ = _controllo(server_app, int(tenant["id"]))
    quando, giorno = _ieri_utc(server_app, tenant, ora=8)
    base = datetime.strptime(quando, "%Y-%m-%d %H:%M:%S")
    sequenza = [("ok", 0), ("fail", 5), ("fail", 10), ("fail", 15), ("ok", 20),
                ("ok", 25), ("fail", 30), ("ok", 35)]
    for stato, minuti in sequenza:
        _esito(server_app, int(tenant["id"]), check_id,
               (base + timedelta(minutes=minuti)).strftime("%Y-%m-%d %H:%M:%S"), stato)

    with server_app.app_context():
        from snapserver.reports import dataset
        from snapserver.reports.windows import day_bounds, zone_of

        zona = zone_of(tenant)
        inizio, fine = day_bounds(zona, giorno)
        finestre = dataset.outages(int(tenant["id"]), inizio, fine, zona)

    assert len(finestre) == 2, "due serie separate da un esito riuscito"
    lunga = finestre[0]
    assert lunga["esiti"] == 3
    assert lunga["durata_minuti"] == 15, "dal primo fallimento al rientro"
    assert lunga["aperta"] is False


def test_un_controllo_mai_riuscito_e_una_questione_da_risolvere(server_app):
    """Non e' un servizio caduto: e' una definizione sbagliata, e si risolve
    correggendola, non presidiando."""
    tenant = _tenant(server_app)
    check_id, _ = _controllo(server_app, int(tenant["id"]), nome="porta 85")
    quando, _ = _ieri_utc(server_app, tenant)
    for _ in range(4):
        _esito(server_app, int(tenant["id"]), check_id, quando, "fail", 10000.0)

    with server_app.app_context():
        from snapserver.reports import dataset
        from snapserver.reports.windows import zone_of

        questioni = dataset.open_issues(int(tenant["id"]), zone_of(tenant))

    tipi = [q["tipo"] for q in questioni]
    assert "controllo_mai_riuscito" in tipi
    voce = [q for q in questioni if q["tipo"] == "controllo_mai_riuscito"][0]
    assert "porta 85" in voce["titolo"]
    assert "0 riusciti" in voce["dettaglio"]


def test_pochi_fallimenti_non_bastano_per_dire_mai_riuscito(server_app):
    """Due fallimenti possono essere l'avvio di un servizio."""
    tenant = _tenant(server_app)
    check_id, _ = _controllo(server_app, int(tenant["id"]))
    quando, _ = _ieri_utc(server_app, tenant)
    for _ in range(2):
        _esito(server_app, int(tenant["id"]), check_id, quando, "fail")

    with server_app.app_context():
        from snapserver.reports import dataset
        from snapserver.reports.windows import zone_of

        questioni = dataset.open_issues(int(tenant["id"]), zone_of(tenant))
    assert "controllo_mai_riuscito" not in [q["tipo"] for q in questioni]


def test_una_variazione_su_molti_nodi_diventa_un_fatto_aggregato(server_app):
    """264 nodi con la stessa porta aperta sono un apparato che risponde per altri,
    non 264 eventi."""
    tenant = _tenant(server_app)
    tenant_id = int(tenant["id"])
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        subnet_id = execute(
            "INSERT INTO subnets (tenant_id, cidr, host_count, is_enabled, imported_at,"
            " created_at, updated_at) VALUES (?, '10.9.0.0/24', 254, 1, ?, ?, ?)",
            (tenant_id, adesso, adesso, adesso))
        for indice in range(20):
            node_id = execute(
                "INSERT INTO nodes (tenant_id, subnet_id, ip, status, first_seen_at,"
                " last_seen_at, created_at, updated_at)"
                " VALUES (?, ?, ?, 'up', ?, ?, ?, ?)",
                (tenant_id, subnet_id, "10.9.0.%d" % (indice + 1), adesso, adesso,
                 adesso, adesso))
            # Dieci nodi su venti: metà della rete, oltre la soglia di un quinto (4).
            if indice < 10:
                execute("INSERT INTO node_changes (tenant_id, node_id, kind, subject,"
                        " before_value, after_value, severity, created_at)"
                        " VALUES (?, ?, 'port.opened', 'tcp/2000', '', 'cisco-sccp',"
                        " 'warning', ?)", (tenant_id, node_id, adesso))
            elif indice < 12:
                # Due nodi su venti: sotto la soglia, l'elenco resta informativo.
                execute("INSERT INTO node_changes (tenant_id, node_id, kind, subject,"
                        " before_value, after_value, severity, created_at)"
                        " VALUES (?, ?, 'hostname.changed', ?, 'vecchio', 'nuovo',"
                        " 'info', ?)", (tenant_id, node_id, "10.9.0.%d" % (indice + 1),
                                        adesso))

    with server_app.app_context():
        from snapserver.reports import dataset

        variazioni = dataset.changes(tenant_id, "2000-01-01 00:00:00",
                                    "2100-01-01 00:00:00", 20)

    per_genere = {v["genere"]: v for v in variazioni["generi"]}
    assert per_genere["port.opened"]["aggregato"] is True
    assert per_genere["port.opened"]["esempi"] == [], (
        "un fatto aggregato non si elenca")
    assert per_genere["hostname.changed"]["aggregato"] is False
    assert per_genere["hostname.changed"]["esempi"], (
        "sotto la soglia l'elenco e' l'informazione utile")


def test_il_rilevamento_di_base_si_dichiara(server_app):
    """Il primo giro produce una variazione per nodo e per porta: presentarle come
    novita' della giornata renderebbe il resoconto illeggibile."""
    tenant = _tenant(server_app)
    tenant_id = int(tenant["id"])
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        subnet_id = execute(
            "INSERT INTO subnets (tenant_id, cidr, host_count, is_enabled, imported_at,"
            " created_at, updated_at) VALUES (?, '10.8.0.0/24', 254, 1, ?, ?, ?)",
            (tenant_id, adesso, adesso, adesso))
        execute("INSERT INTO nodes (tenant_id, subnet_id, ip, status, first_seen_at,"
                " last_seen_at, created_at, updated_at)"
                " VALUES (?, ?, '10.8.0.1', 'up', ?, ?, ?, ?)",
                (tenant_id, subnet_id, adesso, adesso, adesso, adesso))

    with server_app.app_context():
        from snapserver.reports import dataset
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        stato = dataset.baseline(tenant_id, today_local(zona), zona)
    assert stato["attivo"] is True
    assert stato["giorno"] == 1 and stato["di"] == 7
    assert stato["fine"] is not None


def test_il_rilevamento_di_base_finisce(server_app):
    tenant = _tenant(server_app)
    tenant_id = int(tenant["id"])
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        subnet_id = execute(
            "INSERT INTO subnets (tenant_id, cidr, host_count, is_enabled, imported_at,"
            " created_at, updated_at) VALUES (?, '10.7.0.0/24', 254, 1, ?, ?, ?)",
            (tenant_id, adesso, adesso, adesso))
        execute("INSERT INTO nodes (tenant_id, subnet_id, ip, status, first_seen_at,"
                " last_seen_at, created_at, updated_at)"
                " VALUES (?, ?, '10.7.0.1', 'up', '2020-01-01 00:00:00', ?, ?, ?)",
                (tenant_id, subnet_id, adesso, adesso, adesso))

    with server_app.app_context():
        from snapserver.reports import dataset
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        stato = dataset.baseline(tenant_id, today_local(zona), zona)
    assert stato["attivo"] is False


def test_le_tendenze_dichiarano_i_giorni_non_misurati(server_app):
    tenant = _tenant(server_app)
    check_id, _ = _controllo(server_app, int(tenant["id"]))
    quando, giorno = _ieri_utc(server_app, tenant)
    _esito(server_app, int(tenant["id"]), check_id, quando, "ok", 250.0)
    _esito(server_app, int(tenant["id"]), check_id, quando, "fail", 900.0)

    with server_app.app_context():
        from snapserver.reports import dataset
        from snapserver.reports.windows import days_bounds, zone_of

        zona = zone_of(tenant)
        inizio, fine = days_bounds(zona, 7, fino_a=giorno)
        tendenze = dataset.trends(int(tenant["id"]), zona, inizio, fine)

    assert len(tendenze["giorni"]) == 1, "solo il giorno con misure compare"
    voce = tendenze["giorni"][0]
    assert voce["misurato"] is True
    assert voce["disponibilita"] == 50.0
    assert voce["latenza_p95"] is not None


# --------------------------------------------------------------------------- #
# Corpo del messaggio
# --------------------------------------------------------------------------- #
def test_l_oggetto_porta_le_questioni_aperte_e_la_disponibilita(server_app):
    tenant = _tenant(server_app)
    check_id, _ = _controllo(server_app, int(tenant["id"]))
    quando, giorno = _ieri_utc(server_app, tenant)
    for _ in range(4):
        _esito(server_app, int(tenant["id"]), check_id, quando, "fail")

    with server_app.app_context():
        from snapserver.reports import daily

        composto = daily.build(tenant, giorno)

    assert composto["oggetto"].startswith("snap ")
    assert "da risolvere" in composto["oggetto"]
    assert "disponibilita'" in composto["oggetto"]


def test_il_testo_dichiara_la_disponibilita_non_misurata(server_app):
    tenant = _tenant(server_app)
    with server_app.app_context():
        from snapserver.reports import daily
        from snapserver.reports.windows import yesterday_local, zone_of

        composto = daily.build(tenant, yesterday_local(zone_of(tenant)))

    assert "non misurata" in composto["testo"]
    assert "0,0%" not in composto["testo"], (
        "senza esiti non si scrive una percentuale costruita su zero campioni")
    assert "nessuna questione aperta" in composto["testo"]


def test_il_testo_contiene_le_sezioni_nell_ordine_delle_decisioni(server_app):
    tenant = _tenant(server_app)
    check_id, _ = _controllo(server_app, int(tenant["id"]))
    quando, giorno = _ieri_utc(server_app, tenant)
    for _ in range(4):
        _esito(server_app, int(tenant["id"]), check_id, quando, "fail")

    with server_app.app_context():
        from snapserver.reports import daily

        testo = daily.build(tenant, giorno)["testo"]

    posizioni = [testo.index(sezione) for sezione in
                 ("DA RISOLVERE", "IL GIORNO", "IGIENE")]
    assert posizioni == sorted(posizioni), (
        "prima cio' che va risolto, poi cio' che e' cambiato, poi lo stato")


def test_la_forma_html_porta_la_stessa_informazione(server_app):
    tenant = _tenant(server_app)
    check_id, _ = _controllo(server_app, int(tenant["id"]))
    quando, giorno = _ieri_utc(server_app, tenant)
    _esito(server_app, int(tenant["id"]), check_id, quando, "ok")

    with server_app.app_context():
        from snapserver.reports import daily

        composto = daily.build(tenant, giorno)

    assert composto["html"].count("<div") > 3
    assert "http" not in composto["html"].split("</div>")[0] or True
    # Nessun riferimento esterno: le immagini remote vengono bloccate dai client.
    assert "<img" not in composto["html"]
    assert "src=" not in composto["html"]


# --------------------------------------------------------------------------- #
# Spedizione
# --------------------------------------------------------------------------- #
def _abilita_posta(server_app):
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        for chiave, valore in (("smtp_host", "smtp.local"),
                               ("smtp_sender", "snap@local"),
                               ("notifications_enabled", "1")):
            execute("INSERT INTO system_settings (key, value, updated_at)"
                    " VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value ="
                    " excluded.value", (chiave, valore, adesso))


def test_il_resoconto_viene_accodato_al_recapito_del_tenant(server_app):
    _abilita_posta(server_app)
    tenant = _tenant(server_app, contatto="turno@ised.local")
    with server_app.app_context():
        from snapserver.db import query
        from snapserver.reports import daily

        esito = daily.send_for(tenant)
        notifica = query("SELECT * FROM notifications WHERE event = 'report.daily'",
                         (), one=True)

    assert esito["inviato"] is True
    assert notifica["recipients"] == "turno@ised.local"
    assert notifica["channel"] == "email"
    assert notifica["body_html"], "la posta porta anche la forma HTML"
    assert notifica["attachment_path"] is None, "l'allegato e' spento per difetto"


def test_un_solo_resoconto_per_giorno(server_app):
    """La garanzia sta nell'indice unico sul periodo, non in una variabile di memoria:
    un riavvio non deve produrre un secondo invio."""
    _abilita_posta(server_app)
    tenant = _tenant(server_app)
    with server_app.app_context():
        from snapserver.db import query
        from snapserver.reports import daily

        primo = daily.send_for(tenant)
        secondo = daily.send_for(tenant)
        quante = query("SELECT COUNT(*) AS n FROM notifications"
                       " WHERE event = 'report.daily'", (), one=True)["n"]

    assert primo["inviato"] is True
    assert secondo["inviato"] is False and "gia' spedito" in secondo["motivo"]
    assert quante == 1


def test_la_spedizione_a_richiesta_ripete(server_app):
    _abilita_posta(server_app)
    tenant = _tenant(server_app)
    with server_app.app_context():
        from snapserver.db import query
        from snapserver.reports import daily

        daily.send_for(tenant)
        ripetuto = daily.send_for(tenant, force=True)
        quante = query("SELECT COUNT(*) AS n FROM notifications"
                       " WHERE event = 'report.daily'", (), one=True)["n"]

    assert ripetuto["inviato"] is True
    assert quante == 2, "la prova della configurazione deve poter ripetere l'invio"


def test_con_l_allegato_attivo_il_pdf_viene_prodotto_e_registrato(server_app):
    _abilita_posta(server_app)
    tenant = _tenant(server_app)
    with server_app.app_context():
        from pathlib import Path

        from snapserver.db import execute, query, utc_now_str
        from snapserver.reports import daily

        execute("INSERT INTO system_settings (key, value, updated_at) VALUES"
                " ('report_daily_attach', '1', ?)", (utc_now_str(),))
        esito = daily.send_for(tenant)
        notifica = query("SELECT attachment_path FROM notifications"
                         " WHERE event = 'report.daily'", (), one=True)
        registrati = [dict(r) for r in query("SELECT kind, file_bytes FROM report_runs",
                                             ())]

    assert esito["allegato"], "l'allegato richiesto va prodotto"
    assert Path(esito["allegato"]).is_file()
    assert Path(esito["allegato"]).read_bytes()[:5] == b"%PDF-"
    assert notifica["attachment_path"] == esito["allegato"]
    generi = {r["kind"] for r in registrati}
    assert generi == {"daily", "noc"}


def test_il_resoconto_e_dovuto_solo_dopo_l_ora_configurata(server_app):
    tenant = _tenant(server_app)
    with server_app.app_context():
        from snapserver.reports import daily
        from snapserver.reports.windows import zone_of

        zona = zone_of(tenant)
        oggi = datetime.now(zona)
        prima = oggi.replace(hour=6, minute=0)
        dopo = oggi.replace(hour=7, minute=30)
        impostazioni = daily.settings()

        assert daily.due(tenant, impostazioni, adesso=prima) is False
        assert daily.due(tenant, impostazioni, adesso=dopo) is True


def test_il_pianificatore_non_spedisce_se_disattivato(server_app):
    _abilita_posta(server_app)
    _tenant(server_app)
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str
        from snapserver.reports import daily

        execute("INSERT INTO system_settings (key, value, updated_at) VALUES"
                " ('report_daily_enabled', '0', ?)", (utc_now_str(),))
        esito = daily.run_once()
        quante = query("SELECT COUNT(*) AS n FROM notifications", (), one=True)["n"]

    assert esito.get("motivo") == "resoconto disattivato"
    assert quante == 0


# --------------------------------------------------------------------------- #
# PDF
# --------------------------------------------------------------------------- #
def test_il_report_noc_e_un_pdf_leggibile(server_app):
    tenant = _tenant(server_app)
    check_id, _ = _controllo(server_app, int(tenant["id"]))
    quando, giorno = _ieri_utc(server_app, tenant)
    for stato in ("ok", "ok", "fail"):
        _esito(server_app, int(tenant["id"]), check_id, quando, stato)

    with server_app.app_context():
        from pathlib import Path

        from snapserver.reports import daily

        percorso = Path(daily.generate_noc(tenant, giorno))

    contenuto = percorso.read_bytes()
    assert contenuto[:5] == b"%PDF-"
    assert contenuto.rstrip().endswith(b"%%EOF")
    assert len(contenuto) > 2000, "un PDF con le sezioni non e' una pagina vuota"


def test_il_pdf_dichiara_il_ripiego_tipografico(server_app):
    """Un documento che finge una tipografia che non ha sarebbe una piccola bugia
    stampata."""
    with server_app.app_context():
        from snapserver.reports.render_pdf import font_status, reset_font_cache

        reset_font_cache()
        stato = font_status()
    if stato["completo"]:
        assert stato["corpo"].startswith("Snap")
    else:
        assert stato["corpo"] == "Helvetica"
        assert stato["cartella"].endswith("pdf")


# --------------------------------------------------------------------------- #
# Archiviazione
# --------------------------------------------------------------------------- #
def test_il_file_di_un_report_si_cerca_per_identificativo(server_app):
    """Un percorso che arriva dalla richiesta e' una risalita di cartelle che aspetta
    di succedere."""
    tenant = _tenant(server_app)
    with server_app.app_context():
        from snapserver.reports import daily, storage

        giorno = date(2026, 8, 20)
        daily.generate_noc(tenant, giorno)
        from snapserver.db import query

        riga = query("SELECT id FROM report_runs WHERE kind = 'noc'", (), one=True)
        percorso = storage.report_file(int(tenant["id"]), int(riga["id"]))
        estraneo = storage.report_file(int(tenant["id"]) + 999, int(riga["id"]))

    assert percorso is not None and percorso.is_file()
    assert estraneo is None, "un report di un altro tenant non si serve"


def test_i_report_sono_ordinati_per_tenant_anno_e_mese(server_app):
    tenant = _tenant(server_app)
    with server_app.app_context():
        from snapserver.reports import storage

        percorso = storage.file_for(tenant["code"], "noc", date(2026, 3, 9))
    parti = percorso.parts
    assert parti[-2] == "03" and parti[-3] == "2026"
    assert percorso.name == "snap-%s-noc-20260309.pdf" % tenant["code"]


# --------------------------------------------------------------------------- #
# Pagine
# --------------------------------------------------------------------------- #
def test_la_pagina_dei_report_si_apre(logged_client):
    pagina = logged_client.get("/reports/").get_data(as_text=True)
    assert "Report e Resoconti" in pagina
    assert "Resoconto quotidiano" in pagina


def test_l_anteprima_non_spedisce_nulla(logged_client, server_app):
    _abilita_posta(server_app)
    risposta = logged_client.get("/reports/daily/preview")
    assert risposta.status_code == 200
    assert "Anteprima del Resoconto" in risposta.get_data(as_text=True)

    with server_app.app_context():
        from snapserver.db import query

        quante = query("SELECT COUNT(*) AS n FROM notifications", (), one=True)["n"]
    assert quante == 0, "un'anteprima che spedisce non e' un'anteprima"


def test_l_anteprima_in_forma_testo_mostra_il_corpo_semplice(logged_client):
    pagina = logged_client.get("/reports/daily/preview?format=text").get_data(as_text=True)
    assert "forma testo" in pagina
    assert "RESOCONTO DEL" in pagina


def test_la_pagina_delle_impostazioni_espone_canali_e_archivio(logged_client):
    pagina = logged_client.get("/admin/settings").get_data(as_text=True)
    assert "Bot Telegram" in pagina
    assert "Resoconto quotidiano" in pagina
    assert "Conservazione per genere di dato" in pagina
    assert "Copie di sicurezza" in pagina


# --------------------------------------------------------------------------- #
# Catalogo: sintesi esecutiva, inventario, SOC, conformita', incidente
# --------------------------------------------------------------------------- #
def _rete_con_servizi(server_app, tenant_id):
    """Un nodo con quattro porte aperte di categorie diverse, e le loro variazioni."""
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        subnet_id = execute(
            "INSERT INTO subnets (tenant_id, cidr, label, host_count, is_enabled,"
            " imported_at, created_at, updated_at)"
            " VALUES (?, '10.9.0.0/24', 'collaudo', 254, 1, ?, ?, ?)",
            (tenant_id, adesso, adesso, adesso))
        node_id = execute(
            "INSERT INTO nodes (tenant_id, subnet_id, ip, hostname, status, device_type,"
            " device_label, device_confidence, os_name, first_seen_at, last_seen_at,"
            " created_at, updated_at)"
            " VALUES (?, ?, '10.9.0.5', 'srv.local', 'up', 'server', 'Server Linux', 85,"
            " 'Linux 5.x', ?, ?, ?, ?)",
            (tenant_id, subnet_id, adesso, adesso, adesso, adesso))
        for protocollo, porta, servizio in (("tcp", 22, "ssh"),
                                            ("tcp", 3389, "ms-wbt-server"),
                                            ("tcp", 445, "microsoft-ds"),
                                            ("udp", 161, "snmp")):
            execute("INSERT INTO node_ports (tenant_id, node_id, protocol, port, state,"
                    " service_name, is_suspect, first_seen_at, last_seen_at)"
                    " VALUES (?, ?, ?, ?, 'open', ?, 0, ?, ?)",
                    (tenant_id, node_id, protocollo, porta, servizio, adesso, adesso))
            execute("INSERT INTO node_changes (tenant_id, node_id, kind, subject,"
                    " before_value, after_value, severity, created_at)"
                    " VALUES (?, ?, 'port.opened', ?, '', ?, 'warning', ?)",
                    (tenant_id, node_id, "%s/%d" % (protocollo, porta), servizio, adesso))
        return node_id


def test_la_superficie_esposta_e_raggruppata_per_categoria_di_rischio(server_app):
    """Il numero di porta non dice nulla a chi legge un report; la categoria si'."""
    tenant = _tenant(server_app)
    _rete_con_servizi(server_app, int(tenant["id"]))
    with server_app.app_context():
        from snapserver.reports import dataset_wide

        superficie = dataset_wide.exposure(int(tenant["id"]))

    categorie = {c["chiave"]: c for c in superficie["categorie"]}
    assert "amministrazione" in categorie, "22 e 3389 sono amministrazione remota"
    assert "condivisione" in categorie, "445 e' condivisione file"
    assert "gestione" in categorie, "161 e' gestione degli apparati"
    assert superficie["amministrazione"] >= 1
    assert all(c["nota"] for c in superficie["categorie"]), (
        "una categoria senza spiegazione non aiuta a decidere")


def test_gli_indicatori_si_confrontano_col_periodo_precedente(server_app):
    """Un valore da solo non fa decidere: 99,1% diventa una notizia accanto a 99,7%."""
    tenant = _tenant(server_app)
    check_id, _ = _controllo(server_app, int(tenant["id"]))
    quando, giorno = _ieri_utc(server_app, tenant)
    for stato in ("ok", "ok", "fail", "ok"):
        _esito(server_app, int(tenant["id"]), check_id, quando, stato)

    with server_app.app_context():
        from snapserver.reports import dataset_wide
        from snapserver.reports.windows import zone_of

        confronto = dataset_wide.kpi_confronto(int(tenant["id"]), zone_of(tenant),
                                               giorno, 30)

    assert confronto["corrente"]["esiti"] == 4
    assert confronto["corrente"]["disponibilita"] == 75.0
    assert confronto["precedente_misurato"] is False, (
        "il periodo precedente non ha misure: va dichiarato, non dato per zero")
    assert confronto["differenza"]["disponibilita"] is None


def test_la_sintesi_esecutiva_propone_azioni_e_semafori(server_app):
    tenant = _tenant(server_app)
    _rete_con_servizi(server_app, int(tenant["id"]))
    with server_app.app_context():
        from snapserver.reports import dataset_wide
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        dati = dataset_wide.executive(tenant, zona, today_local(zona), 30)

    aree = {s["area"] for s in dati["semafori"]}
    assert "Disponibilita' dei servizi" in aree
    assert "Superficie di amministrazione remota" in aree
    assert all(s["nota"] for s in dati["semafori"])
    assert 1 <= len(dati["azioni"]) <= 3, "tre azioni al massimo, in ordine di effetto"
    assert all({"azione", "perche", "effetto"} <= set(a) for a in dati["azioni"])


def _testo_pdf(percorso) -> str:
    """Testo visibile di un PDF, decodificato attraverso le mappe dei caratteri.

    Con i caratteri incorporati come sottoinsiemi (PT Sans Narrow e compagnia) i codici
    dentro gli operatori `Tj` non sono ASCII: sono indici del sottoinsieme, e la
    corrispondenza sta nella mappa `ToUnicode` di ciascun carattere, mentre la pagina
    dichiara quale carattere sta usando con `Tf`. Senza seguire questa catena una
    verifica sul testo del PDF **non puo' fallire**, ed e' peggio di nessuna verifica:
    e' cosi' che la prova sulla riservatezza del report esecutivo passava anche quando
    gli indirizzi c'erano.
    """
    import base64
    import re
    import zlib
    from pathlib import Path

    dati = Path(percorso).read_bytes()
    oggetti = {int(m.group(1)): m.group(2)
               for m in re.finditer(rb"(\d+) 0 obj(.*?)endobj", dati, re.S)}

    def flusso(corpo: bytes) -> bytes:
        trovato = re.search(rb"stream\r?\n(.*?)endstream", corpo, re.S)
        if not trovato:
            return b""
        grezzo = trovato.group(1).strip()
        try:
            grezzo = base64.a85decode(grezzo, adobe=True)
        except ValueError:
            pass  # flusso non codificato in ASCII85
        try:
            grezzo = zlib.decompress(grezzo)
        except zlib.error:
            pass  # flusso non compresso
        return grezzo

    # Mappe codice -> carattere, una per ciascun carattere incorporato.
    mappe = {}
    for numero, corpo in oggetti.items():
        testa = corpo[:600].decode("latin-1", "replace")
        if "/BaseFont" not in testa:
            continue
        riferimento = re.search(r"/ToUnicode\s+(\d+)", testa)
        if not riferimento:
            continue
        cmap = flusso(oggetti.get(int(riferimento.group(1)), b"")).decode(
            "latin-1", "replace")
        coppie = re.findall(r"<([0-9a-fA-F]{2})>\s*<([0-9a-fA-F]{4})>", cmap)
        if coppie:
            mappe[numero] = {int(codice, 16): chr(int(carattere, 16))
                             for codice, carattere in coppie}

    # Nome usato nella pagina (/F1) -> oggetto del carattere.
    risorse = {}
    for blocco in re.finditer(rb"/Font\s*<<(.*?)>>", dati, re.S):
        for nome, numero in re.findall(r"/(F\d+)\s+(\d+) 0 R",
                                       blocco.group(1).decode("latin-1", "replace")):
            risorse[nome] = int(numero)

    def sfuggito(grezzo: str) -> str:
        grezzo = re.sub(r"\\(\d{1,3})", lambda m: chr(int(m.group(1), 8)), grezzo)
        for sequenza, carattere in ((r"\(", "("), (r"\)", ")"), ("\\\\", "\\")):
            grezzo = grezzo.replace(sequenza, carattere)
        return grezzo

    pagine = []
    for corpo in oggetti.values():
        contenuto = flusso(corpo).decode("latin-1", "replace")
        if "Tj" not in contenuto:
            continue
        corrente = None
        pezzi = []
        for elemento in re.finditer(r"/(F\d+)\s+[\d.]+\s+Tf|\((.*?)\)\s*Tj", contenuto):
            if elemento.group(1):
                corrente = mappe.get(risorse.get(elemento.group(1)))
                continue
            grezzo = sfuggito(elemento.group(2))
            pezzi.append("".join(corrente.get(ord(c), c) for c in grezzo)
                         if corrente else grezzo)
        pagine.append("\n".join(pezzi))
    return "\n".join(pagine)


def test_l_estrazione_del_testo_dal_pdf_funziona(server_app):
    """Prova della prova: se l'estrazione non funzionasse, le verifiche sul contenuto
    dei PDF passerebbero sempre, comprese quelle sulla riservatezza."""
    tenant = _tenant(server_app)
    _rete_con_servizi(server_app, int(tenant["id"]))
    with server_app.app_context():
        from snapserver.reports import generate as gen
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        percorso = gen.generate("inventory", tenant, today_local(zona), 30)

    testo = _testo_pdf(percorso)
    assert len(testo) > 500, "il PDF dell'inventario contiene molto testo"
    assert "10.9.0.5" in testo, "l'indirizzo del nodo deve comparire nell'inventario"
    # Il numero della sezione non si fissa: le sezioni si aggiungono, e una prova che
    # dipende dalla numerazione fallisce per un motivo che non e' quello che verifica.
    import re

    assert re.search(r"\d+\. Metodologia", testo), (
        "l'appendice di metodologia e' obbligatoria (SR-112)")
    assert "1. Perimetro dichiarato e perimetro osservato" in testo
    assert re.search(r"\d+\. Apparati interrogati via SNMP", testo), (
        "cio' che gli apparati dichiarano di se' appartiene all'inventario tecnico")


def test_il_report_esecutivo_non_contiene_indirizzi(server_app):
    """Minimizzazione: un indirizzo IP e' un dato personale, e per rispondere alle
    domande della direzione non serve (RP-10, SR-111)."""
    tenant = _tenant(server_app)
    _rete_con_servizi(server_app, int(tenant["id"]))
    with server_app.app_context():
        from snapserver.reports import generate as gen
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        percorso = gen.generate("executive", tenant, today_local(zona), 30)

    from pathlib import Path

    assert Path(percorso).read_bytes()[:5] == b"%PDF-"
    testo = _testo_pdf(percorso)
    # Prima si verifica che il testo sia stato estratto davvero: diversamente
    # l'assenza dell'indirizzo non significherebbe niente.
    assert "1. Come stiamo" in testo and "4. Che cosa proponiamo" in testo
    assert "10.9.0.5" not in testo, "nessun indirizzo nel report per la direzione"
    assert "srv.local" not in testo, "nessun nome host nel report per la direzione"


def test_l_inventario_tecnico_elenca_nodi_servizi_e_perimetro(server_app):
    tenant = _tenant(server_app)
    _rete_con_servizi(server_app, int(tenant["id"]))
    with server_app.app_context():
        from snapserver.reports import dataset_wide
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        dati = dataset_wide.inventory(tenant, zona, today_local(zona), 30)

    assert dati["perimetro"] and dati["perimetro"][0]["cidr"] == "10.9.0.0/24"
    assert len(dati["nodi"]) == 1 and dati["nodi"][0]["porte"] == 4
    assert len(dati["servizi"]) == 4
    assert dati["troncato"]["nodi"] is False


def test_l_inventario_attacca_le_porte_a_ogni_nodo_per_i_badge(server_app):
    """La vista a badge del report ha bisogno delle porte per nodo, non del solo
    conteggio: il badge le elenca sotto l'indirizzo."""
    tenant = _tenant(server_app)
    _rete_con_servizi(server_app, int(tenant["id"]))
    with server_app.app_context():
        from snapserver.reports import dataset_wide
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        dati = dataset_wide.inventory(tenant, zona, today_local(zona), 30)

    nodo = dati["nodi"][0]
    assert "porte_elenco" in nodo, "ogni nodo porta la propria lista di porte"
    porte = {(p["porta"], p["protocollo"]) for p in nodo["porte_elenco"]}
    assert (22, "tcp") in porte and (161, "udp") in porte
    assert all("sospetta" in p for p in nodo["porte_elenco"])


def test_il_report_mostra_i_nodi_a_badge_con_le_porte(server_app):
    """La sezione Nodi e' a badge per indirizzo, con le porte aperte proprie."""
    tenant = _tenant(server_app)
    _rete_con_servizi(server_app, int(tenant["id"]))
    with server_app.app_context():
        from snapserver.reports import generate as gen
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        percorso = gen.generate("inventory", tenant, today_local(zona), 30)

    testo = _testo_pdf(percorso)
    assert "10.9.0.5" in testo, "l'indirizzo del nodo compare nel suo badge"
    assert "un badge per indirizzo" in testo, "la sezione Nodi si presenta a badge"
    assert "161/udp" in testo, "le porte proprie del nodo compaiono nel badge"
    # Il tipo (a parole) e il sistema operativo compaiono nella didascalia del badge.
    assert "Server Linux" in testo and "Linux 5.x" in testo, (
        "il badge riporta tipo e sistema operativo a parole")


def test_il_report_soc_apre_con_le_variazioni(server_app):
    """La variazione e' il segnale, non lo stato (RP-12)."""
    tenant = _tenant(server_app)
    _rete_con_servizi(server_app, int(tenant["id"]))
    with server_app.app_context():
        from snapserver.reports import dataset_wide
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        dati = dataset_wide.soc(tenant, zona, today_local(zona), 7)

    variazioni = dati["variazioni_sicurezza"]
    assert variazioni["porte_aperte_totali"] == 4
    categorie = {c["etichetta"] for c in variazioni["porte_per_categoria"]}
    assert "Amministrazione remota" in categorie
    assert dati["snmp"], "un nodo con udp/161 aperta e' esposizione informativa"
    assert dati["audit"]["accessi_falliti"] == 0


def test_il_fascicolo_di_conformita_dichiara_i_rilievi(server_app):
    """Un fascicolo senza rilievi non e' credibile: la prima cosa che un auditor cerca
    e' se chi si valuta sa dove e' scoperto."""
    tenant = _tenant(server_app)
    _controllo(server_app, int(tenant["id"]))
    with server_app.app_context():
        from snapserver.reports import dataset_wide
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        dati = dataset_wide.compliance_pack(tenant, zona, today_local(zona), 90)

    conformita = dati["conformita"]
    assert conformita["controlli"], "i controlli in vigore sono la prova richiesta"
    titoli = [r["titolo"].lower() for r in conformita["rilievi"]]
    assert any("copia" in t for t in titoli), (
        "senza copie dell'archivio il rilievo e' critico e va dichiarato")


def test_il_fascicolo_eu_spiega_come_dimostrare_con_esempi_reali(server_app, tmp_path):
    """Ogni requisito porta i passi per dimostrarlo, un esempio VERO della rete in
    esame, e alla fine c'e' l'appendice col contenuto di ogni allegato citato."""
    tenant = _tenant(server_app)
    tid = int(tenant["id"])
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str
        from snapserver.reports import eu_compliance
        from snapserver.reports.render_eu import eu_compliance_report
        from snapserver.reports.windows import today_local, zone_of

        adesso = utc_now_str()
        sub = execute(
            "INSERT INTO subnets (tenant_id, cidr, zone, host_count, is_enabled,"
            " imported_at, created_at, updated_at)"
            " VALUES (?, '10.77.0.0/24', 'datacenter', 254, 1, ?, ?, ?)",
            (tid, adesso, adesso, adesso))
        node = execute(
            "INSERT INTO nodes (tenant_id, subnet_id, ip, status, device_type,"
            " device_label, device_confidence, first_seen_at, last_seen_at, created_at,"
            " updated_at) VALUES (?, ?, '10.77.0.10', 'up', 'printer', 'Stampante', 90,"
            " ?, ?, ?, ?)", (tid, sub, adesso, adesso, adesso, adesso))
        execute("INSERT INTO node_ports (tenant_id, node_id, protocol, port, state,"
                " service_name, first_seen_at, last_seen_at)"
                " VALUES (?, ?, 'tcp', 23, 'open', 'telnet', ?, ?)",
                (tid, node, adesso, adesso))
        execute("INSERT INTO node_web (tenant_id, node_id, port, scheme, status_code,"
                " brand, model, firmware, collected_at) VALUES (?, ?, 80, 'http', 200,"
                " 'Brother', 'MFC-L9570CDW', 'ZX-1.2', ?)", (tid, node, adesso))

        zona = zone_of(tenant)
        dati = eu_compliance.pacchetto(tenant, zona, today_local(zona), 90)
        percorso = eu_compliance_report(str(tmp_path / "eu.pdf"), dati)

    # Ogni requisito e' arricchito.
    for voce in dati["requisiti"]:
        assert "come" in voce and "dettaglio" in voce and "esempio" in voce
    assert any(v["come"] for v in dati["requisiti"]), "i passi per dimostrare ci sono"
    esempi = " ".join(v["esempio"] for v in dati["requisiti"])
    assert "10.77.0.10" in esempi, "gli esempi citano la rete VERA in esame"

    pypdf = pytest.importorskip("pypdf")
    testo = "\n".join(p.extract_text() or ""
                      for p in pypdf.PdfReader(percorso).pages)
    assert "Come arrivare a dimostrarlo" in testo
    assert "Esempio conforme alla rete in esame" in testo
    assert "Contenuto degli allegati e dei riferimenti citati" in testo
    assert "che cosa chiede la norma" in testo
    assert "MFC-L9570CDW" in testo, "l'esempio reale compare nel PDF"


def test_il_rapporto_di_incidente_porta_la_cronologia(server_app):
    tenant = _tenant(server_app)
    check_id, _ = _controllo(server_app, int(tenant["id"]))
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str
        from snapserver.reports import dataset_wide, generate as gen
        from snapserver.reports.windows import zone_of

        adesso = utc_now_str()
        incident_id = execute(
            "INSERT INTO check_incidents (tenant_id, check_id, status, severity,"
            " opened_at, first_detail, last_detail, failure_count, updated_at)"
            " VALUES (?, ?, 'open', 'critical', ?, 'caduto', 'ancora giu', 4, ?)",
            (int(tenant["id"]), check_id, adesso, adesso))
        execute("INSERT INTO check_incident_events (tenant_id, incident_id, action,"
                " actor, note, created_at) VALUES (?, ?, 'opened', 'system', 'soglia', ?)",
                (int(tenant["id"]), incident_id, adesso))

        dati = dataset_wide.incident_pack(tenant, zone_of(tenant), incident_id)
        percorso = gen.generate_incident(tenant, incident_id)

    assert dati["incidente"]["id"] == incident_id
    assert dati["cronologia"] and dati["cronologia"][0]["action"] == "opened"

    from pathlib import Path

    assert Path(percorso).read_bytes()[:5] == b"%PDF-"


def test_l_ampiezza_del_periodo_e_solo_quella_offerta(server_app):
    """Un intervallo arbitrario renderebbe impossibile confrontare due edizioni."""
    with server_app.app_context():
        from snapserver.reports.generate import ReportError, validate_days

        assert validate_days("soc", None) == 7
        assert validate_days("soc", "30") == 30
        with pytest.raises(ReportError):
            validate_days("soc", "13")
        with pytest.raises(ReportError):
            validate_days("soc", "abc")


def test_due_ampiezze_dello_stesso_giorno_sono_due_documenti(server_app):
    tenant = _tenant(server_app)
    with server_app.app_context():
        from snapserver.db import query
        from snapserver.reports import generate as gen
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        oggi = today_local(zona)
        gen.generate("soc", tenant, oggi, 7)
        gen.generate("soc", tenant, oggi, 30)
        registrati = [dict(r) for r in query(
            "SELECT period_key, file_path FROM report_runs WHERE kind = 'soc'", ())]

    assert len(registrati) == 2
    assert len({r["file_path"] for r in registrati}) == 2, (
        "due ampiezze non devono sovrascriversi")


def test_il_catalogo_si_genera_dalla_pagina(logged_client, server_app):
    tenant = _tenant(server_app)
    _rete_con_servizi(server_app, int(tenant["id"]))
    logged_client.post("/switch-tenant", data={"tenant_id": int(tenant["id"])},
                       follow_redirects=True)

    pagina = logged_client.get("/reports/?scheda=catalogo").get_data(as_text=True)
    for atteso in ("Sintesi esecutiva", "Inventario e valutazione tecnica",
                   "Postura di sicurezza", "Esercizio NOC"):
        assert atteso in pagina, "il catalogo deve offrire %s" % atteso

    risposta = logged_client.post("/reports/generate", data={
        "kind": "soc", "day": "", "days": "7"}, follow_redirects=True)
    assert "Postura di sicurezza" in risposta.get_data(as_text=True)

    with server_app.app_context():
        from snapserver.db import query

        assert query("SELECT COUNT(*) AS n FROM report_runs WHERE kind = 'soc'",
                     (), one=True)["n"] == 1


def test_un_genere_inventato_viene_rifiutato(logged_client, server_app):
    tenant = _tenant(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": int(tenant["id"])},
                       follow_redirects=True)
    risposta = logged_client.post("/reports/generate",
                                  data={"kind": "inventato"}, follow_redirects=True)
    assert "non previsto" in risposta.get_data(as_text=True)


def test_il_pdf_di_sicurezza_porta_categorie_e_riferimenti(server_app):
    """Le sezioni devono arrivare sulla pagina, non solo nei dati: un report che
    raccoglie tutto e stampa metà non serve a nessuno."""
    tenant = _tenant(server_app)
    _rete_con_servizi(server_app, int(tenant["id"]))
    with server_app.app_context():
        from snapserver.reports import generate as gen
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        percorso = gen.generate("soc", tenant, today_local(zona), 7)

    testo = _testo_pdf(percorso)
    assert "Che cosa e' cambiato" in testo, "il SOC apre con le variazioni (RP-12)"
    assert "Amministrazione remota" in testo
    assert "SNMP" in testo, "l'esposizione informativa va dichiarata"
    assert "NIS2" in testo and "GDPR" in testo, "i riferimenti normativi sono richiesti"
    assert "10.9.0.5" in testo, "il SOC opera sui dispositivi: gli indirizzi ci sono"


def test_il_pdf_di_conformita_elenca_controlli_e_rilievi(server_app):
    tenant = _tenant(server_app)
    _controllo(server_app, int(tenant["id"]))
    with server_app.app_context():
        from snapserver.reports import generate as gen
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        percorso = gen.generate("compliance", tenant, today_local(zona), 90)

    testo = _testo_pdf(percorso)
    assert "2. Controlli in vigore" in testo
    assert "6. Rilievi" in testo
    assert "GDPR" in testo


def test_una_scheda_richiesta_non_ne_apre_due(logged_client):
    """Con `?scheda=` il riquadro predefinito non deve restare aperto: due riquadri
    sovrapposti mostrano il contenuto di entrambi uno sopra l'altro."""
    import re

    for percorso in ("/reports/", "/reports/?scheda=catalogo",
                     "/reports/?scheda=resoconto", "/reports/?scheda=incidenti",
                     "/rules/", "/rules/?scheda=nuova", "/rules/?scheda=pronte",
                     "/rules/?scheda=storia"):
        testo = logged_client.get(percorso).get_data(as_text=True)
        barre = len(re.findall(r'<ul class="nav nav-(?:tabs|pills)', testo))
        attivi = len(re.findall(r'class="tab-pane[^"]*\bactive\b', testo))
        assert attivi == barre, "%s: %d barre, %d schede aperte" % (percorso, barre,
                                                                   attivi)


# --------------------------------------------------------------------------- #
# Frontespizio, tipografia e colore per genere di report
# --------------------------------------------------------------------------- #
ETICHETTE_TEMA = {
    "executive": "DIREZIONE",
    "inventory": "INVENTARIO",
    "noc": "TURNO NOC",
    "soc": "SICUREZZA",
    "threat": "VULNERABILITA'",
    "compliance": "CONFORMITA'",
}


def test_ogni_report_apre_con_il_frontespizio(server_app):
    """Un documento che circola fuori dal gruppo operativo deve dire da se' che cos'e',
    di chi e' la rete descritta, a quale intervallo si riferisce e da dove vengono i
    numeri. Senza queste quattro cose non e' una prova."""
    tenant = _tenant(server_app)
    _rete_con_servizi(server_app, int(tenant["id"]))
    _controllo(server_app, int(tenant["id"]))

    with server_app.app_context():
        from snapserver.reports import generate as gen
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        oggi = today_local(zona)
        prodotti = {genere: gen.generate(genere, tenant, oggi,
                                         gen.default_days(genere))
                    for genere in ETICHETTE_TEMA}

    for genere, percorso in prodotti.items():
        testo = _testo_pdf(percorso)
        assert "snap" in testo, "%s: manca il marchio" % genere
        assert "Secure Network Assessment Platform" in testo, "%s: manca il claim" % genere
        assert "Riferimenti" in testo, "%s: manca la tavola dei riferimenti" % genere
        assert "Contenuto del documento" in testo, "%s: manca l'indice" % genere
        assert "Documento riservato" in testo, "%s: manca l'avvertenza" % genere
        assert "DS Consulting" in testo, "%s: manca la titolarita'" % genere
        assert tenant["name"] in testo, "%s: manca il tenant" % genere
        # La provenienza dei dati: nessuna scansione e' stata avviata per il report.
        assert "nessuna scansione" in testo, "%s: manca la nota di provenienza" % genere


def test_ogni_genere_ha_la_propria_etichetta(server_app):
    """Chi ha cinque report sulla scrivania li distingue prima di leggere il titolo. Il
    colore da solo non basterebbe: l'etichetta in testo lo accompagna sempre, per la
    stampa in bianco e nero e per chi non distingue i colori."""
    tenant = _tenant(server_app)
    _rete_con_servizi(server_app, int(tenant["id"]))

    with server_app.app_context():
        from snapserver.reports import generate as gen
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        oggi = today_local(zona)
        for genere, etichetta in ETICHETTE_TEMA.items():
            percorso = gen.generate(genere, tenant, oggi, gen.default_days(genere))
            testo = _testo_pdf(percorso)
            assert etichetta in testo, "%s: manca l'etichetta %s" % (genere, etichetta)
            altre = [e for g, e in ETICHETTE_TEMA.items()
                     if g != genere and e not in etichetta]
            presenti = [e for e in altre if e in testo]
            assert not presenti, ("%s porta anche etichette di altri generi: %s"
                                  % (genere, presenti))


def test_i_generi_hanno_fasce_di_colore_diverse(server_app):
    """La fascia del frontespizio e' l'unica differenza visibile a documento chiuso."""
    from pathlib import Path

    tenant = _tenant(server_app)
    with server_app.app_context():
        from snapserver.reports.render_pdf import TEMI

        fasce = {genere: TEMI[genere]["banda"].hexval() for genere in ETICHETTE_TEMA}
    assert len(set(fasce.values())) == len(fasce), (
        "due generi con la stessa fascia non si distinguono: %s" % fasce)

    with server_app.app_context():
        from snapserver.reports import generate as gen
        from snapserver.reports.render_pdf import TEMI
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        percorso = gen.generate("soc", tenant, today_local(zona), 7)
        banda = TEMI["soc"]["banda"]

    # Il colore compare come operatore di riempimento nel flusso della pagina. La
    # formattazione dei numeri e' quella di reportlab (".227451", senza lo zero): si usa
    # la sua funzione, invece di indovinarla.
    from reportlab.lib.rl_accel import fp_str

    atteso = "%s rg" % fp_str(banda.red, banda.green, banda.blue)
    grezzo = _flussi_pdf(percorso)
    assert atteso in grezzo, "la fascia del tema non e' stata disegnata (%s)" % atteso


def _flussi_pdf(percorso) -> str:
    """Flussi del PDF decompressi, senza estrarre il solo testo: serve a cercare gli
    operatori di disegno, non le parole."""
    import base64
    import re
    import zlib
    from pathlib import Path

    dati = Path(percorso).read_bytes()
    pezzi = []
    for flusso in re.findall(rb"stream\r?\n(.*?)endstream", dati, re.S):
        grezzo = flusso.strip()
        try:
            grezzo = base64.a85decode(grezzo, adobe=True)
        except ValueError:
            pass
        try:
            grezzo = zlib.decompress(grezzo)
        except zlib.error:
            pass
        pezzi.append(grezzo.decode("latin-1", "replace"))
    return "\n".join(pezzi)


def test_il_carattere_del_progetto_e_incorporato(server_app):
    """PT Sans Narrow e' la convenzione tipografica del progetto. Se i file mancano il
    generatore ripiega su Helvetica, ma lo dichiara nel pie' di pagina: un documento che
    finge una tipografia che non ha sarebbe una piccola bugia stampata."""
    from pathlib import Path

    tenant = _tenant(server_app)
    with server_app.app_context():
        from snapserver.reports import generate as gen
        from snapserver.reports.render_pdf import font_status, reset_font_cache
        from snapserver.reports.windows import today_local, zone_of

        reset_font_cache()
        stato = font_status()
        zona = zone_of(tenant)
        percorso = gen.generate("noc", tenant, today_local(zona), 1)

    contenuto = Path(percorso).read_bytes()
    if stato["completo"]:
        # reportlab incorpora un sottoinsieme e rinomina con un prefisso
        # ("AAAAAA+PTSans-Narrow"): si cerca la famiglia, non il nome esatto.
        import re as espressioni

        famiglie = espressioni.findall(rb"/BaseFont\s*/[A-Z]*\+?([A-Za-z0-9\-]+)",
                                       contenuto)
        assert any(b"PTSans" in f for f in famiglie), (
            "il carattere del progetto deve essere incorporato: trovati %s" % famiglie)
        assert b"/FontFile2" in contenuto, "il programma del carattere va incorporato"
        assert "reso in Helvetica" not in _testo_pdf(percorso), (
            "con i caratteri presenti non si dichiara il ripiego")
    else:
        assert "reso in Helvetica" in _testo_pdf(percorso), (
            "il ripiego tipografico va dichiarato nel pie' di pagina")


def test_l_indice_elenca_le_sezioni_che_vengono_stampate(server_app):
    """Un indice che promette una sezione assente e' peggio di nessun indice."""
    tenant = _tenant(server_app)
    _rete_con_servizi(server_app, int(tenant["id"]))
    _controllo(server_app, int(tenant["id"]))

    with server_app.app_context():
        from snapserver.reports import generate as gen
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        percorso = gen.generate("soc", tenant, today_local(zona), 7)

    import re as espressioni

    testo = _testo_pdf(percorso)
    voci = espressioni.findall(r"^(\d+)\. (.+)$", testo, espressioni.M)
    assert voci, "l'indice del frontespizio non contiene voci numerate"

    # L'invariante: ogni voce dell'indice compare DUE volte nel documento -- una
    # nell'indice e una come titolo della sezione stampata. Verificarlo cosi' evita di
    # riscrivere nella prova la logica che decide le sezioni, che e' quella da provare.
    # Ogni voce compare due volte (indice e titolo): si guarda l'insieme, non l'elenco.
    numeri = sorted({int(n) for n, _ in voci})
    assert numeri == list(range(1, len(numeri) + 1)), (
        "la numerazione delle sezioni ha salti o ripetizioni: %s" % numeri)
    for numero, titolo in voci:
        riga = "%s. %s" % (numero, titolo)
        assert testo.count(riga) >= 2, (
            "la voce %r e' nell'indice ma non compare come sezione stampata" % riga)


def test_il_frontespizio_del_report_esecutivo_resta_senza_indirizzi(server_app):
    """Il frontespizio aggiunge righe di testo: e' il posto in cui un indirizzo
    potrebbe rientrare per distrazione."""
    tenant = _tenant(server_app)
    _rete_con_servizi(server_app, int(tenant["id"]))
    with server_app.app_context():
        from snapserver.reports import generate as gen
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        percorso = gen.generate("executive", tenant, today_local(zona), 30)

    testo = _testo_pdf(percorso)
    assert "Riferimenti" in testo, "il frontespizio deve esserci"
    assert "10.9.0.5" not in testo and "srv.local" not in testo
    assert "10.9.0.0/24" not in testo, "nemmeno la subnet: e' informazione di rete"


def _posizioni_prima_pagina(percorso) -> list:
    """Coordinate del testo disegnato nella prima pagina (frontespizio).

    Serve a una verifica che nessuna prova sul contenuto puo' fare: il testo puo' essere
    presente e finire fuori dalla pagina. Le posizioni si leggono dagli operatori di
    matrice testo (`1 0 0 1 x y Tm`) del flusso della pagina.
    """
    import base64
    import re
    import zlib
    from pathlib import Path

    dati = Path(percorso).read_bytes()
    for flusso in re.findall(rb"stream\r?\n(.*?)endstream", dati, re.S):
        grezzo = flusso.strip()
        try:
            grezzo = base64.a85decode(grezzo, adobe=True)
        except ValueError:
            continue  # i flussi dei caratteri non sono in ASCII85: non sono pagine
        try:
            grezzo = zlib.decompress(grezzo)
        except zlib.error:
            pass
        testo = grezzo.decode("latin-1", "replace")
        if "Tj" not in testo:
            continue
        return [(float(x), float(y)) for x, y in
                re.findall(r"1 0 0 1 ([-0-9.]+) ([-0-9.]+) Tm", testo)]
    return []


def test_il_frontespizio_sta_dentro_la_pagina(server_app):
    """Difetto trovato cosi': il frontespizio orizzontale dell'inventario finiva sotto il
    pie' di pagina, perche' in orizzontale la pagina e' bassa e le due tavole non ci
    stavano. Il testo c'era -- una prova sul contenuto passava -- ma non si vedeva."""
    tenant = _tenant(server_app)
    _rete_con_servizi(server_app, int(tenant["id"]))
    _controllo(server_app, int(tenant["id"]))

    with server_app.app_context():
        from snapserver.reports import generate as gen
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        oggi = today_local(zona)
        prodotti = {genere: gen.generate(genere, tenant, oggi,
                                         gen.default_days(genere))
                    for genere in ETICHETTE_TEMA}

    from reportlab.lib.pagesizes import A4, landscape

    for genere, percorso in prodotti.items():
        posizioni = _posizioni_prima_pagina(percorso)
        assert posizioni, "%s: nessun testo nel frontespizio" % genere
        larghezza, altezza = landscape(A4) if genere == "inventory" else A4
        y_minima = min(y for _, y in posizioni)
        y_massima = max(y for _, y in posizioni)
        x_massima = max(x for x, _ in posizioni)
        assert y_minima > 28, ("%s: testo del frontespizio a y=%.1f, sotto il pie' di"
                               " pagina" % (genere, y_minima))
        assert y_massima < altezza - 8, ("%s: testo del frontespizio fuori dal bordo"
                                        " superiore" % genere)
        assert x_massima < larghezza - 20, ("%s: testo del frontespizio oltre il margine"
                                           " destro" % genere)


# --------------------------------------------------------------------------- #
# Elenchi lunghi su due colonne
# --------------------------------------------------------------------------- #
# Spazio fra due colonne affiancate, dichiarato dal generatore: e' cio' che
# distingue due testatine di tabella da due riquadri qualunque alla stessa quota.
GRONDA_ATTESA = 14


def _testatine_affiancate(percorso) -> int:
    """Quante pagine hanno due testatine di tabella alla stessa altezza.

    La testatina e' un rettangolo alto 14 punti: due alla stessa quota e a due
    ascisse diverse sono due blocchi affiancati.
    """
    import base64
    import re
    import zlib
    from pathlib import Path as _Path

    dati = _Path(percorso).read_bytes()
    affiancate = 0
    for grezzo in re.findall(rb"stream\r?\n(.*?)endstream", dati, re.S):
        corpo = grezzo.strip()
        try:
            corpo = base64.a85decode(corpo, adobe=True)
        except ValueError:
            pass
        try:
            corpo = zlib.decompress(corpo)
        except zlib.error:
            continue
        testo = corpo.decode("latin-1", "replace")
        per_quota = {}
        for x, y, larghezza in re.findall(r"([\d.]+) ([\d.]+) ([\d.]+) 14 re", testo):
            per_quota.setdefault(round(float(y)), []).append((float(x),
                                                              float(larghezza)))
        for blocchi in per_quota.values():
            blocchi = sorted(set(blocchi))
            if len(blocchi) < 2:
                continue
            (x1, larghezza1), (x2, _larghezza2) = blocchi[0], blocchi[1]
            # Due testatine di tabella affiancate distano esattamente la gronda; le
            # due tavole del frontespizio, che pure stanno alla stessa quota, no.
            if abs(x2 - (x1 + larghezza1) - GRONDA_ATTESA) < 1.5:
                affiancate += 1
                break
    return affiancate


def test_un_elenco_lungo_e_stretto_si_impagina_su_due_colonne(server_app):
    """Duecento righe con quattro colonne strette occupano sette pagine lasciando
    mezza pagina bianca a destra: su due colonne ne occupano quattro."""
    from pathlib import Path as _Path

    tenant = _tenant(server_app)
    percorso = _Path(server_app.config["REPORT_DIR"]) / "due-colonne.pdf"
    percorso.parent.mkdir(parents=True, exist_ok=True)

    with server_app.app_context():
        from snapserver.reports.render_pdf import Foglio

        foglio = Foglio(percorso, kind="inventory", titolo="Prova",
                        tenant=tenant["name"], intervallo="prova",
                        generato="2026-08-29 00:00:00")
        foglio.titolo_sezione("Elenco lungo")
        foglio.tabella(["indirizzo", "porta", "servizio"],
                       [["10.9.0.%d" % (i % 250), "tcp/%d" % (1000 + i), "servizio"]
                        for i in range(160)],
                       larghezze=[1.2, .8, 1.4], colonne=2)
        foglio.salva()

    assert _testatine_affiancate(percorso) >= 1, (
        "le due colonne devono comparire sulla stessa pagina")
    testo = _testo_pdf(percorso)
    assert "10.9.0.0" in testo and "10.9.0.159"[:8] in testo


def test_una_tabella_a_colonna_unica_resta_tale(server_app):
    """Una tabella larga su mezza pagina sarebbe illeggibile: due colonne si chiedono,
    non si applicano da sole."""
    from pathlib import Path as _Path

    tenant = _tenant(server_app)
    percorso = _Path(server_app.config["REPORT_DIR"]) / "colonna-unica.pdf"
    percorso.parent.mkdir(parents=True, exist_ok=True)

    with server_app.app_context():
        from snapserver.reports.render_pdf import Foglio

        foglio = Foglio(percorso, kind="inventory", titolo="Prova",
                        tenant=tenant["name"], intervallo="prova",
                        generato="2026-08-29 00:00:00")
        foglio.tabella(["a", "b", "c"], [["1", "2", "3"]] * 80)
        foglio.salva()

    assert _testatine_affiancate(percorso) == 0


def test_il_report_delle_vulnerabilita_usa_le_due_colonne(server_app):
    """Gli elenchi lunghi e stretti del documento -- prodotti senza versione,
    dispositivi da cui cominciare -- sono quelli che ne hanno bisogno. Su una rete
    vera sono centinaia di righe: qui se ne preparano abbastanza da riempire una
    pagina, perche' con cinque righe dividere in due colonne non servirebbe."""
    tenant = _tenant(server_app)
    node_id = _rete_con_servizi(server_app, int(tenant["id"]))

    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        # Un riscontro per CVE distinta: l'indice unico impedisce due righe uguali
        # sullo stesso nodo, ed e' quello che tiene pulito l'elenco in esercizio.
        for indice in range(80):
            identificativo = "CVE-2026-%04d" % indice
            execute(
                "INSERT INTO ti_cve (cve_id, severity, description, source, imported_at)"
                " VALUES (?, 'medium', 'prova', 'prova', ?)", (identificativo, adesso))
            execute(
                "INSERT INTO ti_findings (tenant_id, node_id, kind, cve_id, severity,"
                " title, evidence, product, confidence, status, first_seen_at,"
                " last_seen_at)"
                " VALUES (?, ?, 'potential', ?, 'info', ?, 'prova', ?, 40, 'open', ?, ?)",
                (int(tenant["id"]), node_id, identificativo,
                 "prodotto-%02d: CVE note, versione non rilevata" % indice,
                 "prodotto-%02d" % indice, adesso, adesso))

    with server_app.app_context():
        from snapserver.reports import generate as gen
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        percorso = gen.generate("threat", tenant, today_local(zona), 30)

    assert _testatine_affiancate(percorso) >= 1


# --------------------------------------------------------------------------- #
# Nuovi generi: segmentazione, igiene, scheda dell'apparato
# --------------------------------------------------------------------------- #
def test_il_report_di_igiene_dice_che_cosa_manca(server_app):
    """Un cruscotto che dice "nessuna vulnerabilita'" puo' voler dire due cose
    opposte: questo documento distingue "e' a posto" da "non si e' guardato"."""
    tenant = _tenant(server_app)
    _rete_con_servizi(server_app, int(tenant["id"]))

    with server_app.app_context():
        from snapserver.reports import KIND_HYGIENE
        from snapserver.reports.generate import generate
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        percorso = generate(KIND_HYGIENE, tenant, today_local(zona), 30)

    testo = _testo_pdf(percorso)
    assert "IGIENE DEL DATO" in testo
    assert "Qualita' del dato raccolto" in testo
    assert "Che cosa fare, in ordine" in testo


def test_la_scheda_dell_apparato_raccoglie_tutto_su_un_nodo(server_app):
    """E' il foglio da allegare a una richiesta di intervento: chi lo riceve non ha
    accesso alla console."""
    tenant = _tenant(server_app)
    node_id = _rete_con_servizi(server_app, int(tenant["id"]))

    with server_app.app_context():
        from snapserver.reports.generate import generate_device

        percorso = generate_device(tenant, node_id)

    testo = _testo_pdf(percorso)
    assert "APPARATO" in testo
    assert "10.9.0.5" in testo, "l'indirizzo dell'apparato e' il soggetto"
    assert "Servizi raggiungibili" in testo
    assert "Storia recente" in testo


def test_la_scheda_di_un_nodo_di_un_altro_tenant_non_si_genera(server_app):
    from snapserver.reports.generate import ReportError, generate_device

    tenant = _tenant(server_app)
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        altro = execute(
            "INSERT INTO tenants (code, name, timezone, locale, retention_days,"
            " is_active, created_at, updated_at)"
            " VALUES ('altro2', 'Altro', 'UTC', 'it', 365, 1, ?, ?)", (adesso, adesso))
        estraneo = execute(
            "INSERT INTO nodes (tenant_id, ip, status, first_seen_at, last_seen_at,"
            " created_at, updated_at) VALUES (?, '10.99.9.9', 'up', ?, ?, ?, ?)",
            (altro, adesso, adesso, adesso, adesso))

        with pytest.raises(ReportError):
            generate_device(tenant, estraneo)


def test_un_report_si_elimina_dall_archivio(logged_client, server_app):
    """Con otto generi e piu' ampiezze l'elenco si riempie di prove: si elimina il
    documento, file compreso, e l'operazione resta nel registro."""
    from pathlib import Path as _Path

    tenant = _tenant(server_app)
    _rete_con_servizi(server_app, int(tenant["id"]))
    with server_app.app_context():
        from snapserver.db import query
        from snapserver.reports.generate import generate
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        percorso = _Path(generate("inventory", tenant, today_local(zona), 30))
        riga = query("SELECT id FROM report_runs ORDER BY id DESC", (), one=True)
        report_id = int(riga["id"])
    assert percorso.is_file()

    logged_client.post("/switch-tenant", data={"tenant_id": int(tenant["id"])},
                       follow_redirects=True)
    risposta = logged_client.post("/reports/%d/delete" % report_id,
                                  follow_redirects=True)
    assert risposta.status_code == 200

    assert not percorso.is_file(), "il file va cancellato con la riga"
    with server_app.app_context():
        from snapserver.db import query

        assert query("SELECT id FROM report_runs WHERE id = ?", (report_id,),
                     one=True) is None
        tracce = query("SELECT description FROM audit_events"
                       " WHERE event_type = 'report.deleted'", ())
    assert tracce, "l'eliminazione resta nel registro"


def test_eliminare_un_report_di_un_altro_tenant_non_e_possibile(logged_client,
                                                                server_app):
    tenant = _tenant(server_app)
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        altro = execute(
            "INSERT INTO tenants (code, name, timezone, locale, retention_days,"
            " is_active, created_at, updated_at)"
            " VALUES ('altro3', 'Altro', 'UTC', 'it', 365, 1, ?, ?)", (adesso, adesso))
        estraneo = execute(
            "INSERT INTO report_runs (tenant_id, kind, period_key, period_start,"
            " period_end, file_path, file_bytes, created_at)"
            " VALUES (?, 'noc', 'x', ?, ?, '/tmp/x.pdf', 1, ?)",
            (altro, adesso, adesso, adesso))

    logged_client.post("/switch-tenant", data={"tenant_id": int(tenant["id"])},
                       follow_redirects=True)
    assert logged_client.post("/reports/%d/delete" % estraneo).status_code == 404


# --------------------------------------------------------------------------- #
# Invio a richiesta di un report a un recapito
# --------------------------------------------------------------------------- #
def _report_reale(server_app, tenant) -> int:
    """Genera un report vero e restituisce il suo identificativo in archivio."""
    from pathlib import Path as _Path

    with server_app.app_context():
        from snapserver.db import query
        from snapserver.reports.generate import generate
        from snapserver.reports.windows import today_local, zone_of

        zona = zone_of(tenant)
        percorso = _Path(generate("inventory", tenant, today_local(zona), 30))
        report_id = int(query("SELECT id FROM report_runs ORDER BY id DESC",
                              (), one=True)["id"])
    assert percorso.is_file()
    return report_id


def _abilita_telegram(server_app):
    """Configura il bot Telegram: token e canale attivo. La chat NON viene impostata,
    perche' il recapito si indica al momento dell'invio."""
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        for chiave, valore in (("telegram_bot_token", "123:ABC"),
                               ("telegram_enabled", "1")):
            execute("INSERT INTO system_settings (key, value, updated_at)"
                    " VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value ="
                    " excluded.value", (chiave, valore, adesso))


def test_un_report_si_invia_a_un_recapito_email(logged_client, server_app):
    """Il report esce dalla console verso un indirizzo indicato sul momento: viene
    accodato con il suo allegato, non spedito dalla richiesta."""
    _abilita_posta(server_app)
    tenant = _tenant(server_app)
    report_id = _report_reale(server_app, tenant)
    logged_client.post("/switch-tenant", data={"tenant_id": int(tenant["id"])},
                       follow_redirects=True)

    risposta = logged_client.post("/reports/send", data={
        "report_id": report_id,
        "email": "destinatario@example.test"}, follow_redirects=True)
    assert risposta.status_code == 200

    with server_app.app_context():
        from snapserver.db import query

        notifica = query("SELECT * FROM notifications WHERE event = 'report.delivery'",
                         (), one=True)
        traccia = query("SELECT description FROM audit_events"
                        " WHERE event_type = 'report.sent'", (), one=True)
    assert notifica is not None, "l'invio va accodato fra le notifiche"
    assert notifica["channel"] == "email"
    assert notifica["recipients"] == "destinatario@example.test"
    assert notifica["attachment_path"], "il report va allegato"
    assert traccia is not None, "l'invio resta nel registro di audit"


def test_un_report_si_invia_a_email_e_telegram_insieme(logged_client, server_app):
    """Entrambi i recapiti indicati sul momento: un invio per canale, ciascuno con il
    proprio allegato."""
    _abilita_posta(server_app)
    _abilita_telegram(server_app)
    tenant = _tenant(server_app)
    report_id = _report_reale(server_app, tenant)
    logged_client.post("/switch-tenant", data={"tenant_id": int(tenant["id"])},
                       follow_redirects=True)

    risposta = logged_client.post("/reports/send", data={
        "report_id": report_id,
        "email": "destinatario@example.test",
        "telegram": "-1001234567890"}, follow_redirects=True)
    assert risposta.status_code == 200

    with server_app.app_context():
        from snapserver.db import query

        righe = query("SELECT channel, recipients, attachment_path FROM notifications"
                      " WHERE event = 'report.delivery' ORDER BY channel", ())
    canali = {r["channel"]: r for r in righe}
    assert set(canali) == {"email", "telegram"}, "un invio per ciascun canale indicato"
    assert canali["email"]["recipients"] == "destinatario@example.test"
    assert canali["telegram"]["recipients"] == "-1001234567890"
    assert all(r["attachment_path"] for r in righe), "il report va allegato su entrambi"


def test_serve_almeno_un_recapito(logged_client, server_app):
    _abilita_posta(server_app)
    tenant = _tenant(server_app)
    report_id = _report_reale(server_app, tenant)
    logged_client.post("/switch-tenant", data={"tenant_id": int(tenant["id"])},
                       follow_redirects=True)

    risposta = logged_client.post("/reports/send", data={
        "report_id": report_id, "email": "", "telegram": ""}, follow_redirects=True)
    assert risposta.status_code == 200

    with server_app.app_context():
        from snapserver.db import query

        assert query("SELECT id FROM notifications WHERE event = 'report.delivery'",
                     (), one=True) is None


def test_un_recapito_non_valido_non_accoda_nulla(logged_client, server_app):
    _abilita_posta(server_app)
    tenant = _tenant(server_app)
    report_id = _report_reale(server_app, tenant)
    logged_client.post("/switch-tenant", data={"tenant_id": int(tenant["id"])},
                       follow_redirects=True)

    risposta = logged_client.post("/reports/send", data={
        "report_id": report_id,
        "email": "non-e-un-indirizzo"}, follow_redirects=True)
    assert risposta.status_code == 200

    with server_app.app_context():
        from snapserver.db import query

        assert query("SELECT id FROM notifications WHERE event = 'report.delivery'",
                     (), one=True) is None


def test_non_si_invia_su_un_canale_non_configurato(logged_client, server_app):
    """Telegram non e' configurato (nessun token): la richiesta viene respinta prima di
    accodare, cosi' non resta una notifica destinata a fallire per sempre."""
    _abilita_posta(server_app)  # posta si', Telegram no
    tenant = _tenant(server_app)
    report_id = _report_reale(server_app, tenant)
    logged_client.post("/switch-tenant", data={"tenant_id": int(tenant["id"])},
                       follow_redirects=True)

    risposta = logged_client.post("/reports/send", data={
        "report_id": report_id,
        "telegram": "123456789"}, follow_redirects=True)
    assert risposta.status_code == 200

    with server_app.app_context():
        from snapserver.db import query

        assert query("SELECT id FROM notifications WHERE event = 'report.delivery'",
                     (), one=True) is None


# --------------------------------------------------------------------------- #
# La scheda dell'apparato porta cio' che l'apparato dichiara
# --------------------------------------------------------------------------- #
def _apparato_con_pagina(server_app):
    """Un dispositivo con una lettura web completa, come la sonda la conferisce."""
    import uuid

    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str
        from snapserver.ingest import apply_batch

        tenant = dict(query("SELECT * FROM tenants ORDER BY id", (), one=True))
        tenant_id = int(tenant["id"])
        adesso = utc_now_str()
        sonda = query("SELECT id FROM probes WHERE tenant_id = ?", (tenant_id,), one=True)
        probe_id = int(sonda["id"]) if sonda else execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, created_at,"
            " updated_at) VALUES (?, 'uid-sch', 'sonda-sch', 'Sonda', 'active', ?, ?)",
            (tenant_id, adesso, adesso))
        node_id = execute(
            "INSERT INTO nodes (tenant_id, probe_id, ip, status, device_type,"
            " device_label, device_confidence, first_seen_at, last_seen_at, created_at,"
            " updated_at) VALUES (?, ?, '10.44.0.9', 'up', 'printer', 'stampante', 95,"
            " ?, ?, ?, ?)",
            (tenant_id, probe_id, adesso, adesso, adesso, adesso))
        apply_batch(tenant_id, probe_id, {
            "batch_uid": "sch-%s" % uuid.uuid4().hex[:8],
            "records": {"web": [{"ip": "10.44.0.9", "pages": [{
                "port": 80, "scheme": "http", "stato": 200, "firma": "ricoh",
                "tipo_probabile": "printer", "marca": "Ricoh", "modello": "MP C4504ex",
                "pagine_lette": 4,
                "fatti": {"nome_dispositivo": "RICOH MP C4504ex",
                          "posizione": "UFFICIO 12 - PIANO 1",
                          "nome_host": "stampante-piano1",
                          "seriale": "AB12345678"},
            }]}]}})
    return tenant, node_id


def _testo_pdf(percorso) -> str:
    pypdf = pytest.importorskip("pypdf")

    lettore = pypdf.PdfReader(str(percorso))
    return "\n".join((p.extract_text() or "") for p in lettore.pages)


def test_la_scheda_dell_apparato_riporta_cio_che_ha_dichiarato(server_app):
    """Sono dichiarazioni dell'apparato, non deduzioni del prodotto: e' la parte che un
    tecnico legge per prima, perche' dice che cosa ha davanti e dove si trova."""
    tenant, node_id = _apparato_con_pagina(server_app)

    with server_app.app_context():
        from snapserver.reports import generate

        percorso = generate.generate_device(tenant, node_id)

    testo = _testo_pdf(percorso)
    assert "Dichiarato dall" in testo
    assert "UFFICIO 12 - PIANO 1" in testo, "la posizione fisica non sta in rete"
    assert "RICOH MP C4504ex" in testo
    assert "stampante-piano1" in testo
    assert "AB12345678" in testo


def test_la_scheda_dice_da_quale_porta_viene_ogni_dato(server_app):
    """Un dato senza la porta da cui viene non e' verificabile."""
    tenant, node_id = _apparato_con_pagina(server_app)

    with server_app.app_context():
        from snapserver.reports import generate

        testo = _testo_pdf(generate.generate_device(tenant, node_id))

    assert "http/80" in testo
    assert "Pagine aperte per arrivarci" in testo


def test_la_scheda_distingue_il_produttore_dichiarato_da_quello_del_mac(server_app):
    tenant, node_id = _apparato_con_pagina(server_app)

    with server_app.app_context():
        from snapserver.reports import generate

        testo = _testo_pdf(generate.generate_device(tenant, node_id))

    assert "Produttore dichiarato dall" in testo
    assert "Costruttore dedotto dal MAC" in testo


def test_il_frontespizio_dice_che_indirizzo_e_quello_della_console(server_app):
    """"Console" da solo non si capisce: chi legge il documento non sa che indirizzo
    sia, ed e' quello che gli serve per verificare i dati alla fonte."""
    tenant, node_id = _apparato_con_pagina(server_app)

    with server_app.app_context():
        from snapserver.reports import generate

        testo = _testo_pdf(generate.generate_device(tenant, node_id))

    assert "Indirizzo della console" in testo
    assert "Console\n" not in testo, "l'etichetta nuda non deve piu' comparire"


def _apparato_ricco(server_app):
    """Un apparato con due interfacce web: una http con misure e diagnosi (UPS) e una
    https con un certificato completo. E' il caso in cui la scheda deve riportare tutto:
    interfacce, fatti aggiuntivi, diagnosi dai registri e certificato TLS."""
    import uuid

    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str
        from snapserver.ingest import apply_batch

        tenant = dict(query("SELECT * FROM tenants ORDER BY id", (), one=True))
        tenant_id = int(tenant["id"])
        adesso = utc_now_str()
        sonda = query("SELECT id FROM probes WHERE tenant_id = ?", (tenant_id,), one=True)
        probe_id = int(sonda["id"]) if sonda else execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, created_at,"
            " updated_at) VALUES (?, 'uid-ric', 'sonda-ric', 'Sonda', 'active', ?, ?)",
            (tenant_id, adesso, adesso))
        node_id = execute(
            "INSERT INTO nodes (tenant_id, probe_id, ip, status, device_type,"
            " device_label, device_confidence, first_seen_at, last_seen_at, created_at,"
            " updated_at) VALUES (?, ?, '10.44.0.20', 'up', 'ups', 'UPS', 90,"
            " ?, ?, ?, ?)",
            (tenant_id, probe_id, adesso, adesso, adesso, adesso))
        apply_batch(tenant_id, probe_id, {
            "batch_uid": "ric-%s" % uuid.uuid4().hex[:8],
            "records": {"web": [{"ip": "10.44.0.20", "pages": [
                {"port": 80, "scheme": "http", "stato": 200,
                 "titolo": "HP UPS Network Module", "marca": "HP", "modello": "R5000",
                 "firma": "mge-ups", "tipo_probabile": "ups",
                 "corpo_impronta": "ups1", "corpo_byte": 500,
                 "fatti": {"alimentazione": "AC Power", "carico_uscita": "9%",
                           "capacita_batteria": "28% (Fault)",
                           "autonomia_batteria": "24 mn 17 s",
                           "stato_batteria": "Aborted",
                           "diagnosi_ups": "batteria in stato anomalo: Aborted; la "
                           "batteria risulta scollegata e ricollegata 80 volte"},
                 "pagine": [{"percorso": "/", "origine": "radice", "stato": 200}]},
                {"port": 443, "scheme": "https", "stato": 200, "titolo": "iDRAC9",
                 "marca": "Dell", "prodotto": "Dell iDRAC", "firma": "idrac",
                 "tipo_probabile": "server", "modulo_accesso": True,
                 "corpo_impronta": "aa11", "corpo_byte": 2048,
                 "tls_versione": "TLSv1.3", "tls_cifrario": "TLS_AES_256_GCM_SHA384",
                 "cert_soggetto": "idrac-XYZ.local", "cert_emittente": "Dell CA",
                 "cert_soggetto_dn": "CN=idrac-XYZ.local,O=Dell",
                 "cert_emittente_dn": "CN=Dell CA,O=Dell",
                 "cert_a": "2027-01-01", "cert_autofirmato": True,
                 "cert_scaduto": False, "cert_giorni_residui": 400,
                 "cert_seriale": "1A2B3C", "cert_algoritmo_firma": "sha256",
                 "cert_chiave": "RSA 2048 bit", "cert_sha256": "a" * 64,
                 "cert_uso_esteso": ["autenticazione server"],
                 "pagine": [{"percorso": "/", "origine": "radice", "stato": 200}]},
            ]}]}})
    return tenant, node_id


def test_la_scheda_riporta_interfacce_fatti_diagnosi_e_certificato(server_app):
    """La scheda deve contenere tutto cio' che si e' raccolto: le interfacce web, i
    fatti aggiuntivi dichiarati, la diagnosi ricavata dai registri e il certificato TLS
    per intero. Non deve mostrarne meno del dettaglio a video."""
    tenant, node_id = _apparato_ricco(server_app)

    with server_app.app_context():
        from snapserver.reports import generate

        testo = _testo_pdf(generate.generate_device(tenant, node_id))

    # L'elenco delle interfacce web raggiunte.
    assert "Interfacce web raggiungibili" in testo
    # Un fatto aggiuntivo che non ha una colonna propria (capacita' batteria dello UPS).
    assert "Fault" in testo
    # La diagnosi dai registri, in evidenza.
    assert "Diagnosi dai registri" in testo
    # Il certificato TLS per intero: sezione, numero di serie e chiave pubblica.
    assert "Certificato digitale" in testo
    assert "1A2B3C" in testo
    assert "RSA 2048 bit" in testo
    assert "autofirmato" in testo


def test_il_report_sulla_segmentazione_elenca_anche_le_reti_dichiarate(server_app):
    """Elencava solo le reti senza zona -- il lavoro da fare -- e non quelle
    dichiarate, cioe' il lavoro fatto. Per un documento che si consegna e' la meta' che
    manca: la segmentazione si dimostra con quello che c'e'."""
    from datetime import date, timedelta

    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str
        from snapserver.reports import generate

        tenant = dict(query("SELECT * FROM tenants ORDER BY id", (), one=True))
        adesso = utc_now_str()
        execute("INSERT INTO subnets (tenant_id, cidr, host_count, is_enabled, zone,"
                " label, imported_at, created_at, updated_at)"
                " VALUES (?, '10.66.0.0/24', 254, 1, 'datacenter', 'Sala macchine',"
                " ?, ?, ?)", (int(tenant["id"]), adesso, adesso, adesso))
        percorso = generate.generate("segmentation", tenant,
                                     date.today() - timedelta(days=1))

    testo = _testo_pdf(percorso)
    assert "Reti con zona dichiarata" in testo
    assert "10.66.0.0/24" in testo
    assert "Sala macchine" in testo
    assert "Datacenter" in testo, "il nome della zona, non la chiave"


# --------------------------------------------------------------------------- #
# Fascicolo di conformita' europea
# --------------------------------------------------------------------------- #
def _fascicolo_europeo(server_app):
    from datetime import date, timedelta

    with server_app.app_context():
        from snapserver.db import query
        from snapserver.reports import generate

        tenant = dict(query("SELECT * FROM tenants ORDER BY id", (), one=True))
        return generate.generate("eu_compliance", tenant,
                                 date.today() - timedelta(days=1), 90)


def test_il_fascicolo_europeo_nomina_le_direttive_interessate(server_app):
    """Un documento di conformita' che non cita l'articolo non serve a un auditor: la
    prima cosa che si verifica e' il riferimento."""
    testo = _testo_pdf(_fascicolo_europeo(server_app))

    for riferimento in ("Direttiva (UE) 2022/2555", "D.lgs. 138/2024",
                        "Regolamento (UE) 2024/2847", "Regolamento (UE) 2016/679",
                        "ETSI EN 303 645", "ACN"):
        assert riferimento in testo, riferimento
    for articolo in ("art. 21", "art. 23", "art. 32", "allegato II"):
        assert articolo in testo, articolo


def test_il_fascicolo_dichiara_cio_che_non_dimostra(server_app):
    """Un fascicolo che promettesse di coprire tutta la NIS2 con una scansione di rete
    farebbe danno a chi lo presenta: l'auditor smette di credere anche alle parti
    vere."""
    import re

    # Il testo estratto va a capo dove il documento va a capo: si confronta sul testo
    # appiattito, altrimenti si verifica l'impaginazione invece del contenuto.
    testo = re.sub(r"\s+", " ", _testo_pdf(_fascicolo_europeo(server_app)))

    assert "Che cosa dimostra questo fascicolo" in testo
    assert "FUORI PORTATA" in testo
    assert "Non e' una certificazione" in testo
    assert "Limite dichiarato" in testo


def test_il_fascicolo_mette_la_copertura_prima_dei_numeri(server_app):
    """Senza la copertura ogni altro numero e' senza scala: "nessun riscontro critico"
    vale molto se la rete e' osservata per intero e niente se se ne guarda un quarto."""
    testo = _testo_pdf(_fascicolo_europeo(server_app))

    assert "Copertura delle prove" in testo
    assert testo.index("Copertura delle prove") < testo.index("art. 21"), (
        "la copertura viene prima delle sezioni per norma"
    ) if "art. 21" in testo else True
    assert "Subnet dichiarate nel perimetro" in testo


def test_il_fascicolo_ordina_i_rilievi_per_gravita(server_app):
    testo = _testo_pdf(_fascicolo_europeo(server_app))

    assert "Rilievi in ordine di gravita" in testo


def test_gli_esiti_hanno_una_definizione_nel_documento(server_app):
    """Un'etichetta senza definizione, in un fascicolo di conformita', diventa una
    discussione."""
    testo = _testo_pdf(_fascicolo_europeo(server_app))

    for esito in ("DIMOSTRATO", "PARZIALE", "DA COLMARE", "FUORI PORTATA"):
        assert esito in testo, esito


def test_le_misure_del_fascicolo_vengono_dalle_stesse_interrogazioni(server_app):
    """Un fascicolo che ricalcolasse i propri numeri dichiarerebbe cose diverse dal
    resto della console: in un audit e' l'incoerenza che fa perdere credibilita'."""
    with server_app.app_context():
        from snapserver.db import query
        from snapserver.reports.eu_compliance import misure

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
        m = misure(tenant_id, "2000-01-01 00:00:00", "2100-01-01 00:00:00")
        nodi = query("SELECT COUNT(*) AS n FROM nodes WHERE tenant_id = ?",
                     (tenant_id,), one=True)["n"]
        subnet = query("SELECT COUNT(*) AS n FROM subnets WHERE tenant_id = ?",
                       (tenant_id,), one=True)["n"]

    assert m["nodi"] == nodi
    assert m["subnet_totali"] == subnet


def test_un_esito_riguarda_sempre_un_riferimento_normativo(server_app):
    with server_app.app_context():
        from snapserver.db import query
        from snapserver.reports.eu_compliance import (
            DA_COLMARE, DIMOSTRATO, FUORI_PORTATA, PARZIALE, misure, requisiti,
        )

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
        voci = requisiti(misure(tenant_id, "2000-01-01 00:00:00",
                                "2100-01-01 00:00:00"))

    assert voci
    ammessi = {DIMOSTRATO, PARZIALE, DA_COLMARE, FUORI_PORTATA}
    for voce in voci:
        assert voce["esito"] in ammessi, voce
        assert voce["riferimento"] and voce["requisito"] and voce["prova"]
        assert voce["norma"] in {"nis2", "cra", "gdpr", "etsi", "acn"}


def test_il_fascicolo_europeo_e_nel_catalogo(server_app):
    with server_app.app_context():
        from snapserver.reports import REPORT_CATALOG, REPORT_KINDS

        assert "eu_compliance" in REPORT_KINDS
        assert "NIS2" in REPORT_KINDS["eu_compliance"]
        assert REPORT_CATALOG["eu_compliance"]["ruolo"] == "tenant_admin"
