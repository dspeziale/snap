"""
snap - Test del percorso di comunicazione ad ACN.

Il vincolo che decide tutto: il portale `segnalazioni.acn.gov.it` e' ad accesso con
identita' digitale (SPID/CIE/CNS) del punto di contatto e non espone un'interfaccia di
programmazione. snap **prepara e sorveglia, non invia** -- e le prove qui verificano
proprio questo, insieme alle due cose che in un'ispezione contano davvero: i termini
dell'art. 23 (24 ore, 72 ore, un mese dalla CONOSCENZA) e la dimostrabilita' di cio'
che e' stato inviato.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from datetime import timedelta

import pytest


def _tenant_id(server_app) -> int:
    with server_app.app_context():
        from snapserver.db import query

        return int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])


def _incidente(server_app, tenant_id: int, severity: str = "critical",
               ore_fa: float = 1.0, risolto: bool = False) -> int:
    """Un incidente vero: bersaglio, controllo e incidente, come li crea il workflow."""
    with server_app.app_context():
        from snapserver.db import execute, utc_now, utc_str

        adesso = utc_now()
        aperto = utc_str(adesso - timedelta(hours=ore_fa))
        target_id = execute(
            "INSERT INTO check_targets (tenant_id, address, name, is_enabled,"
            " created_at, updated_at)"
            " VALUES (?, '10.55.0.10', 'Server gestionale', 1, ?, ?)",
            (tenant_id, aperto, aperto))
        check_id = execute(
            "INSERT INTO checks (tenant_id, target_id, name, kind, is_enabled,"
            " interval_seconds, timeout_seconds, failure_threshold,"
            " escalation_threshold, created_at, updated_at)"
            " VALUES (?, ?, 'Presenza in rete', 'presence', 1, 60, 5, 3, 5, ?, ?)",
            (tenant_id, target_id, aperto, aperto))
        return execute(
            "INSERT INTO check_incidents (tenant_id, check_id, status, severity,"
            " opened_at, first_detail, last_detail, resolved_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, 'nessuna risposta', 'ancora assente', ?, ?)",
            (tenant_id, check_id, "resolved" if risolto else "open", severity, aperto,
             utc_str(adesso) if risolto else None, aperto))


# --------------------------------------------------------------------------- #
# Il vincolo: si prepara, non si invia
# --------------------------------------------------------------------------- #
def test_il_canale_automatico_e_dichiarato_non_disponibile(server_app):
    """Automatizzare l'invio richiederebbe di conservare l'identita' digitale di una
    persona e di attribuirle un atto che non ha compiuto. Il posto per un'eventuale
    interfaccia esiste, e dice di non esserci."""
    with server_app.app_context():
        from snapserver.acn import CANALE_API, CANALE_PORTALE, CANALI

        assert CANALI[CANALE_PORTALE]["disponibile"] is True
        assert CANALI[CANALE_PORTALE]["automatico"] is False
        assert CANALI[CANALE_API]["disponibile"] is False


def test_nel_prodotto_non_ci_sono_credenziali_del_portale():
    """Nessuna identita' digitale, nessuna password del portale, in nessun file."""
    from pathlib import Path

    radice = Path(__file__).resolve().parent.parent / "server/snapserver"
    sospetti = []
    for modulo in radice.rglob("*.py"):
        testo = modulo.read_text(encoding="utf-8").lower()
        for parola in ("spid_password", "spid_user", "cie_pin", "acn_password",
                       "acn_token"):
            if parola in testo:
                sospetti.append("%s: %s" % (modulo.name, parola))
    assert not sospetti, sospetti


# --------------------------------------------------------------------------- #
# I termini dell'art. 23
# --------------------------------------------------------------------------- #
def test_i_termini_decorrono_dalla_conoscenza(server_app):
    """24 ore, 72 ore, un mese: e' cio' che dice l'art. 23, e la conoscenza e' l'unico
    istante documentabile."""
    with server_app.app_context():
        from snapserver.acn import FINALE, NOTIFICA, PREALLARME, scadenza

        assert scadenza("2026-08-31 10:00:00", PREALLARME) == "2026-09-01 10:00:00"
        assert scadenza("2026-08-31 10:00:00", NOTIFICA) == "2026-09-03 10:00:00"
        assert scadenza("2026-08-31 10:00:00", FINALE) == "2026-09-30 10:00:00"


def test_l_aggiornamento_non_ha_un_termine_proprio(server_app):
    with server_app.app_context():
        from snapserver.acn import AGGIORNAMENTO, scadenza

        assert scadenza("2026-08-31 10:00:00", AGGIORNAMENTO) == ""


def test_lo_stato_del_termine_distingue_tre_casi(server_app):
    """"C'e' tempo", "sta finendo" e "e' passato" portano a tre azioni diverse: una
    sola etichetta "in ritardo" non servirebbe a nessuno."""
    with server_app.app_context():
        from snapserver.db import utc_now, utc_str
        from snapserver.acn import DA_PREPARARE, PREALLARME, stato_termine

        adesso = utc_now()

        def voce(ore):
            return {"stage": PREALLARME, "status": DA_PREPARARE,
                    "deadline_at": utc_str(adesso + timedelta(hours=ore))}

        assert stato_termine(voce(20), adesso)["stato"] == "in tempo"
        assert stato_termine(voce(3), adesso)["stato"] == "in scadenza"
        assert stato_termine(voce(-1), adesso)["stato"] == "termine superato"
        assert stato_termine(voce(-1), adesso)["scaduto"] is True


# --------------------------------------------------------------------------- #
# Il fascicolo
# --------------------------------------------------------------------------- #
def test_aprire_il_fascicolo_crea_gli_stadi_con_le_scadenze(server_app):
    tenant_id = _tenant_id(server_app)
    incident_id = _incidente(server_app, tenant_id)

    with server_app.app_context():
        from snapserver import acn

        acn.apri_fascicolo(tenant_id, incident_id)
        voci = acn.comunicazioni(tenant_id, incident_id)

    stadi = {v["stage"] for v in voci}
    assert stadi == {acn.PREALLARME, acn.NOTIFICA, acn.FINALE}
    assert all(v["deadline_at"] for v in voci)
    assert all(v["status"] == acn.DA_PREPARARE for v in voci)


def test_il_fascicolo_non_si_apre_due_volte(server_app):
    tenant_id = _tenant_id(server_app)
    incident_id = _incidente(server_app, tenant_id)

    with server_app.app_context():
        from snapserver import acn

        acn.apri_fascicolo(tenant_id, incident_id)
        with pytest.raises(acn.AcnError):
            acn.apri_fascicolo(tenant_id, incident_id)


def test_l_apertura_resta_nel_registro_degli_eventi(server_app):
    tenant_id = _tenant_id(server_app)
    incident_id = _incidente(server_app, tenant_id)

    with server_app.app_context():
        from snapserver import acn
        from snapserver.db import query

        acn.apri_fascicolo(tenant_id, incident_id)
        tracce = query("SELECT description FROM audit_events"
                       " WHERE event_type = 'acn.dossier.opened'", ())
    assert tracce and str(incident_id) in tracce[-1]["description"]


# --------------------------------------------------------------------------- #
# La macchina a stati
# --------------------------------------------------------------------------- #
def test_l_invio_richiede_il_protocollo(server_app):
    """Senza il numero restituito dal portale la riga direbbe che la comunicazione e'
    partita senza poterlo dimostrare, ed e' la prima cosa che chiede un ispettore."""
    tenant_id = _tenant_id(server_app)
    incident_id = _incidente(server_app, tenant_id)

    with server_app.app_context():
        from snapserver import acn

        acn.apri_fascicolo(tenant_id, incident_id)
        voce = acn.comunicazioni(tenant_id, incident_id)[0]
        acn.cambia_stato(tenant_id, int(voce["id"]), acn.PREPARATA)

        with pytest.raises(acn.AcnError):
            acn.cambia_stato(tenant_id, int(voce["id"]), acn.INVIATA, protocollo="  ")

        aggiornata = acn.cambia_stato(tenant_id, int(voce["id"]), acn.INVIATA,
                                      attore="tecnico@ised.local",
                                      protocollo="ACN-2026-000123")
    assert aggiornata["status"] == acn.INVIATA
    assert aggiornata["reference"] == "ACN-2026-000123"
    assert aggiornata["sent_at"] and aggiornata["sent_by"] == "tecnico@ised.local"


def test_non_si_dichiara_inviata_una_comunicazione_mai_composta(server_app):
    """Una macchina a stati esplicita serve a questo."""
    tenant_id = _tenant_id(server_app)
    incident_id = _incidente(server_app, tenant_id)

    with server_app.app_context():
        from snapserver import acn

        acn.apri_fascicolo(tenant_id, incident_id)
        voce = acn.comunicazioni(tenant_id, incident_id)[0]

        with pytest.raises(acn.AcnError):
            acn.cambia_stato(tenant_id, int(voce["id"]), acn.INVIATA,
                             protocollo="ACN-1")


def test_una_comunicazione_non_dovuta_richiede_la_motivazione(server_app):
    """Distingue "non serviva" da "ce ne siamo dimenticati", che e' precisamente la
    domanda di un ispettore."""
    tenant_id = _tenant_id(server_app)
    incident_id = _incidente(server_app, tenant_id)

    with server_app.app_context():
        from snapserver import acn

        acn.apri_fascicolo(tenant_id, incident_id)
        voce = acn.comunicazioni(tenant_id, incident_id)[0]

        with pytest.raises(acn.AcnError):
            acn.cambia_stato(tenant_id, int(voce["id"]), acn.NON_DOVUTA, note="")

        esito = acn.cambia_stato(
            tenant_id, int(voce["id"]), acn.NON_DOVUTA,
            note="incidente non significativo: ripristino in 12 minuti, nessun"
                 " sospetto di atto illecito")
    assert esito["status"] == acn.NON_DOVUTA
    assert "12 minuti" in esito["notes"]


def test_una_comunicazione_non_dovuta_resta_nell_elenco(server_app):
    tenant_id = _tenant_id(server_app)
    incident_id = _incidente(server_app, tenant_id)

    with server_app.app_context():
        from snapserver import acn

        acn.apri_fascicolo(tenant_id, incident_id)
        voce = acn.comunicazioni(tenant_id, incident_id)[0]
        acn.cambia_stato(tenant_id, int(voce["id"]), acn.NON_DOVUTA,
                         note="non significativo")
        voci = acn.comunicazioni(tenant_id, incident_id)

    assert any(v["status"] == acn.NON_DOVUTA for v in voci)
    assert len(voci) == 3


# --------------------------------------------------------------------------- #
# La valutazione di significativita'
# --------------------------------------------------------------------------- #
def test_la_valutazione_e_una_proposta_non_un_verdetto(server_app):
    """I criteri che contano di piu' -- atto illecito, effetti trasfrontalieri, dati
    personali -- non sono misurabili, e restano da dichiarare."""
    tenant_id = _tenant_id(server_app)
    incident_id = _incidente(server_app, tenant_id, ore_fa=8.0)

    with server_app.app_context():
        from snapserver import acn

        esito = acn.valuta(dict(acn.incidente(tenant_id, incident_id)))

    assert esito["esiti"]["gravita"] is True
    assert esito["esiti"]["durata"] is True, "otto ore superano la soglia di quattro"
    assert esito["esiti"]["illecito"] is None
    assert esito["esiti"]["trasfrontaliero"] is None
    assert esito["esiti"]["dati_personali"] is None
    assert "non sono misurabili" in esito["motivo_proposta"] or \
        "nessuna misura" in esito["motivo_proposta"]


def test_un_incidente_breve_e_non_critico_non_soddisfa_i_criteri(server_app):
    tenant_id = _tenant_id(server_app)
    incident_id = _incidente(server_app, tenant_id, severity="warning", ore_fa=0.2,
                             risolto=True)

    with server_app.app_context():
        from snapserver import acn

        esito = acn.valuta(dict(acn.incidente(tenant_id, incident_id)))

    assert esito["esiti"]["gravita"] is False
    assert esito["esiti"]["durata"] is False
    assert esito["proposta"] is False
    assert "resta comunque dovuta" in esito["motivo_proposta"]


# --------------------------------------------------------------------------- #
# Il registro e la sorveglianza
# --------------------------------------------------------------------------- #
def test_il_registro_conta_cio_che_un_ispettore_chiede(server_app):
    tenant_id = _tenant_id(server_app)
    incident_id = _incidente(server_app, tenant_id)

    with server_app.app_context():
        from snapserver import acn

        acn.apri_fascicolo(tenant_id, incident_id)
        voci = acn.comunicazioni(tenant_id, incident_id)
        acn.cambia_stato(tenant_id, int(voci[0]["id"]), acn.PREPARATA)
        acn.cambia_stato(tenant_id, int(voci[0]["id"]), acn.INVIATA,
                         protocollo="ACN-2026-1")
        acn.cambia_stato(tenant_id, int(voci[1]["id"]), acn.NON_DOVUTA,
                         note="non significativo per questo stadio")
        registro = acn.registro(tenant_id)

    assert registro["totale"] == 3
    assert registro["nei_termini"] == 1
    assert registro["non_dovute"] == 1
    assert registro["da_inviare"] == 1
    assert registro["fuori_termine"] == 0


def test_un_invio_dopo_il_termine_risulta_fuori_termine(server_app):
    tenant_id = _tenant_id(server_app)
    incident_id = _incidente(server_app, tenant_id, ore_fa=48.0)

    with server_app.app_context():
        from snapserver import acn
        from snapserver.db import execute

        acn.apri_fascicolo(tenant_id, incident_id)
        preallarme = [v for v in acn.comunicazioni(tenant_id, incident_id)
                      if v["stage"] == acn.PREALLARME][0]
        acn.cambia_stato(tenant_id, int(preallarme["id"]), acn.PREPARATA)
        acn.cambia_stato(tenant_id, int(preallarme["id"]), acn.INVIATA,
                         protocollo="ACN-2026-2")
        # L'incidente e' noto da 48 ore: il preallarme era dovuto entro 24.
        execute("UPDATE acn_communications SET sent_at = ? WHERE id = ?",
                ("2026-12-31 23:59:59", int(preallarme["id"])))
        registro = acn.registro(tenant_id)

    assert registro["fuori_termine"] >= 1


def test_la_sorveglianza_avvisa_una_volta_sola(server_app, monkeypatch):
    """Un avviso ripetuto ogni cinque minuti diventa rumore, e il rumore si silenzia."""
    tenant_id = _tenant_id(server_app)
    incident_id = _incidente(server_app, tenant_id, ore_fa=20.0)

    with server_app.app_context():
        from snapserver import acn, acn_watch

        acn.apri_fascicolo(tenant_id, incident_id)

        accodate = []
        monkeypatch.setattr(
            acn_watch, "queue_notification",
            lambda *a, **k: accodate.append(a) or 1, raising=False)
        import snapserver.notifications as notifiche
        monkeypatch.setattr(notifiche, "queue_notification",
                            lambda *a, **k: accodate.append(a) or 1)

        primo = acn_watch.giro(ore=6.0)
        secondo = acn_watch.giro(ore=6.0)

    assert primo["avvisi"] == 1, "il preallarme scade fra quattro ore"
    assert secondo["avvisi"] == 0, "non si ripete"


def test_la_sorveglianza_annuncia_il_termine_superato(server_app, monkeypatch):
    tenant_id = _tenant_id(server_app)
    incident_id = _incidente(server_app, tenant_id, ore_fa=30.0)

    with server_app.app_context():
        from snapserver import acn, acn_watch
        import snapserver.notifications as notifiche

        acn.apri_fascicolo(tenant_id, incident_id)
        monkeypatch.setattr(notifiche, "queue_notification", lambda *a, **k: 1)

        esito = acn_watch.giro(ore=6.0)

    assert esito["superati"] >= 1


def test_i_momenti_degli_avvisi_non_sono_filtrabili(server_app):
    """Un termine di legge disattivato da una scelta fatta anni prima e' esattamente il
    modo in cui si perde una scadenza."""
    with server_app.app_context():
        from snapserver.acn_watch import EVENTO_AVVISO, EVENTO_SUPERATO
        from snapserver.notifications import FILTERED_EVENTS, NOTIFY_EVENTS

        assert EVENTO_AVVISO in NOTIFY_EVENTS
        assert EVENTO_SUPERATO in NOTIFY_EVENTS
        assert EVENTO_AVVISO not in FILTERED_EVENTS
        assert EVENTO_SUPERATO not in FILTERED_EVENTS


# --------------------------------------------------------------------------- #
# Le pagine
# --------------------------------------------------------------------------- #
def test_la_pagina_dichiara_che_il_prodotto_non_invia(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/acn/").get_data(as_text=True)

    assert "segnalazioni.acn.gov.it" in pagina
    assert "SPID" in pagina
    assert "identita" in pagina and "digitali" in pagina
    assert "protocollo" in pagina


def test_la_pagina_di_valutazione_mostra_i_criteri(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    incident_id = _incidente(server_app, tenant_id)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/acn/incidenti/%d" % incident_id).get_data(as_text=True)

    assert "significativo" in pagina
    assert "da dichiarare" in pagina
    assert "conoscenza" in pagina


def test_il_fascicolo_pdf_si_scarica_e_porta_i_campi(logged_client, server_app):
    pypdf = pytest.importorskip("pypdf")
    import io

    tenant_id = _tenant_id(server_app)
    incident_id = _incidente(server_app, tenant_id)
    with server_app.app_context():
        from snapserver import acn

        acn.apri_fascicolo(tenant_id, incident_id)
        voce = acn.comunicazioni(tenant_id, incident_id)[0]
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.get("/acn/comunicazioni/%d/fascicolo.pdf" % int(voce["id"]))

    assert risposta.status_code == 200
    assert risposta.data[:5] == b"%PDF-"
    import re

    # Il testo estratto va a capo dove il documento va a capo: si confronta sul testo
    # appiattito, altrimenti si verifica l'impaginazione invece del contenuto.
    grezzo = "\n".join((p.extract_text() or "") for p in
                       pypdf.PdfReader(io.BytesIO(risposta.data)).pages)
    testo = re.sub(r"\s+", " ", grezzo)
    assert "Campi da compilare nel portale" in testo
    assert "art. 23" in testo
    assert "identita' digitale" in testo


def test_comporre_il_fascicolo_porta_lo_stadio_a_preparata(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    incident_id = _incidente(server_app, tenant_id)
    with server_app.app_context():
        from snapserver import acn

        acn.apri_fascicolo(tenant_id, incident_id)
        voce = acn.comunicazioni(tenant_id, incident_id)[0]
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    logged_client.get("/acn/comunicazioni/%d/fascicolo.pdf" % int(voce["id"]))

    with server_app.app_context():
        from snapserver import acn

        aggiornata = acn.comunicazione(tenant_id, int(voce["id"]))
    assert aggiornata["status"] == acn.PREPARATA
    assert aggiornata["prepared_at"]


def test_un_analista_non_comunica_all_autorita(server_app):
    """La comunicazione impegna il soggetto: chi la registra dichiara che e'
    avvenuta."""
    from snapserver.blueprints.acn_views import bp

    with server_app.app_context():
        from snapserver.reports import REPORT_CATALOG  # noqa: F401 - contesto

    # Tutte le rotte del percorso passano dal ruolo di amministratore del tenant.
    sorgente = (__import__("pathlib").Path(bp.root_path).parent
                / "blueprints/acn_views.py").read_text(encoding="utf-8")
    assert sorgente.count("@role_required(ROLE_TENANT_ADMIN)") >= 8


def test_una_comunicazione_di_un_altro_tenant_non_si_apre(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    incident_id = _incidente(server_app, tenant_id)
    with server_app.app_context():
        from snapserver import acn
        from snapserver.db import execute, utc_now_str

        acn.apri_fascicolo(tenant_id, incident_id)
        voce = acn.comunicazioni(tenant_id, incident_id)[0]
        altro = execute("INSERT INTO tenants (name, code, timezone, created_at,"
                        " updated_at) VALUES ('Altro', 'altro-acn', 'Europe/Rome', ?, ?)",
                        (utc_now_str(), utc_now_str()))
    logged_client.post("/switch-tenant", data={"tenant_id": altro},
                       follow_redirects=True)

    risposta = logged_client.get("/acn/comunicazioni/%d" % int(voce["id"]))

    assert risposta.status_code in (403, 404)


# --------------------------------------------------------------------------- #
# Registrare un incidente a mano, ed eliminarlo
# --------------------------------------------------------------------------- #
def test_si_registra_un_incidente_che_non_nasce_da_un_controllo(server_app):
    """Gli incidenti che contano di piu' non li rileva una sonda: li porta una
    telefonata, una segnalazione del CSIRT, un riscatto comparso su uno schermo."""
    tenant_id = _tenant_id(server_app)

    with server_app.app_context():
        from snapserver import acn

        incident_id = acn.registra_incidente(
            tenant_id, titolo="Cifratura dei file su un server di produzione",
            soggetto="10.10.5.20", gravita="critical",
            descrizione="riscatto comparso sulla console alle 03:10")
        voce = dict(acn.incidente(tenant_id, incident_id))

    assert voce["origin"] == "manual"
    assert voce["controllo"] == "Cifratura dei file su un server di produzione", (
        "per un incidente registrato a mano vale il titolo, non il contenitore")
    assert voce["bersaglio"] == "10.10.5.20"
    assert voce["severity"] == "critical"
    assert voce["status"] == "open"


def test_il_titolo_e_obbligatorio(server_app):
    tenant_id = _tenant_id(server_app)

    with server_app.app_context():
        from snapserver import acn

        with pytest.raises(acn.AcnError):
            acn.registra_incidente(tenant_id, titolo="   ")


def test_la_conoscenza_non_puo_essere_nel_futuro(server_app):
    """I termini decorrerebbero da un momento che non e' ancora arrivato."""
    tenant_id = _tenant_id(server_app)

    with server_app.app_context():
        from snapserver import acn

        with pytest.raises(acn.AcnError):
            acn.registra_incidente(tenant_id, titolo="Prova",
                                   conosciuto_alle="2099-01-01 00:00:00")
        with pytest.raises(acn.AcnError):
            acn.registra_incidente(tenant_id, titolo="Prova",
                                   conosciuto_alle="non una data")


def test_il_contenitore_manuale_e_uno_solo_e_non_esegue_nulla(server_app):
    """Un controllo per ogni incidente riempirebbe la pagina dei controlli di righe che
    non verificano niente."""
    tenant_id = _tenant_id(server_app)

    with server_app.app_context():
        from snapserver import acn
        from snapserver.db import query

        acn.registra_incidente(tenant_id, titolo="Primo")
        acn.registra_incidente(tenant_id, titolo="Secondo")
        controlli = query("SELECT id, is_enabled FROM checks WHERE tenant_id = ?"
                          " AND name = ?", (tenant_id, acn.CONTROLLO_MANUALE))

    assert len(controlli) == 1
    assert int(controlli[0]["is_enabled"]) == 0, "non deve eseguire verifiche"


def test_un_incidente_registrato_a_mano_si_elimina(server_app):
    tenant_id = _tenant_id(server_app)

    with server_app.app_context():
        from snapserver import acn
        from snapserver.db import query

        incident_id = acn.registra_incidente(tenant_id, titolo="Falso allarme")
        esito = acn.elimina_incidente(tenant_id, incident_id)
        resta = query("SELECT id FROM check_incidents WHERE id = ?", (incident_id,),
                      one=True)

    assert esito["titolo"] == "Falso allarme"
    assert resta is None


def test_l_eliminazione_porta_via_il_fascicolo_non_inviato(server_app):
    tenant_id = _tenant_id(server_app)

    with server_app.app_context():
        from snapserver import acn
        from snapserver.db import query

        incident_id = acn.registra_incidente(tenant_id, titolo="Da annullare")
        acn.apri_fascicolo(tenant_id, incident_id)
        esito = acn.elimina_incidente(tenant_id, incident_id)
        restano = query("SELECT id FROM acn_communications WHERE incident_id = ?",
                        (incident_id,))

    assert esito["comunicazioni"] == 3
    assert restano == []


def test_un_incidente_gia_comunicato_non_si_elimina(server_app):
    """Il protocollo restituito dal portale e' la prova dei tempi, e la prova non si
    cancella: se e' un falso allarme, lo si dichiara nella relazione finale."""
    tenant_id = _tenant_id(server_app)

    with server_app.app_context():
        from snapserver import acn

        incident_id = acn.registra_incidente(tenant_id, titolo="Comunicato")
        acn.apri_fascicolo(tenant_id, incident_id)
        voce = acn.comunicazioni(tenant_id, incident_id)[0]
        acn.cambia_stato(tenant_id, int(voce["id"]), acn.PREPARATA)
        acn.cambia_stato(tenant_id, int(voce["id"]), acn.INVIATA,
                         protocollo="ACN-2026-9")

        with pytest.raises(acn.AcnError) as errore:
            acn.elimina_incidente(tenant_id, incident_id)

    assert "prova dei tempi" in str(errore.value)


def test_un_incidente_aperto_da_un_controllo_non_si_elimina(server_app):
    """E' un fatto della storia della sorveglianza: cancellarlo falsificherebbe il
    registro."""
    tenant_id = _tenant_id(server_app)
    incident_id = _incidente(server_app, tenant_id)

    with server_app.app_context():
        from snapserver import acn

        with pytest.raises(acn.AcnError) as errore:
            acn.elimina_incidente(tenant_id, incident_id)

    assert "aperto da un controllo" in str(errore.value)


def test_l_eliminazione_resta_nel_registro_degli_eventi(server_app):
    tenant_id = _tenant_id(server_app)

    with server_app.app_context():
        from snapserver import acn
        from snapserver.db import query

        incident_id = acn.registra_incidente(tenant_id, titolo="Tracciato")
        acn.elimina_incidente(tenant_id, incident_id)
        tracce = query("SELECT description FROM audit_events"
                       " WHERE event_type IN ('incident.registered',"
                       " 'incident.deleted') ORDER BY id", ())

    assert len(tracce) >= 2
    assert "Tracciato" in tracce[-1]["description"]


def test_la_pagina_offre_il_modulo_e_l_eliminazione(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    with server_app.app_context():
        from snapserver import acn

        acn.registra_incidente(tenant_id, titolo="Segnalazione dal fornitore")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/acn/").get_data(as_text=True)

    assert "Registra un incidente da valutare" in pagina
    assert "Segnalazione dal fornitore" in pagina
    assert "registrato a mano" in pagina
    assert "/elimina" in pagina


def test_la_registrazione_dalla_pagina_porta_alla_valutazione(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.post("/acn/incidenti", data={
        "titolo": "Esfiltrazione sospetta", "soggetto": "gestionale",
        "gravita": "critical", "descrizione": "traffico anomalo verso l'esterno",
    }, follow_redirects=True)
    pagina = risposta.get_data(as_text=True)

    assert "Esfiltrazione sospetta" in pagina
    assert "significativo" in pagina
    assert "Elimina l" in pagina, "il pulsante di eliminazione e' nella valutazione"


def test_un_titolo_vuoto_dalla_pagina_non_crea_niente(logged_client, server_app):
    tenant_id = _tenant_id(server_app)
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.post("/acn/incidenti", data={"titolo": ""},
                                  follow_redirects=True)

    assert "obbligatorio" in risposta.get_data(as_text=True)
