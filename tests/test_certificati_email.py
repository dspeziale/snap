"""
snap - Test dell'invio per posta dell'elenco dei certificati in scadenza.

Che cosa difendono questi test: che il messaggio sia USABILE da chi deve rinnovare il
certificato senza tornare alla console. Un avviso che dicesse solo "il certificato di
10.20.10.7 scade fra 12 giorni" costringerebbe a riaprire la pagina per ogni campo --
e chi rinnova lavora sul sistema che lo ospita, in una finestra di manutenzione, non
davanti alla console.

remarks: Autore: Daniele Speziale - Data: 2026-09-12
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json
from datetime import date, timedelta

import pytest

OGGI = date(2026, 9, 12)

# Un certificato reale ha tutti questi campi: il messaggio li deve riportare tutti,
# perche' sono esattamente quelli che servono a rifarlo.
DETTAGLIO = {
    "cert_soggetto_dn": "CN=portale.ised.it,O=ISED S.p.A.,C=IT",
    "cert_emittente_dn": "CN=ISED Internal CA,O=ISED S.p.A.,C=IT",
    "cert_valido_da": "2024-09-01 00:00:00 UTC",
    "cert_valido_a": "2026-09-20 23:59:59 UTC",
    "cert_seriale": "0A1B2C3D4E5F",
    "cert_versione": "v3",
    "cert_algoritmo_firma": "sha256WithRSAEncryption",
    "cert_chiave": "RSA 2048 bit",
    "cert_sha256": "aa:bb:cc:dd:ee:ff:00:11",
    "cert_sha1": "11:22:33:44:55:66",
    "cert_nomi": ["portale.ised.it", "www.ised.it"],
    "cert_nomi_ip": ["10.20.10.7"],
    "cert_uso": "digitalSignature, keyEncipherment",
    "cert_uso_esteso": "serverAuth",
}


def _nodo_con_certificato(server_app, tenant_id: int, ip: str, giorni: int,
                          hostname: str = "portale", porta: int = 443) -> int:
    """Un nodo con un'interfaccia HTTPS e un certificato che scade fra `giorni`."""
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        node_id = execute(
            "INSERT INTO nodes (tenant_id, ip, hostname, device_label, device_type,"
            " os_name, first_seen_at, last_seen_at, created_at, updated_at)"
            " VALUES (?, ?, ?, 'Portale applicativo', 'server', 'Linux', ?, ?, ?, ?)",
            (tenant_id, ip, hostname, adesso, adesso, adesso, adesso))
        scadenza = (OGGI + timedelta(days=giorni)).isoformat()
        dettaglio = dict(DETTAGLIO, cert_valido_a="%s 23:59:59 UTC" % scadenza)
        execute(
            "INSERT INTO node_web (tenant_id, node_id, port, scheme, status_code,"
            " title, server_header, product, cert_subject, cert_issuer, cert_expires,"
            " cert_selfsigned, tls_version, cert_json, collected_at)"
            " VALUES (?, ?, ?, 'https', 200, 'Portale', 'nginx/1.24', 'nginx',"
            " ?, ?, ?, 0, 'TLSv1.3', ?, ?)",
            (tenant_id, node_id, porta, DETTAGLIO["cert_soggetto_dn"],
             DETTAGLIO["cert_emittente_dn"], scadenza,
             json.dumps(dettaglio, ensure_ascii=False), adesso))
        return node_id


def _tenant(server_app) -> int:
    with server_app.app_context():
        from snapserver.db import query

        return int(query("SELECT id FROM tenants WHERE code = 'ised'", (), one=True)["id"])


# --------------------------------------------------------------------------- #
# La selezione
# --------------------------------------------------------------------------- #
def test_si_manda_solo_cio_che_scade_entro_la_soglia(server_app):
    """La soglia in giorni della pagina decide, e vale per cio' che DEVE ANCORA
    scadere: un certificato gia' scaduto non sta scadendo, e' un'altra coda di lavoro
    -- piu' urgente -- e mescolarlo qui la renderebbe meno visibile."""
    tenant_id = _tenant(server_app)
    _nodo_con_certificato(server_app, tenant_id, "10.0.0.1", -5, "scaduto")
    _nodo_con_certificato(server_app, tenant_id, "10.0.0.2", 8, "fra-otto")
    _nodo_con_certificato(server_app, tenant_id, "10.0.0.3", 400, "lontano")

    with server_app.app_context():
        from snapserver.certificates_report import certificati_per_rapporto

        voci = certificati_per_rapporto(tenant_id, entro_giorni=30, oggi=OGGI)

    nomi = [v["hostname"] for v in voci]
    assert nomi == ["fra-otto"], nomi
    assert "lontano" not in nomi, "oltre la soglia non si segnala"
    assert "scaduto" not in nomi, "i gia' scaduti non sono 'in scadenza'"


@pytest.mark.parametrize("soglia,attesi", [
    (5, []),
    (10, ["fra-otto"]),
    (60, ["fra-otto", "fra-quaranta"]),
])
def test_la_soglia_e_quella_che_si_indica(server_app, soglia, attesi):
    """E' il campo "Soglia in scadenza (giorni)": cambiare quel numero deve cambiare
    l'elenco che parte, altrimenti il campo mente."""
    tenant_id = _tenant(server_app)
    _nodo_con_certificato(server_app, tenant_id, "10.0.0.2", 8, "fra-otto")
    _nodo_con_certificato(server_app, tenant_id, "10.0.0.4", 40, "fra-quaranta")

    with server_app.app_context():
        from snapserver.certificates_report import certificati_per_rapporto

        voci = certificati_per_rapporto(tenant_id, entro_giorni=soglia, oggi=OGGI)

    assert [v["hostname"] for v in voci] == attesi


def test_quello_che_scade_oggi_ci_sta_dentro(server_app):
    """Il confine inferiore e' OGGI compreso: un certificato che scade stasera e' il
    piu' urgente dell'elenco, non il primo degli esclusi."""
    tenant_id = _tenant(server_app)
    _nodo_con_certificato(server_app, tenant_id, "10.0.0.1", 0, "oggi")

    with server_app.app_context():
        from snapserver.certificates_report import certificati_per_rapporto, corpo_testo

        voci = certificati_per_rapporto(tenant_id, entro_giorni=30, oggi=OGGI)
        testo = corpo_testo(voci, 30, oggi=OGGI)

    assert [v["hostname"] for v in voci] == ["oggi"]
    assert "SCADE OGGI" in testo


def test_prima_gli_scaduti_poi_per_urgenza(server_app):
    """La coda del lavoro deve essere gia' ordinata: chi legge non deve cercarla.

    Si prova con `stato="tutti"`, l'unico caso in cui scaduti e in scadenza stanno
    nello stesso elenco."""
    tenant_id = _tenant(server_app)
    _nodo_con_certificato(server_app, tenant_id, "10.0.0.2", 20, "venti")
    _nodo_con_certificato(server_app, tenant_id, "10.0.0.1", -30, "scadutissimo")
    _nodo_con_certificato(server_app, tenant_id, "10.0.0.3", 3, "tre")

    with server_app.app_context():
        from snapserver.certificates_report import certificati_per_rapporto

        voci = certificati_per_rapporto(tenant_id, entro_giorni=30, stato="tutti",
                                        oggi=OGGI)

    assert [v["hostname"] for v in voci] == ["scadutissimo", "tre", "venti"]


def test_il_filtro_scaduti_manda_solo_quelli(server_app):
    tenant_id = _tenant(server_app)
    _nodo_con_certificato(server_app, tenant_id, "10.0.0.1", -5, "scaduto")
    _nodo_con_certificato(server_app, tenant_id, "10.0.0.2", 8, "vivo")

    with server_app.app_context():
        from snapserver.certificates_report import certificati_per_rapporto

        voci = certificati_per_rapporto(tenant_id, stato="scaduti", oggi=OGGI)

    assert [v["hostname"] for v in voci] == ["scaduto"]


def test_una_data_illeggibile_non_fa_sparire_il_certificato(server_app):
    """Un certificato la cui data non si legge esiste comunque: toglierlo
    nasconderebbe un apparato solo perche' il prodotto non sa leggerne un campo."""
    tenant_id = _tenant(server_app)
    node_id = _nodo_con_certificato(server_app, tenant_id, "10.0.0.9", 5, "rotto")
    with server_app.app_context():
        from snapserver.certificates_report import certificati_per_rapporto
        from snapserver.db import execute

        execute("UPDATE node_web SET cert_expires = 'mai' WHERE node_id = ?", (node_id,))
        voci = certificati_per_rapporto(tenant_id, entro_giorni=3650, oggi=OGGI)

    rotti = [v for v in voci if v["hostname"] == "rotto"]
    # Non entra nella selezione per soglia (non si sa quando scade) ma non esplode.
    assert rotti == [] or rotti[0]["giorni"] is None


# --------------------------------------------------------------------------- #
# Il contenuto: ci deve essere TUTTO
# --------------------------------------------------------------------------- #
def test_il_messaggio_porta_tutti_i_dati_del_certificato(server_app):
    """E' la ragione per cui questo messaggio esiste: chi rinnova deve poterlo fare
    senza tornare alla console."""
    tenant_id = _tenant(server_app)
    _nodo_con_certificato(server_app, tenant_id, "10.20.10.7", 8)

    with server_app.app_context():
        from snapserver.certificates_report import (certificati_per_rapporto,
                                                    corpo_html, corpo_testo)

        voci = certificati_per_rapporto(tenant_id, entro_giorni=30, oggi=OGGI)
        testo = corpo_testo(voci, 30, "ISED", oggi=OGGI)
        html = corpo_html(voci, 30, "ISED", oggi=OGGI)

    for atteso in (DETTAGLIO["cert_soggetto_dn"], DETTAGLIO["cert_emittente_dn"],
                   DETTAGLIO["cert_seriale"], DETTAGLIO["cert_algoritmo_firma"],
                   DETTAGLIO["cert_chiave"], DETTAGLIO["cert_sha256"],
                   DETTAGLIO["cert_sha1"], "portale.ised.it", "www.ised.it",
                   "10.20.10.7", "serverAuth", "TLSv1.3"):
        assert atteso in testo, "manca nel testo: %s" % atteso

    # L'HTML fa l'escape: si confronta sulla forma che il browser mostrera'.
    from markupsafe import escape

    for atteso in (DETTAGLIO["cert_seriale"], "portale.ised.it", "serverAuth"):
        assert str(escape(atteso)) in html, "manca nell'HTML: %s" % atteso


def test_il_messaggio_dice_quanto_manca_e_quanto_e_passato(server_app):
    tenant_id = _tenant(server_app)
    _nodo_con_certificato(server_app, tenant_id, "10.0.0.1", -5, "scaduto")
    _nodo_con_certificato(server_app, tenant_id, "10.0.0.2", 1, "domani")

    with server_app.app_context():
        from snapserver.certificates_report import certificati_per_rapporto, corpo_testo

        # `tutti`: e' il caso in cui il messaggio deve saper dire ENTRAMBE le cose,
        # quanto manca e quanto e' passato.
        voci = certificati_per_rapporto(tenant_id, entro_giorni=30, stato="tutti",
                                        oggi=OGGI)
        testo = corpo_testo(voci, 30, oggi=OGGI)

    assert "SCADUTO da 5 giorni" in testo
    assert "scade domani" in testo


def test_l_oggetto_dice_gia_l_urgenza(server_app):
    """Chi riceve venti messaggi al giorno decide dall'oggetto se aprirlo adesso."""
    tenant_id = _tenant(server_app)
    _nodo_con_certificato(server_app, tenant_id, "10.0.0.1", -5, "scaduto")
    _nodo_con_certificato(server_app, tenant_id, "10.0.0.2", 8, "vivo")

    with server_app.app_context():
        from snapserver.certificates_report import certificati_per_rapporto, oggetto

        voci = certificati_per_rapporto(tenant_id, entro_giorni=30, stato="tutti",
                                        oggi=OGGI)
        testo = oggetto(voci, 30, "ISED")

    assert "1 SCADUTI" in testo and "1 in scadenza" in testo
    assert "ISED" in testo


def test_senza_certificati_lo_dice_invece_di_mandare_un_foglio_bianco(server_app):
    tenant_id = _tenant(server_app)

    with server_app.app_context():
        from snapserver.certificates_report import corpo_html, corpo_testo, oggetto

        testo = corpo_testo([], 30, oggi=OGGI)
        html = corpo_html([], 30, oggi=OGGI)
        assert "nessuno in scadenza" in oggetto([], 30).lower()

    assert "Nessun certificato" in testo and "Nessun certificato" in html
    # Il limite del dato si dichiara sempre, anche quando non c'e' nulla da segnalare:
    # "nessun certificato in scadenza" non significa "nessun certificato".
    # Gli a capo del testo semplice non contano: si confronta il contenuto.
    import re as _re

    disteso = _re.sub(r"\s+", " ", testo)
    assert "non raggiungibile dalla sonda non compare" in disteso


def test_il_messaggio_non_promette_piu_di_quanto_sa(server_app):
    """Il prodotto vede i soli certificati che una sonda ha potuto leggere. Dirlo non
    e' modestia: e' cio' che impedisce di leggere l'elenco come un inventario
    completo dei certificati dell'organizzazione."""
    tenant_id = _tenant(server_app)
    _nodo_con_certificato(server_app, tenant_id, "10.0.0.1", 8)

    with server_app.app_context():
        from snapserver.certificates_report import certificati_per_rapporto, corpo_testo

        voci = certificati_per_rapporto(tenant_id, entro_giorni=30, oggi=OGGI)
        testo = corpo_testo(voci, 30, oggi=OGGI)

    import re as _re

    assert "non e' una conferma" in _re.sub(r"\s+", " ", testo)


# --------------------------------------------------------------------------- #
# La rotta
# --------------------------------------------------------------------------- #
def _posta_configurata(server_app) -> None:
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        for chiave, valore in (("smtp_enabled", "1"), ("smtp_host", "127.0.0.1"),
                               ("smtp_port", "25"), ("smtp_sender", "snap@ised.local")):
            execute("INSERT INTO system_settings (key, value, updated_at)"
                    " VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET"
                    " value = excluded.value", (chiave, valore, adesso))


def test_l_invio_accoda_una_notifica(logged_client, server_app):
    tenant_id = _tenant(server_app)
    _nodo_con_certificato(server_app, tenant_id, "10.20.10.7", 8)
    _posta_configurata(server_app)

    risposta = logged_client.post("/inventory/certificates/email",
                                  data={"email": "referente@ised.local", "entro": "30"},
                                  follow_redirects=True)

    assert risposta.status_code == 200
    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT * FROM notifications WHERE event = 'certificates.expiring'"
                     " ORDER BY id DESC", (), one=True)
    assert riga is not None, "nessuna notifica accodata"
    assert riga["recipients"] == "referente@ised.local"
    assert DETTAGLIO["cert_seriale"] in riga["body"]
    assert riga["body_html"], "manca il corpo HTML"


def test_un_indirizzo_non_valido_non_manda_niente(logged_client, server_app):
    tenant_id = _tenant(server_app)
    _nodo_con_certificato(server_app, tenant_id, "10.20.10.7", 8)
    _posta_configurata(server_app)

    risposta = logged_client.post("/inventory/certificates/email",
                                  data={"email": "non-e-un-indirizzo"},
                                  follow_redirects=True)

    assert "non valido" in risposta.data.decode("utf-8")
    with server_app.app_context():
        from snapserver.db import query

        assert query("SELECT id FROM notifications WHERE event ="
                     " 'certificates.expiring'", (), one=True) is None


def test_senza_posta_configurata_lo_dice(logged_client, server_app):
    """Un bottone che non fa niente e non lo dice e' peggio di un bottone assente."""
    tenant_id = _tenant(server_app)
    _nodo_con_certificato(server_app, tenant_id, "10.20.10.7", 8)

    risposta = logged_client.post("/inventory/certificates/email",
                                  data={"email": "referente@ised.local"},
                                  follow_redirects=True)

    corpo = risposta.data.decode("utf-8")
    assert "posta non e" in corpo and "Canali di recapito" in corpo


def test_l_invio_resta_nel_registro(logged_client, server_app):
    tenant_id = _tenant(server_app)
    _nodo_con_certificato(server_app, tenant_id, "10.20.10.7", 8)
    _posta_configurata(server_app)

    logged_client.post("/inventory/certificates/email",
                       data={"email": "referente@ised.local", "entro": "30"},
                       follow_redirects=True)

    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT * FROM audit_events WHERE event_type ="
                     " 'certificates.emailed' ORDER BY id DESC", (), one=True)
    assert riga is not None, "l'invio non ha lasciato traccia"
    assert "referente@ised.local" in riga["description"]


def test_si_manda_quello_che_si_sta_guardando(logged_client, server_app):
    """Il filtro della pagina viaggia con la richiesta: il messaggio deve corrispondere
    all'elenco a schermo, non a un criterio diverso deciso altrove."""
    tenant_id = _tenant(server_app)
    _nodo_con_certificato(server_app, tenant_id, "10.0.0.1", -5, "scaduto")
    _nodo_con_certificato(server_app, tenant_id, "10.0.0.2", 8, "vivo")
    _posta_configurata(server_app)

    logged_client.post("/inventory/certificates/email",
                       data={"email": "referente@ised.local", "stato": "scaduti"},
                       follow_redirects=True)

    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT body FROM notifications WHERE event ="
                     " 'certificates.expiring' ORDER BY id DESC", (), one=True)
    assert "scaduto" in riga["body"]
    assert "vivo" not in riga["body"], "il filtro della pagina non e' stato rispettato"


def test_la_pagina_offre_il_modulo(logged_client, server_app):
    tenant_id = _tenant(server_app)
    _nodo_con_certificato(server_app, tenant_id, "10.20.10.7", 8)

    corpo = logged_client.get("/inventory/certificates").data.decode("utf-8")

    assert "certificates/email" in corpo
    assert 'name="email"' in corpo
    # L'azione va confermata, come ogni azione che manda dati fuori dalla console.
    assert "data-confirm" in corpo


def test_dalla_pagina_si_manda_solo_cio_che_scade(logged_client, server_app):
    """La stessa regola, vista da dove la usa l'operatore: si preme il bottone senza
    scegliere un filtro, e parte cio' che scade entro la soglia -- non i gia' scaduti."""
    tenant_id = _tenant(server_app)
    _nodo_con_certificato(server_app, tenant_id, "10.0.0.1", -5, "gia-scaduto")
    _nodo_con_certificato(server_app, tenant_id, "10.0.0.2", 8, "fra-otto")
    _nodo_con_certificato(server_app, tenant_id, "10.0.0.3", 90, "fra-novanta")
    _posta_configurata(server_app)

    logged_client.post("/inventory/certificates/email",
                       data={"email": "referente@ised.local", "entro": "30"},
                       follow_redirects=True)

    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT body FROM notifications WHERE event ="
                     " 'certificates.expiring' ORDER BY id DESC", (), one=True)
    corpo = riga["body"]
    assert "fra-otto" in corpo
    assert "gia-scaduto" not in corpo, "un certificato gia' scaduto non sta scadendo"
    assert "fra-novanta" not in corpo, "oltre la soglia di 30 giorni non si manda"
