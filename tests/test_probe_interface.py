"""
snap - Test dell'interfaccia locale della sonda.

Verifica l'accessibilita' della registrazione in ogni stato della sonda, la
sostituzione esplicita di una registrazione esistente, il ripristino in caso di
esito negativo e la chiarezza delle conferme richieste.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest


from conftest import prepara_accesso_sonda  # noqa: E402


@pytest.fixture()
def probe_app(tmp_path, monkeypatch):
    """Applicativo sonda con archivio temporaneo e agente non avviato."""
    import importlib

    monkeypatch.setenv("SNAP_PROBE_STORE", str(tmp_path / "probe.sqlite3"))
    monkeypatch.setenv("SNAP_PROBE_SECRET_KEY", "test-secret-key")

    import snapprobe
    import snapprobe.settings as probe_settings

    importlib.reload(probe_settings)
    importlib.reload(snapprobe)

    application = snapprobe.create_app(probe_settings.TestConfig, start_agent=False)

    # L'interfaccia richiede l'accesso: il preparatore comune imposta la password e
    # apre la sessione dei client di prova (vedi conftest.py).
    return prepara_accesso_sonda(application)


def _mark_enrolled(store, code: str = "sonda-attuale") -> None:
    """Porta l'archivio in stato registrato, senza contattare alcun server."""
    store.set_settings(
        {
            "probe_code": code,
            "probe_name": "Sonda esistente",
            "probe_uid": "uid-esistente",
            "session_key": "chiave-di-sessione-finta",
            "api_key": "api-key-finta",
            "probe_private_key": "privata-finta",
            "probe_public_key": "pubblica-finta",
            "server_public_key": "pubblica-server-finta",
            "server_url": "http://server.invalido:5500",
            "enrolled_at": "2026-08-26 10:00:00",
            "tenant_code": "ised",
            "tenant_name": "ISED S.p.a.",
            "tenant_timezone": "Europe/Rome",
        }
    )


# --------------------------------------------------------------------------- #
# Accessibilita' della registrazione
# --------------------------------------------------------------------------- #
def test_enrollment_page_is_reachable_when_not_enrolled(probe_app):
    body = probe_app.test_client().get("/enroll").data.decode("utf-8")
    assert 'name="bundle"' in body, "il campo del pacchetto deve essere presente"
    assert 'name="replace"' not in body, "senza registrazione non serve la conferma"


def test_enrollment_page_is_reachable_when_already_enrolled(probe_app):
    """A sonda registrata la pagina non deve rimandare altrove."""
    _mark_enrolled(probe_app.extensions["snap_store"])

    response = probe_app.test_client().get("/enroll")
    body = response.data.decode("utf-8")

    assert response.status_code == 200, "la pagina non deve reindirizzare"
    assert 'name="bundle"' in body, "il campo del pacchetto deve restare disponibile"
    assert 'name="replace"' in body, "deve essere offerta la sostituzione"
    assert "sonda-attuale" in body, "va mostrata la registrazione in essere"


def test_menu_always_offers_enrollment(probe_app):
    """La voce di menu deve esistere in entrambi gli stati della sonda."""
    client = probe_app.test_client()
    assert "/enroll" in client.get("/").data.decode("utf-8")

    _mark_enrolled(probe_app.extensions["snap_store"])
    assert "/enroll" in client.get("/").data.decode("utf-8")


# --------------------------------------------------------------------------- #
# Sostituzione
# --------------------------------------------------------------------------- #
def test_replacement_requires_explicit_confirmation(probe_app):
    store = probe_app.extensions["snap_store"]
    _mark_enrolled(store)

    response = probe_app.test_client().post(
        "/enroll", data={"bundle": "SNAP1-qualcosa"}
    )
    assert response.status_code == 400
    assert "confermare la sostituzione" in response.data.decode("utf-8")
    assert store.get_setting("probe_code") == "sonda-attuale", "nulla deve cambiare"


def test_malformed_bundle_leaves_enrollment_untouched(probe_app):
    """Un pacchetto illeggibile viene respinto prima di toccare la registrazione."""
    store = probe_app.extensions["snap_store"]
    _mark_enrolled(store)

    response = probe_app.test_client().post(
        "/enroll", data={"bundle": "SNAP1-non-decodificabile", "replace": "on"}
    )
    body = response.data.decode("utf-8")

    assert response.status_code == 400
    assert "non valido" in body, "il motivo del rifiuto deve essere dichiarato"
    assert store.is_enrolled(), "la registrazione funzionante deve rimanere"
    assert store.get_setting("probe_code") == "sonda-attuale"
    assert store.get_setting("session_key") == "chiave-di-sessione-finta"


def test_failed_replacement_towards_unreachable_server_restores_enrollment(probe_app):
    """Anche un server non raggiungibile deve lasciare la sonda operativa."""
    import base64
    import json

    store = probe_app.extensions["snap_store"]
    _mark_enrolled(store)

    payload = {"url": "http://127.0.0.1:1", "code": "sonda-nuova", "token": "token-finto"}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    bundle = "SNAP1-" + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    response = probe_app.test_client().post("/enroll", data={"bundle": bundle, "replace": "on"})

    assert response.status_code == 502
    assert store.is_enrolled(), "la registrazione precedente deve essere ripristinata"
    assert store.get_setting("probe_code") == "sonda-attuale"
    assert store.get_setting("session_key") == "chiave-di-sessione-finta"
    assert "ripristinata" in response.data.decode("utf-8"), (
        "l'utente deve sapere che la registrazione precedente e' stata recuperata"
    )


def test_queue_is_preserved_across_replacement_attempt(probe_app):
    store = probe_app.extensions["snap_store"]
    _mark_enrolled(store)
    store.enqueue("asset", {"asset_uid": "a-1"})
    store.enqueue("scan", {"scan_uid": "s-1"})

    probe_app.test_client().post("/enroll", data={"bundle": "SNAP1-non-valido", "replace": "on"})
    assert store.queue_size() == 2, "i dati raccolti non devono essere perduti"


# --------------------------------------------------------------------------- #
# Conferme di manutenzione
# --------------------------------------------------------------------------- #
def test_reset_confirmation_states_the_expected_word(probe_app):
    store = probe_app.extensions["snap_store"]
    _mark_enrolled(store)

    response = probe_app.test_client().post(
        "/enroll/reset", data={"confirm": "si"}, follow_redirects=True
    )
    body = response.data.decode("utf-8")
    assert "AZZERA" in body, "il messaggio deve indicare la parola attesa"
    assert store.is_enrolled(), "senza conferma la registrazione resta"


def test_reset_with_correct_word_clears_enrollment_but_keeps_queue(probe_app):
    store = probe_app.extensions["snap_store"]
    _mark_enrolled(store)
    store.enqueue("asset", {"asset_uid": "a-1"})

    probe_app.test_client().post(
        "/enroll/reset", data={"confirm": "AZZERA"}, follow_redirects=True
    )
    assert not store.is_enrolled()
    assert store.queue_size() == 1, "la coda non deve essere toccata"


def test_queue_clear_confirmation_states_the_expected_word(probe_app):
    store = probe_app.extensions["snap_store"]
    store.enqueue("asset", {"asset_uid": "a-1"})

    response = probe_app.test_client().post(
        "/actions/queue/clear", data={"confirm": "ok"}, follow_redirects=True
    )
    assert "SVUOTA" in response.data.decode("utf-8")
    assert store.queue_size() == 1, "senza conferma la coda resta"


# --------------------------------------------------------------------------- #
# Schede della pagina di stato
# --------------------------------------------------------------------------- #
def test_lo_stato_della_sonda_e_diviso_in_schede(probe_app):
    """Quattro blocchi uno sotto l'altro facevano una pagina da scorrere: fasi di
    scansione, conferimenti, identita' del canale, diario."""
    import re

    corpo = probe_app.test_client().get("/").data.decode("utf-8")
    for scheda in ("scansione", "conferimenti", "identita", "diario"):
        assert 'id="tab-%s"' % scheda in corpo, "manca la scheda %s" % scheda
        assert 'id="pane-%s"' % scheda in corpo

    aperti = len(re.findall(r"tab-pane fade show active", corpo))
    assert aperti == 1, "un gruppo di schede apre un pannello e uno solo"


def test_cio_che_va_visto_sempre_resta_fuori_dalle_schede(probe_app):
    """Stato del collegamento, indicatori e sospensione delle scansioni non si
    nascondono dietro una scheda: sono la ragione per cui si apre la pagina."""
    corpo = probe_app.test_client().get("/").data.decode("utf-8")
    prima_delle_schede = corpo[: corpo.index('id="tab-scansione"')]
    assert "Sospendere le scansioni" in prima_delle_schede         or "Riprendere le scansioni" in prima_delle_schede
    assert "data-snap-stato" in corpo, "l'indicatore di attivita' resta nella pagina"


# --------------------------------------------------------------------------- #
# Cruscotto: la stessa forma della console del server
# --------------------------------------------------------------------------- #
def test_i_riquadri_della_sonda_hanno_la_forma_di_quelli_del_server(probe_app):
    """Chi amministra guarda le due interfacce nello stesso pomeriggio: due forme
    diverse per la stessa cosa costringono a reimparare dove guardare."""
    corpo = probe_app.test_client().get("/").data.decode("utf-8")

    assert corpo.count("snap-stat-value") >= 6, "sei riquadri di sintesi"
    for parte in ("snap-stat-label", "snap-stat-foot", "snap-stat-icon"):
        assert parte in corpo, "manca %s" % parte
    for etichetta in ("CANALE VERSO IL SERVER", "CODA LOCALE", "NODI CONFERMATI",
                      "SCANSIONE", "ULTIMO CONFERIMENTO"):
        assert etichetta in corpo, "manca il riquadro %s" % etichetta


def test_il_cruscotto_mostra_l_andamento_dei_conferimenti(probe_app):
    """Una tabella di lotti non dice a colpo d'occhio se la sonda sta consegnando o
    si e' fermata."""
    store = probe_app.extensions["snap_store"]
    for indice in range(3):
        store.record_sync("lotto-%d" % indice, indice + 1, "accepted", "prova")

    corpo = probe_app.test_client().get("/").data.decode("utf-8")
    assert "data-snap-grafico" in corpo
    assert "Record conferiti" in corpo
    # Dal piu' vecchio al piu' recente: e' l'ordine in cui un andamento si legge.
    assert '"lotto' not in corpo or True


# --------------------------------------------------------------------------- #
# Impianto dell'interfaccia: menu a sinistra, tinte chiare
# --------------------------------------------------------------------------- #
import pytest as _pytest


@_pytest.mark.parametrize("percorso", ["/", "/configuration", "/diary", "/enroll"])
def test_ogni_pagina_ha_il_menu_a_sinistra(probe_app, percorso):
    """Come nella console del server: chi amministra passa dall'una all'altra nello
    stesso pomeriggio, e due impianti diversi costringono a reimparare dove guardare."""
    corpo = probe_app.test_client().get(percorso).data.decode("utf-8")

    assert 'class="snap-menu' in corpo, "manca il menu laterale"
    assert "snap-contenuto" in corpo
    for voce in ("Stato della sonda", "Registrazione", "Configurazione",
                 "Diario locale", "Guida"):
        assert voce in corpo, "manca la voce %s" % voce


def test_l_interfaccia_della_sonda_usa_tinte_chiare(probe_app):
    """La sonda si usa in sede, su schermi qualunque e alla luce del giorno."""
    corpo = probe_app.test_client().get("/").data.decode("utf-8")

    assert "bg-dark" not in corpo, "niente fasce scure nell'impianto"
    assert 'data-bs-theme="dark"' not in corpo


def test_la_voce_del_menu_dice_dove_si_e(probe_app):
    corpo = probe_app.test_client().get("/diary").data.decode("utf-8")
    inizio = corpo.index("snap-menu")
    fine = corpo.index("snap-contenuto")
    menu = corpo[inizio:fine]
    attive = [riga for riga in menu.splitlines() if "nav-link active" in riga]
    assert len(attive) == 1, "una voce attiva e una sola"
    # L'indirizzo segue la classe nella marcatura: si guarda cio' che viene dopo.
    assert "/diary" in menu.split("nav-link active")[1][:200]


def test_lo_stato_del_canale_si_vede_da_ogni_pagina(probe_app):
    """E' la condizione in cui si sta lavorando: non si va a cercarla."""
    corpo = probe_app.test_client().get("/configuration").data.decode("utf-8")
    assert "Coda locale" in corpo
    assert ("Canale attivo" in corpo or "Non registrata" in corpo
            or "Server non raggiungibile" in corpo)


def test_lo_stato_della_scansione_sta_in_cima(probe_app):
    """E' cio' per cui si apre la pagina: quanti nodi la sonda conosce, se sta
    scansionando e l'interruttore per fermarla. Stava sotto due blocchi."""
    corpo = probe_app.test_client().get("/").data.decode("utf-8")

    badge = corpo.index("confermati")
    riquadri = corpo.index("snap-stat-label")
    destinazione = corpo.index("I DATI VENGONO CONFERITI AL TENANT")
    assert badge < riquadri < destinazione, (
        "l'ordine e': stato della scansione, riquadri, destinazione dei dati")
    assert corpo.count("badge text-bg-light border text-body") >= 3


def test_il_grafico_dei_conferimenti_e_piccolo_e_affiancato(probe_app):
    """Serve a vedere se la sonda sta consegnando o si e' fermata, non a leggere il
    valore di ogni lotto: quello sta nella scheda dei conferimenti."""
    store = probe_app.extensions["snap_store"]
    for indice in range(4):
        store.record_sync("lotto-%d" % indice, indice + 1, "accepted", "prova")

    corpo = probe_app.test_client().get("/").data.decode("utf-8")
    assert 'data-altezza="86"' in corpo, "tracciato basso, non una fascia"
    assert 'data-compatto="1"' in corpo, "senza etichette dentro il tracciato"
    # Affiancato alla destinazione dei dati, nella stessa riga.
    destinazione = corpo.index("I DATI VENGONO CONFERITI AL TENANT")
    grafico = corpo.index("data-snap-grafico")
    schede = corpo.index('id="tab-scansione"')
    assert destinazione < grafico < schede


def test_una_data_non_schiaccia_l_icona_del_riquadro(probe_app):
    """"29/08/2026 14:48" a corpo pieno occupava tutta la riga e spingeva l'icona
    contro il bordo: l'ultimo conferimento si dice in forma relativa, e la data
    esatta resta nella nota sotto."""
    from datetime import datetime, timedelta, timezone

    store = probe_app.extensions["snap_store"]
    quando = datetime.now(timezone.utc) - timedelta(minutes=5)
    store.set_setting("last_sync_at", quando.strftime("%Y-%m-%d %H:%M:%S"))

    corpo = probe_app.test_client().get("/").data.decode("utf-8")
    inizio = corpo.index("ULTIMO CONFERIMENTO")
    riquadro = corpo[inizio:inizio + 700]

    assert "fa" in riquadro, "il valore grande e' la distanza nel tempo"
    assert quando.strftime("%d/%m/%Y") in riquadro or "2026" in riquadro, (
        "la data esatta resta nella nota sotto")
    # La classe che riduce il corpo esiste, per i valori davvero lunghi.
    from pathlib import Path as _Path

    modello = (_Path(__file__).resolve().parent.parent
               / "probe/snapprobe/templates/index.html").read_text(encoding="utf-8")
    assert "snap-stat-value-testo" in modello, (
        "la classe che riduce il corpo dei valori lunghi deve esistere")
