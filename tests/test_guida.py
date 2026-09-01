"""
snap - Test della guida operativa, su entrambi i lati.

La guida e' un documento servito dall'applicazione: deve essere raggiungibile,
completa nelle sezioni dichiarate nel proprio indice, aperta dal menu in una finestra
nuova, e priva del menu di navigazione -- una finestra che serve a leggere non ha
bisogno di un secondo menu dentro.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from conftest import prepara_accesso_sonda

RADICE = Path(__file__).resolve().parent.parent


@pytest.fixture()
def probe_client(tmp_path, monkeypatch):
    """Client dell'interfaccia locale della sonda, con archivio temporaneo."""
    import importlib

    monkeypatch.setenv("SNAP_PROBE_STORE", str(tmp_path / "probe.sqlite3"))
    monkeypatch.setenv("SNAP_PROBE_SECRET_KEY", "test-secret-key")

    import snapprobe
    import snapprobe.settings as probe_settings

    importlib.reload(probe_settings)
    importlib.reload(snapprobe)

    applicazione = snapprobe.create_app(probe_settings.TestConfig, start_agent=False)

    # La guida della sonda sta dentro l'interfaccia, che richiede l'accesso: si apre
    # una sessione, come farebbe chi la consulta mentre configura la sonda.
    return prepara_accesso_sonda(applicazione).test_client()


# Sezioni attese nella guida della console: sono le stesse voci del suo indice.
SEZIONI_CONSOLE = (
    "cose", "ruoli", "sonde", "perimetro", "scansione", "inventario",
    "monitoraggio", "controlli", "incidenti", "metriche", "dashboard",
    "regole", "canali", "report", "archivio", "threat", "sala", "zone",
    "acn", "sicurezza", "diagnosi", "glossario",
)
SEZIONI_SONDA = (
    "cosa", "installazione", "registrazione", "interfaccia", "accesso", "scelte",
    "autonomia", "controlli", "azzeramento", "diagnosi",
)


# --------------------------------------------------------------------------- #
# Guida della console
# --------------------------------------------------------------------------- #
def test_la_guida_della_console_risponde(logged_client):
    risposta = logged_client.get("/guida/")
    assert risposta.status_code == 200
    testo = risposta.get_data(as_text=True)
    assert "Guida operativa della console" in testo
    assert len(testo) > 20000, "una guida completa non sta in poche righe"


def test_la_guida_della_console_ha_tutte_le_sezioni_del_proprio_indice(logged_client):
    """Una voce d'indice che non porta a nulla e' peggio di una voce assente."""
    testo = logged_client.get("/guida/").get_data(as_text=True)
    ancore = set(re.findall(r'id="([a-z]+)"', testo))
    mancanti = [s for s in SEZIONI_CONSOLE if s not in ancore]
    assert not mancanti, "sezioni dichiarate nell'indice ma assenti: %s" % mancanti
    for sezione in SEZIONI_CONSOLE:
        assert 'href="#%s"' % sezione in testo, "manca la voce d'indice %r" % sezione


def test_la_guida_spiega_i_punti_che_hanno_dato_problemi(logged_client):
    """Cio' che ha richiesto una diagnosi sul campo deve stare nella guida: e' la
    ragione per cui la guida esiste."""
    testo = logged_client.get("/guida/").get_data(as_text=True)
    for atteso in (
        "180 secondi",                    # minimo per le fasi di ispezione
        "perimetro",                      # subnet disattivate e sonda apparentemente ferma
        "Porte iniettate",                # apparato intermedio
        "agente di sicurezza",            # banner che risponde al posto del servizio
        "database",                       # verifiche sul contenuto JSON
        "SOGLIA DI ATTIVAZIONE",          # workflow: seconda soglia
        "email di riferimento del tenant", # recapito in mancanza di indicazione
        "Notifiche",                      # notifiche dei momenti del workflow
        "secondo",                        # un grafico richiede il secondo campione
    ):
        assert atteso in testo, "la guida non spiega %r" % atteso


def test_la_guida_della_sonda_e_consultabile_anche_dalla_console(logged_client):
    risposta = logged_client.get("/guida/sonda")
    assert risposta.status_code == 200
    testo = risposta.get_data(as_text=True)
    assert "Guida della sonda" in testo
    for sezione in SEZIONI_SONDA:
        assert 'id="%s"' % sezione in testo, "manca la sezione %r" % sezione


def test_le_due_guide_si_rimandano_a_vicenda(logged_client):
    console = logged_client.get("/guida/").get_data(as_text=True)
    sonda = logged_client.get("/guida/sonda").get_data(as_text=True)
    assert "/guida/sonda" in console
    assert "/guida/" in sonda


def test_la_guida_non_e_accessibile_senza_accesso(server_client):
    """E' documentazione dell'impianto: descrive perimetro, sonde e comandi."""
    risposta = server_client.get("/guida/")
    assert risposta.status_code in (302, 401), "la guida deve richiedere l'accesso"


def test_la_guida_non_porta_il_menu_laterale(logged_client):
    """Una finestra che serve a leggere non ha bisogno di un secondo menu dentro."""
    testo = logged_client.get("/guida/").get_data(as_text=True)
    assert "app-sidebar" not in testo
    assert "sidebar-menu" not in testo
    # Ha invece un indice interno e la possibilita' di stampare.
    assert "INDICE" in testo
    assert "window.print()" in testo


def test_la_guida_segue_il_tema_scelto_dall_utente(logged_client, server_app):
    """Chi lavora in tema scuro non deve ricevere un documento chiaro in faccia."""
    assert 'data-bs-theme="light"' in logged_client.get("/guida/").get_data(as_text=True)

    with server_app.app_context():
        from snapserver.db import execute

        execute("UPDATE users SET pref_theme = 'dark' WHERE email = ?",
                (server_app.config["BOOTSTRAP_ADMIN_EMAIL"],))
    assert 'data-bs-theme="dark"' in logged_client.get("/guida/").get_data(as_text=True)


# --------------------------------------------------------------------------- #
# Voci di menu
# --------------------------------------------------------------------------- #
def test_il_menu_del_server_apre_la_guida_in_una_finestra_nuova(logged_client):
    pagina = logged_client.get("/", follow_redirects=True).get_data(as_text=True)
    voce = re.search(r'<a[^>]*href="/guida/"[^>]*>', pagina)
    assert voce, "manca la voce di menu della guida"
    assert 'target="_blank"' in voce.group(0), (
        "la guida deve aprirsi in una finestra nuova: si consulta accanto al lavoro")
    assert 'rel="noopener"' in voce.group(0), (
        "target=_blank senza noopener espone la finestra che ha aperto la pagina")


def test_il_menu_della_sonda_apre_la_guida_in_una_finestra_nuova(probe_client):
    pagina = probe_client.get("/").get_data(as_text=True)
    voce = re.search(r'<a[^>]*href="/guida"[^>]*>', pagina)
    assert voce, "manca la voce di menu della guida sulla sonda"
    assert 'target="_blank"' in voce.group(0)
    assert 'rel="noopener"' in voce.group(0)


# --------------------------------------------------------------------------- #
# Guida sulla sonda
# --------------------------------------------------------------------------- #
def test_la_guida_della_sonda_risponde(probe_client):
    risposta = probe_client.get("/guida")
    assert risposta.status_code == 200
    testo = risposta.get_data(as_text=True)
    assert "Guida della sonda" in testo
    for sezione in SEZIONI_SONDA:
        assert 'id="%s"' % sezione in testo, "manca la sezione %r" % sezione
    assert "app-sidebar" not in testo
    assert "navbar-nav" not in testo, "la guida non porta la barra di navigazione"


def test_la_guida_della_sonda_spiega_le_condizioni_che_la_bloccano(probe_client):
    testo = probe_client.get("/guida").get_data(as_text=True)
    for atteso in ("nmap", "Npcap", "perimetro", "180 secondi", "coda",
                   "Diario locale"):
        assert atteso in testo, "la guida della sonda non spiega %r" % atteso


def test_le_due_redazioni_del_corpo_della_sonda_restano_allineate():
    """Il testo nasce nella console e viene copiato nella sonda: se le due copie
    divergono, una delle due mente. I due applicativi non condividono codice per
    requisito di separazione, quindi il controllo e' qui."""
    console = (RADICE / "server/snapserver/templates/guide/_probe_body.html").read_text(
        encoding="utf-8")
    sonda = (RADICE / "probe/snapprobe/templates/guide_body.html").read_text(
        encoding="utf-8")

    def corpo(testo: str) -> str:
        # Si confronta il contenuto, non l'intestazione del file, che dichiara
        # l'applicativo di appartenenza.
        return testo.split("#}", 1)[1].strip()

    assert corpo(console) == corpo(sonda), (
        "il corpo della guida della sonda e' divergente fra console e sonda")


# --------------------------------------------------------------------------- #
# Coerenza con l'impianto descritto
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("voce", [
    "Perimetro", "Incidenti", "Dati dalle sonde", "Flotta sonde",
    "Registra sonda", "Bersagli e controlli", "Stato della rete", "Cambiamenti",
    "Notifiche",
])
def test_la_guida_nomina_le_voci_di_menu_esistenti(logged_client, voce):
    """Una guida che rimanda a voci che non esistono manda in giro l'operatore."""
    guida = logged_client.get("/guida/").get_data(as_text=True)
    assert voce in guida
    menu = logged_client.get("/", follow_redirects=True).get_data(as_text=True)
    assert voce in menu, "la guida nomina %r ma il menu non la contiene" % voce


def test_la_guida_spiega_le_zone_di_rete(logged_client):
    """Il contesto cambia i giudizi sulle esposizioni: chi legge la console deve
    trovare scritto perche' un riscontro non compare fra gli aperti."""
    testo = logged_client.get("/guida/").get_data(as_text=True)
    for atteso in (
        "Zone di rete",
        "Datacenter",
        "Rete ospiti",
        "come rete di utenza",   # chi non dichiara non viene premiato
        "non tocca le vulnerabilita' confermate",   # la zona parla di raggiungibilita'
        "Nulla viene cancellato",
    ):
        assert atteso in testo, "la guida non spiega %r" % atteso


def test_la_guida_elenca_gli_undici_generi_di_report(logged_client):
    """Un catalogo incompleto nella guida fa credere che un documento non esista."""
    testo = logged_client.get("/guida/").get_data(as_text=True)
    for genere in ("Sintesi esecutiva", "Inventario e valutazione tecnica",
                   "Esercizio NOC", "Postura di sicurezza (SOC)",
                   "Vulnerabilita' ed esposizioni", "Fascicolo di conformita'",
                   "Rapporto di incidente", "Segmentazione e zone di rete",
                   "Igiene dell'inventario", "Scheda dell'apparato",
                   "Conformita' europea"):
        assert genere in testo, "il catalogo della guida non nomina %r" % genere
    assert "elimina" in testo, "la guida non dice che un report si puo' eliminare"


def test_la_guida_distingue_il_silenzio_dalla_mancata_interrogazione(logged_client):
    """E' il difetto che l'operatore ha segnalato: la guida deve dire quale elenco
    guardare e che cosa significa."""
    testo = logged_client.get("/guida/").get_data(as_text=True)
    assert "Non interrogati" in testo
    assert "manca la copertura" in testo
