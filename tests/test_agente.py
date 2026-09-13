"""
snap - Test del canale fra le macchine sorvegliate e la sonda.

LA DIREZIONE, ANCORA UNA VOLTA
------------------------------
La sonda apre verso il server perche' il server non la raggiunge; l'agente apre verso
la sonda per la stessa ragione un piano piu' sotto. Una macchina in rete di utenza non
deve essere raggiungibile da nessuno, nemmeno dal prodotto che la sorveglia: un
servizio in ascolto su ogni postazione sarebbe una superficie in piu', per giunta
identica su tutte.

CHE COSA PROTEGGONO QUESTI TEST
-------------------------------
* Il **token** di registrazione vale una volta sola e scade. Un token che sopravvive
  al proprio scopo e' una credenziale che nessuno ricorda di aver lasciato in giro.
* La **firma** lega messaggio, identita', istante e nonce: chi non firma non entra,
  chi firma per un altro non entra, chi rigioca un invio catturato non entra, e chi
  arriva con un orologio fuori finestra nemmeno.
* Il rifiuto **non dice quale verifica non e' passata**: spiegarlo aiuterebbe solo
  chi sta provando. Nel diario della sonda invece si scrive per esteso.

remarks: Autore: Daniele Speziale - Data: 2026-09-13
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from conftest import prepara_accesso_sonda  # noqa: E402

UTC = "%Y-%m-%d %H:%M:%S"


@pytest.fixture()
def probe_app(tmp_path, monkeypatch, database_di_prova):
    """Applicativo sonda con archivio proprio e agente di raccolta non avviato."""
    import importlib

    from snapprobe import db as probe_db

    monkeypatch.setenv("SNAP_PROBE_DATABASE_URL", database_di_prova)
    probe_db.azzera_motore()
    monkeypatch.setenv("SNAP_PROBE_SECRET_KEY", "test-secret-key")

    import snapprobe
    import snapprobe.settings as probe_settings

    importlib.reload(probe_settings)
    importlib.reload(snapprobe)

    application = snapprobe.create_app(probe_settings.TestConfig, start_agent=False)
    return prepara_accesso_sonda(application)


@pytest.fixture()
def archivio(probe_app):
    return probe_app.extensions["snap_store"]


def _firma(chiave: str, agent_uid: str, marca: str, nonce: str, corpo: bytes) -> str:
    from snapprobe.agent_api import VERSIONE_PROTOCOLLO

    messaggio = b"|".join([VERSIONE_PROTOCOLLO.encode("ascii"),
                           agent_uid.encode("utf-8"), marca.encode("ascii"),
                           nonce.encode("ascii"), corpo])
    return hmac.new(chiave.encode("utf-8"), messaggio, hashlib.sha256).hexdigest()


def _invia(client, chiave, agent_uid, corpo: dict, marca: str = None,
           nonce: str = "nonce-1", firma: str = None):
    """Un invio firmato come lo manda l'agente vero."""
    corpo = dict(corpo)
    corpo["agent"] = agent_uid
    corpo["ts"] = marca or datetime.now(timezone.utc).strftime(UTC)
    corpo["nonce"] = nonce
    grezzo = json.dumps(corpo, separators=(",", ":")).encode("utf-8")
    intestazioni = {
        "Content-Type": "application/json",
        "X-Snap-Firma": firma or _firma(chiave, agent_uid, corpo["ts"],
                                        corpo["nonce"], grezzo),
    }
    return client.post("/api/agent/report", data=grezzo, headers=intestazioni)


def _registra(probe_app, archivio, hostname="collaudo"):
    """Emette un token dalla console e lo spende: come farebbe chi installa."""
    from snapprobe.agent_api import emetti_token

    with probe_app.app_context():
        emesso = emetti_token(archivio, "prova")
    risposta = probe_app.test_client().post(
        "/api/agent/enroll",
        json={"token": emesso["token"], "hostname": hostname,
              "sistema": "Linux", "versione": "1.0.0"})
    assert risposta.status_code == 200, risposta.data
    dati = risposta.get_json()
    return dati["agent"], dati["chiave"], emesso["token"]


# --------------------------------------------------------------------------- #
# Il canale esiste, e non racconta nulla di se'
# --------------------------------------------------------------------------- #
def test_ping_risponde_senza_credenziali(probe_app):
    risposta = probe_app.test_client(anonimo=True).get("/api/agent/ping")
    assert risposta.status_code == 200
    assert risposta.get_json()["pronto"] is True


def test_ping_non_rivela_nulla_della_sonda(probe_app):
    """Chi bussa senza credenziali non ha diritto a un inventario."""
    risposta = probe_app.test_client(anonimo=True).get("/api/agent/ping")
    corpo = risposta.get_json()
    assert set(corpo) == {"protocollo", "pronto"}


# --------------------------------------------------------------------------- #
# La registrazione
# --------------------------------------------------------------------------- #
def test_registrazione_con_token_valido(probe_app, archivio):
    agent_uid, chiave, _ = _registra(probe_app, archivio)
    assert agent_uid
    assert len(chiave) >= 40
    assert archivio.agenti_attivi() == 1


def test_token_vale_una_volta_sola(probe_app, archivio):
    _, _, token = _registra(probe_app, archivio)
    risposta = probe_app.test_client().post(
        "/api/agent/enroll", json={"token": token, "hostname": "seconda"})
    assert risposta.status_code == 403
    assert archivio.agenti_attivi() == 1


def test_token_scaduto_non_registra(probe_app, archivio):
    from snapprobe.agent_api import impronta

    scaduto = "token-vecchio"
    ieri = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime(UTC)
    archivio.agent_token_emetti(impronta(scaduto), "vecchio", ieri)
    risposta = probe_app.test_client().post(
        "/api/agent/enroll", json={"token": scaduto, "hostname": "tardiva"})
    assert risposta.status_code == 403
    assert archivio.agenti_attivi() == 0


def test_token_inventato_non_registra(probe_app, archivio):
    risposta = probe_app.test_client().post(
        "/api/agent/enroll", json={"token": "mai-emesso", "hostname": "intrusa"})
    assert risposta.status_code == 403


def test_registrazione_senza_hostname_rifiutata(probe_app, archivio):
    from snapprobe.agent_api import emetti_token

    with probe_app.app_context():
        emesso = emetti_token(archivio, "")
    risposta = probe_app.test_client().post(
        "/api/agent/enroll", json={"token": emesso["token"]})
    assert risposta.status_code == 400


# --------------------------------------------------------------------------- #
# L'invio: la firma, l'orologio, il nonce
# --------------------------------------------------------------------------- #
def test_invio_firmato_viene_accettato(probe_app, archivio):
    agent_uid, chiave, _ = _registra(probe_app, archivio)
    risposta = _invia(probe_app.test_client(), chiave, agent_uid,
                      {"misure": {"cpu": 12.5, "memoria": 40.0},
                       "eventi": [{"genere": "utente_nuovo",
                                   "messaggio": "creato l'utente pippo",
                                   "gravita": "alta"}]})
    assert risposta.status_code == 200
    corpo = risposta.get_json()
    assert corpo["ricevuto"] is True
    assert corpo["eventi_accettati"] == 1
    assert len(archivio.agent_metriche_recenti(agent_uid)) == 1


def test_invio_senza_firma_respinto(probe_app, archivio):
    agent_uid, _, _ = _registra(probe_app, archivio)
    risposta = probe_app.test_client().post(
        "/api/agent/report",
        json={"agent": agent_uid, "ts": datetime.now(timezone.utc).strftime(UTC),
              "nonce": "n", "misure": {"cpu": 1}})
    assert risposta.status_code == 401


def test_firma_con_chiave_sbagliata_respinta(probe_app, archivio):
    agent_uid, _, _ = _registra(probe_app, archivio)
    risposta = _invia(probe_app.test_client(), "chiave-che-non-e-sua", agent_uid,
                      {"misure": {"cpu": 1}})
    assert risposta.status_code == 401


def test_corpo_alterato_dopo_la_firma_respinto(probe_app, archivio):
    """La firma copre il CORPO ESATTO: cambiarne un byte la invalida."""
    agent_uid, chiave, _ = _registra(probe_app, archivio)
    marca = datetime.now(timezone.utc).strftime(UTC)
    onesto = json.dumps({"agent": agent_uid, "ts": marca, "nonce": "n1",
                         "misure": {"cpu": 1}}, separators=(",", ":")).encode("utf-8")
    firma = _firma(chiave, agent_uid, marca, "n1", onesto)
    alterato = onesto.replace(b'"cpu":1', b'"cpu":9')
    risposta = probe_app.test_client().post(
        "/api/agent/report", data=alterato,
        headers={"Content-Type": "application/json", "X-Snap-Firma": firma})
    assert risposta.status_code == 401


def test_marca_temporale_vecchia_respinta(probe_app, archivio):
    from snapprobe.agent_api import FINESTRA_SEC

    agent_uid, chiave, _ = _registra(probe_app, archivio)
    vecchia = (datetime.now(timezone.utc)
               - timedelta(seconds=FINESTRA_SEC + 60)).strftime(UTC)
    risposta = _invia(probe_app.test_client(), chiave, agent_uid,
                      {"misure": {"cpu": 1}}, marca=vecchia)
    assert risposta.status_code == 401


def test_marca_temporale_nel_futuro_respinta(probe_app, archivio):
    from snapprobe.agent_api import FINESTRA_SEC

    agent_uid, chiave, _ = _registra(probe_app, archivio)
    futura = (datetime.now(timezone.utc)
              + timedelta(seconds=FINESTRA_SEC + 60)).strftime(UTC)
    risposta = _invia(probe_app.test_client(), chiave, agent_uid,
                      {"misure": {"cpu": 1}}, marca=futura)
    assert risposta.status_code == 401


def test_invio_ripetuto_respinto(probe_app, archivio):
    """Lo stesso messaggio, rigiocato tale e quale, non deve passare due volte."""
    agent_uid, chiave, _ = _registra(probe_app, archivio)
    marca = datetime.now(timezone.utc).strftime(UTC)
    corpo = {"agent": agent_uid, "ts": marca, "nonce": "sempre-lo-stesso",
             "misure": {"cpu": 3}}
    grezzo = json.dumps(corpo, separators=(",", ":")).encode("utf-8")
    intestazioni = {"Content-Type": "application/json",
                    "X-Snap-Firma": _firma(chiave, agent_uid, marca,
                                           "sempre-lo-stesso", grezzo)}
    client = probe_app.test_client()
    assert client.post("/api/agent/report", data=grezzo,
                       headers=intestazioni).status_code == 200
    assert client.post("/api/agent/report", data=grezzo,
                       headers=intestazioni).status_code == 401


def test_agente_revocato_non_entra_piu(probe_app, archivio):
    agent_uid, chiave, _ = _registra(probe_app, archivio)
    archivio.agent_revoca(agent_uid)
    risposta = _invia(probe_app.test_client(), chiave, agent_uid,
                      {"misure": {"cpu": 1}}, nonce="dopo-la-revoca")
    assert risposta.status_code == 401


def test_il_rifiuto_non_dice_quale_verifica_non_e_passata(probe_app, archivio):
    """Distinguere i motivi aiuterebbe soltanto chi sta provando."""
    agent_uid, chiave, _ = _registra(probe_app, archivio)
    senza_firma = probe_app.test_client().post(
        "/api/agent/report",
        json={"agent": agent_uid, "ts": datetime.now(timezone.utc).strftime(UTC),
              "nonce": "x"})
    chiave_sbagliata = _invia(probe_app.test_client(), "altra", agent_uid,
                              {"misure": {"cpu": 1}}, nonce="y")
    assert senza_firma.get_json() == chiave_sbagliata.get_json()


def test_il_diario_della_sonda_invece_lo_dice(probe_app, archivio):
    """Chi installa un agente deve poter capire perche' non entra."""
    agent_uid, _, _ = _registra(probe_app, archivio)
    _invia(probe_app.test_client(), "chiave-sbagliata", agent_uid,
           {"misure": {"cpu": 1}}, nonce="z")
    diario = " ".join(r["message"] for r in archivio.recent_events(20))
    assert "firma non valida" in diario


# --------------------------------------------------------------------------- #
# La risposta porta la configurazione, non un comando
# --------------------------------------------------------------------------- #
def test_la_risposta_porta_la_configurazione(probe_app, archivio):
    from snapprobe.agent_api import INTERVALLO_PREDEFINITO

    agent_uid, chiave, _ = _registra(probe_app, archivio)
    corpo = _invia(probe_app.test_client(), chiave, agent_uid,
                   {"misure": {"cpu": 1}}).get_json()
    assert corpo["configurazione"]["intervallo"] == INTERVALLO_PREDEFINITO
    assert "soglie" in corpo["configurazione"]


def test_la_risposta_non_contiene_comandi(probe_app, archivio):
    """L'agente non esegue nulla per conto della sonda: non c'e' un canale per farlo."""
    agent_uid, chiave, _ = _registra(probe_app, archivio)
    corpo = _invia(probe_app.test_client(), chiave, agent_uid,
                   {"misure": {"cpu": 1}}).get_json()
    for chiave_vietata in ("comandi", "comando", "esegui", "commands", "exec"):
        assert chiave_vietata not in corpo


# --------------------------------------------------------------------------- #
# Gli eventi diventano rilevazioni, e si esaminano una volta sola
# --------------------------------------------------------------------------- #
def test_evento_di_sicurezza_diventa_una_rilevazione(probe_app, archivio):
    from snapprobe.ids import MotoreIDS, SensoreAgenti

    agent_uid, chiave, _ = _registra(probe_app, archivio)
    _invia(probe_app.test_client(), chiave, agent_uid,
           {"eventi": [{"genere": "sicurezza_ferma", "gravita": "critica",
                        "soggetto": "Defender",
                        "messaggio": "protezione in tempo reale disattivata",
                        "dati": {"servizio": "WinDefend"}}]})
    esito = MotoreIDS(archivio, sensori=[SensoreAgenti()]).esegui()
    assert esito["nuove"] == 1
    rilevazione = archivio.ids_rilevazioni()[0]
    assert rilevazione["regola"] == "SICUREZZA-FERMA"
    assert rilevazione["gravita"] == "critica"


def test_un_evento_si_esamina_una_volta_sola(probe_app, archivio):
    from snapprobe.ids import MotoreIDS, SensoreAgenti

    agent_uid, chiave, _ = _registra(probe_app, archivio)
    _invia(probe_app.test_client(), chiave, agent_uid,
           {"eventi": [{"genere": "utente_nuovo", "gravita": "alta",
                        "messaggio": "creato l'utente pippo"}]})
    MotoreIDS(archivio, sensori=[SensoreAgenti()]).esegui()
    assert archivio.agent_eventi_da_esaminare() == []


def test_accessi_falliti_sotto_soglia_non_allarmano(probe_app, archivio):
    """Tre tentativi sbagliati sono una password dimenticata, non un attacco."""
    from snapprobe.ids import MotoreIDS, SensoreAgenti

    agent_uid, chiave, _ = _registra(probe_app, archivio)
    _invia(probe_app.test_client(), chiave, agent_uid,
           {"eventi": [{"genere": "accessi_falliti", "gravita": "media",
                        "messaggio": "3 accessi falliti",
                        "dati": {"quanti": 3, "soglia": 5}}]})
    esito = MotoreIDS(archivio, sensori=[SensoreAgenti()]).esegui()
    assert esito["nuove"] == 0


def test_evento_senza_genere_o_messaggio_viene_scartato(probe_app, archivio):
    agent_uid, chiave, _ = _registra(probe_app, archivio)
    corpo = _invia(probe_app.test_client(), chiave, agent_uid,
                   {"eventi": [{"genere": "", "messaggio": "senza genere"},
                               {"genere": "utente_nuovo", "messaggio": ""},
                               "non e' nemmeno un oggetto"]}).get_json()
    assert corpo["eventi_accettati"] == 0


# --------------------------------------------------------------------------- #
# I gruppi: il catalogo, la scelta, e cio' che si dichiara
# --------------------------------------------------------------------------- #
def _agente():
    """Il modulo dell'agente, caricato dal file: non e' un pacchetto installabile."""
    import importlib.util
    from pathlib import Path

    percorso = Path(__file__).resolve().parent.parent / "agent" / "snap_agent.py"
    specifica = importlib.util.spec_from_file_location("snap_agent", percorso)
    modulo = importlib.util.module_from_spec(specifica)
    specifica.loader.exec_module(modulo)
    return modulo


def test_ogni_gruppo_ha_un_raccoglitore():
    """Il catalogo mostrato a chi sceglie e le funzioni che raccolgono sono due
    elenchi: se divergono, un gruppo si accende e non manda niente."""
    modulo = _agente()
    raccoglitori = modulo.Raccolta()._raccoglitori()
    assert set(modulo.GRUPPI) == set(raccoglitori), (
        "solo nel catalogo %s, solo fra i raccoglitori %s"
        % (sorted(set(modulo.GRUPPI) - set(raccoglitori)),
           sorted(set(raccoglitori) - set(modulo.GRUPPI))))


def test_ogni_gruppo_dichiara_che_cosa_manda_e_se_riguarda_le_persone():
    """E' quello che chi installa legge per decidere, e quello che il titolare del
    trattamento deve poter leggere senza aprire il codice."""
    modulo = _agente()
    for codice, voce in modulo.GRUPPI.items():
        assert voce["cadenza"] in ("veloce", "lento"), codice
        assert len(voce.get("descrizione", "")) > 30, codice
        assert isinstance(voce.get("personali"), bool), codice
        assert voce.get("privilegi"), codice


def test_il_catalogo_dei_gruppi_e_lo_stesso_nella_console():
    """La console rispecchia il catalogo per poter NOMINARE cio' che non misura."""
    from snapserver.blueprints.ids_views import GRUPPI_AGENTE

    modulo = _agente()
    assert set(modulo.GRUPPI) == set(GRUPPI_AGENTE), (
        "solo nell'agente %s, solo nella console %s"
        % (sorted(set(modulo.GRUPPI) - set(GRUPPI_AGENTE)),
           sorted(set(GRUPPI_AGENTE) - set(modulo.GRUPPI))))


def test_la_preselezione_minima_non_riguarda_le_persone():
    """E' la ragione per cui esiste: si usa dove il trattamento non e' concordato."""
    modulo = _agente()
    for codice in modulo.PRESELEZIONI["minimo"]:
        assert not modulo.GRUPPI[codice]["personali"], (
            "%s riguarda le persone e sta nella preselezione minima" % codice)


def test_i_gruppi_spenti_si_dichiarano():
    """Un gruppo spento non e' un gruppo a zero: la console deve poterlo dire."""
    modulo = _agente()
    raccolta = modulo.Raccolta(gruppi=("carico", "dischi"))
    misure = raccolta.misure()
    assert set(misure["gruppi_attivi"]) == {"carico", "dischi"}
    assert "software" in misure["gruppi_spenti"]
    assert "utenze" in misure["gruppi_spenti"]


def test_un_gruppo_sconosciuto_non_ferma_l_agente():
    """Una configurazione scritta da una versione piu' nuova non deve bloccare."""
    modulo = _agente()
    assert modulo.gruppi_scelti({"gruppi": ["carico", "gruppo-del-futuro"]}) == ("carico",)


def test_senza_scelta_si_raccoglie_tutto():
    modulo = _agente()
    assert modulo.gruppi_scelti({}) == modulo.GRUPPI_PREDEFINITI
    assert set(modulo.GRUPPI_PREDEFINITI) == set(modulo.GRUPPI)


def test_configura_senza_domande_salva_la_scelta(tmp_path):
    modulo = _agente()
    percorso = str(tmp_path / "agente.json")
    argomenti = SimpleNamespace(configurazione=percorso, gruppi="minimo")
    assert modulo.comando_configura(argomenti) == 0
    assert modulo.leggi_configurazione(percorso)["gruppi"] == list(
        modulo.PRESELEZIONI["minimo"])


def test_configura_rifiuta_un_gruppo_inventato(tmp_path):
    """Meglio fermarsi che accendere silenziosamente qualcos'altro."""
    modulo = _agente()
    argomenti = SimpleNamespace(configurazione=str(tmp_path / "a.json"),
                                gruppi="carico,inventato")
    with pytest.raises(SystemExit) as errore:
        modulo.comando_configura(argomenti)
    assert "inventato" in str(errore.value)


# --------------------------------------------------------------------------- #
# La serie storica e l'inventario sono due cose
# --------------------------------------------------------------------------- #
def test_le_misure_non_portano_l_inventario():
    """Misurato: insieme pesavano 99 MB al giorno per macchina, per ripetersi."""
    modulo = _agente()
    raccolta = modulo.Raccolta(gruppi=("carico", "dischi", "software", "utenze"))
    misure = raccolta.misure()
    for lento in ("software", "utenze"):
        assert lento not in misure, "%s viaggia con le misure" % lento
    for veloce in ("carico", "dischi"):
        assert veloce in misure


def test_l_inventario_arriva_una_volta_e_poi_tace():
    modulo = _agente()
    raccolta = modulo.Raccolta(gruppi=("utenze",))
    assert raccolta.inventario(adesso_mono=1000.0) is not None
    assert raccolta.inventario(adesso_mono=1060.0) is None, "ripetuto dopo un minuto"
    dopo = raccolta.inventario(adesso_mono=1000.0 + modulo.CADENZA_LENTA_SEC + 1)
    assert dopo is not None, "non ripetuto dopo la cadenza"


def test_l_inventario_parte_subito_se_cambiano_le_porte_in_ascolto():
    """Una porta nuova non aspetta l'ora: e' cio' per cui si guarda quella pagina."""
    modulo = _agente()
    raccolta = modulo.Raccolta(gruppi=("in_ascolto",))
    raccolta._ascolto_corrente = [{"porta": 22, "processo": "sshd",
                                   "utente": "root", "pubblica": True}]
    assert raccolta.inventario(adesso_mono=1000.0) is not None
    assert raccolta.inventario(adesso_mono=1060.0) is None

    raccolta._ascolto_corrente = [
        {"porta": 22, "processo": "sshd", "utente": "root", "pubblica": True},
        {"porta": 4444, "processo": "nc", "utente": "mrossi", "pubblica": True}]
    subito = raccolta.inventario(adesso_mono=1120.0)
    assert subito is not None
    assert subito["motivo"] == "porte in ascolto cambiate"


def test_senza_gruppi_lenti_non_esiste_inventario():
    modulo = _agente()
    raccolta = modulo.Raccolta(gruppi=("carico",))
    assert raccolta.inventario(adesso_mono=1000.0) is None


def test_la_sonda_conserva_l_inventario_come_stato(probe_app, archivio):
    """Sostituisce, non accoda: l'inventario di martedi' non serve a nessuno."""
    agent_uid, chiave, _ = _registra(probe_app, archivio)
    _invia(probe_app.test_client(), chiave, agent_uid,
           {"misure": {"cpu": 5.0},
            "inventario": {"rilevato_at": "2026-09-13 10:00:00",
                           "software": [{"nome": "nginx", "versione": "1.24"}],
                           "gruppi_spenti": ["container"]}},
           nonce="inv-1")
    _invia(probe_app.test_client(), chiave, agent_uid,
           {"misure": {"cpu": 6.0},
            "inventario": {"rilevato_at": "2026-09-13 11:00:00",
                           "software": [{"nome": "nginx", "versione": "1.26"}],
                           "gruppi_spenti": []}},
           nonce="inv-2")
    conservato = archivio.agent_inventario(agent_uid)
    assert conservato["software"] == [{"nome": "nginx", "versione": "1.26"}]
    # Due invii, due misure, UN inventario.
    assert len(archivio.agent_metriche_recenti(agent_uid)) == 2


def test_un_invio_senza_inventario_non_cancella_quello_che_c_era(probe_app, archivio):
    """L'inventario arriva una volta all'ora: negli altri 59 invii non c'e'."""
    agent_uid, chiave, _ = _registra(probe_app, archivio)
    _invia(probe_app.test_client(), chiave, agent_uid,
           {"misure": {"cpu": 5.0},
            "inventario": {"rilevato_at": "2026-09-13 10:00:00",
                           "software": [{"nome": "nginx"}]}}, nonce="con")
    _invia(probe_app.test_client(), chiave, agent_uid,
           {"misure": {"cpu": 6.0}}, nonce="senza")
    assert archivio.agent_inventario(agent_uid)["software"] == [{"nome": "nginx"}]


def test_si_conferisce_al_server_solo_cio_che_e_cambiato(probe_app, archivio):
    """Il record ripartiva a ogni battito: ogni quindici secondi, identico."""
    agent_uid, chiave, _ = _registra(probe_app, archivio)
    assert len(archivio.agenti_da_conferire()) == 1, "una macchina nuova va conferita"
    archivio.agenti_segna_conferiti(archivio.agenti_da_conferire())
    assert archivio.agenti_da_conferire() == [], "niente e' cambiato: niente da dire"

    _invia(probe_app.test_client(), chiave, agent_uid, {"misure": {"cpu": 1.0}},
           nonce="uno")
    assert len(archivio.agenti_da_conferire()) == 1, "ha mandato: va riconferita"


# --------------------------------------------------------------------------- #
# Il pacchetto di installazione
# --------------------------------------------------------------------------- #
# Il pacchetto E' UNA CREDENZIALE: contiene un token valido. Questi test verificano
# che contenga tutto quello che serve su una macchina che non ha il repository, che il
# token dentro funzioni davvero una volta sola, e che gli installatori restino
# eseguibili dopo essere passati per uno zip -- un installatore che non parte, con un
# messaggio che dice solo "permission denied", fa perdere un pomeriggio.
def _scarica(probe_app, etichetta="server di posta"):
    risposta = probe_app.test_client().post(
        "/agenti/pacchetto", data={"etichetta": etichetta, "verifica_tls": "1"})
    assert risposta.status_code == 200, risposta.data[:200]
    return risposta


def test_il_pacchetto_si_scarica_come_zip(probe_app, archivio):
    risposta = _scarica(probe_app)
    assert risposta.headers["Content-Type"] == "application/zip"
    assert "attachment" in risposta.headers["Content-Disposition"]
    assert "server-di-posta" in risposta.headers["Content-Disposition"]


def test_il_pacchetto_non_si_mette_in_cache(probe_app, archivio):
    """Dentro c'e' una credenziale: nessuna cache, ne' del browser ne' del proxy."""
    risposta = _scarica(probe_app)
    assert "no-store" in risposta.headers.get("Cache-Control", "")


def test_il_pacchetto_contiene_tutto_cio_che_serve(probe_app, archivio):
    """Chi lo riceve non ha il repository: se manca un pezzo, lo scopre sul posto."""
    import io as _io
    import zipfile

    with zipfile.ZipFile(_io.BytesIO(_scarica(probe_app).data)) as pacchetto:
        dentro = set(pacchetto.namelist())
    for atteso in ("snap-agent/snap_agent.py", "snap-agent/pacchetto.json",
                   "snap-agent/requirements.txt", "snap-agent/LEGGIMI.md",
                   "snap-agent/installa.ps1", "snap-agent/installa.sh",
                   "snap-agent/disinstalla.ps1", "snap-agent/disinstalla.sh",
                   "snap-agent/docker/Dockerfile",
                   "snap-agent/docker/docker-compose.yml",
                   "snap-agent/docker/avvio.sh", "snap-agent/docker/.env.example"):
        assert atteso in dentro, "manca dal pacchetto: %s" % atteso


def test_gli_installatori_restano_eseguibili(probe_app, archivio):
    """Uno zip conserva i permessi solo se glieli si scrive."""
    import io as _io
    import zipfile

    with zipfile.ZipFile(_io.BytesIO(_scarica(probe_app).data)) as pacchetto:
        permessi = {i.filename: (i.external_attr >> 16) & 0o777
                    for i in pacchetto.infolist()}
    for eseguibile in ("snap-agent/installa.sh", "snap-agent/disinstalla.sh",
                       "snap-agent/docker/avvio.sh"):
        assert permessi[eseguibile] & 0o111, "%s non e' eseguibile" % eseguibile
    # E la configurazione con dentro il token NON e' leggibile da chiunque.
    assert permessi["snap-agent/pacchetto.json"] == 0o600


def test_il_manifesto_dice_dove_chiamare_e_quando_scade(probe_app, archivio):
    import io as _io
    import json as _json
    import zipfile

    with zipfile.ZipFile(_io.BytesIO(_scarica(probe_app).data)) as pacchetto:
        manifesto = _json.loads(pacchetto.read("snap-agent/pacchetto.json"))
    assert manifesto["sonda"].startswith("http")
    assert manifesto["token"]
    assert manifesto["scade_at"]
    assert manifesto["verifica_tls"] is True
    assert manifesto["etichetta"] == "server di posta"
    # L'avvertenza sta nel file, non solo nella pagina: chi apre il file lo legge
    # prima di copiarlo altrove.
    assert "una volta sola" in manifesto["avvertenza"]


def test_il_token_del_pacchetto_registra_davvero_una_macchina(probe_app, archivio):
    """La prova che conta: il pacchetto serve a registrare, non a sembrare completo."""
    import io as _io
    import json as _json
    import zipfile

    with zipfile.ZipFile(_io.BytesIO(_scarica(probe_app).data)) as pacchetto:
        manifesto = _json.loads(pacchetto.read("snap-agent/pacchetto.json"))
    risposta = probe_app.test_client().post(
        "/api/agent/enroll",
        json={"token": manifesto["token"], "hostname": "dal-pacchetto"})
    assert risposta.status_code == 200, risposta.data
    assert archivio.agenti_attivi() == 1


def test_un_pacchetto_vale_per_una_macchina_sola(probe_app, archivio):
    """Una credenziale condivisa fra venti macchine non si revoca per una sola."""
    import io as _io
    import json as _json
    import zipfile

    with zipfile.ZipFile(_io.BytesIO(_scarica(probe_app).data)) as pacchetto:
        manifesto = _json.loads(pacchetto.read("snap-agent/pacchetto.json"))
    primo = probe_app.test_client().post(
        "/api/agent/enroll", json={"token": manifesto["token"], "hostname": "prima"})
    secondo = probe_app.test_client().post(
        "/api/agent/enroll", json={"token": manifesto["token"], "hostname": "seconda"})
    assert primo.status_code == 200
    assert secondo.status_code == 403
    assert archivio.agenti_attivi() == 1


def test_l_agente_nel_pacchetto_e_quello_del_prodotto(probe_app, archivio):
    """Non una copia: lo stesso file. Due copie divergono, e quella spedita e' la
    peggiore delle due da correggere."""
    import io as _io
    import zipfile
    from pathlib import Path

    with zipfile.ZipFile(_io.BytesIO(_scarica(probe_app).data)) as pacchetto:
        spedito = pacchetto.read("snap-agent/snap_agent.py")
    sorgente = (Path(__file__).resolve().parent.parent / "agent"
                / "snap_agent.py").read_bytes()
    assert spedito == sorgente


def test_lo_scaricamento_resta_nel_diario(probe_app, archivio):
    """Fra un mese si deve poter sapere chi ha chiesto che cosa."""
    _scarica(probe_app, etichetta="reception")
    diario = " ".join(r["message"] for r in archivio.recent_events(20))
    assert "Pacchetto di installazione agente" in diario
    assert "reception" in diario


def test_il_pacchetto_richiede_l_accesso(probe_app):
    """E' una credenziale: non si scarica senza essere entrati."""
    risposta = probe_app.test_client(anonimo=True).post("/agenti/pacchetto")
    assert risposta.status_code in (302, 401, 403)


# --------------------------------------------------------------------------- #
# Le pagine locali della sonda
# --------------------------------------------------------------------------- #
# Si vedono anche quando il collegamento con la sede e' interrotto: chi e' davanti
# alla sonda deve poter capire che cosa sta succedendo senza dipendere dalla rete
# geografica, che e' proprio cio' che potrebbe mancare nel momento in cui serve.
def test_la_pagina_ids_della_sonda_risponde(probe_app, archivio):
    risposta = probe_app.test_client().get("/ids")
    assert risposta.status_code == 200
    testo = risposta.get_data(as_text=True)
    # Il limite deve stare sulla pagina, non nella documentazione soltanto.
    assert "Non ispeziona il traffico" in testo


def test_la_pagina_ids_dichiara_i_sensori_che_non_osservano(probe_app, archivio):
    """Lo zero di un sensore spento non e' una buona notizia, e la pagina lo dice."""
    testo = probe_app.test_client().get("/ids").get_data(as_text=True)
    assert "predisposto e non attivo" in testo


def test_la_pagina_agenti_della_sonda_risponde(probe_app, archivio):
    risposta = probe_app.test_client().get("/agenti")
    assert risposta.status_code == 200
    assert "Agenti di macchina" in risposta.get_data(as_text=True)


def test_le_pagine_locali_reggono_una_macchina_registrata(probe_app, archivio):
    """Con dati veri, non solo con l'archivio vuoto."""
    agent_uid, chiave, _ = _registra(probe_app, archivio)
    _invia(probe_app.test_client(), chiave, agent_uid,
           {"misure": {"cpu": 5.0, "memoria": 30.0},
            "eventi": [{"genere": "sicurezza_ferma", "gravita": "critica",
                        "messaggio": "antivirus fermo"}]})
    pagina = probe_app.test_client().get("/agenti")
    assert pagina.status_code == 200
    assert agent_uid in pagina.get_data(as_text=True)


def test_le_pagine_locali_richiedono_l_accesso(probe_app):
    """Sono pagine dell'interfaccia, non del canale degli agenti."""
    anonimo = probe_app.test_client(anonimo=True)
    for percorso in ("/ids", "/agenti"):
        risposta = anonimo.get(percorso)
        assert risposta.status_code in (302, 401, 403), percorso


# --------------------------------------------------------------------------- #
# Una condizione che dura si dice una volta, non a ogni invio
# --------------------------------------------------------------------------- #
def _raccolta():
    """La sola `Raccolta`, senza importare il modulo come script."""
    import importlib.util
    from pathlib import Path

    percorso = Path(__file__).resolve().parent.parent / "agent" / "snap_agent.py"
    specifica = importlib.util.spec_from_file_location("snap_agent", percorso)
    modulo = importlib.util.module_from_spec(specifica)
    specifica.loader.exec_module(modulo)
    return modulo


def test_un_disco_pieno_si_dice_una_volta_sola():
    """Cento righe identiche in un'ora seppelliscono quella nuova.

    E' successo sul collaudo vero: centootto eventi `disco_pieno` in ventiquattr'ore,
    tutti uguali, e la pagina degli eventi non serviva piu' a niente.
    """
    modulo = _raccolta()
    raccolta = modulo.Raccolta({"disco_percento": 90})
    misure = {"dischi": [{"punto": "C:\\", "percento": 97.7, "totale_gb": 475.8}]}

    assert len(raccolta._soglie(misure)) == 1, "la prima volta si dice"
    assert raccolta._soglie(misure) == [], "la seconda no"
    # Un decimo di punto in piu' non e' una notizia.
    misure["dischi"][0]["percento"] = 97.9
    assert raccolta._soglie(misure) == []


def test_un_disco_che_peggiora_di_una_fascia_si_ridice():
    modulo = _raccolta()
    raccolta = modulo.Raccolta({"disco_percento": 90})
    misure = {"dischi": [{"punto": "/", "percento": 91.0, "totale_gb": 100}]}
    assert len(raccolta._soglie(misure)) == 1
    misure["dischi"][0]["percento"] = 96.0
    assert len(raccolta._soglie(misure)) == 1, "cambiata la fascia: si ridice"


def test_un_disco_tornato_sotto_soglia_si_dimentica():
    """Se risale, si deve ridire subito: non si aspetta il riarmo."""
    modulo = _raccolta()
    raccolta = modulo.Raccolta({"disco_percento": 90})
    pieno = {"dischi": [{"punto": "/", "percento": 92.0, "totale_gb": 100}]}
    vuoto = {"dischi": [{"punto": "/", "percento": 40.0, "totale_gb": 100}]}
    assert len(raccolta._soglie(pieno)) == 1
    assert raccolta._soglie(vuoto) == []
    assert len(raccolta._soglie(pieno)) == 1


def test_una_condizione_che_dura_si_riarma_dopo_il_tempo_dichiarato():
    """Un problema che persiste non deve nemmeno sparire in silenzio."""
    modulo = _raccolta()
    raccolta = modulo.Raccolta({"disco_percento": 90})
    misure = {"dischi": [{"punto": "/", "percento": 92.0, "totale_gb": 100}]}
    assert len(raccolta._soglie(misure)) == 1
    # Si sposta indietro l'istante dell'ultima volta, invece di aspettare sei ore.
    stato, quando = raccolta._condizioni[("disco_pieno", "/")]
    raccolta._condizioni[("disco_pieno", "/")] = (stato,
                                                  quando - modulo.RIARMO_SEC - 1)
    assert len(raccolta._soglie(misure)) == 1


# --------------------------------------------------------------------------- #
# L'agente stesso: quello che dichiara e quello che tace
# --------------------------------------------------------------------------- #
def test_l_agente_non_apre_porte():
    """Il sorgente dell'agente non deve mettersi in ascolto da nessuna parte.

    E' la regola architetturale che giustifica l'intero protocollo: se un giorno
    qualcuno aggiungesse un piccolo server "per comodita' di debug", ogni postazione
    del cliente diventerebbe raggiungibile. Si controlla qui, non a parole.
    """
    import re
    from pathlib import Path

    sorgente = (Path(__file__).resolve().parent.parent / "agent"
                / "snap_agent.py").read_text(encoding="utf-8")
    for vietato in (r"\.bind\(", r"\.listen\(", r"socketserver", r"HTTPServer",
                    r"Flask\("):
        assert not re.search(vietato, sorgente), (
            "l'agente non deve mettersi in ascolto: trovato %s" % vietato)


def test_l_agente_dichiara_i_guasti_invece_di_tacere():
    """Una misura mancante deve dirsi: uno zero silenzioso e' una bugia."""
    from pathlib import Path

    sorgente = (Path(__file__).resolve().parent.parent / "agent"
                / "snap_agent.py").read_text(encoding="utf-8")
    assert "guasti" in sorgente
