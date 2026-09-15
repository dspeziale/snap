# -----------------------------------------------------------------
# test_cattura_processo.py — la cattura deve girare dove i pacchetti si travasano
# Autore: Daniele Speziale
# Data creazione: 2026-09-15
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap probe - Accendere l'osservazione dalla pagina deve far comparire i pacchetti.

IL DIFETTO, riferito da chi la usava: "i pacchetti vengono intercettati ma non
vengono visualizzati sulla pagina pacchetti".

LA CAUSA. La sonda gira in DUE processi: l'interfaccia e l'agente di raccolta.
L'anello dei pacchetti letti vive nel processo che cattura; il travaso nell'archivio
-- l'unica strada per cui la pagina possa mostrarli -- lo fa `_travasa_traffico`, che
sta nel ciclo dell'AGENTE. Accendendo l'osservazione dalla pagina era pero'
l'INTERFACCIA a chiamare `avvia_cattura()`: i pacchetti finivano in un anello che
nessuno svuotava, e la pagina restava vuota mentre il diario diceva "avviata" e il
sensore risultava attivo.

Misurato sull'installazione reale: zero righe per cinque minuti con l'osservazione
accesa dalla pagina; 744 righe in quarantacinque secondi dopo un riavvio, cioe' con
la cattura avviata dall'agente.

LA CORREZIONE: l'impostazione e' l'unica fonte di verita', e l'agente allinea a ogni
giro cio' che gira con cio' che e' stato chiesto.

remarks: Autore: Daniele Speziale - Data: 2026-09-15
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

RADICE = Path(__file__).resolve().parent.parent


class _PresaFinta:
    """Una cattura che non tocca la rete: registra soltanto che le e' stato chiesto."""

    def __init__(self, viva: bool = True):
        self._viva = viva
        self.fermata = False
        self.osservatorio = None

    def stato(self) -> dict:
        return {"viva": self._viva}

    def ferma(self) -> None:
        self._viva = False
        self.fermata = True


@pytest.fixture()
def agente(probe_store):
    from snapprobe.agent import ProbeAgent

    return ProbeAgent(probe_store, "prova")


@pytest.fixture()
def probe_app(monkeypatch, database_di_prova):
    from conftest import prepara_accesso_sonda
    from snapprobe import db as probe_db

    monkeypatch.setenv("SNAP_PROBE_DATABASE_URL", database_di_prova)
    probe_db.azzera_motore()
    monkeypatch.setenv("SNAP_PROBE_SECRET_KEY", "test-secret-key")

    import snapprobe
    import snapprobe.settings as probe_settings

    importlib.reload(probe_settings)
    importlib.reload(snapprobe)
    applicazione = snapprobe.create_app(probe_settings.TestConfig, start_agent=False)
    return prepara_accesso_sonda(applicazione)


def _accendi(store, interfaccia="eth0", filtro=""):
    from snapprobe import ids as modulo_ids

    store.set_settings({modulo_ids.CHIAVE_TRAFFICO_ATTIVO: "1",
                        modulo_ids.CHIAVE_TRAFFICO_INTERFACCIA: interfaccia,
                        modulo_ids.CHIAVE_TRAFFICO_FILTRO: filtro})


# --------------------------------------------------------------------------- #
# L'agente allinea
# --------------------------------------------------------------------------- #
def test_l_agente_avvia_la_cattura_accesa_dalla_pagina(agente, probe_store, monkeypatch):
    """E' il caso che non funzionava: si accende dalla pagina, senza riavviare."""
    avvii = []
    monkeypatch.setattr(agente, "avvia_cattura",
                        lambda: avvii.append(1) or {"attiva": True})
    _accendi(probe_store)

    assert agente._allinea_cattura() == "avviata"
    assert len(avvii) == 1


def test_l_agente_ferma_la_cattura_spenta_dalla_pagina(agente, probe_store):
    from snapprobe import ids as modulo_ids

    presa = _PresaFinta()
    agente._cattura = presa
    probe_store.set_setting(modulo_ids.CHIAVE_TRAFFICO_ATTIVO, "0")

    assert agente._allinea_cattura() == "spenta"
    assert presa.fermata


def test_una_cattura_gia_in_corso_non_si_riavvia_a_ogni_giro(agente, probe_store,
                                                             monkeypatch):
    """Riavviarla ogni quindici secondi perderebbe pacchetti a ogni giro, e il
    difetto sarebbe piu' sottile di quello che si sta correggendo."""
    avvii = []
    monkeypatch.setattr(agente, "avvia_cattura",
                        lambda: avvii.append(1) or {"attiva": True})
    _accendi(probe_store)
    agente._cattura = _PresaFinta()
    agente._cattura_scelta = ("eth0", "")

    assert agente._allinea_cattura() == ""
    assert avvii == []


def test_cambiare_interfaccia_fa_ripartire_la_cattura(agente, probe_store, monkeypatch):
    avvii = []
    monkeypatch.setattr(agente, "avvia_cattura",
                        lambda: avvii.append(1) or {"attiva": True})
    _accendi(probe_store, interfaccia="eth0")
    agente._cattura = _PresaFinta()
    agente._cattura_scelta = ("eth0", "")

    _accendi(probe_store, interfaccia="eth1")

    assert agente._allinea_cattura() == "avviata"
    assert len(avvii) == 1


def test_una_cattura_morta_viene_rimessa_in_piedi(agente, probe_store, monkeypatch):
    """Capita quando la scheda viene staccata e riattaccata: senza, l'osservazione
    resta accesa nelle impostazioni e spenta nei fatti."""
    avvii = []
    monkeypatch.setattr(agente, "avvia_cattura",
                        lambda: avvii.append(1) or {"attiva": True})
    _accendi(probe_store)
    agente._cattura = _PresaFinta(viva=False)
    agente._cattura_scelta = ("eth0", "")

    assert agente._allinea_cattura() == "avviata"
    assert len(avvii) == 1


def test_l_allineamento_sta_nel_ciclo_prima_del_travaso():
    """L'ordine conta: allineare DOPO il travaso perderebbe un giro a ogni accensione.
    Si guarda il sorgente perche' e' una proprieta' dell'ordine, non del risultato."""
    sorgente = (RADICE / "probe" / "snapprobe" / "agent.py").read_text(encoding="utf-8")

    assert sorgente.index("_allinea_cattura()") < sorgente.index("_travasa_traffico()"), (
        "l'allineamento deve precedere il travaso nel ciclo")


# --------------------------------------------------------------------------- #
# La pagina non avvia niente
# --------------------------------------------------------------------------- #
def test_la_pagina_non_avvia_la_cattura_nel_proprio_processo():
    """E' la meta' che chiude il difetto: se l'interfaccia riprendesse ad avviarla,
    i pacchetti tornerebbero in un anello che nessuno svuota."""
    sorgente = (RADICE / "probe" / "snapprobe" / "views.py").read_text(encoding="utf-8")
    inizio = sorgente.index("def save_traffico")
    corpo = sorgente[inizio:sorgente.index("@bp.post", inizio + 10)]

    assert "avvia_cattura" not in corpo, (
        "la vista avvia di nuovo la cattura nel processo dell'interfaccia")
    assert "ferma_cattura" not in corpo


def test_la_pagina_dice_entro_quanto_si_applica(probe_app):
    """Un interruttore che non fa niente per quindici secondi sembra rotto: si
    dichiara l'attesa invece di lasciarla scoprire."""
    risposta = probe_app.test_client().post(
        "/traffico", data={"traffico_attivo": "1", "traffico_interfaccia": "eth0"},
        follow_redirects=True)
    testo = risposta.get_data(as_text=True)

    assert "si avvia entro" in testo
    assert "15 secondi" in testo


# --------------------------------------------------------------------------- #
# L'elenco delle interfacce porta l'indirizzo
# --------------------------------------------------------------------------- #
def test_l_elenco_delle_interfacce_porta_gli_indirizzi():
    """Su una macchina vera le schede hanno descrizioni che si somigliano tutte e
    nomi che non dicono niente: senza l'indirizzo, scegliere e' indovinare."""
    from snapprobe import cattura

    if cattura.motivo_assenza():
        pytest.skip("libreria di cattura non disponibile qui")
    voci = cattura.interfacce()
    if not voci:
        pytest.skip("nessuna interfaccia visibile (di norma: mancano i privilegi)")

    assert all("indirizzi" in v for v in voci), "manca il campo degli indirizzi"
    assert all(isinstance(v["indirizzi"], list) for v in voci)
    # Almeno una scheda della macchina ha un indirizzo: se nessuna ne avesse, la
    # lettura non starebbe funzionando e la prova passerebbe a vuoto.
    assert any(v["indirizzi"] for v in voci), (
        "nessuna interfaccia dichiara un indirizzo: la lettura non funziona")


def test_gli_indirizzi_di_collegamento_locale_non_compaiono():
    """Ce n'e' uno su ogni scheda, sono tutti simili, e riempirebbero l'elenco senza
    distinguere niente."""
    from snapprobe import cattura

    if cattura.motivo_assenza():
        pytest.skip("libreria di cattura non disponibile qui")
    for voce in cattura.interfacce():
        for indirizzo in voce["indirizzi"]:
            assert not indirizzo.lower().startswith("fe80"), voce["nome"]


def test_gli_indirizzi_ipv4_stanno_prima():
    """E' quello con cui la sonda si presenta sulla rete da osservare, ed e' quello
    che chi sceglie riconosce."""
    from snapprobe import cattura

    if cattura.motivo_assenza():
        pytest.skip("libreria di cattura non disponibile qui")
    for voce in cattura.interfacce():
        indirizzi = voce["indirizzi"]
        versioni = [":" in a for a in indirizzi]
        assert versioni == sorted(versioni), voce["nome"]


def test_la_pagina_mostra_l_indirizzo_accanto_al_nome():
    modello = (RADICE / "probe" / "snapprobe" / "templates"
               / "configuration.html").read_text(encoding="utf-8")

    assert "voce.indirizzi|join" in modello
    assert "senza indirizzo" in modello, (
        "un'interfaccia senza indirizzo deve dirlo, non lasciare il posto vuoto")

# --------------------------------------------------------------------------- #
# «Accesa, ma non in ascolto» mentre i pacchetti si vedono
#
# La cattura vive nel processo dell'AGENTE, la pagina gira in quello
# dell'INTERFACCIA. Cercando li' l'oggetto della cattura non lo si trova mai, e la
# pagina dichiarava "non e' partita" mentre quella accanto mostrava il traffico
# appena arrivato. Lo stato attraversa i processi passando dall'archivio.
# --------------------------------------------------------------------------- #
def test_la_pagina_non_cerca_la_cattura_nel_proprio_processo():
    """E' il difetto, non una preferenza di stile: `getattr(agente, "_cattura")` nel
    processo dell'interfaccia restituisce None per costruzione."""
    sorgente = (RADICE / "probe" / "snapprobe" / "views.py").read_text(encoding="utf-8")
    inizio = sorgente.index("def _stato_traffico")
    corpo = sorgente[inizio:sorgente.index("def save_traffico", inizio)]

    # Si cercano le DUE mosse del difetto: farsi dare l'agente di questo processo e
    # frugargli dentro l'attributo della cattura. (`modulo_cattura` contiene la
    # stessa sequenza di lettere ed e' invece legittimo: serve per l'elenco delle
    # interfacce.)
    assert '"snap_agent"' not in corpo, (
        "la pagina torna a chiedere l'agente di questo processo")
    assert '"_cattura"' not in corpo, (
        "la pagina torna a cercare la cattura in un processo che non ce l'ha")
    assert "cattura_in_ascolto" in corpo


def test_senza_istante_firmato_la_cattura_non_risulta_in_ascolto(probe_store):
    from snapprobe import ids as modulo_ids

    assert modulo_ids.cattura_in_ascolto(probe_store) is False


def test_un_istante_appena_firmato_dice_che_sta_ascoltando(probe_store):
    from snapprobe import ids as modulo_ids
    from snapprobe.store import utc_now_str

    probe_store.set_setting(modulo_ids.CHIAVE_TRAFFICO_VIVA_AT, utc_now_str())

    assert modulo_ids.cattura_in_ascolto(probe_store) is True


def test_un_istante_vecchio_non_vale_piu(probe_store):
    """Un processo che muore non fa in tempo a scrivere "sono morto": e' l'istante
    fermo a dirlo, e per questo si guarda quanto e' vecchio."""
    from datetime import datetime, timedelta, timezone

    from snapprobe import ids as modulo_ids

    vecchio = datetime.now(timezone.utc) - timedelta(
        seconds=modulo_ids.TRAFFICO_VIVA_SCADENZA_SEC + 5)
    probe_store.set_setting(modulo_ids.CHIAVE_TRAFFICO_VIVA_AT,
                            vecchio.strftime("%Y-%m-%d %H:%M:%S"))

    assert modulo_ids.cattura_in_ascolto(probe_store) is False


def test_un_istante_illeggibile_non_vale_come_in_ascolto(probe_store):
    """Meglio dire "non sta ascoltando" che dedurlo da una data che non si capisce."""
    from snapprobe import ids as modulo_ids

    probe_store.set_setting(modulo_ids.CHIAVE_TRAFFICO_VIVA_AT, "ieri sera")

    assert modulo_ids.cattura_in_ascolto(probe_store) is False


def test_spegnere_l_osservazione_cancella_l_istante(probe_store):
    """Un istante vecchio rimasto scritto direbbe "ascoltava fino a poco fa" di una
    cattura che e' stata spenta apposta."""
    from snapprobe import ids as modulo_ids
    from snapprobe.agent import ProbeAgent
    from snapprobe.store import utc_now_str

    probe_store.set_setting(modulo_ids.CHIAVE_TRAFFICO_VIVA_AT, utc_now_str())
    probe_store.set_setting(modulo_ids.CHIAVE_TRAFFICO_ATTIVO, "0")

    ProbeAgent(probe_store, "prova")._allinea_cattura()

    assert probe_store.get_setting(modulo_ids.CHIAVE_TRAFFICO_VIVA_AT, "") == ""
    assert modulo_ids.cattura_in_ascolto(probe_store) is False


def test_il_badge_dice_quanti_pacchetti_ci_sono(probe_store, monkeypatch):
    """La scheda scrive "in ascolto - N pacchetti": senza N la riga esce mutilata, e
    Jinja rende un campo che manca come niente, senza dirlo."""
    import snapprobe.views as viste

    monkeypatch.setattr(viste, "_store", lambda: probe_store)
    stato = viste._stato_traffico()["stato"]

    assert "pacchetti" in stato, "il badge resterebbe senza numero"
    assert isinstance(stato["pacchetti"], int)


def test_le_due_console_leggono_la_stessa_fonte(probe_store):
    """Prima la console locale guardava la memoria del proprio processo e quella
    remota l'istantanea del battito: potevano dire cose diverse sulla stessa
    cattura."""
    from snapprobe import ids as modulo_ids
    from snapprobe.agent import ProbeAgent
    from snapprobe.store import utc_now_str

    probe_store.set_setting(modulo_ids.CHIAVE_TRAFFICO_ATTIVO, "1")
    probe_store.set_setting(modulo_ids.CHIAVE_TRAFFICO_VIVA_AT, utc_now_str())

    remota = ProbeAgent(probe_store, "prova")._traffico_console()["in_ascolto"]

    assert remota is modulo_ids.cattura_in_ascolto(probe_store) is True


# --------------------------------------------------------------------------- #
# «Server non raggiungibile» mentre la sonda sta conferendo
#
# Stesso difetto della cattura, in un altro punto: il collegamento col server lo
# tiene l'AGENTE, e `_online` e' un suo attributo in memoria. Nel processo
# dell'INTERFACCIA quell'oggetto esiste ma non gira: il valore viene fissato alla
# costruzione e non cambia mai piu'. La pastiglia restava rossa per tutta la vita del
# processo mentre il diario registrava "Lotto conferito" ogni pochi secondi.
# --------------------------------------------------------------------------- #
def _agente_fermo(store):
    """Un agente come quello del processo dell'interfaccia: costruito, mai avviato."""
    from snapprobe.agent import ProbeAgent

    return ProbeAgent(store, "prova")


def test_l_interfaccia_non_crede_alla_propria_memoria(probe_store):
    """Il valore in memoria e' un'osservazione diretta solo per chi le richieste le
    fa davvero: qui e' il ricordo del momento in cui il processo e' partito."""
    from snapprobe.store import utc_now_str

    agente = _agente_fermo(probe_store)
    # Come dopo un riavvio: il processo e' partito quando il contatto era vecchio.
    agente._online = False
    # ...ma l'agente di raccolta, nell'altro processo, ha appena parlato col server.
    probe_store.set_setting("last_contact_at", utc_now_str())

    assert agente.online is True, (
        "la pagina direbbe 'Server non raggiungibile' mentre la sonda conferisce")
    assert agente.status()["online"] is True


def test_un_contatto_vecchio_non_vale_come_canale_attivo(probe_store):
    """Il difetto ha due facce: latched a vero, la pagina avrebbe detto "Canale
    attivo" per sempre, anche col server spento da ore."""
    from datetime import datetime, timedelta, timezone

    from snapprobe.agent import CONTACT_FRESH_SECONDS

    agente = _agente_fermo(probe_store)
    agente._online = True
    vecchio = datetime.now(timezone.utc) - timedelta(
        seconds=CONTACT_FRESH_SECONDS + 60)
    probe_store.set_setting("last_contact_at",
                            vecchio.strftime("%Y-%m-%d %H:%M:%S"))

    assert agente.online is False
    assert agente.status()["online"] is False


def test_senza_nessun_contatto_registrato_non_si_inventa(probe_store):
    """Prima del primo battito non si sa nulla: dichiararlo attivo sarebbe
    un'affermazione non verificata."""
    agente = _agente_fermo(probe_store)
    agente._online = True

    assert agente.online is False


def test_chi_esegue_il_ciclo_risponde_per_osservazione_diretta(probe_store,
                                                               monkeypatch):
    """Nel processo che il ciclo lo esegue davvero il fallimento si sa nell'istante in
    cui accade, mentre l'archivio impiegherebbe cinque minuti a dirlo. Quella
    prontezza si tiene -- ma solo dove e' vera."""
    from snapprobe.store import utc_now_str

    agente = _agente_fermo(probe_store)
    monkeypatch.setattr(agente, "_ciclo_in_questo_processo", lambda: True)
    # Il server ha risposto un istante fa, ma la richiesta successiva e' fallita.
    probe_store.set_setting("last_contact_at", utc_now_str())
    agente._online = False

    assert agente.online is False, (
        "chi osserva direttamente non deve aspettare che l'archivio invecchi")


# --------------------------------------------------------------------------- #
# La pagina Configurazione con la cattura ACCESA
#
# Il ramo che mostra "In ascolto su ..., N letti, M scartati" si percorre SOLO quando
# la cattura e' viva: provando la pagina a cattura spenta si passa accanto al difetto
# senza vederlo. E' successo: lo stato della cattura ha smesso di portare
# `interfaccia` e `scartati`, e la pagina da cui si accende l'osservazione ha
# risposto 500 finche' qualcuno non l'ha aperta con la cattura in funzione.
# --------------------------------------------------------------------------- #
def _cattura_viva(store, contatori=None):
    import json

    from snapprobe import ids as modulo_ids
    from snapprobe.store import utc_now_str

    _accendi(store)
    store.set_setting(modulo_ids.CHIAVE_TRAFFICO_VIVA_AT, utc_now_str())
    if contatori is not None:
        store.set_setting(modulo_ids.CHIAVE_TRAFFICO_CONTATORI,
                          json.dumps(contatori))


def test_la_configurazione_si_apre_con_la_cattura_accesa(probe_app, probe_store):
    """E' il caso che rispondeva 500, ed e' la pagina da cui si accende e si spegne
    l'osservazione: rotta lei, l'osservazione non si spegne piu' dall'interfaccia."""
    _cattura_viva(probe_store, {"interfaccia": "\\Device\\NPF_{ABC}", "viva": True,
                                "pacchetti": 1200, "scartati": 3, "filtro": ""})

    risposta = probe_app.test_client().get("/configuration")

    assert risposta.status_code == 200
    testo = risposta.get_data(as_text=True)
    assert "In ascolto su" in testo
    assert "1200" in testo and "3" in testo


def test_la_configurazione_regge_i_contatori_non_ancora_arrivati(probe_app,
                                                                  probe_store):
    """Fra l'accensione e il primo giro dell'agente passano fino a quindici secondi:
    in quella finestra la cattura risulta viva e i contatori non ci sono ancora."""
    _cattura_viva(probe_store, contatori=None)

    risposta = probe_app.test_client().get("/configuration")

    assert risposta.status_code == 200, (
        "la pagina deve reggere una cattura viva senza contatori")


def test_ogni_chiave_letta_dalla_pagina_esiste_sempre(probe_app, probe_store,
                                                       monkeypatch):
    """Il difetto non era un valore sbagliato ma una chiave MANCANTE: si controlla
    quindi che ci siano tutte, non che valgano qualcosa."""
    import snapprobe.views as viste

    monkeypatch.setattr(viste, "_store", lambda: probe_store)
    _cattura_viva(probe_store, contatori=None)

    stato = viste._stato_traffico()["stato"]

    for chiave in ("viva", "interfaccia", "pacchetti", "scartati"):
        assert chiave in stato, "la pagina legge %r e non c'e'" % chiave
