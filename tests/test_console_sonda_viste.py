# -----------------------------------------------------------------
# test_console_sonda_viste.py — la console remota e' la console della sonda
# Autore: Daniele Speziale
# Data creazione: 2026-09-15
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap - Dal server, "Console" apre la sonda, non un riepilogo della sonda.

Prima era una pagina sola, lunga, con tutte le schede una sotto l'altra: le
informazioni c'erano, ma non era la console di quella macchina. Ora c'e' il MENU
DELLA SONDA a sinistra -- gli stessi gruppi e le stesse voci della sua interfaccia
locale -- e la barra del server si ritira mentre si sta qui.

Cio' che queste prove difendono:

* ogni voce del menu apre una pagina che si disegna davvero (un `include` che non
  trova il modello e' un errore 500 che nessuno vede finche' non clicca);
* i due menu, quello della sonda e quello rifatto qui, restano allineati;
* una vista inventata non arriva mai al render;
* la regola che regge il prodotto: il server non contatta la sonda.

remarks: Autore: Daniele Speziale - Data: 2026-09-15
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

RADICE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RADICE / "server"))


@pytest.fixture()
def sonda_id(server_app, probe_store):
    """Una sonda registrata, con un'istantanea di console gia' consegnata.

    L'istantanea e' quella VERA, composta dall'agente della sonda: scriverla a mano
    proverebbe che il modello sa disegnare i dati che il modello si aspetta, che non
    e' la stessa cosa.
    """
    from snapprobe.agent import ProbeAgent

    istantanea = ProbeAgent(probe_store, "prova").console_snapshot()
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        tenant = query("SELECT id FROM tenants ORDER BY id LIMIT 1", (), one=True)
        execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status,"
            " enrolled_at, console_json, console_at, last_seen_at, agent_version,"
            " created_at, updated_at)"
            " VALUES (?, 'uid-vista', 'sonda-vista', 'Sonda di prova', 'active',"
            " ?, ?, ?, ?, '1.4.4', ?, ?)",
            (int(tenant["id"]), utc_now_str(), json.dumps(istantanea), utc_now_str(),
             utc_now_str(), utc_now_str(), utc_now_str()))
        riga = query("SELECT id FROM probes WHERE code = 'sonda-vista'", (), one=True)
        return int(riga["id"])


def _viste():
    from snapserver.blueprints.probes import CONSOLE_VISTE

    return [voce[0] for _, _, _, voci in CONSOLE_VISTE for voce in voci]


# --------------------------------------------------------------------------- #
# Ogni voce del menu apre qualcosa
# --------------------------------------------------------------------------- #
def test_ogni_vista_del_menu_si_disegna(logged_client, sonda_id):
    """Un `include` che non trova il modello e' un errore 500 che nessuno vede finche'
    qualcuno non clicca quella voce."""
    for vista in _viste():
        risposta = logged_client.get("/probes/%d/console?vista=%s" % (sonda_id, vista))
        assert risposta.status_code == 200, (
            "la vista %r risponde %s" % (vista, risposta.status_code))


def test_la_vista_aperta_e_accesa_nel_menu(logged_client, sonda_id):
    """Senza, si cambia pagina e non si sa piu' dove si e'."""
    for vista in _viste():
        corpo = logged_client.get(
            "/probes/%d/console?vista=%s" % (sonda_id, vista)).get_data(as_text=True)
        # Il </nav> da cercare e' quello DOPO l'inizio del menu: la pagina ne ha gia'
        # altri prima (la barra del server, l'intestazione), e partire dal primo
        # avrebbe ritagliato una fetta vuota -- una prova che passa senza guardare
        # niente.
        inizio = corpo.index("data-snap-menu-sonda")
        menu = corpo[inizio:corpo.index("</nav>", inizio)]

        # L'indirizzo sta sulla riga PRIMA della classe: si guarda quindi il tratto
        # che precede ogni "acceso", non la sola riga. Come nel menu della sonda si
        # accendono due cose -- la voce e la testa del gruppo che la contiene -- e la
        # testa di gruppo si riconosce perche' non porta da nessuna parte.
        pezzi = menu.split("nav-link active")[:-1]
        teste = [p for p in pezzi if 'href="#"' in p[-200:]]
        voci = [p for p in pezzi if 'href="#"' not in p[-200:]]

        assert len(voci) == 1, "vista %r: voci accese %d" % (vista, len(voci))
        assert len(teste) == 1, "vista %r: gruppi accesi %d" % (vista, len(teste))
        assert "vista=%s" % vista in voci[0][-200:], (
            "la voce accesa non punta alla vista aperta: %r" % voci[0][-200:])


def test_la_vista_predefinita_e_lo_stato(logged_client, sonda_id):
    """E' la pagina che la sonda apre da sola: la domanda con cui si arriva qui."""
    corpo = logged_client.get(
        "/probes/%d/console" % sonda_id).get_data(as_text=True)

    assert "NODI IN INVENTARIO" in corpo


def test_una_vista_inventata_non_arriva_al_render(logged_client, sonda_id):
    """L'allowlist e' l'unica difesa possibile: il nome della vista finisce dentro un
    `include`, e un `include` costruito con cio' che scrive il chiamante e' un modo
    per farsi leggere i modelli che si vogliono."""
    risposta = logged_client.get(
        "/probes/%d/console?vista=../../../etc/passwd" % sonda_id)

    assert risposta.status_code == 200
    assert "NODI IN INVENTARIO" in risposta.get_data(as_text=True), (
        "una vista non valida deve riportare a quella predefinita")


@pytest.mark.parametrize("cattiva", ["", "..", "_stato", "stato.html", "SALUTE"])
def test_nomi_di_vista_storti_ricadono_sulla_predefinita(logged_client, sonda_id,
                                                          cattiva):
    risposta = logged_client.get(
        "/probes/%d/console?vista=%s" % (sonda_id, cattiva))

    assert risposta.status_code == 200
    assert "NODI IN INVENTARIO" in risposta.get_data(as_text=True)


# --------------------------------------------------------------------------- #
# I due menu restano allineati
# --------------------------------------------------------------------------- #
def test_i_gruppi_sono_gli_stessi_del_menu_della_sonda():
    """Se i due divergono, chi passa dall'uno all'altro nello stesso pomeriggio deve
    reimparare dove stanno le cose -- ed e' esattamente cio' che si voleva evitare."""
    from snapserver.blueprints.probes import CONSOLE_VISTE

    modello = (RADICE / "probe" / "snapprobe" / "templates"
               / "base.html").read_text(encoding="utf-8")

    for gruppo, titolo, _, _ in CONSOLE_VISTE:
        assert 'data-snap-gruppo="%s"' % gruppo in modello, (
            "il gruppo %r non esiste nel menu della sonda" % gruppo)
        assert titolo in modello, (
            "il gruppo %r si chiama diversamente sulla sonda" % titolo)


def test_ogni_vista_ha_il_proprio_modello():
    """L'elenco e i file devono coincidere: una voce senza modello e' un 500."""
    from snapserver.blueprints.probes import CONSOLE_VISTE

    cartella = (RADICE / "server" / "snapserver" / "templates" / "probes" / "console")
    attesi = {"_%s.html" % voce[0] for _, _, _, voci in CONSOLE_VISTE for voce in voci}
    presenti = {f.name for f in cartella.glob("*.html")}

    assert attesi <= presenti, "modelli mancanti: %s" % sorted(attesi - presenti)
    assert presenti <= attesi, "modelli orfani: %s" % sorted(presenti - attesi)


# --------------------------------------------------------------------------- #
# La barra del server si ritira, e la regola resta
# --------------------------------------------------------------------------- #
def test_la_pagina_chiede_di_ritirare_la_barra_del_server(logged_client, sonda_id):
    """Due barre affiancate si confondono, e confondere le due significa cliccare
    sulla rete sbagliata."""
    corpo = logged_client.get("/probes/%d/console" % sonda_id).get_data(as_text=True)

    assert "data-snap-sonda-console" in corpo
    assert "snap-sonda-console.js" in corpo


def test_la_barra_si_ritira_senza_salvare_la_scelta_dell_utente():
    """Ritirargliela per sempre perche' e' passato da una sonda sarebbe una decisione
    presa al posto suo: uscendo, la barra deve tornare com'era."""
    sorgente = (RADICE / "server" / "snapserver" / "static" / "js"
                / "snap-sonda-console.js").read_text(encoding="utf-8")

    # Si cercano le CHIAMATE, non la parola: il commento in testa al file spiega
    # proprio perche' quel deposito non si tocca, e nominarlo non e' toccarlo.
    for scrittura in ("localStorage.setItem", "localStorage.removeItem",
                      "localStorage.clear"):
        assert scrittura not in sorgente, (
            "toccare lte.sidebar.state renderebbe permanente una scelta temporanea")
    assert "sidebar-collapse" in sorgente


def test_nessuna_vista_apre_una_connessione_verso_la_sonda():
    """La regola che rende accettabile questo prodotto nella rete di un cliente."""
    sorgente = (RADICE / "server" / "snapserver" / "blueprints"
                / "probes.py").read_text(encoding="utf-8")

    for vietato in ("requests.", "urlopen", "http.client", "socket.create_connection"):
        assert vietato not in sorgente


def test_il_ritorno_dopo_un_comando_e_un_nome_non_un_indirizzo():
    """Un indirizzo di ritorno scelto da chi invia e' il modo classico per far
    rimbalzare qualcuno fuori dal sito."""
    from snapserver.blueprints.probes import RITORNI

    assert set(RITORNI.values()) == {"probes.detail", "probes.console"}
    for valore in RITORNI.values():
        assert valore.startswith("probes."), "si torna solo dentro le pagine sonde"


def test_un_comando_dalla_console_riporta_alla_console(logged_client, server_app,
                                                        sonda_id):
    """Chi ne accoda uno dalla console ne accoda spesso un altro: rimandarlo sulla
    scheda lo costringeva a tornare indietro ogni volta."""
    risposta = logged_client.post(
        "/probes/%d/command" % sonda_id,
        data={"command": "flush", "ritorno": "console", "vista": "comandi"})

    assert risposta.status_code in (302, 303)
    assert "/console" in risposta.headers["Location"]
    assert "vista=comandi" in risposta.headers["Location"]


def test_un_ritorno_inventato_non_porta_fuori(logged_client, sonda_id):
    risposta = logged_client.post(
        "/probes/%d/command" % sonda_id,
        data={"command": "flush", "ritorno": "https://esempio.invalido/"})

    assert risposta.status_code in (302, 303)
    destinazione = risposta.headers["Location"]
    assert "esempio.invalido" not in destinazione
    assert destinazione.endswith("/probes/%d" % sonda_id)


# --------------------------------------------------------------------------- #
# Cio' che non deve comparire
# --------------------------------------------------------------------------- #
def test_i_pacchetti_non_compaiono_nella_console(logged_client, server_app, probe_store,
                                                  sonda_id):
    """Sono il traffico di chi lavora su quella rete: restano sulla sonda. Da qui se
    ne sa il numero, che basta a dire se l'osservazione sta funzionando."""
    corpo = logged_client.get(
        "/probes/%d/console?vista=pacchetti" % sonda_id).get_data(as_text=True)

    assert "PACCHETTI SULLA SONDA" in corpo
    assert "restano sulla sonda" in corpo or "resta dove nasce" in corpo


def test_la_community_snmp_non_compare_in_nessuna_vista(logged_client, server_app,
                                                         probe_store, sonda_id):
    """Un segreto che torna indietro e' un segreto conservato in un posto in piu'."""
    for vista in _viste():
        corpo = logged_client.get(
            "/probes/%d/console?vista=%s" % (sonda_id, vista)).get_data(as_text=True)
        assert "snmp_community" not in corpo, vista
