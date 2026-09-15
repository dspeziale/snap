# -----------------------------------------------------------------
# test_ip_e_schede.py — l'IDS associa indirizzo IP e scheda di rete dai pacchetti
# Autore: Daniele Speziale
# Data creazione: 2026-09-15
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap probe - Indirizzo e scheda, letti dal traffico.

Le regole sul MAC esistevano gia', ma le alimentava il solo sensore dell'inventario,
che legge i MAC raccolti con ARP durante le scansioni: ARP non attraversa un router, e
sull'installazione reale erano 21 nodi su quasi cinquemila. Intanto ogni riga di
traffico porta la coppia gia' fatta.

IL TRANELLO, che e' la ragione per cui non si puo' associare e basta: il MAC di un
pacchetto e' quello del PASSO PRECEDENTE. Se il traffico ha attraversato un router,
quel MAC e' del router -- e associarlo attribuirebbe la sua scheda a mezza internet,
facendo scattare "una scheda su molti indirizzi" su di lui a ogni giro, cioe' il modo
piu' rapido di far ignorare un IDS.

remarks: Autore: Daniele Speziale - Data: 2026-09-15
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ADESSO = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)


def _pacchetti(store, coppie):
    """Scrive righe di traffico: (ip, mac, quante volte)."""
    righe = []
    for ip, mac, quante in coppie:
        for _ in range(quante):
            righe.append({"visto_at": "2026-09-15 12:00:00", "protocollo": "TCP",
                          "mac_sorgente": mac, "mac_destinazione": "ff:ff:ff:ff:ff:ff",
                          "sorgente": ip, "destinazione": "10.0.0.1",
                          "porta_sorgente": 1234, "porta": 443, "bandiere": "S",
                          "byte": 60, "nome": "", "dettaglio": ""})
    store.traffico_scrivi(righe)


@pytest.fixture()
def sensore():
    from snapprobe.ids import SensoreTraffico

    return SensoreTraffico()


# --------------------------------------------------------------------------- #
# Le coppie si leggono
# --------------------------------------------------------------------------- #
def test_le_coppie_si_aggregano_nell_archivio(probe_store):
    """L'aggregazione sta in SQL: le righe sono decine di migliaia, e portarle in
    memoria per contarle sarebbe lo stesso errore della pagina di stato."""
    _pacchetti(probe_store, [("10.0.0.5", "aa:bb:cc:dd:ee:01", 3)])

    coppie = probe_store.traffico_coppie_ip_mac(minimo=2)

    assert len(coppie) == 1
    assert coppie[0]["ip"] == "10.0.0.5"
    assert coppie[0]["mac"] == "aa:bb:cc:dd:ee:01"
    assert coppie[0]["quanti"] == 3


def test_una_coppia_vista_una_volta_sola_non_vale(probe_store):
    """Un pacchetto solo puo' essere un residuo o una lettura storta: non basta per
    dire che una scheda appartiene a un indirizzo."""
    _pacchetti(probe_store, [("10.0.0.6", "aa:bb:cc:dd:ee:02", 1)])

    assert probe_store.traffico_coppie_ip_mac(minimo=2) == []


# --------------------------------------------------------------------------- #
# Il nodo trova la propria scheda
# --------------------------------------------------------------------------- #
def test_un_nodo_senza_scheda_la_riceve_dal_traffico(probe_store, sensore):
    """E' il guadagno vero: un MAC da' il costruttore, e su un apparato muto e'
    spesso l'unico indizio sul tipo."""
    probe_store.upsert_local_node("10.0.0.7", state="confirmed")
    _pacchetti(probe_store, [("10.0.0.7", "aa:bb:cc:dd:ee:07", 4)])

    sensore._ip_e_schede(probe_store, ADESSO)

    nodo = [n for n in probe_store.local_nodes("confirmed") if n["ip"] == "10.0.0.7"]
    assert nodo and nodo[0]["mac"] == "aa:bb:cc:dd:ee:07"


def test_non_si_sovrascrive_un_mac_gia_noto(probe_store, sensore):
    """Quello viene da ARP durante una scansione, che e' una prova diretta sul
    segmento; questo e' dedotto dal traffico. Se discordano non e' un aggiornamento,
    e' una rilevazione."""
    probe_store.upsert_local_node("10.0.0.8", state="confirmed",
                                  mac="11:22:33:44:55:66")
    _pacchetti(probe_store, [("10.0.0.8", "aa:bb:cc:dd:ee:08", 4)])

    sensore._ip_e_schede(probe_store, ADESSO)

    nodo = [n for n in probe_store.local_nodes("confirmed") if n["ip"] == "10.0.0.8"]
    assert nodo[0]["mac"] == "11:22:33:44:55:66"


# --------------------------------------------------------------------------- #
# Il router non inquina l'associazione
# --------------------------------------------------------------------------- #
def test_la_scheda_di_un_router_non_si_attribuisce_a_nessuno(probe_store, sensore):
    """Associare alla cieca attribuirebbe la scheda del router a mezza internet."""
    from snapprobe.ids import INDIRIZZI_OLTRE_I_QUALI_E_UN_ROUTER

    quanti = INDIRIZZI_OLTRE_I_QUALI_E_UN_ROUTER + 3
    coppie = [("93.184.216.%d" % n, "de:ad:be:ef:00:01", 5) for n in range(quanti)]
    for ip, _, _ in coppie:
        probe_store.upsert_local_node(ip, state="confirmed")
    _pacchetti(probe_store, coppie)

    sensore._ip_e_schede(probe_store, ADESSO)

    con_mac = [n for n in probe_store.local_nodes("confirmed")
               if (n.get("mac") or "").strip()]
    assert con_mac == [], "la scheda del router e' finita su dei nodi"


def test_sotto_la_soglia_l_associazione_si_fa(probe_store, sensore):
    """La soglia deve separare un router da una postazione con due indirizzi, non
    spegnere l'associazione."""
    probe_store.upsert_local_node("10.0.0.20", state="confirmed")
    probe_store.upsert_local_node("10.0.0.21", state="confirmed")
    _pacchetti(probe_store, [("10.0.0.20", "aa:bb:cc:00:00:20", 3),
                             ("10.0.0.21", "aa:bb:cc:00:00:20", 3)])

    sensore._ip_e_schede(probe_store, ADESSO)

    con_mac = {n["ip"] for n in probe_store.local_nodes("confirmed")
               if (n.get("mac") or "").strip()}
    assert con_mac == {"10.0.0.20", "10.0.0.21"}


# --------------------------------------------------------------------------- #
# Il cambio di scheda si segnala, con la stessa memoria dell'inventario
# --------------------------------------------------------------------------- #
def test_un_indirizzo_che_cambia_scheda_si_segnala(probe_store, sensore):
    from snapprobe.ids import MATURITA_ORE

    probe_store.upsert_local_node("10.0.0.30", state="confirmed")
    _pacchetti(probe_store, [("10.0.0.30", "aa:aa:aa:aa:aa:aa", 3)])
    sensore._ip_e_schede(probe_store, ADESSO)

    # Piu' tardi, lo stesso indirizzo con un'altra scheda: la memoria per quel
    # soggetto e' ormai matura, quindi il cambio si puo' giudicare.
    probe_store.traffico_svuota()
    _pacchetti(probe_store, [("10.0.0.30", "bb:bb:bb:bb:bb:bb", 3)])
    dopo = ADESSO + timedelta(hours=MATURITA_ORE + 1)

    rilevazioni = sensore._ip_e_schede(probe_store, dopo)

    assert any(r.regola == "ARP-MAC-CAMBIATO" for r in rilevazioni), rilevazioni


def test_usa_la_stessa_memoria_del_sensore_dell_inventario():
    """Due memorie separate farebbero segnalare due volte lo stesso cambio o --
    peggio -- farebbero credere normale a ciascuna cio' che l'altra ha visto
    cambiare."""
    sorgente = (Path(__file__).resolve().parent.parent / "probe" / "snapprobe"
                / "ids.py").read_text(encoding="utf-8")
    inizio = sorgente.index("def _ip_e_schede")
    corpo = sorgente[inizio:inizio + 4000]

    assert '"mac_di_ip"' in corpo
