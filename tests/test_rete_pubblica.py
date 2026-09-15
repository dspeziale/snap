# -----------------------------------------------------------------
# test_rete_pubblica.py — dall'indirizzo pubblico al nome della rete
# Autore: Daniele Speziale
# Data creazione: 2026-09-15
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap - La cache dei nomi delle reti: che cosa deve fare e che cosa non deve fare.

Cio' che queste prove difendono, in ordine di gravita':

* NESSUNA PAGINA INTERROGA INTERNET. Una pagina che aspettasse una risposta RDAP si
  bloccherebbe per secondi su una tabella di trenta righe, e in una rete senza uscita
  non si aprirebbe affatto. La lettura guarda solo la cache, sempre.
* GLI INDIRIZZI PRIVATI NON ESCONO MAI. Sono quelli della rete del cliente, e sono
  anche gli unici che potrebbero identificare una postazione: mandarli a un registro
  pubblico sarebbe una comunicazione di dati che nessuno ha autorizzato.
* SI CONSERVA L'INTERVALLO, non l'indirizzo: e' cio' che rende questa cache capace di
  reggere il traffico di un SIEM. Se si conservasse l'indirizzo, il secondo della
  stessa rete costerebbe una seconda interrogazione.
* SI SCEGLIE L'INTERVALLO PIU' STRETTO: un indirizzo sta insieme nel blocco del RIR e
  nella rete assegnata a un'azienda, e il nome che serve e' il secondo.

Nessuna prova esce in rete: RDAP e' sostituito da una risposta scritta qui.

remarks: Autore: Daniele Speziale - Data: 2026-09-15
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

RADICE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RADICE / "server"))


# Una risposta RDAP vera, ridotta ai campi che si usano.
#
# GLI INDIRIZZI DELLA DOCUMENTAZIONE NON SI POSSONO USARE QUI, ed e' istruttivo:
# `203.0.113.0/24` e le altre reti della RFC 5737 sono marcate PRIVATE dal registro
# IANA degli usi speciali, e `ipaddress` lo riporta fedelmente -- quindi questo
# servizio, giustamente, si rifiuta di chiederle a un registro. Servono indirizzi
# davvero globali: si usa `8.8.8.0/24`, che e' un indirizzario notissimo, e i nomi
# nella risposta restano inventati.
RISPOSTA = {
    "startAddress": "8.8.8.0",
    "endAddress": "8.8.8.255",
    "name": "ESEMPIO-NET",
    "country": "IT",
    "entities": [
        {"handle": "TECH-1", "roles": ["technical"],
         "vcardArray": ["vcard", [["fn", {}, "text", "Assistenza Tecnica Srl"]]]},
        {"handle": "ORG-1", "roles": ["registrant"],
         "vcardArray": ["vcard", [["fn", {}, "text", "Esempio Telecomunicazioni"]]]},
    ],
}


@pytest.fixture()
def rete(server_app):
    from snapserver import rete_pubblica

    with server_app.app_context():
        yield rete_pubblica


# --------------------------------------------------------------------------- #
# Che cosa e' pubblico
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("indirizzo", [
    "10.20.10.42", "192.168.1.1", "172.16.5.9",   # la rete del cliente
    "127.0.0.1", "169.254.1.1", "224.0.0.1",      # loopback, link-local, multicast
    "100.64.3.9",                                  # CGNAT: pubblico per forma
    "", "non-un-indirizzo", None,
])
def test_non_esce_mai_un_indirizzo_che_non_e_pubblico(rete, indirizzo):
    """Gli indirizzi privati sono quelli della rete del cliente, e sono anche gli
    unici che potrebbero identificare una postazione."""
    assert rete.e_pubblico(indirizzo) is False


@pytest.mark.parametrize("indirizzo", ["8.8.8.8", "1.1.1.1", "2606:4700::1111"])
def test_riconosce_gli_indirizzi_di_internet(rete, indirizzo):
    assert rete.e_pubblico(indirizzo) is True


def test_un_indirizzo_privato_non_entra_nemmeno_in_coda(rete):
    """La coda e' l'unica cosa che poi esce verso un registro: se un indirizzo privato
    ci entrasse, uscirebbe."""
    assert rete.osserva("192.168.1.1") is False
    assert rete.stato()["indirizzi_visti"] == 0


# --------------------------------------------------------------------------- #
# La lettura non interroga mai la rete
# --------------------------------------------------------------------------- #
def test_la_lettura_non_esce_in_rete(rete, monkeypatch):
    """E' la prova piu' importante del file: una pagina non deve mai dipendere da
    internet per disegnarsi."""
    def vietato(*_a, **_k):
        raise AssertionError("la lettura ha tentato di uscire in rete")

    monkeypatch.setattr(rete.urllib.request, "urlopen", vietato)

    assert rete.nome_rete("8.8.8.45") is None
    assert rete.etichetta("8.8.8.45") == ""


def test_senza_risposta_l_etichetta_e_vuota_non_inventata(rete):
    """Una etichetta inventata ("sconosciuto") occuperebbe lo spazio del suggerimento
    dicendo meno di niente."""
    assert rete.etichetta("8.8.8.45") == ""
    assert rete.etichetta("192.168.1.1") == ""


# --------------------------------------------------------------------------- #
# La risoluzione
# --------------------------------------------------------------------------- #
@pytest.fixture()
def rdap_finto(rete, monkeypatch):
    chiamate = []

    def finta(indirizzo):
        chiamate.append(indirizzo)
        return RISPOSTA

    monkeypatch.setattr(rete, "_leggi_rdap", finta)
    return chiamate


def test_risolve_e_conserva_l_intervallo(rete, rdap_finto):
    rete.osserva("8.8.8.45")
    rete.risolvi("8.8.8.45")

    dati = rete.nome_rete("8.8.8.45")
    assert dati["nome"] == "ESEMPIO-NET"
    assert dati["rete"] == "8.8.8.0/24"
    assert dati["paese"] == "IT"


def test_il_titolare_vince_sul_contatto_tecnico(rete, rdap_finto):
    """Il contatto tecnico e' spesso un fornitore, non chi usa quella rete."""
    rete.risolvi("8.8.8.45")

    assert rete.nome_rete("8.8.8.45")["titolare"] == "Esempio Telecomunicazioni"


def test_un_solo_interrogativo_copre_tutta_la_rete(rete, rdap_finto):
    """E' la ragione per cui questa cache regge il traffico di un SIEM: si conserva
    l'INTERVALLO, quindi il secondo indirizzo della stessa rete non costa niente."""
    rete.risolvi("8.8.8.45")

    assert rete.nome_rete("8.8.8.200")["nome"] == "ESEMPIO-NET"
    assert rete.nome_rete("8.8.8.1")["nome"] == "ESEMPIO-NET"
    assert len(rdap_finto) == 1, "una sola interrogazione per tutta la rete"


def test_un_indirizzo_fuori_dall_intervallo_resta_sconosciuto(rete, rdap_finto):
    """Il contrario del difetto piu' facile: attribuire a mezza internet il nome
    trovato per un indirizzo."""
    rete.risolvi("8.8.8.45")

    assert rete.nome_rete("9.9.9.7") is None


def test_fra_due_intervalli_vince_il_piu_stretto(rete, rdap_finto, monkeypatch):
    """Un indirizzo sta insieme nel blocco del RIR e nella rete assegnata a
    un'azienda: il nome che serve e' il secondo."""
    monkeypatch.setattr(rete, "_leggi_rdap", lambda _ip: {
        "startAddress": "8.0.0.0", "endAddress": "8.255.255.255",
        "name": "BLOCCO-DEL-REGISTRO", "country": "EU", "entities": []})
    rete.risolvi("8.8.8.45")
    monkeypatch.setattr(rete, "_leggi_rdap", lambda _ip: RISPOSTA)
    rete.risolvi("8.8.8.45")

    assert rete.nome_rete("8.8.8.45")["nome"] == "ESEMPIO-NET"
    # L'altro resta, e vale per il resto del blocco.
    assert rete.nome_rete("8.9.9.9")["nome"] == "BLOCCO-DEL-REGISTRO"


def test_l_etichetta_non_ripete_lo_stesso_nome_due_volte(rete, monkeypatch):
    monkeypatch.setattr(rete, "_leggi_rdap", lambda _ip: {
        "startAddress": "8.8.8.0", "endAddress": "8.8.8.255",
        "name": "Esempio Spa", "country": "IT",
        "entities": [{"handle": "X", "roles": ["registrant"],
                      "vcardArray": ["vcard", [["fn", {}, "text", "Esempio Spa"]]]}]})
    rete.risolvi("8.8.8.45")

    etichetta = rete.etichetta("8.8.8.45")
    assert etichetta.count("Esempio Spa") == 1, etichetta
    assert "8.8.8.0/24" in etichetta


# --------------------------------------------------------------------------- #
# Quando va male
# --------------------------------------------------------------------------- #
def test_un_errore_dirada_i_tentativi_invece_di_ripeterli(rete, monkeypatch):
    """Un registro che risponde "non trovato" continuera' a rispondere cosi':
    riprovare ogni cinque minuti e' il modo di farsi bloccare l'indirizzo."""
    import urllib.error

    def rotto(_indirizzo):
        raise urllib.error.URLError("nessuna rotta verso l'host")

    monkeypatch.setattr(rete, "_leggi_rdap", rotto)
    rete.osserva("8.8.8.45")

    esito = rete.giro()

    assert esito["falliti"] == 1
    # Il turno successivo e' stato spostato avanti: non e' piu' da fare adesso.
    assert rete.da_risolvere() == []
    assert rete.stato()["risolti"] == 0


def test_dopo_troppi_tentativi_si_smette_ma_la_riga_resta(rete, monkeypatch):
    """"Ci si e' provati e non c'e' un nome" e' diverso da "non ci ha mai pensato
    nessuno": la seconda si riproverebbe per sempre."""
    import urllib.error

    monkeypatch.setattr(rete, "_leggi_rdap",
                        lambda _i: (_ for _ in ()).throw(urllib.error.URLError("no")))
    rete.osserva("8.8.8.45")
    for _ in range(rete.TENTATIVI_MASSIMI):
        rete._rimanda("8.8.8.45", "prova")

    assert rete.stato()["rinunciati"] == 1
    assert rete.stato()["in_coda"] == 0


def test_una_rete_isolata_non_fa_fallire_niente(rete, monkeypatch):
    """Il prodotto deve funzionare senza uscita verso internet: cio' che la richiede
    e' un di piu', mai un requisito."""
    import urllib.error

    monkeypatch.setattr(rete, "_leggi_rdap",
                        lambda _i: (_ for _ in ()).throw(urllib.error.URLError("no")))
    rete.osserva("8.8.8.45")

    esito = rete.giro()  # non solleva

    assert esito["risolti"] == 0
    assert rete.etichetta("8.8.8.45") == ""


# --------------------------------------------------------------------------- #
# La cache si alimenta da sola
# --------------------------------------------------------------------------- #
def test_la_raccolta_pesca_gli_indirizzi_dagli_eventi(rete, server_app):
    """E' cio' che rende la cache automatica: nessun punto del codice deve ricordarsi
    di chiamare `osserva()` quando incontra un indirizzo."""
    from snapserver.db import execute, query, utc_now_str

    tenant = query("SELECT id FROM tenants ORDER BY id LIMIT 1", (), one=True)
    execute("INSERT INTO audit_events (tenant_id, event_type, description, source_ip,"
            " created_at) VALUES (?, 'prova', 'prova', '8.8.8.45', ?)",
            (int(tenant["id"]), utc_now_str()))
    # Uno privato nella stessa tabella: non deve entrare in coda.
    execute("INSERT INTO audit_events (tenant_id, event_type, description, source_ip,"
            " created_at) VALUES (?, 'prova', 'prova', '10.20.10.42', ?)",
            (int(tenant["id"]), utc_now_str()))

    nuovi = rete.raccogli()

    assert nuovi == 1
    assert rete.da_risolvere() == ["8.8.8.45"]


def test_la_raccolta_non_tocca_il_percorso_di_acquisizione():
    """Il SIEM fa decine di migliaia di inserimenti al secondo in una transazione
    sola: aggiungerci una lettura e una scrittura per riga significherebbe rallentare
    l'acquisizione per riempire una cache di comodo."""
    sorgente = (RADICE / "server" / "snapserver" / "siem"
                / "store.py").read_text(encoding="utf-8")

    assert "rete_pubblica" not in sorgente
    assert "osserva" not in sorgente


def test_la_raccolta_ha_un_tetto_contro_le_ondate(rete):
    """Una scansione dall'esterno produce migliaia di indirizzi diversi in pochi
    minuti: senza tetto riempirebbero la coda di cose che nessuno guardera' mai."""
    assert rete.RACCOLTA_MASSIMA > 0
    assert rete.RACCOLTA_MASSIMA <= 1000


# --------------------------------------------------------------------------- #
# La pagina da cui si guarda la cache
#
# Un suggerimento vuoto non dice PERCHE' lo sia: servizio spento, server senza uscita
# verso internet, o indirizzo non ancora risolto. Sono tre cose diverse con tre
# rimedi diversi, e senza un posto in cui guardarle si conclude che "non funziona".
# --------------------------------------------------------------------------- #
def test_la_pagina_si_apre_anche_con_la_cache_vuota(logged_client):
    """E' lo stato in cui la si apre la prima volta, ed e' quando serve di piu'."""
    risposta = logged_client.get("/inventory/reti-pubbliche")

    assert risposta.status_code == 200
    testo = risposta.get_data(as_text=True)
    assert "Nessuna rete ancora riconosciuta" in testo


def test_la_pagina_mostra_le_reti_e_chi_non_si_e_risolto(logged_client, server_app,
                                                          monkeypatch):
    from snapserver import rete_pubblica

    with server_app.app_context():
        monkeypatch.setattr(rete_pubblica, "_leggi_rdap", lambda _ip: RISPOSTA)
        rete_pubblica.risolvi("8.8.8.45")
        rete_pubblica.osserva("9.9.9.7")
        rete_pubblica._rimanda("9.9.9.7", "nessuna rotta verso l'host")

    testo = logged_client.get("/inventory/reti-pubbliche").get_data(as_text=True)

    assert "8.8.8.0/24" in testo
    assert "Esempio Telecomunicazioni" in testo
    # E la meta' che spiega un suggerimento vuoto.
    assert "9.9.9.7" in testo
    assert "nessuna rotta" in testo


def test_la_pagina_dichiara_che_gli_indirizzi_privati_non_escono(logged_client):
    """E' la garanzia che rende accettabile un'uscita verso internet in questo
    prodotto: va scritta dove qualcuno la legge, non solo nel codice."""
    testo = logged_client.get("/inventory/reti-pubbliche").get_data(as_text=True)

    assert "privati non escono mai" in testo


def test_la_voce_sta_nel_menu():
    """Una pagina che non sta nel menu e' una pagina che non esiste."""
    modello = (RADICE / "server" / "snapserver" / "templates" / "partials"
               / "sidebar.html").read_text(encoding="utf-8")

    assert "inventory.reti_pubbliche" in modello
