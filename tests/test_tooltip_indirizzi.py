# -----------------------------------------------------------------
# test_tooltip_indirizzi.py — il nome della rete su ogni indirizzo mostrato
# Autore: Daniele Speziale
# Data creazione: 2026-09-15
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap - Il suggerimento sugli indirizzi, dappertutto.

PERCHE' DAPPERTUTTO E NON IN QUALCHE PAGINA. Un aiuto presente in quattro pagine su
venti e' peggio che non averlo: chi lo ha visto una volta si aspetta di ritrovarlo, e
dove non c'e' conclude che quell'indirizzo non sia riconosciuto -- non che quella
pagina non lo mostri.

PERCHE' SI PUO' METTERE OVUNQUE SENZA PENSARCI: `e_pubblico()` scarta un indirizzo
privato senza toccare l'archivio, quindi una tabella di mille nodi di una rete interna
non fa nessuna interrogazione in piu'. Solo gli indirizzi pubblici -- pochi, e spesso
ripetuti -- arrivano alla cache, che ha anche una memoria per richiesta.

CIO' CHE RESTA FUORI, e non per dimenticanza: gli indirizzi dentro un ATTRIBUTO -- il
valore di un campo, il testo di una conferma, un `title`. La macro emette marcatura, e
marcatura dentro un attributo non e' un suggerimento: e' una pagina rotta.

remarks: Autore: Daniele Speziale - Data: 2026-09-15
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

RADICE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RADICE / "server"))

MODELLI = RADICE / "server" / "snapserver" / "templates"

# Le pagine in cui un indirizzo di internet puo' davvero comparire, e in cui quindi il
# suggerimento deve esserci. Elenco esplicito: un controllo che si accontentasse di
# "da qualche parte" non accorgerebbe di una pagina rimasta indietro.
PAGINE_CON_INDIRIZZI = (
    "siem/index.html",
    "operations/soc.html",
    "operations/noc.html",
    "operations/search.html",
    "audit/index.html",
    "checks/index.html",
    "checks/check.html",
    "checks/target.html",
    "inventory/certificates.html",
    "inventory/presence.html",
    "threat/index.html",
    "threat/cve.html",
    "psn/servizi.html",
    "psn/cerca.html",
    "dashboard/index.html",
)


@pytest.mark.parametrize("pagina", PAGINE_CON_INDIRIZZI)
def test_ogni_pagina_con_indirizzi_usa_la_macro(pagina):
    testo = (MODELLI / pagina).read_text(encoding="utf-8")

    assert "snap_indirizzo" in testo, (
        "%s mostra indirizzi senza il suggerimento della rete" % pagina)
    assert "partials/_indirizzo.html" in testo, (
        "%s usa la macro senza importarla" % pagina)


def test_nessun_indirizzo_finisce_dentro_un_attributo():
    """La macro emette marcatura: dentro un attributo non e' un suggerimento, e' una
    pagina rotta. Si controlla che non sia successo da nessuna parte."""
    colpevoli = []
    for percorso in MODELLI.rglob("*.html"):
        for numero, riga in enumerate(
                percorso.read_text(encoding="utf-8").splitlines(), 1):
            if "snap_indirizzo(" not in riga and "snap_scheda(" not in riga:
                continue
            # La macro deve stare in un nodo di TESTO. Se sulla stessa riga la si
            # trova dopo l'apertura di un attributo e prima della sua chiusura, e'
            # finita dentro.
            for attributo in ("value=", "title=", "placeholder=", "data-confirm=",
                              "alt=", "content="):
                posizione = riga.find(attributo)
                if posizione == -1:
                    continue
                dopo = riga[posizione:]
                virgolette = dopo.find('"', len(attributo))
                chiusura = dopo.find('"', virgolette + 1) if virgolette != -1 else -1
                dentro = dopo[:chiusura] if chiusura != -1 else dopo
                if "snap_indirizzo(" in dentro or "snap_scheda(" in dentro:
                    colpevoli.append("%s:%d" % (
                        percorso.relative_to(MODELLI).as_posix(), numero))

    assert not colpevoli, "macro dentro un attributo: %s" % ", ".join(colpevoli)


def test_un_indirizzo_privato_non_costa_nessuna_interrogazione(server_app,
                                                                monkeypatch):
    """E' cio' che rende possibile metterlo ovunque: una tabella di mille nodi di una
    rete interna non deve fare mille letture per non mostrare niente."""
    from snapserver import rete_pubblica

    def vietato(*_a, **_k):
        raise AssertionError("un indirizzo privato ha interrogato l'archivio")

    with server_app.app_context():
        monkeypatch.setattr(rete_pubblica, "query", vietato)
        for privato in ("10.20.10.42", "192.168.1.1", "172.16.0.9", "127.0.0.1"):
            assert rete_pubblica.etichetta(privato) == ""


def test_il_suggerimento_compare_dove_l_indirizzo_e_pubblico(logged_client,
                                                              server_app, monkeypatch):
    """La prova che chiude il cerchio: dato un indirizzo pubblico risolto, la pagina
    lo mostra con il nome della rete accanto."""
    from snapserver import rete_pubblica
    from snapserver.db import execute, query, utc_now_str

    with server_app.app_context():
        monkeypatch.setattr(rete_pubblica, "_leggi_rdap", lambda _ip: {
            "startAddress": "8.8.8.0", "endAddress": "8.8.8.255",
            "name": "ESEMPIO-NET", "country": "IT",
            "entities": [{"handle": "X", "roles": ["registrant"],
                          "vcardArray": ["vcard", [["fn", {}, "text",
                                                    "Esempio Spa"]]]}]})
        rete_pubblica.risolvi("8.8.8.45")
        tenant = query("SELECT id FROM tenants ORDER BY id LIMIT 1", (), one=True)
        execute("INSERT INTO audit_events (tenant_id, event_type, description,"
                " source_ip, created_at) VALUES (?, 'prova', 'prova', '8.8.8.45', ?)",
                (int(tenant["id"]), utc_now_str()))

    testo = logged_client.get("/audit/").get_data(as_text=True)

    assert "8.8.8.45" in testo
    assert "Esempio Spa" in testo, "l'indirizzo non porta il nome della rete"


def test_la_macro_regge_un_valore_assente():
    """Le tabelle hanno celle vuote: la macro deve mostrare il trattino, non
    sollevare."""
    modello = (MODELLI / "partials" / "_indirizzo.html").read_text(encoding="utf-8")

    assert "vuoto='-'" in modello
    assert "{%- if not valore -%}" in modello
