"""
snap - Il contratto di una riga di risultato.

Il prodotto legge le righe in quattro modi -- per nome, per posizione, come
dizionario e cella per cella -- perche' e' nato su `sqlite3.Row`. L'involucro che le
rende leggibili cosi' su PostgreSQL e' un punto di passaggio obbligato: se sbaglia,
sbaglia ovunque e in silenzio.

Sono difetti gia' costati: un'esportazione CSV ha consegnato una riga di INTESTAZIONI
al posto dei dati (scorrere un Mapping da' i nomi, non i valori), e una riga di cinque
colonne ne ha restituite tre (tre espressioni senza alias si chiamavano tutte
`coalesce` e in un dizionario si sono sovrascritte). Questi test fissano il contratto
perche' non si ripeta.

remarks: Autore: Daniele Speziale - Data: 2026-09-09
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations


def test_le_colonne_omonime_non_si_perdono(server_app):
    """Tre espressioni senza alias hanno lo stesso nome: per posizione devono esserci
    tutte e tre, altrimenti una riga di tabella arriva mutilata."""
    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT COALESCE(NULL, 'a'), COALESCE(NULL, 'b'),"
                     " COALESCE(NULL, 'c')", (), one=True)

    assert riga.celle() == ("a", "b", "c")
    assert riga[0] == "a"
    assert riga[2] == "c"


def test_la_lettura_per_nome_resta_quella_di_sempre(server_app):
    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT 1 AS uno, 'due' AS testo", (), one=True)

    assert riga["uno"] == 1
    assert riga["testo"] == "due"
    assert riga[0] == 1
    assert dict(riga) == {"uno": 1, "testo": "due"}


def test_scorrere_una_riga_da_i_nomi_non_i_valori(server_app):
    """E' il contratto dei Mapping, ed e' diverso da `sqlite3.Row`: va conosciuto,
    perche' e' silenzioso. Chi vuole i valori usa `celle()`."""
    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT 1 AS uno, 2 AS due", (), one=True)

    assert list(riga) == ["uno", "due"]
    assert list(riga.celle()) == [1, 2]


def test_ogni_interrogazione_pronta_restituisce_tutte_le_colonne(server_app):
    """Le interrogazioni pronte dichiarano le proprie colonne: le righe devono averne
    esattamente altrettante, o la tabella e il CSV si disallineano.

    Eseguirle tutte, anche su un tenant senza dati, e' meta' della prova: e' cosi'
    che si scopre un SQL non valido su questo dialetto -- un alias usato nella WHERE,
    per esempio -- senza aspettare che qualcuno apra quella pagina.
    """
    from snapserver.searchdb import SAVED_QUERIES

    with server_app.app_context():
        from snapserver.db import query

        for voce in SAVED_QUERIES:
            parametri = tuple(voce["parametri"](1)) + (5,)
            righe = query(voce["sql"] + " LIMIT ?", parametri)
            for riga in righe:
                assert len(riga.celle()) == len(voce["colonne"]), voce["chiave"]
