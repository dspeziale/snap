"""
snap - Test dell'allineamento dello schema su un database GIA' ESISTENTE.

PERCHE' ESISTE
Ogni test della suite parte da un database vuoto, e su un database vuoto lo schema si
crea completo: le tabelle nascono con tutte le loro colonne e nessuna migrazione ha
niente da fare. E' il caso che NON somiglia all'esercizio, dove il database c'e' da
prima e va adeguato.

Difetto misurato in esercizio: la console non si avviava piu' -- `column
"favicon_hash" does not exist`, riavvio in ciclo. La ragione e' l'ordine: `CREATE
TABLE IF NOT EXISTS` non tocca una tabella che esiste gia', quindi le colonne nuove
arrivano dalle migrazioni; ma lo schema dichiara anche gli INDICI, e l'indice su una
colonna nuova veniva eseguito prima che la colonna esistesse.

Questi test simulano un database "vecchio" togliendogli cio' che una versione
precedente non aveva, e verificano che l'allineamento lo ripari.

remarks: Autore: Daniele Speziale - Data: 2026-09-10
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest

from snapserver.db import MIGRATIONS


def _colonne(tabella: str) -> set:
    from snapserver.db import query

    return {r["column_name"] for r in query(
        "SELECT column_name FROM information_schema.columns"
        " WHERE table_schema = current_schema() AND table_name = ?", (tabella,))}


def _indici(tabella: str) -> set:
    from snapserver.db import query

    return {r["indexname"] for r in query(
        "SELECT indexname FROM pg_indexes"
        " WHERE schemaname = current_schema() AND tablename = ?", (tabella,))}


@pytest.mark.parametrize("tabella,colonna", [
    ("node_web", "favicon_hash"),
    ("node_web", "headers_hash"),
    ("nodes", "mac_source"),
    ("node_ports", "is_suspect"),
])
def test_una_colonna_tolta_viene_riaggiunta(server_app, tabella, colonna):
    """E' il gesto che l'aggiornamento deve saper fare: trovare un database di una
    versione precedente e portarlo a questa."""
    with server_app.app_context():
        from snapserver.db import execute, init_db

        # Il nome viene da questo elenco, non dall'esterno.
        execute('ALTER TABLE "%s" DROP COLUMN "%s"' % (tabella, colonna))
        assert colonna not in _colonne(tabella), "la premessa del test"

        init_db()

        assert colonna in _colonne(tabella)


def test_un_indice_su_una_colonna_aggiunta_dalle_migrazioni_si_crea(server_app):
    """IL DIFETTO MISURATO, per intero.

    Lo schema dichiara `ix_node_web_favicon` su `node_web(tenant_id, favicon_hash)`,
    e quella colonna la aggiungono le migrazioni. Su un database esistente l'indice
    veniva dichiarato prima della colonna e l'avvio si fermava: la console riavviava
    in ciclo. Deve funzionare, e la colonna e l'indice devono esserci entrambi.
    """
    with server_app.app_context():
        from snapserver.db import execute, init_db

        execute("DROP INDEX IF EXISTS ix_node_web_favicon")
        execute('ALTER TABLE node_web DROP COLUMN "favicon_hash"')

        init_db()

        assert "favicon_hash" in _colonne("node_web")
        assert "ix_node_web_favicon" in _indici("node_web")


def test_l_allineamento_e_ripetibile(server_app):
    """Si esegue a ogni avvio: la seconda volta non deve cambiare nulla ne' fallire."""
    with server_app.app_context():
        from snapserver.db import init_db

        init_db()
        prima = _colonne("node_web") | _indici("node_web")
        init_db()

        assert _colonne("node_web") | _indici("node_web") == prima


def test_ogni_colonna_delle_migrazioni_esiste_nello_schema(server_app):
    """Le due fonti devono concordare: una colonna dichiarata solo nelle migrazioni
    esisterebbe sui database aggiornati e non su quelli nuovi, e il difetto si vedrebbe
    soltanto su un'installazione nuova -- il posto peggiore per scoprirlo."""
    with server_app.app_context():
        mancanti = []
        for tabella, colonna, _tipo in MIGRATIONS:
            colonne = _colonne(tabella)
            if colonne and colonna not in colonne:
                mancanti.append("%s.%s" % (tabella, colonna))

        assert mancanti == []
