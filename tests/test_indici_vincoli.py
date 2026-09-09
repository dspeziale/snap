"""
snap - Test degli indici sulle colonne di vincolo del database del server.

Perche' esiste: SQLite, per applicare `ON DELETE SET NULL` o `CASCADE`, deve TROVARE
le righe che referenziano la riga cancellata. Senza indice sulla colonna del vincolo
fa una scansione completa della tabella figlia.

Difetto misurato in esercizio: la cancellazione di una sonda dalla console rispondeva
`database is locked` (HTTP 500) tre tentativi di seguito. Una sola sonda comportava
l'aggiornamento di circa 118.000 righe (nodes 7.309 + scan_runs 17.140 +
check_results 93.588), ognuna da cercare con una scansione, mentre i servizi di fondo
scrivevano.

Questi test non misurano il tempo (dipende dalla macchina): verificano la proprieta'
strutturale che lo determina, cioe' che le tabelle che crescono senza limite abbiano
un indice sulle colonne di vincolo.

remarks: Autore: Daniele Speziale - Data: 2026-09-09
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

# Tabelle che crescono con l'esercizio (inventario, misure, esposizioni, diario) e
# colonna di vincolo che deve essere indicizzata. Le anagrafiche di poche righe non
# sono in elenco per scelta: l'indice costerebbe in scrittura senza servire.
VINCOLI_DA_INDICIZZARE = [
    ("nodes", "probe_id"),
    ("scan_runs", "probe_id"),
    ("scan_runs", "batch_id"),
    ("check_results", "probe_id"),
    ("check_metrics", "result_id"),
    ("monitor_samples", "tenant_id"),
    ("check_incident_events", "tenant_id"),
    ("audit_events", "user_id"),
    ("ti_findings", "port_id"),
    ("ti_findings", "cve_id"),
    ("ti_findings", "decided_by"),
    ("notifications", "incident_id"),
]


def _prime_colonne_indicizzate(connection, tabella: str) -> set[str]:
    """Prima colonna di ogni indice della tabella.

    Serve la PRIMA: un indice su (a, b) accelera la ricerca per `a`, non per `b`.
    """
    prime = set()
    for indice in connection.execute("PRAGMA index_list(%s)" % tabella).fetchall():
        colonne = [riga["name"] for riga in
                   connection.execute("PRAGMA index_info(%s)" % ('"%s"' % indice["name"]))]
        if colonne and colonne[0]:
            prime.add(colonne[0])
    return prime


def test_i_vincoli_delle_tabelle_che_crescono_sono_indicizzati(server_app):
    with server_app.app_context():
        from snapserver.db import get_db

        connection = get_db()
        scoperti = []
        for tabella, colonna in VINCOLI_DA_INDICIZZARE:
            if colonna not in _prime_colonne_indicizzate(connection, tabella):
                scoperti.append("%s.%s" % (tabella, colonna))

        assert not scoperti, (
            "senza indice la cancellazione della riga padre scandisce l'intera"
            " tabella figlia: %s" % ", ".join(scoperti))


def test_le_colonne_dichiarate_sono_davvero_vincoli(server_app):
    """Se un vincolo viene rimosso, l'elenco qui sopra va aggiornato: un indice
    mantenuto per un vincolo che non esiste piu' e' solo costo in scrittura."""
    with server_app.app_context():
        from snapserver.db import get_db

        connection = get_db()
        for tabella, colonna in VINCOLI_DA_INDICIZZARE:
            vincoli = {riga["from"] for riga in
                       connection.execute("PRAGMA foreign_key_list(%s)" % tabella)}
            assert colonna in vincoli, (
                "%s.%s non e' piu' una chiave esterna: aggiornare l'elenco"
                % (tabella, colonna))


def test_l_attesa_sul_blocco_e_una_scelta_non_un_valore_predefinito(server_app):
    """Il modulo Python attende 5 secondi per difetto: troppo poco per le operazioni
    lunghe, e nessuno l'aveva scelto. Ora e' dichiarato in configurazione."""
    with server_app.app_context():
        from snapserver.db import get_db

        connection = get_db()
        atteso = int(server_app.config["DB_BUSY_TIMEOUT_MS"])
        assert atteso >= 15000, "un'attesa breve fa fallire le operazioni lunghe"
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == atteso
