"""
snap - Test degli indici sulle colonne di vincolo del database del server.

Perche' esiste: per applicare `ON DELETE SET NULL` o `CASCADE`, la base dati deve
TROVARE le righe che referenziano la riga cancellata. Senza indice sulla colonna del
vincolo fa una scansione completa della tabella figlia. Vale per SQLite come per
PostgreSQL: quest'ultimo NON crea indici sulle chiavi esterne da se' -- li crea per
le chiavi primarie e per i vincoli di unicita', non per i riferimenti.

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


def _prime_colonne_indicizzate(tabella: str) -> set[str]:
    """Prima colonna di ogni indice della tabella.

    Serve la PRIMA: un indice su (a, b) accelera la ricerca per `a`, non per `b`.
    Si legge dal catalogo di PostgreSQL: `indkey[0]` e' l'attributo in testa
    all'indice.
    """
    from snapserver.db import query

    righe = query(
        "SELECT a.attname AS colonna"
        " FROM pg_index i"
        " JOIN pg_class t ON t.oid = i.indrelid"
        " JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = i.indkey[0]"
        " WHERE t.relname = ?", (tabella,))
    return {r["colonna"] for r in righe}


def test_i_vincoli_delle_tabelle_che_crescono_sono_indicizzati(server_app):
    with server_app.app_context():
        scoperti = []
        for tabella, colonna in VINCOLI_DA_INDICIZZARE:
            if colonna not in _prime_colonne_indicizzate(tabella):
                scoperti.append("%s.%s" % (tabella, colonna))

        assert not scoperti, (
            "senza indice la cancellazione della riga padre scandisce l'intera"
            " tabella figlia: %s" % ", ".join(scoperti))


def test_le_colonne_dichiarate_sono_davvero_vincoli(server_app):
    """Se un vincolo viene rimosso, l'elenco qui sopra va aggiornato: un indice
    mantenuto per un vincolo che non esiste piu' e' solo costo in scrittura."""
    with server_app.app_context():
        from snapserver.db import query

        for tabella, colonna in VINCOLI_DA_INDICIZZARE:
            vincoli = {r["colonna"] for r in query(
                "SELECT k.column_name AS colonna"
                " FROM information_schema.table_constraints c"
                " JOIN information_schema.key_column_usage k"
                "   ON k.constraint_name = c.constraint_name"
                "   AND k.constraint_schema = c.constraint_schema"
                " WHERE c.constraint_type = 'FOREIGN KEY' AND c.table_name = ?",
                (tabella,))}
            assert colonna in vincoli, (
                "%s.%s non e' piu' una chiave esterna: aggiornare l'elenco"
                % (tabella, colonna))


def test_l_attesa_sul_blocco_e_una_scelta_non_un_valore_predefinito(server_app):
    """L'attesa su un blocco e' dichiarata in configurazione, non lasciata al valore
    predefinito della libreria.

    Su PostgreSQL si chiama `lock_timeout` e per difetto e' ZERO, cioe' "attendi
    per sempre": una richiesta che tocca una riga bloccata resterebbe appesa finche'
    qualcuno non la interrompe. Il valore scelto la fa fallire con un messaggio
    leggibile, che e' cio' che l'operatore puo' usare.
    """
    with server_app.app_context():
        from snapserver.db import scalar

        atteso = int(server_app.config["DB_LOCK_TIMEOUT_MS"])
        assert atteso >= 15000, "un'attesa breve fa fallire le operazioni lunghe"
        # `SHOW` restituisce il valore con l'unita' ("30s", "500ms"): si confronta
        # in millisecondi, che e' l'unita' della configurazione.
        grezzo = str(scalar("SHOW lock_timeout"))
        millisecondi = (int(grezzo[:-2]) if grezzo.endswith("ms")
                        else int(float(grezzo[:-1]) * 1000) if grezzo.endswith("s")
                        else int(grezzo))
        assert millisecondi == atteso, (
            "lock_timeout in vigore %s, atteso %d ms" % (grezzo, atteso))
