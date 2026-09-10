# -----------------------------------------------------------------
# db.py — strato dati della sonda su PostgreSQL
# Autore: Daniele Speziale
# Data creazione: 2026-09-10
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap probe - Connessione all'archivio della sonda.

PERCHE' ESISTE, E PERCHE' E' UN GEMELLO DI QUELLO DEL SERVER
------------------------------------------------------------
La sonda scriveva su SQLite: un file nel volume, con un lucchetto in memoria a
serializzare i thread. Funzionava, e aveva due difetti che con trentadue thread di
scansione si sentono. Il primo e' che un file singolo non regge scritture
concorrenti: il lucchetto le metteva in fila, quindi il parallelismo del pool si
fermava all'archivio. Il secondo e' che l'archivio della sonda e' una CODA DI
CONFERIMENTO che deve sopravvivere a giorni di server irraggiungibile su un apparato
lasciato in sede: un file che si corrompe e' la perdita di tutto cio' che si e'
raccolto.

Questo modulo rispecchia `snapserver.db` invece di importarlo: sonda e server sono
due applicativi distinti, installati su macchine diverse, e non condividono codice --
la sonda sta nella rete del cliente, il server altrove. La duplicazione e'
deliberata e dichiarata: la regola e' che una correzione qui va portata anche la',
e le due copie vanno tenute allineate.

I SEGNAPOSTO `?`
----------------
Le sessanta e piu' interrogazioni della sonda sono scritte con `?`, il paramstyle di
SQLite. Si traducono qui, in un punto solo (`_con_segnaposto`), invece di riscriverle
una per una: riscriverle sarebbe stata la strada piu' breve per sostituire un
parametro con una concatenazione di stringhe. I valori restano SEMPRE parametri.
"""

from __future__ import annotations

import os
import re
import threading
from collections.abc import Mapping

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

# Motore unico per processo. La sonda non ha il contesto di richiesta di Flask per le
# proprie scansioni (girano in thread propri), quindi il motore sta qui e le
# connessioni si prendono dal pool a ogni operazione.
_motore: Engine | None = None
_serratura_motore = threading.Lock()

# Quante connessioni al massimo. Il pool serve i trentadue thread di scansione piu'
# l'agente, i controlli e l'interfaccia locale: si dimensiona su quelli, non a caso.
POOL_DIMENSIONE = 10
POOL_OLTRE = 30

RE_NON_IDENTIFICATORE = re.compile(r"[^a-zA-Z0-9_]")


def dsn() -> str:
    """Stringa di connessione dell'archivio della sonda.

    Da variabile d'ambiente: mai una credenziale nel codice. Il nome della variabile
    e' quello del contenitore (`docker/probe/.env`).
    """
    valore = (os.environ.get("SNAP_PROBE_DATABASE_URL") or "").strip()
    if not valore:
        raise RuntimeError(
            "Archivio della sonda non configurato: manca SNAP_PROBE_DATABASE_URL"
            " (postgresql+psycopg://utente:password@host:5432/database)")
    return valore


def motore() -> Engine:
    """Il motore di connessione, uno per processo.

    `pool_pre_ping` verifica la connessione prima di usarla e `pool_recycle` la
    rinnova: il contenitore della base dati puo' riavviarsi, e una connessione tenuta
    aperta attraverso quel riavvio e' morta senza dirlo.
    """
    global _motore
    if _motore is not None:
        return _motore
    with _serratura_motore:
        if _motore is None:
            _motore = create_engine(
                dsn(), pool_pre_ping=True, pool_recycle=1800,
                pool_size=POOL_DIMENSIONE, max_overflow=POOL_OLTRE,
                future=True)
    return _motore


def dsn_proprietario() -> str:
    """Indirizzo dell'utenza PROPRIETARIA, quella che puo' creare e migrare.

    Minimo privilegio, come sul server: l'utenza applicativa legge e scrive i dati e
    NON puo' cambiare la struttura -- cosi' un difetto del programma non puo'
    cancellare una tabella. Lo schema lo crea il proprietario, all'avvio.

    Se non e' dichiarata si usa quella applicativa: e' il caso dello sviluppo e dei
    test, dove il database del test lo crea e lo possiede la stessa utenza.
    """
    return (os.environ.get("SNAP_PROBE_OWNER_DATABASE_URL") or "").strip() or dsn()


def motore_proprietario() -> Engine:
    """Motore dell'utenza proprietaria. Non si tiene in cache: serve all'avvio."""
    return create_engine(dsn_proprietario(), pool_pre_ping=True, future=True)


def azzera_motore() -> None:
    """Dimentica il motore: serve ai test, che ne cambiano il bersaglio."""
    global _motore
    with _serratura_motore:
        if _motore is not None:
            _motore.dispose()
        _motore = None


class Riga(Mapping):
    """Riga di risultato leggibile per NOME e per POSIZIONE.

    Il codice della sonda legge le righe come faceva con `sqlite3.Row`: per nome, per
    posizione e come dizionario. Le righe di SQLAlchemy 2 espongono i nomi solo
    attraverso `_mapping`.

    UNA DIFFERENZA DA `sqlite3.Row`, che va conosciuta perche' e' silenziosa: qui vale
    il contratto dei Mapping, quindi **scorrere una riga da' i NOMI delle colonne**,
    non i valori. Per i valori: `celle()`. Sul server la stessa differenza ha fatto
    esportare in CSV una riga di intestazioni al posto dei dati.
    """

    __slots__ = ("_valori", "_celle")

    def __init__(self, mappa, celle=None):
        self._valori = dict(mappa)
        self._celle = (tuple(celle) if celle is not None
                       else tuple(self._valori.values()))

    def __getitem__(self, chiave):
        if isinstance(chiave, int):
            return self._celle[chiave]
        return self._valori[chiave]

    def celle(self) -> tuple:
        return self._celle

    def __iter__(self):
        return iter(self._valori)

    def __len__(self):
        return len(self._valori)

    def keys(self):
        return self._valori.keys()

    def get(self, chiave, predefinito=None):
        return self._valori.get(chiave, predefinito)


def _con_segnaposto(sql: str) -> str:
    """Traduce i segnaposto `?` nella forma con nome usata da SQLAlchemy.

    I `?` dentro una stringa SQL (fra apici) non si toccano: sono dati, non
    segnaposto.
    """
    pezzi = []
    indice = 0
    in_stringa = False
    for carattere in sql:
        if carattere == "'":
            in_stringa = not in_stringa
            pezzi.append(carattere)
        elif carattere == "?" and not in_stringa:
            pezzi.append(":p%d" % indice)
            indice += 1
        else:
            pezzi.append(carattere)
    return "".join(pezzi)


def _legati(params) -> dict:
    """Parametri posizionali nella forma con nome attesa da `_con_segnaposto`."""
    if params is None:
        return {}
    if isinstance(params, Mapping):
        return dict(params)
    return {"p%d" % indice: valore for indice, valore in enumerate(params)}


def esegui(connection, sql: str, params: tuple | list = ()):
    """Esegue un'istruzione su una connessione GIA' aperta, con i segnaposto `?`."""
    return connection.execute(text(_con_segnaposto(sql)), _legati(params))


def righe(connection, sql: str, params: tuple | list = ()) -> list:
    """Come `esegui`, ma restituisce righe leggibili per nome e per posizione."""
    risultato = esegui(connection, sql, params)
    return [Riga(r._mapping, tuple(r)) for r in risultato.all()]


def una_riga(connection, sql: str, params: tuple | list = ()) -> Riga | None:
    elenco = righe(connection, sql, params)
    return elenco[0] if elenco else None


def inserisci(connection, sql: str, params: tuple | list = ()) -> int:
    """Esegue un INSERT e restituisce l'identificativo generato.

    Sostituisce `cursor.lastrowid` di SQLite, che su PostgreSQL non esiste: si chiede
    `RETURNING id` all'istruzione. Se l'istruzione non lo prevede si restituisce 0 --
    non tutte le tabelle hanno una chiave generata.
    """
    testo = sql.rstrip().rstrip(";")
    if " returning " not in testo.lower():
        testo += " RETURNING id"
    risultato = esegui(connection, testo, params)
    riga = risultato.first()
    return int(riga[0]) if riga is not None else 0


def nome_sicuro(valore: str) -> str:
    """Un identificatore SQL ripulito.

    Serve ai pochi punti che compongono il nome di una tabella o di uno schema (le
    migrazioni, i test): quei nomi vengono dal codice, non dall'esterno, e restano
    comunque ripuliti perche' nessuna distrazione futura possa farne un varco.
    """
    return RE_NON_IDENTIFICATORE.sub("", str(valore or ""))[:63]


# --------------------------------------------------------------------------- #
# Adattatore: parla come sqlite3, scrive su PostgreSQL
# --------------------------------------------------------------------------- #
class Cursore:
    """Il risultato di un'istruzione, con l'interfaccia di un cursore sqlite3.

    Esiste per una ragione di misura: l'archivio della sonda ha oltre sessanta punti
    di SQL scritti sull'interfaccia di `sqlite3`. Riscriverli tutti per passare a
    PostgreSQL avrebbe significato sessanta occasioni di sbagliare -- e in un
    archivio che e' una CODA DI CONFERIMENTO, un errore silenzioso e' dato perso.
    Con questo adattatore le interrogazioni restano quelle verificate, e cio' che
    cambia e' il solo strato che le esegue.
    """

    __slots__ = ("_risultato", "_righe", "_lette")

    def __init__(self, risultato):
        self._risultato = risultato
        self._righe = None
        self._lette = False

    def _tutte(self) -> list:
        if self._righe is None:
            if self._risultato.returns_rows:
                self._righe = [Riga(r._mapping, tuple(r))
                               for r in self._risultato.all()]
            else:
                self._righe = []
        return self._righe

    def fetchone(self):
        righe_lette = self._tutte()
        if self._lette or not righe_lette:
            return None
        self._lette = True
        return righe_lette[0]

    def fetchall(self) -> list:
        return list(self._tutte())

    def __iter__(self):
        return iter(self._tutte())

    @property
    def rowcount(self) -> int:
        """Righe toccate. Con `ON CONFLICT DO NOTHING` e' 0 quando non ha inserito:
        e' esattamente la semantica su cui si regge la prenotazione atomica dei
        bersagli di scansione."""
        return int(self._risultato.rowcount or 0)


class Connessione:
    """Connessione con l'interfaccia di `sqlite3.Connection`, su PostgreSQL.

    La transazione e' governata da `ProbeStore._connect()`: entrando si apre,
    uscendo senza eccezioni si conferma. E' lo stesso contratto che aveva
    `sqlite3.connect(...)` usata come gestore di contesto, quindi il codice che la
    usa non cambia.
    """

    __slots__ = ("_c",)

    def __init__(self, connection):
        self._c = connection

    def execute(self, sql: str, params: tuple | list = ()) -> Cursore:
        return Cursore(esegui(self._c, sql, params))

    def executemany(self, sql: str, elenco) -> Cursore:
        serie = [_legati(p) for p in elenco]
        if not serie:
            return Cursore(esegui(self._c, "SELECT 1 WHERE false"))
        return Cursore(self._c.execute(text(_con_segnaposto(sql)), serie))

    def executescript(self, sql: str) -> None:
        """Esegue piu' istruzioni in un solo invio: serve allo schema iniziale."""
        self._c.exec_driver_sql(sql)

    def inserisci(self, sql: str, params: tuple | list = ()) -> int:
        """INSERT che restituisce l'identificativo generato.

        Sostituisce `cursor.lastrowid`, che su PostgreSQL non esiste: qui si chiede
        `RETURNING id` all'istruzione.
        """
        return inserisci(self._c, sql, params)

    @property
    def sottostante(self):
        """La connessione SQLAlchemy vera: serve ai pochi punti che fanno DDL."""
        return self._c
