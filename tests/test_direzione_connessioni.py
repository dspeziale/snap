"""
snap - Test della direzione delle connessioni: la sonda chiama, il server risponde.

PERCHE' ESISTE
La sonda vive nella rete del cliente, dietro un NAT e un firewall che non lascia
entrare nulla: il server **non puo' raggiungerla**, e non ne conosce nemmeno
l'indirizzo (`03_PROTOCOLLO_SNAP_SEC`, assunzione 1.1). Tutto il dialogo va quindi in
una direzione sola -- la sonda apre, il server risponde -- e questo ha due
conseguenze che si dimenticano facilmente scrivendo una funzione nuova:

* cio' che il server vuole FAR FARE alla sonda si accoda (`probe_commands`) e viene
  ritirato al contatto successivo: non si esegue, si prenota;
* cio' che il server vuole SAPERE della sonda arriva con il battito e viene
  rispecchiato con l'istante in cui e' stato consegnato: una fotografia presentata
  come diretta sarebbe una bugia.

Una chiamata diretta verso la sonda non fallirebbe nei test -- fallirebbe in
esercizio, da un cliente, mesi dopo, e sembrerebbe un problema di rete. Questi test
la impediscono prima.

remarks: Autore: Daniele Speziale - Data: 2026-09-13
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

RADICE = Path(__file__).resolve().parent.parent
SERVER = RADICE / "server" / "snapserver"

# Gli unici moduli del server che possono aprire una connessione verso l'esterno, e
# verso chi. Non c'e' nessuna sonda in questo elenco, e non puo' essercene una.
USCITE_AMMESSE = {
    "channels.py": "bot Telegram e server di posta",
    "threat_sources.py": "cataloghi pubblici di vulnerabilita' (NVD, CISA, MITRE)",
    "notifications.py": "server di posta",
}

# `urllib.parse` non apre niente: analizza un URL, e il server lo usa per validare
# gli indirizzi dei controlli. Cio' che apre una connessione e' `urllib.request`.
RE_IMPORT_RETE = re.compile(
    r"^\s*(?:import\s+(?:requests|httpx)\b"
    r"|from\s+(?:requests|httpx)\b"
    r"|import\s+urllib\.(?:request|error)\b"
    r"|from\s+urllib\.(?:request|error)\b)", re.M)


def _moduli_del_server():
    return [p for p in SERVER.rglob("*.py") if "__pycache__" not in str(p)]


# --------------------------------------------------------------------------- #
# Nessuno chiama la sonda
# --------------------------------------------------------------------------- #
def test_solo_i_moduli_dichiarati_aprono_connessioni():
    """Un modulo che comincia a fare richieste HTTP e' la porta da cui entrerebbe una
    chiamata diretta alla sonda: si dichiara qui, con il proprio destinatario."""
    colpevoli = []
    for modulo in _moduli_del_server():
        if modulo.name in USCITE_AMMESSE:
            continue
        testo = modulo.read_text(encoding="utf-8")
        if RE_IMPORT_RETE.search(testo):
            colpevoli.append(str(modulo.relative_to(RADICE)))

    assert not colpevoli, (
        "questi moduli aprono connessioni senza dichiararlo: %s.\n"
        "Se la destinazione e' una sonda, non si puo' fare: la sonda non e'"
        " raggiungibile dal server. Se e' un servizio esterno, va aggiunta a"
        " USCITE_AMMESSE con il motivo." % ", ".join(colpevoli))


def test_nessun_indirizzo_di_sonda_diventa_un_url():
    """Il server non conosce l'indirizzo della sonda, e non deve cominciare a
    costruirselo: un `http://%s` su un campo della tabella `probes` sarebbe
    esattamente la chiamata che il modello di sicurezza esclude."""
    sospetti = []
    RE_URL_COSTRUITO = re.compile(
        r"""(?:https?://[^"']*%s|https?://[^"']*\{)""")
    for modulo in _moduli_del_server():
        testo = modulo.read_text(encoding="utf-8")
        for numero, riga in enumerate(testo.splitlines(), 1):
            if not RE_URL_COSTRUITO.search(riga):
                continue
            # Un URL composto che nella stessa riga nomina la sonda: e' il caso da
            # fermare. Gli altri (console del server, cataloghi) restano leciti.
            if re.search(r"\bprobe\b|\bsonda\b|probe_id|probe\[", riga):
                sospetti.append("%s:%d %s" % (modulo.name, numero, riga.strip()))

    assert not sospetti, (
        "indirizzi di sonda usati come URL:\n%s" % "\n".join(sospetti))


# --------------------------------------------------------------------------- #
# Cio' che il server vuole far fare si accoda
# --------------------------------------------------------------------------- #
def test_un_comando_si_accoda_e_non_si_esegue(logged_client, server_app):
    """Il comando non parte: resta in attesa del prossimo contatto della sonda, e
    all'operatore lo si dice -- altrimenti aspetterebbe un effetto che non arriva."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        tenant = query("SELECT id FROM tenants ORDER BY name", (), one=True)
        sonda = execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, created_at,"
            " updated_at) VALUES (?, 'uid-direzione', 'PD', 'sonda', 'active', ?, ?)",
            (tenant["id"], utc_now_str(), utc_now_str()))

    risposta = logged_client.post("/probes/%d/command" % sonda,
                                  data={"command": "flush"},
                                  follow_redirects=True)
    testo = risposta.get_data(as_text=True)

    assert risposta.status_code == 200
    assert "prossimo contatto" in testo, (
        "l'operatore deve sapere che il comando e' prenotato, non eseguito")

    with server_app.app_context():
        from snapserver.db import query

        coda = query("SELECT command, status FROM probe_commands WHERE probe_id = ?",
                     (sonda,))

    assert len(coda) == 1
    assert coda[0]["status"] == "pending", (
        "il comando resta in coda finche' la sonda non lo ritira")


# --------------------------------------------------------------------------- #
# Cio' che il server vuole sapere e' un rispecchiamento
# --------------------------------------------------------------------------- #
def test_la_console_della_sonda_e_un_rispecchiamento(logged_client, server_app):
    """La pagina mostra l'ultima istantanea consegnata con il battito, e ne dichiara
    l'istante. Non apre nessuna connessione: la sonda potrebbe essere spenta, dietro
    un NAT, o in un'altra rete, e la pagina deve aprirsi lo stesso."""
    import json

    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        tenant = query("SELECT id FROM tenants ORDER BY name", (), one=True)
        istantanea = json.dumps({"riquadri": [], "scan": {"attiva": True}})
        sonda = execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status,"
            " agent_version, console_json, console_at, created_at, updated_at)"
            " VALUES (?, 'uid-specchio', 'PS', 'sonda', 'active', '1.2.2', ?, ?, ?, ?)",
            (tenant["id"], istantanea, utc_now_str(), utc_now_str(), utc_now_str()))

    risposta = logged_client.get("/probes/%d/console" % sonda)

    assert risposta.status_code == 200
    testo = risposta.get_data(as_text=True)
    # L'istante della consegna e' parte della risposta: una fotografia presentata
    # come diretta sarebbe una bugia.
    assert "aggiornata" in testo.lower() or "consegnat" in testo.lower() or (
        "istantanea" in testo.lower()), (
        "la pagina deve dichiarare quando l'istantanea e' stata consegnata")


def test_la_console_si_apre_anche_senza_istantanea(logged_client, server_app):
    """Una sonda che non ha mai parlato non blocca la pagina: si dichiara che non c'e'
    nulla da mostrare. Se il server provasse a contattarla, qui aspetterebbe un
    timeout -- ed e' il sintomo con cui una chiamata diretta si manifesta."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        tenant = query("SELECT id FROM tenants ORDER BY name", (), one=True)
        sonda = execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, created_at,"
            " updated_at) VALUES (?, 'uid-muta', 'PM', 'muta', 'pending', ?, ?)",
            (tenant["id"], utc_now_str(), utc_now_str()))

    risposta = logged_client.get("/probes/%d/console" % sonda)

    assert risposta.status_code == 200


# --------------------------------------------------------------------------- #
# La regola sta scritta dove la si cerca
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("documento,frase", [
    ("docs/03_PROTOCOLLO_SNAP_SEC.md", "Il server non conosce l'indirizzo della sonda"),
])
def test_la_direzione_e_dichiarata_nel_protocollo(documento, frase):
    testo = (RADICE / documento).read_text(encoding="utf-8")

    assert frase in testo, (
        "la regola sulla direzione delle connessioni deve restare scritta in %s"
        % documento)


# --------------------------------------------------------------------------- #
# I due schemi non si toccano
# --------------------------------------------------------------------------- #
# Sonda e console sono due applicativi separati con due basi dati, e in esercizio non
# si incontrano. I test invece li mettono sullo stesso PostgreSQL -- quattordici file
# lo fanno -- e li' una tabella che si chiama come quella dell'altro AVENDO COLONNE
# DIVERSE produce un guasto che non somiglia alla sua causa: `CREATE TABLE IF NOT
# EXISTS` non crea niente, e l'indice successivo fallisce su una colonna inesistente.
#
# E' successo con `ids_findings`, `agent_metrics` e `agent_events`. La regola e' che
# le tabelle proprie della sonda portino il prefisso `local_`, come `local_nodes`.
RE_TABELLA = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?\"?(\w+)", re.I)
RE_INDICE = re.compile(r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?\"?(\w+)", re.I)


def _schema_del_server() -> str:
    return (SERVER / "schema.sql").read_text(encoding="utf-8")


def _schema_della_sonda() -> str:
    """Lo schema vero, non il file che lo contiene.

    Leggendo il sorgente si raccoglievano anche i `CREATE TABLE` citati nei commenti,
    e da uno di quelli usciva una tabella di nome "IF": un test che confronta insiemi
    deve confrontare cose vere, o prima o poi segnala qualcosa che non esiste.
    """
    from snapprobe.store import SCHEMA

    return SCHEMA


def test_nessuna_tabella_si_chiama_come_una_del_server():
    """Stesso nome e colonne diverse: il guasto non somiglia alla sua causa."""
    del_server = set(RE_TABELLA.findall(_schema_del_server()))
    della_sonda = set(RE_TABELLA.findall(_schema_della_sonda()))
    comuni = del_server & della_sonda
    assert not comuni, (
        "tabelle con lo stesso nome nei due schemi: %s."
        " Le tabelle proprie della sonda vanno prefissate con local_"
        % ", ".join(sorted(comuni)))


def test_nessun_indice_si_chiama_come_uno_del_server():
    """Il nome di un indice e' unico per database quanto quello di una tabella."""
    del_server = set(RE_INDICE.findall(_schema_del_server()))
    della_sonda = set(RE_INDICE.findall(_schema_della_sonda()))
    comuni = del_server & della_sonda
    assert not comuni, "indici con lo stesso nome nei due schemi: %s" % ", ".join(
        sorted(comuni))
