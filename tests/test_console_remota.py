# -----------------------------------------------------------------
# test_console_remota.py — governare la sonda dal server, senza raggiungerla
# Autore: Daniele Speziale
# Data creazione: 2026-09-15
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap - La console remota fa quello che fa la console locale.

IL VINCOLO CHE NON SI TOCCA: il server non apre mai una connessione verso la sonda.
Non si puo' quindi "proxare" la console locale, e la richiesta "voglio che diventi a
tutti gli effetti la console della sonda" si soddisfa in un modo solo:

* ogni COMANDO della console locale esiste come comando accodato, consegnato al
  contatto successivo;
* ogni VISTA della console locale viaggia nell'istantanea del battito.

Il risultato per chi guarda e' lo stesso; cio' che cambia e' il ritardo, che la
pagina dichiara invece di nasconderlo.

TRE COSE RESTANO IN SEDE, e non per dimenticanza: la registrazione (e' il momento in
cui la sonda sceglie a chi obbedire), l'emissione di un token per un agente (produce
una credenziale che si vede una volta sola) e l'azzeramento dell'archivio (una
conferma che si clicca da mille chilometri non e' la stessa conferma). Sono
dichiarate nella pagina, e una prova qui sotto pretende che lo restino.

remarks: Autore: Daniele Speziale - Data: 2026-09-15
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

RADICE = Path(__file__).resolve().parent.parent


@pytest.fixture()
def agente(probe_store):
    from snapprobe.agent import ProbeAgent

    return ProbeAgent(probe_store, "prova")


# --------------------------------------------------------------------------- #
# Le viste viaggiano
# --------------------------------------------------------------------------- #
def test_l_istantanea_porta_le_viste_della_console_locale(agente, probe_store):
    """Senza queste, dal server si vedeva la scansione e null'altro."""
    probe_store.set_json("scan_subnets", [{"cidr": "10.0.0.0/24"}])
    istantanea = agente.console_snapshot()

    for vista in ("traffico", "scadenze", "agenti_macchina", "configurazione",
                  "archivio", "ids", "scan", "agent", "diary", "syncs"):
        assert vista in istantanea, "manca la vista %r" % vista


def test_le_interfacce_viaggiano_perche_solo_la_sonda_le_conosce(agente):
    """Senza l'elenco, accendere l'osservazione da remoto sarebbe impossibile: su una
    macchina vera i nomi delle schede non si indovinano."""
    traffico = agente._traffico_console()

    assert "interfacce" in traffico
    assert isinstance(traffico["interfacce"], list)
    # E se la libreria non c'e', lo si DICE invece di mandare un elenco vuoto muto.
    assert traffico["interfacce"] or traffico["assenza"] is not None


def test_l_istantanea_non_porta_mai_la_community_snmp(agente, probe_store):
    """Un segreto che torna indietro e' un segreto conservato in un posto in piu'."""
    from snapprobe import snmp_raccolta

    probe_store.set_setting(snmp_raccolta.CHIAVE_COMMUNITY, "segretissima")
    istantanea = agente.console_snapshot()

    assert "segretissima" not in json.dumps(istantanea, default=str)
    # Ma si dice CHE c'e': altrimenti dal server non si saprebbe se configurarla.
    assert istantanea["configurazione"]["snmp_community_impostata"] is True


def test_l_istantanea_non_porta_i_pacchetti(agente, probe_store):
    """Sono il traffico di chi lavora su quella rete: restano sulla sonda, con la
    loro ritenzione di venti minuti. Dal server se ne sa il NUMERO."""
    istantanea = agente.console_snapshot()

    assert "pacchetti" in istantanea["traffico"]
    assert isinstance(istantanea["traffico"]["pacchetti"], int)
    assert "righe" not in istantanea["traffico"]


# --------------------------------------------------------------------------- #
# I comandi si eseguono
# --------------------------------------------------------------------------- #
def test_il_comando_accende_l_osservazione_del_traffico(agente, probe_store):
    from snapprobe import ids as modulo_ids

    esito = agente._run_command("traffico", {"attiva": True, "interfaccia": "eth0",
                                             "filtro": "arp"})

    assert probe_store.get_setting(modulo_ids.CHIAVE_TRAFFICO_ATTIVO) == "1"
    assert probe_store.get_setting(modulo_ids.CHIAVE_TRAFFICO_INTERFACCIA) == "eth0"
    assert probe_store.get_setting(modulo_ids.CHIAVE_TRAFFICO_FILTRO) == "arp"
    assert "eth0" in esito


def test_il_comando_spegne_l_osservazione(agente, probe_store):
    from snapprobe import ids as modulo_ids

    agente._run_command("traffico", {"attiva": True, "interfaccia": "eth0"})
    agente._run_command("traffico", {"attiva": False})

    assert probe_store.get_setting(modulo_ids.CHIAVE_TRAFFICO_ATTIVO) == "0"


def test_accendere_senza_interfaccia_viene_rifiutato(agente):
    """Il rifiuto torna al server nell'esito del comando: chi l'ha premuto lo vede."""
    with pytest.raises(ValueError, match="interfaccia"):
        agente._run_command("traffico", {"attiva": True})


def test_il_comando_configura_snmp_senza_cancellare_la_community(agente, probe_store):
    """Salvare senza riscrivere la community non deve cancellarla: e' il modo in cui
    si spegne la lettura SNMP per sbaglio."""
    from snapprobe import snmp_raccolta

    probe_store.set_setting(snmp_raccolta.CHIAVE_COMMUNITY, "vecchia")
    agente._run_command("snmp_config", {"attivo": True, "apparati": "10.0.0.1|Router"})

    assert probe_store.get_setting(snmp_raccolta.CHIAVE_COMMUNITY) == "vecchia"
    assert probe_store.get_setting(snmp_raccolta.CHIAVE_ATTIVA) == "1"


def test_un_comando_snmp_vuoto_viene_rifiutato(agente):
    with pytest.raises(ValueError):
        agente._run_command("snmp_config", {})


def test_ogni_comando_dichiarato_dal_server_e_eseguibile_dalla_sonda():
    """Le due meta' devono combaciare: un comando offerto da un pulsante e non
    riconosciuto dalla sonda e' un pulsante che non fa niente, e nessuno se ne
    accorge finche' qualcuno non lo preme."""
    import sys

    sys.path.insert(0, str(RADICE / "server"))
    from snapserver.blueprints.probes import AVAILABLE_COMMANDS, COMANDI_CON_DATI

    sorgente = (RADICE / "probe" / "snapprobe" / "agent.py").read_text(encoding="utf-8")
    inizio = sorgente.index("def _run_command")
    corpo = sorgente[inizio:sorgente.index("def flush_queue", inizio)]

    for comando in list(AVAILABLE_COMMANDS) + list(COMANDI_CON_DATI):
        assert '"%s"' % comando in corpo, (
            "il server offre il comando %r ma la sonda non lo riconosce" % comando)


# --------------------------------------------------------------------------- #
# Il vincolo: nessuna connessione verso la sonda
# --------------------------------------------------------------------------- #
def test_il_server_non_contatta_la_sonda_per_governarla():
    """La regola che rende accettabile questo prodotto nella rete di un cliente. Le
    rotte nuove accodano e basta: se una aprisse una connessione, sarebbe qui."""
    sorgente = (RADICE / "server" / "snapserver" / "blueprints"
                / "probes.py").read_text(encoding="utf-8")

    for vietato in ("requests.", "urlopen", "http.client", "socket.create_connection"):
        assert vietato not in sorgente, (
            "probes.py contiene %r: il server non deve contattare la sonda" % vietato)


def test_le_tre_cose_che_restano_in_sede_sono_dichiarate():
    """Chi le cerca deve sapere dove sono e perche' non sono qui, invece di
    concludere che manchino."""
    import sys

    sys.path.insert(0, str(RADICE / "server"))
    from snapserver.blueprints.probes import SOLO_IN_SEDE

    assert len(SOLO_IN_SEDE) == 3
    for voce, perche in SOLO_IN_SEDE:
        assert voce and len(perche) > 40, "il motivo deve essere scritto, non accennato"

    modello = (RADICE / "server" / "snapserver" / "templates" / "probes"
               / "console.html").read_text(encoding="utf-8")
    assert "solo_in_sede" in modello, "la pagina non le dichiara"


# --------------------------------------------------------------------------- #
# Le rotte del server
# --------------------------------------------------------------------------- #
@pytest.fixture()
def sonda_registrata(server_app):
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        tenant = query("SELECT id FROM tenants ORDER BY id LIMIT 1", (), one=True)
        execute("INSERT INTO probes (tenant_id, probe_uid, code, name, status,"
                " enrolled_at, created_at, updated_at) VALUES (?, 'uid-prova-remota',"
                " 'prova-remota', 'Prova', 'active', ?, ?, ?)",
                (int(tenant["id"]), utc_now_str(), utc_now_str(), utc_now_str()))
        riga = query("SELECT id FROM probes WHERE code = 'prova-remota'", (), one=True)
        return int(riga["id"])


def _comandi(server_app, sonda_id):
    with server_app.app_context():
        from snapserver.db import query

        return [dict(r) for r in query(
            "SELECT command, payload_json FROM probe_commands WHERE probe_id = ?"
            " ORDER BY id DESC", (sonda_id,))]


def test_la_rotta_accoda_l_osservazione_del_traffico(logged_client, server_app,
                                                     sonda_registrata):
    logged_client.post("/probes/%d/traffico" % sonda_registrata,
                       data={"traffico_attivo": "1",
                             "traffico_interfaccia": "eth0",
                             "traffico_filtro": "arp"}, follow_redirects=True)

    accodati = _comandi(server_app, sonda_registrata)
    assert accodati and accodati[0]["command"] == "traffico"
    payload = json.loads(accodati[0]["payload_json"])
    assert payload == {"attiva": True, "interfaccia": "eth0", "filtro": "arp"}


def test_accendere_senza_interfaccia_non_accoda_niente(logged_client, server_app,
                                                       sonda_registrata):
    risposta = logged_client.post("/probes/%d/traffico" % sonda_registrata,
                                  data={"traffico_attivo": "1"},
                                  follow_redirects=True)

    assert "serve scegliere un'interfaccia" in risposta.get_data(as_text=True).replace(
        "&#39;", "'")
    assert _comandi(server_app, sonda_registrata) == []


def test_accendere_il_traffico_resta_nel_registro_delle_azioni(logged_client,
                                                               server_app,
                                                               sonda_registrata):
    """Riguarda le PERSONE che lavorano su quella rete: fra sei mesi si deve poter
    sapere chi l'ha acceso, quando e su che cosa."""
    logged_client.post("/probes/%d/traffico" % sonda_registrata,
                       data={"traffico_attivo": "1", "traffico_interfaccia": "eth0"},
                       follow_redirects=True)

    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT event_type, description, severity FROM audit_events"
                     " WHERE event_type = 'probe.traffico' ORDER BY id DESC LIMIT 1",
                     (), one=True)

    assert riga is not None, "l'accensione non e' stata registrata"
    assert "eth0" in riga["description"]
    assert riga["severity"] == "warning"


def test_la_rotta_snmp_non_cancella_la_community_se_lasciata_vuota(
        logged_client, server_app, sonda_registrata):
    logged_client.post("/probes/%d/snmp" % sonda_registrata,
                       data={"snmp_attivo": "1", "snmp_community": "",
                             "snmp_apparati": "10.0.0.1|Router"},
                       follow_redirects=True)

    payload = json.loads(_comandi(server_app, sonda_registrata)[0]["payload_json"])
    assert "community" not in payload, (
        "una community vuota non deve viaggiare: cancellerebbe quella impostata")
    assert payload["apparati"] == "10.0.0.1|Router"
