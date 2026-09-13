"""
snap - Test del motore di rilevazione delle intrusioni.

CHE COSA PROTEGGONO
-------------------
1. **I due cataloghi non devono divergere.** Le regole vivono sulla sonda
   (`probe/snapprobe/ids.py`); la console ne tiene una copia per poter spiegare una
   rilevazione anche quando la sonda non e' raggiungibile -- e non lo e' mai, per
   costruzione. Due elenchi che si allontanano in silenzio sono peggio di uno solo
   incompleto: la pagina mostrerebbe il codice grezzo, o una gravita' diversa da
   quella con cui la rilevazione e' stata prodotta.

2. **Il primo giro non giudica.** Senza un prima, ogni cosa e' "mai vista": alla
   prima passata su una rete vera sono uscite quattrocento rilevazioni HOST-NUOVO,
   che e' il modo piu' rapido per far disattivare un IDS. La maturita' del singolo
   soggetto non basta -- serve quella dell'archivio.

3. **Un sensore che non guarda va dichiarato.** Il suo zero non e' "tutto a posto",
   e' "non guardato": se il motore lo tacesse, la pagina mostrerebbe una calma che
   nessuno ha verificato.

4. **Le due allowlist devono coincidere.** Un genere dichiarato sulla sonda e non sul
   server (o viceversa) si raccoglie, si accoda e si perde senza che nessuna pagina
   lo dica.

remarks: Autore: Daniele Speziale - Data: 2026-09-13
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

UTC = "%Y-%m-%d %H:%M:%S"


def _istante(ore_fa: float = 0) -> datetime:
    return (datetime.now(timezone.utc) - timedelta(hours=ore_fa)).replace(microsecond=0)


# --------------------------------------------------------------------------- #
# I due cataloghi
# --------------------------------------------------------------------------- #
def test_catalogo_regole_identico_fra_sonda_e_console():
    """Stessi codici, stessa gravita', stessa tecnica ATT&CK.

    Il nome puo' essere scritto una volta sola in due file, ma se diverge la pagina
    del server chiamerebbe una cosa con un nome che la sonda non usa: si confronta
    anche quello.
    """
    from snapprobe.ids import REGOLE as SONDA
    from snapserver.blueprints.ids_views import REGOLE as CONSOLE

    assert set(SONDA) == set(CONSOLE), (
        "cataloghi divergenti: solo sonda %s, solo console %s"
        % (sorted(set(SONDA) - set(CONSOLE)), sorted(set(CONSOLE) - set(SONDA))))

    for codice, regola in SONDA.items():
        nome, gravita, tecnica = CONSOLE[codice]
        assert regola["nome"] == nome, codice
        assert regola["gravita"] == gravita, codice
        assert regola["tecnica"] == tecnica, codice


def test_ogni_regola_dichiara_il_perche():
    """Una rilevazione senza motivo e' un allarme che si impara a ignorare."""
    from snapprobe.ids import REGOLE

    for codice, regola in REGOLE.items():
        assert regola.get("perche", "").strip(), "%s non dice perche' conta" % codice
        assert len(regola["perche"]) > 40, "%s: motivo troppo breve" % codice


def test_gravita_appartengono_alla_scala_della_console():
    from snapprobe.ids import REGOLE
    from snapserver.blueprints.ids_views import ORDINE_GRAVITA

    for codice, regola in REGOLE.items():
        assert regola["gravita"] in ORDINE_GRAVITA, codice


def test_sensori_dichiarati_nei_due_lati():
    """L'elenco dei sensori della console rispecchia quelli della sonda."""
    from snapprobe.ids import SENSORI
    from snapserver.blueprints.ids_views import SENSORI as CONSOLE

    assert ([s.codice for s in SENSORI]
            == [s["codice"] for s in CONSOLE])


def test_le_due_allowlist_coincidono_sui_generi_ids_e_agenti():
    """Un genere in un elenco solo si raccoglie, si accoda e si perde."""
    from snapprobe.agent import RECORD_TYPES
    from snapserver.ingest import _APPLICATORI

    for genere in ("ids_findings", "agent_hosts", "agent_metrics", "agent_events"):
        assert genere in RECORD_TYPES, "%s manca nella sonda" % genere
        assert genere in _APPLICATORI, "%s manca nel server" % genere


# --------------------------------------------------------------------------- #
# La linea di base
# --------------------------------------------------------------------------- #
def test_prima_volta_non_e_un_cambiamento(probe_store):
    esito = probe_store.ids_confronta("porta", "10.0.0.1:22", "aperta", _istante())
    assert esito["nuovo"] is True
    assert esito["cambiato"] is False
    assert esito["maturo"] is False


def test_cambiamento_su_memoria_giovane_si_registra_ma_non_matura(probe_store):
    """Non si puo' dire "e' cambiato" di qualcosa visto un minuto fa."""
    adesso = _istante()
    probe_store.ids_confronta("porta", "10.0.0.2:22", "chiusa", adesso)
    esito = probe_store.ids_confronta("porta", "10.0.0.2:22", "aperta",
                                      adesso + timedelta(minutes=5))
    assert esito["cambiato"] is True
    assert esito["maturo"] is False


def test_cambiamento_su_memoria_matura_vale_come_rilevazione(probe_store):
    from snapprobe.ids import MATURITA_ORE

    nascita = _istante(ore_fa=MATURITA_ORE + 1)
    probe_store.ids_confronta("porta", "10.0.0.3:22", "chiusa", nascita)
    esito = probe_store.ids_confronta("porta", "10.0.0.3:22", "aperta", _istante())
    assert esito["cambiato"] is True
    assert esito["maturo"] is True
    assert esito["prima"] == "chiusa"


def test_la_memoria_si_aggiorna_sempre(probe_store):
    """Altrimenti la stessa rilevazione tornerebbe a ogni giro."""
    from snapprobe.ids import MATURITA_ORE

    nascita = _istante(ore_fa=MATURITA_ORE + 1)
    probe_store.ids_confronta("porta", "10.0.0.4:22", "chiusa", nascita)
    probe_store.ids_confronta("porta", "10.0.0.4:22", "aperta", _istante())
    secondo = probe_store.ids_confronta("porta", "10.0.0.4:22", "aperta", _istante())
    assert secondo["cambiato"] is False


# --------------------------------------------------------------------------- #
# Il primo giro non giudica
# --------------------------------------------------------------------------- #
def test_archivio_vuoto_non_e_maturo(probe_store):
    memoria = probe_store.ids_memoria_matura()
    assert memoria["matura"] is False
    assert memoria["soggetti"] == 0


def test_archivio_appena_nato_non_e_maturo(probe_store):
    probe_store.ids_confronta("nodo_visto", "10.0.0.5", "1", _istante())
    memoria = probe_store.ids_memoria_matura()
    assert memoria["matura"] is False
    assert memoria["soggetti"] == 1


def test_archivio_vecchio_e_maturo(probe_store):
    from snapprobe.ids import MATURITA_ORE

    probe_store.ids_confronta("nodo_visto", "10.0.0.6", "1",
                              _istante(ore_fa=MATURITA_ORE + 2))
    memoria = probe_store.ids_memoria_matura()
    assert memoria["matura"] is True
    assert memoria["ore"] >= MATURITA_ORE


def test_host_nuovo_tace_finche_la_memoria_e_giovane(probe_store, monkeypatch):
    """La prova che ha motivato la correzione: quattrocento HOST-NUOVO al primo giro.

    Con l'archivio giovane il sensore dell'inventario deve costruire la linea di base
    e non produrre nemmeno una rilevazione "mai visto".
    """
    from snapprobe.ids import SensoreInventario

    nodi = [{"ip": "10.0.0.%d" % n, "mac": "aa:bb:cc:dd:ee:%02x" % n,
             "hostname": "host%d" % n, "stato": "confirmed", "porte": [], "smb1": None}
            for n in range(1, 21)]
    monkeypatch.setattr(probe_store, "ids_nodi_osservati", lambda: nodi)
    monkeypatch.setattr(probe_store, "ids_presenze_recenti", lambda minuti=30: [])

    trovate = SensoreInventario().osserva(probe_store, _istante())
    assert [r for r in trovate if r.regola == "HOST-NUOVO"] == []


# --------------------------------------------------------------------------- #
# Rilevazioni: la stessa cosa si aggiorna, non si duplica
# --------------------------------------------------------------------------- #
def _registra(store, soggetto="10.0.0.9", regola="PORTA-AMMINISTRAZIONE"):
    return store.ids_registra(
        regola=regola, gravita="alta", sensore="inventario", soggetto=soggetto,
        titolo="3389 aperta dove non c'era", prova="prima: chiusa",
        tecnica="T1021", dati={"porta": 3389},
        adesso=datetime.now(timezone.utc).strftime(UTC))


def test_stessa_rilevazione_si_aggiorna(probe_store):
    assert _registra(probe_store) == "nuova"
    assert _registra(probe_store) == "aggiornata"
    righe = probe_store.ids_rilevazioni()
    assert len(righe) == 1
    assert righe[0]["conteggio"] == 2


def test_una_rilevazione_aggiornata_torna_da_conferire(probe_store):
    """Se il fatto si ripresenta, il server deve rivederlo: non e' "gia' detto"."""
    _registra(probe_store)
    identificativi = [r["id"] for r in probe_store.ids_rilevazioni(solo_da_conferire=True)]
    probe_store.ids_segna_conferite(identificativi,
                                    datetime.now(timezone.utc).strftime(UTC))
    assert probe_store.ids_rilevazioni(solo_da_conferire=True) == []
    _registra(probe_store)
    assert len(probe_store.ids_rilevazioni(solo_da_conferire=True)) == 1


# --------------------------------------------------------------------------- #
# Il motore
# --------------------------------------------------------------------------- #
def test_sensore_non_disponibile_viene_dichiarato_non_taciuto(probe_store):
    from snapprobe.ids import MotoreIDS

    esito = MotoreIDS(probe_store).esegui()
    saltati = {s["sensore"] for s in esito["sensori_saltati"]}
    # Senza agenti installati e senza cattura del traffico, due sensori su tre non
    # osservano: l'esito deve dirlo, altrimenti il suo zero si legge come una calma.
    assert "traffico" in saltati
    assert "agenti" in saltati
    for saltato in esito["sensori_saltati"]:
        assert saltato["motivo"].strip()


def test_un_sensore_rotto_non_ferma_gli_altri(probe_store):
    from snapprobe.ids import MotoreIDS, Sensore

    class Esplosivo(Sensore):
        codice = "esplosivo"
        nome = "Sensore che rompe"
        descrizione = "esiste per rompersi"

        def disponibile(self, archivio):
            return True, "sempre"

        def osserva(self, archivio, adesso):
            raise RuntimeError("archivio illeggibile")

    class Buono(Sensore):
        codice = "buono"
        nome = "Sensore che funziona"
        descrizione = "osserva e basta"

        def disponibile(self, archivio):
            return True, "sempre"

        def osserva(self, archivio, adesso):
            from snapprobe.ids import Rilevazione

            return [Rilevazione("HOST-NUOVO", self.codice, "10.0.0.99",
                                "nodo mai visto", "prima volta", {})]

    esito = MotoreIDS(probe_store, sensori=[Esplosivo(), Buono()]).esegui()
    assert esito["nuove"] == 1
    assert any(s["sensore"] == "esplosivo" for s in esito["sensori_saltati"])


def test_esito_dichiara_la_maturita_della_memoria(probe_store):
    """Chi legge deve sapere PERCHE' non vede rilevazioni."""
    from snapprobe.ids import MotoreIDS

    esito = MotoreIDS(probe_store).esegui()
    assert "memoria" in esito
    assert esito["memoria"]["matura"] is False


def test_la_gravita_della_rilevazione_viene_dal_catalogo(probe_store):
    from snapprobe.ids import REGOLE, Rilevazione

    rilevazione = Rilevazione("SICUREZZA-FERMA", "agenti", "macchina/av",
                              "antivirus disattivato", "servizio fermo", {})
    assert rilevazione.gravita == REGOLE["SICUREZZA-FERMA"]["gravita"]
    assert rilevazione.tecnica == REGOLE["SICUREZZA-FERMA"]["tecnica"]


def test_regola_sconosciuta_non_diventa_una_gravita_inventata():
    """Meglio una gravita' bassa dichiarata che un'alta inventata."""
    from snapprobe.ids import Rilevazione
    from snapserver.blueprints.ids_views import ORDINE_GRAVITA

    rilevazione = Rilevazione("REGOLA-CHE-NON-ESISTE", "inventario", "x", "y", "z", {})
    assert rilevazione.gravita in ORDINE_GRAVITA


# --------------------------------------------------------------------------- #
# Lo stato viaggia col battito: la console non chiama la sonda
# --------------------------------------------------------------------------- #
def test_istantanea_per_la_console_porta_lo_stato_ids(probe_store, monkeypatch):
    """Il server non puo' chiedere: se non viaggia col battito, non esiste."""
    import snapprobe.agent as modulo_agente

    class AgenteFinto(modulo_agente.ProbeAgent):
        def __init__(self, store):  # noqa: D107 - solo lo stretto necessario
            self.store = store

        def status(self):
            return {}

    finto = AgenteFinto(probe_store)
    stato = finto._ids_console()
    assert set(stato) >= {"eseguito_at", "rilevazioni", "sensori_saltati", "memoria",
                          "agenti"}
    assert stato["memoria"]["matura"] is False
