"""
snap - Il motore della fase delle porte: due livelli, un processo, nessun tetto per host.

Perche' esiste: una scansione /24 non finiva MAI. Il diario riportava 66 abbandoni
consecutivi sugli stessi 24 indirizzi, con ondate da 257 s che restituivano zero
host. La causa non era un parametro mal tarato ma un'assunzione sbagliata scritta nel
codice: che gli host di un gruppo si scansionino "in parallelo senza costo". Il ritmo
di invio di nmap e' PER PROCESSO, quindi N host costano N volte uno -- e con un tetto
di tempo per host scadono tutti.

Le decisioni e le misure che le giustificano stanno in docs/14_MOTORE_DI_SCANSIONE.md.
Questi controlli fissano le proprieta' strutturali che ne derivano, cosi' che nessuna
di esse possa tornare indietro in silenzio.

remarks: Autore: Daniele Speziale - Data: 2026-09-10
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json

import pytest

from snapprobe.scanner import (
    GRUPPO_HOST,
    PORTE_RICONOSCIMENTO,
    SONDE_AL_SECONDO,
    NetworkScanner,
)


@pytest.fixture()
def scanner(probe_store):
    probe_store.set_json("scan_subnets", [{"cidr": "192.0.2.0/24", "hosts": 254}])
    return NetworkScanner(probe_store, None, "1.0.0")


def _con_porta(store, ip: str, porta: int = 80) -> None:
    """Nodo confermato con una porta aperta nota."""
    store.upsert_local_node(
        ip, state="confirmed", stages_done="ports",
        profile_json=json.dumps({"ip": ip, "ports_index": {
            "tcp/%d" % porta: {"protocol": "tcp", "port": porta, "state": "open"}}}))


# --------------------------------------------------------------------------- #
# Nessun tetto per host: e' la correzione del difetto
# --------------------------------------------------------------------------- #
def test_la_fase_delle_porte_non_passa_un_tetto_per_host(scanner, probe_store):
    """Il tetto per host, in questa struttura, non protegge da nulla e CAUSAVA il
    difetto: gli host di un gruppo si dividono il budget di pacchetti del processo,
    quindi ciascuno viene abbandonato prima di essere esaminato."""
    probe_store.set_setting("scan_host_timeout", "30s")   # scelta dell'operatore
    argomenti = scanner._arguments_for("ports", {"raw_sockets": True},
                                       scanner.effort_profile(),
                                       hosts=["192.0.2.%d" % n for n in range(1, 40)])

    assert "--host-timeout" not in argomenti


def test_il_gruppo_di_host_e_fissato_e_non_lasciato_adattare(scanner):
    """Il gruppo e' il solo parametro di taratura del motore: si dichiara, non si
    lascia scegliere a nmap, perche' ha due effetti opposti (troppo piccolo fa
    richiudere la finestra di congestione, troppo grande accumula sonde in volo che
    il percorso non sostiene)."""
    argomenti = scanner._arguments_for("ports", {"raw_sockets": True},
                                       scanner.effort_profile(),
                                       hosts=["192.0.2.%d" % n for n in range(1, 60)])

    assert argomenti[argomenti.index("--min-hostgroup") + 1] == str(GRUPPO_HOST)
    assert argomenti[argomenti.index("--max-hostgroup") + 1] == str(GRUPPO_HOST)


# --------------------------------------------------------------------------- #
# Due livelli: riconoscimento per tutti, profondita' per chi ha un segnale
# --------------------------------------------------------------------------- #
def test_chi_non_ha_porte_note_riceve_l_elenco_di_riconoscimento(scanner, probe_store):
    """Il costo di una passata e' host x porte. Su una rete reale 142 indirizzi su
    256 non hanno ALCUNA porta aperta fra le prime mille: chiederne mille a tutti
    costa oltre un'ora per non imparare nulla."""
    probe_store.upsert_local_node("192.0.2.10", state="candidate")
    argomenti = scanner._arguments_for("ports", {"raw_sockets": True},
                                       scanner.effort_profile(),
                                       hosts=["192.0.2.10"])

    assert "--top-ports" not in argomenti
    elenco = argomenti[argomenti.index("-p") + 1]
    assert elenco == ",".join(str(p) for p in PORTE_RICONOSCIMENTO)


def test_chi_ha_gia_un_segnale_riceve_la_passata_larga(scanner, probe_store):
    """La profondita' si riserva a chi ha mostrato qualcosa: sono poche decine di
    host invece di 254, quindi il costo torna sostenibile."""
    from snapprobe.scanner import PORTE_PROFONDITA, PORTE_RICONOSCIMENTO

    _con_porta(probe_store, "192.0.2.20")
    argomenti = scanner._arguments_for("ports", {"raw_sockets": True},
                                       scanner.effort_profile(),
                                       hosts=["192.0.2.20"])

    chieste = argomenti[argomenti.index("-p") + 1].split(",")
    assert len(chieste) == len(PORTE_PROFONDITA)
    assert len(chieste) > len(PORTE_RICONOSCIMENTO), (
        "la passata di profondita' deve guardare piu' porte del riconoscimento")


def test_basta_un_host_senza_segnale_per_tornare_al_riconoscimento(scanner, probe_store):
    """Meglio una passata veloce in piu' che una lenta su chi non ha nulla da dire."""
    _con_porta(probe_store, "192.0.2.20")
    probe_store.upsert_local_node("192.0.2.21", state="candidate")
    argomenti = scanner._arguments_for("ports", {"raw_sockets": True},
                                       scanner.effort_profile(),
                                       hosts=["192.0.2.20", "192.0.2.21"])

    assert "--top-ports" not in argomenti


def test_le_porte_di_riconoscimento_dicono_che_cosa_e_un_apparato(scanner):
    """Non sono le piu' comuni per frequenza: sono quelle che identificano un
    apparato. Se qualcuno le riduce a un elenco generico, il controllo lo dichiara."""
    attese = {
        22: "ssh", 80: "http", 443: "https", 445: "condivisione Windows",
        3389: "desktop remoto", 515: "stampa", 631: "stampa IPP", 9100: "jetdirect",
        5060: "telefonia SIP", 1433: "banca dati SQL Server",
        3306: "banca dati MySQL", 5432: "banca dati PostgreSQL", 5900: "VNC",
    }
    mancanti = [nome for porta, nome in attese.items()
                if porta not in PORTE_RICONOSCIMENTO]
    assert not mancanti, "l'elenco non identifica piu': manca %s" % ", ".join(mancanti)


# --------------------------------------------------------------------------- #
# Un solo compito con tutti gli host
# --------------------------------------------------------------------------- #
def test_un_solo_compito_porta_tutti_gli_host_in_attesa(scanner, probe_store):
    """E' il cuore del motore: un processo lavora l'insieme a gruppi, invece di un
    processo per host (202 s CIASCUNO, misurato) o di pochi host per processo con un
    tetto per host (che scadono tutti)."""
    for n in range(1, 40):
        probe_store.upsert_local_node("192.0.2.%d" % n, state="candidate")

    porte = [c for c in scanner.plan_tasks(limit=8) if c["stage"] == "ports"]

    assert len(porte) == 1, "un solo compito per le porte, non uno per host"
    assert len(porte[0]["hosts"]) == 39, "il compito deve portare tutti gli host"


def test_i_bersagli_della_fase_non_vengono_troncati(scanner, probe_store):
    """Tagliare i bersagli qui significherebbe tornare alla struttura che non
    finiva mai."""
    for n in range(1, 60):
        probe_store.upsert_local_node("192.0.2.%d" % n, state="candidate")

    assert len(scanner._targets_for("ports")) == 59


# --------------------------------------------------------------------------- #
# La rete di sicurezza: il tempo del PROCESSO, calcolato sul lavoro
# --------------------------------------------------------------------------- #
def test_il_tempo_del_processo_viene_dalle_sonde_da_inviare(scanner):
    """Sostituisce il tetto per host: sonde (host x porte) diviso il ritmo misurato,
    con margine. E' un conto verificabile e si adatta da se'."""
    profilo = scanner.effort_profile()
    porte = len(PORTE_RICONOSCIMENTO)

    breve = scanner._process_timeout("ports", 16, profilo, porte=porte)
    lungo = scanner._process_timeout("ports", 254, profilo, porte=porte)

    assert lungo > breve
    nudo = 254 * porte / SONDE_AL_SECONDO
    assert lungo > nudo, "il tetto deve stare sopra il lavoro nudo"
    # Su una /24 di riconoscimento il lavoro MISURATO e' 445 s: il tetto deve
    # coprirlo con margine, e restare lontano dal limite assoluto -- un processo
    # appeso non deve occupare un posto del ciclo per mezz'ora.
    from snapprobe.scanner import PROCESS_TIMEOUT_MAX_SECONDS
    assert lungo > 445, "il tetto deve coprire il lavoro misurato"
    assert lungo < PROCESS_TIMEOUT_MAX_SECONDS / 4


def test_il_conteggio_delle_porte_legge_gli_argomenti_veri(scanner):
    """Il tetto si calcola sulle porte che la passata chiede DAVVERO: una di
    riconoscimento e una di profondita' chiedono numeri molto diversi."""
    assert scanner._quante_porte(["-p", "80,443,22"]) == 3
    assert scanner._quante_porte(["-p", "1-100"]) == 100
    assert scanner._quante_porte(["--top-ports", "1000"]) == 1000
    assert scanner._quante_porte(["-sS"]) == len(PORTE_RICONOSCIMENTO)


# --------------------------------------------------------------------------- #
# L'elenco di profondita': scelto per famiglia di apparato, non per frequenza
# --------------------------------------------------------------------------- #
def test_la_profondita_usa_l_elenco_curato_e_non_le_prime_mille(scanner, probe_store):
    """Sostituisce `--top-ports 1000`, e la differenza non e' il numero ma il
    criterio: le prime mille di nmap sono ordinate per frequenza su Internet, dove
    meta' sono servizi che su una rete di uffici non esistono e mancano invece porte
    di gestione che qui contano."""
    from snapprobe.scanner import PORTE_PROFONDITA

    _con_porta(probe_store, "192.0.2.30")
    argomenti = scanner._arguments_for("ports", {"raw_sockets": True},
                                       scanner.effort_profile(),
                                       hosts=["192.0.2.30"])

    assert "--top-ports" not in argomenti
    assert argomenti[argomenti.index("-p") + 1] == ",".join(
        str(p) for p in PORTE_PROFONDITA)


def test_l_elenco_di_profondita_e_qualche_centinaio_non_mille(scanner):
    """Meno porte e piu' pertinenti: il costo di una passata e' host x porte, e
    quattro volte meno porte sono quattro volte meno tempo."""
    from snapprobe.scanner import PORTE_PROFONDITA

    assert 150 <= len(PORTE_PROFONDITA) <= 400, (
        "l'elenco deve restare di qualche centinaio di porte: %d"
        % len(PORTE_PROFONDITA))


def test_le_porte_trovate_su_questa_rete_non_possono_mancare(scanner):
    """Sono l'unico dato empirico che si ha: tutte le porte viste aperte
    sull'installazione reale devono essere nell'elenco."""
    from snapprobe.scanner import PORTE_PROFONDITA, PORTE_PROFONDITA_PER_FAMIGLIA

    osservate = set(PORTE_PROFONDITA_PER_FAMIGLIA["osservate"])
    # Le venti porte trovate aperte sulla rete del committente (lo storico del
    # server, settembre 2026). Le UDP hanno un elenco proprio.
    dal_campo = {22, 53, 80, 111, 135, 139, 443, 445, 1000, 1025, 3389, 5357,
                 6000, 7070, 8080, 8081, 8443}
    assert dal_campo <= osservate, "manca cio' che si e' visto: %s" % sorted(
        dal_campo - osservate)
    assert dal_campo <= set(PORTE_PROFONDITA)


def test_ogni_famiglia_di_apparato_e_rappresentata(scanner):
    """L'elenco si mantiene per famiglia: chi aggiunge un apparato sa dove mettere le
    sue porte, e chi legge sa perche' una porta c'e'. Se una famiglia sparisce, un
    genere di apparato diventa invisibile alla passata di profondita'."""
    from snapprobe.scanner import PORTE_PROFONDITA_PER_FAMIGLIA as FAMIGLIE

    attese = ("osservate", "windows", "linux", "rete", "stampa", "voip",
              "videosorveglianza", "impianti", "archiviazione", "banche_dati",
              "fuori_banda", "desktop_remoto")
    mancanti = [f for f in attese if not FAMIGLIE.get(f)]
    assert not mancanti, "famiglie mancanti o vuote: %s" % ", ".join(mancanti)


def test_la_profondita_comprende_il_riconoscimento(scanner):
    """Chi ha un segnale non deve perdere le porte che gli si guardano sempre:
    diversamente una passata di profondita' potrebbe dichiarare chiusa una porta che
    il riconoscimento aveva trovato aperta."""
    from snapprobe.scanner import PORTE_PROFONDITA, PORTE_RICONOSCIMENTO

    assert set(PORTE_RICONOSCIMENTO) <= set(PORTE_PROFONDITA)


def test_la_gestione_fuori_banda_dei_pc_e_guardata(scanner):
    """Intel AMT su una postazione da ufficio e' un'interfaccia di gestione completa
    e indipendente dal sistema operativo: se e' raggiungibile dalla rete di utenza
    e' un riscontro, e per trovarlo va guardato."""
    from snapprobe.scanner import PORTE_PROFONDITA

    assert 16992 in PORTE_PROFONDITA and 16993 in PORTE_PROFONDITA
    assert 623 in PORTE_PROFONDITA, "IPMI"
