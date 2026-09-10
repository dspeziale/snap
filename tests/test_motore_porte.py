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
def test_un_candidato_si_profila_con_un_processo_dedicato(scanner, probe_store):
    """LA STRUTTURA DEL MOTORE, dopo tre misure che l'hanno corretta.

    Prima: un processo per host, 202 s ciascuno -- troppo lento.
    Poi: un processo con TUTTI gli host, a gruppi -- veloce ma cieco. Misurato in
    esercizio: 256 host in un processo hanno dato ZERO porte su 256, e oltre 500 il
    processo non finiva entro le due ore del tetto. Il budget di pacchetti di nmap e'
    per PROCESSO, e dividerlo fra molti host stringe la finestra di congestione su
    ognuno: su una rete che filtra, le porte vere passano per filtrate.
    Ora: un processo per host (la RAFFICA), fino a MAX_WORKERS in parallelo. Il
    parallelismo sta nel pool, dove nmap non lo penalizza, e ogni host ha il budget
    tutto per se': 3,3 s per le porte, ~24 s con `-A`.
    """
    for n in range(1, 40):
        probe_store.upsert_local_node("192.0.2.%d" % n, state="candidate")

    compiti = scanner.plan_tasks(limit=8)
    raffiche = [c for c in compiti if c["stage"] == "raffica"]

    assert raffiche, "i candidati si profilano con la raffica"
    for compito in raffiche:
        assert len(compito["hosts"]) == 1, "un host per processo"
    assert len(raffiche) > 1, "e piu' processi insieme: il parallelismo e' nel pool"
    visti = [ip for c in raffiche for ip in c["hosts"]]
    assert len(visti) == len(set(visti)), "nessun host in due compiti dello stesso ciclo"


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


def test_la_fase_porte_non_mette_tutti_gli_host_in_un_processo(probe_store):
    """Il tetto vale anche per la fase porte, che resta per i nodi che la raffica non
    ha ancora preso: 256 host in un processo hanno dato zero porte su 256, oltre 500
    il processo non finisce in due ore."""
    from snapprobe.scanner import MAX_HOST_PER_PROCESSO_PORTE, NetworkScanner

    probe_store.set_json("scan_subnets", [{"cidr": "10.9.0.0/16", "label": "Grande"}])
    for ultimo in range(200):
        probe_store.upsert_local_node("10.9.%d.%d" % (ultimo // 250, ultimo % 250),
                                      state="confirmed", stages_done="raffica",
                                      open_ports=1)
    scanner = NetworkScanner(probe_store, _EsecutoreMuto(), "prova")

    for compito in [c for c in scanner.plan_tasks(limit=32) if c["stage"] == "ports"]:
        assert len(compito["hosts"]) <= MAX_HOST_PER_PROCESSO_PORTE, (
            "un processo con %d host: e' la struttura che non trovava niente"
            % len(compito["hosts"]))


def test_il_tempo_massimo_di_un_processo_porte_resta_nei_minuti(probe_store):
    """Il tetto delle due ore era una rete di sicurezza che veniva RAGGIUNTA: con
    processi piccoli il tempo calcolato torna nell'ordine dei minuti, che e' cio' che
    rende la fase ripetibile."""
    from snapprobe.scanner import (MAX_HOST_PER_PROCESSO_PORTE, NetworkScanner,
                                   PROCESS_TIMEOUT_MAX_SECONDS)

    scanner = NetworkScanner(probe_store, _EsecutoreMuto(), "prova")

    attesa = scanner._process_timeout("ports", MAX_HOST_PER_PROCESSO_PORTE,
                                      scanner.effort_profile(), porte=30)

    assert attesa < PROCESS_TIMEOUT_MAX_SECONDS, "non deve toccare il tetto"
    assert attesa <= 900, "un processo da 64 host sta in un quarto d'ora: %d s" % attesa


class _EsecutoreMuto:
    """Esecutore che non viene invocato: queste prove guardano la PIANIFICAZIONE."""

    def detect_capabilities(self, force: bool = False) -> dict:
        return {"available": True, "executable": "nmap-finto", "nmap_version": "7.95",
                "raw_sockets": True, "os_detection": True, "detail": "prova"}

    def running_count(self) -> int:
        return 0

    def run(self, arguments, targets, timeout=None, label=None) -> str:
        raise AssertionError("la pianificazione non deve eseguire nmap")



# --------------------------------------------------------------------------- #
# La raffica: -A piu' NSE curato, e il confine di sicurezza
# --------------------------------------------------------------------------- #
def test_la_raffica_chiede_tutto_su_un_nodo_solo(scanner, probe_store):
    """`-A` e' versione, sistema operativo, script default e traceroute. Piu' il
    catalogo curato, con le porte di riconoscimento E di profondita': su un host per
    processo il budget di pacchetti e' tutto suo, quindi si chiede tutto subito."""
    from snapprobe.scanner import (ARGOMENTI_SCRIPT_RAFFICA, PORTE_PROFONDITA,
                                   PORTE_RICONOSCIMENTO, SCRIPT_RAFFICA)

    argomenti = scanner._arguments_for("raffica", {"raw_sockets": True},
                                       scanner.effort_profile(), ["10.0.0.1"])

    assert "-A" in argomenti
    assert "-Pn" in argomenti
    assert "-sS" in argomenti
    elenco = argomenti[argomenti.index("-p") + 1]
    porte = {int(p) for p in elenco.split(",")}
    assert porte == set(PORTE_RICONOSCIMENTO) | set(PORTE_PROFONDITA)
    script = argomenti[argomenti.index("--script") + 1]
    # "default" davanti: `--script` da solo SOSTITUIREBBE il set che `-A` porta con se'.
    assert script.startswith("default,"), script
    for nome in SCRIPT_RAFFICA:
        assert nome in script, nome
    assert argomenti[argomenti.index("--script-args") + 1] == ARGOMENTI_SCRIPT_RAFFICA
    assert "--host-timeout" in argomenti, "un apparato lento non deve appendere nmap"


def test_la_raffica_forza_gli_script_sulle_porte_non_standard(scanner):
    """Il prefisso `+` non e' decorativo: questo prodotto trova interfacce web sulla
    7070 e sulla 8443 e agenti su porte spostate. Senza `+`, nmap non esegue lo script
    dove non ha riconosciuto il servizio atteso -- cioe' proprio dove serve."""
    from snapprobe.scanner import SCRIPT_RAFFICA

    forzati = [s for s in SCRIPT_RAFFICA if s.startswith("+")]

    assert len(forzati) >= 20, "il catalogo si regge sul forzare gli script"
    for nome in ("+ssl-cert", "+http-title", "+smb-os-discovery"):
        assert nome in SCRIPT_RAFFICA


def test_nessuno_script_di_categoria_vietata_finisce_negli_argomenti(scanner):
    """IL CONFINE DI SICUREZZA, scritto nel codice e non nelle intenzioni.

    Su una rete di produzione della PA le categorie NSE non sono equivalenti:
    `brute` blocca gli account e riempie i log, `dos` interrompe i servizi,
    `exploit` e `fuzzer` li corrompono. Un incidente causato da uno strumento di
    inventario e' inaccettabile, ed e' anche una violazione dell'autorizzazione con
    cui si scansiona. Questo test vale per TUTTE le fasi, non solo per la raffica.
    """
    from snapprobe.scanner import SCRIPT_NSE_VIETATI, STAGES

    for fase in STAGES:
        try:
            argomenti = scanner._arguments_for(fase, {"raw_sockets": True},
                                               scanner.effort_profile(), ["10.0.0.1"])
        except Exception:
            continue
        testo = " ".join(argomenti)
        for vietato in SCRIPT_NSE_VIETATI:
            assert vietato not in testo, "%s: script vietato %s" % (fase, vietato)
        for categoria in ("brute", "dos", "exploit", "fuzzer", "intrusive"):
            assert "--script %s" % categoria not in testo
            assert ("," + categoria) not in testo.replace("--script-args", "")


def test_il_catalogo_non_contiene_script_vietati():
    """Il catalogo e l'elenco dei vietati non devono contraddirsi: se qualcuno
    aggiunge uno script che e' anche vietato, e' un errore da fermare qui."""
    from snapprobe.scanner import SCRIPT_NSE_VIETATI, SCRIPT_RAFFICA

    nomi = {s.lstrip("+") for s in SCRIPT_RAFFICA}

    assert nomi.isdisjoint(set(SCRIPT_NSE_VIETATI))


def test_gli_script_esterni_sono_vietati():
    """Interrogano servizi fuori dalla rete del cliente: su una rete senza uscita non
    funzionano, e dove funzionassero manderebbero FUORI l'inventario dei servizi.
    E' una fuga di informazioni, non un arricchimento."""
    from snapprobe.scanner import SCRIPT_NSE_VIETATI

    for nome in ("vulners", "whois-ip", "shodan-api", "http-virustotal"):
        assert nome in SCRIPT_NSE_VIETATI


def test_la_raffica_soddisfa_le_fasi_del_profilo(scanner, probe_store):
    """Una raffica riuscita ha chiesto porte, versioni e sistema operativo in un colpo
    solo: dichiarare quelle fasi da fare significherebbe rifarle."""
    from snapprobe.scanner import FASI_COPERTE_DALLA_RAFFICA

    prove = {"ip": "192.0.2.77", "reachable": True, "ttl": 64,
             "ports": [{"protocol": "tcp", "port": 53, "state": "open",
                        "service_name": "domain", "product": "Unbound"}],
             "os": {"name": "Linux 4.X", "family": "Linux", "accuracy": 89},
             "scripts": {}, "hostname": None, "mac": None}
    probe_store.upsert_local_node("192.0.2.77", state="candidate")

    scanner._merge_profile("192.0.2.77", "raffica", prove)

    svolte = set(probe_store.local_node("192.0.2.77")["stages_done"].split(","))
    assert "raffica" in svolte
    for fase in FASI_COPERTE_DALLA_RAFFICA:
        assert fase in svolte, fase
    assert probe_store.local_node("192.0.2.77")["open_ports"] == 1
