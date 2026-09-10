"""
snap probe - Esecuzione di nmap e rilevamento delle capacita' disponibili.

nmap e' un programma esterno: la sonda lo invoca, ne raccoglie l'uscita XML e la
consegna al lettore.

Uso da piu' thread
------------------
Un solo esecutore serve tutti i thread del pool di scansione. Perche' sia sicuro:

  * ogni invocazione scrive su un file temporaneo proprio, quindi non esiste
    stato condiviso fra le esecuzioni;
  * il rilevamento delle capacita' e' protetto da un lock e avviene una sola
    volta, anche se piu' thread lo chiedono insieme;
  * i processi avviati sono registrati in un insieme protetto da lock, cosi'
    `stop_all()` puo' terminarli tutti quando la scansione viene sospesa: senza
    questo, sospendere la scansione lascerebbe correre fino a quattro processi
    nmap fino al loro tempo massimo.

Capacita' rilevate all'avvio
----------------------------
Su Windows la scansione SYN e il rilevamento del sistema operativo richiedono
l'accesso ai socket raw, che Npcap concede in base alla propria installazione
(chiave AdminOnly). Non e' una condizione garantita, e non si puo' dedurre dal
solo fatto di essere amministratori: si accerta eseguendo una scansione SYN
sull'host locale e verificando il tipo di scansione che nmap dichiara nell'XML.
Se l'accesso raw non e' disponibile si ricade sulla scansione per connessione
(-sT), rinunciando al rilevamento del sistema operativo, e lo si dichiara.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
import tempfile
import threading

# Percorsi in cui nmap si trova di solito su Windows, usati se non e' nel PATH.
PERCORSI_NOTI = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
]


# --------------------------------------------------------------------------- #
# Quali script NSE conosce DAVVERO questo nmap
# --------------------------------------------------------------------------- #
# IL GUASTO CHE HA IMPOSTO QUESTO CONTROLLO, misurato in esercizio.
#
# Il catalogo della raffica elencava `ipp-info` e `pgsql-info`. Nessuno dei due
# esiste in nmap 7.99. La conseguenza non e' che quei due script non partono: nmap
# NON PARTE AFFATTO.
#
#   NSE: failed to initialize the script engine:
#   nse_main.lua:829: 'ipp-info' did not match a category, filename, or directory
#   QUITTING!
#
# Il diario della sonda diceva "0 host, 0 record in 3,9 s" per ogni bersaglio: una
# fase che finiva presto e non trovava nulla, per settimane, senza che nulla dicesse
# che il motivo era un nome scritto male in un elenco. E' il difetto peggiore di
# questo prodotto -- non si vede cio' che non c'e'.
#
# Correggere i due nomi non basta: la lezione e' che UN NOME SBAGLIATO NON DEVE
# POTER FERMARE UNA FASE. Le versioni di nmap non hanno tutte gli stessi script (un
# apparato in sede puo' averne una piu' vecchia), quindi il catalogo va confrontato
# con quello che l'nmap installato conosce, non con quello che ci si aspetta.
#
# La fonte e' `script.db`, l'indice che nmap stesso consulta: si legge dal disco,
# senza avviare processi. Sta accanto agli script, nella cartella dati di nmap.
PERCORSI_SCRIPT_DB = (
    "/usr/share/nmap/scripts/script.db",
    "/usr/local/share/nmap/scripts/script.db",
    "/opt/homebrew/share/nmap/scripts/script.db",
    r"C:\Program Files (x86)\Nmap\scripts\script.db",
    r"C:\Program Files\Nmap\scripts\script.db",
)

# Una voce dell'indice: Entry { filename = "http-title.nse", categories = { ... } }
RIGA_SCRIPT_DB = re.compile(r'filename\s*=\s*"(?:scripts/)?([^"]+?)\.nse"')

# Nomi che in `--script` NON sono script ma insiemi: non stanno in script.db e non
# vanno scartati. Le categorie vietate da questo prodotto (brute, dos, exploit,
# fuzzer, intrusive) non compaiono qui per scelta: se una comparisse in un catalogo
# sarebbe un errore da vedere, non da tollerare.
# `malware` c'e' perche' il catalogo della raffica la usa: rileva backdoor note ed e'
# categoria safe. Verificato con `nmap --script-help`: sia "malware" sia "+malware"
# sono accettati. Le categorie VIETATE da questo prodotto (brute, dos, exploit,
# fuzzer, intrusive) e quelle che interrogano servizi esterni (external) non
# compaiono per scelta: se una comparisse in un catalogo, il filtro la scarterebbe --
# ed e' l'esito giusto.
INSIEMI_NON_SCRIPT = frozenset((
    "default", "safe", "discovery", "version", "auth", "vuln", "malware", "all",
))

_script_noti: frozenset[str] | None = None
_serratura_script = threading.Lock()
_percorso_script_db: str | None = None


def _percorsi_script_db() -> list[str]:
    """Dove cercare l'indice, dal piu' attendibile al piu' generico.

    Stessa strada di `mac_costruttori._percorsi_possibili`: si parte dalla cartella
    dell'eseguibile trovato, perche' una sonda puo' avere nmap installato altrove.
    """
    percorsi = []
    dalla_configurazione = os.environ.get("SNAP_PROBE_NMAP_SCRIPT_DB")
    if dalla_configurazione:
        percorsi.append(dalla_configurazione)
    eseguibile = find_nmap()
    if eseguibile:
        cartella = os.path.dirname(os.path.abspath(eseguibile))
        # Installazione monocartella (Windows) e all'uso di Unix (`bin/`+`share/`).
        percorsi.append(os.path.join(cartella, "scripts", "script.db"))
        percorsi.append(os.path.join(os.path.dirname(cartella), "share", "nmap",
                                     "scripts", "script.db"))
    percorsi.extend(PERCORSI_SCRIPT_DB)
    return percorsi


def script_conosciuti() -> frozenset[str]:
    """I nomi degli script che questo nmap conosce. Vuoto = non accertabile.

    Si legge una volta sola. L'insieme VUOTO ha un significato preciso -- "non si
    e' potuto verificare" -- e chi lo usa non deve scartare nulla: vedi
    `filtra_script`.
    """
    global _script_noti, _percorso_script_db
    if _script_noti is not None:
        return _script_noti
    with _serratura_script:
        if _script_noti is not None:  # un altro filo ha finito mentre si attendeva
            return _script_noti
        nomi: set[str] = set()
        for percorso in _percorsi_script_db():
            if not percorso or not os.path.isfile(percorso):
                continue
            try:
                with open(percorso, "r", encoding="utf-8", errors="replace") as f:
                    nomi = set(RIGA_SCRIPT_DB.findall(f.read()))
            except OSError:
                # Un indice illeggibile non e' un motivo per fermare la sonda: si
                # prosegue senza verifica, che e' il comportamento di prima.
                continue
            if nomi:
                _percorso_script_db = percorso
                break
        _script_noti = frozenset(nomi)
        return _script_noti


def percorso_script_db() -> str | None:
    """L'indice effettivamente letto, per poterlo dire nel diario."""
    script_conosciuti()
    return _percorso_script_db


def azzera_script_conosciuti() -> None:
    """Dimentica l'indice letto. Serve ai test, non all'esercizio."""
    global _script_noti, _percorso_script_db
    with _serratura_script:
        _script_noti = None
        _percorso_script_db = None


def filtra_script(voci) -> tuple[list[str], list[str]]:
    """`(tenuti, scartati)`: dell'elenco resta cio' che questo nmap conosce.

    Il prefisso `+` (forza lo script anche dove il servizio non e' riconosciuto) fa
    parte della voce e si conserva; il confronto avviene sul nome nudo.

    Se l'indice non e' accertabile non si scarta NULLA: meglio il comportamento di
    prima -- nmap che protesta -- di una fase silenziosamente svuotata perche' non
    si e' trovato un file.
    """
    voci = [v for v in (str(v or "").strip() for v in voci) if v]
    noti = script_conosciuti()
    if not noti:
        return (voci, [])
    tenuti, scartati = [], []
    for voce in voci:
        nome = voce.lstrip("+")
        (tenuti if nome in noti or nome in INSIEMI_NON_SCRIPT else scartati).append(voce)
    return (tenuti, scartati)


class NmapError(Exception):
    """nmap non e' disponibile oppure ha terminato in modo anomalo."""


class NmapTimeout(NmapError):
    """nmap non ha terminato entro il tempo massimo concesso."""


class NmapAborted(NmapError):
    """Esecuzione interrotta su richiesta (sospensione o arresto della sonda)."""


def find_nmap(explicit: str | None = None) -> str | None:
    """Individua l'eseguibile di nmap: variabile d'ambiente, PATH, percorsi noti."""
    candidati = [explicit, os.environ.get("SNAP_PROBE_NMAP")]
    for candidato in candidati:
        if candidato and os.path.isfile(candidato):
            return candidato
    trovato = shutil.which("nmap")
    if trovato:
        return trovato
    for percorso in PERCORSI_NOTI:
        if os.path.isfile(percorso):
            return percorso
    return None


class NmapRunner:
    """Invocazione di nmap, sicura per l'uso concorrente e interrompibile."""

    def __init__(self, executable: str | None = None, default_timeout: int = 900):
        self.executable = find_nmap(executable)
        self.default_timeout = default_timeout
        self._capabilities = None
        self._capabilities_lock = threading.Lock()
        # Processi in corso, con fase e istante di avvio: un numero immobile non
        # distingue il lavoro in corso da un blocco, un tempo che avanza si'.
        self._processes = {}
        self._processes_lock = threading.Lock()
        self._aborting = False

    # -- esecuzione ----------------------------------------------------------
    def available(self) -> bool:
        return bool(self.executable)

    def running_count(self) -> int:
        with self._processes_lock:
            return len(self._processes)

    def _register(self, processo, label: str = None) -> None:
        with self._processes_lock:
            self._processes[processo] = {"label": label or "scansione",
                                         "started": time.monotonic()}

    def _unregister(self, processo) -> None:
        with self._processes_lock:
            self._processes.pop(processo, None)

    def running_executions(self) -> list:
        """Esecuzioni in corso, con i secondi trascorsi da ciascuna."""
        adesso = time.monotonic()
        with self._processes_lock:
            voci = list(self._processes.values())
        return sorted(({"label": v["label"],
                        "elapsed_seconds": int(adesso - v["started"])} for v in voci),
                      key=lambda v: -v["elapsed_seconds"])

    def stop_all(self) -> int:
        """Termina tutte le esecuzioni in corso. Restituisce quante ne ha fermate.

        Usata alla sospensione della scansione e all'arresto della sonda: un
        processo nmap lasciato correre continuerebbe a interrogare la rete del
        cliente dopo che gli e' stato chiesto di fermarsi.
        """
        self._aborting = True
        with self._processes_lock:
            processi = list(self._processes)
        for processo in processi:
            try:
                processo.terminate()
            except OSError:
                # Il processo e' gia' terminato da se': non e' una condizione
                # di errore, si prosegue con gli altri.
                continue
        return len(processi)

    def resume(self) -> None:
        """Riabilita le esecuzioni dopo uno stop_all()."""
        self._aborting = False

    def run(self, arguments: list, targets: list, timeout: int | None = None,
            label: str = None) -> str:
        """Esegue nmap e restituisce l'XML prodotto.

        L'XML e' scritto su file temporaneo invece di essere letto dallo standard
        output: nmap mescola sullo standard output messaggi di avanzamento che
        renderebbero il documento non conforme. Il file e' proprio di questa
        invocazione, quindi due thread non si sovrascrivono a vicenda.
        """
        if not self.executable:
            raise NmapError("nmap non e' installato o non e' raggiungibile")
        if not targets:
            raise NmapError("nessun bersaglio indicato")
        if self._aborting:
            raise NmapAborted("esecuzione non avviata: scansione sospesa")

        uscita = tempfile.NamedTemporaryFile(suffix=".xml", delete=False, mode="w")
        uscita.close()
        comando = [self.executable] + list(arguments) + ["-oX", uscita.name] + list(targets)
        attesa = timeout or self.default_timeout
        processo = None
        try:
            try:
                processo = subprocess.Popen(
                    comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            except OSError as errore:
                raise NmapError("impossibile eseguire nmap: %s" % errore) from errore

            self._register(processo, label)
            try:
                _, errori = processo.communicate(timeout=attesa)
            except subprocess.TimeoutExpired as errore:
                processo.kill()
                processo.communicate()
                raise NmapTimeout("nmap non ha terminato entro %d secondi" % attesa) from errore
            finally:
                self._unregister(processo)

            if processo.returncode is not None and processo.returncode < 0:
                # Terminato da un segnale: e' l'interruzione richiesta da stop_all().
                raise NmapAborted("esecuzione interrotta durante la scansione")

            try:
                with open(uscita.name, encoding="utf-8", errors="replace") as documento:
                    xml = documento.read()
            except OSError as errore:
                raise NmapError("uscita di nmap non leggibile: %s" % errore) from errore

            if not xml.strip():
                dettaglio = (errori or "").strip()[:300]
                raise NmapError("nmap non ha prodotto uscita XML: %s"
                                % (dettaglio or "nessun dettaglio"))
            return xml
        finally:
            try:
                os.unlink(uscita.name)
            except OSError:
                # Il file temporaneo restera' nella cartella di sistema: non e'
                # una condizione che giustifichi il fallimento della scansione.
                pass

    # -- capacita' -----------------------------------------------------------
    def version(self) -> str | None:
        if not self.executable:
            return None
        try:
            esito = subprocess.run([self.executable, "--version"], capture_output=True,
                                   text=True, timeout=30, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        trovato = re.search(r"Nmap version ([0-9.]+)", esito.stdout or "")
        return trovato.group(1) if trovato else None

    def detect_capabilities(self, force: bool = False) -> dict:
        """Accerta cosa nmap puo' fare davvero in questo ambiente.

        La verifica avviene sull'host locale: e' un bersaglio sempre autorizzato e
        non produce traffico verso la rete del cliente. Il lock garantisce che con
        piu' thread la verifica avvenga una sola volta.
        """
        with self._capabilities_lock:
            if self._capabilities is not None and not force:
                return self._capabilities

            capacita = {
                "available": self.available(),
                "executable": self.executable,
                "nmap_version": None,
                "raw_sockets": False,
                "os_detection": False,
                "detail": "",
            }
            if not capacita["available"]:
                capacita["detail"] = "nmap non installato: nessuna scansione possibile"
                self._capabilities = capacita
                return capacita

            capacita["nmap_version"] = self.version()
            try:
                xml = self.run(["-sS", "-Pn", "--top-ports", "1"], ["127.0.0.1"], timeout=60)
            except NmapError as errore:
                capacita["detail"] = "scansione SYN non disponibile: %s" % errore
                self._capabilities = capacita
                return capacita

            # nmap dichiara nell'XML il tipo di scansione che ha eseguito davvero:
            # se l'accesso raw manca, ricade su 'connect' senza segnalarlo.
            tipo = re.search(r'<scaninfo type="([a-z]+)"', xml)
            capacita["raw_sockets"] = bool(tipo and tipo.group(1) == "syn")
            capacita["os_detection"] = capacita["raw_sockets"]
            capacita["detail"] = (
                "accesso raw disponibile: scansione SYN e rilevamento del sistema operativo"
                if capacita["raw_sockets"] else
                "accesso raw non disponibile: scansione per connessione, nessun rilevamento "
                "del sistema operativo"
            )
            self._capabilities = capacita
            return capacita
