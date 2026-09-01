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
