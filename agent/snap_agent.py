#!/usr/bin/env python3
# -----------------------------------------------------------------
# snap_agent.py — agente di macchina: misura, osserva, riferisce alla sonda
# Autore: Daniele Speziale
# Data creazione: 2026-09-13
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap agent - Quello che dalla rete non si puo' vedere.

A CHE COSA SERVE
----------------
Dalla rete una porta 4444 aperta e' una porta aperta. Da dentro la macchina e'
`nc.exe`, avviato dall'utente `mrossi` dieci minuti fa. Questo agente porta dentro il
prodotto la seconda informazione: chi ha provato ad accedere, quale processo tiene
aperta una porta, se il disco sta finendo, se la protezione e' stata fermata, che
software e' installato e da quanto non si aggiorna.

COME PARLA
----------
**Apre lui** verso la sonda, e la sonda non lo chiama mai. E' la stessa regola con cui
la sonda parla al server, un piano piu' sotto: una macchina in una rete di utenza non
deve essere raggiungibile da nessuno, nemmeno dal prodotto che la sorveglia. Un
servizio in ascolto su ogni postazione sarebbe una superficie in piu', identica su
tutte.

Per la stessa ragione **non accetta comandi**: riceve la propria configurazione nella
risposta e la applica al giro dopo. E per la stessa ragione l'interfaccia con cui si
sceglie che cosa inviare e' da CONSOLE (`configura`), non una pagina web: una pagina
web vorrebbe dire una porta in ascolto, cioe' esattamente cio' che non si vuole.

CHE COSA MANDA, E CHI LO DECIDE
-------------------------------
La raccolta e' divisa in GRUPPI dichiarati (vedi `GRUPPI`). Ogni gruppo dice che cosa
manda, ogni quanto, e che privilegi gli servono; chi installa l'agente sceglie quali
accendere con `snap_agent.py configura`. I gruppi spenti si dichiarano alla sonda:
**un gruppo spento non e' un gruppo a zero**, e la console deve poter dire "non
misurato" invece di mostrare una calma che nessuno ha verificato.

Ogni gruppo e' isolato: se uno non si puo' leggere -- permessi, sistema diverso,
strumento assente -- gli altri arrivano lo stesso e quello manca DICHIARANDOSI.

CHE COSA NON RACCOGLIE, PER SCELTA
----------------------------------
Contenuto di file, righe di comando complete, traffico, messaggi, cronologia, corpo
delle attivita' pianificate. Le righe di comando possono contenere una password
passata come argomento: si registra il NOME del processo e il suo utente, non come e'
stato invocato. Le misure raccontano una macchina; il contenuto racconterebbe le
persone che la usano, e non serve a nessuna delle regole.

DENTRO UN CONTAINER
-------------------
Un agente dentro un container misura IL CONTAINER, non la macchina: sarebbe un dato
esatto e inutile. Con `SNAP_AGENT_HOSTFS` (piu' `--pid=host` e i mount di sola
lettura, vedi `docker/`) l'agente guarda il sistema ospite. Cio' che nemmeno cosi' si
riesce a vedere viene DICHIARATO come guasto di gruppo, non taciuto.

INSTALLAZIONE
-------------
    pip install psutil
    python snap_agent.py registra https://sonda:5510 <token>
    python snap_agent.py configura          # che cosa inviare (facoltativo)
    python snap_agent.py servizio

Il token si emette dalla console della sonda (Agenti). Vale un'ora e una volta sola.
Il pacchetto pronto -- con gli installatori per Windows, Linux e Docker -- si scarica
dalla stessa pagina.

remarks: Autore: Daniele Speziale - Data: 2026-09-13
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timezone

VERSIONE = "1.2.2"
PROTOCOLLO = "SNAP-AGENT/1"
UTC_FORMAT = "%Y-%m-%d %H:%M:%S"

# Dove si conserva l'identita'. Accanto all'eseguibile, non in una cartella di
# sistema: l'agente e' un file solo, e si disinstalla cancellandolo con il suo stato.
# Nel container la cartella dell'eseguibile e' dentro l'immagine, che e' effimera: la
# chiave finirebbe persa a ogni ricreazione, e la macchina andrebbe registrata di
# nuovo. La variabile la sposta su un volume (vedi docker/).
CONFIG_PREDEFINITA = os.environ.get("SNAP_AGENT_CONFIG") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "snap-agent.json")

# Quanti invii si conservano quando la sonda non risponde. Millecinquecento a un
# minuto l'uno sono piu' di ventiquattr'ore: la rete che si interrompe la notte non
# deve far perdere gli eventi di sicurezza. Oltre, si scartano i PIU'
# VECCHI -- se si deve perdere qualcosa, meglio il passato remoto.
CODA_MASSIMA = 1500

# Quanto si aspetta la sonda. Dieci secondi: oltre, quella richiesta e' persa comunque
# e continuare ad aspettare significa solo saltare la misura successiva.
ATTESA_SEC = 10

# Ogni quanto si torna a dire una condizione che DURA. Mille volte lo stesso fatto e'
# un fatto che dura, non mille fatti: un disco pieno riferito a ogni invio riempie la
# pagina degli eventi e ci seppellisce dentro quello nuovo. Si dice al cambiamento di
# stato, e poi si riarma dopo sei ore -- perche' un problema che persiste non deve
# nemmeno sparire in silenzio.
RIARMO_SEC = 6 * 3600

# Ogni quanto si raccolgono i gruppi LENTI (inventario del software, utenze, servizi,
# aggiornamenti, postura di sicurezza). Un'ora: sono cose che cambiano quando qualcuno
# le cambia, non da sole, e interrogarle a ogni minuto costerebbe una raffica di
# processi figli su ogni macchina sorvegliata -- per riscrivere lo stesso elenco.
CADENZA_LENTA_SEC = 3600

# Tetto ai comandi di sistema: uno strumento che non torna non deve fermare la misura.
# Gli aggiornamenti di Windows hanno un tetto proprio, piu' alto: l'interrogazione del
# servizio di Windows Update e' lenta per sua natura, non per un guasto.
ATTESA_COMANDO_SEC = 20
ATTESA_COMANDO_LUNGA_SEC = 120

# LA RADICE DELLA MACCHINA OSPITE, quando l'agente gira in un container. Vuota
# significa "sono sulla macchina": e' il caso normale. Vedi `docker/` del pacchetto.
HOSTFS = (os.environ.get("SNAP_AGENT_HOSTFS") or "").rstrip("/")


def adesso_testo() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime(UTC_FORMAT)


def _stampa(messaggio: str) -> None:
    print("[%s] %s" % (adesso_testo(), messaggio), flush=True)


def _ospite(percorso: str) -> str:
    """Il percorso come lo vede l'agente: dentro un container passa da HOSTFS."""
    if not HOSTFS:
        return percorso
    return HOSTFS + percorso if percorso.startswith("/") else percorso


def _nel_container() -> bool:
    """Se l'agente gira dentro un container, e quindi che cosa non puo' vedere."""
    if HOSTFS:
        return True
    if os.path.exists("/.dockerenv"):
        return True
    try:
        with open("/proc/1/cgroup", "r", encoding="utf-8", errors="ignore") as file:
            return any(s in file.read() for s in ("docker", "containerd", "kubepods"))
    except OSError:
        return False


def _comando(argomenti: list, attesa: int = ATTESA_COMANDO_SEC) -> str:
    """Esegue uno strumento di sistema e ne restituisce l'uscita.

    Solleva invece di restituire vuoto: un comando che non c'e' o che non ha i
    permessi deve diventare un GUASTO DICHIARATO del suo gruppo, non un elenco vuoto
    che si legge come "non c'e' niente".
    """
    try:
        esito = subprocess.run(argomenti, capture_output=True, text=True,
                               timeout=attesa, errors="replace")
    except FileNotFoundError as errore:
        raise RuntimeError("strumento assente: %s" % argomenti[0]) from errore
    except subprocess.TimeoutExpired as errore:
        raise RuntimeError("%s non ha risposto entro %d s"
                           % (argomenti[0], attesa)) from errore
    if esito.returncode != 0 and not (esito.stdout or "").strip():
        raise RuntimeError("%s: uscita %d %s" % (argomenti[0], esito.returncode,
                                                 (esito.stderr or "")[:120].strip()))
    return esito.stdout or ""


def _powershell(comando: str, attesa: int = ATTESA_COMANDO_SEC) -> str:
    """PowerShell senza profilo: il profilo dell'utente puo' stampare qualunque cosa
    prima dell'uscita vera, e l'analisi troverebbe testo che non ha chiesto."""
    return _comando(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     comando], attesa)


def _righe(testo: str) -> list:
    return [r.strip() for r in (testo or "").splitlines() if r.strip()]


# --------------------------------------------------------------------------- #
# Il catalogo dei gruppi
# --------------------------------------------------------------------------- #
# Ogni gruppo dichiara: che cosa manda, con quale cadenza, di quali privilegi ha
# bisogno e se riguarda le persone. L'ultimo campo non e' decorativo: e' quello che
# chi installa guarda per decidere, e quello che il titolare del trattamento deve poter
# leggere senza aprire il codice (GDPR art. 5, minimizzazione).
#
# `cadenza`: "veloce" = a ogni invio; "lento" = con l'inventario, una volta ogni
# CADENZA_LENTA_SEC o appena qualcosa cambia.
#
# LA REGOLA E' SEMPLICE: i NUMERI stanno nelle misure, gli ELENCHI nell'inventario. Un
# numero ha senso su un grafico e cambia di continuo; un elenco e' uno stato, e
# rispedirlo identico ogni minuto costa quanto tutto il resto messo insieme.
GRUPPI = {
    "identita": {
        "nome": "Identita' della macchina",
        "cadenza": "lento",
        "descrizione": "Nome, sistema operativo e build, architettura, CPU, memoria"
                       " totale, produttore e modello, numero di serie, BIOS,"
                       " virtualizzazione, interfacce di rete, gateway e DNS.",
        "personali": False,
        "privilegi": "nessuno",
    },
    "carico": {
        "nome": "Carico",
        "cadenza": "veloce",
        "descrizione": "CPU, memoria, swap, carico medio, temperature e batteria.",
        "personali": False,
        "privilegi": "nessuno",
    },
    "dischi": {
        "nome": "Dischi",
        "cadenza": "veloce",
        "descrizione": "Spazio per punto di mount, tipo di filesystem, inode,"
                       " cifratura del volume, lettura/scrittura.",
        "personali": False,
        "privilegi": "nessuno",
    },
    "rete": {
        "nome": "Rete",
        "cadenza": "veloce",
        "descrizione": "Ritmo del traffico in entrata e in uscita.",
        "personali": False,
        "privilegi": "nessuno",
    },
    "connessioni": {
        "nome": "Connessioni",
        "cadenza": "veloce",
        "descrizione": "Quante connessioni per stato e verso quanti indirizzi"
                       " distinti. Conteggi, non l'elenco di chi parla con chi.",
        "personali": False,
        "privilegi": "amministratore per attribuirle ai processi",
    },
    "processi": {
        "nome": "Processi",
        "cadenza": "veloce",
        "descrizione": "Quanti sono e i primi per CPU e memoria: nome e utente,"
                       " mai la riga di comando.",
        "personali": True,
        "privilegi": "amministratore per vedere i processi di altri utenti",
    },
    "in_ascolto": {
        "nome": "Porte in ascolto",
        # Si LEGGE a ogni giro -- serve all'evento, che deve essere immediato -- ma si
        # INVIA con l'inventario: e' un elenco, e un elenco che non cambia non e' una
        # serie storica. Quando cambia, l'inventario parte subito.
        "cadenza": "lento",
        "descrizione": "Porta, processo e utente che la tiene aperta, e se e'"
                       " raggiungibile dalla rete o solo dalla macchina.",
        "personali": True,
        "privilegi": "amministratore",
    },
    "utenti": {
        "nome": "Sessioni aperte",
        "cadenza": "veloce",
        "descrizione": "Chi e' collegato adesso e da dove.",
        "personali": True,
        "privilegi": "nessuno",
    },
    "utenze": {
        "nome": "Utenze locali",
        "cadenza": "lento",
        "descrizione": "Utenze della macchina, chi e' amministratore, utenze attive"
                       " o disattivate, password che non scade.",
        "personali": True,
        "privilegi": "amministratore",
    },
    "sicurezza": {
        "nome": "Postura di sicurezza",
        "cadenza": "lento",
        "descrizione": "Antivirus e firewall, avvio protetto, controllo account,"
                       " SMB 1.0, desktop remoto, cifratura del disco, SELinux/AppArmor,"
                       " accesso SSH.",
        "personali": False,
        "privilegi": "amministratore",
    },
    "aggiornamenti": {
        "nome": "Aggiornamenti",
        "cadenza": "lento",
        "descrizione": "Quanti in attesa e quanti di sicurezza, ultimo installato,"
                       " riavvio in attesa.",
        "personali": False,
        "privilegi": "amministratore",
    },
    "software": {
        "nome": "Software installato",
        "cadenza": "lento",
        "descrizione": "Nome e versione dei programmi installati: e' cio' che permette"
                       " di sapere dove vive una vulnerabilita' senza scansionare.",
        "personali": False,
        "privilegi": "nessuno",
    },
    "servizi": {
        "nome": "Servizi",
        "cadenza": "lento",
        "descrizione": "Servizi e unit in esecuzione, e quali partono da soli.",
        "personali": False,
        "privilegi": "nessuno",
    },
    "pianificate": {
        "nome": "Attivita' pianificate",
        "cadenza": "lento",
        "descrizione": "Nomi e stato delle attivita' pianificate e dei lavori cron."
                       " Solo i nomi: il corpo di un'attivita' e' una riga di comando.",
        "personali": False,
        "privilegi": "amministratore",
    },
    "container": {
        "nome": "Container in esecuzione",
        "cadenza": "lento",
        "descrizione": "Nome e immagine dei container attivi, se la macchina ne"
                       " esegue.",
        "personali": False,
        "privilegi": "appartenenza al gruppo docker",
    },
}

# Gruppi accesi quando nessuno ha scelto. Tutti: l'agente si installa per sapere, e
# un valore predefinito che tace meta' delle cose sarebbe una sorpresa al contrario.
# Chi vuole meno lo dice con `configura`, e la scelta resta scritta.
PRESELEZIONI = {
    "tutti": tuple(GRUPPI),
    # Nulla che riguardi le persone: nessun nome utente, nessuna sessione, nessun
    # processo. Serve dove il trattamento non e' stato concordato con chi lavora
    # su quelle macchine.
    "minimo": ("identita", "carico", "dischi", "rete"),
    # Tutto cio' che non costa un inventario completo a ogni giro lento.
    "consigliato": tuple(g for g in GRUPPI if g not in ("software", "pianificate")),
}
GRUPPI_PREDEFINITI = PRESELEZIONI["tutti"]


# --------------------------------------------------------------------------- #
# La raccolta
# --------------------------------------------------------------------------- #
class Raccolta:
    """Le misure di questa macchina.

    Ogni gruppo e' isolato: se uno non si puo' leggere -- permessi, sistema diverso,
    strumento assente -- gli altri arrivano lo stesso e quello manca DICHIARANDOSI.
    Una misura assente e una misura a zero non sono la stessa cosa, e un agente che le
    confonde fa prendere decisioni sbagliate a chi legge.
    """

    def __init__(self, soglie: dict = None, gruppi=None):
        self.soglie = soglie or {}
        self.gruppi = tuple(gruppi) if gruppi else GRUPPI_PREDEFINITI
        self._rete_precedente = None
        self._ascolto_noto = set()
        self._utenti_noti = set()
        self._utenze_note = set()
        self._prima_volta = True
        # `(genere, soggetto) -> (stato, quando)` per le condizioni che DURANO.
        self._condizioni = {}
        # Quando e' stato composto l'ultimo inventario: governa la sua cadenza.
        self._inventario_at = None
        # Le porte in ascolto lette all'ultimo giro, e l'impronta di quelle gia'
        # consegnate: la differenza fra le due fa partire un inventario fuori cadenza.
        self._ascolto_corrente = None
        self._ascolto_inviato = None
        if HOSTFS:
            self._punta_al_sistema_ospite()

    def _punta_al_sistema_ospite(self) -> None:
        """Dentro un container, psutil deve leggere il /proc DELLA MACCHINA.

        Senza questa riga l'agente misurerebbe il container: un dato esatto e inutile,
        che e' il modo peggiore di sbagliare -- sembra funzionare.
        """
        try:
            import psutil

            psutil.PROCFS_PATH = HOSTFS + "/proc"
        except (ImportError, AttributeError):
            # Su Windows psutil non ha PROCFS_PATH, e un container Windows non vede
            # comunque l'ospite: il gruppo lo dichiarera'.
            pass

    # -- identita' -------------------------------------------------------- #
    def identita(self) -> dict:
        """Chi e' questa macchina. Sempre inviata: e' cio' che lega l'agente al nodo.

        Le parti che richiedono uno strumento di sistema (produttore, seriale,
        virtualizzazione) stanno in `dettaglio` e possono mancare: mancano
        dichiarandosi, come tutto il resto.
        """
        import psutil

        base = {
            "hostname": self._hostname(),
            "fqdn": socket.getfqdn(),
            "sistema": platform.system(),
            "versione_sistema": platform.version(),
            "rilascio": platform.release(),
            "architettura": platform.machine(),
            "python": platform.python_version(),
            "agente": VERSIONE,
            "in_container": _nel_container(),
            "avviata_at": datetime.fromtimestamp(
                psutil.boot_time(), timezone.utc).strftime(UTC_FORMAT),
            "indirizzi": self._indirizzi(),
        }
        return base

    def _hostname(self) -> str:
        """Il nome della MACCHINA, non quello del container.

        Un container prende un nome proprio (l'id breve): registrare la macchina con
        quello significherebbe vederla sparire e riapparire a ogni ricreazione del
        container, con un nodo nuovo ogni volta.
        """
        if HOSTFS:
            try:
                with open(_ospite("/etc/hostname"), "r", encoding="utf-8") as file:
                    nome = file.read().strip()
                if nome:
                    return nome
            except OSError:
                pass
        return socket.gethostname()

    def _indirizzi(self) -> list:
        import psutil

        trovati = []
        for nome, indirizzi in psutil.net_if_addrs().items():
            for voce in indirizzi:
                if voce.family == socket.AF_INET and not voce.address.startswith("127."):
                    trovati.append({"interfaccia": nome, "ip": voce.address})
        return trovati[:16]

    # -- misure ------------------------------------------------------------ #
    # Il registro delle funzioni di raccolta: il nome del gruppo sta in GRUPPI (che
    # e' il catalogo mostrato a chi sceglie), la funzione sta qui. Due elenchi che
    # devono corrispondere, e un test lo verifica.
    def _raccoglitori(self) -> dict:
        return {
            "identita": self._identita_estesa,
            "carico": self._carico,
            "dischi": self._dischi,
            "rete": self._rete,
            "connessioni": self._connessioni,
            "processi": self._processi,
            "in_ascolto": self._in_ascolto,
            "utenti": self._utenti,
            "utenze": self._utenze,
            "sicurezza": self._sicurezza,
            "aggiornamenti": self._aggiornamenti,
            "software": self._software,
            "servizi": self._servizi,
            "pianificate": self._pianificate,
            "container": self._container,
        }

    def misure(self, adesso_mono: float = None) -> dict:
        """La SERIE STORICA: i gruppi veloci, quelli che hanno senso nel tempo.

        Qui sta cio' che cambia da un minuto all'altro e che si guarda su un grafico:
        carico, dischi, ritmo di rete, processi, porte in ascolto, sessioni.
        L'INVENTARIO -- software installato, servizi, utenze, postura -- non sta qui:
        vedi `inventario()` e la ragione per cui sono due cose separate.
        """
        adesso_mono = adesso_mono if adesso_mono is not None else time.monotonic()
        misure = {"rilevato_at": adesso_testo(), "guasti": [],
                  "agente": VERSIONE, "in_container": _nel_container()}

        # I gruppi SPENTI si dichiarano. Senza, la console leggerebbe l'assenza di un
        # dato come un dato a zero -- ed e' la differenza fra "non ha antivirus" e
        # "non gliel'ho chiesto".
        misure["gruppi_attivi"] = list(self.gruppi)
        misure["gruppi_spenti"] = [g for g in GRUPPI if g not in self.gruppi]

        self._raccogli(misure, self._veloci())
        # Le porte in ascolto si leggono SEMPRE, anche se viaggiano con l'inventario:
        # senza, l'evento "processo nuovo in ascolto" arriverebbe con un'ora di
        # ritardo, e un'ora e' il tempo che serve a chi entra per sistemarsi.
        if "in_ascolto" in self.gruppi:
            valore, guasto = self._subito(self._in_ascolto)
            if guasto is not None:
                misure["guasti"].append({"gruppo": "in_ascolto", "motivo": guasto})
            self._ascolto_corrente = valore
        self._sintesi(misure)
        return misure

    def inventario(self, adesso_mono: float = None) -> dict:
        """L'INVENTARIO: i gruppi lenti, e solo quando sono scaduti.

        PERCHE' NON VIAGGIA CON LE MISURE
        Misurato su una macchina vera: l'invio intero pesava 70,7 kB, di cui 59 kB di
        inventario -- software installato, servizi, attivita' pianificate. Ripetuto
        ogni minuto faceva **99 MB al giorno per macchina**, per riscrivere 1.440
        volte lo stesso elenco. Separati, la serie storica costa pochi kB al minuto e
        l'inventario arriva una volta all'ora.

        Non e' solo traffico risparmiato. Un inventario e' uno STATO, non una serie:
        la sonda ne tiene l'ultimo e lo aggiorna quando ne arriva uno nuovo, mentre le
        misure si accumulano e si cancellano per anzianita'. Nella stessa tabella
        avrebbe voluto dire conservare 1.440 copie dello stesso software installato
        per poterne leggere una.

        Restituisce `None` quando non e' ancora scaduto: chi chiama non manda nulla.
        """
        adesso_mono = adesso_mono if adesso_mono is not None else time.monotonic()
        lenti = self._lenti_attivi()
        if not lenti:
            return None
        scaduto = (self._inventario_at is None
                   or (adesso_mono - self._inventario_at) >= CADENZA_LENTA_SEC)
        # Un elenco di porte in ascolto diverso non aspetta l'ora: e' esattamente la
        # cosa per cui si guarda questa pagina.
        cambiato = (self._ascolto_corrente is not None
                    and self._impronta_ascolto(self._ascolto_corrente)
                    != self._ascolto_inviato)
        if not scaduto and not cambiato:
            return None
        documento = {"rilevato_at": adesso_testo(), "guasti": [],
                     "agente": VERSIONE,
                     "gruppi_attivi": list(lenti),
                     "gruppi_spenti": [g for g in GRUPPI
                                       if GRUPPI[g]["cadenza"] == "lento"
                                       and g not in lenti]}
        self._raccogli(documento, [g for g in lenti if g != "in_ascolto"])
        if "in_ascolto" in lenti and self._ascolto_corrente is not None:
            documento["in_ascolto"] = self._ascolto_corrente
            self._ascolto_inviato = self._impronta_ascolto(self._ascolto_corrente)
        documento["motivo"] = "cadenza" if scaduto else "porte in ascolto cambiate"
        self._inventario_at = adesso_mono
        return documento

    @staticmethod
    def _impronta_ascolto(elenco) -> frozenset:
        """Che cosa conta come "cambiato": la porta e chi la tiene aperta.

        Non l'ordine, non il PID -- un servizio riavviato ha un PID nuovo e non e' una
        notizia. Se cambia il processo dietro la stessa porta, invece, lo e'.
        """
        return frozenset((v["porta"], v["processo"], v.get("pubblica"))
                         for v in (elenco or []))

    def _veloci(self) -> tuple:
        return tuple(g for g in self.gruppi
                     if GRUPPI.get(g, {}).get("cadenza") != "lento")

    def _lenti_attivi(self) -> tuple:
        return tuple(g for g in self.gruppi
                     if GRUPPI.get(g, {}).get("cadenza") == "lento")

    def _raccogli(self, dentro: dict, codici) -> None:
        raccoglitori = self._raccoglitori()
        for codice in codici:
            funzione = raccoglitori.get(codice)
            if funzione is None:
                dentro["guasti"].append({"gruppo": codice,
                                         "motivo": "gruppo sconosciuto a questa"
                                                   " versione dell'agente"})
                continue
            valore, guasto = self._subito(funzione)
            if guasto is not None:
                dentro["guasti"].append({"gruppo": codice, "motivo": guasto})
            if valore is not None:
                dentro[codice] = valore

    @staticmethod
    def _subito(funzione):
        try:
            return funzione(), None
        except Exception as errore:  # noqa: BLE001 - un gruppo non ferma gli altri
            return None, str(errore)[:300]

    def _sintesi(self, misure: dict) -> None:
        """Le sintesi che la sonda mette in colonna.

        Si calcolano qui, dove i dati ci sono, invece di ricavarle ogni volta da un
        JSON. Restano `None` se il gruppo che le alimenta e' spento: e' la differenza
        fra "nessun disco pieno" e "i dischi non li guardo".
        """
        carico = misure.get("carico") or {}
        misure["cpu"] = carico.get("cpu")
        misure["memoria"] = carico.get("memoria")
        misure["swap"] = carico.get("swap")
        dischi = misure.get("dischi") or []
        misure["disco_max"] = max((d["percento"] for d in dischi), default=None)
        processi = misure.get("processi") or {}
        misure["processi_totali"] = processi.get("totale")
        # Il CONTEGGIO resta nelle misure anche se l'elenco viaggia con l'inventario:
        # un numero su un grafico e' una serie storica, e costa quattro byte.
        misure["ascolto_totale"] = (len(self._ascolto_corrente)
                                    if self._ascolto_corrente is not None else None)
        misure["ascolto_pubbliche"] = (
            len([v for v in self._ascolto_corrente if v.get("pubblica")])
            if self._ascolto_corrente is not None else None)
        utenti = misure.get("utenti")
        misure["utenti_totali"] = len(utenti) if utenti is not None else None

    # -- gruppi: sistema ---------------------------------------------------- #
    def _identita_estesa(self) -> dict:
        """Quello che serve a riconoscere la macchina e a giudicarne la vetusta'."""
        import psutil

        memoria = psutil.virtual_memory()
        frequenza = None
        try:
            misura = psutil.cpu_freq()
            frequenza = round(misura.max or misura.current or 0) or None
        except (AttributeError, OSError, NotImplementedError):
            frequenza = None  # non tutte le piattaforme la espongono

        dati = {
            "cpu_modello": platform.processor() or None,
            "cpu_fisiche": psutil.cpu_count(logical=False),
            "cpu_logiche": psutil.cpu_count(logical=True),
            "cpu_mhz": frequenza,
            "memoria_totale_gb": round(memoria.total / 1024 ** 3, 1),
            "acceso_da_ore": round((time.time() - psutil.boot_time()) / 3600, 1),
            "fuso": time.tzname[0] if time.tzname else None,
        }
        dati.update(self._ferro())
        dati["interfacce"] = self._interfacce()
        dati["gateway"] = self._gateway()
        dati["dns"] = self._dns()
        return dati

    def _ferro(self) -> dict:
        """Produttore, modello, seriale, BIOS, virtualizzazione.

        Sono i campi con cui si risponde a "quante macchine di quel modello abbiamo" e
        "quali hanno un firmware di otto anni fa": senza, la vetusta' si puo' solo
        dedurre dal sistema operativo.
        """
        sistema = platform.system()
        if sistema == "Linux":
            return self._ferro_linux()
        if sistema == "Windows":
            return self._ferro_windows()
        return {}

    def _ferro_linux(self) -> dict:
        def leggi(nome):
            try:
                with open(_ospite("/sys/class/dmi/id/" + nome), "r",
                          encoding="utf-8", errors="ignore") as file:
                    valore = file.read().strip()
                return valore or None
            except OSError:
                return None

        dati = {
            "produttore": leggi("sys_vendor"),
            "modello": leggi("product_name"),
            "seriale": leggi("product_serial"),
            "bios_versione": leggi("bios_version"),
            "bios_data": leggi("bios_date"),
        }
        try:
            dati["virtualizzazione"] = (_comando(["systemd-detect-virt"]).strip()
                                        or "nessuna")
        except RuntimeError:
            dati["virtualizzazione"] = None  # strumento assente: non si inventa
        return dati

    def _ferro_windows(self) -> dict:
        testo = _powershell(
            "$s=Get-CimInstance Win32_ComputerSystem;"
            "$b=Get-CimInstance Win32_BIOS;"
            "$o=Get-CimInstance Win32_OperatingSystem;"
            "[string]::Join('|', @($s.Manufacturer, $s.Model, $b.SerialNumber,"
            " $b.SMBIOSBIOSVersion, $b.ReleaseDate, $s.Domain, $o.Caption,"
            " $o.BuildNumber))")
        pezzi = (testo.strip().split("|") + [""] * 8)[:8]
        produttore, modello, seriale, bios, data_bios, dominio, edizione, build = pezzi
        virtuale = None
        modello_basso = (modello or "").lower()
        for firma, nome in (("vmware", "VMware"), ("virtualbox", "VirtualBox"),
                            ("virtual machine", "Hyper-V"), ("kvm", "KVM"),
                            ("qemu", "QEMU"), ("xen", "Xen")):
            if firma in modello_basso:
                virtuale = nome
                break
        return {
            "produttore": produttore or None,
            "modello": modello or None,
            "seriale": seriale or None,
            "bios_versione": bios or None,
            "bios_data": (data_bios or "")[:10] or None,
            "dominio": dominio or None,
            "edizione": edizione or None,
            "build": build or None,
            "virtualizzazione": virtuale or "nessuna",
        }

    # -- gruppi: carico ----------------------------------------------------- #
    def _carico(self) -> dict:
        import psutil

        memoria = psutil.virtual_memory()
        swap = psutil.swap_memory()
        dati = {
            "cpu": round(psutil.cpu_percent(interval=1.0), 1),
            "memoria": round(memoria.percent, 1),
            "memoria_usata_gb": round(memoria.used / 1024 ** 3, 1),
            "memoria_libera_gb": round(memoria.available / 1024 ** 3, 1),
            "swap": round(swap.percent, 1),
            "processi_in_coda": None,
        }
        if hasattr(os, "getloadavg"):
            uno, cinque, quindici = os.getloadavg()
            dati["carico"] = {"1m": round(uno, 2), "5m": round(cinque, 2),
                              "15m": round(quindici, 2)}
        else:
            # Windows non ha un carico medio: dichiarato assente, non zero.
            dati["carico"] = None
        dati["temperature"] = self._temperature()
        dati["batteria"] = self._batteria()
        return dati

    def _temperature(self):
        import psutil

        lettura = getattr(psutil, "sensors_temperatures", None)
        if lettura is None:
            return None
        try:
            trovate = lettura()
        except (OSError, NotImplementedError, AttributeError):
            return None
        massime = {}
        for nome, voci in (trovate or {}).items():
            valori = [v.current for v in voci if v.current]
            if valori:
                massime[nome] = round(max(valori), 1)
        return massime or None

    def _batteria(self):
        import psutil

        lettura = getattr(psutil, "sensors_battery", None)
        if lettura is None:
            return None
        try:
            stato = lettura()
        except (OSError, NotImplementedError):
            return None
        if stato is None:
            return None  # macchina senza batteria: assente, non a zero
        return {"percento": round(stato.percent, 1),
                "alimentazione": bool(stato.power_plugged)}

    # -- gruppi: dischi ----------------------------------------------------- #
    def _dischi(self) -> list:
        import psutil

        cifrati = self._volumi_cifrati()
        trovati = []
        for partizione in psutil.disk_partitions(all=False):
            punto = partizione.mountpoint
            try:
                uso = psutil.disk_usage(_ospite(punto) if HOSTFS else punto)
            except (PermissionError, OSError):
                # Un lettore vuoto o un volume non pronto: si salta, non si inventa.
                continue
            voce = {
                "punto": punto,
                "dispositivo": partizione.device,
                "tipo": partizione.fstype,
                "sola_lettura": "ro" in (partizione.opts or "").split(","),
                "totale_gb": round(uso.total / 1024 ** 3, 1),
                "usato_gb": round(uso.used / 1024 ** 3, 1),
                "percento": round(uso.percent, 1),
            }
            if cifrati is not None:
                voce["cifrato"] = punto in cifrati or partizione.device in cifrati
            inode = self._inode(punto)
            if inode is not None:
                voce["inode_percento"] = inode
            trovati.append(voce)
        return trovati

    def _inode(self, punto: str):
        """Su Linux un disco puo' riempirsi di inode restando vuoto di byte.

        E' un guasto che si presenta come "spazio disponibile" e ferma comunque la
        macchina: vale la riga in piu' che costa.
        """
        if not hasattr(os, "statvfs"):
            return None
        try:
            stato = os.statvfs(_ospite(punto) if HOSTFS else punto)
        except OSError:
            return None
        if not stato.f_files:
            return None
        usati = stato.f_files - stato.f_ffree
        return round(100.0 * usati / stato.f_files, 1)

    def _volumi_cifrati(self):
        """I volumi cifrati, o `None` se non si e' potuto sapere.

        `None` e un insieme vuoto dicono due cose diverse: "non l'ho chiesto" e
        "nessuno e' cifrato". La seconda e' un rilievo, la prima no.
        """
        sistema = platform.system()
        try:
            if sistema == "Windows":
                testo = _powershell(
                    "Get-BitLockerVolume | Where-Object"
                    " {$_.ProtectionStatus -eq 'On'} |"
                    " ForEach-Object { $_.MountPoint }")
                return {r.rstrip("\\") + "\\" for r in _righe(testo)}
            if sistema == "Linux":
                testo = _comando(["lsblk", "-rno", "TYPE,MOUNTPOINT"])
                return {r.split(" ", 1)[1].strip()
                        for r in _righe(testo)
                        if r.startswith("crypt ") and len(r.split(" ", 1)) > 1}
        except RuntimeError:
            return None
        return None

    # -- gruppi: rete ------------------------------------------------------- #
    def _rete(self) -> dict:
        import psutil

        contatori = psutil.net_io_counters()
        adesso = {"inviati": contatori.bytes_sent, "ricevuti": contatori.bytes_recv,
                  "quando": time.monotonic()}
        delta = None
        if self._rete_precedente:
            secondi = max(1.0, adesso["quando"] - self._rete_precedente["quando"])
            delta = {
                "inviati_al_sec": int((adesso["inviati"] - self._rete_precedente["inviati"]) / secondi),
                "ricevuti_al_sec": int((adesso["ricevuti"] - self._rete_precedente["ricevuti"]) / secondi),
            }
        self._rete_precedente = adesso
        # Il totale dall'avvio da solo non dice nulla: cio' che conta e' il ritmo, e
        # il ritmo si vede solo fra due misure.
        # Le INTERFACCE non stanno qui ma in `identita`: MAC, velocita' e MTU cambiano
        # quando qualcuno li cambia, non ogni minuto, e rispedirli 1.440 volte al
        # giorno costava 1,9 kB a giro per riscrivere le stesse righe.
        return {"totale_inviati": adesso["inviati"],
                "totale_ricevuti": adesso["ricevuti"], "ritmo": delta}

    def _interfacce(self) -> list:
        import psutil

        stato = psutil.net_if_stats()
        trovate = []
        for nome, indirizzi in psutil.net_if_addrs().items():
            voce = {"nome": nome, "mac": None, "ipv4": [], "ipv6": []}
            for indirizzo in indirizzi:
                if indirizzo.family == socket.AF_INET:
                    voce["ipv4"].append(indirizzo.address)
                elif indirizzo.family == socket.AF_INET6:
                    voce["ipv6"].append(indirizzo.address.split("%")[0])
                elif getattr(indirizzo, "family", None) == getattr(
                        psutil, "AF_LINK", None):
                    voce["mac"] = indirizzo.address
            informazioni = stato.get(nome)
            if informazioni is not None:
                voce.update({"su": bool(informazioni.isup),
                             "velocita_mbps": informazioni.speed or None,
                             "mtu": informazioni.mtu})
            trovate.append(voce)
        return trovate[:32]

    def _gateway(self):
        sistema = platform.system()
        try:
            if sistema == "Linux":
                with open(_ospite("/proc/net/route"), "r", encoding="utf-8") as file:
                    for riga in file.readlines()[1:]:
                        campi = riga.split()
                        if len(campi) > 2 and campi[1] == "00000000":
                            grezzo = campi[2]
                            ottetti = [int(grezzo[i:i + 2], 16)
                                       for i in (6, 4, 2, 0)]
                            return ".".join(str(o) for o in ottetti)
                return None
            if sistema == "Windows":
                testo = _powershell(
                    "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction"
                    " SilentlyContinue | Sort-Object RouteMetric |"
                    " Select-Object -First 1).NextHop")
                return testo.strip() or None
        except (OSError, RuntimeError):
            return None
        return None

    def _dns(self):
        sistema = platform.system()
        try:
            if sistema == "Linux":
                trovati = []
                with open(_ospite("/etc/resolv.conf"), "r", encoding="utf-8") as file:
                    for riga in file:
                        if riga.startswith("nameserver"):
                            pezzi = riga.split()
                            if len(pezzi) > 1:
                                trovati.append(pezzi[1])
                return trovati[:6] or None
            if sistema == "Windows":
                testo = _powershell(
                    "Get-DnsClientServerAddress -AddressFamily IPv4 |"
                    " ForEach-Object { $_.ServerAddresses } | Select-Object -Unique")
                return _righe(testo)[:6] or None
        except (OSError, RuntimeError):
            return None
        return None

    # -- gruppi: connessioni, processi, porte ------------------------------- #
    def _connessioni(self) -> dict:
        """Quante connessioni e verso quanti indirizzi, non chi parla con chi.

        L'elenco completo dei corrispondenti sarebbe un registro di cio' che le
        persone fanno: i conteggi bastano a vedere un'anomalia -- una macchina che
        apre di colpo trecento connessioni uscenti -- senza tenere quel registro.
        """
        import psutil

        try:
            connessioni = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError) as errore:
            raise RuntimeError("servono privilegi per contare le connessioni") from errore
        per_stato, remoti, porte_remote = {}, set(), {}
        for connessione in connessioni:
            per_stato[connessione.status] = per_stato.get(connessione.status, 0) + 1
            if connessione.raddr and connessione.status == psutil.CONN_ESTABLISHED:
                remoti.add(connessione.raddr.ip)
                porta = connessione.raddr.port
                porte_remote[porta] = porte_remote.get(porta, 0) + 1
        prime = sorted(porte_remote.items(), key=lambda v: -v[1])[:8]
        return {"totale": len(connessioni), "per_stato": per_stato,
                "remoti_distinti": len(remoti),
                "porte_remote": [{"porta": p, "quante": q} for p, q in prime]}

    def _processi(self) -> dict:
        import psutil

        elenco = []
        for processo in psutil.process_iter(["pid", "name", "username",
                                             "cpu_percent", "memory_percent",
                                             "create_time"]):
            try:
                info = processo.info
                elenco.append({
                    "pid": info["pid"],
                    # Il NOME, non la riga di comando: la riga puo' contenere una
                    # password passata come argomento (vedi l'intestazione).
                    "nome": (info["name"] or "")[:80],
                    "utente": (info["username"] or "")[:80],
                    "cpu": round(info["cpu_percent"] or 0.0, 1),
                    "memoria": round(info["memory_percent"] or 0.0, 1),
                    "da": datetime.fromtimestamp(
                        info["create_time"] or 0, timezone.utc).strftime(UTC_FORMAT),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        per_cpu = sorted(elenco, key=lambda p: p["cpu"], reverse=True)[:5]
        per_memoria = sorted(elenco, key=lambda p: p["memoria"], reverse=True)[:5]
        return {"totale": len(elenco), "per_cpu": per_cpu, "per_memoria": per_memoria}

    def _in_ascolto(self) -> list:
        import psutil

        trovati = {}
        try:
            connessioni = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError) as errore:
            # Senza privilegi non si vedono i processi altrui: si dichiara con un
            # guasto invece di restituire un elenco parziale che sembrerebbe completo.
            raise RuntimeError(
                "servono privilegi per elencare le porte in ascolto") from errore
        for connessione in connessioni:
            if connessione.status != psutil.CONN_LISTEN or not connessione.laddr:
                continue
            nome, utente = "", ""
            if connessione.pid:
                try:
                    processo = psutil.Process(connessione.pid)
                    nome = (processo.name() or "")[:80]
                    utente = (processo.username() or "")[:80]
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            indirizzo = connessione.laddr.ip
            # SI DEDUPLICA. La stessa porta compare due volte, su 0.0.0.0 e su ::,
            # e su questa macchina erano 68 righe per 34 porte vere. Di un indirizzo
            # di ascolto conta una cosa sola: se e' raggiungibile dalla rete o solo
            # dalla macchina -- e quella e' una bandiera, non una stringa.
            pubblica = not (indirizzo.startswith("127.") or indirizzo in ("::1", ""))
            chiave = (connessione.laddr.port, nome, utente)
            precedente = trovati.get(chiave)
            if precedente is None:
                trovati[chiave] = {
                    "porta": connessione.laddr.port,
                    "processo": nome,
                    "utente": utente,
                    "pubblica": pubblica,
                }
            elif pubblica:
                # Se la stessa porta e' in ascolto sia sul loopback sia sulla rete,
                # quella che conta e' la seconda.
                precedente["pubblica"] = True
        return sorted(trovati.values(), key=lambda v: v["porta"])

    def _utenti(self) -> list:
        import psutil

        return [{"utente": voce.name, "da": voce.host or "locale",
                 "dalle": datetime.fromtimestamp(voce.started, timezone.utc)
                 .strftime(UTC_FORMAT)}
                for voce in psutil.users()]

    def _utenze(self) -> dict:
        """Le utenze della macchina e chi puo' amministrarla.

        Un'utenza nuova fra gli amministratori e' uno dei modi piu' comuni di
        mantenere un accesso: senza questo elenco, l'unico segnale sarebbe un accesso
        riuscito che sembra normale.
        """
        sistema = platform.system()
        if sistema == "Windows":
            testo = _powershell(
                "Get-LocalUser | ForEach-Object { [string]::Join('|', @($_.Name,"
                " $_.Enabled, $_.PasswordNeverExpires, $_.LastLogon)) }")
            utenze = []
            for riga in _righe(testo):
                pezzi = (riga.split("|") + [""] * 4)[:4]
                utenze.append({"utente": pezzi[0],
                               "attiva": pezzi[1].strip().lower() == "true",
                               "password_non_scade": pezzi[2].strip().lower() == "true",
                               "ultimo_accesso": pezzi[3].strip()[:19] or None})
            amministratori = _righe(_powershell(
                "Get-LocalGroupMember -Group (Get-LocalGroup -SID"
                " 'S-1-5-32-544').Name | ForEach-Object { $_.Name }"))
            return {"utenze": utenze[:200], "amministratori": amministratori[:50]}
        if sistema == "Linux":
            utenze = []
            try:
                with open(_ospite("/etc/passwd"), "r", encoding="utf-8",
                          errors="ignore") as file:
                    for riga in file:
                        campi = riga.strip().split(":")
                        if len(campi) < 7:
                            continue
                        utenze.append({"utente": campi[0], "uid": int(campi[2] or 0),
                                       "shell": campi[6],
                                       # Un'utenza di servizio non ha una shell vera:
                                       # distinguere le due cose evita di segnalare
                                       # come "utenza nuova" un pacchetto installato.
                                       "di_servizio": campi[6].endswith(
                                           ("nologin", "false"))})
            except OSError as errore:
                raise RuntimeError("non si legge /etc/passwd: %s" % errore) from errore
            amministratori = []
            try:
                with open(_ospite("/etc/group"), "r", encoding="utf-8",
                          errors="ignore") as file:
                    for riga in file:
                        campi = riga.strip().split(":")
                        if len(campi) >= 4 and campi[0] in ("sudo", "wheel", "admin"):
                            amministratori.extend(
                                [m for m in campi[3].split(",") if m])
            except OSError:
                amministratori = []
            return {"utenze": utenze[:200],
                    "amministratori": sorted(set(amministratori))[:50]}
        raise RuntimeError("sistema non previsto per le utenze: %s" % sistema)

    # -- gruppi: postura di sicurezza --------------------------------------- #
    def _sicurezza(self) -> dict:
        sistema = platform.system()
        if sistema == "Windows":
            return self._sicurezza_windows()
        if sistema == "Linux":
            return self._sicurezza_linux()
        raise RuntimeError("sistema non previsto: %s" % sistema)

    def _sicurezza_windows(self) -> dict:
        # SI CHIEDE AL CENTRO SICUREZZA, non a Defender: su una macchina con un
        # antivirus di terze parti Defender e' spento PER DISEGNO, ed e' il sistema
        # che lo disattiva. Guardare li' produrrebbe un allarme su ogni macchina
        # protetta da qualcun altro.
        dati = {}
        try:
            testo = _powershell(
                "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName"
                " AntiVirusProduct | ForEach-Object { [string]::Join('|',"
                " @($_.displayName, $_.productState)) }")
            prodotti = []
            for riga in _righe(testo):
                nome, _, stato = riga.partition("|")
                try:
                    numero = int(stato or 0)
                except ValueError:
                    numero = 0
                # Il byte centrale di productState dice se la protezione e' attiva:
                # 0x10 acceso. E' documentato male e non cambia da quindici anni.
                prodotti.append({"nome": nome,
                                 "attivo": bool((numero >> 12) & 0x1)})
            dati["antivirus"] = prodotti
        except RuntimeError as errore:
            dati["antivirus"] = None
            dati["antivirus_motivo"] = str(errore)[:200]

        coppie = (
            # Vuoto qui significa "nessun profilo spento", che e' la notizia buona:
            # senza il sentinella la pagina lo mostrava come "non misurato", e una
            # macchina in ordine risultava non verificata.
            ("firewall_profili_spenti",
             "$s=(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq 'False'} |"
             " ForEach-Object { $_.Name }) -join ',';"
             " if ($s) { $s } else { 'nessuno' }"),
            ("smb1",
             "(Get-SmbServerConfiguration -ErrorAction SilentlyContinue)"
             ".EnableSMB1Protocol"),
            ("rdp_attivo",
             "((Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal"
             " Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue)"
             ".fDenyTSConnections -eq 0)"),
            ("rdp_nla",
             "((Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal"
             " Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -ErrorAction"
             " SilentlyContinue).UserAuthentication -eq 1)"),
            ("uac",
             "((Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
             "\\Policies\\System' -Name EnableLUA -ErrorAction SilentlyContinue)"
             ".EnableLUA -eq 1)"),
            # `Confirm-SecureBootUEFI` fallisce per DUE motivi opposti: la macchina
            # non e' UEFI (e allora "non applicabile" e' la risposta giusta), oppure
            # mancano i privilegi (e allora non si sa). Confonderli avrebbe detto
            # "non applicabile" su una macchina UEFI con l'avvio protetto spento.
            ("avvio_protetto",
             "try { Confirm-SecureBootUEFI }"
             " catch [System.PlatformNotSupportedException] { 'non applicabile (BIOS)' }"
             " catch { '' }"),
            ("firme_antivirus_giorni",
             "try { (New-TimeSpan -Start (Get-MpComputerStatus)"
             ".AntivirusSignatureLastUpdated).Days } catch { '' }"),
        )
        for chiave, comando in coppie:
            try:
                dati[chiave] = self._valore(_powershell(comando).strip())
            except RuntimeError as errore:
                dati[chiave] = None
                dati[chiave + "_motivo"] = str(errore)[:120]
        return dati

    def _sicurezza_linux(self) -> dict:
        dati = {}
        # Il firewall: si guarda quale dei tre esiste, invece di darne per scontato
        # uno. Nessuno dei tre attivo non e' la stessa cosa di "non ho guardato".
        firewall = {}
        for nome, argomenti in (("firewalld", ["systemctl", "is-active", "firewalld"]),
                                ("ufw", ["systemctl", "is-active", "ufw"]),
                                ("nftables", ["systemctl", "is-active", "nftables"])):
            try:
                firewall[nome] = _comando(argomenti).strip()
            except RuntimeError:
                firewall[nome] = None
        dati["firewall"] = firewall

        try:
            dati["selinux"] = _comando(["getenforce"]).strip()
        except RuntimeError:
            dati["selinux"] = None
        try:
            dati["apparmor"] = "attivo" if "Y" in _comando(
                ["cat", _ospite("/sys/module/apparmor/parameters/enabled")]) else "spento"
        except RuntimeError:
            dati["apparmor"] = None

        # SSH: due impostazioni che decidono quanto e' facile entrare da fuori.
        ssh = {}
        try:
            with open(_ospite("/etc/ssh/sshd_config"), "r", encoding="utf-8",
                      errors="ignore") as file:
                testo = file.read()
            for chiave, predefinito in (("PermitRootLogin", "prohibit-password"),
                                        ("PasswordAuthentication", "yes")):
                trovato = re.search(r"^\s*%s\s+(\S+)" % chiave, testo,
                                    re.M | re.I)
                ssh[chiave] = trovato.group(1) if trovato else predefinito + " (predefinito)"
        except OSError:
            ssh = None
        dati["ssh"] = ssh
        return dati

    # -- gruppi: aggiornamenti, software, servizi --------------------------- #
    def _aggiornamenti(self) -> dict:
        sistema = platform.system()
        if sistema == "Windows":
            return self._aggiornamenti_windows()
        if sistema == "Linux":
            return self._aggiornamenti_linux()
        raise RuntimeError("sistema non previsto: %s" % sistema)

    def _aggiornamenti_windows(self) -> dict:
        # L'interrogazione del servizio di Windows Update e' LENTA per sua natura --
        # contatta il server -- e per questo ha un tetto piu' alto degli altri
        # comandi. Gira una volta all'ora, non a ogni misura.
        testo = _powershell(
            "$s=New-Object -ComObject Microsoft.Update.Session;"
            "$r=$s.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0');"
            "$t=$r.Updates.Count;"
            "$c=($r.Updates | Where-Object { $_.MsrcSeverity -ne $null }).Count;"
            "$u=(Get-CimInstance Win32_QuickFixEngineering | Sort-Object"
            " InstalledOn -Descending | Select-Object -First 1).InstalledOn;"
            "[string]::Join('|', @($t, $c, $u))", ATTESA_COMANDO_LUNGA_SEC)
        pezzi = (testo.strip().split("|") + [""] * 3)[:3]
        riavvio = _powershell(
            "Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
            "Component Based Servicing\\RebootPending'").strip().lower() == "true"
        return {"in_attesa": self._valore(pezzi[0]),
                "di_sicurezza": self._valore(pezzi[1]),
                "ultimo_installato": pezzi[2][:10] or None,
                "riavvio_in_attesa": riavvio}

    def _aggiornamenti_linux(self) -> dict:
        # NON SI PUO' CHIEDERE DA DENTRO UN CONTAINER. `apt-get -s dist-upgrade`
        # risponderebbe per l'immagine, non per la macchina: servono le liste dei
        # pacchetti, la configurazione e le chiavi della macchina, e puntarci
        # `--admindir` non basta. Si dichiara, invece di rispondere "nessun
        # aggiornamento in attesa" -- che sarebbe falso e rassicurante.
        if HOSTFS:
            raise RuntimeError(
                "in container: gli aggiornamenti li conosce il gestore di pacchetti"
                " della macchina, che qui non c'e'. Per questo dato serve"
                " l'installazione nativa (installa.sh)")
        dati = {"riavvio_in_attesa": os.path.exists(_ospite("/var/run/reboot-required"))}
        try:
            testo = _comando(["apt-get", "-s", "-o", "Debug::NoLocking=1",
                              "dist-upgrade"], ATTESA_COMANDO_LUNGA_SEC)
            righe = [r for r in _righe(testo) if r.startswith("Inst ")]
            dati["in_attesa"] = len(righe)
            dati["di_sicurezza"] = len([r for r in righe if "security" in r.lower()])
            return dati
        except RuntimeError:
            pass
        try:
            testo = _comando(["dnf", "-q", "check-update"], ATTESA_COMANDO_LUNGA_SEC)
            righe = [r for r in _righe(testo) if not r.startswith(("Last", "Obsolet"))]
            dati["in_attesa"] = len(righe)
            dati["di_sicurezza"] = None  # dnf non lo dice senza un plugin
            return dati
        except RuntimeError as errore:
            raise RuntimeError(
                "nessun gestore di pacchetti riconosciuto (apt, dnf): %s"
                % errore) from errore

    def _software(self) -> list:
        """L'inventario del software installato.

        E' il gruppo che paga di piu': sapere che su quaranta macchine c'e' una
        versione vulnerabile di un programma NON richiede di scansionarle una per una,
        e non richiede che quel programma esponga una porta. Nome e versione, niente
        altro.
        """
        sistema = platform.system()
        if sistema == "Windows":
            testo = _powershell(
                "$p='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
                "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\"
                "Uninstall\\*';"
                "Get-ItemProperty $p -ErrorAction SilentlyContinue |"
                " Where-Object { $_.DisplayName } |"
                " ForEach-Object { [string]::Join('|', @($_.DisplayName,"
                " $_.DisplayVersion, $_.Publisher)) }", ATTESA_COMANDO_LUNGA_SEC)
            programmi = []
            for riga in _righe(testo):
                pezzi = (riga.split("|") + [""] * 3)[:3]
                programmi.append({"nome": pezzi[0][:120],
                                  "versione": pezzi[1][:40] or None,
                                  "produttore": pezzi[2][:80] or None})
            return sorted(programmi, key=lambda v: v["nome"].lower())[:600]
        if sistema == "Linux":
            # DENTRO UN CONTAINER SI PUNTA ALL'ARCHIVIO DELLA MACCHINA. Senza
            # `--admindir`, `dpkg-query` elenca i pacchetti dell'IMMAGINE: la prima
            # prova di questo container ha restituito gli 87 pacchetti di
            # `python:3.13-slim` come se fossero il software della macchina.
            dpkg = ["dpkg-query", "-W", "-f=${Package}\\t${Version}\\n"]
            rpm = ["rpm", "-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\n"]
            if HOSTFS:
                archivio_dpkg = _ospite("/var/lib/dpkg")
                archivio_rpm = _ospite("/var/lib/rpm")
                if os.path.isdir(archivio_dpkg):
                    dpkg.insert(1, "--admindir=" + archivio_dpkg)
                elif os.path.isdir(archivio_rpm):
                    rpm.insert(1, "--dbpath=" + archivio_rpm)
                else:
                    raise RuntimeError(
                        "in container: l'archivio dei pacchetti della macchina non e'"
                        " montato (serve la radice in sola lettura, vedi docker/)")
            for argomenti, separatore in ((dpkg, "\t"), (rpm, "\t")):
                try:
                    testo = _comando(argomenti, ATTESA_COMANDO_LUNGA_SEC)
                except RuntimeError:
                    continue
                pacchetti = []
                for riga in _righe(testo):
                    nome, _, versione = riga.partition(separatore)
                    pacchetti.append({"nome": nome[:120],
                                      "versione": versione.strip()[:40] or None})
                return sorted(pacchetti, key=lambda v: v["nome"].lower())[:600]
            raise RuntimeError("nessun gestore di pacchetti riconosciuto (dpkg, rpm)")
        raise RuntimeError("sistema non previsto: %s" % sistema)

    def _servizi(self) -> dict:
        sistema = platform.system()
        if sistema == "Windows":
            testo = _powershell(
                "Get-Service | ForEach-Object { [string]::Join('|', @($_.Name,"
                " $_.Status, $_.StartType)) }", ATTESA_COMANDO_LUNGA_SEC)
            servizi = []
            for riga in _righe(testo):
                pezzi = (riga.split("|") + [""] * 3)[:3]
                servizi.append({"nome": pezzi[0][:80], "stato": pezzi[1],
                                "avvio": pezzi[2]})
            in_esecuzione = [s for s in servizi if s["stato"].lower() == "running"]
            return {"totale": len(servizi), "in_esecuzione": len(in_esecuzione),
                    "automatici_fermi": [s["nome"] for s in servizi
                                         if s["avvio"].lower() == "automatic"
                                         and s["stato"].lower() != "running"][:40],
                    "voci": sorted(in_esecuzione, key=lambda s: s["nome"])[:300]}
        if sistema == "Linux":
            testo = _comando(["systemctl", "list-units", "--type=service",
                              "--state=running", "--no-legend", "--no-pager",
                              "--plain"], ATTESA_COMANDO_LUNGA_SEC)
            nomi = [r.split()[0] for r in _righe(testo) if r.split()]
            falliti = []
            try:
                testo_falliti = _comando(["systemctl", "list-units", "--state=failed",
                                          "--no-legend", "--no-pager", "--plain"])
                falliti = [r.split()[0] for r in _righe(testo_falliti) if r.split()]
            except RuntimeError:
                falliti = []
            return {"totale": len(nomi), "in_esecuzione": len(nomi),
                    "falliti": falliti[:40],
                    "voci": [{"nome": n, "stato": "running"} for n in nomi[:300]]}
        raise RuntimeError("sistema non previsto: %s" % sistema)

    def _pianificate(self) -> dict:
        """Le attivita' pianificate: NOMI e stato, mai il corpo.

        Il corpo di un'attivita' pianificata e' una riga di comando, e vale la stessa
        regola dei processi: puo' contenere una password. Il nome basta a notare
        un'attivita' che non c'era.
        """
        sistema = platform.system()
        if sistema == "Windows":
            testo = _powershell(
                "Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } |"
                " ForEach-Object { [string]::Join('|', @($_.TaskPath + $_.TaskName,"
                " $_.State)) }", ATTESA_COMANDO_LUNGA_SEC)
            voci = []
            for riga in _righe(testo):
                nome, _, stato = riga.partition("|")
                voci.append({"nome": nome[:160], "stato": stato})
            return {"totale": len(voci), "voci": voci[:300]}
        if sistema == "Linux":
            voci = []
            for cartella in ("/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                             "/etc/cron.weekly", "/etc/cron.monthly"):
                percorso = _ospite(cartella)
                try:
                    for nome in sorted(os.listdir(percorso)):
                        voci.append({"nome": "%s/%s" % (cartella, nome),
                                     "stato": "presente"})
                except OSError:
                    continue
            timer_letti = True
            try:
                testo = _comando(["systemctl", "list-timers", "--no-legend",
                                  "--no-pager", "--plain", "--all"])
                for riga in _righe(testo):
                    campi = riga.split()
                    if campi:
                        voci.append({"nome": campi[-2] if len(campi) > 1 else campi[0],
                                     "stato": "timer"})
            except RuntimeError:
                # I timer di systemd si chiedono a systemd, che in un container non
                # c'e'. L'elenco resta quello di cron e va detto che e' PARZIALE: un
                # elenco incompleto presentato come completo e' peggio di nessun
                # elenco.
                timer_letti = False
            return {"totale": len(voci), "voci": voci[:300],
                    "completo": timer_letti,
                    "manca": None if timer_letti else "i timer di systemd"}
        raise RuntimeError("sistema non previsto: %s" % sistema)

    def _container(self) -> dict:
        """I container in esecuzione sulla macchina, se ne esegue.

        Un container e' un sistema operativo in piu' da aggiornare, e non compare
        nell'inventario del software della macchina che lo ospita: senza questo
        gruppo resterebbe invisibile.
        """
        for strumento in ("docker", "podman"):
            try:
                testo = _comando([strumento, "ps", "--format",
                                  "{{.Names}}|{{.Image}}|{{.Status}}"])
            except RuntimeError:
                continue
            voci = []
            for riga in _righe(testo):
                pezzi = (riga.split("|") + [""] * 3)[:3]
                voci.append({"nome": pezzi[0][:80], "immagine": pezzi[1][:120],
                             "stato": pezzi[2][:60]})
            return {"strumento": strumento, "totale": len(voci), "voci": voci[:100]}
        raise RuntimeError("nessun motore di container raggiungibile (docker, podman)")

    @staticmethod
    def _valore(testo: str):
        """Il valore di PowerShell come tipo Python, o `None` se non si sa.

        Una stringa vuota non e' `False`: e' "non risponde", e va distinta.
        """
        pulito = (testo or "").strip()
        if not pulito:
            return None
        basso = pulito.lower()
        if basso in ("true", "false"):
            return basso == "true"
        try:
            return int(pulito)
        except ValueError:
            return pulito[:200]

    # -- eventi di sicurezza ----------------------------------------------- #
    def eventi(self, misure: dict, inventario: dict = None) -> list:
        """I fatti che le regole dell'IDS sanno leggere.

        Si producono confrontando questa misura con la precedente: un processo che si
        mette in ascolto adesso, un'utenza che prima non c'era. Al PRIMO giro non si
        emette nulla -- tutto sarebbe "nuovo", e un agente appena installato
        riempirebbe la pagina di allarmi che non sono allarmi.
        """
        eventi = []
        corrente = self._ascolto_corrente or []
        ascolto = {(v["porta"], v["processo"]) for v in corrente}
        utenti = {v["utente"] for v in (misure.get("utenti") or [])}

        if not self._prima_volta:
            for porta, processo in sorted(ascolto - self._ascolto_noto):
                eventi.append({
                    "genere": "ascolto_nuovo",
                    "gravita": "alta",
                    "soggetto": "porta-%s" % porta,
                    "messaggio": "processo %s in ascolto sulla porta %s"
                                 % (processo or "sconosciuto", porta),
                    "dati": {"porta": porta, "processo": processo,
                             "utente": next((v["utente"] for v in corrente
                                             if v["porta"] == porta), "")},
                    "avvenuto_at": adesso_testo(),
                })
            for utente in sorted(utenti - self._utenti_noti):
                eventi.append({
                    "genere": "sessione_nuova",
                    "gravita": "info",
                    "soggetto": utente,
                    "messaggio": "sessione aperta da %s" % utente,
                    "dati": {"utente": utente},
                    "avvenuto_at": adesso_testo(),
                })
            # Le utenze stanno nell'inventario, che arriva una volta all'ora: senza
            # inventario in questo giro non si conclude niente, invece di concludere
            # che non ci sono utenze.
            if inventario:
                eventi.extend(self._utenze_nuove(inventario))

        self._ascolto_noto = ascolto
        self._utenti_noti = utenti

        eventi.extend(self._soglie(misure))
        eventi.extend(self._accessi_falliti())
        # Anche una protezione ferma e' una condizione che dura: si dice quando lo
        # stato cambia, e si riarma. Lo stato e' il messaggio stesso -- "nessun
        # antivirus attivo fra i 2 registrati" cambia se cambia il numero.
        eventi.extend(evento for evento in self._protezione()
                      if self._da_dire(evento, evento["messaggio"]))
        self._prima_volta = False
        return eventi

    def _utenze_nuove(self, inventario: dict) -> list:
        """Un'utenza comparsa, e soprattutto un amministratore nuovo.

        Non si confronta l'elenco intero: si confronta l'insieme dei nomi. Un'utenza
        rinominata conta come una nuova, ed e' giusto -- va guardata comunque.
        """
        utenze = (inventario.get("utenze") or {})
        nomi = {u["utente"] for u in (utenze.get("utenze") or [])}
        amministratori = set(utenze.get("amministratori") or [])
        if not nomi:
            return []  # gruppo spento o non leggibile: non si conclude niente
        eventi = []
        if self._utenze_note:
            for nuova in sorted(nomi - self._utenze_note):
                amministratore = any(nuova in a for a in amministratori)
                eventi.append({
                    "genere": "utente_nuovo",
                    "gravita": "critica" if amministratore else "alta",
                    "soggetto": nuova,
                    "messaggio": "utenza nuova sulla macchina: %s%s"
                                 % (nuova, " (amministratore)" if amministratore else ""),
                    "dati": {"utente": nuova, "amministratore": amministratore},
                    "avvenuto_at": adesso_testo(),
                })
        self._utenze_note = nomi
        return eventi

    def _da_dire(self, evento: dict, stato: str) -> bool:
        """Vale la pena dirlo adesso?

        Un evento di STATO (il disco pieno, la protezione ferma) descrive una
        condizione, non un accadimento: ripeterlo a ogni invio significa scrivere
        cento righe identiche in un'ora e rendere illeggibile la pagina dove si
        dovrebbe notare quella nuova. Si dice quando lo stato CAMBIA, e si torna a
        dirlo dopo `RIARMO_SEC` -- perche' una condizione che dura per giorni non
        deve nemmeno sparire dalla vista.

        `stato` non e' il valore esatto ma la sua FASCIA: un disco che passa dal 97,8%
        al 97,9% non e' una notizia, uno che passa dal 92% al 97% lo e'.
        """
        chiave = (evento["genere"], evento.get("soggetto") or "")
        precedente = self._condizioni.get(chiave)
        adesso = time.time()
        if precedente is not None:
            stato_prima, quando = precedente
            if stato_prima == stato and (adesso - quando) < RIARMO_SEC:
                return False
        self._condizioni[chiave] = (stato, adesso)
        return True

    def _soglie(self, misure: dict) -> list:
        eventi = []
        limite_disco = float(self.soglie.get("disco_percento") or 90)
        for disco in (misure.get("dischi") or []):
            if disco["percento"] < limite_disco:
                # Tornato sotto soglia: si dimentica, cosi' se risale lo si ridice
                # subito invece di aspettare il riarmo.
                self._condizioni.pop(("disco_pieno", disco["punto"]), None)
                continue
            evento = {
                "genere": "disco_pieno",
                "gravita": "alta" if disco["percento"] >= 95 else "media",
                "soggetto": disco["punto"],
                "messaggio": "spazio quasi esaurito su %s: %s%% di %s GB"
                             % (disco["punto"], disco["percento"],
                                disco["totale_gb"]),
                "dati": disco,
                "avvenuto_at": adesso_testo(),
            }
            # La fascia di cinque punti: fra il 97,8% e il 97,9% non e' successo nulla.
            if self._da_dire(evento, "%d" % (int(disco["percento"]) // 5 * 5)):
                eventi.append(evento)
        return eventi

    def _accessi_falliti(self) -> list:
        """Tentativi di accesso falliti nell'ultima ora.

        Si legge dal registro del sistema, che e' l'unico posto dove esistono. Se lo
        strumento non c'e' o non si ha il permesso, non si emette nulla: un conteggio
        a zero perche' non si e' potuto guardare direbbe "nessun attacco".
        """
        sistema = platform.system()
        try:
            if sistema == "Linux":
                uscita = subprocess.run(
                    ["journalctl", "-q", "--since", "1 hour ago", "--no-pager",
                     "_SYSTEMD_UNIT=sshd.service"],
                    capture_output=True, text=True, timeout=20)
                righe = [r for r in uscita.stdout.splitlines()
                         if "Failed password" in r or "authentication failure" in r]
            elif sistema == "Windows":
                uscita = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;"
                     "StartTime=(Get-Date).AddHours(-1)} -ErrorAction SilentlyContinue"
                     " | Measure-Object).Count"],
                    capture_output=True, text=True, timeout=30)
                quanti = int((uscita.stdout or "0").strip() or 0)
                righe = ["accesso fallito"] * quanti
            else:
                return []
        except (OSError, subprocess.SubprocessError, ValueError):
            return []

        soglia = int(self.soglie.get("accessi_falliti") or 5)
        if len(righe) < soglia:
            return []
        evento = {
            "genere": "accessi_falliti",
            "gravita": "alta",
            "soggetto": "accessi",
            "messaggio": "%d accessi falliti nell'ultima ora" % len(righe),
            "dati": {"quanti": len(righe), "soglia": soglia,
                     "esempio": (righe[0] or "")[:200]},
            "avvenuto_at": adesso_testo(),
        }
        # Il conteggio scorre sull'ultima ora e cambia a ogni invio: si guarda la
        # DECINA, altrimenti "17 accessi falliti" e "18 accessi falliti" sarebbero
        # due notizie diverse a un minuto di distanza.
        if not self._da_dire(evento, "%d" % (len(righe) // 10)):
            return []
        return [evento]

    def _protezione(self) -> list:
        """Antivirus e firewall: fermi non ci vanno da soli."""
        sistema = platform.system()
        try:
            if sistema == "Windows":
                # SI CHIEDE AL CENTRO SICUREZZA, non a Defender.
                #
                # `Get-MpComputerStatus` parla del solo Defender, e su una macchina con
                # un antivirus di terze parti Defender e' spento PER DISEGNO: e' il
                # sistema che lo disattiva quando un altro prodotto prende il posto.
                # Guardare li' avrebbe prodotto un allarme critico su ogni macchina
                # protetta da qualcun altro -- e un allarme che si ripete su tutto il
                # parco e' un allarme che si impara a ignorare, che e' il modo in cui
                # un prodotto smette di servire senza che nessuno lo spenga.
                eventi = []
                uscita = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "$a=@(Get-CimInstance -Namespace root/SecurityCenter2"
                     " -ClassName AntiVirusProduct);"
                     "$attivi=@($a | Where-Object { ($_.productState -band 0x1000)"
                     " -ne 0 });"
                     "$f=(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq"
                     " 'False'} | ForEach-Object { $_.Name }) -join ',';"
                     "[string]::Join('|', @($a.Count, $attivi.Count,"
                     " ($a.displayName -join ','), $f))"],
                    capture_output=True, text=True, timeout=30)
                pezzi = (uscita.stdout or "").strip().split("|")
                if len(pezzi) < 4:
                    return []
                registrati, attivi, _nomi, profili = pezzi[0], pezzi[1], pezzi[2], pezzi[3]
                try:
                    quanti_attivi = int(attivi or 0)
                    quanti_registrati = int(registrati or 0)
                except ValueError:
                    return []
                if quanti_registrati and not quanti_attivi:
                    eventi.append({
                        "genere": "sicurezza_ferma", "gravita": "critica",
                        "soggetto": "antivirus",
                        "messaggio": "nessun antivirus attivo fra i %d registrati"
                                     % quanti_registrati,
                        "dati": {"registrati": quanti_registrati, "attivi": 0},
                        "avvenuto_at": adesso_testo()})
                if profili.strip():
                    eventi.append({
                        "genere": "sicurezza_ferma", "gravita": "critica",
                        "soggetto": "firewall",
                        "messaggio": "firewall disattivato sui profili: %s" % profili.strip(),
                        "dati": {"profili": profili.strip()},
                        "avvenuto_at": adesso_testo()})
                return eventi
            if sistema == "Linux":
                uscita = subprocess.run(["systemctl", "is-active", "firewalld"],
                                        capture_output=True, text=True, timeout=15)
                if (uscita.stdout or "").strip() == "inactive":
                    return [{
                        "genere": "sicurezza_ferma", "gravita": "critica",
                        "soggetto": "firewall",
                        "messaggio": "firewalld risulta fermo",
                        "dati": {"componente": "firewalld"},
                        "avvenuto_at": adesso_testo()}]
        except (OSError, subprocess.SubprocessError):
            return []
        return []


# --------------------------------------------------------------------------- #
# Il canale verso la sonda
# --------------------------------------------------------------------------- #
class Canale:
    """Parla con la sonda. Firma ogni invio e non si fida della risposta."""

    def __init__(self, base: str, agent_uid: str = "", chiave: str = "",
                 verifica_tls: bool = True):
        self.base = base.rstrip("/")
        self.agent_uid = agent_uid
        self.chiave = chiave
        self.verifica_tls = verifica_tls

    def _contesto(self):
        if self.verifica_tls:
            return None
        # La sonda ha spesso un certificato proprio, non firmato da un'autorita'
        # pubblica: chi installa lo dichiara con un interruttore esplicito, invece di
        # trovarsi la verifica disattivata senza saperlo.
        contesto = ssl.create_default_context()
        contesto.check_hostname = False
        contesto.verify_mode = ssl.CERT_NONE
        return contesto

    def _apri(self, percorso: str, corpo: bytes, intestazioni: dict):
        richiesta = urllib.request.Request(
            self.base + percorso, data=corpo, method="POST",
            headers={"Content-Type": "application/json",
                     "User-Agent": "snap-agent/%s" % VERSIONE, **intestazioni})
        with urllib.request.urlopen(richiesta, timeout=ATTESA_SEC,
                                    context=self._contesto()) as risposta:
            return json.loads(risposta.read().decode("utf-8") or "{}")

    def registra(self, token: str, identita: dict) -> dict:
        corpo = json.dumps({
            "token": token,
            "hostname": identita["hostname"],
            "sistema": "%s %s" % (identita["sistema"], identita["rilascio"]),
            "versione": VERSIONE,
        }, separators=(",", ":")).encode("utf-8")
        return self._apri("/api/agent/enroll", corpo, {})

    def _firma(self, marca: str, nonce: str, corpo: bytes) -> str:
        messaggio = b"|".join([PROTOCOLLO.encode("ascii"),
                               self.agent_uid.encode("utf-8"),
                               marca.encode("ascii"), nonce.encode("ascii"), corpo])
        return hmac.new(self.chiave.encode("utf-8"), messaggio,
                        hashlib.sha256).hexdigest()

    def invia(self, misure: dict, eventi: list, identita: dict,
              inventario: dict = None) -> dict:
        """Un invio. L'inventario viaggia solo quando c'e': vedi `Raccolta.inventario`."""
        marca = adesso_testo()
        nonce = hashlib.sha256(
            ("%s%s%s" % (marca, self.agent_uid, os.urandom(8).hex()))
            .encode("utf-8")).hexdigest()[:32]
        documento = {
            "agent": self.agent_uid, "ts": marca, "nonce": nonce,
            "identita": identita, "misure": misure, "eventi": eventi,
        }
        if inventario:
            documento["inventario"] = inventario
        corpo = json.dumps(documento, separators=(",", ":"),
                           default=str).encode("utf-8")
        return self._apri("/api/agent/report", corpo,
                          {"X-Snap-Firma": self._firma(marca, nonce, corpo)})


# --------------------------------------------------------------------------- #
# La configurazione locale
# --------------------------------------------------------------------------- #
def leggi_configurazione(percorso: str) -> dict:
    if not os.path.exists(percorso):
        return {}
    with open(percorso, "r", encoding="utf-8") as file:
        return json.load(file)


def scrivi_configurazione(percorso: str, dati: dict) -> None:
    with open(percorso, "w", encoding="utf-8") as file:
        json.dump(dati, file, indent=2)
    try:
        # La chiave sta qui dentro: leggibile solo da chi possiede il file.
        os.chmod(percorso, 0o600)
    except OSError:
        pass  # su Windows i permessi si governano con le ACL, non con chmod


def gruppi_scelti(configurazione: dict) -> tuple:
    """I gruppi da raccogliere: quelli scelti, o i predefiniti.

    Un gruppo scritto nella configurazione ma sconosciuto a questa versione si
    IGNORA dichiarandolo: un agente aggiornato all'indietro non deve fermarsi per un
    nome che non conosce ancora.
    """
    scelti = configurazione.get("gruppi")
    if not scelti:
        return GRUPPI_PREDEFINITI
    validi = tuple(g for g in scelti if g in GRUPPI)
    ignorati = [g for g in scelti if g not in GRUPPI]
    if ignorati:
        _stampa("gruppi ignorati, sconosciuti a questa versione: %s"
                % ", ".join(ignorati))
    return validi or GRUPPI_PREDEFINITI


# --------------------------------------------------------------------------- #
# I comandi
# --------------------------------------------------------------------------- #
def comando_registra(argomenti) -> int:
    raccolta = Raccolta()
    identita = raccolta.identita()
    canale = Canale(argomenti.sonda, verifica_tls=not argomenti.senza_verifica_tls)
    try:
        esito = canale.registra(argomenti.token, identita)
    except urllib.error.HTTPError as errore:
        _stampa("registrazione rifiutata dalla sonda: %s" % errore.code)
        return 2
    except (urllib.error.URLError, OSError) as errore:
        _stampa("sonda non raggiungibile: %s" % errore)
        return 3

    # La scelta dei gruppi, se c'era, si conserva: registrare di nuovo una macchina
    # non deve rimettere a raccogliere cio' che qualcuno aveva spento.
    precedente = leggi_configurazione(argomenti.configurazione)
    nuova = {
        "sonda": argomenti.sonda,
        "agent": esito["agent"],
        "chiave": esito["chiave"],
        "intervallo": int(esito.get("intervallo") or 60),
        "verifica_tls": not argomenti.senza_verifica_tls,
        "registrato_at": adesso_testo(),
    }
    if precedente.get("gruppi"):
        nuova["gruppi"] = precedente["gruppi"]
    elif getattr(argomenti, "gruppi", None):
        nuova["gruppi"] = _gruppi_da_testo(argomenti.gruppi)
    scrivi_configurazione(argomenti.configurazione, nuova)
    _stampa("registrato come %s; configurazione in %s"
            % (esito["agent"], argomenti.configurazione))
    return 0


def _gruppi_da_testo(testo: str) -> list:
    """`--gruppi` accetta una preselezione o un elenco separato da virgole."""
    pulito = (testo or "").strip().lower()
    if pulito in PRESELEZIONI:
        return list(PRESELEZIONI[pulito])
    scelti = [g.strip() for g in pulito.split(",") if g.strip()]
    sconosciuti = [g for g in scelti if g not in GRUPPI]
    if sconosciuti:
        raise SystemExit("gruppi sconosciuti: %s\ngruppi disponibili: %s"
                         % (", ".join(sconosciuti), ", ".join(GRUPPI)))
    return scelti


def _tabella_gruppi(attivi) -> None:
    """L'elenco come lo legge chi deve scegliere: che cosa manda e che cosa costa."""
    print("")
    print("  #  invio  gruppo           cadenza  persone  che cosa manda")
    print("  -- -----  ---------------  -------  -------  " + "-" * 46)
    for numero, (codice, voce) in enumerate(GRUPPI.items(), start=1):
        descrizione = voce["descrizione"]
        if len(descrizione) > 46:
            descrizione = descrizione[:43] + "..."
        print("  %2d  [%s]   %-15s  %-7s  %-7s  %s"
              % (numero, "x" if codice in attivi else " ", codice,
                 voce["cadenza"], "si'" if voce["personali"] else "no",
                 descrizione))
    print("")


def comando_configura(argomenti) -> int:
    """L'interfaccia minima: che cosa questa macchina manda alla sonda.

    E' da CONSOLE e non una pagina web, e non per poverta' di mezzi: una pagina web
    vorrebbe dire un servizio in ascolto sulla macchina sorvegliata, cioe' la cosa
    che tutta l'architettura evita. Qui si sceglie, si salva, e l'agente applica al
    riavvio del servizio.
    """
    configurazione = leggi_configurazione(argomenti.configurazione)
    attivi = list(gruppi_scelti(configurazione))

    if argomenti.gruppi:
        attivi = _gruppi_da_testo(argomenti.gruppi)
        configurazione["gruppi"] = attivi
        scrivi_configurazione(argomenti.configurazione, configurazione)
        _stampa("gruppi attivi: %s" % ", ".join(attivi))
        return 0

    if not sys.stdin or not sys.stdin.isatty():
        # Senza un terminale non si puo' chiedere: si mostra e basta. Un installatore
        # non presidiato non deve restare fermo ad aspettare una risposta.
        _tabella_gruppi(attivi)
        print("Nessun terminale: per scegliere senza domande usare"
              " --gruppi <elenco|tutti|consigliato|minimo>")
        return 0

    print("\nChe cosa questa macchina manda alla sonda.")
    print("L'agente non apre porte e non riceve comandi: questa e' l'unica"
          " interfaccia che ha.")
    while True:
        _tabella_gruppi(attivi)
        print("  numeri = accendi/spegni (es. \"3 7\")   tutti / consigliato / minimo")
        print("  INVIO  = salva ed esci                 q = esci senza salvare")
        try:
            risposta = input("> ").strip().lower()
        except EOFError:
            risposta = ""
        if risposta == "q":
            print("niente salvato.")
            return 0
        if not risposta:
            break
        if risposta in PRESELEZIONI:
            attivi = list(PRESELEZIONI[risposta])
            continue
        codici = list(GRUPPI)
        for pezzo in risposta.replace(",", " ").split():
            if not pezzo.isdigit() or not 1 <= int(pezzo) <= len(codici):
                print("  ignorato: %s" % pezzo)
                continue
            codice = codici[int(pezzo) - 1]
            if codice in attivi:
                attivi.remove(codice)
            else:
                attivi.append(codice)

    configurazione["gruppi"] = [g for g in GRUPPI if g in attivi]
    scrivi_configurazione(argomenti.configurazione, configurazione)
    print("\nsalvato in %s: %d gruppi attivi su %d."
          % (argomenti.configurazione, len(configurazione["gruppi"]), len(GRUPPI)))
    if configurazione["gruppi"] != list(GRUPPI_PREDEFINITI):
        print("I gruppi spenti vengono DICHIARATI alla sonda: la console dira'"
              " \"non misurato\", non zero.")
    return 0


def comando_servizio(argomenti) -> int:
    configurazione = leggi_configurazione(argomenti.configurazione)
    if not configurazione.get("agent"):
        _stampa("non registrato: eseguire prima `registra`")
        return 4

    gruppi = gruppi_scelti(configurazione)
    raccolta = Raccolta(gruppi=gruppi)
    canale = Canale(configurazione["sonda"], configurazione["agent"],
                    configurazione["chiave"],
                    verifica_tls=configurazione.get("verifica_tls", True))
    identita = raccolta.identita()
    intervallo = int(configurazione.get("intervallo") or 60)
    # La coda degli invii non riusciti: la rete che si interrompe non deve far
    # perdere gli eventi di sicurezza. Si scartano i piu' vecchi, non i piu' nuovi.
    coda = deque(maxlen=CODA_MASSIMA)
    _stampa("avviato come %s verso %s, ogni %d s"
            % (configurazione["agent"], configurazione["sonda"], intervallo))
    _stampa("gruppi attivi (%d di %d): %s"
            % (len(gruppi), len(GRUPPI), ", ".join(gruppi)))
    if _nel_container():
        _stampa("in container: radice della macchina ospite %s"
                % (HOSTFS or "NON dichiarata -- si misura il container"))

    while True:
        inizio = time.monotonic()
        try:
            misure = raccolta.misure()
            # L'inventario e' `None` quasi sempre: scade una volta all'ora. Gli eventi
            # si ricavano da entrambi -- un'utenza nuova sta nell'inventario, una porta
            # nuova nelle misure.
            inventario = raccolta.inventario()
            eventi = raccolta.eventi(misure, inventario)
            coda.append((misure, eventi, inventario))
        except Exception as errore:  # noqa: BLE001 - la raccolta non deve fermare il ciclo
            _stampa("raccolta non riuscita: %s" % errore)

        while coda:
            misure, eventi, inventario = coda[0]
            try:
                risposta = canale.invia(misure, eventi, identita, inventario)
            except urllib.error.HTTPError as errore:
                if errore.code in (401, 403):
                    # Chiave non valida o agente revocato: riprovare non serve, e
                    # insistere sarebbe rumore su una sonda che ci ha gia' detto di no.
                    _stampa("respinto dalla sonda (%s): serve una nuova registrazione"
                            % errore.code)
                    return 5
                _stampa("invio non riuscito (%s): resta in coda" % errore.code)
                break
            except (urllib.error.URLError, OSError) as errore:
                _stampa("sonda non raggiungibile (%s): %d invii in coda"
                        % (errore, len(coda)))
                break
            coda.popleft()
            nuovo = int(((risposta or {}).get("configurazione") or {})
                        .get("intervallo") or intervallo)
            if nuovo != intervallo and 10 <= nuovo <= 3600:
                _stampa("intervallo aggiornato dalla sonda: %d s" % nuovo)
                intervallo = nuovo
            raccolta.soglie = ((risposta or {}).get("configurazione") or {}).get(
                "soglie") or raccolta.soglie

        attesa = max(1.0, intervallo - (time.monotonic() - inizio))
        time.sleep(attesa)


def comando_prova(argomenti) -> int:
    """Raccoglie una volta e stampa, senza inviare.

    Esiste per chi installa: risponde alla domanda che chiunque riceva un agente su
    una macchina di produzione fa per prima -- *che cosa mi porta via da qui?* -- e ci
    risponde mostrando esattamente il messaggio, non una descrizione del messaggio.
    """
    configurazione = leggi_configurazione(argomenti.configurazione)
    raccolta = Raccolta(gruppi=gruppi_scelti(configurazione))
    misure = raccolta.misure()
    inventario = raccolta.inventario()
    eventi = raccolta.eventi(misure, inventario)
    documento = {"identita": raccolta.identita(), "misure": misure,
                 "inventario": inventario, "eventi": eventi}
    if argomenti.riassunto:
        _riassunto(documento)
        return 0
    print(json.dumps(documento, indent=2, ensure_ascii=False, default=str))
    return 0


def _peso(oggetto) -> float:
    return len(json.dumps(oggetto, default=str).encode("utf-8")) / 1024


def _riassunto(documento: dict) -> None:
    """Il contenuto in venti righe: quanto pesa, che cosa c'e', che cosa manca.

    I due pesi si mostrano separati perche' sono due costi diversi: le misure si
    pagano a ogni minuto, l'inventario una volta all'ora.
    """
    misure = documento["misure"]
    inventario = documento.get("inventario") or {}
    al_minuto = _peso({"misure": misure, "eventi": documento["eventi"],
                       "identita": documento["identita"]})
    print("\nUn invio di questa macchina")
    print("  misure (ogni minuto)     %6.1f kB  ->  %.1f MB al giorno"
          % (al_minuto, al_minuto * 1440 / 1024))
    if inventario:
        print("  inventario (ogni ora)    %6.1f kB  ->  %.1f MB al giorno"
              % (_peso(inventario), _peso(inventario) * 24 / 1024))
    print("  eventi                   %6d" % len(documento["eventi"]))

    guasti = (misure.get("guasti") or []) + (inventario.get("guasti") or [])
    print("  gruppi che non si leggono %5d" % len(guasti))
    for guasto in guasti:
        print("      %-15s %s" % (guasto["gruppo"], guasto["motivo"][:70]))

    print("\n  gruppo           dove          kB  contenuto")
    for codice, voce in GRUPPI.items():
        dove = "inventario" if voce["cadenza"] == "lento" else "misure"
        sorgente = inventario if voce["cadenza"] == "lento" else misure
        if codice not in (sorgente.get("gruppi_attivi") or []):
            print("      %-15s %-10s   -  SPENTO" % (codice, dove))
            continue
        valore = sorgente.get(codice)
        if valore is None:
            contenuto = "non letto"
        elif isinstance(valore, list):
            contenuto = "%d voci" % len(valore)
        elif isinstance(valore, dict):
            contenuto = ", ".join(sorted(valore)[:4])[:44]
        else:
            contenuto = str(valore)[:44]
        print("      %-15s %-10s %4.1f  %s"
              % (codice, dove, _peso(valore), contenuto))
    print("")


def principale(argomenti_riga=None) -> int:
    analizzatore = argparse.ArgumentParser(
        prog="snap-agent",
        description="Agente di macchina snap: misura, osserva e riferisce alla sonda.")
    analizzatore.add_argument("--configurazione", default=CONFIG_PREDEFINITA,
                              help="file di stato dell'agente")
    analizzatore.add_argument("--senza-verifica-tls", action="store_true",
                              help="accetta il certificato della sonda senza"
                                   " verificarlo (sonde con certificato proprio)")
    sotto = analizzatore.add_subparsers(dest="comando")

    registra = sotto.add_parser("registra", help="registra questa macchina")
    registra.add_argument("sonda", help="indirizzo della sonda, es. https://10.0.0.5:5510")
    registra.add_argument("token", help="token emesso dalla console della sonda")
    registra.add_argument("--gruppi", default="",
                          help="che cosa inviare: elenco separato da virgole, oppure"
                               " tutti / consigliato / minimo")

    configura = sotto.add_parser("configura",
                                 help="scegli che cosa questa macchina invia")
    configura.add_argument("--gruppi", default="",
                           help="senza domande: elenco separato da virgole, oppure"
                                " tutti / consigliato / minimo")

    sotto.add_parser("servizio", help="raccoglie e invia a ciclo continuo")
    prova = sotto.add_parser("prova",
                             help="raccoglie una volta e stampa, senza inviare")
    prova.add_argument("--riassunto", action="store_true",
                       help="il contenuto in venti righe invece del JSON intero")

    argomenti = analizzatore.parse_args(argomenti_riga)
    if argomenti.comando == "registra":
        return comando_registra(argomenti)
    if argomenti.comando == "configura":
        return comando_configura(argomenti)
    if argomenti.comando == "servizio":
        return comando_servizio(argomenti)
    if argomenti.comando == "prova":
        return comando_prova(argomenti)
    analizzatore.print_help()
    return 1


if __name__ == "__main__":
    try:
        sys.exit(principale())
    except KeyboardInterrupt:
        _stampa("interrotto")
        sys.exit(0)
