"""
snap probe - Agente autonomo della sonda.

Il ciclo dell'agente e' pensato per funzionare anche in totale assenza del
server:

  1. RACCOLTA   a intervalli regolari produce record e li accoda localmente;
  2. CONTATTO   se e' registrata, tenta un heartbeat verso il server;
  3. COMANDI    esegue i comandi ricevuti in risposta e ne conferma l'esito;
  4. SCANSIONE  svolge la fase di scansione scaduta, se ce n'e' una;
  5. CONFERIMENTO invia i lotti prenotati dalla coda e li rimuove solo dopo
     l'acknowledgement: la coda si svuota.

Il contatto precede la scansione perche' porta con se' i comandi -- fra cui la
sospensione -- e una fase di ispezione dura minuti: dopo la scansione, i comandi
arriverebbero con altrettanto ritardo. Il conferimento la segue, cosi' cio' che la
scansione produce parte nello stesso giro.

Se il server non e' raggiungibile la sonda continua a raccogliere e la coda
cresce; al ritorno del server la coda viene conferita e liberata.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone

from .checker import CheckRunner
from .client import ProtocolError, ServerClient, TransportError
from .collector import Collector
from .nmap_runner import NmapError, NmapRunner
from .scanner import NetworkScanner, PerimeterViolation, ScanSuspended
from .store import ProbeStore, utc_now_str

MAX_RECORDS_PER_BATCH = 300

# Entro questo tempo dall'ultimo contatto il collegamento si considera valido
# fino a prova contraria: e' l'ultimo dato certo, e il primo battito dopo l'avvio
# lo confermera' o lo smentira' comunque entro un giro.
CONTACT_FRESH_SECONDS = 300

# Tipi di record previsti dal contratto di conferimento. La coda locale conserva
# il genere con cui ogni record e' stato accodato: senza questa traduzione tutto
# finirebbe fra le annotazioni e l'inventario resterebbe vuoto.
RECORD_TYPES = ("events", "nodes", "ports", "os", "scripts", "snmp", "smb", "vuln",
                "monitor", "scan_runs", "removals", "check_results", "web")
QUEUE_KIND_ALIASES = {"event": "events"}


def record_type_of(kind: str) -> str | None:
    """Tipo di record corrispondente al genere accodato; None se non previsto."""
    tipo = QUEUE_KIND_ALIASES.get(kind, kind)
    return tipo if tipo in RECORD_TYPES else None


class ProbeAgent:
    """Esecutore del ciclo di raccolta e conferimento in un thread dedicato."""

    def __init__(self, store: ProbeStore, agent_version: str, tick_seconds: int = 15):
        self.store = store
        self.agent_version = agent_version
        self.tick_seconds = tick_seconds
        self.client = ServerClient(store, agent_version)
        self.collector = Collector(store)
        self.scanner = NetworkScanner(store, NmapRunner(), agent_version)
        # I controlli condividono il runner dello scanner: le esecuzioni di nmap
        # sono cosi' contate e interrompibili insieme alle altre.
        self.checker = CheckRunner(store, self.scanner.runner)

        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        # La scansione ha un thread proprio: una fase di ispezione dura minuti, e il
        # giro dell'agente non deve attenderla, altrimenti per tutto quel tempo non
        # parte un battito e nulla dichiara che qualcosa sta accadendo.
        self._scan_thread: threading.Thread | None = None
        # Anche i controlli hanno un thread proprio: un endpoint lento non deve
        # ritardare il battito ne' attendere la fine di una scansione.
        self._checks_thread: threading.Thread | None = None
        # Prima del primo battito non si sa nulla del collegamento: dichiararlo
        # interrotto sarebbe un'affermazione non verificata, e con una fase di
        # ispezione in corso il primo battito arriva dopo minuti. Si parte percio'
        # dall'ultimo contatto registrato, se e' recente.
        self._online = self._recent_contact()
        self._last_error = ""

    def _recent_contact(self) -> bool:
        """Vero se il server ha risposto di recente, secondo l'archivio locale."""
        ultimo = self.store.get_setting("last_contact_at", None)
        if not ultimo:
            return False
        try:
            momento = datetime.strptime(ultimo, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc)
        except (TypeError, ValueError):
            # Valore illeggibile: non si indovina, si attende il primo battito.
            return False
        return (datetime.now(timezone.utc) - momento).total_seconds() <= CONTACT_FRESH_SECONDS

    # -- ciclo di vita -------------------------------------------------------
    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        # Un solo processo per archivio: qualunque prenotazione presente all'avvio
        # e' stata lasciata da un processo terminato e bloccherebbe i bersagli fino
        # alla scadenza.
        orfane = self.store.release_keys([c["key"] for c in self.store.active_claims()])
        if orfane:
            self.store.log("warning",
                           "Liberate %d prenotazioni lasciate da un processo precedente"
                           % orfane)
        self._thread = threading.Thread(target=self._run, name="snap-probe-agent", daemon=True)
        self._thread.start()
        self.store.log("info", "Agente avviato (versione %s)" % self.agent_version)

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def wake(self) -> None:
        """Sveglia immediatamente il ciclo (usato dai comandi dell'interfaccia)."""
        self._wake.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once(scan_in_background=True)
            except Exception as exc:  # il thread non deve morire per un errore isolato
                self._last_error = str(exc)
                self.store.log("error", "Errore nel ciclo dell'agente: %s" % exc)
            self._wake.wait(self.tick_seconds)
            self._wake.clear()

    # -- singola iterazione --------------------------------------------------
    def reset_store(self, keep_enrollment: bool = False, wait_seconds: float = 20.0) -> dict:
        """Azzera l'archivio dopo aver messo in quiete cio' che sta lavorando.

        Una scansione in corso scriverebbe i propri record subito dopo la
        cancellazione, e l'archivio "azzerato" ripartirebbe con dei residui: si
        sospendono le scansioni, si terminano i processi di nmap e si attende la
        fine dei thread prima di cancellare.
        """
        sospese_prima = self.store.get_setting("scan_paused", "0") == "1"
        self.store.set_setting("scan_paused", "1")
        fermati = self.scanner.runner.stop_all() if hasattr(
            self.scanner.runner, "stop_all") else 0

        for thread in (self._scan_thread, self._checks_thread):
            if thread is not None and thread.is_alive():
                thread.join(timeout=wait_seconds)

        rimosse = self.store.reset(keep_enrollment=keep_enrollment)

        # Le strutture in memoria non stanno nell'archivio: vanno azzerate a mano,
        # altrimenti la sonda continuerebbe a ragionare sui dati cancellati.
        self.scanner.forget_caches()
        if hasattr(self.scanner.runner, "resume"):
            self.scanner.runner.resume()
        self._online = False
        self._last_error = ""

        if keep_enrollment and sospese_prima:
            # Una sospensione decisa prima dell'azzeramento resta valida: non e'
            # l'azzeramento a decidere se si scansiona.
            self.store.set_setting("scan_paused", "1")
        else:
            self.store.set_setting("scan_paused", "0")

        rimosse["nmap_terminati"] = fermati
        return rimosse

    def _dispatch_scan(self) -> dict:
        """Avvia la scansione in un thread proprio, se non ne e' gia' in corso una.

        Una sola scansione per volta resta la regola: le fasi non devono
        sovrapporsi a se stesse.
        """
        if self._scan_thread is not None and self._scan_thread.is_alive():
            return {"running": True, "started": False}
        self._scan_thread = threading.Thread(
            target=self._run_due_scan, name="snap-probe-scan", daemon=True)
        self._scan_thread.start()
        return {"running": True, "started": True}

    def _run_due_checks(self) -> dict | None:
        """Esegue i controlli scaduti e accoda gli esiti.

        Gli errori di un controllo non arrestano l'agente ne' gli altri controlli:
        un endpoint che non risponde e' una condizione di esercizio, ed e' proprio
        cio' che il controllo deve rilevare.
        """
        try:
            record = self.checker.run_due()
        except OSError as errore:
            self.store.log("warning", "Controlli non eseguiti: %s" % errore)
            self._last_error = str(errore)
            return None
        for esito in record:
            self.store.enqueue("check_results", esito)
        return {"executed": len(record)}

    def _dispatch_checks(self) -> dict:
        """Avvia i controlli in un thread proprio, se non ne e' gia' in corso una passata."""
        if self._checks_thread is not None and self._checks_thread.is_alive():
            return {"running": True, "started": False}
        self._checks_thread = threading.Thread(
            target=self._run_due_checks, name="snap-probe-checks", daemon=True)
        self._checks_thread.start()
        return {"running": True, "started": True}

    def _checks_step(self, in_background: bool):
        return self._dispatch_checks() if in_background else self._run_due_checks()

    def _scan_step(self, in_background: bool):
        """Scansione del giro: in un thread proprio nel ciclo, subito altrimenti.

        Il percorso sincrono resta quello di una singola iterazione richiesta dal
        di fuori, dove l'esito deve essere disponibile al ritorno.
        """
        return self._dispatch_scan() if in_background else self._run_due_scan()

    def scan_in_progress(self) -> bool:
        """Vero se una scansione e' in corso nel proprio thread."""
        return self._scan_thread is not None and self._scan_thread.is_alive()

    def run_once(self, scan_in_background: bool = False) -> dict:
        outcome = {"collected": None, "synced": None, "commands": []}

        if self.store.get_setting("paused", "0") == "1":
            return outcome

        if self._collection_due():
            outcome["collected"] = self.collector.collect()

        if not self.store.is_enrolled():
            # Senza registrazione non c'e' con chi parlare: si raccoglie e si
            # scansiona in autonomia, che e' il comportamento previsto.
            outcome["scanned"] = self._scan_step(scan_in_background)
            return outcome

        # Il battito PRECEDE la scansione. Porta con se' la configurazione e i
        # comandi (fra cui la sospensione), e una fase di ispezione dura minuti:
        # rimandarlo a dopo la scansione ritarderebbe i comandi di altrettanto e
        # farebbe apparire irraggiungibile un server che risponde.
        try:
            answer = self.client.heartbeat()
            self._online = True
            self._last_error = ""
        except (TransportError, ProtocolError) as exc:
            self._online = False
            self._last_error = str(exc)
            self.store.set_setting("last_error_at", utc_now_str())
            self.store.log(
                "warning",
                "Server non raggiungibile: la raccolta continua in autonomia (%s)" % exc,
            )
            # La scansione non dipende dal server: prosegue comunque, e cio' che
            # produce resta in coda fino al ritorno del collegamento.
            outcome["scanned"] = self._scan_step(scan_in_background)
            return outcome

        self._apply_server_config(answer.get("config") or {})
        # Il perimetro puo' essere cambiato con questa configurazione: la sua
        # compilazione va rifatta, invece di attendere la scadenza.
        self.scanner.invalidate_perimeter()
        outcome["commands"] = self._execute_commands(answer.get("commands") or [])

        # Una sola fase per volta: la scansione e' l'attivita' piu' costosa e non
        # deve sovrapporsi a se stessa. Nel ciclo gira in un thread proprio, percio'
        # lo svuotamento della coda non ne attende la fine: cio' che produce parte al
        # giro successivo, quindici secondi dopo.
        outcome["checked"] = self._checks_step(scan_in_background)
        outcome["scanned"] = self._scan_step(scan_in_background)
        outcome["synced"] = self.flush_queue()
        return outcome

    def _run_due_scan(self) -> dict | None:
        """Esegue la fase di scansione scaduta, se ce n'e' una.

        Gli errori non arrestano l'agente: una rete che non risponde o un nmap
        assente sono condizioni di esercizio, non guasti del programma.
        """
        try:
            return self.scanner.run_due()
        except ScanSuspended:
            # Condizione voluta, non un errore: non si annota nulla.
            return None
        except PerimeterViolation as errore:
            # Gia' annotata dallo scanner con gravita' alta: qui si evita solo
            # che interrompa il ciclo.
            self._last_error = str(errore)
            return None
        except NmapError as errore:
            self._last_error = str(errore)
            return None
        except OSError as errore:
            self.store.log("warning", "Scansione non eseguita: %s" % errore)
            self._last_error = str(errore)
            return None

    def _collection_due(self) -> bool:
        """Vero se e' trascorso l'intervallo di raccolta configurato."""
        from .store import UTC_FORMAT
        from datetime import datetime, timezone

        last = self.store.get_setting("last_collection_at")
        interval = int(self.store.get_setting("scan_interval_sec", "300") or 300)
        if not last:
            return True
        try:
            moment = datetime.strptime(last, UTC_FORMAT).replace(tzinfo=timezone.utc)
        except ValueError:
            self.store.log("warning", "Data ultima raccolta illeggibile: si forza un ciclo")
            return True
        return (datetime.now(timezone.utc) - moment).total_seconds() >= interval

    def _apply_server_config(self, config: dict) -> None:
        """Recepisce la configurazione consegnata dal server."""
        if not config:
            return
        updates = {}
        interval = config.get("scan_interval_sec")
        if interval and int(interval) != int(self.store.get_setting("scan_interval_sec", "300")):
            updates["scan_interval_sec"] = int(interval)
        for key, setting in (
            ("tenant_code", "tenant_code"),
            ("tenant_name", "tenant_name"),
            ("tenant_timezone", "tenant_timezone"),
            ("probe_name", "probe_name"),
        ):
            value = config.get(key)
            if value and str(value) != self.store.get_setting(setting, ""):
                updates[setting] = value
        if updates:
            self.store.set_settings(updates)
            self.store.log("info", "Configurazione aggiornata dal server: %s" % ", ".join(updates))
        if config.get("options") is not None:
            self.store.set_json("server_options", config.get("options") or {})

        # Perimetro e cadenze: la sonda non li decide, li riceve. Un perimetro
        # che si svuota interrompe le scansioni, ed e' il comportamento voluto.
        if config.get("subnets") is not None:
            precedente = self.store.get_json("scan_subnets", []) or []
            nuovo = config.get("subnets") or []
            if precedente != nuovo:
                self.store.set_json("scan_subnets", nuovo)
                self.store.log(
                    "info",
                    "Perimetro aggiornato dal server: %s"
                    % (", ".join(v.get("cidr", "?") for v in nuovo) or "nessuna subnet"),
                )
        if config.get("cadences"):
            self.store.set_json("scan_cadences", config.get("cadences"))

        # Controlli periodici: come il perimetro, si ricevono e non si scelgono.
        # Un elenco che si svuota ferma i controlli, ed e' il comportamento voluto.
        if config.get("checks") is not None:
            precedenti = self.store.get_json("checks", []) or []
            nuovi = config.get("checks") or []
            if precedenti != nuovi:
                self.store.set_json("checks", nuovi)
                self.store.log(
                    "info",
                    "Controlli aggiornati dal server: %d definizioni (%s)"
                    % (len(nuovi), ", ".join(str(c.get("name")) for c in nuovi[:4])
                       or "nessuno"))
                # I controlli rimossi non devono lasciare il proprio stato in giro:
                # se venissero ridefiniti con lo stesso identificativo, la cadenza
                # sarebbe calcolata su un'esecuzione che non li riguarda.
                validi = {int(c["id"]) for c in nuovi if c.get("id") is not None}
                for vecchio in precedenti:
                    if vecchio.get("id") is not None and int(vecchio["id"]) not in validi:
                        self.store.forget_check_state(int(vecchio["id"]))
        # Le due impostazioni seguenti sono modificabili anche in sede: si
        # applicano solo quando il server le CAMBIA, confrontandole con l'ultimo
        # valore ricevuto e non con quello in uso. Diversamente ogni contatto
        # annullerebbe la scelta fatta sulla sonda.
        self._apply_if_server_changed(
            config, "scan_host_timeout",
            "Tempo massimo per host portato a '%s' dal server",
            vuoto="quello del profilo di sforzo")
        self._apply_if_server_changed(
            config, "scan_effort", "Profilo di sforzo portato a '%s' dal server")
        if config.get("scan_enabled") is not None:
            valore = "1" if config.get("scan_enabled") else "0"
            if self.store.get_setting("scan_enabled", "1") != valore:
                self.store.set_setting("scan_enabled", valore)
                self.store.log(
                    "warning" if valore == "0" else "info",
                    "Scansioni %s dal server"
                    % ("disabilitate" if valore == "0" else "riabilitate"),
                )

    def _apply_if_server_changed(self, config: dict, chiave: str, messaggio: str,
                                 vuoto: str = None) -> bool:
        """Applica un valore della configurazione solo se il server lo ha cambiato.

        L'ultimo valore ricevuto e' conservato a parte (`<chiave>_from_server`):
        e' il confronto con quello, non con il valore in uso, che permette a una
        scelta locale di sopravvivere.
        """
        if chiave not in config:
            return False
        consegnato = "" if config.get(chiave) is None else str(config.get(chiave))
        marcatore = "%s_from_server" % chiave
        precedente = self.store.get_setting(marcatore, None)

        if precedente is not None and str(precedente) == consegnato:
            return False  # il server non ha cambiato nulla: la scelta locale resta

        self.store.set_setting(marcatore, consegnato)
        if self.store.get_setting(chiave, "") == consegnato:
            return False  # gia' in uso: non c'e' nulla da annotare
        self.store.set_setting(chiave, consegnato)
        self.store.log("info", messaggio % (consegnato or (vuoto or "predefinito")))
        return True

    def _execute_commands(self, commands: list[dict]) -> list[dict]:
        """Esegue i comandi consegnati e prepara le conferme."""
        if not commands:
            return []

        results = []
        for command in commands:
            name = str(command.get("command") or "")
            identifier = command.get("id")
            try:
                detail = self._run_command(name, command.get("payload") or {})
                results.append({"id": identifier, "ok": True, "detail": detail})
                self.store.log("info", "Comando '%s' eseguito: %s" % (name, detail))
            except Exception as exc:  # l'esito negativo viene riportato al server
                results.append({"id": identifier, "ok": False, "detail": str(exc)})
                self.store.log("error", "Comando '%s' non eseguito: %s" % (name, exc))

        try:
            self.client.acknowledge_commands(results)
        except (TransportError, ProtocolError) as exc:
            self.store.log("warning", "Conferma comandi non recapitata: %s" % exc)
        return results

    def _run_command(self, name: str, payload: dict = None) -> str:
        payload = payload or {}
        if name == "scan":
            # Fase richiesta dall'operatore: si esegue subito, nel rispetto del
            # perimetro. Il bersaglio dichiarato non aggira la verifica: se non
            # appartiene al perimetro lo scanner lo rifiuta.
            fase = str(payload.get("stage") or "ports")
            bersaglio = str(payload.get("target") or "*")
            # Bersaglio speciale "@all": enumerazione SMB su TUTTI i nodi. Non si esegue
            # qui e adesso (bloccherebbe la sonda per l'intera passata): si attiva una
            # priorita' che il pianificatore onora a ogni ciclo, riempiendo i posti
            # liberi di lotti SMB finche' ogni nodo e' letto. I dati arrivano man mano.
            if bersaglio == "@all":
                if fase != "smb":
                    raise ValueError("la lettura su tutti i nodi vale solo per SMB")
                restano = self.scanner.enable_smb_boost()
                return ("enumerazione SMB su tutti i nodi avviata: %d da leggere,"
                        " procede a ogni ciclo" % restano)
            esito = self.scanner.run_stage(fase, bersaglio)
            return ("fase %s eseguita su %s: %d host, %d record"
                    % (fase, bersaglio, esito.get("hosts", 0),
                       sum(len(v) for v in (esito.get("records") or {}).values())))
        if name == "check_now":
            # Prova immediata richiesta dall'operatore: si esegue anche se la
            # cadenza non e' scaduta, perche' e' proprio cio' che si sta chiedendo.
            try:
                atteso = int(payload.get("check_id"))
            except (TypeError, ValueError):
                raise ValueError("comando check_now senza identificativo di controllo")
            definizione = next((d for d in self.checker.definitions()
                                if int(d.get("id") or 0) == atteso), None)
            if definizione is None:
                raise ValueError("controllo %d non presente fra quelli consegnati a questa "
                                 "sonda" % atteso)
            esito = self.checker.execute(definizione)
            self.store.enqueue("check_results", esito)
            return ("controllo '%s' eseguito subito: %s (%s)"
                    % (definizione.get("name"), esito["status"], esito["detail"][:120]))
        if name == "scan_pause":
            self.store.set_setting("scan_paused", "1")
            return "scansioni sospese su richiesta del server"
        if name == "scan_resume":
            self.store.set_setting("scan_paused", "0")
            return "scansioni riprese su richiesta del server"
        if name == "flush":
            outcome = self.flush_queue()
            return "conferimento immediato: %s" % outcome
        if name == "reconfigure":
            return "configurazione ricaricata al prossimo contatto"
        if name == "pause":
            self.store.set_setting("paused", "1")
            return "raccolta sospesa"
        if name == "resume":
            self.store.set_setting("paused", "0")
            return "raccolta ripresa"
        if name == "wipe":
            removed = self.store.clear_queue()
            return "coda locale svuotata (%d record)" % removed
        if name == "reset":
            self.collector.reset()
            return "conteggio dei cicli azzerato"
        raise ValueError("comando non supportato: %s" % name)

    # -- conferimento --------------------------------------------------------
    def flush_queue(self) -> dict:
        """Conferisce la coda al server, un lotto per volta, e la svuota."""
        summary = {"batches": 0, "records": 0, "remaining": self.store.queue_size()}
        if not self.store.is_enrolled():
            return summary

        while True:
            batch_uid = uuid.uuid4().hex
            reserved = self.store.reserve_batch(batch_uid, MAX_RECORDS_PER_BATCH)
            if not reserved:
                break

            # I record prenotati possono appartenere a un lotto precedente non
            # confermato: si riusa il suo identificativo per l'idempotenza.
            effective_uid = reserved[0]["batch_uid"] or batch_uid
            records = {}
            for item in reserved:
                tipo = record_type_of(item["kind"])
                if tipo is None:
                    # Genere non previsto dal contratto: si scarta dichiarandolo,
                    # altrimenti bloccherebbe la coda a ogni ciclo.
                    self.store.log(
                        "error",
                        "Record %d di genere '%s' non previsto dal contratto: scartato"
                        % (item["id"], item["kind"]),
                    )
                    self.store.discard(int(item["id"]))
                    continue
                records.setdefault(tipo, []).append(item["payload"])
            if not records:
                self.store.commit_batch(effective_uid)
                continue

            try:
                answer = self.client.send_batch(effective_uid, records, utc_now_str())
            except TransportError as exc:
                # Il lotto resta prenotato e verra' ritrasmesso identico.
                self._online = False
                self._last_error = str(exc)
                self.store.record_sync(effective_uid, len(reserved), "pending", str(exc))
                self.store.log("warning", "Conferimento rinviato: %s" % exc)
                break
            except ProtocolError as exc:
                self.store.release_batch(effective_uid)
                self.store.record_sync(effective_uid, len(reserved), "error", str(exc))
                self.store.log("error", "Conferimento rifiutato dal server: %s" % exc)
                break

            if not answer.get("accepted"):
                self.store.release_batch(effective_uid)
                self.store.record_sync(
                    effective_uid, len(reserved), "rejected", str(answer.get("error") or "")
                )
                self.store.log(
                    "error",
                    "Lotto non accettato: %s" % (answer.get("error") or "motivo non indicato"),
                )
                break

            # Un lotto accettato e' un contatto riuscito: l'indicatore si
            # spegneva sull'errore di trasporto ma non si riaccendeva qui.
            self._online = True
            self._last_error = ""
            removed = self.store.commit_batch(effective_uid)
            summary["batches"] += 1
            summary["records"] += removed
            self.store.record_sync(
                effective_uid,
                removed,
                "duplicate" if answer.get("duplicate") else "accepted",
                str(answer.get("detail") or ""),
            )
            self.store.set_setting("last_sync_at", utc_now_str())
            self.store.log(
                "info",
                "Lotto %s conferito e coda locale svuotata di %d record"
                % (effective_uid[:12], removed),
            )

        summary["remaining"] = self.store.queue_size()
        return summary

    # -- stato per l'interfaccia --------------------------------------------
    @property
    def online(self) -> bool:
        return self._online

    @property
    def last_error(self) -> str:
        return self._last_error

    def scan_status(self) -> dict:
        """Stato della scansione, per l'interfaccia locale."""
        return self.scanner.status()

    def status(self) -> dict:
        return {
            "running": self._thread is not None and self._thread.is_alive(),
            "online": self._online,
            "last_error": self._last_error,
            "queue_size": self.store.queue_size(),
            "queue_breakdown": self.store.queue_breakdown(),
            "oldest_queued_at": self.store.oldest_queued_at(),
            "paused": self.store.get_setting("paused", "0") == "1",
            "enrolled": self.store.is_enrolled(),
        }
