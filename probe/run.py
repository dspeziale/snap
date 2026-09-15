"""
snap probe - Punto di avvio della sonda.

Uso:
    python run.py                      avvia sonda e interfaccia locale (porta 5510)
    python run.py --port 5511          avvio su porta alternativa (5500-5600)
    python run.py --headless           avvia solo l'agente, senza interfaccia web
    python run.py --enroll SNAP1-...   registra la sonda da riga di comando ed esce
    python run.py --status             mostra lo stato locale ed esce

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from snapprobe.settings import Config  # noqa: E402

PORT_RANGE = (5500, 5600)


def _archivio_mostrabile() -> str:
    """L'indirizzo dell'archivio senza la credenziale.

    La stringa di connessione contiene la password: si mostra cio' che serve a
    riconoscere l'archivio -- host, porta, nome -- e nient'altro. Lo stesso
    accorgimento del server (`maintenance.database_target`).
    """
    indirizzo = (getattr(Config, "DATABASE_URL", "") or "").strip()
    if not indirizzo:
        return "(non configurato: manca SNAP_PROBE_DATABASE_URL)"
    return indirizzo.rsplit("@", 1)[-1] or "(non indicato)"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Avvio della sonda snap")
    parser.add_argument("--host", default=Config.HOST, help="indirizzo di ascolto dell'interfaccia")
    parser.add_argument("--port", type=int, default=Config.PORT, help="porta dell'interfaccia")
    parser.add_argument("--debug", action="store_true", help="modalita' di sviluppo")
    parser.add_argument(
        "--headless",
        action="store_true",
        help="esegue solo l'agente di raccolta e conferimento",
    )
    parser.add_argument(
        "--enroll",
        metavar="PACCHETTO",
        help="registra la sonda con il pacchetto SNAP1-... emesso dal server",
    )
    parser.add_argument(
        "--solo-interfaccia",
        action="store_true",
        help="avvia SOLO l'interfaccia web, senza l'agente di raccolta",
    )
    parser.add_argument("--status", action="store_true", help="mostra lo stato locale ed esce")
    parser.add_argument(
        "--password",
        nargs="?",
        const="",
        metavar="NUOVA",
        help="imposta o reimposta la password dell'interfaccia locale ed esce."
             " Senza valore la chiede senza mostrarla a schermo; con"
             " --password-casuale ne genera una robusta",
    )
    parser.add_argument(
        "--password-casuale",
        action="store_true",
        help="con --password: genera una password robusta e la mostra una volta",
    )
    return parser.parse_args()


# Lunghezza della password generata. Venti caratteri dall'alfabeto qui sotto sono
# circa 118 bit: piu' che sufficienti per una credenziale che non si digita spesso e
# che si conserva in un gestore di password.
LUNGHEZZA_GENERATA = 20
# Alfabeto senza i caratteri che si confondono a voce o su carta (l/I/1, O/0) e senza
# quelli che una shell interpreta: una password che va citata al telefono o incollata
# in un comando non deve costringere a spiegare quale "l" era.
ALFABETO_GENERATO = ("ABCDEFGHJKLMNPQRSTUVWXYZ"
                     "abcdefghijkmnopqrstuvwxyz"
                     "23456789"
                     "-_.+=")


def genera_password() -> str:
    """Una password robusta che soddisfa la politica per costruzione.

    Si estrae finche' non rispetta la politica invece di comporla a pezzi: comporre
    "una maiuscola, una minuscola, una cifra e poi il resto" riduce lo spazio delle
    password possibili in un modo che non si vede a occhio.
    """
    import secrets

    from snapprobe.auth import errori_di_politica

    for _tentativo in range(100):
        candidata = "".join(secrets.choice(ALFABETO_GENERATO)
                            for _ in range(LUNGHEZZA_GENERATA))
        if not errori_di_politica(candidata):
            return candidata
    # Non e' mai successo e non puo' praticamente succedere; se succedesse, meglio
    # fermarsi che consegnare una password che non rispetta la politica.
    raise RuntimeError("generazione della password non riuscita")


def command_password(valore: str, casuale: bool) -> int:
    """Imposta o reimposta la password dell'interfaccia locale.

    PERCHE' ESISTE. `/primo-accesso` vale solo finche' una password non c'e': una
    password dimenticata non aveva nessuna via d'uscita documentata. Questo comando
    ne e' la via, e chiede piu' di quella pagina -- una shell sulla macchina della
    sonda -- non meno.

    La password non si accetta dalla riga di comando per una ragione misurabile:
    finirebbe nella cronologia della shell e nell'elenco dei processi, dove la vede
    chiunque sia connesso alla stessa macchina.
    """
    import getpass

    from snapprobe.auth import errori_di_politica, imposta_password, password_impostata
    from snapprobe.store import ProbeStore

    ProbeStore()  # apre l'archivio: se non e' raggiungibile, si vede subito
    prima = password_impostata()

    if casuale:
        nuova = genera_password()
        mostrata = True
    elif valore:
        # Un valore sulla riga di comando: si accetta (serve agli automatismi) ma si
        # dice che cosa comporta, invece di lasciarlo scoprire a chi legge la
        # cronologia della shell fra un mese.
        print("ATTENZIONE: la password passata sulla riga di comando resta nella"
              " cronologia della shell e nell'elenco dei processi.")
        nuova, mostrata = valore, False
    else:
        nuova = getpass.getpass("Nuova password dell'interfaccia della sonda: ")
        conferma = getpass.getpass("Ripetere la password: ")
        if nuova != conferma:
            print("Le due password non coincidono: niente e' stato cambiato.",
                  file=sys.stderr)
            return 1
        mostrata = False

    errori = errori_di_politica(nuova)
    if errori:
        for errore in errori:
            print("  %s" % errore, file=sys.stderr)
        print("Niente e' stato cambiato.", file=sys.stderr)
        return 1

    imposta_password(nuova)
    print("Password %s." % ("reimpostata" if prima else "impostata"))
    if mostrata:
        print()
        print("    %s" % nuova)
        print()
        print("Si vede UNA VOLTA: viene conservata come impronta scrypt, quindi"
              " nemmeno la sonda puo' rileggerla.")
    print("L'interfaccia accetta la nuova password subito: non serve riavviare.")
    return 0


def command_status() -> int:
    from snapprobe.store import ProbeStore

    store = ProbeStore()
    settings = store.all_settings()
    print("snap probe %s" % Config.APP_VERSION)
    # L'indirizzo dell'archivio contiene la password: si mostra solo host, porta e
    # nome del database, come fa il server.
    print("Archivio:            %s" % _archivio_mostrabile())
    print("Registrata:          %s" % ("si" if store.is_enrolled() else "no"))
    print("Server:              %s" % settings.get("server_url", "-"))
    print("Codice sonda:        %s" % settings.get("probe_code", "-"))
    print("Tenant:              %s" % settings.get("tenant_name", "-"))
    print("Fuso del tenant:     %s" % settings.get("tenant_timezone", "-"))
    print("Intervallo raccolta: %s s" % settings.get("scan_interval_sec", "-"))
    print("Record in coda:      %d %s" % (store.queue_size(), store.queue_breakdown() or ""))
    print("Ultimo conferimento: %s" % settings.get("last_sync_at", "mai"))
    return 0


def command_enroll(bundle: str) -> int:
    from snapprobe.client import ProtocolError, ServerClient, TransportError, parse_bundle
    from snapprobe.crypto import CryptoError
    from snapprobe.store import ProbeStore

    store = ProbeStore()
    if store.is_enrolled():
        print("La sonda risulta gia' registrata: azzerare prima la registrazione.", file=sys.stderr)
        return 1

    try:
        parameters = parse_bundle(bundle)
    except ValueError as exc:
        print("Pacchetto non valido: %s" % exc, file=sys.stderr)
        return 2

    client = ServerClient(store, Config.APP_VERSION, timeout=Config.HTTP_TIMEOUT)
    try:
        client.enroll(**parameters)
    except (TransportError, ProtocolError, CryptoError) as exc:
        print("Registrazione non riuscita: %s" % exc, file=sys.stderr)
        return 3

    print(
        "Registrazione completata presso %s (tenant %s)"
        % (parameters["server_url"], store.get_setting("tenant_name", "-"))
    )
    return 0


def command_headless() -> int:
    """Esegue il solo agente: utile su dispositivi senza interfaccia."""
    from snapprobe.agent import ProbeAgent
    from snapprobe.store import ProbeStore

    store = ProbeStore()
    if not store.get_setting("scan_interval_sec"):
        store.set_setting("scan_interval_sec", Config.DEFAULT_SCAN_INTERVAL)
    agent = ProbeAgent(store, Config.APP_VERSION, Config.AGENT_TICK_SECONDS)
    agent.start()
    print("snap probe in esecuzione senza interfaccia (Ctrl+C per terminare)")
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        agent.stop()
        print("Agente arrestato.")
    return 0


def main() -> int:
    arguments = parse_arguments()

    if arguments.password is not None or arguments.password_casuale:
        return command_password(arguments.password or "",
                                arguments.password_casuale)
    if arguments.status:
        return command_status()
    if arguments.enroll:
        return command_enroll(arguments.enroll)
    if arguments.headless:
        return command_headless()

    if not PORT_RANGE[0] <= arguments.port <= PORT_RANGE[1]:
        print(
            "Porta %d fuori dall'intervallo consentito %d-%d"
            % (arguments.port, *PORT_RANGE),
            file=sys.stderr,
        )
        return 2

    from snapprobe import create_app

    # DUE PROCESSI, NON UNO, e va spiegato perche' e' una correzione e non una scelta
    # di gusto.
    #
    # L'interfaccia web e i trentadue lavoratori di scansione vivevano nello stesso
    # interprete Python. Un interprete esegue un thread per volta (GIL): mentre la
    # scansione lavora, la pagina aspetta. MISURATO su questa installazione, sulla
    # pagina di accesso -- che non tocca nemmeno l'archivio:
    #
    #     scansioni attive   3-6 secondi, e oltre i 120 s del proxy sotto il carico
    #                        di un browser (decine di richieste in parallelo) -> 504
    #     scansioni sospese  0,46-0,73 secondi
    #
    # Separare i due mestieri in due processi da a ciascuno il proprio interprete:
    # la scansione non puo' piu' affamare l'interfaccia. I due processi condividono
    # l'archivio PostgreSQL, che e' fatto per questo -- ed e' diventato possibile da
    # quando l'archivio non ha piu' un lucchetto globale (vedi store.ProbeStore).
    #
    # `--solo-interfaccia` avvia la sola interfaccia; `--headless` il solo agente.
    application = create_app(start_agent=not arguments.solo_interfaccia)
    print("snap probe %s%s" % (application.config["APP_VERSION"],
                               " (solo interfaccia)" if arguments.solo_interfaccia else ""))
    print("Interfaccia locale:  http://%s:%d/" % (arguments.host, arguments.port))
    print("Archivio:            %s" % _archivio_mostrabile())
    print(
        "Stato registrazione: %s"
        % ("registrata" if application.extensions["snap_store"].is_enrolled() else "non registrata")
    )
    # use_reloader disattivato: il ricaricamento duplicherebbe il thread dell'agente.
    application.run(
        host=arguments.host,
        port=arguments.port,
        debug=arguments.debug or application.config["DEBUG"],
        use_reloader=False,
        threaded=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
