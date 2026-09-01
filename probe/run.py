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
    parser.add_argument("--status", action="store_true", help="mostra lo stato locale ed esce")
    return parser.parse_args()


def command_status() -> int:
    from snapprobe.store import ProbeStore

    store = ProbeStore(Config.STORE_PATH)
    settings = store.all_settings()
    print("snap probe %s" % Config.APP_VERSION)
    print("Archivio locale:     %s" % Config.STORE_PATH)
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

    store = ProbeStore(Config.STORE_PATH)
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

    store = ProbeStore(Config.STORE_PATH)
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

    application = create_app()
    print("snap probe %s" % application.config["APP_VERSION"])
    print("Interfaccia locale:  http://%s:%d/" % (arguments.host, arguments.port))
    print("Archivio locale:     %s" % application.config["STORE_PATH"])
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
