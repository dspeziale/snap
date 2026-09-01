"""
snap server - Punto di avvio.

Uso:
    python run.py                 avvia il server sulla porta configurata (5500)
    python run.py --init          inizializza schema e dati iniziali, poi esce
    python run.py --port 5501     avvio su porta alternativa (intervallo 5500-5600)

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from snapserver import create_app  # noqa: E402
from snapserver.settings import Config  # noqa: E402

PORT_RANGE = (5500, 5600)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Avvio del server snap")
    parser.add_argument("--host", default=Config.HOST, help="indirizzo di ascolto")
    parser.add_argument("--port", type=int, default=Config.PORT, help="porta di ascolto")
    parser.add_argument("--debug", action="store_true", help="modalita' di sviluppo")
    parser.add_argument(
        "--init",
        action="store_true",
        help="inizializza database e dati iniziali senza avviare il servizio",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    if not PORT_RANGE[0] <= arguments.port <= PORT_RANGE[1]:
        print(
            "Porta %d fuori dall'intervallo consentito %d-%d"
            % (arguments.port, *PORT_RANGE),
            file=sys.stderr,
        )
        return 2

    application = create_app()

    if arguments.init:
        from snapserver.seed import seed_initial_data

        with application.app_context():
            for line in seed_initial_data():
                print(line)
        print("Inizializzazione completata: %s" % application.config["DATABASE"])
        return 0

    print("snap server %s" % application.config["APP_VERSION"])
    print("Interfaccia web:   http://%s:%d/" % (arguments.host, arguments.port))
    print("Canale sonde:      http://%s:%d/api/v1/ping" % (arguments.host, arguments.port))
    print("Database:          %s" % application.config["DATABASE"])
    application.run(
        host=arguments.host,
        port=arguments.port,
        debug=arguments.debug or application.config["DEBUG"],
        use_reloader=arguments.debug,
        threaded=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
