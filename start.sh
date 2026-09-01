#!/usr/bin/env bash
# snap - Avvio completo di server e sonda (shell POSIX / Git Bash).
#
# Esempi:
#   ./start.sh              avvia server (5500) e sonda (5510) in background
#   ./start.sh server       avvia solo il server
#   ./start.sh probe        avvia solo la sonda
#   ./start.sh setup        prepara ambiente, dipendenze e database
#   ./start.sh test         esegue la suite di test
#   ./start.sh stop         arresta i processi avviati da questo script
#
# remarks: Autore: Daniele Speziale - Data: 2026-08-26
# copyright: (c) 2024-26 DS Consulting
# license: MIT

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$ROOT/.venv"
PID_DIR="$ROOT/.snap-run"
SERVER_PORT="${SNAP_SERVER_PORT:-5500}"
PROBE_PORT="${SNAP_PROBE_PORT:-5510}"

python_bin() {
  if [ -x "$VENV/bin/python" ]; then echo "$VENV/bin/python"
  elif [ -x "$VENV/Scripts/python.exe" ]; then echo "$VENV/Scripts/python.exe"
  elif command -v python3 >/dev/null 2>&1; then command -v python3
  else command -v python
  fi
}

section() { printf '\n\033[36m== %s ==\033[0m\n' "$1"; }

do_setup() {
  section "Preparazione ambiente"
  if [ ! -d "$VENV" ]; then
    "$(command -v python3 || command -v python)" -m venv "$VENV"
  fi
  local py; py="$(python_bin)"
  "$py" -m pip install --disable-pip-version-check -q -r "$ROOT/server/requirements.txt"
  "$py" -m pip install --disable-pip-version-check -q -r "$ROOT/probe/requirements.txt"
  (cd "$ROOT/server" && "$py" run.py --init)
  echo "Ambiente pronto."
}

do_test() {
  section "Suite di test"
  (cd "$ROOT" && "$(python_bin)" -m pytest tests -v)
}

start_one() {
  local name="$1" dir="$2" port="$3"
  mkdir -p "$PID_DIR"
  local py; py="$(python_bin)"
  ( cd "$dir" && nohup "$py" run.py --port "$port" > "$PID_DIR/$name.log" 2>&1 & echo $! > "$PID_DIR/$name.pid" )
  sleep 1
  if ! kill -0 "$(cat "$PID_DIR/$name.pid")" 2>/dev/null; then
    echo "Avvio di $name non riuscito; consultare $PID_DIR/$name.log" >&2
    return 1
  fi
  printf '  %-12s http://127.0.0.1:%s/   (PID %s)\n' "$name" "$port" "$(cat "$PID_DIR/$name.pid")"
}

do_stop() {
  section "Arresto dei componenti"
  if [ ! -d "$PID_DIR" ]; then echo "Nessun processo registrato."; return 0; fi
  for pidfile in "$PID_DIR"/*.pid; do
    [ -e "$pidfile" ] || continue
    local pid name
    pid="$(cat "$pidfile")"; name="$(basename "$pidfile" .pid)"
    if kill -0 "$pid" 2>/dev/null; then kill "$pid" && echo "Arrestato $name (PID $pid)"
    else echo "$name (PID $pid) non era in esecuzione"; fi
    rm -f "$pidfile"
  done
}

case "${1:-all}" in
  setup) do_setup ;;
  test)  do_test ;;
  stop)  do_stop ;;
  server|probe|all)
    [ -f "$ROOT/server/data/snap_server.sqlite3" ] || do_setup
    section "Avvio di snap"
    case "${1:-all}" in
      server) start_one "server" "$ROOT/server" "$SERVER_PORT" ;;
      probe)  start_one "probe"  "$ROOT/probe"  "$PROBE_PORT" ;;
      all)    start_one "server" "$ROOT/server" "$SERVER_PORT"
              start_one "probe"  "$ROOT/probe"  "$PROBE_PORT" ;;
    esac
    cat <<'INFO'

Credenziali iniziali del server:
  Amministratore di sistema : admin@snap.local / Snap!Admin2026
  Amministratore tenant     : admin@ised.local / Snap!Tenant2026

Sequenza consigliata:
  1. Accedere al server: Sonde & Discovery > Registra sonda
  2. Copiare il pacchetto SNAP1-...
  3. Interfaccia della sonda > Registra la sonda > incollare il pacchetto

Per arrestare: ./start.sh stop
INFO
    ;;
  *) echo "Uso: $0 [all|server|probe|setup|test|stop]" >&2; exit 2 ;;
esac
