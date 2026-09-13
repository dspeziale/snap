#!/usr/bin/env bash
# -----------------------------------------------------------------
# installa.sh — installa l'agente snap su una macchina Linux
# Autore: Daniele Speziale
# Data creazione: 2026-09-13
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
#
# CHE COSA FA, IN ORDINE
#   1. verifica Python e psutil (dal pacchetto, se c'e', o da pip)
#   2. copia l'agente in /opt/snap-agent
#   3. crea l'utenza di servizio `snap-agent` (oppure resta root, vedi sotto)
#   4. registra la macchina sulla sonda con il token del pacchetto
#   5. installa e avvia l'unit systemd
#   6. VERIFICA che il servizio stia davvero girando, e lo dice
#
# I PRIVILEGI, DICHIARATI
# Di norma l'agente gira con un'utenza DEDICATA e senza privilegi: e' il minimo
# privilegio, ed e' la scelta giusta come predefinito. Ha un costo, ed e' bene saperlo
# prima e non dopo -- senza privilegi di amministratore NON si vedono:
#   * il processo e l'utente che tengono aperta una porta (si vede la porta, non chi);
#   * gli accessi falliti nel journal;
#   * le utenze locali complete e i membri dei gruppi di amministrazione.
# Sono esattamente le cose per cui l'agente esiste. Con `--privilegi-completi` gira da
# root e le vede tutte; in entrambi i casi NON legge contenuti di file, righe di
# comando, traffico o messaggi.
#
# I gruppi spenti per mancanza di privilegi vengono DICHIARATI alla sonda: la console
# scrivera' "non misurato", non zero.
set -euo pipefail

QUI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DESTINAZIONE="/opt/snap-agent"
SERVIZIO="snap-agent"
UTENTE="snap-agent"
PRIVILEGI_COMPLETI=0
GRUPPI=""
SENZA_TLS=0

uso() {
    cat <<'FINE'
Uso: sudo ./installa.sh [opzioni]

  --privilegi-completi   esegui come root: servono per vedere il processo dietro una
                         porta in ascolto, gli accessi falliti e le utenze locali
  --gruppi <elenco>      che cosa inviare, senza domande: elenco separato da virgole
                         oppure tutti | consigliato | minimo
  --senza-verifica-tls   accetta il certificato della sonda senza verificarlo
                         (sonde con certificato proprio, non firmato da un'autorita')
  --destinazione <dir>   dove installare (predefinito /opt/snap-agent)
  --aiuto                questo testo
FINE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --privilegi-completi) PRIVILEGI_COMPLETI=1; shift ;;
        --gruppi) GRUPPI="${2:-}"; shift 2 ;;
        --senza-verifica-tls) SENZA_TLS=1; shift ;;
        --destinazione) DESTINAZIONE="${2:-}"; shift 2 ;;
        --aiuto|-h|--help) uso; exit 0 ;;
        *) echo "opzione sconosciuta: $1" >&2; uso; exit 2 ;;
    esac
done

dire() { printf '  %s\n' "$*"; }
errore() { printf '\n  ERRORE: %s\n\n' "$*" >&2; exit 1; }

echo ""
echo "snap agent - installazione"
echo "--------------------------"

# --- 1. le condizioni ------------------------------------------------------ #
[[ $EUID -eq 0 ]] || errore "serve root: rieseguire con sudo."
[[ -f "$QUI/pacchetto.json" ]] || errore "manca pacchetto.json accanto a questo script."
[[ -f "$QUI/snap_agent.py" ]] || errore "manca snap_agent.py accanto a questo script."

PYTHON="$(command -v python3 || true)"
[[ -n "$PYTHON" ]] || errore "python3 non e' installato."
"$PYTHON" - <<'FINE' || errore "serve Python 3.9 o successivo."
import sys
raise SystemExit(0 if sys.version_info >= (3, 9) else 1)
FINE
dire "python: $("$PYTHON" --version 2>&1)"

SONDA="$("$PYTHON" -c "import json;print(json.load(open('$QUI/pacchetto.json'))['sonda'])")"
TOKEN="$("$PYTHON" -c "import json;print(json.load(open('$QUI/pacchetto.json'))['token'])")"
SCADE="$("$PYTHON" -c "import json;print(json.load(open('$QUI/pacchetto.json')).get('scade_at',''))")"
if [[ "$("$PYTHON" -c "import json;print(int(json.load(open('$QUI/pacchetto.json')).get('verifica_tls', True)))")" == "0" ]]; then
    SENZA_TLS=1
fi
dire "sonda:  $SONDA"
dire "token:  valido fino al $SCADE (una volta sola)"

# --- 2. l'ambiente --------------------------------------------------------- #
dire "installo in $DESTINAZIONE"
mkdir -p "$DESTINAZIONE"
install -m 0644 "$QUI/snap_agent.py" "$DESTINAZIONE/snap_agent.py"

if [[ ! -d "$DESTINAZIONE/venv" ]]; then
    "$PYTHON" -m venv "$DESTINAZIONE/venv" 2>/dev/null \
        || errore "non riesco a creare l'ambiente virtuale: manca python3-venv?"
fi
PIP="$DESTINAZIONE/venv/bin/pip"

# I pacchetti dal PACCHETTO, se ci sono: in una rete senza accesso a Internet -- che
# nella PA e' la norma, non l'eccezione -- pip non raggiungerebbe nulla.
if compgen -G "$QUI/wheels/*.whl" >/dev/null 2>&1; then
    dire "psutil dal pacchetto (senza rete)"
    "$PIP" install --quiet --no-index --find-links "$QUI/wheels" psutil \
        || errore "installazione di psutil dal pacchetto non riuscita."
else
    dire "psutil da pip"
    "$PIP" install --quiet -r "$QUI/requirements.txt" \
        || errore "installazione di psutil non riuscita: senza accesso a Internet,
  rigenerare il pacchetto includendo le wheel (vedi LEGGIMI.md)."
fi

# --- 3. l'utenza ----------------------------------------------------------- #
if [[ $PRIVILEGI_COMPLETI -eq 1 ]]; then
    ESECUTORE="root"
    dire "esecuzione come root (--privilegi-completi)"
else
    if ! id -u "$UTENTE" >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin "$UTENTE"
    fi
    ESECUTORE="$UTENTE"
    dire "esecuzione come utenza dedicata '$UTENTE' (minimo privilegio)"
    dire "  senza privilegi non si vedranno: processo dietro le porte in ascolto,"
    dire "  accessi falliti, utenze locali. Verranno DICHIARATI come non misurati."
fi

# --- 4. la registrazione --------------------------------------------------- #
CONFIG="$DESTINAZIONE/snap-agent.json"
ARGOMENTI_TLS=()
[[ $SENZA_TLS -eq 1 ]] && ARGOMENTI_TLS+=(--senza-verifica-tls)

if [[ -f "$CONFIG" ]] && "$PYTHON" -c "import json,sys;sys.exit(0 if json.load(open('$CONFIG')).get('agent') else 1)" 2>/dev/null; then
    dire "gia' registrata: la registrazione esistente si conserva"
else
    dire "registro la macchina sulla sonda..."
    ARGOMENTI_GRUPPI=()
    [[ -n "$GRUPPI" ]] && ARGOMENTI_GRUPPI+=(--gruppi "$GRUPPI")
    "$DESTINAZIONE/venv/bin/python" "$DESTINAZIONE/snap_agent.py" \
        --configurazione "$CONFIG" "${ARGOMENTI_TLS[@]}" \
        registra "$SONDA" "$TOKEN" "${ARGOMENTI_GRUPPI[@]}" \
        || errore "registrazione non riuscita. Il token vale UNA VOLTA SOLA e un'ora:
  se e' scaduto o e' gia' stato usato, emetterne un altro dalla console della sonda."
fi
chown -R "$ESECUTORE":"$ESECUTORE" "$DESTINAZIONE"
chmod 600 "$CONFIG"

# IL TOKEN NON RESTA SULLA MACCHINA. Ha gia' fatto il suo lavoro -- in cambio c'e' la
# chiave -- e una credenziale che sopravvive al proprio scopo e' una credenziale che
# qualcuno trovera' fra sei mesi.
rm -f "$QUI/pacchetto.json"
dire "token rimosso dalla macchina: ha gia' fatto il suo lavoro"

# --- 5. il servizio -------------------------------------------------------- #
cat > "/etc/systemd/system/${SERVIZIO}.service" <<FINE
[Unit]
Description=snap agent - misura questa macchina e riferisce alla sonda
Documentation=https://github.com/ds-consulting/snap
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${ESECUTORE}
ExecStart=${DESTINAZIONE}/venv/bin/python ${DESTINAZIONE}/snap_agent.py --configurazione ${CONFIG} servizio
Restart=always
RestartSec=30
# L'agente non ha bisogno di scrivere altrove che nella propria cartella, e non ha
# bisogno di privilegi che non usa: cio' che non serve si toglie.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${DESTINAZIONE}

[Install]
WantedBy=multi-user.target
FINE

systemctl daemon-reload
systemctl enable --quiet "$SERVIZIO"
systemctl restart "$SERVIZIO"

# --- 6. la verifica -------------------------------------------------------- #
# NON SI DICE "FATTO" SENZA AVER GUARDATO. Un installatore che stampa un esito
# positivo su un servizio che non e' partito fa perdere piu' tempo di uno che fallisce.
sleep 3
if systemctl is-active --quiet "$SERVIZIO"; then
    echo ""
    dire "FATTO. Il servizio '$SERVIZIO' e' attivo."
    dire "  che cosa manda:   $DESTINAZIONE/venv/bin/python $DESTINAZIONE/snap_agent.py --configurazione $CONFIG prova --riassunto"
    dire "  scegliere cosa:   $DESTINAZIONE/venv/bin/python $DESTINAZIONE/snap_agent.py --configurazione $CONFIG configura"
    dire "  diario:           journalctl -u $SERVIZIO -f"
    echo ""
else
    echo ""
    dire "Il servizio NON e' partito. Le ultime righe del suo diario:"
    journalctl -u "$SERVIZIO" -n 15 --no-pager || true
    exit 1
fi
