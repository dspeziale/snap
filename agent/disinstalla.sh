#!/usr/bin/env bash
# -----------------------------------------------------------------
# disinstalla.sh — toglie l'agente snap da una macchina Linux
# Autore: Daniele Speziale
# Data creazione: 2026-09-13
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
#
# Toglie il servizio, l'utenza e i file. NON revoca la macchina sulla sonda: quello
# si fa dalla console della sonda, ed e' voluto che siano due gesti distinti --
# disinstallare e' una manutenzione, revocare una credenziale e' una decisione.
set -euo pipefail

DESTINAZIONE="${1:-/opt/snap-agent}"
SERVIZIO="snap-agent"
UTENTE="snap-agent"

[[ $EUID -eq 0 ]] || { echo "serve root: rieseguire con sudo." >&2; exit 1; }

echo ""
echo "snap agent - disinstallazione"
echo "-----------------------------"

if systemctl list-unit-files | grep -q "^${SERVIZIO}.service"; then
    systemctl disable --now "$SERVIZIO" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVIZIO}.service"
    systemctl daemon-reload
    echo "  servizio rimosso"
fi

if [[ -d "$DESTINAZIONE" ]]; then
    rm -rf "$DESTINAZIONE"
    echo "  file rimossi da $DESTINAZIONE (chiave compresa)"
fi

if id -u "$UTENTE" >/dev/null 2>&1; then
    userdel "$UTENTE" 2>/dev/null || true
    echo "  utenza '$UTENTE' rimossa"
fi

echo ""
echo "  Fatto. La macchina risulta ancora REGISTRATA sulla sonda e smettera'"
echo "  semplicemente di riferire: per chiuderla del tutto, revocarla dalla"
echo "  console della sonda, pagina Agenti."
echo ""
