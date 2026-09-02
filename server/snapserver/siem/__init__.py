# -----------------------------------------------------------------
# __init__.py — modulo SIEM: vocabolario comune di sorgenti, eventi e allarmi
# Autore: Daniele Speziale
# Data creazione: 2026-09-02
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - SIEM: raccolta dei log degli apparati e gestione degli eventi di
sicurezza che se ne ricavano.

Il disegno sta su tre piani, ciascuno col proprio modulo:

- **ingestion** (`ingest.py`, `parsers.py`, `store.py`): i log arrivano dal
  collettore (il container Vector, o il listener syslog integrato in `listener.py`),
  vengono riconosciuti per firma di apparato e normalizzati in un vocabolario
  comune di eventi, poi scritti A LOTTI in un database dedicato -- separato dal
  database della console, perche' un flusso di migliaia di righe al minuto non
  deve contendere le pagine a chi lavora;
- **rilevazione** (`detect.py`): regole a soglia su finestre temporali producono
  ALLARMI deduplicati (un attacco e' un allarme che si aggiorna, non mille);
- **correlazione**: ogni allarme viene agganciato al nodo dell'inventario tramite
  l'indirizzo coinvolto e ai riscontri aperti della threat intelligence su quel
  nodo: un tentativo di accesso verso una macchina gia' esposta vale piu' dello
  stesso tentativo verso una macchina sana, e la gravita' sale di un grado.
"""

from __future__ import annotations

# Tipologie di sorgente: guidano l'onboarding (istruzioni diverse per famiglia)
# e la scelta delle firme di riconoscimento.
SOURCE_KINDS = {
    "firewall": "Firewall / VPN",
    "windows": "Windows (eventi di sicurezza)",
    "linux": "Linux / Unix",
    "network": "Apparato di rete (switch, router, AP)",
    "pbx": "Centralino / PBX (Ericsson MX-ONE, MD110)",
    "other": "Altro (syslog generico)",
}

# Vocabolario comune degli eventi: qualunque apparato parli, l'evento normalizzato
# usa queste voci. E' cio' che rende scrivibili le regole di rilevazione.
EVENT_KINDS = {
    "auth_failure": "Accesso fallito",
    "auth_success": "Accesso riuscito",
    "auth_lockout": "Utenza bloccata",
    "user_change": "Utenza creata o modificata",
    "config_change": "Configurazione modificata",
    "conn_denied": "Connessione negata",
    "conn_allowed": "Connessione consentita",
    "malware": "Malware o minaccia segnalata",
    "log_cleared": "Registro eventi cancellato",
    "port_change": "Porta o collegamento cambiato",
    "equipment_alarm": "Allarme di apparato (guasto, malfunzionamento)",
    "system": "Evento di sistema",
    "other": "Non classificato",
}

# Gravita' degli allarmi: le stesse voci della threat intelligence, cosi' il
# quadro SOC e le notifiche parlano una lingua sola.
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_LABELS = {
    "critical": "Critica",
    "high": "Alta",
    "medium": "Media",
    "low": "Bassa",
    "info": "Informativa",
}

# Stati del ciclo di vita di un allarme: come i riscontri TI, con la presa in
# carico in mezzo. La chiusura libera la chiave di deduplicazione.
ALERT_OPEN = "open"
ALERT_ACK = "ack"
ALERT_CLOSED = "closed"
ALERT_FALSE_POSITIVE = "false_positive"
ALERT_STATUSES = {
    ALERT_OPEN: "Aperto",
    ALERT_ACK: "Preso in carico",
    ALERT_CLOSED: "Chiuso",
    ALERT_FALSE_POSITIVE: "Falso positivo",
}

# Limiti dell'ingestione: una richiesta oltre misura viene rifiutata per intero,
# non troncata in silenzio. I valori proteggono il server, non limitano Vector,
# che spedisce a lotti ben piu' piccoli.
MAX_EVENTS_PER_BATCH = 5000
MAX_MESSAGE_BYTES = 8192

# Porta del syslog: dentro il range 5500-5600 del progetto (vedi PORTS.md).
SYSLOG_PORT = 5514
