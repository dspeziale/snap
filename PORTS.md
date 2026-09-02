# Porte del progetto snap

Le applicazioni del progetto usano SOLO porte nel range **5500-5600**. Questo file
è il registro delle assegnazioni, per evitare conflitti (regola in CLAUDE.md).

| Porta | Protocollo | Servizio | Note |
|------:|------------|----------|------|
| 5500  | HTTP (TCP) | Console server (`snap server`) | Interfaccia web e API. Configurabile con `SNAP_SERVER_PORT`. |
| 5510  | HTTP (TCP) | Interfaccia sonda (`snap probe`)  | Configurazione locale della sonda. |
| 5514  | syslog (UDP/TCP) | Collettore log SIEM | Ricezione syslog dagli apparati: container Vector (`docker/siem/`) o listener integrato (`SNAP_SERVER_SIEM_LISTENER=1`). Configurabile con `SNAP_SERVER_SIEM_LISTENER_PORT`. |

## Note
- La porta di ogni servizio è definita in configurazione (variabile d'ambiente),
  mai hardcoded.
- Il collettore SIEM in container espone 5514 sull'host e inoltra gli eventi alla
  porta 5500 del server (endpoint `/api/siem/ingest`).
