# Collettore di log SIEM (Vector)

Questo container riceve il **syslog** degli apparati e lo inoltra al server snap,
che lo riconosce, lo normalizza e ne ricava eventi e allarmi di sicurezza. È
l'unico pezzo "fuori" dalla console, ed è volutamente minimale: un solo servizio,
nessun database proprio, versione bloccata, utente non-root.

## Perché Vector e non un SIEM completo
Un SIEM open source completo (Graylog, Wazuh, ELK) richiede più container e
diversi GB di RAM, duplica funzioni che la console già ha (multi-tenant,
notifiche, threat intelligence) e renderebbe fragile la correlazione. Qui fuori
serve **solo** ricevere i log in fretta e in modo affidabile: Vector fa esattamente
questo. La conoscenza dei formati degli apparati sta nel server (`parsers.py`), in
un punto solo, così aggiungere il supporto a un nuovo apparato non richiede di
ridistribuire il container.

## Requisiti
- Docker con Compose. Se Docker non è disponibile, il server ha un **listener
  syslog integrato** (più lento ma senza container): si attiva con la variabile
  `SNAP_SERVER_SIEM_LISTENER=1`. In quel caso questo container non serve.

## Avvio in tre passi
1. Nella console: **SIEM → Sorgenti log**, crea un **collettore** e copia il token
   (viene mostrato una sola volta).
2. Copia `.env.example` in `.env` e incolla il token e l'indirizzo del server:
   ```
   cp .env.example .env
   # poi apri .env e compila SNAP_COLLECTOR_TOKEN e SNAP_INGEST_URI
   ```
3. Avvia:
   ```
   docker compose up -d
   ```

Verifica che il token sia valido:
```
docker compose logs -f vector
```
e nella console, dopo qualche secondo di log in arrivo, la scheda **Quadro SIEM**
mostra gli eventi e gli **host non ancora dichiarati**.

## Configurare gli apparati
Puntare il syslog degli apparati verso `host-del-docker:5514` (UDP o TCP). Esempi:

- **Cisco IOS**: `logging host <ip> transport udp port 5514`
- **Fortinet**: `set syslog-server <ip>` porta `5514`
- **Linux (rsyslog)**: `*.* @<ip>:5514` (UDP) o `@@<ip>:5514` (TCP)
- **Windows**: inoltro eventi via NXLog/WinLogBeat verso `<ip>:5514`

## Onboarding delle sorgenti
Dopo che i log iniziano ad arrivare, nella scheda **Sorgenti log** si dichiara ogni
apparato: nome, **tipologia** (firewall, Windows, Linux, apparato di rete), e
l'**host** o l'**indirizzo** con cui riconoscerlo. Collegando la sorgente al suo
**nodo dell'inventario** si abilita la correlazione: un allarme su quella macchina
citerà i riscontri di threat intelligence aperti su di essa, e salirà di gravità.

## Sicurezza
- Il **token** autentica il collettore e vincola il tenant di destinazione. È una
  credenziale: sta in `.env` (mai in repository), e nella console si può rigenerare.
- Il canale è HTTP verso il server: in esercizio va posto **dietro il reverse proxy
  con TLS** della console, come tutto il resto.
- I log contengono utenze e indirizzi: il server applica una **retention**
  configurabile (`SNAP_SERVER_SIEM_RETENTION_DAYS`, 90 giorni per difetto) e cancella
  gli eventi più vecchi (GDPR art. 5).
