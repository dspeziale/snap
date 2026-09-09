# Porte assegnate

Il progetto espone servizi **solo** nel range **5500-5600**. Ogni porta è definita in
configurazione (variabile d'ambiente), mai scritta nel codice. Questo file è l'elenco
autoritativo: prima di aggiungere un servizio si sceglie qui la porta, per non
scoprire un conflitto in esercizio.

## Server (`docker/server/docker-compose.yml`)

| Porta | Protocollo | Servizio | Pubblicata | Variabile |
|---|---|---|---|---|
| **5500** | TCP/HTTPS | Console e API, dietro reverse proxy nginx (terminazione TLS) | sì | `SNAP_HTTPS_PORT` |
| **5501** | TCP/HTTP | Solo rimando `http` → `https` (308) | sì | `SNAP_HTTP_REDIRECT_PORT` |
| 5500 | TCP/HTTP | Gunicorn *dentro* la rete del compose | no | `APP_PORT` |
| **5514** | UDP+TCP | Ascolto syslog del SIEM | sì | `SNAP_SERVER_SIEM_LISTENER_PORT` |
| 5432 | TCP | PostgreSQL | **no**, mai sull'host | — |

### Eccezione dichiarata: porta 514

La **514/UDP+TCP** è fuori dal range del progetto, ma è la porta syslog standard
(IANA): molti apparati sanno spedire solo su quella e non è configurabile lato
apparato. Viene quindi **pubblicata sull'host** e mappata sulla **5514 interna**:

```
514 (host) → 5514 (container)
```

Il doppio salto non è un vezzo: l'applicazione gira **non-root** e un processo
non-root non può legare una porta privilegiata. Mappando, gli apparati continuano a
spedire alla 514 senza che il server debba girare da root. Se la 514 dell'host è già
occupata da un syslog di sistema, si mette `SNAP_SYSLOG_PORT=5514` e si configurano
gli apparati sulla 5514.

## Sonda (`docker/probe/docker-compose.yml`)

La sonda gira in **rete host** (deve vedere la rete del cliente), quindi le porte non
si rimappano: sono quelle che i processi legano direttamente.

| Porta | Protocollo | Servizio | Raggiungibile da |
|---|---|---|---|
| **5510** | TCP/HTTPS | Interfaccia della sonda, dietro nginx | rete |
| **5512** | TCP/HTTP | Solo rimando `http` → `https` (308) | rete |
| 5511 | TCP/HTTP | La sonda (Gunicorn) | **solo 127.0.0.1** |

La 5511 è legata al loopback per costruzione: non esiste un canale in chiaro
raggiungibile dalla rete.

## SIEM opzionale (`docker/siem/docker-compose.yml`)

| Porta | Protocollo | Servizio | Pubblicata |
|---|---|---|---|
| **5514** | UDP+TCP | Collettore Vector | sì |

Il collettore Vector e l'ascolto syslog integrato del server usano la stessa porta:
**si usa l'uno o l'altro**, non entrambi sulla stessa macchina. Con Vector attivo si
mette `SNAP_SERVER_SIEM_LISTENER=0`.

## Sviluppo (`start.ps1`)

In sviluppo i due componenti girano senza container e **in chiaro**, sulle stesse
porte applicative: server **5500**, sonda **5510**. Dalla versione 1.2.8 si legano
per difetto all'indirizzo della macchina oltre che a `127.0.0.1`.
