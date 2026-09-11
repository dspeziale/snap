# Porte assegnate

Il progetto espone servizi **solo** nel range **5500-5600**. Ogni porta è definita in
configurazione (variabile d'ambiente), mai scritta nel codice. Questo file è l'elenco
autoritativo: prima di aggiungere un servizio si sceglie qui la porta, per non
scoprire un conflitto in esercizio.

## Server (`docker/server/docker-compose.yml`)

| Porta | Protocollo | Servizio | Pubblicata | Variabile |
|---|---|---|---|---|
| **443** | TCP/HTTPS | Console e API, dietro reverse proxy nginx (terminazione TLS) | sì | `SNAP_HTTPS_PORT` |
| 5500 | TCP/HTTPS | La stessa console *dentro* la rete del compose | no | — |
| **5501** | TCP/HTTP | Solo rimando `http` → `https` (308) | sì | `SNAP_HTTP_REDIRECT_PORT` |
| 5500 | TCP/HTTP | Gunicorn *dentro* la rete del compose | no | `APP_PORT` |
| **5514** | UDP+TCP | Ascolto syslog del SIEM | sì | `SNAP_SERVER_SIEM_LISTENER_PORT` |
| 5432 | TCP | PostgreSQL | **no**, mai sull'host | — |

### Eccezione dichiarata: porta 443

La **443/TCP** è fuori dal range del progetto, ma è la porta standard di `https`
(IANA): con essa la console si apre come `https://indirizzo`, senza scrivere il
numero. Quell'indirizzo finisce nei pacchetti di registrazione delle sonde, nelle
email alle utenze e nelle copertine dei report: ogni volta che va scritto con una
porta è un'occasione in cui qualcuno lo trascrive male.

Vale lo stesso meccanismo della 514: **dentro** il contenitore nginx ascolta sulla
**5500**, che è nel range, e gira come utente non privilegiato — una porta
privilegiata non potrebbe legarla. È il motore di container, che gira come root, a
pubblicare la 443 dell'host sulla 5500 interna:

```
443 (host) → 5500 (container)
```

La porta pubblica **non è scritta nella configurazione di nginx**: quel file è un
*template* e la riceve da `SNAP_HTTPS_PORT` all'avvio (envsubst). Serve in due punti
che altrimenti resterebbero indietro: la redirezione da `http` e l'intestazione
`X-Forwarded-Port`, con cui l'applicazione costruisce i propri indirizzi.

Chi preferisce restare nel range mette `SNAP_HTTPS_PORT=5500`: non c'è altro da
cambiare.

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
| 5532 | TCP | PostgreSQL della sonda | **solo 127.0.0.1** |

La 5511 è legata al loopback per costruzione: non esiste un canale in chiaro
raggiungibile dalla rete.

### Perché il Postgres della sonda ha una porta e quello del server no

Sul server la base dati sta su una rete interna del compose e **non lega alcuna porta
dell'host**: la 5432 resta un dettaglio interno. La sonda invece gira in **rete
host** (deve vedere la LAN del cliente), e un contenitore in rete host non può
raggiungere una rete interna: la base dati deve quindi stare sul loopback della
macchina, cioè legare una porta dell'host *davvero*.

Da qui due conseguenze, entrambe volute:

- `listen_addresses=127.0.0.1` — non risponde dalla rete, solo dalla macchina della
  sonda. È l'equivalente del «mai sull'host» del server.
- porta **5532** e non la 5432 predefinita: dal momento che si lega una porta
  dell'host, vale la regola del progetto (solo 5500‑5600) e la 5432 è fuori range.

Stato: **in uso**. Dalla versione 1.5.0 la sonda scrive su PostgreSQL e SQLite
non esiste più: i dati del vecchio archivio si importano al primo avvio.

### Sonda fuori dal contenitore (`docker-compose.nativa.yml`)

Su Docker Desktop (Windows/Mac) i contenitori stanno dentro una macchina virtuale e
il suo NAT **risponde per ogni indirizzo**: misurato sulla stessa subnet e nello
stesso momento, `nmap -sn` dava 5 host attivi dal PC e 256 su 256 dentro il
contenitore. Una sonda in quelle condizioni non fa inventario, lo *inventa*. Là la
sonda si avvia sulla macchina (`start-nativa.ps1`) e in contenitore resta la sola
base dati.

Le porte non cambiano, cambia **chi le lega**:

| Porta | Protocollo | Servizio | Chi la lega | Raggiungibile da |
|---|---|---|---|---|
| **5510** | TCP/HTTPS | Interfaccia della sonda | contenitore `proxy-nativa` | rete |
| **5512** | TCP/HTTP | Solo rimando `http` → `https` (308) | contenitore `proxy-nativa` | rete |
| 5511 | TCP/HTTP | La sonda (dev server di Flask) | la sonda, sulla macchina | **solo 127.0.0.1** |
| 5532 | TCP | PostgreSQL della sonda | contenitore, porta pubblicata | **solo 127.0.0.1** |

**Il TLS resta davanti.** Fuori dal contenitore la sonda non ha più il proxy del
compose di esercizio, ed esporla direttamente significherebbe HTTP in chiaro sulla
rete — con la password della sonda dentro. Quindi la sonda ascolta in chiaro *solo*
sul proprio loopback e davanti le sta lo stesso nginx dell'esercizio:

```
rete  --HTTPS-->  proxy-nativa (contenitore)  --loopback-->  sonda:5511
```

Che un contenitore raggiunga un servizio legato al **solo** `127.0.0.1` dell'host non
è ovvio, ed è stato misurato su questa installazione: un servizio di prova legato a
`127.0.0.1:5599` risultava raggiungibile dal contenitore via `host-gateway`, perché
Docker Desktop apre la connessione dal lato Windows — per il servizio è una
connessione locale. È ciò che permette alla sonda di **non esporre nulla in chiaro**.

La **prima impostazione della password** non passa dal proxy: là ogni richiesta
arriva dall'indirizzo del gateway di Docker, uguale per chi sta alla postazione e per
chi arriva dalla LAN, e un permesso su quell'indirizzo aprirebbe la sonda a tutta la
rete. Si fa **dalla macchina della sonda**, avviandola una volta con `-PrimaPassword` e
aprendo `http://127.0.0.1:5511/primo-accesso`: là l'indirizzo del client è quello
vero. L'interruttore serve perché con il proxy davanti il cookie di sessione è
marcato `Secure`, e un cookie Secure non viene rimandato su HTTP: senza cookie non
c'è sessione, senza sessione il token anti-CSRF viene rifiutato e la pagina risponde
«token scaduto» a ogni tentativo. Il token anti-CSRF **resta**: su quella pagina è
ciò che impedisce a un sito qualunque di impossessarsi della sonda. Dopo, si riavvia
senza l'interruttore (vedi `allow-primo-accesso.nativa.conf`).

Con `-SenzaProxy` la sonda si avvia comunque, ma resta raggiungibile solo da
`127.0.0.1`: nulla in chiaro sulla rete, e nulla raggiungibile da altrove.

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
