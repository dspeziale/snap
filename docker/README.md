# Deploy in esercizio

Due deploy separati, perché i due componenti stanno in posti diversi:

- **`server/`** — la console, le API e il SIEM. Sta nel datacenter/sede. Include
  PostgreSQL.
- **`probe/`** — la sonda. Sta **nella rete del cliente**, dove deve scansionare.
- **`siem/`** — collettore Vector, opzionale (alternativa all'ascolto syslog
  integrato nel server).

Entrambi espongono i siti in **HTTPS**: il TLS si termina su un reverse proxy nginx
davanti a Gunicorn, con il certificato **montato** da `./certs` (mai dentro
l'immagine).

## Avvio del server

```bash
cd docker/server
cp .env.example .env          # compilare i segreti (obbligatori)
mkdir -p certs                # mettere server.crt e server.key
docker compose up -d --build
```

Poi, nella console: **Amministrazione → Impostazioni Sistema → Indirizzo pubblico del
server** va messo con `https://` (entra nei pacchetti di registrazione delle sonde,
nelle email ai nuovi utenti e nelle copertine dei report).

## Avvio della sonda

```bash
cd docker/probe
cp .env.example .env
mkdir -p certs                # mettere probe.crt e probe.key
docker compose up -d --build
```

Poi, **dalla macchina della sonda**, aprire `https://127.0.0.1:5510` per scegliere la
password: dalla rete la *prima* impostazione viene rifiutata per disegno, così la
sonda appartiene a chi l'ha installata. Infine si incolla il pacchetto `SNAP1-...`
generato dalla console.

### La base dati della sonda

Anche la sonda ha il suo PostgreSQL (`snap-probe-postgres`), con la stessa struttura
di privilegi del server: un **proprietario** che crea e migra lo schema e un utente
**applicativo** che può solo leggere e scrivere i dati.

**Stato: predisposto, non ancora usato.** Il codice della sonda scrive su SQLite
(modulo `sqlite3`, 63 punti di SQL, nessun driver PostgreSQL fra le dipendenze),
esattamente come il server. Il servizio è il bersaglio del porting; finché il porting
non c'è, l'archivio resta il file nel volume `probe-data`.

Due differenze rispetto al server, entrambe conseguenze della rete host:

| | Server | Sonda |
|---|---|---|
| Dove ascolta | rete interna del compose, **nessuna porta sull'host** | `127.0.0.1:5532` (host) |
| Porta | 5432, dettaglio interno | **5532**, dentro il range del progetto |
| `pg_hba` dal loopback | `trust` (loopback del solo contenitore) | **`scram-sha-256`** |

La terza riga è la meno ovvia e la più importante. L'immagine ufficiale si fida senza
password delle connessioni dal loopback. Sul server quel loopback è quello *interno
al contenitore*, che nessun altro processo condivide. Sulla sonda, che gira in rete
host, è il loopback **della macchina**: con la regola predefinita qualunque processo
locale sull'apparato potrebbe collegarsi *come proprietario della base dati senza
password*. Su un apparato lasciato in sede dal cliente non è accettabile, e
[initdb/20-autenticazione.sh](probe/initdb/20-autenticazione.sh) riscrive `pg_hba.conf`
alla prima inizializzazione. Verificato:

```
dal loopback senza password   fe_sendauth: no password supplied
con la password               snap_probe_app collegato
CREATE TABLE come applicativo ERROR: permission denied for schema public
```

Resta a `trust` solo il socket unix, che vive nel filesystem del contenitore e non è
esposto all'host: serve all'entrypoint dell'immagine, che si collega senza password
per eseguire gli script di inizializzazione.

Gli script `initdb` girano **una sola volta**, alla creazione del volume: su
un'installazione già inizializzata le regole cambiano solo ricreando il volume.

### Aprire l'interfaccia puntando l'IP della macchina

Il rifiuto vale solo per la *prima* impostazione della password, e sono **due
barriere indipendenti** — vanno aperte entrambe, dichiarando la propria postazione:

| Dove | Cosa |
|---|---|
| `allow-primo-accesso.conf` | `allow 10.20.10.7;` (il proxy decide sul vero interlocutore TCP) |
| `.env` | `SNAP_PROBE_FIRST_ACCESS_FROM=10.20.10.7` (la sonda, indirizzi o reti) |

Si dichiara la **propria postazione**, non una rete intera: finché la password non
esiste, chi apre quella pagina diventa proprietario della sonda. Elencare l'IP anche
nel campo SAN del certificato, altrimenti il browser avvisa sul nome.

### Su Docker Desktop (Windows/Mac): connessione rifiutata

Con `network_mode: host` i container non stanno sull'host ma in una macchina
virtuale: le porte 5510/5512 vengono legate **dentro** quella macchina e da
Windows/Mac non risulta nulla in ascolto — il browser risponde
`ERR_CONNECTION_REFUSED` anche con i container `healthy`. La variante di prova
abbandona la rete host e **pubblica** le porte:

```bash
docker compose -f docker-compose.yml -f docker-compose.desktop.yml up -d --build
```

`start.ps1` e `start.sh` la scelgono da sé quando riconoscono Docker Desktop. Serve
a **provare l'interfaccia, non a scansionare**: dietro il NAT di Docker la sonda vede
la rete di Docker, non la LAN del cliente.

## Scelte di esercizio, e perché

**Un solo worker Gunicorn, in entrambi.** Non è una scelta di prestazioni: nel
processo del server vivono i servizi di fondo (spedizione notifiche, resoconto
quotidiano, valutatore delle regole, sorveglianza termini ACN e sonde bloccate,
rilevazione SIEM) e nel processo della sonda vive l'agente di scansione. Ognuno deve
esistere **una volta sola**: con due worker si spedirebbero due volte le notifiche,
si aprirebbero due volte gli stessi allarmi e due agenti scansionerebbero la stessa
rete. La concorrenza si ottiene con i thread (`--threads`).

**La sonda in rete host.** Una sonda dietro il NAT di Docker vedrebbe la rete di
Docker, non quella del cliente: scoprirebbe se stessa e nient'altro. Con
`network_mode: host` vede le interfacce reali. Funziona su **Linux**; su Docker
Desktop (Windows/Mac) la rete host è limitata e la sonda non vedrebbe la LAN.

**Socket raw senza root.** La scansione SYN (`-sS`) e il rilevamento del sistema
operativo (`-O`) richiedono `CAP_NET_RAW`/`CAP_NET_ADMIN`. Si concedono **solo quelle
due** (`cap_drop: ALL` + `cap_add`), mai `privileged: true`, e nell'immagine si scrive
la capacità **sul file** di nmap (`setcap`): senza quel passaggio un processo non-root
non potrebbe usarla e nmap ripiegherebbe in silenzio sulla scansione TCP connect.

**Anti-spoofing dell'indirizzo del client.** nginx **scrive**
`X-Forwarded-For: $remote_addr`, non lo accoda con `$proxy_add_x_forwarded_for`.
Accodando, un client potrebbe inviare `X-Forwarded-For: 127.0.0.1` e ottenere il
privilegio dell'accesso locale — che sulla sonda vale la scelta della password. Lato
applicazione, `ProxyFix` si fida di **un solo** salto.

**Nessun dato nelle immagini.** `.dockerignore` tiene fuori `server/data`
(551 MB di archivio reale), `probe/data`, i log, i `.env`, i certificati e le chiavi.
I dati vivono nei volumi: l'aggiornamento dell'immagine non se li porta via.

**La chiave di sessione è obbligatoria.** Se manca, l'applicazione se ne genererebbe
una dentro l'immagine e **ogni ricreazione del container invaliderebbe tutte le
sessioni**. Il compose si rifiuta di partire senza.

## PostgreSQL: stato reale

Il servizio PostgreSQL è **provisionato e pronto**, a norma dei requisiti:

- immagine ufficiale con versione bloccata (`postgres:16.4-alpine`);
- volume dedicato, `--data-checksums`, healthcheck;
- **porta non pubblicata**: la base dati parla solo con l'applicazione sulla rete
  interna;
- **utente applicativo a privilegi minimi** creato all'inizializzazione
  (`initdb/10-utente-applicativo.sh`): può solo leggere e scrivere i dati, non creare
  né cancellare oggetti; il proprietario è un utente distinto e serve alle migrazioni;
- copie con `pg_dump` e retention configurabile (`backup-postgres.sh`), da schedulare
  sull'host.

**Ma l'applicazione non lo usa ancora.** Oggi il livello dati del server usa
`sqlite3` diretto e scrive su SQLite nel volume `/data`. Portarlo su PostgreSQL è un
lavoro a parte, non un'opzione di configurazione, perché:

| Ostacolo | Quantità |
|---|---|
| Punti SQL raw (`query`/`execute`/`scalar`) con placeholder `?` | ~704 |
| Migrazioni basate su `PRAGMA table_info` | 14 |
| `ORDER BY inet(...)` — funzione **registrata a mano** sulla connessione SQLite | 12 |
| `COLLATE NOCASE` (non esiste in PostgreSQL) | 4 |
| `AUTOINCREMENT` nello schema | 36 |

Il percorso di porting, quando si decide di farlo:

1. astrarre il dialetto (o passare a SQLAlchemy come prescrive lo stack) e convertire
   i placeholder;
2. riscrivere `schema.sql` in forma portabile e sostituire le migrazioni `PRAGMA` con
   **Alembic**;
3. sostituire `inet()` con una funzione lato database (o un ordinamento su colonna
   normalizzata) e `COLLATE NOCASE` con `citext`/`lower()`;
4. configurare il pool (`pool_pre_ping=True`, `pool_recycle`);
5. eseguire la suite su **entrambi** i database, come richiede la regola di
   compatibilità SQLite ↔ PostgreSQL.

Fino ad allora il container PostgreSQL resta acceso e vuoto: costa poco e rende il
passaggio una migrazione di dati, non un cambio di architettura in esercizio.
