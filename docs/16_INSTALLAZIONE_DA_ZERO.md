# snap — Installazione e avvio da zero

> Documento operativo. Porta da macchine vuote a un sistema che scansiona: console,
> sonda, perimetro e agenti. Ogni passo ha una **verifica**: se la verifica non dà il
> risultato indicato, non si prosegue — si risolve, e il capitolo 11 raccoglie i guasti
> che si incontrano davvero, con la causa misurata.

| | |
|---|---|
| Prodotto | snap — Secure Network Assessment Platform |
| Versione documentata | console 2.0.6, sonda 1.5.0, agente 1.2.6 |
| Conformità documentale | ISO/IEC/IEEE 29148:2018 (§ scopo, riferimenti, istruzioni) |
| Destinatari | chi installa il sistema e chi lo assiste |

---

## 1. Che cosa si sta installando

**Tre** componenti, che si parlano in **una sola direzione**. I primi due sono necessari; il terzo è facoltativo e si aggiunge dopo.

| Componente | Dove va | Che cosa fa |
|---|---|---|
| **Console** (server) | sulla rete di gestione | raccoglie l'inventario, lo presenta, invia notifiche e report |
| **Sonda** (probe) | dentro la rete da esaminare | esegue le scansioni e **conferisce** i risultati alla console |
| **Agente** (facoltativo) | sulle macchine da sorvegliare da dentro | riferisce alla sonda ciò che dalla rete non si vede: accessi falliti, utenze nuove, protezioni disattivate, processi in ascolto, dischi che finiscono (capitolo 9) |

**La console non raggiunge mai la sonda.** È la sonda che apre la comunicazione, ogni
quindici secondi, e nella risposta riceve configurazione e comandi. È una scelta di
progetto: nella rete di un cliente non si apre un canale in ingresso.

La stessa regola vale un piano più sotto: **l'agente apre lui** verso la sonda, e la
sonda non lo chiama mai. Chi sta più in basso apre verso chi sta più in alto, e
nessuno dei tre chiama indietro: una macchina in rete di utenza non deve essere
raggiungibile da nessuno, nemmeno dal prodotto che la sorveglia.

**Su quante macchine.** Da una a tre, e la scelta è di chi installa:

| Disposizione | Quando |
|---|---|
| console e sonda sulla **stessa** macchina | impianto piccolo, o collaudo — purché quella macchina stia **dentro** la rete da esaminare (capitolo 6) |
| console e sonda **separate** | l'esercizio normale: la console in rete di gestione, la sonda dentro la rete del cliente |
| più sonde per una console | reti separate, o sedi diverse dello stesso cliente |

L'agente sta invece **sulle macchine da sorvegliare**, una copia per macchina, e non
sostituisce nulla di quanto sopra.

Conseguenza pratica da conoscere subito: i comandi dalla console arrivano alla sonda
**entro un minuto**, non istantaneamente, e la console mostra l'ultima *istantanea*
consegnata, non lo stato dal vivo. Entrambe le cose sono dichiarate nelle pagine.

---

## 2. Prerequisiti

| Requisito | Serve a | Se manca |
|---|---|---|
| **Docker** con Compose v2 | console e basi dati | niente si avvia |
| **Python ≥ 3.12** | sonda fuori dal contenitore (Windows) | solo per quella variante |
| **nmap** ≥ 7.80 | la sonda: è lo strumento che esamina la rete | nessuna scansione; l'interfaccia lo dichiara |
| **Npcap** (solo Windows) | socket raw: scansione SYN e rilevamento del sistema operativo | la sonda ricade sulla scansione per connessione, più lenta e senza sistema operativo |
| **Certificato TLS** per la console | la console non parla in chiaro | il proxy non parte |
| Porte **5500‑5600** libere | vincolo di progetto sulle porte | conflitto all'avvio |

### 2.1 Dove va la sonda: la decisione che conta

| Situazione | Variante da usare |
|---|---|
| Sonda su **Linux** | contenitore, `network_mode: host` — l'esercizio normale |
| Sonda su **Windows/Mac con Docker Desktop** | **fuori dal contenitore** (`start-nativa.ps1`) |

Non è una preferenza. Su Docker Desktop i contenitori non stanno sull'host ma dentro una
macchina virtuale, e il NAT di quella macchina **risponde per ogni indirizzo**. Misurato
sulla stessa subnet nello stesso momento:

```
dal PC                 nmap -sn 10.10.60.0/24  ->    5 host attivi
dentro il contenitore  nmap -sn 10.10.60.0/24  ->  256 host attivi su 256
```

Una sonda in quelle condizioni non fa inventario: lo **inventa** — 251 nodi inesistenti,
con porte e classificazioni che sembrano lavoro fatto. Il prodotto oggi se ne accorge e
rifiuta la scoperta, ma il rifiuto è un allarme, non una soluzione.

---

## 3. La console

### 3.1 Configurazione

```
cd docker/server
cp .env.example .env
```

Nel file `.env` vanno compilate **cinque** voci; le altre hanno un valore predefinito.

| Voce | Che cos'è |
|---|---|
| `SNAP_SERVER_SECRET_KEY` | chiave delle sessioni. Casuale, lunga, mai riusata |
| `POSTGRES_PASSWORD` | password del **proprietario** della base dati: crea e migra lo schema |
| `SNAP_PG_APP_PASSWORD` | password dell'utenza **applicativa**: legge e scrive i dati, non cambia la struttura |
| `SNAP_HTTPS_PORT` | porta pubblica della console (predefinita `443`) |
| `SNAP_SYSLOG_PORT` | porta del collettore syslog, se si usa il SIEM (predefinita `514`) |

Le due utenze di base dati sono distinte per **minimo privilegio**: l'applicazione non
deve poter alterare lo schema. Una chiave di sessione si genera così:

```
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

### 3.2 Certificato

```
mkdir certs
openssl req -x509 -newkey rsa:4096 -sha256 -days 730 -nodes \
  -keyout certs/server.key -out certs/server.crt \
  -subj "/CN=snap.example.local" \
  -addext "subjectAltName=DNS:snap.example.local,IP:10.20.10.42"
```

**Il `subjectAltName` deve contenere l'indirizzo con cui si aprirà la console.** I
browser ignorano il `CN` da anni: senza il SAN giusto la console risulta «Non sicura»
anche con il certificato installato — e in quello stato **Chrome ed Edge rifiutano di
offrire il salvataggio delle credenziali**.

Se il certificato è autofirmato, per togliere l'avviso va reso attendibile sulle
postazioni:

```powershell
Import-Certificate -FilePath "docker\server\certs\server.crt" `
                   -CertStoreLocation Cert:\LocalMachine\Root
```

### 3.3 Avvio

```
.\start.ps1          # Windows
./start.sh           # Linux
```

Lo script verifica i presupposti, costruisce l'immagine e avvia i tre servizi:
`snap-postgres`, `snap-server`, `snap-proxy`.

**Verifica.** Tutti e tre devono risultare `healthy`:

```
docker ps --format "{{.Names}}\t{{.Status}}"
```

e la console deve rispondere in HTTPS:

```
curl -k -o /dev/null -w "%{http_code}\n" https://<indirizzo>/
```

Un `302` è l'esito atteso: è il rimando alla pagina di accesso.

### 3.4 Primo accesso

Le credenziali iniziali sono nel `.env` (`SNAP_BOOTSTRAP_ADMIN_*`). Al primo accesso la
console chiede di **cambiare la password**.

Poi, in *Amministrazione → Impostazioni*:

- **Indirizzo pubblico della console** (`public_url`): è quello che le sonde useranno per
  registrarsi e che finisce nei collegamenti dei messaggi. Se la console è in HTTPS deve
  iniziare per `https://`.
- **Canali di recapito**: server di posta e, se si usa, il bot Telegram. Senza posta
  configurata le notifiche restano in coda e i pulsanti che spediscono lo dichiarano.

---

## 4. La sonda in contenitore (Linux)

```
cd docker/probe
cp .env.example .env
```

Da compilare: `SNAP_PROBE_SECRET_KEY`, `PROBE_POSTGRES_PASSWORD`,
`PROBE_PG_APP_PASSWORD`. Poi il certificato in `./certs/probe.crt` e `probe.key`, con le
stesse regole del capitolo 3.2.

Se la console ha un certificato proprio, va messo il suo certificato (**mai** la chiave
privata) in `./trust/` e dichiarato:

```
SNAP_PROBE_SERVER_CA=/etc/snap/trust/server-ca.crt
```

Senza, la sonda **rifiuta** di parlare con la console — ed è il comportamento giusto: su
quel canale passano le chiavi della registrazione e l'inventario della rete. Non esiste
un interruttore per disattivare la verifica.

```
docker compose up -d --build
```

**Verifica.** `snap-probe`, `snap-probe-proxy` e `snap-probe-postgres` `healthy`, e
l'interfaccia della sonda che risponde su `https://127.0.0.1:5510` **dalla macchina della
sonda**.

---

## 5. La sonda fuori dal contenitore (Windows)

La base dati resta in contenitore; la sonda gira sulla macchina, dove vede le interfacce
vere. Il TLS **resta davanti**: la sonda ascolta in chiaro solo sul proprio loopback e un
nginx in contenitore termina il TLS sulla 5510.

```
rete  --HTTPS-->  proxy-nativa (contenitore)  --loopback-->  sonda:5511
```

### 5.1 Avvio

```powershell
cd docker\probe
copy .env.example .env      # e compilare come al capitolo 4
docker compose -f docker-compose.yml -f docker-compose.nativa.yml up -d postgres proxy-nativa
.\start-nativa.ps1
```

`start-nativa.ps1` verifica i presupposti prima di avviare: file di configurazione,
nessuna sonda in contenitore già attiva, base dati raggiungibile, nmap nel PATH, proxy
TLS in esecuzione, ancora di fiducia verso la console.

Così la sonda resta legata alla finestra: chiuderla la ferma. Per **avviarla senza
finestra**, come si conviene a un servizio:

```powershell
.\start-nativa.ps1 -Nascosta
```

Lo script si rilancia in un processo nascosto e restituisce subito il prompt. Il diario
finisce in `probe\sonda-nativa.log` (e gli errori in `.log.err`), e si sovrascrive a
ogni avvio: è il diario della sessione corrente, non un archivio -- lo storico sta
nell'interfaccia della sonda.

Senza finestra non c'è più un Ctrl+C da premere, e per fermarla c'è un comando:

```powershell
.\stop-nativa.ps1                    # ferma agente e interfaccia
.\stop-nativa.ps1 -ConIContenitori   # ferma anche proxy TLS e archivio
```

`stop-nativa.ps1` ferma **prima l'agente, poi l'interfaccia**: all'inverso resterebbe un
agente che continua a prenotare bersagli senza che nessuno possa vedere che cosa sta
facendo.

Per sapere che cosa fermare guarda due cose, in quest'ordine:

1. il **registro dei processi** `probe\sonda-nativa.pid`, che l'avvio scrive con i PID
   che ha creato;
2. la **riga di comando**, come rete di sicurezza per ciò che è stato avviato a mano.

Il registro non è un vezzo: su Windows la riga di comando di un processo non è sempre
leggibile — basta che appartenga a una sessione chiusa — e un arresto che cercasse solo
lì lascerebbe in vita un agente vecchio. Due agenti sullo stesso archivio si contendono
le prenotazioni dei bersagli, ed è il guasto che l'avvio verifica.

Alla fine lo script **controlla** che i processi siano davvero spariti e, se qualcuno è
sopravvissuto, lo dice con il suo PID: succede quando il processo appartiene a una
sessione chiusa, e in quel caso va fermato da una finestra **amministratore**

```powershell
Stop-Process -Id <i PID elencati> -Force
```

prima di riavviare, o si avranno due agenti sullo stesso archivio.

> **Privilegi.** Aperta come utente normale, la sonda non può usare la scansione SYN
> (`-sS`) né il rilevamento del sistema operativo (`-O`): ricade sulla scansione per
> connessione, più lenta e senza sistema operativo, e lo dichiara nella propria pagina
> di stato. Per l'inventario completo va aperta **come amministratore**.

> **Non avviare mai anche `snap-probe`.** Due sonde sullo stesso archivio si contendono
> le prenotazioni dei bersagli e lo stato dei nodi diventa incoerente. Lo script lo
> verifica e si ferma.

### 5.2 La prima password

L'interfaccia della sonda è protetta da **una sola password**, scelta alla prima
apertura, e si sceglie **dalla postazione della sonda**: dalla rete la scelta iniziale è
rifiutata, così la sonda appartiene a chi l'ha installata e non al primo che la trova.

Fuori dal contenitore c'è un passaggio in più, e va fatto una volta sola:

```powershell
.\start-nativa.ps1 -PrimaPassword
```

Poi si apre `http://127.0.0.1:5511/primo-accesso` **da quella macchina**, si sceglie la
password, si ferma e si riavvia in modo normale. Senza quell'interruttore il cookie di
sessione è marcato `Secure`, non viene rimandato su HTTP e la pagina risponde «il token
di sicurezza è scaduto» a ogni tentativo.

### 5.3 Interfaccia di uscita delle scansioni

Su una macchina con più interfacce, nmap sceglie dalla tabella di instradamento del
sistema — e la tabella può essere sbagliata. Misurato su un'installazione reale:

```
0.0.0.0/0  metrica 40  gateway 10.10.60.1   <- Wi-Fi SPENTO, senza indirizzo
0.0.0.0/0  metrica 55  gateway 10.20.10.1   <- la LAN vera, attiva
```

La rotta migliore era quella di un'interfaccia spenta: le scansioni uscivano da lì, e
l'esito era incoerente senza che nulla lo dicesse. Si dichiara in `.env`:

```
SNAP_PROBE_SCAN_INTERFACE=eth7          # il nome che usa nmap: nmap --iflist
SNAP_PROBE_SCAN_SOURCE_IP=10.20.10.42
```

Vale con i socket raw. Senza di essi la scansione passa dallo stack del sistema e **torna
a subire la rotta sbagliata**: là il difetto va corretto nella tabella di instradamento
della macchina, non nel prodotto.

---

## 6. Sonda e console sulla stessa macchina

Si può, ed è la disposizione normale di un impianto piccolo o di un collaudo. Non è una
variante a sé: è il capitolo 4 (o il 5) eseguito sulla stessa macchina del capitolo 3.
Quello che cambia sono **tre cose che si scontrano**, e vanno sistemate prima, non dopo.

### 6.1 Le tre collisioni

| Cosa si scontra | Perché | Come si risolve |
|---|---|---|
| **Le porte** | console e sonda pubblicano entrambe un'interfaccia in HTTPS | la console sta sulla 443, la sonda sulla 5510: già distinte di serie, **non toccarle** |
| **Le basi dati** | due PostgreSQL, due volumi, due porte | `snap-postgres` (server) e `snap-probe-postgres` (sonda) sono due servizi con nomi e volumi diversi: nessun intervento |
| **Il nome dei container** | i due `docker-compose.yml` girano in due cartelle | Compose antepone il nome della cartella (`server_`, `probe_`): nessun intervento |

Il riepilogo delle porte in uso sta in `PORTS.md`, ed è la prima cosa da guardare se
qualcosa non parte.

### 6.2 L'indirizzo con cui la sonda chiama la console

È l'unico punto in cui la convivenza richiede una decisione. La sonda deve raggiungere
la console, e **`localhost` non va**: la sonda gira in un container, e per lei
`localhost` è il container stesso.

| Sonda | Indirizzo da mettere in `server_url` |
|---|---|
| in contenitore, `network_mode: host` | l'indirizzo della macchina (`https://10.20.10.42/`) |
| in contenitore, rete propria | `https://host.docker.internal/` oppure l'indirizzo della macchina |
| fuori dal contenitore (Windows) | l'indirizzo della macchina, **non** `https://localhost/` |

In tutti e tre i casi vale la regola del capitolo 3.2: quell'indirizzo deve stare nel
`subjectAltName` del certificato della console, altrimenti la sonda rifiuta il canale —
e fa bene.

### 6.3 Quello che la convivenza NON cambia

La direzione delle connessioni resta quella: **è sempre la sonda che chiama la console**,
anche se sono a dieci centimetri l'una dall'altra. Non esiste una scorciatoia locale, e
non è una svista: il giorno in cui la sonda viene spostata nella rete del cliente, tutto
continua a funzionare senza riconfigurare niente.

### 6.4 Quando invece NON conviene

Se la macchina della console non sta **dentro** la rete da esaminare, la sonda lì non
vede quella rete: vede la rete di gestione. Non è un difetto di configurazione, è la
geografia — e nessun parametro lo corregge. In quel caso la sonda va dove sta la rete,
e la console resta dov'è.

**Verifica.** `docker ps` mostra sei servizi `healthy` (tre della console, tre della
sonda), la console risponde sulla 443 e la sonda sulla 5510, e le due interfacce
dichiarano due versioni distinte in fondo alla pagina.

---

## 7. Registrare la sonda

1. Sulla console: *Sonde → Registra sonda*. Si ottiene un **pacchetto** `SNAP1-…`.
2. Sull'interfaccia della sonda: *Registrazione*, si incolla il pacchetto.
3. La sonda scambia le chiavi, riceve la configurazione e compare in *Sonde → Flotta
   sonde* come **attiva**.

**Verifica.** Nella flotta la sonda risulta attiva e il battito è recente. Dal bottone
arancione si apre la sua **console remota**: mostra quello che si vedrebbe stando davanti
alla sonda, compreso il diario locale.

---

## 8. Il perimetro

Senza perimetro la sonda non ha bersagli: resta attiva e non scansiona nulla.

*Rete → Perimetro → Importa*: un file di testo con una subnet per riga
(`10.20.10.0/24 Sede centrale`). Il perimetro è **dichiarato sulla console** e consegnato
alla sonda nella configurazione cifrata: la sonda rifiuta qualunque bersaglio che non vi
sia contenuto.

Per ogni subnet si dichiarano poi:

- **Zona di rete** — il contesto che decide se un'esposizione è un problema. Vuota vale
  come rete di utenza, cioè il giudizio più severo: il silenzio non deve valere come
  giustificazione.
- **Senza fili** — non è un'etichetta: cambia il modo in cui la sonda osserva quella
  rete. Su Wi-Fi un apparato resta agganciato minuti, e una passata ogni tre giorni non
  lo vede mai; con l'interruttore attivo la sonda fa una ricognizione ogni due minuti.

**Verifica.** Entro pochi minuti *Rete → Dispositivi* comincia a popolarsi, e il diario
della sonda mostra le fasi (`discovery`, `raffica`, `ports`, `services`…).

---

## 9. L'agente sulle macchine

Facoltativo, e da fare **dopo** che la sonda scansiona e conferisce: l'agente aggiunge
una vista, non la sostituisce. Va installato dove serve davvero — server, macchine
critiche, postazioni sensibili — non ovunque per abitudine.

### 9.1 Che cosa aggiunge, e perché non basta la scansione

| Dalla rete si vede | Dall'interno si vede |
|---|---|
| che la 3389 è aperta | **chi** ha provato ad entrare e ha sbagliato la password |
| che la macchina risponde | che il disco è al 97% e fra due giorni si ferma |
| che c'è un web server | che l'antivirus è stato disattivato ieri |
| nulla degli utenti | che stanotte è comparsa un'utenza locale nuova |

Sono le cose che una scansione non può vedere per costruzione, non per limite
dell'implementazione.

### 9.2 Il pacchetto: un token, una macchina

Sulla **console della sonda**, pagina *Agenti*:

1. si scrive a che cosa serve il token (finisce nel diario: serve a sapere, fra sei
   mesi, perché quella macchina è stata registrata);
2. si sceglie **Scarica il pacchetto**;
3. si ottiene uno zip di circa 46 kB, `snap-agente-<sonda>-<data>.zip`.

**Il pacchetto è una credenziale.** Dentro c'è un token che vale **un'ora e una volta
sola**, e gli installatori lo cancellano dalla macchina appena speso. Si trasmette come
si trasmette una password, non su una cartella condivisa.

**Un pacchetto per macchina.** Il token si consuma alla prima registrazione: la seconda
macchina che prova riceve un rifiuto. È voluto — una credenziale condivisa fra venti
macchine non si può revocare per una sola.

### 9.3 Installare

Si copia lo zip sulla macchina, si apre, e si esegue **un comando solo**.

| Sistema | Comando |
|---|---|
| **Windows** | PowerShell **come amministratore**: `.\installa.ps1` |
| **Linux** | `sudo ./installa.sh` |
| **Docker** (solo Linux) | `cp docker/.env.example docker/.env`, compilare, poi `docker compose -f docker/docker-compose.yml up -d --build` |

L'installatore crea l'utenza di servizio, installa la dipendenza (`psutil`), registra
l'agente con il token, avvia il servizio, **verifica che stia girando davvero** e solo
allora scrive `FATTO`. Se il servizio non è partito non lo scrive: un installatore che
dichiara successo senza controllare è il modo in cui si scoprono venti agenti spenti
sei mesi dopo.

Su Linux l'agente gira con un'**utenza dedicata**, non come root. Serve root per la
postura di sicurezza e per l'elenco dei pacchetti: chi lo vuole lo chiede
esplicitamente con `sudo ./installa.sh --privilegi-completi`. Quello che non può
leggere viene **dichiarato non misurato**, non riportato come zero.

### 9.4 Guardare prima di mandare

```
python snap_agent.py prova --riassunto
```

Stampa il messaggio vero che partirebbe, gruppo per gruppo, con quanto pesa — **senza
mandare niente**. È il modo di rispondere alla domanda «che cosa esce da questa
macchina?» prima che esca, e non dopo.

### 9.5 Scegliere che cosa inviare

```
python snap_agent.py configura
```

Mostra i **quindici gruppi** con quello che mandano, ogni quanto, e se riguardano le
persone; si accendono e si spengono per numero. Senza domande:

```
python snap_agent.py configura --gruppi minimo
python snap_agent.py configura --gruppi identita,carico,dischi,sicurezza
```

| Preselezione | Che cosa accende |
|---|---|
| `tutti` | tutto quello che l'agente sa raccogliere (predefinito) |
| `consigliato` | tutto tranne l'inventario del software e le attività pianificate |
| `minimo` | identità, carico, dischi, rete: **nulla che riguardi le persone** |

I gruppi spenti vengono **dichiarati** alla sonda: la console scrive «non misurato», non
zero. È la differenza fra «questa macchina non ha antivirus» e «a questa macchina non
l'ho chiesto».

Nomi utente e sessioni sono **dati personali** (GDPR art. 4): la base giuridica è la
sicurezza della rete (art. 6(1)(f)), il trattamento va nel registro dei trattamenti, e
le pagine della console nominano **macchine e utenze, non persone**.

### 9.6 L'agente non ha una pagina web, ed è voluto

Non c'è un indirizzo da aprire sulla macchina sorvegliata: l'agente **non apre porte**,
non installa servizi in ascolto, non accetta connessioni e non riceve comandi. La sua
«interfaccia minima» è il comando `configura`, sulla macchina stessa.

Lo si governa da due posti:

| Dove | Che cosa si vede |
|---|---|
| Console della **sonda**, *Agenti* | le macchine registrate, l'ultimo invio, la revoca |
| Console del **server**, *IDS → Agenti di macchina* | le stesse macchine con misure, inventario e rilevazioni |

### 9.7 Due ritmi, e perché

- le **misure** ogni minuto — carico, dischi, ritmo di rete, processi, sessioni: pochi
  kB, è quello che si guarda su un grafico;
- l'**inventario** una volta all'ora o appena cambia qualcosa — software, servizi,
  utenze, postura, porte in ascolto: è uno *stato*, e rispedirlo ogni minuto costerebbe
  **99 MB al giorno** per non dire niente di nuovo. Separandoli: **7,6 MB al giorno**.

### 9.8 Verifica

| Controllo | Esito atteso |
|---|---|
| `https://<sonda>:5510/api/agent/ping` | `{"protocollo": "SNAP-AGENT/1", "pronto": true}` |
| Console della sonda, *Agenti* | la macchina compare **attiva**, con un invio recente |
| Console del server, *IDS → Agenti di macchina* | la stessa macchina, con CPU, memoria e dischi |

Se la macchina compare sulla sonda ma non sul server, il problema non è l'agente: è il
conferimento della sonda, e si guarda in *Sonde → Console*.

**Una cosa da sapere prima di guardare le rilevazioni.** Le regole dell'IDS che si
fondano sull'assenza di memoria non scattano nelle prime **dodici ore** dalla prima
osservazione: il motore costruisce la linea di base e tace. La pagina lo dichiara in un
avviso. È voluto — un IDS che al primo avvio segnala l'intera rete viene disattivato il
giorno dopo.

### 9.9 Togliere l'agente

| Sistema | Comando |
|---|---|
| **Windows** | `.\disinstalla.ps1` (come amministratore) |
| **Linux** | `sudo ./disinstalla.sh` |
| **Docker** | `docker compose -f docker/docker-compose.yml down -v` |

La disinstallazione toglie servizio, file e configurazione dalla macchina. La
**registrazione sulla sonda resta**: si revoca dalla pagina *Agenti*, ed è una scelta
separata perché sono due cose diverse — una macchina spenta per manutenzione non deve
sparire dall'inventario.

---

## 10. Verifica finale

| Controllo | Esito atteso |
|---|---|
| `docker ps` | tutti i servizi `healthy` |
| Console in HTTPS | pagina di accesso, senza avviso di certificato |
| *Sonde → Flotta* | sonda attiva, battito di meno di un minuto fa |
| *Sonde → Console* | istantanea recente, diario che scorre |
| *Rete → Dispositivi* | nodi con porte, servizi e sistema operativo |
| Diario della sonda | fasi diverse nello stesso ciclo, non una sola ripetuta |
| Sonda, *Salute* | archivio misurato, scadenze delle fasi con un conto alla rovescia |
| Console, *Amministrazione → Impostazioni → Archivio* | occupazione per tabella, righe contate |
| *Agenti* sulla sonda (se installato) | la macchina attiva, con un invio recente |

**Un segnale da riconoscere subito**: una fase che finisce sistematicamente in pochi
secondi con **zero record** non è una fase veloce, è una fase che non ha funzionato. Il
diario dice quanti compiti sono partiti, non quanto dato hanno prodotto: i due numeri
vanno letti insieme.

### 10.1 Che cosa NON deve allarmare il primo giorno

Sono i quattro «zeri» che ogni installazione nuova mostra, e che non sono guasti:

| Si legge | Significa | Quando cambia |
|---|---|---|
| *Crescita al giorno: non ancora* | una crescita è una **differenza fra due misure**, e finora ce n'è una | dopo ventiquattro ore |
| *IDS: zero rilevazioni* | il motore sta costruendo la linea di base e tace di proposito | dopo dodici ore |
| *Fase scaduta* nella pagina Salute | è **in coda**, non è ferma | diventa un problema solo se resta scaduta mentre le altre avanzano |
| *Nodi in lavorazione* | il profilo si completa in più fasi | man mano che le fasi passano |

Nessuno dei quattro va «sistemato»: vanno riletti il giorno dopo. La regola del
prodotto è che uno zero misurato e uno zero non misurato non si scrivono allo stesso
modo — e in questi quattro casi la pagina dice quale dei due è.

---

## 11. Guasti che si incontrano davvero

| Sintomo | Causa | Rimedio |
|---|---|---|
| `400 Bad Request — The plain HTTP request was sent to HTTPS port` | si è aperto `http://` su una porta TLS (il browser lo assume su porte non standard) | dalla 1.5.0 il proxy rimanda da solo |
| Il browser non offre di **salvare la password** | la pagina ha un errore di certificato: in quello stato i browser lo rifiutano | rendere attendibile il certificato; SAN con l'indirizzo usato |
| `certificate verify failed: self-signed certificate` nella sonda | manca l'ancora di fiducia verso la console | certificato della console in `./trust/` (capitolo 4) |
| `conflicting options: custom host-to-IP mapping and the network mode` | `extra_hosts` insieme a `network_mode: service:` | risolto dalla 1.5.0: variabile `SONDA_HOST` |
| `Archivio non ancora pronto`, in ciclo | la base dati ascolta solo sul proprio loopback e la porta pubblicata non lo raggiunge | usare il compose della variante nativa |
| La subnet mostra **tutti** gli indirizzi attivi | sonda dietro il NAT di Docker Desktop | eseguire la sonda fuori dal contenitore (capitolo 5) |
| La sonda è attiva ma non scansiona | perimetro vuoto, subnet disattivate, o scansioni sospese | capitolo 8; la pagina *Perimetro* mostra il numero di subnet attive |
| Nodi «in lavorazione» fermi per ore | una fase monopolizza il ciclo | verificare nel diario che le fasi si alternino |
| L'agente riceve `403` alla registrazione | il token è scaduto (vale un'ora), è già stato usato, o è stato ricopiato male | emetterne un altro dalla pagina *Agenti* della sonda |
| L'agente riceve `401` a ogni invio | firma, marca temporale o nonce non accettati. Il rifiuto non dice quale: il motivo per esteso è nel **diario della sonda** | se dice «marca temporale fuori finestra», l'orologio della macchina è sfasato di più di cinque minuti: sincronizzarlo |
| La pagina *IDS* mostra zero rilevazioni | nelle prime dodici ore è l'esito atteso (memoria in apprendimento); dopo, si guarda **Regole e sensori** | un sensore non disponibile non produce rilevazioni, e il suo zero non è una buona notizia |

---

## 12. Riferimenti

| Documento | Contenuto |
|---|---|
| `PORTS.md` | quale porta a quale servizio, e perché |
| `docs/05_MANUALE_OPERATIVO.md` | uso quotidiano di console e sonda |
| `docs/14_MOTORE_DI_SCANSIONE.md` | come lavora la scansione, con le misure |
| `docs/09_REGOLE_CANALI_MANUTENZIONE.md` | notifiche, conservazione, copie |
| `docs/17_IDS_E_AGENTI.md` | IDS e agenti: decisioni, regole, casi d'uso commentati |
| Guida in applicazione (`/guida/`) | la stessa materia, dentro la console |
