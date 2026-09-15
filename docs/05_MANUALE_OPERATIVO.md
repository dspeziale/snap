<!--
  snap - Manuale di installazione ed esercizio.

  remarks: Autore: Daniele Speziale - Data: 2026-08-26
  copyright: (c) 2024-26 DS Consulting
  license: MIT
-->

# snap - Manuale operativo

| Voce | Valore |
|---|---|
| Sistema | snap - Secure Network Assessment Platform |
| Versione | 1.1.0 |
| Data | 2026-08-27 |
| Autore | Daniele Speziale |

---

## 1. Prerequisiti

| Elemento | Requisito |
|---|---|
| Interprete | Python 3.10 o superiore |
| Sistema operativo | Windows, Linux o macOS |
| Spazio su disco | 100 MB oltre alla crescita della base dati |
| Rete | La sonda deve raggiungere il server in uscita sulla porta scelta (5500-5600). Nessuna porta in ingresso e' richiesta sulla rete della sonda |

Dipendenze installate automaticamente: Flask, Flask-WTF, cryptography, pyotp,
qrcode, tzdata (server); Flask, Flask-WTF, cryptography, requests, tzdata
(sonda).

---

## 2. Installazione

### 2.1 Procedura assistita (consigliata)

Windows PowerShell:

```powershell
cd <cartella del progetto>
.\start.ps1 -Setup
```

Shell POSIX / Git Bash:

```bash
cd <cartella del progetto>
./start.sh setup
```

La procedura crea l'ambiente virtuale `.venv`, installa le dipendenze dei due
componenti e inizializza la base dati con i dati iniziali.

### 2.2 Procedura manuale

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate
# POSIX:    source .venv/bin/activate
pip install -r server/requirements.txt
pip install -r probe/requirements.txt
cd server && python run.py --init
```

### 2.3 Credenziali iniziali

| Utenza | Ruolo | Password iniziale |
|---|---|---|
| `admin@snap.local` | Amministratore di sistema | `Snap!Admin2026` |
| `admin@ised.local` | Amministratore tenant ISED | `Snap!Tenant2026` |
| `analista@ised.local` | Analista tenant ISED | `Snap!Tenant2026` |
| `audit@ised.local` | Consultazione tenant ISED | `Snap!Tenant2026` |

**Sostituire le password al primo accesso.** Le credenziali iniziali possono
essere modificate prima dell'inizializzazione con le variabili d'ambiente
`SNAP_SERVER_ADMIN_EMAIL` e `SNAP_SERVER_ADMIN_PASSWORD`.

---

## 3. Avvio

### 3.1 Avvio di entrambi i componenti

In PowerShell il prefisso `.\` e' obbligatorio: gli script della cartella
corrente non sono cercati nel `PATH`. Se l'esecuzione degli script e' disabilitata
sulla postazione, avviare con
`powershell -ExecutionPolicy Bypass -File .\start.ps1`.

```powershell
.\start.ps1                 # server su 5500, sonda su 5510 (solo locale)
.\start.ps1 -Only server
.\start.ps1 -Only probe
.\start.ps1 -ServerPort 5501 -ProbePort 5511
.\start.ps1 -ShowCommand    # mostra i comandi di avvio senza eseguirli
.\start.ps1 -Stop           # arresto
```

**Che cosa si vede.** Ogni componente apre una finestra propria, con il titolo che
riporta nome e porta, e vi scrive l'avvio e il diario in tempo reale. Lo stesso
diario resta su file in `logs\snap-server.log` e `logs\snap-probe.log`.

Difetto corretto: prima l'uscita dei componenti veniva deviata sui file, e le due
finestre che Windows apre per un processo di console restavano per costruzione
**vuote** -- facevano credere che il prodotto non fosse partito mentre era
regolarmente in ascolto. Ora l'uscita resta nella finestra e il file lo scrive
l'applicazione (`SNAP_SERVER_LOG_FILE`, `SNAP_PROBE_LOG_FILE`).

Se un componente non parte, la finestra **resta aperta** e mostra il motivo con il
codice di uscita; la finestra che ha lanciato l'avvio dichiara che la porta non e'
in ascolto. Chiudere la finestra di un componente lo arresta; `-Stop` arresta tutto.

### 3.1-bis Accesso dalla rete

Per difetto la console risponde **solo su questa postazione**. Per aprirla:

```powershell
.\start.ps1 -ServerHost 10.20.10.42                        # console dalla rete
.\start.ps1 -ServerHost 10.20.10.42 -ProbeHost 10.20.10.42 # anche l'interfaccia della sonda
```

Tre cose da sapere, che lo script ripete a ogni avvio:

1. **Il server ascolta su tutte le interfacce**, non solo su quell'indirizzo. Non e'
   una scorciatoia: legandosi al solo indirizzo di rete, `127.0.0.1` smetterebbe di
   rispondere e la sonda installata sulla stessa postazione -- che conferisce
   proprio su `127.0.0.1` -- resterebbe muta. Difetto misurato, non ipotizzato.
2. **Il canale e' HTTP, non HTTPS**: credenziali e contenuti attraversano la rete in
   chiaro. Ammissibile in una rete controllata per una dimostrazione; in esercizio
   il server va dietro un proxy inverso con TLS.
3. **Il firewall di Windows blocca l'ingresso** per difetto: se da un altro computer
   la pagina non si apre, la causa e' quella e non il prodotto. Lo script stampa il
   comando pronto (`New-NetFirewallRule ... -Profile Private,Domain`), da eseguire
   una volta come amministratore.

Dopo l'apertura conviene impostare l'**indirizzo pubblico** in *Amministrazione >
Impostazioni Sistema*: entra nei pacchetti di registrazione delle sonde e nelle
copertine dei report.

> **L'interfaccia della sonda e' protetta da password** (DEC-11), e la prima
> impostazione si fa dalla postazione della sonda: vedi il capitolo 6.0. Aperta con
> `-ProbeHost` restano due limiti -- il canale e' HTTP, quindi la password
> attraversa la rete in chiaro, e chi ha la password puo' riconfigurare la sonda e
> sospendere le scansioni. Conviene limitarla a un solo indirizzo di origine con
> `New-NetFirewallRule -RemoteAddress <indirizzo>`. Per richiuderla: `-Stop` e
> riavvio senza `-ProbeHost`.

```bash
./start.sh                  # entrambi in background
./start.sh server
./start.sh probe
./start.sh stop

# Indirizzo di ascolto: nella shell POSIX si usa la variabile d'ambiente, che i
# due applicativi leggono da se' (non serve un parametro dello script).
SNAP_SERVER_HOST=0.0.0.0 ./start.sh server
```

Nella shell POSIX i componenti vanno in secondo piano e il diario sta nei file di
`.snap-run/`: non ci sono finestre, quindi non si pone il problema descritto sopra.

### 3.2 Avvio diretto

```bash
cd server && python run.py --port 5500
cd probe  && python run.py --port 5510
```

### 3.3 Indirizzi

| Componente | Indirizzo |
|---|---|
| Console del server | `http://127.0.0.1:5500/` |
| Verifica del canale sonde | `http://127.0.0.1:5500/api/v1/ping` |
| Interfaccia locale della sonda | `http://127.0.0.1:5510/` |

Per rendere il server raggiungibile dalle sonde in rete: `.\start.ps1 -ServerHost
<indirizzo>` (oppure, in avvio diretto, `python run.py --host 0.0.0.0`) e impostare
l'indirizzo pubblico in *Impostazioni Sistema*. Vedi il capitolo 3.1-bis per il
firewall e per i limiti da conoscere.

---

## 4. Messa in servizio di una sonda

1. **Console del server** - *Sonde & Discovery > Registra sonda*: indicare codice
   (minuscolo, 3-32 caratteri), nome, sede e intervallo di raccolta.
2. Alla conferma il server mostra il **pacchetto di registrazione**
   `SNAP1-...`, visibile una sola volta: copiarlo.
3. **Interfaccia della sonda** - *Registra la sonda*: incollare il pacchetto e
   confermare. In alternativa si possono inserire manualmente URL, codice e token.
4. Verificare che la pagina di stato della sonda riporti *Canale attivo* e che
   nella console la sonda risulti *Attiva*.
5. Alla prima raccolta i dati compaiono nella dashboard del tenant.

### 4.1 Sostituzione di una registrazione esistente

Quando il server emette un nuovo pacchetto per una sonda gia' registrata (nuova
sonda, reinstallazione, cambio di tenant) **non occorre azzerare nulla**:

1. Sonda: voce **Registrazione** nel menu (oppure
   `http://<indirizzo-sonda>:5510/enroll`). La pagina mostra la registrazione in
   essere.
2. Incollare il nuovo pacchetto e spuntare
   **Sostituisci la registrazione attuale**.
3. Confermare. Le chiavi precedenti vengono sostituite; i dati in coda restano e
   verranno conferiti al nuovo tenant.

Se il pacchetto non e' valido o il server non risponde, la registrazione
precedente viene **ripristinata automaticamente**: la sonda resta operativa.

La sonda precedente rimane censita sul server: se non serve piu', eliminarla
dalla console (scheda della sonda).

Registrazione senza interfaccia grafica:

```bash
cd probe
python run.py --enroll "SNAP1-..."
python run.py --status
python run.py --headless
```

---

## 5. Uso della console del server

Il menu laterale e' organizzato in **gruppi collassabili**, uno per dominio. Il
gruppo che contiene la pagina in corso e' sempre aperto, qualunque cosa si sia chiuso
in precedenza: un menu che non dice dove si e' costringe a cercare. I gruppi chiusi a
mano restano chiusi anche cambiando pagina (preferenza della postazione, conservata
nel browser); un gruppo introdotto da una versione successiva compare aperto, perche'
si registra cio' che l'utente chiude e non cio' che apre.

| Gruppo | Contenuto |
|---|---|
| Dashboard | Il **quadro d'insieme**: incidenti da prendere in carico, quattro semafori di postura, i numeri di inventario, esposizione, vulnerabilita', certificati, vetusta', SMB e presenze, gli andamenti, lo stato della flotta e gli indicatori che ciascuno tiene sott'occhio |
| Sala operativa | **Quadro NOC** (che cosa non funziona adesso), **quadro SOC** (che cosa e' cambiato nella superficie esposta), **Ricerca** nella base dati con le domande gia' scritte. E' il primo gruppo perche' e' da li' che comincia il turno; specifica in `11_SALA_OPERATIVA.md` |
| Rete | Nodi, **mappa della rete** ad albero, stato della rete, cambiamenti, perimetro, dati conferiti dalle sonde. Pastiglia **verde** con i nodi in inventario |
| Controlli | Bersagli e controlli, incidenti, notifiche, regole di notifica. Pastiglia **blu** con i controlli attivi e, a gruppo chiuso, pastiglia rossa con gli incidenti aperti |
| IDS | **Rilevazioni** (che cosa e' cambiato in un modo che riguarda la sicurezza), **Regole e sensori** (che cosa si sa riconoscere e che cosa in questo momento nessuno sta osservando), **Agenti di macchina** (le macchine su cui e' installato l'agente, con le misure e gli eventi che riferiscono). Il motore gira sulla sonda: la console mostra cio' che le e' stato conferito (capitolo 5.9; specifica in `17_IDS_E_AGENTI.md`) |
| Sicurezza | Threat Intelligence e registro Audit & Eventi. Pastiglia rossa con i riscontri confermati, gialla con quelli aperti |
| Report e resoconti | Catalogo dei quattordici generi di report, archivio di quelli prodotti (scaricabili e eliminabili) e resoconto quotidiano |
| Sonde | Flotta sonde (stato, configurazione, comandi, revoca) e registrazione di una nuova sonda |
| Amministrazione | Tenant (solo amministratore di sistema), utenti, impostazioni e manutenzione |
| Guida operativa | Si apre in una finestra nuova: si consulta accanto a cio' che si sta facendo |

Alcune pagine hanno una struttura che vale la pena conoscere prima di aprirle:

- **Controlli**: in testa la sintesi (media, giorno peggiore, giorni misurati,
  esiti) e il grafico della disponibilita' per giorno locale. La percentuale delle
  ultime 24 ore dice come va adesso; il grafico dice se sta migliorando. La scala
  arriva sempre a 100 e parte da un gradino sotto al giorno peggiore, cosi' due mesi
  si confrontano; le fasce grigie sono i giorni senza esecuzioni, che restano un
  vuoto e non un punto a zero (RP-05). Il valore di un singolo giorno si legge col
  puntatore o, da tastiera, raggiungendo il grafico col tasto Tab e percorrendolo
  con le frecce.
- **Mappa della rete**: l'albero sonda &rarr; perimetro &rarr; dispositivo, fatto di
  blocchi apribili; si cerca con la ricerca del browser e si stampa.
- **Threat Intelligence**: schede che caricano una per volta, e i riscontri divisi per
  classe (confermate, da verificare, esposizioni), elencati **per dispositivo**.
- **Ricerca**: un campo che cerca in tutto cio' che il prodotto conosce, e sedici
  domande gia' scritte esportabili in CSV; l'esportazione resta nel registro.
- **Perimetro**: accanto a ogni subnet il selettore della **zona di rete**. E' la
  dichiarazione di che cos'e' quella porzione di rete, e cambia il modo in cui le
  esposizioni vengono giudicate (§ 5.4).
- **Zone di rete**: il catalogo del contesto. Si creano, si modificano e si
  eliminano le zone; per ciascuna si vede quante subnet e quanti dispositivi la
  riguardano (capitolo 5.4-bis).
- **Mappa della rete**: due letture della stessa rete -- per sonda e perimetro, e
  **per zona di rete** -- con le subnet non ancora descritte in evidenza.
- **Dispositivo**: la scheda *Interfacce web* dice come si presenta il pannello di
  gestione dell'apparato; il pulsante *JSON* mostra il dato grezzo, senza
  interpretazione (capitolo 5.6).
- **Dispositivi**: il comando *Riapplica ai dati raccolti* rifa' riconoscimento,
  correlazione e giudizio delle zone su cio' che e' gia' in archivio, senza avviare
  scansioni (capitolo 5.7).
- **Perimetro**: le subnet scelte si possono **rimuovere in blocco**; la conferma e'
  il numero delle subnet scelte, e i dispositivi gia' trovati restano in inventario.
- **Quadro NOC**: due schede da non confondere. *In silenzio* sono i dispositivi
  interrogati che non hanno risposto; *Non interrogati* sono quelli che la
  sorveglianza non ha ancora raggiunto -- non hanno un guasto, manca la copertura.

Le pastiglie dei gruppi non sono decorazione: un gruppo chiuso nasconde le proprie
voci e con esse la notizia che c'e' qualcosa da guardare. Quella degli incidenti
compare sul gruppo quando e' chiuso e sulla voce quando e' aperto, cosi'
l'informazione non sparisce ne' si ripete.

I contenuti conferiti dalle sonde sono, in questa versione, annotazioni
diagnostiche sul loro funzionamento: confluiscono nel registro *Audit & Eventi*
del tenant e alimentano gli indicatori della dashboard.

### 5.0 La dashboard: che cosa dice, e come si legge

La dashboard risponde a una domanda sola: **che cosa sappiamo di questa rete, e che
cosa ci dice**. Non descrive il prodotto (quello lo fa la relazione sulla flotta):
descrive il parco, e mette su una pagina numeri che altrimenti stanno in otto pagine
diverse.

Si legge dall'alto in basso, e l'ordine non e' estetico:

| Fascia | Che cosa contiene | Perche' sta li' |
|---|---|---|
| Incidenti aperti | I controlli che stanno fallendo adesso | E' l'unica cosa della pagina che chiede un intervento *oggi*: viene prima di qualunque numero |
| Quattro semafori | Raccolta, copertura, vulnerabilita', certificati | Ciascuno porta il **perche'** accanto al colore: un semaforo senza la sua ragione e' un colore, si guarda ma non si usa |
| Dodici numeri | Dispositivi, identificati, porte, amministrazione esposta, vulnerabilita' gravi, certificati in scadenza, vetusta', presenze, SMB, cambiamenti, reti, record | Ognuno e' cliccabile e porta all'elenco da cui viene: un indicatore da cui non si puo' scendere e' una curiosita' |
| Quattro andamenti | Record conferiti, apparati senza fili, cambiamenti, dispositivi nuovi | Dicono se cio' che si vede sopra sta crescendo o calando |
| Controlli e disponibilita' | Riuscita dei controlli, esiti non superati, incidenti aperti per giorno | E' l'unica parte della pagina che parla di SERVIZI invece che di apparati: dice se cio' che deve rispondere sta rispondendo. La riuscita si disegna su una scala 0-100, altrimenti una serie fra 98 e 100 sembrerebbe una montagna russa |
| Sezioni per area | Vulnerabilita', esposizione, igiene del parco, strumento | Il dettaglio, per chi al numero non si ferma |
| I tuoi indicatori | Gli undici riquadri personalizzabili | La scelta e' di chi la compie, e resta sul suo utente |

**La regola che governa tutta la pagina**: zero e "non misurato" non sono la stessa
cosa. Un conteggio a zero perche' nessuno ha ancora guardato si legge come "nessun
problema", ed e' il modo in cui una dashboard mente senza dire una parola falsa. Dove
una fonte non ha prodotto nulla la pagina lo scrive -- *"nessuna correlazione
eseguita: non e' un parco senza vulnerabilita', e' un parco che non e' stato
confrontato con i cataloghi"* -- invece di mostrare uno zero rassicurante.

### 5.0.1 Quattro casi, come si presentano davvero

**Caso 1 -- Il semaforo della raccolta e' rosso.**
Si legge *"nessun conferimento nelle ultime 24 ore: i numeri qui sotto sono vecchi"*.
Prima di guardare qualunque altra cosa: la sonda e' in contatto? Si va in *Sonde* e si
guarda l'ultimo battito. Le cause piu' frequenti, in ordine di probabilita': la sonda
e' ferma (riavviarla), le scansioni sono sospese (riquadro *Flotta e raccolta*, riga
"Scansioni sospese"), il canale verso la console non si apre (diario della sonda). Fino
ad allora ogni numero della pagina descrive ieri.

**Caso 2 -- "2 reti mai guardate" nel semaforo della copertura.**
Sono subnet dichiarate nel perimetro e attive, che nessuna passata ha mai preso come
bersaglio. Non producono righe da nessuna parte: in ogni altro elenco la loro assenza
si legge come "niente da segnalare" invece che come "non guardato". Si aprono da
*Rete > Perimetro*, e le cause sono due: nessuna sonda le raggiunge (manca una rotta:
lo dice il diario della sonda, con il messaggio sui bersagli senza rotta), oppure la
scoperta non e' ancora arrivata al loro turno -- il perimetro si ricensisce ogni tre
giorni, valore configurabile sulla singola sonda.

**Caso 3 -- "129 gia' scaduti" sotto i certificati.**
Un certificato scaduto non e' un rischio teorico: e' un servizio che smette di
funzionare a una data nota. Dal numero si scende all'elenco (*Rete > Certificati TLS*),
si filtra per scadenza e si manda la comunicazione a chi rinnova, dalla stessa pagina:
il messaggio porta il certificato per intero -- soggetto e emittente in DN completo,
validita', numero di serie, algoritmo di firma, chiave, impronte, nomi alternativi --
perche' chi lo rinnova deve poterlo rifare senza aprire la console.

**Caso 5 -- "Riuscita controlli 24h: 92%".**
La percentuale da sola non dice dove guardare: novantadue su cento puo' essere un
bersaglio sempre rotto fra dieci sani, oppure dieci bersagli che sbandano insieme. Si
guarda l'andamento *Esiti non superati* accanto: se i fallimenti sono concentrati in
una fascia oraria, la causa e' quasi sempre una finestra di manutenzione o un lavoro
programmato; se sono distribuiti, e' il bersaglio. Da li' si scende a *Controlli >
Incidenti* per vedere chi ha gia' preso in carico che cosa.

**Caso 4 -- Una fase di scansione al 5%.**
Nella sezione *Le fasi di scansione* la percentuale e' la quota di passate che hanno
visto **almeno un host**. Un valore basso su una fase sola indica bersagli che non
rispondono (rete spenta, filtro in mezzo); basso su tutte indica un problema di
raggiungibilita' generale. Attenzione a non leggere quello che non c'e': per `monitor`,
`deep` e `os` la percentuale **non compare**, e al suo posto si legge che quelle fasi
lavorano su nodi gia' noti e non dichiarano bersagli. Misurarle sugli host darebbe zero
per costruzione -- lo stesso allarme falso che darebbe il contatore dei record, che
infatti qui non si usa.

## 5.1 Preferenze di visualizzazione
Icona con i cursori nella barra superiore: tema chiaro/scuro, dimensione del
carattere (piccolo, normale, grande, extra grande), larghezza della pagina
(stretta, larga). Le preferenze sono salvate nel profilo utente e valide su
qualunque postazione.

### 5.1.0 Accessibilita' della navigazione

La console mantiene il collegamento di salto **al contenuto principale**, che e' cio'
che la WCAG 2.4.1 chiede (bypass dei blocchi ripetuti). Il secondo collegamento che
AdminLTE inserisce da se', *Skip to navigation*, e' stato rimosso: porta al menu, che
da tastiera e' gia' il primo elemento raggiungibile, quindi era un passaggio in piu'
verso un punto che si raggiunge comunque.

### 5.1.1 Dimensioni

Le dimensioni si scrivono nell'unita' che le rende leggibili -- byte, kB, MB, GB, TB --
con al massimo due decimali e la virgola come separatore. Vale per l'indicatore *Dati
ricevuti 24h* e per le tabelle dei conferimenti: prima l'unita' era fissa in kB e 43 MB
comparivano come "44165.5 kB", che richiede una divisione a mente.

### 5.1.1-bis Date e orari

Ogni istante e' conservato in UTC e mostrato nel fuso orario del tenant
selezionato, indicato nel piede di pagina della console. Il cambio del fuso in
*Tenant* si riflette immediatamente su tutti i dati, anche storici, perche' la
conversione avviene alla lettura.

La regola vale anche per:

- le **giornate dei grafici** (andamento dei rilevamenti): i confini di giornata
  seguono il fuso del tenant, per cui lo stesso istante puo' ricadere in giorni
  diversi per tenant differenti;
- i **documenti PDF**, che dichiarano in copertina il fuso di riferimento;
- l'**interfaccia della sonda**, che riceve il fuso del tenant dal server e lo
  dichiara nel piede di pagina. Finche' la sonda non e' registrata il fuso non e'
  noto e vengono usati orari UTC, indicandolo esplicitamente.

### 5.1.2 Uso delle tabelle

Ogni elenco dispone degli stessi strumenti, nella barra sopra la tabella e nelle
intestazioni di colonna:

| Strumento | Dove | Uso |
|---|---|---|
| Ricerca generale | campo *Ricerca* sopra la tabella | filtra le righe che contengono il testo in qualunque colonna |
| Ordinamento | clic sull'intestazione di colonna | un secondo clic inverte il verso |
| Ordinamento su piu' colonne | Maiusc + clic sulle intestazioni successive | i criteri si sommano nell'ordine di selezione |
| Righe per pagina | selettore *Mostra ... righe* | 10, 25, 50 o 100 righe per pagina |
| Navigazione | piede della tabella | *Precedente*, numeri di pagina, *Successiva* |
| Conteggio | piede a sinistra | righe mostrate sul totale, con l'indicazione di quante sono filtrate |

Le colonne di sole azioni non sono ordinabili. Per gli elenchi molto ampi il
server invia fino a 1000 righe per pagina e la navigazione tra le pagine del
server compare solo oltre quella soglia.

**I valori lunghi vanno a capo, non vengono tagliati.** Un identificativo di lotto,
un elenco di destinatari, un protocollo restituito da un portale, la descrizione di
un errore: sono valori che non stanno in una colonna. In tabella vanno a capo dentro
la cella (classe `snap-wrap`), perche' un valore troncato con i puntini costringe a
riaprire il dettaglio per leggerlo, e su un identificativo troncato non si puo'
nemmeno cercare. Vale in particolare per **Rete > Dati dalle sonde > Lotti
ricevuti**, dove ogni riga porta identificativo, esito, generi conferiti e
dimensione.

### 5.1.2-bis Indicatori della dashboard

L'area indicatori sta **in fondo alla dashboard**, sotto il quadro d'insieme, e mostra undici riquadri. Chi tiene il turno ne guarda tre o quattro:
gli altri si nascondono con la crocetta che compare passando sopra al riquadro (ed e'
raggiungibile da tastiera). In fondo all'area compare l'elenco di cio' che si e' messo
via, con le caselle spuntate: togliendo la spunta e salvando, l'indicatore torna;
*Mostra tutti* li riporta tutti.

La scelta e' **personale e persistente**: sta sull'utente, non nella sessione e non nel
browser, quindi vale su qualunque postazione e non scade con l'accesso. Non vale per i
colleghi: il giudizio "questo non mi serve" e' di chi lo esprime. Si conservano le voci
**nascoste**, non quelle visibili, cosi' un indicatore aggiunto da una versione
successiva compare comunque a tutti.

### 5.1.2-ter Tabelle e righe di dettaglio

Le tabelle dati del prodotto sono **piatte**: una riga per elemento. I moduli di
modifica e le conferme di eliminazione si aprono in pannelli **sotto** la tabella, non
in righe dentro di essa.

Non e' una scelta estetica: la libreria delle tabelle costruisce il proprio modello
dalle celle delle righe, e una riga con una sola cella distesa su tutte le colonne
(`colspan`) glielo rompe -- l'errore visibile e' *"Requested unknown parameter"* e la
tabella smette di ordinare e di cercare. E' capitato nella pagina delle zone di rete,
ed e' la ragione per cui esiste una prova automatica che vieta le righe collassabili
dentro le tabelle.

### 5.1.2-quater Il menu: un gruppo alla volta

Aprendo un gruppo del menu gli altri si chiudono. Con sei gruppi aperti insieme il menu
diventa piu' alto dello schermo e la voce che serve finisce sotto il bordo: per trovarla
si scorre, che e' esattamente cio' che un menu dovrebbe evitare.

Due regole restano valide sopra questa:

* il gruppo che contiene la **pagina in corso** resta aperto comunque -- il menu deve
  dire dove si e';
* si ricorda cio' che l'operatore **chiude di proposito**, non cio' che apre, e le
  chiusure fatte dall'accordion non si registrano: non sono una scelta, sono una
  conseguenza. Cosi' un gruppo introdotto da una versione successiva compare aperto,
  invece di restare nascosto da una preferenza che non lo conosceva.

### 5.1.3 Conferme e messaggi

Le richieste di conferma e i messaggi di esito usano *Awesome Notifications*:

- le azioni che eliminano o azzerano dati aprono una finestra di conferma con i
  pulsanti **Conferma** e **Annulla**; annullando non viene applicata alcuna
  modifica;
- gli esiti delle operazioni compaiono come notifiche in alto a destra, con
  durata proporzionata alla gravita' (gli errori restano piu' a lungo);
- l'eliminazione di un tenant richiede in aggiunta la digitazione del suo codice,
  perche' l'operazione e' irreversibile;
- disattivando JavaScript i messaggi restano visibili come avvisi nella pagina e
  le conferme ricadono sulla finestra nativa del browser: nessuna funzione si
  perde.

### 5.1-ter Creazione di un utente e credenziali

*Amministrazione > Utenti*. La password si puo' indicare oppure lasciare vuota: in quel
caso viene generata.

In entrambi i casi le credenziali provvisorie vengono **spedite per posta
all'indirizzo dell'utente**, non mostrate a chi crea l'utenza: una credenziale
comunicata a mano finisce in chat, che e' il posto peggiore in cui possa stare. Il
messaggio dice l'indirizzo della console, l'utenza, la password provvisoria e il
ruolo, e dichiara che snap **non invia password in nessun altro caso** -- e' cio' che
permette a chi lo riceve di riconoscere un messaggio falso.

Se la posta non e' configurata o l'invio non riesce, la password **torna a schermo**
con la ragione: una credenziale che nessuno riceve e nessuno vede significa un utente
inutilizzabile. L'utente viene creato in ogni caso -- l'invio e' un servizio, non una
condizione.

Nel registro degli eventi resta l'esito dell'invio con l'indirizzo del destinatario,
**mai la password**: un segreto nel registro resterebbe la' per tutta la
conservazione.

Compromesso dichiarato: la password viaggia nel corpo del messaggio. La posta e'
cifrata in transito (TLS obbligatorio) ma non a riposo; la credenziale e' provvisoria
con obbligo di cambio al primo accesso, il che limita la finestra di esposizione a
quel primo accesso.

### 5.2 Cambio di tenant
Riservato all'amministratore di sistema: voce *Cambia Tenant* nella barra
superiore. Gli utenti di tenant operano esclusivamente sul proprio perimetro.

### 5.3 Attivazione del secondo fattore
*Profilo e sicurezza > Configura MFA*: inquadrare il QR con Google Authenticator
(o applicazione TOTP equivalente) e confermare il codice a sei cifre. In caso di
dispositivo smarrito, un amministratore puo' azzerare l'MFA dalla sezione Utenti.

---

### 5.4 Dichiarare la zona di una subnet

Menu **Rete > Perimetro**. Ogni subnet ha un selettore con sei possibilita':
datacenter, DMZ, rete di gestione, rete industriale (OT), rete ospiti, rete di
utenza. La pagina spiega ciascuna di esse e conta quante subnet non ne hanno ancora
una.

**Che cosa cambia.** Lo stesso servizio raggiungibile riceve un giudizio diverso a
seconda del contesto: SSH in un datacenter e' *atteso* e smette di contare fra i
riscontri aperti (restando annotato con la ragione); lo stesso SSH in una rete ospiti
diventa una *violazione* e sale di gravita'. Le vulnerabilita' confermate non sono
toccate: quelle sono un fatto del software, non della rete.

**Che cosa non cambia.** La scansione: non si scansiona di piu' o di meno per via
della zona.

**Se la zona e' sbagliata** si corregge e basta: alla passata di correlazione
successiva i riscontri che non sono piu' attesi tornano aperti da soli. Nulla viene
cancellato, in nessuno dei due versi.

**Una subnet senza zona vale come rete di utenza**, che e' il giudizio piu' severo:
non dichiarare nulla non e' un modo per avere meno riscontri. Il dettaglio completo
del catalogo e delle regole sta in `12_ZONE_DI_RETE.md`.

### 5.4-ter Scansionare subito una subnet

Menu **Rete > Perimetro**, colonna **AZIONI**: il pulsante con il fulmine chiede
subito una passata di **scoperta** sulla subnet della riga, senza attendere la cadenza
ordinaria (tre giorni). Viene chiesta conferma, perche' una passata su 254 indirizzi
e' traffico sulla rete del cliente.

Quando usarlo: dopo aver aggiunto una rete al perimetro, dopo un intervento che ha
spostato apparati, quando si sospetta che sia comparso qualcosa.

Che cosa aspettarsi:

* la passata viene eseguita **al prossimo contatto della sonda** (non e' istantanea:
  il server non apre connessioni verso le sonde, per progetto);
* trova gli **indirizzi vivi**; l'esame delle porte dei nodi trovati segue nel ciclo
  ordinario, entro le ore successive;
* la richiesta va alla sonda che ha gia' visto nodi in quella subnet, o a tutte se
  nessuna l'ha ancora vista;
* se la subnet e' **disattivata** il pulsante non c'e': una subnet fuori dal perimetro
  consegnato verrebbe rifiutata dalla sonda;
* se le scansioni sono **sospese** la richiesta viene negata con la ragione: la
  sospensione non si aggira con un comando;
* chiedendola due volte, la seconda lo dichiara e non accoda un doppione.

L'esito si legge nella pagina della sonda (elenco dei comandi) e nell'inventario, dove
i nodi trovati compaiono al conferimento successivo.

### 5.4-bis Governare le zone di rete

Menu **Rete > Zone di rete**. Le sei zone del prodotto sono create al primo avvio e si
possono modificare; se ne aggiungono altre quando la rete ha contesti che il prodotto
non puo' prevedere -- "rete di collaudo", "rete fornitori", "rete di cantiere".

Per ciascuna zona si scelgono, da un **elenco chiuso**, le famiglie di esposizione che
vi sono *attese* e quelle che vi sono *violazione*. L'elenco non e' libero: sono i
titoli delle regole di correlazione, e una famiglia inventata non corrisponderebbe a
nessuna regola -- sembrerebbe attiva senza fare nulla.

| Operazione | Che cosa accade |
|---|---|
| Creazione | La zona nasce non usata: finche' nessuna subnet la dichiara, non cambia nessun giudizio |
| Modifica | I riscontri delle subnet in quella zona vengono rivalutati alla correlazione successiva, oppure subito con *Riapplica ai dati raccolti* |
| Eliminazione | Le subnet che la usavano si riassegnano a una zona scelta, oppure restano **senza zona**: eliminando il contesto si perde la giustificazione, non la si eredita |
| Ripristina predefinite | Riporta all'origine le sei zone del prodotto. Le zone create dall'operatore **non** vengono toccate |

La prima frase della descrizione che si scrive diventa la ragione riportata nei
riscontri attesi di quella zona: vale la pena scriverla per essere letta.

### 5.4-quater Correggere il tipo di un dispositivo

Menu **Rete > Nodi**, si apre il dispositivo, riquadro *Perche' e' stato classificato
cosi'*: in fondo c'e' il selettore del tipo con un campo per la motivazione e il
pulsante **Dichiara**. Serve quando il riconoscimento sbaglia o non ha prove a
sufficienza -- il caso tipico e' l'apparato che non apre porte e non risponde a nulla.

* La scelta viene dal **catalogo** dei tipi: non si scrive a mano, perche' il tipo
  alimenta filtri, conteggi e report.
* La **motivazione** e' facoltativa ma consigliata (fino a 300 caratteri): finisce nel
  registro e nella scheda PDF, e fra sei mesi e' l'unica cosa che spieghera' la scelta.
* Il tipo dichiarato vale **100 di confidenza** e **non viene sovrascritto** dalle
  scansioni successive ne' dalla rideterminazione dell'inventario, che dichiara quante
  dichiarazioni ha rispettato.
* Il riconoscimento automatico continua a lavorare: se non e' d'accordo, la scheda lo
  dice (&laquo;direbbe stampante&raquo;). Vale la pena guardarlo: un disaccordo
  ripetuto sullo stesso genere di apparato e' un catalogo delle firme da correggere.
* **Torna al riconoscimento automatico** annulla la dichiarazione e ricalcola subito il
  tipo dalle prove conservate.
* Dove si legge il tipo, un'icona (persona con spunta) distingue un tipo dichiarato da
  uno riconosciuto: in inventario, stato della rete, mappa, quadri NOC e SOC, Threat
  Intelligence.

### 5.5 Produrre ed eliminare un report

Menu **Report e resoconti**. Nella scheda del catalogo si sceglie il genere, il
giorno finale e l'ampiezza; il documento compare nell'archivio in fondo alla pagina.
Due generi non hanno periodo perche' hanno un soggetto: il **rapporto di incidente**
(dalla pagina dell'incidente) e la **scheda dell'apparato** (pulsante *Scheda PDF*
nella pagina del dispositivo).

Per eliminare un documento si usa il pulsante sulla riga dell'archivio. Viene chiesta
conferma; si cancella prima il file e poi la riga, e l'operazione resta nel registro
degli eventi. Se il file non si potesse cancellare la riga rimane, con un messaggio
esplicito: un archivio che promette una cancellazione non avvenuta e' peggio di uno
che dichiara il problema. Un report eliminato si puo' rigenerare identico.

### 5.6 Il dato grezzo di un dispositivo

Nella pagina di un dispositivo, pulsante **JSON**: si apre in una finestra nuova il
documento completo di cio' che il prodotto conserva su quell'apparato -- identita',
collocazione (subnet, zona, sonda), riconoscimento **con le prove** su cui poggia,
porte, riscontri, letture SNMP, letture web, variazioni, campioni di
raggiungibilita'. Il pulsante accanto lo salva come file, con l'indirizzo nel nome.

Serve a verificare un verdetto ("stampante al 78% in base a che cosa?"), ad allegare
un dispositivo a una segnalazione per chi non ha accesso alla console, e a capire un
difetto -- quando un dato non torna, la prima cosa che serve e' cio' che e' stato
conservato davvero.

Il formato e' versionato (`snap.node/1`), limitato al tenant corrente e privo di
chiavi, token e community SNMP. Lo scarico resta nel registro degli eventi; la
semplice lettura no, perche' registrare ogni sguardo renderebbe invisibili le
estrazioni vere.

### 5.7 Riapplicare il prodotto ai dati gia' raccolti

Menu **Rete > Dispositivi**, comando **Riapplica ai dati raccolti**. Rifa', in
quest'ordine: porte attribuite dalla rete, riconoscimento dei dispositivi,
correlazione delle vulnerabilita' ed esposizioni, giudizio delle zone. Dal menu
accanto si esegue un passo solo.

Quando serve: dopo aver dichiarato o modificato una zona, dopo un aggiornamento del
catalogo delle vulnerabilita', dopo un aggiornamento del prodotto che aggiunge firme o
regole. **Non avvia scansioni** -- rilegge l'archivio -- quindi si puo' eseguire in
orario di lavoro. Riferisce con numeri che cosa ha prodotto, un passo che non riesce
non ferma i successivi, e l'operazione resta nel registro.

### 5.8 Guardare una sonda dal server (console remota)

Menu **Sonde**, bottone **arancione** sulla riga della sonda (oppure *Apri la console
della sonda* dalla sua pagina di configurazione).

Mostra le stesse cose che si vedono aprendo l'interfaccia della sonda in sede:
configurazione in vigore, nodi, coda da conferire, fasi in corso, ricognizione delle
presenze, ultime passate, ultimi conferimenti e il **diario locale** — che prima si
poteva leggere solo stando davanti alla sonda.

**Perche' e' arancione.** La pagina mostra, dentro la console, cio' che appartiene a
un'altra macchina. Due interfacce che si somigliano sono un rischio operativo: chi
crede di stare sul server mentre guarda una sonda prende decisioni sui dati sbagliati.
La sonda ha per questo un marchio arancione, e qui quell'arancione arriva sulla pagina
del server:

- un **nastro appiccicato in alto**, che resta mentre si scorre (su una pagina lunga
  la scritta in testa scorrerebbe via proprio mentre si leggono i numeri);
- una **cornice arancione** attorno a tutto il contenuto, cosi' anche a meta' pagina
  si vede di chi sono i dati;
- un **piede** che ripete l'appartenenza per chi arriva in fondo.

**Il dato non e' dal vivo, e la pagina lo dichiara.** La sonda sta nella rete del
cliente e apre lei la comunicazione, ogni quindici secondi: il server non puo'
raggiungerla. Quello che si vede e' percio' l'**ultima istantanea consegnata**, con il
proprio istante nel nastro. Se il battito non arriva da oltre due minuti la targhetta
dell'istante diventa **rossa**: quello non e' lo stato attuale.

I comandi viaggiano nella direzione opposta — si accodano dalla pagina di
configurazione e la sonda li ritira al battito successivo, entro un minuto. E' un
ritardo dichiarato, non un difetto nascosto: e' il prezzo di non aprire un canale
permanente dall'interno della rete del cliente verso l'esterno.

### 5.9 IDS: rilevazioni, regole e agenti

Menu **IDS**. Tre pagine, tre domande diverse.

**Rilevazioni** -- che cosa e' cambiato in un modo che riguarda la sicurezza. E' la
pagina del turno. L'ordine e' la **gravita', non il tempo**: una rilevazione critica
di ieri conta piu' di una media di stamattina. Ogni riga porta la regola che l'ha
prodotta, la tecnica MITRE ATT&CK corrispondente e la **prova**: che cosa si vedeva
prima, e da quando.

Una rilevazione e' un **cambiamento**, non un fatto assoluto: «la porta 3389 e'
aperta» non e' una rilevazione, «la 3389 e' aperta dove non c'era» lo e'. La
differenza conta quando si decide: la prima e' una configurazione da valutare (e la
relazione sull'esposizione la elenca gia'), la seconda e' qualcosa che e' successo.

Si decide archiviando **con una nota**. Archiviare non significa «non mostrarmela
piu'»: se la stessa cosa si ripresenta, la rilevazione torna aperta al conferimento
successivo. Significa «ho guardato allora, ed ecco che cosa ho concluso» -- ed e' il
motivo per cui la nota si conserva e si legge accanto alla riga riaperta.

**Regole e sensori** -- che cosa il prodotto sa riconoscere, e soprattutto **che cosa
non sta guardando**. Dodici regole, ciascuna con la propria gravita' e la tecnica
ATT&CK. Sotto, lo stato di ogni sensore riferito da ciascuna sonda.

> Una regola con zero rilevazioni puo' significare due cose opposte: che quella
> condizione non si e' mai verificata, oppure che il sensore da cui dipende non sta
> osservando. La tabella dei sensori dice quale delle due.

La colonna **memoria** dice a che punto e' la linea di base di ogni sonda. Finche'
risulta *in apprendimento*, le regole che si fondano sull'assenza di memoria
(«dispositivo mai visto», «apparato senza fili mai visto») non scattano: il motore
costruisce e tace, e la pagina delle rilevazioni lo dichiara in cima. Sono dodici ore
dalla prima osservazione. E' voluto: senza quell'attesa la prima passata segnalerebbe
l'intera rete come «mai vista» -- su una rete di collaudo sono state quattrocento
rilevazioni in un colpo.

**Agenti di macchina** -- le macchine su cui e' installato l'agente, con l'ultima
misura di CPU, memoria e disco, e gli eventi che riferiscono. Dalla rete una porta
4444 aperta e' una porta aperta; da dentro e' un processo con un nome e un utente: e'
per questo che l'agente esiste. Le macchine si aggiungono dalla **console della
sonda**, non da qui (capitolo 6.2): il token va emesso dove la macchina puo'
arrivare.

**Che cosa questo IDS non vede.** Non ispeziona il traffico: niente firme sul
payload, nessun canale di comando cifrato, nessuna esfiltrazione riconosciuta. Il
limite e' scritto in cima a ogni pagina che mostra rilevazioni. Zero rilevazioni
significa «nessun cambiamento fra quelli che so riconoscere», non «nessuna
intrusione».

Le rilevazioni conferite entrano anche nel **SIEM** come eventi di genere `ids`, con
la gravita' della regola: chi lavora sugli incidenti non deve guardare due pagine.
Casi d'uso ed esempi commentati in `17_IDS_E_AGENTI.md`, capitolo 9.

### 5.10 Azzerare le informazioni raccolte di un tenant

Menu **Amministrazione > Tenant**, icona **gomma** sulla riga del tenant. Riservato
all'**amministratore di sistema**.

Non e' l'eliminazione del tenant: il tenant **resta**, con utenze, sonde, perimetro,
controlli e regole. Si butta solo cio' che le sonde hanno **osservato**. Serve quando
la raccolta e' sporca e si vuole ricominciare senza rifare la configurazione: un
perimetro sbagliato, una sonda dietro un NAT che ha inventato nodi, un cambio di rete
che rende l'inventario un archivio di fantasmi.

| Viene eliminato | Viene conservato |
|---|---|
| Nodi, con porte, interfacce web, SMB, SNMP | Utenze e sonde registrate |
| Variazioni dell'inventario e campioni di raggiungibilita' | Perimetro (subnet) e zone di rete |
| Esiti, misure e incidenti dei controlli | Controlli configurati e regole di notifica |
| Presenze sulle reti senza fili | Report prodotti e notifiche inviate |
| Correlazioni con la threat intelligence | Registro di audit |
| Eventi e avvisi SIEM | Collettori e sorgenti SIEM dichiarate |
| Passate di scansione e conferimenti | Incidenti con una comunicazione ad ACN |

Gli **incidenti da cui e' nata una comunicazione ad ACN** non si cancellano: una
comunicazione all'autorita' e' un atto dovuto (D.lgs. 138/2024, art. 25) e la sua prova
non sparisce con un bottone. L'esito dice quanti sono stati conservati.

**Come si conferma.** La finestra mostra il conto di cio' che si perde, voce per voce,
e chiede di **digitare il codice del tenant**: un avviso che si chiude per sbaglio non
e' una conferma per un'operazione che butta giorni di scansione. La colonna *RACCOLTO*
nella tabella dei tenant mostra quel numero anche senza aprire la finestra.

**Cosa succede dopo.** Alle sonde del tenant viene chiesto di **ricominciare dalla
scoperta**: dimenticano i nodi noti e lo stato delle fasi, e la raccolta riparte al
prossimo contatto. La coda da conferire **non** si tocca (cio' che e' in attesa e' stato
raccolto e va consegnato) e nemmeno la registrazione. L'inventario si ripopola man mano,
non istantaneamente: la prima scoperta arriva entro un minuto, i profili nei minuti
successivi.

L'operazione resta nel registro di audit del tenant, con severita' *critica* e con il
conto di cio' che e' stato eliminato.

### 5.10 Sistemi operativi e fine supporto

*Rete → Sistemi operativi*: i sistemi trovati, con data di rilascio, **fine supporto**,
giorni residui e quanti dispositivi li usano. Un sistema fuori supporto non riceve più
correzioni: le vulnerabilità che escono da quel giorno restano aperte per sempre.

| Stato | Significato |
|---|---|
| **fuori supporto** | la data è passata |
| **in scadenza** | entro 180 giorni — il tempo minimo per pianificare e svolgere una migrazione in una PA |
| **da confermare** | l'impronta copre più release con scadenze diverse |
| **supportato** | fine supporto oltre la soglia |
| **non determinabile** | l'osservazione non identifica un prodotto |

**La colonna che conta è l'origine del dato.** nmap non legge la release installata:
riconosce un'impronta di rete e la nomina con la versione da cui l'impronta fu
raccolta. Su una rete reale 307 dispositivi risultano «Windows 11 21H2» — fuori
supporto — e possono essere 24H2 aggiornate ieri. Una riga *stimato* si conferma
installando l'agente o abilitando SMB su quella macchina; solo allora diventa
*dichiarato*.

Quando il verdetto manca, la pagina scrive **perché**: un kernel nudo («Linux 4.0 -
4.4») non ha una fine supporto perché il supporto lo dà la distribuzione, che dalla
rete non si vede; un apparato Cisco non ce l'ha perché il ciclo di vita è del modello,
non della versione di IOS. Sono due assenze diverse e portano a due azioni diverse.

Il *supporto esteso* (ESU, LTS, ESM, ELS) è in una colonna a parte e **non** vale come
copertura: è di chi lo ha acquistato o attivato.

### 5.11 Sospendere un blocco di subnet

*Rete → Perimetro*, riquadro **Sospendere o riattivare un blocco intero**. Si scrive un
blocco di indirizzi e il prodotto trova tutte le subnet del perimetro contenute in
quel blocco.

| Si scrive | Che cosa prende |
|---|---|
| `10.58.0.0/16` | ogni subnet dentro quel blocco, con qualunque maschera |
| `10.6.24.0/22` | `10.6.24.0/24` e `10.6.25.0/24`, **non** `10.6.30.0/24` |
| `10.58.3.7/16` | lo stesso di `10.58.0.0/16`: si accetta anche un indirizzo dentro il blocco |

Il confronto è sugli **indirizzi**, non sulle cifre: le maschere che non cadono su un
punto (`/22`, `/12`) funzionano come le altre.

**Si vede prima, si applica dopo**: il primo pulsante mostra l'elenco esatto di ciò che
cambierebbe senza toccare niente. L'insieme viene ricalcolato al momento
dell'applicazione, quindi non si agisce su un'anteprima vecchia. Sospendere non
cancella nulla — i dispositivi restano in inventario — e l'operazione finisce nel
registro delle azioni con i CIDR toccati.

## 6. Uso dell'interfaccia della sonda

### 6.0-ante La password dell'interfaccia: impostarla e reimpostarla

**Un comando, e non serve fermare la sonda.**

| Dove | Comando |
|---|---|
| Fuori dal contenitore (Windows) | `.\start-nativa.ps1 -Password` |
| Come sopra, generandola robusta | `.\start-nativa.ps1 -Password -Casuale` |
| In contenitore (Linux) | `docker compose ... exec probe python run.py --password` |
| Dove il DSN è già nell'ambiente | `cd probe ; python run.py --password` |

Vale sia per la **prima** password sia per una **dimenticata**. L'interfaccia rilegge
l'impronta a ogni accesso: la nuova password vale dal tentativo successivo, senza
riavvii.

> **Perché esiste questo comando.** La pagina `/primo-accesso` vale solo finché una
> password non c'è: se c'è già, rimanda all'accesso. Una password dimenticata non
> aveva quindi nessuna procedura — restava da cancellare a mano una riga nelle
> impostazioni dell'archivio, cosa che non era scritta da nessuna parte.

La password **non è recuperabile**: è conservata come impronta scrypt, quindi nemmeno
il prodotto può rileggerla. Con `-Casuale` viene mostrata una volta sola.

Senza valore, il comando la chiede **senza mostrarla a schermo**. Passarla sulla riga
di comando si può — serve agli automatismi — ma il comando avverte: finirebbe nella
cronologia della shell e nell'elenco dei processi, dove la vede chiunque sia connesso
a quella macchina.

**La sicurezza non cala rispetto alla pagina.** `/primo-accesso` si fida di chi è
davanti alla macchina; il comando chiede di più: una shell su quella macchina e i
permessi per aprirne l'archivio. Chi può eseguirlo potrebbe già cambiare l'impronta a
mano.

Politica: almeno 10 caratteri, con maiuscola, minuscola e cifra — la stessa della
console, perché scoprire che la sonda accetta password più deboli sarebbe una sorpresa
nel verso sbagliato.

### 6.0-bis La prima password, con la sonda fuori dal contenitore

> Da quando esiste `-Password` (capitolo 6.0-ante) questa procedura non è più
> necessaria: resta documentata perché la pagina `/primo-accesso` continua a
> funzionare, e perché spiega un comportamento dei cookie che si incontra altrove.

Su Windows la sonda si avvia sulla macchina e il TLS lo termina un proxy in
contenitore (vedi `PORTS.md`). In quella configurazione la **prima** password si
sceglie cosi', una volta sola:

```
.\start-nativa.ps1 -PrimaPassword
```

e poi si apre `http://127.0.0.1:5511/primo-accesso` **da quella macchina**. Fatto
questo si ferma e si riavvia senza l'interruttore.

Perche' serve un avvio dedicato: con il proxy davanti il cookie di sessione e'
marcato `Secure`, e un cookie `Secure` **non viene rimandato su HTTP** -- ne' dal
browser ne' da altri client. Senza cookie non c'e' sessione; senza sessione il token
anti-CSRF viene rifiutato e la pagina risponde «il token di sicurezza e' scaduto» a
ogni tentativo. L'interruttore toglie il solo `Secure`, per il tempo della prima
impostazione: il token anti-CSRF **resta**, perche' su quella pagina e' cio' che
impedisce a un sito qualunque, aperto in un'altra scheda, di impossessarsi della
sonda.

Dalla rete quella pagina resta negata dal proxy, per disegno: la' ogni richiesta
arriva dall'indirizzo del gateway di Docker, uguale per chi sta alla postazione e per
chi arriva dalla LAN, e un permesso su quell'indirizzo aprirebbe la sonda a tutti.

### 6.0 Accesso

L'interfaccia e' protetta da **una password**: una sola credenziale, senza elenco
utenti e senza ruoli (DEC-11).

| Situazione | Che cosa accade |
|---|---|
| Prima apertura | La password non esiste e va scelta. **Si scegle dalla postazione della sonda** (`http://127.0.0.1:5510/`): dalla rete la scelta iniziale viene rifiutata con un messaggio esplicito |
| Accessi successivi | Password all'apertura; sessione di 8 ore (`SNAP_PROBE_SESSION_MINUTES`); uscita dal pulsante in fondo al menu |
| Password sbagliata | 5 tentativi, poi blocco di 15 minuti. Il blocco scade da se' |
| Cambio password | *Configurazione > Password dell'interfaccia*, con la password attuale. Almeno 10 caratteri, una maiuscola, una minuscola, una cifra: la stessa regola della console |
| Password dimenticata | Non si recupera da remoto, di proposito. Dal dispositivo: cancellare la voce `ui_password_hash` dalla tabella `settings` dell'archivio locale, con l'utenza proprietaria -- `docker exec snap-probe-postgres psql -U <proprietario> -d snap_probe -p 5532 -c "DELETE FROM settings WHERE key = 'ui_password_hash';"` --; alla riapertura l'interfaccia chiede di scegliere una password nuova |

Ogni accesso -- riuscito, fallito, bloccato -- e il cambio password entrano nel
**diario locale** con l'indirizzo di provenienza: e' la traccia che risponde a "chi
ha toccato questa sonda" (NIS2).

Due limiti dichiarati: il canale dell'interfaccia e' **HTTP** (aperta alla rete, la
password l'attraversa in chiaro) e chi ha la password ha un accesso
**amministrativo**, non di sola lettura. Il canale verso il server e' altra cosa:
cifrato e autenticato dalle chiavi della registrazione.

### 6.1 Pagine

| Pagina | Funzione |
|---|---|
| Stato | Stato del canale, coda locale, ultimi conferimenti, diario recente; azioni *Verifica server*, *Raccogli ora*, *Conferisci ora* |
| Configurazione | Intervallo di raccolta, sospensione, indirizzo del server, configurazione ricevuta, contenuto della coda, manutenzione |
| Diario locale | Eventi e conferimenti registrati sul dispositivo |
| IDS | Le rilevazioni prodotte su questa rete, lo stato dei sensori e la maturita' della memoria. E' la stessa informazione della console, ma **locale**: si vede anche quando il collegamento con la sede e' interrotto |
| Agenti | Le macchine che riferiscono a questa sonda, con l'emissione dei token di registrazione e la revoca (capitolo 6.2) |
| Pacchetti | Che cosa passa sul filo, quando l'osservazione del traffico e' accesa: intestazioni e nomi in chiaro, mai il contenuto |
| Salute | Quanto occupa l'archivio, quanto durera', e quanto manca a ciascuna fase di scansione (capitolo 6.3) |

L'interfaccia non consente la consultazione dei dati raccolti: la loro sede e' il
server. Le pagine IDS, Agenti, Pacchetti e Salute sono l'eccezione, e per un motivo
preciso: chi e' davanti alla sonda deve poter capire che cosa sta succedendo **senza
dipendere dalla rete geografica**, che e' proprio cio' che potrebbe mancare nel momento
in cui serve.

**Operazioni di manutenzione**:
- *Azzera il contatore dei cicli*: riporta a zero la numerazione delle raccolte;
- *Svuota la coda* (digitare `SVUOTA`): elimina i record non conferiti;
- *Azzera la registrazione* (digitare `AZZERA`): rimuove chiavi e credenziali
  mantenendo la coda. Per registrare la sonda su un nuovo pacchetto non serve
  azzerare: si usa la voce *Registrazione*.

### 6.2 Installare un agente su una macchina

L'agente porta dentro il sistema quello che dalla rete non si vede: chi ha provato ad
accedere, quale processo tiene aperta una porta, che software e' installato, se la
protezione e' stata fermata. Si installa dal **pacchetto** che questa console prepara.

> **Il pacchetto e' una credenziale.** Contiene un token valido **un'ora** e **una
> volta sola**. Gli installatori lo cancellano dalla macchina appena speso. Un
> pacchetto vale per **una** macchina: per dieci macchine si scaricano dieci
> pacchetti, e ognuna ha la propria credenziale, revocabile da sola.

**Passo 1 -- preparare il pacchetto.** Pagina **Agenti**: si scrive per quale macchina
(finisce nel nome del file e resta nel diario), si decide se la macchina deve
verificare il certificato di questa sonda -- da togliere solo se la sonda ha un
certificato proprio -- e si preme *Scarica il pacchetto*. Si ottiene un `.zip` di una
cinquantina di kilobyte, da copiare sulla macchina e scompattare.

**Passo 2 -- eseguire l'installatore.**

| Dove | Comando | Che cosa crea |
|---|---|---|
| Windows | PowerShell **come amministratore**: `.\installa.ps1` | attivita' pianificata che parte all'accensione, come SYSTEM |
| Linux | `sudo ./installa.sh` | unit systemd, con utenza dedicata `snap-agent` |
| Docker | `cp docker/.env.example docker/.env`, riempirlo, `docker compose -f docker/docker-compose.yml up -d --build` | container con la macchina montata in sola lettura |

Ogni installatore fa la stessa sequenza: verifica Python, crea un ambiente virtuale
dedicato, installa `psutil`, registra la macchina, **cancella il token**, installa il
servizio e infine **verifica che stia davvero girando**. Se non e' partito lo dice e
mostra il comando per provarlo a mano: non stampa mai «fatto» senza aver guardato.

**Opzioni che vale la pena conoscere.**

| Opzione | Windows | Linux | Effetto |
|---|---|---|---|
| Meno dati personali | `-Gruppi minimo` | `--gruppi minimo` | manda solo identita', carico, dischi, rete |
| Meno privilegi | `-UtenteDiServizio` | (e' il predefinito) | si perdono porte in ascolto, accessi falliti, utenze |
| Piu' privilegi | (SYSTEM e' il predefinito) | `--privilegi-completi` | esegue da root e vede tutto |
| Certificato proprio | `-SenzaVerificaTls` | `--senza-verifica-tls` | accetta il certificato senza verificarlo |

**Senza accesso a Internet** `pip` non raggiunge nulla. Si mettono le *wheel* nel
pacchetto, in una cartella `wheels/`, da una macchina che la rete ce l'ha:

```
pip download psutil==6.1.0 -d wheels/ --only-binary=:all: --platform win_amd64 --python-version 313
pip download psutil==6.1.0 -d wheels/ --only-binary=:all: --platform manylinux2014_x86_64 --python-version 313
```

Se la cartella c'e', gli installatori la usano e non cercano la rete.

#### 6.2-bis Che cosa la macchina invia, e chi lo decide

La raccolta e' divisa in **quindici gruppi**. Chi installa sceglie quali accendere:

```
python snap_agent.py configura                    interattivo
python snap_agent.py configura --gruppi minimo    senza domande
```

L'interfaccia e' **da console** e non una pagina web, e non per poverta' di mezzi: una
pagina web vorrebbe dire un servizio in ascolto su ogni postazione sorvegliata, cioe'
esattamente cio' che l'architettura evita. L'agente non apre porte.

| Preselezione | Accende | Quando si usa |
|---|---|---|
| `tutti` | tutti e quindici | predefinito |
| `consigliato` | tutto tranne software e attivita' pianificate | dove l'inventario completo non serve |
| `minimo` | identita', carico, dischi, rete | dove il trattamento non e' concordato con chi lavora su quelle macchine: **nulla che riguardi le persone** |

I gruppi spenti vengono **dichiarati** alla sonda e la scheda della macchina li elenca
sotto *Non richiesto*, distinti da quelli che l'agente non e' *riuscito* a leggere. La
prima e' una scelta, la seconda un problema, e il prodotto non le confonde.

#### 6.2-ter Due ritmi: le misure e l'inventario

L'agente manda due cose diverse, e la differenza si vede nei numeri.

| | Che cosa | Ogni quanto | Quanto pesa |
|---|---|---|---|
| **Misure** | carico, dischi, ritmo di rete, processi, connessioni, sessioni | un minuto | pochi kB |
| **Inventario** | software installato, servizi, utenze, postura, porte in ascolto | un'ora, o appena cambia qualcosa | qualche decina di kB |

Misurato su una macchina vera: mandare tutto ogni minuto faceva **99 MB al giorno per
macchina**, per riscrivere 1.440 volte lo stesso elenco di programmi installati.
Separati, la stessa macchina manda **7,6 MB al giorno** con piu' informazioni di prima.
L'inventario e' uno *stato* e si sovrascrive; le misure sono una *serie* e si
accumulano.

#### 6.2-quater Che cosa non raccoglie mai

Contenuto di file, righe di comando complete, traffico, messaggi, cronologia, corpo
delle attivita' pianificate, elenco di chi parla con chi. Le righe di comando possono
contenere una password passata come argomento: si registra il **nome** del processo e
il suo utente. Delle connessioni si mandano i **conteggi**, che bastano a vedere
un'anomalia senza tenere un registro di cio' che le persone fanno.

Nomi utente e sessioni sono **dati personali** (GDPR art. 4): base giuridica la
sicurezza della rete, art. 6(1)(f). Prima di installare, la domanda che tutti fanno --
*che cosa mi porta via da qui?* -- ha una risposta che non chiede di fidarsi:

```
python snap_agent.py prova --riassunto
```

raccoglie una volta e **stampa** cio' che manderebbe, gruppo per gruppo, con il peso
al giorno. Senza mandarlo.

#### 6.2-quinquies Il container, e i suoi limiti dichiarati

Un agente dentro un container misura **il container**: sarebbe un dato esatto e
inutile. Il compose apre l'isolamento in tre punti -- `pid: host`,
`network_mode: host`, `/:/hostfs:ro` -- e in nessun altro.

Anche cosi', **quattro gruppi restano fuori** e l'agente lo dichiara: *aggiornamenti*
(li conosce il gestore di pacchetti della macchina), *servizi* (`systemctl` parla con
il systemd della macchina), *container* (servirebbe il socket di Docker, che non si
monta per non dare il controllo del motore), *attivita' pianificate* (i cron si
leggono, i timer di systemd no: l'elenco si dichiara parziale).

Il *software installato* invece funziona, perche' l'agente punta all'archivio dei
pacchetti della macchina. Senza quell'accortezza elencava i pacchetti dell'immagine
come se fossero quelli della macchina -- esatto e falso.

**In sintesi**: il container va bene per i server di cui interessano carico, dischi,
rete, porte e processi; per l'inventario completo l'installazione nativa vede tutto.

#### 6.2-sexies Revocare e togliere

**Revocare** si fa da questa pagina, bottone *revoca*: da quel momento gli invii di
quella macchina vengono respinti. **Togliere** l'agente si fa sulla macchina
(`disinstalla.sh` / `disinstalla.ps1` / `docker compose down -v`). Sono due gesti
distinti di proposito: disinstallare e' una manutenzione, revocare una credenziale e'
una decisione.

**Se non entra.** Il rifiuto che l'agente riceve non dice quale verifica non e'
passata -- spiegarlo aiuterebbe solo chi sta provando. Il motivo per esteso e' nel
**diario della sonda**: «firma non valida», «marca temporale fuori finestra», «agente
sconosciuto o revocato», «invio ripetuto». Prima di tutto il resto si prova
`https://<sonda>:5510/api/agent/ping`: se non risponde, il problema e' la rete o il
proxy, non la chiave.

---

### 6.3 Salute: occupazione dell'archivio e scadenze

Risponde a due domande che prima non avevano una pagina.

**Quanto occupa questa sonda.** L'archivio tabella per tabella, con le righe
**contate** (non stimate), le righe morte e che cosa contiene ciascuna tabella. Una
misura al giorno viene registrata da sola: da due misure la pagina ricava la crescita
al giorno e, con lo spazio libero, fra quanti giorni il volume si riempirebbe.

> Il primo giorno si legge «crescita: non ancora», non «zero». Una crescita e' una
> differenza fra due misure, e finora ce n'e' una sola: uno zero al suo posto si
> leggerebbe come «non cresce», che e' un'affermazione che nessuno ha verificato.

**Quanto manca alla prossima esecuzione.** Per ogni fase: cadenza, ultima esecuzione e
tempo che manca. La **scoperta si conta per subnet**, le altre no: con centinaia di
subnet le scadenze sono altrettante e il perimetro si ricensisce a scaglioni lungo la
giornata, percio' ci sono due colonne — quando scade la prima e quando l'ultima.

| Si legge | Significa |
|---|---|
| *fra 12 h 04 min* | la fase ripartira' allora |
| *scaduta da 6 h* | e' **in coda**, non e' ferma |
| *appena possibile* | non e' mai stata eseguita |
| *mai* nella colonna dell'ultima esecuzione | idem: non c'e' un istante da cui contare |

Una fase scaduta non e' un guasto: lo diventa se resta scaduta mentre le altre
avanzano, ed e' allora che si guarda il diario.

Le stesse cifre dell'archivio arrivano alla console del server col battito, e si
leggono in *Sonde → Console*: la sonda sta in casa del cliente, e nessuno andra' a
guardarle il disco prima che si riempia.

## 7. Esercizio ordinario

### 7.1 Verifiche periodiche
| Verifica | Dove | Indicazione di anomalia |
|---|---|---|
| Sonde in contatto | Dashboard, indicatore *Copertura sonde* | Valore inferiore al totale censito |
| Conferimenti | Indicatore *Conferimenti 24h* | Valore nullo con sonde in contatto |
| Comandi in attesa | Indicatore nella barra superiore | Valore stabilmente maggiore di zero: sonda non in contatto |
| Eventi rilevanti | Indicatore *Eventi rilevanti 7g* | Crescita improvvisa |
| Sonde da registrare | Indicatore *In attesa di registrazione* | Token emessi e mai utilizzati |

### 7.2 Conservazione dei dati
*Impostazioni Sistema > Applica conservazione*: rimuove le voci del registro di
audit e i conferimenti piu' vecchi dei giorni impostati per il tenant. Sonde,
utenti e configurazioni non sono interessati.

### 7.3 Salvataggio e ripristino

La base dati del server e' PostgreSQL: non e' un file da copiare, e copiare la
cartella dei dati del contenitore con il servizio avviato produce un archivio
incoerente. Si usa una delle due strade, che **non sono interscambiabili**.

**Dalla console** (*Impostazioni Sistema > Archivio*), a richiesta:
- **Creare una copia** produce un archivio `pg_dump` in formato personalizzato
  (`snap-AAAAMMGG-hhmmss.dump`), lo **verifica appena prodotto** e ruota le copie
  piu' vecchie. Se la verifica non passa, il file viene eliminato: una copia che
  sembra riuscita e non e' ripristinabile e' peggio di nessuna copia.
- **Verificare** una copia legge l'indice dell'archivio e controlla che contenga le
  tabelle del prodotto, senza ripristinare nulla.
- **Ripristinare** chiede una conferma digitata, salva **prima** una copia dello
  stato corrente, e riversa l'archivio in una sola transazione: un ripristino
  interrotto non lascia una base dati a meta'. Il servizio non va fermato.

**Schedulata dall'host**, con `docker/server/backup-postgres.sh`: scrive SQL
compresso (`.sql.gz`) nel volume della base dati e si ripristina con `psql`. E' la
strada per la copia notturna; quelle copie **non compaiono nella console** e la
console non sa ripristinarle.

Chi definisce la continuita' operativa (NIS2) scelga quale delle due e' la copia
ufficiale, e **la provi**: una copia mai ripristinata non e' una copia.

**Versione del client.** Il ripristino richiede `pg_restore` della stessa versione
major del server (l'immagine porta il client 16 per il server 16). La console
verifica le due versioni prima di ogni copia e di ogni ripristino e si rifiuta se non
corrispondono, dicendo quale serve: con versioni diverse `pg_restore` imposta
parametri di sessione che il server non riconosce e il ripristino si interrompe.

**Oltre alla base dati**, con i servizi arrestati, copiare anche:
- `server/instance/secret_key` (continuita' delle sessioni);
- `probe/data/` per ciascuna sonda (chiavi e coda). Sostituire l'archivio di una
  sonda con uno diverso richiede una nuova registrazione.

**Riservatezza.** Una copia contiene i dati di TUTTI i tenant, gli indirizzi di rete
e le credenziali di servizio conservate nelle impostazioni: va trattata come
l'archivio stesso, con permessi restrittivi, e cifrata se lascia la macchina
(GDPR art. 32). L'operazione e' riservata all'amministratore di sistema ed e'
tracciata nel registro.

---

## 8. Configurazione avanzata (variabili d'ambiente)

### Server (prefisso `SNAP_SERVER_`)
| Variabile | Valore predefinito | Significato |
|---|---|---|
| `SNAP_SERVER_HOST` | `127.0.0.1` | Indirizzo di ascolto |
| `SNAP_SERVER_LOG_FILE` | vuoto | Diario su file, **in aggiunta** a quello a schermo. Vuoto significa solo a schermo. Lo imposta l'avvio assistito |
| `SNAP_SERVER_PORT` | `5500` | Porta di ascolto |
| `SNAP_SERVER_DATABASE_URL` | _obbligatoria_ | Indirizzo della base dati PostgreSQL con l'utenza **applicativa** (legge e scrive i dati, non puo' toccare lo schema). Senza questa variabile il server non parte: un valore predefinito funzionante sarebbe la via piu' rapida per mettere in esercizio una base dati di prova senza accorgersene |
| `SNAP_SERVER_OWNER_DATABASE_URL` | vuoto | Indirizzo con l'utenza **proprietaria**. Serve all'allineamento dello schema all'avvio e alla copia/ripristino dell'archivio dalla console. Senza, quelle due operazioni si rifiutano dichiarando il motivo |
| `SNAP_SERVER_BACKUP_DIR` | `server/data/backups` | Cartella delle copie create dalla console |
| `SNAP_SERVER_SECRET_KEY` | generata in `instance/` | Chiave di sessione |
| `SNAP_SERVER_SESSION_MINUTES` | `120` | Durata della sessione |
| `SNAP_SERVER_COOKIE_NAME` | `snap_server_session` | Nome del cookie di sessione: deve differire da quello della sonda |
| `SNAP_SERVER_COOKIE_SECURE` | `false` | Cookie solo su HTTPS |
| `SNAP_SERVER_COOKIE_SAMESITE` | `Lax` | Politica SameSite del cookie di sessione |
| `SNAP_SERVER_EMBEDDED` | `false` | Uso in cornice: imposta SameSite=None e X-Frame-Options=SAMEORIGIN |
| `SNAP_SERVER_FRAME_OPTIONS` | `DENY` | Valore di X-Frame-Options (`NONE` per non emetterlo) |
| `SNAP_SERVER_ENROLLMENT_TTL_HOURS` | `24` | Validita' del token di registrazione |
| `SNAP_SERVER_PROBE_OFFLINE_AFTER_SEC` | `900` | Soglia di irraggiungibilita' di una sonda |
| `SNAP_SERVER_NONCE_RETENTION_HOURS` | `24` | Conservazione dei nonce anti-replay |
| `SNAP_SERVER_MAX_UPLOAD_MB` | `32` | Dimensione massima di un conferimento |
| `SNAP_SERVER_DEBUG` | `false` | Modalita' di sviluppo |

### Sonda (prefisso `SNAP_PROBE_`)
| Variabile | Valore predefinito | Significato |
|---|---|---|
| `SNAP_PROBE_HOST` | `127.0.0.1` | Indirizzo dell'interfaccia locale |
| `SNAP_PROBE_LOG_FILE` | vuoto | Diario su file, in aggiunta a quello a schermo |
| `SNAP_PROBE_SESSION_MINUTES` | `480` | Durata della sessione dell'interfaccia |
| `SNAP_PROBE_PORT` | `5510` | Porta dell'interfaccia locale |
| `SNAP_PROBE_DATABASE_URL` | *obbligatoria* | Archivio locale (PostgreSQL): l'utenza applicativa, che scrive i dati |
| `SNAP_PROBE_OWNER_DATABASE_URL` | *obbligatoria* | Stessa base dati con l'utenza proprietaria: crea e migra lo schema |
| `SNAP_PROBE_TICK_SECONDS` | `15` | Cadenza del ciclo dell'agente |
| `SNAP_PROBE_SCAN_INTERVAL` | `300` | Intervallo di raccolta iniziale |
| `SNAP_PROBE_HTTP_TIMEOUT` | `15` | Timeout delle richieste al server |
| `SNAP_PROBE_COOKIE_NAME` | `snap_probe_session` | Nome del cookie di sessione: deve differire da quello del server |
| `SNAP_PROBE_DEBUG` | `false` | Modalita' di sviluppo |
| `SNAP_PROBE_BEHIND_PROXY` | `false` | Legge l'indirizzo del client dalle intestazioni `X-Forwarded-*`: si attiva **solo** con un proxy davanti che le riscrive |
| `SNAP_PROBE_COOKIE_SECURE` | `false` | Cookie di sessione solo su HTTPS |
| `SNAP_PROBE_SERVER_CA` | vuoto | Certificato di cui fidarsi per il canale verso il server. Serve quando il server ha un certificato proprio: **senza, la sonda rifiuta di parlargli** -- ed e' il comportamento giusto, su quel canale passano le chiavi della registrazione. Non esiste un interruttore per disattivare la verifica |
| `SNAP_PROBE_FIRST_ACCESS_FROM` | vuoto | Indirizzi ammessi alla **prima** impostazione della password, oltre al loopback. Vuoto = solo dalla postazione della sonda |
| `SNAP_PROBE_SCAN_INTERFACE` | vuoto | Interfaccia da cui devono partire le scansioni (`-e` di nmap), col nome che usa nmap (`nmap --iflist`). Vuoto = come decide il sistema. Vale con i socket raw |
| `SNAP_PROBE_SCAN_SOURCE_IP` | vuoto | Indirizzo di partenza delle scansioni (`-S` di nmap) |
| `SNAP_PROBE_NMAP` | vuoto | Percorso dell'eseguibile di nmap, se non e' nel PATH |
| `SNAP_PROBE_NMAP_SCRIPT_DB` | vuoto | Percorso di `script.db`, l'indice degli script NSE, se non si trova accanto a nmap |

---

## 9. Diagnostica

| Sintomo | Causa probabile | Intervento |
|---|---|---|
| **L'interfaccia della sonda chiede una password che non e' stata mai impostata** | Prima apertura: la password va scelta | Aprire `http://127.0.0.1:5510/` **dalla postazione della sonda** e scegliere la password; dalla rete la scelta iniziale e' rifiutata (capitolo 6.0) |
| **Accesso alla sonda bloccato** | Cinque tentativi falliti | Attendere 15 minuti: il blocco scade da se', non serve riavviare la sonda |
| **Le finestre di avvio si aprono e restano vuote** | Installazione precedente alla correzione: l'uscita dei componenti veniva deviata sui file di log e la finestra non poteva mostrare nulla | Nessun guasto: i servizi erano in ascolto. Aggiornare lo script di avvio; verificare con `logs\snap-server.log` oppure aprendo `http://127.0.0.1:5500/` |
| **Dalla rete la console non si apre, in locale si'** | Firewall di Windows (blocca l'ingresso per difetto), oppure server avviato senza `-ServerHost` | Avviare con `.\start.ps1 -ServerHost <indirizzo>`; se serve, creare la regola del firewall come amministratore (capitolo 3.1-bis) |
| La sonda segnala *Server non raggiungibile* | Indirizzo errato, server arrestato, blocco di rete | *Verifica server* nell'interfaccia della sonda; correggere l'indirizzo in *Configurazione* |
| Registrazione rifiutata con *token gia' utilizzato* | Token consumato da una registrazione precedente | Emettere un nuovo token dalla scheda della sonda |
| Registrazione rifiutata con *token scaduto* | Oltre 24 ore dall'emissione | Emettere un nuovo token |
| Registrazione rifiutata con *busta non valida* | Codice sonda o token non corrispondenti | Ricopiare il pacchetto integralmente |
| Conferimento rifiutato con *auth_failed* | Sonda revocata, oppure orologi non allineati oltre 5 minuti | Verificare lo stato nella console; allineare l'orologio del dispositivo |
| La coda cresce senza conferimenti | Server non raggiungibile o raccolta sospesa | Pagina di stato della sonda e diario locale |
| Dati non aggiornati nella dashboard | Contesto tenant diverso da quello della sonda | Verificare il tenant selezionato nella barra superiore |
| Orari inattesi | Fuso orario del tenant | *Tenant > fuso orario*; tutti gli istanti sono convertiti a quel fuso, comprese le giornate dei grafici |
| La sonda mostra orari diversi dal server | Fuso non ancora riallineato sulla sonda | La sonda recepisce il fuso al contatto successivo: attendere un ciclo oppure usare *Verifica server* e *Conferisci ora* |
| *Il token di sicurezza del modulo e' scaduto* | Sessione scaduta o pagina rimasta aperta | Ricaricare la pagina e ripetere l'operazione |
| Utenza bloccata | Cinque tentativi di accesso falliti | Attendere 15 minuti oppure reimpostare la password dalla sezione Utenti |
| **Il modulo di accesso viene richiesto a ogni pagina** | Il cookie di sessione non torna al server | Aprire `http://127.0.0.1:5500/diagnostics/session`: se `cookie_ricevuto` e' falso il cookie viene scartato dal browser (vedere 9.1) |
| **L'accesso viene richiesto dopo pochi secondi di navigazione, con la sonda aperta in un'altra scheda** | Le due interfacce condividono il nome del cookie sullo stesso nome host | Verificare che `nome_cookie` valga `snap_server_session` sulla rotta di diagnostica; se vale `session`, l'installazione e' precedente alla correzione (vedere 9.1, causa 5) |

### 9.1 Accesso richiesto ripetutamente

La sessione e' mantenuta da un cookie firmato. Se il cookie non raggiunge il
server, ogni pagina protetta rimanda al modulo di accesso e anche l'invio delle
credenziali non va a buon fine, perche' senza cookie manca il token di sicurezza
del modulo.

La rotta di diagnostica dichiara la situazione senza esporre dati riservati:

```
http://127.0.0.1:5500/diagnostics/session
```

| Esito | Significato | Intervento |
|---|---|---|
| `cookie_ricevuto: false` | Il browser non invia il cookie | Vedere le cause sotto |
| `cookie_ricevuto: true`, `sessione_con_utente: false` | Cookie presente ma sessione vuota | Effettuare l'accesso |
| `cookie_ricevuto: true`, `secondo_fattore_superato: false` | Manca la verifica MFA | Completare il secondo fattore |
| `nome_cookie` diverso da `snap_server_session` | Nome del cookie non allineato: rischio di collisione con la sonda | Rimuovere l'eventuale `SNAP_SERVER_COOKIE_NAME` dall'ambiente e riavviare |
| tutti veri | Il trasporto e' corretto | L'eventuale problema non riguarda la sessione |

Cause tipiche di un cookie scartato:

1. **Browser integrato nell'editor** (per esempio *Simple Browser* di VS Code):
   la pagina e' servita in un contesto incorporato di origine diversa e i cookie
   con `SameSite=Lax` non vengono inviati. Rimedio consigliato: aprire la console
   in un browser esterno. In alternativa, per l'uso in cornice:

   ```powershell
   $env:SNAP_SERVER_EMBEDDED = "1"      # SameSite=None e X-Frame-Options=SAMEORIGIN
   $env:SNAP_SERVER_COOKIE_SECURE = "0"
   .\start.ps1 -Only server
   ```

   I browser accettano `SameSite=None` solo su connessione sicura: su HTTP
   semplice alcuni continuano a scartare il cookie. La via affidabile resta il
   browser esterno.

2. **Nomi host alternati**: `127.0.0.1:5500` e `localhost:5500` sono due origini
   distinte e hanno cookie separati. Usare sempre lo stesso indirizzo.

3. **Blocco dei cookie**: navigazione con cookie disattivati, oppure estensioni
   che rimuovono i cookie di sessione.

4. **Sessione scaduta**: durata predefinita 120 minuti, modificabile con
   `SNAP_SERVER_SESSION_MINUTES`.

5. **Collisione con il cookie della sonda**: i cookie sono definiti per dominio
   e non distinguono la porta. Server e sonda convivono su `127.0.0.1`: se
   entrambi usassero lo stesso nome di cookie, ogni risposta della sonda
   sovrascriverebbe la sessione del server e l'accesso verrebbe richiesto di
   nuovo dopo pochi secondi di navigazione (la pagina di stato della sonda si
   ricarica da sola ogni 30 secondi). I due applicativi usano percio' nomi
   distinti, `snap_server_session` e `snap_probe_session`, verificabili sulla
   rotta di diagnostica alla voce `nome_cookie`. Se si personalizzano
   `SNAP_SERVER_COOKIE_NAME` e `SNAP_PROBE_COOKIE_NAME`, i due valori devono
   restare diversi fra loro. Dopo l'aggiornamento e' opportuno rimuovere dal
   browser il vecchio cookie `session` di `127.0.0.1`, che non viene piu' usato.

Gli accessi riusciti sono registrati in *Audit & Eventi* come `auth.login` con
l'email dell'utente: l'assenza di tali eventi conferma che le credenziali non
arrivano al server.

Diario del server: uscita standard del processo. Diario della sonda: pagina
*Diario locale* e uscita standard del processo.

---

## 10. Generazione dei manuali in formato Word

I manuali software adottano il carattere **PT Sans Narrow a 19 punti** con gli
stili predefiniti di Word. La conversione dei documenti di `docs/` avviene con:

```bash
python tools/genera_manuale.py                      # tutti i documenti
python tools/genera_manuale.py 05_MANUALE_OPERATIVO.md
python tools/genera_manuale.py --uscita <cartella>
```

I file prodotti sono depositati in `docs/docx/`. Titoli, elenchi, tabelle e
blocchi di codice sono resi con gli stili corrispondenti (Titolo 1..4, Elenco,
Griglia tabella); i blocchi di codice usano un carattere a spaziatura fissa per
restare leggibili.

La stessa convenzione vale nell'interfaccia: i titoli usano PT Sans Narrow, con
PT Sans per corsivo e grassetto corsivo (varianti che la famiglia stretta non
possiede). I caratteri sono serviti dal prodotto, senza richieste a servizi
esterni.

---

## 11. Collaudo dell'interfaccia nel browser

I test automatici non osservano il comportamento del codice eseguito nel
browser. Con server e sonda in esecuzione:

```bash
python -m pip install playwright
python -m playwright install chromium
python tools/collaudo_ui.py
```

Lo script verifica la costruzione delle tabelle, l'efficacia di ricerca,
ordinamento e paginazione, la finestra di conferma e la comparsa delle notifiche,
segnalando eventuali errori JavaScript.

---

## 12. Esecuzione della suite di test

```powershell
.\start.ps1 -Test
```

```bash
./start.sh test
python -m pytest tests -v
python -m pytest tests --cov=server/snapserver --cov=probe/snapprobe
```

I test utilizzano basi dati temporanee: non alterano gli archivi di esercizio.
