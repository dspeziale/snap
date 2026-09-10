<!--
     14_MOTORE_DI_SCANSIONE.md — riprogettazione del motore di scansione
     Autore: Daniele Speziale
     Data creazione: 2026-09-10
     Copyright (c) 2024-26 DS Consulting
     Licenza: MIT
-->

# Motore di scansione: riprogettazione

Conforme a ISO/IEC/IEEE 29148:2018 (§2 requisiti, §3 verifica) e
ISO/IEC/IEEE 15288 (processo di definizione dell'architettura, §4).

## 1. Il requisito, dichiarato dal committente

> «Devo poter fare una scansione /24 in pochi minuti, non ore.»

E, sulla struttura: eseguire le scansioni **in parallelo**; eliminare il *tempo
massimo per host* se non serve; una soluzione **drastica ma robusta**.

## 2. Perche' il motore precedente non poteva riuscirci

Non era un parametro mal tarato: era un'assunzione sbagliata, scritta nel codice.

> «Con `--min-hostgroup` gli host di un compito vengono scansionati in parallelo:
> il tempo di un'ondata e' quello del singolo host, non la somma.»

**Falsa.** Il ritmo di invio di nmap e' governato dal suo controllo di congestione ed
e' **per processo**. Misurato sulla rete del committente, 200 porte per host:

| Bersagli in un processo | Durata | Ritmo |
|---|---|---|
| 1 host | 21,1 s | 9,5 pacchetti/s |
| 4 host | 81,2 s | 9,9 pacchetti/s |

Quattro host costano quattro volte uno: la passata dura quanto la **somma**. Con un
tetto di tempo **per host**, un gruppo grande garantisce che scadano tutti: 24 host da
1000 porte richiedono ~41 minuti di pacchetti mentre ciascuno viene abbandonato a 4
minuti. Esito osservato in esercizio: ondate da 257 s, **zero** host restituiti, 66
volte di seguito sugli stessi indirizzi. Una /24 non finiva mai.

### 2.1 Perche' il ritmo e' cosi' basso

Gli host di questa rete **scartano** i SYN invece di rifiutarli: rispondono al ping in
0,06 s e presentano tutte le 1000 porte come `filtered`. E' la postura piu' diffusa su
una rete di PA. Con il 100% di mancate risposte nmap legge congestione e riduce la
finestra fino a ~10 pacchetti/s. Non c'e' congestione: i bersagli tacciono.

### 2.2 Cosa NON funziona: forzare il ritmo

`--min-rate` alza la banda di dieci volte e **fa perdere porte aperte**. Misurato su
tre host con porte note (13 in totale), 9 porte su tutta la /24:

| Modo | Durata | Porte note trovate |
|---|---|---|
| `--min-rate 500` | 9,5 s | 2 su 13 |
| `--min-rate 500` + `--max-retries 3` | 9,2 s | **0 su 13** |
| adattivo | 33,5 s | **12 su 13** |

Gli esiti forzati non sono nemmeno riproducibili (4/13, poi 2/13, poi 0/13): sotto
raffica i pacchetti vengono scartati in massa. **La velocita' che perde dati non e'
velocita'**, e un inventario con le porte mancanti e' peggio di un inventario lento:
non si sa quali righe manchino.

## 3. La leva che funziona: distribuire le sonde fra gli HOST

Il ritmo adattivo, applicato a **gruppi ampi di host**, resta accurato e non
collassa: nmap gira le sonde su bersagli diversi, quindi nessun bersaglio viene
limitato dal proprio rate limiting e la finestra di congestione resta aperta perche'
qualcuno risponde.

Misurato a **rete libera** sulla /24 del committente, 28 porte per host, contro 33
coppie host-porta accertate aperte in quel momento:

| Gruppo | Durata della /24 | Ritrovate |
|---|---|---|
| 16 | 449 s | 27 su 33 |
| 32 | 444 s | 30 su 33 |
| **64** | **445 s** | **33 su 33** |
| 254 | **91 s** | 19 su 33 |

C'e' un compromesso vero, e va guardato per intero. Fino a 64 il recall **migliora**
con il gruppo (piu' host che rispondono tengono aperta la finestra di congestione di
nmap) mentre il tempo resta lo stesso: quindi fino a la' un gruppo piu' grande e'
gratis. Oltre, il gruppo diventa cinque volte piu' rapido ma **perde il 42% delle
porte aperte**: le sonde in volo superano cio' che il percorso sostiene e le risposte
si scartano.

**64 e' il punto in cui il recall e' ancora pieno.** E' la scelta: un inventario che
perde porte non si sa dove sbaglia, e un dato mancante non si distingue da un dato
assente. Chi volesse la passata rapida a scapito della completezza puo' alzare il
gruppo, ma la perdita va dichiarata, non scoperta.

### 3.1 Un avvertimento sul metodo

Le prime misure di questa riprogettazione erano **contaminate**: la sonda scandiva in
parallelo con i propri processi, e un processo di una prova interrotta era rimasto
vivo nel contenitore. Portavano a conclusioni diverse e sbagliate -- fra cui un ritmo
di 68 sonde/s (vero valore: 16) e la tesi che i gruppi grandi perdano accuratezza
(vero: la perdono solo sotto contesa). Ogni numero di questo documento viene da una
misura a rete libera, ed e' il motivo per cui il motore precedente era sbagliato:
era stato tarato su numeri non verificati.

**Decisione architetturale ARCH-1.** L'unita' di lavoro di una fase di porte e'
*tutti gli host da esaminare x l'elenco di porte del livello*, in UN processo, con il
gruppo di host pari all'intero insieme (`--min-hostgroup`). Non piu' *pochi host x
tutte le porte*, che e' la struttura in cui il tempo si moltiplica per il numero di
host e ciascuno viene abbandonato.

## 4. Il tempo massimo per host: eliminato dalle fasi di porte

**Decisione ARCH-2.** `--host-timeout` non si usa piu' nelle fasi che sondano le
porte. Con un gruppo che copre tutti gli host non esiste piu' "l'host che trattiene il
gruppo": nmap conclude il gruppo nel suo insieme. Il tetto per host, in quella
struttura, non proteggeva da nulla e **causava** il difetto: era la ragione per cui
ogni host veniva abbandonato.

Resta, e con una motivazione propria, nelle fasi che eseguono script su un singolo
servizio (`services`, `deep`, `snmp`, `smb`, `vuln`, `web`): la' un apparato che non
risponde come previsto puo' tenere appeso uno script, e il tetto e' l'unica cosa che
lo ferma.

La rete di sicurezza delle fasi di porte diventa il **tetto di tempo del processo**,
calcolato sul lavoro richiesto (sonde da inviare / ritmo misurato) con margine.

## 5. Parallelismo: dentro un processo, non fra processi

> **SUPERATO DALLA MISURA (vedi § 8-bis).** Questa sezione descrive la scelta
> precedente e resta come storia del ragionamento. Con UN gruppo di 64 host era
> giusta; con molti gruppi nello stesso processo no: 256 host in un processo hanno
> dato **zero porte su 256**, e oltre 500 il processo non termina entro le due ore del
> tetto. Il parallelismo e' tornato **fra** i processi -- fino a trentadue -- perche' il
> budget di pacchetti di nmap e' per processo.

Questa sezione conteneva la decisione opposta -- dividere le porte fra piu' processi,
"cosi' la banda si somma" -- ed e' stata **scartata da una misura**. Vale scriverlo:
era ragionevole in teoria e falsa in pratica.

| Configurazione (9 porte, tutta la /24) | Durata | Porte note trovate | Ritmo |
|---|---|---|---|
| **1 processo, gruppo da 256 host** | **33,5 s** | **12 su 13** | 68 pacchetti/s |
| 3 processi, fette di porte da 3 | 82,3 s | 7 su 13 | 28 pacchetti/s |

Tre processi sono risultati **piu' lenti e meno accurati** di uno. Due effetti
sommati: puntando tutti allo stesso insieme di host alzano il ritmo **per bersaglio**
(che e' la condizione sotto cui le risposte si perdono), e si contendono lo stesso
percorso di rete, che era gia' il collo di bottiglia.

**Decisione ARCH-3.** La fase di porte usa **un solo processo nmap**. Il parallelismo
che conta e' quello che nmap esercita **dentro** il processo, distribuendo le sonde su
tutti gli host del gruppo. Aggiungere processi sulla stessa fase non aggiunge banda:
la sottrae.

Il parallelismo fra processi resta per le fasi che lavorano su **host diversi e
pochi** (servizi, sistema operativo, letture di arricchimento): la' i processi non si
contendono gli stessi bersagli.

## 6. Cosa si scandisce: due livelli

Il costo e' dominato dagli host muti. Su questa rete 142 indirizzi su 256 non hanno
**alcuna** porta aperta fra le prime 1000: scandirle tutte costa ore per non imparare
nulla.

**Decisione ARCH-4.** Due livelli, con cadenze diverse.

| Livello | Porte | Bersagli | Cadenza | Costo atteso su una /24 |
|---|---|---|---|---|
| **Riconoscimento** | 28 porte che identificano un apparato | tutti gli host vivi | ogni ciclo | 7.112 sonde a 16/s = **~7,5 minuti**, misurati |
| **Profondita'** | prime 1000 (o intervallo dichiarato) | i soli host che hanno mostrato un segnale | cadenza lunga | ~27 host = ~28 minuti |

Il conto viene dal ritmo misurato a rete libera (16 sonde/s, un processo, gruppi da
64). Per confronto, le stesse 1000 porte su TUTTI i 254 host sono 254.000 sonde,
cioe' oltre **quattro ore**: e' il motivo per cui i due livelli hanno cadenze diverse,
non una raffinatezza.

Il requisito era «pochi minuti, non ore». Sette minuti e mezzo per una /24 completa e
accurata lo soddisfa; il punto di partenza era **mai** -- la fase girava per ore
restituendo zero host.

Il primo livello e' cio' che il committente chiede: una /24 in pochi minuti. Il
secondo da' la ricchezza, e riguarda poche decine di host invece di 254.

### 6.1 Quali porte, e con quale criterio

Nessuno dei due livelli usa `--top-ports`. Le prime N porte di nmap sono ordinate per
**frequenza statistica su Internet**: meta' sono servizi che su una rete di uffici
non esistono, e mancano invece porte di gestione che qui contano -- Intel AMT su una
postazione, Winbox su un MikroTik, Modbus su un impianto. "Quante porte" non e' un
criterio; lo e' **quali porte, e perche'**.

**Riconoscimento (28 porte).** Quelle che dicono *che cos'e'* un apparato: gestione,
stampa, telefonia, condivisione, banche dati, controllo remoto. Un host che tace su
tutte e' un host muto, e lo si dichiara tale in sette minuti per l'intera subnet
invece che in ore.

**Profondita' (232 porte, in 19 famiglie).** Divise per **famiglia di apparato**,
perche' e' cosi' che si mantengono: chi aggiunge un genere di apparato sa dove mettere
le sue porte, e chi legge sa perche' una porta c'e'.

| Famiglia | Che cosa copre |
|---|---|
| osservate | tutte quelle trovate aperte su questa rete: l'unico dato empirico disponibile, nessuna puo' mancare |
| windows | RPC e le sue porte alte, dominio (Kerberos, LDAP, catalogo globale), amministrazione remota (RDP, WinRM, WSD) |
| linux | accesso, posta, condivisione, stampa, servizi storici ancora aperti su macchine non aggiornate |
| rete | gestione (SSH, Telnet, web, NETCONF), instradamento (BGP), autenticazione degli accessi (RADIUS, TACACS+), porte proprietarie che identificano un costruttore |
| stampa | stampa diretta, IPP, LPD e interfacce di gestione |
| voip, videosorveglianza | telefoni e telecamere, fra gli apparati piu' numerosi e meno aggiornati |
| impianti | Modbus e vicini: un impianto raggiungibile da una rete di utenza e' un riscontro |
| archiviazione, banche_dati | NAS e basi dati esposte |
| fuori_banda | IPMI, WBEM, agenti di monitoraggio e **Intel AMT**, che su una postazione da ufficio e' una gestione completa e indipendente dal sistema operativo |
| desktop_remoto, web_gestione, code, virtualizzazione, copie, trasferimento | il resto della superficie di gestione |
| storici | protocolli aperti solo su macchine mai aggiornate: trovarli **e'** il riscontro |

**Il costo.** Con 232 porte invece di 1000 la passata di profondita' su ~27 host con
un segnale scende da ~28 minuti a **~6,5**. E' la stessa aritmetica del livello di
riconoscimento: il costo e' host x porte, e le porte si scelgono.

## 7. Requisiti verificabili

| ID | Requisito | Verifica |
|---|---|---|
| SR-100 | Una passata di riconoscimento su una /24 si completa in meno di dieci minuti | misurato: 445 s a rete libera |
| SR-101 | La passata di riconoscimento non perde porte aperte note | misurato: 33 su 33 con gruppi da 64 |
| SR-102 | Nessuna fase di porte usa un tetto di tempo per host | controllo sugli argomenti di nmap |
| SR-103 | Le sonde in volo restano sotto la soglia oltre la quale il percorso ne scarta | dimensione del gruppo dichiarata e misurata (GRUPPO_HOST) |
| SR-104 | Un host che nmap non riesce a esaminare non blocca la coda ne' viene scartato | attesa progressiva, gia' in esercizio |
| SR-105 | Gli esiti di piu' fette si uniscono senza perdere ne' duplicare porte | prova sull'unione |

## 7-bis. Cosa resta da esplorare

Il compromesso fra gruppo e recall e' misurato in quattro punti (16, 32, 64, 254) e
64 e' il piu' grande fra quelli con recall pieno. **Non e' stato misurato fra 64 e
254**: se un gruppo da 96 o 128 mantenesse il recall pieno, il tempo potrebbe
scendere sotto i sette minuti -- a 254 il tempo crolla a 91 s, quindi il guadagno
potenziale e' grande. La prova era avviata ed e' stata interrotta dalla
ricostruzione del contenitore; va rifatta a rete libera.

Chi la rifa': lo schema e' quello di §3, confrontando il ritrovamento delle coppie
host-porta accertate aperte nello stesso momento. Serve la rete libera -- con la
sonda che scandisce in parallelo il gruppo da 254 passa da 19 a 14 su 33, e le
conclusioni si invertono.

---

## 8-bis. Il motore a due fasi: ricognizione, poi raffica per nodo

### 8-bis.1 Tre strutture, tre misure

Questa parte del prodotto e' stata rifatta tre volte, e ogni volta la ragione e' stata
una misura sul campo. Vale la pena tenerle tutte, perche' la conclusione non e'
intuitiva.

| Struttura | Esito misurato |
|---|---|
| **Un processo per host**, un host per ciclo | 202 s per host: corretta ma troppo lenta -- su centinaia di indirizzi non finisce |
| **Un processo con TUTTI gli host**, a gruppi di 64 | veloce, e su un gruppo solo con recall pieno (33 porte su 33). Ma: **256 host in un processo -> ZERO porte su 256**; oltre 500 host -> il processo **non termina entro le due ore** del tetto e la fase scade senza produrre nulla |
| **Un processo per host, fino a 32 insieme** (attuale) | 3,3 s per host con le porte di riconoscimento, ~24 s con `-A`. Recall pieno, tempo prevedibile |

**La causa e' una sola, e spiega tutte e tre le righe:** il budget di pacchetti e la
finestra di congestione di nmap sono **per processo**. Dividerli fra molti host
stringe la finestra su ognuno, e su una rete che filtra -- la postura normale di una
rete di PA -- le porte vere passano per **filtrate**. Non e' un errore di
configurazione: e' cio' che nmap fa quando gli si chiede troppo in un colpo.

La conseguenza sul progetto e' che il parallelismo deve stare **fuori** dal processo,
nel pool: trentadue processi da pochi secondi, non un processo da due ore.

### 8-bis.2 Fase 1 -- chi risponde

`-sn -PE -PS... -PA80 -PR` per subnet, con il proprio tempo per host breve. Dice quali
indirizzi rispondono, il MAC dove ARP arriva, il nome host dove il DNS lo dice. Non
guarda porte: e' cio' che la rende rapida.

### 8-bis.3 Fase 2 -- la raffica (`raffica`)

Un processo per nodo, con tutto quello che nmap sa fare:

- **`-A`**: versione dei servizi, rilevamento del sistema operativo, script `default`,
  traceroute;
- **~234 porte** (riconoscimento + profondita' in un colpo solo): su un host per
  processo il budget e' tutto suo, quindi si chiede tutto subito;
- **29 script NSE curati** per famiglia di servizio (TLS, HTTP, SMB, SSH, FTP,
  database, stampa, malware), scritti come `default,<catalogo>` perche' `--script` da
  solo sostituirebbe il set che `-A` porta con se';
- **il prefisso `+`** su quasi tutti: forza lo script anche dove nmap non ha
  riconosciuto il servizio atteso. Non e' decorativo -- questo prodotto trova
  interfacce web sulla 7070 e sulla 8443 e agenti su porte spostate, e senza il `+`
  gli script non partirebbero **proprio dove servono**;
- **`--script-args http.useragent=...`**: lo user-agent si dichiara, perche' nei log
  del cliente si deve leggere chi ha fatto la richiesta.

Una raffica riuscita **soddisfa** le fasi porte, servizi e sistema operativo
(`FASI_COPERTE_DALLA_RAFFICA`): il contratto del profilo resta espresso nelle tre
fasi -- cosi' un nodo profilato prima che la raffica esistesse resta valido -- ma si
ottiene in una passata di secondi.

### 8-bis.4 Il confine di sicurezza, scritto nel codice

Le categorie NSE non sono equivalenti, e su una rete di produzione della PA il confine
non e' un'opinione: `brute` blocca gli account e riempie i log, `dos` interrompe i
servizi, `exploit` e `fuzzer` li corrompono. Un incidente causato da uno strumento di
**inventario** e' inaccettabile, ed e' anche una violazione dell'autorizzazione con cui
si scansiona.

- **Ammesse**: `default`, `safe`, `version`, `discovery`, e i controlli `vuln` che si
  limitano a verificare.
- **Vietate**: `brute`, `dos`, `exploit`, `fuzzer`, `intrusive`
  (`CATEGORIE_NSE_VIETATE`), piu' un elenco di script per nome
  (`SCRIPT_NSE_VIETATI`). Un test cerca quegli script negli argomenti di **tutte** le
  fasi, non solo della raffica.
- **Rifiutati anche gli script ESTERNI** (`vulners`, `whois-ip`, `shodan-api`,
  `http-virustotal`): su una rete senza uscita non funzionano, e dove funzionassero
  manderebbero **fuori** l'inventario dei servizi del cliente. E' una fuga di
  informazioni, non un arricchimento. La correlazione CVE, quando servira', va fatta
  con una fonte **offline**.

### 8-bis.5 Nessun nodo si scarta sulla parola di una sola passata

**Il difetto piu' grave che questo prodotto abbia avuto**, e la sua correzione.

In esercizio `10.10.60.1` -- il firewall che fa da gateway a una rete di utenza, con la
53/tcp aperta servita da Unbound -- e' stato **scartato** come "nessuna informazione
dopo le fasi ports, snmp". Lo stesso nmap, sullo stesso host, dalla stessa sonda, con
le stesse porte, lo trova in **3,3 secondi**. La differenza era il contesto: quell'host
era uno di 256 in un solo processo.

Perdere un apparato vero non e' un dato mancante: e' un'**affermazione falsa**, e
nessuno se ne accorge, perche' non si vede cio' che non c'e'. Da qui:

1. prima di scartare, il nodo si riesamina **da solo** (`_riesamina_da_solo`);
2. l'esito ha **tre valori** e vanno tenuti distinti: `trovato` (si fondono le prove e
   il nodo resta), `muto` (si scarta), `non_verificato` (**non** si scarta). Confondere
   gli ultimi due e' precisamente l'errore che fa sparire un apparato;
3. il nodo si marca "verificato" **solo se la verifica e' avvenuta**. La prima versione
   lo marcava prima di tentarla, e una verifica che non partiva -- esecutore saturo,
   tempo scaduto -- bruciava l'unica occasione: misurato su `10.10.60.101`;
4. **i nodi gia' persi si recuperano** (`_recupera_i_muti`), in qualunque stato si
   trovino. Un nodo scartato che la ricognizione delle presenze rivede torna
   "candidato" ma con la fase porte gia' segnata: nessuna coda lo riprende piu', e
   guardare solo gli scartati avrebbe lasciato fuori proprio quel caso.

Quattro verifiche per ciclo, una volta per nodo, e sempre dentro il perimetro.

---

## 8-ter. L'archivio della sonda: da SQLite a PostgreSQL

### 8-ter.1 Perche'

La sonda scriveva su un file SQLite nel volume, con un lucchetto in memoria a
serializzare i thread. Due difetti che con trentadue thread di scansione si sentono:

1. **il parallelismo si fermava all'archivio**: un file non regge scritture
   concorrenti, e il lucchetto le metteva in fila;
2. **un file che si corrompe e' la perdita di tutto il raccolto**, e l'archivio della
   sonda e' una **coda di conferimento** che deve sopravvivere a giorni di server
   irraggiungibile su un apparato lasciato in sede.

Il contenitore PostgreSQL della sonda era gia' previsto e non usato, e le dipendenze
(`SQLAlchemy`, `psycopg`) erano gia' nel file dei requisiti: il porting era
predisposto.

### 8-ter.2 Come, e perche' cosi'

L'archivio ha **oltre sessanta punti di SQL** scritti sull'interfaccia di `sqlite3`.
Riscriverli tutti avrebbe significato sessanta occasioni di sbagliare, in un archivio
dove un errore silenzioso e' dato perso. Si e' scritto invece un **adattatore**
(`snapprobe/db.py`: `Connessione`, `Cursore`, `Riga`) che parla come `sqlite3` e scrive
su PostgreSQL: le interrogazioni restano quelle verificate, e cambia solo lo strato che
le esegue. I punti convertiti a mano sono tre, non sessanta.

`snapprobe/db.py` **rispecchia** `snapserver/db.py` invece di importarlo: sonda e
server sono due applicativi su macchine diverse e non condividono codice. La
duplicazione e' deliberata, e la regola e' che una correzione qui va portata anche la'.

Cio' che ha richiesto una traduzione vera:

| SQLite | PostgreSQL |
|---|---|
| `INTEGER PRIMARY KEY AUTOINCREMENT` | `INTEGER GENERATED BY DEFAULT AS IDENTITY` |
| `cursor.lastrowid` | `RETURNING id` |
| `INSERT OR IGNORE` | `ON CONFLICT DO NOTHING` (righe toccate 0 = la chiave era di un altro: la prenotazione atomica dei bersagli regge su questa semantica) |
| `DO UPDATE SET runs = runs + 1` | `runs = scan_state.runs + 1` -- il nome da solo e' **ambiguo** fra tabella e `excluded`, e PostgreSQL lo rifiuta |
| `datetime('now', '-2 hours')` | istante calcolato in Python e passato come parametro |
| `PRAGMA table_info`, `sqlite_master` | `information_schema` |
| `PRAGMA wal_checkpoint`, dimensione dei file | `pg_database_size`, e `VACUUM` che **non** restituisce spazio al sistema (vedi sotto) |

**Due utenze, minimo privilegio**, come sul server: il **proprietario** crea e migra lo
schema all'avvio, l'**applicativo** legge e scrive i dati e non puo' cambiare la
struttura -- quindi un difetto del programma non puo' cancellare una tabella.

**Il lucchetto c'e' ancora**, e va spiegato: serviva a SQLite, e con PostgreSQL non
servirebbe. Si e' mantenuto per fare **una** modifica per volta -- il comportamento
resta quello verificato. Togliendolo, il pool servirebbe i trentadue thread davvero in
parallelo: e' il passo successivo, da fare misurando, non insieme al cambio di
archivio.

### 8-ter.3 I dati del vecchio archivio si importano

Un porting che perde i dati non e' un porting, e' un azzeramento. Nel file SQLite di
una sonda in esercizio ci sono tre cose che non si rifanno da zero senza intervento
umano: la **registrazione** (senza, la sonda non e' piu' riconosciuta e va registrata a
mano dalla console), la **coda** di conferimento, e lo **stato di nodi e fasi** (su
78.000 indirizzi, giorni di lavoro).

`ProbeStore.importa_da_sqlite` copia tutto al primo avvio. Misurato su
un'installazione reale: **80.057 righe importate**, fra cui 79.000 nodi e la
registrazione. Il file resta come copia, rinominato, e non viene piu' guardato.

Due dettagli che sono costati un tentativo ciascuno:

- **il criterio di "archivio non ancora in uso" e' la sola registrazione.** Contando
  anche i nodi, un'importazione interrotta a metà (nodi copiati, impostazioni no)
  risultava "in uso" al riavvio e non riprendeva -- lasciando la sonda **muta**;
- **l'importazione e' ripetibile**: le impostazioni si sovrascrivono (quelle del
  vecchio archivio sono le vere; le poche scritte dall'avvio sono valori predefiniti),
  il resto si salta se c'e' gia'. Senza, una sola collisione su `settings` interrompeva
  l'intera importazione -- ed e' quello che e' successo.

### 8-ter.4 Cose da sapere in esercizio

- **`VACUUM` non restituisce spazio al sistema operativo**: rende riutilizzabile quello
  delle righe morte dentro il database. `compact()` percio' restituisce quasi sempre
  zero, e lo dichiara. `VACUUM FULL` lo restituirebbe, ma richiede un lucchetto
  esclusivo: su una coda di conferimento che trentadue thread stanno scrivendo non si
  prende di iniziativa.
- **La sonda attende l'archivio all'avvio** (fino a 90 secondi, riprovando): il
  contenitore della base dati puo' partire dopo, e un errore all'avvio manderebbe la
  sonda in ciclo di riavvio su un apparato in sede, senza nessuno che guardi.
- **Con il compose per Docker Desktop non si riavvia la sola sonda.** La base dati usa
  la RETE della sonda (`network_mode: "service:snap-probe"`), quindi riavviando solo
  lei la base dati resta senza rete. Si riavvia l'insieme:
  `docker compose -f docker-compose.yml -f docker-compose.desktop.yml restart`.

---

## 8. Cosa si conserva del motore precedente

Non e' una riscrittura da zero di tutto: la scoperta degli host (ping sweep, 0,06 s
per quattro host), la regola di ammissione, il conferimento, le prenotazioni fra
thread, l'attesa progressiva sugli host non esaminabili e le fasi di arricchimento
restano. Cambia **come si sondano le porte**, che e' il punto in cui il motore non
riusciva.
