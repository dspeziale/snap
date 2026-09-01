# snap - Controlli periodici, metriche e andamenti

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT

Documento di progetto redatto secondo ISO/IEC/IEEE 29148:2018 (requisiti),
ISO/IEC/IEEE 15288:2015 (processi di ciclo di vita) e ISO/IEC/IEEE 19510:2013 per la
rappresentazione dei flussi. Vincoli di riservatezza e sicurezza: Regolamento (UE)
2016/679 (GDPR), Regolamento (UE) 2024/2847 (CRA), Direttiva (UE) 2022/2555 (NIS2),
ETSI EN 303 645, EN 50649:2024.

---

## 1. Portata

I controlli periodici rispondono a una domanda che l'inventario di rete non copre:
**i servizi che ci interessano stanno funzionando?** L'inventario dice quali
dispositivi esistono e come sono fatti; un controllo dice se un endpoint risponde
come deve, adesso e nel tempo.

Tre generi, tutti su bersagli dichiarati dall'operatore:

| Genere | Verifica | Misure prodotte |
|---|---|---|
| `presence` | il bersaglio risponde in rete (nmap in sola scoperta) | `reachable` (0/1), latenza |
| `ports` | una o piu' porte risultano aperte (TCP per connessione, UDP con nmap) | `port.<proto>/<num>` (0/1), `port_latency_ms.<proto>/<num>`, `ports_open`, `ports_total`, `all_open`, latenza |
| `http` | un endpoint risponde con lo stato atteso e supera le verifiche sul contenuto JSON | ogni valore numerico e testuale della risposta, latenza |

Il caso portato in specifica e' un endpoint di salute:

```json
{"application": "Texa", "database": "connected", "status": "ok",
 "version": "1.2.1", "metrics": {"cpu_percent": 3.3, "ram_percent": 44.1, ...}}
```

---

## 2. Decisioni assunte

| ID | Decisione | Motivo |
|---|---|---|
| CT-01 | I controlli li **esegue la sonda**, li **definisce e governa il server** | I bersagli stanno nella rete del cliente e il server non apre connessioni verso l'interno (R2). Provare dal server darebbe una risposta falsa rispetto a cio' che la sonda vede |
| CT-02 | Le definizioni viaggiano nella **configurazione cifrata** a ogni contatto; gli esiti tornano come record di conferimento del tipo `check_results` | La sonda non interroga il server per sapere cosa fare, e il contratto di conferimento e' gia' estensibile per tipo di record |
| CT-03 | Un bersaglio di controllo **non e' soggetto al perimetro di scansione** | Non e' una scoperta di rete: e' un indirizzo o un nome host che l'operatore ha dichiarato espressamente. Il perimetro impedisce alla sonda di esplorare cio' che nessuno le ha chiesto; qui l'incarico e' esplicito |
| CT-04 | Le verifiche sul contenuto sono **dichiarative** (percorso, operatore, valore atteso) e conservate con il controllo | Un endpoint di salute risponde 200 anche quando dichiara `database: disconnected`: il codice di stato non basta, e la regola non deve stare nel codice della sonda |
| CT-05 | Un controllo periodico puo' usare **solo GET e HEAD** | Un controllo che modificasse lo stato del bersaglio cambierebbe cio' che verifica |
| CT-06 | Tre esiti distinti: `ok`, `fail` (disservizio del bersaglio), `error` (controllo non eseguibile) | Un incidente aperto per un errore della sonda manderebbe un operatore a cercare un guasto dove non c'e' |
| CT-07 | L'incidente si apre dopo **N fallimenti consecutivi** dichiarati per controllo, contati sugli esiti conservati e non su un contatore | Un singolo fallimento su una rete reale e' rumore. Un contatore andrebbe fuori sincrono a ogni riavvio o conferimento fuori ordine; gli esiti no |
| CT-08 | ~~Gestione autonoma o con operatore, scelta per controllo~~ **sostituita da CT-17** | Chiedeva una decisione al momento sbagliato: quando si definisce il controllo non si sa ancora se il disservizio sara' un singhiozzo o un guasto |
| CT-17 | Il workflow e' **sempre automatico**; una **seconda soglia**, piu' alta di quella di apertura, **attiva un operatore** e da quel momento impedisce la chiusura automatica | Un disservizio breve si esaurisce da solo e non deve disturbare nessuno; uno che dura va guardato da una persona. La soglia sposta la decisione dal momento della definizione al momento in cui i fatti la rendono possibile |
| CT-18 | Il recapito dell'operatore e' quello indicato sul controllo; in mancanza, l'**email di riferimento del tenant**; in mancanza di entrambi l'attivazione avviene comunque, senza recapito, e lo dichiara | Un incidente che aspetta qualcuno che nessuno ha avvisato e' peggio di un incidente senza recapito dichiarato |
| CT-19 | Ogni momento del workflow produce una **notifica accodata**, spedita da un processo a se' con ritentativi | Le notifiche nascono dentro il conferimento di un lotto: un server di posta lento bloccherebbe l'ingest di una sonda, e uno irraggiungibile lo farebbe fallire. La coda rende anche visibile cio' che non e' stato recapitato |
| CT-20 | La posta usa la **libreria standard** (`smtplib`), configurata dalle impostazioni di sistema; senza configurazione le notifiche restano in attesa | Nessuna dipendenza aggiunta. Un workflow che smette di tracciare i propri passaggi perche' manca la posta perderebbe informazione utile |
| CT-09 | Il tempo massimo di un controllo deve stare **sotto la sua cadenza** | Diversamente un'esecuzione lenta si sovrappone alla successiva |
| CT-10 | Gli esiti vengono **scomposti in punti di misura** conservati come serie storica, numeri e testi nella stessa tabella | Una risposta conservata come testo non permette di rispondere a "l'uptime cresce o il servizio si riavvia?" senza rileggere e interpretare migliaia di risposte |
| CT-11 | Le misure sono indicizzate **per porta**, non per posizione nell'elenco | Una serie indicizzata per posizione cambia significato appena si aggiunge o si toglie una porta dalla definizione |
| CT-12 | Una chiave che comincia con `_` nel contenuto prodotto **non diventa una misura** | Tiene fuori dalle serie i testi che cambiano a ogni esecuzione senza dire nulla di nuovo, come "aperta in 9 ms" accanto alla misura del tempo |
| CT-13 | La **prova immediata** di un controllo passa da un comando alla sonda, non da un'esecuzione sul server | Vale CT-01. L'esito torna entro un giro di agente: la configurazione precede i comandi, quindi un controllo creato un istante prima e' comunque eseguibile |
| CT-14 | I grafici sono disegnati in **SVG da un modulo del progetto**, senza librerie esterne | Il progetto non introduce dipendenze senza averlo concordato, e una spezzata con banda di riferimento e lettura puntuale si disegna in poche decine di righe |
| CT-15 | Una serie **costante** non riceve un grafico ma una riga; una serie **binaria** riceve la percentuale di campioni positivi | Una retta orizzontale occupa spazio senza aggiungere nulla, e per una serie 0/1 l'informazione e' la disponibilita', non la media |
| CT-24 | L'ascissa di un grafico e' il **tempo**, non la posizione del punto nell'elenco | Distribuire i punti a passo costante fa sembrare continuo un periodo che non lo e': due misure a distanza di un mese finiscono affiancate. Con un asse temporale il periodo senza dati resta largo quanto e' davvero |
| CT-25 | Le serie **percentuali** hanno il tetto a 100 e un fondo scelto fra gradini dichiarati (95, 98, 99...), con almeno un punto percentuale di scala | Un asse che si stringe sui dati trasforma nove decimi di differenza in una montagna russa; uno che parte da zero appiattisce tutto. I gradini danno una scala confrontabile fra un mese e l'altro, che e' cio' che serve per dire se sta migliorando |
| CT-26 | Le **fasce dei periodi senza misure** si disegnano solo dove la cadenza attesa e' dichiarata | In una serie di conteggi -- porte aperte per giorno -- un giorno assente vale zero, non "non misurato": disegnarci sopra una fascia direbbe il falso. Chi costruisce la serie sa quale dei due casi e' |
| CT-28 | Il tracciato e' una **linea sottile su reticolo completo**, senza area piena; il velo sotto la linea resta solo nelle miniature | Chiesto dall'operatore con un riferimento visivo. In un grafico grande l'area copre il reticolo senza aggiungere informazione, e con una scala che non parte da zero suggerisce una grandezza che non c'e'; in una miniatura alta sessanta pixel, invece, e' quello che rende leggibile l'andamento |
| CT-27 | Il grafico si **ridisegna alla larghezza reale** del contenitore | Stirare un disegno di misura fissa deforma il testo e i tratti in orizzontale: si vedeva, e faceva sembrare approssimativo un dato che non lo era |
| CT-21 | I dati da memorizzare e mostrare si **scelgono per controllo**, come elenco di percorsi; elenco vuoto significa **tutti** | Su un endpoint prolisso la maggior parte dei valori non interessa a nessuno: il numero di core logici o il totale del disco riempiono la serie storica e la pagina. Il valore predefinito resta "tutto", cosi' nessun controllo esistente cambia comportamento |
| CT-22 | I percorsi si presentano come **caselle da spuntare, ricavate dall'ultima risposta ricevuta**, con il valore corrente accanto | Chi definisce un controllo non sa a memoria come si chiamano i campi dentro un JSON scritto da altri, e un percorso sbagliato non da' errore: semplicemente non conserva nulla. Il valore accanto e' cio' che rende la scelta possibile: `metrics.5` non dice niente, `metrics.5 = 41.2` si' |
| CT-23 | Restringere la scelta **non cancella** le misure gia' conservate: le esclude dalla vista | Distruggere uno storico per una preferenza di presentazione non e' reversibile. Chi vuole liberare spazio lo chiede esplicitamente |
| CT-16 | Il riquadro degli incidenti nella dashboard compare **solo quando ce ne sono** | Un pannello che dice "nessun incidente" occupa la parte migliore dello schermo per non dire nulla, e quando qualcosa non va non si distingue dal fondo |

---

## 3. Requisiti

| ID | Requisito |
|---|---|
| SR-80 | L'operatore deve poter dichiarare un bersaglio indicando un indirizzo IP oppure un nome host, con nome e descrizione |
| SR-81 | Un valore composto di soli numeri e punti che non sia un indirizzo valido deve essere rifiutato, non accettato come nome host |
| SR-82 | A un bersaglio si devono poter associare piu' controlli, ciascuno con genere, cadenza, tempo massimo, gravita' e soglia di apertura dell'incidente |
| SR-83 | Il sistema deve conservare **tutti** gli esiti dei controlli, con esito, latenza, dettaglio e risposta ricevuta (accorciata) |
| SR-84 | Il sistema deve conservare i valori ricavati dalle risposte come serie storica interrogabile, numerici e testuali |
| SR-85 | Il workflow deve aprire un incidente al superamento della soglia, consentirne la presa in carico e la risoluzione da parte di un operatore, e tracciare ogni passaggio di stato |
| SR-86 | Il workflow deve chiudere l'incidente da se' al ritorno alla normalita'; superata la soglia di attivazione dell'operatore deve invece annotare il rientro e restare aperto |
| SR-92 | La soglia di attivazione dell'operatore non puo' essere inferiore a quella di apertura dell'incidente |
| SR-93 | Ogni momento del workflow deve produrre una notifica al recapito competente, conservata con il proprio esito di recapito |
| SR-94 | Una notifica non recapitata deve restare visibile con il proprio errore e non essere ritentata all'infinito |
| SR-95 | La sonda deve poter azzerare il proprio archivio, con e senza la registrazione, previa conferma digitata e previa quiescenza delle scansioni in corso |
| SR-87 | Un controllo deve poter essere provato immediatamente, con l'esito visibile nella pagina senza ricaricarla a mano |
| SR-88 | L'interfaccia deve mostrare l'andamento nel tempo delle misure raccolte e, nella dashboard, la situazione dei controlli con gli incidenti aperti |
| SR-89 | Le etichette temporali dei grafici devono essere convertite nel fuso del tenant, come ogni altra data mostrata |
| SR-89a | Il grafico della disponibilita' deve rappresentare l'intero periodo richiesto, non il solo intervallo misurato, e deve distinguere visivamente i giorni senza esecuzioni |
| SR-89b | I grafici devono essere percorribili da tastiera, con lettura del valore puntuale, e restare leggibili nei due temi |
| SR-90 | Un esito il cui controllo e' stato rimosso, o malformato, non deve rendere intrasmissibile il lotto: si salta contandolo |
| SR-91 | I colori dell'interfaccia devono garantire un rapporto di contrasto di almeno 4,5:1 per il testo normale in entrambi i temi |
| SR-96 | L'operatore deve poter scegliere, per un controllo su endpoint, quali dati della risposta memorizzare e mostrare; in mancanza di scelta si memorizzano tutti |
| SR-97 | I percorsi selezionabili devono essere presentati all'operatore ricavandoli dalla risposta effettivamente ricevuta, con il valore corrente; un percorso scelto ma assente dalla risposta non deve produrre errore |
| SR-98 | La restrizione della scelta non deve cancellare le misure gia' conservate, e la vista filtrata deve dichiararlo |

---

## 4. Modello dei dati

```
check_targets ──1:N──> checks ──1:N──> check_results ──1:N──> check_metrics
                         │
                         └──1:N──> check_incidents ──1:N──> check_incident_events
```

| Tabella | Contenuto |
|---|---|
| `check_targets` | bersagli dichiarati: nome, indirizzo o nome host, descrizione, attivazione |
| `checks` | definizioni: genere, configurazione (JSON), cadenza, tempo massimo, gravita', soglia, gestione autonoma |
| `check_results` | esiti: istante, stato, latenza, dettaglio, risposta accorciata, sonda che ha eseguito |
| `check_metrics` | punti di misura: nome, valore numerico oppure testuale, istante, esito di provenienza |
| `check_incidents` | incidenti: stato, gravita', conteggio fallimenti, presa in carico, risoluzione |
| `check_incident_events` | passaggi di stato: azione, autore (sistema od operatore), nota |

Sulla sonda, `check_state` conserva l'ultima esecuzione di ciascun controllo: la
cadenza vale anche dopo un riavvio e senza dipendere dal server.

---

## 5. Flusso (ISO/IEC/IEEE 19510)

```
OPERATORE            SERVER                        SONDA                 BERSAGLIO
    │                   │                            │                       │
    ├─ dichiara ───────>│                            │                       │
    │  bersaglio        │                            │                       │
    ├─ definisce ──────>│                            │                       │
    │  controllo        │                            │                       │
    │                   │<── battito ────────────────┤                       │
    │                   ├── configurazione ─────────>│                       │
    │                   │   (definizioni)            │                       │
    │                   │                            ├── verifica ──────────>│
    │                   │                            │<── risposta ──────────┤
    │                   │<── lotto (check_results) ──┤                       │
    │                   ├─ conserva esito            │                       │
    │                   ├─ ricava le misure          │                       │
    │                   ├─ valuta la soglia          │                       │
    │                   │  └─ apre/chiude incidente  │                       │
    │<─ incidente ──────┤                            │                       │
    ├─ prende in carico >│                           │                       │
    ├─ risolve ────────>│                            │                       │
```

La prova immediata inserisce un comando `check_now`, consegnato nella risposta al
battito successivo: la sonda esegue subito, senza attendere la cadenza.

---

## 6. Verifiche sul contenuto JSON

Il percorso usa il punto per scendere negli oggetti e l'indice per gli elenchi
(`metrics.uptime`, `items.0.name`) -- la stessa notazione con cui le misure vengono
nominate, cosi' cio' che si controlla e cio' che si misura si chiamano nello stesso
modo.

| Operatore | Significato | Nota |
|---|---|---|
| `eq` / `ne` | uguale / diverso | confronto come testo |
| `contains` | contiene | sottostringa |
| `gt` / `lt` | maggiore / minore | numerico; se il valore non e' confrontabile la verifica non e' soddisfatta e lo dichiara |
| `exists` / `absent` | presente / assente | distingue "assente" da "nullo" |

---

## 7. Scelta dei dati da memorizzare e mostrare

Di una risposta si conserva, per difetto, tutto cio' che e' misurabile: fino a 60
punti per esito. Su un endpoint prolisso finiscono in serie storica anche valori che
non interessano a nessuno, e la pagina degli andamenti si riempie di riquadri che non
si guardano. Per questo la scelta e' **per controllo** (CT-21).

**Come si esprime.** Un elenco di percorsi, nella stessa notazione delle verifiche
(`status`, `metrics.uptime`, `items.0.name`): un solo modo di nominare le cose.
Elenco vuoto significa "tutti", che e' il comportamento precedente e resta il
predefinito -- nessun controllo esistente cambia comportamento.

**Come si compila.** Nella scheda *Definizione* del controllo l'elenco dei percorsi
disponibili arriva da due fonti (CT-22):

1. l'**ultima risposta ricevuta**, scomposta con la stessa funzione che ricava le
   misure: mostra tutto cio' che l'endpoint restituisce davvero, comprese le voci mai
   conservate, che vengono marcate come *nuove*;
2. i **nomi gia' in archivio**, che coprono il caso di un endpoint che oggi risponde
   diversamente o non risponde: i dati raccolti per settimane non devono sparire
   dall'elenco.

Accanto a ciascun percorso compare il valore corrente. Un campo di testo separato
accetta percorsi scritti a mano, per un dato che l'endpoint restituisce solo in certe
condizioni -- un errore, una coda -- e che quindi non compare fra le caselle; i
percorsi scelti ma assenti dall'ultima risposta vengono ripresentati in quel campo,
altrimenti il salvataggio successivo li perderebbe in silenzio.

**Cosa la scelta non fa.**

| | |
|---|---|
| Non cancella | Le misure escluse restano nell'archivio e scompaiono soltanto dalla vista (CT-23). La scheda delle metriche dichiara che la vista e' limitata |
| Non tocca la risposta conservata | L'esito conserva la risposta accorciata per intero: da essa le misure si possono ricavare di nuovo, anche per un percorso aggiunto in seguito |
| Non esclude la latenza | Il tempo di risposta non viene dalla risposta ma dall'esecuzione, ed e' la sola misura disponibile per qualunque genere di controllo |
| Non produce errori per un percorso assente | Un dato intermittente si sceglie prima che compaia: l'esito viene conservato comunque |

**Recupero dagli esiti.** La funzione che ricava le misure dagli esiti che ne sono
privi legge la scelta di ciascun controllo: un recupero non deve reintrodurre i dati
che l'operatore ha escluso.

**Generi non interessati.** Presenza in rete e apertura delle porte producono le
misure che la loro definizione implica -- raggiungibilita', una misura per porta
dichiarata -- e non offrono la scelta: non c'e' nulla da scegliere.

---

## 8. Osservazioni dal campo

**8.1 Il rumore delle misure indicizzate per posizione.** La prima versione del
controllo porte produceva le serie `ports.0.port` (configurazione, non una misura),
`ports.0.protocol` (costante), `ports.0.detail` (testo che cambia a ogni esecuzione)
e `ports.0.open` (utile, ma indicizzata per posizione). La pagina degli andamenti
diventava una griglia di rette orizzontali in cui la misura interessante si perdeva.
Correzioni: CT-11, CT-12, CT-15.

**8.2 Il primo endpoint reale.** Il servizio indicato in specifica ha prodotto al
primo giro 17 serie numeriche (cpu, memoria, disco, veicoli accesi, veicoli in
movimento, allarmi aperti, eventi nell'ultima ora, ...) e 4 testuali (applicazione,
banca dati, stato, versione). Tre controlli -- presenza, porta, endpoint -- hanno
dato esito positivo entro venti secondi dalla definizione.

**8.3 Lo storico si recupera.** Gli esiti raccolti prima dell'introduzione delle
metriche conservano la risposta completa: i valori si ricavano invece di perderli
(`flask backfill-check-metrics`). Sull'impianto reale: 64 esiti esaminati, 580 misure
ricavate. L'operazione e' ripetibile senza duplicare nulla.

**8.4 Contrasto del menu laterale.** Con il tema chiaro la voce attiva risultava
illeggibile: le regole del progetto forzavano testo e icone a `#fff` su un fondo
chiarissimo, con un rapporto di contrasto misurato di **1,49:1**. Il sottomenu era a
3,78:1 e le intestazioni a 3,95:1, entrambi sotto il minimo di 4,5:1. Correzione:
impostare le variabili `--lte-sidebar-*` dai token di Bootstrap invece di combattere
sulla specificita' delle regole del fornitore. Valori dopo la correzione: testo
13,0:1, voce attiva 10,3:1, intestazioni 17,7:1 (SR-91).

**8.5 Verifica della scelta dei dati sul controllo reale.** Sul controllo
dell'endpoint di collaudo (19 percorsi disponibili, 20 serie in archivio) sono stati
scelti tre percorsi dalle caselle piu' uno scritto a mano e assente dalla risposta
(`metrics.coda_eventi`). L'esecuzione immediata successiva ha conservato **quattro**
misure: i tre percorsi presenti piu' la latenza; il percorso assente non ha prodotto
errore. Le **20 serie precedenti sono rimaste in archivio** (CT-23), con la pagina che
dichiarava la vista limitata e gli andamenti ridotti a 3 serie. Ripristinata la scelta
vuota, il controllo ha ripreso a conservare tutto.

---

## 9. Notifiche del workflow

| Momento | Quando | Destinatari |
|---|---|---|
| `incident.opened` | soglia di apertura superata | recapito dell'operatore (informativo) |
| `incident.escalated` | soglia di attivazione superata | recapito dell'operatore, con l'avviso che l'incidente non si chiude piu' da se' |
| `incident.recovered` | il controllo rientra dopo l'attivazione | idem, perche' serve una verifica |
| `incident.acknowledged` | un operatore prende in carico | idem |
| `incident.resolved` | chiusura, automatica o umana | idem |

Stati di una notifica in coda: `pending` (in attesa di spedizione), `sent`, `failed`
(esauriti i tentativi, errore conservato), `skipped` (nessun destinatario: la ragione
resta scritta). Il numero massimo di tentativi e' cinque: un indirizzo sbagliato non
diventa giusto al decimo invio, e la coda non deve crescere per sempre.

---

## 10. Azzeramento dell'archivio della sonda

Difetto osservato sull'impianto reale: i comandi di manutenzione esistenti (azzera
registrazione, svuota coda, azzera contatore) lasciavano in archivio **1752 nodi
locali**, 119 stati di fase, 200 righe di storico e 500 righe di diario. La sonda
sembrava azzerata e ripartiva con la memoria di prima.

| Livello | Rimuove | Dopo |
|---|---|---|
| Dati | nodi e profili, stato delle fasi, prenotazioni, coda, storico, stato dei controlli, diario, impostazioni riconsegnate dal server | la sonda resta registrata e riparte dalla scoperta al contatto successivo |
| Tutto | quanto sopra, piu' registrazione, chiavi e ogni impostazione | l'archivio torna allo stato successivo all'installazione: serve una nuova registrazione |

Prima di cancellare si sospendono le scansioni e si terminano i processi di nmap in
corso: una scansione in volo scriverebbe i propri record subito dopo la cancellazione.
Al termine lo spazio viene restituito al sistema -- misurato: da 4,39 MB a 0,42 MB --
e la prima riga del nuovo diario dichiara cosa e' stato rimosso.

L'inventario sul server **non** viene toccato in nessuno dei due casi.

---

## 11. Limiti dichiarati

| Limite | Perche' |
|---|---|
| Le porte UDP si verificano con nmap e restano meno affidabili delle TCP | Una connessione non prova nulla su UDP: l'assenza di risposta non distingue "chiusa" da "silenziosa" |
| Un massimo di 60 punti di misura per esito e 200 serie rappresentate per pagina | Una risposta prolissa riempirebbe la serie storica e la pagina di valori che nessuno guarda; cio' che viene escluso e' dichiarato. La scelta per controllo (CT-21) e' lo strumento con cui ridurre volontariamente cio' che si conserva |
| La scelta dei dati riguarda i controlli su **endpoint HTTP** | Presenza in rete e apertura delle porte producono le misure che la loro definizione implica -- raggiungibilita', una misura per porta dichiarata -- e non c'e' nulla da scegliere |
| I dati esclusi restano nell'archivio | Vale CT-23. La liberazione dello spazio e' un'operazione distinta, da chiedere esplicitamente |
| Un testo piu' lungo di 80 caratteri non diventa una misura | E' contenuto, non stato: resta nella risposta conservata |
| I grafici mostrano una serie per riquadro | Il modulo di disegno e' volutamente minimo (CT-14); piu' serie sovrapposte richiederebbero una libreria |
| La prova immediata va a tutte le sonde attive del tenant | Quale sonda veda il bersaglio non e' noto al server, ed e' una delle cose che la prova accerta |
| Le notifiche sono solo per posta elettronica | E' il recapito che il modello dei dati gia' conosce (email del tenant). Altri canali -- messaggistica, webhook, ticketing -- richiederebbero una dipendenza o una configurazione per canale, da concordare |
| Nessuna ripetizione periodica della notifica di attivazione | Una notifica per momento, non un promemoria: la ripetizione richiederebbe una politica (ogni quanto, fino a quando, a chi) che nessuno ha ancora dichiarato |

---

## Disponibilita' nel tempo (aggiunta)

La pagina dei controlli apre con il **grafico della disponibilita' per giorno**, negli
ultimi trenta giorni, nel fuso del tenant. La percentuale delle ultime 24 ore, che
resta fra gli indicatori, dice *come va adesso*; il grafico dice *se sta migliorando o
peggiorando*, che e' la domanda per cui si apre la pagina.

La serie e' quella dei report (`reports.dataset.trends`), non un secondo calcolo: la
stessa domanda deve avere la stessa risposta nella console e nel PDF, altrimenti due
numeri diversi per la stessa cosa costringono a chiedersi quale sia quello giusto.

### Come si legge il disegno

| Elemento | Che cosa dice |
|---|---|
| Reticolo | Linee orizzontali sulle tacche dei valori e verticali sulle date: servono a leggere un valore alla data giusta senza inseguire la spezzata con il dito |
| Unita' di misura | Scritta una volta sull'asse verticale, non ripetuta su ogni tacca. La percentuale fa eccezione: il segno sta gia' su ogni etichetta |
| Sintesi sopra il tracciato | Media del periodo, giorno peggiore, giorni misurati sul totale, esiti considerati. Sono le quattro misure che qualificano la linea: senza di esse un tracciato dice la forma dell'andamento ma non la sua sostanza |
| Scala verticale | Fondo su un gradino dichiarato sotto al giorno peggiore, tetto a 100, almeno un punto percentuale di ampiezza (CT-25) |
| Linea tratteggiata | Media del periodo, con il proprio valore scritto accanto: una riga tratteggiata senza nome si scambia per una soglia |
| Fascia grigia | Periodo **senza misure**, largo quanto il tempo che copre, con la dicitura *nessuna misura* |
| Interruzione della linea | Fra due misure separate da un vuoto la spezzata non si chiude: unire i due punti direbbe che nel mezzo e' andato tutto bene |
| Pallino pieno a destra | Ultimo valore misurato, che e' quello che si cerca per primo |

Un giorno **senza esecuzioni** non produce un punto: la linea si interrompe e il
tempo vuoto resta visibile per quanto e' lungo. "Non abbiamo guardato" non e' "il
servizio e' caduto" (RP-05), e la sintesi dichiara quanti giorni del periodo non
hanno misure.

Il valore puntuale si legge **passando il puntatore** sul tracciato o percorrendolo
**da tastiera** con le frecce, dopo averlo raggiunto con il tasto Tab (WCAG 2.1 AA,
2.1.1): compare un riquadro con la data per esteso e il valore. Il componente e' lo
stesso per tutti i grafici del prodotto (dashboard, quadri NOC e SOC, misure dei
controlli, sonda), quindi una migliore leggibilita' qui vale ovunque.
