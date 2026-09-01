# snap - Report PDF e resoconto quotidiano

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT

Documento di progetto redatto secondo ISO/IEC/IEEE 29148:2018 (requisiti),
ISO/IEC/IEEE 15288:2015 (processi di ciclo di vita) e ISO/IEC/IEEE 19510:2013 per la
rappresentazione dei flussi. Vincoli di riservatezza e sicurezza: Regolamento (UE)
2016/679 (GDPR), Regolamento (UE) 2024/2847 (CRA), Direttiva (UE) 2022/2555 (NIS2),
ETSI EN 303 645, EN 50649:2024.

> **Stato: realizzato**, tutto il catalogo. Decisioni D1..D5 risolte come indicato al
> capitolo 10.
>
> | Report | Realizzazione |
> |---|---|
> | R1 sintesi esecutiva | `dataset_wide.executive` + `render_wide.executive_report` |
> | R2 inventario e valutazione tecnica | `dataset_wide.inventory` + `render_wide.inventory_report` (A4 orizzontale) |
> | R3 esercizio NOC | `dataset.daily` + `render_pdf.noc_report` |
> | R4 postura di sicurezza | `dataset_wide.soc` + `render_wide.soc_report` |
> | R5 fascicolo di conformita' | `dataset_wide.compliance_pack` + `render_wide.compliance_report` |
> | R6 rapporto di incidente | `dataset_wide.incident_pack` + `render_wide.incident_report` |
> | R7 resoconto quotidiano | `dataset.daily` + `render_mail` + `reports/daily.py` (pianificatore) |
>
> Punto di ingresso unico: `reports/generate.py`. Aggiungere un report e' una
> dichiarazione -- una funzione che raccoglie i dati, una che li impagina, una riga in
> `GENERATORI` -- perche' finestra, percorso, registrazione, audit e chiave del periodo
> sono comuni. Prove in `tests/test_report.py` (46).

---

## 1. Portata

Il sistema raccoglie da settimane dati che oggi si consultano solo a schermo, un
pannello per volta: inventario, variazioni, campioni di raggiungibilita', esiti dei
controlli, misure, incidenti, scansioni, conferimenti, audit. Chi deve **decidere** --
un responsabile che approva una bonifica, un turno che apre la giornata, un auditor che
chiede prova -- non consulta pannelli: legge un documento, e lo legge una volta.

Questo documento specifica:

1. un **catalogo di report** (capitolo 4), ciascuno con un destinatario dichiarato, una
   cadenza, i dati di origine e la decisione che sostiene;
2. il **resoconto quotidiano delle 07:00** spedito per posta (capitolo 5), che risponde
   a due domande: *che cosa e' successo ieri* e *che cosa devo risolvere oggi*;
3. il **motore comune** che li produce (capitolo 6), perche' sette report scritti sette
   volte diventano sette manutenzioni.

Fuori portata: correlazione con feed di vulnerabilita' (CVE), pur essendo presente la
colonna `node_ports.cpe`; esportazione verso SIEM; report interattivi. Motivazioni al
capitolo 11.

---

## 2. Decisioni assunte

| ID | Decisione | Perche' |
|---|---|---|
| RP-01 | Un report ha **un destinatario dichiarato** e risponde a una domanda che quel destinatario si pone davvero | Un documento che serve a tutti non serve a nessuno: finisce con venti pagine di tabelle che il dirigente non apre e il sistemista non usa perche' manca il dettaglio |
| RP-02 | Il contenuto e' ordinato per **decisione**, non per tabella di origine: prima cio' che richiede un intervento, poi cio' che e' cambiato, poi lo stato | Chi legge alle 07:00 ha trenta secondi. Un elenco che comincia dai totali fa scorrere fino in fondo per scoprire che c'e' un incidente aperto |
| RP-03 | Ogni numero mostrato deve essere **riproducibile**: stesso intervallo, stessi numeri, con l'intervallo stampato in testa | Un report di cui non si sa quale finestra copre non e' una prova, e due esecuzioni che divergono distruggono la fiducia nel sistema |
| RP-04 | Le finestre temporali si calcolano nel **fuso del tenant**, non del server, e sono intervalli chiusi `[00:00, 24:00)` | "Ieri" per chi lavora a Roma non e' "ieri" in UTC. Le due letture differiscono di due ore d'estate, e quelle due ore contengono i turni di notte |
| RP-05 | **L'assenza di dati non e' uno zero**: un'ora, un giorno o un bersaglio senza esecuzioni viene dichiarato come non misurato | E' la stessa regola dei grafici (CT-15 e seguenti): inventare uno zero dove non e' stato eseguito nulla fa leggere un crollo dove c'e' solo assenza di dati. Su un report, quel crollo diventa una decisione sbagliata |
| RP-06 | Il resoconto quotidiano si spedisce **anche quando non c'e' nulla da segnalare**, in forma breve | Il silenzio non si distingue da un guasto del reporting. Un messaggio che dice "nessun problema, 289 nodi, disponibilita' 99,4%" e' il battito che prova che la catena funziona |
| RP-07 | Il resoconto passa dalla **coda delle notifiche** esistente, con un evento proprio (`report.daily`) | Ritentativi, registro di cio' che non e' partito e visibilita' degli errori esistono gia' (CT-19, CT-20). Una seconda strada per la posta significherebbe due code da guardare |
| RP-08 | La pianificazione tiene un **marcatore dell'ultima esecuzione** per tenant e per giorno | Un riavvio del server alle 06:59 non deve saltare il resoconto, e uno alle 07:01 non deve spedirne un secondo. L'idempotenza e' per coppia (tenant, giorno) |
| RP-16 | Il marcatore e' un **indice unico** su `report_runs(tenant_id, kind, period_key)`, non un'impostazione di sistema | In realizzazione si e' preferita la garanzia del database a una stringa in `system_settings`: due processi che spedissero nello stesso istante verrebbero fermati dall'indice, una stringa no. La riga registra anche esito, file e notifica, e diventa l'elenco dei report prodotti |
| RP-17 | Il resoconto si spedisce sui canali configurati (**posta, bot Telegram**), con la stessa coda delle notifiche del workflow | Un secondo percorso per la posta significherebbe due code da guardare quando un messaggio non arriva, e la domanda "e' partito?" non deve avere due risposte possibili |
| RP-09 | I report si **conservano su disco** e si scaricano dalla console, con un evento di audit per ogni generazione | Il dato sorgente e' soggetto a retention (`tenants.retention_days`); il report diventa la memoria durevole. Chi lo ha generato e su quale intervallo e' esso stesso informazione di conformita' |
| RP-10 | Il report **executive non contiene indirizzi IP ne' nomi host** | Minimizzazione (GDPR art. 5(1)(c)): un indirizzo IP e' dato personale, e un documento che circola in consiglio di amministrazione non ha bisogno dell'inventario per dire che la copertura e' al 28% |
| RP-11 | Un report tecnico dichiara la **metodologia** in appendice: argomenti nmap, profilo di sforzo, tempi per host, versione dell'agente | Senza metodologia un risultato non e' contestabile, e un risultato non contestabile non e' una misura. Serve anche a spiegare perche' due passate danno numeri diversi |
| RP-12 | La **variazione** e' il segnale, non lo stato: i report di sicurezza aprono con cio' che e' cambiato nel periodo | Una porta 445 aperta su 48 nodi da sempre e' un fatto architetturale noto; la stessa porta aperta ieri su un nodo nuovo e' un evento |
| RP-13 | I primi giorni di vita di un inventario sono dichiarati come **rilevamento di base** e non producono allarmi di variazione | Il primo giro ha prodotto 1851 aperture di porta e 289 nodi comparsi: un resoconto che le presentasse come novita' della giornata sarebbe illeggibile e verrebbe ignorato per sempre |
| RP-14 | I grafici nei PDF si disegnano con le **primitive del generatore**, senza librerie di grafica | E' la stessa scelta dei grafici a schermo (CT-14): una spezzata con banda di riferimento sta in poche decine di righe, e il progetto non aggiunge dipendenze senza averlo concordato |
| RP-18 | Ogni report apre con un **frontespizio**: fascia col marchio, etichetta del genere, titolo, riga di identificazione (tenant, istante, autore), tavola dei **riferimenti**, **indice** delle sezioni e nota sulla provenienza dei dati | Un documento che circola fuori dal gruppo operativo deve dire da se' che cos'e', di chi e' la rete descritta, a quale intervallo si riferisce e da dove vengono i numeri. Senza queste quattro cose non e' una prova ma una stampa. L'indice serve a chi cerca una sezione sola, che e' il caso normale |
| RP-19 | Ogni genere di report ha una **fascia di colore propria**, sempre accompagnata dall'etichetta in testo | Chi ne ha cinque sulla scrivania li distingue a documento chiuso. Il testo accanto al colore serve alla stampa in bianco e nero e a chi non distingue i colori: il colore da solo non e' informazione accessibile |
| RP-20 | La nota di provenienza dichiara che **nessuna scansione e' stata avviata** per produrre il documento | Un report non deve poter essere confuso con un'attivita' sulla rete del cliente: chi lo riceve deve sapere che i numeri vengono dall'archivio, non da una sonda accesa in quel momento |
| RP-24 | Negli elenchi, gli indirizzi si ordinano per **valore numerico** (`inet(ip)`), non come testo | Ordinati come testo, 10.2.9.1 viene dopo 10.2.100.1 e prima di 10.2.99.1: un elenco cosi' non e' sfogliabile, e su un documento consegnato al cliente l'errore si nota subito. La funzione `inet()` e' registrata in SQLite col nome che ha in PostgreSQL, cosi' l'espressione resta valida quando il prodotto girera' su Postgres |
| RP-25 | Gli elenchi dei report **non hanno un limite di righe** | Chiesto dall'operatore. Un documento che si consegna a un cliente non puo' fermarsi a ottanta righe: l'elenco serve intero per essere lavorato. Il costo e' dichiarato -- su un inventario di migliaia di dispositivi il PDF cresce di conseguenza, e la generazione richiede piu' tempo |
| RP-26 | Le colonne delle tabelle si **misurano sul contenuto**; i pesi dichiarati dal generatore distribuiscono soltanto lo spazio che avanza | Difetto trovato dall'operatore su un documento reale: la colonna della subnet mostrava `10.10.14` al posto di `10.10.140.0/24`. Non e' una subnet abbreviata, e' un'ALTRA subnet -- e il documento va al cliente. Le larghezze venivano dai pesi senza guardare che cosa ci fosse dentro, e cio' che non entrava veniva tagliato lettera per lettera in silenzio. Nella stessa tabella due intestazioni si sovrapponevano ("DISPOSITIVIRISCONTRI APERTI") perche' non venivano nemmeno controllate |
| RP-27 | Quando una tabella non entra, i rimedi si applicano **in quest'ordine**: corpo tipografico giu' di un gradino, testo a capo fino a cinque righe, abbreviazione dichiarata con i puntini | Ogni rimedio costa qualcosa e il piu' caro e' l'ultimo: perdere dato. Il corpo scende solo se cosi' la tabella entra intera -- rimpicciolire tutte le cifre per una sola descrizione lunga peggiorerebbe il documento senza risolvere niente. Chi cede spazio e' la colonna piu' larga, non tutte in proporzione: `attivo` non deve diventare `att...` accanto a un URL di settanta caratteri. La prima colonna -- l'identita' della riga -- cede per ultima |
| RP-28 | Nessuna cella viene **accorciata nel codice** che compone il report | Un `[:28]` sul nome host e' un taglio che il lettore non puo' vedere ne' sospettare. Restano ammesse solo le date ISO ridotte a giorno o a minuto, che sono formato e non contenuto, e gli elenchi riuniti in una cella che dichiarano da se' quanti elementi restano fuori |
| RP-32 | Esiste un **fascicolo di conformita' europea** (NIS2, CRA, GDPR, ETSI, ACN) che mette accanto a ogni obbligo il dato conservato, con quattro esiti: dimostrato, parziale, da colmare, **fuori portata** | Le norme non chiedono strumenti, chiedono prove. "Abbiamo un inventario" non e' una prova; "il 12% del perimetro dichiarato non e' mai stato osservato" lo e'. L'esito "fuori portata" e' la parte che rende credibile il resto: un fascicolo che promettesse di coprire tutta la NIS2 con una scansione di rete farebbe smettere di credere anche alle sezioni vere |
| RP-33 | Il fascicolo europeo apre con **la copertura delle prove** e usa le stesse interrogazioni degli altri report | Senza la copertura ogni numero e' senza scala: "nessun riscontro critico" vale molto su una rete osservata per intero e niente su un quarto di rete. E numeri ricalcolati per conto proprio direbbero cose diverse dal resto della console: in un audit e' l'incoerenza, non il numero, che fa perdere credibilita' |
| RP-34 | Tutti gli istanti dei documenti sono nel **fuso dichiarato in copertina**; l'unico UTC ammesso e' la riga che lo dichiara | Difetto trovato controllando: i PDF stampavano gli istanti come stanno in banca dati (UTC) mentre il frontespizio dichiarava "Fuso di riferimento: Europe/Rome". Non era ambiguo, era sbagliato di due ore, e lo stesso evento risultava alle 13:10 sul documento e alle 15:10 nella console |
| RP-31 | Il report sulla segmentazione elenca **anche le reti con zona dichiarata**, non solo quelle senza | Elencare solo cio' che manca e' meta' del documento: la segmentazione si dimostra con le reti che dichiarano che cosa sono, con quante esposizioni risultano attese in quel contesto e quante restano aperte. E' anche il modo di far vedere che una zona dichiarata NON chiude i riscontri: cambia il giudizio su quelli che appartengono a quel contesto |
| RP-29 | La **scheda dell'apparato** riporta cio' che l'apparato dichiara di se' -- nome, marca, modello, posizione fisica, nome host, numero di serie, firmware -- prima della sezione sul riconoscimento | Una dichiarazione dell'apparato vale piu' di una deduzione del prodotto, ed e' la parte che un tecnico legge per prima: dice che cosa ha davanti e dove si trova. Ogni riga porta la porta da cui viene, perche' un dato senza la sua fonte non e' verificabile |
| RP-30 | Il campo del frontespizio si chiama **Indirizzo della console** e non "Console" | Una parola sola non si capisce: chi legge il documento non puo' sapere quale indirizzo sia, ed e' quello che gli serve per verificare i dati alla fonte. Quando non e' impostato, il campo dice anche dove si imposta |
| RP-21 | Un report si puo' **eliminare dall'archivio**, con il suo file, previa conferma | Con dodici generi e piu' ampiezze l'elenco si riempie di prove e di edizioni superate, e un archivio in cui non si trova piu' il documento giusto smette di essere un archivio. L'eliminazione e' tracciata nel registro: si cancella un file, non la storia di averlo prodotto |
| RP-22 | La **scheda dell'apparato** non ha un periodo ma un soggetto | Come il rapporto di incidente: la domanda non e' "che cosa e' successo in trenta giorni" ma "che cosa sappiamo di questo dispositivo". Costringerla in una finestra temporale avrebbe aggiunto una scelta che non serve a chi la stampa per allegarla a una richiesta di intervento |
| RP-23 | Il **report di igiene** misura cio' che manca, non cio' che c'e' | "Nessuna vulnerabilita'" puo' voler dire due cose opposte: che la rete e' a posto o che non si e' guardato. Un documento che dichiara i propri punti ciechi e' l'unico modo perche' gli altri restino credibili |
| RP-15 | La tipografia dei report e' **PT Sans Narrow**, con corpo proporzionato al formato (10 pt su A4), non i 19 pt dei manuali | La convenzione dei 19 pt riguarda i manuali software, dove serve leggibilita' a schermo condiviso. Su un A4 tecnico con tabelle, 19 pt produrrebbe quaranta pagine per dieci di contenuto |

---

## 3. Requisiti

| ID | Requisito |
|---|---|
| SR-99 | Il sistema deve produrre report in formato PDF secondo un catalogo per destinatario (esecutivo, tecnico, NOC, SOC, conformita', incidente) |
| SR-100 | Ogni report deve dichiarare in testa: tenant, intervallo coperto nel fuso del tenant, istante di generazione, autore della richiesta e versione del prodotto |
| SR-101 | Ogni report deve essere riproducibile: la stessa richiesta sullo stesso intervallo deve produrre gli stessi valori |
| SR-102 | I periodi senza dati devono essere dichiarati come non misurati e non rappresentati come valori nulli |
| SR-103 | Il sistema deve spedire un resoconto quotidiano all'ora configurata (predefinita 07:00 locali del tenant) con gli eventi del giorno precedente e le questioni aperte |
| SR-104 | Il resoconto deve essere spedito anche in assenza di eventi, in forma abbreviata |
| SR-105 | Il resoconto deve essere spedito una sola volta per coppia (tenant, giorno), anche a fronte di riavvii del servizio |
| SR-106 | Il resoconto deve elencare distintamente: questioni da risolvere, eventi del periodo, tendenze, igiene del sistema |
| SR-107 | I destinatari del resoconto devono essere configurabili per tenant; in mancanza si usa l'email di riferimento del tenant |
| SR-108 | Un resoconto non recapitato deve restare visibile con il proprio errore, con ritentativi limitati, nella coda delle notifiche |
| SR-109 | I report generati devono essere conservati e riscaricabili, con tracciamento in audit di generazione e scaricamento |
| SR-110 | L'accesso a un report deve rispettare il ruolo: esecutivo e conformita' agli amministratori di tenant, NOC e SOC agli analisti, sola lettura ai profili di consultazione |
| SR-111 | Il report esecutivo non deve contenere indirizzi IP, nomi host o altri identificativi di singoli dispositivi |
| SR-112 | Un report tecnico deve riportare in appendice la metodologia di raccolta dei dati che presenta |
| SR-113 | Il resoconto deve poter essere recapitato per posta elettronica e tramite bot Telegram, con destinatari propri per canale |
| SR-114 | L'anteprima di un resoconto non deve produrre alcuna spedizione |
| SR-115 | La spedizione a richiesta deve poter ripetere un resoconto gia' spedito, dichiarandolo, mentre il pianificatore non lo ripete |
| SR-161 | Il catalogo deve comprendere un report della segmentazione che confronti le zone dichiarate con cio' che e' effettivamente raggiungibile |
| SR-162 | Il catalogo deve comprendere un report di igiene che dichiari le lacune dell'inventario e le azioni per ridurle |
| SR-163 | Deve essere possibile produrre la scheda di un singolo apparato, con identita', servizi, letture SNMP, riscontri e storia recente |
| SR-164 | Un report deve poter essere eliminato dall'archivio con il proprio file, previa conferma esplicita e con tracciamento in audit |
| SR-177 | Negli elenchi dei report gli indirizzi IP devono essere ordinati per valore numerico dell'indirizzo |
| SR-178 | Gli elenchi dei report non devono essere troncati a un numero massimo di righe |
| SR-180 | La larghezza di ogni colonna deve essere determinata dal contenuto della colonna e dalla propria intestazione |
| SR-181 | Nessuna intestazione di colonna deve sovrapporsi a quella adiacente |
| SR-182 | Un valore che non entra nella propria colonna deve essere mandato a capo; se nemmeno cosi' entra, l'abbreviazione deve essere visibile e dichiarata nel documento |
| SR-183 | Il codice che compone i report non deve accorciare i valori delle celle |
| SR-195 | La scheda dell'apparato deve riportare i dati che l'apparato dichiara nelle proprie interfacce di gestione, con la porta da cui provengono |
| SR-196 | Ogni campo del frontespizio deve essere comprensibile senza conoscere la struttura interna del prodotto |
| SR-199 | Deve esistere un report che metta in relazione i dati conservati con gli obblighi di NIS2, CRA, GDPR, ETSI EN 303 645 e delle linee guida ACN/AgID, citando il riferimento normativo puntuale |
| SR-200 | Il report di conformita' deve dichiarare gli obblighi che NON puo' dimostrare |
| SR-201 | Tutti gli istanti stampati nei report devono essere espressi nel fuso dichiarato nel documento |

---

## 4. Catalogo dei report

| ID | Report | Destinatario | Cadenza | Pagine | Domanda a cui risponde |
|---|---|---|---|---|---|
| R1 | Sintesi esecutiva | Direzione, responsabile IT | Mensile, trimestrale | 2-3 | "Siamo coperti? Sta migliorando? Dove serve una decisione?" |
| R2 | Inventario e valutazione tecnica | Sistemisti, rete | Mensile, su richiesta | 15-40 | "Che cosa c'e' in rete, con che cosa risponde, che cosa e' cambiato" |
| R3 | Esercizio NOC | Turno operativo | Giornaliera, settimanale | 3-6 | "Che disponibilita' abbiamo dato, che cosa e' instabile, che cosa e' fermo" |
| R4 | Postura di sicurezza (SOC) | Sicurezza | Settimanale, a evento | 6-12 | "Che superficie esponiamo, che cosa e' cambiato, che cosa va investigato" |
| R5 | Fascicolo di conformita' | Auditor, DPO, direzione | Trimestrale, su richiesta | 8-15 | "Provate che i controlli esistono, funzionano e sono tracciati" |
| R6 | Rapporto di incidente | Chi ha gestito, chi deve notificare | A evento | 2-4 | "Che cosa e' accaduto, quando, chi e' stato avvisato, come e' finita" |
| R7 | Resoconto quotidiano | Turno, responsabile | Giornaliera, 07:00 | email + 1 allegato | "Che cosa e' successo ieri e che cosa devo risolvere oggi" |
| R8 | Vulnerabilita' ed esposizioni | Sicurezza, sistemisti | Mensile, su richiesta | 6-12 | "Che vulnerabilita' abbiamo dimostrato, che cosa va accertato, da quale dispositivo cominciare" |
| R9 | Segmentazione e zone di rete | Sicurezza, architetti di rete | Mensile, su richiesta | 5-9 | "La segmentazione dichiarata regge? Che cosa e' raggiungibile dove non dovrebbe" |
| R10 | Igiene dell'inventario | Chi gestisce il prodotto, sistemisti | Mensile, su richiesta | 4-8 | "Che cosa manca per fidarsi dei numeri, e che cosa fare per migliorarli" |
| R11 | Scheda dell'apparato | Chi interviene, fornitori, inventario d'ufficio | A richiesta, per dispositivo | 3-5 | "Tutto cio' che sappiamo di questo apparato, in un foglio" |

### R1 - Sintesi esecutiva

**Contenuto.** Sei indicatori con il confronto sul periodo precedente e la direzione
della tendenza: nodi in inventario, copertura del perimetro dichiarato, disponibilita'
dei servizi sorvegliati, incidenti aperti e tempo medio di risoluzione, superficie
esposta (numero di servizi di amministrazione remota raggiungibili), quota di
dispositivi non identificati. Poi un semaforo per area (inventario, disponibilita',
sicurezza, conformita'), tre fatti in prosa e **tre azioni proposte** con effetto
atteso.

**Origine.** `nodes`, `subnets`, `check_results`, `check_incidents`, `node_ports`,
`monitor_samples`.

**Cosa NON contiene.** Indirizzi, nomi host, elenchi di porte (RP-10, SR-111), e nessun
termine tecnico non spiegato in una riga.

### R2 - Inventario e valutazione tecnica

**Contenuto.** Perimetro dichiarato contro perimetro osservato, subnet per subnet
(host teorici, nodi trovati, raggiungibili, occupazione percentuale); nodi con sistema
operativo, tipo, etichetta e **confidenza** dell'identificazione; servizi per nodo con
protocollo, porta, prodotto, versione, banner e metodo di rilevamento; nodi da
identificare, con il motivo; porte sospette con la ragione del sospetto; variazioni del
periodo per genere; qualita' della raccolta da `scan_runs` (fasi, durate, host per
passata, fallimenti e scadenze). Appendice di metodologia (RP-11, SR-112).

**Origine.** `nodes`, `node_ports`, `subnets`, `node_changes`, `scan_runs`, `probes`.

**Nota di lettura, dai dati attuali.** Le porte tcp/2000 e tcp/5060 risultano aperte su
264 nodi su 289. Un report tecnico non deve elencarle 264 volte: deve dire che una
porta aperta su quasi tutti i nodi di una rete e' un **apparato che risponde per
altri**, non 264 servizi, e indicare la verifica (`is_suspect`, `suspect_reason`).

**Apparati interrogati via SNMP.** Dove la 161 risponde, la sezione porta cio' che
l'apparato dichiara di se': nome, modello e firmware, collocazione, tempo di accensione,
interfacce. Su switch e stampanti e' l'unica fonte di modello e firmware, che nessuna
porta TCP annuncia. Gli apparati che espongono la porta senza aver risposto sono
dichiarati: la lettura ha una cadenza propria e la community puo' non essere quella di
fabbrica.

### R3 - Esercizio NOC

**Contenuto.** Disponibilita' per bersaglio e per controllo (esiti, percentuale di
riuscita, campioni, finestre di indisponibilita' con inizio, fine e durata); latenza
mediana, 95esimo percentile e massimo per controllo, con andamento; nodi instabili
(transizioni fra raggiungibile e non raggiungibile nel periodo); incidenti aperti,
presi in carico e risolti, con tempo di presa in carico e di risoluzione; stato delle
sonde (ultimo contatto, lotti conferiti, record, scansioni fallite o scadute);
**controlli sospesi** e bersagli senza controlli, cioe' il cieco volontario; coda delle
notifiche non recapitate.

**Origine.** `check_results`, `check_incidents`, `check_incident_events`,
`monitor_samples`, `probes`, `scan_runs`, `ingest_batches`, `notifications`.

**Nota di lettura, dai dati attuali.** Un controllo su `dstracker.vercel.app` porta 85
ha 7 esiti e **zero riuscite**, con latenza a 10 s costante: e' la firma di una
definizione sbagliata, non di un servizio caduto. Il report NOC deve separare "servizio
degradato" da "controllo mai riuscito dalla creazione", perche' la seconda si risolve
correggendo la definizione, non chiamando un sistemista.

### R4 - Postura di sicurezza (SOC)

**Contenuto.** Superficie esposta per **categoria di rischio** invece che per numero di
porta: amministrazione remota (22, 3389, 5900), condivisione file (445, 139), banche
dati (1433, 3306, 5432, 1521), gestione apparati (23 telnet, 161 SNMP, 8080/10001
console), stampa e periferiche (9100), telefonia (2000, 5060). Poi, e con precedenza
(RP-12): porte **aperte nel periodo**, nodi **comparsi** e **scomparsi**, cambi di
sistema operativo o nome host sullo stesso indirizzo (possibile riassegnazione o
sostituzione di apparato), nodi rilevati **fuori perimetro**, letture SNMP disponibili
in sola lettura (esposizione informativa), porte sospette come possibile risposta di
apparato intermedio. Sezione di audit: accessi, cambi di configurazione, comandi
inviati alle sonde, azzeramenti dell'archivio della sonda (SR-95). Mappatura ai
riferimenti: NIS2 art. 21(2) lettere a, e, g; CRA allegato I; GDPR art. 32; ETSI EN 303
645 per gli apparati di consumo rilevati.

**Origine.** `node_ports`, `node_changes`, `nodes`, `audit_events`, `probe_commands`,
`subnets`.

**Nota di lettura, dai dati attuali.** Tcp/1521 (Oracle) risulta aperta su 52 nodi,
tcp/445 su 48, tcp/22 su 212. Sono numeri che chiedono una decisione architetturale, non
un intervento d'urgenza: il report li presenta come postura, e riserva l'urgenza alle
variazioni.

**Che cosa consegna SNMP.** Prima dell'esposizione informativa, il report dichiara
quanto la community di fabbrica ha consegnato: descrizioni di sistema, interfacce,
processi, software installato, connessioni, utenze. Non e' una vulnerabilita': e'
ricognizione servita al bersaglio, e vale per chiunque raggiunga la porta. La stessa
misura compare in R8 come **prova** dell'esposizione.

### R5 - Fascicolo di conformita'

**Contenuto.** Prova documentale che i controlli esistono e funzionano: elenco dei
controlli attivi con genere, cadenza, tempo massimo, soglie di apertura e di attivazione
dell'operatore, recapito; copertura del perimetro dichiarato; registro degli incidenti
con tempi di rilevamento, presa in carico e risoluzione (NIS2: obblighi di gestione e
di notifica); registro degli accessi e delle modifiche da `audit_events`; retention
dichiarata contro dati effettivamente conservati; registro delle notifiche spedite, con
esito. In chiusura, i **rilievi** che il sistema conosce di se stesso.

**Origine.** `checks`, `check_incidents`, `audit_events`, `notifications`, `tenants`,
`system_settings`.

**Rilievo noto da dichiarare.** La password SMTP e' conservata **in chiaro** in
`system_settings`. Un fascicolo di conformita' che non lo dicesse sarebbe un documento
inutile: va elencato fra i rilievi, con la contromisura proposta (cifratura a riposo
della voce o delega a un archivio di segreti).

### R6 - Rapporto di incidente

**Contenuto.** Cronologia dai `check_incident_events` con attori e note; esiti del
controllo nella finestra attorno all'incidente; misure correlate nello stesso
intervallo; notifiche spedite, a chi e quando; risoluzione e causa dichiarata. E' anche
la base per una notifica di incidente significativo ai sensi di NIS2.

### R8 - Vulnerabilita' ed esposizioni

**Contenuto.** E' il documento della correlazione fra inventario e catalogo di
vulnerabilita' note. Apre con cinque indicatori che **non si sommano mai**: sfruttate
attivamente (CISA KEV), confermate, da verificare, esposizioni di servizio, dispositivi
interessati. Poi, nell'ordine: come si legge il documento (le tre classi e che cosa
significano); la **qualita' del dato**, cioe' quante porte aperte annunciano un
prodotto e quante una versione, perche' senza versione una vulnerabilita' non e'
attribuibile a un'istanza (TI-17); le vulnerabilita' confermate ordinate per intervento
e non per punteggio, con le KEV contrassegnate; i prodotti riconosciuti senza versione,
che sono la lista di lavoro per migliorare il dato; le esposizioni **raggruppate per
tipo** con la tecnica MITRE ATT&CK, la motivazione e l'azione consigliata; i dispositivi
ordinati per quanto hanno da sistemare (la risposta a "da quale comincio"); le
variazioni del periodo, cioe' i riscontri comparsi e quelli chiusi; le decisioni
registrate con la loro motivazione; lo stato del catalogo e il registro degli
aggiornamenti.

**Perche' le esposizioni si raggruppano.** Un elenco per dispositivo ripeterebbe "SMB
raggiungibile" centonovantacinque volte. Il fatto da riportare e' che un servizio
rischioso e' raggiungibile su N dispositivi, con l'elenco degli indirizzi sotto.

**Origine.** `ti_findings`, `ti_cve`, `ti_technique`, `ti_sync`, `node_ports`, `nodes`.
Il documento non contatta nessuna sorgente esterna: legge il catalogo locale come tutto
il resto del motore (RP-03).

**Quando il catalogo e' vuoto** il documento lo dichiara in modo esplicito: l'assenza di
riscontri confermati, senza catalogo, non dice niente sulla rete. Le esposizioni ci sono
lo stesso, perche' non dipendono dal catalogo (SR-142).

### R9 - Segmentazione e zone di rete

**Contenuto.** E' il documento che mette a confronto la rete **dichiarata** con la
rete **misurata**. Apre con cinque indicatori: perimetro descritto (quante subnet
dichiarano una zona), esposizioni attese, violazioni di zona, dispositivi per zona,
subnet senza dichiarazione. Poi: come si legge il documento (le tre valutazioni di
`12_ZONE_DI_RETE.md`); la mappa delle zone con quante subnet e quanti dispositivi ne
fanno parte; le **violazioni**, cioe' i servizi raggiungibili dove quella zona dice
che non dovrebbero esserci, ordinate per gravita'; le esposizioni **attese** con la
ragione per cui lo sono, perche' un documento che le nascondesse non sarebbe
verificabile; il **perimetro non descritto**, che e' la prima cosa da sistemare; le
azioni proposte.

**Perche' esiste.** La segmentazione e' la misura architetturale che l'art. 21 della
direttiva NIS2 chiede di dimostrare, e non si dimostra con un disegno: si dimostra
confrontando il disegno con cio' che risponde. Questo report e' quel confronto.

**Origine.** `subnets`, `nodes`, `node_ports`, `ti_findings`, catalogo `zones.py`.

**Limite dichiarato.** Il documento misura cio' che la sonda vede dalla propria
posizione: dice che cosa e' raggiungibile *da li'*, non da ogni altra zona
(`12_ZONE_DI_RETE.md`, cap. 9).

### R10 - Igiene dell'inventario

**Contenuto.** Il documento dei punti ciechi. Indicatori sulla completezza: quota di
dispositivi identificati, quota di porte che dichiarano un prodotto e una versione,
copertura del perimetro, eta' del dato. Poi: qualita' del dato raccolto; perimetro
dichiarato e quanto ne e' stato visto; dispositivi da identificare, che sono la lista
di lavoro; chi non risponde e **chi non e' stato interrogato**, che sono due problemi
diversi (`11_SALA_OPERATIVA.md`, SO-13); sorveglianza e controlli, cioe' quanta parte
dell'inventario e' effettivamente guardata; **che cosa fare, in ordine**.

**Perche' esiste.** Ogni indicatore degli altri dieci report poggia su un dato
raccolto, e un dato raccolto male produce numeri tranquillizzanti. Questo documento
dice quanto ci si puo' fidare degli altri, ed e' il primo da leggere quando un
cruscotto sembra troppo pulito.

**Origine.** `nodes`, `node_ports`, `subnets`, `monitor_samples`, `checks`,
`scan_runs`, `node_snmp`.

### R11 - Scheda dell'apparato

**Contenuto.** Un dispositivo, un foglio. Identita' (indirizzo, nome, MAC,
costruttore, sistema operativo, subnet e zona, sonda che lo vede); come e' stato
riconosciuto, con le prove che hanno portato a quella conclusione e la confidenza;
servizi raggiungibili con prodotto e versione; **che cosa racconta di se'**, cioe' le
letture SNMP in tabella; vulnerabilita' ed esposizioni che lo riguardano;
sorveglianza attiva; storia recente delle variazioni.

**Perche' esiste.** E' il foglio da allegare a una richiesta di intervento, a una
segnalazione a un fornitore o a un inventario d'ufficio: chi lo riceve non ha accesso
alla console, e deve poter capire di che apparato si parla senza aprire nulla.

**Come si produce.** Dalla pagina del dispositivo, pulsante *Scheda PDF*: non ha un
periodo da scegliere (RP-22), e' la fotografia di cio' che si sa adesso.

**Origine.** `nodes`, `node_ports`, `node_snmp`, `node_changes`, `ti_findings`,
`monitor_samples`, `checks`.

---

## 4-bis. Il fascicolo di conformita' europea

**Destinatario**: auditor, DPO, direzione, responsabile NIS2.
**Domanda**: che cosa possiamo dimostrare di NIS2, CRA e GDPR, e che cosa no.
**Periodo**: 30, 90 o 365 giorni. **Ruolo**: amministratore del tenant.

### 4-bis.1 Perche' non e' il fascicolo di conformita' che c'era gia'

Il *Fascicolo di conformita'* dimostra che i controlli del prodotto esistono, funzionano
e sono tracciati. Il fascicolo **europeo** risponde a un'altra domanda: preso un obbligo
di legge, quale dato conservato lo dimostra, e fino a che punto. Sono due documenti
diversi perche' due sono le domande, e unirli avrebbe prodotto un documento che non
serve a nessuno dei due lettori.

### 4-bis.2 I quattro esiti

| esito | significato |
|---|---|
| **dimostrato** | il dato conservato regge da solo come prova |
| **parziale** | il dato copre una parte dell'obbligo, e la parte e' dichiarata |
| **da colmare** | l'obbligo riguarda qualcosa che si puo' fare e non e' stato fatto |
| **fuori portata** | l'obbligo non si dimostra con un inventario di rete: serve documentazione di organizzazione |

"Fuori portata" non e' una scusa: e' la parte che rende credibile il resto. Le politiche,
la formazione, i contratti con i fornitori e la valutazione del rischio sono carte di
organizzazione, e il documento lo dice in prima pagina.

### 4-bis.3 Che cosa contiene, nell'ordine

1. **Che cosa dimostra questo fascicolo**, con il glossario dei quattro esiti.
2. **Copertura delle prove**: subnet dichiarate, scansionate, con dispositivi; nodi
   identificati; apparati che dichiarano se stessi; sonde e ultima consegna. Sta prima
   di tutto perche' senza questo numero ogni altro numero e' senza scala.
3. **NIS2** (Dir. UE 2022/2555, D.lgs. 138/2024): art. 21(2)(a) analisi dei rischi e
   inventario degli asset, (b) gestione degli incidenti, (d) continuita' e
   segmentazione, (e) sicurezza della rete e gestione delle vulnerabilita', (i) igiene
   e controllo accessi, (j) tracciamento; **art. 23** capacita' di notifica.
4. **Cyber Resilience Act** (Reg. UE 2024/2847): allegato I parte I (sicurezza per
   difetto, superficie di attacco), allegato II (gestione delle vulnerabilita',
   versioni, seriali).
5. **GDPR** (Reg. UE 2016/679): art. 5(1)(c) minimizzazione, art. 32 misure tecniche e
   accessi autorizzati -- comprese le implicazioni dei dati che l'inventario contiene
   (indirizzi, nomi host, posizione, contatto letto dagli apparati) e il rimando
   all'art. 30.
6. **ETSI EN 303 645**: provision 5.1 credenziali predefinite, 5.3 aggiornabilita',
   5.6 superficie minima.
7. **Linee guida ACN/AgID** e **OWASP ASVS**.
8. **Rilievi in ordine di gravita'**: la pagina che si legge per decidere.
9. **Riferimenti normativi**, con recepimento e ambito.

### 4-bis.4 Limiti dichiarati

* Non e' una certificazione ne' una dichiarazione di conformita': e' l'insieme delle
  prove tecniche disponibili alla data.
* La qualifica di un incidente come "significativo" (art. 23 NIS2) e' una valutazione,
  non un dato: il documento fornisce i tempi e le prove.
* La notifica al CSIRT non e' automatizzata.
* snap non produce un SBOM dei prodotti del cliente: l'SBOM si chiede al fabbricante,
  che e' il soggetto obbligato dal CRA.
* La segmentazione si dimostra per dichiarazione e per servizi osservati; la
  raggiungibilita' effettiva fra zone richiede una sonda per zona.

## 5. Il resoconto quotidiano delle 07:00

### 5.1 Forma

Email in **testo semplice e HTML** (la stessa informazione nelle due parti), con
allegato PDF facoltativo: il report NOC del giorno precedente (R3). Il corpo deve
essere leggibile su telefono in trenta secondi; il PDF serve a chi vuole il dettaglio.

Oggetto: `snap ISED - 27/08: 3 da risolvere, disponibilita' 99,4%`. L'oggetto porta il
numero delle questioni aperte, perche' e' l'unica parte che si legge in lista.

### 5.2 Contenuto, nell'ordine (RP-02, SR-106)

**1. Una riga di stato.** Nodi, disponibilita' del giorno, questioni aperte, e se
qualcuna richiede un operatore.

**2. Da risolvere.** In ordine di urgenza:

| Voce | Origine | Perche' e' la prima cosa |
|---|---|---|
| Incidenti aperti, con eta' e ultimo dettaglio | `check_incidents` | Sono la definizione di "da risolvere" |
| Incidenti **scalati e non presi in carico** | `check_incidents.escalated_at` con `acknowledged_at` nullo | Qualcuno e' stato attivato e nessuno ha risposto: e' il caso peggiore |
| Controlli **mai riusciti** dalla creazione | `check_results` per controllo | Non e' un guasto, e' una definizione sbagliata; va corretta, non presidiata |
| Sonde mute da oltre 15 minuti | `probes.last_seen_at` | Senza sonda l'intera raccolta e' cieca, e i controlli non vengono eseguiti |
| Scansioni fallite o scadute | `scan_runs.status` | Un inventario che non si aggiorna invecchia in silenzio |
| Notifiche non recapitate | `notifications.status` | Un allarme che non e' partito e' peggio di un allarme assente |

**3. Che cosa e' successo ieri.** Incidenti aperti e chiusi con la durata; finestre di
indisponibilita' con orario e durata; nodi comparsi e scomparsi; porte aperte e chiuse,
le prime per categoria di rischio; cambi di sistema operativo o nome host; esiti dei
controlli per bersaglio con la percentuale di riuscita; volumi di raccolta (passate,
host, record conferiti).

**4. Tendenze.** Sette giorni di disponibilita' e di latenza al 95esimo percentile per
i bersagli sorvegliati. Nel corpo dell'email la tendenza si rende con caratteri di
blocco (`▁▂▃▅▇`), non con immagini: un'immagine remota viene bloccata dai client di
posta e un SVG in linea non e' supportato. Il grafico vero sta nel PDF.

**5. Igiene.** Controlli sospesi, bersagli senza controlli, nodi non identificati,
misure e dati prossimi alla scadenza per retention.

**6. Chiusura.** Intervallo coperto, fuso, istante di generazione, indirizzo della
console. In assenza di eventi il corpo si riduce ai punti 1 e 6 (RP-06, SR-104).

### 5.3 Regole di soppressione

| Regola | Perche' |
|---|---|
| Nei primi 7 giorni di vita di un inventario le variazioni non si elencano ma si contano, dichiarando il **rilevamento di base** (RP-13) | Il primo giro ha prodotto 1851 aperture di porta e 289 nodi comparsi: elencarli renderebbe il primo resoconto illeggibile |
| Una variazione che riguarda oltre il 20% dei nodi si presenta come **fatto aggregato**, non come elenco | 264 nodi con la stessa porta aperta sono un apparato che risponde per altri, non 264 eventi |
| Un giorno senza esecuzioni si dichiara non misurato e non produce disponibilita' 0% (RP-05, SR-102) | Sul 27/08 l'archivio non ha alcun campione: un resoconto che annunciasse "disponibilita' 0%" sarebbe un falso allarme di prima mattina |
| Un incidente gia' risolto entro la notte compare fra gli eventi, non fra le questioni aperte | Sposta l'attenzione su cio' che e' ancora da fare |

### 5.4 Pianificazione

Thread dedicato nel processo del server, come il dispatcher delle notifiche
(`start_dispatcher`), con risveglio ogni minuto e marcatore
`report.daily.last_run.<tenant>` in `system_settings` (RP-08, SR-105). L'ora e i
destinatari sono impostazioni per tenant (`report_daily_time`,
`report_daily_recipients`), con fallback su `tenants.contact_email` (SR-107). La
spedizione passa dalla coda con evento `report.daily` (RP-07, SR-108).

Sul dato attuale il fuso del tenant e' `Europe/Rome`: alle 07:00 locali corrispondono
le 05:00 UTC in estate. Il calcolo di "ieri" segue RP-04.

### 5.5 Esempio, con i dati reali di oggi

```
snap ISED S.p.a. - resoconto del 28/08/2026 (Europe/Rome)

289 nodi, disponibilita' dei servizi 98,9%, 1 questione da risolvere.

DA RISOLVERE
  ! Controllo mai riuscito: "porte dstracker.vercel.app tcp/85"
    7 esiti, 0 riusciti, latenza costante a 10.008 ms (tempo massimo raggiunto).
    Verificare la definizione: la porta risulta chiusa dalla creazione del controllo.

IERI
  Incidenti: 2 aperti, 2 risolti.
    #3 warning  aperto 08:26, risolto 08:28 (2 min), 5 fallimenti
    #4 critical aperto 08:28, risolto 08:29 (1 min), 7 fallimenti, operatore attivato
  Notifiche: 5 spedite, 0 in errore.
  Controlli: 525 esiti, 517 riusciti (98,5%).
    bc-test-ws-dkr50.psn-test.ised.it  http      100,0%   lat  398 ms
    10.2.109.86                        presenza  100,0%   lat 1743 ms
    10.2.109.246                       porte     100,0%   lat   98 ms
    dstracker.vercel.app               porte      98,8%   lat  150 ms
  Inventario: rilevamento di base in corso (giorno 1 di 7).
    289 nodi comparsi, 1851 porte aperte rilevate, 327 tipi di dispositivo assegnati.
    Le variazioni verranno elencate a partire dal 04/09.
  Raccolta: 412 passate completate, 0 fallite. Servizi: 145 s medi per passata.
    Sonda "Probe-Office-Coponia" attiva, ultimo contatto 15:13.

TENDENZE (7 giorni)
  Disponibilita'   ▁▁▁▁▁▁▇  (i giorni precedenti non hanno misure)
  Latenza p95      ▁▁▁▁▁▁▅  398 ms

IGIENE
  4 subnet dichiarate, 1016 host teorici, 289 nodi trovati (occupazione 28%).
  0 controlli sospesi. 0 nodi non identificati.

Intervallo 28/08 00:00 - 24:00 (Europe/Rome). Generato alle 07:00.
Console: http://127.0.0.1:5500/
```

---

## 6. Motore comune

Un report e' una **dichiarazione**, non un programma: chi ne aggiunge uno scrive quali
sezioni contiene, non come si disegna una tabella.

```
server/snapserver/reports/
    windows.py    finestre temporali nel fuso del tenant, "ieri", "ultimi 7 giorni"
    dataset.py    una funzione per sezione: riceve (tenant, finestra), torna dati
    catalog.py    i sette report come elenco di sezioni, con ruolo richiesto
    render_pdf.py cornice A4, intestazione, pie' di pagina, tabelle, grafici
    render_mail.py corpo testo e HTML del resoconto
    daily.py      pianificatore e accodamento
    storage.py    server/data/reports/<tenant>/<anno>/<mese>/, audit, scaricamento
```

Le funzioni di `dataset.py` sono le stesse che alimentano i pannelli, dove esistono
(`checks_queries.py`, le interrogazioni dell'inventario): un numero che sul report
differisce da quello a schermo e' un difetto, non una sfumatura.

**Flusso (ISO/IEC/IEEE 19510, in forma testuale).** Pianificatore → per ogni tenant
attivo: calcola la finestra nel fuso del tenant → verifica il marcatore del giorno →
raccoglie le sezioni → rende il corpo email → genera il PDF allegato → accoda la
notifica → scrive il marcatore → registra l'evento di audit. Un errore su un tenant non
interrompe gli altri: viene registrato e il tenant successivo procede.

---

## 7. Tipografia e impaginazione

### 7.0 Elenchi lunghi su due colonne

Gli elenchi **lunghi e stretti** -- porte aperte su una quota rilevante della rete,
prodotti senza versione, dispositivi da cui cominciare, nodi fuori perimetro -- si
impaginano su **due colonne affiancate**, come le pagine di un elenco telefonico: a
colonna unica meta' pagina resterebbe bianca e il documento sarebbe lungo il doppio.
Ogni colonna ripete la propria testatina, cosi' una riga si legge anche a pagina
girata.

Le tabelle **larghe** (nodi, servizi rilevati, apparati SNMP) restano a colonna
unica: su mezza pagina le loro colonne diventerebbero illeggibili. La scelta e'
dichiarata dal generatore riga per riga (`colonne=2`) e non dedotta: dedurla
significherebbe che un dato in piu' cambia l'impaginazione di un documento senza che
nessuno l'abbia deciso.

### 7.0-bis Che cosa succede quando una tabella non entra

Le colonne non hanno larghezze fisse: si misurano. Per ogni colonna si prende il
valore piu' lungo che contiene e la propria intestazione, e quella e' la larghezza che
la colonna *chiede*. Se la somma sta nella pagina, lo spazio che avanza si distribuisce
secondo i pesi dichiarati dal generatore -- che quindi indicano dove mettere il
respiro, non quanto stringere.

Se la somma non ci sta, si procede in ordine:

1. **il corpo scende di un gradino** (da 8 a 6,6 punti, a scatti di due decimi) ma
   soltanto se la riduzione fa entrare la tabella INTERA. Rimpicciolire tutte le cifre
   per una sola descrizione lunga sarebbe un peggioramento senza rimedio;
2. **cede la colonna piu' larga**, non tutte in proporzione: si abbassa un livello
   comune, come l'acqua nei vasi comunicanti, e le colonne sotto quel livello non
   vengono toccate. L'ordine di cessione e' dichiarato -- prima le descrizioni, poi i
   numeri, per ultima la prima colonna, che porta l'identita' della riga;
3. **il testo va a capo**, fino a cinque righe. Ogni riga usa solo le linee che le
   servono, quindi una tabella con una sola cella lunga non diventa alta cinque volte.
   Le parole che non hanno spazi -- un URL, un identificativo -- si spezzano a forza,
   perche' altrimenti sborderebbero nella colonna vicina;
4. **solo se nemmeno cinque righe bastano**, il valore si abbrevia con i puntini e il
   documento lo dichiara sotto la tabella. `10.10.14` al posto di `10.10.140.0/24` e'
   un dato falso; `10.10.14...` e' un dato abbreviato: fra le due cose passa la
   differenza fra un errore e una nota.

Una colonna non scende mai sotto la larghezza della propria intestazione, ed e' questo
che impedisce a due titoli di sovrapporsi. Non scende nemmeno sotto la larghezza che le
serve per contenere il proprio valore piu' lungo andando a capo: e' la ragione per cui
un indirizzo lungo occupa cinque righe strette invece di perdere la coda.

Sul campo, gli otto generi del catalogo generati sull'inventario reale non abbreviano
piu' alcun valore.

**Elenchi su due colonne.** Il ripiego a colonna unica e' automatico: se a mezza pagina
la tabella non entrerebbe intera, i due blocchi affiancati vengono abbandonati. Un
documento piu' lungo si sfoglia, un elenco di subnet troncate non si usa.

**Marchio.** Sui documenti il marchio disegnato in alto a sinistra -- copertina e
testatina di ogni pagina -- e' **SNAP** in maiuscolo: quattro lettere minuscole accanto
agli archi si leggono come una parola qualsiasi. Nel testo, nei metadati del PDF e
nell'interfaccia il prodotto resta `snap`, che e' il suo nome.

**Date e ore (RP-34).** Ogni istante stampato e' nel fuso dichiarato in copertina
("Fuso di riferimento"), compresa la riga di identificazione che compare su ogni pagina.
L'unica eccezione e' dichiarata: la riga *Generato il (UTC)*, che serve a incrociare il
documento con un registro. Le DATE di calendario che arrivano da cataloghi esterni --
inserimento nel KEV, scadenza per la correzione -- non si convertono: una data non ha un
fuso, e convertirla la sposterebbe di un giorno.

**Frontespizio (RP-18).** Fascia colorata alta il 42% della pagina: marchio (tre archi e
un punto: il segnale che una sonda ascolta), nome del prodotto e claim, etichetta del
genere in alto a destra, titolo, sottotitolo con la domanda a cui il report risponde, riga
`Tenant X · istante · generato da Y`. Sotto la fascia: lo scopo in due righe, poi due
tavole affiancate -- *Riferimenti* (applicazione, versione, console, tenant, intervallo,
fuso, sonde registrate, istante) e *Contenuto del documento* (indice numerato) -- e il
riquadro della provenienza dei dati.

**Colore per genere (RP-19).**

| Report | Fascia | Etichetta |
|---|---|---|
| Sintesi esecutiva | blu notte `#16263f` | DIREZIONE |
| Inventario e valutazione tecnica | verde petrolio `#0f3239` | INVENTARIO |
| Esercizio NOC | verde oliva `#2c3a1c` | TURNO NOC |
| Postura di sicurezza | bordeaux `#3a1618` | SICUREZZA |
| Fascicolo di conformita' | indaco `#2a2440` | CONFORMITA' |
| Rapporto di incidente | terra bruciata `#3d2410` | INCIDENTE |
| Resoconto quotidiano (allegato) | ardesia `#1f3033` | RESOCONTO |

Ogni tema porta anche l'accento (barrette delle sezioni, valori degli indicatori, linea
dei grafici) e il tono chiaro (fasce di indicatori, righe alternate delle tabelle).

| Elemento | Scelta |
|---|---|
| Carattere | PT Sans Narrow (titoli e testatine), PT Sans (corpo), PT Mono (indirizzi e porte), **incorporati** nel PDF da `static/fonts/pdf/` (licenza OFL 1.1, file `OFL-PT.txt` accanto ai caratteri) |
| Corpo | 10 pt su A4, interlinea 1,15; 19 pt resta la convenzione dei **manuali** (RP-15) |
| Formato | A4 verticale; orizzontale per le tabelle di inventario oltre otto colonne |
| Intestazione | Nome del tenant, titolo del report, intervallo coperto |
| Pie' di pagina | Pagina su totale, istante di generazione, `snap <versione>`, classificazione |
| Colore | Semaforo su tre livelli, con l'informazione ripetuta in testo per la stampa in bianco e nero e per chi non distingue i colori |

Il carattere va **incorporato** nel PDF. Nel progetto sono presenti solo i formati web
(`.woff2`); l'incorporamento richiede i file `.ttf`, disponibili con licenza OFL 1.1:
decisione aperta al capitolo 10.

---

## 8. Riservatezza, conformita', accessi

| Aspetto | Trattamento |
|---|---|
| Dati personali | Indirizzi IP, nomi host e MAC sono dati personali (GDPR): i report che li contengono sono classificati "uso interno" e accessibili per ruolo (SR-110); l'esecutivo non li contiene affatto (SR-111) |
| Minimizzazione | Ogni report porta solo i campi che la sua domanda richiede: il NOC non ha bisogno del banner dei servizi, il SOC non ha bisogno delle latenze medie |
| Retention | I report seguono una retention propria, dichiarata; sopravvivono ai dati che riassumono (RP-09) |
| Tracciamento | Generazione e scaricamento producono un evento di audit con utente, report e intervallo |
| NIS2 | R5 e R6 costituiscono la base documentale degli obblighi di gestione del rischio e di notifica |
| CRA | R4 documenta la superficie esposta e la sua evoluzione, richiesta dall'allegato I |
| Trasmissione | Il resoconto viaggia su SMTP con STARTTLS (configurazione attuale: `smtp.gmail.com:587`). Un allegato PDF con inventario non va spedito a caselle esterne al perimetro organizzativo: l'allegato e' facoltativo e disattivabile |

---

## 9. Esercizio

| Aspetto | Scelta proposta |
|---|---|
| Generazione su richiesta | Dalla console, con scelta dell'intervallo; l'attesa e' dichiarata e il file compare nell'elenco |
| Costo | Le interrogazioni pesanti (inventario completo, 4084 porte) girano una volta per report, non una per sezione |
| Fallimento | Un report che non si genera non e' silenzioso: resta nell'elenco con lo stato e l'errore |
| Prova | Ogni report ha una prova che lo genera su un archivio di collaudo e verifica struttura e numeri; i numeri si verificano contro le stesse interrogazioni dei pannelli |

---

## 10. Decisioni assunte (erano aperte)

Risolte il 28/08/2026 come segue.

| # | Decisione | Opzioni | Scelta |
|---|---|---|---|
| D1 | Generatore PDF | **reportlab** (gia' presente nel `.venv`, non dichiarato in `requirements.txt`; puro Python, BSD) - **weasyprint** (HTML→PDF, riuso dei modelli, ma richiede GTK/Pango su Windows) - **nessuna dipendenza**: pagine HTML stampabili dal browser | **reportlab**, dichiarato in `requirements.txt`. Weasyprint su Windows introduce librerie native; l'opzione senza dipendenze non permette l'allegato automatico alle 07:00 |
| D2 | Carattere incorporato | Aggiungere i `.ttf` di PT Sans Narrow (OFL 1.1) come risorsa - usare Helvetica dei generatori | **I `.ttf`**, quando disponibili: il generatore li cerca in `static/fonts/pdf/` e, se non li trova, ripiega su Helvetica **dichiarandolo nel pie' di pagina**. Un documento che finge una tipografia che non ha sarebbe una piccola bugia stampata. I `.ttf` sono stati aggiunti il 28/08/2026 in `static/fonts/pdf/` con il testo della licenza (`OFL-PT.txt`): i report sono in PT Sans Narrow, PT Sans e PT Mono, incorporati come sottoinsiemi. Il ripiego resta come comportamento di sicurezza se i file vengono rimossi |
| D3 | Allegato al resoconto | Sempre - facoltativo per tenant - mai | **Facoltativo, spento per difetto**: un inventario allegato che finisce in una casella esterna e' un problema di riservatezza, non di comodita' |
| D4 | Ordine di realizzazione | R7 (resoconto) prima - R3 (NOC) prima - tutto insieme | **R7 e R3 insieme**: condividono i dati, e R3 e' l'allegato di R7. Poi R4, R1, R2, R5, R6 |
| D5 | Storico dei report | Su disco con retention propria - solo generazione a richiesta | **Su disco**: e' la memoria che sopravvive alla retention dei dati (RP-09) |

---

## 10-bis. Come si genera un report del catalogo

Dalla console, menu **Report e resoconti**, scheda *Catalogo dei report*: si scelgono il
genere, il giorno finale e l'ampiezza del periodo. Le ampiezze sono soltanto quelle
offerte per quel genere:

| Report | Ampiezze | Predefinita | Ruolo richiesto | Formato |
|---|---|---|---|---|
| Sintesi esecutiva | 30, 90 giorni | 30 | amministratore di tenant | A4 verticale |
| Inventario e valutazione tecnica | 7, 30, 90 | 30 | analista | A4 **orizzontale** |
| Esercizio NOC | 1, 7 | 1 | analista | A4 verticale |
| Postura di sicurezza | 7, 30 | 7 | analista | A4 verticale |
| Fascicolo di conformita' | 30, 90, 365 | 90 | amministratore di tenant | A4 verticale |
| Vulnerabilita' ed esposizioni | 7, 30, 90 | 30 | analista | A4 verticale |
| Segmentazione e zone di rete | 7, 30, 90 | 30 | analista | A4 verticale |
| Igiene dell'inventario | 7, 30, 90 | 30 | analista | A4 verticale |
| Rapporto di incidente | l'incidente stesso | - | analista | A4 verticale |
| Scheda dell'apparato | il dispositivo stesso | - | analista | A4 verticale |

Perche' non un intervallo libero: due edizioni dello stesso report con ampiezze
arbitrarie non sono confrontabili, e il confronto con il periodo precedente -- che nella
sintesi esecutiva e' l'informazione principale -- richiede due finestre della stessa
lunghezza. Le due ampiezze dello stesso giorno restano due documenti distinti, con
chiave di periodo e file propri.

**Categorie di rischio.** La superficie esposta non si presenta per numero di porta ma
per categoria, perche' "amministrazione remota raggiungibile su 12 nodi" e' una frase su
cui si decide, mentre "3389 aperta su 12 nodi" richiede di sapere che cos'e' la 3389:
amministrazione remota (22, 23, 3389, 5900, 5985-5986), condivisione file (139, 445,
2049), banche dati (1433, 1521, 3306, 5432, 6379, 27017, 9200), gestione degli apparati
(161, 8080, 8443, 10000-10001, 4443), stampa e periferiche (515, 631, 9100), telefonia
(2000, 5060-5061, 1720), protocolli in chiaro (21, 23, 69, 110, 143, 512-514). Ogni
categoria porta la propria spiegazione nel documento.

---

## 10-ter. Come si elimina un report dall'archivio

Dall'elenco *Report prodotti*, il pulsante di eliminazione su ciascuna riga. La
conferma e' obbligatoria e non e' quella del browser: e' il dialogo dell'interfaccia,
come per ogni azione distruttiva del prodotto.

Che cosa succede, nell'ordine:

1. Si cancella **il file** dal disco.
2. Solo se il file e' stato rimosso si cancella la **riga** dell'archivio.
3. L'operazione entra nel **registro degli eventi** con gravita' *avvertimento*: chi,
   quando, quale documento.

L'ordine non e' casuale. Se il file non si potesse cancellare -- permessi, disco in
sola lettura -- la riga resterebbe, e l'archivio continuerebbe a dire il vero: meglio
una riga che indica un file ancora presente che una promessa di cancellazione non
mantenuta. L'interfaccia lo dichiara con un messaggio esplicito invece di fingere
riuscita (RP-21, SR-164).

Eliminare un report **non impedisce** di rigenerarlo: la chiave di periodo torna
libera, e la stessa richiesta sullo stesso intervallo produce gli stessi valori
(SR-101).

---

## 11. Osservazioni dalla realizzazione

**11.1 Due copie nello stesso secondo.** Il nome dei file di copia dell'archivio ha
risoluzione al secondo. Il ripristino ne crea una dello stato corrente subito prima di
leggere la sorgente: con lo stesso nome, la copia appena creata sovrascriveva il file da
ripristinare, e si tornava allo stato corrente credendo di tornare indietro. La prova
sul ripristino lo ha fatto emergere prima dell'esercizio; correzione: contatore nel nome
quando il file esiste gia'.

**11.2 Il ripristino riporta anche il registro.** Un ripristino sostituisce l'intero
archivio, quindi anche `audit_events`: gli eventi successivi alla copia scompaiono. Non
e' un difetto ed e' irriducibile, ma va detto prima di premere -- il modulo e il
messaggio di esito lo dichiarano, e l'unica traccia che resta e' l'evento del ripristino,
scritto dopo.

**11.3 Il ripiego tipografico.** Il progetto portava i caratteri solo in formato
web (`.woff2`), che un PDF non puo' incorporare. Invece di far fallire la generazione o
di tacere, il generatore ripiegava su Helvetica scrivendolo nel pie' di pagina. I `.ttf`
sono poi stati aggiunti al repository con la propria licenza, e i report adottano la
tipografia del progetto; il ripiego resta come comportamento di sicurezza, con la
dichiarazione in pagina, perche' un documento che finge una tipografia che non ha sarebbe
una piccola bugia stampata.

**11.4 Una prova che passava per il motivo sbagliato.** La verifica che il report
esecutivo non contenga indirizzi cercava la stringa nei byte del PDF. I flussi di
reportlab sono compressi (ASCII85 e Flate): l'indirizzo non si sarebbe trovato in nessun
caso, e la prova sarebbe passata anche su un documento che li conteneva tutti. Correzione:
un estrattore di testo nelle prove (decodifica ASCII85, decompressione, operatori `Tj`) e
una prova della prova che verifica di aver estratto davvero il testo. Vale la regola
generale: una verifica che non puo' fallire non e' una verifica.

**11.5 Il primo giorno di un inventario.** Sul dato reale il primo giro di scansione ha
prodotto 1851 aperture di porta, 289 nodi comparsi e 327 assegnazioni di tipo. Un
resoconto che le presentasse come novita' della giornata sarebbe illeggibile: da qui il
rilevamento di base (RP-13) e la soglia di aggregazione a un quinto della rete.

---

## 12. Limiti dichiarati

| Limite | Perche' |
|---|---|
| Nessuna correlazione con vulnerabilita' note (CVE) | Richiede un feed esterno, il suo aggiornamento e la gestione dei falsi positivi sulle versioni rilevate: e' un progetto a se', e un elenco di CVE sbagliato e' peggio di nessun elenco. La colonna `cpe` conserva il dato per il giorno in cui si affrontera' |
| Nessuna esportazione verso SIEM o ticketing | Richiederebbe una dipendenza o un contratto di interfaccia per prodotto, da concordare |
| I report non sono interattivi | Un PDF si archivia, si firma e si allega a un audit; l'interattivita' e' il compito dei pannelli, che esistono gia' |
| Le tendenze su sette giorni richiedono sette giorni di dati | Con l'archivio attuale (un giorno) le tendenze restano dichiarate come non disponibili (RP-05) |
| Un solo fuso per tenant | Un tenant con sedi in fusi diversi vedrebbe "ieri" secondo il fuso dichiarato; la molteplicita' richiederebbe un fuso per sede, che il modello non ha |
