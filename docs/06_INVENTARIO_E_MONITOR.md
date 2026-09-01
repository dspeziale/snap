<!--
  snap - Progetto dell'inventario di rete e del monitoraggio dei nodi.

  remarks: Autore: Daniele Speziale - Data: 2026-08-27
  copyright: (c) 2024-26 DS Consulting
  license: MIT
-->

# Inventario di rete e monitoraggio dei nodi

| Voce | Valore |
|---|---|
| Versione del documento | 1.0.0 |
| Data | 2026-08-27 |
| Stato | Progetto approvato, realizzazione in corso |
| Norme di riferimento | ISO/IEC/IEEE 29148:2018, 19510:2013, 15288:2015; GDPR; CRA; NIS2 |
| Prerequisito esterno | nmap 7.99 con Npcap 1.87 sulla macchina della sonda |

---

## 1. Portata

Il prodotto diventa un **inventario di rete con monitoraggio dei nodi trovati**.
La sonda scopre i dispositivi presenti nelle subnet dichiarate dal tenant, ne
determina porte, servizi, sistema operativo e **tipo di dispositivo**, e ne
sorveglia nel tempo la raggiungibilita' e i cambiamenti. Il server conserva
l'inventario per tenant, lo presenta nella console e ne registra la storia.

Resta invariato tutto l'impianto esistente: canale cifrato SNAP-SEC/1,
asimmetria della conoscenza, autonomia della sonda, multi-tenancy, fusi orari,
accessi e audit. L'inventario si innesta sul contratto di conferimento
estensibile previsto dalla decisione AD-12: **il trasporto non cambia**.

Fuori portata in questa fase: ricerca di vulnerabilita', gestione delle
correzioni, reportistica PDF. Erano state rimosse dal prodotto e non vengono
reintrodotte.

---

## 2. Decisioni assunte

| ID | Decisione | Motivazione |
|---|---|---|
| ID-01 | Le subnet sono **definite sul server, per tenant**, da un file `.txt` caricato nella console e consegnate alla sonda nella configurazione cifrata | Unica fonte di verita', isolamento per tenant, ogni modifica tracciata in audit; la sonda non ha file da mantenere |
| ID-02 | Il **perimetro e' vincolante**: la sonda scansiona esclusivamente gli indirizzi contenuti nelle subnet ricevute e rifiuta ogni bersaglio esterno | Autorizzazione dimostrabile: si scansiona solo la rete che il cliente ha dichiarato propria (CRA, NIS2) |
| ID-03 | Scansione **progressiva in sei fasi** con cadenze differenziate, piu' esecuzione su richiesta dalla console | Il costo si concentra dove serve: la scoperta e' frequente e leggera, il rilevamento del sistema operativo e' raro e costoso |
| ID-04 | Il **fingerprinting risiede sul server**, non sulla sonda | Il catalogo delle firme evolve: aggiornarlo non deve richiedere una nuova distribuzione delle sonde, e il server puo' rideterminare il tipo di tutto l'inventario quando il catalogo cambia |
| ID-05 | La sonda invia **prove normalizzate**, non verdetti | Le prove restano il dato grezzo verificabile; il verdetto e' ricalcolabile e sempre motivato |
| ID-06 | Il monitoraggio rileva **disponibilita' e deriva** (porta, servizio, versione, sistema operativo, comparsa e scomparsa dei nodi) | La deriva e' il segnale piu' utile di un inventario: dice cosa e' cambiato, non solo cosa esiste |
| ID-07 | Fingerprinting con **UDP selettivo e script NSE mirati** solo sui nodi ancora incerti | Le porte UDP che identificano (SNMP, mDNS, NetBIOS, UPnP) sono poche: si pagano solo quando servono |
| ID-23 | Un nodo la cui subnet non e' piu' dichiarata viene **escluso dalla scelta dei bersagli** invece di far rifiutare l'intero compito, e non conta fra i profili in attesa | Il controllo del perimetro rifiuta il compito intero: un solo nodo uscito dal perimetro annullava anche i quindici bersagli legittimi che lo accompagnavano, fase dopo fase. Non e' un tentativo di violazione, e' un perimetro cambiato. La garanzia non cambia: nulla fuori dal perimetro viene scansionato, e il controllo dentro il compito resta come ultima difesa |
| ID-22 | Le fasi di ispezione hanno un **minimo per host** (180 s), indipendente dal valore scelto dall'operatore, che resta valido per scoperta, porte e sorveglianza | Il tempo per host non e' una preferenza: sotto la soglia necessaria nmap abbandona l'host e la fase non produce nulla. Misurato su una stampante multifunzione con tredici porte note: 90 s -> host abbandonato, zero porte; 300 s -> concluso in 103,5 s e dispositivo riconosciuto |
| ID-21 | La fase dei servizi interroga le **porte gia' trovate aperte** dalla fase precedente; le prime porte per frequenza restano la via di riserva per i bersagli di cui non si sa nulla | Ripartire da duecento porte spende il tempo per host su porte che non risponderanno: su sedici bersagli il processo girava oltre duecento secondi e restituiva "0 host, 0 record" |
| ID-20 | Le fasi del profilo si valutano **dalla piu' avanzata alla prima**, e un nodo attende una fase solo se le precedenti sono svolte | La scoperta aggiunge continuamente nodi privi di ogni fase: valutando le fasi nell'ordine naturale la prima ha sempre lavoro e le altre non arrivano al proprio turno. Osservati 165 nodi fermi con la sola fase delle porte svolta. Il vincolo sulle fasi precedenti impedisce che l'ordine inverso salti dei passaggi |
| ID-19 | Nel giro dell'agente il **contatto precede la scansione**, il conferimento la segue | I comandi -- fra cui la sospensione -- viaggiano nella risposta al battito, e una fase di ispezione dura minuti: dopo la scansione, i comandi arrivavano con altrettanto ritardo e la sonda dichiarava irraggiungibile un server che risponde. Il conferimento resta dopo la scansione, cosi' cio' che essa produce parte nello stesso giro |
| ID-18 | Le impostazioni modificabili su entrambi i lati (sforzo, tempo per host) si applicano solo quando il **server le cambia**: la sonda ricorda l'ultimo valore ricevuto e confronta con quello, non con il valore in uso | Il server ri-afferma la configurazione a ogni contatto: confrontando con il valore in uso, qualunque scelta fatta in sede veniva annullata entro un ciclo. L'interruttore `scan_enabled` resta invece autoritativo a ogni contatto, perche' e' una misura di sicurezza |
| ID-17 | La **scoperta ha un posto garantito** in ogni ciclo, se scaduta; i profili occupano i posti restanti | Con la precedenza assoluta ai profili, su una rete di centinaia di subnet i nodi da profilare non finiscono mai e la scoperta non avanza: osservate 2 subnet esplorate su 380 |
| ID-16 | Un nodo e' **in attesa di profilo solo finche' non e' stato conferito** almeno una volta; la ri-ispezione e' governata dalle cadenze, e il conferimento avviene solo in presenza di prove nuove (`last_merge_at` piu' recente di `conferred_at`) | Azzerare le fasi svolte al conferimento rimetteva il nodo fra quelli in attesa: la sonda riscansionava in eterno gli stessi nodi, sembrando attiva senza produrre nulla di nuovo |
| ID-15 | Le scansioni girano su un **pool di thread** (1, 2 o 4 secondo il profilo di sforzo min/med/max), con tre condizioni che rendono i thread innocui l'uno per l'altro: bersagli disgiunti nella pianificazione, prenotazione atomica in banca dati, coordinamento del conferimento nel solo thread coordinatore | Una scansione per volta non regge un perimetro di centinaia di subnet. Il parallelismo e la profondita' sono la stessa decisione -- quanto carico si accetta sulla rete del cliente -- quindi si comandano con un solo profilo invece che con due manopole slegate |
| ID-14 | Le scansioni si sospendono da **entrambi i lati**: `probes.scan_enabled` viaggia nella configurazione cifrata ed e' autoritativo; `scan_paused` e' locale alla sonda. Prevale il piu' restrittivo | Il gestore deve poter fermare una sonda senza accedervi; il tecnico in sede deve poter fermare le scansioni durante una lavorazione senza attendere il server. Il conferimento della coda prosegue in entrambi i casi |
| ID-13 | Il **banner** annunciato dai servizi entra fra le prove del fingerprinting, con un genere di regola proprio | Quando nmap non riconosce il prodotto, il banner (o l'impronta di servizio grezza) e' spesso l'unico testo che dichiara la natura dell'apparato |
| ID-12 | Le porte **iniettate dalla rete** vengono riconosciute per diffusione unita all'eterogeneita' dei sistemi operativi, marcate e escluse dalle prove -- mai cancellate | Rilevato sul campo: un ALG SIP rispondeva su tcp/2000 e tcp/5060 per ogni indirizzo, e trenta dispositivi su trentadue venivano classificati come telefono VoIP |
| ID-11 | Il conferimento avviene **a profilo completo**: un dispositivo raggiunge il server solo quando tutte le fasi di ispezione applicabili sono state svolte su di esso | Il server riceve dispositivi interi, non frammenti; nessun record puo' arrivare orfano del proprio nodo. I nodi appena scoperti hanno la precedenza sulle nuove scoperte, altrimenti su un perimetro ampio i candidati si accumulano per ore senza che nulla raggiunga il server |
| ID-10 | Il superamento dei limiti del perimetro **rifiuta** l'importazione invece di troncarla | Un perimetro troncato sembra completo senza esserlo: un file di 380 subnet importato come 64 faceva apparire coperta un sesto della rete |
| ID-27 | L'inventario si filtra per **cio' che un nodo espone**, non solo per dove sta e che cosa e' | Su 993 nodi, subnet e tipo rispondono a "dove" e "che cos'e'"; la domanda di chi lavora e' "chi ha SNMP aperto?", "quali apparati hanno un'interfaccia web?", "dove manca ancora la lettura?". Le porte marcate come iniettate dalla rete restano fuori dai filtri come restano fuori dalle prove: un ALG che risponde per altri non rende quei nodi telefoni. Un filtro non riconosciuto (famiglia inesistente, porta scritta male) viene ignorato invece di restituire il vuoto: un elenco vuoto sembrerebbe una rete vuota |
| ID-29 | La rete si rappresenta come **albero di testo** (sonda &rarr; perimetro &rarr; dispositivo), non come disegno di un grafo | Le adiacenze fra dispositivi non si deducono da una scansione: su una rete commutata cio' che si sa e' chi ha visto che cosa e dove, e quella e' una gerarchia. Un grafo di duemilaquattrocento nodi sarebbe una nuvola illeggibile; un albero fatto di `<details>` si apre e si chiude senza JavaScript, si cerca con la ricerca del browser, si stampa e si copia come testo. Ogni ramo dichiara che cosa contiene (quanti dispositivi per tipo), perche' su una subnet da duecento nodi il riepilogo dice piu' dei duecento indirizzi |
| ID-28 | Gli esiti degli script SNMP vengono **interpretati alla lettura** e mostrati in tabella, non come testo di terminale; il testo integrale resta la fonte e resta consultabile | Ottanta connessioni in un riquadro di testo non si leggono, non si ordinano e non si cercano; le stesse ottanta in tabella si'. L'interpretazione alla lettura, e non alla raccolta, vale qui come per il riconoscimento dei dispositivi (SR-47): correggere un lettore non richiede di riscansionare la rete, e cio' che oggi non si riconosce resta comunque conservato -- infatti i riassunti gia' in archivio sono stati ricalcolati senza toccare la rete |
| ID-25 | Dove la porta **161/udp** risponde, una **fase dedicata** legge tutto cio' che SNMP espone (descrizione di sistema, interfacce, tabelle, processi, software installato, condivisioni e utenti) e ne conserva il **testo integrale** in una tabella propria | SNMP racconta di un apparato piu' di dieci porte TCP, ed e' spesso l'unica fonte su switch e stampanti, che di porte utili ne hanno poche. Una fase a se' e non un'aggiunta alle altre: gli script SNMP costano tempo e riguardano pochi nodi, quindi dentro la fase dei servizi allungavano una passata che riguarda tutti. Il testo integrale in una tabella propria perche' nelle prove del profilo verrebbe troncato a 2 kB, e cio' che si perde e' esattamente l'informazione per cui si interroga SNMP. Solo script di **sola lettura**: `snmp-brute`, che indovina le community, resta fuori di proposito -- un inventario non forza serrature |
| ID-26 | La fase SNMP e' pianificata **prima** della ri-ispezione secondo cadenza | Un indirizzo non puo' comparire in due compiti dello stesso ciclo: con la fase SNMP dopo, i nodi che espongono la 161 finivano sempre in un compito di ri-ispezione e la lettura non arrivava mai al proprio turno |
| ID-24 | Una rete piu' ampia di 4096 indirizzi non viene rifiutata ma **suddivisa in blocchi** che stanno in quel limite (una `/16` diventa sedici `/20`), dichiarando la suddivisione | Il limite riguarda l'ampiezza di una singola passata -- una scansione su 65.000 indirizzi durerebbe ore e potrebbe scadere -- non il perimetro che il cliente ha diritto di dichiarare. Chi scrive `10.1.0.0/16` sa quello che vuole; rifiutarlo obbligava a scrivere sedici righe a mano. Il perimetro coperto e' identico, cambia soltanto l'unita' di lavoro; l'etichetta di ogni blocco porta la rete di origine, altrimenti sedici righe non si riconoscerebbero piu'. Oltre 512 blocchi non si suddivide: una `/8` sarebbero sedici milioni di indirizzi, e nessuno lo ha chiesto |
| ID-09 | Un host dichiarato vivo che non porta **nessun'altra informazione** non entra nell'inventario: e' un errore di rete o un falso positivo del ping. La regola si applica pero' solo **dopo** l'esame delle porte; nella sola fase di scoperta il nodo resta *candidato* | Verificato sul campo: una scoperta su una /24 raggiunta per routing ha restituito 8 host tutti con il solo `echo-reply`, e la fase successiva ha dimostrato che erano 8 dispositivi reali. Applicare la regola alla scoperta avrebbe cancellato l'intera rete |
| ID-08 | Nessuna dipendenza nuova: XML di nmap letto con `xml.etree.ElementTree` della libreria standard; i cataloghi delle firme sono quelli distribuiti con nmap | Vincolo di progetto sulle dipendenze; `nmap-mac-prefixes` contiene 52.091 prefissi MAC gia' disponibili |

---

## 3. Capacita' verificate dell'ambiente

Rilevate sulla macchina di sviluppo prima di progettare:

| Verifica | Esito |
|---|---|
| nmap presente | 7.99, `C:\Program Files (x86)\Nmap\nmap.exe` |
| Npcap | 1.87, con `AdminOnly = 0` nel registro |
| SYN scan senza elevazione (`-sS`) | Eseguito realmente: `scaninfo type="syn"` |
| Rilevamento sistema operativo senza elevazione (`-O`) | Eseguito |
| Cataloghi disponibili | `nmap-mac-prefixes` (52.091 righe), `nmap-os-db`, `nmap-service-probes`, `nmap-services`, script NSE |
| Uscita XML | `-oX`, versione schema 1.05 |

**Conseguenza progettuale.** Poiche' Npcap concede l'accesso raw agli utenti non
amministratori, la sonda puo' usare `-sS` e `-O` senza privilegi elevati. Non e'
una condizione garantita su ogni installazione: la sonda deve **accertare le
proprie capacita' all'avvio** e, se l'accesso raw non e' disponibile, ricadere su
`-sT` (connect scan) rinunciando al rilevamento del sistema operativo,
dichiarandolo nella propria pagina di stato e al server.

---

## 4. Requisiti aggiunti

Requisiti funzionali (numerazione in continuita' con `01_REQUISITI.md`).

| ID | Requisito |
|---|---|
| SR-40 | Il tenant deve poter definire le proprie subnet caricando un file di testo, una subnet per riga in notazione CIDR, con righe di commento ammesse |
| SR-41 | Il server deve validare ogni subnet: notazione corretta, assenza di duplicati e sovrapposizioni, numero di indirizzi entro il limite configurato, appartenenza agli intervalli privati salvo deroga esplicita |
| SR-42 | Le subnet approvate devono essere consegnate alla sonda nella configurazione cifrata, senza intervento sul dispositivo |
| SR-43 | La sonda deve rifiutare qualunque bersaglio non contenuto nelle subnet ricevute e registrare il rifiuto |
| SR-44 | La scansione deve procedere per fasi: scoperta, porte, servizi, sistema operativo, approfondimento, monitoraggio |
| SR-45 | Ogni fase deve essere interrompibile e ripartire senza perdere il lavoro svolto, e deve rispettare un tempo massimo dichiarato |
| SR-46 | Per ogni nodo il sistema deve determinare un **tipo di dispositivo** con un grado di confidenza e l'elenco delle prove che lo hanno motivato |
| SR-47 | Il tipo di dispositivo deve essere rideterminabile sull'intero inventario quando il catalogo delle firme cambia, senza nuove scansioni |
| SR-48 | Il sistema deve rilevare e registrare: comparsa di un nodo, scomparsa, passaggio da raggiungibile a non raggiungibile e viceversa, apertura e chiusura di una porta, cambio di servizio o versione, cambio di sistema operativo, cambio di tipo |
| SR-49 | Il monitoraggio deve conservare uno storico di raggiungibilita' e latenza per nodo, soggetto alla conservazione configurata per il tenant |
| SR-50 | La console deve presentare l'inventario con ordinamento, paginazione e ricerca generale, e permettere l'esecuzione immediata di una fase su una subnet o su un singolo nodo |
| SR-51 | Tutti gli istanti dell'inventario devono essere normalizzati al fuso orario del tenant |
| SR-52 | Un host dichiarato vivo che, dopo l'esame delle porte, non porta alcuna prova sostanziale (MAC, nome host, stato di una porta, sistema operativo, esito di script) non deve essere registrato: va scartato come errore di rete, con la motivazione |
| SR-53 | Nella sola fase di scoperta un host vivo privo di altre prove deve essere conservato come *candidato* e registrato solo dopo conferma, mai scartato |
| SR-54 | Ogni esito di ammissione (registrato, candidato, scartato) deve dichiarare la propria motivazione |
| SR-55 | I dati di un nodo devono essere conferiti soltanto quando la scoperta del dispositivo e' completa, cioe' quando tutte le fasi di ispezione applicabili sono state svolte su di esso |
| SR-56 | Un nodo non ancora conferito deve avere la precedenza sulla scoperta di nuove subnet |
| SR-57 | Il superamento dei limiti del perimetro deve rifiutare l'importazione, dichiarando i numeri, e non troncarla |
| SR-80 | La console deve offrire una rappresentazione ad albero della rete censita: sonde, perimetro dichiarato, dispositivi, con il numero di porte aperte, la presenza di letture SNMP e i riscontri di sicurezza per nodo |
| SR-78 | Gli esiti degli script SNMP devono essere presentati in forma tabellare, con il testo integrale conservato e consultabile; un esito di forma non riconosciuta deve restare leggibile come testo e non impedire la visualizzazione |
| SR-79 | Le informazioni SNMP devono comparire nei report di inventario, di sicurezza e delle vulnerabilita' |
| SR-77 | L'elenco dei nodi deve poter essere filtrato per servizio esposto, porta, ricerca libera, presenza di lettura SNMP, riscontri di sicurezza, affidabilita' dell'identificazione e recenza dell'ultimo contatto |
| SR-75 | Sui nodi che espongono la porta 161/udp la sonda deve eseguire una lettura SNMP con i soli script di sola lettura, e il server deve conservarne il testo integrale per script, oltre a un riassunto strutturato |
| SR-76 | Le informazioni SNMP conservate devono essere disponibili al riconoscimento del dispositivo anche dopo una rideterminazione del profilo, e consultabili nella pagina del nodo |
| SR-74 | Una subnet piu' ampia dell'ampiezza massima di una passata deve essere suddivisa in blocchi ammissibili, con la suddivisione dichiarata all'operatore e l'origine riportata nell'etichetta di ciascun blocco |
| SR-58 | Le porte aperte su quasi tutti i nodi e su famiglie di sistema operativo diverse, mai identificate per prodotto, devono essere marcate come iniettate dalla rete ed escluse dalle prove, restando visibili con la propria motivazione |
| SR-59 | Il banner annunciato dai servizi, quando disponibile, deve essere conservato per porta, mostrato nella console e valutato dal fingerprinting |
| SR-61 | Le scansioni devono poter essere eseguite in parallelo, con un massimo invalicabile di quattro esecuzioni contemporanee per sonda |
| SR-62 | Il grado di parallelismo e la profondita' delle scansioni devono essere governati da un profilo di sforzo a tre valori (min, med, max), impostabile dal server per sonda e dall'interfaccia locale della sonda |
| SR-63 | Due esecuzioni contemporanee non devono mai esaminare lo stesso indirizzo, nemmeno in presenza di processi distinti o dopo un riavvio |
| SR-65 | Un nodo conferito non deve essere ri-profilato immediatamente: la ri-ispezione segue le cadenze, e il conferimento avviene solo in presenza di prove nuove |
| SR-66 | La scoperta delle subnet e il completamento dei profili devono avanzare insieme: nessuna delle due attivita' deve poter essere esclusa dall'altra |
| SR-73 | La console deve consentire di scegliere piu' subnet insieme, con una casella che le seleziona o deseleziona tutte, e di attivarle o disattivarle in una sola azione; la scelta deve valere oltre la pagina visibile della tabella |
| SR-72 | Una fase che non restituisce alcun host pur avendo bersagli, e un host abbandonato da nmap per scadenza, devono essere dichiarati nel diario con il tempo per host in uso |
| SR-71 | Le fasi che interrogano i servizi devono disporre di un tempo per host non inferiore al minimo misurato come necessario, qualunque sia il valore scelto dall'operatore |
| SR-70 | Lo stato del collegamento mostrato dalla sonda deve riflettere ogni contatto riuscito, compreso il conferimento di un lotto, e non deve dichiarare interrotto un collegamento che non e' ancora stato provato |
| SR-69 | Il completamento dei profili deve procedere dai nodi piu' avanzati, e nessuna fase deve essere svolta prima di quelle che la precedono |
| SR-67 | All'avvio la sonda deve liberare le prenotazioni lasciate da un processo precedente, e un ciclo che non riesce a prenotare alcun bersaglio deve dichiararlo |
| SR-68 | L'indicatore di attivita' deve riflettere le esecuzioni realmente in corso, non le prenotazioni, che possono sopravvivere al processo che le ha prese |
| SR-64 | Il fallimento di una singola esecuzione non deve interrompere le altre ne' il ciclo; le prenotazioni devono essere rilasciate in ogni caso |
| SR-60 | Le scansioni devono poter essere sospese e riprese sia dal server (per singola sonda e per tutte le sonde di un tenant) sia dall'interfaccia locale della sonda; la sospensione non deve interrompere il conferimento dei dati gia' raccolti |

Requisiti non funzionali.

| ID | Categoria | Requisito |
|---|---|---|
| NFR-20 | Efficienza | Il fingerprinting deve valutare un nodo in tempo proporzionale alle prove raccolte, non alla dimensione del catalogo |
| NFR-21 | Riproducibilita' | Ogni verdetto deve riportare la versione del catalogo che lo ha prodotto |
| NFR-22 | Spiegabilita' | Nessun verdetto senza le prove che lo sostengono |
| NFR-23 | Prudenza di rete | Le scansioni devono avere tempi massimi e concorrenza limitata, per non disturbare la rete del cliente |
| NFR-24 | Minimizzazione | Si raccolgono dati tecnici di rete, non contenuti di traffico; nessun dato personale oltre a nomi host e indirizzi (GDPR) |

---

## 5. Modello dei dati

Tabelle nuove sul server, tutte con `tenant_id` e cascata di cancellazione.

```
subnets          perimetro dichiarato dal tenant
  id, tenant_id, cidr, label, is_enabled, host_count,
  source_file, imported_by, imported_at, notes, created_at, updated_at
  UNIQUE (tenant_id, cidr)

nodes            un nodo scoperto (l'unita' dell'inventario)
  id, tenant_id, subnet_id, probe_id, ip, mac, mac_vendor, hostname,
  status                  up | down | unknown
  latency_ms
  os_name, os_family, os_vendor, os_gen, os_accuracy, os_type
  device_type, device_label, device_confidence,
  fingerprint_json        prove e punteggi che hanno prodotto il verdetto
  catalog_version         versione del catalogo delle firme
  first_seen_at, last_seen_at, last_scan_at, last_change_at,
  is_managed, tags, notes, created_at, updated_at
  UNIQUE (tenant_id, ip)

node_ports       porte e servizi osservati su un nodo
  id, tenant_id, node_id, protocol, port, state,
  service_name, product, version, extrainfo, cpe,
  method, confidence, first_seen_at, last_seen_at, closed_at
  UNIQUE (node_id, protocol, port)

node_changes     la deriva: cosa e' cambiato e quando
  id, tenant_id, node_id, kind, subject, before_value, after_value,
  severity, created_at
  kind: node.appeared | node.disappeared | node.up | node.down |
        port.opened | port.closed | service.changed | os.changed |
        device_type.changed

monitor_samples  storico di raggiungibilita' e latenza
  id, tenant_id, node_id, checked_at, reachable, latency_ms
  INDEX (node_id, checked_at)

scan_runs        telemetria di ogni fase eseguita dalla sonda
  id, tenant_id, probe_id, stage, target, status,
  started_at, finished_at, duration_ms, hosts_total, hosts_up,
  records, nmap_args, nmap_version, detail
```

`subnets` era il nome di una tabella del vecchio dominio, rimossa dal prodotto:
la sua istruzione di eliminazione va **rimossa** dallo script dello schema,
altrimenti ogni avvio cancellerebbe la tabella nuova. Le eliminazioni di
`assets`, `scans`, `services`, `vulnerabilities` e `report_history` restano.

Archivio locale della sonda: si aggiunge `scan_state` (per ogni bersaglio e
fase, l'ultimo istante di esecuzione e l'esito) per pilotare le cadenze anche
dopo un riavvio, e le capacita' rilevate (`raw_sockets`, `nmap_version`).

---

## 6. Scansione progressiva

Sette fasi, ciascuna con bersaglio, comando, cadenza predefinita e prodotto.

| Fase | Bersaglio | Comando nmap | Cadenza | Produce |
|---|---|---|---|---|
| **1 scoperta** | subnet | `-sn -PE -PS22,80,443,3389 -PA80 -PR` | 5 min | nodi vivi, MAC, produttore, nome host |
| **2 porte** | nodi vivi | `-sS --top-ports 1000 -Pn` (o `-sT` senza accesso raw) | 6 h | porte aperte |
| **3 servizi** | nodi con porte aperte | `-sV --version-intensity 5 -Pn -p <porte note>` | 12 h, o subito se le porte cambiano | servizio, prodotto, versione, CPE |
| **4 sistema operativo** | nodi con almeno una porta aperta e una chiusa | `-O --osscan-limit --max-os-tries 1 -Pn` | 3 giorni, o subito se i servizi cambiano | famiglia, generazione, tipo, accuratezza |
| **5 approfondimento** | solo nodi con confidenza sotto soglia | `-sU -p 161,137,5353,1900,123,67 -Pn` piu' NSE mirati (`snmp-info`, `smb-os-discovery`, `http-title`, `upnp-info`) | 7 giorni, o su richiesta | prove decisive per il tipo |
| **6 lettura SNMP** | nodi con 161/udp aperta | `-sU -p 161 -Pn --script snmp-info,snmp-sysdescr,snmp-interfaces,snmp-netstat,snmp-processes,snmp-win32-*` con `--host-timeout 300s` | 12 h | descrizione di sistema, nome, tempo di accensione, collocazione, interfacce, processi, software installato |
| **7 monitoraggio** | nodi noti | verifica leggera: connessione TCP su una porta nota, o `-sn` | 2 min | raggiungibilita', latenza |

### 6.0-bis Quando nmap abbandona l'host: la regola di ammissione

Un esame delle porte finisce in due modi che non vanno confusi: **concluso senza
trovare nulla** oppure **abbandonato perche' il tempo massimo per host e' scaduto**.
nmap li distingue nel proprio XML (attributo `timedout="true"` sull'host), e il
prodotto li tratta in modo opposto.

| Esito di nmap | Significato | Effetto sull'ammissione |
|---|---|---|
| host concluso, nessuna prova | l'host e' stato esaminato ed e' vuoto | consuma un tentativo: dopo due tentativi vuoti l'indirizzo viene scartato (SR-52) |
| host `timedout` | l'host **non** e' stato esaminato | non consuma alcun tentativo; si contano le scadenze e si aumenta il tempo |

**Perche'.** Il difetto e' stato trovato sul campo: un indirizzo dichiarato vivo
dall'operatore veniva scartato con la motivazione "senza alcuna informazione dopo 2
esami delle porte", mentre nmap eseguito a mano sullo stesso indirizzo trovava porte
aperte. I due "esami" non erano esami: erano due abbandoni per tempo scaduto. Contare
un abbandono come un esame vuoto fa sparire dall'inventario proprio i dispositivi che
interessano di piu' -- quelli lenti e con molte porte.

**Come si rimedia.** La scadenza viene registrata sul nodo (`timeout_count`,
`timeout_at`) e al giro successivo il tempo massimo per quell'host viene
**raddoppiato**, fino a un tetto di 300 secondi. Il tetto limita gli aumenti: non
riduce mai un tempo massimo configurato piu' alto.

### 6.1 Esecuzione parallela

Un ciclo di scansione compone fino a N compiti indipendenti e li esegue insieme,
con N dato dal profilo di sforzo. Il limite di quattro esecuzioni contemporanee
non e' superabile da nessun profilo.

| Profilo | Thread | Modello temporale | Porte | Insistenza servizi | Tempo per host | Nodi per compito |
|---|---|---|---|---|---|---|
| `min` | 1 | `-T2` | 100 | 2 | 60 s | 8 |
| `med` | 2 | `-T3` | 200 | 5 | 120 s | 16 |
| `max` | 4 | `-T4` | 1000 | 7 | 180 s | 24 |

Il profilo si imposta dal server per singola sonda (scheda della sonda) e viaggia
nella configurazione cifrata; la sonda puo' cambiarlo dalla propria interfaccia.

**Perche' i thread non si ostacolano.** Tre condizioni, che valgono tutte insieme:

1. *Bersagli disgiunti.* La pianificazione assegna ogni indirizzo a un solo
   compito del ciclo: due thread non guardano mai lo stesso nodo. Per la scoperta
   l'unita' e' la subnet, una per compito.
2. *Prenotazione atomica.* Ogni compito prenota le proprie chiavi nella tabella
   `scan_claims`, la cui chiave primaria rende l'acquisizione atomica: l'esclusione
   regge anche fra processi distinti e sopravvive a un riavvio. Le prenotazioni piu'
   vecchie di trenta minuti vengono liberate, cosi' un thread morto non blocca un
   bersaglio per sempre.
3. *Coordinamento a valle.* I thread accumulano le prove nel profilo del proprio
   nodo e nulla piu'. Il conferimento -- che legge l'insieme dei nodi e decide quali
   profili sono completi -- avviene una sola volta, nel thread coordinatore, quando
   tutti i compiti hanno terminato. Nessuna decisione presa due volte.

A queste si aggiungono: le scritture sull'archivio locale serializzate dal lock di
`ProbeStore` su file in modalita' WAL; un file temporaneo per invocazione di nmap,
quindi nessuno stato condiviso fra le esecuzioni; il rilevamento delle capacita'
protetto da lock ed eseguito una volta sola; e la registrazione dei processi
avviati, che permette di terminarli tutti quando la scansione viene sospesa --
senza di essa, sospendere lascerebbe correre fino a quattro processi nmap fino al
loro tempo massimo.

Il fallimento di un compito e' isolato: viene annotato e restituito con il proprio
esito, gli altri compiti concludono, e le prenotazioni si rilasciano in ogni caso.

Regole comuni a tutte le fasi:

- **Perimetro.** Il bersaglio viene confrontato con le subnet ricevute; un
  indirizzo esterno interrompe la fase e produce un evento di gravita' alta.
- **Tempo massimo.** Ogni fase dichiara `--host-timeout` e un limite complessivo;
  allo scadere conferisce il risultato parziale e riprende dal punto raggiunto.
- **Concorrenza limitata.** Al massimo quattro esecuzioni di nmap per sonda,
  secondo il profilo di sforzo; l'uscita XML e' letta a processo concluso, senza
  analisi incrementale.
- **Ripartenza.** Lo stato per bersaglio e fase e' persistito prima dell'invio:
  un arresto della sonda non fa ripetere il lavoro gia' conferito.
- **Autonomia.** I risultati finiscono nella coda locale con la stessa disciplina
  di prenotazione del lotto: se il server e' assente la scansione continua.

---

## 7. Contratto di conferimento (estensione)

Nuovi tipi di record nel registro `_APPLICATORI` del server. Il trasporto, la
busta cifrata e l'idempotenza per `batch_uid` restano quelli di SNAP-SEC/1.

```json
{
  "records": {
    "nodes":   [ { "ip": "10.10.0.14", "mac": "B8:27:EB:1A:2B:3C",
                   "mac_vendor": "Raspberry Pi Foundation",
                   "hostname": "nas-01", "subnet": "10.10.0.0/24",
                   "reachable": true, "latency_ms": 3.2,
                   "seen_at": "2026-08-27 09:14:00" } ],
    "ports":   [ { "ip": "10.10.0.14", "protocol": "tcp", "port": 9100,
                   "state": "open", "service_name": "jetdirect",
                   "product": "HP LaserJet", "version": "",
                   "cpe": ["cpe:/h:hp:laserjet"], "method": "probed",
                   "confidence": 10 } ],
    "os":      [ { "ip": "10.10.0.14", "name": "Linux 5.4",
                   "family": "Linux", "vendor": "Linux", "gen": "5.X",
                   "type": "general purpose", "accuracy": 96,
                   "cpe": ["cpe:/o:linux:linux_kernel:5.4"] } ],
    "scripts": [ { "ip": "10.10.0.14", "name": "snmp-info",
                   "output": "enterprise: net-snmp ..." } ],
    "monitor": [ { "ip": "10.10.0.14", "reachable": true,
                   "latency_ms": 2.8, "checked_at": "..." } ],
    "scan_runs":[ { "stage": "ports", "target": "10.10.0.0/24",
                    "status": "completed", "started_at": "...",
                    "finished_at": "...", "hosts_total": 254,
                    "hosts_up": 31, "nmap_args": "-sS --top-ports 1000",
                    "nmap_version": "7.99" } ]
  }
}
```

Il tipo `events` resta invariato. Ogni applicatore e' responsabile di una sola
tabella e produce la deriva confrontando lo stato precedente con quello nuovo:
e' l'unico punto in cui `node_changes` viene scritto.

**Cronologia.** L'istante dichiarato dalla sonda (`seen_at`, `checked_at`) deve
essere conservato, non sostituito con l'ora di ricezione: dopo un periodo di
isolamento la sonda conferisce dati raccolti in momenti diversi, e appiattirli
sull'ora del rientro distruggerebbe la cronologia. Nell'applicatore attuale
degli eventi questo difetto e' presente ed e' da correggere insieme
all'estensione.

---

## 8. Fingerprinting

Motore deterministico a **prove pesate**, senza apprendimento automatico, con
verdetto sempre motivato. Risiede sul server (`snapserver/fingerprint.py`).

### 8.1 Prove considerate

Insieme delle porte TCP e UDP aperte; nomi di servizio, prodotto, versione e CPE;
tipo di dispositivo dichiarato da nmap (`osclass type`); famiglia e generazione
del sistema operativo; produttore ricavato dal MAC; nome host; esiti degli script
NSE.

**Indizio dal TTL.** Il TTL osservato -- il TTL iniziale meno i salti del percorso, che
sono pochi -- suggerisce la famiglia del sistema operativo: arrotondato in su al primo
valore iniziale noto vale **64** per Linux/Android/macOS/iOS/FreeBSD, **128** per
Windows recente, **255** per gli apparati di rete (Cisco IOS e simili). E' un segnale
**debole** -- NAT e firewall riscrivono il TTL -- quindi pesa poco, non decide da solo
(resta sotto la soglia minima) e si usa **solo** quando nmap non ha determinato la
famiglia: e' cio' che inclina verso Windows un nodo quasi muto che risponde solo al ping
con TTL ~120. Compare fra le prove del riconoscimento come &laquo;TTL osservato N:
compatibile con ...&raquo;.

### 8.2 Struttura del catalogo

Ogni classe di dispositivo dichiara regole con un peso:

| Genere di regola | Esempio | Peso tipico |
|---|---|---|
| porta | `tcp/9100` per la stampante | 5 |
| servizio | `jetdirect`, `ipp` | 4-5 |
| prodotto (espressione) | `(?i)hp (laserjet\|officejet)` | 5 |
| tipo dichiarato da nmap | `printer` | 6 |
| produttore del MAC | `(?i)kyocera\|ricoh\|lexmark` | 3 |
| nome host | `(?i)^npi` | 2 |
| esito NSE | `snmp-info` contiene `LaserJet` | 4 |
| **prova contraria** | `tcp/3389` aperta su una stampante | -4 |

Le prove contrarie sono essenziali per la robustezza: escludono le
classificazioni che il solo accumulo di indizi favorevoli produrrebbe.

### 8.3 Valutazione in tre stadi

1. **Regole decisive.** Un elenco ordinato di combinazioni non ambigue (per
   esempio `snmp-info` che dichiara Cisco IOS piu' porta 22 aperta = apparato di
   rete gestito). Se una scatta, il verdetto e' immediato con confidenza alta e
   la ragione registrata.
2. **Stadio indicizzato.** Porte, nomi di servizio e tipo dichiarato da nmap sono
   risolti su indici costruiti una volta sola al caricamento del catalogo:
   l'attraversamento e' sulle **prove**, non sulle regole. Ne esce un insieme
   ristretto di classi candidate con un punteggio (requisito NFR-20).
3. **Stadio a espressioni.** Solo per le classi candidate si valutano le regole
   con espressione regolare (prodotto, nome host, CPE, esiti NSE), poche per
   costruzione.

Confidenza calcolata da due componenti: quantita' assoluta di prove raggiunta
rispetto a una soglia di certezza, e **margine** sulla seconda classe. Un nodo
con molte prove ma due classi appaiate riceve confidenza bassa, ed e' questo che
lo manda alla fase 5 di approfondimento. Sotto la soglia minima il verdetto e'
`unknown`, che non e' un fallimento ma un'informazione: dice all'orchestratore
dove spendere il prossimo sforzo.

### 8.4 Classi di dispositivo previste

Apparato di rete (router, switch gestito, punto di accesso, firewall), stampante
e multifunzione, NAS e archiviazione, telecamera IP, telefono VoIP e centralino,
ipervisore, macchina virtuale, server Windows, server Linux e Unix, postazione di
lavoro, dispositivo mobile, apparato industriale e PLC, gruppo di continuita',
automazione dell'edificio, dispositivo multimediale, scheda a basso costo (SBC),
apparato sconosciuto.

### 8.4-bis Tipo dichiarato dall'operatore

Il riconoscimento pesa le prove, e le prove possono non bastare: un apparato che non
apre porte, non risponde a SNMP e non ha una pagina di gestione resta *non
identificato* per sempre, anche quando il tecnico sa che e' il PLC della linea 2. Dalla
scheda del dispositivo il tipo si puo' quindi **dichiarare**.

| Aspetto | Comportamento |
|---|---|
| Chi puo' farlo | ruolo **analista** o superiore |
| Scelta | soltanto dal **catalogo** dei tipi, piu' *Non identificato* (allowlist: un tipo inventato romperebbe filtri, conteggi e report) |
| Motivazione | testo facoltativo, fino a 300 caratteri, conservato e stampato nella scheda PDF |
| Confidenza | **100**: risponde una persona, non una somma di indizi. Cosi' il nodo esce dai filtri *da verificare*, che e' il motivo per cui lo si dichiara |
| Tracciabilita' | evento `node.type.declared` nel registro, cambiamento `device_type.declared` nella storia del nodo, con chi e quando |
| Revoca | *Torna al riconoscimento automatico*: azzera la dichiarazione e **ricalcola subito** il verdetto |

**La dichiarazione resiste ai ricalcoli.** E' la proprieta' che rende la funzione
utile: `refresh_fingerprint` -- il punto unico da cui il tipo viene scritto -- su un
nodo dichiarato aggiorna le prove e il verdetto conservato, ma **non** tocca
`device_type`, `device_label` e `device_confidence`. Vale per ogni conferimento e per la
rideterminazione dell'intero inventario (SR-47), che dichiara nel proprio esito quante
dichiarazioni ha rispettato. Senza questa regola una dichiarazione durerebbe fino alla
scansione successiva, cioe' farebbe *credere* di aver corretto l'inventario.

**Il verdetto automatico non viene spento.** Continua a essere calcolato e conservato in
`fingerprint_json`, e la scheda mostra il disaccordo: &laquo;il riconoscimento
automatico direbbe *stampante*, tu hai dichiarato *PLC*&raquo;. E' il modo in cui si
scopre che il catalogo delle firme va corretto: nasconderlo trasformerebbe un difetto
del catalogo in un dato acquisito.

**Dove si vede la differenza.** Un'icona accanto al tipo (persona con spunta) in
inventario, stato della rete, mappa, quadri NOC e SOC, Threat Intelligence; nella
scheda del nodo una fascia con chi ha dichiarato, quando e perche'; nel dato grezzo
JSON il campo `deciso_da`; nella scheda PDF dell'apparato, al posto della percentuale,
&laquo;dichiarato da *chi* il *quando*&raquo; con il motivo. La ricerca libera nella
base dati resta senza il segno: restituisce colonne generiche, decise dalla singola
interrogazione, e non ha una cella del tipo a cui attaccarlo.

**Colonne** aggiunte a `nodes`: `device_type_source` (`auto` | `manual`),
`device_type_by`, `device_type_at`, `device_type_reason`.

### 8.5 Rideterminazione

Il catalogo porta una versione. Al variare della versione il server puo'
ricalcolare il tipo di tutti i nodi partendo dalle prove conservate in
`fingerprint_json` e in `node_ports`, senza nessuna nuova scansione (SR-47). Un
cambio di verdetto genera una voce di deriva `device_type.changed`.

---

## 9. Interfaccia del server

### 8.9-0 La mappa: chi osserva, e il perimetro che tace

L'albero della rete ha un solo primo livello: la **sonda**, cioe' chi osserva. Il
perimetro non e' un ramo accanto alle sonde -- il perimetro e' del **tenant** e viene
consegnato per intero a tutte le sonde, quindi non appartiene a nessuna in particolare.
Un tentativo di metterlo al loro fianco lo faceva perfino contare fra le "sonde che
osservano": sbagliato due volte.

Le subnet **dichiarate in cui non e' stato trovato alcun dispositivo** stanno percio' in
una sezione propria sotto l'albero, e non elencate una sotto l'altra -- trecento righe
con "0 nodi" non sono un raggruppamento, sono rumore. Si raggruppano per **blocco /16**,
che e' la lettura che gli operatori hanno in testa ("la 10.10", "la 10.50"), e ogni
blocco dichiara quante subnet contiene, quanti indirizzi, e **perche'** tacciono:

| stato | che cosa significa | che cosa se ne fa |
|---|---|---|
| **sospesa** | fuori scansione per scelta | niente: e' una decisione |
| **mai scansionata** | la sonda non e' ancora arrivata | aspettare, o alzare la priorita' |
| **scansionata senza esiti** | la scansione c'e' stata e non ha risposto nessuno | quella rete e' spenta, filtrata o non usata: e' un fatto |

La distinzione fra le ultime due e' la ragione per cui questa sezione esiste: "non ho
trovato niente" e "non ho ancora guardato" portano a due azioni diverse, e senza
distinguerle l'elenco non serve. Sul campo, su 380 subnet dichiarate: 44 con
dispositivi, 188 non ancora scansionate, 148 scansionate e mute.

La seconda scheda, **Per zona di rete**, raggruppa la stessa rete per contesto
dichiarato e parte anch'essa dal perimetro: una subnet appena assegnata a una zona
compare subito, con zero dispositivi (vedi docs/12, ZR-18).

### 8.9-0-bis La mappa grafica: la stessa gerarchia, con le icone

Accanto alla mappa ad albero c'e' una **mappa grafica** (voce *Rete > Mappa grafica*),
per chi la rete la guarda invece di leggerla. Disegna la stessa gerarchia -- sonda,
rete dichiarata, dispositivi -- ma con le **icone del tipo** di ciascun nodo, il colore
dello stato e i collegamenti al centro che rappresenta la rete o la sonda.

**La disposizione la calcola il server** (`map_graphic`), non il browser. E' una scelta
precisa:

* **niente librerie di grafi e niente script inline**: la politica di sicurezza dei
  contenuti del prodotto e' restrittiva e gli asset sono serviti localmente. La
  disposizione arriva alla pagina come percentuali e si disegna con HTML, un SVG per le
  linee e le icone del catalogo -- la pagina funziona anche senza JavaScript, si stampa
  e si cerca;
* e' **verificabile con una prova**: la posizione di ogni icona e' il risultato di una
  funzione, non di una simulazione fisica che cambia a ogni caricamento.

Due viste, una pagina:

* il **panorama**: ogni sonda al centro della propria isola, le reti che osserva
  attorno; la bolla e' grande quanto la consistenza della rete e porta l'icona del tipo
  piu' presente ("questa e' una rete di stampanti") -- un'informazione che un numero non
  darebbe. Rossa se la rete ha riscontri aperti, verde se e' pulita;
* una **rete**: i dispositivi attorno al centro, ciascuno con la propria icona. I nodi
  con **riscontri aperti stanno sugli anelli interni**: se qualcosa viene troncato --
  oltre le 120 icone si sovrapporrebbero -- non e' cio' che ha un problema.

Non e', come l'albero, un grafo dei collegamenti fisici: le adiacenze fra apparati, su
una rete commutata, una scansione non le vede. Disegna cio' che il prodotto *sa*. La
legenda elenca i **soli tipi presenti**, con l'icona che il riconoscimento usa per
decidere il tipo -- un secondo elenco di icone si disallineerebbe al primo cambiamento
del catalogo.

**Disposizione a riempimento.** Gli elementi si distribuiscono su anelli ellittici che
arrivano quasi ai bordi del riquadro in larghezza e altezza: pochi elementi si allargano
verso il bordo invece di stringersi al centro, cosi' non resta lo spazio vuoto ai lati.
Il rapporto del piano e' vicino all'A4 orizzontale.

**Stampa in A4/A3.** Una barra offre i quattro formati (A4 e A3, orizzontale o
verticale) e il pulsante *Stampa ora*. In stampa la mappa **riempie il foglio scelto**
(la dimensione della pagina e' fissata via `@page`), lo sfondo sparisce e i comandi non
compaiono: resta la mappa con la sua legenda, da allegare a un verbale. La scelta del
formato governa la sola stampa, non la vista a schermo.

### 8.9-0-ter Il dettaglio di un nodo: riepilogo a colpo d'occhio

La pagina di un nodo apre con una **striscia di riepilogo** compatta -- una riga di
pastiglie con le cose che si guardano per prime, senza aprire una scheda: stato e
latenza, porte aperte, riscontri di sicurezza aperti, produttore, sistema operativo,
quali fonti di approfondimento sono gia' state lette (SNMP, SMB, web) e l'ultimo
contatto. Il resto sta nelle schede (identita', porte, vulnerabilita', letture,
storia), una per dominio, cosi' la pagina resta leggibile invece di essere un muro di
riquadri.

### 8.9-bis Le colonne dell'elenco: nome host e produttore

**Nome host sopra l'indirizzo.** Il nome host non ha una colonna propria: sta nella
cella dell'indirizzo, sopra di esso, in grigio. Chi cerca un dispositivo lo cerca per
nome quando ce l'ha e per indirizzo quando non ce l'ha, e nella stessa cella le due
cose si leggono come una sola -- con una colonna in meno da guardare. La ricerca
generale della tabella continua a trovare entrambi.

### 8.9-ter Il produttore accanto al tipo

Nella colonna **TIPO** dell'elenco dei nodi, sotto il genere, compare il
**produttore** quando si conosce. "Stampante" dice cosa fa il dispositivo; "Ricoh"
dice con chi si parla per farlo aggiornare, e sono due domande diverse.

Le fonti non valgono lo stesso, quindi hanno un ordine e la fonte si dichiara nel
suggerimento della cella:

1. **la pagina di gestione dell'apparato** (`node_web.brand`, anche via IPP): e'
   l'apparato che parla di se', ed e' la fonte piu' autorevole sulla marca;
2. **l'indirizzo MAC**: dice chi ha costruito la *scheda di rete*, che non sempre e'
   chi ha costruito il dispositivo -- va bene come ripiego, non come verita';
3. **il rilevamento del sistema operativo**: l'ultima delle tre, perche' riguarda il
   software e non l'apparato.

La stessa regola vale nella **scheda del dispositivo**, dove prima compariva soltanto il
costruttore dedotto dal MAC -- che manca quasi sempre, perche' l'indirizzo fisico si vede
solo se la sonda sta nello stesso segmento. Quando MAC e dichiarazione **non concordano**
si mostrano entrambi: un apparato con la scheda di rete di un altro costruttore e' un
fatto, non un errore da nascondere. Se l'apparato ha dichiarato anche il modello, la
scheda lo mostra accanto al produttore: "di chi e'" e "quale e'" sono la stessa
domanda.

### 9.0 Filtri dell'elenco dei nodi

I filtri sono raccolti in **quattro gruppi**, uno per domanda, con una ricerca libera
in testa e le **pastiglie dei filtri attivi** in fondo:

| Gruppo | Filtri | Che domanda risponde |
|---|---|---|
| **Dove** | subnet, zona di rete | dove sta il nodo, in quale contesto dichiarato |
| **Che cos'e'** | tipo di dispositivo, stato, identificazione | che apparato e', risponde adesso, e' un'ipotesi o un verdetto |
| **Che cosa espone** | servizio, porta, lettura SNMP, enumerazione SMB | interfaccia web / accesso remoto / condivisione / …; numero esatto (`3389`, `udp/161`); gia' letto o ancora in coda |
| **Sicurezza e tempo** | sicurezza, ultimo contatto | riscontri aperti, vulnerabilita' confermate, KEV; da quanto risponde o tace |
| _(in testa)_ | **Cerca** | indirizzo, nome host, MAC, costruttore, sistema operativo, tipo |

- **Enumerazione SMB** e' il filtro gemello della lettura SNMP: *gia' enumerata*,
  oppure *porta 139/445 aperta e mai enumerata* -- l'elenco delle macchine Windows che
  ancora mancano all'inventario SMB.
- **Le pastiglie dei filtri attivi** mostrano, sotto la maschera, ogni filtro applicato
  con la sua etichetta leggibile; ognuna e' un collegamento che rimuove *quel solo*
  parametro (l'indirizzo corrente meno quella chiave). Sono calcolate dal server:
  nessuno script in pagina, coerente con la CSP restrittiva del progetto.

I filtri si combinano e ciascuno restringe: due insieme non allargano mai il
risultato. Le famiglie di servizio usano gli stessi numeri di porta delle categorie di
rischio della reportistica (docs/08), con in piu' la famiglia *web*, che in un report
non e' una categoria di rischio ma in un inventario e' la prima cosa che si cerca.



Voci aggiunte al menu, in coerenza con l'impianto esistente:

```
Dashboard
-- INVENTARIO --
    Nodi                     elenco completo, filtri per subnet, tipo, stato
    Subnet                   caricamento del file .txt, validazione, stato
-- MONITORAGGIO --
    Stato della rete         raggiungibilita' corrente, latenze
    Cambiamenti              la deriva, per gravita' e periodo
-- SONDE --
    Flotta sonde
    Registra sonda
-- SICUREZZA --
    Audit & Eventi
-- AMMINISTRAZIONE --
    Tenant / Utenti / Impostazioni Sistema
```

Scheda del nodo: identita' (indirizzo, MAC, produttore, nome host), verdetto di
tipo con **le prove che lo motivano**, sistema operativo, tabella delle porte e
dei servizi, storico di raggiungibilita', cronologia dei cambiamenti, azioni
immediate (scansiona ora una fase, marca come gestito, annota).

Nuovi indicatori di dashboard: nodi noti, nodi raggiungibili, nodi nuovi nelle
24 ore, nodi scomparsi, cambiamenti nelle 24 ore, copertura della scansione
(quota di indirizzi del perimetro esaminati), distribuzione per tipo di
dispositivo, nodi con tipo incerto.

Tutte le tabelle con ordinamento, paginazione e ricerca generale (DataTables);
tutte le conferme con AWN; tutti gli istanti nel fuso del tenant.

---

### 9.0-bis Dichiarazione della zona sulla subnet

Nella pagina del perimetro ogni subnet porta un selettore di **zona**: e' il contesto
in cui quella porzione di rete vive, e decide se un servizio raggiungibile e' atteso,
normale o fuori posto. Il catalogo delle zone, le regole di giudizio e il ciclo di
vita dei riscontri stanno in `12_ZONE_DI_RETE.md`; qui basta sapere tre cose.

1. **La zona non cambia la scansione.** Non si scansiona di piu' o di meno per via
   della zona: cambia soltanto come si legge cio' che si e' trovato. La sola
   eccezione dichiarata riguarda le reti industriali, dove il profilo di sforzo
   consigliato resta il minimo, ma e' una scelta dell'operatore e non un
   automatismo.
2. **Una subnet senza zona vale come rete di utenza**, che e' il giudizio piu'
   severo: non dichiarare nulla non e' un modo per avere meno riscontri.
3. **Il conteggio delle subnet non dichiarate e' in vista** sulla stessa pagina: una
   rete descritta a meta' produce numeri veri solo a meta'.


### 9.0-ter Scansione estemporanea di una subnet

La scoperta ha cadenza di giorni (tre, per difetto): e' la scelta giusta per il regime
ordinario e quella sbagliata quando si e' appena dichiarata una rete, si e' spostato un
apparato o si sospetta che sia comparso qualcosa. La riga della subnet, nella pagina
del perimetro, porta quindi un pulsante che chiede subito una passata.

**Che fase.** `discovery`, e soltanto quella: e' la sola fase che accetta come
bersaglio una **rete**. Le fasi di profilo (porte, servizi, sistema operativo,
approfondimento) lavorano sui nodi gia' noti, quindi chiederle "sulla subnet" non
avrebbe un significato. L'esame delle porte dei nodi trovati segue nel ciclo ordinario,
e la pagina lo dichiara nel messaggio di esito, per non far attendere un risultato che
non arrivera' da quel comando.

**A quale sonda.** Alla sonda che ha **gia' visto nodi** in quella subnet: e' quella
che la raggiunge. Se nessuna l'ha vista -- e' il perimetro che tace -- il comando va a
**tutte** le sonde del tenant, perche' chi la raggiunga non lo si sa ancora; la sonda
che non la raggiunge conclude senza host, che e' a sua volta un'informazione.

**Che cosa il pulsante non fa.**

* Non aggira il perimetro: la verifica resta della sonda, che rifiuta un bersaglio non
  dichiarato (SR-43). Una subnet **disattivata** non entra nel perimetro consegnato, e
  la console lo dice invece di accodare un comando destinato al rifiuto.
* Non aggira la sospensione delle scansioni: se le scansioni sono sospese su tutte le
  sonde interessate la richiesta viene negata subito, con la ragione.
* Non duplica: se un comando identico e' gia' in coda (o gia' consegnato e non ancora
  eseguito) non se ne accoda un altro. Due passate identiche sulla stessa rete sono
  carico inutile sulla rete del cliente.

**Tracciabilita'.** La richiesta registra l'evento `subnet.scan.requested` con la
subnet, il numero di indirizzi e le sonde comandate. Il comando segue il percorso
ordinario dei comandi (`probe_commands`: accodato, consegnato al contatto della sonda,
confermato con l'esito), quindi resta visibile nella pagina della sonda.

**Autorizzazione.** Ruolo analista o superiore, come per la fase immediata sul singolo
nodo: e' una richiesta di lavoro, non una modifica del perimetro. Il pulsante e'
presente solo sulle subnet attive.

## 10. Ordine di realizzazione

| Passo | Contenuto | Stato |
|---|---|---|
| 1 | Questo documento di progetto | fatto |
| 2 | Modello dei dati: tabelle nuove, rimozione della cancellazione di `subnets` | fatto |
| 3 | Motore di fingerprinting con catalogo e test | fatto |
| 4 | Subnet sul server: caricamento del `.txt`, validazione, consegna nella configurazione | fatto |
| 5 | Sonda: lettura dell'XML di nmap e regola di ammissione dei nodi (ID-09) | fatto |
| 5b | Sonda: rilevamento delle capacita' ed esecutore di nmap | fatto |
| 6 | Sonda: orchestratore delle fasi con cadenze, stato persistito e conferimento a profilo completo | fatto |
| 7 | Server: applicatori dei nuovi tipi di record, deriva, correzione della cronologia | fatto |
| 8 | Console: nodi, scheda del nodo, perimetro, stato della rete, cambiamenti, dati conferiti, indicatori | fatto |
| 9 | Riconoscimento delle porte iniettate dalla rete (ID-12) | fatto |
| 10 | Banner fra le prove del fingerprinting (ID-13) | fatto |
| 11 | Sospensione delle scansioni dai due lati (ID-14) | fatto |
| 16 | Correzione dello stallo: profili, scoperta e prenotazioni (ID-16, ID-17) | fatto |
| 15 | Tempo per host selezionabile, con tempo di processo proporzionato | fatto |
| 14 | Pool di scansione parallelo con profili di sforzo (ID-15) | fatto |
| 12 | Test: 366 in totale, di cui 200 su inventario, perimetro, scansione, banner, sospensione, pool, tempi e persistenza delle scelte | fatto |
| 13 | Aggiornamento di `01`, `02`, `03`, `05` e rigenerazione dei manuali | da fare |

---

## 11. Osservazioni dalla prima scansione reale

Prima scansione eseguita su una /24 aziendale raggiunta per routing, con nmap
7.99. Tre risultati hanno effetto sul progetto.

**11.1 Su una subnet remota non si ottengono MAC ne' nomi host.** L'ARP non
attraversa il router e il DNS inverso non ha risposto: tutti gli 8 host vivi si
presentavano con il solo `echo-reply`. Ne consegue che il fingerprinting deve
poter lavorare **senza** produttore del MAC e senza nome host, cioe' sulle sole
porte, servizi e sistema operativo. Le firme che dipendono dal produttore
restano utili sulla rete locale della sonda, non altrove.

**11.2 Il TTL della risposta distingue host genuinamente diversi.** I valori
osservati (243, 116, 52, 20) corrispondono a famiglie di sistema operativo
diverse e provano che a rispondere non era un unico apparato. Il TTL viene
conservato fra le prove: serve alla conferma dei candidati e come indizio.

**11.3 Un apparato intermedio inietta porte inesistenti.** Su **tutti e 8** i
nodi -- router Cisco, stampanti HP e postazioni Windows indistintamente --
risultavano aperte `1720/tcp` (h323q931), `2000/tcp` e `5060/tcp`, in gran parte
`tcpwrapped`. Non sono servizi dei nodi: e' un apparato di rete che risponde per
ogni indirizzo (ALG SIP/H.323 o proxy trasparente).

Effetto misurato sul fingerprinting: i verdetti restano corretti (stampanti,
postazioni e router identificati), ma la classe `voip_phone` compare come
seconda su 6 nodi su 8 con punteggio 5-6, prodotta unicamente da quelle porte.
Su un nodo con poche prove proprie, un'iniezione del genere potrebbe prevalere.

Contromisura **realizzata** (ID-12): una porta viene marcata come iniettata
quando e' aperta su almeno il 95% dei nodi, su almeno tre famiglie di sistema
operativo diverse, e nmap non ha mai riconosciuto un prodotto su di essa. La
marcatura non cancella: la porta resta visibile nella console con la propria
motivazione ed e' soltanto esclusa dalle prove. Se l'apparato intermedio viene
rimosso, la marcatura si annulla da se' al conferimento successivo.

Il criterio distintivo non e' la sola diffusione: in una flotta omogenea porte
come 445 sono legittimamente presenti quasi ovunque. E' la diffusione unita
all'eterogeneita' dei sistemi operativi. Limite dichiarato: un servizio
genuinamente presente su quasi tutti i nodi di una flotta eterogenea, e mai
identificato per prodotto, viene marcato -- ed e' per questo che la marcatura
resta visibile.

Effetto misurato sull'inventario reale: applicato il riconoscimento, 31 nodi su
32 hanno cambiato tipo e la classe `voip_phone` e' scomparsa dai verdetti.

**11.5 Lo stallo silenzioso.** Con il sistema in esercizio su 380 subnet la sonda
dichiarava attivita' e non produceva nulla per un'ora. Tre cause distinte, tutte
necessarie a spiegarlo:

| Causa | Effetto osservato | Correzione |
|---|---|---|
| Il conferimento azzerava le fasi svolte del nodo | Ogni nodo conferito tornava "in attesa di profilo" (106 su 106): la sonda riscansionava in eterno gli stessi nodi | Le fasi svolte non si azzerano; in attesa solo i nodi mai conferiti; conferimento solo con prove nuove (ID-16) |
| I profili avevano la precedenza assoluta sulla scoperta | 2 subnet esplorate su 380, e l'inventario non cresceva | Un posto garantito alla scoperta in ogni ciclo (ID-17) |
| Un processo terminato lasciava le proprie prenotazioni | I cicli successivi non riuscivano a prenotare nulla e restituivano None **in silenzio**, per la mezz'ora della scadenza | Prenotazioni liberate all'avvio; un ciclo senza compiti eseguibili lo annota (SR-67) |

A queste si aggiungeva un indicatore che mentiva: dichiarava le fasi in corso
leggendole dalle prenotazioni, che erano quelle del processo morto. L'attivita' si
misura ora dalle esecuzioni di nmap effettivamente in corso (SR-68).

**11.6 Il secondo stallo: profili fermi alla fase delle porte.** Con il perimetro
completo in esercizio, la barra dei profili completati e' rimasta a 71 conferiti e
165 in lavorazione mentre la sonda dichiarava scansioni in corso. Stato misurato
sull'archivio della sonda: **131 nodi con la sola fase `ports` svolta**, nessuna
voce "Profilo completo" nel diario, e la fase dei servizi che chiudeva con "0 host,
0 record". Quattro cause distinte, tutte necessarie:

| Causa | Misura | Correzione |
|---|---|---|
| Le fasi si valutavano nell'ordine naturale, e la scoperta aggiunge continuamente nodi privi di ogni fase | La fase delle porte aveva sempre lavoro: servizi e sistema operativo non arrivavano al proprio turno | Fasi valutate dalla piu' avanzata alla prima, con il vincolo che le precedenti siano svolte (ID-20) |
| La fase dei servizi ripartiva dalle prime duecento porte, ignorando quelle che la fase precedente aveva trovato | Sedici bersagli, oltre duecento secondi di processo, nessun host restituito | Si interrogano le porte note (ID-21) |
| Il tempo per host scelto (30 s) era sotto la soglia necessaria al riconoscimento dei servizi | `Skipping host due to host timeout`, `timedout="true"`, zero porte nell'XML. A 300 s lo stesso host concludeva in 103,5 s e veniva riconosciuto | Minimo di 180 s per le fasi di ispezione (ID-22) |
| Un nodo la cui subnet non era piu' dichiarata faceva rifiutare l'intero compito | 10.10.11.48 rifiutato ogni 25 secondi, e con lui i quindici bersagli legittimi del compito | Esclusione dalla scelta dei bersagli, non rifiuto del compito (ID-23) |

Verifica dopo le correzioni, sullo stesso impianto: `Fase services su * (16
bersagli): 16 host` seguita da `Fase os su * (16 bersagli): 16 host` e da `Profilo
completo per 16 dispositivi`, con i profili conferiti passati da 72 a 88 nel primo
ciclo utile.

Il difetto comune alle quattro cause e' il silenzio: una fase che gira senza
restituire nulla non si distingueva da una rete senza dispositivi. Ora una fase
senza host e un host abbandonato per scadenza sono dichiarati nel diario con il
tempo per host in uso (SR-72).

**11.7 "Server non raggiungibile" a server raggiungibile.** La sonda dichiarava il
server irraggiungibile mentre i lotti venivano conferiti e l'ultimo contatto era di
pochi secondi prima. La scansione precedeva il contatto nel giro dell'agente: con
fasi da oltre trecento secondi, dopo un riavvio nessun battito era ancora avvenuto.
Inoltre un conferimento riuscito non riaccendeva l'indicatore, che l'errore di
trasporto invece spegneva. Correzioni: contatto prima della scansione (ID-19),
conferimento riuscito trattato come contatto, e stato iniziale ricavato dall'ultimo
contatto registrato (SR-70).

**11.4 Difetti trovati durante la prima prova sul campo.** Vale registrarli,
perche' nessuno era visibile dai test scritti prima:

| Difetto | Effetto | Correzione |
|---|---|---|
| La coda locale veniva conferita interamente come record di tipo `events`, ignorando il genere con cui era stata accodata | I lotti risultavano accettati ma l'inventario restava vuoto: nodi e porte finivano fra le annotazioni di audit | Traduzione dal genere della coda al tipo di record, con test che la fissa |
| Il limite di 64 subnet troncava il perimetro tenendo le prime | Un file di 380 subnet copriva un sesto della rete, e la scansione sembrava completa | Limiti alzati, guardia sul totale degli indirizzi, superamento rifiutato (ID-10) |
| Le cadenze lunghe si applicavano anche alla prima ispezione | Su 65 subnet i candidati si accumulavano per ore senza che nulla raggiungesse il server | Priorita' ai profili incompleti (ID-11) |
| Un `\b` passato attraverso un heredoc di shell diventava un carattere di backspace | Il pattern del firmware di archiviazione restava valido ma non corrispondeva a nulla, e il difetto era invisibile alla lettura | Corretto, con un test che vieta i caratteri di controllo in tutte le espressioni del catalogo |
| Le regole a espressione erano valutate solo sulle classi gia' candidate | Una classe identificabile soltanto dal nome del firmware non veniva mai raggiunta: un apparato OpenWrt con sole ssh e interfaccia web risultava un generico server Linux | Regole decisive sui nomi di firmware inequivocabili, piu' una passata di recupero quando le prove indicizzate sono deboli |

---

## 13-bis. Il contratto dei generi conferiti

Ogni fase accoda i propri risultati con un **genere** (`nodes`, `ports`, `snmp`,
`web`...). Al momento del conferimento il genere viene tradotto in un tipo di record
del contratto: se la traduzione non esiste, il record viene **scartato dichiarandolo
nel diario**, perche' un genere sconosciuto bloccherebbe la coda a ogni ciclo.

Il difetto da ricordare: la fase di lettura delle interfacce web accodava record di
genere `web` che il contratto non prevedeva. La sonda li scartava correttamente, la
console non riceveva nulla, la tabella delle letture restava vuota -- e **nulla
sembrava rotto**: nessun errore, nessun allarme, solo un dato che non arrivava mai. Il
guasto silenzioso e' peggio di quello rumoroso.

Da qui una prova automatica che confronta le due estremita': ogni tipo di record che la
sonda sa conferire deve avere un applicatore sulla console. Un genere in piu' da una
parte sola non fa rumore, e per questo va cercato da una macchina.

## 13-ter. Enumerazione SMB (139/445)

Dove un dispositivo espone SMB -- la **139** (NetBIOS su TCP) o la **445** (SMB
diretto, spesso l'unica aperta su Windows recenti) -- si esegue esattamente il comando
che serve a identificare una macchina Windows:

    nmap -p 139,445 --script smb-os-discovery,smb-enum-shares,smb-enum-users,smb-security-mode <ip>

E' una **fase a se'**, con la stessa disciplina della lettura SNMP: riguarda i soli nodi
con la porta aperta, ha una cadenza propria (dodici ore), comincia dai nodi mai letti
(informazione mancante) e solo dopo rilegge alla cadenza (informazione vecchia).

**Che cosa se ne ricava.**

| script | che cosa dichiara |
|---|---|
| `smb-os-discovery` | versione esatta di Windows, nome del computer, nome NetBIOS, dominio, foresta, FQDN, ora di sistema |
| `smb-enum-shares` | condivisioni pubblicate, con tipo, commento e accesso (anonimo e utente) |
| `smb-enum-users` | utenze locali e di dominio, con RID e stato dell'account |
| `smb-security-mode`, `smb2-security-mode` | se la firma dei messaggi e' richiesta (se no -- anche "supported", cioe' disponibile ma non imposta -- e' un riscontro: espone al relay). SMB2 copre gli host dove SMBv1 e' disabilitato |
| `smb-protocols` | i dialetti SMB accettati. La presenza di **SMBv1** (NT LM 0.12) e' essa stessa un riscontro: e' il protocollo di WannaCry, disabilitato per difetto sui sistemi recenti |

* **Enumerazione di sola lettura.** Si legge cio' che il servizio concede a chi lo
  interroga; `smb-brute`, che tenta credenziali, resta fuori di proposito, come
  `snmp-brute` per SNMP. Un host che nega l'enumerazione anonima risponde con un errore,
  che viene riconosciuto e non contato come una condivisione.
* **Contribuisce al riconoscimento.** `smb-os-discovery` dichiara la famiglia Windows
  meglio del rilevamento del sistema operativo: un nodo con le sole 139/445 aperte, che
  resterebbe incerto, diventa *Server Windows* o *Postazione Windows*.
* **Memorizzazione.** Come per SNMP, il testo intero di ogni script sta in una tabella
  propria (`node_smb`), non nelle prove del profilo, dove verrebbe troncato; la riga
  `summary` porta il riassunto interpretato. La pagina del nodo mostra una scheda
  *Enumerazione SMB* con le tabelle interpretate e, sotto ciascuna, il testo grezzo.
* **La risposta al "nbtstat".** Il nome NetBIOS che `nbtstat -A` avrebbe dato e' un
  sottoinsieme di cio' che `smb-os-discovery` dichiara: questa fase lo ricomprende e vi
  aggiunge dominio, FQDN, condivisioni e utenze.

**Perche' molti host danno pochi dati -- e non e' un difetto.** Su una rete moderna
gran parte dei sistemi ha SMBv1 disabilitato e nega l'enumerazione anonima: e' **buona
postura di sicurezza**. Su quegli host `smb-os-discovery` e gli `smb-enum-*` non
rispondono (nome, dominio, condivisioni e utenze restano protetti), ma `smb-protocols` e
`smb2-security-mode` forniscono comunque i dialetti supportati e lo stato della firma --
che sono le due cose piu' utili per la sicurezza. La pagina lo dichiara invece di
sembrare vuota. I dati ricchi (dominio, utenze) arrivano dai sistemi mal configurati,
che sono proprio quelli da correggere.

**Copertura ed esecuzione a richiesta.** Come SNMP, la fase avanza di **un compito per
ciclo** (fino a `hosts_per_task` nodi): su centinaia di host con SMB aperto la copertura
si completa nell'arco di piu' cicli, senza inondare la rete. Dalla scheda del nodo il
pulsante **Ripeti l'enumerazione SMB** (o *Scansiona ora* con fase `smb`) rifa'
l'enumerazione su **quel** nodo subito, utile dopo un cambiamento di configurazione o
per un controllo mirato. Dalla pagina **Nodi** il pulsante **Enumera SMB su tutti**
attiva una *priorita'* SMB: la sonda dedica i posti liberi di ogni ciclo
all'enumerazione dei nodi mai letti, finche' non ne restano -- non e' una passata
bloccante, i dati arrivano man mano e la sonda resta reattiva. La priorita' si spegne
da se' quando ogni nodo SMB e' stato letto.

## 13-quater. Catalogo NSE di arricchimento

Oltre alle fasi dedicate (SNMP, SMB, web), la **fase dei servizi** applica un insieme
curato di script NSE che arricchiscono l'identita' di un nodo servizio per servizio.
nmap li applica **solo alle porte a cui ciascuno si riferisce** (portrule): elencarli
non li esegue su tutti i bersagli, quindi il costo si paga solo dove il servizio esiste.

| servizio | script | che cosa aggiunge |
|---|---|---|
| TLS (443, 8443, …) | `ssl-cert` | soggetto e SAN del certificato: spesso il nome host e l'organizzazione reali |
| web | `http-title`, `http-server-header`, `http-generator`, `http-favicon` | nome dell'apparato o dell'applicazione, prodotto e versione del server, impronta dell'icona |
| RDP (3389) | `rdp-ntlm-info` | nome computer, dominio e build di Windows |
| NetBIOS (137) | `nbstat` | nome NetBIOS e MAC (la risposta a `nbtstat -A`) |
| SSH (22) | `ssh-hostkey`, `ssh2-enum-algos` | impronta della chiave host, algoritmi deboli |

**Criterio di inclusione (sicurezza).** Entrano solo script di categoria
`default`/`discovery` e di **sola lettura**: interrogano cio' che il servizio dichiara,
senza tentare credenziali ne' modificare nulla. Sono **esclusi di proposito** tutti gli
script di categoria `brute` (forzatura credenziali), `exploit`, `dos`
(denial-of-service) e `vuln` attivo. La correlazione con le vulnerabilita' note resta
compito della Threat Intelligence, che lavora sui dati gia' raccolti (versioni,
prodotti) senza sondare l'apparato -- si veda `10_THREAT_INTELLIGENCE.md`.

Gli esiti di questi script entrano fra le prove del riconoscimento (`build_evidence`) e
sono consultabili nel dato grezzo del nodo. Il catalogo e' dichiarato in un unico punto
(`ENRICHMENT_SCRIPTS`), cosi' che ampliarlo sia una decisione esplicita e verificabile.

## 13-quinquies. Ricerca di vulnerabilita' con nmap

Alle passate di arricchimento si aggiunge una fase **`vuln`** che verifica con nmap i
difetti piu' gravi e diffusi, e collega il risultato alla Threat Intelligence.

**Principio (sicurezza).** Si eseguono SOLO script di **rilevazione** -- che accertano
la presenza di una vulnerabilita' senza sfruttarla -- e si escludono di proposito quelli
di categoria `exploit`, `dos` (denial of service) e `brute`. Un inventario accerta, non
attacca; nel dubbio si sceglie la via piu' prudente (ACN/OWASP, CLAUDE.md).

**Che cosa verifica** (`VULN_SCRIPTS`, in un unico punto, ampliabile per decisione
esplicita):

| script | difetto |
|---|---|
| `ssl-heartbleed` | CVE-2014-0160 (Heartbleed) |
| `ssl-poodle` | CVE-2014-3566 (POODLE) |
| `ssl-ccs-injection` | CVE-2014-0224 (OpenSSL CCS injection) |
| `ssl-dh-params` | parametri Diffie-Hellman deboli (Logjam) |
| `smb-vuln-ms17-010` | CVE-2017-0143 (EternalBlue) -- sola verifica |
| `smb-double-pulsar-backdoor` | impianto DoublePulsar |
| `http-vuln-cve2017-5638` | Apache Struts (RCE) -- sola verifica |

* **Bersagli.** I soli nodi che espongono una porta a rischio (TLS, SMB, HTTP). nmap
  applica ciascuno script solo alla porta pertinente, quindi il costo si paga dove il
  servizio esiste. Prima i nodi mai verificati, poi la cadenza (giornaliera).
* **Sola rilevazione, esito dichiarato.** Un nodo verificato viene segnato tale anche
  quando nulla e' risultato vulnerabile: e' l'informazione *"controllato, nessun difetto
  fra quelli cercati"*, diversa da *"mai controllato"*.

**Il legame con la Threat Intelligence.** Ogni difetto verificato diventa un riscontro
(`ti_findings`) con **origine `nmap`**, accanto a quelli dedotti dalla correlazione per
versione:

* verdetto `VULNERABLE` -> riscontro **confermato**, confidenza 90; `LIKELY VULNERABLE`
  -> **da verificare**, confidenza 60;
* la CVE si lega al catalogo locale se presente (il vincolo la rifiuterebbe altrimenti);
  in ogni caso resta leggibile nel titolo;
* un difetto verificato e' **piu' forte** di una deduzione per versione: l'evidenza
  dichiara "verificato attivamente da nmap (script ...)";
* **cicli di vita separati.** La riconciliazione della correlazione per versione tocca
  solo i propri riscontri (colonna `source`); quelli di nmap li riasserisce o li chiude
  la fase `vuln` -- un difetto sanato, non piu' riportato alla verifica successiva,
  viene chiuso conservandone la storia (SR-144).

Nella pagina del nodo i riscontri di nmap portano un segno **nmap** nella scheda
*Vulnerabilita' ed esposizioni*; per il resto seguono lo stesso percorso di decisione
(rischio accettato, falso positivo) e compaiono negli stessi report.

## 14. Lettura delle interfacce web

### 14.1 Perche' una fase dedicata

Su una rete reale meta' degli apparati non si identifica dalle porte: una 443 aperta
e' una 443 aperta. Ma il loro pannello di gestione **si presenta da solo** -- "HP
LaserJet MFP M428", "Synology DiskStation", "FortiGate", "iDRAC9", "Grafana v10.2.3" --
ed e' informazione che l'apparato pubblica a chiunque apra un browser.

Vale piu' di quanto sembri per due ragioni:

1. **identifica** l'apparato: e' la fonte piu' esplicita dopo SNMP, e a differenza di
   SNMP non richiede una community;
2. **dichiara prodotto e versione**, che sono cio' che rende una vulnerabilita' nota
   attribuibile a un'istanza e non solo a un prodotto in generale (TI-17).

E' la prima fase che **non passa da nmap**: nmap dice che la porta e' aperta, la
pagina dice che cosa c'e' dietro.

### 14.2 Che cosa fa, e che cosa non fa

| Fa | Non fa |
|---|---|
| **GET**, mai altro. Dalla radice si segue il percorso che l'apparato stesso indica (redirezioni, `meta refresh`, salto in JavaScript, frame) fino a cinque pagine e dodici secondi per porta | Nessun tentativo di autenticazione, nessun POST, nessun indirizzo indovinato: un inventario legge il cartello sulla porta, non prova le chiavi. Nessun percorso che contenga un verbo distruttivo, e nessun indirizzo con parametri se il nome suggerisce un comando |
| Legge il **certificato** delle porte cifrate: nome, emittente, scadenza, autofirmato | Non rifiuta un certificato non valido: nelle reti interne l'autofirmato e' la norma, e rifiutarlo significherebbe non leggere nulla. L'esito si annota come informazione |
| Estrae **titolo, intestazioni, generatore, realm**, i **fatti dichiarati** (nome dispositivo, modello, posizione fisica, nome host, numero di serie, firmware, contatto) e applica un catalogo di firme dichiarate | **Non conserva il corpo della pagina**: puo' contenere nomi e recapiti, cioe' dati personali di cui il prodotto non ha bisogno (GDPR art. 5). Restano le etichette, la dimensione e un'impronta |
| Si ferma a **quattro porte** per dispositivo, con timeout di 2 s per connettersi e 5 per leggere, un tetto di cinque pagine e dodici secondi per porta e tre minuti per compito | Non segue redirezioni verso altri host: se un apparato rimanda al portale del fornitore, quel portale non e' il dispositivo e non e' nel perimetro |

Il risultato di una lettura viene **conferito subito**, come quello SNMP: senza
questo, una lettura che aggiunge marca, modello o numero di serie restava nel profilo
locale della sonda fino alla successiva fase di profilo. Sul campo, gli otto apparati
identificati via IPP non comparivano in inventario pur essendo stati letti: il dato
c'era e non si vedeva, che e' il modo peggiore di sbagliare.

Una **capacita' aggiunta dopo** si applica al parco esistente da se': un apparato con
una porta IPP e nessuna lettura IPP torna fra quelli "in attesa", perche' per lui
l'informazione non e' vecchia -- e' mancante, e "mancante" viene prima. Nessuno deve
svuotare niente a mano.

Cadenza: **una volta al giorno**. Quando una porta web si apre per la prima volta la
lettura avviene subito, perche' il nodo non ha ancora nessuna lettura in archivio --
"mai letto" viene prima di "letto e da rileggere".

### 14.2-bis Perche' la radice non basta: il caso che ha guidato il lavoro

`http://<multifunzione>/` -- un apparato in esercizio -- restituisce 577 byte: un
`meta refresh` verso una pagina di avviso, un `location.href` in JavaScript e il titolo
"Web Image Monitor". Nessuna marca, nessun modello, niente.

Tre pagine piu' avanti, dentro un frame, c'e' tutto:

    Nome dispositivo : RICOH MP C4504ex
    Posizione        : UFFICIO 12 - PIANO 1
    Nome host        : stampante-piano1

Leggere solo la radice significa non sapere niente di un apparato che dichiara tutto.
Da qui la navigazione, con un ordine dichiarato:

1. **redirezioni** HTTP (fino a quattro), solo verso lo stesso indirizzo e la stessa
   porta;
2. **`meta refresh`** e **salto in JavaScript** (`location.href`, `location.replace`):
   e' la pagina che l'apparato *voleva* mostrare;
3. **frame e iframe**: sono le sue parti;
4. **collegamenti** il cui nome o testo promette informazioni ("Informazioni
   dispositivo", "Stato", "Home"): si provano soltanto se i fatti mancano ancora --
   e' un tentativo, non una certezza;
5. **indirizzi informativi documentati** della famiglia riconosciuta (per esempio la
   pagina di stato Ricoh nelle due lingue, o l'endpoint XML di sola lettura HP): si
   provano per ultimi, e solo se l'apparato non ha ancora detto niente di se'.

Si legge **prima cio' che sta piu' avanti** nel percorso indicato dall'apparato: e' il
suo imbuto, e seguirlo e' la via piu' breve ai fatti. Le pagine di servizio -- quelle
che esistono per dire al browser che manca JavaScript o un cookie -- si leggono per
ultime, perche' occupano il budget e non portano un fatto. Appena l'apparato ha detto
identita' + un dato di contesto, **si smette**: continuare e' tempo tolto agli altri.

### 14.2-ter Prudenza sulle GET

Una GET non e' innocua se il progettista dell'apparato ha messo un'azione dietro un
collegamento. Quindi due elenchi, non uno:

* **mai**, in nessuna forma: `reboot`, `restart`, `shutdown`, `format`, `erase`,
  `delete`, `factory`, `upgrade`, `logout`, `reset` e simili. Sono azioni che si
  riconoscono dal nome e non esistono come pagine da consultare;
* **solo se l'indirizzo ha parametri**: `set`, `save`, `apply`, `enable`, `disable`,
  `start`, `stop`, `update`, `install`. `settings.htm` e' una pagina, `cgi?set=1` e' un
  comando, e la differenza sta nella coda.

La prima versione di questo elenco conteneva `start` senza distinzioni e scartava
`Start_Wlm.htm`, che e' la pagina iniziale delle Kyocera: si perdevano modello e
posizione di decine di apparati per una parola. La prudenza va calibrata, altrimenti
diventa cecita'.

### 14.2-quater I fatti, e perche' un vocabolario chiuso

Gli apparati scrivono i propri dati come coppie etichetta/valore, in tabelle o liste,
nella lingua dell'interfaccia. Il lettore riconosce un **vocabolario chiuso** di
etichette in italiano, inglese, francese, tedesco e spagnolo, per nove fatti: nome
dispositivo, modello, posizione, nome host, numero di serie, firmware, indirizzo MAC,
contatto, commento. Riconosce anche i nomi di tag equivalenti (`<MakeAndModel>`,
`<SerialNumber>`) per gli apparati che espongono un endpoint XML di sola lettura.

Il vocabolario e' chiuso di proposito: un estrattore che prendesse "qualunque coppia
con i due punti" riempirebbe l'inventario di rumore e, soprattutto, di **dati personali
non richiesti** -- i campi liberi degli apparati contengono nomi di persone.

Due regole che sembrano dettagli e non lo sono:

* un valore segnaposto ("-", "non impostato", "unknown") **vale come assente**:
  registrarlo sarebbe peggio che non averlo, perche' sembrerebbe un dato;
* un campo **vuoto resta vuoto**. Sul campo, la multifunzione ha il campo "Commento"
  vuoto (la cella contiene solo i due punti) e la prima versione dell'estrattore gli
  assegnava "Nome host", cioe' l'etichetta successiva. Un dato sbagliato e' peggio di
  un dato mancante.

**La posizione fisica** merita una riga a parte: e' l'unico dato che nessun'altra fase
puo' ricavare. Non sta in rete -- sta scritta sull'apparato da chi lo ha installato. E'
cio' che trasforma un indirizzo in "la multifunzione dell'ufficio 12".

### 14.3 Che cosa se ne ricava

Il verdetto delle firme porta sempre **la firma che lo ha deciso**: un verdetto senza
la ragione che lo motiva non e' verificabile. Quando la firma riconosce un genere di
dispositivo, la lettura vale come **regola decisiva** del riconoscimento (93%), alla
pari della dichiarazione SNMP: una pagina che si presenta con marca e modello e' una
dichiarazione dell'apparato, non un indizio.

Quando l'apparato ha **dichiarato il proprio nome**, la motivazione lo cita
testualmente e la fiducia sale al 95%: *l'apparato dichiara di se' "RICOH MP C4504ex"
nella propria pagina di gestione sulla porta 80*. Una motivazione cosi' si verifica
aprendo quella pagina, che e' la ragione per cui e' scritta in quel modo.

Il catalogo delle firme copre stampanti, apparati di rete e sicurezza, gestione dei
server (iDRAC, iLO, IPMI), archiviazione e virtualizzazione, videosorveglianza,
telefonia, gruppi di continuita', automazione industriale e le applicazioni di
gestione piu' diffuse -- oltre ai server web generici, che stanno per ultimi perche'
dicono meno di tutto il resto: nginx gira su un NAS come su un router.

Esiste anche una firma **senza marca**: sulla rete reale una ventina di apparati si
presenta come "IP Phone" e nient'altro, con la pagina dei dati protetta da credenziali.
La marca resta ignota, ma il **genere** no -- e per un inventario "telefono VoIP" vale
molto piu' di "sconosciuto".

### 14.3-bis Quando i dati ci sono ma sono chiusi

Alcuni apparati mostrano i propri dati solo dopo l'accesso. La sonda non ha credenziali
e non le tenta: in questi casi la lettura registra `facts_locked` e la scheda del
dispositivo lo scrive -- *la pagina con i dati esiste ma chiede le credenziali*. E'
un'informazione, non un guasto, e spiega perche' di quell'apparato si conosce il genere
e non il modello.

Altri apparati -- alcune Kyocera, per esempio -- costruiscono l'interfaccia via
JavaScript e non servono i dati in HTML. Anche questo e' un limite dichiarato: la marca
si riconosce (compare nel codice della pagina), il modello no.

### 14.3-ter Misure sul campo

Sull'inventario reale (rete di alcune migliaia di indirizzi):

* 45 apparati letti in 30 secondi, con il tetto di cinque pagine per porta;
* la multifunzione dell'esempio: 4 pagine in 7 secondi, con modello, posizione fisica
  e nome host;
* la maggioranza degli apparati risponde in meno di mezzo secondo e in una pagina
  sola: la navigazione costa solo dove serve.

### 14.3-quater IPP: il modello quando l'HTML non lo dice

Alcune famiglie costruiscono la propria interfaccia in JavaScript e non servono nessun
dato in HTML. Sul campo erano **382 apparati Kyocera** con la marca riconosciuta (il
nome compare nel codice della pagina) e il modello vuoto: la pagina di stato risponde
`500` a ogni tentativo, perche' i dati arrivano da chiamate che solo un browser con
JavaScript sa fare.

Quegli stessi apparati rispondono a **IPP**, il protocollo con cui ogni sistema
operativo identifica una stampante quando la si aggiunge. Su un apparato reale, dove
l'HTML non dava niente:

    printer-make-and-model          : ECOSYS M5526cdn
    printer-info                    : Kyocera ECOSYS M5526cdn
    printer-device-id               : MFG:Kyocera; MDL:ECOSYS M5526cdn; SER:...
    printer-firmware-string-version : 2R7_2000.003.101A

Marca, modello, **numero di serie** e firmware in una sola richiesta. Il numero di
serie non arriva da nessun'altra fase e vale doppio: e' cio' che lega un apparato in
rete a un contratto di assistenza o a un cespite.

**Il compromesso, dichiarato.** La lettura delle pagine web usa solo GET, per non
correre il rischio di eseguire per sbaglio un'azione. IPP, per come e' fatto il
protocollo, viaggia su HTTP con un **POST**: non esiste un modo GET di chiedere gli
attributi. La deroga e' ristretta cosi':

* una sola operazione, `Get-Printer-Attributes` (0x000B), scritta come **costante** del
  modulo e non parametrizzabile -- nessuna chiamata futura puo' trasformare questa
  lettura in una stampa o in una scrittura di configurazione;
* si chiedono **solo attributi di identita'** (`printer-*`): niente coda dei lavori,
  che contiene i nomi dei documenti e degli utenti, cioe' dati personali di cui un
  inventario non ha bisogno;
* nessuna credenziale, nessun documento inviato, tre tentativi al massimo (porta 631
  per prima, poi 80 e 443 sui percorsi noti), risposta letta fino a 32 kB e non
  conservata.

La lettura arriva in inventario come una riga di `node_web` con schema `ipp` sulla
porta 631: la tabella conserva letture di **interfacce di gestione**, e IPP e' una di
quelle. Nella fase entrano anche gli apparati che espongono **solo** la 631 e non hanno
alcuna pagina web: hanno un modello e un numero di serie da dichiarare.

### 14.3-quinquies Il PDF della lettura, e perche' non e' l'immagine della pagina

Dalla scheda **Interfacce web** si scarica il **PDF della lettura**: i fatti dichiarati,
il percorso delle pagine aperte con il loro esito, le intestazioni, il certificato, le
impronte. Si allega a una richiesta di intervento o a un inventario e dice, in una
pagina, che apparato e', dove sta e da quali pagine lo si e' saputo. Lo scarico resta nel
registro degli eventi.

Non contiene l'**immagine della pagina**, e non per una difficolta' tecnica: il
contenuto delle pagine non viene conservato (RP-08, GDPR art. 5 -- una pagina di
gestione contiene spesso nomi, recapiti e code di stampa). Cio' che si puo' stampare e'
cio' che si e' scelto di tenere, e il documento stesso lo dichiara in una sezione
propria. L'impronta del contenuto dice se la pagina e' *cambiata* dall'ultima lettura:
serve a quello, e non permette di ricostruirla.

Accanto al PDF c'e' il pulsante **Apri la pagina**, che porta all'interfaccia
dell'apparato in una scheda nuova: e' la pagina come e' adesso, e non lascia una copia
in archivio. Se in futuro servisse la copia della pagina, la strada e' un comando alla
sonda che la rilegge su richiesta -- il canale dei comandi esiste gia' -- con una
retention dichiarata: fino a quel momento la copia non esiste, e questa e' una scelta,
non una mancanza.

### 14.4 Dove si vede

Scheda **Interfacce web** nella pagina del dispositivo. In cima, un riquadro
*Dichiarato dall'apparato* per ogni porta che ha detto qualcosa di se': nome, modello,
posizione fisica, nome host, numero di serie, firmware, contatto, con il numero di
pagine che sono servite ad arrivarci. Sotto, la tabella tecnica: una riga per porta con
esito, come si presenta, prodotto e versione, certificato e data di lettura.

I fatti stanno anche **in colonna** nella banca dati (`node_web.device_name`,
`location`, `host_name`, `serial`, `firmware`, `contact`): nel dettaglio JSON c'erano
gia', ma in colonna si possono cercare, ordinare e mettere in un report -- ed e' cio'
che se ne fa. Il dettaglio completo, compreso il percorso di pagine seguito, sta nel
documento JSON del dispositivo (capitolo 15).

---

## 15. Il dato grezzo di un dispositivo (JSON)

L'interfaccia presenta cio' che il prodotto ha **capito**; questo documento serve al
contrario: **tutto quello che c'e', senza interpretazione**. Si apre dal pulsante
*JSON* nella pagina del dispositivo, e si salva come file dal pulsante accanto.

Serve a tre cose che le pagine non coprono:

* **verificare un verdetto**: se il prodotto dice "stampante al 78%", la domanda
  successiva e' "in base a che cosa", e la risposta completa sono le prove;
* **portare fuori un dispositivo**: allegarlo a una segnalazione, mandarlo a un
  fornitore, confrontarlo con la scansione di ieri;
* **capire un difetto**: quando un dato non torna, la prima cosa che serve e' cio'
  che e' stato conservato davvero.

| Sezione | Contenuto |
|---|---|
| `identita` | Indirizzo, nome host, MAC e costruttore, sistema operativo, stato, prima e ultima volta che e' stato visto |
| `collocazione` | Subnet, etichetta, **zona** (chiave e nome), sonda che lo osserva |
| `riconoscimento` | Tipo, etichetta, confidenza, versione del catalogo e **le prove** su cui poggia il verdetto |
| `porte`, `riscontri`, `letture_snmp`, `letture_web`, `variazioni`, `campioni_di_raggiungibilita` | Il dato conservato, con i limiti dichiarati in `limiti` |

Tre garanzie: il formato e' **versionato** (`snap.node/1`) perche' qualcuno lo
leggera' con uno script; il documento e' **limitato al tenant corrente**; non contiene
**chiavi, token ne' community SNMP** -- un file che si allega a una segnalazione non
deve portare fuori credenziali. Lo **scarico** resta nel registro degli eventi; la
semplice lettura no, perche' registrare ogni sguardo renderebbe invisibili le
estrazioni vere.

---

## 16. Riapplicare il prodotto ai dati gia' raccolti

Il prodotto conserva le prove e ne ricava giudizi. Quando i giudizi migliorano -- una
firma nuova, una zona dichiarata, una regola di esposizione aggiunta, un catalogo di
vulnerabilita' aggiornato -- i dati raccolti ieri restano validi ma **le conclusioni
tratte da essi no**. Senza un modo di rielaborare, il miglioramento vale solo per cio'
che si scansiona domani: su una rete che si ricensisce ogni tre giorni significa
aspettare tre giorni, e nel frattempo le due meta' dell'inventario si leggono con
criteri diversi senza che nulla lo dichiari.

Il comando sta in *Rete > Dispositivi*: **Riapplica ai dati raccolti**. Quattro passi,
in un ordine che non e' un dettaglio -- ognuno usa il risultato del precedente:

| Ordine | Passo | Che cosa fa |
|---|---|---|
| 1 | Porte attribuite dalla rete | Rivaluta quali porte sono state annunciate da un apparato intermedio: una porta che non appartiene al nodo non deve pesare su nessun verdetto |
| 2 | Riconoscimento dei dispositivi | Ricalcola tipo, etichetta e confidenza dalle prove conservate: porte, sistema operativo, script, SNMP e letture web |
| 3 | Vulnerabilita' ed esposizioni | Rifa' la correlazione: dipende dal passo 2, perche' prodotto e versione riconosciuti decidono che cosa e' attribuibile |
| 4 | Giudizio delle zone | Riapplica il contesto alle esposizioni prodotte al passo 3 |

Dal menu accanto al pulsante si esegue **un passo solo**, per chi sa quale gli serve.

**Nessuna scansione**: non contatta i dispositivi, non interroga le sonde, non esce
verso internet. Ed e' esattamente per questo che si puo' eseguire in orario di lavoro.
Ogni passo riferisce con numeri -- "368 dispositivi riesaminati, 1 cambiato" -- perche'
"fatto" non e' una risposta; un passo che non riesce viene dichiarato e **non ferma i
successivi**, che lascerebbero l'archivio a meta'.

L'operazione resta nel registro degli eventi con il riepilogo di cio' che ha prodotto.


## 12. Rischi e contromisure

| Rischio | Contromisura |
|---|---|
| Assenza di accesso raw sulla macchina della sonda | Rilevamento delle capacita' all'avvio, ricaduta su `-sT`, rinuncia dichiarata al rilevamento del sistema operativo |
| Scansione fuori perimetro | Perimetro vincolante lato sonda (ID-02), evento di gravita' alta, nessun bersaglio accettato dall'esterno |
| Disturbo della rete del cliente | Tempi massimi, una sola esecuzione per volta, UDP solo dove necessario, cadenze differenziate |
| Crescita dello storico di monitoraggio | Conservazione per tenant applicata a `monitor_samples`, aggregazione dei campioni piu' vecchi |
| Falsi verdetti di tipo | Prove contrarie, confidenza con margine, `unknown` esplicito, rideterminazione al cambio di catalogo |
| Dati personali | Si raccolgono indirizzi e nomi host, non contenuti di traffico; cancellazione per cascata alla rimozione del tenant |


---

## 12-ter. Mappa della rete

La voce *Mappa della rete* (menu Rete) mostra l'albero di cio' che il prodotto
conosce:

```
Probe-Office-Coponia  [2404 dispositivi, 2394 attivi]
├── 10.1.16.0/20      72 nodi su 4094 indirizzi possibili
│   68 Router / gateway · 2 Server Linux / Unix · 1 Firewall / UTM
│   ├── 10.1.16.1   router-piano1   Router / gateway (95%)  4 porte  SNMP
│   └── ...
└── 10.10.0.0/20      93 nodi
    50 Stampante / multifunzione · 26 Switch gestito · 15 Postazione Windows
```

Ogni foglia porta lo stato (attivo o assente), il tipo con la confidenza, il numero
di porte aperte, l'indicazione delle letture SNMP e i riscontri di sicurezza aperti;
l'indirizzo e' un collegamento alla pagina del dispositivo. Un filtro mostra i soli
dispositivi attivi. Oltre 250 dispositivi per subnet il ramo dichiara quanti ne
restano e rimanda all'elenco filtrato: un albero lungo quanto l'inventario non e'
piu' una mappa.

---

## 12-bis. Interfaccia locale della sonda

L'impianto e' quello della console del server: **menu a sinistra**, contenuto a
destra, tinte **chiare**. Chi amministra passa dall'una all'altra nello stesso
pomeriggio, e due impianti diversi costringono a reimparare dove guardare; le tinte
chiare perche' la sonda si usa in sede, su schermi qualunque e alla luce del giorno.
Sotto il breakpoint `lg` il menu si chiude nella barra superiore: la sonda si governa
anche dal telefono, in piedi davanti a un armadio di rete. Lo stato del canale e la
coda locale stanno in fondo al menu e si vedono da ogni pagina, perche' sono la
condizione in cui si sta lavorando.

L'ordine della pagina segue quello delle domande: in cima una barra di **badge** con
lo stato della scansione (in corso, sospesa in locale, disabilitata dal server),
quanti nodi sono confermati, quanti candidati, quanti profili restano da completare e
quale fase e' la prossima, con accanto l'interruttore per fermarla; poi i riquadri di
sintesi, nella stessa forma di quelli del server (etichetta, valore grande, nota,
icona colorata secondo lo stato); poi, sulla stessa riga, la **destinazione dei dati**
e l'**andamento dei record conferiti**, che sono la stessa domanda -- dove vanno i
dati e se ci stanno arrivando.

Il tracciato dei conferimenti e' volutamente **piccolo** (86 punti di altezza, senza
etichette dentro): serve a vedere se la sonda sta consegnando o si e' fermata, non a
leggere il valore di ogni lotto, che sta nella scheda dei conferimenti. Un tracciato
alto quanto una fascia direbbe la stessa cosa occupando cinque volte lo spazio.

La pagina di stato divide in **schede** le quattro parti che prima stavano una sotto
l'altra: fasi di scansione, conferimenti, identita' e canale, diario recente. Restano
fuori dalle schede -- perche' vanno viste sempre, non cercate -- lo stato del
collegamento, gli indicatori, l'indicatore di attivita' e i comandi di sospensione
delle scansioni: sono la ragione per cui quella pagina si apre.

---

## 13. Lettura SNMP

### 13.1 Perche' una fase dedicata

Su una rete reale la maggior parte degli apparati non annuncia versioni: switch,
stampanti e telefoni espongono poche porte e nessun banner utile. Dove la **161/udp**
risponde, pero', l'apparato racconta di se' piu' di quanto direbbero dieci porte TCP:
modello e firmware nella descrizione di sistema, nome, collocazione, riferimento
amministrativo, interfacce con indirizzi e velocita', e sui sistemi Windows processi,
software installato, condivisioni e utenti.

La lettura e' una **fase propria** (ID-25) e non un'aggiunta alla fase dei servizi:
riguarda pochi nodi, costa un tempo per host alto (300 s: gli script interrogano molte
tabelle e un apparato lento risponde in minuti) e ha una cadenza sua (12 ore, perche'
questi dati cambiano poco). Come fase propria compare nel diario delle scansioni con il
proprio esito, e non allunga una passata che riguarda tutti i nodi.

**Bersagli.** Solo i nodi il cui profilo locale riporta `udp/161` aperta. Interrogare
via SNMP un nodo che non la espone significherebbe attendere il tempo pieno per host
senza ottenere nulla.

**Sola lettura.** Gli script sono `snmp-info`, `snmp-sysdescr`, `snmp-interfaces`,
`snmp-netstat`, `snmp-processes`, `snmp-win32-software`, `snmp-win32-services`,
`snmp-win32-shares`, `snmp-win32-users`, `snmp-hh3c-logins`. `snmp-brute` e' escluso di
proposito: indovina le community, e un inventario non forza serrature. Le community
provate sono quelle **di fabbrica** (`public`), e trovarle funzionanti *e'* il riscontro
di sicurezza, non un tentativo di intrusione.

### 13.2 Che cosa si conserva

Una riga per script in `node_snmp` con il testo integrale (fino a 40.000 caratteri),
piu' una riga `summary` con il riassunto strutturato: descrizione di sistema, nome,
costruttore dichiarato, tempo di accensione, collocazione, riferimento, identificativo
del motore SNMP, community usata e il **numero di voci** di ciascun elenco.

Gli elenchi si contano per **voce**, non per riga: nmap stampa il nome della voce a un
livello di rientro e i suoi dettagli a uno piu' profondo, e stampa la prima riga senza
rientro. Contando ogni riga rientrata, tre interfacce con i loro indirizzi e MAC
diventavano dodici; contando le sole righe al rientro minimo se ne perdeva una. Misurato
su un apparato reale (HP JetDirect, `10.2.112.17`): otto interfacce, non sette e non
trentotto.

### 13.2-bis Dalla forma di terminale alla tabella

Gli script di nmap restituiscono testo pensato per una persona davanti a un
terminale: blocchi rientrati, etichette e valori sulla stessa riga. In `node_snmp` si
conserva quel testo -- e' cio' che l'apparato ha davvero risposto -- mentre
`snmp_tables.py` lo interpreta **alla lettura** e ne ricava tabelle:

| Script | Che tabella produce |
|---|---|
| `snmp-sysdescr` | descrizione dichiarata, tempo di accensione e i **componenti** che molti apparati impacchettano nella stessa riga (firmware, controller, moduli) |
| `snmp-info` | costruttore dichiarato, identificativo e riavvii del motore SNMP |
| `snmp-interfaces` | interfaccia, indirizzo, maschera, MAC, tipo, velocita', stato, traffico inviato e ricevuto |
| `snmp-netstat` | protocollo, indirizzo e porta locale, indirizzo e porta remota |
| `snmp-processes` | PID, nome, percorso, parametri |
| `snmp-win32-software` | software e data di installazione (le righe senza nome e le date non impostate non si mostrano) |
| `snmp-win32-shares` | condivisione, percorso, commento |
| `snmp-win32-services`, `snmp-win32-users`, `snmp-hh3c-logins` | elenchi |

Un esito di forma non riconosciuta **resta testo** e non toglie la pagina (SR-78).

**Tre difetti trovati sui dati veri e corretti.** L'identita' veniva cercata nel testo
di tutti gli script uniti: su cinque stampanti il nome del sistema risultava `OS`,
cioe' il nome del primo processo elencato -- e un dato falso e' peggio di un dato
mancante. I processi non venivano contati (l'espressione pretendeva uno spazio dopo il
numero, nmap scrive `1:`) e nemmeno le connessioni (la riga comincia con il
protocollo, non con l'indirizzo). Corretto il lettore, i 215 riassunti gia' conservati
sono stati **ricalcolati dal testo in archivio**, senza interrogare di nuovo la rete.

### 13.3 Effetto sul riconoscimento

Le letture SNMP entrano fra le **prove** del riconoscimento attraverso
`build_evidence`, che le rilegge dalla tabella a ogni valutazione: cosi' sopravvivono a
una rideterminazione dell'intero inventario (SR-76), che ricostruisce le prove da zero.
La descrizione di sistema viene accodata all'esito di `snmp-info`, perche' e' li' che le
regole del catalogo cercano cio' che l'apparato dichiara di essere.

Effetto misurato: un nodo **senza alcuna porta TCP aperta**, che resterebbe non
identificato, con la sola descrizione di sistema (`Cisco IOS Software, C2960...`) viene
riconosciuto come **switch gestito con confidenza 95**.

### 13.3-bis Nei report

Le letture SNMP non restano nella sola pagina del nodo:

- **Inventario e valutazione tecnica (R2)**: sezione *Apparati interrogati via SNMP*,
  con nome dichiarato, modello e firmware, collocazione, tempo di accensione e numero
  di interfacce. Gli apparati che espongono la porta ma non hanno risposto sono
  dichiarati come tali, perche' non e' una mancanza dell'inventario.
- **Postura di sicurezza (R4)**: quanto la community di fabbrica consegna a chiunque
  raggiunga la porta, contato -- descrizioni, interfacce, processi, software,
  connessioni, utenze.
- **Vulnerabilita' ed esposizioni (R8)**: la stessa misura come **prova**
  dell'esposizione informativa; cio' che un'esposizione consegna non e' un'ipotesi.

### 13.4 Riservatezza

SNMP puo' restituire nomi di utenti e di condivisioni: sono dati personali quando il
nome dell'utenza identifica una persona. Valgono le regole generali del prodotto --
conservazione nel tenant, retention configurabile, accesso secondo il ruolo -- e la
lettura resta consultabile nella sola pagina del nodo, non nei report distribuiti.
