# snap - Sala operativa: quadro NOC, quadro SOC, ricerca nella base dati

**Documento di specifica.** Conforme per struttura a ISO/IEC/IEEE 29148:2018
(requisiti e specifiche) e inserito nel ciclo di vita di ISO/IEC/IEEE 15288:2023.
Riferimenti normativi applicabili: Direttiva (UE) 2022/2555 (NIS2) per la gestione
degli eventi e la loro tracciabilita', Reg. (UE) 2016/679 (GDPR) artt. 4, 5 e 32 per
il trattamento di indirizzi e nomi host, Reg. (UE) 2024/2847 (CRA) per la gestione
delle vulnerabilita', OWASP ASVS/Top 10 (A03: injection) per la ricerca.

Documenti collegati: `06_INVENTARIO_E_MONITOR.md` (inventario e monitoraggio),
`07_CONTROLLI.md` (controlli e incidenti), `08_REPORT.md` (reportistica),
`10_THREAT_INTELLIGENCE.md` (correlazione con le vulnerabilita' note).

---

## 1. Portata

Tre pagine per tre modi di lavorare sullo stesso dato gia' raccolto. Nessuna di esse
avvia scansioni, contatta le sonde o esce verso internet: sono **viste**.

| Pagina | Chi la usa | Domanda a cui risponde |
|---|---|---|
| **Quadro NOC** (`/ops/noc`) | turno operativo | Che cosa non funziona *adesso*, che cosa e' instabile, chi non risponde piu', chi rallenta |
| **Quadro SOC** (`/ops/soc`) | sicurezza | Che cosa e' *cambiato* nella superficie esposta, che cosa e' dimostrato, che cosa va investigato |
| **Ricerca** (`/ops/search`) | tutti | Dove sta quello che ho in mano; e le domande che si ripetono, gia' scritte |

---

## 2. Decisioni assunte

| ID | Decisione | Perche' |
|---|---|---|
| SO-01 | Il NOC guarda **l'ultimo esito di ciascun controllo**, non "un errore nelle ultime ore" | Un controllo che ha fallito alle tre ma alle quattro e' tornato a posto non e' un problema aperto. La domanda del turno e' che cosa non funziona *adesso*, e un elenco che mescola le due cose fa perdere tempo su ferite gia' chiuse |
| SO-02 | Il NOC ha una sezione per cio' che **va e viene**, contando i *cambi di stato* e non i fallimenti | Un servizio fermo si vede; uno instabile consuma il turno e non compare in nessun elenco di errori, perche' quando lo si guarda funziona |
| SO-03 | I nodi che sono stati interrogati e non hanno risposto si chiamano **"in silenzio"**, non "caduti" | Un dispositivo spento di proposito e uno guasto danno lo stesso risultato: la pagina riporta il fatto, il giudizio spetta a chi conosce la rete. Chi non e' stato interrogato affatto sta in un elenco diverso (SO-13) |
| SO-13 | **"Non ha risposto" e "non gliel'abbiamo chiesto" sono due elenchi diversi** | Difetto misurato in esercizio: su tremila nodi la sorveglianza ruota, e guardando l'ultima volta in cui un dispositivo era stato *visto* finivano fra i muti apparati perfettamente vivi, solo non ancora ripassati. Il primo elenco e' un guasto da verificare, il secondo e' copertura che manca: mescolarli fa perdere fiducia in entrambi |
| SO-14 | Il silenzio si decide sull'**ultima verifica**, non su una colonna di stato | La prova diretta viene prima del riassunto: se l'ultima interrogazione dice che il nodo ha risposto, quel nodo non e' in silenzio, qualunque cosa dica una colonna aggiornata dai conferimenti. Lo stato vale solo dove una verifica non c'e' mai stata |
| SO-15 | Il SOC misura la **postura di segmentazione** accanto ai riscontri | Se il contesto governa la gravita' (`12_ZONE_DI_RETE.md`), chi guarda la sicurezza deve poter vedere quanta parte del perimetro e' descritta e quante violazioni di zona ci sono: sono la stessa domanda vista dall'architettura |
| SO-16 | Il SOC dichiara la **copertura ATT&CK**: quali tecniche la superficie attuale renderebbe possibili, con quanti dispositivi ciascuna | Un elenco di porte non si porta in una riunione di sicurezza; "T1021.004 - accesso remoto via SSH: 880 dispositivi" si', perche' e' il linguaggio con cui si descrivono gli attacchi e si confrontano le difese |
| SO-17 | Il SOC riporta l'**andamento della superficie** su trenta giorni, anche quando la finestra scelta e' piu' corta | Una giornata non dice se la superficie sta crescendo. La tendenza e' l'unica misura che distingue una novita' da un'abitudine, e va guardata su una scala piu' lunga della domanda che si sta facendo |
| SO-04 | La prima riga del NOC e' una **frase**, non un colore | Si legge da lontano, si ripete al telefono, e funziona anche per chi non distingue i colori (WCAG 2.1 AA, 1.4.1) |
| SO-05 | Il SOC apre con la **variazione** e non con lo stato | Una porta aperta da sempre e' architettura nota; la stessa porta aperta ieri e' un evento (RP-12). Lo stato -- superficie, riscontri, anomalie -- viene dopo, nelle schede |
| SO-06 | Il SOC ha una **finestra scegliibile** fra 1, 7 e 30 giorni | Ventiquattr'ore risponde a "che cosa e' successo stanotte"; sette e' la settimana di lavoro; trenta distingue una novita' da un'abitudine. Una finestra non prevista non e' un errore: vale la predefinita |
| SO-07 | Le **identita' cambiate** sullo stesso indirizzo hanno una sezione propria | Un indirizzo che era una stampante e adesso e' un server non e' un aggiornamento del catalogo: o e' stato riassegnato, o e' stato collegato un altro apparato |
| SO-08 | La ricerca libera cerca in **piu' generi di dato** e dichiara in quale ha trovato | Chi cerca ha in mano un biglietto -- un indirizzo, un MAC, una CVE -- e non sa in quale tabella guardare. Un elenco piatto senza contesto costringerebbe a indovinare |
| SO-09 | **Nessun SQL arriva dall'esterno**: le interrogazioni pronte sono dichiarate nel codice, la ricerca libera confronta con colonne dichiarate | Un campo che accettasse SQL sarebbe una porta aperta sul database di tutti i tenant (OWASP A03), e nessuna comodita' la vale |
| SO-10 | Sotto i **due caratteri** la ricerca non parte | Restituirebbe mezzo inventario: non sarebbe una ricerca, sarebbe un elenco |
| SO-11 | L'esportazione in **CSV** e' tracciata nel registro, con chi l'ha chiesta e quante righe | Un CSV si apre in un foglio di calcolo e finisce in una cartella condivisa; puo' contenere indirizzi e nomi host, che sono dati personali quando identificano una persona (GDPR art. 4) |
| SO-12 | Le tre pagine hanno un **menu proprio** in cima al menu laterale | Sono il punto di partenza del turno, non una sezione fra le altre: chi apre la console la mattina comincia da li' |

---

## 3. Requisiti

| ID | Requisito |
|---|---|
| SR-81 | La console deve offrire un quadro NOC con i controlli il cui ultimo esito non e' riuscito, i controlli instabili, i nodi in silenzio, i bersagli piu' lenti e lo stato delle sonde |
| SR-82 | Il quadro NOC deve dichiarare in una frase se il turno e' tranquillo |
| SR-83 | La console deve offrire un quadro SOC con le variazioni della superficie esposta in una finestra scegliibile, i dispositivi da cui cominciare, la superficie per categoria di rischio, le anomalie e il registro degli eventi gravi |
| SR-84 | La console deve offrire una ricerca libera su dispositivi, servizi, riscontri, letture SNMP, controlli, perimetro, registro eventi e catalogo CVE, limitata al tenant corrente |
| SR-85 | Le interrogazioni pronte devono essere dichiarate nel codice, parametrizzate, e non devono accettare SQL dall'esterno |
| SR-86 | L'esportazione dei risultati in CSV deve essere tracciata nel registro degli eventi |
| SR-165 | Il quadro NOC deve distinguere i dispositivi interrogati che non hanno risposto da quelli che nella finestra non sono stati interrogati |
| SR-166 | La condizione di silenzio deve essere determinata dall'esito dell'ultima verifica di raggiungibilita' del dispositivo; lo stato registrato vale solo in assenza di verifiche |
| SR-167 | Il quadro SOC deve riportare la postura di segmentazione, la copertura delle tecniche ATT&CK derivate dalla superficie, le porte apertesi nella finestra e l'andamento della superficie su trenta giorni |

---

## 4. Quadro NOC

**Indicatori**: in errore adesso, incidenti aperti, instabili nelle 24 ore, in
silenzio, non interrogati, riuscita 24 ore, sonde in contatto.

**Non funziona adesso.** Per ciascun controllo attivo si legge l'ultimo esito; se non
e' riuscito il controllo compare, con la gravita' dichiarata, da quando dura
(dall'apertura dell'incidente, se c'e'), quante volte ha fallito nelle 24 ore e il
collegamento all'incidente. E' l'unica tabella fuori dalle schede, perche' e' l'unica
che si guarda per prima.

**Va e viene.** Si contano i cambi di stato di ciascun controllo nelle ultime 24 ore;
compaiono quelli con almeno due cambi, in ordine di instabilita'.

**In silenzio.** Dispositivi che *sono stati interrogati e non hanno risposto*:
l'ultima verifica di raggiungibilita' dice zero, oppure una verifica non c'e' mai
stata e lo stato registrato non e' *up* (SO-14). Per ciascuno si legge quando e'
avvenuta l'ultima verifica e se il dispositivo e' sorvegliato da un controllo: un
apparato muto e non sorvegliato e' un buco doppio.

**Non interrogati.** Dispositivi attivi che nelle ultime ventiquattr'ore la
sorveglianza non ha raggiunto affatto. Non e' un guasto: e' copertura che manca. Su
un perimetro ampio la rotazione lascia sempre qualcuno indietro; se l'elenco e' lungo
o cresce di giorno in giorno il problema sta nella cadenza del monitoraggio, nel
profilo di sforzo o nel numero di nodi per passata -- non nei singoli indirizzi
(SO-13, SR-165).

*Perche' la distinzione esiste.* In esercizio, su una rete di circa tremila
dispositivi, l'elenco dei muti conteneva apparati che rispondevano perfettamente:
erano semplicemente non ancora ripassati dal giro di sorveglianza. Un elenco che
contiene falsi allarmi smette di essere letto, e con esso i veri.

**Lentezza.** Latenza media e massima per bersaglio nelle 24 ore, sui controlli con
almeno tre misure: sotto quella soglia una media non significa niente.

**Sonde.** Ultimo contatto, lotti e record delle 24 ore, scansioni eseguite, comandi
in attesa, versione dell'agente.

**Andamenti.** Riuscita per ora (24 ore) e disponibilita' per giorno (14 giorni). Le
ore senza esecuzioni non compaiono: uno zero direbbe che tutto e' fallito.

---

## 5. Quadro SOC

**Indicatori**: porte aperte nella finestra, dispositivi comparsi, identita'
cambiate, vulnerabilita' confermate, esposizioni, attese nel contesto, violazioni di
zona, nodi fuori perimetro.

**Variazioni** (scheda predefinita): porte aperte di recente con il servizio che
risponde; dispositivi comparsi con quante porte hanno gia'; identita' cambiate con il
prima e il dopo.

**Da cui cominciare**: i dispositivi con riscontri aperti, ordinati per gravita' di
cio' che portano -- prima chi ha vulnerabilita' sfruttate attivamente (CISA KEV), poi
chi ne ha di confermate.

**Segmentazione**: la postura delle zone di rete (`12_ZONE_DI_RETE.md`). Quante
esposizioni sono **attese** nel contesto in cui si trovano e quante sono
**violazioni** della zona dichiarata; quanta parte del perimetro non ha ancora una
zona, che e' la prima cosa da sistemare perche' il resto significhi qualcosa. Le due
misure non si sommano e non si sostituiscono: la prima dice quanto rumore e' stato
tolto, la seconda quanto segnale e' rimasto (SO-15).

**Superficie esposta**: per categoria di rischio, con il motivo per cui ciascuna
conta; accanto, la misura di **che cosa consegna SNMP** a chi interroga con la
community di fabbrica. Nella stessa scheda:

- **Tecniche ATT&CK rese possibili** dalla superficie attuale, con quanti dispositivi
  ciascuna interessa. Non e' un elenco di attacchi in corso: e' la traduzione della
  superficie nel linguaggio con cui si discute di difese (SO-16). Su una rete reale
  le prime due voci sono in genere T1046 (scoperta dei servizi) e T1021.004 (accesso
  remoto via SSH).
- **Porte apertesi nella finestra**, raggruppate per porta e non per dispositivo:
  quindici apparati che aprono la stessa porta lo stesso giorno sono un'installazione
  o un cambio di configurazione, non quindici eventi da guardare uno per uno.
- **Andamento della superficie** su trenta giorni, indipendentemente dalla finestra
  scelta per il resto della pagina (SO-17): una giornata non dice se si sta
  crescendo.

**Anomalie**: nodi fuori perimetro e porte riconosciute come iniettate dalla rete.

**Registro e regole**: eventi gravi, regole di notifica scattate (se una regola non
scatta mai, o e' scritta male o quell'evento non accade) e accessi non riusciti alla
console.

---

## 6. Ricerca

### 6.1 Ricerca libera

Un solo campo. Il testo viene cercato dentro: indirizzo, nome host, MAC, costruttore,
sistema operativo e tipo dei **dispositivi**; nome, prodotto, versione, banner e CPE
dei **servizi**; titolo, CVE, prodotto e motivazione dei **riscontri**; testo delle
**letture SNMP**; nome e bersaglio dei **controlli**; CIDR ed etichetta del
**perimetro**; descrizione, tipo e attore del **registro eventi**; identificativo e
descrizione del **catalogo CVE**.

Ogni genere di risultato ha la sua tabella e il collegamento al dettaglio. Il
catalogo CVE e' comune a tutti i tenant e la pagina lo dichiara; tutto il resto e'
limitato al tenant corrente.

### 6.2 Interrogazioni pronte

Sedici domande che si ripetono, con la loro motivazione in chiaro:

| Interrogazione | A che cosa serve |
|---|---|
| Chi espone il desktop remoto | RDP e VNC: la prima porta che un attacco con credenziali rubate prova |
| Chi parla in chiaro | Telnet, FTP e simili: credenziali leggibili sul percorso |
| Banche dati raggiungibili | Una banca dati raggiungibile da una rete di utenza non ha ragione di esserlo |
| Servizi che dichiarano la versione | I soli su cui una vulnerabilita' puo' essere confermata |
| Dispositivi da identificare, con porte aperte | Il primo elenco da guardare in un inventario |
| Comparsi negli ultimi sette giorni | Un indirizzo nuovo e' sempre una domanda |
| In silenzio da oltre sette giorni | Spenti o guasti: la differenza la sa chi conosce la rete |
| Porte piu' diffuse in rete | Come e' fatta la rete, meglio di qualunque elenco |
| Prodotti riconosciuti | L'elenco su cui lavora la correlazione |
| Apparati che rispondono a SNMP | Che cosa raccontano di se' a chiunque |
| Vulnerabilita' sfruttate attivamente | Il dato piu' azionabile che esista |
| Controlli che falliscono di piu' | Dove si consuma il turno |
| Bersagli piu' lenti | La lentezza precede spesso il guasto |
| Copertura del perimetro | Quanto di cio' che si e' dichiarato e' stato visto |
| Eventi gravi del registro | Che cosa il sistema ha annotato |
| Conferimenti rifiutati o parziali | Se una sonda consegna e il server rifiuta, l'inventario invecchia in silenzio |

A video l'elenco si ferma a 200 righe; l'esportazione in CSV ne porta fino a 5.000,
perche' un foglio di calcolo le regge e una pagina no. Il separatore e' il punto e
virgola e il file porta il segno d'ordine UTF-8, cosi' i fogli di calcolo italiani lo
aprono in colonne senza chiedere nulla.

---

## 7. Riservatezza e conformita'

- Ogni interrogazione e' **limitata al tenant corrente**; l'unico dato comune e' il
  catalogo delle CVE, che non contiene nulla del cliente.
- L'esportazione CSV e' **tracciata** (SR-86): il registro dice chi, quando, quale
  interrogazione e quante righe. E' cio' che serve a rispondere alla domanda "chi ha
  portato fuori questo elenco" (NIS2, tracciabilita').
- Indirizzi e nomi host sono dati personali quando identificano una persona (GDPR
  art. 4): le pagine li mostrano a chi ha gia' accesso al tenant, e il CSV eredita la
  stessa responsabilita' di qualunque estrazione.
- Nessun SQL dell'utente raggiunge la banca dati (SO-09).

---

## 8. Limiti dichiarati

- Il quadro NOC non ha aggiornamento automatico: si ricarica con il pulsante. Un
  aggiornamento continuo su una pagina che interroga molte tabelle costerebbe piu' di
  quanto renda, e chi tiene il turno ricarica quando serve.
- La ricerca libera confronta il testo per intero dentro i campi: un indirizzo
  parziale funziona, una parola con un errore di battitura no. Non c'e' ricerca
  fonetica ne' correzione automatica, che su nomi di apparati produrrebbero piu'
  rumore che aiuto.
- Le interrogazioni pronte sono un catalogo chiuso: aggiungerne una e' una modifica
  al codice, per la ragione dichiarata in SO-09.
- L'elenco dei **non interrogati** dipende dalla finestra di ventiquattr'ore: su una
  rete molto ampia con cadenza di monitoraggio piu' lunga sara' sempre popolato, e in
  quel caso non e' un difetto ma la descrizione onesta di come e' configurata la
  sorveglianza. Il numero da guardare e' la sua tendenza, non il suo valore.
- Le tecniche ATT&CK sono derivate dalla **superficie**, non da attivita' osservata:
  dicono che cosa sarebbe possibile, non che cosa e' accaduto. Confonderle sarebbe il
  modo piu' rapido per trasformare un inventario in un falso rilevamento.
