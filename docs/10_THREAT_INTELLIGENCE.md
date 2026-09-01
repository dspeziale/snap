# snap - Threat Intelligence: CVE, CWE, NVD, MITRE e correlazione con i nodi

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT

Documento di progetto redatto secondo ISO/IEC/IEEE 29148:2018 (requisiti),
ISO/IEC/IEEE 15288:2015 (processi di ciclo di vita) e ISO/IEC/IEEE 19510:2013 per la
rappresentazione dei flussi. Vincoli di riservatezza e sicurezza: Regolamento (UE)
2016/679 (GDPR), Regolamento (UE) 2024/2847 (CRA), Direttiva (UE) 2022/2555 (NIS2),
ETSI EN 303 645, EN 50649:2024.

> **Stato: realizzato.** `server/snapserver/threat.py` (dominio e correlazione),
> `threat_sources.py` (NVD, CISA KEV, MITRE CWE, MITRE ATT&CK, importazione da file),
> `blueprints/threat.py`, modelli in `templates/threat/`; prove in
> `tests/test_threat.py` (27).

---

## 1. Portata

Il prodotto sapeva **che cosa c'e' in rete**. Non sapeva **che cosa il mondo sa essere
un problema** di cio' che c'e' in rete. Questo documento specifica il dominio che collega
le due cose: un catalogo locale di vulnerabilita' e tecniche di attacco, e una
correlazione con l'inventario che dichiara sempre quanto vale.

Fuori portata: scansione attiva di vulnerabilita' (il prodotto osserva, non sollecita);
gestione delle patch; punteggio di rischio aggregato per dispositivo -- un numero unico
nasconde proprio la distinzione fra fatto e ipotesi che questo documento difende.

---

## 2. Il problema, prima della soluzione

Correlare un inventario con le CVE e' facile da fare male: si cerca il nome del prodotto
nel testo della vulnerabilita' e si produce un elenco lungo, spaventoso e inutile.

Sull'inventario reale del progetto, al momento della realizzazione:

| Misura | Valore |
|---|---|
| Porte aperte | 3.456 |
| Con identificativo di prodotto (CPE) | 230 |
| **Con versione** | **14** |

Una CVE si attribuisce a un'istanza **solo conoscendo la versione**: senza, qualunque
affermazione del tipo "questo nodo e' vulnerabile a CVE-X" e' indimostrabile nel 99,6%
dei casi. Un prodotto che la facesse comunque produrrebbe un elenco che nessuno guarda,
e nel quale i pochi riscontri veri si perdono.

---

## 3. Decisioni assunte

| ID | Decisione | Perche' |
|---|---|---|
| TI-01 | Tre **classi di riscontro** sempre distinte: `confermato` (prodotto e versione noti, applicabilita' NVD soddisfatta), `da verificare` (prodotto noto, versione ignota), `esposizione` (nessuna CVE: e' il servizio in se' a essere un rischio) | Un elenco che mescola fatti e ipotesi non e' utilizzabile: chi lo legge non sa quali righe sono vere. Le tre classi rispondono a tre domande diverse -- che cosa e' dimostrato, che cosa va accertato, che cosa e' rischioso per natura |
| TI-02 | Il catalogo e' **locale**; la correlazione non contatta nessuno | Funziona in una rete isolata, non dipende dalla disponibilita' di un servizio esterno, e non manda l'inventario del cliente a nessuno. Aggiornare il catalogo e' l'unico momento in cui il server esce verso internet, ed e' esplicito |
| TI-03 | Il catalogo e' **globale** (condiviso fra i tenant); le correlazioni sono **per tenant** | CVE e tecniche sono conoscenza pubblica: duplicarle per tenant moltiplicherebbe centinaia di migliaia di righe senza aggiungere nulla. I riscontri, invece, dicono che cosa ha quel cliente in rete, e sono dato riservato |
| TI-04 | L'aggiornamento predefinito e' **guidato dall'inventario**: si interroga la NVD sui prodotti che esistono davvero in rete | Scaricare 250.000 CVE per correlarne trenta e' lavoro inutile, e produce un catalogo che nessuno tiene aggiornato. Sull'inventario reale: 9 prodotti, 138 secondi, 880 CVE pertinenti |
| TI-05 | Una versione **fuori dall'intervallo dichiarato non produce nulla** | E' la regola che separa una correlazione da un generatore di falsi positivi |
| TI-06 | Una versione **non confrontabile** (`2.2.X - 2.3.X`) non produce certezze | nmap restituisce intervalli: un confronto su quella stringa darebbe un esito inventato |
| TI-07 | I riscontri `da verificare` sono **aggregati per prodotto**, uno per (nodo, porta) | Un solo Oracle TNS senza versione generava cinquanta righe, e l'inventario intero 1.529: illeggibile. La domanda di questa classe non e' "quali CVE" ma "dove serve rilevare la versione" |
| TI-08 | La **versione annunciata da un servizio non e' la versione del sistema operativo** | Difetto trovato sui dati reali: la porta 593 dichiarava `cpe:/a:microsoft:qotd,cpe:/o:microsoft:windows` e versione "1.0" (del protocollo RPC over HTTP). Attribuendola al CPE del sistema si otteneva "Windows 1.0", che corrispondeva a ogni CVE dichiarata per `windows:*`: tre nodi marcati vulnerabili a dodici CVE, tutte false |
| TI-09 | Ogni riscontro porta la propria **confidenza** e la **motivazione in chiaro** | Un riscontro senza motivazione non e' verificabile, e chi lo legge non puo' decidere se fidarsi. La confidenza scende quando il prodotto e' dedotto per euristica dal nome del servizio, o quando la versione viene dal banner invece che dal CPE |
| TI-10 | Le **esposizioni** non dipendono dal catalogo e sono associate a una tecnica **MITRE ATT&CK** | Su un inventario senza versioni sono la classe che porta piu' informazione. La tecnica dice *come* l'esposizione verrebbe usata, che e' cio' che manca a un elenco di porte aperte |
| TI-11 | L'associazione porta&rarr;tecnica e' **nostra**, e viene dichiarata come tale | MITRE non pubblica una mappa "porta 3389 &rarr; T1021.001". Spacciarla per dato ufficiale sarebbe scorretto |
| TI-12 | **CISA KEV** entra nel catalogo e marca le CVE sfruttate attivamente | E' il singolo dato piu' azionabile che esista su una vulnerabilita': fra due con lo stesso punteggio, quella sfruttata va prima. Le CVE del KEV entrano in catalogo anche se la NVD non e' ancora stata interrogata |
| TI-13 | La decisione dell'operatore (rischio accettato, falso positivo) **non viene sovrascritta** dalla rivalutazione | Diversamente ogni passata cancellerebbe il lavoro di chi ha valutato. Un riscontro riconfermato torna a essere *visto*, non riaperto |
| TI-14 | Accettare un rischio o dichiarare un falso positivo **richiede una motivazione** | Senza, fra sei mesi nessuno sapra' perche' quel riscontro e' stato messo da parte |
| TI-15 | Un riscontro non piu' osservato **si chiude, non si cancella** | La storia di cio' che era esposto e' informazione: cancellarla renderebbe impossibile dire quando e' stato chiuso |
| TI-16 | L'importazione da **file** e' una via di pari dignita' | Per le installazioni senza uscita verso internet, che sono la norma in molti ambienti della pubblica amministrazione. Il formato si riconosce dal contenuto, non dall'estensione: un file rinominato non deve finire nella tabella sbagliata |
| TI-17 | La pagina dichiara la **qualita' del dato** su cui sta lavorando | Con 14 versioni su 3.456 porte, "nessuna vulnerabilita' confermata" e' vero ma fuorviante se non si dice perche'. La stessa frase compare nel report di sicurezza |
| TI-24 | L'elenco dei riscontri e' **per dispositivo**, non per riscontro | Lo stesso apparato compariva in venti righe -- una per porta e per CVE -- mentre la domanda di chi lavora e' "da quale dispositivo comincio". Ogni riga porta quanto quel nodo ha da sistemare, diviso per classe, con la gravita' peggiore e le vulnerabilita' sfruttate attivamente in evidenza; i singoli riscontri e le **decisioni** (rischio accettato, falso positivo) stanno nella pagina del nodo, che e' dove si guarda il dispositivo |
| TI-23 | La pagina e' divisa in **schede che sono collegamenti**, e ogni scheda carica soltanto cio' che mostra | Costruire insieme riscontri, catalogo, CWE, tecniche e registro produceva 1,7 MB di marcatura e quattro tabelle da impaginare nel browser, per guardarne una: 523 kB dopo la divisione, e le schede piu' leggere (sorgenti 43 kB, CWE 101 kB). I riscontri si dividono ulteriormente per **classe**, perche' un elenco che mescola fatti e ipotesi non e' utilizzabile (TI-02), e si fermano a 200 righe per classe: piu' lungo non si legge |
| TI-22 | Il legame fra una CVE e le sue classi di debolezza sta in una **tabella propria** (`ti_cve_cwe`), scritta insieme alla CVE | La colonna testuale `cwe_ids` conserva cio' che la sorgente dichiara, ma non e' interrogabile: contare quante CVE citino ciascuna delle 130 debolezze richiedeva un confronto testuale su tutte le CVE per ciascuna debolezza. Misurato su 8.915 CVE: **14,3 secondi** su 14,6 dell'intera pagina. Con il legame in tabella la stessa risposta costa **0,011 s**. Un archivio popolato prima che la tabella esistesse si riempie da solo al primo avvio, dalla colonna testuale, senza contattare nessuna sorgente |
| TI-19 | La **chiave API della NVD** e' una credenziale dell'installazione, non di un cliente: la registra il solo amministratore di sistema | Il catalogo e' unico per tutto il server. Con la chiave la NVD concede 50 richieste ogni 30 secondi invece di 5, e l'aggiornamento per l'inventario passa da minuti a secondi |
| TI-20 | La chiave **non torna mai in chiaro** alla pagina ne' finisce nei registri | Una chiave in un modulo precompilato finisce in una cronologia, in una stampa, in una schermata condivisa; un segreto in un registro di audit e' un segreto compromesso. Si mostrano le ultime quattro cifre |
| TI-21 | La correlazione ha un **report PDF proprio** (R8), oltre alla sezione nel report di sicurezza | Il SOC risponde a "che cosa e' cambiato"; le vulnerabilita' rispondono a "che cosa e' dimostrato e da dove comincio": sono due documenti e due destinatari |
| TI-18 | I riscontri sono una **sorgente di evento** per il motore delle regole | La threat intelligence non serve se nessuno la guarda: un riscontro confermato, o una CVE sfruttata attivamente, deve poter far scattare una notifica come qualunque altro evento |

---

## 4. Requisiti

| ID | Requisito |
|---|---|
| SR-136 | Il sistema deve conservare un catalogo locale di vulnerabilita' (CVE) con punteggio, gravita', descrizione, classi di debolezza e applicabilita' per prodotto e versione |
| SR-137 | Il catalogo deve poter essere aggiornato da NVD, CISA KEV, MITRE CWE e MITRE ATT&CK, e in alternativa importato da file |
| SR-138 | L'aggiornamento predefinito deve riguardare i soli prodotti presenti nell'inventario |
| SR-139 | La correlazione deve funzionare senza alcuna connessione di rete |
| SR-140 | Ogni riscontro deve dichiarare la classe, la motivazione e la confidenza |
| SR-141 | Una vulnerabilita' deve essere dichiarata *confermata* solo se prodotto e versione soddisfano l'applicabilita' dichiarata dalla sorgente |
| SR-142 | Le esposizioni di servizio devono essere prodotte anche in assenza di catalogo, con la tecnica ATT&CK corrispondente |
| SR-143 | L'operatore deve poter accettare un rischio o dichiarare un falso positivo, con motivazione obbligatoria e tracciamento |
| SR-144 | Un riscontro non piu' osservato deve essere chiuso conservandone la storia |
| SR-145 | La console deve mostrare, per ciascun nodo, i riscontri che lo riguardano |
| SR-146 | Il registro degli aggiornamenti deve dichiarare sorgente, modo, esito, numero di voci e istante |
| SR-147 | Un aggiornamento interrotto dal riavvio del processo non deve impedire gli aggiornamenti successivi |
| SR-148 | Il sistema deve permettere di registrare una chiave API della NVD, conservata come credenziale e mai mostrata per intero ne' scritta nei registri |
| SR-149 | I riscontri devono poter essere prodotti come report PDF, con le tre classi distinte e la qualita' del dato dichiarata |
| SR-150 | Le viste del catalogo non devono richiedere confronti testuali su tutte le vulnerabilita': i legami usati per contare vanno conservati in forma interrogabile e ricostruibili senza accesso alla rete |
| SR-210/211 | Oltre alla correlazione per versione, i riscontri possono nascere dalla **verifica attiva con nmap** (fase `vuln`): entrano con origine `nmap`, confidenza alta, e con un ciclo di vita indipendente dalla riconciliazione della correlazione (vedi `06_INVENTARIO_E_MONITOR.md`) |

---

## 5. Sorgenti

| Sorgente | Indirizzo | Che cosa porta | Dimensione |
|---|---|---|---|
| **NVD** API 2.0 | `services.nvd.nist.gov/rest/json/cves/2.0` | CVE con CVSS, CWE, applicabilita' CPE, riferimenti | dipende dall'interrogazione |
| **CISA KEV** | `cisa.gov/.../known_exploited_vulnerabilities.json` | vulnerabilita' sfruttate attivamente | 1.685 voci |
| **MITRE CWE** (vista 1003) | `cwe.mitre.org/data/csv/1003.csv.zip` | 130 classi di debolezza: quelle che la NVD usa | 200 kB |
| **MITRE ATT&CK** | `attack-stix-data`, matrice enterprise | 709 tecniche con tattiche e descrizione | ~35 MB |

**Verifica attiva con nmap.** Accanto a queste sorgenti di *catalogo*, la sonda
porta i difetti che ha **verificato** sulla rete con gli script di rilevazione di nmap
(fase `vuln`). Non e' un catalogo da aggiornare: e' un accertamento sul campo, che
diventa un riscontro con origine `nmap`. Funziona senza rete come il resto della
correlazione.

**Modi di aggiornamento.** `targeted` (predefinito): interroga la NVD sui prodotti
dell'inventario. `window`: CVE modificate negli ultimi N giorni. `kev`, `cwe`, `attack`:
cataloghi interi. `file`: importazione da file, per le reti senza uscita.

**Limiti di interrogazione.** La NVD accetta 5 richieste ogni 30 secondi senza chiave
API (50 con chiave): il modo `targeted` attende 6,5 secondi fra le richieste, quindi con
9 prodotti dura circa un minuto. Il tempo e' dichiarato nella pagina prima di premere.

Nessuna dipendenza aggiunta: `urllib`, `json`, `csv`, `zipfile`, `gzip` sono nella
libreria standard.

---

## 6. Come si correla

**Flusso (ISO/IEC/IEEE 19510, in forma testuale).** Per ogni porta aperta e per ogni
sistema operativo riconosciuto: si leggono i CPE dichiarati dalla sonda (forma 2.2) o si
deduce un CPE dal nome del prodotto (euristica dichiarata) &rarr; si attribuisce la
versione del servizio al solo CPE applicativo, e solo se ce n'e' uno (TI-08) &rarr; si
cercano nel catalogo le applicabilita' per quel prodotto &rarr; se la versione e' nota e
confrontabile si valuta CVE per CVE e si producono riscontri **confermati**; se la
versione manca si produce **un solo** riscontro aggregato **da verificare** &rarr; in
parallelo, la porta viene confrontata con le regole di esposizione e produce un riscontro
**esposizione** con la tecnica ATT&CK. Alla fine, i riscontri non piu' osservati passano a
"non piu' presente" con la data.

**Confronto delle versioni.** Numeri come numeri, testo come testo: `1.9 < 1.10`,
`2.4.7 < 2.4.62`, `1.0 < 1.0p1`. Gli estremi dichiarati dalla NVD sono rispettati come
inclusivi o esclusivi. Una versione con caratteri jolly o intervalli e' dichiarata
incerta e non produce conferme.

**Esposizioni riconosciute.** RDP (T1021.001), SMB (T1021.002), SSH (T1021.004), VNC
(T1021.005), telnet e FTP in chiaro (T1040), SNMP (T1046), banche dati e console di
gestione (T1190), telefonia (T1046, gravita' bassa, con l'avvertenza dell'apparato che
risponde per altri).

---

### 6.1 Lo stato *atteso*: il contesto entra nella correlazione

Le esposizioni -- e soltanto quelle -- passano dal giudizio della **zona** della
subnet in cui si trova il dispositivo prima di diventare riscontri aperti
(`12_ZONE_DI_RETE.md`).

| Giudizio della zona | Stato assegnato | Gravita' |
|---|---|---|
| attesa | *atteso* | invariata, fuori dal conteggio degli aperti |
| normale | *aperto* | quella della regola |
| violazione | *aperto* | un livello sopra quella della regola |

Tre vincoli che tengono onesta la cosa:

- **Le vulnerabilita' confermate e potenziali non sono toccate** (ZR-08). Una CVE su
  un prodotto e' un fatto del prodotto: stare in un datacenter non rende meno
  vulnerabile un software non aggiornato.
- **Nulla viene cancellato.** Un riscontro atteso resta in archivio con la propria
  motivazione in chiaro, e se la zona cambia torna aperto alla passata successiva.
- **Una decisione presa da una persona vince sulla zona** (ZR-07): accettato e falso
  positivo restano dove sono.

La pagina di Threat Intelligence conta gli attesi **a parte**, mai sommati agli
aperti, con la stessa disciplina con cui non somma le tre classi (TI-03).


## 7. Esito sulla rete reale

Prima passata sull'inventario del progetto (545 dispositivi, 3.456 porte aperte),
catalogo con 2.549 CVE e 34.757 righe di applicabilita':

| Classe | Riscontri | Lettura |
|---|---|---|
| Confermati | **0** | Nessun servizio con versione rilevata rientra in un'applicabilita' dichiarata. E' la risposta vera, non un'assenza di funzionamento |
| Da verificare | 278 | Uno per (nodo, porta, prodotto): openldap, oracle, go, windows, net-snmp. Dicono dove serve rilevare la versione |
| Esposizioni | 2.080 | 960 telefonia, 300 SSH, 271 console di gestione, 195 SMB, 82 banche dati, 72 SNMP, 52 RDP, 51 VNC, 15 FTP, 2 telnet |

Le due correzioni fatte durante la messa a punto (TI-07 e TI-08) hanno portato i
riscontri da 4.084 illeggibili -- di cui 24 falsi positivi presentati come conferme -- a
2.358 utilizzabili, con zero conferme false.

**Che cosa serve per avere conferme.** Piu' versioni nell'inventario: profilo di sforzo
piu' alto sulle sonde, che aumenta l'interrogazione dei servizi. La pagina lo dichiara.

---

## 8. Riservatezza e conformita'

| Aspetto | Trattamento |
|---|---|
| Traffico verso l'esterno | Solo durante l'aggiornamento del catalogo, verso NVD, CISA e MITRE; nessun dato del cliente viene trasmesso -- si chiedono CVE per nome di prodotto, non per indirizzo |
| Chiave API della NVD | Conservata nelle impostazioni come le altre credenziali |
| Riscontri | Contengono indirizzi e nomi host, che sono dati personali: restano nel perimetro del tenant e seguono i suoi permessi |
| NIS2 art. 21(2)(e) | Gestione delle vulnerabilita': il catalogo, la correlazione e il registro delle decisioni sono la documentazione richiesta |
| CRA allegato I | Superficie di attacco documentata e sua evoluzione |
| GDPR art. 32 | Misure tecniche adeguate: la sorveglianza dell'esposizione e' una di queste |
| Tracciamento | Aggiornamenti del catalogo, correlazioni e decisioni sui riscontri sono nel registro delle azioni |

---

## 9. Limiti dichiarati

| Limite | Perche' |
|---|---|
| Con pochi servizi versionati, le conferme sono poche o nessuna | E' una proprieta' del dato, non del correlatore. Dichiararlo e' l'unico comportamento corretto; il rimedio e' alzare il profilo di sforzo delle sonde |
| L'associazione prodotto&rarr;CPE per nome e' euristica | La tabella copre i prodotti che compaiono davvero in un inventario di rete; ogni riscontro che ne deriva ha confidenza ridotta e lo dichiara |
| Nessuna verifica attiva della vulnerabilita' | Il prodotto osserva e non sollecita: una verifica attiva e' un'altra autorizzazione e un altro rischio |
| Al massimo 50 CVE per prodotto e 5.000 riscontri per passata | Guardie contro un elenco che nessuno leggerebbe e contro una passata che monopolizza il processo |
| Il catalogo ATT&CK pesa circa 35 MB | E' il pacchetto ufficiale; senza di esso le esposizioni restano valide e mostrano l'identificativo della tecnica senza il nome |
| Nessuna correlazione con exploit pubblici (Exploit-DB, Metasploit) | Richiederebbe un'altra sorgente e una qualita' del dato molto variabile; il KEV copre il caso che conta, cioe' lo sfruttamento reale |
