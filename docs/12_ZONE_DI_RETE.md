# snap - Zone di rete: il contesto che decide se un'esposizione e' un problema

**Documento di specifica.** Conforme per struttura a ISO/IEC/IEEE 29148:2018
(requisiti e specifiche) e inserito nel ciclo di vita di ISO/IEC/IEEE 15288:2023.
Riferimenti normativi applicabili: Direttiva (UE) 2022/2555 (NIS2) art. 21, comma 2,
lettere a) ed e) - analisi dei rischi e sicurezza della rete, di cui la segmentazione
e' la misura architetturale principale; Reg. (UE) 2024/2847 (CRA) allegato I per la
riduzione della superficie di attacco; Reg. (UE) 2016/679 (GDPR) art. 32 per le
misure tecniche adeguate al rischio; OWASP ASVS V1.14 (segregazione dei livelli).

Documenti collegati: `06_INVENTARIO_E_MONITOR.md` (perimetro e dispositivi),
`10_THREAT_INTELLIGENCE.md` (riscontri ed esposizioni), `11_SALA_OPERATIVA.md`
(quadro SOC), `08_REPORT.md` (report della segmentazione).

---

## 1. Il problema

La stessa porta aperta significa cose opposte a seconda di dove si trova.

SSH su una postazione di lavoro e' una via d'ingresso che nessuno ha chiesto. SSH su
un server in un datacenter e' il modo in cui quel server si amministra, dietro un
perimetro che qualcuno ha progettato: firewall, segmentazione, accesso controllato.
Una banca dati raggiungibile dalla rete degli uffici e' un errore; la stessa banca
dati raggiungibile dalla rete applicativa e' l'architettura.

Un prodotto che le segnala allo stesso modo obbliga l'operatore a ignorare centinaia
di righe. E chi impara a ignorare un elenco, poi ignora anche la riga che contava:
questo e' il modo in cui un sistema di allerta smette di funzionare pur continuando a
funzionare.

Misura reale su una rete di collaudo di circa tremila dispositivi: **1.338
esposizioni su 1.448** erano coerenti con la zona in cui si trovavano. Senza il
contesto, le 110 che contavano erano il 7,6% di un elenco che nessuno avrebbe letto
fino in fondo.

---

## 2. Decisioni assunte

| ID | Decisione | Perche' |
|---|---|---|
| ZR-01 | Il contesto si dichiara sulla **subnet**, non sul singolo dispositivo | La subnet e' l'unita' su cui la segmentazione e' gia' progettata: chi ha disegnato la rete sa dire che cosa e' un datacenter e che cosa e' una rete di utenza. Chiedere la stessa cosa dispositivo per dispositivo su tremila indirizzi significa non ottenerla mai |
| ZR-02 | Una subnet **senza zona dichiarata vale come rete di utenza**, che e' il giudizio piu' severo | Il silenzio non deve valere come giustificazione. Se non dichiarare nulla ammorbidisse i riscontri, il modo piu' rapido per avere una rete pulita sarebbe non descriverla |
| ZR-03 | La zona esprime **tre giudizi** su ciascuna famiglia di esposizione: attesa, normale, violazione | Due soli valori costringerebbero a scegliere fra "e' un problema" e "non lo e'". La terza possibilita' -- *in questo contesto e' piu' grave che altrove* -- e' quella che serve per la DMZ e per la rete ospiti |
| ZR-04 | Un'esposizione attesa **non si cancella**: resta in archivio con lo stato *atteso* e con la ragione scritta in chiaro | Nascondere il dato invece di qualificarlo renderebbe il prodotto piu' pulito e meno vero. Chi legge deve poter chiedere "perche' questa non compare" e ricevere una risposta |
| ZR-05 | Se la zona cambia, i riscontri **tornano aperti da se'**, senza rigenerare nulla a mano | Una dichiarazione sbagliata deve costare poco a correggere. Il giudizio si riapplica alla passata di correlazione successiva, e cio' che non e' piu' atteso ricompare fra gli aperti |
| ZR-06 | Una violazione **alza la gravita' di un livello** e non la abbassa mai | Un servizio di amministrazione in una rete ospiti non e' lo stesso servizio in un datacenter: e' la prova che la segmentazione non tiene. La scala si ferma a *critica* |
| ZR-07 | Una **decisione presa da una persona** (accettato, falso positivo) e' piu' forte della zona | La zona e' una regola generale; una persona che ha guardato quel caso ha piu' informazioni della regola. Il contrario -- una regola che sovrascrive un giudizio umano -- farebbe perdere lavoro gia' fatto |
| ZR-08 | La zona **non tocca le vulnerabilita' confermate**, solo le esposizioni | Una CVE su un prodotto e' un fatto del prodotto, non della rete: essere in un datacenter non rende meno vulnerabile un software non aggiornato. La zona parla di *raggiungibilita'*, ed e' l'unico piano su cui ha titolo di parlare |
| ZR-09 | ~~Il catalogo delle zone e' chiuso e dichiarato nel codice~~ **Superata da ZR-13.** | La ragione originaria resta valida per le FAMIGLIE, non per le zone: una famiglia scritta a mano non corrisponderebbe a nessuna regola e sembrerebbe attiva. Le zone in se' sono un'altra cosa -- "rete di collaudo", "rete fornitori", "rete di cantiere" nessuno le puo' prevedere dal prodotto |
| ZR-13 | Il **catalogo delle zone e' un dato del tenant**: si creano, si modificano, si eliminano dalla pagina *Rete > Zone di rete*. Le sei zone del prodotto sono il SEME, copiato alla prima apertura | Reti diverse hanno contesti diversi, e un catalogo chiuso obbliga a piegare la propria rete alle nostre sei categorie. Resta prodotto cio' che il cliente non deve poter inventare: le famiglie di esposizione (allowlist dalle regole di correlazione), il significato dei tre giudizi e la regola dell'aggravamento |
| ZR-18 | La vista per zona parte dal **perimetro dichiarato**, non dai dispositivi trovati | Difetto segnalato: due subnet appena assegnate a una zona non comparivano in "Per zona di rete". La vista si ricavava dall'albero dei dispositivi, e una subnet senza dispositivi non esiste in quell'albero -- ma e' esattamente quella che si va a cercare subito dopo averla dichiarata. "Zero dispositivi" e' un'informazione: dice che quella rete e' dichiarata e non ancora osservata |
| ZR-17 | Le zone si leggono **sempre dal catalogo del tenant**, in ogni punto dell'applicazione | Difetto segnalato dall'operatore: nel Perimetro di Scansione comparivano solo le zone predefinite, quindi una zona appena creata non si poteva assegnare a nessuna subnet -- ed era come non esistere. Quattro punti (menu della subnet, filtro dei dispositivi, postura della sala operativa, report sulla segmentazione) leggevano ancora il seme del prodotto. Il seme e' il punto di partenza di un tenant nuovo, non la verita' corrente: dopo la semina l'unica fonte e' la tabella |
| ZR-16 | Creando una zona si possono **ereditare le famiglie** da una zona esistente; cio' che l'operatore scegle vince sull'ereditarieta' | Chi dichiara "rete di collaudo" ha in mente qualcosa di simile al datacenter, con una differenza o due. E soprattutto: una zona nuova con gli elenchi vuoti non giudica niente -- sembra dichiarata e non fa nulla, che e' il modo peggiore in cui una configurazione possa sbagliare |
| ZR-14 | Una **zona si elimina** anche se in uso: le sue subnet si riassegnano a una zona scelta oppure restano **senza zona** | Eliminando il contesto si perde la giustificazione, non la si eredita: senza zona vale il giudizio piu' severo. E' il verso giusto dell'errore |
| ZR-15 | Anche le zone **predefinite si possono modificare**, e si possono riportare all'origine | Su una rete reale "datacenter" puo' voler dire cose diverse: imporre la nostra idea avrebbe come solo effetto che l'operatore smette di usare la funzione. Restano marcate come predefinite, cosi' il ripristino sa quali riportare indietro senza toccare le zone create |
| ZR-10 | La motivazione e' scritta **per esteso nel riscontro**, non e' un codice | "Atteso in zona datacenter: e' il modo in cui i sistemi si amministrano, dietro un perimetro progettato" si legge in una riunione. `EXPECTED_DC` no |
| ZR-11 | La pagina del perimetro dichiara **quante subnet non hanno zona** | Una rete in cui nessuno ha dichiarato nulla non e' "tutta utenza": e' una rete non ancora descritta, ed e' un'informazione diversa che va detta |
| ZR-12 | La zona e' un **criterio di ricerca** nell'inventario e una **misura** nel quadro SOC | Se il contesto governa i giudizi, deve essere anche una chiave di lettura: "mostrami i dispositivi del datacenter", "quanta parte del perimetro e' descritta" |

---

## 3. Requisiti

| ID | Requisito |
|---|---|
| SR-151 | Ogni subnet deve poter dichiarare una zona scelta da un catalogo chiuso; l'assenza di dichiarazione deve valere come zona di utenza |
| SR-152 | Il sistema deve valutare ogni esposizione nel contesto della zona della subnet del dispositivo, assegnando uno dei tre giudizi: attesa, normale, violazione |
| SR-153 | Un'esposizione attesa deve essere conservata con stato *atteso* e con la motivazione in chiaro, e non deve essere conteggiata fra i riscontri aperti |
| SR-154 | Un'esposizione in violazione deve ricevere una gravita' superiore di un livello a quella della regola, senza superare la gravita' massima |
| SR-155 | Al cambio di zona di una subnet, la valutazione deve essere riapplicata automaticamente alla passata di correlazione successiva |
| SR-156 | Una decisione registrata da un utente (accettato, falso positivo) deve prevalere sul giudizio della zona |
| SR-157 | La zona non deve modificare le vulnerabilita' confermate o potenziali, ma solo le esposizioni |
| SR-158 | La console deve consentire di filtrare i dispositivi per zona e di misurare quante subnet dichiarano una zona |
| SR-159 | Il quadro SOC deve riportare la postura di segmentazione: esposizioni attese, violazioni e perimetro senza zona |
| SR-160 | Deve essere disponibile un report della segmentazione destinato a chi progetta la rete |
| SR-168 | Le zone devono poter essere create, modificate ed eliminate dall'interfaccia, con le famiglie di esposizione scelte da un elenco chiuso ricavato dalle regole di correlazione |
| SR-169 | L'eliminazione di una zona deve riassegnare le subnet che la usano a una zona indicata oppure lasciarle senza zona, senza cancellare dispositivi |
| SR-170 | Le zone del prodotto devono essere create automaticamente per ogni tenant e devono poter essere riportate all'origine senza toccare quelle create dall'operatore |
| SR-179 | Alla creazione di una zona deve essere possibile ereditare le famiglie attese e violate da una zona esistente |
| SR-191 | La vista per zona della mappa deve elencare tutte le subnet del perimetro dichiarato, comprese quelle senza dispositivi osservati |
| SR-184 | Ogni elenco di zone dell'applicazione -- assegnazione alla subnet, filtri, postura, report -- deve leggere il catalogo del tenant, non le zone predefinite del prodotto |

---

## 4. Catalogo delle zone

Sei zone, ciascuna con la propria idea di che cosa e' normale. Le famiglie citate
sono i titoli delle regole di esposizione di `10_THREAT_INTELLIGENCE.md`: cio' che
non e' nominato resta al giudizio della regola.

| Zona | Che cos'e' | Attese | Violazioni |
|---|---|---|---|
| **Rete di utenza** (predefinita) | Postazioni, stampanti, telefoni | nessuna | Banca dati raggiungibile |
| **Datacenter** | Server e servizi applicativi, dietro un perimetro progettato | SSH, RDP, banca dati, SMB, console di gestione | Telnet, FTP |
| **DMZ** | Sistemi raggiungibili da reti non fidate | nessuna | SSH, RDP, VNC, SMB, banca dati, console, SNMP |
| **Rete di gestione** | La rete fuori banda con cui si amministrano gli apparati | SSH, RDP, VNC, SNMP, console di gestione | Telnet |
| **Rete industriale (OT)** | Automazione e controllo di processo, apparati con cicli di vita di decenni | Telnet, FTP, SNMP | SMB, banca dati |
| **Rete ospiti** | Visitatori e dispositivi non gestiti | nessuna | tutte le famiglie note |

Due scelte meritano una spiegazione.

**Perche' in DMZ non c'e' nulla di atteso.** Un sistema in DMZ e' il primo che verra'
provato. Cio' che e' stato pubblicato di proposito - un sito, un'API - non e'
un'esposizione, e' il servizio; tutto il resto e' materiale che non dovrebbe essere
li'. La zona piu' esposta e' anche quella con l'elenco di violazioni piu' lungo, e
non e' un paradosso: e' il motivo per cui esiste.

**Perche' in rete industriale Telnet e' atteso.** Non perche' sia accettabile, ma
perche' su molti apparati di automazione l'alternativa non esiste e il ciclo di vita
si misura in decenni. Il rischio si governa segmentando, non chiedendo di chiudere
una porta che il processo produttivo usa. Il report della segmentazione lo scrive:
l'esposizione e' attesa *e* la rete va isolata.

---

## 5. Come si applica il giudizio

Alla creazione o all'aggiornamento di un'esposizione, la correlazione legge la zona
della subnet del dispositivo e chiede al catalogo che cosa ne pensa.

| Giudizio | Stato del riscontro | Gravita' | Conta fra gli aperti |
|---|---|---|---|
| attesa | *atteso* | invariata | no |
| normale | *aperto* | invariata | si' |
| violazione | *aperto* | +1 livello | si' |

Aggravamento: informativa -> bassa -> media -> alta -> critica -> critica.

La motivazione viene aggiunta alle prove del riscontro, in chiaro, insieme a cio' che
lo ha generato (porta, servizio, versione). Un riscontro atteso letto a distanza di
mesi si spiega da solo.

---

## 6. Ciclo di vita di un riscontro atteso

1. La correlazione crea l'esposizione e la trova attesa: stato *atteso*, motivazione
   scritta, non compare fra gli aperti.
2. La passata successiva la ritrova e conferma il giudizio, a meno che una persona
   non abbia deciso diversamente (ZR-07).
3. Se la zona della subnet cambia, la passata successiva riapplica il giudizio: cio'
   che non e' piu' atteso torna *aperto*, cio' che e' diventato violazione sale di
   gravita'.
4. Se il servizio smette di rispondere, il riscontro si chiude come tutti gli altri.

Nessuno dei quattro passaggi cancella nulla (ZR-04): la storia resta leggibile.

---

## 7. Dove si vede

| Luogo | Che cosa mostra |
|---|---|
| **Rete > Zone di rete** | Il catalogo: creazione, modifica, eliminazione, ordine, ripristino delle predefinite. Per ogni zona quante subnet e quanti dispositivi la riguardano -- una zona dichiarata e mai usata e' un lavoro a meta' |
| **Rete > Perimetro** | La zona di ciascuna subnet, modificabile; il conteggio di quelle non dichiarate; la spiegazione di ogni zona |
| **Rete > Mappa della rete** | Due letture della stessa rete: per sonda e perimetro (dove sta una cosa) e **per zona** (che cosa e' quel posto), con le subnet senza zona in evidenza. La vista per zona si costruisce dal **perimetro dichiarato**, quindi una subnet compare nella propria zona anche se non ha ancora nessun dispositivo |
| **Rete > Dispositivi** | Filtro per zona, accanto agli altri criteri di ricerca |
| **Threat Intelligence** | I riscontri attesi contati a parte, mai sommati agli aperti; la motivazione nel dettaglio del riscontro |
| **Quadro SOC** | Postura di segmentazione: attese, violazioni, perimetro senza zona |
| **Report della segmentazione** | Il documento per chi progetta la rete (`08_REPORT.md`) |

---

## 8. Riservatezza e conformita'

- La zona e' un'informazione di architettura, non un dato personale: non contiene
  nulla di riferibile a una persona (GDPR art. 4).
- La dichiarazione di zona e' un'operazione tracciata nel registro degli eventi: chi
  l'ha cambiata e quando. Serve a rispondere alla domanda "perche' questa esposizione
  non compariva" (NIS2, tracciabilita').
- La segmentazione e' una misura esplicita dell'art. 21 NIS2: il report della
  segmentazione e' pensato per essere allegato a una valutazione del rischio.
- Il valore ricevuto dall'interfaccia e' confrontato con l'elenco delle zone ammesse
  (allowlist, ZR-09): nessuna stringa dell'utente entra nella logica dei giudizi.

---

## 9. Limiti dichiarati

- La zona si applica alla **subnet intera**. Un server esposto dentro una rete di
  utenza eredita il giudizio piu' severo, che e' il verso giusto dell'errore; un
  dispositivo di utenza dentro una subnet di datacenter eredita invece un giudizio
  piu' morbido di quanto meriti. Si corregge dichiarando subnet piu' piccole, che e'
  anche il modo in cui una rete andrebbe descritta.
- Il catalogo delle famiglie di esposizione e' quello delle regole: una regola nuova
  non e' automaticamente attesa o violata in nessuna zona finche' non viene
  dichiarata. Il valore predefinito -- *normale* -- e' quello prudente.
- La zona non descrive **da dove** un servizio e' raggiungibile: snap misura cio' che
  la sonda vede dalla propria posizione. Una rete di gestione dichiarata tale ma
  raggiungibile dagli uffici risulterebbe in ordine. E' una verifica di
  raggiungibilita' fra zone, che richiede una sonda per zona, ed e' dichiarata come
  sviluppo futuro.

---

## 10. Tracciabilita'

| Esigenza | Decisione | Requisito | Realizzazione | Prova |
|---|---|---|---|---|
| Il contesto decide la gravita' | ZR-01, ZR-03 | SR-151, SR-152 | `zones.py`, `threat.py` | `tests/test_zone.py` |
| Chi tace non viene premiato | ZR-02 | SR-151 | `zones.ZONA_PREDEFINITA` | `test_una_zona_non_dichiarata_vale_come_la_piu_severa` |
| Non si cancella nulla | ZR-04, ZR-05 | SR-153, SR-155 | stato *atteso* in `threat.py` | `test_cambiare_zona_riapre_i_riscontri_che_non_sono_piu_attesi` |
| Una violazione pesa di piu' | ZR-06 | SR-154 | `zones.AGGRAVAMENTO` | `test_una_violazione_alza_la_gravita_e_non_la_abbassa_mai` |
| La persona conta piu' della regola | ZR-07 | SR-156 | `threat._upsert_finding` | `test_una_decisione_di_persona_resta_piu_forte_della_zona` |
| Il contesto e' anche una chiave di lettura | ZR-12 | SR-158, SR-159 | `inventory_queries.py`, `operations.zone_posture` | `test_i_nodi_si_filtrano_per_zona`, `test_il_quadro_soc_misura_la_segmentazione` |
| Un documento per chi progetta la rete | ZR-12 | SR-160 | `reports/dataset_wide.segmentation` | `test_il_report_della_segmentazione_si_genera` |
