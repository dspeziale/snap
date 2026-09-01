# snap - Regole di notifica, canali di recapito, manutenzione dell'archivio

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT

Documento di progetto redatto secondo ISO/IEC/IEEE 29148:2018 (requisiti),
ISO/IEC/IEEE 15288:2015 (processi di ciclo di vita) e ISO/IEC/IEEE 19510:2013 per la
rappresentazione dei flussi. Vincoli di riservatezza e sicurezza: Regolamento (UE)
2016/679 (GDPR), Regolamento (UE) 2024/2847 (CRA), Direttiva (UE) 2022/2555 (NIS2),
ETSI EN 303 645, EN 50649:2024.

> **Stato: realizzato.** `server/snapserver/events.py`, `rules.py`, `channels.py`,
> `maintenance.py`, `blueprints/rules_views.py`, sezioni di `blueprints/admin.py`; prove
> in `tests/test_regole.py` e `tests/test_manutenzione.py`.

---

## 1. Portata

Tre capacita' che il prodotto non aveva e che rispondono a tre domande distinte:

1. **Regole di notifica** (capitoli 2-5): il sistema registra molto piu' di quanto
   comunichi. Fino a ieri notificava soltanto i passaggi del workflow degli incidenti;
   un nodo nuovo, una porta di amministrazione che si apre, una sonda che tace, un
   accesso fallito restavano fatti scritti in una tabella che nessuno guarda.
2. **Canali di recapito** (capitolo 6): la posta elettronica viene letta quando qualcuno
   apre la casella. Un incidente alle tre di notte ha bisogno di un canale che suoni.
3. **Manutenzione dell'archivio** (capitoli 7-9): quanto occupa cio' che conservo, per
   quanto devo conservarlo, come lo riporto in vita se lo perdo. Tre facce della stessa
   domanda, che tenute separate producono il caso classico -- una politica di
   conservazione dichiarata che nessuno applica, e una copia che nessuno ha mai provato
   a ripristinare.

---

## 2. Regole: decisioni assunte

| ID | Decisione | Perche' |
|---|---|---|
| RG-01 | Le regole stanno nel **database**, non nel codice | Cio' che merita una notifica cambia da cliente a cliente e nel tempo: una porta 3389 che si apre e' un evento in una rete e la normalita' in un'altra. Scriverlo nel codice significherebbe una versione del prodotto per cliente |
| RG-02 | Il valutatore **legge le tabelle** con un cursore, non intercetta le scritture | Gli eventi nascono in posti diversi -- il conferimento di un lotto, un'azione dell'operatore, un thread di servizio -- e alcuni in un processo senza contesto applicativo. La lettura rende il valutatore indipendente da chi produce l'evento e sopravvive a un riavvio: un aggancio alle scritture perderebbe tutto cio' che accade mentre e' spento |
| RG-03 | Il cursore e' **per sorgente**, non per regola, e non torna indietro | Una regola nuova non deve far rileggere il passato: la sua creazione produrrebbe una raffica di messaggi su fatti vecchi di settimane. Per guardare il passato c'e' la prova sulla storia, che non spedisce nulla |
| RG-04 | Gli eventi si presentano in una **forma normalizzata** comune (tipo, gravita', soggetto, dettaglio, attributi) | Sei tabelle con nomi propri diventerebbero sei linguaggi di condizioni. Una forma sola significa che chi ha imparato a scrivere una regola sa scriverle tutte |
| RG-05 | Le condizioni usano lo **stesso vocabolario delle verifiche sui controlli** (`eq, ne, contains, gt, lt, exists, absent`) | Un solo modo di nominare le cose in tutto il prodotto |
| RG-06 | Le condizioni di una regola sono in **congiunzione**; l'alternativa si esprime con due regole | Un albero di operatori in una pagina web e' illeggibile e si sbaglia; due regole con due nomi si leggono e si sospendono separatamente |
| RG-07 | Un tipo di evento che finisce con il **punto** e' un prefisso (`port.` prende aperture e chiusure) | E' la forma piu' breve di dire "tutte le variazioni delle porte" senza inventare una sintassi di caratteri jolly |
| RG-08 | Ogni regola ha un **limite di messaggi per finestra**; gli eventi in piu' sono registrati come **soppressi** e contati nel primo messaggio successivo | La prima passata di scoperta ha prodotto 1851 aperture di porta: una regola senza limite avrebbe spedito 1851 messaggi e il canale sarebbe stato silenziato dal destinatario entro cinque minuti. Sopprimere non e' perdere: il conteggio arriva |
| RG-09 | La **prova sulla storia** e' parte del percorso di creazione | Attivare una regola senza sapere quante volte avrebbe scattato ieri significa scoprirlo dal numero di messaggi che arrivano |
| RG-10 | Una regola con condizioni **illeggibili non scatta** | Meglio silenziosa che indiscriminata: trattarla come "senza condizioni" la farebbe notificare tutto |
| RG-11 | Il nome della regola e' obbligatorio e compare in ogni messaggio | Senza il nome, chi riceve il messaggio non sa dove andare per non riceverlo piu' |
| RG-12 | Le **regole pronte** sono offerte nella pagina ma non create da se' | Una notifica che nessuno ha chiesto e' rumore. La scelta di che cosa sapere e' dell'operatore; il prodotto abbassa il costo di partire, non decide |
| RG-13 | Una regola puo' essere **solo per il resoconto**: registra senza spedire | Non tutto merita un messaggio immediato. Cio' che va saputo ma non subito appartiene al resoconto delle 07:00 |
| RG-14 | Le regole sono **per tenant** e valutate nel perimetro del tenant dell'evento | Vale l'isolamento del prodotto: un evento di un tenant non attiva la regola di un altro |

---

## 2-bis. La forma dei messaggi di posta

Le email di snap arrivano a persone che non hanno la console davanti: un turno di notte,
un responsabile sul telefono, un amministratore che riceve le proprie credenziali. Hanno
percio' **una forma sola** (`mail_layout`): fascia colorata per genere -- gli stessi
colori dei report --, titolo, poche righe, una tabella di fatti, un pulsante che porta al
posto giusto della console, e un pie' di pagina che dice **perche'** quel messaggio e'
arrivato. Un messaggio che sembra diverso dal precedente costringe a rileggerlo tutto per
capire che cosa e' cambiato.

I vincoli della posta decidono la tecnica, e sono verificati da prove automatiche:

| vincolo | perche' |
|---|---|
| **stili in linea** | i client ignorano i fogli di stile e molti tolgono il tag `<style>`: cio' che deve funzionare sta negli attributi. Il `<style>` resta solo per il tema scuro e la larghezza ridotta, che sono migliorie |
| **impaginazione a tabelle**, con `role="presentation"` | Outlook usa il motore di Word e non impagina con i box moderni; ma una tabella di impaginazione non e' un dato e non va annunciata dai lettori di schermo |
| **nessuna risorsa esterna** | le immagini vengono bloccate per difetto e un messaggio che dipende da loro arriva rotto. Nessun pixel di tracciamento: in un prodotto di sicurezza sarebbe una contraddizione |
| **larghezza 640 px** | sta in una finestra di anteprima senza barra orizzontale e resta leggibile su un telefono |
| **testo semplice sempre** | l'HTML e' l'alternativa, non il contenuto: il testo e' cio' che si legge su qualunque client e nelle notifiche di sistema, e viene per primo nel messaggio |
| **preintestazione** | e' la riga che il client mostra in anteprima accanto all'oggetto: se non la si scrive, mostra il primo testo che trova. **Non contiene mai la password**, perche' l'anteprima finisce su uno schermo bloccato |
| **dati sempre passati per l'escape** | il dettaglio di una verifica arriva dalla rete: se contenesse marcatura la romperebbe, o peggio |

I generi (fasce): incidente aperto e operatore attivato in rosso, rientro in ambra,
risolto in verde, credenziali in blu, comunicazione ACN in blu istituzionale, regola in
viola, resoconto in petrolio. Su **Telegram** va il testo: l'HTML di un messaggio di
posta, la', arriverebbe come marcatura.

## 3. Regole: requisiti

| ID | Requisito |
|---|---|
| SR-116 | L'operatore deve poter definire regole di notifica su qualunque sorgente di evento registrata dal sistema |
| SR-117 | Le sorgenti disponibili devono comprendere: variazioni dell'inventario, esiti dei controlli, passaggi degli incidenti, passate di scansione, conferimenti delle sonde, registro delle azioni |
| SR-118 | Una regola deve consentire di filtrare per tipo di evento e per condizioni sugli attributi dell'evento |
| SR-119 | Una regola deve dichiarare i canali di recapito e i destinatari; in mancanza di destinatario si usa l'email di riferimento del tenant |
| SR-120 | Il sistema deve limitare i messaggi per finestra temporale e registrare gli eventi soppressi, contandoli nel messaggio successivo |
| SR-121 | Il sistema deve consentire di provare una regola sugli eventi passati senza spedire nulla |
| SR-122 | Una regola deve poter essere sospesa senza perdere lo storico delle corrispondenze |
| SR-123 | La valutazione delle regole non deve rileggere eventi gia' valutati a fronte di riavvii del servizio |
| SR-124 | Ogni corrispondenza deve essere conservata con l'esito del recapito |

---

## 4. Regole: sorgenti di evento

| Sorgente | Che cosa porta | Attributi per le condizioni |
|---|---|---|
| `node_changes` | Nodi comparsi o scomparsi, porte aperte o chiuse, cambi di tipo, sistema operativo, nome host, indirizzo fisico | `node_ip, node_hostname, node_type, node_os, subnet, protocol, port, before, after, service` |
| `check_results` | Ogni esito di un controllo periodico: utile per reagire al singolo fallimento senza attendere la soglia dell'incidente | `check_name, check_kind, address, target, status, latency_ms, severity_check` |
| `check_incident_events` | Apertura, attivazione dell'operatore, presa in carico, rientro, risoluzione | `incident_id, action, actor, check_name, address, severity_incident` |
| `scan_runs` | Esito di ogni passata: completata, fallita, scaduta | `stage, status, probe, hosts_total, hosts_up, records, duration_ms` |
| `ingest_batches` | Lotti ricevuti dalle sonde, compresi i rifiutati | `probe, status, records, bytes` |
| `audit_events` | Accessi riusciti e falliti, modifiche alla configurazione, comandi alle sonde, azzeramenti dell'archivio, cancellazioni | `actor, event_type, entity, entity_id, source_ip, user` |

Attributi comuni a tutte le sorgenti: `type`, `severity`, `subject`, `detail`.

**Flusso (ISO/IEC/IEEE 19510, in forma testuale).** Thread del valutatore (ogni 30 s) →
per ogni sorgente: leggi fino a 500 eventi oltre il cursore → per ciascuno: individua il
tenant, carica le regole attive del tenant (una volta per giro) → per ogni regola che
corrisponde: verifica il limite della finestra → accoda le notifiche sui canali della
regola, oppure registra la corrispondenza come soppressa → registra la corrispondenza →
avanza il cursore. Un errore su un evento non ferma il thread: viene registrato.

---

## 5. Regole pronte offerte nella pagina

Nodo nuovo in rete; amministrazione remota esposta (3389); SMB esposto (445); telnet in
chiaro (23); banca dati esposta (1521); nodo scomparso; scansione non completata;
accesso alla console fallito; archivio di una sonda azzerato; controllo in errore;
latenza oltre il secondo; conferimento rifiutato.

Ognuna e' una definizione completa che si crea con un clic -- o si prova prima. Non
sono attive per difetto (RG-12).

---

## 6. Canali di recapito

| ID | Decisione | Perche' |
|---|---|---|
| CN-01 | Il canale e' una **colonna della coda**, non una seconda coda | Due code significherebbero due posti in cui guardare quando un messaggio non arriva, e la domanda "e' partito?" non deve avere due risposte possibili |
| CN-02 | Telegram si raggiunge con `urllib.request`: **nessuna dipendenza aggiunta** | L'interfaccia e' HTTP e la libreria standard basta; il corpo multipart per l'invio di un documento e' poche righe |
| CN-03 | Il **token del bot** e' conservato come la password della posta e non viene mai mostrato per intero | E' una credenziale: chi apre la pagina deve poter riconoscere quale bot e' configurato, non leggerne il segreto |
| CN-04 | Un allegato su Telegram viaggia con `sendDocument` e il testo diventa **didascalia** | Due messaggi separati arriverebbero slegati; la didascalia ha un limite piu' corto e il taglio viene dichiarato nel testo |
| CN-05 | Un canale non configurato produce un **errore di configurazione**, distinto dal fallimento di recapito | I ritentativi non risolvono una configurazione mancante: confonderli farebbe cercare un guasto dove manca un dato |
| CN-06 | La prova del canale interroga l'**identita' del bot** e poi manda un messaggio | Un token sbagliato e una chat sbagliata sono errori diversi: dirlo separatamente fa risparmiare mezz'ora |

Requisiti: **SR-125** il sistema deve recapitare le notifiche per posta elettronica e
tramite bot Telegram; **SR-126** la configurazione di un canale deve poter essere provata
dalla console con esito esplicito; **SR-127** il token del bot non deve essere mostrato
ne' registrato in chiaro nei messaggi di audit.

Limiti dichiarati dell'interfaccia Telegram: 4096 caratteri per messaggio, 50 MB per
documento. Il testo oltre il limite viene troncato **dichiarandolo**, non tagliato in
silenzio.

---

## 7. Manutenzione: dimensione dell'archivio

La pagina delle impostazioni mostra: dimensione del file, spazio **riutilizzabile**
interno, registro di scrittura anticipata (WAL), righe totali, spazio libero sul volume,
e la ripartizione per tabella (righe e, dove SQLite espone `dbstat`, byte).

Lo spazio riutilizzabile ha una voce propria per una ragione precisa: dopo
un'eliminazione **il file non si riduce**, e senza quel numero sembra che la
conservazione non abbia funzionato. Restituire lo spazio al disco e' un'operazione
distinta (compattazione), perche' riscrive l'intero file e su un archivio grande dura.

---

## 8. Manutenzione: conservazione per genere di dato

| Genere di dato | Predefinito | Perche' questa durata |
|---|---|---|
| Campioni di raggiungibilita' | 90 giorni | Migliaia al giorno: sono la materia delle tendenze brevi, non della storia |
| Esiti dei controlli | 365 | Un anno permette il confronto con lo stesso periodo dell'anno precedente |
| Misure ricavate dagli esiti | 365 | Seguono gli esiti da cui sono ricavate |
| Variazioni dell'inventario | 365 | Sono la storia della rete: un anno copre il ciclo degli interventi |
| Passate di scansione | 180 | Spiegano la qualita' della raccolta recente |
| Conferimenti delle sonde | 90 | Diagnostica del canale: oltre tre mesi occupano e non servono |
| Registro delle azioni | 730 | E' la prova che si mostra a un auditor: due anni per NIS2 e GDPR |
| Coda delle notifiche | 365 | Prova di cio' che e' stato comunicato e a chi |
| Corrispondenze delle regole | 365 | Storia delle notifiche automatiche, utile a capire una regola troppo larga |
| Contrassegni antiripetizione | 7 | Oltre la finestra sono inerti |
| Report prodotti | **non scadono** | Un report sopravvive ai dati che riassume |

Decisioni: **MN-01** la durata e' per genere di dato, non unica (una durata sola e' o
troppo corta per il registro delle azioni o troppo lunga per i campioni); **MN-02** `0`
significa "non scade", ed e' esplicito; **MN-03** ogni durata porta la propria
motivazione nella pagina, perche' una durata senza motivo non e' una politica ma un
numero; **MN-04** l'applicazione ha una **simulazione** che conta senza eliminare, perche'
"quanto libero?" e' la domanda che precede un'operazione che non si annulla; **MN-05**
la conservazione e' riservata all'**amministratore di sistema**: riguarda tutti i tenant
ed e' una scelta con conseguenze legali (GDPR art. 5(1)(e)).

Requisiti: **SR-128** la console deve mostrare la dimensione dell'archivio e la sua
ripartizione; **SR-129** la conservazione deve essere configurabile per genere di dato
con motivazione visibile; **SR-130** l'applicazione della conservazione deve poter essere
simulata; **SR-131** l'eliminazione dei dati e la compattazione devono essere operazioni
distinte e dichiarate.

---

## 9. Manutenzione: copia e ripristino

| ID | Decisione | Perche' |
|---|---|---|
| MN-06 | La copia usa l'**API di backup di SQLite**, non la copia del file | Un file copiato mentre il server scrive puo' essere incoerente, e un archivio incoerente e' peggio di nessun archivio |
| MN-07 | Ogni copia viene **verificata appena prodotta** (apertura, `integrity_check`, tabelle del prodotto); se non passa, viene eliminata | Una copia che non si sa se e' valida non e' una copia. Un file parziale sarebbe indistinguibile da una buona |
| MN-08 | Il ripristino **non sostituisce il file**: riversa la copia dentro l'archivio in esercizio, in una transazione | Le connessioni aperte -- richieste in corso, thread di servizio -- continuano a vedere un archivio valido invece di restare appese a un file cancellato |
| MN-09 | Prima di ogni ripristino viene creata una **copia dello stato corrente** | Un ripristino sbagliato non deve essere l'ultima operazione possibile |
| MN-10 | Il ripristino richiede una **conferma digitata** (`RIPRISTINA`) | E' l'operazione piu' distruttiva del prodotto: un clic per errore sostituirebbe i dati di tutti i tenant |
| MN-11 | Il nome di una copia non e' mai un percorso: si accettano solo i nomi della cartella delle copie | Un percorso che arriva da una richiesta e' una lettura arbitraria del file system che aspetta di succedere |
| MN-12 | I nomi delle copie portano un **contatore** quando collidono nello stesso secondo | Il ripristino crea una copia subito prima di leggere la sorgente: con lo stesso nome la sovrascriverebbe, e si tornerebbe allo stato corrente credendo di tornare indietro. Emerso dalle prove, vedi 08_REPORT.md §11.1 |
| MN-13 | Copia, ripristino e conservazione sono riservati all'**amministratore di sistema** | Una copia contiene i dati di tutti i tenant, gli indirizzi di rete e le credenziali di servizio: va trattata come l'archivio stesso |

**Proprieta' da conoscere prima di premere.** Un ripristino riporta anche il **registro
delle azioni**: gli eventi successivi alla copia scompaiono. Non e' un difetto ed e'
irriducibile; l'unica traccia che resta e' l'evento del ripristino, scritto subito dopo.
Il modulo e il messaggio di esito lo dichiarano.

Requisiti: **SR-132** il sistema deve produrre copie coerenti dell'intero archivio;
**SR-133** ogni copia deve essere verificata e la verifica deve poter essere ripetuta
senza ripristinare; **SR-134** il ripristino deve salvare lo stato precedente, richiedere
conferma digitata ed essere tracciato con gravita' critica; **SR-135** le operazioni di
copia e ripristino devono essere riservate all'amministratore di sistema.

---

## 10. Riservatezza e conformita'

| Aspetto | Trattamento |
|---|---|
| Copia dell'archivio | Contiene tutti i tenant e le credenziali di servizio. Scaricamento tracciato con gravita' *warning*; l'operazione e' riservata; la cartella delle copie va protetta come l'archivio |
| Notifiche su canali esterni | Il messaggio di una regola contiene indirizzi IP e nomi host, che sono dati personali (GDPR). Il canale va scelto di conseguenza: un gruppo Telegram e' un servizio di terzi |
| Token del bot | Credenziale conservata nelle impostazioni; mostrata solo nella parte che identifica il bot |
| Conservazione | GDPR art. 5(1)(e): durata dichiarata per genere di dato, con motivazione. NIS2: il registro delle azioni resta due anni |
| Tracciabilita' | Creazione, modifica, sospensione ed eliminazione di una regola; salvataggio delle durate; copia, scaricamento, eliminazione e ripristino; prova dei canali |
| Password SMTP in chiaro | Rilievo noto (vedi 08_REPORT.md, R5): resta da cifrare a riposo o delegare a un archivio di segreti |

---

## 11. Limiti dichiarati

| Limite | Perche' |
|---|---|
| Le condizioni di una regola sono solo in congiunzione | L'alternativa si esprime con due regole, che si leggono e si governano meglio di un albero di operatori (RG-06) |
| Nessuna soglia "N volte in M minuti" come condizione | Richiederebbe uno stato per regola e per soggetto: e' la funzione delle soglie dei controlli, che esistono, e duplicarla qui creerebbe due posti dove cercare |
| Il valutatore legge al massimo 500 eventi per sorgente a ogni giro | Una passata di scoperta ne produce migliaia: il lotto limitato evita che un giro monopolizzi il processo, e il resto viene letto al giro successivo |
| Solo posta e Telegram | Altri canali (messaggistica aziendale, webhook, ticketing) richiederebbero una dipendenza o un contratto di interfaccia per prodotto, da concordare |
| La conservazione e' globale, non per tenant | Il modello ha una durata per tenant (`tenants.retention_days`) usata dalla vecchia manutenzione; le durate per genere di dato valgono per l'archivio. Una matrice tenant x genere richiederebbe una tabella e una pagina proprie |
| Il ripristino non e' parziale | Non si ripristina un solo tenant: SQLite non lo consente senza una procedura di travaso che sarebbe piu' rischiosa dell'operazione intera |
| Il caricamento di una copia e' limitato dalla dimensione massima delle richieste | Oltre, si copia il file nella cartella delle copie e si ripristina dall'elenco: e' dichiarato nella pagina |
