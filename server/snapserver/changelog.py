# -----------------------------------------------------------------
# changelog.py — storico delle versioni del server, con abstract e cambiamenti
# Autore: Daniele Speziale
# Data creazione: 2026-09-03
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Che cosa e' cambiato, versione per versione.

Il badge della versione nella sidebar apre l'elenco di questi cambiamenti: chi
aggiorna la console deve poter vedere, con un clic, che cosa e' arrivato di nuovo.

Regola (memoria di progetto): quando si cambia `APP_VERSION` in `settings.py` si
aggiunge QUI, in cima, una voce con un breve abstract e l'elenco dei cambiamenti
principali rispetto alla versione precedente. La voce piu' recente sta per prima.
"""

from __future__ import annotations

# Ogni voce: version, date (YYYY-MM-DD), abstract (1-2 frasi), changes (elenco).
CHANGELOG = [
    {
        "version": "1.7.0",
        "date": "2026-09-12",
        "abstract": "Quattro relazioni nuove -- vetusta' del parco, presenze senza"
                    " fili, salute della flotta, esposizione SMB -- ciascuna con il"
                    " suo destinatario dichiarato. La pagina delle presenze dice chi"
                    " e' in rete adesso, e si aggiorna da sola. E la sonda comincia a"
                    " contare le proprie versioni per conto suo.",
        "changes": [
            "VETUSTA' DEL PARCO. Una relazione su quali interfacce non le aggiorna"
            " piu' nessuno e da quanti anni, con la PROVA in chiaro accanto a ogni"
            " riga -- il frammento di pagina da cui l'anno viene. Non e' l'elenco"
            " delle vulnerabilita': e' la causa a monte di meta' di esse, e non"
            " compare in nessun catalogo di CVE. Sul parco reale: 55 interfacce ferme"
            " da oltre dieci anni, la piu' vecchia da ventuno.",
            "PRESENZE SULLE RETI SENZA FILI. Chi c'e' stato, con quale certezza lo si"
            " sa e per quanto si conservano quei dati: una relazione che si consegna"
            " a chi risponde della sicurezza fisica e a chi risponde del trattamento"
            " dei dati, e che dichiara la conservazione a termine invece di lasciarla"
            " dedurre.",
            "SALUTE DELLA FLOTTA E COPERTURA. L'unica relazione che non parla della"
            " rete ma dello STRUMENTO, e che va letta prima delle altre: quali sonde"
            " funzionano e -- soprattutto -- quali reti dichiarate nel perimetro non"
            " ha mai guardato nessuno. Una subnet mai scoperta non produce righe in"
            " nessun altro documento, e una tabella vuota si legge come \"niente da"
            " segnalare\" invece che come \"non guardato\".",
            "ESPOSIZIONE SMB. Dove la firma dei messaggi e' abilitata ma non"
            " richiesta, dove SMB 1.0 risponde ancora, quali condivisioni si lasciano"
            " enumerare senza credenziali. Tutto letto da cio' che ogni dispositivo"
            " dichiara di se': nessuna credenziale provata, nessun file aperto.",
            "IN RETE ADESSO, nella pagina delle presenze: chi e' stato visto negli"
            " ultimi cinque minuti, ciascuno con il proprio storico sulla stessa riga"
            " -- quante permanenze, su quanti indirizzi, dal quando -- perche' senza"
            " quello non si distingue l'apparato che c'e' sempre stato da quello"
            " comparso adesso. La pagina si ricarica da sola ogni minuto e, se la"
            " ricognizione e' ferma, lo dichiara: un elenco vuoto perche' non c'e'"
            " nessuno e un elenco vuoto perche' nessuno sta guardando si assomigliano"
            " sullo schermo e significano cose opposte.",
            "SETTE DOMANDE GIA' SCRITTE IN PIU', in Sala operativa, che portano"
            " agli stessi dispositivi delle relazioni nuove: interfacce ferme da"
            " oltre dieci anni, interfacce mute, firma SMB non richiesta, SMB 1.0"
            " ancora acceso, certificati scaduti o in scadenza, reti dichiarate e mai"
            " guardate, chi e' in rete adesso. Il PDF si consegna, il CSV si apre e ci"
            " si lavora.",
            "LA FASCIA DELLA COPERTINA SI DIMENSIONA SUL CONTENUTO. Con l'altezza"
            " fissa la riga di identificazione -- tenant e data -- finiva sotto il"
            " bordo: testo chiaro su fondo bianco, tagliato a meta'. Riguardava ogni"
            " relazione prodotta finora.",
            "LE FASI DI SCANSIONE SI MISURANO SU CIO' CHE E' MISURABILE. Il contatore"
            " dei record lo valorizzano le sole fasi che scrivono record propri; le"
            " altre conferiscono aggiornando i nodi e lo lasciano a zero anche quando"
            " hanno lavorato -- 68.342 righe di porte raccolte a fronte di 563 passate"
            " tutte dichiarate a zero. Presentarlo come \"fase fallita\" sarebbe stato"
            " un allarme falso: si contano le passate che non hanno visto NESSUN host,"
            " e la differenza fra le due cose e' scritta nel documento.",
            "LA SONDA HA UNA NUMERAZIONE PROPRIA, che riparte dalla 1.2.0. Le due"
            " parti si aggiornano in momenti diversi -- la sonda sta in sede dal"
            " cliente, la console si aggiorna quando si vuole -- e un numero unico"
            " costringeva a inventare versioni della sonda per cambiamenti che non la"
            " riguardavano.",
        ],
    },
    {
        "version": "1.6.0",
        "date": "2026-09-12",
        "abstract": "I certificati in scadenza si mandano per posta a chi deve"
                    " rinnovarli, con tutto cio' che serve a rifarli. L'inventario"
                    " dice da quanti anni nessuno tocca un'interfaccia web. E chi"
                    " sbaglia lo schema dell'indirizzo viene rimandato invece che"
                    " respinto.",
        "changes": [
            "CERTIFICATI IN SCADENZA, INVIATI A CHI LI RINNOVA. Dalla pagina"
            " Certificati TLS si spedisce l'elenco a un recapito scritto sul momento."
            " Il recapito non si configura una volta per tutte perche' chi rinnova un"
            " certificato quasi mai e' chi guarda la console: e' il referente del"
            " sistema che lo ospita, e cambia da sistema a sistema. Un elenco di"
            " destinatari fissi manda tutto a tutti, che e' il modo in cui questi"
            " messaggi smettono di essere letti.",
            "Il messaggio porta il certificato PER INTERO -- soggetto e emittente in"
            " DN completo, validita', numero di serie, versione, algoritmo di firma,"
            " chiave, impronte SHA-256 e SHA-1, nomi alternativi DNS e IP, uso e uso"
            " esteso -- piu' il contesto del server (indirizzo, porta, nome host,"
            " dispositivo, sistema operativo, prodotto web, TLS negoziato). Chi"
            " rinnova lavora in una finestra di manutenzione, non davanti alla"
            " console: un avviso che dicesse solo \"scade fra 12 giorni\" lo"
            " costringerebbe a tornare qui per ogni campo.",
            "Si manda ESATTAMENTE cio' che si sta guardando: la soglia in giorni del"
            " campo e la pastiglia attiva. Senza filtro parte cio' che scade entro la"
            " soglia, oggi compreso; i gia' scaduti NON ci sono -- non stanno"
            " scadendo, sono un'altra coda di lavoro, piu' urgente, e mescolarla la"
            " renderebbe meno visibile. Per quelli c'e' la pastiglia Scaduti.",
            "Due corpi, testo e HTML: il testo semplice sopravvive alle regole"
            " aziendali che tolgono l'HTML e al copia-incolla dentro un ticket, che e'"
            " il modo in cui questo elenco viene usato davvero. Il messaggio passa"
            " dalla coda del prodotto, quindi ha ritentativi, e nel registro di audit"
            " resta a chi e' stato mandato e con quale criterio.",
            "QUANTO E' VECCHIA UN'INSTALLAZIONE. Le letture web ricavano ora l'anno"
            " che la pagina dichiara di se': copyright, meta, stringhe di build,"
            " intestazione Last-Modified, inizio di validita' del certificato. Nella"
            " lista dei nodi compare una pastiglia (\"ferma al 2014\") quando l'eta'"
            " supera i cinque anni, rossa oltre i dieci; nel dettaglio c'e' la"
            " colonna ANNO DICHIARATO con la fonte e IL FRAMMENTO da cui l'anno"
            " viene.",
            "La prova si mostra perche' il dato va letto per quello che e': un"
            " \"(c) 2014\" non dimostra che il software sia del 2014, dimostra che"
            " nessuno ha piu' toccato quella pagina dal 2014. E' un limite inferiore"
            " all'eta' -- e resta il segnale piu' economico che esista su una rete"
            " reale per riconoscere un'installazione abbandonata. Si prende l'anno"
            " PIU' RECENTE fra le prove: la domanda e' da quanto nessuno tocca quella"
            " cosa, non quando e' nata.",
            "Gli anni assurdi si rifiutano e i numeri di serie non diventano date: un"
            " solo \"2098\" in un elenco di apparati vecchi farebbe perdere fiducia in"
            " tutto l'elenco. Un Last-Modified di oggi si ignora, perche' una pagina"
            " generata al volo lo scrive sempre \"adesso\" e crederci direbbe che ogni"
            " apparato e' nuovo.",
            "CHI ARRIVA IN CHIARO SU UNA PORTA HTTPS VIENE RIMANDATO, non respinto."
            " Prima rispondeva \"400 Bad Request -- The plain HTTP request was sent to"
            " HTTPS port\": esatto e inutile, perche' chi legge non capisce di avere"
            " sbagliato schema e conclude che il servizio non risponde. Capita a"
            " tutti, perche' davanti a una porta non standard il browser assume"
            " http://. Vale per la console e per la sonda.",
            "GUIDA DI INSTALLAZIONE IN PDF, generata dal sorgente in docs/ con"
            " l'impaginatore dei report: frontespizio con indice, tipografia PT Sans,"
            " numerazione. Porta le misure e i guasti veri incontrati sul campo, non"
            " una procedura teorica. Si rigenera con `python tools/genera_guida_pdf.py`:"
            " una copia modificata a mano sarebbe una seconda verita'.",
            "L'impaginatore dei documenti: il sottotitolo va a capo invece di uscire"
            " dal foglio, un documento senza tenant non scrive piu' \"Tenant\" seguito"
            " dal vuoto, e l'avvertenza di riservatezza dice il vero -- una guida di"
            " installazione non contiene la rete di nessuno, e stamparci sopra"
            " \"riservato\" insegna a ignorare l'avviso proprio dove conta.",
        ],
    },
    {
        "version": "1.5.0",
        "date": "2026-09-10",
        "abstract": "La console della sonda si vede dal server: avanzamento, coda,"
                    " diario e presenze, senza dover raggiungere la sonda. E il"
                    " riconoscimento non attribuisce piu' a 128 nodi una porta che"
                    " risponde per tutto il segmento.",
        "changes": [
            "Nuova pagina Console della sonda (Sonde > Console). Mostra quello che si"
            " vede aprendo l'interfaccia della sonda in sede: configurazione in"
            " vigore, nodi, coda da conferire, fasi in corso, ricognizione delle"
            " presenze, ultime passate e -- soprattutto -- il DIARIO LOCALE, che"
            " finora si poteva leggere solo stando davanti alla sonda.",
            "La console dichiara sempre di QUANDO e' il dato che mostra, e avvisa"
            " quando il battito non arriva da piu' di due minuti: la sonda vive nella"
            " rete del cliente e parla solo in uscita -- il server non puo'"
            " interrogarla -- quindi lo stato arriva col battito. Una fotografia"
            " presentata come diretta sarebbe una bugia.",
            "Porte iniettate: la prova decisiva non dipende piu' dalla diffusione."
            " Se una porta risponde sull'indirizzo di rete o di broadcast di una"
            " subnet -- dove un host non puo' esistere -- la serve un apparato"
            " intermedio per tutto il segmento, e tanto basta. Misurato sulla rete"
            " ospiti di un'installazione: la tcp/5060 era aperta sul 53% dei nodi"
            " (sotto la soglia) e su entrambi gli indirizzi impossibili, e produceva"
            " 128 \"Telefono VoIP\" inesistenti. Ora sono zero.",
            "Sulle subnet dove gli indirizzi impossibili RISPONDONO (anche solo al"
            " ping) la soglia di diffusione scende al 50%: su un segmento cosi' non"
            " si sa nemmeno quali indirizzi siano host, e una porta presente su meta'"
            " di essi non e' attribuibile a nessuno. Non scende a zero, perche'"
            " dietro l'apparato intermedio ci sono anche macchine vere.",
            "Il conferimento accetta il genere \"presence\" (avvistamenti sulle reti"
            " senza fili) e conserva l'istantanea della console consegnata dalla"
            " sonda, con il proprio istante.",
            "SOTTOSISTEMA PSN: il piano di indirizzamento diventa un sistema."
            " Il piano del Polo vive in un foglio di settantanove schede -- anagrafica"
            " delle subnet, una scheda per subnet con UNA RIGA PER INDIRIZZO, tenant,"
            " database, servizi pubblicati, convenzione dei nomi. E' un documento"
            " corretto, e proprio per questo non risponde alle domande che contano:"
            " qual e' il prossimo indirizzo libero, questo hostname esiste due volte,"
            " due subnet si sovrappongono, che cosa sta dietro un URL, che cosa e'"
            " cambiato dalla versione precedente. Nuovo menu PSN con nove pagine.",
            "SEPARATO PER COSTRUZIONE, come richiesto: archivio in un DATABASE"
            " distinto (non uno schema dentro quello del prodotto, che finirebbe nelle"
            " sue copie e nelle sue migrazioni), nessuna chiave esterna verso le"
            " tabelle del prodotto, nessuna query che le nomini -- e due test che lo"
            " verificano, perche' una promessa non verificata decade da se'. Le"
            " istruzioni per rimuoverlo del tutto stanno in docs/15_PSN.md: sette"
            " passi, e l'archivio del prodotto non si sfiora. Nessuna dipendenza"
            " nuova: un .xlsx e' un archivio di XML e si legge con la libreria"
            " standard.",
            "TRE DIFETTI DEL DOCUMENTO, trovati al primo conferimento del piano vero."
            " 441 indirizzi su quattro fogli erano salvati come NUMERI senza punti"
            " (192168230128): nessun lettore li riconosce, e quei fogli risultavano"
            " vuoti -- ora si ricostruiscono, ma solo quando la ricostruzione e'"
            " univoca dentro la rete del foglio, perche' indovinare un indirizzo e'"
            " peggio che perderlo. Due fogli dichiarano un codice di subnet che in"
            " anagrafica appartiene a un'altra rete (il foglio 10.58.70.0 dichiara"
            " 041, che e' la 10.58.80.0): fidandosi del codice, 254 indirizzi"
            " finirebbero archiviati sotto la subnet sbagliata. E centinaia di celle"
            " con errori di formula, che valgono come vuoto invece di diventare una"
            " subnet chiamata #VALUE!.",
            "L'ANALISI DICHIARA, NON ACCUSA. Duplicati di hostname e di indirizzo,"
            " subnet sovrapposte, indirizzi fuori dalla propria subnet, database senza"
            " tenant in anagrafica, rinomine che il piano stesso dichiara in sospeso."
            " Due giudizi sono stati corretti perche' producevano rumore: i segnaposto"
            " (\"-\", \"n/a\", \"VIP 1\") non sono nomi e non fanno duplicati ne'"
            " assegnazioni; e una convenzione INCOMPLETA non rende sbagliati i nomi --"
            " pretendere sito-tenant-ruolo dava 79 riscontri su 257 nomi, ma i nomi"
            " erano giusti e il Nomenclatore non elencava i siti delle Centrali"
            " Operative. Ora una riga per SIGLA non dichiarata, da portare a chi"
            " mantiene la convenzione: da 117 accuse a 64 riscontri azionabili.",
            "LA CONSOLE DI UNA SONDA SI VEDE CHE NON E' IL SERVER. Mostra, dentro"
            " la console, le stesse cose che si vedono aprendo l'interfaccia della"
            " sonda in sede: due interfacce che si somigliano sono un rischio"
            " operativo -- chi crede di stare sul server mentre guarda una sonda"
            " prende decisioni sui dati sbagliati. La pagina porta ora l'arancione"
            " della sonda: un nastro APPICCICATO IN ALTO che resta mentre si scorre"
            " (su una pagina lunga la scritta in testa scorrerebbe via proprio"
            " mentre si leggono i numeri), una cornice arancione attorno a tutto il"
            " contenuto e un piede che ripete l'appartenenza. Il nastro porta anche"
            " l'istante del dato e diventa rosso quando il battito non arriva:"
            " l'altra cosa che non si deve dimenticare guardando quella pagina."
            " Anche i bottoni che aprono la console sono arancioni -- sono il punto"
            " in cui si cambia macchina.",
            "AZZERAMENTO DELLE INFORMAZIONI RACCOLTE, dalla pagina dei tenant. Serve"
            " quando la raccolta e' sporca -- un perimetro sbagliato, una sonda"
            " dietro un NAT che ha inventato nodi, un cambio di rete che rende"
            " l'inventario un archivio di fantasmi -- e si vuole ricominciare senza"
            " rifare la configurazione. Il tenant RESTA: si butta solo cio' che le"
            " sonde hanno osservato.",
            "Il confine fra \"raccolto\" e \"dichiarato\" e' scritto in un punto solo"
            " (purge.py) e verificato da un test che pretende che OGNI tabella del"
            " tenant stia da un lato o dall'altro: chi aggiungera' una tabella e non"
            " la classifichera' vedra' il test rosso, invece di scoprire un giorno"
            " che il bottone mente. Restano utenze, sonde, perimetro, zone,"
            " controlli, regole, report, notifiche inviate e registro di audit.",
            "Due cose non si cancellano per ragioni che non sono tecniche: gli"
            " incidenti da cui e' nata una comunicazione ad ACN -- una comunicazione"
            " all'autorita' e' un atto dovuto (D.lgs. 138/2024 art. 25) e la sua"
            " prova non sparisce con un bottone -- e le notifiche gia' inviate, che"
            " sono la prova di cio' che e' stato comunicato e a chi. L'esito dice"
            " quanti incidenti sono stati conservati e perche'.",
            "La conferma mostra il conto di cio' che si perde, voce per voce, e"
            " chiede di digitare il codice del tenant: un avviso che si chiude per"
            " sbaglio non e' una conferma per un'operazione che butta giorni di"
            " scansione. La pagina dei tenant ha una colonna RACCOLTO con quel"
            " numero, cosi' si vede prima di aprire il bottone.",
            "Alle sonde viene chiesto di ricominciare dalla scoperta (comando"
            " `forget`). Senza, il bottone sembrerebbe rotto: la sonda ricorda quali"
            " fasi ha svolto, e un nodo che il server ha dimenticato non tornerebbe"
            " fino alla scadenza della cadenza -- giorni, con la console vuota.",
        ],
    },
    {
        "version": "1.4.0",
        "date": "2026-09-10",
        "abstract": "Le reti senza fili si dichiarano e si osservano a parte: una"
                    " ricognizione ogni due minuti, e chi compare viene approfondito"
                    " subito invece di attendere il proprio turno. Nasce lo storico"
                    " delle presenze -- chi c'era e quando -- e l'elenco dei nodi non"
                    " lascia piu' vuota la colonna del sistema operativo.",
        "changes": [
            "Interruttore \"Senza fili\" su ogni subnet del Perimetro. Non e'"
            " un'etichetta descrittiva: cambia il modo in cui la sonda osserva quella"
            " rete. Su una rete Wi-Fi un apparato resta agganciato minuti, e una"
            " passata completa ogni tre giorni non lo vede mai.",
            "Nuova pagina Dispositivi > Presenze Wi-Fi: chi era in rete e quando."
            " L'unita' non e' l'indirizzo -- che il DHCP riassegna -- ma l'apparato"
            " riconosciuto, con la fonte del riconoscimento dichiarata in colonna.",
            "Dalla pagina delle presenze un pulsante apre lo STORICO"
            " DELL'ANDAMENTO: un grafico di quanti apparati erano in rete intervallo"
            " per intervallo (il respiro di una rete di utenza: il picco del mattino,"
            " il vuoto della notte) e, sotto, una riga per apparato con le sue"
            " presenze disegnate sul tempo. Si legge a colpo d'occhio la differenza"
            " fra un apparato che sta tutto il giorno e uno che passa venti minuti, e"
            " la riga dichiara quando lo stesso apparato ha avuto piu' indirizzi."
            " Quattro periodi: 24 ore, 48 ore, 7 giorni, 30 giorni, per rete o su"
            " tutte.",
            "L'identita' di un apparato senza fili segue quattro gradi di certezza:"
            " indirizzo fisico e numero di serie identificano l'apparato, il nome host"
            " e' probabile, e quando non c'e' nessuno dei tre il prodotto NON finge di"
            " sapere chi era: dichiara che la permanenza riguarda l'indirizzo. La"
            " pagina avvisa quando piu' della meta' dello storico e' in quel caso, e"
            " dice come rimediare.",
            "Senza indirizzo fisico si usa cio' che si e' raccolto: se le porte e il"
            " TTL osservati su un indirizzo cambiano, quell'indirizzo e' passato a un"
            " altro apparato, e lo storico lo registra come una visita nuova. E' il"
            " solo modo di accorgersene quando il MAC non c'e'.",
            "Lo storico delle presenze ha una conservazione a termine (90 giorni"
            " predefiniti) con cancellazione automatica: la presenza di un apparato"
            " personale e' un dato personale (GDPR art. 5).",
            "Elenco dei nodi: la colonna \"Sistema operativo\" non resta mai vuota."
            " Prima mostrava il solo rilevamento di nmap, che su una rete di PA riesce"
            " raramente; ora otto fonti in cascata -- rilevamento, dichiarazione SMB,"
            " descrizione SNMP, famiglia, banner web, profilo di porte, TTL, classe"
            " dell'apparato -- e l'ultimo gradino dice \"non determinato\" con il"
            " motivo. Le ipotesi si vedono che sono ipotesi.",
            "Elenco dei nodi: al posto della colonna \"Subnet\" -- che si legge gia'"
            " dall'indirizzo e dal filtro -- la colonna \"Info\" con cio' che"
            " l'apparato dichiara nelle proprie pagine: modello, nome, POSIZIONE"
            " FISICA, firmware. La posizione e' l'unico dato che nessuna scansione"
            " puo' ricavare: non sta in rete, sta scritta sull'apparato.",
            "I dati iniziali non creano piu' il tenant dimostrativo \"ACME"
            " International\": serviva a provare l'isolamento fra organizzazioni, ma"
            " quella e' una necessita' dei test, non di un'installazione -- e nel"
            " selettore dei tenant di un amministratore di sistema un tenant finto e'"
            " una cosa che qualcuno prima o poi apre. Le installazioni che lo hanno"
            " gia' non lo perdono: si elimina, se si vuole, da Amministrazione >"
            " Organizzazioni.",
            "Corretto un difetto che impediva l'avvio dopo l'aggiornamento: lo schema"
            " dichiarava un indice su una colonna che le migrazioni aggiungono dopo, e"
            " su un database esistente la console riavviava in ciclo. Le colonne si"
            " allineano ora PRIMA dello schema, e un test simula un database di una"
            " versione precedente.",
        ],
    },
    {
        "version": "1.3.1",
        "date": "2026-09-10",
        "abstract": "Gli apparati che non dicono niente di se' si identificano da come"
                    " RISPONDONO: l'icona che servono e l'insieme delle intestazioni"
                    " HTTP diventano impronte, e un apparato muto prende in prestito il"
                    " verdetto dei nodi identici a lui. La scheda del dispositivo elenca"
                    " gli apparati identici, con il collegamento a ognuno.",
        "changes": [
            "Riconoscimento per somiglianza: due apparati che servono la STESSA icona"
            " sono lo stesso prodotto (l'icona sta nel firmware, non la sceglie chi"
            " installa), e due che rispondono con lo stesso insieme di intestazioni HTTP"
            " hanno dentro lo stesso programma. Un nodo che non dichiara nulla ricava da"
            " qui la propria classificazione.",
            "Il prestito e' prudente per costruzione: il gruppo di apparati identici"
            " deve essere concorde almeno all'80%, marca e modello si riportano solo se"
            " unanimi, e un apparato puo' fare da riferimento solo se il suo tipo lo ha"
            " detto una persona o se lo ha guadagnato con prove proprie. La somiglianza"
            " da sola non produce mai un verdetto confidente: serve una seconda famiglia"
            " di prove.",
            "Nella scheda del dispositivo, sopra le letture web: \"7 altri nodi servono"
            " la stessa icona: e' lo stesso prodotto\", con il collegamento a ognuno. Se"
            " questo apparato va aggiornato, vanno aggiornati anche quelli; e se lo si e'"
            " identificato a mano, quel lavoro vale anche per loro.",
            "Le impronte stanno in colonna nella banca dati (icona e intestazioni):"
            " si possono cercare e confrontare, non solo leggere nel dettaglio di un"
            " nodo. Dell'icona si conserva l'impronta, non l'immagine; delle"
            " intestazioni i nomi, non i valori -- i valori possono contenere dati"
            " dell'apparato.",
            "25 nuove firme di applicazione riconosciute dalle pagine web (NetBox, MyQ,"
            " One Identity Safeguard, WildFly, GlassFish, Oracle XML DB, WebLogic,"
            " JBoss, Jetty, Outlook Web App, SharePoint, RD Web, Nextcloud, Moodle,"
            " Zimbra, Roundcube, UniFi, Veeam, Kibana, Splunk, FreePBX, Proxmox,"
            " Synology, QNAP): su una pagina web conta piu' l'applicazione esposta che"
            " il nome del server web.",
            "Corretto un riconoscimento sbagliato: un GlassFish veniva classificato"
            " stampante Kyocera perche' \"ecosys\" corrispondeva dentro la parola"
            " \"ecosystem\". Tutte le firme sono state riviste per la stessa classe di"
            " errore, e un test la sorveglia.",
        ],
    },
    {
        "version": "1.3.0",
        "date": "2026-09-10",
        "abstract": "Il motore di scansione e' riprogettato: una /24 completa e"
                    " accurata passa da MAI a circa sette minuti. Arrivano gli indirizzi"
                    " MAC e la porta fisica dagli apparati di rete, la copia"
                    " dell'archivio dalla console torna disponibile su PostgreSQL, e le"
                    " porte scandite sono scelte per famiglia di apparato invece che per"
                    " frequenza statistica.",
        "changes": [
            "Indirizzi MAC dalle tabelle ARP degli apparati di rete (SNMP). Su una rete"
            " reale, di 7.309 nodi solo 39 avevano il MAC -- tutti nella subnet della"
            " sonda, perche' ARP non attraversa un router. La sonda ora interroga gli"
            " apparati e ne legge le corrispondenze indirizzo-MAC per interi segmenti."
            " La provenienza si dichiara: \"osservato\" se l'ha visto la sonda,"
            " \"da <apparato>\" se gliel'ha riferito uno switch o un router.",
            "Punto di attacco fisico: dove la catena di tabelle dell'apparato e'"
            " completa, l'inventario dice su quale PORTA di quale switch un nodo e'"
            " attaccato (per esempio Gi1/0/14 su core-sw). Compare nell'elenco dei nodi,"
            " nella scheda del dispositivo e nella sua scheda in PDF. Se la catena si"
            " interrompe la porta non si indovina: resta non nota.",
            "Scoperta automatica degli apparati da interrogare: si provano i gateway"
            " probabili di ogni subnet e i nodi con la 161/UDP osservata aperta, e entra"
            " nell'elenco solo chi risponde con la community configurata E ha una"
            " tabella ARP. Un apparato che risponde con la community di fabbrica"
            " (public/private) NON viene aggiunto ma segnalato nel diario: e'"
            " un'esposizione da chiudere.",
            "Il costruttore della scheda di rete si ricava dal prefisso del MAC anche"
            " per i MAC riferiti da un apparato, con lo stesso catalogo che usa nmap:"
            " su un apparato muto e' spesso l'unico indizio su che cosa sia.",
            "Nuovo filtro \"Indirizzo fisico\" nell'elenco dei nodi: MAC osservato dalla"
            " sonda, MAC riferito da un apparato, senza MAC, con porta di attacco nota."
            " Risponde a \"quali subnet sono coperte davvero?\".",
            "Le ricerche libere non distinguono piu' maiuscole e minuscole: cercare"
            " \"cisco\" trova \"Cisco Systems\". Valeva per la ricerca globale, l'elenco"
            " dei nodi, il registro eventi, il SIEM e il catalogo CVE.",
            "Esportazione CSV delle interrogazioni pronte: consegnava una riga di"
            " intestazioni al posto dei dati, e alcune interrogazioni restituivano meno"
            " colonne di quelle dichiarate. Corretto.",
            "La pagina di dettaglio di una comunicazione ACN non si apriva (errore"
            " interno): il modello non era valido. Corretto, e ora tutti i modelli di"
            " pagina vengono verificati dai test.",
            "Copia e ripristino dell'archivio dalla console tornano disponibili con"
            " PostgreSQL. La copia e' un archivio pg_dump verificato appena prodotto"
            " (se la verifica non passa il file viene eliminato: una copia che sembra"
            " riuscita e non e' ripristinabile e' peggio di nessuna copia); il"
            " ripristino salva prima lo stato corrente e riversa l'archivio in una"
            " sola transazione, senza fermare il servizio.",
            "Le due versioni di PostgreSQL vengono confrontate prima di ogni copia e"
            " di ogni ripristino, e l'operazione si rifiuta se non sono compatibili"
            " dicendo quale client serve. Il ripristino richiede la stessa versione"
            " major del server: con una diversa pg_restore imposta parametri di"
            " sessione che il server non riconosce e si interrompe -- un problema che"
            " altrimenti si scopre il giorno in cui la copia serve.",
            "Compattazione dell'archivio: non promette piu' spazio restituito al"
            " disco. Su PostgreSQL VACUUM rende riutilizzabile lo spazio delle righe"
            " eliminate ma non lo restituisce al sistema operativo (servirebbe VACUUM"
            " FULL, che fermerebbe l'applicazione): il messaggio dichiara quante"
            " righe sono state recuperate, che e' cio' che l'operazione fa davvero.",
            "Motore di scansione riprogettato: una /24 completa e accurata passa da"
            " MAI a circa sette minuti. Il difetto non era un parametro mal tarato ma"
            " un'assunzione sbagliata -- che gli host di un gruppo si scansionino in"
            " parallelo senza costo. Il ritmo di invio di nmap e' PER PROCESSO, quindi"
            " ventiquattro host costano ventiquattro volte uno, e con un tetto di tempo"
            " per host venivano abbandonati TUTTI: sul campo 66 abbandoni di fila sugli"
            " stessi indirizzi, ondate da 257 secondi che restituivano zero host.",
            "La fase delle porte non usa piu' un tetto di tempo per host: in quella"
            " struttura non proteggeva da nulla e causava il difetto. Al suo posto un"
            " tetto sul PROCESSO, calcolato dal lavoro richiesto (sonde da inviare"
            " diviso il ritmo misurato). Il tetto per host resta dove serve davvero:"
            " nelle fasi che eseguono script su un singolo servizio.",
            "Due livelli di esame delle porte. Ogni ciclo, ventotto porte che dicono"
            " CHE COS'E' un apparato, su tutti gli host: e' la passata che si completa"
            " in minuti. A cadenza lunga, le prime mille porte sui soli host che hanno"
            " gia' mostrato un segnale -- sulla rete di prova 142 indirizzi su 256 non"
            " hanno alcuna porta aperta, e chiederne mille a tutti costa oltre quattro"
            " ore per non imparare nulla.",
            "Scartate due strade piu' rapide perche' PERDONO porte aperte, e un"
            " inventario incompleto e' peggio di uno lento: forzare il ritmo di nmap"
            " (0-4 porte note su 13, esiti irriproducibili) e dividere le porte fra"
            " piu' processi (piu' lento E meno accurato di un processo solo).",
            "Cancellazione di una sonda: il messaggio che spiega \"archivio occupato,"
            " nulla e' stato cancellato\" non poteva comparire, perche' il codice"
            " intercettava l'errore di SQLite. Su PostgreSQL l'operatore vedeva una"
            " pagina di errore. Corretto.",
            "Le porte della passata di approfondimento scendono da mille a 232,"
            " scelte per FAMIGLIA DI APPARATO -- postazioni Windows, Linux, apparati di"
            " rete, stampanti, telefoni, telecamere, banche dati, impianti, gestione"
            " fuori banda -- piu' tutte quelle effettivamente trovate aperte sulla rete."
            " Le prime mille di nmap sono ordinate per frequenza su Internet: meta' sono"
            " servizi che in un ufficio non esistono, e mancano porte di gestione che"
            " qui contano (per esempio Intel AMT su una postazione). La passata di"
            " approfondimento passa da ~28 minuti a ~6,5.",
            "Se la scansione trova un apparato SNMP, viene interrogato da se': non"
            " serve piu' premere \"Scopri e popola l'elenco\". Si interrogano tutti gli"
            " host vivi con una richiesta SNMP diretta -- otto secondi per una /24 --"
            " invece di sondare la porta 161 in UDP, che non sa distinguere \"aperta\""
            " da \"nessuna risposta\" e darebbe ogni indirizzo per buono.",
            "Un apparato entra fra quelli interrogati solo se SUPERA LA PROVA: risponde"
            " alla community configurata e ha una tabella ARP non vuota. Chi risponde"
            " con la community di fabbrica (public/private) non viene aggiunto ma"
            " segnalato nel diario: chiunque sulla rete puo' leggerne la"
            " configurazione, ed e' un'esposizione da chiudere.",
            "La scansione continua a non toccare l'intervallo dei server X"
            " (6000-6009), che apriva sui PC degli operatori la finestra \"consenti"
            " accesso al server X?\". Verificato che l'esclusione prevale anche ora che"
            " le porte si chiedono con un elenco esplicito, e la garanzia e' fissata da"
            " un test.",
        ],
    },
    {
        "version": "1.2.9",
        "date": "2026-09-09",
        "abstract": "Cancellare una sonda non fallisce piu' con l'archivio occupato;"
                    " console e sonda si distribuiscono in container con TLS e base dati"
                    " dedicata; il motore di scansione non scarta piu' un apparato per"
                    " un limite di tempo nostro.",
        "changes": [
            "Cancellazione di una sonda: non risponde piu' \"archivio occupato\"."
            " Le colonne di vincolo delle tabelle che crescono (nodi, esecuzioni, esiti"
            " dei controlli, misure, esposizioni, diario) sono ora indicizzate: senza"
            " indice ogni cancellazione scandiva le tabelle per intero -- una sola sonda"
            " comportava l'aggiornamento di circa 118.000 righe. L'attesa sul blocco e'"
            " diventata una scelta dichiarata (trenta secondi) invece del valore"
            " predefinito della libreria (cinque).",
            "Se l'archivio risulta occupato, l'operazione lo DICE e dichiara che nulla"
            " e' stato cancellato, invece di mostrare una pagina di errore.",
            "Distribuzione in container per console e sonda: TLS sulle interfacce,"
            " Gunicorn, utente non privilegiato, base dati PostgreSQL predisposta con"
            " utenze separate (proprietario e applicativo) e script di avvio e arresto"
            " per Windows e Linux.",
            "Sonda in container: la scansione SYN e il rilevamento del sistema operativo"
            " funzionano senza privilegi di amministratore, tramite le capacita' del"
            " kernel concesse al solo nmap.",
            "La sonda verifica il certificato del server e si puo' indicare di quale"
            " certificato fidarsi (CA interna o certificato proprio del server): serve"
            " quando la console e' passata a HTTPS con un certificato non pubblico.",
            "Motore di scansione: un apparato che nmap abbandona per scadenza non viene"
            " piu' scartato dall'inventario. Non essendo stato esaminato e' IGNOTO, non"
            " assente, e scartarlo lo faceva sparire per un limite di tempo nostro.",
            "Motore di scansione: il tempo minimo per host delle fasi di rilevazione"
            " torna al valore misurato come funzionante. Era stato abbassato per drenare"
            " piu' in fretta la coda, ma sotto quella soglia la fase gira senza produrre"
            " nulla.",
            "Il tempo massimo di una scansione si calcola sulle ondate che nmap esegue"
            " davvero, non sul numero di bersagli: un compito non puo' piu' restare"
            " appeso per ore bloccando il ciclo.",
        ],
    },
    {
        "version": "1.2.8",
        "date": "2026-09-04",
        "abstract": "I certificati TLS dei web server si cercano per scadenza e finiscono"
                    " nel resoconto quotidiano; le subnet di ogni tenant si esportano in"
                    " un file di testo; all'avvio i componenti sono raggiungibili dalla"
                    " rete oltre che in locale.",
        "changes": [
            "Nuova pagina \"Certificati TLS\" (Rete): elenca i web server con il loro"
            " certificato e permette di cercare quelli SCADUTI o IN SCADENZA, con i giorni"
            " che mancano. La raccolta del certificato per intero (soggetto, emittente,"
            " validita', numero di serie, impronte, nomi alternativi) era gia' attiva.",
            "Il resoconto quotidiano riporta una sezione \"Certificati TLS\" con i"
            " certificati scaduti e quelli in scadenza entro trenta giorni.",
            "Da Amministrazione > Impostazioni Sistema si esportano le subnet di ciascun"
            " tenant in un file .txt, un CIDR per riga e in ordine numerico -- pronto da"
            " rileggere o reimportare.",
            "All'avvio i componenti ascoltano di default anche sull'indirizzo della"
            " macchina, oltre che su 127.0.0.1: sono raggiungibili dalla rete senza"
            " doverlo indicare a ogni avvio (per il solo locale si passa"
            " -ServerHost 127.0.0.1).",
        ],
    },
    {
        "version": "1.2.7",
        "date": "2026-09-04",
        "abstract": "Il report tecnico di inventario diventa molto piu' compatto: nodi e"
                    " servizi in un'unica vista a badge per indirizzo, con l'icona del"
                    " tipo, e le spiegazioni ripetute ridotte a una sola. Arriva il"
                    " profilo Operatore SIEM, con un menu su misura.",
        "changes": [
            "Report \"Inventario e valutazione tecnica\" molto piu' compatto: le sezioni"
            " Nodi e Servizi rilevati sono fuse in un'unica vista a \"badge\" per"
            " indirizzo -- indirizzo, tipo e sistema operativo a parole, icona del tipo"
            " di dispositivo, e le porte proprie con prodotto e versione. Su una rete di"
            " circa 7.000 nodi il documento passa da ~1.680 a ~880 pagine (da 7,8 a"
            " 4,3 MB).",
            "Le porte \"iniettate\" dalla rete (aperte su quasi tutta la rete, la"
            " risposta di un apparato e non del nodo) non si ripetono piu': la spiegazione"
            " compare una sola volta e nel badge se ne conta solo il numero"
            " (\"+N iniett.\"), invece della stessa frase ripetuta su migliaia di righe.",
            "Icona vettoriale del tipo di dispositivo nel badge del report: server,"
            " stampante, firewall, router, switch, telefono, telecamera, UPS, Wi-Fi,"
            " postazione, archiviazione.",
            "Nuovo profilo \"Operatore SIEM\": opera il SIEM e gli incidenti come un"
            " analista, ma con un menu su misura (SIEM, Incidenti, dashboard, report,"
            " guida) e senza l'amministrazione del tenant.",
        ],
    },
    {
        "version": "1.2.6",
        "date": "2026-09-03",
        "abstract": "La sonda torna a conferire i nodi senza restare bloccata sulla rete"
                    " di migliaia di apparati, e il SIEM diventa operativo: gli allarmi"
                    " confluiscono negli Incidenti, gli eventi si filtrano e si cancellano,"
                    " le regole di rilevazione si creano a mano. Ogni utente puo' ricevere"
                    " notifiche personali su Telegram.",
        "changes": [
            "Sonda: risolto il blocco per cui migliaia di nodi restavano \"in"
            " lavorazione\" senza mai essere conferiti. Un host che nmap abbandona su una"
            " fase di ispezione (servizi, sistema operativo) ora fa comunque avanzare la"
            " fase, invece di essere ripescato a ogni ciclo; il completamento del profilo"
            " prende piu' posti quando l'arretrato e' grande, e le passate dei servizi"
            " sono piu' rapide.",
            "Gli allarmi del SIEM confluiscono negli Incidenti (Controlli): chiudere o"
            " dichiarare falso positivo un allarme risolve anche l'incidente collegato.",
            "Incidenti: sezione propria del menu, con la sua etichetta, sotto il SIEM"
            " -- vi confluiscono controlli, segnalazioni manuali e allarmi del SIEM.",
            "SIEM, Eventi: filtro per OGNI colonna (data, gravita', genere, host,"
            " indirizzo, utenza, messaggio), messaggio a capo per leggerlo per intero,"
            " e cancellazione degli eventi (filtrati o dell'intero archivio).",
            "SIEM, Regole di rilevazione: si creano e si eliminano dalla pagina, oltre"
            " a quelle del catalogo.",
            "SIEM: ascolto syslog integrato in TCP e UDP sulle porte 514 e 5514; nelle"
            " date degli eventi compaiono anche i secondi.",
            "Corretta la chiusura di un allarme SIEM che rispondeva \"Stato non previsto\".",
            "Profilo e sicurezza: ogni utente puo' dichiarare il proprio ID Telegram"
            " (con la spiegazione di come trovarlo e un invio di prova) per ricevere"
            " notifiche personali.",
            "L'email di benvenuto a un nuovo utente riporta sempre l'indirizzo del"
            " sistema (quello dichiarato in \"Indirizzo pubblico del server\").",
        ],
    },
    {
        "version": "1.2.4",
        "date": "2026-09-03",
        "abstract": "Arriva il SIEM: raccolta dei log degli apparati, eventi di"
                    " sicurezza e allarmi correlati alla threat intelligence. Le schede"
                    " degli apparati e i report raccolgono ora tutto cio' che si e'"
                    " letto (interfacce web, certificati, diagnosi), e la sonda profila"
                    " i nodi in modo piu' robusto e senza restare bloccata.",
        "changes": [
            "Nuovo modulo SIEM: onboarding dei log (container Vector o finestra"
            " \"Incolla log\"), riconoscimento per famiglia di apparato (firewall,"
            " Windows, Linux, apparati di rete) e per i centralini Ericsson MX-ONE.",
            "Rilevazione a soglie con allarmi correlati ai riscontri di threat"
            " intelligence del nodo: un attacco verso una macchina gia' esposta pesa"
            " di piu'. Gli allarmi critici di apparato si aprono subito.",
            "Menu diviso in sezioni con etichette fisse (Monitor, SIEM,"
            " Amministrazione e guida).",
            "Invio di un report via email o Telegram a recapiti scritti sul momento.",
            "Scheda PDF dell'apparato e \"PDF della lettura\": ora riportano interfacce"
            " web, fatti dichiarati, diagnosi dai registri e certificato TLS per intero.",
            "Filtro per Attore in Audit & Eventi; freno alle notifiche di rientro di un"
            " incidente (un promemoria al massimo ogni cinque minuti).",
            "Sonda: profilazione piu' robusta -- il completamento del profilo ha la"
            " precedenza sulle letture, gli host che non rispondono si arrendono invece"
            " di bloccare la coda \"in lavorazione\" per ore.",
            "Riconoscimento di telefoni IP Cisco, UPS HP/MGE (con diagnosi dei"
            " registri) e classificazione come Windows dei nodi con la sola porta RDP.",
            "Report di conformita' UE con box per requisito ed esempi reali della rete;"
            " riferimento del documento e metadati PDF (autore, applicazione).",
        ],
    },
    {
        "version": "1.1.0",
        "date": "2026-08-28",
        "abstract": "Versione di base della console: inventario, monitoraggio,"
                    " controlli, threat intelligence, sala operativa e reportistica.",
        "changes": [
            "Inventario di rete dalle sonde, monitoraggio e scostamenti.",
            "Controlli periodici con workflow degli incidenti e notifiche"
            " (posta e Telegram).",
            "Threat intelligence: catalogo locale CVE/CWE/ATT&CK e correlazione.",
            "Sala operativa (NOC, SOC, ricerca), zone di rete e comunicazioni ACN.",
            "Reportistica PDF e resoconto quotidiano.",
        ],
    },
]


def voci() -> list:
    """Le voci del changelog, dalla piu' recente. Copia difensiva: chi la riceve
    non deve poter modificare il catalogo."""
    return [dict(v, changes=list(v["changes"])) for v in CHANGELOG]
