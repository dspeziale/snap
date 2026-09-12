# -----------------------------------------------------------------
# changelog.py — storico delle versioni della sonda, con abstract e cambiamenti
# Autore: Daniele Speziale
# Data creazione: 2026-09-09
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap probe - Che cosa e' cambiato, versione per versione.

Il badge della versione nel menu apre l'elenco di questi cambiamenti, come nella
console: chi trova una sonda installata in sede deve poter vedere, con un clic, di
che versione si tratta e che cosa fa di nuovo -- senza dover aprire un documento.

Regola (memoria di progetto): quando si cambia `APP_VERSION` in `settings.py` si
aggiunge QUI, in cima, una voce con un breve abstract e l'elenco dei cambiamenti
principali. La voce piu' recente sta per prima.

Nota sulla numerazione: fino alla 1.0.0 la sonda aveva una propria numerazione,
mentre l'immagine di distribuzione portava gia' quella del prodotto. Erano due numeri
per la stessa cosa, e in assistenza non si capiva quale contasse: dalla 1.2.9 la sonda
segue la versione del PRODOTTO, la stessa della console.


Numerazione
-----------
Dalla 1.2.0 la sonda ha una numerazione PROPRIA, distinta da quella della console:
le due parti si aggiornano in momenti diversi, e un numero unico costringeva a
inventare versioni della sonda per cambiamenti che non la riguardavano. Le voci
precedenti alla 1.2.0 appartengono al periodo in cui la sonda seguiva la versione del
prodotto, e si conservano come storia: non vanno confrontate con i numeri di oggi.
"""

from __future__ import annotations

# Ogni voce: version, date (YYYY-MM-DD), abstract (1-2 frasi), changes (elenco).
CHANGELOG = [
    {
        "version": "1.2.0",
        "date": "2026-09-12",
        "abstract": "La sonda riparte con una numerazione PROPRIA, staccata da quella"
                    " della console. Questa versione dichiara come base tutto cio' che"
                    " la sonda sa fare oggi; le voci sotto restano come storia del"
                    " periodo in cui seguiva la versione del prodotto.",
        "changes": [
            "NUMERAZIONE PROPRIA. Sonda e console si aggiornano in momenti diversi --"
            " la sonda sta in sede dal cliente, la console si aggiorna quando si"
            " vuole -- e un numero unico costringeva a inventare versioni della sonda"
            " per cambiamenti che non la riguardavano. Il protocollo fra le due parti"
            " non dipende da questi numeri: lo governa la versione dell'agente"
            " dichiarata nel battito.",
            "INTERFACCIA E MOTORE IN DUE PROCESSI. Vivevano nello stesso interprete"
            " Python, che esegue un thread per volta: mentre i trentadue lavoratori"
            " di scansione lavoravano, la pagina aspettava. Misurato sulla pagina di"
            " accesso, che non tocca nemmeno l'archivio: 3-6 secondi con le scansioni"
            " attive (e oltre i 120 secondi del proxy sotto il carico di un browser,"
            " cioe' 504 Gateway Timeout), 0,46-0,73 secondi con le scansioni sospese."
            " Ora l'agente gira in un processo suo e l'interfaccia in un altro:"
            " misurati 0,22 s con le scansioni attive.",
            "TOLTO IL LUCCHETTO GLOBALE DELL'ARCHIVIO. Con SQLite un solo scrittore"
            " per volta era un obbligo del formato; con PostgreSQL ogni operazione ha"
            " gia' la propria transazione, e il database gestisce la concorrenza. Il"
            " lucchetto era sopravvissuto al porting e metteva in fila quarantatre"
            " operazioni -- scansioni, agente, controlli e interfaccia, uno per volta."
            " Resta solo dove serve davvero: l'importazione del vecchio archivio, che"
            " legge e scrive in due transazioni distinte.",
            "NMAP: SI RACCOGLIE CIO' CHE DICE, non solo cio' che produce. Un XML"
            " valido e vuoto non distingue \"l'host non ha risposto\" da \"non so come"
            " arrivarci\": la seconda nmap la scrive su stdout"
            " (\"failed to determine route to ...\") e il prodotto la buttava via."
            " Ora la riconosce, lo dice nel diario con la causa giusta e mette quei"
            " bersagli in attesa invece di riprenderli a ogni ciclo -- anche quando"
            " sono nodi gia' confermati, che ne erano esenti.",
            "L'ANNO DICHIARATO DALLE PAGINE WEB, per riconoscere le installazioni che"
            " nessuno aggiorna piu': copyright, meta, stringhe di build,"
            " `Last-Modified` e inizio di validita' del certificato. Si tiene l'anno"
            " piu' recente con la fonte e il frammento da cui viene, perche' un"
            " \"(c) 2014\" non dimostra che il software sia del 2014 -- dimostra che"
            " nessuno ha piu' toccato quella pagina dal 2014.",
            "IL BROWSER PUO' SALVARE LA PASSWORD dell'interfaccia: il modulo e' ora"
            " dichiarato come un accesso e porta un campo con il codice della sonda,"
            " in sola lettura. Prima non si poteva, ed era una difesa apparente -- il"
            " prezzo era una password lunga da ridigitare ogni volta.",
            "Chi apre l'interfaccia in chiaro sulla porta HTTPS viene rimandato invece"
            " che respinto con un \"400 Bad Request\" che non spiega nulla.",
            "Il proxy davanti alla sonda nativa non risponde piu' a intermittenza: il"
            " nome con cui raggiungeva la sonda era dichiarato due volte in /etc/hosts"
            " (uno IPv4 e uno IPv6 non instradabile) e nginx li usava a turno.",
        ],
    },
    {
        "version": "1.6.0",
        "date": "2026-09-12",
        "abstract": "Le letture web ricavano l'anno che una pagina dichiara di se',"
                    " per riconoscere le installazioni che nessuno aggiorna piu'. Il"
                    " gestore di password del browser puo' finalmente salvare le"
                    " credenziali di questa interfaccia. E un difetto del proxy la"
                    " faceva rispondere a intermittenza.",
        "changes": [
            "L'ANNO CHE LA PAGINA DICHIARA DI SE'. Durante la lettura web si"
            " raccolgono ora gli anni trovati su OGNI pagina visitata -- il copyright"
            " sta quasi sempre nel pie' di una pagina interna, e la radice di un"
            " apparato e' spesso un rimando vuoto -- piu' l'intestazione"
            " `Last-Modified` e l'inizio di validita' del certificato TLS. Si"
            " conserva l'anno piu' recente, la fonte e IL FRAMMENTO da cui viene.",
            "Che cosa se ne puo' concludere, detto qui perche' e' il punto in cui"
            " questo dato si puo' usare male: un \"(c) 2014\" non dimostra che il"
            " software sia del 2014, dimostra che nessuno ha piu' toccato quella"
            " pagina dal 2014. E' un limite INFERIORE all'eta', non una misura -- ed"
            " e' comunque il segnale piu' economico che esista su una rete reale: un"
            " apparato la cui interfaccia si ferma a dodici anni fa non riceve"
            " aggiornamenti, e quasi mai li riceve il firmware sotto.",
            "Quello che NON si conta: gli anni fuori da un intervallo credibile (un"
            " numero di serie non e' una data), quelli dentro script e fogli di stile"
            " (sono le date delle librerie, non dell'apparato) e un `Last-Modified`"
            " di oggi, che una pagina generata al volo scrive sempre -- crederci"
            " direbbe che ogni apparato e' nuovo. Dove non c'e' nessuna prova non si"
            " scrive niente: una pagina che non dichiara un anno non e' \"nuova\".",
            "IL BROWSER PUO' SALVARE LA PASSWORD di questa interfaccia. Prima non"
            " poteva, per due motivi: il modulo dichiarava `autocomplete=\"off\"`, e"
            " non aveva un campo utente -- un modulo con la sola password non viene"
            " salvato dalla maggior parte dei gestori, e quando lo e' finisce senza"
            " identita'. Ora c'e' un campo in sola lettura con il codice della sonda:"
            " dice A QUALE sonda ci si sta collegando, e da' al gestore un nome sotto"
            " cui archiviare.",
            "Il divieto di salvataggio era una difesa apparente: chi ha accesso al"
            " browser di chi amministra la sonda ha gia' vinto, e il prezzo era una"
            " password lunga da ridigitare a ogni accesso -- cioe' l'incentivo a"
            " sceglierne una corta.",
            "Chi apre l'interfaccia in chiaro sulla porta HTTPS viene RIMANDATO invece"
            " che respinto con un \"400 Bad Request\" che non spiega nulla. Capita a"
            " tutti: davanti a una porta non standard come la 5510 il browser assume"
            " http://.",
            "CORRETTO UN DIFETTO DEL PROXY che faceva rispondere l'interfaccia A"
            " INTERMITTENZA -- il guasto peggiore, perche' una prova andata bene"
            " sembra una conferma. Il nome con cui il proxy raggiunge la sonda era"
            " dichiarato due volte in /etc/hosts (uno IPv4 messo da Docker, uno IPv6"
            " aggiunto dal compose), nginx li usava a turno e una richiesta su due"
            " finiva su un indirizzo non instradabile. Un nome, un indirizzo.",
            "Dove sta la sonda lo dice ora una variabile del modello di nginx e non"
            " piu' `extra_hosts`: Docker rifiuta `extra_hosts` insieme a"
            " `network_mode: service:` -- la variante per Docker Desktop -- con un"
            " errore che arriva solo all'avvio del contenitore e non da"
            " `docker compose config`. Resta una sola configurazione di nginx per"
            " tutte le varianti.",
        ],
    },
    {
        "version": "1.5.0",
        "date": "2026-09-10",
        "abstract": "La sonda non usa piu' SQLite: l'archivio e' PostgreSQL, e i dati"
                    " del vecchio archivio -- registrazione compresa -- si importano"
                    " da soli al primo avvio. Il motore di scansione passa a due fasi:"
                    " chi risponde, e poi una raffica di nmap su ciascun nodo.",
        "changes": [
            "ARCHIVIO SU POSTGRESQL. Era un file SQLite nel volume, con un lucchetto"
            " che metteva in fila i trentadue thread di scansione: il parallelismo si"
            " fermava all'archivio. E un file che si corrompe, su una coda di"
            " conferimento che deve sopravvivere a giorni di server irraggiungibile,"
            " e' la perdita di tutto il raccolto. Due utenze come sul server: il"
            " proprietario crea lo schema, l'applicativo scrive i dati e non puo'"
            " cambiare la struttura.",
            "I dati del vecchio archivio si importano al primo avvio: registrazione,"
            " coda, nodi e stato delle fasi. Su un'installazione reale sono state"
            " importate 80.057 righe, fra cui 79.000 nodi e la registrazione -- senza"
            " la quale la sonda andrebbe registrata di nuovo a mano. Il file resta"
            " come copia, rinominato, e non viene piu' guardato.",
            "MOTORE A DUE FASI. Prima la ricognizione dice chi risponde, poi ogni"
            " nodo ha un processo nmap dedicato con `-A` (versioni, sistema"
            " operativo, traceroute) e un catalogo di 29 script scelti per famiglia"
            " di servizio. Fino a trentadue processi insieme.",
            "Il motivo del cambio, misurato: un host per processo si esamina in 3,3"
            " secondi con tutte le porte trovate; 256 host in un processo solo hanno"
            " dato ZERO porte su 256; oltre 500 il processo non finiva entro le due"
            " ore del tetto. Il budget di pacchetti di nmap e' per PROCESSO, e"
            " dividerlo fra molti host fa passare per filtrate le porte vere. Il"
            " parallelismo si e' spostato nel pool, dove nmap non lo penalizza.",
            "Gli script si forzano con il prefisso `+` anche dove nmap non riconosce"
            " il servizio atteso: questo prodotto trova interfacce web sulla 7070 e"
            " sulla 8443 e agenti su porte spostate, e senza il `+` gli script non"
            " partirebbero proprio dove servono. Lo user-agent e' dichiarato: nei log"
            " del cliente si deve leggere chi ha fatto la richiesta.",
            "Le categorie NSE brute, dos, exploit, fuzzer e intrusive sono VIETATE nel"
            " codice, con un test che le cerca in tutte le fasi. Su una rete di"
            " produzione un blocco di account o un servizio interrotto da uno"
            " strumento di inventario e' un incidente, non una scansione. Rifiutati"
            " anche gli script che interrogano servizi esterni (vulners, whois,"
            " shodan): manderebbero fuori l'inventario dei servizi del cliente.",
            "NESSUN NODO SI SCARTA SULLA PAROLA DI UNA SOLA PASSATA DI GRUPPO. Prima"
            " di scartarlo lo si riesamina DA SOLO: costa tre secondi. Misurato in"
            " esercizio, un firewall con la 53 aperta era stato scartato come \"nessuna"
            " informazione\" mentre lo stesso nmap lo trovava in 3,3 secondi. Se la"
            " verifica non si puo' fare, il nodo NON si scarta: perdere un apparato"
            " vero e' un'affermazione falsa, e nessuno se ne accorge perche' non si"
            " vede cio' che non c'e'. I nodi gia' persi vengono recuperati.",
            "UN NOME DI SCRIPT SBAGLIATO NON FERMA PIU' UNA FASE. Il catalogo della"
            " raffica elencava `ipp-info` e `pgsql-info`: nessuno dei due esiste in"
            " nmap 7.99, e la conseguenza non era che quei due script non partivano"
            " -- nmap non partiva affatto (\"did not match a category, filename, or"
            " directory\" e QUITTING!). Il diario diceva \"0 host, 0 record in 3,9 s\""
            " per ogni bersaglio: una fase che finiva presto e non trovava nulla,"
            " senza dire perche'. I due nomi sono corretti (`cups-info` per le"
            " stampanti; per PostgreSQL la versione la da' `-sV`), ma soprattutto il"
            " catalogo viene ora confrontato con l'indice degli script dell'nmap"
            " installato (`script.db`): cio' che quell'nmap non conosce viene"
            " escluso e scritto nel diario. Serve anche in condizioni normali --"
            " le versioni di nmap non hanno tutte gli stessi script, e una sonda"
            " lasciata in sede puo' averne una piu' vecchia.",
            "LA RAFFICA AFFAMAVA L'ARRICCHIMENTO, e il difetto era invisibile."
            " Un nodo risultava in attesa della raffica finche' \"raffica\" non"
            " compariva fra le sue fasi svolte -- e non compare mai su un nodo"
            " profilato per un'altra via, o IMPORTATO dal vecchio archivio, cioe'"
            " su un'installazione reale tutti. La raffica li ripigliava a ogni ciclo"
            " e, occupando un posto per nodo, riempiva tutto: nel diario dieci \"Fase"
            " raffica\" per ciclo su nodi gia' completi e UNA sola fase di"
            " arricchimento. SNMP, SMB, ricerca di vulnerabilita' e letture web non"
            " arrivavano quasi mai al proprio turno: funzioni configurate che non"
            " producevano. Il criterio ora e' quello giusto -- non \"ha fatto la"
            " raffica\" ma \"le fasi che la raffica svolge sono svolte\".",
            "I TETTI DI TEMPO DELLA RAFFICA erano sotto il costo reale: 240 s per host"
            " e 420 s per processo, contro i 432 s misurati su un host vero (sette"
            " porte aperte, Apache e TLS, catalogo completo). nmap scriveva \"Skipping"
            " host due to host timeout\" e buttava anche il lavoro gia' fatto: zero"
            " record dopo quattro minuti di rete. Ora 600 s e 900 s, e un test"
            " verifica che il tetto del processo stia SOPRA quello per host --"
            " altrimenti il processo muore prima e si perde l'XML, cioe' tutto.",
            "Regola che nasce da questi tre difetti insieme (nomi di script"
            " inesistenti, tetti troppo bassi, raffica che si ripiglia): una fase che"
            " finisce sistematicamente in pochi secondi con zero record non e' una"
            " fase veloce, e' una fase che non ha funzionato. Il diario diceva quanti"
            " compiti, non quanto dato.",
            "AVVIO DEDICATO ALLA PRIMA PASSWORD (`start-nativa.ps1"
            " -PrimaPassword`), perche' due decisioni giuste insieme non stavano in"
            " piedi. Col proxy TLS davanti il cookie di sessione si marca `Secure`"
            " -- ed e' giusto: senza, una richiesta verso la porta del solo rimando"
            " a HTTPS porterebbe il cookie in chiaro sulla rete. Ma la prima password"
            " si sceglie sul loopback IN CHIARO, perche' il proxy non puo'"
            " distinguere chi sta alla postazione da chi arriva dalla LAN. Un cookie"
            " Secure non viene rimandato su HTTP: senza cookie non c'e' sessione,"
            " senza sessione il token anti-CSRF viene rifiutato, e il gestore"
            " dell'errore RIMANDA ALLA PAGINA con un avviso -- cioe' il guasto"
            " somigliava a un successo, e l'esito era un ciclo di \"token scaduto\"."
            " L'interruttore toglie il solo `Secure` per il tempo della prima"
            " impostazione; il token anti-CSRF resta, perche' su quella pagina e'"
            " cio' che impedisce a un sito qualunque, aperto in un'altra scheda, di"
            " impossessarsi della sonda.",
            "Nuovo comando `forget`: la sonda dimentica i nodi noti e lo stato delle"
            " fasi, e la raccolta riparte dalla scoperta. Lo manda il server quando"
            " azzera le informazioni raccolte di un tenant. La coda non si tocca --"
            " cio' che e' in attesa e' stato raccolto e va consegnato -- e nemmeno"
            " la registrazione.",
            "SCOPERTA RIFIUTATA QUANDO NON E' CREDIBILE. Su una /24 questo prodotto"
            " dichiarava 256 nodi attivi su 256 indirizzi possibili, mentre lo stesso"
            " `nmap -sn` dal PC dell'operatore ne trovava 5. La causa era la rete del"
            " contenitore: su Docker Desktop il NAT della macchina virtuale risponde"
            " PER OGNI INDIRIZZO, compresi quello di rete e quello di broadcast, dove"
            " un host non puo' esistere. Ora quei due segnali insieme -- indirizzi"
            " impossibili che rispondono e quasi tutto il segmento attivo -- fermano la"
            " scoperta: nessun nodo registrato e il motivo nel diario. Un inventario"
            " inventato e' peggio di un inventario vuoto: 251 nodi falsi con porte e"
            " classificazioni sembrano lavoro fatto, e portano a decisioni sbagliate"
            " su una rete vera.",
            "L'INTERFACCIA DI USCITA SI PUO' DICHIARARE, invece di lasciarla scegliere"
            " a nmap. nmap la prende dalla tabella di instradamento del sistema, e la"
            " tabella puo' essere sbagliata: misurato su una macchina d'ufficio con"
            " nove interfacce, la rotta predefinita con la metrica migliore era quella"
            " di un adattatore Wi-Fi SPENTO (metrica 40) invece della LAN attiva"
            " (metrica 55). Tutto cio' che non stava sulla rete locale usciva da"
            " un'interfaccia morta, e l'esito era incoerente senza che nulla lo"
            " dicesse. Con `SNAP_PROBE_SCAN_INTERFACE` e `SNAP_PROBE_SCAN_SOURCE_IP`"
            " la scelta e' dichiarata; il nome viene accettato solo se corrisponde a"
            " una forma valida, perche' finisce sulla riga di comando di un processo."
            " Vale con i socket raw: una scansione per connessione passa dallo stack"
            " del sistema, che non accetta quelle opzioni.",
            "SONDA FUORI DAL CONTENITORE su Windows, CON IL TLS DAVANTI. Dove un"
            " contenitore non vede la LAN, la sonda si avvia sulla macchina"
            " (`start-nativa.ps1`) e in contenitore resta la sola base dati. La sonda"
            " ascolta in chiaro SOLO sul proprio loopback e davanti le sta lo stesso"
            " nginx dell'esercizio, che termina il TLS sulla 5510: dalla rete non"
            " passa nulla in chiaro, password compresa. Che un contenitore raggiunga"
            " un servizio legato al solo loopback dell'host non era ovvio, ed e' stato"
            " misurato. La prima impostazione della password NON passa dal proxy --"
            " la' ogni richiesta arriverebbe dall'indirizzo del gateway di Docker e un"
            " permesso su quell'indirizzo aprirebbe la sonda a tutta la rete: si fa"
            " dal loopback della macchina, dove l'indirizzo del client e' quello vero.",
            "La console della sonda viaggia col battito: il server la mostra senza"
            " poter raggiungere la sonda. Perimetro e stato delle fasi non tornano"
            " indietro -- li ha mandati il server -- e l'istantanea sta in pochi"
            " kilobyte.",
        ],
    },
    {
        "version": "1.4.0",
        "date": "2026-09-10",
        "abstract": "Le reti dichiarate senza fili hanno una ricognizione propria, in"
                    " un thread a parte: chiede solo chi risponde, ogni due minuti, e"
                    " chi compare passa in testa alla coda dell'esame delle porte.",
        "changes": [
            "Ricognizione delle presenze sulle reti senza fili: una passata breve ogni"
            " due minuti sulle sole subnet dichiarate tali dalla console. Non esamina"
            " porte e non rileva sistemi -- chiede soltanto chi risponde -- e per"
            " questo sta in un thread proprio: una passata di porte dura minuti, e"
            " condividendo il thread la ricognizione arriverebbe sempre dopo, cioe'"
            " quando l'apparato comparso e' gia' andato via.",
            "Un apparato mai visto prima passa in TESTA alla coda dell'esame delle"
            " porte, e il ciclo si sveglia subito. Il ciclo dedica un compito per giro"
            " a quella coda: su un perimetro grande, senza la precedenza un telefono"
            " verrebbe esaminato quando non c'e' piu'.",
            "Il tempo per host della ricognizione e' generoso (3 secondi) e non"
            " aggressivo: un apparato radio in risparmio energetico risponde in"
            " 150-2000 millisecondi, e un tempo breve perderebbe proprio gli apparati"
            " che questa ricognizione esiste per trovare.",
            "Nella pagina della sonda, riquadro \"Presenze sulle reti senza fili\":"
            " reti osservate, esito dell'ultima passata, quanti apparati attendono"
            " l'esame prioritario. Compare solo se una rete e' stata dichiarata.",
            "Il nome che un apparato mostra di se' in rete (friendlyName UPnP) entra"
            " fra i fatti dichiarati.",
            "Corrette due etichette della pagina di configurazione che non"
            " corrispondevano piu' al motore: lo sforzo diceva \"4 thread\" dove i"
            " profili sono 1/16/32 (ora le etichette vengono dai profili e non possono"
            " divergere), e il tempo per host non diceva la cosa piu' importante --"
            " che la fase delle porte non lo usa piu', perche' il suo tetto e' sul"
            " processo e calcolato sulle sonde da inviare.",
        ],
    },
    {
        "version": "1.3.1",
        "date": "2026-09-10",
        "abstract": "La lettura delle pagine web arriva anche dove non c'e'"
                    " niente da seguire: un 401 nudo o una pagina di accesso senza"
                    " collegamenti. E di ogni interfaccia si ricava un'impronta, che"
                    " serve alla console per riconoscere gli apparati identici.",
        "changes": [
            "Percorsi identificanti generici: se l'apparato non ha detto niente di"
            " se' e nessuna firma ha corrisposto, si prova la descrizione UPnP (che"
            " per costruzione si legge senza credenziali e dichiara costruttore,"
            " modello e numero di serie) e alcuni indirizzi informativi documentati."
            " Misurato prima: su 25 nodi letti, tutti si fermavano alla prima"
            " pagina.",
            "Nessuno spreco su chi non risponde in modo utile: non si prova nulla se"
            " l'apparato e' gia' identificato anche solo dal titolo, e si smette al"
            " primo segno che serve la stessa pagina per qualunque indirizzo. Un 404,"
            " al contrario, e' una buona notizia: l'apparato distingue gli"
            " indirizzi.",
            "Impronta dell'icona e impronta dell'insieme delle intestazioni HTTP,"
            " conferite alla console: sono cio' che identifica un apparato quando il"
            " testo non dice nulla. Si conferisce l'impronta dell'icona, non"
            " l'immagine, e dei nomi delle intestazioni, non dei valori.",
            "Il nome che un apparato mostra di se' in rete (friendlyName UPnP) entra"
            " fra i fatti dichiarati.",
            "Alcuni prodotti si annunciano nel NOME di un'intestazione e in nessun altro"
            " posto: un server che ha nascosto `Server` manda ancora"
            " `X-AspNet-Version`, SharePoint manda `MicrosoftSharePointTeamServices`,"
            " Jenkins manda `X-Jenkins`. Ora si riconoscono anche cosi'.",
        ],
    },
    {
        "version": "1.3.0",
        "date": "2026-09-10",
        "abstract": "Il motore di scansione e' riprogettato: una /24 completa passa da"
                    " MAI a circa sette minuti. La sonda legge i MAC e la porta fisica"
                    " dagli apparati di rete, e trova da se' gli apparati SNMP da"
                    " interrogare.",
        "changes": [
            "Motore di scansione riprogettato. Il difetto non era un parametro mal"
            " tarato: era l'assunzione che gli host di un gruppo si scansionino in"
            " parallelo senza costo. Il ritmo di invio di nmap e' PER PROCESSO, quindi"
            " ventiquattro host costano ventiquattro volte uno -- e con un tetto di"
            " tempo per host venivano abbandonati TUTTI. Sul campo: 66 abbandoni di"
            " fila sugli stessi indirizzi, ondate da 257 secondi che restituivano zero"
            " host, per ore.",
            "La fase delle porte usa ora UN processo per tutti gli host, che nmap"
            " lavora a gruppi di 64, e NON riceve piu' un tetto di tempo per host: in"
            " quella struttura non proteggeva da nulla e causava il difetto. Al suo"
            " posto un tetto sul processo, calcolato dal lavoro richiesto (sonde da"
            " inviare diviso il ritmo misurato).",
            "Due livelli di esame delle porte: ogni ciclo ventotto porte che dicono"
            " CHE COS'E' un apparato, su tutti gli host; a cadenza lunga 232 porte"
            " scelte per famiglia di apparato, sui soli host che hanno mostrato un"
            " segnale. Su una rete reale 142 indirizzi su 256 non hanno alcuna porta"
            " aperta: chiederne mille a tutti costava oltre quattro ore per non"
            " imparare nulla.",
            "Un host che nmap non riesce a esaminare non blocca piu' la coda: resta"
            " candidato -- ignoto, non assente -- e si riprova con un'attesa che"
            " raddoppia a ogni abbandono, fino a un giorno. Prima rientrava in ogni"
            " ciclo e la scansione non finiva.",
            "Indirizzi MAC dalle tabelle ARP degli apparati di rete, lette in SNMP:"
            " e' l'unico modo di avere il MAC dei nodi su subnet instradate, perche'"
            " ARP non attraversa un router. Su una rete reale, di 7.309 nodi solo 39"
            " avevano il MAC -- tutti nella subnet della sonda.",
            "Porta fisica di attacco: dove la catena di tabelle dell'apparato e'"
            " completa, si sa su quale porta di quale switch un nodo e' attaccato. Se"
            " la catena si interrompe la porta non si indovina: resta non nota.",
            "Gli apparati SNMP si trovano da se': tutti gli host vivi vengono"
            " interrogati con una richiesta SNMP diretta (otto secondi per una /24, in"
            " parallelo) invece di sondare la porta 161 in UDP, che non distingue"
            " \"aperta\" da \"nessuna risposta\". Entra fra quelli interrogati solo chi"
            " risponde E ha una tabella ARP non vuota.",
            "Il costruttore della scheda di rete si ricava dal prefisso del MAC anche"
            " per i MAC riferiti da un apparato, con lo stesso catalogo che usa nmap:"
            " su un apparato muto e' spesso l'unico indizio su che cosa sia.",
            "La community SNMP resta locale alla sonda: non viene mai conferita al"
            " server, non compare nel diario e non torna nelle pagine -- la"
            " configurazione mostra soltanto SE e' impostata.",
        ],
    },
    {
        "version": "1.2.9",
        "date": "2026-09-09",
        "abstract": "La sonda si distribuisce in container con TLS sull'interfaccia,"
                    " verifica il certificato del server e non scarta piu' un apparato"
                    " per un limite di tempo nostro. La numerazione e' ora quella del"
                    " prodotto, la stessa della console.",
        "changes": [
            "Distribuzione in container: interfaccia in HTTPS, utente non privilegiato,"
            " nessuna capacita' del kernel oltre alle due che servono a scansionare,"
            " base dati PostgreSQL predisposta e script di avvio e arresto.",
            "Scansione SYN e rilevamento del sistema operativo funzionano nel container"
            " SENZA privilegi di amministratore: le capacita' sono concesse al solo"
            " nmap, non al processo che lo avvia.",
            "Il canale verso il server verifica il certificato e si puo' dichiarare di"
            " quale certificato fidarsi (CA interna, o il certificato del server se"
            " autofirmato). Se manca, il messaggio dice cosa fare invece di riportare"
            " l'errore della libreria. La verifica non si puo' disattivare: su quel"
            " canale passano le chiavi della registrazione.",
            "Un apparato che nmap abbandona per scadenza NON viene piu' scartato, per"
            " quante volte scada: non essendo stato esaminato e' ignoto, non assente."
            " Scartarlo lo faceva sparire dall'inventario per un limite di tempo"
            " nostro.",
            "Il tempo minimo per host delle fasi di rilevazione torna al valore misurato"
            " come funzionante: sotto quella soglia la fase gira senza produrre nulla e"
            " il profilo non avanza comunque.",
            "Il tempo massimo di una scansione si calcola sulle ondate che nmap esegue"
            " davvero (host in parallelo entro il gruppo) e non sul numero di bersagli:"
            " un compito non puo' piu' restare appeso per ore bloccando il ciclo.",
            "Il menu ha lo stesso marchio della console -- logo, nome e badge della"
            " versione -- e il badge apre queste note.",
        ],
    },
    {
        "version": "1.0.0",
        "date": "2026-08-26",
        "abstract": "Prima versione della sonda: scoperta e profilazione della rete con"
                    " nmap, canale cifrato verso la console, interfaccia locale per la"
                    " registrazione e la configurazione.",
        "changes": [
            "Motore di scansione a fasi (scoperta, porte, servizi, sistema operativo,"
            " approfondimento, SNMP, SMB, vulnerabilita', pagine di gestione).",
            "Canale SNAP-SEC/1 verso la console: registrazione con pacchetto, conferimento"
            " dei lotti, presenza e comandi. Tutte le connessioni partono dalla sonda.",
            "Archivio locale come coda di conferimento: la sonda continua a raccogliere"
            " anche con la console irraggiungibile.",
            "Interfaccia locale protetta da password, con la prima impostazione ammessa"
            " solo dalla postazione della sonda.",
        ],
    },
]


def voci() -> list:
    """Le voci del changelog, dalla piu' recente. Copia difensiva: chi la riceve
    non deve poter modificare il catalogo."""
    return [dict(v, changes=list(v["changes"])) for v in CHANGELOG]
