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
"""

from __future__ import annotations

# Ogni voce: version, date (YYYY-MM-DD), abstract (1-2 frasi), changes (elenco).
CHANGELOG = [
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
