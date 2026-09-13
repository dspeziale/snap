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
Dalla 1.2.0 la sonda ha una numerazione PROPRIA, distinta da quella della console, e
dalla 1.2.2 avanza a due centesimi per rilascio:
le due parti si aggiornano in momenti diversi -- la sonda sta in sede dal cliente, la
console si aggiorna quando si vuole -- e un numero unico costringeva a inventare
versioni della sonda per cambiamenti che non la riguardavano. Le voci del periodo in cui
la sonda seguiva la versione del prodotto NON si conservano qui: confrontarle con i
numeri di oggi direbbe cose false, e un changelog che va letto con una tabella di
conversione non e' un changelog. La storia di quel periodo resta nel changelog della
console, dove quei numeri hanno ancora il significato con cui furono scritti.
"""

from __future__ import annotations

# Ogni voce: version, date (YYYY-MM-DD), abstract (1-2 frasi), changes (elenco).
CHANGELOG = [
    {
        "version": "1.3.4",
        "date": "2026-09-13",
        "abstract": "I pacchetti si possono GUARDARE. Una pagina nuova mostra che cosa"
                    " sta passando sul filo, chi parla con chi e quali nomi vengono"
                    " richiesti, con la ricerca dentro. Il sensore produceva"
                    " rilevazioni senza far vedere su che cosa lavorava.",
        "changes": [
            "PAGINA *PACCHETTI*, con tre modi di guardare la stessa finestra perche'"
            " sono tre domande diverse: i PACCHETTI dicono che cosa passa (con le"
            " bandiere TCP e l'ARP tradotto -- \"chi ha 10.20.10.41? lo chiede"
            " 10.20.10.1\"), le CONVERSAZIONI dicono chi sta parlando -- che e' quasi"
            " sempre la domanda vera -- e i NOMI dicono dove si sta andando. Si cerca"
            " per indirizzo, MAC o nome.",
            "SEMPRE SOLO I CAMPI, MAI I BYTE. Nell'archivio finisce cio' che si legge"
            " nell'intestazione piu' il nome dichiarato in chiaro: un test mette un"
            " segreto dentro un payload e lo cerca in tutto cio' che viene conservato.",
            "RITENZIONE STRETTA: venti minuti e ventimila pacchetti, i piu' recenti."
            " Serve a guardare che cosa sta succedendo adesso, non a tenere un"
            " registro di cio' che le persone fanno. Spegnendo l'osservazione la"
            " tabella si svuota del tutto: chi spegne si aspetta questo.",
            "TRE DIFETTI TROVATI GUARDANDO LA PAGINA con i pacchetti veri."
            " Centotrentasette righe con protocollo \"?\": erano i pacchetti della"
            " sonda stessa, che l'esclusione scartava PRIMA di decodificarli. Adesso"
            " la regola e' una sola -- il traffico della sonda si VEDE ma non diventa"
            " mai un fatto per le regole. E i nomi si leggono anche dalle RISPOSTE"
            " DNS: con dodici pacchetti DNS visti, la colonna dei nomi restava vuota.",
        ],
    },
    {
        "version": "1.3.2",
        "date": "2026-09-13",
        "abstract": "La sonda sa osservare il TRAFFICO. Legge le intestazioni dei"
                    " pacchetti e i nomi dichiarati in chiaro -- mai il contenuto --"
                    " e ne ricava nove regole nuove: avvelenamento ARP, DHCP abusivo,"
                    " avvelenamento dei nomi, scansioni interne, beaconing, tunnel"
                    " DNS. Nasce SPENTA e si accende dalla Configurazione.",
        "changes": [
            "NOVE REGOLE NUOVE dal filo, che portano il catalogo da dodici a ventuno."
            " Sono le uniche che vedono un attacco che non lascia traccia su nessun"
            " host: avvelenare una cache ARP non apre porte e non crea utenze.",
            "NESSUNA DIPENDENZA NUOVA. libpcap (Npcap su Windows) espone da vent'anni"
            " una C API stabile di cinque funzioni, e `ctypes` e' nella libreria"
            " standard: il collegamento sta in duecento righe. Scartate `scapy`"
            " (GPLv2 su un prodotto MIT) e `pypcap`/`pcapy-ng` (da compilare, cioe'"
            " una toolchain sulla macchina del cliente). Npcap di norma c'e' gia',"
            " perche' lo installa nmap.",
            "SI LEGGONO INTESTAZIONI E NOMI, MAI IL CONTENUTO. Si catturano 512 byte"
            " per pacchetto e se ne estraggono chi parla con chi, con che ritmo, e i"
            " nomi che i protocolli dichiarano in chiaro (DNS, SNI, Host HTTP):"
            " nell'archivio finiscono conteggi e fatti derivati, mai i byte. Un test"
            " mette un segreto dentro un payload e lo cerca in tutto il riassunto.",
            "SPENTA FINCHE' NON LA SI ACCENDE, dichiarando l'interfaccia. La pagina di"
            " Configurazione dice che cosa viene letto e che cosa no PRIMA"
            " dell'interruttore, e ricorda che su una rete di lavoro questo e' un"
            " trattamento di dati personali da mettere nel registro.",
            "LA SONDA NON SI DENUNCIA DA SOLA: scansiona per mestiere, e i suoi SYN"
            " verso mille indirizzi hanno la forma esatta di una scansione interna. I"
            " suoi indirizzi sono esclusi dall'osservazione. Per la stessa ragione il"
            " beaconing si segnala solo verso FUORI dal perimetro: dentro la rete"
            " tutto e' regolare -- monitoraggio, backup, la sonda stessa.",
            "Senza una porta mirror si vede il broadcast, e basta per gli attacchi di"
            " segmento: misurato su una rete vera, venti secondi bastano a vedere le"
            " schede di tutto il segmento, comprese quelle che a una scansione non"
            " rispondono.",
        ],
    },
    {
        "version": "1.3.0",
        "date": "2026-09-13",
        "abstract": "La pagina Agenti prepara un PACCHETTO DI INSTALLAZIONE pronto --"
                    " agente, installatori per Windows, Linux e Docker, istruzioni e"
                    " token gia' dentro -- e la sonda conserva l'inventario di ogni"
                    " macchina come stato, non come serie.",
        "changes": [
            "PACCHETTO DI INSTALLAZIONE. Un archivio da copiare sulla macchina e"
            " aprire: chi lo riceve esegue un comando solo. Dentro ci sono gli"
            " installatori per Windows (attivita' pianificata come SYSTEM), per Linux"
            " (unit systemd con utenza dedicata, oppure root con"
            " --privilegi-completi) e per Docker, piu' il LEGGIMI. Ogni installatore"
            " verifica che il servizio stia DAVVERO girando prima di dire fatto, e se"
            " non e' partito mostra il comando per vedere l'errore.",
            "IL PACCHETTO E' UNA CREDENZIALE, e la pagina lo dice: contiene un token"
            " valido un'ora e una volta sola, e gli installatori lo CANCELLANO dalla"
            " macchina appena speso. Un pacchetto vale per una macchina: dieci"
            " macchine, dieci pacchetti, dieci credenziali revocabili una per una.",
            "L'INVENTARIO E' UNO STATO. Le misure restano una serie e si accumulano;"
            " l'inventario della macchina -- software installato, servizi, utenze,"
            " postura, porte in ascolto -- si SOVRASCRIVE quando ne arriva uno nuovo."
            " Misurato su una macchina vera, tenerli insieme costava 99 MB al giorno"
            " per macchina per riscrivere 1.440 volte lo stesso elenco.",
            "SI CONFERISCE SOLO CIO' CHE E' CAMBIATO. Il record di ogni macchina"
            " ripartiva verso il server a ogni battito -- ogni quindici secondi,"
            " identico -- e con l'inventario dentro sarebbero stati 345 MB al giorno"
            " per una macchina sola. Una macchina registrata e mai avviata viene"
            " comunque conferita: altrimenti si sarebbe vista sulla sonda e non sulla"
            " console.",
            "L'AGENTE (1.2.2) LEGGE DUE COSE IN PIU' CON PRECISIONE. \"Nessun profilo"
            " firewall spento\" e' la notizia buona, e tornava come risposta vuota:"
            " la pagina la mostrava come \"non misurato\", e una macchina in ordine"
            " risultava non verificata. E l'avvio protetto rispondeva \"non"
            " applicabile\" sia su una macchina senza UEFI sia quando mancavano i"
            " privilegi -- due casi opposti sotto la stessa etichetta, e su una"
            " macchina UEFI con l'avvio protetto spento nessuno avrebbe guardato.",
            "La versione dell'agente si aggiorna a ogni invio e non solo alla"
            " registrazione: una macchina aggiornata continuava a risultare alla"
            " versione con cui era stata registrata mesi prima.",
        ],
    },
    {
        "version": "1.2.6",
        "date": "2026-09-13",
        "abstract": "La sonda riconosce le intrusioni e accoglie gli agenti di"
                    " macchina. Il motore gira QUI perche' la sonda e' l'unica a"
                    " contatto con la rete sorvegliata: rilevare sul server"
                    " significherebbe rilevare in ritardo, su dati gia' conferiti.",
        "changes": [
            "MOTORE DI RILEVAZIONE su osservazione, con dodici regole e tre sensori"
            " innestabili. Legge l'archivio locale che le passate di scansione hanno"
            " gia' riempito: non apre connessioni, non scansiona, non aggiunge carico"
            " sulla rete. Gira ogni cinque minuti dentro il ciclo principale.",
            "LA LINEA DI BASE decide tutto: una rilevazione non e' un fatto assoluto"
            " (\"la 3389 e' aperta\") ma un cambiamento (\"la 3389 e' aperta dove non"
            " c'era\"). Finche' la memoria di un soggetto e' piu' giovane di dodici"
            " ore il cambiamento si registra e non si segnala, e finche' l'INTERO"
            " archivio e' giovane le regole \"mai visto\" tacciono: senza questa"
            " seconda condizione la prima passata su una rete vera ha segnalato"
            " quattrocento nodi in un colpo, che e' il modo piu' rapido per far"
            " disattivare un IDS.",
            "CANALE PER GLI AGENTI DI MACCHINA (`/api/agent`). L'agente APRE verso la"
            " sonda e non riceve comandi: una macchina in rete di utenza non deve"
            " essere raggiungibile da nessuno, nemmeno dal prodotto che la sorveglia."
            " Registrazione con un token che vale una volta sola e scade in un'ora;"
            " ogni invio porta una firma HMAC-SHA256 sul corpo esatto, con identita',"
            " marca temporale e nonce -- non si puo' rigiocare altrove, ne' piu'"
            " tardi, ne' per conto di un altro.",
            "L'AGENTE (1.0.2) NON RIPETE CIO' CHE DURA. Un evento che descrive una"
            " condizione -- disco pieno, protezione ferma, accessi falliti -- si"
            " riferisce quando lo stato cambia di fascia e si riarma dopo sei ore."
            " Alla prima prova su una macchina vera erano arrivati centootto eventi"
            " \"disco quasi pieno\" identici in ventiquattr'ore: una riga nuova sarebbe"
            " finita sepolta. Mille volte lo stesso fatto e' un fatto che dura, non"
            " mille fatti. Se la condizione rientra, l'agente se ne dimentica subito:"
            " quando risale lo ridice senza aspettare il riarmo.",
            "Due pagine nuove nella console locale: *IDS* e *Agenti*. Si vedono anche"
            " quando il collegamento con la sede e' interrotto -- chi e' davanti alla"
            " sonda deve poter capire che cosa sta succedendo senza dipendere dalla"
            " rete geografica.",
            "LE TABELLE PROPRIE DELLA SONDA PORTANO IL PREFISSO `local_`, come"
            " `local_nodes` gia' faceva. Tre di quelle nuove si chiamavano come"
            " tabelle della console pur avendo colonne diverse: sonda e console hanno"
            " due basi dati e in esercizio non si incontrano, ma chi le mette sullo"
            " stesso PostgreSQL trova un \"CREATE TABLE IF NOT EXISTS\" che non crea"
            " niente e un indice che fallisce su una colonna inesistente -- un guasto"
            " che non somiglia alla propria causa. L'archivio gia' in esercizio si"
            " rinomina da se' al primo avvio, conservando i dati.",
            "LO STATO DELL'IDS VIAGGIA COL BATTITO: quando il motore ha girato, quali"
            " sensori hanno saltato il turno e da quanto esiste la memoria. Il server"
            " non puo' chiedere niente alla sonda, quindi cio' che non viaggia col"
            " battito per la console non esiste.",
        ],
    },
    {
        "version": "1.2.4",
        "date": "2026-09-13",
        "abstract": "L'avvio sulla macchina registra i propri processi, e l'arresto"
                    " li legge: senza, un agente vecchio poteva sopravvivere a due"
                    " tentativi di arresto e continuare a battere accanto a quello"
                    " nuovo.",
        "changes": [
            "I PROCESSI SI REGISTRANO ALL'AVVIO. `start-nativa.ps1` scrive i PID in"
            " `probe\\sonda-nativa.pid` e `stop-nativa.ps1` parte da li'. Prima"
            " l'arresto riconosceva i processi dalla sola riga di comando, che su"
            " Windows non e' sempre leggibile -- basta che il processo appartenga a"
            " una sessione chiusa -- e quelli che non vedeva restavano in vita. E'"
            " successo: un agente della versione precedente ha continuato a battere"
            " accanto a quello nuovo, e la versione dichiarata alla console"
            " oscillava fra le due a ogni battito. Due agenti sullo stesso archivio"
            " si contendono le prenotazioni dei bersagli.",
            "L'ARRESTO VERIFICA invece di fidarsi: se un processo sopravvive lo dice"
            " con il suo PID e spiega che va fermato da una finestra amministratore"
            " prima di riavviare. Un \"fatto\" stampato su un processo ancora vivo"
            " sarebbe peggio dell'errore.",
        ],
    },
    {
        "version": "1.2.2",
        "date": "2026-09-12",
        "abstract": "Numerazione a due centesimi: da questa versione ogni rilascio"
                    " della sonda avanza di due centesimi, come la console. Nessun"
                    " cambiamento di funzionamento rispetto alla 1.2.0.",
        "changes": [
            "NUMERAZIONE A DUE CENTESIMI (1.2.0 -> 1.2.2). La sonda conserva la"
            " propria numerazione, distinta da quella della console, e ne segue il"
            " passo: due centesimi per rilascio. Il protocollo fra le due parti non"
            " dipende da questi numeri -- lo governa la versione dell'agente"
            " dichiarata nel battito.",
        ],
    },
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
            "AVVIO SENZA FINESTRA (`start-nativa.ps1 -Nascosta`). La sonda e' un"
            " servizio, non un programma da guardare: una finestra aperta per giorni"
            " si chiude per sbaglio, e con lei si ferma la raccolta. Il diario va su"
            " file, e per fermarla c'e' `stop-nativa.ps1` -- che ferma prima l'agente"
            " e poi l'interfaccia, perche' all'inverso resterebbe un agente che"
            " continua a prenotare bersagli senza che nessuno possa vedere che cosa"
            " sta facendo.",
            "Il proxy davanti alla sonda nativa non risponde piu' a intermittenza: il"
            " nome con cui raggiungeva la sonda era dichiarato due volte in /etc/hosts"
            " (uno IPv4 e uno IPv6 non instradabile) e nginx li usava a turno.",
        ],
    },
]


def voci() -> list:
    """Le voci del changelog, dalla piu' recente. Copia difensiva: chi la riceve
    non deve poter modificare il catalogo."""
    return [dict(v, changes=list(v["changes"])) for v in CHANGELOG]
