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
