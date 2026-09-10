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
