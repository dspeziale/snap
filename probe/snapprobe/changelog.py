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
