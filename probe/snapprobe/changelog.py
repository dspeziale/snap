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
