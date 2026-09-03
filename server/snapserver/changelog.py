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
