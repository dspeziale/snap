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
