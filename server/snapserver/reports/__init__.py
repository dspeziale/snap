"""
snap server - Report periodici e resoconto quotidiano.

Il pacchetto e' diviso per responsabilita', cosi' che aggiungere un report sia una
dichiarazione e non un programma nuovo:

    windows.py      finestre temporali nel fuso del tenant
    dataset.py      una funzione per sezione: riceve (tenant, finestra), torna dati
    render_mail.py  corpo del resoconto in testo e in HTML
    render_pdf.py   report NOC in PDF, cornice A4 e grafici con le primitive
    storage.py      archiviazione su disco, elenco e scaricamento
    daily.py        pianificatore autonomo e accodamento della spedizione

Il resoconto e' prodotto e spedito dal SERVER, senza intervento di nessuno: il
pianificatore vive nel processo dell'applicazione come il thread delle notifiche.

Specifica: docs/08_REPORT.md

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

# Generi di report previsti. Il valore e' anche la chiave con cui il report viene
# registrato e ritrovato: cambiarlo significa perdere la corrispondenza con lo storico.
KIND_DAILY = "daily"
KIND_NOC = "noc"
KIND_EXECUTIVE = "executive"
KIND_INVENTORY = "inventory"
KIND_SOC = "soc"
KIND_COMPLIANCE = "compliance"
KIND_THREAT = "threat"
KIND_SEGMENTATION = "segmentation"
KIND_HYGIENE = "hygiene"
KIND_DEVICE = "device"
KIND_INCIDENT = "incident"
KIND_EU_COMPLIANCE = "eu_compliance"

REPORT_KINDS = {
    KIND_DAILY: "Resoconto quotidiano",
    KIND_NOC: "Esercizio NOC",
    KIND_EXECUTIVE: "Sintesi esecutiva",
    KIND_INVENTORY: "Inventario e valutazione tecnica",
    KIND_SOC: "Postura di sicurezza (SOC)",
    KIND_THREAT: "Vulnerabilita' ed esposizioni",
    KIND_SEGMENTATION: "Segmentazione e zone di rete",
    KIND_HYGIENE: "Igiene dell'inventario",
    KIND_DEVICE: "Scheda dell'apparato",
    KIND_COMPLIANCE: "Fascicolo di conformita'",
    KIND_INCIDENT: "Rapporto di incidente",
    KIND_EU_COMPLIANCE: "Conformita' europea (NIS2, CRA, GDPR)",
}

# Ogni report ha un destinatario dichiarato e una domanda a cui risponde (RP-01): sono
# le due cose che l'operatore deve leggere per scegliere quale generare.
REPORT_CATALOG = {
    KIND_EXECUTIVE: {
        "destinatario": "Direzione, responsabile IT",
        "domanda": "Siamo coperti? Sta migliorando? Dove serve una decisione?",
        "periodo": 30,
        "periodi": (30, 90),
        "orizzontale": False,
        "ruolo": "tenant_admin",
    },
    KIND_INVENTORY: {
        "destinatario": "Sistemisti, rete",
        "domanda": "Che cosa c'e' in rete, con che cosa risponde, che cosa e' cambiato",
        "periodo": 30,
        "periodi": (7, 30, 90),
        "orizzontale": True,
        "ruolo": "analyst",
    },
    KIND_NOC: {
        "destinatario": "Turno operativo",
        "domanda": "Che disponibilita' abbiamo dato, che cosa e' instabile, che cosa e'"
                   " fermo",
        "periodo": 1,
        "periodi": (1, 7),
        "orizzontale": False,
        "ruolo": "analyst",
    },
    KIND_SOC: {
        "destinatario": "Sicurezza",
        "domanda": "Che superficie esponiamo, che cosa e' cambiato, che cosa va"
                   " investigato",
        "periodo": 7,
        "periodi": (7, 30),
        "orizzontale": False,
        "ruolo": "analyst",
    },
    KIND_THREAT: {
        "destinatario": "Sicurezza, sistemisti",
        "domanda": "Che vulnerabilita' abbiamo dimostrato, che cosa va accertato,"
                   " da quale dispositivo cominciare",
        "periodo": 30,
        "periodi": (7, 30, 90),
        "orizzontale": False,
        "ruolo": "analyst",
    },
    KIND_SEGMENTATION: {
        "destinatario": "Sicurezza, architetti di rete",
        "domanda": "La segmentazione dichiarata regge? Che cosa e' raggiungibile dove"
                   " non dovrebbe",
        "periodo": 30,
        "periodi": (7, 30, 90),
        "orizzontale": False,
        "ruolo": "analyst",
    },
    KIND_HYGIENE: {
        "destinatario": "Chi gestisce il prodotto, sistemisti",
        "domanda": "Che cosa manca per fidarsi dei numeri, e che cosa fare per"
                   " migliorarli",
        "periodo": 30,
        "periodi": (7, 30, 90),
        "orizzontale": False,
        "ruolo": "analyst",
    },
    KIND_EU_COMPLIANCE: {
        "destinatario": "Auditor, DPO, direzione, responsabile NIS2",
        "domanda": "Che cosa possiamo dimostrare di NIS2, CRA e GDPR, e che cosa no",
        "periodo": 90,
        "periodi": (30, 90, 365),
        "orizzontale": False,
        "ruolo": "tenant_admin",
    },
    KIND_COMPLIANCE: {
        "destinatario": "Auditor, DPO, direzione",
        "domanda": "Provate che i controlli esistono, funzionano e sono tracciati",
        "periodo": 90,
        "periodi": (30, 90, 365),
        "orizzontale": False,
        "ruolo": "tenant_admin",
    },
}

__all__ = ["KIND_EU_COMPLIANCE",
           "KIND_DAILY", "KIND_NOC", "KIND_EXECUTIVE", "KIND_INVENTORY", "KIND_SOC",
           "KIND_THREAT", "KIND_SEGMENTATION", "KIND_HYGIENE", "KIND_DEVICE",
           "KIND_COMPLIANCE", "KIND_INCIDENT", "REPORT_KINDS", "REPORT_CATALOG"]
