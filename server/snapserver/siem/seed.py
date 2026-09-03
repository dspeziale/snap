# -----------------------------------------------------------------
# seed.py — catalogo delle regole di rilevazione SIEM predefinite
# Autore: Daniele Speziale
# Data creazione: 2026-09-02
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Le regole di rilevazione con cui un tenant parte.

Sono soglie su finestre temporali, scelte perche' rispondono a domande concrete
di sicurezza ("qualcuno sta provando le password?", "una configurazione e' stata
toccata?", "un apparato critico e' guasto?"). Restano modificabili: la soglia
giusta dipende dalla rete, e chi la conosce e' l'operatore.

La semina AGGIUNGE le regole del catalogo che un tenant non ha ancora, riconosciute
per codice: cosi' un aggiornamento del prodotto porta le regole nuove anche ai
tenant esistenti, senza toccare quelle che l'operatore ha modificato.
"""

from __future__ import annotations

# code, name, event_kind, group_by, threshold, window_seconds, severity,
# min_severity, technique_id, descrizione
# min_severity "" = qualunque gravita'; una gravita' = "conta solo se almeno cosi' grave".
REGOLE = [
    ("bruteforce_ip", "Forza bruta su un indirizzo",
     "auth_failure", "src_ip", 10, 300, "high", "", "T1110",
     "Molti accessi falliti dalla stessa origine in pochi minuti: qualcuno prova le"
     " password."),
    ("bruteforce_user", "Forza bruta su un'utenza",
     "auth_failure", "username", 10, 300, "high", "", "T1110",
     "Molti accessi falliti sulla stessa utenza: attacco mirato o password scaduta"
     " non aggiornata."),
    ("account_lockout", "Utenze bloccate a raffica",
     "auth_lockout", "host", 3, 600, "medium", "", "T1110",
     "Piu' utenze bloccate sullo stesso host: forza bruta in corso o guasto di un"
     " servizio che si autentica."),
    ("spray_da_ip", "Password spraying da un indirizzo",
     "auth_failure", "src_ip", 30, 900, "high", "", "T1110.003",
     "Molti fallimenti su utenze diverse dalla stessa origine: si prova una password"
     " comune su tutti."),
    ("config_change", "Configurazioni modificate a raffica",
     "config_change", "host", 5, 600, "medium", "", "T1562",
     "Molte modifiche di configurazione in poco tempo: cambiamento legittimo o"
     " manomissione delle difese."),
    ("log_cleared", "Registro eventi cancellato",
     "log_cleared", "host", 1, 300, "high", "", "T1070.001",
     "La cancellazione di un registro di sicurezza e' un classico occultamento delle"
     " tracce: va sempre guardata."),
    ("priv_user_change", "Utenze privilegiate modificate",
     "user_change", "host", 3, 900, "medium", "", "T1098",
     "Creazioni o modifiche di utenze in serie: attenzione se non corrispondono a un"
     " intervento pianificato."),
    ("malware_segnalato", "Malware segnalato dagli apparati",
     "malware", "host", 1, 300, "critical", "", "T1204",
     "Un apparato di sicurezza ha segnalato una minaccia: da verificare subito."),
    ("scan_conn_denied", "Scansione: molte connessioni negate",
     "conn_denied", "src_ip", 50, 300, "medium", "", "T1046",
     "Molte connessioni negate dalla stessa origine: scansione delle porte in corso."),
    # Allarmi di apparato (centralino MX-ONE e simili). Uno CRITICO (severity 4) si
    # apre da solo, subito: soglia 1 filtrata sulla gravita' critica.
    ("equipment_alarm_critico", "Apparato: allarme critico",
     "equipment_alarm", "host", 1, 300, "critical", "critical", "",
     "Un allarme di apparato di gravita' critica va aperto e gestito subito: non si"
     " aspetta che se ne accumulino altri."),
    ("equipment_alarm_raffica", "Apparato: allarmi hardware a raffica",
     "equipment_alarm", "host", 3, 900, "medium", "", "",
     "Piu' allarmi non critici dallo stesso apparato in pochi minuti: un elemento in"
     " sofferenza che conviene guardare prima che diventi un guasto."),
]

_INSERISCI = (
    "INSERT INTO siem_rules (tenant_id, code, name, description, event_kind, group_by,"
    " threshold, window_seconds, severity, min_severity, technique_id, is_enabled,"
    " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)")


def _valori(tenant_id, regola, adesso):
    (code, name, kind, group_by, soglia, finestra, gravita, gravita_min, tecnica,
     descrizione) = regola
    return (tenant_id, code, name, descrizione, kind, group_by, soglia, finestra,
            gravita, gravita_min or None, tecnica or None, adesso, adesso)


def semina_se_serve(tenant_id: int) -> int:
    """Aggiunge al tenant le regole del catalogo che non ha ancora (per codice).

    Usa le funzioni di richiesta (`query`/`execute`): serve alla creazione di un
    tenant dall'interfaccia. Idempotente: le regole gia' presenti non si toccano.
    """
    from ..db import execute, query, utc_now_str

    presenti = {r["code"] for r in query(
        "SELECT code FROM siem_rules WHERE tenant_id = ?", (tenant_id,))}
    adesso = utc_now_str()
    nuove = 0
    for regola in REGOLE:
        if regola[0] in presenti:
            continue
        execute(_INSERISCI, _valori(tenant_id, regola, adesso))
        nuove += 1
    return nuove


def semina_regole(connection, adesso: str) -> int:
    """Aggiunge a ogni tenant le regole del catalogo mancanti (per codice).

    Scrive con la connessione in corso, come `_semina_zone`: qui non c'e' un
    contesto di richiesta e l'inizializzazione dello schema non deve dipendere dal
    resto dell'applicazione. Idempotente e adatta all'evoluzione del catalogo: un
    aggiornamento porta le regole nuove anche ai tenant gia' esistenti.
    """
    tenant = [r[0] for r in connection.execute("SELECT id FROM tenants").fetchall()]
    if not tenant:
        return 0
    aggiunte = 0
    for tenant_id in tenant:
        presenti = {r[0] for r in connection.execute(
            "SELECT code FROM siem_rules WHERE tenant_id = ?", (tenant_id,)).fetchall()}
        for regola in REGOLE:
            if regola[0] in presenti:
                continue
            connection.execute(_INSERISCI, _valori(tenant_id, regola, adesso))
            aggiunte += 1
    return aggiunte
