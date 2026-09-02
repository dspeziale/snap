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
toccata?", "un registro eventi e' stato cancellato?"). Restano modificabili: la
soglia giusta dipende dalla rete, e chi la conosce e' l'operatore.

Le tecniche ATT&CK citate legano l'allarme al linguaggio gia' usato dalla threat
intelligence, cosi' rilevazione e intelligence parlano la stessa lingua.
"""

from __future__ import annotations

# code, name, event_kind, group_by, threshold, window_seconds, severity, technique_id
REGOLE = [
    ("bruteforce_ip", "Forza bruta su un indirizzo",
     "auth_failure", "src_ip", 10, 300, "high", "T1110",
     "Molti accessi falliti dalla stessa origine in pochi minuti: qualcuno prova le"
     " password."),
    ("bruteforce_user", "Forza bruta su un'utenza",
     "auth_failure", "username", 10, 300, "high", "T1110",
     "Molti accessi falliti sulla stessa utenza: attacco mirato o password scaduta"
     " non aggiornata."),
    ("account_lockout", "Utenze bloccate a raffica",
     "auth_lockout", "host", 3, 600, "medium", "T1110",
     "Piu' utenze bloccate sullo stesso host: forza bruta in corso o guasto di un"
     " servizio che si autentica."),
    ("spray_da_ip", "Password spraying da un indirizzo",
     "auth_failure", "src_ip", 30, 900, "high", "T1110.003",
     "Molti fallimenti su utenze diverse dalla stessa origine: si prova una password"
     " comune su tutti."),
    ("config_change", "Configurazioni modificate a raffica",
     "config_change", "host", 5, 600, "medium", "T1562",
     "Molte modifiche di configurazione in poco tempo: cambiamento legittimo o"
     " manomissione delle difese."),
    ("log_cleared", "Registro eventi cancellato",
     "log_cleared", "host", 1, 300, "high", "T1070.001",
     "La cancellazione di un registro di sicurezza e' un classico occultamento delle"
     " tracce: va sempre guardata."),
    ("priv_user_change", "Utenze privilegiate modificate",
     "user_change", "host", 3, 900, "medium", "T1098",
     "Creazioni o modifiche di utenze in serie: attenzione se non corrispondono a un"
     " intervento pianificato."),
    ("malware_segnalato", "Malware segnalato dagli apparati",
     "malware", "host", 1, 300, "critical", "T1204",
     "Un apparato di sicurezza ha segnalato una minaccia: da verificare subito."),
    ("scan_conn_denied", "Scansione: molte connessioni negate",
     "conn_denied", "src_ip", 50, 300, "medium", "T1046",
     "Molte connessioni negate dalla stessa origine: scansione delle porte in corso."),
]


def semina_se_serve(tenant_id: int) -> int:
    """Semina le regole per un tenant solo se non ne ha ancora nessuna.

    Usa le funzioni di richiesta (`query`/`execute`): serve alla creazione di un
    tenant dall'interfaccia, dove un contesto applicativo c'e'. La semina in
    `init_db` copre invece i tenant gia' esistenti a ogni avvio.
    """
    from ..db import execute, query, utc_now_str

    quante = query("SELECT COUNT(*) AS n FROM siem_rules WHERE tenant_id = ?",
                   (tenant_id,), one=True)
    if quante and int(quante["n"] or 0) > 0:
        return 0
    adesso = utc_now_str()
    for (code, name, kind, group_by, soglia, finestra, gravita, tecnica,
         descrizione) in REGOLE:
        execute(
            "INSERT INTO siem_rules (tenant_id, code, name, description, event_kind,"
            " group_by, threshold, window_seconds, severity, technique_id, is_enabled,"
            " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
            (tenant_id, code, name, descrizione, kind, group_by, soglia, finestra,
             gravita, tecnica, adesso, adesso))
    return len(REGOLE)


def semina_regole(connection, adesso: str) -> int:
    """Copia il catalogo nelle regole dei tenant che non ne hanno ancora.

    Scrive con la connessione in corso, come `_semina_zone`: qui non c'e' un
    contesto di richiesta e l'inizializzazione dello schema non deve dipendere dal
    resto dell'applicazione.
    """
    tenant = [r[0] for r in connection.execute("SELECT id FROM tenants").fetchall()]
    if not tenant:
        return 0
    seminati = 0
    for tenant_id in tenant:
        quante = connection.execute(
            "SELECT COUNT(*) FROM siem_rules WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()[0]
        if quante:
            continue
        for (code, name, kind, group_by, soglia, finestra, gravita, tecnica,
             descrizione) in REGOLE:
            connection.execute(
                "INSERT INTO siem_rules (tenant_id, code, name, description, event_kind,"
                " group_by, threshold, window_seconds, severity, technique_id,"
                " is_enabled, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
                (tenant_id, code, name, descrizione, kind, group_by, soglia, finestra,
                 gravita, tecnica, adesso, adesso))
        seminati += 1
    return seminati
