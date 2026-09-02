-- snap server - Schema relazionale SQLite.
--
-- remarks: Autore: Daniele Speziale - Data: 2026-08-26
-- copyright: (c) 2024-26 DS Consulting
-- license: MIT
--
-- Convenzioni:
--   * ogni colonna *_at contiene un timestamp UTC nel formato 'YYYY-MM-DD HH:MM:SS';
--     la conversione al fuso orario del tenant avviene solo in presentazione;
--   * ogni tabella di dominio porta tenant_id: l'isolamento multi-tenant e'
--     applicato in ogni query attraverso il layer di accesso (snapserver.db);
--   * i vincoli ON DELETE CASCADE garantiscono la rimozione completa dei dati
--     di un tenant (diritto alla cancellazione).

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- Anagrafica tenant
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    code            TEXT    NOT NULL UNIQUE,
    name            TEXT    NOT NULL,
    timezone        TEXT    NOT NULL DEFAULT 'Europe/Rome',
    locale          TEXT    NOT NULL DEFAULT 'it_IT',
    contact_email   TEXT,
    retention_days  INTEGER NOT NULL DEFAULT 365,
    is_active       INTEGER NOT NULL DEFAULT 1,
    notes           TEXT,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);

-- ---------------------------------------------------------------------------
-- Utenti (autenticazione con sola email + password, MFA TOTP opzionale)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id         INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
    email             TEXT    NOT NULL UNIQUE,
    password_hash     TEXT    NOT NULL,
    full_name         TEXT    NOT NULL DEFAULT '',
    role              TEXT    NOT NULL DEFAULT 'viewer',
    is_active         INTEGER NOT NULL DEFAULT 1,
    mfa_enabled       INTEGER NOT NULL DEFAULT 0,
    mfa_secret        TEXT,
    mfa_confirmed_at  TEXT,
    must_change_pwd   INTEGER NOT NULL DEFAULT 0,
    failed_logins     INTEGER NOT NULL DEFAULT 0,
    locked_until      TEXT,
    last_login_at     TEXT,
    pref_theme        TEXT    NOT NULL DEFAULT 'light',
    pref_font_size    TEXT    NOT NULL DEFAULT 'normal',
    pref_layout       TEXT    NOT NULL DEFAULT 'wide',
    -- Indicatori che l'utente ha scelto di non vedere: chiavi separate da
    -- virgola. Vuoto significa "mostrali tutti", che e' cio' che serve a chi
    -- apre il prodotto per la prima volta.
    pref_kpi_hidden   TEXT    NOT NULL DEFAULT '',
    created_at        TEXT    NOT NULL,
    updated_at        TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_users_tenant ON users(tenant_id);

-- ---------------------------------------------------------------------------
-- Sonde: il server non conosce l'indirizzo della sonda, solo la sua identita'
-- logica e il materiale crittografico. Ogni contatto e' iniziato dalla sonda.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS probes (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id             INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    probe_uid             TEXT    NOT NULL UNIQUE,
    code                  TEXT    NOT NULL,
    name                  TEXT    NOT NULL,
    description           TEXT,
    site                  TEXT,
    status                TEXT    NOT NULL DEFAULT 'pending',
    enrollment_token_hash TEXT,
    enrollment_key        TEXT,
    enrollment_expires_at TEXT,
    enrolled_at           TEXT,
    probe_public_key      TEXT,
    server_private_key    TEXT,
    server_public_key     TEXT,
    session_key           TEXT,
    api_key_hash          TEXT,
    agent_version         TEXT,
    last_seen_at          TEXT,
    last_sync_at          TEXT,
    scan_interval_sec     INTEGER NOT NULL DEFAULT 300,
    -- Interruttore della scansione, autoritativo: viaggia nella configurazione
    -- cifrata e la sonda lo rispetta senza poterlo aggirare.
    scan_enabled          INTEGER NOT NULL DEFAULT 1,
    -- Profilo di sforzo: min, med, max. Governa il parallelismo e la profondita'
    -- delle scansioni, cioe' il carico che si accetta sulla rete del cliente.
    scan_effort           TEXT    NOT NULL DEFAULT 'med',
    -- Tempo massimo per host: vuoto significa quello del profilo di sforzo.
    scan_host_timeout     TEXT,
    -- Ogni quanti giorni si ricensisce il perimetro con la scoperta.
    scan_discovery_days   INTEGER NOT NULL DEFAULT 3,
    config_json           TEXT    NOT NULL DEFAULT '{}',
    revoked_at            TEXT,
    created_at            TEXT    NOT NULL,
    updated_at            TEXT    NOT NULL,
    UNIQUE (tenant_id, code)
);
CREATE INDEX IF NOT EXISTS ix_probes_tenant ON probes(tenant_id);

-- Anti-replay: nonce delle buste gia' accettate (purga periodica).
CREATE TABLE IF NOT EXISTS probe_nonces (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    probe_id  INTEGER NOT NULL REFERENCES probes(id) ON DELETE CASCADE,
    nonce     TEXT    NOT NULL,
    seen_at   TEXT    NOT NULL,
    UNIQUE (probe_id, nonce)
);
CREATE INDEX IF NOT EXISTS ix_nonces_seen ON probe_nonces(seen_at);

-- Comandi server -> sonda: consegnati solo come risposta a un contatto della sonda.
CREATE TABLE IF NOT EXISTS probe_commands (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id    INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    probe_id     INTEGER NOT NULL REFERENCES probes(id) ON DELETE CASCADE,
    command      TEXT    NOT NULL,
    payload_json TEXT    NOT NULL DEFAULT '{}',
    status       TEXT    NOT NULL DEFAULT 'pending',
    result_json  TEXT,
    created_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at   TEXT    NOT NULL,
    delivered_at TEXT,
    acked_at     TEXT
);
CREATE INDEX IF NOT EXISTS ix_commands_probe ON probe_commands(probe_id, status);

-- ---------------------------------------------------------------------------
-- Tracciatura dei conferimenti (upload) della sonda
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ingest_batches (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id    INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    probe_id     INTEGER NOT NULL REFERENCES probes(id) ON DELETE CASCADE,
    batch_uid    TEXT    NOT NULL,
    record_count INTEGER NOT NULL DEFAULT 0,
    payload_bytes INTEGER NOT NULL DEFAULT 0,
    status       TEXT    NOT NULL DEFAULT 'accepted',
    detail       TEXT,
    -- I record conferiti sono conservati in forma leggibile: e' cio' che rende
    -- consultabile "quello che la sonda ha inviato". Oltre il limite di
    -- dimensione si conserva un estratto e lo si dichiara.
    records_json TEXT,
    records_truncated INTEGER NOT NULL DEFAULT 0,
    received_at  TEXT    NOT NULL,
    UNIQUE (probe_id, batch_uid)
);
CREATE INDEX IF NOT EXISTS ix_batches_tenant ON ingest_batches(tenant_id, received_at);

-- ---------------------------------------------------------------------------
-- Audit e configurazione
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    actor       TEXT    NOT NULL DEFAULT 'system',
    event_type  TEXT    NOT NULL,
    severity    TEXT    NOT NULL DEFAULT 'info',
    entity      TEXT,
    entity_id   TEXT,
    description TEXT    NOT NULL DEFAULT '',
    source_ip   TEXT,
    created_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audit_tenant ON audit_events(tenant_id, created_at);

CREATE TABLE IF NOT EXISTS system_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- Inventario di rete
--
-- Il perimetro di scansione e' dichiarato dal tenant (subnets) e consegnato
-- alla sonda nella configurazione cifrata: la sonda non accetta bersagli che
-- non siano contenuti in queste subnet.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS subnets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    cidr        TEXT    NOT NULL,
    label       TEXT    NOT NULL DEFAULT '',
    -- Zona di rete: il contesto che decide se un'esposizione e' un problema. Vuota
    -- significa non dichiarata, e vale come rete di utenza -- il giudizio piu'
    -- severo: il silenzio non deve valere come giustificazione (zones.py).
    zone        TEXT    NOT NULL DEFAULT '',
    is_enabled  INTEGER NOT NULL DEFAULT 1,
    host_count  INTEGER NOT NULL DEFAULT 0,
    source_file TEXT,
    imported_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    imported_at TEXT,
    notes       TEXT,
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL,
    UNIQUE (tenant_id, cidr)
);
CREATE INDEX IF NOT EXISTS ix_subnets_tenant ON subnets(tenant_id, is_enabled);

-- Un nodo scoperto: e' l'unita' dell'inventario. Il verdetto sul tipo di
-- dispositivo e' accompagnato dalle prove che lo motivano (fingerprint_json) e
-- dalla versione del catalogo che lo ha prodotto, cosi' da poterlo ricalcolare
-- senza nuove scansioni quando il catalogo cambia.
CREATE TABLE IF NOT EXISTS nodes (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id         INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subnet_id         INTEGER REFERENCES subnets(id) ON DELETE SET NULL,
    probe_id          INTEGER REFERENCES probes(id) ON DELETE SET NULL,
    ip                TEXT    NOT NULL,
    mac               TEXT,
    mac_vendor        TEXT,
    hostname          TEXT,
    status            TEXT    NOT NULL DEFAULT 'unknown',
    latency_ms        REAL,
    -- TTL osservato: arrotondato in su al TTL iniziale (64/128/255) da'
    -- un indizio DEBOLE della famiglia del sistema operativo.
    ttl               INTEGER,
    os_name           TEXT,
    os_family         TEXT,
    os_vendor         TEXT,
    os_gen            TEXT,
    os_type           TEXT,
    os_accuracy       INTEGER,
    device_type       TEXT    NOT NULL DEFAULT 'unknown',
    device_label      TEXT    NOT NULL DEFAULT 'Non identificato',
    device_confidence INTEGER NOT NULL DEFAULT 0,
    fingerprint_json  TEXT    NOT NULL DEFAULT '{}',
    catalog_version   TEXT,
    -- Tipo dichiarato dall'operatore: 'auto' (lo decide il riconoscimento) oppure
    -- 'manual'. Una dichiarazione resiste ai ricalcoli, altrimenti durerebbe fino
    -- alla scansione successiva.
    device_type_source TEXT   NOT NULL DEFAULT 'auto',
    device_type_by     TEXT,
    device_type_at     TEXT,
    device_type_reason TEXT,
    is_managed        INTEGER NOT NULL DEFAULT 0,
    tags              TEXT,
    notes             TEXT,
    first_seen_at     TEXT    NOT NULL,
    last_seen_at      TEXT    NOT NULL,
    last_scan_at      TEXT,
    last_change_at    TEXT,
    created_at        TEXT    NOT NULL,
    updated_at        TEXT    NOT NULL,
    UNIQUE (tenant_id, ip)
);
CREATE INDEX IF NOT EXISTS ix_nodes_tenant ON nodes(tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_nodes_type ON nodes(tenant_id, device_type);
CREATE INDEX IF NOT EXISTS ix_nodes_subnet ON nodes(subnet_id);

-- Porte e servizi osservati. closed_at conserva la memoria di una porta che era
-- aperta e non lo e' piu': serve alla deriva, quindi la riga non va cancellata.
CREATE TABLE IF NOT EXISTS node_ports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id     INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    node_id       INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    protocol      TEXT    NOT NULL,
    port          INTEGER NOT NULL,
    state         TEXT    NOT NULL DEFAULT 'open',
    service_name  TEXT,
    product       TEXT,
    version       TEXT,
    extrainfo     TEXT,
    cpe           TEXT,
    method        TEXT,
    confidence    INTEGER,
    -- Banner grezzo restituito dal servizio: e' spesso l'indizio piu' preciso
    -- sulla natura dell'apparato, anche quando nmap non riconosce il prodotto.
    banner        TEXT,
    first_seen_at TEXT    NOT NULL,
    last_seen_at  TEXT    NOT NULL,
    closed_at     TEXT,
    -- Porta iniettata da un apparato di rete e non appartenente al nodo: viene
    -- marcata, non cancellata, ed esclusa dalle prove del fingerprinting.
    is_suspect     INTEGER NOT NULL DEFAULT 0,
    suspect_reason TEXT,
    UNIQUE (node_id, protocol, port)
);
CREATE INDEX IF NOT EXISTS ix_ports_node ON node_ports(node_id, state);
CREATE INDEX IF NOT EXISTS ix_ports_tenant ON node_ports(tenant_id, port);
-- Le sale operative contano di continuo le porte aperte del tenant e cercano quelle
-- viste di recente: senza questi due indici ogni apertura di pagina scorre l'intera
-- tabella delle porte (4.300 righe su una rete media, e cresce con l'inventario).
CREATE INDEX IF NOT EXISTS ix_ports_stato ON node_ports(tenant_id, state);
CREATE INDEX IF NOT EXISTS ix_ports_recenti ON node_ports(tenant_id, first_seen_at);

-- La deriva: l'unico posto in cui si legge cosa e' cambiato e quando.
CREATE TABLE IF NOT EXISTS node_changes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id    INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    node_id      INTEGER REFERENCES nodes(id) ON DELETE CASCADE,
    kind         TEXT    NOT NULL,
    subject      TEXT,
    before_value TEXT,
    after_value  TEXT,
    severity     TEXT    NOT NULL DEFAULT 'info',
    created_at   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_changes_tenant ON node_changes(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS ix_changes_node ON node_changes(node_id, created_at);

-- Storico di raggiungibilita'. Cresce rapidamente: soggetto alla conservazione
-- configurata per il tenant.
CREATE TABLE IF NOT EXISTS monitor_samples (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id  INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    node_id    INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    checked_at TEXT    NOT NULL,
    reachable  INTEGER NOT NULL DEFAULT 0,
    latency_ms REAL
);
CREATE INDEX IF NOT EXISTS ix_samples_node ON monitor_samples(node_id, checked_at);

-- Telemetria delle fasi di scansione eseguite dalla sonda.
CREATE TABLE IF NOT EXISTS scan_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id    INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    probe_id     INTEGER REFERENCES probes(id) ON DELETE SET NULL,
    batch_id     INTEGER REFERENCES ingest_batches(id) ON DELETE SET NULL,
    stage        TEXT    NOT NULL,
    target       TEXT    NOT NULL,
    status       TEXT    NOT NULL DEFAULT 'completed',
    started_at   TEXT,
    finished_at  TEXT,
    duration_ms  INTEGER,
    hosts_total  INTEGER NOT NULL DEFAULT 0,
    hosts_up     INTEGER NOT NULL DEFAULT 0,
    records      INTEGER NOT NULL DEFAULT 0,
    nmap_args    TEXT,
    nmap_version TEXT,
    detail       TEXT,
    created_at   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_runs_tenant ON scan_runs(tenant_id, created_at);

-- ---------------------------------------------------------------------------
-- Controlli periodici
--
-- I bersagli sono dichiarati dall'operatore (onboarding) e sono indipendenti
-- dall'inventario: un controllo puo' riguardare un servizio raggiungibile per
-- nome, che la scoperta non censirebbe.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS check_targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL,
    address     TEXT    NOT NULL,
    description TEXT,
    is_enabled  INTEGER NOT NULL DEFAULT 1,
    created_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL,
    UNIQUE (tenant_id, address, name)
);
CREATE INDEX IF NOT EXISTS ix_targets_tenant ON check_targets(tenant_id, is_enabled);

-- Definizione di un controllo. config_json contiene i parametri del genere:
--   ports : {"ports": [{"protocol": "tcp", "port": 5100}, ...]}
--   http  : {"url": "...", "method": "GET", "expect_status": 200,
--            "assertions": [{"path": "status", "op": "eq", "value": "ok"}, ...]}
CREATE TABLE IF NOT EXISTS checks (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id           INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target_id           INTEGER NOT NULL REFERENCES check_targets(id) ON DELETE CASCADE,
    name                TEXT    NOT NULL,
    kind                TEXT    NOT NULL,
    config_json         TEXT    NOT NULL DEFAULT '{}',
    interval_seconds    INTEGER NOT NULL DEFAULT 300,
    timeout_seconds     INTEGER NOT NULL DEFAULT 10,
    is_enabled          INTEGER NOT NULL DEFAULT 1,
    severity            TEXT    NOT NULL DEFAULT 'warning',
    -- Fallimenti consecutivi che aprono l'incidente.
    failure_threshold   INTEGER NOT NULL DEFAULT 3,
    -- Fallimenti consecutivi oltre i quali viene attivato un operatore: da quel
    -- momento l'incidente non si chiude piu' da se'. Deve essere maggiore o uguale
    -- alla soglia di apertura, altrimenti l'operatore verrebbe attivato prima che
    -- l'incidente esista.
    escalation_threshold INTEGER NOT NULL DEFAULT 6,
    -- Recapito dell'operatore. Vuoto: si usa l'email di riferimento del tenant.
    escalation_email    TEXT,
    created_by          INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at          TEXT    NOT NULL,
    updated_at          TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_checks_tenant ON checks(tenant_id, is_enabled);
CREATE INDEX IF NOT EXISTS ix_checks_target ON checks(target_id);

-- Esito di una esecuzione. payload_json conserva la risposta (accorciata): e' il
-- dato che l'operatore guarda quando qualcosa non torna.
CREATE TABLE IF NOT EXISTS check_results (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id    INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    check_id     INTEGER NOT NULL REFERENCES checks(id) ON DELETE CASCADE,
    probe_id     INTEGER REFERENCES probes(id) ON DELETE SET NULL,
    executed_at  TEXT    NOT NULL,
    status       TEXT    NOT NULL,
    latency_ms   REAL,
    detail       TEXT,
    payload_json TEXT,
    received_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_results_check ON check_results(check_id, executed_at);
CREATE INDEX IF NOT EXISTS ix_results_tenant ON check_results(tenant_id, executed_at);

-- Coda di uscita delle notifiche del workflow.
--
-- Perche' una coda e non un invio diretto: le notifiche nascono dentro il
-- conferimento di un lotto, e un server di posta lento bloccherebbe l'ingest di una
-- sonda per secondi. Qui vengono scritte e un thread a se' le spedisce, con
-- ritentativi. Una notifica non recapitata resta visibile con il proprio errore.
CREATE TABLE IF NOT EXISTS notifications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    incident_id INTEGER REFERENCES check_incidents(id) ON DELETE SET NULL,
    event       TEXT    NOT NULL,
    -- Canale di recapito: posta elettronica oppure bot Telegram. Il destinatario
    -- ha significato diverso nei due casi (indirizzo, identificativo di chat) e
    -- resta nella stessa colonna perche' la coda e' una.
    channel     TEXT    NOT NULL DEFAULT 'email',
    recipients  TEXT    NOT NULL DEFAULT '',
    subject     TEXT    NOT NULL,
    body        TEXT    NOT NULL,
    body_html   TEXT,
    attachment_path TEXT,
    status      TEXT    NOT NULL DEFAULT 'pending',
    attempts    INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT,
    sent_at     TEXT,
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_notifiche_coda ON notifications(status, id);
CREATE INDEX IF NOT EXISTS ix_notifiche_tenant ON notifications(tenant_id, created_at);

-- Punti di misura ricavati dagli esiti: e' cio' che rende interrogabile nel tempo
-- quanto i controlli raccolgono. `value` porta i numeri, `text_value` i testi (una
-- versione, uno stato dichiarato): entrambi sono dati, e tenerli nella stessa
-- tabella evita due interrogazioni per la stessa domanda.
CREATE TABLE IF NOT EXISTS check_metrics (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    check_id    INTEGER NOT NULL REFERENCES checks(id) ON DELETE CASCADE,
    result_id   INTEGER REFERENCES check_results(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL,
    value       REAL,
    text_value  TEXT,
    measured_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_metrics_serie ON check_metrics(check_id, name, measured_at);
CREATE INDEX IF NOT EXISTS ix_metrics_tenant ON check_metrics(tenant_id, measured_at);

-- Incidente: e' l'oggetto del workflow.
CREATE TABLE IF NOT EXISTS check_incidents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    check_id        INTEGER NOT NULL REFERENCES checks(id) ON DELETE CASCADE,
    status          TEXT    NOT NULL DEFAULT 'open',
    severity        TEXT    NOT NULL DEFAULT 'warning',
    opened_at       TEXT    NOT NULL,
    first_detail    TEXT,
    last_detail     TEXT,
    failure_count   INTEGER NOT NULL DEFAULT 1,
    -- Attivazione dell'operatore: quando e a quale recapito.
    escalated_at    TEXT,
    escalated_to    TEXT,
    -- Ultimo promemoria "controllo rientrato, incidente ancora aperto": evita di
    -- rimandare la stessa notifica a ogni giro del controllo (vedi checks.py).
    recovered_notified_at TEXT,
    acknowledged_at TEXT,
    acknowledged_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    resolved_at     TEXT,
    resolved_by     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    resolution      TEXT,
    notes           TEXT,
    -- Da dove viene l'incidente: 'check' se l'ha aperto un controllo, 'manual' se
    -- l'ha registrato una persona. Solo i secondi si possono eliminare: la storia
    -- della sorveglianza non si riscrive.
    origin          TEXT    NOT NULL DEFAULT 'check',
    -- Titolo e soggetto valgono per gli incidenti registrati a mano: il nome del
    -- controllo e l'indirizzo del bersaglio, per quelli, non dicono niente.
    title           TEXT,
    subject         TEXT,
    created_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    updated_at      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_incidents_tenant ON check_incidents(tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_incidents_check ON check_incidents(check_id, status);

-- Passaggi di stato dell'incidente: chi ha fatto cosa e quando.
CREATE TABLE IF NOT EXISTS check_incident_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    incident_id INTEGER NOT NULL REFERENCES check_incidents(id) ON DELETE CASCADE,
    action      TEXT    NOT NULL,
    actor       TEXT    NOT NULL DEFAULT 'system',
    note        TEXT,
    created_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_incident_events ON check_incident_events(incident_id, created_at);

-- ---------------------------------------------------------------------------
-- Report prodotti.
-- L'indice unico su (tenant, genere, periodo) e' cio' che rende impossibile
-- spedire due volte il resoconto dello stesso giorno, anche a fronte di
-- riavvii: la garanzia sta nel database, non in una variabile di memoria.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS report_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind            TEXT    NOT NULL,
    period_key      TEXT    NOT NULL,
    period_start    TEXT    NOT NULL,
    period_end      TEXT    NOT NULL,
    file_path       TEXT,
    file_bytes      INTEGER NOT NULL DEFAULT 0,
    status          TEXT    NOT NULL DEFAULT 'ok',
    detail          TEXT,
    notification_id INTEGER REFERENCES notifications(id) ON DELETE SET NULL,
    requested_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at      TEXT    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_report_periodo
    ON report_runs(tenant_id, kind, period_key);
CREATE INDEX IF NOT EXISTS ix_report_tenant ON report_runs(tenant_id, created_at);

-- ---------------------------------------------------------------------------
-- Regole di notifica: qualunque evento del sistema, una condizione, un canale.
--
-- Perche' le regole stanno nel database e non nel codice: cio' che merita una
-- notifica cambia da cliente a cliente e cambia nel tempo. Una porta 3389 che
-- si apre e' un evento in una rete e la normalita' in un'altra.
--
-- `event_type` a '*' significa qualunque evento della sorgente; le condizioni
-- usano lo stesso vocabolario delle verifiche sui controlli (eq, ne, contains,
-- gt, lt, exists, absent), cosi' chi ha imparato l'una sa usare l'altra.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notify_rules (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id        INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name             TEXT    NOT NULL,
    description      TEXT,
    source           TEXT    NOT NULL,
    event_type       TEXT    NOT NULL DEFAULT '*',
    conditions_json  TEXT    NOT NULL DEFAULT '[]',
    severity         TEXT    NOT NULL DEFAULT 'warning',
    channels         TEXT    NOT NULL DEFAULT 'email',
    recipients       TEXT,
    telegram_chat_id TEXT,
    -- Anti-alluvione: una passata di scoperta produce migliaia di eventi, e
    -- migliaia di messaggi renderebbero il canale inutile. Entro la finestra si
    -- spedisce al massimo `max_per_window`, poi si accumula e si riassume.
    window_seconds   INTEGER NOT NULL DEFAULT 900,
    max_per_window   INTEGER NOT NULL DEFAULT 5,
    digest_only      INTEGER NOT NULL DEFAULT 0,
    is_enabled       INTEGER NOT NULL DEFAULT 1,
    matches_total    INTEGER NOT NULL DEFAULT 0,
    last_matched_at  TEXT,
    created_by       INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at       TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_regole_tenant ON notify_rules(tenant_id, is_enabled);

-- Eventi che hanno soddisfatto una regola: storico, e stato dell'anti-alluvione.
CREATE TABLE IF NOT EXISTS rule_matches (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id         INTEGER NOT NULL REFERENCES notify_rules(id) ON DELETE CASCADE,
    source          TEXT    NOT NULL,
    source_id       INTEGER,
    event_type      TEXT    NOT NULL,
    subject         TEXT,
    detail          TEXT,
    severity        TEXT    NOT NULL DEFAULT 'info',
    occurred_at     TEXT    NOT NULL,
    notified        INTEGER NOT NULL DEFAULT 0,
    suppressed      INTEGER NOT NULL DEFAULT 0,
    notification_id INTEGER REFERENCES notifications(id) ON DELETE SET NULL,
    created_at      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_regola_eventi ON rule_matches(rule_id, created_at);
CREATE INDEX IF NOT EXISTS ix_regola_tenant ON rule_matches(tenant_id, created_at);

-- ---------------------------------------------------------------------------
-- Cursori delle sorgenti di evento: fin dove il valutatore e' arrivato.
--
-- Senza cursore, alla riaccensione il valutatore rivedrebbe tutto l'archivio e
-- spedirebbe una notifica per ogni evento mai registrato. Il cursore e' per
-- sorgente e non per regola: una regola nuova non deve far rileggere il
-- passato, altrimenti la sua creazione produrrebbe una raffica di messaggi.
-- Per guardare il passato c'e' la prova sulla storia, che non spedisce nulla.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS event_cursors (
    source     TEXT PRIMARY KEY,
    last_id    INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT    NOT NULL
);

-- ---------------------------------------------------------------------------
-- Threat Intelligence: catalogo locale e correlazione con l'inventario.
--
-- Il catalogo (CVE, CWE, tecniche ATT&CK) e' GLOBALE: e' conoscenza pubblica, non
-- dato di un cliente, e duplicarlo per tenant moltiplicherebbe centinaia di
-- migliaia di righe senza aggiungere nulla. Le CORRELAZIONI, invece, sono per
-- tenant: dicono che cosa ha quel cliente in rete, e sono dato riservato.
--
-- Tutto funziona OFFLINE: la correlazione legge il catalogo locale e non contatta
-- nessuno. L'aggiornamento del catalogo e' un'operazione esplicita, tracciata, e
-- accetta anche un file caricato a mano per le installazioni senza rete.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ti_cve (
    cve_id        TEXT PRIMARY KEY,
    published_at  TEXT,
    modified_at   TEXT,
    cvss_version  TEXT,
    cvss_vector   TEXT,
    cvss_score    REAL,
    severity      TEXT,
    description   TEXT,
    cwe_ids       TEXT,
    -- Sfruttata attivamente secondo il catalogo CISA KEV: e' il singolo dato piu'
    -- azionabile che esista su una vulnerabilita'.
    kev           INTEGER NOT NULL DEFAULT 0,
    kev_added_at  TEXT,
    kev_due_at    TEXT,
    kev_ransomware INTEGER NOT NULL DEFAULT 0,
    references_json TEXT,
    source        TEXT NOT NULL DEFAULT 'nvd',
    imported_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_ti_cve_severity ON ti_cve(severity, cvss_score);
CREATE INDEX IF NOT EXISTS ix_ti_cve_kev ON ti_cve(kev, cvss_score);
CREATE INDEX IF NOT EXISTS ix_ti_cve_modificata ON ti_cve(modified_at);

-- Applicabilita' dichiarata dalla NVD: a quali prodotti e a quali versioni si
-- applica una CVE. Senza questa tabella una correlazione sarebbe una ricerca per
-- nome, cioe' un generatore di falsi positivi.
CREATE TABLE IF NOT EXISTS ti_cve_cpe (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id        TEXT NOT NULL REFERENCES ti_cve(cve_id) ON DELETE CASCADE,
    criteria      TEXT NOT NULL,
    part          TEXT,
    vendor        TEXT,
    product       TEXT,
    version       TEXT,
    vulnerable    INTEGER NOT NULL DEFAULT 1,
    version_start TEXT,
    version_start_incl INTEGER NOT NULL DEFAULT 0,
    version_end   TEXT,
    version_end_incl   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_ti_cpe_prodotto ON ti_cve_cpe(part, vendor, product);
CREATE INDEX IF NOT EXISTS ix_ti_cpe_cve ON ti_cve_cpe(cve_id);

CREATE TABLE IF NOT EXISTS ti_cwe (
    cwe_id      TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    abstraction TEXT,
    description TEXT,
    mitigation  TEXT,
    url         TEXT,
    imported_at TEXT NOT NULL
);

-- Legame fra una CVE e le classi di debolezza che la NVD le attribuisce.
-- La colonna testuale ti_cve.cwe_ids resta, perche' e' cio' che la sorgente
-- dichiara e va conservato com'e'; questa tabella e' la sua forma interrogabile.
-- Senza, contare le CVE di ciascuna CWE richiedeva un LIKE su tutte le CVE per
-- ciascuna delle 130 debolezze: 14,3 secondi a ogni apertura della pagina.
CREATE TABLE IF NOT EXISTS ti_cve_cwe (
    cve_id TEXT NOT NULL REFERENCES ti_cve(cve_id) ON DELETE CASCADE,
    cwe_id TEXT NOT NULL,
    PRIMARY KEY (cve_id, cwe_id)
);
CREATE INDEX IF NOT EXISTS ix_ti_cve_cwe_debolezza ON ti_cve_cwe(cwe_id);

-- Tecniche MITRE ATT&CK: servono a dire COME una esposizione verrebbe usata, che e'
-- l'informazione che manca a un elenco di porte aperte.
CREATE TABLE IF NOT EXISTS ti_technique (
    technique_id TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    tactics      TEXT,
    description  TEXT,
    url          TEXT,
    is_subtechnique INTEGER NOT NULL DEFAULT 0,
    imported_at  TEXT NOT NULL
);

-- Correlazioni fra inventario e catalogo. Tre classi, sempre dichiarate:
--   confirmed  prodotto E versione noti, applicabilita' NVD soddisfatta
--   potential  prodotto noto, versione ignota: la CVE esiste, l'istanza non e'
--              verificabile -- non e' una vulnerabilita' accertata
--   exposure   nessuna CVE: e' il servizio in se' a essere un rischio, con la
--              tecnica ATT&CK che lo sfrutterebbe
CREATE TABLE IF NOT EXISTS ti_findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id     INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    node_id       INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    port_id       INTEGER REFERENCES node_ports(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL,
    cve_id        TEXT REFERENCES ti_cve(cve_id) ON DELETE SET NULL,
    -- Identificativo della tecnica ATT&CK: e' un'etichetta, non una riga di
    -- nostra proprieta'. Senza vincolo, perche' le esposizioni devono funzionare
    -- anche prima che il catalogo ATT&CK venga importato -- cioe' al primo
    -- avvio, che e' il momento in cui servono di piu'.
    technique_id  TEXT,
    severity      TEXT NOT NULL DEFAULT 'info',
    score         REAL,
    title         TEXT NOT NULL,
    evidence      TEXT NOT NULL,
    cpe_used      TEXT,
    product       TEXT,
    version       TEXT,
    confidence    INTEGER NOT NULL DEFAULT 50,
    status        TEXT NOT NULL DEFAULT 'open',
    -- Da dove viene il riscontro: 'correlation' (versione del servizio contro il
    -- catalogo CVE locale) oppure 'nmap' (verificato attivamente da uno script di
    -- rilevazione). La riconciliazione della correlazione tocca solo i suoi.
    source        TEXT NOT NULL DEFAULT 'correlation',
    note          TEXT,
    decided_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    decided_at    TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL
);
-- Un solo riscontro per (nodo, porta, cve/tecnica): la rivalutazione aggiorna,
-- non duplica, altrimenti l'elenco crescerebbe a ogni passata.
CREATE UNIQUE INDEX IF NOT EXISTS ux_ti_finding
    ON ti_findings(tenant_id, node_id, IFNULL(port_id, 0), kind,
                   IFNULL(cve_id, ''), IFNULL(technique_id, ''));
CREATE INDEX IF NOT EXISTS ix_ti_finding_tenant ON ti_findings(tenant_id, status, severity);
CREATE INDEX IF NOT EXISTS ix_ti_finding_nodo ON ti_findings(node_id);

-- Registro degli aggiornamenti del catalogo: da dove, quando, quanto, con quale
-- esito. Un catalogo di cui non si sa quanto e' vecchio non e' utilizzabile.
CREATE TABLE IF NOT EXISTS ti_sync (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source      TEXT NOT NULL,
    mode        TEXT NOT NULL,
    status      TEXT NOT NULL,
    items       INTEGER NOT NULL DEFAULT 0,
    detail      TEXT,
    requested_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_ti_sync_sorgente ON ti_sync(source, started_at);

-- ---------------------------------------------------------------------------
-- Letture SNMP dei dispositivi.
--
-- Quando la porta 161 risponde, SNMP racconta dell'apparato piu' di dieci porte
-- TCP: nome e descrizione del sistema, interfacce, tabelle di instradamento,
-- processi, software installato. Il testo intero si conserva qui e non dentro il
-- profilo del nodo, dove verrebbe troncato -- e cio' che si perderebbe e' proprio
-- l'elenco delle interfacce e del software.
--
-- Una riga per (nodo, script); la riga con script_id = 'summary' porta il
-- riassunto in forma strutturata.
-- ---------------------------------------------------------------------------
-- ---------------------------------------------------------------------------
-- Zone di rete: il contesto dichiarato di una porzione di rete.
--
-- Nascono come catalogo nel codice (sei zone, docs/12). Da quando l'operatore puo'
-- crearle e modificarle, il catalogo e' un DATO del tenant: reti diverse hanno
-- contesti diversi, e "rete di collaudo" o "rete fornitori" nessuno le puo'
-- prevedere da qui. Resta nel codice cio' che il cliente non deve poter inventare:
-- le FAMIGLIE di esposizione, che sono i titoli delle regole di correlazione.
CREATE TABLE IF NOT EXISTS network_zones (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id     INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Chiave stabile: e' cio' che le subnet conservano in `subnets.zone`.
    key           TEXT    NOT NULL,
    name          TEXT    NOT NULL,
    description   TEXT    NOT NULL DEFAULT '',
    icon          TEXT    NOT NULL DEFAULT 'bi-diagram-3',
    tone          TEXT    NOT NULL DEFAULT 'secondary',
    -- Famiglie attese e famiglie in violazione, come elenchi JSON di titoli.
    expected_json TEXT    NOT NULL DEFAULT '[]',
    violated_json TEXT    NOT NULL DEFAULT '[]',
    -- Zona nata col prodotto: si puo' modificare, e si puo' riportare all'origine.
    is_builtin    INTEGER NOT NULL DEFAULT 0,
    sort_order    INTEGER NOT NULL DEFAULT 100,
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_network_zones ON network_zones(tenant_id, key);

-- ---------------------------------------------------------------------------
-- Letture delle interfacce web dei dispositivi: una riga per porta.
--
-- Perche' in una tabella propria: sono la fonte piu' esplicita dopo SNMP -- una
-- pagina di gestione dichiara marca, modello e spesso la versione -- e nelle prove
-- del profilo verrebbero troncate. Il CORPO della pagina non si conserva: puo'
-- contenere nomi e recapiti, cioe' dati personali di cui il prodotto non ha bisogno
-- (GDPR art. 5). Si conservano le etichette che la pagina dichiara di se', la loro
-- impronta e il verdetto delle firme.
CREATE TABLE IF NOT EXISTS node_web (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id    INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    node_id      INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    port         INTEGER NOT NULL,
    scheme       TEXT    NOT NULL DEFAULT 'http',
    status_code  INTEGER,
    title        TEXT,
    server_header TEXT,
    generator    TEXT,
    realm        TEXT,
    -- Verdetto delle firme: marca, modello, prodotto, versione e la firma che ha
    -- deciso. Senza la firma un verdetto non sarebbe verificabile.
    brand        TEXT,
    model        TEXT,
    product      TEXT,
    version      TEXT,
    device_type  TEXT,
    signature    TEXT,
    -- Certificato, per le porte cifrate: il nome dice l'apparato piu' spesso della
    -- pagina, e la scadenza e' un dato operativo che nessun'altra fase raccoglie.
    cert_subject TEXT,
    cert_issuer  TEXT,
    cert_expires TEXT,
    cert_selfsigned INTEGER NOT NULL DEFAULT 0,
    tls_version  TEXT,
    login_form   INTEGER NOT NULL DEFAULT 0,
    -- Cio' che l'apparato dichiara di se' nelle proprie pagine: sono i dati che si
    -- cercano e si mettono in un report, quindi stanno in colonna e non solo nel
    -- dettaglio. La posizione fisica ("ED A PIANO -1 DIETRO AULA") e' l'informazione
    -- che nessun'altra fase puo' ricavare: non sta in rete, sta scritta sull'apparato.
    device_name  TEXT,
    location     TEXT,
    host_name    TEXT,
    serial       TEXT,
    firmware     TEXT,
    contact      TEXT,
    -- Quante pagine sono state lette per arrivarci, e se i dati esistono ma sono
    -- dietro una richiesta di credenziali (che la sonda non ha e non tenta).
    pages_read   INTEGER NOT NULL DEFAULT 0,
    facts_locked INTEGER NOT NULL DEFAULT 0,
    -- Tutte le etichette dichiarate dall'apparato, anche quelle senza colonna propria
    -- (i telefoni IP Cisco ne dichiarano una decina): il dettaglio del nodo le mostra
    -- tutte. Solo il vocabolario riconosciuto, mai il corpo della pagina.
    facts_json   TEXT,
    -- Tutti i dati del certificato TLS, anche quelli senza colonna propria (numero di
    -- serie, versione, algoritmo di firma, chiave pubblica, impronte, SAN, usi): dove
    -- c'e' HTTPS si registra tutto cio' che il certificato dichiara.
    cert_json    TEXT,
    body_hash    TEXT,
    body_bytes   INTEGER,
    error        TEXT,
    details_json TEXT,
    collected_at TEXT    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_node_web ON node_web(tenant_id, node_id, port);
CREATE INDEX IF NOT EXISTS ix_node_web_nodo ON node_web(node_id, collected_at);

CREATE TABLE IF NOT EXISTS node_snmp (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id    INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    node_id      INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    script_id    TEXT    NOT NULL,
    output       TEXT,
    parsed_json  TEXT,
    collected_at TEXT    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_node_snmp ON node_snmp(tenant_id, node_id, script_id);
CREATE INDEX IF NOT EXISTS ix_node_snmp_nodo ON node_snmp(node_id, collected_at);

-- node_smb: enumerazione SMB (139/445) di una macchina Windows -- sistema operativo,
-- dominio, condivisioni, utenze. Come per node_snmp, il testo intero degli script sta
-- in una tabella propria e non nelle prove del profilo, dove verrebbe troncato. Una
-- riga per script; la riga 'summary' porta il riassunto interpretato.
CREATE TABLE IF NOT EXISTS node_smb (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id    INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    node_id      INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    script_id    TEXT    NOT NULL,
    output       TEXT,
    parsed_json  TEXT,
    collected_at TEXT    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_node_smb ON node_smb(tenant_id, node_id, script_id);
CREATE INDEX IF NOT EXISTS ix_node_smb_nodo ON node_smb(node_id, collected_at);

-- ---------------------------------------------------------------------------
-- Rimozione delle strutture non piu' previste dal modello.
-- Il dominio delle vulnerabilita' e l'archivio dei report sono stati eliminati
-- dal prodotto; assets, scans e services appartenevano al vecchio inventario e
-- sono oggi sostituiti da nodes, scan_runs e node_ports. Le istruzioni seguenti
-- allineano i database creati con le versioni precedenti.
--
-- Nota: 'subnets' NON va eliminata. Era una tabella del vecchio dominio, ma il
-- nome e' oggi riusato dal perimetro di scansione definito sopra: una
-- DROP TABLE qui cancellerebbe il perimetro a ogni avvio.
-- ---------------------------------------------------------------------------
DROP TABLE IF EXISTS report_history;
DROP TABLE IF EXISTS vulnerabilities;
DROP TABLE IF EXISTS services;
DROP TABLE IF EXISTS assets;
DROP TABLE IF EXISTS scans;

-- Comunicazioni all'Agenzia per la Cybersicurezza Nazionale (art. 23 della direttiva
-- (UE) 2022/2555, recepita dal D.lgs. 138/2024). Una riga per stadio: preallarme (24
-- ore), notifica (72 ore), aggiornamenti, relazione finale (un mese).
--
-- Il portale ACN si usa con identita' digitale: snap NON invia. Compone il fascicolo,
-- tiene l'orologio e registra cio' che e' stato inviato -- stadio, istante, persona e
-- numero di protocollo. E' questa la parte che dimostra i tempi in un'ispezione, ed e'
-- la ragione per cui la riga sopravvive alla chiusura dell'incidente.
CREATE TABLE IF NOT EXISTS acn_communications (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id    INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    incident_id  INTEGER NOT NULL REFERENCES check_incidents(id) ON DELETE CASCADE,
    stage        TEXT    NOT NULL,
    status       TEXT    NOT NULL DEFAULT 'da_preparare',
    channel      TEXT    NOT NULL DEFAULT 'portale',
    -- L'istante da cui decorrono i termini: la CONOSCENZA dell'incidente, non il suo
    -- inizio. E' cio' che dice l'art. 23 ed e' l'unico istante documentabile.
    known_at     TEXT    NOT NULL,
    deadline_at  TEXT,
    prepared_at  TEXT,
    sent_at      TEXT,
    sent_by      TEXT,
    -- Il protocollo restituito dal portale: senza questo "inviata" non e' dimostrabile.
    reference    TEXT,
    answered_at  TEXT,
    notes        TEXT,
    file_path    TEXT,
    payload_json TEXT,
    -- Gli avvisi si mandano UNA volta: uno in avvicinamento e uno a termine superato.
    -- Un avviso ripetuto ogni cinque minuti diventa rumore, e il rumore si silenzia.
    alerted_at   TEXT,
    overdue_alerted_at TEXT,
    created_at   TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_acn_tenant
    ON acn_communications(tenant_id, status, deadline_at);
CREATE INDEX IF NOT EXISTS ix_acn_incidente
    ON acn_communications(incident_id, stage);

-- =========================================================================== #
-- SIEM: onboarding dei log, eventi di sicurezza e correlazione con la TI
-- =========================================================================== #

-- Collettore: il punto d'ingresso autenticato dei log (il container Vector, o il
-- listener syslog integrato). Il token viene conservato SOLO come impronta, come
-- l'api_key delle sonde: chi perde il token lo rigenera, non lo rilegge.
CREATE TABLE IF NOT EXISTS siem_collectors (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id     INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT    NOT NULL,
    kind          TEXT    NOT NULL DEFAULT 'vector',
    token_hash    TEXT    NOT NULL,
    is_enabled    INTEGER NOT NULL DEFAULT 1,
    last_seen_at  TEXT,
    events_total  INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL,
    UNIQUE (tenant_id, name)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_siem_collector_token
    ON siem_collectors(token_hash);

-- Sorgente: un apparato (o una classe di apparati) di cui si e' dichiarato
-- l'onboarding. Gli eventi si attribuiscono per host o indirizzo di provenienza;
-- il legame col nodo dell'inventario permette la correlazione con la TI.
CREATE TABLE IF NOT EXISTS siem_sources (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id     INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT    NOT NULL,
    kind          TEXT    NOT NULL DEFAULT 'other',
    vendor        TEXT,
    -- Come si riconoscono gli eventi di questa sorgente: hostname dichiarato nel
    -- syslog oppure indirizzo IP di provenienza. Confronto esatto, senza pattern:
    -- una allowlist, non una blocklist.
    match_host    TEXT,
    match_ip      TEXT,
    node_id       INTEGER REFERENCES nodes(id) ON DELETE SET NULL,
    is_enabled    INTEGER NOT NULL DEFAULT 1,
    last_event_at TEXT,
    events_total  INTEGER NOT NULL DEFAULT 0,
    notes         TEXT,
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL,
    UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS ix_siem_sources_tenant ON siem_sources(tenant_id);

-- Regole di rilevazione: soglie su finestre temporali sopra gli eventi
-- normalizzati. Il catalogo viene seminato per tenant e resta modificabile.
CREATE TABLE IF NOT EXISTS siem_rules (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id      INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    code           TEXT    NOT NULL,
    name           TEXT    NOT NULL,
    description    TEXT,
    event_kind     TEXT    NOT NULL,
    -- Campo su cui raggruppare i conteggi: src_ip, username, host.
    group_by       TEXT    NOT NULL DEFAULT 'src_ip',
    threshold      INTEGER NOT NULL DEFAULT 1,
    window_seconds INTEGER NOT NULL DEFAULT 300,
    severity       TEXT    NOT NULL DEFAULT 'medium',
    -- Gravita' minima dell'evento perche' conti per la regola: vuoto significa
    -- "qualunque". Serve alle regole che devono scattare solo su eventi gia' gravi
    -- (un allarme di apparato critico si apre subito, con soglia 1).
    min_severity   TEXT,
    technique_id   TEXT,
    is_enabled     INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT    NOT NULL,
    updated_at     TEXT    NOT NULL,
    UNIQUE (tenant_id, code)
);

-- Allarmi: gli eventi di sicurezza rilevati. Un allarme aperto per la stessa
-- (regola, origine) si AGGIORNA con il conteggio, non si duplica: mille tentativi
-- di accesso sono un attacco, non mille allarmi.
CREATE TABLE IF NOT EXISTS siem_alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id      INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id        INTEGER REFERENCES siem_rules(id) ON DELETE SET NULL,
    rule_code      TEXT    NOT NULL,
    title          TEXT    NOT NULL,
    severity       TEXT    NOT NULL DEFAULT 'medium',
    status         TEXT    NOT NULL DEFAULT 'open',
    event_kind     TEXT,
    group_value    TEXT,
    src_ip         TEXT,
    username       TEXT,
    host           TEXT,
    node_id        INTEGER REFERENCES nodes(id) ON DELETE SET NULL,
    -- La correlazione con la threat intelligence: i riscontri aperti sul nodo
    -- coinvolto, come elenco JSON di {id, cve, severita'}. La gravita'
    -- dell'allarme viene alzata quando il nodo risulta gia' esposto.
    ti_refs_json   TEXT,
    evidence       TEXT    NOT NULL,
    events_count   INTEGER NOT NULL DEFAULT 1,
    first_event_at TEXT    NOT NULL,
    last_event_at  TEXT    NOT NULL,
    notified_at    TEXT,
    note           TEXT,
    decided_by     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    decided_at     TEXT,
    created_at     TEXT    NOT NULL,
    updated_at     TEXT    NOT NULL
);
-- Un solo allarme APERTO per (regola, origine): la chiusura libera la chiave e
-- un attacco che riprende apre un allarme nuovo, con la propria storia.
CREATE UNIQUE INDEX IF NOT EXISTS ux_siem_alert_aperto
    ON siem_alerts(tenant_id, rule_code, IFNULL(group_value, ''))
    WHERE status IN ('open', 'ack');
CREATE INDEX IF NOT EXISTS ix_siem_alerts_tenant
    ON siem_alerts(tenant_id, status, severity);
