# CLAUDE.md

Istruzioni per Claude Code su questo progetto.

## Progetto

`snap` — TODO: cosa fa, a chi serve, in 2-3 righe.

# Stack tecnologico

## Vincoli di base
- **Linguaggio**: Python (versione ≥ 3.12, dichiarata in `pyproject.toml`
  e nel Dockerfile: la stessa ovunque).
- **Framework**: Flask.
- **Database**: SQLite in sviluppo, PostgreSQL in container in produzione.
- **Porte**: le applicazioni espongono SOLO porte nel range **5500-5600**.
  La porta di ogni app è definita in configurazione (variabile d'ambiente
  `APP_PORT`), mai hardcoded; documentare in un file `PORTS.md` quale porta
  è assegnata a quale servizio per evitare conflitti nel range.

## Struttura dell'applicazione Flask
- Pattern **application factory** (`create_app(config)`) + **blueprint**
  per area funzionale (es. `auth`, `dashboard`, `reports`, `notifications`):
  mai tutta l'app in un unico file.
- Configurazione per ambiente tramite classi (`DevelopmentConfig`,
  `ProductionConfig`, `TestingConfig`) popolate da variabili d'ambiente
  (file `.env` solo in sviluppo, MAI committato; `.env.example` sempre
  aggiornato e committato).
- Estensioni standard: Flask-SQLAlchemy, Flask-Migrate (Alembic),
  Flask-Login (o equivalente) per le sessioni, Flask-WTF per form + CSRF.
- In produzione l'app gira dietro **Gunicorn** (mai il dev server Flask)
  e un reverse proxy; `ProxyFix` configurato per gli header X-Forwarded.

## Database: compatibilità SQLite ↔ PostgreSQL
- TUTTO l'accesso ai dati passa da **SQLAlchemy ORM**: nessuna query SQL
  in dialetto specifico che funzioni solo su uno dei due database.
- Vietati i costrutti non portabili senza astrazione: usare i tipi
  SQLAlchemy neutri (`JSON`, `DateTime(timezone=True)`, `Numeric`);
  se serve una feature solo-Postgres (es. `JSONB`, full-text search),
  isolarla e fornire un fallback funzionante su SQLite.
- **Migrazioni con Alembic obbligatorie** per ogni modifica di schema:
  mai `db.create_all()` fuori dai test. Le migrazioni devono essere
  testate su entrambi i database.
- Attenzione alle differenze note: SQLite non applica `ALTER` completi
  (usare `batch_alter_table` nelle migrazioni) ed è permissivo sui tipi —
  la validazione dei dati deve stare nel codice, non affidata al DB.
- Datetime sempre timezone-aware in UTC; conversione al fuso locale
  (Europe/Rome) solo in presentazione.

## PostgreSQL in produzione (container)
- Postgres in container definito in `docker-compose.yml` (immagine
  ufficiale con versione pinnata, es. `postgres:16.x`), volume dedicato
  per la persistenza, healthcheck configurato.
- L'app si connette con un **utente DB dedicato con privilegi minimi**
  (no superuser); credenziali via variabili d'ambiente o secret.
- La porta di Postgres NON viene pubblicata sull'host in produzione:
  app e DB comunicano sulla rete Docker interna.
- Pool di connessioni configurato (`pool_pre_ping=True`, `pool_recycle`)
  per gestire i riavvii del container DB.
- Backup: prevedere uno script `pg_dump` schedulabile con retention
  configurabile, coerente con i requisiti di continuità operativa (NIS2).

## Qualità e tooling
- Dipendenze gestite con `pyproject.toml` + lockfile (uv o pip-tools);
  versioni pinnate.
- Lint e formatting: `ruff` (lint + format) configurato nel repo;
  type hints sul codice nuovo, verificati con `mypy` o `pyright`.
- Test con `pytest`: i test girano su SQLite in memoria per velocità,
  ma la CI deve eseguire almeno una suite di integrazione contro un
  Postgres in container per intercettare le differenze di dialetto.
- Comandi operativi ripetibili (run, test, lint, migrate) definiti in
  un `Makefile` o `justfile` e documentati nel README.

## Struttura

- `src/` — codice applicativo
- `tests/` — test
- `docs/` — documentazione

## Comandi

```bash
# install
# dev
# build
# test
# lint
```

# Convenzioni

## Lingua e stile del codice
- Codice e identificatori (variabili, funzioni, classi, tabelle DB) in
  **inglese**; commenti, docstring, messaggi utente e documentazione in
  **italiano**.
- Prima di scrivere codice nuovo, cerca nel repository se esiste già una
  funzione/utility equivalente e riusala; se ne trovi una simile ma
  insufficiente, estendila invece di duplicarla.
- Segui lo stile del file che stai modificando (naming, indentazione,
  pattern), anche se differisce dal resto del progetto.
- Commenta il *perché*, non il *cosa*: niente commenti che spiegano l'ovvio.
- Gestione errori sempre esplicita: vietati `except`/`catch` vuoti o che
  inghiottono l'eccezione senza log; ogni errore gestito deve loggare
  contesto sufficiente per il debug.
- Nessuna nuova dipendenza senza chiedere prima ed elencare le alternative
  valutate.

## Standard e normative di riferimento
Applica sempre, anche quando non richiesto esplicitamente:
- **Requisiti e documentazione**: ISO/IEC/IEEE 29148:2018 (Requirements
  engineering) per la struttura di requisiti e specifiche.
- **Ciclo di vita**: ISO/IEC/IEEE 15288 (System life cycle processes,
  ed. 2023) per fasi e processi.
- **Modellazione**: diagrammi UML conformi a ISO/IEC 19505 (UML);
  per i processi di business, BPMN conforme a ISO/IEC 19510.
- **Normativa UE**: Reg. (UE) 2016/679 (GDPR), Reg. (UE) 2024/2847 (CRA),
  Direttiva (UE) 2022/2555 (NIS2) — vedi sezione "Requisiti di sicurezza".
- **Sicurezza AI** (se il progetto include componenti AI/ML):
  ETSI EN 304 223 (baseline di cybersecurity per modelli e sistemi AI).
- **IoT** (se il progetto include dispositivi consumer connessi):
  ETSI EN 303 645.
Nei documenti di specifica, dichiara esplicitamente a quali di questi
standard il documento è conforme e in quale sezione.

## Header dei file sorgente
Ogni file sorgente nuovo inizia con questo header (adattato alla sintassi
di commento del linguaggio):

    # -----------------------------------------------------------------
    # <nome file> — <descrizione in una riga>
    # Autore: <autore>
    # Data creazione: <YYYY-MM-DD>
    # Copyright (c) 2024-26 DS Consulting
    # Licenza: MIT
    # -----------------------------------------------------------------

Quando modifichi un file esistente NON riscrivere l'header: aggiorna solo,
se presente, il campo "Ultima modifica". Il testo completo della licenza
MIT sta nel file LICENSE alla radice del repo, non negli header.

## Documentazione e manuali software
- I manuali (utente, installazione, amministrazione) vanno prodotti come
  file **.docx** usando gli **stili predefiniti di Word** (Titolo 1/2/3,
  Normale, Didascalia): mai formattazione diretta al posto degli stili,
  così sommario e numerazione restano automatici.
- Font: famiglia **PT Sans** — corpo del testo in **PT Sans Narrow 19pt**;
  titoli in PT Sans Narrow / PT Sans Narrow Italic / PT Sans Bold /
  PT Sans Bold Italic secondo il livello.
- Ogni manuale include: frontespizio, sommario automatico, numerazione
  pagine, versione del software documentato e data.
- I contenuti seguono la struttura documentale della ISO/IEC/IEEE 29148
  dove applicabile (scopo, riferimenti, definizioni, requisiti/istruzioni).

## Interfaccia utente
- **Tabelle**: tutte le tabelle dati usano **DataTables.js** (integrazione
  Bootstrap 5) con ordinamento, paginazione e ricerca generale abilitati;
  processing server-side obbligatorio sopra le 1.000 righe. Localizzazione
  italiana dei testi del componente.
- **Dialoghi e conferme**: usa **Awesome Notifications (AWN)** per
  conferme (`.confirm()`), avvisi ed esiti delle operazioni (successo,
  errore, warning). Mai `alert()`/`confirm()` nativi del browser.
  Ogni azione distruttiva (eliminazione, sovrascrittura) richiede
  SEMPRE un `.confirm()` prima di procedere.
- AWN e DataTables installati localmente via npm con versione pinnata
  (regola no-CDN del progetto).

## Robustezza dei file strutturati
- Quando scrivi o riscrivi file JSON, XML, HTML, CSS, JS, YAML: verifica
  la validità sintattica PRIMA di consegnare (parser/linter: `python -m
  json.tool`, `xmllint`, validazione HTML, `ruff`/`eslint`).
- Quando modifichi un file esistente, fai modifiche mirate: non riscrivere
  l'intero file se basta cambiare una sezione, per evitare di introdurre
  errori (tag non chiusi, virgole mancanti, encoding).
- I file JSON di configurazione devono avere uno schema o un esempio
  commentato di riferimento nel repo.

## Notifiche
- Ogni applicazione del progetto integra SEMPRE il modulo di notifiche
  Gmail + bot Telegram descritto nella sezione "Sistema di notifiche",
  come minimo per: errori critici, esito dei job schedulati, generazione
  report completata.

## Come lavorare

- Modifiche piccole e mirate: non rifattorizzare codice non richiesto.
- Se un test fallisce, sistemare la causa — mai disabilitare o adattare il test per farlo passare.
- Dopo una modifica, esegui lint e test prima di dire che e' finita.
- Se una richiesta e' ambigua e le interpretazioni portano a lavori diversi, chiedi prima di partire.
- Prima di iniziare un nuovo task, assicurati di aver capito completamente le specifiche e di avere tutto il necessario per completarlo.
- Assicurati di aver compreso il task e fai domande chiarificatrici se necessario. 
- Documenta sempre il tuo lavoro in modo chiaro e conciso.
- Segui sempre le convenzioni del progetto e assicurati di non violare nessuna delle regole stabilite.
- Non introdurre nuove dipendenze senza chiedere prima.
- Non introdurre modifiche non richieste.
- Segui sempre lo stile del file che stai modificando (naming, indentazione, pattern) anche se differisce dal resto.
- Niente commenti che spiegano l'ovvio: commenta il *perche'*, non il *cosa*.
- Errori: gestione esplicita, niente `catch` vuoti o silenziosi.

## Git

- Branch di lavoro, mai commit diretti su `main`.
- Commit e push solo se richiesto esplicitamente.
- Messaggi di commit brevi, in inglese, all'imperativo (`add`, `fix`, `refactor`).

# Layout e interfaccia web: AdminLTE 4.3.1

L'interfaccia web del progetto deve essere basata su **AdminLTE 4.3.1**
(Bootstrap 5.3), usato in maniera evoluta e non come semplice copia-incolla
dei template demo.

## Versione e installazione
- Versione bloccata: `admin-lte@4.3.1` installata via npm con lockfile,
  NON caricata da CDN (gli asset devono essere serviti localmente, requisito
  di supply chain e di funzionamento in ambienti PA senza accesso internet).
- Nessuna dipendenza da jQuery: AdminLTE 4 è vanilla JS + Bootstrap 5,
  eventuali plugin scelti devono rispettare questo vincolo.
- Build degli asset con bundler (Vite o esbuild): importare solo i moduli
  effettivamente usati, non il bundle completo.

## Uso evoluto (non da demo)
- **Personalizzazione via SCSS**, non con override CSS sparsi: creare un
  entry point SCSS che importa i sorgenti di AdminLTE e ridefinisce le
  variabili (palette istituzionale, radius, spacing, font) PRIMA degli
  import. La palette deve essere la stessa dei report PDF, per coerenza
  visiva tra web e reportistica.
- **Tema chiaro/scuro** nativo tramite `data-bs-theme`, con toggle
  persistito (senza flash of wrong theme al caricamento).
- **Layout**: sidebar collassabile (mini sidebar) con stato persistito,
  header sticky, breadcrumb su ogni pagina, footer con versione applicativo.
- **Componenti da usare in modo semantico**:
  - `small-box` / `info-box` solo per KPI e contatori in dashboard;
  - `card` con header, tools (collapse/refresh) e overlay di caricamento
    per ogni blocco dati;
  - `timeline` per log eventi e cronologia notifiche;
  - badge di stato con colori coerenti (success/warning/danger) mappati
    a stati applicativi documentati.
- **Tabelle dati**: integrare una datatable moderna compatibile con
  Bootstrap 5 (ordinamento, ricerca, paginazione server-side per dataset
  grandi), con esportazione che riusa il modulo di reportistica PDF
  anziché l'export client-side.
- **Form**: validazione Bootstrap nativa (`was-validated`) lato client
  SEMPRE affiancata dalla validazione server-side; feedback di errore
  esplicito per campo.
- **Toast e notifiche UI**: usare i toast Bootstrap per gli esiti delle
  operazioni (incluso l'esito degli invii Gmail/Telegram), mai `alert()`.

## Struttura dei template
- Template engine server-side (Jinja2 o equivalente) con un layout base
  (`base.html`) che definisce sidebar, header, footer e blocchi
  (`content`, `page_title`, `breadcrumb`, `extra_js`): ogni pagina estende
  il base, MAI markup di layout duplicato tra pagine.
- Voci di menu della sidebar generate da una struttura dati centralizzata
  (con permessi/ruoli per voce), non hardcoded nell'HTML.
- Evidenziazione automatica della voce di menu attiva in base alla route.

## Requisiti trasversali
- Responsive reale: dashboard usabile anche da tablet/mobile
  (sidebar off-canvas sotto il breakpoint lg).
- Accessibilità: contrasti conformi WCAG 2.1 AA, attributi ARIA sui
  componenti interattivi, navigazione da tastiera funzionante.
- Nessuno script inline: JS in file esterni per consentire una
  Content-Security-Policy restrittiva coerente con i requisiti di
  sicurezza del progetto.
- Icone: Bootstrap Icons o Font Awesome installate localmente,
  stessa regola no-CDN.

# Requisiti di sicurezza e conformità normativa

Tutto il codice prodotto in questo progetto deve essere conforme al quadro
normativo europeo in materia di cybersecurity. In particolare:

## Quadro normativo di riferimento
- **Direttiva NIS2 (UE 2022/2555)** e recepimento italiano (D.lgs. 138/2024):
  gestione del rischio, sicurezza della supply chain, notifica incidenti.
- **Cyber Resilience Act (UE 2024/2847)**: security-by-design e by-default,
  gestione delle vulnerabilità per l'intero ciclo di vita del prodotto.
- **GDPR (UE 2016/679)**: privacy by design/by default, minimizzazione dei
  dati, pseudonimizzazione ove possibile.
- **Linee guida ACN e AgID** per lo sviluppo sicuro nella PA italiana
  (incluse le "Linee guida per lo sviluppo del software sicuro").
- **OWASP ASVS / OWASP Top 10** come baseline tecnica di verifica.

## Regole vincolanti per il codice

### Input e output
- Valida SEMPRE ogni input esterno (utente, API, file, variabili d'ambiente)
  con allowlist, mai con blocklist.
- Usa query parametrizzate / prepared statements: mai concatenazione di
  stringhe in SQL.
- Applica output encoding contestuale (HTML, JS, URL) per prevenire XSS.

### Autenticazione e segreti
- MAI credenziali, API key, token o segreti hardcoded nel codice o nei log.
  Usa variabili d'ambiente o un secret manager.
- Password: solo hashing con algoritmi moderni (argon2id, bcrypt, scrypt).
  Mai MD5, SHA1 o hash non salati.
- Sessioni e token: scadenza esplicita, invalidazione al logout, cookie
  con flag Secure, HttpOnly, SameSite.

### Crittografia
- Solo algoritmi e protocolli attuali: TLS ≥ 1.2 (preferire 1.3),
  AES-256-GCM, RSA ≥ 3072 o curve ellittiche (Ed25519, P-256).
- Mai implementare crittografia custom: usa librerie standard mantenute.
- Dati personali a riposo cifrati quando il contesto lo richiede (GDPR art. 32).

### Gestione errori e logging
- Mai esporre stack trace, versioni, path interni o dettagli tecnici
  all'utente finale.
- Log strutturati e sufficienti a supportare la notifica incidenti NIS2
  (chi, cosa, quando), ma SENZA dati personali o segreti nei log.

### Dipendenze e supply chain
- Preferisci dipendenze mantenute attivamente e con versioni pinnate
  (lockfile obbligatorio).
- Segnala se una dipendenza suggerita ha CVE note o è deprecata.
- Prevedi la possibilità di generare un SBOM (es. formato CycloneDX),
  come richiesto dal Cyber Resilience Act.

### Privilegi e configurazione
- Principio del minimo privilegio ovunque: utenti DB dedicati, container
  non-root, permessi file restrittivi.
- Configurazioni sicure di default (secure by default): funzionalità
  rischiose disattivate se non esplicitamente richieste.
- Nei Dockerfile: immagini base minimali e aggiornate, no segreti in build.

## Comportamento atteso
- Se una richiesta comporta un trade-off di sicurezza, segnalalo
  esplicitamente prima di procedere.
- Se il codice tratta dati personali, indica le implicazioni GDPR
  (base giuridica, minimizzazione, retention) nei commenti o nella risposta.
- In caso di dubbio tra soluzione più semplice e più sicura, scegli
  la più sicura e spiega il motivo.

  # Reportistica PDF e sistema di notifiche

## Reportistica PDF

Il progetto deve includere un modulo di generazione report in PDF con
aspetto serio e professionale, adatto a contesti aziendali e PA.

### Requisiti grafici e di layout
- Layout pulito e sobrio: palette limitata (2-3 colori istituzionali),
  font leggibili (es. Inter, Source Sans, Roboto), niente elementi decorativi
  superflui.
- Struttura obbligatoria di ogni report:
  - copertina con titolo, data di generazione, autore/sistema, eventuale logo;
  - intestazione e piè di pagina su ogni pagina (titolo documento,
    numerazione "Pagina X di Y", data);
  - sommario automatico se il report supera le 5 pagine;
  - sezioni con gerarchia tipografica chiara (H1/H2/H3 coerenti).
- Tabelle con righe alternate, intestazioni ripetute a ogni cambio pagina,
  numeri allineati a destra con separatori di migliaia in formato italiano.
- Grafici (se presenti) vettoriali o ad alta risoluzione, con legenda
  e fonte dei dati.
- Gestione corretta dei salti pagina: mai spezzare una tabella a metà riga,
  mai un titolo orfano a fine pagina.

### Requisiti tecnici
- Genera i PDF da template HTML/CSS renderizzati (es. WeasyPrint o
  Playwright/Chromium in headless), NON costruendo il PDF a basso livello,
  così i template restano manutenibili.
- Separa dati e presentazione: i template (Jinja2 o equivalente) non devono
  contenere logica di business.
- Ogni report deve riportare metadati PDF corretti (titolo, autore, data)
  e un identificativo univoco di generazione tracciato nei log.
- I report possono contenere dati personali o riservati: salvali in
  directory con permessi restrittivi e prevedi una retention configurabile
  con cancellazione automatica.

## Sistema di notifiche (Gmail + Telegram)

Il progetto deve includere un modulo di notifiche unificato, con
un'interfaccia comune (`Notifier`) e due implementazioni: email via Gmail
e messaggi via bot Telegram.

### Architettura
- Un'unica astrazione (es. classe base o protocollo `Notifier` con metodo
  `send(subject, body, attachments)`) e implementazioni `GmailNotifier`
  e `TelegramNotifier` intercambiabili.
- Canali attivabili/disattivabili da configurazione, senza modifiche
  al codice.
- Coda di invio con retry ed exponential backoff in caso di errore di rete
  o rate limit; un fallimento su un canale NON deve bloccare l'altro.
- Log di ogni invio (canale, destinatario, esito, timestamp) senza mai
  registrare il contenuto completo del messaggio se contiene dati personali.

### Gmail
- Autenticazione: OAuth2 con Gmail API oppure SMTP con App Password;
  MAI la password dell'account in chiaro. Credenziali solo da variabili
  d'ambiente o secret manager.
- Connessione sempre cifrata (TLS); mai fallback a connessioni in chiaro.
- Supporto a messaggi HTML con fallback plain text e ad allegati
  (inclusi i report PDF generati), rispettando il limite di 25 MB.
- Rispetta i limiti di invio di Gmail: throttling configurabile e gestione
  esplicita degli errori 4xx/5xx.

### Telegram (bot)
- Usa la Bot API ufficiale; il token del bot solo da variabile d'ambiente.
- I `chat_id` dei destinatari in configurazione, mai hardcoded.
- Supporto a messaggi formattati (MarkdownV2 o HTML, con escaping corretto
  dei caratteri speciali) e invio documenti (`sendDocument`) per i PDF,
  rispettando il limite di 50 MB.
- Gestione del rate limit di Telegram (errore 429 + `retry_after`).
- Il bot deve ignorare/rifiutare messaggi in ingresso da chat non
  autorizzate (allowlist di chat_id).

### Regole comuni di sicurezza
- Nessun segreto (token bot, credenziali Gmail) nel codice, nei log
  o nei messaggi di errore.
- Contenuto delle notifiche: minimizza i dati personali; per informazioni
  sensibili invia un riferimento (link o ID) invece del dato completo.
- Prevedi un flag "dry-run" che simula gli invii in ambiente di sviluppo
  senza contattare i servizi reali.