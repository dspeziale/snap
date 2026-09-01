<!--
  snap - Processi del ciclo di vita del sistema.
  Conforme all'impostazione di ISO/IEC/IEEE 15288:2015 (System life cycle processes).

  remarks: Autore: Daniele Speziale - Data: 2026-08-26
  copyright: (c) 2024-26 DS Consulting
  license: MIT
-->

# snap - Processi del ciclo di vita

| Voce | Valore |
|---|---|
| Sistema | snap - Secure Network Assessment Platform |
| Versione | 1.1.0 |
| Data | 2026-08-27 |
| Autore | Daniele Speziale |
| Standard | ISO/IEC/IEEE 15288:2015 |

---

## 1. Processi tecnici

### 1.1 Definizione dei requisiti degli stakeholder (6.4.2)
Esito documentato in `01_REQUISITI.md`, sezione 2 (requisiti SH-01..SH-09).
Fonte: richiesta iniziale del committente. Le ambiguita' risolte in fase di
definizione sono registrate nella sezione 5 del presente documento.

### 1.2 Definizione dei requisiti di sistema (6.4.3)
Esito in `01_REQUISITI.md`, sezioni 3 e 4 (SR-01..SR-34d, NFR-01..NFR-13), con
indicazione del metodo di verifica per ciascun requisito.

### 1.3 Definizione dell'architettura (6.4.4)
Esito in `02_ARCHITETTURA.md`: viste di contesto, componenti, dinamica, dati e
distribuzione; decisioni architetturali AD-01..AD-12 con alternative valutate.

### 1.4 Definizione del progetto di dettaglio (6.4.5)
- Protocollo applicativo: `03_PROTOCOLLO_SNAP_SEC.md`.
- Modello relazionale: `server/snapserver/schema.sql` (commentato).
- Struttura del codice: sezione 2 del presente documento.

### 1.5 Realizzazione (6.4.7)
Convenzioni applicate:
- identificatori e codice in inglese, commenti e documentazione in italiano;
- intestazione di ogni file con autore, data, copyright e licenza MIT;
- gestione esplicita degli errori: nessun blocco di cattura silenzioso;
- commenti limitati alla motivazione delle scelte non evidenti.

### 1.6 Integrazione (6.4.8)
I due applicativi si integrano esclusivamente attraverso SNAP-SEC/1. Il test di
integrazione (`tests/test_probe_server_flow.py`) instrada il client della sonda
sul client di test del server, verificando il contratto senza dipendenze di rete.

### 1.7 Verifica (6.4.9)
| Livello | Strumento | Copertura |
|---|---|---|
| Unita' | `tests/test_crypto_channel.py` | Primitive e formato della busta |
| Integrazione | `tests/test_probe_server_flow.py` | Registrazione, autonomia, conferimento, comandi, revoca |
| Sistema | `tests/test_multitenancy.py` | Isolamento, autenticazione, MFA, ruoli, eliminazione dei tenant |
| Sistema | `tests/test_timezones.py` | Normalizzazione oraria, confini di giornata, ora legale |
| Sistema | `tests/test_probe_interface.py` | Interfaccia della sonda: registrazione e sostituzione |
| Sistema | `tests/test_interfaccia.py` | Dotazione delle tabelle e dialogo con l'utente |
| Sistema | `tests/test_sessione.py` | Tenuta della sessione durante la navigazione |
| Sistema | `tests/test_perimetro.py`, `tests/test_scanner.py`, `tests/test_fingerprint.py`, `tests/test_snmp.py` | Perimetro, scansione progressiva, riconoscimento, lettura SNMP |
| Sistema | `tests/test_filtri_inventario.py` | Filtri e mappa dell'inventario |
| Sistema | `tests/test_controlli.py`, `tests/test_regole.py`, `tests/test_notifiche.py` | Controlli, incidenti, motore delle regole, canali |
| Sistema | `tests/test_report.py` | Undici generi di report, resoconto quotidiano, archivio ed eliminazione |
| Sistema | `tests/test_threat.py` | Catalogo delle vulnerabilita' e correlazione in tre classi |
| Sistema | `tests/test_zone.py` | Zone di rete: giudizio, aggravamento, riapertura, precedenza della decisione umana |
| Sistema | `tests/test_sala_operativa.py` | Quadri NOC e SOC, silenzio contro mancata interrogazione, ricerca ed esportazione |
| Sistema | `tests/test_guida.py` | Completezza della guida in linea rispetto al proprio indice |
| Sistema | `tests/test_manutenzione.py`, `tests/test_azzeramento.py` | Conservazione, copie, ripristino, azzeramento |
| Manuale | `tools/collaudo_ui.py` | Comportamento nel browser (tabelle e notifiche) |

Esecuzione: `python -m pytest tests -v` oppure `.\start.ps1 -Test`.

Criterio di accettazione: tutti i test superati; ogni requisito della sezione 3
di `01_REQUISITI.md` associato ad almeno un metodo di verifica.

### 1.8 Transizione (6.4.10)
Procedura in `05_MANUALE_OPERATIVO.md`, sezioni 2 e 3: preparazione ambiente,
inizializzazione della base dati, primo accesso, registrazione della prima sonda.

### 1.9 Validazione (6.4.11)
Scenari di validazione operativa:

| ID | Scenario | Esito atteso |
|---|---|---|
| VAL-01 | Registrazione di una sonda e primo conferimento | La sonda risulta in contatto e il lotto compare fra i conferimenti della dashboard entro un ciclo di raccolta |
| VAL-02 | Arresto del server per un periodo prolungato | La sonda continua a raccogliere; la coda locale cresce; nessun dato perduto |
| VAL-03 | Riavvio del server | La coda viene conferita e svuotata senza duplicazioni |
| VAL-04 | Accesso di due utenti di tenant differenti | Ciascuno vede solo le proprie sonde, con orari nel rispettivo fuso |
| VAL-05 | Sostituzione della registrazione di una sonda con un nuovo pacchetto | La sonda opera sul nuovo tenant; con pacchetto non valido la registrazione precedente e' ripristinata |
| VAL-06 | Revoca di una sonda | Il conferimento e' rifiutato; l'evento e' tracciato nell'audit |

### 1.10 Esercizio (6.4.12)
- Avvio e arresto: `start.ps1` / `start.sh`.
- Sorveglianza lato server: sezione *Sonde*, registro *Audit & Eventi* e area
  indicatori della dashboard.
- Sorveglianza lato sonda: pagina di stato e diario locale.

### 1.11 Manutenzione (6.4.13)
| Attivita' | Periodicita' suggerita | Modalita' |
|---|---|---|
| Applicazione della politica di conservazione | Mensile | *Impostazioni Sistema > Applica conservazione* (registro eventi e conferimenti) |
| Verifica delle sonde non raggiungibili | Settimanale | Elenco flotta sonde |
| Riesame delle utenze e dei ruoli | Trimestrale | *Utenti* |
| Rinnovo delle credenziali di una sonda | A ogni reinstallazione | *Nuovo token* nella scheda sonda |
| Salvataggio dei dati | Giornaliera | Copia di `server/data/` con servizio arrestato |
| Aggiornamento delle dipendenze | Semestrale | `pip install -U -r requirements` e riesecuzione dei test |

### 1.12 Dismissione (6.4.14)
- Dismissione di un tenant: eliminazione dalla console (rimozione in cascata di
  utenti, sonde, conferimenti e registro di audit). L'evento resta tracciato come
  evento globale.
- Dismissione di una sonda: revoca, quindi eliminazione dalla scheda; sul
  dispositivo, azzeramento della registrazione e rimozione di `probe/data/`.
- Dismissione del sistema: arresto dei processi, salvataggio o distruzione
  documentata di `server/data/` e `server/instance/`.

---

## 2. Struttura di configurazione

```
snap/
├── LICENSE                     Licenza MIT
├── CLAUDE.md                   Istruzioni di progetto
├── pytest.ini                  Configurazione dei test
├── requirements-dev.txt        Dipendenze di sviluppo
├── start.ps1                   Avvio completo (Windows PowerShell)
├── start.sh                    Avvio completo (shell POSIX)
├── docs/
│   ├── 01_REQUISITI.md         Specifica dei requisiti (29148)
│   ├── 02_ARCHITETTURA.md      Architettura e diagrammi (19510)
│   ├── 03_PROTOCOLLO_SNAP_SEC.md  Specifica del canale cifrato
│   ├── 04_CICLO_DI_VITA.md     Processi di ciclo di vita (15288)
│   ├── 05_MANUALE_OPERATIVO.md Installazione ed esercizio
│   ├── 06_INVENTARIO_E_MONITOR.md  Perimetro, scansione, riconoscimento, SNMP
│   ├── 07_CONTROLLI.md         Controlli periodici, incidenti, metriche
│   ├── 08_REPORT.md            Catalogo dei report e resoconto quotidiano
│   ├── 09_REGOLE_CANALI_MANUTENZIONE.md  Regole, notifiche, conservazione
│   ├── 10_THREAT_INTELLIGENCE.md   Catalogo CVE e correlazione
│   ├── 11_SALA_OPERATIVA.md    Quadri NOC e SOC, ricerca nella base dati
│   ├── 12_ZONE_DI_RETE.md      Contesto delle subnet e giudizio delle esposizioni
│   └── docx/                   Manuali generati in formato Word
├── server/
│   ├── requirements.txt
│   ├── run.py                  Punto di avvio e comando di inizializzazione
│   ├── data/                   Base dati (generata)
│   ├── instance/               Chiave di sessione persistente (generata)
│   └── snapserver/
│       ├── __init__.py         Factory dell'applicazione
│       ├── settings.py         Configurazione
│       ├── schema.sql          Modello relazionale
│       ├── db.py               Accesso ai dati e utilita' temporali
│       ├── crypto.py           SNAP-SEC/1 lato server
│       ├── security.py         Password, ruoli, TOTP
│       ├── tenancy.py          Contesto tenant e fusi orari
│       ├── audit.py            Registro eventi
│       ├── ingest.py           Applicazione dei lotti conferiti
│       ├── queries.py          Letture aggregate e indicatori
│       ├── inventory_queries.py Letture dell'inventario, filtri, mappa
│       ├── checks_queries.py   Letture dei controlli e andamenti
│       ├── fingerprint.py      Riconoscimento dei dispositivi
│       ├── snmp_tables.py      Letture SNMP dalla forma di terminale alla tabella
│       ├── threat.py           Correlazione in tre classi
│       ├── threat_sources.py   Aggiornamento del catalogo (NVD, CISA KEV, ATT&CK)
│       ├── zones.py            Zone di rete: catalogo e giudizio
│       ├── operations.py       Quadri NOC e SOC
│       ├── searchdb.py         Ricerca libera e interrogazioni pronte
│       ├── rules.py, events.py Motore delle regole
│       ├── notifications.py    Coda di spedizione; channels.py posta e Telegram
│       ├── maintenance.py      Conservazione, copie, ripristino
│       ├── reports/            Dati, resa PDF, archivio, resoconto
│       ├── seed.py             Dati iniziali
│       ├── blueprints/         Rotte dell'interfaccia e canale sonde
│       ├── templates/          Viste (AdminLTE 4.3.1)
│       └── static/             Fogli di stile, script e librerie locali
├── probe/
│   ├── requirements.txt
│   ├── run.py                  Avvio, registrazione da riga di comando, stato
│   ├── data/                   Archivio locale (generato)
│   └── snapprobe/
│       ├── __init__.py         Factory dell'applicativo sonda
│       ├── settings.py         Configurazione
│       ├── crypto.py           SNAP-SEC/1 lato sonda (implementazione autonoma)
│       ├── store.py            Archivio locale: coda, chiavi, diario
│       ├── client.py           Trasporto verso il server
│       ├── collector.py        Raccolta (annotazioni diagnostiche)
│       ├── agent.py            Ciclo autonomo
│       ├── views.py            Interfaccia di registrazione e configurazione
│       ├── templates/          Viste
│       └── static/             Fogli di stile, script e librerie locali
├── tools/
│   ├── collaudo_ui.py          Collaudo dell'interfaccia in un browser reale
│   └── genera_manuale.py       Manuali .docx in PT Sans Narrow 19pt
└── tests/                      Suite di verifica
```

---

## 3. Gestione della configurazione

| Elemento | Regola |
|---|---|
| Versione applicativa | `APP_VERSION` in `settings.py` di ciascun componente |
| Versione del protocollo | `PROTOCOL_VERSION` in entrambi i moduli crittografici: una modifica non retrocompatibile richiede un nuovo identificatore (`SNAP-SEC/2`) |
| Schema della base dati | `schema.sql`, applicato in modo idempotente all'avvio |
| Segreti | Mai nel controllo di versione: `server/instance/`, `probe/data/` e le variabili d'ambiente sono esclusi |
| Dipendenze | Fissate in `requirements.txt` per componente |

Compatibilita' fra versioni: sonda e server devono condividere lo stesso
`PROTOCOL_VERSION`; una sonda con versione diversa riceve
`protocol_error` e resta in attesa, conservando i dati raccolti.

---

## 4. Gestione dei rischi

| ID | Rischio | Impatto | Mitigazione realizzata |
|---|---|---|---|
| RI-01 | Sottrazione del token di registrazione | Registrazione di una sonda non autorizzata | Token monouso con scadenza; conservato solo come impronta; revoca disponibile |
| RI-02 | Compromissione del dispositivo che ospita la sonda | Accesso alla chiave di sessione | Revoca dalla console; nessun privilegio della sonda oltre al conferimento nel proprio tenant |
| RI-03 | Intercettazione del traffico | Riservatezza dei dati | Cifratura applicativa AES-256-GCM indipendente dal trasporto |
| RI-04 | Ripetizione di messaggi catturati | Alterazione dei dati | Registro dei nonce e finestra temporale |
| RI-05 | Errore di isolamento fra tenant | Divulgazione a terzi | Filtro `tenant_id` in ogni istruzione; verifiche automatiche dedicate |
| RI-06 | Indisponibilita' prolungata del server | Perdita di rilevazioni | Coda locale persistente sulla sonda con prenotazione dei lotti |
| RI-07 | Crescita illimitata dell'archivio | Esaurimento dello spazio | Politica di conservazione per tenant; diario e storico locali limitati |
| RI-08 | Smarrimento del dispositivo con secondo fattore | Blocco dell'utenza | Azzeramento MFA da parte dell'amministratore |
| RI-09 | Duplicazione dei dati per ritrasmissione | Registro non attendibile | Identificativo di lotto univoco e riconoscimento dei duplicati |
| RI-10 | Interruzione del thread dell'agente | Sonda inattiva senza segnalazione | Cattura degli errori nel ciclo, registrazione nel diario, indicatore di stato nell'interfaccia |

---

## 5. Registro delle decisioni assunte in assenza di specifica

| ID | Punto aperto | Decisione | Motivazione |
|---|---|---|---|
| DEC-01 | Modalita' di cifratura del canale | Cifratura applicativa end-to-end (opzione confermata dal committente) | Nessuna gestione di certificati; indipendenza dal trasporto |
| DEC-02 | Presentazione del QR per l'MFA | Libreria `qrcode` (installazione confermata dal committente) | Procedura di attivazione MFA immediata per l'utente |
| DEC-03 | Natura dei dati raccolti | Annotazioni diagnostiche sul funzionamento della sonda | Su indicazione del committente il dominio di inventario e' stato rimosso: i contenuti verranno definiti con le funzioni successive |
| DEC-04 | Tenant iniziali | Due tenant dimostrativi con fusi orari differenti (Europe/Rome, America/New_York) | Rende verificabile l'isolamento e la normalizzazione oraria |
| DEC-05 | Protezione dell'interfaccia della sonda | Ascolto su `127.0.0.1`, senza autenticazione propria | L'interfaccia e' strumento locale di installazione; la superficie di attacco resta nulla dall'esterno |
| DEC-05a | Apertura dell'interfaccia della sonda alla rete | Possibile su richiesta esplicita (`start.ps1 -ProbeHost <indirizzo>`), mai per difetto, con l'avviso stampato a ogni avvio | Chiesta per l'amministrazione da un'altra postazione. Resta vero cio' che dice DEC-05: senza autenticazione, chi raggiunge quell'interfaccia puo' registrare la sonda, riconfigurarla o sospendere le scansioni. La scelta e' di chi la compie, quindi il rischio va dichiarato dove la scelta si compie -- non solo nella documentazione -- e la mitigazione suggerita e' la limitazione a un solo indirizzo di origine sul firewall. Un'autenticazione propria della sonda resta da progettare |
| DEC-11 | Accesso all'interfaccia della sonda | **Una password**, credenziale unica senza utenti ne' ruoli; hash scrypt; 5 tentativi e blocco di 15 minuti; prima impostazione ammessa **solo dall'indirizzo locale**; nessuna password di fabbrica | Da quando la sonda si apre alla rete (DEC-05a), la premessa di DEC-05 non vale piu': senza credenziali chi la raggiunge la riconfigura. Una sola credenziale perche' la sonda ha un solo operatore e un modello a piu' utenti aggiungerebbe amministrazione senza aggiungere sicurezza. Nessuna password predefinita perche' una credenziale di fabbrica e' la prima cosa che si prova su un dispositivo trovato in rete. Prima impostazione in locale perche', se la sonda e' gia' esposta, non deve poter scegliere la credenziale il primo che arriva |
| DEC-14 | Deroga alla regola "solo GET" per IPP | La lettura degli attributi di una stampante avviene con un **POST**, ristretto all'operazione `Get-Printer-Attributes` scritta come costante del modulo | Senza questa lettura 382 apparati su una rete reale restano senza modello e senza numero di serie: le loro interfacce web sono costruite in JavaScript e non servono dati in HTML. IPP e' il modo in cui qualunque sistema operativo identifica una stampante, e l'operazione usata e' di sola lettura per specifica. La regola generale resta valida: la deroga e' una, dichiarata, verificata da una prova che controlla il codice dell'operazione e l'assenza di attributi relativi ai lavori |
| DEC-13 | Lettura delle pagine di gestione | La lettura **naviga dentro l'apparato** -- redirezioni, meta refresh, salto in JavaScript, frame, indirizzi informativi noti della famiglia -- invece di fermarsi alla radice; solo GET, con due elenchi di verbi vietati e un tetto di pagine e di tempo | Su una multifunzione in esercizio la radice restituisce 577 byte e nessun dato: modello, posizione fisica e nome host stanno tre pagine piu' avanti, dentro un frame. Fermarsi alla radice significa non sapere niente di un apparato che dichiara tutto. Il rischio -- chiedere per sbaglio un indirizzo che compie un'azione -- si governa con i vincoli, non chiudendo la funzione |
| DEC-12 | Intestatario del copyright | **2024-26 DS Consulting** in entrambi gli applicativi, nelle intestazioni dei sorgenti, nei pie' di pagina delle interfacce, nei report PDF e nella licenza | Le forme sedimentate erano quattro; un prodotto che si presenta con tre intestatari diversi a seconda della pagina non e' credibile davanti a un cliente |
| DEC-10 | Uscita dei componenti all'avvio assistito | Resta nella finestra del componente; il diario su file lo scrive l'applicazione (`SNAP_*_LOG_FILE`) | Deviando entrambi i flussi su file, le finestre aperte da Windows per i processi di console restavano vuote per costruzione: sembrava che il prodotto non fosse partito mentre era in ascolto. Un avvio deve mostrare cio' che fa |
| DEC-06 | Insieme dei ruoli | Consultazione, analista, amministratore di tenant, amministratore di sistema | Copre la separazione dei compiti richiesta senza complessita' superflue |
| DEC-08 | Perimetro dell'interfaccia | Dashboard, sonde, audit, amministrazione | Riduzione richiesta dal committente in prima stesura. **Superata**: inventario, controlli, reportistica, threat intelligence, sala operativa e zone di rete sono stati reintrodotti su richiesta successiva, ciascuno con documento di specifica proprio (`06`..`12`) |
| DEC-09 | Significato di una porta aperta | Il giudizio dipende dalla **zona** dichiarata sulla subnet, con catalogo chiuso nel codice | Lo stesso servizio non ha lo stesso peso in un datacenter e su una postazione: senza contesto l'elenco dei riscontri e' troppo lungo per essere letto. Vedi `12_ZONE_DI_RETE.md` |
| DEC-07 | Porte predefinite | Server 5500, sonda 5510 | Interne all'intervallo 5500-5600 richiesto |
