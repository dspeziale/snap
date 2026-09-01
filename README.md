<!--
  snap - Descrizione del progetto.

  remarks: Autore: Daniele Speziale - Data: 2026-08-26
  copyright: (c) 2024-26 DS Consulting
  license: MIT
-->

# snap - Secure Network Assessment Platform

Sistema **server + sonda** per l'osservazione dello stato di sicurezza di reti
appartenenti a organizzazioni distinte (multi-tenant), con dialogo su **canale
cifrato punto a punto**.

Due proprieta' guidano l'intera architettura:

- **la sonda conosce il server, il server non conosce la sonda**: tutte le
  connessioni sono aperte dalla sonda e nessuna porta in ingresso e' richiesta
  sulla rete osservata;
- **la sonda lavora anche da sola**: in assenza del server continua a raccogliere
  e accumula in una coda locale persistente; quando il server torna disponibile
  conferisce i dati e si svuota, soltanto dopo conferma di acquisizione.

```
snap/
├── server/    console web (sonde, audit, amministrazione) e canale di raccolta  (porta 5500)
├── probe/     agente autonomo con interfaccia di registrazione e configurazione (porta 5510)
├── tests/     suite di verifica (canale cifrato, autonomia, isolamento, interfaccia)
├── tools/     collaudo dell'interfaccia in browser reale, manuali .docx
└── docs/      requisiti, architettura, protocollo, ciclo di vita,
               manuale e specifiche delle aree funzionali (06-12)
```

I due applicativi sono **completamente separati**: nessun codice condiviso, il
protocollo `SNAP-SEC/1` e' il solo contratto fra loro.

---

## Avvio rapido

```powershell
# Windows PowerShell
.\start.ps1 -Setup      # ambiente virtuale, dipendenze, base dati
.\start.ps1             # avvia server (5500) e sonda (5510), solo in locale
.\start.ps1 -Stop       # arresto

# Console raggiungibile dalla rete (vedi docs/05, capitolo 3.1-bis: canale HTTP,
# firewall di Windows, e l'interfaccia della sonda che non ha autenticazione)
.\start.ps1 -ServerHost 10.20.10.42
```

Ogni componente si avvia in una finestra propria che mostra l'avvio e il diario in
tempo reale; lo stesso diario resta in `logs\`.

```bash
# Shell POSIX / Git Bash
./start.sh setup
./start.sh
./start.sh stop
```

| Indirizzo | Componente |
|---|---|
| http://127.0.0.1:5500/ | Console del server |
| http://127.0.0.1:5510/ | Interfaccia locale della sonda |

Credenziali iniziali: `admin@snap.local` / `Snap!Admin2026` (amministratore di
sistema), `admin@ised.local` / `Snap!Tenant2026` (amministratore di tenant).
**Da sostituire al primo accesso.**

### Messa in servizio della prima sonda
1. Console del server: *Sonde & Discovery > Registra sonda*.
2. Copiare il pacchetto `SNAP1-...` mostrato (visibile una sola volta).
3. Interfaccia della sonda: *Registra la sonda*, incollare il pacchetto.
4. La sonda apre il canale cifrato e comincia a conferire i dati.

---

## Funzioni

### Server
- **Dashboard**: riquadri di sintesi (sonde censite, in attesa di registrazione,
  conferimenti ed eventi nelle 24 ore), area indicatori operativi, stato della
  flotta, ultimi conferimenti, attivita' recente.
- **Sonde**: flotta con stato di raggiungibilita', emissione e rinnovo dei token,
  configurazione, coda dei comandi, revoca.
- **Audit**: registro delle operazioni e degli eventi per tenant, con l'attore di
  ogni azione; le annotazioni conferite dalle sonde vi confluiscono.
- **Multi-tenant**: isolamento completo dei dati, fuso orario per tenant con
  normalizzazione di tutte le date e ore, politica di conservazione, cancellazione
  in cascata.
- **Utenti**: accesso con sola email e password, secondo fattore TOTP opzionale
  (Google Authenticator), quattro ruoli, blocco per tentativi falliti, azzeramento
  MFA amministrativo.
- **Interfaccia**: AdminLTE 4.3.1 servito localmente, tema chiaro/scuro, quattro
  dimensioni del carattere, due larghezze di pagina, preferenze nel profilo utente.
- **Tabelle**: ogni elenco offre ordinamento sulle colonne (anche su piu' colonne
  con Maiusc+clic), paginazione con dimensione selezionabile e ricerca generale su
  tutte le colonne, con interfaccia in italiano.
- **Dialogo con l'utente**: conferme e messaggi di esito tramite *Awesome
  Notifications*; le azioni irreversibili richiedono conferma esplicita e, per
  l'eliminazione di un tenant, la digitazione del suo codice.
- **Perimetro di scansione**: subnet dichiarate per tenant da file di testo, con
  validazione severa (solo indirizzamento privato salvo deroga, nessuna
  sovrapposizione, reti ampie suddivise in blocchi), attivazione in blocco e
  richiesta di una **passata di scoperta immediata** su una singola subnet.
- **Inventario**: nodi con indirizzo, nome host, MAC e produttore, porte e servizi
  con prodotto e versione, sistema operativo, **tipo di dispositivo con confidenza**
  e le prove che lo motivano; filtri per servizio esposto, porta, lettura SNMP,
  sicurezza, identificazione e ultimo contatto; mappa ad albero delle sonde e del
  perimetro, compreso quello che ancora tace.
- **Letture di approfondimento**: SNMP in sola lettura (interfacce, processi,
  software, collocazione), interfacce **web di gestione** navigate in sola lettura
  per ricavare marca, modello, collocazione e numero di serie, e **IPP** per le
  stampanti; ogni lettura e' scaricabile in PDF e finisce nella scheda dell'apparato.
- **Monitoraggio**: raggiungibilita' e latenza per nodo, scostamenti dell'inventario
  (comparse, scomparse, porte, servizi, identita' cambiate) e storico soggetto alla
  conservazione del tenant.
- **Controlli e incidenti**: controlli periodici per bersaglio con soglie, esiti in
  tre stati, apertura e scalata degli incidenti, presa in carico e chiusura,
  registrazione **a mano** di un incidente che nessuna sonda puo' rilevare.
- **Report**: dodici generi in PDF con la stessa impaginazione (direzione,
  inventario, NOC, SOC, vulnerabilita', conformita', **conformita' europea NIS2 /
  CRA / GDPR**, segmentazione, igiene, incidente, scheda dell'apparato) e resoconto
  quotidiano spedito dal server.
- **Notifiche**: regole per evento e gravita', coda unica con ritentativi, posta
  (Gmail) e bot Telegram, messaggi con una forma sola e senza risorse esterne.
- **Threat Intelligence**: catalogo locale CVE/CWE/KEV/ATT&CK e correlazione in tre
  classi (confermata, da verificare, esposizione), giudicate nel contesto della
  **zona di rete** dichiarata sulla subnet.
- **Sala operativa**: quadro NOC, quadro SOC e ricerca nella base dati.
- **Comunicazioni ACN**: termini dell'art. 23 NIS2 calcolati dalla conoscenza
  dell'incidente, fascicolo con i campi del portale, registro degli invii con il
  protocollo e avvisi di scadenza. Il prodotto prepara e traccia: **non invia** al
  posto del punto di contatto.

### Sonda
- Registrazione con pacchetto unico (o valori separati), da interfaccia o da riga
  di comando.
- Ciclo autonomo: raccolta a intervallo configurato, heartbeat, conferimento,
  esecuzione dei comandi ricevuti.
- Coda locale persistente con prenotazione dei lotti: nessuna perdita in assenza
  del server, nessuna duplicazione in caso di ritrasmissione.
- Diario locale degli eventi e storico dei conferimenti.
- Modalita' non presidiata (`--headless`).
- **Scansione progressiva** del solo perimetro ricevuto: scoperta, porte, servizi,
  sistema operativo, approfondimento, lettura SNMP, lettura delle interfacce di
  gestione (web e IPP), sorveglianza. Ogni fase ha cadenza, tempo massimo e bersaglio
  propri; un bersaglio non dichiarato viene rifiutato e il rifiuto registrato.
- Profilo di sforzo (minimo, medio, massimo) che governa insieme parallelismo e
  profondita'; sospensione delle scansioni dal server o dalla sonda, e prevale la
  piu' restrittiva.
- Conferimento **a profilo completo**: un nodo viene inviato quando tutte le fasi
  applicabili sono state svolte, cosi' il server non riceve mezzi nodi da correggere.
- Esecuzione dei controlli periodici assegnati e annotazioni diagnostiche sul proprio
  funzionamento (ciclo, coda, ambiente).

---

## Canale cifrato (SNAP-SEC/1)

| Fase | Meccanismo |
|---|---|
| Registrazione | Token monouso con scadenza; il server conserva solo l'impronta SHA-256 e la chiave derivata. La sonda dichiara in chiaro unicamente l'impronta del token |
| Scambio di chiavi | X25519, chiave di sessione derivata con HKDF-SHA256 |
| Scambi successivi | Busta AES-256-GCM con dati associati che legano versione, identita', nonce, marca temporale e rotta |
| Autenticazione | Possesso della chiave di sessione **e** API key trasportata nel payload cifrato |
| Anti-replay | Registro dei nonce per sonda e finestra temporale di 5 minuti |
| Comandi | Accodati sul server e consegnati in risposta a un contatto della sonda: nessuna connessione verso la sonda |

Specifica completa: [docs/03_PROTOCOLLO_SNAP_SEC.md](docs/03_PROTOCOLLO_SNAP_SEC.md).

---

## Verifica

```bash
python -m pytest tests -v
```

Test automatici su: interoperabilita' e proprieta' di sicurezza del canale
cifrato, registrazione e monouso del token, autonomia della sonda con server
assente, svuotamento della coda dopo conferma, idempotenza delle ritrasmissioni,
consegna dei comandi, efficacia della revoca, isolamento fra tenant ed
eliminazione in cascata, normalizzazione oraria (compresa l'ora legale, e la
presenza del fuso in ogni data mostrata), autenticazione e MFA, interfaccia della
sonda, dotazione delle tabelle e dialogo con l'utente.

E sul dominio: perimetro e rifiuto dei bersagli non dichiarati, ammissione dei nodi
(compreso l'host che nmap abbandona per tempo scaduto, che non e' un host vuoto),
riconoscimento dei dispositivi, lettura SNMP, lettura delle interfacce di gestione e
IPP, controlli e incidenti, regole e canali di notifica, forma dei messaggi di posta,
zone di rete, correlazione delle vulnerabilita', impaginazione dei report (nessuna
informazione tagliata) e percorso delle comunicazioni ACN con i suoi termini.

Il comportamento nel browser (tabelle interattive, conferme e notifiche) si
collauda con:

```bash
python tools/collaudo_ui.py
```

---

## Documentazione

| Documento | Contenuto |
|---|---|
| [01_REQUISITI.md](docs/01_REQUISITI.md) | Requisiti di stakeholder e di sistema, casi d'uso, tracciabilita' (ISO/IEC/IEEE 29148:2018) |
| [02_ARCHITETTURA.md](docs/02_ARCHITETTURA.md) | Viste di contesto, componenti, dinamica, dati, distribuzione; decisioni architetturali (ISO/IEC/IEEE 19510:2013) |
| [03_PROTOCOLLO_SNAP_SEC.md](docs/03_PROTOCOLLO_SNAP_SEC.md) | Specifica del canale cifrato |
| [04_CICLO_DI_VITA.md](docs/04_CICLO_DI_VITA.md) | Processi di ciclo di vita, verifica, manutenzione, rischi (ISO/IEC/IEEE 15288:2015) |
| [05_MANUALE_OPERATIVO.md](docs/05_MANUALE_OPERATIVO.md) | Installazione, avvio, uso, configurazione, diagnostica |
| [06_INVENTARIO_E_MONITOR.md](docs/06_INVENTARIO_E_MONITOR.md) | Perimetro dichiarato, scansione progressiva, riconoscimento dei dispositivi, lettura SNMP, filtri e mappa |
| [07_CONTROLLI.md](docs/07_CONTROLLI.md) | Controlli periodici, soglie, incidenti, metriche e andamenti |
| [08_REPORT.md](docs/08_REPORT.md) | Dodici generi di report PDF (compreso il fascicolo di conformita' europea), resoconto quotidiano, archivio |
| [09_REGOLE_CANALI_MANUTENZIONE.md](docs/09_REGOLE_CANALI_MANUTENZIONE.md) | Motore delle regole, notifiche via posta e Telegram, conservazione e copie |
| [10_THREAT_INTELLIGENCE.md](docs/10_THREAT_INTELLIGENCE.md) | Catalogo locale CVE/CWE/KEV/ATT&CK e correlazione in tre classi |
| [11_SALA_OPERATIVA.md](docs/11_SALA_OPERATIVA.md) | Quadro NOC, quadro SOC, ricerca nella base dati |
| [12_ZONE_DI_RETE.md](docs/12_ZONE_DI_RETE.md) | Zone dichiarate sulle subnet e giudizio contestuale delle esposizioni |
| [13_COMUNICAZIONE_ACN.md](docs/13_COMUNICAZIONE_ACN.md) | Comunicazione degli incidenti all'ACN: termini dell'art. 23 NIS2, fascicolo, registro degli invii |

---

## Tecnologie

Python 3.10+, Flask 3, SQLite (senza ORM: il filtro di tenant resta esplicito in
ogni istruzione), cryptography (X25519 / HKDF / AES-GCM), pyotp e qrcode (MFA).
Interfaccia: AdminLTE 4.3.1 con Bootstrap 5.3 e Bootstrap Icons,
DataTables 3.0.2 per le tabelle, Awesome Notifications 3.1.3 per i dialoghi -
tutte le librerie sono servite localmente e nessuna richiede jQuery. Nessun
servizio esterno richiesto; l'interfaccia funziona senza accesso a Internet.

---

## Convenzione tipografica

Titoli in **PT Sans Narrow** (regolare e grassetto), con **PT Sans** per corsivo
e grassetto corsivo: la famiglia stretta non dispone delle varianti inclinate. I
caratteri sono serviti dal prodotto, senza richieste a servizi esterni.

I manuali software si producono in formato Word con PT Sans Narrow a 19 punti:

```bash
python tools/genera_manuale.py
```

---

## Licenza

MIT - Copyright (c) 2024-26 DS Consulting. Vedere [LICENSE](LICENSE).
