# snap — Sottosistema PSN: il piano di indirizzamento come sistema

| | |
|---|---|
| Documento | Specifica del sottosistema PSN |
| Versione del software | 1.5.0 |
| Data | 2026-09-11 |
| Standard di riferimento | ISO/IEC/IEEE 29148:2018 (requisiti), ISO/IEC/IEEE 15288 (processi) |
| Stato | in esercizio |

---

## 1. Scopo

Il piano di indirizzamento del Polo Strategico Nazionale vive in un foglio di calcolo
di **79 schede**: l'anagrafica delle subnet, una scheda per subnet con **una riga per
indirizzo**, i tenant, i database, i servizi pubblicati e la convenzione dei nomi.

È un documento corretto e leggibile. Proprio per questo non risponde alle domande che
contano:

| Domanda | Perché un foglio non risponde |
|---|---|
| Qual è il **prossimo indirizzo libero** nella subnet dei proxy? | Si scorrono 254 righe con l'occhio, per ogni subnet |
| Questo **hostname esiste due volte**? | 79 schede da confrontare fra loro |
| Due **subnet si sovrappongono**? | Richiede aritmetica su CIDR, non confronto di testo |
| Un indirizzo è **fuori dalla propria subnet**? | Idem, per 17.000 righe |
| Quali **nomi** non rispettano la convenzione? | La convenzione è in un'altra scheda |
| Che cosa sta **dietro un URL pubblico**? | La catena è scritta in prosa, in due schede |
| Che cosa è **cambiato** dalla versione precedente? | Due file dall'aspetto identico |

Il sottosistema legge il documento, ne ricostruisce le relazioni e dichiara ciò che non
torna. **Non modifica il piano**: il documento resta la fonte, e le decisioni restano
a chi lo mantiene.

---

## 2. Separazione dal prodotto (requisito posto all'origine)

Il sottosistema è stato richiesto con una condizione: *«non mescolare nulla con
l'applicazione in corso, per poterla eventualmente eliminare»*. La condizione è
rispettata per costruzione:

| Aspetto | Come |
|---|---|
| Archivio | **Un database distinto**, non uno schema dentro quello del prodotto |
| Vincoli | **Nessuna chiave esterna** verso le tabelle del prodotto, né viceversa |
| Query | **Nessuna query** del sottosistema nomina una tabella del prodotto (verificato da un test) |
| Codice | Un package proprio, `snapserver/psn/` |
| Pagine | Un blueprint proprio (`/psn`) e modelli in `templates/psn/` |
| Menu | Un gruppo proprio nella barra laterale, in un blocco commentato |
| Dipendenze | **Nessuna nuova**: il `.xlsx` si legge con la libreria standard |

**Perché un database e non uno schema.** Uno schema dentro l'archivio del prodotto
finirebbe nelle sue copie di sicurezza, nei suoi conteggi di dimensione e nelle sue
migrazioni. Un database distinto si elimina e non lascia traccia.

Due test difendono questa proprietà, perché una promessa non verificata decade da sé:

- `test_l_archivio_del_prodotto_non_contiene_tabelle_del_psn`
- `test_il_modulo_psn_non_legge_le_tabelle_del_prodotto`

### 2.1 Come si rimuove

```
1. cancellare  server/snapserver/psn/
2. cancellare  server/snapserver/templates/psn/
3. cancellare  tests/test_psn.py
4. in server/snapserver/__init__.py     togliere il blocco "Sottosistema PSN"
5. in templates/partials/sidebar.html   togliere il blocco "SOTTOSISTEMA PSN"
                                        e la riga  {% set in_psn = ... %}
6. in server/snapserver/settings.py     togliere PSN_DATABASE_URL e PSN_OWNER_DATABASE_URL
7. DROP DATABASE snap_psn;
```

Nessun altro file va toccato, e l'archivio del prodotto non viene sfiorato.

---

## 3. Archivio

L'indirizzo si **deriva** da quello del prodotto cambiando il solo nome del database
(`snap` → `snap_psn`), così un'installazione esistente non deve configurare nulla e le
credenziali non si duplicano in un secondo segreto. Si può dichiarare esplicitamente
con `SNAP_SERVER_PSN_DATABASE_URL`.

Il database **si crea da sé** alla prima apertura della sezione, con l'utenza
proprietaria, e ci applica il proprio schema: un sottosistema che pretende un
`createdb` a mano prima di funzionare non è installato, è da installare.

### 3.1 Modello dei dati

Tutto è legato a un **conferimento** (`psn_import`): il piano ha una versione, e
conservare le versioni è ciò che permette di rispondere a «che cosa è cambiato».

```
psn_import ──┬── psn_section        le sezioni dell'anagrafica = le SUPERNET,
             │                      con ambiente e criticità estratti dal titolo
             ├── psn_subnet ──┬── psn_address    una riga per indirizzo, liberi compresi
             │                └── (section_id)
             ├── psn_tenant        gli ambienti PSN, identificativo normalizzato
             ├── psn_database      i servizi Oracle, legati al tenant per CODICE
             ├── psn_service       URL → VIP → backend
             ├── psn_naming_token  la convenzione dei nomi, come dati
             ├── psn_reference     i riferimenti estratti dal testo libero
             └── psn_finding       ciò che non torna
```

**Perché si conservano anche gli indirizzi liberi.** Il valore operativo di un piano di
indirizzamento è sapere che cosa è *libero*: «qual è il prossimo indirizzo
disponibile» è la domanda che si fa ogni volta che si installa qualcosa. Conservare
solo gli assegnati risponderebbe alla domanda sbagliata.

**Perché il legame database → tenant è per codice e non per chiave esterna.** Il foglio
a volte attribuisce un database a un tenant che l'anagrafica non elenca. Una chiave
esterna rifiuterebbe la riga; un codice la conserva e lascia che l'analisi dichiari
l'orfano.

---

## 4. Lettura del documento

### 4.1 Nessuna dipendenza nuova

Un `.xlsx` è un archivio zip di documenti XML: `zipfile` più `xml.etree` bastano. Una
libreria generica porterebbe stili, formule, grafici, immagini e la propria superficie
di attacco — per un file che arriva per posta elettronica da fuori, è superficie che non
si vuole.

Il lettore diffida del file: rifiuta archivi con troppe voci o troppo grandi (zip bomb),
legge solo le voci attese, e **rifiuta i documenti che dichiarano un DOCTYPE** (XXE,
billion laughs).

### 4.2 Le colonne si mappano per nome, non per posizione

Nel piano reale i 72 fogli di indirizzi hanno **cinque forme di intestazione diverse**:

```
48 fogli   label | id | ip | hostname | descrizione | note | old_hostname
17 fogli   ip | hostname | descrizione
 4 fogli   label | id | ip | hostname | descrizione | note
 2 fogli   label | id | ip | hostname | descrizione | note | old hostname
 1 foglio  ... | old_hostname | eu
```

Un lettore posizionale prenderebbe l'hostname dalla colonna della descrizione su un
quinto dei fogli, **in silenzio**.

### 4.3 Difetti del documento, gestiti e dichiarati

Tre cose che il piano reale contiene e che una lettura ingenua perde:

**Indirizzi salvati come numeri.** Nel foglio *DC S.Stefano Housing Voip* gli indirizzi
sono `192168230128` invece di `192.168.230.128`: le celle sono numeriche. Nessun lettore
li riconosce, e quel foglio risultava vuoto. Si ricostruiscono provando tutte le
suddivisioni in quattro ottetti e tenendo quella — **una sola** — che cade nella rete
del foglio. Con zero o più candidati non si indovina: l'indirizzo si scarta e lo si
dichiara. *Indovinare un indirizzo in un piano di indirizzamento è peggio che
perderlo.* Sul piano reale: **441 indirizzi recuperati su quattro fogli**.

**Codici di subnet discordanti.** Il foglio `10.58.70.0 |24` dichiara `ID: 041`, ma in
anagrafica 041 è `10.58.80.0/24` (il .70 è il **040**) — e i fogli di `10.58.80.0` e
`10.58.93.0` non esistono affatto. Fidandosi del codice, 254 indirizzi del .70
finirebbero archiviati sotto la subnet del .80: un dato sbagliato che sembra giusto. La
rete nel **nome del foglio** è il dato più difficile da sbagliare, e vince — dichiarando
la discordanza.

**Errori di formula.** Centinaia di `#REF!` e `#VALUE!`: sono formule rotte, non dati.
Valgono come vuoto, altrimenti si importerebbe una subnet chiamata `#VALUE!`.

### 4.4 I riferimenti scritti in prosa

Nel piano le relazioni fra schede esistono ma sono **testo**: `10.58.1.10 (sso-sie,
...)` dentro la descrizione di un indirizzo del WAF significa che quel WAF serve quell'
host, in un'altra subnet. Nessuna formula collega le due celle. Il sottosistema estrae
indirizzi e hostname citati e li trasforma in collegamenti percorribili — è il passo che
rende 79 schede un grafo.

---

## 5. Analisi: ciò che non torna

| Genere | Gravità | Che cosa dice |
|---|---|---|
| `duplicate_hostname` | critica | Un nome su più indirizzi: metà delle connessioni va nel posto sbagliato, e il guasto sembra intermittente |
| `duplicate_ip` | critica | Lo stesso indirizzo in due subnet |
| `overlap` | critica | Due subnet che condividono indirizzi: una delle due non raggiungerà ciò che crede |
| `outside_subnet` | critica | Un indirizzo elencato sotto una subnet che non lo contiene |
| `outside_supernet` | avviso | Una subnet fuori dalla supernet della propria sezione |
| `orphan_tenant` | avviso | Un database attribuito a un tenant che l'anagrafica non elenca |
| `dangling_reference` | avviso | Un indirizzo citato, appartenente a una subnet del piano, senza una riga propria |
| `no_cidr` | avviso | Una subnet senza rete leggibile: senza CIDR non si contano i liberi |
| `naming` | info | Un nome fuori dalla **forma** prevista |
| `naming_vocabulary` | info | Una **sigla usata** nei nomi ma non dichiarata nella convenzione |
| `rename_pending` | info | Una rinomina che il piano stesso dichiara in sospeso |
| `bad_hostname` | info | Un segnaposto (`-`, `n/a`, `VIP 1`) nella colonna hostname |

### 5.1 Due decisioni di giudizio, e perché

**I segnaposto non sono nomi.** La prima stesura confrontava ogni valore della colonna
hostname e produceva riscontri come *«il nome `-` è su sei indirizzi»*. È rumore, e il
rumore in un elenco di conflitti fa ignorare anche i conflitti veri. I segnaposto si
conservano — è ciò che dice il foglio — ma si dichiarano come qualità del dato, non come
duplicati. Un segnaposto non conta nemmeno come **assegnazione**: una riga con `-` e una
descrizione è una *prenotazione*, e contarla fra gli assegnati gonfierebbe l'occupazione.

**Una convenzione incompleta non rende sbagliati i nomi.** La prima stesura pretendeva
`sito-tenant-ruolo` e produceva **79 riscontri su 257 nomi**. Guardandoli, i nomi erano
giusti e la *convenzione* era incompleta: il Nomenclatore elenca i siti dei data center
(`psn`, `bc`, `dr`, `ac`, `pm`) e non quelli delle Centrali Operative, che nei nomi ci
sono eccome — `ss` (S.Stefano), `sc` (S.Camillo), `sg` (S.Giovanni), `ri` (Rieti), `lt`
(Latina), `fr` (Frosinone), `an` (Anagnina).

*Una regola che dichiara non conforme metà del parco non sta misurando la conformità,
sta misurando se stessa.* Il giudizio è stato diviso in due: la **forma** (pochi casi,
veri) e il **vocabolario** (una riga per sigla, con il numero di nomi che la usano —
da portare a chi mantiene il Nomenclatore, non un'accusa a chi ha battezzato le
macchine). Da 117 accuse a **64 riscontri azionabili**.

---

## 6. Le pagine

| Pagina | A che domanda risponde |
|---|---|
| **Quadro d'insieme** | Quanto c'è, quanto è libero, che cosa non torna |
| **Subnet e indirizzi** | Occupazione per subnet e **prossimo indirizzo libero** |
| Dettaglio di una subnet | La mappa indirizzo per indirizzo, i riscontri, e il grafo entrante/uscente |
| **Riscontri** | La coda del lavoro sul piano, filtrabile per genere |
| **Tenant** | Gli ambienti, con quanti database ospitano |
| **Database** | Servizi e istanze, col tenant che li ospita |
| **Servizi pubblicati** | URL → VIP → **quale apparato sta dietro** |
| **Cerca nel piano** | Un indirizzo, un nome, un service name: una ricerca su tutto. Se il testo è un indirizzo, trova anche la **subnet che lo contiene** |
| **Versioni del piano** | Che cosa è cambiato fra le due versioni più recenti |

---

## 7. Riservatezza

Un piano di indirizzamento è la **mappa di come entrare in una rete**. Perciò:

- la **lettura** è riservata agli analisti (ruolo `analyst` e superiori);
- il **conferimento** e l'eliminazione di una versione sono riservati
  all'**amministratore di sistema**;
- l'eliminazione di un conferimento richiede la **trascrizione del nome del file**;
- conferimento ed eliminazione restano nel **registro di audit** del prodotto
  (`psn.plan.imported`, `psn.plan.deleted`).

Il piano non è un dato per tenant: descrive l'infrastruttura del Polo, che è la stessa
per tutti, e non ha quindi un filtro per tenant.

---

## 8. Limiti dichiarati

- Il sottosistema **non scrive** nel piano e non produce un foglio aggiornato: le
  correzioni si fanno sul documento, e la versione successiva si conferisce.
- Il confronto fra versioni riguarda gli **indirizzi** (hostname e stato), non le
  anagrafiche: è dove stanno i cambiamenti che contano.
- Il vocabolario della convenzione è quello del foglio conferito: se il Nomenclatore è
  incompleto, i riscontri `naming_vocabulary` lo dicono ma non lo completano.
- **Nessun confronto con l'inventario raccolto dalle sonde.** Sarebbe la funzione più
  potente — «il piano dice che qui c'è `bc-prod-ipa01`, la rete dice altro» — ed è
  deliberatamente assente: mescolare il piano con l'inventario violerebbe la condizione
  di separabilità con cui il sottosistema è stato chiesto. È la prima cosa da fare se il
  sottosistema viene promosso a parte del prodotto.

---

## 9. Requisiti verificabili

| ID | Requisito |
|---|---|
| PSN-01 | Il sottosistema deve usare un archivio distinto da quello del prodotto, eliminabile senza effetti su di esso |
| PSN-02 | Nessuna tabella del sottosistema deve risiedere nell'archivio del prodotto |
| PSN-03 | L'importazione non deve introdurre dipendenze esterne |
| PSN-04 | Le colonne dei fogli devono essere individuate per nome, non per posizione |
| PSN-05 | Un indirizzo non leggibile deve essere ricostruito solo se la ricostruzione è univoca, altrimenti scartato e dichiarato |
| PSN-06 | Un codice di subnet discordante con la rete del foglio deve essere dichiarato, e gli indirizzi archiviati sotto la subnet che li contiene |
| PSN-07 | L'importazione deve essere una transazione: o entra tutto il piano, o niente |
| PSN-08 | Lo stesso file non deve produrre due conferimenti |
| PSN-09 | Ogni conferimento deve essere conservato e confrontabile con il precedente |
| PSN-10 | L'analisi deve dichiarare duplicati, sovrapposizioni, indirizzi fuori subnet e sigle non dichiarate |
| PSN-11 | Un segnaposto nella colonna hostname non deve produrre un conflitto né contare come assegnazione |
| PSN-12 | Il conferimento deve essere riservato all'amministratore di sistema e tracciato in audit |
