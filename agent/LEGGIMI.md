# Agente snap — installazione su una macchina

> Questo pacchetto installa l'agente su **una** macchina. Il token che contiene vale
> **un'ora e una volta sola**: finché non è stato speso, questo pacchetto è una
> credenziale, e va trattato come tale.

| | |
|---|---|
| Contiene | agente 1.2.0, installatori per Windows, Linux e Docker |
| Il token scade | vedi `pacchetto.json`, campo `scade_at` |
| Vale per | una macchina sola |

---

## 1. In breve

| Dove si installa | Comando |
|---|---|
| **Windows** | PowerShell **come amministratore**: `.\installa.ps1` |
| **Linux** | `sudo ./installa.sh` |
| **Docker** (solo Linux) | `cp docker/.env.example docker/.env`, riempirlo, poi `docker compose -f docker/docker-compose.yml up -d --build` |

Prima di tutto il resto, se vuoi vedere che cosa l'agente porterebbe via da questa
macchina **senza mandare niente**:

```
python snap_agent.py prova --riassunto
```

Stampa il messaggio vero, gruppo per gruppo, con quanto pesa.

---

## 2. Che cosa fa l'agente

Misura questa macchina e lo riferisce alla sonda. **Apre lui** la connessione verso la
sonda: non apre porte, non installa servizi in ascolto, non accetta connessioni e non
riceve comandi. Una macchina in rete di utenza non deve essere raggiungibile da
nessuno, nemmeno dal prodotto che la sorveglia.

Manda due cose, con due ritmi diversi:

- le **misure** ogni minuto — carico, dischi, ritmo di rete, processi, sessioni:
  qualche kB, è quello che si guarda su un grafico;
- l'**inventario** una volta all'ora, o appena cambia qualcosa — software installato,
  servizi, utenze, postura di sicurezza, porte in ascolto: è uno stato, e rispedirlo
  ogni minuto costerebbe 99 MB al giorno per non dire niente di nuovo.

## 3. Che cosa NON raccoglie, per scelta

Contenuto di file, righe di comando complete, traffico, messaggi, cronologia, corpo
delle attività pianificate. Le righe di comando possono contenere una password passata
come argomento: si registra il **nome** del processo e il suo utente, non come è stato
invocato.

Nomi utente e sessioni sono **dati personali** (GDPR art. 4): la base giuridica è la
sicurezza della rete (art. 6(1)(f)) e le pagine della console nominano **macchine e
utenze, non persone**. Con `configura` si possono spegnere tutti i gruppi che
riguardano le persone in un colpo solo: preselezione `minimo`.

---

## 4. Scegliere che cosa inviare

```
python snap_agent.py configura
```

Mostra i quindici gruppi con quello che mandano, ogni quanto e se riguardano le
persone; si accendono e si spengono per numero. Senza domande:

```
python snap_agent.py configura --gruppi minimo
python snap_agent.py configura --gruppi identita,carico,dischi,sicurezza
```

| Preselezione | Che cosa accende |
|---|---|
| `tutti` | tutto quello che l'agente sa raccogliere (predefinito) |
| `consigliato` | tutto tranne l'inventario del software e le attività pianificate |
| `minimo` | identità, carico, dischi, rete: **nulla che riguardi le persone** |

I gruppi spenti vengono **dichiarati** alla sonda: la console scriverà «non misurato»,
non zero. È la differenza fra «questa macchina non ha antivirus» e «a questa macchina
non l'ho chiesto».

---

## 5. Privilegi

L'agente vede quello che il suo utente può vedere. Senza privilegi di amministratore
**non** si vedono: il processo e l'utente che tengono aperta una porta, gli accessi
falliti nel registro, le utenze locali. Sono le cose per cui l'agente esiste, e per
questo gli installatori chiedono privilegi.

| | Predefinito | Ridotto |
|---|---|---|
| Windows | attività pianificata come `SYSTEM` | `.\installa.ps1 -UtenteDiServizio` |
| Linux | utenza dedicata `snap-agent` | — già il minimo; `sudo ./installa.sh --privilegi-completi` per root |
| Docker | root nel container, macchina in **sola lettura** | — |

Quello che non si riesce a leggere viene dichiarato, mai taciuto.

---

## 6. Il container: che cosa vede e che cosa no

Un agente dentro un container misura **il container**: due processi, un filesystem che
non esiste sulla macchina. Sarebbe un dato esatto e inutile. Il `docker-compose.yml`
apre l'isolamento in tre punti precisi, e in nessun altro:

| Riga | Perché |
|---|---|
| `pid: host` | i processi sono quelli della macchina |
| `network_mode: host` | le porte in ascolto e le interfacce sono quelle vere, e la sonda si raggiunge |
| `/:/hostfs:ro` | il filesystem e `/proc` sono quelli della macchina, **in sola lettura** |

**Anche così, quattro gruppi restano fuori** — e l'agente lo dichiara invece di
inventare:

| Gruppo | Perché non si può, dentro un container |
|---|---|
| `aggiornamenti` | li conosce il gestore di pacchetti della macchina, con le sue liste e le sue chiavi |
| `servizi` | `systemctl` parla con il systemd della macchina, che qui non c'è |
| `container` | serve il socket di Docker, che non si monta per non dare il controllo del motore |
| `pianificate` | i lavori cron si leggono, i timer di systemd no: l'elenco si dichiara **parziale** |

`software` invece funziona: l'agente punta all'archivio dei pacchetti della macchina
(`--admindir`). Senza quell'accortezza elencava i pacchetti dell'immagine Debian come
se fossero quelli della macchina — un dato esatto e falso.

**In sintesi**: il container va bene per i server di cui interessano carico, dischi,
rete, porte e processi. Per l'inventario completo, l'installazione nativa vede tutto.

---

## 7. Senza accesso a Internet

`pip` non raggiungerà nulla. Si prepara il pacchetto con le *wheel* dentro, su una
macchina che la rete ce l'ha:

```
pip download psutil==6.1.0 -d wheels/ --only-binary=:all: \
    --platform win_amd64 --python-version 313      # per Windows
pip download psutil==6.1.0 -d wheels/ --only-binary=:all: \
    --platform manylinux2014_x86_64 --python-version 313   # per Linux
```

Se la cartella `wheels/` c'è, gli installatori la usano e non cercano la rete.

---

## 8. Se qualcosa non va

| Sintomo | Causa | Rimedio |
|---|---|---|
| `registrazione rifiutata dalla sonda: 403` | il token è scaduto, è già stato usato, o è stato ricopiato male | emetterne un altro dalla console della sonda |
| `respinto dalla sonda (401)` a ogni invio | la macchina è stata revocata, oppure l'orologio è sfasato di più di 5 minuti | sincronizzare l'ora; se è una revoca, registrare di nuovo |
| `sonda non raggiungibile` | rete, proxy o certificato | provare `https://<sonda>:5510/api/agent/ping`: se non risponde non è la chiave |
| errore di certificato | la sonda ha un certificato proprio | `--senza-verifica-tls` (Linux), `-SenzaVerificaTls` (Windows), `SNAP_AGENT_VERIFICA_TLS=0` (Docker) |
| la macchina compare sulla sonda ma non sul server | non è l'agente: è il conferimento della sonda | guardare *Sonde → Console* sulla console del server |

Il motivo per esteso di un rifiuto sta sempre nel **diario della sonda**: a chi bussa
non si dice quale verifica non è passata, perché sarebbe un modo di aiutarlo a
passarla.

---

## 9. Togliere l'agente

```
sudo ./disinstalla.sh                    # Linux
.\disinstalla.ps1                        # Windows (come amministratore)
docker compose -f docker/docker-compose.yml down -v   # Docker
```

Disinstallare **non** revoca la macchina sulla sonda: smette solo di riferire. Per
chiudere anche la credenziale, revocarla dalla console della sonda, pagina *Agenti*.
Sono due gesti distinti di proposito — disinstallare è una manutenzione, revocare una
credenziale è una decisione.
