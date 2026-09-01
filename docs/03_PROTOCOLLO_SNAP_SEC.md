<!--
  snap - Specifica del protocollo SNAP-SEC/1.

  remarks: Autore: Daniele Speziale - Data: 2026-08-26
  copyright: (c) 2024-26 DS Consulting
  license: MIT
-->

# SNAP-SEC/1 - Specifica del canale cifrato sonda - server

| Voce | Valore |
|---|---|
| Identificatore di protocollo | `SNAP-SEC/1` |
| Versione del documento | 1.0.0 |
| Data | 2026-08-27 |
| Autore | Daniele Speziale |
| Implementazioni | `server/snapserver/crypto.py`, `probe/snapprobe/crypto.py` (indipendenti) |

---

## 1. Modello di sicurezza

### 1.1 Assunzioni
- La sonda conosce l'URL del server. Il server non conosce l'indirizzo della sonda.
- Il canale di trasporto (HTTP) e' considerato **non fidato**: puo' essere
  osservato, ritardato e ripetuto da un attaccante.
- Il token di registrazione e' trasferito all'operatore per via fidata (console
  del server e consegna al tecnico).

### 1.2 Obiettivi
| Obiettivo | Meccanismo |
|---|---|
| Riservatezza del payload | AES-256-GCM con chiave derivata da ECDH X25519 |
| Autenticita' e integrita' | Tag GCM su ciphertext e dati associati (AAD) |
| Autenticazione della sonda | Possesso della chiave di sessione + API key trasportata nel payload cifrato |
| Protezione dalla ripetizione | Nonce registrato per sonda + finestra temporale |
| Non trasferibilita' dei messaggi | AAD che lega versione, identita', nonce, marca temporale e rotta |
| Riservatezza del token di registrazione | Il server conserva solo impronta SHA-256 e chiave derivata |
| Revocabilita' | Azzeramento della chiave di sessione lato server |

### 1.3 Non obiettivi
Anonimato della sonda rispetto all'osservatore di rete; segretezza in avanti
(forward secrecy) per sessione: la chiave e' a lunga durata e si rinnova con una
nuova registrazione.

---

## 2. Primitive crittografiche

| Funzione | Algoritmo | Parametri |
|---|---|---|
| Scambio di chiavi | X25519 (RFC 7748) | chiavi in forma grezza, 32 byte |
| Derivazione | HKDF-SHA256 (RFC 5869) | salt `snap-sec/1\|static-salt`, lunghezza 32 byte |
| Cifratura autenticata | AES-256-GCM | nonce 96 bit da generatore crittografico |
| Impronte | SHA-256 | rappresentazione esadecimale |
| Codifica di trasporto | Base64 URL-safe senza riempimento | - |

Etichette HKDF (`info`), che separano i contesti d'uso:

```
enrollment : "snap-sec/1|enrollment-transport"
sessione   : "snap-sec/1|session-data"
```

---

## 3. Formato della busta

Il corpo di ogni richiesta e risposta di sessione e' un oggetto JSON:

```json
{
  "v":     "SNAP-SEC/1",
  "probe": "<identita' della sonda>",
  "nonce": "<nonce 96 bit, base64url>",
  "ts":    1774537200,
  "data":  "<ciphertext||tag, base64url>"
}
```

I dati associati (AAD), autenticati ma non cifrati, sono la concatenazione:

```
AAD = v | probe | nonce | ts | path
```

dove `path` e' il percorso della rotta (ad esempio `/api/v1/ingest`). Ne
consegue che una busta valida non puo' essere riutilizzata su una rotta diversa,
con un'altra identita' o con una marca temporale alterata.

Il campo `probe` contiene:
- il **codice** della sonda durante l'enrollment (l'identificativo definitivo non
  e' ancora noto alla sonda);
- il **probe_uid** in tutti gli scambi successivi.

---

## 4. Fase 1 - Registrazione (enrollment)

### 4.1 Emissione del token (lato server)
1. L'amministratore crea la sonda: il server assegna `probe_uid` e `code`.
2. Il server genera un token `T` (32 byte casuali, base64url).
3. Il server memorizza:
   - `enrollment_token_hash = SHA256(T)` - indice di ricerca;
   - `enrollment_key = HKDF(T | code, info=enrollment)` - chiave per decifrare;
   - `enrollment_expires_at` - scadenza (24 ore per impostazione predefinita).
4. Il token in chiaro **non viene conservato**: e' mostrato una sola volta.

Il pacchetto consegnato all'operatore e':

```
SNAP1-<base64url({"url": "<server>", "code": "<codice>", "token": "<T>"})>
```

### 4.2 Richiesta (sonda -> server)

`POST /api/v1/enroll`

```json
{
  "token_hint": "<SHA256(T) esadecimale>",
  "envelope": { "v": "SNAP-SEC/1", "probe": "<code>", "nonce": "...", "ts": ..., "data": "..." }
}
```

Payload cifrato con `Ke = HKDF(T | code, info=enrollment)`:

```json
{
  "probe_code": "sonda-sede-01",
  "probe_public_key": "<X25519 pubblica, base64url>",
  "agent_version": "1.0.0",
  "platform": "Windows 11",
  "hostname": "<nome locale>",
  "requested_at": "2026-08-26 19:20:00"
}
```

`token_hint` e' l'unico elemento in chiaro: consente al server di individuare la
sonda senza che il token trasiti in rete.

### 4.3 Verifiche del server
1. Esiste una sonda con quell'impronta di token, altrimenti `403 enroll_unknown`.
2. La sonda non e' revocata, altrimenti `403 probe_revoked`.
3. Il token non e' gia' stato usato, altrimenti `409 enroll_used`.
4. Il token non e' scaduto, altrimenti `403 enroll_expired`.
5. La busta si apre correttamente con `enrollment_key`, altrimenti `403 enroll_crypto`.

### 4.4 Risposta (server -> sonda)
Busta cifrata con la medesima `Ke` (la sonda non possiede ancora la chiave di
sessione):

```json
{
  "probe_uid": "<32 caratteri esadecimali>",
  "api_key": "<32 byte base64url>",
  "server_public_key": "<X25519 pubblica, base64url>",
  "server_time": "2026-08-26 19:20:01",
  "config": {
    "scan_interval_sec": 300,
    "tenant_code": "ised",
    "tenant_name": "ISED S.p.a.",
    "tenant_timezone": "Europe/Rome",
    "probe_name": "Sonda sede centrale",
    "options": {}
  }
}
```

Contestualmente il server: calcola `Ks = HKDF(ECDH, info=sessione)`, memorizza
`Ks` e `SHA256(api_key)`, **azzera** `enrollment_key` e pone lo stato ad `active`.
La sonda calcola la stessa `Ks` e memorizza le credenziali nel proprio archivio.

---

## 5. Fase 2 - Scambi di sessione

Tutte le rotte sono `POST`, con l'intestazione:

```
X-Snap-Probe: <probe_uid>
```

e corpo costituito dalla busta cifrata con `Ks`. Ogni payload contiene il campo
`auth` con l'API key: l'autenticazione richiede quindi due elementi indipendenti
(chiave di sessione e API key).

### 5.1 `POST /api/v1/heartbeat`
Richiesta:
```json
{ "auth": "<api_key>", "agent_version": "1.0.0", "queue_size": 42, "paused": false, "hostname": "..." }
```
Risposta:
```json
{
  "server_time": "2026-08-26 19:25:00",
  "config": { "...": "come in enrollment" },
  "commands": [ { "id": 7, "command": "flush", "payload": {} } ],
  "queue_ack": 42
}
```

### 5.2 `POST /api/v1/ingest`

Richiesta:
```json
{
  "auth": "<api_key>",
  "batch_uid": "<32 esadecimali>",
  "generated_at": "2026-08-27 08:25:03",
  "records": {
    "events": [
      {
        "type": "probe.cycle",
        "severity": "info",
        "description": "Ciclo di raccolta 42 eseguito dalla sonda",
        "created_at": "2026-08-27 08:25:00",
        "detail": { "ciclo": 42, "record_in_coda": 0, "intervallo_sec": 300 }
      }
    ]
  }
}
```
Risposta:
```json
{
  "accepted": true,
  "duplicate": false,
  "batch_uid": "...",
  "records": 1,
  "detail": { "events": 1 }
}
```

**Tipi di record.** Il contratto attuale prevede il solo tipo `events`: le
annotazioni prodotte dalla sonda, che il server registra nell'audit del tenant
conservando la gravita' dichiarata (`info`, `warning`, `critical`; valori diversi
sono normalizzati a `info`). Il campo `detail`, se presente, viene conservato in
forma leggibile insieme alla descrizione.

Un lotto che contenga tipi di record non riconosciuti viene rifiutato con
l'indicazione dei tipi non ammessi: l'introduzione di un nuovo tipo richiede il
corrispondente applicatore sul server (`snapserver.ingest._APPLICATORI`) e il
generatore sulla sonda (`snapprobe.collector`), senza modifiche al trasporto.

**Idempotenza.** `batch_uid` e' univoco per sonda. Un lotto gia' acquisito viene
riconosciuto e riconfermato con `duplicate: true`, senza riapplicare i dati: la
sonda puo' quindi ritrasmettere in sicurezza quando la conferma non e' arrivata.

Gli istanti non interpretabili sono sostituiti dall'ora di ricezione.

### 5.3 `POST /api/v1/command-ack`
```json
{ "auth": "<api_key>", "results": [ { "id": 7, "ok": true, "detail": "coda conferita" } ] }
```
Risposta: `{ "acknowledged": [7] }`.

### 5.4 `GET /api/v1/ping`
Unica rotta in chiaro, priva di dati di tenant: serve alla verifica di
raggiungibilita' dall'interfaccia della sonda.

```json
{ "service": "snap", "protocol": "SNAP-SEC/1", "server_time": "2026-08-26 19:25:00" }
```

---

## 6. Comandi disponibili

| Comando | Effetto sulla sonda |
|---|---|
| `flush` | Conferimento immediato della coda |
| `reconfigure` | Ricarica della configurazione al contatto successivo |
| `pause` | Sospensione di raccolta e conferimento |
| `resume` | Ripresa dell'attivita' |
| `wipe` | Svuotamento della coda locale senza conferimento |

I comandi sono accodati sul server (`probe_commands`), consegnati al primo
contatto della sonda e marcati `delivered`; l'esito riportato dalla sonda li
porta a `completed` o `failed`.

---

## 7. Anti-replay e finestra temporale

- Ogni nonce accettato e' registrato in `probe_nonces` con vincolo di unicita'
  per sonda: la ripresentazione della stessa busta e' rifiutata con `403`.
- Le buste con `|ora_server - ts| > 300 s` sono rifiutate.
- I nonce piu' vecchi della finestra di conservazione configurata sono rimossi
  periodicamente durante gli heartbeat.

---

## 8. Errori di protocollo

Gli errori sono restituiti in chiaro (la chiave potrebbe non essere disponibile o
valida):

```json
{ "error": "<codice>", "detail": "<descrizione>", "v": "SNAP-SEC/1" }
```

| Codice | HTTP | Significato |
|---|---|---|
| `protocol_error` | 400 | Richiesta malformata |
| `enroll_unknown` | 403 | Token non riconosciuto |
| `enroll_used` | 409 | Token gia' utilizzato |
| `enroll_expired` | 403 | Token scaduto |
| `enroll_crypto` | 403 | Busta di enrollment non valida |
| `enroll_nokey` | 400 | Chiave pubblica assente |
| `enroll_kex` | 400 | Scambio di chiavi non riuscito |
| `probe_revoked` | 403 | Sonda revocata |
| `auth_failed` | 403 | Autenticazione di sessione non riuscita (chiave, API key, nonce o marca temporale) |

Comportamento atteso della sonda: gli errori di trasporto (rete) comportano il
mantenimento della coda e un nuovo tentativo al tick successivo; gli errori
applicativi definitivi sono registrati nel diario locale e liberano il lotto.

---

## 9. Ciclo di vita del materiale crittografico

| Elemento | Dove risiede | Durata | Rinnovo |
|---|---|---|---|
| Chiave privata della sonda | Solo sull'archivio della sonda | Fino a nuova registrazione | Nuovo enrollment |
| Chiave privata del server per la sonda | Solo sul server | Fino a nuova registrazione | Nuovo enrollment |
| Chiave di sessione `Ks` | Su entrambi i lati | Fino a revoca o nuova registrazione | Nuovo enrollment |
| Token di registrazione | Impronta e chiave derivata sul server; in chiaro solo nel pacchetto consegnato | 24 ore o primo uso | Emissione di un nuovo token |
| API key | In chiaro sulla sonda; solo impronta sul server | Fino a revoca | Nuovo enrollment |

**Revoca.** L'operazione azzera `session_key` e `api_key_hash` sul server: ogni
conferimento successivo riceve `403 auth_failed`. La sonda registra
l'indisponibilita' e conserva i dati in coda fino a una nuova registrazione.

---

## 10. Verifica del protocollo

I test automatici in `tests/test_crypto_channel.py` e
`tests/test_probe_server_flow.py` verificano: interoperabilita' fra le due
implementazioni, legame con rotta e identita', rilevazione della manomissione,
rifiuto delle buste scadute e ripetute, monouso del token, idempotenza delle
ritrasmissioni, efficacia della revoca.
