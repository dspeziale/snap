# Certificati di cui la sonda si fida

Questa cartella viene montata in sola lettura nel container della sonda, in
`/etc/snap/trust`. Serve a un caso preciso: il server ha un certificato **proprio**
(CA interna oppure autofirmato), che nessun archivio pubblico conosce.

Senza l'ancora di fiducia la registrazione si ferma così:

```
Server non raggiungibile: ... [SSL: CERTIFICATE_VERIFY_FAILED]
certificate verify failed: self-signed certificate
```

Non è un difetto: su quel canale passano le chiavi della registrazione e l'inventario
della rete. Se la sonda accettasse qualunque certificato, chiunque si mettesse in
mezzo potrebbe presentarsi come il server. Per questo **non esiste** un interruttore
per disattivare la verifica: si dichiara *di chi* fidarsi.

## Cosa mettere qui

Un file PEM:

* se il server ha un certificato firmato da una CA interna → il certificato **della
  CA**;
* se il certificato del server è autofirmato → il **certificato del server** stesso
  (`server.crt`, non la chiave).

Poi, in `.env`:

```
SNAP_PROBE_SERVER_CA=/etc/snap/trust/server-ca.crt
```

Fidarsi del solo certificato del server è **più stretto** della fiducia in una CA
pubblica: si accetta quel certificato e nessun altro.

## Come prelevarlo dal server

Dalla macchina della sonda, senza fidarsi di nulla in anticipo:

```bash
openssl s_client -connect IL-SERVER:5500 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM > server-ca.crt
```

Il certificato così ottenuto va **confrontato** con l'impronta letta sul server
(altrimenti si sta fidando di ciò che risponde adesso, non del server):

```bash
openssl x509 -in server-ca.crt -noout -fingerprint -sha256
```

Il file deve contenere l'indirizzo con cui la sonda chiama il server nel campo SAN
(`openssl x509 -in server-ca.crt -noout -ext subjectAltName`): se la console è
configurata con `https://10.20.10.42:5500`, il SAN deve elencare quell'IP.

## Attenzione

I certificati qui dentro sono pubblici (non sono segreti), ma **le chiavi private
non vanno mai messe in questa cartella**: la chiave del proxy sta in `../certs/`,
che non viene montata nel container della sonda proprio per questo.
