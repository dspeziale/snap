<!--
  snap - Specifica dei requisiti.
  Conforme alla struttura prevista da ISO/IEC/IEEE 29148:2018 (Requirements engineering).

  remarks: Autore: Daniele Speziale - Data: 2026-08-27
  copyright: (c) 2024-26 DS Consulting
  license: MIT
-->

# snap - Specifica dei requisiti di sistema (SyRS)

| Voce | Valore |
|---|---|
| Sistema | snap - Secure Network Assessment Platform |
| Documento | Specifica dei requisiti di sistema |
| Versione | 1.1.0 |
| Data | 2026-08-27 |
| Autore | Daniele Speziale |
| Standard di riferimento | ISO/IEC/IEEE 29148:2018, ISO/IEC/IEEE 15288:2015, ISO/IEC/IEEE 19510:2013 |
| Stato | Baseline approvata per la realizzazione |

---

## 1. Scopo e ambito

### 1.1 Scopo del documento
Il presente documento definisce i requisiti degli stakeholder e i requisiti di
sistema per la piattaforma **snap**, costituita da due elementi software
distribuiti separatamente:

- **snap server** - punto di raccolta e presentazione, con interfaccia web per
  la gestione delle sonde, il registro di audit e l'amministrazione multi-tenant;
- **snap probe** (sonda) - agente autonomo installato nelle reti da osservare,
  che raccoglie dati e li conferisce al server su canale cifrato.

### 1.2 Ambito del sistema
Il sistema realizza il collegamento sicuro fra un insieme di sonde distribuite e
un punto di raccolta centrale, con isolamento completo dei dati fra
organizzazioni distinte (tenant).

La versione corrente comprende: registrazione e governo delle sonde, canale
cifrato di conferimento, funzionamento autonomo della sonda in assenza del
server, registro di audit per tenant, gestione di tenant e utenti con secondo
fattore opzionale.

I contenuti raccolti dalla sonda sono, in questa versione, **annotazioni
diagnostiche** sul proprio funzionamento: sufficienti a esercitare l'intero
percorso di conferimento e predisposte all'introduzione delle funzioni di
raccolta che verranno definite.

### 1.3 Fuori ambito
Non fanno parte del sistema: rilevazioni sulla rete osservata, inventario degli
asset, registro delle vulnerabilita', gestione delle scansioni, reportistica
documentale, notifiche verso sistemi terzi, alta disponibilita' e bilanciamento
di carico.

### 1.4 Definizioni
| Termine | Definizione |
|---|---|
| Tenant | Organizzazione cliente; unita' di isolamento dei dati |
| Sonda (probe) | Agente software che raccoglie dati in una rete e li conferisce al server |
| Conferimento | Trasferimento di un lotto di dati dalla sonda al server |
| Lotto (batch) | Insieme di record trasferito in un unico scambio, identificato univocamente |
| Record | Elemento di dato conferito; l'unico tipo previsto e' l'annotazione (`event`) |
| Enrollment | Procedura di registrazione della sonda presso il server |
| SNAP-SEC/1 | Protocollo applicativo cifrato fra sonda e server |
| MFA | Autenticazione a piu' fattori (secondo fattore TOTP) |

---

## 2. Requisiti degli stakeholder (StRS)

| ID | Stakeholder | Requisito | Priorita' |
|---|---|---|---|
| SH-01 | Responsabile sicurezza | Conoscere in ogni momento lo stato delle sonde installate e dei dati che stanno conferendo | Alta |
| SH-02 | Amministratore di sistema | Gestire piu' organizzazioni sulla stessa istanza garantendo separazione totale dei dati | Alta |
| SH-03 | Amministratore di tenant | Gestire autonomamente utenti, sonde e configurazioni della propria organizzazione | Alta |
| SH-04 | Revisore | Disporre di un registro completo e consultabile delle operazioni e degli eventi | Alta |
| SH-05 | Titolare del trattamento | Garantire che i dati transitino cifrati e che le operazioni siano tracciate | Alta |
| SH-06 | Tecnico di campo | Installare la sonda con una procedura semplice, senza aprire porte in ingresso | Alta |
| SH-07 | Tecnico di campo | Continuare la raccolta anche quando il server non e' raggiungibile | Alta |
| SH-08 | Utente con esigenze di accessibilita' | Regolare tema, dimensione del carattere e larghezza della pagina | Media |
| SH-09 | Responsabile IT | Sapere che cosa c'e' in rete e con che cosa risponde, senza installare nulla sui dispositivi | Alta |
| SH-10 | Turno operativo | Accorgersi che un servizio non risponde prima che lo segnali chi lo usa | Alta |
| SH-11 | Direzione, auditor | Ricevere documenti leggibili fuori dal gruppo tecnico ed essere avvisati quando accade qualcosa che conta | Alta |
| SH-12 | Responsabile sicurezza | Sapere quali vulnerabilita' note riguardano davvero i sistemi in rete, distinguendo cio' che e' dimostrato da cio' che va accertato | Alta |
| SH-13 | Operatore NOC e SOC | Cominciare il turno da una pagina che dice che cosa non funziona adesso e che cosa e' cambiato, e poter cercare nella base dati senza scrivere interrogazioni | Alta |
| SH-14 | Chi progetta la rete | Poter dichiarare che cos'e' una porzione di rete, perche' lo stesso servizio non ha lo stesso significato in un datacenter e su una postazione di lavoro | Alta |
| SH-15 | Chi deve consegnare un documento | Avere un report per ciascuna domanda ricorrente -- segmentazione, qualita' del dato, singolo apparato -- e poter tenere in ordine l'archivio di cio' che e' stato prodotto | Media |
| SH-16 | Chi verifica il prodotto sul campo | Vedere il dato grezzo di un dispositivo senza interpretazione, capire su che cosa poggia un verdetto, e riapplicare i miglioramenti a cio' che e' stato raccolto prima | Alta |

---

## 3. Requisiti funzionali di sistema

### 3.1 Canale sonda - server

| ID | Requisito | Verifica |
|---|---|---|
| SR-01 | La sonda deve conoscere l'indirizzo del server; il server non deve conoscere ne' memorizzare informazioni che consentano di contattare la sonda. | Ispezione dello schema dati e del codice; test `test_probe_server_flow` |
| SR-02 | Ogni connessione deve essere iniziata dalla sonda. Il server non deve aprire connessioni verso la sonda. | Ispezione del codice; assenza di client HTTP nel server |
| SR-03 | Il dialogo applicativo deve essere cifrato e autenticato con crittografia autenticata (AEAD) e chiavi derivate da scambio asimmetrico. | Test `test_crypto_channel` |
| SR-04 | La registrazione della sonda deve avvenire tramite token monouso con scadenza, emesso dal server. | `test_enrollment_token_cannot_be_reused` |
| SR-05 | Il server non deve conservare il token di registrazione in chiaro. | Ispezione schema (`enrollment_token_hash`, `enrollment_key`) |
| SR-06 | Il sistema deve rifiutare la ripetizione (replay) di messaggi validi. | `test_replayed_envelope_is_refused` |
| SR-07 | Il sistema deve rifiutare messaggi con marca temporale fuori da una finestra configurata. | `test_stale_envelope_is_rejected` |
| SR-08 | Ogni messaggio deve essere legato alla rotta di destinazione e all'identita' della sonda. | `test_envelope_is_bound_to_request_path`, `test_envelope_is_bound_to_probe_identity` |
| SR-09 | Le credenziali di una sonda devono poter essere revocate; dopo la revoca il conferimento deve essere impedito. | `test_revoked_probe_cannot_upload` |
| SR-10 | I comandi dal server alla sonda devono essere accodati e consegnati come risposta a un contatto della sonda. | `test_server_commands_are_delivered_on_probe_contact` |

### 3.2 Autonomia della sonda

| ID | Requisito | Verifica |
|---|---|---|
| SR-11 | La sonda deve raccogliere dati anche in assenza del server, accodandoli localmente in modo persistente. | `test_probe_works_offline_then_uploads_and_empties_queue` |
| SR-12 | Al ritorno del server la sonda deve conferire la coda e svuotarla soltanto dopo conferma di acquisizione. | come sopra |
| SR-13 | La ritrasmissione di un lotto non confermato non deve produrre duplicazione dei dati sul server. | `test_retransmission_is_idempotent` |
| SR-14 | La sonda deve funzionare anche senza interfaccia grafica (modalita' non presidiata). | `run.py --headless` |
| SR-15 | L'interfaccia della sonda deve limitarsi a registrazione, configurazione e diagnostica locale. | Ispezione delle rotte di `snapprobe.views` |
| SR-15z | L'interfaccia della sonda deve richiedere l'accesso con password, senza credenziale predefinita, ammettendo la prima impostazione soltanto da indirizzo locale. | `test_accesso_sonda.py` |
| SR-15a | La pagina di registrazione deve essere raggiungibile in ogni stato della sonda e consentire la sostituzione di una registrazione esistente, con ripristino automatico se il nuovo tentativo non riesce. | `tests/test_probe_interface.py` |

### 3.3 Multi-tenant

| ID | Requisito | Verifica |
|---|---|---|
| SR-16 | Ogni dato di dominio deve appartenere a un solo tenant e essere accessibile solo nel contesto di quel tenant. | `test_tenant_user_sees_only_own_probes`, `test_tenant_user_cannot_open_probe_of_another_tenant` |
| SR-17 | Un utente di tenant non deve poter commutare il contesto verso un altro tenant. | `test_tenant_user_cannot_switch_tenant` |
| SR-18 | L'amministratore di sistema deve poter commutare il contesto di tenant, crearne e eliminarne. | `test_superadmin_can_switch_tenant`, `test_tenant_deletion_removes_all_its_data` |
| SR-19 | Ogni tenant deve avere un fuso orario proprio; tutte le date e ore presentate devono essere normalizzate a tale fuso. | `test_probe_dates_follow_tenant_timezone` |
| SR-19a | La conversione deve tenere conto dell'ora legale, applicandola per singolo istante e non come scarto fisso. | `test_daylight_saving_is_applied` |
| SR-19b | L'interfaccia della sonda deve presentare gli istanti nel fuso del tenant ricevuto dal server, dichiarando il fuso adottato; in assenza di registrazione deve dichiarare l'uso di UTC. | `test_probe_interface_uses_tenant_timezone`, `test_probe_declares_utc_when_not_enrolled` |
| SR-20 | La cancellazione di un tenant deve rimuovere tutti i dati collegati e richiedere una conferma esplicita che ne dichiari il contenuto. | `test_tenant_deletion_removes_all_its_data`, `test_tenant_deletion_action_is_visible_without_opening_panels` |
| SR-21 | Ogni tenant deve avere una politica di conservazione dei dati storici applicabile su richiesta. | Funzione `admin.apply_retention` |

### 3.4 Utenti, autenticazione, autorizzazione

| ID | Requisito | Verifica |
|---|---|---|
| SR-22 | L'identificazione dell'utente deve avvenire con la sola email, senza username. | Schema `users`; modulo di accesso |
| SR-23 | Le password devono essere conservate esclusivamente come hash con sale. | Ispezione `security.hash_password` |
| SR-24 | Deve essere applicata una politica minima di robustezza della password. | `test_password_policy_is_enforced` |
| SR-25 | L'utenza deve essere bloccata temporaneamente dopo un numero configurato di tentativi falliti. | `test_account_is_locked_after_repeated_failures` |
| SR-26 | Il secondo fattore TOTP (Google Authenticator) deve essere disponibile in forma opzionale per ogni utenza. | `test_mfa_challenge_blocks_access_until_valid_code` |
| SR-27 | L'attivazione dell'MFA deve richiedere la conferma di un codice valido; la disattivazione da parte dell'utente deve richiedere un codice valido. | Ispezione `auth.mfa_enable`, `auth.mfa_disable` |
| SR-28 | L'amministratore deve poter azzerare il secondo fattore di un utente (dispositivo smarrito). | Rotta `admin.reset_mfa` |
| SR-29 | Il sistema deve prevedere i ruoli: consultazione, analista, amministratore di tenant, amministratore di sistema, con privilegi crescenti. | `test_viewer_cannot_reach_administration`, `test_analyst_cannot_manage_tenants` |
| SR-29a | Un token di sicurezza scaduto su un modulo non deve interrompere l'operazione: l'utente deve essere riportato alla pagina di provenienza con un avviso. | Ispezione dell'handler `CSRFError` |

### 3.4-bis Lettura delle interfacce web, dato grezzo, rielaborazione

| ID | Requisito | Verifica |
|---|---|---|
| SR-171 | La sonda deve leggere la pagina radice delle interfacce web dei dispositivi con una sola richiesta GET, senza tentativi di autenticazione, e ricavarne titolo, intestazioni, generatore e certificato. | `tests/test_web.py` |
| SR-172 | Il contenuto della pagina non deve essere conservato: si conservano le etichette dichiarate, la dimensione e un'impronta. | `test_il_corpo_della_pagina_non_si_conserva` |
| SR-173 | Le letture web devono contribuire al riconoscimento del dispositivo e, quando la firma riconosce un genere, valere come regola decisiva. | `test_la_pagina_di_gestione_decide_il_tipo_di_dispositivo` |
| SR-174 | Deve essere disponibile, per ciascun dispositivo, un documento JSON con tutto il dato conservato, versionato, limitato al tenant e privo di segreti. | `tests/test_node_json.py` |
| SR-175 | Deve essere possibile riapplicare ai dati gia' raccolti le regole correnti -- porte attribuite, riconoscimento, correlazione, zone -- senza avviare scansioni. | `tests/test_rielaborazione.py` |
| SR-185 | La lettura di un'interfaccia web deve seguire il percorso indicato dall'apparato stesso (redirezioni, meta refresh, salto in JavaScript, frame) e restare sullo stesso indirizzo e sulla stessa porta. | `test_la_lettura_arriva_ai_fatti_passando_dalle_pagine_intermedie` |
| SR-186 | La lettura deve estrarre i fatti dichiarati dall'apparato -- nome, modello, posizione fisica, nome host, numero di serie, firmware, contatto -- da un vocabolario chiuso di etichette multilingua. | `test_la_pagina_di_informazioni_dichiara_nome_posizione_e_host` |
| SR-187 | La lettura deve usare solo il metodo GET e non deve richiedere alcun indirizzo il cui nome contenga un verbo distruttivo. | `test_un_indirizzo_con_un_verbo_distruttivo_non_si_apre_mai` |
| SR-188 | Ogni lettura deve avere un tetto di pagine e di tempo, per porta e per compito. | `test_la_lettura_si_ferma_quando_l_apparato_ha_detto_abbastanza` |
| SR-189 | Un valore segnaposto o un campo vuoto non devono produrre un fatto. | `test_un_campo_vuoto_non_prende_il_valore_del_campo_successivo` |
| SR-190 | Quando i dati dell'apparato sono protetti da credenziali, il prodotto deve dichiararlo invece di presentare l'apparato come non identificato. | `test_una_pagina_protetta_viene_dichiarata` |
| SR-197 | Dalla scheda di un dispositivo deve essere possibile scaricare in PDF la lettura delle sue interfacce di gestione, con il percorso delle pagine aperte; lo scarico deve essere tracciato. | `test_il_pdf_della_lettura_porta_i_fatti_e_il_percorso` |
| SR-198 | Il risultato di una lettura delle interfacce di gestione deve essere conferito alla console senza attendere la fase di profilo successiva. | `test_ogni_genere_accodato_ha_un_tipo_di_record_corrispondente` |
| SR-202 | Il prodotto deve accompagnare la comunicazione degli incidenti all'ACN (art. 23 NIS2) con i termini, il fascicolo e il registro degli invii, senza inviare al posto del punto di contatto. | `test_il_canale_automatico_e_dichiarato_non_disponibile` |
| SR-203 | Dalla pagina del perimetro deve essere possibile chiedere subito una passata di scoperta su una singola subnet, senza attendere la cadenza; la richiesta deve essere tracciata e non deve poter riguardare una subnet disattivata, una subnet di un altro tenant o sonde con le scansioni sospese. (Completa SR-50, realizzato finora solo per il singolo nodo.) | `test_la_scansione_estemporanea_accoda_una_scoperta_sulla_subnet` |
| SR-204 | Un host che nmap dichiara abbandonato per tempo scaduto non deve contare come host esaminato senza esito: non consuma un tentativo di ammissione, viene contato a parte e al giro successivo riceve piu' tempo. | `tests/test_scadenza_host.py` |
| SR-205 | L'operatore deve poter **dichiarare** il tipo di un dispositivo, scegliendolo dal catalogo, con una motivazione facoltativa; la dichiarazione deve resistere a ogni ricalcolo del verdetto (conferimento e rideterminazione dell'inventario) ed essere revocabile in un passaggio. | `tests/test_tipo_dichiarato.py` |
| SR-206 | Anche con un tipo dichiarato il verdetto automatico deve continuare a essere calcolato e restare consultabile, e l'interfaccia deve distinguere un tipo dichiarato da uno riconosciuto. | `test_il_verdetto_automatico_continua_a_essere_calcolato_e_conservato` |
| SR-207 | Deve esistere una mappa di rete **grafica** che disegni la stessa gerarchia della mappa ad albero (sonda, rete dichiarata, dispositivi) con le icone del tipo di ciascun nodo; la disposizione dev'essere calcolata dal server, senza librerie di grafi ne' script inline. | `tests/test_mappa_grafica.py` |
| SR-208 | Dove un dispositivo espone SMB (139/445) deve essere eseguita un'enumerazione in sola lettura (`smb-os-discovery`, `smb-enum-shares`, `smb-enum-users`, `smb-security-mode`) e il risultato memorizzato per intero, interpretato in tabelle e usato per il riconoscimento; nessuno script deve tentare credenziali. | `tests/test_smb.py` |
| SR-209 | La fase dei servizi deve arricchire i nodi con un insieme curato di script NSE di sola lettura (identita' TLS, web, RDP, NetBIOS, SSH), auto-limitati da nmap alle porte pertinenti, con esclusione di ogni script di forzatura, exploit o denial-of-service. | `test_nessuno_script_snmp_tenta_credenziali` |
| SR-210 | Il prodotto deve cercare le vulnerabilita' con nmap in una fase dedicata, con soli script di **rilevazione** (mai exploit, dos o brute), sui soli nodi che espongono un servizio a rischio. | `tests/test_vuln.py` |
| SR-211 | Ogni vulnerabilita' verificata da nmap deve diventare un riscontro della Threat Intelligence con origine `nmap`, distinto da quelli dedotti per versione; la riconciliazione della correlazione per versione non deve chiudere i riscontri di nmap, e un difetto sanato deve essere chiuso alla verifica successiva. | `test_la_correlazione_per_versione_non_chiude_i_riscontri_di_nmap` |
| SR-212 | Il riconoscimento deve usare il **TTL** osservato (arrotondato in su al TTL iniziale 64/128/255) come indizio debole della famiglia del sistema operativo, solo quando nmap non l'ha determinata, con un peso che da solo non decide. | `test_il_ttl_nudge_la_famiglia_quando_le_prove_scarseggiano` |
| SR-213 | La mappa grafica deve essere stampabile in formato A4/A3 (orizzontale o verticale): in stampa la mappa riempie il foglio e i comandi non compaiono. | `test_la_mappa_grafica_si_stampa` |
| SR-192 | Dove la pagina web non dichiara il modello, il prodotto deve tentare di ricavare marca, modello, numero di serie e firmware con IPP. | `test_i_fatti_arrivano_con_i_nomi_del_prodotto` |
| SR-193 | La lettura IPP deve usare esclusivamente l'operazione `Get-Printer-Attributes` e non deve richiedere attributi relativi ai lavori di stampa. | `test_la_richiesta_non_chiede_la_coda_dei_lavori` |
| SR-194 | Gli apparati che espongono solo IPP devono entrare nella fase di lettura delle interfacce di gestione. | `test_la_fase_web_interroga_anche_chi_ha_solo_ipp` |
| SR-176 | Deve essere possibile rimuovere in blocco le subnet scelte dal perimetro, con conferma esplicita, senza cancellare i dispositivi gia' scoperti. | `test_si_rimuovono_le_subnet_scelte` |

### 3.5 Dati e presentazione

| ID | Requisito | Verifica |
|---|---|---|
| SR-30 | Il server deve registrare ogni conferimento ricevuto (lotto, numero di record, dimensione, esito) e conservarne lo storico per tenant. | Schema `ingest_batches`; `snapserver.ingest` |
| SR-31 | La dashboard deve presentare riquadri di sintesi, un'area indicatori operativi, lo stato della flotta sonde, gli ultimi conferimenti e l'attivita' recente del registro eventi. | Ispezione `dashboard/index.html` |
| SR-32 | Le annotazioni conferite dalle sonde devono confluire nel registro di audit del tenant, conservando la gravita' dichiarata. | `test_probe_works_offline_then_uploads_and_empties_queue` |
| SR-33 | Le operazioni rilevanti devono essere registrate in un registro di audit consultabile per tenant, con l'indicazione dell'attore. | Sezione Audit & Eventi |
| SR-34 | L'interfaccia deve consentire tema chiaro/scuro, quattro dimensioni del carattere e due larghezze di pagina, memorizzate nel profilo utente. | Ispezione `auth.preferences`, `snap.css` |
| SR-34a | Ogni tabella di elenco deve offrire ordinamento sulle colonne, paginazione con dimensione selezionabile e ricerca generale su tutte le colonne. | `test_ogni_pagina_elenco_ha_una_tabella_attrezzata`, `test_le_funzioni_richieste_sono_configurate`, `tools/collaudo_ui.py` |
| SR-34b | Il dialogo con l'utente (conferme e messaggi di esito) deve avvenire tramite Awesome Notifications, non con le finestre native del browser. | `test_le_conferme_native_del_browser_non_sono_piu_usate`, `test_i_messaggi_del_server_sono_esposti_alle_notifiche` |
| SR-34c | Ogni azione che elimina o azzera dati deve richiedere una conferma esplicita. | `test_le_azioni_distruttive_richiedono_conferma` |
| SR-34d | La navigazione non deve contenere collegamenti verso pagine inesistenti. | `test_nessun_collegamento_verso_pagine_inesistenti` |
| SR-34e | I titoli devono adottare PT Sans Narrow, con PT Sans per le varianti corsive; i caratteri devono essere serviti dal prodotto. | `test_i_caratteri_sono_serviti_localmente`, `test_i_titoli_usano_la_famiglia_stretta` |
| SR-35 | La sessione dell'utente deve resistere alla navigazione: nessuna risposta che non modifichi la sessione deve riscrivere il cookie, in particolare quelle dei file statici. | `tests/test_sessione.py` |
| SR-35a | Le due interfacce devono poter restare aperte contemporaneamente sullo stesso nome host: la sessione di una non deve essere invalidata dall'uso dell'altra. | `test_i_due_applicativi_usano_cookie_con_nomi_distinti`, `test_un_cookie_della_sonda_non_invalida_la_sessione_del_server` |

---

### 3.6 Aree funzionali specificate in documenti propri

Il prodotto e' cresciuto per aree, ciascuna con un documento di specifica che ne
porta requisiti, decisioni e limiti. Qui se ne dichiara l'esistenza e l'intervallo di
requisiti, perche' un elenco di sistema che si fermasse alla prima versione direbbe
il falso su che cosa il prodotto fa.

| Area | Documento | Requisiti | In sintesi |
|---|---|---|---|
| Inventario di rete e monitoraggio | `06_INVENTARIO_E_MONITOR.md` | SR-40..SR-80, SR-171..SR-176 | Perimetro dichiarato, scansione progressiva in sette fasi (compresa la lettura SNMP), riconoscimento dei dispositivi con prove conservate, sorveglianza della raggiungibilita', mappa ad albero, filtri dell'inventario |
| Controlli periodici e incidenti | `07_CONTROLLI.md` | SR-90..SR-112 | Bersagli e controlli eseguiti dalle sonde, soglie, incidenti con presa in carico e risoluzione, metriche ricavate dagli esiti, andamento della disponibilita' |
| Reportistica e resoconto | `08_REPORT.md` | SR-100..SR-120, SR-161..SR-164 | Undici generi di report PDF con frontespizio, palette per genere e caratteri incorporati; resoconto quotidiano composto e spedito dal server |
| Regole, canali, manutenzione | `09_REGOLE_CANALI_MANUTENZIONE.md` | SR-121..SR-135 | Motore delle regole su qualunque sorgente di evento, notifiche via posta e Telegram, retention per tipo di dato, copia e ripristino dell'archivio |
| Threat Intelligence | `10_THREAT_INTELLIGENCE.md` | SR-136..SR-150 | Catalogo locale CVE/CWE/KEV/ATT&CK, correlazione con l'inventario in tre classi dichiarate, decisioni tracciate, chiave API della NVD |
| Sala operativa | `11_SALA_OPERATIVA.md` | SR-81..SR-86, SR-165..SR-167 | Quadro NOC, quadro SOC, ricerca libera e interrogazioni pronte con esportazione tracciata |
| Zone di rete | `12_ZONE_DI_RETE.md` | SR-151..SR-160, SR-168..SR-170 | Contesto dichiarato sulla subnet che qualifica le esposizioni in attese, normali o violazioni, senza cancellare nulla; catalogo governato dall'operatore |

---

## 4. Requisiti non funzionali

| ID | Categoria | Requisito |
|---|---|---|
| NFR-01 | Sicurezza | Cifratura AES-256-GCM, scambio chiavi X25519, derivazione HKDF-SHA256 |
| NFR-02 | Sicurezza | Protezione CSRF su tutti i moduli dell'interfaccia; canale sonde escluso in quanto autenticato per costruzione |
| NFR-03 | Sicurezza | Intestazioni di risposta: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` |
| NFR-04 | Portabilita' | Python 3.10 o superiore; nessun servizio esterno richiesto; base dati SQLite su file |
| NFR-05 | Portabilita' | Risorse dell'interfaccia (AdminLTE 4.3.1, Bootstrap 5.3, Bootstrap Icons, DataTables 3.0.2, Awesome Notifications 3.1.3) servite localmente, senza jQuery: funzionamento senza accesso a Internet, verificato da `test_nessun_riferimento_a_reti_esterne_nei_modelli` |
| NFR-06 | Vincoli di esercizio | Porte di ascolto nell'intervallo 5500-5600 |
| NFR-07 | Manutenibilita' | Codice e identificatori in inglese, commenti e documentazione in italiano; intestazione con autore, data, copyright e licenza MIT in ogni file |
| NFR-07a | Presentazione | Convenzione tipografica: titoli in PT Sans Narrow (regolare e grassetto) con PT Sans per corsivo e grassetto corsivo; manuali software in PT Sans Narrow 19pt |
| NFR-08 | Manutenibilita' | Server e sonda in directory separate, senza codice condiviso: distribuzione e aggiornamento indipendenti |
| NFR-09 | Estensibilita' | L'aggiunta di un nuovo tipo di record conferito deve richiedere modifiche solo al generatore sulla sonda e all'applicatore sul server, senza toccare il protocollo di trasporto |
| NFR-10 | Affidabilita' | Un errore nel ciclo dell'agente non deve arrestare la sonda; l'errore e' registrato nel diario locale |
| NFR-11 | Tracciabilita' | Ogni istante e' persistito in UTC e convertito soltanto in presentazione |
| NFR-12 | Verificabilita' | Suite di test automatici a copertura dei requisiti sopra elencati, integrata da un collaudo dell'interfaccia in browser reale |
| NFR-13 | Manutenzione dello schema | L'allineamento del modello dati su installazioni esistenti deve avvenire all'avvio, senza interventi manuali |

---

## 5. Casi d'uso principali

### UC-01 Registrazione di una sonda
**Attori**: amministratore di tenant, tecnico di campo, sonda, server.
**Precondizione**: server in esercizio; sonda installata e raggiungibile localmente.
**Flusso principale**
1. L'amministratore crea la sonda nella console del server.
2. Il server emette un token monouso e mostra il pacchetto di registrazione.
3. Il tecnico incolla il pacchetto nell'interfaccia della sonda.
4. La sonda genera la coppia di chiavi e invia la richiesta cifrata.
5. Il server valida il token, completa lo scambio di chiavi e restituisce le credenziali.
6. La sonda memorizza la chiave di sessione e inizia a operare.

**Estensione E1**: token scaduto, token gia' usato, server non raggiungibile: la
sonda segnala l'errore e resta in stato non registrato, continuando a raccogliere.

**Estensione E2 - sonda gia' registrata**: la pagina di registrazione mostra la
registrazione in essere e richiede la conferma di sostituzione; se il nuovo
tentativo non riesce, la registrazione precedente viene ripristinata.

### UC-02 Raccolta e conferimento
**Attori**: sonda, server.
**Flusso principale**
1. La sonda esegue un ciclo di raccolta all'intervallo configurato.
2. I record entrano nella coda locale persistente.
3. La sonda contatta il server (heartbeat) e riceve configurazione e comandi.
4. La sonda prenota un lotto, lo cifra e lo trasmette.
5. Il server applica i dati e conferma l'acquisizione.
6. La sonda elimina il lotto dalla coda.

**Estensione E1 - server assente**: i passi 3-6 non avvengono; la coda cresce.
Al ritorno del server il flusso riprende dal passo 3 e la coda viene svuotata.

### UC-03 Governo di una sonda
**Attori**: amministratore di tenant o analista.
**Flusso principale**: dalla scheda della sonda l'operatore modifica la
configurazione oppure accoda un comando; il provvedimento viene consegnato al
primo contatto utile e la sonda ne conferma l'esito, tracciato nell'audit.

---

## 6. Matrice di tracciabilita' (estratto)

| Requisito stakeholder | Requisiti di sistema | Componente realizzativo |
|---|---|---|
| SH-01 | SR-30, SR-31 | `snapserver.queries`, `blueprints.dashboard` |
| SH-02 | SR-16..SR-21 | `snapserver.tenancy`, `blueprints.admin` |
| SH-03 | SR-22..SR-29 | `snapserver.security`, `blueprints.admin` |
| SH-04 | SR-32, SR-33 | `snapserver.audit`, `blueprints.audit_views` |
| SH-05 | SR-01..SR-10, SR-33, NFR-01..NFR-03 | `snapserver.crypto`, `snapprobe.crypto`, `snapserver.audit` |
| SH-06 | SR-04, SR-15, SR-15a | `blueprints.probes`, `snapprobe.views` |
| SH-07 | SR-11..SR-14 | `snapprobe.agent`, `snapprobe.store` |
| SH-09 | SR-40..SR-80 | `snapserver.inventory_queries`, `snapserver.fingerprint`, `snapserver.snmp_tables`, `blueprints.inventory`, `snapprobe.scanner` |
| SH-10 | SR-90..SR-112 | `snapserver.checks`, `snapserver.checks_queries`, `blueprints.checks`, `snapprobe.checker` |
| SH-11 | SR-100..SR-135 | `snapserver.reports`, `snapserver.rules`, `snapserver.events`, `snapserver.notifications`, `snapserver.channels`, `snapserver.maintenance` |
| SH-12 | SR-136..SR-150 | `snapserver.threat`, `snapserver.threat_sources`, `blueprints.threat` |
| SH-13 | SR-81..SR-86, SR-165..SR-167 | `snapserver.operations`, `snapserver.searchdb`, `blueprints.operations` |
| SH-14 | SR-151..SR-160 | `snapserver.zones`, `snapserver.threat`, `snapserver.inventory_queries`, `blueprints.inventory` |
| SH-16 | SR-171..SR-176 | `snapprobe.web_probe`, `snapserver.node_json`, `snapserver.rielabora`, `snapserver.zone_admin` |
| SH-15 | SR-161..SR-164 | `snapserver.reports.dataset_wide`, `snapserver.reports.render_wide`, `snapserver.reports.storage`, `blueprints.reports` |
| SH-08 | SR-34, SR-34a..SR-34e, SR-35, SR-35a | `auth.preferences`, `static/js`, `static/css/snap.css`, `snapserver.settings`, `snapprobe.settings` |
