"""
snap probe - Orchestratore della scansione progressiva.

Sei fasi, ciascuna con il proprio bersaglio, il proprio comando e la propria
cadenza. Una sola esecuzione di nmap per volta: la fase piu' urgente scaduta
viene eseguita e conferita, poi si torna al ciclo dell'agente.

  1 discovery  la subnet          host vivi, MAC e produttore dove disponibili
  2 ports      i nodi noti        porte aperte
  3 services   i nodi con porte   servizio, prodotto, versione
  4 os         i nodi con porte   sistema operativo
  5 deep       i nodi incerti     UDP selettivo e script NSE mirati
  6 monitor    i nodi confermati  raggiungibilita' e latenza

Perimetro vincolante
--------------------
La sonda scansiona esclusivamente indirizzi contenuti nelle subnet ricevute dal
server. Un bersaglio esterno non viene scansionato e produce un'annotazione di
gravita' alta. La verifica di appartenenza e' duplicata rispetto al server: i due
applicativi sono distribuiti separatamente e non condividono codice, quindi la
duplicazione e' voluta e va mantenuta allineata.

Regola di ammissione
--------------------
Un host vivo che non porta altre informazioni resta 'candidato' e non viene
conferito: la fase delle porte lo conferma o lo scarta come errore di rete.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import time
import uuid
from datetime import datetime, timezone

from . import mac_costruttori
from . import nmap_xml
from . import snmp_raccolta
from .nmap_runner import NmapAborted, NmapError, NmapRunner, NmapTimeout, filtra_script

# Fasi nell'ordine di priorita' con cui vengono valutate.
STAGES = ("discovery", "monitor", "raffica", "ports", "services", "os", "deep",
          "snmp", "smb", "vuln", "web")

# Fasi che compongono il profilo di un dispositivo. Il nodo viene conferito solo
# quando tutte quelle applicabili sono state eseguite su di esso: il server
# riceve dispositivi interi, non frammenti.
# Il profilo di un dispositivo resta definito dalle tre fasi che lo compongono: porte,
# servizi, sistema operativo. La RAFFICA non cambia il contratto -- lo SODDISFA in un
# processo solo, marcando tutte e tre (vedi FASI_COPERTE_DALLA_RAFFICA). Cosi' il primo
# profilo si ottiene in una passata di pochi secondi, e le tre fasi restano disponibili
# per la RI-ispezione di un nodo gia' conferito, dove interessa una cosa per volta.
PROFILE_STAGES = ("ports", "services", "os")

# Le fasi che la raffica SVOLGE. Quando la raffica riesce, queste risultano fatte:
# ha chiesto le porte, le versioni dei servizi e il sistema operativo in un colpo
# solo, e dichiararle da fare significherebbe rifarle.
FASI_COPERTE_DALLA_RAFFICA = ("ports", "services", "os")

# Cadenze predefinite, in secondi. La scoperta ricensisce il perimetro: una rete
# non cambia di minuto in minuto, e su centinaia di subnet una scoperta continua
# terrebbe occupata la rete senza necessita'. I cambiamenti sui nodi gia' noti
# sono colti dal monitoraggio e dalle ri-ispezioni, non dalla scoperta.
# Tempo massimo speso da un compito di lettura web. Un compito porta fino a qualche
# decina di dispositivi e alcuni apparati impiegano secondi a comporre la propria
# pagina: senza questo tetto un solo compito potrebbe occupare la sonda per mezz'ora.
BUDGET_WEB_COMPITO = 180.0

DEFAULT_CADENCES = {
    "discovery": 3 * 24 * 3600,
    # La raffica e' il primo profilo di un nodo: si esegue quando il nodo non ce l'ha
    # ancora, non a cadenza. Il valore serve alla RI-esecuzione su un nodo gia'
    # profilato, e sei ore sono la stessa cadenza che avevano le porte.
    "raffica": 21600,
    "ports": 21600,
    "services": 43200,
    "os": 259200,
    "deep": 604800,
    "monitor": 120,
    # Ricognizione delle presenze sulle reti senza fili (vedi presence.py). Non e' una
    # fase del ciclo: ha un thread proprio, e questa e' la sua cadenza.
    "presence": 120,
    # SNMP riguarda pochi nodi e cambia poco: mezza giornata basta. Quando la porta
    # si apre per la prima volta, la lettura avviene subito perche' il nodo non ha
    # ancora una lettura in archivio.
    "snmp": 43200,
    # SMB (139/445) racconta di una postazione o di un server Windows: sistema
    # operativo, dominio, condivisioni, utenze. Come SNMP cambia poco -- mezza
    # giornata basta -- e alla prima apertura della porta la lettura avviene subito.
    "smb": 43200,
    # La ricerca di vulnerabilita' con nmap: la postura cambia lentamente (una patch,
    # un servizio riconfigurato), quindi una volta al giorno basta; un nodo mai
    # verificato ha comunque la precedenza.
    "vuln": 86400,
    # Le pagine di gestione cambiano poco -- una volta al giorno basta -- ma quando
    # una porta web si apre per la prima volta la lettura avviene subito, perche' il
    # nodo non ha ancora nessuna lettura in archivio.
    "web": 86400,
}

# Porte UDP che identificano un dispositivo quando le prove TCP non bastano.
UDP_IDENTIFYING_PORTS = "161,137,5353,1900,123,67,47808"
# Porte per il ping TCP del monitoraggio quando il nodo non ne ha di note. Sono le
# piu' diffuse fra apparati e postazioni: meglio di ICMP da solo, che su molte reti
# aziendali e' bloccato.
MONITOR_FALLBACK_PORTS = "443,80,22,3389,445,135,8080"
# Quante porte al massimo entrano nei probe di ping: l'elenco cresce con i bersagli
# del compito, e un elenco lunghissimo rallenterebbe lo sweep senza aggiungere prove.
MONITOR_PING_PORTS_MAX = 12
# Stati che PROVANO la presenza dell'host: `closed` e' un RST, e un RST lo manda solo
# qualcuno che c'e'. `filtered` non prova nulla -- e' il silenzio di un firewall.
ALIVE_PORT_STATES = ("open", "closed")

# Script NSE mirati: pochi, scelti per il contributo all'identificazione.
NSE_SCRIPTS = "snmp-info,smb-os-discovery,http-title,upnp-info"

# Script NSE di ARRICCHIMENTO per la fase dei servizi. Sono tutti di categoria
# "default"/"discovery" e di SOLA LETTURA: interrogano cio' che il servizio dichiara,
# senza tentare credenziali ne' modificare nulla. nmap li applica solo alle porte a cui
# ciascuno si riferisce (portrule): elencarli non li esegue su tutti i bersagli, quindi
# il costo si paga solo dove il servizio esiste.
#
# Scelti per quanto identificano un nodo, servizio per servizio:
#   ssl-cert        certificato TLS: soggetto e SAN portano spesso il nome host e
#                   l'organizzazione reali, anche dietro un indirizzo anonimo;
#   http-title      titolo della pagina: nome dell'apparato o dell'applicazione;
#   http-server-header / http-generator  prodotto e versione del server web;
#   http-favicon    impronta dell'icona: identifica famiglie di apparati;
#   rdp-ntlm-info   su 3389 dichiara nome computer, dominio e build di Windows;
#   nbstat          nome NetBIOS e MAC (la risposta a "nbtstat -A"): identita' di rete;
#   ssh-hostkey     impronta della chiave host SSH: distingue un apparato riconfigurato;
#   ssh2-enum-algos / ssl-enum-ciphers  algoritmi deboli: sono riscontri di sicurezza.
#
# Esclusi di proposito: qualunque script di categoria "brute", "intrusive"
# aggressiva, "exploit", "dos" o "vuln" attivo. Un inventario non forza serrature.
ENRICHMENT_SCRIPTS = ("ssl-cert,http-title,http-server-header,http-generator,"
                      "http-favicon,rdp-ntlm-info,nbstat,ssh-hostkey,ssh2-enum-algos")

# SNMP e' la fonte piu' ricca su un apparato di rete: nome, descrizione del sistema,
# interfacce, tabelle di instradamento, processi, software installato. Quando la porta
# risponde si leggono tutti gli script INFORMATIVI, in sola lettura.
#
# Restano fuori di proposito: `snmp-brute`, che indovina le community -- cioe' tenta
# credenziali -- e qualunque script di scrittura. Un inventario non forza serrature.
SNMP_SCRIPTS = ("snmp-info,snmp-sysdescr,snmp-interfaces,snmp-netstat,"
                "snmp-processes,snmp-win32-software,snmp-win32-services,"
                "snmp-win32-shares,snmp-win32-users,snmp-hh3c-logins")
SNMP_PORT = 161

# SMB e' la fonte piu' ricca su una postazione o un server Windows: sistema operativo
# esatto, dominio, nome del computer, condivisioni pubblicate, utenze locali. Dove la
# 139 (NetBIOS) o la 445 (SMB diretto) rispondono, si esegue esattamente il comando
# chiesto dall'operatore:
#     nmap -p 139,445 --script smb-os-discovery,smb-enum-shares,smb-enum-users <ip>
#
# Restano fuori di proposito: `smb-brute`, che tenta credenziali, e qualunque script
# che scriva. E' enumerazione di SOLA LETTURA: si legge cio' che il servizio concede a
# chi lo interroga, non si forza nulla.
SMB_SCRIPTS = ("smb-os-discovery,smb-enum-shares,smb-enum-users,"
               "smb-security-mode,smb2-security-mode,smb-protocols,smb2-time")
SMB_PORTS = "139,445"
# Le due porte SMB. La 139 e' quella che l'operatore ha indicato (NetBIOS su TCP); la
# 445 e' il suo equivalente moderno, che su Windows recenti e' spesso la sola aperta.
# Si interroga chi ha aperta l'una O l'altra: scandire solo la 139 lascerebbe fuori
# gran parte dei server.
SMB_PORT_NUMBERS = (139, 445)
# Gli script SMB interrogano SAMR e LSA e su un dominio popoloso l'enumerazione delle
# utenze non e' istantanea: tre minuti sono un margine prudente, e riguardano pochi
# nodi per volta.
SMB_HOST_TIMEOUT = "180s"

# Ricerca di vulnerabilita' con nmap: SOLO script di rilevazione, mai di sfruttamento.
# Verificano la presenza di un difetto senza sfruttarlo. Sono esclusi di proposito gli
# script di categoria `exploit`, `dos` e `brute`: un inventario accerta, non attacca.
# nmap applica ciascuno solo alla porta pertinente (portrule), quindi il costo si paga
# dove il servizio esiste.
#   ssl-heartbleed        CVE-2014-0160 (Heartbleed)
#   ssl-poodle            CVE-2014-3566 (POODLE)
#   ssl-ccs-injection     CVE-2014-0224 (OpenSSL CCS injection)
#   ssl-dh-params         parametri Diffie-Hellman deboli (Logjam)
#   smb-vuln-ms17-010     CVE-2017-0143 (EternalBlue) -- sola verifica
#   smb-double-pulsar-backdoor  presenza dell'impianto DoublePulsar
#   http-vuln-cve2017-5638  Apache Struts (RCE) -- sola verifica
VULN_SCRIPTS = ("ssl-heartbleed,ssl-poodle,ssl-ccs-injection,ssl-dh-params,"
                "smb-vuln-ms17-010,smb-double-pulsar-backdoor,"
                "http-vuln-cve2017-5638")
# Le porte che rendono utile la fase: TLS, SMB, HTTP. Un nodo che non ne espone nessuna
# non ha nulla da verificare con questi script.
VULN_PORT_NUMBERS = (443, 8443, 993, 995, 465, 636, 990, 445, 139, 80, 8080, 8000, 8888)
# Gli script di vulnerabilita' fanno piu' giri di negoziazione: cinque minuti per host
# sono un margine prudente, e riguardano pochi nodi per volta.
VULN_HOST_TIMEOUT = "300s"

# Un nodo con poche porte aperte e senza sistema operativo rilevato e' incerto:
# e' l'approssimazione locale del giudizio che il server esprime con la
# confidenza, e serve solo a decidere dove spendere la fase di approfondimento.
UNCERTAIN_MAX_PORTS = 2

# Quante volte si tenta di confermare un candidato prima di scartarlo.
MAX_CANDIDATE_ATTEMPTS = 2

# DECISIONE: un candidato che nmap abbandona per scadenza NON si scarta, mai.
#
# C'e' stata una soglia qui (`MAX_TIMEOUT_ABANDONMENTS`), introdotta con una misura
# vera: sul campo un host e' stato abbandonato oltre 600 volte, tenendo occupato uno
# slot per ore senza produrre nulla. Il problema esiste, la soluzione era sbagliata --
# un host abbandonato per scadenza non e' stato ESAMINATO: e' ignoto, non assente, e
# scartarlo lo fa sparire dall'inventario per un limite nostro (e' il caso misurato
# della multifunzione con undici porte aperte). Vedi `_annota_scadenza`.
#
# Cosa risponde allo spreco: si guarda quell'host piu' RARAMENTE, contando
# `timeout_count`. E' cio' che questo commento prescriveva e che mancava: senza,
# gli stessi indirizzi tornavano in coda a OGNI ciclo e la scansione non finiva mai.
# Misurato sul campo: 66 abbandoni consecutivi sugli stessi 24 indirizzi, ondate da
# 257 s che restituivano zero host, per ore. Vedi `ATTESA_RITENTATIVO_*` e
# `_scadenza_troppo_recente`.
#
# L'attesa raddoppia a ogni abbandono e si ferma a un tetto: l'host resta IGNOTO --
# non scartato, non assente -- ma smette di occupare uno slot in ogni ciclo. Chi
# torna a rispondere viene ripreso al primo tentativo utile.

# Attesa prima di riprovare un host che nmap ha abbandonato per scadenza. Raddoppia
# a ogni abbandono (1 -> 30 min, 2 -> 1 h, 3 -> 2 h, ...) fino al tetto.
#
# Perche' un'attesa e non un tetto ai tentativi: un host abbandonato non e' stato
# ESAMINATO, quindi non si puo' concludere nulla su di lui. Riprovarlo ogni ciclo e'
# spreco, rinunciarvi e' perdita di inventario; riprovarlo di rado e' l'unica delle
# tre che non butta via un dato ne' blocca le altre.
ATTESA_RITENTATIVO_BASE_SEC = 30 * 60
ATTESA_RITENTATIVO_TETTO_SEC = 24 * 3600

# Quante volte una FASE DI ISPEZIONE puo' scadere su un nodo GIA' confermato prima di
# rinunciare e segnarla "tentata". Uno: un nodo con le porte aperte e' gia' inventario
# utile, e su reti dove la rilevazione dei servizi scade sistematicamente (host VoIP che
# appendono nmap, 23 su 24 abbandonati in una passata) insistere terrebbe migliaia di
# nodi "in lavorazione" per giorni. Un solo tentativo scaduto basta a capire che quella
# fase non concludera': si conferisce il nodo con le porte, e i servizi/OS lo
# arricchiranno alla ri-ispezione, se un giorno risponderanno.
MAX_STAGE_TIMEOUTS = 1

# Dimensione del gruppo di host che nmap scansiona in PARALLELO nelle fasi di
# ispezione. Senza questo, nmap adatta il gruppo partendo da pochi host e serializza:
# sul campo una passata di servizi su 24 host abbandonati e' durata 765s (23 su 24
# scaduti a 180s), perche' nmap ne teneva ~6 alla volta. Forzando il gruppo alla
# dimensione del compito la passata dura quanto il singolo host (~180s), non la somma.
# Porte che la scansione NON tocca.
#
# Il valore predefinito e' l'intervallo dei server X (6000-6009). Motivo, misurato:
# su tre postazioni di amministrazione girava MobaXterm, che tiene un X server in
# ascolto sulla 6000; ogni passata della sonda apriva sul PC dell'operatore una
# finestra "un'applicazione su <indirizzo> vuole accedere al server X: consenti?".
# Una scansione di inventario non deve interrompere chi lavora.
#
# COSA SI PERDE, detto perche' non lo si scopra a un collaudo: un X server in
# ascolto sulla rete e' un'esposizione vera (X11 senza autenticazione permette di
# leggere i tasti premuti e catturare lo schermo delle altre finestre), e da qui in
# avanti la sonda non la rilevera' piu'. La scelta e' dell'operatore ed e'
# reversibile: si svuota l'impostazione `scan_exclude_ports` e la rilevazione torna.
DEFAULT_EXCLUDED_PORTS = "6000-6009"
# Allowlist: solo cifre, virgole e trattini. Il valore finisce sulla riga di comando
# di nmap, e cio' che finisce su una riga di comando si valida, non si spera.
EXCLUDED_PORTS_PATTERN = re.compile(r"^[0-9,\-]+$")

MAX_HOSTGROUP = 64

# --------------------------------------------------------------------------- #
# Il motore delle porte: due livelli, un processo, nessun tetto per host
# --------------------------------------------------------------------------- #
# Riprogettato dopo che una /24 non finiva mai. Le decisioni e le misure che le
# giustificano stanno in docs/14_MOTORE_DI_SCANSIONE.md; qui il minimo per capire
# il codice senza aprire il documento.
#
# IL VINCOLO. Il ritmo di invio di nmap e' governato dal suo controllo di
# congestione. Su questa rete gli host SCARTANO i SYN (rispondono al ping, tacciono
# su ogni porta): con il 100% di mancate risposte nmap legge congestione e scende a
# ~10 pacchetti/s. Il budget e' PER PROCESSO, quindi N host in un processo costano N
# volte uno -- e con un tetto di tempo per host scadono tutti. Misurato: 24 host da
# 1000 porte richiedono ~41 minuti di pacchetti mentre ciascuno viene abbandonato a
# 4 minuti; esito osservato, 66 abbandoni di fila e zero host restituiti.
#
# COSA NON FUNZIONA, provato e scartato:
#   * forzare il ritmo (`--min-rate`): dieci volte piu' veloce e PERDE porte aperte
#     (0-4 su 13 note, esiti irriproducibili). La velocita' che perde dati non e'
#     velocita';
#   * dividere le porte fra piu' processi: piu' lento E meno accurato di un processo
#     solo (82,3 s e 7/13 contro 33,5 s e 12/13), perche' i processi puntano agli
#     stessi bersagli e si contendono lo stesso percorso.
#
# COSA FUNZIONA. Un solo processo, tutti gli host, e nmap che li lavora a GRUPPI:
# dentro un gruppo le sonde si distribuiscono su host diversi, quindi nessun
# bersaglio viene limitato dal proprio rate limiting e la finestra resta aperta
# perche' qualcuno risponde. Misurato su 16 host vivi con l'elenco di
# riconoscimento: 2,6 s e recall COMPLETO (33 coppie host-porta su 33 realmente
# aperte).

# Quanti host nmap lavora insieme dentro il processo. E' il solo parametro di
# taratura del motore.
#
# MISURATO sulla /24 del committente, a rete libera, 28 porte per host, confrontando
# il ritrovamento di 33 coppie host-porta accertate aperte in quel momento:
#
#     gruppi da  16  ->  449 s   27 su 33
#     gruppi da  32  ->  444 s   30 su 33
#     gruppi da  64  ->  445 s   33 su 33   <- scelto
#
# Due letture, entrambe utili:
#   * il TEMPO non dipende dalla dimensione del gruppo (445 s in tutti i casi):
#     dipende dal lavoro totale, host x porte;
#   * il RECALL migliora con gruppi piu' grandi, perche' piu' host che rispondono
#     tengono aperta la finestra di congestione di nmap.
#
# Perche' 64 e non tutta la subnet in un gruppo: in esercizio questa fase gira
# insieme alle altre, e sotto contesa i gruppi grandi crollano -- la stessa prova
# con la sonda che scandiva in parallelo dava 14 su 33 con un gruppo da 254. Con 64
# il recall e' pieno e resta margine per il carico concorrente.
# QUANTI HOST IN UN PROCESSO DI FASE PORTE. Uguale al gruppo: un processo, un gruppo.
#
# Misurato in esercizio, e i numeri stanno nel pianificatore accanto alla suddivisione:
# 64 host in un processo danno recall completo; 256 in un processo danno ZERO porte su
# 256 host; oltre 500 non terminano entro le due ore del tetto. Il budget di pacchetti
# di nmap e' per PROCESSO, quindi piu' gruppi nello stesso processo se lo dividono.
# --------------------------------------------------------------------------- #
# Controllo di sanita' della scoperta
# --------------------------------------------------------------------------- #
# QUANDO UNA SCOPERTA NON E' CREDIBILE, E PERCHE' VA RIFIUTATA.
#
# Il caso misurato, e va raccontato per intero perche' e' costato una giornata di
# lavoro a compensare a valle un difetto che stava a monte.
#
# Sulla subnet 10.10.60.0/24 questo prodotto dichiarava 256 nodi attivi su 256
# indirizzi possibili. Dal PC dell'operatore, lo stesso `nmap -sn` sulla stessa
# subnet trovava 5 host. La differenza non erano gli argomenti: anche `nmap -sn`
# nudo, eseguito DENTRO il contenitore della sonda, trovava 256 su 256.
#
# La causa e' la rete del contenitore. Su Docker Desktop la sonda gira in
# `network_mode: bridge` e il NAT della macchina virtuale RISPONDE PER OGNI
# INDIRIZZO: ogni sonda di raggiungibilita' torna positiva, compresi l'indirizzo di
# rete e quello di broadcast, dove un host non puo' esistere. Il documento del
# contenitore lo avvertiva ("su Docker Desktop la rete host e' limitata e la sonda
# non vedrebbe la LAN: in esercizio la sonda va su Linux"), ma il prodotto non se ne
# accorgeva: produceva 251 nodi inesistenti e li conferiva come inventario.
#
# Un inventario inventato e' il peggior esito possibile per questo prodotto. Un dato
# mancante si vede; 251 nodi falsi con porte e classificazioni sembrano lavoro fatto,
# e portano a decisioni sbagliate su una rete vera.
#
# I due segnali, insieme, sono conclusivi:
#   1. rispondono l'indirizzo di RETE o quello di BROADCAST -- la' non c'e' un host,
#      per definizione (RFC 950): se rispondono, risponde qualcos'altro;
#   2. risponde QUASI TUTTO il segmento (oltre la soglia): una /24 con 254 host tutti
#      attivi esiste, ma insieme al primo segnale non e' una rete, e' un intermediario.
#
# In quel caso la scoperta si RIFIUTA: nessun nodo registrato, e il motivo scritto nel
# diario. Meglio una subnet vuota e un avviso che 251 nodi inventati.
SANITA_QUOTA_SOSPETTA = 0.95

# --------------------------------------------------------------------------- #
# Interfaccia di uscita delle scansioni
# --------------------------------------------------------------------------- #
# PERCHE' SI PUO' FISSARE, con il caso che lo ha imposto.
#
# Una sonda che gira su una macchina d'ufficio non ha una sola interfaccia. Misurato
# su un'installazione reale (Windows, sonda fuori dal contenitore): NOVE interfacce --
# la LAN, due adattatori virtuali di Docker/WSL e sei link-local -- e nella tabella di
# instradamento due rotte predefinite:
#
#   0.0.0.0/0   eth6  metrica 40   gateway 10.10.60.1   <- Wi-Fi, SPENTO, senza IP
#   0.0.0.0/0   eth7  metrica 55   gateway 10.20.10.1   <- la LAN vera, attiva
#
# La rotta con la metrica migliore era quella di un'interfaccia SPENTA, rimasta appesa
# al Wi-Fi. Tutto cio' che non stava sulla rete locale usciva da la': le scansioni
# partivano da un'interfaccia morta, e l'esito era incoerente senza che nulla lo
# dicesse.
#
# nmap sceglie l'interfaccia dalla tabella di instradamento, quindi eredita l'errore.
# Dichiararla esplicitamente e' l'unica difesa: `-e` per l'interfaccia e `-S` per
# l'indirizzo di partenza. Vale solo con i socket raw -- una scansione per connessione
# passa dallo stack del sistema e non li accetta.
#
# Si configura con l'ambiente (la sonda sa dove gira) oppure nell'archivio locale:
#   SNAP_PROBE_SCAN_INTERFACE=eth7          il nome che usa NMAP (nmap --iflist)
#   SNAP_PROBE_SCAN_SOURCE_IP=10.20.10.42
#
# Vuoto significa "come decide il sistema": e' il comportamento di sempre, ed e' giusto
# dove c'e' una sola interfaccia (la sonda in contenitore su Linux con rete host).

# Che cosa e' un nome di interfaccia accettabile. Non e' pedanteria: questo valore
# finisce sulla riga di comando di un processo, e un'allowlist e' l'unico modo di
# escludere che ci finisca altro. Comprende la forma di Windows
# (`\Device\NPF_{GUID}`) oltre ai nomi brevi.
RE_INTERFACCIA = re.compile(r"^[A-Za-z0-9_.:\\{}-]{1,64}$")

MAX_HOST_PER_PROCESSO_PORTE = 64

GRUPPO_HOST = 64

# Ritmo accurato misurato, sonde al secondo, un processo. Serve a calcolare quanto
# tempo concedere a un processo.
#
# Vale 16 e non piu': una stima precedente di 68 veniva da una prova con 9 porte per
# host, e il ritmo NON e' indipendente dal numero di porte -- con piu' porte per host
# nmap incontra piu' silenzio di fila e riduce la finestra piu' spesso. Il valore
# giusto e' quello misurato nella condizione d'uso: 7.112 sonde in 445 s.
#
# Se la rete cambia si rimisura e si aggiorna qui: e' un parametro dichiarato, non
# una costante magica.
SONDE_AL_SECONDO = 16.0

# Di quanto il tetto di tempo del processo sta sopra il lavoro misurato.
#
# Due, non quattro come nella vecchia formula "a ondate": la' la stima era indiretta
# (un tetto per host moltiplicato per il numero di ondate) e serviva un margine
# ampio. Qui la stima viene da una misura diretta -- sonde diviso ritmo -- quindi il
# doppio basta e tiene il ciclo reattivo: con il fattore 4 un processo appeso
# occupava un posto per mezz'ora dove il lavoro ne richiede sette minuti.
MARGINE_TEMPO_PORTE = 2

# Porte del livello di RICONOSCIMENTO.
#
# Non sono "le piu' comuni" per frequenza statistica: sono quelle che dicono CHE
# COS'E' un apparato -- gestione, stampa, telefonia, condivisione, banche dati,
# controllo remoto. E' la differenza fra un inventario e un elenco di numeri.
#
# Perche' poche: il costo di una passata e' host x porte, e su questa rete 142
# indirizzi su 256 non hanno ALCUNA porta aperta fra le prime mille. Chiederne mille
# a tutti costa oltre un'ora per non imparare nulla; chiederne ventotto costa
# ~7.100 sonde, cioe' un paio di minuti per l'intera /24. La profondita' si riserva
# a chi ha mostrato un segnale.
PORTE_RICONOSCIMENTO = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 515, 631,
    1025, 1433, 1521, 3306, 3389, 5060, 5357, 5432, 5900, 7070, 8080, 8443, 9100,
    # Le due porte che identificano un TELEFONO, e le sole che un telefono offra:
    # 62078 e' il servizio di sincronizzazione di iOS (lockdownd, aperto su ogni
    # iPhone e iPad), 5555 il ponte di debug Android quando e' abilitato. Senza
    # queste due, un dispositivo mobile non ha alcun segnale di porta e resta
    # riconoscibile solo dal produttore della scheda di rete -- che sulle subnet
    # instradate non si ha.
    5555, 62078,
)

# Porte del livello di PROFONDITA'.
#
# Sostituiscono `--top-ports 1000`, e la differenza non e' il numero: e' il CRITERIO.
# Le prime mille di nmap sono ordinate per frequenza statistica su Internet, dove
# meta' sono servizi che su una rete di uffici non esistono e mancano invece porte di
# gestione che qui contano. Queste sono scelte per FAMIGLIA DI APPARATO -- postazioni
# Windows, Linux, apparati di rete, stampanti, telefoni, telecamere, banche dati,
# gestione fuori banda -- piu' tutte quelle effettivamente trovate aperte su questa
# rete.
#
# Il costo scende con il numero: la passata di profondita' riguarda i soli host che
# hanno mostrato un segnale, e con ~230 porte invece di 1000 costa un quarto.
#
# L'elenco resta diviso per famiglia perche' e' cosi' che si mantiene: chi aggiunge un
# apparato nuovo sa dove mettere le sue porte, e chi legge sa perche' una porta c'e'.
PORTE_PROFONDITA_PER_FAMIGLIA = {
    # Trovate aperte sulla rete del committente: nessuna di queste puo' mancare,
    # sono l'unico dato empirico che si ha.
    #
    # La 6000 (X11) e' in elenco DI PROPOSITO anche se l'esclusione predefinita la
    # sopprime (DEFAULT_EXCLUDED_PORTS: apriva una finestra "consenti accesso al
    # server X?" sul PC di chi lavorava). L'esclusione e' il punto di controllo
    # UNICO e configurabile: chi la svuota vuole tornare a rilevare un X11 esposto
    # -- che e' un'esposizione vera -- e deve ottenerlo senza toccare il codice. Se
    # invece togliessimo la porta da qui, svuotare l'esclusione non avrebbe effetto:
    # sarebbe un secondo cancello nascosto. Verificato che `--exclude-ports` prevale
    # su `-p` esplicito (vedi test_porte_escluse.py).
    "osservate": (22, 53, 80, 111, 135, 139, 443, 445, 1000, 1025, 3389, 5357,
                  6000, 7070, 8080, 8081, 8443),
    # Postazioni e server Windows: RPC e le sue porte alte, dominio (Kerberos,
    # LDAP, catalogo globale), amministrazione remota (RDP, WinRM, WSD).
    "windows": (42, 88, 135, 139, 389, 445, 464, 593, 636, 1026, 1027, 1028, 1029,
                1030, 2179, 3268, 3269, 3343, 3389, 5357, 5722, 5985, 5986, 9389,
                47001),
    # Linux e Unix: accesso, posta, condivisione file, stampa, servizi storici che
    # su una macchina non aggiornata sono ancora aperti.
    "linux": (21, 22, 25, 69, 79, 110, 111, 143, 177, 465, 512, 513, 514, 515, 587,
              631, 873, 993, 995, 2049, 3306, 5432, 6001, 6002, 10000),
    # Apparati di rete: gestione (SSH, Telnet, web, NETCONF), instradamento (BGP),
    # autenticazione degli accessi (RADIUS, TACACS+) e le porte proprietarie che
    # identificano un costruttore (Winbox di MikroTik, Smart Install di Cisco).
    "rete": (22, 23, 49, 80, 179, 443, 830, 1723, 1812, 1813, 2000, 4786, 5000,
             7547, 8291, 8728, 8729, 32764),
    # Stampanti e multifunzione: stampa diretta, IPP, LPD e le interfacce di
    # gestione. Su una rete di uffici sono fra gli apparati piu' numerosi.
    "stampa": (21, 23, 80, 443, 515, 631, 7627, 8080, 9100, 9101, 9102, 9103, 9220,
               9500, 9600),
    "voip": (1719, 1720, 2000, 5060, 5061, 5090, 8000),
    "videosorveglianza": (80, 443, 554, 8000, 8081, 8554, 8899, 34567, 37777, 37778),
    # UPS, automazione e impianti: Modbus e i suoi vicini. Un impianto raggiungibile
    # da una rete di utenza e' un riscontro di sicurezza, non un dettaglio.
    "impianti": (102, 502, 789, 1911, 2404, 3052, 4911, 5000, 20000, 44818),
    "archiviazione": (111, 445, 548, 2049, 3260, 5000, 5001, 9000, 50000),
    "banche_dati": (1433, 1521, 1830, 3306, 5432, 5433, 5984, 6379, 7000, 7001,
                    8086, 9042, 9200, 9300, 11211, 27017, 27018, 27019, 50000),
    # Gestione fuori banda: IPMI, WBEM, agenti di monitoraggio e -- soprattutto --
    # Intel AMT, che su una postazione da ufficio e' un'interfaccia di gestione
    # completa e indipendente dal sistema operativo.
    "fuori_banda": (161, 199, 623, 664, 2381, 3283, 4949, 5666, 5938, 5988, 5989,
                    6568, 9990, 10050, 10051, 16992, 16993),
    "virtualizzazione": (902, 903, 2375, 2376, 2379, 6443, 8006, 10250),
    "copie": (8014, 9392, 13720, 13724),
    "desktop_remoto": (1494, 2222, 2598, 3390, 4899, 5800, 5900, 5901, 5902),
    "web_gestione": (81, 88, 591, 1080, 3000, 3128, 4000, 4443, 4444, 6080, 7080,
                     8000, 8001, 8008, 8009, 8010, 8069, 8082, 8083, 8088, 8090,
                     8140, 8161, 8180, 8181, 8280, 8500, 8834, 8880, 8888, 9080,
                     9090, 9091, 9443, 10443, 15672),
    "trasferimento": (20, 26, 69, 115, 873, 989, 990, 2121, 2525, 3690, 6881, 8021),
    "code": (1099, 4505, 4506, 4848, 5222, 5672),
    # Protocolli storici: aperti solo su macchine mai aggiornate, ed e' esattamente
    # per questo che si guardano -- trovarli E' il riscontro.
    "storici": (7, 9, 13, 17, 19, 37, 70, 113, 119, 194, 540, 543, 544, 2323, 6667,
                6668),
    # Dispositivi d'uso personale: sono le sole porte che un telefono o un tablet
    # offra. 62078 e' la sincronizzazione di iOS (aperta su ogni iPhone e iPad),
    # 5555 il ponte di debug Android -- che aperto in rete e' anche un'esposizione,
    # perche' consente di installare applicazioni senza autenticazione.
    "mobili": (5555, 62078),
    "varie": (5040, 7680, 9999),
}

# L'elenco piatto, ordinato: e' cio' che finisce sulla riga di comando di nmap.
PORTE_PROFONDITA = tuple(sorted({
    porta for porte in PORTE_PROFONDITA_PER_FAMIGLIA.values() for porta in porte
}))



# Tetto all'intensita' della rilevazione versione (-sV) nella fase dei servizi. Al
# massimo (7) nmap invia troppe sonde per porta: su apparati che non rispondono come
# previsto la fase si trascina per centinaia di secondi. Cinque mantiene le
# identificazioni comuni con una frazione delle sonde.
MAX_SERVICE_INTENSITY = 5

# Fasi che devono essere state svolte prima di poter dichiarare un nodo privo di
# informazioni: tutte quelle del profilo piu' l'approfondimento.
STAGES_BEFORE_REMOVAL = PROFILE_STAGES + ("deep",)
# Dopo lo scarto l'indirizzo continua a rispondere al ping: senza un periodo di
# attesa la scoperta lo ritroverebbe e il giro ricomincerebbe da capo.
NO_INFORMATION_COOLDOWN_SECONDS = 7 * 24 * 3600

# Profili di sforzo. Governano insieme il grado di parallelismo e l'aggressivita'
# della singola scansione: chiedere piu' thread E scansioni piu' profonde sono la
# stessa decisione, cioe' quanto carico si accetta di mettere sulla rete del
# cliente e sulla macchina della sonda.
#
#   workers            esecuzioni di nmap contemporanee
#   timing             modello temporale di nmap (-T)
#   version_intensity  insistenza del riconoscimento dei servizi
#   host_timeout       tempo massimo per host
#   hosts_per_task     nodi affidati a un singolo compito
#   udp_ports          porte UDP interrogate nella fase di approfondimento
# I profili di sforzo governano il PARALLELISMO FRA COMPITI e l'aggressivita' della
# singola scansione. Non governano piu' la fase delle porte, che ha un motore proprio
# (vedi GRUPPO_HOST e PORTE_RICONOSCIMENTO): quella usa UN processo con tutti gli
# host, perche' processi diversi puntati sugli stessi bersagli si contendono il
# percorso e perdono risposte -- misurato, 82,3 s e 7/13 contro 33,6 s e 12/13.
#
# Dove il parallelismo fra processi FUNZIONA: le fasi che lavorano su host DIVERSI e
# pochi (servizi, sistema operativo, letture SNMP/SMB/web). La' i processi non si
# contendono gli stessi bersagli e il ritmo si somma -- misurato, 32 processi su 32
# host diversi danno 159 sonde/s contro 9,9 di un processo solo, senza perdite.
#
# `hosts_per_task` resta a 1 per quelle fasi: un host per processo, molti processi.
# Le PORTE non stanno piu' nei profili: la fase porte usa due elenchi curati
# (PORTE_RICONOSCIMENTO e PORTE_PROFONDITA), gli stessi per ogni profilo. Un numero
# di porte regolabile era un parametro morto -- nessuno sapeva quale valore fosse
# giusto, e "le prime mille per frequenza" non e' un criterio per una rete di uffici.
# `host_timeout` vale per le fasi che eseguono script su un servizio: la' un apparato
# che non risponde come previsto puo' tenere appeso nmap, e il tetto e' l'unica cosa
# che lo ferma. Alla fase delle porte NON si passa piu'.
EFFORT_PROFILES = {
    "min": {
        # Il profilo gentile resta gentile: UNA scansione per volta. E' cio' che
        # promette, e la parallelizzazione e' l'opzione degli altri due -- non il
        # nuovo minimo. Con un host per compito e 100 porte costa ~10 s per host.
        "workers": 1, "timing": "-T2", "version_intensity": 2,
        "host_timeout": "120s", "hosts_per_task": 1, "udp_ports": "161,137",
        "label": "minimo: una scansione per volta, rete poco disturbata",
    },
    "med": {
        "workers": 16, "timing": "-T3", "version_intensity": 5,
        "host_timeout": "180s", "hosts_per_task": 1, "udp_ports": UDP_IDENTIFYING_PORTS,
        "label": "medio: sedici host in parallelo, equilibrio fra velocita e prudenza",
    },
    "max": {
        "workers": 32, "timing": "-T3", "version_intensity": 7,
        "host_timeout": "300s", "hosts_per_task": 1, "udp_ports": UDP_IDENTIFYING_PORTS,
        "label": "massimo: trentadue host in parallelo, inventario piu ricco e rapido",
    },
}
DEFAULT_EFFORT = "med"

# Tempi massimi per host proposti nelle interfacce. Non sono un vincolo tecnico
# ma un elenco di valori sensati: un menu chiuso evita di scrivere valori che
# nmap rifiuterebbe o che bloccherebbero una scansione per ore.
HOST_TIMEOUT_CHOICES = ("30s", "60s", "120s", "180s", "300s", "600s")
# Limiti di sicurezza: sotto i cinque secondi nmap non conclude nulla di utile,
# oltre la mezz'ora per host la scansione non termina in tempi ragionevoli.
HOST_TIMEOUT_MIN_SECONDS = 5
HOST_TIMEOUT_MAX_SECONDS = 1800
# Minimo per host nelle fasi che interrogano i servizi. Misurato sul campo su una
# stampante multifunzione con tredici porte note, intensita' 5:
#     90s  -> host abbandonato per scadenza, zero porte nell'XML
#    300s  -> concluso in 103,5 s, dispositivo riconosciuto
# Sotto questa soglia la fase gira senza produrre nulla e il profilo non avanza: il
# tempo per host non e' una preferenza, e' una condizione di funzionamento. Il valore
# scelto dall'operatore resta valido per la scoperta e per le porte.
MIN_HOST_TIMEOUT_INSPECTION = 180

# Tempo per host dello SWEEP di scoperta, indipendente dalla scelta dell'operatore:
# `-sn` manda pochi pacchetti e non scansiona porte, quindi non serve di piu'; e su
# una subnet fatta in gran parte di indirizzi morti un valore lungo allungherebbe la
# passata senza aggiungere informazione. Sta in una costante perche' lo usano DUE
# punti: gli argomenti di nmap e il calcolo del tempo massimo del processo -- quando
# erano due numeri distinti, il tetto della scoperta veniva calcolato su un valore
# che nmap non riceveva mai.
DISCOVERY_HOST_TIMEOUT = "20s"
# Fasi di COMPLETAMENTO del profilo: portano un nodo al conferimento (le porte le ha
# gia' dalla fase 'ports') e, dopo UNA sola scadenza, si segnano "tentate" -- il nodo
# viene conferito con cio' che ha.
#
# Hanno un trattamento distinto per il RADDOPPIO, non per il minimo. Il minimo resta
# quello misurato sopra: si e' provato ad abbassarlo a 90s per drenare piu' in fretta
# la frontiera, ed era sbagliato -- 90s e' proprio il valore misurato come inutile
# (host abbandonato, zero porte). Un floor sotto la soglia di funzionamento non rende
# la fase piu' veloce: la rende inutile, e il profilo non avanza comunque. Il
# drenaggio della frontiera si ottiene con il parallelismo delle sonde
# (SERVICE_MIN_PARALLELISM) e instradando gli host che nmap non restituisce, non
# accorciando il tempo sotto la soglia.
STAGES_PROFILE_COMPLETION = ("services", "os")
# Tetto per singolo script NSE nella fase servizi: gli script di arricchimento su un
# servizio che non risponde restano appesi oltre il tempo per host e trascinano l'intera
# passata. Legarli la riporta vicino al tempo per host. Generoso per gli script comuni,
# che rispondono in pochi secondi.
SERVICE_SCRIPT_TIMEOUT = "30s"
# Concorrenza minima delle sonde nella fase servizi. Davanti a molti host lenti o muti il
# controllo di congestione di nmap RIDUCE le sonde in volo e serializza il gruppo in piu'
# ondate: una passata da 24 host con tempo per host 90s si trascinava a ~300s (tre ondate)
# invece dei ~90-120s di una scansione davvero parallela. Un minimo di sonde in volo tiene
# il gruppo in parallelo. Valore prudente per una rete interna di inventario -- piu' sonde
# simultanee, non un flood -- scelto esplicitamente per privilegiare il drenaggio della
# frontiera su una rete di migliaia di nodi.
SERVICE_MIN_PARALLELISM = 24
# Tetto del tempo per host quando si riprova un host GIA' abbandonato per scadenza.
# Oltre questo il problema non e' il tempo: e' un apparato che non risponde come
# previsto, e insistere ruberebbe la passata a tutti gli altri.
MAX_HOST_TIMEOUT_RETRY = 300
STAGES_NEEDING_TIME = ("services", "os", "deep", "snmp", "smb", "vuln")
# La raffica NON e' in elenco: ha un tempo per host proprio e generoso
# (ATTESA_RAFFICA_HOST), scelto sulla misura di `-A`, e non deve essere riscritto dal
# minimo delle fasi di ispezione ne' dal valore scelto dall'operatore.
# Gli script SNMP interrogano molte tabelle (interfacce, processi, software): su un
# apparato lento cinque minuti non sono troppi, e riguardano pochi nodi per volta.
SNMP_HOST_TIMEOUT = "300s"
# Community di sola lettura da provare. "public" e "private" sono i valori predefiniti
# che si trovano ancora oggi sugli apparati; non e' un tentativo di indovinare
# credenziali -- sono i valori di fabbrica, e trovarli aperti E' il riscontro.
SNMP_COMMUNITIES = "public,private"

# Per quanto tempo la compilazione del perimetro resta valida senza rileggerlo dal
# database. Il perimetro cambia solo quando il server ne consegna uno nuovo, e in
# quel momento l'agente invalida la compilazione: questa soglia e' la garanzia di
# ultima istanza, non il meccanismo ordinario di aggiornamento.
PERIMETER_CACHE_SECONDS = 5

# Oltre questo numero di porte l'elenco esplicito non conviene piu': si torna
# alle prime porte, che nmap ordina per frequenza.
MAX_EXPLICIT_PORTS = 300

# Margine sul tempo del processo, per l'avvio di nmap e la scrittura dell'XML.
PROCESS_TIMEOUT_MARGIN_SECONDS = 120
PROCESS_TIMEOUT_MAX_SECONDS = 7200
# Quante volte il tempo per host puo' durare un'ONDATA parallela (vedi
# `_process_timeout`). Non e' una stima a occhio: le due passate misurate su 24 host
# danno 470s con 180s per host (2,6x) e ~300s con 90s per host (3,3x). Quattro sta
# sopra entrambe e lascia margine per l'avvio e per le fasi degli script.
PROCESS_TIMEOUT_WAVE_FACTOR = 4
# Limite invalicabile, indipendente dal profilo.
#
# Era quattro, con l'idea che quattro processi nmap fossero tutto il carico
# accettabile su una sonda. La misura dice altro: il ritmo di invio e' governato da
# nmap PER PROCESSO, e con un solo processo si resta a ~9,5 pacchetti/s su bersagli
# che non rispondono. Il parallelismo dei processi e' percio' l'unica leva che
# aumenta la banda senza forzare il ritmo -- e forzarlo (`--min-rate`) e' stato
# provato e scartato: fa PERDERE porte aperte (misurato: un host con 135, 139, 445
# ne restituiva zero).
#
# Costo verificato sul campo con 34 processi nmap contemporanei: CPU 1,8%, memoria
# 443 MB su 12 CPU e 16 GB. Una scansione e' attesa di pacchetti, non calcolo.
# --------------------------------------------------------------------------- #
# LA RAFFICA: nmap -A piu' un catalogo NSE curato, su UN nodo per volta
# --------------------------------------------------------------------------- #
# PERCHE' UN NODO PER VOLTA, con i numeri misurati su questa rete.
#
# Il budget di pacchetti di nmap e' PER PROCESSO: dividerlo fra molti host stringe la
# finestra di congestione su ognuno, e su una rete che filtra (la posizione normale di
# una rete di PA) le porte vere passano per filtrate. Misurato:
#
#   1 host,  30 porte                ->   3,3 s, trova tutto
#   1 host,  -A                      ->  ~24 s, trova versione, sistema, traceroute
#   64 host in un processo           ->  recall completo
#   256 host in un processo          ->  ZERO porte su 256 host
#   500+ host in un processo         ->  non termina in 2 ore, la fase scade
#
# Da qui la struttura: la ricognizione dice CHI risponde, poi ogni nodo ha il proprio
# processo con tutto quello che nmap sa fare. Il parallelismo sta nel pool -- fino a
# MAX_WORKERS processi insieme -- dove nmap non lo penalizza, invece che dentro un
# processo solo dove lo penalizza.
#
# CATEGORIE NSE AMMESSE E VIETATE.
#
# Le categorie di nmap si dividono per rischio, e su una rete di produzione della PA
# il confine non e' un'opinione: `brute` blocca gli account e riempie i log,
# `dos` interrompe i servizi, `exploit` e `fuzzer` li corrompono. Un incidente causato
# da uno strumento di inventario e' inaccettabile -- e sarebbe anche una violazione
# dell'autorizzazione con cui si scansiona.
#
# Ammesse: default, safe, version, discovery e i controlli `vuln` che si limitano a
# VERIFICARE senza sfruttare. Vietate: brute, dos, exploit, fuzzer, intrusive. Un test
# verifica che nessuno script di quelle categorie finisca negli argomenti.
CATEGORIE_NSE_VIETATE = ("brute", "dos", "exploit", "fuzzer", "intrusive")

# Script NSE che NON si eseguono mai, per nome: appartengono a categorie vietate o
# fanno un numero di richieste che su una rete di utenza si nota (e che il lettore web
# di questo prodotto fa meglio, in modo mirato).
SCRIPT_NSE_VIETATI = (
    # Forza bruta: blocco degli account, log pieni.
    "ssh-brute", "http-brute", "smb-brute", "ftp-brute", "mysql-brute",
    "ms-sql-brute", "snmp-brute", "vnc-brute", "rdp-brute", "telnet-brute",
    "http-form-brute", "pgsql-brute", "oracle-brute", "ldap-brute",
    # Denial of service e sfruttamento.
    "smb-flood", "http-slowloris", "ipv6-ra-flood", "smb-vuln-ms06-025",
    "http-vuln-cve2010-2861", "smb2-vuln-uptime",
    # Enumerazione a forza di richieste: centinaia per host. Il lettore web di questo
    # prodotto (web_probe) legge le pagine in modo mirato e dice di piu'.
    "http-enum", "http-wordpress-enum", "dns-brute",
    # Interrogano servizi ESTERNI: su una rete senza uscita non funzionano, e dove
    # funzionassero manderebbero fuori l'inventario dei servizi del cliente.
    "vulners", "http-virustotal", "whois-ip", "whois-domain", "targets-asn",
    "shodan-api", "hostmap-robtex", "http-shodan-api",
)

# Il catalogo della raffica, per famiglia di servizio. Il prefisso `+` forza lo script
# anche dove nmap non ha riconosciuto il servizio atteso: questo prodotto trova
# interfacce web sulla 7070 e la 8443 e agenti SNMP su porte spostate, e senza il `+`
# quegli script non partirebbero proprio dove servono.
#
# Tutti safe/default/version/discovery: leggono cio' che il servizio dichiara.
SCRIPT_RAFFICA = (
    # Identita' del servizio, qualunque porta.
    "banner",
    # TLS: il certificato nomina l'apparato piu' spesso della pagina, e la scadenza e'
    # un dato operativo che nessun'altra fase raccoglie.
    "+ssl-cert", "+ssl-enum-ciphers",
    # Web: titolo, intestazioni, generatore, icona. Sono le stesse cose su cui si
    # regge il riconoscimento dalle pagine.
    "+http-title", "+http-server-header", "+http-generator", "+http-favicon",
    "+http-methods", "+http-security-headers", "+http-robots.txt",
    # Windows: nome, dominio, versione. La fonte piu' precisa che esista su Windows.
    "+smb-os-discovery", "+smb-security-mode", "+smb2-security-mode",
    "+smb-protocols", "+rdp-ntlm-info", "+nbstat",
    # Unix e apparati.
    "+ssh-hostkey", "+ssh2-enum-algos", "+ssh-auth-methods",
    "+ftp-anon", "+telnet-encryption",
    # Basi di dati: dicono versione e a volte nomi di istanza. Per PostgreSQL non
    # c'e' uno script di sola lettura (esiste `pgsql-brute`, categoria vietata da
    # questo prodotto): la versione la dichiara `-sV`.
    "+mysql-info", "+ms-sql-info", "+mongodb-info", "+redis-info",
    "+oracle-tns-version",
    # Stampanti e apparati di stampa. `cups-info` e non `ipp-info`, che NON ESISTE:
    # il nome sbagliato faceva uscire nmap prima di scansionare -- vedi la nota su
    # `script_conosciuti` in nmap_runner.py.
    "+cups-info",
    # Malware: rileva backdoor note. E' categoria `safe`, non intrusiva.
    "+malware",
)

# Argomenti degli script. Lo user-agent si dichiara: nei log del cliente si deve
# leggere CHI ha fatto la richiesta, e un'impronta anonima in un registro di sicurezza
# e' esattamente cio' che questo prodotto serve a evitare.
ARGOMENTI_SCRIPT_RAFFICA = (
    "http.useragent=snap-probe (inventario di rete autorizzato)")

# Tempo massimo della raffica, per host e per processo. I due numeri vanno letti
# insieme, e la loro storia va raccontata perche' li avevo sbagliati entrambi.
#
# Erano 240 s per host e 420 s per processo, su una stima di ~24 s per `-A`. Misurato
# in esercizio su un host vero di questa rete (10.20.10.31, sette porte aperte,
# Apache + TLS), con il catalogo completo:
#
#   30 porte di riconoscimento   432,6 s   7 porte, 256 righe NSE, sistema operativo
#   porte note + riconoscimento  438,5 s   identico
#   234 porte (elenco completo)  oltre 390 s e non concluso
#
# Il numero di PORTE e' quasi irrilevante (432 contro 438): il costo e' `-A` piu' il
# catalogo di script -- rilevamento del sistema operativo, traceroute, `-sV`, e
# script lenti per natura come `ssl-enum-ciphers`, che enumera tutte le suite di
# cifratura di ogni porta TLS.
#
# Con i due tetti vecchi la raffica NON POTEVA CONCLUDERE su un host con porte
# aperte: nmap scriveva "Skipping host ... due to host timeout" e buttava anche il
# lavoro gia' fatto -- zero record dopo quattro minuti di rete. E' lo stesso difetto
# che il commento precedente diceva di voler evitare, con i numeri sbagliati.
#
# L'ORDINE FRA I DUE CONTA. Il tetto del PROCESSO deve stare sopra quello per host,
# altrimenti il processo viene ucciso prima che il tetto per host possa intervenire e
# si perde l'XML -- cioe' tutto. Un test lo verifica.
ATTESA_RAFFICA_HOST = "600s"
ATTESA_RAFFICA_PROCESSO_SEC = 900

MAX_WORKERS = 32

# Le fasi di ARRICCHIMENTO: non servono a completare il profilo di un nodo (quello
# lo fanno porte, servizi e sistema operativo) ma sono cio' che rende un inventario
# utile. Si nominano qui, in un punto solo, perche' erano elencate a mano in due
# posti e in uno mancava `snmp` -- con l'effetto che il posto riservato alla lettura
# SNMP era codice morto: la condizione lo scartava sempre, il monitoraggio si
# prendeva il nodo prima, e la raccolta dei MAC dagli apparati partiva solo per caso.
FASI_ARRICCHIMENTO = ("snmp", "smb", "vuln", "web")

# Posti che il completamento del profilo NON puo' prendere, per lasciarli alle fasi
# di arricchimento. Uno per fase.
#
# Serve da quando ogni compito porta UN host: la soglia che decideva "arretrato
# grande" era "piu' di un lotto", e con lotti da un host e' diventata "piu' di un
# nodo" -- cioe' sempre. Il completamento riempiva ogni ciclo e le letture di
# arricchimento non partivano mai; fra queste c'e' la raccolta SNMP, che e' l'unica
# fonte dei MAC sulle subnet instradate.
RISERVA_ARRICCHIMENTO = len(FASI_ARRICCHIMENTO)

# Le prenotazioni scadute vengono liberate: se un thread muore senza rilasciare,
# il bersaglio non deve restare bloccato.
CLAIM_MAX_AGE_SECONDS = 1800


def _now_str() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")


def _durata_leggibile(secondi: int) -> str:
    """Una durata in parole. Nel diario "21600 s" non si legge; "6 ore" si'."""
    if secondi < 3600:
        return "%d minuti" % max(1, round(secondi / 60))
    ore = secondi / 3600.0
    if ore < 2:
        return "un'ora" if abs(ore - 1) < 0.05 else "%.1f ore" % ore
    return "%d ore" % round(ore)


def parse_timeout(value) -> int | None:
    """Converte un tempo nella notazione di nmap in secondi.

    Accetta le unita' che nmap accetta (ms, s, m, h) e il numero nudo, che nmap
    interpreta come secondi. Restituisce None se il valore non e' utilizzabile:
    la scelta di cosa fare in quel caso spetta al chiamante, che deve dichiararla.
    """
    if value is None:
        return None
    testo = str(value).strip().lower()
    trovato = re.fullmatch(r"(\d+(?:\.\d+)?)\s*(ms|s|m|h)?", testo)
    if not trovato:
        return None
    quantita = float(trovato.group(1))
    unita = trovato.group(2) or "s"
    secondi = {"ms": quantita / 1000.0, "s": quantita,
               "m": quantita * 60, "h": quantita * 3600}[unita]
    secondi = int(round(secondi))
    if not HOST_TIMEOUT_MIN_SECONDS <= secondi <= HOST_TIMEOUT_MAX_SECONDS:
        return None
    return secondi


def within_perimeter(subnets, address: str) -> bool:
    """Verifica che un indirizzo appartenga al perimetro dichiarato.

    Duplicata rispetto a `snapserver.subnets.within_perimeter`: i due applicativi
    non condividono codice per requisito di separazione.
    """
    try:
        indirizzo = ipaddress.ip_address(address)
    except ValueError:
        return False
    for voce in subnets or ():
        cidr = voce.get("cidr") if isinstance(voce, dict) else voce
        try:
            rete = ipaddress.ip_network(cidr)
        except (ValueError, TypeError):
            continue
        if indirizzo.version == rete.version and indirizzo in rete:
            return True
    return False


class PerimeterViolation(Exception):
    """Bersaglio non contenuto nel perimetro dichiarato dal server."""


class ScanSuspended(Exception):
    """Scansione sospesa dal server o dalla sonda."""


class NetworkScanner:
    """Esegue le fasi scadute e produce i record da conferire."""

    def __init__(self, store, runner: NmapRunner = None, agent_version: str = "1.0.0"):
        self.store = store
        self.runner = runner or NmapRunner()
        self.agent_version = agent_version
        # Perimetro compilato e nodi che ne sono fuori, gia' segnalati. Vivono
        # quanto il processo: al riavvio l'informazione viene ricostruita.
        self._perimeter_signature = None
        self._perimeter_networks = None
        self._perimeter_index = {}
        self._perimeter_read_at = None
        self._reported_outside = set()
        # Fasi per cui si e' gia' detto quali script del catalogo questo nmap non
        # conosce: si dice una volta, non a ogni processo.
        self._script_scartati_detti = set()

    # -- configurazione ------------------------------------------------------
    def perimeter(self) -> list[dict]:
        return self.store.get_json("scan_subnets", []) or []

    def cadences(self) -> dict:
        cadenze = dict(DEFAULT_CADENCES)
        cadenze.update(self.store.get_json("scan_cadences", {}) or {})
        return cadenze

    def scanning_allowed(self) -> tuple:
        """Verifica i due interruttori. Restituisce (consentito, motivo).

        Il piu' restrittivo prevale: se il server ha disabilitato la scansione
        oppure il tecnico l'ha sospesa in sede, non si scansiona.
        """
        if self.store.get_setting("scan_paused", "0") == "1":
            return (False, "scansioni sospese sulla sonda")
        if self.store.get_setting("scan_enabled", "1") == "0":
            return (False, "scansioni disabilitate dal server")
        return (True, "")

    def effort(self) -> str:
        """Profilo di sforzo in vigore, con ricaduta dichiarata sul valore medio."""
        valore = str(self.store.get_setting("scan_effort", DEFAULT_EFFORT) or DEFAULT_EFFORT)
        if valore not in EFFORT_PROFILES:
            self.store.log("warning",
                           "Profilo di sforzo '%s' non riconosciuto: si usa '%s'"
                           % (valore, DEFAULT_EFFORT))
            return DEFAULT_EFFORT
        return valore

    def interfaccia_di_uscita(self) -> str:
        """L'interfaccia da cui devono partire le sonde, o vuoto per lasciar decidere
        il sistema. Vedi la nota su RE_INTERFACCIA per il caso che l'ha imposta."""
        valore = (os.environ.get("SNAP_PROBE_SCAN_INTERFACE")
                  or self.store.get_setting("scan_interface", "") or "").strip()
        if not valore:
            return ""
        if not RE_INTERFACCIA.match(valore):
            self.store.log("warning",
                           "Nome di interfaccia non valido (%r): ignorato, l'uscita la"
                           " decide il sistema" % valore[:40])
            return ""
        return valore

    def indirizzo_di_uscita(self) -> str:
        """L'indirizzo da cui devono partire le sonde, o vuoto.

        Si accetta solo un indirizzo IP valido: un valore qualunque finirebbe sulla
        riga di comando di nmap.
        """
        import ipaddress

        valore = (os.environ.get("SNAP_PROBE_SCAN_SOURCE_IP")
                  or self.store.get_setting("scan_source_ip", "") or "").strip()
        if not valore:
            return ""
        try:
            ipaddress.ip_address(valore)
        except ValueError:
            self.store.log("warning",
                           "Indirizzo di partenza non valido (%r): ignorato"
                           % valore[:40])
            return ""
        return valore

    def excluded_ports(self) -> str:
        """Porte escluse dalla scansione, dall'impostazione o dal valore predefinito.

        Vuoto significa "nessuna esclusione": e' il modo di riattivare la rilevazione
        delle porte escluse senza toccare il codice. Un valore non valido viene
        RIFIUTATO dichiarandolo, non passato a nmap: la riga di comando non e' il
        posto dove far arrivare una stringa non controllata.
        """
        grezzo = self.store.get_setting("scan_exclude_ports", None)
        if grezzo is None:
            return DEFAULT_EXCLUDED_PORTS
        valore = str(grezzo).replace(" ", "")
        if not valore:
            return ""
        if not EXCLUDED_PORTS_PATTERN.match(valore):
            self.store.log("warning",
                           "Porte da escludere '%s' non utilizzabili (ammessi solo"
                           " numeri, virgole e trattini): si usa '%s'"
                           % (grezzo, DEFAULT_EXCLUDED_PORTS))
            return DEFAULT_EXCLUDED_PORTS
        return valore

    def host_timeout(self) -> str | None:
        """Tempo massimo per host scelto, se e' stato scelto.

        None significa: si usa quello del profilo di sforzo. Un valore non
        utilizzabile viene rifiutato dichiarandolo, non silenziosamente ignorato.
        """
        grezzo = self.store.get_setting("scan_host_timeout", "") or ""
        if not str(grezzo).strip():
            return None
        secondi = parse_timeout(grezzo)
        if secondi is None:
            self.store.log("warning",
                           "Tempo massimo per host '%s' non utilizzabile: si usa quello del "
                           "profilo di sforzo" % grezzo)
            return None
        return "%ds" % secondi

    def effort_profile(self) -> dict:
        profilo = dict(EFFORT_PROFILES[self.effort()])
        profilo["workers"] = max(1, min(MAX_WORKERS, int(profilo["workers"])))
        scelto = self.host_timeout()
        if scelto:
            # La scelta esplicita prevale su quella del profilo.
            profilo["host_timeout"] = scelto
        return profilo

    def capabilities(self) -> dict:
        """Capacita' di nmap, accertate una volta e conservate localmente."""
        conservate = self.store.get_json("nmap_capabilities", None)
        if conservate:
            return conservate
        capacita = self.runner.detect_capabilities()
        self.store.set_json("nmap_capabilities", capacita)
        self.store.log(
            "info" if capacita.get("available") else "warning",
            "Capacita' di nmap: %s" % capacita.get("detail", "non rilevate"),
        )
        return capacita

    # -- pianificazione ------------------------------------------------------
    def _due(self, target: str, stage: str, cadenza: int) -> bool:
        stato = self.store.scan_state(target, stage)
        if stato is None or not stato.get("last_run_at"):
            return True
        try:
            ultimo = datetime.strptime(stato["last_run_at"], "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return True  # stato illeggibile: si riparte, non si indovina
        trascorso = (datetime.now(timezone.utc) - ultimo).total_seconds()
        return trascorso >= cadenza

    def _required_stages(self) -> tuple:
        """Fasi necessarie a dichiarare completo il profilo di un dispositivo.

        Le soddisfa la RAFFICA in un processo solo (FASI_COPERTE_DALLA_RAFFICA); il
        contratto resta espresso in termini delle tre fasi, cosi' un nodo profilato
        prima che la raffica esistesse resta valido.
        """
        if self.capabilities().get("os_detection"):
            return PROFILE_STAGES
        # Senza accesso raw il sistema operativo non e' rilevabile: il profilo si
        # considera completo con porte e servizi, e lo si dichiara.
        return tuple(f for f in PROFILE_STAGES if f != "os")

    def pending_nodes(self, stage: str = None) -> list[dict]:
        """Nodi che attendono il PRIMO profilo completo.

        Un nodo gia' conferito non e' in attesa: la sua ri-ispezione e' governata
        dalle cadenze. Senza questa distinzione il completamento dei profili
        avrebbe sempre lavoro da fare e la scoperta non avanzerebbe mai.
        """
        richieste = self._required_stages()
        # Un nodo attende una fase solo quando le precedenti sono svolte. Senza
        # questo vincolo un nodo appena scoperto risulterebbe in attesa di TUTTE
        # le fasi, e la pianificazione potrebbe interrogarne i servizi prima di
        # conoscerne le porte.
        precedenti = frozenset(richieste[:richieste.index(stage)]) if stage in richieste else frozenset()
        attesa = []
        for nodo in self.store.local_nodes():
            if nodo["state"] == "discarded":
                continue
            if nodo.get("conferred_at"):
                continue
            svolte = set((nodo.get("stages_done") or "").split(",")) - {""}
            if stage is None:
                attesa.append(nodo)
                continue
            # LA RAFFICA NON HA NULLA DA CHIEDERE A UN NODO GIA' PROFILATO, e senza
            # questo controllo non lo sapeva. Il difetto, misurato in esercizio:
            #
            # la raffica dichiara svolte le fasi che copre (`svolte.update(
            # FASI_COPERTE_DALLA_RAFFICA)`), ma "raffica" non compare mai in
            # `stages_done` di un nodo profilato per un'altra via -- uno profilato
            # prima che la raffica esistesse, o IMPORTATO dal vecchio archivio. Per
            # quei nodi `"raffica" not in svolte` restava vero per sempre: la raffica
            # li ripigliava a ogni ciclo, e siccome ogni raffica occupa un posto del
            # ciclo per suo conto, riempiva tutto. Nel diario di un'installazione si
            # leggevano dieci "Fase raffica" per ciclo su nodi gia' completi, e UNA
            # sola fase di arricchimento: SNMP, SMB, vulnerabilita' e letture web non
            # arrivavano quasi mai al proprio turno.
            #
            # Il criterio giusto non e' "ha fatto la raffica" ma "le fasi che la
            # raffica svolge sono svolte": e' cio' per cui la raffica esiste. Si
            # confronta con le fasi RICHIESTE, perche' senza socket raw il sistema
            # operativo non e' rilevabile e non va preteso.
            if stage == "raffica":
                coperte = set(FASI_COPERTE_DALLA_RAFFICA) & set(richieste)
                if coperte and coperte <= svolte:
                    continue
            # Un host che ha gia' fatto 'ports' senza trovare porte aperte non ha piu'
            # nulla da profilare: servizi, sistema operativo e approfondimento lavorano
            # tutti sulle porte. Metterlo in coda per quelle fasi e' tempo sprecato -- su
            # una rete reale sono migliaia gli host che rispondono al solo ping -- e viene
            # invece conferito o scartato subito dopo 'ports'.
            if (stage not in ("discovery", "ports", "raffica")
                    and self._niente_da_profilare(nodo)):
                continue
            # Un candidato che nmap ha appena abbandonato non torna subito in coda:
            # riprovarlo con gli stessi mezzi dara' lo stesso esito, e intanto
            # occupa lo slot di un host esaminabile. L'attesa cresce a ogni
            # abbandono, l'host resta candidato (ignoto, non assente).
            if self._scadenza_troppo_recente(nodo):
                continue
            if stage not in svolte and precedenti <= svolte:
                attesa.append(nodo)
        # Il filtro del perimetro sta qui perche' questo e' l'unico punto da cui i
        # nodi da profilare provengono: pianificazione del pool, console e conteggio
        # dell'interfaccia. Un nodo non scansionabile non e' lavoro in attesa.
        if stage is None:
            return attesa
        return self._within_perimeter_only(attesa, stage)

    def _scadenza_troppo_recente(self, nodo: dict) -> bool:
        """Vero se questo candidato e' stato abbandonato per scadenza troppo di
        recente per riprovarlo adesso.

        L'attesa raddoppia a ogni abbandono, fino al tetto. Serve a togliere dalla
        coda gli host che nmap non riesce a esaminare, SENZA scartarli: restano
        candidati (cioe' ignoti) e tornano quando l'attesa e' passata.

        Senza questo, gli stessi indirizzi rientravano in ogni ciclo: misurati 66
        abbandoni consecutivi sugli stessi 24, e una scansione che non finiva.
        """
        if nodo.get("state") != "candidate":
            return False
        grezzo = nodo.get("profile_json")
        if not grezzo:
            return False
        try:
            profilo = json.loads(grezzo) or {}
        except (TypeError, ValueError):
            return False
        quante = int(profilo.get("timeout_count") or 0)
        if quante <= 0:
            return False
        quando = profilo.get("timed_out_at")
        if not quando:
            # Conteggio senza istante: viene da una versione precedente. Si concede
            # un tentativo -- e l'istante verra' scritto se scade di nuovo.
            return False
        try:
            ultimo = datetime.strptime(quando, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return False
        attesa = min(ATTESA_RITENTATIVO_BASE_SEC * (2 ** (quante - 1)),
                     ATTESA_RITENTATIVO_TETTO_SEC)
        trascorso = (datetime.now(timezone.utc) - ultimo).total_seconds()
        return trascorso < attesa

    def next_due(self) -> tuple | None:
        """Prima fase dovuta, nell'ordine di priorita'. None se nulla e' dovuto.

        I nodi appena scoperti hanno la precedenza: il loro profilo va completato
        subito, altrimenti su un perimetro ampio i candidati si accumulerebbero
        per ore senza che nulla raggiunga il server. Le cadenze lunghe regolano la
        RI-ispezione dei nodi gia' conferiti.
        """
        consentito, _ = self.scanning_allowed()
        if not consentito:
            return None
        perimetro = self.perimeter()
        if not perimetro:
            return None
        cadenze = self.cadences()

        # 1. La scoperta scaduta ha un posto garantito: e' la prima cosa dovuta.
        for cidr in [v["cidr"] if isinstance(v, dict) else v for v in perimetro]:
            if self._due(cidr, "discovery", cadenze["discovery"]):
                return ("discovery", cidr)

        # 2. Completare il profilo dei nodi non ancora conferiti, partendo dalle
        #    fasi finali (si veda plan_tasks).
        for fase in reversed(self._required_stages()):
            if self.pending_nodes(fase):
                return (fase, "*")

        confermati = self.store.local_nodes("confirmed")

        # 3. Sorvegliare i nodi conferiti.
        if confermati and self._due("*", "monitor", cadenze["monitor"]):
            return ("monitor", "*")

        # 4. Ri-ispezionare secondo le cadenze.
        for fase in self._required_stages():
            if confermati and self._due("*", fase, cadenze[fase]):
                return (fase, "*")

        # 5. Leggere SNMP dove la porta e' aperta: e' la fonte piu' ricca che esista
        #    su un apparato di rete, e vale piu' di dieci porte TCP.
        if self._snmp_pending() or (self._snmp_nodes()
                                    and self._due("*", "snmp", cadenze["snmp"])):
            return ("snmp", "*")

        # 6. Enumerare SMB dove la 139 o la 445 rispondono: su una postazione o un
        #    server Windows e' la fonte piu' ricca dopo SNMP. Prima i nodi mai letti.
        if self._smb_pending() or (self._smb_nodes()
                                   and self._due("*", "smb", cadenze["smb"])):
            return ("smb", "*")

        # 7. Cercare le vulnerabilita' con nmap dove c'e' un servizio a rischio.
        if self._vuln_pending() or (self._vuln_nodes()
                                    and self._due("*", "vuln", cadenze["vuln"])):
            return ("vuln", "*")

        # 8. Leggere le pagine di gestione: nmap dice che la porta e' aperta, la
        #    pagina dice che cosa c'e' dietro. Prima i nodi mai letti.
        if self._web_pending() or (self._web_nodes()
                                   and self._due("*", "web", cadenze["web"])):
            return ("web", "*")

        # 9. Approfondire i nodi rimasti incerti.
        if self._uncertain_nodes() and self._due("*", "deep", cadenze["deep"]):
            return ("deep", "*")
        return None

    def _uncertain_nodes(self) -> list[dict]:
        # Un host senza porte aperte non e' "incerto": e' vuoto, e l'approfondimento
        # (UDP e script mirati sulle porte) non ci troverebbe nulla. Si esclude, altrimenti
        # migliaia di host che rispondono al solo ping tornerebbero in coda ogni settimana.
        return [n for n in self.store.local_nodes("confirmed")
                if (int(n.get("open_ports") or 0) <= UNCERTAIN_MAX_PORTS
                    or not int(n.get("has_os") or 0))
                and not self._niente_da_profilare(n)]

    # -- esecuzione ----------------------------------------------------------
    def run_due(self) -> dict | None:
        """Esegue un ciclo di scansione. None se non c'era nulla da fare."""
        return self.run_cycle()

    # -- ciclo parallelo -----------------------------------------------------
    def _arricchimenti_per_urgenza(self) -> list:
        """Le fasi di arricchimento, dalla piu' in attesa alla meno.

        PERCHE' L'ORDINE NON PUO' ESSERE FISSO, con la misura che l'ha imposto.

        I posti del ciclo riservati all'arricchimento sono pochi -- quattro fasi per
        RISERVA_ARRICCHIMENTO posti -- e quando la frontiera dei profili e' piena se
        ne libera uno o due per volta. Con un ordine fisso quei posti vanno sempre
        alle stesse fasi, e l'ultima dell'elenco non arriva MAI al proprio turno.

        Misurato su un'installazione reale, dopo giorni di esercizio:

            smb    184 esecuzioni
            vuln    72 esecuzioni
            web      0      <- ultima dell'elenco
            snmp     0      <- nessun nodo con la 161 aperta (altro motivo)

        La conseguenza non era un ritardo: era una funzione MORTA. La pagina dei
        certificati TLS restava vuota per sempre, perche' i certificati li raccoglie
        la lettura web; e la colonna con cio' che le interfacce dichiarano di se'
        restava vuota con 1.875 nodi che espongono una 443.

        Chi ha atteso di piu' passa davanti: una fase MAI eseguita prima di tutte,
        poi la meno recente. Cosi' nessuna fase puo' restare indietro per il solo
        fatto di essere in fondo a un elenco, e l'ordine si corregge da se'.
        """
        def attesa(fase: str):
            stato = self.store.scan_state("*", fase) or {}
            ultimo = (stato.get("last_run_at") or "").strip()
            # `False` viene prima di `True`: le fasi mai eseguite stanno in testa.
            return (bool(ultimo), ultimo)

        return sorted(FASI_ARRICCHIMENTO, key=attesa)

    def _claim_keys_for(self, task: dict) -> list:
        """Chiavi da prenotare per un compito.

        Per la scoperta la chiave e' la subnet; per le fasi sui nodi e' un
        indirizzo per volta, cosi' l'esclusione ha la granularita' del nodo.
        """
        if task["stage"] == "discovery":
            return ["discovery:%s" % task["target"]]
        return ["node:%s" % ip for ip in task["hosts"]]

    def run_cycle(self, limit: int = None) -> dict | None:
        """Esegue fino a N compiti in parallelo e conferisce i profili completi.

        Il conferimento avviene qui, una sola volta, dopo che tutti i compiti
        hanno terminato: e' la condizione che evita decisioni prese due volte da
        thread diversi.
        """
        consentito, motivo = self.scanning_allowed()
        if not consentito:
            return None

        # Le prenotazioni rimaste da un thread morto non devono bloccare i
        # bersagli per sempre.
        liberate = self.store.purge_stale_claims(CLAIM_MAX_AGE_SECONDS)
        if liberate:
            self.store.log("warning",
                           "Liberate %d prenotazioni scadute di scansione" % liberate)

        profilo = self.effort_profile()
        compiti = self.plan_tasks(limit or profilo["workers"])
        if not compiti:
            return None

        capacita = self.capabilities()
        if not capacita.get("available"):
            raise NmapError("nmap non disponibile: %s" % capacita.get("detail", ""))

        proprietario = "ciclo-%s" % uuid.uuid4().hex[:8]
        prenotate = []
        eseguibili = []
        for compito in compiti:
            chiavi = self._claim_keys_for(compito)
            ottenute = self.store.claim_keys(chiavi, proprietario, compito["stage"])
            if not ottenute:
                continue  # bersagli tutti in mano ad altri: si salta il compito
            prenotate.extend(ottenute)
            if compito["stage"] != "discovery":
                # Si lavora solo sugli indirizzi effettivamente prenotati.
                compito = dict(compito,
                               hosts=[k.split(":", 1)[1] for k in ottenute])
            compito["claimed"] = set(prenotate)
            eseguibili.append(compito)

        if not eseguibili:
            # Tutti i bersagli sono in mano a qualcun altro. Se accade a
            # ripetizione sono prenotazioni orfane: va detto, invece di restare
            # fermi in silenzio.
            self.store.log(
                "warning",
                "Ciclo senza compiti eseguibili: %d bersagli risultano prenotati "
                "(%d prenotazioni attive)"
                % (sum(len(c["hosts"]) for c in compiti), len(self.store.active_claims())))
            return None

        lavoratori = max(1, min(MAX_WORKERS, profilo["workers"], len(eseguibili)))
        esiti = []
        try:
            if lavoratori == 1:
                for compito in eseguibili:
                    esiti.append(self._safe_task(compito, capacita, profilo))
            else:
                with concurrent.futures.ThreadPoolExecutor(
                        max_workers=lavoratori, thread_name_prefix="snap-scan") as pool:
                    futuri = [pool.submit(self._safe_task, compito, capacita, profilo)
                              for compito in eseguibili]
                    for futuro in concurrent.futures.as_completed(futuri):
                        esiti.append(futuro.result())
        finally:
            # Le prenotazioni si rilasciano sempre, anche se un compito solleva.
            self.store.release_keys(prenotate, proprietario)

        # Conferimento: una volta sola, qui.
        records = {}
        for esito in esiti:
            for tipo, elenco in (esito.get("records") or {}).items():
                records.setdefault(tipo, []).extend(elenco)
        completi = self._confer_complete_profiles()
        for tipo, elenco in completi.items():
            records.setdefault(tipo, []).extend(elenco)

        for tipo, elenco in records.items():
            for elemento in elenco:
                self.store.enqueue(tipo, elemento)

        conferiti = len(completi.get("nodes", []))
        self.store.log(
            "info",
            "Ciclo di scansione: %d compiti su %d thread (sforzo %s), %d dispositivi conferiti"
            % (len(eseguibili), lavoratori, self.effort(), conferiti))
        return {
            "tasks": len(eseguibili),
            "workers": lavoratori,
            "effort": self.effort(),
            "conferred": conferiti,
            "records": records,
            "results": esiti,
        }

    def _safe_task(self, task: dict, capacita: dict, profilo: dict) -> dict:
        """Esegue un compito isolando i propri errori.

        Un compito che fallisce non deve far cadere il ciclo ne' impedire agli
        altri di concludere: l'errore viene annotato e restituito.
        """
        try:
            return self._run_task(task, capacita, profilo)
        except (ScanSuspended, NmapAborted) as errore:
            return {"stage": task["stage"], "target": task["target"], "records": {},
                    "status": "suspended", "detail": str(errore)}
        except PerimeterViolation as errore:
            return {"stage": task["stage"], "target": task["target"], "records": {},
                    "status": "refused", "detail": str(errore)}
        except NmapError as errore:
            return {"stage": task["stage"], "target": task["target"], "records": {},
                    "status": "failed", "detail": str(errore)}
        except Exception as errore:  # nessun compito deve poter fermare il ciclo
            self.store.log("error", "Compito %s su %s interrotto da un errore inatteso: %s"
                           % (task["stage"], task["target"], errore))
            return {"stage": task["stage"], "target": task["target"], "records": {},
                    "status": "error", "detail": str(errore)}

    def _targets_for(self, stage: str) -> list[str]:
        if stage == "monitor":
            # Si sorvegliano solo i nodi che il server conosce, a ROTAZIONE: prima
            # quelli non verificati da piu' tempo. Senza l'ordinamento ogni passata
            # prendeva gli stessi primi sedici nodi, e i restanti non venivano mai
            # riverificati -- restando dichiarati assenti per sempre.
            nodi = sorted(
                (n for n in self.store.local_nodes("confirmed") if n.get("conferred_at")),
                key=lambda n: (n.get("monitored_at") or ""))
        elif stage == "deep":
            # Anche l'approfondimento va limitato al perimetro: i nodi incerti
            # possono appartenere a subnet non piu' dichiarate, e un solo bersaglio
            # fuori perimetro fa rifiutare il compito intero.
            nodi = self._within_perimeter_only(self._uncertain_nodes(), stage)
        elif stage == "web":
            # Solo i nodi con una porta web aperta: una GET su un nodo che non la
            # espone e' tempo speso ad attendere un timeout. Prima quelli mai letti.
            nodi = self._within_perimeter_only(
                self._web_pending() or self._web_nodes(), stage)
        elif stage == "snmp":
            # Solo i nodi che hanno risposto sulla 161: la lettura SNMP su un nodo che
            # non la espone e' tempo speso ad attendere un timeout. Prima quelli mai
            # letti; se non ne restano, e' una ri-lettura e riguarda tutti.
            nodi = self._within_perimeter_only(
                self._snmp_pending() or self._snmp_nodes(), stage)
        elif stage == "smb":
            # Solo i nodi con SMB aperto: come per SNMP, interrogare gli altri e'
            # tempo speso ad attendere un timeout. Prima quelli mai letti.
            nodi = self._within_perimeter_only(
                self._smb_pending() or self._smb_nodes(), stage)
        elif stage == "vuln":
            # Solo i nodi che espongono una porta a rischio. Prima i mai verificati.
            nodi = self._within_perimeter_only(
                self._vuln_pending() or self._vuln_nodes(), stage)
        elif stage in PROFILE_STAGES:
            # Prima i nodi il cui profilo attende questa fase; se non ce ne sono,
            # e' una ri-ispezione e riguarda i nodi confermati.
            nodi = self.pending_nodes(stage)
            if not nodi:
                nodi = [n for n in self.store.local_nodes("confirmed")
                        if not self._still_in_cooldown(n)]
        else:
            return []
        # Un nodo la cui subnet non e' piu' dichiarata non e' scansionabile: se
        # entrasse nel compito ne annullerebbe tutti gli altri bersagli, perche' il
        # controllo del perimetro rifiuta l'intero compito. Non e' un tentativo di
        # violazione, e' un perimetro cambiato: il nodo resta in inventario e non
        # viene piu' scelto.
        dentro = [n["ip"] for n in self._within_perimeter_only(nodi, stage)]
        if stage == "ports":
            # Nessun troncamento: il motore delle porte lavora l'intero insieme in
            # UN processo, a gruppi di GRUPPO_HOST. Tagliare i bersagli qui
            # significherebbe tornare alla struttura che non finiva mai.
            return dentro
        return dentro[:self.effort_profile()["hosts_per_task"]]

    def _compiled_perimeter(self) -> list:
        """Reti del perimetro, compilate una volta sola e indicizzate per prefisso.

        Confrontare ogni indirizzo con ogni rete non regge la dimensione reale: con
        1304 nodi e 369 subnet sono quasi mezzo milione di confronti per chiamata, e
        `status.json` -- che l'interfaccia interroga ogni pochi secondi -- arrivava a
        rispondere in oltre trenta secondi, apparendo bloccata.

        L'indice raccoglie, per ciascuna lunghezza di prefisso, gli indirizzi di rete
        come interi: verificare un indirizzo diventa una mascheratura e una ricerca
        in un insieme, di norma una sola perche' le subnet sono quasi tutte /24.
        """
        # Prima di tutto: senza questa guardia si rileggerebbe il perimetro dal
        # database, con la decodifica del JSON, per OGNI indirizzo verificato.
        if (self._perimeter_networks is not None and self._perimeter_read_at is not None
                and (time.monotonic() - self._perimeter_read_at) < PERIMETER_CACHE_SECONDS):
            return self._perimeter_networks

        perimetro = self.perimeter()
        firma = tuple((v.get("cidr") if isinstance(v, dict) else v) for v in perimetro or ())
        self._perimeter_read_at = time.monotonic()
        if self._perimeter_signature == firma and self._perimeter_networks is not None:
            return self._perimeter_networks
        reti = []
        indice = {}
        for cidr in firma:
            try:
                rete = ipaddress.ip_network(cidr)
            except (TypeError, ValueError):
                # Notazione illeggibile nel perimetro: si annota e si prosegue, il
                # perimetro non si indovina.
                self.store.log("warning",
                               "Subnet non interpretabile nel perimetro: %r" % (cidr,))
                continue
            reti.append(rete)
            if rete.version == 4:
                indice.setdefault(rete.prefixlen, set()).add(int(rete.network_address))
        self._perimeter_signature = firma
        self._perimeter_networks = reti
        self._perimeter_index = indice
        return reti

    def forget_caches(self) -> None:
        """Dimentica tutto cio' che lo scanner tiene in memoria.

        Serve dopo un azzeramento dell'archivio: senza questo, il perimetro
        compilato e l'elenco dei nodi gia' segnalati sopravvivrebbero alla
        cancellazione, e la sonda continuerebbe a ragionare su dati che non
        esistono piu'.
        """
        self._perimeter_signature = None
        self._perimeter_networks = None
        self._perimeter_index = {}
        self._perimeter_read_at = None
        self._reported_outside.clear()

    def invalidate_perimeter(self) -> None:
        """Costringe a rileggere il perimetro alla prossima verifica.

        La chiama l'agente quando il server consegna una configurazione: e' il
        momento in cui il perimetro puo' essere cambiato davvero.
        """
        self._perimeter_read_at = None

    def _in_perimeter(self, address: str) -> bool:
        """Appartenenza di un indirizzo al perimetro, in tempo costante su IPv4."""
        reti = self._compiled_perimeter()
        if not reti:
            return False
        try:
            indirizzo = ipaddress.ip_address(address)
        except ValueError:
            return False
        if indirizzo.version == 4:
            valore = int(indirizzo)
            for lunghezza, indirizzi in self._perimeter_index.items():
                maschera = (0xFFFFFFFF << (32 - lunghezza)) & 0xFFFFFFFF
                if (valore & maschera) in indirizzi:
                    return True
            return False
        # IPv6 e casi residui: confronto diretto, sono pochi e la mascheratura non
        # vale la duplicazione della logica.
        for rete in reti:
            if indirizzo.version == rete.version and indirizzo in rete:
                return True
        return False

    def _within_perimeter_only(self, nodi: list, stage: str) -> list:
        """Nodi appartenenti al perimetro dichiarato, con annotazione degli esclusi."""
        if not self._compiled_perimeter():
            return []
        ammessi, nuovi = [], []
        for nodo in nodi:
            if self._in_perimeter(nodo["ip"]):
                ammessi.append(nodo)
            elif nodo["ip"] not in self._reported_outside:
                # Una volta per nodo: ripetere l'avviso a ogni ciclo seppellisce
                # il diario invece di informare.
                self._reported_outside.add(nodo["ip"])
                nuovi.append(nodo["ip"])
        if nuovi:
            self.store.log(
                "warning",
                "%d nodi esclusi dalle scansioni: la loro subnet non e' piu' fra quelle "
                "dichiarate dal server (%s%s). Restano in inventario."
                % (len(nuovi), ", ".join(nuovi[:5]), ", ..." if len(nuovi) > 5 else ""))
        return ammessi

    def _monitor_ping_ports(self, hosts: list) -> str:
        """Porte da usare nei probe di ping, ricavate dai nodi del compito.

        Tre porte fisse non bastano: un nodo che espone soltanto 135, 139 e 445 non
        risponde a un SYN su 443, 80 o 22, e su una rete che blocca ICMP finirebbe
        dichiarato assente pur essendo vivo.
        """
        frequenza = {}
        for ip in hosts or ():
            locale = self.store.local_node(ip)
            if not locale:
                continue
            try:
                profilo = json.loads(locale.get("profile_json") or "{}")
            except (TypeError, ValueError):
                continue
            for voce in (profilo.get("ports_index") or {}).values():
                if voce.get("state") != "open":
                    continue
                if (voce.get("protocol") or "tcp").lower() != "tcp":
                    continue
                try:
                    numero = int(voce["port"])
                except (KeyError, TypeError, ValueError):
                    continue
                frequenza[numero] = frequenza.get(numero, 0) + 1
        if not frequenza:
            return MONITOR_FALLBACK_PORTS
        # Prima le porte comuni a piu' nodi: coprono piu' bersagli con meno probe.
        ordinate = sorted(frequenza, key=lambda p: (-frequenza[p], p))
        return ",".join(str(p) for p in ordinate[:MONITOR_PING_PORTS_MAX])

    def _known_open_ports(self, hosts: list) -> list:
        """Porte TCP gia' risultate aperte sui bersagli indicati.

        La fase precedente le ha trovate: ripartire dalle prime duecento porte
        significa spendere il tempo per host su porte che non risponderanno, e
        arrivare alla scadenza senza aver riconosciuto alcun servizio.
        """
        porte = set()
        for ip in hosts or ():
            locale = self.store.local_node(ip)
            if not locale:
                continue
            try:
                profilo = json.loads(locale.get("profile_json") or "{}")
            except (TypeError, ValueError):
                # Profilo illeggibile: si ignora questo bersaglio, non si indovina.
                self.store.log("warning",
                               "Profilo locale di %s illeggibile: porte note ignorate" % ip)
                continue
            for voce in (profilo.get("ports_index") or {}).values():
                if voce.get("state") != "open":
                    continue
                if (voce.get("protocol") or "tcp").lower() != "tcp":
                    continue
                try:
                    porte.add(int(voce["port"]))
                except (KeyError, TypeError, ValueError):
                    continue
        return sorted(porte)

    def _service_ports(self, hosts: list, profilo: dict, snmp: bool = False) -> list:
        """Porte della fase dei servizi: le porte TCP note, piu' udp/161 SOLO dove la
        161 e' gia' risultata aperta.

        Lo scan UDP e' lento e rate-limitato: farlo su OGNI host trascinava la passata
        a centinaia di secondi su chi non risponde (sul campo oltre 800s, quasi tutti
        scaduti), bloccando il completamento del profilo. Lo si fa quindi solo dove
        serve davvero -- l'apparato ha gia' mostrato la 161 aperta -- e per gli altri
        i servizi restano una rilevazione TCP, veloce.
        """
        note = self._known_open_ports(hosts)
        if note and len(note) <= MAX_EXPLICIT_PORTS:
            tcp = ",".join(str(p) for p in note)
        else:
            # Senza porte note si usa l'elenco curato di profondita', non "le prime
            # N per frequenza": e' la stessa scelta della fase delle porte (vedi
            # PORTE_PROFONDITA_PER_FAMIGLIA) e nel prodotto esiste UNA lista sola.
            # L'elenco esplicito serve anche perche' --top-ports non si combina
            # con -p, che qui serve per distinguere TCP da UDP.
            tcp = ",".join(str(p) for p in PORTE_PROFONDITA)
        if snmp:
            # Prefisso di protocollo esplicito: senza, nmap applicherebbe l'elenco a
            # entrambi i protocolli e tenterebbe in UDP porte che in UDP non esistono.
            return ["-p", "T:%s,U:%d" % (tcp, SNMP_PORT)]
        return ["-p", tcp]

    def _web_nodes(self) -> list[dict]:
        """Nodi con un'interfaccia di gestione leggibile: pagina web oppure IPP.

        Anche IPP: una stampante che espone solo la 631 non ha una pagina da leggere,
        ma ha un modello e un numero di serie da dichiarare -- e senza questa riga non
        entrerebbe mai nella fase.
        """
        from .ipp_probe import porte_ipp
        from .web_probe import porte_web

        scelti = []
        for locale in self.store.local_nodes("confirmed"):
            porte = self._porte_di(locale)
            if porte and (porte_web(porte) or porte_ipp(porte)):
                scelti.append(locale)
        return scelti

    def _web_pending(self) -> list[dict]:
        """Nodi la cui interfaccia di gestione non e' ancora stata letta del tutto.

        Un nodo mai letto ha la precedenza sulla cadenza: e' la differenza fra
        informazione MANCANTE e informazione vecchia, e la prima vale piu' della
        seconda.

        Vale anche per una capacita' aggiunta dopo: un apparato con una porta IPP che
        non ha ancora avuto una lettura IPP e' un apparato di cui manca il modello,
        non uno di cui il modello e' vecchio. Cosi' una funzione nuova si applica al
        parco esistente da se', senza che nessuno svuoti niente a mano.
        """
        from .ipp_probe import porte_ipp

        attesa = []
        for nodo in self._web_nodes():
            profilo = self._profilo_di(nodo) or {}
            if not profilo.get("web_read_at"):
                attesa.append(nodo)
                continue
            if porte_ipp(self._porte_di(nodo)) and not profilo.get("ipp_tried_at"):
                attesa.append(nodo)
        return attesa

    def _porte_di(self, locale: dict) -> list:
        """Porte osservate su un nodo, dal suo profilo locale."""
        profilo = self._profilo_di(locale)
        if not profilo:
            return []
        return list((profilo.get("ports_index") or {}).values())

    def _profilo_di(self, locale: dict) -> dict:
        try:
            return json.loads(locale.get("profile_json") or "{}") or {}
        except (TypeError, ValueError):
            return {}

    def _snmp_nodes(self) -> list[dict]:
        """Nodi su cui la porta SNMP risulta aperta.

        E' l'elenco dei bersagli della fase dedicata: interrogare via SNMP un nodo che
        non ha la 161 aperta significherebbe aspettare un tempo pieno per nulla.
        """
        nodi = []
        for locale in self.store.local_nodes():
            if locale.get("state") == "discarded":
                continue
            try:
                profilo = json.loads(locale.get("profile_json") or "{}")
            except (TypeError, ValueError):
                continue
            voce = (profilo.get("ports_index") or {}).get("udp/%d" % SNMP_PORT)
            if voce and voce.get("state") == "open":
                nodi.append(locale)
        return nodi

    def _snmp_pending(self) -> list[dict]:
        """Nodi che espongono SNMP e non sono mai stati letti.

        Hanno la precedenza sulla cadenza: la cadenza governa le ri-letture, non la
        prima. Diversamente, una passata da sedici nodi bloccherebbe la fase per
        dodici ore e su duecento apparati servirebbero giorni.
        """
        mancanti = []
        for locale in self._snmp_nodes():
            try:
                profilo = json.loads(locale.get("profile_json") or "{}")
            except (TypeError, ValueError):
                continue
            if not profilo.get("snmp_read_at"):
                mancanti.append(locale)
        return mancanti

    def _smb_nodes(self) -> list[dict]:
        """Nodi con una porta SMB aperta (139 NetBIOS oppure 445 diretto).

        E' l'elenco dei bersagli della fase: interrogare via SMB un nodo che non
        espone ne' la 139 ne' la 445 significherebbe attendere un tempo pieno per
        nulla.
        """
        nodi = []
        for locale in self.store.local_nodes():
            if locale.get("state") == "discarded":
                continue
            porte = (self._profilo_di(locale).get("ports_index") or {})
            for numero in SMB_PORT_NUMBERS:
                voce = porte.get("tcp/%d" % numero)
                if voce and voce.get("state") == "open":
                    nodi.append(locale)
                    break
        return nodi

    def _smb_pending(self) -> list[dict]:
        """Nodi che espongono SMB e non sono mai stati letti.

        Hanno la precedenza sulla cadenza: la cadenza governa le ri-letture, non la
        prima -- la stessa disciplina della lettura SNMP.
        """
        mancanti = []
        for locale in self._smb_nodes():
            if not (self._profilo_di(locale).get("smb_read_at")):
                mancanti.append(locale)
        return mancanti

    def _vuln_nodes(self) -> list[dict]:
        """Nodi che espongono almeno una porta a rischio (TLS, SMB, HTTP).

        Sono i bersagli della ricerca di vulnerabilita': su un nodo senza queste porte
        gli script non avrebbero nulla su cui lavorare.
        """
        nodi = []
        for locale in self.store.local_nodes("confirmed"):
            porte = (self._profilo_di(locale).get("ports_index") or {})
            for numero in VULN_PORT_NUMBERS:
                voce = porte.get("tcp/%d" % numero)
                if voce and voce.get("state") == "open":
                    nodi.append(locale)
                    break
        return nodi

    def _vuln_pending(self) -> list[dict]:
        """Nodi a rischio mai verificati: hanno la precedenza sulla cadenza."""
        return [n for n in self._vuln_nodes()
                if not self._profilo_di(n).get("vuln_read_at")]

    def _snmp_open_on(self, hosts: list) -> bool:
        """Vero se udp/161 risulta gia' aperta su almeno uno dei bersagli.

        Gli script SNMP costano tempo: si aggiungono solo dove serve. Al primo giro la
        porta non e' ancora nota e non si aggiungono; appena risponde, la passata
        successiva legge tutto.
        """
        for ip in hosts or ():
            locale = self.store.local_node(ip)
            if not locale:
                continue
            try:
                profilo_locale = json.loads(locale.get("profile_json") or "{}")
            except (TypeError, ValueError):
                continue
            voce = (profilo_locale.get("ports_index") or {}).get("udp/%d" % SNMP_PORT)
            if voce and voce.get("state") == "open":
                return True
        return False

    def _port_selection(self, stage: str, hosts: list, profilo: dict) -> list:
        """Scelta delle porte per una fase di ispezione.

        Le porte note prevalgono: sono poche, sono quelle che hanno risposto, e
        permettono di concludere entro il tempo per host. Senza porte note si usa
        l'elenco curato di profondita' -- non "le prime N per frequenza", che
        contiene servizi che su una rete di uffici non esistono e non contiene porte
        di gestione che qui contano.
        """
        note = self._known_open_ports(hosts)
        if note and len(note) <= MAX_EXPLICIT_PORTS:
            return ["-p", ",".join(str(p) for p in note)]
        return ["-p", ",".join(str(p) for p in PORTE_PROFONDITA)]

    def _porte_della_raffica(self) -> tuple:
        """Le porte della raffica: riconoscimento piu' profondita', in un colpo solo.

        Su un host per processo si puo': sono ~260 porte con un budget di pacchetti
        tutto per lui. Erano divise in due elenchi -- riconoscimento per tutti,
        profondita' per chi dava segno -- perche' un processo doveva servire centinaia
        di host e le sonde si dividevano fra loro. Con un host per processo quella
        economia non serve piu', e chiedere tutto subito significa un nodo profilato
        per intero al primo passaggio.
        """
        return tuple(sorted(set(PORTE_RICONOSCIMENTO) | set(PORTE_PROFONDITA)))

    def _porte_della_fase(self, hosts: list, profilo: dict) -> list:
        """Quali porte chiedere in questa passata: riconoscimento o profondita'.

        RICONOSCIMENTO (il caso normale): l'elenco di PORTE_RICONOSCIMENTO su tutti
        gli host. Poche porte, ma quelle che dicono che cos'e' un apparato, e un
        costo che permette di concludere l'intera subnet in un paio di minuti.

        PROFONDITA': PORTE_PROFONDITA, e riguarda i soli host che hanno GIA' mostrato
        almeno una porta aperta. Sono poche decine invece di 254, quindi il costo
        torna sostenibile. Un host che tace su tutte le porte di riconoscimento non
        diventa interessante alla duecentesima: se cambia, lo dira' aprendone una di
        quelle che si guardano sempre.

        Non si usa piu' `--top-ports`: le prime mille di nmap sono ordinate per
        frequenza su Internet, mentre queste sono scelte per famiglia di apparato e
        comprendono tutte quelle trovate aperte su questa rete. Meno porte e piu'
        pertinenti -- vedi PORTE_PROFONDITA_PER_FAMIGLIA.
        """
        if self._tutti_con_porte_note(hosts):
            return ["-p", ",".join(str(p) for p in PORTE_PROFONDITA)]
        return ["-p", ",".join(str(p) for p in PORTE_RICONOSCIMENTO)]

    def _tutti_con_porte_note(self, hosts: list) -> bool:
        """Vero se OGNI host del compito ha gia' almeno una porta aperta conosciuta.

        E' la condizione della passata di profondita': si allarga l'esame solo dove
        c'e' gia' un segnale. Basta un host senza porte note perche' il compito
        torni al livello di riconoscimento -- meglio una passata veloce in piu' che
        una lenta su chi non ha nulla da dire.
        """
        if not hosts:
            return False
        for ip in hosts:
            locale = self.store.local_node(ip)
            if not locale:
                return False
            porte = (self._profilo_di(locale).get("ports_index") or {})
            if not any(v.get("state") == "open" for v in porte.values()):
                return False
        return True

    def _hostgroup(self, hosts: list = None) -> str:
        """Quanti host far scansionare a nmap in parallelo dentro UN processo.

        SMENTITO DA UNA MISURA, e vale scriverlo perche' l'assunzione contraria ha
        fatto girare a vuoto una scansione per ore. Qui c'era scritto che un gruppo
        parallelo "rende una passata lunga quanto il singolo host e non la somma".
        E' falso: il ritmo di invio e' di nmap ed e' PER PROCESSO, non per host.
        Misurato sugli stessi bersagli, 200 porte ciascuno:

            1 host  -> 21,1 s   (9,5 pacchetti/s)
            4 host  -> 81,2 s   (9,9 pacchetti/s)

        Quattro host costano quattro volte uno: la passata dura quanto la SOMMA. Con
        un tetto di tempo PER HOST, un gruppo grande garantisce che scadano tutti --
        24 host da 1000 porte richiedono ~41 minuti di pacchetti mentre ciascuno
        viene abbandonato a 4 minuti. E' cio' che accadeva: ondate da 257 s, zero
        host restituiti, per 66 volte di seguito.

        La conseguenza sta nei profili di sforzo: un host per compito, molti processi
        in parallelo. Ogni processo ha allora il proprio budget di pacchetti e
        conclude. Questo tetto resta per i casi in cui un compito porti piu' host.
        """
        return str(max(1, min(len(hosts or []) or 1, MAX_HOSTGROUP)))

    def _arguments_for(self, stage: str, capacita: dict, profilo: dict = None,
                       hosts: list = None) -> list:
        """Argomenti di nmap per una fase, con le porte escluse applicate a tutte.

        L'esclusione si aggiunge QUI e non nei singoli rami: ogni ramo costruisce i
        propri argomenti e ne uscira' un altro in futuro. Aggiungerla in un punto
        solo significa che nessuna fase puo' dimenticarsela.

        Restano fuori `discovery` e `monitor`: non scansionano porte (sono sweep di
        raggiungibilita' con `-sn`) e a nmap l'opzione risulterebbe inutile.
        """
        argomenti = self._arguments_base(stage, capacita, profilo, hosts)
        escluse = self.excluded_ports()
        if escluse and stage not in ("discovery", "monitor"):
            argomenti = argomenti + ["--exclude-ports", escluse]

        # L'INTERFACCIA DI USCITA, dichiarata a nmap invece che lasciata alla tabella
        # di instradamento (vedi la nota su RE_INTERFACCIA: su una macchina con nove
        # interfacce la rotta migliore era quella di un adattatore SPENTO). Solo con i
        # socket raw: una scansione per connessione passa dallo stack del sistema, che
        # non accetta ne' `-e` ne' `-S`.
        if capacita.get("raw_sockets"):
            interfaccia = self.interfaccia_di_uscita()
            if interfaccia:
                argomenti = argomenti + ["-e", interfaccia]
            partenza = self.indirizzo_di_uscita()
            if partenza:
                argomenti = argomenti + ["-S", partenza]
        return argomenti

    def _script_utilizzabili(self, fase: str, voci) -> list:
        """Dell'elenco resta cio' che l'nmap installato conosce davvero.

        UN NOME SBAGLIATO NON DEVE POTER FERMARE UNA FASE. nmap rifiuta di partire
        se un solo nome non corrisponde a nulla ("did not match a category,
        filename, or directory" e QUITTING!): la fase finisce in pochi secondi
        senza un record, e il diario non dice perche'. E' successo in esercizio con
        `ipp-info` e `pgsql-info`, che non esistono -- vedi la nota su
        `script_conosciuti` in nmap_runner.py.

        Serve anche in condizioni normali: le versioni di nmap non hanno tutti gli
        stessi script, e una sonda lasciata in sede puo' averne una piu' vecchia.

        Cio' che si scarta si scrive nel diario UNA VOLTA per fase: un elenco
        ridotto in silenzio sarebbe una perdita di dati invisibile.
        """
        tenuti, scartati = filtra_script(voci)
        if scartati and fase not in self._script_scartati_detti:
            self._script_scartati_detti.add(fase)
            self.store.log(
                "warning",
                "Fase %s: %d script del catalogo non esistono in questo nmap e sono"
                " stati esclusi (%s). Senza l'esclusione nmap rifiuterebbe di"
                " partire e la fase non produrrebbe nulla."
                % (fase, len(scartati), ", ".join(s.lstrip("+") for s in scartati)))
        return tenuti

    def _arguments_base(self, stage: str, capacita: dict, profilo: dict = None,
                        hosts: list = None) -> list:
        """Argomenti di nmap per una fase, secondo il profilo di sforzo."""
        raw = bool(capacita.get("raw_sockets"))
        profilo = profilo or self.effort_profile()
        timing = profilo["timing"]
        attesa = self._host_timeout_for(stage, profilo, hosts)

        if stage == "raffica":
            # TUTTO QUELLO CHE NMAP SA FARE, SU UN NODO SOLO.
            #
            # `-A` e' versione dei servizi, rilevamento del sistema operativo, script
            # `default` e traceroute in una sigla. Vi si aggiunge il catalogo curato:
            # `--script` da solo SOSTITUIREBBE il set `default` che `-A` porta con
            # se', quindi si scrive "default" davanti e lo si conserva.
            #
            # Il `+` davanti a molti script non e' decorativo: forza lo script anche
            # dove nmap non ha riconosciuto il servizio atteso. Questo prodotto trova
            # interfacce web sulla 7070 e sulla 8443 e agenti su porte spostate, e
            # senza il `+` gli script non partirebbero proprio dove servono.
            argomenti = [("-sS" if raw else "-sT"), "-Pn", "-A", timing]
            argomenti += ["-p", ",".join(str(porta)
                                         for porta in self._porte_della_raffica())]
            argomenti += ["--script", ",".join(
                self._script_utilizzabili("raffica", ("default",) + SCRIPT_RAFFICA))]
            argomenti += ["--script-args", ARGOMENTI_SCRIPT_RAFFICA]
            # Un tempo per host generoso: `-A` su un apparato lento impiega minuti, e
            # sotto la soglia la raffica non conclude e non lascia dato -- che e' il
            # difetto peggiore, perche' consuma tempo senza produrre niente.
            argomenti += ["--host-timeout", ATTESA_RAFFICA_HOST]
            # `--exclude-ports` NON si aggiunge qui: lo mette `_arguments_for`, che
            # avvolge questa funzione per tutte le fasi che scandiscono porte.
            # Aggiungerlo due volte non e' innocuo -- nmap rifiuta l'esecuzione con
            # "Only 1 --exclude-ports option allowed" e la fase non produce nulla.
            return argomenti

        if stage == "discovery":
            # La scoperta conserva il proprio tempo breve anche quando se ne sceglie
            # uno piu' lungo: lo decide `_host_timeout_for` (DISCOVERY_HOST_TIMEOUT),
            # cosi' il valore e' uno solo -- quello che nmap riceve e quello su cui si
            # calcola il tempo massimo del processo.
            return ["-sn", "-PE", "-PS22,80,443,3389,445", "-PA80", "-PR", timing,
                    "--host-timeout", DISCOVERY_HOST_TIMEOUT]
        if stage == "ports":
            # NESSUN `--host-timeout`. Non e' una dimenticanza: in questa struttura
            # non protegge da nulla e CAUSAVA il difetto per cui una /24 non finiva
            # mai (gli host di un gruppo si dividono il budget di pacchetti del
            # processo, quindi con un tetto per host scadono tutti). La rete di
            # sicurezza e' il tetto di tempo del PROCESSO, calcolato sulle sonde da
            # inviare -- vedi `_process_timeout`.
            #
            # `--max-hostgroup` fissa il gruppo invece di lasciarlo adattare a nmap:
            # e' il solo parametro di taratura, e i suoi due effetti opposti sono
            # spiegati su GRUPPO_HOST.
            gruppo = str(GRUPPO_HOST)
            return ([("-sS" if raw else "-sT"), "-Pn", timing]
                    + self._porte_della_fase(hosts, profilo)
                    + ["--min-hostgroup", gruppo, "--max-hostgroup", gruppo])
        if stage == "services":
            # Rilevazione dei servizi in TCP: -sV sulle porte gia' trovate aperte, con
            # lo script 'banner' (il testo che i servizi annunciano, spesso identifica
            # l'apparato meglio del prodotto) e il set curato di arricchimento.
            #
            # Lo scan UDP (e gli script SNMP) si aggiungono SOLO dove la 161 e' gia'
            # risultata aperta: farli su ogni host rendeva la passata lentissima e
            # bloccava il completamento del profilo. Per la maggioranza degli host,
            # che non espone SNMP, i servizi restano una rilevazione TCP e veloce.
            snmp = self._snmp_open_on(hosts)
            script = ",".join(self._script_utilizzabili(
                "services",
                ("banner",) + tuple(ENRICHMENT_SCRIPTS.split(","))
                + (tuple(SNMP_SCRIPTS.split(",")) if snmp else ())))
            argomenti = [("-sS" if raw else "-sT")]
            if snmp:
                argomenti.append("-sU")
            # Intensita' della rilevazione versione limitata: al massimo (7) nmap invia
            # una valanga di sonde per porta e su un apparato che non risponde come
            # previsto (VoIP, IoT) la fase si trascina per centinaia di secondi senza
            # concludere. Il tetto la mantiene rapida senza perdere le identificazioni
            # comuni.
            intensita = min(int(profilo["version_intensity"]), MAX_SERVICE_INTENSITY)
            # Tetto di tempo per singolo script NSE. Gli script di arricchimento
            # (http-title, ssl-cert, http-server-header...) su un servizio che non
            # risponde come previsto restano appesi OLTRE il tempo per host: sul campo
            # una passata da 24 host con tempo per host 90s si trascinava comunque a
            # 300-440s, perche' il limite per host non fermava gli script. Legandoli si
            # riporta la durata della passata vicino al tempo per host, senza perdere le
            # identificazioni comuni (che rispondono in pochi secondi).
            argomenti += ["-Pn", "-sV", "--version-intensity", str(intensita),
                          "--min-hostgroup", self._hostgroup(hosts),
                          "--min-parallelism", str(SERVICE_MIN_PARALLELISM),
                          "--script", script, "--script-timeout", SERVICE_SCRIPT_TIMEOUT,
                          timing]
            return argomenti + self._service_ports(hosts, profilo, snmp) + \
                ["--host-timeout", attesa]
        if stage == "os":
            return ["-O", "--osscan-limit", "--max-os-tries", "1", "-Pn", timing,
                    "--min-hostgroup", self._hostgroup(hosts),
                    "--top-ports", "100", "--host-timeout", attesa]
        if stage == "snmp":
            # Lettura completa di cio' che SNMP espone: nome e descrizione del
            # sistema, interfacce, tabelle, processi, software installato, condivisioni
            # e utenti sui sistemi Windows. Tutti script di SOLA LETTURA: `snmp-brute`,
            # che indovina le community, resta fuori di proposito -- un inventario non
            # forza serrature.
            return ["-sU", "-p", str(SNMP_PORT), "-Pn", "--script", SNMP_SCRIPTS,
                    "--script-args", "snmpcommunity=%s" % SNMP_COMMUNITIES.split(",")[0],
                    timing, "--host-timeout", SNMP_HOST_TIMEOUT]
        if stage == "smb":
            # Esattamente il comando chiesto: enumerazione in sola lettura di sistema
            # operativo, condivisioni e utenze su chi espone la 139 o la 445.
            return ["-p", SMB_PORTS, "-Pn", "--script", SMB_SCRIPTS,
                    "--min-hostgroup", self._hostgroup(hosts),
                    timing, "--host-timeout", SMB_HOST_TIMEOUT]
        if stage == "vuln":
            # Ricerca di vulnerabilita' in sola rilevazione, sulle porte a rischio.
            return ["-sV", "--version-light",
                    "-p", ",".join(str(n) for n in VULN_PORT_NUMBERS), "-Pn",
                    "--script", VULN_SCRIPTS, timing,
                    "--min-hostgroup", self._hostgroup(hosts),
                    "--host-timeout", VULN_HOST_TIMEOUT]
        if stage == "deep":
            # L'approfondimento sonda gia' le porte UDP identificative, 161 compresa:
            # quando ha risposto, qui si legge tutto SNMP.
            script = NSE_SCRIPTS
            if self._snmp_open_on(hosts):
                script = NSE_SCRIPTS + "," + SNMP_SCRIPTS
            return ["-sU", "-p", profilo["udp_ports"], "-Pn", "--script", script,
                    timing, "--host-timeout", attesa]
        if stage == "monitor":
            # Echo, timestamp, SYN e ACK sulle porte che questi nodi hanno davvero
            # aperte: su una rete che blocca ICMP l'echo da solo non basta, e l'ACK
            # passa alcuni filtri che scartano i SYN.
            porte = self._monitor_ping_ports(hosts)
            return ["-sn", "-PE", "-PP", "-PS" + porte, "-PA" + porte,
                    timing, "--host-timeout", "20s"]
        raise NmapError("fase non prevista: %s" % stage)

    def _quante_porte(self, argomenti: list) -> int:
        """Quante porte chiede questa invocazione di nmap.

        Si leggono dagli ARGOMENTI gia' composti, non si indovinano: la passata di
        riconoscimento e quella di profondita' chiedono numeri molto diversi, e un
        tetto di tempo calcolato sul caso peggiore terrebbe occupato un posto del
        ciclo per un'ora dove servono due minuti.
        """
        if "--top-ports" in argomenti:
            try:
                return int(argomenti[argomenti.index("--top-ports") + 1])
            except (IndexError, ValueError):
                return len(PORTE_RICONOSCIMENTO)
        if "-p" in argomenti:
            elenco = argomenti[argomenti.index("-p") + 1]
            quante = 0
            for pezzo in str(elenco).split(","):
                if "-" in pezzo.lstrip("TU:"):
                    estremi = pezzo.lstrip("TU:").split("-")
                    try:
                        quante += abs(int(estremi[1]) - int(estremi[0])) + 1
                    except (IndexError, ValueError):
                        quante += 1
                else:
                    quante += 1
            return max(1, quante)
        return len(PORTE_RICONOSCIMENTO)

    def _process_timeout(self, stage: str, hosts: int, profilo: dict,
                         porte: int = None) -> int:
        """Tempo massimo del processo nmap per un compito.

        I compiti portano UN host (vedi EFFORT_PROFILES), quindi il calcolo e' il
        tempo per host piu' il margine di avvio -- moltiplicato per il fattore che
        copre cio' che `--host-timeout` non limita: l'avvio di nmap, la rilevazione
        di versione e le fasi degli script, che sul campo hanno portato una passata a
        2,6-3,3 volte il tempo per host.

        La formula per ONDATE resta perche' un compito puo' ancora portare piu' host
        (una richiesta esplicita dalla console, o un profilo futuro). Ma l'assunzione
        su cui era costruita -- "il tempo di un'ondata e' quello del singolo host, non
        la somma" -- E' FALSA, ed e' stata misurata falsa: il ritmo di invio di nmap e'
        per PROCESSO, e quattro host in un processo costano quattro volte uno (81,2 s
        contro 21,1 s, 200 porte). Se un compito portera' di nuovo molti host, il
        tetto qui va calcolato sulla SOMMA, non sull'ondata. Con un host per compito
        le due formule coincidono e la questione non si pone.

        Perche' non si moltiplicava per i bersagli, com'era prima: il limite arrivava a
        migliaia di secondi e sul campo una passata di servizi su host VoIP che
        appendono nmap ha tenuto un ciclo bloccato per ore -- e senza che il compito si
        concludesse, il "give-up" per fase non scattava mai.
        """
        # Il tempo su cui si calcola il tetto deve essere quello che nmap RICEVE
        # davvero: la scoperta ha il proprio, breve, indipendente dalla scelta
        # dell'operatore (vedi DISCOVERY_HOST_TIMEOUT e `_arguments_for`).
        bersagli = max(1, int(hosts or 1))

        # La fase delle porte non ha piu' un tetto per host: il suo tempo si calcola
        # dal LAVORO, cioe' dalle sonde da inviare diviso il ritmo misurato. E' un
        # conto verificabile e si adatta da se' al numero di host e di porte, invece
        # di moltiplicare un tetto per host che non esiste piu'.
        if stage == "raffica":
            # Un host per processo, con ~234 porte, `-A` e il catalogo di script: il
            # tetto e' il tempo per host della raffica piu' il margine, non un calcolo
            # sulle sonde. Misurato: 24 s su un host che risponde, minuti su un
            # apparato lento.
            return int(min(PROCESS_TIMEOUT_MAX_SECONDS,
                           ATTESA_RAFFICA_PROCESSO_SEC * max(1, bersagli)))

        if stage == "ports":
            quante = int(porte or len(PORTE_RICONOSCIMENTO))
            sonde = bersagli * quante
            stimato = int(sonde / SONDE_AL_SECONDO * MARGINE_TEMPO_PORTE)
            return int(min(PROCESS_TIMEOUT_MAX_SECONDS,
                           stimato + PROCESS_TIMEOUT_MARGIN_SECONDS))

        effettivo = (DISCOVERY_HOST_TIMEOUT if stage == "discovery"
                     else self._host_timeout_for(stage, profilo))
        per_host = parse_timeout(effettivo) or 120
        ondate = -(-bersagli // MAX_HOSTGROUP)  # divisione per eccesso
        stimato = ondate * per_host * PROCESS_TIMEOUT_WAVE_FACTOR
        return int(min(PROCESS_TIMEOUT_MAX_SECONDS,
                       stimato + PROCESS_TIMEOUT_MARGIN_SECONDS))

    def _host_timeout_for(self, stage: str, profilo: dict, hosts: list = None) -> str:
        """Tempo per host della fase, con il minimo per quelle che lo richiedono.

        Un valore troppo breve non rende la fase piu' rapida: la rende inutile,
        perche' nmap abbandona l'host e non restituisce nulla.

        Se nel gruppo c'e' un host che e' GIA' stato abbandonato per scadenza, il
        tempo raddoppia (fino a un tetto): insistere con lo stesso tempo darebbe lo
        stesso esito, e l'host verrebbe scartato per un limite nostro.
        """
        attesa = profilo["host_timeout"]
        secondi = parse_timeout(attesa) or MIN_HOST_TIMEOUT_INSPECTION
        if stage in STAGES_NEEDING_TIME and secondi < MIN_HOST_TIMEOUT_INSPECTION:
            secondi = MIN_HOST_TIMEOUT_INSPECTION

        # La fase delle porte NON riceve piu' un tetto per host: qui c'era il
        # calcolo di un minimo ricavato dal numero di porte, aggiunto quando la
        # struttura era "un host per processo". Con il motore a gruppi il tetto per
        # host e' scomparso del tutto da quella fase (vedi `_arguments_base`), e un
        # minimo per un valore che non viene passato sarebbe solo un messaggio
        # fuorviante nel diario.

        # Il raddoppio "seconda occasione" NON si applica al completamento del profilo:
        # servizi e sistema operativo si arrendono dopo una sola scadenza (l'host viene
        # segnato "tentato" e conferito con cio' che ha), quindi un tempo doppio non
        # cambia l'esito e raddoppierebbe soltanto la durata dell'intera ondata parallela.
        if (hosts and stage not in STAGES_PROFILE_COMPLETION
                and self._qualcuno_e_scaduto(hosts)):
            raddoppiato = min(secondi * 2, MAX_HOST_TIMEOUT_RETRY)
            if raddoppiato > secondi:
                self.store.log(
                    "info",
                    "Fase %s: tempo per host portato a %ds (era %ds) perche' nel"
                    " gruppo c'e' almeno un host abbandonato in precedenza per"
                    " scadenza." % (stage, raddoppiato, secondi))
                secondi = raddoppiato

        return "%ds" % secondi

    def _qualcuno_e_scaduto(self, hosts: list) -> bool:
        """Vero se fra questi host c'e' un CANDIDATO gia' abbandonato per scadenza.

        Solo i candidati: il `timeout_count` di un nodo gia' CONFERMATO viene dalla sua
        fase di candidato (quando scadeva sullo sweep di ping) ed e' ormai superato --
        ha risposto alle porte. Contarlo raddoppiava il tempo per host dell'intero
        gruppo (a 300s) per una scadenza vecchia, e bastava un solo nodo cosi' a
        rendere lentissima la fase dei servizi su tutti gli altri.
        """
        for ip in hosts or []:
            locale = self.store.local_node(ip)
            if not locale or locale.get("state") != "candidate":
                continue
            if not locale.get("profile_json"):
                continue
            try:
                profilo = json.loads(locale["profile_json"]) or {}
            except (TypeError, ValueError):
                continue
            if int(profilo.get("timeout_count") or 0) > 0:
                return True
        return False

    # -- pianificazione dei compiti paralleli --------------------------------
    def _in_ordine_di_priorita(self, nodi: list) -> list:
        """I nodi comparsi su una rete senza fili prima di tutti gli altri.

        Perche' serve: il ciclo dedica UN compito per giro all'esame delle porte dei
        candidati, e su un perimetro di centinaia di indirizzi la coda e' lunga. Un
        telefono che si e' agganciato adesso verrebbe esaminato quando e' gia' andato
        via -- cioe' mai. La coda la scrive la ricognizione delle presenze
        (presence.py), i piu' recenti davanti.
        """
        from .presence import CHIAVE_PRIORITA

        coda = [ip for ip in (self.store.get_json(CHIAVE_PRIORITA, []) or [])
                if isinstance(ip, str)]
        if not coda:
            return nodi
        posizione = {ip: indice for indice, ip in enumerate(coda)}
        # `sorted` e' stabile: chi non e' in coda conserva l'ordine che aveva.
        return sorted(nodi, key=lambda n: posizione.get(n["ip"], len(coda)))

    def plan_tasks(self, limit: int = None) -> list:
        """Compone fino a `limit` compiti indipendenti fra loro.

        Indipendenti significa: nessun indirizzo compare in due compiti dello
        stesso ciclo. E' la prima delle tre condizioni che rendono i thread
        innocui l'uno per l'altro.
        """
        consentito, _ = self.scanning_allowed()
        if not consentito:
            return []
        perimetro = self.perimeter()
        if not perimetro:
            return []

        profilo = self.effort_profile()
        limite = max(1, int(limit or profilo["workers"]))
        per_compito = int(profilo["hosts_per_task"])
        # Posti che il completamento del profilo non puo' prendere: restano alle fasi
        # che vengono DOPO (monitoraggio, SNMP, SMB, vulnerabilita', web). Con un
        # host per compito il completamento riempiva l'intero ciclo e quelle fasi non
        # partivano mai -- fra queste la lettura SNMP, unica fonte dei MAC sulle
        # subnet instradate.
        tetto_profilo = max(1, limite - RISERVA_ARRICCHIMENTO)
        cadenze = self.cadences()
        compiti = []
        assegnati = set()

        def aggiungi_nodi(fase, nodi, tetto=None):
            """Spezza i nodi in compiti da `per_compito`, senza ripetere indirizzi.

            `tetto` limita quanti posti del ciclo questa fase puo' occupare: serve a
            non far riempire l'intero ciclo da una fase sola.
            """
            massimo = limite if tetto is None else min(limite, tetto)
            gruppo = []
            for nodo in nodi:
                if len(compiti) >= massimo:
                    break
                if nodo["ip"] in assegnati:
                    continue
                gruppo.append(nodo["ip"])
                assegnati.add(nodo["ip"])
                if len(gruppo) >= per_compito:
                    compiti.append({"stage": fase, "target": "*", "hosts": list(gruppo)})
                    gruppo = []
            if gruppo and len(compiti) < massimo:
                compiti.append({"stage": fase, "target": "*", "hosts": list(gruppo)})

        def aggiungi_un_compito(fase, nodi):
            """Un solo compito per questa fase: il resto del ciclo resta agli altri."""
            gruppo = []
            for nodo in nodi:
                if nodo["ip"] in assegnati or len(gruppo) >= per_compito:
                    continue
                gruppo.append(nodo["ip"])
                assegnati.add(nodo["ip"])
            if gruppo:
                compiti.append({"stage": fase, "target": "*", "hosts": list(gruppo)})

        # 1. Un posto riservato alla scoperta, se ce n'e' una scaduta: le due
        #    attivita' devono avanzare insieme. Diversamente, su una rete grande i
        #    nodi da profilare non finiscono mai e la scoperta resta indietro.
        da_scoprire = [v["cidr"] if isinstance(v, dict) else v for v in perimetro]
        da_scoprire = [c for c in da_scoprire
                       if self._due(c, "discovery", cadenze["discovery"])]
        if da_scoprire:
            compiti.append({"stage": "discovery", "target": da_scoprire[0],
                            "hosts": [da_scoprire[0]]})

        # 1-ante. Un posto riservato all'esame delle PORTE dei candidati: e' la frontiera
        #    che trasforma un host scoperto (che risponde al solo ping) in un nodo
        #    profilato -- o lo manda allo scarto se non ha nulla. Senza un posto
        #    garantito, i servizi, il sistema operativo e le letture mai fatte riempiono
        #    ogni ciclo e le porte non vengono MAI esaminate: sul campo, con migliaia di
        #    host che rispondono al ping, il conteggio "in lavorazione" restava fermo per
        #    ore senza che nessuno di quei candidati venisse toccato. Un compito per ciclo,
        #    come la scoperta: le due frontiere devono avanzare insieme.
        # 1-ante-0. LA RAFFICA: un processo per nodo, fino a riempire il ciclo.
        #
        # E' la seconda fase del motore: la ricognizione dice CHI risponde, la raffica
        # chiede a ciascuno tutto quello che nmap sa dire -- porte, versioni, sistema
        # operativo, script -- con un processo dedicato. Il parallelismo sta qui, nei
        # posti del ciclo: fino a MAX_WORKERS processi insieme, dove nmap non lo
        # penalizza, invece che dentro un processo solo dove lo penalizza (i numeri
        # stanno su SCRIPT_RAFFICA).
        if len(compiti) < limite:
            in_raffica = [n for n in self.pending_nodes("raffica")
                          if n["ip"] not in assegnati]
            # Chi e' comparso su una rete senza fili passa davanti: la sua finestra e'
            # di minuti, quella di un apparato cablato non finisce.
            in_raffica = self._in_ordine_di_priorita(in_raffica)
            for nodo in in_raffica:
                if len(compiti) >= max(1, limite - RISERVA_ARRICCHIMENTO):
                    break
                assegnati.add(nodo["ip"])
                compiti.append({"stage": "raffica", "target": nodo["ip"],
                                "hosts": [nodo["ip"]]})

        if len(compiti) < limite:
            porte_attesa = [n for n in self.pending_nodes("ports")
                            if n["ip"] not in assegnati]
            # Chi e' comparso su una rete senza fili passa davanti: la sua finestra
            # e' di minuti, quella di un apparato cablato non finisce.
            porte_attesa = self._in_ordine_di_priorita(porte_attesa)
            if porte_attesa:
                # Host a GRUPPI, non tutti in un processo solo.
                #
                # La struttura a un host per compito costava 202 s per host: da qui
                # l'idea di darne molti a un solo processo, dove nmap li lavora a
                # gruppi e distribuisce le sonde. Con un gruppo (64 host) e' vero e
                # misurato: 16 host vivi in 2,6 s con recall completo.
                #
                # Con MOLTI gruppi in un processo solo, no. Misurato in esercizio, ed
                # e' il motivo di questa suddivisione:
                #   * 256 host in un processo: fase "completed", ZERO record. Nessuna
                #     porta trovata su nessuno dei 256 -- mentre lo stesso nmap, sullo
                #     stesso host, con le stesse porte, ne trova in 3,3 secondi;
                #   * oltre 500 host in un processo: nmap non termina entro le due ore
                #     del tetto (PROCESS_TIMEOUT_MAX_SECONDS) e la fase scade.
                # La ragione e' la stessa che aveva fatto scegliere i gruppi: il budget
                # di pacchetti di nmap e' PER PROCESSO. Molti gruppi nello stesso
                # processo se lo dividono, la finestra di congestione si stringe su
                # ogni gruppo, e le porte vere passano per filtrate.
                #
                # Un processo = un gruppo = MAX_HOST_PER_PROCESSO_PORTE host. I compiti
                # che ne risultano girano in parallelo nel pool, quindi il parallelismo
                # non si perde: si sposta dove nmap non lo penalizza.
                indirizzi = [n["ip"] for n in porte_attesa]
                assegnati.update(indirizzi)
                spazio = max(1, limite - len(compiti))
                for inizio in range(0, len(indirizzi),
                                    MAX_HOST_PER_PROCESSO_PORTE):
                    if len([c for c in compiti if c["stage"] == "ports"]) >= spazio:
                        break
                    gruppo = indirizzi[inizio:inizio + MAX_HOST_PER_PROCESSO_PORTE]
                    compiti.append({"stage": "ports", "target": "*",
                                    "hosts": gruppo})
                # Gli indirizzi non entrati in questo ciclo tornano disponibili: senza
                # questo resterebbero "assegnati" senza avere un compito, e nessuna
                # fase li guarderebbe.
                assegnati.difference_update(
                    set(indirizzi) - {ip for c in compiti if c["stage"] == "ports"
                                      for ip in c["hosts"]})

        # 1-ante-2. Un posto riservato al COMPLETAMENTO del profilo: le fasi necessarie
        #    al conferimento (servizi e, dove possibile, sistema operativo) DOPO le
        #    porte. Il conferimento dipende solo da queste fasi, non dalle letture di
        #    arricchimento. Senza un posto garantito qui, con pochi worker i posti
        #    riservati all'arricchimento (SNMP, SMB, vulnerabilita', web) consumano ogni
        #    ciclo e i nodi restano fermi a "ports": confermati ma MAI conferiti, perche'
        #    i servizi non vengono mai interrogati -- sul campo, migliaia "in lavorazione"
        #    per ore. Prima si porta a termine il profilo, poi lo si arricchisce.
        #    Quando l'arretrato del profilo e' GRANDE, il completamento prende la
        #    maggior parte dei posti liberi del ciclo, non uno solo: i compiti girano a
        #    barriera (il ciclo dura quanto il compito piu' lento) e con un solo lotto di
        #    servizi per ciclo migliaia di nodi non si conferiscono mai. L'arricchimento
        #    (SNMP, SMB, vulnerabilita', web) aspetta che la frontiera si svuoti; con
        #    arretrato piccolo torna il posto singolo e l'arricchimento riprende il suo.
        if len(compiti) < limite:
            pendenti = {}
            for fase in reversed(self._required_stages()):
                if fase == "ports":
                    continue
                pendenti[fase] = [n for n in self.pending_nodes(fase)
                                  if n["ip"] not in assegnati]
            # "Arretrato grande" si misura in POSTI del ciclo, non in lotti: con un
            # host per compito un lotto e' un nodo, e "piu' di un nodo" avrebbe
            # dichiarato grande qualunque arretrato.
            molti = (sum(len(v) for v in pendenti.values())
                     > max(per_compito, limite // 2))

            for fase in reversed(self._required_stages()):
                if fase == "ports" or len(compiti) >= limite:
                    continue
                completa = [n for n in (pendenti.get(fase) or [])
                            if n["ip"] not in assegnati]
                if not completa:
                    continue
                aggiungi_un_compito(fase, completa)
                if not molti:
                    # Arretrato piccolo: un solo lotto di profilo, poi l'arricchimento.
                    break
                completa = [n for n in completa if n["ip"] not in assegnati]
                while completa and len(compiti) < tetto_profilo:
                    prima = len(compiti)
                    aggiungi_un_compito(fase, completa)
                    if len(compiti) == prima:
                        break
                    completa = [n for n in completa if n["ip"] not in assegnati]

        # 1-bis. Un posto riservato alle letture MAI fatte: SNMP e pagine di
        #    gestione. Senza questo posto non arrivano mai al proprio turno -- sul
        #    campo, con 443 apparati che espongono una pagina web e centinaia di nodi
        #    ancora da profilare, la fase web non e' partita nemmeno una volta in un
        #    giorno di esercizio: il passo 2 esauriva ogni ciclo. Un compito per fase e
        #    per ciclo: le due attivita' devono avanzare insieme, come la scoperta.
        in_attesa_di_lettura = {"snmp": self._snmp_pending, "smb": self._smb_pending,
                                "vuln": self._vuln_pending, "web": self._web_pending}
        # L'ORDINE NON E' FISSO: chi ha atteso di piu' passa davanti. Con un ordine
        # fisso l'ultima fase dell'elenco non arrivava mai al proprio turno -- vedi
        # `_arricchimenti_per_urgenza`, dove sta la misura.
        for fase in self._arricchimenti_per_urgenza():
            mai_lette = in_attesa_di_lettura[fase]
            if len(compiti) >= limite:
                break
            if (fase not in self._required_stages()
                    and fase not in FASI_ARRICCHIMENTO):
                continue
            attesa = [n for n in mai_lette() if n["ip"] not in assegnati]
            if attesa:
                aggiungi_un_compito(fase, attesa)

        # 1-ter. Priorita' SMB (pulsante "enumera su tutti"): finche' e' attiva, i posti
        #    liberi di QUESTO ciclo vengono riempiti di lotti SMB, non uno solo. Cosi'
        #    la copertura si completa nell'arco di pochi cicli invece che a goccia, e i
        #    dati arrivano man mano -- la sonda non si blocca. Quando non restano nodi
        #    SMB mai letti, la priorita' si spegne da se'.
        if self.smb_boost_active():
            attesa = [n for n in self._smb_pending() if n["ip"] not in assegnati]
            if attesa:
                aggiungi_nodi("smb", attesa)
            elif not any(c["stage"] == "smb" for c in compiti):
                self.store.set_setting(self.SMB_BOOST, "0")
                self.store.log("info", "Enumerazione SMB su tutti i nodi: completata")

        # 2. Completare il profilo dei nodi non ancora conferiti, partendo dalle
        #    fasi FINALI: la scoperta aggiunge continuamente nodi nuovi, e
        #    valutando le fasi nell'ordine naturale la prima avrebbe sempre
        #    lavoro mentre le altre non arriverebbero mai al proprio turno. Cosi'
        #    i nodi piu' avanzati vengono portati a termine per primi.
        for fase in reversed(self._required_stages()):
            if len(compiti) >= tetto_profilo:
                break
            aggiungi_nodi(fase, self.pending_nodes(fase), tetto=tetto_profilo)

        # 3. Altre subnet da scoprire, se restano posti.
        for cidr in da_scoprire[1:]:
            if len(compiti) >= limite:
                break
            compiti.append({"stage": "discovery", "target": cidr, "hosts": [cidr]})

        # 3. Sorvegliare i nodi gia' noti al server.
        #    Con la riserva, come il completamento del profilo: il monitoraggio
        #    riguarda TUTTI i nodi conferiti, quindi con un host per compito
        #    riempirebbe da solo ogni ciclo e le letture che vengono dopo (SNMP, SMB,
        #    vulnerabilita', web) non partirebbero mai. Rileggere lo stato di un nodo
        #    gia' noto non vale piu' della PRIMA lettura di un apparato mai letto.
        if len(compiti) < tetto_profilo and self._due("*", "monitor", cadenze["monitor"]):
            noti = self._within_perimeter_only(
                [n for n in self.store.local_nodes("confirmed")
                 if n.get("conferred_at") and n["ip"] not in assegnati], "monitor")
            if noti:
                aggiungi_nodi("monitor", noti, tetto=tetto_profilo)

        # 4. Leggere SNMP dove la porta e' aperta. Prima della ri-ispezione, non
        #    dopo: la ri-ispezione prende per se' tutti i nodi confermati e un
        #    indirizzo non puo' stare in due compiti dello stesso ciclo, quindi
        #    dopo di essa la lettura SNMP non arriverebbe mai al proprio turno.
        #    SNMP riguarda pochi nodi, ha cadenza di mezza giornata e racconta
        #    dell'apparato piu' di una ri-lettura delle porte.
        #    ANCHE QUI L'ORDINE NON E' FISSO. Le quattro fasi erano elencate una
        #    dopo l'altra, sempre nella stessa sequenza, ed erano due elenchi da
        #    tenere allineati (questo e quello dei posti riservati). L'effetto lo
        #    racconta `_arricchimenti_per_urgenza`: l'ultima dell'elenco non
        #    arrivava mai al proprio turno. Ora la sequenza la decide l'attesa, in
        #    un punto solo.
        pendenti_di = {"snmp": (self._snmp_pending, self._snmp_nodes),
                       "smb": (self._smb_pending, self._smb_nodes),
                       "vuln": (self._vuln_pending, self._vuln_nodes),
                       "web": (self._web_pending, self._web_nodes)}
        for fase in self._arricchimenti_per_urgenza():
            if len(compiti) >= limite:
                break
            mai_letti, tutti = pendenti_di[fase]
            attesa = mai_letti()
            if not attesa and not self._due("*", fase, cadenze[fase]):
                continue
            aggiungi_nodi(fase, [n for n in (attesa or tutti())
                                 if n["ip"] not in assegnati])

        # 5. Ri-ispezionare secondo le cadenze.
        for fase in self._required_stages():
            if len(compiti) >= limite:
                break
            if self._due("*", fase, cadenze[fase]):
                aggiungi_nodi(fase, [n for n in self.store.local_nodes("confirmed")
                                     if n["ip"] not in assegnati])

        # 6. Approfondire i nodi rimasti incerti.
        if len(compiti) < limite and self._due("*", "deep", cadenze["deep"]):
            aggiungi_nodi("deep", [n for n in self._uncertain_nodes()
                                   if n["ip"] not in assegnati])

        return compiti[:limite]

    def run_stage(self, stage: str, target: str) -> dict:
        """Esegue una singola fase e conferisce quanto risulta completo.

        E' il percorso delle richieste immediate dalla console: un compito solo,
        nessun parallelismo, e il conferimento subito dopo.
        """
        if stage not in STAGES:
            raise NmapError("fase non prevista: %s" % stage)

        consentito, motivo = self.scanning_allowed()
        if not consentito:
            # Vale anche per le fasi richieste a mano dalla console: la
            # sospensione non si aggira con un comando.
            self.store.record_scan(target, stage, "suspended", motivo)
            raise ScanSuspended(motivo)

        capacita = self.capabilities()
        if not capacita.get("available"):
            raise NmapError("nmap non disponibile: %s" % capacita.get("detail", ""))

        if stage == "discovery" or (target and target != "*"):
            # Bersaglio esplicito dalla console: si esegue su quel solo host, anche se
            # e' gia' stato letto -- e' proprio cio' che si chiede rifacendo la
            # lettura. Il controllo del perimetro nel compito resta valido.
            bersagli = [target]
        else:
            bersagli = self._targets_for(stage)
        if not bersagli:
            self.store.record_scan(target, stage, "skipped", "nessun bersaglio")
            return {"stage": stage, "target": target, "records": {}, "hosts": 0,
                    "status": "skipped"}

        esito = self._run_task({"stage": stage, "target": target, "hosts": bersagli},
                               capacita, self.effort_profile())
        records = dict(esito.get("records") or {})
        # La lettura SNMP conferisce come le fasi del profilo: e' una richiesta
        # immediata dalla console, e chi la chiede si aspetta di vedere il dato
        # sul server subito dopo, non alla ri-ispezione successiva.
        # Anche "web": una lettura che aggiunge marca, modello o numero di serie deve
        # arrivare sulla console subito, come quella SNMP. Senza questa riga il dato
        # restava nel profilo locale fino alla prossima fase di profilo -- e sul campo
        # gli otto apparati identificati via IPP non comparivano in inventario.
        if stage in PROFILE_STAGES or stage in ("snmp", "smb", "vuln", "web"):
            for tipo, elenco in self._confer_complete_profiles().items():
                records.setdefault(tipo, []).extend(elenco)

        for tipo, elenco in records.items():
            for elemento in elenco:
                self.store.enqueue(tipo, elemento)
        esito["records"] = records
        return esito

    # Chiave del flag di priorita' SMB: quando e' attivo, il pianificatore dedica i
    # posti liberi del ciclo all'enumerazione SMB dei nodi mai letti, finche' non ne
    # restano. E' il pulsante "enumera SMB su tutti": non blocca la sonda -- procede a
    # ogni ciclo, e i dati arrivano man mano, non tutti alla fine.
    SMB_BOOST = "smb_boost"

    def enable_smb_boost(self) -> int:
        """Attiva la priorita' SMB. Restituisce quanti nodi SMB restano da leggere."""
        self.store.set_setting(self.SMB_BOOST, "1")
        return len(self._smb_pending())

    def smb_boost_active(self) -> bool:
        return self.store.get_setting(self.SMB_BOOST, "0") == "1"

    def _run_task(self, task: dict, capacita: dict, profilo: dict) -> dict:
        """Esegue un compito: e' la funzione che girano i thread del pool.

        Non conferisce e non prende decisioni sull'insieme dei nodi: si limita ad
        accumulare le prove nei profili dei propri bersagli e a restituire i
        record che non richiedono coordinamento.
        """
        stage = task["stage"]
        target = task["target"]
        bersagli = list(task["hosts"])

        perimetro = self.perimeter()
        if not perimetro:
            raise PerimeterViolation("perimetro non ricevuto dal server: nessuna scansione")

        # Perimetro vincolante: si verifica ogni bersaglio, non solo il primo.
        for bersaglio in bersagli:
            if stage == "discovery":
                if not self._subnet_declared(bersaglio, perimetro):
                    self._refuse(stage, bersaglio)
            elif not within_perimeter(perimetro, bersaglio):
                self._refuse(stage, bersaglio)

        # La fase web non passa da nmap: e' una richiesta HTTP per porta aperta. Ha
        # un percorso proprio, e si ferma qui.
        if stage == "web":
            return self._run_web_task(task, bersagli)

        argomenti = self._arguments_for(stage, capacita, profilo, bersagli)
        attesa_processo = self._process_timeout(stage, len(bersagli), profilo,
                                                porte=self._quante_porte(argomenti))
        inizio = _now_str()
        avvio = time.monotonic()
        try:
            etichetta = "%s su %s" % (
                stage, target if stage == "discovery" else "%d nodi" % len(bersagli))
            xml = self.runner.run(argomenti, bersagli, timeout=attesa_processo,
                                  label=etichetta)
            stato = "completed"
            dettaglio = ""
        except NmapTimeout as errore:
            # Il tempo massimo e' una condizione prevista, non un guasto: la fase
            # viene annotata come parziale e ritentata alla cadenza successiva.
            self.store.record_scan(target, stage, "timeout", str(errore))
            self.store.log("warning", "Fase %s su %s: %s" % (stage, target, errore))
            return {"stage": stage, "target": target, "records": {}, "hosts": 0,
                    "status": "timeout", "detail": str(errore)}
        except NmapError as errore:
            self.store.record_scan(target, stage, "failed", str(errore))
            self.store.log("warning", "Fase %s su %s non eseguita: %s" % (stage, target, errore))
            raise

        durata = int((time.monotonic() - avvio) * 1000)
        letto = nmap_xml.parse_scan(xml)

        # Monitoraggio: prima di dichiarare assente un bersaglio si riprova sulle sue
        # porte note. Su una rete che blocca ICMP lo sweep non basta.
        vivi_per_porta = {}
        if stage == "monitor":
            visti = {p["ip"] for p in letto["nodes"] + letto["candidates"]}
            mancanti = [ip for ip in bersagli if ip not in visti]
            if mancanti:
                vivi_per_porta = self._confirm_by_ports(mancanti, capacita, profilo)
                if vivi_per_porta:
                    self.store.log(
                        "info",
                        "Monitoraggio: %d nodi su %d non hanno risposto allo sweep ma "
                        "sono vivi sulle proprie porte (%s%s)"
                        % (len(vivi_per_porta), len(mancanti),
                           ", ".join(sorted(vivi_per_porta)[:5]),
                           ", ..." if len(vivi_per_porta) > 5 else ""))

        records = self._records_from(stage, letto, target, task.get("claimed"),
                                    hosts=bersagli, alive_extra=vivi_per_porta)

        esecuzione = {
            "stage": stage,
            "target": target if stage == "discovery" else "%d nodi" % len(bersagli),
            "status": stato,
            "started_at": inizio,
            "finished_at": _now_str(),
            "duration_ms": durata,
            "hosts_total": len(letto["nodes"]) + len(letto["candidates"]) + len(letto["discarded"]),
            "hosts_up": len(letto["nodes"]) + len(letto["candidates"]),
            "records": sum(len(v) for v in records.values()),
            "nmap_args": " ".join(argomenti),
            "nmap_version": capacita.get("nmap_version"),
            "detail": dettaglio or None,
        }
        records.setdefault("scan_runs", []).append(esecuzione)

        # Lo stato viene annotato prima del conferimento: un arresto della sonda
        # non deve far ripetere il lavoro gia' svolto.
        self.store.record_scan(target, stage, stato,
                               "%d host, %d record" % (esecuzione["hosts_up"],
                                                       esecuzione["records"]))
        scaduti = [p.get("ip") for p in (letto.get("nodes") or [])
                   + (letto.get("candidates") or []) + (letto.get("discarded") or [])
                   if p.get("timed_out")]
        if scaduti:
            self.store.log(
                "warning",
                "Fase %s: %d host abbandonati da nmap per scadenza con %s per host "
                "(%s%s). Con meno tempo del necessario la fase non produce nulla."
                % (stage, len(scaduti), self._host_timeout_for(stage, profilo),
                   ", ".join(str(i) for i in scaduti[:5]),
                   ", ..." if len(scaduti) > 5 else ""))
        if bersagli and not esecuzione["hosts_up"]:
            # Nessun host restituito pur avendo bersagli: tipicamente il tempo
            # per host non basta e nmap abbandona. Senza questa annotazione il
            # blocco resterebbe invisibile.
            self.store.log(
                "warning",
                "Fase %s: nessun host restituito su %d bersagli con %s per host. "
                "Se si ripete, il tempo per host e' troppo breve per questa fase."
                % (stage, len(bersagli), " ".join(argomenti[argomenti.index("--host-timeout") + 1:
                                                            argomenti.index("--host-timeout") + 2])
                   if "--host-timeout" in argomenti else "il valore corrente"))
        self.store.log("info", "Fase %s su %s (%d bersagli): %d host, %d record in %.1f s"
                       % (stage, target, len(bersagli), esecuzione["hosts_up"],
                          esecuzione["records"], durata / 1000.0))
        return {"stage": stage, "target": target, "records": records,
                "hosts": esecuzione["hosts_up"], "status": stato, "run": esecuzione}

    def _run_web_task(self, task: dict, bersagli: list) -> dict:
        """Legge le pagine di gestione dei bersagli e ne accumula le prove.

        Non usa nmap e non produce record di nodo: aggiunge al profilo di ciascun
        dispositivo cio' che la sua pagina dichiara di se'. Il conferimento avviene
        con il profilo, come per SNMP.
        """
        from .ipp_probe import leggi as leggi_ipp
        from .web_probe import leggi_dispositivo

        inizio = _now_str()
        avvio = time.monotonic()
        letti = 0
        pagine = 0
        rimasti = 0
        da_ipp = 0
        scadenza = avvio + BUDGET_WEB_COMPITO
        for indice, ip in enumerate(bersagli):
            if time.monotonic() > scadenza:
                # Il tempo del compito e' finito: i dispositivi non letti restano
                # "mai letti" e hanno la precedenza al giro successivo. Meglio una
                # passata che chiude e riprende, di una che non chiude.
                rimasti = len(bersagli) - indice
                break
            locale = self.store.local_node(ip)
            if not locale:
                continue
            porte = self._porte_di(locale)
            try:
                letture = leggi_dispositivo(ip, porte)
            except Exception as errore:  # noqa: BLE001 - una pagina non deve fermare la passata
                self.store.log("warning", "Lettura web di %s non riuscita: %s"
                                          % (ip, type(errore).__name__))
                letture = []

            # IPP: dove la pagina HTML non dice il modello -- accade con le interfacce
            # costruite in JavaScript -- il protocollo di stampa lo dice, insieme al
            # numero di serie e al firmware. E' una sola richiesta di sola lettura.
            try:
                lettura_ipp = leggi_ipp(ip, porte)
            except Exception as errore:  # noqa: BLE001 - un apparato non deve fermare la passata
                self.store.log("warning", "Lettura IPP di %s non riuscita: %s"
                                          % (ip, type(errore).__name__))
                lettura_ipp = {}
            if lettura_ipp:
                letture = list(letture) + [lettura_ipp]
                da_ipp += 1
            if not letture:
                continue
            self._merge_web(ip, letture)
            letti += 1
            pagine += len([v for v in letture if v.get("stato")])

        durata = int((time.monotonic() - avvio) * 1000)
        esecuzione = {
            "stage": "web",
            "target": "%d nodi" % len(bersagli),
            "status": "completed",
            "started_at": inizio,
            "finished_at": _now_str(),
            "duration_ms": durata,
            "hosts_total": len(bersagli),
            "hosts_up": letti,
            "records": pagine,
            # Nessun comando esterno: la fase e' fatta di richieste HTTP.
            "nmap_args": "(lettura HTTP interna, nessun processo esterno)",
            "nmap_version": None,
            "detail": ("%d pagine lette su %d dispositivi (%d identificati via IPP)"
                       % (pagine, letti, da_ipp))
                      + (", %d rinviati al giro successivo per tempo" % rimasti
                         if rimasti else ""),
        }
        self.store.record_scan("*", "web", "partial" if rimasti else "completed",
                               "%d dispositivi, %d pagine%s"
                               % (letti, pagine,
                                  ", %d rinviati" % rimasti if rimasti else ""))
        self.store.log("info", "Fase web: %d dispositivi interrogati, %d pagine lette,"
                               " %d identificati via IPP, in %.1f s"
                               % (len(bersagli), pagine, da_ipp, durata / 1000.0))
        return {"stage": "web", "target": task["target"],
                "records": {"scan_runs": [esecuzione]}, "hosts": letti,
                "status": "completed", "run": esecuzione}

    def _merge_web(self, ip: str, letture: list) -> None:
        """Unisce al profilo locale cio' che le pagine del dispositivo dichiarano."""
        locale = self.store.local_node(ip)
        profilo = self._profilo_di(locale) if locale else {}
        profilo["ip"] = ip
        profilo["web"] = letture
        profilo["web_read_at"] = _now_str()
        # Si annota che IPP e' stato TENTATO, non che ha risposto: un apparato che non
        # parla IPP non deve essere richiesto a ogni ciclo.
        profilo["ipp_tried_at"] = _now_str()
        profilo["ipp_read"] = any((v.get("scheme") == "ipp") for v in letture
                                 if isinstance(v, dict))

        svolte = set((locale or {}).get("stages_done", "").split(",")) - {""}
        svolte.add("web")
        self.store.upsert_local_node(
            ip,
            state="confirmed",
            profile_json=json.dumps(profilo, ensure_ascii=False),
            stages_done=",".join(sorted(svolte)),
            last_merge_at=_now_str(),
        )

    def _subnet_declared(self, cidr: str, perimetro: list) -> bool:
        dichiarate = {v["cidr"] if isinstance(v, dict) else v for v in perimetro}
        return cidr in dichiarate

    def _refuse(self, stage: str, bersaglio: str) -> None:
        messaggio = ("Bersaglio %s rifiutato nella fase %s: non appartiene al perimetro "
                     "dichiarato dal server" % (bersaglio, stage))
        self.store.log("warning", messaggio)
        self.store.enqueue("event", {
            "type": "probe.perimeter.refused",
            "severity": "critical",
            "description": messaggio,
            "created_at": _now_str(),
            "detail": {"bersaglio": bersaglio, "fase": stage},
        })
        raise PerimeterViolation(messaggio)

    # -- trasformazione delle prove in record --------------------------------
    def _confirm_by_ports(self, hosts: list, capacita: dict, profilo: dict) -> dict:
        """Riprova i nodi che non hanno risposto allo sweep, sulle loro porte note.

        Restituisce {ip: latenza in ms oppure None} per quelli che risultano vivi.
        Una porta `open` o `closed` prova la presenza dell'host; `filtered` no.

        E' il secondo tentativo che mancava: prima si dichiarava assente un nodo che
        rispondeva regolarmente in TCP, solo perche' non rispondeva a ICMP.
        """
        if not hosts:
            return {}
        porte = self._known_open_ports(hosts)
        elenco = (",".join(str(p) for p in porte[:MONITOR_PING_PORTS_MAX])
                  if porte else MONITOR_FALLBACK_PORTS)
        argomenti = [("-sS" if capacita.get("raw_sockets") else "-sT"), "-Pn",
                     "-p", elenco, profilo["timing"], "--host-timeout", "25s"]
        try:
            xml = self.runner.run(argomenti, hosts,
                                  timeout=self._process_timeout("monitor", len(hosts),
                                                                profilo),
                                  label="verifica su porte note (%d nodi)" % len(hosts))
        except (NmapTimeout, NmapAborted):
            return {}
        except NmapError as errore:
            self.store.log("warning",
                           "Verifica sulle porte note non eseguita: %s" % errore)
            return {}

        letto = nmap_xml.parse_scan(xml)
        vivi = {}
        for prove in letto["nodes"] + letto["candidates"] + letto["discarded"]:
            stati = [(p.get("state") or "") for p in prove.get("ports") or []]
            if any(s in ALIVE_PORT_STATES for s in stati):
                vivi[prove["ip"]] = prove.get("latency_ms")
        return vivi

    def _records_from(self, stage: str, letto: dict, target: str, claimed=None,
                      hosts: list = None, alive_extra: dict = None) -> dict:
        if stage == "discovery":
            # Il bersaglio (la subnet) serve al controllo di sanita': senza sapere
            # QUALE subnet si e' guardata non si puo' dire se la risposta e' credibile.
            return self._records_discovery(letto, claimed, target)
        if stage == "monitor":
            return self._records_monitor(letto, hosts or [], alive_extra or {})
        return self._records_inspection(letto, stage, hosts or [])

    def scoperta_credibile(self, cidr: str, visti: list) -> tuple:
        """`(credibile, motivo)` per l'esito di una scoperta su una subnet.

        Vedi la nota su SANITA_QUOTA_SOSPETTA: qui si riconosce una rete che risponde
        per interposta persona -- il NAT di un contenitore, un apparato intermedio --
        prima che i suoi indirizzi diventino nodi dell'inventario.
        """
        import ipaddress

        try:
            rete = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return (True, "")
        if rete.num_addresses < 8:
            # Su una /30 o piu' piccola "quasi tutti" non significa niente.
            return (True, "")

        indirizzi = {str(i) for i in visti}
        impossibili = sorted(indirizzi & {str(rete.network_address),
                                          str(rete.broadcast_address)})
        quota = len(indirizzi) / float(rete.num_addresses)
        if not impossibili or quota < SANITA_QUOTA_SOSPETTA:
            return (True, "")
        return (False,
                "rispondono %d indirizzi su %d (%d%%) COMPRESI %s, dove un host non"
                " puo' esistere: non e' la rete che risponde ma un intermediario"
                " -- il NAT di un contenitore, o un apparato che risponde per il"
                " segmento. Nessun nodo registrato: un inventario inventato e' peggio"
                " di un inventario vuoto. Se la sonda gira in un contenitore su"
                " Docker Desktop, va eseguita con accesso reale alla rete"
                " (network_mode: host su Linux, oppure fuori dal contenitore)."
                % (len(indirizzi), rete.num_addresses, round(quota * 100),
                   " e ".join(impossibili)))

    def _records_discovery(self, letto: dict, claimed=None, target: str = "") -> dict:
        """La scoperta conferisce i nodi con prove; i nudi restano candidati.

        Gli indirizzi prenotati da un altro compito del ciclo vengono ignorati:
        li sta esaminando qualcun altro e non va toccato il loro stato.

        Prima di registrare qualunque cosa si verifica che l'esito sia CREDIBILE: una
        rete in cui risponde tutto, indirizzo di rete e di broadcast compresi, non e'
        una rete ma un intermediario che risponde per lei (vedi `scoperta_credibile`).
        """
        visti = [p["ip"] for p in
                 letto["nodes"] + letto["candidates"] + letto["discarded"]]
        credibile, motivo = self.scoperta_credibile(target, visti)
        if not credibile:
            self.store.log("error", "Scoperta di %s RIFIUTATA: %s" % (target, motivo))
            return {}

        occupati = set()
        for chiave in (claimed or ()):
            if chiave.startswith("node:"):
                occupati.add(chiave.split(":", 1)[1])
        nodi = []
        for prove in letto["nodes"]:
            if prove["ip"] in occupati:
                continue
            self.store.upsert_local_node(prove["ip"], state="confirmed", ttl=prove.get("ttl"),
                                         mac=prove.get("mac"), hostname=prove.get("hostname"))
            nodi.append(self._node_record(prove, ports_examined=False))
        for prove in letto["candidates"]:
            if prove["ip"] in occupati:
                continue
            esistente = self.store.local_node(prove["ip"])
            if esistente and self._still_in_cooldown(esistente):
                # Scartato di recente perche' privo di informazioni: si lascia
                # stare, altrimenti il giro ricomincerebbe da capo.
                continue
            if esistente and esistente["state"] == "confirmed":
                # Nodo gia' confermato in passato: la scoperta ne attesta la
                # presenza, non lo retrocede a candidato.
                self.store.upsert_local_node(prove["ip"], ttl=prove.get("ttl"))
                nodi.append(self._node_record(prove, ports_examined=False))
            else:
                self.store.upsert_local_node(prove["ip"], state="candidate",
                                             ttl=prove.get("ttl"))
        return {"nodes": nodi} if nodi else {}

    def _records_monitor(self, letto: dict, bersagli: list,
                         vivi_per_porta: dict = None) -> dict:
        """Campioni di raggiungibilita' dei SOLI bersagli del compito.

        Difetto corretto qui: si dichiarava "non raggiungibile" ogni nodo conferito
        non visto nello sweep, compresi quelli che il compito non aveva nemmeno
        interrogato. Con 170 nodi e sedici per passata, 154 risultavano assenti a ogni
        giro -- e avevano tutti porte aperte in inventario.
        """
        vivi_per_porta = vivi_per_porta or {}
        campioni = []
        for prove in letto["nodes"] + letto["candidates"]:
            campioni.append({
                "ip": prove["ip"],
                "reachable": bool(prove.get("reachable")),
                "latency_ms": prove.get("latency_ms"),
                "checked_at": _now_str(),
            })
        visti = {p["ip"] for p in letto["nodes"] + letto["candidates"]}
        for ip in bersagli:
            if ip in visti:
                continue
            if ip in vivi_per_porta:
                # Non ha risposto allo sweep ma risponde sulle proprie porte: e' vivo,
                # e dichiararlo assente sarebbe falso.
                campioni.append({"ip": ip, "reachable": True,
                                 "latency_ms": vivi_per_porta[ip],
                                 "checked_at": _now_str(),
                                 "detail": "raggiunto sulle porte note, non risponde "
                                           "ai probe di ping"})
                continue
            campioni.append({"ip": ip, "reachable": False,
                             "latency_ms": None, "checked_at": _now_str(),
                             "detail": "nessuna risposta ai probe di ping ne' sulle "
                                       "porte note"})
        # I bersagli verificati si annotano: e' cio' che fa girare la rotazione.
        self.store.mark_monitored([c["ip"] for c in campioni])
        # Solo i nodi noti al server: un campione per un nodo mai conferito
        # arriverebbe orfano.
        noti = {n["ip"] for n in self.store.local_nodes("confirmed") if n.get("conferred_at")}
        campioni = [c for c in campioni if c["ip"] in noti]
        return {"monitor": campioni} if campioni else {}

    def _records_inspection(self, letto: dict, stage: str, bersagli: list = None) -> dict:
        """Fasi di ispezione: le prove si accumulano nel profilo locale.

        Nulla viene conferito qui. Il conferimento avviene in
        `_confer_complete_profiles`, quando il profilo del dispositivo e'
        completo: il server deve ricevere dispositivi interi.
        """
        for prove in letto["nodes"]:
            self._merge_profile(prove["ip"], stage, prove)

        # Gli host che nmap non ha restituito: per la fase 'ports' e' la regola di
        # ammissione (candidato senza porte -> si valuta lo scarto); per le fasi di
        # ispezione (servizi, sistema operativo, SMB...) un host GIA' confermato che
        # scade NON retrocede a candidato -- ha gia' le porte -- ma dopo troppe
        # scadenze la fase si segna "tentata", cosi' la frontiera avanza sempre.
        for prove in letto["discarded"] + letto["candidates"]:
            self._handle_inspection_miss(prove, stage)

        # Gli host che nmap ha ABBANDONATO del tutto: su una fase di ispezione un
        # apparato lento -- VoIP, IoT, sistemi che non rispondono a -sV -- viene
        # scartato da nmap al superare del tempo per host e non compare nell'XML, ne'
        # fra i nodi ne' fra gli scartati. Prima non erano contati da nessuna parte:
        # la fase non li portava mai a termine, il pianificatore li ripescava a OGNI
        # ciclo e la frontiera restava bloccata (sul campo: migliaia "in lavorazione"
        # per giorni, il conteggio dei conferiti fermo). Un host confermato assente
        # dal risultato vale come una scadenza di fase, esattamente come uno che nmap
        # restituisce marcato scaduto: dopo la soglia la fase e' "tentata" e il nodo
        # puo' essere conferito con cio' che ha. Non riguarda 'ports' (li' l'assenza e'
        # gestita dall'ammissione dei candidati) ne' la scoperta.
        if bersagli and stage not in ("discovery", "ports", "raffica"):
            visti = {p["ip"] for p in
                     letto["nodes"] + letto["candidates"] + letto["discarded"]}
            for ip in bersagli:
                if ip in visti:
                    continue
                locale = self.store.local_node(ip)
                if locale and locale.get("state") == "confirmed":
                    self._stage_timeout_confirmed(ip, stage, locale)

        # Il conferimento non avviene qui: e' il coordinatore a deciderlo, una
        # volta sola, quando tutti i compiti del ciclo hanno terminato.
        return {}

    def _handle_inspection_miss(self, prove: dict, stage: str) -> None:
        """Un host che una fase non ha restituito. Distingue il nodo confermato
        (che non retrocede) dal candidato ancora da ammettere."""
        locale = self.store.local_node(prove["ip"])
        if locale and locale.get("state") == "confirmed":
            # Un nodo confermato non torna candidato per una fase di ispezione
            # scaduta. Se e' scaduto, dopo troppe volte la fase si segna tentata.
            if prove.get("timed_out"):
                self._stage_timeout_confirmed(prove["ip"], stage, locale)
            return
        # Nodo non ancora confermato: e' l'esame delle porte che ne decide l'ammissione.
        self._handle_unconfirmed(prove)

    def _stage_timeout_confirmed(self, ip: str, stage: str, locale: dict) -> None:
        """Conta le scadenze di una fase su un nodo confermato e, oltre la soglia,
        segna la fase come TENTATA cosi' non si ripete all'infinito e non blocca il
        conferimento. Un nodo che non risponde mai a una fase va conferito con cio'
        che ha, non tenuto "in lavorazione" per sempre."""
        try:
            profilo = json.loads(locale.get("profile_json") or "{}") or {}
        except (TypeError, ValueError):
            profilo = {}
        conteggi = profilo.get("stage_timeouts") or {}
        quante = int(conteggi.get(stage) or 0) + 1
        conteggi[stage] = quante
        profilo["stage_timeouts"] = conteggi
        profilo["ip"] = ip

        if quante < MAX_STAGE_TIMEOUTS:
            self.store.upsert_local_node(
                ip, profile_json=json.dumps(profilo, ensure_ascii=False))
            return

        svolte = set((locale.get("stages_done") or "").split(",")) - {""}
        svolte.add(stage)
        self.store.upsert_local_node(
            ip, state="confirmed", stages_done=",".join(sorted(svolte)),
            profile_json=json.dumps(profilo, ensure_ascii=False))
        self.store.log(
            "warning",
            "Fase %s su %s segnata come tentata dopo %d scadenze: non verra' piu'"
            " riprovata finche' le prove non cambiano, cosi' il nodo puo' essere"
            " conferito con cio' che ha." % (stage, ip, quante))

    def _merge_profile(self, ip: str, stage: str, prove: dict) -> None:
        """Unisce le prove di una fase al profilo locale del nodo."""
        locale = self.store.local_node(ip)
        profilo = {}
        if locale and locale.get("profile_json"):
            try:
                profilo = json.loads(locale["profile_json"]) or {}
            except (TypeError, ValueError):
                # Profilo illeggibile: si riparte da questa fase invece di
                # trascinare un contenuto corrotto.
                self.store.log("warning", "Profilo locale di %s illeggibile: ricostruito" % ip)
                profilo = {}

        profilo["ip"] = ip
        for campo in ("mac", "mac_vendor", "hostname", "ttl", "latency_ms", "reachable"):
            if prove.get(campo) is not None:
                profilo[campo] = prove[campo]

        porte = {"%s/%s" % (p["protocol"], p["port"]): p
                 for p in profilo.get("ports_index", {}).values()} if profilo.get("ports_index") else {}
        for porta in prove.get("ports") or []:
            if porta["state"] not in ("open", "closed"):
                continue
            voce = dict(porta)
            voce["ip"] = ip
            voce["seen_at"] = _now_str()
            porte["%s/%s" % (voce["protocol"], voce["port"])] = voce
        profilo["ports_index"] = porte

        sistema = prove.get("os") or {}
        if sistema.get("name"):
            voce = dict(sistema)
            voce["ip"] = ip
            profilo["os"] = voce
        if prove.get("scripts"):
            script = profilo.get("scripts") or {}
            script.update(prove["scripts"])
            profilo["scripts"] = script
            # Cio' che SNMP racconta e' la fonte piu' ricca su un apparato di rete:
            # si conserva anche in forma leggibile, non solo come testo di script.
            riassunto = snmp_summary(script)
            if riassunto:
                profilo["snmp"] = riassunto
                # Quando il nodo e' stato letto: distingue "mai letto" da "letto e
                # da rileggere", che e' la differenza fra informazione mancante e
                # informazione vecchia.
                profilo["snmp_read_at"] = _now_str()

        if stage == "smb":
            # La fase e' stata eseguita su questo nodo: lo si segna letto anche se
            # non ha restituito nulla, altrimenti resterebbe per sempre "mai letto" e
            # la fase lo riprenderebbe a ogni ciclo. Un servizio che non concede nulla
            # e' a sua volta un'informazione.
            profilo["smb_read_at"] = _now_str()
            riassunto_smb = smb_summary(profilo.get("scripts") or {})
            if riassunto_smb:
                profilo["smb"] = riassunto_smb

        if stage == "vuln":
            # Verificato: si segna anche quando nulla e' risultato vulnerabile -- e'
            # l'informazione "controllato, nessun difetto fra quelli cercati".
            profilo["vuln_read_at"] = _now_str()
            trovati = vuln_findings(profilo.get("scripts") or {})
            if trovati:
                profilo["vuln"] = trovati

        svolte = set((locale or {}).get("stages_done", "").split(",")) - {""}
        svolte.add(stage)
        if stage == "raffica":
            # La raffica ha chiesto porte, versioni e sistema operativo in un colpo
            # solo: dichiarare quelle fasi da fare significherebbe rifarle. Restano
            # utili alla RI-ispezione di un nodo gia' conferito, dove interessa una
            # cosa per volta.
            svolte.update(FASI_COPERTE_DALLA_RAFFICA)
        aperte = [p for p in porte.values() if p["state"] == "open"]

        # L'host ha RISPOSTO a questa fase: la sua storia di scadenze e' superata e
        # non deve piu' penalizzare i gruppi in cui finisce. Senza questo azzeramento
        # un nodo confermato trascinava con se' il conteggio di quando, da candidato,
        # scadeva sullo sweep: bastava uno di questi in un gruppo per portare TUTTI i
        # servizi a 300s per host, gonfiare il tempo del processo a migliaia di secondi
        # e bloccare il ciclo -- e i nodi sani non ottenevano mai la fase 'services'.
        profilo.pop("timeout_count", None)
        profilo.pop("timed_out_at", None)
        # Se aveva scadenze registrate su QUESTA fase (nodo confermato), ora che ha
        # risposto si azzerano: non e' piu' un caso di rinuncia.
        if profilo.get("stage_timeouts", {}).get(stage):
            profilo["stage_timeouts"].pop(stage, None)

        self.store.upsert_local_node(
            ip,
            state="confirmed",
            ttl=prove.get("ttl"),
            mac=prove.get("mac"),
            hostname=prove.get("hostname"),
            open_ports=len(aperte),
            has_os=1 if profilo.get("os") else None,
            profile_json=json.dumps(profilo, ensure_ascii=False),
            stages_done=",".join(sorted(svolte)),
            last_merge_at=_now_str(),
        )

    @staticmethod
    def profile_has_information(profilo: dict) -> bool:
        """Vero se il profilo porta almeno un'informazione sul dispositivo.

        Porte chiuse o filtrate non contano: sono la prova che qualcosa ha
        risposto -- utile all'ammissione -- ma non dicono nulla sul dispositivo.
        """
        if not profilo:
            return False
        for campo in ("hostname", "mac", "mac_vendor"):
            if profilo.get(campo):
                return True
        if (profilo.get("os") or {}).get("name"):
            return True
        if profilo.get("scripts"):
            return True
        for porta in (profilo.get("ports_index") or {}).values():
            if porta.get("state") == "open":
                return True
            if porta.get("banner"):
                return True
        return False

    def _niente_da_profilare(self, nodo) -> bool:
        """Vero se un host ha fatto la fase 'ports' e NON ha porte aperte.

        Le fasi successive -- servizi, sistema operativo, approfondimento, SMB, web,
        vulnerabilita' -- lavorano tutte sulle porte: su un host che non ne ha aperte non
        troverebbero nulla. Trattarlo come gia' esaminato evita di sprecare minuti di
        rilevamento su migliaia di host che rispondono al solo ping, e lo porta subito a
        conferimento (se ha un nome o un MAC) o allo scarto (se non ha nulla).
        """
        svolte = set((nodo.get("stages_done") or "").split(",")) - {""}
        return "ports" in svolte and int(nodo.get("open_ports") or 0) == 0

    def _fully_examined(self, nodo) -> bool:
        """Vero se non c'e' piu' nulla da profilare: o tutte le fasi sono svolte, oppure
        'ports' non ha trovato porte aperte (e allora le altre fasi sono inutili)."""
        svolte = set((nodo.get("stages_done") or "").split(",")) - {""}
        richieste = set(self._required_stages()) | {"deep"}
        return richieste <= svolte or self._niente_da_profilare(nodo)

    # Quante verifiche singole si fanno in un ciclo, prima di scartare. Il tetto serve
    # a non far monopolizzare il ciclo dal riesame: chi resta fuori NON viene scartato,
    # viene verificato al giro dopo -- restare candidato non costa niente, sparire si'.
    MAX_VERIFICHE_PRIMA_DELLO_SCARTO = 4

    # Tempo massimo del riesame singolo. Misurato: un host di questo tipo si esamina in
    # 3,3 secondi da solo; trenta secondi sono abbondanti anche su una rete che non
    # risponde.
    ATTESA_VERIFICA_SEC = 20

    def _segna_verificato(self, ip: str) -> None:
        """Annota che il nodo E' STATO guardato da solo, e non va riesaminato.

        Si chiama solo quando la verifica e' AVVENUTA -- non prima di tentarla. La
        prima versione la segnava prima, e una verifica che non partiva (esecutore
        saturo, tempo scaduto) bruciava l'unica occasione: il nodo restava muto per
        sempre senza essere mai stato guardato.
        """
        locale = self.store.local_node(ip)
        try:
            profilo = json.loads((locale or {}).get("profile_json") or "{}") or {}
        except (TypeError, ValueError):
            profilo = {}
        profilo["verified_alone_at"] = _now_str()
        self.store.upsert_local_node(
            ip, profile_json=json.dumps(profilo, ensure_ascii=False))

    def _riesamina_da_solo(self, ip: str) -> str:
        """Riesamina un host DA SOLO prima di scartarlo.

        Restituisce `"trovato"`, `"muto"` oppure `"non_verificato"`. I tre esiti sono
        tre cose diverse e vanno tenute distinte: "muto" autorizza lo scarto,
        "non_verificato" no -- e confonderli e' precisamente l'errore che ha fatto
        sparire un firewall dall'inventario.

        PERCHE' ESISTE, con la misura che lo ha imposto.
        In esercizio 10.10.60.1 -- il firewall che fa da gateway a una rete di utenza,
        con la 53/tcp aperta e servita da Unbound -- e' stato scartato come "nessuna
        informazione dopo le fasi ports, snmp". Lo stesso nmap, sullo stesso host,
        dalla stessa sonda, con le stesse trenta porte, lo trova in 3,3 secondi.
        L'unica differenza era il contesto: quell'host era uno di 256 in un solo
        processo, su una rete che a quasi tutto non risponde.

        Perdere un apparato vero e' il difetto piu' grave che questo prodotto possa
        avere. Un dato mancante e' un dato mancante; un firewall che sparisce
        dall'inventario e' un'AFFERMAZIONE FALSA -- e chi legge non ha modo di
        accorgersene, perche' non si vede cio' che non c'e'.

        Il riesame costa pochi secondi, si fa solo su chi sta per essere scartato (un
        numero piccolo) e si fa UNA volta per nodo: se anche da solo non dice nulla, il
        nodo si scarta e non lo si riesamina piu'.
        """
        argomenti = ["-sS" if self.capabilities().get("raw_sockets") else "-sT",
                     "-Pn", "-T3", "-p", ",".join(str(p) for p in PORTE_RICONOSCIMENTO)]
        escluse = self.excluded_ports()
        if escluse:
            argomenti += ["--exclude-ports", escluse]
        try:
            xml = self.runner.run(argomenti, [ip],
                                  timeout=self.ATTESA_VERIFICA_SEC,
                                  label="verifica di %s prima dello scarto" % ip)
        except (NmapTimeout, NmapError) as errore:
            # Non si e' potuto verificare: NON si scarta e NON si consuma l'occasione.
            # Costato subito: la prima versione segnava il nodo come "verificato"
            # prima di verificarlo, quindi una verifica che non partiva (esecutore
            # saturo, tempo scaduto) bruciava l'unica occasione e il nodo restava muto
            # per sempre. Misurato su 10.10.60.101.
            self.store.log("warning",
                           "Verifica di %s non eseguita (%s): il nodo resta in attesa"
                           % (ip, type(errore).__name__))
            return "non_verificato"
        try:
            letto = nmap_xml.parse_scan(xml, ports_examined=True)
        except nmap_xml.NmapXmlError as errore:
            self.store.log("warning", "Verifica di %s illeggibile (%s): il nodo resta"
                                      " in attesa" % (ip, errore))
            return "non_verificato"

        for prove in letto["nodes"] + letto["candidates"] + letto["discarded"]:
            if prove["ip"] != ip:
                continue
            aperte = [p for p in (prove.get("ports") or [])
                      if p.get("state") == "open"]
            if not aperte and not prove.get("os") and not prove.get("hostname"):
                return "muto"
            # Qualcosa c'era: si fondono le prove come quelle di una fase normale, e il
            # nodo torna nel giro invece di uscirne.
            self._merge_profile(ip, "ports", prove)
            self.store.log("warning",
                           "Nodo %s stava per essere scartato ma da solo risponde:"
                           " %d porte aperte (%s). La passata di gruppo non le aveva"
                           " viste."
                           % (ip, len(aperte),
                              ", ".join("%s/%s" % (p.get("protocol"), p.get("port"))
                                        for p in aperte[:6]) or "nessuna"))
            return "trovato"
        # nmap non ha nemmeno elencato l'host: non e' una risposta, e' un'assenza di
        # risposta. Non conta come verifica.
        return "non_verificato"

    def _recupera_i_muti(self, quota: int) -> int:
        """Riesamina da solo chi ha fatto la fase porte senza trovare niente, e non e'
        mai stato guardato da solo. Restituisce quanti ne ha riesaminati.

        Perche' serve oltre alla verifica che precede lo scarto: quella impedisce di
        perdere ALTRI apparati, ma quelli gia' persi resterebbero fuori fino al
        censimento successivo -- giorni. Un firewall mancante dall'inventario per tre
        giorni e' comunque un'affermazione falsa per tre giorni.

        Vale per QUALUNQUE stato, e la ragione e' un difetto misurato: un nodo scartato
        che la ricognizione delle presenze rivede torna "candidato", ma con la fase
        porte gia' segnata e zero porte aperte -- quindi nessuna coda lo riprende, e
        resta la' per sempre, ne' conferito ne' scartato. Guardare solo gli scartati
        avrebbe lasciato fuori proprio il caso che ha fatto scoprire il difetto.

        Il riesame vale UNA volta per nodo (`verified_alone_at`): un nodo che anche da
        solo non dice niente e' muto per davvero, e non si riesamina a ogni ciclo.
        """
        if quota <= 0:
            return 0
        recuperati = 0
        for locale in self.store.local_nodes():
            if recuperati >= quota:
                break
            svolte = set((locale.get("stages_done") or "").split(",")) - {""}
            if "ports" not in svolte or int(locale.get("open_ports") or 0) > 0:
                continue
            try:
                profilo = json.loads(locale.get("profile_json") or "{}")
            except (TypeError, ValueError):
                continue
            if profilo.get("verified_alone_at"):
                continue
            # Il perimetro vincola anche il riesame: un indirizzo non piu' dichiarato
            # non si tocca, nemmeno per recuperarlo.
            if not within_perimeter(self.perimeter(), locale["ip"]):
                continue
            recuperati += 1
            era_scartato = locale.get("state") == "discarded"
            esito = self._riesamina_da_solo(locale["ip"])
            if esito != "non_verificato":
                self._segna_verificato(locale["ip"])
            if esito == "trovato":
                # `_riesamina_da_solo` ha fuso le prove: il nodo torna "confirmed" e il
                # conferimento del ciclo successivo lo rimette nell'inventario, da cui
                # era stato rimosso.
                self.store.upsert_local_node(locale["ip"], state="confirmed")
                self.store.log(
                    "warning",
                    "Nodo %s %s: da solo risponde, la passata di gruppo non lo aveva"
                    " visto" % (locale["ip"],
                                "recuperato" if era_scartato else "riportato in giro"))
        return recuperati

    def _drop_without_information(self) -> list:
        """Scarta i nodi che, esaurite tutte le fasi, non portano informazioni.

        Restituisce i record di rimozione da conferire: la decisione e' della
        sonda, che sa quali fasi ha svolto, ma l'inventario e' del server, che la
        applica solo dopo aver verificato di non avere dati propri sul nodo.
        """
        rimozioni = []
        verifiche = 0
        for locale in self.store.local_nodes("confirmed"):
            svolte = set((locale.get("stages_done") or "").split(",")) - {""}
            if not self._fully_examined(locale):
                continue
            try:
                profilo = json.loads(locale.get("profile_json") or "{}")
            except (TypeError, ValueError):
                self.store.log("warning", "Profilo di %s illeggibile: non si scarta"
                               % locale["ip"])
                continue
            if self.profile_has_information(profilo):
                continue

            # RIESAME PRIMA DELLO SCARTO. Una passata di gruppo che non ha visto nulla
            # non e' una prova che non ci sia nulla: vedi `_riesamina_da_solo`, che
            # esiste per un firewall vero scartato per errore.
            if not profilo.get("verified_alone_at"):
                if verifiche >= self.MAX_VERIFICHE_PRIMA_DELLO_SCARTO:
                    # Fuori quota: NON si scarta. Si riprova al giro dopo -- restare
                    # candidato non costa niente, sparire si'.
                    continue
                verifiche += 1
                esito = self._riesamina_da_solo(locale["ip"])
                if esito != "muto":
                    # "trovato" oppure "non_verificato": in nessuno dei due casi si
                    # scarta, e l'occasione NON si consuma se la verifica non e'
                    # avvenuta -- altrimenti un esecutore saturo condannerebbe il nodo
                    # (misurato su 10.10.60.101).
                    if esito == "trovato":
                        self._segna_verificato(locale["ip"])
                    continue
                self._segna_verificato(locale["ip"])

            adesso = _now_str()
            self.store.upsert_local_node(locale["ip"], state="discarded",
                                         discarded_at=adesso)
            motivo = ("nessuna informazione dopo le fasi %s: nessuna porta aperta, "
                      "nessun sistema operativo, nessun nome host, nessun banner"
                      % ", ".join(sorted(svolte)))
            rimozioni.append({"ip": locale["ip"], "reason": motivo,
                              "stages": sorted(svolte), "decided_at": adesso})
            self.store.log("info", "Nodo %s scartato: %s" % (locale["ip"], motivo))

        # Con la quota che resta si guarda indietro: chi e' passato per la fase porte
        # senza trovare niente, prima che questa verifica esistesse, non e' mai stato
        # guardato da solo -- scartato, o rimasto candidato senza piu' una coda che lo
        # riprendesse.
        self._recupera_i_muti(self.MAX_VERIFICHE_PRIMA_DELLO_SCARTO - verifiche)
        return rimozioni

    def _confer_complete_profiles(self) -> dict:
        """Conferisce i nodi il cui profilo e' completo, e solo quelli."""
        richieste = set(self._required_stages())
        nodi, porte, sistemi, script, snmp = [], [], [], [], []
        web, smb, vuln = [], [], []
        conferiti = []

        for locale in self.store.local_nodes("confirmed"):
            svolte = set((locale.get("stages_done") or "").split(",")) - {""}
            completo = richieste <= svolte
            # Un host senza porte aperte non completera' mai servizi e sistema operativo:
            # non ha senso attenderli. Se ha un nome o un MAC lo si conferisce cosi'
            # com'e' (presenza in rete); se non ha nulla, lo scarta _drop_without_information.
            if not (completo or self._niente_da_profilare(locale)):
                continue  # profilo incompleto: si attende la fase mancante
            conferito = locale.get("conferred_at")
            fuso = locale.get("last_merge_at")
            if conferito and (not fuso or fuso <= conferito):
                # Nulla di nuovo dall'ultimo conferimento: non si riconferisce.
                continue
            try:
                profilo = json.loads(locale.get("profile_json") or "{}")
            except (TypeError, ValueError):
                self.store.log("warning",
                               "Profilo di %s illeggibile: non conferito" % locale["ip"])
                continue
            if not profilo:
                continue
            if not completo and not self.profile_has_information(profilo):
                # Niente porte e niente informazioni: non e' inventario, lo scarta
                # _drop_without_information invece di conferirlo come nodo vuoto.
                continue

            nodi.append({
                "ip": profilo["ip"],
                "mac": profilo.get("mac"),
                "mac_vendor": profilo.get("mac_vendor"),
                "hostname": profilo.get("hostname"),
                "reachable": bool(profilo.get("reachable", True)),
                "latency_ms": profilo.get("latency_ms"),
                "ttl": profilo.get("ttl"),
                "seen_at": _now_str(),
                # Il profilo e' completo: le porte non riviste possono essere chiuse.
                "ports_examined": True,
                "profile_stages": sorted(svolte),
            })
            porte.extend(profilo.get("ports_index", {}).values())
            if profilo.get("os"):
                sistemi.append(profilo["os"])
            for nome, esito in (profilo.get("scripts") or {}).items():
                script.append({"ip": profilo["ip"], "name": nome, "output": esito})
            # Gli esiti SNMP viaggiano come record propri, con il testo intero: nel
            # profilo generale verrebbero troncati, e cio' che si perde e' proprio
            # l'elenco delle interfacce e del software installato.
            letture = {nome: esito for nome, esito in (profilo.get("scripts") or {}).items()
                       if nome.startswith("snmp-")}
            if letture:
                snmp.append({"ip": profilo["ip"], "scripts": letture,
                             "summary": profilo.get("snmp") or {}})
            # Le enumerazioni SMB viaggiano come record propri, col testo intero: nel
            # profilo generale l'elenco di condivisioni e utenti verrebbe troncato.
            letture_smb = {nome: esito
                           for nome, esito in (profilo.get("scripts") or {}).items()
                           if nome.startswith("smb")}
            if letture_smb:
                smb.append({"ip": profilo["ip"], "scripts": letture_smb,
                            "summary": profilo.get("smb") or {}})
            # I difetti verificati da nmap viaggiano come record propri: sono riscontri
            # di sicurezza, e li applica la Threat Intelligence del server.
            if profilo.get("vuln"):
                vuln.append({"ip": profilo["ip"], "findings": profilo["vuln"]})
            # Le letture web viaggiano come record propri: una pagina per porta, con
            # cio' che dichiara di se'. Nel profilo generale sarebbero troncate.
            if profilo.get("web"):
                web.append({"ip": profilo["ip"], "pages": profilo["web"],
                            "read_at": profilo.get("web_read_at")})
            conferiti.append(locale["ip"])

        rimozioni = self._drop_without_information()
        if not nodi:
            return {"removals": rimozioni} if rimozioni else {}

        for ip in conferiti:
            # Le fasi svolte NON si azzerano: azzerarle rimetterebbe il nodo fra
            # quelli in attesa di profilo, e la scoperta non avanzerebbe piu'. La
            # ri-ispezione e' governata dalle cadenze.
            self.store.upsert_local_node(ip, conferred_at=_now_str())

        self.store.log("info", "Profilo completo per %d dispositivi: conferimento in corso"
                       % len(nodi))
        risultato = {"nodes": nodi}
        if rimozioni:
            risultato["removals"] = rimozioni
        if porte:
            risultato["ports"] = porte
        if sistemi:
            risultato["os"] = sistemi
        if script:
            risultato["scripts"] = script
        if snmp:
            risultato["snmp"] = snmp
        if smb:
            risultato["smb"] = smb
        if vuln:
            risultato["vuln"] = vuln
        if web:
            risultato["web"] = web
        return risultato

    def _still_in_cooldown(self, locale: dict) -> bool:
        """Vero se il nodo e' stato scartato da meno del periodo di attesa."""
        if locale.get("state") != "discarded" or not locale.get("discarded_at"):
            return False
        try:
            quando = datetime.strptime(locale["discarded_at"], "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return False  # istante illeggibile: si riesamina, non si indovina
        trascorso = (datetime.now(timezone.utc) - quando).total_seconds()
        return trascorso < NO_INFORMATION_COOLDOWN_SECONDS

    def _handle_unconfirmed(self, prove: dict) -> None:
        """Gestisce un host che l'esame delle porte non ha confermato.

        Un host che nmap ha ABBANDONATO per scadenza (`--host-timeout`) non e' stato
        esaminato: nell'XML arriva senza porte, ma la sua assenza di informazioni
        misura il nostro tempo, non lui. Contarlo come tentativo -- e al secondo
        scartarlo -- e' il modo piu' rapido di perdere un apparato: sul campo e'
        accaduto a una multifunzione con undici porte aperte, che nmap interrogato da
        solo restituisce in due secondi e mezzo.
        """
        locale = self.store.local_node(prove["ip"])
        if prove.get("timed_out"):
            self._annota_scadenza(prove["ip"], locale)
            return
        tentativi = int((locale or {}).get("attempts") or 0) + 1
        if tentativi < MAX_CANDIDATE_ATTEMPTS:
            self.store.upsert_local_node(prove["ip"], state="candidate", attempts=tentativi)
            return
        self.store.drop_local_node(prove["ip"])
        messaggio = ("Host %s scartato: dichiarato vivo (%s) ma senza alcuna informazione "
                     "dopo %d esami delle porte" % (prove["ip"],
                                                    prove.get("status_reason") or "ping",
                                                    tentativi))
        self.store.log("warning", messaggio)
        self.store.enqueue("event", {
            "type": "probe.node.discarded",
            "severity": "info",
            "description": messaggio,
            "created_at": _now_str(),
            "detail": {"indirizzo": prove["ip"], "tentativi": tentativi,
                       "motivo": prove.get("assessment_reason")},
        })

    def _annota_scadenza(self, ip: str, locale: dict = None) -> None:
        """Registra che nmap ha abbandonato questo host, e lo lascia candidato.

        Il conteggio serve a due decisioni: quando riprovare (attesa progressiva,
        vedi `_scadenza_troppo_recente`) e con quanto tempo, nelle fasi che un tetto
        per host lo ricevono ancora. La fase delle porte non ne riceve piu', quindi
        da la' non arrivano piu' abbandoni per scadenza: nmap conclude il gruppo.
        """
        profilo = {}
        if locale and locale.get("profile_json"):
            try:
                profilo = json.loads(locale["profile_json"]) or {}
            except (TypeError, ValueError):
                profilo = {}
        quante = int(profilo.get("timeout_count") or 0) + 1
        profilo["ip"] = ip
        profilo["timeout_count"] = quante
        profilo["timed_out_at"] = _now_str()

        # NON si scarta, per quante volte scada. Si era provato a rinunciare oltre una
        # soglia, con l'argomento che uno slot occupato da un host muto serve agli
        # host reali: l'argomento sul throughput e' vero, la conclusione era sbagliata.
        # Un host che nmap ha ABBANDONATO per scadenza non e' stato esaminato: e'
        # IGNOTO, non assente. Scartarlo lo fa sparire dall'inventario per un limite
        # nostro -- ed e' esattamente il caso della multifunzione con undici porte
        # aperte, che nmap interrogato da solo restituisce in due secondi e mezzo.
        # Peggio: la scoperta lo ritrova vivo, rientra candidato, scade di nuovo, e il
        # nodo appare e sparisce dalla console.
        #
        # Lo slot occupato E' stato un problema (66 abbandoni consecutivi sugli
        # stessi indirizzi, ondate da 257 s a vuoto): la risposta e' quella scritta
        # qui sopra, DEPRIORITIZZARE. L'attesa e' calcolata da
        # `_scadenza_troppo_recente` e si dichiara nel diario, perche' "riprovato
        # fra sei ore" e "rinunciato" non sono la stessa cosa e chi legge deve
        # distinguerle.
        self.store.upsert_local_node(
            ip, state="candidate",
            profile_json=json.dumps(profilo, ensure_ascii=False))
        attesa = min(ATTESA_RITENTATIVO_BASE_SEC * (2 ** (quante - 1)),
                     ATTESA_RITENTATIVO_TETTO_SEC)
        self.store.log(
            "warning",
            "Host %s: nmap ha abbandonato l'esame per scadenza (%d volta/e). Resta"
            " candidato -- ignoto, non assente -- e verra' riprovato fra %s: con gli"
            " stessi mezzi un tentativo immediato darebbe lo stesso esito e"
            " occuperebbe il posto di un host esaminabile."
            % (ip, quante, _durata_leggibile(attesa)))

    def _node_record(self, prove: dict, ports_examined: bool) -> dict:
        mac = prove.get("mac")
        # `arp` significa OSSERVATO: nmap ha visto la risposta ARP, quindi il nodo e'
        # sullo stesso segmento della sonda. E' l'unica fonte diretta.
        fonte_mac = "arp" if mac else None
        if not mac:
            # Nessun MAC osservato: si guarda se un apparato di rete lo ha RIFERITO
            # (tabella ARP letta in SNMP). E' il solo modo di avere il MAC di un nodo
            # su una subnet instradata -- ARP non attraversa un router.
            #
            # L'ordine conta e non e' arbitrario: cio' che si e' visto vince su cio'
            # che si e' sentito dire. Un MAC riferito da un apparato puo' essere
            # scaduto, il proprio no.
            riferito = snmp_raccolta.mac_per(self.store, prove["ip"])
            if riferito:
                mac = riferito["mac"]
                fonte_mac = "snmp:%s" % riferito["fonte"]
        # Il costruttore della scheda: nmap lo dichiara solo per i MAC che ha visto
        # di persona. Per quelli riferiti da un apparato si ricava dal prefisso, con
        # lo STESSO catalogo che userebbe nmap -- altrimenti il dato piu' utile del
        # MAC (chi ha fatto l'apparato, spesso l'unico indizio su un nodo muto)
        # esisterebbe solo per la subnet della sonda.
        costruttore = prove.get("mac_vendor")
        if mac and not costruttore:
            costruttore = mac_costruttori.costruttore(mac)
        # Dove e' ATTACCATO: la porta fisica si cerca per MAC, perche' la tabella di
        # forwarding di uno switch parla di MAC e non sa nulla di indirizzi IP. Senza
        # MAC non c'e' modo di saperlo, ed e' il motivo per cui i due dati viaggiano
        # insieme: l'uno e' la chiave dell'altro.
        porta = snmp_raccolta.porta_per(self.store, mac) if mac else None
        return {
            "ip": prove["ip"],
            "mac": mac,
            "mac_source": fonte_mac,
            "switch_device": porta["fonte"] if porta else None,
            "switch_port": porta["porta"] if porta else None,
            "mac_vendor": costruttore,
            "hostname": prove.get("hostname"),
            "reachable": bool(prove.get("reachable")),
            "latency_ms": prove.get("latency_ms"),
            "ttl": prove.get("ttl"),
            "seen_at": _now_str(),
            "ports_examined": bool(ports_examined),
        }

    # -- stato per l'interfaccia --------------------------------------------
    def status(self) -> dict:
        capacita = self.store.get_json("nmap_capabilities", {}) or {}
        return {
            "perimeter": self.perimeter(),
            "cadences": self.cadences(),
            "capabilities": capacita,
            "nodes_confirmed": self.store.local_node_count("confirmed"),
            "nodes_candidate": self.store.local_node_count("candidate"),
            "profiles_pending": len(self.pending_nodes()),
            "nodes_conferred": sum(1 for n in self.store.local_nodes("confirmed")
                                   if n.get("conferred_at")),
            "nodes_discarded": self.store.local_node_count("discarded"),
            "subnets_total": len(self.perimeter()),
            "subnets_scanned": len({s["target"] for s in self.store.all_scan_states()
                                    if s["stage"] == "discovery" and s["target"] != "*"}),
            "discovery_days": round(self.cadences()["discovery"] / 86400.0, 1),
            "phases_in_flight": sorted({c["stage"] for c in self.store.active_claims()
                                        if c.get("stage")}),
            "required_stages": list(self._required_stages()),
            "effort": self.effort(),
            "effort_label": EFFORT_PROFILES[self.effort()]["label"],
            # Le scelte con il NUMERO VERO di thread di ciascun profilo. Stavano
            # scritte a mano nella pagina e dicevano 1/2/4 mentre i profili erano
            # diventati 1/16/32: un'etichetta che contraddice la spiegazione due righe
            # sotto e' peggio di nessuna etichetta. Generandole da qui non possono
            # piu' divergere.
            "effort_choices": [
                {"valore": chiave, "thread": voce["workers"],
                 "nome": voce["label"].split(":", 1)[0]}
                for chiave, voce in EFFORT_PROFILES.items()],
            # Quali fasi usano DAVVERO il tempo per host: dalla riprogettazione del
            # motore la fase delle porte non lo riceve piu' (il tetto e' sul processo,
            # calcolato sulle sonde da inviare), e la pagina non deve far credere che
            # quel valore governi la fase piu' lunga.
            "host_timeout_stages": list(STAGES_NEEDING_TIME),
            "host_timeout": self.effort_profile()["host_timeout"],
            "host_timeout_chosen": self.host_timeout(),
            "host_timeout_choices": list(HOST_TIMEOUT_CHOICES),
            "host_timeout_floor": "%ds" % MIN_HOST_TIMEOUT_INSPECTION,
            # Cosa ha chiesto il server: mostrarlo accanto alla scelta locale
            # rende comprensibile una configurazione diversa da quella centrale.
            "effort_from_server": self.store.get_setting("scan_effort_from_server", None),
            "host_timeout_from_server": self.store.get_setting(
                "scan_host_timeout_from_server", None),
            "workers": self.effort_profile()["workers"],
            "max_workers": MAX_WORKERS,
            "running_scans": self.runner.running_count() if hasattr(
                self.runner, "running_count") else 0,
            "running_executions": (self.runner.running_executions()
                                   if hasattr(self.runner, "running_executions") else []),
            "active_claims": len(self.store.active_claims()),
            "scanning_allowed": self.scanning_allowed()[0],
            "suspended_reason": self.scanning_allowed()[1],
            "paused_locally": self.store.get_setting("scan_paused", "0") == "1",
            "enabled_by_server": self.store.get_setting("scan_enabled", "1") == "1",
            "uncertain": len(self._uncertain_nodes()),
            "next_due": self.next_due(),
            "states": self.store.all_scan_states(),
            "hostname": socket.gethostname(),
        }


def _snmp_voci(testo: str) -> int:
    """Conta le voci di un elenco annidato prodotto da nmap.

    Gli script SNMP stampano il nome della voce a un livello di rientro e i suoi
    dettagli a uno piu' profondo: contare tutte le righe rientrate significherebbe
    contare anche indirizzi e MAC. Si contano quindi le sole righe al rientro
    minimo, qualunque esso sia -- il rientro cambia fra le versioni di nmap.
    """
    righe = [r.rstrip() for r in (testo or "").splitlines() if r.strip()]
    if not righe:
        return 0
    # nmap normalizza l'inizio dell'esito togliendo il rientro alla prima riga:
    # quella e' sempre una voce, e il livello delle altre si legge dal resto.
    rientri = [len(r) - len(r.lstrip()) for r in righe[1:]]
    utili = [n for n in rientri if n > 0]
    if not utili:
        return len(righe)  # elenco piatto: ogni riga e' una voce
    minimo = min(utili)
    return 1 + sum(1 for n in rientri if n == minimo)


def snmp_summary(scripts: dict) -> dict:
    """Riassunto leggibile di cio' che SNMP ha raccontato.

    Gli script di nmap restituiscono testo pensato per essere letto da una persona:
    qui se ne estraggono i campi che identificano l'apparato e si contano gli elenchi.
    L'estrazione e' tollerante -- il formato cambia fra versioni di nmap e fra
    apparati -- e cio' che non si riconosce resta comunque nel testo conservato.
    """
    letture = {nome: (esito or "") for nome, esito in (scripts or {}).items()
               if nome.startswith("snmp-")}
    if not letture:
        return {}

    # L'identita' si legge da chi la dichiara. Cercandola nel testo di tutti gli
    # script uniti, il "Name: OS" del primo processo di una stampante diventava il
    # nome del sistema: un dato falso e' peggio di un dato mancante.
    identita = "\n".join(letture.get(nome, "") for nome in
                         ("snmp-sysdescr", "snmp-info"))
    riassunto = {"scripts": sorted(letture)}

    # Descrizione del sistema: e' la riga che identifica l'apparato meglio di
    # qualunque altra prova (modello, versione del firmware, sistema operativo).
    descrizione = (letture.get("snmp-sysdescr") or "").strip()
    if descrizione:
        prima = [r.strip() for r in descrizione.splitlines() if r.strip()]
        if prima:
            riassunto["sysdescr"] = prima[0][:500]

    campi = (
        ("sysname", r"(?:^|\n)\s*(?:System name|sysName)\s*[:=]\s*(.+)"),
        ("uptime", r"(?:^|\n)\s*(?:System uptime|Uptime)\s*[:=]\s*(.+)"),
        ("contact", r"(?:^|\n)\s*(?:Contact|sysContact)\s*[:=]\s*(.+)"),
        ("location", r"(?:^|\n)\s*(?:Location|sysLocation)\s*[:=]\s*(.+)"),
        ("enterprise", r"(?:^|\n)\s*(?:enterprise)\s*[:=]\s*(.+)"),
        ("engine_id", r"(?:^|\n)\s*(?:snmpEngineID|engineIDData)\s*[:=]\s*(.+)"),
    )
    for chiave, espressione in campi:
        trovato = re.search(espressione, identita, re.I)
        if trovato:
            riassunto[chiave] = trovato.group(1).strip()[:200]

    # Gli elenchi si contano: il testo intero resta negli esiti conservati.
    # Dove le voci sono annidate (interfacce, condivisioni, utenti, servizi) si
    # contano le righe di primo livello; dove sono piatte basta un'espressione.
    annidati = {
        "interfacce": "snmp-interfaces",
        "condivisioni": "snmp-win32-shares",
        "utenti": "snmp-win32-users",
        "servizi": "snmp-win32-services",
    }
    for etichetta, nome in annidati.items():
        quante = _snmp_voci(letture.get(nome, ""))
        if quante:
            riassunto[etichetta] = quante

    piatti = {
        # nmap scrive "1: " (numero, due punti) e "TCP  0.0.0.0:80": le espressioni
        # precedenti pretendevano uno spazio dopo il numero e un indirizzo a inizio
        # riga, e non contavano nulla.
        "processi": ("snmp-processes", r"^\s*\d+\s*[:.]"),
        "software": ("snmp-win32-software", r"^\s*\S.+;"),
        "connessioni": ("snmp-netstat", r"^\s*(?:TCP|UDP)\s+\S+:\d+"),
    }
    for etichetta, (nome, espressione) in piatti.items():
        testo = letture.get(nome)
        if not testo:
            continue
        quante = len([r for r in testo.splitlines() if re.match(espressione, r)])
        if quante:
            riassunto[etichetta] = quante

    # La community con cui si e' ottenuta la risposta e' essa stessa un riscontro:
    # se e' quella di fabbrica, l'apparato racconta tutto a chiunque.
    riassunto["community"] = SNMP_COMMUNITIES.split(",")[0]
    return riassunto


def _voci_livello_zero(testo: str, salta_prefissi: tuple = ()) -> int:
    """Conta le voci di primo livello di un elenco annidato di nmap.

    smb-enum-shares e smb-enum-users stampano la voce -- una condivisione, un utente --
    a inizio riga (rientro zero) e i suoi dettagli rientrati sotto. Si contano quindi
    le righe NON rientrate, saltando le intestazioni note (per esempio la riga
    "account_used:" di smb-enum-shares, che non e' una condivisione).
    """
    # nmap, quando lo script fallisce (host che nega l'enumerazione anonima), mette
    # una riga "ERROR: ...": non e' una voce e non va contata.
    salti = tuple(salta_prefissi) + ("error:", "error ", "false", "smb:")
    quante = 0
    for riga in (testo or "").splitlines():
        if not riga.strip() or riga[:1].isspace():
            continue
        testa = riga.strip().lower()
        if any(testa.startswith(prefisso) for prefisso in salti):
            continue
        quante += 1
    return quante

def smb_summary(scripts: dict) -> dict:
    """Riassunto leggibile di cio' che SMB ha raccontato di una macchina Windows.

    Estrae da smb-os-discovery i campi d'identita' (sistema operativo, nome del
    computer, dominio, FQDN), conta le condivisioni e le utenze, e legge dallo
    smb-security-mode se la firma dei messaggi e' richiesta. L'estrazione e'
    tollerante: il formato cambia fra le versioni di nmap, e cio' che non si riconosce
    resta comunque nel testo conservato.
    """
    letture = {nome: (esito or "") for nome, esito in (scripts or {}).items()
               if nome.startswith("smb")}
    if not letture:
        return {}

    riassunto = {"scripts": sorted(letture)}
    os_discovery = letture.get("smb-os-discovery", "")
    inizio = r"(?:^|\n)\s*"
    campi = (
        ("os", inizio + r"OS\s*:\s*(.+)"),
        ("computer_name", inizio + r"Computer name\s*:\s*(.+)"),
        ("netbios_name", inizio + r"NetBIOS computer name\s*:\s*(.+)"),
        ("domain", inizio + r"Domain name\s*:\s*(.+)"),
        ("forest", inizio + r"Forest name\s*:\s*(.+)"),
        ("fqdn", inizio + r"FQDN\s*:\s*(.+)"),
        ("system_time", inizio + r"System time\s*:\s*(.+)"),
    )
    for chiave, espressione in campi:
        trovato = re.search(espressione, os_discovery, re.I)
        if trovato:
            # nmap conclude alcune righe con la sequenza letterale "\x00" (il
            # terminatore NetBIOS): non e' parte del nome e va tolta.
            valore = re.sub(r"(?:\\x00)+$", "", trovato.group(1).strip()).strip()
            if valore and valore.lower() not in ("unknown", "<unknown>", "n/a"):
                riassunto[chiave] = valore[:200]

    condivisioni = _voci_livello_zero(letture.get("smb-enum-shares", ""),
                                      salta_prefissi=("account_used",))
    if condivisioni:
        riassunto["condivisioni"] = condivisioni

    utenti = _voci_livello_zero(letture.get("smb-enum-users", ""))
    if utenti:
        riassunto["utenti"] = utenti

    # La firma dei messaggi: "supported" significa disponibile ma NON obbligatoria,
    # quindi ancora esposta al relay -- va trattata come "non richiesta". Solo
    # "required"/"enabled" e' una firma imposta. Si guarda sia SMB1 sia SMB2.
    firma = (letture.get("smb-security-mode", "") + "\n"
             + letture.get("smb2-security-mode", ""))
    if re.search(r"message_signing\s*:\s*(required|enabled)", firma, re.I):
        riassunto["firma_messaggi"] = "richiesta"
    elif re.search(r"(?:Message signing (?:enabled and )?required)", firma, re.I):
        riassunto["firma_messaggi"] = "richiesta"
    elif re.search(r"message_signing\s*:\s*(disabled|not required|supported)", firma,
                   re.I) or re.search(r"Message signing (?:enabled )?but not required",
                                      firma, re.I):
        riassunto["firma_messaggi"] = "non richiesta"

    # Dialetti SMB supportati: la presenza di SMBv1 (NT LM 0.12 / SMBv1) e' essa stessa
    # un riscontro di sicurezza -- e' il protocollo di WannaCry, disabilitato per
    # difetto sui sistemi recenti.
    protocolli = letture.get("smb-protocols", "")
    dialetti = re.findall(
        r"(?:^|\n)\s*(NT LM 0\.12|SMBv[123]|[0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        protocolli)
    if dialetti:
        riassunto["dialetti_smb"] = ", ".join(dict.fromkeys(dialetti))
    if re.search(r"NT LM 0\.12|SMBv1", protocolli, re.I):
        riassunto["smbv1"] = True

    return riassunto


# --------------------------------------------------------------------------- #
# Ricerca di vulnerabilita': interpretazione dell'esito degli script nmap
# --------------------------------------------------------------------------- #
# Uno script di vulnerabilita' dichiara un verdetto ("State: VULNERABLE") e, quando li
# ha, gli identificativi CVE. Si estraggono verdetto, titolo, gravita' e CVE; cio' che
# non e' vulnerabile non produce un riscontro.
_STATO_VULN = re.compile(r"State:\s*(LIKELY VULNERABLE|VULNERABLE)", re.I)
_CVE = re.compile(r"CVE[-:]?\s*(CVE-\d{4}-\d{4,7})", re.I)
_CVE_SEMPLICE = re.compile(r"(CVE-\d{4}-\d{4,7})", re.I)
_RISCHIO = re.compile(r"Risk factor:\s*(\w+)", re.I)


def vuln_findings(scripts: dict) -> list:
    """I difetti verificati da nmap, uno per script che ha dato esito vulnerabile.

    Interpreta l'esito degli script di vulnerabilita': verdetto, titolo, gravita' e
    identificativi CVE. Non solleva -- il formato cambia fra le versioni di nmap -- e
    cio' che non risulta vulnerabile non produce un riscontro.
    """
    trovati = []
    for nome, esito in (scripts or {}).items():
        testo = esito or ""
        # Un difetto solo dove nmap dichiara un verdetto vulnerabile. "NOT VULNERABLE"
        # non lo e': l'espressione richiede la parola VULNERABLE preceduta da "State:".
        stato = _STATO_VULN.search(testo)
        if not stato and "VULNERABLE:" not in testo:
            continue
        if not stato and re.search(r"NOT VULNERABLE", testo, re.I):
            continue
        verdetto = (stato.group(1).upper() if stato else "VULNERABLE")

        # Titolo: la prima riga con contenuto dopo "VULNERABLE:", o il nome dello script.
        titolo = nome
        marcatore = re.search(r"VULNERABLE:\s*\n(\s*)(.+)", testo)
        if marcatore:
            titolo = marcatore.group(2).strip()
        else:
            prima = [r.strip() for r in testo.splitlines() if r.strip()]
            if prima:
                titolo = prima[0].rstrip(":").strip()

        cves = _CVE.findall(testo) or _CVE_SEMPLICE.findall(testo)
        cves = [c.upper() for c in dict.fromkeys(cves)]

        rischio = _RISCHIO.search(testo)
        gravita = _gravita_da_rischio(rischio.group(1) if rischio else "",
                                      "LIKELY" in verdetto)

        trovati.append({
            "script": nome,
            "state": "likely" if "LIKELY" in verdetto else "confirmed",
            "title": titolo[:300],
            "cves": cves,
            "severity": gravita,
        })
    return trovati


def _gravita_da_rischio(rischio: str, incerto: bool) -> str:
    """Traduce il "Risk factor" di nmap nella scala di gravita' del prodotto."""
    r = (rischio or "").lower()
    if incerto:
        return "medium"
    if "critical" in r:
        return "critical"
    if "high" in r:
        return "high"
    if "medium" in r or "moderate" in r:
        return "medium"
    if "low" in r:
        return "low"
    # Un difetto verificato senza gravita' dichiarata resta alto: nmap segnala i gravi.
    return "high"
