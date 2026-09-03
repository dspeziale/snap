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
import re
import socket
import time
import uuid
from datetime import datetime, timezone

from . import nmap_xml
from .nmap_runner import NmapAborted, NmapError, NmapRunner, NmapTimeout

# Fasi nell'ordine di priorita' con cui vengono valutate.
STAGES = ("discovery", "monitor", "ports", "services", "os", "deep", "snmp", "smb",
          "vuln", "web")

# Fasi che compongono il profilo di un dispositivo. Il nodo viene conferito solo
# quando tutte quelle applicabili sono state eseguite su di esso: il server
# riceve dispositivi interi, non frammenti.
PROFILE_STAGES = ("ports", "services", "os")

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
    "ports": 21600,
    "services": 43200,
    "os": 259200,
    "deep": 604800,
    "monitor": 120,
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

# Quante volte un host puo' essere ABBANDONATO da nmap per scadenza prima di
# rinunciare. Un host che scade viene riprovato con piu' tempo (fino a 300s), ma
# oltre questa soglia non e' piu' "lento": non risponde come nmap si aspetta, e
# insistere ruberebbe ogni ciclo agli host reali -- sul campo un host e' stato
# abbandonato oltre 600 volte, tenendo occupato uno slot per ore senza produrre
# nulla. Superata la soglia il candidato si scarta (verra' riscoperto se torna
# vivo) e la fase di un nodo confermato si segna "tentata", cosi' la frontiera
# avanza sempre e non resta mai bloccata su chi non risponde.
MAX_TIMEOUT_ABANDONMENTS = 6

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
MAX_HOSTGROUP = 64

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
#   top_ports          quante porte fra le piu' comuni
#   version_intensity  insistenza del riconoscimento dei servizi
#   host_timeout       tempo massimo per host
#   hosts_per_task     nodi affidati a un singolo compito
#   udp_ports          porte UDP interrogate nella fase di approfondimento
EFFORT_PROFILES = {
    "min": {
        "workers": 1, "timing": "-T2", "top_ports": 100, "version_intensity": 2,
        "host_timeout": "60s", "hosts_per_task": 8, "udp_ports": "161,137",
        "label": "minimo: una scansione per volta, rete poco disturbata",
    },
    "med": {
        "workers": 2, "timing": "-T3", "top_ports": 200, "version_intensity": 5,
        "host_timeout": "120s", "hosts_per_task": 16, "udp_ports": UDP_IDENTIFYING_PORTS,
        "label": "medio: due scansioni in parallelo, equilibrio fra velocita e prudenza",
    },
    "max": {
        "workers": 4, "timing": "-T4", "top_ports": 1000, "version_intensity": 7,
        "host_timeout": "180s", "hosts_per_task": 24, "udp_ports": UDP_IDENTIFYING_PORTS,
        "label": "massimo: quattro scansioni in parallelo, inventario piu ricco e rapido",
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
# Le fasi di COMPLETAMENTO del profilo (servizi, sistema operativo) hanno un floor piu'
# basso. Sono la frontiera che porta migliaia di nodi al conferimento e, dopo una sola
# scadenza, la fase si segna "tentata": il nodo si conferisce con cio' che ha (le porte
# le ha gia' dalla fase 'ports'). Non conviene insistere a lungo su un host che non
# risponde a -sV: uno reattivo risponde molto prima, uno lento verrebbe abbandonato
# comunque -- e il floor pieno teneva ferma tutta la frontiera (una passata servizi da
# 24 host richiedeva ~470s, uno solo per ciclo). Le letture di arricchimento (SNMP, SMB,
# vulnerabilita', approfondimento) mantengono invece il floor pieno: sono poche per giro
# e i loro script hanno bisogno di tempo. La perdita e' recuperabile: la ri-ispezione
# rivede i nodi conferiti quando la frontiera si e' svuotata.
MIN_HOST_TIMEOUT_PROFILE = 90
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
# Limite invalicabile, indipendente dal profilo: quattro processi nmap sono il
# massimo che si accetta di avere contemporaneamente su una sonda.
MAX_WORKERS = 4

# Le prenotazioni scadute vengono liberate: se un thread muore senza rilasciare,
# il bersaglio non deve restare bloccato.
CLAIM_MAX_AGE_SECONDS = 1800


def _now_str() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")


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
        """Fasi necessarie a dichiarare completo il profilo di un dispositivo."""
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
            # Un host che ha gia' fatto 'ports' senza trovare porte aperte non ha piu'
            # nulla da profilare: servizi, sistema operativo e approfondimento lavorano
            # tutti sulle porte. Metterlo in coda per quelle fasi e' tempo sprecato -- su
            # una rete reale sono migliaia gli host che rispondono al solo ping -- e viene
            # invece conferito o scartato subito dopo 'ports'.
            if stage not in ("discovery", "ports") and self._niente_da_profilare(nodo):
                continue
            if stage not in svolte and precedenti <= svolte:
                attesa.append(nodo)
        # Il filtro del perimetro sta qui perche' questo e' l'unico punto da cui i
        # nodi da profilare provengono: pianificazione del pool, console e conteggio
        # dell'interfaccia. Un nodo non scansionabile non e' lavoro in attesa.
        if stage is None:
            return attesa
        return self._within_perimeter_only(attesa, stage)

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
        return [n["ip"] for n in self._within_perimeter_only(nodi, stage)
                ][:self.effort_profile()["hosts_per_task"]]

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
            # Senza porte note si sondano le prime porte per frequenza: l'elenco
            # esplicito serve perche' --top-ports non si combina con -p.
            tcp = "1-%d" % int(profilo["top_ports"])
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

        Le porte note prevalgono sulle prime porte per frequenza: sono poche, sono
        quelle che hanno risposto, e permettono di concludere entro il tempo per
        host. Senza porte note si torna alle prime porte.
        """
        note = self._known_open_ports(hosts)
        if note and len(note) <= MAX_EXPLICIT_PORTS:
            return ["-p", ",".join(str(p) for p in note)]
        return ["--top-ports", str(profilo["top_ports"])]

    def _hostgroup(self, hosts: list = None) -> str:
        """Quanti host far scansionare a nmap in parallelo: tutti quelli del compito,
        entro un tetto. E' cio' che rende una passata lunga quanto il singolo host e
        non la somma dei suoi host lenti."""
        return str(max(1, min(len(hosts or []) or 1, MAX_HOSTGROUP)))

    def _arguments_for(self, stage: str, capacita: dict, profilo: dict = None,
                       hosts: list = None) -> list:
        """Argomenti di nmap per una fase, secondo il profilo di sforzo."""
        raw = bool(capacita.get("raw_sockets"))
        profilo = profilo or self.effort_profile()
        timing = profilo["timing"]
        porte = str(profilo["top_ports"])
        attesa = self._host_timeout_for(stage, profilo, hosts)

        if stage == "discovery":
            # La scoperta conserva il proprio tempo breve anche quando se ne
            # sceglie uno piu' lungo: e' uno sweep su tutta la subnet, e un tempo
            # per host lungo si moltiplicherebbe per ogni indirizzo morto.
            return ["-sn", "-PE", "-PS22,80,443,3389,445", "-PA80", "-PR", timing,
                    "--host-timeout", "20s"]
        if stage == "ports":
            return [("-sS" if raw else "-sT"), "-Pn", timing, "--top-ports", porte,
                    "--host-timeout", attesa]
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
            script = "banner," + ENRICHMENT_SCRIPTS
            if snmp:
                script = script + "," + SNMP_SCRIPTS
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

    def _process_timeout(self, stage: str, hosts: int, profilo: dict) -> int:
        """Tempo massimo del processo nmap per un compito.

        Le fasi di ispezione usano `--min-hostgroup` per scansionare TUTTI gli host del
        gruppo in parallelo: il tempo reale e' quello del singolo host, non la somma.
        Moltiplicare per il numero di host (com'era prima) portava il limite a migliaia
        di secondi -- sul campo una passata di servizi su host VoIP che appendono nmap
        ha tenuto un ciclo bloccato per ore, e senza che la task si concludesse il
        "give-up" per fase non scattava mai. Un fattore piccolo e fisso basta: da'
        margine per l'avvio e per qualche host che nmap serializza, senza consentire a
        un solo compito di bloccare tutto.
        """
        per_host = parse_timeout(self._host_timeout_for(stage, profilo)) or 120
        # Sia lo sweep (discovery/monitor) sia le ispezioni scansionano in parallelo:
        # il ceiling e' un multiplo del tempo per host, non del numero di bersagli.
        stimato = per_host * 4
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
        # Il floor dipende dalla fase: piu' basso per il completamento del profilo
        # (servizi, sistema operativo), pieno per le letture di arricchimento.
        if stage in STAGES_PROFILE_COMPLETION:
            if secondi < MIN_HOST_TIMEOUT_PROFILE:
                secondi = MIN_HOST_TIMEOUT_PROFILE
        elif stage in STAGES_NEEDING_TIME and secondi < MIN_HOST_TIMEOUT_INSPECTION:
            secondi = MIN_HOST_TIMEOUT_INSPECTION

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
        cadenze = self.cadences()
        compiti = []
        assegnati = set()

        def aggiungi_nodi(fase, nodi):
            """Spezza i nodi in compiti da `per_compito`, senza ripetere indirizzi."""
            gruppo = []
            for nodo in nodi:
                if len(compiti) >= limite:
                    break
                if nodo["ip"] in assegnati:
                    continue
                gruppo.append(nodo["ip"])
                assegnati.add(nodo["ip"])
                if len(gruppo) >= per_compito:
                    compiti.append({"stage": fase, "target": "*", "hosts": list(gruppo)})
                    gruppo = []
            if gruppo and len(compiti) < limite:
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
        if len(compiti) < limite:
            porte_attesa = [n for n in self.pending_nodes("ports")
                            if n["ip"] not in assegnati]
            if porte_attesa:
                aggiungi_un_compito("ports", porte_attesa)

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
            molti = sum(len(v) for v in pendenti.values()) > per_compito
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
                while completa and len(compiti) < limite:
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
        for fase, mai_lette in (("snmp", self._snmp_pending),
                                ("smb", self._smb_pending),
                                ("vuln", self._vuln_pending),
                                ("web", self._web_pending)):
            if len(compiti) >= limite:
                break
            if fase not in self._required_stages() and fase not in ("web", "smb", "vuln"):
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
            if len(compiti) >= limite:
                break
            aggiungi_nodi(fase, self.pending_nodes(fase))

        # 3. Altre subnet da scoprire, se restano posti.
        for cidr in da_scoprire[1:]:
            if len(compiti) >= limite:
                break
            compiti.append({"stage": "discovery", "target": cidr, "hosts": [cidr]})

        # 3. Sorvegliare i nodi gia' noti al server.
        if len(compiti) < limite and self._due("*", "monitor", cadenze["monitor"]):
            noti = self._within_perimeter_only(
                [n for n in self.store.local_nodes("confirmed")
                 if n.get("conferred_at") and n["ip"] not in assegnati], "monitor")
            if noti:
                aggiungi_nodi("monitor", noti)

        # 4. Leggere SNMP dove la porta e' aperta. Prima della ri-ispezione, non
        #    dopo: la ri-ispezione prende per se' tutti i nodi confermati e un
        #    indirizzo non puo' stare in due compiti dello stesso ciclo, quindi
        #    dopo di essa la lettura SNMP non arriverebbe mai al proprio turno.
        #    SNMP riguarda pochi nodi, ha cadenza di mezza giornata e racconta
        #    dell'apparato piu' di una ri-lettura delle porte.
        if len(compiti) < limite and (self._snmp_pending()
                                      or self._due("*", "snmp", cadenze["snmp"])):
            aggiungi_nodi("snmp", [n for n in (self._snmp_pending()
                                               or self._snmp_nodes())
                                   if n["ip"] not in assegnati])

        # 4-bis. Enumerare SMB, con la stessa ragione della lettura SNMP: prima
        #    della ri-ispezione, altrimenti non arriverebbe mai al proprio turno.
        #    Prima i nodi mai letti.
        if len(compiti) < limite and (self._smb_pending()
                                      or self._due("*", "smb", cadenze["smb"])):
            aggiungi_nodi("smb", [n for n in (self._smb_pending() or self._smb_nodes())
                                  if n["ip"] not in assegnati])

        # 4-quater. Cercare le vulnerabilita', con la stessa ragione: prima della
        #    ri-ispezione. Prima i nodi mai verificati.
        if len(compiti) < limite and (self._vuln_pending()
                                      or self._due("*", "vuln", cadenze["vuln"])):
            aggiungi_nodi("vuln", [n for n in (self._vuln_pending() or self._vuln_nodes())
                                   if n["ip"] not in assegnati])

        # 4-ter. Leggere le pagine di gestione, con la stessa ragione della
        #    lettura SNMP: prima della ri-ispezione, altrimenti non arriverebbe mai
        #    al proprio turno. Prima i nodi mai letti.
        if len(compiti) < limite and (self._web_pending()
                                      or self._due("*", "web", cadenze["web"])):
            aggiungi_nodi("web", [n for n in (self._web_pending() or self._web_nodes())
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
        attesa_processo = self._process_timeout(stage, len(bersagli), profilo)
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
            return self._records_discovery(letto, claimed)
        if stage == "monitor":
            return self._records_monitor(letto, hosts or [], alive_extra or {})
        return self._records_inspection(letto, stage, hosts or [])

    def _records_discovery(self, letto: dict, claimed=None) -> dict:
        """La scoperta conferisce i nodi con prove; i nudi restano candidati.

        Gli indirizzi prenotati da un altro compito del ciclo vengono ignorati:
        li sta esaminando qualcun altro e non va toccato il loro stato.
        """
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
        if bersagli and stage not in ("discovery", "ports"):
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

    def _drop_without_information(self) -> list:
        """Scarta i nodi che, esaurite tutte le fasi, non portano informazioni.

        Restituisce i record di rimozione da conferire: la decisione e' della
        sonda, che sa quali fasi ha svolto, ma l'inventario e' del server, che la
        applica solo dopo aver verificato di non avere dati propri sul nodo.
        """
        rimozioni = []
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

            adesso = _now_str()
            self.store.upsert_local_node(locale["ip"], state="discarded",
                                         discarded_at=adesso)
            motivo = ("nessuna informazione dopo le fasi %s: nessuna porta aperta, "
                      "nessun sistema operativo, nessun nome host, nessun banner"
                      % ", ".join(sorted(svolte)))
            rimozioni.append({"ip": locale["ip"], "reason": motivo,
                              "stages": sorted(svolte), "decided_at": adesso})
            self.store.log("info", "Nodo %s scartato: %s" % (locale["ip"], motivo))
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

        Il conteggio serve alla decisione successiva: un host che scade due volte va
        esaminato con piu' tempo, non riprovato con lo stesso.
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

        # Oltre la soglia si rinuncia: un host abbandonato tante volte non e' lento,
        # non risponde, e continuare a riprovarlo tiene occupato uno slot che serve
        # agli host reali. Si scarta con un periodo di attesa (come un host senza
        # informazioni): lo stato "discarded" con la data attiva il cooldown, cosi'
        # la scoperta non lo ripesca subito. Se torna a rispondere, lo ritrovera' dopo.
        if quante >= MAX_TIMEOUT_ABANDONMENTS:
            adesso = _now_str()
            profilo["giveup_reason"] = "timeout_ripetuti"
            self.store.upsert_local_node(
                ip, state="discarded", discarded_at=adesso,
                profile_json=json.dumps(profilo, ensure_ascii=False))
            messaggio = ("Host %s scartato: nmap lo ha abbandonato per scadenza %d volte "
                         "di seguito senza mai completarlo. Se torna a rispondere verra' "
                         "riscoperto." % (ip, quante))
            self.store.log("warning", messaggio)
            self.store.enqueue("event", {
                "type": "probe.node.discarded",
                "severity": "info",
                "description": messaggio,
                "created_at": adesso,
                "detail": {"indirizzo": ip, "motivo": "scadenze ripetute",
                           "scadenze": quante},
            })
            return

        self.store.upsert_local_node(
            ip, state="candidate",
            profile_json=json.dumps(profilo, ensure_ascii=False))
        self.store.log(
            "warning",
            "Host %s: nmap ha abbandonato l'esame per scadenza (%d volta/e su %d). Il"
            " tentativo non conta e l'host resta candidato: la prossima volta avra'"
            " piu' tempo." % (ip, quante, MAX_TIMEOUT_ABANDONMENTS))

    def _node_record(self, prove: dict, ports_examined: bool) -> dict:
        return {
            "ip": prove["ip"],
            "mac": prove.get("mac"),
            "mac_vendor": prove.get("mac_vendor"),
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
