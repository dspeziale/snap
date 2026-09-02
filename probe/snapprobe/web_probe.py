"""
snap probe - Lettura delle interfacce web dei dispositivi.

Perche' esiste: su una rete reale la meta' degli apparati non dice nulla di se'
sulle porte TCP -- una 443 aperta e' una 443 aperta -- ma serve una pagina che si
presenta da sola. "HP LaserJet MFP M428", "Synology DiskStation", "FortiGate",
"iDRAC9", "Grafana v10.2.3": e' la fonte piu' esplicita che esista dopo SNMP, ed e'
gia' pubblicata a chiunque apra un browser.

Che cosa fa, esattamente:

* una **richiesta GET** alla radice, con al massimo due redirezioni e solo verso lo
  stesso indirizzo. Nessun tentativo di autenticazione, nessun POST, nessuna
  ricerca di percorsi: un inventario legge il cartello sulla porta, non prova le
  chiavi;
* per HTTPS legge anche il **certificato** (nome, emittente, scadenza): un
  certificato dice il nome dell'apparato piu' spesso della pagina, e la sua
  scadenza e' un dato operativo che nessun'altra fase raccoglie;
* dal contenuto ricava **titolo, prodotto, versione, marca e tipo probabile** con un
  catalogo di firme dichiarate. Prodotto e versione sono cio' che rende una
  vulnerabilita' attribuibile a un'istanza (docs/10, TI-17): trovarli qui vale piu'
  di dieci porte aperte.

Che cosa NON fa, e perche':

* **non conserva il corpo della pagina.** Una pagina interna puo' contenere nomi,
  indirizzi di posta, numeri di telefono: dati personali di cui questo prodotto non
  ha bisogno (GDPR art. 5, minimizzazione). Si conservano i campi estratti, la loro
  lunghezza e un'impronta del contenuto -- che basta per accorgersi che la pagina e'
  cambiata;
* **non verifica la validita' del certificato per decidere se proseguire**: nelle
  reti interne il certificato autofirmato e' la norma, e rifiutarlo significherebbe
  non leggere nulla. L'esito della verifica viene comunque registrato, perche' e'
  un'informazione;
* **non segue redirezioni verso altri host**: se un apparato rimanda al portale del
  fornitore, quel portale non e' il dispositivo e non e' nel perimetro.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import hashlib
import re
import time
import socket
import ssl
from datetime import datetime, timezone
from html import unescape
from urllib.parse import urlsplit

# Porte che valgono la pena di una lettura. Non e' un elenco di "porte web" in
# generale: sono quelle su cui, su reti reali, si trova un'interfaccia di gestione.
# La lettura avviene solo dove la porta risulta APERTA, quindi un elenco piu' lungo
# non costa scansioni: costa solo righe qui.
PORTE_HTTP = (80, 8080, 8000, 8008, 8081, 8088, 8888, 3000, 5000, 7080, 9090, 10000)
PORTE_HTTPS = (443, 8443, 4443, 9443, 10443, 8834, 7443)

# Byte letti al massimo dal corpo. Una pagina di gestione utile sta in pochi kB;
# oltre questa soglia si tratta di un'applicazione, e cio' che serve
# all'identificazione e' comunque nella parte iniziale.
MAX_BYTE_CORPO = 65536
# Tempi: due secondi per connettersi, tre per leggere. Su una passata di centinaia
# di nodi la somma dei timeout e' il costo dominante, e un apparato che non risponde
# in due secondi sulla propria pagina di gestione non risponderebbe nemmeno dopo.
TIMEOUT_CONNESSIONE = 2.0
TIMEOUT_LETTURA = 5.0   # le pagine di stato degli apparati sono lente: la
                        # multifunzione che ha guidato il lavoro impiega 1-4 s
                        # per comporre la propria pagina di informazioni
MAX_REDIREZIONI = 4
# Pagine lette su una singola porta, comprese le redirezioni: la radice di un apparato
# spesso non contiene niente e cio' che serve sta due o tre passi dentro. Il tetto
# esiste perche' una passata riguarda centinaia di indirizzi.
MAX_PAGINE_PER_PORTA = 5
# Tempo massimo speso su una porta, in secondi. E' il vincolo che conta davvero: cinque
# pagine su un apparato lento costerebbero quindici secondi, e moltiplicati per
# duemila dispositivi la passata non chiuderebbe piu'.
BUDGET_SECONDI_PORTA = 12.0
# Profondita' oltre la quale si provano anche i collegamenti "informazioni/stato": si
# fa solo se i fatti mancano ancora, perche' e' un tentativo, non una certezza.
PROFONDITA_ANCORE = 1

# Quanto si conserva di ciascun campo estratto: sono etichette, non documenti.
MAX_TESTO = 300


# --------------------------------------------------------------------------- #
# Catalogo delle firme
# --------------------------------------------------------------------------- #
# Ogni firma dichiara dove cercare e cosa se ne deduce. `dove` puo' essere:
#   titolo, server, generator, intestazioni, corpo, certificato, realm
# `versione` e' un'espressione con un gruppo: se corrisponde, la versione entra nel
# risultato ed e' quella che rende attribuibile una vulnerabilita'.
#
# L'ordine conta: la prima firma che corrisponde vince, quindi le piu' specifiche
# stanno prima delle generiche (un server "Apache" su una stampante HP e' una
# stampante HP, non un server Apache).
FIRME = [
    # --- stampanti multifunzione ---
    {"chiave": "hp-printer", "dove": ("titolo", "corpo", "certificato"),
     "espressione": r"(?i)\b(laserjet|officejet|deskjet|designjet|pagewide|hp\s+color\s+laser)",
     "marca": "HP", "tipo": "printer", "prodotto": "HP LaserJet/OfficeJet",
     "modello": r"(?i)((?:laserjet|officejet|deskjet|designjet|pagewide)[\w\s\-\.]{0,24})",
     # Endpoint di sola lettura del firmware HP: risponde in XML con modello e
     # numero di serie, senza credenziali.
     "percorsi": ("/DevMgmt/ProductConfigDyn.xml",
                  "/hp/device/DeviceStatus/Index")},
    {"chiave": "kyocera", "dove": ("titolo", "corpo"), "espressione": r"(?i)kyocera|taskalfa|ecosys",
     "marca": "Kyocera", "tipo": "printer", "prodotto": "Kyocera",
     "modello": r"(?i)((?:taskalfa|ecosys)[\w\s\-]{0,20})"},
    # --- generi riconoscibili anche senza marca ---
    # Sulla rete reale una ventina di apparati si presenta come "IP Phone" e
    # nient'altro: la pagina di stato chiede le credenziali, che non abbiamo. La marca
    # resta ignota, ma il genere no -- e per un inventario e' cio' che conta di piu'.
    # Telefoni IP Cisco Unified (79xx e successivi). La radice e' un menu HTML che si
    # presenta da solo ("Cisco Unified IP Phone CP-7962G ( SEP... )") e rimanda a due
    # endpoint XML di sola lettura -- /NetworkConfigurationX e /DeviceInformationX --
    # che dichiarano una montagna di dati tecnici: MAC, nome host, interno, carichi
    # software e di avvio, revisione hardware, numero di serie, modello, gestore
    # chiamate e server TFTP. Sta prima della firma generica "cisco" (che sarebbe uno
    # switch) e della "telefono-ip" (che non darebbe la marca). I percorsi si leggono
    # nell'ordine dato: prima la configurazione di rete, che da sola non e' "abbastanza"
    # e non ferma la navigazione, poi le informazioni del dispositivo che la completano
    # -- cosi' entrambe le pagine vengono lette.
    # `voip_phone` e' la chiave esatta della classe nel catalogo del riconoscimento
    # (fingerprint): dichiararla qui fa scattare la regola decisiva, e il nodo si
    # classifica come "Telefono VoIP" citando marca e modello letti dalla pagina.
    {"chiave": "cisco-ip-phone", "dove": ("titolo", "corpo", "fatti"),
     "espressione": r"(?i)cisco[\s\S]{0,40}ip phone|\bCP-\d{3,4}[A-Z]{0,2}\b"
                    r"|\bSEP[0-9A-F]{12}\b",
     "marca": "Cisco", "tipo": "voip_phone", "prodotto": "Cisco Unified IP Phone",
     "modello": r"(?i)(CP-\d{3,4}[A-Z]{0,2})",
     "percorsi": ("/NetworkConfigurationX", "/DeviceInformationX")},
    {"chiave": "telefono-ip", "dove": ("titolo", "server", "intestazioni"),
     "espressione": r"(?i)\bip[ -]?phone\b|\bvoip\b|\bsip phone\b"
                    r"|phone web (?:user )?interface|telefono ip",
     "tipo": "voip", "prodotto": "telefono IP (marca non dichiarata)"},

    {"chiave": "ricoh", "dove": ("titolo", "corpo", "fatti"),
     # "Web Image Monitor" e' il nome della console web di tutte le Ricoh (e dei
     # marchi del gruppo): compare nel titolo anche quando la marca non c'e'.
     "espressione": r"(?i)\bricoh\b|aficio|web image monitor|\blanier\b|\bsavin\b"
                    r"|nashuatec|gestetner",
     "marca": "Ricoh", "tipo": "printer", "prodotto": "Ricoh (Web Image Monitor)",
     "modello": r"(?i)((?:MP|IM|SP|Pro)\s?C?\d{3,4}[A-Za-z]{0,3})",
     # La console Ricoh esiste in piu' lingue: la pagina italiana e quella inglese
     # sono lo stesso documento, e almeno una delle due risponde.
     "percorsi": ("/web/guest/it/websys/webArch/topPage.cgi",
                  "/web/guest/en/websys/webArch/topPage.cgi")},
    {"chiave": "canon", "dove": ("titolo", "corpo"), "espressione": r"(?i)\bcanon\b|imagerunner|imageclass",
     "marca": "Canon", "tipo": "printer", "prodotto": "Canon"},
    {"chiave": "epson", "dove": ("titolo", "corpo"), "espressione": r"(?i)\bepson\b|workforce|ecotank",
     "marca": "Epson", "tipo": "printer", "prodotto": "Epson"},
    {"chiave": "brother", "dove": ("titolo", "corpo"), "espressione": r"(?i)\bbrother\b",
     "marca": "Brother", "tipo": "printer", "prodotto": "Brother"},
    {"chiave": "lexmark", "dove": ("titolo", "corpo"), "espressione": r"(?i)\blexmark\b",
     "marca": "Lexmark", "tipo": "printer", "prodotto": "Lexmark"},
    {"chiave": "xerox", "dove": ("titolo", "corpo"), "espressione": r"(?i)\bxerox\b|workcentre|versalink|altalink",
     "marca": "Xerox", "tipo": "printer", "prodotto": "Xerox"},
    {"chiave": "sharp-mfp", "dove": ("titolo", "corpo"), "espressione": r"(?i)\bsharp\b.*(mx|bp)-",
     "marca": "Sharp", "tipo": "printer", "prodotto": "Sharp MFP"},

    # --- apparati di rete e sicurezza ---
    {"chiave": "fortigate", "dove": ("titolo", "corpo", "certificato"),
     "espressione": r"(?i)fortigate|fortinet|fortiweb|fortimail",
     "marca": "Fortinet", "tipo": "firewall", "prodotto": "Fortinet FortiOS"},
    {"chiave": "pfsense", "dove": ("titolo", "corpo"), "espressione": r"(?i)pfsense",
     "marca": "Netgate", "tipo": "firewall", "prodotto": "pfSense"},
    {"chiave": "opnsense", "dove": ("titolo", "corpo"), "espressione": r"(?i)opnsense",
     "marca": "OPNsense", "tipo": "firewall", "prodotto": "OPNsense"},
    {"chiave": "sophos", "dove": ("titolo", "corpo"), "espressione": r"(?i)sophos|utm firewall",
     "marca": "Sophos", "tipo": "firewall", "prodotto": "Sophos"},
    {"chiave": "sonicwall", "dove": ("titolo", "corpo"), "espressione": r"(?i)sonicwall",
     "marca": "SonicWall", "tipo": "firewall", "prodotto": "SonicWall"},
    {"chiave": "watchguard", "dove": ("titolo", "corpo"), "espressione": r"(?i)watchguard",
     "marca": "WatchGuard", "tipo": "firewall", "prodotto": "WatchGuard"},
    {"chiave": "stormshield", "dove": ("titolo", "corpo"), "espressione": r"(?i)stormshield",
     "marca": "Stormshield", "tipo": "firewall", "prodotto": "Stormshield"},
    {"chiave": "mikrotik", "dove": ("titolo", "corpo", "server"),
     "espressione": r"(?i)routeros|mikrotik",
     "marca": "MikroTik", "tipo": "router", "prodotto": "MikroTik RouterOS",
     "versione": r"(?i)routeros[\s/v]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    {"chiave": "ubiquiti", "dove": ("titolo", "corpo"), "espressione": r"(?i)unifi|ubiquiti|airos|edgeos",
     "marca": "Ubiquiti", "tipo": "access_point", "prodotto": "Ubiquiti"},
    {"chiave": "cisco", "dove": ("titolo", "corpo", "realm"),
     "espressione": r"(?i)\bcisco\b|level_15_access|catalyst",
     "marca": "Cisco", "tipo": "switch", "prodotto": "Cisco IOS"},
    {"chiave": "aruba", "dove": ("titolo", "corpo"), "espressione": r"(?i)\baruba\b|arubaos|instant\s+ap",
     "marca": "Aruba", "tipo": "access_point", "prodotto": "ArubaOS"},
    {"chiave": "hp-procurve", "dove": ("titolo", "corpo"), "espressione": r"(?i)procurve|hpe?\s+switch|aruba\s+\d{4}",
     "marca": "HPE", "tipo": "switch", "prodotto": "HPE ProCurve"},
    {"chiave": "zyxel", "dove": ("titolo", "corpo"), "espressione": r"(?i)zyxel",
     "marca": "Zyxel", "tipo": "router", "prodotto": "Zyxel"},
    {"chiave": "tplink", "dove": ("titolo", "corpo"), "espressione": r"(?i)tp-?link|omada",
     "marca": "TP-Link", "tipo": "router", "prodotto": "TP-Link"},
    {"chiave": "netgear", "dove": ("titolo", "corpo"), "espressione": r"(?i)netgear|prosafe",
     "marca": "NETGEAR", "tipo": "switch", "prodotto": "NETGEAR"},
    {"chiave": "dlink", "dove": ("titolo", "corpo"), "espressione": r"(?i)d-link",
     "marca": "D-Link", "tipo": "router", "prodotto": "D-Link"},
    {"chiave": "draytek", "dove": ("titolo", "corpo"), "espressione": r"(?i)draytek|vigor",
     "marca": "DrayTek", "tipo": "router", "prodotto": "DrayTek Vigor"},
    {"chiave": "teltonika", "dove": ("titolo", "corpo"), "espressione": r"(?i)teltonika|rut\d{3}",
     "marca": "Teltonika", "tipo": "router", "prodotto": "Teltonika"},

    # --- gestione dei server (BMC) ---
    {"chiave": "idrac", "dove": ("titolo", "corpo", "certificato"), "espressione": r"(?i)idrac|integrated dell remote",
     "marca": "Dell", "tipo": "server", "prodotto": "Dell iDRAC",
     "versione": r"(?i)idrac\s*([0-9]+)"},
    {"chiave": "ilo", "dove": ("titolo", "corpo", "certificato"), "espressione": r"(?i)\bilo\s*\d?\b|integrated lights-out",
     "marca": "HPE", "tipo": "server", "prodotto": "HPE iLO",
     "versione": r"(?i)ilo\s*([0-9]+)"},
    {"chiave": "supermicro", "dove": ("titolo", "corpo"), "espressione": r"(?i)supermicro|atenipmi",
     "marca": "Supermicro", "tipo": "server", "prodotto": "Supermicro IPMI"},
    {"chiave": "lenovo-xcc", "dove": ("titolo", "corpo"), "espressione": r"(?i)lenovo\s+xclarity|imm2",
     "marca": "Lenovo", "tipo": "server", "prodotto": "Lenovo XClarity"},

    # --- archiviazione e virtualizzazione ---
    {"chiave": "synology", "dove": ("titolo", "corpo"), "espressione": r"(?i)synology|diskstation|rackstation",
     "marca": "Synology", "tipo": "nas", "prodotto": "Synology DSM"},
    {"chiave": "qnap", "dove": ("titolo", "corpo"), "espressione": r"(?i)\bqnap\b|qts\b",
     "marca": "QNAP", "tipo": "nas", "prodotto": "QNAP QTS"},
    {"chiave": "truenas", "dove": ("titolo", "corpo"), "espressione": r"(?i)truenas|freenas",
     "marca": "iXsystems", "tipo": "nas", "prodotto": "TrueNAS"},
    {"chiave": "proxmox", "dove": ("titolo", "corpo"), "espressione": r"(?i)proxmox",
     "marca": "Proxmox", "tipo": "server", "prodotto": "Proxmox VE"},
    {"chiave": "vmware", "dove": ("titolo", "corpo"), "espressione": r"(?i)vmware|esxi|vsphere|vcenter",
     "marca": "VMware", "tipo": "server", "prodotto": "VMware ESXi/vCenter"},
    {"chiave": "veeam", "dove": ("titolo", "corpo"), "espressione": r"(?i)veeam",
     "marca": "Veeam", "tipo": "server", "prodotto": "Veeam"},

    # Web card Vertiv (gia' Emerson Network Power) IntelliSlot: interfaccia di gestione
    # di UPS e unita' di raffreddamento Liebert -- i "gruppi frigo" dei datacenter. Sta
    # qui, prima delle telecamere, perche' la sua pagina e' fatta di frame e JavaScript
    # e la vecchia firma hikvision (`dvr.*web`) la agganciava per sbaglio ("web"
    # abbonda). La pagina redirige a web/initialize.htm e dichiara il firmware in
    # `fwLabel`.
    {"chiave": "vertiv-intellislot", "dove": ("titolo", "corpo", "fatti"),
     "espressione": r"(?i)intellislot|emerson network power|is-?unity|\bliebert\b",
     "marca": "Vertiv", "tipo": "building_automation",
     "prodotto": "Vertiv/Emerson IntelliSlot (gestione UPS o raffreddamento)",
     "modello": r"(?i)(IntelliSlot[\w \-]{0,20}|IS-?UNITY[\w.\-]{0,14})"},

    # --- videosorveglianza, telefonia, controllo accessi ---
    # `dvr.*web` con distanza illimitata agganciava pagine che nulla c'entrano con una
    # telecamera (bastava un "dvr" e un "web" lontani): la distanza e' ora limitata.
    {"chiave": "hikvision", "dove": ("titolo", "corpo"),
     "espressione": r"(?i)hikvision|\bdvr\b[\s\S]{0,30}web|ivms",
     "marca": "Hikvision", "tipo": "camera", "prodotto": "Hikvision"},
    {"chiave": "dahua", "dove": ("titolo", "corpo"), "espressione": r"(?i)dahua|\bnvr\b\s*web",
     "marca": "Dahua", "tipo": "camera", "prodotto": "Dahua"},
    {"chiave": "axis", "dove": ("titolo", "corpo", "server"), "espressione": r"(?i)axis\s+(?:communications|camera|q\d|p\d|m\d)",
     "marca": "Axis", "tipo": "camera", "prodotto": "Axis"},
    {"chiave": "mobotix", "dove": ("titolo", "corpo"), "espressione": r"(?i)mobotix",
     "marca": "MOBOTIX", "tipo": "camera", "prodotto": "MOBOTIX"},
    {"chiave": "asterisk", "dove": ("titolo", "corpo"), "espressione": r"(?i)freepbx|asterisk",
     "marca": "Sangoma", "tipo": "voip", "prodotto": "FreePBX/Asterisk"},
    {"chiave": "yealink", "dove": ("titolo", "corpo"), "espressione": r"(?i)yealink",
     "marca": "Yealink", "tipo": "voip", "prodotto": "Yealink"},
    {"chiave": "grandstream", "dove": ("titolo", "corpo"), "espressione": r"(?i)grandstream",
     "marca": "Grandstream", "tipo": "voip", "prodotto": "Grandstream"},
    {"chiave": "snom", "dove": ("titolo", "corpo"), "espressione": r"(?i)\bsnom\b",
     "marca": "Snom", "tipo": "voip", "prodotto": "Snom"},

    # --- alimentazione e ambiente ---
    {"chiave": "apc", "dove": ("titolo", "corpo"), "espressione": r"(?i)\bapc\b|smart-?ups|network management card",
     "marca": "APC", "tipo": "ups", "prodotto": "APC NMC"},
    {"chiave": "eaton", "dove": ("titolo", "corpo"), "espressione": r"(?i)\beaton\b.*ups|powerware",
     "marca": "Eaton", "tipo": "ups", "prodotto": "Eaton UPS"},
    {"chiave": "riello", "dove": ("titolo", "corpo"), "espressione": r"(?i)riello\s*ups",
     "marca": "Riello", "tipo": "ups", "prodotto": "Riello UPS"},
    # Schede di gestione di rete degli UPS di scuola MGE/Eaton, rivendute da HP, Dell,
    # Lenovo: la pagina e' un frameset servito da RomPager, con il modello scritto in
    # grassetto ("HP R5000") nella pagina "Power Source" (ups_prop.htm) e la telemetria
    # aggiornata via JavaScript. La firma scatta gia' dal titolo "... UPS Network
    # Module"; il percorso noto porta alla pagina del modello anche quando i frame non
    # si raggiungono in tempo. Marca e modello si leggono; la posizione e la telemetria
    # non hanno un'etichetta e cambiano a ogni lettura, quindi non si conservano.
    {"chiave": "mge-ups", "dove": ("titolo", "corpo", "server"),
     "espressione": r"(?i)ups network module|mgeweb|/html/synoptic/",
     "tipo": "ups", "prodotto": "UPS con scheda di gestione di rete (MGE/Eaton)",
     "modello": r"(?i)(?:HP|HPE|MGE|Eaton|Dell|Lenovo|Riello)\s+"
                r"([RT]P?\s?\d{3,5}[A-Za-z]{0,3})",
     "percorsi": ("/ups_prop.htm",)},

    # --- automazione industriale ---
    {"chiave": "siemens-s7", "dove": ("titolo", "corpo"), "espressione": r"(?i)simatic|s7-\d{3}|siemens",
     "marca": "Siemens", "tipo": "plc", "prodotto": "Siemens SIMATIC"},
    {"chiave": "schneider", "dove": ("titolo", "corpo"), "espressione": r"(?i)schneider\s*electric|modicon",
     "marca": "Schneider Electric", "tipo": "plc", "prodotto": "Modicon"},
    {"chiave": "moxa", "dove": ("titolo", "corpo"), "espressione": r"(?i)\bmoxa\b",
     "marca": "Moxa", "tipo": "plc", "prodotto": "Moxa"},
    {"chiave": "wago", "dove": ("titolo", "corpo"), "espressione": r"(?i)\bwago\b",
     "marca": "WAGO", "tipo": "plc", "prodotto": "WAGO"},

    # --- applicazioni di gestione (prodotto e versione: utili alla correlazione) ---
    {"chiave": "grafana", "dove": ("titolo", "corpo", "intestazioni"), "espressione": r"(?i)grafana",
     "tipo": "server", "prodotto": "Grafana",
     "versione": r"(?i)grafana[\s/v\"]*([0-9]+\.[0-9]+\.[0-9]+)"},
    {"chiave": "zabbix", "dove": ("titolo", "corpo"), "espressione": r"(?i)zabbix",
     "tipo": "server", "prodotto": "Zabbix",
     "versione": r"(?i)zabbix\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    {"chiave": "nagios", "dove": ("titolo", "corpo"), "espressione": r"(?i)nagios|centreon|icinga",
     "tipo": "server", "prodotto": "Nagios/Icinga"},
    {"chiave": "prtg", "dove": ("titolo", "corpo"), "espressione": r"(?i)\bprtg\b",
     "tipo": "server", "prodotto": "PRTG Network Monitor"},
    {"chiave": "jenkins", "dove": ("titolo", "corpo", "intestazioni"), "espressione": r"(?i)jenkins",
     "tipo": "server", "prodotto": "Jenkins",
     "versione": r"(?i)jenkins[\s/v\"]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    {"chiave": "gitlab", "dove": ("titolo", "corpo"), "espressione": r"(?i)gitlab",
     "tipo": "server", "prodotto": "GitLab"},
    {"chiave": "portainer", "dove": ("titolo", "corpo"), "espressione": r"(?i)portainer",
     "tipo": "server", "prodotto": "Portainer"},
    {"chiave": "phpmyadmin", "dove": ("titolo", "corpo"), "espressione": r"(?i)phpmyadmin",
     "tipo": "server", "prodotto": "phpMyAdmin",
     "versione": r"(?i)phpmyadmin[\s/v]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    {"chiave": "wordpress", "dove": ("generator", "corpo"), "espressione": r"(?i)wordpress",
     "tipo": "server", "prodotto": "WordPress",
     "versione": r"(?i)wordpress[\s/v]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    {"chiave": "joomla", "dove": ("generator", "corpo"), "espressione": r"(?i)joomla",
     "tipo": "server", "prodotto": "Joomla",
     "versione": r"(?i)joomla!?[\s/v]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    {"chiave": "drupal", "dove": ("generator", "corpo", "intestazioni"), "espressione": r"(?i)drupal",
     "tipo": "server", "prodotto": "Drupal"},
    {"chiave": "homeassistant", "dove": ("titolo", "corpo"), "espressione": r"(?i)home\s*assistant",
     "tipo": "iot", "prodotto": "Home Assistant"},
    {"chiave": "plex", "dove": ("titolo", "corpo"), "espressione": r"(?i)\bplex\b",
     "tipo": "server", "prodotto": "Plex"},
    {"chiave": "tomcat", "dove": ("titolo", "corpo", "server"), "espressione": r"(?i)apache\s+tomcat",
     "tipo": "server", "prodotto": "Apache Tomcat",
     "versione": r"(?i)tomcat[\s/v]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},

    # --- server generici: ultimi, perche' dicono meno di tutto il resto ---
    {"chiave": "iis", "dove": ("server",), "espressione": r"(?i)microsoft-iis",
     "tipo": "server", "prodotto": "Microsoft IIS",
     "versione": r"(?i)microsoft-iis/([0-9]+\.[0-9]+)"},
    {"chiave": "nginx", "dove": ("server",), "espressione": r"(?i)nginx",
     "tipo": "server", "prodotto": "nginx",
     "versione": r"(?i)nginx/([0-9]+\.[0-9]+\.[0-9]+)"},
    {"chiave": "apache", "dove": ("server",), "espressione": r"(?i)apache",
     "tipo": "server", "prodotto": "Apache httpd",
     "versione": r"(?i)apache/([0-9]+\.[0-9]+\.[0-9]+)"},
    {"chiave": "lighttpd", "dove": ("server",), "espressione": r"(?i)lighttpd",
     "tipo": "server", "prodotto": "lighttpd",
     "versione": r"(?i)lighttpd/([0-9]+\.[0-9]+\.[0-9]+)"},
    {"chiave": "boa", "dove": ("server",), "espressione": r"(?i)\bboa/|goahead|mini_httpd|thttpd",
     "tipo": "iot", "prodotto": "server web embedded"},
]

# Estrazioni dall'HTML. Sono etichette che le pagine dichiarano di se': non si
# cerca dentro il testo della pagina, che e' contenuto dell'utente.
RE_TITOLO = re.compile(r"(?is)<title[^>]*>(.{0,300}?)</title>")
RE_META = re.compile(
    r"(?is)<meta\s+[^>]*?name\s*=\s*[\"']?(generator|description|application-name)[\"']?"
    r"[^>]*?content\s*=\s*[\"']([^\"']{0,300})")
RE_META_INVERSO = re.compile(
    r"(?is)<meta\s+[^>]*?content\s*=\s*[\"']([^\"']{0,300})[\"'][^>]*?name\s*=\s*"
    r"[\"']?(generator|description|application-name)")
RE_H1 = re.compile(r"(?is)<h1[^>]*>(.{0,200}?)</h1>")
RE_FORM_PASSWORD = re.compile(r"(?i)type\s*=\s*[\"']?password")
RE_TAG = re.compile(r"(?s)<[^>]+>")


def _testo(valore, massimo: int = MAX_TESTO) -> str:
    """Testo ripulito: senza marcatori, senza spazi ripetuti, accorciato."""
    if not valore:
        return ""
    pulito = unescape(RE_TAG.sub(" ", str(valore)))
    pulito = re.sub(r"\s+", " ", pulito).strip()
    return pulito[:massimo]


# --------------------------------------------------------------------------- #
# Certificato TLS
# --------------------------------------------------------------------------- #
def leggi_certificato(ip: str, port: int, timeout: float = TIMEOUT_CONNESSIONE) -> dict:
    """Dati del certificato presentato: nome, emittente, validita'.

    Si apre una connessione senza verifica (nelle reti interne l'autofirmato e' la
    norma) e si legge il certificato cosi' com'e'. La verifica si annota come esito,
    non come condizione: un certificato scaduto o autofirmato e' un'informazione
    utile, non un motivo per rinunciare a leggere.
    """
    contesto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    contesto.check_hostname = False
    contesto.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as presa:
            with contesto.wrap_socket(presa, server_hostname=None) as sicura:
                grezzo = sicura.getpeercert(binary_form=True)
                protocollo = sicura.version()
                cifrario = sicura.cipher()
    except (OSError, ssl.SSLError, socket.timeout):
        return {}

    dati = {"tls_versione": protocollo or "",
            "tls_cifrario": (cifrario[0] if cifrario else "") or ""}
    if not grezzo:
        return dati
    dati.update(dettagli_certificato(grezzo))
    return dati


def dettagli_certificato(grezzo: bytes) -> dict:
    """Tutti i dati leggibili di un certificato in forma DER.

    Funzione pura, senza rete: prende i byte del certificato e ne ricava nomi (corti e
    completi), validita', numero di serie, versione, algoritmo di firma, chiave
    pubblica, impronte, nomi alternativi e usi consentiti. Separata dalla connessione
    proprio per poterla collaudare su un certificato costruito a tavolino.

    Non solleva: un certificato malformato annota `cert_errore` e nient'altro.
    """
    dati = {}
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding

        certificato = x509.load_der_x509_certificate(grezzo)
        # Nomi: la forma corta (CN/O) per la colonna e la tabella, la forma completa
        # (DN) per chi vuole verificare esattamente chi ha emesso e per chi.
        dati["cert_soggetto"] = _nome_x509(certificato.subject)
        dati["cert_emittente"] = _nome_x509(certificato.issuer)
        dati["cert_soggetto_dn"] = _testo(certificato.subject.rfc4514_string(), 300)
        dati["cert_emittente_dn"] = _testo(certificato.issuer.rfc4514_string(), 300)
        # Validita': la data per la colonna, l'ora completa per il dettaglio, e i due
        # esiti operativi (scaduto, giorni residui) che nessun'altra fase calcola.
        inizio = certificato.not_valid_before_utc
        scadenza = certificato.not_valid_after_utc
        dati["cert_da"] = inizio.strftime("%Y-%m-%d")
        dati["cert_a"] = scadenza.strftime("%Y-%m-%d")
        dati["cert_valido_da"] = inizio.strftime("%Y-%m-%d %H:%M:%S UTC")
        dati["cert_valido_a"] = scadenza.strftime("%Y-%m-%d %H:%M:%S UTC")
        adesso = datetime.now(timezone.utc)
        dati["cert_autofirmato"] = (certificato.subject == certificato.issuer)
        dati["cert_non_ancora_valido"] = inizio > adesso
        dati["cert_scaduto"] = scadenza < adesso
        dati["cert_giorni_residui"] = (scadenza - adesso).days
        # Identita' del certificato: numero di serie e versione (v3 quasi ovunque).
        dati["cert_seriale"] = format(certificato.serial_number, "X")
        dati["cert_versione"] = getattr(certificato.version, "name", "")
        # Algoritmo di firma: un certificato ancora firmato in SHA-1 e' un dato di
        # sicurezza (algoritmo deprecato), non un dettaglio.
        try:
            algoritmo = certificato.signature_hash_algorithm
            dati["cert_algoritmo_firma"] = getattr(algoritmo, "name", "") or ""
        except Exception:  # noqa: BLE001 - algoritmo non standard: si tace, non e' fatale
            pass
        chiave = _chiave_pubblica(certificato)
        if chiave:
            dati["cert_chiave"] = chiave
        # Impronte per intero: la SHA-256 identifica il certificato in modo univoco
        # (fissaggio, confronto fra apparati), la SHA-1 e' quella che molti strumenti
        # ancora mostrano. `cert_impronta` (corta) resta per compatibilita'.
        der = certificato.public_bytes(Encoding.DER)
        dati["cert_sha256"] = hashlib.sha256(der).hexdigest()
        dati["cert_sha1"] = hashlib.sha1(der).hexdigest()
        dati["cert_impronta"] = dati["cert_sha256"][:32]
        # Nomi alternativi: DNS e IP dichiarati nel certificato. Sono i nomi per cui il
        # certificato e' valido, e dicono spesso il vero nome dell'apparato.
        dns, indirizzi = _nomi_alternativi(certificato)
        if dns:
            dati["cert_nomi"] = dns[:20]
        if indirizzi:
            dati["cert_nomi_ip"] = indirizzi[:20]
        usi = _usi_chiave(certificato)
        if usi:
            dati["cert_uso"] = usi
        uso_esteso = _uso_esteso(certificato)
        if uso_esteso:
            dati["cert_uso_esteso"] = uso_esteso
    except Exception as errore:  # noqa: BLE001 - certificato malformato: si dichiara
        # Un certificato illeggibile non deve far perdere il resto della lettura: si
        # annota il motivo, che a volte e' esso stesso un'informazione sull'apparato.
        dati["cert_errore"] = str(errore)[:120]
    return dati


def _chiave_pubblica(certificato) -> str:
    """La chiave pubblica in forma leggibile: tipo e dimensione (o curva).

    E' un dato di sicurezza: una RSA a 1024 bit e' debole, una P-256 no. Serve una
    riga, non l'esponente.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import ec, rsa

        pk = certificato.public_key()
        if isinstance(pk, rsa.RSAPublicKey):
            return "RSA %d bit" % pk.key_size
        if isinstance(pk, ec.EllipticCurvePublicKey):
            return "EC %s (%d bit)" % (pk.curve.name, pk.key_size)
        nome = type(pk).__name__.replace("PublicKey", "").lstrip("_")
        dimensione = getattr(pk, "key_size", None)
        return "%s%s" % (nome, " %d bit" % dimensione if dimensione else "")
    except Exception:  # noqa: BLE001 - chiave di tipo inatteso: non e' fatale
        return ""


def _nomi_alternativi(certificato):
    """I SAN del certificato: nomi DNS e indirizzi IP per cui e' valido."""
    from cryptography import x509

    try:
        san = certificato.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return [], []
    dns = [_testo(v, 120) for v in san.get_values_for_type(x509.DNSName)]
    indirizzi = [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    return [d for d in dns if d], indirizzi


def _usi_chiave(certificato) -> list:
    """Gli usi consentiti dalla chiave (KeyUsage), in forma leggibile."""
    from cryptography import x509

    try:
        ku = certificato.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return []
    coppie = [
        (ku.digital_signature, "firma digitale"),
        (ku.content_commitment, "non ripudio"),
        (ku.key_encipherment, "cifratura chiave"),
        (ku.data_encipherment, "cifratura dati"),
        (ku.key_agreement, "accordo chiave"),
        (ku.key_cert_sign, "firma certificati"),
        (ku.crl_sign, "firma CRL"),
    ]
    return [nome for attivo, nome in coppie if attivo]


def _uso_esteso(certificato) -> list:
    """Gli usi estesi (ExtendedKeyUsage): server TLS, client TLS, firma codice..."""
    from cryptography import x509

    try:
        eku = certificato.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return []
    nomi = {
        "serverAuth": "autenticazione server", "clientAuth": "autenticazione client",
        "codeSigning": "firma codice", "emailProtection": "protezione posta",
        "timeStamping": "marca temporale", "OCSPSigning": "firma OCSP",
    }
    fuori = []
    for oid in eku:
        grezzo = getattr(oid, "_name", None) or oid.dotted_string
        fuori.append(nomi.get(grezzo, grezzo))
    return fuori


def _nome_x509(nome) -> str:
    """Nome X.509 in forma leggibile, con il CN davanti se c'e'."""
    try:
        from cryptography.x509.oid import NameOID

        comuni = nome.get_attributes_for_oid(NameOID.COMMON_NAME)
        if comuni:
            return _testo(comuni[0].value, 120)
        organizzazioni = nome.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if organizzazioni:
            return _testo(organizzazioni[0].value, 120)
    except Exception:  # noqa: BLE001 - nome non convenzionale
        pass
    return _testo(getattr(nome, "rfc4514_string", lambda: "")(), 120)


# --------------------------------------------------------------------------- #
# Lettura della pagina
# --------------------------------------------------------------------------- #
def _scarica(indirizzo: str, ip: str):
    """Una GET, con i limiti del modulo. Restituisce (risposta, corpo, errore).

    Il corpo torna come byte e non viene conservato da nessuna parte: chi chiama lo
    usa per estrarre i fatti e lo lascia andare.
    """
    import requests

    try:
        risposta = requests.get(
            indirizzo,
            timeout=(TIMEOUT_CONNESSIONE, TIMEOUT_LETTURA),
            verify=False,
            allow_redirects=False,
            stream=True,
            headers={"User-Agent": "snap-probe/1.0 (inventario di rete)",
                     "Accept": "text/html,*/*"},
        )
    except Exception as errore:  # noqa: BLE001 - qualunque errore di rete e' un esito
        return None, b"", type(errore).__name__

    try:
        corpo = risposta.raw.read(MAX_BYTE_CORPO, decode_content=True) or b""
    except Exception:  # noqa: BLE001 - corpo illeggibile: restano le intestazioni
        corpo = b""
    finally:
        risposta.close()
    return risposta, corpo, None


def _decodifica(corpo: bytes, tipo_contenuto: str) -> str:
    """Il corpo come testo, rispettando la codifica dichiarata.

    Un apparato che dichiara `charset=iso-8859-1` e viene letto come UTF-8 restituisce
    "Posizione: ED A PIANO ï¿½1": il fatto c'e' ma e' illeggibile, e finirebbe cosi'
    nell'inventario.
    """
    if not corpo:
        return ""
    codifiche = []
    dichiarata = re.search(r"(?i)charset\s*=\s*[\"\']?([\w\-]{2,20})",
                           tipo_contenuto or "")
    if dichiarata:
        codifiche.append(dichiarata.group(1))
    nella_pagina = re.search(rb"(?i)charset\s*=\s*[\"\']?([\w\-]{2,20})", corpo[:2048])
    if nella_pagina:
        codifiche.append(nella_pagina.group(1).decode("ascii", "ignore"))
    codifiche.extend(("utf-8", "cp1252", "latin-1"))
    for codifica in codifiche:
        try:
            return corpo.decode(codifica)
        except (LookupError, UnicodeDecodeError):
            continue
    return corpo.decode("utf-8", errors="replace")


def _sufficiente(fatti_noti: dict) -> bool:
    """Vero quando l'apparato ha detto abbastanza di se': si smette di navigare.

    "Abbastanza" e' l'identita' piu' un dato di contesto. Continuare a leggere pagine
    di un apparato che si e' gia' presentato e' tempo tolto agli altri.
    """
    identita = fatti_noti.get("nome_dispositivo") or fatti_noti.get("modello")
    contesto = any(fatti_noti.get(c) for c in ("posizione", "nome_host", "seriale"))
    return bool(identita and contesto)


def leggi_pagina(ip: str, port: int, tls: bool) -> dict:
    """Legge l'interfaccia web di una porta e ne ricava cio' che dichiara di se'.

    Non si ferma alla radice: segue le redirezioni, il `meta refresh`, il salto
    scritto in JavaScript e i frame, e -- se i fatti mancano ancora -- prova i
    collegamenti che l'apparato chiama "informazioni" o "stato". Il percorso seguito
    resta nel risultato, perche' un fatto senza la pagina da cui viene non e'
    verificabile.

    Vincoli: massimo `MAX_PAGINE_PER_PORTA` letture e `BUDGET_SECONDI_PORTA` secondi,
    solo GET, solo lo stesso apparato e la stessa porta, nessun percorso che contenga
    un verbo d'azione (vedi `web_facts.VERBI_PERICOLOSI`).

    Restituisce sempre un dizionario: se la lettura non riesce, contiene il motivo.
    Non solleva eccezioni, perche' una passata riguarda centinaia di indirizzi e un
    apparato che non risponde non deve interromperla.
    """
    import urllib3

    from . import web_facts

    # L'avviso sul certificato non verificato e' atteso e dichiarato (vedi
    # leggi_certificato): lasciarlo stampare riempirebbe il diario di righe che non
    # aggiungono nulla.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    schema = "https" if tls else "http"
    indirizzo = "%s://%s:%d/" % (schema, ip, port)
    esito = {"port": port, "protocol": "tcp", "scheme": schema, "url": indirizzo}

    if tls:
        esito.update(leggi_certificato(ip, port))

    scadenza = time.monotonic() + BUDGET_SECONDI_PORTA
    coda = [{"url": indirizzo, "origine": "radice", "profondita": 0, "priorita": 0}]
    visitati = []
    fatti_noti = {}
    materiale = []
    prima = True

    while coda and len(visitati) < MAX_PAGINE_PER_PORTA:
        if time.monotonic() > scadenza:
            esito["budget_esaurito"] = True
            break
        # Si legge prima cio' che sta piu' avanti nel percorso che l'apparato stesso
        # indica: e' il suo imbuto, e seguirlo e' il modo piu' breve di arrivare ai
        # fatti. A pari profondita' conta la promessa del bersaglio.
        coda.sort(key=lambda c: (-c["profondita"], c.get("priorita", 2)))
        passo = coda.pop(0)
        risposta, corpo, errore = _scarica(passo["url"], ip)
        # `if risposta` sarebbe sbagliato: un oggetto risposta di `requests` e' FALSO
        # quando lo stato e' 4xx o 5xx, e un 404 verrebbe registrato come "nessuno
        # stato". E' il difetto che faceva sparire il 500 di una Kyocera dal diario.
        visitati.append({"percorso": _percorso(passo["url"]),
                         "origine": passo["origine"],
                         "stato": (int(risposta.status_code)
                                   if risposta is not None else None),
                         "errore": errore})
        if errore:
            if prima:
                esito["errore"] = errore
                return esito
            if (errore in ("ReadTimeout", "ConnectionError", "ChunkedEncodingError")
                    and not passo.get("ritentato")):
                # Le pagine lente sono spesso quelle che contengono i fatti: un solo
                # ritentativo, in coda, se il tempo lo permette.
                coda.append(dict(passo, ritentato=True, priorita=1))
            continue

        if prima:
            _registra_prima_pagina(esito, risposta, corpo, passo["url"])
            prima = False

        # Redirezione: si segue in testa alla coda, e' la pagina che l'apparato voleva.
        if risposta.is_redirect:
            destinazione = risposta.headers.get("Location") or ""
            esito.setdefault("redirezioni", []).append(_testo(destinazione, 200))
            prossimo = _redirezione_interna(passo["url"], destinazione, ip)
            if prossimo and prossimo not in [v["percorso"] for v in visitati]:
                coda.insert(0, {"url": prossimo, "origine": "redirezione",
                                "priorita": 0,
                                "profondita": passo["profondita"] + 1})
            continue

        # La prima pagina letta era una redirezione: lo stato e le intestazioni che
        # descrivono il servizio sono quelli della pagina vera, non del 302.
        if 300 <= int(esito.get("stato") or 0) < 400:
            _registra_prima_pagina(esito, risposta, corpo, passo["url"])
        # Il realm dell'autenticazione nomina l'apparato piu' spesso della pagina, e
        # compare su pagine interne che chiedono le credenziali (che non abbiamo).
        if not esito.get("www_authenticate"):
            realm = risposta.headers.get("WWW-Authenticate")
            if realm:
                esito["www_authenticate"] = _testo(realm, 200)

        testo = _decodifica(corpo, risposta.headers.get("Content-Type") or "")
        if not testo:
            continue
        materiale.append(testo)

        for chiave, valore in web_facts.fatti(testo).items():
            fatti_noti.setdefault(chiave, valore)
        titolo = RE_TITOLO.search(testo)
        if titolo:
            _annota_titolo(esito, _testo(titolo.group(1), 200))

        if _sufficiente(fatti_noti):
            break
        if passo["profondita"] >= 3:
            continue

        cerca_ancore = (passo["profondita"] >= PROFONDITA_ANCORE
                        and not fatti_noti.get("nome_dispositivo"))
        for bersaglio in web_facts.bersagli(testo, passo["url"], cerca_ancore):
            if not web_facts.stesso_apparato(bersaglio["url"], ip, port):
                continue
            percorso = _percorso(bersaglio["url"])
            if any(v["percorso"] == percorso for v in visitati):
                continue
            if any(c["url"] == bersaglio["url"] for c in coda):
                continue
            coda.append({"url": bersaglio["url"], "origine": bersaglio["origine"],
                         "priorita": bersaglio.get("priorita", 2),
                         "profondita": passo["profondita"] + 1})

    # Ultima carta: la firma ha riconosciuto la famiglia ma l'apparato non ha ancora
    # detto niente di se'. Le famiglie che si conoscono hanno un indirizzo informativo
    # documentato: si prova quello, non si cerca a tentoni.
    if not _sufficiente(fatti_noti) and time.monotonic() < scadenza:
        verdetto = riconosci(esito, "\n".join(materiale)[:MAX_BYTE_CORPO])
        percorsi = _percorsi_noti(verdetto.get("firma"))
        for percorso in percorsi[:2]:
            if time.monotonic() > scadenza or len(visitati) >= MAX_PAGINE_PER_PORTA + 2:
                break
            candidato = "%s://%s:%d%s" % (schema, ip, port, percorso)
            if any(v["percorso"] == percorso for v in visitati):
                continue
            risposta, corpo, errore = _scarica(candidato, ip)
            visitati.append({"percorso": percorso, "origine": "percorso noto",
                             "stato": (int(risposta.status_code)
                                       if risposta is not None else None),
                             "errore": errore})
            if errore or risposta is None or risposta.status_code >= 400:
                continue
            testo = _decodifica(corpo, risposta.headers.get("Content-Type") or "")
            if not testo:
                continue
            materiale.append(testo)
            for chiave, valore in web_facts.fatti(testo).items():
                fatti_noti.setdefault(chiave, valore)
            if _sufficiente(fatti_noti):
                break

    esito["pagine"] = visitati[:MAX_PAGINE_PER_PORTA + 2]
    esito["pagine_lette"] = len(visitati)
    if not fatti_noti and any(v["stato"] == 401 for v in visitati):
        # Detto esplicitamente: la pagina che contiene i dati esiste ma chiede le
        # credenziali. E' un'informazione, non un guasto -- e spiega perche' di questo
        # apparato si sa solo il genere.
        esito["fatti_protetti"] = True
    if fatti_noti:
        esito["fatti"] = fatti_noti

    # Prima le firme (danno il genere e la ragione), poi cio' che l'apparato dichiara
    # di se': fra un catalogo e l'apparato stesso, ha ragione l'apparato.
    esito.update(riconosci(esito, "\n".join(materiale)[:MAX_BYTE_CORPO]))
    dichiarato = web_facts.marca_e_modello(fatti_noti, esito.get("titolo"),
                                           esito.get("server"))
    for chiave in ("marca", "modello"):
        if dichiarato.get(chiave):
            esito[chiave] = dichiarato[chiave]
            esito.setdefault("fonte_identita", "pagina dell'apparato")

    # UPS con scheda MGE/Eaton: oltre a marca e modello si legge lo stato e i tre
    # registri, e se ne ricava una diagnosi (batteria, orologio). Vale per QUALUNQUE
    # apparato di questa famiglia -- e' la parte "replicabile su tutti i nodi simili".
    if esito.get("firma") == "mge-ups" and time.monotonic() < scadenza:
        diagnosi = _diagnostica_ups(ip, port, schema, scadenza)
        if diagnosi:
            esito.setdefault("fatti", {}).update(diagnosi)
    return esito


# Pagine di sola lettura che ogni scheda MGE/Eaton espone allo stesso indirizzo: lo
# stato corrente e i tre registri del menu "Logs" (eventi, sistema, misure).
PAGINE_UPS = {
    "status": "/ups_propStatus.htm",
    "eventi": "/ups_loge.htm",
    "sistema": "/ups_logs.htm",
    "misure": "/ups01_logMeasures.htm",
}


def _diagnostica_ups(ip: str, port: int, schema: str, scadenza: float) -> dict:
    """Legge stato e registri di uno UPS MGE/Eaton e ne ricava la diagnosi.

    Sono pagine di sola lettura (GET), come il resto della fase web: nessun comando,
    nessuna credenziale. Se il tempo per questa porta e' finito si legge cio' che si
    puo' e ci si ferma -- una passata riguarda centinaia di indirizzi.
    """
    from . import web_facts

    contenuti = {}
    for nome, percorso in PAGINE_UPS.items():
        if time.monotonic() > scadenza:
            break
        risposta, corpo, errore = _scarica("%s://%s:%d%s" % (schema, ip, port, percorso), ip)
        if errore or risposta is None or risposta.status_code >= 400:
            continue
        contenuti[nome] = _decodifica(corpo, risposta.headers.get("Content-Type") or "")
    if not contenuti:
        return {}
    return web_facts.diagnosi_ups(**contenuti)


def _percorsi_noti(chiave_firma: str) -> tuple:
    """Indirizzi informativi documentati della famiglia riconosciuta."""
    if not chiave_firma:
        return ()
    for firma in FIRME:
        if firma["chiave"] == chiave_firma:
            return tuple(firma.get("percorsi") or ())
    return ()


def _percorso(indirizzo: str) -> str:
    """Solo il percorso: l'indirizzo e la porta si sanno gia', e ripeterli in ogni
    riga del diario renderebbe illeggibile il percorso seguito."""
    parti = urlsplit(indirizzo or "")
    return _testo((parti.path or "/") + (("?" + parti.query) if parti.query else ""), 160)


def _annota_titolo(esito: dict, titolo: str) -> None:
    """Titolo della pagina: si tiene il primo, ma un titolo che nomina l'apparato
    vale piu' di "Web Image Monitor" o "Home"."""
    if not titolo:
        return
    corrente = esito.get("titolo") or ""
    generico = re.compile(r"(?i)^(home|index|main|login|status|stato|intestazione|"
                          r"header|menu|frame|untitled|senza titolo)\b")
    if not corrente or (generico.match(corrente) and not generico.match(titolo)):
        esito["titolo"] = titolo
    elif titolo not in (esito.get("titoli") or []) and titolo != corrente:
        esito.setdefault("titoli", []).append(titolo)


def _registra_prima_pagina(esito: dict, risposta, corpo: bytes, indirizzo: str) -> None:
    """Stato, intestazioni e impronta della PRIMA pagina: e' quella che descrive il
    servizio esposto sulla porta. Le successive servono ai fatti, non all'esposizione."""
    esito["stato"] = int(risposta.status_code)
    esito["url_finale"] = indirizzo
    intestazioni = {k.lower(): _testo(v, 200) for k, v in risposta.headers.items()}
    for nome in ("server", "x-powered-by", "www-authenticate", "location",
                 "content-type", "x-generator", "x-frame-options"):
        if intestazioni.get(nome):
            esito[nome.replace("-", "_")] = intestazioni[nome]
    biscotti = [c.split("=", 1)[0].strip()
                for c in risposta.headers.get("Set-Cookie", "").split(",") if "=" in c]
    if biscotti:
        esito["cookie"] = [b[:40] for b in biscotti[:6]]

    esito["corpo_byte"] = len(corpo)
    if corpo:
        # L'impronta serve a un solo scopo: accorgersi che la pagina e' cambiata
        # senza conservarne il contenuto (GDPR art. 5).
        esito["corpo_impronta"] = hashlib.sha256(corpo).hexdigest()[:32]

    testo = _decodifica(corpo, intestazioni.get("content-type") or "")
    for espressione, ordine in ((RE_META, (1, 2)), (RE_META_INVERSO, (2, 1))):
        for trovato in espressione.finditer(testo):
            nome = trovato.group(ordine[0]).lower()
            valore = _testo(trovato.group(ordine[1]), 200)
            chiave = {"generator": "generator", "description": "descrizione",
                      "application-name": "applicazione"}[nome]
            if valore and chiave not in esito:
                esito[chiave] = valore
    intestazione1 = RE_H1.search(testo)
    if intestazione1:
        esito["intestazione"] = _testo(intestazione1.group(1), 120)
    esito["modulo_accesso"] = bool(RE_FORM_PASSWORD.search(testo))


def _redirezione_interna(corrente: str, destinazione: str, ip: str) -> str | None:
    """Destinazione della redirezione, se resta sullo stesso apparato.

    Un apparato che rimanda al portale del fornitore non e' quel portale, e quel
    portale non e' nel perimetro dichiarato: si annota la redirezione e si smette di
    seguirla.
    """
    if not destinazione:
        return None
    if destinazione.startswith("/"):
        parti = urlsplit(corrente)
        return "%s://%s%s" % (parti.scheme, parti.netloc, destinazione)
    parti = urlsplit(destinazione)
    if not parti.scheme:
        return None
    if parti.hostname not in (ip, "localhost", "127.0.0.1"):
        return None
    return destinazione


# --------------------------------------------------------------------------- #
# Riconoscimento
# --------------------------------------------------------------------------- #
def riconosci(esito: dict, corpo: str = "") -> dict:
    """Applica il catalogo delle firme a cio' che la pagina ha dichiarato.

    Restituisce solo cio' che ha trovato: marca, tipo probabile, prodotto, versione
    e la chiave della firma che ha deciso -- perche' un verdetto senza la ragione
    che lo motiva non e' verificabile.
    """
    campi = {
        "titolo": " ".join(filter(None, [esito.get("titolo"), esito.get("intestazione"),
                                         esito.get("applicazione")])),
        "server": " ".join(filter(None, [esito.get("server"), esito.get("x_powered_by")])),
        "generator": " ".join(filter(None, [esito.get("generator"), esito.get("x_generator")])),
        "realm": esito.get("www_authenticate") or "",
        # I fatti che la pagina dichiara di se' ("Nome dispositivo: RICOH MP C4504ex")
        # sono la fonte piu' precisa che esista: e' l'apparato che parla di se stesso.
        "fatti": " | ".join("%s: %s" % (chiave, valore)
                            for chiave, valore in (esito.get("fatti") or {}).items()),
        "certificato": " ".join(filter(None, [esito.get("cert_soggetto"),
                                              esito.get("cert_emittente")])),
        "intestazioni": " ".join("%s: %s" % (k, v) for k, v in esito.items()
                                 if k in ("server", "x_powered_by", "x_generator",
                                          "www_authenticate")),
        # Il corpo si usa per il riconoscimento ma NON si conserva.
        "corpo": corpo[:MAX_BYTE_CORPO],
    }

    for firma in FIRME:
        materiale = " \n".join(campi.get(dove, "") for dove in firma["dove"])
        if not materiale.strip():
            continue
        if not re.search(firma["espressione"], materiale):
            continue

        trovato = {"firma": firma["chiave"], "tipo_probabile": firma["tipo"]}
        if firma.get("marca"):
            trovato["marca"] = firma["marca"]
        if firma.get("prodotto"):
            trovato["prodotto"] = firma["prodotto"]
        if firma.get("modello"):
            modello = re.search(firma["modello"], materiale)
            if modello:
                trovato["modello"] = _testo(modello.group(1), 60)
        if firma.get("versione"):
            versione = re.search(firma["versione"], materiale)
            if versione:
                trovato["versione"] = _testo(versione.group(1), 30)
        return trovato

    return {}


# --------------------------------------------------------------------------- #
# Lettura di un dispositivo
# --------------------------------------------------------------------------- #
def porte_web(porte_aperte) -> list[tuple]:
    """Porte da leggere su questo dispositivo, con l'indicazione se cifrate.

    Riceve le porte osservate dalla scansione: si leggono solo quelle aperte e solo
    quelle previste dal catalogo. Il nome del servizio, quando c'e', ha l'ultima
    parola: un `http` su una porta insolita va letto, e un `ssh` sulla 8080 no.
    """
    scelte = []
    for porta in porte_aperte or []:
        try:
            numero = int(porta.get("port"))
        except (TypeError, ValueError):
            continue
        if (porta.get("protocol") or "tcp") != "tcp" or porta.get("state") != "open":
            continue

        servizio = (porta.get("service_name") or "").lower()
        prodotto = (porta.get("product") or "").lower()
        cifrata = numero in PORTE_HTTPS or "https" in servizio or "ssl" in servizio
        e_web = (numero in PORTE_HTTP or numero in PORTE_HTTPS
                 or servizio in ("http", "https", "http-alt", "http-proxy", "https-alt")
                 or "http" in prodotto)
        # Un servizio dichiarato non-web su una porta del catalogo non si legge: e'
        # il caso di un SSH spostato sulla 8080, e una GET la' non serve a nessuno.
        # "tcpwrapped" NON e' una dichiarazione: e' il modo in cui nmap dice "la porta
        # apre e chiude subito, non so cosa sia" -- tipico degli apparati che limitano i
        # tentativi (un telefono IP Cisco, per dire, espone la 80 come "tcpwrapped").
        # Trattarlo come un servizio non-web faceva saltare la lettura di quella pagina.
        if servizio and not any(s in servizio
                                for s in ("http", "www", "ssl", "unknown", "tcpwrapped")):
            e_web = e_web and numero not in PORTE_HTTP and numero not in PORTE_HTTPS
        if e_web:
            scelte.append((numero, cifrata))
    return sorted(set(scelte))


def leggi_dispositivo(ip: str, porte_aperte, massimo_porte: int = 4) -> list[dict]:
    """Legge le interfacce web di un dispositivo: una voce per porta.

    Si fermano a quattro porte: un apparato che espone otto interfacce web dice le
    stesse cose su tutte, e la passata deve chiudersi in tempi utili.
    """
    letture = []
    for numero, cifrata in porte_web(porte_aperte)[:massimo_porte]:
        letture.append(leggi_pagina(ip, numero, cifrata))
    return letture
