"""
snap server - Identificazione del tipo di dispositivo (fingerprinting).

Motore deterministico a prove pesate: nessun apprendimento automatico, nessuna
chiamata esterna, verdetto sempre accompagnato dalle prove che lo sostengono.

Perche' risiede sul server e non sulla sonda: il catalogo delle firme evolve nel
tempo e aggiornarlo non deve richiedere una nuova distribuzione delle sonde. La
sonda invia prove normalizzate, il server emette il verdetto e puo' rideterminare
il tipo di tutto l'inventario quando il catalogo cambia, senza nuove scansioni.

Valutazione in tre stadi:
  1. regole decisive: combinazioni non ambigue che chiudono il caso;
  2. stadio indicizzato: porte, servizi, tipo dichiarato da nmap e famiglia del
     sistema operativo sono risolti su indici costruiti una sola volta, quindi
     il costo dipende dalle PROVE del nodo e non dalla dimensione del catalogo;
  3. stadio a espressioni: le regole con espressione regolare sono valutate solo
     sulle classi rimaste candidate, che per costruzione sono poche.

Le prove contrarie (pesi negativi) sono parte del progetto: senza di esse il
solo accumulo di indizi favorevoli classificherebbe come stampante qualunque
server che espone una porta di stampa.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re

# Il verdetto conserva la versione del catalogo che lo ha prodotto: al variare
# della versione l'inventario e' rideterminabile a partire dalle prove.
CATALOG_VERSION = "1.0.0"

# Punteggio oltre il quale le prove si considerano abbondanti. Non basta il
# peso: una porta e il nome di servizio che le corrisponde sono una sola
# osservazione, e da sole non devono produrre un verdetto certo.
CERTAINTY_SCORE = 14.0
# Generi di prova distinti (porta, servizio, tipo dichiarato, famiglia del
# sistema operativo, prodotto, produttore, nome host, script) oltre i quali le
# prove si considerano varie.
CERTAINTY_GENRES = 4
# La certezza piena e' riservata alle regole decisive: il percorso a punteggio si
# ferma prima, perche' un punteggio alto resta un'inferenza.
MAX_SCORED_CONFIDENCE = 95
# Sotto questo punteggio il verdetto resta 'unknown': non e' un fallimento, e'
# l'indicazione che il nodo va approfondito nella fase 5.
MINIMUM_SCORE = 2.5

UNKNOWN = {"key": "unknown", "label": "Non identificato", "icon": "bi-question-circle"}

# Firmware che identificano da soli la natura dell'apparato. Sono nomi propri di
# distribuzioni dedicate: non compaiono su un server generico.
FIRMWARE_RULES = (
    (r"(?i)openwrt|routeros|mikrotik|dd-wrt|tomato firmware|vyos|edgeos",
     "router_gateway", "firmware di apparato di rete riconosciuto"),
    (r"(?i)pfsense|opnsense|fortios|pan-os|sonicos|ipfire",
     "firewall", "firmware di firewall riconosciuto"),
    (r"(?i)\bqnap\b|\bqts\b|synology|diskstation|rackstation|truenas|freenas|unraid",
     "nas", "firmware di sistema di archiviazione riconosciuto"),
    (r"(?i)arubaos|procurve|comware|extremexos|nx-os|junos|cisco ios",
     "switch_managed", "firmware di apparato di rete gestito riconosciuto"),
    (r"(?i)airos|unifi|ruckus|meraki",
     "access_point", "firmware di punto di accesso riconosciuto"),
    (r"(?i)raspbian|raspberry pi os|armbian|dietpi",
     "sbc", "distribuzione per scheda a basso costo riconosciuta"),
)

# Prefissi MAC dei principali ambienti virtuali. La virtualizzazione non e' un
# tipo di dispositivo ma un attributo ortogonale: un server Windows resta un
# server Windows anche se gira su un ipervisore, quindi non compete nel
# punteggio delle classi.
VIRTUAL_MAC_PREFIXES = {
    "00:05:69": "VMware", "00:0c:29": "VMware", "00:1c:14": "VMware",
    "00:50:56": "VMware", "08:00:27": "VirtualBox", "0a:00:27": "VirtualBox",
    "00:15:5d": "Hyper-V", "00:03:ff": "Hyper-V", "00:16:3e": "Xen",
    "52:54:00": "QEMU/KVM", "00:1c:42": "Parallels", "00:16:cb": "Parallels",
}
# Agenti di sicurezza per endpoint riconoscibili dal banner. Quando uno di
# questi risponde su una porta, la porta e' intercettata: la sua etichetta di
# servizio non descrive il dispositivo, e l'agente stesso e' la prova che si
# tratta di un endpoint di uso generale.
SECURITY_AGENT_PATTERNS = (
    (r"(?i)bitdefender", "Bitdefender Endpoint Security"),
    (r"(?i)\beset\b|eset endpoint", "ESET Endpoint Security"),
    (r"(?i)sophos", "Sophos Endpoint"),
    (r"(?i)kaspersky", "Kaspersky Endpoint Security"),
    (r"(?i)symantec|broadcom endpoint", "Symantec Endpoint Protection"),
    (r"(?i)mcafee|trellix", "Trellix (McAfee) Endpoint"),
    (r"(?i)trend micro|officescan|apex one", "Trend Micro Apex One"),
    (r"(?i)crowdstrike|falcon sensor", "CrowdStrike Falcon"),
    (r"(?i)sentinelone", "SentinelOne"),
    (r"(?i)forticlient", "FortiClient"),
    (r"(?i)windows defender|smartscreen", "Microsoft Defender"),
    (r"(?i)zscaler", "Zscaler"),
    (r"(?i)cisco umbrella", "Cisco Umbrella"),
    (r"(?i)webroot|malwarebytes|f-secure|withsecure|panda security",
     "agente di sicurezza per endpoint"),
)
SECURITY_AGENT_COMPILED = tuple((re.compile(e), n) for e, n in SECURITY_AGENT_PATTERNS)
# Espressione unica usata nelle regole del catalogo: la presenza di un agente e'
# prova a favore delle classi di endpoint e contraria a quelle degli apparati.
#
# I singoli pattern portano ciascuno il proprio '(?i)': unendoli senza rimuoverlo
# il flag finirebbe a meta' espressione, dove Python lo rifiuta. Si toglie dai
# pezzi e si mette una volta sola all'inizio.
AGENT_BANNER_PATTERN = "(?i)" + "|".join(
    e.replace("(?i)", "") for e, _ in SECURITY_AGENT_PATTERNS)

VIRTUAL_VENDOR_PATTERN = re.compile(
    r"(?i)vmware|virtualbox|innotek|parallels|qemu|xensource|microsoft corporation"
)


# --------------------------------------------------------------------------- #
# Catalogo delle firme
#
# Ogni classe dichiara le prove che la sostengono, con il rispettivo peso:
#   ports          {(protocollo, porta): peso}
#   services       {nome di servizio: peso}
#   os_types       {tipo dichiarato da nmap: peso}
#   os_families    {famiglia del sistema operativo: peso}
#   products       [(espressione su prodotto/versione, peso)]
#   mac_vendors    [(espressione sul produttore del MAC, peso)]
#   hostnames      [(espressione sul nome host, peso)]
#   banners        [(espressione sul banner annunciato dal servizio, peso)]
#   negative_banners [(espressione sul banner, peso negativo)]
#   scripts        [(nome script NSE, espressione sull'esito, peso)]
#   negative_ports {(protocollo, porta): peso negativo}
# --------------------------------------------------------------------------- #
DEVICE_CLASSES = [
    {
        "key": "printer",
        "label": "Stampante / multifunzione",
        "icon": "bi-printer",
        "ports": {("tcp", 9100): 5, ("tcp", 515): 4, ("tcp", 631): 4, ("tcp", 9101): 3,
                  ("tcp", 9102): 3, ("udp", 161): 1},
        "services": {"jetdirect": 5, "printer": 4, "ipp": 4, "hp-pdl-datastr": 5},
        "os_types": {"printer": 6},
        "products": [(r"(?i)\b(laserjet|officejet|deskjet|designjet)\b", 5),
                     (r"(?i)\b(kyocera|ricoh|lexmark|brother|epson|canon|xerox|konica|sharp|oki)\b", 4),
                     (r"(?i)cups", 2)],
        "mac_vendors": [(r"(?i)hewlett|kyocera|ricoh|lexmark|brother|seiko epson|canon|xerox|konica|sharp", 3)],
        "hostnames": [(r"(?i)^(npi|hp[a-f0-9]{6}|kyocera|ricoh|brn|canon|epson)", 2)],
        "banners": [(r"(?i)jetdirect|laserjet|officejet|kyocera|ricoh|lexmark|brother", 5),
                    (r"(?i)printer ready|pjl|postscript", 4)],
        "scripts": [("snmp-info", r"(?i)laserjet|printer|imagerunner|bizhub", 4)],
        # Un apparato incorporato non esegue un agente di sicurezza per endpoint.
        "negative_banners": [(AGENT_BANNER_PATTERN, -5)],
        "negative_ports": {("tcp", 3389): -4, ("tcp", 1433): -3, ("tcp", 3306): -3},
    },
    {
        "key": "nas",
        "label": "NAS / archiviazione",
        "icon": "bi-hdd-stack",
        "ports": {("tcp", 5000): 3, ("tcp", 5001): 3, ("tcp", 548): 3, ("tcp", 2049): 4,
                  ("tcp", 111): 2, ("tcp", 873): 3, ("tcp", 445): 1, ("tcp", 8200): 2},
        "services": {"nfs": 4, "afp": 3, "rsync": 3, "netbios-ssn": 1},
        "os_types": {"storage-misc": 5, "NAS device": 6},
        "products": [(r"(?i)synology|qnap|truenas|freenas|openmediavault|netatalk", 5),
                     (r"(?i)diskstation|rackstation", 5)],
        "mac_vendors": [(r"(?i)synology|qnap|western digital|buffalo|netgear.*storage|thecus", 4)],
        "banners": [(r"(?i)synology|qnap|diskstation|truenas|netatalk|unraid", 5)],
        "hostnames": [(r"(?i)(nas|diskstation|rackstation|storage)", 2)],
        # Un apparato incorporato non esegue un agente di sicurezza per endpoint.
        "negative_banners": [(AGENT_BANNER_PATTERN, -5)],
        "negative_ports": {("tcp", 9100): -3, ("tcp", 554): -2},
    },
    {
        "key": "router_gateway",
        "label": "Router / gateway",
        "icon": "bi-router",
        "ports": {("tcp", 53): 2, ("tcp", 7547): 5, ("tcp", 8291): 5, ("tcp", 4444): 1,
                  ("udp", 53): 2, ("udp", 67): 3, ("udp", 1900): 2},
        "services": {"domain": 2, "cwmp": 5, "upnp": 2, "dhcps": 3},
        "os_types": {"router": 6, "broadband router": 6, "WAP": 2},
        "products": [(r"(?i)mikrotik|routeros|openwrt|dd-wrt|pfsense|vyos|edgeos", 5),
                     (r"(?i)fritz!?box|draytek|zyxel|tp-link|netgear|asus.*router", 4)],
        "mac_vendors": [(r"(?i)mikrotik|avm gmbh|draytek|zyxel|tp-link|netgear|technicolor|sagemcom", 3)],
        "banners": [(r"(?i)routeros|mikrotik|openwrt|dropbear.*openwrt|edgeos|vyos", 5),
                    (r"(?i)fritz!?box|draytek|zyxel", 4)],
        "hostnames": [(r"(?i)(gw|gateway|router|fritz|rt-)", 2)],
        "scripts": [("snmp-info", r"(?i)routeros|ios|routing", 3)],
        # Un apparato incorporato non esegue un agente di sicurezza per endpoint.
        "negative_banners": [(AGENT_BANNER_PATTERN, -5)],
        "negative_ports": {("tcp", 9100): -4, ("tcp", 3389): -3},
    },
    {
        "key": "switch_managed",
        "label": "Switch gestito",
        "icon": "bi-diagram-3",
        "ports": {("tcp", 23): 2, ("tcp", 22): 1, ("udp", 161): 3, ("tcp", 80): 1},
        "services": {"snmp": 3, "telnet": 2},
        "os_types": {"switch": 7},
        "products": [(r"(?i)cisco ios|nx-os|junos|arubaos|procurve|comware|extremexos|dell emc networking", 6)],
        "mac_vendors": [(r"(?i)cisco|juniper|hewlett packard enterprise|aruba|extreme|brocade|arista", 3)],
        "banners": [(r"(?i)cisco|juniper|arubaos|procurve|comware|extremexos", 5),
                    (r"(?i)user access verification|press ret", 4)],
        "hostnames": [(r"(?i)(sw|switch|core|access)[-_0-9]", 2)],
        "scripts": [("snmp-info", r"(?i)cisco ios|junos|arubaos|procurve|comware|switch", 5)],
        # Un apparato incorporato non esegue un agente di sicurezza per endpoint.
        "negative_banners": [(AGENT_BANNER_PATTERN, -5)],
        "negative_ports": {("tcp", 9100): -4, ("tcp", 3389): -4, ("tcp", 445): -3},
    },
    {
        "key": "access_point",
        "label": "Punto di accesso",
        "icon": "bi-wifi",
        "ports": {("tcp", 8443): 2, ("tcp", 22): 1, ("udp", 161): 1, ("tcp", 80): 1},
        "os_types": {"WAP": 7},
        "products": [(r"(?i)unifi|ubiquiti|airos|ruckus|meraki|aruba instant|omada", 5)],
        "mac_vendors": [(r"(?i)ubiquiti|ruckus|cisco meraki|aruba|tp-link.*eap", 4)],
        "hostnames": [(r"(?i)(ap|wap|unifi|wifi)[-_0-9]", 2)],
        "negative_ports": {("tcp", 9100): -4, ("tcp", 3389): -3},
    },
    {
        "key": "firewall",
        "label": "Firewall / UTM",
        "icon": "bi-shield-lock",
        "ports": {("tcp", 4443): 3, ("tcp", 10443): 4, ("tcp", 8443): 1,
                  ("udp", 500): 3, ("udp", 4500): 3},
        "services": {"isakmp": 3},
        "os_types": {"firewall": 7},
        "products": [(r"(?i)fortigate|fortios|pfsense|opnsense|palo alto|pan-os|sonicwall|sophos|watchguard|checkpoint", 6)],
        "mac_vendors": [(r"(?i)fortinet|palo alto|sonicwall|sophos|watchguard|check point", 4)],
        "hostnames": [(r"(?i)(fw|firewall|utm|edge)[-_0-9]", 2)],
        "negative_ports": {("tcp", 9100): -4},
    },
    {
        "key": "ip_camera",
        "label": "Telecamera IP",
        "icon": "bi-camera-video",
        "ports": {("tcp", 554): 5, ("tcp", 8000): 2, ("tcp", 8899): 3, ("tcp", 37777): 5,
                  ("tcp", 80): 1},
        "services": {"rtsp": 5, "onvif": 5},
        "os_types": {"webcam": 7, "media device": 1},
        "products": [(r"(?i)hikvision|dahua|axis|vivotek|foscam|reolink|onvif|mobotix|dvrdvs", 5)],
        "mac_vendors": [(r"(?i)hangzhou hikvision|dahua|axis communications|vivotek|reolink|foscam", 4)],
        "banners": [(r"(?i)hikvision|dahua|axis|vivotek|onvif|rtsp/1\.0", 5)],
        "hostnames": [(r"(?i)(cam|camera|ipc|dvr|nvr)", 2)],
        # Un apparato incorporato non esegue un agente di sicurezza per endpoint.
        "negative_banners": [(AGENT_BANNER_PATTERN, -5)],
        "negative_ports": {("tcp", 3389): -4, ("tcp", 445): -3, ("tcp", 9100): -3},
    },
    {
        "key": "voip_phone",
        "label": "Telefono VoIP",
        "icon": "bi-telephone",
        "ports": {("tcp", 5060): 4, ("tcp", 5061): 3, ("udp", 5060): 5, ("tcp", 80): 1},
        "services": {"sip": 5},
        "os_types": {"VoIP phone": 7, "phone": 5},
        "products": [(r"(?i)yealink|grandstream|snom|polycom|fanvil|gigaset|cisco spa|aastra|mitel", 5)],
        "mac_vendors": [(r"(?i)yealink|grandstream|snom|polycom|fanvil|gigaset|mitel", 4)],
        "banners": [(r"(?i)yealink|grandstream|snom|polycom|fanvil|asterisk pbx", 5)],
        "hostnames": [(r"(?i)(sip|phone|tel)[-_0-9]", 2)],
        # Un apparato incorporato non esegue un agente di sicurezza per endpoint.
        "negative_banners": [(AGENT_BANNER_PATTERN, -5)],
        "negative_ports": {("tcp", 3389): -4, ("tcp", 445): -3, ("tcp", 5038): -3},
    },
    {
        "key": "pbx",
        "label": "Centralino telefonico",
        "icon": "bi-diagram-2",
        "ports": {("tcp", 5038): 5, ("tcp", 5060): 2, ("tcp", 8088): 2, ("udp", 5060): 2},
        "services": {"asterisk": 5},
        "os_types": {"PBX": 7},
        "products": [(r"(?i)asterisk|freepbx|3cx|issabel|elastix|kamailio", 6)],
        "hostnames": [(r"(?i)(pbx|centralino|asterisk)", 3)],
    },
    {
        "key": "hypervisor",
        "label": "Ipervisore",
        "icon": "bi-hdd-network",
        "ports": {("tcp", 902): 5, ("tcp", 903): 4, ("tcp", 5989): 4, ("tcp", 8006): 5,
                  ("tcp", 5900): 1, ("tcp", 443): 1},
        "services": {"vmware-auth": 5, "iss-realsecure": 1},
        "products": [(r"(?i)vmware esxi|vcenter|proxmox|xenserver|xcp-ng|hyper-v|nutanix", 6)],
        "os_families": {"vmkernel": 6, "esx server": 6},
        "hostnames": [(r"(?i)(esxi?|vmhost|pve|proxmox|hv)[-_0-9]", 3)],
        "negative_ports": {("tcp", 9100): -4, ("tcp", 554): -3},
    },
    {
        "key": "server_windows",
        "label": "Server Windows",
        "icon": "bi-server",
        "ports": {("tcp", 3389): 2, ("tcp", 445): 1, ("tcp", 135): 1, ("tcp", 389): 4,
                  ("tcp", 636): 3, ("tcp", 88): 4, ("tcp", 1433): 4, ("tcp", 25): 2,
                  ("tcp", 53): 2},
        "services": {"ldap": 4, "kerberos-sec": 4, "ms-sql-s": 4, "msrpc": 1},
        "os_families": {"windows": 2},
        "products": [(r"(?i)windows server|microsoft sql server|exchange|iis", 5),
                     (r"(?i)active directory", 5)],
        "hostnames": [(r"(?i)(srv|server|dc[0-9]|ad[0-9]|sql|exch)", 2)],
        "banners": [(r"(?i)microsoft-iis|microsoft ftp|microsoft esmtp", 4),
                    # Un agente per endpoint gira su una macchina di uso generale.
                    (AGENT_BANNER_PATTERN, 3)],
        "scripts": [("smb-os-discovery", r"(?i)windows server", 6)],
        "negative_ports": {("tcp", 9100): -3, ("tcp", 554): -3},
    },
    {
        "key": "server_unix",
        "label": "Server Linux / Unix",
        "icon": "bi-server",
        "ports": {("tcp", 22): 2, ("tcp", 80): 1, ("tcp", 443): 1, ("tcp", 3306): 4,
                  ("tcp", 5432): 4, ("tcp", 25): 2, ("tcp", 6379): 3, ("tcp", 27017): 3,
                  ("tcp", 8080): 1},
        "services": {"mysql": 4, "postgresql": 4, "redis": 3, "mongodb": 3, "ssh": 2},
        "os_families": {"linux": 2, "freebsd": 3, "openbsd": 3, "sunos": 3, "aix": 3},
        "products": [(r"(?i)nginx|apache httpd|openssh|postfix|mariadb|postgresql|tomcat|gunicorn", 3),
                     (r"(?i)ubuntu|debian|centos|red hat|rocky|almalinux|suse", 3)],
        "banners": [(r"(?i)openssh[^|]*(ubuntu|debian|centos|el[0-9]|rhel|suse)", 4),
                    (r"(?i)vsftpd|postfix|dovecot|apache/[0-9]|nginx/[0-9]", 3),
                    (AGENT_BANNER_PATTERN, 2)],
        "hostnames": [(r"(?i)(srv|server|web|db|app|node)[-_0-9]", 2)],
        "negative_ports": {("tcp", 9100): -3, ("tcp", 554): -3},
    },
    {
        "key": "workstation_windows",
        "label": "Postazione Windows",
        "icon": "bi-windows",
        "ports": {("tcp", 445): 2, ("tcp", 139): 2, ("tcp", 135): 2, ("tcp", 5357): 3,
                  ("udp", 137): 2, ("udp", 5353): 1},
        "services": {"netbios-ssn": 2, "microsoft-ds": 2, "wsdapi": 3},
        "os_families": {"windows": 3},
        "products": [(r"(?i)windows (7|8|10|11)\b", 5)],
        "hostnames": [(r"(?i)(pc|desktop|nb|lt|wks)[-_0-9]", 2)],
        "banners": [(AGENT_BANNER_PATTERN, 4)],
        "scripts": [("smb-os-discovery", r"(?i)windows (10|11)", 5)],
        "negative_ports": {("tcp", 1433): -3, ("tcp", 389): -4, ("tcp", 9100): -3,
                           ("tcp", 554): -3},
    },
    {
        "key": "workstation_mac",
        "label": "Postazione macOS",
        "icon": "bi-laptop",
        "ports": {("tcp", 5900): 3, ("tcp", 548): 3, ("tcp", 22): 1, ("tcp", 88): 1,
                  ("udp", 5353): 2},
        "services": {"rfb": 3, "afp": 3, "mdns": 2},
        "os_families": {"mac os x": 6, "macos": 6, "os x": 6, "darwin": 5},
        "products": [(r"(?i)apple (afp|remote desktop|os x|macos)", 5)],
        "banners": [(AGENT_BANNER_PATTERN, 2)],
        "mac_vendors": [(r"(?i)apple", 3)],
        # Un apparato incorporato non esegue un agente di sicurezza per endpoint.
        "negative_banners": [(AGENT_BANNER_PATTERN, -5)],
        "negative_ports": {("tcp", 3389): -3, ("tcp", 9100): -3},
    },
    {
        "key": "mobile",
        "label": "Dispositivo mobile",
        "icon": "bi-phone",
        "ports": {("udp", 5353): 2, ("tcp", 62078): 5},
        "services": {"iphone-sync": 5},
        "os_families": {"ios": 6, "android": 6, "linux 3.x": 0},
        "os_types": {"phone": 5, "media device": 1},
        "mac_vendors": [(r"(?i)apple|samsung electro|xiaomi|huawei|oneplus|oppo|vivo mobile", 2)],
        "hostnames": [(r"(?i)(iphone|ipad|android|galaxy|redmi)", 5)],
        "negative_ports": {("tcp", 22): -1, ("tcp", 445): -3, ("tcp", 3389): -3},
    },
    {
        "key": "plc_industrial",
        "label": "Apparato industriale / PLC",
        "icon": "bi-cpu",
        "ports": {("tcp", 502): 6, ("tcp", 102): 6, ("tcp", 44818): 6, ("tcp", 20000): 5,
                  ("tcp", 4840): 5, ("udp", 47808): 3, ("udp", 2222): 4},
        "services": {"modbus": 6, "iso-tsap": 6, "EtherNetIP-2": 6, "opcua": 5},
        "os_types": {"specialized": 3, "PLC": 7},
        "products": [(r"(?i)siemens|simatic|rockwell|allen-bradley|schneider|beckhoff|omron|mitsubishi electric", 5)],
        "mac_vendors": [(r"(?i)siemens|rockwell|schneider electric|beckhoff|omron|phoenix contact|wago", 4)],
        "negative_ports": {("tcp", 3389): -3, ("tcp", 9100): -3},
    },
    {
        "key": "ups",
        "label": "Gruppo di continuita'",
        "icon": "bi-battery-charging",
        "ports": {("tcp", 3493): 6, ("udp", 161): 2, ("tcp", 80): 1},
        "services": {"nut": 6},
        "os_types": {"power-device": 7},
        "products": [(r"(?i)\bapc\b|smart-?ups|eaton|riello|legrand|network management card", 5)],
        "mac_vendors": [(r"(?i)american power conversion|apc|eaton|riello|legrand|schneider.*apc", 4)],
        "banners": [(r"(?i)smart-?ups|powerchute|network management card|eaton", 5)],
        "hostnames": [(r"(?i)(ups|apc)[-_0-9]?", 3)],
        "scripts": [("snmp-info", r"(?i)ups|smart-?ups|powerchute", 5)],
        # Un apparato incorporato non esegue un agente di sicurezza per endpoint.
        "negative_banners": [(AGENT_BANNER_PATTERN, -5)],
        "negative_ports": {("tcp", 3389): -4, ("tcp", 445): -3},
    },
    {
        "key": "building_automation",
        "label": "Automazione dell'edificio",
        "icon": "bi-building-gear",
        "ports": {("udp", 47808): 6, ("udp", 3671): 6, ("tcp", 1911): 5, ("tcp", 4911): 4,
                  ("tcp", 80): 1},
        "services": {"bacnet": 6, "knx": 6, "niagara-fox": 5},
        "products": [(r"(?i)niagara|tridium|honeywell|johnson controls|carrier|bacnet|knx", 5)],
        "mac_vendors": [(r"(?i)honeywell|johnson controls|tridium|carrier|siemens building", 4)],
        "negative_ports": {("tcp", 3389): -3},
    },
    {
        "key": "media_device",
        "label": "Dispositivo multimediale",
        "icon": "bi-tv",
        "ports": {("tcp", 8008): 4, ("tcp", 8009): 4, ("tcp", 7000): 3, ("tcp", 32400): 5,
                  ("tcp", 1400): 4, ("udp", 1900): 2, ("udp", 5353): 1},
        "services": {"upnp": 2, "airplay": 4, "plex": 5},
        "os_types": {"media device": 6, "game console": 4},
        "products": [(r"(?i)chromecast|roku|sonos|apple tv|plex|kodi|shield|samsung tv|lg webos", 5)],
        "mac_vendors": [(r"(?i)sonos|roku|google|amazon technologies|samsung electronics|lg electronics", 2)],
        "hostnames": [(r"(?i)(tv|chromecast|roku|sonos|appletv|shield)", 3)],
        "negative_ports": {("tcp", 3389): -3, ("tcp", 9100): -3},
    },
    {
        "key": "sbc",
        "label": "Scheda a basso costo (SBC)",
        "icon": "bi-cpu-fill",
        "ports": {("tcp", 22): 2, ("tcp", 80): 1},
        "os_families": {"linux": 1},
        "mac_vendors": [(r"(?i)raspberry pi|beagleboard|orange pi|hardkernel|espressif|arduino", 6)],
        "banners": [(r"(?i)raspbian|raspberry|armbian|dietpi", 6)],
        "hostnames": [(r"(?i)(raspberry|rasp|rpi|orangepi|odroid|esp)", 4)],
        "negative_ports": {("tcp", 3389): -3, ("tcp", 1433): -3},
    },
]


# --------------------------------------------------------------------------- #
# Indici: costruiti una sola volta, permettono di attraversare le prove del nodo
# invece del catalogo (requisito di efficienza NFR-20).
# --------------------------------------------------------------------------- #
def _build_indexes(classes):
    porte, servizi, tipi, famiglie, contrarie = {}, {}, {}, {}, {}
    for classe in classes:
        chiave = classe["key"]
        for porta, peso in classe.get("ports", {}).items():
            porte.setdefault(porta, []).append((chiave, peso))
        for nome, peso in classe.get("services", {}).items():
            servizi.setdefault(nome.lower(), []).append((chiave, peso))
        for tipo, peso in classe.get("os_types", {}).items():
            tipi.setdefault(tipo.lower(), []).append((chiave, peso))
        for famiglia, peso in classe.get("os_families", {}).items():
            famiglie.setdefault(famiglia.lower(), []).append((chiave, peso))
        for porta, peso in classe.get("negative_ports", {}).items():
            contrarie.setdefault(porta, []).append((chiave, peso))
    return porte, servizi, tipi, famiglie, contrarie


PORT_INDEX, SERVICE_INDEX, OSTYPE_INDEX, OSFAMILY_INDEX, NEGATIVE_INDEX = _build_indexes(
    DEVICE_CLASSES
)
CLASSES_BY_KEY = {classe["key"]: classe for classe in DEVICE_CLASSES}


# --------------------------------------------------------------------------- #
# Normalizzazione delle prove
# --------------------------------------------------------------------------- #
def detect_security_agent(evidence: dict) -> dict:
    """Riconosce un agente di sicurezza per endpoint dai banner.

    Restituisce anche le porte su cui l'agente ha risposto: sono intercettate, e
    la loro etichetta di servizio non descrive il dispositivo.
    """
    trovato = None
    porte = set()
    for porta in evidence.get("ports") or []:
        banner = porta.get("banner")
        if not banner:
            continue
        for espressione, nome in SECURITY_AGENT_COMPILED:
            if espressione.search(str(banner)):
                trovato = trovato or nome
                try:
                    porte.add(((porta.get("protocol") or "tcp").lower(), int(porta.get("port"))))
                except (TypeError, ValueError):
                    pass
                break
    if not trovato:
        return {"detected": False, "agent": None, "ports": []}
    return {"detected": True, "agent": trovato,
            "ports": sorted("%s/%d" % p for p in porte),
            "evidence": "banner restituito dall'agente su %d porte" % len(porte)}


def _intercepted_ports(evidence: dict) -> set:
    """Porte su cui ha risposto un agente di sicurezza, non il servizio atteso."""
    intercettate = set()
    for porta in evidence.get("ports") or []:
        banner = porta.get("banner")
        if not banner:
            continue
        if any(e.search(str(banner)) for e, _ in SECURITY_AGENT_COMPILED):
            try:
                intercettate.add(((porta.get("protocol") or "tcp").lower(),
                                  int(porta.get("port"))))
            except (TypeError, ValueError):
                continue
    return intercettate


def _open_ports(evidence: dict) -> set:
    """Insieme delle porte aperte come coppie (protocollo, numero).

    Le porte intercettate da un agente di sicurezza sono escluse: sono aperte, ma
    a rispondere e' l'agente e il numero di porta non descrive alcun servizio del
    dispositivo.
    """
    intercettate = _intercepted_ports(evidence)
    aperte = set()
    for porta in evidence.get("ports") or []:
        if (porta.get("state") or "open") != "open":
            continue
        try:
            numero = int(porta.get("port"))
        except (TypeError, ValueError):
            continue  # porta non interpretabile: si ignora, non si indovina
        chiave = ((porta.get("protocol") or "tcp").lower(), numero)
        if chiave in intercettate:
            continue
        aperte.add(chiave)
    return aperte


def _service_names(evidence: dict) -> set:
    """Nomi di servizio delle porte aperte, escluse quelle intercettate."""
    intercettate = _intercepted_ports(evidence)
    nomi = set()
    for porta in evidence.get("ports") or []:
        if (porta.get("state") or "open") != "open":
            continue
        try:
            chiave = ((porta.get("protocol") or "tcp").lower(), int(porta.get("port")))
        except (TypeError, ValueError):
            chiave = None
        if chiave in intercettate:
            continue
        nome = (porta.get("service_name") or "").strip().lower()
        if nome:
            nomi.add(nome)
    return nomi


def _banner_text(evidence: dict) -> str:
    """Solo i banner, per le regole che li riguardano specificamente."""
    return " | ".join(str(p.get("banner")) for p in evidence.get("ports") or []
                      if p.get("banner"))


def _product_text(evidence: dict) -> str:
    """Prodotti, versioni, banner e CPE concatenati: unico testo per le espressioni."""
    pezzi = []
    for porta in evidence.get("ports") or []:
        # Il banner e' incluso: quando nmap non riconosce il prodotto, e' spesso
        # l'unico testo che dichiara la natura dell'apparato. Ne consegue che le
        # regole di prodotto e quelle sui firmware valgono anche sui banner.
        for campo in ("product", "version", "extrainfo", "banner"):
            valore = porta.get(campo)
            if valore:
                pezzi.append(str(valore))
        cpe = porta.get("cpe")
        if isinstance(cpe, (list, tuple)):
            pezzi.extend(str(c) for c in cpe)
        elif cpe:
            pezzi.append(str(cpe))
    sistema = evidence.get("os") or {}
    for campo in ("name", "vendor", "family", "gen"):
        valore = sistema.get(campo)
        if valore:
            pezzi.append(str(valore))
    cpe = sistema.get("cpe")
    if isinstance(cpe, (list, tuple)):
        pezzi.extend(str(c) for c in cpe)
    return " | ".join(pezzi)


def detect_virtualization(evidence: dict) -> dict:
    """Riconosce un ambiente virtuale dal MAC o dal produttore dichiarato.

    La virtualizzazione e' un attributo del nodo, non un tipo di dispositivo: un
    server Windows resta tale anche sotto un ipervisore. Per questo non entra nel
    punteggio delle classi.
    """
    mac = (evidence.get("mac") or "").lower().replace("-", ":")
    prefisso = mac[:8]
    if prefisso in VIRTUAL_MAC_PREFIXES:
        return {"virtualized": True, "platform": VIRTUAL_MAC_PREFIXES[prefisso],
                "evidence": "prefisso MAC %s" % prefisso}
    vendor = evidence.get("mac_vendor") or ""
    trovato = VIRTUAL_VENDOR_PATTERN.search(vendor)
    if trovato and "microsoft" not in trovato.group(0).lower():
        return {"virtualized": True, "platform": trovato.group(0),
                "evidence": "produttore MAC %s" % vendor}
    return {"virtualized": False, "platform": None, "evidence": None}


# --------------------------------------------------------------------------- #
# Stadio 1 - Regole decisive
#
# Combinazioni non ambigue: quando una scatta il verdetto e' immediato. Sono
# poche per scelta, e ciascuna dichiara la ragione che verra' mostrata.
# --------------------------------------------------------------------------- #
def _web_dichiarazioni(evidence) -> list:
    """Le letture web del nodo, come elenco di dichiarazioni."""
    letture = evidence.get("web")
    return [v for v in (letture or []) if isinstance(v, dict)]


def _web_testo(evidence) -> str:
    """Tutto cio' che le pagine dichiarano, in un testo unico su cui cercare."""
    pezzi = []
    for voce in _web_dichiarazioni(evidence):
        for campo in ("title", "server", "generator", "realm", "brand", "model",
                      "product", "cert_subject", "cert_issuer",
                      # Cio' che l'apparato scrive di se' vale piu' di cio' che si
                      # deduce: "RICOH MP C4504ex" e' una dichiarazione.
                      "device_name", "firmware"):
            valore = voce.get(campo)
            if valore:
                pezzi.append(str(valore))
    return " \n".join(pezzi)


def _decisive_rules(evidence, aperte, servizi, prodotti):
    sistema = evidence.get("os") or {}
    tipo_nmap = (sistema.get("type") or "").lower()
    script = {k.lower(): (v or "") for k, v in (evidence.get("scripts") or {}).items()}

    if tipo_nmap == "printer" and aperte & {("tcp", 9100), ("tcp", 515), ("tcp", 631)}:
        return ("printer", 97, "nmap dichiara una stampante e una porta di stampa e' aperta")

    if re.search(r"(?i)vmware esxi|vcenter server", prodotti) or ("tcp", 8006) in aperte:
        return ("hypervisor", 96, "prodotto di virtualizzazione esposto in rete")

    # Nomi di firmware inequivocabili: dichiarano da soli la natura
    # dell'apparato, indipendentemente dalle porte esposte. Un apparato OpenWrt
    # che mostra solo ssh e la propria interfaccia web resta un apparato di rete,
    # e senza questa regola verrebbe letto come un generico server Linux.
    for espressione, classe, motivo in FIRMWARE_RULES:
        if re.search(espressione, prodotti):
            return (classe, 94, motivo)

    if aperte & {("tcp", 502), ("tcp", 102), ("tcp", 44818)}:
        return ("plc_industrial", 95, "protocollo industriale attivo (Modbus, S7 o EtherNet/IP)")

    if ("tcp", 3493) in aperte or re.search(r"(?i)smart-?ups|powerchute", prodotti):
        return ("ups", 94, "servizio di gruppo di continuita' esposto")

    # Una pagina di gestione che si presenta con marca e modello e' una
    # dichiarazione dell'apparato, non un indizio: quando la firma riconosce un
    # genere, vale come la dichiarazione SNMP. Il tipo lo ha deciso il catalogo delle
    # firme (web_probe), che e' dichiarato e verificabile.
    for voce in _web_dichiarazioni(evidence):
        genere = (voce.get("device_type") or "").strip()
        if not genere or genere not in CLASSES_BY_KEY:
            continue
        # Se l'apparato ha dichiarato il proprio nome, la motivazione lo cita
        # testualmente: e' verificabile aprendo quella pagina.
        dichiarato = (voce.get("device_name") or "").strip()
        if dichiarato:
            return (genere, 95,
                    "l'apparato dichiara di se' \"%s\" nella propria pagina di"
                    " gestione sulla porta %s" % (dichiarato, voce.get("port")))
        marca = voce.get("brand") or voce.get("product") or "la pagina di gestione"
        modello = (" " + voce["model"]) if voce.get("model") else ""
        return (genere, 93,
                "l'interfaccia web sulla porta %s si presenta come %s%s"
                % (voce.get("port"), marca, modello))

    for nome, testo in script.items():
        if nome == "snmp-info" and re.search(r"(?i)cisco ios|junos|arubaos|procurve|comware", testo):
            return ("switch_managed", 95, "SNMP dichiara un sistema operativo di apparato di rete")
        if nome == "smb-os-discovery" and re.search(r"(?i)windows server", testo):
            return ("server_windows", 93, "SMB dichiara un sistema operativo Windows Server")

    if ("tcp", 37777) in aperte or "onvif" in servizi:
        return ("ip_camera", 93, "protocollo di videosorveglianza attivo")

    return None


# --------------------------------------------------------------------------- #
# Stadio 2 e 3 - Punteggio
# --------------------------------------------------------------------------- #
# TTL iniziali noti e la famiglia OS che indicano. Il TTL osservato e' quello iniziale
# meno il numero di salti (hop) del percorso, sempre piccolo: si arrotonda in su al
# primo TTL iniziale >= osservato.
INITIAL_TTLS = (64, 128, 255)
# Che cosa suggerisce ciascun TTL iniziale: descrizione leggibile e classi con un peso
# basso (il segnale e' debole e non deve decidere da solo).
TTL_HINTS = {
    64: {"descrizione": "Linux / Android / macOS / iOS / FreeBSD",
         "classi": (("server_unix", 1.0), ("workstation_mac", 0.6),
                    ("mobile", 0.6), ("nas", 0.5))},
    128: {"descrizione": "Windows recente",
          "classi": (("workstation_windows", 1.5), ("server_windows", 1.0))},
    255: {"descrizione": "apparato di rete (Cisco IOS e simili)",
          "classi": (("router_gateway", 1.5), ("switch_managed", 1.0),
                     ("firewall", 0.8))},
}


def os_family_from_ttl(ttl) -> dict | None:
    """La famiglia OS suggerita dal TTL osservato, o None.

    Arrotonda il TTL osservato in su al TTL iniziale (64/128/255) e restituisce la
    descrizione leggibile e le classi con il loro peso. E' un indizio debole: NAT e
    firewall riscrivono il TTL, quindi il chiamante lo usa solo come nudge.
    """
    if ttl is None:
        return None
    try:
        valore = int(ttl)
    except (TypeError, ValueError):
        return None
    if valore <= 0 or valore > 255:
        return None
    iniziale = next((v for v in INITIAL_TTLS if valore <= v), None)
    return TTL_HINTS.get(iniziale)


def _score(evidence, aperte, servizi, prodotti):
    """Punteggi per classe e prove che li hanno prodotti."""
    punteggi = {}
    prove = {}
    generi = {}

    def aggiungi(chiave, peso, motivo, genere):
        punteggi[chiave] = punteggi.get(chiave, 0.0) + peso
        prove.setdefault(chiave, []).append({"peso": peso, "prova": motivo, "genere": genere})
        # I generi distinti misurano la varieta' delle prove, non la loro
        # quantita': e' cio' che distingue un indizio ripetuto da piu' indizi
        # indipendenti che convergono.
        if peso > 0:
            generi.setdefault(chiave, set()).add(genere)

    # Stadio indicizzato: si attraversano le prove, non il catalogo.
    for porta in aperte:
        for chiave, peso in PORT_INDEX.get(porta, ()):
            aggiungi(chiave, peso, "porta %s/%d aperta" % (porta[0], porta[1]), "porta")
        for chiave, peso in NEGATIVE_INDEX.get(porta, ()):
            aggiungi(chiave, peso, "porta %s/%d aperta (prova contraria)" % (porta[0], porta[1]),
                     "contraria")
    for nome in servizi:
        for chiave, peso in SERVICE_INDEX.get(nome, ()):
            aggiungi(chiave, peso, "servizio %s" % nome, "servizio")

    sistema = evidence.get("os") or {}
    tipo = (sistema.get("type") or "").strip().lower()
    if tipo:
        for chiave, peso in OSTYPE_INDEX.get(tipo, ()):
            aggiungi(chiave, peso, "nmap dichiara il tipo '%s'" % tipo, "tipo dichiarato")
    famiglia = (sistema.get("family") or "").strip().lower()
    if famiglia:
        for chiave, peso in OSFAMILY_INDEX.get(famiglia, ()):
            aggiungi(chiave, peso, "famiglia del sistema operativo '%s'" % famiglia,
                     "sistema operativo")
    elif evidence.get("ttl"):
        # Indizio DEBOLE dal TTL: il TTL osservato, arrotondato in su al TTL iniziale
        # (64 Linux/Android/macOS/iOS/FreeBSD, 128 Windows recente, 255 Cisco/IOS),
        # suggerisce la famiglia del sistema operativo. Pesa poco -- NAT e firewall
        # riscrivono il TTL, e il valore da solo non basta a decidere (resta sotto la
        # soglia minima) -- e si usa SOLO quando nmap non ha determinato la famiglia.
        ipotesi = os_family_from_ttl(evidence.get("ttl"))
        if ipotesi:
            motivo = "TTL osservato %d: compatibile con %s" % (
                int(evidence["ttl"]), ipotesi["descrizione"])
            for chiave, peso in ipotesi["classi"]:
                aggiungi(chiave, peso, motivo, "TTL")

    banner = _banner_text(evidence)

    # Stadio a espressioni: normalmente solo sulle classi rimaste candidate.
    #
    # Con prove deboli, pero', si valutano TUTTE le classi: una classe
    # identificabile soltanto dal nome del prodotto o del sistema operativo -- un
    # apparato OpenWrt che espone solo ssh e la propria interfaccia web, per dire
    # -- non diventerebbe mai candidata nello stadio indicizzato, e resterebbe
    # invisibile. Il costo e' una ventina di espressioni regolari, pagate solo
    # quando le prove indicizzate non bastano.
    candidate = [c for c, p in punteggi.items() if p > 0]
    if not candidate or max(punteggi.values()) <= CERTAINTY_SCORE / 2:
        candidate = list(CLASSES_BY_KEY)
    if banner:
        # Le regole sui banner si valutano su TUTTE le classi, non solo sulle
        # candidate: un banner e' una prova forte e sparsa, e una classe il cui
        # punteggio indicizzato e' stato annullato dalle prove contrarie non
        # arriverebbe mai a essere valutata. Accaduto davvero con l'agente di
        # sicurezza su una porta di stampa: la postazione restava a zero e la
        # stampante vinceva.
        candidate = sorted(set(candidate) | set(CLASSES_BY_KEY))
    vendor = evidence.get("mac_vendor") or ""
    hostname = evidence.get("hostname") or ""
    script = {k.lower(): (v or "") for k, v in (evidence.get("scripts") or {}).items()}

    for chiave in candidate:
        classe = CLASSES_BY_KEY[chiave]
        for espressione, peso in classe.get("products", ()):
            if prodotti and re.search(espressione, prodotti):
                aggiungi(chiave, peso, "prodotto riconosciuto", "prodotto")
        for espressione, peso in classe.get("banners", ()):
            if banner and re.search(espressione, banner):
                aggiungi(chiave, peso, "banner del servizio riconosciuto", "banner")
        for espressione, peso in classe.get("negative_banners", ()):
            if banner and re.search(espressione, banner):
                aggiungi(chiave, peso, "banner incompatibile con questa classe",
                         "contraria")
        for espressione, peso in classe.get("mac_vendors", ()):
            if vendor and re.search(espressione, vendor):
                aggiungi(chiave, peso, "produttore del MAC: %s" % vendor, "produttore")
        for espressione, peso in classe.get("hostnames", ()):
            if hostname and re.search(espressione, hostname):
                aggiungi(chiave, peso, "nome host: %s" % hostname, "nome host")
        for nome, espressione, peso in classe.get("scripts", ()):
            testo = script.get(nome.lower())
            if testo and re.search(espressione, testo):
                aggiungi(chiave, peso, "esito dello script %s" % nome, "script")

    return punteggi, prove, generi


def _confidence(migliore: float, seconda: float, generi: int) -> int:
    """Confidenza da quantita' delle prove, loro varieta' e margine.

    Tre componenti, perche' due non bastavano: con la sola somma dei pesi una
    singola osservazione (una porta e il servizio che le corrisponde) saturava la
    soglia e produceva un verdetto certo. La varieta' dei generi di prova
    distingue un indizio ripetuto da piu' indizi indipendenti che convergono.

    Un nodo con molte prove ma due classi appaiate riceve comunque confidenza
    bassa: e' esattamente il caso che va mandato all'approfondimento della fase 5.
    """
    if migliore <= 0:
        return 0
    abbondanza = min(1.0, migliore / CERTAINTY_SCORE)
    varieta = min(1.0, generi / float(CERTAINTY_GENRES))
    margine = max(0.0, (migliore - max(seconda, 0.0)) / migliore)
    valore = 100 * (0.45 * abbondanza + 0.30 * varieta + 0.25 * margine)
    return min(MAX_SCORED_CONFIDENCE, int(round(valore)))


def identify(evidence: dict) -> dict:
    """Determina il tipo di dispositivo dalle prove raccolte su un nodo.

    Restituisce sempre un verdetto: 'unknown' quando le prove non bastano, che e'
    un'informazione utile e non un fallimento.
    """
    aperte = _open_ports(evidence)
    servizi = _service_names(evidence)
    prodotti = _product_text(evidence)
    virtuale = detect_virtualization(evidence)
    agente = detect_security_agent(evidence)

    decisiva = _decisive_rules(evidence, aperte, servizi, prodotti)
    if decisiva is not None:
        chiave, confidenza, motivo = decisiva
        classe = CLASSES_BY_KEY[chiave]
        return {
            "device_type": chiave,
            "device_label": classe["label"],
            "icon": classe["icon"],
            "confidence": confidenza,
            "catalog_version": CATALOG_VERSION,
            "decided_by": "regola decisiva",
            "evidence": [{"peso": None, "prova": motivo}],
            "scores": {},
            "virtualization": virtuale,
            "security_agent": agente,
        }

    punteggi, prove, generi = _score(evidence, aperte, servizi, prodotti)
    ordinati = sorted(punteggi.items(), key=lambda voce: voce[1], reverse=True)
    migliore = ordinati[0] if ordinati else None
    seconda = ordinati[1][1] if len(ordinati) > 1 else 0.0

    if migliore is None or migliore[1] < MINIMUM_SCORE:
        return {
            "device_type": UNKNOWN["key"],
            "device_label": UNKNOWN["label"],
            "icon": UNKNOWN["icon"],
            "confidence": 0,
            "catalog_version": CATALOG_VERSION,
            "decided_by": "prove insufficienti",
            "evidence": prove.get(migliore[0], []) if migliore else [],
            "scores": {c: round(p, 2) for c, p in ordinati[:5]},
            "virtualization": virtuale,
            "security_agent": agente,
        }

    chiave, punteggio = migliore
    classe = CLASSES_BY_KEY[chiave]
    return {
        "device_type": chiave,
        "device_label": classe["label"],
        "icon": classe["icon"],
        "confidence": _confidence(punteggio, seconda, len(generi.get(chiave, ()))),
        "catalog_version": CATALOG_VERSION,
        "decided_by": "punteggio",
        "evidence": sorted(prove.get(chiave, []), key=lambda v: v["peso"], reverse=True),
        "scores": {c: round(p, 2) for c, p in ordinati[:5]},
        "virtualization": virtuale,
        "security_agent": agente,
    }


def needs_deep_scan(verdict: dict, threshold: int = 60) -> bool:
    """Indica se il nodo va approfondito nella fase 5 (UDP e script mirati)."""
    return verdict.get("device_type") == UNKNOWN["key"] or verdict.get("confidence", 0) < threshold
