# -----------------------------------------------------------------
# web_facts.py — lettura del contenuto di una pagina di apparato: fatti e navigazione
# Autore: Daniele Speziale
# Data creazione: 2026-08-31
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap probe - Che cosa dice di se' la pagina di un apparato.

Perche' esiste questo modulo
----------------------------
La radice di un apparato spesso non contiene niente. L'esempio che ha guidato questo
lavoro e' una multifunzione Ricoh: `http://10.10.25.21/` restituisce 577 byte con un
`meta refresh`, un `location.href` in JavaScript e il titolo "Web Image Monitor" --
nessuna marca, nessun modello. Il modello, la posizione fisica e il nome host stanno
tre pagine piu' avanti, dentro un frame (`mainFrame.cgi` -> `topPage.cgi`), scritti
come coppie etichetta/valore in italiano:

    Nome dispositivo : RICOH MP C4504ex
    Posizione        : ED A PIANO -1 DIETRO AULA
    Nome host        : crl-AS1-st0018

Leggere solo la radice significa non sapere nulla di un apparato che dichiara tutto.

Due mestieri, tenuti separati
-----------------------------
* **estrarre**: da un testo HTML ricavare i fatti (funzioni pure, nessuna rete: si
  provano su file salvati, ed e' l'unico modo di collaudare un parser);
* **navigare**: da un testo HTML ricavare gli indirizzi da leggere dopo.

Il traffico e la sicurezza stanno in `web_probe`, che usa questo modulo.

Regole che questo modulo non tradisce
-------------------------------------
* il **contenuto della pagina non viene mai restituito**: solo i fatti riconosciuti,
  ciascuno corto e ripulito (GDPR art. 5, minimizzazione);
* si accettano soltanto le etichette del vocabolario: un parser che prendesse
  "qualunque coppia con i due punti" riempirebbe l'inventario di rumore e di dati
  personali non richiesti (nomi di persone nei campi "contatto" liberi);
* un valore segnaposto ("-", "non impostato", "unknown") vale come assente: registrarlo
  sarebbe peggio che non averlo, perche' sembrerebbe un dato.
"""

from __future__ import annotations

import html
import re
from urllib.parse import urljoin, urlsplit

# --------------------------------------------------------------------------- #
# Limiti
# --------------------------------------------------------------------------- #
MAX_VALORE = 120        # un valore piu' lungo non e' un'etichetta, e' un testo
MAX_TOKEN = 400         # oltre questo, un frammento di pagina non e' un'etichetta
MAX_FATTI = 12
MAX_BERSAGLI = 8        # indirizzi proposti da una singola pagina

# Valori che dicono "vuoto" in cinque lingue e in tre convenzioni.
SEGNAPOSTO = {
    "", "-", "--", "---", ":", "n/a", "n.a.", "na", "none", "null", "nil", "0",
    "not set", "not specified", "not configured", "unknown", "undefined", "empty",
    "non impostato", "non specificato", "non configurato", "sconosciuto", "vuoto",
    "nessuno", "nessuna", "non disponibile", "no", "off",
    "nicht festgelegt", "unbekannt", "keine",
    "non defini", "non defini(e)", "inconnu", "aucun",
    "no establecido", "desconocido", "ninguno",
}

# --------------------------------------------------------------------------- #
# Vocabolario delle etichette
# --------------------------------------------------------------------------- #
# Una voce per fatto: l'ordine conta, la prima etichetta che corrisponde vince.
# Le etichette sono espressioni regolari ancorate (vedi `_ETICHETTA`), non
# sottostringhe: "modello" non deve prendere "modello di stampa a colori".
ETICHETTE = (
    ("nome_dispositivo", (
        r"nome (?:del )?dispositivo", r"device name", r"nome (?:della )?stampante",
        r"printer name", r"unit name", r"system name", r"nome sistema",
        r"nom (?:du )?(?:p[ée]riph[ée]rique|appareil)", r"ger[äa]tename",
        r"nombre del dispositivo", r"nome apparato", r"nome macchina",
        r"machine name", r"nome unit[àa]",
    )),
    ("modello", (
        r"modello", r"model(?: name| number| no\.?)?", r"nome modello",
        r"product name", r"nome prodotto", r"machine model", r"printer model",
        r"mod[èe]le", r"modell", r"modelo", r"tipo(?: di)? dispositivo",
        r"device model", r"type/model", r"prodotto",
    )),
    ("posizione", (
        r"posizione", r"location", r"device location", r"installed location",
        r"ubicazione", r"emplacement", r"standort", r"ubicaci[óo]n",
        r"syslocation", r"posizione (?:del )?dispositivo",
    )),
    ("nome_host", (
        r"nome host", r"host ?name", r"nome (?:del )?computer", r"nom d'h[ôo]te",
        r"hostname", r"nombre de host", r"nome nodo", r"node name",
    )),
    ("seriale", (
        r"(?:numero|nr\.?|n\.?) (?:di )?serie", r"serial(?: number| no\.?)?",
        r"num[ée]ro de s[ée]rie", r"seriennummer", r"n[úu]mero de serie",
        r"machine serial", r"service tag", r"matricola",
    )),
    ("firmware", (
        r"(?:versione )?firmware", r"firmware(?: version| revision)?",
        r"versione software", r"software version", r"system version",
        r"versione (?:del )?sistema", r"version (?:du )?firmware",
        r"firmware-?version", r"versi[óo]n de firmware", r"bios version",
        r"versione applicativo",
    )),
    ("mac", (
        r"indirizzo mac", r"mac ?address", r"adresse mac", r"mac-?adresse",
        r"direcci[óo]n mac", r"ethernet address", r"indirizzo fisico",
    )),
    ("contatto", (
        r"contatto", r"contact(?: person| name)?", r"persona di contatto",
        r"kontakt", r"contacto", r"syscontact", r"amministratore(?: di sistema)?",
        r"referente",
    )),
    ("commento", (
        r"commento", r"comment(?:s)?", r"commentaire", r"kommentar", r"comentario",
        r"note", r"annotazione",
    )),
)

# Marche riconosciute dentro un nome dispositivo o un titolo. Il nome canonico e'
# quello a destra: "RICOH" e "Ricoh" devono diventare la stessa cosa, altrimenti
# l'inventario mostra due produttori dove ce n'e' uno.
MARCHE = (
    (r"ricoh|lanier|savin|nashuatec|infotec|gestetner|rex[- ]?rotary", "Ricoh"),
    (r"hewlett[- ]?packard|\bhp\b|laserjet|officejet|designjet|pagewide", "HP"),
    (r"kyocera|taskalfa|ecosys", "Kyocera"),
    (r"konica[- ]?minolta|bizhub", "Konica Minolta"),
    (r"canon|imagerunner|image ?class|imagepress", "Canon"),
    (r"\bepson\b|workforce|ecotank", "Epson"),
    (r"\bbrother\b", "Brother"),
    (r"lexmark", "Lexmark"),
    (r"\bxerox\b|workcentre|versalink|altalink|phaser", "Xerox"),
    (r"\bsharp\b", "Sharp"),
    (r"toshiba|e-?studio", "Toshiba"),
    (r"\boki\b|okidata", "OKI"),
    (r"\bzebra\b", "Zebra"),
    (r"\bdell\b", "Dell"),
    (r"fujitsu|fuji ?xerox", "Fujitsu"),
    (r"samsung", "Samsung"),
    (r"\bapc\b|schneider ?electric", "Schneider Electric"),
    (r"eaton\b", "Eaton"),
    (r"riello ?ups|riello", "Riello"),
    (r"axis communications|\baxis\b", "Axis"),
    (r"hikvision", "Hikvision"),
    (r"dahua", "Dahua"),
    (r"mobotix", "Mobotix"),
    (r"synology", "Synology"),
    (r"qnap", "QNAP"),
    (r"netgear", "NETGEAR"),
    (r"\btp-?link\b", "TP-Link"),
    (r"\bcisco\b", "Cisco"),
    (r"aruba networks|\bhpe aruba\b", "Aruba"),
    (r"ubiquiti|unifi", "Ubiquiti"),
    (r"mikrotik|routeros", "MikroTik"),
    (r"fortinet|fortigate", "Fortinet"),
    (r"sophos", "Sophos"),
    (r"watchguard", "WatchGuard"),
    (r"sonicwall", "SonicWall"),
    (r"supermicro", "Supermicro"),
    (r"lenovo|thinksystem", "Lenovo"),
    (r"siemens|simatic", "Siemens"),
    (r"schneider|modicon", "Schneider Electric"),
    (r"rockwell|allen[- ]?bradley", "Rockwell"),
    (r"phoenix ?contact", "Phoenix Contact"),
    (r"beckhoff", "Beckhoff"),
    (r"wago", "WAGO"),
    (r"vmware|esxi", "VMware"),
    (r"proxmox", "Proxmox"),
    (r"idrac|poweredge", "Dell"),
    (r"\bilo\b|integrated lights-?out|proliant", "HP"),
    # Vertiv (gia' Emerson Network Power): web card IntelliSlot e unita' Liebert
    # (UPS e raffreddamento di precisione, i "gruppi frigo" dei datacenter).
    (r"vertiv|emerson network power|intellislot|is-?unity|liebert", "Vertiv"),
    (r"\bcarel\b", "CAREL"),
    (r"\bdanfoss\b", "Danfoss"),
)

# Modelli riconoscibili senza etichetta: la sigla stessa dice l'apparato.
MODELLI = (
    r"(?:MP|IM|SP|Pro)\s?C?\d{3,4}[A-Za-z]{0,3}",          # Ricoh
    r"(?:TASKalfa|ECOSYS)\s?[\w\-]{2,14}",                  # Kyocera
    r"bizhub\s?[\w\-]{2,12}",                               # Konica Minolta
    r"(?:LaserJet|OfficeJet|DesignJet|PageWide)[\w\s\-\.]{0,20}",
    r"(?:WorkCentre|VersaLink|AltaLink|Phaser)\s?[\w\-]{2,12}",
    r"e-?STUDIO\s?[\w\-]{2,12}",                            # Toshiba
    r"imageRUNNER(?:\s?ADVANCE)?\s?[\w\-]{2,14}",           # Canon
    r"(?:MX|BP)-[\w]{3,10}",                                # Sharp
    r"IntelliSlot(?:\s+(?:Unity|Web\s+Card|IS-?UNITY))?",   # Vertiv/Emerson web card
    r"IS-?UNITY(?:[-_][\w.]{1,20})?",                       # Vertiv IntelliSlot Unity
    r"CP-\d{3,4}[A-Z]{0,2}",                                # Cisco Unified IP Phone
)

# --------------------------------------------------------------------------- #
# Espressioni
# --------------------------------------------------------------------------- #
RE_SCRIPT = re.compile(r"(?is)<(script|style|noscript)[^>]*>.*?</\1\s*>")
RE_COMMENTO_HTML = re.compile(r"(?s)<!--.*?-->")
RE_TAG = re.compile(r"(?s)<[^>]+>")
RE_SPAZI = re.compile(r"\s+")
RE_META_REFRESH = re.compile(
    r"""(?is)<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*"""
    r"""content\s*=\s*["']([^"']{1,300})["']""")
RE_JS_LOCATION = re.compile(
    r"""(?is)(?:(?:window\s*\.\s*)?location\s*(?:\.\s*href\s*)?=|"""
    r"""location\s*\.\s*(?:replace|assign)\s*\()\s*["']([^"'\s]{1,300})["']""")
RE_FRAME = re.compile(r"""(?is)<(?:i?frame)[^>]+src\s*=\s*["']?([^"'\s>]{1,300})""")
# Alcune famiglie scrivono la versione del firmware in una variabile JavaScript invece
# che in un'etichetta: i web card Vertiv/Emerson IntelliSlot espongono
# `var fwLabel = "IS-UNITY_5.0.0.0_91932"`. Si riconosce la forma, non si esegue nulla.
RE_FW_LABEL = re.compile(
    r"""(?i)fwLabel\s*=\s*["'](IS-?UNITY[_-][\d.]+)_(\d{3,})["']""")
RE_ANCORA = re.compile(
    r"""(?is)<a[^>]+href\s*=\s*["']?([^"'\s>]{1,300})["']?[^>]*>(.{0,120}?)</a>""")

# Una GET su un apparato non e' innocua se il progettista ha messo un'azione dietro un
# collegamento. Ma la prudenza va calibrata, altrimenti diventa cecita': la prima
# versione di questo elenco conteneva "start" e scartava `Start_Wlm.htm`, che e' la
# pagina iniziale delle Kyocera -- si perdevano modello e posizione di decine di
# apparati per una parola. Stesso caso con "initialize": `web/initialize.htm` e' la
# landing page dei web card Vertiv/Emerson IntelliSlot (un redirect, non un'azione), e
# scartarla lasciava il gruppo frigo classificato come un generico server Linux.
#
# Quindi due elenchi:
# * VERBI_DISTRUTTIVI: mai, in nessuna forma. Sono azioni che si riconoscono dal nome
#   e non esistono come pagine da consultare;
# * VERBI_CON_EFFETTO: solo se l'indirizzo ha dei parametri. `settings.htm` e' una
#   pagina, `cgi?set=1` e' un comando -- e la differenza sta nella coda. "initialize"
#   sta qui: `initialize.htm` (senza coda) e' una pagina, `initialize?...` un comando.
VERBI_DISTRUTTIVI = re.compile(
    r"(?i)(reboot|restart|shutdown|poweroff|power_?off|halt|format|erase|wipe|"
    r"delete|remove|purge|factory|firmware.?up|upgrade|logout|logoff|signout|"
    r"sign_?out|shred|clear_?(?:log|all|counter)|reset)")
VERBI_CON_EFFETTO = re.compile(
    r"(?i)(enable|disable|apply|commit|save|set_?|write|cancel|abort|install|update|"
    r"start|stop|test_?print|print_?test|calibrat|unlock|reboot|restart|initiali[sz]e)")
# Nome conservato per compatibilita' con chi lo importa: vale il caso distruttivo.
VERBI_PERICOLOSI = VERBI_DISTRUTTIVI

# Collegamenti che valgono la pena di essere seguiti quando i fatti mancano: sono le
# pagine che gli apparati chiamano "informazioni" o "stato".
ANCORE_UTILI = re.compile(
    r"(?i)(informazioni|informazione|device ?info|deviceinformation|dispositivo|"
    r"stato/informazioni|status|stato|system|sistema|about|riepilogo|summary|"
    r"identific|home|toppage|top_?page|main|index|overview|panoramica|"
    r"configuraz|configuration|properties|propriet)")


# Pagine di servizio: esistono per dire al browser che manca qualcosa. Si leggono per
# ultime, perche' occupano il budget senza portare un fatto.
POCO_UTILI = re.compile(
    r"(?i)(javascriptoff|jsoff|cookieoff|nocookie|nosupport|browsercheck|unsupported|"
    r"error|errore|help|guida|manual|licen[sz]|copyright|privacy)")


def _ancorata(etichetta: str) -> re.Pattern:
    """Etichetta come espressione ancorata, tollerante su punteggiatura e spazi."""
    return re.compile(r"(?i)^[\s\W]{0,4}%s[\s\W]{0,4}$" % etichetta)


_ETICHETTA = tuple((chiave, tuple(_ancorata(e) for e in espressioni))
                   for chiave, espressioni in ETICHETTE)
# Forma "etichetta: valore" dentro un unico frammento.
_ETICHETTA_INLINE = tuple(
    (chiave, tuple(re.compile(r"(?i)(?:^|[>\| \s])%s\s*[::]\s*(.{1,160})$" % e)
                   for e in espressioni))
    for chiave, espressioni in ETICHETTE)


# --------------------------------------------------------------------------- #
# Testo
# --------------------------------------------------------------------------- #
def pulisci(valore) -> str:
    """Valore ripulito e accorciato, oppure stringa vuota se non e' un valore.

    Un valore che contiene ancora marcatura o uno schema `javascript:` non e' un dato
    letto male: e' un pezzo di pagina finito dove non doveva, e va scartato.
    """
    if valore is None:
        return ""
    testo = html.unescape(str(valore))
    testo = testo.replace(" ", " ").replace("　", " ")
    testo = testo.lstrip(" :\t\r\n-–—")
    testo = RE_SPAZI.sub(" ", testo).strip()
    if not testo or len(testo) > MAX_VALORE:
        return testo[:MAX_VALORE].strip() if testo else ""
    if "<" in testo or ">" in testo:
        return ""
    if re.search(r"(?i)javascript:|function\s*\(|=\s*['\"]", testo):
        return ""
    if testo.strip(" .").lower() in SEGNAPOSTO:
        return ""
    return testo


def frammenti(pagina: str) -> list:
    """Il testo visibile della pagina, spezzato dove stavano i tag.

    Gli apparati scrivono l'etichetta in una cella e il valore in quella accanto:
    conservare il confine fra i due e' l'unico modo di riconoscere la coppia. Per
    questo non si produce un testo unico ma un elenco di frammenti.
    """
    if not pagina:
        return []
    ripulita = RE_COMMENTO_HTML.sub(" ", RE_SCRIPT.sub(" ", pagina))
    grezzi = RE_TAG.sub("\n", ripulita).splitlines()
    fuori = []
    for grezzo in grezzi:
        pezzo = html.unescape(grezzo).replace(" ", " ")
        pezzo = RE_SPAZI.sub(" ", pezzo).strip()
        if pezzo and len(pezzo) <= MAX_TOKEN:
            fuori.append(pezzo)
    return fuori


# --------------------------------------------------------------------------- #
# Fatti
# --------------------------------------------------------------------------- #
def fatti(pagina: str) -> dict:
    """I fatti che la pagina dichiara di se', per etichetta riconosciuta.

    Tre forme, in ordine di precisione:

    1. etichetta e valore in due frammenti vicini (`Nome host` | `: crl-AS1-st0018`):
       e' come scrivono le tabelle degli apparati;
    2. etichetta e valore nello stesso frammento (`Modello: MP C4504ex`);
    3. `meta name="..."` con nome corrispondente.

    Il primo valore valido vince: le pagine ripetono le stesse etichette nei menu, e
    la prima occorrenza e' quella della tabella dei dati.
    """
    trovati = {}
    pezzi = frammenti(pagina)

    for indice, pezzo in enumerate(pezzi):
        for chiave, espressioni in _ETICHETTA:
            if chiave in trovati:
                continue
            if not any(e.match(pezzo) for e in espressioni):
                continue
            # Il valore sta nel frammento successivo. Le tabelle degli apparati
            # mettono i due punti nella cella del valore (`: RICOH MP C4504ex`):
            # se dopo i due punti non c'e' niente, il campo e' VUOTO -- e guardare il
            # frammento dopo prenderebbe il valore dell'etichetta seguente. E' il
            # difetto visto sul campo: il "Commento" vuoto si prendeva "Nome host".
            for salto in (1, 2):
                if indice + salto >= len(pezzi):
                    break
                candidato = pezzi[indice + salto]
                if candidato.lstrip().startswith((":", ":")):
                    valore = pulisci(candidato)
                    if valore:
                        trovati[chiave] = valore
                    break
                if _e_etichetta(candidato):
                    break  # e' l'etichetta successiva: questo campo e' vuoto
                valore = pulisci(candidato)
                if valore:
                    trovati[chiave] = valore
                    break

    for pezzo in pezzi:
        for chiave, espressioni in _ETICHETTA_INLINE:
            if chiave in trovati:
                continue
            for espressione in espressioni:
                trovato = espressione.search(pezzo)
                if trovato:
                    valore = pulisci(trovato.group(1))
                    if valore:
                        trovati[chiave] = valore
                        break

    for chiave, valore in _meta(pagina).items():
        trovati.setdefault(chiave, valore)
    for chiave, valore in fatti_xml(pagina).items():
        trovati.setdefault(chiave, valore)

    if "firmware" not in trovati:
        fw = RE_FW_LABEL.search(pagina)
        if fw:
            trovati["firmware"] = "%s (build %s)" % (fw.group(1).replace("_", " "),
                                                     fw.group(2))

    return dict(list(trovati.items())[:MAX_FATTI])


# Tag XML che valgono come etichetta: gli apparati che espongono un endpoint di sola
# lettura non scrivono "Modello :", scrivono <MakeAndModel>. E' la stessa cosa detta a
# una macchina invece che a una persona.
TAG_XML = {
    "makeandmodel": "modello", "model": "modello", "modelname": "modello",
    "productname": "modello", "devicemodel": "modello", "printermodel": "modello",
    "modelnumber": "modello",
    "devicename": "nome_dispositivo", "hostname": "nome_host",
    "devicehostname": "nome_host", "systemname": "nome_dispositivo",
    "serialnumber": "seriale", "serialnum": "seriale", "productserialnumber": "seriale",
    "firmwareversion": "firmware", "fwversion": "firmware", "version": "firmware",
    "versionid": "firmware", "softwareversion": "firmware",
    "devicelocation": "posizione",
    "location": "posizione", "syslocation": "posizione", "contact": "contatto",
    "syscontact": "contatto", "macaddress": "mac", "manufacturer": "marca_dichiarata",
    "make": "marca_dichiarata", "vendor": "marca_dichiarata",
    # Telefoni IP Cisco: gli endpoint /DeviceInformationX e /NetworkConfigurationX
    # dichiarano in XML tutto cio' che serve a inventariare l'apparato. Sono etichette
    # tecniche (nessun dato personale): l'interno e' un numero di apparato, non di
    # persona, e vale come identificativo del terminale.
    "phonedn": "numero_interno", "apploadid": "carico_software",
    "bootloadid": "carico_avvio", "hardwarerevision": "revisione_hw",
    "callmanager1": "gestore_chiamate", "tftpserver1": "server_tftp",
}
RE_TAG_VALORE = re.compile(
    r"(?is)<(?:\w+:)?([A-Za-z][\w\-\.]{2,40})\s*>\s*([^<>]{1,160}?)\s*</")


def fatti_xml(documento: str) -> dict:
    """Fatti ricavati dai nomi dei tag di un documento XML (o di un frammento).

    Non si usa un parser XML: questi endpoint restituiscono spesso XML malformato o
    troncato dal limite di lettura, e un parser rigoroso non ne ricaverebbe nulla. Qui
    interessano solo le coppie tag/valore, e per quelle basta riconoscerle.
    """
    trovati = {}
    for trovato in RE_TAG_VALORE.finditer(documento or ""):
        chiave = TAG_XML.get(trovato.group(1).replace("-", "").replace(".", "").lower())
        if not chiave or chiave in trovati:
            continue
        valore = pulisci(trovato.group(2))
        if valore:
            trovati[chiave] = valore
    return trovati


def _e_etichetta(frammento: str) -> bool:
    """Vero se il frammento e' a sua volta un'etichetta del vocabolario."""
    return any(e.match(frammento)
               for _chiave, espressioni in _ETICHETTA for e in espressioni)


def _meta(pagina: str) -> dict:
    """Fatti dichiarati nei `meta` della pagina."""
    fuori = {}
    for trovato in re.finditer(
            r"""(?is)<meta[^>]+name\s*=\s*["']?([\w\-\.]{1,40})["']?[^>]*"""
            r"""content\s*=\s*["']([^"']{0,200})["']""", pagina or ""):
        nome = trovato.group(1).lower()
        valore = pulisci(trovato.group(2))
        if not valore:
            continue
        if nome in ("device-model", "model", "product"):
            fuori.setdefault("modello", valore)
        elif nome in ("device-name", "application-name"):
            fuori.setdefault("nome_dispositivo", valore)
        elif nome in ("author", "contact"):
            fuori.setdefault("contatto", valore)
    return fuori


def marca_e_modello(fatti_pagina: dict, *altri: str) -> dict:
    """Marca e modello ricavati dai fatti e dai testi di contorno.

    Un nome dispositivo come `RICOH MP C4504ex` contiene entrambe le cose: la marca
    va riconosciuta e il modello va ripulito di quella, altrimenti l'inventario
    mostrerebbe il modello "RICOH MP C4504ex" della marca "Ricoh".
    """
    materiale = " | ".join(
        [str(fatti_pagina.get(c) or "") for c in ("marca_dichiarata", "nome_dispositivo",
                                                  "modello", "commento")]
        + [str(t or "") for t in altri])

    esito = {}
    for espressione, canonica in MARCHE:
        if re.search(espressione, materiale, re.IGNORECASE):
            esito["marca"] = canonica
            break

    grezzo = fatti_pagina.get("modello") or fatti_pagina.get("nome_dispositivo") or ""
    if not grezzo:
        for espressione in MODELLI:
            trovato = re.search(espressione, materiale, re.IGNORECASE)
            if trovato:
                grezzo = trovato.group(0)
                break
    modello = _modello_pulito(grezzo, esito.get("marca"))
    if modello:
        esito["modello"] = modello
    return esito


def _modello_pulito(grezzo: str, marca: str | None) -> str:
    """Il modello senza la marca davanti e senza le parole di contorno."""
    testo = pulisci(grezzo)
    if not testo:
        return ""
    if marca:
        for parte in marca.split():
            testo = re.sub(r"(?i)^\W*%s\W*" % re.escape(parte), "", testo).strip()
    # Se il residuo contiene una sigla di modello nota, vale quella: le pagine
    # aggiungono spesso "stampante", "series", "multifunzione".
    for espressione in MODELLI:
        trovato = re.search(espressione, testo, re.IGNORECASE)
        if trovato:
            return pulisci(trovato.group(0))
    testo = re.sub(r"(?i)\b(printer|stampante|series|serie|multifunzione|"
                   r"multifunction|device|dispositivo)\b", " ", testo)
    return pulisci(testo)


# --------------------------------------------------------------------------- #
# Navigazione
# --------------------------------------------------------------------------- #
def bersagli(pagina: str, base: str, cerca_ancore: bool = False) -> list:
    """Indirizzi che vale la pena leggere dopo questo, in ordine di promessa.

    L'ordine non e' casuale: un `meta refresh` e un `location.href` sono la pagina
    che l'apparato *voleva* mostrare, i frame sono le sue parti, i collegamenti sono
    un tentativo -- e si seguono solo se mancano ancora i fatti.

    Tutti gli indirizzi tornano assoluti e risolti sulla base. Chi chiama decide
    ancora se sono sullo stesso apparato: qui non si conosce la rete.
    """
    if not pagina:
        return []
    proposte = []

    for trovato in RE_META_REFRESH.finditer(pagina):
        contenuto = trovato.group(1)
        indirizzo = re.search(r"(?i)url\s*=\s*['\"]?([^'\"\s;]+)", contenuto)
        if indirizzo:
            proposte.append(("refresh", indirizzo.group(1)))

    for trovato in RE_JS_LOCATION.finditer(pagina):
        proposte.append(("script", trovato.group(1)))

    for trovato in RE_FRAME.finditer(pagina):
        proposte.append(("frame", trovato.group(1)))

    if cerca_ancore:
        for trovato in RE_ANCORA.finditer(pagina):
            riferimento, testo = trovato.group(1), html.unescape(trovato.group(2) or "")
            testo = RE_TAG.sub(" ", testo)
            if ANCORE_UTILI.search(riferimento) or ANCORE_UTILI.search(testo):
                proposte.append(("collegamento", riferimento))

    fuori, visti = [], set()
    for origine, riferimento in proposte:
        indirizzo = _assoluto(base, riferimento)
        if not indirizzo or indirizzo in visti:
            continue
        visti.add(indirizzo)
        fuori.append({"origine": origine, "url": indirizzo,
                      "priorita": priorita(origine, indirizzo)})
        if len(fuori) >= MAX_BERSAGLI:
            break
    return fuori


def priorita(origine: str, indirizzo: str) -> int:
    """Quanto promette un bersaglio: piu' basso, piu' presto si legge."""
    if POCO_UTILI.search(urlsplit(indirizzo or "").path or "") or POCO_UTILI.search(
            urlsplit(indirizzo or "").query or ""):
        return 3
    return {"refresh": 0, "script": 0, "frame": 1, "collegamento": 2}.get(origine, 2)


def _assoluto(base: str, riferimento: str) -> str | None:
    """Indirizzo assoluto, se e' una GET che si puo' fare senza fare danni."""
    riferimento = (riferimento or "").strip()
    if not riferimento or riferimento.startswith("#"):
        return None
    if re.match(r"(?i)^(javascript|mailto|tel|data|ftp|file):", riferimento):
        return None
    try:
        indirizzo = urljoin(base, riferimento)
    except ValueError:  # riferimento malformato: non e' un indirizzo
        return None
    parti = urlsplit(indirizzo)
    if parti.scheme not in ("http", "https"):
        return None
    if VERBI_DISTRUTTIVI.search(parti.path) or VERBI_DISTRUTTIVI.search(parti.query):
        # Meglio perdere un fatto che spegnere una stampante durante un inventario.
        return None
    if parti.query and VERBI_CON_EFFETTO.search(parti.path + " " + parti.query):
        # Con dei parametri non e' una pagina, e' un comando.
        return None
    if len(indirizzo) > 300:
        return None
    return indirizzo


def stesso_apparato(indirizzo: str, ip: str, porta: int) -> bool:
    """Vero se l'indirizzo resta sullo stesso apparato e sulla stessa porta.

    Il perimetro dichiarato e' fatto di indirizzi: seguire un collegamento verso il
    portale del fornitore significherebbe leggere una macchina che nessuno ha
    autorizzato a leggere.
    """
    parti = urlsplit(indirizzo or "")
    if parti.hostname not in (ip, "localhost", "127.0.0.1"):
        return False
    predefinita = 443 if parti.scheme == "https" else 80
    return (parti.port or predefinita) == int(porta)
