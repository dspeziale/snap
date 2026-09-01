"""
snap server - Threat Intelligence: catalogo locale e correlazione con l'inventario.

Il problema, prima della soluzione
----------------------------------
Correlare un inventario di rete con le CVE e' facile da fare male: si cerca il nome del
prodotto nel testo della vulnerabilita' e si produce un elenco lungo, spaventoso e
inutile. Sull'inventario reale di questo progetto, su 2540 porte aperte solo 192 portano
un CPE e **7 portano una versione**: qualunque affermazione del tipo "questo nodo e'
vulnerabile a CVE-X" sarebbe indimostrabile nel 99,7% dei casi.

Per questo la correlazione ha **tre classi, sempre dichiarate**:

`confirmed`  prodotto e versione noti, e l'applicabilita' dichiarata dalla NVD
             (intervalli di versione) e' soddisfatta. E' l'unico caso in cui si dice
             che il nodo e' interessato.
`potential`  prodotto noto, versione ignota. La CVE riguarda quel prodotto, ma
             l'istanza non e' verificabile: si dichiara che serve la versione, e non
             si conta fra le vulnerabilita'.
`exposure`   nessuna CVE. E' il servizio in se' a costituire rischio -- telnet in
             chiaro, SMB raggiungibile, amministrazione remota aperta -- con la
             tecnica MITRE ATT&CK che lo sfrutterebbe. Su questo inventario e' la
             classe che porta piu' informazione, e non dipende dalle versioni.

Il catalogo e' locale: la correlazione non contatta nessuno e funziona in una rete
isolata. Aggiornarlo e' un'operazione esplicita (`threat_sources.py`).

Riferimenti: NIS2 art. 21(2)(e) gestione delle vulnerabilita'; CRA allegato I;
docs/10_THREAT_INTELLIGENCE.md.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re

from .audit import log_event
from . import zones
from .db import execute, query, scalar, utc_now_str

# Classi di riscontro.
KIND_CONFIRMED = "confirmed"
KIND_POTENTIAL = "potential"
KIND_EXPOSURE = "exposure"
KINDS = {
    KIND_CONFIRMED: "Confermato",
    KIND_POTENTIAL: "Da verificare",
    KIND_EXPOSURE: "Esposizione",
}

# Stati di un riscontro. `accepted` e' il rischio accettato con motivazione: senza
# questo stato l'elenco resta pieno di cose note e nessuno lo guarda piu'.
STATUS_OPEN = "open"
# Atteso nel contesto della zona dichiarata dalla subnet (zones.py). Non e' una
# decisione di una persona -- quella e' "rischio accettato" -- ma la conseguenza di
# un'architettura dichiarata: SSH in un datacenter non e' una svista. Il riscontro
# resta in archivio con la sua motivazione e non conta fra quelli aperti; se la zona
# cambia, la rivalutazione lo riapre da se'.
STATUS_EXPECTED = "expected"
STATUS_ACCEPTED = "accepted"
STATUS_FALSE_POSITIVE = "false_positive"
STATUS_FIXED = "fixed"
STATUSES = {
    STATUS_OPEN: "Aperto",
    STATUS_EXPECTED: "Atteso nella zona",
    STATUS_ACCEPTED: "Rischio accettato",
    STATUS_FALSE_POSITIVE: "Falso positivo",
    STATUS_FIXED: "Non piu' presente",
}

SEVERITIES = ("critical", "high", "medium", "low", "info")
ORDINE_SEVERITA = {s: i for i, s in enumerate(SEVERITIES)}

# Guardie: una correlazione non deve diventare una scansione dell'intero catalogo per
# ogni porta, ne' un elenco che nessuno leggera'.
MAX_CVE_PER_PRODOTTO = 50
# Quanti riscontri al massimo in una passata. Misurato sul campo: una rete di 2.400
# nodi ne produce oltre 4.400 di sole esposizioni, e con il limite a 5.000 la
# correlazione si fermava prima di arrivare alle ultime subnet -- che restavano senza
# riscontri senza che nulla lo dicesse in modo evidente. Il limite resta, perche' una
# passata deve finire, ma sta dove serve: oltre questa soglia c'e' un difetto, non una
# rete grande.
MAX_FINDINGS_PER_PASSATA = 25000


class ThreatError(RuntimeError):
    """Errore di dominio della threat intelligence. Il messaggio e' per l'operatore."""


# --------------------------------------------------------------------------- #
# CPE: lettura e confronto delle versioni
# --------------------------------------------------------------------------- #
def parse_cpe(testo: str) -> dict | None:
    """Legge un CPE 2.2 (`cpe:/a:vendor:prodotto:versione`) o 2.3.

    nmap emette la forma 2.2 e spesso senza versione; la NVD usa la 2.3. Serve leggerle
    entrambe, altrimenti metà dell'inventario resta fuori dalla correlazione.
    """
    grezzo = (testo or "").strip().lower()
    if not grezzo.startswith("cpe:"):
        return None
    if grezzo.startswith("cpe:2.3:"):
        pezzi = grezzo.split(":")
        # cpe:2.3:part:vendor:product:version:update:...
        if len(pezzi) < 6:
            return None
        parte, vendor, prodotto, versione = pezzi[2], pezzi[3], pezzi[4], pezzi[5]
    else:
        resto = grezzo[len("cpe:/"):]
        pezzi = resto.split(":")
        parte = pezzi[0] if pezzi else ""
        vendor = pezzi[1] if len(pezzi) > 1 else ""
        prodotto = pezzi[2] if len(pezzi) > 2 else ""
        versione = pezzi[3] if len(pezzi) > 3 else ""
    if parte not in ("a", "o", "h") or not prodotto:
        return None
    return {
        "part": parte,
        "vendor": _pulisci(vendor),
        "product": _pulisci(prodotto),
        "version": _pulisci(versione),
    }


def _pulisci(valore: str) -> str:
    """Normalizza un campo CPE: `*`, `-` e vuoto significano "non specificato"."""
    testo = (valore or "").strip().lower()
    if testo in ("*", "-", ""):
        return ""
    # I CPE sfuggono i caratteri con la barra inversa: qui non serve conservarla.
    return testo.replace("\\", "")


_PEZZO = re.compile(r"(\d+|[a-z]+)")


def version_key(versione: str) -> tuple:
    """Chiave di ordinamento di una versione: numeri come numeri, testo come testo.

    Non e' un confronto semantico completo (non lo e' nemmeno la realta': "2.2.X" e
    "8.9p1" convivono nello stesso inventario), ma ordina correttamente i casi che
    contano: 1.9 < 1.10, 2.4.7 < 2.4.62, 1.0 < 1.0p1.
    """
    chiave = []
    for pezzo in _PEZZO.findall((versione or "").strip().lower()):
        if pezzo.isdigit():
            chiave.append((1, int(pezzo), ""))
        else:
            chiave.append((0, 0, pezzo))
    return tuple(chiave)


def compare_versions(prima: str, seconda: str) -> int:
    a, b = version_key(prima), version_key(seconda)
    return (a > b) - (a < b)


def version_uncertain(versione: str) -> bool:
    """Vero se la versione non e' confrontabile: intervalli, `X`, generici.

    nmap restituisce cose come "2.2.X - 2.3.X": un confronto su quella stringa darebbe
    un esito inventato. Meglio dichiarare l'incertezza.
    """
    testo = (versione or "").strip().lower()
    if not testo:
        return True
    return bool(re.search(r"[x*]|\s-\s|\bor\b|,", testo))


def version_in_range(versione: str, voce: dict) -> bool:
    """Applicabilita' di una versione all'intervallo dichiarato dalla NVD."""
    if version_uncertain(versione):
        return False
    fissa = (voce.get("version") or "").strip()
    if fissa and not version_uncertain(fissa):
        return compare_versions(versione, fissa) == 0

    inizio = (voce.get("version_start") or "").strip()
    fine = (voce.get("version_end") or "").strip()
    if inizio:
        confronto = compare_versions(versione, inizio)
        if confronto < 0 or (confronto == 0 and not voce.get("version_start_incl")):
            return False
    if fine:
        confronto = compare_versions(versione, fine)
        if confronto > 0 or (confronto == 0 and not voce.get("version_end_incl")):
            return False
    # Nessun vincolo dichiarato: la CVE si applica a tutte le versioni del prodotto.
    return True


# --------------------------------------------------------------------------- #
# Da cio' che nmap dice a cio' che la NVD conosce
# --------------------------------------------------------------------------- #
# nmap nomina i prodotti come li annuncia il servizio; la NVD usa i nomi CPE. La
# tabella copre i casi che compaiono davvero in un inventario di rete: e' una
# euristica dichiarata, non un dizionario completo, e ogni riscontro che ne deriva
# porta confidenza ridotta.
ALIAS_PRODOTTI = {
    "openssh": ("openbsd", "openssh"),
    "apache httpd": ("apache", "http_server"),
    "nginx": ("f5", "nginx"),
    "microsoft iis httpd": ("microsoft", "internet_information_services"),
    "microsoft httpapi httpd": ("microsoft", "http.sys"),
    "openldap": ("openldap", "openldap"),
    "net-snmp": ("net-snmp", "net-snmp"),
    "vsftpd": ("beasts", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "postfix smtpd": ("postfix", "postfix"),
    "exim smtpd": ("exim", "exim"),
    "dovecot imapd": ("dovecot", "dovecot"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "microsoft sql server": ("microsoft", "sql_server"),
    "oracle tns listener": ("oracle", "database_server"),
    "redis key-value store": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "samba smbd": ("samba", "samba"),
    "isc bind": ("isc", "bind"),
    "dnsmasq": ("thekelleys", "dnsmasq"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "jetty": ("eclipse", "jetty"),
    "apache tomcat": ("apache", "tomcat"),
    "gsoap": ("genivia", "gsoap"),
    "golang net/http server": ("golang", "go"),
    "java rmi": ("oracle", "jre"),
}


def cpe_from_service(product: str, version: str) -> dict | None:
    """Ricava un CPE plausibile dal prodotto annunciato da un servizio."""
    nome = (product or "").strip().lower()
    if not nome:
        return None
    voce = ALIAS_PRODOTTI.get(nome)
    if voce is None:
        # Prova con il primo pezzo del nome: "OpenSSH 8.9p1" -> "openssh".
        primo = nome.split()[0]
        voce = ALIAS_PRODOTTI.get(primo)
    if voce is None:
        return None
    vendor, prodotto = voce
    return {"part": "a", "vendor": vendor, "product": prodotto,
            "version": _pulisci(version), "alias": True}


# --------------------------------------------------------------------------- #
# Esposizioni: rischio del servizio, non della versione
# --------------------------------------------------------------------------- #
# Ogni riga dice: che cosa e' esposto, quale tecnica MITRE ATT&CK lo sfrutterebbe,
# quanto conta, e che cosa se ne fa chi legge. Le tecniche sono quelle del catalogo
# ATT&CK; l'associazione porta-tecnica e' NOSTRA e va dichiarata come tale: MITRE non
# pubblica una mappa "porta 3389 -> T1021.001".
EXPOSURE_RULES = [
    {
        "porte": [(3389, "tcp")], "technique": "T1021.001",
        "severity": "high", "titolo": "Desktop remoto (RDP) raggiungibile",
        "motivo": "Chi raggiunge questa porta con credenziali valide comanda il"
                  " dispositivo. E' il primo bersaglio di un attacco con credenziali"
                  " rubate e la via d'ingresso piu' usata dai ransomware.",
        "azione": "Limitare l'accesso a una rete di amministrazione, imporre il secondo"
                  " fattore, disattivarlo dove non serve.",
    },
    {
        "porte": [(445, "tcp"), (139, "tcp")], "technique": "T1021.002",
        "severity": "high", "titolo": "Condivisione file Windows (SMB) raggiungibile",
        "motivo": "E' la strada su cui i ransomware si propagano fra dispositivi della"
                  " stessa rete, e su cui si enumerano condivisioni e utenti.",
        "azione": "Segmentare, disattivare SMBv1, limitare l'accesso alle sole reti che"
                  " ne hanno bisogno.",
    },
    {
        "porte": [(22, "tcp")], "technique": "T1021.004",
        "severity": "medium", "titolo": "Accesso remoto SSH raggiungibile",
        "motivo": "Accesso amministrativo completo. In rete interna e' normale che"
                  " esista; che sia raggiungibile da qualunque segmento no.",
        "azione": "Chiavi invece di password, limitazione per rete di origine,"
                  " registrazione degli accessi.",
    },
    {
        "porte": [(5900, "tcp"), (5901, "tcp")], "technique": "T1021.005",
        "severity": "high", "titolo": "Desktop remoto VNC raggiungibile",
        "motivo": "Molte installazioni VNC non richiedono autenticazione o usano una"
                  " password di otto caratteri, che e' il limite del protocollo.",
        "azione": "Incapsulare in una galleria cifrata o sostituire con uno strumento"
                  " che autentica seriamente.",
    },
    {
        "porte": [(23, "tcp")], "technique": "T1040",
        "severity": "high", "titolo": "Telnet: credenziali in chiaro",
        "motivo": "Utente e password viaggiano leggibili da chiunque sia sul percorso."
                  " Su un apparato di rete significa la sua amministrazione completa.",
        "azione": "Sostituire con SSH e disattivare il servizio.",
    },
    {
        "porte": [(21, "tcp")], "technique": "T1040",
        "severity": "medium", "titolo": "FTP: credenziali e dati in chiaro",
        "motivo": "Come telnet, con in piu' il trasferimento di file leggibile.",
        "azione": "Passare a SFTP o FTPS.",
    },
    {
        "porte": [(161, "udp")], "technique": "T1046",
        "severity": "medium", "titolo": "SNMP leggibile",
        "motivo": "Con una community predefinita SNMP racconta interfacce, tabelle di"
                  " instradamento, processi e software installato: e' ricognizione"
                  " servita al bersaglio.",
        "azione": "Cambiare le community, passare a SNMPv3, limitare per rete di"
                  " origine.",
    },
    {
        "porte": [(1433, "tcp"), (1521, "tcp"), (3306, "tcp"), (5432, "tcp"),
                  (6379, "tcp"), (27017, "tcp"), (9200, "tcp")],
        "technique": "T1190",
        "severity": "high", "titolo": "Banca dati raggiungibile dalla rete",
        "motivo": "Una banca dati raggiungibile da una rete di utenza non ha ragione di"
                  " esserlo: e' un bersaglio diretto e spesso con credenziali"
                  " predefinite.",
        "azione": "Esporla solo agli applicativi che la usano, con regole di rete"
                  " esplicite.",
    },
    {
        "porte": [(8080, "tcp"), (8443, "tcp"), (10000, "tcp"), (10001, "tcp"),
                  (4443, "tcp")],
        "technique": "T1190",
        "severity": "medium", "titolo": "Console di gestione raggiungibile",
        "motivo": "Le console di gestione sono spesso installate con credenziali"
                  " predefinite mai cambiate e restano fuori dagli inventari.",
        "azione": "Verificare le credenziali, limitare l'accesso, censire l'apparato.",
    },
    {
        "porte": [(2000, "tcp"), (5060, "tcp"), (5061, "tcp")], "technique": "T1046",
        "severity": "low", "titolo": "Servizi di telefonia raggiungibili",
        "motivo": "Utili a riconoscere gli apparati. Se compaiono su moltissimi nodi"
                  " sono la risposta di un centralino che risponde per altri, non"
                  " altrettanti servizi.",
        "azione": "Verificare che non si tratti di un apparato intermedio prima di"
                  " censirli come esposizione.",
    },
]

# Tecniche citate dalle regole: se il catalogo ATT&CK non e' stato importato, il
# riscontro resta valido e mostra l'identificativo senza il nome.
TECNICHE_USATE = sorted({regola["technique"] for regola in EXPOSURE_RULES})


def _regola_per_porta(porta: int, protocollo: str) -> dict | None:
    for regola in EXPOSURE_RULES:
        if (int(porta), (protocollo or "tcp").lower()) in regola["porte"]:
            return regola
    return None


# --------------------------------------------------------------------------- #
# Catalogo: interrogazioni
# --------------------------------------------------------------------------- #
def catalog_summary() -> dict:
    """Che cosa contiene il catalogo locale e quanto e' vecchio."""
    ultimo = query(
        "SELECT source, MAX(finished_at) AS quando, SUM(items) AS voci FROM ti_sync"
        " WHERE status = 'ok' GROUP BY source", ())
    return {
        "cve": scalar("SELECT COUNT(*) FROM ti_cve", (), default=0),
        "cve_kev": scalar("SELECT COUNT(*) FROM ti_cve WHERE kev = 1", (), default=0),
        "cpe": scalar("SELECT COUNT(*) FROM ti_cve_cpe", (), default=0),
        "cwe": scalar("SELECT COUNT(*) FROM ti_cwe", (), default=0),
        "tecniche": scalar("SELECT COUNT(*) FROM ti_technique", (), default=0),
        "ultimo_per_sorgente": {r["source"]: {"quando": r["quando"], "voci": r["voci"]}
                                for r in ultimo},
        "cve_piu_recente": scalar("SELECT MAX(published_at) FROM ti_cve", (),
                                  default=None),
    }


def cve(cve_id: str) -> dict | None:
    riga = query("SELECT * FROM ti_cve WHERE cve_id = ?", ((cve_id or "").upper(),),
                 one=True)
    if riga is None:
        return None
    voce = dict(riga)
    voce["cpe"] = [dict(r) for r in query(
        "SELECT * FROM ti_cve_cpe WHERE cve_id = ? ORDER BY vendor, product",
        (voce["cve_id"],))]
    voce["cwe"] = [dict(r) for r in query(
        "SELECT * FROM ti_cwe WHERE cwe_id IN (%s)"
        % ",".join("?" * len([c for c in (voce["cwe_ids"] or "").split(",") if c])),
        tuple(c.strip() for c in (voce["cwe_ids"] or "").split(",") if c.strip()))
    ] if (voce["cwe_ids"] or "").strip() else []
    return voce


def search_cve(testo: str = "", severita: str = "", solo_kev: bool = False,
               limit: int = 200) -> list:
    condizioni = []
    parametri = []
    cercato = (testo or "").strip()
    if cercato:
        condizioni.append("(cve_id LIKE ? OR description LIKE ?)")
        parametri.extend(["%" + cercato.upper() + "%", "%" + cercato + "%"])
    if severita in SEVERITIES:
        condizioni.append("severity = ?")
        parametri.append(severita)
    if solo_kev:
        condizioni.append("kev = 1")
    dove = (" WHERE " + " AND ".join(condizioni)) if condizioni else ""
    parametri.append(int(limit))
    return [dict(r) for r in query(
        "SELECT cve_id, published_at, severity, cvss_score, kev, cwe_ids,"
        " SUBSTR(description, 1, 300) AS descrizione FROM ti_cve" + dove +
        " ORDER BY kev DESC, cvss_score DESC, published_at DESC LIMIT ?", parametri)]


def cwe_list(limit: int = 300) -> list:
    """Debolezze del catalogo, con quante CVE le citano fra quelle conosciute.

    Il conteggio viene dalla tabella dei legami e non da un confronto testuale sulla
    colonna `cwe_ids`: quel confronto costava un esame di tutte le CVE per ciascuna
    delle 130 debolezze, cioe' 14,3 secondi a ogni apertura della pagina.
    """
    return [dict(r) for r in query(
        "SELECT w.*, COUNT(l.cve_id) AS cve_collegate FROM ti_cwe w"
        " LEFT JOIN ti_cve_cwe l ON l.cwe_id = w.cwe_id"
        " GROUP BY w.cwe_id ORDER BY cve_collegate DESC, w.cwe_id LIMIT ?",
        (int(limit),))]


def techniques(limit: int = 400) -> list:
    return [dict(r) for r in query(
        "SELECT * FROM ti_technique ORDER BY technique_id LIMIT ?", (int(limit),))]


def exposure_catalog() -> list:
    """Regole di esposizione con il nome della tecnica, quando il catalogo c'e'."""
    nomi = {r["technique_id"]: dict(r) for r in query(
        "SELECT technique_id, name, tactics, url FROM ti_technique WHERE technique_id IN"
        " (%s)" % ",".join("?" * len(TECNICHE_USATE)), tuple(TECNICHE_USATE))}
    voci = []
    for regola in EXPOSURE_RULES:
        tecnica = nomi.get(regola["technique"])
        voci.append(dict(regola,
                         porte_testo=", ".join("%s/%s" % (protocollo, porta)
                                               for porta, protocollo in regola["porte"]),
                         tecnica_nome=tecnica["name"] if tecnica else "",
                         tecnica_url=tecnica["url"] if tecnica else "",
                         tecnica_tattiche=tecnica["tactics"] if tecnica else ""))
    return voci


# --------------------------------------------------------------------------- #
# Correlazione
# --------------------------------------------------------------------------- #
def _cve_per_prodotto(parte: str, vendor: str, prodotto: str) -> list:
    """Voci di applicabilita' per un prodotto. Il vendor, se noto, restringe molto."""
    condizioni = ["c.part = ?", "c.product = ?", "c.vulnerable = 1"]
    parametri = [parte, prodotto]
    if vendor:
        condizioni.append("c.vendor = ?")
        parametri.append(vendor)
    parametri.append(MAX_CVE_PER_PRODOTTO)
    return [dict(r) for r in query(
        "SELECT c.*, v.severity, v.cvss_score, v.kev, v.description"
        " FROM ti_cve_cpe c JOIN ti_cve v ON v.cve_id = c.cve_id"
        " WHERE " + " AND ".join(condizioni) +
        " ORDER BY v.kev DESC, v.cvss_score DESC LIMIT ?", parametri)]


def _osservazioni(tenant_id: int) -> list:
    """Cio' su cui si puo' correlare: porte con CPE o prodotto, e sistemi operativi."""
    osservazioni = []
    for riga in query(
            "SELECT p.id AS port_id, p.node_id, p.protocol, p.port, p.service_name,"
            " p.product, p.version, p.cpe, n.ip, n.hostname,"
            " COALESCE(s.zone, '') AS zone, COALESCE(s.cidr, '') AS subnet_cidr"
            " FROM node_ports p JOIN nodes n ON n.id = p.node_id"
            " LEFT JOIN subnets s ON s.id = n.subnet_id"
            " WHERE p.tenant_id = ? AND p.state = 'open'", (tenant_id,)):
        voce = dict(riga)
        candidati = []
        for pezzo in (voce["cpe"] or "").split(","):
            letto = parse_cpe(pezzo)
            if letto:
                candidati.append(letto)

        # A quale CPE appartiene la versione che nmap ha annunciato.
        #
        # Difetto trovato sui dati reali: la porta 593 di un Windows portava
        # `cpe:/a:microsoft:qotd,cpe:/o:microsoft:windows` e la versione "1.0", che e'
        # la versione del PROTOCOLLO annunciato dal servizio ("RPC over HTTP 1.0").
        # Attribuendola al CPE del sistema operativo si otteneva "Windows versione
        # 1.0", che corrispondeva a ogni CVE dichiarata per `windows:*`: tre nodi
        # marcati come vulnerabili a dodici CVE del 2008, tutte false.
        #
        # Regole: la versione di un servizio non e' mai la versione di un sistema
        # operativo (`part = o`); e se un servizio dichiara piu' CPE applicativi, non
        # si sa a quale appartenga, quindi non si attribuisce a nessuno.
        versione_servizio = _pulisci(voce["version"])
        applicativi = [c for c in candidati if c["part"] == "a" and not c["version"]]
        if versione_servizio and len(applicativi) == 1:
            applicativi[0]["version"] = versione_servizio
            applicativi[0]["version_da_servizio"] = True
        if not candidati:
            dedotto = cpe_from_service(voce["product"], voce["version"])
            if dedotto:
                candidati.append(dedotto)
        voce["cpe_candidati"] = candidati
        osservazioni.append(voce)

    for riga in query(
            "SELECT id AS node_id, ip, hostname, os_name, os_family, os_vendor"
            " FROM nodes WHERE tenant_id = ? AND os_name IS NOT NULL AND os_name <> ''",
            (tenant_id,)):
        voce = dict(riga)
        voce.update({"port_id": None, "protocol": None, "port": None,
                     "service_name": "sistema operativo",
                     "product": voce["os_name"], "version": "",
                     "cpe_candidati": []})
        osservazioni.append(voce)
    return osservazioni


def _upsert_finding(tenant_id: int, voce: dict, adesso: str) -> str:
    """Inserisce o aggiorna un riscontro. Restituisce 'nuovo' oppure 'aggiornato'.

    La decisione dell'operatore (rischio accettato, falso positivo) non viene
    sovrascritta: un riscontro riconfermato torna a essere visto, non riaperto.
    """
    esistente = query(
        "SELECT id, status FROM ti_findings WHERE tenant_id = ? AND node_id = ?"
        " AND IFNULL(port_id, 0) = ? AND kind = ? AND IFNULL(cve_id, '') = ?"
        " AND IFNULL(technique_id, '') = ?",
        (tenant_id, voce["node_id"], voce.get("port_id") or 0, voce["kind"],
         voce.get("cve_id") or "", voce.get("technique_id") or ""), one=True)
    # Un'esposizione attesa nella zona nasce (e torna) nello stato "atteso"; se la
    # zona cambia e non la prevede piu', la rivalutazione la riapre. La decisione di
    # una persona -- rischio accettato, falso positivo -- resta piu' forte di
    # entrambe: e' un giudizio, non una regola.
    atteso = voce.get("giudizio_zona") == zones.ATTESA
    stato_iniziale = STATUS_EXPECTED if atteso else STATUS_OPEN

    if esistente is not None:
        stato = esistente["status"]
        nuovo_stato = STATUS_OPEN if stato == STATUS_FIXED else stato
        if stato in (STATUS_OPEN, STATUS_EXPECTED, STATUS_FIXED):
            nuovo_stato = stato_iniziale
        execute(
            "UPDATE ti_findings SET severity = ?, score = ?, title = ?, evidence = ?,"
            " cpe_used = ?, product = ?, version = ?, confidence = ?, status = ?,"
            " source = ?, last_seen_at = ? WHERE id = ?",
            (voce["severity"], voce.get("score"), voce["title"], voce["evidence"],
             voce.get("cpe_used"), voce.get("product"), voce.get("version"),
             voce.get("confidence", 50), nuovo_stato, voce.get("source", "correlation"),
             adesso, int(esistente["id"])))
        return "aggiornato"

    execute(
        "INSERT INTO ti_findings (tenant_id, node_id, port_id, kind, cve_id,"
        " technique_id, severity, score, title, evidence, cpe_used, product, version,"
        " confidence, status, source, first_seen_at, last_seen_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (tenant_id, voce["node_id"], voce.get("port_id"), voce["kind"],
         voce.get("cve_id"), voce.get("technique_id"), voce["severity"],
         voce.get("score"), voce["title"], voce["evidence"], voce.get("cpe_used"),
         voce.get("product"), voce.get("version"), voce.get("confidence", 50),
         stato_iniziale, voce.get("source", "correlation"), adesso, adesso))
    return "nuovo"


def correlate(tenant_id: int, requested_by: int = None) -> dict:
    """Rivaluta l'inventario contro il catalogo locale. Non contatta nessuno.

    I riscontri non piu' osservati non vengono cancellati: passano a "non piu'
    presente" con la data. La storia di cio' che era esposto e' informazione, e
    cancellarla renderebbe impossibile dire quando e' stato chiuso.
    """
    adesso = utc_now_str()
    esito = {"nuovi": 0, "aggiornati": 0, "chiusi": 0, "confermati": 0,
             "da_verificare": 0, "esposizioni": 0, "esaminati": 0, "troncato": False}
    visti = []

    for osservazione in _osservazioni(tenant_id):
        esito["esaminati"] += 1
        if len(visti) >= MAX_FINDINGS_PER_PASSATA:
            esito["troncato"] = True
            break

        # --- esposizione del servizio, indipendente dalle versioni ---
        if osservazione.get("port"):
            regola = _regola_per_porta(osservazione["port"], osservazione["protocol"])
            if regola is not None:
                # Lo stesso servizio significa cose opposte a seconda di dove si
                # trova: la zona della subnet lo dice, e la sua motivazione entra
                # nella prova, cosi' chi legge capisce senza conoscere il catalogo.
                esito_zona, gravita, motivo_zona = zones.applica(
                    osservazione.get("zone"), regola["titolo"], regola["severity"])
                prova = "%s/%s aperta%s. %s" % (
                    osservazione["protocol"], osservazione["port"],
                    " (%s)" % osservazione["service_name"]
                    if osservazione["service_name"] else "", regola["motivo"])
                if motivo_zona:
                    prova += " " + motivo_zona
                voce = {
                    "node_id": osservazione["node_id"],
                    "port_id": osservazione["port_id"],
                    "kind": KIND_EXPOSURE,
                    "technique_id": regola["technique"],
                    "severity": gravita,
                    "score": None,
                    "title": regola["titolo"],
                    "evidence": prova,
                    "product": osservazione.get("product") or "",
                    "version": osservazione.get("version") or "",
                    "confidence": 90,
                    "zona": osservazione.get("zone") or "",
                    "giudizio_zona": esito_zona,
                }
                risultato = _upsert_finding(tenant_id, voce, adesso)
                esito["nuovi" if risultato == "nuovo" else "aggiornati"] += 1
                esito["esposizioni"] += 1
                visti.append((osservazione["node_id"], osservazione["port_id"],
                              KIND_EXPOSURE, "", regola["technique"]))

        # --- CVE, solo dove c'e' un prodotto riconoscibile ---
        for candidato in osservazione["cpe_candidati"]:
            applicabili = _cve_per_prodotto(candidato["part"], candidato["vendor"],
                                            candidato["product"])
            if not applicabili:
                continue
            versione = candidato.get("version") or ""
            incerta = version_uncertain(versione)

            if incerta:
                # Senza versione si produce UN SOLO riscontro aggregato per prodotto,
                # non uno per CVE.
                #
                # Difetto trovato sui dati reali: un solo Oracle TNS Listener senza
                # versione generava cinquanta righe "da verificare", e in tutto
                # l'inventario 1529: un elenco che nessuno legge, in cui la decina di
                # riscontri veri si perde. La domanda a cui questa classe risponde non
                # e' "quali CVE" ma "su che cosa devo rilevare la versione".
                esempi = ", ".join(v["cve_id"] for v in applicabili[:3])
                dati = {
                    "node_id": osservazione["node_id"],
                    "port_id": osservazione["port_id"],
                    "kind": KIND_POTENTIAL,
                    "cve_id": None,
                    "severity": "info",
                    "score": None,
                    "title": "%s: %d CVE note per il prodotto, versione non rilevata"
                             % (candidato["product"], len(applicabili)),
                    "evidence": ("%s riconosciuto come %s:%s. Il catalogo contiene %d"
                                 " CVE per questo prodotto (%s%s), ma senza la versione"
                                 " l'applicabilita' a questa istanza non e'"
                                 " verificabile: non e' una vulnerabilita' accertata."
                                 " Per deciderlo serve la versione del servizio."
                                 % (osservazione.get("product")
                                    or candidato["product"],
                                    candidato["vendor"] or "?", candidato["product"],
                                    len(applicabili), esempi,
                                    " e altre" if len(applicabili) > 3 else "")),
                    "cpe_used": "cpe:2.3:%s:%s:%s" % (candidato["part"],
                                                      candidato["vendor"] or "*",
                                                      candidato["product"]),
                    "product": candidato["product"],
                    "version": "",
                    "confidence": 25 if candidato.get("alias") else 40,
                }
                if candidato.get("alias"):
                    dati["evidence"] += (" Prodotto ricavato dal nome annunciato dal"
                                         " servizio: corrispondenza euristica.")
                risultato = _upsert_finding(tenant_id, dati, adesso)
                esito["nuovi" if risultato == "nuovo" else "aggiornati"] += 1
                esito["da_verificare"] += 1
                visti.append((osservazione["node_id"], osservazione["port_id"] or 0,
                              KIND_POTENTIAL, "", ""))
                continue

            # Con la versione si valuta CVE per CVE: sono fatti, e vanno elencati.
            for voce_cpe in applicabili:
                if not version_in_range(versione, voce_cpe):
                    continue  # versione nota e fuori intervallo: non si segnala nulla
                confidenza = 85
                prova = ("%s versione %s: rientra nell'applicabilita' dichiarata"
                         " dalla NVD (%s)."
                         % (candidato["product"], versione, voce_cpe["criteria"]))
                if candidato.get("version_da_servizio"):
                    confidenza = 65
                    prova += (" La versione e' quella annunciata dal servizio, non"
                              " dichiarata nel CPE: va verificata sull'apparato.")
                if candidato.get("alias"):
                    confidenza = max(20, confidenza - 25)
                    prova += (" Prodotto ricavato dal nome annunciato dal servizio:"
                              " corrispondenza euristica.")

                dati = {
                    "node_id": osservazione["node_id"],
                    "port_id": osservazione["port_id"],
                    "kind": KIND_CONFIRMED,
                    "cve_id": voce_cpe["cve_id"],
                    "severity": (voce_cpe["severity"] or "info").lower(),
                    "score": voce_cpe["cvss_score"],
                    "title": "%s%s su %s"
                             % (voce_cpe["cve_id"],
                                " (sfruttata attivamente)" if voce_cpe["kev"] else "",
                                candidato["product"]),
                    "evidence": prova,
                    "cpe_used": voce_cpe["criteria"],
                    "product": candidato["product"],
                    "version": versione,
                    "confidence": confidenza,
                }
                risultato = _upsert_finding(tenant_id, dati, adesso)
                esito["nuovi" if risultato == "nuovo" else "aggiornati"] += 1
                esito["confermati"] += 1
                visti.append((osservazione["node_id"], osservazione["port_id"] or 0,
                              KIND_CONFIRMED, voce_cpe["cve_id"], ""))

    # Chiusura di cio' che non si osserva piu'. SOLO i riscontri della correlazione per
    # versione: quelli verificati da nmap hanno un ciclo di vita proprio (li riasserisce
    # o li chiude la fase di ricerca vulnerabilita'), e questa riconciliazione non li
    # deve toccare.
    aperti = query(
        "SELECT id, node_id, port_id, kind, cve_id, technique_id FROM ti_findings"
        " WHERE tenant_id = ? AND status IN (?, ?)"
        " AND COALESCE(source, 'correlation') = 'correlation'",
        (tenant_id, STATUS_OPEN, STATUS_ACCEPTED))
    insieme = {(n, p or 0, k, c or "", t or "") for n, p, k, c, t in visti}
    for riga in aperti:
        chiave = (riga["node_id"], riga["port_id"] or 0, riga["kind"],
                  riga["cve_id"] or "", riga["technique_id"] or "")
        if chiave in insieme:
            continue
        execute("UPDATE ti_findings SET status = ?, last_seen_at = last_seen_at,"
                " note = COALESCE(note || ' | ', '') || ? WHERE id = ?",
                (STATUS_FIXED, "non piu' osservato al %s" % adesso, int(riga["id"])))
        esito["chiusi"] += 1

    log_event("threat.correlated",
              "Correlazione eseguita: %d osservazioni, %d riscontri nuovi, %d aggiornati,"
              " %d chiusi (%d confermati, %d da verificare, %d esposizioni)"
              % (esito["esaminati"], esito["nuovi"], esito["aggiornati"],
                 esito["chiusi"], esito["confermati"], esito["da_verificare"],
                 esito["esposizioni"]),
              tenant_id=tenant_id, severity="info", entity="threat")
    return esito


# --------------------------------------------------------------------------- #
# Vulnerabilita' verificate da nmap
# --------------------------------------------------------------------------- #
SOURCE_NMAP = "nmap"


def import_vuln_findings(tenant_id: int, node_id: int, trovati: list) -> dict:
    """Registra come riscontri i difetti che nmap ha VERIFICATO su un nodo.

    Collega la ricerca di vulnerabilita' della sonda alla Threat Intelligence: ogni
    difetto rilevato diventa un riscontro `confirmed` (o `potential` se nmap lo dava
    "likely"), con origine `nmap`. Un difetto verificato attivamente e' piu' forte di
    una correlazione per versione: la confidenza e' alta.

    Riasserisce l'insieme: i riscontri nmap di questo nodo che la nuova verifica non
    riporta piu' vengono chiusi (la vulnerabilita' e' stata sanata). Restituisce il
    conteggio di nuovi, aggiornati e chiusi.
    """
    adesso = utc_now_str()
    esito = {"nuovi": 0, "aggiornati": 0, "chiusi": 0}
    visti = set()

    for difetto in trovati or []:
        cves = difetto.get("cves") or []
        # Si lega la CVE al catalogo solo se c'e': il vincolo di ti_findings verso
        # ti_cve rifiuterebbe una CVE non catalogata. La CVE resta comunque nel titolo.
        cve_id = None
        for c in cves:
            if query("SELECT 1 FROM ti_cve WHERE cve_id = ?", (c,), one=True):
                cve_id = c
                break
        etichette = (" (%s)" % ", ".join(cves)) if cves else ""
        kind = KIND_CONFIRMED if difetto.get("state") != "likely" else KIND_POTENTIAL
        voce = {
            "node_id": node_id,
            "kind": kind,
            "cve_id": cve_id,
            # Senza CVE catalogata si usa il nome dello script come chiave di identita',
            # cosi' due difetti diversi sullo stesso nodo non si sovrascrivono.
            "technique_id": None if cve_id else ("nmap:" + difetto.get("script", ""))[:64],
            "severity": difetto.get("severity") or "high",
            "title": (difetto.get("title") or difetto.get("script") or "vulnerabilita'")
                      + etichette,
            "evidence": "Verificato attivamente da nmap (script %s)%s"
                        % (difetto.get("script", "?"),
                           "; CVE: " + ", ".join(cves) if cves else ""),
            "confidence": 90 if difetto.get("state") != "likely" else 60,
            "source": SOURCE_NMAP,
        }
        risultato = _upsert_finding(tenant_id, voce, adesso)
        esito["nuovi" if risultato == "nuovo" else "aggiornati"] += 1
        visti.add((cve_id or "", voce["technique_id"] or ""))

    # Chiusura dei difetti nmap di questo nodo non piu' verificati: la vulnerabilita' e'
    # stata sanata (o il servizio non risponde piu' come prima).
    for riga in query(
            "SELECT id, cve_id, technique_id FROM ti_findings WHERE tenant_id = ?"
            " AND node_id = ? AND source = ? AND status IN (?, ?)",
            (tenant_id, node_id, SOURCE_NMAP, STATUS_OPEN, STATUS_ACCEPTED)):
        if (riga["cve_id"] or "", riga["technique_id"] or "") in visti:
            continue
        execute("UPDATE ti_findings SET status = ?, note = COALESCE(note || ' | ', '')"
                " || ? WHERE id = ?",
                (STATUS_FIXED, "non piu' verificato al %s" % adesso, int(riga["id"])))
        esito["chiusi"] += 1

    if esito["nuovi"] or esito["aggiornati"] or esito["chiusi"]:
        log_event("threat.vuln.imported",
                  "Vulnerabilita' da nmap sul nodo %d: %d nuovi, %d aggiornati,"
                  " %d chiusi" % (node_id, esito["nuovi"], esito["aggiornati"],
                                  esito["chiusi"]),
                  tenant_id=tenant_id, entity="node", entity_id=node_id)
    return esito


# --------------------------------------------------------------------------- #
# Riscontri: lettura e decisioni
# --------------------------------------------------------------------------- #
def findings(tenant_id: int, kind: str = "", status: str = STATUS_OPEN,
             severita: str = "", node_id: int = None, limit: int = 500) -> list:
    condizioni = ["f.tenant_id = ?"]
    parametri = [tenant_id]
    if kind in KINDS:
        condizioni.append("f.kind = ?")
        parametri.append(kind)
    if status in STATUSES:
        condizioni.append("f.status = ?")
        parametri.append(status)
    if severita in SEVERITIES:
        condizioni.append("f.severity = ?")
        parametri.append(severita)
    if node_id is not None:
        condizioni.append("f.node_id = ?")
        parametri.append(int(node_id))
    parametri.append(int(limit))
    return [dict(r) for r in query(
        "SELECT f.*, n.ip, n.hostname, n.device_label, p.protocol, p.port,"
        " p.service_name, c.kev, c.cvss_score AS cve_score, c.severity AS cve_severity,"
        " t.name AS tecnica_nome, t.url AS tecnica_url"
        " FROM ti_findings f JOIN nodes n ON n.id = f.node_id"
        " LEFT JOIN node_ports p ON p.id = f.port_id"
        " LEFT JOIN ti_cve c ON c.cve_id = f.cve_id"
        " LEFT JOIN ti_technique t ON t.technique_id = f.technique_id"
        " WHERE " + " AND ".join(condizioni) +
        " ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
        "   WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,"
        " c.kev DESC, f.score DESC, n.ip LIMIT ?", parametri)]


def nodes_with_findings(tenant_id: int, kind: str = "", status: str = STATUS_OPEN,
                        severita: str = "", limit: int = 300) -> list:
    """Un nodo per riga, con quanto ha da sistemare.

    L'elenco per riscontro mostra lo stesso apparato venti volte -- una per porta e
    per CVE -- e non risponde alla domanda operativa, che e' "da quale dispositivo
    comincio". Qui i riscontri sono raccolti per nodo, ordinati per gravita' di cio'
    che portano: prima chi ha vulnerabilita' sfruttate attivamente, poi chi ne ha di
    confermate, poi il resto.
    """
    condizioni = ["f.tenant_id = ?"]
    parametri = [tenant_id]
    if kind in KINDS:
        condizioni.append("f.kind = ?")
        parametri.append(kind)
    if status in STATUSES:
        condizioni.append("f.status = ?")
        parametri.append(status)
    if severita in SEVERITIES:
        condizioni.append("f.severity = ?")
        parametri.append(severita)
    parametri.append(int(limit))

    righe = query(
        "SELECT n.id AS node_id, n.ip, n.hostname, n.device_label, n.device_type,"
        " COALESCE(n.device_type_source, 'auto') AS device_type_source,"
        " COUNT(*) AS riscontri,"
        " SUM(f.kind = 'confirmed') AS confermati,"
        " SUM(f.kind = 'potential') AS da_verificare,"
        " SUM(f.kind = 'exposure') AS esposizioni,"
        " SUM(COALESCE(c.kev, 0)) AS kev,"
        " MAX(COALESCE(f.score, 0)) AS punteggio,"
        " MIN(CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
        "   WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END) AS ordine_gravita,"
        " COUNT(DISTINCT f.port_id) AS porte,"
        # Separatore non stampabile e non DISTINCT: un titolo contiene virgole
        # ("go: 50 CVE note per il prodotto, versione non rilevata") e con la
        # virgola come separatore si spezzava in due voci. I doppioni si tolgono
        # qui sotto, dove l'ordine si puo' conservare.
        " GROUP_CONCAT(f.title, char(31)) AS titoli,"
        " MAX(f.last_seen_at) AS ultimo,"
        " SUM(f.status = 'accepted') AS accettati"
        " FROM ti_findings f JOIN nodes n ON n.id = f.node_id"
        " LEFT JOIN ti_cve c ON c.cve_id = f.cve_id"
        " WHERE " + " AND ".join(condizioni) +
        " GROUP BY n.id"
        " ORDER BY (kev > 0) DESC, confermati DESC, ordine_gravita, punteggio DESC,"
        " riscontri DESC LIMIT ?", parametri)

    gravita = {0: "critical", 1: "high", 2: "medium", 3: "low", 4: "info"}
    voci = []
    for riga in righe:
        voce = dict(riga)
        voce["peggiore"] = gravita.get(int(voce.pop("ordine_gravita") or 4), "info")
        # I titoli servono a capire di che cosa si tratta senza aprire il nodo: tre
        # bastano, il resto e' nella pagina del dispositivo.
        titoli, visti = [], set()
        for titolo in (voce.get("titoli") or "").split(""):
            titolo = titolo.strip()
            if titolo and titolo not in visti:
                visti.add(titolo)
                titoli.append(titolo)
        voce["titoli"] = titoli[:3]
        voce["altri_titoli"] = max(0, len(titoli) - 3)
        voci.append(voce)
    return voci


def finding(tenant_id: int, finding_id: int) -> dict | None:
    righe = findings(tenant_id, status="", limit=1000)
    for voce in righe:
        if int(voce["id"]) == int(finding_id):
            return voce
    return None


def summary(tenant_id: int) -> dict:
    """Numeri della pagina: per classe, per gravita', nodi interessati, KEV."""
    per_classe = {r["kind"]: int(r["n"]) for r in query(
        "SELECT kind, COUNT(*) AS n FROM ti_findings WHERE tenant_id = ?"
        " AND status = ? GROUP BY kind", (tenant_id, STATUS_OPEN))}
    per_gravita = {r["severity"]: int(r["n"]) for r in query(
        "SELECT severity, COUNT(*) AS n FROM ti_findings WHERE tenant_id = ?"
        " AND status = ? GROUP BY severity", (tenant_id, STATUS_OPEN))}
    return {
        "per_classe": per_classe,
        "per_gravita": per_gravita,
        "aperti": sum(per_classe.values()),
        "confermati": per_classe.get(KIND_CONFIRMED, 0),
        "da_verificare": per_classe.get(KIND_POTENTIAL, 0),
        "esposizioni": per_classe.get(KIND_EXPOSURE, 0),
        "kev": scalar(
            "SELECT COUNT(*) FROM ti_findings f JOIN ti_cve c ON c.cve_id = f.cve_id"
            " WHERE f.tenant_id = ? AND f.status = ? AND c.kev = 1 AND f.kind = ?",
            (tenant_id, STATUS_OPEN, KIND_CONFIRMED), default=0),
        "nodi": scalar("SELECT COUNT(DISTINCT node_id) FROM ti_findings"
                       " WHERE tenant_id = ? AND status = ?",
                       (tenant_id, STATUS_OPEN), default=0),
        "accettati": scalar("SELECT COUNT(*) FROM ti_findings WHERE tenant_id = ?"
                            " AND status = ?", (tenant_id, STATUS_ACCEPTED), default=0),
        # Attesi per zona: non sono aperti e non sono stati decisi da nessuno, sono
        # la conseguenza di un'architettura dichiarata. Contarli a parte permette di
        # dire "quaranta esposizioni, di cui trenta attese nel datacenter", che e'
        # un'informazione, mentre nasconderle sarebbe una bugia per omissione.
        "attesi": scalar("SELECT COUNT(*) FROM ti_findings WHERE tenant_id = ?"
                         " AND status = ?", (tenant_id, STATUS_EXPECTED), default=0),
        "attesi_per_zona": {r["zone"]: int(r["quanti"]) for r in query(
            "SELECT COALESCE(s.zone, '') AS zone, COUNT(*) AS quanti"
            " FROM ti_findings f JOIN nodes n ON n.id = f.node_id"
            " LEFT JOIN subnets s ON s.id = n.subnet_id"
            " WHERE f.tenant_id = ? AND f.status = ? GROUP BY s.zone",
            (tenant_id, STATUS_EXPECTED))},
        "chiusi": scalar("SELECT COUNT(*) FROM ti_findings WHERE tenant_id = ?"
                         " AND status = ?", (tenant_id, STATUS_FIXED), default=0),
        # Qualita' del dato: senza versioni la classe "confermato" non puo' esistere,
        # e dirlo e' piu' utile che mostrare un elenco vuoto.
        "porte_aperte": scalar("SELECT COUNT(*) FROM node_ports WHERE tenant_id = ?"
                               " AND state = 'open'", (tenant_id,), default=0),
        "porte_con_versione": scalar(
            "SELECT COUNT(*) FROM node_ports WHERE tenant_id = ? AND state = 'open'"
            " AND version IS NOT NULL AND version <> ''", (tenant_id,), default=0),
        "porte_con_cpe": scalar(
            "SELECT COUNT(*) FROM node_ports WHERE tenant_id = ? AND state = 'open'"
            " AND cpe IS NOT NULL AND cpe <> ''", (tenant_id,), default=0),
    }


def affected_nodes(tenant_id: int, cve_id: str) -> list:
    return [dict(r) for r in query(
        "SELECT f.*, n.ip, n.hostname, n.device_label, p.protocol, p.port"
        " FROM ti_findings f JOIN nodes n ON n.id = f.node_id"
        " LEFT JOIN node_ports p ON p.id = f.port_id"
        " WHERE f.tenant_id = ? AND f.cve_id = ? ORDER BY n.ip",
        (tenant_id, (cve_id or "").upper()))]


def decide(tenant_id: int, finding_id: int, stato: str, note: str = "",
           user_id: int = None) -> bool:
    """Decisione dell'operatore su un riscontro: accettato, falso positivo, riaperto."""
    if stato not in (STATUS_OPEN, STATUS_ACCEPTED, STATUS_FALSE_POSITIVE, STATUS_FIXED):
        raise ThreatError("Stato non previsto per un riscontro.")
    voce = query("SELECT * FROM ti_findings WHERE id = ? AND tenant_id = ?",
                 (finding_id, tenant_id), one=True)
    if voce is None:
        return False
    if stato in (STATUS_ACCEPTED, STATUS_FALSE_POSITIVE) and not (note or "").strip():
        raise ThreatError("Per accettare un rischio o dichiarare un falso positivo"
                          " serve una motivazione: senza, fra sei mesi nessuno sapra'"
                          " perche' quel riscontro e' stato messo da parte.")
    execute("UPDATE ti_findings SET status = ?, note = ?, decided_by = ?, decided_at = ?"
            " WHERE id = ?", (stato, (note or "").strip()[:1000], user_id,
                              utc_now_str(), finding_id))
    log_event("threat.finding.decided",
              "Riscontro #%d su %s portato a '%s'%s"
              % (finding_id, voce["title"], STATUSES[stato],
                 ": %s" % note.strip()[:120] if note else ""),
              tenant_id=tenant_id, severity="info", entity="finding",
              entity_id=finding_id)
    return True


def node_findings(tenant_id: int, node_id: int) -> list:
    """Riscontri di un nodo, per la sua pagina di dettaglio."""
    return findings(tenant_id, status="", node_id=node_id, limit=200)
