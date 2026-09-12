"""
snap server - Ricerca nella base dati: ricerca libera e interrogazioni pronte.

Due modi, perche' le domande sono di due specie.

**Ricerca libera**: si scrive quello che si ha in mano -- un indirizzo, un nome host,
un MAC, un prodotto, una CVE, un pezzo di messaggio -- e il prodotto cerca in tutto
cio' che conosce, dicendo in quale genere di dato ha trovato. E' la ricerca di chi ha
un biglietto in mano e non sa da che parte cominciare.

**Interrogazioni pronte**: domande che si ripetono ("chi espone il desktop remoto?",
"quali apparati parlano in chiaro?", "che cosa e' comparso questa settimana?"),
scritte una volta e disponibili con un clic, esportabili in CSV.

Nessun SQL scritto dall'utente arriva alla banca dati: le interrogazioni sono
dichiarate qui, con parametri legati, e la ricerca libera usa `ILIKE` su colonne
dichiarate. Un campo di ricerca che accettasse SQL sarebbe una porta aperta sul
database di tutti i tenant (OWASP A03), e nessuna comodita' la vale.

`ILIKE` e non `LIKE`: su PostgreSQL `LIKE` distingue le maiuscole, e chi cerca
scrive "cisco" per trovare "Cisco Systems". Vale solo per i termini digitati da una
persona -- i confronti su valori interni (per esempio la provenienza di un MAC)
restano con `LIKE`, dove la distinzione fra maiuscole e minuscole e' voluta.

remarks: Autore: Daniele Speziale - Data: 2026-08-29
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from .db import days_ago_str, query

# Righe per genere nella ricerca libera: il risultato deve stare in una schermata,
# e chi cerca restringe la domanda invece di scorrere trecento righe.
MAX_PER_GENERE = 25
# Righe di un'interrogazione pronta mostrate a video. L'esportazione ne porta di piu':
# un CSV si apre in un foglio di calcolo, una pagina no.
MAX_RIGHE = 200
MAX_RIGHE_CSV = 5000

# Sotto i due caratteri una ricerca restituirebbe mezzo inventario: non e' una
# ricerca, e' un elenco.
MIN_CARATTERI = 2


def _like(testo: str) -> str:
    return "%%%s%%" % testo.strip()


# --------------------------------------------------------------------------- #
# Ricerca libera
# --------------------------------------------------------------------------- #
def global_search(tenant_id: int, testo: str, limit: int = MAX_PER_GENERE) -> dict:
    """Cerca lo stesso testo in tutto cio' che il prodotto conosce.

    Ogni genere di risultato dice dove si trova e come si arriva al dettaglio: un
    elenco piatto di righe senza contesto costringerebbe a indovinare da che tabella
    vengano.
    """
    cercato = (testo or "").strip()
    if len(cercato) < MIN_CARATTERI:
        return {"testo": cercato, "troppo_corto": True, "generi": [], "totale": 0}

    modello = _like(cercato)
    generi = []

    # Il costruttore dichiarato dall'apparato nella propria pagina di gestione (brand)
    # e il modello: sono la fonte piu' autorevole -- e' l'apparato che parla di se' --
    # e vanno mostrati e resi cercabili qui come nell'inventario. Senza, un gruppo
    # frigo Vertiv non si trovava cercando "Vertiv", ne' compariva fra i suoi dati.
    nodi = [dict(r) for r in query(
        "SELECT n.id, n.ip, n.hostname, n.mac, n.mac_vendor, n.os_name,"
        " n.device_label, n.status, s.cidr AS subnet_cidr,"
        " (SELECT w.brand FROM node_web w WHERE w.node_id = n.id"
        "   AND COALESCE(w.brand, '') <> '' ORDER BY w.port LIMIT 1) AS web_vendor,"
        " (SELECT w.model FROM node_web w WHERE w.node_id = n.id"
        "   AND COALESCE(w.model, '') <> '' ORDER BY w.port LIMIT 1) AS web_model"
        " FROM nodes n LEFT JOIN subnets s ON s.id = n.subnet_id"
        " WHERE n.tenant_id = ? AND (n.ip ILIKE ? OR n.hostname ILIKE ?"
        "   OR n.mac ILIKE ? OR n.mac_vendor ILIKE ? OR n.os_name ILIKE ?"
        "   OR n.device_label ILIKE ?"
        "   OR EXISTS (SELECT 1 FROM node_web w WHERE w.node_id = n.id"
        "     AND (COALESCE(w.brand, '') ILIKE ? OR COALESCE(w.model, '') ILIKE ?)))"
        " ORDER BY n.ip LIMIT ?",
        (tenant_id, modello, modello, modello, modello, modello, modello,
         modello, modello, limit))]
    generi.append({"chiave": "nodi", "titolo": "Dispositivi", "icona": "bi-hdd-network",
                   "righe": nodi})

    servizi = [dict(r) for r in query(
        "SELECT p.id, p.protocol, p.port, p.service_name, p.product, p.version,"
        " p.banner, p.cpe, n.id AS node_id, n.ip, n.hostname"
        " FROM node_ports p JOIN nodes n ON n.id = p.node_id"
        " WHERE p.tenant_id = ? AND p.state = 'open'"
        " AND (p.service_name ILIKE ? OR p.product ILIKE ? OR p.version ILIKE ?"
        "      OR p.banner ILIKE ? OR p.cpe ILIKE ?)"
        " ORDER BY n.ip, p.port LIMIT ?",
        (tenant_id, modello, modello, modello, modello, modello, limit))]
    generi.append({"chiave": "servizi", "titolo": "Servizi e porte",
                   "icona": "bi-plug", "righe": servizi})

    riscontri = [dict(r) for r in query(
        "SELECT f.id, f.kind, f.severity, f.title, f.cve_id, f.product, f.version,"
        " f.status, n.id AS node_id, n.ip"
        " FROM ti_findings f JOIN nodes n ON n.id = f.node_id"
        " WHERE f.tenant_id = ? AND (f.title ILIKE ? OR f.cve_id ILIKE ?"
        "   OR f.product ILIKE ? OR f.evidence ILIKE ?)"
        " ORDER BY f.severity, n.ip LIMIT ?",
        (tenant_id, modello, modello, modello, modello, limit))]
    generi.append({"chiave": "riscontri", "titolo": "Vulnerabilita' ed esposizioni",
                   "icona": "bi-shield-exclamation", "righe": riscontri})

    letture = [dict(r) for r in query(
        "SELECT s.script_id, substr(s.output, 1, 200) AS estratto, s.collected_at,"
        " n.id AS node_id, n.ip, n.device_label"
        " FROM node_snmp s JOIN nodes n ON n.id = s.node_id"
        " WHERE s.tenant_id = ? AND s.output ILIKE ? ORDER BY n.ip LIMIT ?",
        (tenant_id, modello, limit))]
    generi.append({"chiave": "snmp", "titolo": "Letture SNMP", "icona": "bi-broadcast",
                   "righe": letture})

    controlli = [dict(r) for r in query(
        "SELECT c.id, c.name, c.kind, c.is_enabled, t.address, t.name AS target_name"
        " FROM checks c JOIN check_targets t ON t.id = c.target_id"
        " WHERE c.tenant_id = ? AND (c.name ILIKE ? OR t.address ILIKE ?"
        "   OR t.name ILIKE ?) ORDER BY c.name LIMIT ?",
        (tenant_id, modello, modello, modello, limit))]
    generi.append({"chiave": "controlli", "titolo": "Controlli e bersagli",
                   "icona": "bi-clipboard-check", "righe": controlli})

    subnet = [dict(r) for r in query(
        "SELECT s.id, s.cidr, s.label, s.host_count, s.is_enabled,"
        " (SELECT COUNT(*) FROM nodes n WHERE n.subnet_id = s.id) AS nodi"
        " FROM subnets s WHERE s.tenant_id = ? AND (s.cidr ILIKE ? OR s.label ILIKE ?)"
        " ORDER BY s.cidr LIMIT ?", (tenant_id, modello, modello, limit))]
    generi.append({"chiave": "subnet", "titolo": "Perimetro",
                   "icona": "bi-bounding-box", "righe": subnet})

    eventi = [dict(r) for r in query(
        "SELECT id, created_at, event_type, severity, description, actor, entity"
        " FROM audit_events WHERE tenant_id = ?"
        " AND (description ILIKE ? OR event_type ILIKE ? OR actor ILIKE ?)"
        " ORDER BY created_at DESC LIMIT ?",
        (tenant_id, modello, modello, modello, limit))]
    generi.append({"chiave": "eventi", "titolo": "Registro eventi",
                   "icona": "bi-journal-text", "righe": eventi})

    cve = [dict(r) for r in query(
        "SELECT cve_id, severity, cvss_score, kev, substr(description, 1, 160)"
        "   AS descrizione FROM ti_cve"
        " WHERE cve_id ILIKE ? OR description ILIKE ? ORDER BY cvss_score DESC LIMIT ?",
        (modello, modello, limit))]
    generi.append({"chiave": "cve", "titolo": "Catalogo CVE (comune a tutti i tenant)",
                   "icona": "bi-database", "righe": cve})

    generi = [g for g in generi if g["righe"]]
    return {
        "testo": cercato,
        "troppo_corto": False,
        "generi": generi,
        "totale": sum(len(g["righe"]) for g in generi),
        "troncato": any(len(g["righe"]) >= limit for g in generi),
    }


# --------------------------------------------------------------------------- #
# Interrogazioni pronte
# --------------------------------------------------------------------------- #
# Ogni voce dichiara: chiave, titolo, la DOMANDA a cui risponde (perche' un titolo da
# solo non dice se serve), le colonne e l'SQL con i suoi parametri. L'SQL sta qui e
# non arriva mai dall'esterno.
def _q(chiave, titolo, domanda, colonne, sql, parametri=None, nota=""):
    return {"chiave": chiave, "titolo": titolo, "domanda": domanda,
            "colonne": colonne, "sql": sql, "parametri": parametri or (lambda t: (t,)),
            "nota": nota}


def _anno_di(quanti_anni_fa: int) -> int:
    """L'anno di tanti anni fa.

    La soglia si calcola ADESSO e non si scrive in tabella: una soglia scritta
    invecchia insieme al codice che la contiene, e fra due anni direbbe un'altra cosa.
    """
    from datetime import date

    return date.today().year - int(quanti_anni_fa)


def _fra_giorni(giorni: int) -> str:
    """Una data futura in forma ISO, per confrontarla con le scadenze dei certificati:
    l'archivio le conserva come testo ISO, e il confronto fra testi ISO ordina bene."""
    from datetime import date, timedelta

    return (date.today() + timedelta(days=int(giorni))).isoformat()


def _minuti_fa(minuti: int) -> str:
    """L'istante di tanti minuti fa, nella scrittura dell'archivio."""
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc)
            - timedelta(minutes=int(minuti))).strftime("%Y-%m-%d %H:%M:%S")


SAVED_QUERIES = [
    _q("desktop_remoto", "Chi espone il desktop remoto",
       "Quali dispositivi rispondono su RDP o VNC? E' la prima porta che un attacco"
       " con credenziali rubate prova.",
       ["indirizzo", "nome host", "dispositivo", "porta", "servizio", "vista dal"],
       "SELECT n.ip, n.hostname, n.device_label, p.protocol || '/' || p.port,"
       " p.service_name, p.first_seen_at"
       " FROM node_ports p JOIN nodes n ON n.id = p.node_id"
       " WHERE p.tenant_id = ? AND p.state = 'open'"
       " AND COALESCE(p.is_suspect, 0) = 0 AND p.port IN (3389, 5900, 5901)"
       " ORDER BY n.ip"),

    _q("in_chiaro", "Chi parla in chiaro",
       "Telnet, FTP, HTTP di gestione: protocolli che trasportano credenziali"
       " leggibili da chiunque sia sul percorso.",
       ["indirizzo", "dispositivo", "porta", "servizio", "prodotto"],
       "SELECT n.ip, n.device_label, p.protocol || '/' || p.port, p.service_name,"
       " COALESCE(p.product, '')"
       " FROM node_ports p JOIN nodes n ON n.id = p.node_id"
       " WHERE p.tenant_id = ? AND p.state = 'open'"
       " AND COALESCE(p.is_suspect, 0) = 0 AND p.port IN (21, 23, 69, 110, 143, 512,"
       " 513, 514) ORDER BY p.port, n.ip"),

    _q("banche_dati", "Banche dati raggiungibili",
       "Una banca dati raggiungibile da una rete di utenza non ha ragione di esserlo.",
       ["indirizzo", "dispositivo", "porta", "servizio", "prodotto", "versione"],
       "SELECT n.ip, n.device_label, p.protocol || '/' || p.port, p.service_name,"
       " COALESCE(p.product, ''), COALESCE(p.version, '')"
       " FROM node_ports p JOIN nodes n ON n.id = p.node_id"
       " WHERE p.tenant_id = ? AND p.state = 'open'"
       " AND COALESCE(p.is_suspect, 0) = 0"
       " AND p.port IN (1433, 1521, 3306, 5432, 6379, 9200, 27017) ORDER BY n.ip"),

    _q("con_versione", "Servizi che dichiarano la versione",
       "Sono i soli su cui una vulnerabilita' puo' essere confermata: senza versione"
       " il riscontro resta da verificare.",
       ["indirizzo", "porta", "servizio", "prodotto", "versione", "CPE"],
       "SELECT n.ip, p.protocol || '/' || p.port, p.service_name, p.product,"
       " p.version, COALESCE(p.cpe, '')"
       " FROM node_ports p JOIN nodes n ON n.id = p.node_id"
       " WHERE p.tenant_id = ? AND p.state = 'open' AND p.version IS NOT NULL"
       " AND p.version <> '' ORDER BY p.product, p.version"),

    _q("non_identificati", "Dispositivi da identificare, con porte aperte",
       "Un apparato che risponde su piu' porte e non si sa che cosa sia e' il primo"
       " da guardare in un inventario.",
       ["indirizzo", "nome host", "sistema operativo", "confidenza", "porte aperte"],
       "SELECT n.ip, COALESCE(n.hostname, ''), COALESCE(n.os_name, ''),"
       " COALESCE(n.device_confidence, 0),"
       " (SELECT COUNT(*) FROM node_ports p WHERE p.node_id = n.id"
       "   AND p.state = 'open' AND COALESCE(p.is_suspect, 0) = 0) AS porte"
       " FROM nodes n WHERE n.tenant_id = ?"
       " AND (n.device_type IS NULL OR n.device_type = 'unknown'"
       "      OR COALESCE(n.device_confidence, 0) < 60)"
       # "porte > 0" nella WHERE usava l'alias di una colonna calcolata: SQLite lo
       # consentiva, PostgreSQL no (l'alias non esiste ancora quando la WHERE si
       # valuta). EXISTS dice la stessa cosa e non conta cio' che non serve contare.
       " AND EXISTS (SELECT 1 FROM node_ports p WHERE p.node_id = n.id"
       "   AND p.state = 'open' AND COALESCE(p.is_suspect, 0) = 0)"
       " ORDER BY porte DESC, n.ip"),

    _q("comparsi", "Comparsi negli ultimi sette giorni",
       "Un indirizzo nuovo e' sempre una domanda: chi lo ha collegato, e perche'.",
       ["indirizzo", "nome host", "dispositivo", "subnet", "visto la prima volta"],
       "SELECT n.ip, COALESCE(n.hostname, ''), COALESCE(n.device_label, ''),"
       " COALESCE(s.cidr, 'fuori perimetro'), n.first_seen_at"
       " FROM nodes n LEFT JOIN subnets s ON s.id = n.subnet_id"
       " WHERE n.tenant_id = ? AND n.first_seen_at >= ?"
       " ORDER BY n.first_seen_at DESC",
       parametri=lambda t: (t, days_ago_str(7))),

    _q("spariti", "In silenzio da oltre sette giorni",
       "Dispositivi che non rispondono piu': spenti di proposito o guasti, la"
       " differenza la sa chi conosce la rete.",
       ["indirizzo", "nome host", "dispositivo", "ultimo contatto", "stato"],
       "SELECT n.ip, COALESCE(n.hostname, ''), COALESCE(n.device_label, ''),"
       " n.last_seen_at, n.status FROM nodes n"
       " WHERE n.tenant_id = ? AND n.last_seen_at < ? ORDER BY n.last_seen_at",
       parametri=lambda t: (t, days_ago_str(7))),

    _q("porte_diffuse", "Porte piu' diffuse in rete",
       "Che cosa risponde su piu' dispositivi: dice come e' fatta la rete meglio di"
       " qualunque elenco.",
       ["porta", "servizio", "dispositivi", "prodotti distinti"],
       "SELECT p.protocol || '/' || p.port, MAX(COALESCE(p.service_name, '')),"
       " COUNT(DISTINCT p.node_id) AS nodi, COUNT(DISTINCT p.product) AS prodotti"
       " FROM node_ports p WHERE p.tenant_id = ? AND p.state = 'open'"
       " AND COALESCE(p.is_suspect, 0) = 0"
       " GROUP BY p.protocol, p.port ORDER BY nodi DESC"),

    _q("prodotti", "Prodotti riconosciuti in rete",
       "L'elenco su cui lavora la correlazione con le vulnerabilita' note.",
       ["prodotto", "versioni distinte", "dispositivi", "porte"],
       "SELECT p.product, COUNT(DISTINCT COALESCE(p.version, '')) AS versioni,"
       " COUNT(DISTINCT p.node_id) AS nodi, COUNT(*) AS porte"
       " FROM node_ports p WHERE p.tenant_id = ? AND p.state = 'open'"
       " AND p.product IS NOT NULL AND p.product <> ''"
       " GROUP BY p.product ORDER BY nodi DESC"),

    _q("snmp_aperti", "Apparati che rispondono a SNMP",
       "Con la community di fabbrica un apparato racconta interfacce, processi e"
       " software installato a chiunque raggiunga la porta.",
       ["indirizzo", "dispositivo", "descrizione dichiarata", "letto il"],
       "SELECT n.ip, COALESCE(n.device_label, ''),"
       " COALESCE((SELECT substr(x.output, 1, 90) FROM node_snmp x"
       "   WHERE x.node_id = n.id AND x.script_id = 'snmp-sysdescr'), ''),"
       " MAX(s.collected_at)"
       " FROM node_snmp s JOIN nodes n ON n.id = s.node_id"
       " WHERE s.tenant_id = ? GROUP BY n.id ORDER BY n.ip"),

    _q("kev", "Vulnerabilita' sfruttate attivamente",
       "Fra due vulnerabilita' con lo stesso punteggio, quella che risulta sfruttata"
       " in attacchi reali va prima.",
       ["indirizzo", "CVE", "gravita'", "punteggio", "prodotto", "stato"],
       "SELECT n.ip, f.cve_id, f.severity, COALESCE(f.score, 0),"
       " COALESCE(f.product, ''), f.status"
       " FROM ti_findings f JOIN nodes n ON n.id = f.node_id"
       " JOIN ti_cve c ON c.cve_id = f.cve_id"
       " WHERE f.tenant_id = ? AND c.kev = 1 ORDER BY f.score DESC"),

    _q("controlli_peggiori", "Controlli che falliscono di piu'",
       "Dove si consuma il turno: sette giorni di esiti, ordinati per fallimenti.",
       ["controllo", "bersaglio", "esiti", "falliti", "riuscita %"],
       "SELECT c.name, t.address, COUNT(*) AS esiti,"
       " SUM(CASE WHEN r.status <> 'ok' THEN 1 ELSE 0 END) AS falliti,"
       " ROUND(100.0 * SUM(CASE WHEN r.status = 'ok' THEN 1 ELSE 0 END) / COUNT(*), 1)"
       " FROM check_results r JOIN checks c ON c.id = r.check_id"
       " JOIN check_targets t ON t.id = c.target_id"
       " WHERE r.tenant_id = ? AND r.executed_at >= ?"
       # `falliti` e' un alias: in HAVING si ripete l'espressione.
       " GROUP BY c.id, t.address"
       " HAVING SUM(CASE WHEN r.status <> 'ok' THEN 1 ELSE 0 END) > 0"
       " ORDER BY falliti DESC",
       parametri=lambda t: (t, days_ago_str(7))),

    _q("latenza", "Bersagli piu' lenti",
       "La lentezza precede spesso il guasto: sette giorni di misure.",
       ["controllo", "bersaglio", "misure", "latenza media (ms)", "massima (ms)"],
       "SELECT c.name, t.address, COUNT(*) AS misure,"
       " ROUND(AVG(r.latency_ms)::numeric, 1), MAX(r.latency_ms)"
       " FROM check_results r JOIN checks c ON c.id = r.check_id"
       " JOIN check_targets t ON t.id = c.target_id"
       " WHERE r.tenant_id = ? AND r.executed_at >= ? AND r.latency_ms IS NOT NULL"
       " GROUP BY c.id, t.address HAVING COUNT(*) >= 3"
       " ORDER BY AVG(r.latency_ms) DESC",
       parametri=lambda t: (t, days_ago_str(7))),

    _q("copertura", "Copertura del perimetro dichiarato",
       "Quanto di cio' che si e' dichiarato di sorvegliare e' stato davvero visto.",
       ["subnet", "etichetta", "indirizzi possibili", "nodi trovati", "attivi",
        "occupazione %"],
       "SELECT s.cidr, COALESCE(s.label, ''), s.host_count,"
       " (SELECT COUNT(*) FROM nodes n WHERE n.subnet_id = s.id) AS nodi,"
       " (SELECT COUNT(*) FROM nodes n WHERE n.subnet_id = s.id AND n.status = 'up'),"
       " ROUND(100.0 * (SELECT COUNT(*) FROM nodes n WHERE n.subnet_id = s.id)"
       "   / NULLIF(s.host_count, 0), 1)"
       " FROM subnets s WHERE s.tenant_id = ? ORDER BY nodi DESC"),

    _q("eventi_gravi", "Eventi gravi del registro",
       "Che cosa il sistema ha annotato come degno di attenzione negli ultimi sette"
       " giorni.",
       ["quando", "tipo", "gravita'", "descrizione", "attore"],
       "SELECT created_at, event_type, severity, substr(description, 1, 120),"
       " COALESCE(actor, '') FROM audit_events"
       " WHERE tenant_id = ? AND severity IN ('warning', 'critical')"
       " AND created_at >= ? ORDER BY created_at DESC",
       parametri=lambda t: (t, days_ago_str(7))),

    # ----------------------------------------------------------------------- #
    # I nodi delle relazioni
    #
    # Ogni relazione del catalogo risponde a una domanda; queste interrogazioni
    # portano agli STESSI dispositivi, ma qui e ora e in forma esportabile. Servono a
    # chi il documento lo ha letto e adesso deve lavorarci: il PDF si consegna, il CSV
    # si apre.
    # ----------------------------------------------------------------------- #
    _q("vetusta_grave", "Interfacce ferme da oltre dieci anni",
       "Quali interfacce web dichiarano un anno anteriore a dieci anni fa? Sono i"
       " nodi della relazione sulla vetusta' del parco: non e' la prova che il"
       " software sia di allora, e' la prova che da allora non lo tocca nessuno.",
       ["indirizzo", "nome host", "dispositivo", "porta", "prodotto", "anno",
        "fonte dell'anno"],
       "SELECT n.ip, COALESCE(n.hostname, ''), COALESCE(n.device_label, ''),"
       " w.scheme || '/' || w.port,"
       " COALESCE(w.product, COALESCE(w.server_header, '')),"
       " w.web_year, COALESCE(w.web_year_source, '')"
       " FROM node_web w JOIN nodes n ON n.id = w.node_id"
       " WHERE w.tenant_id = ? AND w.web_year IS NOT NULL AND w.web_year > 0"
       " AND w.web_year <= ? ORDER BY w.web_year, n.ip",
       parametri=lambda t: (t, _anno_di(10)),
       nota="E' la sezione \"Ferme da oltre dieci anni\" della relazione sulla"
            " vetusta' del parco, con gli stessi dispositivi."),

    _q("vetusta_muta", "Interfacce che non dichiarano alcun anno",
       "Quali interfacce web non lasciano capire la propria eta'? Non sono"
       " \"recenti\": sono mute, ed e' una cosa diversa -- nella relazione sulla"
       " vetusta' non compaiono, e questa e' la loro lista.",
       ["indirizzo", "nome host", "dispositivo", "porta", "prodotto", "titolo"],
       "SELECT n.ip, COALESCE(n.hostname, ''), COALESCE(n.device_label, ''),"
       " w.scheme || '/' || w.port,"
       " COALESCE(w.product, COALESCE(w.server_header, '')),"
       " substr(COALESCE(w.title, ''), 1, 60)"
       " FROM node_web w JOIN nodes n ON n.id = w.node_id"
       " WHERE w.tenant_id = ? AND (w.web_year IS NULL OR w.web_year = 0)"
       " ORDER BY n.ip"),

    _q("smb_senza_firma", "Dove la firma SMB non e' richiesta",
       "Su quali dispositivi la firma dei messaggi e' abilitata ma NON richiesta? E'"
       " il presupposto degli attacchi di inoltro NTLM, e sono i nodi della relazione"
       " sull'esposizione SMB.",
       ["indirizzo", "nome host", "dispositivo", "sistema", "che cosa dichiara",
        "letto il"],
       "SELECT n.ip, COALESCE(n.hostname, ''), COALESCE(n.device_label, ''),"
       " COALESCE(n.os_name, ''), substr(m.output, 1, 90), m.collected_at"
       " FROM node_smb m JOIN nodes n ON n.id = m.node_id"
       " WHERE m.tenant_id = ? AND m.script_id LIKE '%security-mode%'"
       " AND LOWER(m.output) LIKE '%enabled but not required%'"
       " ORDER BY n.ip"),

    _q("smb_uno", "Chi parla ancora SMB 1.0",
       "Quali dispositivi accettano il dialetto SMB 1.0? Si riconosce dal nome"
       " storico \"NT LM 0.12\": chi lo accetta resta esposto anche se dichiara pure"
       " le versioni recenti, perche' e' il client a scegliere.",
       ["indirizzo", "nome host", "dispositivo", "sistema", "dialetti dichiarati"],
       "SELECT n.ip, COALESCE(n.hostname, ''), COALESCE(n.device_label, ''),"
       " COALESCE(n.os_name, ''), substr(m.output, 1, 90)"
       " FROM node_smb m JOIN nodes n ON n.id = m.node_id"
       " WHERE m.tenant_id = ? AND m.script_id LIKE '%protocols%'"
       " AND LOWER(m.output) LIKE '%nt lm 0.12%' ORDER BY n.ip"),

    _q("certificati_in_scadenza", "Certificati TLS scaduti o in scadenza",
       "Quali certificati sono gia' scaduti o scadono entro trenta giorni? Un"
       " certificato che scade non e' un rischio teorico: e' un servizio che smette"
       " di funzionare a una data nota.",
       ["indirizzo", "nome host", "porta", "soggetto", "emittente", "scade il"],
       "SELECT n.ip, COALESCE(n.hostname, ''), w.port,"
       " substr(COALESCE(w.cert_subject, ''), 1, 60),"
       " substr(COALESCE(w.cert_issuer, ''), 1, 60), w.cert_expires"
       " FROM node_web w JOIN nodes n ON n.id = w.node_id"
       " WHERE w.tenant_id = ? AND w.cert_expires IS NOT NULL"
       " AND w.cert_expires <> '' AND substr(w.cert_expires, 1, 10) <= ?"
       " ORDER BY w.cert_expires",
       parametri=lambda t: (t, _fra_giorni(30))),

    _q("reti_mai_guardate", "Reti dichiarate e mai guardate",
       "Quali subnet sono nel perimetro, attive, e nessuna passata ha mai preso come"
       " bersaglio? Sono i punti ciechi: non producono righe in nessun altro elenco,"
       " e una tabella vuota si legge come \"niente da segnalare\".",
       ["subnet", "etichetta", "zona", "indirizzi possibili", "dichiarata il"],
       "SELECT s.cidr, COALESCE(s.label, ''), COALESCE(s.zone, ''), s.host_count,"
       " s.created_at FROM subnets s"
       " WHERE s.tenant_id = ? AND s.is_enabled = 1"
       " AND NOT EXISTS (SELECT 1 FROM scan_runs r WHERE r.tenant_id = s.tenant_id"
       "   AND r.target = s.cidr) ORDER BY s.cidr"),

    _q("presenti_ora", "Chi e' in rete adesso, senza fili",
       "Quali apparati sono stati visti sulle reti senza fili negli ultimi cinque"
       " minuti, e da che cosa sono riconosciuti? E' l'elenco della pagina delle"
       " presenze, in forma esportabile.",
       ["apparato", "indirizzo", "MAC", "riconosciuto da", "qui dalle",
        "ultimo avvistamento"],
       "SELECT COALESCE(p.device_label, COALESCE(p.hostname, 'non identificato')),"
       " p.ip, COALESCE(p.mac, ''), p.identity_source, p.first_seen_at,"
       " p.last_seen_at FROM presence_sessions p"
       " WHERE p.tenant_id = ? AND p.last_seen_at >= ?"
       " ORDER BY p.last_seen_at DESC",
       parametri=lambda t: (t, _minuti_fa(5))),

    _q("conferimenti", "Conferimenti rifiutati o parziali",
       "Se una sonda consegna e il server rifiuta, l'inventario invecchia senza che"
       " nessuno se ne accorga.",
       ["quando", "sonda", "record", "esito", "dettaglio"],
       "SELECT b.received_at, COALESCE(p.name, ''), b.record_count, b.status,"
       " substr(COALESCE(b.detail, ''), 1, 120)"
       " FROM ingest_batches b LEFT JOIN probes p ON p.id = b.probe_id"
       " WHERE b.tenant_id = ? AND b.status <> 'accepted'"
       " ORDER BY b.received_at DESC"),
]

SAVED_BY_KEY = {voce["chiave"]: voce for voce in SAVED_QUERIES}


def run_saved(tenant_id: int, chiave: str, limit: int = MAX_RIGHE) -> dict:
    """Esegue un'interrogazione pronta. La chiave deve esistere: niente SQL da fuori."""
    voce = SAVED_BY_KEY.get(chiave)
    if voce is None:
        return {}
    parametri = tuple(voce["parametri"](tenant_id)) + (int(limit),)
    # `celle()` e non `list(r)`: una riga di risultato e' un Mapping, e scorrerla
    # da' i NOMI delle colonne -- l'esportazione CSV consegnava una riga di
    # intestazioni al posto dei dati. E nemmeno `values()`: queste interrogazioni
    # hanno piu' espressioni senza alias, che finiscono con lo stesso nome e in un
    # dizionario si sovrascrivono. `celle()` da' le colonne del SELECT, tutte.
    righe = [list(r.celle())
             for r in query(voce["sql"] + " LIMIT ?", parametri)]

    # Quando la prima colonna e' un indirizzo di nodo, si porta accanto a ogni riga
    # l'identificativo del nodo, cosi' la pagina puo' rendere l'indirizzo cliccabile
    # verso la scheda del dispositivo. La colonna dei valori NON cambia (l'export CSV
    # resta identico): l'identificativo viaggia a parte.
    colonna_indirizzo = (voce["colonne"].index("indirizzo")
                         if "indirizzo" in voce["colonne"] else None)
    nodi = []
    if colonna_indirizzo is not None and righe:
        mappa = {r["ip"]: int(r["id"]) for r in query(
            "SELECT id, ip FROM nodes WHERE tenant_id = ?", (tenant_id,))}
        nodi = [mappa.get(riga[colonna_indirizzo]) for riga in righe]

    return {
        "chiave": voce["chiave"],
        "titolo": voce["titolo"],
        "domanda": voce["domanda"],
        "colonne": voce["colonne"],
        "righe": righe,
        # Indice della colonna dell'indirizzo (o None) e id del nodo per riga: servono
        # solo alla pagina, per il collegamento.
        "colonna_indirizzo": colonna_indirizzo,
        "nodi": nodi,
        "troncato": len(righe) >= limit,
        "limite": limit,
    }
