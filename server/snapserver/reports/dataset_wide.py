"""
snap server - Dati dei report di periodo: esecutivo, inventario tecnico, sicurezza.

Sta accanto a `dataset.py` e non dentro: le sezioni del resoconto quotidiano rispondono
a "che cosa e' successo ieri", queste a "come stiamo su un periodo". Le interrogazioni
sono diverse -- confronto con il periodo precedente, categorie di rischio, copertura del
perimetro -- e tenerle separate evita un modulo in cui non si trova piu' nulla.

Regole che valgono anche qui (docs/08_REPORT.md): RP-03 riproducibilita', RP-05 l'assenza
di dati non e' uno zero, RP-10 minimizzazione (il report esecutivo non contiene
indirizzi), RP-12 la variazione e' il segnale.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from datetime import timedelta

from ..checks import INCIDENT_ACK, INCIDENT_OPEN, STATUS_OK
from ..db import parse_utc, query, scalar
from . import dataset
from .windows import day_bounds, days_bounds

# Categorie di rischio delle porte. Il numero di porta non dice nulla a chi legge un
# report; la categoria si': "amministrazione remota raggiungibile su 12 nodi" e' una
# frase su cui si decide. L'elenco e' volutamente corto e commentato: una tassonomia
# lunga non viene letta.
RISK_CATEGORIES = [
    ("amministrazione", "Amministrazione remota", [22, 23, 3389, 5900, 5985, 5986],
     "Chi entra qui comanda il dispositivo. Su una rete interna e' normale che ci sia;"
     " che sia raggiungibile da tutti non lo e'."),
    ("condivisione", "Condivisione file", [139, 445, 2049],
     "E' la strada su cui si propagano i ransomware fra dispositivi della stessa rete."),
    ("banche_dati", "Banche dati", [1433, 1521, 3306, 5432, 6379, 27017, 9200],
     "Una banca dati raggiungibile dalla rete di utenza non ha ragione di esserlo."),
    ("gestione", "Gestione degli apparati", [161, 8080, 8443, 10000, 10001, 4443],
     "Console e agenti di gestione: spesso con credenziali predefinite mai cambiate."),
    ("stampa", "Stampa e periferiche", [515, 631, 9100],
     "Poco rischiose in se', utili a riconoscere cosa c'e' in rete."),
    ("telefonia", "Telefonia e videoconferenza", [2000, 5060, 5061, 1720],
     "Su molti nodi contemporaneamente indicano un apparato che risponde per altri,"
     " non altrettanti servizi."),
    ("legacy", "Protocolli in chiaro", [21, 23, 69, 110, 143, 512, 513, 514],
     "Trasportano credenziali leggibili da chiunque sia sul percorso."),
]

# Quanto si porta in un report: oltre, un elenco diventa un archivio stampato.
MAX_NODI = 400
MAX_SERVIZI = 600
MAX_VARIAZIONI = 200
MAX_AUDIT = 120


def _categoria_di(porta: int) -> tuple:
    for chiave, etichetta, porte, _nota in RISK_CATEGORIES:
        if porta in porte:
            return chiave, etichetta
    return "altro", "Altri servizi"


# --------------------------------------------------------------------------- #
# Indicatori di periodo e confronto
# --------------------------------------------------------------------------- #
def kpi(tenant_id: int, inizio: str, fine: str) -> dict:
    """Indicatori del periodo. `None` dove non e' stato misurato nulla (RP-05)."""
    esiti = query(
        "SELECT COUNT(*) AS esiti, COALESCE(SUM(status = ?), 0) AS riusciti,"
        " ROUND(AVG(latency_ms), 1) AS latenza"
        " FROM check_results WHERE tenant_id = ? AND executed_at >= ?"
        " AND executed_at < ?", (STATUS_OK, tenant_id, inizio, fine), one=True)
    incidenti = query(
        "SELECT COUNT(*) AS aperti FROM check_incidents WHERE tenant_id = ?"
        " AND opened_at >= ? AND opened_at < ?", (tenant_id, inizio, fine), one=True)
    risolti = query(
        "SELECT COUNT(*) AS risolti, opened_at, resolved_at FROM check_incidents"
        " WHERE tenant_id = ? AND resolved_at >= ? AND resolved_at < ?",
        (tenant_id, inizio, fine), one=True)
    durate = [
        int((parse_utc(r["resolved_at"]) - parse_utc(r["opened_at"])).total_seconds() // 60)
        for r in query("SELECT opened_at, resolved_at FROM check_incidents"
                       " WHERE tenant_id = ? AND resolved_at >= ? AND resolved_at < ?"
                       " AND opened_at IS NOT NULL", (tenant_id, inizio, fine))
        if parse_utc(r["resolved_at"]) and parse_utc(r["opened_at"])]

    variazioni = scalar("SELECT COUNT(*) FROM node_changes WHERE tenant_id = ?"
                        " AND created_at >= ? AND created_at < ?",
                        (tenant_id, inizio, fine), default=0)
    nuovi = scalar("SELECT COUNT(*) FROM nodes WHERE tenant_id = ? AND first_seen_at >= ?"
                   " AND first_seen_at < ?", (tenant_id, inizio, fine), default=0)

    numero_esiti = int(esiti["esiti"] or 0)
    return {
        "esiti": numero_esiti,
        "disponibilita": (round(100.0 * int(esiti["riusciti"] or 0) / numero_esiti, 2)
                          if numero_esiti else None),
        "latenza_media": esiti["latenza"],
        "incidenti_aperti": int(incidenti["aperti"] or 0),
        "incidenti_risolti": int(risolti["risolti"] or 0) if risolti else 0,
        "tempo_risoluzione_medio": int(sum(durate) / len(durate)) if durate else None,
        "variazioni": int(variazioni or 0),
        "nodi_nuovi": int(nuovi or 0),
    }


def kpi_confronto(tenant_id: int, zona, giorno_fine, giorni: int) -> dict:
    """Indicatori del periodo e dello stesso periodo precedente, con la differenza.

    Un valore da solo non permette di decidere: "disponibilita' 99,1%" diventa una
    notizia solo accanto a "era 99,7%".
    """
    inizio, fine = days_bounds(zona, giorni, fino_a=giorno_fine)
    precedente_fine = giorno_fine - timedelta(days=giorni)
    inizio_prec, fine_prec = days_bounds(zona, giorni, fino_a=precedente_fine)

    corrente = kpi(tenant_id, inizio, fine)
    precedente = kpi(tenant_id, inizio_prec, fine_prec)
    differenze = {}
    for chiave, valore in corrente.items():
        prima = precedente.get(chiave)
        if valore is None or prima is None:
            differenze[chiave] = None
            continue
        differenze[chiave] = round(valore - prima, 2)
    return {
        "corrente": corrente, "precedente": precedente, "differenza": differenze,
        "inizio": inizio, "fine": fine,
        "inizio_precedente": inizio_prec, "fine_precedente": fine_prec,
        "giorni": giorni,
        "precedente_misurato": precedente["esiti"] > 0,
    }


# --------------------------------------------------------------------------- #
# Superficie esposta
# --------------------------------------------------------------------------- #
def exposure(tenant_id: int) -> dict:
    """Porte aperte raggruppate per categoria di rischio, con i nodi coinvolti."""
    righe = query(
        "SELECT p.protocol, p.port, COUNT(DISTINCT p.node_id) AS nodi,"
        " COALESCE(SUM(p.is_suspect), 0) AS sospette,"
        " MAX(p.service_name) AS servizio, MAX(p.product) AS prodotto"
        " FROM node_ports p WHERE p.tenant_id = ? AND p.state = 'open'"
        " GROUP BY p.protocol, p.port ORDER BY nodi DESC", (tenant_id,))

    per_categoria = {}
    for riga in righe:
        chiave, etichetta = _categoria_di(int(riga["port"]))
        voce = per_categoria.setdefault(chiave, {
            "chiave": chiave, "etichetta": etichetta, "porte": [], "nodi": 0,
            "nota": next((n for c, _e, _p, n in RISK_CATEGORIES if c == chiave),
                         "Servizi non classificati."),
        })
        voce["porte"].append({
            "porta": "%s/%s" % (riga["protocol"], riga["port"]),
            "nodi": int(riga["nodi"] or 0),
            "servizio": riga["servizio"] or "",
            "prodotto": riga["prodotto"] or "",
            "sospette": int(riga["sospette"] or 0),
        })
        voce["nodi"] = max(voce["nodi"], int(riga["nodi"] or 0))

    ordine = [c for c, *_ in RISK_CATEGORIES] + ["altro"]
    categorie = [per_categoria[c] for c in ordine if c in per_categoria]
    return {
        "categorie": categorie,
        "porte_aperte": sum(len(c["porte"]) for c in categorie),
        "amministrazione": next((c["nodi"] for c in categorie
                                 if c["chiave"] == "amministrazione"), 0),
    }


def snmp_readable(tenant_id: int) -> list:
    """Nodi su cui SNMP risponde: e' esposizione informativa, non un guasto."""
    return [dict(r) for r in query(
        "SELECT n.ip, n.hostname, n.device_label, p.service_name, p.extrainfo"
        " FROM node_ports p JOIN nodes n ON n.id = p.node_id"
        " WHERE p.tenant_id = ? AND p.protocol = 'udp' AND p.port = 161"
        " AND p.state = 'open' ORDER BY inet(n.ip)", (tenant_id,))]


def snmp_devices(tenant_id: int, limit: int = 200) -> list:
    """Apparati che hanno risposto a SNMP, con cio' che hanno raccontato di se'.

    E' la parte piu' ricca dell'inventario tecnico: su switch, stampanti e apparati
    di rete la descrizione di sistema porta modello e firmware, che nessuna porta TCP
    dichiara. Il riassunto e' gia' calcolato al conferimento (`node_snmp.summary`):
    qui si legge, non si reinterpreta.
    """
    import json as _json

    righe = []
    for riga in query(
            "SELECT n.ip, n.hostname, n.device_label, s.parsed_json, s.collected_at"
            " FROM node_snmp s JOIN nodes n ON n.id = s.node_id"
            " WHERE s.tenant_id = ? AND s.script_id = 'summary'"
            " ORDER BY inet(n.ip)", (tenant_id,)):
        try:
            riassunto = _json.loads(riga["parsed_json"] or "{}")
        except (TypeError, ValueError):
            riassunto = {}
        voce = dict(riga)
        voce.pop("parsed_json", None)
        voce.update({
            "descrizione": riassunto.get("sysdescr") or "",
            "nome": riassunto.get("sysname") or "",
            "costruttore": riassunto.get("enterprise") or "",
            "accensione": riassunto.get("uptime") or "",
            "collocazione": riassunto.get("location") or "",
            "riferimento": riassunto.get("contact") or "",
            "community": riassunto.get("community") or "",
            "interfacce": riassunto.get("interfacce") or 0,
            "processi": riassunto.get("processi") or 0,
            "software": riassunto.get("software") or 0,
            "connessioni": riassunto.get("connessioni") or 0,
            "utenti": riassunto.get("utenti") or 0,
            "condivisioni": riassunto.get("condivisioni") or 0,
        })
        righe.append(voce)
    return righe


def snmp_coverage(tenant_id: int) -> dict:
    """Quanti apparati espongono SNMP, quanti hanno risposto, che cosa hanno detto."""
    esposti = scalar(
        "SELECT COUNT(DISTINCT node_id) FROM node_ports WHERE tenant_id = ?"
        " AND protocol = 'udp' AND port = 161 AND state = 'open'",
        (tenant_id,), default=0)
    letti = scalar("SELECT COUNT(DISTINCT node_id) FROM node_snmp WHERE tenant_id = ?",
                   (tenant_id,), default=0)
    voci = snmp_devices(tenant_id, limit=1000)
    return {
        "esposti": esposti,
        "letti": letti,
        # Non e' un guasto: la fase ha una cadenza propria, e un apparato puo' avere
        # una community diversa da quella di fabbrica. Dirlo evita di leggere il
        # numero come una mancanza del prodotto.
        "da_leggere": max(0, esposti - letti),
        "con_descrizione": len([v for v in voci if v["descrizione"]]),
        "con_collocazione": len([v for v in voci if v["collocazione"]]),
        "interfacce": sum(v["interfacce"] for v in voci),
        "processi": sum(v["processi"] for v in voci),
        "software": sum(v["software"] for v in voci),
        "connessioni": sum(v["connessioni"] for v in voci),
        "utenti": sum(v["utenti"] for v in voci),
    }


def out_of_perimeter(tenant_id: int) -> list:
    """Nodi che non appartengono a nessuna subnet dichiarata o a una sospesa."""
    return [dict(r) for r in query(
        "SELECT n.ip, n.hostname, n.device_label, s.cidr, s.is_enabled"
        " FROM nodes n LEFT JOIN subnets s ON s.id = n.subnet_id"
        " WHERE n.tenant_id = ? AND (n.subnet_id IS NULL OR s.is_enabled = 0)"
        " ORDER BY inet(n.ip)", (tenant_id,))]


# --------------------------------------------------------------------------- #
# Variazioni di sicurezza
# --------------------------------------------------------------------------- #
def security_changes(tenant_id: int, inizio: str, fine: str) -> dict:
    """Variazioni del periodo che contano per la sicurezza, in ordine di precedenza.

    Le porte aperte vengono classificate per categoria di rischio: un elenco di numeri
    non permette di decidere, "si e' aperta l'amministrazione remota su tre nodi" si'.
    """
    aperte = query(
        "SELECT c.subject, c.after_value, c.created_at, n.ip, n.hostname, n.device_label"
        " FROM node_changes c LEFT JOIN nodes n ON n.id = c.node_id"
        " WHERE c.tenant_id = ? AND c.kind = 'port.opened' AND c.created_at >= ?"
        " AND c.created_at < ? ORDER BY c.created_at DESC LIMIT ?",
        (tenant_id, inizio, fine, MAX_VARIAZIONI))

    per_categoria = {}
    for riga in aperte:
        protocollo, _, numero = (riga["subject"] or "").partition("/")
        if not numero.isdigit():
            continue
        chiave, etichetta = _categoria_di(int(numero))
        voce = per_categoria.setdefault(chiave, {"etichetta": etichetta, "eventi": []})
        voce["eventi"].append({
            "porta": riga["subject"], "servizio": riga["after_value"] or "",
            "nodo": riga["ip"] or "?", "nome": riga["hostname"] or "",
            "etichetta_nodo": riga["device_label"] or "", "quando": riga["created_at"],
        })

    def _variazioni(genere):
        return [dict(r) for r in query(
            "SELECT c.subject, c.before_value, c.after_value, c.created_at, n.ip,"
            " n.hostname FROM node_changes c LEFT JOIN nodes n ON n.id = c.node_id"
            " WHERE c.tenant_id = ? AND c.kind = ? AND c.created_at >= ?"
            " AND c.created_at < ? ORDER BY c.created_at DESC LIMIT ?",
            (tenant_id, genere, inizio, fine, MAX_VARIAZIONI))]

    return {
        "porte_per_categoria": [
            per_categoria[c] for c, *_ in RISK_CATEGORIES if c in per_categoria
        ] + ([per_categoria["altro"]] if "altro" in per_categoria else []),
        "porte_aperte_totali": len(aperte),
        "nodi_comparsi": _variazioni("node.appeared"),
        "nodi_scomparsi": _variazioni("node.disappeared"),
        "sistemi_cambiati": _variazioni("os.changed"),
        "nomi_cambiati": _variazioni("hostname.changed"),
        "indirizzi_fisici_cambiati": _variazioni("mac.changed"),
        "porte_chiuse": len(_variazioni("port.closed")),
    }


def audit_digest(tenant_id: int, inizio: str, fine: str) -> dict:
    """Registro delle azioni del periodo: conteggi per tipo e voci notevoli.

    Notevoli sono le azioni che cambiano la postura del sistema o che riguardano
    l'accesso: non e' un elenco di tutto, che nessuno leggerebbe.
    """
    NOTEVOLI = ("auth.login.failed", "probe.store.reset", "probe.revoked",
                "tenant.deleted", "user.deleted", "settings.updated",
                "settings.notifications", "settings.telegram", "maintenance.restore",
                "maintenance.purge", "maintenance.retention", "rules.deleted",
                "checks.check.deleted", "checks.target.deleted")
    conteggi = query(
        "SELECT event_type, severity, COUNT(*) AS n FROM audit_events"
        " WHERE tenant_id = ? AND created_at >= ? AND created_at < ?"
        " GROUP BY event_type ORDER BY n DESC LIMIT ?",
        (tenant_id, inizio, fine, MAX_AUDIT))
    notevoli = query(
        "SELECT a.event_type, a.severity, a.actor, a.description, a.source_ip,"
        " a.created_at, u.full_name FROM audit_events a"
        " LEFT JOIN users u ON u.id = a.user_id"
        " WHERE a.tenant_id = ? AND a.created_at >= ? AND a.created_at < ?"
        " AND (a.severity IN ('warning', 'critical') OR a.event_type IN (%s))"
        " ORDER BY a.created_at DESC LIMIT ?"
        % ",".join("?" * len(NOTEVOLI)),
        (tenant_id, inizio, fine) + NOTEVOLI + (MAX_AUDIT,))
    accessi = query(
        "SELECT COALESCE(SUM(event_type = 'auth.login'), 0) AS riusciti,"
        " COALESCE(SUM(event_type = 'auth.login.failed'), 0) AS falliti"
        " FROM audit_events WHERE tenant_id = ? AND created_at >= ? AND created_at < ?",
        (tenant_id, inizio, fine), one=True)
    return {
        "per_tipo": [dict(r) for r in conteggi],
        "notevoli": [dict(r) for r in notevoli],
        "accessi_riusciti": int(accessi["riusciti"] or 0) if accessi else 0,
        "accessi_falliti": int(accessi["falliti"] or 0) if accessi else 0,
        "totale": sum(int(r["n"]) for r in conteggi),
    }


# --------------------------------------------------------------------------- #
# Inventario tecnico
# --------------------------------------------------------------------------- #
def perimeter(tenant_id: int) -> list:
    """Perimetro dichiarato contro perimetro osservato, subnet per subnet."""
    return [dict(r) for r in query(
        "SELECT s.cidr, s.label, s.is_enabled, s.host_count,"
        " COUNT(n.id) AS nodi, COALESCE(SUM(n.status = 'up'), 0) AS su,"
        " COALESCE(SUM(n.device_type IS NULL OR n.device_type = ''), 0) AS senza_tipo,"
        " s.imported_at"
        " FROM subnets s LEFT JOIN nodes n ON n.subnet_id = s.id"
        " WHERE s.tenant_id = ? GROUP BY s.id ORDER BY s.cidr", (tenant_id,))]


def nodes_detail(tenant_id: int, limite: int = MAX_NODI) -> list:
    return [dict(r) for r in query(
        "SELECT n.ip, n.hostname, n.mac, n.mac_vendor, n.status, n.os_name, n.os_family,"
        " n.device_type, n.device_label, n.device_confidence, n.latency_ms,"
        " n.first_seen_at, n.last_seen_at, s.cidr,"
        " (SELECT COUNT(*) FROM node_ports p WHERE p.node_id = n.id"
        "  AND p.state = 'open') AS porte"
        " FROM nodes n LEFT JOIN subnets s ON s.id = n.subnet_id"
        " WHERE n.tenant_id = ? ORDER BY inet(n.ip)", (tenant_id,))]


def services_detail(tenant_id: int, limite: int = MAX_SERVIZI) -> list:
    return [dict(r) for r in query(
        "SELECT n.ip, n.hostname, p.protocol, p.port, p.state, p.service_name,"
        " p.product, p.version, p.method, p.confidence, p.is_suspect, p.suspect_reason,"
        " p.banner FROM node_ports p JOIN nodes n ON n.id = p.node_id"
        " WHERE p.tenant_id = ? AND p.state = 'open'"
        " ORDER BY inet(n.ip), p.protocol, p.port", (tenant_id,))]


def unidentified(tenant_id: int, limite: int = 100) -> list:
    """Nodi senza tipo o con confidenza bassa: sono il lavoro che resta da fare."""
    return [dict(r) for r in query(
        "SELECT ip, hostname, os_name, device_type, device_label, device_confidence,"
        " (SELECT COUNT(*) FROM node_ports p WHERE p.node_id = nodes.id"
        "  AND p.state = 'open') AS porte"
        " FROM nodes WHERE tenant_id = ?"
        " AND (device_type IS NULL OR device_type = '' OR device_confidence < 50)"
        " ORDER BY device_confidence, inet(ip)", (tenant_id,))]


def suspect_ports(tenant_id: int, limite: int = 200) -> list:
    """Porte su cui risponde probabilmente un apparato intermedio."""
    return [dict(r) for r in query(
        "SELECT n.ip, p.protocol, p.port, p.service_name, p.suspect_reason"
        " FROM node_ports p JOIN nodes n ON n.id = p.node_id"
        " WHERE p.tenant_id = ? AND p.is_suspect = 1"
        " ORDER BY inet(n.ip), p.port", (tenant_id,))]


def frequent_ports(tenant_id: int, minimo_quota: float = 0.20) -> list:
    """Porte aperte su una quota rilevante dei nodi: sono fatti architetturali.

    Elencarle nodo per nodo occuperebbe pagine e nasconderebbe la cosa vera, cioe' che
    una porta aperta su quasi tutta la rete e' un apparato che risponde per altri.
    """
    nodi = scalar("SELECT COUNT(*) FROM nodes WHERE tenant_id = ?", (tenant_id,),
                  default=0) or 1
    soglia = max(2, int(minimo_quota * nodi))
    return [dict(r) | {"quota": round(100.0 * int(r["nodi"]) / nodi, 1)}
            for r in query(
                "SELECT protocol, port, COUNT(DISTINCT node_id) AS nodi,"
                " MAX(service_name) AS servizio FROM node_ports"
                " WHERE tenant_id = ? AND state = 'open' GROUP BY protocol, port"
                " HAVING nodi >= ? ORDER BY nodi DESC", (tenant_id, soglia))]


# --------------------------------------------------------------------------- #
# Conformita'
# --------------------------------------------------------------------------- #
def compliance(tenant_id: int, inizio: str, fine: str) -> dict:
    """Materiale del fascicolo: controlli in vigore, incidenti con i tempi, rilievi."""
    controlli = [dict(r) for r in query(
        "SELECT c.name, c.kind, c.interval_seconds, c.timeout_seconds, c.severity,"
        " c.failure_threshold, c.escalation_threshold, c.escalation_email, c.is_enabled,"
        " t.address, t.name AS bersaglio FROM checks c"
        " JOIN check_targets t ON t.id = c.target_id"
        " WHERE c.tenant_id = ? ORDER BY t.address, c.name", (tenant_id,))]
    incidenti = [dict(r) for r in query(
        "SELECT i.id, i.severity, i.status, i.opened_at, i.acknowledged_at,"
        " i.escalated_at, i.resolved_at, i.failure_count, i.resolution,"
        " c.name AS controllo, t.address FROM check_incidents i"
        " JOIN checks c ON c.id = i.check_id"
        " JOIN check_targets t ON t.id = c.target_id"
        " WHERE i.tenant_id = ? AND i.opened_at >= ? AND i.opened_at < ?"
        " ORDER BY i.opened_at", (tenant_id, inizio, fine))]
    notifiche = [dict(r) for r in query(
        "SELECT event, channel, status, COUNT(*) AS n FROM notifications"
        " WHERE tenant_id = ? AND created_at >= ? AND created_at < ?"
        " GROUP BY event, channel, status", (tenant_id, inizio, fine))]
    tenant = query("SELECT retention_days, contact_email, timezone FROM tenants"
                   " WHERE id = ?", (tenant_id,), one=True)

    rilievi = []
    from ..channels import telegram_config
    from ..notifications import is_configured, smtp_config

    posta = smtp_config()
    if posta.get("password"):
        rilievi.append({
            "gravita": "warning",
            "titolo": "Credenziale della posta conservata in chiaro",
            "dettaglio": "La password SMTP e' conservata come testo nelle impostazioni di"
                         " sistema. Contromisura proposta: cifratura a riposo della voce"
                         " oppure delega a un archivio di segreti.",
        })
    if telegram_config().get("token"):
        rilievi.append({
            "gravita": "warning",
            "titolo": "Token del bot Telegram conservato in chiaro",
            "dettaglio": "Vale la stessa contromisura della credenziale di posta.",
        })
    if not is_configured(posta):
        rilievi.append({
            "gravita": "warning",
            "titolo": "Canale di notifica non configurato",
            "dettaglio": "Gli incidenti vengono registrati e accodati ma non recapitati:"
                         " la catena di comunicazione non e' dimostrabile.",
        })
    sospesi = [c for c in controlli if not c["is_enabled"]]
    if sospesi:
        rilievi.append({
            "gravita": "info",
            "titolo": "%d controlli sospesi" % len(sospesi),
            "dettaglio": "Un controllo sospeso e' una verifica dichiarata e non eseguita:"
                         " %s." % ", ".join("%s (%s)" % (c["name"], c["address"])
                                            for c in sospesi[:5]),
        })
    senza_copia = not _copie_presenti()
    if senza_copia:
        rilievi.append({
            "gravita": "critical",
            "titolo": "Nessuna copia dell'archivio",
            "dettaglio": "Una copia che non esiste e' l'unico guasto che non si puo'"
                         " riparare.",
        })

    return {
        "controlli": controlli,
        "controlli_attivi": len([c for c in controlli if c["is_enabled"]]),
        "incidenti": incidenti,
        "notifiche": notifiche,
        "retention_giorni": tenant["retention_days"] if tenant else None,
        "contatto": tenant["contact_email"] if tenant else None,
        "fuso": tenant["timezone"] if tenant else None,
        "rilievi": rilievi,
    }


def _copie_presenti() -> bool:
    try:
        from ..maintenance import list_backups

        return bool(list_backups())
    except Exception:  # noqa: BLE001 - un rilievo non deve fare cadere il report
        return True


# --------------------------------------------------------------------------- #
# Insiemi completi per genere di report
# --------------------------------------------------------------------------- #
def _comune(tenant: dict, zona, giorno_fine, giorni: int) -> dict:
    from ..db import utc_now, utc_str
    from .windows import describe_range

    inizio, fine = days_bounds(zona, giorni, fino_a=giorno_fine)
    return {
        "tenant": {"id": int(tenant["id"]), "nome": tenant["name"],
                   "codice": tenant["code"],
                   "fuso": zona.key if hasattr(zona, "key") else str(zona)},
        "giorno": giorno_fine,
        "giorni": giorni,
        "intervallo": describe_range(giorno_fine, giorni, zona),
        "inizio_utc": inizio,
        "fine_utc": fine,
        "generato_utc": utc_str(utc_now()),
    }


def executive(tenant: dict, zona, giorno_fine, giorni: int = 30) -> dict:
    """Sintesi esecutiva: pochi indicatori con la tendenza, senza un solo indirizzo."""
    tenant_id = int(tenant["id"])
    dati = _comune(tenant, zona, giorno_fine, giorni)
    inventario = dataset.inventory(tenant_id)
    confronto = kpi_confronto(tenant_id, zona, giorno_fine, giorni)
    superficie = exposure(tenant_id)
    igiene = dataset.hygiene(tenant_id)
    aperti = scalar("SELECT COUNT(*) FROM check_incidents WHERE tenant_id = ?"
                    " AND status IN (?, ?)", (tenant_id, INCIDENT_OPEN, INCIDENT_ACK),
                    default=0)
    dati.update({
        "inventario": inventario,
        "confronto": confronto,
        "superficie": {
            "porte_aperte": superficie["porte_aperte"],
            "amministrazione": superficie["amministrazione"],
            "categorie": [{"etichetta": c["etichetta"], "nodi": c["nodi"],
                           "porte": len(c["porte"])} for c in superficie["categorie"]],
        },
        "incidenti_aperti": int(aperti or 0),
        "igiene": {
            "controlli_sospesi": len(igiene["controlli_sospesi"]),
            "bersagli_senza_controlli": len(igiene["bersagli_senza_controlli"]),
            "nodi_non_identificati": igiene["nodi_non_identificati"],
            "retention_giorni": igiene["retention_giorni"],
        },
        "semafori": _semafori(inventario, confronto, superficie, igiene, int(aperti or 0)),
    })
    dati["azioni"] = _azioni(dati)
    return dati


def _semaforo(valore, verde, giallo) -> str:
    """Tre livelli, con l'informazione ripetuta in testo per la stampa in bianco e nero."""
    if valore is None:
        return "non misurato"
    if valore >= verde:
        return "buono"
    if valore >= giallo:
        return "da guardare"
    return "critico"


def _semafori(inventario, confronto, superficie, igiene, incidenti_aperti) -> list:
    disponibilita = confronto["corrente"]["disponibilita"]
    copertura = inventario.get("occupazione")
    identificati = (100.0 * (int(inventario.get("nodi") or 0)
                             - int(igiene["nodi_non_identificati"] or 0))
                    / max(1, int(inventario.get("nodi") or 0)))
    return [
        {"area": "Disponibilita' dei servizi",
         "stato": _semaforo(disponibilita, 99.0, 95.0),
         "valore": disponibilita,
         "nota": "percentuale di verifiche riuscite nel periodo"},
        {"area": "Incidenti aperti",
         "stato": "buono" if incidenti_aperti == 0 else "critico",
         "valore": incidenti_aperti,
         "nota": "qualunque valore diverso da zero richiede un intervento"},
        {"area": "Identificazione dei dispositivi",
         "stato": _semaforo(identificati, 95.0, 80.0),
         "valore": round(identificati, 1),
         "nota": "quota di dispositivi con tipo riconosciuto"},
        {"area": "Superficie di amministrazione remota",
         "stato": "buono" if superficie["amministrazione"] == 0
                  else ("da guardare" if superficie["amministrazione"] < 10 else "critico"),
         "valore": superficie["amministrazione"],
         "nota": "dispositivi con amministrazione remota raggiungibile"},
        {"area": "Copertura del perimetro dichiarato",
         "stato": "non misurato" if copertura is None else "buono",
         "valore": copertura,
         "nota": "quota di indirizzi dichiarati in cui si e' trovato un dispositivo"},
    ]


def _azioni(dati: dict) -> list:
    """Tre azioni proposte, scelte dai dati: un report senza proposta non fa decidere.

    L'ordine e' per effetto atteso, non per gravita' tecnica: chi legge questo documento
    decide dove mettere il tempo di qualcuno.
    """
    azioni = []
    if dati["incidenti_aperti"]:
        azioni.append({
            "azione": "Chiudere i %d incidenti aperti" % dati["incidenti_aperti"],
            "perche": "Un incidente aperto e' un disservizio che dura o una verifica che"
                      " nessuno ha guardato.",
            "effetto": "Riduzione immediata del rischio di indisponibilita' prolungata.",
        })
    amministrazione = dati["superficie"]["amministrazione"]
    if amministrazione:
        azioni.append({
            "azione": "Rivedere l'amministrazione remota su %d dispositivi" % amministrazione,
            "perche": "Chi raggiunge quelle porte comanda il dispositivo. In rete interna"
                      " e' normale che esista; che sia raggiungibile da tutti no.",
            "effetto": "Riduzione della superficie sfruttabile senza fermare i servizi.",
        })
    non_identificati = dati["igiene"]["nodi_non_identificati"]
    if non_identificati:
        azioni.append({
            "azione": "Identificare %d dispositivi rimasti senza tipo" % non_identificati,
            "perche": "Cio' che non e' identificato non e' governato: non si sa chi lo"
                      " gestisce ne' se deve essere in rete.",
            "effetto": "Inventario utilizzabile per le decisioni di manutenzione.",
        })
    if dati["igiene"]["controlli_sospesi"]:
        azioni.append({
            "azione": "Riattivare o rimuovere %d controlli sospesi"
                      % dati["igiene"]["controlli_sospesi"],
            "perche": "Un controllo sospeso e' una verifica dichiarata e non eseguita:"
                      " il cieco volontario.",
            "effetto": "Copertura di sorveglianza pari a quella dichiarata.",
        })
    if dati["confronto"]["corrente"]["disponibilita"] is None:
        azioni.append({
            "azione": "Definire controlli sui servizi che contano",
            "perche": "Nel periodo non e' stata eseguita nessuna verifica: la"
                      " disponibilita' non e' misurata, e non e' zero.",
            "effetto": "Un numero su cui discutere al prossimo riesame.",
        })
    return azioni[:3]


def inventory(tenant: dict, zona, giorno_fine, giorni: int = 30) -> dict:
    """Inventario e valutazione tecnica: che cosa c'e', con che cosa risponde."""
    tenant_id = int(tenant["id"])
    dati = _comune(tenant, zona, giorno_fine, giorni)
    dati.update({
        "inventario": dataset.inventory(tenant_id),
        "perimetro": perimeter(tenant_id),
        "nodi": nodes_detail(tenant_id),
        "servizi": services_detail(tenant_id),
        "non_identificati": unidentified(tenant_id),
        "apparati_snmp": snmp_devices(tenant_id),
        "copertura_snmp": snmp_coverage(tenant_id),
        "porte_sospette": suspect_ports(tenant_id),
        "porte_frequenti": frequent_ports(tenant_id),
        "variazioni": dataset.changes(tenant_id, dati["inizio_utc"], dati["fine_utc"],
                                      int(dataset.inventory(tenant_id).get("nodi") or 0)),
        "raccolta": dataset.collection(tenant_id, dati["inizio_utc"], dati["fine_utc"],
                                       zona),
        "igiene": dataset.hygiene(tenant_id),
    })
    dati["troncato"] = {
        "nodi": len(dati["nodi"]) >= MAX_NODI,
        "servizi": len(dati["servizi"]) >= MAX_SERVIZI,
    }
    return dati


def soc(tenant: dict, zona, giorno_fine, giorni: int = 7) -> dict:
    """Postura di sicurezza: prima cio' che e' cambiato, poi cio' che si espone."""
    tenant_id = int(tenant["id"])
    dati = _comune(tenant, zona, giorno_fine, giorni)
    dati.update({
        "inventario": dataset.inventory(tenant_id),
        "variazioni_sicurezza": security_changes(tenant_id, dati["inizio_utc"],
                                                 dati["fine_utc"]),
        "superficie": exposure(tenant_id),
        "snmp": snmp_readable(tenant_id),
        "apparati_snmp": snmp_devices(tenant_id, limit=60),
        "copertura_snmp": snmp_coverage(tenant_id),
        "fuori_perimetro": out_of_perimeter(tenant_id),
        "porte_sospette": suspect_ports(tenant_id),
        "audit": audit_digest(tenant_id, dati["inizio_utc"], dati["fine_utc"]),
        "rilevamento_base": dataset.baseline(tenant_id, giorno_fine, zona),
        "minacce": threat_summary(tenant_id),
    })
    return dati


def threat_summary(tenant_id: int) -> dict:
    """Riscontri di threat intelligence per il report di sicurezza.

    Le tre classi restano distinte anche qui: un report che sommasse vulnerabilita'
    accertate e ipotesi da verificare direbbe un numero che non significa niente.
    """
    try:
        from ..threat import KIND_CONFIRMED, KIND_POTENTIAL, findings, summary
        from ..threat_sources import recent_syncs

        riepilogo = summary(tenant_id)
        aggiornamenti = [s for s in recent_syncs(20) if s["status"] == "ok"]
        return {
            "disponibile": True,
            "riepilogo": riepilogo,
            "confermati": findings(tenant_id, kind=KIND_CONFIRMED, limit=60),
            "da_verificare": findings(tenant_id, kind=KIND_POTENTIAL, limit=40),
            "ultimo_aggiornamento": aggiornamenti[0]["finished_at"]
                                    if aggiornamenti else None,
        }
    except Exception:  # noqa: BLE001 - un report non deve cadere per una sezione
        return {"disponibile": False, "riepilogo": {}, "confermati": [],
                "da_verificare": [], "ultimo_aggiornamento": None}


# --------------------------------------------------------------------------- #
# R8 - Vulnerabilita' ed esposizioni
# --------------------------------------------------------------------------- #
# Quante voci per elenco. Un documento operativo si legge: un elenco di duemila righe
# non viene letto da nessuno, e il totale resta dichiarato nel riepilogo.
# Un tempo questi valori tagliavano gli elenchi dei report. Su richiesta
# dell'operatore i report elencano TUTTO: un documento che si consegna a un cliente
# non puo' fermarsi a ottanta righe senza dirlo, e dirlo non basta -- l'elenco serve
# intero per essere lavorato. Restano dichiarati perche' la pagina della guida li
# cita come storia della decisione (RP-21bis).
MAX_RIGHE_CONFERMATI = None
MAX_RIGHE_VERIFICARE = None
MAX_RIGHE_NODI = None


def _priorita_riscontro(voce: dict) -> tuple:
    """Ordine di intervento: sfruttata attivamente, gravita', punteggio.

    Non e' l'ordine del punteggio CVSS: fra due vulnerabilita' con lo stesso
    punteggio, quella che risulta sfruttata in attacchi reali (CISA KEV) va prima,
    perche' il punteggio misura il danno possibile e il KEV misura il fatto.
    """
    ordine_gravita = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return (0 if voce.get("kev") else 1,
            ordine_gravita.get(voce.get("severity"), 5),
            -float(voce.get("score") or 0))


def _regola_esposizione(titolo: str) -> dict:
    """Regola di esposizione da cui viene un riscontro, cercata per titolo.

    Motivazione e azione consigliata appartengono alla regola e non vengono
    ricopiate in ogni riscontro: sarebbero migliaia di copie della stessa frase,
    e correggere una parola vorrebbe dire riscrivere l'archivio.
    """
    try:
        from ..threat import EXPOSURE_RULES
    except ImportError:
        return {}
    for regola in EXPOSURE_RULES:
        if regola["titolo"] == titolo:
            return regola
    return {}


def _raggruppa_esposizioni(voci: list) -> list:
    """Esposizioni per tipo di servizio, con i nodi che le presentano.

    Un elenco per nodo direbbe duemila volte "Telnet in chiaro"; il fatto da
    riportare e' che Telnet e' esposto su N nodi, e quali sono.
    """
    gruppi = {}
    for voce in voci:
        chiave = (voce.get("title") or "").strip() or "Esposizione non qualificata"
        gruppo = gruppi.setdefault(chiave, {
            "titolo": chiave,
            "severity": voce.get("severity") or "info",
            "tecnica": voce.get("technique_id") or "",
            "tecnica_nome": voce.get("tecnica_nome") or "",
            "motivo": "",
            "raccomandazione": "",
            "nodi": [],
            "porte": set(),
        })
        gruppo["nodi"].append({"ip": voce.get("ip"), "hostname": voce.get("hostname"),
                               "device": voce.get("device_label"),
                               "porta": "%s/%s" % (voce.get("protocol") or "-",
                                                   voce.get("port") or "-")})
        if voce.get("port"):
            gruppo["porte"].add("%s/%s" % (voce.get("protocol") or "tcp", voce["port"]))
        # La gravita' del gruppo e' la peggiore fra quelle dei suoi riscontri.
        ordine = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        if ordine.get(voce.get("severity"), 4) < ordine.get(gruppo["severity"], 4):
            gruppo["severity"] = voce.get("severity")

    elenco = []
    for gruppo in gruppi.values():
        gruppo["porte"] = ", ".join(sorted(gruppo["porte"]))
        gruppo["quanti"] = len(gruppo["nodi"])
        regola = _regola_esposizione(gruppo["titolo"])
        gruppo["motivo"] = regola.get("motivo", "")
        gruppo["raccomandazione"] = regola.get("azione", "")
        elenco.append(gruppo)
    ordine = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    elenco.sort(key=lambda g: (ordine.get(g["severity"], 4), -g["quanti"]))
    return elenco


def _nodi_piu_esposti(voci: list, limite: int = None) -> list:
    """Nodi ordinati per quanto hanno da sistemare.

    Serve a rispondere alla domanda operativa "da quale dispositivo comincio":
    un elenco per vulnerabilita' non la risponde, perche' lo stesso apparato
    compare in venti righe diverse.
    """
    nodi = {}
    for voce in voci:
        chiave = voce.get("ip") or "?"
        nodo = nodi.setdefault(chiave, {
            "ip": chiave, "hostname": voce.get("hostname"),
            "device": voce.get("device_label"),
            "confermati": 0, "da_verificare": 0, "esposizioni": 0, "kev": 0,
            "peggiore": "info", "punteggio": 0.0,
        })
        genere = voce.get("kind")
        if genere == "confirmed":
            nodo["confermati"] += 1
        elif genere == "potential":
            nodo["da_verificare"] += 1
        else:
            nodo["esposizioni"] += 1
        if voce.get("kev"):
            nodo["kev"] += 1
        ordine = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        if ordine.get(voce.get("severity"), 4) < ordine.get(nodo["peggiore"], 4):
            nodo["peggiore"] = voce.get("severity") or "info"
        nodo["punteggio"] = max(nodo["punteggio"], float(voce.get("score") or 0))

    elenco = sorted(nodi.values(),
                    key=lambda n: (-n["kev"], -n["confermati"], -n["punteggio"],
                                   -n["esposizioni"]))
    return elenco[:limite]


def threat(tenant: dict, zona, giorno_fine, giorni: int = 30) -> dict:
    """Report delle vulnerabilita': che cosa e' dimostrato, che cosa va accertato.

    Il documento e' fotografia piu' periodo: i riscontri sono lo stato corrente
    della correlazione, mentre il periodo serve a dire che cosa e' comparso e che
    cosa e' stato chiuso nell'intervallo. Le tre classi non si sommano mai in un
    numero unico: un totale che mescoli vulnerabilita' accertate, ipotesi da
    verificare ed esposizioni di servizio non significa niente (TI-02).
    """
    tenant_id = int(tenant["id"])
    dati = _comune(tenant, zona, giorno_fine, giorni)

    try:
        from ..threat import (KIND_CONFIRMED, KIND_EXPOSURE, KIND_POTENTIAL,
                              STATUS_ACCEPTED, STATUS_FALSE_POSITIVE, STATUS_FIXED,
                              catalog_summary, findings, summary)
        from ..threat_sources import recent_syncs
    except ImportError:
        dati.update({"disponibile": False, "riepilogo": {}, "catalogo": {},
                     "confermati": [], "da_verificare": [], "esposizioni": [],
                     "decisioni": [], "nodi": [], "aggiornamenti": [],
                     "comparsi": [], "chiusi": []})
        return dati

    riepilogo = summary(tenant_id)
    aperti = findings(tenant_id, status="open", limit=5000)
    confermati = sorted([v for v in aperti if v["kind"] == KIND_CONFIRMED],
                        key=_priorita_riscontro)
    da_verificare = [v for v in aperti if v["kind"] == KIND_POTENTIAL]
    esposizioni = [v for v in aperti if v["kind"] == KIND_EXPOSURE]

    # Che cosa e' cambiato nell'intervallo: comparsi e chiusi. E' la parte che
    # distingue un report da una schermata (RP-12).
    comparsi = [v for v in aperti
                if (v.get("first_seen_at") or "") >= dati["inizio_utc"]]
    chiusi = [dict(r) for r in query(
        "SELECT f.kind, f.severity, f.title, f.cve_id, f.status, f.decided_at,"
        " n.ip, n.device_label FROM ti_findings f JOIN nodes n ON n.id = f.node_id"
        " WHERE f.tenant_id = ? AND f.status IN (?, ?, ?)"
        " AND COALESCE(f.decided_at, f.last_seen_at) BETWEEN ? AND ?"
        " ORDER BY COALESCE(f.decided_at, f.last_seen_at) DESC LIMIT 60",
        (tenant_id, STATUS_FIXED, STATUS_ACCEPTED, STATUS_FALSE_POSITIVE,
         dati["inizio_utc"], dati["fine_utc"]))]

    # Le decisioni prese sono parte del documento: un rischio accettato senza
    # motivazione tracciata, fra sei mesi, e' un rischio dimenticato (TI-13).
    decisioni = [dict(r) for r in query(
        "SELECT f.kind, f.severity, f.title, f.cve_id, f.status,"
        " f.note AS decision_note, f.decided_at, n.ip, u.email AS deciso_da"
        " FROM ti_findings f JOIN nodes n ON n.id = f.node_id"
        " LEFT JOIN users u ON u.id = f.decided_by"
        " WHERE f.tenant_id = ? AND f.status IN (?, ?)"
        " ORDER BY f.decided_at DESC LIMIT 60",
        (tenant_id, STATUS_ACCEPTED, STATUS_FALSE_POSITIVE))]

    aggiornamenti = [s for s in recent_syncs(12)]
    riusciti = [s for s in aggiornamenti if s["status"] == "ok"]

    dati.update({
        "disponibile": True,
        "riepilogo": riepilogo,
        "catalogo": catalog_summary(),
        "confermati": confermati,
        "confermati_totale": len(confermati),
        "da_verificare": da_verificare,
        "da_verificare_totale": len(da_verificare),
        "esposizioni": _raggruppa_esposizioni(esposizioni),
        "esposizioni_totale": len(esposizioni),
        "nodi": _nodi_piu_esposti(aperti),
        "nodi_totale": riepilogo.get("nodi", 0),
        "decisioni": decisioni,
        "comparsi": comparsi,
        "chiusi": chiusi,
        "aggiornamenti": aggiornamenti,
        "ultimo_aggiornamento": riusciti[0]["finished_at"] if riusciti else None,
        "inventario": dataset.inventory(tenant_id),
        "copertura_snmp": snmp_coverage(tenant_id),
    })
    return dati


# --------------------------------------------------------------------------- #
# R9 - Segmentazione e zone di rete
# --------------------------------------------------------------------------- #
def segmentation(tenant: dict, zona, giorno_fine, giorni: int = 30) -> dict:
    """La segmentazione dichiarata regge?

    Non e' un elenco di porte: e' il confronto fra cio' che ogni rete dichiara di
    essere e cio' che ci si trova dentro. Una rete ben segmentata ha molte esposizioni
    attese nel proprio contesto e poche violazioni; una rete piatta ha tutto aperto e
    niente di dichiarato -- e quello e' il primo dato da mettere per iscritto.
    """
    from ..operations import zone_posture
    from ..zones import catalogo

    tenant_id = int(tenant["id"])
    dati = _comune(tenant, zona, giorno_fine, giorni)
    postura = zone_posture(tenant_id)

    violazioni = [dict(r) for r in query(
        "SELECT n.ip, n.hostname, n.device_label, COALESCE(s.zone, '') AS zone,"
        " COALESCE(s.cidr, 'fuori perimetro') AS cidr, f.title, f.severity,"
        " f.evidence, p.protocol, p.port"
        " FROM ti_findings f JOIN nodes n ON n.id = f.node_id"
        " LEFT JOIN subnets s ON s.id = n.subnet_id"
        " LEFT JOIN node_ports p ON p.id = f.port_id"
        " WHERE f.tenant_id = ? AND f.kind = 'exposure' AND f.status = 'open'"
        " AND f.evidence LIKE '%Violazione della zona%'"
        " ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
        "   WHEN 'medium' THEN 2 ELSE 3 END, inet(n.ip)", (tenant_id,))]

    attese = [dict(r) for r in query(
        "SELECT COALESCE(s.zone, '') AS zone, f.title, COUNT(*) AS quante,"
        " COUNT(DISTINCT f.node_id) AS nodi"
        " FROM ti_findings f JOIN nodes n ON n.id = f.node_id"
        " LEFT JOIN subnets s ON s.id = n.subnet_id"
        " WHERE f.tenant_id = ? AND f.status = 'expected'"
        " GROUP BY s.zone, f.title ORDER BY quante DESC", (tenant_id,))]

    senza = [dict(r) for r in query(
        "SELECT s.cidr, COALESCE(s.label, '') AS label, s.host_count,"
        " (SELECT COUNT(*) FROM nodes n WHERE n.subnet_id = s.id) AS nodi,"
        " (SELECT COUNT(*) FROM ti_findings f JOIN nodes n2 ON n2.id = f.node_id"
        "   WHERE n2.subnet_id = s.id AND f.status = 'open') AS riscontri"
        " FROM subnets s WHERE s.tenant_id = ? AND COALESCE(s.zone, '') = ''"
        " ORDER BY nodi DESC", (tenant_id,))]

    # Le reti CON zona dichiarata: e' il lavoro fatto, e in un documento che si
    # consegna conta quanto quello che manca. Ordinate per zona e poi per indirizzo
    # numerico, cosi' le reti di uno stesso contesto stanno insieme.
    con_zona = [dict(r) for r in query(
        "SELECT s.cidr, COALESCE(s.label, '') AS label, s.host_count,"
        " COALESCE(s.zone, '') AS zone,"
        " (SELECT COUNT(*) FROM nodes n WHERE n.subnet_id = s.id) AS nodi,"
        " (SELECT COUNT(*) FROM nodes n WHERE n.subnet_id = s.id AND n.status = 'up')"
        "   AS attivi,"
        " (SELECT COUNT(*) FROM ti_findings f JOIN nodes n2 ON n2.id = f.node_id"
        "   WHERE n2.subnet_id = s.id AND f.status = 'open') AS riscontri,"
        " (SELECT COUNT(*) FROM ti_findings f JOIN nodes n3 ON n3.id = f.node_id"
        "   WHERE n3.subnet_id = s.id AND f.status = 'expected') AS attese"
        " FROM subnets s WHERE s.tenant_id = ? AND COALESCE(s.zone, '') <> ''"
        " ORDER BY s.zone, inet(s.cidr)", (tenant_id,))]

    dati.update({
        "postura": postura,
        "violazioni": violazioni,
        "attese": attese,
        "con_zona": con_zona,
        "senza_zona": senza,
        "catalogo": catalogo(tenant_id),
        "inventario": dataset.inventory(tenant_id),
    })
    return dati


# --------------------------------------------------------------------------- #
# R10 - Igiene dell'inventario
# --------------------------------------------------------------------------- #
def hygiene_pack(tenant: dict, zona, giorno_fine, giorni: int = 30) -> dict:
    """Che cosa manca per fidarsi dei numeri.

    Ogni prodotto di inventario ha un punto cieco: cio' che non ha guardato, cio' che
    non ha saputo riconoscere, cio' che ha smesso di aggiornare. Metterlo per iscritto
    e' l'unico modo perche' i numeri delle altre pagine restino credibili -- e per
    sapere dove intervenire per migliorarli.
    """
    from ..operations import silent_nodes, unchecked_nodes

    tenant_id = int(tenant["id"])
    dati = _comune(tenant, zona, giorno_fine, giorni)
    inventario = dataset.inventory(tenant_id)

    porte_aperte = scalar("SELECT COUNT(*) FROM node_ports WHERE tenant_id = ?"
                          " AND state = 'open'", (tenant_id,), default=0)
    con_prodotto = scalar("SELECT COUNT(*) FROM node_ports WHERE tenant_id = ?"
                          " AND state = 'open' AND product IS NOT NULL AND product <> ''",
                          (tenant_id,), default=0)
    con_versione = scalar("SELECT COUNT(*) FROM node_ports WHERE tenant_id = ?"
                          " AND state = 'open' AND version IS NOT NULL AND version <> ''",
                          (tenant_id,), default=0)

    subnet_totali = scalar("SELECT COUNT(*) FROM subnets WHERE tenant_id = ?",
                           (tenant_id,), default=0)
    subnet_senza_zona = scalar("SELECT COUNT(*) FROM subnets WHERE tenant_id = ?"
                               " AND COALESCE(zone, '') = ''", (tenant_id,), default=0)
    subnet_sospese = scalar("SELECT COUNT(*) FROM subnets WHERE tenant_id = ?"
                            " AND is_enabled = 0", (tenant_id,), default=0)
    subnet_vuote = [dict(r) for r in query(
        "SELECT s.cidr, COALESCE(s.label, '') AS label, s.host_count, s.is_enabled"
        " FROM subnets s WHERE s.tenant_id = ?"
        " AND NOT EXISTS (SELECT 1 FROM nodes n WHERE n.subnet_id = s.id)"
        " ORDER BY s.cidr", (tenant_id,))]

    return {
        **dati,
        "inventario": inventario,
        "igiene": dataset.hygiene(tenant_id),
        "qualita": {
            "porte_aperte": porte_aperte,
            "con_prodotto": con_prodotto,
            "con_versione": con_versione,
            "quota_prodotto": round(100.0 * con_prodotto / porte_aperte, 1)
                              if porte_aperte else None,
            "quota_versione": round(100.0 * con_versione / porte_aperte, 1)
                              if porte_aperte else None,
        },
        "perimetro": {
            "subnet": subnet_totali,
            "senza_zona": subnet_senza_zona,
            "sospese": subnet_sospese,
            "vuote": subnet_vuote,
        },
        "silenzi": silent_nodes(tenant_id, limit=100),
        "non_interrogati": unchecked_nodes(tenant_id, limit=100),
        "non_identificati": unidentified(tenant_id),
        "raccolta": dataset.collection(tenant_id, dati["inizio_utc"], dati["fine_utc"],
                                       zona),
        "copertura_snmp": snmp_coverage(tenant_id),
    }


# --------------------------------------------------------------------------- #
# R11 - Scheda di un apparato
# --------------------------------------------------------------------------- #
def device_sheet(tenant: dict, zona, node_id: int) -> dict:
    """Tutto cio' che si sa di un singolo apparato, in un foglio.

    E' il documento che si allega a una richiesta di intervento, a un inventario
    d'ufficio o a una segnalazione: chi lo riceve non ha accesso alla console, e deve
    poter capire di che apparato si parla senza aprire nulla.
    """
    import json as _json

    from ..db import utc_now, utc_str
    from ..snmp_tables import parse_all

    tenant_id = int(tenant["id"])
    nodo = query(
        "SELECT n.*, s.cidr AS subnet_cidr, s.label AS subnet_label,"
        " COALESCE(s.zone, '') AS zone, p.name AS probe_name"
        " FROM nodes n LEFT JOIN subnets s ON s.id = n.subnet_id"
        " LEFT JOIN probes p ON p.id = n.probe_id"
        " WHERE n.id = ? AND n.tenant_id = ?", (node_id, tenant_id), one=True)
    if nodo is None:
        raise ValueError("nodo non trovato in questo tenant")

    voce = dict(nodo)
    try:
        profilo = _json.loads(voce.get("fingerprint_json") or "{}")
    except ValueError:
        profilo = {}

    letture = [dict(r) for r in query(
        "SELECT script_id, output, collected_at FROM node_snmp"
        " WHERE tenant_id = ? AND node_id = ? AND output IS NOT NULL"
        " ORDER BY script_id", (tenant_id, node_id))]

    return {
        "tenant": {"id": tenant_id, "nome": tenant["name"], "codice": tenant["code"],
                   "fuso": zona.key if hasattr(zona, "key") else str(zona)},
        "generato_utc": utc_str(utc_now()),
        "intervallo": "fotografia del %s" % utc_str(utc_now())[:10],
        "nodo": voce,
        "verdetto": profilo.get("verdict") or {},
        "prove": (profilo.get("evidence") or {}),
        "porte": [dict(r) for r in query(
            "SELECT protocol, port, state, service_name, product, version, banner,"
            " is_suspect, suspect_reason, first_seen_at, last_seen_at"
            " FROM node_ports WHERE tenant_id = ? AND node_id = ?"
            " ORDER BY (state = 'open') DESC, protocol, port", (tenant_id, node_id))],
        "snmp": parse_all(letture),
        # Cio' che l'apparato dichiara di se' nelle proprie pagine di gestione (e via
        # IPP): e' la parte della scheda che un tecnico legge per prima, perche' dice
        # che cosa ha davanti e dove si trova.
        "web": [dict(r) for r in query(
            "SELECT port, scheme, status_code, title, brand, model, product, version,"
            " device_name, location, host_name, serial, firmware, contact, realm,"
            " server_header, pages_read, facts_locked, login_form, cert_subject,"
            " cert_expires, collected_at"
            " FROM node_web WHERE tenant_id = ? AND node_id = ? ORDER BY port",
            (tenant_id, node_id))],
        "riscontri": [dict(r) for r in query(
            "SELECT f.kind, f.severity, f.title, f.cve_id, f.status, f.evidence,"
            " f.confidence, p.protocol, p.port"
            " FROM ti_findings f LEFT JOIN node_ports p ON p.id = f.port_id"
            " WHERE f.tenant_id = ? AND f.node_id = ?"
            " ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
            "   WHEN 'medium' THEN 2 ELSE 3 END LIMIT 100", (tenant_id, node_id))],
        "cambiamenti": [dict(r) for r in query(
            "SELECT kind, subject, before_value, after_value, severity, created_at"
            " FROM node_changes WHERE tenant_id = ? AND node_id = ?"
            " ORDER BY created_at DESC LIMIT 60", (tenant_id, node_id))],
        "controlli": [dict(r) for r in query(
            "SELECT c.name, c.kind, c.is_enabled, c.interval_seconds, t.address"
            " FROM checks c JOIN check_targets t ON t.id = c.target_id"
            " WHERE c.tenant_id = ? AND (t.address = ? OR t.address = ?)"
            " ORDER BY c.name", (tenant_id, voce["ip"], voce.get("hostname") or ""))],
        "monitoraggio": [dict(r) for r in query(
            "SELECT checked_at, reachable, latency_ms FROM monitor_samples"
            " WHERE node_id = ? ORDER BY checked_at DESC LIMIT 40", (node_id,))],
    }


def _registro_acn(tenant_id: int, inizio: str, fine: str) -> dict:
    """Il registro ACN del periodo. Se il modulo non e' disponibile, un registro vuoto:
    un report non deve cadere perche' una parte del prodotto non c'e'."""
    try:
        from ..acn import registro

        return registro(tenant_id, inizio, fine)
    except Exception:  # noqa: BLE001 - il documento vale anche senza questa sezione
        from flask import current_app

        current_app.logger.warning("Registro ACN non disponibile per il tenant %s",
                                   tenant_id)
        return {"comunicazioni": [], "totale": 0, "nei_termini": 0,
                "fuori_termine": 0, "da_inviare": 0, "non_dovute": 0, "incidenti": 0}


def compliance_pack(tenant: dict, zona, giorno_fine, giorni: int = 90) -> dict:
    """Fascicolo di conformita': la prova che i controlli esistono e funzionano."""
    tenant_id = int(tenant["id"])
    dati = _comune(tenant, zona, giorno_fine, giorni)
    dati.update({
        "inventario": dataset.inventory(tenant_id),
        "conformita": compliance(tenant_id, dati["inizio_utc"], dati["fine_utc"]),
        "audit": audit_digest(tenant_id, dati["inizio_utc"], dati["fine_utc"]),
        "disponibilita": dataset.availability(tenant_id, dati["inizio_utc"],
                                             dati["fine_utc"]),
        "perimetro": perimeter(tenant_id),
        # Il registro delle comunicazioni all'autorita': e' la parte della sezione
        # "Comunicazioni inviate" che ha valore verso l'esterno.
        "acn": _registro_acn(tenant_id, dati["inizio_utc"], dati["fine_utc"]),
    })
    return dati


def incident_pack(tenant: dict, zona, incident_id: int) -> dict:
    """Rapporto di incidente: cronologia, esiti attorno, notifiche, risoluzione."""
    tenant_id = int(tenant["id"])
    incidente = query(
        "SELECT i.*, c.name AS controllo, c.kind, t.address, t.name AS bersaglio"
        " FROM check_incidents i JOIN checks c ON c.id = i.check_id"
        " JOIN check_targets t ON t.id = c.target_id"
        " WHERE i.id = ? AND i.tenant_id = ?", (incident_id, tenant_id), one=True)
    if incidente is None:
        raise ValueError("incidente %s non trovato" % incident_id)

    from ..db import utc_now, utc_str

    apertura = parse_utc(incidente["opened_at"])
    chiusura = parse_utc(incidente["resolved_at"]) or utc_now()
    inizio = utc_str(apertura - timedelta(hours=2)) if apertura else incidente["opened_at"]
    fine = utc_str(chiusura + timedelta(hours=2))

    return {
        "tenant": {"id": tenant_id, "nome": tenant["name"], "codice": tenant["code"],
                   "fuso": zona.key if hasattr(zona, "key") else str(zona)},
        "intervallo": "incidente #%s: %s - %s (finestra allargata di 2 ore)"
                      % (incident_id, incidente["opened_at"],
                         incidente["resolved_at"] or "aperto"),
        "inizio_utc": inizio,
        "fine_utc": fine,
        "generato_utc": utc_str(utc_now()),
        "incidente": dict(incidente),
        "cronologia": [dict(r) for r in query(
            "SELECT action, actor, note, created_at FROM check_incident_events"
            " WHERE incident_id = ? ORDER BY id", (incident_id,))],
        "esiti": [dict(r) for r in query(
            "SELECT executed_at, status, latency_ms, detail FROM check_results"
            " WHERE check_id = ? AND executed_at >= ? AND executed_at < ?"
            " ORDER BY executed_at LIMIT 200",
            (incidente["check_id"], inizio, fine))],
        "misure": [dict(r) for r in query(
            "SELECT name, value, text_value, measured_at FROM check_metrics"
            " WHERE check_id = ? AND measured_at >= ? AND measured_at < ?"
            " ORDER BY measured_at LIMIT 300",
            (incidente["check_id"], inizio, fine))],
        "notifiche": [dict(r) for r in query(
            "SELECT event, channel, recipients, status, sent_at, last_error"
            " FROM notifications WHERE incident_id = ? ORDER BY id", (incident_id,))],
    }
