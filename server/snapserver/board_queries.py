# -----------------------------------------------------------------
# board_queries.py — indicatori aggregati della seconda dashboard (Board2)
# Autore: Daniele Speziale
# Data creazione: 2026-09-12
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Gli indicatori di Board2, in una passata sola.

PERCHE' UN MODULO PROPRIO. Board2 mette su una pagina cio' che il prodotto ha
raccolto in ogni sua area: inventario, esposizione, vulnerabilita', certificati,
vetusta', SMB, presenze, flotta, attivita'. I dati ci sono gia', ma ciascuno vive
nella pagina che lo ha prodotto -- e le raccolte dei report (`reports/dataset_wide`)
non si possono riusare qui: caricano gli ELENCHI interi (1246 certificati, 2780
letture SMB) perche' devono stamparli, mentre una dashboard ha bisogno dei soli
CONTEGGI. Leggere un elenco per contarne le righe, su una pagina che si apre dieci
volte al giorno, e' lavoro sprecato sul database.

Quindi qui ci sono solo aggregazioni: `COUNT`, `SUM`, `GROUP BY`. Nessuna riga di
dettaglio, salvo le poche classifiche brevi che la pagina mostra per esteso.

DUE REGOLE CHE VALGONO PER TUTTI GLI INDICATORI
-----------------------------------------------
1. **Zero e "non misurato" non sono la stessa cosa.** Un conteggio a zero perche'
   nessuno ha ancora guardato si legge come "nessun problema", ed e' il modo in cui
   una dashboard mente senza dire una parola falsa. Ogni raccolta dichiara se la
   propria fonte ha dati (`misurato`), e la pagina lo dice al posto di mostrare uno
   zero rassicurante.
2. **Ogni numero deve portare da qualche parte.** Un indicatore senza il suo elenco
   e' una curiosita': ciascuno espone il collegamento alla pagina dove si vede di
   che cosa e' fatto.

remarks: Autore: Daniele Speziale - Data: 2026-09-12
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from .db import days_ago_str, hours_ago_str, query, scalar
from .presence import FINESTRA_PRESENZA_MIN

# Porte che espongono l'amministrazione di un apparato. Non e' un elenco di porte
# "pericolose": e' l'elenco di cio' con cui si prende il controllo di una macchina, e
# che quindi non dovrebbe rispondere a una rete di utenza.
PORTE_AMMINISTRAZIONE = (22, 23, 3389, 5900, 5901, 5985, 5986, 623)
# Protocolli che trasportano credenziali leggibili da chiunque stia sul percorso.
PORTE_IN_CHIARO = (21, 23, 69, 110, 143, 512, 513, 514)
# Banche dati: raggiungibili da una rete di utenza non hanno ragione di esserlo.
PORTE_BANCHE_DATI = (1433, 1521, 3306, 5432, 6379, 9200, 27017)

# Da quanti anni un'interfaccia web ferma diventa un problema, e da quanti e' grave.
# Sono le stesse soglie della relazione sulla vetusta': due numeri diversi per la
# stessa cosa, in due punti del prodotto, sarebbero due verita'.
ETA_PREOCCUPANTE = 5
ETA_GRAVE = 10


def _giorni_indietro(giorni: int) -> str:
    return days_ago_str(giorni)


def _minuti_indietro(minuti: int) -> str:
    """Istante di N minuti fa. `hours_ago_str` tronca a ore intere, e la finestra
    delle presenze si misura in minuti."""
    return (datetime.now(timezone.utc)
            - timedelta(minutes=int(minuti))).strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# Inventario
# --------------------------------------------------------------------------- #
def inventario(tenant_id: int) -> dict:
    """Che cosa c'e' in rete: quantita', stato, identificazione, copertura."""
    riga = query(
        "SELECT COUNT(*) AS totale,"
        " SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END) AS attivi,"
        " SUM(CASE WHEN status = 'down' THEN 1 ELSE 0 END) AS spenti,"
        " SUM(CASE WHEN device_type IS NULL OR device_type = 'unknown'"
        "          OR COALESCE(device_confidence, 0) < 60 THEN 1 ELSE 0 END) AS incerti,"
        " SUM(CASE WHEN os_name IS NOT NULL AND os_name <> '' THEN 1 ELSE 0 END) AS con_os,"
        " SUM(CASE WHEN mac IS NOT NULL AND mac <> '' THEN 1 ELSE 0 END) AS con_mac,"
        " SUM(CASE WHEN subnet_id IS NULL THEN 1 ELSE 0 END) AS fuori_perimetro"
        " FROM nodes WHERE tenant_id = ?", (tenant_id,), one=True)
    dati = {k: int(v or 0) for k, v in dict(riga).items()} if riga else {}

    perimetro = query(
        "SELECT COUNT(*) AS dichiarate,"
        " SUM(CASE WHEN COALESCE(is_enabled, 0) = 1 THEN 1 ELSE 0 END) AS attive,"
        " SUM(CASE WHEN COALESCE(is_wifi, 0) = 1 THEN 1 ELSE 0 END) AS senza_fili,"
        " COALESCE(SUM(host_count), 0) AS indirizzi"
        " FROM subnets WHERE tenant_id = ?", (tenant_id,), one=True)
    dati.update({"subnet_%s" % k: int(v or 0)
                 for k, v in dict(perimetro or {}).items()})

    # Reti dichiarate e mai prese come bersaglio: i punti ciechi. Una rete mai
    # guardata non produce righe da nessuna parte, e la sua assenza si legge come
    # "niente da segnalare" invece che come "non guardato".
    dati["reti_cieche"] = int(scalar(
        "SELECT COUNT(*) FROM subnets s WHERE s.tenant_id = ?"
        " AND COALESCE(s.is_enabled, 0) = 1"
        " AND NOT EXISTS (SELECT 1 FROM scan_runs r WHERE r.tenant_id = s.tenant_id"
        "                 AND r.target = s.cidr)", (tenant_id,)) or 0)
    dati["cambiamenti_24h"] = int(scalar(
        "SELECT COUNT(*) FROM node_changes WHERE tenant_id = ? AND created_at >= ?",
        (tenant_id, _giorni_indietro(1))) or 0)
    dati["identificati_percento"] = (
        round(100.0 * (dati["totale"] - dati["incerti"]) / dati["totale"], 1)
        if dati.get("totale") else 0.0)
    dati["misurato"] = bool(dati.get("totale"))
    return dati


def per_zona(tenant_id: int, massimo: int = 8) -> list:
    """Nodi per zona di rete: dice come e' distribuito il parco, non solo quanto e'
    grande. Le zone senza nodi restano fuori: una riga a zero non aggiunge nulla."""
    righe = query(
        "SELECT COALESCE(NULLIF(s.zone, ''), 'non dichiarata') AS zona,"
        " COUNT(n.id) AS nodi,"
        " SUM(CASE WHEN n.status = 'up' THEN 1 ELSE 0 END) AS attivi"
        " FROM nodes n LEFT JOIN subnets s ON s.id = n.subnet_id"
        " WHERE n.tenant_id = ? GROUP BY 1 HAVING COUNT(n.id) > 0"
        " ORDER BY COUNT(n.id) DESC LIMIT ?", (tenant_id, int(massimo)))
    return [{"zona": r["zona"], "nodi": int(r["nodi"] or 0),
             "attivi": int(r["attivi"] or 0)} for r in righe]


def per_tipo(tenant_id: int, massimo: int = 10) -> list:
    """Composizione del parco per tipo di apparato."""
    righe = query(
        "SELECT COALESCE(NULLIF(device_label, ''), 'non identificato') AS tipo,"
        " COUNT(*) AS quanti FROM nodes WHERE tenant_id = ?"
        " GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT ?", (tenant_id, int(massimo)))
    return [{"tipo": r["tipo"], "quanti": int(r["quanti"] or 0)} for r in righe]


# --------------------------------------------------------------------------- #
# Superficie esposta
# --------------------------------------------------------------------------- #
def _porte_in(tenant_id: int, porte: tuple) -> dict:
    segnaposti = ", ".join("?" for _ in porte)
    riga = query(
        "SELECT COUNT(*) AS porte, COUNT(DISTINCT node_id) AS nodi"
        " FROM node_ports WHERE tenant_id = ? AND state = 'open'"
        " AND COALESCE(is_suspect, 0) = 0 AND port IN (" + segnaposti + ")",
        tuple([tenant_id] + list(porte)), one=True)
    return {"porte": int((riga or {})["porte"] or 0),
            "nodi": int((riga or {})["nodi"] or 0)}


def esposizione(tenant_id: int) -> dict:
    """La superficie: quante porte rispondono, e quali fra quelle che contano."""
    riga = query(
        "SELECT COUNT(*) AS aperte, COUNT(DISTINCT node_id) AS nodi,"
        " COUNT(DISTINCT port) AS porte_distinte,"
        " SUM(CASE WHEN version IS NOT NULL AND version <> '' THEN 1 ELSE 0 END)"
        "   AS con_versione"
        " FROM node_ports WHERE tenant_id = ? AND state = 'open'"
        " AND COALESCE(is_suspect, 0) = 0", (tenant_id,), one=True)
    dati = {k: int(v or 0) for k, v in dict(riga or {}).items()}
    dati["amministrazione"] = _porte_in(tenant_id, PORTE_AMMINISTRAZIONE)
    dati["in_chiaro"] = _porte_in(tenant_id, PORTE_IN_CHIARO)
    dati["banche_dati"] = _porte_in(tenant_id, PORTE_BANCHE_DATI)
    dati["misurato"] = bool(dati.get("aperte"))
    return dati


def porte_piu_diffuse(tenant_id: int, massimo: int = 8) -> list:
    """Che cosa risponde su piu' dispositivi: descrive la rete meglio di un elenco."""
    righe = query(
        "SELECT port, MAX(COALESCE(NULLIF(service_name, ''), '')) AS servizio,"
        " COUNT(DISTINCT node_id) AS nodi FROM node_ports"
        " WHERE tenant_id = ? AND state = 'open' AND COALESCE(is_suspect, 0) = 0"
        " GROUP BY port ORDER BY COUNT(DISTINCT node_id) DESC LIMIT ?",
        (tenant_id, int(massimo)))
    return [{"porta": int(r["port"]), "servizio": r["servizio"] or "-",
             "nodi": int(r["nodi"] or 0),
             "amministrazione": int(r["port"]) in PORTE_AMMINISTRAZIONE,
             "in_chiaro": int(r["port"]) in PORTE_IN_CHIARO} for r in righe]


# --------------------------------------------------------------------------- #
# Vulnerabilita'
# --------------------------------------------------------------------------- #
GRAVITA_ORDINE = ("critical", "high", "medium", "low", "none")
GRAVITA_NOME = {"critical": "critica", "high": "alta", "medium": "media",
                "low": "bassa", "none": "non classificata"}


def vulnerabilita(tenant_id: int) -> dict:
    """I riscontri di vulnerabilita': quanti, di che gravita', su quanti apparati.

    Si contano i RISCONTRI e i NODI separatamente: venti riscontri su un apparato
    solo e venti apparati con un riscontro ciascuno sono due situazioni diverse, e un
    numero solo non le distingue.
    """
    righe = query(
        "SELECT COALESCE(NULLIF(severity, ''), 'none') AS gravita,"
        " COUNT(*) AS quanti, COUNT(DISTINCT node_id) AS nodi"
        " FROM ti_findings WHERE tenant_id = ? GROUP BY 1", (tenant_id,))
    per_gravita = {r["gravita"]: {"quanti": int(r["quanti"] or 0),
                                  "nodi": int(r["nodi"] or 0)} for r in righe}
    ordinate = [{"chiave": chiave, "nome": GRAVITA_NOME[chiave],
                 "quanti": per_gravita.get(chiave, {}).get("quanti", 0),
                 "nodi": per_gravita.get(chiave, {}).get("nodi", 0)}
                for chiave in GRAVITA_ORDINE]

    riga = query(
        "SELECT COUNT(*) AS totale, COUNT(DISTINCT f.node_id) AS nodi,"
        " SUM(CASE WHEN COALESCE(c.kev, 0) = 1 THEN 1 ELSE 0 END) AS kev,"
        " SUM(CASE WHEN f.status = 'open' THEN 1 ELSE 0 END) AS aperti,"
        " SUM(CASE WHEN f.first_seen_at >= ? THEN 1 ELSE 0 END) AS nuovi_7g"
        " FROM ti_findings f LEFT JOIN ti_cve c ON c.cve_id = f.cve_id"
        " WHERE f.tenant_id = ?", (_giorni_indietro(7), tenant_id), one=True)
    dati = {k: int(v or 0) for k, v in dict(riga or {}).items()}
    dati["per_gravita"] = ordinate
    dati["gravi"] = sum(v["quanti"] for v in ordinate
                        if v["chiave"] in ("critical", "high"))
    dati["misurato"] = bool(dati.get("totale"))
    return dati


def nodi_piu_esposti(tenant_id: int, massimo: int = 6) -> list:
    """Da dove cominciare: gli apparati con piu' riscontri gravi."""
    righe = query(
        "SELECT n.id, n.ip, COALESCE(n.hostname, '') AS hostname,"
        " COALESCE(n.device_label, '') AS device_label,"
        " COUNT(*) AS riscontri,"
        " SUM(CASE WHEN f.severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS gravi,"
        " SUM(CASE WHEN COALESCE(c.kev, 0) = 1 THEN 1 ELSE 0 END) AS kev"
        " FROM ti_findings f JOIN nodes n ON n.id = f.node_id"
        " LEFT JOIN ti_cve c ON c.cve_id = f.cve_id"
        " WHERE f.tenant_id = ? GROUP BY n.id, n.ip, n.hostname, n.device_label"
        " ORDER BY SUM(CASE WHEN COALESCE(c.kev, 0) = 1 THEN 1 ELSE 0 END) DESC,"
        " SUM(CASE WHEN f.severity IN ('critical', 'high') THEN 1 ELSE 0 END) DESC,"
        " COUNT(*) DESC LIMIT ?", (tenant_id, int(massimo)))
    return [dict(r) for r in righe]


# --------------------------------------------------------------------------- #
# Certificati TLS
# --------------------------------------------------------------------------- #
def certificati(tenant_id: int, oggi: date = None) -> dict:
    """Scadenze e debolezze dei certificati, contate senza caricarli tutti."""
    oggi = oggi or date.today()
    entro_30 = (oggi + timedelta(days=30)).isoformat()
    entro_90 = (oggi + timedelta(days=90)).isoformat()
    riga = query(
        "SELECT COUNT(*) AS totale,"
        " SUM(CASE WHEN substr(cert_expires, 1, 10) < ? THEN 1 ELSE 0 END) AS scaduti,"
        " SUM(CASE WHEN substr(cert_expires, 1, 10) >= ?"
        "          AND substr(cert_expires, 1, 10) <= ? THEN 1 ELSE 0 END) AS entro_30,"
        " SUM(CASE WHEN substr(cert_expires, 1, 10) >= ?"
        "          AND substr(cert_expires, 1, 10) <= ? THEN 1 ELSE 0 END) AS entro_90,"
        " SUM(CASE WHEN COALESCE(cert_selfsigned, 0) = 1 THEN 1 ELSE 0 END)"
        "   AS autofirmati,"
        " COUNT(DISTINCT node_id) AS nodi"
        " FROM node_web WHERE tenant_id = ? AND scheme = 'https'"
        " AND cert_expires IS NOT NULL AND cert_expires <> ''",
        (oggi.isoformat(), oggi.isoformat(), entro_30, oggi.isoformat(), entro_90,
         tenant_id), one=True)
    dati = {k: int(v or 0) for k, v in dict(riga or {}).items()}
    dati["misurato"] = bool(dati.get("totale"))
    return dati


# --------------------------------------------------------------------------- #
# Vetusta' delle interfacce
# --------------------------------------------------------------------------- #
def vetusta(tenant_id: int, oggi: date = None) -> dict:
    """Da quanti anni non si tocca piu' un'interfaccia, contato per fasce.

    Il limite dichiarato e' lo stesso della relazione: un anno letto da una pagina e'
    un limite INFERIORE all'eta', non una misura. Qui conta come tale.
    """
    anno = (oggi or date.today()).year
    riga = query(
        "SELECT COUNT(*) AS con_anno,"
        " SUM(CASE WHEN web_year <= ? THEN 1 ELSE 0 END) AS gravi,"
        " SUM(CASE WHEN web_year > ? AND web_year <= ? THEN 1 ELSE 0 END)"
        "   AS preoccupanti,"
        " MIN(web_year) AS anno_minimo"
        " FROM node_web WHERE tenant_id = ? AND web_year IS NOT NULL AND web_year > 0",
        (anno - ETA_GRAVE, anno - ETA_GRAVE, anno - ETA_PREOCCUPANTE, tenant_id),
        one=True)
    dati = {k: int(v or 0) for k, v in dict(riga or {}).items()}
    dati["senza_anno"] = int(scalar(
        "SELECT COUNT(*) FROM node_web WHERE tenant_id = ?"
        " AND (web_year IS NULL OR web_year = 0)", (tenant_id,)) or 0)
    dati["eta_massima"] = (anno - dati["anno_minimo"]) if dati.get("anno_minimo") else 0
    dati["misurato"] = bool(dati.get("con_anno"))

    # La distribuzione per anno: e' il grafico che racconta la storia del parco, e si
    # legge solo se gli anni sono tutti, anche quelli senza nessuna interfaccia --
    # un buco in mezzo e' un'informazione, non una riga da saltare.
    righe = query(
        "SELECT web_year AS anno, COUNT(DISTINCT node_id) AS nodi FROM node_web"
        " WHERE tenant_id = ? AND web_year IS NOT NULL AND web_year > 0"
        " GROUP BY web_year ORDER BY web_year", (tenant_id,))
    per_anno = {int(r["anno"]): int(r["nodi"] or 0) for r in righe}
    if per_anno:
        primo, ultimo = min(per_anno), max(per_anno)
        dati["distribuzione"] = [{"anno": a, "nodi": per_anno.get(a, 0),
                                  "eta": anno - a}
                                 for a in range(primo, ultimo + 1)]
    else:
        dati["distribuzione"] = []
    return dati


# --------------------------------------------------------------------------- #
# Esposizione SMB
# --------------------------------------------------------------------------- #
def smb(tenant_id: int) -> dict:
    """Firma dei messaggi e dialetto 1.0, contati sulle letture gia' raccolte."""
    riga = query(
        "SELECT COUNT(DISTINCT node_id) AS nodi,"
        " COUNT(DISTINCT CASE WHEN script_id LIKE '%security-mode%'"
        "   AND LOWER(output) LIKE '%enabled but not required%'"
        "   THEN node_id END) AS senza_firma,"
        " COUNT(DISTINCT CASE WHEN script_id LIKE '%security-mode%'"
        "   AND LOWER(output) LIKE '%signing%required%'"
        "   AND LOWER(output) NOT LIKE '%not required%'"
        "   THEN node_id END) AS firma_richiesta,"
        " COUNT(DISTINCT CASE WHEN script_id LIKE '%protocols%'"
        "   AND LOWER(output) LIKE '%nt lm 0.12%' THEN node_id END) AS smb1"
        " FROM node_smb WHERE tenant_id = ?", (tenant_id,), one=True)
    dati = {k: int(v or 0) for k, v in dict(riga or {}).items()}
    dati["misurato"] = bool(dati.get("nodi"))
    return dati


# --------------------------------------------------------------------------- #
# Presenze sulle reti senza fili
# --------------------------------------------------------------------------- #
def presenze(tenant_id: int) -> dict:
    """Chi c'e' adesso e chi c'e' stato oggi, sulle sole reti dichiarate senza fili."""
    da_24h = hours_ago_str(24)
    riga = query(
        "SELECT COUNT(DISTINCT identity_key) AS apparati_24h, COUNT(*) AS permanenze,"
        " COUNT(DISTINCT CASE WHEN identity_source = 'address' THEN identity_key END)"
        "   AS senza_identita,"
        " COUNT(DISTINCT CASE WHEN last_seen_at >= ? THEN identity_key END) AS adesso"
        " FROM presence_sessions WHERE tenant_id = ? AND last_seen_at >= ?",
        (_minuti_indietro(FINESTRA_PRESENZA_MIN), tenant_id, da_24h), one=True)
    dati = {k: int(v or 0) for k, v in dict(riga or {}).items()}
    dati["reti"] = int(scalar(
        "SELECT COUNT(*) FROM subnets WHERE tenant_id = ?"
        " AND COALESCE(is_wifi, 0) = 1 AND COALESCE(is_enabled, 0) = 1",
        (tenant_id,)) or 0)
    dati["nuovi_24h"] = int(scalar(
        "SELECT COUNT(*) FROM (SELECT identity_key FROM presence_sessions"
        " WHERE tenant_id = ? GROUP BY identity_key"
        " HAVING MIN(first_seen_at) >= ?) AS nuovi", (tenant_id, da_24h)) or 0)
    ultimo = scalar("SELECT MAX(last_seen_at) FROM presence_sessions"
                    " WHERE tenant_id = ?", (tenant_id,))
    dati["ultimo_avvistamento"] = ultimo
    dati["misurato"] = bool(dati.get("permanenze"))
    return dati


# --------------------------------------------------------------------------- #
# Flotta e raccolta
# --------------------------------------------------------------------------- #
def flotta(tenant_id: int) -> dict:
    """Lo stato dello STRUMENTO: sonde, passate, conferimenti.

    Va letto prima di ogni altro numero della pagina: dice se ci si puo' fidare.
    """
    riga = query(
        "SELECT COUNT(*) AS sonde,"
        " SUM(CASE WHEN status = 'active' AND revoked_at IS NULL THEN 1 ELSE 0 END)"
        "   AS attive,"
        " SUM(CASE WHEN COALESCE(scan_paused, 0) = 1"
        "          OR COALESCE(scan_enabled, 1) = 0 THEN 1 ELSE 0 END) AS sospese,"
        " SUM(CASE WHEN last_seen_at >= ? THEN 1 ELSE 0 END) AS in_contatto,"
        " MAX(last_seen_at) AS ultimo_contatto"
        " FROM probes WHERE tenant_id = ?", (hours_ago_str(1), tenant_id), one=True)
    dati = dict(riga or {})
    for chiave in ("sonde", "attive", "sospese", "in_contatto"):
        dati[chiave] = int(dati.get(chiave) or 0)

    passate = query(
        "SELECT COUNT(*) AS passate,"
        " SUM(CASE WHEN COALESCE(hosts_up, 0) = 0 THEN 1 ELSE 0 END) AS a_vuoto,"
        " COALESCE(SUM(hosts_up), 0) AS host,"
        " COUNT(DISTINCT stage) AS fasi"
        " FROM scan_runs WHERE tenant_id = ? AND created_at >= ?",
        (tenant_id, _giorni_indietro(1)), one=True)
    dati.update({k: int(v or 0) for k, v in dict(passate or {}).items()})

    lotti = query(
        "SELECT COUNT(*) AS lotti, COALESCE(SUM(record_count), 0) AS record,"
        " COALESCE(SUM(payload_bytes), 0) AS byte,"
        " SUM(CASE WHEN status <> 'accepted' THEN 1 ELSE 0 END) AS rifiutati"
        " FROM ingest_batches WHERE tenant_id = ? AND received_at >= ?",
        (tenant_id, _giorni_indietro(1)), one=True)
    dati.update({k: int(v or 0) for k, v in dict(lotti or {}).items()})
    dati["misurato"] = bool(dati.get("sonde"))
    return dati


def fasi_di_scansione(tenant_id: int) -> list:
    """Le fasi delle ultime ventiquattro ore, con quante sono andate a vuoto.

    Si contano le passate senza NESSUN host: il contatore dei record lo valorizzano
    le sole fasi che scrivono record propri, e leggerlo come misura di successo
    darebbe un allarme falso su tutte le altre.
    """
    righe = query(
        "SELECT stage, COUNT(*) AS passate,"
        " SUM(CASE WHEN COALESCE(hosts_up, 0) = 0 THEN 1 ELSE 0 END) AS a_vuoto,"
        " COALESCE(SUM(hosts_up), 0) AS host,"
        " COALESCE(SUM(hosts_total), 0) AS bersagli,"
        " ROUND(AVG(COALESCE(duration_ms, 0)) / 1000.0, 1) AS secondi"
        " FROM scan_runs WHERE tenant_id = ? AND created_at >= ?"
        " GROUP BY stage ORDER BY COUNT(*) DESC", (tenant_id, _giorni_indietro(1)))

    fasi = []
    for r in righe:
        passate = int(r["passate"] or 0)
        # UNA FASE CHE NON CONTA HOST NON SI GIUDICA SUGLI HOST. `monitor`, `deep` e
        # `os` lavorano su nodi gia' noti e non dichiarano bersagli: misurarle con la
        # quota di passate "che hanno visto qualcuno" darebbe 0% su tutte -- lo stesso
        # allarme falso che il contatore dei record dava altrove, con un altro campo.
        conta_host = bool(int(r["bersagli"] or 0))
        fasi.append({
            "fase": r["stage"],
            "passate": passate,
            "a_vuoto": int(r["a_vuoto"] or 0),
            "host": int(r["host"] or 0),
            "bersagli": int(r["bersagli"] or 0),
            "secondi": float(r["secondi"] or 0),
            "conta_host": conta_host,
            "resa": (round(100.0 * (passate - int(r["a_vuoto"] or 0)) / passate, 1)
                     if conta_host and passate else None),
        })
    return fasi


# --------------------------------------------------------------------------- #
# Andamenti (serie per i grafici)
# --------------------------------------------------------------------------- #
def andamento_record(tenant_id: int, ore: int = 24) -> list:
    """Record conferiti per ora: il polso della raccolta."""
    righe = query(
        "SELECT to_char(received_at::timestamp, 'YYYY-MM-DD HH24:00:00') AS ora,"
        " COALESCE(SUM(record_count), 0) AS record FROM ingest_batches"
        " WHERE tenant_id = ? AND received_at >= ? GROUP BY 1 ORDER BY 1",
        (tenant_id, hours_ago_str(ore)))
    return [[r["ora"], float(r["record"] or 0)] for r in righe]


def andamento_cambiamenti(tenant_id: int, giorni: int = 14) -> list:
    """Cambiamenti rilevati per giorno: quanto si muove la rete."""
    righe = query(
        "SELECT substr(created_at, 1, 10) AS giorno, COUNT(*) AS quanti"
        " FROM node_changes WHERE tenant_id = ? AND created_at >= ?"
        " GROUP BY 1 ORDER BY 1", (tenant_id, _giorni_indietro(giorni)))
    return [[r["giorno"], float(r["quanti"] or 0)] for r in righe]


def andamento_presenze(tenant_id: int, ore: int = 24) -> list:
    """Apparati PRESENTI ora per ora sulle reti senza fili.

    Un apparato conta in un'ora se la sua permanenza la TOCCA: la presenza e' un
    fatto continuo, e raggruppare sull'ultimo avvistamento -- come si farebbe con un
    GROUP BY sulla colonna -- metterebbe una permanenza di sei ore in un'ora sola,
    disegnando una rete vuota per cinque ore su sei.
    """
    from datetime import datetime, timedelta, timezone

    permanenze = query(
        "SELECT first_seen_at, last_seen_at, identity_key FROM presence_sessions"
        " WHERE tenant_id = ? AND last_seen_at >= ? LIMIT 5000",
        (tenant_id, hours_ago_str(ore)))
    if not permanenze:
        return []

    def istante(valore):
        try:
            return datetime.strptime(str(valore), "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return None

    intervalli = []
    for riga in permanenze:
        inizio, fine = istante(riga["first_seen_at"]), istante(riga["last_seen_at"])
        if inizio and fine:
            intervalli.append((inizio, fine, riga["identity_key"]))

    adesso = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    punti = []
    for indietro in range(int(ore), -1, -1):
        momento = adesso - timedelta(hours=indietro)
        prossimo = momento + timedelta(hours=1)
        presenti = {chiave for inizio, fine, chiave in intervalli
                    if inizio < prossimo and fine >= momento}
        punti.append([momento.strftime("%Y-%m-%d %H:%M:%S"), float(len(presenti))])
    return punti


def andamento_nodi(tenant_id: int, giorni: int = 14) -> list:
    """Nodi visti per la prima volta, giorno per giorno: la crescita del censimento."""
    righe = query(
        "SELECT substr(first_seen_at, 1, 10) AS giorno, COUNT(*) AS quanti"
        " FROM nodes WHERE tenant_id = ? AND first_seen_at >= ?"
        " GROUP BY 1 ORDER BY 1", (tenant_id, _giorni_indietro(giorni)))
    return [[r["giorno"], float(r["quanti"] or 0)] for r in righe]


# --------------------------------------------------------------------------- #
# Controlli e disponibilita'
# --------------------------------------------------------------------------- #
def controlli(tenant_id: int) -> dict:
    """Quanti controlli, quanti incidenti, quanta riuscita -- e i loro andamenti.

    E' l'unica parte della pagina che parla di SERVIZI invece che di apparati: dice
    se cio' che deve rispondere sta rispondendo. I conteggi vengono da
    `checks_queries`, che li calcola gia' per le proprie pagine: rifarli qui
    significherebbe avere due verita' sullo stesso numero.
    """
    from .checks_queries import checks_summary, incidents_daily, results_hourly

    sintesi = dict(checks_summary(tenant_id))
    orari = results_hourly(tenant_id)
    giornalieri = incidents_daily(tenant_id)
    return {
        "sintesi": sintesi,
        # La riuscita e' una percentuale: il grafico la disegna su una scala 0-100,
        # altrimenti una serie fra 98 e 100 sembrerebbe una montagna russa.
        "riuscita": [[v["hour"], float(v["success_rate"])] for v in orari
                     if v["success_rate"] is not None],
        "falliti": [[v["hour"], float(v["failed"])] for v in orari],
        "incidenti": [[v["day"], float(v["opened"])] for v in giornalieri],
        "misurato": bool(sintesi.get("checks_enabled")),
    }


# --------------------------------------------------------------------------- #
# Attivita' del sistema
# --------------------------------------------------------------------------- #
def attivita(tenant_id: int) -> dict:
    """Che cosa ha fatto il sistema: registro, notifiche, relazioni prodotte."""
    dati = {
        "eventi_24h": int(scalar(
            "SELECT COUNT(*) FROM audit_events WHERE tenant_id = ? AND created_at >= ?",
            (tenant_id, _giorni_indietro(1))) or 0),
        "eventi_gravi_7g": int(scalar(
            "SELECT COUNT(*) FROM audit_events WHERE tenant_id = ?"
            " AND severity IN ('warning', 'critical') AND created_at >= ?",
            (tenant_id, _giorni_indietro(7))) or 0),
        "notifiche_24h": int(scalar(
            "SELECT COUNT(*) FROM notifications WHERE tenant_id = ? AND created_at >= ?",
            (tenant_id, _giorni_indietro(1))) or 0),
        "notifiche_fallite_7g": int(scalar(
            "SELECT COUNT(*) FROM notifications WHERE tenant_id = ?"
            " AND status = 'failed' AND created_at >= ?",
            (tenant_id, _giorni_indietro(7))) or 0),
        "relazioni_30g": int(scalar(
            "SELECT COUNT(*) FROM report_runs WHERE tenant_id = ? AND created_at >= ?",
            (tenant_id, _giorni_indietro(30))) or 0),
        "comandi_in_attesa": int(scalar(
            "SELECT COUNT(*) FROM probe_commands WHERE tenant_id = ?"
            " AND status = 'pending'", (tenant_id,)) or 0),
    }
    return dati


# --------------------------------------------------------------------------- #
# La postura: quattro semafori, ciascuno con la propria ragione
# --------------------------------------------------------------------------- #
def _semaforo(valore: bool, attenzione: bool = False) -> str:
    if attenzione:
        return "warning"
    return "success" if valore else "danger"


def postura(inv: dict, vuln: dict, cert: dict, flo: dict) -> list:
    """Quattro giudizi in cima alla pagina, ognuno con il perche' scritto accanto.

    Un semaforo senza la sua ragione e' un colore: si puo' guardare, non si puo'
    usare. Ciascuno dichiara il numero da cui viene e dove si va a vederlo.
    """
    fresco = bool(flo.get("lotti"))
    vulnerabile = vuln.get("gravi", 0)
    scadenze = cert.get("scaduti", 0) + cert.get("entro_30", 0)
    ciechi = inv.get("reti_cieche", 0)

    return [
        {
            "chiave": "raccolta",
            "titolo": "Raccolta",
            "stato": "success" if fresco else "danger",
            "icona": "bi-cloud-arrow-down" if fresco else "bi-cloud-slash",
            "valore": "%d lotti/24h" % flo.get("lotti", 0),
            "motivo": ("il dato di questa pagina e' aggiornato"
                       if fresco else
                       "nessun conferimento nelle ultime 24 ore: i numeri qui sotto"
                       " sono vecchi"),
        },
        {
            "chiave": "copertura",
            "titolo": "Copertura",
            "stato": "warning" if ciechi else "success",
            "icona": "bi-eye-slash" if ciechi else "bi-bounding-box",
            "valore": ("%d reti mai guardate" % ciechi) if ciechi else "perimetro coperto",
            "motivo": ("una rete mai guardata non produce righe da nessuna parte, e la"
                       " sua assenza si legge come \"niente da segnalare\""
                       if ciechi else
                       "ogni rete attiva del perimetro e' stata guardata almeno una volta"),
        },
        {
            "chiave": "vulnerabilita",
            "titolo": "Vulnerabilita'",
            "stato": ("danger" if vuln.get("kev") else
                      ("warning" if vulnerabile else "success")),
            "icona": "bi-shield-exclamation" if vulnerabile else "bi-shield-check",
            "valore": ("%d gravi" % vulnerabile) if vuln.get("misurato") else "non misurate",
            "motivo": (("%d sfruttate in attacchi reali (KEV): fra due riscontri con lo"
                        " stesso punteggio, queste vanno prima" % vuln["kev"])
                       if vuln.get("kev") else
                       ("nessun riscontro critico o alto"
                        if vuln.get("misurato") else
                        "nessuna correlazione eseguita: non e' un parco senza"
                        " vulnerabilita', e' un parco non confrontato")),
        },
        {
            "chiave": "certificati",
            "titolo": "Certificati TLS",
            "stato": ("danger" if cert.get("scaduti") else
                      ("warning" if scadenze else "success")),
            "icona": "bi-patch-exclamation" if scadenze else "bi-patch-check",
            "valore": (("%d scaduti, %d entro 30 giorni"
                        % (cert.get("scaduti", 0), cert.get("entro_30", 0)))
                       if cert.get("misurato") else "nessuno letto"),
            "motivo": ("un certificato che scade non e' un rischio teorico: e' un"
                       " servizio che smette di funzionare a una data nota"),
        },
    ]


# --------------------------------------------------------------------------- #
# Il pannello intero
# --------------------------------------------------------------------------- #
def pannello(tenant_id: int) -> dict:
    """Tutti gli indicatori di Board2. Una chiamata sola: la pagina non deve sapere
    da quante tabelle viene cio' che mostra."""
    inv = inventario(tenant_id)
    vuln = vulnerabilita(tenant_id)
    cert = certificati(tenant_id)
    flo = flotta(tenant_id)
    return {
        "controlli": controlli(tenant_id),
        "inventario": inv,
        "zone": per_zona(tenant_id),
        "tipi": per_tipo(tenant_id),
        "esposizione": esposizione(tenant_id),
        "porte": porte_piu_diffuse(tenant_id),
        "vulnerabilita": vuln,
        "nodi_esposti": nodi_piu_esposti(tenant_id),
        "certificati": cert,
        "vetusta": vetusta(tenant_id),
        "smb": smb(tenant_id),
        "presenze": presenze(tenant_id),
        "flotta": flo,
        "fasi": fasi_di_scansione(tenant_id),
        "attivita": attivita(tenant_id),
        "postura": postura(inv, vuln, cert, flo),
        "grafici": {
            "record": andamento_record(tenant_id),
            "cambiamenti": andamento_cambiamenti(tenant_id),
            "presenze": andamento_presenze(tenant_id),
            "nodi": andamento_nodi(tenant_id),
        },
        "generato": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    }
