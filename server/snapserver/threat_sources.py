"""
snap server - Sorgenti della threat intelligence: NVD, CISA KEV, CWE, MITRE ATT&CK.

Principio: il catalogo e' **locale**. La correlazione con l'inventario non contatta
nessuno e funziona in una rete isolata; l'aggiornamento del catalogo e' un'operazione
esplicita, tracciata, e accetta anche un file caricato a mano -- che e' il solo modo di
tenere aggiornato un server in un ambiente senza uscita verso internet.

Sorgenti e forma verificata il 28/08/2026:

| Sorgente | Indirizzo | Note |
|---|---|---|
| NVD API 2.0 | `services.nvd.nist.gov/rest/json/cves/2.0` | 5 richieste ogni 30 s senza chiave, 50 con chiave |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | 1685 voci, un solo file |
| CWE (vista 1003) | `cwe.mitre.org/data/csv/1003.csv.zip` | 130 debolezze: quelle che la NVD usa davvero |
| MITRE ATT&CK | `attack-stix-data` (enterprise) | ~35 MB, tecniche e tattiche |

Modi di aggiornamento
---------------------
`targeted`  interroga la NVD **per i prodotti che esistono nell'inventario**. E' il modo
            predefinito: poche richieste, e tutto cio' che scarica riguarda cose che il
            cliente ha davvero. Scaricare 250.000 CVE per correlarne trenta e' lavoro
            inutile e un catalogo che nessuno tiene aggiornato.
`window`    CVE modificate negli ultimi giorni: tiene fresco cio' che si ha.
`kev`, `cwe`, `attack`  cataloghi interi, piccoli.
`file`      importazione da file, per le installazioni senza rete.

Nessuna dipendenza aggiunta: `urllib`, `json`, `csv`, `zipfile`, `gzip` stanno nella
libreria standard.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone

from .audit import log_event
from .db import execute, query, utc_now_str

USER_AGENT = "snap-threat-intelligence/1.0"
HTTP_TIMEOUT = 60
# Un file piu' grande di questo non si scarica: e' una guardia contro una sorgente
# cambiata o un errore di indirizzo, non un limite dell'ATT&CK (35 MB).
MAX_DOWNLOAD_BYTES = 80 * 1024 * 1024

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
CWE_URL = "https://cwe.mitre.org/data/csv/1003.csv.zip"
ATTACK_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
              "master/enterprise-attack/enterprise-attack.json")

# Pause fra le richieste alla NVD: senza chiave sono 5 richieste ogni 30 secondi, e
# superarle produce un 403 che blocca l'indirizzo per un po'. Con la chiave si sale.
PAUSA_NVD_SENZA_CHIAVE = 6.5
PAUSA_NVD_CON_CHIAVE = 0.8
NVD_PAGINA = 2000
# La NVD accetta finestre di 120 giorni al massimo per `lastModStartDate`.
MAX_GIORNI_FINESTRA = 120

SORGENTI = {
    "nvd": "NVD (National Vulnerability Database)",
    "kev": "CISA KEV (vulnerabilita' sfruttate attivamente)",
    "cwe": "MITRE CWE (classi di debolezza)",
    "attack": "MITRE ATT&CK (tecniche)",
}


class SourceError(RuntimeError):
    """La sorgente non e' utilizzabile. Il messaggio e' destinato all'operatore."""


# --------------------------------------------------------------------------- #
# Impostazioni e registro
# --------------------------------------------------------------------------- #
def _setting(chiave: str, predefinito: str = "") -> str:
    riga = query("SELECT value FROM system_settings WHERE key = ?", (chiave,), one=True)
    if riga is None or riga["value"] is None:
        return predefinito
    return str(riga["value"])


def _save_setting(chiave: str, valore: str) -> None:
    execute("INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value,"
            " updated_at = excluded.updated_at", (chiave, valore, utc_now_str()))


def settings() -> dict:
    """Impostazioni delle sorgenti. La chiave API non esce mai in chiaro."""
    chiave = _setting("ti_nvd_api_key").strip()
    return {
        "api_key": chiave,
        "has_api_key": bool(chiave),
        "api_key_masked": mask_key(chiave),
        "api_key_url": NVD_KEY_URL,
        # Il ritmo effettivo e' l'informazione utile: dice quanto durera' un
        # aggiornamento, ed e' la ragione per cui la chiave conviene.
        "pausa": PAUSA_NVD_CON_CHIAVE if chiave else PAUSA_NVD_SENZA_CHIAVE,
        "richieste_per_finestra": 50 if chiave else 5,
        "enabled": _setting("ti_sync_enabled", "1") != "0",
        "window_days": int(_setting("ti_window_days", "30") or 30),
    }


# La NVD emette chiavi in forma di UUID: 36 caratteri fra cifre esadecimali e
# trattini. Si valida in allowlist -- non per sicurezza della NVD, ma per accorgersi
# subito di un incolla sbagliato invece di scoprirlo con un 403 dopo dieci minuti.
NVD_KEY_PATTERN = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                             r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
NVD_KEY_URL = "https://nvd.nist.gov/developers/request-an-api-key"


def public_settings() -> dict:
    """Impostazioni destinate alla pagina, senza la chiave in chiaro.

    Il modello non la stampa, ma un valore nel contesto e' a un'espressione di
    distanza dall'essere stampato per sbaglio e compare in ogni traccia di debug
    della resa: alla pagina va una copia senza il segreto.
    """
    return {chiave: valore for chiave, valore in settings().items()
            if chiave != "api_key"}


def mask_key(chiave: str) -> str:
    """Forma mostrabile di una chiave: ultime quattro cifre e nulla piu'.

    La chiave non torna mai alla pagina in chiaro: chi la vede in un modulo
    precompilato la vede anche in una cronologia, in un rendering di stampa o in una
    schermata condivisa. Le ultime quattro cifre bastano a riconoscere quale chiave
    e' registrata.
    """
    pulita = (chiave or "").strip()
    if not pulita:
        return ""
    return "%s%s" % ("*" * 32, pulita[-4:]) if len(pulita) > 4 else "*" * len(pulita)


def save_api_key(chiave: str, requested_by: int = None) -> str:
    """Registra o rimuove la chiave API della NVD. Restituisce cio' che e' avvenuto.

    Un valore vuoto la rimuove: e' il modo di tornare al ritmo senza chiave senza
    dover modificare la banca dati a mano.
    """
    pulita = (chiave or "").strip()
    if not pulita:
        _save_setting("ti_nvd_api_key", "")
        log_event("threat.apikey.removed",
                  "Chiave API della NVD rimossa: gli aggiornamenti tornano al ritmo"
                  " senza chiave (5 richieste ogni 30 secondi).",
                  severity="info", entity="threat", global_event=True)
        return "rimossa"

    if not NVD_KEY_PATTERN.match(pulita):
        raise SourceError(
            "La chiave non ha la forma attesa: la NVD emette chiavi di 36 caratteri"
            " nella forma xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx. Verificare che sia"
            " stata copiata per intero.")

    _save_setting("ti_nvd_api_key", pulita)
    # Nel registro finisce il fatto, non la chiave: un segreto in un registro di
    # audit e' un segreto compromesso.
    log_event("threat.apikey.saved",
              "Chiave API della NVD registrata (%s): gli aggiornamenti passano a 50"
              " richieste ogni 30 secondi." % mask_key(pulita),
              severity="info", entity="threat", global_event=True)
    return "registrata"


def _apri(url: str, dati: bytes = None, timeout: int = HTTP_TIMEOUT,
          intestazioni: dict = None) -> bytes:
    """Una richiesta HTTP con guardie: dimensione massima e messaggi comprensibili."""
    richiesta = urllib.request.Request(url, data=dati,
                                       headers={"User-Agent": USER_AGENT})
    for chiave, valore in (intestazioni or {}).items():
        richiesta.add_header(chiave, valore)
    contesto = ssl.create_default_context()
    try:
        with urllib.request.urlopen(richiesta, timeout=timeout,
                                    context=contesto) as risposta:
            lunghezza = risposta.headers.get("Content-Length")
            if lunghezza and int(lunghezza) > MAX_DOWNLOAD_BYTES:
                raise SourceError("La sorgente dichiara %s byte, oltre il massimo"
                                  " consentito." % lunghezza)
            contenuto = risposta.read(MAX_DOWNLOAD_BYTES + 1)
            if len(contenuto) > MAX_DOWNLOAD_BYTES:
                raise SourceError("Scaricamento oltre il massimo consentito.")
            if (risposta.headers.get("Content-Encoding") == "gzip"
                    or url.endswith(".gz")):
                contenuto = gzip.decompress(contenuto)
            return contenuto
    except urllib.error.HTTPError as errore:
        dettaglio = ""
        try:
            dettaglio = errore.read().decode("utf-8", "replace")[:200]
        except OSError:
            dettaglio = ""
        if errore.code == 403:
            raise SourceError(
                "La sorgente ha risposto 403: la NVD limita le richieste senza chiave"
                " (5 ogni 30 secondi). Attendere qualche minuto oppure indicare una"
                " chiave API. %s" % dettaglio) from errore
        raise SourceError("La sorgente ha risposto %s: %s"
                          % (errore.code, dettaglio or errore.reason)) from errore
    except (urllib.error.URLError, OSError, ssl.SSLError) as errore:
        raise SourceError("Sorgente non raggiungibile: %s. In una rete senza uscita"
                          " usare l'importazione da file." % errore) from errore


def _inizio_sync(source: str, mode: str, requested_by=None) -> int:
    return execute(
        "INSERT INTO ti_sync (source, mode, status, items, started_at, requested_by)"
        " VALUES (?, ?, 'running', 0, ?, ?)",
        (source, mode, utc_now_str(), requested_by))


def _fine_sync(sync_id: int, status: str, items: int, detail: str = "") -> None:
    execute("UPDATE ti_sync SET status = ?, items = ?, detail = ?, finished_at = ?"
            " WHERE id = ?",
            (status, int(items), (detail or "")[:1000], utc_now_str(), sync_id))


def rebuild_cwe_links() -> int:
    """Ricostruisce il legame CVE-CWE dalla colonna testuale gia' conservata.

    Serve una volta sola, sugli archivi popolati prima che la tabella esistesse: le
    CVE ci sono, il legame no, e senza riempimento la scheda delle debolezze
    mostrerebbe zero ovunque. Non contatta nessuna sorgente.
    """
    scritti = 0
    for riga in query("SELECT cve_id, cwe_ids FROM ti_cve WHERE cwe_ids IS NOT NULL"
                      " AND cwe_ids <> ''", ()):
        for debolezza in (riga["cwe_ids"] or "").replace(" ", "").split(","):
            if debolezza.startswith("CWE-"):
                execute("INSERT OR IGNORE INTO ti_cve_cwe (cve_id, cwe_id)"
                        " VALUES (?, ?)", (riga["cve_id"], debolezza))
                scritti += 1
    return scritti


def recent_syncs(limit: int = 40) -> list:
    return [dict(r) for r in query(
        "SELECT s.*, u.full_name AS richiedente FROM ti_sync s"
        " LEFT JOIN users u ON u.id = s.requested_by"
        " ORDER BY s.id DESC LIMIT ?", (int(limit),))]


# Oltre questo tempo un aggiornamento "in corso" non lo e' piu': il processo che lo
# eseguiva e' stato riavviato (aggiornamento del prodotto, ricaricamento automatico in
# sviluppo, arresto della macchina). Una riga lasciata a "in corso" per sempre
# impedirebbe qualunque aggiornamento successivo, che e' il difetto peggiore di tutti.
MINUTI_ABBANDONO = 30


def running_sync() -> dict | None:
    """Aggiornamento realmente in corso. Le righe abbandonate vengono chiuse."""
    from datetime import datetime, timedelta, timezone

    from .db import utc_str

    riga = query("SELECT * FROM ti_sync WHERE status = 'running' ORDER BY id DESC"
                 " LIMIT 1", (), one=True)
    if riga is None:
        return None

    limite = utc_str(datetime.now(timezone.utc) - timedelta(minutes=MINUTI_ABBANDONO))
    if (riga["started_at"] or "") < limite:
        execute("UPDATE ti_sync SET status = 'interrupted', detail = ?,"
                " finished_at = ? WHERE id = ?",
                ("interrotto: il processo che lo eseguiva e' stato riavviato"
                 " (avviato %s, nessun avanzamento da oltre %d minuti)"
                 % (riga["started_at"], MINUTI_ABBANDONO),
                 utc_now_str(), int(riga["id"])))
        log_event("threat.sync.interrupted",
                  "Aggiornamento %s/%s dichiarato interrotto: avviato %s, nessun"
                  " avanzamento" % (riga["source"], riga["mode"], riga["started_at"]),
                  severity="warning", entity="threat")
        return None
    return dict(riga)


# --------------------------------------------------------------------------- #
# NVD: lettura di una CVE
# --------------------------------------------------------------------------- #
def _metrica(cve: dict) -> tuple:
    """Punteggio CVSS: si preferisce la versione piu' recente disponibile.

    Un punteggio v2 e un v3.1 non sono confrontabili; dichiarare quale si sta usando
    evita di sommare mele e pere in una tabella.
    """
    metriche = cve.get("metrics") or {}
    for chiave, versione in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                             ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        voci = metriche.get(chiave) or []
        if not voci:
            continue
        dati = voci[0].get("cvssData") or {}
        gravita = (dati.get("baseSeverity")
                   or voci[0].get("baseSeverity") or "").lower()
        return (versione, dati.get("vectorString") or "", dati.get("baseScore"),
                gravita or _gravita_da_punteggio(dati.get("baseScore")))
    return ("", "", None, "")


def _gravita_da_punteggio(punteggio) -> str:
    try:
        valore = float(punteggio)
    except (TypeError, ValueError):
        return ""
    if valore >= 9.0:
        return "critical"
    if valore >= 7.0:
        return "high"
    if valore >= 4.0:
        return "medium"
    if valore > 0:
        return "low"
    return "info"


def _cpe_da_configurazioni(cve: dict) -> list:
    voci = []
    for configurazione in cve.get("configurations") or []:
        for nodo in configurazione.get("nodes") or []:
            for corrispondenza in nodo.get("cpeMatch") or []:
                criterio = corrispondenza.get("criteria") or ""
                pezzi = criterio.split(":")
                if len(pezzi) < 6:
                    continue
                voci.append({
                    "criteria": criterio,
                    "part": pezzi[2],
                    "vendor": pezzi[3],
                    "product": pezzi[4],
                    "version": "" if pezzi[5] in ("*", "-") else pezzi[5],
                    "vulnerable": 1 if corrispondenza.get("vulnerable") else 0,
                    "version_start": corrispondenza.get("versionStartIncluding")
                                     or corrispondenza.get("versionStartExcluding") or "",
                    "version_start_incl": 1 if corrispondenza.get(
                        "versionStartIncluding") else 0,
                    "version_end": corrispondenza.get("versionEndIncluding")
                                   or corrispondenza.get("versionEndExcluding") or "",
                    "version_end_incl": 1 if corrispondenza.get(
                        "versionEndIncluding") else 0,
                })
    return voci


def store_cve(cve: dict, source: str = "nvd") -> bool:
    """Scrive (o aggiorna) una CVE della NVD nel catalogo locale."""
    identificativo = (cve.get("id") or "").upper()
    if not identificativo.startswith("CVE-"):
        return False

    descrizioni = {d.get("lang"): d.get("value") for d in cve.get("descriptions") or []}
    descrizione = descrizioni.get("it") or descrizioni.get("en") or ""
    versione, vettore, punteggio, gravita = _metrica(cve)
    cwe = sorted({d.get("value") for w in cve.get("weaknesses") or []
                  for d in w.get("description") or []
                  if (d.get("value") or "").startswith("CWE-")})
    riferimenti = [r.get("url") for r in cve.get("references") or [] if r.get("url")]
    adesso = utc_now_str()

    execute(
        "INSERT INTO ti_cve (cve_id, published_at, modified_at, cvss_version,"
        " cvss_vector, cvss_score, severity, description, cwe_ids, references_json,"
        " source, imported_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(cve_id) DO UPDATE SET published_at = excluded.published_at,"
        " modified_at = excluded.modified_at, cvss_version = excluded.cvss_version,"
        " cvss_vector = excluded.cvss_vector, cvss_score = excluded.cvss_score,"
        " severity = excluded.severity, description = excluded.description,"
        " cwe_ids = excluded.cwe_ids, references_json = excluded.references_json,"
        " imported_at = excluded.imported_at",
        (identificativo, (cve.get("published") or "")[:19],
         (cve.get("lastModified") or "")[:19], versione, vettore, punteggio,
         gravita or _gravita_da_punteggio(punteggio), descrizione[:4000],
         ",".join(cwe), json.dumps(riferimenti[:25]), source, adesso))

    # Il legame con le debolezze si riscrive insieme alla CVE: e' la forma
    # interrogabile di `cwe_ids`, e una CVE aggiornata puo' cambiarne l'elenco.
    execute("DELETE FROM ti_cve_cwe WHERE cve_id = ?", (identificativo,))
    for debolezza in cwe:
        execute("INSERT OR IGNORE INTO ti_cve_cwe (cve_id, cwe_id) VALUES (?, ?)",
                (identificativo, debolezza))

    # L'applicabilita' si riscrive: una CVE aggiornata puo' cambiare gli intervalli, e
    # tenere le righe vecchie produrrebbe corrispondenze su versioni non piu' incluse.
    execute("DELETE FROM ti_cve_cpe WHERE cve_id = ?", (identificativo,))
    for voce in _cpe_da_configurazioni(cve):
        execute(
            "INSERT INTO ti_cve_cpe (cve_id, criteria, part, vendor, product, version,"
            " vulnerable, version_start, version_start_incl, version_end,"
            " version_end_incl) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (identificativo, voce["criteria"], voce["part"], voce["vendor"],
             voce["product"], voce["version"], voce["vulnerable"],
             voce["version_start"], voce["version_start_incl"], voce["version_end"],
             voce["version_end_incl"]))
    return True


def _pausa(config: dict) -> float:
    return PAUSA_NVD_CON_CHIAVE if config.get("api_key") else PAUSA_NVD_SENZA_CHIAVE


def _chiedi_nvd(parametri: dict, config: dict) -> dict:
    url = NVD_API + "?" + urllib.parse.urlencode(parametri)
    intestazioni = {"apiKey": config["api_key"]} if config.get("api_key") else {}
    contenuto = _apri(url, intestazioni=intestazioni)
    try:
        return json.loads(contenuto)
    except ValueError as errore:
        raise SourceError("Risposta della NVD non interpretabile.") from errore


# --------------------------------------------------------------------------- #
# Aggiornamenti
# --------------------------------------------------------------------------- #
def inventory_products(tenant_id: int = None) -> list:
    """Prodotti distinti presenti nell'inventario, in forma (part, vendor, product).

    E' il cuore del modo `targeted`: si scarica solo cio' che riguarda cose che il
    cliente ha davvero.
    """
    from .threat import cpe_from_service, parse_cpe

    condizione = "" if tenant_id is None else " AND p.tenant_id = ?"
    parametri = () if tenant_id is None else (tenant_id,)
    prodotti = {}
    for riga in query(
            "SELECT DISTINCT p.cpe, p.product, p.version FROM node_ports p"
            " WHERE p.state = 'open'" + condizione, parametri):
        letti = []
        for pezzo in (riga["cpe"] or "").split(","):
            letto = parse_cpe(pezzo)
            if letto:
                letti.append(letto)
        if not letti:
            dedotto = cpe_from_service(riga["product"], riga["version"])
            if dedotto:
                letti.append(dedotto)
        for letto in letti:
            chiave = (letto["part"], letto["vendor"], letto["product"])
            prodotti.setdefault(chiave, 0)
            prodotti[chiave] += 1
    return [{"part": p, "vendor": v, "product": n, "osservazioni": q}
            for (p, v, n), q in sorted(prodotti.items(), key=lambda x: -x[1])]


def sync_targeted(tenant_id: int = None, requested_by=None, limite_prodotti: int = 60,
                  progresso=None) -> dict:
    """Scarica dalla NVD le CVE dei prodotti presenti nell'inventario."""
    config = settings()
    sync_id = _inizio_sync("nvd", "targeted", requested_by)
    prodotti = inventory_products(tenant_id)[:limite_prodotti]
    scritte = 0
    errori = []
    try:
        for indice, voce in enumerate(prodotti, start=1):
            criterio = "cpe:2.3:%s:%s:%s" % (voce["part"], voce["vendor"] or "*",
                                             voce["product"])
            try:
                documento = _chiedi_nvd({"virtualMatchString": criterio,
                                         "resultsPerPage": 200}, config)
            except SourceError as errore:
                errori.append("%s: %s" % (voce["product"], errore))
                continue
            for elemento in documento.get("vulnerabilities") or []:
                if store_cve(elemento.get("cve") or {}):
                    scritte += 1
            if progresso:
                progresso(indice, len(prodotti), voce["product"])
            execute("UPDATE ti_sync SET items = ?, detail = ? WHERE id = ?",
                    (scritte, "prodotto %d di %d: %s" % (indice, len(prodotti),
                                                         voce["product"]), sync_id))
            time.sleep(_pausa(config))
    except Exception as errore:  # noqa: BLE001 - l'esito va registrato comunque
        _fine_sync(sync_id, "error", scritte, str(errore))
        raise

    dettaglio = "%d prodotti interrogati" % len(prodotti)
    if errori:
        dettaglio += "; %d in errore: %s" % (len(errori), "; ".join(errori[:3]))
    _fine_sync(sync_id, "ok" if not errori else "partial", scritte, dettaglio)
    log_event("threat.sync",
              "Catalogo NVD aggiornato per l'inventario: %d CVE, %s"
              % (scritte, dettaglio), severity="info", entity="threat")
    return {"cve": scritte, "prodotti": len(prodotti), "errori": errori}


def sync_window(giorni: int = None, requested_by=None) -> dict:
    """Scarica le CVE modificate negli ultimi giorni, a pagine."""
    config = settings()
    giorni = min(int(giorni or config["window_days"]), MAX_GIORNI_FINESTRA)
    sync_id = _inizio_sync("nvd", "window", requested_by)
    fine = datetime.now(timezone.utc)
    inizio = fine - timedelta(days=giorni)
    scritte = 0
    try:
        indice = 0
        while True:
            documento = _chiedi_nvd({
                "lastModStartDate": inizio.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "lastModEndDate": fine.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": NVD_PAGINA,
                "startIndex": indice,
            }, config)
            voci = documento.get("vulnerabilities") or []
            for elemento in voci:
                if store_cve(elemento.get("cve") or {}):
                    scritte += 1
            totale = int(documento.get("totalResults") or 0)
            indice += len(voci)
            execute("UPDATE ti_sync SET items = ?, detail = ? WHERE id = ?",
                    (scritte, "%d di %d" % (indice, totale), sync_id))
            if not voci or indice >= totale:
                break
            time.sleep(_pausa(config))
    except Exception as errore:  # noqa: BLE001
        _fine_sync(sync_id, "error", scritte, str(errore))
        raise

    _fine_sync(sync_id, "ok", scritte, "finestra di %d giorni" % giorni)
    log_event("threat.sync", "Catalogo NVD aggiornato: %d CVE modificate negli ultimi"
                             " %d giorni" % (scritte, giorni),
              severity="info", entity="threat")
    return {"cve": scritte, "giorni": giorni}


def sync_kev(requested_by=None, contenuto: bytes = None) -> dict:
    """Catalogo CISA delle vulnerabilita' sfruttate attivamente.

    Le CVE del catalogo che non sono ancora nel nostro archivio vengono create: sono
    le piu' importanti che esistano, e non averle perche' la NVD non e' ancora stata
    interrogata sarebbe il difetto peggiore.
    """
    sync_id = _inizio_sync("kev", "file" if contenuto else "api", requested_by)
    try:
        dati = contenuto if contenuto is not None else _apri(KEV_URL)
        documento = json.loads(dati)
        voci = documento.get("vulnerabilities") or []
        adesso = utc_now_str()
        for voce in voci:
            identificativo = (voce.get("cveID") or "").upper()
            if not identificativo.startswith("CVE-"):
                continue
            descrizione = (voce.get("shortDescription") or "")[:4000]
            execute(
                "INSERT INTO ti_cve (cve_id, description, severity, kev, kev_added_at,"
                " kev_due_at, kev_ransomware, source, imported_at)"
                " VALUES (?, ?, 'high', 1, ?, ?, ?, 'kev', ?)"
                " ON CONFLICT(cve_id) DO UPDATE SET kev = 1,"
                " kev_added_at = excluded.kev_added_at,"
                " kev_due_at = excluded.kev_due_at,"
                " kev_ransomware = excluded.kev_ransomware,"
                " description = CASE WHEN ti_cve.description IS NULL"
                "   OR ti_cve.description = '' THEN excluded.description"
                "   ELSE ti_cve.description END",
                (identificativo, descrizione, voce.get("dateAdded"),
                 voce.get("dueDate"),
                 1 if str(voce.get("knownRansomwareCampaignUse", "")).lower() == "known"
                 else 0, adesso))
    except Exception as errore:  # noqa: BLE001
        _fine_sync(sync_id, "error", 0, str(errore))
        raise

    _fine_sync(sync_id, "ok", len(voci),
               "catalogo %s" % documento.get("catalogVersion", ""))
    log_event("threat.sync", "Catalogo CISA KEV aggiornato: %d vulnerabilita' sfruttate"
                             " attivamente" % len(voci),
              severity="info", entity="threat")
    return {"kev": len(voci), "versione": documento.get("catalogVersion")}


def sync_cwe(requested_by=None, contenuto: bytes = None) -> dict:
    """Vista CWE 1003: le 130 debolezze che la NVD usa per classificare le CVE."""
    sync_id = _inizio_sync("cwe", "file" if contenuto else "api", requested_by)
    scritte = 0
    try:
        dati = contenuto if contenuto is not None else _apri(CWE_URL)
        if dati[:2] == b"PK":
            archivio = zipfile.ZipFile(io.BytesIO(dati))
            nome = next((n for n in archivio.namelist() if n.endswith(".csv")), None)
            if nome is None:
                raise SourceError("L'archivio CWE non contiene un file CSV.")
            testo = archivio.read(nome).decode("utf-8", "replace")
        else:
            testo = dati.decode("utf-8", "replace")

        adesso = utc_now_str()
        for riga in csv.DictReader(io.StringIO(testo)):
            identificativo = (riga.get("CWE-ID") or "").strip()
            if not identificativo.isdigit():
                continue
            chiave = "CWE-%s" % identificativo
            execute(
                "INSERT INTO ti_cwe (cwe_id, name, abstraction, description, mitigation,"
                " url, imported_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(cwe_id) DO UPDATE SET name = excluded.name,"
                " abstraction = excluded.abstraction,"
                " description = excluded.description,"
                " mitigation = excluded.mitigation, imported_at = excluded.imported_at",
                (chiave, (riga.get("Name") or "").strip(),
                 (riga.get("Weakness Abstraction") or "").strip(),
                 (riga.get("Description") or "").strip()[:4000],
                 (riga.get("Potential Mitigations") or "").strip()[:4000],
                 "https://cwe.mitre.org/data/definitions/%s.html" % identificativo,
                 adesso))
            scritte += 1
    except Exception as errore:  # noqa: BLE001
        _fine_sync(sync_id, "error", scritte, str(errore))
        raise

    _fine_sync(sync_id, "ok", scritte, "vista 1003 (mappatura NVD)")
    log_event("threat.sync", "Catalogo CWE aggiornato: %d classi di debolezza" % scritte,
              severity="info", entity="threat")
    return {"cwe": scritte}


def sync_attack(requested_by=None, contenuto: bytes = None) -> dict:
    """Tecniche MITRE ATT&CK (matrice enterprise) dal pacchetto STIX ufficiale."""
    sync_id = _inizio_sync("attack", "file" if contenuto else "api", requested_by)
    scritte = 0
    try:
        dati = contenuto if contenuto is not None else _apri(ATTACK_URL, timeout=180)
        documento = json.loads(dati)
        adesso = utc_now_str()
        for oggetto in documento.get("objects") or []:
            if oggetto.get("type") != "attack-pattern" or oggetto.get("revoked"):
                continue
            identificativo = ""
            url = ""
            for riferimento in oggetto.get("external_references") or []:
                if riferimento.get("source_name") == "mitre-attack":
                    identificativo = riferimento.get("external_id") or ""
                    url = riferimento.get("url") or ""
                    break
            if not identificativo.startswith("T"):
                continue
            tattiche = ", ".join(
                (fase.get("phase_name") or "").replace("-", " ")
                for fase in oggetto.get("kill_chain_phases") or []
                if fase.get("kill_chain_name") == "mitre-attack")
            execute(
                "INSERT INTO ti_technique (technique_id, name, tactics, description,"
                " url, is_subtechnique, imported_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(technique_id) DO UPDATE SET name = excluded.name,"
                " tactics = excluded.tactics, description = excluded.description,"
                " url = excluded.url, imported_at = excluded.imported_at",
                (identificativo, (oggetto.get("name") or "")[:200], tattiche,
                 (oggetto.get("description") or "")[:4000], url,
                 1 if oggetto.get("x_mitre_is_subtechnique") else 0, adesso))
            scritte += 1
    except Exception as errore:  # noqa: BLE001
        _fine_sync(sync_id, "error", scritte, str(errore))
        raise

    _fine_sync(sync_id, "ok", scritte, "matrice enterprise")
    log_event("threat.sync", "Catalogo MITRE ATT&CK aggiornato: %d tecniche" % scritte,
              severity="info", entity="threat")
    return {"tecniche": scritte}


# --------------------------------------------------------------------------- #
# Importazione da file (installazioni senza uscita verso internet)
# --------------------------------------------------------------------------- #
def import_file(contenuto: bytes, nome: str = "", requested_by=None) -> dict:
    """Riconosce il contenuto e lo importa. Nessuna connessione.

    Si riconosce dal contenuto e non dall'estensione: un file rinominato non deve
    essere importato nella tabella sbagliata.
    """
    if not contenuto:
        raise SourceError("File vuoto.")
    if contenuto[:2] == b"\x1f\x8b":
        contenuto = gzip.decompress(contenuto)

    if contenuto[:2] == b"PK":
        return sync_cwe(requested_by=requested_by, contenuto=contenuto)

    testa = contenuto[:4000].decode("utf-8", "replace")
    if testa.lstrip().startswith("CWE-ID,"):
        return sync_cwe(requested_by=requested_by, contenuto=contenuto)

    try:
        documento = json.loads(contenuto)
    except ValueError as errore:
        raise SourceError("Formato non riconosciuto: atteso JSON della NVD, del"
                          " catalogo KEV, del pacchetto ATT&CK, oppure il CSV/ZIP"
                          " delle CWE.") from errore

    if isinstance(documento, dict) and documento.get("type") == "bundle":
        return sync_attack(requested_by=requested_by, contenuto=contenuto)
    if isinstance(documento, dict) and "catalogVersion" in documento:
        return sync_kev(requested_by=requested_by, contenuto=contenuto)
    if isinstance(documento, dict) and "vulnerabilities" in documento:
        sync_id = _inizio_sync("nvd", "file", requested_by)
        scritte = 0
        try:
            for elemento in documento["vulnerabilities"]:
                cve = elemento.get("cve") if isinstance(elemento, dict) else None
                if cve and store_cve(cve):
                    scritte += 1
        except Exception as errore:  # noqa: BLE001
            _fine_sync(sync_id, "error", scritte, str(errore))
            raise
        _fine_sync(sync_id, "ok", scritte, "importazione da file %s" % nome[:120])
        log_event("threat.sync", "Catalogo NVD importato da file %s: %d CVE"
                                 % (nome[:80], scritte),
                  severity="info", entity="threat")
        return {"cve": scritte}
    raise SourceError("Il file non contiene nessuno dei formati previsti.")


# --------------------------------------------------------------------------- #
# Esecuzione in secondo piano
# --------------------------------------------------------------------------- #
_thread: threading.Thread | None = None


def start_background(app, operazione: str, tenant_id: int = None,
                     requested_by=None, giorni: int = None) -> bool:
    """Avvia un aggiornamento in un thread. Un solo aggiornamento per volta.

    L'interrogazione della NVD per l'inventario dura minuti (una richiesta ogni sei
    secondi e mezzo): tenerla dentro una richiesta web significherebbe una pagina che
    resta appesa e un timeout del proxy.
    """
    global _thread
    if _thread is not None and _thread.is_alive():
        return False
    if running_sync() is not None:
        return False

    def giro():
        with app.app_context():
            try:
                if operazione == "targeted":
                    sync_targeted(tenant_id, requested_by)
                elif operazione == "window":
                    sync_window(giorni, requested_by)
                elif operazione == "kev":
                    sync_kev(requested_by)
                elif operazione == "cwe":
                    sync_cwe(requested_by)
                elif operazione == "attack":
                    sync_attack(requested_by)
                elif operazione == "tutto":
                    sync_kev(requested_by)
                    sync_cwe(requested_by)
                    sync_attack(requested_by)
                    sync_targeted(tenant_id, requested_by)
                else:
                    app.logger.warning("Aggiornamento non previsto: %s", operazione)
            except Exception as errore:  # noqa: BLE001 - l'esito e' nel registro
                app.logger.warning("Aggiornamento del catalogo non riuscito: %s", errore)

    _thread = threading.Thread(target=giro, name="snap-threat", daemon=True)
    _thread.start()
    return True
