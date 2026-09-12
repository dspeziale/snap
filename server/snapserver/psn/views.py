# -----------------------------------------------------------------
# psn/views.py — le pagine del sottosistema PSN
# Autore: Daniele Speziale
# Data creazione: 2026-09-11
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Pagine del piano di indirizzamento PSN.

Il piano e' un documento UNICO, non un dato per tenant: descrive l'infrastruttura
del Polo, che e' la stessa per tutti. Non c'e' quindi un filtro per tenant, e
proprio per questo la lettura e' riservata agli ANALISTI e l'importazione
all'amministratore di sistema: un piano di indirizzamento e' la mappa di come
entrare in una rete.

remarks: Autore: Daniele Speziale - Data: 2026-09-11
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import ipaddress
import json
import re

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from ..audit import log_event
from ..security import ROLE_ANALYST, ROLE_SUPERADMIN, login_required, role_required
from . import analysis
from . import db as psn_db
from .importer import importa
from .xlsx import XlsxNonValido

bp = Blueprint("psn", __name__, url_prefix="/psn")

# Tetto sul file caricato: il piano reale pesa meno di un megabyte. Dieci e' un
# margine larghissimo, e serve a non far entrare in memoria un file qualunque.
MAX_UPLOAD_BYTES = 10 * 1024 * 1024

ETICHETTE_RISCONTRI = {
    "duplicate_hostname": "Hostname duplicati",
    "duplicate_ip": "Indirizzi in due subnet",
    "overlap": "Subnet sovrapposte",
    "outside_subnet": "Indirizzi fuori dalla propria subnet",
    "outside_supernet": "Subnet fuori dalla propria supernet",
    "naming": "Nomi fuori dalla forma prevista",
    "naming_vocabulary": "Sigle usate ma non dichiarate nella convenzione",
    "rename_pending": "Rinomine in sospeso",
    "orphan_tenant": "Database senza tenant in anagrafica",
    "dangling_reference": "Riferimenti senza riga nel piano",
    "no_cidr": "Subnet senza CIDR",
    "bad_hostname": "Segnaposto nella colonna hostname",
}


@bp.teardown_app_request
def _chiudi(errore):
    psn_db.chiudi(errore)


def _ultimo_import(esplicito=None):
    """Il conferimento da mostrare: quello chiesto, altrimenti il piu' recente."""
    if esplicito:
        riga = psn_db.query("SELECT * FROM psn_import WHERE id = ?",
                            (int(esplicito),), one=True)
        if riga is None:
            abort(404)
        return riga
    return psn_db.query(
        "SELECT * FROM psn_import ORDER BY imported_at DESC, id DESC LIMIT 1",
        (), one=True)


def _import_richiesto():
    grezzo = (request.args.get("piano") or "").strip()
    return _ultimo_import(grezzo if grezzo.isdigit() else None)


def _elenco_import():
    return psn_db.query(
        "SELECT id, file_name, version, imported_at, counts_json FROM psn_import"
        " ORDER BY imported_at DESC, id DESC")


# --------------------------------------------------------------------------- #
# Quadro d'insieme
# --------------------------------------------------------------------------- #
@bp.get("/")
@role_required(ROLE_ANALYST)
def index():
    piano = _import_richiesto()
    if piano is None:
        return render_template("psn/vuoto.html")

    riscontri = psn_db.query(
        "SELECT kind, severity, count(*) AS quanti FROM psn_finding"
        " WHERE import_id = ? GROUP BY kind, severity ORDER BY 3 DESC",
        (piano["id"],))
    occupazione = analysis.occupazione(int(piano["id"]))
    # Le subnet piu' piene per prime: e' la coda del lavoro di chi deve assegnare
    # un indirizzo nuovo.
    piene = sorted((v for v in occupazione if v["totale"]),
                   key=lambda v: -v["percentuale"])[:8]
    totali = {
        "subnet": len(occupazione),
        "indirizzi": sum(v["totale"] for v in occupazione),
        "assegnati": sum(int(v["assegnati"] or 0) for v in occupazione),
        "riservati": sum(int(v["riservati"] or 0) for v in occupazione),
        "liberi": sum(int(v["liberi"] or 0) for v in occupazione),
    }
    per_ambiente = {}
    for voce in occupazione:
        chiave = voce.get("environment") or "non dichiarato"
        gruppo = per_ambiente.setdefault(
            chiave, {"subnet": 0, "assegnati": 0, "totale": 0})
        gruppo["subnet"] += 1
        gruppo["assegnati"] += int(voce["assegnati"] or 0)
        gruppo["totale"] += int(voce["totale"] or 0)

    return render_template(
        "psn/index.html", piano=piano, piani=_elenco_import(),
        riscontri=riscontri, totali=totali, piene=piene,
        per_ambiente=sorted(per_ambiente.items()),
        etichette=ETICHETTE_RISCONTRI,
        conteggi=json.loads(piano["counts_json"] or "{}"),
        avvisi=json.loads(piano["warnings_json"] or "[]"),
        sezioni=psn_db.query(
            "SELECT * FROM psn_section WHERE import_id = ? ORDER BY position",
            (piano["id"],)))


# --------------------------------------------------------------------------- #
# Subnet e indirizzi
# --------------------------------------------------------------------------- #
@bp.get("/subnet")
@role_required(ROLE_ANALYST)
def subnets():
    piano = _import_richiesto()
    if piano is None:
        return render_template("psn/vuoto.html")
    return render_template("psn/subnet.html", piano=piano, piani=_elenco_import(),
                           subnet=analysis.occupazione(int(piano["id"])))


@bp.get("/subnet/<int:subnet_id>")
@role_required(ROLE_ANALYST)
def subnet(subnet_id: int):
    riga = psn_db.query(
        "SELECT s.*, z.title AS section_title, z.supernet, z.environment,"
        " z.criticality FROM psn_subnet s"
        " LEFT JOIN psn_section z ON z.id = s.section_id WHERE s.id = ?",
        (subnet_id,), one=True)
    if riga is None:
        abort(404)
    indirizzi = psn_db.query(
        "SELECT * FROM psn_address WHERE subnet_id = ? ORDER BY ip_sort",
        (subnet_id,))
    riscontri = psn_db.query(
        "SELECT * FROM psn_finding WHERE subnet_id = ? ORDER BY severity, id",
        (subnet_id,))
    # I riferimenti che entrano in questa subnet e quelli che ne escono: e' la
    # ragione per cui il grafo esiste.
    identificativi = [int(v["id"]) for v in indirizzi] or [0]
    segnaposto = ",".join("?" * len(identificativi))
    uscenti = psn_db.query(
        "SELECT r.*, a.ip AS target_ip, a.hostname AS target_host,"
        " s.code AS target_subnet FROM psn_reference r"
        " LEFT JOIN psn_address a ON a.id = r.address_id"
        " LEFT JOIN psn_subnet s ON s.id = a.subnet_id"
        " WHERE r.from_kind = 'address' AND r.from_id IN (%s)" % segnaposto,
        tuple(identificativi))
    entranti = psn_db.query(
        "SELECT r.*, a.ip AS from_ip, a.hostname AS from_host,"
        " s.code AS from_subnet FROM psn_reference r"
        " LEFT JOIN psn_address a ON a.id = r.from_id AND r.from_kind = 'address'"
        " LEFT JOIN psn_subnet s ON s.id = a.subnet_id"
        " WHERE r.address_id IN (%s)" % segnaposto, tuple(identificativi))
    return render_template("psn/subnet_dettaglio.html", subnet=riga,
                           indirizzi=indirizzi, riscontri=riscontri,
                           uscenti=uscenti, entranti=entranti,
                           prossimo_libero=_prossimo_libero(indirizzi))


def _prossimo_libero(indirizzi) -> str:
    for voce in indirizzi:
        if voce["state"] == "libero":
            return voce["ip"]
    return ""


# --------------------------------------------------------------------------- #
# Tenant, database, servizi
# --------------------------------------------------------------------------- #
@bp.get("/tenant")
@role_required(ROLE_ANALYST)
def tenants():
    piano = _import_richiesto()
    if piano is None:
        return render_template("psn/vuoto.html")
    righe = psn_db.query(
        "SELECT t.*, (SELECT count(*) FROM psn_database d"
        "   WHERE d.import_id = t.import_id AND d.tenant_tgu = t.tgu) AS database_count"
        " FROM psn_tenant t WHERE t.import_id = ? ORDER BY t.zone, t.name",
        (piano["id"],))
    return render_template("psn/tenant.html", piano=piano, piani=_elenco_import(),
                           tenant=righe)


@bp.get("/database")
@role_required(ROLE_ANALYST)
def databases():
    piano = _import_richiesto()
    if piano is None:
        return render_template("psn/vuoto.html")
    righe = psn_db.query(
        "SELECT d.*, t.name AS tenant_name, t.zone AS tenant_zone"
        " FROM psn_database d"
        " LEFT JOIN psn_tenant t ON t.import_id = d.import_id AND t.tgu = d.tenant_tgu"
        " WHERE d.import_id = ? ORDER BY d.kind, d.service_name", (piano["id"],))
    return render_template("psn/database.html", piano=piano, piani=_elenco_import(),
                           database=righe)


@bp.get("/servizi")
@role_required(ROLE_ANALYST)
def services():
    piano = _import_richiesto()
    if piano is None:
        return render_template("psn/vuoto.html")
    righe = psn_db.query(
        "SELECT * FROM psn_service WHERE import_id = ? ORDER BY source, label",
        (piano["id"],))
    # La catena: per ogni backend citato si cerca la riga del piano, cosi' da un URL
    # si arriva all'apparato.
    catena = {}
    for riga in righe:
        indirizzi = [v for v in (riga["backends"] or "").split(",") if v]
        if not indirizzi:
            continue
        segnaposto = ",".join("?" * len(indirizzi))
        catena[int(riga["id"])] = psn_db.query(
            "SELECT a.id, a.ip, a.hostname, s.code, s.name FROM psn_address a"
            " JOIN psn_subnet s ON s.id = a.subnet_id"
            " WHERE a.import_id = ? AND a.ip IN (%s)" % segnaposto,
            tuple([piano["id"]] + indirizzi))
    return render_template("psn/servizi.html", piano=piano, piani=_elenco_import(),
                           servizi=righe, catena=catena)


# --------------------------------------------------------------------------- #
# Riscontri
# --------------------------------------------------------------------------- #
@bp.get("/riscontri")
@role_required(ROLE_ANALYST)
def findings():
    piano = _import_richiesto()
    if piano is None:
        return render_template("psn/vuoto.html")
    genere = (request.args.get("genere") or "").strip()
    if genere and genere not in ETICHETTE_RISCONTRI:
        genere = ""
    if genere:
        righe = psn_db.query(
            "SELECT f.*, s.code AS subnet_code FROM psn_finding f"
            " LEFT JOIN psn_subnet s ON s.id = f.subnet_id"
            " WHERE f.import_id = ? AND f.kind = ? ORDER BY f.severity, f.id",
            (piano["id"], genere))
    else:
        righe = psn_db.query(
            "SELECT f.*, s.code AS subnet_code FROM psn_finding f"
            " LEFT JOIN psn_subnet s ON s.id = f.subnet_id"
            " WHERE f.import_id = ? ORDER BY"
            " CASE f.severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1"
            " ELSE 2 END, f.kind, f.id", (piano["id"],))
    per_genere = psn_db.query(
        "SELECT kind, count(*) AS quanti FROM psn_finding WHERE import_id = ?"
        " GROUP BY kind ORDER BY 2 DESC", (piano["id"],))
    return render_template("psn/riscontri.html", piano=piano, piani=_elenco_import(),
                           riscontri=righe, per_genere=per_genere, genere=genere,
                           etichette=ETICHETTE_RISCONTRI)


# --------------------------------------------------------------------------- #
# Ricerca: un indirizzo, un nome, un servizio
# --------------------------------------------------------------------------- #
@bp.get("/cerca")
@role_required(ROLE_ANALYST)
def search():
    piano = _import_richiesto()
    testo = (request.args.get("q") or "").strip()
    esiti = {"indirizzi": [], "subnet": [], "tenant": [], "database": [],
             "servizi": [], "riferimenti": []}
    if piano is not None and len(testo) >= 2:
        like = "%" + testo.replace("%", "") + "%"
        esiti["indirizzi"] = psn_db.query(
            "SELECT a.*, s.code, s.name AS subnet_name FROM psn_address a"
            " JOIN psn_subnet s ON s.id = a.subnet_id"
            " WHERE a.import_id = ? AND (a.ip LIKE ? OR a.hostname ILIKE ?"
            "   OR a.old_hostname ILIKE ? OR a.description ILIKE ?)"
            " ORDER BY a.ip_sort LIMIT 200",
            (piano["id"], like, like, like, like))
        esiti["subnet"] = psn_db.query(
            "SELECT * FROM psn_subnet WHERE import_id = ?"
            " AND (code LIKE ? OR name ILIKE ? OR cidr LIKE ?) ORDER BY code",
            (piano["id"], like, like, like))
        esiti["tenant"] = psn_db.query(
            "SELECT * FROM psn_tenant WHERE import_id = ?"
            " AND (tgu ILIKE ? OR tgu_raw ILIKE ? OR name ILIKE ?)",
            (piano["id"], like, like, like))
        esiti["database"] = psn_db.query(
            "SELECT * FROM psn_database WHERE import_id = ?"
            " AND (service_name ILIKE ? OR pdb ILIKE ? OR db_unique_name ILIKE ?"
            "   OR ip_tenant LIKE ? OR ip_sed LIKE ?)",
            (piano["id"], like, like, like, like, like))
        esiti["servizi"] = psn_db.query(
            "SELECT * FROM psn_service WHERE import_id = ?"
            " AND (label ILIKE ? OR url ILIKE ? OR vip LIKE ? OR backends LIKE ?)",
            (piano["id"], like, like, like, like))
        # Se il testo e' un indirizzo, si cerca anche la subnet che lo CONTIENE:
        # e' la domanda vera di chi ha in mano un indirizzo e non sa di chi sia.
        contenuto = _subnet_che_contiene(int(piano["id"]), testo)
        if contenuto:
            esiti["subnet"] = list(esiti["subnet"]) + [
                v for v in contenuto
                if all(int(v["id"]) != int(x["id"]) for x in esiti["subnet"])]
    return render_template("psn/cerca.html", piano=piano, piani=_elenco_import(),
                           q=testo, esiti=esiti)


def _subnet_che_contiene(import_id: int, testo: str) -> list:
    try:
        indirizzo = ipaddress.ip_address(testo)
    except ValueError:
        return []
    trovate = []
    for riga in psn_db.query(
            "SELECT * FROM psn_subnet WHERE import_id = ? AND cidr <> ''",
            (import_id,)):
        try:
            if indirizzo in ipaddress.ip_network(riga["cidr"], strict=False):
                trovate.append(riga)
        except ValueError:
            continue
    return trovate


# --------------------------------------------------------------------------- #
# Conferimenti: importazione e confronto fra versioni
# --------------------------------------------------------------------------- #
@bp.get("/conferimenti")
@role_required(ROLE_ANALYST)
def imports():
    piani = _elenco_import()
    confronti = []
    if len(piani) >= 2:
        confronti = _confronta(int(piani[1]["id"]), int(piani[0]["id"]))
    return render_template("psn/conferimenti.html", piani=piani,
                           piano=piani[0] if piani else None,
                           confronti=confronti,
                           conteggi=[json.loads(p["counts_json"] or "{}")
                                     for p in piani])


def _confronta(vecchio: int, nuovo: int) -> list:
    """Che cosa e' cambiato fra due versioni del piano.

    E' la domanda a cui un foglio non risponde MAI: due file con lo stesso aspetto,
    e diciottomila righe da confrontare a mano.
    """
    def indice(import_id: int) -> dict:
        return {"%s|%s" % (r["ip"], r["code"]): r for r in psn_db.query(
            "SELECT a.ip, a.hostname, a.description, a.state, s.code"
            " FROM psn_address a JOIN psn_subnet s ON s.id = a.subnet_id"
            " WHERE a.import_id = ?", (import_id,))}

    prima, dopo = indice(vecchio), indice(nuovo)
    cambi = []
    for chiave, riga in dopo.items():
        vecchia = prima.get(chiave)
        if vecchia is None:
            if riga["hostname"] or riga["description"]:
                cambi.append({"tipo": "nuovo", "ip": riga["ip"],
                              "subnet": riga["code"], "prima": "",
                              "dopo": riga["hostname"] or riga["description"]})
            continue
        if (vecchia["hostname"] or "") != (riga["hostname"] or ""):
            cambi.append({"tipo": "hostname", "ip": riga["ip"],
                          "subnet": riga["code"], "prima": vecchia["hostname"],
                          "dopo": riga["hostname"]})
        elif (vecchia["state"] or "") != (riga["state"] or ""):
            cambi.append({"tipo": "stato", "ip": riga["ip"],
                          "subnet": riga["code"], "prima": vecchia["state"],
                          "dopo": riga["state"]})
    for chiave, riga in prima.items():
        if chiave not in dopo and (riga["hostname"] or riga["description"]):
            cambi.append({"tipo": "rimosso", "ip": riga["ip"],
                          "subnet": riga["code"],
                          "prima": riga["hostname"] or riga["description"],
                          "dopo": ""})
    cambi.sort(key=lambda v: (v["subnet"], v["ip"]))
    return cambi


@bp.get("/importa")
@role_required(ROLE_SUPERADMIN)
def import_form():
    return render_template("psn/importa.html", piani=_elenco_import(),
                           piano=_ultimo_import())


@bp.post("/importa")
@role_required(ROLE_SUPERADMIN)
def import_run():
    file = request.files.get("piano")
    if file is None or not (file.filename or "").strip():
        flash("Nessun file scelto.", "warning")
        return redirect(url_for("psn.import_form"))
    nome = re.sub(r"[^\w .()-]", "_", (file.filename or "").strip())[:200]
    if not nome.lower().endswith((".xlsx", ".xlsm")):
        flash("Il piano si importa da un file .xlsx: %r non lo e'." % nome,
              "warning")
        return redirect(url_for("psn.import_form"))

    dati = file.read(MAX_UPLOAD_BYTES + 1)
    if len(dati) > MAX_UPLOAD_BYTES:
        flash("Il file supera %d MB: rifiutato." % (MAX_UPLOAD_BYTES // (1024 * 1024)),
              "warning")
        return redirect(url_for("psn.import_form"))

    import io as _io
    try:
        esito = importa(_io.BytesIO(dati), nome,
                        utente=(g.user or {}).get("email", ""))
    except XlsxNonValido as errore:
        psn_db.rollback()
        flash("Il file non e' un piano leggibile: %s" % errore, "danger")
        return redirect(url_for("psn.import_form"))
    except Exception as errore:  # noqa: BLE001 - si dichiara e non si perde la sessione
        psn_db.rollback()
        current_app.logger.exception("Importazione PSN non riuscita")
        flash("Importazione non riuscita: %s. Nessun dato e' stato scritto."
              % type(errore).__name__, "danger")
        return redirect(url_for("psn.import_form"))

    if not esito.conteggi:
        for avviso in esito.avvisi:
            flash(avviso, "secondary")
        return redirect(url_for("psn.index", piano=esito.import_id))

    riscontri = analysis.analizza(esito.import_id)
    log_event("psn.plan.imported",
              "Piano di indirizzamento PSN importato da %s: %s"
              % (nome, ", ".join("%s %d" % (k, v)
                                 for k, v in sorted(esito.conteggi.items()))),
              severity="info", entity="psn_import", entity_id=esito.import_id)
    flash("Piano importato: %s."
          % ", ".join("%s %d" % (k, v) for k, v in sorted(esito.conteggi.items())),
          "success")
    if riscontri:
        flash("Riscontri trovati: %s."
              % ", ".join("%s %d" % (ETICHETTE_RISCONTRI.get(k, k), v)
                          for k, v in sorted(riscontri.items())), "warning")
    for avviso in esito.avvisi:
        flash(avviso, "secondary")
    return redirect(url_for("psn.index", piano=esito.import_id))


@bp.post("/conferimenti/<int:import_id>/elimina")
@role_required(ROLE_SUPERADMIN)
def import_delete(import_id: int):
    """Elimina un conferimento e tutto cio' che ne dipende.

    La cascata dello schema fa il resto: un conferimento e' l'unita' di tutto il
    sottosistema, e buttarlo non lascia orfani.
    """
    riga = psn_db.query("SELECT * FROM psn_import WHERE id = ?", (import_id,),
                        one=True)
    if riga is None:
        abort(404)
    if (request.form.get("conferma") or "").strip() != riga["file_name"]:
        flash("Per eliminare un conferimento digitare esattamente il nome del file:"
              " %s." % riga["file_name"], "warning")
        return redirect(url_for("psn.imports"))
    psn_db.execute("DELETE FROM psn_import WHERE id = ?", (import_id,))
    psn_db.commit()
    log_event("psn.plan.deleted",
              "Conferimento del piano PSN %s eliminato" % riga["file_name"],
              severity="warning", entity="psn_import", entity_id=import_id)
    flash("Conferimento eliminato.", "info")
    return redirect(url_for("psn.imports"))
