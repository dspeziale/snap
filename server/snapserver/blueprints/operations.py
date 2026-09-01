"""
snap server - Sala operativa: quadro NOC, quadro SOC, ricerca nella base dati.

Tre pagine per tre modi di lavorare: chi tiene il turno (NOC), chi guarda la
superficie esposta (SOC), chi deve rispondere a una domanda precisa (ricerca).
Sono viste sul dato gia' raccolto: nessuna di queste pagine avvia scansioni o
contatta le sonde.

remarks: Autore: Daniele Speziale - Data: 2026-08-29
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import csv
import io

from flask import Response, render_template, request

from ..audit import log_event
from ..operations import noc_board, soc_board
from ..searchdb import (MAX_RIGHE_CSV, SAVED_BY_KEY, SAVED_QUERIES, global_search,
                        run_saved)
from ..security import login_required
from ..tenancy import current_tenant_id

from flask import Blueprint  # noqa: E402  (dopo gli altri, per leggibilita')

bp = Blueprint("operations", __name__, url_prefix="/ops")

# Finestre offerte al SOC. Sette giorni e' la settimana di lavoro; ventiquattr'ore
# risponde a "che cosa e' successo stanotte"; trenta serve a distinguere una novita'
# da un'abitudine.
FINESTRE_SOC = (1, 7, 30)


@bp.get("/noc")
@login_required
def noc():
    """Quadro del turno: che cosa non funziona adesso, che cosa balla, chi tace."""
    return render_template("operations/noc.html", board=noc_board(current_tenant_id()))


@bp.get("/soc")
@login_required
def soc():
    """Quadro della sicurezza: prima le variazioni, poi lo stato."""
    giorni = request.args.get("giorni", type=int)
    if giorni not in FINESTRE_SOC:
        giorni = 7
    return render_template(
        "operations/soc.html",
        board=soc_board(current_tenant_id(), giorni=giorni),
        finestre=FINESTRE_SOC,
    )


@bp.get("/search")
@login_required
def search():
    """Ricerca libera e interrogazioni pronte."""
    tenant_id = current_tenant_id()
    testo = (request.args.get("q") or "").strip()
    chiave = (request.args.get("pronta") or "").strip()

    risultati = global_search(tenant_id, testo) if testo else None
    pronta = run_saved(tenant_id, chiave) if chiave in SAVED_BY_KEY else None
    return render_template(
        "operations/search.html",
        testo=testo,
        risultati=risultati,
        pronte=SAVED_QUERIES,
        pronta=pronta,
    )


@bp.get("/search/export/<chiave>")
@login_required
def export_saved(chiave: str):
    """Esporta in CSV l'esito di un'interrogazione pronta.

    Un CSV si apre in un foglio di calcolo e finisce in una cartella condivisa: puo'
    contenere indirizzi e nomi host, che sono dati personali quando identificano una
    persona (GDPR art. 4). L'esportazione e' quindi **tracciata** nel registro, con
    chi l'ha chiesta e quante righe ha portato via.
    """
    tenant_id = current_tenant_id()
    esito = run_saved(tenant_id, chiave, limit=MAX_RIGHE_CSV)
    if not esito:
        return Response("interrogazione non prevista", status=404, mimetype="text/plain")

    memoria = io.StringIO()
    # Punto e virgola: e' il separatore che un foglio di calcolo italiano si aspetta,
    # e senza di quello ogni riga finisce in una cella sola.
    scrittore = csv.writer(memoria, delimiter=";", quoting=csv.QUOTE_MINIMAL,
                           lineterminator="\r\n")
    scrittore.writerow(esito["colonne"])
    for riga in esito["righe"]:
        scrittore.writerow(["" if c is None else c for c in riga])

    log_event("search.exported",
              "Esportazione CSV dell'interrogazione \"%s\": %d righe"
              % (esito["titolo"], len(esito["righe"])),
              tenant_id=tenant_id, severity="info", entity="search",
              entity_id=chiave)

    contenuto = "﻿" + memoria.getvalue()  # BOM: i fogli di calcolo leggono UTF-8
    return Response(
        contenuto,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="snap-%s.csv"' % chiave},
    )
