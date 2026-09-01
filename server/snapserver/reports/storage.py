"""
snap server - Archiviazione dei report prodotti.

Perche' si conservano invece di rigenerarli a richiesta: il dato sorgente scade per
conservazione (`tenants.retention_days`), il report no. Un documento che ha
accompagnato una decisione deve poter essere riletto anche quando gli esiti su cui era
costruito non ci sono piu' (RP-09).

Lo scaricamento avviene per identificativo e mai per percorso: un percorso che arriva
dalla richiesta e' una risalita di cartelle che aspetta di succedere.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from pathlib import Path

from flask import current_app

from ..db import execute, query, utc_now_str

STATO_OK = "ok"
STATO_ERRORE = "error"


def base_dir() -> Path:
    """Cartella radice dei report, accanto al database."""
    configurata = current_app.config.get("REPORTS_DIR")
    if configurata:
        radice = Path(configurata)
    else:
        radice = Path(current_app.config["DATABASE"]).resolve().parent / "reports"
    radice.mkdir(parents=True, exist_ok=True)
    return radice


def file_for(tenant_code: str, kind: str, giorno) -> Path:
    """Percorso del file: una cartella per tenant, anno e mese.

    Un'unica cartella con migliaia di file rende impossibile qualunque intervento
    manuale, e la suddivisione per mese e' quella con cui si ragiona quando si cerca
    un documento.
    """
    codice = "".join(c for c in (tenant_code or "tenant") if c.isalnum() or c in "-_")
    cartella = base_dir() / (codice or "tenant") / giorno.strftime("%Y") / giorno.strftime("%m")
    cartella.mkdir(parents=True, exist_ok=True)
    return cartella / ("snap-%s-%s-%s.pdf" % (codice, kind, giorno.strftime("%Y%m%d")))


def existing(tenant_id: int, kind: str, period_key: str):
    return query(
        "SELECT * FROM report_runs WHERE tenant_id = ? AND kind = ? AND period_key = ?",
        (tenant_id, kind, period_key), one=True)


def register(tenant_id: int, kind: str, period_key: str, period_start: str,
             period_end: str, file_path=None, file_bytes: int = 0,
             status: str = STATO_OK, detail: str = "", notification_id: int = None,
             requested_by: int = None) -> int:
    """Registra il report prodotto. Sovrascrive la registrazione dello stesso periodo.

    L'indice unico su (tenant, genere, periodo) e' cio' che rende impossibile spedire
    due volte il resoconto dello stesso giorno, anche a fronte di riavvii: la garanzia
    sta nel database, non in una variabile di memoria.
    """
    adesso = utc_now_str()
    presente = existing(tenant_id, kind, period_key)
    if presente is not None:
        execute(
            "UPDATE report_runs SET period_start = ?, period_end = ?, file_path = ?,"
            " file_bytes = ?, status = ?, detail = ?, notification_id = ?,"
            " requested_by = ?, created_at = ? WHERE id = ?",
            (period_start, period_end, str(file_path) if file_path else None,
             int(file_bytes or 0), status, detail, notification_id, requested_by,
             adesso, int(presente["id"])))
        return int(presente["id"])
    return execute(
        "INSERT INTO report_runs (tenant_id, kind, period_key, period_start, period_end,"
        " file_path, file_bytes, status, detail, notification_id, requested_by, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (tenant_id, kind, period_key, period_start, period_end,
         str(file_path) if file_path else None, int(file_bytes or 0), status, detail,
         notification_id, requested_by, adesso))


def recent(tenant_id: int, limit: int = 100) -> list:
    righe = query(
        "SELECT r.*, u.full_name AS richiedente, n.status AS notifica_stato,"
        " n.recipients AS notifica_destinatari, n.channel AS notifica_canale"
        " FROM report_runs r"
        " LEFT JOIN users u ON u.id = r.requested_by"
        " LEFT JOIN notifications n ON n.id = r.notification_id"
        " WHERE r.tenant_id = ? ORDER BY r.created_at DESC, r.id DESC LIMIT ?",
        (tenant_id, int(limit)))
    voci = []
    for riga in righe:
        voce = dict(riga)
        percorso = voce.get("file_path")
        voce["presente"] = bool(percorso) and Path(percorso).is_file()
        voce["nome_file"] = Path(percorso).name if percorso else None
        voci.append(voce)
    return voci


def report_file(tenant_id: int, report_id: int) -> Path | None:
    """File di un report del tenant indicato, se esiste ancora su disco.

    Il confronto con la cartella radice non e' ridondante: un percorso conservato in
    archivio potrebbe essere stato scritto da una versione precedente, e un file fuori
    dalla cartella dei report non si serve.
    """
    riga = query("SELECT file_path FROM report_runs WHERE id = ? AND tenant_id = ?",
                 (report_id, tenant_id), one=True)
    if riga is None or not riga["file_path"]:
        return None
    percorso = Path(riga["file_path"]).resolve()
    radice = base_dir().resolve()
    if radice not in percorso.parents:
        current_app.logger.warning(
            "Report %s fuori dalla cartella dei report: %s", report_id, percorso)
        return None
    return percorso if percorso.is_file() else None


def remove(tenant_id: int, report_id: int) -> dict | None:
    """Elimina un report: prima il file, poi la riga d'archivio.

    In quest'ordine perche' se la cancellazione del file fallisce -- permessi, file
    aperto da un altro programma -- la riga resta, e l'archivio continua a dire il
    vero. Il contrario lascerebbe un PDF orfano che nessuna pagina mostra piu' e che
    nessuna retention cancellera'.
    """
    riga = query("SELECT * FROM report_runs WHERE id = ? AND tenant_id = ?",
                 (report_id, tenant_id), one=True)
    if riga is None:
        return None

    voce = dict(riga)
    percorso = report_file(tenant_id, report_id)
    voce["file_rimosso"] = False
    if percorso is not None:
        try:
            percorso.unlink()
            voce["file_rimosso"] = True
        except OSError as errore:
            # Non si nasconde: la riga resta e chi ha chiesto la cancellazione deve
            # saperlo, perche' lo spazio non si e' liberato.
            current_app.logger.warning("Report %s non cancellabile: %s",
                                       percorso, errore)
            voce["errore"] = str(errore)
            return voce

    execute("DELETE FROM report_runs WHERE id = ? AND tenant_id = ?",
            (report_id, tenant_id))
    return voce


def footprint(tenant_id: int = None) -> dict:
    """Quanto occupano i report conservati."""
    condizione = "" if tenant_id is None else " WHERE tenant_id = ?"
    parametri = () if tenant_id is None else (tenant_id,)
    riga = query(
        "SELECT COUNT(*) AS documenti, COALESCE(SUM(file_bytes), 0) AS byte"
        " FROM report_runs" + condizione, parametri, one=True)
    return {"documenti": int(riga["documenti"] or 0), "byte": int(riga["byte"] or 0)}
