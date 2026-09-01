"""
snap server - Generazione di un report: un solo punto di ingresso per tutti i generi.

Aggiungere un report e' una dichiarazione: si scrive la funzione che raccoglie i dati,
quella che li impagina, e si aggiunge una riga a GENERATORI. Il resto -- finestra nel
fuso del tenant, percorso del file, registrazione, audit, chiave del periodo -- e'
comune, perche' sette report scritti sette volte diventano sette manutenzioni.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from datetime import date

from ..audit import log_event
from . import (
    KIND_COMPLIANCE,
    KIND_EXECUTIVE,
    KIND_EU_COMPLIANCE,
    KIND_INCIDENT,
    KIND_INVENTORY,
    KIND_NOC,
    KIND_DEVICE,
    KIND_HYGIENE,
    KIND_SEGMENTATION,
    KIND_SOC,
    KIND_THREAT,
    REPORT_CATALOG,
    REPORT_KINDS,
)
from . import dataset, dataset_wide, eu_compliance, render_eu, render_pdf, \
    render_wide, storage
from .windows import day_bounds, days_bounds, period_key, zone_of


class ReportError(RuntimeError):
    """Il report non si puo' produrre. Il messaggio e' per l'operatore."""


def _dati_noc(tenant, zona, giorno, giorni):
    # Il NOC su piu' giorni resta il documento di una giornata: la finestra piu' larga
    # serve alle tendenze, non a mescolare due giornate in una disponibilita' sola.
    return dataset.daily(tenant, giorno, zona, giorni_tendenza=max(2, giorni))


GENERATORI = {
    KIND_NOC: (_dati_noc, render_pdf.noc_report),
    KIND_EXECUTIVE: (dataset_wide.executive, render_wide.executive_report),
    KIND_INVENTORY: (dataset_wide.inventory, render_wide.inventory_report),
    KIND_SOC: (dataset_wide.soc, render_wide.soc_report),
    KIND_THREAT: (dataset_wide.threat, render_wide.threat_report),
    KIND_SEGMENTATION: (dataset_wide.segmentation,
                        render_wide.segmentation_report),
    KIND_HYGIENE: (dataset_wide.hygiene_pack, render_wide.hygiene_report),
    KIND_COMPLIANCE: (dataset_wide.compliance_pack, render_wide.compliance_report),
    KIND_EU_COMPLIANCE: (eu_compliance.pacchetto, render_eu.eu_compliance_report),
}


def default_days(kind: str) -> int:
    voce = REPORT_CATALOG.get(kind) or {}
    return int(voce.get("periodo") or 1)


def allowed_days(kind: str) -> tuple:
    voce = REPORT_CATALOG.get(kind) or {}
    return tuple(voce.get("periodi") or (default_days(kind),))


def validate_days(kind: str, valore) -> int:
    """Ampiezza del periodo. Solo i valori offerti dal catalogo: un intervallo
    arbitrario renderebbe impossibile confrontare due edizioni dello stesso report."""
    consentiti = allowed_days(kind)
    if valore in (None, ""):
        return default_days(kind)
    try:
        giorni = int(valore)
    except (TypeError, ValueError) as errore:
        raise ReportError("Ampiezza del periodo non valida.") from errore
    if giorni not in consentiti:
        raise ReportError("Per questo report l'ampiezza puo' essere: %s giorni."
                          % ", ".join(str(g) for g in consentiti))
    return giorni


def generate(kind: str, tenant: dict, giorno: date, giorni: int = None,
             requested_by: int = None) -> str:
    """Produce il report indicato e lo registra. Restituisce il percorso del file."""
    if kind not in GENERATORI:
        raise ReportError("Genere di report non previsto: %r" % kind)

    zona = zone_of(tenant)
    giorni = validate_days(kind, giorni)
    raccogli, impagina = GENERATORI[kind]
    dati = raccogli(tenant, zona, giorno, giorni)

    percorso = storage.file_for(tenant["code"], kind, giorno)
    if giorni > 1:
        # Due edizioni dello stesso giorno con ampiezza diversa sono due documenti.
        percorso = percorso.with_name(percorso.stem + "-%dg" % giorni + percorso.suffix)

    if kind == KIND_NOC:
        impagina(percorso, dati, {"sonde": ", ".join(
            "%s (sforzo %s)" % (s["nome"], s["sforzo"])
            for s in dati["raccolta"]["sonde"])})
    else:
        impagina(percorso, dati)

    inizio, fine = (day_bounds(zona, giorno) if giorni == 1
                    else days_bounds(zona, giorni, fino_a=giorno))
    storage.register(
        int(tenant["id"]), kind, period_key(kind, giorno, giorni), inizio, fine,
        file_path=percorso, file_bytes=percorso.stat().st_size,
        requested_by=requested_by)
    log_event("report.generated",
              "%s generato per il periodo di %d giorni al %s (%s)"
              % (REPORT_KINDS.get(kind, kind), giorni, giorno.strftime("%d/%m/%Y"),
                 percorso.name),
              tenant_id=int(tenant["id"]), severity="info", entity="report")
    return str(percorso)


def generate_device(tenant: dict, node_id: int, requested_by: int = None) -> str:
    """Scheda di un singolo apparato: il periodo non c'entra, il soggetto si'.

    Come il rapporto di incidente, non ha una finestra temporale ma un oggetto: il
    documento e' la fotografia di cio' che si sa di quel dispositivo adesso.
    """
    zona = zone_of(tenant)
    try:
        dati = dataset_wide.device_sheet(tenant, zona, node_id)
    except ValueError as errore:
        raise ReportError(str(errore)) from errore

    nodo = dati["nodo"]
    percorso = storage.file_for(tenant["code"], KIND_DEVICE, date.today())
    percorso = percorso.with_name(
        percorso.stem + "-" + str(nodo["ip"]).replace(".", "-") + percorso.suffix)
    render_wide.device_report(percorso, dati)

    inizio, fine = day_bounds(zona, date.today())
    storage.register(
        int(tenant["id"]), KIND_DEVICE, "device-%s" % node_id, inizio, fine,
        file_path=percorso, file_bytes=percorso.stat().st_size,
        requested_by=requested_by)
    log_event("report.generated",
              "Scheda dell'apparato %s (%s)" % (nodo["ip"], percorso.name),
              tenant_id=int(tenant["id"]), severity="info", entity="report")
    return str(percorso)


def generate_incident(tenant: dict, incident_id: int, requested_by: int = None) -> str:
    """Rapporto di un singolo incidente: il periodo e' l'incidente stesso."""
    zona = zone_of(tenant)
    try:
        dati = dataset_wide.incident_pack(tenant, zona, incident_id)
    except ValueError as errore:
        raise ReportError(str(errore)) from errore

    quando = dati["incidente"].get("opened_at") or ""
    giorno = date.fromisoformat(quando[:10]) if quando[:10] else date.today()
    percorso = storage.file_for(tenant["code"], KIND_INCIDENT, giorno)
    percorso = percorso.with_name(percorso.stem + "-%d" % incident_id + percorso.suffix)
    render_wide.incident_report(percorso, dati)

    storage.register(
        int(tenant["id"]), KIND_INCIDENT, "%s:%d" % (KIND_INCIDENT, incident_id),
        dati["inizio_utc"], dati["fine_utc"], file_path=percorso,
        file_bytes=percorso.stat().st_size, requested_by=requested_by)
    log_event("report.generated",
              "Rapporto dell'incidente #%d generato (%s)"
              % (incident_id, percorso.name),
              tenant_id=int(tenant["id"]), severity="info", entity="report",
              entity_id=incident_id)
    return str(percorso)
