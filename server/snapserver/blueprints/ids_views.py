# -----------------------------------------------------------------
# ids_views.py — le pagine dell'IDS e degli agenti di macchina
# Autore: Daniele Speziale
# Data creazione: 2026-09-13
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Quello che l'IDS ha notato, e le macchine che riferiscono.

TRE PAGINE, TRE DOMANDE
-----------------------
* **Rilevazioni** -- che cosa e' cambiato in un modo che riguarda la sicurezza. E' la
  pagina del turno: si guarda, si decide, si archivia con una nota.
* **Regole e sensori** -- che cosa il prodotto sa riconoscere, e soprattutto che cosa
  NON sta guardando. Un sensore non disponibile va dichiarato: il suo zero non e' un
  "tutto a posto", e' un "non guardato".
* **Agenti** -- le macchine che riferiscono di se', con le loro misure.

Le rilevazioni arrivano conferite dalle sonde: questa console non interroga nulla, e
mostra l'ultima cosa consegnata dichiarando quando e' arrivata.

remarks: Autore: Daniele Speziale - Data: 2026-09-13
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json

from flask import (Blueprint, flash, redirect, render_template, request,
                   url_for)

from ..audit import log_event
from ..db import days_ago_str, execute, query, scalar, utc_now_str
from ..security import login_required, role_required, ROLE_ANALYST
from ..tenancy import current_tenant_id

bp = Blueprint("ids", __name__, url_prefix="/ids")

# L'ordine in cui si guardano le cose: il piu' grave per primo. Non e' alfabetico e
# non e' cronologico -- una rilevazione critica di ieri conta piu' di una media di
# stamattina.
ORDINE_GRAVITA = ("critica", "alta", "media", "bassa", "info")

# Il catalogo delle regole vive sulla sonda (probe/snapprobe/ids.py): la console lo
# rispecchia per poter spiegare una rilevazione anche quando la sonda non e'
# raggiungibile. Sono gli stessi codici, e un test verifica che i due elenchi non
# divergano -- due cataloghi che si allontanano in silenzio sono peggio di uno solo
# incompleto.
REGOLE = {
    "ARP-MAC-CAMBIATO": ("Indirizzo con scheda di rete diversa", "alta", "T1557"),
    "ARP-MAC-MULTIPLO": ("Una scheda di rete su molti indirizzi", "media", "T1557"),
    "HOST-NUOVO": ("Dispositivo mai visto", "media", "T1200"),
    "PORTA-AMMINISTRAZIONE": ("Amministrazione comparsa", "alta", "T1021"),
    "PORTA-INSOLITA": ("Porta alta comparsa", "media", "T1571"),
    "SERVIZIO-SPARITO": ("Servizio scomparso", "media", "T1489"),
    "SMB1-RIACCESO": ("SMB 1.0 tornato attivo", "alta", "T1210"),
    "WIFI-NOTTURNO": ("Apparato senza fili in orario di chiusura", "media", "T1200"),
    "ACCESSI-FALLITI": ("Tentativi di accesso falliti", "alta", "T1110"),
    "UTENTE-NUOVO": ("Utenza nuova o promossa", "alta", "T1136"),
    "SICUREZZA-FERMA": ("Protezione disattivata", "critica", "T1562"),
    "ASCOLTO-NUOVO": ("Processo nuovo in ascolto", "alta", "T1571"),
    # Dal filo (sensore `traffico`): sono le uniche che vedono un attacco che non
    # lascia traccia su nessun host.
    "ARP-AVVELENAMENTO": ("Un indirizzo rivendicato da due schede", "critica",
                          "T1557.002"),
    "ARP-RAFFICA": ("Raffica di annunci ARP", "alta", "T1557.002"),
    "DHCP-ABUSIVO": ("Un server DHCP che non dovrebbe esserci", "critica", "T1557"),
    "NOME-AVVELENATO": ("Qualcuno risponde a nomi che non sono suoi", "alta",
                        "T1557.001"),
    "MAC-NUOVO-SUL-FILO": ("Una scheda di rete mai vista sul segmento", "media",
                           "T1200"),
    "SCANSIONE-INTERNA": ("Qualcuno sta scansionando dall'interno", "alta", "T1046"),
    "BEACONING": ("Qualcuno chiama casa a orologeria", "alta", "T1071"),
    "DNS-ANOMALO": ("Nomi che sembrano trasportare dati", "alta", "T1071.004"),
    "HTTP-IN-CHIARO": ("Traffico HTTP non cifrato", "bassa", "T1040"),
}

SENSORI = (
    {"codice": "inventario", "nome": "Osservazione dell'inventario",
     "descrizione": "Nodi, porte, indirizzi fisici, presenze senza fili e letture SMB"
                    " gia' raccolti dalle passate di scansione."},
    {"codice": "agenti", "nome": "Agenti di macchina",
     "descrizione": "Accessi, utenze, servizi di sicurezza e processi in ascolto"
                    " riferiti dalle macchine su cui l'agente e' installato."},
    # NON piu' "predisposto": esiste e funziona, ma nasce SPENTO. La differenza
    # conta per chi legge la pagina -- "predisposto" significa "non c'e' ancora",
    # "spento" significa "c'e', e qualcuno deve decidere di accenderlo".
    {"codice": "traffico", "nome": "Osservazione del traffico",
     "descrizione": "Intestazioni dei pacchetti e nomi dichiarati in chiaro (DNS,"
                    " SNI, Host HTTP). Riconosce avvelenamento ARP, DHCP abusivo,"
                    " avvelenamento dei nomi, scansioni interne, beaconing e tunnel"
                    " DNS. Non legge il contenuto. Si accende dalla Configurazione"
                    " della sonda, scegliendo l'interfaccia."},
)


# I gruppi che l'agente sa raccogliere. Come per le regole dell'IDS, il catalogo vive
# sull'agente (`agent/snap_agent.py`, `GRUPPI`) e la console lo rispecchia: serve a
# dire "non misurato" con il NOME della cosa che non si sta misurando, invece di un
# codice. Un test verifica che i due elenchi non divergano.
GRUPPI_AGENTE = {
    "identita": "Identita' della macchina",
    "carico": "Carico",
    "dischi": "Dischi",
    "rete": "Rete",
    "connessioni": "Connessioni",
    "processi": "Processi",
    "in_ascolto": "Porte in ascolto",
    "utenti": "Sessioni aperte",
    "utenze": "Utenze locali",
    "sicurezza": "Postura di sicurezza",
    "aggiornamenti": "Aggiornamenti",
    "software": "Software installato",
    "servizi": "Servizi",
    "pianificate": "Attivita' pianificate",
    "container": "Container in esecuzione",
}


def _conteggi(tenant_id: int) -> dict:
    righe = query(
        "SELECT gravita, stato, COUNT(*) AS quante FROM ids_findings"
        " WHERE tenant_id = ? GROUP BY gravita, stato", (tenant_id,))
    per_gravita, aperte = {}, 0
    for riga in righe:
        if riga["stato"] == "aperta":
            per_gravita[riga["gravita"]] = (per_gravita.get(riga["gravita"], 0)
                                            + int(riga["quante"]))
            aperte += int(riga["quante"])
    return {
        "per_gravita": [(g, per_gravita.get(g, 0)) for g in ORDINE_GRAVITA],
        "aperte": aperte,
        "ultime_24h": int(scalar(
            "SELECT COUNT(*) FROM ids_findings WHERE tenant_id = ? AND ultima_at >= ?",
            (tenant_id, days_ago_str(1))) or 0),
        "archiviate": int(scalar(
            "SELECT COUNT(*) FROM ids_findings WHERE tenant_id = ? AND stato = 'archiviata'",
            (tenant_id,)) or 0),
    }


def _stato_sonde(tenant_id: int) -> list:
    """Che cosa le sonde hanno dichiarato dell'IDS nell'ultimo battito.

    La console non interroga le sonde -- non puo': stanno dietro NAT e parlano solo
    in uscita. Lo stato del motore arriva insieme al battito e qui si rispecchia,
    dichiarando l'istante in cui e' stato composto.
    """
    sonde = []
    for riga in query(
            "SELECT code, name, agent_version, console_json, console_at FROM probes"
            " WHERE tenant_id = ? AND revoked_at IS NULL ORDER BY code", (tenant_id,)):
        sonda = dict(riga)
        try:
            consolle = json.loads(sonda.get("console_json") or "{}")
        except (TypeError, ValueError):
            consolle = {}
        sonda["ids"] = (consolle or {}).get("ids") or {}
        sonde.append(sonda)
    return sonde


def _in_apprendimento(sonde: list) -> list:
    """Le sonde la cui memoria e' ancora troppo giovane per giudicare.

    Serve a non far leggere uno zero come una buona notizia: finche' l'archivio di
    cio' che era normale e' giovane, le regole che si fondano sull'assenza di memoria
    non possono scattare, e il silenzio e' un motore che sta ancora imparando.
    """
    giovani = []
    for sonda in sonde:
        memoria = (sonda.get("ids") or {}).get("memoria") or {}
        if memoria and not memoria.get("matura"):
            giovani.append({"code": sonda["code"],
                            "ore": memoria.get("ore", 0),
                            "soggetti": memoria.get("soggetti", 0)})
    return giovani


@bp.get("/")
@login_required
def index():
    """Le rilevazioni, le piu' gravi per prime."""
    tenant_id = current_tenant_id()
    stato = request.args.get("stato") or "aperta"
    gravita = request.args.get("gravita") or ""

    condizioni = ["f.tenant_id = ?"]
    parametri = [tenant_id]
    if stato in ("aperta", "archiviata"):
        condizioni.append("f.stato = ?")
        parametri.append(stato)
    if gravita in ORDINE_GRAVITA:
        condizioni.append("f.gravita = ?")
        parametri.append(gravita)

    righe = query(
        "SELECT f.*, n.hostname, n.device_label, p.code AS sonda"
        " FROM ids_findings f"
        " LEFT JOIN nodes n ON n.id = f.node_id"
        " LEFT JOIN probes p ON p.id = f.probe_id"
        " WHERE " + " AND ".join(condizioni) +
        # L'ordine e' la gravita', non il tempo: una rilevazione critica di ieri conta
        # piu' di una media di stamattina.
        " ORDER BY CASE f.gravita WHEN 'critica' THEN 0 WHEN 'alta' THEN 1"
        " WHEN 'media' THEN 2 WHEN 'bassa' THEN 3 ELSE 4 END, f.ultima_at DESC"
        " LIMIT 300", tuple(parametri))

    rilevazioni = []
    for riga in righe:
        voce = dict(riga)
        try:
            voce["dati"] = json.loads(voce.get("dati_json") or "{}")
        except (TypeError, ValueError):
            voce["dati"] = {}
        voce["regola_nome"] = REGOLE.get(voce["regola"], (voce["regola"],))[0]
        rilevazioni.append(voce)

    return render_template(
        "ids/index.html",
        rilevazioni=rilevazioni,
        conteggi=_conteggi(tenant_id),
        apprendimento=_in_apprendimento(_stato_sonde(tenant_id)),
        stato=stato,
        gravita=gravita,
        gravita_possibili=ORDINE_GRAVITA,
    )


@bp.post("/<int:finding_id>/decidi")
@role_required(ROLE_ANALYST)
def decidi(finding_id: int):
    """Archivia una rilevazione, o la riapre.

    Archiviare NON significa "non mostrarmela piu'": se la stessa cosa si ripresenta,
    la rilevazione torna aperta al conferimento successivo. Significa "ho guardato
    allora, ed ecco che cosa ho concluso" -- per questo la nota si conserva.
    """
    tenant_id = current_tenant_id()
    riga = query("SELECT * FROM ids_findings WHERE id = ? AND tenant_id = ?",
                 (finding_id, tenant_id), one=True)
    if riga is None:
        flash("Rilevazione non trovata.", "warning")
        return redirect(url_for("ids.index"))

    azione = (request.form.get("azione") or "archivia").strip()
    nota = (request.form.get("nota") or "").strip()[:1000]
    from flask import g

    utente = getattr(g, "user", None)
    nuovo_stato = "archiviata" if azione == "archivia" else "aperta"
    execute(
        "UPDATE ids_findings SET stato = ?, nota = ?, decisa_da = ?, decisa_at = ?"
        " WHERE id = ? AND tenant_id = ?",
        (nuovo_stato, nota or None, int(utente["id"]) if utente is not None else None,
         utc_now_str(), finding_id, tenant_id))
    log_event("ids.decisione",
              "Rilevazione %s su %s: %s" % (riga["regola"], riga["soggetto"],
                                            nuovo_stato),
              tenant_id=tenant_id, entity="ids_finding", entity_id=finding_id)
    flash("Rilevazione %s." % ("archiviata" if nuovo_stato == "archiviata"
                               else "riaperta"), "success")
    return redirect(url_for("ids.index"))


@bp.get("/regole")
@login_required
def regole():
    """Che cosa si sa riconoscere, e che cosa non si sta guardando."""
    tenant_id = current_tenant_id()
    conteggi = {r["regola"]: int(r["quante"]) for r in query(
        "SELECT regola, COUNT(*) AS quante FROM ids_findings WHERE tenant_id = ?"
        " GROUP BY regola", (tenant_id,))}

    catalogo = [{
        "codice": codice,
        "nome": nome,
        "gravita": gravita,
        "tecnica": tecnica,
        "rilevazioni": conteggi.get(codice, 0),
    } for codice, (nome, gravita, tecnica) in sorted(
        REGOLE.items(), key=lambda v: ORDINE_GRAVITA.index(v[1][1]))]

    # Lo stato dei sensori lo dichiara la sonda nel proprio battito: qui si mostra
    # l'ultima cosa che ha detto, con quando l'ha detta.
    return render_template("ids/regole.html", catalogo=catalogo, sensori=SENSORI,
                           sonde=_stato_sonde(tenant_id))


@bp.get("/agenti")
@login_required
def agenti():
    """Le macchine che riferiscono di se'."""
    tenant_id = current_tenant_id()
    macchine = [dict(r) for r in query(
        "SELECT a.*, n.device_label, n.status AS stato_nodo,"
        " (SELECT COUNT(*) FROM agent_events e WHERE e.tenant_id = a.tenant_id"
        "  AND e.agent_uid = a.agent_uid AND e.ricevuto_at >= ?) AS eventi_24h,"
        " (SELECT cpu FROM agent_metrics m WHERE m.tenant_id = a.tenant_id"
        "  AND m.agent_uid = a.agent_uid ORDER BY m.rilevato_at DESC LIMIT 1) AS cpu,"
        " (SELECT memoria FROM agent_metrics m WHERE m.tenant_id = a.tenant_id"
        "  AND m.agent_uid = a.agent_uid ORDER BY m.rilevato_at DESC LIMIT 1) AS memoria,"
        " (SELECT disco_max FROM agent_metrics m WHERE m.tenant_id = a.tenant_id"
        "  AND m.agent_uid = a.agent_uid ORDER BY m.rilevato_at DESC LIMIT 1) AS disco"
        " FROM agent_hosts a LEFT JOIN nodes n ON n.id = a.node_id"
        " WHERE a.tenant_id = ? ORDER BY a.ultimo_invio DESC NULLS LAST",
        (days_ago_str(1), tenant_id))]

    eventi = [dict(r) for r in query(
        "SELECT * FROM agent_events WHERE tenant_id = ?"
        " ORDER BY ricevuto_at DESC LIMIT 100", (tenant_id,))]

    for riga in macchine:
        spenti = [g for g in (riga.get("gruppi_spenti") or "").split(",") if g]
        riga["spenti"] = spenti
        riga["gruppi_inviati"] = len(GRUPPI_AGENTE) - len(spenti)

    return render_template("ids/agenti.html", macchine=macchine, eventi=eventi,
                           gruppi_totali=len(GRUPPI_AGENTE),
                           misure_totali=int(scalar(
                               "SELECT COUNT(*) FROM agent_metrics WHERE tenant_id = ?",
                               (tenant_id,)) or 0))


@bp.get("/agenti/<agent_uid>")
@login_required
def agente(agent_uid: str):
    """Una macchina: le sue misure nel tempo e i suoi eventi."""
    tenant_id = current_tenant_id()
    macchina = query(
        "SELECT a.*, n.device_label FROM agent_hosts a"
        " LEFT JOIN nodes n ON n.id = a.node_id"
        " WHERE a.tenant_id = ? AND a.agent_uid = ?",
        (tenant_id, agent_uid), one=True)
    if macchina is None:
        flash("Macchina non trovata.", "warning")
        return redirect(url_for("ids.agenti"))

    misure = [dict(r) for r in query(
        "SELECT * FROM agent_metrics WHERE tenant_id = ? AND agent_uid = ?"
        " ORDER BY rilevato_at DESC LIMIT 240", (tenant_id, agent_uid))]
    ultima = misure[0] if misure else None
    dettaglio = {}
    if ultima:
        try:
            dettaglio = json.loads(ultima.get("dati_json") or "{}")
        except (TypeError, ValueError):
            dettaglio = {}

    # L'INVENTARIO NON STA NELLE MISURE: arriva una volta all'ora e vive accanto alla
    # macchina, perche' e' uno stato e non una serie. Vedi `Raccolta.inventario`
    # nell'agente per il perche'.
    try:
        inventario = json.loads(macchina["inventario_json"] or "{}")
    except (TypeError, ValueError, KeyError):
        # Un inventario illeggibile non deve rompere la pagina che lo mostra: il
        # prossimo invio lo sostituisce.
        inventario = {}

    # Che cosa questa macchina NON manda, con il suo nome. Sono due cose diverse:
    # quello che chi ha installato l'agente ha SPENTO, e quello che l'agente non e'
    # RIUSCITO a leggere. La seconda e' un problema, la prima una scelta.
    spenti = [g for g in (macchina.get("gruppi_spenti") or "").split(",") if g]
    guasti = list(dettaglio.get("guasti") or []) + list(inventario.get("guasti") or [])
    non_misurati = {
        "spenti": [{"codice": g, "nome": GRUPPI_AGENTE.get(g, g)} for g in spenti],
        "guasti": [{"codice": g.get("gruppo"),
                    "nome": GRUPPI_AGENTE.get(g.get("gruppo"), g.get("gruppo")),
                    "motivo": g.get("motivo")} for g in guasti],
    }

    eventi = [dict(r) for r in query(
        "SELECT * FROM agent_events WHERE tenant_id = ? AND agent_uid = ?"
        " ORDER BY ricevuto_at DESC LIMIT 100", (tenant_id, agent_uid))]

    # Le serie si disegnano in ordine cronologico: le misure arrivano dalla piu'
    # recente perche' cosi' si legge l'elenco, ma un grafico all'indietro non si legge.
    serie = list(reversed(misure))
    return render_template(
        "ids/agente.html",
        macchina=dict(macchina),
        ultima=ultima,
        dettaglio=dettaglio,
        inventario=inventario,
        non_misurati=non_misurati,
        eventi=eventi,
        grafici={
            "cpu": [[m["rilevato_at"], float(m["cpu"] or 0)] for m in serie
                    if m["cpu"] is not None],
            "memoria": [[m["rilevato_at"], float(m["memoria"] or 0)] for m in serie
                        if m["memoria"] is not None],
            "disco": [[m["rilevato_at"], float(m["disco_max"] or 0)] for m in serie
                      if m["disco_max"] is not None],
        },
    )
