"""
snap server - Il dato grezzo di un dispositivo, in JSON.

Perche' esiste: l'interfaccia presenta cio' che il prodotto ha capito -- tipo di
dispositivo, confidenza, riscontri, riassunti. Chi lavora sul campo ha bisogno anche
del contrario: **tutto quello che c'e', senza interpretazione**. Serve a tre cose che
la pagina non copre:

* **verificare un verdetto**: se il prodotto dice "stampante al 78%", la domanda
  successiva e' "in base a che cosa", e la risposta completa sono le prove;
* **portare fuori un dispositivo**: allegarlo a una segnalazione, mandarlo a un
  fornitore, confrontarlo con la scansione di ieri;
* **capire un difetto**: quando un dato non torna, la prima cosa che serve e' cio'
  che e' stato conservato davvero, non la sua presentazione.

Tre scelte:

1. **Un solo documento per dispositivo**, non un endpoint per tabella: la domanda e'
   "che cosa sappiamo di 10.2.112.17", e comporla da cinque chiamate sarebbe un
   lavoro dell'operatore invece che nostro.
2. **Struttura dichiarata e stabile**, con una versione: e' un formato che qualcuno
   leggera' con uno script, e cambiarlo di nascosto romperebbe quello script.
3. **Nessun segreto e nessun dato di altri**: il documento e' limitato al tenant
   corrente e non contiene chiavi, token o community SNMP -- un file che si allega a
   una segnalazione non deve portare fuori credenziali.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json

from .db import query

# Versione del formato. Chi legge con uno script deve poter verificare di stare
# leggendo cio' che si aspetta.
FORMATO = "snap.node/1"

# Limiti: un documento si apre in un browser e si allega a un messaggio. Oltre queste
# soglie non aggiunge informazione, aggiunge peso.
MAX_PORTE = 400
MAX_CAMPIONI = 300
MAX_VARIAZIONI = 200
MAX_RISCONTRI = 200
MAX_SNMP_CARATTERI = 20000


def _da_json(testo, dove: str):
    """Contenuto JSON conservato in una colonna, oppure la dichiarazione dell'errore.

    Un campo illeggibile non fa cadere il documento: si dichiara dove sta il
    problema. Cio' che non si puo' leggere e' un'informazione, e nasconderlo
    renderebbe il documento piu' pulito e meno vero.
    """
    if not testo:
        return None
    try:
        return json.loads(testo)
    except (TypeError, ValueError) as errore:
        return {"_illeggibile": dove, "_motivo": str(errore)[:200]}


def documento(tenant_id: int, node_id: int, con_snmp: bool = True) -> dict | None:
    """Tutto cio' che il prodotto conserva su un dispositivo, in forma grezza.

    Restituisce None se il dispositivo non appartiene al tenant: non e' un errore da
    spiegare, e' un dispositivo che per questo tenant non esiste.
    """
    nodo = query(
        "SELECT n.*, s.cidr AS subnet_cidr, s.label AS subnet_label,"
        " COALESCE(s.zone, '') AS subnet_zone, p.name AS probe_name, p.code AS probe_code"
        " FROM nodes n LEFT JOIN subnets s ON s.id = n.subnet_id"
        " LEFT JOIN probes p ON p.id = n.probe_id"
        " WHERE n.id = ? AND n.tenant_id = ?", (node_id, tenant_id), one=True)
    if nodo is None:
        return None

    from . import zones

    zona = zones.zona(nodo["subnet_zone"], tenant_id) if nodo["subnet_zone"] else None

    porte = [dict(riga) for riga in query(
        "SELECT protocol, port, state, service_name, product, version, extrainfo,"
        " cpe, method, confidence, banner, is_suspect, suspect_reason,"
        " first_seen_at, last_seen_at, closed_at"
        " FROM node_ports WHERE tenant_id = ? AND node_id = ?"
        " ORDER BY protocol, port LIMIT ?", (tenant_id, node_id, MAX_PORTE))]

    campioni = [dict(riga) for riga in query(
        "SELECT checked_at, reachable, latency_ms FROM monitor_samples"
        " WHERE tenant_id = ? AND node_id = ? ORDER BY checked_at DESC, id DESC LIMIT ?",
        (tenant_id, node_id, MAX_CAMPIONI))]

    variazioni = [dict(riga) for riga in query(
        "SELECT created_at, kind, subject, before_value, after_value, severity"
        " FROM node_changes WHERE tenant_id = ? AND node_id = ?"
        " ORDER BY created_at DESC, id DESC LIMIT ?",
        (tenant_id, node_id, MAX_VARIAZIONI))]

    riscontri = [dict(riga) for riga in query(
        "SELECT kind, status, severity, score, title, cve_id, technique_id, product,"
        " version, cpe_used, confidence, evidence, note, decided_by, decided_at,"
        " first_seen_at, last_seen_at FROM ti_findings"
        " WHERE tenant_id = ? AND node_id = ? ORDER BY severity, title LIMIT ?",
        (tenant_id, node_id, MAX_RISCONTRI))]

    pagine = [dict(riga) for riga in query(
        "SELECT port, scheme, status_code, title, server_header, generator, realm,"
        " brand, model, product, version, device_type, signature, cert_subject,"
        " cert_issuer, cert_expires, cert_selfsigned, tls_version, login_form,"
        " device_name, location, host_name, serial, firmware, contact,"
        " pages_read, facts_locked,"
        " body_hash, body_bytes, error, details_json, collected_at"
        " FROM node_web WHERE tenant_id = ? AND node_id = ? ORDER BY port",
        (tenant_id, node_id))]
    for pagina in pagine:
        # Il dettaglio e' conservato come testo: si restituisce interpretato, cosi'
        # chi legge il documento con uno script non deve decodificarlo due volte.
        pagina["details_json"] = _da_json(pagina.get("details_json"),
                                          "node_web.details_json")

    letture = []
    if con_snmp:
        for riga in query(
            "SELECT script_id, output, parsed_json, collected_at FROM node_snmp"
            " WHERE tenant_id = ? AND node_id = ? ORDER BY script_id",
                (tenant_id, node_id)):
            voce = {"script": riga["script_id"], "letto_alle": riga["collected_at"]}
            if riga["parsed_json"]:
                voce["interpretato"] = _da_json(riga["parsed_json"],
                                                "node_snmp.parsed_json")
            if riga["output"]:
                testo = riga["output"]
                voce["testo"] = testo[:MAX_SNMP_CARATTERI]
                if len(testo) > MAX_SNMP_CARATTERI:
                    voce["testo_troncato_a"] = MAX_SNMP_CARATTERI
            letture.append(voce)

    letture_smb = []
    for riga in query(
        "SELECT script_id, output, parsed_json, collected_at FROM node_smb"
        " WHERE tenant_id = ? AND node_id = ? ORDER BY script_id",
            (tenant_id, node_id)):
        voce = {"script": riga["script_id"], "letto_alle": riga["collected_at"]}
        if riga["parsed_json"]:
            voce["interpretato"] = _da_json(riga["parsed_json"],
                                            "node_smb.parsed_json")
        if riga["output"]:
            testo = riga["output"]
            voce["testo"] = testo[:MAX_SNMP_CARATTERI]
            if len(testo) > MAX_SNMP_CARATTERI:
                voce["testo_troncato_a"] = MAX_SNMP_CARATTERI
        letture_smb.append(voce)

    # Le prove del riconoscimento sono il documento piu' interessante: dicono su che
    # cosa poggia il verdetto, e sono la ragione per cui questa vista esiste.
    prove = _da_json(nodo["fingerprint_json"], "nodes.fingerprint_json")

    def campo(nome, predefinito=None):
        """Valore di una colonna, se lo schema la ha.

        Un documento diagnostico non deve cadere perche' una colonna e' cambiata
        nome: la sua ragione d'essere e' funzionare proprio quando qualcosa non
        torna.
        """
        try:
            return nodo[nome]
        except (IndexError, KeyError):
            return predefinito

    identita = {
        "ip": nodo["ip"],
        "hostname": nodo["hostname"],
        "mac": nodo["mac"],
        "mac_vendor": campo("mac_vendor"),
        "os_name": nodo["os_name"],
        "os_family": campo("os_family"),
        "os_vendor": campo("os_vendor"),
        "os_type": campo("os_type"),
        "os_accuracy": campo("os_accuracy"),
        "stato": nodo["status"],
        "visto_la_prima_volta": nodo["first_seen_at"],
        "visto_l_ultima_volta": nodo["last_seen_at"],
        "latenza_ms": campo("latency_ms"),
    }
    riconoscimento = {
        "tipo": nodo["device_type"],
        "etichetta": nodo["device_label"],
        "confidenza": nodo["device_confidence"],
        # Chi ha deciso il tipo: il riconoscimento o una persona. Senza questo campo
        # una confidenza 100 sarebbe indistinguibile da una certezza automatica.
        "deciso_da": ("operatore"
                      if (campo("device_type_source") or "auto") == "manual"
                      else "riconoscimento automatico"),
        "dichiarato_da": campo("device_type_by"),
        "dichiarato_il": campo("device_type_at"),
        "dichiarato_perche": campo("device_type_reason"),
        "versione_catalogo": campo("catalog_version"),
        "ultima_scansione": campo("last_scan_at"),
        "ultimo_cambiamento": campo("last_change_at"),
        "prove": prove,
    }
    collocazione = {
        "subnet": nodo["subnet_cidr"],
        "subnet_etichetta": nodo["subnet_label"],
        "zona": nodo["subnet_zone"] or None,
        "zona_nome": zona["nome"] if zona else None,
        "sonda": nodo["probe_name"],
        "sonda_codice": nodo["probe_code"],
    }

    return {
        "formato": FORMATO,
        "generato_alle": _adesso(),
        "tenant_id": int(tenant_id),
        "node_id": int(node_id),
        "identita": identita,
        "collocazione": collocazione,
        "riconoscimento": riconoscimento,
        "porte": porte,
        "riscontri": riscontri,
        "letture_snmp": letture,
        "letture_smb": letture_smb,
        "letture_web": pagine,
        "variazioni": variazioni,
        "campioni_di_raggiungibilita": campioni,
        "conteggi": {
            "porte": len(porte),
            "porte_aperte": len([p for p in porte if p["state"] == "open"
                                 and not int(p["is_suspect"] or 0)]),
            "riscontri": len(riscontri),
            "letture_snmp": len(letture),
            "letture_smb": len(letture_smb),
            "letture_web": len(pagine),
            "variazioni": len(variazioni),
            "campioni": len(campioni),
        },
        "limiti": {
            "porte": MAX_PORTE, "campioni": MAX_CAMPIONI,
            "variazioni": MAX_VARIAZIONI, "riscontri": MAX_RISCONTRI,
            "caratteri_per_lettura_snmp": MAX_SNMP_CARATTERI,
        },
        "nota": "Documento generato dall'archivio del server: nessuna scansione e'"
                " stata avviata per produrlo. Non contiene chiavi, token ne' community"
                " SNMP.",
    }


def _adesso() -> str:
    from .db import utc_now_str

    return utc_now_str()


def testo(tenant_id: int, node_id: int, indentato: bool = True) -> str | None:
    """Il documento come testo JSON, pronto da mostrare o da scaricare."""
    dati = documento(tenant_id, node_id)
    if dati is None:
        return None
    return json.dumps(dati, ensure_ascii=False, indent=2 if indentato else None,
                      sort_keys=False, default=str)
