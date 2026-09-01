# -----------------------------------------------------------------
# eu_compliance.py — prove di conformita' al quadro europeo di cybersecurity
# Autore: Daniele Speziale
# Data creazione: 2026-08-31
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Che cosa l'inventario puo' dimostrare, norma per norma.

Perche' un documento cosi'
--------------------------
NIS2, CRA e GDPR non chiedono strumenti: chiedono **prove**. "Abbiamo un inventario" non
e' una prova; "il 12% del perimetro dichiarato non e' mai stato osservato" lo e', ed e'
anche piu' utile, perche' dice dove intervenire.

Questo modulo raccoglie cio' che snap conserva e lo mette accanto agli obblighi, con tre
esiti possibili e nessuna scorciatoia:

* **dimostrato** -- il dato c'e' e regge da solo;
* **parziale** -- il dato c'e' ma copre una parte, e la parte si dichiara;
* **da colmare** -- l'obbligo riguarda qualcosa che si puo' fare e non e' stato fatto;
* **fuori portata** -- l'obbligo non si dimostra con un inventario di rete, e dirlo e'
  parte dell'onesta' del documento. Un fascicolo che promette di coprire tutta la NIS2
  con una scansione fa danno a chi lo presenta.

Il quadro di riferimento
------------------------
* **Direttiva (UE) 2022/2555 (NIS2)**, recepita in Italia con il **D.lgs. 138/2024**:
  art. 21 (misure di gestione del rischio) e art. 23 (notifica degli incidenti).
* **Regolamento (UE) 2024/2847 (Cyber Resilience Act)**: allegato I (requisiti
  essenziali di cybersicurezza) e allegato II (gestione delle vulnerabilita').
* **Regolamento (UE) 2016/679 (GDPR)**: art. 5 (minimizzazione), art. 30 (registro dei
  trattamenti), art. 32 (misure tecniche).
* **ETSI EN 303 645**: baseline per i dispositivi connessi di consumo -- credenziali
  predefinite, servizi esposti, aggiornamenti.
* **Linee guida ACN/AgID** per lo sviluppo e l'esercizio sicuri nella PA, con
  **OWASP ASVS/Top 10** come baseline tecnica.

Nota di metodo: i numeri arrivano dalle stesse interrogazioni che alimentano gli altri
report. Un fascicolo che ricalcolasse i propri numeri per conto suo finirebbe per
dichiarare cose diverse dal resto della console -- e in un audit e' l'incoerenza, non il
numero, che fa perdere credibilita'.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from ..db import query

# Esiti possibili di un requisito. L'ordine e' quello di gravita' crescente: serve a
# ordinare i rilievi senza inventare un punteggio.
DIMOSTRATO = "dimostrato"
PARZIALE = "parziale"
DA_COLMARE = "da colmare"
FUORI_PORTATA = "fuori portata"

ORDINE_ESITO = {DA_COLMARE: 0, PARZIALE: 1, FUORI_PORTATA: 2, DIMOSTRATO: 3}

NORME = (
    {
        "chiave": "nis2",
        "titolo": "Direttiva (UE) 2022/2555 - NIS2",
        "recepimento": "D.lgs. 138/2024 (Italia)",
        "ambito": "Gestione del rischio, sicurezza della catena di fornitura,"
                  " notifica degli incidenti",
    },
    {
        "chiave": "cra",
        "titolo": "Regolamento (UE) 2024/2847 - Cyber Resilience Act",
        "recepimento": "applicabilita' progressiva dal 2026 al 2027",
        "ambito": "Sicurezza dei prodotti con elementi digitali, gestione delle"
                  " vulnerabilita' per l'intero ciclo di vita",
    },
    {
        "chiave": "gdpr",
        "titolo": "Regolamento (UE) 2016/679 - GDPR",
        "recepimento": "D.lgs. 196/2003 come modificato dal D.lgs. 101/2018",
        "ambito": "Minimizzazione, misure tecniche di sicurezza, registro dei"
                  " trattamenti",
    },
    {
        "chiave": "etsi",
        "titolo": "ETSI EN 303 645",
        "recepimento": "norma tecnica europea (baseline IoT di consumo)",
        "ambito": "Credenziali predefinite, servizi esposti, aggiornabilita' dei"
                  " dispositivi connessi",
    },
    {
        "chiave": "acn",
        "titolo": "Linee guida ACN / AgID, OWASP ASVS",
        "recepimento": "linee guida nazionali e baseline tecnica",
        "ambito": "Esercizio sicuro, sviluppo sicuro, verifica delle configurazioni",
    },
)


# --------------------------------------------------------------------------- #
# Le misure: numeri presi una volta e usati da tutti i requisiti
# --------------------------------------------------------------------------- #
def _uno(sql: str, parametri: tuple, predefinito=0):
    riga = query(sql, parametri, one=True)
    if riga is None:
        return predefinito
    valore = riga[0] if not isinstance(riga, dict) else list(riga.values())[0]
    return valore if valore is not None else predefinito


def misure(tenant_id: int, inizio: str, fine: str) -> dict:
    """I numeri su cui poggiano i requisiti. Una interrogazione per misura, e basta."""
    subnet_totali = _uno("SELECT COUNT(*) FROM subnets WHERE tenant_id = ?",
                         (tenant_id,))
    subnet_osservate = _uno(
        "SELECT COUNT(DISTINCT n.subnet_id) FROM nodes n WHERE n.tenant_id = ?"
        " AND n.subnet_id IS NOT NULL", (tenant_id,))
    subnet_scansionate = _uno(
        "SELECT COUNT(*) FROM subnets s WHERE s.tenant_id = ?"
        " AND EXISTS (SELECT 1 FROM scan_runs r WHERE r.tenant_id = s.tenant_id"
        "             AND r.stage = 'discovery' AND r.target = s.cidr)", (tenant_id,))

    nodi = _uno("SELECT COUNT(*) FROM nodes WHERE tenant_id = ?", (tenant_id,))
    nodi_identificati = _uno(
        "SELECT COUNT(*) FROM nodes WHERE tenant_id = ? AND device_type IS NOT NULL"
        " AND device_type <> 'unknown' AND COALESCE(device_confidence, 0) >= 60",
        (tenant_id,))
    nodi_con_dichiarazione = _uno(
        "SELECT COUNT(DISTINCT node_id) FROM node_web WHERE tenant_id = ?"
        " AND (COALESCE(device_name,'') <> '' OR COALESCE(model,'') <> '')",
        (tenant_id,))
    nodi_con_seriale = _uno(
        "SELECT COUNT(DISTINCT node_id) FROM node_web WHERE tenant_id = ?"
        " AND COALESCE(serial,'') <> ''", (tenant_id,))
    nodi_con_firmware = _uno(
        "SELECT COUNT(DISTINCT node_id) FROM node_web WHERE tenant_id = ?"
        " AND COALESCE(firmware,'') <> ''", (tenant_id,))

    riscontri = {r["severity"]: int(r["quanti"]) for r in query(
        "SELECT severity, COUNT(*) AS quanti FROM ti_findings"
        " WHERE tenant_id = ? AND status = 'open' GROUP BY severity", (tenant_id,))}
    attese = _uno("SELECT COUNT(*) FROM ti_findings WHERE tenant_id = ?"
                  " AND status = 'expected'", (tenant_id,))
    violazioni = _uno(
        "SELECT COUNT(*) FROM ti_findings WHERE tenant_id = ? AND status = 'open'"
        " AND kind = 'exposure' AND evidence LIKE '%Violazione della zona%'",
        (tenant_id,))
    confermati = _uno("SELECT COUNT(*) FROM ti_findings WHERE tenant_id = ?"
                      " AND status = 'open' AND kind = 'confirmed'", (tenant_id,))
    kev = _uno(
        "SELECT COUNT(*) FROM ti_findings f JOIN ti_cve c ON c.cve_id = f.cve_id"
        " WHERE f.tenant_id = ? AND f.status = 'open' AND c.kev = 1", (tenant_id,))
    senza_versione = _uno(
        "SELECT COUNT(*) FROM node_ports p JOIN nodes n ON n.id = p.node_id"
        " WHERE n.tenant_id = ? AND p.state = 'open' AND COALESCE(p.product,'') <> ''"
        " AND COALESCE(p.version,'') = ''", (tenant_id,))

    zone_dichiarate = _uno("SELECT COUNT(*) FROM subnets WHERE tenant_id = ?"
                           " AND COALESCE(zone,'') <> ''", (tenant_id,))

    controlli = _uno("SELECT COUNT(*) FROM checks WHERE tenant_id = ?", (tenant_id,))
    controlli_attivi = _uno("SELECT COUNT(*) FROM checks WHERE tenant_id = ?"
                            " AND is_enabled = 1", (tenant_id,))
    incidenti = _uno("SELECT COUNT(*) FROM check_incidents WHERE tenant_id = ?"
                     " AND opened_at BETWEEN ? AND ?", (tenant_id, inizio, fine))
    incidenti_aperti = _uno("SELECT COUNT(*) FROM check_incidents WHERE tenant_id = ?"
                            " AND resolved_at IS NULL", (tenant_id,))
    incidenti_con_presa = _uno(
        "SELECT COUNT(*) FROM check_incidents WHERE tenant_id = ?"
        " AND opened_at BETWEEN ? AND ? AND acknowledged_at IS NOT NULL",
        (tenant_id, inizio, fine))
    incidenti_risolti = _uno(
        "SELECT COUNT(*) FROM check_incidents WHERE tenant_id = ?"
        " AND opened_at BETWEEN ? AND ? AND resolved_at IS NOT NULL",
        (tenant_id, inizio, fine))

    audit = _uno("SELECT COUNT(*) FROM audit_events WHERE tenant_id = ?"
                 " AND created_at BETWEEN ? AND ?", (tenant_id, inizio, fine))
    audit_attori = _uno(
        "SELECT COUNT(DISTINCT COALESCE(actor, '')) FROM audit_events"
        " WHERE tenant_id = ? AND created_at BETWEEN ? AND ?", (tenant_id, inizio, fine))
    audit_primo = _uno("SELECT MIN(created_at) FROM audit_events WHERE tenant_id = ?",
                       (tenant_id,), predefinito="")

    utenti = _uno("SELECT COUNT(*) FROM users WHERE tenant_id = ?", (tenant_id,))
    amministratori = _uno("SELECT COUNT(*) FROM users WHERE tenant_id = ?"
                          " AND role IN ('tenant_admin', 'superadmin')", (tenant_id,))
    utenti_mai_entrati = _uno("SELECT COUNT(*) FROM users WHERE tenant_id = ?"
                              " AND last_login_at IS NULL", (tenant_id,))

    # Comunicazioni all'autorita': la capacita' di notificare si dimostra con le
    # notifiche fatte e con i loro tempi, non con i canali configurati.
    acn_totale = _uno("SELECT COUNT(*) FROM acn_communications WHERE tenant_id = ?",
                      (tenant_id,))
    acn_inviate = _uno(
        "SELECT COUNT(*) FROM acn_communications WHERE tenant_id = ?"
        " AND status IN ('inviata', 'riscontro')", (tenant_id,))
    acn_fuori = _uno(
        "SELECT COUNT(*) FROM acn_communications WHERE tenant_id = ?"
        " AND status IN ('inviata', 'riscontro') AND COALESCE(deadline_at, '') <> ''"
        " AND sent_at > deadline_at", (tenant_id,))
    acn_aperte = _uno(
        "SELECT COUNT(*) FROM acn_communications WHERE tenant_id = ?"
        " AND status IN ('da_preparare', 'preparata')", (tenant_id,))

    notifiche = [dict(r) for r in query(
        "SELECT channel, COUNT(*) AS quante,"
        " SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END) AS riuscite"
        " FROM notifications WHERE tenant_id = ? AND created_at BETWEEN ? AND ?"
        " GROUP BY channel", (tenant_id, inizio, fine))]

    # Credenziali di fabbrica e protocolli in chiaro: sono le due cose che la baseline
    # IoT chiede per prime, e si vedono dalle porte.
    snmp_fabbrica = _uno(
        "SELECT COUNT(DISTINCT n.id) FROM nodes n JOIN node_ports p ON p.node_id = n.id"
        " WHERE n.tenant_id = ? AND p.state = 'open' AND p.port = 161"
        " AND (COALESCE(p.extrainfo,'') LIKE '%public%'"
        "      OR COALESCE(p.extrainfo,'') LIKE '%private%')", (tenant_id,))
    in_chiaro = _uno(
        "SELECT COUNT(DISTINCT n.id) FROM nodes n JOIN node_ports p ON p.node_id = n.id"
        " WHERE n.tenant_id = ? AND p.state = 'open' AND p.protocol = 'tcp'"
        " AND p.port IN (21, 23, 80, 512, 513, 514)", (tenant_id,))
    gestione_esposta = _uno(
        "SELECT COUNT(DISTINCT n.id) FROM nodes n JOIN node_ports p ON p.node_id = n.id"
        " LEFT JOIN subnets s ON s.id = n.subnet_id"
        " WHERE n.tenant_id = ? AND p.state = 'open' AND p.protocol = 'tcp'"
        " AND p.port IN (22, 23, 3389, 5900, 623)"
        " AND COALESCE(s.zone, '') NOT IN ('gestione', 'datacenter')", (tenant_id,))

    sonde = _uno("SELECT COUNT(*) FROM probes WHERE tenant_id = ? AND revoked_at IS NULL",
                 (tenant_id,))
    ultima_consegna = _uno(
        "SELECT MAX(received_at) FROM ingest_batches WHERE tenant_id = ?",
        (tenant_id,), predefinito="")

    console_url = _uno("SELECT value FROM system_settings WHERE key = 'public_url'",
                       (), predefinito="")

    return {
        "subnet_totali": int(subnet_totali or 0),
        "subnet_osservate": int(subnet_osservate or 0),
        "subnet_scansionate": int(subnet_scansionate or 0),
        "zone_dichiarate": int(zone_dichiarate or 0),
        "nodi": int(nodi or 0),
        "nodi_identificati": int(nodi_identificati or 0),
        "nodi_con_dichiarazione": int(nodi_con_dichiarazione or 0),
        "nodi_con_seriale": int(nodi_con_seriale or 0),
        "nodi_con_firmware": int(nodi_con_firmware or 0),
        "riscontri_aperti": sum(riscontri.values()),
        "riscontri_critici": int(riscontri.get("critical", 0)),
        "riscontri_alti": int(riscontri.get("high", 0)),
        "attese": int(attese or 0),
        "violazioni_zona": int(violazioni or 0),
        "confermati": int(confermati or 0),
        "kev": int(kev or 0),
        "porte_senza_versione": int(senza_versione or 0),
        "controlli": int(controlli or 0),
        "controlli_attivi": int(controlli_attivi or 0),
        "incidenti": int(incidenti or 0),
        "incidenti_aperti": int(incidenti_aperti or 0),
        "incidenti_con_presa": int(incidenti_con_presa or 0),
        "incidenti_risolti": int(incidenti_risolti or 0),
        "audit": int(audit or 0),
        "audit_attori": int(audit_attori or 0),
        "audit_primo": audit_primo or "",
        "utenti": int(utenti or 0),
        "amministratori": int(amministratori or 0),
        "utenti_mai_entrati": int(utenti_mai_entrati or 0),
        "notifiche": notifiche,
        "canali_attivi": len([n for n in notifiche if int(n["riuscite"] or 0)]),
        "acn_totale": int(acn_totale or 0),
        "acn_inviate": int(acn_inviate or 0),
        "acn_fuori_termine": int(acn_fuori or 0),
        "acn_aperte": int(acn_aperte or 0),
        "snmp_fabbrica": int(snmp_fabbrica or 0),
        "in_chiaro": int(in_chiaro or 0),
        "gestione_esposta": int(gestione_esposta or 0),
        "sonde": int(sonde or 0),
        "ultima_consegna": ultima_consegna or "",
        "console_https": bool(str(console_url or "").startswith("https://")),
        "console_url": console_url or "",
    }


def _quota(parte: int, totale: int) -> int:
    """Percentuale intera, senza dividere per zero."""
    if not totale:
        return 0
    return int(round(parte * 100.0 / totale))


# --------------------------------------------------------------------------- #
# I requisiti: che cosa chiede la norma, che cosa se ne puo' provare
# --------------------------------------------------------------------------- #
def requisiti(m: dict) -> list:
    """Un elenco di requisiti, ciascuno con esito, prova e limite dichiarato.

    Ogni voce e' scritta per essere letta da un auditor: il riferimento normativo, che
    cosa chiede, che cosa mostra snap (con il numero) e -- quando serve -- che cosa
    NON si puo' concludere da quel numero.
    """
    copertura = _quota(m["subnet_scansionate"], m["subnet_totali"])
    identificati = _quota(m["nodi_identificati"], m["nodi"])
    voci = []

    # --- NIS2 -------------------------------------------------------------- #
    voci.append({
        "norma": "nis2", "riferimento": "art. 21(2)(a) - analisi dei rischi",
        "requisito": "Politiche di analisi dei rischi e di sicurezza dei sistemi",
        "esito": FUORI_PORTATA,
        "prova": "snap non conserva politiche: conserva i fatti su cui una politica"
                 " si applica (inventario, esposizioni, zone dichiarate).",
        "limite": "La politica, il suo riesame e l'assegnazione delle responsabilita'"
                  " sono documenti di organizzazione: vanno allegati a parte.",
    })
    voci.append({
        "norma": "nis2", "riferimento": "art. 21(2)(a) - inventario degli asset",
        "requisito": "Conoscenza degli asset esposti e del perimetro",
        "esito": (DIMOSTRATO if copertura >= 95 and identificati >= 70
                  else PARZIALE if copertura >= 50 else DA_COLMARE),
        "prova": "%d dispositivi in inventario su %d subnet dichiarate; %d%% del"
                 " perimetro e' stato scansionato almeno una volta; %d%% dei"
                 " dispositivi ha un tipo attribuito con affidabilita' >= 60%%."
                 % (m["nodi"], m["subnet_totali"], copertura, identificati),
        "limite": ("Il %d%% del perimetro non e' ancora stato osservato: su quella"
                   " parte l'inventario non dice nulla, ne' in positivo ne' in"
                   " negativo." % (100 - copertura)) if copertura < 100 else "",
    })
    voci.append({
        "norma": "nis2", "riferimento": "art. 21(2)(b) - gestione degli incidenti",
        "requisito": "Rilevamento, registrazione e trattamento degli incidenti",
        "esito": (DIMOSTRATO if m["controlli_attivi"] and m["incidenti_con_presa"]
                  else PARZIALE if m["controlli_attivi"] else DA_COLMARE),
        "prova": "%d controlli attivi su %d definiti; %d incidenti aperti nel periodo,"
                 " %d presi in carico, %d risolti, %d ancora aperti. Ogni passaggio"
                 " porta l'istante e l'operatore."
                 % (m["controlli_attivi"], m["controlli"], m["incidenti"],
                    m["incidenti_con_presa"], m["incidenti_risolti"],
                    m["incidenti_aperti"]),
        "limite": "La qualifica di un incidente come 'significativo' ai fini dell'art."
                  " 23 e' una valutazione, non un dato: snap fornisce i tempi e le"
                  " prove, la valutazione resta all'organizzazione.",
    })
    voci.append({
        "norma": "nis2", "riferimento": "art. 21(2)(e) - sicurezza della rete",
        "requisito": "Sicurezza dell'acquisizione, sviluppo e manutenzione delle reti,"
                     " compresa la gestione delle vulnerabilita'",
        "esito": (DA_COLMARE if m["kev"] or m["riscontri_critici"]
                  else PARZIALE if m["riscontri_aperti"] else DIMOSTRATO),
        "prova": "%d riscontri aperti (%d critici, %d alti), di cui %d confermati per"
                 " versione e %d su vulnerabilita' sfruttate attivamente (catalogo"
                 " KEV)." % (m["riscontri_aperti"], m["riscontri_critici"],
                             m["riscontri_alti"], m["confermati"], m["kev"]),
        "limite": "%d servizi non dichiarano la versione: su quelli una vulnerabilita'"
                  " nota non e' attribuibile all'istanza, ed e' un punto cieco"
                  " dichiarato." % m["porte_senza_versione"],
    })
    voci.append({
        "norma": "nis2", "riferimento": "art. 21(2)(d) - continuita' e segmentazione",
        "requisito": "Continuita' operativa e segmentazione della rete",
        "esito": (DIMOSTRATO if m["zone_dichiarate"] and not m["violazioni_zona"]
                  else PARZIALE if m["zone_dichiarate"] else DA_COLMARE),
        "prova": "%d subnet su %d dichiarano la propria zona; %d esposizioni risultano"
                 " attese nel loro contesto e %d sono violazioni del contesto"
                 " dichiarato." % (m["zone_dichiarate"], m["subnet_totali"],
                                   m["attese"], m["violazioni_zona"]),
        "limite": "La segmentazione si dimostra qui per DICHIARAZIONE e per servizi"
                  " osservati: la raggiungibilita' effettiva fra zone richiede una"
                  " sonda per zona (limite dichiarato del prodotto).",
    })
    voci.append({
        "norma": "nis2", "riferimento": "art. 21(2)(i) - igiene e controllo accessi",
        "requisito": "Pratiche di igiene informatica e controllo degli accessi",
        "esito": (PARZIALE if m["snmp_fabbrica"] or m["in_chiaro"] else DIMOSTRATO),
        "prova": "%d dispositivi rispondono a una community SNMP di fabbrica; %d"
                 " espongono protocolli in chiaro (FTP, Telnet, HTTP, rsh); %d"
                 " espongono un servizio di amministrazione fuori dalle zone di"
                 " gestione." % (m["snmp_fabbrica"], m["in_chiaro"],
                                 m["gestione_esposta"]),
        "limite": "Riguarda gli apparati osservati in rete, non le postazioni e gli"
                  " account degli utenti.",
    })
    voci.append({
        "norma": "nis2", "riferimento": "art. 23 - capacita' di notifica",
        "requisito": "Notifica tempestiva (24 ore preallarme, 72 ore notifica, 1 mese"
                     " relazione finale)",
        "esito": (DA_COLMARE if m["acn_fuori_termine"]
                  else PARZIALE if (m["acn_aperte"] or not m["canali_attivi"])
                  else DIMOSTRATO),
        "prova": "Registro delle comunicazioni all'autorita': %d aperte in totale, %d"
                 " inviate con protocollo, %d oltre il termine, %d ancora da inviare."
                 " Avvisi interni: %d canali con invii riusciti nel periodo (%s). Gli"
                 " incidenti registrano apertura, presa in carico, escalation e"
                 " risoluzione con l'istante di ciascun passaggio."
                 % (m["acn_totale"], m["acn_inviate"], m["acn_fuori_termine"],
                    m["acn_aperte"], m["canali_attivi"],
                    ", ".join("%s: %d/%d" % (n["channel"], int(n["riuscite"] or 0),
                                             int(n["quante"] or 0))
                              for n in m["notifiche"]) or "nessun invio"),
        "limite": "L'invio al portale ACN avviene con identita' digitale del punto di"
                  " contatto e non e' automatizzabile: il prodotto compone il"
                  " fascicolo, tiene i termini e registra il protocollo restituito.",
    })
    voci.append({
        "norma": "nis2", "riferimento": "art. 21(2)(j) - tracciamento",
        "requisito": "Registrazione delle attivita' e conservazione delle prove",
        "esito": (DIMOSTRATO if m["audit"] else DA_COLMARE),
        "prova": "%d eventi di registro nel periodo, da %d attori distinti; il registro"
                 " parte dal %s. Ogni evento dice chi, che cosa, quando."
                 % (m["audit"], m["audit_attori"], m["audit_primo"][:10] or "-"),
        "limite": "Nel registro non finiscono ne' password ne' dati personali del"
                  " contenuto: e' una scelta di minimizzazione, e limita cio' che il"
                  " registro puo' dimostrare a chi ha fatto che cosa.",
    })

    # --- CRA --------------------------------------------------------------- #
    voci.append({
        "norma": "cra", "riferimento": "allegato I, parte I - sicurezza per difetto",
        "requisito": "Prodotti configurati in modo sicuro per difetto, senza"
                     " credenziali predefinite",
        "esito": (DA_COLMARE if m["snmp_fabbrica"] else DIMOSTRATO),
        "prova": "%d apparati con community SNMP di fabbrica; %d con protocolli di"
                 " gestione in chiaro." % (m["snmp_fabbrica"], m["in_chiaro"]),
        "limite": "Riguarda i prodotti in esercizio nella rete del titolare, non la"
                  " conformita' dei fabbricanti: quella si chiede al fornitore.",
    })
    voci.append({
        "norma": "cra", "riferimento": "allegato II - gestione delle vulnerabilita'",
        "requisito": "Identificazione dei componenti, delle versioni e delle"
                     " vulnerabilita' note",
        "esito": (PARZIALE if m["nodi_con_firmware"] or m["confermati"]
                  else DA_COLMARE),
        "prova": "%d apparati dichiarano la versione del firmware; %d dichiarano un"
                 " numero di serie; %d riscontri sono confermati per versione."
                 % (m["nodi_con_firmware"], m["nodi_con_seriale"], m["confermati"]),
        "limite": "snap non produce un SBOM dei prodotti del cliente: raccoglie"
                  " versioni e modelli osservati. L'SBOM va chiesto al fabbricante"
                  " (obbligo suo, non del titolare della rete).",
    })
    voci.append({
        "norma": "cra", "riferimento": "allegato I, parte I(2) - superficie di attacco",
        "requisito": "Riduzione della superficie di attacco",
        "esito": (PARZIALE if m["riscontri_aperti"] else DIMOSTRATO),
        "prova": "%d riscontri aperti sulla superficie osservata; %d esposizioni sono"
                 " dichiarate attese nel proprio contesto e restano annotate con la"
                 " loro motivazione." % (m["riscontri_aperti"], m["attese"]),
        "limite": "",
    })

    # --- GDPR -------------------------------------------------------------- #
    voci.append({
        "norma": "gdpr", "riferimento": "art. 5(1)(c) - minimizzazione",
        "requisito": "Trattare solo i dati necessari alla finalita'",
        "esito": DIMOSTRATO,
        "prova": "Della lettura delle interfacce di gestione si conservano soltanto le"
                 " etichette dichiarate dall'apparato e un'impronta del contenuto: il"
                 " corpo delle pagine non viene conservato. I report non contengono"
                 " credenziali e il registro non contiene password.",
        "limite": "L'inventario contiene comunque dati che possono essere personali in"
                  " contesto: indirizzi IP, nomi host, nomi di postazione, e il campo"
                  " 'contatto' se l'apparato lo dichiara. Vanno inseriti nel registro"
                  " dei trattamenti (art. 30) con base giuridica e conservazione.",
    })
    voci.append({
        "norma": "gdpr", "riferimento": "art. 32(1)(a,b) - misure tecniche",
        "requisito": "Cifratura, riservatezza e integrita' del trattamento",
        "esito": (PARZIALE if not m["console_https"] else DIMOSTRATO),
        "prova": "Il canale fra sonda e console e' cifrato e autenticato (protocollo"
                 " proprio, chiavi per sonda); le password degli utenti sono"
                 " conservate con funzione di derivazione moderna; la console %s."
                 % ("e' pubblicata in HTTPS" if m["console_https"]
                    else "risulta pubblicata in HTTP (indirizzo dichiarato: %s)"
                         % (m["console_url"] or "non impostato")),
        "limite": ("Con la console in HTTP le credenziali degli operatori"
                   " attraversano la rete in chiaro: e' il rilievo piu' grave di"
                   " questa sezione e si chiude con un proxy inverso TLS.")
                  if not m["console_https"] else "",
    })
    voci.append({
        "norma": "gdpr", "riferimento": "art. 32(4) - accessi autorizzati",
        "requisito": "Accesso ai dati limitato alle persone autorizzate",
        "esito": (PARZIALE if m["utenti_mai_entrati"] or m["amministratori"] > 3
                  else DIMOSTRATO),
        "prova": "%d utenze sul tenant, di cui %d con privilegi amministrativi; %d non"
                 " hanno mai effettuato l'accesso." % (m["utenti"], m["amministratori"],
                                                       m["utenti_mai_entrati"]),
        "limite": "Il prodotto non impone una seconda credenziale (MFA): e' un limite"
                  " dichiarato, da compensare con l'accesso alla rete di gestione.",
    })

    # --- ETSI EN 303 645 --------------------------------------------------- #
    voci.append({
        "norma": "etsi", "riferimento": "provision 5.1 - password predefinite",
        "requisito": "Nessuna credenziale predefinita universale",
        "esito": (DA_COLMARE if m["snmp_fabbrica"] else DIMOSTRATO),
        "prova": "%d dispositivi rispondono a una community di fabbrica: per ciascuno"
                 " l'inventario riporta indirizzo, modello e posizione, quando"
                 " l'apparato li dichiara." % m["snmp_fabbrica"],
        "limite": "La verifica riguarda i servizi osservabili in rete; le credenziali"
                  " delle interfacce web non vengono provate, per scelta.",
    })
    voci.append({
        "norma": "etsi", "riferimento": "provision 5.6 - superficie minima",
        "requisito": "Ridurre al minimo le superfici di attacco esposte",
        "esito": (PARZIALE if m["in_chiaro"] or m["gestione_esposta"] else DIMOSTRATO),
        "prova": "%d dispositivi espongono protocolli in chiaro; %d espongono"
                 " amministrazione remota fuori dalle zone di gestione."
                 % (m["in_chiaro"], m["gestione_esposta"]),
        "limite": "",
    })
    voci.append({
        "norma": "etsi", "riferimento": "provision 5.3 - aggiornabilita'",
        "requisito": "I dispositivi devono essere aggiornabili e dichiarare la versione",
        "esito": (PARZIALE if m["nodi_con_firmware"] else DA_COLMARE),
        "prova": "%d dispositivi dichiarano la versione del firmware attraverso le"
                 " proprie interfacce di gestione." % m["nodi_con_firmware"],
        "limite": "snap non applica aggiornamenti e non li verifica: registra la"
                  " versione dichiarata.",
    })

    # --- ACN / AgID / OWASP ------------------------------------------------ #
    voci.append({
        "norma": "acn", "riferimento": "linee guida ACN - esercizio sicuro",
        "requisito": "Configurazioni verificate, sorveglianza continua, tracciamento",
        "esito": (DIMOSTRATO if m["sonde"] and m["controlli_attivi"] and m["audit"]
                  else PARZIALE),
        "prova": "%d sonde attive, ultima consegna %s; %d controlli attivi; %d eventi"
                 " tracciati nel periodo." % (m["sonde"], m["ultima_consegna"][:16]
                                              or "mai", m["controlli_attivi"],
                                              m["audit"]),
        "limite": "",
    })
    voci.append({
        "norma": "acn", "riferimento": "OWASP ASVS - verifica applicativa",
        "requisito": "Verifica della sicurezza dell'applicazione che tratta i dati",
        "esito": PARZIALE,
        "prova": "La console applica isolamento fra tenant, controllo dei ruoli,"
                 " protezione CSRF sui moduli e registrazione delle azioni; il"
                 " prodotto dichiara i propri rilievi noti nel fascicolo di"
                 " conformita'.",
        "limite": "Una verifica ASVS formale e' un'attivita' esterna: questo documento"
                  " non la sostituisce.",
    })

    return voci


def pacchetto(tenant: dict, zona, giorno_fine, giorni: int = 90) -> dict:
    """Tutto cio' che serve al documento, in una struttura sola.

    La finestra e' quella comune a tutti i report: stesse date, stessi confini. Un
    fascicolo con una finestra propria dichiarerebbe numeri diversi dal resto della
    console, e in un audit e' l'incoerenza che fa perdere credibilita'.
    """
    from .dataset_wide import _comune

    tenant_id = int(tenant["id"])
    base = _comune(tenant, zona, giorno_fine, giorni)
    inizio, fine = base["inizio_utc"], base["fine_utc"]
    intervallo = base["intervallo"]
    m = misure(tenant_id, inizio, fine)
    voci = requisiti(m)
    per_norma = {}
    for voce in voci:
        per_norma.setdefault(voce["norma"], []).append(voce)
    for elenco in per_norma.values():
        elenco.sort(key=lambda v: ORDINE_ESITO.get(v["esito"], 9))

    conteggi = {}
    for voce in voci:
        conteggi[voce["esito"]] = conteggi.get(voce["esito"], 0) + 1

    documento = dict(base)
    documento.update({
        "misure": m,
        "norme": NORME,
        "requisiti": voci,
        "per_norma": per_norma,
        "conteggi": conteggi,
        # I rilievi: cio' che manca, in ordine di gravita'. E' la pagina che si legge
        # per prima quando il documento serve a decidere.
        "rilievi": [v for v in sorted(voci, key=lambda v: ORDINE_ESITO.get(v["esito"], 9))
                    if v["esito"] in (DA_COLMARE, PARZIALE)],
    })
    return documento
