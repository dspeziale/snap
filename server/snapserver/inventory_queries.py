"""
snap server - Interrogazioni dell'inventario di rete e del monitoraggio.

Tenute separate da `queries.py` perche' riguardano un dominio distinto: lo stato
delle sonde da una parte, i nodi che le sonde hanno scoperto dall'altra. Ogni
interrogazione porta il tenant come primo filtro.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from .db import days_ago_str, query, scalar

# Un nodo non visto da piu' di questo tempo e' considerato assente anche se
# nessuna scansione lo ha ancora dichiarato tale.
STALE_AFTER_HOURS = 24


def inventory_summary(tenant_id: int) -> dict:
    """Sintesi dell'inventario per i riquadri e gli indicatori."""
    totale = scalar("SELECT COUNT(*) FROM nodes WHERE tenant_id = ?", (tenant_id,))
    su = scalar("SELECT COUNT(*) FROM nodes WHERE tenant_id = ? AND status = 'up'", (tenant_id,))
    giu = scalar("SELECT COUNT(*) FROM nodes WHERE tenant_id = ? AND status = 'down'", (tenant_id,))
    nuovi = scalar("SELECT COUNT(*) FROM nodes WHERE tenant_id = ? AND first_seen_at >= ?",
                   (tenant_id, days_ago_str(1)))
    incerti = scalar(
        "SELECT COUNT(*) FROM nodes WHERE tenant_id = ?"
        " AND (device_type = 'unknown' OR device_confidence < 60)", (tenant_id,))
    cambiamenti = scalar("SELECT COUNT(*) FROM node_changes WHERE tenant_id = ? AND created_at >= ?",
                         (tenant_id, days_ago_str(1)))
    gravi = scalar(
        "SELECT COUNT(*) FROM node_changes WHERE tenant_id = ? AND created_at >= ?"
        " AND severity IN ('warning', 'critical')", (tenant_id, days_ago_str(7)))
    subnet = scalar("SELECT COUNT(*) FROM subnets WHERE tenant_id = ? AND is_enabled = 1",
                    (tenant_id,))
    indirizzi = scalar("SELECT COALESCE(SUM(host_count), 0) FROM subnets"
                       " WHERE tenant_id = ? AND is_enabled = 1", (tenant_id,))
    return {
        "total": totale,
        "up": su,
        "down": giu,
        "unknown_state": totale - su - giu,
        "new_24h": nuovi,
        "uncertain": incerti,
        "changes_24h": cambiamenti,
        "changes_7d_severe": gravi,
        "subnets": subnet,
        "perimeter_addresses": indirizzi,
        # Quota del perimetro dichiarato in cui e' stato trovato qualcosa.
        "coverage_pct": round(100.0 * totale / indirizzi, 1) if indirizzi else 0.0,
    }


def device_type_distribution(tenant_id: int) -> list[dict]:
    """Distribuzione dei nodi per tipo di dispositivo."""
    righe = query(
        "SELECT device_type, device_label, COUNT(*) AS n,"
        " ROUND(AVG(device_confidence)) AS conf FROM nodes WHERE tenant_id = ?"
        " GROUP BY device_type, device_label ORDER BY n DESC", (tenant_id,))
    return [{"type": r["device_type"], "label": r["device_label"], "count": int(r["n"]),
             "avg_confidence": int(r["conf"] or 0)} for r in righe]


# Famiglie di servizio con cui si cerca un nodo per cio' che espone. I numeri sono
# gli stessi di RISK_CATEGORIES (docs/08): li' servono a raggruppare per rischio in
# un report, qui a ritrovare un apparato -- e l'inventario non deve dipendere dal
# pacchetto della reportistica. La famiglia "web" esiste solo qui: in un report non
# e' una categoria di rischio, ma e' la prima cosa che si cerca in un inventario.
SERVICE_FAMILIES = [
    ("web", "Interfaccia web", [("tcp", p) for p in
                                (80, 443, 8000, 8080, 8443, 8888)]),
    ("snmp", "SNMP", [("udp", 161)]),
    ("remoto", "Accesso remoto", [("tcp", p) for p in
                                  (22, 23, 3389, 5900, 5901, 5985, 5986)]),
    ("condivisione", "Condivisione file", [("tcp", p) for p in (139, 445, 2049)]),
    ("banche_dati", "Banche dati", [("tcp", p) for p in
                                    (1433, 1521, 3306, 5432, 6379, 9200, 27017)]),
    ("stampa", "Stampa", [("tcp", p) for p in (515, 631, 9100)]),
    ("posta", "Posta", [("tcp", p) for p in
                        (25, 110, 143, 465, 587, 993, 995)]),
    ("telefonia", "Telefonia", [("tcp", p) for p in (1720, 2000, 5060, 5061)]),
    ("chiaro", "Protocolli in chiaro", [("tcp", p) for p in
                                        (21, 23, 69, 110, 143, 512, 513, 514)]),
]

# Quanto indietro guardano i filtri temporali, in giorni.
FRESHNESS = {"24h": 1, "7g": 7, "30g": 30}


def _famiglia(chiave: str):
    for voce in SERVICE_FAMILIES:
        if voce[0] == chiave:
            return voce
    return None


def parse_port_filter(testo: str) -> tuple:
    """Legge "161", "udp/161", "tcp 80" e restituisce (protocollo, porta).

    Il protocollo e' facoltativo: chi cerca "3389" non deve sapere che e' TCP, e chi
    cerca "udp/161" non vuole vedere una porta 161 TCP di un altro apparato.
    """
    grezzo = (testo or "").strip().lower().replace("\\", "/")
    if not grezzo:
        return None, None
    protocollo = None
    for separatore in ("/", ":", " "):
        if separatore in grezzo:
            testa, _, coda = grezzo.partition(separatore)
            if testa in ("tcp", "udp"):
                protocollo, grezzo = testa, coda.strip()
            break
    if not grezzo.isdigit():
        return protocollo, None
    porta = int(grezzo)
    return (protocollo, porta) if 0 < porta <= 65535 else (protocollo, None)


def nodes_list(tenant_id: int, subnet_id: int = None, device_type: str = None,
               status: str = None, service: str = None, port: str = None,
               text: str = None, snmp: str = None, smb: str = None,
               risk: str = None, identified: str = None, seen: str = None,
               zone: str = None, limit: int = 1000) -> list[dict]:
    """Elenco dei nodi con il conteggio delle porte aperte."""
    condizioni = ["n.tenant_id = ?"]
    parametri = [tenant_id]
    if subnet_id:
        condizioni.append("n.subnet_id = ?")
        parametri.append(subnet_id)
    if device_type:
        condizioni.append("n.device_type = ?")
        parametri.append(device_type)
    if status:
        condizioni.append("n.status = ?")
        parametri.append(status)

    # Cio' che il nodo espone: e' il filtro che risponde a "chi ha SNMP aperto?",
    # "quali apparati hanno un'interfaccia web?". Le porte riconosciute come
    # iniettate dalla rete non contano: risponde un apparato intermedio, non il nodo.
    famiglia = _famiglia(service or "")
    if famiglia:
        coppie = famiglia[2]
        segnaposti = " OR ".join(["(p.protocol = ? AND p.port = ?)"] * len(coppie))
        condizioni.append(
            "EXISTS (SELECT 1 FROM node_ports p WHERE p.node_id = n.id"
            " AND p.state = 'open' AND COALESCE(p.is_suspect, 0) = 0"
            " AND (%s))" % segnaposti)
        for protocollo, numero in coppie:
            parametri.extend([protocollo, numero])

    protocollo, numero = parse_port_filter(port)
    if numero:
        condizione = ("EXISTS (SELECT 1 FROM node_ports p WHERE p.node_id = n.id"
                      " AND p.state = 'open' AND p.port = ?")
        parametri.append(numero)
        if protocollo:
            condizione += " AND p.protocol = ?"
            parametri.append(protocollo)
        condizioni.append(condizione + ")")

    # Ricerca libera: chi cerca un nodo ha in mano un indirizzo, un nome, un MAC o
    # il nome del costruttore letto su un'etichetta.
    cercato = (text or "").strip()
    if cercato:
        campi = ("n.ip", "n.hostname", "n.mac", "n.mac_vendor", "n.os_name",
                 "n.device_label")
        condizioni.append("(%s)" % " OR ".join("%s LIKE ?" % c for c in campi))
        parametri.extend(["%%%s%%" % cercato] * len(campi))

    if snmp == "letto":
        condizioni.append("EXISTS (SELECT 1 FROM node_snmp s WHERE s.node_id = n.id)")
    elif snmp == "da_leggere":
        # Porta aperta ma nessuna lettura: e' l'elenco di cio' che manca, non un
        # difetto -- la fase SNMP ha una cadenza propria.
        condizioni.append(
            "EXISTS (SELECT 1 FROM node_ports p WHERE p.node_id = n.id"
            " AND p.state = 'open' AND p.protocol = 'udp' AND p.port = 161)"
            " AND NOT EXISTS (SELECT 1 FROM node_snmp s WHERE s.node_id = n.id)")

    # SMB come SNMP: gia' enumerato, oppure porta aperta (139/445) e mai enumerato.
    if smb == "letto":
        condizioni.append("EXISTS (SELECT 1 FROM node_smb s WHERE s.node_id = n.id)")
    elif smb == "da_leggere":
        condizioni.append(
            "EXISTS (SELECT 1 FROM node_ports p WHERE p.node_id = n.id"
            " AND p.state = 'open' AND p.protocol = 'tcp' AND p.port IN (139, 445))"
            " AND NOT EXISTS (SELECT 1 FROM node_smb s WHERE s.node_id = n.id)")

    if risk == "aperti":
        condizioni.append("EXISTS (SELECT 1 FROM ti_findings f WHERE f.node_id = n.id"
                          " AND f.status = 'open')")
    elif risk == "confermati":
        condizioni.append("EXISTS (SELECT 1 FROM ti_findings f WHERE f.node_id = n.id"
                          " AND f.status = 'open' AND f.kind = 'confirmed')")
    elif risk == "kev":
        condizioni.append(
            "EXISTS (SELECT 1 FROM ti_findings f JOIN ti_cve c ON c.cve_id = f.cve_id"
            " WHERE f.node_id = n.id AND f.status = 'open' AND c.kev = 1)")

    if identified == "incerto":
        # Sotto la soglia il verdetto e' un'ipotesi: sono i nodi su cui serve
        # guardare, ed e' il filtro che li raduna.
        condizioni.append("(COALESCE(n.device_confidence, 0) < 60"
                          " OR n.device_type IS NULL OR n.device_type = 'unknown')")
    elif identified == "certo":
        condizioni.append("COALESCE(n.device_confidence, 0) >= 60"
                          " AND n.device_type IS NOT NULL AND n.device_type <> 'unknown'")

    # Zona della subnet: "che cosa espone la rete di gestione?" e' una domanda che
    # si fa spesso, e senza questo filtro si risponde a mano.
    if zone == "senza":
        condizioni.append("(s.zone IS NULL OR s.zone = '')")
    elif zone:
        condizioni.append("s.zone = ?")
        parametri.append(zone)

    giorni = FRESHNESS.get(seen or "")
    if giorni:
        condizioni.append("n.last_seen_at >= ?")
        parametri.append(days_ago_str(giorni))
    elif seen == "silenzio":
        condizioni.append("n.last_seen_at < ?")
        parametri.append(days_ago_str(7))
    parametri.append(limit)
    # Un nodo puo' essere gia' fra i bersagli dei controlli, per indirizzo oppure per
    # nome host: l'elenco lo dichiara, altrimenti si rifa' l'onboarding di qualcosa
    # che e' gia' sorvegliato senza accorgersene.
    return query(
        "SELECT n.*, s.cidr AS subnet_cidr, s.label AS subnet_label,"
        " COALESCE(s.zone, '') AS zone,"
        " (SELECT COUNT(*) FROM node_ports p WHERE p.node_id = n.id AND p.state = 'open')"
        "   AS open_ports,"
        # Il produttore dichiarato dalla pagina di gestione dell'apparato. E' la fonte
        # piu' autorevole che esista sulla marca -- e' l'apparato che parla di se' --
        # e va davanti al costruttore ricavato dal MAC, che dice chi ha fatto la
        # scheda di rete e non sempre chi ha fatto il dispositivo.
        " (SELECT w.brand FROM node_web w WHERE w.node_id = n.id"
        "   AND COALESCE(w.brand, '') <> '' ORDER BY w.port LIMIT 1) AS web_vendor,"
        " (SELECT t.id FROM check_targets t WHERE t.tenant_id = n.tenant_id"
        "   AND (t.address = n.ip OR (n.hostname IS NOT NULL AND n.hostname <> ''"
        "        AND t.address = n.hostname)) LIMIT 1) AS check_target_id,"
        " (SELECT COUNT(*) FROM checks c JOIN check_targets t ON t.id = c.target_id"
        "   WHERE t.tenant_id = n.tenant_id AND c.is_enabled = 1"
        "   AND (t.address = n.ip OR (n.hostname IS NOT NULL AND n.hostname <> ''"
        "        AND t.address = n.hostname))) AS checks_active"
        " FROM nodes n LEFT JOIN subnets s ON s.id = n.subnet_id"
        " WHERE %s ORDER BY n.last_seen_at DESC LIMIT ?" % " AND ".join(condizioni),
        tuple(parametri),
    )



# Quanti dispositivi si elencano sotto una subnet. Oltre, l'albero diventa un elenco
# lungo quanto l'inventario: il ramo dichiara quanti ne restano e la subnet ha la sua
# pagina filtrata.
MAX_NODI_PER_SUBNET = 250


def network_tree(tenant_id: int, solo_attivi: bool = False) -> dict:
    """Struttura della rete come albero: sonde, perimetro, dispositivi.

    L'albero segue la gerarchia vera di cio' che il prodotto conosce -- quale sonda
    osserva, quale perimetro dichiarato, quali dispositivi ci sono dentro -- e non un
    grafo di adiacenze, che su una rete commutata non si puo' dedurre da una
    scansione: quello che si sa e' chi ha visto che cosa, e dove.
    """
    condizione = " AND n.status = 'up'" if solo_attivi else ""
    righe = query(
        "SELECT n.id, n.ip, n.hostname, n.status, n.device_type, n.device_label,"
        " n.device_confidence, COALESCE(n.device_type_source, 'auto')"
        "   AS device_type_source,"
        " n.os_name, n.last_seen_at, n.subnet_id, n.probe_id,"
        " s.cidr, s.label AS subnet_label, s.host_count, s.is_enabled,"
        " COALESCE(s.zone, '') AS zone,"
        " p.name AS probe_name, p.code AS probe_code,"
        " (SELECT COUNT(*) FROM node_ports x WHERE x.node_id = n.id"
        "   AND x.state = 'open' AND COALESCE(x.is_suspect, 0) = 0) AS porte,"
        " (SELECT COUNT(*) FROM node_snmp y WHERE y.node_id = n.id) AS snmp,"
        " (SELECT COUNT(*) FROM ti_findings f WHERE f.node_id = n.id"
        "   AND f.status = 'open') AS riscontri"
        " FROM nodes n"
        " LEFT JOIN subnets s ON s.id = n.subnet_id"
        " LEFT JOIN probes p ON p.id = n.probe_id"
        " WHERE n.tenant_id = ?" + condizione +
        " ORDER BY p.name, s.cidr, n.ip", (tenant_id,))

    sonde = {}
    for riga in righe:
        voce = dict(riga)
        chiave_sonda = voce["probe_id"] or 0
        sonda = sonde.setdefault(chiave_sonda, {
            "id": voce["probe_id"],
            "nome": voce["probe_name"] or "Senza sonda dichiarata",
            "codice": voce["probe_code"] or "",
            "subnet": {},
            "nodi": 0,
            "attivi": 0,
        })
        chiave_subnet = voce["subnet_id"] or 0
        subnet = sonda["subnet"].setdefault(chiave_subnet, {
            "id": voce["subnet_id"],
            "cidr": voce["cidr"] or "fuori perimetro",
            "etichetta": voce["subnet_label"] or "",
            # La zona dichiarata: dice CHE COSA e' questo posto, mentre il CIDR dice
            # soltanto dove sta.
            "zona": voce["zone"] or "",
            "host_teorici": voce["host_count"] or 0,
            "attiva": bool(voce["is_enabled"]) if voce["cidr"] else False,
            "nodi": [],
            "per_tipo": {},
            "attivi": 0,
            "riscontri": 0,
        })
        subnet["nodi"].append(voce)
        subnet["per_tipo"][voce["device_label"] or "non identificato"] = \
            subnet["per_tipo"].get(voce["device_label"] or "non identificato", 0) + 1
        subnet["riscontri"] += int(voce["riscontri"] or 0)
        if voce["status"] == "up":
            subnet["attivi"] += 1
            sonda["attivi"] += 1
        sonda["nodi"] += 1

    rami = []
    for sonda in sorted(sonde.values(), key=lambda s: (s["id"] is None, s["nome"])):
        subnet = []
        for voce in sorted(sonda["subnet"].values(),
                           key=lambda v: (v["cidr"] == "fuori perimetro", v["cidr"])):
            voce["totale"] = len(voce["nodi"])
            voce["troncato"] = max(0, voce["totale"] - MAX_NODI_PER_SUBNET)
            voce["nodi"] = voce["nodi"][:MAX_NODI_PER_SUBNET]
            voce["per_tipo"] = sorted(voce["per_tipo"].items(),
                                      key=lambda c: (-c[1], c[0]))
            subnet.append(voce)
        sonda["subnet"] = subnet
        rami.append(sonda)

    # Quante subnet hanno prodotto dispositivi: si conta PRIMA di aggiungere il ramo
    # del perimetro non osservato, perche' l'indicatore della pagina dice "subnet con
    # dispositivi" e deve continuare a dire quello.
    subnet_osservate = sum(len(s["subnet"]) for s in rami)

    # Il perimetro senza dispositivi non e' un ramo accanto alle sonde: il perimetro e'
    # del TENANT e viene consegnato a tutte le sonde, quindi non e' una sonda. Ed
    # elencare centinaia di subnet vuote una sotto l'altra non e' un raggruppamento.
    # Si raggruppa per blocco di rete, dicendo perche' sono vuote (vedi `perimetro_muto`).
    viste = {int(s["id"]) for sonda in rami for s in sonda["subnet"] if s["id"]}
    muto = perimetro_muto(tenant_id, viste)
    mai_viste = muto["subnet"]

    # Vista per zona: la stessa rete raggruppata per contesto invece che per sonda.
    # E' il modo in cui si legge la segmentazione: quante subnet e quanti dispositivi
    # in ciascun contesto, e quanto perimetro non e' ancora descritto.
    #
    # Si parte dal PERIMETRO DICHIARATO, non dai dispositivi trovati. Una subnet
    # appena assegnata a una zona non ha ancora dispositivi -- ed e' proprio quella
    # che l'operatore va a cercare qui subito dopo averla dichiarata. Ricavare la
    # vista dall'albero dei dispositivi la faceva sparire, che e' il modo piu' rapido
    # di perdere fiducia in una vista. "Zero dispositivi" e' un'informazione: dice che
    # quella rete e' dichiarata e non ancora osservata.
    from . import zones

    dichiarate = zones.per_chiave(tenant_id)
    per_zona = {}

    def voce_zona(chiave):
        return per_zona.setdefault(chiave, {
            "chiave": chiave,
            "nome": dichiarate[chiave]["nome"] if chiave else "Senza zona dichiarata",
            "icona": dichiarate[chiave]["icona"] if chiave else "bi-question-circle",
            "tono": dichiarate[chiave]["tono"] if chiave else "warning",
            "descrizione": dichiarate[chiave]["descrizione"] if chiave else
                           "Vale come rete di utenza, cioe' il giudizio piu'"
                           " severo: il silenzio non fa da giustificazione.",
            "subnet": [],
            "nodi": 0,
            "attivi": 0,
            "riscontri": 0,
        })

    def aggiungi(chiave, cidr, etichetta, subnet_id, sonda, nodi, attivi, riscontri):
        voce = voce_zona(chiave)
        voce["subnet"].append({"cidr": cidr, "etichetta": etichetta, "id": subnet_id,
                               "sonda": sonda, "nodi": nodi, "attivi": attivi,
                               "riscontri": riscontri})
        voce["nodi"] += nodi
        voce["attivi"] += attivi
        voce["riscontri"] += riscontri

    # Cio' che l'albero ha osservato, indicizzato per subnet: i conteggi vengono da qui.
    osservate = {}
    fuori_perimetro = []
    for sonda in rami:
        for subnet in sonda["subnet"]:
            if subnet["id"]:
                osservate[int(subnet["id"])] = (subnet, sonda["nome"])
            else:
                fuori_perimetro.append((subnet, sonda["nome"]))

    for riga in query(
            "SELECT id, cidr, COALESCE(label, '') AS etichetta,"
            " COALESCE(zone, '') AS zona FROM subnets WHERE tenant_id = ?"
            " ORDER BY cidr", (tenant_id,)):
        chiave = riga["zona"] if riga["zona"] in dichiarate else ""
        trovata = osservate.pop(int(riga["id"]), None)
        subnet, nome_sonda = trovata if trovata else (None, "")
        aggiungi(chiave, riga["cidr"], riga["etichetta"], int(riga["id"]),
                 nome_sonda or "nessun dispositivo osservato",
                 subnet["totale"] if subnet else 0,
                 subnet["attivi"] if subnet else 0,
                 subnet["riscontri"] if subnet else 0)

    # Dispositivi su subnet non piu' nel perimetro, e dispositivi fuori perimetro:
    # restano visibili sotto "senza zona dichiarata". Sono proprio i casi da vedere.
    for subnet, nome_sonda in list(osservate.values()) + fuori_perimetro:
        chiave = subnet["zona"] if subnet["zona"] in dichiarate else ""
        aggiungi(chiave, subnet["cidr"], subnet["etichetta"], subnet["id"], nome_sonda,
                 subnet["totale"], subnet["attivi"], subnet["riscontri"])

    # Le zone senza nessuna subnet compaiono comunque: una zona dichiarata e mai usata
    # e' un'informazione, non un vuoto da nascondere.
    for chiave, dichiarata in dichiarate.items():
        if chiave not in per_zona:
            per_zona[chiave] = {"chiave": chiave, "nome": dichiarata["nome"],
                                "icona": dichiarata["icona"], "tono": dichiarata["tono"],
                                "descrizione": dichiarata["descrizione"],
                                "subnet": [], "nodi": 0, "attivi": 0, "riscontri": 0}

    zone_ordinate = sorted(per_zona.values(),
                           key=lambda v: (v["chiave"] == "", -v["nodi"], v["nome"]))
    for voce in zone_ordinate:
        voce["subnet"].sort(key=lambda s: (-s["nodi"], s["cidr"]))

    return {
        "sonde": rami,
        "nodi": sum(s["nodi"] for s in rami),
        "attivi": sum(s["attivi"] for s in rami),
        "subnet": subnet_osservate,
        "subnet_dichiarate": subnet_osservate + len(mai_viste),
        "subnet_mai_viste": len(mai_viste),
        "perimetro_muto": muto,
        "zone": zone_ordinate,
        "senza_zona": next((v["subnet"] for v in zone_ordinate if v["chiave"] == ""), []),
    }


# Blocco in cui si raggruppano le subnet senza dispositivi. /16 e' la lettura che gli
# operatori hanno in testa ("la 10.10", "la 10.50"): piu' fine non aggrega niente, piu'
# grosso mette insieme reti che non hanno relazione.
PREFISSO_BLOCCO = 16


def perimetro_muto(tenant_id: int, viste: set = None) -> dict:
    """Le subnet dichiarate in cui non e' stato trovato alcun dispositivo.

    Raggruppate per blocco di rete e con il MOTIVO del silenzio, che e' l'unica cosa
    che rende utile questo elenco:

    * `sospesa` -- fuori scansione per scelta;
    * `mai scansionata` -- la sonda non e' ancora arrivata;
    * `scansionata senza esiti` -- la scansione c'e' stata e non ha trovato niente:
      quella rete e' spenta, filtrata o non usata. E' un fatto, non un vuoto.
    """
    import ipaddress

    viste = viste or set()
    righe = query(
        "SELECT s.id, s.cidr, COALESCE(s.label, '') AS etichetta,"
        " COALESCE(s.zone, '') AS zona, COALESCE(s.host_count, 0) AS host_count,"
        " s.is_enabled,"
        " (SELECT COUNT(*) FROM scan_runs r WHERE r.tenant_id = s.tenant_id"
        "    AND r.stage = 'discovery' AND r.target = s.cidr) AS scansioni,"
        " (SELECT MAX(r.finished_at) FROM scan_runs r WHERE r.tenant_id = s.tenant_id"
        "    AND r.stage = 'discovery' AND r.target = s.cidr) AS ultima_scansione"
        " FROM subnets s WHERE s.tenant_id = ? ORDER BY s.cidr", (tenant_id,))

    voci = []
    for riga in righe:
        if int(riga["id"]) in viste:
            continue
        if not riga["is_enabled"]:
            stato = "sospesa"
        elif not int(riga["scansioni"] or 0):
            stato = "mai scansionata"
        else:
            stato = "scansionata senza esiti"
        voci.append({
            "id": int(riga["id"]),
            "cidr": riga["cidr"],
            "etichetta": riga["etichetta"],
            "zona": riga["zona"],
            "host_teorici": int(riga["host_count"] or 0),
            "attiva": bool(riga["is_enabled"]),
            "stato": stato,
            "scansioni": int(riga["scansioni"] or 0),
            "ultima_scansione": riga["ultima_scansione"] or "",
            # Forma compatibile con i rami dell'albero: la vista per zona le mostra
            # accanto alle subnet osservate e non deve distinguere due modelli.
            "nodi": [], "totale": 0, "troncato": 0, "per_tipo": [], "attivi": 0,
            "riscontri": 0,
        })

    blocchi = {}
    for voce in voci:
        try:
            rete = ipaddress.ip_network(voce["cidr"], strict=False)
        except ValueError:  # CIDR non interpretabile: sta in un blocco proprio
            chiave = voce["cidr"]
        else:
            if rete.version == 4 and rete.prefixlen >= PREFISSO_BLOCCO:
                chiave = str(rete.supernet(new_prefix=PREFISSO_BLOCCO))
            else:
                chiave = str(rete)
        blocco = blocchi.setdefault(chiave, {
            "rete": chiave, "subnet": [], "indirizzi": 0,
            "sospese": 0, "mai_scansionate": 0, "senza_esiti": 0,
            "ultima_scansione": "",
        })
        blocco["subnet"].append(voce)
        blocco["indirizzi"] += voce["host_teorici"]
        if voce["stato"] == "sospesa":
            blocco["sospese"] += 1
        elif voce["stato"] == "mai scansionata":
            blocco["mai_scansionate"] += 1
        else:
            blocco["senza_esiti"] += 1
        if voce["ultima_scansione"] > blocco["ultima_scansione"]:
            blocco["ultima_scansione"] = voce["ultima_scansione"]

    ordinati = sorted(blocchi.values(), key=lambda b: (-len(b["subnet"]), b["rete"]))
    return {
        "blocchi": ordinati,
        "subnet": voci,
        "totale": len(voci),
        "indirizzi": sum(v["host_teorici"] for v in voci),
        "sospese": sum(b["sospese"] for b in ordinati),
        "mai_scansionate": sum(b["mai_scansionate"] for b in ordinati),
        "senza_esiti": sum(b["senza_esiti"] for b in ordinati),
    }


def node_detail(tenant_id: int, node_id: int):
    return query(
        "SELECT n.*, s.cidr AS subnet_cidr, s.label AS subnet_label, p.name AS probe_name,"
        " p.code AS probe_code FROM nodes n"
        " LEFT JOIN subnets s ON s.id = n.subnet_id"
        " LEFT JOIN probes p ON p.id = n.probe_id"
        " WHERE n.id = ? AND n.tenant_id = ?", (node_id, tenant_id), one=True)


def node_ports(tenant_id: int, node_id: int) -> list[dict]:
    return query(
        "SELECT * FROM node_ports WHERE tenant_id = ? AND node_id = ?"
        " ORDER BY (state = 'open') DESC, protocol, port", (tenant_id, node_id))


def node_changes(tenant_id: int, node_id: int = None, limit: int = 200,
                 severity: str = None) -> list[dict]:
    condizioni = ["c.tenant_id = ?"]
    parametri = [tenant_id]
    if node_id:
        condizioni.append("c.node_id = ?")
        parametri.append(node_id)
    if severity:
        condizioni.append("c.severity = ?")
        parametri.append(severity)
    parametri.append(limit)
    return query(
        "SELECT c.*, n.ip, n.hostname, n.device_label FROM node_changes c"
        " LEFT JOIN nodes n ON n.id = c.node_id"
        " WHERE %s ORDER BY c.created_at DESC, c.id DESC LIMIT ?" % " AND ".join(condizioni),
        tuple(parametri),
    )


def monitor_history(tenant_id: int, node_id: int, limit: int = 200) -> list[dict]:
    return query(
        "SELECT * FROM monitor_samples WHERE tenant_id = ? AND node_id = ?"
        " ORDER BY checked_at DESC LIMIT ?", (tenant_id, node_id, limit))


def monitor_overview(tenant_id: int) -> list[dict]:
    """Stato corrente della rete con la disponibilita' calcolata sulle 24 ore."""
    return query(
        "SELECT n.id, n.ip, n.hostname, n.status, n.latency_ms, n.device_label,"
        " n.device_type, COALESCE(n.device_type_source, 'auto') AS device_type_source,"
        " n.last_seen_at, s.cidr AS subnet_cidr,"
        " (SELECT COUNT(*) FROM monitor_samples m WHERE m.node_id = n.id"
        "    AND m.checked_at >= ?) AS samples_24h,"
        " (SELECT COUNT(*) FROM monitor_samples m WHERE m.node_id = n.id"
        "    AND m.checked_at >= ? AND m.reachable = 1) AS ok_24h,"
        " (SELECT ROUND(AVG(m.latency_ms), 1) FROM monitor_samples m"
        "    WHERE m.node_id = n.id AND m.checked_at >= ? AND m.reachable = 1) AS avg_latency"
        " FROM nodes n LEFT JOIN subnets s ON s.id = n.subnet_id"
        " WHERE n.tenant_id = ? ORDER BY n.status = 'up', n.ip",
        (days_ago_str(1), days_ago_str(1), days_ago_str(1), tenant_id),
    )


def subnets_list(tenant_id: int) -> list[dict]:
    """Perimetro dichiarato, con i nodi trovati in ciascuna subnet."""
    return query(
        "SELECT s.*, u.email AS imported_by_email,"
        " (SELECT COUNT(*) FROM nodes n WHERE n.subnet_id = s.id) AS nodes_found,"
        " (SELECT COUNT(*) FROM nodes n WHERE n.subnet_id = s.id AND n.status = 'up')"
        "   AS nodes_up"
        " FROM subnets s LEFT JOIN users u ON u.id = s.imported_by"
        " WHERE s.tenant_id = ? ORDER BY s.is_enabled DESC, s.cidr", (tenant_id,))


def deliveries_list(tenant_id: int, probe_id: int = None, limit: int = 500) -> list[dict]:
    """Lotti conferiti dalle sonde: e' cio' che le sonde hanno inviato."""
    condizioni = ["b.tenant_id = ?"]
    parametri = [tenant_id]
    if probe_id:
        condizioni.append("b.probe_id = ?")
        parametri.append(probe_id)
    parametri.append(limit)
    return query(
        "SELECT b.*, p.name AS probe_name, p.code AS probe_code,"
        " (SELECT COUNT(*) FROM scan_runs r WHERE r.batch_id = b.id) AS runs"
        " FROM ingest_batches b"
        " LEFT JOIN probes p ON p.id = b.probe_id AND p.tenant_id = b.tenant_id"
        " WHERE %s ORDER BY b.received_at DESC LIMIT ?" % " AND ".join(condizioni),
        tuple(parametri),
    )


def delivery_detail(tenant_id: int, batch_id: int):
    return query(
        "SELECT b.*, p.name AS probe_name, p.code AS probe_code FROM ingest_batches b"
        " LEFT JOIN probes p ON p.id = b.probe_id AND p.tenant_id = b.tenant_id"
        " WHERE b.id = ? AND b.tenant_id = ?", (batch_id, tenant_id), one=True)


def scan_runs_list(tenant_id: int, batch_id: int = None, limit: int = 200) -> list[dict]:
    condizioni = ["r.tenant_id = ?"]
    parametri = [tenant_id]
    if batch_id:
        condizioni.append("r.batch_id = ?")
        parametri.append(batch_id)
    parametri.append(limit)
    return query(
        "SELECT r.*, p.name AS probe_name FROM scan_runs r"
        " LEFT JOIN probes p ON p.id = r.probe_id"
        " WHERE %s ORDER BY r.created_at DESC LIMIT ?" % " AND ".join(condizioni),
        tuple(parametri),
    )


def inventory_indicators(tenant_id: int) -> list[dict]:
    """Indicatori dell'inventario per l'area indicatori della dashboard."""
    sintesi = inventory_summary(tenant_id)
    return [
        {
            "key": "nodes",
            "label": "Nodi in inventario",
            "value": str(sintesi["total"]),
            "hint": "%d raggiungibili, %d assenti" % (sintesi["up"], sintesi["down"]),
            "icon": "bi-hdd-network",
            "tone": "success" if sintesi["total"] and not sintesi["down"] else "info",
        },
        {
            # La chiave era "coverage" come quella della copertura delle SONDE:
            # due indicatori diversi con la stessa chiave. Finche' le chiavi non
            # servivano a nulla il difetto era invisibile; da quando l'utente puo'
            # nascondere un indicatore, nasconderne uno ne nascondeva due.
            "key": "perimeter_coverage",
            "label": "Copertura del perimetro",
            "value": "%.1f%%" % sintesi["coverage_pct"],
            "hint": "%d indirizzi dichiarati in %d subnet"
                    % (sintesi["perimeter_addresses"], sintesi["subnets"]),
            "icon": "bi-bounding-box",
            "tone": "secondary" if sintesi["subnets"] else "warning",
        },
        {
            "key": "new",
            "label": "Nodi nuovi 24h",
            "value": str(sintesi["new_24h"]),
            "hint": "comparsi da meno di un giorno",
            "icon": "bi-plus-circle",
            "tone": "warning" if sintesi["new_24h"] else "secondary",
        },
        {
            "key": "changes",
            "label": "Cambiamenti 24h",
            "value": str(sintesi["changes_24h"]),
            "hint": "porte, servizi, stato e tipo",
            "icon": "bi-arrow-left-right",
            "tone": "warning" if sintesi["changes_24h"] else "success",
        },
        {
            "key": "uncertain",
            "label": "Nodi da identificare",
            "value": str(sintesi["uncertain"]),
            "hint": "tipo incerto: attendono l'approfondimento",
            "icon": "bi-question-circle",
            "tone": "warning" if sintesi["uncertain"] else "success",
        },
    ]
