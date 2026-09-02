"""
snap server - Inventario di rete: nodi, perimetro e dati conferiti dalle sonde.

L'inventario e' cio' che le sonde hanno scoperto. Il perimetro e' cio' che il
tenant ha dichiarato di possedere: e' la sede dell'autorizzazione a scansionare,
quindi il caricamento del file passa da una validazione severa.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from ..audit import log_event
from ..db import execute, query, utc_now_str
from ..fingerprint import CATALOG_VERSION, DEVICE_CLASSES
from ..ingest import refingerprint_tenant, refresh_fingerprint
from ..rielabora import descrizione_passi
from ..inventory_queries import (
    delivery_detail,
    deliveries_list,
    device_type_distribution,
    inventory_summary,
    monitor_history,
    node_changes,
    node_detail,
    network_tree,
    node_ports,
    nodes_list,
    SERVICE_FAMILIES,
    scan_runs_list,
    subnets_list,
)
from ..snmp_tables import parse_all
from ..smb_tables import parse_all as smb_parse_all
from .. import map_graphic
from .. import zones
from ..security import ROLE_ANALYST, ROLE_TENANT_ADMIN, login_required, role_required
from ..subnets import MAX_HOSTS_PER_SUBNET, SubnetError, import_subnets
from ..tenancy import current_tenant_id

bp = Blueprint("inventory", __name__, url_prefix="/inventory")

# Fasi che l'operatore puo' chiedere immediatamente a una sonda.
REQUESTABLE_STAGES = ("discovery", "ports", "services", "os", "deep", "snmp",
                      "smb", "vuln", "web", "monitor")

# Tipo del dispositivo dichiarato dall'operatore. Il valore convenzionale che
# restituisce la decisione al riconoscimento non e' un tipo: sta a parte perche'
# nessun catalogo lo contiene.
RITORNO_AUTOMATICO = "__auto__"
TIPO_NON_IDENTIFICATO = "unknown"
ETICHETTA_NON_IDENTIFICATO = "Non identificato"


# --------------------------------------------------------------------------- #
# Nodi
# --------------------------------------------------------------------------- #
@bp.get("/nodes")
@login_required
def nodes():
    tenant_id = current_tenant_id()
    return render_template(
        "inventory/nodes.html",
        # I passi della rielaborazione: elenco e spiegazioni stanno nel modulo che
        # li esegue, non nel markup.
        passi_rielaborazione=descrizione_passi(),
        nodes=nodes_list(
            tenant_id,
            subnet_id=request.args.get("subnet", type=int),
            device_type=request.args.get("type") or None,
            status=request.args.get("status") or None,
            service=request.args.get("servizio") or None,
            port=request.args.get("porta") or None,
            text=request.args.get("cerca") or None,
            snmp=request.args.get("snmp") or None,
            smb=request.args.get("smb") or None,
            risk=request.args.get("rischio") or None,
            identified=request.args.get("identificazione") or None,
            seen=request.args.get("visto") or None,
            zone=request.args.get("zona") or None,
        ),
        summary=inventory_summary(tenant_id),
        distribution=device_type_distribution(tenant_id),
        subnets=subnets_list(tenant_id),
        classes=sorted(DEVICE_CLASSES, key=lambda c: c["label"]),
        service_families=SERVICE_FAMILIES,
        filters={"subnet": request.args.get("subnet", type=int),
                 "type": request.args.get("type") or "",
                 "status": request.args.get("status") or "",
                 "servizio": request.args.get("servizio") or "",
                 "porta": request.args.get("porta") or "",
                 "cerca": request.args.get("cerca") or "",
                 "snmp": request.args.get("snmp") or "",
                 "smb": request.args.get("smb") or "",
                 "rischio": request.args.get("rischio") or "",
                 "identificazione": request.args.get("identificazione") or "",
                 "visto": request.args.get("visto") or "",
                 "zona": request.args.get("zona") or ""},
        # Le zone del TENANT, non il seme del prodotto: quelle create
        # dall'operatore devono comparire nel filtro come le predefinite.
        zones=zones.catalogo(tenant_id),
        # Quanti nodi espongono SMB: e' l'etichetta del pulsante di enumerazione totale.
        smb_open_count=_smb_open_count(tenant_id),
        # I filtri attivi come pastiglie rimovibili: si vede a colpo d'occhio che cosa
        # sta restringendo l'elenco, e ognuna si toglie con un clic. Tutto lato server,
        # senza JavaScript, coerente con la politica di sicurezza dei contenuti.
        active_filters=_active_filters(tenant_id),
        catalog_version=CATALOG_VERSION,
    )


# Etichette leggibili dei valori di filtro che non sono gia' un nome (subnet, tipo,
# servizio e zona si risolvono a parte, sui dati del tenant).
_FILTER_VALUE_LABELS = {
    "status": {"up": "raggiungibile", "down": "assente"},
    "visto": {"24h": "ultime 24 ore", "7g": "ultimi 7 giorni",
              "30g": "ultimi 30 giorni", "silenzio": "muti da oltre 7 giorni"},
    "snmp": {"letto": "gia' letta", "da_leggere": "porta aperta, mai letta"},
    "smb": {"letto": "gia' enumerata",
            "da_leggere": "porta 139/445 aperta, mai enumerata"},
    "rischio": {"aperti": "con riscontri aperti",
                "confermati": "con vulnerabilita' confermate",
                "kev": "sfruttate attivamente (KEV)"},
    "identificazione": {"incerto": "da verificare", "certo": "riconosciuto"},
}
# Come si chiama, per una persona, ciascun filtro.
_FILTER_TITLES = {
    "subnet": "Subnet", "type": "Tipo", "status": "Stato", "visto": "Ultimo contatto",
    "servizio": "Servizio", "porta": "Porta", "zona": "Zona", "snmp": "Lettura SNMP",
    "smb": "Enumerazione SMB", "rischio": "Sicurezza",
    "identificazione": "Identificazione", "cerca": "Cerca",
}
# L'ordine in cui le pastiglie compaiono: lo stesso ordine di lettura dei gruppi.
_FILTER_ORDER = ("subnet", "zona", "type", "identificazione", "status", "visto",
                 "servizio", "porta", "snmp", "smb", "rischio", "cerca")


def _active_filters(tenant_id: int) -> list[dict]:
    """I filtri applicati, come pastiglie con l'etichetta leggibile e il link che le
    toglie (l'indirizzo corrente meno quel solo parametro)."""
    grezzi = {chiave: (request.args.get(chiave) or "").strip()
              for chiave in _FILTER_ORDER}
    grezzi = {k: v for k, v in grezzi.items() if v}
    if not grezzi:
        return []

    # Le etichette che dipendono dai dati del tenant.
    subnet_label = {}
    if "subnet" in grezzi:
        for s in subnets_list(tenant_id):
            subnet_label[str(s["id"])] = "%s%s" % (
                s["cidr"], " - %s" % s["label"] if s["label"] else "")
    tipo_label = {c["key"]: c["label"] for c in DEVICE_CLASSES}
    tipo_label["unknown"] = "Non identificato"
    servizio_label = {chiave: etichetta for chiave, etichetta, _ in SERVICE_FAMILIES}
    zona_label = {z["chiave"]: z["nome"] for z in zones.catalogo(tenant_id)}
    zona_label["senza"] = "non dichiarata"

    def leggibile(nome: str, valore: str) -> str:
        if nome == "subnet":
            return subnet_label.get(valore, valore)
        if nome == "type":
            return tipo_label.get(valore, valore)
        if nome == "servizio":
            return servizio_label.get(valore, valore)
        if nome == "zona":
            return zona_label.get(valore, valore)
        return _FILTER_VALUE_LABELS.get(nome, {}).get(valore, valore)

    attivi = []
    for nome in _FILTER_ORDER:
        if nome not in grezzi:
            continue
        rimanenti = {k: v for k, v in grezzi.items() if k != nome}
        attivi.append({
            "nome": nome,
            "titolo": _FILTER_TITLES.get(nome, nome),
            "valore": leggibile(nome, grezzi[nome]),
            "reset_url": url_for("inventory.nodes", **rimanenti),
        })
    return attivi


def _produttore(nodo, pagine_web) -> dict:
    """Chi ha fatto questo apparato, e da dove lo sappiamo.

    Ordine di autorevolezza:

    1. cio' che l'apparato **dichiara di se'** nella propria pagina di gestione o via
       IPP: e' l'apparato che parla;
    2. l'**indirizzo MAC**: dice chi ha costruito la scheda di rete, che non sempre e'
       chi ha costruito il dispositivo -- e si vede solo se la sonda sta nello stesso
       segmento;
    3. il **rilevamento del sistema operativo**: riguarda il software, non l'apparato.

    Restituisce anche il modello quando l'apparato lo ha dichiarato: chiedersi "di chi
    e'" e "quale e'" e' la stessa domanda, e la risposta sta nello stesso posto.
    """
    dichiarato = ""
    modello = ""
    for pagina in pagine_web or []:
        if not dichiarato and (pagina.get("brand") or "").strip():
            dichiarato = pagina["brand"].strip()
        if not modello and (pagina.get("model") or "").strip():
            modello = pagina["model"].strip()

    mac_vendor = (nodo["mac_vendor"] or "").strip() if "mac_vendor" in nodo.keys() else ""
    os_vendor = (nodo["os_vendor"] or "").strip() if "os_vendor" in nodo.keys() else ""

    if dichiarato:
        nome, fonte = dichiarato, "dichiarato dall'apparato"
    elif mac_vendor:
        nome, fonte = mac_vendor, "dedotto dall'indirizzo MAC"
    elif os_vendor:
        nome, fonte = os_vendor, "dedotto dal rilevamento del sistema operativo"
    else:
        nome, fonte = "", ""

    # La seconda fonte si mostra solo se dice qualcosa di diverso: ripetere "Kyocera"
    # due volte non aggiunge niente, mentre "Kyocera" con una scheda "Intel" si.
    secondo = ""
    if dichiarato and mac_vendor:
        prima = dichiarato.split()[0].lower()
        if prima not in mac_vendor.lower() and mac_vendor.split()[0].lower() not in dichiarato.lower():
            secondo = mac_vendor

    return {"nome": nome, "fonte": fonte, "modello": modello,
            "scheda_di_rete": secondo}


@bp.get("/map")
@login_required
def network_map():
    """Mappa della rete come albero: sonde, perimetro, dispositivi."""
    tenant_id = current_tenant_id()
    solo_attivi = request.args.get("attivi") == "1"
    return render_template(
        "inventory/map.html",
        tree=network_tree(tenant_id, solo_attivi=solo_attivi),
        summary=inventory_summary(tenant_id),
        solo_attivi=solo_attivi,
        # Le zone servono all'albero per mostrare il contesto di ogni subnet: si
        # passano indicizzate, perche' il template le cerca per chiave.
        zone_per_chiave=zones.per_chiave(tenant_id),
    )


@bp.get("/map/grafica")
@login_required
def network_map_graphic():
    """Mappa grafica: le reti attorno alle sonde, i dispositivi con la loro icona.

    La disposizione la calcola il server (`map_graphic`): la pagina non carica
    librerie di grafi e non ha script inline, coerentemente con la politica di
    sicurezza dei contenuti del prodotto.
    """
    tenant_id = current_tenant_id()
    solo_attivi = request.args.get("attivi") == "1"
    albero = network_tree(tenant_id, solo_attivi=solo_attivi)

    # La rete scelta: un valore illeggibile non e' un errore da spiegare, e' un
    # panorama.
    try:
        scelta = int(request.args.get("subnet") or 0)
    except ValueError:
        scelta = 0
    vista = map_graphic.rete(albero, scelta) if scelta else None
    if scelta and vista is None:
        flash("Quella rete non ha dispositivi da disegnare, oppure non appartiene a"
              " questo tenant: viene mostrato il panorama.", "info")

    # L'elenco per il selettore: solo reti con dispositivi, le piu' popolose per prime.
    reti = sorted(
        ({"id": v["id"], "cidr": v["cidr"], "etichetta": v["etichetta"],
          "totale": int(v.get("totale") or 0)}
         for s in albero.get("sonde") or [] for v in s.get("subnet") or []
         if v.get("id")),
        key=lambda v: (-v["totale"], v["cidr"]))

    # Formato di stampa scelto: governa la dimensione della pagina (@page). Allowlist,
    # perche' il valore finisce in un foglio di stile.
    foglio = request.args.get("foglio")
    if foglio not in _FOGLI_STAMPA:
        foglio = "a4-landscape"

    return render_template(
        "inventory/map_grafica.html",
        panorama=map_graphic.panorama(albero),
        vista=vista,
        reti=reti,
        legenda=map_graphic.legenda(albero),
        max_nodi=map_graphic.MAX_NODI_DISEGNATI,
        solo_attivi=solo_attivi,
        foglio=foglio,
        fogli_stampa=_FOGLI_STAMPA,
    )


# Formati di stampa della mappa, con la dimensione @page e l'etichetta. L'orizzontale
# e' il verso naturale della mappa (rapporto vicino all'A4 orizzontale).
_FOGLI_STAMPA = {
    "a4-landscape": {"css": "A4 landscape", "label": "A4 orizzontale"},
    "a4-portrait": {"css": "A4 portrait", "label": "A4 verticale"},
    "a3-landscape": {"css": "A3 landscape", "label": "A3 orizzontale"},
    "a3-portrait": {"css": "A3 portrait", "label": "A3 verticale"},
}

# Etichette leggibili per i fatti che l'apparato dichiara di se' e che non hanno una
# colonna propria nel dettaglio (nome, modello, posizione, host, serie, firmware e
# contatto sono gia' mostrati sopra). Chi non e' in elenco non si mostra: e' l'unico
# modo di tenere il dettaglio pulito e di non far comparire chiavi tecniche grezze.
_ETICHETTE_FATTI_WEB = {
    "mac": "Indirizzo MAC",
    "numero_interno": "Numero interno",
    "carico_software": "Carico software (app)",
    "carico_avvio": "Carico di avvio (boot)",
    "revisione_hw": "Revisione hardware",
    "gestore_chiamate": "Gestore chiamate (CUCM)",
    "server_tftp": "Server TFTP",
    # Misure di stato di un UPS MGE/Eaton (la diagnosi vera e' a parte, vedi sotto).
    "alimentazione": "Alimentazione",
    "carico_uscita": "Carico in uscita",
    "capacita_batteria": "Capacita' batteria",
    "autonomia_batteria": "Autonomia batteria",
    "stato_batteria": "Stato batteria",
}
# La diagnosi dell'UPS non e' una riga fra le altre: e' l'esito dell'analisi dei
# registri e va mostrata in evidenza (verde se tutto bene, in avviso se ci sono
# problemi). Non compare quindi fra i "dati aggiuntivi".
_DIAGNOSI_OK = "Nessun problema rilevato"
# Fatti gia' esposti come campo dedicato: non vanno ripetuti fra i "dati aggiuntivi".
_FATTI_WEB_GIA_MOSTRATI = frozenset((
    "nome_dispositivo", "modello", "posizione", "nome_host", "seriale", "firmware",
    "contatto", "marca_dichiarata",
))


def _fatti_aggiuntivi(facts_json: str | None) -> list[dict]:
    """I fatti dichiarati dall'apparato che non hanno gia' un campo dedicato.

    Restituisce coppie (etichetta leggibile, valore) in un ordine stabile, saltando i
    fatti gia' mostrati e le chiavi che non sono nel vocabolario di presentazione: un
    telefono IP Cisco dichiara interno, carichi, revisione hardware, gestore chiamate e
    server TFTP, e questi altrimenti resterebbero solo nel dato grezzo.
    """
    if not facts_json:
        return []
    try:
        fatti = json.loads(facts_json)
    except json.JSONDecodeError:
        return []
    if not isinstance(fatti, dict):
        return []
    aggiuntivi = []
    for chiave, etichetta in _ETICHETTE_FATTI_WEB.items():
        valore = fatti.get(chiave)
        if chiave in _FATTI_WEB_GIA_MOSTRATI or not valore:
            continue
        aggiuntivi.append({"etichetta": etichetta, "valore": str(valore)})
    return aggiuntivi


def _diagnosi_web(facts_json: str | None) -> dict:
    """La diagnosi ricavata dai registri dell'apparato (oggi lo UPS MGE/Eaton).

    Restituisce `{"problemi": [...], "ok": bool}` oppure {} se non c'e' una diagnosi.
    I problemi arrivano dalla sonda come un'unica stringa separata da "; "."""
    if not facts_json:
        return {}
    try:
        fatti = json.loads(facts_json)
    except json.JSONDecodeError:
        return {}
    if not isinstance(fatti, dict):
        return {}
    testo = (fatti.get("diagnosi_ups") or "").strip()
    if not testo:
        return {}
    if testo == _DIAGNOSI_OK:
        return {"problemi": [], "ok": True}
    return {"problemi": [p.strip() for p in testo.split(";") if p.strip()], "ok": False}


# Etichette leggibili per i dati del certificato TLS, nell'ordine in cui si leggono
# davanti a un certificato: chi, chi lo ha emesso, per quanto e' valido, com'e' fatto.
_ETICHETTE_CERT = (
    ("cert_soggetto_dn", "Soggetto"),
    ("cert_emittente_dn", "Emittente"),
    ("cert_valido_da", "Valido dal"),
    ("cert_valido_a", "Valido fino al"),
    ("cert_giorni_residui", "Giorni residui"),
    ("cert_seriale", "Numero di serie"),
    ("cert_versione", "Versione"),
    ("cert_algoritmo_firma", "Algoritmo di firma"),
    ("cert_chiave", "Chiave pubblica"),
    ("cert_uso", "Usi consentiti"),
    ("cert_uso_esteso", "Usi estesi"),
    ("cert_nomi", "Nomi alternativi (DNS)"),
    ("cert_nomi_ip", "Nomi alternativi (IP)"),
    ("cert_sha256", "Impronta SHA-256"),
    ("cert_sha1", "Impronta SHA-1"),
    ("tls_versione", "Protocollo TLS"),
    ("tls_cifrario", "Cifrario"),
    ("cert_errore", "Errore di lettura"),
)
# Chiavi da rendere in monospazio (impronte, seriale) e chiavi-elenco (liste).
_CERT_MONOSPAZIO = frozenset(("cert_seriale", "cert_sha256", "cert_sha1"))
_CERT_ELENCHI = frozenset(("cert_uso", "cert_uso_esteso", "cert_nomi", "cert_nomi_ip"))


def _mac_da_snmp(snmp_tabelle: list) -> list[str]:
    """I MAC che l'agente SNMP dichiara nelle proprie interfacce, senza ripetizioni.

    E' l'unico modo di conoscere il MAC di un apparato su un'altra rete, dove l'ARP non
    arriva e la colonna del nodo resta vuota. Si saltano i segnaposto (00:00:00:00:00:00)
    e i valori non simili a un MAC.
    """
    fuori = []
    for tabella in snmp_tabelle or []:
        if tabella.get("script_id") != "snmp-interfaces":
            continue
        colonne = tabella.get("colonne") or []
        if "MAC" not in colonne:
            continue
        indice = colonne.index("MAC")
        for riga in tabella.get("righe") or []:
            if indice >= len(riga):
                continue
            # La cella puo' contenere il MAC seguito dal costruttore fra parentesi
            # ("00:1A:2B:... (Aruba)"): si estrae il solo indirizzo.
            trovato = re.search(r"(?i)\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b",
                                riga[indice] or "")
            if not trovato:
                continue
            mac = trovato.group(1).upper()
            if mac == "00:00:00:00:00:00" or mac in fuori:
                continue
            fuori.append(mac)
    return fuori


def _certificato_leggibile(cert_json: str | None) -> dict:
    """Il certificato TLS come struttura pronta per il dettaglio.

    Restituisce `{"righe": [...], "autofirmato": bool, "scaduto": bool, ...}` oppure un
    dizionario vuoto se non c'e' un certificato. Le righe sono coppie (etichetta,
    valore) in ordine di lettura; gli esiti di sicurezza (autofirmato, scaduto, non
    ancora valido) restano separati perche' meritano un'evidenza, non una riga."""
    if not cert_json:
        return {}
    try:
        cert = json.loads(cert_json)
    except json.JSONDecodeError:
        return {}
    if not isinstance(cert, dict) or not cert:
        return {}
    righe = []
    for chiave, etichetta in _ETICHETTE_CERT:
        valore = cert.get(chiave)
        if valore in (None, "", [], {}):
            continue
        if chiave in _CERT_ELENCHI and isinstance(valore, list):
            valore = ", ".join(str(v) for v in valore)
        righe.append({"etichetta": etichetta, "valore": str(valore),
                      "monospazio": chiave in _CERT_MONOSPAZIO})
    return {
        "righe": righe,
        "autofirmato": bool(cert.get("cert_autofirmato")),
        "scaduto": bool(cert.get("cert_scaduto")),
        "non_ancora_valido": bool(cert.get("cert_non_ancora_valido")),
    }


@bp.get("/nodes/<int:node_id>")
@login_required
def node(node_id: int):
    tenant_id = current_tenant_id()
    riga = node_detail(tenant_id, node_id)
    if riga is None:
        abort(404)

    try:
        conservato = json.loads(riga["fingerprint_json"] or "{}")
    except json.JSONDecodeError:
        current_app.logger.warning("fingerprint_json non valido per il nodo %s", node_id)
        conservato = {}

    porte = node_ports(tenant_id, node_id)
    aperte = [p for p in porte
              if (p["state"] or "") == "open" and not int(p["is_suspect"] or 0)]
    # Un nodo puo' essere gia' fra i bersagli, per indirizzo o per nome host: dirlo
    # evita di premere un pulsante che non aggiungerebbe nulla.
    indirizzi = [riga["ip"]] + ([riga["hostname"]] if riga["hostname"] else [])
    sorvegliato = query(
        "SELECT id, name FROM check_targets WHERE tenant_id = ? AND address IN (%s)"
        % ",".join("?" * len(indirizzi)), [tenant_id] + indirizzi, one=True)

    # Riscontri di threat intelligence del nodo: la domanda "questo dispositivo ha
    # problemi noti?" si pone guardando il dispositivo, non un elenco generale.
    from ..threat import node_findings

    riscontri = node_findings(tenant_id, node_id)

    # Letture web: dove un'interfaccia di gestione risponde, e' la fonte piu'
    # esplicita dopo SNMP -- una pagina che si presenta con marca e modello dice
    # dell'apparato piu' di dieci porte aperte.
    pagine_web = [dict(r) for r in query(
        "SELECT port, scheme, status_code, title, server_header, generator, realm,"
        " brand, model, product, version, device_type, signature, cert_subject,"
        " cert_issuer, cert_expires, cert_selfsigned, tls_version, login_form,"
        " device_name, location, host_name, serial, firmware, contact,"
        " pages_read, facts_locked, facts_json, cert_json,"
        " body_bytes, error, collected_at FROM node_web"
        " WHERE tenant_id = ? AND node_id = ? ORDER BY port", (tenant_id, node_id))]
    # I fatti che l'apparato dichiara e che non hanno una colonna propria (l'interno e i
    # carichi di un telefono IP, per esempio) diventano una lista leggibile mostrata nel
    # dettaglio, accanto ai campi principali. Lo stesso per il certificato TLS: dove c'e'
    # HTTPS, si mostra tutto cio' che dichiara.
    for pagina in pagine_web:
        facts_json = pagina.pop("facts_json", None)
        pagina["extra"] = _fatti_aggiuntivi(facts_json)
        pagina["diagnosi"] = _diagnosi_web(facts_json)
        pagina["cert"] = _certificato_leggibile(pagina.pop("cert_json", None))

    # Letture SNMP: dove la 161 risponde, e' la fonte piu' ricca sull'apparato.
    letture = [dict(r) for r in query(
        "SELECT script_id, output, parsed_json, collected_at FROM node_snmp"
        " WHERE tenant_id = ? AND node_id = ? ORDER BY script_id",
        (tenant_id, node_id))]

    # Enumerazione SMB: dove la 139 o la 445 rispondono, dice di una macchina Windows
    # sistema operativo, dominio, condivisioni e utenze.
    letture_smb = [dict(r) for r in query(
        "SELECT script_id, output, parsed_json, collected_at FROM node_smb"
        " WHERE tenant_id = ? AND node_id = ? ORDER BY script_id",
        (tenant_id, node_id))]
    riassunto_smb = {}
    for voce in letture_smb:
        if voce["script_id"] == "summary" and voce["parsed_json"]:
            try:
                riassunto_smb = json.loads(voce["parsed_json"])
            except json.JSONDecodeError:
                current_app.logger.warning(
                    "riassunto SMB illeggibile per il nodo %s", node_id)
    riassunto_snmp = {}
    for voce in letture:
        if voce["script_id"] == "summary" and voce["parsed_json"]:
            try:
                riassunto_snmp = json.loads(voce["parsed_json"])
            except json.JSONDecodeError:
                current_app.logger.warning(
                    "riassunto SNMP illeggibile per il nodo %s", node_id)

    snmp_tabelle = parse_all([v for v in letture if v["script_id"] != "summary"])

    return render_template(
        "inventory/node.html",
        node=riga,
        web=pagine_web,
        produttore=_produttore(riga, pagine_web),
        # MAC dichiarati dall'agente SNMP (dalle interfacce): sono l'unico modo di
        # conoscere il MAC di un apparato su un'altra rete, dove l'ARP non arriva.
        mac_snmp=_mac_da_snmp(snmp_tabelle),
        ports=porte,
        open_ports=aperte,
        findings=riscontri,
        findings_aperti=[f for f in riscontri if f["status"] == "open"],
        snmp=snmp_tabelle,
        snmp_summary=riassunto_snmp,
        smb=smb_parse_all([v for v in letture_smb if v["script_id"] != "summary"]),
        smb_summary=riassunto_smb,
        monitored_target=dict(sorvegliato) if sorvegliato is not None else None,
        changes=node_changes(tenant_id, node_id, limit=100),
        samples=monitor_history(tenant_id, node_id, limit=120),
        verdict=conservato.get("verdict") or {},
        evidence=conservato.get("evidence") or {},
        stages=REQUESTABLE_STAGES,
        # Il catalogo dei tipi serve al selettore della dichiarazione: chi conosce la
        # rete puo' dire che cos'e' un apparato che il riconoscimento sbaglia.
        classes=sorted(DEVICE_CLASSES, key=lambda c: c["label"]),
    )


@bp.post("/nodes/<int:node_id>/managed")
@role_required(ROLE_ANALYST)
def toggle_managed(node_id: int):
    tenant_id = current_tenant_id()
    riga = node_detail(tenant_id, node_id)
    if riga is None:
        abort(404)
    nuovo = 0 if int(riga["is_managed"]) else 1
    execute("UPDATE nodes SET is_managed = ?, updated_at = ? WHERE id = ? AND tenant_id = ?",
            (nuovo, utc_now_str(), node_id, tenant_id))
    log_event("node.managed" if nuovo else "node.unmanaged",
              "Nodo %s %s" % (riga["ip"], "marcato come gestito" if nuovo else "non piu' gestito"),
              tenant_id=tenant_id, entity="node", entity_id=node_id)
    flash("Nodo %s aggiornato." % riga["ip"], "success")
    return redirect(url_for("inventory.node", node_id=node_id))


@bp.post("/nodes/<int:node_id>/type")
@role_required(ROLE_ANALYST)
def declare_type(node_id: int):
    """Dichiara il tipo di un dispositivo, o restituisce la decisione al riconoscimento.

    Il riconoscimento pesa le prove, e su un apparato che non parla di se' le prove
    possono non bastare: chi conosce la rete sa che quel silenzio e' un PLC. La
    dichiarazione vale 100 di confidenza -- risponde una persona -- e resiste ai
    ricalcoli, altrimenti durerebbe fino al conferimento successivo.
    """
    tenant_id = current_tenant_id()
    riga = node_detail(tenant_id, node_id)
    if riga is None:
        abort(404)

    scelto = (request.form.get("device_type") or "").strip()
    motivo = (request.form.get("reason") or "").strip()[:300]
    adesso = utc_now_str()

    # Ritorno all'automatico: si azzera la dichiarazione e si ricalcola subito, perche'
    # una pagina che dice "automatico" mostrando ancora il tipo dichiarato mentirebbe.
    if scelto == RITORNO_AUTOMATICO:
        if (riga["device_type_source"] or "auto") != "manual":
            flash("Il tipo di %s e' gia' deciso dal riconoscimento automatico."
                  % riga["ip"], "info")
            return redirect(url_for("inventory.node", node_id=node_id))
        execute(
            "UPDATE nodes SET device_type_source = 'auto', device_type_by = NULL,"
            " device_type_at = NULL, device_type_reason = NULL, updated_at = ?"
            " WHERE id = ? AND tenant_id = ?", (adesso, node_id, tenant_id))
        verdetto = refresh_fingerprint(tenant_id, node_id)
        log_event("node.type.reverted",
                  "Tipo di %s restituito al riconoscimento automatico: %s"
                  % (riga["ip"], (verdetto or {}).get("device_label", "non identificato")),
                  tenant_id=tenant_id, entity="node", entity_id=node_id)
        flash("Tipo di %s deciso di nuovo dal riconoscimento: %s."
              % (riga["ip"], (verdetto or {}).get("device_label", "non identificato")),
              "success")
        return redirect(url_for("inventory.node", node_id=node_id))

    # Allowlist: i tipi sono quelli del catalogo, piu' "non identificato". Un tipo
    # inventato romperebbe filtri, conteggi e report, che sul tipo si appoggiano.
    ammessi = {c["key"]: c["label"] for c in DEVICE_CLASSES}
    ammessi[TIPO_NON_IDENTIFICATO] = ETICHETTA_NON_IDENTIFICATO
    if scelto not in ammessi:
        flash("Tipo di dispositivo non previsto: la scelta deve venire dal catalogo.",
              "warning")
        return redirect(url_for("inventory.node", node_id=node_id))

    etichetta = ammessi[scelto]
    precedente = riga["device_label"]
    execute(
        "UPDATE nodes SET device_type = ?, device_label = ?, device_confidence = 100,"
        " device_type_source = 'manual', device_type_by = ?, device_type_at = ?,"
        " device_type_reason = ?, last_change_at = ?, updated_at = ?"
        " WHERE id = ? AND tenant_id = ?",
        (scelto, etichetta, g.user["email"], adesso, motivo or None, adesso, adesso,
         node_id, tenant_id))

    # Il cambiamento entra nella storia del nodo come tutti gli altri: chi legge i
    # cambiamenti deve vedere anche quelli decisi da una persona.
    if (riga["device_type"] or "") != scelto:
        execute(
            "INSERT INTO node_changes (tenant_id, node_id, kind, subject, before_value,"
            " after_value, severity, created_at)"
            " VALUES (?, ?, 'device_type.declared', ?, ?, ?, 'info', ?)",
            (tenant_id, node_id, riga["ip"], precedente, etichetta, adesso))

    log_event("node.type.declared",
              "Tipo di %s dichiarato: %s (era %s)%s"
              % (riga["ip"], etichetta, precedente,
                 " - motivo: %s" % motivo if motivo else ""),
              tenant_id=tenant_id, entity="node", entity_id=node_id)
    flash("Tipo di %s dichiarato: %s. Il riconoscimento automatico continua a"
          " calcolare il proprio verdetto, che resta consultabile, ma non sovrascrive"
          " la dichiarazione." % (riga["ip"], etichetta), "success")
    return redirect(url_for("inventory.node", node_id=node_id))


@bp.post("/nodes/<int:node_id>/notes")
@role_required(ROLE_ANALYST)
def save_notes(node_id: int):
    tenant_id = current_tenant_id()
    if node_detail(tenant_id, node_id) is None:
        abort(404)
    execute("UPDATE nodes SET notes = ?, updated_at = ? WHERE id = ? AND tenant_id = ?",
            ((request.form.get("notes") or "").strip()[:1000], utc_now_str(), node_id, tenant_id))
    flash("Annotazione salvata.", "success")
    return redirect(url_for("inventory.node", node_id=node_id))


@bp.post("/nodes/<int:node_id>/scan")
@role_required(ROLE_ANALYST)
def scan_now(node_id: int):
    """Chiede alla sonda di eseguire subito una fase sul nodo indicato."""
    tenant_id = current_tenant_id()
    riga = node_detail(tenant_id, node_id)
    if riga is None:
        abort(404)
    fase = (request.form.get("stage") or "ports").strip()
    if fase not in REQUESTABLE_STAGES:
        flash("Fase di scansione non riconosciuta.", "warning")
        return redirect(url_for("inventory.node", node_id=node_id))
    if riga["probe_id"] is None:
        flash("Il nodo non e' associato ad alcuna sonda: impossibile richiedere la scansione.",
              "warning")
        return redirect(url_for("inventory.node", node_id=node_id))

    execute(
        "INSERT INTO probe_commands (tenant_id, probe_id, command, payload_json, status,"
        " created_by, created_at) VALUES (?, ?, 'scan', ?, 'pending', ?, ?)",
        (tenant_id, int(riga["probe_id"]),
         json.dumps({"stage": fase, "target": riga["ip"]}),
         int(g.user["id"]), utc_now_str()),
    )
    log_event("node.scan.requested",
              "Richiesta fase %s sul nodo %s" % (fase, riga["ip"]),
              tenant_id=tenant_id, entity="node", entity_id=node_id)
    flash("Fase %s richiesta: verra' eseguita al prossimo contatto della sonda." % fase, "info")
    return redirect(url_for("inventory.node", node_id=node_id))


def _smb_open_count(tenant_id: int) -> int:
    """Quanti nodi del tenant hanno una porta SMB (139/445) aperta."""
    riga = query(
        "SELECT COUNT(DISTINCT p.node_id) AS n FROM node_ports p"
        " JOIN nodes n ON n.id = p.node_id AND n.tenant_id = ?"
        " WHERE p.state = 'open' AND p.protocol = 'tcp' AND p.port IN (139, 445)",
        (tenant_id,), one=True)
    return int((riga or {"n": 0})["n"] or 0)


@bp.post("/smb/enumerate-all")
@role_required(ROLE_ANALYST)
def enumerate_all_smb():
    """Chiede a tutte le sonde di enumerare via SMB tutti i nodi con 139/445 aperta.

    Una passata SMB completa: invece di un lotto per ciclo, ogni sonda scorre l'intero
    elenco dei propri nodi SMB, a lotti ed entro un tempo massimo. Se non conclude in
    una volta, i restanti li prende la cadenza ordinaria, o un secondo clic.
    """
    tenant_id = current_tenant_id()
    aperti = _smb_open_count(tenant_id)
    if not aperti:
        flash("Nessun nodo con una porta SMB (139/445) aperta: non c'e' nulla da"
              " enumerare.", "info")
        return redirect(url_for("inventory.nodes"))

    sonde = query(
        "SELECT id, name, code, COALESCE(scan_enabled, 1) AS scan_enabled"
        " FROM probes WHERE tenant_id = ?", (tenant_id,))
    attive = [s for s in sonde if int(s["scan_enabled"] or 0)]
    if not attive:
        flash("Le scansioni sono sospese su tutte le sonde: la richiesta non verrebbe"
              " eseguita. Riprenderle e ripetere.", "warning")
        return redirect(url_for("inventory.nodes"))

    carico = json.dumps({"stage": "smb", "target": "@all"})
    accodate = 0
    for sonda in attive:
        # Non si accoda un doppione se una passata totale e' gia' in attesa.
        pendente = query(
            "SELECT id FROM probe_commands WHERE tenant_id = ? AND probe_id = ?"
            " AND command = 'scan' AND payload_json = ? AND status IN"
            " ('pending', 'delivered')", (tenant_id, int(sonda["id"]), carico),
            one=True)
        if pendente is not None:
            continue
        execute(
            "INSERT INTO probe_commands (tenant_id, probe_id, command, payload_json,"
            " status, created_by, created_at) VALUES (?, ?, 'scan', ?, 'pending', ?, ?)",
            (tenant_id, int(sonda["id"]), carico, int(g.user["id"]), utc_now_str()))
        accodate += 1

    log_event("inventory.smb.enumerate_all",
              "Enumerazione SMB su tutti i nodi richiesta a %d sonde (%d nodi con"
              " SMB aperto)" % (accodate, aperti),
              tenant_id=tenant_id, entity="node")
    if accodate:
        flash("Enumerazione SMB richiesta su tutti i %d nodi con 139/445 aperta"
              " (%d sonde). Viene eseguita a lotti dal prossimo contatto; se non"
              " conclude in una volta, i restanti seguono alla cadenza ordinaria."
              % (aperti, accodate), "info")
    else:
        flash("Un'enumerazione SMB su tutti i nodi era gia' in coda: non ne viene"
              " accodata un'altra.", "secondary")
    return redirect(url_for("inventory.nodes"))


@bp.post("/refingerprint")
@role_required(ROLE_TENANT_ADMIN)
def refingerprint():
    """Rideterminazione del tipo su tutto l'inventario, senza nuove scansioni."""
    tenant_id = current_tenant_id()
    esito = refingerprint_tenant(tenant_id)
    # I tipi dichiarati a mano si dichiarano a parte: senza questo numero l'operatore
    # non sa se la rideterminazione ha travolto le proprie dichiarazioni.
    dichiarati = esito.get("declared") or 0
    log_event("inventory.refingerprint",
              "Tipo rideterminato su %d nodi (%d cambiati, %d dichiarati e rispettati)"
              " con il catalogo %s"
              % (esito["nodes"], esito["changed"], dichiarati,
                 esito["catalog_version"]),
              tenant_id=tenant_id, entity="node")
    flash("Rideterminati %d nodi: %d hanno cambiato tipo (catalogo %s).%s"
          % (esito["nodes"], esito["changed"], esito["catalog_version"],
             " %d tipi dichiarati dall'operatore sono stati rispettati."
             % dichiarati if dichiarati else ""), "success")
    return redirect(url_for("inventory.nodes"))


# --------------------------------------------------------------------------- #
# Perimetro
# --------------------------------------------------------------------------- #
@bp.get("/subnets")
@login_required
def subnets():
    tenant_id = current_tenant_id()
    sonde = query(
        "SELECT COUNT(*) AS totali,"
        " SUM(CASE WHEN COALESCE(scan_enabled, 1) = 1 THEN 1 ELSE 0 END) AS attive"
        " FROM probes WHERE tenant_id = ?", (tenant_id,), one=True)
    return render_template(
        "inventory/subnets.html",
        subnets=subnets_list(tenant_id),
        summary=inventory_summary(tenant_id),
        zones=zones.catalogo(tenant_id),
        zone_summary=zones.summary(subnets_list(tenant_id)),
        max_hosts=MAX_HOSTS_PER_SUBNET,
        probes_total=int(sonde["totali"] or 0),
        probes_scanning=int(sonde["attive"] or 0),
    )


@bp.post("/subnets")
@role_required(ROLE_TENANT_ADMIN)
def upload_subnets():
    """Carica il perimetro da file di testo oppure da testo incollato."""
    tenant_id = current_tenant_id()
    documento = request.files.get("file")
    nome = "incollato"
    testo = ""

    if documento is not None and documento.filename:
        nome = documento.filename[:120]
        try:
            testo = documento.read().decode("utf-8", errors="replace")
        except OSError as errore:
            flash("File non leggibile: %s" % errore, "warning")
            return redirect(url_for("inventory.subnets"))
    else:
        testo = request.form.get("text") or ""

    if not testo.strip():
        flash("Nessun contenuto da importare: indicare un file oppure incollare le subnet.",
              "warning")
        return redirect(url_for("inventory.subnets"))

    try:
        esito = import_subnets(
            tenant_id=tenant_id,
            text=testo,
            source_file=nome,
            user_id=int(g.user["id"]),
            replace=bool(request.form.get("replace")),
            allow_public=bool(request.form.get("allow_public")),
        )
    except SubnetError as errore:
        flash("Perimetro rifiutato: %s" % errore, "warning")
        return redirect(url_for("inventory.subnets"))

    # Una rete piu' ampia del limite di una passata viene suddivisa: la cosa va detta,
    # altrimenti chi ha scritto una riga se ne ritrova sedici e non capisce perche'.
    for suddivisa in esito.get("split") or []:
        flash("%s (%d indirizzi) supera l'ampiezza di una singola passata: suddivisa in"
              " %d blocchi /%d. Il perimetro coperto e' lo stesso; cambia soltanto"
              " l'unita' di lavoro della sonda."
              % (suddivisa["value"], suddivisa["indirizzi"], suddivisa["blocchi"],
                 suddivisa["prefisso"]), "info")

    messaggio = ("Perimetro importato da %s: %d nuove, %d aggiornate, %d disabilitate, "
                 "%d indirizzi complessivi."
                 % (nome, len(esito["added"]), len(esito["updated"]),
                    len(esito["disabled"]), esito["total_hosts"]))
    flash(messaggio, "success")
    for errore in esito["errors"][:10]:
        flash("Riga %s rifiutata (%s): %s"
              % (errore["line"], errore["value"] or "-", errore["reason"]), "warning")
    if len(esito["errors"]) > 10:
        flash("Altre %d righe rifiutate: correggere il file e ripetere."
              % (len(esito["errors"]) - 10), "warning")
    return redirect(url_for("inventory.subnets"))


@bp.post("/scanning")
@role_required(ROLE_TENANT_ADMIN)
def toggle_tenant_scanning():
    """Abilita o disabilita le scansioni per tutte le sonde del tenant."""
    tenant_id = current_tenant_id()
    attive = query(
        "SELECT COUNT(*) AS n FROM probes WHERE tenant_id = ?"
        " AND COALESCE(scan_enabled, 1) = 1", (tenant_id,), one=True)
    ferma = int(attive["n"]) > 0
    execute("UPDATE probes SET scan_enabled = ?, updated_at = ? WHERE tenant_id = ?",
            (0 if ferma else 1, utc_now_str(), tenant_id))
    log_event(
        "tenant.scan.disabled" if ferma else "tenant.scan.enabled",
        "Scansioni %s per tutte le sonde del tenant" % ("sospese" if ferma else "riprese"),
        tenant_id=tenant_id, severity="warning" if ferma else "info", entity="probe",
    )
    flash("Scansioni %s per tutte le sonde del tenant." % ("sospese" if ferma else "riprese"),
          "warning" if ferma else "success")
    return redirect(url_for("inventory.subnets"))


def _selected_subnet_ids() -> list[int]:
    """Identificativi delle subnet scelte nel modulo.

    Le caselle delle pagine non visibili non arrivano nel modulo, perche' la
    tabella le stacca dal documento: la pagina invia quindi anche l'elenco
    completo delle scelte in un solo campo. Senza JavaScript arrivano invece le
    caselle vere, che in quel caso sono tutte presenti.
    """
    grezzi = list(request.form.getlist("subnet_ids"))
    elenco = (request.form.get("subnet_ids_csv") or "").strip()
    if elenco:
        grezzi.extend(elenco.split(","))
    identificativi = []
    for voce in grezzi:
        voce = (voce or "").strip()
        if not voce:
            continue
        try:
            numero = int(voce)
        except ValueError:
            # Una scelta illeggibile non si indovina: si scarta e si dichiara.
            current_app.logger.warning("Scelta di subnet non numerica ignorata: %r", voce)
            continue
        if numero not in identificativi:
            identificativi.append(numero)
    return identificativi


@bp.post("/subnets/toggle-all")
@role_required(ROLE_TENANT_ADMIN)
def toggle_all_subnets():
    """Attiva o disattiva le subnet scelte, o tutte se non ve n'e' alcuna scelta.

    Disattivarle tutte svuota il perimetro: le sonde non scansionano piu' nulla.
    Per questo l'azione arriva sempre da una conferma esplicita.
    """
    tenant_id = current_tenant_id()
    attiva = (request.form.get("state") or "").strip() == "on"
    scelte = _selected_subnet_ids()

    # La condizione e i parametri sono gli stessi per il conteggio e per la
    # modifica: cosi' cio' che si dichiara e cio' che si cambia coincidono.
    condizione = "tenant_id = ?"
    parametri: list = [tenant_id]
    if scelte:
        condizione += " AND id IN (%s)" % ",".join("?" * len(scelte))
        parametri.extend(scelte)

    conteggio = query(
        "SELECT COUNT(*) AS totali,"
        " SUM(CASE WHEN is_enabled = ? THEN 1 ELSE 0 END) AS da_cambiare"
        " FROM subnets WHERE " + condizione, [0 if attiva else 1] + parametri, one=True)
    totali = int(conteggio["totali"] or 0)
    da_cambiare = int(conteggio["da_cambiare"] or 0)

    if not totali:
        flash("Nessuna subnet fra quelle scelte appartiene al perimetro del tenant.",
              "warning")
        return redirect(url_for("inventory.subnets"))
    if not da_cambiare:
        flash("Nessuna subnet da %s: sono gia' tutte nello stato richiesto."
              % ("attivare" if attiva else "disattivare"), "info")
        return redirect(url_for("inventory.subnets"))

    execute("UPDATE subnets SET is_enabled = ?, updated_at = ? WHERE " + condizione,
            [1 if attiva else 0, utc_now_str()] + parametri)

    attive = query("SELECT COUNT(*) AS n FROM subnets WHERE tenant_id = ? AND is_enabled = 1",
                   (tenant_id,), one=True)
    rimaste = int(attive["n"] or 0)
    # L'evento distingue l'ambito: agire su tutto il perimetro non e' la stessa
    # cosa che agire su alcune subnet, e chi legge l'audit deve poterlo vedere.
    ambito = "selection" if scelte else "all"
    log_event(
        "subnets.%s.%s" % ("enabled" if attiva else "disabled", ambito),
        "%s %d subnet su %d %s: %d attive nel perimetro"
        % ("Attivate" if attiva else "Disattivate", da_cambiare, totali,
           "scelte" if scelte else "dichiarate", rimaste),
        tenant_id=tenant_id, severity="info" if attiva else "warning", entity="subnet",
    )
    flash("%s %d subnet.%s" % ("Attivate" if attiva else "Disattivate", da_cambiare,
                               "" if rimaste else " Il perimetro e' vuoto: le sonde non "
                               "scansionano piu' nulla."),
          "success" if rimaste else "warning")
    return redirect(url_for("inventory.subnets"))


@bp.post("/subnets/<int:subnet_id>/toggle")
@role_required(ROLE_TENANT_ADMIN)
def toggle_subnet(subnet_id: int):
    tenant_id = current_tenant_id()
    riga = query("SELECT * FROM subnets WHERE id = ? AND tenant_id = ?",
                 (subnet_id, tenant_id), one=True)
    if riga is None:
        abort(404)
    nuovo = 0 if int(riga["is_enabled"]) else 1
    execute("UPDATE subnets SET is_enabled = ?, updated_at = ? WHERE id = ? AND tenant_id = ?",
            (nuovo, utc_now_str(), subnet_id, tenant_id))
    log_event("subnet.enabled" if nuovo else "subnet.disabled",
              "Subnet %s %s" % (riga["cidr"], "attivata" if nuovo else "disattivata"),
              tenant_id=tenant_id, entity="subnet", entity_id=subnet_id)
    flash("Subnet %s %s." % (riga["cidr"], "attivata" if nuovo else "disattivata"), "success")
    return redirect(url_for("inventory.subnets"))


@bp.post("/subnets/<int:subnet_id>/scan")
@role_required(ROLE_ANALYST)
def scan_subnet_now(subnet_id: int):
    """Chiede subito una passata di scoperta sulla subnet indicata.

    La cadenza ordinaria della scoperta e' di giorni: quando si aggiunge una rete, si
    sposta un apparato o si sospetta che qualcosa sia comparso, aspettarla non ha
    senso. La fase e' `discovery` perche' e' la sola che accetta una rete come
    bersaglio; l'esame delle porte dei nodi trovati segue nel ciclo ordinario.
    """
    tenant_id = current_tenant_id()
    riga = query("SELECT * FROM subnets WHERE id = ? AND tenant_id = ?",
                 (subnet_id, tenant_id), one=True)
    if riga is None:
        abort(404)

    if not int(riga["is_enabled"] or 0):
        # Una subnet disattivata non fa parte del perimetro consegnato alle sonde: il
        # comando verrebbe rifiutato dalla sonda stessa. Si dice perche', non si accoda.
        flash("La subnet %s e' disattivata: non fa parte del perimetro consegnato alle"
              " sonde, che rifiuterebbero il bersaglio. Attivarla prima di chiedere la"
              " scansione." % riga["cidr"], "warning")
        return redirect(url_for("inventory.subnets"))

    proprietarie = [int(r["probe_id"]) for r in query(
        "SELECT DISTINCT probe_id FROM nodes"
        " WHERE tenant_id = ? AND subnet_id = ? AND probe_id IS NOT NULL",
        (tenant_id, subnet_id))]
    if proprietarie:
        sonde = query(
            "SELECT id, name, code, COALESCE(scan_enabled, 1) AS scan_enabled"
            " FROM probes WHERE tenant_id = ? AND id IN (%s)"
            % ",".join("?" * len(proprietarie)),
            tuple([tenant_id] + proprietarie))
    else:
        # Nessuna sonda ha ancora visto nulla qui: non si sa chi raggiunga questa rete,
        # e chiederlo a tutte e' l'unico modo di scoprirlo. La sonda che non la
        # raggiunge conclude senza host, che e' a sua volta un'informazione.
        sonde = query(
            "SELECT id, name, code, COALESCE(scan_enabled, 1) AS scan_enabled"
            " FROM probes WHERE tenant_id = ? ORDER BY id", (tenant_id,))

    if not sonde:
        flash("Nessuna sonda registrata per questo tenant: la scansione non ha chi"
              " eseguirla.", "warning")
        return redirect(url_for("inventory.subnets"))

    attive = [s for s in sonde if int(s["scan_enabled"] or 0)]
    if not attive:
        flash("Le scansioni sono sospese su tutte le sonde che potrebbero eseguirla:"
              " la richiesta non verrebbe eseguita. Riprendere le scansioni e"
              " ripetere.", "warning")
        return redirect(url_for("inventory.subnets"))

    carico = json.dumps({"stage": "discovery", "target": riga["cidr"]})
    accodate, gia_in_coda = [], []
    for sonda in attive:
        pendente = query(
            "SELECT id FROM probe_commands WHERE tenant_id = ? AND probe_id = ?"
            " AND command = 'scan' AND payload_json = ? AND status IN"
            " ('pending', 'delivered')",
            (tenant_id, int(sonda["id"]), carico), one=True)
        if pendente is not None:
            gia_in_coda.append(sonda["name"] or sonda["code"])
            continue
        execute(
            "INSERT INTO probe_commands (tenant_id, probe_id, command, payload_json,"
            " status, created_by, created_at) VALUES (?, ?, 'scan', ?, 'pending', ?, ?)",
            (tenant_id, int(sonda["id"]), carico, int(g.user["id"]), utc_now_str()))
        accodate.append(sonda["name"] or sonda["code"])

    if accodate:
        log_event("subnet.scan.requested",
                  "Richiesta scoperta immediata su %s (%d indirizzi) a: %s"
                  % (riga["cidr"], riga["host_count"] or 0, ", ".join(accodate)),
                  tenant_id=tenant_id, entity="subnet", entity_id=subnet_id)
        flash("Scoperta richiesta su %s (%d indirizzi) a %s: viene eseguita al"
              " prossimo contatto della sonda. L'esame delle porte dei nodi trovati"
              " segue nel ciclo ordinario."
              % (riga["cidr"], riga["host_count"] or 0,
                 ", ".join(accodate) if len(accodate) > 1
                 else accodate[0]), "info")
    if gia_in_coda:
        flash("Una scoperta su %s era gia' in coda per %s: non ne viene accodata"
              " un'altra." % (riga["cidr"], ", ".join(gia_in_coda)), "secondary")
    return redirect(url_for("inventory.subnets"))


@bp.post("/subnets/<int:subnet_id>/zone")
@role_required(ROLE_TENANT_ADMIN)
def set_subnet_zone(subnet_id: int):
    """Dichiara la zona di rete di una subnet.

    Cambiare zona cambia il giudizio sulle esposizioni gia' registrate: la
    correlazione successiva le rivaluta da se', e la pagina lo dice invece di
    lasciarlo scoprire.
    """
    tenant_id = current_tenant_id()
    riga = query("SELECT * FROM subnets WHERE id = ? AND tenant_id = ?",
                 (subnet_id, tenant_id), one=True)
    if riga is None:
        abort(404)

    # Allowlist: una zona non prevista non viene scritta, e non e' un errore da
    # mostrare -- vale la predefinita, che e' la piu' severa.
    scelta = zones.valida(request.form.get("zone"))
    execute("UPDATE subnets SET zone = ?, updated_at = ? WHERE id = ? AND tenant_id = ?",
            (scelta, utc_now_str(), subnet_id, tenant_id))
    voce = zones.zona(scelta)
    log_event("subnet.zone.changed",
              "Subnet %s dichiarata in zona %s" % (riga["cidr"], voce["nome"]),
              tenant_id=tenant_id, entity="subnet", entity_id=subnet_id)
    # Il messaggio dice anche COME farlo subito: "alla prossima correlazione" da solo
    # lascia l'operatore a chiedersi se deve aspettare o fare qualcosa.
    flash("Subnet %s: zona %s. La mappa della rete e i filtri la mostrano subito;"
          " le esposizioni gia' registrate vengono rivalutate alla prossima"
          " correlazione, oppure subito con Dispositivi > Riapplica ai dati gia'"
          " raccolti (passi \"correlazione\" e \"zone\")."
          % (riga["cidr"], voce["nome"]), "success")
    return redirect(url_for("inventory.subnets"))


@bp.post("/subnets/<int:subnet_id>/delete")
@role_required(ROLE_TENANT_ADMIN)
def delete_subnet(subnet_id: int):
    tenant_id = current_tenant_id()
    riga = query("SELECT * FROM subnets WHERE id = ? AND tenant_id = ?",
                 (subnet_id, tenant_id), one=True)
    if riga is None:
        abort(404)
    if (request.form.get("confirm") or "").strip() != riga["cidr"]:
        flash("Conferma non corrispondente: la subnet %s non e' stata rimossa. "
              "Digitare esattamente %s." % (riga["cidr"], riga["cidr"]), "warning")
        return redirect(url_for("inventory.subnets"))

    nodi = query("SELECT COUNT(*) AS n FROM nodes WHERE subnet_id = ?", (subnet_id,), one=True)
    execute("DELETE FROM subnets WHERE id = ? AND tenant_id = ?", (subnet_id, tenant_id))
    log_event("subnet.deleted",
              "Subnet %s rimossa dal perimetro (%d nodi restano in inventario senza subnet)"
              % (riga["cidr"], int(nodi["n"])),
              tenant_id=tenant_id, severity="warning", entity="subnet", entity_id=subnet_id)
    flash("Subnet %s rimossa. I %d nodi scoperti restano in inventario."
          % (riga["cidr"], int(nodi["n"])), "success")
    return redirect(url_for("inventory.subnets"))


# --------------------------------------------------------------------------- #
# Dati conferiti dalle sonde
# --------------------------------------------------------------------------- #
@bp.get("/deliveries")
@login_required
def deliveries():
    tenant_id = current_tenant_id()
    lotti = [dict(r) for r in
             deliveries_list(tenant_id, probe_id=request.args.get("probe", type=int))]
    for lotto in lotti:
        lotto["contenuto"] = _contenuto_lotto(lotto.get("detail"))
    return render_template(
        "inventory/deliveries.html",
        deliveries=lotti,
        probes=query("SELECT id, code, name FROM probes WHERE tenant_id = ? ORDER BY name",
                     (tenant_id,)),
        runs=scan_runs_list(tenant_id, limit=100),
        selected_probe=request.args.get("probe", type=int),
    )


# Come si chiamano i generi di record quando li legge una persona. Il JSON dei
# conteggi e' cio' che la sonda scrive per la console: mostrarlo cosi' com'e' vuol dire
# lasciare a chi guarda il lavoro di interpretarlo.
NOMI_RECORD = {
    "nodes": "nodi", "ports": "porte", "os": "sistemi", "scripts": "script",
    "snmp": "SNMP", "web": "pagine web", "monitor": "verifiche",
    "scan_runs": "fasi", "events": "eventi", "removals": "rimozioni",
    "check_results": "controlli",
}


def _contenuto_lotto(dettaglio) -> list:
    """I conteggi del lotto come coppie leggibili, senza le voci a zero.

    Le voci a zero non si mostrano: un lotto di controlli dichiarerebbe dieci generi
    vuoti, e l'unica informazione -- che porta due controlli -- si perderebbe in mezzo.
    """
    if not dettaglio:
        return []
    try:
        conteggi = json.loads(dettaglio)
    except (json.JSONDecodeError, TypeError):
        # Non e' JSON: e' un messaggio, e come messaggio si mostra.
        return [(str(dettaglio)[:200], None)]
    if not isinstance(conteggi, dict):
        return [(str(dettaglio)[:200], None)]
    voci = []
    for chiave, valore in conteggi.items():
        try:
            quanti = int(valore)
        except (TypeError, ValueError):
            continue
        if quanti:
            voci.append((NOMI_RECORD.get(chiave, chiave), quanti))
    return voci


@bp.get("/deliveries/<int:batch_id>")
@login_required
def delivery(batch_id: int):
    tenant_id = current_tenant_id()
    riga = delivery_detail(tenant_id, batch_id)
    if riga is None:
        abort(404)
    try:
        record = json.loads(riga["records_json"] or "{}")
    except json.JSONDecodeError:
        current_app.logger.warning("records_json non valido per il lotto %s", batch_id)
        record = {}
    try:
        conteggi = json.loads(riga["detail"] or "{}")
    except json.JSONDecodeError:
        conteggi = {}
    return render_template(
        "inventory/delivery.html",
        batch=riga,
        records=record,
        counters=conteggi,
        runs=scan_runs_list(tenant_id, batch_id=batch_id),
        pretty=json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True),
    )


# --------------------------------------------------------------------------- #
# Zone di rete: il catalogo lo governa l'operatore
# --------------------------------------------------------------------------- #
@bp.get("/zones")
@login_required
def zone_index():
    """Elenco delle zone, con quanto perimetro e quanti dispositivi riguardano.

    I conteggi sono la ragione per cui questa pagina si guarda: una zona dichiarata e
    mai usata e' un lavoro a meta', e una zona con cinquecento dispositivi non si
    elimina senza saperlo.
    """
    from ..zone_admin import TONI, elenco_per_pagina, senza_zona

    tenant_id = current_tenant_id()
    return render_template(
        "inventory/zones.html",
        zone=elenco_per_pagina(tenant_id),
        senza=senza_zona(tenant_id),
        famiglie=zones.famiglie_esposizione(),
        toni=TONI,
    )


@bp.post("/zones/create")
@role_required(ROLE_TENANT_ADMIN)
def zone_create():
    from ..zone_admin import ZonaError, crea

    tenant_id = current_tenant_id()
    try:
        chiave = crea(
            tenant_id,
            nome=request.form.get("nome"),
            descrizione=request.form.get("descrizione"),
            icona=request.form.get("icona"),
            tono=request.form.get("tono"),
            attese=request.form.getlist("attese"),
            violazioni=request.form.getlist("violazioni"),
            eredita_da=request.form.get("eredita_da"),
        )
    except ZonaError as errore:
        flash(str(errore), "danger")
        return redirect(url_for("inventory.zone_index"))

    log_event("zone.created",
              "Zona di rete creata: %s (%s)" % (request.form.get("nome"), chiave),
              tenant_id=tenant_id, entity="zone")
    flash("Zona creata. Va ora dichiarata sulle subnet che le appartengono: finche'"
          " nessuna la usa, non cambia nessun giudizio.", "success")
    return redirect(url_for("inventory.zone_index"))


@bp.post("/zones/<chiave>/update")
@role_required(ROLE_TENANT_ADMIN)
def zone_update(chiave: str):
    from ..zone_admin import ZonaError, aggiorna

    tenant_id = current_tenant_id()
    try:
        aggiorna(
            tenant_id, chiave,
            nome=request.form.get("nome"),
            descrizione=request.form.get("descrizione"),
            icona=request.form.get("icona"),
            tono=request.form.get("tono"),
            attese=request.form.getlist("attese"),
            violazioni=request.form.getlist("violazioni"),
        )
    except ZonaError as errore:
        flash(str(errore), "danger")
        return redirect(url_for("inventory.zone_index"))

    log_event("zone.updated", "Zona di rete modificata: %s" % chiave,
              tenant_id=tenant_id, entity="zone")
    flash("Zona aggiornata. I riscontri delle subnet in questa zona vengono"
          " rivalutati alla prossima correlazione.", "success")
    return redirect(url_for("inventory.zone_index"))


@bp.post("/zones/<chiave>/delete")
@role_required(ROLE_TENANT_ADMIN)
def zone_delete(chiave: str):
    """Elimina una zona; le subnet che la usavano vengono riassegnate.

    Senza una destinazione esplicita restano SENZA zona, che vale come rete di
    utenza: eliminando il contesto si perde la giustificazione, non la si eredita.
    """
    from ..zone_admin import ZonaError, elimina

    tenant_id = current_tenant_id()
    try:
        esito = elimina(tenant_id, chiave, riassegna_a=request.form.get("riassegna_a"))
    except ZonaError as errore:
        flash(str(errore), "danger")
        return redirect(url_for("inventory.zone_index"))

    log_event("zone.deleted",
              "Zona di rete eliminata: %s (%d subnet riassegnate a %s)"
              % (chiave, esito["subnet_riassegnate"],
                 esito["destinazione"] or "nessuna zona"),
              tenant_id=tenant_id, severity="warning", entity="zone")
    if esito["subnet_riassegnate"]:
        dove = ("in zona %s" % zones.zona(esito["destinazione"])["nome"]
                if esito["destinazione"]
                else "senza zona, cioe' al giudizio piu' severo")
        flash("Zona eliminata: %d subnet ora %s. Le esposizioni verranno rivalutate."
              % (esito["subnet_riassegnate"], dove), "warning")
    else:
        flash("Zona eliminata: nessuna subnet la usava.", "success")
    return redirect(url_for("inventory.zone_index"))


@bp.post("/zones/<chiave>/move")
@role_required(ROLE_TENANT_ADMIN)
def zone_move(chiave: str):
    """Sposta una zona di una posizione: l'ordine e' quello in cui si leggono."""
    from ..zone_admin import ZonaError, riordina

    try:
        riordina(current_tenant_id(), chiave,
                 1 if request.form.get("verso") == "giu" else -1)
    except ZonaError as errore:
        flash(str(errore), "danger")
    return redirect(url_for("inventory.zone_index"))


@bp.post("/zones/restore")
@role_required(ROLE_TENANT_ADMIN)
def zone_restore():
    """Riporta all'origine le zone nate col prodotto, senza toccare le altre."""
    from ..zone_admin import semina

    tenant_id = current_tenant_id()
    quante = semina(tenant_id, forzando=True)
    log_event("zone.restored", "Zone predefinite riportate all'origine (%d)" % quante,
              tenant_id=tenant_id, severity="warning", entity="zone")
    flash("Zone predefinite riportate all'origine: %d. Le zone create da te non sono"
          " state toccate." % quante, "success")
    return redirect(url_for("inventory.zone_index"))


# --------------------------------------------------------------------------- #
# Il dato grezzo di un dispositivo
# --------------------------------------------------------------------------- #
@bp.get("/nodes/<int:node_id>/web.pdf")
@login_required
def node_web_pdf(node_id: int):
    """PDF della lettura delle interfacce di gestione del dispositivo.

    Non e' l'immagine della pagina: il contenuto delle pagine non viene conservato
    (GDPR art. 5). E' tutto cio' che si conserva della lettura -- i fatti dichiarati,
    il percorso delle pagine aperte, le intestazioni, il certificato, le impronte -- in
    un documento che si allega a una richiesta di intervento o a un inventario.
    """
    import tempfile

    from ..reports.render_web_lettura import lettura_web

    tenant_id = current_tenant_id()
    riga = node_detail(tenant_id, node_id)
    if riga is None:
        abort(404)

    letture = [dict(r) for r in query(
        "SELECT port, scheme, status_code, title, server_header, generator, realm,"
        " brand, model, product, version, device_type, signature, cert_subject,"
        " cert_issuer, cert_expires, tls_version, login_form, device_name, location,"
        " host_name, serial, firmware, contact, pages_read, facts_locked, body_hash,"
        " error, details_json, collected_at"
        " FROM node_web WHERE tenant_id = ? AND node_id = ? ORDER BY port",
        (tenant_id, node_id))]
    if not letture:
        abort(404)

    for voce in letture:
        # Il percorso delle pagine sta nel dettaglio conservato: si tira fuori qui,
        # perche' e' la parte che rende verificabile ogni riga del documento.
        try:
            dettaglio = json.loads(voce.pop("details_json", None) or "{}")
        except (TypeError, ValueError):
            dettaglio = {}
        voce["pagine"] = dettaglio.get("pagine") or []

    tenant = query("SELECT name, code, timezone FROM tenants WHERE id = ?",
                   (tenant_id,), one=True)
    dati = {
        "tenant": {"id": tenant_id,
                   "nome": tenant["name"] if tenant else "",
                   "codice": tenant["code"] if tenant else "",
                   "fuso": (tenant["timezone"] if tenant else "") or "Europe/Rome"},
        "nodo": dict(riga),
        "letture": letture,
        "generato_utc": utc_now_str(),
        "intervallo": "fotografia del %s" % utc_now_str()[:10],
        "autore": (g.user or {})["email"] if getattr(g, "user", None) else "",
    }

    cartella = Path(tempfile.gettempdir()) / "snap-letture"
    cartella.mkdir(parents=True, exist_ok=True)
    percorso = cartella / ("snap-lettura-web-%s.pdf"
                           % str(riga["ip"]).replace(".", "-"))
    lettura_web(percorso, dati)

    log_event("node.web.pdf",
              "Lettura delle interfacce di %s scaricata in PDF" % riga["ip"],
              tenant_id=tenant_id, entity="node", entity_id=node_id)
    return send_file(percorso, mimetype="application/pdf", as_attachment=True,
                     download_name=percorso.name)


@bp.get("/nodes/<int:node_id>/json")
@login_required
def node_json(node_id: int):
    """Tutto cio' che si conserva sul dispositivo, in JSON.

    Due usi diversi dalla stessa rotta: senza parametri risponde come documento da
    leggere nel browser; con `?download=1` come allegato da salvare. Un solo posto in
    cui il documento si compone, due modi di consegnarlo.
    """
    from ..node_json import testo as documento_json

    tenant_id = current_tenant_id()
    contenuto = documento_json(tenant_id, node_id)
    if contenuto is None:
        abort(404)

    riga = node_detail(tenant_id, node_id)
    nome = "snap-nodo-%s.json" % (str(riga["ip"]).replace(".", "-") if riga else node_id)

    if request.args.get("download") == "1":
        log_event("node.json.downloaded",
                  "Dato grezzo del dispositivo %s scaricato" % (riga["ip"] if riga else node_id),
                  tenant_id=tenant_id, entity="node", entity_id=node_id)
        return Response(
            contenuto, mimetype="application/json; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=%s" % nome})

    # Nel browser si serve come testo semplice: un JSON di duecento kB dentro una
    # pagina con menu e schede si apre lento e non si copia bene.
    return Response(contenuto, mimetype="application/json; charset=utf-8")


# --------------------------------------------------------------------------- #
# Eliminazione in blocco del perimetro
# --------------------------------------------------------------------------- #
@bp.post("/subnets/delete-selected")
@role_required(ROLE_TENANT_ADMIN)
def delete_selected_subnets():
    """Elimina le subnet scelte dal perimetro.

    Perche' la conferma qui NON e' la digitazione del CIDR come per una subnet sola:
    trenta CIDR da ricopiare non sono una conferma, sono un ostacolo che si aggira
    smettendo di leggere. Si chiede invece il numero delle subnet scelte, che e' il
    dato che chi sbaglia selezione ha davanti agli occhi.

    I dispositivi NON si cancellano: restano in inventario senza subnet. Cancellare
    l'inventario insieme al perimetro sarebbe distruggere una raccolta di mesi per
    una modifica di configurazione, e nessuno se lo aspetterebbe da un'operazione
    che si chiama "rimuovi dal perimetro".
    """
    tenant_id = current_tenant_id()
    scelte = _selected_subnet_ids()
    if not scelte:
        flash("Nessuna subnet scelta: niente da rimuovere.", "info")
        return redirect(url_for("inventory.subnets"))

    righe = query(
        "SELECT id, cidr FROM subnets WHERE tenant_id = ? AND id IN (%s)"
        % ",".join("?" * len(scelte)), [tenant_id] + scelte)
    if not righe:
        flash("Nessuna subnet fra quelle scelte appartiene al perimetro del tenant.",
              "warning")
        return redirect(url_for("inventory.subnets"))

    atteso = str(len(righe))
    if (request.form.get("confirm") or "").strip() != atteso:
        flash("Conferma non corrispondente: digitare %s, cioe' il numero di subnet"
              " scelte. Nessuna subnet e' stata rimossa." % atteso, "warning")
        return redirect(url_for("inventory.subnets"))

    identificativi = [int(r["id"]) for r in righe]
    nodi = query(
        "SELECT COUNT(*) AS n FROM nodes WHERE tenant_id = ? AND subnet_id IN (%s)"
        % ",".join("?" * len(identificativi)), [tenant_id] + identificativi, one=True)
    quanti_nodi = int(nodi["n"] or 0) if nodi is not None else 0

    execute("DELETE FROM subnets WHERE tenant_id = ? AND id IN (%s)"
            % ",".join("?" * len(identificativi)), [tenant_id] + identificativi)

    elenco = ", ".join(r["cidr"] for r in righe[:8])
    if len(righe) > 8:
        elenco += ", e altre %d" % (len(righe) - 8)
    log_event("subnets.deleted",
              "Rimosse %d subnet dal perimetro (%s); %d dispositivi restano in"
              " inventario senza subnet" % (len(righe), elenco, quanti_nodi),
              tenant_id=tenant_id, severity="warning", entity="subnet")
    flash("Rimosse %d subnet dal perimetro. I %d dispositivi gia scoperti restano in"
          " inventario, senza subnet: la loro storia non si cancella con una"
          " modifica di configurazione." % (len(righe), quanti_nodi), "success")
    return redirect(url_for("inventory.subnets"))


# --------------------------------------------------------------------------- #
# Riapplicare il prodotto ai dati gia' raccolti
# --------------------------------------------------------------------------- #
@bp.post("/reprocess")
@role_required(ROLE_ANALYST)
def reprocess():
    """Rielabora l'archivio con le regole di oggi. Nessuna scansione.

    Serve dopo ogni miglioramento del prodotto -- una firma nuova, una zona
    dichiarata, un catalogo aggiornato: i dati raccolti ieri restano validi, ma le
    conclusioni tratte da essi no.
    """
    from ..rielabora import CHIAVI, rielabora

    tenant_id = current_tenant_id()
    scelti = [c for c in request.form.getlist("passi") if c in CHIAVI]
    esito = rielabora(tenant_id, passi=scelti or None,
                      attore=(g.user["email"] if getattr(g, "user", None) else None))

    righe = [dati.get("riassunto") for dati in esito["passi"].values()
             if isinstance(dati, dict) and dati.get("riassunto")]
    flash("Rielaborazione conclusa in %s s su %d dispositivi. %s"
          % (esito["durata_s"], esito["nodi"], " | ".join(righe)), "success")
    return redirect(request.referrer or url_for("inventory.nodes"))
