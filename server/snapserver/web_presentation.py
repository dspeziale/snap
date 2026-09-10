# -----------------------------------------------------------------
# web_presentation.py — presentazione dei fatti letti dalle pagine web e dei certificati
# Autore: Daniele Speziale
# Data creazione: 2026-09-02
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Come si leggono i dati raccolti navigando un apparato.

Un apparato dichiara di se' molto piu' di quanto entri nelle colonne dedicate:
un telefono IP Cisco espone interno, carichi software, revisione hardware e
gestore chiamate; uno UPS MGE/Eaton espone alimentazione, carico e stato della
batteria oltre alla diagnosi ricavata dai propri registri; un HTTPS espone un
certificato con soggetto, emittente, validita', chiave, usi e impronte.

Questi dati vengono conservati in forma grezza (JSON) e qui diventano coppie
(etichetta leggibile, valore) in un ordine stabile. La stessa presentazione serve
al dettaglio del nodo nella console e alla scheda PDF dell'apparato: sta qui, in un
punto solo, perche' le due viste non divergano.
"""

from __future__ import annotations

import json

# Etichette leggibili per i fatti dichiarati dall'apparato che non hanno gia' un
# campo dedicato. L'ordine e' quello di lettura.
ETICHETTE_FATTI_WEB = {
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
# Esito atteso quando la diagnosi dei registri non trova nulla di anomalo.
DIAGNOSI_OK = "Nessun problema rilevato"
# Fatti gia' esposti come campo dedicato: non vanno ripetuti fra i "dati aggiuntivi".
FATTI_WEB_GIA_MOSTRATI = frozenset((
    "nome_dispositivo", "modello", "posizione", "nome_host", "seriale", "firmware",
    "contatto", "marca_dichiarata",
))


# --------------------------------------------------------------------------- #
# L'indirizzo con cui aprire l'interfaccia di un apparato
# --------------------------------------------------------------------------- #
# Chi guarda la scheda di un nodo e vede la 80 o la 443 aperta vuole aprirla: e'
# il gesto successivo naturale, e senza un collegamento si ricopia l'indirizzo a
# mano. Le porte e lo schema sono gli stessi che usa la sonda per leggere le
# pagine di gestione (`web_probe.PORTE_HTTPS`), cosi' console e sonda non
# divergono su cosa sia "web".
PORTE_HTTPS = frozenset({443, 8443, 4443, 9443, 10443, 8834, 7443, 5986})
PORTE_HTTP = frozenset({80, 81, 88, 591, 3000, 5000, 7080, 8000, 8001, 8008,
                        8080, 8081, 8082, 8083, 8088, 8090, 8180, 8181, 8280,
                        8888, 9080, 9090, 10000})
# Nomi di servizio che dichiarano un'interfaccia web anche su una porta inattesa:
# un apparato puo' esporre la propria pagina di gestione dove vuole.
SERVIZI_WEB = ("http", "https", "http-alt", "https-alt", "http-proxy", "ssl/http",
               "http-mgmt", "caldav", "wsdapi")


def indirizzo_web(ip: str, porta: dict) -> str | None:
    """L'indirizzo con cui aprire questa porta nel browser, o None se non e' web.

    Restituisce None quando la porta non e' un'interfaccia web: un collegamento
    che apre una pagina di errore e' peggio di nessun collegamento.
    """
    if not ip or (porta.get("state") or "") != "open":
        return None
    if (porta.get("protocol") or "").lower() != "tcp":
        return None
    try:
        numero = int(porta.get("port"))
    except (TypeError, ValueError):
        return None

    servizio = (porta.get("service_name") or "").strip().lower()
    cifrata = numero in PORTE_HTTPS or "https" in servizio or servizio.startswith("ssl")
    e_web = (numero in PORTE_HTTPS or numero in PORTE_HTTP
             or servizio in SERVIZI_WEB or servizio.startswith("http"))
    if not e_web:
        return None

    schema = "https" if cifrata else "http"
    # La porta predefinita non si scrive: l'indirizzo resta quello che l'operatore
    # avrebbe digitato.
    if (schema == "https" and numero == 443) or (schema == "http" and numero == 80):
        return "%s://%s/" % (schema, ip)
    return "%s://%s:%d/" % (schema, ip, numero)


def fatti_aggiuntivi(facts_json: str | None) -> list[dict]:
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
    for chiave, etichetta in ETICHETTE_FATTI_WEB.items():
        valore = fatti.get(chiave)
        if chiave in FATTI_WEB_GIA_MOSTRATI or not valore:
            continue
        aggiuntivi.append({"etichetta": etichetta, "valore": str(valore)})
    return aggiuntivi


def diagnosi_web(facts_json: str | None) -> dict:
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
    if testo == DIAGNOSI_OK:
        return {"problemi": [], "ok": True}
    return {"problemi": [p.strip() for p in testo.split(";") if p.strip()], "ok": False}


# Etichette leggibili per i dati del certificato TLS, nell'ordine in cui si leggono
# davanti a un certificato: chi, chi lo ha emesso, per quanto e' valido, com'e' fatto.
ETICHETTE_CERT = (
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
CERT_MONOSPAZIO = frozenset(("cert_seriale", "cert_sha256", "cert_sha1"))
CERT_ELENCHI = frozenset(("cert_uso", "cert_uso_esteso", "cert_nomi", "cert_nomi_ip"))


def certificato_leggibile(cert_json: str | None) -> dict:
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
    for chiave, etichetta in ETICHETTE_CERT:
        valore = cert.get(chiave)
        if valore in (None, "", [], {}):
            continue
        if chiave in CERT_ELENCHI and isinstance(valore, list):
            valore = ", ".join(str(v) for v in valore)
        righe.append({"etichetta": etichetta, "valore": str(valore),
                      "monospazio": chiave in CERT_MONOSPAZIO})
    return {
        "righe": righe,
        "autofirmato": bool(cert.get("cert_autofirmato")),
        "scaduto": bool(cert.get("cert_scaduto")),
        "non_ancora_valido": bool(cert.get("cert_non_ancora_valido")),
    }


# Che cosa mostrare nella colonna "Info" dell'elenco dei nodi, in ordine di valore.
# L'ordine e' quello dell'utilita' per chi guarda un elenco: che cos'e' (prodotto,
# modello), come si chiama, DOVE STA fisicamente -- che e' l'informazione che nessuna
# altra fase puo' dare -- e come si presenta.
CAMPI_INFO_WEB = (
    ("product", "prodotto", None),
    ("model", "modello", None),
    ("device_name", "nome", None),
    ("location", "posizione", "bi-geo-alt"),
    ("firmware", "firmware", None),
    ("title", "titolo della pagina", None),
    ("server_header", "server web", None),
)
# Quante voci stanno in una cella prima di diventare illeggibili.
MAX_VOCI_INFO = 3
MAX_TESTO_INFO = 42


def riassunto_web(pagine) -> list:
    """Le informazioni piu' utili raccolte dalle interfacce web, per una cella.

    Sono le stesse che il dettaglio del nodo mostra per intero: qui si scelgono le
    prime `MAX_VOCI_INFO` per valore informativo, senza ripetere lo stesso testo su
    piu' porte -- una multifunzione con la 80 e la 443 dichiara due volte le stesse
    cose, e in un elenco quella ripetizione occupa la riga senza aggiungere nulla.

    Restituisce una lista di `{"campo", "etichetta", "valore", "icona", "porta"}`.
    """
    scelte = []
    visti = set()
    for campo, etichetta, icona in CAMPI_INFO_WEB:
        for pagina in pagine or []:
            valore = (pagina.get(campo) or "").strip()
            if not valore:
                continue
            confronto = valore.lower()
            if confronto in visti:
                continue
            visti.add(confronto)
            testo = valore if len(valore) <= MAX_TESTO_INFO else \
                valore[:MAX_TESTO_INFO - 1].rstrip() + "…"
            scelte.append({"campo": campo, "etichetta": etichetta, "valore": testo,
                           "completo": valore, "icona": icona,
                           "porta": pagina.get("port")})
            break  # un campo una volta: la prima porta che lo dichiara basta
        if len(scelte) >= MAX_VOCI_INFO:
            break
    return scelte
