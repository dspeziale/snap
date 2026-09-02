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
