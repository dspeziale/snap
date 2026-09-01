# -----------------------------------------------------------------
# ipp_probe.py — identita' di una stampante letta con IPP (sola lettura)
# Autore: Daniele Speziale
# Data creazione: 2026-08-31
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap probe - Marca, modello, seriale e firmware di una stampante, via IPP.

Perche' serve
-------------
Alcune famiglie di apparati costruiscono la propria interfaccia web in JavaScript e
non servono nessun dato in HTML: la lettura delle pagine riconosce la marca (compare
nel codice della pagina) ma non il modello. Sul campo sono 382 apparati Kyocera con
`brand = Kyocera` e `model` vuoto.

Quegli stessi apparati rispondono a **IPP**, che e' il protocollo con cui ogni sistema
operativo identifica una stampante quando la si aggiunge. Su `10.10.33.32`, dove
l'HTML non dava niente, IPP restituisce:

    printer-make-and-model  : ECOSYS M5526cdn
    printer-info            : Kyocera ECOSYS M5526cdn
    printer-device-id       : MFG:Kyocera;MDL:ECOSYS M5526cdn;SER:...;CLS:PRINTER
    printer-firmware-...    : 2R7_2000.003.101A

Il compromesso, dichiarato
--------------------------
La lettura delle pagine web usa **solo GET**, per non correre il rischio di eseguire
per sbaglio un'azione. IPP, per come e' fatto il protocollo, viaggia su HTTP con un
**POST**: non esiste un modo GET di chiedere gli attributi.

La deroga e' ristretta a una sola operazione, scritta come costante e non
parametrizzabile: `Get-Printer-Attributes` (0x000B), che la specifica definisce di
sola lettura ed e' cio' che fa qualunque sistema operativo per riconoscere una
stampante. Nessuna operazione di stampa, nessuna scrittura di configurazione, nessuna
credenziale, nessun documento inviato. Il corpo della risposta non viene conservato:
restano i soli attributi riconosciuti (RFC 8011, ex RFC 2911).
"""

from __future__ import annotations

import re
import struct

# --------------------------------------------------------------------------- #
# Limiti e costanti di protocollo
# --------------------------------------------------------------------------- #
# L'unica operazione ammessa. Non e' un parametro: e' una costante del modulo, cosi'
# nessuna chiamata futura puo' trasformare questa lettura in una scrittura.
OPERAZIONE_ATTRIBUTI = 0x000B
VERSIONE_IPP = (1, 1)

PORTE_IPP = (631, 80, 443, 8631)
PERCORSI = ("/ipp/print", "/ipp", "/")
TIMEOUT_CONNESSIONE = 2.0
TIMEOUT_LETTURA = 4.0
MAX_RISPOSTA = 32768
MAX_TENTATIVI = 3
MAX_VALORE = 120
# Il `printer-device-id` (IEEE 1284) e' una stringa strutturata lunga: ha un tetto
# proprio, perche' i campi che interessano -- fra cui il numero di serie -- stanno
# in fondo, e con il tetto normale andrebbero perduti.
MAX_IDENTIFICATIVO = 512

# Attributi richiesti: solo identita' dell'apparato. Non si chiede lo stato dei
# materiali di consumo ne' la coda dei lavori -- la coda contiene i nomi dei documenti
# e degli utenti, cioe' dati personali di cui l'inventario non ha bisogno.
ATTRIBUTI_RICHIESTI = (
    "printer-make-and-model",
    "printer-info",
    "printer-location",
    "printer-name",
    "printer-dns-sd-name",
    "printer-firmware-string-version",
    "printer-serial-number",
    "printer-device-id",
)

# Corrispondenza con i fatti del prodotto (gli stessi nomi di `web_facts`).
FATTI = {
    "printer-make-and-model": "modello",
    "printer-info": "nome_dispositivo",
    "printer-location": "posizione",
    "printer-firmware-string-version": "firmware",
    "printer-serial-number": "seriale",
}

# Tag dei valori testuali di IPP: gli altri (interi, booleani, enumerazioni) non
# servono all'identita' e si saltano.
TAG_TESTUALI = {0x41, 0x42, 0x44, 0x45, 0x47, 0x48, 0x49}
TAG_INTERI = {0x21, 0x23}


def _testo(valore, massimo: int = MAX_VALORE) -> str:
    """Valore ripulito: una stringa corta, senza marcatura e senza spazi doppi."""
    if not valore:
        return ""
    if isinstance(valore, bytes):
        valore = valore.decode("utf-8", errors="replace")
    pulito = re.sub(r"\s+", " ", valore).strip().strip("\x00")
    if "<" in pulito or ">" in pulito:
        return ""
    return pulito[:massimo]


# --------------------------------------------------------------------------- #
# Costruzione della richiesta
# --------------------------------------------------------------------------- #
def costruisci_richiesta(ip: str, percorso: str, richiesta_id: int = 1) -> bytes:
    """Il corpo IPP di una `Get-Printer-Attributes`.

    Si scrive a mano perche' non vale una dipendenza in piu': sono venti righe di
    struttura fissa, e l'unica operazione che ci interessa e' una.
    """
    def attributo(tag: int, nome: str, valore: str) -> bytes:
        n = nome.encode("utf-8")
        v = valore.encode("utf-8")
        return (bytes([tag]) + struct.pack(">H", len(n)) + n
                + struct.pack(">H", len(v)) + v)

    corpo = bytes(VERSIONE_IPP)
    corpo += struct.pack(">H", OPERAZIONE_ATTRIBUTI)
    corpo += struct.pack(">I", richiesta_id)
    corpo += b"\x01"  # gruppo degli attributi di operazione
    corpo += attributo(0x47, "attributes-charset", "utf-8")
    corpo += attributo(0x48, "attributes-natural-language", "en")
    corpo += attributo(0x45, "printer-uri", "ipp://%s%s" % (ip, percorso))
    primo, *altri = ATTRIBUTI_RICHIESTI
    corpo += attributo(0x44, "requested-attributes", primo)
    for nome in altri:
        # Valore aggiuntivo dello stesso attributo: nome vuoto, come vuole il formato.
        v = nome.encode("utf-8")
        corpo += b"\x44" + struct.pack(">H", 0) + struct.pack(">H", len(v)) + v
    corpo += b"\x03"  # fine degli attributi
    return corpo


# --------------------------------------------------------------------------- #
# Lettura della risposta
# --------------------------------------------------------------------------- #
def interpreta_risposta(dati: bytes) -> dict:
    """Attributi testuali della risposta IPP, per nome.

    Non solleva: una risposta troncata o malformata restituisce cio' che si e' potuto
    leggere. Un apparato che risponde male non deve fermare la passata.
    """
    attributi = {}
    if not dati or len(dati) < 9:
        return attributi

    posizione = 8  # versione (2) + codice di stato (2) + id richiesta (4)
    nome_corrente = ""
    while posizione < len(dati):
        tag = dati[posizione]
        posizione += 1
        if tag == 0x03:      # fine degli attributi
            break
        if tag < 0x10:       # delimitatore di gruppo
            nome_corrente = ""
            continue
        if posizione + 2 > len(dati):
            break
        lunghezza_nome = struct.unpack(">H", dati[posizione:posizione + 2])[0]
        posizione += 2
        if posizione + lunghezza_nome > len(dati):
            break
        nome = dati[posizione:posizione + lunghezza_nome].decode("utf-8", "replace")
        posizione += lunghezza_nome
        if posizione + 2 > len(dati):
            break
        lunghezza_valore = struct.unpack(">H", dati[posizione:posizione + 2])[0]
        posizione += 2
        if posizione + lunghezza_valore > len(dati):
            break
        grezzo = dati[posizione:posizione + lunghezza_valore]
        posizione += lunghezza_valore

        if nome:
            nome_corrente = nome
        if not nome_corrente:
            continue
        if tag in TAG_TESTUALI:
            # Si conserva per intero: e' chi legge i fatti a decidere il tetto,
            # e per l'identificativo il tetto e' diverso.
            valore = _testo(grezzo, massimo=MAX_IDENTIFICATIVO)
            if valore and nome_corrente not in attributi:
                attributi[nome_corrente] = valore
        elif tag in TAG_INTERI and lunghezza_valore == 4:
            attributi.setdefault(nome_corrente,
                                 str(struct.unpack(">i", grezzo)[0]))
    return attributi


def fatti_da_attributi(attributi: dict) -> dict:
    """I fatti del prodotto ricavati dagli attributi IPP.

    `printer-device-id` e' la fonte piu' precisa quando c'e': e' la stringa IEEE 1284
    che l'apparato usa per farsi riconoscere, e contiene costruttore, modello e
    numero di serie separati -- senza doverli indovinare da un nome unico.
    """
    from . import web_facts

    fatti = {}
    for chiave, fatto in FATTI.items():
        valore = _testo(attributi.get(chiave), massimo=MAX_VALORE)
        if valore:
            fatti[fatto] = valore

    identificativo = _testo(attributi.get("printer-device-id"),
                            massimo=MAX_IDENTIFICATIVO)
    if identificativo:
        campi = {}
        for pezzo in identificativo.split(";"):
            if ":" in pezzo:
                etichetta, valore = pezzo.split(":", 1)
                campi[etichetta.strip().upper()] = _testo(valore)
        if campi.get("MFG"):
            fatti["marca_dichiarata"] = campi["MFG"]
        if campi.get("MDL"):
            fatti["modello"] = campi["MDL"]
        if campi.get("SER"):
            fatti["seriale"] = campi["SER"]
        if campi.get("DES") and "nome_dispositivo" not in fatti:
            fatti["nome_dispositivo"] = campi["DES"]

    # Il nome della coda ("KM12C1BAB") non e' un nome host: si tiene solo se non c'e'
    # niente di meglio, e senza spacciarlo per altro.
    if "nome_dispositivo" not in fatti and attributi.get("printer-name"):
        fatti["nome_dispositivo"] = _testo(attributi["printer-name"])

    identita = web_facts.marca_e_modello(fatti)
    if identita.get("marca"):
        fatti.setdefault("marca_dichiarata", identita["marca"])
    if identita.get("modello"):
        fatti["modello"] = identita["modello"]
    return fatti


# --------------------------------------------------------------------------- #
# Interrogazione di un apparato
# --------------------------------------------------------------------------- #
def porte_ipp(porte_aperte) -> list:
    """Porte su cui provare IPP, in ordine di probabilita'.

    Si guarda anche il nome del servizio: molti apparati espongono IPP sulla 631, ma
    alcuni lo servono sulla 80 sotto `/ipp/print`, e nmap lo dichiara.
    """
    scelte = []
    for porta in porte_aperte or []:
        try:
            numero = int(porta.get("port"))
        except (TypeError, ValueError):
            continue
        if (porta.get("protocol") or "tcp") != "tcp" or porta.get("state") != "open":
            continue
        servizio = (porta.get("service_name") or "").lower()
        if numero in PORTE_IPP or "ipp" in servizio:
            scelte.append(numero)
    # La 631 prima delle altre: e' la porta dedicata, e risponde senza ambiguita'.
    return sorted(set(scelte), key=lambda n: (n != 631, n))


def leggi(ip: str, porte_aperte) -> dict:
    """Identita' di una stampante via IPP. Restituisce {} se non risponde.

    Non solleva: un apparato che non parla IPP e' la normalita', non un guasto.
    """
    import requests
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    tentativi = 0
    for porta in porte_ipp(porte_aperte):
        schema = "https" if porta in (443, 8443) else "http"
        for percorso in PERCORSI:
            if tentativi >= MAX_TENTATIVI:
                return {}
            tentativi += 1
            indirizzo = "%s://%s:%d%s" % (schema, ip, porta, percorso)
            try:
                risposta = requests.post(
                    indirizzo,
                    data=costruisci_richiesta(ip, percorso),
                    timeout=(TIMEOUT_CONNESSIONE, TIMEOUT_LETTURA),
                    verify=False,
                    stream=True,
                    headers={"Content-Type": "application/ipp",
                             "User-Agent": "snap-probe/1.0 (inventario di rete)"},
                )
            except Exception:  # noqa: BLE001 - non parla IPP: si prova il prossimo
                continue

            try:
                if risposta.status_code >= 400:
                    continue
                dati = risposta.raw.read(MAX_RISPOSTA, decode_content=True) or b""
            except Exception:  # noqa: BLE001 - risposta illeggibile
                continue
            finally:
                risposta.close()

            attributi = interpreta_risposta(dati)
            fatti = fatti_da_attributi(attributi)
            if not fatti.get("modello") and not fatti.get("nome_dispositivo"):
                continue
            return {
                "port": porta,
                "protocol": "tcp",
                "scheme": "ipp",
                "url": indirizzo,
                "stato": int(risposta.status_code),
                "fatti": fatti,
                "attributi_letti": len(attributi),
                "tipo_probabile": "printer",
                "firma": "ipp",
                "prodotto": "IPP (%s)" % (fatti.get("marca_dichiarata") or "stampante"),
                "marca": fatti.get("marca_dichiarata") or "",
                "modello": fatti.get("modello") or "",
                "pagine_lette": 1,
            }
    return {}
