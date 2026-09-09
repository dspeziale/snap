# -----------------------------------------------------------------
# snmp.py — client SNMPv2c minimo: interrogazione delle tabelle degli apparati
# Autore: Daniele Speziale
# Data creazione: 2026-09-09
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap probe - Lettura delle tabelle SNMP di router e switch.

PERCHE' ESISTE
--------------
Il MAC di un apparato si ottiene con ARP, che e' protocollo di livello 2 e NON
attraversa un router: una sonda vede i MAC del proprio segmento e di nessun altro.
Misurato su una rete reale: 7309 nodi in inventario, 39 MAC -- tutti e 39 nella
subnet della sonda.

Gli apparati di rete invece conoscono quelle corrispondenze per l'intero segmento a
cui sono attestati, e le espongono in SNMP:

    ipNetToMediaPhysAddress  1.3.6.1.2.1.4.22.1.2   IP -> MAC (tabella ARP)
    dot1dTpFdbPort           1.3.6.1.2.1.17.4.3.1.2 MAC -> porta dello switch

Interrogare un router da fuori del suo segmento e' l'unico modo di avere quei dati
su una rete instradata.

PERCHE' SCRITTO A MANO E NON CON UNA LIBRERIA
---------------------------------------------
Alternative valutate:

* `pysnmp` -- copre tutto (v3, MIB compilati) ma e' una dipendenza grande, con una
  storia di manutenzione discontinua e piu' fork in circolazione: su un prodotto
  destinato alla PA la catena di fornitura conta e va dichiarata in SBOM.
* `snmpwalk` di net-snmp installato nell'immagine -- maturo e mantenuto dalla
  distribuzione, ma esisterebbe SOLO nel container: la sonda gira anche nativa su
  Windows, dove non c'e', e la funzione risulterebbe presente o assente a seconda
  di come e' stata installata la sonda. Un comportamento che dipende dal modo di
  installazione e' un difetto in attesa.
* SNMPv2c a mano, qui -- NESSUNA dipendenza nuova, identico su Windows e in
  container. Il costo e' codificare BER, che per un GetNext con un solo
  variable-binding e' un formato piccolo e interamente specificato (RFC 3416).

Si e' scelta la terza.

LIMITE DA CONOSCERE: questo modulo parla SNMPv2c, che NON e' cifrato e si autentica
con una community che viaggia in chiaro. Va usato con community di SOLA LETTURA e su
reti dove il traffico di gestione e' segregato. Per SNMPv3 (cifrato, con utenze)
servira' una libreria, e a quel punto la si valuta con i suoi numeri.
"""

from __future__ import annotations

import socket
import time

# --- tag BER usati da SNMP -------------------------------------------------
INTEGER = 0x02
OCTET_STRING = 0x04
NULL = 0x05
OID = 0x06
SEQUENCE = 0x30
IP_ADDRESS = 0x40
COUNTER32 = 0x41
GAUGE32 = 0x42
TIMETICKS = 0x43
COUNTER64 = 0x46
NO_SUCH_OBJECT = 0x80
NO_SUCH_INSTANCE = 0x81
END_OF_MIB_VIEW = 0x82

GET_NEXT_REQUEST = 0xA1
RESPONSE = 0xA2

VERSION_2C = 1

# Tabelle che interessano all'inventario.
OID_IP_NET_TO_MEDIA_PHYS = "1.3.6.1.2.1.4.22.1.2"   # IP -> MAC (ARP dell'apparato)
OID_SYS_DESCR = "1.3.6.1.2.1.1.1"                    # descrizione (ramo)
OID_SYS_NAME = "1.3.6.1.2.1.1.5"                     # nome (ramo)

# --- da MAC a PORTA FISICA: serve una catena di tre tabelle ----------------
#
# La tabella di forwarding NON da' il nome dell'interfaccia: da' un "numero di porta
# bridge", che e' un indice interno del MIB e non corrisponde ne' al numero stampato
# sullo chassis ne' all'ifIndex. Riportarlo come sta significherebbe scrivere in
# inventario "porta 47" senza che nessuno possa trovarla.
#
#   1. dot1dTpFdbPort        MAC          -> porta bridge
#   2. dot1dBasePortIfIndex  porta bridge -> ifIndex
#   3. ifName (o ifDescr)    ifIndex      -> "GigabitEthernet1/0/12"
#
# Gli switch con VLAN spesso popolano solo la versione Q-BRIDGE (dot1q), indicizzata
# per VLAN + MAC: si provano entrambe, perche' quale delle due sia popolata dipende
# dall'apparato e non e' prevedibile.
OID_DOT1D_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"        # MAC -> porta bridge
OID_DOT1Q_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"    # VLAN+MAC -> porta bridge
OID_DOT1D_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"   # porta bridge -> ifIndex
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"               # ifIndex -> nome breve
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"                 # ifIndex -> descrizione

# Limite di sicurezza: un apparato che risponde sempre lo stesso OID manderebbe il
# ciclo all'infinito. Ventimila voci ARP sono molto piu' del previsto su una rete
# come quella per cui il prodotto e' fatto.
MAX_PASSI = 20000


class SnmpError(Exception):
    """L'apparato non risponde, o risponde in un modo non utilizzabile."""


# --------------------------------------------------------------------------- #
# Codifica BER
# --------------------------------------------------------------------------- #
def _lunghezza(n: int) -> bytes:
    """Campo lunghezza BER: forma breve fino a 127, poi forma lunga."""
    if n < 0x80:
        return bytes([n])
    grezzo = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(grezzo)]) + grezzo


def _tlv(tag: int, contenuto: bytes) -> bytes:
    return bytes([tag]) + _lunghezza(len(contenuto)) + contenuto


def _intero(valore: int) -> bytes:
    """INTEGER in complemento a due, nella forma piu' corta (come esige BER)."""
    lunghezza = (valore + (1 if valore < 0 else 0)).bit_length() // 8 + 1
    return _tlv(INTEGER, valore.to_bytes(lunghezza, "big", signed=True))


def codifica_oid(testo: str) -> bytes:
    """OBJECT IDENTIFIER: i primi due archi in un byte solo, poi base 128."""
    parti = [int(p) for p in testo.strip(".").split(".")]
    if len(parti) < 2:
        raise SnmpError("OID non valido: %r" % testo)
    corpo = bytearray([parti[0] * 40 + parti[1]])
    for arco in parti[2:]:
        if arco < 0x80:
            corpo.append(arco)
            continue
        pezzi = []
        while arco:
            pezzi.insert(0, (arco & 0x7F) | 0x80)
            arco >>= 7
        pezzi[-1] &= 0x7F
        corpo.extend(pezzi)
    return _tlv(OID, bytes(corpo))


def decodifica_oid(corpo: bytes) -> str:
    """Inverso di `codifica_oid`."""
    if not corpo:
        raise SnmpError("OID vuoto")
    archi = [corpo[0] // 40, corpo[0] % 40]
    valore = 0
    for byte in corpo[1:]:
        valore = (valore << 7) | (byte & 0x7F)
        if not byte & 0x80:
            archi.append(valore)
            valore = 0
    return ".".join(str(a) for a in archi)


# --------------------------------------------------------------------------- #
# Decodifica
# --------------------------------------------------------------------------- #
def _leggi_tlv(dati: bytes, i: int) -> tuple[int, bytes, int]:
    """Restituisce (tag, contenuto, indice successivo)."""
    if i + 2 > len(dati):
        raise SnmpError("risposta troncata")
    tag = dati[i]
    lung = dati[i + 1]
    i += 2
    if lung & 0x80:
        quanti = lung & 0x7F
        if quanti == 0 or i + quanti > len(dati):
            raise SnmpError("lunghezza indefinita o troncata")
        lung = int.from_bytes(dati[i:i + quanti], "big")
        i += quanti
    if i + lung > len(dati):
        raise SnmpError("contenuto troncato")
    return tag, dati[i:i + lung], i + lung


def _valore(tag: int, corpo: bytes):
    """Valore Python di un variable-binding, secondo il tipo SNMP."""
    if tag == INTEGER:
        return int.from_bytes(corpo, "big", signed=True)
    if tag in (COUNTER32, GAUGE32, TIMETICKS, COUNTER64):
        return int.from_bytes(corpo, "big")
    if tag == IP_ADDRESS:
        return ".".join(str(b) for b in corpo) if len(corpo) == 4 else corpo.hex()
    if tag == OID:
        return decodifica_oid(corpo)
    if tag in (NULL, NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW):
        return None
    # OCTET STRING e il resto restano BYTE: un MAC non e' testo, e decodificarlo
    # come UTF-8 lo distruggerebbe.
    return corpo


def analizza_risposta(pacchetto: bytes) -> tuple[int, list]:
    """(request-id, [(oid, valore), ...]) da un messaggio di risposta."""
    tag, corpo, _ = _leggi_tlv(pacchetto, 0)
    if tag != SEQUENCE:
        raise SnmpError("il messaggio non e' una SEQUENCE")
    i = 0
    _, _, i = _leggi_tlv(corpo, i)            # version
    _, _, i = _leggi_tlv(corpo, i)            # community
    tag_pdu, pdu, _ = _leggi_tlv(corpo, i)
    if tag_pdu != RESPONSE:
        raise SnmpError("PDU inattesa: 0x%02x" % tag_pdu)

    j = 0
    _, rid, j = _leggi_tlv(pdu, j)
    _, stato, j = _leggi_tlv(pdu, j)
    _, _indice, j = _leggi_tlv(pdu, j)
    codice = int.from_bytes(stato, "big")
    if codice:
        raise SnmpError("l'apparato ha risposto con errore %d" % codice)

    tag_lista, lista, _ = _leggi_tlv(pdu, j)
    if tag_lista != SEQUENCE:
        raise SnmpError("variable-bindings non e' una SEQUENCE")

    coppie = []
    k = 0
    while k < len(lista):
        _, binding, k = _leggi_tlv(lista, k)
        m = 0
        tag_oid, corpo_oid, m = _leggi_tlv(binding, m)
        if tag_oid != OID:
            raise SnmpError("variable-binding senza OID")
        tag_val, corpo_val, _ = _leggi_tlv(binding, m)
        coppie.append((decodifica_oid(corpo_oid), _valore(tag_val, corpo_val)))
    return int.from_bytes(rid, "big"), coppie


def messaggio_getnext(community: str, oid: str, request_id: int) -> bytes:
    """Messaggio GetNextRequest per un solo variable-binding."""
    binding = _tlv(SEQUENCE, codifica_oid(oid) + _tlv(NULL, b""))
    pdu = _tlv(GET_NEXT_REQUEST,
               _intero(request_id) + _intero(0) + _intero(0)
               + _tlv(SEQUENCE, binding))
    return _tlv(SEQUENCE,
                _intero(VERSION_2C)
                + _tlv(OCTET_STRING, community.encode("utf-8"))
                + pdu)


# --------------------------------------------------------------------------- #
# Interrogazione
# --------------------------------------------------------------------------- #
def sotto_albero(oid: str, radice: str) -> bool:
    """L'OID appartiene ancora al sotto-albero richiesto?

    Il confronto e' sui NODI e non sul testo: "1.3.6.1.2.1.4.22" non e' figlio di
    "1.3.6.1.2.1.4.2" anche se ne e' un prefisso come stringa.
    """
    a = [int(x) for x in oid.strip(".").split(".")]
    b = [int(x) for x in radice.strip(".").split(".")]
    return a[:len(b)] == b


def walk(host: str, community: str, radice: str, porta: int = 161,
         timeout: float = 2.0, tentativi: int = 2,
         limite: int = MAX_PASSI) -> list[tuple[str, object]]:
    """Percorre un sotto-albero con GetNext e restituisce le coppie (oid, valore).

    Un GetNext per volta e non GetBulk: e' piu' lento ma lo capiscono anche gli
    apparati vecchi, che sono esattamente quelli che ancora espongono SNMPv2c.

    Il ciclo si ferma quando l'OID esce dal sotto-albero, quando l'apparato non
    avanza (ripete lo stesso OID) e in ogni caso al limite dichiarato: un apparato
    che risponde male non deve tenere occupata la sonda per sempre.
    """
    risultati: list[tuple[str, object]] = []
    corrente = radice
    request_id = int(time.time()) & 0x7FFFFFFF

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as presa:
        presa.settimeout(timeout)
        for _ in range(max(1, limite)):
            request_id = (request_id + 1) & 0x7FFFFFFF
            messaggio = messaggio_getnext(community, corrente, request_id)

            coppie = None
            for tentativo in range(max(1, tentativi)):
                try:
                    presa.sendto(messaggio, (host, porta))
                    scadenza = time.monotonic() + timeout
                    while time.monotonic() < scadenza:
                        dati, _ = presa.recvfrom(65535)
                        rid, lette = analizza_risposta(dati)
                        # Una risposta di un'interrogazione precedente (UDP non
                        # garantisce l'ordine) si scarta, invece di attribuirle
                        # l'OID sbagliato.
                        if rid == request_id:
                            coppie = lette
                            break
                    if coppie is not None:
                        break
                except socket.timeout:
                    continue
                except OSError as errore:
                    raise SnmpError("%s non raggiungibile: %s" % (host, errore))

            if coppie is None:
                if not risultati:
                    raise SnmpError(
                        "%s non risponde in SNMP: community non valida, SNMP non"
                        " attivo, oppure UDP 161 filtrato" % host)
                break

            if not coppie:
                break
            oid, valore = coppie[0]
            if not sotto_albero(oid, radice) or oid == corrente:
                break
            risultati.append((oid, valore))
            corrente = oid

    return risultati


def mac_leggibile(grezzo) -> str | None:
    """Sei byte in "aa:bb:cc:dd:ee:ff". None se non sono sei byte."""
    if not isinstance(grezzo, (bytes, bytearray)) or len(grezzo) != 6:
        return None
    return ":".join("%02x" % b for b in grezzo)


def arp_table(host: str, community: str, **opzioni) -> dict[str, str]:
    """La tabella ARP dell'apparato: {indirizzo IP: MAC}.

    L'indice di `ipNetToMediaPhysAddress` finisce con l'interfaccia e i quattro
    byte dell'indirizzo IP: l'IP si legge dall'OID, il MAC dal valore.

    Le voci incomplete (MAC assente, non di sei byte, o tutto zeri) si SCARTANO
    invece di inventarle: una riga di inventario con un MAC sbagliato e' peggio di
    una riga senza MAC -- la seconda si vede che manca, la prima no.
    """
    tabella: dict[str, str] = {}
    for oid, valore in walk(host, community, OID_IP_NET_TO_MEDIA_PHYS, **opzioni):
        archi = oid.strip(".").split(".")
        if len(archi) < 5:
            continue
        indirizzo = ".".join(archi[-4:])
        mac = mac_leggibile(valore)
        if mac and mac != "00:00:00:00:00:00":
            tabella[indirizzo] = mac
    return tabella


def identifica(host: str, community: str, **opzioni) -> dict:
    """Nome e descrizione dell'apparato: serve a dire CHI ha fornito i dati.

    Un MAC senza la fonte non e' verificabile: sapere che viene dal router di
    quella subnet, e quale, e' cio' che permette di rileggerlo domani.
    """
    dati = {}
    for etichetta, radice in (("descrizione", OID_SYS_DESCR), ("nome", OID_SYS_NAME)):
        try:
            coppie = walk(host, community, radice, limite=2, **opzioni)
        except SnmpError:
            continue
        for _oid, valore in coppie:
            if isinstance(valore, (bytes, bytearray)):
                dati[etichetta] = valore.decode("utf-8", "replace").strip()
                break
    return dati


def _mac_da_archi(archi: list[str]) -> str | None:
    """MAC dai sei ultimi archi di un OID (l'indice della tabella di forwarding).

    L'indice di `dot1dTpFdbPort` E' il MAC, un arco per byte in decimale. Nella
    versione Q-BRIDGE l'indice e' VLAN + MAC, quindi il MAC sono sempre gli ultimi
    sei archi -- e prenderli dalla fine funziona per entrambe.
    """
    if len(archi) < 6:
        return None
    ultimi = archi[-6:]
    try:
        byte = [int(a) for a in ultimi]
    except ValueError:
        return None
    if any(b < 0 or b > 255 for b in byte):
        return None
    return ":".join("%02x" % b for b in byte)


def forwarding_table(host: str, community: str, **opzioni) -> dict[str, int]:
    """MAC -> numero di porta bridge, dalla tabella di forwarding dello switch.

    Si prova prima la versione classica (dot1d) e poi quella con VLAN (dot1q): quale
    delle due sia popolata dipende dall'apparato. Se la prima non da' nulla non e'
    un errore -- e' uno switch che usa l'altra.
    """
    tabella: dict[str, int] = {}
    for radice in (OID_DOT1D_FDB_PORT, OID_DOT1Q_FDB_PORT):
        try:
            coppie = walk(host, community, radice, **opzioni)
        except SnmpError:
            continue
        for oid, valore in coppie:
            mac = _mac_da_archi(oid.strip(".").split("."))
            if mac and isinstance(valore, int) and valore > 0:
                tabella[mac] = valore
        if tabella:
            break
    return tabella


def _indice_finale(oid: str) -> str:
    return oid.strip(".").split(".")[-1]


def porta_bridge_verso_ifindex(host: str, community: str, **opzioni) -> dict[int, int]:
    """Porta bridge -> ifIndex. Vuoto se l'apparato non espone il BRIDGE-MIB."""
    mappa: dict[int, int] = {}
    try:
        coppie = walk(host, community, OID_DOT1D_BASE_PORT_IFINDEX, **opzioni)
    except SnmpError:
        return mappa
    for oid, valore in coppie:
        try:
            mappa[int(_indice_finale(oid))] = int(valore)
        except (TypeError, ValueError):
            continue
    return mappa


def nomi_interfacce(host: str, community: str, **opzioni) -> dict[int, str]:
    """ifIndex -> nome dell'interfaccia.

    Si preferisce `ifName` ("Gi1/0/12", come lo scrive chi configura l'apparato) e si
    ripiega su `ifDescr`, che c'e' sempre ma e' piu' verboso.
    """
    for radice in (OID_IF_NAME, OID_IF_DESCR):
        try:
            coppie = walk(host, community, radice, **opzioni)
        except SnmpError:
            continue
        nomi = {}
        for oid, valore in coppie:
            testo = (valore.decode("utf-8", "replace").strip()
                     if isinstance(valore, (bytes, bytearray)) else str(valore or ""))
            if not testo:
                continue
            try:
                nomi[int(_indice_finale(oid))] = testo[:60]
            except ValueError:
                continue
        if nomi:
            return nomi
    return {}


def mac_su_porta(host: str, community: str, **opzioni) -> dict[str, str]:
    """MAC -> nome della porta fisica, componendo le tre tabelle.

    Se la catena si interrompe (l'apparato non espone il BRIDGE-MIB o i nomi delle
    interfacce) si restituisce cio' che si e' potuto risolvere e NIENTE per il resto:
    un numero interno al posto di un nome di porta sarebbe un dato inutilizzabile
    scritto come se fosse buono.
    """
    fdb = forwarding_table(host, community, **opzioni)
    if not fdb:
        return {}
    verso_ifindex = porta_bridge_verso_ifindex(host, community, **opzioni)
    nomi = nomi_interfacce(host, community, **opzioni)

    risultato: dict[str, str] = {}
    for mac, porta_bridge in fdb.items():
        ifindex = verso_ifindex.get(porta_bridge)
        nome = nomi.get(ifindex) if ifindex is not None else None
        if nome:
            risultato[mac] = nome
    return risultato
