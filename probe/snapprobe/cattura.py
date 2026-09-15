# -----------------------------------------------------------------
# cattura.py — lettura dei pacchetti dal filo, senza dipendenze nuove
# Autore: Daniele Speziale
# Data creazione: 2026-09-13
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap probe - Il collegamento a libpcap/Npcap, e nient'altro.

PERCHE' NON UNA LIBRERIA
------------------------
La scelta ovvia sarebbe `scapy`. Non si usa per due ragioni, in quest'ordine:

1. **La licenza.** Scapy e' GPLv2; questo prodotto e' MIT. Legarlo significherebbe
   discutere di licenze a ogni consegna, per una funzione sola.
2. **Il peso.** Scapy porta dentro un dissezionatore universale e un motore di
   invio: qui serve leggere quattro intestazioni e buttare il resto.

L'alternativa e' piu' piccola di quanto sembri: libpcap (Npcap su Windows) espone da
vent'anni una C API stabile di cinque funzioni, e `ctypes` e' nella libreria standard.
Questo file e' quel collegamento -- circa duecento righe -- e non aggiunge nulla al
`requirements.txt`.

Alternative valutate e scartate: `pypcap` e `pcapy-ng` (BSD, ma vanno compilate: su
Windows significa una toolchain sulla macchina del cliente), `dpkt` (ottimo per
analizzare, non cattura).

CHE COSA NON FA QUESTO FILE
---------------------------
Non interpreta. Consegna i byte e il loro istante a chi li sa leggere
(`traffico.py`). La divisione non e' pedanteria: la parte che parla con una libreria
di sistema in C e' quella dove un errore costa caro, e deve restare corta abbastanza
da poterla leggere tutta.

QUANTO SI CATTURA
-----------------
`SNAPLEN` byte per pacchetto, non il pacchetto intero: il resto non entra mai nella
memoria del processo. E' la differenza fra osservare una rete e intercettarla.

remarks: Autore: Daniele Speziale - Data: 2026-09-13
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import ctypes
import ctypes.util
import socket
import sys
import threading
import time

# Quanti byte di ogni pacchetto entrano in memoria.
#
# 512 e' scelto, non arrotondato: le intestazioni Ethernet+IP+TCP stanno in 74 byte,
# ma il nome del server in un ClientHello TLS (SNI) e l'intestazione Host di HTTP
# cadono piu' avanti, tipicamente entro i primi 500. Oltre non si prende nulla,
# perche' oltre comincia il CONTENUTO, che questo prodotto non legge.
SNAPLEN = 512

# Quanto aspetta `pcap_next_ex` prima di tornare a mani vuote. Serve a poter chiudere
# la cattura in fretta quando qualcuno la spegne: senza, il thread resterebbe fermo
# dentro la libreria C fino al primo pacchetto.
ATTESA_MS = 250

# Il filtro predefinito, in sintassi BPF (la stessa di tcpdump e Wireshark).
#
# NON e' un'ottimizzazione: e' il modo per NON catturare cio' che non serve. Il filtro
# gira dentro il kernel, quindi i pacchetti esclusi non arrivano nemmeno al processo.
# Qui si prende cio' su cui le regole lavorano davvero: ARP, DHCP, i protocolli di
# risoluzione dei nomi, il DNS, e l'apertura delle connessioni TCP (i soli SYN, non
# il flusso intero).
FILTRO_PREDEFINITO = (
    "arp or (udp port 67 or udp port 68) or (udp port 53) or (udp port 5353)"
    " or (udp port 5355) or (udp port 137) or (tcp[tcpflags] & tcp-syn != 0)"
    " or (tcp port 80) or (tcp port 443 and tcp[tcpflags] & tcp-push != 0)"
)


class ErroreCattura(RuntimeError):
    """La cattura non e' possibile, e il motivo si dichiara a chi guarda la pagina."""


# --------------------------------------------------------------------------- #
# Il minimo dell'API di libpcap
# --------------------------------------------------------------------------- #
class _Intestazione(ctypes.Structure):
    """`struct pcap_pkthdr`: quando e' arrivato, quanto se n'e' preso, quanto era."""

    _fields_ = [("sec", ctypes.c_long), ("usec", ctypes.c_long),
                ("caplen", ctypes.c_uint32), ("len", ctypes.c_uint32)]


class _Indirizzo(ctypes.Structure):
    """`struct pcap_addr`: un indirizzo dell'interfaccia, con la sua maschera.

    Di questa struttura serve il solo `addr`: la maschera e il broadcast non
    aiutano a riconoscere un'interfaccia in un elenco a discesa, e leggerli
    vorrebbe dire trattare altri tre `sockaddr` per niente.
    """

    pass


_Indirizzo._fields_ = [("next", ctypes.POINTER(_Indirizzo)),
                       ("addr", ctypes.c_void_p),
                       ("netmask", ctypes.c_void_p),
                       ("broadaddr", ctypes.c_void_p),
                       ("dstaddr", ctypes.c_void_p)]


class _Dispositivo(ctypes.Structure):
    pass


_Dispositivo._fields_ = [("next", ctypes.POINTER(_Dispositivo)),
                         ("name", ctypes.c_char_p),
                         ("description", ctypes.c_char_p),
                         ("addresses", ctypes.POINTER(_Indirizzo)),
                         ("flags", ctypes.c_uint32)]


# Quanti byte si leggono da un `sockaddr`: bastano per IPv6 (28), che e' il piu'
# lungo dei due che interessano. Si legge una copia, non si tiene il puntatore: la
# libreria libera tutto con `pcap_freealldevs`.
_SOCKADDR_BYTE = 28


def _famiglia_e_indirizzo(puntatore) -> tuple:
    """(famiglia, indirizzo) da un `struct sockaddr`. (None, None) se non si sa.

    IL FORMATO NON E' UNO SOLO, e questa e' l'unica ragione per cui questa funzione
    e' piu' lunga di tre righe:

    * su Linux e Windows i primi due byte sono la famiglia, come intero a 16 bit
      nell'ordine della macchina;
    * sui BSD (macOS compreso) il primo byte e' la LUNGHEZZA della struttura e il
      secondo la famiglia.

    Sbagliare interpretazione non da' un errore: da' un indirizzo plausibile e
    sbagliato, che e' molto peggio. Dove il formato non e' noto si restituisce
    "non lo so" e l'interfaccia compare senza indirizzo -- come ogni altra cosa
    che questo prodotto non ha potuto misurare.
    """
    if not puntatore:
        return None, None
    grezzo = ctypes.string_at(puntatore, _SOCKADDR_BYTE)
    if sys.platform.startswith(("linux", "win")):
        famiglia = int.from_bytes(grezzo[0:2], sys.byteorder)
    elif sys.platform == "darwin" or "bsd" in sys.platform:
        famiglia = grezzo[1]
    else:
        return None, None

    try:
        if famiglia == socket.AF_INET:
            return famiglia, socket.inet_ntop(socket.AF_INET, grezzo[4:8])
        if famiglia == socket.AF_INET6:
            return famiglia, socket.inet_ntop(socket.AF_INET6, grezzo[8:24])
    except (OSError, ValueError):
        # Byte che non compongono un indirizzo valido: non si inventa niente.
        return famiglia, None
    return famiglia, None


def _indirizzi_di(dispositivo) -> list:
    """Gli indirizzi IPv4 e IPv6 di un dispositivo, nell'ordine in cui li elenca.

    IPv4 PRIMA: e' quello con cui la sonda si presenta sulla rete che si vuole
    osservare, ed e' quello che chi sceglie l'interfaccia riconosce. Gli IPv6 di
    collegamento locale (fe80::) si scartano: ce n'e' uno su ogni scheda, sono tutti
    simili, e riempirebbero l'elenco senza distinguere niente.
    """
    trovati, voce = [], dispositivo.addresses
    while voce:
        contenuto = voce.contents
        famiglia, indirizzo = _famiglia_e_indirizzo(contenuto.addr)
        if indirizzo and indirizzo not in trovati:
            if not (famiglia == socket.AF_INET6 and indirizzo.lower().startswith("fe80")):
                trovati.append(indirizzo)
        voce = contenuto.next
    # Gli IPv4 in testa: `:` compare solo negli IPv6.
    return sorted(trovati, key=lambda a: (":" in a, a))


class _Programma(ctypes.Structure):
    """`struct bpf_program`: il filtro compilato."""

    _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.c_void_p)]


_libreria = None
_errore_libreria = ""


def libreria():
    """La libreria di cattura, o `None` se su questa macchina non c'e'.

    Non solleva: l'assenza di libpcap e' una condizione normale -- la maggior parte
    delle installazioni non ha il traffico attivo -- e va DICHIARATA nella pagina dei
    sensori, non fatta esplodere all'avvio.
    """
    global _libreria, _errore_libreria
    if _libreria is not None or _errore_libreria:
        return _libreria
    try:
        if sys.platform == "win32":
            # Npcap si installa con nmap, che la sonda richiede gia': su una macchina
            # dove la sonda gira, quasi sempre c'e'.
            caricata = ctypes.WinDLL("wpcap.dll")
        else:
            nome = ctypes.util.find_library("pcap")
            if not nome:
                raise OSError("libpcap non trovata (pacchetto libpcap0.8 o libpcap)")
            caricata = ctypes.CDLL(nome)
    except OSError as errore:
        _errore_libreria = str(errore)
        return None

    caricata.pcap_open_live.restype = ctypes.c_void_p
    caricata.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
                                        ctypes.c_int, ctypes.c_char_p]
    caricata.pcap_next_ex.restype = ctypes.c_int
    caricata.pcap_next_ex.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(_Intestazione)),
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
    caricata.pcap_close.argtypes = [ctypes.c_void_p]
    caricata.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(_Dispositivo)),
                                          ctypes.c_char_p]
    caricata.pcap_freealldevs.argtypes = [ctypes.POINTER(_Dispositivo)]
    caricata.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(_Programma),
                                      ctypes.c_char_p, ctypes.c_int, ctypes.c_uint]
    caricata.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(_Programma)]
    caricata.pcap_freecode.argtypes = [ctypes.POINTER(_Programma)]
    caricata.pcap_geterr.restype = ctypes.c_char_p
    caricata.pcap_geterr.argtypes = [ctypes.c_void_p]
    caricata.pcap_datalink.restype = ctypes.c_int
    caricata.pcap_datalink.argtypes = [ctypes.c_void_p]
    _libreria = caricata
    return _libreria


def motivo_assenza() -> str:
    """Perche' la cattura non e' possibile. Vuoto se lo e'."""
    if libreria() is not None:
        return ""
    if sys.platform == "win32":
        return ("Npcap non e' installato (%s). Si installa con nmap, oppure da"
                " npcap.com: e' lo stesso componente che usa Wireshark."
                % (_errore_libreria or "wpcap.dll assente"))
    return ("libpcap non e' installata (%s): pacchetto `libpcap0.8` su Debian/Ubuntu,"
            " `libpcap` su RHEL." % (_errore_libreria or "assente"))


def interfacce() -> list:
    """Le interfacce su cui si puo' ascoltare, come le vede la libreria.

    Elenco vuoto non significa "non ce ne sono": su Linux significa quasi sempre che
    mancano i privilegi. Chi chiama deve dirlo cosi'.
    """
    pcap = libreria()
    if pcap is None:
        return []
    primo = ctypes.POINTER(_Dispositivo)()
    errore = ctypes.create_string_buffer(512)
    if pcap.pcap_findalldevs(ctypes.byref(primo), errore) != 0:
        raise ErroreCattura(errore.value.decode(errors="replace"))
    trovate, voce = [], primo
    try:
        while voce:
            contenuto = voce.contents
            trovate.append({
                "nome": (contenuto.name or b"").decode(errors="replace"),
                "descrizione": (contenuto.description or b"").decode(errors="replace"),
                # Gli indirizzi con cui l'interfaccia si presenta sulla rete: senza,
                # scegliere fra tre schede con la stessa descrizione e' indovinare.
                "indirizzi": _indirizzi_di(contenuto),
                # Il bit 1 di `flags` e' PCAP_IF_LOOPBACK: un'interfaccia di loopback
                # non vede la rete del cliente, e proporla sarebbe un invito a
                # scegliere quella sbagliata.
                "loopback": bool(contenuto.flags & 0x00000001),
            })
            voce = contenuto.next
    finally:
        pcap.pcap_freealldevs(primo)
    return trovate


# --------------------------------------------------------------------------- #
# La cattura
# --------------------------------------------------------------------------- #
class Cattura:
    """Ascolta un'interfaccia e consegna i pacchetti a una funzione.

    Gira in un thread proprio perche' `pcap_next_ex` e' bloccante: dentro il ciclo
    principale della sonda fermerebbe le scansioni. Il thread non fa analisi -- quella
    sta in `traffico.py` -- ma la funzione che riceve i byte viene chiamata QUI, nel
    thread di cattura: deve essere breve, o i pacchetti si perdono nel buffer.
    """

    def __init__(self, interfaccia: str, consegna, filtro: str = None,
                 promiscua: bool = True):
        self.interfaccia = interfaccia
        self.consegna = consegna
        self.filtro = FILTRO_PREDEFINITO if filtro is None else filtro
        self.promiscua = promiscua
        self._presa = None
        self._thread = None
        self._fermare = threading.Event()
        self.pacchetti = 0
        self.scartati = 0
        self.avviata_at = None
        self.ultimo_errore = ""

    # -- apertura ---------------------------------------------------------- #
    def _apri(self):
        pcap = libreria()
        if pcap is None:
            raise ErroreCattura(motivo_assenza())
        errore = ctypes.create_string_buffer(512)
        presa = pcap.pcap_open_live(self.interfaccia.encode("utf-8"), SNAPLEN,
                                    1 if self.promiscua else 0, ATTESA_MS, errore)
        if not presa:
            testo = errore.value.decode(errors="replace")
            # Il caso di gran lunga piu' comune, e il messaggio della libreria non lo
            # dice in modo utile: si traduce.
            if "permission" in testo.lower() or "denied" in testo.lower():
                raise ErroreCattura(
                    "permesso negato su %s: la cattura richiede privilegi"
                    " (CAP_NET_RAW su Linux, amministratore su Windows)"
                    % self.interfaccia)
            raise ErroreCattura("%s: %s" % (self.interfaccia, testo))

        # Solo Ethernet. Un'interfaccia PPP o una VPN hanno un altro incapsulamento e
        # le regole leggerebbero byte a caso: meglio rifiutare che interpretare male.
        collegamento = pcap.pcap_datalink(presa)
        if collegamento != 1:  # DLT_EN10MB
            pcap.pcap_close(presa)
            raise ErroreCattura(
                "%s non e' Ethernet (incapsulamento %d): le regole del traffico"
                " leggono intestazioni Ethernet" % (self.interfaccia, collegamento))

        if self.filtro:
            programma = _Programma()
            if pcap.pcap_compile(presa, ctypes.byref(programma),
                                 self.filtro.encode("utf-8"), 1, 0xFFFFFFFF) != 0:
                dettaglio = (pcap.pcap_geterr(presa) or b"").decode(errors="replace")
                pcap.pcap_close(presa)
                raise ErroreCattura("filtro non valido (%s): %s"
                                    % (self.filtro[:60], dettaglio))
            esito = pcap.pcap_setfilter(presa, ctypes.byref(programma))
            pcap.pcap_freecode(ctypes.byref(programma))
            if esito != 0:
                pcap.pcap_close(presa)
                raise ErroreCattura("il filtro non si applica a %s" % self.interfaccia)
        return presa

    # -- ciclo -------------------------------------------------------------- #
    def _ciclo(self):
        pcap = libreria()
        intestazione = ctypes.POINTER(_Intestazione)()
        corpo = ctypes.POINTER(ctypes.c_ubyte)()
        while not self._fermare.is_set():
            esito = pcap.pcap_next_ex(self._presa, ctypes.byref(intestazione),
                                      ctypes.byref(corpo))
            if esito == 0:
                continue  # scaduta l'attesa: normale, si riprova
            if esito != 1:
                # -1 errore, -2 fine del file: in cattura dal vivo il secondo non
                # capita, il primo va dichiarato e fa terminare il thread.
                self.ultimo_errore = (pcap.pcap_geterr(self._presa)
                                      or b"").decode(errors="replace")
                break
            quanti = intestazione.contents.caplen
            if quanti < 14:
                self.scartati += 1
                continue
            self.pacchetti += 1
            try:
                self.consegna(bytes(bytearray(corpo[:quanti])),
                              intestazione.contents.sec)
            except Exception as errore:  # noqa: BLE001 - un pacchetto storto non ferma
                # Un pacchetto malformato non deve spegnere l'osservazione: e' proprio
                # cio' che manderebbe chi vuole farla smettere.
                self.scartati += 1
                self.ultimo_errore = str(errore)[:200]

    def avvia(self):
        if self._thread is not None and self._thread.is_alive():
            return
        self._presa = self._apri()
        self._fermare.clear()
        self.avviata_at = time.time()
        self._thread = threading.Thread(target=self._ciclo, name="cattura",
                                        daemon=True)
        self._thread.start()

    def ferma(self):
        self._fermare.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
        if self._presa is not None:
            libreria().pcap_close(self._presa)
            self._presa = None
        self._thread = None

    @property
    def viva(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def stato(self) -> dict:
        return {
            "interfaccia": self.interfaccia,
            "viva": self.viva,
            "pacchetti": self.pacchetti,
            "scartati": self.scartati,
            "da": self.avviata_at,
            "filtro": self.filtro,
            "ultimo_errore": self.ultimo_errore,
        }
