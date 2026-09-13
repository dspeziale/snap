# -----------------------------------------------------------------
# traffico.py — che cosa si ricava dalle intestazioni, e nient'altro
# Autore: Daniele Speziale
# Data creazione: 2026-09-13
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap probe - Leggere il filo senza leggere quello che la gente scrive.

CHE COSA SI GUARDA
------------------
Le intestazioni -- chi parla con chi, con quale protocollo, quando, quanto -- piu' i
NOMI che i protocolli dichiarano in chiaro: il dominio di una query DNS, il nome del
server in un ClientHello TLS (SNI), l'intestazione `Host` di HTTP. Sono metadati, non
contenuto, e sono cio' che permette di riconoscere un tunnel DNS o un dominio di
comando senza aprire un solo byte di payload.

CHE COSA NON SI GUARDA MAI
--------------------------
Il corpo dei pacchetti. La cattura prende `SNAPLEN` byte (vedi `cattura.py`), e questo
modulo estrae quei pochi campi e **butta il resto**: dentro l'osservatorio finiscono
fatti derivati -- conteggi, insiemi di nomi, istanti -- mai i byte. Non e' una
promessa di comportamento: e' che i byte non vengono conservati da nessuna parte.

PERCHE' UNA FINESTRA E NON UN FLUSSO
------------------------------------
L'osservatorio accumula per qualche minuto e poi si svuota quando il motore IDS lo
legge. Una rete vede decine di migliaia di pacchetti al minuto: tenerli sarebbe
impossibile e inutile. Cio' che conta e' il RIASSUNTO della finestra -- quanti host
diversi ha toccato quell'indirizzo, con che regolarita' quello ha chiamato lo stesso
posto -- e il riassunto occupa qualche kilobyte.

OGNI CONTENITORE HA UN TETTO
----------------------------
Non e' prudenza generica. Un osservatorio che cresce con il traffico si riempie da
solo quando qualcuno manda rumore, e riempire la memoria della sonda e' un modo
economico per farla smettere di guardare: e' la prima cosa che farebbe chi sa che c'e'.

remarks: Autore: Daniele Speziale - Data: 2026-09-13
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import math
import socket
import struct
import threading
from collections import defaultdict, deque

# I tetti. Superati, si smette di aggiungere e si DICHIARA di aver troncato: un
# riassunto parziale presentato come completo farebbe concludere il falso.
MAX_MAC = 4096
MAX_FLUSSI = 20000
MAX_NOMI = 5000
MAX_IP_PER_MAC = 64

# Quanti istanti si conservano per flusso, per riconoscere un ritmo. Trenta bastano a
# vedere una regolarita' e costano 240 byte per flusso.
MAX_ISTANTI = 30

# Quanti pacchetti gia' LETTI si tengono in memoria per poterli mostrare.
#
# E' un anello: il piu' vecchio esce quando entra il piu' nuovo. Duemila righe di
# campi decodificati stanno in circa un megabyte e coprono qualche minuto su una rete
# d'ufficio. Non sono i pacchetti: sono i loro campi -- i byte non si conservano da
# nessuna parte, nemmeno qui.
MAX_REGISTRO = 2000

ETH_ARP = 0x0806
ETH_IPV4 = 0x0800

PORTE_NOMI = {5355: "llmnr", 137: "nbns", 5353: "mdns"}


def _mac(dati: bytes) -> str:
    return ":".join("%02x" % b for b in dati)


def _ip(dati: bytes) -> str:
    return socket.inet_ntoa(dati)


VOCALI = set("aeiouy")


def _entropia(testo: str) -> float:
    """Quanti caratteri diversi, in scala logaritmica.

    Si conserva perche' finisce nella PROVA di una rilevazione -- chi guarda una riga
    vuole il numero -- ma NON decide piu' da sola: vedi `_pronunciabile`.
    """
    if not testo:
        return 0.0
    frequenze = defaultdict(int)
    for carattere in testo:
        frequenze[carattere] += 1
    lunghezza = len(testo)
    return -sum((n / lunghezza) * math.log2(n / lunghezza)
                for n in frequenze.values())


def _pronunciabile(testo: str) -> float:
    """La frazione di vocali: quanto quel nome somiglia a una parola.

    PERCHE' NON L'ENTROPIA. Su un'etichetta corta l'entropia di Shannon misura in
    pratica quanti caratteri distinti ci sono, che per una parola breve e' quasi la
    lunghezza: misurato, `sharepoint` fa 3,32 e `xk4mz9qp7wv2` fa 3,58 -- due cose
    completamente diverse a due decimi di distanza. Con le vocali si separano: 0,40
    contro 0,00.

    Non e' una prova. Esistono nomi legittimi senza vocali (sigle, nomi di CDN
    generati), ed e' per questo che la regola che usa questa misura pretende ANCHE
    una lunghezza minima.
    """
    if not testo:
        return 0.0
    lettere = [c for c in testo.lower() if c.isalpha()]
    if not lettere:
        return 0.0  # tutte cifre: non e' una parola
    return sum(1 for c in lettere if c in VOCALI) / len(lettere)


def _nome_dns(dati: bytes, inizio: int, limite: int = 8) -> str:
    """Il nome di dominio di una query, letto dalle etichette.

    Si ferma al primo puntatore di compressione: nelle QUERY non ce ne sono, e
    seguirli richiederebbe di rileggere il pacchetto da capo -- con il rischio di
    cicli, che e' esattamente cio' che manderebbe chi vuole far girare a vuoto un
    analizzatore.
    """
    etichette, posizione, giri = [], inizio, 0
    while posizione < len(dati) and giri < limite:
        lunghezza = dati[posizione]
        if lunghezza == 0:
            break
        if lunghezza & 0xC0:
            break  # puntatore di compressione: non si segue
        posizione += 1
        if posizione + lunghezza > len(dati):
            break
        etichette.append(dati[posizione:posizione + lunghezza]
                         .decode("ascii", errors="replace"))
        posizione += lunghezza
        giri += 1
    return ".".join(etichette).lower()[:253]


def _sni(dati: bytes) -> str:
    """Il nome del server dentro un ClientHello TLS.

    Si cerca la sola estensione `server_name`, saltando i campi a lunghezza variabile
    che la precedono. E' l'unico pezzo di un flusso cifrato che sia leggibile, ed e'
    il motivo per cui un canale di comando verso un dominio noto si puo' riconoscere
    senza decifrare niente.
    """
    # record TLS: tipo(1) versione(2) lunghezza(2) | handshake: tipo(1) lunghezza(3)
    if len(dati) < 45 or dati[0] != 0x16 or dati[5] != 0x01:
        return ""
    posizione = 43  # dopo versione(2) + random(32) del ClientHello
    if posizione >= len(dati):
        return ""
    sessione = dati[posizione]
    posizione += 1 + sessione
    if posizione + 2 > len(dati):
        return ""
    cifrari = struct.unpack("!H", dati[posizione:posizione + 2])[0]
    posizione += 2 + cifrari
    if posizione >= len(dati):
        return ""
    compressioni = dati[posizione]
    posizione += 1 + compressioni
    if posizione + 2 > len(dati):
        return ""
    posizione += 2  # lunghezza complessiva delle estensioni
    while posizione + 4 <= len(dati):
        tipo, lunghezza = struct.unpack("!HH", dati[posizione:posizione + 4])
        posizione += 4
        if tipo == 0x0000:  # server_name
            # elenco(2) tipo(1) lunghezza(2) nome
            if posizione + 5 > len(dati):
                return ""
            quanti = struct.unpack("!H", dati[posizione + 3:posizione + 5])[0]
            inizio = posizione + 5
            if inizio + quanti > len(dati):
                return ""
            return dati[inizio:inizio + quanti].decode("ascii",
                                                       errors="replace").lower()[:253]
        posizione += lunghezza
    return ""


def _host_http(dati: bytes) -> str:
    """L'intestazione `Host` di una richiesta HTTP.

    Si guarda solo l'inizio: `Host` sta fra le prime righe per convenzione, e cercarla
    piu' avanti significherebbe leggere il corpo della richiesta.
    """
    testa = dati[:400]
    if not testa[:8].upper().startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ",
                                         b"OPTIONS ", b"DELETE ")):
        return ""
    for riga in testa.split(b"\r\n")[1:12]:
        if riga[:5].lower() == b"host:":
            return riga[5:].strip().decode("ascii", errors="replace").lower()[:253]
    return ""


def _bandiere_tcp(valore: int) -> str:
    """Le bandiere TCP come le scrive chiunque le legga: SYN, SYN-ACK, FIN...

    Servono a capire a colpo d'occhio se un pacchetto apre, chiude o rifiuta una
    connessione: un RST di ritorno da mille porte diverse e' una scansione respinta,
    e si vede da qui.
    """
    nomi = (("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04), ("PSH", 0x08),
            ("ACK", 0x10), ("URG", 0x20))
    accese = [nome for nome, bit in nomi if valore & bit]
    return "-".join(accese) if accese else "-"


class Osservatorio:
    """Il riassunto di cio' che e' passato sul filo, nella finestra corrente.

    Scritto dal thread di cattura, letto dal motore IDS: ogni accesso passa da un
    lucchetto. Non e' pessimismo -- sono due thread veri, e un dizionario modificato
    mentre lo si percorre solleva in Python, cioe' spegnerebbe la cattura.
    """

    def __init__(self, escludi_mac=None, escludi_ip=None):
        self._lucchetto = threading.Lock()
        # LA SONDA SCANSIONA. I suoi SYN verso mille indirizzi sono esattamente la
        # forma di una scansione interna, e senza questa esclusione la prima
        # rilevazione del sensore sarebbe la sonda che denuncia se stessa. E' il
        # genere di falso positivo che fa perdere fiducia a chi guarda.
        self.escludi_mac = {m.lower() for m in (escludi_mac or ())}
        self.escludi_ip = set(escludi_ip or ())
        # L'anello dei pacchetti gia' letti, per la pagina che li mostra.
        self.registro = deque(maxlen=MAX_REGISTRO)
        self.azzera()

    def azzera(self):
        self.pacchetti = 0
        self.troncato = set()
        # L'anello NON si azzera qui: il riassunto lo legge il motore IDS ogni cinque
        # minuti, e azzerare anche i pacchetti mostrati vorrebbe dire una pagina che
        # si svuota da sola mentre la si guarda. Si svuota travasandolo (`preleva`).
        # MAC visto sul filo -> (primo, ultimo, quanti, {ip dichiarati})
        self.mac = {}
        # IP -> {mac che lo hanno dichiarato in ARP}
        self.arp_per_ip = defaultdict(set)
        self.arp_gratuiti = defaultdict(int)
        # MAC -> quanti DHCP OFFER/ACK ha mandato (cioe': si comporta da server)
        self.dhcp_server = defaultdict(int)
        # MAC -> nomi distinti a cui ha RISPOSTO in LLMNR/NBNS/mDNS
        self.risposte_nomi = defaultdict(set)
        # (ip sorgente) -> {ip destinazione}, {porte destinazione}
        self.scansione_host = defaultdict(set)
        self.scansione_porte = defaultdict(set)
        # (sorgente, destinazione, porta) -> [istanti]
        self.flussi = defaultdict(list)
        # nome -> quante volte chiesto
        self.nomi = defaultdict(int)
        # zona di secondo livello -> {sottodomini distinti}
        self.sottodomini = defaultdict(set)
        self.http_in_chiaro = defaultdict(set)

    # -- scrittura (thread di cattura) -------------------------------------- #
    def _tetto(self, contenitore, massimo: int, etichetta: str) -> bool:
        if len(contenitore) >= massimo:
            self.troncato.add(etichetta)
            return True
        return False

    def osserva(self, dati: bytes, quando: float) -> None:
        """Un pacchetto. Si estraggono i fatti e i byte si buttano."""
        if len(dati) < 14:
            return
        sorgente_mac = _mac(dati[6:12])
        # UNA REGOLA SOLA: il traffico della sonda si LEGGE -- deve comparire
        # nell'elenco, o la pagina mostra righe mezze vuote -- ma non diventa mai un
        # FATTO per le regole. La sonda scansiona per mestiere e si denuncerebbe da
        # sola. Vale per il MAC come per l'indirizzo.
        mia = sorgente_mac in self.escludi_mac
        with self._lucchetto:
            self.pacchetti += 1
            if not mia:
                self._vedi_mac(sorgente_mac, quando)
            tipo = struct.unpack("!H", dati[12:14])[0]
            riga = {"at": quando, "mac_sorgente": sorgente_mac,
                    "mac_destinazione": _mac(dati[0:6]), "byte": len(dati)}
            if tipo == ETH_ARP:
                self._arp(dati, sorgente_mac, riga, mia)
            elif tipo == ETH_IPV4:
                self._ipv4(dati, sorgente_mac, quando, riga, mia)
            else:
                riga["protocollo"] = "0x%04x" % tipo
            self.registro.append(riga)

    def _vedi_mac(self, indirizzo: str, quando: float) -> None:
        voce = self.mac.get(indirizzo)
        if voce is None:
            if self._tetto(self.mac, MAX_MAC, "schede di rete"):
                return
            self.mac[indirizzo] = [quando, quando, 1, set()]
        else:
            voce[1] = quando
            voce[2] += 1

    def _arp(self, dati: bytes, sorgente_mac: str, riga: dict = None,
             solo_lettura: bool = False) -> None:
        riga = riga if riga is not None else {}
        riga["protocollo"] = "ARP"
        if len(dati) < 42:
            return
        operazione = struct.unpack("!H", dati[20:22])[0]
        mittente_mac = _mac(dati[22:28])
        mittente_ip = _ip(dati[28:32])
        bersaglio_ip = _ip(dati[38:42])
        riga["sorgente"] = mittente_ip
        riga["destinazione"] = bersaglio_ip
        riga["dettaglio"] = ("chi ha %s? lo chiede %s" % (bersaglio_ip, mittente_ip)
                             if operazione == 1
                             else "%s sta su %s" % (mittente_ip, mittente_mac))
        if mittente_ip == "0.0.0.0" or solo_lettura:
            return  # ARP probe di un host che prende un indirizzo, oppure la sonda
        if not self._tetto(self.arp_per_ip, MAX_MAC, "ARP"):
            self.arp_per_ip[mittente_ip].add(mittente_mac)
        voce = self.mac.get(sorgente_mac)
        if voce is not None and len(voce[3]) < MAX_IP_PER_MAC:
            voce[3].add(mittente_ip)
        # ARP gratuito: una risposta che nessuno ha chiesto, o un annuncio in cui
        # mittente e bersaglio coincidono. Uno e' normale (dopo un riavvio); una
        # raffica e' il modo in cui si tiene avvelenata una cache.
        if operazione == 2 or mittente_ip == bersaglio_ip:
            self.arp_gratuiti[mittente_ip] += 1

    def _ipv4(self, dati: bytes, sorgente_mac: str, quando: float,
              riga: dict = None, mia: bool = False) -> None:
        riga = riga if riga is not None else {}
        if len(dati) < 34:
            return
        lunghezza = (dati[14] & 0x0F) * 4
        if lunghezza < 20:
            return
        protocollo = dati[23]
        sorgente_ip = _ip(dati[26:30])
        destinazione_ip = _ip(dati[30:34])
        riga["sorgente"] = sorgente_ip
        riga["destinazione"] = destinazione_ip
        # L'ESCLUSIONE RIGUARDA I FATTI, NON LA LETTURA. La sonda va esclusa dalle
        # regole -- scansiona per mestiere e si denuncerebbe da sola -- ma i suoi
        # pacchetti vanno letti lo stesso, o nell'elenco compaiono righe mezze vuote
        # con protocollo "?". Sulla rete di collaudo erano centotrentasette.
        solo_lettura = mia or sorgente_ip in self.escludi_ip
        inizio = 14 + lunghezza
        if len(dati) < inizio + 4:
            return
        porta_sorgente, porta_destinazione = struct.unpack("!HH",
                                                           dati[inizio:inizio + 4])
        riga["porta_sorgente"] = porta_sorgente
        riga["porta"] = porta_destinazione
        if protocollo == 17:
            riga["protocollo"] = "UDP"
            self._udp(dati, inizio, sorgente_mac, sorgente_ip, porta_sorgente,
                      porta_destinazione, riga, solo_lettura)
        elif protocollo == 6:
            riga["protocollo"] = "TCP"
            self._tcp(dati, inizio, sorgente_ip, destinazione_ip,
                      porta_destinazione, quando, riga, solo_lettura)
        else:
            riga["protocollo"] = "IP/%d" % protocollo

    def _udp(self, dati, inizio, sorgente_mac, sorgente_ip, porta_sorgente,
             porta_destinazione, riga: dict = None,
             solo_lettura: bool = False) -> None:
        riga = riga if riga is not None else {}
        etichetta = PORTE_NOMI.get(porta_destinazione) or PORTE_NOMI.get(porta_sorgente)
        if porta_destinazione == 53 or porta_sorgente == 53:
            etichetta = "dns"
        elif porta_sorgente in (67, 68) or porta_destinazione in (67, 68):
            etichetta = "dhcp"
        if etichetta:
            riga["protocollo"] = "UDP/%s" % etichetta.upper()
        carico = inizio + 8
        if porta_sorgente == 67:
            riga["dettaglio"] = "risponde da server DHCP"
            # Chi manda DA 67 si comporta da server DHCP. Che sia quello vero lo
            # decide chi conosce la rete: qui si contano i candidati.
            if not solo_lettura:
                self.dhcp_server[sorgente_mac] += 1
            return
        if 53 in (porta_destinazione, porta_sorgente) and len(dati) > carico + 12:
            # IL NOME SI LEGGE ANCHE DALLE RISPOSTE. Prima si guardavano solo le
            # domande, e con dodici pacchetti DNS visti la colonna dei nomi restava
            # vuota: in una risposta la porta 53 e' quella di ORIGINE.
            risposta = bool(len(dati) > carico + 3 and (dati[carico + 2] & 0x80))
            nome = _nome_dns(dati, carico + 12)
            if nome:
                riga["nome"] = nome
                riga["dettaglio"] = ("risponde per %s" if risposta
                                     else "chiede %s") % nome
            # Nelle statistiche del tunnel entra la DOMANDA: contare anche la
            # risposta raddoppierebbe ogni conteggio.
            if nome and not risposta and not solo_lettura:
                self._conta_nome(nome)
            return
        nome_protocollo = PORTE_NOMI.get(porta_sorgente)
        if nome_protocollo and len(dati) > carico + 12:
            # Una RISPOSTA a una query di nome (il bit QR e' acceso). Chi risponde a
            # nomi sempre diversi sta facendo il lavoro di Responder.
            if len(dati) > carico + 3 and (dati[carico + 2] & 0x80):
                risposto = _nome_dns(dati, carico + 12)
                if not solo_lettura:
                    nomi = self.risposte_nomi[sorgente_mac]
                    if len(nomi) < 256:
                        nomi.add(risposto)
                if risposto:
                    riga["nome"] = risposto
                    riga["dettaglio"] = "risponde per %s" % risposto

    def _conta_nome(self, nome: str) -> None:
        """Il nome entra nelle statistiche: quante volte, e sotto quale zona."""
        if not nome or self._tetto(self.nomi, MAX_NOMI, "nomi"):
            return
        self.nomi[nome] += 1
        pezzi = nome.split(".")
        if len(pezzi) >= 3:
            zona = ".".join(pezzi[-2:])
            sotto = self.sottodomini[zona]
            if len(sotto) < 512:
                sotto.add(".".join(pezzi[:-2]))

    def _tcp(self, dati, inizio, sorgente_ip, destinazione_ip, porta, quando,
             riga: dict = None, solo_lettura: bool = False) -> None:
        riga = riga if riga is not None else {}
        if len(dati) < inizio + 14:
            return
        bandiere = dati[inizio + 13]
        riga["bandiere"] = _bandiere_tcp(bandiere)
        sin, ack = bool(bandiere & 0x02), bool(bandiere & 0x10)
        if sin and not ack:
            riga["dettaglio"] = "apre verso %s:%d" % (destinazione_ip, porta)
            if solo_lettura:
                return
            # L'APERTURA di una connessione: e' l'unica parte del flusso che
            # interessa, e conta una volta sola per flusso.
            if not self._tetto(self.scansione_host, MAX_MAC, "scansioni"):
                bersagli = self.scansione_host[sorgente_ip]
                if len(bersagli) < 4096:
                    bersagli.add(destinazione_ip)
                porte = self.scansione_porte[sorgente_ip]
                if len(porte) < 4096:
                    porte.add(porta)
            chiave = (sorgente_ip, destinazione_ip, porta)
            if not self._tetto(self.flussi, MAX_FLUSSI, "flussi"):
                istanti = self.flussi[chiave]
                if len(istanti) < MAX_ISTANTI:
                    istanti.append(quando)
            return
        # Non e' un SYN: puo' portare i NOMI in chiaro.
        carico = inizio + ((dati[inizio + 12] >> 4) * 4)
        if carico >= len(dati):
            return
        corpo = dati[carico:]
        # Si guardano ENTRAMBE le porte: in una risposta la porta nota e' quella di
        # ORIGINE, e cercandola solo fra le destinazioni la meta' del traffico
        # restava senza nome.
        nome = _sni(corpo)
        if nome:
            riga["protocollo"] = "TLS"
            riga["nome"] = nome
            riga["dettaglio"] = "chiede il certificato di %s" % nome
            if not solo_lettura:
                self._conta_nome(nome)
            return
        nome = _host_http(corpo)
        if nome:
            riga["protocollo"] = "HTTP"
            riga["nome"] = nome
            riga["dettaglio"] = "richiesta in chiaro a %s" % nome
            if not solo_lettura and not self._tetto(self.http_in_chiaro, MAX_NOMI,
                                                    "nomi"):
                self.http_in_chiaro[sorgente_ip].add(nome)

    def preleva_registro(self, massimo: int = MAX_REGISTRO) -> list:
        """I pacchetti letti da quando si e' prelevato l'ultima volta.

        Si SVUOTA prelevando: l'anello vive nel processo dell'agente, e chi lo legge
        (l'agente stesso, per travasarlo nell'archivio) deve prendere ogni riga una
        volta sola. Lasciarle dentro significherebbe riscrivere ogni giro le stesse
        righe nell'archivio.
        """
        with self._lucchetto:
            quante = min(massimo, len(self.registro))
            righe = [self.registro.popleft() for _ in range(quante)]
        return righe

    # -- lettura (motore IDS) ----------------------------------------------- #
    def riassunto(self) -> dict:
        """Il riassunto della finestra, e la finestra si azzera.

        Si svuota LEGGENDO: se il motore non passa, la finestra successiva
        continuerebbe ad accumulare e i tetti la troncherebbero. Meglio una finestra
        che si chiude con il giro dell'IDS.
        """
        with self._lucchetto:
            dati = {
                "pacchetti": self.pacchetti,
                "troncato": sorted(self.troncato),
                "mac": {k: (v[0], v[1], v[2], sorted(v[3])[:8])
                        for k, v in self.mac.items()},
                "arp_per_ip": {k: sorted(v) for k, v in self.arp_per_ip.items()
                               if len(v) > 1},
                "arp_gratuiti": dict(self.arp_gratuiti),
                "dhcp_server": dict(self.dhcp_server),
                "risposte_nomi": {k: sorted(v) for k, v in self.risposte_nomi.items()},
                "scansione_host": {k: len(v) for k, v in self.scansione_host.items()},
                "scansione_porte": {k: len(v) for k, v in self.scansione_porte.items()},
                "flussi": {k: list(v) for k, v in self.flussi.items() if len(v) >= 4},
                "nomi": dict(self.nomi),
                "sottodomini": {k: len(v) for k, v in self.sottodomini.items()},
                "http_in_chiaro": {k: sorted(v)[:16]
                                   for k, v in self.http_in_chiaro.items()},
            }
            self.azzera()
        return dati


# --------------------------------------------------------------------------- #
# Le misure che le regole leggono
# --------------------------------------------------------------------------- #
def ritmo(istanti: list) -> dict:
    """Quanto e' regolare una serie di contatti.

    Un canale di comando chiama casa a intervalli quasi fissi -- ogni sessanta
    secondi, ogni cinque minuti -- perche' dall'altra parte c'e' un programma. Una
    persona che naviga no. La regolarita' si misura con lo scarto relativo degli
    intervalli: vicino a zero significa "un orologio".

    Non e' una prova di per se': anche un aggiornamento automatico e' regolare. Per
    questo la regola che la usa pretende ANCHE che la destinazione sia fuori dalle
    reti dichiarate.
    """
    if len(istanti) < 4:
        return {"regolare": False}
    ordinati = sorted(istanti)
    intervalli = [b - a for a, b in zip(ordinati, ordinati[1:])]
    media = sum(intervalli) / len(intervalli)
    if media <= 0:
        return {"regolare": False}
    scarto = (sum((i - media) ** 2 for i in intervalli) / len(intervalli)) ** 0.5
    relativo = scarto / media
    return {
        "regolare": relativo < 0.15 and media >= 10,
        "intervallo_sec": round(media, 1),
        "scarto_relativo": round(relativo, 3),
        "contatti": len(ordinati),
    }


# Una persona scrive `posta`, `outlook`, `sharepoint`: fra un quinto e meta' delle
# lettere sono vocali. Sotto questa soglia il nome non si pronuncia, e i nomi che non
# si pronunciano o sono sigle (corte) o sono dati (lunghi).
VOCALI_MINIME = 0.15

# Sotto questa lunghezza non si giudica: `srv`, `ns1`, `vpn` non hanno vocali e sono
# perfettamente normali. Una sigla e' corta per definizione.
LUNGHEZZA_GIUDICABILE = 12

# Oltre questa, l'etichetta non e' piu' un nome: e' un contenitore. E' cosi' che si
# infilano dati dentro una query DNS.
LUNGHEZZA_SOSPETTA = 30


def nome_anomalo(nome: str) -> dict:
    """Un nome che sembra generato, o che trasporta dati.

    Due segnali, entrambi sull'ETICHETTA e mai sul contenuto:

    * la **lunghezza** -- un tunnel DNS infila i dati nel nome, e i nomi diventano
      lunghissimi;
    * la **pronunciabilita'** -- un nome scritto da una persona ha vocali, una stringa
      codificata no. Si guarda solo da `LUNGHEZZA_GIUDICABILE` in su, perche' le
      sigle corte senza vocali sono normali.
    """
    pezzi = nome.split(".")
    if len(pezzi) < 2:
        return {"anomalo": False}
    prima = pezzi[0]
    vocali = _pronunciabile(prima)
    lunga = len(prima) >= LUNGHEZZA_SOSPETTA
    illeggibile = (len(prima) >= LUNGHEZZA_GIUDICABILE and vocali < VOCALI_MINIME)
    return {
        "anomalo": lunga or illeggibile,
        "etichetta": prima[:60],
        "lunghezza": len(prima),
        "entropia": round(_entropia(prima), 2),
        "vocali": round(vocali, 2),
        "motivo": ("etichetta lunga" if lunga
                   else ("nome non pronunciabile" if illeggibile else "")),
    }
