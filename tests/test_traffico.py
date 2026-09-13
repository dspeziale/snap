"""
snap - Test dell'osservazione del traffico.

CHE COSA PROTEGGONO
-------------------
1. **Il contenuto non si legge, e non per promessa.** La cattura prende poche
   centinaia di byte per pacchetto e l'analisi estrae intestazioni e nomi: nei fatti
   che restano in memoria non ci sono byte del payload. Due test lo verificano su
   pacchetti costruiti apposta, con un segreto dentro -- uno in memoria, uno
   nell'archivio.

2. **La sonda non si denuncia da sola.** La sonda scansiona per mestiere: i suoi SYN
   verso mille indirizzi hanno la forma esatta di una scansione interna. Senza
   l'esclusione, la prima rilevazione del sensore sarebbe la sonda che segnala se
   stessa -- il genere di falso positivo che fa spegnere un prodotto.

3. **Le regole scattano davvero.** Su una rete sana il sensore produce zero
   rilevazioni, ed e' la risposta giusta; ma uno zero non dimostra che le regole
   sappiano riconoscere quello che devono. Qui si costruisce il traffico ostile.

4. **I tetti reggono.** Un osservatorio che cresce con il traffico si riempie da solo
   quando qualcuno manda rumore: riempire la memoria della sonda e' un modo economico
   per farla smettere di guardare.

remarks: Autore: Daniele Speziale - Data: 2026-09-13
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import struct
import time

import pytest

from snapprobe import traffico


# --------------------------------------------------------------------------- #
# Pacchetti costruiti a mano: si prova su byte veri, non su oggetti finti
# --------------------------------------------------------------------------- #
def _mac(testo: str) -> bytes:
    return bytes(int(p, 16) for p in testo.split(":"))


def _ip(testo: str) -> bytes:
    return bytes(int(p) for p in testo.split("."))


def ethernet(destinazione: str, sorgente: str, tipo: int) -> bytes:
    return _mac(destinazione) + _mac(sorgente) + struct.pack("!H", tipo)


def arp(sorgente_mac: str, mittente_ip: str, bersaglio_ip: str,
        operazione: int = 2) -> bytes:
    corpo = (struct.pack("!HHBBH", 1, 0x0800, 6, 4, operazione)
             + _mac(sorgente_mac) + _ip(mittente_ip)
             + _mac("00:00:00:00:00:00") + _ip(bersaglio_ip))
    return ethernet("ff:ff:ff:ff:ff:ff", sorgente_mac, 0x0806) + corpo


def ipv4(sorgente_mac: str, sorgente: str, destinazione: str, protocollo: int,
         carico: bytes) -> bytes:
    intestazione = (struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(carico), 0, 0, 64,
                                protocollo, 0) + _ip(sorgente) + _ip(destinazione))
    return ethernet("ff:ff:ff:ff:ff:ff", sorgente_mac, 0x0800) + intestazione + carico


def udp(porta_sorgente: int, porta_destinazione: int, corpo: bytes) -> bytes:
    return struct.pack("!HHHH", porta_sorgente, porta_destinazione,
                       8 + len(corpo), 0) + corpo


def tcp(porta_destinazione: int, bandiere: int, corpo: bytes = b"") -> bytes:
    return (struct.pack("!HHIIBBHHH", 40000, porta_destinazione, 0, 0, 0x50,
                        bandiere, 0, 0, 0) + corpo)


def dns_query(nome: str) -> bytes:
    etichette = b"".join(bytes([len(p)]) + p.encode() for p in nome.split("."))
    return (struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + etichette
            + b"\x00" + b"\x00\x01\x00\x01")


def dns_risposta(nome: str) -> bytes:
    """Una risposta (bit QR acceso): e' quella che conta per l'avvelenamento dei nomi."""
    etichette = b"".join(bytes([len(p)]) + p.encode() for p in nome.split("."))
    return (struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0) + etichette
            + b"\x00" + b"\x00\x01\x00\x01")


SYN = 0x02
PSH_ACK = 0x18

# L'a capo di HTTP come costante: dentro un literal si confonde con un a capo vero.
CRLF = b"\r\n"


# --------------------------------------------------------------------------- #
# Il contenuto non entra mai
# --------------------------------------------------------------------------- #
def test_il_contenuto_di_un_pacchetto_non_finisce_nell_osservatorio():
    """La prova che conta: un segreto dentro il payload non deve comparire da
    nessuna parte nel riassunto."""
    import json

    segreto = "PAROLA-SEGRETISSIMA-DA-NON-TROVARE"
    osservatorio = traffico.Osservatorio()
    corpo = b"POST /login" + CRLF + b"Host: intranet" + CRLF + CRLF + segreto.encode()
    osservatorio.osserva(
        ipv4("aa:bb:cc:dd:ee:01", "10.0.0.5", "10.0.0.9", 6, tcp(80, PSH_ACK, corpo)),
        time.time())
    riassunto = json.dumps(osservatorio.riassunto(), default=str)
    assert segreto not in riassunto
    # Il NOME invece si', perche' e' cio' che si e' scelto di leggere.
    assert "intranet" in riassunto


def test_nemmeno_nell_archivio_finisce_il_contenuto(probe_store):
    """La stessa prova un piano piu' sotto: si conservano i campi, non i byte."""
    import json

    segreto = "PAROLA-SEGRETISSIMA-DA-NON-TROVARE"
    osservatorio = traffico.Osservatorio()
    corpo = b"POST /login" + CRLF + b"Host: intranet" + CRLF + CRLF + segreto.encode()
    osservatorio.osserva(
        ipv4("aa:bb:cc:dd:ee:02", "10.0.0.5", "10.0.0.9", 6, tcp(80, PSH_ACK, corpo)),
        time.time())
    probe_store.traffico_scrivi(osservatorio.preleva_registro())
    conservato = json.dumps(probe_store.traffico_pacchetti(), default=str)
    assert segreto not in conservato
    assert "intranet" in conservato


def test_si_leggono_i_nomi_e_non_altro_da_una_query_dns():
    osservatorio = traffico.Osservatorio()
    osservatorio.osserva(
        ipv4("aa:bb:cc:dd:ee:03", "10.0.0.5", "10.0.0.1", 17,
             udp(51000, 53, dns_query("posta.comune.it"))), time.time())
    assert "posta.comune.it" in osservatorio.riassunto()["nomi"]


# --------------------------------------------------------------------------- #
# La sonda non si denuncia da sola
# --------------------------------------------------------------------------- #
def test_il_traffico_della_sonda_si_vede_ma_non_diventa_un_fatto():
    """La sonda scansiona per mestiere: senza l'esclusione segnalerebbe se stessa.

    Ma i suoi pacchetti vanno LETTI lo stesso, o nell'elenco compaiono righe mezze
    vuote con protocollo "?" -- sulla rete di collaudo erano centotrentasette. La
    regola e' una sola: si vede, non diventa un fatto.
    """
    mia = "aa:bb:cc:dd:ee:99"
    osservatorio = traffico.Osservatorio(escludi_mac={mia}, escludi_ip={"10.0.0.7"})
    for numero in range(40):
        osservatorio.osserva(
            ipv4(mia, "10.0.0.7", "10.0.0.%d" % numero, 6, tcp(445, SYN)),
            time.time())
    # Si vede, e si vede per intero.
    righe = osservatorio.preleva_registro()
    assert len(righe) == 40
    assert righe[0]["protocollo"] == "TCP"
    assert righe[0]["bandiere"] == "SYN"
    # Ma non e' un fatto: nessuna scansione, nessuna scheda in inventario.
    riassunto = osservatorio.riassunto()
    assert riassunto["scansione_host"] == {}
    assert riassunto["mac"] == {}


def test_l_esclusione_per_indirizzo_vale_anche_con_un_mac_diverso():
    """Un secondo MAC della stessa macchina non deve far rientrare dalla finestra
    cio' che si e' escluso dalla porta."""
    osservatorio = traffico.Osservatorio(escludi_ip={"10.0.0.7"})
    for numero in range(40):
        osservatorio.osserva(
            ipv4("aa:bb:cc:dd:ee:77", "10.0.0.7", "10.0.0.%d" % numero, 6,
                 tcp(445, SYN)), time.time())
    assert osservatorio.riassunto()["scansione_host"] == {}
    # Anche qui: letti, non contati.
    assert len(osservatorio.preleva_registro()) == 40


def test_una_risposta_dns_porta_il_nome():
    """Prima si leggeva solo la domanda: con dodici pacchetti DNS visti sulla rete
    vera, la colonna dei nomi restava vuota."""
    osservatorio = traffico.Osservatorio()
    osservatorio.osserva(
        ipv4("aa:bb:cc:dd:ee:04", "10.0.0.1", "10.0.0.5", 17,
             udp(53, 51000, dns_risposta("posta.comune.it"))), time.time())
    riga = osservatorio.preleva_registro()[0]
    assert riga["nome"] == "posta.comune.it"
    assert "risponde" in riga["dettaglio"]


def test_una_risposta_dns_non_conta_due_volte_nelle_statistiche():
    """Contare domanda e risposta raddoppierebbe ogni conteggio."""
    osservatorio = traffico.Osservatorio()
    osservatorio.osserva(
        ipv4("aa:bb:cc:dd:ee:05", "10.0.0.5", "10.0.0.1", 17,
             udp(51000, 53, dns_query("posta.comune.it"))), time.time())
    osservatorio.osserva(
        ipv4("aa:bb:cc:dd:ee:06", "10.0.0.1", "10.0.0.5", 17,
             udp(53, 51000, dns_risposta("posta.comune.it"))), time.time())
    assert osservatorio.riassunto()["nomi"]["posta.comune.it"] == 1


# --------------------------------------------------------------------------- #
# L'osservatorio riconosce quello che deve
# --------------------------------------------------------------------------- #
def test_due_schede_che_rivendicano_lo_stesso_indirizzo():
    osservatorio = traffico.Osservatorio()
    osservatorio.osserva(arp("aa:bb:cc:00:00:01", "10.0.0.1", "10.0.0.5"), time.time())
    osservatorio.osserva(arp("aa:bb:cc:00:00:02", "10.0.0.1", "10.0.0.5"), time.time())
    riassunto = osservatorio.riassunto()
    assert "10.0.0.1" in riassunto["arp_per_ip"]
    assert len(riassunto["arp_per_ip"]["10.0.0.1"]) == 2


def test_una_sola_scheda_per_indirizzo_non_e_una_rilevazione():
    """Il caso normale non deve comparire: un ARP per ogni host di una rete
    riempirebbe la pagina di righe che non dicono niente."""
    osservatorio = traffico.Osservatorio()
    for numero in range(30):
        osservatorio.osserva(arp("aa:bb:cc:00:00:%02x" % numero,
                                 "10.0.0.%d" % numero, "10.0.0.1"), time.time())
    assert osservatorio.riassunto()["arp_per_ip"] == {}


def test_chi_risponde_da_server_dhcp_viene_contato():
    osservatorio = traffico.Osservatorio()
    osservatorio.osserva(
        ipv4("aa:bb:cc:00:00:09", "10.0.0.1", "255.255.255.255", 17,
             udp(67, 68, b"\x02" + b"\x00" * 40)), time.time())
    assert osservatorio.riassunto()["dhcp_server"] == {"aa:bb:cc:00:00:09": 1}


def test_una_scansione_si_vede_dal_numero_di_host():
    osservatorio = traffico.Osservatorio()
    for numero in range(30):
        osservatorio.osserva(
            ipv4("aa:bb:cc:00:00:0a", "10.0.0.66", "10.0.0.%d" % numero, 6,
                 tcp(445, SYN)), time.time())
    assert osservatorio.riassunto()["scansione_host"]["10.0.0.66"] == 30


# --------------------------------------------------------------------------- #
# Il ritmo: si misura, non si indovina
# --------------------------------------------------------------------------- #
def test_un_ritmo_regolare_si_riconosce():
    """Sessanta secondi esatti: un programma, non una persona."""
    misura = traffico.ritmo([1000.0, 1060.0, 1120.0, 1180.0, 1240.0])
    assert misura["regolare"] is True
    assert 59 <= misura["intervallo_sec"] <= 61


def test_una_navigazione_irregolare_non_e_un_ritmo():
    assert traffico.ritmo([1000.0, 1003.0, 1090.0, 1092.0, 1400.0])["regolare"] is False


def test_contatti_troppo_fitti_non_sono_beaconing():
    """Dieci contatti al secondo sono una connessione che si riapre, non un canale
    di comando: la soglia minima di intervallo li esclude."""
    assert traffico.ritmo([1000.0, 1000.5, 1001.0, 1001.5, 1002.0])["regolare"] is False


def test_pochi_contatti_non_bastano_a_dire_regolare():
    assert traffico.ritmo([1000.0, 1060.0])["regolare"] is False


# --------------------------------------------------------------------------- #
# I nomi anomali
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("nome", [
    # Nomi veri, presi dalla cattura su una rete reale: nessuno deve risultare
    # anomalo, o la regola diventa rumore e chi guarda smette di guardarla.
    "posta.comune.it",
    "www.google.com",
    "eu-teams.events.data.microsoft.com",
    "sharepoint.ised.it",
    "login.microsoftonline.com",
    "safebrowsing.googleapis.com",
    "246.113.2.10.in-addr.arpa",
    "_googlecast._tcp.local",
    # Sigle senza vocali: normalissime, e corte. La lunghezza minima esiste per loro.
    "srv.local",
    "ns1.example.it",
    "vpn.ised.it",
])
def test_un_nome_normale_non_e_anomalo(nome):
    assert traffico.nome_anomalo(nome)["anomalo"] is False


@pytest.mark.parametrize("nome", [
    # Un'etichetta lunghissima: e' cosi' che si infilano dati in una query DNS.
    "a7f3b9c2d8e1f4a6b3c9d2e7f1a4b8c3d6e9f2a5b7.tunnel.example.com",
    # Non si pronuncia: un dominio generato da un algoritmo non ha vocali.
    "xk4mz9qp7wv2.example.com",
    "kq3xzp9wmv7b2.bad.net",
    "zzbcdfghjklm.evil.com",
])
def test_un_nome_che_trasporta_dati_si_riconosce(nome):
    giudizio = traffico.nome_anomalo(nome)
    assert giudizio["anomalo"] is True
    assert giudizio["motivo"]


def test_l_entropia_da_sola_non_avrebbe_distinto_niente():
    """La ragione per cui la misura e' cambiata, messa a verbale.

    Su un'etichetta corta l'entropia di Shannon misura quanti caratteri distinti ci
    sono, che per una parola breve e' quasi la lunghezza: due nomi completamente
    diversi finivano a due decimi l'uno dall'altro. Le vocali li separano.
    """
    vero = traffico.nome_anomalo("sharepoint.ised.it")
    generato = traffico.nome_anomalo("xk4mz9qp7wv2.example.com")
    assert abs(vero["entropia"] - generato["entropia"]) < 0.5, (
        "l'entropia non distingue: %s contro %s"
        % (vero["entropia"], generato["entropia"]))
    assert vero["vocali"] > 0.3 and generato["vocali"] == 0.0
    assert vero["anomalo"] is False and generato["anomalo"] is True


# --------------------------------------------------------------------------- #
# I tetti: il rumore non deve riempire la memoria
# --------------------------------------------------------------------------- #
def test_un_diluvio_di_schede_non_fa_crescere_l_osservatorio_all_infinito():
    """Riempire la memoria della sonda e' un modo economico per farla smettere di
    guardare: e' la prima cosa che farebbe chi sa che c'e'."""
    osservatorio = traffico.Osservatorio()
    for numero in range(traffico.MAX_MAC + 500):
        finto = "%02x:%02x:%02x:%02x:%02x:%02x" % tuple(
            (numero >> (8 * i)) & 0xFF for i in range(6))
        osservatorio.osserva(arp(finto, "10.1.%d.%d" % (numero // 256, numero % 256),
                                 "10.0.0.1"), time.time())
    riassunto = osservatorio.riassunto()
    assert len(riassunto["mac"]) <= traffico.MAX_MAC
    # E soprattutto lo DICHIARA, invece di presentare un elenco troncato come completo.
    assert riassunto["troncato"]


def test_un_pacchetto_malformato_non_ferma_l_osservazione():
    """E' proprio cio' che manderebbe chi vuole farla smettere."""
    osservatorio = traffico.Osservatorio()
    for storto in (b"", b"\x00", b"\xff" * 13, b"\xaa" * 15,
                   ethernet("ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:01", 0x0806)):
        osservatorio.osserva(storto, time.time())
    # Dopo i pacchetti storti si continua a leggere quelli buoni.
    osservatorio.osserva(arp("aa:bb:cc:dd:ee:02", "10.0.0.3", "10.0.0.1"), time.time())
    assert "aa:bb:cc:dd:ee:02" in osservatorio.riassunto()["mac"]


def test_il_riassunto_azzera_la_finestra():
    """Si svuota leggendo: altrimenti la finestra successiva continuerebbe ad
    accumulare e i tetti la troncherebbero."""
    osservatorio = traffico.Osservatorio()
    osservatorio.osserva(arp("aa:bb:cc:dd:ee:03", "10.0.0.4", "10.0.0.1"), time.time())
    assert osservatorio.riassunto()["pacchetti"] == 1
    assert osservatorio.riassunto()["pacchetti"] == 0


# --------------------------------------------------------------------------- #
# La cattura si dichiara quando non e' possibile
# --------------------------------------------------------------------------- #
def test_senza_libreria_si_dichiara_il_motivo():
    """L'assenza di libpcap e' una condizione normale, non un errore da far
    esplodere all'avvio."""
    from snapprobe import cattura

    if cattura.libreria() is None:
        motivo = cattura.motivo_assenza()
        assert motivo
        assert "npcap" in motivo.lower() or "libpcap" in motivo.lower()
    else:
        assert cattura.motivo_assenza() == ""


def test_il_filtro_predefinito_prende_solo_cio_che_serve_alle_regole():
    """Il filtro gira dentro il kernel: cio' che esclude non arriva al processo, e
    quindi non viene nemmeno letto."""
    from snapprobe import cattura

    for atteso in ("arp", "udp port 67", "udp port 53", "udp port 5355", "tcp-syn"):
        assert atteso in cattura.FILTRO_PREDEFINITO


def test_si_catturano_poche_centinaia_di_byte_non_il_pacchetto_intero():
    """E' la differenza fra osservare una rete e intercettarla."""
    from snapprobe import cattura

    assert cattura.SNAPLEN <= 600


# --------------------------------------------------------------------------- #
# I pacchetti si possono guardare
# --------------------------------------------------------------------------- #
# Il sensore produceva rilevazioni senza far vedere su che cosa lavorava, e un sensore
# cosi' si accende una volta e poi non si accende piu'. Queste prove coprono la strada
# che porta un pacchetto letto fino alla pagina: anello -> archivio -> tabella, con la
# ritenzione stretta e lo svuotamento allo spegnimento.
def test_ogni_pacchetto_letto_lascia_una_riga_leggibile():
    osservatorio = traffico.Osservatorio()
    osservatorio.osserva(
        ipv4("aa:bb:cc:dd:ee:20", "10.0.0.5", "10.0.0.1", 17,
             udp(51000, 53, dns_query("posta.comune.it"))), 1700000000.0)
    righe = osservatorio.preleva_registro()
    assert len(righe) == 1
    riga = righe[0]
    assert riga["protocollo"] == "UDP/DNS"
    assert riga["sorgente"] == "10.0.0.5"
    assert riga["destinazione"] == "10.0.0.1"
    assert riga["nome"] == "posta.comune.it"
    assert "chiede" in riga["dettaglio"]


def test_le_bandiere_tcp_si_leggono_in_chiaro():
    """Un RST di ritorno da mille porte e' una scansione respinta, e si vede da qui."""
    osservatorio = traffico.Osservatorio()
    osservatorio.osserva(
        ipv4("aa:bb:cc:dd:ee:21", "10.0.0.5", "10.0.0.9", 6, tcp(443, SYN)),
        1700000000.0)
    assert osservatorio.preleva_registro()[0]["bandiere"] == "SYN"


def test_il_registro_si_svuota_prelevandolo():
    """Chi lo travasa nell'archivio deve prendere ogni riga una volta sola."""
    osservatorio = traffico.Osservatorio()
    osservatorio.osserva(arp("aa:bb:cc:dd:ee:22", "10.0.0.3", "10.0.0.1"), time.time())
    assert len(osservatorio.preleva_registro()) == 1
    assert osservatorio.preleva_registro() == []


def test_il_registro_e_un_anello_e_non_cresce():
    osservatorio = traffico.Osservatorio()
    for numero in range(traffico.MAX_REGISTRO + 300):
        osservatorio.osserva(arp("aa:bb:cc:dd:ee:23", "10.0.0.%d" % (numero % 250),
                                 "10.0.0.1"), time.time())
    assert len(osservatorio.preleva_registro()) == traffico.MAX_REGISTRO


def test_il_riassunto_per_l_ids_non_svuota_i_pacchetti_da_mostrare():
    """Altrimenti la pagina si svuoterebbe da sola ogni cinque minuti, mentre la si
    guarda: il motore IDS legge il riassunto, non i pacchetti."""
    osservatorio = traffico.Osservatorio()
    osservatorio.osserva(arp("aa:bb:cc:dd:ee:24", "10.0.0.3", "10.0.0.1"), time.time())
    osservatorio.riassunto()
    assert len(osservatorio.preleva_registro()) == 1


def test_i_pacchetti_arrivano_nell_archivio_e_si_rileggono(probe_store):
    osservatorio = traffico.Osservatorio()
    osservatorio.osserva(
        ipv4("aa:bb:cc:dd:ee:25", "10.0.0.5", "10.0.0.1", 17,
             udp(51000, 53, dns_query("posta.comune.it"))), time.time())
    probe_store.traffico_scrivi(osservatorio.preleva_registro())
    righe = probe_store.traffico_pacchetti()
    assert len(righe) == 1
    assert righe[0]["nome"] == "posta.comune.it"


def test_si_cerca_dentro_ai_pacchetti(probe_store):
    osservatorio = traffico.Osservatorio()
    for nome, sorgente in (("posta.comune.it", "10.0.0.5"),
                           ("www.google.com", "10.0.0.6")):
        osservatorio.osserva(
            ipv4("aa:bb:cc:dd:ee:26", sorgente, "10.0.0.1", 17,
                 udp(51000, 53, dns_query(nome))), time.time())
    probe_store.traffico_scrivi(osservatorio.preleva_registro())
    assert len(probe_store.traffico_pacchetti(cerca="google")) == 1
    assert len(probe_store.traffico_pacchetti(cerca="10.0.0.5")) == 1
    assert len(probe_store.traffico_pacchetti(protocollo="UDP")) == 2


def test_le_conversazioni_aggregano_chi_parla_con_chi(probe_store):
    osservatorio = traffico.Osservatorio()
    for _ in range(5):
        osservatorio.osserva(
            ipv4("aa:bb:cc:dd:ee:27", "10.0.0.5", "10.0.0.9", 6, tcp(443, SYN)),
            time.time())
    probe_store.traffico_scrivi(osservatorio.preleva_registro())
    conversazioni = probe_store.traffico_conversazioni()
    assert len(conversazioni) == 1
    assert conversazioni[0]["pacchetti"] == 5
    assert conversazioni[0]["sorgente"] == "10.0.0.5"


def test_l_archivio_dei_pacchetti_non_cresce_oltre_il_tetto(probe_store):
    """Venti minuti e ventimila righe: serve a guardare adesso, non a tenere un
    registro di cio' che le persone fanno."""
    probe_store.TRAFFICO_RIGHE_MASSIME = 50
    try:
        osservatorio = traffico.Osservatorio()
        for numero in range(120):
            osservatorio.osserva(
                ipv4("aa:bb:cc:dd:ee:28", "10.0.0.%d" % (numero % 200), "10.0.0.1", 6,
                     tcp(443, SYN)), time.time())
        probe_store.traffico_scrivi(osservatorio.preleva_registro())
        assert probe_store.traffico_riepilogo()["pacchetti"] == 50
    finally:
        probe_store.TRAFFICO_RIGHE_MASSIME = 20000


def test_spegnendo_l_osservazione_non_resta_niente(probe_store):
    """Chi spegne si aspetta questo, e trovare venti minuti di pacchetti ancora li'
    sarebbe una sorpresa sgradevole."""
    osservatorio = traffico.Osservatorio()
    osservatorio.osserva(arp("aa:bb:cc:dd:ee:29", "10.0.0.3", "10.0.0.1"), time.time())
    probe_store.traffico_scrivi(osservatorio.preleva_registro())
    assert probe_store.traffico_riepilogo()["pacchetti"] == 1
    probe_store.traffico_svuota()
    assert probe_store.traffico_riepilogo()["pacchetti"] == 0


# --------------------------------------------------------------------------- #
# Le regole scattano: uno zero su una rete sana non prova che funzionino
# --------------------------------------------------------------------------- #
class _PresaFinta:
    """Una cattura che non cattura: porta solo l'osservatorio gia' riempito."""

    def __init__(self, osservatorio):
        self.osservatorio = osservatorio
        self.viva = True

    def stato(self):
        return {"interfaccia": "finta", "pacchetti": 1, "scartati": 0,
                "da": None, "filtro": "", "ultimo_errore": ""}


@pytest.fixture()
def sensore_acceso(probe_store):
    """Il sensore vero, con la cattura sostituita da un osservatorio riempito a mano."""
    from snapprobe import ids

    osservatorio = traffico.Osservatorio()
    ids.imposta_cattura(_PresaFinta(osservatorio))
    probe_store.set_setting(ids.CHIAVE_TRAFFICO_ATTIVO, "1")
    try:
        yield ids.SensoreTraffico(), osservatorio, probe_store
    finally:
        ids.imposta_cattura(None)


def _rilevazioni(sensore, archivio):
    from datetime import datetime, timezone

    return sensore.osserva(archivio, datetime.now(timezone.utc))


def _regole(rilevazioni):
    return {r.regola for r in rilevazioni}


def test_l_avvelenamento_arp_scatta_ed_e_critico(sensore_acceso):
    """Due schede che rivendicano lo stesso indirizzo: e' la forma di un attacco in
    mezzo alla comunicazione."""
    sensore, osservatorio, archivio = sensore_acceso
    osservatorio.osserva(arp("aa:bb:cc:00:00:01", "10.0.0.1", "10.0.0.5"), time.time())
    osservatorio.osserva(arp("de:ad:be:ef:00:02", "10.0.0.1", "10.0.0.5"), time.time())
    trovate = _rilevazioni(sensore, archivio)
    assert "ARP-AVVELENAMENTO" in _regole(trovate)
    voce = next(r for r in trovate if r.regola == "ARP-AVVELENAMENTO")
    assert voce.gravita == "critica"
    # La PROVA deve nominare le due schede: chi guarda deve poter decidere.
    assert "de:ad:be:ef:00:02" in voce.prova


def test_una_raffica_di_arp_gratuiti_scatta(sensore_acceso):
    from snapprobe.ids import ARP_GRATUITI_RAFFICA

    sensore, osservatorio, archivio = sensore_acceso
    for _ in range(ARP_GRATUITI_RAFFICA + 2):
        osservatorio.osserva(arp("de:ad:be:ef:00:03", "10.0.0.9", "10.0.0.9"),
                             time.time())
    assert "ARP-RAFFICA" in _regole(_rilevazioni(sensore, archivio))


def test_un_solo_arp_gratuito_non_scatta(sensore_acceso):
    """Uno e' normale dopo un riavvio: segnalarlo sarebbe rumore garantito."""
    sensore, osservatorio, archivio = sensore_acceso
    osservatorio.osserva(arp("de:ad:be:ef:00:04", "10.0.0.9", "10.0.0.9"), time.time())
    assert "ARP-RAFFICA" not in _regole(_rilevazioni(sensore, archivio))


def test_una_scansione_interna_scatta(sensore_acceso):
    from snapprobe.ids import SCANSIONE_HOST

    sensore, osservatorio, archivio = sensore_acceso
    for numero in range(SCANSIONE_HOST + 5):
        osservatorio.osserva(
            ipv4("de:ad:be:ef:00:05", "10.0.0.66", "10.0.0.%d" % numero, 6,
                 tcp(445, SYN)), time.time())
    trovate = _rilevazioni(sensore, archivio)
    assert "SCANSIONE-INTERNA" in _regole(trovate)
    assert next(r for r in trovate
                if r.regola == "SCANSIONE-INTERNA").gravita == "alta"


def test_una_macchina_che_parla_con_pochi_host_non_e_una_scansione(sensore_acceso):
    """Un client normale parla con il proprio server, il gateway e poco altro."""
    sensore, osservatorio, archivio = sensore_acceso
    for numero in range(4):
        osservatorio.osserva(
            ipv4("de:ad:be:ef:00:06", "10.0.0.20", "10.0.0.%d" % numero, 6,
                 tcp(443, SYN)), time.time())
    assert "SCANSIONE-INTERNA" not in _regole(_rilevazioni(sensore, archivio))


def test_chi_risponde_a_molti_nomi_scatta(sensore_acceso):
    """E' quello che fa Responder: rispondere a tutto per raccogliere credenziali."""
    from snapprobe.ids import NOMI_RISPOSTI_SOSPETTI

    sensore, osservatorio, archivio = sensore_acceso
    for numero in range(NOMI_RISPOSTI_SOSPETTI + 2):
        osservatorio.osserva(
            ipv4("de:ad:be:ef:00:07", "10.0.0.31", "10.0.0.5", 17,
                 udp(5355, 51000, dns_risposta("stampante%d.local" % numero))),
            time.time())
    assert "NOME-AVVELENATO" in _regole(_rilevazioni(sensore, archivio))


def test_un_apparato_che_annuncia_se_stesso_non_scatta(sensore_acceso):
    """Una stampante che annuncia i propri servizi risponde per due o tre nomi."""
    sensore, osservatorio, archivio = sensore_acceso
    for nome in ("_ipp._tcp.local", "_printer._tcp.local"):
        osservatorio.osserva(
            ipv4("de:ad:be:ef:00:08", "10.0.0.32", "224.0.0.251", 17,
                 udp(5353, 5353, dns_risposta(nome))), time.time())
    assert "NOME-AVVELENATO" not in _regole(_rilevazioni(sensore, archivio))


def test_un_nome_che_trasporta_dati_scatta(sensore_acceso):
    sensore, osservatorio, archivio = sensore_acceso
    osservatorio.osserva(
        ipv4("de:ad:be:ef:00:09", "10.0.0.40", "10.0.0.1", 17,
             udp(51000, 53, dns_query("xk4mz9qp7wv2.example.com"))), time.time())
    assert "DNS-ANOMALO" in _regole(_rilevazioni(sensore, archivio))


def test_i_nomi_normali_non_producono_rilevazioni(sensore_acceso):
    """La condizione piu' importante: su una rete che lavora, silenzio."""
    sensore, osservatorio, archivio = sensore_acceso
    for nome in ("posta.comune.it", "login.microsoftonline.com",
                 "sharepoint.ised.it", "www.google.com"):
        osservatorio.osserva(
            ipv4("de:ad:be:ef:00:0a", "10.0.0.41", "10.0.0.1", 17,
                 udp(51000, 53, dns_query(nome))), time.time())
    assert _rilevazioni(sensore, archivio) == []


def test_il_beaconing_verso_fuori_scatta(sensore_acceso):
    """Un ritmo da orologio verso un indirizzo pubblico.

    L'indirizzo NON e' uno di quelli da manuale (`192.0.2.x`, `203.0.113.x`): quelle
    reti sono riservate alla documentazione (RFC 5737) e Python le classifica come
    PRIVATE, quindi "dentro al perimetro". Il primo tentativo di questo test e'
    fallito per questo, e non per un difetto della regola.
    """
    sensore, osservatorio, archivio = sensore_acceso
    quando = 1000.0
    for _ in range(6):
        osservatorio.osserva(
            ipv4("de:ad:be:ef:00:0b", "10.0.0.50", "93.184.216.34", 6, tcp(443, SYN)),
            quando)
        quando += 60.0
    trovate = _rilevazioni(sensore, archivio)
    assert "BEACONING" in _regole(trovate)
    assert "ogni 60" in next(r for r in trovate if r.regola == "BEACONING").titolo


def test_un_ritmo_regolare_dentro_la_rete_non_scatta(sensore_acceso):
    """Dentro la rete tutto e' regolare -- monitoraggio, backup, la sonda stessa --
    e senza questo filtro la regola segnalerebbe l'infrastruttura del cliente."""
    sensore, osservatorio, archivio = sensore_acceso
    quando = 1000.0
    for _ in range(6):
        osservatorio.osserva(
            ipv4("de:ad:be:ef:00:0c", "10.0.0.51", "10.0.0.200", 6, tcp(443, SYN)),
            quando)
        quando += 60.0
    assert "BEACONING" not in _regole(_rilevazioni(sensore, archivio))


def test_il_primo_server_dhcp_non_e_un_allarme(sensore_acceso):
    """Il primo che si vede e' quello VERO: diventa la linea di base, non una
    rilevazione. Altrimenti installare la sonda segnalerebbe il router."""
    sensore, osservatorio, archivio = sensore_acceso
    osservatorio.osserva(
        ipv4("de:ad:be:ef:00:0d", "10.0.0.1", "255.255.255.255", 17,
             udp(67, 68, b"\x02" + b"\x00" * 40)), time.time())
    assert "DHCP-ABUSIVO" not in _regole(_rilevazioni(sensore, archivio))


def test_http_in_chiaro_scatta_ed_e_di_gravita_bassa(sensore_acceso):
    """Va detto, ma non e' un incidente: sta in fondo alla pagina, non in cima."""
    sensore, osservatorio, archivio = sensore_acceso
    corpo = b"GET / HTTP/1.1" + CRLF + b"Host: intranet.ised.it" + CRLF + CRLF
    osservatorio.osserva(
        ipv4("de:ad:be:ef:00:0e", "10.0.0.60", "10.0.0.80", 6,
             tcp(80, PSH_ACK, corpo)), time.time())
    trovate = _rilevazioni(sensore, archivio)
    assert "HTTP-IN-CHIARO" in _regole(trovate)
    assert next(r for r in trovate if r.regola == "HTTP-IN-CHIARO").gravita == "bassa"


def test_ogni_rilevazione_del_traffico_porta_una_prova(sensore_acceso):
    """Una rilevazione senza prova e' un'affermazione, e chi guarda non puo'
    verificarla."""
    sensore, osservatorio, archivio = sensore_acceso
    osservatorio.osserva(arp("aa:bb:cc:00:00:11", "10.0.0.1", "10.0.0.5"), time.time())
    osservatorio.osserva(arp("de:ad:be:ef:00:12", "10.0.0.1", "10.0.0.5"), time.time())
    for numero in range(25):
        osservatorio.osserva(
            ipv4("de:ad:be:ef:00:13", "10.0.0.67", "10.0.0.%d" % numero, 6,
                 tcp(445, SYN)), time.time())
    trovate = _rilevazioni(sensore, archivio)
    assert trovate
    for voce in trovate:
        assert voce.titolo and voce.prova, voce.regola
        assert voce.soggetto, voce.regola
        assert voce.sensore == "traffico"


# --------------------------------------------------------------------------- #
# Il sensore dichiara perche' non osserva
# --------------------------------------------------------------------------- #
def test_il_sensore_nasce_spento_e_lo_dice(probe_store):
    from snapprobe.ids import SensoreTraffico

    disponibile, motivo = SensoreTraffico().disponibile(probe_store)
    assert disponibile is False
    assert "si accende da Configurazione" in motivo


def test_acceso_senza_interfaccia_il_sensore_non_mente(probe_store):
    """Acceso ma non in ascolto non e' "nessuna rilevazione": e' "non sto
    guardando", e la pagina deve dire la seconda."""
    from snapprobe.ids import CHIAVE_TRAFFICO_ATTIVO, SensoreTraffico

    probe_store.set_setting(CHIAVE_TRAFFICO_ATTIVO, "1")
    disponibile, motivo = SensoreTraffico().disponibile(probe_store)
    assert disponibile is False
    assert motivo
