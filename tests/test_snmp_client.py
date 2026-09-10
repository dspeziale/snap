"""
snap - Test del client SNMPv2c della sonda.

Perche' esiste: il MAC di un nodo si ottiene con ARP, che non attraversa un router.
Su una rete reale sono stati misurati 39 MAC su 7309 nodi -- tutti e 39 nella subnet
della sonda. Gli apparati di rete conoscono quelle corrispondenze per interi segmenti
e le espongono in SNMP: questo modulo le legge.

Il modulo codifica BER a mano (nessuna dipendenza nuova: vedi la motivazione in
`snapprobe/snmp.py`), quindi i test devono verificare i BYTE, non solo il
comportamento. Il pacchetto di risposta usato qui e' scritto a mano dalla specifica,
NON generato dal codificatore di questo stesso modulo: con un pacchetto generato in
casa, un errore simmetrico fra codifica e decodifica passerebbe inosservato.

remarks: Autore: Daniele Speziale - Data: 2026-09-09
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest

# Risposta SNMPv2c scritta a mano dalla RFC 3416, byte per byte:
#
#   30 35                          SEQUENCE, 53 byte
#     02 01 01                     version = 1 (SNMPv2c)
#     04 06 "public"               community
#     a2 28                        GetResponse, 40 byte
#       02 04 12 34 56 78          request-id = 0x12345678
#       02 01 00                   error-status = 0 (nessun errore)
#       02 01 00                   error-index = 0
#       30 1a                      variable-bindings, 26 byte
#         30 18                    varbind, 24 byte
#           06 0e 2b 06 01 02 01 04 16 01 02 01 0a 14 0a 12
#                                  OID 1.3.6.1.2.1.4.22.1.2.1.10.20.10.18
#                                  (ipNetToMediaPhysAddress, if 1, IP 10.20.10.18)
#           04 06 38 14 28 28 6e 12
#                                  OCTET STRING: il MAC 38:14:28:28:6e:12
RISPOSTA_ARP = bytes.fromhex(
    "3035"
    "020101"
    "0406" "7075626c6963"
    "a228"
    "0204" "12345678"
    "020100"
    "020100"
    "301a"
    "3018"
    "060e" "2b060102010416010201" "0a140a12"
    "0406" "38142828" "6e12"
)


# --------------------------------------------------------------------------- #
# Codifica: si verificano i byte, non il fatto che "funzioni"
# --------------------------------------------------------------------------- #
def test_l_oid_si_codifica_come_dice_la_specifica():
    """I primi due archi in un byte solo (1.3 -> 43), poi un byte per arco."""
    from snapprobe.snmp import codifica_oid

    atteso = bytes.fromhex("060e" "2b060102010416010201" "0a140a12")
    assert codifica_oid("1.3.6.1.2.1.4.22.1.2.1.10.20.10.18") == atteso


def test_un_arco_grande_usa_la_base_128():
    """Sopra 127 un arco occupa piu' byte, con il bit di continuazione: e' il caso
    degli OID di costruttore (1.3.6.1.4.1.<enterprise>)."""
    from snapprobe.snmp import codifica_oid, decodifica_oid

    grezzo = codifica_oid("1.3.6.1.4.1.9999")
    # 9999 = 0x270F -> 0xCE 0x0F in base 128 con bit di continuazione.
    assert grezzo.endswith(bytes([0xCE, 0x0F]))
    assert decodifica_oid(grezzo[2:]) == "1.3.6.1.4.1.9999"


def test_la_lunghezza_lunga_scatta_oltre_127_byte():
    """Un campo di 200 byte non entra nella forma breve: BER usa 0x81 0xC8."""
    from snapprobe.snmp import OCTET_STRING, _tlv

    tlv = _tlv(OCTET_STRING, b"x" * 200)
    assert tlv[:3] == bytes([OCTET_STRING, 0x81, 0xC8])


# --------------------------------------------------------------------------- #
# Decodifica del pacchetto scritto a mano
# --------------------------------------------------------------------------- #
def test_si_legge_una_risposta_reale():
    from snapprobe.snmp import analizza_risposta

    request_id, coppie = analizza_risposta(RISPOSTA_ARP)

    assert request_id == 0x12345678
    assert len(coppie) == 1
    oid, valore = coppie[0]
    assert oid == "1.3.6.1.2.1.4.22.1.2.1.10.20.10.18"
    # Il MAC resta in BYTE: non e' testo, e decodificarlo come UTF-8 lo romperebbe.
    assert valore == bytes([0x38, 0x14, 0x28, 0x28, 0x6E, 0x12])


def test_un_pacchetto_troncato_non_fa_indovinare():
    """Meglio un errore dichiarato che un valore inventato da byte mancanti."""
    from snapprobe.snmp import SnmpError, analizza_risposta

    for taglio in (5, 20, len(RISPOSTA_ARP) - 3):
        with pytest.raises(SnmpError):
            analizza_risposta(RISPOSTA_ARP[:taglio])


def test_un_errore_dell_apparato_viene_dichiarato():
    """error-status diverso da zero: l'apparato dice che non puo' rispondere."""
    from snapprobe.snmp import SnmpError, analizza_risposta

    # Si porta error-status da 0x00 a 0x02 (noSuchName) lasciando tutto il resto.
    guasta = bytearray(RISPOSTA_ARP)
    guasta[guasta.index(bytes.fromhex("020100"))+2] = 0x02

    with pytest.raises(SnmpError):
        analizza_risposta(bytes(guasta))


# --------------------------------------------------------------------------- #
# Il confronto dei sotto-alberi si fa sui NODI, non sul testo
# --------------------------------------------------------------------------- #
def test_il_sotto_albero_si_confronta_per_nodi():
    """1.3.6.1.2.1.4.22 NON e' figlio di 1.3.6.1.2.1.4.2, anche se ne e' un
    prefisso come stringa: confrontando i testi il walk uscirebbe dal ramo giusto
    o vi resterebbe dentro per sbaglio."""
    from snapprobe.snmp import sotto_albero

    assert sotto_albero("1.3.6.1.2.1.4.22.1.2.1", "1.3.6.1.2.1.4.22.1.2")
    assert not sotto_albero("1.3.6.1.2.1.4.22.1.2.1", "1.3.6.1.2.1.4.2")
    assert not sotto_albero("1.3.6.1.2.1.5", "1.3.6.1.2.1.4")


# --------------------------------------------------------------------------- #
# La tabella ARP: cosa si tiene e cosa si scarta
# --------------------------------------------------------------------------- #
def _finto_walk(coppie):
    """Sostituisce il walk di rete con un elenco dato: i test non toccano la rete."""
    def walk(host, community, radice, **opzioni):
        return coppie
    return walk


def test_la_tabella_arp_ricava_l_ip_dall_oid_e_il_mac_dal_valore(monkeypatch):
    from snapprobe import snmp

    monkeypatch.setattr(snmp, "walk", _finto_walk([
        ("1.3.6.1.2.1.4.22.1.2.1.10.20.10.18", bytes.fromhex("381428286e12")),
        ("1.3.6.1.2.1.4.22.1.2.1.10.20.10.166", bytes.fromhex("ac1a3daf9641")),
    ]))

    assert snmp.arp_table("10.20.10.1", "public") == {
        "10.20.10.18": "38:14:28:28:6e:12",
        "10.20.10.166": "ac:1a:3d:af:96:41",
    }


def test_le_voci_incomplete_si_scartano_invece_di_inventarle(monkeypatch):
    """Una riga di inventario con un MAC sbagliato e' peggio di una senza: la
    seconda si vede che manca, la prima no."""
    from snapprobe import snmp

    monkeypatch.setattr(snmp, "walk", _finto_walk([
        ("1.3.6.1.2.1.4.22.1.2.1.10.20.10.5", b""),                       # vuoto
        ("1.3.6.1.2.1.4.22.1.2.1.10.20.10.6", bytes.fromhex("0011")),      # 2 byte
        ("1.3.6.1.2.1.4.22.1.2.1.10.20.10.7", bytes(6)),                   # tutto zeri
        ("1.3.6.1.2.1.4.22.1.2.1.10.20.10.8", bytes.fromhex("381428286e12")),
    ]))

    assert snmp.arp_table("10.20.10.1", "public") == {
        "10.20.10.8": "38:14:28:28:6e:12"}


# --------------------------------------------------------------------------- #
# Da MAC a PORTA FISICA: la catena delle tre tabelle
# --------------------------------------------------------------------------- #
# La tabella di forwarding da' un NUMERO DI PORTA BRIDGE, che e' un indice interno
# del MIB: non corrisponde al numero stampato sullo chassis ne' all'ifIndex.
# Riportarlo come sta significherebbe scrivere "porta 47" in inventario senza che
# nessuno possa trovarla. Questi test verificano che la catena si componga, e che
# quando si interrompe NON si inventi un valore.
def test_il_mac_si_ricava_dagli_ultimi_sei_archi_dell_oid():
    """L'indice della tabella di forwarding E' il MAC, un arco per byte. Nella
    versione con VLAN (dot1q) l'indice e' VLAN+MAC: prendendo gli ultimi sei archi
    funziona per entrambe."""
    from snapprobe.snmp import _mac_da_archi

    # dot1d: ... .1.2 . 56.20.40.40.110.18
    assert _mac_da_archi("1.3.6.1.2.1.17.4.3.1.2.56.20.40.40.110.18".split(".")) \
        == "38:14:28:28:6e:12"
    # dot1q: l'indice comincia con la VLAN (100), il MAC resta in coda.
    assert _mac_da_archi("1.3.6.1.2.1.17.7.1.2.2.1.2.100.56.20.40.40.110.18".split(".")) \
        == "38:14:28:28:6e:12"
    # Un arco fuori dall'intervallo di un byte non e' un MAC.
    assert _mac_da_archi("1.2.3.999.20.40.40.110.18".split(".")) is None


def test_la_catena_traduce_il_numero_di_porta_nel_nome(monkeypatch):
    from snapprobe import snmp

    def finto_walk(host, community, radice, **opzioni):
        if radice == snmp.OID_DOT1D_FDB_PORT:
            return [("1.3.6.1.2.1.17.4.3.1.2.56.20.40.40.110.18", 47)]
        if radice == snmp.OID_DOT1D_BASE_PORT_IFINDEX:
            return [("1.3.6.1.2.1.17.1.4.1.2.47", 10112)]
        if radice == snmp.OID_IF_NAME:
            return [("1.3.6.1.2.1.31.1.1.1.1.10112", b"Gi1/0/12")]
        return []

    monkeypatch.setattr(snmp, "walk", finto_walk)

    assert snmp.mac_su_porta("10.20.10.2", "vera") == {
        "38:14:28:28:6e:12": "Gi1/0/12"}


def test_se_la_catena_si_interrompe_non_si_inventa_una_porta(monkeypatch):
    """Uno switch che non espone il BRIDGE-MIB (o i nomi delle interfacce) lascia
    il dato incompleto: meglio NIENTE che un indice interno spacciato per porta."""
    from snapprobe import snmp

    def solo_fdb(host, community, radice, **opzioni):
        if radice == snmp.OID_DOT1D_FDB_PORT:
            return [("1.3.6.1.2.1.17.4.3.1.2.56.20.40.40.110.18", 47)]
        return []          # nessuna traduzione disponibile

    monkeypatch.setattr(snmp, "walk", solo_fdb)

    assert snmp.mac_su_porta("10.20.10.2", "vera") == {}


def test_si_ripiega_sulla_tabella_con_vlan(monkeypatch):
    """Molti switch popolano solo la versione Q-BRIDGE: se la prima e' vuota si
    prova l'altra, perche' quale sia popolata dipende dall'apparato."""
    from snapprobe import snmp

    def finto_walk(host, community, radice, **opzioni):
        if radice == snmp.OID_DOT1D_FDB_PORT:
            return []
        if radice == snmp.OID_DOT1Q_FDB_PORT:
            return [("1.3.6.1.2.1.17.7.1.2.2.1.2.100.56.20.40.40.110.18", 3)]
        if radice == snmp.OID_DOT1D_BASE_PORT_IFINDEX:
            return [("1.3.6.1.2.1.17.1.4.1.2.3", 3)]
        if radice == snmp.OID_IF_NAME:
            return [("1.3.6.1.2.1.31.1.1.1.1.3", b"GigabitEthernet0/3")]
        return []

    monkeypatch.setattr(snmp, "walk", finto_walk)

    assert snmp.mac_su_porta("10.20.10.2", "vera") == {
        "38:14:28:28:6e:12": "GigabitEthernet0/3"}
