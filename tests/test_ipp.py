"""
snap - Test della lettura IPP: marca, modello, seriale e firmware di una stampante.

Perche' esiste. Alcune famiglie di apparati costruiscono l'interfaccia web in
JavaScript e non servono nessun dato in HTML: la lettura delle pagine riconosce la
marca (compare nel codice) ma non il modello. Sul campo erano 382 apparati Kyocera con
la marca e il modello vuoto. Gli stessi apparati rispondono a IPP, che e' il protocollo
con cui ogni sistema operativo identifica una stampante quando la si aggiunge.

Il compromesso e' dichiarato: IPP viaggia su HTTP con un POST -- non esiste un modo GET
di chiedere gli attributi -- e la deroga alla regola "solo GET" e' ristretta a una sola
operazione, `Get-Printer-Attributes`, che la specifica definisce di sola lettura.

La risposta usata nelle prove e' quella vera di un apparato in esercizio, con il numero
di serie sostituito.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture()
def risposta_reale() -> bytes:
    return (FIXTURES / "ipp_kyocera_attributi.bin").read_bytes()


# --------------------------------------------------------------------------- #
# Interpretazione della risposta
# --------------------------------------------------------------------------- #
def test_gli_attributi_di_un_apparato_reale_si_leggono(risposta_reale):
    from snapprobe.ipp_probe import interpreta_risposta

    attributi = interpreta_risposta(risposta_reale)

    assert attributi["printer-make-and-model"] == "ECOSYS M5526cdn"
    assert attributi["printer-info"] == "Kyocera ECOSYS M5526cdn"
    assert attributi["printer-firmware-string-version"].startswith("2R7_")


def test_i_fatti_arrivano_con_i_nomi_del_prodotto(risposta_reale):
    """Gli stessi nomi della lettura web: chi legge l'inventario non deve sapere da
    quale protocollo e' arrivato un modello."""
    from snapprobe.ipp_probe import fatti_da_attributi, interpreta_risposta

    fatti = fatti_da_attributi(interpreta_risposta(risposta_reale))

    assert fatti["modello"] == "ECOSYS M5526cdn"
    assert fatti["marca_dichiarata"] == "Kyocera"
    assert fatti["nome_dispositivo"] == "Kyocera ECOSYS M5526cdn"
    assert fatti["seriale"] == "AB12345678"
    assert fatti["firmware"].startswith("2R7_")


def test_il_numero_di_serie_sta_in_fondo_all_identificativo(risposta_reale):
    """`printer-device-id` e' una stringa di duecento caratteri e il seriale sta in
    fondo: accorciarla prima di interpretarla lo faceva perdere. E' il difetto trovato
    provando il lettore sull'apparato vero."""
    from snapprobe.ipp_probe import MAX_VALORE, interpreta_risposta

    attributi = interpreta_risposta(risposta_reale)
    identificativo = attributi["printer-device-id"]

    assert len(identificativo) > MAX_VALORE
    assert "SER:AB12345678" in identificativo


def test_il_nome_della_coda_non_diventa_un_nome_host(risposta_reale):
    """`printer-name` e' il nome della coda di stampa ("KM12C1BA") e
    `printer-dns-sd-name` e' il nome con cui l'apparato si annuncia: nessuno dei due
    e' un nome host, e spacciarli per tale sarebbe un dato inventato."""
    from snapprobe.ipp_probe import fatti_da_attributi, interpreta_risposta

    fatti = fatti_da_attributi(interpreta_risposta(risposta_reale))

    assert "nome_host" not in fatti


def test_una_risposta_vuota_o_troncata_non_manda_in_errore():
    from snapprobe.ipp_probe import interpreta_risposta

    assert interpreta_risposta(b"") == {}
    assert interpreta_risposta(b"\x01\x01\x00\x00") == {}
    # Intestazione valida e corpo tagliato a metà di un valore.
    parziale = b"\x01\x01\x00\x00\x00\x00\x00\x01\x01\x41\x00\x05nome\x00\x40abc"
    assert isinstance(interpreta_risposta(parziale), dict)


def test_un_valore_che_contiene_marcatura_non_diventa_un_fatto():
    from snapprobe.ipp_probe import fatti_da_attributi

    fatti = fatti_da_attributi({"printer-make-and-model": "<script>x</script>"})

    assert "modello" not in fatti


def test_i_valori_lunghi_vengono_accorciati():
    from snapprobe.ipp_probe import MAX_VALORE, fatti_da_attributi

    fatti = fatti_da_attributi({"printer-info": "A" * 400})

    assert len(fatti["nome_dispositivo"]) <= MAX_VALORE


# --------------------------------------------------------------------------- #
# Costruzione della richiesta: e' qui che sta la garanzia di sola lettura
# --------------------------------------------------------------------------- #
def test_la_richiesta_chiede_soltanto_gli_attributi():
    """L'operazione e' una costante del modulo: nessuna chiamata puo' trasformare
    questa lettura in una scrittura o in una stampa."""
    from snapprobe.ipp_probe import OPERAZIONE_ATTRIBUTI, costruisci_richiesta

    corpo = costruisci_richiesta("10.0.0.1", "/ipp/print")

    assert OPERAZIONE_ATTRIBUTI == 0x000B, "Get-Printer-Attributes, sola lettura"
    assert struct.unpack(">H", corpo[2:4])[0] == OPERAZIONE_ATTRIBUTI
    assert corpo[:2] == b"\x01\x01", "IPP 1.1"
    assert corpo.endswith(b"\x03")


def test_la_richiesta_non_chiede_la_coda_dei_lavori():
    """La coda contiene i nomi dei documenti e degli utenti: dati personali di cui un
    inventario non ha bisogno (GDPR, minimizzazione)."""
    from snapprobe.ipp_probe import ATTRIBUTI_RICHIESTI, costruisci_richiesta

    corpo = costruisci_richiesta("10.0.0.1", "/ipp/print")

    for vietato in (b"job", b"document", b"user", b"requesting-user-name"):
        assert vietato not in corpo.lower(), vietato
    assert all(a.startswith("printer-") for a in ATTRIBUTI_RICHIESTI)


def test_la_richiesta_dichiara_l_apparato_a_cui_e_rivolta():
    from snapprobe.ipp_probe import costruisci_richiesta

    corpo = costruisci_richiesta("10.0.0.1", "/ipp/print")

    assert b"ipp://10.0.0.1/ipp/print" in corpo


# --------------------------------------------------------------------------- #
# Scelta delle porte
# --------------------------------------------------------------------------- #
def test_la_porta_dedicata_si_prova_per_prima():
    from snapprobe.ipp_probe import porte_ipp

    porte = [{"protocol": "tcp", "port": 80, "state": "open", "service_name": "http"},
             {"protocol": "tcp", "port": 631, "state": "open", "service_name": "ipp"}]

    assert porte_ipp(porte)[0] == 631, "la 631 risponde senza ambiguita'"


def test_una_porta_chiusa_non_si_interroga():
    from snapprobe.ipp_probe import porte_ipp

    porte = [{"protocol": "tcp", "port": 631, "state": "closed", "service_name": "ipp"},
             {"protocol": "udp", "port": 631, "state": "open", "service_name": "ipp"}]

    assert porte_ipp(porte) == []


def test_ipp_dichiarato_su_una_porta_insolita_viene_letto():
    from snapprobe.ipp_probe import porte_ipp

    porte = [{"protocol": "tcp", "port": 7631, "state": "open", "service_name": "ipp"}]

    assert porte_ipp(porte) == [7631]


# --------------------------------------------------------------------------- #
# Lettura completa, senza rete
# --------------------------------------------------------------------------- #
class RispostaFinta:
    def __init__(self, stato, corpo: bytes):
        self.status_code = stato
        self._corpo = corpo
        self.headers = {"Content-Type": "application/ipp"}
        self.raw = self

    def read(self, quanti, decode_content=True):
        return self._corpo[:quanti]

    def close(self):
        pass

    def __bool__(self):
        return self.status_code < 400


def test_la_lettura_restituisce_una_voce_pronta_per_l_inventario(risposta_reale,
                                                                monkeypatch):
    import snapprobe.ipp_probe as lettore

    chiamate = []

    class FintoRequests:
        @staticmethod
        def post(indirizzo, **parametri):
            chiamate.append(indirizzo)
            return RispostaFinta(200, risposta_reale)

    monkeypatch.setitem(__import__("sys").modules, "requests", FintoRequests)
    esito = lettore.leggi("10.0.0.1", [{"protocol": "tcp", "port": 631,
                                        "state": "open", "service_name": "ipp"}])

    assert esito["scheme"] == "ipp"
    assert esito["port"] == 631
    assert esito["marca"] == "Kyocera"
    assert esito["modello"] == "ECOSYS M5526cdn"
    assert esito["tipo_probabile"] == "printer"
    assert esito["fatti"]["seriale"] == "AB12345678"
    assert len(chiamate) == 1, "un solo tentativo quando il primo risponde"


def test_un_apparato_che_non_parla_ipp_non_e_un_guasto(monkeypatch):
    import snapprobe.ipp_probe as lettore

    class FintoRequests:
        @staticmethod
        def post(indirizzo, **parametri):
            raise OSError("connessione rifiutata")

    monkeypatch.setitem(__import__("sys").modules, "requests", FintoRequests)

    assert lettore.leggi("10.0.0.1", [{"protocol": "tcp", "port": 631,
                                       "state": "open", "service_name": "ipp"}]) == {}


def test_i_tentativi_sono_limitati(monkeypatch):
    """Un apparato che risponde 200 con un corpo inutile non deve far provare
    venti indirizzi."""
    import snapprobe.ipp_probe as lettore

    chiamate = []

    class FintoRequests:
        @staticmethod
        def post(indirizzo, **parametri):
            chiamate.append(indirizzo)
            return RispostaFinta(200, b"\x01\x01\x00\x00\x00\x00\x00\x01\x03")

    monkeypatch.setitem(__import__("sys").modules, "requests", FintoRequests)
    lettore.leggi("10.0.0.1", [{"protocol": "tcp", "port": 631, "state": "open",
                                "service_name": "ipp"},
                               {"protocol": "tcp", "port": 80, "state": "open",
                                "service_name": "http"}])

    assert len(chiamate) <= lettore.MAX_TENTATIVI


# --------------------------------------------------------------------------- #
# Dalla sonda all'inventario
# --------------------------------------------------------------------------- #
def test_la_fase_web_interroga_anche_chi_ha_solo_ipp():
    """Una stampante che espone solo la 631 non ha una pagina da leggere, ma ha un
    modello e un numero di serie da dichiarare."""
    from snapprobe.ipp_probe import porte_ipp
    from snapprobe.web_probe import porte_web

    solo_ipp = [{"protocol": "tcp", "port": 631, "state": "open", "service_name": "ipp"}]

    assert porte_web(solo_ipp) == []
    assert porte_ipp(solo_ipp) == [631]


def test_la_lettura_ipp_si_conserva_come_le_altre(server_app):
    """Arriva sulla console come una riga di `node_web` con schema `ipp`: la tabella
    conserva letture di interfacce di gestione, e IPP e' una di quelle."""
    import uuid

    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str
        from snapserver.ingest import apply_batch

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
        adesso = utc_now_str()
        sonda = query("SELECT id FROM probes WHERE tenant_id = ?", (tenant_id,), one=True)
        probe_id = int(sonda["id"]) if sonda else execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, created_at,"
            " updated_at) VALUES (?, 'uid-ipp', 'sonda-ipp', 'Sonda', 'active', ?, ?)",
            (tenant_id, adesso, adesso))
        node_id = execute(
            "INSERT INTO nodes (tenant_id, probe_id, ip, status, first_seen_at,"
            " last_seen_at, created_at, updated_at)"
            " VALUES (?, ?, '10.33.0.32', 'up', ?, ?, ?, ?)",
            (tenant_id, probe_id, adesso, adesso, adesso, adesso))

        apply_batch(tenant_id, probe_id, {
            "batch_uid": "ipp-%s" % uuid.uuid4().hex[:8],
            "records": {"web": [{"ip": "10.33.0.32", "pages": [{
                "port": 631, "scheme": "ipp", "stato": 200, "firma": "ipp",
                "tipo_probabile": "printer", "marca": "Kyocera",
                "modello": "ECOSYS M5526cdn", "pagine_lette": 1,
                "fatti": {"modello": "ECOSYS M5526cdn",
                          "nome_dispositivo": "Kyocera ECOSYS M5526cdn",
                          "seriale": "AB12345678",
                          "firmware": "2R7_2000.003.101"},
            }]}]}})

        riga = query("SELECT scheme, port, brand, model, device_name, serial, firmware"
                     " FROM node_web WHERE node_id = ?", (node_id,), one=True)
        from snapserver.fingerprint import identify
        from snapserver.ingest import build_evidence

        verdetto = identify(build_evidence(tenant_id, node_id))

    assert riga["scheme"] == "ipp" and riga["port"] == 631
    assert riga["brand"] == "Kyocera"
    assert riga["model"] == "ECOSYS M5526cdn"
    assert riga["serial"] == "AB12345678"
    assert riga["firmware"].startswith("2R7_")
    assert verdetto["device_type"] == "printer"
    assert "Kyocera ECOSYS M5526cdn" in " ".join(p["prova"] for p in verdetto["evidence"])
