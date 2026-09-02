"""
snap - Test delle tabelle nei report: nessun dato tagliato, nessuna intestazione sopra
l'altra.

Difetto segnalato dall'operatore su un documento reale: nell'elenco delle reti senza
zona dichiarata la colonna della subnet mostrava `10.10.14` al posto di
`10.10.140.0/24`. Non e' una subnet abbreviata, e' un'ALTRA subnet -- e il documento va
al cliente. Nella stessa tabella "DISPOSITIVI" e "RISCONTRI APERTI" finivano una sopra
l'altra.

La causa era la stessa per entrambe le cose: le larghezze venivano dai pesi dichiarati
dal chiamante senza guardare il contenuto, e cio' che non entrava veniva tagliato
lettera per lettera in silenzio; le intestazioni non venivano nemmeno controllate.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest
from reportlab.pdfbase import pdfmetrics

# Le colonne del caso segnalato, con i valori piu' lunghi che la rete produce davvero.
INTESTAZIONI = ["Subnet", "Etichetta", "Indirizzi", "Dispositivi", "Riscontri aperti"]
PESI = [1.2, 2.4, .8, .8, 1.0]
ALLINEAMENTO = ["l", "l", "r", "r", "r"]
RIGHE = [
    ["10.10.140.0/24", "Utenza piano terzo", "254", "72", "220"],
    ["10.1.26.0/24", "", "254", "43", "211"],
    ["192.168.100.0/22", "Reparto amministrazione e contabilita'", "1022", "34", "182"],
    ["10.255.255.248/29", "Interconnessione con la sede distaccata", "6", "3", "8"],
]


@pytest.fixture()
def foglio(server_app, tmp_path):
    """Un foglio vero: le larghezze dipendono dai font effettivamente caricati."""
    with server_app.app_context():
        from snapserver.reports.render_pdf import Foglio

        yield Foglio(tmp_path / "prova.pdf", kind="wide", titolo="Prova delle tabelle",
                     tenant="Tenant di prova", intervallo="prova",
                     generato="2026-08-31 10:00", orizzontale=True)


def _spazio_utile(foglio, colonne=1):
    from snapserver.reports.render_pdf import MARGINE

    utile = foglio.larghezza - 2 * MARGINE
    if colonne > 1:
        return (utile - foglio.GRONDA * (colonne - 1)) / colonne
    return utile


# --------------------------------------------------------------------------- #
# Il dato non si taglia
# --------------------------------------------------------------------------- #
def test_a_pagina_piena_nessun_valore_viene_abbreviato(foglio):
    larghezze, corpo, abbreviata = foglio._misura_colonne(
        INTESTAZIONI, RIGHE, PESI, ALLINEAMENTO, _spazio_utile(foglio))

    assert not abbreviata
    for riga in RIGHE:
        for indice, valore in enumerate(riga):
            larga = pdfmetrics.stringWidth(valore, foglio._font_cella(indice), corpo)
            assert larga <= larghezze[indice] - foglio.RIENTRO, (
                "%r non entra nella propria colonna" % valore)


def test_la_subnet_resta_intera_anche_a_mezza_pagina(foglio):
    """Il caso segnalato: due blocchi affiancati, colonne strette."""
    larghezze, corpo, _ = foglio._misura_colonne(
        INTESTAZIONI, RIGHE, PESI, ALLINEAMENTO, _spazio_utile(foglio, colonne=2))

    for riga in RIGHE:
        testo, tagliato = foglio._entra(riga[0], foglio._font_cella(0), corpo,
                                        larghezze[0] - foglio.RIENTRO)
        assert not tagliato, "la subnet non si abbrevia: %r" % riga[0]
        assert testo == riga[0]


def test_i_pesi_dichiarati_non_stringono_una_colonna_sotto_il_contenuto(foglio):
    """Peso ridicolo sulla prima colonna: prima bastava a tagliare gli indirizzi."""
    larghezze, corpo, _ = foglio._misura_colonne(
        INTESTAZIONI, RIGHE, [0.05, 4.0, .5, .5, .5], ALLINEAMENTO,
        _spazio_utile(foglio, colonne=2))

    piu_lunga = max(RIGHE, key=lambda r: len(r[0]))[0]
    assert (pdfmetrics.stringWidth(piu_lunga, foglio._font_cella(0), corpo)
            <= larghezze[0] - foglio.RIENTRO)


def test_una_tabella_che_a_meta_pagina_perderebbe_dati_torna_a_colonna_unica(foglio):
    """Meglio un documento piu' lungo di un elenco di subnet troncate."""
    lunghe = [["10.10.140.0/24",
               "Descrizione molto lunga che non entra in nessun modo su mezza pagina"
               " perche' continua e continua", "254", "72", "220"]] * 4

    _, _, a_meta = foglio._misura_colonne(INTESTAZIONI, lunghe, PESI, ALLINEAMENTO,
                                          _spazio_utile(foglio, colonne=2))
    _, _, a_piena = foglio._misura_colonne(INTESTAZIONI, lunghe, PESI, ALLINEAMENTO,
                                           _spazio_utile(foglio))

    assert a_meta, "a mezza pagina questa tabella perde pezzi"
    assert not a_piena, "a pagina piena entra: e' il caso in cui si deve ripiegare"


def test_la_stretta_la_paga_la_descrizione_non_l_indirizzo(foglio):
    """Quando lo spazio non basta, chi cede e' il testo, non l'identita' della riga.

    In uno spazio cosi' stretto l'indirizzo non entra su una riga sola: viene mandato
    a capo, e quello che si verifica e' che non ne perda un pezzo. La descrizione
    invece cede spazio -- e' lei a pagare la stretta.
    """
    indirizzo = "10.255.255.248/29"
    descrizione = ("Descrizione lunghissima che serve solo a togliere spazio alle altre"
                   " colonne e non finisce mai")
    lunghe = [[indirizzo, descrizione, "1022", "72", "220"]] * 3
    larghezze, corpo, abbreviata = foglio._misura_colonne(
        INTESTAZIONI, lunghe, PESI, ALLINEAMENTO, _spazio_utile(foglio, colonne=3))

    assert abbreviata, "in questo spazio la tabella non entra su una riga per cella"

    linee, perduto = foglio._righe_cella(indirizzo, foglio._font_cella(0), corpo,
                                         larghezze[0] - foglio.RIENTRO,
                                         foglio.MAX_RIGHE_CELLA)
    assert not perduto, "l'indirizzo va a capo, non si abbrevia"
    assert "".join(linee) == indirizzo, "l'indirizzo resta intero: %r" % linee

    # Chi ha ceduto: si confronta lo spazio ottenuto con quello che serviva.
    def quota(indice, valore):
        serve = pdfmetrics.stringWidth(valore, foglio._font_cella(indice), corpo)
        return (larghezze[indice] - foglio.RIENTRO) / serve

    assert quota(1, descrizione) < quota(0, indirizzo), (
        "la descrizione deve ottenere una quota minore di cio' che le servirebbe")


def test_un_valore_abbreviato_lo_dichiara_con_i_puntini(foglio):
    """`10.10.14` al posto di `10.10.140.0/24` e' un dato falso; `10.10.14...` e' un
    dato abbreviato. Fra le due cose passa la differenza fra un errore e una nota."""
    testo, tagliato = foglio._entra("Descrizione che non entra", foglio.font["corpo"],
                                    8, 40)

    assert tagliato
    assert testo.endswith("...")
    assert len(testo) > 3, "qualcosa del valore deve restare leggibile"


def test_uno_spazio_ridicolo_non_manda_in_errore(foglio):
    """Nessuna eccezione e nessun ciclo infinito quando la colonna e' piu' stretta dei
    puntini: si perde il valore, non il documento."""
    testo, tagliato = foglio._entra("10.10.140.0/24", foglio.font["mono"], 8, 2)

    assert tagliato
    assert testo == ""


# --------------------------------------------------------------------------- #
# Le intestazioni non si sovrappongono
# --------------------------------------------------------------------------- #
def test_ogni_colonna_e_larga_almeno_quanto_il_proprio_titolo(foglio):
    """Si leggeva "DISPOSITIVIRISCONTRI APERTI": due titoli scritti uno sopra l'altro."""
    larghezze, _, _ = foglio._misura_colonne(
        INTESTAZIONI, RIGHE, PESI, ALLINEAMENTO, _spazio_utile(foglio, colonne=3))

    for indice, titolo in enumerate(INTESTAZIONI):
        minimo = pdfmetrics.stringWidth(titolo.upper(), foglio.font["titolo"],
                                        foglio.CORPO_TESTATA_MINIMO)
        assert larghezze[indice] >= minimo, (
            "il titolo %r sfora nella colonna successiva" % titolo)


def test_le_larghezze_riempiono_lo_spazio_senza_sforarlo(foglio):
    for colonne in (1, 2, 3):
        spazio = _spazio_utile(foglio, colonne)
        larghezze, _, _ = foglio._misura_colonne(INTESTAZIONI, RIGHE, PESI,
                                                 ALLINEAMENTO, spazio)
        assert sum(larghezze) <= spazio + .5, "la tabella esce dal margine"


# --------------------------------------------------------------------------- #
# Robustezza e disegno effettivo
# --------------------------------------------------------------------------- #
def test_una_riga_piu_corta_delle_intestazioni_non_rompe_la_tabella(foglio):
    """I dataset non sempre riempiono tutte le celle."""
    righe = [["10.10.140.0/24", "Utenza"], ["10.1.26.0/24", "", "254", "43", "211"]]

    foglio.tabella(INTESTAZIONI, righe, larghezze=PESI, allineamento=ALLINEAMENTO)

    assert foglio.y < foglio.altezza


def test_i_marcatori_di_gravita_non_finiscono_nel_testo(foglio):
    from snapserver.reports.render_pdf import ATTENZIONE, CRITICO, INCHIOSTRO_2, OK

    assert foglio._cella("!!5 critiche") == (CRITICO, "5 critiche")
    assert foglio._cella("!2 alte") == (ATTENZIONE, "2 alte")
    assert foglio._cella("+nessuna") == (OK, "nessuna")
    assert foglio._cella(None) == (INCHIOSTRO_2, "")
    assert foglio._cella(0) == (INCHIOSTRO_2, "0"), "uno zero e' un dato, non un vuoto"


def test_i_marcatori_non_allargano_la_colonna(foglio):
    """La larghezza si misura sul testo mostrato, non sui punti esclamativi."""
    con = foglio._misura_colonne(["Esiti"], [["!!5 critiche"]], [1.0], ["l"], 400)
    senza = foglio._misura_colonne(["Esiti"], [["5 critiche"]], [1.0], ["l"], 400)

    assert con[0][0] == senza[0][0]


def test_la_tabella_affiancata_misura_su_tutte_le_righe(foglio):
    """Le colonne devono essere larghe uguale in cima e in fondo all'elenco: se ogni
    blocco si misurasse da se', la stessa tabella cambierebbe forma a metà pagina."""
    misurate = []
    originale = foglio._misura_colonne

    def spia(intestazioni, righe, pesi, allineamento, utile):
        misurate.append(len(list(righe)))
        return originale(intestazioni, righe, pesi, allineamento, utile)

    foglio._misura_colonne = spia
    foglio.tabella(INTESTAZIONI, RIGHE * 30, larghezze=PESI,
                   allineamento=ALLINEAMENTO, colonne=2)
    foglio._misura_colonne = originale

    assert misurate, "la misura viene fatta"
    assert all(quante == len(RIGHE) * 30 for quante in misurate), (
        "ogni blocco misura sull'intera tabella")


def test_la_tabella_vuota_resta_una_nota(foglio):
    prima = foglio.y
    foglio.tabella(INTESTAZIONI, [], nota_vuota="Nessun dato per questo intervallo.")

    assert foglio.y < prima


# --------------------------------------------------------------------------- #
# Marchio
# --------------------------------------------------------------------------- #
def test_il_marchio_dei_documenti_e_in_maiuscolo(server_app):
    """Quattro lettere minuscole accanto agli archi si leggono come una parola
    qualsiasi: sui documenti il marchio e' SNAP."""
    with server_app.app_context():
        from snapserver.reports.render_pdf import MARCHIO, PRODOTTO

    assert MARCHIO == "SNAP"
    assert PRODOTTO == "snap", "nel testo e nei metadati il prodotto tiene il suo nome"


def test_il_frontespizio_porta_il_riferimento_del_documento(server_app, tmp_path):
    """Sopra il pie' del frontespizio, in grassetto e a corpo grande, ci sono tenant,
    istante di generazione e periodo di riferimento: chi riceve il report fuori dal
    gruppo operativo lo colloca subito. Vale per tutti i report, che passano tutti dal
    frontespizio comune."""
    pypdf = pytest.importorskip("pypdf")
    with server_app.app_context():
        from snapserver.reports.render_pdf import Foglio

        percorso = tmp_path / "riferimento.pdf"
        foglio = Foglio(percorso, kind="wide", titolo="Report di prova",
                        tenant="ACME S.p.A.",
                        intervallo="dal 01/08/2026 al 02/09/2026",
                        generato="2026-09-02 09:34:00", sezioni=["Prima"])
        foglio.c.save()

    testo = pypdf.PdfReader(str(percorso)).pages[0].extract_text()
    assert "Tenant ACME S.p.A." in testo
    assert "periodo di riferimento" in testo
    assert "dal 01/08/2026 al 02/09/2026" in testo


# --------------------------------------------------------------------------- #
# Il corpo tipografico
# --------------------------------------------------------------------------- #
def test_una_descrizione_lunghissima_non_rimpicciolisce_tutta_la_tabella(foglio):
    """Le colonne di testo libero non hanno un limite di lunghezza. Rimpicciolire
    tutte le cifre per una sola descrizione lunga peggiorerebbe il documento senza
    risolvere niente: si stringe quella colonna, il corpo resta pieno."""
    righe = [["10.10.140.0/24", "Descrizione " * 60, "254", "72", "220"]]

    _, corpo, abbreviata = foglio._misura_colonne(
        INTESTAZIONI, righe, PESI, ALLINEAMENTO, _spazio_utile(foglio))

    assert corpo == foglio.CORPO_CELLA
    assert abbreviata, "la colonna del testo cede, e il taglio si dichiara"


def test_il_corpo_scende_di_un_gradino_se_cosi_la_tabella_entra_intera(foglio):
    """Un numero un po' piu' piccolo si legge, un indirizzo tagliato no."""
    spazio = _spazio_utile(foglio)
    # Righe costruite per sforare di poco: quel poco lo recupera il corpo.
    larghe, corpo_pieno, _ = foglio._misura_colonne(INTESTAZIONI, RIGHE, PESI,
                                                   ALLINEAMENTO, spazio)
    assert corpo_pieno == foglio.CORPO_CELLA
    stretto = sum(larghe) * .97

    _, corpo, abbreviata = foglio._misura_colonne(INTESTAZIONI, RIGHE, PESI,
                                                 ALLINEAMENTO, stretto)

    assert corpo <= foglio.CORPO_CELLA
    assert not abbreviata, "riducendo il corpo la tabella entra: nulla da abbreviare"


def test_il_corpo_non_scende_sotto_il_minimo_dichiarato(foglio):
    righe = [["10.10.140.0/24", "Testo " * 200, "254", "72", "220"]]

    _, corpo, _ = foglio._misura_colonne(INTESTAZIONI, righe, PESI, ALLINEAMENTO, 120)

    assert corpo >= foglio.CORPO_CELLA_MINIMO


# --------------------------------------------------------------------------- #
# Niente tagli a mano nelle celle dei report
# --------------------------------------------------------------------------- #
def test_nessuna_cella_dei_report_viene_tagliata_a_mano():
    """Le celle venivano accorciate nel codice -- `(hostname or "")[:28]` -- e gli
    elenchi limitati a quaranta righe. Sono tagli che il lettore non puo' vedere: ora
    le colonne si misurano sul contenuto e cio' che non entra si dichiara.

    Restano ammessi soltanto: le date ISO ridotte a giorno o minuto (formato, non
    contenuto), gli elenchi riuniti in una cella che dichiarano quanti ne restano
    fuori, e il numero di gruppi descritti per esteso, che il documento dichiara.
    """
    import re

    DATE = ("created_at", "updated_at", "last_seen_at", "first_seen_at", "decided_at",
            "opened_at", "acknowledged_at", "escalated_at", "resolved_at", "sent_at",
            "executed_at", "measured_at", "started_at", "finished_at",
            "ultima_verifica", "ultimo_aggiornamento", "quando", "accensione")

    sorgente = (Path(__file__).resolve().parent.parent
                / "server/snapserver/reports/render_wide.py").read_text(encoding="utf-8")

    colpevoli = []
    for numero, riga in enumerate(sorgente.splitlines(), 1):
        for trovato in re.finditer(r"\[:(\d+)\]", riga):
            quanti = int(trovato.group(1))
            if "join(" in riga or "gruppi[:8]" in riga:
                continue
            if quanti in (10, 16, 19):
                nomi = re.findall(r"[\"'](\w+)[\"']", riga[:trovato.start()])
                if any(nome in DATE for nome in nomi[-3:]):
                    continue
            colpevoli.append("%d: %s" % (numero, riga.strip()))

    assert not colpevoli, "tagli a mano nelle celle:\n" + "\n".join(colpevoli)


def test_i_gruppi_descritti_per_esteso_sono_dichiarati():
    """Un limite che resta deve almeno dirsi: chi legge crede di avere davanti tutto."""
    sorgente = (Path(__file__).resolve().parent.parent
                / "server/snapserver/reports/render_wide.py").read_text(encoding="utf-8")

    assert "gruppi[:8]" in sorgente
    assert "gruppi di esposizione piu' gravi su" in sorgente
