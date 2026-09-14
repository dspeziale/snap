# -----------------------------------------------------------------
# test_occupazione.py — occupazione degli archivi, crescita, scadenze
# Autore: Daniele Speziale
# Data creazione: 2026-09-14
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap - Quanto occupano i due archivi, e quanto durera'.

Il difetto che ha originato questi test era misurabile: la pagina del server leggeva
le righe da `pg_stat_user_tables.n_live_tup`, che e' una statistica dell'autovacuum e
resta a ZERO su una tabella caricata in blocco e mai piu' scritta. Su un archivio
reale mostrava `ti_cve` con 0 righe avendone 6.434 e `ti_cve_cpe` con 0 avendone
117.167: il totale in cima alla pagina era sbagliato di 123.601 righe.

La regola che questi test difendono e' sempre la stessa del progetto: **uno zero deve
essere una misura, non un'assenza di misura**. Vale per le righe di una tabella come
per la crescita di un archivio: con una sola misura la crescita non e' zero, e' ignota,
e dirlo "zero" sarebbe una rassicurazione inventata.

remarks: Autore: Daniele Speziale - Data: 2026-09-14
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest


# --------------------------------------------------------------------------- #
# Il difetto che ha originato tutto: righe contate, non stimate
# --------------------------------------------------------------------------- #
def test_le_righe_sono_contate_non_lette_da_una_statistica(server_app):
    """Una tabella scritta in blocco e mai analizzata ha `n_live_tup` a zero.

    E' il caso reale: su questo archivio `ti_cve` mostrava 0 righe avendone 6.434.
    Il test scrive righe SENZA far passare l'autovacuum e verifica che il conteggio
    le veda: se qualcuno tornasse alla statistica, qui comparirebbe uno zero.
    """
    with server_app.app_context():
        from snapserver.db import execute, query
        from snapserver.maintenance import database_size

        for i in range(37):
            execute("INSERT INTO system_settings (key, value, updated_at)"
                    " VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE"
                    " SET value = excluded.value",
                    ("prova.occupazione.%d" % i, str(i), "2026-09-14 00:00:00"))

        vere = int(query("SELECT COUNT(*) AS n FROM system_settings",
                         (), one=True)["n"])
        misura = database_size()
        righe = {t["tabella"]: t["righe"] for t in misura["tabelle"]}

    assert righe["system_settings"] == vere, (
        "le righe di system_settings non coincidono con un conteggio vero:"
        " %s invece di %s" % (righe.get("system_settings"), vere))
    assert misura["righe_esatte"] is True


def test_il_totale_delle_righe_e_la_somma_delle_tabelle(server_app):
    """Il numero in cima alla pagina non e' calcolato per conto proprio."""
    with server_app.app_context():
        from snapserver.maintenance import database_size

        misura = database_size()

    assert misura["righe_totali"] == sum(t["righe"] for t in misura["tabelle"])
    assert misura["righe_morte"] == sum(t["morte"] for t in misura["tabelle"])


def test_sopra_la_soglia_le_righe_sono_stimate_e_lo_dichiara(server_app, monkeypatch):
    """Un archivio enorme non si conta riga per riga: si stima, e si DICE che e' una
    stima. Contarle tutte renderebbe la pagina inutilizzabile proprio dove serve."""
    with server_app.app_context():
        from snapserver import maintenance

        monkeypatch.setattr(maintenance, "CONTEGGIO_ESATTO_MASSIMO_BYTE", 1)
        misura = maintenance.database_size()

    assert misura["righe_esatte"] is False, (
        "oltre la soglia il conteggio esatto deve cedere il posto alla stima")


def test_l_occupazione_comprende_gli_indici(server_app):
    """`pg_total_relation_size` e non `pg_relation_size`: su questo prodotto gli
    indici pesano quanto i dati, e una misura che li escludesse direbbe che
    l'archivio occupa la meta' di quello che occupa davvero."""
    with server_app.app_context():
        from snapserver.db import scalar
        from snapserver.maintenance import database_size

        misura = database_size()
        solo_dati = int(scalar("SELECT pg_relation_size('system_settings')",
                               (), default=0) or 0)
        totale = int(scalar("SELECT pg_total_relation_size('system_settings')",
                            (), default=0) or 0)

    voce = next(t for t in misura["tabelle"] if t["tabella"] == "system_settings")
    assert voce["byte"] == totale
    assert totale >= solo_dati


# --------------------------------------------------------------------------- #
# La crescita: una differenza, non un numero
# --------------------------------------------------------------------------- #
def test_con_una_sola_misura_la_crescita_non_e_zero_ma_ignota(server_app):
    """La distinzione vale l'intero capitolo: zero significa "non cresce", ed e' una
    rassicurazione. Ignota significa "non lo so ancora", ed e' la verita'."""
    with server_app.app_context():
        from snapserver.db import execute
        from snapserver.maintenance import storage_sample, storage_trend

        execute("DELETE FROM storage_samples")
        assert storage_sample(forza=True) is True
        tendenza = storage_trend()

    assert tendenza["campioni"] == 1
    assert tendenza["crescita_giorno"] is None, (
        "con una misura sola la crescita deve essere ignota, non zero")
    assert tendenza["giorni_al_riempimento"] is None


def test_con_due_misure_la_crescita_e_la_differenza_al_giorno(server_app):
    """Due misure a dieci giorni di distanza, dieci megabyte di differenza: un
    megabyte al giorno. L'aritmetica e' banale, ed e' proprio per questo che va
    verificata: e' il numero su cui si decide se aggiungere un disco."""
    with server_app.app_context():
        from snapserver.db import execute
        from snapserver.maintenance import storage_trend

        execute("DELETE FROM storage_samples")
        execute("INSERT INTO storage_samples (measured_at, db_bytes, rows_total,"
                " dead_rows, disk_free, disk_total) VALUES (?, ?, ?, ?, ?, ?)",
                ("2026-09-01 00:00:00", 100 * 1024 ** 2, 1000, 0,
                 50 * 1024 ** 2, 1024 ** 3))
        execute("INSERT INTO storage_samples (measured_at, db_bytes, rows_total,"
                " dead_rows, disk_free, disk_total) VALUES (?, ?, ?, ?, ?, ?)",
                ("2026-09-11 00:00:00", 110 * 1024 ** 2, 2000, 0,
                 40 * 1024 ** 2, 1024 ** 3))
        tendenza = storage_trend()

    assert tendenza["campioni"] == 2
    assert tendenza["crescita_giorno"] == pytest.approx(1024 ** 2, rel=0.001), (
        "dieci megabyte in dieci giorni sono un megabyte al giorno")
    # 40 MB liberi a 1 MB al giorno: quaranta giorni.
    assert tendenza["giorni_al_riempimento"] == pytest.approx(40, rel=0.001)


def test_un_archivio_che_non_cresce_non_si_riempie_mai(server_app):
    """Non "fra zero giorni": mai. Sono affermazioni opposte e il segno di una
    divisione le separa."""
    with server_app.app_context():
        from snapserver.db import execute
        from snapserver.maintenance import storage_trend

        execute("DELETE FROM storage_samples")
        for giorno, byte in (("2026-09-01 00:00:00", 100 * 1024 ** 2),
                             ("2026-09-11 00:00:00", 90 * 1024 ** 2)):
            execute("INSERT INTO storage_samples (measured_at, db_bytes, rows_total,"
                    " dead_rows, disk_free, disk_total) VALUES (?, ?, ?, ?, ?, ?)",
                    (giorno, byte, 1000, 0, 50 * 1024 ** 2, 1024 ** 3))
        tendenza = storage_trend()

    assert tendenza["crescita_giorno"] < 0
    assert tendenza["giorni_al_riempimento"] is None


def test_la_misura_non_si_ripete_nello_stesso_giorno(server_app):
    """Misurare piu' spesso riempirebbe di righe proprio la tabella che serve a
    misurare le righe."""
    with server_app.app_context():
        from snapserver.db import execute, scalar
        from snapserver.maintenance import storage_sample

        execute("DELETE FROM storage_samples")
        assert storage_sample() is True
        assert storage_sample() is False, "due misure nello stesso giorno"
        assert int(scalar("SELECT COUNT(*) FROM storage_samples", (), default=0)) == 1


# --------------------------------------------------------------------------- #
# L'archivio della sonda
# --------------------------------------------------------------------------- #
def test_la_sonda_misura_il_proprio_archivio(probe_store):
    misura = probe_store.occupazione()

    assert misura["byte"] > 0
    assert misura["tabelle"], "nessuna tabella misurata"
    assert misura["righe"] == sum(t["righe"] for t in misura["tabelle"])
    assert misura["righe_esatte"] is True


def test_la_sonda_dice_ignota_la_crescita_con_una_misura_sola(probe_store):
    probe_store.archivio_campiona(disco_libero=1024 ** 3, forza=True)
    tendenza = probe_store.archivio_tendenza(1024 ** 3)

    assert tendenza["campioni"] >= 1
    if tendenza["campioni"] == 1:
        assert tendenza["crescita_giorno"] is None
        assert tendenza["giorni_al_riempimento"] is None


def test_la_sonda_non_rimisura_nello_stesso_giorno(probe_store):
    probe_store.archivio_campiona(disco_libero=1024 ** 3, forza=True)
    assert probe_store.archivio_campiona(disco_libero=1024 ** 3) is False


def test_la_storia_dell_archivio_se_ne_va_con_l_archivio(probe_store):
    """Conservarla darebbe una crescita calcolata a cavallo di un azzeramento: una
    differenza NEGATIVA fra un archivio pieno e uno vuoto, cioe' un "non si riempie
    mai" che nessuno ha misurato."""
    assert "local_archivio_storia" in probe_store.DATA_TABLES
    assert "local_archivio_storia" not in probe_store.KEPT_TABLES


# --------------------------------------------------------------------------- #
# Le scadenze: il conto alla rovescia che non c'era
# --------------------------------------------------------------------------- #
@pytest.fixture()
def probe_scanner(probe_store):
    """Uno scanner sull'archivio di prova, con un perimetro di tre subnet.

    Tre e non una: la scoperta si conta PER SUBNET, e con una sola il difetto di
    chi la contasse una volta sola resterebbe invisibile.
    """
    from snapprobe.scanner import NetworkScanner

    probe_store.set_json("scan_subnets", [{"cidr": "10.0.1.0/24"},
                                          {"cidr": "10.0.2.0/24"},
                                          {"cidr": "10.0.3.0/24"}])
    return NetworkScanner(probe_store, None, "prova")


def _scadenza(store, target: str, stage: str, quando: str) -> None:
    """Scrive l'istante di un'esecuzione passata.

    `record_scan` usa l'ora corrente e non accetta una data: per provare il ritardo
    serve poter tornare indietro, quindi si scrive la riga direttamente.
    """
    with store._connect() as connessione:
        connessione.execute(
            "INSERT INTO scan_state (target, stage, last_run_at, last_status,"
            " last_detail, runs) VALUES (?, ?, ?, 'completed', 'prova', 1)"
            " ON CONFLICT(target, stage) DO UPDATE"
            " SET last_run_at = excluded.last_run_at",
            (target, stage, quando))


def test_una_fase_mai_eseguita_non_ha_un_conto_alla_rovescia(probe_scanner):
    """`None` e non zero: "appena possibile" e "fra zero secondi" si somigliano
    soltanto. La prima e' una fase che non ha mai girato."""
    voci = {v["fase"]: v for v in probe_scanner.scadenze()}

    assert voci, "nessuna fase a cadenza dichiarata"
    for voce in voci.values():
        if voce["ultima"] is None:
            assert voce["manca_sec"] is None


def test_una_fase_appena_eseguita_scade_fra_una_cadenza(probe_scanner, probe_store):
    """Eseguita adesso, cadenza di sei ore: mancano sei ore, non zero."""
    from datetime import datetime, timezone

    adesso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    _scadenza(probe_store, "*", "ports", adesso)

    voce = next(v for v in probe_scanner.scadenze() if v["fase"] == "ports")
    assert voce["manca_sec"] is not None
    # Sei ore meno il tempo trascorso fra la scrittura e la lettura.
    assert 6 * 3600 - 60 < voce["manca_sec"] <= 6 * 3600


def test_una_fase_scaduta_ha_un_conto_alla_rovescia_negativo(probe_scanner, probe_store):
    """Non si porta a zero: "scaduta da sei ore" e "scade adesso" non sono la stessa
    notizia per chi deve capire se la sonda sta dietro al proprio lavoro."""
    from datetime import datetime, timedelta, timezone

    vecchio = (datetime.now(timezone.utc) - timedelta(hours=12)).strftime(
        "%Y-%m-%d %H:%M:%S")
    _scadenza(probe_store, "*", "ports", vecchio)

    voce = next(v for v in probe_scanner.scadenze() if v["fase"] == "ports")
    assert voce["manca_sec"] < 0, "una fase scaduta deve risultare in ritardo"


def test_la_scoperta_si_conta_per_subnet(probe_scanner, probe_store):
    """Con molte subnet le scadenze sono altrettante e il giro si distende nel tempo:
    un numero solo direbbe una cosa falsa. Da qui due colonne, prima e ultima."""
    voce = next(v for v in probe_scanner.scadenze() if v["fase"] == "discovery")

    assert voce["per_subnet"] is True
    assert voce["bersagli"] == len(probe_scanner.perimeter())


def test_la_raffica_non_compare_fra_le_scadenze(probe_scanner):
    """Si esegue quando manca il profilo, non a tempo: mostrarne la cadenza farebbe
    attendere qualcosa che a quell'ora non arriva."""
    fasi = {v["fase"] for v in probe_scanner.scadenze()}

    assert "raffica" not in fasi

# --------------------------------------------------------------------------- #
# Le pagine: i numeri devono ARRIVARE a schermo
# --------------------------------------------------------------------------- #
@pytest.fixture()
def probe_app(tmp_path, monkeypatch, database_di_prova):
    """Applicativo sonda con archivio proprio e agente di raccolta non avviato."""
    import importlib

    from conftest import prepara_accesso_sonda
    from snapprobe import db as probe_db

    monkeypatch.setenv("SNAP_PROBE_DATABASE_URL", database_di_prova)
    probe_db.azzera_motore()
    monkeypatch.setenv("SNAP_PROBE_SECRET_KEY", "test-secret-key")

    import snapprobe
    import snapprobe.settings as probe_settings

    importlib.reload(probe_settings)
    importlib.reload(snapprobe)

    applicazione = snapprobe.create_app(probe_settings.TestConfig, start_agent=False)
    return prepara_accesso_sonda(applicazione)


def test_la_pagina_della_sonda_mostra_l_occupazione(probe_app):
    testo = probe_app.test_client().get("/salute").get_data(as_text=True)

    assert "Salute della sonda" in testo
    assert "Occupazione per tabella" in testo
    # Le tabelle vere dell'archivio, non un elenco scritto a mano nel modello.
    assert "local_nodes" in testo
    assert "scan_state" in testo


def test_la_pagina_della_sonda_dice_che_la_crescita_non_e_nota(probe_app):
    """Il caso di un'installazione nuova, che e' il piu' frequente: si deve leggere
    che la crescita non e' ancora nota, non uno zero."""
    testo = probe_app.test_client().get("/salute").get_data(as_text=True)

    assert "CRESCITA AL GIORNO" in testo
    assert "non ancora" in testo
    assert "non e' zero" in testo.replace("&#39;", "'")


def test_la_pagina_della_sonda_mostra_il_conto_alla_rovescia(probe_app):
    """La domanda che ha originato la pagina: quanto manca alla prossima scansione."""
    archivio = probe_app.extensions["snap_store"]
    archivio.set_json("scan_subnets", [{"cidr": "10.0.1.0/24"}])
    testo = probe_app.test_client().get("/salute").get_data(as_text=True)

    assert "Quanto manca a ciascuna fase" in testo
    assert "discovery" in testo
    assert "3 g 00 h" in testo, "la cadenza di tre giorni deve essere leggibile"


def test_la_pagina_del_server_non_mostra_piu_i_due_zeri_finti(logged_client):
    """RIUTILIZZABILE e REGISTRO WAL valevano zero per costruzione su PostgreSQL.

    Due riquadri fermi a "0,00 MB" si leggono come una misura, non come un "qui non
    si applica": erano l'unica cosa nella pagina che non fosse misurata.

    SI GUARDANO LE ETICHETTE DEI RIQUADRI, non tutta la pagina. La prima stesura
    cercava le due parole nel testo intero e falliva: il changelog, che sta in ogni
    pagina e che ANNUNCIA la rimozione, le contiene. Cercare una parola in tutto un
    documento per dimostrare che un elemento non c'e' e' una prova sbagliata -- e
    questa ha fallito sul primo caso utile.
    """
    import re

    testo = logged_client.get("/admin/settings").get_data(as_text=True)
    etichette = set(re.findall(r'snap-stat-label mb-0">([^<]+)</p>', testo))

    assert "RIUTILIZZABILE" not in etichette
    assert "REGISTRO WAL" not in etichette
    assert "RIGHE MORTE" in etichette, "al loro posto c'e' una grandezza misurata"
    assert "CRESCITA AL GIORNO" in etichette
    assert "SI RIEMPIE FRA" in etichette


def test_la_pagina_del_server_mostra_l_occupazione_per_tabella(logged_client):
    testo = logged_client.get("/admin/settings").get_data(as_text=True)

    assert "Dimensione per tabella" in testo
    assert "system_settings" in testo
    assert "Come sta crescendo" in testo


# --------------------------------------------------------------------------- #
# Il manuale di installazione: deve bastare da solo, e deve essere navigabile
# --------------------------------------------------------------------------- #
def test_il_manuale_di_installazione_copre_i_tre_componenti():
    """Il documento porta da macchine vuote a un sistema che scansiona: se uno dei
    tre componenti non ha il proprio capitolo, chi installa deve cercare altrove --
    ed e' il momento in cui si inventa una procedura."""
    from pathlib import Path

    radice = Path(__file__).resolve().parent.parent
    testo = (radice / "docs" / "16_INSTALLAZIONE_DA_ZERO.md").read_text(encoding="utf-8")

    for capitolo in ("## 3. La console",
                     "## 4. La sonda in contenitore",
                     "## 5. La sonda fuori dal contenitore",
                     "## 6. Sonda e console sulla stessa macchina",
                     "## 9. L'agente sulle macchine"):
        assert capitolo in testo, "manca il capitolo: %s" % capitolo


def test_i_capitoli_del_manuale_sono_numerati_senza_buchi():
    """Un documento che si cita per capitoli ("vedi capitolo 9") non puo' avere una
    numerazione che salta: il rimando punterebbe altrove."""
    import re
    from pathlib import Path

    radice = Path(__file__).resolve().parent.parent
    testo = (radice / "docs" / "16_INSTALLAZIONE_DA_ZERO.md").read_text(encoding="utf-8")
    numeri = [int(n) for n in re.findall(r"^## (\d+)\.", testo, re.M)]

    assert numeri == list(range(1, len(numeri) + 1)), (
        "numerazione dei capitoli con buchi o fuori ordine: %s" % numeri)


def test_i_rimandi_interni_del_manuale_esistono():
    """Ogni "capitolo N" citato nel testo deve essere un capitolo che esiste."""
    import re
    from pathlib import Path

    radice = Path(__file__).resolve().parent.parent
    testo = (radice / "docs" / "16_INSTALLAZIONE_DA_ZERO.md").read_text(encoding="utf-8")
    esistenti = {int(n) for n in re.findall(r"^## (\d+)\.", testo, re.M)}
    citati = {int(n) for n in re.findall(r"capitolo (\d+)", testo)}

    assert citati <= esistenti, (
        "rimandi a capitoli inesistenti: %s" % sorted(citati - esistenti))


# --------------------------------------------------------------------------- #
# Il sommario del PDF: leggibile, non solo corretto
# --------------------------------------------------------------------------- #
def test_ogni_voce_del_sommario_sta_su_una_riga_propria(tmp_path):
    """Le voci erano tutte alla stessa quota, e il sommario era una macchia nera.

    LA PROVA CHE NON BASTAVA. La prima verifica leggeva il testo estratto dal PDF e i
    numeri di pagina: erano giusti tutti e trentaquattro, e il sommario era comunque
    illeggibile. Un testo estratto non ha geometria -- i caratteri c'erano, solo
    sovrapposti.

    Qui si misura una cosa che non si puo' aggirare: **duecento voci non stanno in una
    pagina**. Se ciascuna consuma una riga ne servono almeno tre; se il cursore non
    avanza ci stanno tutte, ed e' esattamente il difetto. Non serve saper leggere un
    PDF per accorgersene.

    La causa era: `foglio.spazio(n)` RISERVA spazio e cambia pagina se non ce n'e'
    piu', ma non sposta `foglio.y`. Lo sposta chi disegna.
    """
    import sys
    from pathlib import Path

    radice = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(radice / "server"))
    sys.path.insert(0, str(radice / "tools"))

    import genera_guida_pdf
    from snapserver.reports import render_pdf

    foglio = render_pdf.Foglio(
        tmp_path / "prova.pdf", kind="installazione", titolo="Prova",
        tenant="", intervallo="prova", generato="2026-09-14 00:00:00")

    voci = [((i % 3 == 0) + 1, "%d. Una voce di prova" % i, 3) for i in range(200)]
    occupate = genera_guida_pdf._sommario(foglio, voci, 1)
    foglio.salva()

    # Misurato con il codice corretto: cinque pagine. Con il difetto ne bastavano
    # due. La soglia sta a quattro -- lontana da entrambe -- cosi' non fallisce per
    # un ritocco all'interlinea ma coglie subito un cursore che non avanza.
    assert occupate >= 4, (
        "duecento voci di sommario sono entrate in %d pagina/e: vuol dire che il"
        " cursore non avanza e le voci si sovrappongono" % occupate)


def test_il_sommario_non_ruba_un_numero_alle_sezioni(tmp_path):
    """Disegnato come una sezione qualunque, il sommario diventava "1." e spostava di
    uno l'intero documento -- proprio i numeri che stava dichiarando."""
    import sys
    from pathlib import Path

    radice = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(radice / "server"))
    sys.path.insert(0, str(radice / "tools"))

    import genera_guida_pdf
    from snapserver.reports import render_pdf

    foglio = render_pdf.Foglio(
        tmp_path / "prova.pdf", kind="installazione", titolo="Prova",
        tenant="", intervallo="prova", generato="2026-09-14 00:00:00")

    genera_guida_pdf._sommario(foglio, [(1, "1. Qualcosa", 3)], 1)
    assert foglio.numero_sezione == 0, "il sommario ha consumato un numero di sezione"

    foglio.titolo_sezione("Il primo capitolo vero")
    foglio.salva()
    assert foglio.numero_sezione == 1
