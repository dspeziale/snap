"""
snap - Test del quadro d'insieme: la dashboard e gli indicatori aggregati.

PERCHE' ESISTE
La dashboard riunisce su una pagina numeri che vengono da otto aree diverse. Il
rischio non e' che si rompa -- quello lo si vede -- ma che dica una cosa falsa con
un'aria tranquilla. Questi test fissano le tre bugie che una dashboard puo' dire:

1. **uno zero al posto di "non misurato"**: un conteggio a zero perche' nessuno ha
   guardato si legge come "nessun problema";
2. **una percentuale calcolata su cio' che non si misura**: le fasi che lavorano su
   nodi gia' noti non dichiarano bersagli, e una quota sugli host direbbe zero per
   costruzione -- lo stesso errore del contatore dei record, con un altro campo;
3. **una presenza contata sull'ultimo avvistamento**: una permanenza di sei ore
   finirebbe in un'ora sola, e il grafico disegnerebbe una rete vuota per cinque ore
   su sei.

E fissano l'unica cosa che la pagina deve garantire a chi la usa: quando si e' deciso
di mettere via un indicatore, quella scelta resta.

remarks: Autore: Daniele Speziale - Data: 2026-09-12
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations


def _tenant_id(server_app) -> int:
    with server_app.app_context():
        from snapserver.db import query

        return int(query("SELECT id FROM tenants ORDER BY name", (), one=True)["id"])


def _pannello(server_app) -> dict:
    with server_app.app_context():
        from snapserver.board_queries import pannello

        return pannello(_tenant_id(server_app))


# --------------------------------------------------------------------------- #
# La pagina
# --------------------------------------------------------------------------- #
def test_la_dashboard_si_apre(logged_client):
    risposta = logged_client.get("/")

    assert risposta.status_code == 200
    testo = risposta.get_data(as_text=True)
    assert "Dashboard" in testo


def test_la_dashboard_mostra_il_quadro_d_insieme(logged_client):
    """Le sezioni che la compongono: se una sparisce, la pagina resta in piedi e
    nessuno se ne accorge."""
    testo = logged_client.get("/").get_data(as_text=True)

    for sezione in ("snap-postura", "Vulnerabilita' per gravita'",
                    "Vetusta' delle interfacce", "Certificati TLS",
                    "Esposizione SMB", "Le fasi di scansione",
                    "Composizione del parco", "Dispositivi per zona"):
        assert sezione in testo, "manca la sezione %r" % sezione


def test_ogni_semaforo_porta_la_propria_ragione(server_app):
    """Un semaforo senza il perche' e' un colore: si puo' guardare, non si puo' usare."""
    postura = _pannello(server_app)["postura"]

    assert len(postura) == 4
    for voce in postura:
        assert voce["motivo"].strip(), "il semaforo %r non dice perche'" % voce["chiave"]
        assert voce["stato"] in ("success", "warning", "danger")
        assert voce["icona"].startswith("bi-"), (
            "il colore non basta: serve anche l'icona, per chi i colori non li"
            " distingue")


def test_board2_non_esiste_piu_come_pagina_a_se(logged_client):
    """Due pagine che si chiamano quasi allo stesso modo si guardano a turno senza
    sapere perche': il quadro d'insieme e' LA dashboard."""
    assert logged_client.get("/board2").status_code == 404


# --------------------------------------------------------------------------- #
# Zero e "non misurato"
# --------------------------------------------------------------------------- #
def test_una_fonte_senza_dati_si_dichiara_invece_di_valere_zero(server_app):
    """Su un tenant appena creato nessuna raccolta ha prodotto nulla: gli indicatori
    devono dirlo, non mostrare zero."""
    board = _pannello(server_app)

    for area in ("vulnerabilita", "certificati", "smb", "vetusta", "presenze"):
        assert "misurato" in board[area], (
            "%s non dichiara se la sua fonte ha dati: uno zero senza questa"
            " informazione si legge come \"nessun problema\"" % area)


def test_la_pagina_dice_che_cosa_non_e_stato_misurato(logged_client):
    testo = logged_client.get("/").get_data(as_text=True)

    assert "zero e \"non misurato\" non sono la stessa cosa" in testo.lower()


# --------------------------------------------------------------------------- #
# Le fasi: non si giudicano tutte allo stesso modo
# --------------------------------------------------------------------------- #
def _passata(server_app, tenant_id, stage, hosts_up, hosts_total):
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        execute(
            "INSERT INTO scan_runs (tenant_id, probe_id, stage, target, status,"
            " hosts_up, hosts_total, records, created_at)"
            " VALUES (?, NULL, ?, '10.0.0.0/24', 'completed', ?, ?, 0, ?)",
            (tenant_id, stage, hosts_up, hosts_total, utc_now_str()))


def test_una_fase_che_non_cerca_host_non_si_misura_sugli_host(server_app):
    """`monitor`, `deep` e `os` lavorano su nodi gia' noti e non dichiarano bersagli:
    una quota calcolata sugli host direbbe zero per costruzione, ed e' esattamente
    l'allarme falso che il contatore dei record dava altrove."""
    tenant_id = _tenant_id(server_app)
    _passata(server_app, tenant_id, "monitor", hosts_up=0, hosts_total=0)
    _passata(server_app, tenant_id, "discovery", hosts_up=7, hosts_total=250)

    with server_app.app_context():
        from snapserver.board_queries import fasi_di_scansione

        fasi = {v["fase"]: v for v in fasi_di_scansione(tenant_id)}

    assert fasi["monitor"]["conta_host"] is False
    assert fasi["monitor"]["resa"] is None, (
        "una fase che non cerca host non ha una resa: mostrarne una, per giunta a"
        " zero, direbbe che non funziona")
    assert fasi["discovery"]["conta_host"] is True
    assert fasi["discovery"]["resa"] == 100.0


def test_una_fase_a_vuoto_si_riconosce(server_app):
    """Una passata completata su zero host non e' una passata veloce: e' una passata
    che non ha visto nulla."""
    tenant_id = _tenant_id(server_app)
    _passata(server_app, tenant_id, "ports", hosts_up=0, hosts_total=64)
    _passata(server_app, tenant_id, "ports", hosts_up=3, hosts_total=64)

    with server_app.app_context():
        from snapserver.board_queries import fasi_di_scansione

        fasi = {v["fase"]: v for v in fasi_di_scansione(tenant_id)}

    assert fasi["ports"]["a_vuoto"] == 1
    assert fasi["ports"]["resa"] == 50.0


# --------------------------------------------------------------------------- #
# Le presenze: un fatto continuo, non un istante
# --------------------------------------------------------------------------- #
def test_una_permanenza_lunga_conta_in_tutte_le_ore_che_tocca(server_app):
    """Raggruppare sull'ultimo avvistamento metterebbe sei ore di presenza in un'ora
    sola, e il grafico direbbe che la rete e' stata vuota per cinque ore su sei."""
    from datetime import datetime, timedelta, timezone

    tenant_id = _tenant_id(server_app)
    adesso = datetime.now(timezone.utc)
    with server_app.app_context():
        from snapserver.db import execute

        from snapserver.db import utc_now_str

        execute(
            "INSERT INTO presence_sessions (tenant_id, identity_key, identity_source,"
            " ip, first_seen_at, last_seen_at, sightings, opened_reason, created_at)"
            " VALUES (?, 'mac:aa:bb:cc:dd:ee:01', 'mac', '10.9.9.9', ?, ?, 12,"
            " 'prima', ?)",
            (tenant_id,
             (adesso - timedelta(hours=6)).strftime("%Y-%m-%d %H:%M:%S"),
             (adesso - timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S"),
             utc_now_str()))

    with server_app.app_context():
        from snapserver.board_queries import andamento_presenze

        punti = andamento_presenze(tenant_id)

    con_presenza = [p for p in punti if p[1] > 0]
    assert len(con_presenza) >= 6, (
        "sei ore di permanenza devono comparire in sei ore del grafico, non in una")


# --------------------------------------------------------------------------- #
# Gli indicatori personalizzabili restano
# --------------------------------------------------------------------------- #
def test_gli_indicatori_di_ciascuno_restano_nella_nuova_dashboard(logged_client):
    """La dashboard e' cambiata: la scelta di chi aveva messo via un indicatore no."""
    logged_client.post("/preferences/indicatori", data={"nascondi": "volume"},
                       follow_redirects=True)
    pagina = logged_client.get("/").get_data(as_text=True)

    assert "Nascosti da te" in pagina
    assert "I tuoi indicatori" in pagina


def test_gli_incidenti_aperti_restano_in_cima(server_app, logged_client):
    """E' l'unica cosa della pagina a chiedere un intervento adesso: viene prima di
    qualunque numero."""
    pagina = logged_client.get("/").get_data(as_text=True)

    # Senza incidenti il riquadro non c'e'; la pagina resta valida.
    if "incidenti aperti sui controlli" in pagina:
        assert (pagina.index("incidenti aperti sui controlli")
                < pagina.index("snap-postura"))


# --------------------------------------------------------------------------- #
# Costo
# --------------------------------------------------------------------------- #
def test_il_pannello_non_legge_elenchi_per_contarli(server_app):
    """Le raccolte dei report caricano gli elenchi interi perche' devono stamparli.
    Una dashboard che facesse lo stesso leggerebbe migliaia di righe per contarle."""
    import inspect
    import re

    from snapserver import board_queries

    sorgente = inspect.getsource(board_queries)
    # Si guardano gli IMPORT: il nome compare anche nella spiegazione di perche' quel
    # modulo non si usa, e cercarlo come parola boccerebbe proprio il commento che
    # dichiara la scelta.
    importazioni = [riga for riga in sorgente.splitlines()
                    if re.match(r"\s*(from|import)\s", riga)]
    assert not [riga for riga in importazioni if "dataset_wide" in riga], (
        "il pannello non deve riusare le raccolte dei report: quelle caricano gli"
        " elenchi interi per stamparli, e qui servono i soli conteggi")
