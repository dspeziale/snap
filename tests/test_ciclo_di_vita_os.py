# -----------------------------------------------------------------
# test_ciclo_di_vita_os.py — fine supporto dei sistemi operativi
# Autore: Daniele Speziale
# Data creazione: 2026-09-14
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap - Da una stringa di sistema operativo alla sua fine supporto.

Quasi tutte queste prove nascono da stringhe VERE, prese dall'inventario di una rete
in esercizio. Erano gia' servite a trovare due difetti prima che il codice uscisse:

* `Windows 10 1903 - 22H2` (148 nodi) riceveva la fine supporto del PRIMO estremo,
  cioe' l'allarme piu' grave fra quelli possibili, scelto a caso;
* `Windows 11 21H2` (307 nodi) riceveva un verdetto di fuori supporto con la stessa
  autorevolezza di un dato letto dentro la macchina -- mentre nmap nomina la release
  da cui l'impronta fu raccolta, non quella installata.

La regola che questi test difendono: **si risponde solo quando si sa, e si dichiara
sempre da dove viene la risposta.**

remarks: Autore: Daniele Speziale - Data: 2026-09-14
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from datetime import date

import pytest

# Una data fissa: un test che dipende da "oggi" cambia esito da solo, e un giorno
# fallisce senza che nessuno abbia toccato niente.
OGGI = date(2026, 9, 14)


# --------------------------------------------------------------------------- #
# Riconoscimento
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("osservato,prodotto,release,stato", [
    ("Microsoft Windows Server 2019", "Windows Server", "2019", "supportato"),
    ("Microsoft Windows Server 2022", "Windows Server", "2022", "supportato"),
    ("Microsoft Windows Server 2012 R2", "Windows Server", "2012 R2", "fuori_supporto"),
    ("Microsoft Windows 11 21H2", "Windows", "11 21H2", "fuori_supporto"),
    ("Microsoft Windows 11 24H2", "Windows", "11 24H2", "in_scadenza"),
    ("Microsoft Windows 10 1607", "Windows", "10 1607", "fuori_supporto"),
    ("VMware ESXi 7.0.3", "ESXi", "7.0", "fuori_supporto"),
    ("VMware ESXi 4.1.0", "ESXi", "4.1", "fuori_supporto"),
    ("Debian GNU/Linux 12 (bookworm)", "Debian", "12", "fuori_supporto"),
    ("Ubuntu 22.04.5 LTS", "Ubuntu", "22.04", "supportato"),
    ("Red Hat Enterprise Linux 9.4", "RHEL", "9", "supportato"),
    ("CentOS Linux 7 (Core)", "CentOS", "7", "fuori_supporto"),
])
def test_riconosce_i_prodotti_dell_inventario(osservato, prodotto, release, stato):
    """Le stringhe sono quelle che nmap e gli agenti producono davvero."""
    from snapserver.os_lifecycle import riconosci

    esito = riconosci(osservato, "", "agente", oggi=OGGI)

    assert esito["prodotto"] == prodotto, osservato
    assert esito["release"] == release, osservato
    assert esito["stato"] == stato, "%s: atteso %s" % (osservato, stato)
    assert esito["fine_supporto"], "manca la data di fine supporto"


def test_windows_server_non_diventa_un_windows_client():
    """"Windows Server 2019" contiene "Windows": senza una regola piu' specifica
    prima, diventerebbe un client chiamato "Server 2019" -- e prenderebbe la fine
    supporto sbagliata, o nessuna."""
    from snapserver.os_lifecycle import riconosci

    esito = riconosci("Microsoft Windows Server 2019", "Windows", "smb", oggi=OGGI)
    assert esito["prodotto"] == "Windows Server"


# --------------------------------------------------------------------------- #
# Il difetto trovato sui dati veri: un intervallo non e' una release
# --------------------------------------------------------------------------- #
def test_un_intervallo_non_diventa_il_suo_estremo_peggiore():
    """148 nodi reali riportano "Windows 10 1903 - 22H2".

    Le due estremita' hanno fine supporto a cinque anni di distanza (08/12/2020 e
    14/10/2025). La prima stesura restituiva la PRIMA -- cioe' l'allarme piu' grave
    fra quelli possibili, scelto perche' capitava per primo nel catalogo.
    """
    from snapserver.os_lifecycle import riconosci

    esito = riconosci("Microsoft Windows 10 1903 - 22H2", "Windows", "nmap", oggi=OGGI)

    assert esito["fine_supporto"] != "2020-12-08", (
        "il verdetto ha preso l'estremo piu' vecchio dell'intervallo")
    # Al 14/09/2026 ogni release dell'intervallo e' fuori supporto: il verdetto e'
    # legittimo, ma la data mostrata deve essere quella del caso MIGLIORE.
    assert esito["stato"] == "fuori_supporto"
    assert esito["fine_supporto"] == "2025-10-14"
    assert "TUTTE fuori supporto" in esito["perche"]


def test_un_intervallo_a_cavallo_della_soglia_resta_ambiguo():
    """Quando una parte dell'intervallo e' ancora supportata, il verdetto non si
    sbilancia: scegliere sarebbe inventare un allarme o una rassicurazione."""
    from snapserver.os_lifecycle import riconosci

    # Al 01/01/2025 la 22H2 (14/10/2025) era ancora supportata, la 1903 no.
    esito = riconosci("Microsoft Windows 10 1903 - 22H2", "Windows", "nmap",
                      oggi=date(2025, 1, 1))

    assert esito["stato"] == "ambiguo"
    assert "alcune sono fuori supporto e altre no" in esito["perche"]


# --------------------------------------------------------------------------- #
# Quando NON si sa: due assenze diverse, scritte in modo diverso
# --------------------------------------------------------------------------- #
def test_un_kernel_nudo_non_ha_una_fine_supporto():
    """E' meta' dei nodi di una rete reale: 729 con "Linux 4.0 - 4.4".

    Il supporto lo da' la DISTRIBUZIONE, non il kernel: due macchine con lo stesso
    kernel possono stare una dentro e una fuori supporto.
    """
    from snapserver.os_lifecycle import riconosci

    for osservato in ("Linux 4.0 - 4.4", "Linux 2.6.32", "Linux 3.11 - 4.9"):
        esito = riconosci(osservato, "Linux", "nmap", oggi=OGGI)
        assert esito["stato"] == "non_determinabile", osservato
        assert esito["fine_supporto"] is None
        assert "KERNEL" in esito["perche"], (
            "la pagina deve spiegare PERCHE', non lasciare una cella vuota")
        assert "agente" in esito["perche"], "deve dire anche come si risolve"


def test_un_apparato_di_rete_dichiara_perche_non_ha_un_catalogo():
    """Cisco pubblica il ciclo di vita per MODELLO, non per versione di IOS: due
    switch con lo stesso IOS possono avere date diverse. Un catalogo per versione
    darebbe una risposta sbagliata con l'aria di essere giusta."""
    from snapserver.os_lifecycle import riconosci

    esito = riconosci("Cisco 2811 or 3900 router (IOS 12.X or IOS 15.1)", "IOS",
                      "nmap", oggi=OGGI)

    assert esito["stato"] == "non_determinabile"
    assert "MODELLO" in esito["perche"]


def test_senza_sistema_operativo_si_dice_cosi():
    from snapserver.os_lifecycle import riconosci

    esito = riconosci("", "", "nmap", oggi=OGGI)
    assert esito["stato"] == "non_determinabile"
    assert "nessun sistema operativo" in esito["perche"]


def test_una_release_fuori_catalogo_non_viene_inventata():
    """Una release nuova non deve ricevere la data di un'altra: si dichiara che il
    catalogo va aggiornato."""
    from snapserver.os_lifecycle import riconosci

    esito = riconosci("Ubuntu 30.04 LTS", "Linux", "agente", oggi=OGGI)

    assert esito["prodotto"] == "Ubuntu"
    assert esito["fine_supporto"] is None
    assert "non e' nel catalogo" in esito["perche"]


# --------------------------------------------------------------------------- #
# La fiducia: un'impronta non vale una dichiarazione
# --------------------------------------------------------------------------- #
def test_il_verdetto_dichiara_se_e_stimato_o_dichiarato():
    """307 nodi reali risultano a nmap "Windows 11 21H2", che e' fuori supporto --
    ma nmap nomina la release da cui l'impronta fu raccolta, non quella installata:
    possono essere 24H2 aggiornate ieri. Aprire trecento migrazioni su quella base
    brucia la credibilita' dello strumento al primo controllo."""
    from snapserver.os_lifecycle import riconosci

    stimato = riconosci("Microsoft Windows 11 21H2", "Windows", "nmap", oggi=OGGI)
    dichiarato = riconosci("Microsoft Windows 11 21H2", "Windows", "agente", oggi=OGGI)

    assert stimato["fiducia"] == "stimato"
    assert dichiarato["fiducia"] == "dichiarato"
    # Il verdetto e' lo stesso: cambia quanto ci si puo' contare, non il calcolo.
    assert stimato["stato"] == dichiarato["stato"]
    assert "confermare" in stimato["fiducia_perche"].lower()


def test_una_sorgente_non_dichiarata_vale_come_stima():
    """Nel dubbio si sceglie la lettura prudente: il contrario farebbe passare per
    certo un dato di cui non si sa la provenienza."""
    from snapserver.os_lifecycle import riconosci

    esito = riconosci("Microsoft Windows Server 2019", "", "chissa", oggi=OGGI)
    assert esito["fiducia"] == "stimato"


# --------------------------------------------------------------------------- #
# La build di Windows: l'unico modo di saperlo con certezza
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("build,server,release", [
    ("26200", False, "11 25H2"),
    ("26100", False, "11 24H2"),
    ("22000", False, "11 21H2"),
    ("19045", False, "10 22H2"),
    ("26100", True, "2025"),
    ("17763", True, "2019"),
])
def test_la_build_di_windows_identifica_la_versione(build, server, release):
    """Il nome "Windows 11" non ha una fine supporto: ce l'ha la versione. La build
    e' l'unico dato che la identifica senza ambiguita'."""
    from snapserver.os_lifecycle import da_build_windows

    voce = da_build_windows(build, server)
    assert voce is not None, "build %s non riconosciuta" % build
    assert voce["release"] == release


def test_la_stessa_build_distingue_client_e_server():
    """26100 e' insieme Windows 11 24H2 e Windows Server 2025: senza la distinzione
    per prodotto, un server verrebbe letto come una postazione."""
    from snapserver.os_lifecycle import da_build_windows

    assert da_build_windows("26100", server=False)["prodotto"] == "Windows"
    assert da_build_windows("26100", server=True)["prodotto"] == "Windows Server"


def test_una_build_sconosciuta_non_riceve_una_data_inventata():
    from snapserver.os_lifecycle import da_build_windows

    assert da_build_windows("99999") is None


# --------------------------------------------------------------------------- #
# Il catalogo
# --------------------------------------------------------------------------- #
def test_il_catalogo_non_ha_date_incoerenti():
    """Una fine supporto prima del rilascio, o un supporto esteso che finisce prima
    di quello ordinario, sono errori di trascrizione: qui si trovano subito."""
    from snapserver.os_lifecycle import CATALOGO

    for prodotto, release, _nome, rilascio, fine, esteso, _nota in CATALOGO:
        assert rilascio < fine, "%s %s: fine supporto prima del rilascio" % (
            prodotto, release)
        if esteso:
            assert esteso >= fine, (
                "%s %s: il supporto esteso finisce prima di quello ordinario"
                % (prodotto, release))


def test_il_catalogo_non_ha_doppioni():
    from snapserver.os_lifecycle import CATALOGO

    chiavi = [(v[0], v[1]) for v in CATALOGO]
    doppi = {c for c in chiavi if chiavi.count(c) > 1}
    assert not doppi, "voci duplicate nel catalogo: %s" % sorted(doppi)


def test_il_catalogo_dichiara_a_quando_risale():
    """Un dato di ciclo di vita senza la propria data di verifica invecchia in
    silenzio: fra due anni queste date saranno in parte sbagliate, e chi guarda deve
    poterlo sapere dalla pagina."""
    import re

    from snapserver.os_lifecycle import VERIFICATO_AL

    assert re.fullmatch(r"\d{4}-\d{2}", VERIFICATO_AL)


def test_le_soglie_sono_quelle_dichiarate():
    """Sei mesi di preavviso: e' il tempo minimo per pianificare, approvare e
    svolgere una migrazione in una PA."""
    from snapserver.os_lifecycle import GIORNI_DI_PREAVVISO, stato_di

    assert GIORNI_DI_PREAVVISO == 180
    assert stato_di("2026-09-13", OGGI)[0] == "fuori_supporto"
    assert stato_di("2026-09-15", OGGI)[0] == "in_scadenza"
    assert stato_di("2027-09-15", OGGI)[0] == "supportato"
    # Il giorno stesso della scadenza non e' ancora "fuori": lo e' il giorno dopo.
    assert stato_di("2026-09-14", OGGI)[0] == "in_scadenza"


# --------------------------------------------------------------------------- #
# La pagina
# --------------------------------------------------------------------------- #
def test_la_pagina_dei_sistemi_si_apre(logged_client):
    testo = logged_client.get("/inventory/sistemi").get_data(as_text=True)

    assert "FUORI SUPPORTO" in testo
    assert "NON DETERMINABILE" in testo
    assert "catalogo verificato al" in testo


def test_la_pagina_distingue_stimato_da_dichiarato(logged_client, server_app):
    """E' la distinzione su cui si decide se aprire una migrazione."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        tenant = query("SELECT id FROM tenants ORDER BY id LIMIT 1", (), one=True)
        execute("INSERT INTO nodes (tenant_id, ip, status, os_name, os_family,"
                " first_seen_at, last_seen_at, created_at, updated_at)"
                " VALUES (?, '10.9.9.9', 'up', 'Microsoft Windows 11 21H2',"
                " 'Windows', ?, ?, ?, ?)",
                (int(tenant["id"]), utc_now_str(), utc_now_str(), utc_now_str(),
                 utc_now_str()))

    testo = logged_client.get("/inventory/sistemi").get_data(as_text=True)

    assert "Microsoft Windows 11 21H2" in testo
    assert "stimato" in testo, "l'origine del dato deve comparire nella tabella"
    # Frase CORTA: quelle lunghe nei modelli vanno a capo, e il confronto
    # fallirebbe per l'impaginazione invece che per il contenuto.
    assert "24H2 aggiornata ieri" in testo, (
        "la pagina deve spiegare perche' una stima non basta per una migrazione")


def test_la_pagina_si_filtra_per_stato(logged_client):
    testo = logged_client.get(
        "/inventory/sistemi?stato=fuori_supporto").get_data(as_text=True)

    assert "togli il filtro" in testo


# --------------------------------------------------------------------------- #
# L'agente: la distribuzione, non il kernel
# --------------------------------------------------------------------------- #
def test_l_agente_legge_la_distribuzione_da_os_release(tmp_path, monkeypatch):
    """Senza, l'agente riporta "6.1.0-18-amd64": un kernel, da cui nessuna fine
    supporto si ricava. E' proprio il dato per cui si installa l'agente."""
    import sys

    from pathlib import Path

    radice = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(radice / "agent"))
    import snap_agent

    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "os-release").write_text(
        'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n'
        'NAME="Debian GNU/Linux"\nVERSION_ID="12"\nID=debian\n',
        encoding="utf-8")

    monkeypatch.setattr(snap_agent.platform, "system", lambda: "Linux")
    monkeypatch.setattr(snap_agent, "HOSTFS", str(tmp_path))

    distribuzione = snap_agent.Raccolta()._distribuzione()

    assert distribuzione["tipo"] == "debian"
    assert distribuzione["versione"] == "12"
    assert distribuzione["completo"] == "Debian GNU/Linux 12 (bookworm)"


def test_quello_che_l_agente_legge_arriva_a_una_fine_supporto():
    """La prova che chiude il giro: cio' che l'agente riporta dev'essere cio' che il
    riconoscimento sa leggere. Due meta' giuste che non si parlano sono un difetto
    che nessuna delle due prove separate vedrebbe."""
    from snapserver.os_lifecycle import riconosci

    for dichiarato, prodotto in (("Debian GNU/Linux 12 (bookworm)", "Debian"),
                                 ("Ubuntu 22.04.5 LTS", "Ubuntu"),
                                 ("Red Hat Enterprise Linux 9.4 (Plow)", "RHEL")):
        esito = riconosci(dichiarato, "Linux", "agente", oggi=OGGI)
        assert esito["prodotto"] == prodotto, dichiarato
        assert esito["fine_supporto"], dichiarato
        assert esito["fiducia"] == "dichiarato"


def test_l_agente_dichiara_quando_non_puo_leggere_la_distribuzione(tmp_path, monkeypatch):
    """Un vuoto senza motivo e' indistinguibile da un vuoto perche' non c'e' niente."""
    import sys

    from pathlib import Path

    radice = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(radice / "agent"))
    import snap_agent

    monkeypatch.setattr(snap_agent.platform, "system", lambda: "Linux")
    monkeypatch.setattr(snap_agent, "HOSTFS", str(tmp_path))

    distribuzione = snap_agent.Raccolta()._distribuzione()

    assert distribuzione["tipo"] is None
    assert "non e' dichiarata" in distribuzione["motivo"]


def test_ogni_riga_della_tabella_ha_lo_stesso_numero_di_celle(logged_client, server_app):
    """«DataTables warning: Requested unknown parameter» — il difetto riferito da chi
    usava la pagina.

    La tabella metteva la spiegazione del verdetto in una RIGA PROPRIA con
    `colspan="9"`, in mezzo a righe da nove celle. DataTables costruisce la propria
    idea delle colonne dalla prima riga e pretende che tutte le altre la rispettino:
    con una riga irregolare smette di funzionare del tutto — niente ordinamento,
    niente ricerca, un avviso al posto dei dati.

    SI GUARDA L'HTML RESO, non il modello. Una prima stesura analizzava il sorgente
    Jinja contando i `<tr>` dentro il ciclo: sbagliava i confini dei blocchi e dava
    novantacinque falsi positivi, cioe' era inservibile. Sul reso il numero di celle
    di ogni riga e' un fatto, non una deduzione.

    La riga dell'elenco vuoto resta lecita e non falsa la prova: compare solo quando
    non c'e' nessuna riga di dati.
    """
    import re

    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        tenant = query("SELECT id FROM tenants ORDER BY id LIMIT 1", (), one=True)
        # Due sistemi che producono verdetti DIVERSI: uno riconosciuto e uno no. Il
        # secondo e' quello che portava la spiegazione, cioe' la riga irregolare.
        for indirizzo, sistema, famiglia in (
                ("10.9.9.11", "Microsoft Windows Server 2019", "Windows"),
                ("10.9.9.12", "Linux 4.0 - 4.4", "Linux")):
            execute("INSERT INTO nodes (tenant_id, ip, status, os_name, os_family,"
                    " first_seen_at, last_seen_at, created_at, updated_at)"
                    " VALUES (?, ?, 'up', ?, ?, ?, ?, ?, ?)",
                    (int(tenant["id"]), indirizzo, sistema, famiglia,
                     utc_now_str(), utc_now_str(), utc_now_str(), utc_now_str()))

    testo = logged_client.get("/inventory/sistemi").get_data(as_text=True)

    corpo = testo[testo.index("<tbody>"):testo.index("</tbody>")]
    righe = re.findall(r"<tr\b.*?</tr>", corpo, re.S)
    celle = [len(re.findall(r"<td\b", riga)) for riga in righe]

    assert len(righe) >= 2, "servono almeno due righe perche' la prova provi qualcosa"
    assert len(set(celle)) == 1, (
        "righe con un numero diverso di celle (%s): DataTables si rifiuta di"
        " costruire la tabella" % celle)
    # E il numero deve coincidere con le intestazioni.
    testata = testo[testo.index("<thead>"):testo.index("</thead>")]
    assert celle[0] == len(re.findall(r"<th\b", testata))


def test_la_spiegazione_del_verdetto_resta_visibile(logged_client, server_app):
    """Tolta la riga propria, la spiegazione non deve sparire: era il motivo per cui
    era stata scritta — «Linux 4.0 - 4.4» senza spiegazione e' una cella vuota."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        tenant = query("SELECT id FROM tenants ORDER BY id LIMIT 1", (), one=True)
        execute("INSERT INTO nodes (tenant_id, ip, status, os_name, os_family,"
                " first_seen_at, last_seen_at, created_at, updated_at)"
                " VALUES (?, '10.9.9.13', 'up', 'Linux 4.0 - 4.4', 'Linux', ?, ?, ?, ?)",
                (int(tenant["id"]), utc_now_str(), utc_now_str(), utc_now_str(),
                 utc_now_str()))

    testo = logged_client.get("/inventory/sistemi").get_data(as_text=True)

    assert "Linux 4.0 - 4.4" in testo
    assert "KERNEL" in testo, "la spiegazione del perche' non e' piu' visibile"


# --------------------------------------------------------------------------- #
# Il report
# --------------------------------------------------------------------------- #
@pytest.fixture()
def parco(server_app):
    """Un parco con un sistema fuori supporto, uno in scadenza e un kernel nudo."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        tenant = dict(query("SELECT * FROM tenants ORDER BY id LIMIT 1", (), one=True))
        for indirizzo, sistema, famiglia in (
                ("10.7.0.1", "Microsoft Windows Server 2012 R2", "Windows"),
                ("10.7.0.2", "Microsoft Windows Server 2012 R2", "Windows"),
                ("10.7.0.3", "Microsoft Windows Server 2016", "Windows"),
                ("10.7.0.4", "Linux 4.0 - 4.4", "Linux"),
                ("10.7.0.5", "Microsoft Windows Server 2022", "Windows")):
            execute("INSERT INTO nodes (tenant_id, ip, status, os_name, os_family,"
                    " first_seen_at, last_seen_at, created_at, updated_at)"
                    " VALUES (?, ?, 'up', ?, ?, ?, ?, ?, ?)",
                    (int(tenant["id"]), indirizzo, sistema, famiglia,
                     utc_now_str(), utc_now_str(), utc_now_str(), utc_now_str()))
        return tenant


def test_il_report_conta_fuori_supporto_e_in_scadenza(server_app, parco):
    from datetime import date

    with server_app.app_context():
        from snapserver.reports import dataset_wide
        from snapserver.reports.windows import zone_of

        dati = dataset_wide.fine_supporto(parco, zone_of(parco), date.today(), 30)

    conti = dati["conteggi"]
    assert conti["esaminati"] >= 5
    # I due Server 2012 R2 (fine supporto 2023) sono fuori; il 2022 e' supportato.
    assert conti["fuori"] >= 2
    assert conti["supportati"] >= 1
    assert conti["non_determinabili"] >= 1, "il kernel nudo non e' determinabile"


def test_il_report_raggruppa_per_release_e_non_per_macchina(server_app, parco):
    """Una migrazione si pianifica per release: trenta righe con lo stesso contenuto
    sono un elenco da ricomporre a mano."""
    from datetime import date

    with server_app.app_context():
        from snapserver.reports import dataset_wide
        from snapserver.reports.windows import zone_of

        dati = dataset_wide.fine_supporto(parco, zone_of(parco), date.today(), 30)

    gruppi = {(g["prodotto"], g["release"]): g for g in dati["gruppi"]}
    assert ("Windows Server", "2012 R2") in gruppi
    assert gruppi[("Windows Server", "2012 R2")]["nodi"] == 2, (
        "le due macchine con la stessa release devono formare un gruppo solo")


def test_il_report_mette_i_piu_vecchi_per_primi(server_app, parco):
    """E' l'ordine in cui si interviene."""
    from datetime import date

    with server_app.app_context():
        from snapserver.reports import dataset_wide
        from snapserver.reports.windows import zone_of

        dati = dataset_wide.fine_supporto(parco, zone_of(parco), date.today(), 30)

    date_fuori = [v["fine_supporto"] for v in dati["fuori"]]
    assert date_fuori == sorted(date_fuori)


def test_il_report_raggruppa_i_motivi_invece_di_ripeterli(server_app, parco):
    """Le ragioni sono poche e si ripetevano identiche su decine di righe, ciascuna
    troncata a meta' frase. Raggruppate si leggono per esteso."""
    from datetime import date

    with server_app.app_context():
        from snapserver.reports import dataset_wide
        from snapserver.reports.windows import zone_of

        dati = dataset_wide.fine_supporto(parco, zone_of(parco), date.today(), 30)

    assert dati["motivi"], "nessun motivo raggruppato"
    assert len(dati["motivi"]) <= len(dati["non_determinabili"])
    assert all(g["nodi"] >= 1 for g in dati["motivi"])


def test_senza_agenti_il_report_dichiara_che_sono_tutte_stime(server_app, parco):
    """La misura che dice quanto ci si puo' fidare del documento. Vale zero quando
    nessuna macchina dichiara, ed e' la verita': prima veniva calcolata confrontando
    l'impronta di nmap con cio' che la macchina dice di se', due stringhe che non
    combaciano mai -- uno zero che sembrava una misura ma non era un abbinamento."""
    from datetime import date

    with server_app.app_context():
        from snapserver.reports import dataset_wide
        from snapserver.reports.windows import zone_of

        dati = dataset_wide.fine_supporto(parco, zone_of(parco), date.today(), 30)

    assert dati["conteggi"]["dichiarati"] == 0
    assert all(v["fiducia"] == "stimato" for v in dati["nodi"])


def test_un_agente_collegato_al_nodo_rende_dichiarato_il_verdetto(server_app, parco):
    """L'abbinamento e' per NODO, e la stringa giudicata e' quella DICHIARATA: e' cio'
    che rende utile installare l'agente."""
    from datetime import date

    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str
        from snapserver.os_lifecycle import sistemi_dichiarati
        from snapserver.reports import dataset_wide
        from snapserver.reports.windows import zone_of

        nodo = query("SELECT id FROM nodes WHERE ip = '10.7.0.4'", (), one=True)
        execute("INSERT INTO agent_hosts (tenant_id, agent_uid, hostname, ip,"
                " node_id, sistema, aggiornato_at, inventario_json)"
                " VALUES (?, 'prova-eol', 'macchina', '10.7.0.4', ?, 'Linux 4.4',"
                " ?, ?)",
                (int(parco["id"]), int(nodo["id"]), utc_now_str(),
                 '{"identita": {"distribuzione": {"completo":'
                 ' "Debian GNU/Linux 11 (bullseye)"}}}'))

        dichiarati = sistemi_dichiarati(int(parco["id"]))
        dati = dataset_wide.fine_supporto(parco, zone_of(parco), date.today(), 30)

    assert dichiarati.get(int(nodo["id"])) == "Debian GNU/Linux 11 (bullseye)"
    voce = next(v for v in dati["nodi"] if v["ip"] == "10.7.0.4")
    assert voce["fiducia"] == "dichiarato"
    # E il verdetto si basa sulla stringa DICHIARATA, non sul kernel nudo di nmap.
    assert voce["prodotto"] == "Debian"
    assert voce["stato"] != "non_determinabile"


def test_il_report_si_genera_davvero(server_app, parco, tmp_path):
    """Un dataset che non si impagina non e' un report."""
    from datetime import date

    with server_app.app_context():
        from snapserver.reports import KIND_FINE_SUPPORTO, dataset_wide, render_wide
        from snapserver.reports.windows import zone_of

        dati = dataset_wide.fine_supporto(parco, zone_of(parco), date.today(), 30)
        percorso = tmp_path / "fine_supporto.pdf"
        render_wide.fine_supporto_report(percorso, dati)

        from snapserver.reports.generate import GENERATORI

        assert KIND_FINE_SUPPORTO in GENERATORI

    assert percorso.exists() and percorso.stat().st_size > 5000


def test_il_report_e_nel_catalogo_con_destinatario_e_domanda():
    """RP-01: ogni report dichiara a chi si consegna e a che domanda risponde."""
    from snapserver.reports import KIND_FINE_SUPPORTO, REPORT_CATALOG, REPORT_KINDS

    voce = REPORT_CATALOG[KIND_FINE_SUPPORTO]
    assert voce["destinatario"] and voce["domanda"]
    assert REPORT_KINDS[KIND_FINE_SUPPORTO] == "Fine supporto dei sistemi operativi"
