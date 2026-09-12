"""
snap - Test del sottosistema PSN (piano di indirizzamento).

DUE COSE SI DIFENDONO QUI, e la seconda vale quanto la prima.

1. CHE IL PIANO SIA LETTO BENE. Un importatore che perde righe in silenzio e' peggio
   del foglio da cui legge: il foglio almeno non pretende di essere completo. Le
   prove coprono le cinque forme di intestazione, gli indirizzi che Excel ha salvato
   come numeri, le celle con errori di formula e i codici di subnet discordanti --
   tutte cose che stanno nel piano reale.

2. CHE IL SOTTOSISTEMA SIA SEPARABILE. E' la condizione con cui e' stato chiesto: si
   deve poter eliminare se non convince. Un test verifica che l'archivio del prodotto
   NON contenga tabelle del PSN e che il modulo non referenzi tabelle del prodotto:
   se qualcuno domani le mescolasse, la promessa "si butta con un DROP DATABASE"
   diventerebbe falsa senza che nulla lo dica.

remarks: Autore: Daniele Speziale - Data: 2026-09-11
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import io
import uuid
import zipfile
from pathlib import Path

import pytest

RADICE = Path(__file__).resolve().parents[1]
PIANO_REALE = RADICE / "docs" / "raw" / "PSN-PianoDiIndirizzamento-V.1.8.xlsx"


# --------------------------------------------------------------------------- #
# Un foglio .xlsx costruito dal test
# --------------------------------------------------------------------------- #
# SI COSTRUISCE, NON SI ALLEGA. Un file binario nel repository non dice che cosa
# prova: si aprirebbe con Excel per capirlo. Qui la forma del foglio e' scritta in
# chiaro nel test, quindi la prova e' leggibile -- e si puo' modificare per provare
# un caso nuovo senza aprire un programma di calcolo.
def _xlsx(fogli: dict) -> bytes:
    """Un .xlsx minimo ma valido: `{nome_foglio: [[cella, ...], ...]}`."""
    def esc(valore: str) -> str:
        return (str(valore).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))

    dati = io.BytesIO()
    with zipfile.ZipFile(dati, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats'
                   '.org/package/2006/content-types">'
                   '<Default Extension="xml" ContentType="application/xml"/>'
                   '<Default Extension="rels" ContentType="application/vnd.openxml'
                   'formats-package.relationships+xml"/></Types>')
        voci = []
        relazioni = []
        for indice, (nome, righe) in enumerate(fogli.items(), start=1):
            voci.append('<sheet name="%s" sheetId="%d" r:id="rId%d"/>'
                        % (esc(nome), indice, indice))
            relazioni.append(
                '<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/'
                'officeDocument/2006/relationships/worksheet" Target="worksheets/'
                'sheet%d.xml"/>' % (indice, indice))
            corpo = []
            for numero, riga in enumerate(righe, start=1):
                celle = []
                for colonna, valore in enumerate(riga):
                    if valore is None or valore == "":
                        continue
                    riferimento = "%s%d" % (_lettera(colonna), numero)
                    if isinstance(valore, (int, float)):
                        celle.append('<c r="%s"><v>%s</v></c>' % (riferimento, valore))
                    else:
                        celle.append('<c r="%s" t="inlineStr"><is><t>%s</t></is></c>'
                                     % (riferimento, esc(valore)))
                corpo.append('<row r="%d">%s</row>' % (numero, "".join(celle)))
            z.writestr("xl/worksheets/sheet%d.xml" % indice,
                       '<?xml version="1.0"?><worksheet xmlns="http://schemas.'
                       'openxmlformats.org/spreadsheetml/2006/main"><sheetData>%s'
                       '</sheetData></worksheet>' % "".join(corpo))
        z.writestr("xl/workbook.xml",
                   '<?xml version="1.0"?><workbook xmlns="http://schemas.'
                   'openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://'
                   'schemas.openxmlformats.org/officeDocument/2006/relationships">'
                   '<sheets>%s</sheets></workbook>' % "".join(voci))
        z.writestr("xl/_rels/workbook.xml.rels",
                   '<?xml version="1.0"?><Relationships xmlns="http://schemas.'
                   'openxmlformats.org/package/2006/relationships">%s</Relationships>'
                   % "".join(relazioni))
        z.writestr("_rels/.rels",
                   '<?xml version="1.0"?><Relationships xmlns="http://schemas.'
                   'openxmlformats.org/package/2006/relationships"><Relationship '
                   'Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument'
                   '/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
                   '</Relationships>')
    return dati.getvalue()


def _lettera(indice: int) -> str:
    nome = ""
    indice += 1
    while indice:
        indice, resto = divmod(indice - 1, 26)
        nome = chr(65 + resto) + nome
    return nome


def _piano_minimo(**varianti) -> bytes:
    """Un piano con due subnet: una normale e una da provare nei casi difficili."""
    indirizzi_020 = [
        ["", "Label", "ID", "IP", "hostname", "Descrizione", "NOTE", "OLD Hostname"],
        ["", "Ipa", "020", "10.58.3.0", "", "10.58.3.0/24", "", ""],
        ["", "Ipa", "020", "10.58.3.1", "", "gateway", "", ""],
        ["", "Ipa", "020", "10.58.3.4", "bc-prod-ipa01", "SSO", "", "urg-dc1"],
        ["", "Ipa", "020", "10.58.3.5", "bc-prod-ipa02", "SSO, vedi 10.58.4.9", "", ""],
        ["", "Ipa", "020", "10.58.3.6", "-", "segnaposto", "", ""],
        ["", "Ipa", "020", "10.58.3.7", "xx-prod-dns1", "DNS DA RINOMINARE IN - bc-prod-dns01", "", ""],
        ["", "Ipa", "020", "10.58.3.8", "", "", "", ""],
    ]
    indirizzi_021 = [
        ["", "IP", "hostname", "Descrizione"],
        ["", "10.58.4.9", "bc-prod-ipa01", "duplicato voluto dalla prova"],
        ["", "10.58.4.10", "", ""],
    ]
    fogli = {
        "Summary": [
            ["", "Anagrafica delle subnet"],
            ["SEZIONE DI PROVA - 10.58.0.0/18"],
            ["", "Nome", "Subnet", "ID", "Descrizione"],
            ["", "Ipa", "10.58.3.0/24 - 255.255.255.0", "020", "Dati"],
            ["", "Altra", "10.58.4.0/24 - 255.255.255.0", "021", "Dati"],
        ],
        "Tenant": [
            ["", "TGU/ID", "Tenant/Ambienti", "Stato", "IP", "Zona", "Commento",
             "Fonte", "Note"],
            ["", "PSN 02 84 27 23", "Produzione", "Attivo", "198.18.226.3", "Iaas",
             "", "", ""],
        ],
        "DB": [
            ["Database"],
            ["IP da Tenant Ised", "IP da SED", "Porta", "ServiceName", "SID", "User",
             "DB Unique Name", "PDB", "Tenant"],
            ["100.67.102.9", "10.58.3.252", "1521", "s_prod.psn", "-", "pa_admin",
             "PROD", "PDB1", "PSN02842723"],
            ["100.67.102.9", "10.58.3.252", "1521", "s_orfano.psn", "-", "pa_admin",
             "ORF", "PDB2", "PSN99999999"],
        ],
        "Nomenclatore_1.1": [
            ["", "Sito (*)", "", "", "", "", "", "", "", "Tenant (*)"],
            ["", "bc", "i data center", "", "", "", "", "", "", "prod", "produzione"],
            ["", "ac", "Acilia", "", "", "", "", "", "", "test", "collaudo"],
        ],
        "URL-VIP": [
            ["", "CLUSTER WILDFLY", "VIP", "URL"],
            ["", "EU", "10.58.3.4", "https://eu.example.it"],
        ],
        "10.58.3.0 |24": [["d", "", "", "ID:", "020"],
                          ["", "", "", "Label:", "Ipa"]] + indirizzi_020,
        "10.58.4.0 |24": [["d", "", "", "ID:", "021"],
                          ["", "", "", "Label:", "Altra"]] + indirizzi_021,
    }
    fogli.update(varianti)
    return _xlsx(fogli)


# --------------------------------------------------------------------------- #
# Preparatori
# --------------------------------------------------------------------------- #
@pytest.fixture()
def psn_app(server_app):
    """L'applicazione con un archivio PSN proprio, creato e distrutto dal test.

    L'archivio PSN e' un DATABASE distinto da quello del prodotto: qui se ne crea uno
    per il test, ed e' anche la prova che la separazione funziona davvero -- se il
    sottosistema scrivesse nell'archivio del prodotto, questo preparatore non
    servirebbe a niente e i test passerebbero comunque.
    """
    import sqlalchemy as sa

    from conftest import DSN_AMMINISTRATIVO, _senza_database

    nome = "psn_prova_%s" % uuid.uuid4().hex[:10]
    dsn = DSN_AMMINISTRATIVO.rsplit("/", 1)[0] + "/" + nome
    server_app.config["PSN_DATABASE_URL"] = dsn
    server_app.config["PSN_OWNER_DATABASE_URL"] = dsn
    amministrativo = sa.create_engine(_senza_database(DSN_AMMINISTRATIVO),
                                      isolation_level="AUTOCOMMIT")
    try:
        yield server_app
    finally:
        with server_app.app_context():
            from snapserver.psn import db as psn_db
            psn_db.azzera_motore()
        with amministrativo.connect() as connessione:
            connessione.exec_driver_sql(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity"
                " WHERE datname = '%s' AND pid <> pg_backend_pid()" % nome)
            connessione.exec_driver_sql('DROP DATABASE IF EXISTS "%s"' % nome)
        amministrativo.dispose()


@pytest.fixture()
def psn_client(psn_app):
    cliente = psn_app.test_client()
    risposta = cliente.post("/login", data={
        "email": psn_app.config["BOOTSTRAP_ADMIN_EMAIL"],
        "password": psn_app.config["BOOTSTRAP_ADMIN_PASSWORD"]},
        follow_redirects=True)
    assert risposta.status_code == 200
    return cliente


def _importa(applicazione, dati: bytes, nome: str = "PSN-Piano-V.1.0.xlsx"):
    with applicazione.app_context():
        from snapserver.psn import analysis
        from snapserver.psn.importer import importa

        esito = importa(io.BytesIO(dati), nome, utente="prova@test")
        riscontri = analysis.analizza(esito.import_id) if esito.conteggi else {}
        return esito, riscontri


def _riscontri(applicazione, genere: str) -> list:
    with applicazione.app_context():
        from snapserver.psn import db as psn_db

        return psn_db.query(
            "SELECT * FROM psn_finding WHERE kind = ? ORDER BY id", (genere,))


# --------------------------------------------------------------------------- #
# Il lettore del foglio
# --------------------------------------------------------------------------- #
def test_le_colonne_si_mappano_per_nome_non_per_posizione():
    """Nel piano reale i fogli di indirizzi hanno CINQUE forme di intestazione: uno
    parte da `Label`, un altro da `IP`, uno ha una colonna in piu'. Un lettore
    posizionale prenderebbe l'hostname dalla colonna della descrizione."""
    from snapserver.psn.xlsx import Libro

    dati = _xlsx({
        "largo": [["", "Label", "ID", "IP", "hostname", "Descrizione"],
                  ["", "X", "1", "10.0.0.1", "host-a", "prima"]],
        "stretto": [["", "IP", "hostname", "Descrizione"],
                    ["", "10.0.0.2", "host-b", "seconda"]],
    })
    with Libro(io.BytesIO(dati)) as libro:
        largo = list(libro.foglio("largo").tabella(("ip",)))
        stretto = list(libro.foglio("stretto").tabella(("ip",)))

    assert largo[0]["hostname"] == "host-a"
    assert stretto[0]["hostname"] == "host-b", (
        "con le colonne mappate per posizione qui arriverebbe la descrizione")


def test_un_documento_con_doctype_viene_rifiutato():
    """Il file arriva da fuori: un DOCTYPE puo' dichiarare entita' esterne o
    ricorsive, e un foglio prodotto da un programma di calcolo non ne ha bisogno."""
    from snapserver.psn.xlsx import Libro, XlsxNonValido

    dati = io.BytesIO()
    with zipfile.ZipFile(dati, "w") as z:
        z.writestr("xl/workbook.xml",
                   '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><workbook/>')
    with pytest.raises(XlsxNonValido) as errore:
        Libro(io.BytesIO(dati.getvalue()))
    assert "DOCTYPE" in str(errore.value)


def test_gli_errori_di_formula_valgono_come_vuoto():
    """Nel piano reale ci sono centinaia di `#REF!` e `#VALUE!`: sono formule rotte,
    non dati, e importarli produrrebbe una subnet chiamata '#VALUE!'."""
    from snapserver.psn.xlsx import pulito

    for errore in ("#REF!", "#VALUE!", "#N/A", "#DIV/0!"):
        assert pulito(errore) == ""
    assert pulito("  vero  ") == "vero"


def test_un_archivio_che_non_e_un_foglio_viene_rifiutato():
    from snapserver.psn.xlsx import Libro, XlsxNonValido

    dati = io.BytesIO()
    with zipfile.ZipFile(dati, "w") as z:
        z.writestr("qualunque.txt", "non sono un foglio")
    with pytest.raises(XlsxNonValido):
        Libro(io.BytesIO(dati.getvalue()))


# --------------------------------------------------------------------------- #
# Gli indirizzi che Excel ha rovinato
# --------------------------------------------------------------------------- #
def test_un_indirizzo_salvato_come_numero_si_ricostruisce():
    """IL CASO REALE: nel foglio "DC S.Stefano Housing Voip" gli indirizzi sono
    `192168230128` invece di `192.168.230.128`, perche' le celle sono numeriche.
    Quel foglio risultava vuoto: 128 indirizzi persi in silenzio. In tutto, sul piano
    reale, 441 indirizzi su quattro fogli."""
    import ipaddress

    from snapserver.psn.importer import ricostruisci_ip

    rete = ipaddress.ip_network("192.168.230.128/25")
    assert ricostruisci_ip("192168230128", rete) == "192.168.230.128"
    assert ricostruisci_ip("192168230255", rete) == "192.168.230.255"


def test_una_ricostruzione_ambigua_non_si_indovina():
    """Indovinare un indirizzo in un piano di indirizzamento e' peggio che perderlo:
    un indirizzo inventato sembra un dato."""
    import ipaddress

    from snapserver.psn.importer import ricostruisci_ip

    # In una /8 le suddivisioni possibili sono molte: nessuna e' "la" risposta.
    assert ricostruisci_ip("11111", ipaddress.ip_network("1.0.0.0/8")) is None
    assert ricostruisci_ip("non-cifre", ipaddress.ip_network("10.0.0.0/24")) is None
    assert ricostruisci_ip("10101010", None) is None


@pytest.mark.parametrize("valore,valido", [
    ("bc-prod-ipa01", True), ("host.example.it", True),
    ("-", False), ("--", False), ("n/a", False), ("N.D.", False),
    ("VIP 1", False), ("", False), ("?", False),
])
def test_un_segnaposto_non_e_un_hostname(valore, valido):
    """Nel piano la colonna hostname contiene anche "-" e etichette come "VIP 1".
    Confrontarle fra loro produceva riscontri come "il nome '-' e' su sei
    indirizzi": rumore, e il rumore fa ignorare anche i conflitti veri."""
    from snapserver.psn.importer import hostname_utilizzabile

    assert hostname_utilizzabile(valore) is valido


# --------------------------------------------------------------------------- #
# Importazione
# --------------------------------------------------------------------------- #
def test_il_piano_entra_con_le_sue_relazioni(psn_app):
    esito, _ = _importa(psn_app, _piano_minimo())

    assert esito.conteggi["subnet"] == 2
    assert esito.conteggi["sezioni"] == 1
    assert esito.conteggi["tenant"] == 1
    assert esito.conteggi["database"] == 2
    assert esito.conteggi["indirizzi"] == 9

    with psn_app.app_context():
        from snapserver.psn import db as psn_db

        sezione = psn_db.query("SELECT * FROM psn_section", (), one=True)
        assert sezione["supernet"] == "10.58.0.0/18", (
            "la supernet sta nel TITOLO della sezione, e va estratta")
        subnet = psn_db.query(
            "SELECT * FROM psn_subnet WHERE code = '020'", (), one=True)
        assert subnet["cidr"] == "10.58.3.0/24"
        assert subnet["section_id"] == sezione["id"]
        assert subnet["sheet_name"] == "10.58.3.0 |24"


def test_lo_stato_di_un_indirizzo_distingue_il_libero_dal_non_assegnabile(psn_app):
    """Chi cerca il prossimo indirizzo disponibile non deve trovarsi proposto
    l'indirizzo di rete."""
    _importa(psn_app, _piano_minimo())

    with psn_app.app_context():
        from snapserver.psn import db as psn_db

        stati = {r["ip"]: r["state"] for r in psn_db.query(
            "SELECT ip, state FROM psn_address", ())}

    assert stati["10.58.3.0"] == "rete"
    assert stati["10.58.3.1"] == "gateway"
    assert stati["10.58.3.4"] == "assegnato"
    assert stati["10.58.3.8"] == "libero"


def test_lo_stesso_file_non_si_conferisce_due_volte(psn_app):
    """Due conferimenti con la stessa impronta sono lo stesso documento: lo si dice
    invece di duplicare diciottomila righe in silenzio."""
    dati = _piano_minimo()
    primo, _ = _importa(psn_app, dati)
    secondo, _ = _importa(psn_app, dati)

    assert secondo.import_id == primo.import_id
    assert not secondo.conteggi
    assert any("gia'" in a for a in secondo.avvisi)


def test_un_tenant_si_collega_al_proprio_database(psn_app):
    """Nel foglio lo stesso identificativo e' scritto in piu' modi ("PSN 02 84 27 23"
    con gli spazi, "PSN02842723" senza): senza normalizzazione ogni database
    sembrerebbe orfano."""
    _importa(psn_app, _piano_minimo())

    with psn_app.app_context():
        from snapserver.psn import db as psn_db

        collegati = psn_db.query(
            "SELECT d.service_name, t.name FROM psn_database d"
            " JOIN psn_tenant t ON t.tgu = d.tenant_tgu", ())
    assert [r["service_name"] for r in collegati] == ["s_prod.psn"]


def test_i_riferimenti_scritti_in_prosa_diventano_collegamenti(psn_app):
    """Nel piano le relazioni ci sono ma sono nel testo: "SSO, vedi 10.58.4.9" dentro
    una descrizione lega due subnet, e nessuna formula collega le due celle."""
    _importa(psn_app, _piano_minimo())

    with psn_app.app_context():
        from snapserver.psn import db as psn_db

        riferimenti = psn_db.query(
            "SELECT r.target, r.address_id, a.ip AS sorgente FROM psn_reference r"
            " JOIN psn_address a ON a.id = r.from_id"
            " WHERE r.target_kind = 'ip'", ())

    trovati = {(r["sorgente"], r["target"]) for r in riferimenti}
    assert ("10.58.3.5", "10.58.4.9") in trovati
    assert all(r["address_id"] for r in riferimenti if r["target"] == "10.58.4.9")


# --------------------------------------------------------------------------- #
# L'analisi
# --------------------------------------------------------------------------- #
def test_un_hostname_su_due_indirizzi_e_un_conflitto(psn_app):
    _, riscontri = _importa(psn_app, _piano_minimo())

    assert riscontri.get("duplicate_hostname") == 1
    trovati = _riscontri(psn_app, "duplicate_hostname")
    assert "bc-prod-ipa01" in trovati[0]["title"]
    assert trovati[0]["severity"] == "critical"


def test_un_segnaposto_non_produce_un_falso_conflitto(psn_app):
    """Il piano ha "-" nella colonna hostname su piu' righe: non e' un duplicato."""
    _, riscontri = _importa(psn_app, _piano_minimo())

    titoli = " ".join(r["title"] for r in _riscontri(psn_app, "duplicate_hostname"))
    assert "'-'" not in titoli
    assert riscontri.get("bad_hostname", 0) >= 1


def test_una_rinomina_dichiarata_nel_piano_si_ritrova(psn_app):
    _, riscontri = _importa(psn_app, _piano_minimo())

    assert riscontri.get("rename_pending") == 1
    assert "bc-prod-dns01" in _riscontri(psn_app, "rename_pending")[0]["detail"]


def test_una_sigla_non_dichiarata_si_riporta_una_volta_per_sigla(psn_app):
    """LA DISTINZIONE CHE CONTA. La prima stesura accusava ogni nome che non
    combaciava con la convenzione: 79 riscontri su 257 nomi del piano reale, e i nomi
    erano giusti -- era la convenzione a non elencare i siti delle Centrali
    Operative. Una riga per SIGLA, col numero di nomi che la usano, e' una riga da
    portare a chi mantiene il Nomenclatore; 79 accuse non si leggono."""
    _, riscontri = _importa(psn_app, _piano_minimo())

    vocabolario = _riscontri(psn_app, "naming_vocabulary")
    assert riscontri.get("naming_vocabulary") == 1, (
        "una sola sigla ignota nel piano di prova: 'xx'")
    assert vocabolario[0]["subject"] == "xx"
    assert "Nomenclatore" in vocabolario[0]["detail"]


def test_un_indirizzo_fuori_dalla_propria_subnet_e_critico(psn_app):
    """Un foglio che elenca 10.58.9.1 sotto la subnet 10.58.3.0/24: uno dei due dati
    e' sbagliato, e nel piano reale succede."""
    varianti = {"10.58.3.0 |24": [
        ["d", "", "", "ID:", "020"], ["", "", "", "Label:", "Ipa"],
        ["", "Label", "ID", "IP", "hostname", "Descrizione"],
        ["", "Ipa", "020", "10.58.3.4", "bc-prod-ipa01", "giusto"],
        ["", "Ipa", "020", "10.58.9.1", "bc-prod-altro", "fuori dalla subnet"],
    ]}
    _, riscontri = _importa(psn_app, _piano_minimo(**varianti))

    assert riscontri.get("outside_subnet") == 1
    trovato = _riscontri(psn_app, "outside_subnet")[0]
    assert "10.58.9.1" in trovato["title"] and trovato["severity"] == "critical"


def test_due_subnet_sovrapposte_sono_critiche(psn_app):
    varianti = {"Summary": [
        ["", "Anagrafica delle subnet"],
        ["SEZIONE DI PROVA - 10.58.0.0/18"],
        ["", "Nome", "Subnet", "ID", "Descrizione"],
        ["", "Ipa", "10.58.3.0/24 - 255.255.255.0", "020", "Dati"],
        ["", "Sovrapposta", "10.58.0.0/22 - 255.255.252.0", "022", "Dati"],
    ]}
    _, riscontri = _importa(psn_app, _piano_minimo(**varianti))

    assert riscontri.get("overlap") == 1
    assert _riscontri(psn_app, "overlap")[0]["severity"] == "critical"


def test_un_database_senza_tenant_in_anagrafica_si_dichiara(psn_app):
    _, riscontri = _importa(psn_app, _piano_minimo())

    assert riscontri.get("orphan_tenant") == 1
    assert "PSN99999999" in _riscontri(psn_app, "orphan_tenant")[0]["title"]


def test_una_subnet_fuori_dalla_propria_supernet_si_dichiara(psn_app):
    varianti = {"Summary": [
        ["", "Anagrafica delle subnet"],
        ["SEZIONE DI PROVA - 10.58.0.0/18"],
        ["", "Nome", "Subnet", "ID", "Descrizione"],
        ["", "Fuori", "192.168.1.0/24 - 255.255.255.0", "020", "Dati"],
    ]}
    _, riscontri = _importa(psn_app, _piano_minimo(**varianti))

    assert riscontri.get("outside_supernet") == 1


def test_il_codice_di_un_foglio_discordante_non_sposta_gli_indirizzi(psn_app):
    """IL CASO REALE. Il foglio "10.58.70.0 |24" del piano dichiara `ID: 041`, ma in
    anagrafica 041 e' 10.58.80.0/24 (il .70 e' il 040). Fidandosi del codice, 254
    indirizzi del .70 finirebbero archiviati sotto la subnet del .80: un dato
    sbagliato che sembra giusto. La rete nel nome del foglio e' il dato piu' difficile
    da sbagliare, e vince -- dichiarando la discordanza."""
    varianti = {"10.58.4.0 |24": [
        ["d", "", "", "ID:", "020"],   # codice SBAGLIATO: 020 e' la 10.58.3.0/24
        ["", "", "", "Label:", "Altra"],
        ["", "IP", "hostname", "Descrizione"],
        ["", "10.58.4.9", "bc-prod-altro", "sta nella 10.58.4.0/24"],
    ]}
    esito, _ = _importa(psn_app, _piano_minimo(**varianti))

    assert esito.conteggi.get("codici_foglio_discordanti") == 1
    assert any("dichiara ID 020" in a for a in esito.avvisi)
    with psn_app.app_context():
        from snapserver.psn import db as psn_db

        riga = psn_db.query(
            "SELECT s.code FROM psn_address a JOIN psn_subnet s ON s.id = a.subnet_id"
            " WHERE a.ip = '10.58.4.9'", (), one=True)
    assert riga["code"] == "021", (
        "l'indirizzo deve stare sotto la subnet a cui APPARTIENE, non sotto quella"
        " che il codice sbagliato indicava")


def test_l_occupazione_dice_il_prossimo_indirizzo_libero(psn_app):
    """E' il dato per cui si apre un piano di indirizzamento."""
    _importa(psn_app, _piano_minimo())

    with psn_app.app_context():
        from snapserver.psn import analysis
        from snapserver.psn import db as psn_db

        piano = psn_db.query("SELECT id FROM psn_import", (), one=True)
        per_codice = {v["code"]: v for v in analysis.occupazione(int(piano["id"]))}

    assert per_codice["020"]["primo_libero_ip"] == "10.58.3.8"
    # Tre assegnati (.4, .5, .7) e UNO RISERVATO: la riga .6 ha "-" nella colonna
    # hostname e una descrizione, quindi e' una prenotazione, non un'assegnazione.
    # Contarla fra gli assegnati gonfierebbe l'occupazione.
    assert per_codice["020"]["assegnati"] == 3
    assert per_codice["020"]["riservati"] == 1
    assert per_codice["020"]["totale"] == 7


# --------------------------------------------------------------------------- #
# Le pagine
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("percorso", [
    "/psn/", "/psn/subnet", "/psn/riscontri", "/psn/tenant", "/psn/database",
    "/psn/servizi", "/psn/cerca", "/psn/conferimenti", "/psn/importa",
])
def test_ogni_pagina_risponde_senza_piano(psn_client, percorso):
    """Un sottosistema installato e senza dati non deve dare errore: deve dire che
    attende il documento."""
    risposta = psn_client.get(percorso)
    assert risposta.status_code == 200, percorso


def test_le_pagine_mostrano_il_piano_conferito(psn_app, psn_client):
    _importa(psn_app, _piano_minimo())

    corpo = psn_client.get("/psn/").get_data(as_text=True)
    assert "Ipa" in corpo
    assert "10.58.0.0/18" in corpo, "la supernet della sezione deve comparire"

    corpo = psn_client.get("/psn/subnet").get_data(as_text=True)
    assert "10.58.3.0/24" in corpo and "10.58.3.8" in corpo, (
        "l'elenco deve portare la rete e il prossimo indirizzo libero"
    )

    corpo = psn_client.get("/psn/riscontri").get_data(as_text=True)
    assert "bc-prod-ipa01" in corpo


def test_la_ricerca_trova_la_subnet_che_contiene_un_indirizzo(psn_app, psn_client):
    """E' la domanda vera di chi ha in mano un indirizzo e non sa di chi sia: non
    "quale riga lo nomina" ma "quale subnet lo contiene"."""
    _importa(psn_app, _piano_minimo())

    corpo = psn_client.get("/psn/cerca?q=10.58.3.200").get_data(as_text=True)

    assert "10.58.3.0/24" in corpo, (
        "l'indirizzo non e' elencato in nessuna riga, ma appartiene a questa subnet")


def test_la_ricerca_trova_un_hostname(psn_app, psn_client):
    _importa(psn_app, _piano_minimo())

    corpo = psn_client.get("/psn/cerca?q=ipa01").get_data(as_text=True)

    assert "10.58.3.4" in corpo and "10.58.4.9" in corpo


def test_il_conferimento_e_riservato_all_amministratore_di_sistema(psn_app):
    """Un piano di indirizzamento e' la mappa di come entrare in una rete."""
    with psn_app.app_context():
        from snapserver.db import execute, utc_now_str
        from snapserver.security import ROLE_ANALYST, hash_password

        adesso = utc_now_str()
        execute(
            "INSERT INTO users (tenant_id, email, password_hash, full_name, role,"
            " is_active, created_at, updated_at)"
            " VALUES ((SELECT id FROM tenants ORDER BY id LIMIT 1), ?, ?, ?, ?, 1, ?, ?)",
            ("analista@test.local", hash_password("Snap!Analista2026"),
             "Analista", ROLE_ANALYST, adesso, adesso))

    cliente = psn_app.test_client()
    cliente.post("/login", data={"email": "analista@test.local",
                                 "password": "Snap!Analista2026"},
                 follow_redirects=True)

    assert cliente.get("/psn/").status_code == 200, "l'analista puo' leggere"
    risposta = cliente.get("/psn/importa")
    assert risposta.status_code in (302, 403), (
        "l'analista NON deve poter conferire un piano")


# --------------------------------------------------------------------------- #
# La separabilita': e' la condizione con cui il sottosistema e' stato chiesto
# --------------------------------------------------------------------------- #
def test_l_archivio_del_prodotto_non_contiene_tabelle_del_psn(psn_app):
    """LA PROMESSA E' "si butta con un DROP DATABASE". Se qualcuno domani creasse le
    tabelle PSN dentro l'archivio del prodotto, quella promessa diventerebbe falsa
    senza che nulla lo dica -- e le tabelle finirebbero nelle copie di sicurezza del
    prodotto, nei suoi conteggi e nelle sue migrazioni."""
    _importa(psn_app, _piano_minimo())

    with psn_app.app_context():
        from snapserver.db import query

        intruse = query(
            "SELECT table_name FROM information_schema.tables"
            " WHERE table_schema = 'public' AND table_name LIKE 'psn_%'", ())
    assert not intruse, (
        "tabelle PSN nell'archivio del prodotto: %s"
        % ", ".join(r["table_name"] for r in intruse))


def test_il_modulo_psn_non_legge_le_tabelle_del_prodotto():
    """Nessuna query del sottosistema deve nominare una tabella del prodotto: e'
    l'altra meta' della separazione, e si verifica sul codice perche' e' la' che si
    romperebbe."""
    import re

    TABELLE_DEL_PRODOTTO = ("nodes", "node_ports", "subnets", "probes", "tenants",
                            "users", "check_results", "monitor_samples",
                            "ingest_batches", "siem_events", "presence_sessions")
    cartella = RADICE / "server" / "snapserver" / "psn"
    colpevoli = []
    for file in sorted(cartella.glob("*.py")):
        testo = file.read_text(encoding="utf-8")
        # Si guardano le sole frasi SQL: i commenti nominano le tabelle del prodotto
        # per spiegare la separazione, ed e' giusto che lo facciano.
        for frase in re.findall(r"\"[^\"]*(?:FROM|JOIN|INTO|UPDATE)\s+(\w+)", testo):
            if frase in TABELLE_DEL_PRODOTTO:
                colpevoli.append("%s: %s" % (file.name, frase))
    assert not colpevoli, (
        "il sottosistema PSN interroga tabelle del prodotto: %s" % colpevoli)


def test_l_archivio_psn_si_crea_da_se(psn_app):
    """Un sottosistema che pretende un `createdb` a mano prima di funzionare non e'
    installato, e' da installare."""
    with psn_app.app_context():
        from snapserver.psn import db as psn_db

        tabelle = psn_db.query(
            "SELECT table_name FROM information_schema.tables"
            " WHERE table_schema = 'public' ORDER BY table_name", ())
    nomi = {r["table_name"] for r in tabelle}
    assert {"psn_import", "psn_subnet", "psn_address", "psn_finding"} <= nomi


def test_eliminare_un_conferimento_non_lascia_orfani(psn_app, psn_client):
    """Un conferimento e' l'unita' di tutto il sottosistema: la cascata dello schema
    fa il resto."""
    esito, _ = _importa(psn_app, _piano_minimo())

    risposta = psn_client.post("/psn/conferimenti/%d/elimina" % esito.import_id,
                               data={"conferma": "PSN-Piano-V.1.0.xlsx"},
                               follow_redirects=True)
    assert risposta.status_code == 200

    with psn_app.app_context():
        from snapserver.psn import db as psn_db

        for tabella in ("psn_import", "psn_subnet", "psn_address", "psn_finding",
                        "psn_tenant", "psn_database", "psn_reference"):
            riga = psn_db.query("SELECT count(*) AS n FROM %s" % tabella, (), one=True)
            assert int(riga["n"]) == 0, "%s non e' stata svuotata" % tabella


def test_un_conferimento_si_elimina_solo_digitando_il_nome(psn_app, psn_client):
    esito, _ = _importa(psn_app, _piano_minimo())

    psn_client.post("/psn/conferimenti/%d/elimina" % esito.import_id,
                    data={"conferma": "sbagliato"}, follow_redirects=True)

    with psn_app.app_context():
        from snapserver.psn import db as psn_db

        riga = psn_db.query("SELECT count(*) AS n FROM psn_import", (), one=True)
    assert int(riga["n"]) == 1


# --------------------------------------------------------------------------- #
# Il piano vero, se e' nel repository
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(not PIANO_REALE.exists(),
                    reason="il piano reale non e' nel repository")
def test_il_piano_reale_si_importa_per_intero(psn_app):
    """LA PROVA CHE CONTA: il documento vero, con le sue settantanove schede, le sue
    cinque forme di intestazione, i suoi errori di formula e i suoi indirizzi salvati
    come numeri. Una prova su un foglio costruito dal test dimostra che il lettore
    funziona; questa dimostra che funziona su CIO' CHE C'E'."""
    esito, riscontri = _importa(psn_app, PIANO_REALE.read_bytes(),
                                PIANO_REALE.name)

    assert esito.conteggi["subnet"] >= 70
    assert esito.conteggi["indirizzi"] > 16000
    assert esito.conteggi["sezioni"] >= 7
    assert esito.conteggi["tenant"] >= 20
    # I 441 indirizzi che erano invisibili: quattro fogli li avevano salvati come
    # numeri, e senza la ricostruzione risultavano vuoti.
    assert esito.conteggi.get("indirizzi_ricostruiti", 0) >= 400
    # I due fogli col codice discordante.
    assert esito.conteggi.get("codici_foglio_discordanti", 0) >= 2
    # L'analisi trova qualcosa: un piano di questa dimensione non e' mai perfetto, e
    # un'analisi che non trovasse nulla sarebbe un'analisi che non guarda.
    assert riscontri, "nessun riscontro sul piano reale: l'analisi non sta guardando"
