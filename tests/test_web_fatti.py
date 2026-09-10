"""
snap - Test della lettura evoluta delle pagine di gestione: navigazione e fatti.

Il caso che ha guidato il lavoro e' reale: `http://10.10.25.21/` restituisce 577 byte
con un `meta refresh`, un salto scritto in JavaScript e il titolo "Web Image Monitor".
Nessuna marca, nessun modello. Il modello, la posizione fisica e il nome host stanno
tre pagine piu' avanti, dentro un frame, come coppie etichetta/valore in italiano.
Leggere solo la radice significa non sapere niente di un apparato che dichiara tutto.

Le pagine di questa prova sono quelle vere dell'apparato, con nome host e posizione
sostituiti: la struttura serve alla prova, i dati di un apparato del cliente no.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def pagina(nome: str) -> str:
    return (FIXTURES / nome).read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Estrazione dei fatti
# --------------------------------------------------------------------------- #
def test_la_pagina_di_informazioni_dichiara_nome_posizione_e_host():
    """E' il dato che nessun'altra fase puo' ricavare: la posizione fisica non sta in
    rete, sta scritta sull'apparato da chi lo ha installato."""
    from snapprobe.web_facts import fatti

    trovati = fatti(pagina("web_ricoh_informazioni.html"))

    assert trovati["nome_dispositivo"] == "RICOH MP C4504ex"
    assert trovati["posizione"] == "UFFICIO 12 - PIANO 1"
    assert trovati["nome_host"] == "stampante-piano1"


def test_un_campo_vuoto_non_prende_il_valore_del_campo_successivo():
    """Difetto trovato sul campo: il "Commento" e' vuoto (la cella contiene solo i due
    punti) e l'estrattore gli assegnava "Nome host", cioe' l'ETICHETTA successiva."""
    from snapprobe.web_facts import fatti

    trovati = fatti(pagina("web_ricoh_informazioni.html"))

    assert trovati.get("commento") in (None, ""), (
        "un campo vuoto resta vuoto: %r" % trovati.get("commento"))


def test_la_radice_non_dichiara_niente_e_lo_si_deve_ammettere():
    from snapprobe.web_facts import fatti

    assert fatti(pagina("web_ricoh_radice.html")) == {}


def test_marca_e_modello_si_separano():
    """Un nome come `RICOH MP C4504ex` contiene entrambe le cose: senza separarle
    l'inventario mostrerebbe il modello "RICOH MP C4504ex" della marca "Ricoh"."""
    from snapprobe.web_facts import marca_e_modello

    esito = marca_e_modello({"nome_dispositivo": "RICOH MP C4504ex"})

    assert esito["marca"] == "Ricoh"
    assert esito["modello"] == "MP C4504ex"


def test_marche_scritte_in_modo_diverso_diventano_la_stessa():
    from snapprobe.web_facts import marca_e_modello

    for scritta in ("RICOH MP C4504ex", "Ricoh Aficio MP 2000", "NASHUATEC MP C300"):
        assert marca_e_modello({"nome_dispositivo": scritta})["marca"] == "Ricoh"


def test_i_valori_segnaposto_valgono_come_assenti():
    """Registrare "non impostato" e' peggio che non avere il dato: sembra un dato."""
    from snapprobe.web_facts import fatti

    trovati = fatti("<table><tr><td>Posizione</td><td>: non impostato</td></tr>"
                    "<tr><td>Nome host</td><td>: -</td></tr></table>")

    assert "posizione" not in trovati
    assert "nome_host" not in trovati


def test_un_frammento_di_marcatura_non_diventa_un_valore():
    from snapprobe.web_facts import pulisci

    assert pulisci("<b>ciao</b>") == ""
    assert pulisci("javascript:void(0)") == ""
    assert pulisci(" : RICOH MP C4504ex ") == "RICOH MP C4504ex"


def test_le_etichette_valgono_in_piu_lingue():
    from snapprobe.web_facts import fatti

    inglese = fatti("<tr><td>Device Name</td><td>: HP LaserJet MFP M428</td></tr>"
                    "<tr><td>Serial Number</td><td>: CNB1234567</td></tr>")
    tedesco = fatti("<dl><dt>Ger&auml;tename</dt><dd>: KYOCERA TASKalfa 3253ci</dd></dl>")

    assert inglese["nome_dispositivo"] == "HP LaserJet MFP M428"
    assert inglese["seriale"] == "CNB1234567"
    assert tedesco["nome_dispositivo"] == "KYOCERA TASKalfa 3253ci"


def test_i_fatti_si_leggono_anche_dai_tag_di_un_documento_xml():
    """Molti apparati espongono un endpoint di sola lettura: nomi di tag al posto
    delle etichette, la stessa informazione detta a una macchina."""
    from snapprobe.web_facts import fatti

    trovati = fatti("<ProductConfig><MakeAndModel>HP LaserJet M507</MakeAndModel>"
                    "<SerialNumber>VNC3K12345</SerialNumber>"
                    "<DeviceLocation>Magazzino</DeviceLocation></ProductConfig>")

    assert trovati["modello"] == "HP LaserJet M507"
    assert trovati["seriale"] == "VNC3K12345"
    assert trovati["posizione"] == "Magazzino"


def test_un_documento_xml_troncato_non_manda_in_errore():
    """Il corpo si legge fino a un tetto di byte: l'ultimo tag puo' restare aperto."""
    from snapprobe.web_facts import fatti

    trovati = fatti("<cfg><ModelName>Zebra ZT411</ModelName><SerialNumber>ZT4")

    assert trovati["modello"] == "Zebra ZT411"


def test_i_fatti_non_contengono_il_contenuto_della_pagina():
    """Un fatto e' corto per costruzione: se un valore fosse un paragrafo, il modulo
    starebbe restituendo il contenuto della pagina invece di un dato (GDPR art. 5)."""
    from snapprobe.web_facts import MAX_VALORE, fatti

    trovati = fatti(pagina("web_ricoh_informazioni.html"))

    assert trovati
    for chiave, valore in trovati.items():
        assert len(valore) <= MAX_VALORE, chiave


# --------------------------------------------------------------------------- #
# Navigazione
# --------------------------------------------------------------------------- #
def test_dalla_radice_si_ricava_il_salto_scritto_in_javascript():
    """Il `meta refresh` di questo apparato porta a una pagina di avviso; il salto
    vero e' nel `location.href` eseguito al caricamento."""
    from snapprobe.web_facts import bersagli

    proposte = bersagli(pagina("web_ricoh_radice.html"), "http://10.0.0.1/")
    per_origine = {p["origine"]: p["url"] for p in proposte}

    assert per_origine["script"].endswith("/web/guest/it/websys/webArch/mainFrame.cgi")
    assert "refresh" in per_origine


def test_la_pagina_di_avviso_si_legge_per_ultima():
    """Esiste per dire al browser che manca JavaScript: occupa il budget e non porta
    un fatto."""
    from snapprobe.web_facts import bersagli

    proposte = {p["origine"]: p["priorita"]
                for p in bersagli(pagina("web_ricoh_radice.html"), "http://10.0.0.1/")}

    assert proposte["script"] < proposte["refresh"]


def test_i_frame_di_una_pagina_sono_le_sue_parti():
    from snapprobe.web_facts import bersagli

    proposte = bersagli(pagina("web_ricoh_frameset.html"),
                        "http://10.0.0.1/web/guest/it/websys/webArch/mainFrame.cgi")
    indirizzi = [p["url"] for p in proposte if p["origine"] == "frame"]

    assert any(i.endswith("/header.cgi") for i in indirizzi)
    assert any(i.endswith("/topPage.cgi") for i in indirizzi)


def test_un_indirizzo_con_un_verbo_distruttivo_non_si_apre_mai():
    """Una GET non e' innocua se dietro c'e' un'azione: meglio perdere un fatto che
    spegnere una stampante durante un inventario."""
    from snapprobe.web_facts import bersagli

    for cattivo in ("/cgi/reboot.cgi", "/admin/factory_reset.htm", "/logout.cgi",
                    "/fw/upgrade.html", "/config/delete?id=3"):
        proposte = bersagli('<frame src="%s">' % cattivo, "http://10.0.0.1/")
        assert proposte == [], cattivo


def test_una_pagina_il_cui_nome_contiene_start_si_apre():
    """La prima versione dell'elenco conteneva "start" e scartava `Start_Wlm.htm`, che
    e' la pagina iniziale delle Kyocera: si perdevano modello e posizione di decine di
    apparati per una parola."""
    from snapprobe.web_facts import bersagli

    proposte = bersagli('<frameset><frame src="../startwlm/Start_Wlm.htm"></frameset>',
                        "http://10.0.0.1/")

    assert [p["url"] for p in proposte] == ["http://10.0.0.1/startwlm/Start_Wlm.htm"]


def test_un_comando_con_parametri_resta_escluso():
    from snapprobe.web_facts import bersagli

    assert bersagli('<a href="/cgi?set=1&value=off">Imposta</a>', "http://10.0.0.1/",
                    True) == []


def test_la_landing_page_initialize_si_apre_ma_non_il_comando():
    """`web/initialize.htm` e' la landing page dei web card Vertiv/Emerson IntelliSlot,
    non un'azione: si segue il redirect JavaScript. Con dei parametri, invece, diventa
    un comando e resta escluso -- come "start"."""
    from snapprobe.web_facts import bersagli

    pagina = '<script>document.location = "web/initialize.htm";</script>'
    assert [p["url"] for p in bersagli(pagina, "http://10.112.9.24/")] == [
        "http://10.112.9.24/web/initialize.htm"]
    con_coda = '<script>document.location = "web/initialize.htm?do=factory";</script>'
    assert bersagli(con_coda, "http://10.112.9.24/") == []


def test_il_web_card_vertiv_intellislot_si_riconosce():
    """Il gruppo frigo (unita' Liebert) espone un web card Vertiv/Emerson IntelliSlot:
    dal titolo si ricava marca e modello, e la versione dalla variabile `fwLabel`."""
    from snapprobe.web_facts import fatti, marca_e_modello

    titolo = "Emerson Network Power IntelliSlot Web Card"
    esito = marca_e_modello({}, titolo, "Apache/2.4.4 (Unix)")
    assert esito["marca"] == "Vertiv"
    assert "IntelliSlot" in esito["modello"]

    fw = fatti('<script>var fwLabel = "IS-UNITY_5.0.0.0_91932";</script>')
    assert fw.get("firmware") == "IS-UNITY 5.0.0.0 (build 91932)"


def test_il_telefono_ip_cisco_dichiara_tutto_nei_suoi_xml():
    """Gli endpoint /DeviceInformationX e /NetworkConfigurationX di un telefono IP Cisco
    dichiarano in XML una montagna di dati: interno, carichi, revisione hardware,
    numero di serie, modello, gestore chiamate, server TFTP. E' il caso reale del
    CP-7962G, con MAC, host e interno sostituiti."""
    from snapprobe.web_facts import fatti, marca_e_modello

    dev = fatti(pagina("web_cisco_phone_deviceinfo.xml"))
    assert dev["modello"] == "CP-7962G"
    assert dev["nome_host"] == "SEP001122334455"
    assert dev["seriale"] == "ABC1234567X"
    assert dev["firmware"] == "*SCCP42.9-4-2SR3-1S*"
    assert dev["numero_interno"] == "1000"
    assert dev["carico_software"] == "jar42sccp.9-4-2ES26.sbn"
    assert dev["carico_avvio"] == "tnp62.8-3-1-21a.bin"
    assert dev["revisione_hw"] == "13.0"

    net = fatti(pagina("web_cisco_phone_netconfig.xml"))
    assert net["server_tftp"] == "10.0.0.101"
    assert net["gestore_chiamate"] == "10.0.0.101 Attivo"

    # Cisco arriva dal titolo/nome dispositivo, non dalla sigla del modello.
    assert marca_e_modello(dev, "Cisco Systems, Inc.")["marca"] == "Cisco"
    assert marca_e_modello(dev, "Cisco Systems, Inc.")["modello"] == "CP-7962G"


def test_i_collegamenti_si_seguono_solo_se_promettono_informazioni():
    from snapprobe.web_facts import bersagli

    marcatura = ('<a href="/info/device.htm">Informazioni dispositivo</a>'
                 '<a href="/shop.html">Acquista consumabili</a>')
    proposte = bersagli(marcatura, "http://10.0.0.1/", cerca_ancore=True)

    assert [p["url"] for p in proposte] == ["http://10.0.0.1/info/device.htm"]


def test_senza_il_permesso_i_collegamenti_non_si_seguono():
    """I collegamenti sono un tentativo: si fanno solo quando i fatti mancano."""
    from snapprobe.web_facts import bersagli

    assert bersagli('<a href="/info/device.htm">Informazioni</a>',
                    "http://10.0.0.1/") == []


def test_un_indirizzo_fuori_dall_apparato_non_e_dello_stesso_apparato():
    """Un apparato che rimanda al portale del fornitore non e' quel portale, e quel
    portale non e' nel perimetro che qualcuno ha autorizzato a leggere."""
    from snapprobe.web_facts import stesso_apparato

    assert stesso_apparato("http://10.0.0.1/x.htm", "10.0.0.1", 80)
    assert not stesso_apparato("http://supporto.esempio.com/x", "10.0.0.1", 80)
    assert not stesso_apparato("http://10.0.0.1:8080/x", "10.0.0.1", 80), (
        "un'altra porta e' un altro servizio")
    assert stesso_apparato("https://10.0.0.1/x", "10.0.0.1", 443)


def test_uno_schema_non_web_non_e_un_bersaglio():
    from snapprobe.web_facts import bersagli

    marcatura = ('<a href="mailto:tecnico@esempio.it">Assistenza</a>'
                 '<frame src="javascript:void(0)">'
                 '<frame src="ftp://10.0.0.1/firmware">')

    assert bersagli(marcatura, "http://10.0.0.1/", True) == []


# --------------------------------------------------------------------------- #
# Lettura completa, senza rete
# --------------------------------------------------------------------------- #
class RispostaFinta:
    """Il minimo che il lettore usa di una risposta HTTP."""

    def __init__(self, stato=200, corpo="", intestazioni=None):
        self.status_code = stato
        self._corpo = corpo.encode("utf-8")
        self.headers = intestazioni or {"Content-Type": "text/html; charset=UTF-8"}

    @property
    def is_redirect(self):
        return 300 <= self.status_code < 400 and "Location" in self.headers

    def __bool__(self):
        # Come `requests`: una risposta 4xx/5xx e' falsa. Serve a difendere il lettore
        # dal difetto che faceva registrare un 500 come "nessuno stato".
        return self.status_code < 400


@pytest.fixture()
def rete_ricoh(monkeypatch):
    """La multifunzione come risponde davvero, senza toccare la rete."""
    import snapprobe.web_probe as lettore

    pagine = {
        "/": pagina("web_ricoh_radice.html"),
        "/web/guest/it/websys/webArch/mainFrame.cgi": pagina("web_ricoh_frameset.html"),
        "/web/guest/it/websys/webArch/topPage.cgi": pagina("web_ricoh_informazioni.html"),
        "/web/guest/it/websys/webArch/header.cgi": "<title>Intestazione</title>",
    }
    chieste = []

    def falso_scarica(indirizzo, ip):
        from urllib.parse import urlsplit

        parti = urlsplit(indirizzo)
        chieste.append(parti.path + (("?" + parti.query) if parti.query else ""))
        corpo = pagine.get(parti.path)
        if corpo is None:
            return RispostaFinta(404, "non trovato"), b"", None
        risposta = RispostaFinta(200, corpo)
        risposta.headers["Server"] = "Web-Server/3.0"
        return risposta, corpo.encode("utf-8"), None

    monkeypatch.setattr(lettore, "_scarica", falso_scarica)
    return chieste


def test_la_lettura_arriva_ai_fatti_passando_dalle_pagine_intermedie(rete_ricoh):
    from snapprobe.web_probe import leggi_pagina

    esito = leggi_pagina("10.0.0.1", 80, False)

    assert esito["marca"] == "Ricoh"
    assert esito["modello"] == "MP C4504ex"
    assert esito["tipo_probabile"] == "printer"
    assert esito["fatti"]["posizione"] == "UFFICIO 12 - PIANO 1"
    assert esito["fatti"]["nome_host"] == "stampante-piano1"
    assert esito["pagine_lette"] >= 3
    assert "/web/guest/it/websys/webArch/topPage.cgi" in rete_ricoh


def test_il_percorso_seguito_resta_nel_risultato(rete_ricoh):
    """Un fatto senza la pagina da cui viene non e' verificabile."""
    from snapprobe.web_probe import leggi_pagina

    esito = leggi_pagina("10.0.0.1", 80, False)
    origini = {p["origine"] for p in esito["pagine"]}

    assert "radice" in origini
    assert "script" in origini or "refresh" in origini
    assert all("percorso" in p and "stato" in p for p in esito["pagine"])


def test_la_lettura_si_ferma_quando_l_apparato_ha_detto_abbastanza(rete_ricoh):
    """Continuare a leggere pagine di un apparato che si e' presentato e' tempo tolto
    agli altri."""
    from snapprobe.web_probe import MAX_PAGINE_PER_PORTA, leggi_pagina

    esito = leggi_pagina("10.0.0.1", 80, False)

    assert esito["pagine_lette"] <= MAX_PAGINE_PER_PORTA
    assert "/web/guest/it/websys/webArch/message.cgi" not in " ".join(rete_ricoh), (
        "la pagina di avviso non serviva piu'")


def test_il_corpo_delle_pagine_non_compare_nel_risultato(rete_ricoh):
    """Il contenuto puo' contenere dati personali di cui il prodotto non ha bisogno."""
    import json

    from snapprobe.web_probe import leggi_pagina

    esito = leggi_pagina("10.0.0.1", 80, False)
    testo = json.dumps(esito, ensure_ascii=False)

    assert "frameset" not in testo
    assert "<html" not in testo
    assert "Toner" not in testo, "lo stato dei materiali di consumo non e' inventario"
    assert esito["corpo_impronta"], "resta l'impronta, che dice se la pagina e' cambiata"


def test_uno_stato_di_errore_viene_registrato_come_tale(monkeypatch):
    """`if risposta` sarebbe sbagliato: in `requests` una risposta 4xx/5xx e' falsa, e
    un 500 finiva nel diario come "nessuno stato"."""
    import snapprobe.web_probe as lettore

    def falso_scarica(indirizzo, ip):
        if indirizzo.endswith("/"):
            risposta = RispostaFinta(200, '<frameset><frame src="/x.htm"></frameset>')
            return risposta, b'<frameset><frame src="/x.htm"></frameset>', None
        return RispostaFinta(500, "errore"), b"errore", None

    monkeypatch.setattr(lettore, "_scarica", falso_scarica)
    esito = lettore.leggi_pagina("10.0.0.1", 80, False)

    stati = [p["stato"] for p in esito["pagine"]]
    assert 500 in stati


def test_una_pagina_protetta_viene_dichiarata(monkeypatch):
    """La pagina con i dati esiste ma chiede le credenziali: e' un'informazione, non un
    guasto, e spiega perche' di questo apparato si sa solo il genere."""
    import snapprobe.web_probe as lettore

    def falso_scarica(indirizzo, ip):
        if indirizzo.endswith("/"):
            corpo = ('<title>IP Phone</title><script>location.replace('
                     '"/cgi-bin/cgiServer.exx?page=Status.htm")</script>')
            return RispostaFinta(200, corpo), corpo.encode(), None
        return RispostaFinta(401, "401 Unauthorized"), b"401 Unauthorized", None

    monkeypatch.setattr(lettore, "_scarica", falso_scarica)
    esito = lettore.leggi_pagina("10.0.0.1", 80, False)

    assert esito["fatti_protetti"] is True
    assert esito["tipo_probabile"] == "voip", (
        "la marca resta ignota, il genere no: per un inventario e' cio' che conta")


def test_un_apparato_che_non_risponde_non_ferma_la_passata(monkeypatch):
    import snapprobe.web_probe as lettore

    monkeypatch.setattr(lettore, "_scarica",
                        lambda indirizzo, ip: (None, b"", "ConnectTimeout"))
    esito = lettore.leggi_pagina("10.0.0.1", 80, False)

    assert esito["errore"] == "ConnectTimeout"
    assert "fatti" not in esito


def test_un_anello_di_redirezioni_non_gira_a_vuoto(monkeypatch):
    import snapprobe.web_probe as lettore

    def falso_scarica(indirizzo, ip):
        risposta = RispostaFinta(302, "", {"Location": "/", "Content-Type": "text/html"})
        return risposta, b"", None

    monkeypatch.setattr(lettore, "_scarica", falso_scarica)
    esito = lettore.leggi_pagina("10.0.0.1", 80, False)

    assert esito["pagine_lette"] <= lettore.MAX_PAGINE_PER_PORTA


@pytest.fixture()
def rete_cisco_phone(monkeypatch):
    """Un telefono IP Cisco come risponde davvero: la radice e' un menu HTML che si
    presenta, e i dati stanno nei due XML di sola lettura /NetworkConfigurationX e
    /DeviceInformationX."""
    import snapprobe.web_probe as lettore

    pagine = {
        "/": pagina("web_cisco_phone_radice.html"),
        "/DeviceInformationX": pagina("web_cisco_phone_deviceinfo.xml"),
        "/NetworkConfigurationX": pagina("web_cisco_phone_netconfig.xml"),
    }

    def falso_scarica(indirizzo, ip):
        from urllib.parse import urlsplit

        corpo = pagine.get(urlsplit(indirizzo).path)
        if corpo is None:
            return RispostaFinta(404, "non trovato"), b"", None
        return RispostaFinta(200, corpo), corpo.encode("utf-8"), None

    monkeypatch.setattr(lettore, "_scarica", falso_scarica)


def test_la_lettura_del_telefono_cisco_passa_dai_due_xml(rete_cisco_phone):
    """Dalla radice, che non dichiara nulla di macchina, si arriva ai due endpoint XML
    documentati: entrambi vengono letti (la configurazione di rete da sola non basta a
    fermare la navigazione), e il verdetto e' un telefono VoIP Cisco CP-7962G."""
    from snapprobe.web_probe import leggi_pagina

    esito = leggi_pagina("10.0.0.139", 80, False)

    assert esito["marca"] == "Cisco"
    assert esito["modello"] == "CP-7962G"
    assert esito["prodotto"] == "Cisco Unified IP Phone"
    # La chiave e' quella esatta della classe: fa scattare la regola decisiva.
    assert esito["tipo_probabile"] == "voip_phone"
    assert esito["firma"] == "cisco-ip-phone"

    fatti = esito["fatti"]
    assert fatti["seriale"] == "ABC1234567X"
    assert fatti["numero_interno"] == "1000"
    assert fatti["gestore_chiamate"].startswith("10.0.0.101")
    assert fatti["server_tftp"] == "10.0.0.101"
    percorsi = [p["percorso"] for p in esito["pagine"]]
    assert "/NetworkConfigurationX" in percorsi and "/DeviceInformationX" in percorsi


def test_del_telefono_cisco_non_si_conserva_il_corpo(rete_cisco_phone):
    """Solo le etichette riconosciute: nessun frammento di pagina finisce nel dato."""
    import json

    from snapprobe.web_probe import leggi_pagina

    testo = json.dumps(leggi_pagina("10.0.0.139", 80, False), ensure_ascii=False)

    assert "<html" not in testo.lower()
    assert "Serviceability" not in testo, "i collegamenti del menu non sono un dato"


@pytest.fixture()
def rete_hp_ups(monkeypatch):
    """Uno UPS HP con scheda di gestione MGE/Eaton: la radice e' un frameset servito da
    RomPager, il modello ("HP R5000") sta in grassetto nella pagina Power Source."""
    import snapprobe.web_probe as lettore

    pagine = {
        "/": pagina("web_hp_ups_radice.html"),
        "/ups_prop.htm": pagina("web_hp_ups_prop.html"),
    }

    def falso_scarica(indirizzo, ip):
        from urllib.parse import urlsplit

        corpo = pagine.get(urlsplit(indirizzo).path)
        if corpo is None:
            return RispostaFinta(404, "non trovato"), b"", None
        risposta = RispostaFinta(200, corpo)
        risposta.headers["Server"] = "Allegro-Software-RomPager/4.01"
        return risposta, corpo.encode("utf-8"), None

    monkeypatch.setattr(lettore, "_scarica", falso_scarica)


def test_lo_ups_hp_si_riconosce_e_ne_esce_marca_e_modello(rete_hp_ups):
    """Il modello e' scritto in grassetto senza etichetta, e la radice e' un frameset:
    la firma scatta dal titolo e il percorso noto porta alla pagina del modello."""
    from snapprobe.web_probe import leggi_pagina

    esito = leggi_pagina("10.0.0.7", 80, False)

    assert esito["marca"] == "HP"
    assert esito["modello"] == "R5000"
    assert esito["tipo_probabile"] == "ups"
    assert esito["firma"] == "mge-ups"
    assert "/ups_prop.htm" in [p["percorso"] for p in esito["pagine"]]


def test_la_diagnosi_ups_legge_stato_e_registri_e_trova_i_problemi():
    """Vale per qualunque UPS con scheda MGE/Eaton: dallo stato e dai tre registri si
    ricavano le misure e i problemi. Le pagine sono quelle vere di un HP R5000, con i
    dati resi anonimi ma la struttura intatta."""
    from snapprobe.web_facts import diagnosi_ups

    d = diagnosi_ups(
        status=pagina("web_hp_ups_status.html"),
        eventi=pagina("web_hp_ups_eventlog.html"),
        sistema=pagina("web_hp_ups_systemlog.html"),
        misure=pagina("web_hp_ups_datalog.html"))

    assert d["alimentazione"] == "AC Power"
    assert d["carico_uscita"] == "9%"
    assert d["stato_batteria"] == "Aborted"
    assert d["autonomia_batteria"].startswith("24 mn")
    assert "28%" in d["capacita_batteria"] and "Fault" in d["capacita_batteria"]
    diagnosi = d["diagnosi_ups"]
    assert "Aborted" in diagnosi, "lo stato anomalo della batteria e' un problema"
    assert "non sta caricando" in diagnosi, "capacita' ferma al 28% sotto rete"
    assert "scollegata e ricollegata 80 volte" in diagnosi
    assert "orologio non affidabile" in diagnosi


def test_la_diagnosi_ups_dice_anche_quando_va_tutto_bene():
    """Uno UPS sano: batteria carica, nessun evento anomalo. La diagnosi deve dirlo,
    altrimenti "nessun problema" e "non controllato" si confonderebbero."""
    from snapprobe.web_facts import diagnosi_ups

    status = ("<table>"
              "<tr><td>Power source :</td><td>AC Power</td></tr>"
              "<tr><td>Output load level :</td><td>20%</td></tr>"
              "<tr><td>Battery Capacity :</td><td>100 %</td></tr>"
              "<tr><td>Remaining backup time :</td><td>45 mn</td></tr>"
              "<tr><td>Battery status :</td><td>Resting</td></tr></table>")

    d = diagnosi_ups(status=status, eventi="<table></table>", sistema="", misure="")

    assert d["capacita_batteria"] == "100%"
    assert d["stato_batteria"] == "Resting"
    assert d["diagnosi_ups"] == "Nessun problema rilevato"


def test_la_codifica_dichiarata_viene_rispettata():
    """Un apparato letto con la codifica sbagliata restituisce un fatto illeggibile, e
    quello finirebbe nell'inventario."""
    from snapprobe.web_probe import _decodifica

    corpo = "Posizione: UFFICIO PIÙ GRANDE".encode("cp1252")

    assert "PIÙ" in _decodifica(corpo, "text/html; charset=windows-1252")
    assert _decodifica(b"", "text/html") == ""


# --------------------------------------------------------------------------- #
# L'apparato muto: percorsi identificanti generici
# --------------------------------------------------------------------------- #
# Misurato su questa rete: `pagine_lette` restava a 1 su tutti i nodi esaminati. Non
# era il lettore a sbagliare -- era che la radice di un apparato incorporato e' un 401
# nudo, o una pagina di accesso senza un solo collegamento da seguire. Il lettore non
# aveva dove andare, e l'apparato restava anonimo pur avendo una pagina che lo dichiara
# per intero. Questi test coprono la via d'uscita e i suoi limiti.
DESCRIZIONE_UPNP = (
    '<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0">'
    "<device><deviceType>urn:schemas-upnp-org:device:Printer:1</deviceType>"
    "<friendlyName>STAMPANTE-SEGRETERIA</friendlyName>"
    "<manufacturer>Brother Industries, Ltd.</manufacturer>"
    "<modelName>HL-L3270CDW series</modelName>"
    "<serialNumber>E7A123456</serialNumber>"
    "</device></root>")


def _rete_muta(monkeypatch, pagine, stato_radice=401):
    """Un apparato che alla radice non dice niente e risponde solo su un percorso."""
    import snapprobe.web_probe as lettore

    chieste = []

    def falso_scarica(indirizzo, ip):
        from urllib.parse import urlsplit

        percorso = urlsplit(indirizzo).path
        chieste.append(percorso)
        if percorso == "/":
            return RispostaFinta(stato_radice, ""), b"", None
        corpo = pagine.get(percorso)
        if corpo is None:
            return RispostaFinta(404, "non trovato"), b"", None
        tipo = ("text/xml" if corpo.lstrip().startswith("<?xml") else "text/html")
        risposta = RispostaFinta(200, corpo, {"Content-Type": tipo})
        return risposta, corpo.encode("utf-8"), None

    monkeypatch.setattr(lettore, "_scarica", falso_scarica)
    return chieste


def test_un_apparato_muto_si_identifica_dalla_descrizione_upnp(monkeypatch):
    """La descrizione UPnP e' leggibile senza credenziali per costruzione, e dichiara
    costruttore, modello, numero di serie e nome: su un apparato muto e' tutto."""
    from snapprobe.web_probe import leggi_pagina

    chieste = _rete_muta(monkeypatch, {"/description.xml": DESCRIZIONE_UPNP})

    esito = leggi_pagina("10.0.0.9", 80, False)

    assert "/description.xml" in chieste
    assert esito["fatti"]["nome_dispositivo"] == "STAMPANTE-SEGRETERIA"
    assert esito["fatti"]["seriale"] == "E7A123456"
    assert esito["marca"] == "Brother"
    assert "HL-L3270CDW" in esito["modello"]
    assert esito["pagine_lette"] > 1


def test_i_percorsi_generici_si_provano_solo_se_manca_tutto(monkeypatch):
    """Un apparato che si e' gia' presentato non va interrogato ancora: sarebbero
    richieste tolte agli altri nodi della passata."""
    from snapprobe.web_probe import leggi_pagina

    chieste = _rete_muta(monkeypatch, {}, stato_radice=200)
    import snapprobe.web_probe as lettore

    def parlante(indirizzo, ip):
        from urllib.parse import urlsplit

        chieste.append(urlsplit(indirizzo).path)
        corpo = ("<title>HP LaserJet MFP M428</title>"
                 "<table><tr><td>Nome host:</td><td>hp-m428</td></tr>"
                 "<tr><td>Numero di serie:</td><td>CNB1234</td></tr>"
                 "<tr><td>Posizione:</td><td>UFFICIO 3</td></tr></table>")
        return RispostaFinta(200, corpo), corpo.encode("utf-8"), None

    monkeypatch.setattr(lettore, "_scarica", parlante)

    leggi_pagina("10.0.0.10", 80, False)

    assert not any(p == "/description.xml" for p in chieste)


def test_la_stessa_pagina_servita_per_ogni_percorso_non_si_riesamina(monkeypatch):
    """Molti apparati servono la propria pagina di accesso per QUALUNQUE indirizzo: si
    otterrebbero cinque copie della stessa pagina, e un conto di pagine lette che
    promette un approfondimento mai avvenuto."""
    import snapprobe.web_probe as lettore
    from snapprobe.web_probe import leggi_pagina

    accesso = '<html><body><form><input type="password"></form></body></html>'
    chieste = []

    def sempre_accesso(indirizzo, ip):
        from urllib.parse import urlsplit

        chieste.append(urlsplit(indirizzo).path)
        return RispostaFinta(200, accesso), accesso.encode("utf-8"), None

    monkeypatch.setattr(lettore, "_scarica", sempre_accesso)

    esito = leggi_pagina("10.0.0.11", 80, False)
    letti = [p for p in esito["pagine"] if p["origine"] == "percorso generico"]

    assert len(chieste) > 1, "i percorsi generici si provano: la radice non dice nulla"
    assert esito["modulo_accesso"] is True
    assert len(letti) <= len(chieste), "ogni tentativo resta nel diario"
    assert "fatti" not in esito, "una copia della pagina di accesso non e' un fatto"


def test_i_percorsi_generici_sono_di_sola_lettura():
    """Nessun percorso del catalogo deve contenere un verbo d'azione: la fase web fa
    solo GET informative, e un indirizzo con "reset" o "reboot" nel nome sarebbe un
    comando anche se richiesto in GET."""
    from snapprobe.web_facts import VERBI_CON_EFFETTO, VERBI_DISTRUTTIVI
    from snapprobe.web_probe import PERCORSI_GENERICI

    for percorso in PERCORSI_GENERICI:
        assert percorso.startswith("/"), percorso
        assert "?" not in percorso, "%s: nessun parametro" % percorso
        assert not VERBI_DISTRUTTIVI.search(percorso), percorso
        assert not VERBI_CON_EFFETTO.search(percorso), percorso


def test_il_tetto_delle_pagine_vale_anche_con_i_percorsi_generici(monkeypatch):
    """Il budget e' quello che rende la fase eseguibile su centinaia di indirizzi: i
    tentativi in piu' non devono poterlo sfondare."""
    from snapprobe.web_probe import (MAX_PAGINE_EXTRA, MAX_PAGINE_PER_PORTA,
                                     leggi_pagina)

    _rete_muta(monkeypatch, {"/status.html": "<title>Stato</title>",
                             "/info.html": "<title>Informazioni</title>",
                             "/system.html": "<title>Sistema</title>"})

    esito = leggi_pagina("10.0.0.12", 80, False)

    assert esito["pagine_lette"] <= MAX_PAGINE_PER_PORTA + MAX_PAGINE_EXTRA


def test_ogni_percorso_generico_si_arriva_a_provarlo():
    """Un percorso che il tetto per passata non raggiunge mai non e' un percorso: e'
    una riga che sembra fare qualcosa. Chi aggiunge un indirizzo al catalogo deve
    alzare il tetto, e questo test glielo dice."""
    from snapprobe.web_probe import (MAX_PAGINE_EXTRA, MAX_PERCORSI_GENERICI,
                                     PERCORSI_GENERICI)

    assert MAX_PERCORSI_GENERICI >= len(PERCORSI_GENERICI)
    assert MAX_PAGINE_EXTRA >= len(PERCORSI_GENERICI) + 2, (
        "il diario deve poter contenere anche i due percorsi della famiglia nota")


def test_un_indirizzo_assente_non_interrompe_la_ricerca(monkeypatch):
    """Un 404 e' una buona notizia: l'apparato distingue gli indirizzi, quindi il
    tentativo successivo ha senso. E' il contrario del catch-all."""
    from snapprobe.web_probe import PERCORSI_GENERICI, leggi_pagina

    ultimo = PERCORSI_GENERICI[-1]
    chieste = _rete_muta(monkeypatch, {
        ultimo: "<title>Info</title><table>"
                "<tr><td>Model:</td><td>ECOSYS M3145idn</td></tr>"
                "<tr><td>Host name:</td><td>kyo-piano2</td></tr></table>"})

    esito = leggi_pagina("10.0.0.13", 80, False)

    assert ultimo in chieste, "i 404 precedenti non hanno fermato la ricerca"
    assert esito["fatti"]["nome_host"] == "kyo-piano2"


def test_un_apparato_che_incanala_tutto_non_si_interroga_a_vuoto(monkeypatch):
    """Chi rimanda altrove qualunque indirizzo senza mai servire una pagina darebbe la
    stessa risposta a tutti i tentativi: sono richieste tolte agli altri nodi."""
    import snapprobe.web_probe as lettore

    chieste = []

    def sempre_redirezione(indirizzo, ip):
        from urllib.parse import urlsplit

        chieste.append(urlsplit(indirizzo).path)
        risposta = RispostaFinta(302, "", {"Location": "/", "Content-Type": "text/html"})
        return risposta, b"", None

    monkeypatch.setattr(lettore, "_scarica", sempre_redirezione)

    lettore.leggi_pagina("10.0.0.14", 80, False)

    assert not any(p in lettore.PERCORSI_GENERICI for p in chieste)
