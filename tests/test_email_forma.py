"""
snap - Test della forma dei messaggi di posta.

Le email di snap arrivano a persone che non hanno la console davanti: un turno di notte,
un responsabile sul telefono, un amministratore che riceve le proprie credenziali. Le
prove qui verificano le cose che decidono se quel messaggio si legge o si butta:

* **una forma sola** per tutti i generi -- un messaggio che sembra diverso dal
  precedente costringe a rileggerlo tutto per capire che cosa e' cambiato;
* i **vincoli della posta**: stili in linea, impaginazione a tabelle, nessuna risorsa
  esterna, nessun tracciamento;
* la **preintestazione**, cioe' la riga che il client mostra in anteprima: se non la si
  scrive, mostra il primo testo che trova. E in quella riga non deve finire una
  password;
* il **testo semplice** resta il contenuto: l'HTML e' l'alternativa.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

import pytest

INCIDENTE = {
    "id": 42, "check_name": "Presenza in rete", "address": "10.10.5.20",
    "severity": "critical", "opened_at": "2026-08-31 14:05:00", "failure_count": 5,
    "acknowledged_at": None, "resolved_at": None,
}
CONSOLE = "http://10.20.10.42:5500"


class Bilancio(HTMLParser):
    """Controlla che i tag siano chiusi nell'ordine giusto.

    I client di posta meno tolleranti non correggono la marcatura: un tag non chiuso
    diventa mezzo messaggio invisibile.
    """

    VUOTI = {"meta", "br", "img", "hr", "input", "link"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.pila = []
        self.errori = []

    def handle_starttag(self, tag, attrs):
        if tag not in self.VUOTI:
            self.pila.append(tag)

    def handle_endtag(self, tag):
        if not self.pila or self.pila[-1] != tag:
            self.errori.append("</%s> inattesa (aperti: %s)" % (tag, self.pila[-3:]))
        else:
            self.pila.pop()


@pytest.fixture()
def messaggi(server_app):
    """Un messaggio per ciascun genere che il prodotto invia."""
    with server_app.app_context():
        from snapserver.notifications import _credenziali_html, incident_html

        return {
            "aperto": incident_html("incident.opened", INCIDENTE, "nessuna risposta",
                                    CONSOLE),
            "escalato": incident_html("incident.escalated", INCIDENTE, "", CONSOLE),
            "risolto": incident_html("incident.resolved",
                                     dict(INCIDENTE, resolved_at="2026-08-31 15:10:00"),
                                     "", CONSOLE),
            "credenziali": _credenziali_html("nuovo@ised.local", "Prov!2026-xY7",
                                             "Buongiorno,", "Analista", CONSOLE),
        }


# --------------------------------------------------------------------------- #
# I vincoli della posta
# --------------------------------------------------------------------------- #
def test_ogni_messaggio_e_marcatura_chiusa(messaggi):
    for nome, html in messaggi.items():
        bilancio = Bilancio()
        bilancio.feed(html)
        assert not bilancio.errori, "%s: %s" % (nome, bilancio.errori)
        assert not bilancio.pila, "%s: tag aperti %s" % (nome, bilancio.pila)


def test_nessun_messaggio_carica_risorse_esterne(messaggi):
    """Le immagini vengono bloccate per difetto: un messaggio che dipende da loro arriva
    rotto. E un pixel di tracciamento, in un prodotto di sicurezza, sarebbe una
    contraddizione."""
    for nome, html in messaggi.items():
        assert "<img" not in html, nome
        assert "background-image" not in html, nome
        assert "fonts.googleapis" not in html and "@import" not in html, nome
        # I soli indirizzi ammessi sono i collegamenti alla console del tenant.
        indirizzi = re.findall(r'(?:href|src)="(https?://[^"]+)"', html)
        assert all(i.startswith(CONSOLE) for i in indirizzi), (nome, indirizzi)


def test_gli_stili_sono_in_linea(messaggi):
    """I client di posta ignorano i fogli di stile e molti tolgono il tag `style`: cio'
    che deve funzionare sta negli attributi."""
    for nome, html in messaggi.items():
        assert html.count('style="') > 10, nome
        # Il tag `<style>` c'e' solo per il tema scuro e la larghezza ridotta: sono
        # migliorie, non condizioni di leggibilita'.
        blocco = re.search(r"<style>(.*?)</style>", html, re.S)
        if blocco:
            assert "prefers-color-scheme" in blocco.group(1) or \
                "max-width" in blocco.group(1), nome


def test_l_impaginazione_a_tabelle_non_e_annunciata_ai_lettori_di_schermo(messaggi):
    """Outlook usa il motore di Word e non impagina con i box moderni; le tabelle di
    impaginazione, pero', non sono dati e non vanno annunciate."""
    for nome, html in messaggi.items():
        tabelle = re.findall(r"<table[^>]*>", html)
        assert tabelle, nome
        assert all('role="presentation"' in t for t in tabelle), nome


def test_la_larghezza_e_dichiarata(messaggi):
    from snapserver.mail_layout import LARGHEZZA

    for nome, html in messaggi.items():
        assert "%dpx" % LARGHEZZA in html, nome
        assert LARGHEZZA <= 700, "oltre questa misura serve la barra orizzontale"


# --------------------------------------------------------------------------- #
# La forma, e cio' che dice
# --------------------------------------------------------------------------- #
def test_ogni_messaggio_ha_marchio_titolo_e_ragione(messaggi):
    import html as modulo_html

    for nome, sorgente in messaggi.items():
        # Gli apostrofi escono come entita' (la stessa funzione di escape serve anche
        # agli attributi): si confronta con le entita' risolte.
        leggibile = modulo_html.unescape(sorgente)
        assert "SNAP" in leggibile, nome
        assert "<h1" in sorgente, nome
        assert "Ricevi questo messaggio perche'" in leggibile, (
            "%s: senza la ragione, il destinatario non sa perche' e' arrivato" % nome)
        assert "Non rispondere a questo indirizzo" in leggibile, nome
        assert "DS Consulting" in leggibile, nome


def test_la_fascia_distingue_i_generi(messaggi):
    """Un incidente aperto e un incidente rientrato non possono avere lo stesso colore,
    altrimenti la fascia non aggiunge niente."""
    from snapserver.mail_layout import GENERI

    critico = GENERI["critico"]["banda"]
    sereno = GENERI["sereno"]["banda"]

    assert critico in messaggi["aperto"]
    assert sereno in messaggi["risolto"]
    assert critico != sereno


def test_l_anteprima_e_scritta_e_non_contiene_la_password(messaggi):
    """La preintestazione compare nelle notifiche del telefono: una password la'
    finisce su uno schermo bloccato."""
    for nome, html in messaggi.items():
        anteprima = re.search(r"display:none[^>]*>(.*?)</div>", html, re.S)
        assert anteprima, "%s: manca la preintestazione" % nome
        assert anteprima.group(1).strip(), nome
    anteprima = re.search(r"display:none[^>]*>(.*?)</div>", messaggi["credenziali"],
                          re.S).group(1)
    assert "Prov!2026-xY7" not in anteprima
    assert "Prov!2026-xY7" in messaggi["credenziali"], (
        "la password c'e', ma nel corpo")


def test_il_pulsante_porta_alla_console_e_senza_console_non_c_e(server_app):
    """Un pulsante che non porta da nessuna parte e' peggio della sua assenza."""
    with server_app.app_context():
        from snapserver.notifications import incident_html

        con = incident_html("incident.opened", INCIDENTE, "", CONSOLE)
        senza = incident_html("incident.opened", INCIDENTE, "", "")

    assert CONSOLE in con
    assert "href=" not in senza or "http" not in senza


def test_i_dati_non_possono_iniettare_marcatura(server_app):
    """Il dettaglio di una verifica arriva dalla rete: se contenesse marcatura, la
    romperebbe -- o peggio."""
    with server_app.app_context():
        from snapserver.notifications import incident_html

        html = incident_html("incident.opened",
                             dict(INCIDENTE, check_name="<script>x</script>"),
                             "<b>grassetto</b> & <img src=x>", CONSOLE)

    assert "<script>" not in html
    assert "<b>grassetto</b>" not in html
    assert "&lt;script&gt;" in html


def test_il_messaggio_html_accompagna_sempre_il_testo(server_app):
    """L'HTML e' l'alternativa, non il contenuto: `compose` mette il testo per primo."""
    with server_app.app_context():
        from snapserver.notifications import compose, incident_html, incident_message

        oggetto, corpo = incident_message("incident.opened", INCIDENTE, "dettaglio")
        html = incident_html("incident.opened", INCIDENTE, "dettaglio", CONSOLE)
        messaggio = compose({"sender": "snap@esempio", "sender_name": "snap"},
                            "a@esempio", oggetto, corpo, body_html=html)

    parti = [p.get_content_type() for p in messaggio.walk()]
    assert "text/plain" in parti
    assert "text/html" in parti
    assert parti.index("text/plain") < parti.index("text/html"), (
        "il testo viene prima: e' la forma che si legge dappertutto")


# --------------------------------------------------------------------------- #
# I blocchi del layout
# --------------------------------------------------------------------------- #
def test_i_fatti_saltano_i_valori_vuoti(server_app):
    """Una riga "Risolto il: -" occupa spazio e non dice niente."""
    with server_app.app_context():
        from snapserver.mail_layout import fatti

        html = fatti([("Presente", "valore"), ("Vuoto", ""), ("Niente", None)])

    assert "Presente" in html
    assert "Vuoto" not in html and "Niente" not in html


def test_un_valore_da_copiare_sta_in_un_riquadro(server_app):
    """Una password in mezzo a un paragrafo si seleziona male, e chi la seleziona male
    la incolla con uno spazio."""
    with server_app.app_context():
        from snapserver.mail_layout import codice

        html = codice("Prov!2026-xY7")

    assert "Prov!2026-xY7" in html
    assert "word-break:break-all" in html
    assert "monospace" in html


def test_il_resoconto_quotidiano_indossa_la_stessa_cornice(server_app):
    """Un resoconto che sembrasse un altro prodotto costringerebbe a riconoscere due
    mittenti diversi per lo stesso mittente."""
    from datetime import date

    with server_app.app_context():
        from snapserver.reports.render_mail import html_body

        dati = {
            "tenant": {"nome": "Tenant di prova", "fuso": "Europe/Rome"},
            "giorno": date(2026, 8, 31),
            "intervallo": "31/08/2026",
            "generato_utc": "2026-08-31 05:00:00",
            "inventario": {"nodi": 700, "subnet_dichiarate": 380,
                           "subnet_teorici": 96520, "occupazione": 0.7},
            "disponibilita": {"percentuale": 99.4, "misurato": True, "controlli": []},
            "incidenti": {"aperti": 0, "risolti": 1, "durata_media_minuti": 12,
                          "voci": []},
            "indisponibilita": [],
            "rilevamento_base": {"attivo": False},
            "da_risolvere": [],
            "tendenze": {"giorni": []},
            "igiene": {"controlli_sospesi": [], "bersagli_senza_controlli": [],
                       "nodi_non_identificati": 3, "porte_sospette": 0},
            "variazioni": {"generi": [], "totale": 0},
        }
        html = html_body(dati, CONSOLE)

    import html as modulo_html

    assert html.startswith("<!doctype html>")
    leggibile = modulo_html.unescape(html)
    assert "SNAP" in leggibile and "Ricevi questo messaggio perche'" in leggibile
    bilancio = Bilancio()
    bilancio.feed(html)
    assert not bilancio.errori and not bilancio.pila
