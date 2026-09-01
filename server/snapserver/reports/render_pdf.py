"""
snap server - Impaginazione dei report in PDF: frontespizio, cornice, tabelle, grafici.

Struttura di ogni documento
---------------------------
1. **Frontespizio**: fascia colorata con il marchio, l'etichetta del genere di report, il
   titolo e la riga di identificazione (tenant, istante, autore della richiesta); poi due
   tavole affiancate -- *Riferimenti* (versioni, console, intervallo, fonte dei dati) e
   *Contenuto del documento* (indice delle sezioni) -- e la nota sulla provenienza dei
   dati.
2. **Pagine di contenuto**: testatina con marchio e genere, sezioni numerate, tabelle a
   righe alternate, indicatori a fascia, grafici a spezzata.
3. **Pie' di pagina**: titolarita', avvertenza di riservatezza, numero di pagina.

Il frontespizio non e' decorazione: un documento che circola fuori dal gruppo operativo
deve dire da se' che cos'e', di chi e' la rete descritta, a quale intervallo si riferisce
e da dove vengono i numeri. Senza queste quattro cose non e' una prova.

Un colore per genere
--------------------
Ogni genere di report ha una propria fascia: chi ne ha cinque sulla scrivania li
distingue prima di leggere il titolo. Il colore e' sempre accompagnato dall'etichetta in
testo, perche' una stampa in bianco e nero e chi non distingue i colori devono avere la
stessa informazione.

Tipografia: PT Sans Narrow per titoli e testatine, PT Sans per il corpo, PT Mono per
indirizzi e porte (convenzione di progetto). I file `.ttf` stanno in
`static/fonts/pdf/`; se mancano si ripiega su Helvetica dichiarandolo nel pie' di pagina,
perche' un documento che finge una tipografia che non ha sarebbe una piccola bugia
stampata.

Nessuna libreria di grafica: i grafici sono disegnati con le primitive (RP-14).

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from pathlib import Path

from reportlab.lib.colors import Color, HexColor
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.utils import simpleSplit
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas as pdf_canvas

from ..db import to_tenant_time
from ..tenancy import DEFAULT_TIMEZONE
from .dataset import change_label

# --------------------------------------------------------------------------- #
# Tavolozza
# --------------------------------------------------------------------------- #
INCHIOSTRO = HexColor("#131a1f")
INCHIOSTRO_2 = HexColor("#3f515d")
INCHIOSTRO_3 = HexColor("#6d8290")
LINEA = HexColor("#d6dee4")
FONDO = HexColor("#f3f6f8")
BIANCO = HexColor("#ffffff")
ACCENTO = HexColor("#0d6b78")
OK = HexColor("#1b7247")
ATTENZIONE = HexColor("#8f5600")
CRITICO = HexColor("#a32620")

# Un genere, un colore, un'etichetta. La fascia e' scura perche' il titolo va in bianco;
# l'accento serve alle barrette delle sezioni e ai valori; il chiaro alle fasce di
# indicatori e alle righe alternate delle tabelle.
TEMI = {
    "noc": {
        "banda": HexColor("#2c3a1c"), "accento": HexColor("#5f7a2e"),
        "chiaro": HexColor("#f0f3e7"), "etichetta": "TURNO NOC",
    },
    "executive": {
        "banda": HexColor("#16263f"), "accento": HexColor("#2c5c8f"),
        "chiaro": HexColor("#eaf0f7"), "etichetta": "DIREZIONE",
    },
    "inventory": {
        "banda": HexColor("#0f3239"), "accento": HexColor("#0d6b78"),
        "chiaro": HexColor("#e4f0f2"), "etichetta": "INVENTARIO",
    },
    "soc": {
        "banda": HexColor("#3a1618"), "accento": HexColor("#a32620"),
        "chiaro": HexColor("#f9ecea"), "etichetta": "SICUREZZA",
    },
    "threat": {
        "banda": HexColor("#2b1b3d"), "accento": HexColor("#6b3fa0"),
        "chiaro": HexColor("#f2ecf9"), "etichetta": "VULNERABILITA'",
    },
    "segmentation": {
        "banda": HexColor("#10302a"), "accento": HexColor("#1f7a63"),
        "chiaro": HexColor("#e6f2ee"), "etichetta": "SEGMENTAZIONE",
    },
    "hygiene": {
        "banda": HexColor("#33301a"), "accento": HexColor("#8a7a24"),
        "chiaro": HexColor("#f5f2e3"), "etichetta": "IGIENE DEL DATO",
    },
    "device": {
        "banda": HexColor("#1c2a35"), "accento": HexColor("#41708f"),
        "chiaro": HexColor("#eaf1f6"), "etichetta": "APPARATO",
    },
    "compliance": {
        "banda": HexColor("#2a2440"), "accento": HexColor("#574b8f"),
        "chiaro": HexColor("#efedf8"), "etichetta": "CONFORMITA'",
    },
    "acn": {
        # Comunicazione all'autorita': grigio-blu istituzionale, senza allarme. Il
        # documento e' formale, non un avviso di emergenza.
        "banda": HexColor("#1f2a44"), "accento": HexColor("#3c5488"),
        "chiaro": HexColor("#eceff6"), "etichetta": "COMUNICAZIONE ACN",
    },
    "eu_compliance": {
        # Il blu dell'Unione europea. L'accento resta un blu piu' chiaro: l'oro della
        # bandiera su fondo bianco non tiene il contrasto richiesto (WCAG AA).
        "banda": HexColor("#003399"), "accento": HexColor("#3366cc"),
        "chiaro": HexColor("#e9eefa"), "etichetta": "CONFORMITA' UE",
    },
    "incident": {
        "banda": HexColor("#3d2410"), "accento": HexColor("#b25a12"),
        "chiaro": HexColor("#fbf0e5"), "etichetta": "INCIDENTE",
    },
    "daily": {
        "banda": HexColor("#1f3033"), "accento": HexColor("#0d6b78"),
        "chiaro": HexColor("#eef3f4"), "etichetta": "RESOCONTO",
    },
}
TEMA_PREDEFINITO = TEMI["noc"]

MM = 2.834645669
MARGINE = 18 * MM
CORPO = 9
INTERLINEA = 12

PRODOTTO = "snap"
# Il marchio DISEGNATO sui documenti va in maiuscolo: a corpo 24 sulla copertina
# e a corpo 10 nella testatina, quattro lettere minuscole accanto agli archi si
# leggono come una parola qualsiasi. Nel testo e nei metadati il prodotto resta
# "snap", che e' il suo nome.
MARCHIO = PRODOTTO.upper()
SOTTOTITOLO_PRODOTTO = "Secure Network Assessment Platform"

# Cartella in cui cercare i caratteri da incorporare.
CARTELLA_FONT = Path(__file__).resolve().parent.parent / "static" / "fonts" / "pdf"
FONT_ATTESI = {
    "SnapNarrow": "PTSansNarrow-Regular.ttf",
    "SnapNarrow-Bold": "PTSansNarrow-Bold.ttf",
    "SnapSans": "PTSans-Regular.ttf",
    "SnapSans-Bold": "PTSans-Bold.ttf",
    "SnapMono": "PTMono-Regular.ttf",
}
_font_registrati = None


def tema_di(kind: str) -> dict:
    return TEMI.get(kind or "", TEMA_PREDEFINITO)


def font_status() -> dict:
    """Registra i caratteri se presenti. Idempotente, con esito dichiarato."""
    global _font_registrati
    if _font_registrati is not None:
        return _font_registrati

    presenti = {}
    for nome, file_atteso in FONT_ATTESI.items():
        percorso = CARTELLA_FONT / file_atteso
        if not percorso.is_file():
            continue
        try:
            pdfmetrics.registerFont(TTFont(nome, str(percorso)))
            presenti[nome] = file_atteso
        except Exception as errore:  # noqa: BLE001 - il file puo' essere corrotto
            # Un carattere illeggibile non deve impedire il report: si ripiega e si
            # dichiara, invece di far fallire una spedizione automatica alle 07:00.
            presenti.setdefault("_errori", {})[nome] = str(errore)

    completo = all(nome in presenti for nome in FONT_ATTESI)
    _font_registrati = {
        "completo": completo,
        "trovati": presenti,
        "cartella": str(CARTELLA_FONT),
        "titolo": "SnapNarrow-Bold" if completo else "Helvetica-Bold",
        "sottotitolo": "SnapNarrow" if completo else "Helvetica",
        "corpo": "SnapSans" if completo else "Helvetica",
        "corpo_grassetto": "SnapSans-Bold" if completo else "Helvetica-Bold",
        "mono": "SnapMono" if completo else "Courier",
    }
    return _font_registrati


def reset_font_cache() -> None:
    """Solo per le prove: rilegge la cartella dei caratteri."""
    global _font_registrati
    _font_registrati = None


class Foglio:
    """Cornice del documento: frontespizio, testatina, sezioni, avanzamento verticale.

    Il chiamante descrive le sezioni; le coordinate, i cambi di pagina e la numerazione
    sono di questa classe.
    """

    def __init__(self, percorso, kind, titolo, tenant, intervallo, generato,
                 sottotitolo="", scopo=(), sezioni=(), riferimenti=(), nota="",
                 orizzontale=False, autore="", fuso=None):
        self.font = font_status()
        self.tema = tema_di(kind)
        self.kind = kind
        self.formato = landscape(A4) if orizzontale else A4
        self.larghezza, self.altezza = self.formato
        self.c = pdf_canvas.Canvas(str(percorso), pagesize=self.formato)
        self.c.setTitle("%s - %s" % (PRODOTTO, titolo))
        self.c.setAuthor(PRODOTTO)
        self.c.setSubject(intervallo)
        self.c.setCreator("%s - %s" % (PRODOTTO, SOTTOTITOLO_PRODOTTO))
        self.titolo = titolo
        # Il fuso in cui il documento scrive le date. E' dichiarato in copertina
        # ("Fuso di riferimento"), quindi ogni istante stampato deve essere in QUEL
        # fuso: stampare UTC sotto quella dichiarazione non e' ambiguo, e' sbagliato.
        self.fuso = fuso or DEFAULT_TIMEZONE
        self.sottotitolo = sottotitolo or titolo
        self.tenant = tenant
        self.intervallo = intervallo
        # La riga di identificazione (copertina e testatina di ogni pagina) mostra
        # l'istante nel fuso del documento: era l'ultimo posto in cui restava un UTC
        # non dichiarato, e compariva su ogni pagina.
        self.generato_utc = generato
        momento = to_tenant_time(generato, self.fuso)
        self.generato = (momento.strftime("%d/%m/%Y %H:%M") if momento
                         else str(generato or ""))
        self.autore = autore
        self.sezioni_dichiarate = list(sezioni)
        self.numero_sezione = 0
        self.pagina = 0
        self._frontespizio(scopo, riferimenti, nota)
        self._nuova_pagina()

    # ------------------------------------------------------------------ #
    # Frontespizio
    # ------------------------------------------------------------------ #
    # -- date -----------------------------------------------------------------
    def istante(self, valore, vuoto: str = "-") -> str:
        """Un istante UTC scritto nel fuso del documento, al minuto.

        I secondi non si stampano: in una tabella non servono a nessuno e rubano
        spazio a cio' che serve.
        """
        momento = to_tenant_time(valore, self.fuso)
        return momento.strftime("%d/%m/%Y %H:%M") if momento else vuoto

    def giorno(self, valore, vuoto: str = "-") -> str:
        """Solo il giorno, nel fuso del documento."""
        momento = to_tenant_time(valore, self.fuso)
        return momento.strftime("%d/%m/%Y") if momento else vuoto

    def _marchio(self, x, y, scala=1.0, colore=None):
        """Marchio: tre archi e un punto, il segnale che una sonda ascolta."""
        c = self.c
        c.saveState()
        c.setStrokeColor(colore or BIANCO)
        c.setLineWidth(1.6 * scala)
        c.setLineCap(1)
        for raggio in (5, 9, 13):
            c.arc(x - raggio * scala, y - raggio * scala,
                  x + raggio * scala, y + raggio * scala, startAng=35, extent=110)
        c.setFillColor(colore or BIANCO)
        c.circle(x, y - 1 * scala, 1.9 * scala, stroke=0, fill=1)
        c.restoreState()

    def _frontespizio(self, scopo, riferimenti, nota):
        c = self.c
        self.pagina = 1
        # In orizzontale la pagina e' bassa e larga: la fascia si accorcia e il corpo del
        # frontespizio si distribuisce su tre colonne, altrimenti le tavole finiscono
        # sotto il pie' di pagina. In verticale la fascia puo' essere generosa.
        verticale = self.altezza > self.larghezza
        alto_banda = self.altezza * (0.42 if verticale else 0.34)
        base_banda = self.altezza - alto_banda

        c.setFillColor(self.tema["banda"])
        c.rect(0, base_banda, self.larghezza, alto_banda, stroke=0, fill=1)

        # Marchio e nome del prodotto.
        self._marchio(MARGINE + 14, self.altezza - 52, scala=1.0)
        c.setFillColor(BIANCO)
        c.setFont(self.font["titolo"], 24)
        c.drawString(MARGINE + 36, self.altezza - 62, MARCHIO)
        c.setFont(self.font["sottotitolo"], 9)
        c.setFillColor(Color(1, 1, 1, alpha=.72))
        c.drawString(MARGINE + 36, self.altezza - 76, SOTTOTITOLO_PRODOTTO)

        # Etichetta del genere, in alto a destra: si riconosce prima del titolo.
        etichetta = self.tema["etichetta"]
        larghezza_etichetta = pdfmetrics.stringWidth(etichetta, self.font["titolo"], 9) + 18
        c.setFillColor(self.tema["accento"])
        c.roundRect(self.larghezza - MARGINE - larghezza_etichetta, self.altezza - 70,
                    larghezza_etichetta, 16, 3, stroke=0, fill=1)
        c.setFillColor(BIANCO)
        c.setFont(self.font["titolo"], 9)
        c.drawCentredString(self.larghezza - MARGINE - larghezza_etichetta / 2,
                            self.altezza - 65, etichetta)

        # Titolo grande e riga di identificazione.
        y = base_banda + alto_banda * 0.34
        c.setFillColor(BIANCO)
        c.setFont(self.font["titolo"], 34)
        for riga in simpleSplit(self.titolo, self.font["titolo"], 34,
                                self.larghezza - 2 * MARGINE):
            c.drawString(MARGINE, y, riga)
            y -= 38
        c.setFont(self.font["sottotitolo"], 13)
        c.setFillColor(Color(1, 1, 1, alpha=.82))
        c.drawString(MARGINE, y - 2, self.sottotitolo)
        c.setFont(self.font["corpo"], 9)
        c.setFillColor(Color(1, 1, 1, alpha=.66))
        identificazione = "Tenant %s  ·  %s" % (self.tenant, self.generato)
        if self.autore:
            identificazione += "  ·  generato da %s" % self.autore
        c.drawString(MARGINE, y - 20, identificazione)

        # Scopo del documento, subito sotto la fascia.
        self.y = base_banda - 26
        for riga_scopo in scopo:
            self.paragrafo(riga_scopo, INCHIOSTRO_2, dimensione=10)
        self.y -= 6

        # Tavole affiancate: riferimenti e indice; in orizzontale anche la nota, che in
        # verticale sta sotto.
        colonne = 2 if verticale else 3
        spazio = 18
        colonna = (self.larghezza - 2 * MARGINE - spazio * (colonne - 1)) / colonne
        cima = self.y
        fine_riferimenti = self._tavola_frontespizio(
            MARGINE, cima, colonna, "Riferimenti",
            list(riferimenti) or self._riferimenti_predefiniti())
        fine_indice = self._tavola_frontespizio(
            MARGINE + colonna + spazio, cima, colonna, "Contenuto del documento",
            [("%d. %s" % (indice, titolo), None)
             for indice, titolo in enumerate(self.sezioni_dichiarate, start=1)])
        fine = min(fine_riferimenti, fine_indice)

        if nota and colonne == 3:
            self._nota(nota, x=MARGINE + 2 * (colonna + spazio), larghezza=colonna,
                       cima=cima)
        elif nota:
            self.y = fine - 18
            self._nota(nota)
            fine = self.y
        self.y = min(fine, self.y) - 18
        self._pie(frontespizio=True)

    def _riferimenti_predefiniti(self) -> list:
        return [
            ("Applicazione", "%s - %s" % (PRODOTTO, SOTTOTITOLO_PRODOTTO)),
            ("Tenant", self.tenant),
            ("Intervallo", self.intervallo),
            ("Generato il", self.generato),
        ]

    def _tavola_frontespizio(self, x, y, larghezza, titolo, righe) -> float:
        """Tavola a due colonne con testatina colorata. Restituisce la quota finale."""
        c = self.c
        c.setFillColor(self.tema["banda"])
        c.rect(x, y - 14, larghezza, 14, stroke=0, fill=1)
        c.setFillColor(BIANCO)
        c.setFont(self.font["titolo"], 8.5)
        c.drawString(x + 6, y - 10.5, titolo)

        quota = y - 14
        for indice, (etichetta, valore) in enumerate(righe):
            righe_etichetta = simpleSplit(str(etichetta), self.font["corpo"], 8,
                                          (larghezza * .48 if valore is not None
                                           else larghezza - 12))
            righe_valore = simpleSplit(str(valore), self.font["corpo_grassetto"], 8,
                                       larghezza * .48) if valore is not None else []
            alta = max(len(righe_etichetta), len(righe_valore), 1) * 10 + 6
            if indice % 2 == 0:
                c.setFillColor(FONDO)
                c.rect(x, quota - alta, larghezza, alta, stroke=0, fill=1)
            c.setStrokeColor(LINEA)
            c.setLineWidth(.3)
            c.line(x, quota - alta, x + larghezza, quota - alta)

            c.setFont(self.font["corpo"], 8)
            c.setFillColor(INCHIOSTRO_2)
            for numero, riga in enumerate(righe_etichetta):
                c.drawString(x + 6, quota - 12 - numero * 10, riga)
            c.setFont(self.font["corpo_grassetto"], 8)
            c.setFillColor(INCHIOSTRO)
            for numero, riga in enumerate(righe_valore):
                c.drawString(x + larghezza * .5, quota - 12 - numero * 10, riga)
            quota -= alta
        c.setStrokeColor(LINEA)
        c.setLineWidth(.5)
        c.rect(x, quota, larghezza, y - quota, stroke=1, fill=0)
        return quota

    def _nota(self, testo, x=None, larghezza=None, cima=None):
        """Riquadro della provenienza dei dati: da dove vengono i numeri.

        Senza argomenti occupa la larghezza utile a partire dalla quota corrente (uso
        verticale); con `x`, `larghezza` e `cima` diventa la terza colonna del
        frontespizio orizzontale.
        """
        c = self.c
        colonna = larghezza is not None
        x = MARGINE if x is None else x
        larghezza = (self.larghezza - 2 * MARGINE) if larghezza is None else larghezza
        cima = self.y if cima is None else cima
        righe = simpleSplit(testo, self.font["corpo"], 8, larghezza - 20)
        alta = len(righe) * 11 + 12
        base = cima - alta
        c.setFillColor(self.tema["chiaro"])
        c.rect(x, base, larghezza, alta, stroke=0, fill=1)
        c.setFillColor(self.tema["accento"])
        c.rect(x, base, 3, alta, stroke=0, fill=1)
        c.setFillColor(INCHIOSTRO_2)
        c.setFont(self.font["corpo"], 8)
        for numero, riga in enumerate(righe):
            c.drawString(x + 12, cima - 14 - numero * 11, riga)
        if not colonna:
            self.y = base - 14

    # ------------------------------------------------------------------ #
    # Cornice delle pagine di contenuto
    # ------------------------------------------------------------------ #
    def _nuova_pagina(self):
        self.c.showPage()
        self.pagina += 1
        self.y = self.altezza - MARGINE
        self._testatina()
        self._pie()

    def _testatina(self):
        c = self.c
        alta = 26
        base = self.altezza - alta
        c.setFillColor(self.tema["banda"])
        c.rect(0, base, self.larghezza, alta, stroke=0, fill=1)
        self._marchio(MARGINE + 6, base + 13, scala=.42)
        c.setFillColor(BIANCO)
        c.setFont(self.font["titolo"], 10)
        c.drawString(MARGINE + 20, base + 9, MARCHIO)
        c.setFont(self.font["sottotitolo"], 9)
        c.setFillColor(Color(1, 1, 1, alpha=.78))
        c.drawString(MARGINE + 20 + pdfmetrics.stringWidth(MARCHIO, self.font["titolo"],
                                                           10) + 8,
                     base + 9, self.titolo)
        c.setFont(self.font["corpo"], 8)
        c.drawRightString(self.larghezza - MARGINE, base + 9,
                          "%s · %s" % (self.tenant, self.generato))
        c.setFillColor(self.tema["accento"])
        c.rect(0, base - 2.5, self.larghezza, 2.5, stroke=0, fill=1)
        self.y = base - 22

    def _pie(self, frontespizio=False):
        c = self.c
        c.setStrokeColor(LINEA)
        c.setLineWidth(.5)
        c.line(MARGINE, MARGINE + 18, self.larghezza - MARGINE, MARGINE + 18)
        c.setFont(self.font["corpo_grassetto"], 7.5)
        c.setFillColor(INCHIOSTRO_2)
        c.drawString(MARGINE, MARGINE + 8, "© 2024-26 DS Consulting")
        c.setFont(self.font["corpo"], 7)
        c.setFillColor(INCHIOSTRO_3)
        c.drawString(MARGINE, MARGINE - 1,
                     "Documento riservato: contiene informazioni sulla rete del tenant.")
        nota = "%s%s" % (PRODOTTO, "" if self.font["completo"]
                         else " · PT Sans Narrow non disponibile, reso in Helvetica")
        c.drawRightString(self.larghezza - MARGINE, MARGINE + 8, nota)
        c.drawRightString(self.larghezza - MARGINE, MARGINE - 1,
                          "frontespizio" if frontespizio else "pagina %d" % self.pagina)

    def spazio(self, quanto):
        """Riserva spazio verticale; cambia pagina se non ce n'e' piu'."""
        if self.y - quanto < MARGINE + 34:
            self._nuova_pagina()
            return True
        return False

    # ------------------------------------------------------------------ #
    # Elementi
    # ------------------------------------------------------------------ #
    def titolo_sezione(self, testo, nota=""):
        """Sezione numerata, con la barretta del colore del genere."""
        self.spazio(46)
        self.numero_sezione += 1
        c = self.c
        c.setFillColor(self.tema["accento"])
        c.rect(MARGINE, self.y - 3, 3.5, 16, stroke=0, fill=1)
        c.setFont(self.font["titolo"], 13)
        c.setFillColor(INCHIOSTRO)
        c.drawString(MARGINE + 10, self.y, "%d. %s" % (self.numero_sezione, testo))
        if nota:
            c.setFont(self.font["corpo"], 8)
            c.setFillColor(INCHIOSTRO_3)
            c.drawRightString(self.larghezza - MARGINE, self.y + 1, nota)
        self.y -= 10
        c.setStrokeColor(LINEA)
        c.setLineWidth(.7)
        c.line(MARGINE, self.y, self.larghezza - MARGINE, self.y)
        self.y -= 14

    def paragrafo(self, testo, colore=None, dimensione=CORPO, mono=False):
        c = self.c
        font = self.font["mono"] if mono else self.font["corpo"]
        larghezza_utile = self.larghezza - 2 * MARGINE
        for riga in simpleSplit(testo, font, dimensione, larghezza_utile):
            self.spazio(INTERLINEA)
            c.setFont(font, dimensione)
            c.setFillColor(colore or INCHIOSTRO_2)
            c.drawString(MARGINE, self.y, riga)
            self.y -= INTERLINEA
        self.y -= 2

    def elenco(self, voci, colore=None):
        for voce in voci:
            self.spazio(INTERLINEA)
            self.c.setFillColor(self.tema["accento"])
            self.c.setFont(self.font["corpo"], CORPO)
            self.c.drawString(MARGINE + 6, self.y, "•")
            for indice, riga in enumerate(simpleSplit(
                    voce, self.font["corpo"], CORPO, self.larghezza - 2 * MARGINE - 18)):
                if indice:
                    self.spazio(INTERLINEA)
                self.c.setFont(self.font["corpo"], CORPO)
                self.c.setFillColor(colore or INCHIOSTRO_2)
                self.c.drawString(MARGINE + 16, self.y, riga)
                self.y -= INTERLINEA
        self.y -= 2

    def riquadri(self, voci):
        """Fascia di indicatori: valore grande, etichetta piccola, come sul cruscotto."""
        self.spazio(52)
        c = self.c
        quanti = max(1, len(voci))
        larghezza = (self.larghezza - 2 * MARGINE) / quanti
        alto = 44
        base = self.y - alto
        c.setFillColor(self.tema["chiaro"])
        c.rect(MARGINE, base, self.larghezza - 2 * MARGINE, alto, stroke=0, fill=1)
        for indice, (valore, etichetta, colore) in enumerate(voci):
            x = MARGINE + indice * larghezza
            if indice:
                c.setStrokeColor(BIANCO)
                c.setLineWidth(1)
                c.line(x, base + 6, x, base + alto - 6)
            testo = str(valore)
            dimensione = 19 if len(testo) <= 7 else (15 if len(testo) <= 12 else 11)
            c.setFillColor(colore or self.tema["accento"])
            c.setFont(self.font["titolo"], dimensione)
            c.drawCentredString(x + larghezza / 2, base + alto - 24, testo)
            c.setFillColor(INCHIOSTRO_3)
            c.setFont(self.font["corpo"], 7)
            for numero, riga in enumerate(simpleSplit(etichetta, self.font["corpo"], 7,
                                                     larghezza - 10)[:2]):
                c.drawCentredString(x + larghezza / 2, base + 12 - numero * 8, riga)
        self.y = base - 18

    # Spazio fra due colonne affiancate: meno di questo e le due tabelle sembrano
    # una sola con le colonne sbagliate.
    GRONDA = 14

    # Corpi tipografici delle tabelle. Il corpo delle celle puo' scendere di qualche
    # decimo per far entrare una colonna intera: un numero un po' piu' piccolo si
    # legge, un indirizzo tagliato no.
    CORPO_CELLA = 8
    CORPO_CELLA_MINIMO = 6.6
    CORPO_TESTATA = 7.5
    CORPO_TESTATA_MINIMO = 5.8
    RIENTRO = 8          # respiro ai due lati della cella
    PUNTINI = "..."      # cio' che dichiara un valore abbreviato
    # Righe per cella quando una tabella non entra. Ogni riga usa solo le linee che le
    # servono, quindi il tetto costa nulla alle righe brevi: cinque bastano a un URL in
    # una colonna stretta, che era l'ultimo valore che restava abbreviato sul campo.
    MAX_RIGHE_CELLA = 5

    def _font_cella(self, indice: int) -> str:
        """Indirizzi e porte in monospazio (prima colonna), il resto nel corpo."""
        return self.font["mono"] if indice == 0 else self.font["corpo"]

    @staticmethod
    def _cella(valore):
        """Colore e testo di una cella, letti i marcatori di gravita' (`!!`, `!`, `+`)."""
        testo = "" if valore is None else str(valore)
        if testo.startswith("!!"):
            return CRITICO, testo[2:].strip()
        if testo.startswith("!"):
            return ATTENZIONE, testo[1:].strip()
        if testo.startswith("+"):
            return OK, testo[1:].strip()
        return INCHIOSTRO_2, testo

    def _entra(self, testo, font, corpo, disponibile):
        """Testo adattato allo spazio, con i puntini quando si e' dovuto abbreviare.

        Il taglio deve VEDERSI: `10.10.14` al posto di `10.10.140.0/24` e' un dato
        falso, `10.10.14...` e' un dato abbreviato. Fra le due cose passa la differenza
        fra un errore e una nota, e questi documenti finiscono in mano al cliente.
        """
        if not testo or pdfmetrics.stringWidth(testo, font, corpo) <= disponibile:
            return testo, False
        coda = pdfmetrics.stringWidth(self.PUNTINI, font, corpo)
        ridotto = testo
        while ridotto and (pdfmetrics.stringWidth(ridotto, font, corpo)
                           + coda) > disponibile:
            ridotto = ridotto[:-1]
        return (ridotto + self.PUNTINI) if ridotto else "", True

    def _misura_colonne(self, intestazioni, righe, pesi, allineamento, utile):
        """Larghezze ricavate dal contenuto; i pesi distribuiscono solo l'avanzo.

        Restituisce `(larghezze, corpo, abbreviata)`. I pesi dichiarati dal chiamante
        NON sono un vincolo: una colonna larga il 15% di mezza pagina tagliava le
        subnet. Sono un'indicazione di dove mettere lo spazio che avanza -- e' il
        contenuto a decidere il minimo.

        Se il necessario non entra, la stretta la pagano le colonne che sforano il
        proprio titolo (tipicamente le descrizioni), non quelle il cui contenuto e'
        piu' corto dell'intestazione; e ogni colonna resta larga almeno quanto il
        proprio titolo al corpo minimo, cosi' due intestazioni non si sovrappongono
        mai piu'.
        """
        quante = len(intestazioni)
        titoli = [pdfmetrics.stringWidth((titolo or "").upper(), self.font["titolo"],
                                         self.CORPO_TESTATA_MINIMO) + self.RIENTRO
                  for titolo in intestazioni]

        # Il contenuto piu' lungo di ogni colonna, misurato una volta sola al corpo
        # pieno: la larghezza di un testo e' proporzionale al corpo, quindi per gli
        # altri corpi basta una proporzione -- su un elenco di tremila dispositivi
        # rimisurare tutto a ogni tentativo sarebbe tempo buttato.
        contenuti = [0.0] * quante
        for riga in righe:
            for indice in range(min(quante, len(riga))):
                _, testo = self._cella(riga[indice])
                if not testo:
                    continue
                larga = pdfmetrics.stringWidth(testo, self._font_cella(indice),
                                               self.CORPO_CELLA)
                if larga > contenuti[indice]:
                    contenuti[indice] = larga

        def necessarie_a(corpo):
            fattore = corpo / self.CORPO_CELLA
            return [max(titoli[i], contenuti[i] * fattore + self.RIENTRO)
                    for i in range(quante)]

        # Il corpo si riduce SOLO se la riduzione fa entrare la tabella intera. Una
        # colonna di testo libero non ha un limite di lunghezza: rimpicciolire tutte le
        # cifre per una sola descrizione lunga peggiorerebbe il documento senza
        # risolvere niente.
        corpo = self.CORPO_CELLA
        necessarie = necessarie_a(corpo)
        while sum(necessarie) > utile and corpo > self.CORPO_CELLA_MINIMO:
            corpo = round(corpo - .2, 2)
            necessarie = necessarie_a(corpo)
        if sum(necessarie) > utile:
            corpo = self.CORPO_CELLA
            necessarie = necessarie_a(corpo)

        avanzo = utile - sum(necessarie)
        if avanzo >= 0:
            somma_pesi = sum(pesi) or 1.0
            larghezze = [necessarie[i] + avanzo * pesi[i] / somma_pesi
                         for i in range(quante)]
            return larghezze, corpo, False

        # Non entra nemmeno al corpo minimo: qualcuno deve cedere, e conta l'ordine.
        # Cedono per prime le descrizioni: una descrizione abbreviata resta
        # riconoscibile, un indirizzo abbreviato diventa un altro indirizzo. La prima
        # colonna -- l'identita' della riga -- cede per ultima e solo se non c'e' altro
        # modo di stare nella pagina.
        deficit = -avanzo
        larghezze = list(necessarie)
        # Fin dove una colonna puo' stringersi: il proprio titolo, oppure la larghezza
        # che le basta per contenere il proprio valore piu' lungo andando a capo. Il
        # secondo termine e' la ragione per cui un indirizzo lungo non viene piu'
        # abbreviato: la colonna resta larga abbastanza da mandarlo a capo per intero.
        minimi = [max(titoli[i],
                      min(necessarie[i],
                          (necessarie[i] - self.RIENTRO) * 1.15 / self.MAX_RIGHE_CELLA
                          + self.RIENTRO))
                  for i in range(quante)]
        ordine_di_cessione = (
            [i for i in range(1, quante) if allineamento[i] != "r"],
            [i for i in range(1, quante) if allineamento[i] == "r"],
            [0],
        )
        for gruppo in ordine_di_cessione:
            if deficit <= 0:
                break
            deficit = self._livella(larghezze, gruppo, minimi, deficit)
        if deficit > 0:
            # Non entrano nemmeno i soli titoli: si comprime tutto in proporzione, e le
            # intestazioni verranno abbreviate con i puntini come le celle.
            fattore = utile / sum(larghezze)
            larghezze = [larga * fattore for larga in larghezze]
        return larghezze, corpo, True

    @staticmethod
    def _livella(larghezze, gruppo, minimi, deficit):
        """Ricava `deficit` punti dalle colonne del gruppo, dalle piu' larghe.

        Come l'acqua in vasi comunicanti: si cerca un livello comune e si abbassano a
        quel livello solo le colonne che lo superano; chi sta sotto non viene toccato.
        La ripartizione proporzionale, provata prima, faceva perdere due lettere anche
        a una colonna che conteneva "attivo" mentre accanto restava un indirizzo HTTP
        di settanta caratteri.

        Restituisce il deficit che resta da recuperare altrove.
        """
        cedibile = sum(max(0.0, larghezze[i] - minimi[i]) for i in gruppo)
        if cedibile <= 0:
            return deficit
        stretta = min(deficit, cedibile)
        obiettivo = sum(larghezze[i] for i in gruppo) - stretta

        def totale_al_livello(livello):
            return sum(min(larghezze[i], max(minimi[i], livello)) for i in gruppo)

        basso, alto = 0.0, max(larghezze[i] for i in gruppo)
        for _ in range(40):  # 40 dimezzamenti: precisione molto sotto il punto
            mezzo = (basso + alto) / 2
            if totale_al_livello(mezzo) > obiettivo:
                alto = mezzo
            else:
                basso = mezzo
        livello = (basso + alto) / 2
        for indice in gruppo:
            larghezze[indice] = min(larghezze[indice], max(minimi[indice], livello))
        return deficit - stretta

    def _testata_colonne(self, x, y, larghezza_totale, larghezze, intestazioni,
                         allineamento):
        """Testatina colorata con i titoli adattati alla propria colonna.

        Prima i titoli venivano scritti senza guardare lo spazio: due intestazioni
        vicine si sovrapponevano e si leggeva "DISPOSITIVIRISCONTRI APERTI".
        """
        c = self.c
        c.setFillColor(self.tema["banda"])
        c.rect(x, y - 4, larghezza_totale, 14, stroke=0, fill=1)
        c.setFillColor(BIANCO)
        cursore = x
        for indice, titolo in enumerate(intestazioni):
            testo = (titolo or "").upper()
            disponibile = larghezze[indice] - self.RIENTRO
            corpo = self.CORPO_TESTATA
            while (corpo > self.CORPO_TESTATA_MINIMO
                   and pdfmetrics.stringWidth(testo, self.font["titolo"],
                                              corpo) > disponibile):
                corpo = round(corpo - .1, 2)
            testo, _ = self._entra(testo, self.font["titolo"], corpo, disponibile)
            c.setFont(self.font["titolo"], corpo)
            if allineamento[indice] == "r":
                c.drawRightString(cursore + larghezze[indice] - 4, y, testo)
            else:
                c.drawString(cursore + 4, y, testo)
            cursore += larghezze[indice]

    def _righe_cella(self, testo, font, corpo, disponibile, massimo):
        """Il testo della cella spezzato in righe; l'ultima abbreviata se non basta.

        Con `massimo` a 1 e' il comportamento di sempre: una riga, abbreviata se serve.
        """
        if not testo:
            return [""], False
        if massimo <= 1:
            unica, tagliato = self._entra(testo, font, corpo, disponibile)
            return [unica], tagliato
        pezzi = simpleSplit(testo, font, corpo, max(disponibile, 1)) or [""]
        # Un URL o un identificativo lungo non ha spazi su cui andare a capo:
        # `simpleSplit` lo restituisce intero e sborderebbe nella colonna vicina.
        # Si spezza a forza -- e' cio' che fa qualunque browser con un indirizzo lungo.
        intere = []
        for pezzo in pezzi:
            intere.extend(self._spezza_a_forza(pezzo, font, corpo, disponibile))
        pezzi = intere or [""]
        if len(pezzi) <= massimo:
            return pezzi, False
        # Non basta nemmeno andando a capo: l'ultima riga raccoglie cio' che resta e
        # dichiara il taglio.
        tenute = list(pezzi[:massimo])
        tenute[-1], _ = self._entra(" ".join(pezzi[massimo - 1:]), font, corpo,
                                    disponibile)
        return tenute, True

    def _spezza_a_forza(self, pezzo, font, corpo, disponibile):
        """Spezza una parola piu' larga della colonna, carattere per carattere."""
        if not pezzo or pdfmetrics.stringWidth(pezzo, font, corpo) <= disponibile:
            return [pezzo]
        fette, corrente = [], ""
        for carattere in pezzo:
            if (corrente
                    and pdfmetrics.stringWidth(corrente + carattere, font,
                                               corpo) > disponibile):
                fette.append(corrente)
                corrente = carattere
            else:
                corrente += carattere
        if corrente:
            fette.append(corrente)
        return fette

    def _celle_misurate(self, riga, larghezze, corpo, massimo):
        """Colore, font e righe di ogni cella, piu' l'altezza che serve alla riga."""
        celle = []
        abbreviata = False
        for indice in range(len(larghezze)):
            valore = riga[indice] if indice < len(riga) else None
            colore, testo = self._cella(valore)
            font = self._font_cella(indice)
            linee, tagliato = self._righe_cella(testo, font, corpo,
                                                larghezze[indice] - self.RIENTRO,
                                                massimo)
            abbreviata = abbreviata or tagliato
            celle.append((colore, font, linee))
        quante = max(len(linee) for _, _, linee in celle) if celle else 1
        altezza = INTERLINEA + (quante - 1) * (corpo + 2)
        return celle, altezza, abbreviata

    def _riga_tabella(self, x, y, riga, larghezze, allineamento, corpo,
                      massimo_righe=1, fondo=None, larghezza_banda=None):
        """Scrive una riga, anche su piu' linee; dice quanto e' alta e se ha abbreviato.

        La banda a righe alterne la disegna questa funzione, perche' e' l'unica che sa
        quanto e' alta la riga prima di scriverla.
        """
        c = self.c
        celle, altezza, abbreviata = self._celle_misurate(riga, larghezze, corpo,
                                                          massimo_righe)
        if fondo is not None and larghezza_banda:
            c.setFillColor(fondo)
            c.rect(x, y - 3 - (altezza - INTERLINEA), larghezza_banda, altezza,
                   stroke=0, fill=1)

        cursore = x
        for indice, (colore, font, linee) in enumerate(celle):
            c.setFont(font, corpo)
            c.setFillColor(colore)
            for numero, linea in enumerate(linee):
                quota = y - numero * (corpo + 2)
                if allineamento[indice] == "r":
                    c.drawRightString(cursore + larghezze[indice] - 4, quota, linea)
                else:
                    c.drawString(cursore + 4, quota, linea)
            cursore += larghezze[indice]
        return altezza, abbreviata

    def _blocco_tabella(self, x, larghezza_blocco, intestazioni, righe, pesi,
                        allineamento, righe_massime, larghezze_da=None):
        """Disegna una porzione di tabella a partire dall'origine indicata.

        Non impagina e non cambia pagina: e' il mattone con cui `tabella` costruisce
        sia la colonna unica sia le due affiancate. Restituisce quante righe ha
        disegnato, cosi' chi chiama sa da dove riprendere.
        """
        c = self.c
        # Le larghezze si misurano su TUTTE le righe della tabella (`larghezze_da`),
        # non solo su quelle di questo blocco: altrimenti la stessa colonna sarebbe
        # larga in modo diverso in cima e in fondo all'elenco.
        larghezze, corpo, abbreviata = self._misura_colonne(
            intestazioni, larghezze_da if larghezze_da is not None else righe,
            pesi, allineamento, larghezza_blocco)
        partenza = self.y

        self._testata_colonne(x, partenza, larghezza_blocco, larghezze, intestazioni,
                              allineamento)

        y = partenza - 15
        disegnate = 0
        alternata = False
        for riga in righe[:righe_massime]:
            # Le colonne affiancate restano a riga singola: l'altezza variabile
            # scombinerebbe l'allineamento fra i due blocchi. Una tabella che avrebbe
            # bisogno di andare a capo non arriva qui -- torna a colonna unica.
            _, tagliata = self._riga_tabella(
                x, y, riga, larghezze, allineamento, corpo,
                fondo=self.tema["chiaro"] if alternata else None,
                larghezza_banda=larghezza_blocco)
            alternata = not alternata
            abbreviata = abbreviata or tagliata
            y -= INTERLINEA
            disegnate += 1

        c.setStrokeColor(LINEA)
        c.setLineWidth(.5)
        c.line(x, y + 8, x + larghezza_blocco, y + 8)
        return disegnate, y, abbreviata

    def tabella(self, intestazioni, righe, larghezze=None, allineamento=None,
                nota_vuota="Nessun dato per questo intervallo.", colonne=1):
        """Tabella con testatina colorata, righe alternate e intestazione ripetuta.

        `colonne=2` affianca due blocchi della stessa tabella, come le pagine di un
        elenco telefonico: serve agli elenchi lunghi e STRETTI (indirizzi, porte,
        prodotti), dove a colonna unica meta' pagina resterebbe bianca e il documento
        sarebbe lungo il doppio. Una tabella larga resta a colonna unica, perche' su
        mezza pagina le sue colonne diventerebbero illeggibili.
        """
        if not righe:
            self.paragrafo(nota_vuota, INCHIOSTRO_3)
            return
        pesi = list(larghezze) if larghezze else [1.0] * len(intestazioni)
        allineamento = allineamento or ["l"] * len(intestazioni)

        utile = self.larghezza - 2 * MARGINE

        if colonne > 1:
            # Due blocchi affiancati stanno in piedi solo se a mezza pagina la tabella
            # entra ancora INTERA. Altrimenti si torna a colonna unica: un documento
            # piu' lungo si sfoglia, un elenco di subnet troncate non si usa.
            larghezza_blocco = (utile - self.GRONDA * (colonne - 1)) / colonne
            _, _, abbreviata = self._misura_colonne(
                intestazioni, righe, pesi, allineamento, larghezza_blocco)
            if not abbreviata:
                self._tabella_affiancata(intestazioni, righe, pesi, allineamento,
                                         colonne)
                return

        larghezze, corpo, abbreviata = self._misura_colonne(
            intestazioni, righe, pesi, allineamento, utile)

        def testa():
            self._testata_colonne(MARGINE, self.y, utile, larghezze, intestazioni,
                                  allineamento)
            self.y -= 15

        # Se le colonne non bastano, il testo va a capo invece di essere abbreviato: il
        # dato resta tutto e il documento diventa un po' piu' alto, che e' il prezzo
        # giusto. Le tabelle che entrano -- la grande maggioranza -- restano a riga
        # singola come prima.
        massimo_righe = self.MAX_RIGHE_CELLA if abbreviata else 1
        abbreviata = False

        self.spazio(44)
        testa()
        alternata = False
        for riga in righe:
            _, alta, _ = self._celle_misurate(riga, larghezze, corpo, massimo_righe)
            if self.spazio(alta + 2):
                testa()
                alternata = False
            _, tagliata = self._riga_tabella(
                MARGINE, self.y, riga, larghezze, allineamento, corpo,
                massimo_righe=massimo_righe,
                fondo=self.tema["chiaro"] if alternata else None,
                larghezza_banda=utile)
            alternata = not alternata
            abbreviata = abbreviata or tagliata
            self.y -= alta
        self.c.setStrokeColor(LINEA)
        self.c.setLineWidth(.5)
        self.c.line(MARGINE, self.y + 8, self.larghezza - MARGINE, self.y + 8)
        self.y -= 10
        if abbreviata:
            self._nota_abbreviazione()


    def _nota_abbreviazione(self):
        """Dice che qualche valore e' abbreviato, invece di lasciarlo indovinare.

        Succede solo quando un testo lungo non entra nemmeno a pagina piena: gli
        indirizzi e i codici non ci arrivano, perche' le colonne si misurano sul
        contenuto. Ma se accade, deve stare scritto sul documento -- chi lo legge non
        puo' distinguere da se' un valore abbreviato da un valore corto.
        """
        self.paragrafo("I valori piu' lunghi di quanto la colonna possa contenere sono"
                       " abbreviati con i puntini (...); il dato completo resta"
                       " nell'inventario della console.", INCHIOSTRO_3)

    def _tabella_affiancata(self, intestazioni, righe, pesi, allineamento, colonne):
        """Distribuisce le righe su piu' blocchi affiancati, pagina per pagina."""
        colonne = max(2, min(3, int(colonne)))
        utile = self.larghezza - 2 * MARGINE
        larghezza_blocco = (utile - self.GRONDA * (colonne - 1)) / colonne

        tutte = list(righe)
        abbreviata = False
        restanti = list(righe)
        while restanti:
            # Quante righe entrano in un blocco da qui al fondo della pagina. Meno di
            # sei non vale la pena: si va a pagina nuova, dove ne entrano tutte.
            self.spazio(60)
            disponibili = int((self.y - MARGINE - 26) / INTERLINEA)
            if disponibili < 6:
                self._nuova_pagina()
                disponibili = int((self.y - MARGINE - 26) / INTERLINEA)
            per_blocco = max(1, disponibili)

            partenza = self.y
            piu_basso = self.y
            for indice in range(colonne):
                if not restanti:
                    break
                self.y = partenza
                x = MARGINE + indice * (larghezza_blocco + self.GRONDA)
                disegnate, fine, tagliato = self._blocco_tabella(
                    x, larghezza_blocco, intestazioni, restanti, pesi, allineamento,
                    per_blocco, larghezze_da=tutte)
                restanti = restanti[disegnate:]
                piu_basso = min(piu_basso, fine)
                abbreviata = abbreviata or tagliato

            self.y = piu_basso - 10
            if restanti:
                self._nuova_pagina()
        if abbreviata:
            self._nota_abbreviazione()

    def spezzata(self, titolo, punti, unita="", altezza=90):
        """Grafico a spezzata con banda di riferimento e ultimo punto in evidenza.

        `punti` e' un elenco di coppie (etichetta, valore); un valore `None` interrompe
        la linea invece di essere disegnato come zero (RP-05).
        """
        valori = [v for _, v in punti if v is not None]
        if len(valori) < 2:
            self.paragrafo("%s: meno di due misure nell'intervallo, nessun andamento da"
                           " rappresentare." % titolo, INCHIOSTRO_3)
            return
        self.spazio(altezza + 34)
        c = self.c
        x0, y0 = MARGINE, self.y - altezza
        larghezza = self.larghezza - 2 * MARGINE

        c.setFont(self.font["titolo"], 9.5)
        c.setFillColor(INCHIOSTRO)
        c.drawString(x0, self.y - 2, titolo.upper())

        minimo, massimo = min(valori), max(valori)
        campo = (massimo - minimo) or 1.0
        passo = larghezza / max(1, len(punti) - 1)

        c.setFillColor(self.tema["chiaro"])
        c.rect(x0, y0, larghezza, altezza - 14, stroke=0, fill=1)
        c.setStrokeColor(LINEA)
        c.setLineWidth(.4)
        for quota in (0, .5, 1):
            y = y0 + quota * (altezza - 14)
            c.line(x0, y, x0 + larghezza, y)
        c.setFont(self.font["corpo"], 6.5)
        c.setFillColor(INCHIOSTRO_3)
        c.drawString(x0 + 2, y0 + altezza - 20, "%s %s" % (round(massimo, 1), unita))
        c.drawString(x0 + 2, y0 + 3, "%s %s" % (round(minimo, 1), unita))

        c.setStrokeColor(self.tema["accento"])
        c.setLineWidth(1.4)
        percorso = None
        for indice, (_, valore) in enumerate(punti):
            if valore is None:
                percorso = None
                continue
            x = x0 + indice * passo
            y = y0 + (valore - minimo) / campo * (altezza - 18)
            if percorso is None:
                percorso = (x, y)
                continue
            c.line(percorso[0], percorso[1], x, y)
            percorso = (x, y)
        if percorso is not None:
            c.setFillColor(self.tema["accento"])
            c.circle(percorso[0], percorso[1], 2.4, stroke=0, fill=1)

        c.setFont(self.font["corpo"], 6.5)
        c.setFillColor(INCHIOSTRO_3)
        c.drawString(x0, y0 - 9, str(punti[0][0]))
        c.drawRightString(x0 + larghezza, y0 - 9, str(punti[-1][0]))
        for indice, (etichetta, valore) in enumerate(punti):
            if valore is None:
                c.setFillColor(Color(.42, .51, .57, alpha=.6))
                c.drawCentredString(x0 + indice * passo, y0 + (altezza - 14) / 2,
                                    "non misurato")
        self.y = y0 - 24

    def salva(self):
        self.c.save()


# --------------------------------------------------------------------------- #
# Riferimenti comuni del frontespizio
# --------------------------------------------------------------------------- #
def istante_nel_fuso(valore, fuso: str = None, vuoto: str = "-") -> str:
    """Un istante UTC nel fuso indicato, per chi non ha (ancora) un foglio.

    I riferimenti di copertina si compongono nella stessa chiamata che crea il foglio:
    la' `foglio` non esiste ancora, e usarlo era un errore -- trovato dalle prove.
    """
    momento = to_tenant_time(valore, fuso or DEFAULT_TIMEZONE)
    return momento.strftime("%d/%m/%Y %H:%M") if momento else vuoto


def _istante_locale(dati: dict) -> str:
    """L'istante di generazione nel fuso dichiarato dal documento."""
    fuso = (dati.get("tenant") or {}).get("fuso") or DEFAULT_TIMEZONE
    momento = to_tenant_time(dati.get("generato_utc"), fuso)
    return momento.strftime("%d/%m/%Y %H:%M") if momento else "-"


def riferimenti_comuni(dati: dict, extra=()) -> list:
    """Tavola dei riferimenti: da dove vengono i numeri e a che cosa si riferiscono."""
    from flask import current_app

    from ..db import query

    try:
        versione = current_app.config.get("APP_VERSION", "")
        console = query("SELECT value FROM system_settings WHERE key = 'public_url'",
                        (), one=True)
        console = (console["value"] if console and console["value"]
                   else "non impostato (Amministrazione > Impostazioni Sistema)")
        sonde = query("SELECT COUNT(*) AS n FROM probes WHERE tenant_id = ?"
                      " AND revoked_at IS NULL", (dati["tenant"]["id"],), one=True)
        sonde = int(sonde["n"] or 0) if sonde else 0
    except Exception:  # noqa: BLE001 - i riferimenti non devono far cadere il report
        versione, console, sonde = "", "non disponibile", 0

    voci = [
        ("Applicazione", "%s - %s" % (PRODOTTO, SOTTOTITOLO_PRODOTTO)),
        ("Versione del server", versione or "non dichiarata"),
        # "Console" da solo non si capisce: chi legge il documento non sa che
        # indirizzo sia. E' l'indirizzo con cui si raggiunge questa installazione --
        # quello che serve per verificare i dati alla fonte.
        ("Indirizzo della console", console),
        ("Tenant", dati["tenant"]["nome"]),
        ("Intervallo", dati["intervallo"]),
        ("Fuso di riferimento", dati["tenant"]["fuso"]),
        ("Sonde registrate", sonde),
        # L'istante locale per chi legge, quello UTC per chi deve incrociarlo con un
        # registro: sono due usi diversi e servono entrambi. Qui non c'e' un foglio --
        # questa funzione compone i riferimenti prima che il documento esista -- quindi
        # la conversione si fa con il fuso dichiarato nei dati.
        ("Generato il", _istante_locale(dati)),
        ("Generato il (UTC)", dati["generato_utc"]),
    ]
    voci.extend(extra)
    return voci


NOTA_PROVENIENZA = (
    "Documento prodotto dai dati gia' raccolti dalle sonde e conservati sul server:"
    " nessuna scansione e' stata avviata per produrlo e nessuna sonda e' stata"
    " contattata. Gli intervalli sono calcolati nel fuso del tenant; un periodo senza"
    " esecuzioni e' dichiarato non misurato e non vale come zero."
)


def _percentuale(valore) -> str:
    return "non misurata" if valore is None else ("%.2f%%" % valore).replace(".", ",")


def _durata(minuti) -> str:
    if minuti is None:
        return "in corso"
    if minuti < 60:
        return "%d min" % minuti
    ore, resto = divmod(int(minuti), 60)
    return "%dh%02d" % (ore, resto)


# --------------------------------------------------------------------------- #
# R3 - Esercizio NOC
# --------------------------------------------------------------------------- #
SEZIONI_NOC = [
    "Indicatori del turno",
    "Da risolvere",
    "Disponibilita' dei servizi sorvegliati",
    "Finestre di indisponibilita'",
    "Incidenti",
    "Tendenze",
    "Raccolta: sonde, scansioni, conferimenti",
    "Variazioni dell'inventario",
    "Igiene: il cieco volontario",
    "Metodologia",
]


def noc_report(percorso, dati: dict, metodologia: dict = None) -> str:
    """Genera il report NOC. Restituisce il percorso del file prodotto."""
    disponibilita = dati["disponibilita"]
    incidenti = dati["incidenti"]
    inventario = dati["inventario"]
    quante = len(dati["da_risolvere"])
    metodologia = metodologia or {}

    foglio = Foglio(
        percorso, kind="noc", titolo="Esercizio NOC",
        sottotitolo="Passaggio di turno: che cosa si e' rotto, che cosa e' rientrato,"
                    " che cosa resta aperto",
        tenant=dati["tenant"]["nome"], intervallo=dati["intervallo"],
        generato=dati["generato_utc"], autore=metodologia.get("autore", ""),
        scopo=[
            "Riepilogo operativo dell'intervallo %s per il tenant %s."
            % (dati["intervallo"], dati["tenant"]["nome"]),
            "Serve a passare il turno: le questioni aperte stanno in testa, prima di"
            " qualunque totale, perche' chi legge ha trenta secondi.",
        ],
        sezioni=SEZIONI_NOC, riferimenti=riferimenti_comuni(dati),
        nota=NOTA_PROVENIENZA)

    foglio.riquadri([
        (inventario.get("nodi") or 0, "nodi in inventario", None),
        (_percentuale(disponibilita["percentuale"]), "riuscita dei controlli",
         OK if (disponibilita["percentuale"] or 0) >= 99 else ATTENZIONE),
        (disponibilita["esiti"], "esiti raccolti", None),
        ("%d / %d" % (incidenti["aperti"], incidenti["risolti"]),
         "incidenti aperti / risolti", CRITICO if incidenti["aperti"] else OK),
        (quante, "questioni da risolvere", CRITICO if quante else OK),
    ])

    foglio.titolo_sezione("Indicatori del turno", "in una riga")
    foglio.paragrafo(
        "%s nodi in inventario, %s esiti di controllo raccolti, riuscita %s, %d incidenti"
        " aperti e %d risolti, %d questioni ancora da risolvere."
        % (inventario.get("nodi") or 0, disponibilita["esiti"],
           _percentuale(disponibilita["percentuale"]), incidenti["aperti"],
           incidenti["risolti"], quante))

    # --- Da risolvere --- #
    foglio.titolo_sezione("Da risolvere", "in ordine di urgenza")
    if dati["da_risolvere"]:
        foglio.tabella(
            ["questione", "soggetto", "dettaglio"],
            [[("!!" if v["gravita"] == "critical" else "!") + v["titolo"],
              v.get("soggetto", ""), v.get("dettaglio", "")]
             for v in dati["da_risolvere"]],
            larghezze=[3, 2.4, 4.6])
    else:
        foglio.paragrafo("Nessuna questione aperta: nessun incidente, nessuna sonda muta,"
                         " nessuna scansione ferma, nessuna notifica non recapitata.", OK)

    # --- Disponibilita' --- #
    foglio.titolo_sezione("Disponibilita' dei servizi sorvegliati")
    if disponibilita["misurato"]:
        foglio.tabella(
            ["bersaglio", "genere", "esiti", "riusciti", "riuscita", "lat. media",
             "lat. max"],
            [[v["indirizzo"], v["genere"], v["esiti"], v["riusciti"],
              _percentuale(v["percentuale"]),
              "%s ms" % int(v["latenza_media"]) if v["latenza_media"] else "-",
              "%s ms" % int(v["latenza_massima"]) if v["latenza_massima"] else "-"]
             for v in disponibilita["controlli"]],
            larghezze=[3.4, 1.1, .8, .9, 1.2, 1.3, 1.3],
            allineamento=["l", "l", "r", "r", "r", "r", "r"])
    else:
        foglio.paragrafo("Nessuna esecuzione dei controlli nell'intervallo: la"
                         " disponibilita' non e' misurata. Non e' uno zero.", ATTENZIONE)

    # --- Indisponibilita' --- #
    foglio.titolo_sezione("Finestre di indisponibilita'", "le piu' lunghe")
    foglio.tabella(
        ["bersaglio", "controllo", "da", "a", "durata", "esiti", "dettaglio"],
        [[f["indirizzo"], f["nome"], f["da"], f["a"],
          _durata(f["durata_minuti"]) if not f["aperta"] else "in corso",
          f["esiti"], f["dettaglio"]] for f in dati["indisponibilita"]],
        larghezze=[2.2, 2.2, .7, .7, .9, .6, 3],
        nota_vuota="Nessuna finestra di indisponibilita': tutti gli esiti sono riusciti.")

    # --- Incidenti --- #
    foglio.titolo_sezione(
        "Incidenti",
        "durata media %s" % _durata(incidenti["durata_media_minuti"])
        if incidenti["durata_media_minuti"] is not None else "")
    foglio.tabella(
        ["#", "gravita'", "bersaglio", "controllo", "aperto", "risolto", "durata",
         "fallimenti", "operatore"],
        [[v["id"], v["gravita"], v["indirizzo"], v["controllo"], v["aperto"],
          v["risolto"] or "aperto", _durata(v["durata_minuti"]), v["fallimenti"],
          "attivato" if v["scalato"] else ("preso in carico" if v["preso_in_carico"]
                                           else "-")]
         for v in incidenti["voci"]],
        larghezze=[.5, .9, 2, 2, .8, .8, .9, .9, 1.2],
        nota_vuota="Nessun incidente aperto nell'intervallo.")

    # --- Tendenze --- #
    giorni = dati["tendenze"]["giorni"]
    foglio.titolo_sezione("Tendenze", "%d giorni" % len(giorni) if giorni else "")
    if giorni:
        foglio.spezzata("Riuscita dei controlli",
                        [(g["giorno"].strftime("%d/%m"), g["disponibilita"])
                         for g in giorni], unita="%")
        foglio.spezzata("Latenza al 95esimo percentile",
                        [(g["giorno"].strftime("%d/%m"), g["latenza_p95"])
                         for g in giorni], unita="ms")
    else:
        foglio.paragrafo("Nessuna misura nell'intervallo delle tendenze.", INCHIOSTRO_3)

    # --- Raccolta --- #
    raccolta = dati["raccolta"]
    foglio.titolo_sezione("Raccolta: sonde, scansioni, conferimenti")
    foglio.tabella(
        ["sonda", "stato", "ultimo contatto", "versione", "sforzo", "scansione"],
        [[s["nome"], s["stato"], s["ultimo_contatto"], s["versione"] or "-",
          s["sforzo"] or "-", "attiva" if s["scansione_attiva"] else "!sospesa"]
         for s in raccolta["sonde"]],
        larghezze=[2.4, 1, 1.4, 1, .8, 1],
        nota_vuota="Nessuna sonda registrata.")
    foglio.tabella(
        ["fase", "esito", "passate", "durata media", "host attivi", "host totali"],
        [[r["stage"], r["status"] if r["status"] == "completed" else "!" + r["status"],
          r["n"], "%s s" % r["secondi"], r["su"], r["totali"]]
         for r in raccolta["passate"]],
        larghezze=[1.2, 1.2, .8, 1.2, 1, 1],
        allineamento=["l", "l", "r", "r", "r", "r"],
        nota_vuota="Nessuna passata di scansione nell'intervallo.")
    foglio.paragrafo("Conferimenti: %s lotti, %s record, %s byte, %s rifiutati."
                     % (raccolta["lotti"].get("lotti", 0),
                        raccolta["lotti"].get("record", 0),
                        raccolta["lotti"].get("byte", 0),
                        raccolta["lotti"].get("rifiutati", 0)))

    # --- Variazioni --- #
    variazioni = dati["variazioni"]
    base = dati["rilevamento_base"]
    foglio.titolo_sezione("Variazioni dell'inventario",
                          "rilevamento di base, giorno %d di %d"
                          % (base["giorno"], base["di"]) if base["attivo"] else "")
    if base["attivo"]:
        foglio.paragrafo("Rilevamento di base in corso: le variazioni si contano ma non"
                         " si elencano, perche' il primo censimento produce una"
                         " variazione per ogni nodo e per ogni porta trovata.",
                         ATTENZIONE)
    foglio.tabella(
        ["genere", "eventi", "nodi", "presentazione"],
        [[change_label(g["genere"]), g["eventi"], g["nodi"],
          "fatto aggregato (oltre un quinto della rete)" if g["aggregato"]
          else "elencabile"] for g in variazioni["generi"]],
        larghezze=[3, .8, .8, 4],
        allineamento=["l", "r", "r", "l"],
        nota_vuota="Nessuna variazione registrata nell'intervallo.")

    # --- Igiene --- #
    igiene = dati["igiene"]
    foglio.titolo_sezione("Igiene: il cieco volontario")
    voci = []
    if igiene["controlli_sospesi"]:
        voci.append("Controlli sospesi: %s"
                    % ", ".join("%s (%s)" % (v["name"], v["address"])
                                for v in igiene["controlli_sospesi"]))
    if igiene["bersagli_senza_controlli"]:
        voci.append("Bersagli senza controlli: %s"
                    % ", ".join(v["address"] for v in igiene["bersagli_senza_controlli"]))
    voci.append("Nodi non identificati: %s" % igiene["nodi_non_identificati"])
    voci.append("Porte sospette: %s" % igiene["porte_sospette"])
    voci.append("Conservazione dichiarata: %s giorni" % igiene["retention_giorni"])
    if inventario.get("occupazione") is not None:
        voci.append("Perimetro: %s subnet dichiarate, %s host teorici, %s nodi trovati"
                    " (occupazione %s%%)"
                    % (inventario.get("subnet_dichiarate"),
                       inventario.get("subnet_teorici"), inventario.get("nodi"),
                       inventario["occupazione"]))
    foglio.elenco(voci)

    # --- Metodologia --- #
    foglio.titolo_sezione("Metodologia", "SR-112")
    foglio.paragrafo(
        "I dati provengono dalle sonde installate nella rete del cliente: nessuna"
        " connessione entrante verso la rete sorvegliata. La disponibilita' e' calcolata"
        " sugli esiti dei controlli periodici definiti dall'operatore; le finestre di"
        " indisponibilita' sono serie consecutive di esiti non riusciti, chiuse dal"
        " primo esito riuscito successivo.")
    foglio.paragrafo(
        "Le finestre temporali sono calcolate nel fuso del tenant (%s) come intervalli"
        " chiusi a sinistra e aperti a destra. Un intervallo senza esecuzioni e'"
        " dichiarato non misurato e non viene rappresentato come valore nullo."
        % dati["tenant"]["fuso"])
    if metodologia.get("sonde"):
        foglio.paragrafo("Profili di scansione in vigore: %s." % metodologia["sonde"])
    foglio.paragrafo(
        "Documento prodotto automaticamente da %s %s. Riproducibile: la stessa richiesta"
        " sullo stesso intervallo produce gli stessi valori."
        % (PRODOTTO, metodologia.get("versione") or ""))

    foglio.salva()
    return str(percorso)
