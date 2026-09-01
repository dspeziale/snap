"""
snap - Test della normalizzazione delle date: un solo fuso per documento e per pagina.

Difetto trovato controllando: i PDF stampavano gli istanti **come stanno in banca
dati**, cioe' in UTC, tagliati a mano (`(x or "")[:16]`), mentre il frontespizio
dichiara "Fuso di riferimento: Europe/Rome". Non era un'ambiguita': era un errore di due
ore, e lo stesso evento risultava alle 13:10 sul documento e alle 15:10 nella console.

Le regole verificate qui:

* ogni istante mostrato -- console o PDF -- e' nel fuso del tenant;
* l'unico UTC ammesso e' quello **dichiarato come tale** ("Generato il (UTC)"), che
  serve a incrociare il documento con un registro;
* una DATA di calendario (inserimento nel KEV, scadenza per la correzione) non si
  converte: non ha un fuso, e convertirla la sposterebbe di un giorno;
* i renderer non tagliano piu' le date a mano: e' il taglio che nascondeva il difetto.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

RENDERER = ("render_pdf.py", "render_wide.py", "render_web_lettura.py")

CAMPI_ISTANTE = ("created_at", "updated_at", "last_seen_at", "first_seen_at",
                 "decided_at", "opened_at", "acknowledged_at", "escalated_at",
                 "resolved_at", "sent_at", "executed_at", "measured_at", "started_at",
                 "finished_at", "collected_at", "imported_at", "ultima_verifica",
                 "ultimo_aggiornamento", "quando", "accensione")


def _sorgente_report(nome: str) -> str:
    return (Path(__file__).resolve().parent.parent
            / "server/snapserver/reports" / nome).read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# I renderer non tagliano le date a mano
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("modulo", RENDERER)
def test_nessun_renderer_taglia_una_data_a_mano(modulo):
    """`(x or "")[:16]` prende i primi sedici caratteri di un istante UTC: e'
    presentazione fatta con le mani, e nasconde il fatto che il fuso non e' stato
    applicato. Le date passano da `foglio.istante` e `foglio.giorno`."""
    sorgente = _sorgente_report(modulo)

    colpevoli = []
    for numero, riga in enumerate(sorgente.splitlines(), 1):
        if not re.search(r"\[:(10|16|19)\]", riga):
            continue
        if any(campo in riga for campo in CAMPI_ISTANTE):
            colpevoli.append("%s:%d %s" % (modulo, numero, riga.strip()))

    assert not colpevoli, "date tagliate a mano:\n" + "\n".join(colpevoli)


def test_il_foglio_converte_nel_fuso_dichiarato(server_app, tmp_path):
    """Lo stesso istante, due fusi, due ore diverse: e' la prova che la conversione
    avviene e non e' un caso."""
    with server_app.app_context():
        from snapserver.reports.render_pdf import Foglio

        def foglio(fuso):
            return Foglio(tmp_path / ("prova-%s.pdf" % fuso.replace("/", "-")),
                          kind="wide", titolo="Prova", tenant="T",
                          intervallo="prova", generato="2026-08-31 13:23:11",
                          fuso=fuso)

        roma = foglio("Europe/Rome")
        londra = foglio("Europe/London")

        assert roma.istante("2026-08-31 13:23:11") == "31/08/2026 15:23"
        assert londra.istante("2026-08-31 13:23:11") == "31/08/2026 14:23"
        assert roma.giorno("2026-08-31 23:30:00") == "01/09/2026", (
            "a Roma quell'istante e' del giorno dopo: e' proprio il motivo per cui il"
            " fuso va applicato")
        assert roma.istante(None) == "-"
        assert roma.istante("", vuoto="mai") == "mai"


def test_la_riga_di_identificazione_e_in_ora_locale(server_app, tmp_path):
    """Compare su ogni pagina: era l'ultimo posto in cui restava un UTC non dichiarato."""
    with server_app.app_context():
        from snapserver.reports.render_pdf import Foglio

        foglio = Foglio(tmp_path / "identificazione.pdf", kind="wide", titolo="Prova",
                        tenant="T", intervallo="prova",
                        generato="2026-08-31 13:23:11", fuso="Europe/Rome")

    assert foglio.generato == "31/08/2026 15:23"
    assert foglio.generato_utc == "2026-08-31 13:23:11", (
        "l'istante UTC resta disponibile: serve a chi incrocia il documento con un"
        " registro")


# --------------------------------------------------------------------------- #
# Il documento prodotto
# --------------------------------------------------------------------------- #
def test_un_report_non_contiene_istanti_utc_non_dichiarati(server_app):
    """Nel documento l'unico ISO ammesso e' quello della riga che dice "(UTC)"."""
    pypdf = pytest.importorskip("pypdf")
    from datetime import date, timedelta

    with server_app.app_context():
        from snapserver.db import query
        from snapserver.reports import generate

        tenant = dict(query("SELECT * FROM tenants ORDER BY id", (), one=True))
        percorso = generate.generate("inventory", tenant,
                                     date.today() - timedelta(days=1))

    testo = "\n".join((p.extract_text() or "")
                      for p in pypdf.PdfReader(str(percorso)).pages)
    iso = re.findall(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}", testo)
    dichiarati = testo.count("Generato il (UTC)")

    assert len(iso) <= dichiarati, (
        "istanti UTC non dichiarati nel documento: %r" % iso[:5])
    assert "Fuso di riferimento" in testo, "il documento dichiara in che fuso scrive"


# --------------------------------------------------------------------------- #
# La console
# --------------------------------------------------------------------------- #
def test_nessun_modello_stampa_un_istante_senza_convertirlo():
    """Nella console la conversione passa dai filtri (`dt`, `dtz`, `ago`): un istante
    stampato senza filtro e' un'ora sbagliata mostrata all'operatore."""
    radice = Path(__file__).resolve().parent.parent / "server/snapserver/templates"

    colpevoli = []
    for modello in radice.rglob("*.html"):
        for numero, riga in enumerate(modello.read_text(encoding="utf-8").splitlines(), 1):
            for trovato in re.finditer(r"\{\{([^}]*)\}\}", riga):
                contenuto = trovato.group(1)
                if not any(campo in contenuto for campo in CAMPI_ISTANTE):
                    continue
                if re.search(r"\|\s*(dt|dtz|ago|d|giorno)\b", contenuto):
                    continue
                colpevoli.append("%s:%d %s" % (modello.name, numero, contenuto.strip()))

    assert not colpevoli, "istanti non convertiti nei modelli:\n" + "\n".join(colpevoli)


def test_una_data_di_calendario_non_si_converte(server_app):
    """Inserimento nel KEV e scadenza per la correzione sono date, non istanti: un
    fuso applicato a una data la sposta di un giorno."""
    with server_app.app_context():
        from snapserver.tenancy import fmt_giorno_semplice

        assert fmt_giorno_semplice("2025-01-15") == "15/01/2025"
        assert fmt_giorno_semplice("2025-01-15T23:50:00") == "15/01/2025"
        assert fmt_giorno_semplice("") == "-"
        # Cio' che non e' una data torna come testo, non come suo frammento.
        assert fmt_giorno_semplice("non una data") == "non una data"


def test_il_filtro_delle_date_e_registrato(server_app):
    assert "giorno" in server_app.jinja_env.filters
    assert "dtz" in server_app.jinja_env.filters
