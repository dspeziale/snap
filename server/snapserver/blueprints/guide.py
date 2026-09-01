"""
snap server - Guida operativa, servita come documento a se'.

Perche' non e' una pagina come le altre: la guida si consulta ACCANTO a cio' che si
sta facendo, non al posto suo. La voce di menu la apre in una finestra propria, e la
pagina non porta il menu laterale -- sarebbe un secondo menu dentro una finestra che
serve a leggere -- ma un indice interno e una resa di stampa.

Perche' e' generata dall'applicazione e non un file allegato: cosi' riporta il nome e
la versione dell'installazione, e le sue tabelle usano gli stessi strumenti del resto
della console.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from flask import Blueprint, g, render_template

from ..security import login_required

bp = Blueprint("guide", __name__, url_prefix="/guida")

THEMES = ("light", "dark")
DEFAULT_THEME = "light"


def _theme() -> str:
    """Tema scelto dall'utente, come lo applica il layout ordinario.

    La guida si apre in una finestra propria e non passa dal layout: la preferenza
    va letta qui, altrimenti chi lavora in tema scuro riceverebbe un documento
    chiaro in faccia.
    """
    utente = getattr(g, "user", None)
    if utente is None:
        return DEFAULT_THEME
    try:
        scelto = str(utente["pref_theme"] or DEFAULT_THEME)
    except (KeyError, IndexError, TypeError):
        # Utenza senza la colonna delle preferenze: non e' un errore da propagare
        # a una pagina di documentazione.
        return DEFAULT_THEME
    return scelto if scelto in THEMES else DEFAULT_THEME


@bp.get("/")
@login_required
def index():
    """Guida della console."""
    return render_template("guide/index.html", theme=_theme())


@bp.get("/sonda")
@login_required
def probe_guide():
    """Guida della sonda, consultabile anche da qui.

    E' la stessa che la sonda mostra sulla propria interfaccia locale: chi governa
    le sonde dalla console deve poter leggere cosa succede in sede senza collegarsi
    alla macchina.
    """
    return render_template("guide/probe.html", theme=_theme())
