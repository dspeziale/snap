"""
snap server - Dashboard: il quadro d'insieme.

Riunisce su una pagina cio' che il prodotto ha raccolto in ogni sua area --
inventario, esposizione, vulnerabilita', certificati, vetusta', SMB, presenze,
flotta, attivita' -- preceduto da cio' che chiede un intervento adesso: gli
incidenti aperti. I numeri arrivano tutti aggregati da `board_queries.pannello`:
la pagina non legge nessun elenco per contarne le righe.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from flask import Blueprint, g, redirect, render_template, url_for

from ..inventory_queries import inventory_indicators
from ..checks_queries import checks_summary, incidents as check_incidents
from ..queries import dashboard_indicators
from ..security import login_required
from ..tenancy import current_tenant_id, fmt_grafico

bp = Blueprint("dashboard", __name__)


@bp.get("/")
@login_required
def index():
    if getattr(g, "tenant", None) is None:
        # Nessun tenant selezionabile: il superadmin deve prima crearne uno.
        return redirect(url_for("admin.tenants"))

    tenant_id = current_tenant_id()
    from .auth import _kpi_nascosti
    from ..board_queries import pannello

    # Gli indicatori si filtrano QUI e non nel template: cosi' il conteggio nella
    # scheda dice quanti se ne vedono, e l'elenco per riattivarli sa quali sono stati
    # messi via.
    tutti_kpi = dashboard_indicators(tenant_id) + inventory_indicators(tenant_id)
    nascosti = set(_kpi_nascosti(g.user))

    quadro = pannello(tenant_id)
    # Gli istanti delle serie arrivano in UTC: le etichette degli assi si convertono
    # QUI, dove si converte ogni altra data mostrata. Un andamento letto con l'ora
    # sbagliata porta a conclusioni sbagliate, e sulla stessa pagina il grafico e le
    # fasce direbbero due ore diverse per lo stesso momento.
    # Le serie dei controlli hanno lo stesso trattamento: a ore si convertono, a
    # giorni no.
    quadro["controlli"] = dict(
        quadro["controlli"],
        riuscita=[[fmt_grafico(i), v] for i, v in quadro["controlli"]["riuscita"]],
        falliti=[[fmt_grafico(i), v] for i, v in quadro["controlli"]["falliti"]],
    )
    A_ORE = ("record", "presenze")
    quadro["grafici"] = {
        nome: ([[fmt_grafico(istante), valore] for istante, valore in serie]
               if nome in A_ORE else serie)
        for nome, serie in quadro["grafici"].items()
    }

    return render_template(
        "dashboard/index.html",
        # Il quadro d'insieme: tutti gli indicatori aggregati, in una passata sola.
        board=quadro,
        # Cio' che chiede un intervento adesso, prima di qualunque numero.
        open_incidents=check_incidents(tenant_id, status="aperti", limit=8),
        checks=checks_summary(tenant_id),
        kpi=[voce for voce in tutti_kpi if voce["key"] not in nascosti],
        kpi_nascosti=[voce for voce in tutti_kpi if voce["key"] in nascosti],
    )
