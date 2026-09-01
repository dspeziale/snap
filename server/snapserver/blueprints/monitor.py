"""
snap server - Monitoraggio dei nodi: stato della rete e deriva.

Lo stato risponde alla domanda "cosa risponde adesso"; la deriva risponde a
"cosa e' cambiato", che in un inventario e' l'informazione piu' utile.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from flask import Blueprint, render_template, request

from ..inventory_queries import inventory_summary, monitor_overview, node_changes
from ..security import login_required
from ..tenancy import current_tenant_id

bp = Blueprint("monitor", __name__, url_prefix="/monitor")

# Generi di scostamento, con l'etichetta mostrata all'operatore.
CHANGE_LABELS = {
    "node.appeared": "Nodo comparso",
    "node.disappeared": "Nodo scomparso",
    "node.removed": "Nodo rimosso dall'inventario",
    "node.up": "Tornato raggiungibile",
    "node.down": "Non raggiungibile",
    "port.opened": "Porta aperta",
    "port.closed": "Porta chiusa",
    "service.changed": "Servizio cambiato",
    "os.changed": "Sistema operativo cambiato",
    "device_type.changed": "Tipo di dispositivo cambiato",
    "hostname.changed": "Nome host cambiato",
    "mac.changed": "Indirizzo MAC cambiato",
}


@bp.get("/")
@login_required
def status():
    tenant_id = current_tenant_id()
    nodi = monitor_overview(tenant_id)
    return render_template(
        "monitor/status.html",
        nodes=nodi,
        summary=inventory_summary(tenant_id),
    )


@bp.get("/changes")
@login_required
def changes():
    tenant_id = current_tenant_id()
    gravita = request.args.get("severity") or None
    return render_template(
        "monitor/changes.html",
        changes=node_changes(tenant_id, limit=500, severity=gravita),
        summary=inventory_summary(tenant_id),
        labels=CHANGE_LABELS,
        selected_severity=gravita or "",
    )
