"""
snap server - Dashboard di controllo.

Riunisce lo stato delle sonde del tenant corrente: riquadri di sintesi, area
indicatori operativi, stato della flotta, ultimi conferimenti ricevuti sul
canale cifrato e attivita' recente del registro eventi.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from flask import Blueprint, g, redirect, render_template, url_for

from ..db import days_ago_str, hours_ago_str, query, scalar
from ..inventory_queries import (
    device_type_distribution,
    inventory_indicators,
    inventory_summary,
    node_changes,
)
from ..checks_queries import (
    checks_summary,
    incidents as check_incidents,
    incidents_daily,
    results_hourly,
)
from ..queries import dashboard_indicators, probe_fleet, probe_summary, recent_audit
from ..tenancy import fmt_grafico
from ..security import login_required
from ..tenancy import current_tenant_id

bp = Blueprint("dashboard", __name__)


@bp.get("/")
@login_required
def index():
    if getattr(g, "tenant", None) is None:
        # Nessun tenant selezionabile: il superadmin deve prima crearne uno.
        return redirect(url_for("admin.tenants"))

    tenant_id = current_tenant_id()
    conferimenti = query(
        "SELECT b.*, p.name AS probe_name, p.code AS probe_code FROM ingest_batches b"
        " LEFT JOIN probes p ON p.id = b.probe_id AND p.tenant_id = b.tenant_id"
        " WHERE b.tenant_id = ? ORDER BY b.received_at DESC LIMIT 10",
        (tenant_id,),
    )
    # Andamenti: le etichette sono convertite nel fuso del tenant, come ogni data
    # mostrata. Un andamento letto con l'ora sbagliata porta a conclusioni sbagliate.
    orari = results_hourly(tenant_id)
    giornalieri = incidents_daily(tenant_id)
    consegne = query(
        "SELECT strftime('%Y-%m-%d %H:00:00', received_at) AS ora,"
        " COALESCE(SUM(record_count), 0) AS record FROM ingest_batches"
        " WHERE tenant_id = ? AND received_at >= ?"
        " GROUP BY ora ORDER BY ora", (tenant_id, hours_ago_str(24)))

    grafici = {
        "riuscita": [[fmt_grafico(v["hour"]), v["success_rate"]]
                     for v in orari if v["success_rate"] is not None],
        "falliti": [[fmt_grafico(v["hour"]), float(v["failed"])] for v in orari],
        "incidenti": [[v["day"], float(v["opened"])] for v in giornalieri],
        "record": [[fmt_grafico(r["ora"]), float(r["record"])] for r in consegne],
    }

    from .auth import _kpi_nascosti

    tutti_kpi = dashboard_indicators(tenant_id) + inventory_indicators(tenant_id)
    nascosti = set(_kpi_nascosti(g.user))

    return render_template(
        "dashboard/index.html",
        probes=probe_summary(tenant_id),
        checks=checks_summary(tenant_id),
        open_incidents=check_incidents(tenant_id, status="aperti", limit=8),
        charts=grafici,
        # Gli indicatori delle sonde e quelli dell'inventario condividono l'area
        # indicatori: il conferimento e cio' che ne deriva si leggono insieme.
        # Gli indicatori si filtrano QUI e non nel template: cosi' il conteggio
        # nella scheda dice quanti se ne vedono, e l'elenco per riattivarli sa
        # quali sono stati messi via.
        kpi=[voce for voce in tutti_kpi if voce["key"] not in nascosti],
        kpi_nascosti=[voce for voce in tutti_kpi if voce["key"] in nascosti],
        inventory=inventory_summary(tenant_id),
        distribution=device_type_distribution(tenant_id)[:8],
        changes=node_changes(tenant_id, limit=10),
        fleet=probe_fleet(tenant_id),
        batches=conferimenti,
        events=recent_audit(tenant_id, 10),
        records_24h=scalar(
            "SELECT COALESCE(SUM(record_count), 0) FROM ingest_batches"
            " WHERE tenant_id = ? AND received_at >= ?",
            (tenant_id, days_ago_str(1)),
        ),
        batches_24h=scalar(
            "SELECT COUNT(*) FROM ingest_batches WHERE tenant_id = ? AND received_at >= ?",
            (tenant_id, days_ago_str(1)),
        ),
        events_24h=scalar(
            "SELECT COUNT(*) FROM audit_events WHERE tenant_id = ? AND created_at >= ?",
            (tenant_id, days_ago_str(1)),
        ),
    )
