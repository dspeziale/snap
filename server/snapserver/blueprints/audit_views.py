"""
snap server - Consultazione del registro di audit.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from flask import Blueprint, render_template, request

from ..db import paginate, query
from ..security import login_required
from ..tenancy import current_tenant_id

bp = Blueprint("audit", __name__, url_prefix="/audit")

SEVERITY_BADGES = {"info": "secondary", "warning": "warning", "critical": "danger"}


@bp.get("/")
@login_required
def index():
    tenant_id = current_tenant_id()
    severity = (request.args.get("severity") or "").strip()
    event_type = (request.args.get("type") or "").strip()
    search = (request.args.get("q") or "").strip()

    where = ["tenant_id = ?"]
    params: list = [tenant_id]
    if severity in SEVERITY_BADGES:
        where.append("severity = ?")
        params.append(severity)
    if event_type:
        where.append("event_type LIKE ?")
        params.append("%s%%" % event_type)
    if search:
        where.append("(description LIKE ? OR actor LIKE ?)")
        params.extend(["%%%s%%" % search] * 2)
    clause = " WHERE " + " AND ".join(where)

    page = paginate(
        "SELECT * FROM audit_events" + clause + " ORDER BY created_at DESC, id DESC",
        "SELECT COUNT(*) FROM audit_events" + clause,
        params,
        request.args.get("page", 1),
        1000,
    )
    families = query(
        "SELECT DISTINCT substr(event_type, 1, instr(event_type || '.', '.') - 1) AS family"
        " FROM audit_events WHERE tenant_id = ? ORDER BY family",
        (tenant_id,),
    )
    return render_template(
        "audit/index.html",
        page=page,
        badges=SEVERITY_BADGES,
        families=[row["family"] for row in families if row["family"]],
        filters={"severity": severity, "type": event_type, "q": search},
    )
