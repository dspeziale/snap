"""
snap server - Registro di audit.

Ogni evento rilevante per la sicurezza o per la tracciabilita' operativa viene
registrato con tenant, attore, tipo evento e severita'. Il registro e' la fonte
per la sezione "Audit & Eventi".

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from flask import g, has_request_context, request

from .db import execute, utc_now_str

SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"


def log_event(
    event_type: str,
    description: str = "",
    tenant_id: int | None = None,
    severity: str = SEVERITY_INFO,
    entity: str | None = None,
    entity_id: str | int | None = None,
    actor: str | None = None,
    global_event: bool = False,
    created_at: str | None = None,
) -> int:
    """Registra un evento di audit.

    `global_event` registra la traccia senza tenant: serve per gli eventi che
    sopravvivono alla cancellazione del tenant stesso (la FK e' in cascata).

    `created_at` permette al chiamante di dichiarare l'istante dell'evento. Serve
    ai dati conferiti da una sonda che ha lavorato isolata: i record raccolti in
    momenti diversi devono conservare la propria cronologia, non assumere l'ora
    del conferimento.
    """
    user = getattr(g, "user", None) if has_request_context() else None
    tenant = getattr(g, "tenant", None) if has_request_context() else None

    if global_event:
        tenant_id = None
    elif tenant_id is None and tenant is not None:
        tenant_id = int(tenant["id"])
    if actor is None:
        actor = user["email"] if user is not None else "system"

    source_ip = None
    if has_request_context():
        source_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    return execute(
        "INSERT INTO audit_events (tenant_id, user_id, actor, event_type, severity,"
        " entity, entity_id, description, source_ip, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            tenant_id,
            int(user["id"]) if user is not None else None,
            actor,
            event_type,
            severity,
            entity,
            str(entity_id) if entity_id is not None else None,
            description,
            source_ip,
            created_at or utc_now_str(),
        ),
    )
