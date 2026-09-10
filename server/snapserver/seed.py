"""
snap server - Dati iniziali (bootstrap).

Crea l'amministratore di sistema e il tenant iniziale con le proprie utenze. Il
comando e' idempotente: le entita' gia' presenti non vengono duplicate ne'
modificate.

UN SOLO TENANT, e la ragione va scritta perche' qui ce n'erano due. Il secondo
("ACME International") serviva a dimostrare l'isolamento multi-tenant e la
normalizzazione oraria, ma quella e' una necessita' dei TEST, non
dell'installazione: in esercizio compariva nel selettore dei tenant di ogni
amministratore di sistema, e un tenant finto in un elenco vero e' una cosa che
qualcuno prima o poi apre. I test che hanno bisogno di due tenant se lo creano
(vedi tests/test_multitenancy.py), cosi' la prova non dipende da quali dati
dimostrativi il prodotto decide di creare.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from flask import current_app

from .db import execute, query, utc_now_str
from .security import (
    ROLE_ANALYST,
    ROLE_SUPERADMIN,
    ROLE_TENANT_ADMIN,
    ROLE_VIEWER,
    hash_password,
)

# Il tenant iniziale. Il nome della costante resta al plurale perche' l'elenco resta
# un elenco: un'installazione che nasce con piu' organizzazioni le dichiara qui.
DEMO_TENANTS = [
    {
        "code": "ised",
        "name": "ISED S.p.a.",
        "timezone": "Europe/Rome",
        "contact_email": "security@ised.local",
        "users": [
            ("admin@ised.local", "Amministratore ISED", ROLE_TENANT_ADMIN),
            ("analista@ised.local", "Analista Sicurezza", ROLE_ANALYST),
            ("audit@ised.local", "Revisore Interno", ROLE_VIEWER),
        ],
    },
]

DEMO_PASSWORD = "Snap!Tenant2026"


def seed_initial_data() -> list[str]:
    """Popola i dati iniziali e restituisce il riepilogo delle operazioni."""
    messages: list[str] = []
    now = utc_now_str()
    # Le zone di rete seguono il tenant: si seminano in fondo, quando i tenant di
    # questa funzione esistono (vedi _semina_zone_dei_tenant).

    admin_email = current_app.config["BOOTSTRAP_ADMIN_EMAIL"].strip().lower()
    admin_password = current_app.config["BOOTSTRAP_ADMIN_PASSWORD"]
    existing = query("SELECT id FROM users WHERE lower(email) = ?", (admin_email,), one=True)
    if existing is None:
        execute(
            "INSERT INTO users (tenant_id, email, password_hash, full_name, role, is_active,"
            " created_at, updated_at) VALUES (NULL, ?, ?, ?, ?, 1, ?, ?)",
            (
                admin_email,
                hash_password(admin_password),
                "Amministratore di Sistema",
                ROLE_SUPERADMIN,
                now,
                now,
            ),
        )
        messages.append("Amministratore di sistema creato: %s / %s" % (admin_email, admin_password))
    else:
        messages.append("Amministratore di sistema gia' presente: %s" % admin_email)

    for definition in DEMO_TENANTS:
        tenant = query("SELECT * FROM tenants WHERE code = ?", (definition["code"],), one=True)
        if tenant is None:
            tenant_id = execute(
                "INSERT INTO tenants (code, name, timezone, locale, contact_email,"
                " retention_days, is_active, notes, created_at, updated_at)"
                " VALUES (?, ?, ?, 'it_IT', ?, 365, 1, ?, ?, ?)",
                (
                    definition["code"],
                    definition["name"],
                    definition["timezone"],
                    definition["contact_email"],
                    "Tenant creato dal bootstrap iniziale.",
                    now,
                    now,
                ),
            )
            messages.append(
                "Tenant %s creato (fuso orario %s)" % (definition["code"], definition["timezone"])
            )
        else:
            tenant_id = int(tenant["id"])
            messages.append("Tenant %s gia' presente" % definition["code"])

        for email, full_name, role in definition["users"]:
            if query("SELECT id FROM users WHERE lower(email) = ?", (email,), one=True) is None:
                execute(
                    "INSERT INTO users (tenant_id, email, password_hash, full_name, role,"
                    " is_active, must_change_pwd, created_at, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, 1, 1, ?, ?)",
                    (tenant_id, email, hash_password(DEMO_PASSWORD), full_name, role, now, now),
                )
                messages.append("Utente %s creato (%s) / %s" % (email, role, DEMO_PASSWORD))

        # Le zone di rete sono un dato del tenant: senza di esse il catalogo
        # ripiegherebbe sul seme in memoria, e le zone sarebbero leggibili ma non
        # modificabili -- la peggiore delle due condizioni, perche' sembra funzionare.
        from .zone_admin import semina_se_serve

        quante = semina_se_serve(tenant_id)
        if quante:
            messages.append("Zone di rete iniziali create per %s (%d)"
                            % (definition["code"], quante))

        # Le regole di rilevazione SIEM sono anch'esse un dato del tenant.
        from .siem.seed import semina_se_serve as semina_regole_siem

        if semina_regole_siem(tenant_id):
            messages.append("Regole SIEM iniziali create per %s" % definition["code"])

    return messages
