"""
snap - Test di isolamento multi-tenant, normalizzazione oraria e MFA.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pyotp


# IL SECONDO TENANT LO CREA IL TEST.
#
# I dati iniziali del prodotto creano un solo tenant, quello reale: un secondo tenant
# dimostrativo compariva nel selettore di ogni amministratore di sistema in esercizio,
# e un tenant finto in un elenco vero e' una cosa che qualcuno prima o poi apre.
# Dimostrare l'isolamento e la normalizzazione oraria e' una necessita' di QUESTI test,
# e un test che ha bisogno di due tenant se lo costruisce: cosi' la prova non dipende
# da quali dati dimostrativi il prodotto decide di creare.
#
# Fuso orario di New York per un motivo preciso: e' UTC-5 contro l'UTC+1 di Roma, e la
# differenza di sei ore rende visibile una conversione sbagliata.
SECONDO = {
    "code": "secondo",
    "name": "Secondo Cliente S.r.l.",
    "timezone": "America/New_York",
    "email": "admin@secondo.local",
}


def _crea_secondo_tenant(server_app) -> int:
    """Un secondo tenant con il proprio amministratore. Restituisce il suo id."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str
        from snapserver.security import ROLE_TENANT_ADMIN, hash_password

        esistente = query("SELECT id FROM tenants WHERE code = ?",
                          (SECONDO["code"],), one=True)
        if esistente is not None:
            return int(esistente["id"])
        adesso = utc_now_str()
        tenant_id = int(execute(
            "INSERT INTO tenants (code, name, timezone, contact_email, is_active,"
            " created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?)",
            (SECONDO["code"], SECONDO["name"], SECONDO["timezone"],
             "soc@secondo.local", adesso, adesso)))
        execute(
            "INSERT INTO users (tenant_id, email, password_hash, full_name, role,"
            " is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
            (tenant_id, SECONDO["email"], hash_password("Snap!Tenant2026"),
             "Amministratore Secondo", ROLE_TENANT_ADMIN, adesso, adesso))
        return tenant_id


def _tenant_ids(server_app) -> dict:
    with server_app.app_context():
        from snapserver.db import query

        return {
            row["code"]: int(row["id"]) for row in query("SELECT id, code FROM tenants")
        }


def _seed_probe(server_app, tenant_id: int, code: str, name: str, moment: str = None) -> int:
    """Sonda di prova, visibile nella flotta del tenant."""
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = moment or utc_now_str()
        return execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, enrolled_at,"
            " last_seen_at, last_sync_at, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)",
            (tenant_id, "uid-" + code, code, name, adesso, adesso, adesso, adesso, adesso),
        )


def _login(server_app, email: str, password: str = "Snap!Tenant2026"):
    client = server_app.test_client()
    response = client.post(
        "/login", data={"email": email, "password": password}, follow_redirects=True
    )
    assert response.status_code == 200, "accesso non riuscito per %s" % email
    return client


# --------------------------------------------------------------------------- #
# Isolamento
# --------------------------------------------------------------------------- #
def test_tenant_user_sees_only_own_probes(server_app):
    tenants = _tenant_ids(server_app)
    secondo = _crea_secondo_tenant(server_app)
    _seed_probe(server_app, tenants["ised"], "sonda-ised", "Sonda ISED")
    _seed_probe(server_app, secondo, "sonda-secondo", "Sonda del secondo")

    client = _login(server_app, "admin@ised.local")
    body = client.get("/probes/").data.decode("utf-8")

    assert "sonda-ised" in body
    assert "sonda-secondo" not in body, "violazione di isolamento fra tenant"


def test_tenant_user_cannot_open_probe_of_another_tenant(server_app):
    tenants = _tenant_ids(server_app)
    estranea = _seed_probe(server_app, _crea_secondo_tenant(server_app),
                           "sonda-estranea", "Sonda estranea")

    client = _login(server_app, "admin@ised.local")
    assert client.get("/probes/%d" % estranea).status_code == 404


def test_tenant_user_cannot_switch_tenant(server_app):
    tenants = _tenant_ids(server_app)
    client = _login(server_app, "admin@ised.local")

    response = client.post(
        "/switch-tenant", data={"tenant_id": _crea_secondo_tenant(server_app)},
        follow_redirects=True
    )
    assert response.status_code == 200
    body = client.get("/").data.decode("utf-8")
    assert "ISED S.p.a." in body, "il contesto tenant non deve poter essere forzato"


def test_superadmin_can_switch_tenant(server_app):
    tenants = _tenant_ids(server_app)
    client = server_app.test_client()
    client.post(
        "/login",
        data={
            "email": server_app.config["BOOTSTRAP_ADMIN_EMAIL"],
            "password": server_app.config["BOOTSTRAP_ADMIN_PASSWORD"],
        },
        follow_redirects=True,
    )
    client.post("/switch-tenant", data={"tenant_id": tenants["ised"]}, follow_redirects=True)
    assert "ISED S.p.a." in client.get("/").data.decode("utf-8")

    client.post("/switch-tenant", data={"tenant_id": _crea_secondo_tenant(server_app)},
                follow_redirects=True)
    assert SECONDO["name"] in client.get("/").data.decode("utf-8")


def test_viewer_cannot_reach_administration(server_app):
    client = _login(server_app, "audit@ised.local")
    response = client.get("/admin/users", follow_redirects=False)
    assert response.status_code == 302, "il ruolo di consultazione non accede all'amministrazione"


def test_analyst_cannot_manage_tenants(server_app):
    client = _login(server_app, "analista@ised.local")
    assert client.get("/admin/tenants", follow_redirects=False).status_code == 302


# --------------------------------------------------------------------------- #
# Fusi orari
# --------------------------------------------------------------------------- #
def test_timestamps_are_rendered_in_tenant_timezone(server_app):
    """Lo stesso istante UTC e' mostrato nei due fusi dei rispettivi tenant."""
    tenants = _tenant_ids(server_app)
    moment = "2026-01-15 12:00:00"  # UTC: Roma +1, New York -5

    _seed_probe(server_app, tenants["ised"], "tz-ised", "Sonda ISED", moment)
    _seed_probe(server_app, _crea_secondo_tenant(server_app), "tz-secondo",
                "Sonda del secondo", moment)

    ised_body = _login(server_app, "admin@ised.local").get("/probes/").data.decode("utf-8")
    secondo_body = _login(server_app, SECONDO["email"]).get("/probes/").data.decode("utf-8")

    assert "15/01/2026 13:00" in ised_body, "atteso orario di Roma (UTC+1)"
    assert "15/01/2026 07:00" in secondo_body, "atteso orario di New York (UTC-5)"


def test_tenant_timezone_change_is_applied_to_presentation(server_app):
    tenants = _tenant_ids(server_app)
    moment = "2026-06-15 12:00:00"
    _seed_probe(server_app, tenants["ised"], "tz-move", "Sonda spostata", moment)
    with server_app.app_context():
        from snapserver.db import execute

        execute("UPDATE tenants SET timezone = 'Asia/Tokyo' WHERE id = ?", (tenants["ised"],))

    body = _login(server_app, "admin@ised.local").get("/probes/").data.decode("utf-8")
    assert "15/06/2026 21:00" in body, "atteso orario di Tokyo (UTC+9)"


# --------------------------------------------------------------------------- #
# Autenticazione e MFA
# --------------------------------------------------------------------------- #
def test_login_requires_valid_credentials(server_app):
    client = server_app.test_client()
    response = client.post(
        "/login", data={"email": "admin@ised.local", "password": "sbagliata"}
    )
    assert response.status_code == 401


def test_account_is_locked_after_repeated_failures(server_app):
    client = server_app.test_client()
    for _ in range(5):
        client.post("/login", data={"email": "admin@ised.local", "password": "sbagliata"})

    response = client.post(
        "/login", data={"email": "admin@ised.local", "password": "Snap!Tenant2026"}
    )
    assert response.status_code == 403, "l'utenza deve risultare bloccata"


def test_mfa_challenge_blocks_access_until_valid_code(server_app):
    secret = pyotp.random_base32()
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        execute(
            "UPDATE users SET mfa_enabled = 1, mfa_secret = ?, mfa_confirmed_at = ?"
            " WHERE email = 'admin@ised.local'",
            (secret, utc_now_str()),
        )

    client = server_app.test_client()
    client.post(
        "/login",
        data={"email": "admin@ised.local", "password": "Snap!Tenant2026"},
        follow_redirects=False,
    )
    # Senza secondo fattore la dashboard non e' accessibile.
    assert client.get("/", follow_redirects=False).headers["Location"].endswith("/mfa")

    wrong = client.post("/mfa", data={"code": "000000"})
    assert wrong.status_code == 200

    client.post("/mfa", data={"code": pyotp.TOTP(secret).now()}, follow_redirects=True)
    assert client.get("/", follow_redirects=False).status_code == 200


def test_password_policy_is_enforced(server_app):
    from snapserver.security import password_policy_errors

    assert password_policy_errors("Password2026") == []
    assert password_policy_errors("breve1A")
    assert password_policy_errors("tuttominuscolo1")


def test_tenant_deletion_removes_all_its_data(server_app):
    """La cancellazione del tenant elimina in cascata i dati collegati."""
    tenants = _tenant_ids(server_app)
    secondo = _crea_secondo_tenant(server_app)
    _seed_probe(server_app, secondo, "sonda-cascade", "Sonda in cascata")

    client = server_app.test_client()
    client.post(
        "/login",
        data={
            "email": server_app.config["BOOTSTRAP_ADMIN_EMAIL"],
            "password": server_app.config["BOOTSTRAP_ADMIN_PASSWORD"],
        },
        follow_redirects=True,
    )
    client.post(
        "/admin/tenants/%d/delete" % secondo,
        data={"confirm_code": SECONDO["code"]},
        follow_redirects=True,
    )

    with server_app.app_context():
        from snapserver.db import scalar

        assert scalar("SELECT COUNT(*) FROM tenants WHERE code = ?",
                      (SECONDO["code"],)) == 0
        assert scalar("SELECT COUNT(*) FROM probes WHERE tenant_id = ?", (secondo,)) == 0
        assert scalar("SELECT COUNT(*) FROM users WHERE tenant_id = ?", (secondo,)) == 0

def test_tenant_deletion_action_is_visible_without_opening_panels(server_app):
    """L'eliminazione deve essere raggiungibile dalla riga del tenant."""
    client = server_app.test_client()
    client.post(
        "/login",
        data={
            "email": server_app.config["BOOTSTRAP_ADMIN_EMAIL"],
            "password": server_app.config["BOOTSTRAP_ADMIN_PASSWORD"],
        },
        follow_redirects=True,
    )
    body = client.get("/admin/tenants").data.decode("utf-8")

    assert "bi-trash" in body, "il pulsante di eliminazione deve essere presente"
    assert "modal fade" in body, "deve esistere una finestra di conferma"
    assert "sonde, con le relative credenziali" in body, (
        "la conferma deve dichiarare cosa viene eliminato"
    )


def test_tenant_deletion_wrong_confirmation_states_expected_code(server_app):
    secondo = _crea_secondo_tenant(server_app)
    client = server_app.test_client()
    client.post(
        "/login",
        data={
            "email": server_app.config["BOOTSTRAP_ADMIN_EMAIL"],
            "password": server_app.config["BOOTSTRAP_ADMIN_PASSWORD"],
        },
        follow_redirects=True,
    )

    response = client.post(
        "/admin/tenants/%d/delete" % secondo,
        data={"confirm_code": "codice-errato"},
        follow_redirects=True,
    )
    body = response.data.decode("utf-8")

    assert "digitare esattamente il suo codice: %s" % SECONDO["code"] in body, (
        "il messaggio deve indicare il codice atteso"
    )
    with server_app.app_context():
        from snapserver.db import scalar

        assert scalar("SELECT COUNT(*) FROM tenants WHERE code = ?",
                      (SECONDO["code"],)) == 1


def test_deleting_selected_tenant_keeps_console_usable(server_app):
    """Eliminare il tenant in uso non deve rendere inagibile la console."""
    secondo = _crea_secondo_tenant(server_app)
    client = server_app.test_client()
    client.post(
        "/login",
        data={
            "email": server_app.config["BOOTSTRAP_ADMIN_EMAIL"],
            "password": server_app.config["BOOTSTRAP_ADMIN_PASSWORD"],
        },
        follow_redirects=True,
    )
    client.post("/switch-tenant", data={"tenant_id": secondo}, follow_redirects=True)

    client.post(
        "/admin/tenants/%d/delete" % secondo,
        data={"confirm_code": SECONDO["code"]},
        follow_redirects=True,
    )

    # Il contesto passa all'altro tenant disponibile, senza errori.
    dashboard = client.get("/", follow_redirects=True)
    assert dashboard.status_code == 200
    assert "ISED" in dashboard.data.decode("utf-8")


def test_deleting_every_tenant_leaves_administration_reachable(server_app):
    """Senza tenant residui la console rimanda alla loro gestione."""
    tenants = _tenant_ids(server_app)
    client = server_app.test_client()
    client.post(
        "/login",
        data={
            "email": server_app.config["BOOTSTRAP_ADMIN_EMAIL"],
            "password": server_app.config["BOOTSTRAP_ADMIN_PASSWORD"],
        },
        follow_redirects=True,
    )
    for code, tenant_id in tenants.items():
        client.post(
            "/admin/tenants/%d/delete" % tenant_id,
            data={"confirm_code": code},
            follow_redirects=True,
        )

    with server_app.app_context():
        from snapserver.db import scalar

        assert scalar("SELECT COUNT(*) FROM tenants") == 0

    response = client.get("/", follow_redirects=True)
    assert response.status_code == 200
    assert "Nessun tenant censito" in response.data.decode("utf-8")
