# -----------------------------------------------------------------
# test_operatore_siem.py — il profilo "Operatore SIEM" e il suo menu su misura
# Autore: Daniele Speziale
# Data creazione: 2026-09-03
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""L'Operatore SIEM e' una figura specializzata: opera il SIEM e gli incidenti a pieno,
ma non l'inventario ne' l'amministrazione. Il menu gli mostra solo cio' che gli serve."""

from __future__ import annotations


def _crea_operatore(server_app, email="op.siem@ised.local", password="OpSiem!2026xy"):
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str
        from snapserver.security import hash_password

        tenant_id = query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"]
        execute(
            "INSERT INTO users (tenant_id, email, password_hash, full_name, role,"
            " is_active, must_change_pwd, created_at, updated_at)"
            " VALUES (?, ?, ?, 'Operatore di prova', 'siem_operator', 1, 0, ?, ?)",
            (tenant_id, email, hash_password(password), utc_now_str(), utc_now_str()))
    return email, password


def _login(client, email, password):
    return client.post("/login", data={"email": email, "password": password},
                       follow_redirects=True)


def test_il_ruolo_operatore_siem_esiste_ed_e_assegnabile(server_app):
    with server_app.app_context():
        from snapserver.blueprints.admin import ASSIGNABLE_ROLES
        from snapserver.security import ROLE_LABELS, ROLE_SIEM_OPERATOR

        assert ROLE_SIEM_OPERATOR in ASSIGNABLE_ROLES
        assert ROLE_LABELS[ROLE_SIEM_OPERATOR] == "Operatore SIEM"


def test_l_operatore_siem_opera_il_siem_come_un_analista(server_app):
    """Le azioni del SIEM sono protette da role_required(analyst): l'operatore SIEM,
    allo stesso livello, deve poterle compiere."""
    with server_app.app_context():
        from snapserver.security import ROLE_ANALYST, role_level, ROLE_SIEM_OPERATOR

        assert role_level(ROLE_SIEM_OPERATOR) == role_level(ROLE_ANALYST)


def test_il_menu_dell_operatore_siem_e_su_misura(server_app):
    email, password = _crea_operatore(server_app)
    client = server_app.test_client()
    _login(client, email, password)
    pagina = client.get("/", follow_redirects=True).get_data(as_text=True)
    menu = pagina[pagina.index("app-sidebar"):pagina.index("</aside>")]

    # Vede cio' che gli serve: il SIEM e gli incidenti.
    assert 'data-snap-gruppo="siem"' in menu, "l'operatore SIEM deve vedere il SIEM"
    assert '>INCIDENTI<' in menu, "l'operatore SIEM deve vedere gli incidenti"

    # NON vede cio' che non lo riguarda: rete, controlli, sicurezza, sonde, admin.
    for gruppo in ('data-snap-gruppo="rete"', 'data-snap-gruppo="controlli"',
                   'data-snap-gruppo="sicurezza"', 'data-snap-gruppo="sonde"',
                   'data-snap-gruppo="admin"', 'data-snap-gruppo="sala"'):
        assert gruppo not in menu, "l'operatore SIEM non deve vedere %r" % gruppo


def test_l_analista_continua_a_vedere_il_menu_completo(logged_client):
    """Regressione: il menu su misura vale SOLO per l'operatore SIEM; gli altri ruoli
    continuano a vedere tutto quanto gli spetta."""
    pagina = logged_client.get("/", follow_redirects=True).get_data(as_text=True)
    menu = pagina[pagina.index("app-sidebar"):pagina.index("</aside>")]
    assert 'data-snap-gruppo="rete"' in menu
    assert 'data-snap-gruppo="controlli"' in menu
    assert 'data-snap-gruppo="siem"' in menu
