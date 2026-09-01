"""
snap - Test degli indicatori della dashboard che si possono nascondere.

L'area indicatori mostra undici riquadri: su una dashboard usata ogni giorno, chi
tiene il turno ne guarda tre o quattro e gli altri gli coprono lo spazio. La scelta
di nasconderne alcuni e' personale e persistente -- sta sull'utente, non nella
sessione e non nel browser.

Difetto trovato scrivendo questa funzione, e coperto qui: due indicatori diversi
condividevano la chiave `coverage` (copertura delle sonde e copertura del
perimetro). Finche' le chiavi non servivano a nulla non si vedeva; da quando
governano cio' che si nasconde, nasconderne uno ne nascondeva due.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest


def _tenant_id(server_app):
    with server_app.app_context():
        from snapserver.db import query

        return int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])


def _nascosti_di(server_app, email: str = None) -> str:
    with server_app.app_context():
        from snapserver.db import query

        indirizzo = email or server_app.config["BOOTSTRAP_ADMIN_EMAIL"]
        riga = query("SELECT pref_kpi_hidden FROM users WHERE email = ?",
                     (indirizzo,), one=True)
        return riga["pref_kpi_hidden"] or ""


def _indicatori(server_app) -> list:
    with server_app.app_context():
        from snapserver.inventory_queries import inventory_indicators
        from snapserver.queries import dashboard_indicators

        return dashboard_indicators(_tenant_id(server_app)) + inventory_indicators(
            _tenant_id(server_app))


# --------------------------------------------------------------------------- #
# Le chiavi
# --------------------------------------------------------------------------- #
def test_ogni_indicatore_ha_una_chiave_propria(server_app):
    """Due indicatori con la stessa chiave sono un difetto silenzioso: nasconderne
    uno ne nasconde due."""
    voci = _indicatori(server_app)
    chiavi = [v["key"] for v in voci]

    assert len(chiavi) == len(set(chiavi)), (
        "chiavi ripetute: %s" % sorted({c for c in chiavi if chiavi.count(c) > 1}))
    assert all(v.get("label") for v in voci), "un indicatore senza etichetta non si nasconde"


def test_l_elenco_delle_chiavi_ammesse_copre_tutti_gli_indicatori(server_app):
    from snapserver.queries import kpi_keys

    with server_app.app_context():
        ammesse = kpi_keys()

    assert {v["key"] for v in _indicatori(server_app)} <= ammesse


# --------------------------------------------------------------------------- #
# Nascondere e ritrovare
# --------------------------------------------------------------------------- #
def test_all_inizio_si_vedono_tutti(logged_client, server_app):
    pagina = logged_client.get("/").get_data(as_text=True)

    assert pagina.count('class="snap-kpi snap-kpi-') == len(_indicatori(server_app))
    assert "Nascosti da te" not in pagina, (
        "senza indicatori nascosti il riquadro per riattivarli non serve")


def test_nascondere_un_indicatore_ne_toglie_uno_solo(logged_client, server_app):
    quanti = len(_indicatori(server_app))
    risposta = logged_client.post("/preferences/indicatori",
                                  data={"nascondi": "volume"}, follow_redirects=True)

    assert risposta.status_code == 200
    pagina = logged_client.get("/").get_data(as_text=True)
    assert pagina.count('class="snap-kpi snap-kpi-') == quanti - 1
    assert "Dati ricevuti 24h" not in pagina.split("Nascosti da te")[0]
    assert _nascosti_di(server_app) == "volume"


def test_la_scelta_resta_fra_una_sessione_e_l_altra(logged_client, server_app):
    """Persistente vuol dire sull'utente: un cliente che chiude il browser e torna
    domani deve ritrovare la propria dashboard, non quella predefinita."""
    logged_client.post("/preferences/indicatori", data={"nascondi": "commands"},
                       follow_redirects=True)
    logged_client.get("/logout", follow_redirects=True)

    nuovo = server_app.test_client()
    nuovo.post("/login", data={"email": server_app.config["BOOTSTRAP_ADMIN_EMAIL"],
                               "password": server_app.config["BOOTSTRAP_ADMIN_PASSWORD"]},
               follow_redirects=True)
    pagina = nuovo.get("/").get_data(as_text=True)

    assert "Nascosti da te (1)" in pagina
    assert 'value="commands"' in pagina, "l'indicatore nascosto si puo' riattivare"


def test_la_scelta_e_di_chi_la_compie_non_dei_colleghi(logged_client, server_app):
    """Il giudizio "questo non mi serve" vale per chi lo esprime: un secondo utente
    apre la propria dashboard completa."""
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str
        from snapserver.security import hash_password

        adesso = utc_now_str()
        execute(
            "INSERT INTO users (tenant_id, email, password_hash, full_name, role,"
            " is_active, created_at, updated_at) VALUES (?, 'collega@ised.local', ?,"
            " 'Collega', 'analyst', 1, ?, ?)",
            (_tenant_id(server_app), hash_password("Collega!2026"), adesso, adesso))

    logged_client.post("/preferences/indicatori", data={"nascondi": "volume"},
                       follow_redirects=True)

    collega = server_app.test_client()
    collega.post("/login", data={"email": "collega@ised.local",
                                 "password": "Collega!2026"}, follow_redirects=True)
    pagina = collega.get("/").get_data(as_text=True)

    assert pagina.count('class="snap-kpi snap-kpi-') == len(_indicatori(server_app))
    assert _nascosti_di(server_app, "collega@ised.local") == ""


def test_si_riattivano_tutti_con_un_comando(logged_client, server_app):
    for chiave in ("volume", "commands", "events"):
        logged_client.post("/preferences/indicatori", data={"nascondi": chiave},
                           follow_redirects=True)
    assert _nascosti_di(server_app) == "commands,events,volume"

    logged_client.post("/preferences/indicatori", data={"azione": "mostra_tutti"},
                       follow_redirects=True)

    assert _nascosti_di(server_app) == ""
    pagina = logged_client.get("/").get_data(as_text=True)
    assert pagina.count('class="snap-kpi snap-kpi-') == len(_indicatori(server_app))


def test_si_riattiva_togliendo_la_spunta(logged_client, server_app):
    """Il riquadro elenca i nascosti con la spunta messa: togliendola e salvando,
    l'indicatore torna. Si inviano le chiavi che RESTANO nascoste."""
    for chiave in ("volume", "commands"):
        logged_client.post("/preferences/indicatori", data={"nascondi": chiave},
                           follow_redirects=True)

    logged_client.post("/preferences/indicatori", data={"nascosti": ["volume"]},
                       follow_redirects=True)

    assert _nascosti_di(server_app) == "volume"


# --------------------------------------------------------------------------- #
# Robustezza
# --------------------------------------------------------------------------- #
def test_una_chiave_non_prevista_non_entra(logged_client, server_app):
    """Allowlist: il campo non deve diventare un deposito di testo arbitrario."""
    logged_client.post("/preferences/indicatori",
                       data={"nascondi": "../../etc/passwd"}, follow_redirects=True)
    logged_client.post("/preferences/indicatori",
                       data={"nascosti": ["<script>", "volume"]}, follow_redirects=True)

    assert _nascosti_di(server_app) == "volume"


def test_un_indicatore_nuovo_si_vede_anche_a_chi_aveva_nascosto_qualcosa(
        logged_client, server_app):
    """Si conservano le chiavi NASCOSTE, non quelle visibili: cosi' un indicatore
    aggiunto da una versione successiva compare a tutti. Il contrario -- un elenco
    di chiavi ammesse -- lo terrebbe invisibile a chi ha personalizzato la vista, ed
    e' un lavoro fatto e mai mostrato."""
    logged_client.post("/preferences/indicatori", data={"nascondi": "volume"},
                       follow_redirects=True)
    quanti = len(_indicatori(server_app))

    pagina = logged_client.get("/").get_data(as_text=True)
    assert pagina.count('class="snap-kpi snap-kpi-') == quanti - 1, (
        "nascosto uno, tutti gli altri restano visibili -- compresi quelli futuri")


def test_serve_l_accesso(server_client):
    risposta = server_client.post("/preferences/indicatori", data={"nascondi": "volume"})

    assert risposta.status_code in (302, 401)
    assert "/login" in risposta.headers.get("Location", "/login")


@pytest.mark.parametrize("chiave", ["coverage", "perimeter_coverage"])
def test_le_due_coperture_restano_distinte(server_app, chiave):
    """Erano lo stesso `coverage`: la copertura delle sonde e quella del perimetro
    sono due misure diverse e si nascondono separatamente."""
    chiavi = {v["key"]: v["label"] for v in _indicatori(server_app)}

    assert chiave in chiavi
    assert chiavi["coverage"] != chiavi["perimeter_coverage"]
