# -----------------------------------------------------------------
# test_probe_scan_watch.py — avviso quando una sonda ha le scansioni bloccate
# Autore: Daniele Speziale
# Data creazione: 2026-09-09
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""La sorveglianza avvisa una volta per episodio quando una sonda ha le scansioni
bloccate (sospese sulla sonda o disabilitate dal server) e azzera l'avviso al ripristino."""

from __future__ import annotations


def _tenant_id(server_app) -> int:
    with server_app.app_context():
        from snapserver.db import query

        return int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])


def _sonda(server_app, tenant_id, *, scan_enabled=1, scan_paused=0, vista="ora"):
    """Crea una sonda registrata. `vista` = 'ora' (online) o 'vecchia' (offline)."""
    with server_app.app_context():
        from snapserver.db import days_ago_str, execute, query, utc_now_str

        last_seen = utc_now_str() if vista == "ora" else days_ago_str(1)
        adesso = utc_now_str()
        execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, enrolled_at,"
            " last_seen_at, scan_enabled, scan_paused, scan_interval_sec,"
            " created_at, updated_at)"
            " VALUES (?, 'uid-watch', 'P-WATCH', 'Sonda vigilata', 'active', ?, ?,"
            " ?, ?, 300, ?, ?)",
            (tenant_id, adesso, last_seen, scan_enabled, scan_paused, adesso, adesso))
        return int(query("SELECT id FROM probes WHERE probe_uid = 'uid-watch'",
                         (), one=True)["id"])


def _stato(server_app, probe_id):
    with server_app.app_context():
        from snapserver.db import query

        return dict(query("SELECT scan_blocked_alerted_at FROM probes WHERE id = ?",
                          (probe_id,), one=True))


def _eventi(server_app, azione):
    with server_app.app_context():
        from snapserver.db import query

        return int(query("SELECT COUNT(*) AS n FROM audit_events WHERE event_type = ?",
                         (azione,), one=True)["n"])


def test_una_sonda_che_scansiona_non_produce_avvisi(server_app):
    tenant_id = _tenant_id(server_app)
    _sonda(server_app, tenant_id, scan_enabled=1, scan_paused=0)
    with server_app.app_context():
        from snapserver import probe_scan_watch

        esito = probe_scan_watch.giro()
    assert esito["avvisi"] == 0


def test_scansioni_sospese_sulla_sonda_avvisano_una_volta_sola(server_app):
    tenant_id = _tenant_id(server_app)
    probe_id = _sonda(server_app, tenant_id, scan_paused=1, vista="ora")
    with server_app.app_context():
        from snapserver import probe_scan_watch

        primo = probe_scan_watch.giro()
        secondo = probe_scan_watch.giro()  # niente doppio avviso
    assert primo["avvisi"] == 1
    assert secondo["avvisi"] == 0
    assert _stato(server_app, probe_id)["scan_blocked_alerted_at"] is not None
    assert _eventi(server_app, "probe.scan.blocked") == 1


def test_scansioni_disabilitate_dal_server_avvisano_anche_se_offline(server_app):
    """L'interruttore del server e' una verita' del server: vale anche a sonda offline."""
    tenant_id = _tenant_id(server_app)
    _sonda(server_app, tenant_id, scan_enabled=0, vista="vecchia")
    with server_app.app_context():
        from snapserver import probe_scan_watch

        esito = probe_scan_watch.giro()
    assert esito["avvisi"] == 1


def test_pausa_locale_su_sonda_offline_non_avvisa(server_app):
    """La pausa locale vale solo se la sonda si e' fatta viva: su una offline il dato
    dell'heartbeat e' vecchio, e l'assenza e' un altro problema."""
    tenant_id = _tenant_id(server_app)
    _sonda(server_app, tenant_id, scan_enabled=1, scan_paused=1, vista="vecchia")
    with server_app.app_context():
        from snapserver import probe_scan_watch

        esito = probe_scan_watch.giro()
    assert esito["avvisi"] == 0


def test_al_ripristino_l_avviso_si_azzera(server_app):
    tenant_id = _tenant_id(server_app)
    probe_id = _sonda(server_app, tenant_id, scan_paused=1, vista="ora")
    with server_app.app_context():
        from snapserver import probe_scan_watch
        from snapserver.db import execute, utc_now_str

        probe_scan_watch.giro()  # avvisa e segna
        assert _stato(server_app, probe_id)["scan_blocked_alerted_at"] is not None
        # La sonda riprende.
        execute("UPDATE probes SET scan_paused = 0, updated_at = ? WHERE id = ?",
                (utc_now_str(), probe_id))
        esito = probe_scan_watch.giro()
    assert esito["ripristini"] == 1
    assert _stato(server_app, probe_id)["scan_blocked_alerted_at"] is None
    assert _eventi(server_app, "probe.scan.resumed") == 1
