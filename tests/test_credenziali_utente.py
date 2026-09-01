"""
snap - Test dell'invio delle credenziali provvisorie a un utente appena creato.

Prima la password compariva in un messaggio a schermo e chi creava l'utente doveva
comunicarla a mano -- di solito in chat, che e' il posto peggiore in cui una
credenziale possa finire. Ora il messaggio va a chi deve usarla; se la posta non
parte, la password torna a schermo con la ragione, perche' una credenziale che
nessuno riceve e nessuno vede significa un utente inutilizzabile.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest


@pytest.fixture()
def posta_finta(server_app, monkeypatch):
    """Cattura i messaggi invece di spedirli: nessuna prova esce dal calcolatore."""
    spediti = []

    with server_app.app_context():
        import snapserver.notifications as notifiche

        def falso_smtp():
            return {"enabled": True, "host": "posta.esempio", "port": 587,
                    "user": "snap", "password": "x", "sender": "snap@esempio",
                    "use_tls": True}

        def falso_invio(config, recipients, subject, body, body_html=None,
                        attachment=None):
            spediti.append({"a": recipients, "oggetto": subject, "corpo": body})

        monkeypatch.setattr(notifiche, "smtp_config", falso_smtp)
        monkeypatch.setattr(notifiche, "send_now", falso_invio)
    return spediti


def _crea_utente(logged_client, email="nuovo@ised.local", password=""):
    return logged_client.post("/admin/users", data={
        "email": email, "full_name": "Utente Nuovo", "role": "analyst",
        "password": password,
    }, follow_redirects=True)


def test_le_credenziali_arrivano_a_chi_le_deve_usare(logged_client, posta_finta):
    risposta = _crea_utente(logged_client, "destinatario@ised.local")

    assert risposta.status_code == 200
    assert len(posta_finta) == 1, "un messaggio, a una persona"
    messaggio = posta_finta[0]
    assert messaggio["a"] == "destinatario@ised.local"
    assert "credenziali" in messaggio["oggetto"].lower()
    assert "Password provvisoria" in messaggio["corpo"]
    assert "destinatario@ised.local" in messaggio["corpo"]


def test_il_messaggio_dice_che_la_password_va_cambiata(logged_client, posta_finta):
    _crea_utente(logged_client, "avvisato@ised.local")

    corpo = posta_finta[0]["corpo"]
    assert "provvisoria" in corpo
    assert "cambiarla" in corpo
    assert "una volta sola" in corpo, (
        "va detto che snap non manda password in nessun altro caso: e' cio' che"
        " permette di riconoscere un messaggio falso")


def test_la_password_non_finisce_nel_registro(logged_client, posta_finta, server_app):
    """Un segreto nel registro degli eventi resta la' per tutta la conservazione."""
    _crea_utente(logged_client, "riservato@ised.local")
    password = None
    for riga in posta_finta[0]["corpo"].splitlines():
        if "Password provvisoria" in riga:
            password = riga.split(":", 1)[1].strip()
    assert password, "la password sta nel messaggio"

    with server_app.app_context():
        from snapserver.db import query

        eventi = query("SELECT description FROM audit_events WHERE event_type LIKE"
                       " 'user.%'", ())
    testo = " ".join(r["description"] or "" for r in eventi)
    assert password not in testo
    assert "riservato@ised.local" in testo, "l'indirizzo si registra, la password no"


def test_l_invio_resta_nel_registro(logged_client, posta_finta, server_app):
    _crea_utente(logged_client, "tracciato@ised.local")

    with server_app.app_context():
        from snapserver.db import query

        tracce = query("SELECT description FROM audit_events"
                       " WHERE event_type = 'user.credentials.sent'", ())
    assert tracce
    assert "tracciato@ised.local" in tracce[0]["description"]


def test_senza_posta_configurata_la_password_torna_a_schermo(logged_client, server_app,
                                                             monkeypatch):
    """Una credenziale che nessuno riceve e nessuno vede e' un utente inutilizzabile."""
    with server_app.app_context():
        import snapserver.notifications as notifiche

        monkeypatch.setattr(notifiche, "smtp_config",
                            lambda: {"enabled": False})

    risposta = _crea_utente(logged_client, "senzaposta@ised.local")
    testo = risposta.get_data(as_text=True)

    assert "NON sono state spedite" in testo
    assert "posta non configurata" in testo
    assert "Password provvisoria da comunicare" in testo


def test_un_invio_non_riuscito_viene_dichiarato(logged_client, server_app, monkeypatch):
    with server_app.app_context():
        import snapserver.notifications as notifiche

        def esplode(*_argomenti, **_parametri):
            raise OSError("server di posta non raggiungibile")

        monkeypatch.setattr(notifiche, "smtp_config",
                            lambda: {"enabled": True, "host": "x", "port": 25,
                                     "user": "", "password": "", "sender": "s@x",
                                     "use_tls": True})
        monkeypatch.setattr(notifiche, "send_now", esplode)

    risposta = _crea_utente(logged_client, "irraggiungibile@ised.local")
    testo = risposta.get_data(as_text=True)

    assert "NON sono state spedite" in testo
    assert "OSError" in testo, "si dice quale errore, non solo che e' andata male"
    with server_app.app_context():
        from snapserver.db import query

        tracce = query("SELECT description FROM audit_events"
                       " WHERE event_type = 'user.credentials.failed'", ())
    assert tracce


def test_l_utente_viene_creato_anche_se_la_posta_non_parte(logged_client, server_app,
                                                           monkeypatch):
    """L'invio e' un servizio, non una condizione: un guasto della posta non deve
    impedire di creare un accesso."""
    with server_app.app_context():
        import snapserver.notifications as notifiche

        monkeypatch.setattr(notifiche, "smtp_config", lambda: {"enabled": False})

    _crea_utente(logged_client, "creato.comunque@ised.local")

    with server_app.app_context():
        from snapserver.db import query

        assert query("SELECT id FROM users WHERE email = 'creato.comunque@ised.local'",
                     (), one=True) is not None
