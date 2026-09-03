# -----------------------------------------------------------------
# test_profilo_telegram.py — l'utente puo' dichiarare il proprio ID Telegram
# Autore: Daniele Speziale
# Data creazione: 2026-09-03
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""Verifica che dalla pagina "Profilo e sicurezza" l'utente possa indicare il proprio
identificativo di chat Telegram per ricevere notifiche personali, con la spiegazione di
come trovarlo e con la validazione dell'ingresso."""

from __future__ import annotations


def _id_utente(server_app):
    with server_app.app_context():
        from snapserver.db import query

        return int(query("SELECT id FROM users ORDER BY id", (), one=True)["id"])


def test_la_pagina_profilo_spiega_come_trovare_l_id_telegram(logged_client):
    corpo = logged_client.get("/profile").get_data(as_text=True)
    assert 'name="telegram_chat_id"' in corpo
    assert "@userinfobot" in corpo, "va spiegato come trovare il proprio ID Telegram"
    assert "/profile/telegram" in corpo


def test_salva_un_id_telegram_valido(logged_client, server_app):
    r = logged_client.post("/profile/telegram",
                           data={"telegram_chat_id": "123456789"},
                           follow_redirects=True)
    assert r.status_code == 200
    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT telegram_chat_id FROM users WHERE id = ?",
                     (_id_utente(server_app),), one=True)
    assert riga["telegram_chat_id"] == "123456789"


def test_rifiuta_un_id_telegram_non_numerico(logged_client, server_app):
    logged_client.post("/profile/telegram",
                       data={"telegram_chat_id": "non-e-un-numero"},
                       follow_redirects=True)
    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT telegram_chat_id FROM users WHERE id = ?",
                     (_id_utente(server_app),), one=True)
    assert not riga["telegram_chat_id"], "un ID non valido non deve essere salvato"


def test_svuotare_il_campo_disattiva_le_notifiche_personali(logged_client, server_app):
    logged_client.post("/profile/telegram", data={"telegram_chat_id": "555555555"},
                       follow_redirects=True)
    logged_client.post("/profile/telegram", data={"telegram_chat_id": "  "},
                       follow_redirects=True)
    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT telegram_chat_id FROM users WHERE id = ?",
                     (_id_utente(server_app),), one=True)
    assert not riga["telegram_chat_id"]
