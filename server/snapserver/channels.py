"""
snap server - Canali di recapito delle notifiche: posta elettronica e bot Telegram.

Perche' Telegram accanto alla posta: una notifica che arriva in una casella viene
letta quando qualcuno apre la casella. Un incidente alle tre di notte ha bisogno di un
canale che suoni. Il bot e' anche l'unico modo pratico di raggiungere un turno che
cambia persona senza rifare la configurazione: si cambia il gruppo, non i recapiti.

Dipendenze: nessuna aggiunta. Telegram ha un'interfaccia HTTP e `urllib.request` sta
nella libreria standard; il corpo multipart per l'invio di un documento e' costruito a
mano, poche righe, invece di aggiungere una libreria per farlo.

Riservatezza: il token del bot e' una credenziale. Viene conservato nelle impostazioni
di sistema come la password della posta e non viene mai mostrato per intero.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json
import mimetypes
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .db import query

CHANNEL_EMAIL = "email"
CHANNEL_TELEGRAM = "telegram"
CHANNELS = {
    CHANNEL_EMAIL: "Posta elettronica",
    CHANNEL_TELEGRAM: "Bot Telegram",
}

TELEGRAM_API = "https://api.telegram.org"
# Limiti dell'interfaccia Telegram: un messaggio non supera i 4096 caratteri e un
# documento i 50 MB. Superarli non produce un errore comprensibile, quindi si taglia
# prima e si dichiara il taglio.
TELEGRAM_TEXT_LIMIT = 4096
TELEGRAM_FILE_LIMIT = 50 * 1024 * 1024
TELEGRAM_TIMEOUT_SECONDS = 15


class ChannelError(RuntimeError):
    """Errore di recapito su un canale. Il messaggio e' destinato all'operatore."""


def _setting(key: str, default: str = "") -> str:
    riga = query("SELECT value FROM system_settings WHERE key = ?", (key,), one=True)
    if riga is None or riga["value"] is None:
        return default
    return str(riga["value"])


# --------------------------------------------------------------------------- #
# Configurazione
# --------------------------------------------------------------------------- #
def telegram_config() -> dict:
    return {
        "token": _setting("telegram_bot_token").strip(),
        "chat_id": _setting("telegram_chat_id").strip(),
        "enabled": _setting("telegram_enabled", "0") == "1",
    }


def is_telegram_configured(config: dict = None) -> bool:
    config = config or telegram_config()
    return bool(config["token"] and config["chat_id"])


def masked_token(token: str) -> str:
    """Token in forma non utilizzabile, per mostrarlo nella pagina.

    Si mostra la parte iniziale perche' e' l'identificativo del bot, non il segreto:
    serve a riconoscere quale bot e' configurato senza esporre la credenziale.
    """
    testo = (token or "").strip()
    if not testo:
        return ""
    identificativo = testo.split(":", 1)[0]
    return "%s:%s" % (identificativo, "*" * 8)


def available_channels() -> dict:
    """Canali utilizzabili adesso, con la ragione di chi non lo e'."""
    from .notifications import is_configured as posta_configurata, smtp_config

    posta = smtp_config()
    telegram = telegram_config()
    return {
        CHANNEL_EMAIL: {
            "etichetta": CHANNELS[CHANNEL_EMAIL],
            "pronto": bool(posta["enabled"] and posta_configurata(posta)),
            "motivo": "" if posta_configurata(posta)
                      else "indicare almeno server di posta e mittente",
        },
        CHANNEL_TELEGRAM: {
            "etichetta": CHANNELS[CHANNEL_TELEGRAM],
            "pronto": bool(telegram["enabled"] and is_telegram_configured(telegram)),
            "motivo": "" if is_telegram_configured(telegram)
                      else "indicare token del bot e identificativo della chat",
        },
    }


# --------------------------------------------------------------------------- #
# Telegram
# --------------------------------------------------------------------------- #
def _post(url: str, dati: bytes, tipo: str) -> dict:
    richiesta = urllib.request.Request(url, data=dati, method="POST")
    richiesta.add_header("Content-Type", tipo)
    contesto = ssl.create_default_context()
    try:
        with urllib.request.urlopen(richiesta, timeout=TELEGRAM_TIMEOUT_SECONDS,
                                    context=contesto) as risposta:
            corpo = risposta.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as errore:
        # Il corpo dell'errore di Telegram contiene la descrizione utile
        # ("chat not found", "bot was blocked"): perderla lascerebbe l'operatore
        # con un 400 senza spiegazione.
        dettaglio = ""
        try:
            dettaglio = errore.read().decode("utf-8", "replace")[:300]
        except OSError:
            dettaglio = ""
        raise ChannelError("Telegram ha risposto %s: %s"
                           % (errore.code, dettaglio or errore.reason)) from errore
    except (urllib.error.URLError, OSError, ssl.SSLError) as errore:
        raise ChannelError("Telegram non raggiungibile: %s" % errore) from errore

    try:
        documento = json.loads(corpo)
    except ValueError as errore:
        raise ChannelError("Risposta di Telegram non interpretabile.") from errore
    if not documento.get("ok"):
        raise ChannelError("Telegram ha rifiutato la richiesta: %s"
                           % documento.get("description", "senza descrizione"))
    return documento


def _multipart(campi: dict, file_campo: str, percorso: Path) -> tuple:
    """Corpo multipart per l'invio di un documento. Restituisce (dati, tipo)."""
    confine = "----snap%s" % os.urandom(12).hex()
    pezzi = []
    for nome, valore in campi.items():
        pezzi.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
                      % (confine, nome, valore)).encode("utf-8"))
    tipo_file = mimetypes.guess_type(percorso.name)[0] or "application/octet-stream"
    pezzi.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\";"
                  " filename=\"%s\"\r\nContent-Type: %s\r\n\r\n"
                  % (confine, file_campo, percorso.name, tipo_file)).encode("utf-8"))
    pezzi.append(percorso.read_bytes())
    pezzi.append(("\r\n--%s--\r\n" % confine).encode("utf-8"))
    return b"".join(pezzi), "multipart/form-data; boundary=%s" % confine


def send_telegram(config: dict, chat_id: str, text: str, attachment=None) -> dict:
    """Recapita un messaggio a una chat. Solleva ChannelError se non riesce.

    Con un allegato si usa `sendDocument` e il testo diventa la didascalia: due
    messaggi separati arriverebbero slegati, e la didascalia ha un limite piu' corto
    del messaggio, quindi il testo lungo viene tagliato dichiarandolo.
    """
    if not config.get("token"):
        raise ChannelError("Token del bot Telegram non configurato.")
    destinazione = (chat_id or config.get("chat_id") or "").strip()
    if not destinazione:
        raise ChannelError("Identificativo della chat Telegram non indicato.")

    corpo = text or ""
    if attachment:
        percorso = Path(attachment)
        if not percorso.is_file():
            raise ChannelError("Allegato non trovato: %s" % percorso.name)
        if percorso.stat().st_size > TELEGRAM_FILE_LIMIT:
            raise ChannelError("Allegato oltre i 50 MB consentiti da Telegram.")
        didascalia = corpo[:1024]
        if len(corpo) > 1024:
            didascalia = corpo[:1000].rstrip() + "\n[...] testo completo nel documento"
        dati, tipo = _multipart({"chat_id": destinazione, "caption": didascalia},
                                "document", percorso)
        return _post("%s/bot%s/sendDocument" % (TELEGRAM_API, config["token"]),
                     dati, tipo)

    if len(corpo) > TELEGRAM_TEXT_LIMIT:
        corpo = corpo[:TELEGRAM_TEXT_LIMIT - 60].rstrip() + \
            "\n[...] messaggio troncato, il seguito e' nella console."
    dati = urllib.parse.urlencode({
        "chat_id": destinazione,
        "text": corpo,
        "disable_web_page_preview": "true",
    }).encode("utf-8")
    return _post("%s/bot%s/sendMessage" % (TELEGRAM_API, config["token"]),
                 dati, "application/x-www-form-urlencoded")


def telegram_identity(config: dict = None) -> dict:
    """Chi e' il bot configurato. Serve alla pagina per dire che il token e' valido."""
    config = config or telegram_config()
    if not config.get("token"):
        raise ChannelError("Token del bot Telegram non configurato.")
    documento = _post("%s/bot%s/getMe" % (TELEGRAM_API, config["token"]), b"",
                      "application/x-www-form-urlencoded")
    risultato = documento.get("result") or {}
    return {
        "id": risultato.get("id"),
        "username": risultato.get("username"),
        "nome": risultato.get("first_name"),
    }
