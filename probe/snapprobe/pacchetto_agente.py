# -----------------------------------------------------------------
# pacchetto_agente.py — il pacchetto di installazione dell'agente, pronto da copiare
# Autore: Daniele Speziale
# Data creazione: 2026-09-13
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap probe - Un archivio da copiare sulla macchina e aprire.

PERCHE' UN PACCHETTO E NON TRE RIGHE DA COPIARE
-----------------------------------------------
Le tre righe da copiare funzionano quando chi installa e' la stessa persona che ha
emesso il token, ha il repository sottomano e sa che cosa sta facendo. Su venti
macchine, meta' delle quali amministrate da qualcun altro, quelle tre righe diventano
un messaggio inoltrato con un token dentro, un file preso da una cartella condivisa e
una versione dell'agente che nessuno sa quale sia.

Il pacchetto porta con se' tutto: l'agente, gli installatori per Windows, Linux e
Docker, le istruzioni, e il token gia' dentro. Chi lo riceve esegue un comando solo.

IL PACCHETTO E' UNA CREDENZIALE
-------------------------------
Dentro c'e' un token valido. Vale **un'ora e una volta sola** -- e' la stessa scelta
del token delle sonde, per la stessa ragione -- e gli installatori lo CANCELLANO dalla
macchina appena speso, perche' una credenziale che sopravvive al proprio scopo e' una
credenziale che qualcuno trovera' fra sei mesi. La pagina che lo genera lo dice, e
l'emissione resta nel diario della sonda.

UNA MACCHINA, UN PACCHETTO
--------------------------
Il token si consuma alla prima registrazione: il secondo che prova riceve un rifiuto.
E' voluto -- ogni macchina ha la propria credenziale, e una credenziale condivisa fra
venti macchine non si puo' revocare per una sola.

DA DOVE VENGONO I FILE
----------------------
Da `agent/` del prodotto, non da stringhe scritte qui dentro: sono file veri,
versionati, che si leggono e si collaudano come il resto del codice. Qui si compone
l'archivio e si aggiunge il solo file che dipende da chi lo scarica -- `pacchetto.json`,
con indirizzo della sonda e token.

remarks: Autore: Daniele Speziale - Data: 2026-09-13
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

# Dove sta l'agente, in ordine di tentativo.
#
# 1. Nel contenitore della sonda il Dockerfile copia `agent/` in `/app/agente/`, che
#    e' accanto al pacchetto `snapprobe`.
# 2. Fuori dal contenitore la sonda gira dal repository, e `agent/` sta due livelli
#    sopra `snapprobe`.
#
# Si dichiarano tutti e due invece di cercare in giro: se un giorno nessuno dei due
# esiste, l'errore deve dire quali posti sono stati guardati.
RADICI_AGENTE = (
    Path(__file__).resolve().parent.parent / "agente",
    Path(__file__).resolve().parent.parent.parent / "agent",
)

# Che cosa entra nell'archivio. Il percorso a sinistra e' quello dentro il pacchetto:
# `snap_agent.py` in cima, perche' e' quello che si guarda per primo.
CONTENUTO = (
    ("snap_agent.py", "snap_agent.py"),
    ("requirements.txt", "requirements.txt"),
    ("LEGGIMI.md", "LEGGIMI.md"),
    ("installa.ps1", "installa.ps1"),
    ("installa.sh", "installa.sh"),
    ("disinstalla.ps1", "disinstalla.ps1"),
    ("disinstalla.sh", "disinstalla.sh"),
    ("docker/Dockerfile", "docker/Dockerfile"),
    ("docker/docker-compose.yml", "docker/docker-compose.yml"),
    ("docker/avvio.sh", "docker/avvio.sh"),
    ("docker/.env.example", "docker/.env.example"),
)

# I file che sulla macchina devono essere ESEGUIBILI. Lo zip conserva i permessi solo
# se glieli si scrive: senza, chi scompatta su Linux trova un installatore che non
# parte e un messaggio ("permission denied") che non spiega perche'.
ESEGUIBILI = ("installa.sh", "disinstalla.sh", "docker/avvio.sh")


def radice_agente() -> Path:
    """Dove stanno i file dell'agente. Solleva dicendo dove ha guardato."""
    for candidata in RADICI_AGENTE:
        if (candidata / "snap_agent.py").is_file():
            return candidata
    raise FileNotFoundError(
        "i file dell'agente non si trovano. Cercati in: %s"
        % ", ".join(str(c) for c in RADICI_AGENTE))


def versione_agente() -> str:
    """La versione dichiarata dall'agente che sta per essere impacchettato.

    Si legge dal sorgente invece di tenerne una copia qui: due numeri in due posti
    divergono, e quello sbagliato sarebbe proprio quello mostrato a chi installa.
    """
    sorgente = (radice_agente() / "snap_agent.py").read_text(encoding="utf-8")
    for riga in sorgente.splitlines():
        if riga.startswith("VERSIONE = "):
            return riga.split("=", 1)[1].strip().strip('"').strip("'")
    return "sconosciuta"


def _manifesto(sonda: str, token: str, scade_at: str, verifica_tls: bool,
               etichetta: str, adesso: str) -> str:
    """Il solo file che cambia da un pacchetto all'altro."""
    return json.dumps({
        "sonda": sonda,
        "token": token,
        "scade_at": scade_at,
        "verifica_tls": bool(verifica_tls),
        "etichetta": etichetta,
        "emesso_at": adesso,
        "agente": versione_agente(),
        # Scritto qui perche' chi apre il file lo legga prima di copiarlo altrove.
        "avvertenza": ("Questo file contiene un token valido: vale una volta sola e"
                       " scade all'ora indicata in scade_at. Gli installatori lo"
                       " cancellano dalla macchina appena speso."),
    }, indent=2, ensure_ascii=False)


def costruisci(sonda: str, token: str, scade_at: str, adesso: str,
               verifica_tls: bool = True, etichetta: str = "") -> bytes:
    """L'archivio zip, in memoria.

    In memoria e non su disco: contiene una credenziale, e un file temporaneo con una
    credenziale dentro e' un file che resta li' quando qualcosa va storto.
    """
    radice = radice_agente()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archivio:
        for dentro, fuori in CONTENUTO:
            percorso = radice / fuori
            if not percorso.is_file():
                # Un pacchetto a cui manca un pezzo non si consegna: chi lo riceve
                # scoprirebbe il buco sulla macchina del cliente.
                raise FileNotFoundError("manca dal pacchetto: %s" % percorso)
            informazioni = zipfile.ZipInfo("snap-agent/" + dentro)
            informazioni.date_time = (2026, 1, 1, 0, 0, 0)
            # 0644, e 0755 per cio' che deve partire.
            permessi = 0o755 if dentro in ESEGUIBILI else 0o644
            informazioni.external_attr = (permessi << 16) | 0o100000
            informazioni.compress_type = zipfile.ZIP_DEFLATED
            archivio.writestr(informazioni,
                              percorso.read_bytes())

        manifesto = zipfile.ZipInfo("snap-agent/pacchetto.json")
        manifesto.date_time = (2026, 1, 1, 0, 0, 0)
        manifesto.external_attr = (0o600 << 16) | 0o100000
        manifesto.compress_type = zipfile.ZIP_DEFLATED
        archivio.writestr(manifesto,
                          _manifesto(sonda, token, scade_at, verifica_tls,
                                     etichetta, adesso).encode("utf-8"))
    return buffer.getvalue()


def nome_file(etichetta: str, adesso: str) -> str:
    """Il nome del file scaricato: deve dire a che cosa serve, senza aprirlo.

    L'etichetta finisce nel nome perche' fra dieci pacchetti nella cartella dei
    download l'unica differenza sarebbe l'ora.
    """
    pulita = "".join(c if c.isalnum() or c in "-_" else "-"
                     for c in (etichetta or "").strip().lower())[:40].strip("-")
    giorno = (adesso or "")[:10].replace("-", "")
    pezzi = ["snap-agent"]
    if pulita:
        pezzi.append(pulita)
    if giorno:
        pezzi.append(giorno)
    return "-".join(pezzi) + ".zip"
