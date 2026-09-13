# -----------------------------------------------------------------
# agent_api.py — il canale fra le macchine sorvegliate e la sonda
# Autore: Daniele Speziale
# Data creazione: 2026-09-13
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap probe - Le macchine parlano alla sonda; la sonda non le chiama mai.

LA DIREZIONE, ANCORA UNA VOLTA
------------------------------
La sonda apre verso il server perche' il server non la raggiunge. Qui vale la stessa
regola un piano piu' sotto: **l'agente apre verso la sonda**. Una macchina in una rete
di utenza non deve essere raggiungibile da nessuno, nemmeno dal prodotto che la
sorveglia -- un servizio in ascolto su ogni postazione sarebbe una superficie in piu'
offerta a chi attacca, per giunta identica su tutte.

Conseguenza pratica: l'agente non riceve comandi. Riceve la propria configurazione
nella risposta all'invio, e la applica al giro successivo.

COME CI SI AUTENTICA
--------------------
1. **Registrazione**: chi installa l'agente porta un token emesso dalla console della
   sonda. Il token vale una volta sola e scade. In cambio l'agente riceve una chiave
   propria; la sonda ne conserva solo l'impronta, cosi' il suo archivio non contiene
   nulla che permetta di firmare al posto di qualcuno.
2. **Invio**: ogni richiesta porta `agent`, `ts`, `nonce` e `firma` --
   HMAC-SHA256 della chiave sul corpo esatto, con dentro identita', istante e nonce.
   La firma lega il messaggio a quell'agente, a quel momento e a quell'invio: non si
   puo' rigiocare altrove, ne' piu' tardi, ne' per conto di un altro.

Perche' non lo stesso protocollo della sonda verso il server (X25519 + AES-GCM): li'
si attraversa Internet e il payload va nascosto; qui si sta sulla rete locale del
cliente, sotto TLS del proxy, e cio' che serve e' sapere CHI parla e che il messaggio
non sia stato ripetuto. Una cifratura in piu' sarebbe complessita' senza un rischio
corrispondente -- e complessita' inutile, in sicurezza, e' un difetto.

remarks: Autore: Daniele Speziale - Data: 2026-09-13
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, jsonify, request

bp = Blueprint("agent_api", __name__, url_prefix="/api/agent")

UTC_FORMAT = "%Y-%m-%d %H:%M:%S"

# Quanto puo' essere vecchia la marca temporale di un invio. Cinque minuti coprono uno
# scarto di orologio ragionevole senza lasciare aperta una finestra in cui un
# messaggio catturato si possa rigiocare.
FINESTRA_SEC = 300

# Quanto vale un token di registrazione. Un'ora basta a installare l'agente su una
# macchina; se serve di piu', se ne emette un altro -- un token che vive per sempre e'
# una credenziale che nessuno ricorda di aver lasciato in giro.
TOKEN_VALIDO_ORE = 1

# Intervallo predefinito fra due invii. Sessanta secondi danno una serie leggibile
# senza pesare: una macchina con l'agente scrive circa 1.400 misure al giorno.
INTERVALLO_PREDEFINITO = 60

VERSIONE_PROTOCOLLO = "SNAP-AGENT/1"


def _adesso() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _testo(momento: datetime) -> str:
    return momento.strftime(UTC_FORMAT)


def impronta(valore: str) -> str:
    return hashlib.sha256(valore.encode("utf-8")).hexdigest()


def emetti_token(store, etichetta: str = "") -> dict:
    """Un token di registrazione, in chiaro una volta sola.

    Chi lo chiede lo vede adesso: dopo resta solo l'impronta. E' la stessa scelta del
    token delle sonde, per la stessa ragione -- un archivio rubato non deve contenere
    credenziali utilizzabili.
    """
    token = secrets.token_urlsafe(32)
    scade = _adesso() + timedelta(hours=TOKEN_VALIDO_ORE)
    store.agent_token_emetti(impronta(token), etichetta, _testo(scade))
    return {"token": token, "scade_at": _testo(scade),
            "valido_ore": TOKEN_VALIDO_ORE}


def _corpo_json() -> dict:
    try:
        dati = request.get_json(force=True, silent=True)
    except Exception:  # noqa: BLE001 - corpo illeggibile: si risponde, non si esplode
        dati = None
    return dati if isinstance(dati, dict) else {}


def _firma_attesa(chiave: str, agent_uid: str, marca: str, nonce: str,
                  corpo: bytes) -> str:
    """La firma lega identita', istante, nonce e CORPO ESATTO.

    Il corpo entra come byte ricevuti, non come oggetto ricomposto: due JSON
    equivalenti ma scritti in modo diverso darebbero firme diverse, e chi verifica
    deve controllare quello che e' arrivato -- non una sua interpretazione.
    """
    messaggio = b"|".join([
        VERSIONE_PROTOCOLLO.encode("ascii"),
        agent_uid.encode("utf-8"),
        marca.encode("ascii"),
        nonce.encode("ascii"),
        corpo,
    ])
    return hmac.new(chiave.encode("utf-8"), messaggio, hashlib.sha256).hexdigest()


def _rifiuta(motivo: str, codice: int = 401):
    """Un rifiuto dice poco a chi bussa e tutto al diario.

    A chi prova non si spiega QUALE verifica non e' passata: sarebbe un modo di
    aiutarlo a capire come passarla. Nel diario della sonda invece si scrive per
    esteso, perche' chi installa un agente deve poter capire perche' non entra.
    """
    current_app.extensions["snap_store"].log("warning", "Agente respinto: %s" % motivo)
    return jsonify({"errore": "non autorizzato"}), codice


def _autentica(store) -> tuple:
    """`(agente, corpo, errore)`. L'errore, se c'e', e' gia' una risposta Flask."""
    corpo_grezzo = request.get_data() or b""
    dati = _corpo_json()
    agent_uid = str(dati.get("agent") or "").strip()
    marca = str(dati.get("ts") or "").strip()
    nonce = str(dati.get("nonce") or "").strip()
    # La firma arriva nell'INTESTAZIONE: il corpo che si verifica e' identico a
    # quello che e' stato firmato, byte per byte.
    firma = str(request.headers.get("X-Snap-Firma") or "").strip()

    if not (agent_uid and marca and nonce and firma):
        return None, None, _rifiuta("invio senza identita', marca o firma")

    agente = store.agent(agent_uid)
    if agente is None or agente.get("revocato_at") or agente.get("stato") != "attivo":
        return None, None, _rifiuta("agente sconosciuto o revocato: %s" % agent_uid)

    # La marca temporale prima della firma: un messaggio vecchio non merita nemmeno
    # il costo di un confronto crittografico.
    try:
        quando = datetime.strptime(marca, UTC_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None, None, _rifiuta("marca temporale illeggibile da %s" % agent_uid)
    scarto = abs((_adesso() - quando).total_seconds())
    if scarto > FINESTRA_SEC:
        return None, None, _rifiuta(
            "marca temporale fuori finestra (%d s) da %s" % (scarto, agent_uid))

    # La firma si confronta a tempo costante: un confronto normale perde tempo in
    # proporzione ai caratteri uguali, e quel tempo si misura.
    chiave = agente.get("chiave_hash") or ""
    atteso = _firma_attesa(chiave, agent_uid, marca, nonce, corpo_grezzo)
    if not hmac.compare_digest(atteso, firma):
        return None, None, _rifiuta("firma non valida da %s" % agent_uid)

    if not store.agent_nonce_nuovo(nonce, agent_uid):
        return None, None, _rifiuta("invio ripetuto (nonce gia' visto) da %s" % agent_uid)

    return agente, dati, None


@bp.post("/enroll")
def enroll():
    """Registrazione di una macchina, con il token emesso dalla console.

    La chiave che l'agente ricevera' e' generata QUI e mostrata una volta sola: se si
    perde, si registra di nuovo. Conservarla in chiaro sulla sonda significherebbe
    che chi legge l'archivio puo' firmare per conto di ogni macchina.
    """
    store = current_app.extensions["snap_store"]
    dati = _corpo_json()
    token = str(dati.get("token") or "").strip()
    hostname = str(dati.get("hostname") or "").strip()[:200]
    if not token or not hostname:
        return jsonify({"errore": "token e hostname sono obbligatori"}), 400

    agent_uid = "%s-%s" % (hostname.lower().replace(" ", "-")[:40],
                           secrets.token_hex(4))
    if not store.agent_token_consuma(impronta(token), agent_uid):
        # Non c'e', e' scaduto o e' gia' stato usato: per chi bussa la risposta e'
        # la stessa. Distinguere aiuterebbe solo chi sta provando token a caso.
        store.log("warning", "Registrazione agente rifiutata da %s: token non valido"
                  % hostname)
        return jsonify({"errore": "token non valido"}), 403

    chiave = secrets.token_urlsafe(48)
    store.agent_registra(
        agent_uid=agent_uid,
        hostname=hostname,
        ip=(request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip(),
        sistema=str(dati.get("sistema") or "")[:200],
        versione=str(dati.get("versione") or "")[:40],
        # La chiave si conserva com'e' perche' serve a VERIFICARE una firma: a
        # differenza di una password, non si puo' confrontare un'impronta. Sta in un
        # archivio che vive sulla macchina della sonda, protetto come il resto.
        chiave_hash=chiave,
        intervallo=INTERVALLO_PREDEFINITO,
    )
    store.log("info", "Agente registrato: %s (%s)" % (hostname, agent_uid))
    return jsonify({
        "agent": agent_uid,
        "chiave": chiave,
        "intervallo": INTERVALLO_PREDEFINITO,
        "protocollo": VERSIONE_PROTOCOLLO,
    })


@bp.post("/report")
def report():
    """Un invio: misure, eventi, e la configurazione in risposta."""
    store = current_app.extensions["snap_store"]
    agente, dati, errore = _autentica(store)
    if errore is not None:
        return errore

    adesso = _testo(_adesso())
    misure = dati.get("misure") if isinstance(dati.get("misure"), dict) else {}
    eventi = dati.get("eventi") if isinstance(dati.get("eventi"), list) else []
    inventario = (dati.get("inventario")
                  if isinstance(dati.get("inventario"), dict) else None)

    if misure:
        store.agent_metriche_scrivi(agente["agent_uid"], adesso, misure)

    # L'INVENTARIO ARRIVA DI RADO -- una volta all'ora, o appena cambiano le porte in
    # ascolto -- e SOSTITUISCE il precedente invece di accodarsi. Vedi
    # `Raccolta.inventario` nell'agente per il perche' non viaggia con le misure.
    if inventario:
        store.agent_inventario_scrivi(agente["agent_uid"], inventario)

    accettati = 0
    for evento in eventi[:200]:
        if not isinstance(evento, dict):
            continue
        genere = str(evento.get("genere") or "").strip()[:60]
        messaggio = str(evento.get("messaggio") or "").strip()[:1000]
        if not genere or not messaggio:
            continue
        store.agent_evento_scrivi(
            agent_uid=agente["agent_uid"],
            genere=genere,
            gravita=str(evento.get("gravita") or "info")[:20],
            soggetto=str(evento.get("soggetto") or "")[:200] or None,
            messaggio=messaggio,
            dati=evento.get("dati") if isinstance(evento.get("dati"), dict) else {},
            avvenuto_at=str(evento.get("avvenuto_at") or adesso)[:19],
        )
        accettati += 1

    # La risposta porta la configurazione: e' l'unico modo che la sonda ha di
    # influenzare l'agente, e non e' un comando -- e' un'impostazione che l'agente
    # applica al giro successivo.
    return jsonify({
        "ricevuto": True,
        "eventi_accettati": accettati,
        "inventario_ricevuto": bool(inventario),
        "configurazione": {
            "intervallo": int(agente.get("intervallo") or INTERVALLO_PREDEFINITO),
            "soglie": {"disco_percento": 90, "cpu_percento": 95,
                       "accessi_falliti": 5},
        },
        "server_time": adesso,
    })


@bp.get("/ping")
def ping():
    """Verifica che il canale esista, senza autenticazione e senza dire nulla.

    Serve a chi installa: se questa non risponde, il problema e' la rete o il proxy,
    non la chiave. Non rivela nulla della sonda -- nemmeno la versione: chi bussa
    senza credenziali non ha diritto a un inventario.
    """
    return jsonify({"protocollo": VERSIONE_PROTOCOLLO, "pronto": True})
