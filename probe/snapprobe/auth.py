"""
snap probe - Accesso all'interfaccia locale della sonda.

Perche' esiste, quando prima non serviva: l'interfaccia era raggiungibile solo da
`127.0.0.1` e valeva la decisione DEC-05 -- strumento locale di installazione, nessuna
superficie dall'esterno. Da quando la sonda si puo' aprire alla rete (DEC-05a) quella
premessa non vale piu': senza credenziali, chiunque la raggiunga puo' registrarla
presso un altro server, cambiarne la configurazione o sospendere le scansioni.

Modello di accesso, ridotto a cio' che una sonda richiede:

* **una sola credenziale**, senza elenco utenti e senza ruoli. La sonda ha un solo
  operatore -- chi la installa e chi la assiste -- e un modello a piu' utenti
  aggiungerebbe amministrazione senza aggiungere sicurezza;
* **nessuna password di fabbrica**. Alla prima apertura la password non esiste e va
  impostata: una credenziale predefinita, per quanto ben documentata, e' la prima
  cosa che si prova su un dispositivo trovato in rete;
* **la prima impostazione si fa dalla postazione della sonda** (indirizzo di
  loopback). Se la sonda e' gia' esposta in rete e nessuno ha ancora scelto la
  password, non deve poterla scegliere il primo che passa;
* **hash scrypt** (libreria standard, nessuna dipendenza nuova), tentativi contati e
  blocco temporaneo, come sul server;
* ogni accesso -- riuscito, fallito, bloccato -- **entra nel diario locale**: e' la
  traccia che serve a rispondere a "chi ha toccato questa sonda" (NIS2).

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from datetime import timedelta
from functools import wraps

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from .store import utc_now_str

bp = Blueprint("auth", __name__)

# Chiavi nell'archivio locale. Il prefisso `ui_` distingue cio' che riguarda
# l'interfaccia da cio' che riguarda la raccolta.
CHIAVE_HASH = "ui_password_hash"
CHIAVE_IMPOSTATA = "ui_password_set_at"
CHIAVE_TENTATIVI = "ui_failed_logins"
CHIAVE_BLOCCO = "ui_locked_until"
CHIAVE_ULTIMO_ACCESSO = "ui_last_login_at"

TENTATIVI_MASSIMI = 5
MINUTI_BLOCCO = 15

# Indirizzi che valgono come "la postazione della sonda". Non si accetta un nome:
# un nome si risolve, e cio' che si risolve si puo' dirottare.
INDIRIZZI_LOCALI = {"127.0.0.1", "::1", "localhost"}

# Rotte raggiungibili senza sessione: quelle dell'accesso stesso e i file statici.
# Elenco chiuso (allowlist): una rotta nuova e' protetta per difetto, che e' il
# verso giusto dell'errore.
LIBERE = {"auth.login", "auth.primo_accesso", "static"}


# --------------------------------------------------------------------------- #
# Password
# --------------------------------------------------------------------------- #
def _store():
    return current_app.extensions["snap_store"]


def hash_password(chiaro: str) -> str:
    """Hash con scrypt: algoritmo attuale, dalla libreria standard."""
    return generate_password_hash(chiaro, method="scrypt")


def verifica_password(impronta: str, chiaro: str) -> bool:
    return check_password_hash(impronta, chiaro)


def errori_di_politica(password: str) -> list[str]:
    """Robustezza minima della password; elenco vuoto se va bene.

    Stessa regola del server. Non e' codice condiviso perche' i due applicativi si
    distribuiscono separati (AD-03), ma la regola per l'operatore deve essere una:
    scoprire che la sonda accetta password piu' debole della console sarebbe una
    sorpresa nel verso sbagliato.
    """
    errori: list[str] = []
    if len(password) < 10:
        errori.append("La password deve contenere almeno 10 caratteri.")
    if not any(c.isupper() for c in password):
        errori.append("La password deve contenere almeno una lettera maiuscola.")
    if not any(c.islower() for c in password):
        errori.append("La password deve contenere almeno una lettera minuscola.")
    if not any(c.isdigit() for c in password):
        errori.append("La password deve contenere almeno una cifra.")
    return errori


def password_impostata() -> bool:
    return bool((_store().get_setting(CHIAVE_HASH) or "").strip())


def imposta_password(chiaro: str) -> None:
    store = _store()
    store.set_settings({
        CHIAVE_HASH: hash_password(chiaro),
        CHIAVE_IMPOSTATA: utc_now_str(),
        CHIAVE_TENTATIVI: "0",
        CHIAVE_BLOCCO: "",
    })


# --------------------------------------------------------------------------- #
# Provenienza della richiesta
# --------------------------------------------------------------------------- #
def richiesta_locale() -> bool:
    """La richiesta arriva dalla postazione su cui gira la sonda?

    Si guarda l'indirizzo del chiamante e non un'intestazione: `X-Forwarded-For` la
    scrive chi chiama, e una decisione di sicurezza non si prende su un dato che
    l'interlocutore controlla.
    """
    return (request.remote_addr or "") in INDIRIZZI_LOCALI


# --------------------------------------------------------------------------- #
# Sessione
# --------------------------------------------------------------------------- #
def autenticato() -> bool:
    return bool(session.get("ui_autenticata"))


def apri_sessione() -> None:
    session.clear()
    session["ui_autenticata"] = True
    session["ui_accesso_alle"] = utc_now_str()
    session.permanent = True
    _store().set_setting(CHIAVE_ULTIMO_ACCESSO, utc_now_str())


def chiudi_sessione() -> None:
    session.clear()


# --------------------------------------------------------------------------- #
# Tentativi e blocco
# --------------------------------------------------------------------------- #
def _minuti_di_blocco_residui() -> int:
    """Minuti che restano al blocco, zero se non c'e'."""
    from datetime import datetime, timezone

    from .timefmt import parse_utc

    fino_a = (_store().get_setting(CHIAVE_BLOCCO) or "").strip()
    if not fino_a:
        return 0
    istante = parse_utc(fino_a)
    if istante is None:
        return 0

    residuo = (istante - datetime.now(timezone.utc)).total_seconds()
    return max(0, int(residuo // 60) + (1 if residuo % 60 else 0))


def _registra_fallimento(motivo: str) -> int:
    """Conta il tentativo fallito e, alla soglia, blocca. Restituisce i tentativi."""
    from datetime import datetime, timezone

    store = _store()
    tentativi = int(store.get_setting(CHIAVE_TENTATIVI) or 0) + 1
    valori = {CHIAVE_TENTATIVI: str(tentativi)}
    if tentativi >= TENTATIVI_MASSIMI:
        fino_a = datetime.now(timezone.utc) + timedelta(minutes=MINUTI_BLOCCO)
        valori[CHIAVE_BLOCCO] = fino_a.replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")
        store.log("warning", "Accesso all'interfaccia bloccato per %d minuti dopo %d"
                             " tentativi falliti (da %s)"
                             % (MINUTI_BLOCCO, tentativi, request.remote_addr or "?"))
    else:
        store.log("warning", "Accesso all'interfaccia non riuscito (%s) da %s"
                             % (motivo, request.remote_addr or "?"))
    store.set_settings(valori)
    return tentativi


def _azzera_tentativi() -> None:
    _store().set_settings({CHIAVE_TENTATIVI: "0", CHIAVE_BLOCCO: ""})


# --------------------------------------------------------------------------- #
# Guardia applicata a ogni richiesta
# --------------------------------------------------------------------------- #
def registra_guardia(app) -> None:
    """Installa la guardia: senza sessione si va all'accesso, non alla pagina."""

    @app.before_request
    def _controlla_accesso():
        if request.endpoint in LIBERE or autenticato():
            return None

        # Le richieste in JSON (l'indicatore di attivita' della pagina) ricevono un
        # rifiuto in JSON: una pagina di accesso dentro un fetch verrebbe letta come
        # dato e l'indicatore mostrerebbe numeri inventati.
        if request.path.endswith(".json"):
            return jsonify({"errore": "accesso richiesto"}), 401

        if not password_impostata():
            return redirect(url_for("auth.primo_accesso"))
        return redirect(url_for("auth.login", avanti=request.full_path
                                if request.method == "GET" else None))


def accesso_richiesto(funzione):
    """Guardia per le singole viste, dove serve indipendentemente dal before_request."""

    @wraps(funzione)
    def involucro(*argomenti, **parametri):
        if not autenticato():
            return redirect(url_for("auth.login"))
        return funzione(*argomenti, **parametri)

    return involucro


# --------------------------------------------------------------------------- #
# Rotte
# --------------------------------------------------------------------------- #
@bp.route("/primo-accesso", methods=["GET", "POST"])
def primo_accesso():
    """Scelta della password, alla prima apertura dell'interfaccia."""
    if password_impostata():
        return redirect(url_for("auth.login"))

    # La prima password si sceglie dalla postazione della sonda. Se l'interfaccia
    # e' stata aperta alla rete prima di scegliere una credenziale, il primo che
    # arriva non deve poter diventare il proprietario della sonda.
    if not richiesta_locale():
        # L'indirizzo locale si compone con la porta su cui la sonda sta davvero
        # ascoltando: scriverne una fissa manderebbe altrove chi ha cambiato porta.
        porta = request.host.split(":")[-1] if ":" in request.host else "5510"
        return render_template(
            "primo_accesso.html", solo_locale=True,
            indirizzo=request.remote_addr or "?",
            indirizzo_locale="http://127.0.0.1:%s/primo-accesso" % porta), 403

    if request.method == "POST":
        password = request.form.get("password") or ""
        conferma = request.form.get("conferma") or ""
        errori = errori_di_politica(password)
        if password != conferma:
            errori.append("Le due password non coincidono.")
        if errori:
            for errore in errori:
                flash(errore, "danger")
            return render_template("primo_accesso.html", solo_locale=False), 400

        imposta_password(password)
        _store().log("info", "Password dell'interfaccia impostata dalla postazione locale")
        apri_sessione()
        flash("Password impostata: l'interfaccia della sonda e' ora protetta.", "success")
        return redirect(url_for("probe.index"))

    return render_template("primo_accesso.html", solo_locale=False)


@bp.route("/login", methods=["GET", "POST"])
def login():
    """Accesso con la password dell'interfaccia."""
    if not password_impostata():
        return redirect(url_for("auth.primo_accesso"))
    if autenticato():
        return redirect(url_for("probe.index"))

    bloccato = _minuti_di_blocco_residui()
    if request.method == "POST":
        if bloccato:
            flash("Troppi tentativi: riprovare fra %d minuti." % bloccato, "danger")
            return render_template("login.html", bloccato=bloccato), 429

        password = request.form.get("password") or ""
        impronta = _store().get_setting(CHIAVE_HASH) or ""
        if password and verifica_password(impronta, password):
            _azzera_tentativi()
            apri_sessione()
            _store().log("info", "Accesso all'interfaccia riuscito da %s"
                                 % (request.remote_addr or "?"))
            avanti = request.form.get("avanti") or ""
            # Solo percorsi interni: un indirizzo esterno in questo campo sarebbe
            # un rimando aperto, cioe' un aiuto a chi costruisce un inganno.
            if avanti.startswith("/") and not avanti.startswith("//"):
                return redirect(avanti)
            return redirect(url_for("probe.index"))

        tentativi = _registra_fallimento("password errata")
        restanti = TENTATIVI_MASSIMI - tentativi
        if restanti > 0:
            flash("Password non corretta: %d tentativi prima del blocco." % restanti,
                  "danger")
        else:
            flash("Troppi tentativi: accesso bloccato per %d minuti." % MINUTI_BLOCCO,
                  "danger")
        return render_template("login.html",
                               bloccato=_minuti_di_blocco_residui()), 401

    return render_template("login.html", bloccato=bloccato,
                           avanti=request.args.get("avanti") or "")


@bp.post("/logout")
def logout():
    """Uscita. In POST perche' e' un'azione, e un'azione non si compie con un
    collegamento che qualcuno puo' far seguire al posto tuo."""
    chiudi_sessione()
    flash("Sessione chiusa.", "info")
    return redirect(url_for("auth.login"))


@bp.post("/password")
def cambia_password():
    """Cambio della password dalla pagina di configurazione."""
    if not autenticato():
        return redirect(url_for("auth.login"))

    attuale = request.form.get("attuale") or ""
    nuova = request.form.get("nuova") or ""
    conferma = request.form.get("conferma") or ""
    impronta = _store().get_setting(CHIAVE_HASH) or ""

    if not verifica_password(impronta, attuale):
        _store().log("warning", "Cambio password rifiutato: password attuale errata"
                                " (da %s)" % (request.remote_addr or "?"))
        flash("La password attuale non e' corretta: nessuna modifica applicata.",
              "danger")
        return redirect(url_for("probe.configuration"))

    errori = errori_di_politica(nuova)
    if nuova != conferma:
        errori.append("Le due password non coincidono.")
    if errori:
        for errore in errori:
            flash(errore, "danger")
        return redirect(url_for("probe.configuration"))

    imposta_password(nuova)
    _store().log("info", "Password dell'interfaccia cambiata da %s"
                         % (request.remote_addr or "?"))
    flash("Password aggiornata.", "success")
    return redirect(url_for("probe.configuration"))
