"""
snap probe - Interfaccia locale della sonda.

Ambito volutamente ristretto: registrazione presso il server, configurazione
operativa, diagnostica della coda e del diario. Nessuna consultazione dei dati
raccolti: la loro sede e' il server.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re

from flask import (
    jsonify,
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from .crypto import CryptoError
from .client import ProtocolError, TransportError, parse_bundle
from .store import utc_now_str

bp = Blueprint("probe", __name__)

CODE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")


def _store():
    return current_app.extensions["snap_store"]


def _agent():
    return current_app.extensions["snap_agent"]


def _riquadri_stato(agente, store) -> list[dict]:
    """I riquadri di sintesi della dashboard, calcolati una volta sola.

    La pagina li disegna e la rotta di stato (`status.json`) li rimanda uguali, cosi'
    l'aggiornamento via AJAX aggiorna i contatori senza ricaricare la pagina e senza
    duplicare la logica dei colori e delle note in JavaScript: qui c'e' la verita', il
    client la applica soltanto.
    """
    stato = agente.status()
    scan = agente.scan_status()
    impostazioni = store.all_settings()
    ago = current_app.jinja_env.filters["ago"]
    dt = current_app.jinja_env.filters["dt"]
    fuso = store.get_setting("tenant_timezone") or "UTC"

    registrata = bool(stato.get("enrolled"))
    online = bool(stato.get("online"))
    coda = int(stato.get("queue_size") or 0)
    sospesa = bool(scan.get("paused_locally") or not scan.get("enabled_by_server"))
    ultimo = impostazioni.get("last_sync_at")
    prossima = scan.get("next_due")
    confermati = int(scan.get("nodes_confirmed") or 0)
    candidati = int(scan.get("nodes_candidate") or 0)
    profili = int(scan.get("profiles_pending") or 0)

    def nota_scansione() -> str:
        if not scan.get("enabled_by_server"):
            return "disabilitata dal server"
        if scan.get("paused_locally"):
            return "sospesa in locale"
        if prossima:
            return "%s su %s" % (prossima[0], prossima[1])
        return "nessuna fase scaduta"

    return [
        {"key": "canale", "etichetta": "CANALE VERSO IL SERVER", "icona": "bi-shield-lock",
         "valore": ("Attivo" if online else "In attesa") if registrata else "Non registrata",
         "tono": ("success" if online else "warning") if registrata else "secondary",
         "nota": impostazioni.get("server_url") or "server non configurato"},
        {"key": "coda", "etichetta": "CODA LOCALE", "valore": coda, "icona": "bi-inboxes",
         "tono": "warning" if coda else "success",
         "nota": ("in attesa dal " + dt(stato.get("oldest_queued_at")))
                 if stato.get("oldest_queued_at") else "nessun dato in attesa"},
        {"key": "raccolta", "etichetta": "RACCOLTA", "icona": "bi-arrow-repeat",
         "valore": "Sospesa" if stato.get("paused") else "Attiva",
         "tono": "warning" if stato.get("paused") else "success",
         "nota": "ogni %s secondi" % impostazioni.get("scan_interval_sec", "300")},
        {"key": "nodi_confermati", "etichetta": "NODI CONFERMATI", "valore": confermati,
         "icona": "bi-hdd-network", "tono": "info" if confermati else "secondary",
         "nota": "%d candidati, %d profili da completare" % (candidati, profili)},
        {"key": "scansione", "etichetta": "SCANSIONE", "icona": "bi-radar",
         "valore": "Sospesa" if sospesa else "In corso",
         "tono": "warning" if sospesa else "success", "nota": nota_scansione()},
        {"key": "ultimo_conferimento", "etichetta": "ULTIMO CONFERIMENTO",
         "icona": "bi-cloud-arrow-up", "valore": ago(ultimo) if ultimo else "mai",
         "tono": "success" if ultimo else "secondary",
         "nota": ("%s · fuso %s" % (dt(ultimo), fuso)) if ultimo
                 else "nessun lotto ancora inviato"},
    ]


@bp.get("/")
def index():
    """Stato della sonda: registrazione, coda, ultimi conferimenti."""
    store = _store()
    agente = _agent()
    conferimenti = store.recent_syncs(30)
    # Dal piu' vecchio al piu' recente: e' l'ordine in cui un andamento si legge,
    # mentre la tabella resta dal piu' recente, che e' l'ordine in cui si cerca.
    punti = [[riga["created_at"], int(riga["records"] or 0)]
             for riga in reversed(conferimenti)]
    return render_template(
        "index.html",
        status=agente.status(),
        scan=agente.scan_status(),
        riquadri=_riquadri_stato(agente, store),
        syncs=conferimenti[:10],
        conferimenti_punti=punti,
        events=store.recent_events(12),
    )


# --------------------------------------------------------------------------- #
# Registrazione
# --------------------------------------------------------------------------- #
@bp.get("/enroll")
def enroll_form():
    """Modulo di registrazione, raggiungibile in qualunque stato della sonda.

    A sonda gia' registrata la pagina non rimanda altrove: mostra la
    registrazione in essere e consente di sostituirla, che e' l'operazione
    necessaria quando il server emette un nuovo pacchetto.
    """
    store = _store()
    return render_template("enroll.html", form={}, already=store.is_enrolled())


@bp.post("/enroll")
def enroll():
    """Registrazione con pacchetto unico oppure con i tre valori separati."""
    store = _store()
    agent = _agent()

    already = store.is_enrolled()
    if already and not request.form.get("replace"):
        flash(
            "La sonda e' gia' registrata: per usare un nuovo pacchetto occorre"
            " confermare la sostituzione della registrazione esistente.",
            "warning",
        )
        return render_template("enroll.html", form=request.form, already=True), 400

    bundle = (request.form.get("bundle") or "").strip()
    if bundle:
        try:
            parameters = parse_bundle(bundle)
        except ValueError as exc:
            flash("Pacchetto di registrazione non valido: %s" % exc, "danger")
            return render_template("enroll.html", form=request.form), 400
    else:
        parameters = {
            "server_url": (request.form.get("server_url") or "").strip().rstrip("/"),
            "probe_code": (request.form.get("probe_code") or "").strip().lower(),
            "enrollment_token": (request.form.get("enrollment_token") or "").strip(),
        }
        if not all(parameters.values()):
            flash("Compilare il pacchetto oppure tutti e tre i campi manuali.", "warning")
            return render_template("enroll.html", form=request.form), 400
        if not parameters["server_url"].startswith(("http://", "https://")):
            flash("L'URL del server deve iniziare con http:// oppure https://", "warning")
            return render_template("enroll.html", form=request.form), 400
        if not CODE_PATTERN.match(parameters["probe_code"]):
            flash("Codice sonda non valido.", "warning")
            return render_template("enroll.html", form=request.form), 400

    # La registrazione in essere viene messa da parte e non eliminata: se il
    # nuovo pacchetto non e' valido o il server non risponde, viene ripristinata.
    snapshot = None
    if already:
        snapshot = store.snapshot_enrollment()
        precedente = store.get_setting("probe_code", "n.d.")
        store.reset_enrollment()
        store.log(
            "warning",
            "Sostituzione della registrazione richiesta dall'interfaccia"
            " (precedente: %s)" % precedente,
        )

    try:
        agent.client.enroll(**parameters)
    except TransportError as exc:
        if snapshot:
            store.restore_enrollment(snapshot)
        flash(
            "Server non raggiungibile: %s%s" % (
                exc,
                " La registrazione precedente e' stata ripristinata." if snapshot else "",
            ),
            "danger",
        )
        store.log("error", "Registrazione non riuscita (trasporto): %s" % exc)
        return render_template("enroll.html", form=request.form,
                               already=store.is_enrolled()), 502
    except (ProtocolError, CryptoError, ValueError) as exc:
        if snapshot:
            store.restore_enrollment(snapshot)
        flash(
            "Registrazione rifiutata: %s%s" % (
                exc,
                " La registrazione precedente e' stata ripristinata." if snapshot else "",
            ),
            "danger",
        )
        store.log("error", "Registrazione non riuscita: %s" % exc)
        return render_template("enroll.html", form=request.form,
                               already=store.is_enrolled()), 400

    flash(
        "Registrazione completata: la sonda e' operativa sul tenant %s."
        % (store.get_setting("tenant_name") or store.get_setting("tenant_code") or "n.d."),
        "success",
    )
    agent.wake()
    return redirect(url_for("probe.index"))


@bp.post("/enroll/reset")
def enroll_reset():
    """Dimentica il server mantenendo i dati raccolti in coda."""
    store = _store()
    if (request.form.get("confirm") or "").strip().upper() != "AZZERA":
        flash(
            "Per azzerare la registrazione digitare la parola AZZERA nel campo di"
            " conferma. Nessuna modifica effettuata. Per registrare la sonda su un"
            " nuovo pacchetto non serve azzerare: usare la voce Registrazione.",
            "warning",
        )
        return redirect(url_for("probe.configuration"))

    store.reset_enrollment()
    flash("Registrazione azzerata: i dati in coda sono stati conservati.", "warning")
    return redirect(url_for("probe.index"))


# --------------------------------------------------------------------------- #
# Configurazione
# --------------------------------------------------------------------------- #
@bp.get("/configuration")
def configuration():
    store = _store()
    return render_template(
        "configuration.html",
        status=_agent().status(),
        options=store.get_json("server_options", {}) or {},
        queue=store.queue_preview(40),
    )


@bp.post("/configuration")
def save_configuration():
    """Parametri locali: intervallo di raccolta e sospensione della raccolta.

    L'intervallo viene comunque riallineato dal server al contatto successivo:
    qui si imposta il valore usato in autonomia.
    """
    store = _store()
    try:
        interval = int(request.form.get("scan_interval_sec") or 300)
    except ValueError:
        flash("Intervallo di raccolta non valido.", "warning")
        return redirect(url_for("probe.configuration"))

    if not 30 <= interval <= 86400:
        flash("L'intervallo deve essere compreso fra 30 e 86400 secondi.", "warning")
        return redirect(url_for("probe.configuration"))

    store.set_settings(
        {
            "scan_interval_sec": interval,
            "paused": "1" if request.form.get("paused") else "0",
        }
    )
    store.log("info", "Configurazione locale aggiornata (intervallo %d s)" % interval)
    flash("Configurazione locale salvata.", "success")
    return redirect(url_for("probe.configuration"))


@bp.post("/server-url")
def update_server_url():
    """Aggiorna l'indirizzo del server (es. cambio di rete o di porta)."""
    store = _store()
    url = (request.form.get("server_url") or "").strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        flash("L'URL del server deve iniziare con http:// oppure https://", "warning")
        return redirect(url_for("probe.configuration"))

    store.set_setting("server_url", url)
    store.log("info", "Indirizzo del server aggiornato a %s" % url)
    flash("Indirizzo del server aggiornato.", "success")
    return redirect(url_for("probe.configuration"))


# --------------------------------------------------------------------------- #
# Azioni operative
# --------------------------------------------------------------------------- #
@bp.post("/actions/collect")
def action_collect():
    """Forza un ciclo di raccolta immediato."""
    agent = _agent()
    outcome = agent.collector.collect()
    flash(
        "Raccolta eseguita: ciclo %d, %d record accodati."
        % (outcome["cycle"], outcome["events"]),
        "success",
    )
    return redirect(request.referrer or url_for("probe.index"))


@bp.post("/actions/flush")
def action_flush():
    """Tenta il conferimento immediato della coda."""
    store = _store()
    agent = _agent()
    if not store.is_enrolled():
        flash("Sonda non registrata: conferimento non possibile.", "warning")
        return redirect(url_for("probe.index"))

    queued_before = store.queue_size()
    outcome = agent.flush_queue()
    if outcome["records"]:
        flash(
            "Conferiti %d record in %d lotti; in coda restano %d record."
            % (outcome["records"], outcome["batches"], outcome["remaining"]),
            "success",
        )
    elif queued_before == 0:
        # L'agente in background puo' avere gia' conferito la coda: non e' un errore.
        flash("Nessun dato in attesa: la coda locale e' gia' vuota.", "info")
    else:
        flash(
            "Conferimento non riuscito: %s"
            % (agent.last_error or "server non raggiungibile"),
            "warning",
        )
    return redirect(request.referrer or url_for("probe.index"))


@bp.post("/actions/test")
def action_test():
    """Verifica la raggiungibilita' del server senza inviare dati."""
    agent = _agent()
    try:
        answer = agent.client.ping()
    except TransportError as exc:
        flash("Server non raggiungibile: %s" % exc, "danger")
        return redirect(request.referrer or url_for("probe.index"))
    except ProtocolError as exc:
        flash("Configurazione incompleta: %s" % exc, "warning")
        return redirect(request.referrer or url_for("probe.index"))

    flash(
        "Server raggiungibile: %s, protocollo %s, ora %s."
        % (answer.get("service"), answer.get("protocol"), answer.get("server_time")),
        "success",
    )
    return redirect(request.referrer or url_for("probe.index"))


@bp.post("/actions/queue/clear")
def action_clear_queue():
    store = _store()
    if (request.form.get("confirm") or "").strip().upper() != "SVUOTA":
        flash(
            "Per svuotare la coda digitare la parola SVUOTA nel campo di conferma."
            " Nessun record eliminato.",
            "warning",
        )
        return redirect(url_for("probe.configuration"))

    removed = store.clear_queue()
    store.log("warning", "Coda locale svuotata manualmente (%d record)" % removed)
    flash("Coda svuotata: %d record eliminati senza conferimento." % removed, "warning")
    return redirect(url_for("probe.configuration"))


@bp.post("/actions/scan/toggle")
def action_toggle_scan():
    """Sospende o riprende le scansioni di rete su decisione del tecnico.

    Non tocca il dialogo con il server: la sonda continua a conferire la coda e a
    ricevere configurazione e comandi.
    """
    store = _store()
    sospeso = store.get_setting("scan_paused", "0") == "1"
    store.set_setting("scan_paused", "0" if sospeso else "1")
    store.log("info" if sospeso else "warning",
              "Scansioni %s dalla sonda" % ("riprese" if sospeso else "sospese"))
    store.enqueue("event", {
        "type": "probe.scan.resumed" if sospeso else "probe.scan.paused",
        "severity": "info" if sospeso else "warning",
        "description": "Scansioni %s dall'interfaccia locale della sonda"
                       % ("riprese" if sospeso else "sospese"),
        "created_at": utc_now_str(),
    })
    flash("Scansioni %s." % ("riprese" if sospeso else "sospese"),
          "success" if sospeso else "warning")
    return redirect(url_for("probe.index"))


@bp.get("/status.json")
def status_json():
    """Stato corrente in JSON, per l'indicatore di attivita' della pagina.

    Serve un aggiornamento ogni pochi secondi: la pagina intera si ricarica ogni
    trenta, che e' troppo lento per capire se una scansione sta procedendo.
    """
    agente = _agent()
    scansione = agente.scan_status()
    stato = agente.status()
    perimetro = int(scansione.get("subnets_total") or 0)
    scoperte = min(int(scansione.get("subnets_scanned") or 0), perimetro)
    conferiti = int(scansione.get("nodes_conferred") or 0)
    attesa = int(scansione.get("profiles_pending") or 0)
    in_corso = int(scansione.get("running_scans") or 0)

    return jsonify({
        # L'attivita' vera e' il numero di esecuzioni di nmap: le prenotazioni
        # possono sopravvivere a un processo terminato e mentirebbero.
        "attiva": bool(in_corso),
        "consentita": bool(scansione.get("scanning_allowed")),
        "motivo_sospensione": scansione.get("suspended_reason") or "",
        "scansioni_in_corso": in_corso,
        "thread": int(scansione.get("workers") or 1),
        "thread_massimi": int(scansione.get("max_workers") or 1),
        "sforzo": scansione.get("effort"),
        "tempo_per_host": scansione.get("host_timeout"),
        "tempo_per_host_scelto": scansione.get("host_timeout_chosen"),
        "sforzo_dal_server": scansione.get("effort_from_server"),
        "tempo_per_host_dal_server": scansione.get("host_timeout_from_server"),
        "fasi_in_corso": scansione.get("phases_in_flight") or [],
        # Fase, bersagli e secondi trascorsi di ciascuna esecuzione: un tempo che
        # avanza distingue il lavoro in corso da un blocco.
        "esecuzioni": [
            {"descrizione": e.get("label"), "da_secondi": int(e.get("elapsed_seconds") or 0)}
            for e in (scansione.get("running_executions") or [])
        ],
        "prossima_fase": (list(scansione["next_due"]) if scansione.get("next_due") else None),
        "perimetro_subnet": perimetro,
        "perimetro_scoperte": scoperte,
        "perimetro_percento": round(100.0 * scoperte / perimetro, 1) if perimetro else 0.0,
        "profili_conferiti": conferiti,
        "profili_in_attesa": attesa,
        "profili_percento": (round(100.0 * conferiti / (conferiti + attesa), 1)
                             if (conferiti + attesa) else 0.0),
        "nodi_confermati": int(scansione.get("nodes_confirmed") or 0),
        "nodi_candidati": int(scansione.get("nodes_candidate") or 0),
        "coda": int(stato.get("queue_size") or 0),
        "online": bool(stato.get("online")),
        # I riquadri di sintesi gia' pronti (valore, colore, nota): la pagina li disegna
        # a lato server e qui li rimanda uguali, cosi' il client aggiorna i contatori
        # senza ricaricare e senza rifare la logica dei colori.
        "riquadri": [{"key": r["key"], "valore": r["valore"], "tono": r["tono"],
                      "nota": r["nota"]} for r in _riquadri_stato(agente, _store())],
        "aggiornato_alle": utc_now_str(),
    })


@bp.post("/actions/scan/host-timeout")
def action_host_timeout():
    """Imposta il tempo massimo per host dall'interfaccia locale della sonda."""
    from .scanner import HOST_TIMEOUT_CHOICES, parse_timeout

    store = _store()
    valore = (request.form.get("host_timeout") or "").strip()
    if valore and parse_timeout(valore) is None:
        flash("Tempo massimo per host non utilizzabile: valori possibili %s, oppure vuoto "
              "per quello del profilo." % ", ".join(HOST_TIMEOUT_CHOICES), "warning")
        return redirect(url_for("probe.index"))

    store.set_setting("scan_host_timeout", valore)
    store.log("info", "Tempo massimo per host portato a '%s' dalla sonda"
              % (valore or "quello del profilo di sforzo"))
    flash("Tempo massimo per host: %s." % (valore or "quello del profilo di sforzo"), "success")
    return redirect(url_for("probe.index"))


@bp.post("/actions/scan/effort")
def action_scan_effort():
    """Imposta il profilo di sforzo dall'interfaccia locale della sonda."""
    from .scanner import EFFORT_PROFILES

    store = _store()
    valore = (request.form.get("effort") or "").strip().lower()
    if valore not in EFFORT_PROFILES:
        flash("Profilo di sforzo non riconosciuto: ammessi %s."
              % ", ".join(EFFORT_PROFILES), "warning")
        return redirect(url_for("probe.index"))
    store.set_setting("scan_effort", valore)
    store.log("info", "Profilo di sforzo portato a '%s' dalla sonda" % valore)
    flash("Profilo di sforzo: %s (%s)." % (valore, EFFORT_PROFILES[valore]["label"]), "success")
    return redirect(url_for("probe.index"))


@bp.post("/actions/collector/reset")
def action_reset_collector():
    """Azzera il conteggio dei cicli di raccolta."""
    agent = _agent()
    agent.collector.reset()
    flash("Conteggio dei cicli di raccolta azzerato.", "info")
    return redirect(url_for("probe.configuration"))


# Parole di conferma dell'azzeramento. Sono diverse fra loro perche' le due azioni
# hanno conseguenze diverse: chi vuole azzerare i dati non deve poter cancellare la
# registrazione per una parola digitata di fretta.
RESET_WORDS = {"dati": "AZZERA I DATI", "tutto": "AZZERA TUTTO"}


@bp.post("/actions/reset")
def action_reset():
    """Azzera l'archivio locale, con o senza la registrazione."""
    agent = _agent()
    store = _store()
    ambito = (request.form.get("scope") or "").strip().lower()
    if ambito not in RESET_WORDS:
        flash("Ambito di azzeramento non riconosciuto: nessuna modifica effettuata.",
              "warning")
        return redirect(url_for("probe.configuration"))

    attesa = RESET_WORDS[ambito]
    if (request.form.get("confirm") or "").strip().upper() != attesa:
        flash("Per azzerare l'archivio digitare esattamente %s nel campo di conferma."
              " Nessun dato eliminato." % attesa, "warning")
        return redirect(url_for("probe.configuration"))

    prima = store.footprint()
    rimosse = agent.reset_store(keep_enrollment=(ambito == "dati"))
    dopo = store.footprint()

    dati = sum(v for k, v in rimosse.items()
               if k not in ("settings", "nmap_terminati"))
    dettaglio = ("Archivio azzerato: %d righe di dati rimosse, %d impostazioni,"
                 " %d processi di nmap terminati. Spazio liberato: %.1f MB."
                 % (dati, max(0, rimosse.get("settings", 0)),
                    rimosse.get("nmap_terminati", 0), max(0, prima - dopo) / 1048576.0))

    if ambito == "tutto":
        flash(dettaglio + " La registrazione e' stata rimossa: la sonda va registrata"
                          " di nuovo prima di riprendere.", "warning")
        return redirect(url_for("probe.enroll_form"))

    flash(dettaglio + " La registrazione e' stata conservata: al prossimo contatto la"
                      " sonda riceve di nuovo perimetro e controlli, e riparte dalla"
                      " scoperta.", "warning")
    return redirect(url_for("probe.index"))


@bp.get("/guida")
def guide():
    """Guida della sonda, come documento a se'.

    Non richiede alcun accorgimento particolare: l'interfaccia della sonda ascolta
    solo su 127.0.0.1, e chi puo' aprirla e' gia' sulla macchina.
    """
    return render_template("guide.html")


@bp.get("/diary")
def diary():
    store = _store()
    return render_template(
        "diary.html",
        events=store.recent_events(200),
        syncs=store.recent_syncs(50),
    )
