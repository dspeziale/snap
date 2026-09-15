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
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .crypto import CryptoError
from .client import ProtocolError, TransportError, parse_bundle
from .store import utc_now_str

bp = Blueprint("probe", __name__)

CODE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")


# Entro quanto l'agente si accorge di un cambio sull'osservazione del traffico: e' il
# suo giro di ciclo. Si dichiara all'operatore invece di lasciarlo nell'incertezza --
# un interruttore che non fa niente per quindici secondi sembra rotto.
_ATTESA_CATTURA_SEC = 15


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
    from . import snmp_raccolta

    store = _store()
    return render_template(
        "configuration.html",
        traffico=_stato_traffico(),
        status=_agent().status(),
        options=store.get_json("server_options", {}) or {},
        queue=store.queue_preview(40),
        # SNMP: si passa l'elenco degli apparati e SE una community e' impostata,
        # non la community. Un segreto non torna alla pagina che lo ha ricevuto.
        snmp_devices=store.get_setting(snmp_raccolta.CHIAVE_APPARATI, "") or "",
        snmp_enabled=str(store.get_setting(snmp_raccolta.CHIAVE_ATTIVA, "0")) == "1",
        snmp_community_impostata=bool(
            (store.get_setting(snmp_raccolta.CHIAVE_COMMUNITY, "") or "").strip()),
        snmp_corrispondenze=store.conteggio_arp_snmp(),
        snmp_ultima=store.get_setting("last_snmp_at", "") or "",
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


@bp.get("/pacchetti")
def pacchetti():
    """Che cosa sta passando sul filo, adesso.

    E' la pagina che mancava: il sensore produceva rilevazioni senza far vedere su che
    cosa lavorava, e un sensore cosi' si accende una volta e non si accende piu'. Qui
    si guardano i pacchetti gia' letti -- i loro campi -- si cerca dentro, e si vede
    chi parla con chi.

    Quello che NON c'e', e non perche' sia stato tolto: il contenuto. Non e' mai stato
    letto (vedi `traffico.py`), quindi non c'e' niente da nascondere qui.
    """
    from . import ids as modulo_ids

    store = _store()
    cerca = (request.args.get("cerca") or "").strip()[:80]
    protocollo = (request.args.get("protocollo") or "").strip()[:20]
    return render_template(
        "pacchetti.html",
        attiva=store.get_setting(modulo_ids.CHIAVE_TRAFFICO_ATTIVO, "0") == "1",
        traffico=_stato_traffico(),
        riepilogo=store.traffico_riepilogo(),
        pacchetti=store.traffico_pacchetti(limite=800, cerca=cerca,
                                           protocollo=protocollo),
        conversazioni=store.traffico_conversazioni(limite=120),
        nomi=store.traffico_nomi(limite=120),
        cerca=cerca,
        protocollo=protocollo,
        minuti=store.TRAFFICO_MINUTI,
        righe_massime=store.TRAFFICO_RIGHE_MASSIME,
    )


@bp.get("/pacchetti.json")
def pacchetti_json():
    """Gli ultimi pacchetti, per l'aggiornamento della pagina senza ricaricarla.

    Stessa forma della pagina: la verita' sta qui, il client la disegna soltanto.
    """
    store = _store()
    cerca = (request.args.get("cerca") or "").strip()[:80]
    protocollo = (request.args.get("protocollo") or "").strip()[:20]
    return jsonify({
        "riepilogo": store.traffico_riepilogo(),
        "pacchetti": store.traffico_pacchetti(limite=200, cerca=cerca,
                                              protocollo=protocollo),
    })


def _stato_traffico() -> dict:
    """Che cosa mostrare nella scheda dell'osservazione del traffico.

    Le interfacce si chiedono alla libreria a ogni apertura della pagina e non si
    conservano: cambiano quando si attacca una scheda, e un elenco vecchio farebbe
    scegliere un'interfaccia che non c'e' piu'.
    """
    from . import cattura as modulo_cattura
    from . import ids as modulo_ids

    store = _store()
    assenza = modulo_cattura.motivo_assenza()
    elenco = []
    if not assenza:
        try:
            elenco = [i for i in modulo_cattura.interfacce() if not i["loopback"]]
        except modulo_cattura.ErroreCattura as errore:
            assenza = str(errore)

    # NON si guarda l'oggetto `Cattura` di questo processo: la cattura vive in quello
    # dell'agente (e' l'unico che possa travasare i pacchetti nell'archivio), quindi
    # qui non c'e' mai. Cercarlo qui faceva dichiarare "la cattura non e' partita"
    # mentre la pagina Pacchetti mostrava il traffico appena arrivato.
    in_ascolto = modulo_ids.cattura_in_ascolto(store)
    # I CONTATORI li pubblica l'agente a ogni giro: interfaccia, letti, scartati. Non
    # esistono fuori dal processo che cattura, e la pagina ne mostra tre -- cercarli
    # qui in memoria la faceva sollevare.
    contatori = dict(modulo_ids.contatori_cattura(store))
    contatori["viva"] = in_ascolto
    # OGNI CHIAVE CHE LA PAGINA LEGGE DEVE ESISTERE, anche quando i contatori non
    # sono ancora arrivati: fra l'accensione e il primo giro dell'agente passano fino
    # a quindici secondi, e in quella finestra la cattura risulta viva ma senza
    # numeri. E' la finestra in cui la pagina Configurazione sollevava.
    contatori.setdefault("interfaccia",
                         store.get_setting(modulo_ids.CHIAVE_TRAFFICO_INTERFACCIA, ""))
    contatori.setdefault("scartati", 0)
    # Quanti ne sono arrivati in ARCHIVIO: numero diverso da quelli letti, e l'unico
    # che sopravviva a un riavvio del processo che cattura.
    contatori.setdefault("pacchetti", store.traffico_riepilogo()["pacchetti"])
    return {
        "possibile": not assenza,
        "motivo": assenza,
        "interfacce": elenco,
        "attiva": store.get_setting(modulo_ids.CHIAVE_TRAFFICO_ATTIVO, "0") == "1",
        "interfaccia": store.get_setting(modulo_ids.CHIAVE_TRAFFICO_INTERFACCIA, ""),
        "filtro": store.get_setting(modulo_ids.CHIAVE_TRAFFICO_FILTRO, ""),
        "filtro_predefinito": modulo_cattura.FILTRO_PREDEFINITO,
        "errore": store.get_setting(modulo_ids.CHIAVE_TRAFFICO_ERRORE, ""),
        "stato": contatori,
    }


@bp.post("/traffico")
def save_traffico():
    """Accende o spegne l'osservazione del traffico, e dice su che cosa.

    E' l'unica impostazione della sonda che riguarda il traffico di PERSONE, e per
    questo non ha un valore predefinito acceso: chi la accende lo fa sapendo che cosa
    viene letto (intestazioni e nomi in chiaro) e che cosa no (il contenuto). La
    scelta finisce nel diario con l'interfaccia, perche' fra un mese si deve poter
    sapere da quando quella rete e' osservata.
    """
    from . import ids as modulo_ids

    store = _store()
    attiva = bool(request.form.get("traffico_attivo"))
    interfaccia = (request.form.get("traffico_interfaccia") or "").strip()
    filtro = (request.form.get("traffico_filtro") or "").strip()

    if attiva and not interfaccia:
        flash("Per osservare il traffico serve scegliere un'interfaccia.", "warning")
        return redirect(url_for("probe.configuration"))

    store.set_settings({
        modulo_ids.CHIAVE_TRAFFICO_ATTIVO: "1" if attiva else "0",
        modulo_ids.CHIAVE_TRAFFICO_INTERFACCIA: interfaccia,
        modulo_ids.CHIAVE_TRAFFICO_FILTRO: filtro,
    })

    # QUI SI SCRIVE SOLTANTO. La cattura la avvia l'agente di raccolta, che e' un
    # ALTRO PROCESSO: e' l'unico che poi travasa i pacchetti nell'archivio, e quindi
    # l'unico che possa farli comparire nella pagina Pacchetti.
    #
    # Prima la avviava questo processo, e sembrava funzionare: il diario diceva
    # "avviata", il sensore risultava attivo, e non compariva un pacchetto -- perche'
    # finivano in un anello che nessuno svuotava. Misurato: zero righe per cinque
    # minuti con l'osservazione accesa dalla pagina, 744 in quarantacinque secondi
    # dopo un riavvio.
    store.log("info", "Osservazione del traffico %s"
              % ("attivata su %s" % interfaccia if attiva else "disattivata"))
    if attiva:
        flash("Osservazione del traffico su %s: si avvia entro %d secondi."
              % (interfaccia, _ATTESA_CATTURA_SEC), "success")
    else:
        flash("Osservazione del traffico disattivata: si ferma entro %d secondi."
              % _ATTESA_CATTURA_SEC, "success")
    return redirect(url_for("probe.configuration"))


@bp.post("/snmp")
def save_snmp():
    """Apparati di rete da interrogare in SNMP, e community di sola lettura.

    Il MAC di un nodo si ottiene con ARP, che non attraversa un router: per le
    subnet instradate l'unico modo di averlo e' chiederlo a un apparato di quel
    segmento. Qui si dichiara a quali apparati chiederlo.

    La community e' un SEGRETO e viene trattata come tale:
      * si salva solo se l'operatore ne scrive una nuova (il campo arriva vuoto se
        non la si vuole cambiare): cosi' salvare le altre impostazioni non la
        cancella per distrazione;
      * non viene MAI rimandata alla pagina, ne' scritta nel diario o in un
        messaggio -- il diario locale si legge dall'interfaccia, e un segreto che
        finisce in un diario e' un segreto perduto.
    """
    from . import snmp_raccolta

    store = _store()
    apparati = (request.form.get("snmp_devices") or "").strip()
    community = request.form.get("snmp_community") or ""
    attiva = bool(request.form.get("snmp_enabled"))

    valori = {
        snmp_raccolta.CHIAVE_APPARATI: apparati,
        snmp_raccolta.CHIAVE_ATTIVA: "1" if attiva else "0",
    }
    # Campo vuoto = "lascia quella che c'e'". Per togliere la community si svuota
    # l'elenco degli apparati o si disattiva la raccolta.
    if community.strip():
        valori[snmp_raccolta.CHIAVE_COMMUNITY] = community.strip()
    store.set_settings(valori)

    dichiarati = snmp_raccolta.apparati_dichiarati(store)
    if attiva and not (store.get_setting(snmp_raccolta.CHIAVE_COMMUNITY, "") or "").strip():
        flash("Raccolta SNMP attivata ma manca la community di sola lettura:"
              " nessun apparato verra' interrogato.", "warning")
    elif attiva and not dichiarati:
        flash("Raccolta SNMP attivata ma nessun apparato dichiarato.", "warning")
    else:
        store.log("info", "Raccolta SNMP %s: %d apparati dichiarati"
                          % ("attivata" if attiva else "disattivata", len(dichiarati)))
        flash("Impostazioni SNMP salvate: %d apparati dichiarati."
              % len(dichiarati), "success")
    return redirect(url_for("probe.configuration"))


@bp.post("/snmp/discover")
def discover_snmp():
    """Scopre gli apparati interrogabili e popola l'elenco.

    Si aggiunge SOLO cio' che ha superato la prova: risponde in SNMP con la community
    configurata e ha una tabella ARP con almeno una voce. Un apparato che "sembra" un
    router ma non risponde non serve, e uno senza tabella ARP non aggiunge dati.
    """
    from . import snmp_scoperta

    store = _store()
    esito = snmp_scoperta.scopri(_agent().scanner)

    if not esito["community_configurata"]:
        flash("Serve prima la community di sola lettura: senza, nessun apparato puo'"
              " essere provato. Sono stati comunque cercati apparati con la community"
              " di fabbrica (vedi sotto e il diario).", "warning")

    if esito["aggiunti"]:
        dettaglio = "; ".join("%s (%s, %d voci ARP)"
                              % (a["etichetta"], a["indirizzo"], a["voci_arp"])
                              for a in esito["aggiunti"][:6])
        flash("Apparati aggiunti all'elenco: %d su %d candidati provati. %s"
              % (len(esito["aggiunti"]), esito["candidati"], dettaglio), "success")
    elif esito["candidati"]:
        flash("Provati %d candidati, nessuno ha risposto con la community"
              " configurata." % esito["candidati"], "warning")
    else:
        flash("Nessun candidato: serve un perimetro configurato oppure almeno una"
              " scansione svolta.", "warning")

    if esito["di_fabbrica"]:
        elenco = ", ".join("%s (%s)" % (v["indirizzo"], v["community"])
                           for v in esito["di_fabbrica"][:6])
        flash("ATTENZIONE: %d apparati rispondono con la community di FABBRICA: %s."
              " E' un'esposizione da chiudere. Non sono stati aggiunti all'elenco."
              % (len(esito["di_fabbrica"]), elenco), "danger")

    if esito["senza_arp"]:
        flash("%d apparati rispondono ma non hanno tabella ARP: non aggiungono dati"
              " e non sono stati aggiunti." % len(esito["senza_arp"]), "info")

    return redirect(url_for("probe.configuration"))


@bp.post("/snmp/test")
def test_snmp():
    """Interroga subito gli apparati e riporta l'esito, apparato per apparato.

    Serve a scoprire ORA se la community e' quella giusta, invece di aspettare la
    cadenza e poi cercare nel diario perche' i MAC non arrivano.
    """
    from . import snmp_raccolta

    store = _store()
    if not snmp_raccolta.attiva(store):
        flash("La raccolta SNMP non e' attiva, oppure manca la community.", "warning")
        return redirect(url_for("probe.configuration"))

    esito = snmp_raccolta.raccogli(store)
    store.set_setting("last_snmp_at", utc_now_str())
    if not esito["apparati"]:
        flash("Nessun apparato dichiarato.", "warning")
    elif not esito["interrogati"]:
        motivi = "; ".join("%s: %s" % (d["apparato"], d.get("motivo", ""))
                           for d in esito["dettagli"])
        flash("Nessun apparato ha risposto. %s" % motivi, "danger")
    else:
        flash("Interrogati %d apparati su %d: %d corrispondenze IP-MAC."
              % (esito["interrogati"], esito["apparati"], esito["coppie"]), "success")
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


# --------------------------------------------------------------------------- #
# IDS e agenti di macchina
# --------------------------------------------------------------------------- #
@bp.get("/ids")
def ids():
    """Quello che il motore di rilevazione ha notato su questa rete.

    E' la stessa informazione che la console del server mostra, ma qui e' LOCALE:
    si vede anche quando il collegamento con la sede e' interrotto, ed e' il posto
    dove guardare quando si e' davanti alla sonda per capire che cosa sta succedendo.
    """
    from .ids import REGOLE, sensori_dichiarati

    store = _store()
    rilevazioni = store.ids_rilevazioni(limite=200)
    for voce in rilevazioni:
        voce["regola_nome"] = REGOLE.get(voce["regola"], {}).get("nome", voce["regola"])
        voce["perche"] = REGOLE.get(voce["regola"], {}).get("perche", "")
    return render_template(
        "ids.html",
        rilevazioni=rilevazioni,
        riepilogo=store.ids_riepilogo(),
        sensori=sensori_dichiarati(store),
        ultima_passata=store.get_json("ids_last_result", {}),
    )


@bp.get("/salute")
def salute():
    """Quanto occupa questa sonda, come sta lavorando, e quanto manca alle scadenze.

    PERCHE' UNA PAGINA SOLA E NON TRE. Sono numeri che si guardano insieme o non si
    guardano: un archivio che cresce e una coda che non si svuota sono lo stesso
    guasto visto da due lati, e una fase scaduta da due giorni spiega tutte e due.
    Sparpagliarli avrebbe richiesto di ricordarsi di aprire tre pagine.

    Non c'e' niente qui che riguardi la rete esaminata: sono le condizioni di salute
    DELLA SONDA. Cio' che ha trovato sta altrove.
    """
    import shutil

    from . import ids as modulo_ids

    store = _store()
    agente = _agent()

    try:
        disco = shutil.disk_usage(".")
        disco_libero, disco_totale = int(disco.free), int(disco.total)
    except OSError as errore:
        # Volume non interrogabile: si dichiara, non si mostra uno zero. Zero byte
        # liberi e "non l'ho potuto misurare" sono notizie opposte.
        current_app.logger.warning("Spazio su disco non leggibile: %s", errore)
        disco_libero, disco_totale = None, None

    occupazione = store.occupazione()
    tendenza = store.archivio_tendenza(disco_libero or 0)
    stato = agente.status()
    scansione = agente.scan_status()

    return render_template(
        "salute.html",
        occupazione=occupazione,
        tendenza=tendenza,
        storia=store.archivio_storia(store.STORIA_GIORNI_MASSIMI),
        disco_libero=disco_libero,
        disco_totale=disco_totale,
        scadenze=agente.scanner.scadenze(),
        stato=stato,
        scansione=scansione,
        traffico_attivo=store.get_setting(modulo_ids.CHIAVE_TRAFFICO_ATTIVO, "0") == "1",
        pacchetti=store.traffico_riepilogo(),
        agenti_attivi=store.agenti_attivi(),
        ids=store.get_json("ids_last_result", {}) or {},
        ritenzione_minuti=store.TRAFFICO_MINUTI,
        storia_giorni=store.STORIA_GIORNI_MASSIMI,
        tendenza_giorni=store.TENDENZA_GIORNI,
    )


@bp.get("/agenti")
def agenti():
    """Le macchine che riferiscono a questa sonda, e come aggiungerne una."""
    store = _store()
    return render_template(
        "agenti.html",
        agenti=store.agenti(limite=200),
        eventi=store.agent_eventi_recenti(limite=50),
        token=session.pop("agent_token", None),
        token_scade=session.pop("agent_token_scade", None),
    )


@bp.post("/agenti/token")
def agenti_token():
    """Emette un token di registrazione per una macchina nuova.

    Il token si vede UNA VOLTA SOLA, subito dopo averlo chiesto: dopo resta soltanto
    la sua impronta. Se si perde, se ne emette un altro -- costa meno che conservare
    in giro una credenziale che nessuno ricorda di aver lasciato.
    """
    from .agent_api import emetti_token

    store = _store()
    etichetta = (request.form.get("etichetta") or "").strip()[:120]
    esito = emetti_token(store, etichetta)
    # Nella sessione e non nel modello: un token in un URL finirebbe nella cronologia
    # del browser e nei log del proxy.
    session["agent_token"] = esito["token"]
    session["agent_token_scade"] = esito["scade_at"]
    store.log("info", "Token di registrazione agente emesso%s"
              % ((" per %s" % etichetta) if etichetta else ""))
    flash("Token emesso: vale %d ora e una volta sola." % esito["valido_ore"], "success")
    return redirect(url_for("probe.agenti"))


@bp.post("/agenti/pacchetto")
def agenti_pacchetto():
    """Consegna un pacchetto di installazione pronto, con dentro un token nuovo.

    IL PACCHETTO E' UNA CREDENZIALE. Contiene un token valido un'ora e una volta sola:
    per quell'ora, chiunque lo abbia puo' registrare una macchina. Gli installatori lo
    cancellano appena speso, e l'emissione resta nel diario -- fra un mese si deve
    poter sapere chi ha chiesto che cosa.

    Non passa dalla sessione come il token in chiaro: qui il token esce dentro un file
    che il browser salva, e un file salvato non finisce nei log del proxy.
    """
    from .agent_api import emetti_token
    from .pacchetto_agente import costruisci, nome_file

    store = _store()
    etichetta = (request.form.get("etichetta") or "").strip()[:120]
    # Se la sonda ha un certificato proprio, chi installa non deve scoprirlo sulla
    # macchina del cliente: la scelta si fa qui e viaggia dentro il pacchetto.
    verifica_tls = request.form.get("verifica_tls", "1") != "0"

    # L'indirizzo che l'agente dovra' chiamare e' quello con cui si sta guardando
    # questa pagina: e' l'unico che si sa raggiungibile davvero, perche' ci si e'
    # appena arrivati. Un indirizzo scritto in configurazione sarebbe quello giusto
    # solo finche' nessuno sposta la sonda.
    sonda = request.url_root.rstrip("/")

    esito = emetti_token(store, etichetta)
    try:
        archivio = costruisci(
            sonda=sonda, token=esito["token"], scade_at=esito["scade_at"],
            adesso=utc_now_str(), verifica_tls=verifica_tls, etichetta=etichetta)
    except FileNotFoundError as errore:
        # Il token e' gia' stato emesso: scadra' da solo fra un'ora senza essere
        # usato. Si dichiara il guasto invece di consegnare un archivio incompleto.
        store.log("error", "Pacchetto agente non costruito: %s" % errore)
        flash("Pacchetto non disponibile su questa installazione: %s" % errore,
              "danger")
        return redirect(url_for("probe.agenti"))

    store.log("info", "Pacchetto di installazione agente scaricato%s (scade %s)"
              % ((" per %s" % etichetta) if etichetta else "", esito["scade_at"]))
    risposta = make_response(archivio)
    risposta.headers["Content-Type"] = "application/zip"
    risposta.headers["Content-Disposition"] = (
        'attachment; filename="%s"' % nome_file(etichetta, utc_now_str()))
    # Un pacchetto con dentro una credenziale non si mette in nessuna cache.
    risposta.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return risposta


@bp.post("/agenti/<agent_uid>/revoca")
def agenti_revoca(agent_uid: str):
    """Revoca una macchina: da quel momento i suoi invii vengono respinti."""
    store = _store()
    macchina = store.agent(agent_uid)
    if macchina is None:
        flash("Macchina non trovata.", "warning")
        return redirect(url_for("probe.agenti"))
    store.agent_revoca(agent_uid)
    store.log("warning", "Agente revocato: %s (%s)"
              % (macchina.get("hostname"), agent_uid))
    flash("Agente revocato: i suoi invii verranno respinti.", "success")
    return redirect(url_for("probe.agenti"))
