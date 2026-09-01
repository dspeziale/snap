# -----------------------------------------------------------------
# acn.py — comunicazione degli incidenti all'ACN: obbligo, scadenze, fascicolo
# Autore: Daniele Speziale
# Data creazione: 2026-08-31
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Il percorso di una comunicazione ad ACN, dall'incidente al protocollo.

Il vincolo da cui parte tutto
-----------------------------
Il portale delle segnalazioni dell'Agenzia per la Cybersicurezza Nazionale
(`segnalazioni.acn.gov.it`) e' un'applicazione web ad accesso **autenticato con
identita' digitale** (SPID, CIE, CNS), riservata al *punto di contatto* designato dal
soggetto registrato. Non espone un'interfaccia di programmazione pubblica per l'invio
automatico.

Quindi snap **prepara e sorveglia, non invia**. Non e' una limitazione tecnica che si
possa aggirare, ed evitarla sarebbe sbagliato in tre modi:

1. **credenziali**: automatizzare l'accesso richiederebbe di conservare l'identita'
   digitale di una persona. Non si fa, e nessuna comodita' lo giustifica;
2. **imputabilita'**: la notifica e' un atto di una persona identificata. Un programma
   che la invia al posto suo attribuisce a quella persona un atto che non ha compiuto;
3. **fragilita'**: un robot che compila i moduli di un portale della pubblica
   amministrazione si rompe al primo cambio di pagina, e si rompe nel momento peggiore
   -- quando c'e' un incidente in corso e le ore contano.

Cio' che snap fa, e che e' il lavoro che serve davvero:

* **riconosce l'obbligo** e propone la valutazione di significativita', con i criteri
  scritti e verificabili -- la decisione resta di una persona, con la motivazione
  registrata;
* **tiene l'orologio**: preallarme entro 24 ore, notifica entro 72 ore, relazione
  finale entro un mese dalla **conoscenza** dell'incidente (art. 23 della direttiva
  (UE) 2022/2555, recepita dal D.lgs. 138/2024). Avvisa prima che scadano, non dopo;
* **compone il fascicolo** con i campi che il portale chiede, in due forme: un PDF da
  allegare e i blocchi di testo da incollare nei campi del modulo;
* **registra cio' che e' stato inviato**: stadio, istante, persona, numero di
  protocollo restituito dal portale, e il riscontro. E' questa la parte che in un audit
  vale piu' di tutte, perche' dimostra i tempi;
* **lascia la porta aperta**: il canale e' un'astrazione (`CANALI`). Se ACN pubblichera'
  un'interfaccia di programmazione, si aggiunge un canale e il percorso non cambia.

Gli stadi, e perche' sono quattro
---------------------------------
| stadio | termine | che cosa contiene |
|---|---|---|
| `preallarme` | 24 ore | che e' successo qualcosa, se si sospetta un atto illecito e se c'e' impatto trasfrontaliero |
| `notifica` | 72 ore | valutazione iniziale: gravita', impatto, indicatori di compromissione |
| `aggiornamento` | su richiesta | cio' che si e' saputo dopo |
| `finale` | 1 mese | descrizione, causa, misure adottate, impatto trasfrontaliero |

Uno stadio non si "salta": si dichiara **non dovuto** con una motivazione. Un elenco in
cui le comunicazioni non dovute sparissero non permetterebbe di distinguere "non
serviva" da "ce ne siamo dimenticati", che e' precisamente la domanda di un ispettore.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json
from datetime import timedelta

from .audit import log_event
from .db import execute, parse_utc, query, utc_now, utc_str

PORTALE = "https://segnalazioni.acn.gov.it/"

# --------------------------------------------------------------------------- #
# Stadi e termini
# --------------------------------------------------------------------------- #
PREALLARME = "preallarme"
NOTIFICA = "notifica"
AGGIORNAMENTO = "aggiornamento"
FINALE = "finale"

# Ore entro cui ciascuno stadio e' dovuto, contate dalla CONOSCENZA dell'incidente.
# L'aggiornamento non ha un termine proprio: si invia quando l'autorita' lo chiede o
# quando si sa qualcosa che cambia il quadro.
TERMINI_ORE = {
    PREALLARME: 24,
    NOTIFICA: 72,
    AGGIORNAMENTO: None,
    FINALE: 24 * 30,
}

STADI = (
    {"chiave": PREALLARME, "nome": "Preallarme",
     "termine": "entro 24 ore dalla conoscenza",
     "contenuto": "Che e' successo un incidente significativo; se si sospetta un atto"
                  " illecito o doloso; se puo' avere impatto in altri Stati membri."},
    {"chiave": NOTIFICA, "nome": "Notifica dell'incidente",
     "termine": "entro 72 ore dalla conoscenza",
     "contenuto": "Valutazione iniziale: gravita', impatto, indicatori di"
                  " compromissione, aggiornamento di cio' che era nel preallarme."},
    {"chiave": AGGIORNAMENTO, "nome": "Aggiornamento",
     "termine": "su richiesta dell'autorita', o quando il quadro cambia",
     "contenuto": "Cio' che si e' saputo dopo la notifica: nuove evidenze, estensione"
                  " dell'impatto, misure aggiuntive."},
    {"chiave": FINALE, "nome": "Relazione finale",
     "termine": "entro un mese dalla notifica",
     "contenuto": "Descrizione dettagliata, gravita' e impatto, tipo di minaccia e"
                  " causa probabile, misure di attenuazione applicate ed effetti"
                  " trasfrontalieri."},
)
STADI_PER_CHIAVE = {s["chiave"]: s for s in STADI}

# Stati di una comunicazione. `non_dovuta` non e' una scorciatoia: e' una decisione con
# motivazione, e resta nell'elenco.
DA_PREPARARE = "da_preparare"
PREPARATA = "preparata"
INVIATA = "inviata"
RISCONTRO = "riscontro"
NON_DOVUTA = "non_dovuta"

STATI = {
    DA_PREPARARE: "da preparare",
    PREPARATA: "preparata, da inviare dal portale",
    INVIATA: "inviata al portale",
    RISCONTRO: "riscontro ricevuto",
    NON_DOVUTA: "non dovuta (motivata)",
}

# Transizioni ammesse. Una macchina a stati esplicita serve a un fine preciso: nessuno
# deve poter dichiarare "inviata" una comunicazione che non e' mai stata composta.
TRANSIZIONI = {
    DA_PREPARARE: {PREPARATA, NON_DOVUTA},
    PREPARATA: {INVIATA, NON_DOVUTA, DA_PREPARARE},
    INVIATA: {RISCONTRO, INVIATA},
    RISCONTRO: {RISCONTRO},
    NON_DOVUTA: {DA_PREPARARE},
}


class AcnError(RuntimeError):
    """Il passaggio richiesto non e' ammesso. Il messaggio e' per l'operatore."""


# --------------------------------------------------------------------------- #
# Canali: oggi uno solo, ma l'astrazione serve
# --------------------------------------------------------------------------- #
CANALE_PORTALE = "portale"
CANALE_API = "api"

CANALI = {
    CANALE_PORTALE: {
        "nome": "Portale ACN (invio manuale dal punto di contatto)",
        "disponibile": True,
        "automatico": False,
        "nota": "Accesso con identita' digitale (SPID/CIE/CNS) riservato al punto di"
                " contatto: snap compone il fascicolo, l'invio e' un atto della"
                " persona.",
    },
    CANALE_API: {
        "nome": "Interfaccia di programmazione ACN",
        "disponibile": False,
        "automatico": True,
        "nota": "Non disponibile: l'Agenzia non pubblica un'interfaccia di"
                " programmazione per l'invio. Il posto per collegarla esiste, e il"
                " percorso non cambierebbe.",
    },
}


# --------------------------------------------------------------------------- #
# Significativita': i criteri sono scritti, la decisione e' di una persona
# --------------------------------------------------------------------------- #
# Soglie predefinite, dichiarate e modificabili in configurazione. Non sono la legge:
# la direttiva parla di incidenti che causano "una grave perturbazione operativa o
# perdite finanziarie" o che "hanno ripercussioni su altri soggetti". Sono un aiuto a
# non lasciar passare inosservato cio' che va valutato.
SOGLIE = {
    "ore_indisponibilita": 4,
    "servizi_coinvolti": 3,
    "gravita_minima": "critical",
}

CRITERI = (
    {"chiave": "gravita",
     "titolo": "Gravita' dichiarata dell'incidente",
     "domanda": "L'incidente e' classificato critico dal controllo che lo ha aperto?"},
    {"chiave": "durata",
     "titolo": "Durata dell'indisponibilita'",
     "domanda": "Il servizio e' rimasto indisponibile oltre la soglia dichiarata?"},
    {"chiave": "estensione",
     "titolo": "Numero di servizi o dispositivi coinvolti",
     "domanda": "L'incidente riguarda piu' servizi o piu' apparati contemporaneamente?"},
    {"chiave": "illecito",
     "titolo": "Sospetto di atto illecito o doloso",
     "domanda": "Ci sono indizi di accesso non autorizzato, cifratura dei dati o"
                " esfiltrazione?"},
    {"chiave": "trasfrontaliero",
     "titolo": "Effetti su altri soggetti o Stati membri",
     "domanda": "L'incidente puo' avere ripercussioni su terzi o oltre confine?"},
    {"chiave": "dati_personali",
     "titolo": "Coinvolgimento di dati personali",
     "domanda": "Ci sono indizi di violazione di dati personali? In tal caso valutare"
                " anche la notifica al Garante (GDPR art. 33, 72 ore).",
     "nota": "Le due notifiche sono indipendenti: una non sostituisce l'altra."},
)


def valuta(incidente: dict, soglie: dict = None) -> dict:
    """Proposta di valutazione: quali criteri risultano soddisfatti dai dati.

    Restituisce una PROPOSTA, non un verdetto. La significativita' e' una valutazione
    dell'organizzazione: qui si dice soltanto che cosa dicono i dati, criterio per
    criterio, cosi' che chi decide lo faccia guardando qualcosa.
    """
    soglie = {**SOGLIE, **(soglie or {})}
    esiti = {}

    gravita = (incidente.get("severity") or "").lower()
    esiti["gravita"] = gravita == soglie["gravita_minima"]

    aperto = parse_utc(incidente.get("opened_at"))
    chiuso = parse_utc(incidente.get("resolved_at")) or utc_now()
    ore = ((chiuso - aperto).total_seconds() / 3600.0) if aperto else 0.0
    esiti["durata"] = ore >= float(soglie["ore_indisponibilita"])

    coinvolti = int(incidente.get("servizi_coinvolti") or 1)
    esiti["estensione"] = coinvolti >= int(soglie["servizi_coinvolti"])

    # Questi tre non si deducono da una misura: li dichiara chi valuta.
    esiti["illecito"] = None
    esiti["trasfrontaliero"] = None
    esiti["dati_personali"] = None

    soddisfatti = [c for c, v in esiti.items() if v is True]
    return {
        "esiti": esiti,
        "soddisfatti": soddisfatti,
        "ore_indisponibilita": round(ore, 1),
        "proposta": bool(soddisfatti),
        "motivo_proposta": (
            "Criteri soddisfatti dai dati: %s. Restano da dichiarare i criteri che"
            " nessuna misura puo' stabilire (atto illecito, effetti trasfrontalieri,"
            " dati personali)." % ", ".join(soddisfatti)
            if soddisfatti else
            "Nessun criterio automatico soddisfatto: la valutazione resta comunque"
            " dovuta, perche' i criteri che contano di piu' non sono misurabili."),
        "soglie": soglie,
    }


# --------------------------------------------------------------------------- #
# Scadenze
# --------------------------------------------------------------------------- #
def scadenza(conosciuto_alle: str, stadio: str) -> str:
    """Istante entro cui lo stadio e' dovuto, in UTC. Stringa vuota se non ha termine.

    Si conta dalla **conoscenza** dell'incidente, non dal suo inizio: e' cio' che dice
    l'art. 23, ed e' anche l'unico istante che si puo' documentare.
    """
    ore = TERMINI_ORE.get(stadio)
    momento = parse_utc(conosciuto_alle)
    if not ore or momento is None:
        return ""
    return utc_str(momento + timedelta(hours=ore))


def residuo_ore(scadenza_utc: str, adesso=None) -> float | None:
    """Ore che restano (negative se il termine e' passato). None se non c'e' termine."""
    momento = parse_utc(scadenza_utc)
    if momento is None:
        return None
    riferimento = adesso or utc_now()
    return round((momento - riferimento).total_seconds() / 3600.0, 1)


def stato_termine(comunicazione: dict, adesso=None) -> dict:
    """Come sta la comunicazione rispetto al proprio termine.

    Tre casi che vanno distinti perche' portano a tre azioni diverse: c'e' tempo, il
    tempo sta finendo, il termine e' passato. Un'unica etichetta "in ritardo" non
    servirebbe a nessuno.
    """
    residuo = residuo_ore(comunicazione.get("deadline_at") or "", adesso)
    inviata = comunicazione.get("status") in (INVIATA, RISCONTRO)
    if comunicazione.get("status") == NON_DOVUTA:
        return {"stato": "non dovuta", "residuo": residuo, "urgente": False,
                "scaduto": False}
    if residuo is None:
        return {"stato": "senza termine", "residuo": None, "urgente": False,
                "scaduto": False}
    if inviata:
        return {"stato": "inviata", "residuo": residuo, "urgente": False,
                "scaduto": False}
    if residuo < 0:
        return {"stato": "termine superato", "residuo": residuo, "urgente": True,
                "scaduto": True}
    if residuo <= max(1.0, TERMINI_ORE.get(comunicazione.get("stage") or "", 24) * 0.25):
        return {"stato": "in scadenza", "residuo": residuo, "urgente": True,
                "scaduto": False}
    return {"stato": "in tempo", "residuo": residuo, "urgente": False, "scaduto": False}


# --------------------------------------------------------------------------- #
# Il fascicolo dell'incidente
# --------------------------------------------------------------------------- #
def incidente(tenant_id: int, incident_id: int):
    """L'incidente con il bersaglio e il controllo che lo ha aperto."""
    return query(
        "SELECT i.*,"
        # Per un incidente registrato a mano il nome del controllo e l'indirizzo del
        # bersaglio non dicono niente: valgono il titolo e il soggetto che ha scritto
        # l'operatore.
        " COALESCE(NULLIF(i.title, ''), c.name) AS controllo, c.kind AS genere,"
        " COALESCE(NULLIF(i.subject, ''), t.address) AS bersaglio,"
        " t.name AS bersaglio_nome,"
        " (SELECT COUNT(*) FROM check_incidents x JOIN checks y ON y.id = x.check_id"
        "  JOIN check_targets z ON z.id = y.target_id"
        "  WHERE x.tenant_id = i.tenant_id AND x.status = 'open') AS servizi_coinvolti"
        " FROM check_incidents i"
        " JOIN checks c ON c.id = i.check_id"
        " JOIN check_targets t ON t.id = c.target_id"
        " WHERE i.tenant_id = ? AND i.id = ?", (tenant_id, incident_id), one=True)


# Il controllo fittizio sotto cui vivono gli incidenti registrati a mano. Serve
# perche' un incidente, nello schema, appartiene a un controllo: invece di allentare quel
# vincolo -- e di dover controllare l'assenza del controllo in venti interrogazioni -- si
# dichiara un contenitore, uno per tenant, disattivato, che non esegue nulla.
CONTROLLO_MANUALE = "Registrazione manuale di incidente"
BERSAGLIO_MANUALE = "registrazione manuale"

GRAVITA = ("critical", "warning", "info")


def _contenitore_manuale(tenant_id: int) -> int:
    """Il controllo (disattivato) sotto cui si registrano gli incidenti a mano."""
    riga = query(
        "SELECT c.id FROM checks c JOIN check_targets t ON t.id = c.target_id"
        " WHERE c.tenant_id = ? AND c.name = ? LIMIT 1",
        (tenant_id, CONTROLLO_MANUALE), one=True)
    if riga is not None:
        return int(riga["id"])

    adesso = utc_str(utc_now())
    bersaglio = query("SELECT id FROM check_targets WHERE tenant_id = ? AND address = ?",
                      (tenant_id, BERSAGLIO_MANUALE), one=True)
    target_id = int(bersaglio["id"]) if bersaglio is not None else execute(
        "INSERT INTO check_targets (tenant_id, address, name, description, is_enabled,"
        " created_at, updated_at) VALUES (?, ?, ?, ?, 0, ?, ?)",
        (tenant_id, BERSAGLIO_MANUALE, "Incidenti registrati a mano",
         "Contenitore degli incidenti che non nascono da un controllo: segnalazioni,"
         " comunicazioni di terzi, riscontri sul campo. Non esegue verifiche.",
         adesso, adesso))
    return int(execute(
        "INSERT INTO checks (tenant_id, target_id, name, kind, is_enabled,"
        " interval_seconds, timeout_seconds, severity, failure_threshold,"
        " escalation_threshold, created_at, updated_at)"
        " VALUES (?, ?, ?, 'presence', 0, 3600, 5, 'warning', 1, 1, ?, ?)",
        (tenant_id, target_id, CONTROLLO_MANUALE, adesso, adesso)))


def registra_incidente(tenant_id: int, titolo: str, soggetto: str = "",
                       gravita: str = "warning", conosciuto_alle: str = "",
                       descrizione: str = "", utente_id: int = None,
                       attore: str = "") -> int:
    """Registra un incidente che non nasce da un controllo. Restituisce il suo id.

    Serve perche' gli incidenti che contano di piu' non li rileva una sonda: li porta
    una telefonata, una segnalazione del CSIRT, un riscatto comparso su uno schermo. Se
    il percorso di comunicazione partisse solo dai controlli, quegli incidenti
    resterebbero fuori dal fascicolo.
    """
    titolo = (titolo or "").strip()
    if not titolo:
        raise AcnError("Il titolo dell'incidente e' obbligatorio: e' cio' che si legge"
                       " nell'elenco e nel fascicolo.")
    if gravita not in GRAVITA:
        raise AcnError("Gravita' non prevista: %r." % gravita)

    quando = (conosciuto_alle or "").strip() or utc_str(utc_now())
    if parse_utc(quando) is None:
        raise AcnError("L'istante di conoscenza non e' una data valida"
                       " (formato: AAAA-MM-GG hh:mm:ss).")
    if parse_utc(quando) > utc_now():
        raise AcnError("L'istante di conoscenza e' nel futuro: i termini decorrerebbero"
                       " da un momento che non e' ancora arrivato.")

    check_id = _contenitore_manuale(tenant_id)
    incident_id = int(execute(
        "INSERT INTO check_incidents (tenant_id, check_id, status, severity, opened_at,"
        " first_detail, last_detail, failure_count, origin, title, subject, created_by,"
        " updated_at) VALUES (?, ?, 'open', ?, ?, ?, ?, 1, 'manual', ?, ?, ?, ?)",
        (tenant_id, check_id, gravita, quando,
         (descrizione or "").strip()[:2000] or titolo[:2000],
         (descrizione or "").strip()[:2000] or titolo[:2000],
         titolo[:300], (soggetto or "").strip()[:300] or None, utente_id,
         utc_str(utc_now()))))

    log_event("incident.registered",
              "Incidente registrato a mano: %s%s (conoscenza: %s)"
              % (titolo, " su %s" % soggetto.strip() if soggetto.strip() else "",
                 quando),
              tenant_id=tenant_id, entity="incident", entity_id=incident_id,
              severity="warning")
    return incident_id


def elimina_incidente(tenant_id: int, incident_id: int, attore: str = "") -> dict:
    """Elimina un incidente registrato a mano, se nulla e' stato comunicato.

    Due limiti, entrambi voluti:

    * un incidente aperto da un CONTROLLO non si elimina: e' un fatto della storia
      della sorveglianza, e cancellarlo falsificherebbe il registro;
    * un incidente per cui una comunicazione e' stata **inviata** non si elimina: il
      protocollo restituito dal portale e' la prova dei tempi. Se si rivela un falso
      allarme, lo si dichiara nella relazione finale -- non facendo sparire la riga.
    """
    riga = query("SELECT * FROM check_incidents WHERE tenant_id = ? AND id = ?",
                 (tenant_id, incident_id), one=True)
    if riga is None:
        raise AcnError("Incidente non trovato per questo tenant.")
    if (riga["origin"] or "check") != "manual":
        raise AcnError("Questo incidente e' stato aperto da un controllo: e' un fatto"
                       " della sorveglianza e non si elimina. Si chiude, con la sua"
                       " motivazione.")

    inviate = query(
        "SELECT COUNT(*) AS quante FROM acn_communications"
        " WHERE tenant_id = ? AND incident_id = ? AND status IN (?, ?)",
        (tenant_id, incident_id, INVIATA, RISCONTRO), one=True)
    if int((inviate or {"quante": 0})["quante"] or 0):
        raise AcnError("Una comunicazione di questo incidente e' gia' stata inviata"
                       " all'autorita': il protocollo e' la prova dei tempi e non si"
                       " cancella. Se e' un falso allarme, lo si dichiara nella"
                       " relazione finale.")

    titolo = riga["title"] or riga["first_detail"] or "#%s" % incident_id
    comunicazioni_tolte = int(query(
        "SELECT COUNT(*) AS quante FROM acn_communications"
        " WHERE tenant_id = ? AND incident_id = ?",
        (tenant_id, incident_id), one=True)["quante"] or 0)

    execute("DELETE FROM acn_communications WHERE tenant_id = ? AND incident_id = ?",
            (tenant_id, incident_id))
    execute("DELETE FROM check_incidents WHERE tenant_id = ? AND id = ?",
            (tenant_id, incident_id))

    log_event("incident.deleted",
              "Incidente registrato a mano eliminato: %s (#%s)%s"
              % (titolo, incident_id,
                 ", con %d comunicazioni mai inviate" % comunicazioni_tolte
                 if comunicazioni_tolte else ""),
              tenant_id=tenant_id, entity="incident", entity_id=incident_id,
              severity="warning")
    return {"incidente": incident_id, "comunicazioni": comunicazioni_tolte,
            "titolo": titolo}


def comunicazioni(tenant_id: int, incident_id: int = None) -> list:
    """Le comunicazioni registrate, dalla piu' urgente."""
    condizioni = ["tenant_id = ?"]
    parametri = [tenant_id]
    if incident_id:
        condizioni.append("incident_id = ?")
        parametri.append(incident_id)
    righe = [dict(r) for r in query(
        "SELECT * FROM acn_communications WHERE %s"
        " ORDER BY COALESCE(deadline_at, '9999'), id" % " AND ".join(condizioni),
        tuple(parametri))]
    for riga in righe:
        riga["termine"] = stato_termine(riga)
        riga["stadio_nome"] = STADI_PER_CHIAVE.get(riga["stage"], {}).get(
            "nome", riga["stage"])
        riga["stato_nome"] = STATI.get(riga["status"], riga["status"])
    return righe


def apri_fascicolo(tenant_id: int, incident_id: int, conosciuto_alle: str = None,
                   valutazione: dict = None, attore: str = "") -> list:
    """Crea le comunicazioni previste per un incidente, se non ci sono gia'.

    Si creano TUTTE in stato "da preparare", anche quelle che forse non serviranno: un
    elenco che mostra solo il prossimo passo non permette di vedere l'obbligo nel suo
    insieme, e l'obbligo e' fatto di scadenze che arrivano insieme.
    """
    esistenti = {c["stage"] for c in comunicazioni(tenant_id, incident_id)}
    if esistenti:
        raise AcnError("Il fascicolo di questo incidente e' gia' aperto.")

    voce = incidente(tenant_id, incident_id)
    if voce is None:
        raise AcnError("Incidente non trovato per questo tenant.")

    conosciuto = conosciuto_alle or voce["opened_at"]
    adesso = utc_str(utc_now())
    creati = []
    for stadio in STADI:
        chiave = stadio["chiave"]
        # L'aggiornamento non si crea da se': si aggiunge quando serve, altrimenti
        # resterebbe per sempre una riga "da preparare" che nessuno deve preparare.
        if chiave == AGGIORNAMENTO:
            continue
        nuovo = execute(
            "INSERT INTO acn_communications (tenant_id, incident_id, stage, status,"
            " channel, known_at, deadline_at, payload_json, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (tenant_id, incident_id, chiave, DA_PREPARARE, CANALE_PORTALE,
             conosciuto, scadenza(conosciuto, chiave),
             json.dumps(valutazione or {}, ensure_ascii=False), adesso, adesso))
        creati.append(int(nuovo))

    log_event("acn.dossier.opened",
              "Fascicolo ACN aperto per l'incidente #%s (conoscenza: %s)"
              % (incident_id, conosciuto),
              tenant_id=tenant_id, entity="incident", entity_id=incident_id,
              severity="warning")
    return creati


def aggiungi_aggiornamento(tenant_id: int, incident_id: int, motivo: str = "") -> int:
    """Uno stadio di aggiornamento in piu': si aggiunge quando l'autorita' lo chiede."""
    voce = incidente(tenant_id, incident_id)
    if voce is None:
        raise AcnError("Incidente non trovato per questo tenant.")
    esistenti = comunicazioni(tenant_id, incident_id)
    if not esistenti:
        raise AcnError("Aprire prima il fascicolo dell'incidente.")

    conosciuto = esistenti[0].get("known_at") or voce["opened_at"]
    adesso = utc_str(utc_now())
    nuovo = execute(
        "INSERT INTO acn_communications (tenant_id, incident_id, stage, status,"
        " channel, known_at, deadline_at, notes, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?)",
        (tenant_id, incident_id, AGGIORNAMENTO, DA_PREPARARE, CANALE_PORTALE,
         conosciuto, (motivo or "")[:500], adesso, adesso))
    log_event("acn.update.added",
             "Aggiornamento ACN aggiunto all'incidente #%s" % incident_id,
              tenant_id=tenant_id, entity="incident", entity_id=incident_id)
    return int(nuovo)


def comunicazione(tenant_id: int, comunicazione_id: int):
    riga = query("SELECT * FROM acn_communications WHERE tenant_id = ? AND id = ?",
                 (tenant_id, comunicazione_id), one=True)
    return dict(riga) if riga is not None else None


def cambia_stato(tenant_id: int, comunicazione_id: int, nuovo: str, attore: str = "",
                 protocollo: str = "", note: str = "", percorso: str = "") -> dict:
    """Passaggio di stato, con le condizioni che lo rendono vero.

    "Inviata" richiede il numero di protocollo restituito dal portale: senza quello la
    riga direbbe che la comunicazione e' partita senza poterlo dimostrare, ed e'
    esattamente cio' che un ispettore chiede.
    """
    voce = comunicazione(tenant_id, comunicazione_id)
    if voce is None:
        raise AcnError("Comunicazione non trovata per questo tenant.")
    corrente = voce["status"]
    if nuovo not in STATI:
        raise AcnError("Stato non previsto: %r." % nuovo)
    if nuovo not in TRANSIZIONI.get(corrente, set()):
        raise AcnError("Da \"%s\" non si passa a \"%s\"."
                       % (STATI.get(corrente, corrente), STATI.get(nuovo, nuovo)))
    if nuovo == INVIATA and not (protocollo or "").strip():
        raise AcnError("Per registrare l'invio serve il numero di protocollo"
                       " restituito dal portale.")
    if nuovo == NON_DOVUTA and not (note or "").strip():
        raise AcnError("Una comunicazione non dovuta richiede la motivazione: e' cio'"
                       " che distingue \"non serviva\" da \"ce ne siamo dimenticati\".")

    adesso = utc_str(utc_now())
    campi = ["status = ?", "updated_at = ?"]
    valori = [nuovo, adesso]
    if nuovo == PREPARATA:
        campi.append("prepared_at = ?")
        valori.append(adesso)
        if percorso:
            campi.append("file_path = ?")
            valori.append(percorso)
    if nuovo == INVIATA:
        campi.extend(["sent_at = ?", "sent_by = ?", "reference = ?"])
        valori.extend([adesso, (attore or "")[:160], protocollo.strip()[:80]])
    if nuovo == RISCONTRO:
        campi.append("answered_at = ?")
        valori.append(adesso)
    if note:
        campi.append("notes = ?")
        valori.append(note[:2000])

    execute("UPDATE acn_communications SET %s WHERE tenant_id = ? AND id = ?"
            % ", ".join(campi), tuple(valori) + (tenant_id, comunicazione_id))

    log_event("acn.communication.%s" % nuovo,
              "Comunicazione ACN %s (incidente #%s) -> %s%s"
              % (STADI_PER_CHIAVE.get(voce["stage"], {}).get("nome", voce["stage"]),
                 voce["incident_id"], STATI.get(nuovo, nuovo),
                 ", protocollo %s" % protocollo.strip() if protocollo else ""),
              tenant_id=tenant_id, entity="incident",
              entity_id=int(voce["incident_id"]),
              severity="warning" if nuovo == NON_DOVUTA else "info")
    return comunicazione(tenant_id, comunicazione_id)


# --------------------------------------------------------------------------- #
# Il contenuto da portare al portale
# --------------------------------------------------------------------------- #
def fascicolo(tenant_id: int, comunicazione_id: int) -> dict:
    """Tutto cio' che serve a compilare il modulo, e le prove da allegare."""
    voce = comunicazione(tenant_id, comunicazione_id)
    if voce is None:
        raise AcnError("Comunicazione non trovata per questo tenant.")
    inc = incidente(tenant_id, int(voce["incident_id"]))
    if inc is None:
        raise AcnError("Incidente non trovato per questo tenant.")

    tenant = query("SELECT name, code, timezone, contact_email FROM tenants"
                   " WHERE id = ?", (tenant_id,), one=True)
    cronologia = [dict(r) for r in query(
        "SELECT executed_at, status, detail FROM check_results"
        " WHERE tenant_id = ? AND check_id = ? AND executed_at >= ?"
        " ORDER BY executed_at LIMIT 200",
        (tenant_id, inc["check_id"], inc["opened_at"]))]
    misure = [dict(r) for r in query(
        "SELECT created_at, event_type, description, actor FROM audit_events"
        " WHERE tenant_id = ? AND created_at >= ? ORDER BY created_at LIMIT 200",
        (tenant_id, inc["opened_at"]))]
    notifiche = [dict(r) for r in query(
        "SELECT channel, recipients, status, sent_at, last_error FROM notifications"
        " WHERE tenant_id = ? AND created_at >= ? ORDER BY created_at LIMIT 100",
        (tenant_id, inc["opened_at"]))]

    try:
        valutazione = json.loads(voce.get("payload_json") or "{}")
    except (TypeError, ValueError):
        valutazione = {}

    return {
        "comunicazione": voce,
        "stadio": STADI_PER_CHIAVE.get(voce["stage"], {}),
        "termine": stato_termine(voce),
        "incidente": dict(inc),
        "tenant": {"nome": tenant["name"] if tenant else "",
                   "codice": tenant["code"] if tenant else "",
                   "fuso": (tenant["timezone"] if tenant else "") or "Europe/Rome",
                   "recapito": (tenant["contact_email"] if tenant else "") or ""},
        "valutazione": valutazione,
        "cronologia": cronologia,
        "misure": misure,
        "notifiche": notifiche,
        "portale": PORTALE,
        "canale": CANALI.get(voce.get("channel") or CANALE_PORTALE, {}),
        "criteri": CRITERI,
        "altre": [c for c in comunicazioni(tenant_id, int(voce["incident_id"]))
                  if int(c["id"]) != int(comunicazione_id)],
    }


def registro(tenant_id: int, inizio: str = None, fine: str = None) -> dict:
    """Il registro delle comunicazioni, per il fascicolo di conformita'.

    Conta cio' che un ispettore chiede: quante dovute, quante inviate nei termini,
    quante fuori termine, quante dichiarate non dovute e con quale motivazione.
    """
    condizioni = ["tenant_id = ?"]
    parametri = [tenant_id]
    if inizio and fine:
        condizioni.append("created_at BETWEEN ? AND ?")
        parametri.extend([inizio, fine])
    righe = [dict(r) for r in query(
        "SELECT * FROM acn_communications WHERE %s ORDER BY created_at"
        % " AND ".join(condizioni), tuple(parametri))]

    dentro = fuori = aperte = non_dovute = 0
    for riga in righe:
        if riga["status"] == NON_DOVUTA:
            non_dovute += 1
            continue
        if riga["status"] in (INVIATA, RISCONTRO):
            inviata = parse_utc(riga.get("sent_at"))
            termine = parse_utc(riga.get("deadline_at"))
            if termine is None or (inviata and inviata <= termine):
                dentro += 1
            else:
                fuori += 1
        else:
            aperte += 1
        riga["termine"] = stato_termine(riga)
        riga["stadio_nome"] = STADI_PER_CHIAVE.get(riga["stage"], {}).get(
            "nome", riga["stage"])

    return {
        "comunicazioni": righe,
        "totale": len(righe),
        "nei_termini": dentro,
        "fuori_termine": fuori,
        "da_inviare": aperte,
        "non_dovute": non_dovute,
        "incidenti": len({r["incident_id"] for r in righe}),
    }


def in_scadenza(tenant_id: int = None, ore: float = 6.0) -> list:
    """Comunicazioni dovute entro `ore`, o gia' fuori termine.

    Serve all'avviso: un termine di legge che scade in silenzio e' il difetto peggiore
    che questo modulo possa avere.
    """
    condizioni = ["status IN (?, ?)", "COALESCE(deadline_at, '') <> ''"]
    parametri = [DA_PREPARARE, PREPARATA]
    if tenant_id:
        condizioni.append("tenant_id = ?")
        parametri.append(tenant_id)
    righe = [dict(r) for r in query(
        "SELECT * FROM acn_communications WHERE %s ORDER BY deadline_at"
        % " AND ".join(condizioni), tuple(parametri))]

    scelte = []
    for riga in righe:
        residuo = residuo_ore(riga.get("deadline_at") or "")
        if residuo is None or residuo > ore:
            continue
        riga["residuo_ore"] = residuo
        riga["termine"] = stato_termine(riga)
        riga["stadio_nome"] = STADI_PER_CHIAVE.get(riga["stage"], {}).get(
            "nome", riga["stage"])
        scelte.append(riga)
    return scelte
