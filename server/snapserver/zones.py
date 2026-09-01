"""
snap server - Zone di rete: il contesto che decide se un'esposizione e' un problema.

La stessa porta aperta significa cose opposte a seconda di dove si trova. SSH su una
rete di utenza e' una via d'ingresso che nessuno ha chiesto; SSH in un datacenter e'
il modo in cui i sistemi si amministrano, dietro un perimetro che qualcuno ha gia'
progettato. Un prodotto che le segnala allo stesso modo costringe l'operatore a
ignorare centinaia di righe -- e chi impara a ignorare un elenco poi ignora anche la
riga che contava.

Per questo ogni subnet puo' dichiarare la propria **zona**, e la zona esprime tre
giudizi possibili su ciascuna famiglia di esposizione:

    attesa      il servizio appartiene a quel contesto: il riscontro si conserva ma
                non entra fra quelli aperti, e ne porta scritta la ragione
    normale     vale la gravita' della regola
    violazione  in quel contesto quel servizio non ci dovrebbe essere: la gravita'
                sale, perche' e' un fatto piu' grave dello stesso servizio altrove

Due principi che rendono la cosa onesta:

1. **Non si cancella nulla.** Un'esposizione attesa resta in archivio con la sua
   motivazione ("atteso in zona datacenter"): se domani la zona cambia, il riscontro
   torna aperto da se'. Nascondere il dato invece di qualificarlo renderebbe il
   prodotto piu' pulito e meno vero.
2. **Chi non dichiara non viene premiato.** Una subnet senza zona vale come rete di
   utenza, che e' il giudizio piu' severo: il silenzio non deve valere come
   giustificazione.

remarks: Autore: Daniele Speziale - Data: 2026-08-29
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

# Giudizi possibili di una zona su una famiglia di esposizione.
ATTESA = "attesa"
NORMALE = "normale"
VIOLAZIONE = "violazione"

# Zona applicata quando la subnet non ne dichiara una. La piu' severa, di proposito.
ZONA_PREDEFINITA = "utenza"

# Le famiglie citate qui sono le chiavi delle regole di esposizione (threat.py):
# il titolo della regola e' la chiave, perche' e' quello che l'operatore legge.
#
# `attese`     -> il servizio appartiene al contesto
# `violazioni` -> in quel contesto e' piu' grave che altrove
#
# Le famiglie non nominate restano al giudizio della regola.
ZONE = [
    {
        "chiave": "utenza",
        "nome": "Rete di utenza",
        "icona": "bi-pc-display",
        "tono": "secondary",
        "descrizione":
            "Postazioni di lavoro, stampanti, telefoni. E' il contesto piu' severo:"
            " qui un servizio di amministrazione o una banca dati non hanno ragione"
            " di essere raggiungibili, e ogni esposizione vale per quello che e'.",
        "attese": [],
        "violazioni": ["Banca dati raggiungibile dalla rete"],
    },
    {
        "chiave": "datacenter",
        "nome": "Datacenter",
        "icona": "bi-hdd-rack",
        "tono": "primary",
        "descrizione":
            "Server e servizi applicativi, dietro un perimetro progettato: firewall,"
            " segmentazione, accesso amministrativo controllato. Qui SSH, desktop"
            " remoto e banche dati sono il modo in cui i sistemi lavorano, non una"
            " svista: sono attesi, e restano annotati senza contare come riscontri"
            " aperti.",
        "attese": [
            "Accesso remoto SSH raggiungibile",
            "Desktop remoto (RDP) raggiungibile",
            "Banca dati raggiungibile dalla rete",
            "Condivisione file Windows (SMB) raggiungibile",
            "Console di gestione raggiungibile",
        ],
        "violazioni": ["Telnet: credenziali in chiaro", "FTP: credenziali e dati in chiaro"],
    },
    {
        "chiave": "dmz",
        "nome": "DMZ",
        "icona": "bi-shield-slash",
        "tono": "danger",
        "descrizione":
            "Sistemi raggiungibili da reti non fidate. Qui e' atteso soltanto cio'"
            " che e' stato pubblicato di proposito: tutto il resto -- amministrazione,"
            " condivisioni, banche dati -- e' una violazione, perche' un sistema in"
            " DMZ e' il primo che verra' provato.",
        "attese": [],
        "violazioni": [
            "Accesso remoto SSH raggiungibile",
            "Desktop remoto (RDP) raggiungibile",
            "Desktop remoto VNC raggiungibile",
            "Condivisione file Windows (SMB) raggiungibile",
            "Banca dati raggiungibile dalla rete",
            "Console di gestione raggiungibile",
            "SNMP leggibile",
        ],
    },
    {
        "chiave": "gestione",
        "nome": "Rete di gestione",
        "icona": "bi-diagram-2",
        "tono": "info",
        "descrizione":
            "La rete fuori banda con cui si amministrano apparati e server: SSH,"
            " desktop remoto, SNMP e console sono la sua ragione di esistere. Il"
            " rischio qui non e' che quei servizi ci siano, ma che questa rete sia"
            " raggiungibile da altrove -- ed e' una verifica di segmentazione, non"
            " di porte.",
        "attese": [
            "Accesso remoto SSH raggiungibile",
            "Desktop remoto (RDP) raggiungibile",
            "Desktop remoto VNC raggiungibile",
            "SNMP leggibile",
            "Console di gestione raggiungibile",
        ],
        "violazioni": ["Telnet: credenziali in chiaro"],
    },
    {
        "chiave": "industriale",
        "nome": "Rete industriale (OT)",
        "icona": "bi-gear-wide-connected",
        "tono": "warning",
        "descrizione":
            "Automazione, controllo di processo, apparati con cicli di vita di"
            " decenni. Molti protocolli legacy sono attesi perche' l'alternativa non"
            " esiste sull'apparato; il rischio si governa segmentando, non chiudendo"
            " porte che il processo usa. La scansione va tenuta al profilo minimo.",
        "attese": [
            "Telnet: credenziali in chiaro",
            "FTP: credenziali e dati in chiaro",
            "SNMP leggibile",
        ],
        "violazioni": [
            "Condivisione file Windows (SMB) raggiungibile",
            "Banca dati raggiungibile dalla rete",
        ],
    },
    {
        "chiave": "ospiti",
        "nome": "Rete ospiti",
        "icona": "bi-wifi",
        "tono": "dark",
        "descrizione":
            "Accesso per visitatori e dispositivi non gestiti. Qui non dovrebbe"
            " esserci nulla da esporre: qualunque servizio raggiungibile e' una"
            " violazione, perche' significa che un dispositivo aziendale e' finito"
            " nella rete sbagliata o che la segmentazione non tiene.",
        "attese": [],
        "violazioni": [
            "Accesso remoto SSH raggiungibile",
            "Desktop remoto (RDP) raggiungibile",
            "Desktop remoto VNC raggiungibile",
            "Condivisione file Windows (SMB) raggiungibile",
            "Banca dati raggiungibile dalla rete",
            "Console di gestione raggiungibile",
            "SNMP leggibile",
            "Telnet: credenziali in chiaro",
            "FTP: credenziali e dati in chiaro",
        ],
    },
]

# Il catalogo qui sopra e' il SEME, non l'elenco definitivo: alla prima apertura
# viene copiato nella banca dati del tenant, e da quel momento l'operatore lo governa
# dalla pagina "Zone di rete" (creazione, modifica, eliminazione). Il codice conserva
# due cose che il cliente non deve poter inventare:
#
#   * le FAMIGLIE di esposizione, che sono i titoli delle regole di correlazione: una
#     famiglia scritta a mano non corrisponderebbe a nessuna regola e non farebbe
#     nulla, sembrando invece attiva;
#   * il significato dei tre giudizi e la regola dell'aggravamento.
#
# Cosi' il *contesto* e' un dato del cliente e il *modo di giudicarlo* resta prodotto.
SEME = ZONE
ZONE_PER_CHIAVE = {voce["chiave"]: voce for voce in ZONE}
CHIAVI = tuple(voce["chiave"] for voce in ZONE)

# Come sale la gravita' quando la zona dichiara una violazione. Non si va oltre
# "critical", e non si scende: una violazione non attenua mai.
AGGRAVAMENTO = {"info": "low", "low": "medium", "medium": "high", "high": "critical",
                "critical": "critical"}


def famiglie_esposizione() -> list:
    """Titoli delle famiglie di esposizione: l'allowlist di cio' che una zona puo'
    dichiarare atteso o in violazione.

    Si ricavano dalle regole di correlazione e non da un secondo elenco: due elenchi
    divergono, e il primo sintomo sarebbe una zona che dichiara qualcosa su una
    famiglia che non esiste piu', senza che nulla lo segnali.
    """
    from .threat import EXPOSURE_RULES

    return sorted({regola["titolo"] for regola in EXPOSURE_RULES})


def catalogo(tenant_id: int = None) -> list:
    """Zone del tenant, nell'ordine in cui si mostrano.

    Legge dalla banca dati; se il tenant non ha ancora zone -- prima apertura, oppure
    tabella non ancora creata -- restituisce il seme. Cosi' il prodotto funziona anche
    prima che qualcuno apra la pagina delle zone, che e' la condizione di ogni
    installazione nuova.
    """
    from flask import g, has_request_context

    if tenant_id is None:
        try:
            from .tenancy import current_tenant_id

            tenant_id = current_tenant_id()
        except Exception:  # noqa: BLE001 - fuori da una richiesta: vale il seme
            tenant_id = None
    if not tenant_id:
        return _seme_normalizzato()

    # Memoria per richiesta: la correlazione chiede la zona per ogni esposizione, e su
    # venticinquemila riscontri sarebbero venticinquemila interrogazioni.
    if has_request_context():
        memoria = getattr(g, "_snap_zone", None)
        if memoria is not None and memoria.get("tenant") == tenant_id:
            return memoria["zone"]

    try:
        from .db import query

        righe = query(
            "SELECT key, name, description, icon, tone, expected_json, violated_json,"
            " is_builtin, sort_order FROM network_zones WHERE tenant_id = ?"
            " ORDER BY sort_order, name", (tenant_id,))
    except Exception:  # noqa: BLE001 - tabella assente: vale il seme
        righe = []

    voci = [_da_riga(riga) for riga in righe] or _seme_normalizzato()
    if has_request_context():
        g._snap_zone = {"tenant": tenant_id, "zone": voci}
    return voci


def dimentica_catalogo() -> None:
    """Scarta la memoria per richiesta: si chiama dopo una modifica alle zone."""
    from flask import g, has_request_context

    if has_request_context() and hasattr(g, "_snap_zone"):
        del g._snap_zone


def _seme_normalizzato() -> list:
    """Il seme nella stessa forma delle righe della banca dati.

    Chi legge il catalogo non deve accorgersi della differenza fra "zone dichiarate
    nel tenant" e "zone del prodotto": due forme diverse per la stessa cosa fanno
    cadere il consumatore proprio nel caso meno frequente, cioe' un'installazione
    nuova.
    """
    return [dict(voce, predefinita=True, ordine=(indice + 1) * 10)
            for indice, voce in enumerate(SEME)]


def _da_riga(riga) -> dict:
    import json

    def elenco(testo):
        try:
            valori = json.loads(testo or "[]")
        except (TypeError, ValueError):
            return []
        return [str(v) for v in valori if isinstance(v, str)]

    return {
        "chiave": riga["key"],
        "nome": riga["name"],
        "descrizione": riga["description"] or "",
        "icona": riga["icon"] or "bi-diagram-3",
        "tono": riga["tone"] or "secondary",
        "attese": elenco(riga["expected_json"]),
        "violazioni": elenco(riga["violated_json"]),
        "predefinita": bool(riga["is_builtin"]),
        "ordine": int(riga["sort_order"] or 100),
    }


def per_chiave(tenant_id: int = None) -> dict:
    return {voce["chiave"]: voce for voce in catalogo(tenant_id)}


def zona(chiave: str, tenant_id: int = None) -> dict:
    """Descrizione di una zona; la predefinita se la chiave non e' dichiarata."""
    voci = per_chiave(tenant_id)
    cercata = (chiave or "").strip()
    if cercata in voci:
        return voci[cercata]
    if ZONA_PREDEFINITA in voci:
        return voci[ZONA_PREDEFINITA]
    # Un tenant che ha eliminato anche la zona predefinita non deve far cadere la
    # correlazione: vale la piu' severa fra quelle che restano, cioe' quella con piu'
    # violazioni dichiarate.
    if voci:
        return max(voci.values(), key=lambda v: len(v.get("violazioni") or []))
    return dict(ZONE_PER_CHIAVE[ZONA_PREDEFINITA])


def valida(chiave: str, tenant_id: int = None) -> str:
    """Chiave di zona ammessa, oppure quella predefinita. Allowlist, mai blocklist."""
    pulita = (chiave or "").strip()
    return pulita if pulita in per_chiave(tenant_id) else ZONA_PREDEFINITA


def giudizio(chiave_zona: str, titolo_esposizione: str, tenant_id: int = None) -> str:
    """Che cosa dice la zona su questa famiglia di esposizione."""
    voce = zona(chiave_zona, tenant_id)
    if titolo_esposizione in voce["attese"]:
        return ATTESA
    if titolo_esposizione in voce["violazioni"]:
        return VIOLAZIONE
    return NORMALE


def applica(chiave_zona: str, titolo_esposizione: str, severita: str,
            tenant_id: int = None) -> tuple:
    """Gravita' e motivazione di un'esposizione, letta nel contesto della zona.

    Restituisce (giudizio, gravita', motivazione). La motivazione e' in chiaro e
    finisce nel riscontro: chi legge deve poter capire *perche'* quella riga e'
    grave, o perche' non lo e', senza conoscere questo file.
    """
    voce = zona(chiave_zona, tenant_id)
    esito = giudizio(chiave_zona, titolo_esposizione, tenant_id)
    if esito == ATTESA:
        return (ATTESA, severita,
                "Atteso in zona %s: %s. Il riscontro resta annotato ma non conta fra"
                " quelli aperti; se la zona cambia, torna aperto da se'."
                % (voce["nome"].lower(), _motivo_attesa(voce)))
    if esito == VIOLAZIONE:
        return (VIOLAZIONE, AGGRAVAMENTO.get(severita, severita),
                "Violazione della zona %s: in questo contesto quel servizio non"
                " dovrebbe essere raggiungibile, quindi la gravita' sale."
                % voce["nome"].lower())
    return (NORMALE, severita, "")


def _motivo_attesa(voce: dict) -> str:
    """Perche' quel servizio e' atteso in quella zona.

    Per le zone nate col prodotto la ragione e' scritta qui. Per una zona creata
    dall'operatore la ragione migliore e' la SUA descrizione: nessuno la conosce
    meglio di chi l'ha dichiarata, e ripiegare su "il contesto lo prevede" quando
    una spiegazione c'e' sarebbe una risposta peggiore di quella disponibile.
    """
    predefinite = {
        "datacenter": "e' il modo in cui i sistemi si amministrano, dietro un"
                      " perimetro progettato",
        "gestione": "e' la ragione per cui questa rete esiste",
        "industriale": "l'apparato non offre alternative e il rischio si governa"
                       " segmentando",
    }
    if voce["chiave"] in predefinite:
        return predefinite[voce["chiave"]]
    propria = (voce.get("descrizione") or "").strip()
    if propria:
        prima_frase = propria.split(".")[0].strip()
        if prima_frase:
            return prima_frase[0].lower() + prima_frase[1:]
    return "il contesto lo prevede"


def summary(subnet_rows, tenant_id: int = None) -> dict:
    """Quante subnet per zona, quante senza dichiarazione.

    Serve alla pagina del perimetro e ai report: una rete in cui nessuna subnet
    dichiara la zona non e' "tutta utenza", e' una rete non ancora descritta.
    """
    dichiarate = per_chiave(tenant_id)
    per_zona = {chiave: 0 for chiave in dichiarate}
    senza = 0
    for riga in subnet_rows:
        dichiarata = (riga["zone"] if "zone" in riga.keys() else None) or ""
        if dichiarata.strip() in dichiarate:
            per_zona[dichiarata.strip()] += 1
        else:
            senza += 1
    return {
        "per_zona": per_zona,
        "senza_zona": senza,
        "dichiarate": sum(per_zona.values()),
        "totale": sum(per_zona.values()) + senza,
    }
