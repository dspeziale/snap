# -----------------------------------------------------------------
# presence.py — storico delle presenze sulle reti senza fili
# Autore: Daniele Speziale
# Data creazione: 2026-09-10
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Chi c'era, e quando.

IL PROBLEMA
-----------
Su una rete cablata un indirizzo e' quasi un apparato: cambia raramente, e
l'inventario puo' trattare i due come la stessa cosa. Su una rete senza fili no. Il
DHCP riassegna, un telefono entra in una stanza e prende `10.2.3.55`, domani prende
`.78`, e `.55` intanto e' di un portatile. Un inventario che confonde indirizzo e
apparato, su una rete cosi', dice tre cose false: che l'apparato di ieri e' ancora
qui, che quello di oggi c'e' da sempre, e che sono lo stesso.

Servono percio' due domande separate: **chi**, e **quando era qui**.

L'IDENTITA', CHE E' LA PARTE DIFFICILE
--------------------------------------
Riconoscere lo stesso apparato su due indirizzi diversi richiede qualcosa che
l'indirizzo non e'. In ordine di certezza:

1. **il MAC** (`mac`) -- identifica la scheda. Si ha se la sonda sta sullo stesso
   segmento (ARP), oppure se un apparato di rete l'ha riferito in SNMP. Sulle reti
   senza fili instradate spesso NON si ha: e' il caso che ha motivato questo modulo.
   (Va detto che un telefono recente ruota il MAC fra le reti: fra due visite alla
   STESSA rete resta stabile, ma non e' un identificativo perpetuo.)
2. **il numero di serie** (`serial`) -- letto dalla pagina dell'apparato, da SNMP o
   da IPP. Vale per stampanti e apparati, non per i telefoni.
3. **il nome host** (`hostname`) -- probabile, non certo: un nome si puo' riassegnare.
   In pratica, su una rete di postazioni, e' quasi sempre l'apparato.
4. **niente** (`address`) -- non si ha un'identita' stabile. La permanenza si registra
   sull'INDIRIZZO e lo si dichiara: meglio un dato con la sua incertezza scritta che
   un apparato inventato.

QUANDO NON SI HA L'IDENTITA', SI USA CIO' CHE SI RACCOGLIE
----------------------------------------------------------
Anche senza identita' si sa qualcosa: il TTL osservato, quante e quali porte
rispondono, la famiglia di sistema operativo. Presi insieme sono un'impronta
**debole** -- mille telefoni uguali la condividono, quindi non identifica nessuno --
ma serve a un'altra domanda, che e' quella giusta: se l'impronta cambia SULLO STESSO
INDIRIZZO, quell'indirizzo e' passato a un altro apparato. E' l'unico modo di
accorgersene quando il MAC non c'e', e per questo la permanenza si chiude e se ne apre
una nuova, con il motivo scritto.

LE PERMANENZE
-------------
Una riga di `presence_sessions` e' una permanenza: un'identita', su un indirizzo, da
un istante a un altro, con quanti avvistamenti la sostengono. Se ne apre una nuova
quando l'identita' ricompare su un indirizzo diverso, quando il profilo dell'indirizzo
cambia, o dopo un'assenza piu' lunga di `GAP_SESSIONE_SEC` -- che non e' la stessa
visita.

GDPR. Un apparato personale in una rete Wi-Fi puo' riferirsi a una persona: MAC, nome
host e presenza nel tempo sono, insieme, un dato personale (considerando 30 del Reg.
UE 2016/679). Il trattamento e' quello dichiarato per l'inventario -- sicurezza della
rete, art. 6(1)(f) -- e le conseguenze pratiche stanno qui: si conservano solo i campi
tecnici che servono a riconoscere l'apparato, mai il contenuto del traffico, e lo
storico ha una conservazione a termine con cancellazione automatica. Il termine e'
dichiarato fra i tipi di conservazione di `maintenance.py`, insieme a tutti gli altri,
e non in un meccanismo proprio: una seconda politica di cancellazione sarebbe una
politica che qualcuno dimentica di applicare.
"""

from __future__ import annotations

import hashlib
import re

from .db import execute, query, utc_now_str

# Un'assenza piu' lunga di questa non e' la stessa visita: si chiude la permanenza e
# la prossima comparsa ne apre un'altra. Mezz'ora e' scelta sulla ricognizione: con
# una passata ogni due minuti, mezz'ora significa quindici passate senza vedere
# l'apparato -- non e' un buco di misura, e' andato via.
GAP_SESSIONE_SEC = 30 * 60

# Da che cosa e' stata riconosciuta un'identita', con quanto ci si puo' contare. E'
# un'allowlist: quello che non e' qui non finisce in banca dati.
FONTI = {
    "mac": {"nome": "indirizzo fisico", "certezza": "certa",
            "spiegazione": "il MAC identifica la scheda di rete"},
    "serial": {"nome": "numero di serie", "certezza": "certa",
               "spiegazione": "il numero di serie e' dell'apparato"},
    "hostname": {"nome": "nome host", "certezza": "probabile",
                 "spiegazione": "un nome host si puo' riassegnare, ma di norma"
                                " accompagna l'apparato"},
    "address": {"nome": "solo l'indirizzo", "certezza": "nessuna",
                "spiegazione": "nessuna identita' stabile: la permanenza riguarda"
                               " l'indirizzo, non un apparato riconosciuto"},
}

# Motivi per cui una permanenza e' nuova invece di continuare la precedente.
MOTIVI = {
    "prima": "primo avvistamento",
    "indirizzo": "ricomparso su un altro indirizzo",
    "assenza": "tornato dopo un'assenza",
    "profilo": "l'indirizzo e' passato a un altro apparato",
}

RE_NON_ESADECIMALE = re.compile(r"[^0-9a-f]")


def normalizza_mac(mac) -> str | None:
    """Il MAC in una sola scrittura, o `None` se non e' un MAC.

    Gli apparati lo scrivono con due punti, trattini, punti o attaccato: e' lo stesso
    indirizzo, e due scritture diverse produrrebbero due identita' diverse per lo
    stesso apparato -- cioe' esattamente il difetto che questo modulo esiste per
    evitare.
    """
    if not mac:
        return None
    cifre = RE_NON_ESADECIMALE.sub("", str(mac).lower())
    if len(cifre) != 12:
        return None
    return ":".join(cifre[i:i + 2] for i in range(0, 12, 2))


def identita(nodo: dict, seriale: str | None = None) -> tuple:
    """`(chiave, fonte)` con cui riconoscere questo apparato fra una visita e l'altra.

    L'ordine e' quello della certezza, dichiarato nella docstring del modulo. La
    chiave e' prefissata dalla fonte perche' un numero di serie e un nome host
    potrebbero coincidere, e sarebbero due apparati diversi.
    """
    mac = normalizza_mac(nodo.get("mac"))
    if mac:
        return ("mac:" + mac, "mac")
    pulito = (seriale or "").strip()
    if pulito:
        return ("serial:" + pulito.lower()[:80], "serial")
    nome = (nodo.get("hostname") or "").strip().lower()
    if nome:
        return ("host:" + nome[:190], "hostname")
    return ("addr:" + (nodo.get("ip") or "").strip(), "address")


def impronta_profilo(ttl=None, porte=None, famiglia_os: str | None = None) -> str | None:
    """Impronta debole del profilo osservato, o `None` se non si sa nulla.

    Non identifica un apparato e non va usata per quello. Serve a una sola domanda:
    se cambia sullo stesso indirizzo, l'indirizzo e' passato a un altro apparato.

    Le porte si ordinano: l'insieme conta, l'ordine in cui sono state viste no.
    """
    parti = []
    if ttl:
        parti.append("ttl=%d" % int(ttl))
    if porte:
        parti.append("porte=" + ",".join(str(p) for p in sorted(set(int(x) for x in porte))))
    if famiglia_os:
        parti.append("os=" + famiglia_os.strip().lower())
    if not parti:
        return None
    return hashlib.sha256("|".join(parti).encode("utf-8")).hexdigest()[:16]


def _secondi_tra(prima: str, dopo: str) -> float:
    """Distanza in secondi fra due istanti nel formato dell'archivio.

    Un valore illeggibile non si indovina: si restituisce un tempo enorme, che fa
    aprire una permanenza nuova. E' la scelta prudente -- si spezza uno storico
    invece di unire due apparati diversi.
    """
    from datetime import datetime, timezone

    def leggi(valore):
        try:
            return datetime.strptime(str(valore), "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return None

    a, b = leggi(prima), leggi(dopo)
    if a is None or b is None:
        return float("inf")
    return (b - a).total_seconds()


def registra_avvistamento(tenant_id: int, nodo: dict, *, visto_a: str = None,
                          seriale: str = None, profilo: str = None,
                          subnet_id: int = None, node_id: int = None,
                          etichetta: str = None) -> dict:
    """Registra che questo apparato e' stato visto, aprendo o prolungando la permanenza.

    Restituisce `{"session_id", "nuova", "motivo", "identity_source"}`: chi chiama
    deve poter sapere se e' comparso qualcosa di nuovo, perche' e' la condizione che
    fa partire l'arricchimento.
    """
    adesso = utc_now_str()
    visto = visto_a or adesso
    chiave, fonte = identita(nodo, seriale)
    ip = (nodo.get("ip") or "").strip()
    mac = normalizza_mac(nodo.get("mac"))
    nome = (nodo.get("hostname") or "").strip() or None

    aperta = query(
        "SELECT * FROM presence_sessions WHERE tenant_id = ? AND identity_key = ?"
        " ORDER BY last_seen_at DESC LIMIT 1", (tenant_id, chiave), one=True)

    motivo = "prima"
    if aperta is not None:
        if aperta["ip"] != ip:
            motivo = "indirizzo"
        elif _secondi_tra(aperta["last_seen_at"], visto) > GAP_SESSIONE_SEC:
            motivo = "assenza"
        elif (fonte == "address" and profilo and aperta["profile_key"]
                and profilo != aperta["profile_key"]):
            # Senza identita' stabile, il cambio di profilo sullo stesso indirizzo e'
            # l'unico segnale che l'apparato non e' piu' lo stesso.
            motivo = "profilo"
        else:
            execute(
                "UPDATE presence_sessions SET last_seen_at = ?,"
                " sightings = sightings + 1,"
                " mac = COALESCE(?, mac), hostname = COALESCE(?, hostname),"
                " device_label = COALESCE(?, device_label),"
                " node_id = COALESCE(?, node_id), subnet_id = COALESCE(?, subnet_id),"
                " profile_key = COALESCE(?, profile_key)"
                " WHERE id = ?",
                (max(str(aperta["last_seen_at"]), str(visto)), mac, nome, etichetta,
                 node_id, subnet_id, profilo, int(aperta["id"])))
            return {"session_id": int(aperta["id"]), "nuova": False,
                    "motivo": None, "identity_source": fonte}

    session_id = execute(
        "INSERT INTO presence_sessions (tenant_id, subnet_id, node_id, identity_key,"
        " identity_source, ip, mac, hostname, device_label, profile_key,"
        " first_seen_at, last_seen_at, sightings, opened_reason, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
        (tenant_id, subnet_id, node_id, chiave, fonte, ip, mac, nome, etichetta,
         profilo, visto, visto, motivo, adesso))
    return {"session_id": int(session_id), "nuova": True, "motivo": motivo,
            "identity_source": fonte}


def storico(tenant_id: int, *, subnet_id: int = None, node_id: int = None,
            identity_key: str = None, limit: int = 500) -> list:
    """Le permanenze, dalla piu' recente. E' la pagina dello storico."""
    condizioni = ["p.tenant_id = ?"]
    parametri = [tenant_id]
    if subnet_id:
        condizioni.append("p.subnet_id = ?")
        parametri.append(int(subnet_id))
    if node_id:
        condizioni.append("p.node_id = ?")
        parametri.append(int(node_id))
    if identity_key:
        condizioni.append("p.identity_key = ?")
        parametri.append(identity_key)
    parametri.append(max(1, min(int(limit), 5000)))
    righe = query(
        "SELECT p.*, s.cidr AS subnet_cidr, n.device_label AS node_label,"
        " n.mac_vendor"
        " FROM presence_sessions p"
        " LEFT JOIN subnets s ON s.id = p.subnet_id"
        " LEFT JOIN nodes n ON n.id = p.node_id"
        " WHERE " + " AND ".join(condizioni) +
        " ORDER BY p.last_seen_at DESC, p.id DESC LIMIT ?", tuple(parametri))
    return [_leggibile(r) for r in righe]


def _leggibile(riga) -> dict:
    """Una permanenza con i campi che la pagina mostra, incertezza compresa."""
    voce = dict(riga)
    fonte = FONTI.get(voce.get("identity_source") or "", FONTI["address"])
    voce["identity_label"] = fonte["nome"]
    voce["identity_certainty"] = fonte["certezza"]
    voce["identity_explained"] = fonte["spiegazione"]
    voce["opened_label"] = MOTIVI.get(voce.get("opened_reason") or "", "")
    voce["duration_sec"] = max(0.0, _secondi_tra(voce["first_seen_at"],
                                                 voce["last_seen_at"]))
    return voce


def riepilogo(tenant_id: int, *, subnet_id: int = None) -> dict:
    """Quanti apparati distinti, quante permanenze, quanti senza identita' stabile.

    L'ultimo numero e' quello che dice se lo storico e' affidabile: se la meta' delle
    permanenze e' riconosciuta "solo dall'indirizzo", la rete non fornisce i MAC e lo
    storico va letto per quello che e'.
    """
    condizioni = ["tenant_id = ?"]
    parametri = [tenant_id]
    if subnet_id:
        condizioni.append("subnet_id = ?")
        parametri.append(int(subnet_id))
    dove = " AND ".join(condizioni)
    riga = query(
        "SELECT COUNT(*) AS permanenze, COUNT(DISTINCT identity_key) AS apparati,"
        " SUM(CASE WHEN identity_source = 'address' THEN 1 ELSE 0 END) AS senza_identita,"
        " SUM(CASE WHEN identity_source = 'mac' THEN 1 ELSE 0 END) AS con_mac,"
        " MIN(first_seen_at) AS dal, MAX(last_seen_at) AS al"
        " FROM presence_sessions WHERE " + dove, tuple(parametri), one=True)
    esito = dict(riga) if riga is not None else {}
    for chiave in ("permanenze", "apparati", "senza_identita", "con_mac"):
        esito[chiave] = int(esito.get(chiave) or 0)
    return esito


# --------------------------------------------------------------------------- #
# L'andamento nel tempo
# --------------------------------------------------------------------------- #
# Periodi offerti dalla pagina, con il passo con cui si contano gli apparati. Il passo
# non e' una preferenza grafica: contare per ORA su trenta giorni darebbe 720 punti su
# una spezzata larga mille pixel -- un rumore, non un andamento -- e contare per GIORNO
# su ventiquattro ore darebbe un punto solo.
PERIODI = (
    {"chiave": "24h", "nome": "ultime 24 ore", "ore": 24, "passo_min": 60,
     "con_ora": True},
    {"chiave": "48h", "nome": "ultime 48 ore", "ore": 48, "passo_min": 60,
     "con_ora": True},
    {"chiave": "7g", "nome": "ultimi 7 giorni", "ore": 24 * 7, "passo_min": 360,
     "con_ora": True},
    {"chiave": "30g", "nome": "ultimi 30 giorni", "ore": 24 * 30, "passo_min": 1440,
     "con_ora": False},
)
PERIODO_PREDEFINITO = "48h"

# Quanti apparati si disegnano nelle fasce. Oltre questo numero la pagina diventa un
# muro di righe: si mostrano i piu' recenti e si dichiara quanti restano fuori.
MAX_APPARATI_FASCE = 60


def periodo(chiave: str | None) -> dict:
    """Il periodo scelto, o quello predefinito. Allowlist: la chiave viene dall'URL."""
    for voce in PERIODI:
        if voce["chiave"] == (chiave or PERIODO_PREDEFINITO):
            return voce
    return next(v for v in PERIODI if v["chiave"] == PERIODO_PREDEFINITO)


def _istante(valore):
    """Un istante dell'archivio come datetime, o `None` se illeggibile."""
    from datetime import datetime, timezone

    try:
        return datetime.strptime(str(valore), "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _permanenze_nel_periodo(tenant_id: int, da, subnet_id: int = None) -> list:
    """Le permanenze che TOCCANO il periodo, non solo quelle iniziate dentro.

    La differenza conta: un apparato presente da ieri e ancora presente adesso ha una
    permanenza cominciata prima dell'inizio del periodo, e ignorarla direbbe che quel
    apparato non c'era.
    """
    condizioni = ["tenant_id = ?", "last_seen_at >= ?"]
    parametri = [tenant_id, da.strftime("%Y-%m-%d %H:%M:%S")]
    if subnet_id:
        condizioni.append("subnet_id = ?")
        parametri.append(int(subnet_id))
    return list(query(
        "SELECT id, identity_key, identity_source, ip, mac, hostname, device_label,"
        " node_id, subnet_id, first_seen_at, last_seen_at, sightings, opened_reason"
        " FROM presence_sessions WHERE " + " AND ".join(condizioni) +
        " ORDER BY last_seen_at DESC LIMIT 5000", tuple(parametri)))


def andamento(tenant_id: int, *, chiave_periodo: str = None,
              subnet_id: int = None) -> dict:
    """Quanti apparati distinti erano presenti, intervallo per intervallo.

    E' la risposta alla domanda che una tabella di permanenze non da': non "chi", ma
    "quanti, e quando". Serve a vedere il respiro di una rete di utenza -- il picco
    del mattino, il vuoto della notte -- e a notare il giorno in cui quel respiro
    cambia.

    Un apparato conta in un intervallo se la sua permanenza lo TOCCA, anche solo in
    parte: la presenza e' un fatto continuo, e un intervallo attraversato da una
    permanenza e' un intervallo in cui quell'apparato c'era.

    Restituisce `{"punti": [[istante, quanti], ...], "da", "a", "periodo", "massimo",
    "media", "apparati"}`.
    """
    from datetime import datetime, timedelta, timezone

    voce = periodo(chiave_periodo)
    # La finestra si chiude al minuto SUCCESSIVO, non a quello in corso. Troncando ai
    # minuti, un apparato visto trenta secondi fa cadeva DOPO la fine della finestra e
    # non compariva ne' nel conteggio ne' nelle fasce: spariva proprio quello che si
    # vuole vedere di piu'. Un minuto in avanti costa un intervallo appena cominciato
    # e non perde niente.
    adesso = (datetime.now(timezone.utc).replace(second=0, microsecond=0)
              + timedelta(minutes=1))
    passo = timedelta(minutes=voce["passo_min"])
    da = adesso - timedelta(hours=voce["ore"])

    permanenze = _permanenze_nel_periodo(tenant_id, da, subnet_id)
    intervalli = []
    for riga in permanenze:
        inizio = _istante(riga["first_seen_at"])
        fine = _istante(riga["last_seen_at"])
        if inizio is None or fine is None:
            continue  # una riga con un istante illeggibile non si indovina
        intervalli.append((inizio, fine, riga["identity_key"]))

    punti = []
    quanti_per_intervallo = []
    momento = da
    while momento < adesso:
        prossimo = momento + passo
        presenti = {chiave for inizio, fine, chiave in intervalli
                    if inizio < prossimo and fine >= momento}
        punti.append([momento.strftime("%Y-%m-%d %H:%M:%S"), len(presenti)])
        quanti_per_intervallo.append(len(presenti))
        momento = prossimo

    distinti = {chiave for _, _, chiave in intervalli}
    return {
        "punti": punti,
        "da": da.strftime("%Y-%m-%d %H:%M:%S"),
        "a": adesso.strftime("%Y-%m-%d %H:%M:%S"),
        "periodo": voce,
        "massimo": max(quanti_per_intervallo) if quanti_per_intervallo else 0,
        "media": (round(sum(quanti_per_intervallo) / len(quanti_per_intervallo), 1)
                  if quanti_per_intervallo else 0.0),
        "apparati": len(distinti),
        "permanenze": len(intervalli),
    }


def fasce(tenant_id: int, *, chiave_periodo: str = None, subnet_id: int = None,
          massimo: int = MAX_APPARATI_FASCE) -> dict:
    """Le presenze di ciascun apparato disegnate sul tempo, una riga per apparato.

    E' l'altra meta' dell'andamento: il grafico dice quanti, questo dice CHI e per
    quanto. Su una rete di utenza si legge a colpo d'occhio la differenza fra un
    apparato che sta tutto il giorno (una postazione, una stampante) e uno che passa
    per venti minuti (un telefono di chi entra in una stanza) -- che e' proprio la
    distinzione che un inventario senza tempo non puo' fare.

    Ogni fascia porta la propria posizione in percentuale del periodo, cosi' la
    pagina la disegna senza calcoli e senza JavaScript.
    """
    voce = periodo(chiave_periodo)
    dati = andamento(tenant_id, chiave_periodo=voce["chiave"], subnet_id=subnet_id)
    inizio_periodo = _istante(dati["da"])
    fine_periodo = _istante(dati["a"])
    durata = max(1.0, (fine_periodo - inizio_periodo).total_seconds())

    per_apparato = {}
    for riga in _permanenze_nel_periodo(tenant_id, inizio_periodo, subnet_id):
        inizio = _istante(riga["first_seen_at"])
        fine = _istante(riga["last_seen_at"])
        if inizio is None or fine is None:
            continue
        # Si taglia al periodo: una permanenza cominciata tre giorni fa disegna solo
        # la parte che cade nella finestra guardata. Gli estremi si riportano DENTRO la
        # finestra invece di scartare la permanenza: l'istante dichiarato viene dalla
        # sonda, e l'orologio di una sonda qualche secondo avanti metterebbe
        # l'avvistamento nel futuro. Scartarlo farebbe sparire dalla pagina l'apparato
        # visto per ultimo -- cioe' quello che si guarda per primo.
        visibile_da = min(max(inizio, inizio_periodo), fine_periodo)
        visibile_a = max(min(fine, fine_periodo), inizio_periodo)
        if visibile_a < visibile_da:
            # Avvistamento puntuale ai margini: resta una fascia, che la larghezza
            # minima rende visibile.
            visibile_a = visibile_da
        sinistra = (visibile_da - inizio_periodo).total_seconds() / durata * 100.0
        larghezza = (visibile_a - visibile_da).total_seconds() / durata * 100.0
        gruppo = per_apparato.setdefault(riga["identity_key"], {
            "identity_key": riga["identity_key"],
            "identity_source": riga["identity_source"],
            "identity_label": FONTI.get(riga["identity_source"] or "",
                                        FONTI["address"])["nome"],
            "identity_certainty": FONTI.get(riga["identity_source"] or "",
                                            FONTI["address"])["certezza"],
            "device_label": riga["device_label"],
            "hostname": riga["hostname"],
            "mac": riga["mac"],
            "node_id": riga["node_id"],
            "indirizzi": [],
            "fasce": [],
            "presenza_sec": 0.0,
            "ultimo": riga["last_seen_at"],
        })
        if riga["ip"] and riga["ip"] not in gruppo["indirizzi"]:
            gruppo["indirizzi"].append(riga["ip"])
        gruppo["fasce"].append({
            # Una permanenza di pochi minuti su trenta giorni sarebbe larga zero: si
            # tiene un minimo visibile, altrimenti la riga direbbe "mai stato qui".
            "sinistra": round(max(0.0, min(99.6, sinistra)), 3),
            "larghezza": round(max(0.4, min(100.0, larghezza)), 3),
            "ip": riga["ip"],
            "dalle": riga["first_seen_at"],
            "alle": riga["last_seen_at"],
            "avvistamenti": riga["sightings"],
            "motivo": MOTIVI.get(riga["opened_reason"] or "", ""),
        })
        gruppo["presenza_sec"] += (visibile_a - visibile_da).total_seconds()
        gruppo["ultimo"] = max(str(gruppo["ultimo"]), str(riga["last_seen_at"]))

    righe = sorted(per_apparato.values(), key=lambda g: g["ultimo"], reverse=True)
    for gruppo in righe:
        gruppo["presenza_percento"] = round(gruppo["presenza_sec"] / durata * 100.0, 1)
        gruppo["fasce"].sort(key=lambda f: f["sinistra"])
    return {
        "righe": righe[:max(1, int(massimo))],
        "esclusi": max(0, len(righe) - max(1, int(massimo))),
        "totale": len(righe),
        "andamento": dati,
        # Le tacche dell'asse: la pagina le disegna come colonne di riferimento, e
        # senza di esse una fascia larga il 12% non direbbe di quando si tratta.
        "tacche": _tacche(inizio_periodo, fine_periodo, voce),
    }


def _tacche(da, a, voce: dict, quante: int = 8) -> list:
    """Riferimenti temporali equidistanti, con la posizione in percentuale."""
    from datetime import timedelta

    durata = max(1.0, (a - da).total_seconds())
    passo = timedelta(seconds=durata / quante)
    tacche = []
    for indice in range(quante + 1):
        momento = da + passo * indice
        tacche.append({
            "posizione": round(indice / quante * 100.0, 3),
            "etichetta": (momento.strftime("%H:%M") if voce["con_ora"]
                          else momento.strftime("%d/%m")),
            "istante": momento.strftime("%Y-%m-%d %H:%M:%S"),
        })
    return tacche
