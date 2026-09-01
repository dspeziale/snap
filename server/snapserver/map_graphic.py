# -----------------------------------------------------------------
# map_graphic.py — disposizione della mappa grafica della rete
# Autore: Daniele Speziale
# Data creazione: 2026-08-31
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""Calcolo della disposizione (layout) della mappa grafica.

Perche' il calcolo sta qui e non nel browser:

* **niente JavaScript inline** e nessuna libreria di grafi da caricare: la politica
  di sicurezza dei contenuti del prodotto e' restrittiva e gli asset sono serviti
  localmente. Una disposizione calcolata in Python arriva alla pagina come dati e si
  disegna con HTML, CSS e un SVG per le linee;
* e' **verificabile con una prova**: la posizione di ogni icona e' il risultato di una
  funzione, non di una simulazione fisica che cambia a ogni caricamento;
* la pagina resta leggibile senza JavaScript, si stampa e si cerca con la ricerca del
  browser.

Che cosa **non** e': un grafo delle adiacenze fra dispositivi. Le adiacenze di una rete
commutata una scansione non le vede; cio' che si conosce e' chi ha osservato che cosa e
dentro quale rete dichiarata, e questa e' la gerarchia che la mappa disegna.

Il sistema di riferimento e' un piano logico di LARGHEZZA x ALTEZZA unita': il template
lo rende con un `viewBox`, quindi la mappa scala con la finestra senza ricalcoli.
"""

from __future__ import annotations

import math

from .fingerprint import DEVICE_CLASSES

# Piano logico. Le proporzioni sono quelle di uno schermo largo: la mappa vive in una
# pagina, non in un poster.
# Rapporto vicino all'A4 orizzontale (297x210): la mappa nasce per stare in una pagina.
LARGHEZZA = 1200.0
ALTEZZA = 850.0

# Icona per tipo di dispositivo: viene dal catalogo delle firme, cosi' la mappa non
# tiene un secondo elenco che si disallineerebbe al primo cambiamento del catalogo.
ICONE = {classe["key"]: classe.get("icon") or "bi-hdd-network"
         for classe in DEVICE_CLASSES}
ICONA_IGNOTO = "bi-question-circle"
ICONA_SONDA = "bi-broadcast-pin"
ICONA_RETE = "bi-diagram-3"

# Oltre questa soglia una rete non si disegna dispositivo per dispositivo: le icone si
# sovrapporrebbero e la mappa diventerebbe una macchia. Il troncamento viene
# dichiarato in pagina, non subito in silenzio.
MAX_NODI_DISEGNATI = 120

# Quanti dispositivi stanno sul primo anello. Gli anelli successivi ne contengono di
# piu', perche' la circonferenza cresce: senza questo, gli anelli esterni sarebbero
# vuoti e quelli interni affollati.
PRIMO_ANELLO = 10
PASSO_ANELLO = 6


def icona(tipo: str | None) -> str:
    """Classe dell'icona per un tipo di dispositivo."""
    return ICONE.get((tipo or "").strip(), ICONA_IGNOTO)


def _stato(nodo: dict) -> str:
    """Stato grafico di un dispositivo: e' il colore, e ha tre valori soli."""
    if (nodo.get("status") or "") == "up":
        return "critico" if int(nodo.get("riscontri") or 0) else "attivo"
    return "assente"


def _etichetta(nodo: dict) -> str:
    """Cio' che si scrive sotto l'icona: il nome se c'e', altrimenti l'indirizzo.

    Il nome host e' il modo in cui le persone chiamano un apparato; l'indirizzo resta
    nel suggerimento, che e' dove lo si cerca quando serve.
    """
    nome = (nodo.get("hostname") or "").strip()
    if not nome:
        return nodo.get("ip") or "?"
    # Un nome pienamente qualificato lungo sposta le icone vicine: si mostra la prima
    # parte, il resto sta nel suggerimento.
    corto = nome.split(".")[0]
    return corto if len(corto) <= 18 else corto[:17] + "…"


def _anelli(quanti: int) -> list[int]:
    """Quanti elementi per anello, dal piu' interno al piu' esterno."""
    anelli, restano, capienza = [], quanti, PRIMO_ANELLO
    while restano > 0:
        posti = min(restano, capienza)
        anelli.append(posti)
        restano -= posti
        capienza += PASSO_ANELLO
    return anelli


def disponi_in_anelli(elementi: list, centro: tuple[float, float],
                      raggio_primo: float, distanza: float,
                      raggio_massimo: float | None = None,
                      compressione_y: float = 0.78) -> list[dict]:
    """Dispone gli elementi su anelli concentrici attorno a un centro.

    Restituisce una lista di dizionari con `x`, `y` e l'elemento originale in `voce`.
    Gli anelli pari sono ruotati di mezzo passo: due anelli allineati farebbero
    sembrare la mappa una griglia storta, e le etichette si sovrapporrebbero.

    Con `raggio_massimo` gli anelli si **distribuiscono** fino a quel raggio: pochi
    elementi si allargano verso il bordo invece di stringersi al centro (lo spazio
    vuoto che restava attorno), e molti elementi rientrano comunque nel riquadro. Un
    solo anello si posiziona a buona distanza dal centro, non addosso. Il fattore
    verticale schiaccia gli anelli in ovali, cosi' la mappa riempie una pagina larga
    invece di un cerchio con gli angoli vuoti.
    """
    numero_anelli = len(_anelli(len(elementi)))
    if raggio_massimo is not None:
        if numero_anelli > 1:
            # Passo che porta l'anello piu' esterno esattamente al raggio massimo.
            distanza = (raggio_massimo - raggio_primo) / (numero_anelli - 1)
        else:
            # Un anello solo: lo si porta a buona parte del raggio disponibile, cosi'
            # non resta un pugno di icone al centro con tutto il resto vuoto.
            raggio_primo = max(raggio_primo, raggio_massimo * 0.62)
    posizioni = []
    indice = 0
    for numero_anello, posti in enumerate(_anelli(len(elementi))):
        raggio = raggio_primo + numero_anello * distanza
        scarto = (math.pi / posti) if numero_anello % 2 else 0.0
        for posto in range(posti):
            angolo = (2 * math.pi * posto / posti) + scarto - math.pi / 2
            posizioni.append({
                "voce": elementi[indice],
                "x": centro[0] + raggio * math.cos(angolo),
                "y": centro[1] + raggio * math.sin(angolo) * compressione_y,
            })
            indice += 1
    return posizioni


# --------------------------------------------------------------------------- #
# Panorama: le reti attorno alle sonde che le osservano
# --------------------------------------------------------------------------- #
def panorama(albero: dict, limite_reti: int = 60) -> dict:
    """Disposizione del panorama: una sonda al centro, le sue reti attorno.

    `albero` e' la struttura di `inventory_queries.network_tree`. Con piu' sonde le
    isole vengono affiancate: ciascuna sonda vede la propria parte di rete, e mischiarle
    in un unico grappolo farebbe perdere l'informazione di chi ha visto che cosa.
    """
    sonde = [s for s in (albero.get("sonde") or []) if s.get("subnet")]
    isole = []
    if not sonde:
        return {"isole": [], "larghezza": LARGHEZZA, "altezza": ALTEZZA,
                "reti_totali": 0, "reti_disegnate": 0}

    colonne = 1 if len(sonde) == 1 else 2
    righe = math.ceil(len(sonde) / colonne)
    passo_x = LARGHEZZA / colonne
    passo_y = ALTEZZA / righe

    reti_totali = reti_disegnate = 0
    for indice, sonda in enumerate(sonde):
        colonna, riga = indice % colonne, indice // colonne
        centro = (passo_x * (colonna + 0.5), passo_y * (riga + 0.5))

        reti = sorted(sonda["subnet"],
                      key=lambda v: (-len(v.get("nodi") or []), v.get("cidr") or ""))
        reti_totali += len(reti)
        troncate = max(0, len(reti) - limite_reti)
        reti = reti[:limite_reti]
        reti_disegnate += len(reti)

        # Il raggio si adatta al numero di reti e allo spazio dell'isola: con due sonde
        # l'isola e' meta', e un raggio fisso sfonderebbe il bordo. L'anello piu'
        # esterno non deve superare il bordo dell'isola, meno il posto per una bolla e
        # la sua etichetta.
        # Ellisse che riempie l'isola in ENTRAMBE le direzioni: il raggio orizzontale
        # arriva quasi al bordo laterale, la compressione verticale porta gli anelli
        # fino al bordo alto e basso. Senza questo il raggio era limitato dal lato piu'
        # corto e restavano ampie fasce vuote a destra e a sinistra.
        raggio_massimo = passo_x / 2 - 62
        compressione = min(0.95, max(0.55, (passo_y / 2 - 52) / raggio_massimo))
        raggio_primo = raggio_massimo * 0.32

        voci = []
        for posizione in disponi_in_anelli(reti, centro, raggio_primo, 0.0,
                                           raggio_massimo=raggio_massimo,
                                           compressione_y=compressione):
            rete = posizione["voce"]
            nodi = rete.get("nodi") or []
            attivi = int(rete.get("attivi") or 0)
            dominante = (rete.get("per_tipo") or [])
            tipo_dominante = dominante[0][0] if dominante else ""
            # L'icona dell'isola e' quella del tipo piu' presente: dice a colpo
            # d'occhio "questa e' una rete di stampanti", che e' l'informazione che
            # una bolla con un numero non da'.
            chiave = next((n.get("device_type") for n in nodi
                           if (n.get("device_label") or "") == tipo_dominante), None)
            voci.append({
                "x": posizione["x"], "y": posizione["y"],
                "cidr": rete.get("cidr") or "fuori perimetro",
                "subnet_id": rete.get("id"),
                "etichetta": rete.get("etichetta") or "",
                "zona": rete.get("zona") or "",
                "totale": int(rete.get("totale") or len(nodi)),
                "attivi": attivi,
                "riscontri": int(rete.get("riscontri") or 0),
                "icona": icona(chiave),
                "tipo_dominante": tipo_dominante or "non identificato",
                "stato": ("critico" if int(rete.get("riscontri") or 0)
                          else ("attivo" if attivi else "assente")),
                # La dimensione dichiara la consistenza: reti da 3 e da 300
                # dispositivi non possono avere la stessa bolla.
                "peso": _peso(int(rete.get("totale") or len(nodi))),
            })

        isole.append({
            "sonda": sonda.get("nome") or "Senza sonda dichiarata",
            "codice": sonda.get("codice") or "",
            "x": centro[0], "y": centro[1],
            "nodi": int(sonda.get("nodi") or 0),
            "attivi": int(sonda.get("attivi") or 0),
            "reti": voci,
            "reti_non_disegnate": troncate,
        })

    return {"isole": isole, "larghezza": LARGHEZZA, "altezza": ALTEZZA,
            "reti_totali": reti_totali, "reti_disegnate": reti_disegnate}


def _peso(totale: int) -> str:
    """Tre misure sole: le sfumature intermedie non si distinguono a occhio."""
    if totale >= 40:
        return "grande"
    if totale >= 10:
        return "medio"
    return "piccolo"


# --------------------------------------------------------------------------- #
# Una rete: i dispositivi con la loro icona
# --------------------------------------------------------------------------- #
def rete(albero: dict, subnet_id: int) -> dict | None:
    """Disposizione dei dispositivi di una rete attorno al centro che la rappresenta.

    Restituisce None se la rete non compare nell'albero (non ha dispositivi, oppure
    appartiene a un altro tenant: per questa vista sono lo stesso caso).
    """
    trovata = None
    sonda_di = None
    for sonda in albero.get("sonde") or []:
        for voce in sonda.get("subnet") or []:
            if (voce.get("id") or 0) == subnet_id:
                trovata, sonda_di = voce, sonda
                break
        if trovata:
            break
    if trovata is None:
        return None

    nodi = list(trovata.get("nodi") or [])
    troncati = max(0, len(nodi) - MAX_NODI_DISEGNATI)
    # Prima i dispositivi con riscontri aperti, poi gli attivi: se qualcosa viene
    # tagliato non deve essere cio' che ha un problema.
    nodi.sort(key=lambda n: (-int(n.get("riscontri") or 0),
                             (n.get("status") or "") != "up",
                             n.get("ip") or ""))
    nodi = nodi[:MAX_NODI_DISEGNATI]

    centro = (LARGHEZZA / 2, ALTEZZA / 2)
    # Ellisse che riempie il piano in larghezza E altezza: il raggio orizzontale arriva
    # quasi al bordo, la compressione verticale porta gli anelli fino in alto e in
    # basso. Cosi' le icone non restano in una fascia centrale con i lati vuoti.
    raggio_massimo = LARGHEZZA / 2 - 60
    compressione = min(0.95, max(0.55, (ALTEZZA / 2 - 52) / raggio_massimo))
    voci = []
    for posizione in disponi_in_anelli(nodi, centro, raggio_massimo * 0.24, 0.0,
                                       raggio_massimo=raggio_massimo,
                                       compressione_y=compressione):
        nodo = posizione["voce"]
        voci.append({
            "x": posizione["x"], "y": posizione["y"],
            "id": nodo.get("id"),
            "ip": nodo.get("ip"),
            "hostname": nodo.get("hostname") or "",
            "etichetta": _etichetta(nodo),
            "tipo": nodo.get("device_label") or "non identificato",
            "icona": icona(nodo.get("device_type")),
            "stato": _stato(nodo),
            "confidenza": int(nodo.get("device_confidence") or 0),
            "dichiarato": (nodo.get("device_type_source") or "auto") == "manual",
            "porte": int(nodo.get("porte") or 0),
            "snmp": int(nodo.get("snmp") or 0),
            "riscontri": int(nodo.get("riscontri") or 0),
        })

    return {
        "subnet_id": subnet_id,
        "cidr": trovata.get("cidr") or "fuori perimetro",
        "etichetta": trovata.get("etichetta") or "",
        "zona": trovata.get("zona") or "",
        "sonda": (sonda_di or {}).get("nome") or "Senza sonda dichiarata",
        "totale": int(trovata.get("totale") or len(nodi)),
        "attivi": int(trovata.get("attivi") or 0),
        "riscontri": int(trovata.get("riscontri") or 0),
        "per_tipo": trovata.get("per_tipo") or [],
        "nodi": voci,
        "non_disegnati": troncati,
        "centro": {"x": centro[0], "y": centro[1]},
        "larghezza": LARGHEZZA,
        "altezza": ALTEZZA,
    }


def legenda(albero: dict) -> list[dict]:
    """Tipi presenti nella rete, con la loro icona e quanti sono.

    Una legenda che elencasse tutto il catalogo costringerebbe a cercare i tre tipi che
    esistono davvero fra venti che non ci sono.
    """
    conteggi = {}
    for sonda in albero.get("sonde") or []:
        for voce in sonda.get("subnet") or []:
            for nodo in voce.get("nodi") or []:
                chiave = (nodo.get("device_type") or "",
                          nodo.get("device_label") or "non identificato")
                conteggi[chiave] = conteggi.get(chiave, 0) + 1
    return [{"tipo": tipo, "etichetta": etichetta, "icona": icona(tipo),
             "quanti": quanti}
            for (tipo, etichetta), quanti in sorted(conteggi.items(),
                                                    key=lambda c: (-c[1], c[0][1]))]
