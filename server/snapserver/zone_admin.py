"""
snap server - Governo delle zone di rete: seme, creazione, modifica, eliminazione.

Perche' questo modulo esiste separato da `zones.py`: quello risponde alla domanda
"che cosa dice la zona su questa esposizione" ed e' interrogato migliaia di volte per
passata di correlazione; qui stanno le operazioni di scrittura, che avvengono quando
una persona apre una pagina. Tenerle insieme avrebbe messo la parte piu' delicata --
il giudizio -- accanto a quella piu' movimentata.

Che cosa il cliente puo' dichiarare, e che cosa no:

* **puo'** creare zone proprie ("collaudo", "fornitori", "rete di cantiere"),
  cambiare nome, descrizione, icona, colore e ordine, e scegliere quali famiglie di
  esposizione sono attese e quali sono violazioni;
* **non puo'** inventare le famiglie: quelle sono i titoli delle regole di
  correlazione (`threat.EXPOSURE_RULES`). Una famiglia scritta a mano non
  corrisponderebbe a nessuna regola, non farebbe nulla, e sembrerebbe attiva --
  che e' il modo peggiore in cui una configurazione possa sbagliare;
* **non puo'** cambiare il significato dei tre giudizi ne' la regola
  dell'aggravamento: quelle sono prodotto, e sono cio' che rende confrontabili due
  installazioni diverse.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json
import re

from . import zones
from .db import execute, query, utc_now_str

# Chiave: minuscole, cifre, trattini. E' cio' che le subnet conservano, quindi deve
# restare stabile e scrivibile in un URL senza sorprese.
CHIAVE_AMMESSA = re.compile(r"^[a-z][a-z0-9\-]{1,31}$")

# Toni ammessi: sono le classi di colore di Bootstrap gia' usate nel prodotto. Un
# valore libero finirebbe in `class="..."` come testo arbitrario.
TONI = ("primary", "secondary", "success", "danger", "warning", "info", "dark")
# Icone: si accetta un nome di Bootstrap Icons, non un frammento di markup. Un
# carattere basta -- `bi-x` esiste -- e il limite di due lo rifiutava.
ICONA_AMMESSA = re.compile(r"^bi-[a-z0-9\-]{1,40}$")

MAX_NOME = 60
MAX_DESCRIZIONE = 600


class ZonaError(ValueError):
    """Dato non valido: il messaggio e' scritto per essere mostrato all'operatore."""


# --------------------------------------------------------------------------- #
# Seme
# --------------------------------------------------------------------------- #
def semina(tenant_id: int, forzando: bool = False) -> int:
    """Copia le zone del prodotto nella banca dati del tenant.

    Si chiama alla prima apertura e quando l'operatore chiede di ripristinare le
    predefinite. Le zone create da lui non si toccano: ripristinare significa
    riportare all'origine quelle nate col prodotto, non cancellare il suo lavoro.
    """
    adesso = utc_now_str()
    scritte = 0
    for ordine, voce in enumerate(zones.SEME, start=1):
        esistente = query("SELECT id FROM network_zones WHERE tenant_id = ? AND key = ?",
                          (tenant_id, voce["chiave"]), one=True)
        if esistente is not None and not forzando:
            continue
        if esistente is not None:
            execute(
                "UPDATE network_zones SET name = ?, description = ?, icon = ?, tone = ?,"
                " expected_json = ?, violated_json = ?, is_builtin = 1, sort_order = ?,"
                " updated_at = ? WHERE id = ?",
                (voce["nome"], voce["descrizione"], voce["icona"], voce["tono"],
                 json.dumps(voce["attese"], ensure_ascii=False),
                 json.dumps(voce["violazioni"], ensure_ascii=False),
                 ordine * 10, adesso, int(esistente["id"])))
        else:
            execute(
                "INSERT INTO network_zones (tenant_id, key, name, description, icon,"
                " tone, expected_json, violated_json, is_builtin, sort_order,"
                " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
                (tenant_id, voce["chiave"], voce["nome"], voce["descrizione"],
                 voce["icona"], voce["tono"],
                 json.dumps(voce["attese"], ensure_ascii=False),
                 json.dumps(voce["violazioni"], ensure_ascii=False),
                 ordine * 10, adesso, adesso))
        scritte += 1
    if scritte:
        zones.dimentica_catalogo()
    return scritte


def semina_se_serve(tenant_id: int) -> int:
    """Semina solo se il tenant non ha ancora nessuna zona."""
    quante = query("SELECT COUNT(*) AS n FROM network_zones WHERE tenant_id = ?",
                   (tenant_id,), one=True)
    if quante and int(quante["n"] or 0) > 0:
        return 0
    return semina(tenant_id)


# --------------------------------------------------------------------------- #
# Validazione
# --------------------------------------------------------------------------- #
def _famiglie_valide(scelte) -> list:
    """Solo famiglie che corrispondono a una regola di correlazione (allowlist)."""
    ammesse = set(zones.famiglie_esposizione())
    return sorted({str(v).strip() for v in (scelte or []) if str(v).strip() in ammesse})


def _valida_comuni(nome: str, descrizione: str, icona: str, tono: str) -> tuple:
    nome = (nome or "").strip()[:MAX_NOME]
    if len(nome) < 2:
        raise ZonaError("Il nome della zona deve avere almeno due caratteri.")
    descrizione = (descrizione or "").strip()[:MAX_DESCRIZIONE]
    icona = (icona or "").strip() or "bi-diagram-3"
    if not ICONA_AMMESSA.match(icona):
        raise ZonaError("Icona non riconosciuta: si attende un nome come"
                        " `bi-hdd-rack`.")
    tono = (tono or "secondary").strip()
    if tono not in TONI:
        raise ZonaError("Colore non previsto.")
    return nome, descrizione, icona, tono


def _chiave_da_nome(nome: str, tenant_id: int) -> str:
    """Chiave ricavata dal nome, resa unica nel tenant.

    Si genera qui invece di chiederla: e' un dettaglio tecnico, e chiederlo a chi
    dichiara "rete di cantiere" sarebbe chiedere di fare un lavoro nostro.
    """
    base = re.sub(r"[^a-z0-9]+", "-", (nome or "").lower()).strip("-")[:24]
    base = base or "zona"
    if not base[0].isalpha():
        base = "z-" + base
    esistenti = set(zones.per_chiave(tenant_id))
    if base not in esistenti:
        return base
    for numero in range(2, 100):
        tentativo = "%s-%d" % (base, numero)
        if tentativo not in esistenti:
            return tentativo
    raise ZonaError("Troppe zone con un nome simile: sceglierne uno piu' distintivo.")


# --------------------------------------------------------------------------- #
# Operazioni
# --------------------------------------------------------------------------- #
def crea(tenant_id: int, nome: str, descrizione: str = "", icona: str = "bi-diagram-3",
         tono: str = "secondary", attese=None, violazioni=None,
         chiave: str = None, eredita_da: str = None) -> str:
    """Crea una zona e restituisce la sua chiave.

    `eredita_da` copia le famiglie attese e violate da una zona esistente, ma solo se
    non ne sono state indicate: cio' che l'operatore ha scelto vince sempre
    sull'ereditarieta', altrimenti una spunta togliuta tornerebbe da sola.
    """
    nome, descrizione, icona, tono = _valida_comuni(nome, descrizione, icona, tono)

    if eredita_da and not attese and not violazioni:
        madre = zones.per_chiave(tenant_id).get(eredita_da.strip())
        if madre is None:
            raise ZonaError("La zona da cui ereditare non esiste.")
        attese = list(madre.get("attese") or [])
        violazioni = list(madre.get("violazioni") or [])

    if chiave:
        chiave = chiave.strip().lower()
        if not CHIAVE_AMMESSA.match(chiave):
            raise ZonaError("Chiave non valida: minuscole, cifre e trattini, da 2 a 32"
                            " caratteri, iniziando per lettera.")
        if chiave in zones.per_chiave(tenant_id):
            raise ZonaError("Esiste gia' una zona con questa chiave.")
    else:
        chiave = _chiave_da_nome(nome, tenant_id)

    attese_valide = _famiglie_valide(attese)
    violazioni_valide = [f for f in _famiglie_valide(violazioni) if f not in attese_valide]

    adesso = utc_now_str()
    ordine = query("SELECT COALESCE(MAX(sort_order), 0) + 10 AS prossimo"
                   " FROM network_zones WHERE tenant_id = ?", (tenant_id,), one=True)
    prossimo = int(ordine["prossimo"] or 100) if ordine is not None else 100
    execute(
        "INSERT INTO network_zones (tenant_id, key, name, description, icon, tone,"
        " expected_json, violated_json, is_builtin, sort_order, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)",
        (tenant_id, chiave, nome, descrizione, icona, tono,
         json.dumps(attese_valide, ensure_ascii=False),
         json.dumps(violazioni_valide, ensure_ascii=False),
         prossimo, adesso, adesso))
    zones.dimentica_catalogo()
    return chiave


def aggiorna(tenant_id: int, chiave: str, nome: str, descrizione: str, icona: str,
             tono: str, attese=None, violazioni=None) -> None:
    """Modifica una zona esistente, predefinita compresa.

    Anche le zone nate col prodotto si possono modificare: su una rete reale
    "datacenter" puo' voler dire cose diverse, e imporre la nostra idea avrebbe come
    solo effetto che l'operatore smette di usare la funzione. Restano marcate come
    predefinite, cosi' il ripristino sa quali riportare all'origine.
    """
    riga = query("SELECT id FROM network_zones WHERE tenant_id = ? AND key = ?",
                 (tenant_id, chiave), one=True)
    if riga is None:
        raise ZonaError("Zona non trovata.")

    nome, descrizione, icona, tono = _valida_comuni(nome, descrizione, icona, tono)
    attese_valide = _famiglie_valide(attese)
    # Una famiglia non puo' essere attesa E violazione: sarebbe una regola che
    # contraddice se stessa, e il giudizio dipenderebbe dall'ordine di lettura.
    violazioni_valide = [f for f in _famiglie_valide(violazioni) if f not in attese_valide]

    execute(
        "UPDATE network_zones SET name = ?, description = ?, icon = ?, tone = ?,"
        " expected_json = ?, violated_json = ?, updated_at = ? WHERE id = ?",
        (nome, descrizione, icona, tono,
         json.dumps(attese_valide, ensure_ascii=False),
         json.dumps(violazioni_valide, ensure_ascii=False),
         utc_now_str(), int(riga["id"])))
    zones.dimentica_catalogo()


def subnet_che_la_usano(tenant_id: int, chiave: str) -> int:
    riga = query("SELECT COUNT(*) AS n FROM subnets WHERE tenant_id = ? AND zone = ?",
                 (tenant_id, chiave), one=True)
    return int(riga["n"] or 0) if riga is not None else 0


def elimina(tenant_id: int, chiave: str, riassegna_a: str = None) -> dict:
    """Elimina una zona. Le subnet che la usano vanno riassegnate, non abbandonate.

    Senza riassegnazione esplicita le subnet tornano SENZA zona, che vale come rete
    di utenza: il giudizio piu' severo. E' il verso giusto -- eliminando il contesto
    si perde la giustificazione, non la si eredita.
    """
    riga = query("SELECT id, is_builtin FROM network_zones WHERE tenant_id = ? AND key = ?",
                 (tenant_id, chiave), one=True)
    if riga is None:
        raise ZonaError("Zona non trovata.")

    quante = subnet_che_la_usano(tenant_id, chiave)
    destinazione = ""
    if quante and riassegna_a:
        destinazione = zones.valida(riassegna_a, tenant_id)
        if destinazione == chiave:
            raise ZonaError("La zona di destinazione non puo' essere quella eliminata.")
    if quante:
        execute("UPDATE subnets SET zone = ?, updated_at = ? WHERE tenant_id = ? AND zone = ?",
                (destinazione, utc_now_str(), tenant_id, chiave))

    execute("DELETE FROM network_zones WHERE id = ?", (int(riga["id"]),))
    zones.dimentica_catalogo()
    return {"subnet_riassegnate": quante, "destinazione": destinazione}


def riordina(tenant_id: int, chiave: str, verso: int) -> None:
    """Sposta una zona di una posizione nell'elenco."""
    voci = zones.catalogo(tenant_id)
    posizioni = [v["chiave"] for v in voci]
    if chiave not in posizioni:
        raise ZonaError("Zona non trovata.")
    indice = posizioni.index(chiave)
    scambio = indice + (1 if verso > 0 else -1)
    if scambio < 0 or scambio >= len(posizioni):
        return

    adesso = utc_now_str()
    posizioni[indice], posizioni[scambio] = posizioni[scambio], posizioni[indice]
    for ordine, voce in enumerate(posizioni, start=1):
        execute("UPDATE network_zones SET sort_order = ?, updated_at = ?"
                " WHERE tenant_id = ? AND key = ?", (ordine * 10, adesso, tenant_id, voce))
    zones.dimentica_catalogo()


# --------------------------------------------------------------------------- #
# Lettura per la pagina
# --------------------------------------------------------------------------- #
def elenco_per_pagina(tenant_id: int) -> list:
    """Zone con quante subnet e quanti dispositivi le riguardano.

    I conteggi sono la ragione per cui una pagina di configurazione si guarda: una
    zona dichiarata e mai usata e' un lavoro a metà, e una zona con 500 dispositivi
    non si elimina senza saperlo.
    """
    semina_se_serve(tenant_id)
    conteggi = {riga["zone"] or "": riga for riga in query(
        "SELECT COALESCE(s.zone, '') AS zone, COUNT(DISTINCT s.id) AS subnet,"
        " COUNT(n.id) AS nodi FROM subnets s"
        " LEFT JOIN nodes n ON n.subnet_id = s.id"
        " WHERE s.tenant_id = ? GROUP BY COALESCE(s.zone, '')", (tenant_id,))}

    voci = []
    for zona in zones.catalogo(tenant_id):
        misure = conteggi.get(zona["chiave"])
        voci.append(dict(zona,
                         subnet=int(misure["subnet"]) if misure else 0,
                         nodi=int(misure["nodi"]) if misure else 0))
    return voci


def senza_zona(tenant_id: int) -> dict:
    """Subnet e dispositivi che non hanno una zona dichiarata."""
    riga = query(
        "SELECT COUNT(DISTINCT s.id) AS subnet, COUNT(n.id) AS nodi FROM subnets s"
        " LEFT JOIN nodes n ON n.subnet_id = s.id"
        " WHERE s.tenant_id = ? AND COALESCE(s.zone, '') = ''", (tenant_id,), one=True)
    if riga is None:
        return {"subnet": 0, "nodi": 0}
    return {"subnet": int(riga["subnet"] or 0), "nodi": int(riga["nodi"] or 0)}
