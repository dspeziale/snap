# -----------------------------------------------------------------
# snmp_scoperta.py — scoperta automatica degli apparati di rete interrogabili
# Autore: Daniele Speziale
# Data creazione: 2026-09-09
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap probe - Trova gli apparati che possono fornire le corrispondenze IP->MAC.

PERCHE'
-------
Le tabelle ARP degli apparati sono l'unico modo di avere il MAC dei nodi su subnet
instradate (ARP non attraversa un router). Ma dichiarare gli apparati a mano non
regge su una rete di migliaia di nodi e decine di subnet: si dimenticano, cambiano,
e nessuno tiene aggiornato un elenco scritto a mano.

COME SI DECIDE CHE UN INDIRIZZO E' UN APPARATO DA INTERROGARE
-------------------------------------------------------------
Non per aspetto. Un candidato entra nell'elenco solo se SUPERA UNA PROVA: risponde in
SNMP con la community configurata e ha una tabella ARP con almeno una voce. E' il
solo criterio che conta, perche' e' esattamente cio' che serve -- un apparato che
"sembra" un router ma non risponde non serve a niente, e uno che risponde ma non ha
tabella ARP non aggiunge dati.

I candidati si ricavano da cio' che la sonda GIA' sa, senza scansioni aggiuntive:

* gli indirizzi di gateway di ogni subnet del perimetro (primo e ultimo utilizzabile:
  e' dove sta un router in nove reti su dieci) -- una congettura, che la prova
  confermera' o scartera';
* i nodi dell'inventario locale che hanno la 161/UDP aperta: quella non e' una
  congettura, e' un'osservazione;
* i nodi con porte da apparato di rete (SSH e Telnet insieme, o servizi di gestione)
  che la fase di rilevazione ha gia' visto.

LA COMMUNITY DI FABBRICA
------------------------
Se un candidato risponde con "public" o "private" NON viene aggiunto all'elenco -- il
modello tiene una community sola, e non si puo' registrare quella di un singolo
apparato -- ma viene SEGNALATO: un apparato di rete che risponde con la community di
fabbrica e' un'esposizione, non un dettaglio di configurazione. Chi legge il diario
deve trovarlo scritto.
"""

from __future__ import annotations

import ipaddress

from . import snmp, snmp_raccolta

# Community di fabbrica: non e' un tentativo di indovinare credenziali, sono i valori
# predefiniti che si trovano ancora oggi sugli apparati -- e trovarli aperti E' il
# riscontro (la stessa scelta, con la stessa motivazione, e' in scanner.py).
COMMUNITY_DI_FABBRICA = ("public", "private")

# Porte che, viste aperte insieme, indicano un apparato di rete piu' che un server.
PORTE_DA_APPARATO = ({22, 23}, {23, 161}, {22, 161}, {161})

# Quanti candidati si provano al massimo in una scoperta. Ogni prova e' un paio di
# pacchetti UDP con attesa breve, ma su un perimetro con decine di subnet il numero
# cresce e la scoperta non deve durare piu' di un ciclo di scansione.
MAX_CANDIDATI = 200

# Attese brevi: qui non si vuole leggere una tabella, si vuole sapere se risponde.
TIMEOUT_PROVA = 1.5
TENTATIVI_PROVA = 1


def _gateway_probabili(cidr: str) -> list[str]:
    """Primo e ultimo indirizzo utilizzabile di una subnet.

    E' una congettura dichiarata: in nove reti su dieci il router sta su `.1` oppure
    sull'ultimo indirizzo. La prova SNMP dira' se e' vero -- qui si sceglie solo chi
    interrogare per primo, non chi finisce nell'elenco.
    """
    try:
        rete = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    if rete.num_addresses < 4:
        return []
    ospiti = list(rete.hosts())
    return [str(ospiti[0]), str(ospiti[-1])]


def _porte_aperte(nodo) -> set[int]:
    import json

    try:
        profilo = json.loads(nodo.get("profile_json") or "{}")
    except (TypeError, ValueError):
        return set()
    porte = set()
    for chiave, voce in (profilo.get("ports_index") or {}).items():
        if isinstance(voce, dict) and voce.get("state") == "open":
            try:
                porte.add(int(voce.get("port")))
            except (TypeError, ValueError):
                continue
    return porte


def candidati(scanner) -> list[dict]:
    """Indirizzi da provare, con il motivo per cui sono stati scelti.

    Il motivo si conserva e si scrive nel diario: chi guardera' l'elenco fra sei mesi
    deve poter sapere perche' un indirizzo e' finito fra gli apparati.
    """
    store = scanner.store
    visti: dict[str, list[str]] = {}

    def aggiungi(indirizzo: str, motivo: str) -> None:
        try:
            ipaddress.ip_address(indirizzo)
        except ValueError:
            return
        visti.setdefault(indirizzo, [])
        if motivo not in visti[indirizzo]:
            visti[indirizzo].append(motivo)

    # 1. I gateway probabili di ogni subnet del perimetro.
    for voce in scanner.perimeter() or []:
        cidr = voce["cidr"] if isinstance(voce, dict) else voce
        for indirizzo in _gateway_probabili(cidr):
            aggiungi(indirizzo, "gateway probabile di %s" % cidr)

    # 2. I nodi che la sonda ha OSSERVATO con la 161 aperta, o con porte da apparato.
    for nodo in store.local_nodes("confirmed"):
        porte = _porte_aperte(nodo)
        if not porte:
            continue
        if 161 in porte:
            aggiungi(nodo["ip"], "161/UDP osservata aperta")
            continue
        for insieme in PORTE_DA_APPARATO:
            if insieme <= porte:
                aggiungi(nodo["ip"], "porte da apparato di rete (%s)"
                                     % ",".join(str(p) for p in sorted(insieme)))
                break

    elenco = [{"indirizzo": ip, "motivi": motivi} for ip, motivi in visti.items()]
    # Prima i nodi osservati, poi le congetture: se il limite taglia, taglia le
    # congetture.
    elenco.sort(key=lambda v: any(m.startswith("gateway") for m in v["motivi"]))
    return elenco[:MAX_CANDIDATI]


def _prova(indirizzo: str, community: str) -> dict | None:
    """Interroga un candidato. `None` se non risponde con quella community.

    La prova e' quella che conta: si legge la tabella ARP. Un apparato che risponde
    ma non ha voci ARP non aggiunge dati all'inventario, e va saputo subito.
    """
    try:
        tabella = snmp.arp_table(indirizzo, community,
                                 timeout=TIMEOUT_PROVA, tentativi=TENTATIVI_PROVA)
    except snmp.SnmpError:
        return None
    identita = {}
    try:
        identita = snmp.identifica(indirizzo, community,
                                   timeout=TIMEOUT_PROVA, tentativi=TENTATIVI_PROVA)
    except snmp.SnmpError:
        pass
    return {"voci_arp": len(tabella),
            "nome": identita.get("nome", ""),
            "descrizione": identita.get("descrizione", "")}


def _etichetta(indirizzo: str, esito: dict) -> str:
    """Etichetta dell'apparato: il nome dichiarato dall'apparato stesso, se c'e'.

    Il nome viene da `sysName`, cioe' da come l'apparato si chiama in rete: e' piu'
    utile di un'etichetta inventata, e diventa la PROVENIENZA del MAC nell'inventario.
    Si ripulisce perche' finisce in un campo di configurazione a righe: un `|` o un
    ritorno a capo spezzerebbero l'elenco.
    """
    nome = (esito.get("nome") or "").strip().replace("|", " ").replace("\n", " ")
    nome = " ".join(nome.split())[:60]
    return nome or indirizzo


def scopri(scanner, aggiungi_all_elenco: bool = True) -> dict:
    """Prova i candidati e popola l'elenco degli apparati con quelli che rispondono.

    Restituisce un riassunto con, per ogni candidato, l'esito e il motivo: e' cio'
    che permette di capire perche' un apparato non e' stato aggiunto, invece di
    guardare un elenco vuoto senza spiegazione.
    """
    store = scanner.store
    configurata = (store.get_setting(snmp_raccolta.CHIAVE_COMMUNITY, "") or "").strip()

    esito = {"candidati": 0, "aggiunti": [], "di_fabbrica": [], "muti": 0,
             "senza_arp": [], "community_configurata": bool(configurata)}

    elenco = candidati(scanner)
    esito["candidati"] = len(elenco)
    if not elenco:
        store.log("warning", "Scoperta degli apparati: nessun candidato. Serve un"
                             " perimetro configurato o almeno una scansione svolta.")
        return esito

    gia_presenti = {a["indirizzo"] for a in snmp_raccolta.apparati_dichiarati(store)}
    nuovi = []

    for candidato in elenco:
        indirizzo = candidato["indirizzo"]
        motivi = ", ".join(candidato["motivi"])

        risposta = _prova(indirizzo, configurata) if configurata else None
        if risposta is not None:
            if not risposta["voci_arp"]:
                # Risponde ma non ha tabella ARP: nell'elenco non serve, e dirlo
                # evita di cercare il motivo per cui non arrivano MAC.
                esito["senza_arp"].append({"indirizzo": indirizzo, "motivi": motivi,
                                           "nome": risposta["nome"]})
                continue
            etichetta = _etichetta(indirizzo, risposta)
            esito["aggiunti"].append({"indirizzo": indirizzo, "etichetta": etichetta,
                                      "voci_arp": risposta["voci_arp"],
                                      "motivi": motivi,
                                      "descrizione": risposta["descrizione"][:120]})
            if indirizzo not in gia_presenti:
                nuovi.append("%s|%s" % (indirizzo, etichetta))
            continue

        # La community configurata non ha funzionato (o non c'e'): si prova con
        # quelle di fabbrica. Non per usarle -- per SEGNALARLE.
        for fabbrica in COMMUNITY_DI_FABBRICA:
            if fabbrica == configurata:
                continue
            aperto = _prova(indirizzo, fabbrica)
            if aperto is None:
                continue
            esito["di_fabbrica"].append({"indirizzo": indirizzo,
                                         "community": fabbrica,
                                         "nome": aperto["nome"],
                                         "voci_arp": aperto["voci_arp"]})
            store.log("warning",
                      "Apparato %s risponde in SNMP con la community di fabbrica"
                      " '%s': e' un'esposizione da chiudere. Non e' stato aggiunto"
                      " all'elenco -- il prodotto conserva una sola community."
                      % (indirizzo, fabbrica))
            break
        else:
            esito["muti"] += 1

    if nuovi and aggiungi_all_elenco:
        attuale = (store.get_setting(snmp_raccolta.CHIAVE_APPARATI, "") or "").rstrip()
        righe = ([attuale] if attuale else []) + nuovi
        store.set_setting(snmp_raccolta.CHIAVE_APPARATI, "\n".join(righe))
        store.log("info", "Scoperta degli apparati: %d aggiunti all'elenco (%s)"
                          % (len(nuovi), ", ".join(n.split("|")[0] for n in nuovi)))
    elif not esito["aggiunti"]:
        store.log("warning",
                  "Scoperta degli apparati: %d candidati provati, nessuno ha"
                  " risposto con la community configurata%s"
                  % (len(elenco),
                     "" if configurata else " (community non impostata)"))
    return esito
