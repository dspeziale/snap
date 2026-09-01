"""
snap server - Perimetro di scansione dichiarato dal tenant.

Le subnet arrivano da un file di testo caricato nella console: una per riga, in
notazione CIDR, con etichetta facoltativa e righe di commento. Il server le
valida e le consegna alla sonda nella configurazione cifrata; la sonda non
accetta bersagli che non siano contenuti in queste subnet.

La validazione e' la sede dell'autorizzazione: si accettano solo intervalli di
indirizzamento privato, salvo deroga esplicita, e si rifiutano perimetri troppo
ampi. Scansionare per errore una rete di terzi non e' un difetto di
funzionamento, e' un problema legale.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import ipaddress

from .audit import SEVERITY_WARNING, log_event
from .db import execute, query, utc_now_str

# Intervalli di indirizzamento privato ammessi senza deroga.
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),      # RFC 6598, indirizzamento di transito
    ipaddress.ip_network("192.0.2.0/24"),       # RFC 5737, documentazione e collaudo
    ipaddress.ip_network("fd00::/8"),           # RFC 4193, IPv6 locale
]

# Una singola passata piu' ampia di questo non e' ragionevole: durerebbe ore e
# disturberebbe la rete del cliente. Non e' pero' un motivo per RIFIUTARE una rete
# grande: chi dichiara una /16 sa quello che vuole, e il modo giusto di darglielo e'
# suddividerla in blocchi che stanno in questo limite, dichiarandolo. Il perimetro
# risultante e' lo stesso; cambia soltanto l'unita' di lavoro della sonda.
MAX_HOSTS_PER_SUBNET = 4096
# Oltre questo numero di blocchi non si suddivide: una /8 diventerebbe 4096 passate, e
# nessuno ha dichiarato di voler scansionare sedici milioni di indirizzi.
MAX_SPLIT_BLOCKS = 512
# Una rete aziendale segmentata puo' avere centinaia di subnet: il limite serve
# solo a fermare un file evidentemente sbagliato, non a contenere il perimetro.
MAX_SUBNETS_PER_TENANT = 2048
# Guardia sul totale degli indirizzi: e' questa, non il numero di subnet, la
# misura del lavoro che si chiede alla sonda.
MAX_TOTAL_ADDRESSES = 262144


class SubnetError(Exception):
    """Il perimetro proposto non e' accettabile."""


def _is_private(rete) -> bool:
    return any(rete.subnet_of(ammessa) for ammessa in PRIVATE_NETWORKS
               if rete.version == ammessa.version)


def _host_count(rete) -> int:
    """Numero di indirizzi assegnabili: per /31 e /32 si conta l'indirizzo stesso."""
    totale = rete.num_addresses
    return totale if totale <= 2 else totale - 2


def split_network(rete) -> list:
    """Suddivide una rete in blocchi che stanno dentro MAX_HOSTS_PER_SUBNET.

    Si scende di un bit alla volta fino al primo prefisso abbastanza piccolo: per una
    /16 con limite 4096 il risultato sono sedici blocchi /20. Blocchi grandi riducono
    il numero di passate; scendere oltre il necessario le moltiplicherebbe senza
    guadagno. Elenco vuoto significa "non suddivisibile entro il massimo di blocchi".
    """
    if _host_count(rete) <= MAX_HOSTS_PER_SUBNET:
        return [rete]
    prefisso = rete.prefixlen
    while prefisso < rete.max_prefixlen:
        prefisso += 1
        if 2 ** (prefisso - rete.prefixlen) > MAX_SPLIT_BLOCKS:
            return []
        campione = next(rete.subnets(new_prefix=prefisso))
        if _host_count(campione) <= MAX_HOSTS_PER_SUBNET:
            return list(rete.subnets(new_prefix=prefisso))
    return []


def parse_subnet_file(text: str, allow_public: bool = False) -> dict:
    """Interpreta il file del perimetro.

    Formato di ogni riga:  <CIDR> [etichetta libera]
    Le righe vuote e quelle che iniziano con '#' sono ignorate.

    Restituisce {'subnets': [...], 'errors': [...], 'lines': n}: gli errori non
    interrompono la lettura, cosi' l'operatore li vede tutti in una volta.
    """
    accettate = []
    errori = []
    suddivise = []
    viste = {}
    righe = (text or "").splitlines()

    for numero, riga in enumerate(righe, start=1):
        contenuto = riga.strip()
        if not contenuto or contenuto.startswith("#"):
            continue

        pezzi = contenuto.split(None, 1)
        grezzo = pezzi[0].strip()
        etichetta = pezzi[1].strip() if len(pezzi) > 1 else ""
        # Un'etichetta puo' essere introdotta anche da un commento a fine riga.
        if etichetta.startswith("#"):
            etichetta = etichetta.lstrip("#").strip()

        try:
            rete = ipaddress.ip_network(grezzo, strict=False)
        except ValueError as errore:
            errori.append({"line": numero, "value": grezzo,
                           "reason": "notazione non valida: %s" % errore})
            continue

        if not allow_public and not _is_private(rete):
            errori.append({"line": numero, "value": str(rete),
                           "reason": "non appartiene a un intervallo di indirizzamento privato"})
            continue

        # Una rete piu' ampia del limite di una passata viene suddivisa in blocchi: il
        # perimetro dichiarato resta lo stesso, cambia l'unita' di lavoro della sonda.
        blocchi = split_network(rete)
        if not blocchi:
            errori.append({"line": numero, "value": str(rete),
                           "reason": "perimetro troppo ampio: %d indirizzi, oltre il"
                                     " massimo suddivisibile (%d blocchi da %d)"
                                     % (_host_count(rete), MAX_SPLIT_BLOCKS,
                                        MAX_HOSTS_PER_SUBNET)})
            continue
        if len(blocchi) > 1:
            suddivise.append({"line": numero, "value": str(rete),
                              "blocchi": len(blocchi),
                              "prefisso": blocchi[0].prefixlen,
                              "indirizzi": _host_count(rete)})

        for indice, blocco in enumerate(blocchi, start=1):
            canonica = str(blocco)
            if canonica in viste:
                errori.append({"line": numero, "value": canonica,
                               "reason": "ripetuta (gia' dichiarata alla riga %d)"
                                         % viste[canonica]})
                continue

            sovrapposta = next(
                (altra for altra in accettate
                 if blocco.version == ipaddress.ip_network(altra["cidr"]).version
                 and blocco.overlaps(ipaddress.ip_network(altra["cidr"]))), None)
            if sovrapposta is not None:
                errori.append({"line": numero, "value": canonica,
                               "reason": "si sovrappone a %s" % sovrapposta["cidr"]})
                continue

            # L'etichetta porta l'origine: senza, sedici righe /20 non si
            # riconoscerebbero piu' come la /16 che qualcuno ha dichiarato.
            if len(blocchi) > 1:
                origine = "%s (%d/%d di %s)" % (etichetta or "blocco", indice,
                                                len(blocchi), rete)
            else:
                origine = etichetta
            viste[canonica] = numero
            accettate.append({"cidr": canonica, "label": origine[:120],
                              "host_count": _host_count(blocco), "line": numero})

    # Il superamento dei limiti complessivi non tronca: dichiara il rifiuto. Un
    # perimetro troncato sembrerebbe completo senza esserlo.
    totale_indirizzi = sum(v["host_count"] for v in accettate)
    if len(accettate) > MAX_SUBNETS_PER_TENANT:
        raise SubnetError("troppe subnet: %d, il limite per tenant e' %d"
                          % (len(accettate), MAX_SUBNETS_PER_TENANT))
    if totale_indirizzi > MAX_TOTAL_ADDRESSES:
        raise SubnetError("perimetro complessivo troppo ampio: %d indirizzi, il limite e' %d"
                          % (totale_indirizzi, MAX_TOTAL_ADDRESSES))

    return {"subnets": accettate, "errors": errori, "lines": len(righe),
            "total_hosts": totale_indirizzi, "split": suddivise}


def import_subnets(tenant_id: int, text: str, source_file: str, user_id: int | None = None,
                   replace: bool = False, allow_public: bool = False) -> dict:
    """Importa il perimetro per un tenant.

    `replace` disabilita le subnet non piu' presenti nel file invece di
    cancellarle: i nodi gia' scoperti restano collegati alla propria subnet e la
    storia non si perde.
    """
    esito = parse_subnet_file(text, allow_public=allow_public)
    if not esito["subnets"] and esito["errors"]:
        raise SubnetError("nessuna subnet valida nel file: %d righe rifiutate"
                          % len(esito["errors"]))

    adesso = utc_now_str()
    esistenti = {riga["cidr"]: riga for riga in query(
        "SELECT * FROM subnets WHERE tenant_id = ?", (tenant_id,))}

    aggiunte, aggiornate = [], []
    for voce in esito["subnets"]:
        precedente = esistenti.get(voce["cidr"])
        if precedente is None:
            execute(
                "INSERT INTO subnets (tenant_id, cidr, label, is_enabled, host_count,"
                " source_file, imported_by, imported_at, created_at, updated_at)"
                " VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?)",
                (tenant_id, voce["cidr"], voce["label"], voce["host_count"],
                 source_file, user_id, adesso, adesso, adesso),
            )
            aggiunte.append(voce["cidr"])
        else:
            execute(
                "UPDATE subnets SET label = ?, host_count = ?, is_enabled = 1,"
                " source_file = ?, imported_by = ?, imported_at = ?, updated_at = ?"
                " WHERE id = ? AND tenant_id = ?",
                (voce["label"] or precedente["label"], voce["host_count"], source_file,
                 user_id, adesso, adesso, int(precedente["id"]), tenant_id),
            )
            aggiornate.append(voce["cidr"])

    disabilitate = []
    if replace:
        presenti = {v["cidr"] for v in esito["subnets"]}
        for cidr, riga in esistenti.items():
            if cidr not in presenti and int(riga["is_enabled"]):
                execute("UPDATE subnets SET is_enabled = 0, updated_at = ?"
                        " WHERE id = ? AND tenant_id = ?",
                        (adesso, int(riga["id"]), tenant_id))
                disabilitate.append(cidr)

    log_event(
        event_type="subnets.imported",
        description="Perimetro importato da %s: %d nuove, %d aggiornate, %d disabilitate, "
                    "%d righe rifiutate" % (source_file, len(aggiunte), len(aggiornate),
                                            len(disabilitate), len(esito["errors"])),
        tenant_id=tenant_id,
        severity=SEVERITY_WARNING if esito["errors"] else "info",
        entity="subnet",
    )

    return {
        "added": aggiunte,
        "updated": aggiornate,
        "disabled": disabilitate,
        "errors": esito["errors"],
        "total_hosts": sum(v["host_count"] for v in esito["subnets"]),
        # Reti suddivise: la pagina lo dichiara, altrimenti chi ha scritto una riga se
        # ne ritrova sedici senza capire perche'.
        "split": esito.get("split", []),
    }


def active_subnets(tenant_id: int) -> list[dict]:
    """Perimetro attivo, nella forma consegnata alla sonda."""
    righe = query(
        "SELECT cidr, label, host_count FROM subnets"
        " WHERE tenant_id = ? AND is_enabled = 1 ORDER BY cidr",
        (tenant_id,),
    )
    return [{"cidr": r["cidr"], "label": r["label"], "hosts": int(r["host_count"])}
            for r in righe]


def subnet_of_address(tenant_id: int, address: str) -> int | None:
    """Identificativo della subnet che contiene un indirizzo, se dichiarata."""
    try:
        indirizzo = ipaddress.ip_address(address)
    except ValueError:
        return None
    for riga in query("SELECT id, cidr FROM subnets WHERE tenant_id = ?", (tenant_id,)):
        try:
            rete = ipaddress.ip_network(riga["cidr"])
        except ValueError:
            continue  # riga corrotta in banca dati: si ignora, non si indovina
        if indirizzo.version == rete.version and indirizzo in rete:
            return int(riga["id"])
    return None


def within_perimeter(subnets: list, address: str) -> bool:
    """Verifica di appartenenza al perimetro, usata anche dalla sonda."""
    try:
        indirizzo = ipaddress.ip_address(address)
    except ValueError:
        return False
    for voce in subnets:
        cidr = voce.get("cidr") if isinstance(voce, dict) else voce
        try:
            rete = ipaddress.ip_network(cidr)
        except (ValueError, TypeError):
            continue
        if indirizzo.version == rete.version and indirizzo in rete:
            return True
    return False
