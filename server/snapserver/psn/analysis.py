# -----------------------------------------------------------------
# psn/analysis.py — cio' che nel piano non torna, e le relazioni che non si vedono
# Autore: Daniele Speziale
# Data creazione: 2026-09-11
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Analisi del piano di indirizzamento.

E' LA RAGIONE PER CUI IL MODULO ESISTE. Importare un foglio in un database non
aggiunge nulla: si guardava un foglio, ora si guarda una tabella. Cio' che un foglio
non puo' fare e' RISPONDERE, e le risposte che contano sono sempre le stesse:

    questo hostname esiste due volte?              -> duplicate_hostname
    questo indirizzo e' scritto in due subnet?     -> duplicate_ip
    due subnet si sovrappongono?                   -> overlap
    un indirizzo e' fuori dalla propria subnet?    -> outside_subnet
    una subnet e' fuori dalla propria supernet?    -> outside_supernet
    quali nomi violano la convenzione?             -> naming
    quali rinomine sono in sospeso?                -> rename_pending
    un database punta a un tenant che non c'e'?    -> orphan_tenant
    una descrizione cita un indirizzo inesistente? -> dangling_reference
    una subnet e' senza CIDR?                      -> no_cidr

Ognuna di queste, su un foglio di settantanove schede e diciottomila righe, e' un
lavoro di mezza giornata a occhio -- e va rifatto a ogni versione del piano. Qui
sono un conto che si esegue all'importazione.

GRAVITA'. Tre livelli, e il criterio e' la conseguenza operativa, non l'estetica:
  critical  due cose diverse hanno lo stesso indirizzo: qualcosa NON funzionera'.
  warning   il piano si contraddice, ma funziona: va deciso, non subito.
  info      una convenzione non rispettata o una nota da lavorare.

remarks: Autore: Daniele Speziale - Data: 2026-09-11
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import ipaddress
import re

from . import db as psn_db
from .importer import hostname_utilizzabile

# Le rinomine che il piano stesso dichiara in sospeso: nel documento reale si
# leggono note come "DA RINOMINARE IN - bc-prod-dns02".
RE_RINOMINA = re.compile(r"da\s+rinominare", re.I)

RUOLI_INDICE = re.compile(r"^([a-z]+?)(\d{1,3})$")


def _rete(cidr: str):
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None


def _scrivi(import_id: int, kind: str, severity: str, title: str,
            detail: str = "", subject: str = "", subnet_id=None,
            address_id=None) -> None:
    psn_db.execute(
        "INSERT INTO psn_finding (import_id, kind, severity, title, detail,"
        " subject, subnet_id, address_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (import_id, kind, severity, title[:300], detail[:2000], subject[:200],
         subnet_id, address_id))


def analizza(import_id: int) -> dict:
    """Calcola i riscontri di un conferimento. Restituisce i conteggi per genere."""
    psn_db.execute("DELETE FROM psn_finding WHERE import_id = ?", (import_id,))
    conteggi = {}

    def conta(kind: str) -> None:
        conteggi[kind] = conteggi.get(kind, 0) + 1

    subnet = psn_db.query(
        "SELECT s.id, s.code, s.name, s.cidr, s.sheet_name, s.section_id,"
        " z.title AS section_title, z.supernet"
        " FROM psn_subnet s LEFT JOIN psn_section z ON z.id = s.section_id"
        " WHERE s.import_id = ? ORDER BY s.code", (import_id,))

    # --- subnet senza CIDR, e subnet fuori dalla propria supernet -----------
    reti = {}
    for riga in subnet:
        rete = _rete(riga["cidr"] or "")
        if rete is None:
            _scrivi(import_id, "no_cidr", "warning",
                    "Subnet %s senza CIDR valido" % riga["code"],
                    "Il foglio %r non dichiara una rete leggibile: senza CIDR non si"
                    " puo' dire se un indirizzo le appartenga, ne' contare i liberi."
                    % (riga["sheet_name"] or riga["name"]),
                    riga["name"], riga["id"])
            conta("no_cidr")
            continue
        reti[int(riga["id"])] = rete
        supernet = _rete(riga["supernet"] or "")
        if supernet is not None and not rete.subnet_of(supernet):
            _scrivi(import_id, "outside_supernet", "warning",
                    "La subnet %s (%s) non sta nella supernet della sua sezione"
                    % (riga["code"], rete),
                    "Sezione %r, supernet %s. O la subnet e' nella sezione"
                    " sbagliata, o la supernet dichiarata nel titolo non e' quella."
                    % (riga["section_title"], supernet),
                    str(rete), riga["id"])
            conta("outside_supernet")

    # --- sovrapposizioni fra subnet ----------------------------------------
    elenco = sorted(reti.items(), key=lambda v: (v[1].version, int(v[1].network_address)))
    for i, (id_a, rete_a) in enumerate(elenco):
        for id_b, rete_b in elenco[i + 1:]:
            if rete_b.network_address > rete_a.broadcast_address:
                break  # ordinate: oltre questo punto non si sovrappone piu' nulla
            if rete_a.overlaps(rete_b):
                nomi = {int(r["id"]): "%s (%s)" % (r["code"], r["name"])
                        for r in subnet}
                _scrivi(import_id, "overlap", "critical",
                        "Subnet sovrapposte: %s e %s" % (rete_a, rete_b),
                        "%s e %s condividono indirizzi. Due subnet sovrapposte nello"
                        " stesso piano non possono coesistere sulla rete: una delle"
                        " due non raggiungera' cio' che crede."
                        % (nomi.get(id_a, id_a), nomi.get(id_b, id_b)),
                        "%s | %s" % (rete_a, rete_b), id_a)
                conta("overlap")

    # --- indirizzi: duplicati, fuori subnet, rinomine -----------------------
    indirizzi = psn_db.query(
        "SELECT a.id, a.ip, a.hostname, a.description, a.notes, a.state,"
        " a.subnet_id, s.code, s.name AS subnet_name"
        " FROM psn_address a JOIN psn_subnet s ON s.id = a.subnet_id"
        " WHERE a.import_id = ? AND (a.hostname <> '' OR a.description <> '')",
        (import_id,))

    per_hostname = {}
    per_ip = {}
    etichette = {}
    for riga in indirizzi:
        if riga["hostname"]:
            # UN SEGNAPOSTO NON E' UN NOME. Nel piano reale la colonna hostname
            # contiene anche "-", "n/a" e etichette come "VIP 1": confrontarle fra
            # loro produceva riscontri come "il nome '-' e' su sei indirizzi", cioe'
            # rumore -- e il rumore in un elenco di conflitti fa ignorare anche i
            # conflitti veri. Si conservano (e' cio' che dice il foglio) ma si
            # dichiarano come qualita' del dato, non come duplicati.
            if hostname_utilizzabile(riga["hostname"]):
                per_hostname.setdefault(riga["hostname"].lower(), []).append(riga)
            else:
                etichette.setdefault(riga["hostname"].strip().lower(), []).append(riga)
        per_ip.setdefault(riga["ip"], []).append(riga)

        rete = reti.get(int(riga["subnet_id"]))
        if rete is not None:
            try:
                if ipaddress.ip_address(riga["ip"]) not in rete:
                    _scrivi(import_id, "outside_subnet", "critical",
                            "%s non appartiene alla subnet %s"
                            % (riga["ip"], rete),
                            "L'indirizzo e' elencato nel foglio della subnet %s (%s)"
                            " ma sta fuori dalla sua rete: uno dei due dati e'"
                            " sbagliato." % (riga["code"], riga["subnet_name"]),
                            riga["ip"], riga["subnet_id"], riga["id"])
                    conta("outside_subnet")
            except ValueError:
                pass

        testo = " ".join(filter(None, (riga["description"], riga["notes"])))
        if RE_RINOMINA.search(testo):
            _scrivi(import_id, "rename_pending", "info",
                    "Rinomina in sospeso: %s" % (riga["hostname"] or riga["ip"]),
                    testo, riga["hostname"] or riga["ip"], riga["subnet_id"],
                    riga["id"])
            conta("rename_pending")

    for nome, righe in etichette.items():
        _scrivi(import_id, "bad_hostname", "info",
                "Nella colonna hostname c'e' %r, che non e' un nome" % nome,
                "Compare su %d indirizzi (%s). E' un segnaposto o un'etichetta di"
                " ruolo: utile a chi legge, ma non e' il nome di una macchina, e non"
                " si puo' confrontare con gli altri per trovare duplicati."
                % (len(righe), ", ".join(r["ip"] for r in righe[:8])),
                nome, righe[0]["subnet_id"], righe[0]["id"])
        conta("bad_hostname")

    for nome, righe in per_hostname.items():
        if len(righe) > 1:
            _scrivi(import_id, "duplicate_hostname", "critical",
                    "Hostname %r su %d indirizzi" % (nome, len(righe)),
                    "Assegnato a: %s. Un nome che risolve su due indirizzi manda"
                    " meta' delle connessioni nel posto sbagliato, e il guasto"
                    " sembra intermittente."
                    % ", ".join("%s (subnet %s)" % (r["ip"], r["code"])
                                for r in righe),
                    nome, righe[0]["subnet_id"], righe[0]["id"])
            conta("duplicate_hostname")

    for ip, righe in per_ip.items():
        subnet_distinte = {int(r["subnet_id"]) for r in righe}
        if len(subnet_distinte) > 1:
            _scrivi(import_id, "duplicate_ip", "critical",
                    "Indirizzo %s usato in %d subnet" % (ip, len(subnet_distinte)),
                    "Compare in: %s."
                    % ", ".join(sorted({"%s (%s)" % (r["code"], r["subnet_name"])
                                        for r in righe})),
                    ip, righe[0]["subnet_id"], righe[0]["id"])
            conta("duplicate_ip")

    # --- conformita' dei nomi alla convenzione ------------------------------
    sigle = {}
    for riga in psn_db.query(
            "SELECT dimension, token FROM psn_naming_token WHERE import_id = ?",
            (import_id,)):
        sigle.setdefault(riga["dimension"], set()).add(riga["token"])

    if sigle.get("sito"):
        # DUE RISCONTRI DIVERSI, e la distinzione e' il punto.
        #
        # La prima stesura accusava ogni nome che non combaciava con la convenzione:
        # 79 riscontri su 257 nomi. Guardandoli, i nomi erano giusti e la CONVENZIONE
        # era incompleta -- il Nomenclatore elenca i siti dei data center (psn, bc,
        # dr, ac, pm) e non quelli delle Centrali Operative, che nei nomi ci sono
        # eccome: `ss` (S.Stefano), `sc` (S.Camillo), `sg` (S.Giovanni), `ri`
        # (Rieti), `lt` (Latina), `fr` (Frosinone), `an` (Anagnina). Accusare 79 nomi
        # perche' il vocabolario e' incompleto sposta la colpa sul posto sbagliato, e
        # un elenco di 79 righe non si legge: si chiude.
        #
        # Quindi:
        #   naming             il nome viola la FORMA (un segmento solo). Sono pochi
        #                      e sono veri.
        #   naming_vocabulary  una sigla USATA nei nomi non e' dichiarata nella
        #                      convenzione. Una riga per SIGLA, col numero di nomi
        #                      che la usano: e' una riga da portare a chi mantiene il
        #                      Nomenclatore, non un'accusa a chi ha battezzato le
        #                      macchine.
        sigle_ignote = {}
        for nome, righe in per_hostname.items():
            motivo, ignota = _giudica_nome(nome, sigle)
            if motivo:
                _scrivi(import_id, "naming", "info",
                        "Nome fuori dalla forma prevista: %s" % nome, motivo,
                        nome, righe[0]["subnet_id"], righe[0]["id"])
                conta("naming")
            if ignota:
                voce = sigle_ignote.setdefault(ignota, [])
                voce.append((nome, righe[0]))

        for sigla, usi in sorted(sigle_ignote.items(), key=lambda v: -len(v[1])):
            esempi = ", ".join(n for n, _ in usi[:6])
            _scrivi(import_id, "naming_vocabulary", "info",
                    "La sigla %r e' usata da %d nomi ma non e' nella convenzione"
                    % (sigla, len(usi)),
                    "Usata da: %s%s. O va aggiunta al Nomenclatore -- e' il caso"
                    " delle sigle delle Centrali Operative, che la convenzione non"
                    " elenca -- oppure quei nomi vanno corretti. Il prodotto non"
                    " decide quale delle due: dichiara la differenza."
                    % (esempi, " e altri" if len(usi) > 6 else ""),
                    sigla, usi[0][1]["subnet_id"], usi[0][1]["id"])
            conta("naming_vocabulary")

    # --- database orfani ----------------------------------------------------
    tenant_noti = {r["tgu"] for r in psn_db.query(
        "SELECT tgu FROM psn_tenant WHERE import_id = ?", (import_id,)) if r["tgu"]}
    for riga in psn_db.query(
            "SELECT id, tenant_tgu, service_name, db_unique_name FROM psn_database"
            " WHERE import_id = ? AND tenant_tgu <> ''", (import_id,)):
        if riga["tenant_tgu"] not in tenant_noti:
            _scrivi(import_id, "orphan_tenant", "warning",
                    "Database %s: tenant %s non in anagrafica"
                    % (riga["service_name"] or riga["db_unique_name"],
                       riga["tenant_tgu"]),
                    "Il foglio DB attribuisce questo servizio a un tenant che il"
                    " foglio Tenant non elenca: o il tenant manca dall'anagrafica,"
                    " o l'identificativo e' scritto male.",
                    riga["tenant_tgu"])
            conta("orphan_tenant")

    # --- riferimenti che non portano da nessuna parte -----------------------
    for riga in psn_db.query(
            "SELECT target, count(*) AS quanti FROM psn_reference"
            " WHERE import_id = ? AND address_id IS NULL AND target_kind = 'ip'"
            " GROUP BY target ORDER BY 2 DESC", (import_id,)):
        dentro_al_piano = any(
            _dentro(riga["target"], rete) for rete in reti.values())
        if dentro_al_piano:
            _scrivi(import_id, "dangling_reference", "warning",
                    "%s e' citato %d volte ma non compare nel piano"
                    % (riga["target"], riga["quanti"]),
                    "L'indirizzo appartiene a una subnet del piano, ma il foglio di"
                    " quella subnet non ha una riga per lui: manca una riga, oppure"
                    " la citazione e' sbagliata.", riga["target"])
            conta("dangling_reference")

    psn_db.commit()
    return conteggi


def _dentro(ip: str, rete) -> bool:
    try:
        return ipaddress.ip_address(ip) in rete
    except ValueError:
        return False


def _giudica_nome(hostname: str, sigle: dict) -> tuple:
    """`(motivo_di_forma, sigla_ignota)` per un hostname. Entrambi vuoti se va bene.

    LA CONVENZIONE, letta dal Nomenclatore e non inventata qui: un nome comincia con
    una sigla di SITO, e il segmento successivo e' una sigla dichiarata in una
    qualunque delle dimensioni della convenzione (ambiente, dominio, ...).

    PERCHE' "UNA QUALUNQUE" E NON "IL TENANT". La prima stesura pretendeva
    sito-tenant-ruolo e produceva 117 riscontri su un piano di 247 nomi: nomi come
    `ac-neu-rec` e `ac-urg-tdm` hanno al secondo posto un DOMINIO (`neu`) o una
    criticita' (`urg`), non un ambiente. Non erano nomi sbagliati: era la regola
    sbagliata. Una regola che dichiara non conforme meta' del parco non sta
    misurando la conformita', sta misurando se stessa.

    Il RUOLO resta libero: la convenzione non ne elenca i valori ammessi, e
    inventarne un elenco vorrebbe dire spacciare un nostro giudizio per regola del
    cliente.
    """
    pezzi = hostname.split("-")
    if len(pezzi) < 2:
        return ("Il nome non ha la forma sito-...-ruolo: un segmento solo non dice"
                " ne' il sito ne' l'ambito.", "")
    # Tutte le sigle della convenzione, in qualunque dimensione siano dichiarate:
    # nei nomi del piano il secondo posto ospita un ambiente, un dominio o una
    # criticita' indifferentemente, e pretenderne uno solo sarebbe una regola nostra.
    ammesse = set()
    for valori in sigle.values():
        ammesse |= set(valori)
    if pezzi[0] not in (sigle.get("sito") or set()):
        return ("", pezzi[0])
    if len(pezzi) >= 3 and pezzi[1] not in ammesse:
        return ("", pezzi[1])
    return ("", "")


# --------------------------------------------------------------------------- #
# Occupazione: la domanda che si fa ogni volta che si installa qualcosa
# --------------------------------------------------------------------------- #
def occupazione(import_id: int) -> list:
    """Per ogni subnet: quanti indirizzi assegnati, riservati, liberi, e il primo
    libero utilizzabile.

    E' il dato per cui si apre un piano di indirizzamento, e su un foglio si ottiene
    scorrendo 254 righe con l'occhio.
    """
    righe = psn_db.query(
        "SELECT s.id, s.code, s.name, s.cidr, s.traffic_class, s.sheet_name,"
        " z.title AS section_title, z.environment, z.criticality,"
        " count(a.id) AS totale,"
        " count(a.id) FILTER (WHERE a.state = 'assegnato') AS assegnati,"
        " count(a.id) FILTER (WHERE a.state = 'riservato') AS riservati,"
        " count(a.id) FILTER (WHERE a.state = 'libero') AS liberi,"
        " min(a.ip_sort) FILTER (WHERE a.state = 'libero') AS primo_libero"
        " FROM psn_subnet s"
        " LEFT JOIN psn_section z ON z.id = s.section_id"
        " LEFT JOIN psn_address a ON a.subnet_id = s.id"
        " WHERE s.import_id = ?"
        " GROUP BY s.id, s.code, s.name, s.cidr, s.traffic_class, s.sheet_name,"
        " z.title, z.environment, z.criticality"
        " ORDER BY s.code", (import_id,))
    esito = []
    for riga in righe:
        voce = dict(riga)
        totale = int(voce.get("totale") or 0)
        usati = int(voce.get("assegnati") or 0) + int(voce.get("riservati") or 0)
        voce["usati"] = usati
        voce["percentuale"] = round(usati * 100.0 / totale, 1) if totale else 0.0
        primo = voce.get("primo_libero")
        voce["primo_libero_ip"] = (str(ipaddress.ip_address(int(primo)))
                                   if primo else "")
        esito.append(voce)
    return esito
