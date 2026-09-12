# -----------------------------------------------------------------
# psn/importer.py — dal foglio del piano all'archivio PSN
# Autore: Daniele Speziale
# Data creazione: 2026-09-11
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Importazione del piano di indirizzamento PSN.

LE REGOLE DI LETTURA, dichiarate qui perche' sono l'unico punto in cui questo
prodotto fa un'ipotesi sul foglio di qualcun altro. Se il piano cambia forma, e'
questo file che va aggiornato, e il lettore dice quali fogli non ha riconosciuto
invece di importarne meta' in silenzio.

  `Summary`            anagrafica delle subnet. Una riga con uno "/" nella colonna
                       della subnet e un codice accanto e' una subnet; una riga con
                       il solo testo nella prima colonna e' l'intestazione di una
                       SEZIONE, e le sezioni portano la supernet, l'ambiente e la
                       criticita' nel proprio titolo.
  fogli di indirizzo   uno per subnet, con `ID:` e `Label:` nelle prime righe e una
                       riga per indirizzo. Cinque forme di intestazione diverse: si
                       mappa per NOME di colonna (vedi `xlsx.Foglio.tabella`).
  `Tenant`             gli ambienti PSN, con l'identificativo TGU.
  `DB`                 i database Oracle, col tenant che li ospita. Due blocchi:
                       i database e l'area di staging.
  `URL-VIP`            i servizi pubblicati: cluster, VIP, URL.
  `OverviewSubnet`     la catena WAF: URL pubblico -> indirizzo -> backend.
  `Nomenclatore_1.1`   la convenzione dei nomi, per dimensione.
  `Integrazioni`       integrazioni verso terzi, conservate come servizi.

COSA NON SI FA. Non si "aggiusta" il dato: un CIDR malformato entra come testo e
l'analisi lo dichiara; un tenant citato da un database ma assente dall'anagrafica
resta un orfano visibile. Un importatore che corregge in silenzio costruisce una
verita' che non e' quella del documento, e allora tanto vale il documento.

remarks: Autore: Daniele Speziale - Data: 2026-09-11
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re

from ..db import utc_now_str
from . import db as psn_db
from .xlsx import Libro, pulito

# I fogli che NON sono elenchi di indirizzi: hanno una struttura propria.
FOGLI_STRUTTURALI = {
    "Tenant", "Nomenclatore_1.1", "DB", "Summary", "Integrazioni", "URL-VIP",
    "OverviewSubnet",
}

RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_CIDR = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\s*/\s*(\d{1,2})\b")
# Un hostname del piano: lettere, cifre e trattini, almeno due segmenti separati da
# trattino (bc-prod-ipa01). Serve a trovare citazioni nel testo libero senza
# raccogliere ogni parola.
RE_HOSTNAME = re.compile(r"\b([a-z0-9]+(?:-[a-z0-9]+){1,5})\b", re.I)
RE_VERSIONE = re.compile(r"V\.?\s*(\d+(?:\.\d+)*)", re.I)

# Le dimensioni del nomenclatore, come compaiono nelle intestazioni del foglio.
DIMENSIONI_NOMENCLATORE = ("sito", "tenant", "dominio", "ruolo", "ambiente",
                           "servizio", "tipo")


# Il nome di un foglio di indirizzi porta la propria rete: "10.58.3.0 |24". La barra
# e' diventata una pipe perche' un nome di foglio non puo' contenere "/".
RE_RETE_DA_FOGLIO = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s*[|/]\s*(\d{1,2})")

# Hostname che non sono hostname: segnaposto e etichette. Nel piano reale ci sono
# celle con "-", "n/a" e "VIP 1" nella colonna dell'hostname. Trattarli come nomi
# produceva finti duplicati ("il nome '-' e' su sei indirizzi"), che e' rumore --
# e il rumore in un elenco di conflitti fa ignorare anche i conflitti veri.
SEGNAPOSTO_HOSTNAME = {"-", "--", "---", "n/a", "na", "nd", "n.d.", "?", "??",
                       "tbd", "da definire", "libero", "non assegnato"}
RE_HOSTNAME_VALIDO = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62})$", re.I)


def hostname_utilizzabile(valore: str) -> bool:
    """Vero se il testo puo' essere un hostname, non un segnaposto o un'etichetta.

    Un'etichetta con spazi ("VIP 1") descrive un ruolo, non una macchina: conservarla
    e' giusto -- e' cio' che dice il foglio -- ma confrontarla con gli altri nomi per
    trovare duplicati non lo e'.
    """
    testo = (valore or "").strip()
    if not testo or testo.lower() in SEGNAPOSTO_HOSTNAME:
        return False
    return bool(RE_HOSTNAME_VALIDO.match(testo))


def ricostruisci_ip(testo: str, rete):
    """Un indirizzo da una cella che Excel ha salvato come NUMERO.

    IL CASO MISURATO. Nel foglio "DC S.Stefano Housing Voip" gli indirizzi sono
    scritti senza punti -- `192168230128` invece di `192.168.230.128` -- perche' le
    celle sono numeriche. Nessun lettore li riconosce come indirizzi, e quel foglio
    risultava vuoto: 128 indirizzi persi in silenzio.

    Si ricostruisce solo quando la ricostruzione e' UNIVOCA dentro la subnet
    dichiarata dal foglio: si provano tutte le suddivisioni in quattro ottetti e si
    tiene quella -- una sola -- che cade nella rete. Con zero o piu' candidati non si
    indovina: l'indirizzo si scarta e lo si dichiara. Indovinare un indirizzo in un
    piano di indirizzamento e' peggio che perderlo.
    """
    cifre = (testo or "").strip()
    if not cifre.isdigit() or not (7 <= len(cifre) <= 12) or rete is None:
        return None
    candidati = set()
    for a in range(1, 4):
        for b in range(1, 4):
            for c in range(1, 4):
                d = len(cifre) - a - b - c
                if not 1 <= d <= 3:
                    continue
                pezzi = [cifre[:a], cifre[a:a + b], cifre[a + b:a + b + c],
                         cifre[a + b + c:]]
                if any(len(p) > 1 and p[0] == "0" for p in pezzi):
                    continue  # "01" non e' un ottetto scritto da un essere umano
                if any(int(p) > 255 for p in pezzi):
                    continue
                indirizzo = ".".join(str(int(p)) for p in pezzi)
                try:
                    if ipaddress.ip_address(indirizzo) in rete:
                        candidati.add(indirizzo)
                except ValueError:
                    continue
    return candidati.pop() if len(candidati) == 1 else None


def _numero_ip(ip: str) -> int:
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0


def _rete(cidr: str):
    """La rete di un CIDR, o `None` se il testo non e' un CIDR."""
    trovato = RE_CIDR.search(cidr or "")
    if not trovato:
        return None
    try:
        return ipaddress.ip_network("%s/%s" % trovato.groups(), strict=False)
    except ValueError:
        return None


def _ambiente_e_criticita(titolo: str) -> tuple:
    """Ambiente e criticita' dal titolo di una sezione.

    I titoli del piano dichiarano entrambi, in prosa: "IAAS - PRODUZIONE
    EMERGENZA/URGENZA - 10.58.0.0 /18" dice IaaS, produzione, urgenza. Sono le
    dimensioni con cui si legge tutto il resto, e restavano in una cella di testo.
    """
    t = (titolo or "").upper()
    ambiente = ""
    if "PRODUZIONE" in t:
        ambiente = "produzione"
    elif "COLLAUDO" in t:
        ambiente = "collaudo"
    elif "HOUSING" in t or "SEDI" in t:
        ambiente = "housing"
    elif "WAF" in t:
        ambiente = "perimetro"
    criticita = ""
    if "NON URGENZA" in t:
        criticita = "non urgenza"
    elif "URGENZA" in t or "EMERGENZA" in t:
        criticita = "urgenza"
    return ambiente, criticita


def _classe_di_traffico(descrizione: str, nome: str) -> str:
    testo = ("%s %s" % (descrizione or "", nome or "")).lower()
    if "management" in testo or " mng" in testo:
        return "management"
    if "voip" in testo:
        return "voip"
    if "dati" in testo:
        return "dati"
    if nome.upper().startswith("VNET"):
        return "vnet"
    return ""


def _stato_indirizzo(ip: str, rete, hostname: str, descrizione: str) -> str:
    """Come e' usato un indirizzo.

    Distinguere "libero" da "non assegnabile" e' il punto: chi cerca il prossimo
    indirizzo disponibile non deve trovarsi proposto l'indirizzo di rete.
    """
    testo = (descrizione or "").lower()
    if rete is not None:
        try:
            indirizzo = ipaddress.ip_address(ip)
            if indirizzo == rete.network_address:
                return "rete"
            if rete.version == 4 and indirizzo == rete.broadcast_address:
                return "broadcast"
        except ValueError:
            pass
    if "broadcast" in testo:
        return "broadcast"
    # UN SEGNAPOSTO NON E' UN'ASSEGNAZIONE. Una riga con "-" nella colonna hostname e
    # una descrizione e' una PRENOTAZIONE: qualcuno ha scritto a che cosa serve
    # quell'indirizzo, non che macchina ci sta. Contarla fra gli assegnati gonfia
    # l'occupazione, che e' il numero per cui si apre un piano di indirizzamento.
    if hostname_utilizzabile(hostname):
        return "assegnato"
    if "gateway" in testo:
        return "gateway"
    if descrizione:
        # Una descrizione senza hostname e' una prenotazione: qualcuno ha scritto a
        # che cosa serve quell'indirizzo prima che l'apparato esistesse.
        return "riservato"
    return "libero"


class Esito:
    """Il resoconto di un'importazione: conteggi e avvisi."""

    def __init__(self):
        self.conteggi = {}
        self.avvisi = []
        self.import_id = 0

    def piu(self, chiave: str, quanti: int = 1) -> None:
        self.conteggi[chiave] = self.conteggi.get(chiave, 0) + quanti

    def avvisa(self, testo: str) -> None:
        if testo not in self.avvisi:
            self.avvisi.append(testo)


def importa(percorso_o_dati, nome_file: str, utente: str = "") -> Esito:
    """Legge il foglio e lo scrive nell'archivio PSN. Restituisce l'esito.

    L'importazione e' una TRANSAZIONE: o entra tutto il piano, o niente. Un piano
    importato a meta' sarebbe peggio di nessun piano, perche' sembrerebbe completo.
    """
    dati = (percorso_o_dati.read() if hasattr(percorso_o_dati, "read")
            else open(percorso_o_dati, "rb").read())
    impronta = hashlib.sha256(dati).hexdigest()
    esito = Esito()

    gia = psn_db.query("SELECT id, file_name, imported_at FROM psn_import"
                       " WHERE sha256 = ?", (impronta,), one=True)
    if gia is not None:
        esito.import_id = int(gia["id"])
        esito.avvisa("Questo file era gia' stato importato il %s come %s:"
                     " nessun nuovo conferimento."
                     % (gia["imported_at"], gia["file_name"]))
        return esito

    import io as _io

    versione = ""
    trovato = RE_VERSIONE.search(nome_file or "")
    if trovato:
        versione = trovato.group(1)

    with Libro(_io.BytesIO(dati)) as libro:
        esito.import_id = psn_db.execute(
            "INSERT INTO psn_import (file_name, version, sha256, size_bytes,"
            " imported_at, imported_by, sheets_total, counts_json, warnings_json)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, '{}', '[]')",
            (nome_file, versione, impronta, len(dati), utc_now_str(), utente,
             len(libro.fogli)))

        subnet_per_codice = _importa_anagrafica(libro, esito)
        _importa_indirizzi(libro, esito, subnet_per_codice)
        _importa_tenant(libro, esito)
        _importa_database(libro, esito)
        _importa_servizi(libro, esito)
        _importa_nomenclatore(libro, esito)
        _estrai_riferimenti(esito)

    psn_db.execute(
        "UPDATE psn_import SET counts_json = ?, warnings_json = ? WHERE id = ?",
        (json.dumps(esito.conteggi, ensure_ascii=False),
         json.dumps(esito.avvisi, ensure_ascii=False), esito.import_id))
    psn_db.commit()
    return esito


# --------------------------------------------------------------------------- #
# Anagrafica: sezioni e subnet
# --------------------------------------------------------------------------- #
def _importa_anagrafica(libro: Libro, esito: Esito) -> dict:
    foglio = libro.foglio("Summary")
    if foglio is None:
        esito.avvisa("Foglio 'Summary' assente: senza anagrafica le subnet non"
                     " hanno codice ne' CIDR.")
        return {}

    per_codice = {}
    sezione_id = None
    posizione = 0
    for riga in foglio.righe():
        celle = [pulito(c) for c in riga] + [""] * 6
        prima, nome, subnet, codice, descrizione = (celle[0], celle[1], celle[2],
                                                    celle[3], celle[4])
        # Una riga di subnet: CIDR nella colonna della subnet e un codice accanto.
        if "/" in subnet and codice:
            rete = _rete(subnet)
            cidr = str(rete) if rete is not None else subnet
            netmask = ""
            if " - " in subnet:
                netmask = subnet.split(" - ", 1)[1].strip()
            identificativo = psn_db.execute(
                "INSERT INTO psn_subnet (import_id, section_id, code, name, cidr,"
                " netmask, traffic_class, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (esito.import_id, sezione_id, codice, nome or codice, cidr, netmask,
                 _classe_di_traffico(descrizione, nome), descrizione))
            per_codice[codice] = identificativo
            esito.piu("subnet")
            continue
        # Un'intestazione di sezione: testo nella prima colonna e nessuna subnet.
        if prima and not subnet and not codice and len(prima) > 3:
            rete = _rete(prima)
            ambiente, criticita = _ambiente_e_criticita(prima)
            posizione += 1
            sezione_id = psn_db.execute(
                "INSERT INTO psn_section (import_id, position, title, supernet,"
                " environment, criticality) VALUES (?, ?, ?, ?, ?, ?)",
                (esito.import_id, posizione, prima,
                 str(rete) if rete is not None else "", ambiente, criticita))
            esito.piu("sezioni")
    return per_codice


# --------------------------------------------------------------------------- #
# Indirizzi: un foglio per subnet
# --------------------------------------------------------------------------- #
def _intestazione_foglio(foglio) -> dict:
    """`ID:` e `Label:` dalle prime righe di un foglio di indirizzi."""
    testa = {}
    for indice, riga in enumerate(foglio.righe()):
        if indice > 3:
            break
        for i, cella in enumerate(riga):
            chiave = pulito(cella).rstrip(":").strip().lower()
            if chiave in ("id", "label") and i + 1 < len(riga):
                testa.setdefault(chiave, pulito(riga[i + 1]))
    return testa


def _importa_indirizzi(libro: Libro, esito: Esito, subnet_per_codice: dict) -> None:
    for foglio in libro.fogli:
        if foglio.nome in FOGLI_STRUTTURALI:
            continue
        testa = _intestazione_foglio(foglio)
        codice = testa.get("id", "")
        subnet_id = subnet_per_codice.get(codice)

        # IL CODICE SCRITTO NEL FOGLIO PUO' ESSERE SBAGLIATO, e nel piano reale lo
        # e'. Il foglio "10.58.70.0 |24" dichiara `ID: 041`, ma in anagrafica 041 e'
        # 10.58.80.0/24 (il .70 e' il 040) -- e i fogli di 10.58.80.0 e 10.58.93.0
        # non esistono affatto. Fidandosi del codice, 254 indirizzi del .70
        # finirebbero archiviati sotto la subnet del .80: un dato sbagliato che
        # sembra giusto.
        #
        # Il nome del foglio porta la propria rete, ed e' il dato piu' difficile da
        # sbagliare: se contraddice il codice e in anagrafica c'e' una subnet con
        # QUELLA rete, si sceglie quella e si dichiara la discordanza. Il piano va
        # corretto, ma nel frattempo gli indirizzi stanno dove appartengono.
        rete_del_nome = None
        trovato = RE_RETE_DA_FOGLIO.search(foglio.nome)
        if trovato:
            try:
                rete_del_nome = ipaddress.ip_network("%s/%s" % trovato.groups(),
                                                     strict=False)
            except ValueError:
                rete_del_nome = None
        if rete_del_nome is not None and subnet_id is not None:
            atteso = psn_db.query("SELECT cidr FROM psn_subnet WHERE id = ?",
                                  (subnet_id,), one=True)
            if _rete((atteso or {}).get("cidr") or "") != rete_del_nome:
                corretto = psn_db.query(
                    "SELECT id, code FROM psn_subnet WHERE import_id = ? AND cidr = ?",
                    (esito.import_id, str(rete_del_nome)), one=True)
                if corretto is not None:
                    esito.avvisa(
                        "Foglio %r: dichiara ID %s, che in anagrafica e' %s; la rete"
                        " del nome del foglio corrisponde invece alla subnet %s. Gli"
                        " indirizzi sono stati archiviati sotto %s."
                        % (foglio.nome, codice, (atteso or {}).get("cidr"),
                           corretto["code"], corretto["code"]))
                    esito.piu("codici_foglio_discordanti")
                    subnet_id = int(corretto["id"])
                    codice = corretto["code"]
                else:
                    esito.avvisa(
                        "Foglio %r: dichiara ID %s (%s in anagrafica), che non"
                        " corrisponde alla rete del nome del foglio, e nessuna subnet"
                        " in anagrafica ha quella rete."
                        % (foglio.nome, codice, (atteso or {}).get("cidr")))
                    esito.piu("codici_foglio_discordanti")
        if subnet_id is None:
            # Un foglio senza corrispondenza in anagrafica: si registra la subnet
            # comunque, perche' il foglio E' il dato. Un foglio scartato in silenzio
            # sarebbe una perdita invisibile.
            etichetta = testa.get("label") or foglio.nome
            subnet_id = psn_db.execute(
                "INSERT INTO psn_subnet (import_id, code, name, cidr, netmask,"
                " traffic_class, sheet_name, description)"
                " VALUES (?, ?, ?, '', '', ?, ?, ?)",
                (esito.import_id, codice or ("foglio:%s" % foglio.nome), etichetta,
                 _classe_di_traffico("", etichetta), foglio.nome,
                 "subnet non presente nell'anagrafica Summary"))
            esito.piu("subnet_senza_anagrafica")
            esito.avvisa("Foglio %r: il codice %r non e' nell'anagrafica Summary;"
                         " la subnet e' stata registrata dal foglio."
                         % (foglio.nome, codice))
        else:
            psn_db.execute("UPDATE psn_subnet SET sheet_name = ? WHERE id = ?",
                           (foglio.nome, subnet_id))

        riga_subnet = psn_db.query(
            "SELECT cidr FROM psn_subnet WHERE id = ?", (subnet_id,), one=True)
        rete = _rete((riga_subnet or {}).get("cidr") or "") or rete_del_nome

        quanti = 0
        recuperati = 0
        illeggibili = 0
        for voce in foglio.tabella(("ip",)):
            ip = pulito(voce.get("ip", ""))
            if not RE_IP.fullmatch(ip):
                # Excel puo' aver salvato l'indirizzo come NUMERO, senza i punti:
                # succede in un foglio del piano reale. Si ricostruisce solo se la
                # ricostruzione e' univoca dentro la rete del foglio.
                recuperato = ricostruisci_ip(ip, rete or rete_del_nome)
                if recuperato is None:
                    if ip:
                        illeggibili += 1
                    continue
                ip = recuperato
                recuperati += 1
            hostname = pulito(voce.get("hostname", ""))
            descrizione = pulito(voce.get("descrizione", ""))
            note = pulito(voce.get("note", ""))
            vecchio = pulito(voce.get("old_hostname", "")
                             or voce.get("old hostname", ""))
            psn_db.execute(
                "INSERT INTO psn_address (import_id, subnet_id, ip, ip_sort,"
                " hostname, description, notes, old_hostname, state)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (esito.import_id, subnet_id, ip, _numero_ip(ip), hostname,
                 descrizione, note, vecchio,
                 _stato_indirizzo(ip, rete, hostname, descrizione)))
            quanti += 1
        esito.piu("indirizzi", quanti)
        if recuperati:
            esito.piu("indirizzi_ricostruiti", recuperati)
            esito.avvisa(
                "Foglio %r: %d indirizzi erano salvati come numeri senza punti"
                " (celle numeriche) e sono stati ricostruiti dentro la rete del"
                " foglio. Senza questa ricostruzione il foglio risultava vuoto."
                % (foglio.nome, recuperati))
        if illeggibili:
            esito.piu("indirizzi_illeggibili", illeggibili)
            esito.avvisa("Foglio %r: %d celle nella colonna IP non sono indirizzi"
                         " leggibili e sono state scartate." % (foglio.nome, illeggibili))
        if not quanti:
            esito.avvisa("Foglio %r: nessun indirizzo riconosciuto." % foglio.nome)


# --------------------------------------------------------------------------- #
# Tenant, database, servizi, nomenclatore
# --------------------------------------------------------------------------- #
def _normalizza_tgu(testo: str) -> str:
    """"PSN 02 84 27 23" -> "PSN02842723".

    Nel foglio lo stesso identificativo e' scritto in tre modi (con spazi, senza,
    con un suffisso "-??"). Senza normalizzazione il collegamento fra un database e
    il suo tenant non si trova, e ogni database sembrerebbe orfano.
    """
    pulita = re.sub(r"[^A-Za-z0-9?]", "", testo or "").upper()
    return pulita


def _importa_tenant(libro: Libro, esito: Esito) -> None:
    foglio = libro.foglio("Tenant")
    if foglio is None:
        esito.avvisa("Foglio 'Tenant' assente.")
        return
    for voce in foglio.tabella(("tgu/id", "tenant/ambienti")):
        grezzo = pulito(voce.get("tgu/id", ""))
        nome = pulito(voce.get("tenant/ambienti", ""))
        if not grezzo and not nome:
            continue
        if grezzo.upper().startswith("COMPLETARE"):
            esito.avvisa("Foglio 'Tenant': una riga e' un promemoria (%r), non un"
                         " tenant." % grezzo[:40])
            continue
        psn_db.execute(
            "INSERT INTO psn_tenant (import_id, tgu, tgu_raw, name, state, zone,"
            " ip, source, notes, verify) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (esito.import_id, _normalizza_tgu(grezzo), grezzo,
             nome.replace("\n", " ").strip(), pulito(voce.get("stato", "")),
             pulito(voce.get("zona", "")), pulito(voce.get("ip", "")),
             pulito(voce.get("fonte", "")), pulito(voce.get("note", "")),
             1 if "?" in grezzo else 0))
        esito.piu("tenant")


def _importa_database(libro: Libro, esito: Esito) -> None:
    foglio = libro.foglio("DB")
    if foglio is None:
        esito.avvisa("Foglio 'DB' assente.")
        return
    # Il foglio ha DUE blocchi con intestazioni diverse: i database e l'area di
    # staging. Si leggono le righe a mano, riconoscendo il blocco dall'intestazione.
    chiavi = None
    genere = "database"
    for riga in foglio.righe():
        celle = [pulito(c) for c in riga] + [""] * 10
        minuscole = [c.lower() for c in celle]
        if "area di staging" in " ".join(minuscole):
            genere = "staging"
            chiavi = None
            continue
        if "porta" in minuscole and ("servicename" in minuscole or "utente" in minuscole):
            chiavi = minuscole
            continue
        if chiavi is None or not celle[0]:
            continue
        if not RE_IP.search(celle[0]):
            continue
        voce = {chiavi[i]: celle[i] for i in range(min(len(chiavi), len(celle)))}
        psn_db.execute(
            "INSERT INTO psn_database (import_id, tenant_tgu, ip_tenant, ip_sed,"
            " port, service_name, sid, db_user, db_unique_name, pdb, kind, notes)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (esito.import_id, _normalizza_tgu(voce.get("tenant", "")),
             voce.get("ip da tenant ised", "") or celle[0],
             voce.get("ip da sed", ""), voce.get("porta", ""),
             voce.get("servicename", ""), voce.get("sid", ""),
             voce.get("user", "") or voce.get("utente", ""),
             voce.get("db unique name", ""), voce.get("pdb", ""), genere,
             voce.get("visibile da:", "")))
        esito.piu("database")


def _importa_servizi(libro: Libro, esito: Esito) -> None:
    # URL-VIP: cluster -> VIP -> URL.
    foglio = libro.foglio("URL-VIP")
    if foglio is not None:
        for voce in foglio.tabella(("vip", "url")):
            etichetta = ""
            for chiave, valore in voce.items():
                if "cluster" in chiave:
                    etichetta = pulito(valore)
            url = pulito(voce.get("url", ""))
            vip = pulito(voce.get("vip", ""))
            if not (url or vip or etichetta):
                continue
            psn_db.execute(
                "INSERT INTO psn_service (import_id, source, label, url, vip,"
                " backends, description, notes) VALUES (?, 'URL-VIP', ?, ?, ?, '', '', '')",
                (esito.import_id, etichetta, url, vip))
            esito.piu("servizi")

    # OverviewSubnet: la catena del WAF, con i backend citati nella descrizione.
    foglio = libro.foglio("OverviewSubnet")
    if foglio is not None:
        for voce in foglio.tabella(("label", "ip", "hostname")):
            etichetta = pulito(voce.get("label", ""))
            ip = pulito(voce.get("ip", ""))
            hostname = pulito(voce.get("hostname", ""))
            descrizione = pulito(voce.get("descrizione", ""))
            if not (etichetta or ip or hostname):
                continue
            backend = sorted(set(RE_IP.findall(descrizione)))
            url = hostname if hostname.lower().startswith("http") else ""
            psn_db.execute(
                "INSERT INTO psn_service (import_id, source, label, url, vip,"
                " backends, description, notes)"
                " VALUES (?, 'OverviewSubnet', ?, ?, ?, ?, ?, ?)",
                (esito.import_id, etichetta or hostname, url, ip,
                 ",".join(backend), descrizione, pulito(voce.get("note", ""))))
            esito.piu("servizi")

    # Integrazioni: si conservano come servizi, con la riga intera nella descrizione.
    foglio = libro.foglio("Integrazioni")
    if foglio is not None:
        for riga in foglio.righe():
            celle = [pulito(c) for c in riga if pulito(c)]
            if len(celle) < 2:
                continue
            psn_db.execute(
                "INSERT INTO psn_service (import_id, source, label, url, vip,"
                " backends, description, notes)"
                " VALUES (?, 'Integrazioni', ?, '', '', ?, ?, '')",
                (esito.import_id, celle[0][:200],
                 ",".join(sorted(set(RE_IP.findall(" ".join(celle))))),
                 " | ".join(celle[1:])[:1000]))
            esito.piu("integrazioni")


def _importa_nomenclatore(libro: Libro, esito: Esito) -> None:
    """La convenzione dei nomi, letta per COLONNE.

    Il foglio dispone le dimensioni in orizzontale: ogni dimensione ha
    un'intestazione ("Sito (*)", "Tenant (*)", "Dominio") e sotto le sigle ammesse
    con il loro significato nella colonna accanto. Si leggono quindi le colonne, non
    le righe.
    """
    foglio = libro.foglio("Nomenclatore_1.1")
    if foglio is None:
        esito.avvisa("Foglio 'Nomenclatore_1.1' assente: la conformita' dei nomi"
                     " non si puo' verificare.")
        return
    righe = [[pulito(c) for c in r] for r in foglio.righe()]
    if not righe:
        return
    largo = max(len(r) for r in righe)
    for r in righe:
        r.extend([""] * (largo - len(r)))

    # Le intestazioni delle dimensioni: la prima riga che contiene una di esse.
    colonne = {}
    for riga in righe[:4]:
        for i, cella in enumerate(riga):
            nome = re.sub(r"\(\*\)", "", cella).strip().lower()
            if nome in DIMENSIONI_NOMENCLATORE:
                colonne[i] = nome
    if not colonne:
        esito.avvisa("Foglio 'Nomenclatore_1.1': nessuna dimensione riconosciuta"
                     " fra %s." % ", ".join(DIMENSIONI_NOMENCLATORE))
        return

    for indice, dimensione in colonne.items():
        for riga in righe:
            sigla = riga[indice].strip().lower()
            if not sigla or sigla == dimensione or len(sigla) > 24:
                continue
            if not re.fullmatch(r"[a-z0-9]{1,12}", sigla):
                continue
            significato = riga[indice + 1] if indice + 1 < largo else ""
            psn_db.execute(
                "INSERT INTO psn_naming_token (import_id, dimension, token, meaning)"
                " VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING",
                (esito.import_id, dimensione, sigla, significato[:300]))
            esito.piu("sigle_nomenclatore")


# --------------------------------------------------------------------------- #
# I riferimenti nascosti nel testo libero
# --------------------------------------------------------------------------- #
def _estrai_riferimenti(esito: Esito) -> None:
    """Trova nelle descrizioni gli indirizzi e gli hostname che citano ALTRE righe.

    E' il passo che trasforma settantanove schede in un grafo. Nel piano le
    relazioni ci sono ma sono scritte in prosa: "10.58.1.10 (sso-sie, ...)" dentro la
    descrizione di un indirizzo del WAF significa che quel WAF serve quell'host, in
    un'altra subnet. Nessuna formula collega le due celle.
    """
    indirizzi = psn_db.query(
        "SELECT id, ip, hostname, description, notes FROM psn_address"
        " WHERE import_id = ?", (esito.import_id,))
    per_ip = {}
    per_hostname = {}
    for riga in indirizzi:
        per_ip.setdefault(riga["ip"], int(riga["id"]))
        if riga["hostname"]:
            per_hostname.setdefault(riga["hostname"].lower(), int(riga["id"]))

    def registra(genere: str, sorgente: int, testo: str) -> None:
        if not testo:
            return
        for ip in set(RE_IP.findall(testo)):
            if ip in per_ip and per_ip[ip] != sorgente:
                psn_db.execute(
                    "INSERT INTO psn_reference (import_id, from_kind, from_id,"
                    " target_kind, target, address_id, context)"
                    " VALUES (?, ?, ?, 'ip', ?, ?, ?)",
                    (esito.import_id, genere, sorgente, ip, per_ip[ip], testo[:300]))
                esito.piu("riferimenti")
            elif ip not in per_ip:
                psn_db.execute(
                    "INSERT INTO psn_reference (import_id, from_kind, from_id,"
                    " target_kind, target, address_id, context)"
                    " VALUES (?, ?, ?, 'ip', ?, NULL, ?)",
                    (esito.import_id, genere, sorgente, ip, testo[:300]))
                esito.piu("riferimenti_non_risolti")
        for nome in set(n.lower() for n in RE_HOSTNAME.findall(testo)):
            if nome in per_hostname and per_hostname[nome] != sorgente:
                psn_db.execute(
                    "INSERT INTO psn_reference (import_id, from_kind, from_id,"
                    " target_kind, target, address_id, context)"
                    " VALUES (?, ?, ?, 'hostname', ?, ?, ?)",
                    (esito.import_id, genere, sorgente, nome,
                     per_hostname[nome], testo[:300]))
                esito.piu("riferimenti")

    for riga in indirizzi:
        registra("address", int(riga["id"]),
                 " ".join(filter(None, (riga["description"], riga["notes"]))))

    for riga in psn_db.query(
            "SELECT id, description, notes, backends FROM psn_service"
            " WHERE import_id = ?", (esito.import_id,)):
        registra("service", int(riga["id"]),
                 " ".join(filter(None, (riga["description"], riga["notes"],
                                        riga["backends"]))))
