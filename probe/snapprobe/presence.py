# -----------------------------------------------------------------
# presence.py — ricognizione continua delle reti senza fili
# Autore: Daniele Speziale
# Data creazione: 2026-09-10
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap probe - Chi c'e' adesso, su una rete senza fili.

PERCHE' UN PROCESSO A PARTE
---------------------------
Il ciclo ordinario e' fatto per una rete cablata: la scoperta ripassa il perimetro
ogni tre giorni, le porte ogni sei ore, e la profondita' con cui guarda ciascun nodo
e' il suo pregio. Su una rete senza fili quel ritmo non vede niente: un telefono che
entra in una stanza resta agganciato dieci minuti, un portatile si sospende, e fra
due passate della scoperta sono passati tre giorni. L'inventario finisce per
raccontare la rete di tre giorni fa.

Serve l'opposto: una ricognizione **breve** (solo "chi risponde", nessuna porta,
nessun sistema operativo) e **frequente** (minuti). Le due cose non si possono
ottenere allargando le cadenze del ciclo ordinario, perche' quel ciclo ha una sola
riserva di lavoro e una passata di porte dura minuti: la ricognizione arriverebbe
sempre dopo. Ha percio' un thread proprio, non prende posti nel pool di scansione, e
non tocca lo stato delle fasi degli altri nodi.

CHE COSA FA, QUANDO TROVA QUALCUNO
----------------------------------
1. conferisce l'avvistamento: e' quello che tiene lo storico delle presenze sul
   server (chi c'era e quando -- vedi `presence.py` del server, dove sta la parte
   difficile, l'identita');
2. se l'indirizzo non era noto, lo mette in **testa** alla coda dell'esame delle
   porte e sveglia il ciclo: un apparato che compare su una rete senza fili va
   guardato ADESSO, perche' fra dieci minuti non c'e' piu'. Senza questo, un nuovo
   nodo aspetterebbe il proprio turno dietro centinaia di altri e verrebbe esaminato
   quando e' gia' andato via.

CHE COSA NON FA
---------------
Non esamina porte, non rileva sistemi operativi, non legge pagine: tutto
l'arricchimento resta al ciclo ordinario, che sa farlo e sa non ripeterlo. Questa e'
solo la domanda "c'e' qualcuno?", posta spesso.

PRUDENZA SUL TEMPO PER HOST
---------------------------
Un apparato radio in risparmio energetico spegne la radio fra i beacon: misurato su
questa installazione, i tempi di risposta arrivano a 2 secondi con scarti di oltre un
secondo, contro i 2-17 ms di un apparato cablato. Un tempo per host aggressivo --
quello che renderebbe la ricognizione istantanea -- non troverebbe proprio gli
apparati che questa ricognizione esiste per trovare. Da qui `ATTESA_HOST`: breve per
una scansione, generosa per una radio.
"""

from __future__ import annotations

import ipaddress
import time

from . import mac_costruttori, nmap_xml
from .nmap_runner import NmapError, NmapTimeout
from .store import utc_now_str

# Ogni quanto si ripassa una rete senza fili, se il server non dice altro. Due minuti
# e' il ritmo del monitoraggio: abbastanza spesso da vedere una permanenza breve,
# abbastanza raro da non pesare su una rete di utenza.
INTERVALLO_PREDEFINITO_SEC = 120

# Tempo massimo per host. Vedi la nota sulla prudenza nel docstring del modulo: sotto
# il secondo si perdono gli apparati radio in risparmio energetico, che sono la
# ragione di questa ricognizione.
ATTESA_HOST = "3s"

# Tempo massimo del PROCESSO, per subnet. Una /24 con questi parametri si esaurisce
# in pochi secondi; il tetto serve al caso in cui la rete non risponda affatto, per
# non tenere occupato il thread fino alla passata successiva.
ATTESA_PROCESSO_SEC = 180

# Quante reti senza fili si ripassano in una passata. Piu' di cosi' e la "ricognizione
# breve" non sarebbe piu' breve: le altre toccano alla passata successiva.
MAX_SUBNET_PER_PASSATA = 4

# Quanti indirizzi possono attendere l'esame prioritario delle porte. E' un tetto di
# sicurezza: su una rete di utenza affollata si presentano decine di apparati, e la
# coda prioritaria non deve diventare l'intera coda -- altrimenti "prioritario" non
# significa piu' niente.
MAX_PRIORITA = 128

# Chiavi nell'archivio locale della sonda.
CHIAVE_PRIORITA = "presence_priority"
CHIAVE_ULTIMA = "presence_last_run_at"
CHIAVE_STATO = "presence_last_result"


def subnet_senza_fili(perimetro: list) -> list:
    """I CIDR del perimetro dichiarati come reti senza fili.

    Il perimetro arriva dal server; una voce che non porta il campo (una sonda che
    parla con un server piu' vecchio) NON e' senza fili: la ricognizione si attiva
    per dichiarazione, non per supposizione.
    """
    scelte = []
    for voce in perimetro or []:
        if not isinstance(voce, dict):
            continue
        if not voce.get("wifi"):
            continue
        cidr = (voce.get("cidr") or "").strip()
        if not cidr:
            continue
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            # Una riga corrotta non si indovina: la scansione ordinaria la rifiuta
            # allo stesso modo.
            continue
        scelte.append(cidr)
    return scelte


class PresenceWatcher:
    """Ricognizione delle presenze sulle reti senza fili, in un thread proprio.

    Condivide con lo scanner l'esecutore di nmap (le esecuzioni sono cosi' contate e
    interrompibili insieme alle altre) e il perimetro, che e' vincolante anche qui:
    si ripassano solo le reti dichiarate.
    """

    def __init__(self, store, scanner):
        self.store = store
        self.scanner = scanner

    # -- configurazione ------------------------------------------------------
    def intervallo(self) -> int:
        """Ogni quanti secondi si ripassa. Dal server, con un minimo di 30 secondi.

        Il minimo non e' prudenza generica: sotto quella soglia due passate si
        sovrappongono su una rete lenta, e la seconda misurerebbe la prima.
        """
        cadenze = self.scanner.cadences()
        try:
            valore = int(cadenze.get("presence") or INTERVALLO_PREDEFINITO_SEC)
        except (TypeError, ValueError):
            self.store.log("warning",
                           "Cadenza della ricognizione non valida: si usa %d s"
                           % INTERVALLO_PREDEFINITO_SEC)
            return INTERVALLO_PREDEFINITO_SEC
        return max(30, valore)

    def reti(self) -> list:
        return subnet_senza_fili(self.scanner.perimeter())

    def due(self) -> bool:
        """Se e' il momento di ripassare. Falso se non ci sono reti senza fili."""
        if not self.reti():
            return False
        consentito, _ = self.scanner.scanning_allowed()
        if not consentito:
            return False
        ultima = self.store.get_setting(CHIAVE_ULTIMA, None)
        if not ultima:
            return True
        from datetime import datetime, timezone

        try:
            momento = datetime.strptime(ultima, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return True
        trascorsi = (datetime.now(timezone.utc) - momento).total_seconds()
        return trascorsi >= self.intervallo()

    # -- la passata ----------------------------------------------------------
    def run_once(self) -> dict:
        """Una passata su tutte le reti senza fili dovute.

        Restituisce l'esito, con i record da conferire. Non solleva per una rete che
        non risponde: le altre devono essere ripassate comunque.
        """
        reti = self.reti()
        if not reti:
            return {"stage": "presence", "subnets": 0, "records": {}}

        consentito, motivo = self.scanner.scanning_allowed()
        if not consentito:
            return {"stage": "presence", "subnets": 0, "records": {},
                    "detail": motivo}

        # Chi e' stato esaminato esce dalla coda prioritaria: lasciarlo dentro
        # sposterebbe la priorita' su nodi che non ne hanno piu' bisogno, e dopo un
        # po' la coda sarebbe l'inventario.
        self._pota_priorita()

        avvio = time.monotonic()
        inizio = utc_now_str()
        nodi = []
        presenze = []
        nuovi = []
        esaminate = 0
        for cidr in self._prossime(reti):
            esito = self._passata_su(cidr)
            esaminate += 1
            nodi.extend(esito["nodes"])
            presenze.extend(esito["presence"])
            nuovi.extend(esito["new"])
            self.store.set_setting("presence_last_%s" % cidr, utc_now_str())

        self.store.set_setting(CHIAVE_ULTIMA, utc_now_str())
        durata = time.monotonic() - avvio
        if nuovi:
            # In testa alla coda delle porte: su una rete senza fili un apparato
            # comparso va guardato adesso, non al proprio turno.
            self.segna_priorita(nuovi)
        dettaglio = ("%d reti, %d apparati presenti, %d nuovi, in %.1f s"
                     % (esaminate, len(presenze), len(nuovi), durata))
        self.store.set_json(CHIAVE_STATO, {
            "at": utc_now_str(), "subnets": esaminate, "seen": len(presenze),
            "new": len(nuovi), "duration_sec": round(durata, 1)})
        if presenze:
            self.store.log("info", "Ricognizione delle presenze: " + dettaglio)
        record = {}
        if nodi:
            record["nodes"] = nodi
        if presenze:
            record["presence"] = presenze
        return {"stage": "presence", "subnets": esaminate, "seen": len(presenze),
                "new": nuovi, "records": record, "started_at": inizio,
                "duration_ms": int(durata * 1000), "detail": dettaglio}

    def _prossime(self, reti: list) -> list:
        """Le reti da ripassare in questa passata, le meno recenti per prime.

        Con piu' reti senza fili di quante ne stiano in una passata, girare sempre
        dalla prima lascerebbe l'ultima mai osservata.
        """
        def ultima(cidr):
            return self.store.get_setting("presence_last_%s" % cidr, "") or ""

        return sorted(reti, key=ultima)[:MAX_SUBNET_PER_PASSATA]

    def _passata_su(self, cidr: str) -> dict:
        """La ricognizione su una rete: chi risponde, e chi non c'era prima."""
        argomenti = ["-sn", "-PE", "-PS80,443,22,3389,445", "-PA80", "-PR", "-T4",
                     "--max-retries", "1", "--host-timeout", ATTESA_HOST]
        try:
            xml = self.scanner.runner.run(argomenti, [cidr],
                                          timeout=ATTESA_PROCESSO_SEC,
                                          label="presenze su %s" % cidr)
        except NmapTimeout as errore:
            # Il tetto di tempo e' una condizione prevista: la rete si ripassa alla
            # cadenza successiva, e nel frattempo non si dichiara nessuna assenza.
            self.store.log("warning", "Ricognizione di %s oltre il tempo massimo: %s"
                                      % (cidr, errore))
            return {"nodes": [], "presence": [], "new": []}
        except NmapError as errore:
            self.store.log("warning", "Ricognizione di %s non eseguita: %s"
                                      % (cidr, errore))
            return {"nodes": [], "presence": [], "new": []}

        try:
            letto = nmap_xml.parse_scan(xml, ports_examined=False)
        except nmap_xml.NmapXmlError as errore:
            self.store.log("warning", "Esito della ricognizione di %s illeggibile: %s"
                                      % (cidr, errore))
            return {"nodes": [], "presence": [], "new": []}

        adesso = utc_now_str()
        nodi = []
        presenze = []
        nuovi = []
        for prove in letto["nodes"] + letto["candidates"]:
            if prove.get("reachable") is False:
                # nmap elenca anche host che dichiara giu': un avvistamento e' una
                # presenza, e un host giu' non e' presente.
                continue
            ip = prove["ip"]
            esistente = self.store.local_node(ip)
            # "Nuovo" significa: mai visto, o visto e scartato perche' non aveva
            # niente da dire. Il secondo caso conta come nuovo su una rete senza
            # fili -- l'apparato di prima non e' quello di adesso.
            e_nuovo = esistente is None or esistente.get("state") == "discarded"
            self.store.upsert_local_node(
                ip, state="candidate" if e_nuovo else None,
                ttl=prove.get("ttl"), mac=prove.get("mac"),
                hostname=prove.get("hostname"))
            nodi.append(self._record_nodo(prove, adesso))
            presenze.append({
                "ip": ip,
                "mac": prove.get("mac"),
                "hostname": prove.get("hostname"),
                "seen_at": adesso,
                "subnet": cidr,
            })
            if e_nuovo:
                nuovi.append(ip)
        return {"nodes": nodi, "presence": presenze, "new": nuovi}

    def _record_nodo(self, prove: dict, adesso: str) -> dict:
        """Il nodo come lo vede la ricognizione: presente, e nient'altro.

        Non passa da `node_record` dello scanner, e la ragione e' che quel record
        dichiara anche cio' che la ricognizione NON ha guardato -- porte esaminate,
        punto di attacco fisico, MAC riferito da un apparato in SNMP. Dichiarare qui
        quei campi vorrebbe dire affermare di aver fatto un lavoro che non e' stato
        fatto: l'arricchimento resta del ciclo ordinario.
        """
        mac = prove.get("mac")
        costruttore = prove.get("mac_vendor")
        if mac and not costruttore:
            costruttore = mac_costruttori.costruttore(mac)
        record = {
            "ip": prove["ip"],
            "reachable": True,
            "seen_at": adesso,
            "ports_examined": False,
        }
        for chiave, valore in (("mac", mac), ("mac_vendor", costruttore),
                               ("hostname", prove.get("hostname")),
                               ("ttl", prove.get("ttl")),
                               ("latency_ms", prove.get("latency_ms"))):
            if valore is not None:
                record[chiave] = valore
        if mac:
            # `arp` significa OSSERVATO dalla sonda: la ricognizione usa `-PR`, quindi
            # dove il MAC c'e' e' perche' e' arrivata una risposta ARP.
            record["mac_source"] = "arp"
        return record

    # -- coda prioritaria ----------------------------------------------------
    def segna_priorita(self, indirizzi: list) -> list:
        """Mette questi indirizzi in testa alla coda dell'esame delle porte.

        Restituisce la coda risultante. I piu' recenti stanno davanti: su una rete
        senza fili l'apparato appena comparso e' quello che si rischia di perdere.
        """
        coda = [ip for ip in (self.store.get_json(CHIAVE_PRIORITA, []) or [])
                if isinstance(ip, str)]
        for ip in indirizzi:
            if ip in coda:
                coda.remove(ip)
        coda = list(indirizzi) + coda
        coda = coda[:MAX_PRIORITA]
        self.store.set_json(CHIAVE_PRIORITA, coda)
        return coda

    def _pota_priorita(self) -> None:
        """Toglie dalla coda chi non attende piu' l'esame delle porte.

        Un indirizzo esce quando le sue porte sono state esaminate, quando il nodo e'
        stato conferito, o quando non esiste piu' nell'archivio locale.
        """
        coda = self.priorita()
        if not coda:
            return
        restano = []
        for ip in coda:
            nodo = self.store.local_node(ip)
            if nodo is None:
                continue
            if nodo.get("conferred_at"):
                continue
            fasi = set((nodo.get("stages_done") or "").split(",")) - {""}
            if "ports" in fasi:
                continue
            restano.append(ip)
        if len(restano) != len(coda):
            self.store.set_json(CHIAVE_PRIORITA, restano)

    def priorita(self) -> list:
        return [ip for ip in (self.store.get_json(CHIAVE_PRIORITA, []) or [])
                if isinstance(ip, str)]

    def dimentica_priorita(self, indirizzi) -> None:
        """Toglie dalla coda prioritaria cio' che e' stato esaminato."""
        da_togliere = set(indirizzi or ())
        if not da_togliere:
            return
        coda = [ip for ip in self.priorita() if ip not in da_togliere]
        self.store.set_json(CHIAVE_PRIORITA, coda)

    def stato(self) -> dict:
        """Esito dell'ultima passata, per la pagina di stato della sonda."""
        esito = dict(self.store.get_json(CHIAVE_STATO, {}) or {})
        esito["subnets_wifi"] = self.reti()
        esito["interval_sec"] = self.intervallo()
        esito["priority_queue"] = len(self.priorita())
        return esito
