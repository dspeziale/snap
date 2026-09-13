# -----------------------------------------------------------------
# ids.py — motore di rilevazione delle intrusioni sulla sonda
# Autore: Daniele Speziale
# Data creazione: 2026-09-13
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap probe - Riconoscere che qualcosa e' cambiato in un modo che riguarda la sicurezza.

CHE COS'E', E CHE COSA NON E'
-----------------------------
E' un motore su OSSERVAZIONE: confronta cio' che la sonda e gli agenti vedono adesso
con cio' che era normale prima, e applica un catalogo di regole dichiarate.

NON ispeziona il traffico: non vede i pacchetti, quindi non riconosce un exploit nel
payload, un canale di comando cifrato o un'esfiltrazione. Il limite e' scritto in ogni
pagina che mostra rilevazioni, perche' un prodotto che lasciasse credere il contrario
darebbe una sicurezza che non ha.

L'architettura pero' non lo esclude: i sensori sono innestabili (vedi `SENSORI`), e
aggiungere un sensore di traffico significa scrivere una classe -- non rifare questo
motore.

LA LINEA DI BASE
----------------
Una rilevazione non e' un fatto assoluto ("la porta 3389 e' aperta") ma un
cambiamento rispetto a cio' che si era visto ("la 3389 e' aperta DOVE NON C'ERA").
Senza un prima, la prima passata segnalerebbe l'intera rete come sospetta.

Da qui la regola che governa tutto il modulo: **finche' la memoria di un soggetto e'
piu' giovane di `MATURITA_ORE`, il cambiamento si registra ma non si allarma.** Non si
puo' dire "e' cambiato" di qualcosa che si e' visto una volta sola.

PERCHE' GIRA QUI E NON SUL SERVER
----------------------------------
La sonda e' l'unica a contatto con la rete sorvegliata; il server non la raggiunge
nemmeno. Rilevare sul server vorrebbe dire rilevare in ritardo, su dati gia'
conferiti, e con la cadenza del conferimento invece che quella dell'osservazione.

remarks: Autore: Daniele Speziale - Data: 2026-09-13
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

UTC_FORMAT = "%Y-%m-%d %H:%M:%S"

# Quanto deve essere vecchia la memoria di un soggetto perche' un suo cambiamento
# valga come rilevazione. Dodici ore coprono un ciclo di lavoro: una macchina accesa
# solo di giorno viene vista almeno una volta prima di essere giudicata.
MATURITA_ORE = 12

# Ogni quanto gira il motore. Piu' fitto non serve: le osservazioni arrivano dalle
# passate di scansione, che hanno cadenze loro.
CADENZA_SEC = 300

# Porte con cui si prende il controllo di una macchina. Non e' un elenco di porte
# "pericolose": e' l'elenco di cio' che non dovrebbe comparire dove non c'era.
PORTE_AMMINISTRAZIONE = {22, 23, 3389, 5900, 5901, 5985, 5986, 623}

# Fascia oraria in cui la comparsa di un apparato mai visto vale come rilevazione.
# E' una convenzione d'ufficio, e si cambia per tenant: un magazzino chiuso alle 18 e
# un reparto con turni notturni non hanno la stessa idea di "insolito".
NOTTE_DA, NOTTE_A = 21, 6


def _adesso() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _testo(momento: datetime) -> str:
    return momento.strftime(UTC_FORMAT)


def _istante(valore):
    try:
        return datetime.strptime(str(valore), UTC_FORMAT).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# Il catalogo delle regole
# --------------------------------------------------------------------------- #
# Ogni regola dichiara: che cosa riconosce, quanto e' grave, quale tecnica ATT&CK, e
# il PERCHE' conta. Una rilevazione senza il motivo e' un allarme che si impara a
# ignorare, ed e' il modo in cui un IDS smette di servire senza che nessuno lo spenga.
REGOLE = {
    "ARP-MAC-CAMBIATO": {
        "nome": "Indirizzo con scheda di rete diversa",
        "gravita": "alta",
        "tecnica": "T1557",
        "perche": "Lo stesso indirizzo IP risponde con un MAC diverso da quello noto."
                  " Puo' essere una sostituzione legittima di hardware, oppure"
                  " qualcuno che si e' messo in mezzo: la differenza la fa chi conosce"
                  " la rete, ma va guardata.",
    },
    "ARP-MAC-MULTIPLO": {
        "nome": "Una scheda di rete su molti indirizzi",
        "gravita": "media",
        "tecnica": "T1557",
        "perche": "Un solo MAC che risponde per molti indirizzi e' normale su un"
                  " router; su una postazione e' un apparato che si sta proponendo"
                  " come via d'uscita per gli altri.",
    },
    "HOST-NUOVO": {
        "nome": "Dispositivo mai visto",
        "gravita": "media",
        "tecnica": "T1200",
        "perche": "Un apparato che non c'era in una rete dichiarata: qualcuno lo ha"
                  " collegato. Su una rete di ospiti e' la normalita', su una rete di"
                  " server no -- per questo la gravita' segue la zona.",
    },
    "PORTA-AMMINISTRAZIONE": {
        "nome": "Amministrazione comparsa",
        "gravita": "alta",
        "tecnica": "T1021",
        "perche": "SSH, RDP, VNC o WinRM rispondono dove prima non rispondevano. E'"
                  " il modo in cui si prende il controllo di una macchina, e la"
                  " comparsa e' piu' significativa della presenza.",
    },
    "PORTA-INSOLITA": {
        "nome": "Porta alta comparsa",
        "gravita": "media",
        "tecnica": "T1571",
        "perche": "Una porta alta non standard su un nodo che era stabile da"
                  " settimane. Molti canali di comando usano porte scelte a caso.",
    },
    "SERVIZIO-SPARITO": {
        "nome": "Servizio scomparso",
        "gravita": "media",
        "tecnica": "T1489",
        "perche": "Un servizio che rispondeva da settimane ha smesso. Puo' essere una"
                  " manutenzione -- o qualcuno che lo ha fermato.",
    },
    "SMB1-RIACCESO": {
        "nome": "SMB 1.0 tornato attivo",
        "gravita": "alta",
        "tecnica": "T1210",
        "perche": "Un nodo torna ad accettare il dialetto ritirato da Microsoft. Se"
                  " era stato disattivato, qualcuno lo ha riacceso.",
    },
    "WIFI-NOTTURNO": {
        "nome": "Apparato senza fili in orario di chiusura",
        "gravita": "media",
        "tecnica": "T1200",
        "perche": "Un apparato mai visto compare sulla rete senza fili quando"
                  " l'ufficio e' chiuso. Da solo non prova nulla; insieme all'orario,"
                  " merita una domanda.",
    },
    "ACCESSI-FALLITI": {
        "nome": "Tentativi di accesso falliti",
        "gravita": "alta",
        "tecnica": "T1110",
        "perche": "Tentativi ripetuti e falliti su una macchina: e' la forma piu'"
                  " comune di attacco, e la piu' facile da vedere -- se qualcuno"
                  " guarda.",
    },
    "UTENTE-NUOVO": {
        "nome": "Utenza nuova o promossa",
        "gravita": "alta",
        "tecnica": "T1136",
        "perche": "Un'utenza creata, o aggiunta agli amministratori. E' il modo in cui"
                  " un accesso occasionale diventa permanente.",
    },
    "SICUREZZA-FERMA": {
        "nome": "Protezione disattivata",
        "gravita": "critica",
        "tecnica": "T1562",
        "perche": "L'antivirus o il firewall della macchina risultano fermi. Non"
                  " succede da solo, ed e' cio' che si fa prima del resto.",
    },
    "ASCOLTO-NUOVO": {
        "nome": "Processo nuovo in ascolto",
        "gravita": "alta",
        "tecnica": "T1571",
        "perche": "Un processo che prima non c'era tiene aperta una porta. Vista dalla"
                  " rete sarebbe solo una porta; vista da dentro ha un nome e un"
                  " utente.",
    },
}

GRAVITA_ORDINE = ("critica", "alta", "media", "bassa", "info")


class Rilevazione:
    """Una cosa notata, con la sua prova.

    `soggetto` e' cio' a cui si riferisce (un indirizzo, un nodo, una macchina): serve
    a non duplicare -- mille volte lo stesso fatto e' un fatto che dura, non mille
    fatti.
    """

    __slots__ = ("regola", "sensore", "soggetto", "titolo", "prova", "dati")

    def __init__(self, regola: str, sensore: str, soggetto: str, titolo: str,
                 prova: str, dati: dict = None):
        self.regola = regola
        self.sensore = sensore
        self.soggetto = str(soggetto)
        self.titolo = titolo
        self.prova = prova
        self.dati = dati or {}

    @property
    def gravita(self) -> str:
        return REGOLE.get(self.regola, {}).get("gravita", "media")

    @property
    def tecnica(self) -> str:
        return REGOLE.get(self.regola, {}).get("tecnica", "")


# --------------------------------------------------------------------------- #
# I sensori
# --------------------------------------------------------------------------- #
class Sensore:
    """Un sensore produce osservazioni; il motore non sa come le ha ottenute.

    Quattro cose: `codice`, `nome`, `disponibile()` e `osserva()`. E' il punto
    d'innesto dichiarato nel progetto: un sensore di traffico si aggiunge qui, senza
    toccare il motore ne' le regole che non lo riguardano.
    """

    codice = ""
    nome = ""
    descrizione = ""

    def disponibile(self, archivio) -> tuple:
        """`(disponibile, motivo)`. Il motivo si mostra nella pagina dei sensori: chi
        guarda deve sapere che cosa NON e' stato guardato."""
        return True, ""

    def osserva(self, archivio, adesso: datetime) -> list:
        raise NotImplementedError


class SensoreInventario(Sensore):
    """Quello che la sonda gia' raccoglie: nodi, porte, MAC, presenze, SMB.

    Non costa nulla in piu': non apre connessioni, non scansiona, non aggiunge
    carico. Legge l'archivio locale dopo che le passate lo hanno riempito.
    """

    codice = "inventario"
    nome = "Osservazione dell'inventario"
    descrizione = ("Nodi, porte, indirizzi fisici, presenze senza fili e letture SMB"
                   " gia' raccolti dalle passate di scansione. Non vede il traffico.")

    def osserva(self, archivio, adesso: datetime) -> list:
        rilevazioni = []
        nodi = archivio.ids_nodi_osservati()
        # IL PRIMO GIRO NON GIUDICA. Se la memoria complessiva e' piu' giovane di
        # MATURITA_ORE, ogni cosa risulterebbe "mai vista": si costruisce la linea di
        # base e si tace. Vale per le regole che si fondano sull'assenza di memoria
        # (host nuovo, apparato senza fili mai visto); quelle che confrontano un
        # valore con un altro hanno gia' la propria maturita' per soggetto.
        puo_dire_nuovo = archivio.ids_memoria_matura()["matura"]

        for nodo in nodi:
            ip = nodo["ip"]
            # --- la scheda di rete di un indirizzo ---------------------------
            if nodo.get("mac"):
                cambiato = archivio.ids_confronta("mac_di_ip", ip, nodo["mac"], adesso)
                if cambiato and cambiato["maturo"]:
                    rilevazioni.append(Rilevazione(
                        "ARP-MAC-CAMBIATO", self.codice, ip,
                        "%s risponde con una scheda di rete diversa" % ip,
                        "prima %s, adesso %s (noto dal %s)"
                        % (cambiato["prima"], nodo["mac"], cambiato["visto_da"]),
                        {"ip": ip, "mac_prima": cambiato["prima"],
                         "mac_adesso": nodo["mac"]}))

            # --- le porte di un nodo ----------------------------------------
            porte = sorted(int(p) for p in (nodo.get("porte") or []))
            memoria = archivio.ids_confronta(
                "porte_di_nodo", ip, ",".join(str(p) for p in porte), adesso)
            if memoria and memoria["maturo"]:
                prima = {int(p) for p in (memoria["prima"] or "").split(",") if p}
                comparse = set(porte) - prima
                sparite = prima - set(porte)
                amministrazione = comparse & PORTE_AMMINISTRAZIONE
                if amministrazione:
                    rilevazioni.append(Rilevazione(
                        "PORTA-AMMINISTRAZIONE", self.codice,
                        "%s:%s" % (ip, ",".join(str(p) for p in sorted(amministrazione))),
                        "amministrazione comparsa su %s" % ip,
                        "porte %s dove non rispondevano (noto dal %s)"
                        % (", ".join(str(p) for p in sorted(amministrazione)),
                           memoria["visto_da"]),
                        {"ip": ip, "porte": sorted(amministrazione)}))
                alte = {p for p in comparse - PORTE_AMMINISTRAZIONE if p >= 1024}
                if alte:
                    rilevazioni.append(Rilevazione(
                        "PORTA-INSOLITA", self.codice,
                        "%s:%s" % (ip, ",".join(str(p) for p in sorted(alte))),
                        "porta alta comparsa su %s" % ip,
                        "porte %s dove non rispondevano"
                        % ", ".join(str(p) for p in sorted(alte)),
                        {"ip": ip, "porte": sorted(alte)}))
                if sparite and not porte:
                    rilevazioni.append(Rilevazione(
                        "SERVIZIO-SPARITO", self.codice, ip,
                        "%s non risponde piu' su nessuna porta" % ip,
                        "rispondeva su %s" % ", ".join(str(p) for p in sorted(sparite)),
                        {"ip": ip, "porte": sorted(sparite)}))

            # --- il nodo stesso ---------------------------------------------
            memoria_nodo = archivio.ids_confronta("nodo_visto", ip, "1", adesso)
            if memoria_nodo and memoria_nodo["nuovo"] and puo_dire_nuovo:
                rilevazioni.append(Rilevazione(
                    "HOST-NUOVO", self.codice, ip,
                    "dispositivo mai visto: %s" % ip,
                    "primo avvistamento %s%s" % (
                        _testo(adesso),
                        (", %s" % nodo["hostname"]) if nodo.get("hostname") else ""),
                    {"ip": ip, "hostname": nodo.get("hostname") or "",
                     "mac": nodo.get("mac") or ""}))

            # --- il dialetto SMB --------------------------------------------
            if nodo.get("smb1") is not None:
                memoria_smb = archivio.ids_confronta(
                    "smb1_di_nodo", ip, "1" if nodo["smb1"] else "0", adesso)
                if (memoria_smb and memoria_smb["maturo"] and nodo["smb1"]
                        and memoria_smb["prima"] == "0"):
                    rilevazioni.append(Rilevazione(
                        "SMB1-RIACCESO", self.codice, ip,
                        "%s accetta di nuovo SMB 1.0" % ip,
                        "il dialetto NT LM 0.12 era assente alla lettura precedente",
                        {"ip": ip}))

        # --- una scheda di rete su molti indirizzi ---------------------------
        per_mac = {}
        for nodo in nodi:
            if nodo.get("mac"):
                per_mac.setdefault(nodo["mac"], []).append(nodo["ip"])
        for mac, indirizzi in per_mac.items():
            if len(indirizzi) >= 4:
                memoria = archivio.ids_confronta(
                    "indirizzi_di_mac", mac, str(len(indirizzi)), adesso)
                if memoria and memoria["maturo"] and int(memoria["prima"] or 0) < len(indirizzi):
                    rilevazioni.append(Rilevazione(
                        "ARP-MAC-MULTIPLO", self.codice, mac,
                        "una sola scheda risponde per %d indirizzi" % len(indirizzi),
                        "prima %s indirizzi: %s" % (
                            memoria["prima"], ", ".join(sorted(indirizzi)[:8])),
                        {"mac": mac, "indirizzi": sorted(indirizzi)[:32]}))

        # --- presenze senza fili in orario di chiusura -----------------------
        ora = adesso.hour
        if ora >= NOTTE_DA or ora < NOTTE_A:
            for apparato in archivio.ids_presenze_recenti(minuti=30):
                visto = archivio.ids_confronta(
                    "wifi_apparato", apparato["identity_key"], "1", adesso)
                if visto and visto["nuovo"] and puo_dire_nuovo:
                    rilevazioni.append(Rilevazione(
                        "WIFI-NOTTURNO", self.codice, apparato["identity_key"],
                        "apparato mai visto sulla rete senza fili, alle %02d:%02d"
                        % (adesso.hour, adesso.minute),
                        "riconosciuto da: %s%s" % (
                            apparato.get("identity_source") or "solo l'indirizzo",
                            (", %s" % apparato["ip"]) if apparato.get("ip") else ""),
                        {"identita": apparato["identity_key"],
                         "ip": apparato.get("ip") or ""}))
        return rilevazioni


class SensoreAgenti(Sensore):
    """Quello che le macchine riferiscono di se': accessi, utenze, servizi, processi.

    E' il sensore piu' informato che questo prodotto abbia: dalla rete una porta 4444
    aperta e' una porta aperta; da dentro e' un processo con un nome e un utente.
    """

    codice = "agenti"
    nome = "Agenti di macchina"
    descrizione = ("Accessi, utenze, servizi di sicurezza e processi in ascolto"
                   " riferiti dalle macchine su cui l'agente e' installato.")

    def disponibile(self, archivio) -> tuple:
        quanti = archivio.agenti_attivi()
        if not quanti:
            return False, ("nessun agente installato: le regole su accessi, utenze e"
                           " processi non possono scattare")
        return True, "%d macchine riferiscono" % quanti

    def osserva(self, archivio, adesso: datetime) -> list:
        rilevazioni = []
        for evento in archivio.agent_eventi_da_esaminare(limite=500):
            genere = evento["genere"]
            dati = {}
            try:
                dati = json.loads(evento["dati_json"] or "{}")
            except (TypeError, ValueError):
                dati = {}
            soggetto = "%s/%s" % (evento["agent_uid"], evento.get("soggetto") or genere)

            if genere == "accessi_falliti":
                quanti = int(dati.get("quanti") or 0)
                if quanti >= int(dati.get("soglia") or 5):
                    rilevazioni.append(Rilevazione(
                        "ACCESSI-FALLITI", self.codice, soggetto,
                        "%d accessi falliti su %s" % (quanti, evento["agent_uid"]),
                        evento["messaggio"], dati))
            elif genere == "utente_nuovo":
                rilevazioni.append(Rilevazione(
                    "UTENTE-NUOVO", self.codice, soggetto,
                    evento["messaggio"], json.dumps(dati, ensure_ascii=False)[:400],
                    dati))
            elif genere == "sicurezza_ferma":
                rilevazioni.append(Rilevazione(
                    "SICUREZZA-FERMA", self.codice, soggetto,
                    evento["messaggio"], json.dumps(dati, ensure_ascii=False)[:400],
                    dati))
            elif genere == "ascolto_nuovo":
                rilevazioni.append(Rilevazione(
                    "ASCOLTO-NUOVO", self.codice, soggetto,
                    evento["messaggio"],
                    "processo %s, utente %s, porta %s" % (
                        dati.get("processo", "?"), dati.get("utente", "?"),
                        dati.get("porta", "?")),
                    dati))
            archivio.agent_evento_esaminato(evento["id"], _testo(adesso))
        return rilevazioni


class SensoreTraffico(Sensore):
    """PREDISPOSTO, non attivo.

    Vedere i pacchetti richiede libpcap (Npcap su Windows), privilegi permanenti e --
    per vedere traffico non diretto alla sonda -- una porta mirror sullo switch. Sono
    tre condizioni che si concordano con chi gestisce la rete, non si danno per
    scontate installando un prodotto.

    Il posto pero' e' questo: quando quelle condizioni ci sono, si implementa
    `osserva()` e il motore comincia a usarlo senza che nient'altro cambi. Le regole
    che ne nascerebbero (ARP poisoning osservato sul filo, DNS anomalo, connessioni
    verso indirizzi noti come malevoli) si aggiungono al catalogo come le altre.
    """

    codice = "traffico"
    nome = "Osservazione del traffico"
    descrizione = ("Ispezione dei pacchetti. Richiede libpcap/Npcap, privilegi di"
                   " amministratore e una porta mirror: si abilita quando quelle"
                   " condizioni esistono.")

    def disponibile(self, archivio) -> tuple:
        return False, ("sensore predisposto e non attivo: senza cattura del traffico"
                       " questo prodotto non vede exploit nel payload, canali di"
                       " comando cifrati ne' esfiltrazioni")

    def osserva(self, archivio, adesso: datetime) -> list:
        return []


# L'ordine conta: i sensori piu' informati per ultimi, cosi' le loro rilevazioni
# arrivano dopo quelle generiche nello stesso giro.
SENSORI = [SensoreInventario(), SensoreAgenti(), SensoreTraffico()]


def sensori_dichiarati(archivio) -> list:
    """Lo stato di ogni sensore, per la pagina che li elenca."""
    elenco = []
    for sensore in SENSORI:
        disponibile, motivo = sensore.disponibile(archivio)
        elenco.append({
            "codice": sensore.codice,
            "nome": sensore.nome,
            "descrizione": sensore.descrizione,
            "disponibile": disponibile,
            "motivo": motivo,
        })
    return elenco


# --------------------------------------------------------------------------- #
# Il motore
# --------------------------------------------------------------------------- #
class MotoreIDS:
    """Osserva, confronta, applica, deduplica, accoda, aggiorna la memoria.

    Non decide nulla da solo: ogni rilevazione porta la regola che l'ha prodotta, la
    prova su cui si basa e l'istante. Chi legge deve poter dare un giudizio, non
    fidarsi.
    """

    def __init__(self, archivio, sensori=None):
        self.archivio = archivio
        self.sensori = sensori if sensori is not None else SENSORI

    def esegui(self, adesso: datetime = None) -> dict:
        adesso = adesso or _adesso()
        prodotte, per_sensore, saltati = [], {}, []

        for sensore in self.sensori:
            disponibile, motivo = sensore.disponibile(self.archivio)
            if not disponibile:
                saltati.append({"sensore": sensore.codice, "motivo": motivo})
                continue
            try:
                trovate = sensore.osserva(self.archivio, adesso) or []
            except Exception as errore:  # noqa: BLE001 - un sensore rotto non ferma gli altri
                # Un sensore che esplode non deve fermare la rilevazione: si dichiara
                # nel diario e si continua con gli altri. Tacere sarebbe peggio.
                self.archivio.log("error",
                                  "Sensore IDS %s non ha potuto osservare: %s"
                                  % (sensore.codice, errore))
                saltati.append({"sensore": sensore.codice, "motivo": str(errore)})
                continue
            per_sensore[sensore.codice] = len(trovate)
            prodotte.extend(trovate)

        nuove, aggiornate = 0, 0
        for rilevazione in prodotte:
            esito = self.archivio.ids_registra(
                regola=rilevazione.regola,
                gravita=rilevazione.gravita,
                sensore=rilevazione.sensore,
                soggetto=rilevazione.soggetto,
                titolo=rilevazione.titolo,
                prova=rilevazione.prova,
                tecnica=rilevazione.tecnica,
                dati=rilevazione.dati,
                adesso=_testo(adesso),
            )
            if esito == "nuova":
                nuove += 1
            else:
                aggiornate += 1

        if nuove:
            self.archivio.log(
                "warning",
                "IDS: %d rilevazioni nuove (%s)"
                % (nuove, ", ".join("%s=%d" % (k, v) for k, v in per_sensore.items())))

        memoria = self.archivio.ids_memoria_matura()
        return {
            "rilevazioni": len(prodotte),
            "nuove": nuove,
            "aggiornate": aggiornate,
            "per_sensore": per_sensore,
            "sensori_saltati": saltati,
            "eseguito_at": _testo(adesso),
            # Si dichiara: finche' la memoria e' giovane, le regole che si fondano
            # sull'assenza di memoria non possono scattare, e il silenzio non e' una
            # buona notizia -- e' un motore che sta ancora imparando.
            "memoria": memoria,
        }
