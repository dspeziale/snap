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


# --------------------------------------------------------------------------- #
# La configurazione del sensore del traffico
# --------------------------------------------------------------------------- #
# Il sensore e' SPENTO finche' qualcuno non lo accende, e la scelta vive
# nell'archivio della sonda come tutte le altre scelte locali.
CHIAVE_TRAFFICO_ATTIVO = "traffico_attivo"
CHIAVE_TRAFFICO_INTERFACCIA = "traffico_interfaccia"
CHIAVE_TRAFFICO_FILTRO = "traffico_filtro"
CHIAVE_TRAFFICO_ERRORE = "traffico_ultimo_errore"

# L'ISTANTE dell'ultimo giro in cui la cattura risultava viva. Attraversa i due
# processi passando dall'archivio: il processo dell'interfaccia non ha nessun
# oggetto Cattura da interrogare, perche' la cattura vive in quello dell'agente.
# Un istante e non un interruttore: un processo che muore non fa in tempo a
# scrivere "sono morto", mentre un istante fermo da un minuto lo dice da solo.
CHIAVE_TRAFFICO_VIVA_AT = "traffico_viva_at"
# I CONTATORI della cattura: quanti pacchetti ha letto, quanti ne ha scartati, su che
# cosa e da quando. Sono stato del processo che cattura, e attraversano i processi
# nello stesso modo dell'istante qui sopra -- passando dall'archivio. Gli SCARTATI in
# particolare non si ricavano da nessun'altra parte: sono quelli che l'anello ha perso
# perche' nessuno li ha ritirati in tempo, cioe' il segnale che la sonda non tiene il
# passo del traffico.
CHIAVE_TRAFFICO_CONTATORI = "traffico_contatori"

# Oltre questo numero di indirizzi diversi, una scheda di rete non e' di una macchina:
# e' di un ROUTER, e il MAC che si vede nei suoi pacchetti e' il suo, non quello di
# chi li ha generati. Le coppie che passano di li' non si associano.
#
# La soglia si calibra da sola sul segmento e non richiede di conoscere maschere,
# gateway o topologia -- che la sonda spesso non conosce. Otto e' largo per una
# postazione (che ne ha uno, al massimo due con un indirizzo secondario) e stretto per
# un router (che ne serve decine).
INDIRIZZI_OLTRE_I_QUALI_E_UN_ROUTER = 8

# Quante volte una coppia deve essersi vista per valere. Un pacchetto solo puo' essere
# un residuo o una lettura storta.
COPPIE_MINIME = 2
# Oltre questo, l'ultimo istante firmato non vale piu' come "sta ascoltando":
# e' quattro giri del ciclo, quindi non basta un giro lungo a far sembrare
# ferma una cattura che sta lavorando.
TRAFFICO_VIVA_SCADENZA_SEC = 60

# La cattura vive nel processo dell'agente di raccolta, non in quello
# dell'interfaccia: e' li' che gira il motore IDS che ne legge il riassunto. Questo
# riferimento lo tiene il modulo perche' il sensore possa raggiungerlo senza che il
# motore debba saperne niente.
_CATTURA = {"presa": None}


def imposta_cattura(presa) -> None:
    _CATTURA["presa"] = presa


def _cattura_in_corso():
    return _CATTURA.get("presa")


def contatori_cattura(store) -> dict:
    """I contatori pubblicati dall'agente. Vuoti se non ne ha ancora pubblicati.

    Si torna un dizionario e non None: chi lo usa lo interroga per chiave, e un
    dizionario vuoto risponde "non lo so" a tutte senza far sollevare niente -- che
    e' esattamente cio' che serve a un modello.
    """
    import json

    grezzo = (store.get_setting(CHIAVE_TRAFFICO_CONTATORI, "") or "").strip()
    if not grezzo:
        return {}
    try:
        voci = json.loads(grezzo)
    except (TypeError, ValueError):
        return {}
    return voci if isinstance(voci, dict) else {}


def cattura_in_ascolto(store) -> bool:
    """Vero se la cattura sta ascoltando ADESSO, chiunque lo chieda.

    Non si guarda l'oggetto `Cattura` in memoria: vive nel processo dell'agente, e
    chi fa questa domanda e' quasi sempre il processo dell'interfaccia, che non ce
    l'ha. Guardarlo li' faceva dichiarare "la cattura non e' partita" su una pagina
    che nel frattempo mostrava i pacchetti appena arrivati.

    Si guarda invece l'istante che l'agente firma a ogni giro finche' la cattura e'
    viva: se e' recente, sta ascoltando.
    """
    from datetime import datetime, timezone

    firmato = (store.get_setting(CHIAVE_TRAFFICO_VIVA_AT, "") or "").strip()
    if not firmato:
        return False
    try:
        quando = datetime.strptime(firmato, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return False
    return (datetime.now(timezone.utc) - quando).total_seconds() <= TRAFFICO_VIVA_SCADENZA_SEC


def _reti_dichiarate(archivio) -> list:
    """Le reti del perimetro, per distinguere "dentro" da "fuori".

    Si leggono dalla configurazione che il server ha consegnato: e' la stessa
    dichiarazione su cui lavora la scansione, e usare due idee diverse di "la nostra
    rete" nello stesso prodotto sarebbe un modo sicuro di litigare con se stessi.
    """
    import ipaddress

    reti = []
    for voce in (archivio.get_json("scan_subnets", []) or []):
        cidr = voce.get("cidr") if isinstance(voce, dict) else voce
        try:
            reti.append(ipaddress.ip_network(str(cidr), strict=False))
        except ValueError:
            continue
    return reti


def _dentro_al_perimetro(indirizzo: str, reti: list) -> bool:
    import ipaddress

    try:
        valore = ipaddress.ip_address(indirizzo)
    except ValueError:
        return True  # non si sa: non si segnala
    if valore.is_private and not reti:
        # Senza perimetro dichiarato, "privato" e' la migliore approssimazione di
        # "dentro": meglio tacere che segnalare il backup notturno.
        return True
    return any(valore in rete for rete in reti)


# --------------------------------------------------------------------------- #
# Le soglie del sensore del traffico
# --------------------------------------------------------------------------- #
# Ogni numero qui sotto e' una scelta, non un valore "giusto": sono la linea fra
# un'osservazione e un allarme, e si spostano quando una rete vera dice che sono
# sbagliate. Stanno insieme perche' si leggano insieme.

# Quanti annunci ARP non richiesti, per lo stesso indirizzo e nella stessa finestra,
# smettono di sembrare un riavvio.
ARP_GRATUITI_RAFFICA = 12

# A quanti nomi DIVERSI deve rispondere una macchina perche' non stia semplicemente
# annunciando i propri servizi. Una stampante o un televisore rispondono per se'
# stessi -- due, tre nomi; Responder risponde a tutto.
NOMI_RISPOSTI_SOSPETTI = 8

# Quanti host distinti in una finestra fanno una scansione. Un client normale parla
# con il proprio server, il gateway e poco altro.
SCANSIONE_HOST = 15
SCANSIONE_PORTE = 25

# Quanti sottodomini diversi sotto una stessa zona prima di sospettare un tunnel.
# I servizi cloud ne usano parecchi (telemetria, CDN): la soglia e' alta apposta.
SOTTODOMINI_SOSPETTI = 60


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
    # --- dal filo (sensore `traffico`) ------------------------------------ #
    # Queste nove non guardano un archivio: guardano i pacchetti mentre passano. E'
    # l'unico posto dove si vedono gli attacchi che non lasciano traccia su nessun
    # host -- avvelenare una cache ARP non apre porte e non crea utenze.
    "ARP-AVVELENAMENTO": {
        "nome": "Un indirizzo rivendicato da due schede",
        "gravita": "critica",
        "tecnica": "T1557.002",
        "perche": "Due schede di rete diverse dichiarano lo stesso indirizzo IP nello"
                  " stesso momento. E' la forma che ha un attacco in mezzo alla"
                  " comunicazione: da quel momento il traffico destinato a uno passa"
                  " dall'altro. Puo' anche essere un indirizzo duplicato per errore,"
                  " ma le due cose si distinguono guardando CHI sono le due schede.",
    },
    "ARP-RAFFICA": {
        "nome": "Raffica di annunci ARP",
        "gravita": "alta",
        "tecnica": "T1557.002",
        "perche": "Un annuncio ARP che nessuno ha chiesto e' normale dopo un riavvio."
                  " Una raffica no: una cache avvelenata va tenuta avvelenata, e per"
                  " tenerla cosi' bisogna ripetere l'annuncio di continuo.",
    },
    "DHCP-ABUSIVO": {
        "nome": "Un server DHCP che non dovrebbe esserci",
        "gravita": "critica",
        "tecnica": "T1557",
        "perche": "Una scheda risponde alle richieste DHCP e non e' quella che lo"
                  " faceva prima. Chi assegna gli indirizzi assegna anche il gateway e"
                  " il DNS: e' il modo piu' pulito per mettersi in mezzo a tutto il"
                  " traffico di una rete senza toccare un solo host.",
    },
    "NOME-AVVELENATO": {
        "nome": "Qualcuno risponde a nomi che non sono suoi",
        "gravita": "alta",
        "tecnica": "T1557.001",
        "perche": "Una macchina risponde a molte query LLMNR/NBNS per nomi diversi."
                  " Windows chiede in broadcast il nome che non sa risolvere, e chi"
                  " risponde a tutto raccoglie le credenziali di chi ci casca: e'"
                  " esattamente quello che fa Responder.",
    },
    "MAC-NUOVO-SUL-FILO": {
        "nome": "Una scheda di rete mai vista sul segmento",
        "gravita": "media",
        "tecnica": "T1200",
        "perche": "Un apparato che parla sul filo e che non si era mai visto. Conta"
                  " piu' di un host nuovo trovato scansionando, perche' si vede anche"
                  " se non risponde a niente: una macchina che ascolta e non risponde"
                  " e' invisibile a una scansione, non a chi guarda il traffico.",
    },
    "SCANSIONE-INTERNA": {
        "nome": "Qualcuno sta scansionando dall'interno",
        "gravita": "alta",
        "tecnica": "T1046",
        "perche": "Un indirizzo apre connessioni verso molti host o molte porte in"
                  " pochi minuti. E' la prima cosa che fa chi e' entrato e deve"
                  " capire dove si trova. La sonda stessa e' esclusa: scansiona per"
                  " mestiere.",
    },
    "BEACONING": {
        "nome": "Qualcuno chiama casa a orologeria",
        "gravita": "alta",
        "tecnica": "T1071",
        "perche": "Contatti verso la stessa destinazione a intervalli quasi fissi."
                  " Una persona che naviga non e' regolare; un programma che aspetta"
                  " ordini si'. Non si legge un byte del contenuto: si misura il"
                  " RITMO, che il cifrato non nasconde.",
    },
    "DNS-ANOMALO": {
        "nome": "Nomi che sembrano trasportare dati",
        "gravita": "alta",
        "tecnica": "T1071.004",
        "perche": "Etichette lunghissime o casuali, o centinaia di sottodomini diversi"
                  " sotto una stessa zona. Il DNS esce quasi sempre anche dove non"
                  " esce nient'altro, ed e' per questo che ci si fanno passare i dati"
                  " e i canali di comando.",
    },
    "HTTP-IN-CHIARO": {
        "nome": "Traffico HTTP non cifrato",
        "gravita": "bassa",
        "tecnica": "T1040",
        "perche": "Una richiesta HTTP in chiaro su una rete dove tutto il resto e'"
                  " cifrato. Chiunque sia sul percorso legge tutto, credenziali"
                  " comprese, e non lascia traccia sull'host.",
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
    """Quello che passa sul filo, letto dalle sole intestazioni e dai nomi in chiaro.

    SPENTO FINCHE' NON LO SI ACCENDE, e non per prudenza formale: la cattura vede il
    traffico di chi lavora su quella rete. Si accende da *Configurazione*, dichiarando
    su quale interfaccia, e la pagina dice che cosa legge e che cosa non legge mai.

    CHE COSA VEDE SENZA UNA PORTA MIRROR
    Su uno switch, alla sonda arriva il traffico diretto a lei piu' tutto il
    BROADCAST. Sembra poco ed e' invece dove vivono gli attacchi di segmento: ARP,
    DHCP, LLMNR/NBNS. Misurato su una rete vera, venti secondi bastano a vedere le
    schede di rete di tutto il segmento -- comprese quelle che a una scansione non
    rispondono.

    CHE COSA SERVE UNA PORTA MIRROR PER VEDERE
    Le conversazioni fra altri: scansioni interne, beaconing, nomi richiesti da altri.
    La pagina dei sensori dichiara quale dei due casi si sta osservando, perche' le
    regole che non possono scattare non devono sembrare regole che non hanno trovato
    niente.

    CHE COSA NON VEDE MAI
    Il contenuto. Si catturano poche centinaia di byte per pacchetto e si estraggono
    intestazioni e nomi (`traffico.py`): il payload non entra in memoria.
    """

    codice = "traffico"
    nome = "Osservazione del traffico"
    descrizione = ("Intestazioni dei pacchetti e nomi dichiarati in chiaro (DNS, SNI,"
                   " Host HTTP). Riconosce avvelenamento ARP, DHCP abusivo,"
                   " avvelenamento dei nomi, scansioni interne, beaconing e tunnel"
                   " DNS, e associa indirizzo IP e scheda di rete. Non legge il"
                   " contenuto.")

    def disponibile(self, archivio) -> tuple:
        from . import cattura as modulo_cattura

        if archivio.get_setting(CHIAVE_TRAFFICO_ATTIVO, "0") != "1":
            return False, ("spento: si accende da Configurazione, scegliendo"
                           " l'interfaccia da ascoltare")
        assenza = modulo_cattura.motivo_assenza()
        if assenza:
            return False, assenza
        # NON si guarda l'oggetto della cattura: vive nel processo dell'AGENTE, e
        # questa domanda la fa quasi sempre la pagina IDS, che gira in quello
        # dell'INTERFACCIA. Cercarlo li' faceva dichiarare "cattura non avviata" su
        # una pagina che mostrava le rilevazioni appena prodotte da quella cattura.
        if not cattura_in_ascolto(archivio):
            motivo = archivio.get_setting(CHIAVE_TRAFFICO_ERRORE, "")
            return False, (motivo or "cattura non avviata")
        stato = contatori_cattura(archivio)
        return True, ("in ascolto su %s: %s pacchetti letti"
                      % (str(stato.get("interfaccia") or "?")[-24:],
                         stato.get("pacchetti", "?")))

    def osserva(self, archivio, adesso: datetime) -> list:
        presa = _cattura_in_corso()
        if presa is None:
            return []
        osservatorio = getattr(presa, "osservatorio", None)
        if osservatorio is None:
            return []
        finestra = osservatorio.riassunto()
        if not finestra.get("pacchetti"):
            return []

        rilevazioni = []
        rilevazioni.extend(self._arp(archivio, finestra, adesso))
        rilevazioni.extend(self._dhcp(archivio, finestra, adesso))
        rilevazioni.extend(self._nomi_risposti(finestra))
        rilevazioni.extend(self._schede_nuove(archivio, finestra, adesso))
        rilevazioni.extend(self._scansioni(finestra))
        rilevazioni.extend(self._beaconing(archivio, finestra))
        rilevazioni.extend(self._dns(finestra))
        rilevazioni.extend(self._http(finestra))
        # L'associazione indirizzo/scheda legge l'ARCHIVIO e non la finestra in
        # memoria: le coppie vanno confrontate con quelle di prima, e la finestra
        # dura quanto un giro.
        rilevazioni.extend(self._ip_e_schede(archivio, adesso))
        return rilevazioni

    # -- indirizzo e scheda di rete ----------------------------------------- #
    def _ip_e_schede(self, archivio, adesso: datetime) -> list:
        """Associa indirizzo IP e scheda di rete leggendo i pacchetti conservati.

        Il MAC di un pacchetto e' quello del passo precedente, non della macchina che
        l'ha generato: se il traffico ha attraversato un router, quel MAC e' del
        ROUTER. Associare alla cieca attribuirebbe la sua scheda a mezza internet e
        farebbe scattare "una scheda su molti indirizzi" su di lui a ogni giro -- un
        allarme quotidiano su un fatto normale, cioe' il modo piu' rapido di far
        ignorare un IDS.

        Un router si riconosce proprio da li': e' la scheda che compare con molti
        indirizzi diversi. Le coppie che passano da quelle schede non si associano.
        """
        coppie = archivio.traffico_coppie_ip_mac(minimo=COPPIE_MINIME)
        if not coppie:
            return []

        # Quante schede per indirizzo e quanti indirizzi per scheda: servono
        # entrambi, e si contano una volta sola.
        indirizzi_per_scheda = {}
        for voce in coppie:
            indirizzi_per_scheda.setdefault(voce["mac"], set()).add(voce["ip"])
        schede_di_transito = {mac for mac, ips in indirizzi_per_scheda.items()
                              if len(ips) > INDIRIZZI_OLTRE_I_QUALI_E_UN_ROUTER}

        rilevazioni = []
        for voce in coppie:
            ip, mac = voce["ip"], voce["mac"]
            if mac in schede_di_transito:
                # Traffico instradato: la scheda e' del router. Non si associa, e non
                # si segnala -- e' il funzionamento normale di una rete.
                continue

            # La memoria e' la STESSA del sensore dell'inventario (`mac_di_ip`): le
            # due sorgenti devono concordare, altrimenti un cambio di scheda
            # verrebbe segnalato due volte o, peggio, ciascuna sorgente crederebbe
            # normale cio' che l'altra ha visto cambiare.
            cambiato = archivio.ids_confronta("mac_di_ip", ip, mac, adesso)
            if cambiato and cambiato["maturo"]:
                rilevazioni.append(Rilevazione(
                    "ARP-MAC-CAMBIATO", self.codice, ip,
                    "%s risponde con una scheda di rete diversa" % ip,
                    "visto nel traffico: prima %s, adesso %s (noto dal %s)"
                    % (cambiato["prima"], mac, cambiato["visto_da"]),
                    {"ip": ip, "mac_prima": cambiato["prima"], "mac_adesso": mac,
                     "fonte": "traffico"}))
                continue

            # IL GUADAGNO VERO: un nodo che non aveva scheda ora ce l'ha. Un MAC da'
            # il costruttore, e su un apparato muto e' spesso l'unico indizio sul
            # tipo. Non si sovrascrive mai un MAC gia' noto -- quello viene da ARP
            # durante una scansione, che e' una prova diretta.
            if archivio.nodo_senza_mac(ip):
                archivio.assegna_mac_osservato(ip, mac)
        return rilevazioni

    # -- le regole ---------------------------------------------------------- #
    def _arp(self, archivio, finestra, adesso) -> list:
        trovate = []
        for indirizzo, schede in (finestra.get("arp_per_ip") or {}).items():
            trovate.append(Rilevazione(
                "ARP-AVVELENAMENTO", self.codice, indirizzo,
                "%s rivendicato da %d schede diverse" % (indirizzo, len(schede)),
                "schede: %s" % ", ".join(schede[:6]),
                {"ip": indirizzo, "mac": schede[:8]}))
        for indirizzo, quanti in (finestra.get("arp_gratuiti") or {}).items():
            if quanti >= ARP_GRATUITI_RAFFICA:
                trovate.append(Rilevazione(
                    "ARP-RAFFICA", self.codice, indirizzo,
                    "%d annunci ARP non richiesti per %s" % (quanti, indirizzo),
                    "in una sola finestra di osservazione",
                    {"ip": indirizzo, "quanti": quanti}))
        return trovate

    def _dhcp(self, archivio, finestra, adesso) -> list:
        """Un server DHCP nuovo. Il primo che si vede NON e' una rilevazione: e'
        quello vero, e diventa la linea di base."""
        trovate = []
        for scheda, quanti in (finestra.get("dhcp_server") or {}).items():
            memoria = archivio.ids_confronta("dhcp_server", scheda, "1", adesso)
            if memoria and memoria["nuovo"] and archivio.ids_memoria_matura()["matura"]:
                trovate.append(Rilevazione(
                    "DHCP-ABUSIVO", self.codice, scheda,
                    "la scheda %s risponde alle richieste DHCP" % scheda,
                    "%d risposte osservate; non lo faceva prima" % quanti,
                    {"mac": scheda, "risposte": quanti}))
        return trovate

    def _nomi_risposti(self, finestra) -> list:
        trovate = []
        for scheda, nomi in (finestra.get("risposte_nomi") or {}).items():
            if len(nomi) >= NOMI_RISPOSTI_SOSPETTI:
                trovate.append(Rilevazione(
                    "NOME-AVVELENATO", self.codice, scheda,
                    "%s risponde per %d nomi diversi" % (scheda, len(nomi)),
                    "fra cui: %s" % ", ".join(nomi[:5]),
                    {"mac": scheda, "nomi": nomi[:20]}))
        return trovate

    def _schede_nuove(self, archivio, finestra, adesso) -> list:
        """Una scheda mai vista. Vale la regola del primo giro: finche' la memoria
        e' giovane si impara e non si giudica."""
        if not archivio.ids_memoria_matura()["matura"]:
            return []
        trovate = []
        for scheda, (_primo, _ultimo, quanti, indirizzi) in (
                finestra.get("mac") or {}).items():
            memoria = archivio.ids_confronta("mac_sul_filo", scheda, "1", adesso)
            if memoria and memoria["nuovo"]:
                trovate.append(Rilevazione(
                    "MAC-NUOVO-SUL-FILO", self.codice, scheda,
                    "scheda di rete mai vista sul segmento: %s" % scheda,
                    "%d pacchetti%s" % (quanti, (", indirizzi %s"
                                                 % ", ".join(indirizzi[:3]))
                                        if indirizzi else ""),
                    {"mac": scheda, "ip": indirizzi[:8]}))
        return trovate

    def _scansioni(self, finestra) -> list:
        trovate = []
        porte = finestra.get("scansione_porte") or {}
        for sorgente, host in (finestra.get("scansione_host") or {}).items():
            quante_porte = porte.get(sorgente, 0)
            if host >= SCANSIONE_HOST or quante_porte >= SCANSIONE_PORTE:
                trovate.append(Rilevazione(
                    "SCANSIONE-INTERNA", self.codice, sorgente,
                    "%s ha contattato %d host su %d porte" % (sorgente, host,
                                                              quante_porte),
                    "in una sola finestra di osservazione",
                    {"ip": sorgente, "host": host, "porte": quante_porte}))
        return trovate

    def _beaconing(self, archivio, finestra) -> list:
        """Un ritmo regolare verso FUORI.

        La condizione "fuori dal perimetro dichiarato" non e' un dettaglio: dentro la
        rete tutto e' regolare -- il monitoraggio, i backup, la sonda stessa -- e
        senza quel filtro questa regola segnalerebbe l'infrastruttura del cliente.
        """
        from .traffico import ritmo

        dentro = _reti_dichiarate(archivio)
        trovate = []
        for chiave, istanti in (finestra.get("flussi") or {}).items():
            sorgente, destinazione, porta = chiave
            if _dentro_al_perimetro(destinazione, dentro):
                continue
            misura = ritmo(istanti)
            if not misura.get("regolare"):
                continue
            trovate.append(Rilevazione(
                "BEACONING", self.codice, "%s->%s:%s" % (sorgente, destinazione, porta),
                "%s contatta %s:%s ogni %.0f secondi"
                % (sorgente, destinazione, porta, misura["intervallo_sec"]),
                "%d contatti, scarto %.0f%%: un ritmo da programma, non da persona"
                % (misura["contatti"], misura["scarto_relativo"] * 100),
                {"sorgente": sorgente, "destinazione": destinazione,
                 "porta": porta, **misura}))
        return trovate

    def _dns(self, finestra) -> list:
        from .traffico import nome_anomalo

        trovate = []
        for nome, quante in (finestra.get("nomi") or {}).items():
            giudizio = nome_anomalo(nome)
            if giudizio["anomalo"]:
                trovate.append(Rilevazione(
                    "DNS-ANOMALO", self.codice, nome[:120],
                    "nome insolito richiesto %d volte: %s" % (quante, nome[:80]),
                    "%s (%d caratteri, entropia %.1f)"
                    % (giudizio["motivo"], giudizio["lunghezza"],
                       giudizio["entropia"]),
                    {"nome": nome[:200], **giudizio}))
        for zona, quanti in (finestra.get("sottodomini") or {}).items():
            if quanti >= SOTTODOMINI_SOSPETTI:
                trovate.append(Rilevazione(
                    "DNS-ANOMALO", self.codice, zona,
                    "%d sottodomini diversi sotto %s" % (quanti, zona),
                    "in una sola finestra: e' la forma di un tunnel DNS",
                    {"zona": zona, "sottodomini": quanti}))
        return trovate

    def _http(self, finestra) -> list:
        trovate = []
        for sorgente, nomi in (finestra.get("http_in_chiaro") or {}).items():
            trovate.append(Rilevazione(
                "HTTP-IN-CHIARO", self.codice, sorgente,
                "%s usa HTTP non cifrato verso %d siti" % (sorgente, len(nomi)),
                "fra cui: %s" % ", ".join(nomi[:5]),
                {"ip": sorgente, "siti": nomi[:16]}))
        return trovate


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
