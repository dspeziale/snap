# -----------------------------------------------------------------
# rete_pubblica.py — di chi e' un indirizzo pubblico: nome della rete, da RDAP
# Autore: Daniele Speziale
# Data creazione: 2026-09-15
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Dall'indirizzo pubblico al nome della rete.

A CHE COSA SERVE. Un indirizzo pubblico in una tabella non dice niente:
`203.0.113.45` e' quattro numeri. Sapere che e' *Vodafone Italia* oppure *Microsoft
Azure* oppure *una rete residenziale in Vietnam* cambia la lettura di quella riga --
ed e' la differenza fra un allarme che si capisce in tre secondi e uno che richiede
una ricerca a mano su un altro sito, che nessuno fa mai.

COME. Si chiede a RDAP (RFC 7482/7483), il successore di whois: e' interrogabile in
HTTP, risponde in JSON, e `rdap.org` instrada da solo verso il registro regionale
giusto (RIPE per l'Europa, ARIN per il Nord America, e cosi' via). Nessuna chiave,
nessun contratto, nessuna dipendenza aggiunta: `urllib` e `json` stanno nella
libreria standard, come per la threat intelligence.

LA CACHE SI ALIMENTA DA SOLA, e questo e' il punto.

* Ogni volta che il prodotto INCONTRA un indirizzo pubblico -- un evento SIEM, un
  allarme, un nodo -- lo registra in coda con `osserva()`. Registrare costa una
  scrittura e non contatta nessuno: si puo' fare nel percorso di una richiesta.
* Un thread di fondo svuota la coda con calma, rispettando i limiti dei registri, e
  scrive il risultato nella tabella degli intervalli.
* Le PAGINE NON INTERROGANO MAI LA RETE. Leggono solo la cache: un indirizzo non
  ancora risolto mostra se' stesso, come prima, e si arricchisce da solo al giro
  successivo. Una pagina che aspettasse una risposta RDAP si bloccherebbe per secondi
  su una tabella di trenta righe, e in una rete senza uscita verso internet non si
  aprirebbe affatto.

SI CONSERVA L'INTERVALLO, NON L'INDIRIZZO. RDAP non risponde "questo indirizzo e' di
X": risponde "l'intervallo da A a B e' di X". Conservare l'intervallo significa che
una sola interrogazione copre tutti gli indirizzi di quella rete -- spesso migliaia --
e il secondo indirizzo della stessa rete non costa niente. E' la ragione per cui
questa cache regge il traffico di un SIEM invece di soffocarlo.

COME SI CONFRONTANO GLI INTERVALLI. Come stringhe esadecimali a lunghezza fissa (8
caratteri per IPv4, 32 per IPv6): un IPv6 e' un numero a 128 bit, che nessun intero
di PostgreSQL o SQLite contiene, mentre l'ordinamento di due esadecimali della stessa
lunghezza e' lo stesso dei numeri che rappresentano. Portabile su entrambi gli
archivi senza tipi propri di nessuno dei due.

SENZA USCITA VERSO INTERNET il servizio si spegne da solo e lo dichiara: le pagine
continuano a funzionare mostrando gli indirizzi come li mostravano prima. E' la
stessa scelta della threat intelligence -- il prodotto deve funzionare in una rete
isolata, e cio' che richiede internet e' un di piu', mai un requisito.

PRIVACY (GDPR). Si interroga un registro PUBBLICO su un indirizzo di rete, e si
conserva cio' che il registro dichiara: nome della rete, organizzazione titolare,
paese, numero di sistema autonomo. Non si manda a nessuno chi ha parlato con quel
indirizzo, ne' quando: RDAP riceve l'indirizzo e nient'altro. Gli indirizzi PRIVATI
non escono mai -- sono quelli della rete del cliente, e sono anche gli unici che
potrebbero identificare una postazione.

remarks: Autore: Daniele Speziale - Data: 2026-09-15
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import ipaddress
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import timedelta

from .db import execute, query, utc_now, utc_now_str

# --------------------------------------------------------------------------- #
# Costanti di servizio
# --------------------------------------------------------------------------- #
USER_AGENT = "snap-rete-pubblica/1.0"
HTTP_TIMEOUT = 15

# `rdap.org` e' il servizio di instradamento della IANA: reindirizza verso il
# registro regionale competente. Si segue il reindirizzamento, cosi' non serve
# tenere aggiornata qui una tabella dei blocchi assegnati a ciascun RIR.
RDAP_BASE = "https://rdap.org/ip/"

# Una risposta RDAP e' qualche kilobyte. Oltre questo c'e' un errore di indirizzo o
# una sorgente cambiata, non una rete grande.
MAX_RISPOSTA_BYTE = 512 * 1024

# Quanto vale una risposta prima di richiederla. Le assegnazioni cambiano di rado --
# si misurano in anni -- e un mese tiene la cache utile senza farla invecchiare.
GIORNI_DI_VALIDITA = 30

# Quando un indirizzo non si risolve non lo si riprova subito: un registro che
# risponde "non trovato" continuera' a rispondere cosi'. I tentativi si diradano.
ATTESE_DOPO_ERRORE_ORE = (1, 6, 24, 72)
TENTATIVI_MASSIMI = len(ATTESE_DOPO_ERRORE_ORE)

# Quanti indirizzi si risolvono per giro. I registri regionali limitano le richieste
# (RIPE: qualche decina al minuto): venti per giro, un giro ogni cinque minuti, sono
# quattro all'ora per il registro e nessun rischio di essere bloccati.
PER_GIRO = 20
TICK_SECONDI = 300
PAUSA_FRA_RICHIESTE = 1.0

_thread = None
_stop = threading.Event()


# --------------------------------------------------------------------------- #
# Che cosa e' pubblico
# --------------------------------------------------------------------------- #
def e_pubblico(indirizzo) -> bool:
    """Vero se l'indirizzo sta su internet e non nella rete del cliente.

    Si escludono, oltre ai privati: loopback, link-local, multicast, riservati e
    l'intervallo 100.64/10 degli operatori (CGNAT) -- che e' pubblico per forma ma
    interno per sostanza, e non e' registrato in RDAP a nome di nessuno.
    """
    try:
        ip = ipaddress.ip_address(str(indirizzo).strip())
    except (TypeError, ValueError):
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return False
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False
    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return True


def _esadecimale(ip) -> str:
    """L'indirizzo come esadecimale a lunghezza fissa, per confrontare intervalli."""
    larghezza = 8 if ip.version == 4 else 32
    return format(int(ip), "0%dx" % larghezza)


# --------------------------------------------------------------------------- #
# La coda che si alimenta da sola
# --------------------------------------------------------------------------- #
def osserva(indirizzo) -> bool:
    """Registra un indirizzo pubblico incontrato dal prodotto.

    Costa una scrittura e NON contatta nessuno: si puo' chiamare nel percorso di una
    richiesta o durante l'acquisizione, che e' il punto -- la cache si alimenta con
    cio' che il prodotto vede davvero, invece di aspettare che qualcuno la riempia.
    """
    if not e_pubblico(indirizzo):
        return False
    testo = str(indirizzo).strip()
    adesso = utc_now_str()
    esistente = query("SELECT ip FROM net_lookups WHERE ip = ?", (testo,), one=True)
    if esistente:
        execute("UPDATE net_lookups SET last_seen_at = ? WHERE ip = ?", (adesso, testo))
        return False
    execute(
        "INSERT INTO net_lookups (ip, first_seen_at, last_seen_at, attempts,"
        " next_try_at) VALUES (?, ?, ?, 0, ?)", (testo, adesso, adesso, adesso))
    return True


def osserva_molti(indirizzi) -> int:
    """Registra un gruppo di indirizzi; torna quanti erano nuovi."""
    nuovi = 0
    for indirizzo in set(str(i).strip() for i in indirizzi if i):
        if osserva(indirizzo):
            nuovi += 1
    return nuovi


# --------------------------------------------------------------------------- #
# La lettura: solo cache, mai rete
# --------------------------------------------------------------------------- #
def nome_rete(indirizzo) -> dict | None:
    """Che cosa si sa dell'indirizzo, dalla sola cache. None se non si sa ancora.

    Non interroga mai la rete: una pagina che aspettasse una risposta RDAP si
    bloccherebbe per secondi su una tabella di trenta righe.
    """
    if not e_pubblico(indirizzo):
        return None
    ip = ipaddress.ip_address(str(indirizzo).strip())
    chiave = _esadecimale(ip)
    riga = query(
        "SELECT cidr, name, holder, country, asn, source, fetched_at"
        " FROM net_ranges WHERE version = ? AND start_hex <= ? AND end_hex >= ?"
        # Il piu' SPECIFICO fra gli intervalli che lo contengono: un indirizzo sta
        # insieme nel blocco /12 del RIR e nella /24 assegnata a un'azienda, e il
        # nome che serve e' il secondo. Fra due intervalli che contengono lo stesso
        # indirizzo, il piu' stretto e' quello che comincia piu' tardi.
        " ORDER BY start_hex DESC, end_hex ASC LIMIT 1",
        (ip.version, chiave, chiave), one=True)
    if not riga:
        return None
    return {
        "rete": riga["cidr"],
        "nome": riga["name"],
        "titolare": riga["holder"],
        "paese": riga["country"],
        "asn": riga["asn"],
        "fonte": riga["source"],
        "aggiornato_at": riga["fetched_at"],
    }


def etichetta(indirizzo) -> str:
    """Una riga sola, per un suggerimento a comparsa.

    Vuota se non si sa: chi la usa mostra l'indirizzo e basta, come prima. Una
    etichetta inventata ("sconosciuto") occuperebbe lo spazio del suggerimento
    dicendo meno di niente.
    """
    dati = nome_rete(indirizzo)
    if not dati:
        return ""
    # IL TITOLARE PER PRIMO, e non il nome della rete. Provato sui registri veri:
    # `8.8.8.0/24` si chiama "GOGL" e appartiene a "Google LLC". Il netname e' una
    # sigla da registro, il titolare e' cio' che chi legge riconosce -- e in un
    # suggerimento conta la prima parola, perche' e' quella che si legge davvero.
    pezzi = [p for p in (dati["titolare"], dati["nome"]) if p]
    # Nome e titolare coincidono spesso: non si ripete lo stesso testo due volte.
    testo = " — ".join(dict.fromkeys(pezzi))
    coda = [p for p in (dati["rete"], dati["paese"], dati["asn"]) if p]
    if coda:
        testo = "%s (%s)" % (testo, ", ".join(coda))
    return testo


# --------------------------------------------------------------------------- #
# La risoluzione: il thread di fondo
# --------------------------------------------------------------------------- #
def _leggi_rdap(indirizzo: str) -> dict:
    richiesta = urllib.request.Request(
        RDAP_BASE + urllib.parse.quote(indirizzo),
        headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"})
    with urllib.request.urlopen(richiesta, timeout=HTTP_TIMEOUT) as risposta:
        grezzo = risposta.read(MAX_RISPOSTA_BYTE + 1)
    if len(grezzo) > MAX_RISPOSTA_BYTE:
        raise ValueError("risposta RDAP piu' grande di %d byte" % MAX_RISPOSTA_BYTE)
    return json.loads(grezzo.decode("utf-8", "replace"))


def _titolare(documento: dict) -> str:
    """Il nome dell'organizzazione, dalle schede vCard della risposta.

    RDAP porta i contatti in vCard (RFC 7095): un elenco di triplette in cui il nome
    sta sotto la voce `fn`. Si preferisce chi ha il ruolo di titolare o di
    registratore -- gli altri sono contatti tecnici e amministrativi, che spesso
    sono un fornitore e non chi usa quella rete.
    """
    migliore = ""
    for ente in documento.get("entities") or []:
        ruoli = [str(r).lower() for r in (ente.get("roles") or [])]
        nome = ""
        vcard = ente.get("vcardArray") or []
        if len(vcard) == 2 and isinstance(vcard[1], list):
            for voce in vcard[1]:
                if isinstance(voce, list) and len(voce) >= 4 and voce[0] == "fn":
                    nome = str(voce[3])
                    break
        if not nome:
            nome = str(ente.get("handle") or "")
        if not nome:
            continue
        if "registrant" in ruoli or "registrar" in ruoli:
            return nome
        if not migliore:
            migliore = nome
    return migliore


def _intervallo(documento: dict, indirizzo: str):
    """L'intervallo dichiarato dalla risposta, come coppia di indirizzi."""
    inizio = documento.get("startAddress")
    fine = documento.get("endAddress")
    if inizio and fine:
        try:
            return ipaddress.ip_address(inizio), ipaddress.ip_address(fine)
        except ValueError:
            pass
    # Senza intervallo dichiarato si conserva il SOLO indirizzo chiesto: meglio una
    # cache che copre poco di una che attribuisce a mezza internet il nome trovato
    # per un indirizzo.
    ip = ipaddress.ip_address(indirizzo)
    return ip, ip


def _cidr(inizio, fine) -> str:
    try:
        reti = list(ipaddress.summarize_address_range(inizio, fine))
    except (TypeError, ValueError):
        return ""
    return str(reti[0]) if len(reti) == 1 else "%s - %s" % (inizio, fine)


def risolvi(indirizzo: str) -> dict | None:
    """Interroga RDAP e scrive l'intervallo nella cache. None se non si e' potuto."""
    documento = _leggi_rdap(indirizzo)
    inizio, fine = _intervallo(documento, indirizzo)
    nome = str(documento.get("name") or "").strip()
    titolare = _titolare(documento)
    paese = str(documento.get("country") or "").strip()
    # Il numero di sistema autonomo non e' in tutte le risposte: dove c'e', e' il
    # dato che dice davvero di chi e' la rete in esercizio.
    asn = ""
    for voce in documento.get("cidr0_cidrs") or []:
        if isinstance(voce, dict) and voce.get("asn"):
            asn = str(voce["asn"])
            break

    adesso = utc_now_str()
    scadenza = (utc_now() + timedelta(days=GIORNI_DI_VALIDITA)).strftime(
        "%Y-%m-%d %H:%M:%S")
    chiave_inizio = _esadecimale(inizio)
    chiave_fine = _esadecimale(fine)

    esistente = query(
        "SELECT id FROM net_ranges WHERE version = ? AND start_hex = ? AND"
        " end_hex = ?", (inizio.version, chiave_inizio, chiave_fine), one=True)
    if esistente:
        execute(
            "UPDATE net_ranges SET cidr = ?, name = ?, holder = ?, country = ?,"
            " asn = ?, source = 'rdap', fetched_at = ?, expires_at = ? WHERE id = ?",
            (_cidr(inizio, fine), nome, titolare, paese, asn, adesso, scadenza,
             int(esistente["id"])))
    else:
        execute(
            "INSERT INTO net_ranges (version, start_hex, end_hex, cidr, name, holder,"
            " country, asn, source, fetched_at, expires_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'rdap', ?, ?)",
            (inizio.version, chiave_inizio, chiave_fine, _cidr(inizio, fine), nome,
             titolare, paese, asn, adesso, scadenza))

    execute("UPDATE net_lookups SET resolved_at = ?, error = NULL, next_try_at = NULL"
            " WHERE ip = ?", (adesso, indirizzo))
    return {"rete": _cidr(inizio, fine), "nome": nome, "titolare": titolare,
            "paese": paese, "asn": asn}


def _rimanda(indirizzo: str, motivo: str) -> None:
    """Segna il tentativo fallito e allontana il successivo.

    Un registro che risponde "non trovato" continuera' a rispondere cosi': riprovare
    ogni cinque minuti sarebbe traffico inutile verso un servizio pubblico gratuito,
    ed e' il modo di farsi bloccare.
    """
    riga = query("SELECT attempts FROM net_lookups WHERE ip = ?", (indirizzo,),
                 one=True)
    tentativi = int((riga or {"attempts": 0})["attempts"]) + 1
    if tentativi >= TENTATIVI_MASSIMI:
        # Si smette di riprovare, ma la riga resta: dice che ci si e' provati e
        # perche' non c'e' un nome, che e' diverso da "non ci ha mai pensato nessuno".
        execute("UPDATE net_lookups SET attempts = ?, error = ?, next_try_at = NULL"
                " WHERE ip = ?", (tentativi, motivo[:200], indirizzo))
        return
    ore = ATTESE_DOPO_ERRORE_ORE[tentativi - 1]
    prossimo = (utc_now() + timedelta(hours=ore)).strftime("%Y-%m-%d %H:%M:%S")
    execute("UPDATE net_lookups SET attempts = ?, error = ?, next_try_at = ?"
            " WHERE ip = ?", (tentativi, motivo[:200], prossimo, indirizzo))


# --------------------------------------------------------------------------- #
# Da dove la cache si alimenta
#
# NON dal percorso di scrittura degli eventi. `insert_events` fa decine di migliaia
# di inserimenti al secondo in una sola transazione: aggiungerci una lettura e una
# scrittura per riga significherebbe rallentare l'acquisizione del SIEM per riempire
# una cache di comodo. Il rapporto fra i due costi e' assurdo.
#
# Si RACCOGLIE invece a valle, una volta per giro: una query per tabella che chiede
# gli indirizzi DISTINTI visti di recente. Costa tre letture ogni cinque minuti
# invece di due scritture per evento, e trova esattamente le stesse cose -- perche'
# un indirizzo che non e' finito in nessuna tabella non compare in nessuna pagina, e
# quindi non ha nessun suggerimento da mostrare.
# --------------------------------------------------------------------------- #
# Da quanto indietro si guarda a ogni giro. Piu' della cadenza del giro, cosi' un
# riavvio o un giro saltato non lascia scoperta una finestra di tempo.
ORE_DA_RACCOGLIERE = 48

# Quanti indirizzi distinti si prendono per tabella e per giro: una guardia contro
# un'ondata (una scansione dall'esterno produce migliaia di indirizzi diversi in
# pochi minuti) che riempirebbe la coda di cose che nessuno guardera' mai.
RACCOLTA_MASSIMA = 200

SORGENTI = (
    # tabella, colonna dell'indirizzo, colonna del tempo
    ("siem_events", "src_ip", "received_at"),
    ("siem_alerts", "src_ip", "created_at"),
    ("audit_events", "source_ip", "created_at"),
)


def raccogli(ore: int = ORE_DA_RACCOGLIERE, tetto: int = RACCOLTA_MASSIMA) -> int:
    """Registra in coda gli indirizzi pubblici comparsi di recente. Torna i nuovi.

    E' il meccanismo che rende la cache automatica: nessuno deve ricordarsi di
    chiedere la risoluzione di un indirizzo, e nessun punto del codice deve
    ricordarsi di chiamare `osserva()` quando ne incontra uno.

    `ore` e `tetto` si allargano per la raccolta STRAORDINARIA (vedi
    `raccogli_tutto`): a regime servono stretti, ma su un archivio che ha gia' mesi di
    eventi la finestra di due giorni lascerebbe le righe vecchie senza nome per
    settimane.
    """
    da_quando = (utc_now() - timedelta(hours=int(ore))).strftime("%Y-%m-%d %H:%M:%S")
    nuovi = 0
    for tabella, colonna, tempo in SORGENTI:
        try:
            righe = query(
                "SELECT DISTINCT %s AS ip FROM %s WHERE %s >= ? AND %s IS NOT NULL"
                " LIMIT %d" % (colonna, tabella, tempo, colonna, int(tetto)),
                (da_quando,))
        except Exception:  # noqa: BLE001
            # Una tabella che non esiste ancora (installazione nuova, migrazione in
            # corso) non deve impedire alle altre di alimentare la cache.
            continue
        nuovi += osserva_molti(r["ip"] for r in righe)
    return nuovi


# Quanto si guarda indietro nella raccolta straordinaria: dieci anni, cioe' tutto.
# Un numero grande invece di togliere la condizione dal SQL, cosi' la query resta una
# sola e non ci sono due strade da provare.
ORE_DI_TUTTO = 24 * 365 * 10

# Quanti indirizzi distinti si accettano per tabella in una raccolta straordinaria.
# Un tetto c'e' comunque: un archivio che ne contenesse un milione non si risolve in
# nessun tempo utile, e riempire la coda di cose che nessuno guardera' mai la rende
# solo piu' lenta da smaltire.
TETTO_STRAORDINARIO = 20000


def raccogli_tutto(tetto: int = TETTO_STRAORDINARIO) -> int:
    """Guarda TUTTO l'archivio, una volta sola, e mette in coda cio' che trova.

    Si usa all'avvio su un'installazione che ha gia' storia: il servizio normale
    guarda indietro di due giorni, e su mesi di eventi impiegherebbe settimane a
    dare un nome alle righe vecchie. Dopo questa, riprende il proprio passo.
    """
    return raccogli(ore=ORE_DI_TUTTO, tetto=tetto)


def da_risolvere(limite: int = PER_GIRO) -> list:
    """Gli indirizzi in coda il cui turno e' arrivato, i piu' visti per primi."""
    adesso = utc_now_str()
    righe = query(
        "SELECT ip FROM net_lookups WHERE resolved_at IS NULL"
        " AND next_try_at IS NOT NULL AND next_try_at <= ?"
        " ORDER BY last_seen_at DESC LIMIT %d" % int(limite), (adesso,))
    return [r["ip"] for r in righe]


def giro(limite: int = PER_GIRO) -> dict:
    """Un giro di risoluzione. Non solleva: il thread non deve morire."""
    # Prima si raccoglie, poi si risolve: cosi' un indirizzo appena comparso e'
    # gia' in coda al giro in cui lo si potrebbe risolvere, invece che al successivo.
    try:
        nuovi = raccogli()
    except Exception:  # noqa: BLE001 - la raccolta non deve impedire la risoluzione
        nuovi = 0

    risolti, falliti = 0, 0
    for indirizzo in da_risolvere(limite):
        if _stop.is_set():
            break
        try:
            risolvi(indirizzo)
            risolti += 1
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError,
                json.JSONDecodeError, OSError) as errore:
            _rimanda(indirizzo, str(errore))
            falliti += 1
        # Una pausa fra le richieste: i registri regionali limitano il ritmo, e
        # superarlo fa bloccare l'indirizzo del server, non la singola richiesta.
        # Si aspetta sull'evento di arresto, cosi' un riavvio non deve attendere la
        # fine del giro.
        _stop.wait(PAUSA_FRA_RICHIESTE)
    return {"raccolti": nuovi, "risolti": risolti, "falliti": falliti}


def stato() -> dict:
    """Quanto e' piena la cache e quanto e' rimasto da fare."""
    def conta(sql, parametri=()):
        riga = query(sql, parametri, one=True)
        return int((riga or {"n": 0})["n"] or 0)

    return {
        "intervalli": conta("SELECT count(*) AS n FROM net_ranges"),
        "indirizzi_visti": conta("SELECT count(*) AS n FROM net_lookups"),
        "risolti": conta("SELECT count(*) AS n FROM net_lookups"
                         " WHERE resolved_at IS NOT NULL"),
        "in_coda": conta("SELECT count(*) AS n FROM net_lookups"
                         " WHERE resolved_at IS NULL AND next_try_at IS NOT NULL"),
        "rinunciati": conta("SELECT count(*) AS n FROM net_lookups"
                            " WHERE resolved_at IS NULL AND next_try_at IS NULL"),
    }


# --------------------------------------------------------------------------- #
# Il servizio di fondo
# --------------------------------------------------------------------------- #
def start_watcher(app) -> None:
    global _thread
    if _thread is not None and _thread.is_alive():
        return
    if not app.config.get("RETE_PUBBLICA_ATTIVA", True):
        app.logger.info("Risoluzione delle reti pubbliche disattivata da"
                        " configurazione")
        return

    def ciclo():
        while not _stop.wait(TICK_SECONDI):
            try:
                with app.app_context():
                    esito = giro()
                    if esito["risolti"]:
                        app.logger.info("Reti pubbliche: %d risolte, %d non riuscite",
                                        esito["risolti"], esito["falliti"])
            except Exception as errore:  # nessun errore deve fermare il thread
                app.logger.warning("Risoluzione delle reti pubbliche non riuscita: %s",
                                   errore)
            if _stop.is_set():
                break

    _thread = threading.Thread(target=ciclo, name="snap-rete-pubblica", daemon=True)
    _thread.start()
    app.logger.info("Risoluzione delle reti pubbliche avviata (ogni %d s)",
                    TICK_SECONDI)


def stop_watcher() -> None:
    _stop.set()
