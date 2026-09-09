# -----------------------------------------------------------------
# snmp_raccolta.py — raccolta delle tabelle ARP dagli apparati di rete
# Autore: Daniele Speziale
# Data creazione: 2026-09-09
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap probe - Interroga gli apparati dichiarati e archivia le corrispondenze IP->MAC.

PERCHE'
-------
ARP non attraversa un router: la sonda vede i MAC del proprio segmento e di nessun
altro (misurato: 39 MAC su 7309 nodi, tutti nella subnet della sonda). Un router
conosce invece le corrispondenze di TUTTI i segmenti a cui e' attestato, e le espone
in SNMP. Interrogarlo e' l'unico modo di avere quel dato su una rete instradata.

DOVE STANNO LE CREDENZIALI, E PERCHE' QUI
-----------------------------------------
La community di sola lettura sta nelle impostazioni LOCALI della sonda, non sul
server. Tre ragioni:

* e' una credenziale di RETE del sito dove la sonda e' installata, non un dato del
  tenant: chi amministra quella rete la conosce, il gestore della console no;
* non attraversa il canale verso il server, quindi non c'e' un secondo posto da cui
  possa uscire;
* la si usa qui, e un segreto conviene tenerlo dove serve.

Conseguenza da conoscere: ogni sonda si configura per conto proprio. E' una scelta,
non una dimenticanza.

La community NON viene mai scritta nel diario ne' nei messaggi di errore: il diario
locale e' leggibile dall'interfaccia della sonda, e un segreto che finisce in un
diario e' un segreto perduto.
"""

from __future__ import annotations

from . import snmp

# Impostazioni locali (vedi la pagina Configurazione della sonda).
CHIAVE_APPARATI = "snmp_devices"
CHIAVE_COMMUNITY = "snmp_community"
CHIAVE_ATTIVA = "snmp_enabled"

# Quanto tempo una corrispondenza resta utilizzabile. Gli indirizzi si riassegnano:
# oltre questa finestra si preferisce NESSUN MAC a un MAC probabilmente sbagliato.
GIORNI_VALIDITA = 7

# Un apparato lento non deve tenere occupata la sonda: la raccolta e' un
# arricchimento, non la funzione principale.
TIMEOUT_APPARATO = 3.0
TENTATIVI = 2


def apparati_dichiarati(store) -> list[dict]:
    """Gli apparati da interrogare, dalle impostazioni locali.

    Formato di una riga: `indirizzo` oppure `indirizzo|etichetta`. Righe vuote e
    righe che iniziano con `#` si ignorano, cosi' l'elenco si puo' commentare.

    L'indirizzo si valida (allowlist): finisce in una connessione di rete e in un
    messaggio, e cio' che arriva dall'esterno si controlla.
    """
    import ipaddress

    grezzo = store.get_setting(CHIAVE_APPARATI, "") or ""
    apparati = []
    for riga in str(grezzo).splitlines():
        riga = riga.strip()
        if not riga or riga.startswith("#"):
            continue
        indirizzo, _, etichetta = riga.partition("|")
        indirizzo = indirizzo.strip()
        try:
            ipaddress.ip_address(indirizzo)
        except ValueError:
            store.log("warning", "Apparato SNMP ignorato: '%s' non e' un indirizzo"
                                 " valido" % indirizzo[:40])
            continue
        apparati.append({"indirizzo": indirizzo,
                         "etichetta": etichetta.strip() or indirizzo})
    return apparati


def attiva(store) -> bool:
    """La raccolta e' attiva? Serve la community, altrimenti non c'e' niente da fare."""
    if str(store.get_setting(CHIAVE_ATTIVA, "0")) not in ("1", "true", "si", "on"):
        return False
    return bool((store.get_setting(CHIAVE_COMMUNITY, "") or "").strip())


def raccogli(store) -> dict:
    """Interroga gli apparati e archivia le corrispondenze. Restituisce un riassunto.

    Un apparato che non risponde NON ferma gli altri: si annota e si continua. Su
    una rete vera un apparato spento o con la community diversa e' la norma, non
    l'eccezione, e non deve costare la raccolta di tutti gli altri.
    """
    esito = {"apparati": 0, "interrogati": 0, "falliti": 0, "coppie": 0,
             "porte": 0, "dettagli": []}
    if not attiva(store):
        return esito

    community = (store.get_setting(CHIAVE_COMMUNITY, "") or "").strip()
    apparati = apparati_dichiarati(store)
    esito["apparati"] = len(apparati)

    for apparato in apparati:
        indirizzo = apparato["indirizzo"]
        etichetta = apparato["etichetta"]
        try:
            tabella = snmp.arp_table(indirizzo, community,
                                     timeout=TIMEOUT_APPARATO, tentativi=TENTATIVI)
        except snmp.SnmpError as errore:
            # `errore` non contiene la community: il modulo snmp non la include nei
            # propri messaggi, ed e' una proprieta' da mantenere.
            esito["falliti"] += 1
            esito["dettagli"].append({"apparato": etichetta, "esito": "errore",
                                      "motivo": str(errore)})
            store.log("warning", "Apparato %s non interrogabile: %s"
                                 % (etichetta, errore))
            continue

        quante = store.salva_arp_snmp(tabella, etichetta)

        # Le PORTE FISICHE sono un secondo dato, da una tabella diversa: un router
        # ha la tabella ARP ma non quella di forwarding, uno switch di accesso il
        # contrario. Non trovarla non e' un errore, e' l'apparato che non e' uno
        # switch -- per questo si conta a parte e non fa fallire l'apparato.
        porte = {}
        try:
            porte = snmp.mac_su_porta(indirizzo, community,
                                      timeout=TIMEOUT_APPARATO, tentativi=TENTATIVI)
        except snmp.SnmpError:
            porte = {}
        quante_porte = store.salva_porte_snmp(porte, etichetta)

        esito["interrogati"] += 1
        esito["coppie"] += quante
        esito["porte"] += quante_porte
        esito["dettagli"].append({"apparato": etichetta, "esito": "ok",
                                  "coppie": quante, "porte": quante_porte})
        store.log("info", "Apparato %s: %d corrispondenze IP-MAC%s lette in SNMP"
                          % (etichetta, quante,
                             ", %d porte fisiche" % quante_porte if quante_porte
                             else ""))

    if esito["interrogati"]:
        store.log("info", "Raccolta SNMP: %d apparati interrogati, %d corrispondenze"
                          " IP-MAC totali (%d apparati non hanno risposto)"
                          % (esito["interrogati"], esito["coppie"], esito["falliti"]))
    return esito


def porta_per(store, mac: str) -> dict | None:
    """La porta fisica di un MAC, se recente. `None` se non si sa.

    E' il dato che dice DOVE e' attaccato un apparato: senza, un inventario dice che
    cosa c'e' in rete ma non dove andare a staccarlo.
    """
    return store.porta_da_snmp(mac, entro_giorni=GIORNI_VALIDITA)


def mac_per(store, ip: str) -> dict | None:
    """La corrispondenza per un indirizzo, se recente. `None` se non c'e'.

    Restituisce anche la FONTE: chi usera' questo dato deve poter dire da quale
    apparato viene, altrimenti fra sei mesi non e' verificabile.
    """
    return store.mac_da_snmp(ip, entro_giorni=GIORNI_VALIDITA)
