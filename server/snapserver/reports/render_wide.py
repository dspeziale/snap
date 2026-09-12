"""
snap server - Resa in PDF dei report di periodo: esecutivo, inventario, SOC,
conformita', incidente.

Usa la cornice di `render_pdf.py` (classe Foglio): intestazione, pie' di pagina,
tabelle, spezzate, tutto con le primitive del generatore e senza librerie di grafica
(RP-14). Qui sta soltanto la COMPOSIZIONE di ciascun documento, cioe' l'ordine in cui
le sezioni compaiono e le frasi che le rendono leggibili.

Ogni report apre con cio' che il suo destinatario cerca per primo: l'esecutivo con i
semafori, il SOC con le variazioni del periodo, l'inventario con la copertura del
perimetro, la conformita' con l'elenco dei controlli in vigore.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re
from html import unescape

from .dataset import change_label
from .render_pdf import (
    ATTENZIONE,
    CRITICO,
    Foglio,
    INCHIOSTRO,
    INCHIOSTRO_2,
    INCHIOSTRO_3,
    NOTA_PROVENIENZA,
    OK,
    istante_nel_fuso,
    riferimenti_comuni,
)

# Colore del semaforo. Il testo lo ripete sempre: un documento stampato in bianco e
# nero, o letto da chi non distingue i colori, deve dire la stessa cosa.
COLORE_STATO = {
    "buono": OK,
    "da guardare": ATTENZIONE,
    "critico": CRITICO,
    "non misurato": INCHIOSTRO_3,
}


def _percentuale(valore) -> str:
    return "non misurata" if valore is None else ("%.2f%%" % valore).replace(".", ",")


def _durata(minuti) -> str:
    if minuti is None:
        return "-"
    if minuti < 60:
        return "%d min" % minuti
    ore, resto = divmod(int(minuti), 60)
    return "%dh%02d" % (ore, resto)


def _differenza(valore, unita: str = "", inverti: bool = False) -> str:
    """Variazione rispetto al periodo precedente, con il segno e la direzione.

    `inverti` per gli indicatori in cui salire e' peggio (incidenti, superficie): la
    freccia dice se la cosa e' migliorata, non se il numero e' cresciuto.
    """
    if valore is None:
        return "periodo precedente non misurato"
    if abs(valore) < 0.005:
        return "stabile"
    migliora = (valore < 0) if inverti else (valore > 0)
    return "%s%s%s (%s)" % ("+" if valore > 0 else "", round(valore, 2), unita,
                            "in miglioramento" if migliora else "in peggioramento")


# --------------------------------------------------------------------------- #
# R1 - Sintesi esecutiva
# --------------------------------------------------------------------------- #
SEZIONI_EXECUTIVE = [
    "Come stiamo",
    "Andamento degli indicatori",
    "Superficie esposta",
    "Che cosa proponiamo",
    "Nota di lettura",
]


def executive_report(percorso, dati: dict) -> str:
    """Due o tre pagine, senza un solo indirizzo IP (RP-10, SR-111)."""
    foglio = Foglio(
        percorso, kind="executive", titolo="Sintesi esecutiva",
        sottotitolo="Siamo coperti? Sta migliorando? Dove serve una decisione?",
        tenant=dati["tenant"]["nome"], intervallo=dati["intervallo"],
        fuso=dati["tenant"].get("fuso"),
        generato=dati["generato_utc"],
        scopo=[
            "Stato della sorveglianza della rete di %s nell'intervallo %s, con il"
            " confronto sul periodo precedente."
            % (dati["tenant"]["nome"], dati["intervallo"]),
            "Il documento non contiene indirizzi ne' nomi di dispositivi: per rispondere"
            " a queste domande non servono, e un indirizzo di rete e' un dato personale.",
        ],
        sezioni=SEZIONI_EXECUTIVE, riferimenti=riferimenti_comuni(dati),
        nota=NOTA_PROVENIENZA)
    corrente = dati["confronto"]["corrente"]
    differenza = dati["confronto"]["differenza"]
    inventario = dati["inventario"]

    foglio.riquadri([
        (inventario.get("nodi") or 0, "dispositivi censiti", None),
        (_percentuale(corrente["disponibilita"]), "servizi disponibili",
         OK if (corrente["disponibilita"] or 0) >= 99 else ATTENZIONE),
        (dati["incidenti_aperti"], "incidenti aperti",
         CRITICO if dati["incidenti_aperti"] else OK),
        (_durata(corrente["tempo_risoluzione_medio"]), "tempo medio di ripristino",
         None),
        (dati["superficie"]["amministrazione"], "accessi remoti esposti",
         CRITICO if dati["superficie"]["amministrazione"] >= 10 else ATTENZIONE),
    ])

    foglio.titolo_sezione("Come stiamo", "confronto con il periodo precedente")
    if not dati["confronto"]["precedente_misurato"]:
        foglio.paragrafo(
            "Il periodo precedente non ha misure: il confronto sara' disponibile dal"
            " prossimo riesame. Non e' un peggioramento ne' un miglioramento, e' assenza"
            " di dati.", ATTENZIONE)
    foglio.tabella(
        ["area", "stato", "valore", "che cosa significa"],
        [[s["area"], s["stato"],
          ("-" if s["valore"] is None else s["valore"]), s["nota"]]
         for s in dati["semafori"]],
        larghezze=[2.6, 1.4, 1.0, 5.0])

    foglio.titolo_sezione("Andamento degli indicatori")
    foglio.tabella(
        ["indicatore", "periodo", "precedente", "variazione"],
        [
            ["Servizi disponibili", _percentuale(corrente["disponibilita"]),
             _percentuale(dati["confronto"]["precedente"]["disponibilita"]),
             _differenza(differenza["disponibilita"], "%")],
            ["Incidenti aperti nel periodo", corrente["incidenti_aperti"],
             dati["confronto"]["precedente"]["incidenti_aperti"],
             _differenza(differenza["incidenti_aperti"], inverti=True)],
            ["Tempo medio di ripristino",
             _durata(corrente["tempo_risoluzione_medio"]),
             _durata(dati["confronto"]["precedente"]["tempo_risoluzione_medio"]),
             _differenza(differenza["tempo_risoluzione_medio"], " min", inverti=True)],
            ["Dispositivi comparsi", corrente["nodi_nuovi"],
             dati["confronto"]["precedente"]["nodi_nuovi"],
             _differenza(differenza["nodi_nuovi"])],
            ["Variazioni registrate", corrente["variazioni"],
             dati["confronto"]["precedente"]["variazioni"],
             _differenza(differenza["variazioni"])],
        ],
        larghezze=[3.0, 1.6, 1.6, 3.8],
        allineamento=["l", "r", "r", "l"])

    foglio.titolo_sezione("Superficie esposta", "per categoria, senza dettagli tecnici")
    foglio.tabella(
        ["categoria di servizio", "dispositivi", "servizi distinti"],
        [[c["etichetta"], c["nodi"], c["porte"]]
         for c in dati["superficie"]["categorie"]],
        larghezze=[5.0, 1.5, 1.5],
        allineamento=["l", "r", "r"],
        nota_vuota="Nessun servizio raggiungibile rilevato.")

    foglio.titolo_sezione("Che cosa proponiamo", "tre azioni, in ordine di effetto")
    if dati["azioni"]:
        for indice, azione in enumerate(dati["azioni"], start=1):
            foglio.paragrafo("%d. %s" % (indice, azione["azione"]), INCHIOSTRO_2,
                             dimensione=10)
            foglio.paragrafo("    Perche': %s" % azione["perche"], INCHIOSTRO_3)
            foglio.paragrafo("    Effetto atteso: %s" % azione["effetto"], INCHIOSTRO_3)
    else:
        foglio.paragrafo("Nessuna azione da proporre: nessun incidente aperto, nessuna"
                         " esposizione anomala, inventario identificato.", OK)

    foglio.titolo_sezione("Nota di lettura")
    foglio.paragrafo(
        "Questo documento non contiene indirizzi ne' nomi di dispositivi: un indirizzo"
        " di rete e' un dato personale ai sensi del GDPR, e per rispondere alle domande"
        " di questa pagina non serve. Il dettaglio tecnico e' nel report di inventario e"
        " in quello di sicurezza, il cui accesso e' riservato a chi opera sulla rete.")
    foglio.paragrafo(
        "I valori sono riproducibili: la stessa richiesta sullo stesso intervallo"
        " produce gli stessi numeri. Dove non e' stata eseguita alcuna misura si legge"
        " \"non misurata\": non e' uno zero.")
    foglio.salva()
    return str(percorso)


# --------------------------------------------------------------------------- #
# R2 - Inventario e valutazione tecnica
# --------------------------------------------------------------------------- #
SEZIONI_INVENTARIO = [
    "Perimetro dichiarato e perimetro osservato",
    "Porte aperte su una quota rilevante della rete",
    "Nodi e servizi propri",
    "Apparati interrogati via SNMP",
    "Da identificare",
    "Variazioni del periodo",
    "Qualita' della raccolta",
    "Metodologia",
]


def inventory_report(percorso, dati: dict) -> str:
    """Orizzontale: le tabelle dell'inventario hanno piu' di otto colonne."""
    foglio = Foglio(
        percorso, kind="inventory", titolo="Inventario e valutazione tecnica",
        sottotitolo="Che cosa c'e' in rete, con che cosa risponde, che cosa e' cambiato",
        tenant=dati["tenant"]["nome"], intervallo=dati["intervallo"],
        fuso=dati["tenant"].get("fuso"),
        generato=dati["generato_utc"], orizzontale=True,
        scopo=[
            "Censimento dei dispositivi e dei servizi raggiungibili nel perimetro"
            " dichiarato di %s, con le variazioni dell'intervallo %s."
            % (dati["tenant"]["nome"], dati["intervallo"]),
            "L'appendice di metodologia dichiara come i dati sono stati raccolti: senza,"
            " un risultato non e' contestabile, e un risultato non contestabile non e'"
            " una misura.",
        ],
        sezioni=SEZIONI_INVENTARIO, riferimenti=riferimenti_comuni(dati),
        nota=NOTA_PROVENIENZA)
    inventario = dati["inventario"]

    foglio.riquadri([
        (inventario.get("nodi") or 0, "nodi in inventario", None),
        (inventario.get("su") or 0, "raggiungibili", OK),
        (inventario.get("senza_tipo") or 0, "senza tipo",
         ATTENZIONE if inventario.get("senza_tipo") else OK),
        (len(dati["servizi"]), "servizi aperti rilevati", None),
        ("%s%%" % (inventario.get("occupazione")
                   if inventario.get("occupazione") is not None else "-"),
         "occupazione del perimetro", None),
    ])

    foglio.titolo_sezione("Perimetro dichiarato e perimetro osservato")
    foglio.tabella(
        ["subnet", "etichetta", "stato", "host teorici", "nodi trovati", "raggiungibili",
         "senza tipo", "occupazione"],
        [[p["cidr"], p["label"] or "", "attiva" if p["is_enabled"] else "!sospesa",
          p["host_count"], p["nodi"], p["su"], p["senza_tipo"],
          "%s%%" % round(100.0 * int(p["nodi"] or 0) / max(1, int(p["host_count"] or 1)), 1)]
         for p in dati["perimetro"]],
        larghezze=[1.6, 3.0, 1.0, 1.2, 1.2, 1.2, 1.0, 1.2],
        allineamento=["l", "l", "l", "r", "r", "r", "r", "r"],
        nota_vuota="Nessuna subnet dichiarata: senza perimetro la sonda non scansiona.")

    foglio.titolo_sezione("Porte aperte su una quota rilevante della rete",
                          "fatti architetturali, non eventi")
    if dati["porte_frequenti"]:
        foglio.paragrafo(
            "Una porta aperta su quasi tutti i nodi non sono altrettanti servizi: e' un"
            " apparato che risponde per altri (tipicamente un centralino o un apparato"
            " di rete che intercetta la connessione). Verificarlo prima di censirla come"
            " superficie esposta.", INCHIOSTRO_2)
    foglio.tabella(
        ["porta", "servizio", "nodi", "quota della rete"],
        [["%s/%s" % (p["protocol"], p["port"]), p["servizio"] or "", p["nodi"],
          "%s%%" % p["quota"]] for p in dati["porte_frequenti"]],
        larghezze=[1.2, 2.0, 1.0, 1.4],
        allineamento=["l", "l", "r", "r"], colonne=2,
        nota_vuota="Nessuna porta aperta su piu' di un quinto dei nodi.")

    # Nodi e servizi in un'unica sezione: prima erano due paragrafi che ripetevano lo
    # stesso indirizzo -- uno per elencare il nodo, uno per i suoi servizi. Fusi in un
    # solo badge per nodo (indirizzo, tipo e porte proprie con prodotto e versione) si
    # risparmia lo spazio della ripetizione e il documento si accorcia ancora.
    from ..ingest import SUSPECT_MIN_PREVALENCE

    iniettati = sum(1 for s in dati["servizi"] if s["is_suspect"])
    foglio.titolo_sezione(
        "Nodi e servizi propri",
        "%d nodi%s — un badge per indirizzo, con tipo e servizi propri" % (
            len(dati["nodi"]), ", elenco troncato" if dati["troncato"]["nodi"] else ""))
    foglio.paragrafo(
        "Un badge per nodo: l'indirizzo, il tipo attribuito e le porte aperte proprie con"
        " cio' che risponde (porta, prodotto, versione). Le porte iniettate dalla rete --"
        " le stesse su quasi tutta la rete, gia' spiegate qui sopra -- non si elencano nel"
        " badge: si contano in coda come \"+N iniett.\", cosi' il documento resta compatto.",
        INCHIOSTRO_2)
    if iniettati:
        foglio.paragrafo(
            "Non elencati %d servizi su porte iniettate (aperte su almeno il %d%% dei nodi"
            " e su famiglie di sistema operativo diverse): sono le stesse porte ripetute su"
            " quasi tutta la rete. Vedi \"Porte aperte su una quota rilevante\"."
            % (iniettati, int(SUSPECT_MIN_PREVALENCE * 100)), INCHIOSTRO_3)
    foglio.griglia_nodi_servizi(dati["nodi"], dati["servizi"], colonne=2,
                                nota_vuota="Inventario vuoto.")

    # --- Cio' che gli apparati hanno raccontato di se' --------------------- #
    copertura = dati.get("copertura_snmp") or {}
    apparati = dati.get("apparati_snmp") or []
    foglio.titolo_sezione(
        "Apparati interrogati via SNMP",
        "%d apparati su %d che espongono la porta"
        % (copertura.get("letti", 0), copertura.get("esposti", 0)))
    foglio.paragrafo(
        "Dove SNMP risponde, l'apparato dichiara di se' piu' di quanto direbbe"
        " qualunque porta TCP: modello e versione del firmware nella descrizione di"
        " sistema, nome, collocazione, riferimento amministrativo, interfacce con i"
        " loro indirizzi. Su switch e stampanti e' spesso l'unica fonte di modello e"
        " firmware, e per questo l'inventario tecnico se ne serve.")
    if copertura.get("da_leggere"):
        foglio.paragrafo(
            "%d apparati espongono la porta ma non hanno risposto: la lettura ha una"
            " cadenza propria, e chi non risponde puo' avere una community diversa da"
            " quella di fabbrica. Non e' una mancanza dell'inventario."
            % copertura["da_leggere"], INCHIOSTRO_3)
    foglio.tabella(
        ["nodo", "dispositivo", "nome dichiarato", "modello e firmware",
         "collocazione", "acceso da", "intf."],
        [[v["ip"], (v["device_label"] or ""), (v["nome"] or ""),
          (v["descrizione"] or ""), (v["collocazione"] or ""),
          foglio.istante(v["accensione"], ""), v["interfacce"] or "-"]
         for v in apparati],
        larghezze=[1.1, 1.5, 1.6, 3.4, 1.4, 1.2, .5],
        allineamento=["l", "l", "l", "l", "l", "l", "r"],
        nota_vuota="Nessun apparato ha risposto a SNMP in questo inventario.")

    foglio.titolo_sezione("Da identificare", "il lavoro che resta")
    foglio.tabella(
        ["indirizzo", "nome host", "sistema operativo", "tipo attribuito", "confidenza",
         "porte aperte"],
        [[n["ip"], (n["hostname"] or ""), (n["os_name"] or ""),
          n["device_label"] or n["device_type"] or "nessuno",
          "%s%%" % (n["device_confidence"] or 0), n["porte"]]
         for n in dati["non_identificati"]],
        larghezze=[1.4, 2.4, 2.6, 2.2, 1.2, 1.0],
        allineamento=["l", "l", "l", "l", "r", "r"],
        nota_vuota="Tutti i nodi hanno un tipo con confidenza sufficiente.")

    foglio.titolo_sezione("Variazioni del periodo")
    foglio.tabella(
        ["genere", "eventi", "nodi coinvolti", "presentazione"],
        [[change_label(g["genere"]), g["eventi"], g["nodi"],
          "fatto aggregato (oltre un quinto della rete)" if g["aggregato"]
          else "elencabile"] for g in dati["variazioni"]["generi"]],
        larghezze=[3.0, 1.0, 1.2, 4.0],
        allineamento=["l", "r", "r", "l"],
        nota_vuota="Nessuna variazione nell'intervallo.")

    foglio.titolo_sezione("Qualita' della raccolta")
    foglio.tabella(
        ["fase", "esito", "passate", "durata media", "host attivi", "host totali"],
        [[r["stage"], r["status"] if r["status"] == "completed" else "!" + r["status"],
          r["n"], "%s s" % r["secondi"], r["su"], r["totali"]]
         for r in dati["raccolta"]["passate"]],
        larghezze=[1.6, 1.6, 1.0, 1.4, 1.2, 1.2],
        allineamento=["l", "l", "r", "r", "r", "r"],
        nota_vuota="Nessuna passata di scansione nell'intervallo.")

    _metodologia(foglio, dati)
    foglio.salva()
    return str(percorso)


def _metodologia(foglio, dati: dict) -> None:
    """Appendice comune ai report tecnici (RP-11, SR-112)."""
    foglio.titolo_sezione("Metodologia", "SR-112")
    foglio.paragrafo(
        "I dati provengono dalle sonde installate nella rete del cliente: nessuna"
        " connessione entra nella rete sorvegliata dall'esterno. La sonda contatta il"
        " server, riceve il perimetro dichiarato e non accetta bersagli che non siano"
        " contenuti in esso.")
    foglio.paragrafo(
        "La scansione procede per fasi: scoperta degli host, porte, servizi e versioni,"
        " sistema operativo, approfondimento. Ogni fase ha un proprio tempo massimo per"
        " host; le porte esaminate nelle fasi successive sono quelle risultate aperte"
        " nella precedente, quindi due passate a distanza di tempo possono produrre"
        " numeri diversi senza che nulla sia cambiato in rete.")
    sonde = dati.get("raccolta", {}).get("sonde") or []
    if sonde:
        foglio.paragrafo("Sonde e profilo di sforzo in vigore: %s."
                         % ", ".join("%s (%s, %s)"
                                     % (s["nome"], s["sforzo"] or "?",
                                        "scansione attiva" if s["scansione_attiva"]
                                        else "scansione sospesa") for s in sonde))
    foglio.paragrafo(
        "Le finestre temporali sono calcolate nel fuso del tenant (%s). Un intervallo"
        " senza esecuzioni e' dichiarato non misurato e non viene rappresentato come"
        " valore nullo." % dati["tenant"]["fuso"])


# --------------------------------------------------------------------------- #
# R4 - Postura di sicurezza
# --------------------------------------------------------------------------- #
SEZIONI_SOC = [
    "Vulnerabilita' note sui dispositivi",
    "Che cosa e' cambiato",
    "Nodi comparsi e scomparsi",
    "Identita' cambiate sullo stesso indirizzo",
    "Superficie esposta",
    "Esposizione informativa",
    "Nodi fuori perimetro",
    "Porte sospette",
    "Registro delle azioni",
    "Riferimenti normativi",
]


def soc_report(percorso, dati: dict) -> str:
    """Apre con le variazioni: la variazione e' il segnale, non lo stato (RP-12)."""
    variazioni = dati["variazioni_sicurezza"]
    superficie = dati["superficie"]
    base = dati["rilevamento_base"]
    # L'indice segue le sezioni che verranno davvero stampate: l'avvertenza sul
    # rilevamento di base compare solo quando serve.
    sezioni = (["Avvertenza: rilevamento di base"] if base["attivo"] else []) \
        + SEZIONI_SOC

    foglio = Foglio(
        percorso, kind="soc", titolo="Postura di sicurezza",
        sottotitolo="Che superficie esponiamo, che cosa e' cambiato, che cosa va"
                    " investigato",
        tenant=dati["tenant"]["nome"], intervallo=dati["intervallo"],
        fuso=dati["tenant"].get("fuso"),
        generato=dati["generato_utc"],
        scopo=[
            "Variazioni di sicurezza e superficie esposta della rete di %s"
            " nell'intervallo %s." % (dati["tenant"]["nome"], dati["intervallo"]),
            "Le variazioni vengono prima dello stato: una porta aperta da sempre e'"
            " architettura nota, la stessa porta aperta ieri e' un evento.",
        ],
        sezioni=sezioni, riferimenti=riferimenti_comuni(dati),
        nota=NOTA_PROVENIENZA)

    foglio.riquadri([
        (variazioni["porte_aperte_totali"], "porte aperte nel periodo",
         ATTENZIONE if variazioni["porte_aperte_totali"] else OK),
        (len(variazioni["nodi_comparsi"]), "nodi comparsi",
         ATTENZIONE if variazioni["nodi_comparsi"] else OK),
        (superficie["amministrazione"], "nodi con accesso remoto",
         CRITICO if superficie["amministrazione"] >= 10 else ATTENZIONE),
        (len(dati["fuori_perimetro"]), "nodi fuori perimetro",
         CRITICO if dati["fuori_perimetro"] else OK),
        (dati["audit"]["accessi_falliti"], "accessi falliti",
         ATTENZIONE if dati["audit"]["accessi_falliti"] else OK),
    ])

    if base["attivo"]:
        foglio.titolo_sezione("Avvertenza: rilevamento di base")
        foglio.paragrafo(
            "L'inventario e' al giorno %d di %d di rilevamento di base: le variazioni di"
            " questo periodo comprendono il primo censimento, quindi una variazione per"
            " ogni nodo e per ogni porta trovata. Non vanno lette come eventi di"
            " sicurezza. Dal %s il confronto sara' significativo."
            % (base["giorno"], base["di"],
               base["fine"].strftime("%d/%m/%Y") if base["fine"] else "termine"),
            ATTENZIONE)

    # --- Vulnerabilita' note: prima delle variazioni, perche' un riscontro confermato
    # e' un fatto su cui intervenire, non un cambiamento da valutare.
    minacce = dati.get("minacce") or {}
    riepilogo = minacce.get("riepilogo") or {}
    foglio.titolo_sezione(
        "Vulnerabilita' note sui dispositivi",
        "catalogo aggiornato al %s" % foglio.giorno(minacce.get("ultimo_aggiornamento"), "mai"))
    if not minacce.get("disponibile"):
        foglio.paragrafo("Correlazione non disponibile in questo archivio.", INCHIOSTRO_3)
    elif not riepilogo.get("aperti"):
        foglio.paragrafo(
            "Nessun riscontro aperto. Se il catalogo delle CVE non e' mai stato"
            " aggiornato, questo non significa che non ci siano vulnerabilita': la"
            " correlazione lavora sul catalogo locale.", ATTENZIONE)
    else:
        foglio.paragrafo(
            "Riscontri aperti: %d confermati, %d da verificare, %d esposizioni di"
            " servizio, su %d dispositivi. Le tre classi restano distinte perche'"
            " rispondono a domande diverse: che cosa e' dimostrato, che cosa va"
            " accertato, che cosa e' rischioso per natura."
            % (riepilogo.get("confermati", 0), riepilogo.get("da_verificare", 0),
               riepilogo.get("esposizioni", 0), riepilogo.get("nodi", 0)))
        qualita = ("Qualita' del dato: %d porte aperte, %d con identificativo di"
                   " prodotto, %d con versione. Una CVE si attribuisce a un'istanza"
                   " solo conoscendo la versione."
                   % (riepilogo.get("porte_aperte", 0),
                      riepilogo.get("porte_con_cpe", 0),
                      riepilogo.get("porte_con_versione", 0)))
        foglio.paragrafo(qualita, INCHIOSTRO_3)

        foglio.tabella(
            ["nodo", "porta", "CVE", "gravita'", "punteggio", "prodotto", "versione",
             "conf."],
            [[v["ip"], "%s/%s" % (v["protocol"] or "-", v["port"] or "-"),
              ("!!" if v["kev"] else "") + (v["cve_id"] or ""),
              v["severity"], v["score"] or "-", v["product"] or "",
              v["version"] or "", "%d%%" % v["confidence"]]
             for v in minacce.get("confermati") or []],
            larghezze=[1.4, .9, 1.6, 1.0, .9, 1.6, 1.0, .7],
            allineamento=["l", "l", "l", "l", "r", "l", "l", "r"],
            nota_vuota="Nessuna vulnerabilita' confermata: nessun servizio con versione"
                       " rilevata rientra nell'applicabilita' dichiarata dalla NVD.")

        if minacce.get("da_verificare"):
            foglio.paragrafo("Da verificare: prodotti riconosciuti senza versione, per i"
                             " quali il catalogo contiene CVE. Non sono vulnerabilita'"
                             " accertate; dicono dove serve rilevare la versione.",
                             INCHIOSTRO_2)
            foglio.tabella(
                ["nodo", "porta", "riscontro", "conf."],
                [[v["ip"], "%s/%s" % (v["protocol"] or "-", v["port"] or "-"),
                  v["title"], "%d%%" % v["confidence"]]
                 for v in (minacce.get("da_verificare") or [])],
                larghezze=[1.4, .9, 3.6, .7],
                allineamento=["l", "l", "l", "r"], colonne=2)

    foglio.titolo_sezione("Che cosa e' cambiato", "in ordine di rischio")
    for categoria in variazioni["porte_per_categoria"]:
        foglio.paragrafo("%s: %d aperture" % (categoria["etichetta"],
                                              len(categoria["eventi"])),
                         INCHIOSTRO_2, dimensione=10)
        foglio.tabella(
            ["nodo", "nome host", "porta", "servizio", "quando"],
            [[e["nodo"], (e["nome"] or ""), e["porta"], (e["servizio"] or ""),
              foglio.istante(e["quando"], "")] for e in categoria["eventi"]],
            larghezze=[1.4, 2.4, 1.0, 2.0, 1.6],
            nota_vuota="-")
    if not variazioni["porte_per_categoria"]:
        foglio.paragrafo("Nessuna porta aperta nel periodo.", OK)

    foglio.titolo_sezione("Nodi comparsi e scomparsi")
    foglio.tabella(
        ["evento", "indirizzo", "nome host", "quando"],
        [["comparso", v["subject"], (v["hostname"] or ""), foglio.istante(v["created_at"], "")]
         for v in variazioni["nodi_comparsi"]]
        + [["scomparso", v["subject"], (v["hostname"] or ""),
            foglio.istante(v["created_at"], "")] for v in variazioni["nodi_scomparsi"]],
        larghezze=[1.2, 1.6, 3.0, 1.6],
        nota_vuota="Nessun nodo comparso o scomparso nel periodo.")

    foglio.titolo_sezione("Identita' cambiate sullo stesso indirizzo",
                          "possibile sostituzione di apparato o riassegnazione")
    foglio.tabella(
        ["genere", "soggetto", "prima", "adesso", "quando"],
        [["sistema operativo", v["subject"], (v["before_value"] or ""),
          (v["after_value"] or ""), foglio.istante(v["created_at"], "")]
         for v in variazioni["sistemi_cambiati"]]
        + [["nome host", v["subject"], (v["before_value"] or ""),
            (v["after_value"] or ""), foglio.istante(v["created_at"], "")]
           for v in variazioni["nomi_cambiati"]]
        + [["indirizzo fisico", v["subject"], (v["before_value"] or ""),
            (v["after_value"] or ""), foglio.istante(v["created_at"], "")]
           for v in variazioni["indirizzi_fisici_cambiati"]],
        larghezze=[1.6, 1.6, 2.2, 2.2, 1.6],
        nota_vuota="Nessun cambio di identita' nel periodo.")

    foglio.titolo_sezione("Superficie esposta", "stato, non variazione")
    for categoria in superficie["categorie"]:
        foglio.paragrafo("%s - %s" % (categoria["etichetta"], categoria["nota"]),
                         INCHIOSTRO_2)
        foglio.tabella(
            ["porta", "servizio", "prodotto", "nodi", "sospette"],
            [[p["porta"], (p["servizio"] or ""), (p["prodotto"] or ""),
              p["nodi"], p["sospette"] or ""] for p in categoria["porte"]],
            larghezze=[1.0, 1.8, 2.6, .8, .8],
            allineamento=["l", "l", "l", "r", "r"],
            nota_vuota="-")

    copertura_snmp = dati.get("copertura_snmp") or {}
    if copertura_snmp.get("letti"):
        foglio.paragrafo(
            "Con la community di fabbrica %d apparati hanno raccontato: %d descrizioni"
            " di sistema con modello e firmware, %d interfacce di rete con i loro"
            " indirizzi, %d processi, %d voci di software installato, %d connessioni"
            " e %d utenze locali. Non e' una vulnerabilita': e' ricognizione servita"
            " al bersaglio, e vale per chiunque raggiunga la porta."
            % (copertura_snmp.get("letti", 0),
               copertura_snmp.get("con_descrizione", 0),
               copertura_snmp.get("interfacce", 0), copertura_snmp.get("processi", 0),
               copertura_snmp.get("software", 0), copertura_snmp.get("connessioni", 0),
               copertura_snmp.get("utenti", 0)),
            ATTENZIONE)

    foglio.titolo_sezione("Esposizione informativa", "SNMP leggibile in sola lettura")
    foglio.tabella(
        ["indirizzo", "nome host", "etichetta", "servizio", "informazioni"],
        [[s["ip"], (s["hostname"] or ""), (s["device_label"] or ""),
          (s["service_name"] or ""), (s["extrainfo"] or "")]
         for s in dati["snmp"]],
        larghezze=[1.4, 2.0, 1.8, 1.4, 2.4],
        nota_vuota="Nessun nodo risponde a SNMP.")

    foglio.titolo_sezione("Nodi fuori perimetro",
                          "rilevati ma non appartenenti a una subnet attiva")
    foglio.tabella(
        ["indirizzo", "nome host", "etichetta", "subnet", "stato subnet"],
        [[n["ip"], (n["hostname"] or ""), (n["device_label"] or ""),
          n["cidr"] or "nessuna", "sospesa" if n["cidr"] else "-"]
         for n in dati["fuori_perimetro"]],
        larghezze=[1.4, 1.8, 1.8, 1.4, 1.0], colonne=2,
        nota_vuota="Tutti i nodi appartengono a una subnet dichiarata e attiva.")

    foglio.titolo_sezione("Porte sospette",
                          "risposta probabile di un apparato intermedio")
    foglio.tabella(
        ["indirizzo", "porta", "servizio", "motivo del sospetto"],
        [[p["ip"], "%s/%s" % (p["protocol"], p["port"]), (p["service_name"] or ""),
          (p["suspect_reason"] or "")] for p in dati["porte_sospette"]],
        larghezze=[1.4, 1.0, 1.8, 4.6],
        nota_vuota="Nessuna porta marcata come sospetta.")

    foglio.titolo_sezione("Registro delle azioni", "accessi e modifiche del periodo")
    foglio.paragrafo("Accessi riusciti: %d. Accessi falliti: %d. Eventi registrati: %d."
                     % (dati["audit"]["accessi_riusciti"],
                        dati["audit"]["accessi_falliti"], dati["audit"]["totale"]))
    foglio.tabella(
        ["quando", "evento", "gravita'", "attore", "descrizione"],
        [[foglio.istante(a["created_at"], ""), a["event_type"],
          ("!!" if a["severity"] == "critical" else "!") + (a["severity"] or "")
          if a["severity"] in ("warning", "critical") else (a["severity"] or ""),
          (a["full_name"] or a["actor"] or ""), (a["description"] or "")]
         for a in dati["audit"]["notevoli"]],
        larghezze=[1.4, 2.0, 1.0, 1.6, 4.0],
        nota_vuota="Nessun evento notevole nel periodo.")

    foglio.titolo_sezione("Riferimenti normativi")
    foglio.elenco([
        "NIS2 (UE) 2022/2555 art. 21(2)(a): analisi dei rischi e sicurezza dei sistemi"
        " informativi -- l'inventario e la superficie esposta sono la base.",
        "NIS2 art. 21(2)(e): sicurezza nell'acquisizione, sviluppo e manutenzione, con"
        " gestione delle vulnerabilita' -- i servizi rilevati con versione ne sono il"
        " presupposto.",
        "NIS2 art. 21(2)(g): igiene informatica di base -- protocolli in chiaro e accessi"
        " remoti esposti sono gli indicatori piu' diretti.",
        "CRA (UE) 2024/2847 allegato I: superficie di attacco documentata e sua"
        " evoluzione nel tempo.",
        "GDPR art. 32: misure tecniche adeguate -- questo documento e' la prova che la"
        " superficie e' sorvegliata.",
        "ETSI EN 303 645: apparati di consumo rilevati in rete (telecamere, stampanti,"
        " apparati domotici) con servizi di gestione raggiungibili.",
    ])
    foglio.salva()
    return str(percorso)


# --------------------------------------------------------------------------- #
# R8 - Vulnerabilita' ed esposizioni
# --------------------------------------------------------------------------- #
SEZIONI_VULNERABILITA = [
    "Come leggere questo documento",
    "Qualita' del dato",
    "Vulnerabilita' confermate",
    "Da verificare: prodotti senza versione",
    "Esposizioni di servizio",
    "Dispositivi da cui cominciare",
    "Che cosa e' cambiato nel periodo",
    "Decisioni registrate",
    "Stato del catalogo",
    "Riferimenti normativi",
]

# Gravita' in italiano e colore. Il testo dice sempre la parola: un documento
# stampato in bianco e nero deve dire la stessa cosa del colore.
GRAVITA = {
    "critical": ("critica", CRITICO),
    "high": ("alta", CRITICO),
    "medium": ("media", ATTENZIONE),
    "low": ("bassa", INCHIOSTRO_2),
    "info": ("informativa", INCHIOSTRO_3),
}


def _gravita(codice: str) -> str:
    return GRAVITA.get(codice, ("non dichiarata", INCHIOSTRO_3))[0]


def _colore_gravita(codice: str):
    return GRAVITA.get(codice, ("", INCHIOSTRO_3))[1]


def threat_report(percorso, dati: dict) -> str:
    """Vulnerabilita' ed esposizioni: che cosa e' dimostrato, che cosa va accertato.

    L'ordine e' quello dell'intervento, non quello del punteggio: prima le
    vulnerabilita' sfruttate attivamente, poi le confermate per gravita', poi le
    esposizioni di servizio raggruppate per tipo. Le tre classi non vengono mai
    sommate in un totale unico (TI-02).
    """
    riepilogo = dati.get("riepilogo") or {}
    catalogo = dati.get("catalogo") or {}

    foglio = Foglio(
        percorso, kind="threat", titolo="Vulnerabilita' ed esposizioni",
        sottotitolo="Che cosa e' dimostrato, che cosa va accertato, da dove cominciare",
        tenant=dati["tenant"]["nome"], intervallo=dati["intervallo"],
        fuso=dati["tenant"].get("fuso"),
        generato=dati["generato_utc"],
        scopo=[
            "Correlazione fra l'inventario di %s e il catalogo locale di"
            " vulnerabilita' note (NVD/CVE), classi di debolezza (CWE),"
            " vulnerabilita' sfruttate attivamente (CISA KEV) e tecniche di"
            " attacco (MITRE ATT&CK)." % dati["tenant"]["nome"],
            "Il documento riporta lo stato corrente della correlazione e, per"
            " l'intervallo %s, che cosa e' comparso e che cosa e' stato chiuso."
            % dati["intervallo"],
        ],
        sezioni=SEZIONI_VULNERABILITA, riferimenti=riferimenti_comuni(dati, extra=[
            ("Catalogo CVE", "%s voci" % catalogo.get("cve", 0)),
            ("Aggiornato il", istante_nel_fuso(dati.get("ultimo_aggiornamento"),
                                              dati["tenant"].get("fuso"), "mai")),
        ]),
        nota=NOTA_PROVENIENZA)

    if not dati.get("disponibile"):
        foglio.titolo_sezione("Correlazione non disponibile")
        foglio.paragrafo(
            "Il modulo di threat intelligence non e' disponibile in questo archivio:"
            " il documento non puo' riportare riscontri. Non significa che non ci"
            " siano vulnerabilita'.", ATTENZIONE)
        foglio.salva()
        return str(percorso)

    foglio.riquadri([
        (riepilogo.get("kev", 0), "sfruttate attivamente",
         CRITICO if riepilogo.get("kev") else OK),
        (riepilogo.get("confermati", 0), "confermate",
         CRITICO if riepilogo.get("confermati") else OK),
        (riepilogo.get("da_verificare", 0), "da verificare",
         ATTENZIONE if riepilogo.get("da_verificare") else OK),
        (riepilogo.get("esposizioni", 0), "esposizioni di servizio",
         ATTENZIONE if riepilogo.get("esposizioni") else OK),
        (riepilogo.get("nodi", 0), "dispositivi interessati", INCHIOSTRO_2),
    ])

    # --- 1. Come si legge -------------------------------------------------- #
    foglio.titolo_sezione("Come leggere questo documento")
    foglio.paragrafo(
        "Correlare un inventario con le vulnerabilita' pubblicate e' facile da fare"
        " male: si cerca il nome del prodotto e si produce un elenco lungo,"
        " spaventoso e inutile. Per questo ogni riscontro dichiara a quale classe"
        " appartiene, e le classi non si sommano.")
    foglio.elenco([
        "CONFERMATA - prodotto e versione noti, e la versione rientra"
        " nell'applicabilita' dichiarata dalla NVD. E' un fatto: quel dispositivo e'"
        " interessato. E' l'unico caso in cui si parla di vulnerabilita'.",
        "DA VERIFICARE - prodotto riconosciuto, versione ignota. Le vulnerabilita'"
        " esistono per quel prodotto, ma l'istanza non e' verificabile. Dice dove"
        " serve rilevare la versione, non che ci sia un problema.",
        "ESPOSIZIONE - nessuna vulnerabilita' in gioco: e' il servizio in se' a"
        " essere un rischio. Telnet in chiaro, SMB raggiungibile, desktop remoto"
        " aperto. Porta la tecnica MITRE ATT&CK che la sfrutterebbe.",
    ])
    foglio.paragrafo(
        "Una versione fuori intervallo non produce nulla: se il servizio dichiara"
        " una versione e quella versione non rientra nell'applicabilita', non si"
        " segnala niente. E' la regola che separa una correlazione da un generatore"
        " di falsi positivi.", INCHIOSTRO_2)
    foglio.paragrafo(
        "L'associazione fra porta esposta e tecnica MITRE ATT&CK e' nostra e non di"
        " MITRE, che non pubblica una mappa porta-tecnica: le tecniche citate"
        " appartengono al catalogo ATT&CK, l'attribuzione e' una valutazione di"
        " questo prodotto.", INCHIOSTRO_3)

    # --- 2. Qualita' del dato ---------------------------------------------- #
    foglio.titolo_sezione(
        "Qualita' del dato",
        "una vulnerabilita' si attribuisce solo conoscendo la versione")
    aperte = riepilogo.get("porte_aperte", 0)
    con_versione = riepilogo.get("porte_con_versione", 0)
    quota = (100.0 * con_versione / aperte) if aperte else 0.0
    foglio.tabella(
        ["misura", "valore", "che cosa comporta"],
        [["Porte aperte nell'inventario", aperte,
          "l'insieme su cui la correlazione lavora"],
         ["Con identificativo di prodotto (CPE)", riepilogo.get("porte_con_cpe", 0),
          "il prodotto e' riconoscibile senza euristiche"],
         ["Con versione rilevata", con_versione,
          "sono le sole su cui una vulnerabilita' puo' essere confermata"],
         ["Quota con versione", ("%.1f%%" % quota).replace(".", ","),
          "il tetto massimo delle conferme possibili"]],
        larghezze=[2.2, 1.0, 3.4], allineamento=["l", "r", "l"])
    if quota < 5:
        foglio.paragrafo(
            "Meno del 5% delle porte aperte annuncia una versione: con questo dato"
            " un elenco di vulnerabilita' confermate quasi vuoto e' la risposta"
            " vera, non un guasto. Per averne di piu' serve piu' informazione, cioe'"
            " un profilo di sforzo piu' alto sulle sonde, che aumenta"
            " l'interrogazione dei servizi.", ATTENZIONE)

    # --- 3. Confermate ----------------------------------------------------- #
    foglio.titolo_sezione(
        "Vulnerabilita' confermate",
        "%d in totale, ordinate per intervento" % dati.get("confermati_totale", 0))
    if riepilogo.get("kev"):
        foglio.paragrafo(
            "%d riscontri riguardano vulnerabilita' che risultano SFRUTTATE"
            " ATTIVAMENTE in attacchi reali (elenco CISA KEV) e sono contrassegnate"
            " con (!). Fra due vulnerabilita' con lo stesso punteggio, quella"
            " sfruttata va prima: il punteggio misura il danno possibile, il KEV"
            " misura il fatto." % riepilogo["kev"], CRITICO)
    foglio.tabella(
        ["nodo", "dispositivo", "porta", "CVE", "gravita'", "CVSS", "prodotto",
         "versione", "conf."],
        [[v["ip"], (v["device_label"] or ""),
          "%s/%s" % (v["protocol"] or "-", v["port"] or "-"),
          ("(!) " if v.get("kev") else "") + (v["cve_id"] or ""),
          _gravita(v["severity"]), v["score"] or "-", (v["product"] or ""),
          (v["version"] or ""), "%d%%" % v["confidence"]]
         for v in dati.get("confermati") or []],
        larghezze=[1.2, 1.6, .8, 1.5, .9, .6, 1.4, .9, .6],
        allineamento=["l", "l", "l", "l", "l", "r", "l", "l", "r"],
        nota_vuota="Nessuna vulnerabilita' confermata: nessun servizio con versione"
                   " rilevata rientra nell'applicabilita' dichiarata dalla NVD."
                   " Vedere la sezione sulla qualita' del dato.")
    if dati.get("confermati_totale", 0) > len(dati.get("confermati") or []):
        foglio.paragrafo(
            "Elencate le prime %d di %d: l'elenco completo e' nella console, alla"
            " voce Threat Intelligence."
            % (len(dati["confermati"]), dati["confermati_totale"]), INCHIOSTRO_3)

    # --- 4. Da verificare -------------------------------------------------- #
    foglio.titolo_sezione(
        "Da verificare: prodotti senza versione",
        "%d riscontri" % dati.get("da_verificare_totale", 0))
    foglio.paragrafo(
        "Non sono vulnerabilita' accertate. Dicono dove il rilevamento della"
        " versione manca e per quali prodotti il catalogo contiene vulnerabilita'"
        " note: sono la lista di lavoro per migliorare il dato, non per aprire"
        " interventi.", INCHIOSTRO_2)
    foglio.tabella(
        ["nodo", "porta", "riscontro", "conf."],
        [[v["ip"], "%s/%s" % (v["protocol"] or "-", v["port"] or "-"),
          (v["title"] or ""), "%d%%" % v["confidence"]]
         for v in dati.get("da_verificare") or []],
        larghezze=[1.2, .8, 3.4, .6], allineamento=["l", "l", "l", "r"], colonne=2,
        nota_vuota="Nessun prodotto riconosciuto in attesa di versione.")

    # --- 5. Esposizioni ---------------------------------------------------- #
    foglio.titolo_sezione(
        "Esposizioni di servizio",
        "%d riscontri, raggruppati per tipo" % dati.get("esposizioni_totale", 0))
    foglio.paragrafo(
        "Raggruppate per tipo e non per dispositivo: il fatto da riportare e' che"
        " un servizio rischioso e' raggiungibile su N dispositivi, non N volte la"
        " stessa frase. Su un inventario reale questa e' la classe che porta piu'"
        " informazione, perche' non dipende dalle versioni.")
    foglio.tabella(
        ["esposizione", "gravita'", "nodi", "porte", "ATT&CK"],
        [[g["titolo"], _gravita(g["severity"]), g["quanti"],
          g["porte"], g["tecnica"] or "-"]
         for g in dati.get("esposizioni") or []],
        larghezze=[3.4, .9, .6, 1.2, .9],
        allineamento=["l", "l", "r", "l", "l"],
        nota_vuota="Nessuna esposizione di servizio rilevata.")

    copertura_snmp = dati.get("copertura_snmp") or {}
    if copertura_snmp.get("letti"):
        foglio.paragrafo(
            "Sull'esposizione SNMP la prova e' gia' stata raccolta: %d apparati hanno"
            " risposto alla community di fabbrica e hanno dichiarato %d interfacce,"
            " %d processi e %d voci di software installato. Cio' che un'esposizione"
            " informativa consegna non e' un'ipotesi: e' scritto nell'inventario."
            % (copertura_snmp.get("letti", 0), copertura_snmp.get("interfacce", 0),
               copertura_snmp.get("processi", 0), copertura_snmp.get("software", 0)),
            INCHIOSTRO_2)

    # Questi non sono righe di tabella: ogni gruppo porta tre paragrafi di prosa e
    # l'elenco degli indirizzi. Il limite resta -- ma va DICHIARATO, altrimenti chi
    # legge crede di avere davanti tutto.
    gruppi = dati.get("esposizioni") or []
    if len(gruppi) > 8:
        foglio.paragrafo(
            "Sono descritti per esteso gli %d gruppi di esposizione piu' gravi su %d;"
            " i restanti %d compaiono nelle tabelle delle sezioni successive e"
            " nell'inventario della console."
            % (8, len(gruppi), len(gruppi) - 8), INCHIOSTRO_3)
    for gruppo in gruppi[:8]:
        foglio.paragrafo("%s - %s (%d dispositivi)"
                         % (gruppo["titolo"], _gravita(gruppo["severity"]),
                            gruppo["quanti"]),
                         _colore_gravita(gruppo["severity"]))
        if gruppo.get("motivo"):
            foglio.paragrafo("Perche' conta: %s" % gruppo["motivo"], INCHIOSTRO_2)
        if gruppo.get("raccomandazione"):
            foglio.paragrafo("Che fare: %s" % gruppo["raccomandazione"], INCHIOSTRO_2)
        indirizzi = ", ".join(n["ip"] for n in gruppo["nodi"][:24] if n["ip"])
        if len(gruppo["nodi"]) > 24:
            indirizzi += " e altri %d" % (len(gruppo["nodi"]) - 24)
        foglio.paragrafo("Dispositivi: %s" % indirizzi, INCHIOSTRO_3, mono=True)

    # --- 6. Da dove cominciare --------------------------------------------- #
    foglio.titolo_sezione(
        "Dispositivi da cui cominciare",
        "%d dispositivi con almeno un riscontro aperto" % dati.get("nodi_totale", 0))
    foglio.paragrafo(
        "Lo stesso apparato compare in molte righe degli elenchi precedenti: qui"
        " compare una volta sola, con quanto ha da sistemare. E' l'ordine con cui"
        " conviene lavorare.")
    foglio.tabella(
        ["nodo", "dispositivo", "conf.", "verif.", "espos.", "KEV", "peggiore"],
        [[n["ip"], (n["device"] or ""), n["confermati"], n["da_verificare"],
          n["esposizioni"], n["kev"] or "-", _gravita(n["peggiore"])]
         for n in dati.get("nodi") or []],
        larghezze=[1.2, 1.8, .7, .7, .7, .6, 1.1],
        allineamento=["l", "l", "r", "r", "r", "r", "l"], colonne=2,
        nota_vuota="Nessun dispositivo con riscontri aperti.")

    # --- 7. Che cosa e' cambiato ------------------------------------------- #
    foglio.titolo_sezione("Che cosa e' cambiato nel periodo", dati["intervallo"])
    comparsi = dati.get("comparsi") or []
    chiusi = dati.get("chiusi") or []
    foglio.paragrafo(
        "Comparsi nell'intervallo: %d riscontri. Non piu' aperti: %d. La variazione"
        " e' il segnale: un'esposizione presente da sempre e' architettura nota, la"
        " stessa esposizione comparsa ieri e' un evento."
        % (len(comparsi), len(chiusi)))
    foglio.tabella(
        ["comparso il", "nodo", "classe", "gravita'", "riscontro"],
        [[foglio.istante(v.get("first_seen_at"), ""), v["ip"],
          {"confirmed": "confermata", "potential": "da verificare",
           "exposure": "esposizione"}.get(v["kind"], v["kind"]),
          _gravita(v["severity"]), (v["title"] or "")]
         for v in comparsi],
        larghezze=[1.2, 1.2, 1.2, .9, 3.5],
        nota_vuota="Nessun riscontro nuovo nell'intervallo.")
    foglio.tabella(
        ["chiuso il", "nodo", "esito", "riscontro"],
        [[foglio.istante(v.get("decided_at"), ""), v["ip"],
          {"fixed": "non piu' presente", "accepted": "rischio accettato",
           "false_positive": "falso positivo"}.get(v["status"], v["status"]),
          (v["title"] or "")]
         for v in chiusi],
        larghezze=[1.2, 1.2, 1.4, 4.2],
        nota_vuota="Nessun riscontro chiuso nell'intervallo.")

    # --- 8. Decisioni ------------------------------------------------------ #
    foglio.titolo_sezione(
        "Decisioni registrate",
        "%d accettati, %d chiusi" % (riepilogo.get("accettati", 0),
                                     riepilogo.get("chiusi", 0)))
    foglio.paragrafo(
        "Un rischio accettato senza motivazione tracciata, fra sei mesi, e' un"
        " rischio dimenticato: la motivazione e' obbligatoria e resta qui. Le"
        " decisioni non vengono sovrascritte dalle rivalutazioni successive.")
    foglio.tabella(
        ["data", "nodo", "esito", "riscontro", "motivazione", "deciso da"],
        [[foglio.istante(v.get("decided_at"), ""), v["ip"],
          "accettato" if v["status"] == "accepted" else "falso positivo",
          (v["title"] or ""), (v.get("decision_note") or ""),
          (v.get("deciso_da") or "")]
         for v in dati.get("decisioni") or []],
        larghezze=[1.1, 1.1, 1.0, 2.2, 2.6, 1.4],
        nota_vuota="Nessuna decisione registrata: tutti i riscontri sono aperti.")

    # --- 9. Stato del catalogo --------------------------------------------- #
    foglio.titolo_sezione(
        "Stato del catalogo",
        "la correlazione lavora sul catalogo locale, non su internet")
    foglio.tabella(
        ["contenuto", "voci"],
        [["Vulnerabilita' (CVE)", catalogo.get("cve", 0)],
         ["Regole di applicabilita' (CPE)", catalogo.get("cpe", 0)],
         ["Sfruttate attivamente (CISA KEV)", catalogo.get("cve_kev", 0)],
         ["Classi di debolezza (CWE)", catalogo.get("cwe", 0)],
         ["Tecniche MITRE ATT&CK", catalogo.get("tecniche", 0)]],
        larghezze=[3.0, 1.0], allineamento=["l", "r"])
    if not catalogo.get("cve"):
        foglio.paragrafo(
            "Il catalogo delle vulnerabilita' e' vuoto: nessuna conferma e' possibile"
            " e l'assenza di riscontri confermati non dice niente sulla rete."
            " Aggiornare il catalogo dalla voce Threat Intelligence della console.",
            CRITICO)
    foglio.tabella(
        ["aggiornamento", "sorgente", "esito", "voci", "concluso il"],
        [[foglio.istante(s.get("started_at"), ""), s.get("source") or "",
          s.get("status") or "", s.get("items") or 0,
          foglio.istante(s.get("finished_at"), "")]
         for s in dati.get("aggiornamenti") or []],
        larghezze=[1.4, 1.4, 1.0, .7, 1.4],
        allineamento=["l", "l", "l", "r", "l"],
        nota_vuota="Il catalogo non e' mai stato aggiornato su questo server.")

    foglio.titolo_sezione("Riferimenti normativi")
    foglio.elenco([
        "Direttiva (UE) 2022/2555 (NIS2), art. 21: gestione delle vulnerabilita' e"
        " del rischio come misura minima; il documento e' la traccia della"
        " valutazione periodica.",
        "Reg. (UE) 2024/2847 (Cyber Resilience Act): gestione delle vulnerabilita'"
        " per l'intero ciclo di vita del prodotto.",
        "Reg. (UE) 2016/679 (GDPR), art. 32: adeguatezza delle misure tecniche"
        " rispetto al rischio; le esposizioni di servizio ne sono una misura.",
        "OWASP ASVS e OWASP Top 10 come baseline tecnica di verifica.",
        "Fonti del catalogo: NIST NVD (CVE, CPE, CVSS), CISA KEV, MITRE CWE,"
        " MITRE ATT&CK. La correlazione e' locale e non trasmette dati del cliente.",
    ])

    foglio.salva()
    return str(percorso)


# --------------------------------------------------------------------------- #
# R9 - Segmentazione e zone di rete
# --------------------------------------------------------------------------- #
SEZIONI_SEGMENTAZIONE = [
    "Che cosa dice questo documento",
    "Le zone dichiarate",
    "Violazioni del contesto",
    "Esposizioni attese, per zona",
    "Reti con zona dichiarata",
    "Reti senza zona dichiarata",
    "Catalogo delle zone",
    "Riferimenti normativi",
]


def segmentation_report(percorso, dati: dict) -> str:
    """La segmentazione dichiarata contro quella osservata."""
    postura = dati["postura"]
    # Il nome della zona, non la sua chiave: "psn-prod" e' un identificativo, "Psn-Prod"
    # e' cio' che l'operatore ha scritto.
    zone_per_chiave = {v.get("chiave"): v for v in (dati.get("catalogo") or [])}
    foglio = Foglio(
        percorso, kind="segmentation", titolo="Segmentazione e zone di rete",
        sottotitolo="La segmentazione dichiarata regge?",
        tenant=dati["tenant"]["nome"], intervallo=dati["intervallo"],
        fuso=dati["tenant"].get("fuso"),
        generato=dati["generato_utc"],
        scopo=[
            "Confronto fra cio' che ogni rete di %s dichiara di essere e cio' che ci"
            " si trova dentro." % dati["tenant"]["nome"],
            "Lo stesso servizio significa cose opposte a seconda di dove si trova:"
            " questo documento lo mette per iscritto, zona per zona.",
        ],
        sezioni=SEZIONI_SEGMENTAZIONE, riferimenti=riferimenti_comuni(dati),
        nota=NOTA_PROVENIENZA)

    foglio.riquadri([
        (postura["violazioni"], "violazioni del contesto",
         CRITICO if postura["violazioni"] else OK),
        (postura["attese"], "esposizioni attese", OK if postura["attese"] else INCHIOSTRO_3),
        (postura["senza_zona"], "reti senza zona",
         ATTENZIONE if postura["senza_zona"] else OK),
        (len([z for z in postura["zone"] if z["chiave"]]), "zone in uso", INCHIOSTRO_2),
    ])

    foglio.titolo_sezione("Che cosa dice questo documento")
    foglio.paragrafo(
        "SSH su una rete di utenza e' una via d'ingresso che nessuno ha chiesto; SSH"
        " in un datacenter e' il modo in cui i sistemi si amministrano, dietro un"
        " perimetro progettato. Segnalarli allo stesso modo costringe a ignorare"
        " centinaia di righe, e chi impara a ignorare un elenco poi ignora anche la"
        " riga che contava.")
    foglio.elenco([
        "ATTESA - il servizio appartiene a quel contesto: il riscontro resta annotato"
        " con la sua motivazione e non conta fra quelli aperti.",
        "VIOLAZIONE - in quel contesto quel servizio non dovrebbe esserci: la gravita'"
        " sale, perche' e' un fatto piu' grave dello stesso servizio altrove.",
        "NON DICHIARATA - la rete non dice che cosa e': vale come rete di utenza, che"
        " e' il giudizio piu' severo. Il silenzio non vale come giustificazione.",
    ])
    foglio.paragrafo(
        "Nulla viene cancellato: se la zona di una rete cambia, la rivalutazione"
        " successiva riapre da se' i riscontri che non sono piu' attesi.", INCHIOSTRO_2)

    foglio.titolo_sezione("Le zone dichiarate", "come si comporta ciascun contesto")
    foglio.tabella(
        ["zona", "subnet", "dispositivi", "esposizioni aperte", "attese", "violazioni"],
        [[z["nome"], z["subnet"], z["nodi"], z["aperte"], z["attese"] or "-",
          ("!!%d" % z["violazioni"]) if z["violazioni"] else "-"]
         for z in postura["zone"]],
        larghezze=[2.0, .8, 1.0, 1.4, .9, 1.0],
        allineamento=["l", "r", "r", "r", "r", "r"],
        nota_vuota="Nessuna subnet in inventario.")

    foglio.titolo_sezione("Violazioni del contesto",
                          "%d in totale" % len(dati["violazioni"]))
    foglio.paragrafo(
        "Servizi raggiungibili dove la zona dichiarata non li prevede. Sono le righe"
        " da guardare per prime: non perche' il servizio sia peggiore di altrove, ma"
        " perche' qualcuno ha dichiarato che li' non dovrebbe esserci.")
    foglio.tabella(
        ["nodo", "zona", "subnet", "porta", "esposizione", "gravita'"],
        [[v["ip"], v["zone"] or "non dichiarata", v["cidr"],
          "%s/%s" % (v["protocol"] or "-", v["port"] or "-"),
          (v["title"] or ""), _gravita(v["severity"])]
         for v in dati["violazioni"]],
        larghezze=[1.2, 1.3, 1.4, .8, 3.0, .9], colonne=2,
        nota_vuota="Nessuna violazione: cio' che e' raggiungibile appartiene al"
                   " contesto in cui si trova.")

    foglio.titolo_sezione("Esposizioni attese, per zona")
    foglio.paragrafo(
        "Restano annotate perche' la storia di cio' che era raggiungibile e'"
        " informazione: se la zona cambia, tornano aperte.", INCHIOSTRO_2)
    foglio.tabella(
        ["zona", "esposizione", "riscontri", "dispositivi"],
        [[a["zone"] or "non dichiarata", (a["title"] or ""), a["quante"], a["nodi"]]
         for a in dati["attese"]],
        larghezze=[1.4, 3.6, 1.0, 1.2], allineamento=["l", "l", "r", "r"], colonne=2,
        nota_vuota="Nessuna esposizione attesa: nessuna zona dichiarata le prevede.")

    con_zona = dati.get("con_zona") or []
    foglio.titolo_sezione("Reti con zona dichiarata", "%d subnet" % len(con_zona))
    foglio.paragrafo(
        "Il perimetro che dichiara che cosa e'. Per ciascuna rete: la zona, quanti"
        " dispositivi ci sono dentro, quante esposizioni sono ANNOTATE COME ATTESE in"
        " quel contesto e quanti riscontri restano aperti. Una zona dichiarata non"
        " chiude i riscontri: cambia il giudizio su quelli che appartengono a quel"
        " contesto, e lascia aperti gli altri.", INCHIOSTRO_2)
    foglio.tabella(
        ["subnet", "zona", "etichetta", "indirizzi", "dispositivi", "attivi",
         "attese", "riscontri aperti"],
        [[v["cidr"],
          (zone_per_chiave.get(v["zone"], {}).get("nome") if zone_per_chiave
           else v["zone"]) or v["zone"],
          v["label"], v["host_count"], v["nodi"], v["attivi"], v["attese"],
          v["riscontri"]]
         for v in con_zona],
        larghezze=[1.4, 1.6, 2.0, .9, 1.0, .9, .9, 1.2],
        allineamento=["l", "l", "l", "r", "r", "r", "r", "r"],
        nota_vuota="Nessuna rete dichiara la propria zona: la segmentazione non e'"
                   " ancora descritta, e ogni servizio viene giudicato con il criterio"
                   " piu' severo.")

    foglio.titolo_sezione("Reti senza zona dichiarata",
                          "%d subnet" % len(dati["senza_zona"]))
    foglio.tabella(
        ["subnet", "etichetta", "indirizzi", "dispositivi", "riscontri aperti"],
        [[s["cidr"], (s["label"] or ""), s["host_count"], s["nodi"], s["riscontri"]]
         for s in dati["senza_zona"]],
        larghezze=[1.4, 2.0, 1.0, 1.0, 1.2],
        allineamento=["l", "l", "r", "r", "r"], colonne=2,
        nota_vuota="Tutte le subnet dichiarano la propria zona.")

    foglio.titolo_sezione("Catalogo delle zone")
    for voce in dati["catalogo"]:
        foglio.paragrafo("%s" % voce["nome"], CRITICO if voce["chiave"] == "dmz"
                         else INCHIOSTRO)
        foglio.paragrafo(voce["descrizione"], INCHIOSTRO_2)
        if voce["attese"]:
            foglio.paragrafo("Atteso qui: " + "; ".join(voce["attese"]), INCHIOSTRO_3)
        if voce["violazioni"]:
            foglio.paragrafo("Vietato qui: " + "; ".join(voce["violazioni"]),
                             INCHIOSTRO_3)

    foglio.titolo_sezione("Riferimenti normativi")
    foglio.elenco([
        "Direttiva (UE) 2022/2555 (NIS2), art. 21: misure di gestione del rischio,"
        " fra cui la sicurezza della rete e la segmentazione.",
        "Reg. (UE) 2024/2847 (CRA): riduzione della superficie di attacco per"
        " l'intero ciclo di vita.",
        "OWASP ASVS V1: architettura e segmentazione come requisito verificabile.",
        "La classificazione delle zone e le famiglie attese o vietate in ciascuna"
        " sono di questo prodotto, dichiarate e modificabili: non sono uno standard.",
    ])
    foglio.salva()
    return str(percorso)


# --------------------------------------------------------------------------- #
# R10 - Igiene dell'inventario
# --------------------------------------------------------------------------- #
SEZIONI_IGIENE = [
    "Perche' questo documento esiste",
    "Qualita' del dato raccolto",
    "Perimetro dichiarato",
    "Dispositivi da identificare",
    "Chi non risponde e chi non e' stato interrogato",
    "Sorveglianza e controlli",
    "Che cosa fare, in ordine",
]


def hygiene_report(percorso, dati: dict) -> str:
    """Che cosa manca perche' i numeri delle altre pagine siano credibili."""
    qualita = dati["qualita"]
    perimetro = dati["perimetro"]
    igiene = dati["igiene"]
    inventario = dati["inventario"]

    foglio = Foglio(
        percorso, kind="hygiene", titolo="Igiene dell'inventario",
        sottotitolo="Che cosa manca per fidarsi dei numeri",
        tenant=dati["tenant"]["nome"], intervallo=dati["intervallo"],
        fuso=dati["tenant"].get("fuso"),
        generato=dati["generato_utc"],
        scopo=[
            "Stato di completezza e di affidabilita' dei dati raccolti su %s."
            % dati["tenant"]["nome"],
            "Ogni inventario ha un punto cieco: cio' che non ha guardato, cio' che non"
            " ha saputo riconoscere, cio' che ha smesso di aggiornare. Metterlo per"
            " iscritto e' l'unico modo perche' i numeri restino credibili.",
        ],
        sezioni=SEZIONI_IGIENE, riferimenti=riferimenti_comuni(dati),
        nota=NOTA_PROVENIENZA)

    foglio.riquadri([
        (inventario.get("nodi", 0), "dispositivi in inventario", INCHIOSTRO_2),
        (inventario.get("uncertain", 0), "da identificare",
         ATTENZIONE if inventario.get("uncertain") else OK),
        (len(dati["silenzi"]), "in silenzio",
         CRITICO if dati["silenzi"] else OK),
        (len(dati["non_interrogati"]), "non interrogati",
         ATTENZIONE if dati["non_interrogati"] else OK),
        (perimetro["senza_zona"], "subnet senza zona",
         ATTENZIONE if perimetro["senza_zona"] else OK),
    ])

    foglio.titolo_sezione("Perche' questo documento esiste")
    foglio.paragrafo(
        "Un cruscotto che dice \"nessuna vulnerabilita'\" puo' significare due cose"
        " opposte: che la rete e' a posto, o che non si e' guardato abbastanza. Questo"
        " documento distingue le due, e per ciascuna lacuna dice che cosa la"
        " ridurrebbe.")

    foglio.titolo_sezione("Qualita' del dato raccolto",
                          "senza versione una vulnerabilita' non e' attribuibile")
    foglio.tabella(
        ["misura", "valore", "che cosa comporta"],
        [["Porte aperte osservate", qualita["porte_aperte"],
          "l'insieme su cui lavorano correlazione e report"],
         ["Con prodotto riconosciuto", qualita["con_prodotto"],
          "%s%% del totale" % (qualita["quota_prodotto"]
                               if qualita["quota_prodotto"] is not None else "-")],
         ["Con versione rilevata", qualita["con_versione"],
          "%s%% del totale: sono le sole su cui una CVE si conferma"
          % (qualita["quota_versione"]
             if qualita["quota_versione"] is not None else "-")],
         ["Apparati letti via SNMP", dati["copertura_snmp"]["letti"],
          "su %d che espongono la porta" % dati["copertura_snmp"]["esposti"]]],
        larghezze=[2.2, 1.0, 3.4], allineamento=["l", "r", "l"])
    if (qualita["quota_versione"] or 0) < 5:
        foglio.paragrafo(
            "Meno del 5% delle porte annuncia una versione: con questo dato l'elenco"
            " delle vulnerabilita' confermate resta quasi vuoto, ed e' la risposta"
            " vera. Per averne di piu' serve un profilo di sforzo piu' alto sulle"
            " sonde, che aumenta l'interrogazione dei servizi.", ATTENZIONE)

    foglio.titolo_sezione("Perimetro dichiarato")
    foglio.tabella(
        ["misura", "valore"],
        [["Subnet dichiarate", perimetro["subnet"]],
         ["Senza zona di rete", perimetro["senza_zona"]],
         ["Sospese", perimetro["sospese"]],
         ["Senza alcun dispositivo trovato", len(perimetro["vuote"])]],
        larghezze=[3.0, 1.0], allineamento=["l", "r"])
    foglio.tabella(
        ["subnet", "etichetta", "indirizzi", "stato"],
        [[v["cidr"], (v["label"] or ""), v["host_count"],
          "attiva" if v["is_enabled"] else "sospesa"] for v in perimetro["vuote"]],
        larghezze=[1.4, 2.4, 1.0, 1.0], colonne=2,
        nota_vuota="Ogni subnet dichiarata ha almeno un dispositivo.")

    foglio.titolo_sezione("Dispositivi da identificare",
                          "%d in elenco" % len(dati["non_identificati"]))
    foglio.tabella(
        ["indirizzo", "nome host", "sistema operativo", "conf.", "porte"],
        [[n["ip"], (n.get("hostname") or ""), (n.get("os_name") or ""),
          n.get("device_confidence") or 0, n.get("porte") or n.get("open_ports") or 0]
         for n in dati["non_identificati"]],
        larghezze=[1.2, 1.6, 2.0, .7, .7],
        allineamento=["l", "l", "l", "r", "r"], colonne=2,
        nota_vuota="Ogni dispositivo ha un tipo attribuito con confidenza sufficiente.")

    foglio.titolo_sezione("Chi non risponde e chi non e' stato interrogato")
    foglio.paragrafo(
        "Sono due fatti diversi e vanno letti diversamente: il primo e' un problema"
        " del dispositivo, il secondo e' un problema di copertura della sonda.")
    foglio.tabella(
        ["indirizzo", "dispositivo", "ultima verifica", "ultimo contatto"],
        [[n["ip"], (n["device_label"] or ""),
          foglio.istante(n.get("ultima_verifica"), "mai"), foglio.istante(n["last_seen_at"], "")]
         for n in dati["silenzi"]],
        larghezze=[1.2, 2.2, 1.4, 1.4], colonne=2,
        nota_vuota="Nessun dispositivo interrogato ha smesso di rispondere.")
    foglio.paragrafo("Non interrogati nelle ultime 24 ore: %d dispositivi."
                     % len(dati["non_interrogati"]), INCHIOSTRO_2)

    foglio.titolo_sezione("Sorveglianza e controlli")
    foglio.tabella(
        ["che cosa", "quanti"],
        [["Controlli sospesi", len(igiene.get("controlli_sospesi") or [])],
         ["Bersagli senza alcun controllo", len(igiene.get("bersagli_senza_controlli") or [])],
         ["Porte marcate come iniettate dalla rete", igiene.get("porte_sospette", 0)],
         ["Conservazione dichiarata (giorni)", igiene.get("retention_giorni", 0)]],
        larghezze=[3.4, 1.0], allineamento=["l", "r"])

    foglio.titolo_sezione("Che cosa fare, in ordine")
    azioni = []
    if perimetro["senza_zona"]:
        azioni.append("Dichiarare la zona delle %d subnet che non ce l'hanno: e' la"
                      " modifica che riduce di piu' il rumore, perche' cambia il"
                      " giudizio su centinaia di esposizioni."
                      % perimetro["senza_zona"])
    if (qualita["quota_versione"] or 0) < 20:
        azioni.append("Alzare il profilo di sforzo delle sonde dove la rete lo"
                      " consente: aumenta le versioni rilevate, e con quelle le"
                      " vulnerabilita' che si possono confermare.")
    if dati["non_interrogati"]:
        azioni.append("Verificare la cadenza del monitoraggio: %d dispositivi non sono"
                      " stati interrogati nelle ultime 24 ore."
                      % len(dati["non_interrogati"]))
    if inventario.get("uncertain"):
        azioni.append("Approfondire i %d dispositivi senza tipo attribuito: la fase di"
                      " approfondimento si puo' chiedere anche dalla pagina del nodo."
                      % inventario["uncertain"])
    if igiene.get("bersagli_senza_controlli"):
        azioni.append("Definire almeno un controllo per i %d bersagli che non ne hanno."
                      % len(igiene["bersagli_senza_controlli"]))
    if not azioni:
        azioni.append("Nessuna lacuna rilevata: i numeri delle altre pagine si"
                      " possono leggere per quello che dicono.")
    foglio.elenco(azioni)
    foglio.salva()
    return str(percorso)


# --------------------------------------------------------------------------- #
# R11 - Scheda di un apparato
# --------------------------------------------------------------------------- #
SEZIONI_APPARATO = [
    "Identita'",
    "Interfacce web, dati dichiarati e certificato",
    "Come e' stato riconosciuto",
    "Servizi raggiungibili",
    "Che cosa racconta di se' (SNMP)",
    "Vulnerabilita' ed esposizioni",
    "Sorveglianza",
    "Storia recente",
]


def device_report(percorso, dati: dict) -> str:
    """Tutto cio' che si sa di un singolo apparato, in un foglio."""
    nodo = dati["nodo"]
    verdetto = dati["verdetto"] or {}
    aperte = [p for p in dati["porte"] if p["state"] == "open"
              and not int(p["is_suspect"] or 0)]

    foglio = Foglio(
        percorso, kind="device", titolo="Scheda dell'apparato %s" % nodo["ip"],
        sottotitolo=nodo.get("hostname") or nodo.get("device_label")
                    or "dispositivo non identificato",
        tenant=dati["tenant"]["nome"], intervallo=dati["intervallo"],
        fuso=dati["tenant"].get("fuso"),
        generato=dati["generato_utc"],
        scopo=[
            "Tutto cio' che %s sa dell'apparato %s: identita', servizi raggiungibili,"
            " cio' che dichiara di se', riscontri di sicurezza e storia recente."
            % ("snap", nodo["ip"]),
            "E' il foglio da allegare a una richiesta di intervento o a una"
            " segnalazione: chi lo riceve non ha accesso alla console.",
        ],
        sezioni=SEZIONI_APPARATO,
        riferimenti=riferimenti_comuni(dati, extra=[
            ("Apparato", nodo["ip"]),
            ("Subnet", nodo.get("subnet_cidr") or "fuori perimetro"),
        ]),
        nota=NOTA_PROVENIENZA)

    foglio.riquadri([
        (len(aperte), "servizi raggiungibili", ATTENZIONE if aperte else OK),
        (len([r for r in dati["riscontri"] if r["status"] == "open"]),
         "riscontri aperti",
         CRITICO if [r for r in dati["riscontri"] if r["status"] == "open"] else OK),
        (nodo.get("device_confidence") or 0,
         "tipo dichiarato" if (nodo.get("device_type_source") or "auto") == "manual"
         else "confidenza del tipo",
         OK if (nodo.get("device_confidence") or 0) >= 60 else ATTENZIONE),
        (len(dati["controlli"]), "controlli attivi",
         OK if dati["controlli"] else INCHIOSTRO_3),
    ])

    # Da dove viene il MAC: un indirizzo osservato dalla sonda e uno riferito da un
    # apparato non hanno la stessa affidabilita', e chi legge la scheda deve saperlo
    # senza doverlo chiedere.
    fonte_mac = nodo.get("mac_source") or ""
    if not nodo.get("mac"):
        mac_leggibile = "non rilevato"
    elif fonte_mac == "arp":
        mac_leggibile = "%s (osservato dalla sonda sul proprio segmento)" % nodo["mac"]
    elif fonte_mac.startswith("snmp:"):
        mac_leggibile = ("%s (riferito dalla tabella ARP di %s)"
                         % (nodo["mac"], fonte_mac[5:]))
    else:
        mac_leggibile = nodo["mac"]
    punto_di_attacco = (
        "%s su %s" % (nodo["switch_port"],
                      nodo.get("switch_device") or "un apparato di rete")
        if nodo.get("switch_port")
        else "non noto (serve la tabella di inoltro di uno switch interrogabile)")

    foglio.titolo_sezione("Identita'")
    foglio.tabella(
        ["campo", "valore"],
        [["Indirizzo", nodo["ip"]],
         ["Nome host", nodo.get("hostname") or "non rilevato"],
         ["Indirizzo fisico (MAC)", mac_leggibile],
         ["Punto di attacco", punto_di_attacco],
         ["Costruttore dedotto dal MAC", nodo.get("mac_vendor")
          or "non disponibile (prefisso non in catalogo)"],
         ["Produttore dichiarato dall'apparato",
          next((v.get("brand") for v in (dati.get("web") or []) if v.get("brand")),
               "non dichiarato")],
         ["Modello dichiarato dall'apparato",
          next((v.get("model") for v in (dati.get("web") or []) if v.get("model")),
               "non dichiarato")],
         ["Tipo attribuito",
          ("%s (dichiarato da %s il %s)"
           % (nodo.get("device_label") or "non identificato",
              nodo.get("device_type_by") or "un operatore",
              foglio.istante(nodo.get("device_type_at"), "")))
          if (nodo.get("device_type_source") or "auto") == "manual"
          else "%s (%s%%)" % (nodo.get("device_label") or "non identificato",
                              nodo.get("device_confidence") or 0)],
         ["Sistema operativo", nodo.get("os_name") or "non rilevato"],
         ["Subnet", "%s %s" % (nodo.get("subnet_cidr") or "fuori perimetro",
                               nodo.get("subnet_label") or "")],
         ["Zona di rete", nodo.get("zone") or "non dichiarata"],
         ["Sonda che lo osserva", nodo.get("probe_name") or "-"],
         ["Stato", nodo.get("status") or "-"],
         ["Visto la prima volta", foglio.istante(nodo.get("first_seen_at"), "")],
         ["Ultimo contatto", foglio.istante(nodo.get("last_seen_at"), "")]]
        # La ragione della dichiarazione vale piu' del verdetto che ha scavalcato: e'
        # la sola cosa che spiega a chi legge perche' il tipo non viene da una misura.
        + ([["Motivo della dichiarazione", nodo.get("device_type_reason")]]
           if (nodo.get("device_type_source") or "auto") == "manual"
           and nodo.get("device_type_reason") else []),
        larghezze=[2.0, 4.0])

    # --- Tutto cio' che si e' letto dalle interfacce web dell'apparato ------- #
    # Viene prima del riconoscimento: una dichiarazione dell'apparato vale piu' di una
    # deduzione del prodotto, ed e' la parte che un tecnico legge per prima.
    web = dati.get("web") or []
    if web:
        foglio.titolo_sezione(
            "Interfacce web raggiungibili",
            "%d interfaccia/e" % len(web))
        # Quali interfacce rispondono, come si presentano e se chiedono le credenziali.
        foglio.tabella(
            ["dove", "stato", "titolo", "server", "accesso", "TLS"],
            [["%s/%s" % (v.get("scheme") or "http", v.get("port")),
              str(v.get("status_code") or "-"),
              (v.get("title") or ""),
              (v.get("server_header") or ""),
              ("chiede le credenziali" if (v.get("login_form")
                                           or v.get("facts_locked")) else "aperta"),
              (v.get("tls_version") or ("si" if v.get("scheme") == "https" else "-"))]
             for v in web],
            larghezze=[1.0, .7, 1.9, 1.7, 1.5, 1.0],
            nota_vuota="Nessuna interfaccia web raggiunta.")

    # Cio' che l'apparato dichiara di se' nelle sue pagine: i campi con un significato
    # noto (marca, modello, seriale...) e i fatti aggiuntivi (interno e carichi di un
    # telefono IP, misure di uno UPS) che non hanno una colonna propria.
    letture_web = [v for v in web
                   if any(v.get(c) for c in ("device_name", "model", "location",
                                             "host_name", "serial", "firmware",
                                             "contact", "brand"))
                   or v.get("extra")]
    if letture_web:
        foglio.titolo_sezione(
            "Dichiarato dall'apparato",
            "letto dalle sue pagine di gestione")
        foglio.paragrafo(
            "La sonda ha aperto l'interfaccia di gestione dell'apparato e ne ha letto le"
            " etichette, seguendo il percorso che l'apparato stesso indica. Il contenuto"
            " delle pagine non viene conservato: restano i dati qui sotto. Sono"
            " dichiarazioni dell'apparato, non deduzioni del prodotto.", INCHIOSTRO_2)
        righe = []
        for voce in letture_web:
            dove = "%s/%s" % (voce.get("scheme") or "http", voce.get("port"))
            for etichetta, campo in (("Nome dichiarato", "device_name"),
                                     ("Marca", "brand"),
                                     ("Modello", "model"),
                                     ("Posizione fisica", "location"),
                                     ("Nome host dichiarato", "host_name"),
                                     ("Numero di serie", "serial"),
                                     ("Firmware", "firmware"),
                                     ("Contatto", "contact")):
                if voce.get(campo):
                    righe.append([dove, etichetta, voce[campo]])
            # I fatti aggiuntivi (etichetta, valore) arrivano gia' pronti dal dato.
            for fatto in voce.get("extra") or []:
                righe.append([dove, fatto["etichetta"], fatto["valore"]])
            if voce.get("pages_read"):
                righe.append([dove, "Pagine aperte per arrivarci",
                              str(voce["pages_read"])])
        foglio.tabella(["dove", "campo", "valore dichiarato"], righe,
                       larghezze=[1.0, 2.0, 4.0])

    # La diagnosi ricavata dai registri dell'apparato (oggi lo UPS MGE/Eaton) non e' una
    # riga fra le altre: e' un esito, e va in evidenza in un riquadro colorato.
    for voce in web:
        diagnosi = voce.get("diagnosi") or {}
        if not diagnosi:
            continue
        dove = "%s/%s" % (voce.get("scheme") or "http", voce.get("port"))
        if diagnosi.get("ok"):
            foglio.box(
                [{"testo": "Diagnosi dai registri (%s): nessun problema rilevato."
                  % dove, "grassetto": True, "colore": OK}], colore_barra=OK)
        else:
            elementi = [{"testo": "Diagnosi dai registri (%s): attenzione" % dove,
                         "grassetto": True, "colore": CRITICO}]
            for problema in diagnosi.get("problemi") or []:
                elementi.append({"testo": "- %s" % problema, "colore": INCHIOSTRO,
                                 "rientro": 8})
            foglio.box(elementi, colore_barra=CRITICO)

    # Il certificato TLS, per intero, dove c'e' HTTPS: soggetto, emittente, validita',
    # chiave, usi, nomi alternativi e impronte. Gli esiti di sicurezza (scaduto,
    # autofirmato) sono detti a parole, non lasciati dedurre da una data.
    interfacce_cert = [v for v in web if (v.get("cert") or {}).get("righe")]
    if interfacce_cert:
        foglio.titolo_sezione("Certificato digitale (TLS)")
    for voce in interfacce_cert:
        cert = voce["cert"]
        dove = "%s/%s" % (voce.get("scheme") or "https", voce.get("port"))
        avvisi = []
        if cert.get("scaduto"):
            avvisi.append("scaduto")
        if cert.get("non_ancora_valido"):
            avvisi.append("non ancora valido")
        if cert.get("autofirmato"):
            avvisi.append("autofirmato")
        grave = cert.get("scaduto") or cert.get("non_ancora_valido")
        foglio.paragrafo(
            "Certificato digitale su %s%s"
            % (dove, (" - %s" % ", ".join(avvisi)) if avvisi else ""),
            CRITICO if grave else INCHIOSTRO)
        foglio.tabella(["campo", "valore"],
                       [[r["etichetta"], r["valore"]] for r in cert["righe"]],
                       larghezze=[2.0, 4.0], nota_vuota="")

    foglio.titolo_sezione("Come e' stato riconosciuto",
                          "catalogo %s" % (verdetto.get("catalog_version") or "-"))
    if verdetto.get("reasons"):
        foglio.tabella(
            ["prova", "peso", "motivo"],
            [[(r.get("chiave") or r.get("key") or ""), r.get("peso") or r.get("weight") or "",
              (r.get("motivo") or r.get("reason") or "")]
             for r in verdetto["reasons"]],
            larghezze=[1.8, .6, 4.0], allineamento=["l", "r", "l"])
    else:
        foglio.paragrafo(
            "Nessuna prova decisiva conservata: il tipo, se attribuito, viene"
            " dall'insieme dei segnali e non da una singola evidenza.", INCHIOSTRO_3)

    foglio.titolo_sezione("Servizi raggiungibili", "%d porte aperte" % len(aperte))
    foglio.tabella(
        ["porta", "servizio", "prodotto", "versione", "vista dal", "ultima verifica"],
        [["%s/%s" % (p["protocol"], p["port"]), (p["service_name"] or ""),
          (p["product"] or ""), (p["version"] or ""),
          foglio.istante(p["first_seen_at"], ""), foglio.istante(p["last_seen_at"], "")]
         for p in aperte],
        larghezze=[.9, 1.4, 1.8, 1.0, 1.3, 1.3],
        nota_vuota="Nessun servizio raggiungibile.")

    sospette = [p for p in dati["porte"] if int(p["is_suspect"] or 0)]
    if sospette:
        foglio.paragrafo(
            "%d porte sono marcate come iniettate dalla rete: risponde un apparato"
            " intermedio, non questo dispositivo, e non contano come prove."
            % len(sospette), INCHIOSTRO_3)

    foglio.titolo_sezione("Che cosa racconta di se' (SNMP)")
    if dati["snmp"]:
        for lettura in dati["snmp"]:
            if lettura["kind"] == "tabella" and lettura["righe"]:
                foglio.paragrafo(lettura["titolo"], INCHIOSTRO)
                foglio.tabella(
                    [c.lower() for c in lettura["colonne"]],
                    [[str(c) for c in riga] for riga in lettura["righe"]],
                    nota_vuota="")
            elif lettura["kind"] == "coppie" and lettura["righe"]:
                foglio.paragrafo(lettura["titolo"], INCHIOSTRO)
                foglio.tabella(["campo", "valore"],
                               [[r[0], str(r[1])] for r in lettura["righe"]],
                               larghezze=[2.0, 4.0], nota_vuota="")
    else:
        foglio.paragrafo(
            "Nessuna lettura SNMP: l'apparato non espone la porta 161, oppure non ha"
            " risposto alla community di fabbrica.", INCHIOSTRO_3)

    foglio.titolo_sezione("Vulnerabilita' ed esposizioni")
    foglio.tabella(
        ["classe", "gravita'", "porta", "riscontro", "stato", "conf."],
        [[r["kind"], _gravita(r["severity"]),
          "%s/%s" % (r["protocol"] or "-", r["port"] or "-"),
          ((r["cve_id"] + " ") if r["cve_id"] else "") + (r["title"] or ""),
          r["status"], "%d%%" % (r["confidence"] or 0)]
         for r in dati["riscontri"]],
        larghezze=[1.0, .9, .8, 3.4, 1.2, .6],
        nota_vuota="Nessun riscontro per questo apparato.")

    foglio.titolo_sezione("Sorveglianza")
    foglio.tabella(
        ["controllo", "genere", "stato", "intervallo"],
        [[c["name"], c["kind"], "attivo" if c["is_enabled"] else "sospeso",
          "%d s" % (c["interval_seconds"] or 0)] for c in dati["controlli"]],
        larghezze=[2.4, 1.2, 1.0, 1.0],
        nota_vuota="Nessun controllo definito su questo apparato.")
    if dati["monitoraggio"]:
        risposte = len([m for m in dati["monitoraggio"] if m["reachable"]])
        foglio.paragrafo(
            "Ultime %d verifiche di raggiungibilita': %d con risposta."
            % (len(dati["monitoraggio"]), risposte), INCHIOSTRO_2)

    foglio.titolo_sezione("Storia recente")
    foglio.tabella(
        ["quando", "che cosa", "soggetto", "prima", "adesso"],
        [[foglio.istante(c["created_at"], ""), change_label(c["kind"]),
          (c["subject"] or ""), (c["before_value"] or ""),
          (c["after_value"] or "")] for c in dati["cambiamenti"]],
        larghezze=[1.3, 1.6, 1.4, 1.4, 1.4],
        nota_vuota="Nessun cambiamento registrato per questo apparato.")
    foglio.salva()
    return str(percorso)


# --------------------------------------------------------------------------- #
# R5 - Fascicolo di conformita'
# --------------------------------------------------------------------------- #
SEZIONI_CONFORMITA = [
    "Che cosa dimostra questo documento",
    "Controlli in vigore",
    "Registro degli incidenti",
    "Comunicazioni inviate",
    "Conservazione dei dati e riferimenti",
    "Rilievi",
    "Perimetro dichiarato",
]


def compliance_report(percorso, dati: dict) -> str:
    foglio = Foglio(
        percorso, kind="compliance", titolo="Fascicolo di conformita'",
        sottotitolo="Prova che i controlli esistono, funzionano e sono tracciati",
        tenant=dati["tenant"]["nome"], intervallo=dati["intervallo"],
        fuso=dati["tenant"].get("fuso"),
        generato=dati["generato_utc"],
        scopo=[
            "Materiale documentale sulla sorveglianza della rete di %s nell'intervallo"
            " %s: controlli in vigore, incidenti con i propri tempi, comunicazioni"
            " inviate, conservazione applicata."
            % (dati["tenant"]["nome"], dati["intervallo"]),
            "Riferimenti: NIS2 (UE) 2022/2555 art. 21, GDPR art. 5 e 32, CRA (UE)"
            " 2024/2847. In chiusura i rilievi che il sistema conosce di se stesso.",
        ],
        sezioni=SEZIONI_CONFORMITA, riferimenti=riferimenti_comuni(dati),
        nota=NOTA_PROVENIENZA)
    conformita = dati["conformita"]
    disponibilita = dati["disponibilita"]

    foglio.riquadri([
        (conformita["controlli_attivi"], "controlli attivi", None),
        (len(conformita["incidenti"]), "incidenti nel periodo", None),
        (_percentuale(disponibilita["percentuale"]), "verifiche riuscite",
         OK if (disponibilita["percentuale"] or 0) >= 99 else ATTENZIONE),
        (dati["audit"]["totale"], "azioni registrate", None),
        (len(conformita["rilievi"]), "rilievi",
         CRITICO if any(r["gravita"] == "critical" for r in conformita["rilievi"])
         else ATTENZIONE if conformita["rilievi"] else OK),
    ])

    foglio.titolo_sezione("Che cosa dimostra questo documento")
    foglio.paragrafo(
        "Che i controlli dichiarati esistono, con quale cadenza e con quali soglie"
        " vengono eseguiti; che gli incidenti sono stati registrati con i tempi di"
        " rilevamento, presa in carico e risoluzione; che le azioni sui sistemi sono"
        " tracciate; e quali rilievi il sistema conosce di se stesso. E' materiale per"
        " NIS2 (gestione del rischio e notifica), GDPR art. 32 (misure tecniche) e CRA.")

    foglio.titolo_sezione("Controlli in vigore")
    foglio.tabella(
        ["bersaglio", "controllo", "genere", "cadenza", "tempo max", "incidente a",
         "operatore a", "recapito", "stato"],
        [[c["address"], (c["name"] or ""), c["kind"],
          "%s s" % c["interval_seconds"], "%s s" % c["timeout_seconds"],
          c["failure_threshold"], c["escalation_threshold"],
          c["escalation_email"] or "email del tenant",
          "attivo" if c["is_enabled"] else "!sospeso"]
         for c in conformita["controlli"]],
        larghezze=[2.0, 2.4, .9, 1.0, 1.0, .9, .9, 2.2, 1.0],
        nota_vuota="Nessun controllo definito: non c'e' sorveglianza da dimostrare.")

    foglio.titolo_sezione("Registro degli incidenti", "con i tempi")
    foglio.tabella(
        ["#", "gravita'", "bersaglio", "aperto", "preso in carico", "operatore attivato",
         "risolto", "esito"],
        [[i["id"], i["severity"], i["address"], foglio.istante(i["opened_at"], ""),
          foglio.istante(i["acknowledged_at"], "-"), foglio.istante(i["escalated_at"], "-"),
          foglio.istante(i["resolved_at"], "aperto"), (i["resolution"] or "")]
         for i in conformita["incidenti"]],
        larghezze=[.5, .9, 1.8, 1.4, 1.4, 1.4, 1.4, 2.2],
        nota_vuota="Nessun incidente nel periodo.")

    foglio.titolo_sezione("Comunicazioni inviate")
    foglio.paragrafo(
        "Due cose diverse, e vanno distinte: gli avvisi INTERNI (posta e messaggistica"
        " verso gli operatori), che dimostrano quando l'organizzazione ha saputo, e le"
        " comunicazioni all'AUTORITA' (art. 23 NIS2), che sono un atto verso"
        " l'esterno. Un avviso interno non e' una notifica.", INCHIOSTRO_2)
    foglio.tabella(
        ["momento", "canale", "esito", "quante"],
        [[n["event"], n["channel"], n["status"], n["n"]]
         for n in conformita["notifiche"]],
        larghezze=[3.0, 1.4, 1.4, 1.0],
        allineamento=["l", "l", "l", "r"],
        nota_vuota="Nessun avviso interno nel periodo.")

    acn = dati.get("acn") or {}
    foglio.titolo_sezione("Comunicazioni all'autorita' (ACN)",
                          "%d nel periodo, su %d incidenti"
                          % (acn.get("totale", 0), acn.get("incidenti", 0)))
    foglio.riquadri([
        (acn.get("nei_termini", 0), "inviate nei termini",
         OK if acn.get("nei_termini") else INCHIOSTRO_3),
        (acn.get("fuori_termine", 0), "fuori termine",
         CRITICO if acn.get("fuori_termine") else OK),
        (acn.get("da_inviare", 0), "ancora da inviare",
         ATTENZIONE if acn.get("da_inviare") else OK),
        (acn.get("non_dovute", 0), "non dovute (motivate)", INCHIOSTRO_3),
    ])
    foglio.tabella(
        ["incidente", "stadio", "stato", "scadenza", "inviata il", "protocollo",
         "motivazione"],
        [["#%s" % v["incident_id"], v.get("stadio_nome") or v["stage"], v["status"],
          foglio.istante(v.get("deadline_at"), "-"),
          foglio.istante(v.get("sent_at"), "-"),
          v.get("reference") or "-", (v.get("notes") or "")]
         for v in acn.get("comunicazioni") or []],
        larghezze=[.8, 1.4, 1.2, 1.3, 1.3, 1.4, 3.0],
        nota_vuota="Nessuna comunicazione all'autorita' nel periodo: nessun incidente"
                   " e' stato valutato significativo, oppure il fascicolo non e' stato"
                   " aperto. Le due cose non sono la stessa, ed e' la differenza che un"
                   " ispettore verifica.")
    foglio.paragrafo(
        "Il portale delle segnalazioni si usa con identita' digitale del punto di"
        " contatto: il prodotto compone il fascicolo, tiene i termini e registra il"
        " protocollo restituito. L'invio e' un atto della persona, e questa tabella ne"
        " e' la prova.", INCHIOSTRO_3)

    foglio.titolo_sezione("Conservazione dei dati e riferimenti")
    foglio.elenco([
        "Conservazione dichiarata per il tenant: %s giorni."
        % conformita["retention_giorni"],
        "Fuso dichiarato: %s. Tutte le date dei report sono calcolate in questo fuso."
        % (conformita["fuso"] or "non dichiarato"),
        "Recapito di riferimento: %s." % (conformita["contatto"] or "non indicato"),
        "GDPR art. 5(1)(e): i dati sono conservati per il tempo dichiarato, con durate"
        " distinte per genere di dato, e la politica e' applicabile e verificabile dalla"
        " console.",
        "GDPR art. 5(1)(c): i documenti destinati alla direzione non contengono"
        " identificativi di dispositivi.",
    ])

    foglio.titolo_sezione("Rilievi", "cio' che il sistema sa di se stesso")
    if conformita["rilievi"]:
        foglio.tabella(
            ["gravita'", "rilievo", "dettaglio e contromisura"],
            [[("!!" if r["gravita"] == "critical" else "!") + r["gravita"],
              r["titolo"], r["dettaglio"]] for r in conformita["rilievi"]],
            larghezze=[1.0, 2.6, 6.0])
    else:
        foglio.paragrafo("Nessun rilievo.", OK)
    foglio.paragrafo(
        "Un fascicolo che non elencasse i propri rilievi sarebbe un documento inutile:"
        " l'assenza di rilievi in un sistema reale non e' credibile, e la prima cosa che"
        " un auditor cerca e' se chi si valuta sa dove e' scoperto.")

    foglio.titolo_sezione("Perimetro dichiarato")
    foglio.tabella(
        ["subnet", "etichetta", "stato", "host teorici", "nodi trovati"],
        [[p["cidr"], (p["label"] or ""), "attiva" if p["is_enabled"] else "sospesa",
          p["host_count"], p["nodi"]] for p in dati["perimetro"]],
        larghezze=[1.6, 3.4, 1.2, 1.4, 1.4],
        allineamento=["l", "l", "l", "r", "r"],
        nota_vuota="Nessuna subnet dichiarata.")
    foglio.salva()
    return str(percorso)


# --------------------------------------------------------------------------- #
# R6 - Rapporto di incidente
# --------------------------------------------------------------------------- #
SEZIONI_INCIDENTE = [
    "Oggetto",
    "Cronologia",
    "Esiti del controllo attorno all'incidente",
    "Comunicazioni",
    "Uso di questo documento",
]


def incident_report(percorso, dati: dict) -> str:
    incidente = dati["incidente"]
    sezioni = list(SEZIONI_INCIDENTE)
    if dati["misure"]:
        sezioni.insert(3, "Misure correlate")

    foglio = Foglio(
        percorso, kind="incident",
        titolo="Rapporto di incidente #%s" % incidente["id"],
        sottotitolo="Che cosa e' accaduto, quando, chi e' stato avvisato, come e' finita",
        tenant=dati["tenant"]["nome"], intervallo=dati["intervallo"],
        fuso=dati["tenant"].get("fuso"),
        generato=dati["generato_utc"],
        scopo=[
            "Ricostruzione dell'incidente #%s sul controllo \"%s\" del bersaglio %s."
            % (incidente["id"], incidente["controllo"], incidente["address"]),
            "E' la base per il riesame a posteriori e per una notifica di incidente"
            " significativo ai sensi della direttiva NIS2.",
        ],
        sezioni=sezioni, riferimenti=riferimenti_comuni(dati, extra=[
            ("Incidente", "#%s" % incidente["id"]),
            ("Gravita'", incidente["severity"]),
            ("Stato", incidente["status"]),
        ]),
        nota=NOTA_PROVENIENZA)

    durata = None
    if incidente.get("opened_at") and incidente.get("resolved_at"):
        from ..db import parse_utc

        apertura, chiusura = parse_utc(incidente["opened_at"]), parse_utc(incidente["resolved_at"])
        if apertura and chiusura:
            durata = int((chiusura - apertura).total_seconds() // 60)

    foglio.riquadri([
        (incidente["severity"], "gravita'",
         CRITICO if incidente["severity"] == "critical" else ATTENZIONE),
        (incidente["status"], "stato",
         OK if incidente["status"] == "resolved" else CRITICO),
        (_durata(durata), "durata", None),
        (incidente["failure_count"], "fallimenti consecutivi", None),
        (len(dati["notifiche"]), "comunicazioni inviate", None),
    ])

    foglio.titolo_sezione("Oggetto")
    foglio.paragrafo("Controllo \"%s\" (%s) sul bersaglio %s."
                     % (incidente["controllo"], incidente["kind"], incidente["address"]))
    foglio.paragrafo("Primo dettaglio registrato: %s"
                     % (incidente["first_detail"] or "-"))
    foglio.paragrafo("Ultimo dettaglio registrato: %s"
                     % (incidente["last_detail"] or "-"))
    if incidente.get("escalated_at"):
        foglio.paragrafo("Operatore attivato il %s, recapito %s."
                         % (incidente["escalated_at"],
                            incidente["escalated_to"] or "non indicato"), ATTENZIONE)

    foglio.titolo_sezione("Cronologia")
    foglio.tabella(
        ["quando", "passaggio", "attore", "nota"],
        [[foglio.istante(e["created_at"], ""), e["action"], e["actor"] or "sistema",
          (e["note"] or "")] for e in dati["cronologia"]],
        larghezze=[1.8, 1.6, 1.4, 4.2],
        nota_vuota="Nessun passaggio registrato.")

    foglio.titolo_sezione("Esiti del controllo attorno all'incidente",
                          "finestra allargata di due ore")
    foglio.tabella(
        ["quando", "esito", "latenza", "dettaglio"],
        [[foglio.istante(r["executed_at"], ""),
          r["status"] if r["status"] == "ok" else "!" + r["status"],
          "%s ms" % int(r["latency_ms"]) if r["latency_ms"] else "-",
          (r["detail"] or "")] for r in dati["esiti"]],
        larghezze=[1.8, 1.0, 1.2, 5.0],
        nota_vuota="Nessun esito nella finestra.")

    if dati["misure"]:
        foglio.titolo_sezione("Misure correlate", "prime 60 nella finestra")
        foglio.tabella(
            ["quando", "misura", "valore"],
            [[foglio.istante(m["measured_at"], ""), m["name"],
              m["value"] if m["value"] is not None else (m["text_value"] or "")]
             for m in dati["misure"]],
            larghezze=[1.8, 3.4, 2.0],
            allineamento=["l", "l", "r"])

    foglio.titolo_sezione("Comunicazioni")
    foglio.tabella(
        ["momento", "canale", "destinatari", "esito", "quando", "errore"],
        [[n["event"], n["channel"], (n["recipients"] or ""), n["status"],
          foglio.istante(n["sent_at"], "-"), (n["last_error"] or "")]
         for n in dati["notifiche"]],
        larghezze=[1.8, 1.0, 2.2, 1.0, 1.4, 2.0],
        nota_vuota="Nessuna comunicazione registrata per questo incidente.")

    foglio.titolo_sezione("Uso di questo documento")
    foglio.paragrafo(
        "E' la base per una notifica di incidente significativo ai sensi della direttiva"
        " NIS2: contiene il momento del rilevamento, la cronologia degli interventi, chi"
        " e' stato avvisato e quando, e l'esito. Va integrato con la valutazione"
        " dell'impatto, che il sistema non puo' conoscere.")
    foglio.salva()
    return str(percorso)


# Quante righe stanno in un elenco prima che smetta di essere un documento.
# Misurato sul parco reale: 1246 certificati facevano 136 pagine -- non un
# documento, un archivio stampato che nessuno legge.
MAX_RIGHE_ELENCO = 120

SEZIONI_CERTIFICATI = [
    "Che cosa dice questo documento",
    "Situazione in una riga",
    "Gia' scaduti",
    "In scadenza nei prossimi 30 giorni",
    "In scadenza fra 31 e 90 giorni",
    "Certificati con una debolezza dimostrata",
    "Chi ha emesso i certificati",
    "Elenco completo",
]


def _riga_certificato(voce: dict) -> list:
    """Una riga della tabella: dove sta, che cos'e', quando scade."""
    nome = (voce.get("hostname") or voce.get("device_label") or "").strip()
    dove = "%s:%s" % (voce.get("ip") or "?", voce.get("port") or "?")
    giorni = voce.get("giorni")
    if giorni is None:
        quando = "data non leggibile"
    elif giorni < 0:
        quando = "scaduto da %d gg" % abs(giorni)
    elif giorni == 0:
        quando = "scade oggi"
    else:
        quando = "fra %d gg" % giorni
    return [
        # UNA RIGA SOLA: l'impaginatore disegna la cella com'e', e un
        # a capo esce come un quadratino -- il carattere che il font non ha.
        ("%s  %s" % (nome, dove)) if nome else dove,
        str(voce.get("cert_subject") or voce.get("cert_soggetto_dn") or "-"),
        str(voce.get("cert_issuer") or voce.get("cert_emittente_dn") or "-"),
        str(voce.get("cert_expires") or "-"),
        quando,
        ", ".join(voce.get("debolezze") or []) or "-",
    ]


COLONNE_CERTIFICATO = ["DOVE", "SOGGETTO", "EMITTENTE", "SCADENZA", "QUANDO",
                       "DEBOLEZZE"]
PESI_CERTIFICATO = [16, 26, 22, 12, 12, 12]


def certificates_report(percorso, dati: dict) -> str:
    """Lo stato dei certificati TLS del parco."""
    conti = dati["conteggi"]
    foglio = Foglio(
        percorso, kind="certificates", titolo="Certificati TLS",
        sottotitolo="Quali scadono, quali sono deboli, chi li ha emessi",
        tenant=dati["tenant"]["nome"], intervallo=dati["intervallo"],
        fuso=dati["tenant"].get("fuso"),
        generato=dati["generato_utc"],
        scopo=[
            "Lo stato dei certificati TLS trovati sul parco di %s: quando scadono,"
            " chi li ha emessi e quali portano una debolezza dimostrata."
            % dati["tenant"]["nome"],
            "Un certificato che scade non e' un rischio teorico: e' un servizio che"
            " smette di funzionare a una data nota. L'unica ragione per cui coglie di"
            " sorpresa e' che nessuno tiene l'elenco.",
        ],
        sezioni=SEZIONI_CERTIFICATI, riferimenti=riferimenti_comuni(dati),
        nota=NOTA_PROVENIENZA, orizzontale=True)

    foglio.titolo_sezione("Che cosa dice questo documento")
    foglio.paragrafo(
        "Ogni riga e' un certificato che una sonda ha letto aprendo una connessione"
        " HTTPS verso un servizio del parco. Non c'e' nulla di dedotto: soggetto,"
        " emittente, validita', algoritmo di firma e lunghezza della chiave sono"
        " scritti dentro il certificato stesso.")
    foglio.box([{"testo":
                 "Limite di questo elenco: si vedono i soli certificati che una sonda"
                 " ha potuto leggere. Un servizio che la sonda non raggiunge non"
                 " compare, e la sua assenza NON e' la conferma che non esista."}])

    foglio.titolo_sezione("Situazione in una riga")
    # Il colore non e' decorazione: distingue cio' che e' gia' rotto da cio' che lo
    # sara'. Un numero senza colore in una fascia di sei si legge come gli altri.
    foglio.riquadri([
        (conti["scaduti"], "gia' scaduti",
         ATTENZIONE if conti["scaduti"] else OK),
        (conti["entro_30"], "scadono entro 30 giorni",
         ATTENZIONE if conti["entro_30"] else OK),
        (conti["entro_90"], "entro 90 giorni", None),
        (conti["deboli"], "con una debolezza",
         ATTENZIONE if conti["deboli"] else OK),
        (conti["autofirmati"], "autofirmati", None),
        (conti["totale"], "certificati in totale", None),
    ])
    foglio.paragrafo(
        "I certificati sono distribuiti su %d dispositivi. Le tre finestre non si"
        " sommano: chi scade entro 30 giorni e' compreso anche negli 90."
        % conti["nodi"])

    def tabella(titolo: str, voci: list, vuoto: str) -> None:
        foglio.titolo_sezione(titolo)
        if not voci:
            foglio.paragrafo(vuoto)
            return
        foglio.tabella(COLONNE_CERTIFICATO,
                       [_riga_certificato(v) for v in voci[:MAX_RIGHE_ELENCO]],
                       larghezze=PESI_CERTIFICATO)
        if len(voci) > MAX_RIGHE_ELENCO:
            foglio.paragrafo("Mostrati i primi %d di %d, in ordine di scadenza: i"
                             " piu' urgenti sono qui."
                             % (MAX_RIGHE_ELENCO, len(voci)))

    tabella("Gia' scaduti", dati["scaduti"],
            "Nessun certificato risulta scaduto fra quelli letti.")
    tabella("In scadenza nei prossimi 30 giorni", dati["entro_30"],
            "Nessun certificato scade entro trenta giorni.")
    tabella("In scadenza fra 31 e 90 giorni",
            [c for c in dati["entro_90"] if c not in dati["entro_30"]],
            "Nessun certificato scade in quella finestra.")

    foglio.titolo_sezione("Certificati con una debolezza dimostrata")
    foglio.paragrafo(
        "Un certificato invecchia anche senza scadere. La firma SHA-1 non e' piu'"
        " emessa dalle CA pubbliche dal 2016 e una chiave RSA sotto i 2048 bit non e'"
        " piu' adeguata (NIST SP 800-57): sono difetti che restano tali fino al"
        " rinnovo, qualunque sia la data di scadenza. L'autofirma non e' un difetto in"
        " se' -- su una rete interna e' una scelta legittima -- ma va deciso di"
        " proposito, non subito.")
    if dati["deboli"]:
        foglio.tabella(COLONNE_CERTIFICATO,
                       [_riga_certificato(v)
                        for v in dati["deboli"][:MAX_RIGHE_ELENCO]],
                       larghezze=PESI_CERTIFICATO)
        if len(dati["deboli"]) > MAX_RIGHE_ELENCO:
            foglio.paragrafo(
                "Mostrati i primi %d di %d. Quando le debolezze sono cosi' diffuse il"
                " problema non e' il singolo certificato: e' che nessuno li emette da"
                " un punto solo -- si veda la sezione sugli emittenti."
                % (MAX_RIGHE_ELENCO, len(dati["deboli"])))
    else:
        foglio.paragrafo("Nessuna debolezza dimostrata fra i certificati letti.")

    foglio.titolo_sezione("Chi ha emesso i certificati")
    foglio.paragrafo(
        "Un parco con venti emittenti diversi non ha una politica dei certificati: ne"
        " ha venti. E' il primo dato da guardare prima delle singole scadenze.")
    if dati["emittenti"]:
        foglio.tabella(
            ["EMITTENTE", "QUANTI", "AUTOFIRMATI", "CON DEBOLEZZE"],
            [[str(e["emittente"]), str(e["quanti"]), str(e["autofirmati"]),
              str(e["deboli"])] for e in dati["emittenti"]],
            larghezze=[58, 14, 14, 14], allineamento=["l", "r", "r", "r"])
    else:
        foglio.paragrafo("Nessun certificato letto.")

    foglio.titolo_sezione("Elenco completo")
    # SI TRONCA, E LO SI DICE. Un troncamento taciuto sarebbe peggio dell'elenco
    # lungo: chi legge crederebbe di avere tutto.
    completo = dati["certificati"]
    if completo:
        foglio.tabella(COLONNE_CERTIFICATO,
                       [_riga_certificato(v) for v in completo[:MAX_RIGHE_ELENCO]],
                       larghezze=PESI_CERTIFICATO)
        if len(completo) > MAX_RIGHE_ELENCO:
            foglio.paragrafo(
                "Mostrati i primi %d di %d, in ordine di scadenza. L'elenco intero si"
                " consulta nella console (Rete > Certificati TLS), dove si filtra e si"
                " ordina." % (MAX_RIGHE_ELENCO, len(completo)))
    else:
        foglio.paragrafo(
            "Nessun certificato TLS e' stato letto sul parco. Se ci si aspettava il"
            " contrario, la causa e' quasi sempre una di queste: i servizi HTTPS non"
            " sono nel perimetro dichiarato, la fase di lettura web non e' ancora"
            " passata, oppure le sonde non raggiungono quelle reti.")

    foglio.salva()
    return percorso


# --------------------------------------------------------------------------- #
# Vetusta' del parco
# --------------------------------------------------------------------------- #
SEZIONI_VETUSTA = [
    "Che cosa dice questo documento, e che cosa non dice",
    "Situazione in una riga",
    "Ferme da oltre dieci anni",
    "Ferme da cinque a dieci anni",
    "Distribuzione per anno dichiarato",
]


RE_MARCATORE = re.compile(r"<[^>]*>")


def _prova_leggibile(testo, anno, larghezza: int = 56) -> str:
    """La prova dell'anno, ripulita dal markup e centrata sull'anno.

    Il frammento arriva cosi' com'e' dalla pagina, e spesso porta con se' la coda di
    un attributo HTML tagliato a meta': una prova che si legge come codice rotto non
    convince nessuno, e questo documento chiede di essere giudicato sulle prove.
    """
    testo = RE_MARCATORE.sub(" ", str(testo or ""))
    # Le entita' HTML si sciolgono DOPO aver tolto i marcatori: prima, un "&lt;"
    # diventerebbe una parentesi e si porterebbe via il testo che segue.
    testo = unescape(testo)
    # Coda di un marcatore aperto e mai chiuso, in fondo al frammento.
    if "<" in testo and ">" not in testo[testo.index("<"):]:
        testo = testo[:testo.index("<")]
    anno = str(anno or "")
    posizione = testo.find(anno) if anno else -1
    if posizione > 0:
        # Coda di un attributo senza la sua apertura: la prova comincia dopo
        # l'ultimo segno di chiusura che precede l'anno.
        taglio = testo.rfind(">", 0, posizione)
        if taglio >= 0:
            testo = testo[taglio + 1:]
    testo = " ".join(testo.split())
    if len(testo) <= larghezza:
        return testo or "-"
    posizione = testo.find(anno) if anno else 0
    inizio = max(0, (posizione if posizione >= 0 else 0) - larghezza // 4)
    ritaglio = testo[inizio:inizio + larghezza]
    return ("..." + ritaglio if inizio else ritaglio).rstrip()


def _riga_vetusta(v: dict) -> list:
    # Il nome host e NIENTE altro: il tipo di apparato ha gia' la sua colonna, e
    # ripeterlo qui sprecava la meta' della piu' stretta.
    nome = str(v.get("hostname") or "").strip()
    dove = "%s:%s" % (v.get("ip") or "?", v.get("port") or "?")
    return [
        ("%s  %s" % (nome, dove)) if nome else dove,
        str(v.get("device_label") or v.get("device_type") or "-"),
        str(v.get("product") or v.get("server_header") or v.get("title") or "-"),
        str(v.get("web_year") or "-"),
        ("%d anni" % v["eta"]) if v.get("eta") is not None else "-",
        str(v.get("web_year_source") or "-"),
        _prova_leggibile(v.get("web_year_evidence"), v.get("web_year")),
    ]


COLONNE_VETUSTA = ["DOVE", "DISPOSITIVO", "PRODOTTO", "ANNO", "ETA'", "FONTE", "PROVA"]
PESI_VETUSTA = [16, 13, 17, 6, 8, 11, 29]


def vetusta_report(percorso, dati: dict) -> str:
    """Da quanti anni nessuno aggiorna le interfacce del parco."""
    conti = dati["conteggi"]
    foglio = Foglio(
        percorso, kind="vetusta", titolo="Vetusta' del parco",
        sottotitolo="Da quanti anni nessuno tocca queste interfacce",
        tenant=dati["tenant"]["nome"], intervallo=dati["intervallo"],
        fuso=dati["tenant"].get("fuso"), generato=dati["generato_utc"],
        scopo=[
            "Quali sistemi di %s non li aggiorna piu' nessuno, con la prova."
            % dati["tenant"]["nome"],
            "Non e' l'elenco delle vulnerabilita': e' la causa a monte di meta' di"
            " esse, e non compare in nessun catalogo di CVE.",
        ],
        sezioni=SEZIONI_VETUSTA, riferimenti=riferimenti_comuni(dati),
        nota=NOTA_PROVENIENZA, orizzontale=True)

    foglio.titolo_sezione("Che cosa dice questo documento, e che cosa non dice")
    foglio.paragrafo(
        "Ogni riga riporta l'anno che l'interfaccia web di un apparato dichiara di se':"
        " il copyright nel pie' di pagina, una data in un meta, una stringa di build,"
        " l'intestazione Last-Modified oppure l'inizio di validita' del certificato"
        " TLS. Fra le prove si tiene la piu' recente.")
    foglio.box([{"testo":
                 "Un \"(c) 2014\" NON dimostra che il software sia del 2014: dimostra"
                 " che nessuno ha piu' toccato quella pagina dal 2014. E' un limite"
                 " INFERIORE all'eta', non una misura. Per questo ogni riga porta la"
                 " PROVA -- il frammento da cui l'anno viene -- e non il solo numero:"
                 " chi legge deve poter dare un giudizio, non fidarsi."}])
    foglio.paragrafo(
        "Le interfacce che non dichiarano alcun anno sono %d e NON compaiono qui."
        " Non sono \"recenti\": sono mute, ed e' una cosa diversa."
        % conti["senza_anno"])

    foglio.titolo_sezione("Situazione in una riga")
    foglio.riquadri([
        (conti["gravi"], "ferme da 10+ anni",
         ATTENZIONE if conti["gravi"] else OK),
        (conti["preoccupanti"], "ferme da 5-10 anni",
         ATTENZIONE if conti["preoccupanti"] else OK),
        ("%d anni" % conti["eta_massima"], "la piu' vecchia", None),
        (conti["nodi"], "dispositivi con un anno", None),
        (conti["senza_anno"], "interfacce mute", None),
    ])

    foglio.titolo_sezione("Ferme da oltre dieci anni")
    if dati["gravi"]:
        foglio.paragrafo(
            "Un'interfaccia ferma a piu' di dieci anni fa non e' un caso: e' un"
            " apparato uscito dal ciclo di manutenzione. Se e' raggiungibile dalla rete"
            " di utenza, va deciso che cosa farne -- aggiornarlo, isolarlo o"
            " sostituirlo -- prima che lo decida qualcun altro.")
        foglio.tabella(COLONNE_VETUSTA,
                       [_riga_vetusta(v) for v in dati["gravi"][:MAX_RIGHE_ELENCO]],
                       larghezze=PESI_VETUSTA)
        if len(dati["gravi"]) > MAX_RIGHE_ELENCO:
            foglio.paragrafo("Mostrati i primi %d di %d, dal piu' vecchio."
                             % (MAX_RIGHE_ELENCO, len(dati["gravi"])))
    else:
        foglio.paragrafo("Nessuna interfaccia dichiara un anno anteriore a dieci anni fa.")

    foglio.titolo_sezione("Ferme da cinque a dieci anni")
    if dati["preoccupanti"]:
        foglio.tabella(
            COLONNE_VETUSTA,
            [_riga_vetusta(v) for v in dati["preoccupanti"][:MAX_RIGHE_ELENCO]],
            larghezze=PESI_VETUSTA)
        if len(dati["preoccupanti"]) > MAX_RIGHE_ELENCO:
            foglio.paragrafo("Mostrati i primi %d di %d."
                             % (MAX_RIGHE_ELENCO, len(dati["preoccupanti"])))
    else:
        foglio.paragrafo("Nessuna interfaccia in questa fascia.")

    foglio.titolo_sezione("Distribuzione per anno dichiarato")
    if dati["distribuzione"]:
        # Affiancata su tre colonne: due sole colonne di numeri stirate su una pagina
        # orizzontale sono un righello, non una tabella.
        foglio.tabella(
            ["ANNO", "DISPOSITIVI"],
            [[str(v["anno"]), str(v["quanti"])] for v in dati["distribuzione"]],
            larghezze=[1.0, 1.0], allineamento=["l", "r"], colonne=3)
    else:
        foglio.paragrafo("Nessun anno raccolto.")

    foglio.salva()
    return percorso


# --------------------------------------------------------------------------- #
# Presenze sulle reti senza fili
# --------------------------------------------------------------------------- #
SEZIONI_PRESENZE = [
    "Che cosa dice questo documento",
    "Situazione in una riga",
    "Le reti osservate",
    "Con quale certezza si riconoscono gli apparati",
    "Apparati comparsi per la prima volta nel periodo",
    "Gli apparati piu' assidui",
    "Trattamento dei dati",
]


def presenze_report(percorso, dati: dict) -> str:
    """Chi c'e' stato sulle reti senza fili, e con quale certezza."""
    conti = dati["conteggi"]
    foglio = Foglio(
        percorso, kind="presenze", titolo="Presenze sulle reti senza fili",
        sottotitolo="Chi c'e' stato, quanti non si riconoscono",
        tenant=dati["tenant"]["nome"], intervallo=dati["intervallo"],
        fuso=dati["tenant"].get("fuso"), generato=dati["generato_utc"],
        scopo=[
            "Gli apparati visti sulle reti senza fili di %s nel periodo, con la fonte"
            " dell'identita' e la sua incertezza." % dati["tenant"]["nome"],
            "Su una rete di utenza la domanda operativa e' quanti apparati non si"
            " riconoscono; quella di conformita' e' per quanto tempo si conservano"
            " questi dati.",
        ],
        sezioni=SEZIONI_PRESENZE, riferimenti=riferimenti_comuni(dati),
        nota=NOTA_PROVENIENZA, orizzontale=True)

    foglio.titolo_sezione("Che cosa dice questo documento")
    foglio.paragrafo(
        "L'unita' non e' l'indirizzo IP -- che il DHCP riassegna, e che confonderebbe"
        " due apparati diversi in una riga sola -- ma l'APPARATO riconosciuto. Il"
        " riconoscimento e' a scalare e la sua fonte e' sempre dichiarata, perche'"
        " un'identita' dedotta vale meno di una letta.")

    foglio.titolo_sezione("Situazione in una riga")
    foglio.riquadri([
        (conti["apparati"], "apparati distinti", None),
        (conti["nuovi"], "mai visti prima",
         ATTENZIONE if conti["nuovi"] else OK),
        (conti["identita_deboli"], "riconosciuti dal solo indirizzo",
         ATTENZIONE if conti["identita_deboli"] else OK),
        (conti["permanenze"], "permanenze registrate", None),
        (conti["reti"], "reti senza fili", None),
    ])

    foglio.titolo_sezione("Le reti osservate")
    if dati["reti"]:
        foglio.tabella(
            ["RETE", "ETICHETTA", "ZONA", "APPARATI", "PERMANENZE"],
            [[str(r["cidr"]), str(r["label"] or "-"), str(r["zone"] or "-"),
              str(r["apparati"] or 0), str(r["permanenze"] or 0)]
             for r in dati["reti"]],
            larghezze=[20, 30, 18, 16, 16], allineamento=["l", "l", "l", "r", "r"])
    else:
        foglio.paragrafo(
            "Nessuna rete e' dichiarata senza fili. La ricognizione delle presenze si"
            " attiva sulle sole subnet con quell'interruttore acceso (Rete >"
            " Perimetro): senza, questo documento resta vuoto anche se la rete Wi-Fi"
            " esiste.")

    foglio.titolo_sezione("Con quale certezza si riconoscono gli apparati")
    foglio.paragrafo(
        "E' il dato che dice se lo storico e' affidabile. Se meta' degli apparati e'"
        " riconosciuta dal solo indirizzo, la rete non fornisce i MAC alla sonda e lo"
        " storico va letto per quello che e': una successione di indirizzi, non di"
        " apparati.")
    if dati["per_fonte"]:
        foglio.tabella(
            ["FONTE", "QUANTO VALE", "APPARATI", "PERMANENZE"],
            [[str(v["nome"]), str(v["certezza"]), str(v["apparati"] or 0),
              str(v["permanenze"] or 0)] for v in dati["per_fonte"]],
            larghezze=[26, 34, 20, 20], allineamento=["l", "l", "r", "r"])
    else:
        foglio.paragrafo("Nessuna presenza registrata nel periodo.")

    foglio.titolo_sezione("Apparati comparsi per la prima volta nel periodo")
    if dati["nuovi"]:
        foglio.tabella(
            ["APPARATO", "MAC", "INDIRIZZO", "FONTE", "DAL", "PERMANENZE"],
            [[str(v.get("hostname") or v.get("device_label") or v["identity_key"]),
              str(v.get("mac") or "-"), str(v.get("ip") or "-"),
              str(v["fonte"]), foglio.istante(v["dal"]), str(v["permanenze"])]
             for v in dati["nuovi"][:MAX_RIGHE_ELENCO]],
            larghezze=[26, 16, 14, 18, 16, 10],
            allineamento=["l", "l", "l", "l", "l", "r"])
        if len(dati["nuovi"]) > MAX_RIGHE_ELENCO:
            foglio.paragrafo("Mostrati i primi %d di %d, dal piu' recente."
                             % (MAX_RIGHE_ELENCO, len(dati["nuovi"])))
    else:
        foglio.paragrafo("Nessun apparato nuovo nel periodo.")

    foglio.titolo_sezione("Gli apparati piu' assidui")
    foglio.paragrafo(
        "Chi torna ogni giorno e' l'arredamento della rete. Serve come termine di"
        " paragone: e' rispetto a questi che un apparato comparso una volta sola si"
        " nota.")
    if dati["assidui"]:
        foglio.tabella(
            ["APPARATO", "MAC", "FONTE", "PERMANENZE", "DAL", "ULTIMA VOLTA"],
            [[str(v.get("hostname") or v.get("device_label") or v["identity_key"]),
              str(v.get("mac") or "-"), str(v["fonte"]),
              str(v["permanenze"]), foglio.istante(v["dal"]), foglio.istante(v["al"])]
             for v in dati["assidui"]],
            larghezze=[26, 16, 18, 10, 15, 15],
            allineamento=["l", "l", "l", "r", "l", "l"])
    else:
        foglio.paragrafo("Nessuna permanenza nel periodo.")

    foglio.titolo_sezione("Trattamento dei dati")
    foglio.box([{"testo":
                 "Sapere quali apparati personali erano in rete e quando e' un dato"
                 " che riguarda le persone, non solo le macchine (Reg. UE 2016/679,"
                 " art. 5). Questo documento nomina gli APPARATI, non le persone. Le"
                 " presenze si conservano per il tempo dichiarato in Amministrazione >"
                 " Archivio (90 giorni per impostazione predefinita) e poi si"
                 " cancellano da se': e' il tempo che serve a leggere un andamento,"
                 " non per sempre."}])

    foglio.salva()
    return percorso


# --------------------------------------------------------------------------- #
# Salute della flotta e copertura
# --------------------------------------------------------------------------- #
SEZIONI_FLOTTA = [
    "Che cosa dice questo documento",
    "Situazione in una riga",
    "Le sonde",
    "Punti ciechi: dichiarati e mai guardati",
    "Reti guardate che non hanno prodotto nulla",
    "Le fasi di scansione",
    "Copertura del perimetro",
]


STATI_SONDA = {"active": "attiva", "pending": "in attesa", "idle": "ferma",
               "error": "in errore", "unknown": "sconosciuto"}


def _nome_sonda(s: dict) -> str:
    """Codice della sonda, e il nome solo se aggiunge qualcosa.

    Nome e codice sono quasi sempre lo stesso testo scritto in due modi, e affiancarli
    riempiva la colonna di una ripetizione troncata a meta' parola.
    """
    codice = str(s["code"] or "")
    nome = str(s["name"] or "").strip()
    confronto = nome.lower().replace(" ", "").replace("-", "")
    if not nome or confronto in codice.lower().replace("-", ""):
        return codice
    return "%s  %s" % (codice, nome)


def _stato_sonda(s: dict) -> str:
    """Lo stato come lo legge chi non conosce i codici interni."""
    if s["revoked_at"]:
        return "revocata"
    if int(s["scan_paused"] or 0) or not int(s["scan_enabled"] or 0):
        return "sospesa"
    stato = str(s["status"] or "").lower()
    return STATI_SONDA.get(stato, stato or "-")


def flotta_report(percorso, dati: dict) -> str:
    """Lo strumento funziona? Posso fidarmi degli altri report?"""
    conti = dati["conteggi"]
    foglio = Foglio(
        percorso, kind="flotta", titolo="Salute della flotta e copertura",
        sottotitolo="Posso fidarmi di questi dati?",
        tenant=dati["tenant"]["nome"], intervallo=dati["intervallo"],
        fuso=dati["tenant"].get("fuso"), generato=dati["generato_utc"],
        scopo=[
            "Lo stato delle sonde di %s e quanta parte del perimetro dichiarato e'"
            " davvero coperta." % dati["tenant"]["nome"],
            "Non parla della rete: parla dello STRUMENTO. E' la domanda da farsi prima"
            " di guardare qualunque altro report.",
        ],
        sezioni=SEZIONI_FLOTTA, riferimenti=riferimenti_comuni(dati),
        nota=NOTA_PROVENIENZA, orizzontale=True)

    foglio.titolo_sezione("Che cosa dice questo documento")
    foglio.paragrafo(
        "Una subnet dichiarata nel perimetro e mai guardata non produce righe in"
        " nessun altro report -- e una tabella vuota si legge come \"niente da"
        " segnalare\" invece che come \"non guardato\". Questo documento nomina quei"
        " punti ciechi.")

    foglio.titolo_sezione("Situazione in una riga")
    foglio.riquadri([
        (conti["sonde_attive"], "sonde attive",
         OK if conti["sonde_attive"] else ATTENZIONE),
        (conti["sonde_sospese"], "con scansioni sospese",
         ATTENZIONE if conti["sonde_sospese"] else OK),
        (conti["ciechi"], "reti mai guardate",
         ATTENZIONE if conti["ciechi"] else OK),
        (conti["vuote"], "guardate senza esito", None),
        (conti["subnet_attive"], "reti nel perimetro", None),
        (conti["passate"], "passate nel periodo", None),
    ])

    foglio.titolo_sezione("Le sonde")
    if dati["sonde"]:
        foglio.tabella(
            ["SONDA", "SEDE", "STATO", "AGENTE", "ULTIMO BATTITO", "LOTTI", "PASSATE",
             "NODI"],
            [[_nome_sonda(s), str(s["site"] or "-"), _stato_sonda(s),
              str(s["agent_version"] or "-"), foglio.istante(s["last_seen_at"], vuoto="mai"),
              str(s["lotti"] or 0), str(s["passate"] or 0), str(s["nodi"] or 0)]
             for s in dati["sonde"]],
            larghezze=[22, 13, 11, 9, 15, 10, 10, 10],
            allineamento=["l", "l", "l", "l", "l", "r", "r", "r"])
    else:
        foglio.paragrafo(
            "Nessuna sonda registrata: nessun dato di questo tenant puo' essere"
            " aggiornato. Si registra da Sonde > Registra sonda.")

    foglio.titolo_sezione("Punti ciechi: dichiarati e mai guardati")
    if dati["ciechi"]:
        foglio.paragrafo(
            "Queste reti sono nel perimetro e attive, ma nessuna passata le ha mai"
            " prese come bersaglio. Le cause piu' frequenti: nessuna sonda le"
            " raggiunge (manca una rotta), oppure la scoperta non e' ancora arrivata"
            " al loro turno.")
        foglio.tabella(
            ["RETE", "ETICHETTA", "ZONA", "INDIRIZZI"],
            [[str(c["cidr"]), str(c["label"] or "-"), str(c["zone"] or "-"),
              str(c["host_count"] or 0)] for c in dati["ciechi"][:MAX_RIGHE_ELENCO]],
            larghezze=[22, 38, 22, 18], allineamento=["l", "l", "l", "r"])
        if len(dati["ciechi"]) > MAX_RIGHE_ELENCO:
            foglio.paragrafo("Mostrate le prime %d di %d."
                             % (MAX_RIGHE_ELENCO, len(dati["ciechi"])))
    else:
        foglio.paragrafo("Ogni rete attiva del perimetro e' stata guardata almeno una"
                         " volta.")

    foglio.titolo_sezione("Reti guardate che non hanno prodotto nulla")
    if dati["vuote"]:
        foglio.paragrafo(
            "Una rete guardata e vuota puo' essere davvero vuota -- oppure non"
            " raggiungibile. Le due cose si distinguono dal diario della sonda, che"
            " dichiara quando nmap non sa come arrivare a un bersaglio.")
        foglio.tabella(
            ["RETE", "ETICHETTA", "ULTIMA PASSATA"],
            [[str(c["cidr"]), str(c["label"] or "-"), foglio.istante(c["ultima"])]
             for c in dati["vuote"][:MAX_RIGHE_ELENCO]],
            larghezze=[1.2, 1.6, 1.4], colonne=2)
    else:
        foglio.paragrafo("Ogni rete guardata ha prodotto almeno un nodo.")

    foglio.titolo_sezione("Le fasi di scansione")
    foglio.paragrafo(
        "Una passata completata su ZERO host non e' una passata veloce: e' una passata"
        " che non ha visto nulla. La colonna \"a vuoto\" e' il numero da guardare per"
        " primo: se cresce su una fase sola, il problema e' quella fase; se cresce su"
        " tutte, il problema e' la raggiungibilita' delle reti.")
    if dati["fasi"]:
        foglio.tabella(
            ["FASE", "PASSATE", "COMPLETATE", "A VUOTO", "HOST VISTI", "RECORD",
             "SECONDI MEDI"],
            [[str(f["stage"]), str(f["passate"] or 0), str(f["completate"] or 0),
              str(f["senza_host"] or 0), str(f["host"] or 0), str(f["record"] or 0),
              str(f["secondi_medi"] or 0)] for f in dati["fasi"]],
            larghezze=[18, 12, 14, 12, 14, 12, 14],
            allineamento=["l", "r", "r", "r", "r", "r", "r"])
        foglio.box([{"testo":
                     "Come si legge la colonna RECORD. La valorizzano le sole fasi che"
                     " scrivono record propri -- la scoperta e la lettura web; le"
                     " altre (porte, SMB, vulnerabilita') conferiscono aggiornando i"
                     " nodi e lasciano quel contatore a zero anche quando hanno"
                     " lavorato. Un zero in quella colonna NON significa che la fase"
                     " abbia fallito: per quello si guarda \"a vuoto\"."}])
    else:
        foglio.paragrafo("Nessuna passata registrata nel periodo.")

    foglio.titolo_sezione("Copertura del perimetro")
    if dati["copertura"]:
        foglio.tabella(
            ["RETE", "ETICHETTA", "ZONA", "ATTIVA", "WI-FI", "NODI", "ULTIMA PASSATA"],
            [[str(c["cidr"]), str(c["label"] or "-"), str(c["zone"] or "-"),
              "si" if int(c["is_enabled"] or 0) else "no",
              "si" if int(c["is_wifi"] or 0) else "-",
              str(c["nodi"] or 0), foglio.istante(c["ultima"], vuoto="mai")]
             for c in dati["copertura"][:MAX_RIGHE_ELENCO]],
            larghezze=[1.3, 1.4, 1.0, .6, .5, .6, 1.2],
            allineamento=["l", "l", "l", "l", "l", "r", "l"], colonne=2)
        if len(dati["copertura"]) > MAX_RIGHE_ELENCO:
            foglio.paragrafo("Mostrate le prime %d di %d."
                             % (MAX_RIGHE_ELENCO, len(dati["copertura"])))
    else:
        foglio.paragrafo("Nessuna subnet dichiarata nel perimetro.")

    foglio.salva()
    return percorso


# --------------------------------------------------------------------------- #
# Condivisioni ed esposizione SMB
# --------------------------------------------------------------------------- #
SEZIONI_SMB = [
    "Che cosa dice questo documento",
    "Situazione in una riga",
    "Firma dei messaggi non richiesta",
    "Protocollo SMB 1.0 ancora attivo",
    "Condivisioni enumerate",
    "Tutti i dispositivi letti",
]


# La firma in forma breve, per l'elenco completo: la dicitura estesa non entra in una
# colonna e usciva troncata a meta' parola ("abilitata ma non richi"), che si legge come
# un errore del programma. Il significato esteso sta nella sezione che la spiega.
FIRMA_BREVE = {
    "abilitata ma non richiesta": "non richiesta",
    "non attiva": "non attiva",
    "richiesta": "richiesta",
}


def smb_report(percorso, dati: dict) -> str:
    """Che cosa dichiara di se' il parco Windows."""
    conti = dati["conteggi"]
    foglio = Foglio(
        percorso, kind="smb", titolo="Esposizione SMB",
        sottotitolo="Firma dei messaggi, versioni del protocollo, condivisioni",
        tenant=dati["tenant"]["nome"], intervallo=dati["intervallo"],
        fuso=dati["tenant"].get("fuso"), generato=dati["generato_utc"],
        scopo=[
            "Che cosa dichiarano di se' i dispositivi di %s che parlano SMB."
            % dati["tenant"]["nome"],
            "SMB e' il protocollo con cui si muove il ransomware dentro una rete: la"
            " firma non richiesta e il protocollo 1.0 acceso sono le due condizioni"
            " che glielo rendono facile.",
        ],
        sezioni=SEZIONI_SMB, riferimenti=riferimenti_comuni(dati),
        nota=NOTA_PROVENIENZA, orizzontale=True)

    foglio.titolo_sezione("Che cosa dice questo documento")
    foglio.paragrafo(
        "Tutto cio' che segue e' letto in SOLA LETTURA da quello che ogni dispositivo"
        " dichiara di se' quando gli si chiede come parla: nessuna credenziale"
        " provata, nessun file aperto, nessuna condivisione montata.")

    foglio.titolo_sezione("Situazione in una riga")
    foglio.riquadri([
        (conti["senza_firma"], "firma non richiesta",
         ATTENZIONE if conti["senza_firma"] else OK),
        (conti["smb1"], "con SMB 1.0", ATTENZIONE if conti["smb1"] else OK),
        (conti["firma_richiesta"], "firma richiesta", OK),
        (conti["condivisioni"], "condivisioni viste", None),
        (conti["nodi"], "dispositivi letti", None),
    ])

    foglio.titolo_sezione("Firma dei messaggi non richiesta")
    foglio.paragrafo(
        "Con la firma abilitata ma NON richiesta, un client puo' scegliere di non"
        " firmare: la sessione diventa alterabile da chi sta in mezzo, ed e'"
        " esattamente il presupposto degli attacchi di inoltro NTLM. \"Abilitata\" non"
        " basta: deve essere \"richiesta\".")
    if dati["senza_firma"]:
        foglio.tabella(
            ["DISPOSITIVO", "INDIRIZZO", "SISTEMA", "RETE", "FIRMA"],
            [[str(v.get("hostname") or v.get("device_label") or "-"),
              str(v["ip"]), str(v.get("os_name") or "-"),
              str(v.get("cidr") or "-"), str(v["firma"])]
             for v in dati["senza_firma"][:MAX_RIGHE_ELENCO]],
            larghezze=[22, 14, 22, 16, 26])
        if len(dati["senza_firma"]) > MAX_RIGHE_ELENCO:
            foglio.paragrafo("Mostrati i primi %d di %d."
                             % (MAX_RIGHE_ELENCO, len(dati["senza_firma"])))
    else:
        foglio.paragrafo("Nessun dispositivo letto dichiara la firma come non"
                         " richiesta.")

    foglio.titolo_sezione("Protocollo SMB 1.0 ancora attivo")
    foglio.paragrafo(
        "SMB 1.0 e' ritirato da Microsoft e non riceve correzioni: dove risponde,"
        " risponde anche a chi lo sfrutta. Nell'elenco dei dialetti si riconosce dal"
        " nome storico \"NT LM 0.12\": un dispositivo che dichiara anche 3.1.1 resta"
        " esposto finche' accetta quel dialetto, perche' e' il client a scegliere.")
    if dati["con_smb1"]:
        foglio.tabella(
            ["DISPOSITIVO", "INDIRIZZO", "SISTEMA", "PROTOCOLLI DICHIARATI"],
            [[str(v.get("hostname") or v.get("device_label") or "-"),
              str(v["ip"]), str(v.get("os_name") or "-"),
              ", ".join(v["protocolli"]) or "-"]
             for v in dati["con_smb1"][:MAX_RIGHE_ELENCO]],
            larghezze=[22, 14, 22, 42])
    else:
        foglio.paragrafo("Nessun dispositivo letto dichiara SMB 1.0.")

    foglio.titolo_sezione("Condivisioni enumerate")
    if dati["con_condivisioni"]:
        foglio.tabella(
            ["DISPOSITIVO", "INDIRIZZO", "CONDIVISIONI"],
            [[str(v.get("hostname") or v.get("device_label") or "-"),
              str(v["ip"]), ", ".join(v["condivisioni"]) or "-"]
             for v in dati["con_condivisioni"][:MAX_RIGHE_ELENCO]],
            larghezze=[24, 16, 66])
    else:
        foglio.paragrafo(
            "Nessuna condivisione enumerata. L'enumerazione riesce solo dove il"
            " dispositivo la concede senza credenziali: dove non compare nulla, il"
            " dispositivo ha rifiutato -- ed e' il comportamento corretto.")

    foglio.titolo_sezione("Tutti i dispositivi letti")
    foglio.paragrafo(
        "Nella colonna FIRMA, \"non richiesta\" sta per \"abilitata ma non"
        " richiesta\": e' la condizione descritta nella sezione 3, non una firma"
        " assente -- quella e' \"non attiva\". Una casella vuota significa che il"
        " dispositivo non ha dichiarato nulla in proposito.")
    if dati["nodi"]:
        foglio.tabella(
            ["DISPOSITIVO", "INDIRIZZO", "SISTEMA", "RETE", "FIRMA", "PROTOCOLLI"],
            [[str(v.get("hostname") or v.get("device_label") or "-"),
              str(v["ip"]), str(v.get("os_name") or "-"),
              str(v.get("cidr") or "-"),
              FIRMA_BREVE.get(v["firma"], v["firma"] or "-"),
              ", ".join(v["protocolli"]) or "-"]
             for v in dati["nodi"][:MAX_RIGHE_ELENCO]],
            larghezze=[22, 13, 21, 15, 13, 24])
        if len(dati["nodi"]) > MAX_RIGHE_ELENCO:
            foglio.paragrafo("Mostrati i primi %d di %d."
                             % (MAX_RIGHE_ELENCO, len(dati["nodi"])))
    else:
        foglio.paragrafo(
            "Nessun dispositivo ha risposto a SMB. La lettura avviene sui soli nodi"
            " con la 139 o la 445 aperta.")

    foglio.salva()
    return percorso
