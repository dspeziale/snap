# -----------------------------------------------------------------
# render_eu.py — fascicolo di conformita' al quadro europeo di cybersecurity
# Autore: Daniele Speziale
# Data creazione: 2026-08-31
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Il documento di conformita' europea: NIS2, CRA, GDPR, ETSI, ACN.

Stessa grafica degli altri report (frontespizio, fascia per genere, testatina,
tabelle a righe alternate): un fascicolo che sembrasse un altro prodotto perderebbe la
riconoscibilita' che serve a chi ha cinque documenti sulla scrivania.

Struttura, e perche' in questo ordine
-------------------------------------
1. **Che cosa dimostra e che cosa non dimostra**: prima di tutto. Un fascicolo che
   promette di coprire tutta la NIS2 con una scansione di rete fa danno a chi lo
   presenta -- l'auditor smette di credere anche alle parti vere.
2. **Copertura delle prove**: quanta parte del perimetro e' stata osservata. Senza
   questo numero ogni altro numero del documento e' senza scala.
3. **Una sezione per norma**, con il riferimento puntuale (articolo o provision), che
   cosa chiede, che cosa si prova, e il limite dichiarato.
4. **Rilievi**, in ordine di gravita': e' la pagina che si legge per decidere.
5. **Riferimenti normativi**, per chi deve risalire al testo.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from .eu_compliance import (
    DA_COLMARE,
    DIMOSTRATO,
    FUORI_PORTATA,
    PARZIALE,
)
from .render_pdf import (
    ATTENZIONE,
    CRITICO,
    INCHIOSTRO,
    INCHIOSTRO_2,
    INCHIOSTRO_3,
    OK,
    Foglio,
    riferimenti_comuni,
)

SEZIONI = [
    "Che cosa dimostra questo fascicolo",
    "Copertura delle prove",
    "NIS2 - Direttiva (UE) 2022/2555",
    "Cyber Resilience Act - Reg. (UE) 2024/2847",
    "GDPR - Reg. (UE) 2016/679",
    "ETSI EN 303 645 - dispositivi connessi",
    "Linee guida ACN / AgID e OWASP",
    "Rilievi in ordine di gravita'",
    "Riferimenti normativi",
]

# Colore dell'esito: la stessa scala degli altri documenti, cosi' il significato non
# cambia da un report all'altro.
COLORE = {
    DIMOSTRATO: OK,
    PARZIALE: ATTENZIONE,
    DA_COLMARE: CRITICO,
    FUORI_PORTATA: INCHIOSTRO_3,
}

# Come si legge un esito. Sta nel documento perche' un'etichetta senza definizione, in
# un fascicolo di conformita', diventa una discussione.
GLOSSARIO = (
    (DIMOSTRATO, "il dato conservato regge da solo come prova"),
    (PARZIALE, "il dato copre una parte dell'obbligo, e la parte e' dichiarata"),
    (DA_COLMARE, "l'obbligo riguarda qualcosa che si puo' fare e non e' stato fatto"),
    (FUORI_PORTATA, "l'obbligo non si dimostra con un inventario di rete: serve"
                    " documentazione di organizzazione"),
)

TITOLI_NORMA = {
    "nis2": "NIS2 - Direttiva (UE) 2022/2555",
    "cra": "Cyber Resilience Act - Reg. (UE) 2024/2847",
    "gdpr": "GDPR - Reg. (UE) 2016/679",
    "etsi": "ETSI EN 303 645 - dispositivi connessi",
    "acn": "Linee guida ACN / AgID e OWASP",
}


def _quota(parte: int, totale: int) -> int:
    return int(round(parte * 100.0 / totale)) if totale else 0


def _sezione_norma(foglio, chiave: str, dati: dict) -> None:
    """Una norma: la sintesi in tabella, poi ogni requisito con la sua prova."""
    voci = dati["per_norma"].get(chiave) or []
    foglio.titolo_sezione(TITOLI_NORMA[chiave], "%d requisiti valutati" % len(voci))
    if not voci:
        foglio.paragrafo("Nessun requisito valutato per questa norma.", INCHIOSTRO_3)
        return

    foglio.tabella(
        ["riferimento", "requisito", "esito"],
        [[v["riferimento"], v["requisito"], v["esito"].upper()] for v in voci],
        larghezze=[1.8, 3.4, 1.0], allineamento=["l", "l", "r"])

    for voce in voci:
        foglio.paragrafo("%s - %s" % (voce["riferimento"], voce["esito"].upper()),
                         COLORE.get(voce["esito"], INCHIOSTRO))
        foglio.paragrafo("Che cosa chiede: %s" % voce["requisito"], INCHIOSTRO_2)
        foglio.paragrafo("Che cosa si prova: %s" % voce["prova"], INCHIOSTRO_2)
        if voce["limite"]:
            foglio.paragrafo("Limite dichiarato: %s" % voce["limite"], INCHIOSTRO_3)


def eu_compliance_report(percorso, dati: dict) -> str:
    """Compone il fascicolo. `dati` come lo prepara `eu_compliance.pacchetto`."""
    m = dati["misure"]
    conteggi = dati["conteggi"]

    foglio = Foglio(
        percorso, kind="eu_compliance",
        titolo="Conformita' al quadro europeo di cybersecurity",
        sottotitolo="Che cosa possiamo dimostrare, norma per norma",
        tenant=dati["tenant"]["nome"], intervallo=dati["intervallo"],
        generato=dati["generato_utc"], fuso=dati["tenant"].get("fuso"),
        scopo=[
            "NIS2, Cyber Resilience Act e GDPR non chiedono strumenti: chiedono"
            " prove. Questo fascicolo mette accanto a ciascun obbligo il dato che"
            " l'inventario conserva, con il suo limite.",
            "Ogni riga si puo' verificare nella console: i numeri sono gli stessi degli"
            " altri report, calcolati dalle stesse interrogazioni.",
        ],
        sezioni=SEZIONI,
        riferimenti=riferimenti_comuni(dati, extra=[
            ("Requisiti valutati", len(dati["requisiti"])),
            ("Norme considerate", len(dati["norme"])),
        ]),
        nota=("Documento prodotto dai dati gia' raccolti dalle sonde e conservati sul"
              " server: nessuna scansione e' stata avviata per produrlo. Non e' una"
              " certificazione ne' una dichiarazione di conformita': e' l'insieme delle"
              " prove tecniche disponibili alla data indicata."),
        orizzontale=False,
    )

    foglio.riquadri([
        (conteggi.get(DIMOSTRATO, 0), "dimostrati", OK),
        (conteggi.get(PARZIALE, 0), "parziali",
         ATTENZIONE if conteggi.get(PARZIALE) else OK),
        (conteggi.get(DA_COLMARE, 0), "da colmare",
         CRITICO if conteggi.get(DA_COLMARE) else OK),
        (conteggi.get(FUORI_PORTATA, 0), "fuori portata", INCHIOSTRO_3),
    ])

    # --- 1 ----------------------------------------------------------------- #
    foglio.titolo_sezione("Che cosa dimostra questo fascicolo")
    foglio.paragrafo(
        "Un inventario di rete dimostra i FATTI TECNICI: che cosa esiste, che cosa"
        " espone, che cosa e' cambiato, chi ha fatto che cosa e quando. Non dimostra le"
        " politiche, la formazione del personale, i contratti con i fornitori, la"
        " valutazione del rischio: quelle sono carte di organizzazione e vanno allegate"
        " a parte. Dirlo qui non e' una excusatio: e' la ragione per cui le parti"
        " tecniche di questo documento si possono prendere per buone.", INCHIOSTRO_2)
    foglio.elenco(["%s: %s" % (esito.upper(), spiegazione)
                   for esito, spiegazione in GLOSSARIO])
    foglio.paragrafo(
        "Il fascicolo copre il quadro europeo che riguarda una rete in esercizio:"
        " NIS2 (con il recepimento italiano, D.lgs. 138/2024), Cyber Resilience Act,"
        " GDPR per le misure tecniche, ETSI EN 303 645 per i dispositivi connessi, e le"
        " linee guida ACN/AgID con OWASP come baseline di verifica.", INCHIOSTRO_2)

    # --- 2 ----------------------------------------------------------------- #
    copertura = _quota(m["subnet_scansionate"], m["subnet_totali"])
    foglio.titolo_sezione("Copertura delle prove",
                          "%d%% del perimetro dichiarato" % copertura)
    foglio.paragrafo(
        "Senza questo numero ogni altro numero del documento e' senza scala: un"
        " \"nessun riscontro critico\" vale molto se la rete e' osservata per intero e"
        " niente se se ne guarda un quarto.", INCHIOSTRO_2)
    foglio.tabella(
        ["misura", "valore", "che cosa significa"],
        [["Subnet dichiarate nel perimetro", m["subnet_totali"],
          "il perimetro che l'organizzazione ha deciso di sorvegliare"],
         ["Subnet scansionate almeno una volta", m["subnet_scansionate"],
          "%d%% del perimetro: sul resto l'inventario non dice nulla" % copertura],
         ["Subnet con dispositivi trovati", m["subnet_osservate"],
          "le altre sono dichiarate e mute: spente, filtrate o non usate"],
         ["Dispositivi in inventario", m["nodi"],
          "%d con un tipo attribuito in modo affidabile" % m["nodi_identificati"]],
         ["Dispositivi che dichiarano se stessi", m["nodi_con_dichiarazione"],
          "modello letto dalla loro interfaccia di gestione, non dedotto"],
         ["Sonde attive", m["sonde"],
          "ultima consegna: %s" % (foglio.istante(m["ultima_consegna"]))],
         ["Subnet con zona dichiarata", m["zone_dichiarate"],
          "la segmentazione descritta, su cui si giudicano le esposizioni"]],
        larghezze=[2.4, .8, 3.4], allineamento=["l", "r", "l"])

    # --- 3..7 -------------------------------------------------------------- #
    for chiave in ("nis2", "cra", "gdpr", "etsi", "acn"):
        _sezione_norma(foglio, chiave, dati)

    # --- 8 ----------------------------------------------------------------- #
    rilievi = dati["rilievi"]
    foglio.titolo_sezione("Rilievi in ordine di gravita'",
                          "%d da trattare" % len(rilievi))
    if rilievi:
        foglio.tabella(
            ["norma", "riferimento", "esito", "che cosa manca"],
            [[TITOLI_NORMA.get(v["norma"], v["norma"]).split(" - ")[0],
              v["riferimento"], v["esito"].upper(),
              v["limite"] or v["prova"]] for v in rilievi],
            larghezze=[1.0, 1.6, .9, 4.0], allineamento=["l", "l", "r", "l"])
        foglio.paragrafo(
            "L'ordine e' quello della gravita' dell'esito, non della difficolta' della"
            " correzione: il primo rilievo non e' necessariamente il primo lavoro da"
            " fare, ed e' una decisione che resta all'organizzazione.", INCHIOSTRO_3)
    else:
        foglio.paragrafo(
            "Nessun rilievo tecnico aperto alla data del documento. Restano gli"
            " obblighi fuori portata di un inventario, elencati nelle rispettive"
            " sezioni.", OK)

    # --- 9 ----------------------------------------------------------------- #
    foglio.titolo_sezione("Riferimenti normativi")
    foglio.tabella(
        ["norma", "recepimento / stato", "ambito"],
        [[n["titolo"], n["recepimento"], n["ambito"]] for n in dati["norme"]],
        larghezze=[2.2, 1.8, 3.0])
    foglio.paragrafo(
        "I riferimenti puntuali (articoli, allegati, provision) sono indicati in"
        " ciascun requisito. Il documento e' redatto secondo la struttura documentale"
        " della ISO/IEC/IEEE 29148:2018 per la parte di requisiti e verifica.",
        INCHIOSTRO_3)

    foglio.salva()
    return str(percorso)
