# -----------------------------------------------------------------
# render_acn.py — il fascicolo da portare al portale ACN
# Autore: Daniele Speziale
# Data creazione: 2026-08-31
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Il documento che accompagna una comunicazione ad ACN.

Serve a due usi in un foglio solo:

* i **campi da compilare** nel portale, uno per riga, pronti da copiare. Chi sta
  notificando un incidente alle tre di notte non deve cercare i dati in cinque pagine
  diverse della console;
* l'**allegato** da caricare: la cronologia dei fatti, la valutazione di
  significativita' con i suoi criteri, le misure adottate e le comunicazioni interne.

Quello che questo documento NON e' -- ed e' scritto anche dentro il documento -- e' una
notifica inviata. Il portale ACN si usa con identita' digitale e la notifica e' un atto
di una persona identificata: snap prepara e registra, non invia.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from .render_pdf import (
    ATTENZIONE,
    CRITICO,
    INCHIOSTRO_2,
    INCHIOSTRO_3,
    OK,
    Foglio,
    istante_nel_fuso,
)

SEZIONI = [
    "Che cosa e' questo documento",
    "Campi da compilare nel portale",
    "Cronologia dei fatti",
    "Valutazione di significativita'",
    "Misure adottate",
    "Comunicazioni interne",
    "Stato del fascicolo",
]

ETICHETTE_CRITERIO = {
    True: "SI",
    False: "NO",
    None: "da dichiarare",
}


def _riga_valutazione(criterio: dict, valutazione: dict) -> list:
    esiti = (valutazione or {}).get("esiti") or {}
    valore = esiti.get(criterio["chiave"])
    return [criterio["titolo"], ETICHETTE_CRITERIO.get(valore, "-"),
            criterio["domanda"]]


def acn_report(percorso, dati: dict) -> str:
    """Compone il fascicolo. `dati` come lo prepara `acn.fascicolo`."""
    comunicazione = dati["comunicazione"]
    stadio = dati["stadio"]
    inc = dati["incidente"]
    termine = dati["termine"]
    fuso = dati["tenant"]["fuso"]

    foglio = Foglio(
        percorso, kind="acn",
        titolo="Comunicazione ad ACN - %s" % stadio.get("nome", comunicazione["stage"]),
        sottotitolo="Incidente #%s: %s" % (inc["id"], inc.get("controllo") or ""),
        tenant=dati["tenant"]["nome"],
        intervallo="conoscenza dell'incidente: %s"
                   % istante_nel_fuso(comunicazione.get("known_at"), fuso),
        generato=dati.get("generato_utc") or "",
        fuso=fuso,
        scopo=[
            "I campi da compilare sul portale %s e l'allegato da caricare, per lo"
            " stadio \"%s\" (%s)." % (dati["portale"], stadio.get("nome", ""),
                                      stadio.get("termine", "")),
            "Il portale si usa con identita' digitale: questo documento prepara la"
            " comunicazione, non la invia. L'invio resta un atto del punto di contatto.",
        ],
        sezioni=SEZIONI,
        riferimenti=[
            ("Soggetto", dati["tenant"]["nome"]),
            ("Codice tenant", dati["tenant"]["codice"]),
            ("Recapito di riferimento", dati["tenant"]["recapito"] or "non indicato"),
            ("Stadio", stadio.get("nome", comunicazione["stage"])),
            ("Termine", stadio.get("termine", "-")),
            ("Scadenza", istante_nel_fuso(comunicazione.get("deadline_at"), fuso,
                                          "senza termine")),
            ("Stato del fascicolo", termine.get("stato", "-")),
            ("Fuso di riferimento", fuso),
            ("Generato il", istante_nel_fuso(dati.get("generato_utc"), fuso)),
            ("Generato il (UTC)", dati.get("generato_utc") or ""),
        ],
        nota=("Documento preparato dai dati conservati sul server. NON e' una notifica"
              " inviata: l'invio avviene dal portale ACN con identita' digitale del"
              " punto di contatto, e va registrato in console con il numero di"
              " protocollo restituito."),
        orizzontale=False,
    )

    residuo = termine.get("residuo")
    foglio.riquadri([
        (stadio.get("nome", comunicazione["stage"]), "stadio", INCHIOSTRO_2),
        ("%.1f h" % residuo if residuo is not None else "-",
         "al termine" if (residuo or 0) >= 0 else "oltre il termine",
         CRITICO if termine.get("scaduto") else
         ATTENZIONE if termine.get("urgente") else OK),
        (inc.get("severity") or "-", "gravita' dell'incidente",
         CRITICO if (inc.get("severity") or "") == "critical" else ATTENZIONE),
        (comunicazione.get("reference") or "non inviata", "protocollo",
         OK if comunicazione.get("reference") else INCHIOSTRO_3),
    ])

    # --- 1 ----------------------------------------------------------------- #
    foglio.titolo_sezione("Che cosa e' questo documento")
    foglio.paragrafo(
        "E' il fascicolo dello stadio \"%s\" della comunicazione dovuta all'Agenzia per"
        " la Cybersicurezza Nazionale ai sensi dell'art. 23 della direttiva (UE)"
        " 2022/2555, recepita dal D.lgs. 138/2024. Contiene i campi da compilare sul"
        " portale e le prove da allegare."
        % stadio.get("nome", comunicazione["stage"]), INCHIOSTRO_2)
    foglio.elenco([
        "Il portale (%s) si usa con SPID, CIE o CNS del punto di contatto: nessun"
        " programma puo' accedervi al posto suo, e snap non conserva identita'"
        " digitali." % dati["portale"],
        "Dopo l'invio, il numero di protocollo restituito dal portale va registrato in"
        " console: e' cio' che dimostra i tempi in un'ispezione.",
        "La qualifica dell'incidente come significativo e' una valutazione"
        " dell'organizzazione: la sezione 4 riporta i criteri e cio' che i dati"
        " dicono, non una decisione automatica.",
        "Se sono coinvolti dati personali, la notifica al Garante (GDPR art. 33, 72"
        " ore) e' un obbligo distinto: una non sostituisce l'altra.",
    ])

    # --- 2 ----------------------------------------------------------------- #
    foglio.titolo_sezione("Campi da compilare nel portale",
                          "pronti da copiare, uno per riga")
    campi = [
        ["Soggetto notificante", dati["tenant"]["nome"]],
        ["Riferimento interno dell'incidente", "#%s" % inc["id"]],
        ["Stadio della comunicazione", stadio.get("nome", comunicazione["stage"])],
        ["Istante di conoscenza dell'incidente",
         istante_nel_fuso(comunicazione.get("known_at"), fuso)],
        ["Istante di apertura dell'incidente",
         istante_nel_fuso(inc.get("opened_at"), fuso)],
        ["Istante di presa in carico",
         istante_nel_fuso(inc.get("acknowledged_at"), fuso, "non ancora")],
        ["Istante di chiusura",
         istante_nel_fuso(inc.get("resolved_at"), fuso, "ancora aperto")],
        ["Servizio o bersaglio interessato",
         "%s (%s)" % (inc.get("bersaglio") or "-", inc.get("bersaglio_nome") or "")],
        ["Controllo che ha rilevato", "%s (%s)" % (inc.get("controllo") or "-",
                                                   inc.get("genere") or "-")],
        ["Gravita' dichiarata", inc.get("severity") or "-"],
        ["Descrizione sintetica", (inc.get("first_detail") or "")[:400] or "-"],
        ["Situazione al momento della comunicazione",
         (inc.get("last_detail") or "")[:400] or "-"],
        ["Misure adottate", (inc.get("resolution") or "")[:400]
         or "in corso di adozione: vedere sezione 5"],
        ["Sospetto di atto illecito o doloso", "da dichiarare (vedere sezione 4)"],
        ["Effetti su altri soggetti o Stati membri", "da dichiarare (vedere sezione 4)"],
        ["Coinvolgimento di dati personali", "da dichiarare (vedere sezione 4)"],
        ["Recapito per i riscontri", dati["tenant"]["recapito"] or "da indicare"],
    ]
    foglio.tabella(["campo del modulo", "valore da inserire"], campi,
                   larghezze=[2.2, 4.4])
    foglio.paragrafo(
        "I tre campi \"da dichiarare\" non sono lasciati vuoti per dimenticanza: sono"
        " valutazioni che nessuna misura tecnica puo' stabilire, e vanno compilate da"
        " chi conosce il contesto.", INCHIOSTRO_3)

    # --- 3 ----------------------------------------------------------------- #
    cronologia = dati["cronologia"]
    foglio.titolo_sezione("Cronologia dei fatti", "%d verifiche registrate"
                          % len(cronologia))
    if cronologia:
        foglio.tabella(
            ["quando", "esito", "dettaglio"],
            [[foglio.istante(r["executed_at"]), r["status"],
              (r["detail"] or "")] for r in cronologia],
            larghezze=[1.3, .8, 4.5])
    else:
        foglio.paragrafo(
            "Nessuna verifica registrata dopo l'apertura dell'incidente: l'incidente e'"
            " stato aperto e non ci sono state ulteriori esecuzioni del controllo nel"
            " periodo conservato.", INCHIOSTRO_3)

    # --- 4 ----------------------------------------------------------------- #
    valutazione = dati["valutazione"]
    foglio.titolo_sezione("Valutazione di significativita'",
                          "criteri dichiarati, decisione dell'organizzazione")
    foglio.paragrafo(
        "La direttiva chiede di notificare gli incidenti SIGNIFICATIVI. La tabella"
        " riporta i criteri, cio' che i dati dicono e cio' che resta da dichiarare."
        " %s" % (valutazione.get("motivo_proposta") or ""), INCHIOSTRO_2)
    foglio.tabella(
        ["criterio", "dai dati", "domanda a cui rispondere"],
        [_riga_valutazione(c, valutazione) for c in dati["criteri"]],
        larghezze=[1.8, .8, 4.0])
    if valutazione.get("ore_indisponibilita") is not None:
        foglio.paragrafo(
            "Durata dell'indisponibilita' misurata: %s ore (soglia dichiarata: %s ore)."
            % (valutazione.get("ore_indisponibilita"),
               (valutazione.get("soglie") or {}).get("ore_indisponibilita", "-")),
            INCHIOSTRO_2)

    # --- 5 ----------------------------------------------------------------- #
    misure = dati["misure"]
    foglio.titolo_sezione("Misure adottate", "dal registro degli eventi")
    if misure:
        foglio.tabella(
            ["quando", "evento", "operatore", "descrizione"],
            [[foglio.istante(r["created_at"]), r["event_type"],
              r["actor"] or "sistema", r["description"] or ""] for r in misure],
            larghezze=[1.2, 1.2, 1.2, 3.4])
    else:
        foglio.paragrafo("Nessun evento registrato dopo l'apertura dell'incidente.",
                         INCHIOSTRO_3)

    # --- 6 ----------------------------------------------------------------- #
    notifiche = dati["notifiche"]
    foglio.titolo_sezione("Comunicazioni interne", "avvisi inviati dal prodotto")
    foglio.paragrafo(
        "Sono le comunicazioni INTERNE (posta e messaggistica verso gli operatori): non"
        " hanno valore di notifica all'autorita', e sono qui perche' dimostrano quando"
        " l'organizzazione ha saputo.", INCHIOSTRO_2)
    if notifiche:
        foglio.tabella(
            ["canale", "destinatario", "esito", "inviata", "errore"],
            [[r["channel"], r["recipients"], r["status"],
              foglio.istante(r["sent_at"], "-"), r["last_error"] or ""]
             for r in notifiche],
            larghezze=[.8, 2.0, .8, 1.2, 2.0])
    else:
        foglio.paragrafo("Nessuna comunicazione interna registrata nel periodo.",
                         INCHIOSTRO_3)

    # --- 7 ----------------------------------------------------------------- #
    foglio.titolo_sezione("Stato del fascicolo", "tutti gli stadi dell'incidente")
    righe = [[stadio.get("nome", comunicazione["stage"]),
              comunicazione.get("status") or "",
              istante_nel_fuso(comunicazione.get("deadline_at"), fuso, "-"),
              istante_nel_fuso(comunicazione.get("sent_at"), fuso, "-"),
              comunicazione.get("reference") or "-"]]
    for altra in dati["altre"]:
        righe.append([altra.get("stadio_nome") or altra["stage"],
                      altra.get("status") or "",
                      istante_nel_fuso(altra.get("deadline_at"), fuso, "-"),
                      istante_nel_fuso(altra.get("sent_at"), fuso, "-"),
                      altra.get("reference") or "-"])
    foglio.tabella(["stadio", "stato", "scadenza", "inviata il", "protocollo"], righe,
                   larghezze=[1.6, 1.4, 1.4, 1.4, 1.4])
    foglio.paragrafo(
        "Uno stadio dichiarato \"non dovuta\" resta nell'elenco con la propria"
        " motivazione: un elenco in cui le comunicazioni non dovute sparissero non"
        " permetterebbe di distinguere \"non serviva\" da \"ce ne siamo dimenticati\","
        " che e' precisamente la domanda di un ispettore.", INCHIOSTRO_3)

    foglio.salva()
    return str(percorso)
