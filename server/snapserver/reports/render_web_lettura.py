# -----------------------------------------------------------------
# render_web_lettura.py — PDF della lettura delle interfacce di gestione di un nodo
# Autore: Daniele Speziale
# Data creazione: 2026-08-31
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Il PDF di cio' che si e' letto navigando le pagine di un apparato.

Che cosa contiene, e che cosa non puo' contenere
-----------------------------------------------
Contiene tutto quello che il prodotto conserva della lettura: i fatti dichiarati
dall'apparato (nome, marca, modello, posizione fisica, nome host, numero di serie,
firmware, contatto), il **percorso delle pagine** aperte per arrivarci con il loro
esito, le intestazioni del servizio, il certificato, il verdetto delle firme e
l'impronta del contenuto.

**Non** contiene l'immagine della pagina, e non perche' sia difficile: il contenuto
delle pagine non viene conservato (GDPR art. 5, minimizzazione -- una pagina di
gestione contiene spesso nomi, recapiti e code di stampa). Cio' che si puo' stampare e'
cio' che si e' scelto di tenere. L'impronta del contenuto serve a dire se la pagina e'
cambiata dall'ultima lettura, non a ricostruirla.

Per vedere la pagina come e' adesso c'e' il collegamento diretto all'apparato: e' un
click, e non lascia una copia in archivio.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from .render_pdf import (
    ATTENZIONE,
    CRITICO,
    INCHIOSTRO,
    INCHIOSTRO_2,
    INCHIOSTRO_3,
    OK,
    Foglio,
)

# Etichette dei fatti, nell'ordine in cui si leggono: prima chi e', poi dov'e', poi i
# numeri che servono all'assistenza.
CAMPI = (
    ("device_name", "Nome dichiarato"),
    ("brand", "Marca"),
    ("model", "Modello"),
    ("location", "Posizione fisica"),
    ("host_name", "Nome host dichiarato"),
    ("serial", "Numero di serie"),
    ("firmware", "Firmware"),
    ("contact", "Contatto"),
)

TECNICI = (
    ("title", "Titolo della pagina"),
    ("server_header", "Server dichiarato"),
    ("generator", "Generatore"),
    ("realm", "Realm dell'autenticazione"),
    ("product", "Prodotto riconosciuto"),
    ("version", "Versione riconosciuta"),
    ("signature", "Firma che ha deciso"),
    ("cert_subject", "Certificato: soggetto"),
    ("cert_issuer", "Certificato: emittente"),
    ("cert_expires", "Certificato: scadenza"),
    ("tls_version", "Versione TLS"),
    ("body_hash", "Impronta del contenuto"),
)


def _valore(voce: dict, chiave: str) -> str:
    valore = voce.get(chiave)
    if valore is None or valore == "":
        return ""
    return str(valore)


def lettura_web(percorso, dati: dict) -> str:
    """Compone il PDF della lettura. `dati` come lo prepara `dataset_web_lettura`."""
    nodo = dati["nodo"]
    letture = dati["letture"]

    foglio = Foglio(
        percorso, kind="device",
        titolo="Lettura delle interfacce di gestione",
        sottotitolo="Che cosa dichiara di se' %s" % nodo["ip"],
        tenant=dati["tenant"]["nome"], intervallo=dati["intervallo"],
        fuso=dati["tenant"].get("fuso"),
        generato=dati["generato_utc"], autore=dati.get("autore", ""),
        scopo=[
            "Cio' che la sonda ha letto aprendo le interfacce di gestione di %s,"
            " seguendo il percorso che l'apparato stesso indica." % nodo["ip"],
            "Sono dichiarazioni dell'apparato, non deduzioni del prodotto: ogni riga"
            " porta la porta e la pagina da cui viene.",
        ],
        sezioni=["Che cosa dichiara l'apparato", "Percorso seguito",
                 "Dati tecnici del servizio", "Certificato digitale (TLS)",
                 "Perche' non c'e' l'immagine della pagina"],
        nota=("Documento prodotto dai dati gia' conservati sul server: nessuna"
              " scansione e' stata avviata per produrlo e nessun apparato e' stato"
              " contattato adesso."),
        orizzontale=False,
    )

    foglio.riquadri([
        (len(letture), "interfacce lette", INCHIOSTRO_2),
        (sum(int(v.get("pages_read") or 0) for v in letture), "pagine aperte",
         INCHIOSTRO_2),
        (len([v for v in letture if v.get("facts_locked")]), "con dati protetti",
         ATTENZIONE if [v for v in letture if v.get("facts_locked")] else OK),
        (nodo.get("device_label") or "non identificato", "tipo attribuito",
         OK if (nodo.get("device_confidence") or 0) >= 60 else ATTENZIONE),
    ])

    foglio.titolo_sezione("Che cosa dichiara l'apparato")
    righe = []
    for voce in letture:
        dove = "%s/%s" % (voce.get("scheme") or "http", voce.get("port"))
        for chiave, etichetta in CAMPI:
            valore = _valore(voce, chiave)
            if valore:
                righe.append([dove, etichetta, valore])
        # I fatti aggiuntivi che non hanno una colonna propria (interno e carichi di un
        # telefono IP, misure di uno UPS): arrivano gia' pronti come (etichetta, valore).
        for fatto in voce.get("extra") or []:
            righe.append([dove, fatto["etichetta"], fatto["valore"]])
    if righe:
        foglio.tabella(["dove", "campo", "valore dichiarato"], righe,
                       larghezze=[1.0, 2.0, 3.4])
    else:
        foglio.paragrafo(
            "Nessuna interfaccia ha dichiarato dati di identita'. Accade con gli"
            " apparati che costruiscono la propria pagina in JavaScript e con quelli"
            " che mostrano i dati solo dopo l'accesso: in questi casi si conosce il"
            " genere del servizio, non il modello dell'apparato.", INCHIOSTRO_3)

    protette = [v for v in letture if v.get("facts_locked")]
    if protette:
        foglio.paragrafo(
            "Su %d interfaccia/e la pagina con i dati esiste ma chiede le credenziali:"
            " la sonda non ne ha e non le tenta." % len(protette), ATTENZIONE)

    # La diagnosi ricavata dai registri dell'apparato (oggi lo UPS MGE/Eaton) non e' una
    # riga fra le altre: e' un esito, e va in evidenza in un riquadro colorato, come nel
    # dettaglio a video.
    for voce in letture:
        diagnosi = voce.get("diagnosi") or {}
        if not diagnosi:
            continue
        dove = "%s/%s" % (voce.get("scheme") or "http", voce.get("port"))
        if diagnosi.get("ok"):
            foglio.box(
                [{"testo": "Diagnosi dai registri (%s): nessun problema rilevato."
                  % dove, "grassetto": True, "colore": OK}], colore_barra=OK)
        else:
            elementi = [{"testo": "Diagnosi dai registri (%s): problemi rilevati" % dove,
                         "grassetto": True, "colore": CRITICO}]
            for problema in diagnosi.get("problemi") or []:
                elementi.append({"testo": "- %s" % problema, "colore": INCHIOSTRO,
                                 "rientro": 8})
            foglio.box(elementi, colore_barra=CRITICO)

    foglio.titolo_sezione("Percorso seguito",
                          "un fatto senza la pagina da cui viene non e' verificabile")
    passi = []
    for voce in letture:
        dove = "%s/%s" % (voce.get("scheme") or "http", voce.get("port"))
        for passo in voce.get("pagine") or []:
            passi.append([dove, passo.get("origine") or "",
                          passo.get("percorso") or "",
                          str(passo.get("stato") or passo.get("errore") or "")])
    if passi:
        foglio.tabella(["dove", "come ci si e' arrivati", "pagina", "esito"], passi,
                       larghezze=[.9, 1.4, 3.2, .8],
                       allineamento=["l", "l", "l", "r"])
    else:
        foglio.paragrafo(
            "Il percorso delle pagine non e' disponibile per questa lettura: e'"
            " anteriore alla versione che lo registra.", INCHIOSTRO_3)

    foglio.titolo_sezione("Dati tecnici del servizio")
    tecnici = []
    for voce in letture:
        dove = "%s/%s" % (voce.get("scheme") or "http", voce.get("port"))
        tecnici.append([dove, "Stato HTTP", str(voce.get("status_code") or
                                                voce.get("error") or "-")])
        for chiave, etichetta in TECNICI:
            valore = _valore(voce, chiave)
            if valore:
                tecnici.append([dove, etichetta, valore])
        if voce.get("login_form"):
            tecnici.append([dove, "Modulo di accesso", "presente"])
        if voce.get("collected_at"):
            tecnici.append([dove, "Letta il", foglio.istante(voce["collected_at"])])
    foglio.tabella(["dove", "campo", "valore"], tecnici, larghezze=[1.0, 2.0, 3.4],
                   nota_vuota="Nessun dato tecnico conservato per questo apparato.")

    # Il certificato TLS per intero, dove c'e' HTTPS: soggetto, emittente, validita',
    # chiave, usi, nomi alternativi e impronte. Gli esiti di sicurezza (scaduto,
    # autofirmato) sono detti a parole, non lasciati dedurre da una data.
    con_cert = [v for v in letture if (v.get("cert") or {}).get("righe")]
    if con_cert:
        foglio.titolo_sezione("Certificato digitale (TLS)")
        for voce in con_cert:
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

    foglio.titolo_sezione("Perche' non c'e' l'immagine della pagina")
    foglio.paragrafo(
        "Il contenuto delle pagine di gestione non viene conservato: una pagina di"
        " apparato contiene spesso nomi di persone, recapiti e code di stampa, cioe'"
        " dati personali di cui un inventario non ha bisogno (GDPR art. 5,"
        " minimizzazione). Cio' che si puo' stampare e' cio' che si e' scelto di"
        " tenere: le etichette, il percorso e le impronte.", INCHIOSTRO_2)
    foglio.elenco([
        "L'impronta del contenuto dice se la pagina e' CAMBIATA dall'ultima lettura;"
        " non permette di ricostruirla, ed e' proprio il suo scopo.",
        "Per vedere la pagina come e' adesso c'e' il collegamento diretto"
        " all'apparato nella scheda del dispositivo: e' un click, e non lascia una"
        " copia in archivio.",
        "Le credenziali non vengono mai tentate: un inventario legge il cartello sulla"
        " porta, non prova le chiavi.",
    ])

    foglio.salva()
    return str(percorso)
