# -----------------------------------------------------------------
# certificates_report.py — il messaggio dei certificati in scadenza
# Autore: Daniele Speziale
# Data creazione: 2026-09-12
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Il rapporto sui certificati TLS in scadenza, per posta.

A CHE COSA SERVE. Chi rinnova un certificato non lavora davanti alla console: lavora
sul sistema che lo ospita, spesso in una finestra di manutenzione concordata, e ha
bisogno di avere sotto gli occhi TUTTO cio' che serve a rifarlo -- il soggetto esatto,
l'emittente, i nomi alternativi, l'algoritmo, la chiave. Un avviso che dicesse solo
"il certificato di 10.20.10.7 scade fra 12 giorni" costringerebbe a tornare qui per
ogni campo.

Il messaggio porta quindi, per ogni server, il certificato PER INTERO: cio' che il
prodotto ha raccolto e' tutto quello che il certificato dichiara, e qui si riversa
senza sceglierne un sottoinsieme.

DUE CORPI, e non e' un vezzo. Il testo semplice e' quello che sopravvive a qualunque
client di posta, alle regole aziendali che tolgono l'HTML e al copia-incolla in un
ticket; l'HTML rende leggibile un elenco di venti server. Il modulo di notifica del
prodotto li spedisce entrambi (`multipart/alternative`), e il lettore sceglie.

ORDINE: prima cio' che e' gia' scaduto, poi cio' che scade prima. La coda del lavoro
e' gia' ordinata per urgenza, e chi legge non deve cercarla.

COSA NON C'E' DENTRO. Nessuna chiave privata (il prodotto non le vede: legge il
certificato dalla connessione TLS, che e' pubblico) e nessun dato personale. Il
contenuto e' materiale di configurazione, ma resta un elenco di punti deboli
dell'infrastruttura: va spedito a un recapito scelto, non diffuso -- e il registro di
audit conserva a chi e' stato mandato.

remarks: Autore: Daniele Speziale - Data: 2026-09-12
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import json
from datetime import date

from markupsafe import escape

from .db import query

# I campi del certificato, nell'ordine in cui si leggono quando si deve RIFARE un
# certificato: prima chi e' e chi lo ha firmato, poi la validita', poi la crittografia,
# infine i nomi coperti. L'ordine e' la ragione per cui questo elenco e' scritto a mano
# invece di riversare il JSON cosi' com'e'.
CAMPI_CERTIFICATO = (
    ("cert_soggetto_dn", "Soggetto (DN completo)"),
    ("cert_emittente_dn", "Emittente (DN completo)"),
    ("cert_valido_da", "Valido dal"),
    ("cert_valido_a", "Valido fino al"),
    ("cert_seriale", "Numero di serie"),
    ("cert_versione", "Versione"),
    ("cert_algoritmo_firma", "Algoritmo di firma"),
    ("cert_chiave", "Chiave"),
    ("cert_sha256", "Impronta SHA-256"),
    ("cert_sha1", "Impronta SHA-1"),
    ("cert_nomi", "Nomi alternativi (DNS)"),
    ("cert_nomi_ip", "Nomi alternativi (IP)"),
    ("cert_uso", "Uso della chiave"),
    ("cert_uso_esteso", "Uso esteso"),
)


def certificati_per_rapporto(tenant_id: int, entro_giorni: int = 30,
                             stato: str = "in_scadenza", oggi: date = None) -> list:
    """I certificati da mettere nel messaggio, con TUTTO cio' che se ne sa.

    LA SELEZIONE SEGUE LA PAGINA, e questo e' il punto. Il campo "Soglia in scadenza
    (giorni)" e le pastiglie del filtro decidono che cosa si sta guardando, e il
    messaggio deve contenere quello -- non un criterio diverso deciso qui:

      `in_scadenza` (predefinito)  scadono FRA 0 E `entro_giorni` giorni. I gia'
                                   scaduti NON ci sono: non stanno scadendo, sono
                                   scaduti, e sono un'altra lista di lavoro;
      `scaduti`                    solo quelli gia' scaduti;
      `tutti`                      scaduti e in scadenza insieme.

    Si rilegge dall'archivio invece di riusare l'elenco della pagina: la pagina mostra
    poche colonne, e il messaggio ne vuole molte di piu' -- fra cui quelle che stanno
    solo dentro `cert_json`.
    """
    oggi = oggi or date.today()
    righe = query(
        "SELECT n.id AS node_id, n.ip, n.hostname, n.device_label, n.device_type,"
        " n.os_name, w.port, w.scheme, w.cert_subject, w.cert_issuer, w.cert_expires,"
        " w.cert_selfsigned, w.tls_version, w.cert_json, w.title, w.server_header,"
        " w.product, w.collected_at"
        " FROM node_web w JOIN nodes n ON n.id = w.node_id"
        " WHERE w.tenant_id = ? AND w.scheme = 'https'"
        " AND w.cert_expires IS NOT NULL AND w.cert_expires != ''",
        (int(tenant_id),))

    voci = []
    for riga in righe:
        voce = dict(riga)
        try:
            scadenza = date.fromisoformat(str(riga["cert_expires"])[:10])
            voce["giorni"] = (scadenza - oggi).days
        except (ValueError, TypeError):
            # Una data illeggibile non si perde e non si conta: entra in fondo, con
            # il proprio testo. Toglierla sarebbe nascondere un certificato che
            # esiste solo perche' il prodotto non ne sa leggere la data.
            voce["giorni"] = None
        voce["scaduto"] = voce["giorni"] is not None and voce["giorni"] < 0
        try:
            voce["dettaglio"] = json.loads(riga["cert_json"] or "{}")
        except (TypeError, ValueError):
            voce["dettaglio"] = {}
        voci.append(voce)

    soglia = int(entro_giorni)
    if stato == "scaduti":
        scelti = [v for v in voci if v["scaduto"]]
    elif stato == "tutti":
        scelti = [v for v in voci
                  if v["giorni"] is not None and v["giorni"] <= soglia]
    else:
        # "In scadenza" significa che scadranno: da oggi compreso fino alla soglia.
        # Un certificato gia' scaduto non sta scadendo -- e' un'altra coda di lavoro,
        # piu' urgente, e mescolarla qui la renderebbe meno visibile.
        scelti = [v for v in voci
                  if v["giorni"] is not None and 0 <= v["giorni"] <= soglia]

    # Prima gli scaduti (giorni negativi), poi per scadenza piu' vicina. Le date
    # illeggibili in fondo: non si sa quando scadono, quindi non si sa se urgono.
    scelti.sort(key=lambda v: (v["giorni"] is None,
                               v["giorni"] if v["giorni"] is not None else 0))
    return scelti


def _nome_server(voce: dict) -> str:
    """Come si chiama questo server in una riga: il nome se c'e', l'indirizzo sempre."""
    nome = (voce.get("hostname") or voce.get("device_label") or "").strip()
    indirizzo = "%s:%s" % (voce.get("ip") or "?", voce.get("port") or "?")
    return "%s (%s)" % (nome, indirizzo) if nome else indirizzo


def _urgenza(voce: dict) -> str:
    giorni = voce.get("giorni")
    if giorni is None:
        return "scadenza non leggibile"
    if giorni < 0:
        return "SCADUTO da %d giorni" % abs(giorni)
    if giorni == 0:
        return "SCADE OGGI"
    if giorni == 1:
        return "scade domani"
    return "scade fra %d giorni" % giorni


def _valore(voce: dict, campo: str) -> str:
    """Il valore di un campo del certificato, dal dettaglio o dalla colonna."""
    dettaglio = voce.get("dettaglio") or {}
    valore = dettaglio.get(campo)
    if valore in (None, "", [], {}):
        # Alcuni campi hanno anche una colonna propria: si ripiega su quella, cosi'
        # un conferimento vecchio -- fatto prima che il dettaglio esistesse -- non
        # produce un messaggio vuoto.
        ripiego = {"cert_soggetto_dn": "cert_subject",
                   "cert_emittente_dn": "cert_issuer",
                   "cert_valido_a": "cert_expires"}.get(campo)
        valore = voce.get(ripiego) if ripiego else None
    if valore in (None, "", [], {}):
        return ""
    if isinstance(valore, (list, tuple)):
        return ", ".join(str(v) for v in valore)
    if isinstance(valore, bool):
        return "si" if valore else "no"
    return str(valore)


def _riepilogo(voci: list, entro_giorni: int) -> dict:
    scaduti = sum(1 for v in voci if v["scaduto"])
    return {
        "totale": len(voci),
        "scaduti": scaduti,
        "in_scadenza": len(voci) - scaduti,
        "entro": int(entro_giorni),
    }


def oggetto(voci: list, entro_giorni: int, tenant: str = "") -> str:
    """L'oggetto del messaggio: dice il numero e l'urgenza gia' nell'elenco della posta.

    Chi riceve venti messaggi al giorno decide dall'oggetto se aprirlo adesso: un
    oggetto che dicesse solo "Certificati TLS" costringerebbe ad aprirli tutti.
    """
    conto = _riepilogo(voci, entro_giorni)
    if not voci:
        return "[snap%s] Certificati TLS: nessuno in scadenza entro %d giorni" % (
            (" %s" % tenant) if tenant else "", conto["entro"])
    pezzi = []
    if conto["scaduti"]:
        pezzi.append("%d SCADUTI" % conto["scaduti"])
    if conto["in_scadenza"]:
        pezzi.append("%d in scadenza entro %d giorni"
                     % (conto["in_scadenza"], conto["entro"]))
    return "[snap%s] Certificati TLS: %s" % (
        (" %s" % tenant) if tenant else "", ", ".join(pezzi))


def corpo_testo(voci: list, entro_giorni: int, tenant: str = "",
                console_url: str = "", oggi: date = None) -> str:
    """Il messaggio in testo semplice.

    E' il corpo che sopravvive a tutto: alle regole aziendali che tolgono l'HTML, ai
    client vecchi, e al copia-incolla dentro un ticket -- che e' il modo in cui questo
    elenco viene usato davvero.
    """
    oggi = oggi or date.today()
    conto = _riepilogo(voci, entro_giorni)
    righe = [
        "Certificati TLS in scadenza%s" % ((" - %s" % tenant) if tenant else ""),
        "=" * 70,
        "",
        "Rilevazione del %s. Soglia: %d giorni." % (oggi.isoformat(), conto["entro"]),
        "Certificati segnalati: %d (%d gia' scaduti, %d in scadenza)."
        % (conto["totale"], conto["scaduti"], conto["in_scadenza"]),
        "",
    ]
    if not voci:
        righe += [
            "Nessun certificato risulta scaduto o in scadenza entro la soglia.",
            "",
            "Questo elenco riguarda i soli certificati che le sonde hanno potuto",
            "leggere aprendo una connessione HTTPS: un servizio non raggiungibile",
            "dalla sonda non compare, e la sua assenza non e' una conferma.",
        ]
        return "\n".join(righe)

    for numero, voce in enumerate(voci, 1):
        righe.append("-" * 70)
        righe.append("%d. %s  --  %s" % (numero, _nome_server(voce), _urgenza(voce)))
        righe.append("")
        contesto = [
            ("Indirizzo", "%s:%s (%s)" % (voce.get("ip") or "?", voce.get("port") or "?",
                                          voce.get("scheme") or "https")),
            ("Nome host", voce.get("hostname") or ""),
            ("Dispositivo", voce.get("device_label") or voce.get("device_type") or ""),
            ("Sistema operativo", voce.get("os_name") or ""),
            ("Prodotto web", voce.get("product") or voce.get("server_header") or ""),
            ("Titolo della pagina", voce.get("title") or ""),
            ("Autofirmato", "si" if voce.get("cert_selfsigned") else "no"),
            ("TLS negoziato", voce.get("tls_version") or ""),
        ]
        for etichetta, valore in contesto:
            if valore:
                righe.append("   %-24s %s" % (etichetta + ":", valore))
        righe.append("")
        for campo, etichetta in CAMPI_CERTIFICATO:
            valore = _valore(voce, campo)
            if valore:
                righe.append("   %-24s %s" % (etichetta + ":", valore))
        if voce.get("collected_at"):
            righe.append("")
            righe.append("   %-24s %s" % ("Letto il:", voce["collected_at"]))
        righe.append("")

    righe.append("-" * 70)
    righe.append("")
    if console_url:
        righe.append("Elenco aggiornato: %s" % console_url.rstrip("/"))
    righe.append(
        "Questo elenco riguarda i soli certificati che le sonde hanno potuto leggere")
    righe.append(
        "aprendo una connessione HTTPS: un servizio non raggiungibile dalla sonda non")
    righe.append("compare, e la sua assenza non e' una conferma.")
    return "\n".join(righe)


def corpo_html(voci: list, entro_giorni: int, tenant: str = "",
               console_url: str = "", oggi: date = None) -> str:
    """Il messaggio in HTML: stili in linea, perche' i client di posta tolgono i fogli.

    Nessuna immagine e nessun riferimento esterno: un messaggio che carica risorse da
    fuori dichiara a chi le ospita che e' stato aperto, e qui non serve a nulla.
    """
    oggi = oggi or date.today()
    conto = _riepilogo(voci, entro_giorni)
    testa = (
        '<div style="font-family:Segoe UI,Arial,sans-serif;color:#212529;'
        'max-width:900px">'
        '<h2 style="margin:0 0 4px">Certificati TLS in scadenza%s</h2>'
        '<p style="margin:0 0 16px;color:#6c757d;font-size:13px">'
        'Rilevazione del %s &middot; soglia %d giorni &middot; '
        '<strong>%d</strong> segnalati (<strong>%d</strong> gia&#39; scaduti, '
        '<strong>%d</strong> in scadenza)</p>'
        % (escape(" - %s" % tenant) if tenant else "", escape(oggi.isoformat()),
           conto["entro"], conto["totale"], conto["scaduti"], conto["in_scadenza"]))

    if not voci:
        return testa + (
            '<p>Nessun certificato risulta scaduto o in scadenza entro la soglia.</p>'
            '<p style="color:#6c757d;font-size:12px">Questo elenco riguarda i soli '
            'certificati che le sonde hanno potuto leggere aprendo una connessione '
            'HTTPS.</p></div>')

    pezzi = [testa]
    for voce in voci:
        colore = "#842029" if voce["scaduto"] else (
            "#664d03" if (voce.get("giorni") or 999) <= 7 else "#0f5132")
        sfondo = "#f8d7da" if voce["scaduto"] else (
            "#fff3cd" if (voce.get("giorni") or 999) <= 7 else "#d1e7dd")
        pezzi.append(
            '<div style="border:1px solid #dee2e6;border-radius:6px;margin:0 0 14px">'
            '<div style="background:%s;color:%s;padding:8px 12px;font-weight:600;'
            'border-radius:6px 6px 0 0">%s &mdash; %s</div>'
            '<table style="width:100%%;border-collapse:collapse;font-size:13px">'
            % (sfondo, colore, escape(_nome_server(voce)), escape(_urgenza(voce))))

        def riga(etichetta: str, valore: str) -> str:
            return ('<tr><td style="padding:4px 12px;color:#6c757d;width:210px;'
                    'vertical-align:top;border-top:1px solid #f1f3f5">%s</td>'
                    '<td style="padding:4px 12px;vertical-align:top;'
                    'border-top:1px solid #f1f3f5;word-break:break-all">%s</td></tr>'
                    % (escape(etichetta), escape(valore)))

        for etichetta, valore in (
                ("Indirizzo", "%s:%s" % (voce.get("ip") or "?", voce.get("port") or "?")),
                ("Nome host", voce.get("hostname") or ""),
                ("Dispositivo", voce.get("device_label") or voce.get("device_type") or ""),
                ("Sistema operativo", voce.get("os_name") or ""),
                ("Prodotto web", voce.get("product") or voce.get("server_header") or ""),
                ("Titolo della pagina", voce.get("title") or ""),
                ("Autofirmato", "si" if voce.get("cert_selfsigned") else "no"),
                ("TLS negoziato", voce.get("tls_version") or "")):
            if valore:
                pezzi.append(riga(etichetta, str(valore)))
        for campo, etichetta in CAMPI_CERTIFICATO:
            valore = _valore(voce, campo)
            if valore:
                pezzi.append(riga(etichetta, valore))
        if voce.get("collected_at"):
            pezzi.append(riga("Letto il", str(voce["collected_at"])))
        pezzi.append("</table></div>")

    if console_url:
        pezzi.append('<p style="font-size:12px"><a href="%s">Elenco aggiornato nella '
                     'console</a></p>' % escape(console_url.rstrip("/")))
    pezzi.append(
        '<p style="color:#6c757d;font-size:12px">Questo elenco riguarda i soli '
        'certificati che le sonde hanno potuto leggere aprendo una connessione HTTPS: '
        'un servizio non raggiungibile dalla sonda non compare, e la sua assenza non '
        'e&#39; una conferma.</p></div>')
    return "".join(pezzi)
