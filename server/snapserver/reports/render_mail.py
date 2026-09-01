"""
snap server - Corpo del resoconto quotidiano, in testo e in HTML.

Il messaggio e' prodotto dall'APPLICAZIONE: nessun intervento umano, nessuna
elaborazione esterna. Le due forme portano la stessa informazione, perche' un
destinatario che legge il testo semplice non deve ricevere meno di chi vede l'HTML.

Scelte di forma:

* l'oggetto porta il numero delle questioni aperte e la disponibilita': e' l'unica
  parte che si legge in una lista di posta;
* l'ordine e' quello delle decisioni (RP-02): prima cio' che va risolto, poi cio' che
  e' cambiato, poi lo stato;
* le tendenze si rendono con caratteri di blocco e non con immagini: un'immagine
  remota viene bloccata dai client di posta e un SVG in linea non e' supportato. Il
  grafico vero sta nel PDF;
* nessuna immagine, nessun riferimento esterno, nessun tracciamento.

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from html import escape

from .dataset import change_label

# Caratteri di blocco per le tendenze: otto livelli, dal piu' basso al piu' alto.
BLOCCHI = "▁▂▃▄▅▆▇█"
# Un giorno non misurato non riceve un blocco alto ne' uno basso: riceve un segno
# proprio, perche' "non abbiamo guardato" non e' un valore.
NON_MISURATO = "·"

GRAVITA_SEGNO = {"critical": "!!", "warning": "!", "info": " "}


def _sparkline(valori: list) -> str:
    """Rende una serie in caratteri di blocco. `None` diventa il segno di assenza."""
    presenti = [v for v in valori if v is not None]
    if not presenti:
        return NON_MISURATO * len(valori)
    minimo, massimo = min(presenti), max(presenti)
    campo = (massimo - minimo) or 1.0
    resa = []
    for valore in valori:
        if valore is None:
            resa.append(NON_MISURATO)
            continue
        livello = int(round((valore - minimo) / campo * (len(BLOCCHI) - 1)))
        resa.append(BLOCCHI[livello])
    return "".join(resa)


def _durata(minuti) -> str:
    if minuti is None:
        return "in corso"
    if minuti < 60:
        return "%d min" % minuti
    ore, resto = divmod(int(minuti), 60)
    return "%dh%02d" % (ore, resto)


def _percentuale(valore) -> str:
    return "non misurata" if valore is None else ("%.1f%%" % valore).replace(".", ",")


def subject(dati: dict) -> str:
    """Oggetto: numero di questioni aperte e disponibilita'."""
    quante = len(dati["da_risolvere"])
    if quante == 0:
        stato = "nulla da risolvere"
    elif quante == 1:
        stato = "1 da risolvere"
    else:
        stato = "%d da risolvere" % quante
    disponibilita = dati["disponibilita"]["percentuale"]
    coda = ("disponibilita' %s" % _percentuale(disponibilita)
            if disponibilita is not None else "nessuna misura")
    return "snap %s - %s: %s, %s" % (
        dati["tenant"]["codice"].upper(),
        dati["giorno"].strftime("%d/%m"), stato, coda)


# --------------------------------------------------------------------------- #
# Testo semplice
# --------------------------------------------------------------------------- #
def text_body(dati: dict, console_url: str = "") -> str:
    righe = []
    aggiungi = righe.append

    aggiungi("SNAP %s - RESOCONTO DEL %s (%s)"
             % (dati["tenant"]["nome"].upper(),
                dati["giorno"].strftime("%d/%m/%Y"), dati["tenant"]["fuso"]))
    aggiungi("")

    inventario = dati["inventario"]
    disponibilita = dati["disponibilita"]
    quante = len(dati["da_risolvere"])
    aggiungi("%s nodi, disponibilita' dei servizi %s, %s."
             % (inventario.get("nodi") or 0,
                _percentuale(disponibilita["percentuale"]),
                "nessuna questione aperta" if quante == 0
                else ("1 questione da risolvere" if quante == 1
                      else "%d questioni da risolvere" % quante)))

    # --- Da risolvere ---
    if dati["da_risolvere"]:
        aggiungi("")
        aggiungi("DA RISOLVERE")
        for voce in dati["da_risolvere"]:
            segno = GRAVITA_SEGNO.get(voce["gravita"], " ")
            aggiungi("  %-2s %s" % (segno, voce["titolo"]))
            if voce.get("soggetto"):
                aggiungi("     %s" % voce["soggetto"])
            if voce.get("eta_minuti") is not None:
                aggiungi("     aperto da %s%s" % (
                    _durata(voce["eta_minuti"]),
                    ", operatore: %s" % voce["recapito"] if voce.get("recapito") else ""))
            if voce.get("dettaglio"):
                aggiungi("     %s" % voce["dettaglio"])

    # --- Ieri ---
    aggiungi("")
    aggiungi("IL GIORNO %s" % dati["giorno"].strftime("%d/%m"))

    incidenti = dati["incidenti"]
    if incidenti["aperti"] or incidenti["risolti"]:
        aggiungi("  Incidenti: %d aperti, %d risolti%s."
                 % (incidenti["aperti"], incidenti["risolti"],
                    ", durata media %s" % _durata(incidenti["durata_media_minuti"])
                    if incidenti["durata_media_minuti"] is not None else ""))
        for voce in incidenti["voci"]:
            aggiungi("    #%-4s %-8s aperto %s%s, %s fallimenti%s"
                     % (voce["id"], voce["gravita"], voce["aperto"],
                        ", risolto %s (%s)" % (voce["risolto"],
                                               _durata(voce["durata_minuti"]))
                        if voce["risolto"] else " (ancora aperto)",
                        voce["fallimenti"],
                        ", operatore attivato" if voce["scalato"] else ""))
    else:
        aggiungi("  Incidenti: nessuno.")

    if dati["indisponibilita"]:
        aggiungi("  Indisponibilita':")
        for finestra in dati["indisponibilita"]:
            aggiungi("    %-34s %s-%s (%s, %d esiti non riusciti)"
                     % (finestra["indirizzo"][:34], finestra["da"], finestra["a"],
                        _durata(finestra["durata_minuti"]) if not finestra["aperta"]
                        else "in corso", finestra["esiti"]))

    if disponibilita["misurato"]:
        aggiungi("  Controlli: %d esiti, %d riusciti (%s)."
                 % (disponibilita["esiti"], disponibilita["riusciti"],
                    _percentuale(disponibilita["percentuale"])))
        for voce in disponibilita["controlli"]:
            aggiungi("    %-34s %-9s %7s   lat %s ms"
                     % (voce["indirizzo"][:34], voce["genere"],
                        _percentuale(voce["percentuale"]),
                        int(voce["latenza_media"]) if voce["latenza_media"] else "?"))
    else:
        aggiungi("  Controlli: nessuna esecuzione nella giornata (non misurata).")

    base = dati["rilevamento_base"]
    variazioni = dati["variazioni"]
    if base["attivo"]:
        aggiungi("  Inventario: rilevamento di base in corso (giorno %d di %d)."
                 % (base["giorno"], base["di"]))
        for genere in variazioni["generi"]:
            aggiungi("    %s: %d" % (change_label(genere["genere"]), genere["eventi"]))
        if base["fine"]:
            aggiungi("    Le variazioni verranno elencate a partire dal %s."
                     % base["fine"].strftime("%d/%m"))
    elif variazioni["totale"]:
        aggiungi("  Variazioni dell'inventario: %d." % variazioni["totale"])
        for genere in variazioni["generi"]:
            if genere["aggregato"]:
                aggiungi("    %s: %d eventi su %d nodi (fatto aggregato: oltre un"
                         " quinto della rete)"
                         % (change_label(genere["genere"]), genere["eventi"],
                            genere["nodi"]))
                continue
            aggiungi("    %s: %d" % (change_label(genere["genere"]), genere["eventi"]))
            for esempio in genere["esempi"]:
                dettaglio = " (%s -> %s)" % (esempio["da"], esempio["a"]) \
                    if esempio["da"] or esempio["a"] else ""
                aggiungi("      %s%s" % (esempio["soggetto"], dettaglio))
    else:
        aggiungi("  Variazioni dell'inventario: nessuna.")

    raccolta = dati["raccolta"]
    aggiungi("  Raccolta: %d passate, %d non completate. Lotti %s, record %s."
             % (raccolta["passate_totali"], raccolta["passate_fallite"],
                raccolta["lotti"].get("lotti", 0), raccolta["lotti"].get("record", 0)))
    for sonda in raccolta["sonde"]:
        aggiungi("    Sonda \"%s\": %s, ultimo contatto %s%s"
                 % (sonda["nome"], sonda["stato"], sonda["ultimo_contatto"],
                    "" if sonda["scansione_attiva"] else ", scansione sospesa"))

    # --- Tendenze ---
    giorni = dati["tendenze"]["giorni"]
    if giorni:
        aggiungi("")
        aggiungi("TENDENZE (%d giorni)" % len(giorni))
        aggiungi("  Disponibilita'   %s  %s"
                 % (_sparkline([g["disponibilita"] for g in giorni]),
                    _percentuale(giorni[-1]["disponibilita"])))
        aggiungi("  Latenza p95      %s  %s"
                 % (_sparkline([g["latenza_p95"] for g in giorni]),
                    "%d ms" % giorni[-1]["latenza_p95"]
                    if giorni[-1]["latenza_p95"] else "non misurata"))
        non_misurati = [g for g in giorni if not g["misurato"]]
        if non_misurati:
            aggiungi("  (%d giorni senza misure, resi con \"%s\")"
                     % (len(non_misurati), NON_MISURATO))

    # --- Igiene ---
    igiene = dati["igiene"]
    aggiungi("")
    aggiungi("IGIENE")
    aggiungi("  %s subnet dichiarate, %s host teorici, %s nodi trovati%s."
             % (inventario.get("subnet_dichiarate") or 0,
                inventario.get("subnet_teorici") or 0, inventario.get("nodi") or 0,
                " (occupazione %s%%)" % str(inventario["occupazione"]).replace(".", ",")
                if inventario.get("occupazione") is not None else ""))
    aggiungi("  %d controlli sospesi, %d bersagli senza controlli, %s nodi non"
             " identificati, %s porte sospette."
             % (len(igiene["controlli_sospesi"]),
                len(igiene["bersagli_senza_controlli"]),
                igiene["nodi_non_identificati"], igiene["porte_sospette"]))
    for voce in igiene["controlli_sospesi"]:
        aggiungi("    sospeso: %s (%s)" % (voce["name"], voce["address"]))

    # --- Chiusura ---
    aggiungi("")
    aggiungi("Intervallo %s. Generato da snap alle %s."
             % (dati["intervallo"], dati["generato_utc"]))
    if console_url:
        aggiungi("Console: %s" % console_url)
    return "\n".join(righe)


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
def _stile(nome: str) -> str:
    """Stili in linea: i client di posta ignorano i fogli di stile."""
    stili = {
        "corpo": "margin:0;padding:16px;background:#f3f6f8;color:#131a1f;"
                 "font-family:'PT Sans','Segoe UI',Arial,sans-serif;font-size:14px;"
                 "line-height:1.5",
        "scheda": "max-width:760px;margin:0 auto;background:#ffffff;"
                  "border:1px solid #d6dee4;border-radius:3px;padding:20px",
        "titolo": "margin:0 0 4px;font-family:'PT Sans Narrow',Arial,sans-serif;"
                  "font-size:22px;font-weight:700",
        "sotto": "margin:0 0 16px;color:#3f515d;font-size:13px",
        "sezione": "margin:20px 0 6px;font-family:'PT Sans Narrow',Arial,sans-serif;"
                   "font-size:12px;font-weight:700;letter-spacing:.12em;"
                   "text-transform:uppercase;color:#6d8290;"
                   "border-bottom:1px solid #d6dee4;padding-bottom:3px",
        "tabella": "width:100%;border-collapse:collapse;font-size:13px",
        "th": "text-align:left;padding:4px 6px;border-bottom:1px solid #d6dee4;"
              "color:#6d8290;font-family:'PT Sans Narrow',Arial,sans-serif;"
              "font-size:12px;letter-spacing:.06em;text-transform:uppercase",
        "td": "padding:4px 6px;border-bottom:1px solid #eef2f5;vertical-align:top",
        "mono": "font-family:'PT Mono',Consolas,monospace;font-size:12px",
        "pie": "margin-top:20px;padding-top:10px;border-top:1px solid #d6dee4;"
               "color:#6d8290;font-size:12px",
        "critico": "border-left:3px solid #a32620;padding:6px 10px;margin:6px 0;"
                   "background:#fbf1f0",
        "attenzione": "border-left:3px solid #8f5600;padding:6px 10px;margin:6px 0;"
                      "background:#fdf7ee",
        "sereno": "border-left:3px solid #1b7247;padding:6px 10px;margin:6px 0;"
                  "background:#f0f8f3",
    }
    return stili[nome]


def html_body(dati: dict, console_url: str = "") -> str:
    inventario = dati["inventario"]
    disponibilita = dati["disponibilita"]
    incidenti = dati["incidenti"]
    parti = []
    scrivi = parti.append


    quante = len(dati["da_risolvere"])
    stile_stato = "critico" if any(v["gravita"] == "critical" for v in dati["da_risolvere"]) \
        else ("attenzione" if quante else "sereno")
    scrivi('<div style="%s"><b>%s nodi</b> &middot; disponibilita\' dei servizi'
           ' <b>%s</b> &middot; %s</div>'
           % (_stile(stile_stato), inventario.get("nodi") or 0,
              _percentuale(disponibilita["percentuale"]),
              "nessuna questione aperta" if quante == 0
              else "<b>%d da risolvere</b>" % quante))

    if dati["da_risolvere"]:
        scrivi('<div style="%s">Da risolvere</div>' % _stile("sezione"))
        for voce in dati["da_risolvere"]:
            stile = "critico" if voce["gravita"] == "critical" else "attenzione"
            dettagli = []
            if voce.get("soggetto"):
                dettagli.append(escape(voce["soggetto"]))
            if voce.get("eta_minuti") is not None:
                dettagli.append("aperto da %s" % _durata(voce["eta_minuti"]))
            if voce.get("recapito"):
                dettagli.append("operatore: %s" % escape(voce["recapito"]))
            scrivi('<div style="%s"><b>%s</b><br><span style="color:#3f515d">%s</span>%s</div>'
                   % (_stile(stile), escape(voce["titolo"]), " &middot; ".join(dettagli),
                      '<br><span style="color:#3f515d">%s</span>' % escape(voce["dettaglio"])
                      if voce.get("dettaglio") else ""))

    scrivi('<div style="%s">Il giorno %s</div>'
           % (_stile("sezione"), dati["giorno"].strftime("%d/%m")))
    scrivi('<p style="margin:4px 0">Incidenti: <b>%d</b> aperti, <b>%d</b> risolti%s.</p>'
           % (incidenti["aperti"], incidenti["risolti"],
              ", durata media %s" % _durata(incidenti["durata_media_minuti"])
              if incidenti["durata_media_minuti"] is not None else ""))
    if incidenti["voci"]:
        scrivi('<table style="%s"><tr>'
               '<th style="%s">#</th><th style="%s">Gravita\'</th>'
               '<th style="%s">Aperto</th><th style="%s">Risolto</th>'
               '<th style="%s">Durata</th><th style="%s">Su</th></tr>'
               % (_stile("tabella"), *[_stile("th")] * 6))
        for voce in incidenti["voci"]:
            scrivi('<tr><td style="%s">%s</td><td style="%s">%s</td>'
                   '<td style="%s">%s</td><td style="%s">%s</td>'
                   '<td style="%s">%s</td><td style="%s">%s</td></tr>'
                   % (_stile("td"), voce["id"], _stile("td"), escape(voce["gravita"] or ""),
                      _stile("td"), voce["aperto"], _stile("td"), voce["risolto"] or "-",
                      _stile("td"), _durata(voce["durata_minuti"]),
                      _stile("td"), escape("%s (%s)" % (voce["indirizzo"], voce["controllo"]))))
        scrivi('</table>')

    if disponibilita["misurato"]:
        scrivi('<table style="%s"><tr><th style="%s">Bersaglio</th>'
               '<th style="%s">Genere</th><th style="%s">Esiti</th>'
               '<th style="%s">Riuscita</th><th style="%s">Latenza</th></tr>'
               % (_stile("tabella"), *[_stile("th")] * 5))
        for voce in disponibilita["controlli"]:
            scrivi('<tr><td style="%s"><span style="%s">%s</span></td>'
                   '<td style="%s">%s</td><td style="%s">%d</td>'
                   '<td style="%s">%s</td><td style="%s">%s ms</td></tr>'
                   % (_stile("td"), _stile("mono"), escape(voce["indirizzo"]),
                      _stile("td"), escape(voce["genere"]),
                      _stile("td"), voce["esiti"],
                      _stile("td"), _percentuale(voce["percentuale"]),
                      _stile("td"), int(voce["latenza_media"] or 0)))
        scrivi('</table>')
    else:
        scrivi('<p style="margin:4px 0;color:#3f515d">Nessuna esecuzione dei controlli'
               ' nella giornata: disponibilita\' <b>non misurata</b>.</p>')

    if dati["indisponibilita"]:
        scrivi('<p style="margin:10px 0 4px">Finestre di indisponibilita\':</p>')
        scrivi('<ul style="margin:4px 0;padding-left:18px">')
        for finestra in dati["indisponibilita"]:
            scrivi('<li><span style="%s">%s</span> %s&ndash;%s (%s, %d esiti non'
                   ' riusciti)</li>'
                   % (_stile("mono"), escape(finestra["indirizzo"]), finestra["da"],
                      finestra["a"],
                      _durata(finestra["durata_minuti"]) if not finestra["aperta"]
                      else "in corso", finestra["esiti"]))
        scrivi('</ul>')

    base = dati["rilevamento_base"]
    variazioni = dati["variazioni"]
    scrivi('<div style="%s">Inventario</div>' % _stile("sezione"))
    if base["attivo"]:
        scrivi('<p style="margin:4px 0"><b>Rilevamento di base in corso</b>'
               ' (giorno %d di %d): le variazioni si contano ma non si elencano,'
               ' altrimenti il primo resoconto sarebbe illeggibile.%s</p>'
               % (base["giorno"], base["di"],
                  " Elenco dal %s." % base["fine"].strftime("%d/%m")
                  if base["fine"] else ""))
    scrivi('<ul style="margin:4px 0;padding-left:18px">')
    if variazioni["generi"]:
        for genere in variazioni["generi"]:
            coda = ""
            if genere["aggregato"]:
                coda = (" &mdash; su %d nodi: fatto aggregato, oltre un quinto della rete"
                        % genere["nodi"])
            scrivi('<li>%s: <b>%d</b>%s</li>'
                   % (escape(change_label(genere["genere"])), genere["eventi"], coda))
    else:
        scrivi('<li>Nessuna variazione registrata.</li>')
    scrivi('</ul>')

    giorni = dati["tendenze"]["giorni"]
    if giorni:
        scrivi('<div style="%s">Tendenze (%d giorni)</div>'
               % (_stile("sezione"), len(giorni)))
        scrivi('<p style="%s;margin:4px 0">Disponibilita\' %s &nbsp; Latenza p95 %s</p>'
               % (_stile("mono"),
                  _sparkline([g["disponibilita"] for g in giorni]),
                  _sparkline([g["latenza_p95"] for g in giorni])))

    igiene = dati["igiene"]
    scrivi('<div style="%s">Igiene</div>' % _stile("sezione"))
    scrivi('<p style="margin:4px 0">%s subnet dichiarate, %s host teorici, %s nodi'
           ' trovati%s. %d controlli sospesi, %d bersagli senza controlli, %s nodi non'
           ' identificati, %s porte sospette.</p>'
           % (inventario.get("subnet_dichiarate") or 0,
              inventario.get("subnet_teorici") or 0, inventario.get("nodi") or 0,
              " (occupazione %s%%)" % inventario["occupazione"]
              if inventario.get("occupazione") is not None else "",
              len(igiene["controlli_sospesi"]),
              len(igiene["bersagli_senza_controlli"]),
              igiene["nodi_non_identificati"], igiene["porte_sospette"]))

    from .. import mail_layout as m

    quante = len(dati["da_risolvere"])
    genere = ("critico" if any(v["gravita"] == "critical" for v in dati["da_risolvere"])
              else ("attenzione" if quante else "resoconto"))
    if console_url:
        parti.append(m.bottone("Apri la console", console_url, genere))
    return m.messaggio(
        titolo="Resoconto del %s" % dati["giorno"].strftime("%d/%m/%Y"),
        sottotitolo="%s &middot; %s" % (dati["tenant"]["nome"], dati["tenant"]["fuso"]),
        genere=genere,
        preintestazione="%d questioni aperte, disponibilita' %s"
                        % (quante, _percentuale(dati["disponibilita"]["percentuale"])),
        blocchi=parti,
        tenant=dati["tenant"]["nome"],
        quando="%s UTC" % dati["generato_utc"],
        perche="Ricevi questo messaggio perche' sei il recapito di riferimento del"
               " tenant: il resoconto si disattiva dalle impostazioni.",
        console_url=console_url,
    )
