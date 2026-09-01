# -----------------------------------------------------------------
# mail_layout.py — impaginazione dei messaggi di posta: una forma per tutti
# Autore: Daniele Speziale
# Data creazione: 2026-08-31
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Come si presenta un messaggio che esce dal prodotto.

Perche' un modulo, e non l'HTML dentro ogni notifica
---------------------------------------------------
Le email di snap arrivano a persone che non hanno la console davanti: un turno di notte,
un responsabile IT sul telefono, un amministratore che riceve le proprie credenziali. Una
notifica costruita a mano ogni volta finisce per essere diversa ogni volta -- e un
messaggio che sembra diverso dal precedente costringe a rileggerlo tutto per capire che
cosa e' cambiato.

Qui c'e' una forma sola: fascia colorata per genere (le stesse dei report), titolo,
poche righe di testo, una tabella di fatti, un pulsante che porta al posto giusto della
console, un pie' di pagina che dice **perche'** quel messaggio e' arrivato.

I vincoli della posta, che decidono la tecnica
---------------------------------------------
* **stili in linea**: i client di posta ignorano i fogli di stile, e molti tolgono anche
  il tag `<style>`. Cio' che deve funzionare sta negli attributi `style`;
* **impaginazione a tabelle**: Outlook usa il motore di Word e non impagina con i box
  moderni. Le tabelle di impaginazione portano `role="presentation"`, cosi' i lettori di
  schermo non le annunciano come dati;
* **nessuna risorsa esterna**: nessuna immagine, nessun carattere da scaricare, nessun
  pixel di tracciamento. Le immagini vengono bloccate per difetto e un messaggio che
  dipende da loro arriva rotto; il tracciamento, in un prodotto di sicurezza, sarebbe
  una contraddizione;
* **testo semplice sempre**: l'HTML e' l'alternativa, non il contenuto (vedi
  `notifications.compose`). Ogni messaggio esce nelle due forme;
* **preintestazione**: la riga che i client mostrano in anteprima accanto all'oggetto.
  Se non la si scrive, il client mostra il primo testo che trova -- di solito
  "Visualizza nel browser" o l'intestazione della fascia;
* **tema scuro**: dichiarato con `color-scheme` e con una regola di preferenza per i
  client che la rispettano. I colori restano leggibili in entrambi i casi perche' il
  contrasto e' calcolato sul fondo chiaro, che e' quello garantito.

Larghezza: 640 pixel. E' la misura che sta in una finestra di anteprima senza barra
orizzontale e resta leggibile su un telefono.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from html import escape

MARCHIO = "SNAP"
CLAIM = "Secure Network Assessment Platform"
TITOLARE = "2024-26 DS Consulting"
LARGHEZZA = 640

# Le fasce: gli stessi colori dei report, perche' un genere di messaggio e il documento
# che gli corrisponde devono essere riconoscibili come la stessa cosa.
GENERI = {
    "critico": {"banda": "#3a1618", "accento": "#a32620", "chiaro": "#f9ecea",
                "etichetta": "INCIDENTE"},
    "attenzione": {"banda": "#33301a", "accento": "#8a7a24", "chiaro": "#f5f2e3",
                   "etichetta": "ATTENZIONE"},
    "sereno": {"banda": "#10302a", "accento": "#1f7a63", "chiaro": "#e6f2ee",
               "etichetta": "RIENTRATO"},
    "informativo": {"banda": "#1f3033", "accento": "#0d6b78", "chiaro": "#eef3f4",
                    "etichetta": "INFORMAZIONE"},
    "credenziali": {"banda": "#16263f", "accento": "#2c5c8f", "chiaro": "#eaf0f7",
                    "etichetta": "ACCESSO"},
    "acn": {"banda": "#1f2a44", "accento": "#3c5488", "chiaro": "#eceff6",
            "etichetta": "COMUNICAZIONE ACN"},
    "regola": {"banda": "#2b1b3d", "accento": "#6b3fa0", "chiaro": "#f2ecf9",
               "etichetta": "REGOLA"},
    "resoconto": {"banda": "#1f3033", "accento": "#0d6b78", "chiaro": "#eef3f4",
                  "etichetta": "RESOCONTO"},
}
GENERE_PREDEFINITO = "informativo"

# Caratteri: PT Sans se il destinatario lo ha installato (chi usa il prodotto lo ha),
# altrimenti i caratteri di sistema. Nessun carattere da scaricare.
FONT = "'PT Sans','Segoe UI',Helvetica,Arial,sans-serif"
FONT_TITOLI = "'PT Sans Narrow','Segoe UI',Helvetica,Arial,sans-serif"
FONT_MONO = "'PT Mono',Consolas,'Courier New',monospace"

INCHIOSTRO = "#131a1f"
INCHIOSTRO_2 = "#3f515d"
INCHIOSTRO_3 = "#6d8290"
LINEA = "#d6dee4"
FONDO = "#f3f6f8"


def _tema(genere: str) -> dict:
    return GENERI.get(genere or GENERE_PREDEFINITO, GENERI[GENERE_PREDEFINITO])


def _testo(valore) -> str:
    """Testo pronto per l'HTML: niente marcatura che arrivi dai dati."""
    return escape("" if valore is None else str(valore), quote=True)


# --------------------------------------------------------------------------- #
# Blocchi
# --------------------------------------------------------------------------- #
def paragrafo(testo: str, colore: str = None) -> str:
    return ('<p style="margin:0 0 12px;color:%s;font-size:14px;line-height:1.55">%s</p>'
            % (colore or INCHIOSTRO_2, _testo(testo)))


def titolo_sezione(testo: str) -> str:
    return ('<p style="margin:22px 0 8px;font-family:%s;font-size:12px;font-weight:700;'
            'letter-spacing:.12em;text-transform:uppercase;color:%s;'
            'border-bottom:1px solid %s;padding-bottom:4px">%s</p>'
            % (FONT_TITOLI, INCHIOSTRO_3, LINEA, _testo(testo)))


def fatti(coppie, mono_valori: bool = False) -> str:
    """Tabella etichetta/valore: e' la forma in cui si leggono i dati di un incidente.

    Le etichette a sinistra, i valori a destra, una riga per fatto. Su un telefono la
    tabella si stringe ma non si spezza, perche' le colonne sono due.
    """
    righe = []
    for etichetta, valore in coppie:
        if valore is None or valore == "":
            continue
        stile_valore = ("font-family:%s;font-size:13px" % FONT_MONO if mono_valori
                        else "font-size:14px")
        righe.append(
            '<tr>'
            '<td style="padding:7px 10px 7px 0;border-bottom:1px solid %s;'
            'color:%s;font-size:13px;white-space:nowrap;vertical-align:top">%s</td>'
            '<td style="padding:7px 0;border-bottom:1px solid %s;color:%s;%s;'
            'word-break:break-word">%s</td>'
            '</tr>'
            % (LINEA, INCHIOSTRO_3, _testo(etichetta), LINEA, INCHIOSTRO,
               stile_valore, _testo(valore)))
    if not righe:
        return ""
    return ('<table role="presentation" cellpadding="0" cellspacing="0" border="0"'
            ' width="100%%" style="width:100%%;border-collapse:collapse;margin:4px 0 8px">'
            '%s</table>' % "".join(righe))


def avviso(testo: str, genere: str = "attenzione") -> str:
    """Il riquadro che dice la cosa che non si deve perdere."""
    tema = _tema(genere)
    return ('<table role="presentation" cellpadding="0" cellspacing="0" border="0"'
            ' width="100%%" style="width:100%%;margin:14px 0">'
            '<tr><td style="background:%s;border-left:4px solid %s;padding:12px 14px;'
            'color:%s;font-size:14px;line-height:1.5">%s</td></tr></table>'
            % (tema["chiaro"], tema["accento"], INCHIOSTRO, _testo(testo)))


def elenco(voci) -> str:
    if not voci:
        return ""
    righe = "".join('<li style="margin:0 0 6px">%s</li>' % _testo(v) for v in voci)
    return ('<ul style="margin:0 0 14px;padding-left:20px;color:%s;font-size:14px;'
            'line-height:1.5">%s</ul>' % (INCHIOSTRO_2, righe))


def codice(testo: str) -> str:
    """Un valore da copiare: password provvisoria, protocollo, indirizzo."""
    return ('<table role="presentation" cellpadding="0" cellspacing="0" border="0"'
            ' width="100%%" style="width:100%%;margin:10px 0">'
            '<tr><td style="background:%s;border:1px solid %s;border-radius:3px;'
            'padding:12px 14px;font-family:%s;font-size:15px;color:%s;'
            'word-break:break-all">%s</td></tr></table>'
            % (FONDO, LINEA, FONT_MONO, INCHIOSTRO, _testo(testo)))


def bottone(etichetta: str, indirizzo: str, genere: str = None) -> str:
    """Un pulsante che porta al posto giusto della console.

    E' una tabella con un collegamento dentro, non un elemento con i bordi
    arrotondati: Outlook userebbe il motore di Word e il pulsante arriverebbe come una
    riga di testo colorata.
    """
    if not indirizzo:
        return ""
    tema = _tema(genere)
    return ('<table role="presentation" cellpadding="0" cellspacing="0" border="0"'
            ' style="margin:18px 0 6px">'
            '<tr><td style="background:%s;border-radius:3px">'
            '<a href="%s" style="display:inline-block;padding:11px 22px;color:#ffffff;'
            'font-family:%s;font-size:14px;font-weight:700;text-decoration:none;'
            'letter-spacing:.02em">%s</a></td></tr></table>'
            % (tema["accento"], _testo(indirizzo), FONT_TITOLI, _testo(etichetta)))


# --------------------------------------------------------------------------- #
# La pagina
# --------------------------------------------------------------------------- #
def messaggio(titolo: str, blocchi, genere: str = GENERE_PREDEFINITO,
              sottotitolo: str = "", preintestazione: str = "", tenant: str = "",
              quando: str = "", perche: str = "", console_url: str = "") -> str:
    """Il messaggio completo, pronto per `notifications.compose`.

    `blocchi` e' una sequenza di frammenti prodotti dalle funzioni di questo modulo:
    si compone come si comporrebbe una pagina, senza scrivere marcatura a mano.
    """
    tema = _tema(genere)
    corpo = "".join(b for b in blocchi if b)

    intestazione = (
        '<tr><td style="background:%s;padding:18px 24px">'
        '<table role="presentation" cellpadding="0" cellspacing="0" border="0"'
        ' width="100%%" style="width:100%%"><tr>'
        '<td style="font-family:%s;font-size:22px;font-weight:700;color:#ffffff;'
        'letter-spacing:.04em">%s'
        '<span style="display:block;font-size:11px;font-weight:400;'
        'letter-spacing:.06em;color:rgba(255,255,255,.72);margin-top:2px">%s</span>'
        '</td>'
        '<td align="right" style="font-family:%s;font-size:11px;font-weight:700;'
        'letter-spacing:.10em;color:#ffffff;white-space:nowrap;vertical-align:top">'
        '<span style="background:%s;padding:5px 10px;border-radius:2px">%s</span>'
        '</td></tr></table></td></tr>'
        % (tema["banda"], FONT_TITOLI, MARCHIO, _testo(CLAIM), FONT_TITOLI,
           tema["accento"], tema["etichetta"]))

    testata = (
        '<tr><td style="padding:22px 24px 0">'
        '<h1 style="margin:0 0 6px;font-family:%s;font-size:24px;line-height:1.25;'
        'font-weight:700;color:%s">%s</h1>'
        % (FONT_TITOLI, INCHIOSTRO, _testo(titolo)))
    if sottotitolo:
        testata += ('<p style="margin:0 0 4px;color:%s;font-size:14px">%s</p>'
                    % (INCHIOSTRO_2, _testo(sottotitolo)))
    testata += "</td></tr>"

    pie_righe = []
    if tenant:
        pie_righe.append("Tenant: %s" % tenant)
    if quando:
        pie_righe.append("Istante: %s" % quando)
    if perche:
        pie_righe.append(perche)
    pie_righe.append("Messaggio automatico di %s (%s). Non rispondere a questo"
                     " indirizzo." % (MARCHIO, CLAIM))
    pie_righe.append("Documento riservato: puo' contenere informazioni sulla rete del"
                     " tenant.")
    pie_righe.append("(c) %s" % TITOLARE)
    pie = ('<tr><td style="padding:8px 24px 22px">'
           '<table role="presentation" cellpadding="0" cellspacing="0" border="0"'
           ' width="100%%" style="width:100%%;border-top:1px solid %s;margin-top:8px">'
           '<tr><td style="padding-top:12px;color:%s;font-size:12px;line-height:1.5">'
           '%s</td></tr></table></td></tr>'
           % (LINEA, INCHIOSTRO_3,
              "<br>".join(_testo(r) for r in pie_righe)))

    # La preintestazione: testo nascosto che il client mostra in anteprima. Gli spazi
    # invisibili in coda impediscono che il client peschi anche il testo successivo.
    anteprima = (
        '<div style="display:none;max-height:0;overflow:hidden;mso-hide:all;'
        'font-size:1px;line-height:1px;color:%s">%s%s</div>'
        % (FONDO, _testo(preintestazione or sottotitolo or titolo), "&#8203;" * 60))

    return (
        '<!doctype html>'
        '<html lang="it"><head>'
        '<meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="color-scheme" content="light dark">'
        '<meta name="supported-color-schemes" content="light dark">'
        '<title>%s</title>'
        '<style>'
        '@media (max-width:620px){.snap-scheda{width:100%% !important}'
        '.snap-imbottitura{padding-left:16px !important;padding-right:16px !important}}'
        '@media (prefers-color-scheme:dark){'
        '.snap-fondo{background:#0f1416 !important}'
        '.snap-scheda{background:#161d20 !important;border-color:#2a353a !important}'
        '.snap-testo{color:#e6edf0 !important}}'
        '</style>'
        '</head>'
        '<body class="snap-fondo" style="margin:0;padding:0;background:%s;'
        '-webkit-text-size-adjust:100%%;-ms-text-size-adjust:100%%">'
        '%s'
        '<table role="presentation" cellpadding="0" cellspacing="0" border="0"'
        ' width="100%%" style="width:100%%;background:%s">'
        '<tr><td align="center" style="padding:20px 12px">'
        '<table role="presentation" cellpadding="0" cellspacing="0" border="0"'
        ' class="snap-scheda" width="%d" style="width:%dpx;max-width:%dpx;'
        'background:#ffffff;border:1px solid %s;border-radius:4px;overflow:hidden">'
        '%s%s'
        '<tr><td class="snap-imbottitura snap-testo" style="padding:8px 24px 0;'
        'font-family:%s;color:%s">%s</td></tr>'
        '%s'
        '</table>'
        '</td></tr></table>'
        '</body></html>'
        % (_testo(titolo), FONDO, anteprima, FONDO, LARGHEZZA, LARGHEZZA, LARGHEZZA,
           LINEA, intestazione, testata, FONT, INCHIOSTRO_2, corpo, pie))
