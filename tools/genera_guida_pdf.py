"""
snap - Generazione in PDF di un documento di docs/.

PERCHE' UN SECONDO GENERATORE E NON UN'OPZIONE DI QUELLO ESISTENTE. `genera_manuale.py`
produce `.docx` con gli stili di Word: e' la forma richiesta per i manuali, perche' il
sommario e la numerazione restano automatici e il documento si modifica. Il PDF serve a
un uso diverso -- si consegna, si stampa, si porta in sala macchine -- e usa
l'impaginatore del PRODOTTO (`snapserver.reports.render_pdf`), quello dei report:
frontespizio, testatina, pie' con numerazione, tipografia PT Sans, palette istituzionale.
Mescolare i due mestieri in un file solo avrebbe reso illeggibili entrambi.

Uso:
    python tools/genera_guida_pdf.py 16_INSTALLAZIONE_DA_ZERO.md
    python tools/genera_guida_pdf.py 16_INSTALLAZIONE_DA_ZERO.md --uscita docs/pdf

Che cosa riconosce del Markdown: titoli (`#`..`###`), paragrafi, elenchi puntati,
tabelle, blocchi di codice (```), citazioni (`>`), righe orizzontali. E' un
sottoinsieme deliberato: i documenti di questo progetto usano quello, e un convertitore
generico porterebbe casi che nessuno scrive e che nessuno collauderebbe.

remarks: Autore: Daniele Speziale - Data: 2026-09-12
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent
DOCS = RADICE / "docs"
sys.path.insert(0, str(RADICE / "server"))

from snapserver.reports import render_pdf  # noqa: E402
from snapserver.reports.render_pdf import (  # noqa: E402
    INCHIOSTRO,
    INCHIOSTRO_3,
    INTERLINEA,
    LINEA,
    MARGINE,
)

# Larghezza massima di una riga di codice prima che vada a capo da sola. Il corpo
# monospazio del documento entra in circa novanta caratteri sulla A4 con i margini
# dell'impaginatore: oltre, la riga uscirebbe dalla pagina.
COLONNE_CODICE = 92

RE_TITOLO = re.compile(r"^(#{1,6})\s+(.*)$")
RE_ELENCO = re.compile(r"^\s*[-*]\s+(.*)$")
# Gli elenchi NUMERATI sono sequenze di passi -- "1. crea il pacchetto, 2. incollalo"
# -- e leggerli come un paragrafo unico perde proprio cio' che li rende istruzioni.
RE_ELENCO_NUMERATO = re.compile(r"^\s*(\d+)[.)]\s+(.*)$")
# La riga che CONTINUA una voce di elenco: rientrata, senza un segno proprio.
RE_CONTINUA = re.compile(r"^\s{2,}\S")
RE_CITAZIONE = re.compile(r"^>\s?(.*)$")
RE_SEPARATORE = re.compile(r"^\s*---+\s*$")
RE_TABELLA_SEP = re.compile(r"^\s*\|[\s:|-]+\|\s*$")
# La formattazione in linea si toglie: l'impaginatore disegna testo semplice, e lasciare
# gli asterischi renderebbe il PDF peggiore dell'originale.
RE_GRASSETTO = re.compile(r"\*\*(.+?)\*\*")
RE_CORSIVO = re.compile(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)")
RE_CODICE_INLINE = re.compile(r"`([^`]+)`")
RE_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")

# Segni che PT Sans non disegna: escono come quadratini, ed e' peggio del carattere
# che sostituiscono. La freccia dei percorsi di menu ("Rete -> Perimetro") e' il caso
# che si presenta a ogni pagina.
SOSTITUZIONI = (
    ("&mdash;", "—"), ("&rarr;", " > "), ("→", " > "),
    ("←", " < "), ("✓", "ok"), ("✗", "no"),
    (" ", " "),
)


def testo_piano(riga: str) -> str:
    """Il testo senza i segni del Markdown.

    I collegamenti diventano il loro testo: in un documento stampato un URL fra
    parentesi e' rumore, e il capitolo dei riferimenti li elenca comunque.
    """
    riga = RE_LINK.sub(r"\1", riga)
    riga = RE_GRASSETTO.sub(r"\1", riga)
    riga = RE_CODICE_INLINE.sub(r"\1", riga)
    riga = RE_CORSIVO.sub(r"\1", riga)
    for segno, sostituto in SOSTITUZIONI:
        riga = riga.replace(segno, sostituto)
    return riga.replace("|", "/").strip()


RE_NUMERAZIONE = re.compile(r"^\d+(?:\.\d+)*\.?\s+")


def _senza_numero(testo: str) -> str:
    """Il titolo senza la numerazione del sorgente Markdown."""
    return RE_NUMERAZIONE.sub("", testo)


def _celle(riga: str) -> list:
    return [testo_piano(c) for c in riga.strip().strip("|").split("|")]


def _spezza_codice(riga: str) -> list:
    """Una riga di codice, spezzata se non entra. Non si tronca: si manda a capo.

    Troncare un comando in una guida di installazione significa consegnare un comando
    che non funziona, ed e' il difetto peggiore che questo documento possa avere.
    """
    riga = riga.rstrip()
    if len(riga) <= COLONNE_CODICE:
        return [riga]
    pezzi = []
    while len(riga) > COLONNE_CODICE:
        taglio = riga.rfind(" ", 0, COLONNE_CODICE)
        if taglio < 20:
            taglio = COLONNE_CODICE
        pezzi.append(riga[:taglio])
        riga = "    " + riga[taglio:].lstrip()
    pezzi.append(riga)
    return pezzi


def leggi_blocchi(sorgente: Path) -> tuple:
    """Il documento come sequenza di blocchi, piu' titolo e sottotitolo.

    Restituisce `(titolo, sottotitolo, blocchi)`; ogni blocco e' `(genere, contenuto)`.
    """
    righe = sorgente.read_text(encoding="utf-8").splitlines()
    titolo, sottotitolo = sorgente.stem.replace("_", " "), ""
    blocchi = []
    paragrafo = []
    elenco = []
    tabella = []
    codice = []
    in_codice = False
    ultima_riga_citazione = False

    def chiudi_paragrafo():
        if paragrafo:
            # Si unisce PRIMA e si ripulisce DOPO: un `**...**` che si apre su una
            # riga e si chiude su quella successiva, riga per riga, non si riconosce
            # -- e gli asterischi finiscono stampati nel documento.
            blocchi.append(("paragrafo", testo_piano(" ".join(paragrafo))))
            paragrafo.clear()

    def chiudi_elenco():
        if elenco:
            blocchi.append(("elenco", [testo_piano(v) for v in elenco]))
            elenco.clear()

    def chiudi_tabella():
        if tabella:
            blocchi.append(("tabella", list(tabella)))
            tabella.clear()

    def chiudi_tutto():
        chiudi_paragrafo()
        chiudi_elenco()
        chiudi_tabella()

    for riga in righe:
        if riga.strip().startswith("```"):
            if in_codice:
                blocchi.append(("codice", list(codice)))
                codice.clear()
            else:
                chiudi_tutto()
            in_codice = not in_codice
            continue
        if in_codice:
            codice.append(riga)
            continue

        if not riga.strip():
            chiudi_tutto()
            ultima_riga_citazione = False
            continue
        if RE_SEPARATORE.match(riga):
            chiudi_tutto()
            continue

        trovato = RE_TITOLO.match(riga)
        if trovato or riga.lstrip().startswith("|"):
            ultima_riga_citazione = False
        if trovato:
            chiudi_tutto()
            livello, testo = len(trovato.group(1)), testo_piano(trovato.group(2))
            if livello == 1 and not blocchi:
                titolo = testo
                continue
            # Via la numerazione del sorgente SOLO dove l'impaginatore rinumera
            # lui, cioe' ai primi due livelli: lasciarla darebbe "4. 4. La sonda in
            # contenitore". Il terzo livello invece non viene numerato da nessuno, e
            # toglierla rendeva "9.3 Installare" un "Installare" qualunque -- in un
            # documento che si cita per capitoli e sottocapitoli.
            livello_reso = min(livello, 3)
            blocchi.append(("titolo%d" % livello_reso,
                            testo if livello_reso == 3 else _senza_numero(testo)))
            continue

        if riga.lstrip().startswith("|"):
            chiudi_paragrafo()
            chiudi_elenco()
            if RE_TABELLA_SEP.match(riga):
                continue
            tabella.append(_celle(riga))
            continue

        trovato = RE_CITAZIONE.match(riga)
        if trovato:
            chiudi_paragrafo()
            chiudi_elenco()
            # Le citazioni su piu' righe sono UNA nota: unirle e' cio' che evita di
            # troncare il sottotitolo a meta' frase, com'e' successo alla prima resa.
            testo = trovato.group(1).strip()
            if blocchi and blocchi[-1][0] == "nota" and ultima_riga_citazione:
                blocchi[-1] = ("nota",
                               testo_piano(blocchi[-1][1] + " " + testo))
            elif testo:
                blocchi.append(("nota", testo_piano(testo)))
            ultima_riga_citazione = True
            continue

        trovato = RE_ELENCO.match(riga)
        if trovato:
            chiudi_paragrafo()
            chiudi_tabella()
            elenco.append(trovato.group(1).strip())
            continue

        numerato = RE_ELENCO_NUMERATO.match(riga)
        if numerato:
            chiudi_paragrafo()
            chiudi_tabella()
            # Il numero si conserva: e' l'ordine dei passi, e l'impaginatore disegna
            # un punto elenco uguale per tutti.
            elenco.append("%s. %s" % (numerato.group(1), numerato.group(2).strip()))
            continue

        # Una riga rientrata dopo una voce di elenco la CONTINUA. Senza questo, una
        # voce che va a capo diventava un paragrafo a se', fuori dall'elenco e
        # allineato al margine: si leggeva come un'altra cosa.
        if elenco and RE_CONTINUA.match(riga):
            elenco[-1] = (elenco[-1] + " " + riga.strip()).strip()
            continue

        chiudi_elenco()
        chiudi_tabella()
        paragrafo.append(riga.strip())

    chiudi_tutto()

    # Il sottotitolo: la citazione d'APERTURA, quella che sta prima di ogni titolo e
    # che per convenzione dice a che cosa serve il documento. Si toglie dai blocchi,
    # perche' in copertina ci sta gia'.
    #
    # "Prima di ogni titolo" non e' un dettaglio: cercando la prima citazione ovunque,
    # un documento senza apertura si prendeva in copertina una citazione qualunque del
    # corpo -- ed e' successo, con l'esempio di una rilevazione IDS finito a fare da
    # sottotitolo -- e per giunta quel blocco spariva dal testo.
    for indice, (genere, contenuto) in enumerate(blocchi):
        if genere in ("titolo1", "titolo2", "titolo3"):
            break
        if genere == "nota":
            sottotitolo = contenuto
            blocchi.pop(indice)
            break
    return titolo, sottotitolo, blocchi


# Sopra questa lunghezza il documento vuole un sommario con i numeri di pagina. La
# soglia e' quella della regola documentale del progetto (cinque pagine): sotto, un
# indice sarebbe piu' lungo di cio' che indicizza.
PAGINE_CHE_VOGLIONO_UN_SOMMARIO = 5
# Quante volte al massimo si rifa' l'impaginazione cercando il punto fisso. Due giri
# bastano sempre nei casi reali; il terzo e' il margine, e oltre si smette e si
# stampa comunque -- un sommario con un numero incerto e' meglio di nessun documento.
GIRI_MASSIMI = 4


def _impagina(foglio, blocchi, registro=None) -> None:
    """Disegna il corpo del documento. Con `registro`, annota dove finisce ogni titolo.

    La stessa funzione serve i due giri: e' l'unico modo perche' il secondo impagini
    esattamente come il primo. Due funzioni gemelle divergerebbero alla prima modifica,
    e i numeri del sommario indicherebbero pagine sbagliate senza che nulla lo dica.
    """
    for genere, contenuto in blocchi:
        if genere in ("titolo1", "titolo2"):
            foglio.titolo_sezione(contenuto)
            if registro is not None:
                registro.append((1, "%d. %s" % (foglio.numero_sezione, contenuto),
                                 foglio.pagina))
        elif genere == "titolo3":
            foglio.sottotitolo_sezione(contenuto)
            if registro is not None:
                registro.append((2, contenuto, foglio.pagina))
        elif genere == "paragrafo":
            foglio.paragrafo(contenuto)
        elif genere == "elenco":
            foglio.elenco(contenuto)
        elif genere == "nota":
            # `box` vuole elementi descritti, non stringhe: vedi la sua firma.
            foglio.box([{"testo": contenuto}])
        elif genere == "codice":
            righe = []
            for riga in contenuto:
                righe.extend(_spezza_codice(riga))
            for riga in righe:
                foglio.paragrafo(riga or " ", mono=True)
            foglio.a_capo()
        elif genere == "tabella":
            if len(contenuto) >= 2:
                foglio.tabella(contenuto[0], contenuto[1:])
            foglio.a_capo()


def _sommario(foglio, voci, scarto: int) -> int:
    """Disegna il sommario. Restituisce quante pagine ha occupato.

    `scarto` e' di quanto il sommario stesso sposta in avanti il corpo: i numeri
    stampati sono quelli del giro precedente PIU' questo, ed e' esattamente il valore
    che il punto fisso sta cercando.

    ATTENZIONE AL CURSORE. `foglio.spazio(n)` riserva spazio e cambia pagina se non ce
    n'e' piu', ma NON sposta `foglio.y`: lo sposta chi disegna. Dimenticarlo qui aveva
    prodotto trentaquattro voci una sopra l'altra -- e la prova sul testo estratto non
    se n'era accorta, perche' i caratteri c'erano tutti e i numeri erano giusti. Un
    sommario si guarda, non si interroga.
    """
    prima = foglio.pagina
    foglio.titolo_sezione("Sommario", numerato=False)
    c = foglio.c
    destra = foglio.larghezza - MARGINE

    for livello, testo, pagina in voci:
        capitolo = livello == 1
        altezza = INTERLINEA + (3 if capitolo else 0)
        # Un filo d'aria prima di ogni capitolo: senza, i sottocapitoli del capitolo
        # precedente e il capitolo nuovo formano un blocco unico e l'occhio non trova
        # piu' l'inizio.
        if capitolo:
            foglio.y -= 4
        foglio.spazio(altezza)

        rientro = MARGINE + (0 if capitolo else 16)
        font = foglio.font["titolo"] if capitolo else foglio.font["corpo"]
        corpo = 10 if capitolo else 8.5
        numero = "%d" % (pagina + scarto)

        c.setFont(font, corpo)
        c.setFillColor(INCHIOSTRO if capitolo else INCHIOSTRO_3)
        c.drawString(rientro, foglio.y, testo)
        c.drawRightString(destra, foglio.y, numero)

        # La guida dell'occhio dal titolo al numero. E' una linea TRATTEGGIATA e non
        # una fila di punti scritti: a corpo pieno, lunga mezza pagina, quella fila si
        # legge come una riga continua e pesa piu' del titolo che accompagna.
        inizio = rientro + c.stringWidth(testo, font, corpo) + 6
        fine = destra - c.stringWidth(numero, font, corpo) - 6
        if fine > inizio + 12:
            c.saveState()
            c.setStrokeColor(LINEA)
            c.setLineWidth(.6)
            c.setDash(0.6, 2.6)
            # Un filo sotto la linea di base, dove passerebbero i puntini.
            c.line(inizio, foglio.y + 2, fine, foglio.y + 2)
            c.restoreState()

        foglio.y -= altezza

    # Il corpo comincia su una pagina propria: cosi' lo scarto e' esattamente il
    # numero di pagine del sommario, e non dipende da quanto spazio ne avanza.
    foglio._nuova_pagina()
    return foglio.pagina - prima


def genera(sorgente: Path, destinazione: Path) -> Path:
    """Impagina il documento con l'impaginatore del prodotto.

    Due giri quando il documento e' lungo: il primo per sapere dove cade ogni titolo,
    il secondo per stamparlo con il sommario davanti. Si veda `_sommario` per il
    punto fisso.
    """
    titolo, sottotitolo, blocchi = leggi_blocchi(sorgente)
    destinazione.parent.mkdir(parents=True, exist_ok=True)
    adesso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # L'indice delle sezioni per il frontespizio: i titoli di primo livello del corpo.
    # L'impaginatore numera da se' le voci dell'indice: lasciare anche i numeri del
    # sorgente darebbe "1. 1. Che cosa si sta installando".
    sezioni = [c for g, c in blocchi if g in ("titolo1", "titolo2")]

    # Che cosa dichiara la copertina. Un documento che non e' una procedura non deve
    # portare la fascia "INSTALLAZIONE": chi cerca come si installa e apre una
    # specifica ha perso tempo per colpa di un'etichetta sbagliata.
    procedura = "INSTALLAZIONE" in sorgente.stem.upper()

    def foglio_nuovo(percorso):
        return render_pdf.Foglio(
            percorso,
            kind="installazione" if procedura else "documentazione",
            titolo=titolo,
            # NESSUN TENANT: non e' il report di una rete, e l'impaginatore omette la
            # riga "Tenant ..." quando e' vuota (vedi render_pdf._riferimento_documento).
            tenant="",
            intervallo=("procedura di installazione" if procedura
                        else "documentazione di prodotto"),
            generato=adesso,
            sottotitolo=sottotitolo,
            scopo=(sottotitolo,) if sottotitolo else (),
            sezioni=sezioni[:14],
            riferimenti=[
                ("Sorgente", sorgente.name),
                ("Prodotto", "snap - Secure Network Assessment Platform"),
            ],
            nota="Documento generato dal sorgente in docs/: se il contenuto cambia,"
                 " cambia il sorgente e questo PDF si rigenera. Una copia modificata"
                 " a mano sarebbe una seconda verita'.",
        )

    # PRIMO GIRO, in un file di scarto: serve solo a sapere dove cade ogni titolo.
    prova = destinazione.with_suffix(".giro.pdf")
    voci = []
    foglio = foglio_nuovo(prova)
    _impagina(foglio, blocchi, registro=voci)
    pagine = foglio.pagina
    foglio.salva()
    prova.unlink(missing_ok=True)

    if pagine <= PAGINE_CHE_VOGLIONO_UN_SOMMARIO or not voci:
        foglio = foglio_nuovo(destinazione)
        _impagina(foglio, blocchi)
        foglio.salva()
        return destinazione

    # SECONDO GIRO E SEGUENTI: si stampa con il sommario, e si ripete finche' il
    # numero di pagine che il sommario occupa non coincide con quello usato per
    # calcolare i numeri che vi sono stampati.
    scarto = 1
    for _ in range(GIRI_MASSIMI):
        foglio = foglio_nuovo(destinazione)
        occupate = _sommario(foglio, voci, scarto)
        _impagina(foglio, blocchi)
        foglio.salva()
        if occupate == scarto:
            return destinazione
        scarto = occupate
        # I titoli non si spostano fra un giro e l'altro -- il corpo e' identico e
        # comincia sempre a inizio pagina -- quindi `voci` resta valido: cambia solo
        # di quanto va traslato.
    return destinazione


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Genera in PDF un documento di docs/ con l'impaginatore del prodotto")
    parser.add_argument("documenti", nargs="*",
                        help="nomi dei file in docs/ (predefinito: la guida di installazione)")
    parser.add_argument("--uscita", default=str(DOCS / "pdf"),
                        help="cartella di destinazione")
    argomenti = parser.parse_args()

    nomi = argomenti.documenti or ["16_INSTALLAZIONE_DA_ZERO.md"]
    sorgenti = [DOCS / n for n in nomi]
    mancanti = [s for s in sorgenti if not s.exists()]
    if mancanti:
        for s in mancanti:
            print("documento non trovato: %s" % s, file=sys.stderr)
        return 2

    # `completo` e' la chiave che l'impaginatore espone: dice se TUTTI e cinque i
    # caratteri sono stati registrati. Chiederne una che non esiste darebbe sempre
    # "ripiego", cioe' un'informazione falsa sul documento che si sta consegnando.
    stato = render_pdf.font_status()
    print("Tipografia: %s"
          % ("PT Sans / PT Sans Narrow / PT Mono" if stato.get("completo")
             else "ripiego su Helvetica: mancano %s"
                  % ", ".join(sorted(set(render_pdf.FONT_ATTESI)
                                     - set(stato.get("trovati") or {})))))
    uscita = Path(argomenti.uscita)
    for sorgente in sorgenti:
        prodotto = genera(sorgente, uscita / (sorgente.stem + ".pdf"))
        print("  %-34s -> %s (%d kB)"
              % (sorgente.name, prodotto.name, prodotto.stat().st_size // 1024))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
