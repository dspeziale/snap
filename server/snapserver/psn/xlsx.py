# -----------------------------------------------------------------
# psn/xlsx.py — lettura di un foglio .xlsx con la sola libreria standard
# Autore: Daniele Speziale
# Data creazione: 2026-09-11
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Lettore minimo di fogli .xlsx.

PERCHE' NON UNA LIBRERIA. La regola di progetto vieta dipendenze non concordate, e
qui non servono: un `.xlsx` e' un archivio zip di documenti XML, e `zipfile` piu'
`xml.etree` bastano a leggerne le celle. Una libreria generica porterebbe stili,
formule, grafici, immagini e la propria superficie di attacco -- per un file che
arriva per posta elettronica da fuori, e' superficie che non si vuole.

COSA LEGGE, E COSA NO. Legge i VALORI delle celle: testo, numeri, stringhe
condivise e stringhe in linea. NON valuta le formule: prende il valore memorizzato
da Excel, che e' quello che serve; dove Excel ha salvato un errore (`#REF!`,
`#VALUE!`) restituisce quel testo, e chi importa lo tratta come "non disponibile"
invece di crederci.

SICUREZZA. Il file arriva da fuori, quindi si diffida:
  * si rifiuta un archivio troppo grande o con troppe voci (zip bomb);
  * si leggono solo le voci attese (`xl/...`), non tutto cio' che c'e' dentro;
  * l'XML si analizza con `xml.etree`, che non risolve entita' esterne, e si
    rifiutano i documenti che dichiarano un DOCTYPE (XXE, billion laughs).

remarks: Autore: Daniele Speziale - Data: 2026-09-11
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
import zipfile

NS = {
    "m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
}

# Limiti su un file che arriva da fuori. Il piano reale pesa 0,9 MB e si espande a
# pochi MB: i tetti sono larghi dieci volte, e servono a fermare un archivio
# costruito per esaurire la memoria, non un piano che cresce.
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_ESPANSO_BYTES = 512 * 1024 * 1024
MAX_VOCI = 5000


class XlsxNonValido(Exception):
    """Il file non e' un foglio leggibile, e il motivo e' nel messaggio."""


def _radice(z: zipfile.ZipFile, nome: str):
    """Analizza una voce dell'archivio come XML, rifiutando i DOCTYPE."""
    dati = z.read(nome)
    # Un DOCTYPE puo' dichiarare entita' esterne o ricorsive: un foglio prodotto da
    # un programma di calcolo non ne ha bisogno, e rifiutarlo costa nulla.
    if re.search(rb"<!DOCTYPE", dati[:4096], re.I):
        raise XlsxNonValido("il documento %s dichiara un DOCTYPE: rifiutato" % nome)
    try:
        return ET.fromstring(dati)
    except ET.ParseError as errore:
        raise XlsxNonValido("documento %s illeggibile: %s" % (nome, errore)) from errore


class Foglio:
    """Un foglio del libro: nome, stato e le sue righe."""

    def __init__(self, libro: "Libro", nome: str, percorso: str, stato: str):
        self.libro = libro
        self.nome = nome
        self.percorso = percorso
        self.stato = stato

    @property
    def nascosto(self) -> bool:
        return self.stato != "visible"

    def righe(self):
        """Genera le righe come liste di stringhe, senza celle vuote in coda."""
        radice = _radice(self.libro.zip, self.percorso)
        dati = radice.find("m:sheetData", NS)
        if dati is None:
            return
        for riga in dati:
            celle = {}
            for cella in riga:
                indice = _colonna(cella.get("r") or "")
                if indice is None:
                    continue
                celle[indice] = self.libro._valore(cella)
            if not celle:
                yield []
                continue
            largo = max(celle) + 1
            yield [celle.get(i, "") for i in range(largo)]

    def tabella(self, intestazioni_attese=()):
        """Le righe come dizionari, con le chiavi prese dall'INTESTAZIONE del foglio.

        SI MAPPA PER NOME, NON PER POSIZIONE, e non e' pedanteria: nel piano reale i
        settantadue fogli di indirizzi hanno CINQUE forme di intestazione diverse
        (alcuni hanno `Label` e `ID`, altri partono da `IP`; uno ha una colonna `EU`
        in piu'). Un lettore posizionale prenderebbe l'hostname dalla colonna della
        descrizione su un quinto dei fogli, in silenzio.

        `intestazioni_attese` dice quali nomi cercare per riconoscere la riga di
        intestazione: la prima riga che li contiene tutti e' quella.
        """
        attese = {str(v).strip().lower() for v in intestazioni_attese}
        chiavi = None
        for riga in self.righe():
            pulite = [str(c).strip() for c in riga]
            minuscole = {c.lower() for c in pulite if c}
            if chiavi is None:
                if attese and attese <= minuscole:
                    chiavi = [c.strip().lower() for c in pulite]
                continue
            if not any(pulite):
                continue
            voce = {}
            for i, chiave in enumerate(chiavi):
                if not chiave:
                    continue
                voce[chiave] = pulite[i] if i < len(pulite) else ""
            yield voce


class Libro:
    """Un file .xlsx aperto in lettura."""

    def __init__(self, percorso_o_dati):
        self.zip = zipfile.ZipFile(percorso_o_dati)
        self._controlla_dimensioni()
        self._stringhe = self._leggi_stringhe()
        self.fogli = self._leggi_fogli()

    # -- apertura e limiti ---------------------------------------------------
    def _controlla_dimensioni(self) -> None:
        voci = self.zip.infolist()
        if len(voci) > MAX_VOCI:
            raise XlsxNonValido("l'archivio contiene %d voci: oltre il limite"
                                % len(voci))
        espanso = sum(v.file_size for v in voci)
        if espanso > MAX_ESPANSO_BYTES:
            raise XlsxNonValido(
                "l'archivio si espanderebbe a %d byte: oltre il limite" % espanso)
        if "xl/workbook.xml" not in self.zip.namelist():
            raise XlsxNonValido("non e' un foglio di calcolo: manca xl/workbook.xml")

    def _leggi_stringhe(self) -> list:
        if "xl/sharedStrings.xml" not in self.zip.namelist():
            return []
        radice = _radice(self.zip, "xl/sharedStrings.xml")
        testi = []
        for si in radice.findall("m:si", NS):
            testi.append("".join(t.text or "" for t in si.iter("{%s}t" % NS["m"])))
        return testi

    def _leggi_fogli(self) -> list:
        collegamenti = {}
        if "xl/_rels/workbook.xml.rels" in self.zip.namelist():
            radice = _radice(self.zip, "xl/_rels/workbook.xml.rels")
            for rel in radice:
                collegamenti[rel.get("Id")] = rel.get("Target") or ""
        radice = _radice(self.zip, "xl/workbook.xml")
        elenco = radice.find("m:sheets", NS)
        fogli = []
        for sh in (elenco if elenco is not None else []):
            bersaglio = collegamenti.get(sh.get("{%s}id" % NS["r"]), "")
            if not bersaglio:
                continue
            if not bersaglio.startswith("/"):
                bersaglio = "xl/" + bersaglio.lstrip("./")
            bersaglio = bersaglio.lstrip("/")
            if bersaglio not in self.zip.namelist():
                continue
            fogli.append(Foglio(self, sh.get("name") or "", bersaglio,
                                sh.get("state") or "visible"))
        return fogli

    # -- lettura -------------------------------------------------------------
    def _valore(self, cella) -> str:
        tipo = cella.get("t")
        if tipo == "s":
            v = cella.find("m:v", NS)
            if v is None or v.text is None:
                return ""
            try:
                return (self._stringhe[int(v.text)] or "").strip()
            except (ValueError, IndexError):
                return ""
        if tipo == "inlineStr":
            blocco = cella.find("m:is", NS)
            if blocco is None:
                return ""
            return "".join(t.text or "" for t in blocco.iter("{%s}t" % NS["m"])).strip()
        v = cella.find("m:v", NS)
        return (v.text or "").strip() if v is not None else ""

    def foglio(self, nome: str) -> Foglio | None:
        for f in self.fogli:
            if f.nome == nome:
                return f
        return None

    @property
    def nomi(self) -> list:
        return [f.nome for f in self.fogli]

    def close(self) -> None:
        self.zip.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def _colonna(riferimento: str):
    """Da 'BC12' all'indice 0-based della colonna. `None` se non e' un riferimento."""
    trovato = re.match(r"([A-Z]+)", riferimento)
    if not trovato:
        return None
    indice = 0
    for carattere in trovato.group(1):
        indice = indice * 26 + (ord(carattere) - 64)
    return indice - 1


def errore_di_excel(valore: str) -> bool:
    """Vero se la cella contiene un errore salvato da Excel.

    Nel piano reale ce ne sono a centinaia (`#REF!`, `#VALUE!`): sono formule rotte,
    non dati. Crederci significherebbe importare "#VALUE!" come nome di una subnet.
    """
    return str(valore or "").strip().upper() in {
        "#REF!", "#VALUE!", "#N/A", "#NAME?", "#DIV/0!", "#NULL!", "#NUM!"}


def pulito(valore: str) -> str:
    """Il testo di una cella, con gli errori di Excel trattati come vuoto."""
    testo = str(valore or "").strip()
    return "" if errore_di_excel(testo) else testo
