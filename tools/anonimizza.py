"""
snap - Sostituzione degli identificativi per i documenti che si consegnano fuori.

PERCHE' NON BASTA SOSTITUIRE GLI INDIRIZZI. In un estratto di report l'indirizzo IP
e' l'identificativo piu' evidente, non l'unico: la subnet dice l'ampiezza e lo schema
di indirizzamento, il nome host dice l'ente e spesso la sede ("ISED-7007-DELL"), e
l'emittente di un certificato interno e' quasi sempre il nome di un server reale
("lbsrv.solari"). Sostituire i soli indirizzi darebbe l'impressione di aver protetto
qualcosa senza averlo fatto.

DETERMINISTICA E COERENTE. Lo stesso indirizzo reale diventa sempre lo stesso
indirizzo finto dentro lo stesso documento: se cambiasse a ogni riga, due righe sullo
stesso apparato sembrerebbero due apparati diversi, e l'esempio non si leggerebbe
piu'. La corrispondenza vive in memoria e muore con il processo: non viene salvata da
nessuna parte, quindi non esiste un file che permetta di tornare indietro.

GLI INDIRIZZI FINTI SONO QUELLI DELLA DOCUMENTAZIONE (RFC 5737): 192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24. Sono riservati proprio a questo uso e non appartengono
a nessuno: usare indirizzi privati a caso avrebbe potuto far somigliare l'esempio alla
rete di qualcun altro.

remarks: Autore: Daniele Speziale - Data: 2026-09-15
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import ipaddress
import re

# Gli intervalli riservati alla documentazione. Tre, perche' con uno solo un esempio
# che cita piu' di 254 apparati finirebbe gli indirizzi.
RETI_DI_ESEMPIO = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")

# Emittenti di certificato che NON si sostituiscono: sono autorita' pubbliche, note a
# chiunque, e non dicono niente di chi le usa. Toglierle renderebbe l'esempio meno
# leggibile senza proteggere nessuno.
EMITTENTI_PUBBLICI = (
    "let's encrypt", "digicert", "sectigo", "globalsign", "actalis", "entrust",
    "godaddy", "amazon", "google trust", "verisign", "thawte", "comodo",
    "microsoft", "isrg",
)

RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class Anonimo:
    """Sostituisce gli identificativi in modo coerente per la durata di un documento."""

    def __init__(self):
        self._indirizzi: dict[str, str] = {}
        self._reti: dict[str, str] = {}
        self._nomi: dict[str, str] = {}
        self._emittenti: dict[str, str] = {}
        self._liberi = [str(a) for rete in RETI_DI_ESEMPIO
                        for a in ipaddress.ip_network(rete).hosts()]
        self._prossima_rete = 0

    # -- indirizzi ---------------------------------------------------------- #
    def indirizzo(self, valore) -> str:
        testo = str(valore or "").strip()
        if not testo:
            return "-"
        if testo in self._indirizzi:
            return self._indirizzi[testo]
        try:
            ipaddress.ip_address(testo)
        except ValueError:
            # Non e' un indirizzo: puo' essere un nome. Si tratta come tale invece di
            # restituirlo intatto, che sarebbe il modo di lasciarsi sfuggire qualcosa.
            return self.nome(testo)
        if not self._liberi:
            # Finiti gli indirizzi di esempio: si dichiara, non si riusa il primo --
            # due apparati con lo stesso indirizzo renderebbero l'esempio falso.
            self._indirizzi[testo] = "(oltre l'esempio)"
            return self._indirizzi[testo]
        self._indirizzi[testo] = self._liberi.pop(0)
        return self._indirizzi[testo]

    def rete(self, valore) -> str:
        """Una subnet. Si conserva l'AMPIEZZA, che e' informativa e non identifica."""
        testo = str(valore or "").strip()
        if not testo:
            return "-"
        if testo in self._reti:
            return self._reti[testo]
        try:
            maschera = ipaddress.ip_network(testo, strict=False).prefixlen
        except ValueError:
            return self.nome(testo)
        base = RETI_DI_ESEMPIO[self._prossima_rete % len(RETI_DI_ESEMPIO)]
        self._prossima_rete += 1
        self._reti[testo] = "%s/%d" % (base.split("/")[0], maschera)
        return self._reti[testo]

    # -- nomi --------------------------------------------------------------- #
    def nome(self, valore, genere: str = "apparato") -> str:
        """Un nome host o di macchina. Il GENERE si conserva perche' e' la sola parte
        che serve a leggere l'esempio; il resto e' l'ente e la sede."""
        testo = str(valore or "").strip()
        if not testo:
            return "-"
        if testo not in self._nomi:
            self._nomi[testo] = "%s-%02d" % (genere, len(self._nomi) + 1)
        return self._nomi[testo]

    def emittente(self, valore) -> str:
        """Emittente di un certificato. Le autorita' pubbliche restano; tutto il resto
        e' un nome interno e diventa un'etichetta."""
        testo = str(valore or "").strip()
        if not testo:
            return "-"
        if any(pubblico in testo.lower() for pubblico in EMITTENTI_PUBBLICI):
            return testo
        if testo not in self._emittenti:
            self._emittenti[testo] = "autorita-interna-%02d" % (len(self._emittenti) + 1)
        return self._emittenti[testo]

    # -- testo libero -------------------------------------------------------- #
    def testo(self, valore) -> str:
        """Sostituisce gli indirizzi che compaiono dentro una frase.

        Serve per i campi scritti a mano dal prodotto -- la spiegazione di una porta
        sospetta, la prova di una vulnerabilita' -- dove l'indirizzo e' in mezzo alle
        parole e non in un campo proprio.
        """
        return RE_IPV4.sub(lambda t: self.indirizzo(t.group(0)), str(valore or ""))

    @property
    def quanti(self) -> dict:
        return {"indirizzi": len(self._indirizzi), "reti": len(self._reti),
                "nomi": len(self._nomi), "emittenti": len(self._emittenti)}
