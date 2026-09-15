# -----------------------------------------------------------------
# test_anonimizza.py — sostituzione degli identificativi nei documenti che escono
# Autore: Daniele Speziale
# Data creazione: 2026-09-15
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap - Che cosa esce da un documento con esempi reali, e che cosa no.

E' il pezzo che impedisce a un estratto di portare fuori la rete di un cliente, e per
questo e' provato piu' del resto: un difetto qui non produce un messaggio d'errore,
produce un PDF che gira per posta con dentro indirizzi veri.

Le due proprieta' che contano:

* **niente passa intatto** -- indirizzi, subnet, nomi, emittenti interni; e anche gli
  indirizzi nascosti dentro una frase, che sono quelli che si dimenticano;
* **la sostituzione e' coerente** -- lo stesso apparato porta lo stesso identificativo
  finto in tutte le righe, altrimenti due righe sullo stesso apparato sembrano due
  apparati e l'esempio diventa illeggibile.

remarks: Autore: Daniele Speziale - Data: 2026-09-15
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

import pytest

RADICE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RADICE / "tools"))

# Gli intervalli che possono comparire in un documento: sono riservati alla
# documentazione (RFC 5737) e non appartengono a nessuno.
AMMESSI = tuple(ipaddress.ip_network(r) for r in
                ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))


def _di_esempio(indirizzo: str) -> bool:
    quale = ipaddress.ip_address(indirizzo)
    return any(quale in rete for rete in AMMESSI)


@pytest.fixture()
def anonimo():
    from anonimizza import Anonimo

    return Anonimo()


# --------------------------------------------------------------------------- #
# Niente passa intatto
# --------------------------------------------------------------------------- #
def test_un_indirizzo_reale_non_esce_mai(anonimo):
    for reale in ("10.20.3.31", "172.16.4.9", "192.168.1.1", "8.8.8.8"):
        finto = anonimo.indirizzo(reale)
        assert finto != reale, "%s e' uscito intatto" % reale
        assert _di_esempio(finto), "%s non e' un indirizzo di documentazione" % finto


def test_gli_indirizzi_dentro_una_frase_vengono_sostituiti(anonimo):
    """Sono quelli che si dimenticano: stanno in un campo di testo scritto dal
    prodotto, non in una colonna che si sa di dover trattare."""
    frase = ("aperta sul 100% dei nodi di 10.1.26.0/24: la inietta 10.1.26.1,"
             " non il nodo 10.1.26.55")
    uscita = anonimo.testo(frase)

    assert "10.1.26.1" not in uscita
    assert "10.1.26.55" not in uscita
    # Il senso della frase resta.
    assert "la inietta" in uscita and "100%" in uscita


def test_una_subnet_conserva_l_ampiezza_ma_non_l_indirizzo(anonimo):
    """L'ampiezza e' informativa (dice quanto e' grande la rete) e non identifica;
    l'indirizzo di rete invece dice lo schema di indirizzamento dell'ente."""
    finta = anonimo.rete("10.58.7.0/24")

    assert not finta.startswith("10.58")
    assert finta.endswith("/24")


def test_un_nome_di_macchina_diventa_un_genere(anonimo):
    """"ISED-7007-DELL" dice l'ente e spesso la sede. Di utile resta solo che cosa
    e' la macchina, e quello si conserva."""
    finto = anonimo.nome("ISED-7007-DELL", genere="postazione")

    assert "ISED" not in finto
    assert finto.startswith("postazione")


def test_un_emittente_interno_diventa_un_etichetta(anonimo):
    """"lbsrv.solari" e' il nome di un server reale: e' un identificativo quanto un
    indirizzo, e la prima stesura di questo strumento lo avrebbe lasciato passare."""
    assert "solari" not in anonimo.emittente("lbsrv.solari")


def test_le_autorita_pubbliche_restano(anonimo):
    """Sostituirle non protegge nessuno e rende l'esempio meno leggibile: che un
    certificato sia di Let's Encrypt e' proprio l'informazione utile."""
    for pubblica in ("Let's Encrypt R3", "DigiCert Global Root CA", "Sectigo RSA"):
        assert anonimo.emittente(pubblica) == pubblica


def test_un_valore_non_riconosciuto_non_passa_intatto(anonimo):
    """Nel dubbio si sostituisce. Lasciar passare cio' che non si e' saputo
    classificare e' il modo in cui un dato esce senza che nessuno l'abbia deciso."""
    uscita = anonimo.indirizzo("srv-contabilita.interno.ente.it")

    assert "contabilita" not in uscita
    assert "ente" not in uscita


# --------------------------------------------------------------------------- #
# La sostituzione e' coerente
# --------------------------------------------------------------------------- #
def test_lo_stesso_apparato_porta_sempre_lo_stesso_identificativo(anonimo):
    """Se cambiasse a ogni riga, due righe sullo stesso apparato sembrerebbero due
    apparati: l'esempio diventerebbe illeggibile proprio dove deve convincere."""
    primo = anonimo.indirizzo("10.20.3.31")

    assert anonimo.indirizzo("10.20.3.31") == primo
    assert anonimo.testo("il nodo 10.20.3.31 espone la 443").count(primo) == 1


def test_apparati_diversi_non_collassano_sullo_stesso_indirizzo(anonimo):
    finti = {anonimo.indirizzo("10.0.0.%d" % n) for n in range(1, 60)}

    assert len(finti) == 59, "due apparati diversi hanno ricevuto lo stesso indirizzo"


def test_finiti_gli_indirizzi_lo_dichiara_invece_di_riusarli(anonimo):
    """Riusare il primo renderebbe l'esempio FALSO -- due apparati con lo stesso
    indirizzo -- e nessuno se ne accorgerebbe leggendo."""
    anonimo._liberi = []

    assert anonimo.indirizzo("10.9.9.9") == "(oltre l'esempio)"


def test_due_documenti_non_condividono_la_corrispondenza():
    """La tabella vive in memoria e muore con il processo: non esiste un file che
    permetta di tornare dagli indirizzi finti a quelli veri."""
    from anonimizza import Anonimo

    primo, secondo = Anonimo(), Anonimo()
    primo.indirizzo("10.1.1.1")
    primo.indirizzo("10.1.1.2")

    # Il secondo documento riparte da capo: non eredita nulla dal primo.
    assert secondo.indirizzo("10.1.1.2") == primo.indirizzo("10.1.1.1")


def test_il_conteggio_dice_che_cosa_e_stato_sostituito(anonimo):
    """Il documento lo dichiara in fondo: senza, chi lo riceve non ha modo di sapere
    che cosa e' stato protetto e che cosa no."""
    anonimo.indirizzo("10.1.1.1")
    anonimo.rete("10.1.1.0/24")
    anonimo.nome("SRV-01")
    anonimo.emittente("interno.locale")

    assert anonimo.quanti == {"indirizzi": 1, "reti": 1, "nomi": 1, "emittenti": 1}
