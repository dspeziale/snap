# -----------------------------------------------------------------
# test_password_sonda.py — impostare e reimpostare la password dell'interfaccia
# Autore: Daniele Speziale
# Data creazione: 2026-09-15
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap probe - La via d'uscita per una password dimenticata.

IL BUCO CHE QUESTE PROVE CHIUDONO. La prima password si sceglie da
`/primo-accesso`, che risponde soltanto a chi apre la pagina dalla macchina della
sonda: e' giusto, perche' il primo che passa non deve poter diventare proprietario di
una sonda appena installata. Ma quella pagina vale SOLO finche' una password non
c'e': se c'e' gia', rimanda all'accesso. Una password dimenticata non aveva quindi
nessuna procedura -- restava da cancellare a mano una riga nelle impostazioni
dell'archivio, cosa che non era scritta da nessuna parte.

La sicurezza non cala: il comando richiede una shell sulla macchina della sonda e i
permessi per aprirne l'archivio. Chi puo' eseguirlo potrebbe gia' cambiare l'impronta
a mano.

remarks: Autore: Daniele Speziale - Data: 2026-09-15
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

RADICE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RADICE / "probe"))


# --------------------------------------------------------------------------- #
# La password generata
# --------------------------------------------------------------------------- #
def test_la_password_generata_rispetta_la_politica():
    """Generata a caso e poi VERIFICATA, non composta a pezzi: comporre "una
    maiuscola, una minuscola, una cifra e poi il resto" riduce lo spazio delle
    password possibili in un modo che non si vede a occhio."""
    import run as probe_run
    from snapprobe.auth import errori_di_politica

    for _ in range(40):
        password = probe_run.genera_password()
        assert not errori_di_politica(password), password
        assert len(password) == probe_run.LUNGHEZZA_GENERATA


def test_la_password_generata_non_si_ripete():
    import run as probe_run

    generate = {probe_run.genera_password() for _ in range(50)}
    assert len(generate) == 50, "due generazioni hanno prodotto la stessa password"


def test_l_alfabeto_evita_i_caratteri_che_si_confondono():
    """Una password va citata al telefono o incollata in un comando: la "l" di lima e
    la "I" di India, lo zero e la O, sono il modo in cui si perde un quarto d'ora."""
    import run as probe_run

    for confondibile in ("l", "I", "1", "O", "0"):
        assert confondibile not in probe_run.ALFABETO_GENERATO, confondibile
    # E niente che una shell interpreti.
    for pericoloso in ("$", "`", '"', "'", "\\", ";", "|", "&", "*"):
        assert pericoloso not in probe_run.ALFABETO_GENERATO, pericoloso


# --------------------------------------------------------------------------- #
# Il comando
# --------------------------------------------------------------------------- #
def test_il_comando_imposta_la_password(probe_store, capsys):
    """La prima impostazione: prima non c'e' nessuna impronta."""
    import run as probe_run
    from snapprobe.auth import password_impostata, verifica_password

    assert not password_impostata()
    assert probe_run.command_password("Prova!Sonda2026", casuale=False) == 0

    assert password_impostata()
    assert verifica_password(probe_store.get_setting("ui_password_hash"),
                             "Prova!Sonda2026")


def test_il_comando_reimposta_una_password_dimenticata(probe_store):
    """E' la ragione per cui il comando esiste: `/primo-accesso` non serve piu' una
    volta che una password c'e'."""
    import run as probe_run
    from snapprobe.auth import verifica_password

    probe_run.command_password("Vecchia!2026", casuale=False)
    probe_run.command_password("Nuova!Sonda2026", casuale=False)

    impronta = probe_store.get_setting("ui_password_hash")
    assert verifica_password(impronta, "Nuova!Sonda2026")
    assert not verifica_password(impronta, "Vecchia!2026")


def test_una_password_debole_viene_rifiutata_senza_cambiare_niente(probe_store):
    """Il rifiuto deve lasciare l'archivio com'era: una password rifiutata che
    intanto ha cancellato quella buona sarebbe peggio di nessun comando."""
    import run as probe_run
    from snapprobe.auth import verifica_password

    probe_run.command_password("Buona!Sonda2026", casuale=False)
    prima = probe_store.get_setting("ui_password_hash")

    assert probe_run.command_password("corta", casuale=False) == 1

    assert probe_store.get_setting("ui_password_hash") == prima
    assert verifica_password(prima, "Buona!Sonda2026")


def test_la_generata_viene_mostrata_una_volta(probe_store, capsys):
    """Si conserva come impronta: se non la si legge adesso, non la si legge piu'."""
    import run as probe_run
    from snapprobe.auth import verifica_password

    assert probe_run.command_password("", casuale=True) == 0
    uscita = capsys.readouterr().out

    mostrata = [r.strip() for r in uscita.splitlines() if r.strip()]
    candidate = [r for r in mostrata if len(r) == probe_run.LUNGHEZZA_GENERATA]
    assert candidate, "la password generata non e' stata mostrata"
    assert verifica_password(probe_store.get_setting("ui_password_hash"),
                             candidate[0])
    assert "UNA VOLTA" in uscita


def test_la_password_sulla_riga_di_comando_avvisa(probe_store, capsys):
    """Si accetta perche' serve agli automatismi, ma resta nella cronologia della
    shell e nell'elenco dei processi: chi la usa deve saperlo adesso, non fra un
    mese leggendo la cronologia."""
    import run as probe_run

    probe_run.command_password("DaRiga!Sonda2026", casuale=False)
    uscita = capsys.readouterr().out

    assert "cronologia" in uscita


def test_il_modulo_di_autenticazione_funziona_fuori_dall_applicazione(probe_store):
    """Il comando gira senza contesto Flask: se `auth` lo pretendesse, la via
    d'uscita non esisterebbe -- ed e' esattamente com'era."""
    from snapprobe.auth import imposta_password, password_impostata

    imposta_password("FuoriContesto2026")

    assert password_impostata()


def test_impostare_la_password_azzera_i_tentativi_falliti(probe_store):
    """Chi reimposta la password dopo essersi bloccato fuori non deve trovare il
    blocco ancora attivo: sarebbe la via d'uscita che non porta fuori."""
    import run as probe_run

    probe_store.set_settings({"ui_failed_logins": "5",
                              "ui_locked_until": "2099-01-01 00:00:00"})
    probe_run.command_password("Sbloccata!2026", casuale=False)

    assert probe_store.get_setting("ui_failed_logins") == "0"
    assert not (probe_store.get_setting("ui_locked_until") or "").strip()
