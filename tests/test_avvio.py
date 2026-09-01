"""
snap - Test dell'avvio: diario su file e forma dello script di avvio.

Difetto che ha dato origine a questi test: lo script apriva una finestra per
componente e rediriggeva ENTRAMBI i flussi su file. La finestra, per costruzione,
non poteva mostrare niente: due finestre vuote facevano credere che il prodotto non
fosse partito, mentre i due servizi erano regolarmente in ascolto.

La correzione ha due parti, e qui si verificano entrambe: l'applicazione sa scrivere
un diario su file (cosi' il file non serve piu' a catturare la console), e lo script
lascia l'uscita alla finestra invece di deviarla.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

RADICE = Path(__file__).resolve().parent.parent


@pytest.fixture()
def radice_pulita():
    """Toglie i diari su file lasciati dalle prove: sono sul logger radice, che e'
    condiviso, e un gestore dimenticato scriverebbe dentro le prove successive."""
    prima = list(logging.getLogger().handlers)
    yield
    radice = logging.getLogger()
    for gestore in list(radice.handlers):
        if gestore not in prima:
            radice.removeHandler(gestore)
            gestore.close()


# --------------------------------------------------------------------------- #
# Il diario su file, in aggiunta a quello a schermo
# --------------------------------------------------------------------------- #
def test_il_server_scrive_il_diario_sul_file_indicato(tmp_path, monkeypatch,
                                                      radice_pulita):
    """Serve all'avvio assistito: la finestra mostra cosa accade, il file lo
    conserva per la diagnosi del giorno dopo."""
    import snapserver

    percorso = tmp_path / "diari" / "server.log"
    monkeypatch.setenv("SNAP_SERVER_DATABASE", str(tmp_path / "prova.sqlite3"))
    monkeypatch.setenv("SNAP_SERVER_SECRET_KEY", "prova")
    monkeypatch.setenv("SNAP_SERVER_LOG_FILE", str(percorso))

    import importlib

    import snapserver.settings as impostazioni

    importlib.reload(impostazioni)
    quanti_prima = len(logging.getLogger().handlers)
    applicazione = snapserver.create_app(impostazioni.Config)
    logging.getLogger("snapserver").warning("riga di prova")

    assert percorso.is_file(), "la cartella del diario va creata se non c'e'"
    assert "riga di prova" in percorso.read_text(encoding="utf-8")
    assert applicazione is not None

    su_file = [g for g in logging.getLogger().handlers
               if isinstance(g, logging.FileHandler)
               and g.baseFilename == str(percorso.resolve())]
    assert len(su_file) == 1
    assert su_file[0].level == logging.NOTSET, (
        "il diario su file non filtra per conto proprio: riceve quello che riceve"
        " il resto, altrimenti in esercizio perderebbe le righe informative")
    assert len(logging.getLogger().handlers) == quanti_prima + 1, (
        "il diario su file si AGGIUNGE a quello a schermo, non lo sostituisce")


def test_senza_indicazione_non_si_crea_nessun_file(tmp_path, monkeypatch,
                                                   radice_pulita):
    """L'avvio manuale e i test non devono lasciare file in giro."""
    import importlib

    import snapserver
    import snapserver.settings as impostazioni

    monkeypatch.setenv("SNAP_SERVER_DATABASE", str(tmp_path / "prova.sqlite3"))
    monkeypatch.setenv("SNAP_SERVER_SECRET_KEY", "prova")
    monkeypatch.delenv("SNAP_SERVER_LOG_FILE", raising=False)

    importlib.reload(impostazioni)
    quanti_prima = len([g for g in logging.getLogger().handlers
                        if isinstance(g, logging.FileHandler)])
    snapserver.create_app(impostazioni.Config)

    quanti_dopo = len([g for g in logging.getLogger().handlers
                       if isinstance(g, logging.FileHandler)])
    assert quanti_dopo == quanti_prima
    assert list(tmp_path.glob("*.log")) == []


def test_un_diario_non_apribile_non_impedisce_l_avvio(tmp_path, monkeypatch,
                                                      radice_pulita, caplog):
    """Il diario e' un aiuto, non un requisito: se il percorso non e' scrivibile il
    servizio parte comunque, ma la cosa viene dichiarata -- un diario che si crede
    attivo e non lo e' e' peggio della sua assenza."""
    import importlib

    import snapserver
    import snapserver.settings as impostazioni

    # Un file al posto della cartella: la creazione della cartella non puo' riuscire.
    ostacolo = tmp_path / "ostacolo"
    ostacolo.write_text("non sono una cartella", encoding="utf-8")

    monkeypatch.setenv("SNAP_SERVER_DATABASE", str(tmp_path / "prova.sqlite3"))
    monkeypatch.setenv("SNAP_SERVER_SECRET_KEY", "prova")
    monkeypatch.setenv("SNAP_SERVER_LOG_FILE", str(ostacolo / "server.log"))

    importlib.reload(impostazioni)
    with caplog.at_level(logging.WARNING):
        applicazione = snapserver.create_app(impostazioni.Config)

    assert applicazione is not None, "il servizio parte anche senza diario su file"
    assert any("Diario su file non disponibile" in r.message for r in caplog.records), \
        "il problema va dichiarato, non ingoiato"


def test_il_diario_non_si_apre_due_volte(tmp_path, monkeypatch, radice_pulita):
    """Con il ricaricatore automatico create_app viene chiamata due volte: due
    gestori sullo stesso file scriverebbero ogni riga in doppio."""
    import importlib

    import snapserver
    import snapserver.settings as impostazioni

    percorso = tmp_path / "server.log"
    monkeypatch.setenv("SNAP_SERVER_DATABASE", str(tmp_path / "prova.sqlite3"))
    monkeypatch.setenv("SNAP_SERVER_SECRET_KEY", "prova")
    monkeypatch.setenv("SNAP_SERVER_LOG_FILE", str(percorso))

    importlib.reload(impostazioni)
    snapserver.create_app(impostazioni.Config)
    snapserver.create_app(impostazioni.Config)

    su_file = [g for g in logging.getLogger().handlers
               if isinstance(g, logging.FileHandler)
               and g.baseFilename == str(percorso.resolve())]
    assert len(su_file) == 1


def test_la_sonda_scrive_il_diario_sul_file_indicato(tmp_path, monkeypatch,
                                                     radice_pulita):
    import importlib

    import snapprobe
    import snapprobe.settings as impostazioni

    percorso = tmp_path / "sonda.log"
    monkeypatch.setenv("SNAP_PROBE_STORE", str(tmp_path / "sonda.sqlite3"))
    monkeypatch.setenv("SNAP_PROBE_SECRET_KEY", "prova")
    monkeypatch.setenv("SNAP_PROBE_LOG_FILE", str(percorso))

    importlib.reload(impostazioni)
    importlib.reload(snapprobe)
    snapprobe.create_app(impostazioni.TestConfig, start_agent=False)
    logging.getLogger("snapprobe").warning("riga di prova")

    assert percorso.is_file()
    assert "riga di prova" in percorso.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Forma dello script di avvio
# --------------------------------------------------------------------------- #
def _script() -> str:
    return (RADICE / "start.ps1").read_text(encoding="utf-8")


def test_l_avvio_non_devia_l_uscita_dei_componenti():
    """E' la causa del difetto: con entrambi i flussi rediretti su file, la finestra
    che Windows apre per un processo di console non puo' mostrare nulla."""
    script = _script()
    assert "-RedirectStandardOutput" not in script, (
        "l'uscita deve restare nella finestra del componente: il file lo scrive"
        " l'applicazione, con SNAP_*_LOG_FILE")
    assert "-RedirectStandardError" not in script
    assert "SNAP_SERVER_LOG_FILE" in script and "SNAP_PROBE_LOG_FILE" in script
    assert "PYTHONUNBUFFERED" in script, (
        "senza questo l'uscita compare a blocchi e la finestra sembra ferma")
    assert "-NoExit" in script, (
        "una finestra che si chiude porta via con se' il motivo dell'errore")


def test_l_avvio_puo_esporre_i_componenti_su_un_indirizzo_di_rete():
    script = _script()
    assert "$ServerHost" in script and "$ProbeHost" in script
    assert "--host" in script, "l'indirizzo di ascolto va passato a run.py"
    # Aprire alla rete non deve chiudere il locale: la sonda conferisce su 127.0.0.1.
    assert "'0.0.0.0'" in script, (
        "con un indirizzo di rete si ascolta su tutte le interfacce, altrimenti"
        " 127.0.0.1 smette di rispondere e la sonda locale resta muta")


def test_l_avvio_dichiara_i_rischi_di_cio_che_apre():
    """Un'apertura silenziosa e' il modo piu' rapido per lasciare esposto un
    servizio che nessuno ricorda di aver aperto."""
    script = _script()
    assert "HTTP, non HTTPS" in script, "il canale in chiaro va dichiarato"
    assert "protetta da password" in script, (
        "l'interfaccia della sonda ha un accesso (DEC-11): lo script deve dirlo,"
        " altrimenti si continua a credere il contrario")
    assert "POSTAZIONE DELLA SONDA" in script, (
        "la prima password si scegle in locale: chi apre alla rete deve sapere dove"
        " andare per impostarla")
    assert "New-NetFirewallRule" in script, (
        "il firewall di Windows blocca l'ingresso: senza il comando pronto la causa"
        " sembra il prodotto")
    assert "-RemoteAddress" in script, "per la sonda si suggerisce un solo indirizzo"


def test_le_porte_restano_nell_intervallo_assegnato():
    """Vincolo di progetto: le applicazioni espongono solo porte 5500-5600."""
    script = _script()
    assert "$ServerPort = 5500" in script
    assert "$ProbePort = 5510" in script
