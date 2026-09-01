"""
snap - Test dell'accesso all'interfaccia della sonda.

Perche' esiste: finche' l'interfaccia della sonda rispondeva solo su `127.0.0.1`
valeva DEC-05 -- strumento locale, nessuna superficie dall'esterno. Da quando la si
puo' aprire alla rete (DEC-05a), senza credenziali chiunque la raggiunga puo'
registrare la sonda presso un altro server, cambiarne la configurazione o sospendere
le scansioni. Queste prove verificano che la porta sia chiusa e che si apra solo nel
modo previsto.

remarks: Autore: Daniele Speziale - Data: 2026-08-31
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest

PASSWORD = "SondaProva2026"
DA_RETE = {"REMOTE_ADDR": "10.20.10.9"}
DA_LOCALE = {"REMOTE_ADDR": "127.0.0.1"}


@pytest.fixture()
def sonda(tmp_path, monkeypatch):
    """Sonda con archivio temporaneo e SENZA password: e' lo stato di prima apertura."""
    import importlib

    monkeypatch.setenv("SNAP_PROBE_STORE", str(tmp_path / "probe.sqlite3"))
    monkeypatch.setenv("SNAP_PROBE_SECRET_KEY", "test-secret-key")

    import snapprobe
    import snapprobe.settings as impostazioni

    importlib.reload(impostazioni)
    importlib.reload(snapprobe)
    return snapprobe.create_app(impostazioni.TestConfig, start_agent=False)


@pytest.fixture()
def sonda_protetta(sonda):
    """Sonda con la password gia' scelta."""
    with sonda.app_context():
        from snapprobe.auth import imposta_password

        imposta_password(PASSWORD)
    return sonda


def _store(applicazione):
    return applicazione.extensions["snap_store"]


# --------------------------------------------------------------------------- #
# Prima apertura
# --------------------------------------------------------------------------- #
def test_senza_password_ogni_pagina_porta_alla_prima_apertura(sonda):
    client = sonda.test_client()
    risposta = client.get("/", environ_base=DA_LOCALE)

    assert risposta.status_code == 302
    assert "/primo-accesso" in risposta.headers["Location"]


def test_nessuna_password_di_fabbrica(sonda):
    """Una credenziale predefinita e' la prima cosa che si prova su un dispositivo
    trovato in rete: qui non ce n'e' nessuna."""
    with sonda.app_context():
        from snapprobe.auth import CHIAVE_HASH, password_impostata

        assert not password_impostata()
        assert not _store(sonda).get_setting(CHIAVE_HASH)


def test_la_prima_password_non_si_scegle_dalla_rete(sonda):
    """Se l'interfaccia e' stata aperta alla rete prima di scegliere la password, il
    primo che arriva non deve poter diventare il proprietario della sonda."""
    client = sonda.test_client()
    pagina = client.get("/primo-accesso", environ_base=DA_RETE)

    assert pagina.status_code == 403
    testo = pagina.get_data(as_text=True)
    assert "solo in locale" in testo.lower() or "solo locale" in testo.lower()
    assert "10.20.10.9" in testo, "l'indirizzo che ha provato va dichiarato"
    # Chi apre l'interfaccia dalla postazione della sonda usando l'indirizzo di rete
    # sta a un clic dalla soluzione: il collegamento locale glielo offre, con la
    # porta su cui la sonda ascolta davvero.
    assert 'href="http://127.0.0.1:' in testo
    assert "/primo-accesso" in testo

    tentativo = client.post("/primo-accesso",
                            data={"password": PASSWORD, "conferma": PASSWORD},
                            environ_base=DA_RETE)
    assert tentativo.status_code == 403
    with sonda.app_context():
        from snapprobe.auth import password_impostata

        assert not password_impostata(), "nessuna password impostata dalla rete"


def test_la_prima_password_si_scegle_dalla_postazione_della_sonda(sonda):
    client = sonda.test_client()
    risposta = client.post("/primo-accesso",
                           data={"password": PASSWORD, "conferma": PASSWORD},
                           environ_base=DA_LOCALE)

    assert risposta.status_code == 302
    with sonda.app_context():
        from snapprobe.auth import password_impostata

        assert password_impostata()

    # La sessione si apre da se': chi ha appena scelto la password non deve
    # ridigitarla per entrare.
    assert client.get("/", environ_base=DA_LOCALE).status_code == 200


def test_una_password_debole_non_viene_accettata(sonda):
    client = sonda.test_client()
    risposta = client.post("/primo-accesso", data={"password": "corta", "conferma": "corta"},
                           environ_base=DA_LOCALE)

    assert risposta.status_code == 400
    assert "10 caratteri" in risposta.get_data(as_text=True)
    with sonda.app_context():
        from snapprobe.auth import password_impostata

        assert not password_impostata()


def test_le_due_password_devono_coincidere(sonda):
    client = sonda.test_client()
    risposta = client.post("/primo-accesso",
                           data={"password": PASSWORD, "conferma": PASSWORD + "x"},
                           environ_base=DA_LOCALE)

    assert risposta.status_code == 400
    assert "non coincidono" in risposta.get_data(as_text=True)


def test_la_password_non_si_conserva_in_chiaro(sonda_protetta):
    with sonda_protetta.app_context():
        from snapprobe.auth import CHIAVE_HASH

        impronta = _store(sonda_protetta).get_setting(CHIAVE_HASH)

    assert PASSWORD not in impronta
    assert impronta.startswith("scrypt:"), (
        "algoritmo di hashing attuale, dalla libreria standard: %s" % impronta[:20])


# --------------------------------------------------------------------------- #
# Accesso
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("percorso", ["/", "/configuration", "/diary", "/enroll",
                                      "/guida"])
def test_ogni_pagina_richiede_l_accesso(sonda_protetta, percorso):
    risposta = sonda_protetta.test_client().get(percorso, environ_base=DA_RETE)

    assert risposta.status_code == 302
    assert "/login" in risposta.headers["Location"]


@pytest.mark.parametrize("percorso", ["/actions/collect", "/actions/flush",
                                      "/actions/scan/toggle", "/actions/reset",
                                      "/enroll", "/server-url"])
def test_nessuna_azione_si_compie_senza_accesso(sonda_protetta, percorso):
    """E' il punto che conta: senza credenziali non si deve poter riconfigurare la
    sonda ne' sospenderne le scansioni."""
    risposta = sonda_protetta.test_client().post(percorso, data={}, environ_base=DA_RETE)

    assert risposta.status_code == 302
    assert "/login" in risposta.headers["Location"]


def test_l_indicatore_di_attivita_risponde_in_json_non_con_una_pagina(sonda_protetta):
    """La pagina interroga `status.json` ogni pochi secondi: una pagina di accesso
    dentro quella risposta verrebbe letta come dato."""
    risposta = sonda_protetta.test_client().get("/status.json", environ_base=DA_RETE)

    assert risposta.status_code == 401
    assert risposta.is_json
    assert "accesso" in risposta.get_json()["errore"]


def test_con_la_password_giusta_si_entra(sonda_protetta):
    client = sonda_protetta.test_client()
    risposta = client.post("/login", data={"password": PASSWORD}, environ_base=DA_RETE)

    assert risposta.status_code == 302
    assert client.get("/", environ_base=DA_RETE).status_code == 200

    with sonda_protetta.app_context():
        diario = [r["message"] for r in _store(sonda_protetta).recent_events(10)]
    assert any("Accesso all'interfaccia riuscito" in m for m in diario), (
        "l'accesso va registrato nel diario: e' la traccia di chi ha toccato la sonda")


def test_con_la_password_sbagliata_non_si_entra(sonda_protetta):
    client = sonda_protetta.test_client()
    risposta = client.post("/login", data={"password": "sbagliata"}, environ_base=DA_RETE)

    assert risposta.status_code == 401
    assert client.get("/", environ_base=DA_RETE).status_code == 302

    with sonda_protetta.app_context():
        diario = [r["message"] for r in _store(sonda_protetta).recent_events(10)]
    assert any("non riuscito" in m for m in diario)


def test_dopo_cinque_tentativi_l_accesso_si_blocca(sonda_protetta):
    client = sonda_protetta.test_client()
    for _ in range(5):
        client.post("/login", data={"password": "sbagliata"}, environ_base=DA_RETE)

    # Anche con la password GIUSTA il blocco tiene: diversamente non sarebbe un
    # blocco ma un consiglio.
    risposta = client.post("/login", data={"password": PASSWORD}, environ_base=DA_RETE)
    assert risposta.status_code == 429
    assert "minuti" in risposta.get_data(as_text=True)

    with sonda_protetta.app_context():
        diario = [r["message"] for r in _store(sonda_protetta).recent_events(10)]
    assert any("bloccato" in m for m in diario)


def test_l_uscita_chiude_la_sessione(sonda_protetta):
    client = sonda_protetta.test_client()
    client.post("/login", data={"password": PASSWORD}, environ_base=DA_RETE)
    assert client.get("/", environ_base=DA_RETE).status_code == 200

    client.post("/logout", environ_base=DA_RETE)
    assert client.get("/", environ_base=DA_RETE).status_code == 302


def test_l_uscita_non_si_compie_con_un_collegamento(sonda_protetta):
    """Un'azione raggiungibile in GET la puo' far compiere chi manda un collegamento."""
    client = sonda_protetta.test_client()
    client.post("/login", data={"password": PASSWORD}, environ_base=DA_RETE)

    assert client.get("/logout", environ_base=DA_RETE).status_code == 405
    assert client.get("/", environ_base=DA_RETE).status_code == 200


def test_dopo_l_accesso_si_torna_dove_si_stava(sonda_protetta):
    client = sonda_protetta.test_client()
    client.get("/configuration", environ_base=DA_RETE)  # rimando alla pagina di accesso
    risposta = client.post("/login", data={"password": PASSWORD, "avanti": "/configuration"},
                           environ_base=DA_RETE)

    assert risposta.status_code == 302
    assert risposta.headers["Location"].endswith("/configuration")


def test_un_indirizzo_esterno_nel_rimando_viene_ignorato(sonda_protetta):
    """Un campo di rimando che accetta indirizzi esterni e' un aiuto a chi costruisce
    un inganno: si accettano solo percorsi interni."""
    client = sonda_protetta.test_client()
    risposta = client.post("/login",
                           data={"password": PASSWORD, "avanti": "//esempio.invalido/"},
                           environ_base=DA_RETE)

    assert "esempio.invalido" not in risposta.headers["Location"]


# --------------------------------------------------------------------------- #
# Cambio password
# --------------------------------------------------------------------------- #
def test_il_cambio_password_richiede_quella_attuale(sonda_protetta):
    client = sonda_protetta.test_client()
    client.post("/login", data={"password": PASSWORD}, environ_base=DA_RETE)

    client.post("/password", data={"attuale": "sbagliata", "nuova": "NuovaSonda2026",
                                   "conferma": "NuovaSonda2026"}, environ_base=DA_RETE)

    with sonda_protetta.app_context():
        from snapprobe.auth import CHIAVE_HASH, verifica_password

        impronta = _store(sonda_protetta).get_setting(CHIAVE_HASH)
        assert verifica_password(impronta, PASSWORD), "la password non e' cambiata"


def test_la_password_cambiata_sostituisce_la_precedente(sonda_protetta):
    client = sonda_protetta.test_client()
    client.post("/login", data={"password": PASSWORD}, environ_base=DA_RETE)
    client.post("/password", data={"attuale": PASSWORD, "nuova": "NuovaSonda2026",
                                   "conferma": "NuovaSonda2026"}, environ_base=DA_RETE)
    client.post("/logout", environ_base=DA_RETE)

    vecchia = client.post("/login", data={"password": PASSWORD}, environ_base=DA_RETE)
    assert vecchia.status_code == 401

    nuova = client.post("/login", data={"password": "NuovaSonda2026"},
                        environ_base=DA_RETE)
    assert nuova.status_code == 302


def test_una_nuova_password_debole_non_passa(sonda_protetta):
    client = sonda_protetta.test_client()
    client.post("/login", data={"password": PASSWORD}, environ_base=DA_RETE)
    client.post("/password", data={"attuale": PASSWORD, "nuova": "corta",
                                   "conferma": "corta"}, environ_base=DA_RETE)

    with sonda_protetta.app_context():
        from snapprobe.auth import CHIAVE_HASH, verifica_password

        impronta = _store(sonda_protetta).get_setting(CHIAVE_HASH)
        assert verifica_password(impronta, PASSWORD)


# --------------------------------------------------------------------------- #
# Forma della guardia
# --------------------------------------------------------------------------- #
def test_le_rotte_libere_sono_un_elenco_chiuso():
    """Una rotta nuova deve essere protetta per difetto: e' il verso giusto
    dell'errore. Con una lista di esclusioni sarebbe il contrario."""
    from snapprobe.auth import LIBERE

    assert LIBERE == {"auth.login", "auth.primo_accesso", "static"}


def test_la_provenienza_si_giudica_sull_indirizzo_non_su_un_intestazione(sonda):
    """`X-Forwarded-For` la scrive chi chiama: una decisione di sicurezza non si
    prende su un dato che l'interlocutore controlla."""
    client = sonda.test_client()
    risposta = client.get("/primo-accesso", environ_base=DA_RETE,
                          headers={"X-Forwarded-For": "127.0.0.1"})

    assert risposta.status_code == 403
