# -----------------------------------------------------------------
# test_perimetro_blocco.py — sospendere un intero blocco di indirizzi
# Autore: Daniele Speziale
# Data creazione: 2026-09-14
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Sospensione e riattivazione di tutte le subnet di un aggregato.

IL CASO. Un perimetro reale ha 380 subnet. Quando una sede va in manutenzione si
devono sospendere le trenta che le appartengono: spuntandole a mano, sparse su tre
pagine di tabella, se ne dimentica una e nessuno se ne accorge -- la sonda continua a
scansionarla e il guasto e' silenzioso.

Si scrive `10.58.0.0/16` e il prodotto trova le subnet contenute in quel blocco. Sul
perimetro vero: 29 subnet, di cui 28 attive.

PERCHE' `ipaddress` E NON IL TESTO. Confrontare i prefissi come stringhe ("10.58.")
sbaglia in due modi: prende cio' che non deve (10.580.x non esiste, ma 10.5.8.x
comincia per "10.5") e soprattutto non sa vedere le maschere che non cadono su un
punto -- un /22 o un /12 non si riconoscono guardando le cifre.

remarks: Autore: Daniele Speziale - Data: 2026-09-14
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest

SUBNET_DI_PROVA = (
    ("10.58.10.0/24", "Sede A"),
    ("10.58.200.0/24", "Sede A"),
    ("10.58.0.0/20", "Sede A, aggregato"),
    ("10.59.1.0/24", "Sede B"),
    ("10.6.24.0/24", "Sede C"),
    ("10.6.25.0/24", "Sede C"),
    ("10.6.30.0/24", "Sede D"),
    ("192.168.1.0/24", "Laboratorio"),
)


@pytest.fixture()
def perimetro(server_app):
    """Un perimetro di prova con maschere diverse, non tutte allineate ai punti."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        tenant = query("SELECT id FROM tenants ORDER BY id LIMIT 1", (), one=True)
        for cidr, etichetta in SUBNET_DI_PROVA:
            execute("INSERT INTO subnets (tenant_id, cidr, label, is_enabled,"
                    " created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)"
                    " ON CONFLICT (tenant_id, cidr) DO UPDATE SET is_enabled = 1",
                    (int(tenant["id"]), cidr, etichetta, utc_now_str(), utc_now_str()))
        return int(tenant["id"])


def _stato(server_app, cidr: str) -> int:
    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT is_enabled FROM subnets WHERE cidr = ?", (cidr,), one=True)
        return int(riga["is_enabled"]) if riga else -1


# --------------------------------------------------------------------------- #
# La selezione
# --------------------------------------------------------------------------- #
def test_un_blocco_trova_le_subnet_contenute(server_app, perimetro):
    with server_app.app_context():
        from snapserver.blueprints.inventory import _subnet_contenute

        contenute, errore = _subnet_contenute(perimetro, "10.58.0.0/16")

    assert not errore
    trovate = {v["cidr"] for v in contenute}
    assert trovate == {"10.58.10.0/24", "10.58.200.0/24", "10.58.0.0/20"}


def test_una_maschera_non_allineata_ai_punti_funziona(server_app, perimetro):
    """Il caso che il confronto fra stringhe non puo' risolvere: /22 copre
    10.6.24.0 e 10.6.25.0 ma non 10.6.30.0, e le tre cominciano tutte per "10.6."."""
    with server_app.app_context():
        from snapserver.blueprints.inventory import _subnet_contenute

        contenute, _ = _subnet_contenute(perimetro, "10.6.24.0/22")

    trovate = {v["cidr"] for v in contenute}
    assert trovate == {"10.6.24.0/24", "10.6.25.0/24"}
    assert "10.6.30.0/24" not in trovate


def test_si_accetta_anche_un_indirizzo_dentro_il_blocco(server_app, perimetro):
    """Chi scrive "10.58.3.7/16" intende quel blocco: rifiutarlo e' pedanteria."""
    with server_app.app_context():
        from snapserver.blueprints.inventory import _subnet_contenute

        da_rete, _ = _subnet_contenute(perimetro, "10.58.0.0/16")
        da_indirizzo, _ = _subnet_contenute(perimetro, "10.58.3.7/16")

    assert {v["cidr"] for v in da_rete} == {v["cidr"] for v in da_indirizzo}


def test_un_blocco_scritto_male_non_tocca_niente(server_app, perimetro):
    with server_app.app_context():
        from snapserver.blueprints.inventory import _subnet_contenute

        for scritto in ("banana", "10.58.0.0/99", "", "999.0.0.0/8"):
            contenute, errore = _subnet_contenute(perimetro, scritto)
            assert errore, "%r doveva essere rifiutato" % scritto
            assert contenute == []


def test_un_blocco_senza_corrispondenze_lo_dice(server_app, perimetro):
    with server_app.app_context():
        from snapserver.blueprints.inventory import _subnet_contenute

        contenute, errore = _subnet_contenute(perimetro, "172.16.0.0/12")

    assert not errore
    assert contenute == []


def test_una_riga_malformata_non_ferma_le_altre(server_app, perimetro):
    """Un CIDR illeggibile in archivio non deve far fallire l'intera operazione:
    si salta quella riga e si prosegue."""
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str
        from snapserver.blueprints.inventory import _subnet_contenute

        execute("INSERT INTO subnets (tenant_id, cidr, label, is_enabled,"
                " created_at, updated_at) VALUES (?, 'non-un-cidr', 'rotta', 1, ?, ?)",
                (perimetro, utc_now_str(), utc_now_str()))
        contenute, errore = _subnet_contenute(perimetro, "10.58.0.0/16")

    assert not errore
    assert len(contenute) == 3


# --------------------------------------------------------------------------- #
# L'anteprima non cambia niente
# --------------------------------------------------------------------------- #
def test_l_anteprima_mostra_l_elenco_senza_toccare_nulla(logged_client, server_app,
                                                         perimetro):
    """Una conferma che non dice CHE COSA cambia non e' una conferma informata."""
    risposta = logged_client.post("/inventory/subnets/blocco", data={
        "cidr": "10.58.0.0/16", "state": "off", "azione": "anteprima"})
    testo = risposta.get_data(as_text=True)

    assert risposta.status_code == 200, "l'anteprima non deve rimandare altrove"
    assert "10.58.10.0/24" in testo, "l'elenco di cio' che cambierebbe deve comparire"
    assert "10.58.200.0/24" in testo
    assert "10.59.1.0/24" not in testo or "verrebbero" in testo

    # E soprattutto: non ha cambiato niente.
    assert _stato(server_app, "10.58.10.0/24") == 1
    assert _stato(server_app, "10.58.200.0/24") == 1


# --------------------------------------------------------------------------- #
# L'applicazione
# --------------------------------------------------------------------------- #
def test_sospende_tutte_le_subnet_del_blocco(logged_client, server_app, perimetro):
    logged_client.post("/inventory/subnets/blocco", data={
        "cidr": "10.58.0.0/16", "state": "off", "azione": "applica"},
        follow_redirects=True)

    assert _stato(server_app, "10.58.10.0/24") == 0
    assert _stato(server_app, "10.58.200.0/24") == 0
    assert _stato(server_app, "10.58.0.0/20") == 0
    # E NIENTE ALTRO: e' la meta' che conta di questa prova.
    assert _stato(server_app, "10.59.1.0/24") == 1
    assert _stato(server_app, "10.6.24.0/24") == 1
    assert _stato(server_app, "192.168.1.0/24") == 1


def test_riattiva_tutte_le_subnet_del_blocco(logged_client, server_app, perimetro):
    logged_client.post("/inventory/subnets/blocco", data={
        "cidr": "10.58.0.0/16", "state": "off", "azione": "applica"},
        follow_redirects=True)
    logged_client.post("/inventory/subnets/blocco", data={
        "cidr": "10.58.0.0/16", "state": "on", "azione": "applica"},
        follow_redirects=True)

    assert _stato(server_app, "10.58.10.0/24") == 1
    assert _stato(server_app, "10.58.0.0/20") == 1


def test_l_operazione_resta_nel_registro_delle_azioni(logged_client, server_app,
                                                      perimetro):
    """Sospendere trenta subnet e' una decisione: fra sei mesi si deve poter sapere
    chi l'ha presa, quando, e su che cosa."""
    logged_client.post("/inventory/subnets/blocco", data={
        "cidr": "10.58.0.0/16", "state": "off", "azione": "applica"},
        follow_redirects=True)

    with server_app.app_context():
        from snapserver.db import query

        riga = query("SELECT event_type, description FROM audit_events"
                     " WHERE event_type LIKE 'subnets.%.blocco'"
                     " ORDER BY id DESC LIMIT 1", (), one=True)

    assert riga is not None, "l'operazione non e' stata registrata"
    assert "10.58.0.0/16" in riga["description"]
    # I CIDR toccati stanno nel messaggio: senza, il registro dice "trenta subnet" e
    # nessuno puo' piu' sapere quali.
    assert "10.58.10.0/24" in riga["description"]


def test_applicare_due_volte_non_e_un_errore(logged_client, server_app, perimetro):
    logged_client.post("/inventory/subnets/blocco", data={
        "cidr": "10.58.0.0/16", "state": "off", "azione": "applica"},
        follow_redirects=True)
    risposta = logged_client.post("/inventory/subnets/blocco", data={
        "cidr": "10.58.0.0/16", "state": "off", "azione": "applica"},
        follow_redirects=True)

    assert risposta.status_code == 200
    assert "gia' tutte" in risposta.get_data(as_text=True).replace("&#39;", "'")


def test_il_modulo_porta_il_token_anti_csrf():
    """Un modulo senza token e' un modulo che smette di funzionare appena la
    protezione e' attiva -- e i test di rotta non se ne accorgono, perche' nella
    configurazione di prova il CSRF e' disattivato."""
    from pathlib import Path

    radice = Path(__file__).resolve().parent.parent
    testo = (radice / "server" / "snapserver" / "templates" / "inventory"
             / "subnets.html").read_text(encoding="utf-8")

    inizio = testo.index("inventory.subnets_blocco")
    # I due moduli (anteprima e applicazione) devono avere entrambi il token.
    assert testo.count("inventory.subnets_blocco") == 2
    for pezzo in testo.split("inventory.subnets_blocco")[1:]:
        assert "csrf_token()" in pezzo[:600], (
            "un modulo della sospensione per blocco non ha il token anti-CSRF")
    assert inizio > 0
