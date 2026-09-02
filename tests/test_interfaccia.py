"""
snap - Test della dotazione di interfaccia.

Verifica che ogni tabella disponga delle funzioni richieste (ordinamento,
paginazione e ricerca generale), che il dialogo con l'utente passi da Awesome
Notifications e che le librerie siano servite localmente, senza dipendenze da
servizi esterni.

Il comportamento nel browser e' verificato separatamente da tools/collaudo_ui.py.

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

RADICE = Path(__file__).resolve().parent.parent

# Pagine del server che devono presentare almeno una tabella attrezzata.
PAGINE_CON_TABELLA = [
    "/",
    "/probes/",
    "/audit/",
    "/admin/tenants",
    "/admin/users",
    "/inventory/nodes",
    "/inventory/subnets",
    "/inventory/deliveries",
    "/monitor/",
    "/monitor/changes",
]

RISORSE_LOCALI = [
    "/static/vendor/awn/index.var.js",
    "/static/vendor/awn/style.css",
    "/static/vendor/datatables/dataTables.min.js",
    "/static/vendor/datatables/dataTables.bootstrap5.min.js",
    "/static/vendor/datatables/dataTables.bootstrap5.min.css",
    "/static/js/snap-dialogs.js",
    "/static/js/snap-tables.js",
]


@pytest.fixture()
def admin_client(server_app):
    client = server_app.test_client()
    client.post(
        "/login",
        data={
            "email": server_app.config["BOOTSTRAP_ADMIN_EMAIL"],
            "password": server_app.config["BOOTSTRAP_ADMIN_PASSWORD"],
        },
        follow_redirects=True,
    )
    return client


# --------------------------------------------------------------------------- #
# Tabelle
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("percorso", PAGINE_CON_TABELLA)
def test_ogni_pagina_elenco_ha_una_tabella_attrezzata(admin_client, percorso):
    risposta = admin_client.get(percorso)
    assert risposta.status_code == 200, "pagina non raggiungibile: %s" % percorso
    assert "data-snap-table" in risposta.data.decode("utf-8"), (
        "la tabella di %s non e' attrezzata" % percorso
    )


def test_nessuna_tabella_priva_di_attrezzatura_nei_modelli():
    """Ogni tabella con intestazioni nei modelli deve essere dichiarata interattiva."""
    mancanti = []
    for cartella in ("server/snapserver/templates", "probe/snapprobe/templates"):
        for modello in (RADICE / cartella).rglob("*.html"):
            testo = modello.read_text(encoding="utf-8")
            for apertura in re.finditer(r"<table\b[^>]*>", testo):
                seguito = testo[apertura.end():apertura.end() + 400]
                if "<thead" not in seguito:
                    continue  # tabelle di sola presentazione, senza intestazioni
                if "data-snap-table" not in apertura.group(0):
                    mancanti.append("%s: %s" % (modello.name, apertura.group(0)[:60]))
    assert not mancanti, "tabelle senza funzioni interattive: %s" % mancanti


def test_le_funzioni_richieste_sono_configurate():
    """Il modulo delle tabelle deve realizzare tutte le funzioni richieste."""
    modulo = (RADICE / "server/snapserver/static/js/snap-tables.js").read_text(encoding="utf-8")
    attese = {
        "libreria DataTables": "new DataTable(",
        "ordinamento": "order:",
        "colonne non ordinabili": "orderable",
        "paginazione": "paging: true",
        "dimensione della pagina": "pageLength",
        "ricerca generale": "searching",
        "interfaccia in italiano": "Nessun risultato con i criteri impostati",
    }
    assenti = [nome for nome, indizio in attese.items() if indizio not in modulo]
    assert not assenti, "funzioni non configurate: %s" % assenti


def test_le_tabelle_della_sonda_usano_lo_stesso_modulo():
    """Il modulo delle tabelle e' identico nei due applicativi, tranne l'intestazione."""
    server = (RADICE / "server/snapserver/static/js/snap-tables.js").read_text(encoding="utf-8")
    sonda = (RADICE / "probe/snapprobe/static/js/snap-tables.js").read_text(encoding="utf-8")
    assert server.replace("snap server", "snap probe") == sonda


def test_i_grafici_della_sonda_usano_lo_stesso_modulo():
    """La sonda ha una copia propria del modulo (i due applicativi si distribuiscono
    separati), e le copie divergono in silenzio: era gia' successo, con la sonda
    rimasta a una versione precedente del disegno. Se cambia una, cambia l'altra."""
    server = (RADICE / "server/snapserver/static/js/snap-grafici.js").read_text(encoding="utf-8")
    sonda = (RADICE / "probe/snapprobe/static/js/snap-grafici.js").read_text(encoding="utf-8")
    assert server.replace("snap server", "snap probe") == sonda


def test_gli_stili_dei_grafici_esistono_nei_due_applicativi():
    """Il modulo disegna con classi CSS invece che con colori scritti dentro: senza
    quelle classi il tracciato resta senza colore ne' spessore."""
    classi = ("snap-grafico-linea", "snap-grafico-punto", "snap-grafico-ultimo",
              "snap-grafico-media", "snap-grafico-guida", "snap-grafico-nota",
              "snap-grafico-vuoto")
    for foglio in ("server/snapserver/static/css/snap.css",
                   "probe/snapprobe/static/css/probe.css"):
        testo = (RADICE / foglio).read_text(encoding="utf-8")
        mancanti = [c for c in classi if ("." + c) not in testo]
        assert not mancanti, "%s non definisce %s" % (foglio, mancanti)


def test_nessun_residuo_della_libreria_precedente():
    """La sostituzione di Tabulator deve essere completa."""
    for cartella in ("server/snapserver", "probe/snapprobe"):
        for percorso in (RADICE / cartella).rglob("*"):
            if percorso.is_dir() or percorso.suffix not in {".html", ".css", ".js", ".py"}:
                continue
            if "vendor" in percorso.parts:
                continue
            testo = percorso.read_text(encoding="utf-8", errors="ignore")
            assert "tabulator" not in testo.lower(), "residuo in %s" % percorso.name


def test_le_tabelle_amministrative_sono_piatte():
    """Le righe di dettaglio collassate impedirebbero il funzionamento delle tabelle."""
    for nome in ("admin/tenants.html", "admin/users.html"):
        testo = (RADICE / "server/snapserver/templates" / nome).read_text(encoding="utf-8")
        assert 'class="collapse"' not in testo, (
            "%s contiene ancora righe collassate dentro la tabella" % nome
        )
        assert "modal fade" in testo, "%s deve usare finestre di dialogo" % nome


def test_la_dimensione_della_pagina_e_dichiarata(admin_client):
    """Ogni tabella dichiara quante righe mostrare per pagina."""
    corpo = admin_client.get("/probes/").data.decode("utf-8")
    marcatura = re.search(r"<table[^>]*data-snap-table[^>]*>", corpo).group(0)
    assert "data-page-size" in marcatura


# --------------------------------------------------------------------------- #
# Dialogo con l'utente
# --------------------------------------------------------------------------- #
def test_le_risorse_sono_servite_localmente(admin_client):
    """Nessuna dipendenza da servizi esterni: le librerie sono nel prodotto."""
    for risorsa in RISORSE_LOCALI:
        risposta = admin_client.get(risorsa)
        assert risposta.status_code == 200, "risorsa non servita: %s" % risorsa
        assert len(risposta.data) > 500, "risorsa incompleta: %s" % risorsa


def test_nessun_riferimento_a_reti_esterne_nei_modelli():
    for cartella in ("server/snapserver/templates", "probe/snapprobe/templates"):
        for modello in (RADICE / cartella).rglob("*.html"):
            testo = modello.read_text(encoding="utf-8")
            for indizio in ("cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com"):
                assert indizio not in testo, "%s richiama %s" % (modello.name, indizio)


def test_i_messaggi_del_server_sono_esposti_alle_notifiche(server_app):
    """I messaggi di esito devono portare gli attributi usati dalle notifiche."""
    client = server_app.test_client()
    risposta = client.post(
        "/login",
        data={"email": "admin@ised.local", "password": "sbagliata"},
        follow_redirects=True,
    )
    corpo = risposta.data.decode("utf-8")
    assert "data-snap-flash" in corpo
    assert 'data-flash-category="danger"' in corpo
    assert "data-flash-message=" in corpo


def test_le_conferme_native_del_browser_non_sono_piu_usate():
    """Le richieste di conferma devono passare da AWN, non da window.confirm."""
    for percorso in (
        "server/snapserver/static/js/snap.js",
        "probe/snapprobe/static/js/probe.js",
        "server/snapserver/static/js/snap-tables.js",
    ):
        testo = (RADICE / percorso).read_text(encoding="utf-8")
        assert "window.confirm" not in testo, "%s usa ancora la conferma nativa" % percorso

    # Nel modulo dei dialoghi la conferma nativa resta solo come ricaduta.
    dialoghi = (RADICE / "server/snapserver/static/js/snap-dialogs.js").read_text(encoding="utf-8")
    assert dialoghi.count("global.confirm") == 1
    assert "notifier.confirm" in dialoghi


def test_le_azioni_distruttive_richiedono_conferma(admin_client, server_app):
    """Ogni modulo che elimina dati deve dichiarare la richiesta di conferma."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        tenant = query("SELECT id FROM tenants WHERE code = 'ised'", (), one=True)
        now = utc_now_str()
        execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, created_at,"
            " updated_at) VALUES (?, 'uid-ui', 'sonda-ui', 'Sonda UI', 'active', ?, ?)",
            (int(tenant["id"]), now, now),
        )
        probe_id = int(query("SELECT id FROM probes WHERE code = 'sonda-ui'", (), one=True)["id"])
        tenant_id = int(tenant["id"])

    # La sonda appartiene al tenant ISED: il contesto va portato su quello.
    admin_client.post("/switch-tenant", data={"tenant_id": tenant_id}, follow_redirects=True)
    corpo = admin_client.get("/probes/%d" % probe_id).data.decode("utf-8")
    moduli_eliminazione = re.findall(r"<form[^>]*probes/%d/(?:delete|revoke)[^>]*>" % probe_id, corpo)
    assert moduli_eliminazione, "moduli di eliminazione non trovati"
    for modulo in moduli_eliminazione:
        assert "data-confirm" in modulo, "azione distruttiva senza conferma: %s" % modulo[:80]


def test_le_pagine_autonome_dispongono_delle_notifiche(server_app):
    """Accesso e secondo fattore mostrano messaggi: servono anche a loro."""
    client = server_app.test_client()
    corpo = client.get("/login").data.decode("utf-8")
    assert "awn/index.var.js" in corpo
    assert "snap-dialogs.js" in corpo

# --------------------------------------------------------------------------- #
# Coerenza della navigazione
# --------------------------------------------------------------------------- #
def test_nessun_collegamento_verso_pagine_inesistenti(server_app):
    """Ogni url_for nei modelli deve puntare a una rotta registrata."""
    import re as _re

    rotte = {regola.endpoint for regola in server_app.url_map.iter_rules()}
    mancanti = []
    for modello in (RADICE / "server/snapserver/templates").rglob("*.html"):
        testo = modello.read_text(encoding="utf-8")
        for riferimento in _re.findall(r"url_for\(\s*'([^']+)'", testo):
            if riferimento not in rotte:
                mancanti.append("%s -> %s" % (modello.name, riferimento))
    assert not mancanti, "collegamenti verso rotte inesistenti: %s" % mancanti


def test_le_sezioni_rimosse_non_sono_piu_raggiungibili(admin_client):
    """Le pagine eliminate devono rispondere 404, non essere ancora servite."""
    for percorso in (
        "/assets/",
        "/assets/services",
        "/assets/subnets",
        "/vulnerabilities/",
        "/vulnerabilities/remediation",
        "/audit/scans",
        "/audit/ingest",
        # "/reports/" e' tornata a esistere: e' il menu dei report e del resoconto
        # quotidiano (docs/08_REPORT.md), non la vecchia sezione eliminata.
    ):
        risposta = admin_client.get(percorso)
        assert risposta.status_code == 404, (
            "%s risponde ancora con %s" % (percorso, risposta.status_code)
        )


# --------------------------------------------------------------------------- #
# Audit & Eventi: filtro per attore
# --------------------------------------------------------------------------- #
def test_l_audit_filtra_per_attore(admin_client, server_app):
    """Il filtro Attore mostra solo gli eventi dell'attore scelto e propone
    l'elenco degli attori presenti nel registro."""
    with server_app.app_context():
        from snapserver.audit import log_event
        from snapserver.db import query

        tenant = query("SELECT id FROM tenants WHERE code = 'ised'", (), one=True)
        tenant_id = int(tenant["id"])
        log_event(
            "test.audit",
            "azione di alice",
            tenant_id=tenant_id,
            actor="alice@example.test",
        )
        log_event(
            "test.audit",
            "azione di bruno",
            tenant_id=tenant_id,
            actor="bruno@example.test",
        )

    admin_client.post("/switch-tenant", data={"tenant_id": tenant_id}, follow_redirects=True)

    # Senza filtro: la tendina degli attori li propone entrambi.
    corpo = admin_client.get("/audit/").data.decode("utf-8")
    assert 'name="actor"' in corpo, "manca la tendina del filtro Attore"
    assert "alice@example.test" in corpo
    assert "bruno@example.test" in corpo

    # Con il filtro: resta solo l'attore scelto.
    filtrato = admin_client.get("/audit/?actor=alice@example.test").data.decode("utf-8")
    assert "azione di alice" in filtrato
    assert "azione di bruno" not in filtrato


def _menu(client) -> str:
    corpo = client.get("/").data.decode("utf-8")
    return corpo[corpo.index("app-sidebar"):corpo.index("</aside>")]


def _barra(client) -> str:
    """La barra superiore: da app-header alla fine della sua <nav>."""
    corpo = client.get("/").data.decode("utf-8")
    inizio = corpo.index("app-header")
    return corpo[inizio:corpo.index("</nav>", inizio)]


def test_la_barra_ospita_la_ricerca_nella_base_dati(admin_client):
    """Accanto al tenant c'e' il campo di ricerca, che porta alla stessa
    interrogazione della pagina dedicata (operations.search, su /ops/search)."""
    barra = _barra(admin_client)

    assert 'class="snap-ricerca"' in barra
    assert 'action="/ops/search"' in barra
    assert 'name="q"' in barra
    assert 'method="get"' in barra


def test_gli_indicatori_lasciano_la_barra_per_il_menu_di_stato(admin_client):
    """Gli indicatori non stanno piu' distesi sulla barra (dove ora c'e' la
    ricerca) ma raccolti nel menu di stato del sistema."""
    barra = _barra(admin_client)

    assert "snap-indicator" not in barra, "i vecchi riquadri non sono piu' sulla barra"
    assert "snap-stato-menu" in barra, "lo stato del sistema ha il suo menu"
    assert "Sonde attive" in barra


def test_il_menu_contiene_solo_le_voci_previste(admin_client):
    """Il menu laterale elenca dashboard, rete, controlli, sicurezza, report, sonde e
    amministrazione."""
    menu = _menu(admin_client)

    for atteso in ("Dashboard", "Sonde", "Flotta sonde", "Registra sonda",
                   "Audit &amp; Eventi", "Tenant", "Utenti", "Impostazioni Sistema",
                   # Inventario di rete e dati conferiti dalle sonde.
                   "Nodi", "Stato della rete", "Cambiamenti", "Dati dalle sonde",
                   "Perimetro",
                   # Gruppi introdotti con il menu collassabile.
                   "Rete", "Controlli", "Sicurezza", "Report e resoconti"):
        assert atteso in menu, "voce mancante nel menu: %s" % atteso

    # Il vecchio dominio degli asset e della reportistica resta fuori dal prodotto.
    # "Vulnerabilita'" non e' piu' fra le voci proibite: la Threat Intelligence
    # (docs/10) e' una parte prevista del prodotto, e la sua voce si chiama cosi'.
    for rimosso in ("Inventario Asset", "Tutti gli asset", "Remediation",
                    "Reportistica"):
        assert rimosso not in menu, "voce ancora presente nel menu: %s" % rimosso


def test_il_menu_e_organizzato_in_gruppi_collassabili(admin_client):
    """Quattordici voci in un elenco piatto costringevano a scorrere: i gruppi
    riducono il menu a otto righe quando sono chiusi."""
    menu = _menu(admin_client)

    for gruppo in ("rete", "controlli", "sicurezza", "sonde", "admin"):
        assert 'data-snap-gruppo="%s"' % gruppo in menu, "gruppo mancante: %s" % gruppo
    # Il meccanismo e' quello di AdminLTE: sottomenu in nav-treeview.
    assert menu.count("nav-treeview") >= 5


def test_il_gruppo_della_pagina_in_corso_e_aperto(admin_client):
    """Un menu che non dice dove si e' costringe a cercare: il gruppo che contiene la
    pagina si apre da solo, qualunque cosa l'utente abbia chiuso in precedenza."""
    corpo = admin_client.get("/inventory/nodes").data.decode("utf-8")
    menu = corpo[corpo.index("app-sidebar"):corpo.index("</aside>")]
    apertura = menu.index('data-snap-gruppo="rete"')
    riga = menu[max(0, apertura - 200):apertura]
    assert "menu-open" in riga, "il gruppo della pagina in corso deve essere aperto"

    # Gli altri restano chiusi: e' il senso di un menu compatto.
    chiusura = menu.index('data-snap-gruppo="sonde"')
    assert "menu-open" not in menu[max(0, chiusura - 200):chiusura]


# --------------------------------------------------------------------------- #
# Convenzione tipografica
# --------------------------------------------------------------------------- #
FONT_ATTESI = [
    "pt-sans-regular.woff2",
    "pt-sans-italic.woff2",
    "pt-sans-bold.woff2",
    "pt-sans-bold-italic.woff2",
    "pt-sans-narrow-regular.woff2",
    "pt-sans-narrow-bold.woff2",
]


@pytest.mark.parametrize("carattere", FONT_ATTESI)
def test_i_caratteri_sono_serviti_localmente(admin_client, carattere):
    """PT Sans e PT Sans Narrow sono nel prodotto, non richiesti a servizi esterni."""
    risposta = admin_client.get("/static/vendor/fonts/" + carattere)
    assert risposta.status_code == 200, "carattere non servito: %s" % carattere
    assert len(risposta.data) > 10000, "file del carattere incompleto: %s" % carattere


def test_il_foglio_dei_caratteri_dichiara_le_quattro_varianti():
    foglio = (RADICE / "server/snapserver/static/css/snap-fonts.css").read_text(encoding="utf-8")
    for atteso in (
        'font-family: "PT Sans Narrow"',
        'font-family: "PT Sans"',
        "font-style: italic",
        "font-weight: 700",
    ):
        assert atteso in foglio, "dichiarazione mancante: %s" % atteso
    # I titoli adottano la famiglia stretta, il corsivo ricade su PT Sans.
    assert "--snap-font-titoli" in foglio
    assert "--snap-font-corsivo" in foglio


def test_i_titoli_usano_la_famiglia_stretta():
    foglio = (RADICE / "server/snapserver/static/css/snap-fonts.css").read_text(encoding="utf-8")
    blocco = foglio[foglio.index("/* --- Titoli"):]
    for selettore in ("h1", ".card-title", ".modal-title", ".snap-stat-value",
                      ".snap-kpi-value", "table.dataTable thead th"):
        assert selettore in blocco, "selettore non incluso fra i titoli: %s" % selettore
    assert "var(--snap-font-titoli)" in blocco


def test_i_manuali_adottano_diciannove_punti():
    """La convenzione dei manuali software: PT Sans Narrow a 19 punti."""
    foglio = (RADICE / "server/snapserver/static/css/snap-fonts.css").read_text(encoding="utf-8")
    assert ".snap-documento" in foglio
    assert "font-size: 19pt" in foglio

    generatore = (RADICE / "tools/genera_manuale.py").read_text(encoding="utf-8")
    assert 'CARATTERE = "PT Sans Narrow"' in generatore
    assert "CORPO_PT = 19" in generatore


def test_il_foglio_dei_caratteri_e_collegato_in_ogni_layout():
    modelli = [
        "server/snapserver/templates/base.html",
        "server/snapserver/templates/auth/login.html",
        "server/snapserver/templates/auth/mfa.html",
        "server/snapserver/templates/errors/error.html",
        "probe/snapprobe/templates/base.html",
    ]
    for rel in modelli:
        testo = (RADICE / rel).read_text(encoding="utf-8")
        assert "css/snap-fonts.css" in testo, "foglio dei caratteri assente in %s" % rel


def test_nessun_carattere_richiesto_a_servizi_esterni():
    for cartella in ("server/snapserver", "probe/snapprobe"):
        for modello in (RADICE / cartella / "templates").rglob("*.html"):
            testo = modello.read_text(encoding="utf-8")
            for indizio in ("fonts.googleapis.com", "fonts.gstatic.com"):
                assert indizio not in testo, "%s richiama %s" % (modello.name, indizio)


# --------------------------------------------------------------------------- #
# Dimensioni: l'unita' segue il valore
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("byte,atteso", [
    (0, "0 B"),
    (512, "512 B"),
    (1023, "1023 B"),
    (1024, "1 kB"),
    (1536, "1,5 kB"),
    (102400, "100 kB"),
    (1048576, "1 MB"),
    (1319413, "1,26 MB"),
    (1073741824, "1 GB"),
])
def test_le_dimensioni_si_scrivono_nell_unita_che_le_rende_leggibili(byte, atteso):
    """"1289,4 kB" costringe a una divisione a mente; "1,26 MB" no. Difetto misurato:
    con l'unita' fissa in kB, 43 MB di conferimenti apparivano come "44165.5 kB"."""
    from snapserver.tenancy import fmt_bytes

    assert fmt_bytes(byte) == atteso


def test_un_intero_non_perde_gli_zeri_finali():
    """Togliendo gli zeri superflui senza guardare la virgola, "100 kB" diventava
    "1 kB": lo zero di un intero e' una cifra, non un decimale di troppo."""
    from snapserver.tenancy import fmt_bytes

    assert fmt_bytes(102400) == "100 kB"
    assert fmt_bytes(104857600) == "100 MB"


def test_una_dimensione_non_misurabile_si_dichiara():
    from snapserver.tenancy import fmt_bytes

    for valore in (None, "", "abc", -5):
        assert fmt_bytes(valore) == "-"


def test_l_indicatore_dei_dati_ricevuti_usa_l_unita_giusta(admin_client, server_app):
    """L'indicatore della dashboard e le tabelle dei conferimenti dicono la stessa
    cosa nello stesso modo."""
    with server_app.app_context():
        from flask import g

        from snapserver.db import execute, query, utc_now_str
        from snapserver.queries import dashboard_indicators

        tenant = query("SELECT * FROM tenants ORDER BY id", (), one=True)
        sonda = execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, created_at,"
            " updated_at) VALUES (?, 'uid-peso', 'PB', 'sonda', 'active', ?, ?)",
            (tenant["id"], utc_now_str(), utc_now_str()))
        execute(
            "INSERT INTO ingest_batches (tenant_id, probe_id, batch_uid, record_count,"
            " payload_bytes, status, received_at) VALUES (?, ?, 'b-peso', 10, ?, 'accepted', ?)",
            (tenant["id"], sonda, 5 * 1024 * 1024, utc_now_str()))

        g.tenant = tenant
        g.user = query("SELECT * FROM users ORDER BY id", (), one=True)
        indicatori = {v["key"]: v for v in dashboard_indicators(int(tenant["id"]))}

    assert indicatori["volume"]["value"] == "5 MB"


# --------------------------------------------------------------------------- #
# Collegamenti di salto
# --------------------------------------------------------------------------- #
def test_il_salto_alla_navigazione_viene_tolto():
    """AdminLTE inserisce due collegamenti di salto. Quello al contenuto resta --
    e' cio' che la WCAG 2.4.1 chiede -- mentre quello alla navigazione porta al menu,
    che da tastiera e' gia' il primo elemento raggiungibile."""
    sorgente = (Path(__file__).resolve().parent.parent
                / "server/snapserver/static/js/snap.js").read_text(encoding="utf-8")

    assert 'a[href="#navigation"]' in sorgente, (
        "il collegamento alla navigazione va rimosso all'avvio")
    assert 'href="#main"' not in sorgente, (
        "il salto al contenuto principale non si tocca: e' un requisito di"
        " accessibilita'")


def _sorgente(relativo: str) -> str:
    """Il testo di un modello, per le prove strutturali sulle tabelle."""
    from pathlib import Path as _Path

    return (_Path(__file__).resolve().parent.parent
            / "server/snapserver/templates" / relativo).read_text(encoding="utf-8")


def _primo_tenant(server_app) -> int:
    with server_app.app_context():
        from snapserver.db import query

        return int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])


def _nodo_con_nome(server_app, tenant_id: int, ip: str, nome: str) -> int:
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        adesso = utc_now_str()
        sonda = query("SELECT id FROM probes WHERE tenant_id = ?", (tenant_id,), one=True)
        probe_id = int(sonda["id"]) if sonda else execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, created_at,"
            " updated_at) VALUES (?, 'uid-nomi', 'sonda-nomi', 'Sonda', 'active', ?, ?)",
            (tenant_id, adesso, adesso))
        return execute(
            "INSERT INTO nodes (tenant_id, probe_id, ip, hostname, status, device_label,"
            " device_confidence, first_seen_at, last_seen_at, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, 'up', 'stampante', 90, ?, ?, ?, ?)",
            (tenant_id, probe_id, ip, nome, adesso, adesso, adesso, adesso))


# --------------------------------------------------------------------------- #
# La colonna dell'indirizzo porta anche il nome host
# --------------------------------------------------------------------------- #


def test_il_nome_host_compare_sopra_l_indirizzo(logged_client, server_app):
    tenant_id = _primo_tenant(server_app)
    _nodo_con_nome(server_app, tenant_id, "10.4.4.4", "stampante-piano1")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/nodes").get_data(as_text=True)
    cella = pagina[pagina.index("stampante-piano1"):]

    assert "stampante-piano1" in pagina
    assert cella.index("10.4.4.4") < 400, (
        "il nome host e l'indirizzo stanno nella stessa cella, il nome sopra")


def test_lo_stato_della_rete_mostra_il_nome_host(logged_client, server_app):
    tenant_id = _primo_tenant(server_app)
    _nodo_con_nome(server_app, tenant_id, "10.4.4.5", "stampante-piano2")
    logged_client.post("/switch-tenant", data={"tenant_id": tenant_id},
                       follow_redirects=True)

    risposta = logged_client.get("/monitor/")
    pagina = risposta.get_data(as_text=True)

    assert risposta.status_code == 200
    assert "stampante-piano2" in pagina
    cella = pagina[pagina.index("stampante-piano2"):]
    assert cella.index("10.4.4.5") < 400, (
        "il nome host e l'indirizzo stanno nella stessa cella, il nome sopra")


# --------------------------------------------------------------------------- #
# Tutte le tabelle di nodi si leggono allo stesso modo
# --------------------------------------------------------------------------- #
# Sono la stessa tabella vista da posti diversi: inventario, stato della rete, NOC,
# SOC, ricerca, minacce. Averla in sei forme diverse costringe a reimparare la stessa
# pagina a ogni cambio di sezione. Le colonne attese stanno qui perche' una tabella a
# cui si aggiunge una colonna senza aggiungere la cella si rompe in silenzio: la
# libreria chiede la colonna e non la trova.
TABELLE_DI_NODI = [
    ("inventory/nodes.html", "{% for n in nodes %}", 10),
    ("monitor/status.html", "{% for n in nodes %}", 8),
    ("operations/noc.html", "{% for n in board.silenzi %}", 7),
    ("operations/noc.html", "{% for n in board.non_interrogati %}", 5),
    ("operations/soc.html", "{% for n in board.fuori_perimetro %}", 3),
    ("operations/search.html", "{% for r in genere.righe %}", 6),
    ("threat/index.html", "{% for n in nodes %}", 9),
]


@pytest.mark.parametrize("modello,ciclo,colonne", TABELLE_DI_NODI)
def test_ogni_tabella_di_nodi_porta_il_nome_host_nell_indirizzo(modello, ciclo, colonne):
    import re

    sorgente = _sorgente(modello)
    avvio = sorgente.index(ciclo)
    apertura = sorgente.rindex("<thead>", 0, avvio)
    testata = sorgente[apertura:sorgente.index("</thead>", apertura)]
    riga = sorgente[avvio:sorgente.index("</tr>", avvio)]

    assert "NOME HOST" not in testata, (
        "%s: il nome host ha ancora una colonna propria" % modello)
    assert "hostname" in riga, (
        "%s: il nome host deve stare nella cella dell'indirizzo" % modello)
    assert len(re.findall(r"<th\b", testata)) == colonne
    assert len(re.findall(r"<td\b", riga)) == colonne, (
        "%s: celle e intestazioni non corrispondono" % modello)


@pytest.mark.parametrize("modello,ciclo,colonne", TABELLE_DI_NODI)
def test_la_riga_vuota_copre_tutte_le_colonne(modello, ciclo, colonne):
    """Una riga con `colspan` sbagliato e' il difetto che ha dato "Requested unknown
    parameter" nelle zone di rete: la libreria delle tabelle non lo perdona."""
    import re

    sorgente = _sorgente(modello)
    avvio = sorgente.index(ciclo)
    coda = sorgente[avvio:]
    trovato = re.search(r'colspan="(\d+)"', coda[:coda.index("</tbody>")])
    if trovato is None:
        pytest.skip("questa tabella non ha una riga per l'elenco vuoto")
    assert int(trovato.group(1)) == colonne


# --------------------------------------------------------------------------- #
# Lotti ricevuti: campi che vanno a capo e contenuto leggibile
# --------------------------------------------------------------------------- #
def test_il_contenuto_del_lotto_si_legge(server_app):
    """Il JSON dei conteggi e' cio' che la sonda scrive per la console: mostrarlo
    cosi' com'e' lascia a chi guarda il lavoro di interpretarlo."""
    with server_app.app_context():
        from snapserver.blueprints.inventory import _contenuto_lotto

        voci = _contenuto_lotto('{"check_results":2,"nodes":0,"web":4,"events":1}')

    assert ("controlli", 2) in voci
    assert ("pagine web", 4) in voci
    assert ("eventi", 1) in voci
    assert not [v for v in voci if v[0] == "nodi"], (
        "le voci a zero si tacciono: dieci generi vuoti nasconderebbero l'unico pieno")


def test_un_dettaglio_che_non_e_json_si_mostra_come_messaggio(server_app):
    with server_app.app_context():
        from snapserver.blueprints.inventory import _contenuto_lotto

        assert _contenuto_lotto("rifiutato: firma non valida") == [
            ("rifiutato: firma non valida", None)]
        assert _contenuto_lotto(None) == []


def test_le_colonne_lunghe_dei_lotti_vanno_a_capo():
    """Un identificativo esadecimale non ha spazi: senza il capo dentro la parola
    allarga la tabella e spinge le altre colonne fuori schermo."""
    sorgente = _sorgente("inventory/deliveries.html")
    stile = (Path(__file__).resolve().parent.parent
             / "server/snapserver/static/css/snap.css").read_text(encoding="utf-8")

    assert "snap-wrap" in sorgente
    assert "b.batch_uid[:16]" not in sorgente, "l'identificativo si mostra intero"
    assert "overflow-wrap: anywhere" in stile


def test_un_solo_gruppo_di_menu_resta_aperto():
    """Con sei gruppi aperti insieme il menu diventa piu' alto dello schermo e la voce
    che serve finisce sotto il bordo: per trovarla si scorre, che e' esattamente cio'
    che un menu dovrebbe evitare."""
    sorgente = (Path(__file__).resolve().parent.parent
                / "server/snapserver/static/js/snap.js").read_text(encoding="utf-8")

    assert "function soloQuesto(" in sorgente
    assert 'altro.classList.remove("menu-open")' in sorgente, (
        "aprendo un gruppo, gli altri si chiudono")
    # La chiusura automatica non e' una scelta dell'utente e non va ricordata,
    # altrimenti al ritorno sulla pagina i gruppi risulterebbero chiusi "per volonta'".
    posizione = sorgente.index("function soloQuesto(")
    coda = sorgente[posizione:posizione + 1400]
    assert "soloQuesto(gruppo);" in coda
    assert coda.index("soloQuesto(gruppo);") < coda.index("aggiornato.push(nome);"), (
        "l'accordion agisce quando il gruppo si APRE; il ricordo riguarda le chiusure"
        " volute")


def test_il_gruppo_della_pagina_in_corso_resta_aperto():
    """Regola che vince su tutto: il menu deve dire dove si e'."""
    sorgente = (Path(__file__).resolve().parent.parent
                / "server/snapserver/static/js/snap.js").read_text(encoding="utf-8")

    assert '.nav-treeview .nav-link.active' in sorgente
    posizione = sorgente.index("contieneLaPagina")
    assert 'gruppo.classList.add("menu-open")' in sorgente[posizione:posizione + 400]
