"""
snap - Test del riconoscimento per somiglianza fra interfacce web.

PERCHE' ESISTE
Su questa rete la maggior parte degli apparati incorporati non dichiara nulla nelle
proprie pagine: un 401 nudo, una pagina di accesso senza titolo, nessuna intestazione
`Server`. Il testo non identifica niente, ma la FORMA della risposta si': l'icona che
l'apparato serve e' un file che il costruttore ha messo nel firmware -- identica su
tutti gli esemplari di quel modello -- e l'insieme dei nomi delle intestazioni HTTP e'
l'impronta del programma che risponde.

Da qui il riconoscimento per somiglianza: un nodo muto prende in prestito il verdetto
dei nodi che rispondono come lui. E' potente e per questo pericoloso: un errore si
moltiplica su tutto il gruppo, che e' esattamente il modo in cui questo prodotto ha
gia' prodotto 98 telefoni VoIP inesistenti da una sola porta iniettata. Questi test
fissano i tre argini: il gruppo deve essere CONCORDE, il donatore deve avere prove
PROPRIE, e la somiglianza da sola non deve mai bastare a decidere.

remarks: Autore: Daniele Speziale - Data: 2026-09-10
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import uuid


ICONA = "b1946ac92492d234"
INTESTAZIONI = "9f86d081884c7d65"


# --------------------------------------------------------------------------- #
# Aiuti
# --------------------------------------------------------------------------- #
def _tenant_e_sonda(server_app):
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        tenant_id = int(query("SELECT id FROM tenants ORDER BY id", (), one=True)["id"])
        adesso = utc_now_str()
        sonda = query("SELECT id FROM probes WHERE tenant_id = ?", (tenant_id,), one=True)
        probe_id = int(sonda["id"]) if sonda else execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, created_at,"
            " updated_at) VALUES (?, 'uid-gem', 'sonda-gem', 'Sonda', 'active', ?, ?)",
            (tenant_id, adesso, adesso))
        return tenant_id, int(probe_id)


def _nodo(server_app, tenant_id, probe_id, ip, *, tipo=None, etichetta=None,
          confidenza=0, fonte="auto"):
    """Un nodo con il verdetto che gli si vuole dare: serve a costruire i donatori."""
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        adesso = utc_now_str()
        return int(execute(
            "INSERT INTO nodes (tenant_id, probe_id, ip, status, device_type,"
            " device_label, device_confidence, device_type_source, first_seen_at,"
            " last_seen_at, created_at, updated_at)"
            " VALUES (?, ?, ?, 'up', ?, ?, ?, ?, ?, ?, ?, ?)",
            (tenant_id, probe_id, ip, tipo or "unknown",
             etichetta or "Non identificato", confidenza, fonte,
             adesso, adesso, adesso, adesso)))


def _pagina(server_app, tenant_id, node_id, *, favicon=None, intestazioni=None,
            marca=None, modello=None, porta=443):
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        execute(
            "INSERT INTO node_web (tenant_id, node_id, port, scheme, status_code,"
            " brand, model, favicon_hash, headers_hash, collected_at)"
            " VALUES (?, ?, ?, 'https', 401, ?, ?, ?, ?, ?)",
            (tenant_id, node_id, porta, marca, modello, favicon, intestazioni,
             utc_now_str()))


def _prove(server_app, tenant_id, node_id):
    with server_app.app_context():
        from snapserver.ingest import build_evidence

        return build_evidence(tenant_id, node_id)


def _gruppo_stampanti(server_app, quanti=3, *, tipo="printer",
                      etichetta="Stampante", confidenza=88, fonte="auto",
                      favicon=ICONA, modello="TASKalfa 3253ci", marca="Kyocera"):
    """Un gruppo di apparati identificati che servono la stessa icona."""
    tenant_id, probe_id = _tenant_e_sonda(server_app)
    for indice in range(quanti):
        ip = "10.9.%d.%d" % (quanti, 10 + indice)
        node_id = _nodo(server_app, tenant_id, probe_id, ip, tipo=tipo,
                        etichetta=etichetta, confidenza=confidenza, fonte=fonte)
        _pagina(server_app, tenant_id, node_id, favicon=favicon, marca=marca,
                modello=modello)
    return tenant_id, probe_id


# --------------------------------------------------------------------------- #
# Che cosa viene composto come prova
# --------------------------------------------------------------------------- #
def test_la_stessa_icona_di_apparati_concordi_diventa_una_prova(server_app):
    """Il caso per cui il meccanismo esiste: un apparato che non dice niente di se',
    ma serve l'icona di tre stampanti riconosciute."""
    tenant_id, probe_id = _gruppo_stampanti(server_app, 3)
    muto = _nodo(server_app, tenant_id, probe_id, "10.9.3.99")
    _pagina(server_app, tenant_id, muto, favicon=ICONA)

    gemelli = _prove(server_app, tenant_id, muto)["web_twins"]

    assert len(gemelli) == 1
    gruppo = gemelli[0]
    assert gruppo["kind"] == "favicon"
    assert gruppo["device_type"] == "printer"
    assert gruppo["nodes"] == 3
    assert gruppo["agreement"] == 1.0
    assert gruppo["model"] == "TASKalfa 3253ci"


def test_un_gruppo_discorde_non_e_una_prova(server_app):
    """L'insieme delle intestazioni di nginx e' lo stesso su una telecamera e su un
    server: da un gruppo discorde non si conclude niente, e dichiararlo comunque
    sarebbe il modo di propagare un errore su tutto il gruppo."""
    tenant_id, probe_id = _tenant_e_sonda(server_app)
    for indice, tipo in enumerate(("ip_camera", "server_unix", "nas", "printer")):
        node_id = _nodo(server_app, tenant_id, probe_id, "10.9.7.%d" % (20 + indice),
                        tipo=tipo, etichetta=tipo, confidenza=90)
        _pagina(server_app, tenant_id, node_id, intestazioni=INTESTAZIONI)
    muto = _nodo(server_app, tenant_id, probe_id, "10.9.7.99")
    _pagina(server_app, tenant_id, muto, intestazioni=INTESTAZIONI)

    assert _prove(server_app, tenant_id, muto)["web_twins"] == []


def test_un_gruppo_quasi_unanime_resta_una_prova(server_app):
    """Un solo discorde su cinque non annulla il gruppo: sopra la soglia di accordo la
    prova resta, e si dichiara la percentuale invece di far finta che sia unanime."""
    tenant_id, probe_id = _tenant_e_sonda(server_app)
    tipi = ["printer"] * 4 + ["nas"]
    for indice, tipo in enumerate(tipi):
        node_id = _nodo(server_app, tenant_id, probe_id, "10.9.8.%d" % (20 + indice),
                        tipo=tipo, etichetta=tipo, confidenza=90)
        _pagina(server_app, tenant_id, node_id, favicon=ICONA)
    muto = _nodo(server_app, tenant_id, probe_id, "10.9.8.99")
    _pagina(server_app, tenant_id, muto, favicon=ICONA)

    gruppo = _prove(server_app, tenant_id, muto)["web_twins"][0]

    assert gruppo["device_type"] == "printer"
    assert gruppo["agreement"] == 0.8
    assert gruppo["nodes"] == 5


def test_un_gemello_senza_prove_proprie_non_fa_da_donatore(server_app):
    """Il contrario della circolarita': se il gemello e' a sua volta un'ipotesi debole,
    prestarla a un terzo nodo trasformerebbe un dubbio in un'attribuzione."""
    tenant_id, probe_id = _gruppo_stampanti(server_app, 2, confidenza=30)
    muto = _nodo(server_app, tenant_id, probe_id, "10.9.2.99")
    _pagina(server_app, tenant_id, muto, favicon=ICONA)

    assert _prove(server_app, tenant_id, muto)["web_twins"] == []


def test_un_tipo_dichiarato_da_una_persona_fa_da_donatore_senza_confidenza(server_app):
    """Una dichiarazione dell'operatore e' la prova piu' attendibile che il prodotto
    abbia: non le si chiede anche una confidenza calcolata."""
    tenant_id, probe_id = _gruppo_stampanti(server_app, 2, confidenza=0, fonte="manual")
    muto = _nodo(server_app, tenant_id, probe_id, "10.9.2.98")
    _pagina(server_app, tenant_id, muto, favicon=ICONA)

    gruppo = _prove(server_app, tenant_id, muto)["web_twins"][0]

    assert gruppo["device_type"] == "printer"
    assert gruppo["declared"] == 2


def test_modelli_diversi_nello_stesso_gruppo_non_si_riportano(server_app):
    """Due modelli sotto la stessa impronta vogliono dire che l'impronta e' del
    programma, non dell'apparato: un modello sbagliato in una scheda e' peggio di un
    modello assente."""
    tenant_id, probe_id = _tenant_e_sonda(server_app)
    for indice, modello in enumerate(("TASKalfa 3253ci", "ECOSYS M3145")):
        node_id = _nodo(server_app, tenant_id, probe_id, "10.9.6.%d" % (20 + indice),
                        tipo="printer", etichetta="Stampante", confidenza=90)
        _pagina(server_app, tenant_id, node_id, favicon=ICONA, marca="Kyocera",
                modello=modello)
    muto = _nodo(server_app, tenant_id, probe_id, "10.9.6.99")
    _pagina(server_app, tenant_id, muto, favicon=ICONA)

    gruppo = _prove(server_app, tenant_id, muto)["web_twins"][0]

    assert gruppo["model"] is None
    assert gruppo["brand"] == "Kyocera", "la marca resta: su quella sono unanimi"


def test_un_nodo_senza_impronte_non_ha_gemelli(server_app):
    tenant_id, probe_id = _gruppo_stampanti(server_app, 3)
    solo = _nodo(server_app, tenant_id, probe_id, "10.9.3.98")
    _pagina(server_app, tenant_id, solo)

    assert _prove(server_app, tenant_id, solo)["web_twins"] == []


def test_il_nodo_non_e_gemello_di_se_stesso(server_app):
    """Un apparato con due porte web serve la stessa icona su entrambe: se contasse
    come proprio gemello, ogni nodo si confermerebbe da solo."""
    tenant_id, probe_id = _tenant_e_sonda(server_app)
    solo = _nodo(server_app, tenant_id, probe_id, "10.9.5.99", tipo="printer",
                 etichetta="Stampante", confidenza=90)
    _pagina(server_app, tenant_id, solo, favicon=ICONA, porta=443)
    _pagina(server_app, tenant_id, solo, favicon=ICONA, porta=80)

    assert _prove(server_app, tenant_id, solo)["web_twins"] == []


# --------------------------------------------------------------------------- #
# Quanto pesa nel riconoscimento
# --------------------------------------------------------------------------- #
def test_la_somiglianza_entra_nel_verdetto_come_genere_proprio():
    """Deve essere un genere distinto: e' cio' che la rende una seconda famiglia di
    prove capace di far superare a un apparato muto la soglia dell'ipotesi."""
    from snapserver import fingerprint

    verdetto = fingerprint.identify({
        "ip": "10.9.0.1",
        "ports": [],
        "web_twins": [{"kind": "favicon", "hash": ICONA, "device_type": "printer",
                       "device_label": "Stampante", "nodes": 4, "agreement": 1.0,
                       "declared": 0, "model": "TASKalfa 3253ci"}],
    })

    assert verdetto["device_type"] == "printer"
    prove = [p["prova"] for p in verdetto["evidence"]]
    assert any("icona" in p for p in prove)
    assert any(p["genere"] == "somiglianza" for p in verdetto["evidence"])


def test_l_icona_pesa_piu_delle_intestazioni():
    """L'icona e' un file scelto dal costruttore, le intestazioni identificano il
    programma: la prima dice il prodotto, la seconda solo la famiglia."""
    from snapserver.fingerprint import prove_dai_gemelli

    comune = {"device_type": "printer", "device_label": "Stampante", "nodes": 4,
              "agreement": 1.0, "declared": 0}
    icona = prove_dai_gemelli([dict(comune, kind="favicon", hash=ICONA)])
    intestazioni = prove_dai_gemelli([dict(comune, kind="headers", hash=INTESTAZIONI)])

    assert icona[0][1] > intestazioni[0][1]


def test_la_somiglianza_da_sola_non_puo_produrre_un_donatore():
    """L'ARGINE CONTRO LA CIRCOLARITA', verificato sui numeri e non sulle intenzioni.

    Se un nodo riconosciuto per sola somiglianza raggiungesse la confidenza richiesta
    a un donatore, il primo errore si propagherebbe di nodo in nodo senza che nessuna
    osservazione lo fermi. Il tetto sul peso e la regola del genere unico devono
    tenerlo sotto quella soglia, sempre.
    """
    from snapserver import fingerprint
    from snapserver.ingest import CONFIDENZA_MINIMA_DONATORE

    verdetto = fingerprint.identify({
        "ip": "10.9.0.2",
        "ports": [],
        "web_twins": [{"kind": "favicon", "hash": ICONA, "device_type": "printer",
                       "device_label": "Stampante", "nodes": 40, "agreement": 1.0,
                       "declared": 40, "model": "TASKalfa 3253ci"}],
    })

    assert verdetto["confidence"] < CONFIDENZA_MINIMA_DONATORE


def test_un_tipo_che_il_catalogo_non_conosce_non_e_una_prova():
    """Le classi cambiano fra le versioni: un tipo rimasto in banca dati e non piu' nel
    catalogo va ignorato, non tradotto in un punteggio su una classe inesistente."""
    from snapserver.fingerprint import prove_dai_gemelli

    assert prove_dai_gemelli([
        {"kind": "favicon", "hash": ICONA, "device_type": "macchina_del_caffe",
         "device_label": "?", "nodes": 5, "agreement": 1.0, "declared": 0}]) == []


def test_senza_gemelli_il_riconoscimento_non_cambia():
    from snapserver import fingerprint

    prove = {"ip": "10.9.0.3",
             "ports": [{"protocol": "tcp", "port": 9100, "state": "open",
                        "service_name": "jetdirect"}]}
    senza = fingerprint.identify(dict(prove))
    vuoto = fingerprint.identify(dict(prove, web_twins=[]))

    assert senza["device_type"] == vuoto["device_type"]
    assert senza["confidence"] == vuoto["confidence"]


# --------------------------------------------------------------------------- #
# Che cosa arriva dalla sonda e dove finisce
# --------------------------------------------------------------------------- #
def test_le_impronte_conferite_dalla_sonda_si_conservano(server_app):
    """Senza colonne proprie le impronte resterebbero dentro `details_json`, e un
    confronto fra nodi diversi non si potrebbe interrogare."""
    tenant_id, probe_id = _tenant_e_sonda(server_app)
    node_id = _nodo(server_app, tenant_id, probe_id, "10.9.1.10")

    with server_app.app_context():
        from snapserver.db import query
        from snapserver.ingest import apply_batch

        apply_batch(tenant_id, probe_id, {
            "batch_uid": "gemelli-%s" % uuid.uuid4().hex[:8],
            "records": {"web": [{"ip": "10.9.1.10", "pages": [{
                "port": 443, "scheme": "https", "stato": 401,
                "favicon_impronta": ICONA, "favicon_byte": 1150,
                "favicon_percorso": "/favicon.ico",
                "intestazioni_impronta": INTESTAZIONI,
                "intestazioni_nomi": "server,content-type,www-authenticate",
            }]}]}})
        riga = query("SELECT * FROM node_web WHERE node_id = ?", (node_id,), one=True)

    assert riga["favicon_hash"] == ICONA
    assert riga["favicon_bytes"] == 1150
    assert riga["favicon_path"] == "/favicon.ico"
    assert riga["headers_hash"] == INTESTAZIONI
    assert riga["headers_names"] == "server,content-type,www-authenticate"


def test_le_impronte_compaiono_fra_le_prove_del_nodo(server_app):
    tenant_id, probe_id = _tenant_e_sonda(server_app)
    node_id = _nodo(server_app, tenant_id, probe_id, "10.9.1.11")
    _pagina(server_app, tenant_id, node_id, favicon=ICONA, intestazioni=INTESTAZIONI)

    pagina = _prove(server_app, tenant_id, node_id)["web"][0]

    assert pagina["favicon_hash"] == ICONA
    assert pagina["headers_hash"] == INTESTAZIONI
