"""
snap - Test del perimetro di scansione dichiarato dal tenant.

Il perimetro e' la sede dell'autorizzazione: si accettano solo intervalli di
indirizzamento privato salvo deroga esplicita, si rifiutano perimetri troppo
ampi, e la sonda non deve poter scansionare nulla che non sia dichiarato qui.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import pytest

FILE_ESEMPIO = """# Perimetro della sede centrale
10.50.9.0/24 Sede centrale
10.20.10.0/24 Amministrazione

192.168.4.0/24   # laboratorio
"""


@pytest.fixture()
def contesto(server_app):
    """Contesto applicativo con un tenant noto."""
    with server_app.app_context():
        from snapserver.db import query

        tenant = query("SELECT id FROM tenants ORDER BY id", (), one=True)
        yield int(tenant["id"])


# --------------------------------------------------------------------------- #
# Lettura del file
# --------------------------------------------------------------------------- #
def test_il_file_viene_letto_con_etichette_e_commenti(server_app):
    with server_app.app_context():
        from snapserver.subnets import parse_subnet_file

        esito = parse_subnet_file(FILE_ESEMPIO)
    assert [s["cidr"] for s in esito["subnets"]] == [
        "10.50.9.0/24", "10.20.10.0/24", "192.168.4.0/24"]
    assert esito["subnets"][0]["label"] == "Sede centrale"
    assert esito["subnets"][2]["label"] == "laboratorio"
    assert esito["errors"] == []
    assert esito["subnets"][0]["host_count"] == 254


def test_gli_indirizzi_pubblici_sono_rifiutati_senza_deroga(server_app):
    with server_app.app_context():
        from snapserver.subnets import parse_subnet_file

        esito = parse_subnet_file("8.8.8.0/24\n10.0.0.0/24\n")
    assert [s["cidr"] for s in esito["subnets"]] == ["10.0.0.0/24"]
    assert len(esito["errors"]) == 1
    assert "privato" in esito["errors"][0]["reason"]


def test_la_deroga_consente_gli_indirizzi_pubblici(server_app):
    with server_app.app_context():
        from snapserver.subnets import parse_subnet_file

        esito = parse_subnet_file("203.0.113.0/24\n", allow_public=True)
    assert [s["cidr"] for s in esito["subnets"]] == ["203.0.113.0/24"]


def test_un_perimetro_troppo_ampio_viene_rifiutato(server_app):
    """Una /8 non si suddivide: sarebbero migliaia di passate per sedici milioni di
    indirizzi, e nessuno ha dichiarato di volerlo."""
    with server_app.app_context():
        from snapserver.subnets import MAX_HOSTS_PER_SUBNET, parse_subnet_file

        esito = parse_subnet_file("10.0.0.0/8\n")
    assert esito["subnets"] == []
    assert "troppo ampio" in esito["errors"][0]["reason"]
    assert str(MAX_HOSTS_PER_SUBNET) in esito["errors"][0]["reason"]


def test_una_rete_ampia_viene_suddivisa_invece_di_essere_rifiutata(server_app):
    """Chi dichiara una /16 sa quello che vuole: il limite riguarda l'ampiezza di una
    singola passata, non il perimetro. La rete viene suddivisa in blocchi e la
    suddivisione viene dichiarata."""
    with server_app.app_context():
        from snapserver.subnets import MAX_HOSTS_PER_SUBNET, parse_subnet_file

        esito = parse_subnet_file("10.1.0.0/16 sede Milano\n")

    assert esito["errors"] == [], "una /16 non e' un errore"
    assert len(esito["subnets"]) == 16, "sedici blocchi /20 coprono la /16"
    assert all(v["host_count"] <= MAX_HOSTS_PER_SUBNET for v in esito["subnets"])
    assert esito["subnets"][0]["cidr"] == "10.1.0.0/20"
    assert esito["subnets"][-1]["cidr"] == "10.1.240.0/20"
    # Gli indirizzi coperti sono quelli della rete dichiarata, meno i due per blocco.
    assert esito["total_hosts"] == 16 * 4094

    suddivisione = esito["split"][0]
    assert suddivisione["value"] == "10.1.0.0/16"
    assert suddivisione["blocchi"] == 16 and suddivisione["prefisso"] == 20
    # L'etichetta porta l'origine: sedici righe /20 devono restare riconoscibili.
    assert "sede Milano" in esito["subnets"][0]["label"]
    assert "10.1.0.0/16" in esito["subnets"][0]["label"]


def test_una_rete_dentro_il_limite_non_viene_toccata(server_app):
    with server_app.app_context():
        from snapserver.subnets import parse_subnet_file

        esito = parse_subnet_file("10.2.0.0/22 collaudo\n")
    assert [v["cidr"] for v in esito["subnets"]] == ["10.2.0.0/22"]
    assert esito["split"] == []
    assert esito["subnets"][0]["label"] == "collaudo", (
        "senza suddivisione l'etichetta resta quella scritta")


def test_la_suddivisione_non_si_sovrappone_a_una_subnet_gia_dichiarata(server_app):
    """Se un blocco copre una subnet gia' presente, il conflitto va dichiarato riga per
    riga invece di produrre due perimetri che si accavallano."""
    with server_app.app_context():
        from snapserver.subnets import parse_subnet_file

        esito = parse_subnet_file("10.3.32.0/24 collaudo\n10.3.0.0/16 sede\n")

    assert any("si sovrappone" in e["reason"] for e in esito["errors"])
    accettate = [v["cidr"] for v in esito["subnets"]]
    assert "10.3.32.0/24" in accettate
    assert "10.3.32.0/20" not in accettate, "il blocco in conflitto non entra"
    assert len(accettate) == 16, "gli altri quindici blocchi restano validi"


def test_le_ripetizioni_e_le_sovrapposizioni_sono_rifiutate(server_app):
    with server_app.app_context():
        from snapserver.subnets import parse_subnet_file

        esito = parse_subnet_file("10.1.0.0/24\n10.1.0.0/24\n10.1.0.0/25\n")
    assert [s["cidr"] for s in esito["subnets"]] == ["10.1.0.0/24"]
    motivi = " ".join(e["reason"] for e in esito["errors"])
    assert "ripetuta" in motivi
    assert "sovrappone" in motivi


def test_una_notazione_non_valida_non_interrompe_la_lettura(server_app):
    with server_app.app_context():
        from snapserver.subnets import parse_subnet_file

        esito = parse_subnet_file("non-una-rete\n10.2.0.0/24 Buona\n")
    assert [s["cidr"] for s in esito["subnets"]] == ["10.2.0.0/24"]
    assert esito["errors"][0]["line"] == 1


def test_un_indirizzo_singolo_diventa_una_rete_di_un_indirizzo(server_app):
    with server_app.app_context():
        from snapserver.subnets import parse_subnet_file

        esito = parse_subnet_file("10.3.0.7\n")
    assert esito["subnets"][0]["cidr"] == "10.3.0.7/32"
    assert esito["subnets"][0]["host_count"] == 1


# --------------------------------------------------------------------------- #
# Importazione
# --------------------------------------------------------------------------- #
def test_l_importazione_crea_le_subnet_e_le_registra_in_audit(server_app, contesto):
    with server_app.app_context():
        from snapserver.db import query
        from snapserver.subnets import import_subnets

        esito = import_subnets(contesto, FILE_ESEMPIO, "perimetro.txt")
        assert len(esito["added"]) == 3
        assert esito["total_hosts"] == 254 * 3

        righe = query("SELECT * FROM subnets WHERE tenant_id = ? ORDER BY cidr", (contesto,))
        assert len(righe) == 3
        assert all(int(r["is_enabled"]) == 1 for r in righe)

        eventi = query("SELECT * FROM audit_events WHERE tenant_id = ?"
                       " AND event_type = 'subnets.imported'", (contesto,))
        assert len(eventi) == 1


def test_la_reimportazione_aggiorna_senza_duplicare(server_app, contesto):
    with server_app.app_context():
        from snapserver.subnets import import_subnets

        import_subnets(contesto, FILE_ESEMPIO, "primo.txt")
        esito = import_subnets(contesto, "10.50.9.0/24 Sede rinominata\n", "secondo.txt")
    assert esito["added"] == []
    assert esito["updated"] == ["10.50.9.0/24"]


def test_la_sostituzione_disattiva_le_subnet_assenti_senza_cancellarle(server_app, contesto):
    with server_app.app_context():
        from snapserver.db import query
        from snapserver.subnets import import_subnets

        import_subnets(contesto, FILE_ESEMPIO, "primo.txt")
        esito = import_subnets(contesto, "10.50.9.0/24 Sede\n", "secondo.txt", replace=True)
        assert sorted(esito["disabled"]) == ["10.20.10.0/24", "192.168.4.0/24"]
        # Le righe restano: i nodi scoperti conservano il collegamento e la storia.
        assert len(query("SELECT * FROM subnets WHERE tenant_id = ?", (contesto,))) == 3


def test_un_file_senza_subnet_valide_viene_rifiutato(server_app, contesto):
    with server_app.app_context():
        from snapserver.subnets import SubnetError, import_subnets

        with pytest.raises(SubnetError):
            import_subnets(contesto, "8.8.8.8/32\nnon-valida\n", "cattivo.txt")


def test_il_perimetro_attivo_e_quello_consegnato_alla_sonda(server_app, contesto):
    with server_app.app_context():
        from snapserver.subnets import active_subnets, import_subnets

        import_subnets(contesto, FILE_ESEMPIO, "perimetro.txt")
        import_subnets(contesto, "10.50.9.0/24 Sede\n", "solo-sede.txt", replace=True)
        attive = active_subnets(contesto)
    assert [s["cidr"] for s in attive] == ["10.50.9.0/24"]
    assert attive[0]["hosts"] == 254


def test_l_appartenenza_al_perimetro_e_verificabile(server_app, contesto):
    with server_app.app_context():
        from snapserver.subnets import import_subnets, subnet_of_address, within_perimeter

        import_subnets(contesto, FILE_ESEMPIO, "perimetro.txt")
        dentro = subnet_of_address(contesto, "10.50.9.18")
        fuori = subnet_of_address(contesto, "8.8.8.8")
    assert dentro is not None
    assert fuori is None
    assert within_perimeter([{"cidr": "10.50.9.0/24"}], "10.50.9.18") is True
    assert within_perimeter([{"cidr": "10.50.9.0/24"}], "10.50.10.1") is False
    assert within_perimeter([], "10.50.9.18") is False


def test_le_due_verifiche_di_perimetro_concordano(server_app):
    """Server e sonda duplicano la verifica: le due implementazioni devono coincidere."""
    from snapprobe.scanner import within_perimeter as sonda

    with server_app.app_context():
        from snapserver.subnets import within_perimeter as server

        perimetro = [{"cidr": "10.50.9.0/24"}, {"cidr": "192.168.4.0/24"}]
        casi = ["10.50.9.1", "10.50.9.255", "10.50.10.1", "192.168.4.7",
                "8.8.8.8", "non-un-indirizzo", ""]
        for indirizzo in casi:
            assert server(perimetro, indirizzo) == sonda(perimetro, indirizzo), indirizzo


# --------------------------------------------------------------------------- #
# Consegna alla sonda
# --------------------------------------------------------------------------- #
def test_la_configurazione_consegnata_porta_il_perimetro_e_le_cadenze(server_app, contesto):
    with server_app.app_context():
        from snapserver.blueprints.api_probe import DEFAULT_SCAN_CADENCES, _probe_config
        from snapserver.db import query, utc_now_str
        from snapserver.subnets import import_subnets

        import_subnets(contesto, FILE_ESEMPIO, "perimetro.txt")
        adesso = utc_now_str()
        query("SELECT 1", ())  # apre la connessione nel contesto
        from snapserver.db import execute

        execute(
            "INSERT INTO probes (tenant_id, probe_uid, code, name, status, scan_interval_sec,"
            " config_json, created_at, updated_at)"
            " VALUES (?, 'uid-test', 'sonda-test', 'Sonda di prova', 'active', 300, '{}', ?, ?)",
            (contesto, adesso, adesso),
        )
        sonda = query("SELECT * FROM probes WHERE probe_uid = 'uid-test'", (), one=True)
        tenant = dict(query("SELECT * FROM tenants WHERE id = ?", (contesto,), one=True))
        configurazione = _probe_config(sonda, tenant)

    assert [s["cidr"] for s in configurazione["subnets"]] == [
        "10.20.10.0/24", "10.50.9.0/24", "192.168.4.0/24"]
    # Le cadenze sono quelle predefinite, tranne la scoperta che viene dal campo
    # della sonda (in giorni).
    attese = dict(DEFAULT_SCAN_CADENCES)
    attese["discovery"] = configurazione["discovery_days"] * 86400
    assert configurazione["cadences"] == attese
    assert configurazione["tenant_name"] == tenant["name"]


def test_un_perimetro_oltre_il_limite_viene_rifiutato_non_troncato(server_app):
    """Un perimetro troncato sembrerebbe completo senza esserlo.

    Era un difetto reale: un file di 380 subnet veniva importato tenendo le prime
    64, e la scansione appariva completa mentre copriva un sesto della rete.
    """
    with server_app.app_context():
        from snapserver.subnets import (
            MAX_SUBNETS_PER_TENANT,
            MAX_TOTAL_ADDRESSES,
            SubnetError,
            parse_subnet_file,
        )

        # Molte subnet, tutte valide: devono essere accettate tutte.
        molte = "\n".join("10.%d.%d.0/24" % (i // 256, i % 256) for i in range(380))
        esito = parse_subnet_file(molte)
        assert len(esito["subnets"]) == 380, "il perimetro non deve essere troncato"
        assert esito["total_hosts"] == 380 * 254

        # Oltre il limite complessivo di indirizzi si rifiuta, dichiarando i numeri.
        troppe = "\n".join("10.%d.%d.0/24" % (i // 256, i % 256) for i in range(1200))
        with pytest.raises(SubnetError) as errore:
            parse_subnet_file(troppe)
        assert str(MAX_TOTAL_ADDRESSES) in str(errore.value)
        assert MAX_SUBNETS_PER_TENANT >= 2048


# --------------------------------------------------------------------------- #
# Attivazione e disattivazione di tutte le subnet
# --------------------------------------------------------------------------- #
def test_si_possono_attivare_e_disattivare_tutte_le_subnet(logged_client, server_app, contesto):
    """Con centinaia di subnet, una per una non e' proponibile."""
    with server_app.app_context():
        from snapserver.db import query
        from snapserver.subnets import import_subnets

        import_subnets(contesto, FILE_ESEMPIO, "perimetro.txt")
        totali = len(query("SELECT id FROM subnets WHERE tenant_id = ?", (contesto,)))

    logged_client.post("/switch-tenant", data={"tenant_id": contesto}, follow_redirects=True)

    risposta = logged_client.post("/inventory/subnets/toggle-all", data={"state": "off"},
                                  follow_redirects=True)
    assert risposta.status_code == 200
    with server_app.app_context():
        from snapserver.db import query

        attive = query("SELECT COUNT(*) AS n FROM subnets WHERE tenant_id = ? AND is_enabled = 1",
                       (contesto,), one=True)
        assert int(attive["n"]) == 0, "il perimetro doveva restare vuoto"
        evento = query("SELECT * FROM audit_events WHERE event_type = 'subnets.disabled.all'",
                       (), one=True)
        assert evento is not None and evento["severity"] == "warning"

    logged_client.post("/inventory/subnets/toggle-all", data={"state": "on"},
                       follow_redirects=True)
    with server_app.app_context():
        from snapserver.db import query

        attive = query("SELECT COUNT(*) AS n FROM subnets WHERE tenant_id = ? AND is_enabled = 1",
                       (contesto,), one=True)
        assert int(attive["n"]) == totali, "tutte le subnet dovevano tornare attive"


def test_le_subnet_disattivate_escono_dal_perimetro_consegnato(server_app, contesto):
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str
        from snapserver.subnets import active_subnets, import_subnets

        import_subnets(contesto, FILE_ESEMPIO, "perimetro.txt")
        assert len(active_subnets(contesto)) == 3
        execute("UPDATE subnets SET is_enabled = 0, updated_at = ? WHERE tenant_id = ?",
                (utc_now_str(), contesto))
        assert active_subnets(contesto) == []


def test_la_pagina_del_perimetro_offre_i_due_pulsanti(logged_client, server_app, contesto):
    """Le due azioni agiscono sulle subnet scelte con le caselle di spunta."""
    with server_app.app_context():
        from snapserver.subnets import import_subnets

        import_subnets(contesto, FILE_ESEMPIO, "perimetro.txt")
    logged_client.post("/switch-tenant", data={"tenant_id": contesto}, follow_redirects=True)
    pagina = logged_client.get("/inventory/subnets").data.decode("utf-8")
    assert "Attiva scelte" in pagina
    assert "Disattiva scelte" in pagina
    # La disattivazione passa da una conferma: sottrae indirizzi al perimetro.
    assert "data-confirm" in pagina
    # Finche' nulla e' scelto le azioni non sono disponibili.
    assert "disabled" in pagina


# --------------------------------------------------------------------------- #
# Scelta di alcune subnet con le caselle di spunta
# --------------------------------------------------------------------------- #
def _dichiara_subnet(server_app, tenant_id, elenco_cidr):
    """Inserisce le subnet indicate e restituisce i loro identificativi."""
    identificativi = []
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        for cidr in elenco_cidr:
            execute(
                "INSERT INTO subnets (tenant_id, cidr, label, host_count, is_enabled,"
                " source_file, imported_at, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)",
                (tenant_id, cidr, "prova", 254, "prova.txt", utc_now_str(),
                 utc_now_str(), utc_now_str()))
            riga = query("SELECT id FROM subnets WHERE tenant_id = ? AND cidr = ?",
                         (tenant_id, cidr), one=True)
            identificativi.append(int(riga["id"]))
    return identificativi


def _stato_subnet(server_app, tenant_id):
    """Stato di attivazione delle subnet del tenant, per identificativo."""
    with server_app.app_context():
        from snapserver.db import query

        righe = query("SELECT id, is_enabled FROM subnets WHERE tenant_id = ?", (tenant_id,))
    return {int(r["id"]): int(r["is_enabled"]) for r in righe}


def test_l_azione_riguarda_solo_le_subnet_scelte(logged_client, server_app, contesto):
    """Con centinaia di subnet l'azione deve poter riguardare solo le scelte."""
    identificativi = _dichiara_subnet(server_app, contesto,
                                      ["10.20.1.0/24", "10.20.2.0/24", "10.20.3.0/24"])
    logged_client.post("/switch-tenant", data={"tenant_id": contesto}, follow_redirects=True)

    risposta = logged_client.post(
        "/inventory/subnets/toggle-all",
        data={"state": "off", "subnet_ids": [str(identificativi[0]), str(identificativi[2])]},
        follow_redirects=True)
    assert risposta.status_code == 200

    stato = _stato_subnet(server_app, contesto)
    assert stato[identificativi[0]] == 0
    assert stato[identificativi[1]] == 1, "una subnet non scelta non va toccata"
    assert stato[identificativi[2]] == 0

    with server_app.app_context():
        from snapserver.db import query

        evento = query("SELECT * FROM audit_events"
                       " WHERE event_type = 'subnets.disabled.selection'", (), one=True)
    assert evento is not None, "l'audit deve distinguere le scelte da tutto il perimetro"


def test_l_elenco_in_un_solo_campo_vale_come_le_caselle(logged_client, server_app, contesto):
    """La tabella stacca le righe non visibili: le scelte arrivano in un campo.

    Senza questa via, agire su una selezione piu' ampia di una pagina sarebbe
    impossibile, perche' le caselle delle altre pagine non fanno parte dell'invio.
    """
    identificativi = _dichiara_subnet(server_app, contesto, ["10.21.1.0/24", "10.21.2.0/24"])
    logged_client.post("/switch-tenant", data={"tenant_id": contesto}, follow_redirects=True)

    logged_client.post(
        "/inventory/subnets/toggle-all",
        data={"state": "off",
              "subnet_ids_csv": "%d,%d" % (identificativi[0], identificativi[1])},
        follow_redirects=True)

    stato = _stato_subnet(server_app, contesto)
    assert stato[identificativi[0]] == 0
    assert stato[identificativi[1]] == 0


def test_una_scelta_illeggibile_non_ferma_le_altre(logged_client, server_app, contesto):
    identificativi = _dichiara_subnet(server_app, contesto, ["10.22.1.0/24"])
    logged_client.post("/switch-tenant", data={"tenant_id": contesto}, follow_redirects=True)

    risposta = logged_client.post(
        "/inventory/subnets/toggle-all",
        data={"state": "off", "subnet_ids_csv": "non-un-numero,%d" % identificativi[0]},
        follow_redirects=True)
    assert risposta.status_code == 200
    assert _stato_subnet(server_app, contesto)[identificativi[0]] == 0


def test_una_subnet_di_un_altro_tenant_non_si_tocca(logged_client, server_app, contesto):
    """L'appartenenza al tenant e' una condizione della modifica, non un filtro
    applicato dopo: un identificativo altrui non deve cambiare nulla."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        execute("INSERT INTO tenants (code, name, is_active, created_at, updated_at)"
                " VALUES (?, ?, 1, ?, ?)",
                ("altro-cliente", "Altro cliente", utc_now_str(), utc_now_str()))
        altro = int(query("SELECT id FROM tenants WHERE code = 'altro-cliente'",
                          (), one=True)["id"])

    miei = _dichiara_subnet(server_app, contesto, ["10.23.1.0/24"])
    altrui = _dichiara_subnet(server_app, altro, ["10.23.2.0/24"])
    logged_client.post("/switch-tenant", data={"tenant_id": contesto}, follow_redirects=True)

    risposta = logged_client.post(
        "/inventory/subnets/toggle-all",
        data={"state": "off", "subnet_ids": [str(altrui[0])]},
        follow_redirects=True)
    assert risposta.status_code == 200
    assert "Nessuna subnet fra quelle scelte" in risposta.get_data(as_text=True)
    assert _stato_subnet(server_app, altro)[altrui[0]] == 1, (
        "la subnet di un altro tenant doveva restare attiva")
    assert _stato_subnet(server_app, contesto)[miei[0]] == 1


def test_la_pagina_offre_la_casella_per_tutte(logged_client, server_app, contesto):
    _dichiara_subnet(server_app, contesto, ["10.24.1.0/24"])
    logged_client.post("/switch-tenant", data={"tenant_id": contesto}, follow_redirects=True)

    pagina = logged_client.get("/inventory/subnets").get_data(as_text=True)
    assert "data-selezione-tutte" in pagina, "manca la casella dell'intestazione"
    assert "data-selezione-voce" in pagina, "mancano le caselle delle righe"
    assert 'form="modulo-subnet-scelte"' in pagina, (
        "le caselle non sono collegate al modulo: un modulo dentro un altro non e' "
        "consentito, e l'attributo form e' l'unica via")
    assert "snap-selezione.js" in pagina


# --------------------------------------------------------------------------- #
# Scansione estemporanea di una subnet
# --------------------------------------------------------------------------- #
def _sonda(server_app, tenant_id, uid="uid-perimetro", codice="P-PER", attiva=True):
    """Sonda registrata per il tenant, con le scansioni attive o sospese."""
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        execute("INSERT INTO probes (tenant_id, probe_uid, code, name, status,"
                " scan_enabled, scan_interval_sec, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, 'active', ?, 300, ?, ?)",
                (tenant_id, uid, codice, "Sonda %s" % codice, 1 if attiva else 0,
                 utc_now_str(), utc_now_str()))
        return int(query("SELECT id FROM probes WHERE probe_uid = ?", (uid,),
                         one=True)["id"])


def _comandi(server_app, tenant_id):
    with server_app.app_context():
        from snapserver.db import query

        return query("SELECT * FROM probe_commands WHERE tenant_id = ?"
                     " ORDER BY id", (tenant_id,))


def test_la_scansione_estemporanea_accoda_una_scoperta_sulla_subnet(
        logged_client, server_app, contesto):
    """La scoperta ordinaria ha cadenza di giorni: quando si aggiunge una rete,
    aspettarla non ha senso. La fase e' `discovery` perche' e' la sola che accetta
    come bersaglio una rete, e il bersaglio e' esattamente il CIDR dichiarato."""
    import json

    identificativi = _dichiara_subnet(server_app, contesto, ["10.31.7.0/24"])
    sonda = _sonda(server_app, contesto)
    logged_client.post("/switch-tenant", data={"tenant_id": contesto},
                       follow_redirects=True)

    risposta = logged_client.post("/inventory/subnets/%d/scan" % identificativi[0],
                                  follow_redirects=True)
    assert risposta.status_code == 200

    comandi = _comandi(server_app, contesto)
    assert len(comandi) == 1, "doveva essere accodato un comando e uno solo"
    assert comandi[0]["command"] == "scan"
    assert int(comandi[0]["probe_id"]) == sonda
    assert json.loads(comandi[0]["payload_json"]) == {
        "stage": "discovery", "target": "10.31.7.0/24"}
    assert comandi[0]["status"] == "pending"

    with server_app.app_context():
        from snapserver.db import query

        evento = query("SELECT * FROM audit_events"
                       " WHERE event_type = 'subnet.scan.requested'", (), one=True)
    assert evento is not None, "la richiesta deve restare nel registro degli eventi"
    assert "10.31.7.0/24" in evento["description"]


def test_la_richiesta_va_alla_sonda_che_ha_gia_visto_quella_subnet(
        logged_client, server_app, contesto):
    """Con piu' sonde, chiedere a tutte una rete gia' osservata da una sola e'
    carico inutile sulla rete del cliente."""
    identificativi = _dichiara_subnet(server_app, contesto, ["10.32.7.0/24"])
    prima = _sonda(server_app, contesto, "uid-per-1", "P-1")
    seconda = _sonda(server_app, contesto, "uid-per-2", "P-2")
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        execute("INSERT INTO nodes (tenant_id, probe_id, subnet_id, ip, status,"
                " first_seen_at, last_seen_at, created_at, updated_at)"
                " VALUES (?, ?, ?, '10.32.7.10', 'up', ?, ?, ?, ?)",
                (contesto, seconda, identificativi[0], utc_now_str(), utc_now_str(),
                 utc_now_str(), utc_now_str()))

    logged_client.post("/switch-tenant", data={"tenant_id": contesto},
                       follow_redirects=True)
    logged_client.post("/inventory/subnets/%d/scan" % identificativi[0],
                       follow_redirects=True)

    comandi = _comandi(server_app, contesto)
    assert [int(c["probe_id"]) for c in comandi] == [seconda], (
        "la richiesta doveva andare alla sola sonda che osserva quella subnet")
    assert prima != seconda


def test_una_subnet_che_nessuno_ha_visto_viene_chiesta_a_tutte_le_sonde(
        logged_client, server_app, contesto):
    """E' il perimetro che tace: chi raggiunga quella rete non lo si sa ancora, e
    chiederlo a tutte e' l'unico modo di scoprirlo."""
    identificativi = _dichiara_subnet(server_app, contesto, ["10.33.7.0/24"])
    prima = _sonda(server_app, contesto, "uid-per-3", "P-3")
    seconda = _sonda(server_app, contesto, "uid-per-4", "P-4")
    logged_client.post("/switch-tenant", data={"tenant_id": contesto},
                       follow_redirects=True)

    logged_client.post("/inventory/subnets/%d/scan" % identificativi[0],
                       follow_redirects=True)

    comandi = _comandi(server_app, contesto)
    assert sorted(int(c["probe_id"]) for c in comandi) == sorted([prima, seconda])


def test_una_subnet_disattivata_non_accoda_nulla(logged_client, server_app, contesto):
    """Non fa parte del perimetro consegnato: la sonda rifiuterebbe il bersaglio.
    Accodare un comando destinato al rifiuto sarebbe una promessa falsa."""
    identificativi = _dichiara_subnet(server_app, contesto, ["10.34.7.0/24"])
    _sonda(server_app, contesto, "uid-per-5", "P-5")
    with server_app.app_context():
        from snapserver.db import execute, utc_now_str

        execute("UPDATE subnets SET is_enabled = 0, updated_at = ? WHERE id = ?",
                (utc_now_str(), identificativi[0]))

    logged_client.post("/switch-tenant", data={"tenant_id": contesto},
                       follow_redirects=True)
    risposta = logged_client.post("/inventory/subnets/%d/scan" % identificativi[0],
                                  follow_redirects=True)

    assert "disattivata" in risposta.get_data(as_text=True)
    assert _comandi(server_app, contesto) == []


def test_con_le_scansioni_sospese_la_richiesta_viene_negata(
        logged_client, server_app, contesto):
    """Una richiesta accodata mentre le scansioni sono sospese resterebbe in coda
    senza esito: la sospensione non si aggira con un comando."""
    identificativi = _dichiara_subnet(server_app, contesto, ["10.35.7.0/24"])
    _sonda(server_app, contesto, "uid-per-6", "P-6", attiva=False)
    logged_client.post("/switch-tenant", data={"tenant_id": contesto},
                       follow_redirects=True)

    risposta = logged_client.post("/inventory/subnets/%d/scan" % identificativi[0],
                                  follow_redirects=True)

    assert "sospese" in risposta.get_data(as_text=True)
    assert _comandi(server_app, contesto) == []


def test_la_stessa_richiesta_non_si_accoda_due_volte(
        logged_client, server_app, contesto):
    """Due passate identiche sulla stessa rete sono carico inutile: la seconda
    richiesta lo dichiara invece di duplicare."""
    identificativi = _dichiara_subnet(server_app, contesto, ["10.36.7.0/24"])
    _sonda(server_app, contesto, "uid-per-7", "P-7")
    logged_client.post("/switch-tenant", data={"tenant_id": contesto},
                       follow_redirects=True)

    logged_client.post("/inventory/subnets/%d/scan" % identificativi[0],
                       follow_redirects=True)
    risposta = logged_client.post("/inventory/subnets/%d/scan" % identificativi[0],
                                  follow_redirects=True)

    assert "gia" in risposta.get_data(as_text=True).replace("&#39;", "'")
    assert len(_comandi(server_app, contesto)) == 1


def test_la_subnet_di_un_altro_tenant_non_si_scansiona(
        logged_client, server_app, contesto):
    with server_app.app_context():
        from snapserver.db import execute, query, utc_now_str

        execute("INSERT INTO tenants (code, name, created_at, updated_at)"
                " VALUES (?, ?, ?, ?)",
                ("cliente-scansione", "Cliente scansione", utc_now_str(),
                 utc_now_str()))
        altro = int(query("SELECT id FROM tenants WHERE code = 'cliente-scansione'",
                          (), one=True)["id"])

    altrui = _dichiara_subnet(server_app, altro, ["10.37.7.0/24"])
    _sonda(server_app, contesto, "uid-per-8", "P-8")
    logged_client.post("/switch-tenant", data={"tenant_id": contesto},
                       follow_redirects=True)

    risposta = logged_client.post("/inventory/subnets/%d/scan" % altrui[0])
    assert risposta.status_code == 404
    assert _comandi(server_app, contesto) == []


def test_la_pagina_del_perimetro_offre_il_pulsante_sulle_subnet_attive(
        logged_client, server_app, contesto):
    """Il pulsante sta sulla riga, accanto alle altre azioni: e' la subnet che si
    guarda quando si decide di scansionarla."""
    identificativi = _dichiara_subnet(server_app, contesto, ["10.38.7.0/24"])
    logged_client.post("/switch-tenant", data={"tenant_id": contesto},
                       follow_redirects=True)

    pagina = logged_client.get("/inventory/subnets").get_data(as_text=True)
    assert "/inventory/subnets/%d/scan" % identificativi[0] in pagina
    assert "data-confirm" in pagina, (
        "una passata su 254 indirizzi si conferma prima di partire")
    assert "alert(" not in pagina and "confirm(" not in pagina
