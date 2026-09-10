# -----------------------------------------------------------------
# purge.py — azzeramento delle informazioni RACCOLTE di un tenant
# Autore: Daniele Speziale
# Data creazione: 2026-09-10
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - Cancellazione di tutto cio' che le sonde hanno raccolto.

CHE COSA DISTINGUE QUESTO DALL'ELIMINAZIONE DEL TENANT.

Eliminare un tenant lo fa sparire: utenze, sonde, perimetro, controlli, tutto.
Serve quando un cliente se ne va. Qui il tenant RESTA e si azzera solo il RACCOLTO:
l'inventario e tutto quanto le sonde ne hanno detto. Serve quando la raccolta e'
sporca -- una scansione partita su un perimetro sbagliato, una sonda dietro un NAT
che ha inventato nodi, un cambio di rete che rende l'inventario un archivio di
fantasmi -- e si vuole ricominciare senza rifare la configurazione.

IL CONFINE, dichiarato una volta e in un punto solo. Questo modulo esiste perche'
quel confine e' una decisione, non un dettaglio di implementazione: un bottone che
cancella "tutto" e che poi porta via anche la configurazione o una prova di
conformita' e' peggio di nessun bottone.

  SI CANCELLA cio' che una sonda ha OSSERVATO, e che una sonda puo' riosservare:
  nodi con porte, servizi, web, SMB, SNMP; variazioni; campioni di monitoraggio;
  esiti e misure dei controlli; presenze sulle reti senza fili; correlazioni con la
  threat intelligence; eventi e avvisi SIEM; passate di scansione e conferimenti.

  NON SI CANCELLA cio' che una PERSONA ha dichiarato o cio' che vale come prova:
  il tenant e le sue utenze; le sonde registrate (con le loro credenziali); il
  perimetro (subnets) e le zone di rete; i controlli configurati e i loro bersagli;
  le regole di notifica; i collettori e le sorgenti SIEM dichiarate; i report
  prodotti; le notifiche inviate; il registro di audit -- che anzi registra questo
  azzeramento.

DUE ECCEZIONI, entrambe con un motivo che non e' tecnico:

  * gli INCIDENTI da cui e' nata una comunicazione ad ACN NON si cancellano. Un
    incidente e' materia raccolta, ma una comunicazione all'autorita' e' un atto
    dovuto (D.lgs. 138/2024, art. 25): la sua prova non puo' sparire con un
    bottone. Quegli incidenti restano, con le loro comunicazioni, e l'esito lo
    dichiara.
  * le NOTIFICHE GIA' INVIATE restano: sono la prova di cio' che e' stato
    comunicato e a chi. Cancellarle non renderebbe il sistema piu' pulito, solo
    meno dimostrabile.

remarks: Autore: Daniele Speziale - Data: 2026-09-10
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from .db import execute, query

# --------------------------------------------------------------------------- #
# Che cosa se ne va
# --------------------------------------------------------------------------- #
# `radice` distingue le tabelle da cui si cancella DIRETTAMENTE da quelle che se ne
# vanno per vincolo di chiave esterna (ON DELETE CASCADE). Si elencano anche le
# seconde perche' vanno CONTATE: dire "eliminati 412 nodi" senza dire che con loro
# sono spariti 9.000 record di porte e 60.000 campioni non e' un resoconto.
#
# L'ordine conta: prima le tabelle che ne referenziano altre con `ON DELETE SET
# NULL`, altrimenti resterebbero righe vive col riferimento azzerato -- cioe' senza
# il contesto che le spiega (una presenza senza il nodo, un avviso senza l'incidente).
TABELLE_RACCOLTE = (
    # (tabella, etichetta, radice)
    ("presence_sessions", "Presenze sulle reti senza fili", True),
    ("ti_findings", "Correlazioni con la threat intelligence", True),
    ("siem_alerts", "Avvisi SIEM", True),
    ("siem_events", "Eventi SIEM", True),
    ("check_metrics", "Misure ricavate dagli esiti", False),
    ("check_results", "Esiti dei controlli", True),
    ("check_incident_events", "Cronologia degli incidenti", False),
    ("check_incidents", "Incidenti", True),
    ("rule_matches", "Eventi che hanno soddisfatto una regola", True),
    ("node_ports", "Porte", False),
    ("node_web", "Interfacce web", False),
    ("node_snmp", "Letture SNMP", False),
    ("node_smb", "Condivisioni SMB", False),
    ("monitor_samples", "Campioni di raggiungibilita'", False),
    ("node_changes", "Variazioni dell'inventario", True),
    ("nodes", "Nodi dell'inventario", True),
    ("scan_runs", "Passate di scansione", True),
    ("ingest_batches", "Conferimenti ricevuti", True),
)

# Le tabelle che questo azzeramento NON tocca, dichiarate per poterlo verificare con
# un test: e' l'altra meta' del confine, e una meta' sola non si puo' controllare.
TABELLE_CONSERVATE = (
    "tenants", "users", "probes", "probe_commands", "system_settings",
    "subnets", "network_zones", "check_targets", "checks", "notify_rules",
    "notifications", "report_runs", "audit_events", "acn_communications",
    "siem_collectors", "siem_sources", "siem_rules",
)


def conteggi(tenant_id: int) -> dict:
    """Quanti record raccolti ha il tenant, tabella per tabella.

    Serve a mostrare in anticipo cio' che si sta per perdere: una conferma che non
    dice il numero non e' una conferma informata.
    """
    esito = {}
    for tabella, _etichetta, _radice in TABELLE_RACCOLTE:
        riga = query("SELECT COUNT(*) AS n FROM %s WHERE tenant_id = ?" % tabella,
                     (int(tenant_id),), one=True)
        esito[tabella] = int((riga or {"n": 0})["n"] or 0)
    return esito


def riepilogo(tenant_id: int) -> dict:
    """Il conto in una forma mostrabile: totale e le voci che hanno record."""
    conti = conteggi(tenant_id)
    voci = [{"tabella": t, "etichetta": e, "record": conti.get(t, 0)}
            for t, e, _r in TABELLE_RACCOLTE if conti.get(t, 0)]
    voci.sort(key=lambda v: -v["record"])
    return {"totale": sum(conti.values()), "voci": voci, "conteggi": conti}


def riepiloghi() -> dict:
    """Il conto del raccolto per OGNI tenant: `{tenant_id: riepilogo}`.

    Una query per tabella con `GROUP BY tenant_id`, non una per tenant: la pagina
    dei tenant mostra questo numero per ciascuna riga, e con un conteggio per
    tenant il costo crescerebbe col numero dei tenant senza motivo.
    """
    per_tenant: dict = {}
    for tabella, etichetta, _radice in TABELLE_RACCOLTE:
        righe = query("SELECT tenant_id, COUNT(*) AS n FROM %s"
                      " WHERE tenant_id IS NOT NULL GROUP BY tenant_id" % tabella)
        for riga in righe or ():
            identificativo = int(riga["tenant_id"])
            numero = int(riga["n"] or 0)
            if not numero:
                continue
            voce = per_tenant.setdefault(identificativo,
                                         {"totale": 0, "voci": [], "conteggi": {}})
            voce["totale"] += numero
            voce["conteggi"][tabella] = numero
            voce["voci"].append({"tabella": tabella, "etichetta": etichetta,
                                 "record": numero})
    for voce in per_tenant.values():
        voce["voci"].sort(key=lambda v: -v["record"])
    return per_tenant


def incidenti_protetti(tenant_id: int) -> list:
    """Gli incidenti che NON si cancellano perche' hanno prodotto un atto verso ACN.

    Vedi la nota in testa al modulo: una comunicazione all'autorita' e' un atto
    dovuto, e la sua prova non sparisce con un bottone.
    """
    return query(
        "SELECT i.id, i.title, COUNT(c.id) AS comunicazioni"
        " FROM check_incidents i"
        " JOIN acn_communications c ON c.incident_id = i.id AND c.tenant_id = i.tenant_id"
        " WHERE i.tenant_id = ?"
        " GROUP BY i.id, i.title ORDER BY i.id",
        (int(tenant_id),)) or []


def azzera(tenant_id: int) -> dict:
    """Cancella il raccolto del tenant e restituisce il resoconto di cio' che e' andato.

    Il resoconto non e' cosmetico: e' cio' che finisce nel registro di audit, e senza
    numeri quella voce non dimostrerebbe niente.
    """
    tenant_id = int(tenant_id)
    prima = conteggi(tenant_id)
    protetti = [int(r["id"]) for r in incidenti_protetti(tenant_id)]

    for tabella, _etichetta, radice in TABELLE_RACCOLTE:
        if not radice:
            continue  # se ne va per cascata: cancellarla a mano sarebbe lavoro doppio
        if tabella == "check_incidents" and protetti:
            execute(
                "DELETE FROM check_incidents WHERE tenant_id = ?"
                " AND id NOT IN (%s)" % ",".join("?" * len(protetti)),
                tuple([tenant_id] + protetti))
            continue
        execute("DELETE FROM %s WHERE tenant_id = ?" % tabella, (tenant_id,))

    # L'ISTANTANEA DELLA CONSOLE DELLE SONDE e' raccolto come il resto: contiene il
    # diario e lo stato delle fasi. La sonda ne manda una nuova col primo battito,
    # quindi azzerarla non perde nulla di irrecuperabile -- ma lasciarla mostrerebbe
    # nella console il riassunto di un inventario che non esiste piu'.
    execute("UPDATE probes SET console_json = NULL, console_at = NULL"
            " WHERE tenant_id = ?", (tenant_id,))

    dopo = conteggi(tenant_id)
    return {
        "eliminati": {t: prima.get(t, 0) - dopo.get(t, 0) for t in prima},
        "rimasti": {t: n for t, n in dopo.items() if n},
        "totale": sum(prima.values()) - sum(dopo.values()),
        "incidenti_protetti": protetti,
    }


def descrizione(esito: dict) -> str:
    """Il resoconto in una riga, per il registro di audit e per l'avviso a schermo."""
    per_tabella = {t: e for t, e, _r in TABELLE_RACCOLTE}
    parti = ["%s %d" % (per_tabella.get(t, t).lower(), n)
             for t, n in sorted(esito.get("eliminati", {}).items(),
                                key=lambda v: -v[1]) if n]
    testo = "%d record eliminati" % esito.get("totale", 0)
    if parti:
        testo += " (%s)" % ", ".join(parti[:6])
    protetti = esito.get("incidenti_protetti") or []
    if protetti:
        testo += ("; %d incidenti conservati perche' hanno prodotto una"
                  " comunicazione ad ACN" % len(protetti))
    return testo
