"""
snap probe - Lettura dell'uscita XML di nmap e normalizzazione delle prove.

La sonda non emette verdetti: estrae dall'XML prove normalizzate e le conferisce
al server, che le interpreta. Questo modulo e' il confine fra il formato di nmap
e il contratto di conferimento.

Regola di ammissione di un nodo
-------------------------------
Un host che nmap dichiara vivo senza portare nessun'altra informazione non va
registrato nell'inventario: e' un errore di rete o di nmap (una risposta ICMP
prodotta da un apparato intermedio, un indirizzo che risponde per delega, un
falso positivo del ping di scoperta).

La regola non puo' pero' essere applicata al risultato della sola fase di
scoperta. In una subnet raggiunta per routing l'ARP non arriva e il DNS inverso
puo' non rispondere: in quel caso NESSUN host porta altra informazione oltre a
'vivo', e applicare la regola li' cancellerebbe l'intera rete. Verificato sul
campo: una scoperta su una /24 remota ha restituito 8 host tutti con il solo
'echo-reply', e la fase successiva ha dimostrato che erano 8 dispositivi reali.

Il nodo attraversa quindi tre stati:
  * REGISTRABILE  esiste una prova sostanziale (MAC, nome host, stato di una
                  porta anche solo chiusa o filtrata, sistema operativo);
  * CANDIDATO     vivo senza altre prove, ma le porte non sono ancora state
                  esaminate: si conserva in attesa di conferma, non si registra;
  * SCARTATO      vivo senza altre prove anche dopo l'esame delle porte: e'
                  l'errore di rete descritto sopra.

Il TTL della risposta e' conservato: risposte con TTL diversi provengono da host
genuinamente diversi, mentre un fantasma prodotto da un unico apparato mostra
sempre lo stesso TTL. Serve alla conferma e come indizio sul sistema operativo.

remarks: Autore: Daniele Speziale - Data: 2026-08-27
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

REGISTRABILE = "registrabile"
CANDIDATO = "candidato"
SCARTATO = "scartato"

# Stati di porta che costituiscono prova dell'esistenza dell'host: anche una
# porta chiusa e' una risposta, quindi prova che qualcuno ha risposto.
STATI_PROBANTI = {"open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"}


class NmapXmlError(Exception):
    """Uscita di nmap illeggibile o non conforme."""


def _testo(valore, predefinito=None):
    if valore is None:
        return predefinito
    valore = str(valore).strip()
    return valore or predefinito


def _intero(valore):
    try:
        return int(valore)
    except (TypeError, ValueError):
        return None


def _indirizzi(host):
    ip = mac = vendor = None
    for elemento in host.findall("address"):
        tipo = elemento.get("addrtype")
        if tipo in ("ipv4", "ipv6") and ip is None:
            ip = elemento.get("addr")
        elif tipo == "mac":
            mac = elemento.get("addr")
            vendor = _testo(elemento.get("vendor"))
    return ip, mac, vendor


def _nome_host(host):
    elenco = host.find("hostnames")
    if elenco is None:
        return None
    for nome in elenco.findall("hostname"):
        valore = _testo(nome.get("name"))
        if valore:
            return valore
    return None


def _porte(host):
    """Porte con uno stato dichiarato, piu' il conteggio degli stati aggregati."""
    porte = []
    aggregati = {}
    elemento = host.find("ports")
    if elemento is None:
        return porte, aggregati

    for extra in elemento.findall("extraports"):
        stato = _testo(extra.get("state"), "")
        conteggio = _intero(extra.get("count")) or 0
        if stato:
            aggregati[stato] = aggregati.get(stato, 0) + conteggio

    for porta in elemento.findall("port"):
        stato_elemento = porta.find("state")
        stato = _testo(stato_elemento.get("state"), "") if stato_elemento is not None else ""
        numero = _intero(porta.get("portid"))
        if numero is None:
            continue  # porta non interpretabile: si ignora, non si indovina
        servizio = porta.find("service")
        voce = {
            "protocol": _testo(porta.get("protocol"), "tcp"),
            "port": numero,
            "state": stato,
            "service_name": None,
            "product": None,
            "version": None,
            "extrainfo": None,
            "cpe": [],
            "method": None,
            "confidence": None,
            "banner": None,
        }
        # Il banner e' l'indizio piu' diretto sulla natura del servizio: lo
        # fornisce lo script 'banner' e, quando nmap non riconosce il prodotto,
        # l'impronta grezza (servicefp) ne contiene comunque il testo.
        for script in porta.findall("script"):
            if _testo(script.get("id")) == "banner":
                voce["banner"] = _testo(script.get("output"))
                break
        if servizio is not None:
            voce.update({
                "service_name": _testo(servizio.get("name")),
                "product": _testo(servizio.get("product")),
                "version": _testo(servizio.get("version")),
                "extrainfo": _testo(servizio.get("extrainfo")),
                "cpe": [c.text for c in servizio.findall("cpe") if c.text],
                "method": _testo(servizio.get("method")),
                "confidence": _intero(servizio.get("conf")),
            })
            if not voce["banner"]:
                voce["banner"] = _testo(servizio.get("servicefp"))
        porte.append(voce)
        aggregati[stato] = aggregati.get(stato, 0) + 1
    return porte, aggregati


def _sistema_operativo(host):
    elemento = host.find("os")
    if elemento is None:
        return {}
    corrispondenze = elemento.findall("osmatch")
    if not corrispondenze:
        return {}
    migliore = corrispondenze[0]
    sistema = {
        "name": _testo(migliore.get("name")),
        "accuracy": _intero(migliore.get("accuracy")),
    }
    classi = migliore.findall("osclass")
    if classi:
        classe = classi[0]
        sistema.update({
            "vendor": _testo(classe.get("vendor")),
            "family": _testo(classe.get("osfamily")),
            "gen": _testo(classe.get("osgen")),
            "type": _testo(classe.get("type")),
            "cpe": [c.text for c in classe.findall("cpe") if c.text],
        })
    return sistema


def _script(host):
    """Esiti degli script NSE, sia dell'host sia delle singole porte."""
    esiti = {}
    for contenitore in host.findall("hostscript"):
        for script in contenitore.findall("script"):
            nome = _testo(script.get("id"))
            if nome:
                esiti[nome] = _testo(script.get("output"), "")
    porte = host.find("ports")
    if porte is not None:
        for porta in porte.findall("port"):
            for script in porta.findall("script"):
                nome = _testo(script.get("id"))
                if nome:
                    esiti.setdefault(nome, _testo(script.get("output"), ""))
    return esiti


def assess_host(evidence: dict, ports_examined: bool) -> tuple:
    """Decide se un host va registrato, tenuto come candidato o scartato.

    `ports_examined` distingue una fase di sola scoperta da una fase che ha
    davvero interrogato le porte: e' cio' che impedisce di scartare host reali
    soltanto perche' la scoperta non poteva sapere altro su di loro.

    Restituisce (stato, motivo).
    """
    if not evidence.get("reachable"):
        return SCARTATO, "host non raggiungibile"

    sostanziali = []
    if evidence.get("mac"):
        sostanziali.append("MAC noto")
    if evidence.get("hostname"):
        sostanziali.append("nome host risolto")
    if (evidence.get("os") or {}).get("name"):
        sostanziali.append("sistema operativo rilevato")
    if any(p.get("state") in STATI_PROBANTI for p in evidence.get("ports") or []):
        sostanziali.append("almeno una porta con stato dichiarato")
    if any(stato in STATI_PROBANTI and conteggio
           for stato, conteggio in (evidence.get("port_states") or {}).items()):
        sostanziali.append("stati di porta aggregati presenti")
    if evidence.get("scripts"):
        sostanziali.append("esito di script")

    if sostanziali:
        return REGISTRABILE, "; ".join(sostanziali)

    if not ports_examined:
        # La scoperta non poteva sapere altro: si attende la fase delle porte.
        return CANDIDATO, ("vivo per %s, porte non ancora esaminate: in attesa di conferma"
                           % (evidence.get("status_reason") or "risposta al ping"))

    return SCARTATO, ("vivo per %s ma nessuna informazione dopo l'esame delle porte: "
                      "errore di rete o falso positivo del ping"
                      % (evidence.get("status_reason") or "risposta al ping"))


def parse_scan(xml_text: str, ports_examined: bool = None) -> dict:
    """Legge l'uscita XML di nmap e restituisce le prove normalizzate.

    `ports_examined` puo' essere omesso: viene dedotto dalla presenza di
    <scaninfo> con un tipo diverso dalla sola scoperta.
    """
    try:
        radice = ET.fromstring(xml_text)
    except ET.ParseError as errore:
        raise NmapXmlError("uscita di nmap illeggibile: %s" % errore) from errore
    if radice.tag != "nmaprun":
        raise NmapXmlError("elemento radice inatteso: %s" % radice.tag)

    tipi = [_testo(s.get("type"), "") for s in radice.findall("scaninfo")]
    if ports_examined is None:
        # Una scansione di sola scoperta non dichiara alcun tipo di scansione
        # delle porte: e' l'unico modo per distinguerla dall'uscita.
        ports_examined = bool([t for t in tipi if t and t not in ("", "ping")])

    esecuzione = {
        "nmap_version": _testo(radice.get("version")),
        "nmap_args": _testo(radice.get("args")),
        "scan_types": [t for t in tipi if t],
        "started_at": _intero(radice.get("start")),
        "ports_examined": ports_examined,
    }
    riepilogo = radice.find("runstats/finished")
    if riepilogo is not None:
        esecuzione["elapsed_sec"] = riepilogo.get("elapsed")
        esecuzione["exit_status"] = _testo(riepilogo.get("exit"))

    registrati, candidati, scartati = [], [], []
    for host in radice.findall("host"):
        ip, mac, vendor = _indirizzi(host)
        if not ip:
            continue  # senza indirizzo non c'e' nodo da registrare
        stato = host.find("status")
        porte, aggregati = _porte(host)
        tempi = host.find("times")

        prove = {
            "ip": ip,
            "mac": mac,
            "mac_vendor": vendor,
            "hostname": _nome_host(host),
            "reachable": (stato.get("state") if stato is not None else None) == "up",
            "status_reason": _testo(stato.get("reason")) if stato is not None else None,
            "ttl": _intero(stato.get("reason_ttl")) if stato is not None else None,
            "latency_ms": (round(_intero(tempi.get("srtt")) / 1000.0, 2)
                           if tempi is not None and _intero(tempi.get("srtt")) else None),
            "ports": porte,
            "port_states": aggregati,
            # nmap dichiara qui l'host abbandonato per scadenza: e' la differenza
            # fra "non ha nulla" e "non c'e' stato tempo di guardare".
            "timed_out": _testo(host.get("timedout")) == "true",
            "os": _sistema_operativo(host),
            "scripts": _script(host),
        }
        esito, motivo = assess_host(prove, ports_examined)
        prove["assessment"] = esito
        prove["assessment_reason"] = motivo
        if esito == REGISTRABILE:
            registrati.append(prove)
        elif esito == CANDIDATO:
            candidati.append(prove)
        else:
            scartati.append(prove)

    return {
        "run": esecuzione,
        "nodes": registrati,
        "candidates": candidati,
        "discarded": scartati,
    }


def distinct_ttls(nodes: list) -> int:
    """Numero di TTL distinti fra i nodi di una scansione.

    Un solo TTL su molti indirizzi indica che a rispondere e' un unico apparato:
    e' l'indizio che la scoperta ha prodotto fantasmi.
    """
    return len({n.get("ttl") for n in nodes if n.get("ttl") is not None})
