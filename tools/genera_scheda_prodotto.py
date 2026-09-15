"""
snap - Scheda di prodotto: che cosa fa snap, in quattro pagine.

PER CHI E': la direzione aziendale. Non chi installa il prodotto (per quello c'e'
`docs/16_INSTALLAZIONE_DA_ZERO.md`) ne' chi lo usa tutti i giorni (`docs/05`): chi
deve decidere se serve, che cosa copre e a quali obblighi risponde. Da qui la scelta
di che cosa NON c'e' dentro: nessun nome di file, nessuna riga di comando, nessuna
architettura interna.

PERCHE' USA L'IMPAGINATORE DEI REPORT e non quello dei manuali: e' un documento che
si consegna, e chi lo riceve ha gia' visto i report del prodotto. Stessa copertina,
stessa tipografia, stesso pie' di pagina -- il riconoscimento vale piu' di qualunque
grafica nuova.

SEI PAGINE, CONTATE. Il limite non e' un'aspirazione: alla fine il documento viene
riletto e, se supera, la generazione fallisce invece di consegnare pagine in piu' a
chi non le ha chieste.

GLI ESTRATTI VENGONO DA UN IMPIANTO REALE, ANONIMIZZATI. Le ultime due pagine
mostrano che cosa i report trovano davvero: i numeri sono quelli misurati su una rete
in esercizio, perche' un esempio inventato non convince nessuno e soprattutto non
dimostra che il prodotto funzioni. Indirizzi, subnet, nomi host ed emittenti interni
vengono pero' SOSTITUITI (vedi `tools/anonimizza.py`): l'indirizzo IP e'
l'identificativo piu' evidente ma non l'unico, e sostituire solo quello darebbe
l'impressione di aver protetto qualcosa senza averlo fatto.

VERTICALE. I report che portano molte colonne per riga sono orizzontali; questo e' un
documento di prosa con tabelle strette, e in verticale si legge e si stampa come ci si
aspetta da una scheda.

Uso (dove l'archivio e' raggiungibile -- di norma nel contenitore del server):
    python tools/genera_scheda_prodotto.py
    python tools/genera_scheda_prodotto.py --uscita docs/pdf
    python tools/genera_scheda_prodotto.py --senza-estratti   # solo le prime pagine

remarks: Autore: Daniele Speziale - Data: 2026-09-15
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent

# Dove sta il pacchetto del server, in ordine di tentativo. Due posti perche' questo
# strumento gira in due: dal repository, per produrre il documento senza estratti, e
# DENTRO il contenitore del server, che e' l'unico posto da cui l'archivio si
# raggiunge -- e li' il codice sta in /app, non in <repo>/server. Si dichiarano
# entrambi invece di indovinare: se un giorno nessuno dei due esiste, l'errore deve
# dire quali posti sono stati guardati.
RADICI_SERVER = (RADICE / "server", Path("/app"), RADICE)
for _radice in RADICI_SERVER:
    if (_radice / "snapserver").is_dir():
        sys.path.insert(0, str(_radice))
        break
else:  # nessuna delle due: si dice dove si e' guardato
    raise SystemExit("pacchetto 'snapserver' non trovato in: %s"
                     % ", ".join(str(r) for r in RADICI_SERVER))
# Lo strumento di anonimizzazione sta accanto a questo file.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from snapserver.reports.render_pdf import Foglio  # noqa: E402

# Quante pagine puo' occupare: quattro di presentazione piu' due di estratti. Se ne
# escono di piu', il documento non si consegna -- si accorcia. Un limite verificato
# vale un limite; un limite dichiarato e non verificato e' un'intenzione.
PAGINE_MASSIME = 6

# Quante righe di esempio per estratto. Tre bastano a far capire che forma ha il dato;
# oltre, l'estratto smette di essere un estratto e diventa il report.
RIGHE_DI_ESEMPIO = 3


def _intero(valore) -> str:
    """Numero con il punto delle migliaia. "21.353" si legge senza contare le cifre,
    ed e' l'unica ragione per cui i separatori esistono."""
    try:
        return "{:,}".format(int(valore)).replace(",", ".")
    except (TypeError, ValueError):
        return str(valore)


def raccogli_estratti() -> dict:
    """Numeri e righe di esempio dai report veri, con gli identificativi sostituiti.

    PERCHE' DAL DATABASE E NON A MANO. Un esempio inventato non dimostra niente: chi
    legge una scheda di prodotto sa distinguere una cifra plausibile da una misurata,
    e la seconda e' l'unica che risponda alla domanda "funziona?". Questi numeri
    vengono da una rete in esercizio.

    PERCHE' ANONIMIZZATI. Il documento esce dall'azienda che gestisce quella rete, e
    non e' detto che si fermi al primo destinatario. Indirizzi, subnet, nomi host ed
    emittenti interni vengono sostituiti in modo coerente (vedi `anonimizza`): gli
    ordini di grandezza e le proporzioni -- che sono la parte informativa -- restano
    intatti.
    """
    from datetime import date

    from anonimizza import Anonimo
    from snapserver import create_app
    from snapserver.settings import Config

    applicazione = create_app(Config)
    with applicazione.app_context():
        from snapserver.db import query
        from snapserver.reports import dataset_wide
        from snapserver.reports.windows import zone_of

        riga = query("SELECT * FROM tenants ORDER BY id LIMIT 1", (), one=True)
        if riga is None:
            raise RuntimeError("nessun tenant nell'archivio: non ci sono estratti")
        tenant = dict(riga)
        zona = zone_of(tenant)
        oggi = date.today()
        anonimo = Anonimo()

        certificati = dataset_wide.certificates(tenant, zona, oggi, 30)
        fine = dataset_wide.fine_supporto(tenant, zona, oggi, 30)
        minacce = dataset_wide.threat(tenant, zona, oggi, 30)
        inventario = dataset_wide.inventory(tenant, zona, oggi, 30)

    def righe_certificati():
        elenco = (certificati.get("entro_30") or []) + (certificati.get("scaduti") or [])
        for voce in elenco[:RIGHE_DI_ESEMPIO]:
            yield [anonimo.indirizzo(voce.get("ip")),
                   str(voce.get("port") or "-"),
                   anonimo.emittente(voce.get("cert_issuer")),
                   str(voce.get("cert_expires") or "-")]

    def righe_fine_supporto():
        for gruppo in [g for g in fine["gruppi"]
                       if g["stato"] == "fuori_supporto"][:RIGHE_DI_ESEMPIO]:
            yield [str(gruppo["nome"] or "-"), str(gruppo["nodi"]),
                   str(gruppo["fine_supporto"] or "-")]

    def righe_igiene():
        for voce in (inventario.get("porte_sospette") or [])[:RIGHE_DI_ESEMPIO]:
            yield [anonimo.indirizzo(voce.get("ip")),
                   "%s/%s" % (voce.get("protocol") or "?", voce.get("port") or "?"),
                   anonimo.testo(voce.get("suspect_reason"))]

    riepilogo = minacce.get("riepilogo") or {}
    return {
        "certificati": {"conteggi": certificati["conteggi"],
                        "righe": list(righe_certificati())},
        "fine_supporto": {"conteggi": fine["conteggi"],
                          "righe": list(righe_fine_supporto())},
        "minacce": {"conteggi": {
            "aperti": riepilogo.get("aperti", 0),
            "confermati": riepilogo.get("confermati", 0),
            "kev": riepilogo.get("kev", 0),
            "critici": (riepilogo.get("per_gravita") or {}).get("critical", 0),
            "nodi": riepilogo.get("nodi", 0)}},
        "inventario": {"conteggi": inventario.get("inventario") or {},
                       "righe": list(righe_igiene())},
        "sostituiti": anonimo.quanti,
    }


def pagine_di_estratti(foglio, estratti: dict) -> None:
    """Le due pagine che mostrano che cosa i report trovano davvero."""
    foglio.titolo_sezione("Che cosa trova, in pratica")
    foglio.paragrafo(
        "Gli estratti che seguono vengono da un impianto in esercizio. I numeri sono"
        " quelli misurati; indirizzi, subnet e nomi sono stati sostituiti, e gli"
        " indirizzi di esempio appartengono agli intervalli riservati alla"
        " documentazione. Gli ordini di grandezza e le proporzioni -- la parte che"
        " conta -- sono quelli veri.")

    inventario = estratti["inventario"]["conteggi"]
    foglio.riquadri([
        (_intero(inventario.get("nodi", 0)), "dispositivi trovati", None),
        (inventario.get("subnet_dichiarate", 0), "subnet nel perimetro", None),
        (inventario.get("subnet_attive", 0), "subnet con apparati", None),
        ("%s%%" % inventario.get("occupazione", 0), "occupazione degli indirizzi", None),
    ])
    foglio.paragrafo(
        "Un perimetro dichiarato di %s subnet, di cui %s contengono davvero qualcosa:"
        " il resto e' indirizzamento riservato e mai usato. E' la prima cosa che si"
        " scopre, e in genere nessuno la sapeva."
        % (_intero(inventario.get("subnet_dichiarate", 0)),
           _intero(inventario.get("subnet_attive", 0))))

    # -- fine supporto ---------------------------------------------------- #
    conti = estratti["fine_supporto"]["conteggi"]
    foglio.sottotitolo_sezione("Fine supporto dei sistemi operativi")
    foglio.paragrafo(
        "%s dispositivi su %s hanno un sistema operativo che non riceve piu'"
        " correzioni, e altri %s le perderanno entro sei mesi. I %s fuori supporto si"
        " concentrano su %s release: sono %s progetti di migrazione, non %s"
        " interventi."
        % (_intero(conti.get("fuori", 0)), _intero(conti.get("esaminati", 0)),
           _intero(conti.get("in_scadenza", 0)), _intero(conti.get("fuori", 0)),
           conti.get("release_fuori", 0), conti.get("release_fuori", 0),
           _intero(conti.get("fuori", 0))))
    if estratti["fine_supporto"]["righe"]:
        foglio.tabella(["SISTEMA", "DISPOSITIVI", "FINE SUPPORTO"],
                       estratti["fine_supporto"]["righe"],
                       larghezze=[52, 22, 26], mono_prima=False)

    # -- certificati ------------------------------------------------------- #
    conti = estratti["certificati"]["conteggi"]
    foglio.sottotitolo_sezione("Certificati TLS in scadenza")
    foglio.paragrafo(
        "%s certificati letti su %s dispositivi: %s gia' scaduti, %s in scadenza entro"
        " trenta giorni, %s entro novanta. %s sono autofirmati e %s usano parametri"
        " ormai deboli."
        % (_intero(conti.get("totale", 0)), _intero(conti.get("nodi", 0)),
           _intero(conti.get("scaduti", 0)), _intero(conti.get("entro_30", 0)),
           _intero(conti.get("entro_90", 0)), _intero(conti.get("autofirmati", 0)),
           _intero(conti.get("deboli", 0))))
    if estratti["certificati"]["righe"]:
        foglio.tabella(["DISPOSITIVO", "PORTA", "EMITTENTE", "SCADENZA"],
                       estratti["certificati"]["righe"],
                       larghezze=[30, 14, 34, 22])

    # -- vulnerabilita' ----------------------------------------------------- #
    conti = estratti["minacce"]["conteggi"]
    foglio.sottotitolo_sezione("Vulnerabilita' ed esposizioni")
    foglio.paragrafo(
        "%s riscontri aperti su %s dispositivi. Di questi %s sono vulnerabilita'"
        " CONFERMATE -- il prodotto ha visto la versione, non solo il servizio -- e"
        " %s riguardano vulnerabilita' che risultano sfruttate attivamente in rete:"
        " sono quelle da chiudere per prime, indipendentemente dal punteggio."
        % (_intero(conti.get("aperti", 0)), _intero(conti.get("nodi", 0)),
           _intero(conti.get("confermati", 0)), _intero(conti.get("kev", 0))))

    # -- igiene ------------------------------------------------------------- #
    foglio.sottotitolo_sezione("Quando il dato non e' quello che sembra")
    foglio.paragrafo(
        "Non tutto cio' che si misura e' vero, e il prodotto lo dichiara invece di"
        " contarlo. Esempio reale: porte che risultano aperte su OGNI nodo di una"
        " subnet e su famiglie di sistema operativo diverse non appartengono ai nodi"
        " -- le inietta un apparato in mezzo. Contarle avrebbe gonfiato la superficie"
        " esposta di migliaia di porte inesistenti.")
    if estratti["inventario"]["righe"]:
        foglio.tabella(["DISPOSITIVO", "PORTA", "PERCHE' NON SI CONTA"],
                       estratti["inventario"]["righe"],
                       larghezze=[22, 12, 66])

    sostituiti = estratti["sostituiti"]
    foglio.box([
        {"testo": "Che cosa e' stato sostituito in questa pagina.", "grassetto": True},
        {"testo": "Sostituiti in modo coerente -- lo stesso apparato porta lo stesso"
                  " identificativo finto in tutte le righe -- %s. Cio' che non compare"
                  " in questo elenco non era presente in questi estratti. Le autorita'"
                  " di certificazione pubbliche non vengono sostituite, perche' non"
                  " dicono nulla di chi le usa."
                  % (", ".join(
                      "%d %s" % (quanti, etichetta)
                      for etichetta, quanti in (
                          ("indirizzi", sostituiti["indirizzi"]),
                          ("subnet", sostituiti["reti"]),
                          ("nomi di macchina", sostituiti["nomi"]),
                          ("emittenti interni di certificato", sostituiti["emittenti"]))
                      if quanti) or "nessun identificativo")},
    ])


def scheda(destinazione: Path, versione: str, estratti: dict = None) -> Path:
    adesso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    foglio = Foglio(
        destinazione,
        kind="executive",
        titolo="snap - Che cosa fa",
        sottotitolo="Inventario, sicurezza e conformita' di una rete, in un prodotto solo",
        # NESSUN TENANT: non e' il documento di una rete, e l'impaginatore omette la
        # riga "Tenant ..." quando e' vuota. Il pie' di pagina cambia di conseguenza:
        # "documentazione di prodotto", non "documento riservato".
        tenant="",
        intervallo="scheda di prodotto",
        generato=adesso,
        scopo=[
            "Che cosa fa snap, che cosa non fa, e a quali obblighi risponde.",
            "Documento di sintesi per la direzione: le procedure operative e"
            " l'installazione stanno in manuali separati.",
        ],
        sezioni=(["Il problema", "Che cosa fa", "Che cosa produce",
                  "Conformita'", "Come e' fatto", "I limiti dichiarati"]
                 + (["Che cosa trova, in pratica"] if estratti else [])),
        riferimenti=[
            ("Prodotto", "snap - Secure Network Assessment Platform"),
            ("Versione", versione),
            ("Documenti collegati", "Manuale operativo, Installazione da zero"),
        ],
        # La nota dichiara che cosa NON c'e' dentro. La prima stesura prometteva
        # "cifre da un'installazione reale" e poi non ne citava nessuna: una nota
        # che promette qualcosa che il documento non contiene e' peggio di nessuna
        # nota, perche' chi legge la cerca.
        nota=("Gli esempi delle ultime pagine provengono da un impianto reale in"
              " esercizio: indirizzi, subnet, nomi di macchina ed emittenti interni"
              " sono stati sostituiti."
              if estratti else
              "Documento di prodotto: non contiene dati di alcuna rete. Le misure di"
              " un impianto specifico stanno nei report, che si generano su quello."),
        # L'avvertenza del pie' deve essere vera: con gli estratti il documento
        # PORTA misure di una rete reale, anche se gli identificativi sono sostituiti.
        avvertenza=("Documento di prodotto con esempi da un impianto reale:"
                    " identificativi sostituiti." if estratti else ""),
        # VERTICALE: i report portano molte colonne per riga e stanno in orizzontale;
        # questa e' prosa con tabelle strette, e si stampa come una scheda.
        orizzontale=False)

    # ------------------------------------------------------------------ #
    foglio.titolo_sezione("Il problema")
    foglio.paragrafo(
        "Nessuno sa con esattezza che cosa c'e' collegato alla propria rete. L'elenco"
        " degli apparati e' un foglio di calcolo aggiornato l'ultima volta da chi non"
        " lavora piu' qui; i sistemi fuori supporto si scoprono quando qualcuno li"
        " attacca; il perimetro cresce per sedimentazione. Le tre domande a cui in"
        " genere non si sa rispondere sono sempre le stesse:")
    foglio.elenco([
        "che cosa e' collegato alla rete, adesso, e da quando;",
        "che cosa di quello e' esposto, o non riceve piu' correzioni di sicurezza;",
        "che cosa e' cambiato dall'ultima volta che qualcuno ha guardato.",
    ])
    foglio.paragrafo(
        "snap risponde a queste tre domande in modo continuo e documentato, senza"
        " installare nulla sulle macchine da inventariare e senza aprire porte verso"
        " la rete del cliente.")

    # ------------------------------------------------------------------ #
    foglio.titolo_sezione("Che cosa fa")
    foglio.tabella(
        ["AREA", "CHE COSA RISOLVE", "IN CONCRETO"],
        [
            ["Inventario continuo",
             "L'elenco degli apparati non e' piu' un foglio di calcolo",
             "Scopre gli indirizzi attivi, ne esamina porte e servizi, riconosce il"
             " tipo di dispositivo e il sistema operativo, e registra ogni"
             " cambiamento con la sua data"],
            ["Ciclo di vita",
             "Si sa in anticipo che cosa va sostituito, e quando",
             "Data di fine supporto di ogni sistema operativo trovato, scadenza dei"
             " certificati TLS, eta' delle interfacce di gestione"],
            ["Esposizioni",
             "Un servizio pericoloso qui puo' essere normale altrove",
             "Le esposizioni sono giudicate secondo la ZONA della rete: la stessa"
             " porta aperta vale diversamente in un datacenter e in una rete di"
             " utenza"],
            ["Vulnerabilita'",
             "Dalle vulnerabilita' note ai propri apparati",
             "Correlazione con i cataloghi pubblici (CVE, vulnerabilita' sfruttate"
             " attivamente) svolta in locale, anche su reti senza uscita a internet"],
            ["Rilevazione",
             "Accorgersi di cio' che cambia senza doverlo guardare",
             "Confronta la rete con la memoria di com'era: apparati comparsi,"
             " indirizzi che cambiano scheda, servizi che si aprono, traffico"
             " anomalo"],
            ["Monitoraggio",
             "Sapere se un servizio e' su, e da quando non lo e'",
             "Controlli periodici con soglie, incidenti aperti e chiusi, notifiche"
             " per posta e Telegram"],
            ["Vista dall'interno",
             "Cio' che dalla rete non si puo' vedere",
             "Un agente facoltativo sulle macchine che contano riferisce accessi"
             " falliti, utenze nuove, protezioni disattivate, dischi che finiscono"],
        ],
        larghezze=[16, 30, 54], mono_prima=False)

    # ------------------------------------------------------------------ #
    foglio.titolo_sezione("Che cosa produce")
    foglio.paragrafo(
        "Diciassette documenti in PDF, ciascuno con un destinatario dichiarato e una"
        " domanda a cui risponde: si generano a richiesta o a cadenza, e si spediscono"
        " da soli. Alcuni esempi:")
    foglio.tabella(
        ["DOCUMENTO", "A CHI SI CONSEGNA", "A CHE DOMANDA RISPONDE"],
        [
            ["Sintesi esecutiva", "Direzione",
             "Com'e' messa la rete, in una pagina"],
            ["Fine supporto dei sistemi operativi", "Chi pianifica le migrazioni",
             "Quali sistemi non ricevono piu' correzioni, e da quando"],
            ["Postura di sicurezza", "Responsabile sicurezza",
             "Che cosa e' esposto, e quanto e' grave nel suo contesto"],
            ["Vulnerabilita' ed esposizioni", "Chi applica le correzioni",
             "Quali vulnerabilita' note riguardano davvero questi apparati"],
            ["Conformita' europea", "Direzione, consulenti, auditor",
             "Che cosa si puo' dimostrare rispetto a NIS2, CRA e GDPR"],
            ["Certificati TLS", "Sistemisti",
             "Quali certificati scadono, quali sono deboli"],
            ["Salute della flotta", "Chi gestisce il servizio",
             "Le sonde funzionano? Quanta parte del perimetro e' davvero coperta?"],
        ],
        larghezze=[26, 26, 48], mono_prima=False)
    foglio.paragrafo(
        "Ogni documento dichiara in copertina il periodo, la data di generazione e la"
        " provenienza dei dati. Nessun numero compare senza che si possa risalire a"
        " come e' stato ottenuto.")

    # ------------------------------------------------------------------ #
    foglio.titolo_sezione("Conformita'")
    foglio.paragrafo(
        "snap non promette la conformita': produce le PROVE che servono a dimostrarla,"
        " e dichiara quali non e' in grado di produrre.")
    foglio.tabella(
        ["NORMA", "A CHE COSA SERVE snap"],
        [
            ["NIS2 (dir. UE 2022/2555)",
             "Inventario degli asset, gestione del rischio, continuita', registro"
             " delle azioni conservato due anni, supporto alla notifica degli"
             " incidenti"],
            ["CRA (reg. UE 2024/2847)",
             "Gestione delle vulnerabilita' lungo il ciclo di vita, distinta di"
             " composizione del software (SBOM)"],
            ["GDPR (reg. UE 2016/679)",
             "Minimizzazione dichiarata per ogni dato raccolto, durate di"
             " conservazione per genere di dato, avvisi sui trattamenti che"
             " riguardano le persone"],
            ["Linee guida ACN e AgID",
             "Comunicazioni ad ACN con i termini di legge sorvegliati, e un avviso"
             " prima che scadano"],
        ],
        larghezze=[24, 76], mono_prima=False)

    # ------------------------------------------------------------------ #
    foglio.titolo_sezione("Come e' fatto")
    foglio.paragrafo(
        "Tre componenti, e una regola che vale per tutti: chi sta piu' in basso apre"
        " la comunicazione verso chi sta piu' in alto, e nessuno chiama indietro.")
    foglio.tabella(
        ["COMPONENTE", "DOVE STA", "CHE COSA FA"],
        [
            ["Console", "Sulla rete di gestione",
             "Raccoglie, presenta, avvisa, produce i documenti. Serve piu' clienti"
             " tenuti separati"],
            ["Sonda", "Dentro la rete da esaminare",
             "Esegue le scansioni e conferisce i risultati. Non riceve connessioni"
             " dall'esterno"],
            ["Agente", "Sulle macchine che contano, facoltativo",
             "Riferisce cio' che dalla rete non si vede. Non apre porte, non accetta"
             " comandi"],
        ],
        larghezze=[16, 26, 58], mono_prima=False)
    foglio.box([
        {"testo": "Perche' la direzione delle connessioni conta.", "grassetto": True},
        {"testo": "Nella rete di un cliente non si apre un canale in ingresso: e' la"
                  " prima cosa che un cliente chiede, ed e' la prima che un revisore"
                  " verifica. La conseguenza pratica e' che i comandi dalla console"
                  " arrivano alla sonda entro un minuto, non istantaneamente -- e le"
                  " pagine lo dichiarano invece di far credere il contrario."},
    ])

    # ------------------------------------------------------------------ #
    foglio.titolo_sezione("I limiti dichiarati")
    foglio.paragrafo(
        "Un prodotto che non dichiara i propri limiti costringe chi lo usa a"
        " scoprirli da solo, di solito nel momento peggiore. Questi sono scritti"
        " dentro le pagine del prodotto, non solo qui.")
    foglio.elenco([
        "Zero rilevazioni significa «nessun cambiamento fra quelli che so"
        " riconoscere», non «nessuna intrusione»: ogni pagina che mostra un"
        " conteggio dichiara anche quali sensori non hanno potuto guardare.",
        "Uno zero misurato e uno zero non misurato non si scrivono allo stesso modo."
        " Dove un dato manca, il prodotto scrive perche' manca e come si ottiene.",
        "Dalla rete si vede un'impronta, non una versione: i verdetti dedotti sono"
        " marcati come stime, e si confermano installando l'agente.",
        "La sonda non scansiona nulla fuori dal perimetro dichiarato, nemmeno per"
        " errore: il rifiuto e' registrato come evento grave.",
    ])
    foglio.paragrafo(
        "Ogni versione del prodotto porta con se' l'elenco di cio' che e' cambiato,"
        " consultabile dall'interfaccia: chi lo usa puo' sapere quando una cosa e'"
        " cambiata, e perche'.")

    if estratti:
        pagine_di_estratti(foglio, estratti)

    foglio.salva()
    return destinazione


def main() -> int:
    lettore = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    lettore.add_argument("--uscita", default=str(RADICE / "docs" / "pdf"))
    lettore.add_argument("--senza-estratti", action="store_true",
                         help="solo le pagine di presentazione, senza leggere"
                              " l'archivio")
    scelte = lettore.parse_args()

    from snapserver.settings import Config

    uscita = Path(scelte.uscita)
    uscita.mkdir(parents=True, exist_ok=True)
    destinazione = uscita / "snap-scheda-prodotto.pdf"

    estratti = None
    if not scelte.senza_estratti:
        try:
            estratti = raccogli_estratti()
        except Exception as errore:  # noqa: BLE001 - l'errore va DETTO, non nascosto
            # Senza archivio si potrebbe produrre lo stesso le prime pagine, ma in
            # silenzio: chi ha chiesto gli estratti riceverebbe un documento che non
            # li ha, senza sapere perche'. Si dichiara e si prosegue.
            print("  estratti non raccolti (%s: %s)."
                  % (type(errore).__name__, str(errore)[:120]))
            print("  Il documento esce senza le ultime pagine. Per averle, eseguire"
                  " dove l'archivio e' raggiungibile.")

    scheda(destinazione, Config.APP_VERSION, estratti)

    # IL LIMITE SI VERIFICA. Quattro pagine chieste, quattro consegnate: se il
    # documento cresce, questo si accorge prima di chi lo riceve.
    try:
        import pypdf

        pagine = len(pypdf.PdfReader(str(destinazione)).pages)
    except ImportError:
        print("  (pypdf non presente: pagine non verificate)")
        pagine = None

    print("  snap-scheda-prodotto.pdf  (%d kB%s)"
          % (destinazione.stat().st_size // 1024,
             ", %d pagine" % pagine if pagine else ""))
    if pagine and pagine > PAGINE_MASSIME:
        print("  ERRORE: %d pagine, il massimo e' %d. Il documento va accorciato."
              % (pagine, PAGINE_MASSIME))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
