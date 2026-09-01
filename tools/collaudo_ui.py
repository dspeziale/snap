"""
snap - Collaudo dell'interfaccia in un browser reale.

Verifica il comportamento che i test automatici non possono osservare: la
costruzione delle tabelle interattive (ordinamento, paginazione, ricerca
generale), la finestra di conferma di Awesome Notifications e la comparsa dei
messaggi del server come notifiche.

Prerequisiti: server e sonda in esecuzione, pacchetto playwright con i browser
installati (python -m playwright install chromium).

Uso:
    python tools/collaudo_ui.py

remarks: Autore: Daniele Speziale - Data: 2026-08-26
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from playwright.sync_api import sync_playwright

SERVER = "http://127.0.0.1:5500"
SONDA = "http://127.0.0.1:5510"


def accedi(pagina) -> None:
    pagina.goto(SERVER + "/login")
    pagina.fill("#email", "admin@snap.local")
    pagina.fill("#password", "Snap!Admin2026")
    pagina.click("button[type=submit]")
    pagina.wait_for_load_state("networkidle")


def esito(condizione: bool) -> str:
    return "OK " if condizione else "NO "


with sync_playwright() as motore:
    browser = motore.chromium.launch()
    contesto = browser.new_context(viewport={"width": 1500, "height": 950})
    pagina = contesto.new_page()
    errori = []
    pagina.on("pageerror", lambda e: errori.append(str(e)))
    pagina.on("console", lambda m: errori.append(m.text) if m.type == "error" else None)

    accedi(pagina)
    print("1. librerie e moduli")
    print("   %s Awesome Notifications" % esito(pagina.evaluate("typeof AWN !== 'undefined'")))
    print("   %s modulo dei dialoghi" % esito(pagina.evaluate("!!window.snapDialogs")))
    print("   %s DataTables" % esito(pagina.evaluate("typeof DataTable !== 'undefined'")))
    print("   %s nessuna dipendenza da jQuery" % esito(pagina.evaluate("typeof jQuery === 'undefined'")))

    pagina.goto(SERVER + "/probes/")
    pagina.wait_for_timeout(1500)
    print("2. tabella della flotta sonde")
    print("   %s tabella inizializzata" % esito(pagina.locator("table.dataTable").count() > 0))
    print("   %s campo di ricerca generale" % esito(pagina.locator(".dt-search input").count() > 0))
    print("   %s selettore righe per pagina" % esito(pagina.locator(".dt-length select").count() > 0))
    print("   %s navigazione fra le pagine" % esito(pagina.locator(".dt-paging .page-link").count() > 0))
    print("   %s intestazioni ordinabili" % esito(pagina.locator("th.dt-orderable-asc").count() > 0))
    print("   %s interfaccia in italiano" % esito("Mostra" in pagina.locator(".dt-length").inner_text()))

    righe = pagina.locator("table.dataTable tbody tr").count()
    informazioni = pagina.locator(".dt-info").inner_text()
    print("   righe nella pagina: %d   informazioni: %s" % (righe, informazioni.replace("\n", " ")))

    # Ricerca generale su tutte le colonne.
    pagina.fill(".dt-search input", "server")
    pagina.wait_for_timeout(900)
    dopo = pagina.locator("table.dataTable tbody tr").count()
    info_filtrata = pagina.locator(".dt-info").inner_text()
    print("   %s la ricerca filtra (%d -> %d righe)" % (esito(dopo <= righe), righe, dopo))
    print("   %s conteggio filtrato dichiarato" % esito("filtrate" in info_filtrata))
    pagina.fill(".dt-search input", "")
    pagina.wait_for_timeout(700)

    # Ordinamento.
    prima_cella = pagina.locator("table.dataTable tbody tr td").nth(1).inner_text()
    pagina.click("table.dataTable thead th:nth-child(2)")
    pagina.wait_for_timeout(700)
    dopo_ordine = pagina.locator("table.dataTable tbody tr td").nth(1).inner_text()
    ordinata = pagina.locator("table.dataTable thead th.dt-ordering-asc, table.dataTable thead th.dt-ordering-desc").count()
    print("   %s ordinamento applicato (%s -> %s)" % (esito(ordinata > 0), prima_cella[:14], dopo_ordine[:14]))

    # Paginazione: cambio della dimensione di pagina.
    pagina.select_option(".dt-length select", "10")
    pagina.wait_for_timeout(800)
    print("   %s dimensione pagina applicata (%d righe)"
          % (esito(pagina.locator("table.dataTable tbody tr").count() <= 10),
             pagina.locator("table.dataTable tbody tr").count()))

    print("3. finestra di conferma (AWN)")
    # Si apre la scheda della prima sonda elencata: gli identificativi variano.
    pagina.goto(SERVER + "/probes/")
    pagina.wait_for_timeout(1200)
    collegamento = pagina.locator("table.dataTable tbody a[href*='/probes/']").first
    if collegamento.count() > 0:
        collegamento.click()
        pagina.wait_for_load_state("networkidle")
        pagina.wait_for_timeout(700)
    conferma = pagina.locator("form[data-confirm] button[type=submit]").first
    if conferma.count() == 0:
        print("   NO  nessun modulo con conferma trovato")
    else:
        conferma.click()
        pagina.wait_for_timeout(800)
        popup = pagina.locator(".awn-popup-confirm")
        print("   %s finestra mostrata" % esito(popup.count() > 0))
        if popup.count() > 0:
            testo = popup.inner_text().replace("\n", " ")
            print("   %s pulsanti Conferma/Annulla" % esito("Conferma" in testo and "Annulla" in testo))
            print("       %s..." % testo[:70])
            pagina.locator(".awn-buttons button").last.click()
            pagina.wait_for_timeout(500)
            print("   %s annullamento chiude senza modifiche"
                  % esito(pagina.locator(".awn-popup-confirm").count() == 0))

    print("4. messaggi del server come notifiche")
    pagina.goto(SERVER + "/admin/tenants")
    pagina.wait_for_timeout(700)
    pagina.click("button[data-bs-target='#nuovo-tenant']")
    pagina.wait_for_timeout(500)
    pagina.fill("#code", "collaudoui")
    pagina.fill("#name", "Collaudo Interfaccia")
    pagina.click("#nuovo-tenant button[type=submit]")
    pagina.wait_for_load_state("networkidle")
    pagina.wait_for_timeout(1000)
    toast = pagina.locator(".awn-toast")
    print("   %s notifica mostrata" % esito(toast.count() > 0))
    if toast.count() > 0:
        print("       %s" % toast.first.inner_text().replace("\n", " ")[:70])
    print("   %s avviso rimosso dal flusso della pagina"
          % esito(pagina.locator("[data-snap-flash] .alert").count() == 0))

    print("5. tabelle nelle altre viste")
    for percorso in ["/", "/audit/", "/admin/tenants", "/admin/users"]:
        pagina.goto(SERVER + percorso)
        pagina.wait_for_timeout(1100)
        print("   %s %-22s tabelle: %d  ricerca: %d"
              % (esito(pagina.locator("table.dataTable").count() > 0), percorso,
                 pagina.locator("table.dataTable").count(),
                 pagina.locator(".dt-search input").count()))

    print("6. interfaccia della sonda")
    pagina.goto(SONDA + "/diary")
    pagina.wait_for_timeout(1300)
    print("   %s tabelle inizializzate (%d)"
          % (esito(pagina.locator("table.dataTable").count() > 0),
             pagina.locator("table.dataTable").count()))
    print("   %s Awesome Notifications" % esito(pagina.evaluate("typeof AWN !== 'undefined'")))

    reali = [e for e in errori if "favicon" not in e.lower()]
    print()
    print("errori JavaScript rilevati: %d" % len(reali))
    for e in reali[:6]:
        print("   - %s" % e[:150])

    contesto.close()
    browser.close()
