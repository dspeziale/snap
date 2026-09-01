/*
 * snap server - Comportamenti di interfaccia: preferenze di visualizzazione,
 * copia negli appunti, conferme di azioni distruttive.
 *
 * Le preferenze vengono applicate subito sul documento e persistite sul
 * profilo utente, cosi' da restare valide su ogni dispositivo.
 *
 * remarks: Autore: Daniele Speziale - Data: 2026-08-26
 * copyright: (c) 2024-26 DS Consulting
 * license: MIT
 */
(function () {
  "use strict";

  const root = document.documentElement;
  const form = document.getElementById("pref-form");

  function currentPreferences() {
    return {
      theme: root.getAttribute("data-bs-theme") || "light",
      font_size: (root.className.match(/snap-font-(\w+)/) || [])[1] || "normal",
      layout: (root.className.match(/snap-layout-(\w+)/) || [])[1] || "wide"
    };
  }

  function applyPreference(name, value) {
    if (name === "theme") {
      root.setAttribute("data-bs-theme", value);
    } else if (name === "font_size") {
      root.className = root.className.replace(/snap-font-\w+/, "snap-font-" + value);
    } else if (name === "layout") {
      root.className = root.className.replace(/snap-layout-\w+/, "snap-layout-" + value);
    }
    markActiveButtons();
  }

  function markActiveButtons() {
    const preferences = currentPreferences();
    document.querySelectorAll("[data-pref]").forEach(function (button) {
      const isActive = preferences[button.dataset.pref] === button.dataset.value;
      button.classList.toggle("active", isActive);
      button.classList.toggle("btn-primary", isActive);
      button.classList.toggle("btn-outline-secondary", !isActive);
    });
  }

  function persistPreferences() {
    if (!form) {
      return; // pagine senza sessione (login): nulla da persistere
    }
    const preferences = currentPreferences();
    const body = new URLSearchParams();
    body.set("csrf_token", form.querySelector('[name="csrf_token"]').value);
    Object.keys(preferences).forEach(function (key) {
      body.set(key, preferences[key]);
    });

    fetch(form.action, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Requested-With": "XMLHttpRequest"
      },
      body: body.toString(),
      credentials: "same-origin"
    }).catch(function (error) {
      // La preferenza resta applicata alla sessione corrente: si segnala in console.
      console.warn("snap: preferenza non persistita", error);
    });
  }

  document.addEventListener("click", function (event) {
    const button = event.target.closest("[data-pref]");
    if (button) {
      event.preventDefault();
      applyPreference(button.dataset.pref, button.dataset.value);
      persistPreferences();
      return;
    }

    const copy = event.target.closest("[data-copy]");
    if (copy) {
      event.preventDefault();
      const source = document.querySelector(copy.dataset.copy);
      if (!source) {
        return;
      }
      const text = source.value !== undefined ? source.value : source.textContent.trim();
      navigator.clipboard.writeText(text).then(function () {
        const original = copy.innerHTML;
        copy.innerHTML = '<i class="bi bi-check2"></i> Copiato';
        window.setTimeout(function () {
          copy.innerHTML = original;
        }, 1600);
      }).catch(function (error) {
        console.warn("snap: copia non riuscita", error);
      });
    }
  });

  // Le richieste di conferma sono gestite da snap-dialogs.js con AWN.

  // Auto-invio dei filtri al cambio di una select.
  document.querySelectorAll("[data-autosubmit]").forEach(function (element) {
    element.addEventListener("change", function () {
      element.closest("form").submit();
    });
  });

  // Apertura di una scheda da un comando che NON sta nella barra delle schede.
  //
  // Perche' non si usa data-bs-toggle="tab" fuori dalla barra: Bootstrap cerca il
  // contenitore con closest('.nav, [role="tablist"]'), non lo trova, e chiama
  // querySelectorAll su null -- "Illegal invocation", con la scheda che non si apre.
  // Qui si agisce invece sul pulsante vero della barra, attraverso la sua API.
  document.addEventListener("click", function (evento) {
    var comando = evento.target.closest("[data-snap-scheda]");
    if (!comando) {
      return;
    }
    var chiave = comando.getAttribute("data-snap-scheda");
    var pulsante = document.getElementById("tab-" + chiave);
    if (!pulsante) {
      // La scheda non esiste in questa pagina: non si finge che sia accaduto nulla.
      console.warn("snap: scheda non trovata:", chiave);
      return;
    }
    evento.preventDefault();
    if (window.bootstrap && window.bootstrap.Tab) {
      window.bootstrap.Tab.getOrCreateInstance(pulsante).show();
    } else {
      pulsante.click();
    }
    pulsante.scrollIntoView({ block: "nearest" });
  });

  // Spunta di gruppo su un elenco di caselle: `data-snap-spunta` vale "tutti" o
  // "nessuno", `data-snap-gruppo` porta l'id del contenitore.
  //
  // Un elenco di sessanta percorsi non si spunta a mano, e spuntarli uno per uno e'
  // il momento in cui si dimentica quello che serviva.
  document.addEventListener("click", function (evento) {
    var comando = evento.target.closest("[data-snap-spunta]");
    if (!comando) {
      return;
    }
    var contenitore = document.getElementById(comando.getAttribute("data-snap-gruppo"));
    if (!contenitore) {
      console.warn("snap: gruppo di caselle non trovato:",
                   comando.getAttribute("data-snap-gruppo"));
      return;
    }
    evento.preventDefault();
    var acceso = comando.getAttribute("data-snap-spunta") === "tutti";
    // Solo le voci visibili: con un filtro attivo, "tutti" vuol dire "tutti questi".
    contenitore.querySelectorAll("input[type=checkbox]").forEach(function (casella) {
      var voce = casella.closest("[data-voce]");
      if (voce && voce.hidden) {
        return;
      }
      casella.checked = acceso;
    });
  });

  // Filtro dell'elenco delle caselle: nasconde le voci che non contengono il testo.
  document.querySelectorAll("[data-snap-filtro]").forEach(function (campo) {
    var contenitore = document.getElementById(campo.getAttribute("data-snap-filtro"));
    if (!contenitore) {
      console.warn("snap: elenco da filtrare non trovato:",
                   campo.getAttribute("data-snap-filtro"));
      return;
    }
    campo.addEventListener("input", function () {
      var cercato = campo.value.trim().toLowerCase();
      contenitore.querySelectorAll("[data-voce]").forEach(function (voce) {
        var nome = (voce.getAttribute("data-voce") || "").toLowerCase();
        voce.hidden = cercato !== "" && nome.indexOf(cercato) === -1;
      });
    });
  });


  // ------------------------------------------------------------------ //
  // Menu laterale: quali gruppi restano aperti
  //
  // AdminLTE apre e chiude i gruppi, ma dimentica la scelta al cambio di pagina:
  // chi lavora sui controlli riaprirebbe quel gruppo a ogni clic. La scelta si
  // conserva nel browser (e' una preferenza di questa postazione, non un dato da
  // mandare al server), con una regola che vince su tutto: il gruppo che contiene
  // la pagina in corso resta aperto comunque, perche' il menu deve dire dove si e'.
  // ------------------------------------------------------------------ //
  (function gruppiDelMenu() {
    var CHIAVE = "snap.menu.gruppi";
    var menu = document.querySelector("[data-snap-menu]");
    if (!menu) {
      return;
    }

    function chiusi() {
      try {
        var salvato = window.localStorage.getItem(CHIAVE);
        return salvato ? JSON.parse(salvato) : [];
      } catch (errore) {
        // Navigazione privata o archivio non disponibile: il menu funziona lo
        // stesso, semplicemente non ricorda.
        console.warn("snap: preferenza del menu non leggibile:", errore);
        return [];
      }
    }

    function ricorda(elenco) {
      try {
        window.localStorage.setItem(CHIAVE, JSON.stringify(elenco));
      } catch (errore) {
        console.warn("snap: preferenza del menu non conservabile:", errore);
      }
    }

    var elenco = chiusi();
    menu.querySelectorAll("[data-snap-gruppo]").forEach(function (gruppo) {
      var nome = gruppo.getAttribute("data-snap-gruppo");
      var contieneLaPagina = !!gruppo.querySelector(".nav-treeview .nav-link.active");
      if (contieneLaPagina) {
        gruppo.classList.add("menu-open");
        return;
      }
      if (elenco.indexOf(nome) !== -1) {
        gruppo.classList.remove("menu-open");
      }
    });

    /* Un gruppo alla volta: aprendone uno, gli altri si chiudono. Con sei gruppi
       aperti insieme il menu diventa piu' alto dello schermo e la voce che serve
       finisce sotto il bordo -- e per trovarla si scorre, che e' esattamente cio'
       che un menu dovrebbe evitare. */
    function soloQuesto(aperto) {
      menu.querySelectorAll("[data-snap-gruppo]").forEach(function (altro) {
        if (altro !== aperto) {
          altro.classList.remove("menu-open");
        }
      });
    }

    // Si registra cio' che l'utente CHIUDE di proposito, non cio' che apre: un gruppo
    // nuovo introdotto da una versione successiva deve comparire aperto, non nascosto
    // da una preferenza che non lo conosceva. Le chiusure fatte dall'accordion non si
    // registrano: non sono una scelta, sono una conseguenza.
    menu.addEventListener("click", function (evento) {
      var comando = evento.target.closest("[data-snap-gruppo] > .nav-link");
      if (!comando) {
        return;
      }
      var gruppo = comando.parentElement;
      var nome = gruppo.getAttribute("data-snap-gruppo");
      // AdminLTE cambia la classe dopo il clic: si legge lo stato al giro dopo.
      window.setTimeout(function () {
        var aggiornato = chiusi().filter(function (voce) {
          return voce !== nome;
        });
        if (gruppo.classList.contains("menu-open")) {
          soloQuesto(gruppo);
        } else {
          aggiornato.push(nome);
        }
        ricorda(aggiornato);
      }, 0);
    });
  })();


  // ------------------------------------------------------------------ //
  // Collegamento "Skip to navigation"
  //
  // AdminLTE inserisce da se' due collegamenti di salto a inizio pagina. Quello al
  // contenuto principale resta -- e' cio' che la WCAG 2.4.1 chiede, saltare i blocchi
  // ripetuti -- mentre quello alla navigazione porta al menu, che sulla tastiera e'
  // gia' il primo elemento raggiungibile: e' un passaggio in piu' che non porta
  // dove non si arriverebbe comunque.
  // ------------------------------------------------------------------ //
  (function togliSaltoAllaNavigazione() {
    function rimuovi() {
      var collegamento = document.querySelector('.skip-links a[href="#navigation"]');
      if (collegamento) {
        collegamento.remove();
      }
    }
    rimuovi();
    // AdminLTE li aggiunge al proprio avvio, che puo' avvenire dopo questo modulo.
    document.addEventListener("DOMContentLoaded", rimuovi);
    window.setTimeout(rimuovi, 0);
  })();

  // ------------------------------------------------------------------ //
  // Stampa
  //
  // Un elemento con [data-print] apre la finestra di stampa del browser. Sta qui, in
  // un file esterno, perche' la Content-Security-Policy del progetto vieta il
  // JavaScript in linea (nessun onclick nel markup).
  // ------------------------------------------------------------------ //
  (function stampa() {
    document.addEventListener("click", function (evento) {
      var elemento = evento.target.closest("[data-print]");
      if (!elemento) {
        return;
      }
      evento.preventDefault();
      window.print();
    });
  })();

  markActiveButtons();
})();
