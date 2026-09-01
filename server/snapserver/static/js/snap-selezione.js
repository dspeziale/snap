/*
 * snap server - Scelta di piu' righe in una tabella, con una casella che le
 * seleziona o deseleziona tutte.
 *
 * Uso nei template:
 *   <table data-snap-table
 *          data-selezione-modulo="id-del-modulo"   modulo che riceve le scelte
 *          data-selezione-tutti="1,2,3">           tutti gli identificativi
 *     <thead>... <input type="checkbox" data-selezione-tutte> ...</thead>
 *     <tbody>... <input type="checkbox" name="..." value="7"
 *                       form="id-del-modulo" data-selezione-voce> ...</tbody>
 *   </table>
 *
 *   Nel modulo:
 *     <input type="hidden" name="..._csv" data-selezione-elenco>
 *     <input type="hidden" name="state"   data-selezione-stato>
 *     <button type="submit" value="on" data-selezione-azione>
 *     <small data-selezione-conteggio></small>
 *
 * Perche' un elenco in un campo nascosto: la tabella (DataTables) stacca dal
 * documento le righe delle pagine non visibili, e le loro caselle non fanno parte
 * dell'invio. Le scelte sono percio' tenute qui e ricomposte in un solo campo al
 * momento dell'invio. Senza JavaScript la tabella non e' paginata, le caselle
 * vere sono tutte presenti e arrivano al server per la via ordinaria.
 *
 * remarks: Autore: Daniele Speziale - Data: 2026-08-27
 * copyright: (c) 2024-26 DS Consulting
 * license: MIT
 */
(function (global) {
  "use strict";

  function elencoIdentificativi(valore) {
    if (!valore) {
      return [];
    }
    return valore.split(",").map(function (voce) { return voce.trim(); }).filter(Boolean);
  }

  /* Identificativi delle righe che l'utente sta effettivamente vedendo, filtro
     compreso: scegliere "tutte" mentre una ricerca e' attiva deve riguardare cio'
     che la ricerca ha selezionato, non l'intera tabella. */
  function identificativiVisibili(tabella, tutti) {
    if (typeof DataTable === "undefined" || !DataTable.isDataTable ||
        !DataTable.isDataTable(tabella)) {
      return tutti.slice();
    }
    try {
      var api = new DataTable(tabella);
      var trovati = [];
      api.rows({ search: "applied" }).nodes().each(function (riga) {
        var casella = riga.querySelector("input[data-selezione-voce]");
        if (casella) {
          trovati.push(casella.value);
        }
      });
      return trovati;
    } catch (errore) {
      // Versione della tabella senza questa interrogazione: si ripiega
      // sull'elenco completo, che e' un sovrainsieme corretto.
      if (global.console) {
        global.console.debug("righe filtrate non interrogabili:", errore);
      }
      return tutti.slice();
    }
  }

  function collega(tabella) {
    var idModulo = tabella.getAttribute("data-selezione-modulo");
    if (!idModulo || tabella.dataset.selezionePronta === "1") {
      return;
    }
    var modulo = document.getElementById(idModulo);
    if (!modulo) {
      // Modulo assente: senza i permessi la testata non viene prodotta, e le
      // caselle non hanno destinazione. Non e' un errore, non c'e' nulla da fare.
      return;
    }

    /* Moduli AGGIUNTIVI che vogliono la stessa selezione. Nel perimetro sono due --
       attivazione e rimozione -- e chiedono conferme diverse: due moduli, una sola
       selezione. Senza questo, il secondo riceverebbe un elenco vuoto e sembrerebbe
       che non fosse stato scelto nulla. */
    var altri = [];
    (tabella.getAttribute("data-selezione-moduli-extra") || "").split(",")
      .forEach(function (nome) {
        var voce = document.getElementById(nome.trim());
        if (voce) { altri.push(voce); }
      });
    tabella.dataset.selezionePronta = "1";

    var tutti = elencoIdentificativi(tabella.getAttribute("data-selezione-tutti"));
    var scelte = Object.create(null);
    var quante = 0;

    var casellaTutte = tabella.querySelector("[data-selezione-tutte]");
    var conteggio = modulo.querySelector("[data-selezione-conteggio]");
    var stato = modulo.querySelector("[data-selezione-stato]");

    function raccogli(selettore) {
      /* Lo stesso elemento in tutti i moduli collegati: la selezione e' una, e i
         moduli che la usano possono essere piu' di uno. */
      var trovati = [];
      [modulo].concat(altri).forEach(function (voce) {
        voce.querySelectorAll(selettore).forEach(function (nodo) { trovati.push(nodo); });
      });
      return trovati;
    }

    var elenchi = raccogli("[data-selezione-elenco]");
    var azioni = raccogli("[data-selezione-azione], button[type=submit]");

    function scelto(identificativo) {
      return scelte[identificativo] === true;
    }

    function aggiornaTestata() {
      if (conteggio) {
        conteggio.textContent = quante === 0 ? "nessuna subnet scelta"
          : (quante === 1 ? "1 subnet scelta" : quante + " subnet scelte");
      }
      Array.prototype.forEach.call(azioni, function (pulsante) {
        pulsante.disabled = quante === 0;
      });
      if (casellaTutte) {
        var visibili = identificativiVisibili(tabella, tutti);
        var sceltiVisibili = visibili.filter(scelto).length;
        casellaTutte.checked = visibili.length > 0 && sceltiVisibili === visibili.length;
        casellaTutte.indeterminate = sceltiVisibili > 0 && sceltiVisibili < visibili.length;
      }
    }

    /* Dopo ogni ridisegno (pagina, ordinamento, ricerca) le caselle presenti nel
       documento sono altre: vanno riportate allo stato delle scelte. */
    function riallineaCaselle() {
      tabella.querySelectorAll("input[data-selezione-voce]").forEach(function (casella) {
        casella.checked = scelto(casella.value);
      });
      aggiornaTestata();
    }

    tabella.addEventListener("change", function (evento) {
      var casella = evento.target;
      if (!casella.matches || !casella.matches("input[data-selezione-voce]")) {
        return;
      }
      if (casella.checked) {
        if (!scelto(casella.value)) {
          scelte[casella.value] = true;
          quante += 1;
        }
      } else if (scelto(casella.value)) {
        delete scelte[casella.value];
        quante -= 1;
      }
      aggiornaTestata();
    });

    if (casellaTutte) {
      casellaTutte.addEventListener("change", function () {
        var visibili = identificativiVisibili(tabella, tutti);
        visibili.forEach(function (identificativo) {
          if (casellaTutte.checked) {
            if (!scelto(identificativo)) {
              scelte[identificativo] = true;
              quante += 1;
            }
          } else if (scelto(identificativo)) {
            delete scelte[identificativo];
            quante -= 1;
          }
        });
        riallineaCaselle();
      });
    }

    tabella.addEventListener("draw.dt", riallineaCaselle);

    /* Il pulsante premuto non fa parte dell'invio quando il modulo viene inviato
       per programma dopo una conferma: cio' che dichiara va scritto subito. */
    Array.prototype.forEach.call(azioni, function (pulsante) {
      pulsante.addEventListener("click", function () {
        if (stato) {
          stato.value = pulsante.getAttribute("value") || "";
        }
      });
    });

    /* L'invio vale per tutti i moduli collegati: ognuno chiede la stessa selezione,
       e ognuno la deve trovare scritta nel proprio campo. */
    [modulo].concat(altri).forEach(function (voce) {
      voce.addEventListener("submit", function (evento) {
        var identificativi = Object.keys(scelte);
        if (!identificativi.length) {
          // Senza scelte il server agirebbe su tutte le subnet: non e' cio' che
          // l'operatore ha chiesto premendo un pulsante di azione sulle scelte.
          evento.preventDefault();
          if (global.snapDialogs && global.snapDialogs.warning) {
            global.snapDialogs.warning("Nessuna subnet scelta: selezionare almeno una riga.");
          }
          return;
        }
        elenchi.forEach(function (campo) {
          campo.value = identificativi.join(",");
        });
      }, true);
    });

    riallineaCaselle();
  }

  function collegaTutte() {
    document.querySelectorAll("table[data-selezione-modulo]").forEach(collega);
  }

  global.snapSelezione = { collegaTutte: collegaTutte };
  // Le tabelle vengono preparate al caricamento: questo modulo si aggancia dopo,
  // cosi' il riallineamento parte con la tabella gia' paginata.
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", collegaTutte);
  } else {
    collegaTutte();
  }
})(window);
