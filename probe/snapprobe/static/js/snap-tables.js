/*
 * snap probe - Tabelle con ordinamento, paginazione e ricerca generale (DataTables).
 *
 * Le tabelle sono prodotte dal server in HTML: questo modulo aggiunge le funzioni
 * di consultazione senza sostituire il contenuto, che resta leggibile in assenza
 * di JavaScript.
 *
 * Uso nei template:
 *   <table data-snap-table
 *          data-page-size="25"        righe per pagina (10, 25, 50, 100)
 *          data-order-column="0"      colonna di ordinamento iniziale
 *          data-order-dir="asc"       verso dell'ordinamento iniziale
 *          data-no-sort="AZIONI"      colonne escluse dall'ordinamento
 *          data-no-search="false">    disabilita la ricerca su questa tabella
 *
 * remarks: Autore: Daniele Speziale - Data: 2026-08-26
 * copyright: (c) 2024-26 DS Consulting
 * license: MIT
 */
(function (global) {
  "use strict";

  /* Traduzione dell'interfaccia: DataTables non include l'italiano. */
  var ITALIANO = {
    emptyTable: "Nessun dato presente nella tabella",
    info: "Righe da _START_ a _END_ di _TOTAL_",
    infoEmpty: "Nessuna riga da mostrare",
    infoFiltered: "(filtrate da _MAX_ righe totali)",
    infoThousands: ".",
    lengthMenu: "Mostra _MENU_ righe",
    loadingRecords: "Caricamento...",
    processing: "Elaborazione...",
    search: "Ricerca:",
    searchPlaceholder: "in tutte le colonne",
    zeroRecords: "Nessun risultato con i criteri impostati",
    paginate: {
      first: "Prima",
      last: "Ultima",
      next: "Successiva",
      previous: "Precedente"
    },
    aria: {
      sortAscending: ": ordina in modo crescente",
      sortDescending: ": ordina in modo decrescente"
    },
    entries: { _: "righe", 1: "riga" }
  };

  function elencoAttributo(tabella, nome) {
    var valore = tabella.getAttribute(nome);
    if (!valore) {
      return [];
    }
    return valore.split(",").map(function (voce) { return voce.trim(); }).filter(Boolean);
  }

  /* Intestazioni della tabella, usate per individuare le colonne per nome. */
  function intestazioni(tabella) {
    return Array.prototype.map.call(tabella.querySelectorAll("thead th"), function (cella) {
      return (cella.textContent || "").trim();
    });
  }

  /* Le celle contengono marcatori e collegamenti: ordinamento e ricerca devono
     operare sul testo, non sul codice HTML. */
  function definizioniColonne(tabella) {
    var nomi = intestazioni(tabella);
    var senzaOrdinamento = elencoAttributo(tabella, "data-no-sort");

    return nomi.map(function (nome, indice) {
      var definizione = { targets: indice, type: "html" };
      if (!nome || senzaOrdinamento.indexOf(nome) > -1) {
        definizione.orderable = false;
        definizione.searchable = false;
      }
      return definizione;
    });
  }

  function ordinamentoIniziale(tabella) {
    var colonna = tabella.getAttribute("data-order-column");
    if (colonna === null) {
      return [];
    }
    var verso = (tabella.getAttribute("data-order-dir") || "asc").toLowerCase();
    return [[parseInt(colonna, 10), verso === "desc" ? "desc" : "asc"]];
  }

  /* Una tabella senza righe di dati non ha bisogno degli strumenti. */
  function haDati(tabella) {
    var righe = tabella.querySelectorAll("tbody tr");
    if (!righe.length) {
      return false;
    }
    // La riga di cortesia "nessun dato" occupa tutte le colonne con un colspan.
    if (righe.length === 1 && righe[0].querySelector("td[colspan]")) {
      return false;
    }
    return true;
  }

  var istanze = [];

  function inizializza(tabella) {
    if (typeof DataTable === "undefined" || tabella.dataset.snapPronta === "1") {
      return;
    }
    if (!tabella.querySelector("thead th") || !haDati(tabella)) {
      return;
    }

    tabella.dataset.snapPronta = "1";
    var dimensione = parseInt(tabella.getAttribute("data-page-size") || "25", 10);
    var ricercaAttiva = tabella.getAttribute("data-no-search") !== "true";

    istanze.push(new DataTable(tabella, {
      language: ITALIANO,
      // r = elaborazione, f = ricerca, l = righe per pagina, t = tabella,
      // i = informazioni, p = navigazione fra le pagine.
      layout: {
        topStart: ricercaAttiva ? "search" : null,
        topEnd: "pageLength",
        bottomStart: "info",
        bottomEnd: "paging"
      },
      searching: ricercaAttiva,
      paging: true,
      pageLength: dimensione,
      lengthMenu: [10, 25, 50, 100],
      order: ordinamentoIniziale(tabella),
      columnDefs: definizioniColonne(tabella),
      autoWidth: false,
      // La struttura prodotta dal server resta quella visibile: nessuna
      // riscrittura del contenuto delle celle.
      orderClasses: false,
      stateSave: false
    }));
  }

  /* Le tabelle dentro una scheda nascosta non conoscono la propria larghezza
     fino a quando la scheda non viene mostrata: alla comparsa si riadattano. */
  function adatta() {
    istanze.forEach(function (istanza) {
      try {
        istanza.columns.adjust();
      } catch (errore) {
        // Istanza distrutta o tabella rimossa dal documento: non c'e' nulla da
        // riadattare, e non e' una condizione che debba interrompere le altre.
        if (window.console) {
          window.console.debug("tabella non riadattabile:", errore);
        }
      }
    });
  }

  function inizializzaTutte() {
    document.querySelectorAll("table[data-snap-table]").forEach(inizializza);
  }

  global.snapTables = { inizializzaTutte: inizializzaTutte, adatta: adatta };
  document.addEventListener("DOMContentLoaded", inizializzaTutte);
  // Gli eventi delle schede di Bootstrap risalgono il documento.
  document.addEventListener("shown.bs.tab", adatta);
})(window);
