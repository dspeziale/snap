// -----------------------------------------------------------------
// snap-sonda-console.js — ritira la barra del server nella console di una sonda
// Autore: Daniele Speziale
// Data creazione: 2026-09-15
// Copyright (c) 2024-26 DS Consulting
// Licenza: MIT
// -----------------------------------------------------------------
//
// PERCHE' ESISTE. La console remota di una sonda ha il MENU DELLA SONDA a sinistra.
// Due barre affiancate -- quella del server e quella della sonda -- si confondono, e
// confondere le due significa cliccare sulla rete sbagliata.
//
// PERCHE' IN JAVASCRIPT E NON NEL CORPO DELLA PAGINA. Scrivere `sidebar-collapse`
// nella classe del <body> non basta: AdminLTE, appena parte, rilegge lo stato della
// barra da localStorage e la RIAPRE se l'utente l'aveva lasciata aperta. Serve quindi
// agire dopo di lui.
//
// PERCHE' NON SI SALVA. La barra si ritira solo qui: uscendo da questa pagina torna
// com'era. Non si tocca `lte.sidebar.state`, cosi' la scelta dell'utente rimane la
// sua -- ritirargliela per sempre perche' e' passato da una sonda sarebbe una
// decisione presa al posto suo.
(function () {
  'use strict';

  function ritira() {
    // Il segnale e' un elemento della pagina e non una classe sul <body>: il modello
    // base non ha un blocco per le classi del corpo, e aggiungerne uno per una sola
    // pagina avrebbe toccato l'impianto di tutte le altre.
    if (!document.querySelector('[data-snap-sonda-console]')) {
      return;
    }
    // AdminLTE si inizializza sullo stesso evento: si aspetta la fine del giro
    // corrente, altrimenti la sua `loadSidebarState()` arriva dopo e riapre.
    window.setTimeout(function () {
      document.body.classList.add('sidebar-collapse');
      document.body.classList.remove('sidebar-open');
    }, 0);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', ritira);
  } else {
    ritira();
  }
})();
