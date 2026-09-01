/*
 * snap server - Ereditarieta' delle famiglie fra zone di rete.
 *
 * Chi crea una zona ha in mente qualcosa di simile a una che esiste gia': "rete di
 * collaudo" e' un datacenter con una differenza o due. Scegliendo la zona di
 * partenza, le caselle si spuntano subito -- cosi' si VEDE cio' che si sta
 * ereditando prima di salvare, e si puo' cambiare.
 *
 * Il server fa la stessa cosa da se' (`eredita_da` in zone_admin.crea): questo
 * modulo e' un miglioramento della pagina, non la sostanza della funzione. Senza
 * JavaScript la zona nasce comunque con le famiglie ereditate.
 *
 * remarks: Autore: Daniele Speziale - Data: 2026-08-31
 * copyright: (c) 2024-26 DS Consulting
 * license: MIT
 */
(function (global) {
  "use strict";

  function elencoDa(valore) {
    /* Le famiglie viaggiano separate da una barra verticale: nei titoli delle regole
       compaiono virgole e due punti, e la virgola come separatore spezzerebbe
       "Telnet: credenziali in chiaro" a meta'. */
    return (valore || "").split("|").map(function (voce) {
      return voce.trim();
    }).filter(function (voce) {
      return voce.length > 0;
    });
  }

  function spunta(modulo, nome, valori) {
    var scelte = Object.create(null);
    valori.forEach(function (voce) { scelte[voce] = true; });

    modulo.querySelectorAll("input[name='" + nome + "']").forEach(function (casella) {
      casella.checked = scelte[casella.value] === true;
    });
  }

  function collega(selettore) {
    if (selettore.dataset.zoneEreditaPronto === "1") { return; }
    selettore.dataset.zoneEreditaPronto = "1";

    selettore.addEventListener("change", function () {
      var modulo = selettore.closest("form");
      if (!modulo) { return; }
      var scelta = selettore.options[selettore.selectedIndex];
      if (!scelta || !scelta.value) {
        // "nessuna": si azzerano le spunte, perche' l'operatore ha appena detto che
        // vuole scegliere da se'. Lasciarle sarebbe un'eredita' non richiesta.
        spunta(modulo, "attese", []);
        spunta(modulo, "violazioni", []);
        return;
      }
      spunta(modulo, "attese", elencoDa(scelta.getAttribute("data-attese")));
      spunta(modulo, "violazioni", elencoDa(scelta.getAttribute("data-violazioni")));
    });
  }

  function collegaTutti() {
    document.querySelectorAll("select[data-zone-eredita]").forEach(collega);
  }

  global.snapZone = { collegaTutti: collegaTutti };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", collegaTutti);
  } else {
    collegaTutti();
  }
})(window);
