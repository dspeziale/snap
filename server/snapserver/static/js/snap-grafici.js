/*
 * snap server - Grafici di andamento, disegnati in SVG senza librerie esterne.
 *
 * Perche' senza librerie: il progetto non introduce dipendenze senza averlo
 * concordato, e cio' che serve qui -- una spezzata, una griglia di riferimento e un
 * valore sotto il puntatore -- si disegna in poche centinaia di righe. Se in futuro
 * servissero assi logaritmici, zoom o piu' serie sovrapposte, allora una libreria
 * avrebbe senso; per un andamento nel tempo no.
 *
 * Uso nei template:
 *   <div data-snap-grafico
 *        data-punti='[["2026-08-27 10:00:00", 12.5], ...]'
 *        data-etichetta="latenza"       nome della serie (lettura assistiva)
 *        data-altezza="170"             altezza in pixel (facoltativa)
 *        data-unita="%"                 suffisso dei valori
 *        data-scala="percentuale"       il tetto e' 100 e non il massimo osservato
 *        data-passo="giorno"            l'ascissa e' un calendario: i buchi si vedono
 *        data-da="2026-07-31"           inizio del periodo dichiarato
 *        data-a="2026-08-29"            fine del periodo dichiarato
 *        data-soglia="99"               linea di obiettivo (facoltativa)
 *        data-compatto="1">             senza griglia ne' etichette dentro il tracciato
 *   </div>
 *
 * Tre scelte che distinguono questo disegno da un tracciato qualunque:
 *
 * 1. **L'ascissa e' il tempo, non la posizione nell'elenco.** Un giorno senza misure
 *    non e' un punto che manca: e' un tratto di calendario in cui non si e' guardato,
 *    e resta visibile come interruzione con la sua fascia. Distribuire i punti a
 *    passo costante direbbe che il tempo si e' fermato (RP-05).
 * 2. **La scala non si adatta di soppiatto.** Con `scala=percentuale` il tetto e'
 *    100: una disponibilita' fra 98 e 100 deve *sembrare* quello che e', non una
 *    montagna russa prodotta da un asse che si stringe sui dati.
 * 3. **Si ridisegna alla larghezza reale**, invece di stirare un disegno di misura
 *    fissa: cosi' testo e tratti restano nelle proporzioni giuste a ogni larghezza.
 *
 * I punti sono in ordine cronologico crescente. Il colore della serie viene dal tema
 * (`currentColor`, cioe' la classe di testo del contenitore); griglia, assi ed
 * etichette usano le variabili di Bootstrap, cosi' chiaro e scuro restano coerenti
 * senza che questo modulo conosca nessuna palette.
 *
 * remarks: Autore: Daniele Speziale - Data: 2026-08-27
 * Ultima modifica: 2026-08-29 (assi reali, scala dichiarata, buchi visibili)
 * copyright: (c) 2024-26 DS Consulting
 * license: MIT
 */
(function (global) {
  "use strict";

  var NS = "http://www.w3.org/2000/svg";
  var MARGINE_PIENO = { alto: 14, destro: 14, basso: 30, sinistro: 58 };
  /* Altezza minima fra due tacche dei valori. Sotto i ventotto pixel le etichette
     si toccano; sopra i quaranta il reticolo si dirada e non aiuta piu' a leggere
     un valore per interpolazione, che e' il motivo per cui il reticolo esiste. */
  var PASSO_TACCA_PIXEL = 32;
  var MARGINE_COMPATTO = { alto: 4, destro: 3, basso: 4, sinistro: 3 };
  var ALTEZZA_PREDEFINITA = 170;
  var GIORNO = 86400000;
  /* Sotto questa larghezza il contenitore e' nascosto (scheda chiusa, riquadro non
     ancora aperto): si rimanda, perche' un disegno largo zero non e' un disegno. */
  var LARGHEZZA_MINIMA = 60;
  var progressivo = 0;

  var NUMERO = (global.Intl && global.Intl.NumberFormat)
    ? new global.Intl.NumberFormat("it-IT", { maximumFractionDigits: 2 })
    : null;

  function elemento(nome, attributi) {
    var nodo = document.createElementNS(NS, nome);
    Object.keys(attributi || {}).forEach(function (chiave) {
      nodo.setAttribute(chiave, attributi[chiave]);
    });
    return nodo;
  }

  /* Unico punto in cui nasce del testo DENTRO il tracciato. In modalita' compatta
     non ne nasce nessuno: in un disegno alto sessanta pixel tre etichette lo
     coprirebbero, e gli stessi numeri stanno gia' nell'intestazione del riquadro.
     Passare da qui invece di ripetere la condizione a ogni etichetta e' cio' che
     rende la regola verificabile invece che ricordata. */
  function testo(svg, compatto, attributi, contenuto) {
    if (compatto) { return null; }
    var nodo = elemento("text", attributi);
    nodo.textContent = contenuto;
    svg.appendChild(nodo);
    return nodo;
  }

  /* ------------------------------------------------------------------ numeri */

  function decimale(valore) {
    if (NUMERO) { return NUMERO.format(valore); }
    return String(Math.round(valore * 100) / 100).replace(".", ",");
  }

  function numeroLeggibile(valore, unita) {
    if (valore === null || valore === undefined || !isFinite(valore)) { return "-"; }
    var assoluto = Math.abs(valore);
    var testo;
    if (assoluto >= 1000000) { testo = decimale(valore / 1000000) + " M"; }
    else if (assoluto >= 10000) { testo = decimale(valore / 1000) + " k"; }
    else { testo = decimale(valore); }
    return unita ? testo + unita : testo;
  }

  /* ------------------------------------------------------------------- tempo */

  var ISTANTE = /^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2}))?/;

  function istanteDi(testo) {
    /* Gli istanti arrivano gia' convertiti dal server nel fuso del tenant: qui si
       leggono come orario locale del disegno, senza reinterpretare nulla. */
    var pezzi = ISTANTE.exec(String(testo || ""));
    if (!pezzi) { return null; }
    var data = new Date(+pezzi[1], +pezzi[2] - 1, +pezzi[3],
                        +(pezzi[4] || 0), +(pezzi[5] || 0));
    return { tempo: data.getTime(), conOra: pezzi[4] !== undefined, data: data };
  }

  function duePosizioni(numero) { return (numero < 10 ? "0" : "") + numero; }

  function etichettaData(data, conOra) {
    var giorno = duePosizioni(data.getDate()) + "/" + duePosizioni(data.getMonth() + 1);
    if (!conOra) { return giorno; }
    /* Data E ora, non la sola ora: su una finestra che attraversa la mezzanotte
       "00:15" non dice di quale giorno, e su un turno di notte e' proprio quello
       che si sta cercando di capire. */
    return giorno + " " + duePosizioni(data.getHours()) + ":"
      + duePosizioni(data.getMinutes());
  }

  function etichettaAsse(voce) {
    if (!voce.istante) { return String(voce.chiave).substring(0, 16); }
    return etichettaData(voce.istante.data, voce.istante.conOra);
  }

  function etichettaEstesa(voce) {
    if (!voce.istante) { return String(voce.chiave); }
    var d = voce.istante.data;
    var giorno = duePosizioni(d.getDate()) + "/" + duePosizioni(d.getMonth() + 1)
      + "/" + d.getFullYear();
    if (!voce.istante.conOra) { return giorno; }
    return giorno + " " + duePosizioni(d.getHours()) + ":" + duePosizioni(d.getMinutes());
  }

  /* Passi ammessi per le tacche temporali: multipli che una persona riconosce.
     Un passo qualunque -- ogni 7 ore, ogni 3 giorni e mezzo -- costringerebbe a
     fare i conti per capire dove si trova un punto. */
  var PASSI_ORA = [1, 2, 3, 4, 6, 12, 24];
  var PASSI_GIORNO = [1, 2, 3, 7, 14, 28, 30, 60, 90, 180, 365];

  function taccheTemporali(da, a, quante, conOra) {
    var unita = conOra ? 3600000 : GIORNO;
    var passi = conOra ? PASSI_ORA : PASSI_GIORNO;
    var totale = Math.max(1, Math.round((a - da) / unita));
    var passo = passi[passi.length - 1];
    for (var i = 0; i < passi.length; i += 1) {
      if (totale / passi[i] <= quante - 1) { passo = passi[i]; break; }
    }
    /* Si parte dalla fine: l'ultimo istante e' quello che si cerca per primo, e
       deve cadere su una tacca invece che restare fra due. */
    var istanti = [];
    for (var t = a; t >= da - unita / 2 && istanti.length < 12; t -= passo * unita) {
      istanti.unshift(t);
    }
    return istanti.map(function (tempo) {
      return { tempo: tempo, testo: etichettaData(new Date(tempo), conOra) };
    }).filter(function (tacca, posto, tutte) {
      /* Due scritte uguali ATTACCATE sono una scritta ripetuta -- capitava con serie
         brevi, dove sei tacche cadevano tutte nello stesso giorno. Due uguali agli
         estremi no: su ventiquattro ore la prima e l'ultima portano lo stesso
         orario, e toglierne una lascerebbe l'asse senza il suo estremo. */
      return posto === 0 || tacca.testo !== tutte[posto - 1].testo;
    });
  }

  function taccheDiElenco(punti, quante) {
    var viste = {};
    var risultato = [];
    for (var k = 0; k < quante; k += 1) {
      var indice = Math.round(k * (punti.length - 1) / (quante - 1));
      var testo = etichettaAsse(punti[indice]);
      if (viste[testo]) { continue; }
      viste[testo] = true;
      risultato.push({ indice: indice, testo: testo });
    }
    return risultato;
  }

  /* ------------------------------------------------------------------- scale */

  /* Gradini di una scala percentuale. Una disponibilita' si legge vicino al tetto:
     partire da zero appiattirebbe ogni differenza, partire dal minimo osservato la
     gonfierebbe. Si sceglie il gradino piu' alto che sta sotto al dato. */
  var GRADINI = [0, 50, 80, 90, 95, 97, 98, 99, 99.5, 99.9];

  function quanteTacche(altezzaUtile) {
    return Math.max(3, Math.min(11, Math.round(altezzaUtile / PASSO_TACCA_PIXEL)));
  }

  function scalaPercentuale(minimo, quante) {
    var base = 0;
    for (var i = 0; i < GRADINI.length; i += 1) {
      if (GRADINI[i] <= minimo - 0.001) { base = GRADINI[i]; }
    }
    /* Almeno un punto percentuale di scala. Una serie sempre al 100% su un asse
       99,9-100 mostrerebbe decimi che nessuno ha misurato: e' precisione finta, e
       fa sembrare fragile un risultato pieno. Un punto intero e' il contesto in cui
       quel 100% si legge per quello che e'. */
    if (100 - base < 1) { base = 99; }
    /* Le tacche si distribuiscono su un passo riconoscibile fra il fondo e 100:
       un reticolo con valori come 98,3666 si legge peggio di uno senza reticolo. */
    var passo = passoBello(100 - base, Math.max(2, (quante || 3) - 1));
    var tacche = [];
    for (var valore = base; valore <= 100 + passo / 1000; valore += passo) {
      tacche.push(Math.round(valore * 10000) / 10000);
    }
    if (tacche[tacche.length - 1] < 100) { tacche.push(100); }
    return { minimo: base, massimo: 100, tacche: tacche };
  }

  function passoBello(intervallo, quante) {
    var grezzo = intervallo / Math.max(1, quante);
    var potenza = Math.pow(10, Math.floor(Math.log(grezzo) / Math.LN10));
    var normalizzato = grezzo / potenza;
    var fattore = normalizzato <= 1 ? 1 : normalizzato <= 2 ? 2 : normalizzato <= 5 ? 5 : 10;
    return fattore * potenza;
  }

  function scalaLibera(minimo, massimo, quante) {
    /* Una serie di conteggi non ha valori negativi: un asse che scendesse sotto lo
       zero riempirebbe meta' del riquadro con un'area che non esiste, e la tacca
       "-1" prometterebbe misure impossibili. */
    var soloPositivi = minimo >= 0;
    if (minimo === massimo) {
      /* Serie costante: senza un margine la linea cadrebbe sul bordo e sembrerebbe
         assente. Il valore costante e' un'informazione, non un difetto. */
      var scarto = Math.abs(minimo) > 1 ? Math.abs(minimo) * 0.1 : 1;
      minimo -= scarto;
      massimo += scarto;
    }
    var passo = passoBello(massimo - minimo, Math.max(2, (quante || 3) - 1));
    var basso = Math.floor(minimo / passo) * passo;
    if (soloPositivi && basso < 0) { basso = 0; }
    var alto = Math.ceil(massimo / passo) * passo;
    var tacche = [];
    for (var v = basso; v <= alto + passo / 1000; v += passo) {
      tacche.push(Math.round(v * 1000000) / 1000000);
    }
    return { minimo: basso, massimo: alto, tacche: tacche };
  }

  /* -------------------------------------------------------------- lettura dati */

  function leggiPunti(contenitore) {
    var grezzi = contenitore.getAttribute("data-punti");
    if (!grezzi) { return []; }
    var punti;
    try {
      punti = JSON.parse(grezzi);
    } catch (errore) {
      // Dati illeggibili: si dichiara e non si disegna una linea inventata.
      if (global.console) {
        global.console.warn("grafico non disegnabile, punti illeggibili:", errore);
      }
      return [];
    }
    if (!Array.isArray(punti)) { return []; }
    return punti.filter(function (voce) {
      return Array.isArray(voce) && voce.length >= 2 && typeof voce[1] === "number"
        && isFinite(voce[1]);
    }).map(function (voce) {
      return { chiave: voce[0], valore: voce[1], istante: istanteDi(voce[0]) };
    });
  }

  function distanzaAttesa(voci, passoDichiarato) {
    if (passoDichiarato === "giorno") { return GIORNO; }
    if (passoDichiarato === "ora") { return 3600000; }
    var salti = [];
    for (var i = 1; i < voci.length; i += 1) {
      salti.push(voci[i].istante.tempo - voci[i - 1].istante.tempo);
    }
    if (!salti.length) { return 0; }
    salti.sort(function (a, b) { return a - b; });
    return salti[Math.floor(salti.length / 2)] || 0;
  }

  /* ------------------------------------------------------------------ disegno */

  function costruisci(contenitore) {
    var larghezza = contenitore.clientWidth;
    if (!larghezza || larghezza < LARGHEZZA_MINIMA) { return false; }

    var punti = leggiPunti(contenitore);
    var compatto = contenitore.getAttribute("data-compatto") === "1";
    var altezza = parseInt(contenitore.getAttribute("data-altezza")
                           || ALTEZZA_PREDEFINITA, 10);
    var unita = contenitore.getAttribute("data-unita") || "";
    var etichettaSerie = contenitore.getAttribute("data-etichetta") || "una misura";

    contenitore.textContent = "";
    contenitore.classList.add("snap-grafico");

    if (punti.length < 2) {
      var avviso = document.createElement("p");
      avviso.className = "text-body-secondary small mb-0 py-3 text-center";
      avviso.textContent = punti.length === 1
        ? "Una sola misura: l'andamento comincia dalla seconda."
        : "Nessuna misura numerica da rappresentare.";
      contenitore.appendChild(avviso);
      return true;
    }

    var margine = compatto ? MARGINE_COMPATTO : MARGINE_PIENO;
    var valori = punti.map(function (p) { return p.valore; });
    var minimo = Math.min.apply(null, valori);
    var massimo = Math.max.apply(null, valori);
    var medio = valori.reduce(function (a, b) { return a + b; }, 0) / valori.length;

    var tacchePreviste = quanteTacche(altezza - margine.alto - margine.basso);
    var scala = contenitore.getAttribute("data-scala") === "percentuale"
      ? scalaPercentuale(minimo, tacchePreviste)
      : scalaLibera(minimo, massimo, tacchePreviste);

    /* Ascissa temporale quando le chiavi sono istanti: e' l'unico modo perche' un
       giorno mancante resti un vuoto invece di sparire. */
    var temporale = punti.every(function (p) { return p.istante; });
    var estremoDa = istanteDi(contenitore.getAttribute("data-da"));
    var estremoA = istanteDi(contenitore.getAttribute("data-a"));
    var t0 = temporale ? punti[0].istante.tempo : 0;
    var t1 = temporale ? punti[punti.length - 1].istante.tempo : punti.length - 1;
    if (temporale && estremoDa) { t0 = Math.min(t0, estremoDa.tempo); }
    if (temporale && estremoA) { t1 = Math.max(t1, estremoA.tempo); }
    if (temporale && t1 === t0) { t1 = t0 + GIORNO; }

    var largh = larghezza - margine.sinistro - margine.destro;
    var alt = altezza - margine.alto - margine.basso;

    function ascissa(indice) {
      if (!temporale) {
        return margine.sinistro + (indice / (punti.length - 1)) * largh;
      }
      return margine.sinistro
        + ((punti[indice].istante.tempo - t0) / (t1 - t0)) * largh;
    }
    function ascissaTempo(tempo) {
      return margine.sinistro + ((tempo - t0) / (t1 - t0)) * largh;
    }
    function ordinata(valore) {
      var quota = (valore - scala.minimo) / (scala.massimo - scala.minimo);
      return margine.alto + alt - Math.max(0, Math.min(1, quota)) * alt;
    }

    progressivo += 1;
    var idSfumatura = "snap-grafico-velo-" + progressivo;

    var svg = elemento("svg", {
      viewBox: "0 0 " + larghezza + " " + altezza,
      width: larghezza, height: altezza,
      role: "img",
      tabindex: compatto ? "-1" : "0",
      "aria-label": "Andamento di " + etichettaSerie + ": da "
        + numeroLeggibile(punti[0].valore, unita) + " del " + etichettaEstesa(punti[0])
        + " a " + numeroLeggibile(punti[punti.length - 1].valore, unita) + " del "
        + etichettaEstesa(punti[punti.length - 1]) + "; minimo "
        + numeroLeggibile(minimo, unita) + ", massimo " + numeroLeggibile(massimo, unita)
        + ", media " + numeroLeggibile(medio, unita) + ".",
      class: "snap-grafico-tela"
    });

    var definizioni = elemento("defs", {});
    var sfumatura = elemento("linearGradient", {
      id: idSfumatura, x1: "0", y1: "0", x2: "0", y2: "1"
    });
    sfumatura.appendChild(elemento("stop", {
      offset: "0", "stop-color": "currentColor", "stop-opacity": "0.26"
    }));
    sfumatura.appendChild(elemento("stop", {
      offset: "1", "stop-color": "currentColor", "stop-opacity": "0.02"
    }));
    definizioni.appendChild(sfumatura);
    svg.appendChild(definizioni);

    /* --- fasce dei periodi senza misure ---------------------------------- */
    var vuoti = [];
    var passoDichiarato = contenitore.getAttribute("data-passo");
    /* Le fasce dei periodi vuoti si disegnano solo dove la cadenza e' dichiarata.
       In una serie di conteggi -- porte aperte per giorno -- un giorno assente vale
       zero, non "non misurato": disegnarci sopra una fascia direbbe il falso. Chi
       costruisce la serie sa quale dei due casi e', e lo dice con data-passo. */
    if (temporale && passoDichiarato) {
      var atteso = distanzaAttesa(punti, passoDichiarato);
      var taglio = atteso * 1.8;
      var bordi = [];
      if (estremoDa && punti[0].istante.tempo - estremoDa.tempo > taglio) {
        bordi.push([estremoDa.tempo, punti[0].istante.tempo]);
      }
      for (var g = 1; g < punti.length; g += 1) {
        var salto = punti[g].istante.tempo - punti[g - 1].istante.tempo;
        if (atteso && salto > taglio) {
          bordi.push([punti[g - 1].istante.tempo, punti[g].istante.tempo]);
          vuoti.push(g);
        }
      }
      if (estremoA && estremoA.tempo - punti[punti.length - 1].istante.tempo > taglio) {
        bordi.push([punti[punti.length - 1].istante.tempo, estremoA.tempo]);
      }
      bordi.forEach(function (fascia) {
        var x = ascissaTempo(fascia[0]);
        var larghezzaFascia = ascissaTempo(fascia[1]) - x;
        if (larghezzaFascia <= 1) { return; }
        svg.appendChild(elemento("rect", {
          x: x, y: margine.alto, width: larghezzaFascia, height: alt,
          class: "snap-grafico-vuoto"
        }));
        if (larghezzaFascia > 120) {
          /* In alto e non a meta' altezza: a meta' finirebbe sopra la linea della
             media, e due informazioni sovrapposte non se ne leggono nemmeno una. */
          testo(svg, compatto, {
            x: x + larghezzaFascia / 2, y: margine.alto + 14,
            "text-anchor": "middle", class: "snap-grafico-vuoto-testo"
          }, "nessuna misura");
        }
      });
    }

    /* --- griglia e valori dell'asse -------------------------------------- */
    if (!compatto) {
      scala.tacche.forEach(function (valore) {
        var y = ordinata(valore);
        svg.appendChild(elemento("line", {
          x1: margine.sinistro, x2: larghezza - margine.destro, y1: y, y2: y,
          class: "snap-grafico-griglia"
        }));
        testo(svg, compatto, {
          x: margine.sinistro - 8, y: y + 3.5, "text-anchor": "end",
          class: "snap-grafico-tacca"
        }, numeroLeggibile(valore, unita));
      });
      /* Assi come nel riferimento: base e lato sinistro marcati, il resto
         reticolo. Danno un bordo al disegno senza chiuderlo in una scatola. */
      svg.appendChild(elemento("line", {
        x1: margine.sinistro, x2: larghezza - margine.destro,
        y1: margine.alto + alt, y2: margine.alto + alt, class: "snap-grafico-asse"
      }));
      svg.appendChild(elemento("line", {
        x1: margine.sinistro, x2: margine.sinistro,
        y1: margine.alto, y2: margine.alto + alt, class: "snap-grafico-asse"
      }));
      /* L'unita' di misura scritta una volta sull'asse, non ripetuta su ogni tacca:
         dieci volte "ms" sono nove volte di troppo. La percentuale fa eccezione --
         il segno sta gia' su ogni etichetta, e "percento" scritto di lato sarebbe
         la stessa informazione una volta in piu'. */
      if (unita && unita !== "%") {
        testo(svg, compatto, {
          x: 12, y: margine.alto + alt / 2, "text-anchor": "middle",
          transform: "rotate(-90 12 " + (margine.alto + alt / 2) + ")",
          class: "snap-grafico-unita"
        }, unita);
      }
    }

    /* --- linea dell'obiettivo, se dichiarato ------------------------------ */
    var soglia = parseFloat(contenitore.getAttribute("data-soglia"));
    if (isFinite(soglia) && soglia >= scala.minimo && soglia <= scala.massimo) {
      var ySoglia = ordinata(soglia);
      svg.appendChild(elemento("line", {
        x1: margine.sinistro, x2: larghezza - margine.destro, y1: ySoglia, y2: ySoglia,
        class: "snap-grafico-soglia"
      }));
      testo(svg, compatto, {
        x: larghezza - margine.destro - 2, y: ySoglia - 5, "text-anchor": "end",
        class: "snap-grafico-soglia-testo"
      }, "obiettivo " + numeroLeggibile(soglia, unita));
    }

    /* --- media: la riga di riferimento su cui si giudica il resto ---------- */
    var yMedio = ordinata(medio);
    svg.appendChild(elemento("line", {
      x1: margine.sinistro, x2: larghezza - margine.destro, y1: yMedio, y2: yMedio,
      class: "snap-grafico-media"
    }));
    /* Una riga tratteggiata senza nome e' un enigma: chi guarda deve sapere che
       quella e' la media del periodo e non una soglia. */
    testo(svg, compatto, {
      x: margine.sinistro + 4, y: yMedio - 5, class: "snap-grafico-media-testo"
    }, "media " + numeroLeggibile(medio, unita));

    /* --- area e spezzata, spezzata davvero dove il dato manca -------------- */
    var segmenti = [];
    var corrente = [];
    punti.forEach(function (punto, indice) {
      if (vuoti.indexOf(indice) >= 0 && corrente.length) {
        segmenti.push(corrente);
        corrente = [];
      }
      corrente.push([ascissa(indice), ordinata(punto.valore)]);
    });
    if (corrente.length) { segmenti.push(corrente); }

    segmenti.forEach(function (segmento) {
      var coordinate = segmento.map(function (p) {
        return p[0].toFixed(2) + "," + p[1].toFixed(2);
      });
      if (segmento.length > 1) {
        /* Il velo sotto la linea resta soltanto nelle miniature: la' e' quello che
           rende leggibile un andamento alto sessanta pixel. In un grafico grande
           copre il reticolo senza aggiungere informazione, e con una scala che non
           parte da zero suggerisce anche una grandezza che non c'e'. */
        if (compatto) {
          svg.appendChild(elemento("polygon", {
            points: segmento[0][0].toFixed(2) + "," + (margine.alto + alt) + " "
              + coordinate.join(" ") + " "
              + segmento[segmento.length - 1][0].toFixed(2) + "," + (margine.alto + alt),
            fill: "url(#" + idSfumatura + ")", stroke: "none"
          }));
        }
        svg.appendChild(elemento("polyline", {
          points: coordinate.join(" "), class: "snap-grafico-linea",
          "stroke-width": compatto ? "2.2" : "1.4"
        }));
      } else {
        /* Un punto isolato fra due vuoti: senza pallino sparirebbe. */
        svg.appendChild(elemento("circle", {
          cx: segmento[0][0], cy: segmento[0][1], r: compatto ? "2.2" : "3",
          class: "snap-grafico-punto"
        }));
      }
    });

    /* --- pallini: solo quando si distinguono ------------------------------- */
    if (!compatto && punti.length <= 45) {
      punti.forEach(function (punto, indice) {
        svg.appendChild(elemento("circle", {
          cx: ascissa(indice), cy: ordinata(punto.valore), r: "2",
          class: "snap-grafico-punto"
        }));
      });
    }

    /* --- ultimo valore: e' quello che si cerca ----------------------------- */
    var ultimo = punti[punti.length - 1];
    svg.appendChild(elemento("circle", {
      cx: ascissa(punti.length - 1), cy: ordinata(ultimo.valore),
      r: compatto ? "2.8" : "4", class: "snap-grafico-ultimo"
    }));

    /* --- date sull'asse: un andamento senza tempi non si colloca ----------- */
    if (!compatto) {
      /* Le etichette portano data e ora: servono circa centoquaranta pixel per
         non sovrapporsi. Le linee verticali del reticolo cadono sulle stesse
         posizioni, cosi' ogni riferimento visivo ha la sua etichetta. */
      var quante = Math.max(2, Math.min(9, Math.floor(largh / 140)));
      var conOra = temporale && punti[0].istante.conOra;
      var tacche = temporale
        ? taccheTemporali(t0, t1, quante, conOra)
        : taccheDiElenco(punti, quante);
      tacche.forEach(function (tacca, posto) {
        var x = temporale ? ascissaTempo(tacca.tempo) : ascissa(tacca.indice);
        var ancora = posto === 0 ? "start"
          : (posto === tacche.length - 1 ? "end" : "middle");
        /* Linea verticale del reticolo: e' cio' che permette di leggere un
           valore alla data giusta senza inseguire la spezzata con il dito. */
        if (x > margine.sinistro + 1 && x < larghezza - margine.destro - 1) {
          svg.appendChild(elemento("line", {
            x1: x, x2: x, y1: margine.alto, y2: margine.alto + alt,
            class: "snap-grafico-griglia"
          }));
        }
        testo(svg, compatto, {
          x: Math.max(margine.sinistro, Math.min(larghezza - margine.destro, x)),
          y: altezza - 10, "text-anchor": ancora, class: "snap-grafico-tacca"
        }, tacca.testo);
      });
    }

    /* --- lettura puntuale: guida, pallino, riquadro ------------------------ */
    var guida = elemento("line", {
      x1: 0, x2: 0, y1: margine.alto, y2: margine.alto + alt,
      class: "snap-grafico-guida", visibility: "hidden"
    });
    svg.appendChild(guida);
    var fuoco = elemento("circle", {
      cx: 0, cy: 0, r: compatto ? "3" : "4.5", class: "snap-grafico-fuoco",
      visibility: "hidden"
    });
    svg.appendChild(fuoco);

    var nota = document.createElement("div");
    nota.className = "snap-grafico-nota";
    nota.hidden = true;
    var lettura = document.createElement("p");
    lettura.className = compatto ? "small text-body-secondary lh-1 mb-0"
      : "small text-body-secondary mb-0 mt-1";

    function riassunto() {
      lettura.textContent = "ultimo: " + numeroLeggibile(ultimo.valore, unita)
        + " del " + etichettaEstesa(ultimo);
    }
    riassunto();

    function mostra(indice) {
      var punto = punti[indice];
      var x = ascissa(indice);
      var y = ordinata(punto.valore);
      guida.setAttribute("x1", x);
      guida.setAttribute("x2", x);
      guida.setAttribute("visibility", "visible");
      fuoco.setAttribute("cx", x);
      fuoco.setAttribute("cy", y);
      fuoco.setAttribute("visibility", "visible");
      nota.textContent = "";
      var quando = document.createElement("span");
      quando.className = "snap-grafico-nota-quando";
      quando.textContent = etichettaEstesa(punto);
      var quanto = document.createElement("strong");
      quanto.textContent = numeroLeggibile(punto.valore, unita);
      nota.appendChild(quando);
      nota.appendChild(quanto);
      nota.hidden = false;
      /* Il riquadro segue il punto e resta dentro il contenitore: uno che esce dal
         bordo costringerebbe a inseguirlo con il mouse. */
      var sinistra = Math.max(4, Math.min(larghezza - 4 - nota.offsetWidth,
                                          x - nota.offsetWidth / 2));
      nota.style.left = sinistra + "px";
      nota.style.top = Math.max(0, y - nota.offsetHeight - 12) + "px";
      lettura.textContent = numeroLeggibile(punto.valore, unita) + " del "
        + etichettaEstesa(punto);
    }

    function nascondi() {
      guida.setAttribute("visibility", "hidden");
      fuoco.setAttribute("visibility", "hidden");
      nota.hidden = true;
      riassunto();
    }

    function indiceVicino(clientX) {
      var riquadro = svg.getBoundingClientRect();
      if (!riquadro.width) { return 0; }
      var relativo = (clientX - riquadro.left) / riquadro.width * larghezza;
      var scelto = 0;
      var distanza = Infinity;
      for (var i = 0; i < punti.length; i += 1) {
        var d = Math.abs(ascissa(i) - relativo);
        if (d < distanza) { distanza = d; scelto = i; }
      }
      return scelto;
    }

    var indiceCorrente = punti.length - 1;
    svg.addEventListener("mousemove", function (evento) {
      indiceCorrente = indiceVicino(evento.clientX);
      mostra(indiceCorrente);
    });
    svg.addEventListener("mouseleave", nascondi);
    /* Con la tastiera si percorre la serie punto per punto: un grafico leggibile
       solo con il mouse esclude chi non lo usa (WCAG 2.1 AA, 2.1.1). */
    svg.addEventListener("focus", function () { mostra(indiceCorrente); });
    svg.addEventListener("blur", nascondi);
    svg.addEventListener("keydown", function (evento) {
      var passo = evento.key === "ArrowRight" ? 1 : evento.key === "ArrowLeft" ? -1 : 0;
      if (evento.key === "Home") { indiceCorrente = 0; }
      else if (evento.key === "End") { indiceCorrente = punti.length - 1; }
      else if (passo) {
        indiceCorrente = Math.max(0, Math.min(punti.length - 1, indiceCorrente + passo));
      } else { return; }
      evento.preventDefault();
      mostra(indiceCorrente);
    });

    var tela = document.createElement("div");
    tela.className = "snap-grafico-tela-esterna";
    tela.appendChild(svg);
    tela.appendChild(nota);
    contenitore.appendChild(tela);
    contenitore.appendChild(lettura);
    return true;
  }

  function disegna(contenitore) {
    if (contenitore.dataset.snapGraficoPronto === "1") { return; }
    if (costruisci(contenitore)) {
      contenitore.dataset.snapGraficoPronto = "1";
      sorveglia(contenitore);
    }
  }

  function ridisegna(contenitore) {
    if (contenitore.dataset.snapGraficoPronto !== "1") { return; }
    costruisci(contenitore);
  }

  /* Il disegno e' fatto sulla larghezza reale, non stirato: quando il contenitore
     cambia misura -- finestra, menu laterale che si chiude, scheda che si apre --
     va rifatto, altrimenti resterebbe tagliato o corto. */
  var sorvegliante = (global.ResizeObserver) ? new global.ResizeObserver(function (voci) {
    voci.forEach(function (voce) {
      var contenitore = voce.target;
      if (contenitore.dataset.snapGraficoPronto === "1") {
        if (contenitore.dataset.snapGraficoLarghezza === String(contenitore.clientWidth)) {
          return;
        }
        contenitore.dataset.snapGraficoLarghezza = String(contenitore.clientWidth);
        ridisegna(contenitore);
      } else {
        disegna(contenitore);
      }
    });
  }) : null;

  function sorveglia(contenitore) {
    if (!sorvegliante || contenitore.dataset.snapGraficoSorvegliato === "1") { return; }
    contenitore.dataset.snapGraficoSorvegliato = "1";
    contenitore.dataset.snapGraficoLarghezza = String(contenitore.clientWidth);
    sorvegliante.observe(contenitore);
  }

  function disegnaTutti() {
    document.querySelectorAll("[data-snap-grafico]").forEach(function (contenitore) {
      disegna(contenitore);
      /* Anche i contenitori ancora larghi zero vanno sorvegliati: apriranno una
         scheda o un riquadro, e a quel punto il disegno si fa da se'. */
      sorveglia(contenitore);
    });
  }

  global.snapGrafici = { disegnaTutti: disegnaTutti, disegna: disegna };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", disegnaTutti);
  } else {
    disegnaTutti();
  }
  /* Un grafico dentro una scheda nascosta ha larghezza zero: quando la scheda si
     apre il sorvegliante se ne accorge, ma i browser senza ResizeObserver no. */
  document.addEventListener("shown.bs.tab", disegnaTutti);
})(window);
