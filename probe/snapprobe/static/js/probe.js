/*
 * snap probe - Comportamenti minimi dell'interfaccia locale:
 * aggiornamento periodico della pagina di stato e conferme di sicurezza.
 *
 * remarks: Autore: Daniele Speziale - Data: 2026-08-26
 * copyright: (c) 2024-26 DS Consulting
 * license: MIT
 */
/*
 * Indicatore di attivita': interroga la rotta di stato e aggiorna spia, barre e
 * contatori senza ricaricare la pagina. Un errore di rete non viene ignorato:
 * la spia diventa rossa e il testo lo dichiara.
 */
(function () {
  "use strict";

  var INTERVALLO_MS = 3000;
  var contenitore = document.querySelector("[data-snap-stato]");
  if (!contenitore) {
    return;
  }

  function elemento(nome) {
    return contenitore.querySelector("[" + nome + "]");
  }

  function percento(valore) {
    var numero = Number(valore);
    if (!isFinite(numero) || numero < 0) { return 0; }
    return Math.min(100, numero);
  }

  function spia(classe) {
    var punto = elemento("data-spia");
    if (!punto) { return; }
    punto.className = "snap-spia " + classe;
  }

  /* Un tempo trascorso si legge meglio in minuti quando supera il minuto. */
  function durata(secondi) {
    if (secondi < 60) { return secondi + " s"; }
    var minuti = Math.floor(secondi / 60);
    var resto = secondi % 60;
    return minuti + " min" + (resto ? " " + resto + " s" : "");
  }

  /* Le fasi di ispezione durano minuti: senza il tempo trascorso l'indicatore
     resta identico e non si distingue da un blocco. */
  function descriviEsecuzioni(stato) {
    var esecuzioni = stato.esecuzioni || [];
    if (!esecuzioni.length) {
      var fasi = (stato.fasi_in_corso || []).join(", ");
      return (stato.scansioni_in_corso || 0) + " esecuzioni di nmap"
        + (fasi ? " (" + fasi + ")" : "");
    }
    return esecuzioni.map(function (voce) {
      return (voce.descrizione || "scansione") + ", da " + durata(voce.da_secondi || 0);
    }).join(" · ");
  }

  /* Sostituisce la sola classe di tinta (text-bg-*) lasciando intatte le altre. */
  function classeTono(el, tono) {
    if (!el) { return; }
    el.className = el.className.replace(/\btext-bg-\S+/g, "").replace(/\s+/g, " ").trim()
      + " text-bg-" + tono;
  }

  /* I contatori di sintesi (riquadri e badge in cima): valore, colore e nota come li
     ha gia' calcolati il server, cosi' cambiano senza ricaricare la pagina. Gli
     elementi stanno fuori dal contenitore dell'indicatore, quindi si cercano nel
     documento. */
  function aggiornaSintesi(stato) {
    (stato.riquadri || []).forEach(function (r) {
      var card = document.querySelector('[data-card="' + r.key + '"]');
      if (!card) { return; }
      var valore = card.querySelector("[data-card-val]");
      var nota = card.querySelector("[data-card-nota]");
      if (valore) { valore.textContent = r.valore; }
      if (nota) { nota.textContent = r.nota; }
      classeTono(card.querySelector("[data-card-tono]"), r.tono);
    });

    document.querySelectorAll("[data-stat]").forEach(function (el) {
      var chiave = el.getAttribute("data-stat");
      if (Object.prototype.hasOwnProperty.call(stato, chiave)) {
        el.textContent = stato[chiave];
      }
    });

    var scansione = (stato.riquadri || []).filter(function (r) {
      return r.key === "scansione";
    })[0];
    var badge = document.querySelector("[data-scan-badge]");
    if (scansione && badge) {
      classeTono(badge, scansione.tono);
      var testo = badge.querySelector("[data-scan-badge-testo]");
      if (testo) {
        testo.textContent = scansione.tono === "success"
          ? "scansione in corso" : scansione.nota;
      }
    }
  }

  function aggiorna(stato) {
    aggiornaSintesi(stato);
    var testo = elemento("data-stato-testo");
    var dettaglio = elemento("data-stato-dettaglio");
    var barra = elemento("data-barra-attivita");

    if (!stato.consentita) {
      spia("snap-spia-sospesa");
      testo.textContent = "scansioni sospese";
      dettaglio.textContent = stato.motivo_sospensione || "";
      if (barra) { barra.hidden = true; }
    } else if (stato.attiva) {
      spia("snap-spia-attiva");
      testo.textContent = "scansione in corso";
      dettaglio.textContent = descriviEsecuzioni(stato);
      if (barra) { barra.hidden = false; }
    } else {
      spia("snap-spia-attesa");
      testo.textContent = "in attesa";
      dettaglio.textContent = stato.prossima_fase
        ? "prossima fase: " + stato.prossima_fase.join(" su ")
        : "nessuna fase scaduta";
      if (barra) { barra.hidden = true; }
    }

    var thread = elemento("data-thread");
    if (thread) {
      thread.textContent = "sforzo " + (stato.sforzo || "-") + " · "
        + (stato.thread || 1) + "/" + (stato.thread_massimi || 1) + " thread · "
        + (stato.tempo_per_host || "-") + "/host";
    }

    var perimetroBarra = elemento("data-perimetro-barra");
    var perimetroTesto = elemento("data-perimetro-testo");
    if (perimetroBarra && perimetroTesto) {
      perimetroBarra.style.width = percento(stato.perimetro_percento) + "%";
      perimetroTesto.textContent = (stato.perimetro_scoperte || 0) + " / "
        + (stato.perimetro_subnet || 0) + " subnet";
    }

    var profiliBarra = elemento("data-profili-barra");
    var profiliTesto = elemento("data-profili-testo");
    if (profiliBarra && profiliTesto) {
      profiliBarra.style.width = percento(stato.profili_percento) + "%";
      profiliTesto.textContent = (stato.profili_conferiti || 0) + " conferiti, "
        + (stato.profili_in_attesa || 0) + " in lavorazione";
    }

    var aggiornato = elemento("data-aggiornato");
    if (aggiornato) {
      aggiornato.textContent = "aggiornato ora";
      aggiornato.classList.remove("text-danger");
    }
  }

  function fallito(errore) {
    spia("snap-spia-errore");
    var testo = elemento("data-stato-testo");
    var dettaglio = elemento("data-stato-dettaglio");
    if (testo) { testo.textContent = "stato non disponibile"; }
    if (dettaglio) { dettaglio.textContent = String(errore && errore.message || errore); }
    var aggiornato = elemento("data-aggiornato");
    if (aggiornato) {
      aggiornato.textContent = "ultimo aggiornamento non riuscito";
      aggiornato.classList.add("text-danger");
    }
  }

  function interroga() {
    fetch("status.json", { headers: { "Accept": "application/json" } })
      .then(function (risposta) {
        if (!risposta.ok) {
          throw new Error("la sonda ha risposto " + risposta.status);
        }
        return risposta.json();
      })
      .then(aggiorna)
      .catch(fallito);
  }

  interroga();
  setInterval(interroga, INTERVALLO_MS);
})();

// I contatori (coda, nodi, ultimo conferimento, stato scansione) si aggiornano ora
// via AJAX ogni pochi secondi dalla rotta di stato, senza ricaricare la pagina: il
// vecchio ricaricamento completo ogni trenta secondi non serve piu' e faceva perdere
// la scheda aperta e la posizione di scorrimento.
// Le richieste di conferma sono gestite da snap-dialogs.js con AWN.
