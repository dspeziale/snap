/*
 * snap server - Dialogo con l'utente tramite Awesome Notifications (AWN).
 *
 * Sostituisce le finestre native del browser: le richieste di conferma usano
 * notifier.confirm() e i messaggi di esito prodotti dal server diventano
 * notifiche. Gli avvisi restano presenti nel documento come alternativa in
 * assenza di JavaScript: se AWN e' disponibile vengono trasformati in notifiche
 * e rimossi dal flusso della pagina.
 *
 * remarks: Autore: Daniele Speziale - Data: 2026-08-26
 * copyright: (c) 2024-26 DS Consulting
 * license: MIT
 */
(function (global) {
  "use strict";

  var DURATE = { success: 5000, info: 6000, warning: 9000, danger: 12000 };

  var notifier = null;
  if (typeof AWN !== "undefined") {
    notifier = new AWN({
      position: "top-right",
      maxNotifications: 6,
      durations: {
        global: 6000,
        success: DURATE.success,
        info: DURATE.info,
        warning: DURATE.warning,
        alert: DURATE.danger
      },
      labels: {
        tip: "Suggerimento",
        info: "Informazione",
        success: "Operazione eseguita",
        warning: "Attenzione",
        alert: "Errore",
        async: "Operazione in corso",
        confirm: "Confermare l'operazione",
        confirmOk: "Conferma",
        confirmCancel: "Annulla"
      },
      icons: { enabled: true }
    });
  }

  /* Corrispondenza fra le categorie di messaggio del server e i metodi AWN. */
  function notify(categoria, testo) {
    if (!notifier) {
      return false;
    }
    switch (categoria) {
      case "success":
        notifier.success(testo);
        break;
      case "warning":
        notifier.warning(testo);
        break;
      case "danger":
      case "error":
        notifier.alert(testo);
        break;
      default:
        notifier.info(testo);
    }
    return true;
  }

  /* Conferma di un'azione: risolve con true solo se l'utente conferma. */
  function confirm(messaggio, opzioni) {
    var impostazioni = opzioni || {};
    return new Promise(function (resolve) {
      if (!notifier) {
        // Ricaduta sulla finestra nativa se la libreria non e' disponibile.
        resolve(global.confirm(messaggio));
        return;
      }
      notifier.confirm(
        messaggio,
        function () { resolve(true); },
        function () { resolve(false); },
        {
          labels: {
            confirm: impostazioni.titolo || "Confermare l'operazione",
            confirmOk: impostazioni.conferma || "Conferma",
            confirmCancel: impostazioni.annulla || "Annulla"
          },
          classes: {
            confirmOkBtn: impostazioni.distruttiva
              ? "awn-btn awn-btn-danger"
              : "awn-btn awn-btn-primary"
          }
        }
      );
    });
  }

  /* Messaggi di esito emessi dal server: diventano notifiche. */
  function mostraMessaggiDelServer() {
    var contenitore = document.querySelector("[data-snap-flash]");
    if (!contenitore || !notifier) {
      return;
    }
    contenitore.querySelectorAll("[data-flash-category]").forEach(function (avviso) {
      var testo = (avviso.getAttribute("data-flash-message") || avviso.textContent || "").trim();
      if (testo) {
        notify(avviso.getAttribute("data-flash-category"), testo);
      }
      avviso.remove();
    });
  }

  /* Conferme sui moduli: l'attributo data-confirm descrive l'operazione.
     Un modulo con piu' azioni (attivare, disattivare) ha bisogno di conferme
     diverse: se il pulsante premuto ne dichiara una propria, prevale su quella
     del modulo. Attenzione: l'invio per programma piu' sotto NON porta con se'
     il pulsante, quindi cio' che il pulsante deve comunicare al server va scritto
     in un campo nascosto, non nel suo attributo name. */
  function collegaConferme() {
    document.addEventListener(
      "submit",
      function (evento) {
        var modulo = evento.target;
        var origine = evento.submitter || null;
        function attributo(nome) {
          if (origine && origine.hasAttribute(nome)) {
            return origine.getAttribute(nome);
          }
          return modulo.getAttribute(nome);
        }
        var messaggio = attributo("data-confirm");
        if (!messaggio || modulo.dataset.snapConfermato === "1") {
          return;
        }
        evento.preventDefault();
        confirm(messaggio, {
          titolo: attributo("data-confirm-title") || undefined,
          conferma: attributo("data-confirm-ok") || undefined,
          distruttiva: (origine && origine.hasAttribute("data-confirm-destructive")) ||
            modulo.hasAttribute("data-confirm-destructive")
        }).then(function (confermato) {
          if (confermato) {
            // Si evita il secondo passaggio dal gestore, poi si invia il modulo.
            modulo.dataset.snapConfermato = "1";
            modulo.submit();
          }
        });
      },
      true
    );
  }

  /* Conferme su collegamenti che avviano un'azione. */
  function collegaConfermeSuCollegamenti() {
    document.addEventListener("click", function (evento) {
      var collegamento = evento.target.closest("a[data-confirm]");
      if (!collegamento) {
        return;
      }
      evento.preventDefault();
      confirm(collegamento.getAttribute("data-confirm"), {
        distruttiva: collegamento.hasAttribute("data-confirm-destructive")
      }).then(function (confermato) {
        if (confermato) {
          global.location.href = collegamento.href;
        }
      });
    });
  }

  global.snapDialogs = {
    notifier: notifier,
    notify: notify,
    confirm: confirm,
    success: function (testo) { return notify("success", testo); },
    warning: function (testo) { return notify("warning", testo); },
    error: function (testo) { return notify("danger", testo); },
    info: function (testo) { return notify("info", testo); }
  };

  document.addEventListener("DOMContentLoaded", function () {
    mostraMessaggiDelServer();
    collegaConferme();
    collegaConfermeSuCollegamenti();
  });
})(window);
