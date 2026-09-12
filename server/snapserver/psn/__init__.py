# -----------------------------------------------------------------
# psn/__init__.py — sottosistema PSN: il piano di indirizzamento, gestito
# Autore: Daniele Speziale
# Data creazione: 2026-09-11
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
"""
snap server - PSN: il piano di indirizzamento come sistema, non come foglio.

CHE COS'E'. Il piano di indirizzamento del Polo Strategico Nazionale vive in un
foglio Excel di settantanove schede: un'anagrafica di subnet, un foglio per ogni
subnet con UNA RIGA PER INDIRIZZO, l'elenco dei tenant, i database, i servizi
pubblicati (URL -> VIP -> backend) e la convenzione dei nomi. E' un documento
corretto e leggibile, e proprio per questo non risponde alle domande che contano:

    quale e' il prossimo indirizzo libero nella subnet dei proxy?
    questo hostname esiste due volte?
    quali nomi non rispettano la convenzione?
    che cosa sta dietro l'URL pubblico che non risponde?
    che cosa e' cambiato dalla versione precedente del piano?

Un foglio di calcolo non le sa rispondere perche' non conosce le relazioni fra le
sue schede: le tiene vicine, non collegate. Questo modulo le rende esplicite.

SEPARATO, E SI DEVE POTER BUTTARE. Il sottosistema non tocca nulla del prodotto:

  * ARCHIVIO PROPRIO, un database distinto (non uno schema dentro quello del
    prodotto): si elimina con un `DROP DATABASE` senza sfiorare l'inventario;
  * NESSUNA chiave esterna verso le tabelle del prodotto, nessuna scrittura nelle
    sue tabelle, nessuna modifica al suo schema;
  * un blueprint proprio (`/psn`) e una voce di menu propria;
  * i modelli in `templates/psn/`.

Per rimuoverlo del tutto: cancellare `snapserver/psn/`, `templates/psn/`, il blocco
PSN nella barra laterale, la registrazione del blueprint in `create_app` e il
database. Le istruzioni stanno in `docs/15_PSN.md`.

NESSUNA DIPENDENZA NUOVA. Il foglio si legge con la sola libreria standard: un
`.xlsx` e' un archivio zip di XML, e `zipfile` piu' `xml.etree` bastano (vedi
`xlsx.py`). La regola di progetto vieta dipendenze non concordate, e per leggere
cinque forme di intestazione non serve un lettore generico.

remarks: Autore: Daniele Speziale - Data: 2026-09-11
copyright: (c) 2024-26 DS Consulting
license: MIT
"""

from __future__ import annotations

from .views import bp

__all__ = ["bp"]
