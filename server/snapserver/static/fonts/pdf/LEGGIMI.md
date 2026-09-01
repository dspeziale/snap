# Caratteri incorporati nei report PDF

Questi file sono **risorse del prodotto**, non dipendenze: il generatore dei report li
incorpora nel PDF (come sottoinsiemi) per rispettare la convenzione tipografica del
progetto. Vanno versionati insieme al codice, perche' un'installazione senza rete -- il
caso di molti ambienti della pubblica amministrazione -- deve poter produrre i documenti
con la tipografia prevista.

| File | Uso nei report |
|---|---|
| `PTSansNarrow-Regular.ttf` | testatine, sottotitoli, etichette |
| `PTSansNarrow-Bold.ttf` | titolo del frontespizio, titoli di sezione, testate di tabella |
| `PTSans-Regular.ttf` | corpo del testo |
| `PTSans-Bold.ttf` | valori in evidenza |
| `PTMono-Regular.ttf` | indirizzi, porte, nomi di file |

## Provenienza e licenza

Famiglia **PT Sans / PT Sans Narrow / PT Mono** (ParaType), distribuita con licenza
**SIL Open Font License 1.1** — testo completo in `OFL-PT.txt`. Scaricati il 28/08/2026
dal repository ufficiale Google Fonts (`github.com/google/fonts`, cartelle
`ofl/ptsans`, `ofl/ptsansnarrow`, `ofl/ptmono`). La licenza consente l'incorporamento nei
documenti e la redistribuzione con il software.

## Se i file mancano

Il generatore non fallisce: ripiega su Helvetica e lo **dichiara nel pie' di pagina** di
ogni documento, e la pagina *Report e resoconti* mostra l'istruzione per completare
l'installazione. Un documento che finge una tipografia che non ha sarebbe una piccola
bugia stampata.

I nomi dei file sono attesi esattamente come in tabella: il registro sta in
`server/snapserver/reports/render_pdf.py` (`FONT_ATTESI`).

remarks: Autore: Daniele Speziale - Data: 2026-08-28
copyright: (c) 2024-26 DS Consulting — il presente file: licenza MIT; i caratteri: OFL 1.1
