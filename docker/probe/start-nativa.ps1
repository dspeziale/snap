# -----------------------------------------------------------------
# start-nativa.ps1 — avvia la SONDA sulla macchina, fuori dal contenitore
# Autore: Daniele Speziale
# Data creazione: 2026-09-10
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
<#
.SYNOPSIS
    Avvia la sonda direttamente su Windows, con la sola base dati in contenitore.

.DESCRIPTION
    PERCHE' ESISTE, con la misura che l'ha imposta.

    Su Docker Desktop i contenitori stanno dentro una macchina virtuale e il suo NAT
    risponde per ogni indirizzo. Misurato sulla stessa subnet, nello stesso momento:

        dal PC                ->    5 host attivi
        dentro il contenitore ->  256 host attivi su 256

    Una sonda in quelle condizioni non fa inventario: lo inventa. Su Windows la sonda
    va quindi eseguita sulla macchina, dove vede le interfacce vere; in contenitore
    resta la sola base dati, che di rete non ha bisogno.

    Lo script: verifica i presupposti, legge le credenziali da .env (mai a schermo),
    compone gli indirizzi di connessione e avvia `run.py`.

    IL TLS RESTA DAVANTI. Fuori dal contenitore la sonda non ha piu' il proxy del
    compose di esercizio, ed esporla direttamente significherebbe HTTP IN CHIARO
    sulla rete -- con la password della sonda dentro. Percio' qui la sonda ascolta
    in chiaro SOLO sul proprio loopback (5511) e davanti c'e' lo stesso nginx
    dell'esercizio, in contenitore, che termina il TLS sulla 5510:

        rete  --HTTPS-->  proxy-nativa (contenitore)  --loopback-->  sonda:5511

    Che un contenitore raggiunga un servizio legato al solo 127.0.0.1 dell'host non
    e' ovvio: e' stato misurato su questa installazione (Docker Desktop apre la
    connessione dal lato Windows, quindi per la sonda e' una connessione locale).

.PARAMETER Port
    Porta LOCALE della sonda, sul solo loopback, in chiaro. Predefinita 5511: dalla
    rete si passa dalla 5510 del proxy, in HTTPS. Dentro il range del progetto
    (5500-5600).

.PARAMETER SenzaProxy
    Avvia la sonda senza pretendere il proxy TLS davanti. L'interfaccia resta
    raggiungibile SOLO da 127.0.0.1: nulla in chiaro sulla rete, ma nulla
    raggiungibile dalla rete.

.PARAMETER PrimaPassword
    Avvio per la SOLA prima impostazione della password, da fare una volta.

    Perche' serve una modalita' a parte. Con il proxy TLS davanti il cookie di
    sessione si marca `Secure`, e un cookie Secure NON viene rimandato su HTTP: ne'
    dal browser ne' da nessun altro client. La prima password si sceglie invece sul
    loopback in chiaro (http://127.0.0.1:5511/primo-accesso), perche' il proxy non
    puo' distinguere chi sta alla postazione da chi arriva dalla LAN -- vede sempre
    l'indirizzo del gateway di Docker. Le due cose insieme non funzionano: senza
    cookie non c'e' sessione, senza sessione il token anti-CSRF viene rifiutato, e
    la pagina risponde "token scaduto" a ogni tentativo.

    Con questo interruttore il cookie NON e' marcato Secure, cosi' la prima
    impostazione si puo' fare. Serve una volta: dopo, si riavvia senza
    l'interruttore. Non si indebolisce la protezione anti-CSRF, che su quella pagina
    e' cio' che impedisce a un sito qualunque di impossessarsi della sonda.

.PARAMETER SoloVerifica
    Controlla i presupposti e non avvia nulla.

.EXAMPLE
    .\start-nativa.ps1
    .\start-nativa.ps1 -SoloVerifica
    .\start-nativa.ps1 -SenzaProxy
    .\start-nativa.ps1 -PrimaPassword      # una volta, per scegliere la password
#>
[CmdletBinding()]
param(
    [int]$Port = 5511,
    [switch]$SenzaProxy,
    [switch]$PrimaPassword,
    [switch]$SoloVerifica
)

$ErrorActionPreference = 'Stop'
$Qui = Split-Path -Parent $MyInvocation.MyCommand.Path
$Radice = Resolve-Path (Join-Path $Qui '..\..')

function Fermati([string]$Messaggio) {
    Write-Host ''
    Write-Host "  $Messaggio" -ForegroundColor Red
    Write-Host ''
    exit 1
}

function Avvisa([string]$Messaggio) {
    Write-Host "  $Messaggio" -ForegroundColor Yellow
}

function Bene([string]$Messaggio) {
    Write-Host "  $Messaggio" -ForegroundColor Green
}

Write-Host ''
Write-Host 'Sonda snap - avvio sulla macchina (fuori dal contenitore)' -ForegroundColor Cyan
Write-Host '---------------------------------------------------------' -ForegroundColor DarkGray

# --- 1. Le credenziali, dal file di configurazione ---------------------------
$fileConf = Join-Path $Qui '.env'
if (-not (Test-Path $fileConf)) {
    Fermati "manca ${fileConf}: copiarlo da .env.example e compilarlo"
}
$conf = @{}
foreach ($riga in Get-Content $fileConf) {
    if ($riga -match '^\s*([A-Z0-9_]+)\s*=\s*(.*)$') {
        $conf[$Matches[1]] = $Matches[2].Trim()
    }
}
foreach ($chiave in @('PROBE_POSTGRES_DB', 'PROBE_PG_APP_USER', 'PROBE_PG_APP_PASSWORD',
                      'PROBE_POSTGRES_USER', 'PROBE_POSTGRES_PASSWORD',
                      'SNAP_PROBE_SECRET_KEY')) {
    if (-not $conf.ContainsKey($chiave) -or -not $conf[$chiave]) {
        Fermati "da compilare in .env: $chiave"
    }
}
Bene 'configurazione letta da .env (le credenziali non vengono mostrate)'

# --- 2. Nessun'altra sonda sullo stesso archivio -----------------------------
# Due sonde si contendono le prenotazioni dei bersagli: il pool si blocca a vicenda e
# lo stato dei nodi diventa incoerente.
$inContenitore = docker ps --filter 'name=snap-probe' --filter 'status=running' `
    --format '{{.Names}}' 2>$null | Where-Object { $_ -eq 'snap-probe' }
if ($inContenitore) {
    Fermati @"
la sonda in contenitore e' in esecuzione: due sonde sullo stesso archivio si
  contendono i bersagli. Fermarla e lasciare solo la base dati:

    docker compose -f docker-compose.yml -f docker-compose.desktop.yml stop snap-probe proxy
    docker compose -f docker-compose.yml -f docker-compose.nativa.yml up -d postgres proxy-nativa
"@
}
Bene 'nessuna sonda in contenitore in esecuzione'

# --- 3. La base dati risponde sul loopback -----------------------------------
$db = Test-NetConnection -ComputerName '127.0.0.1' -Port 5532 -InformationLevel Quiet `
      -WarningAction SilentlyContinue
if (-not $db) {
    Fermati @"
la base dati della sonda non risponde su 127.0.0.1:5532. Avviarla con:

    docker compose -f docker-compose.yml -f docker-compose.nativa.yml up -d postgres proxy-nativa
"@
}
Bene 'base dati raggiungibile su 127.0.0.1:5532'

# --- 3-bis. Il proxy TLS davanti -----------------------------------------------
# Senza proxy l'interfaccia sarebbe HTTP in chiaro: si accetta solo sul loopback,
# mai sulla rete. Chi vuole davvero il solo loopback lo dichiara con -SenzaProxy.
$proxyVivo = docker ps --filter 'name=snap-probe-proxy-nativa' --filter 'status=running' `
    --format '{{.Names}}' 2>$null | Where-Object { $_ -eq 'snap-probe-proxy-nativa' }
$proxyEsercizio = docker ps --filter 'name=snap-probe-proxy' --filter 'status=running' `
    --format '{{.Names}}' 2>$null | Where-Object { $_ -eq 'snap-probe-proxy' }
if ($proxyEsercizio) {
    Fermati @"
e' in esecuzione il proxy di esercizio (snap-probe-proxy), che cerca la sonda nel
  proprio contenitore e occupa la 5510. Fermarlo e usare quello della variante nativa:

    docker compose -f docker-compose.yml -f docker-compose.desktop.yml stop proxy
    docker compose -f docker-compose.yml -f docker-compose.nativa.yml up -d proxy-nativa
"@
}
if ($SenzaProxy -or $PrimaPassword) {
    Avvisa @"
-SenzaProxy: nessuna terminazione TLS. L'interfaccia restera' raggiungibile SOLO da
  127.0.0.1 sulla macchina della sonda; dalla rete non sara' raggiungibile affatto.
  Non si espone nulla in chiaro, ma non si accede da altrove.
"@
} elseif (-not $proxyVivo) {
    Fermati @"
il proxy TLS non e' in esecuzione. Senza di lui l'interfaccia della sonda sarebbe
  HTTP IN CHIARO sulla rete -- password compresa -- quindi resta legata al solo
  loopback e da fuori non si raggiunge. Avviarlo con:

    docker compose -f docker-compose.yml -f docker-compose.nativa.yml up -d proxy-nativa

  Oppure, per avviare comunque la sonda solo sul loopback:  .\start-nativa.ps1 -SenzaProxy
"@
} else {
    Bene 'proxy TLS in esecuzione: interfaccia in HTTPS sulla 5510'
}

# --- 4. nmap, e i privilegi che gli servono ----------------------------------
$nmap = Get-Command nmap -ErrorAction SilentlyContinue
if (-not $nmap) {
    Fermati @"
nmap non e' nel PATH. Senza nmap la sonda non scansiona:
  https://nmap.org/download.html (installare anche Npcap)
"@
}
Bene ("nmap trovato: {0}" -f $nmap.Source)

$amministratore = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $amministratore) {
    Avvisa @"
questa finestra NON e' amministratore. Senza privilegi la scansione SYN (-sS) e il
  rilevamento del sistema operativo (-O) non sono disponibili: la sonda ricade sulla
  scansione per connessione, piu' lenta e senza sistema operativo. Lo dichiara nella
  propria pagina di stato. Per l'inventario completo: riaprire come amministratore.
"@
} else {
    Bene 'finestra amministratore: scansione SYN e rilevamento del sistema disponibili'
}

# --- 5. L'interprete ---------------------------------------------------------
$python = Join-Path $Radice '.venv\Scripts\python.exe'
if (-not (Test-Path $python)) {
    $comando = Get-Command python -ErrorAction SilentlyContinue
    if (-not $comando) { Fermati 'Python non trovato: ne' .venv ne' nel PATH' }
    $python = $comando.Source
}
Bene ("interprete: {0}" -f $python)

# --- 5-bis. L'ancora di fiducia verso il server -------------------------------
# PERCHE' SERVE QUI. In .env il percorso dell'ancora e' quello DENTRO il contenitore
# (/etc/snap/trust/...), perche' il compose monta ./trust li'. Fuori dal contenitore
# quel percorso non esiste: la sonda non trova l'ancora, ricade sul magazzino di
# certificati del sistema e -- se il server ha un certificato proprio, com'e' normale
# in sede -- rifiuta di parlargli. Il sintomo e' netto:
#
#   Server non raggiungibile: certificato del server non verificabile
#   [SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate
#
# Il rifiuto e' il comportamento giusto (su quel canale passano le chiavi della
# registrazione e l'inventario della rete): va corretto il percorso, non la verifica.
# Qui si traduce il percorso del contenitore nel file corrispondente sul disco.
$AncoraServer = ''
$dichiarata = $conf['SNAP_PROBE_SERVER_CA']
if ($dichiarata) {
    if (Test-Path -LiteralPath $dichiarata) {
        $AncoraServer = (Resolve-Path -LiteralPath $dichiarata).Path
    } else {
        $locale = Join-Path (Join-Path $Qui 'trust') (Split-Path $dichiarata -Leaf)
        if (Test-Path -LiteralPath $locale) {
            $AncoraServer = (Resolve-Path -LiteralPath $locale).Path
        }
    }
}
if ($AncoraServer) {
    Bene ("ancora di fiducia verso il server: {0}" -f (Split-Path $AncoraServer -Leaf))
} elseif ($dichiarata) {
    Avvisa @"
l'ancora di fiducia dichiarata in .env non si trova sul disco:
    $dichiarata
  Cercato anche in .\trust\. Senza ancora la sonda non riuscira' a parlare con un
  server che ha un certificato proprio: mettere il certificato del server (mai la
  chiave privata) in .\trust\ -- vedi .\trust\LEGGIMI.md.
"@
} else {
    Avvisa @"
nessuna ancora di fiducia dichiarata (SNAP_PROBE_SERVER_CA in .env). Va bene solo se
  il server ha un certificato firmato da una CA pubblica; con un certificato proprio
  la sonda rifiutera' di parlargli -- ed e' il comportamento giusto.
"@
}

if ($SoloVerifica) {
    Write-Host ''
    Write-Host '  Presupposti verificati. Nessun avvio (-SoloVerifica).' -ForegroundColor Cyan
    Write-Host ''
    exit 0
}

# --- 6. Avvio -----------------------------------------------------------------
# Gli indirizzi di connessione si compongono qui e restano nell'ambiente di QUESTO
# processo: non finiscono in un file, non compaiono a schermo.
$db_nome = $conf['PROBE_POSTGRES_DB']
$env:SNAP_PROBE_DATABASE_URL =
    "postgresql+psycopg://$($conf['PROBE_PG_APP_USER']):$($conf['PROBE_PG_APP_PASSWORD'])@127.0.0.1:5532/$db_nome"
$env:SNAP_PROBE_OWNER_DATABASE_URL =
    "postgresql+psycopg://$($conf['PROBE_POSTGRES_USER']):$($conf['PROBE_POSTGRES_PASSWORD'])@127.0.0.1:5532/$db_nome"
$env:SNAP_PROBE_SECRET_KEY = $conf['SNAP_PROBE_SECRET_KEY']
# Il percorso sul disco, non quello del contenitore: vedi il controllo 5-bis.
if ($AncoraServer) { $env:SNAP_PROBE_SERVER_CA = $AncoraServer }
$env:PYTHONUNBUFFERED = '1'
# Dietro il proxy la sonda deve leggere l'indirizzo del client dalle intestazioni
# X-Forwarded-*, che nginx SCRIVE con il vero interlocutore TCP (vedi nginx.conf).
# Senza proxy le intestazioni non ci sono e vale l'indirizzo della connessione: in
# entrambi i casi una richiesta diretta al loopback risulta locale, quindi la prima
# impostazione della password dalla macchina continua a funzionare.
$env:SNAP_PROBE_BEHIND_PROXY = $(if ($SenzaProxy) { '0' } else { '1' })
# IL COOKIE DI SESSIONE solo su HTTPS quando c'e' il TLS davanti -- con una
# eccezione dichiarata.
#
# Un cookie Secure non viene rimandato su HTTP: ne' dal browser ne' da altri client.
# Sul canale che conta (browser -> proxy) e' giusto marcarlo, perche' altrimenti una
# richiesta verso la 5512 in chiaro -- quella del solo rimando a HTTPS -- porterebbe
# il cookie sulla rete. Ma la PRIMA impostazione della password si fa sul loopback in
# chiaro, e la' un cookie Secure impedisce perfino di cominciare: senza cookie non
# c'e' sessione, senza sessione il token anti-CSRF viene rifiutato, e la pagina
# risponde "token scaduto" a ogni tentativo. Da qui -PrimaPassword: una volta, per
# scegliere la password, poi si riavvia senza.
$env:SNAP_PROBE_COOKIE_SECURE =
    $(if ($SenzaProxy -or $PrimaPassword) { '0' } else { '1' })

# L'INTERFACCIA DI USCITA DELLE SCANSIONI, se dichiarata in .env. Su una macchina con
# piu' interfacce nmap sceglie dalla tabella di instradamento, e la tabella puo'
# essere sbagliata: misurato su questa installazione, la rotta predefinita migliore
# era quella di un adattatore Wi-Fi SPENTO (metrica 40) invece della LAN attiva
# (metrica 55). Dichiararla toglie la scelta a nmap. Vedi la nota su RE_INTERFACCIA
# in probe/snapprobe/scanner.py. Vuoto = come decide il sistema.
foreach ($chiave in @('SNAP_PROBE_SCAN_INTERFACE', 'SNAP_PROBE_SCAN_SOURCE_IP')) {
    if ($conf.ContainsKey($chiave) -and $conf[$chiave]) {
        Set-Item -Path "Env:$chiave" -Value $conf[$chiave]
        Bene ("{0} = {1}" -f $chiave, $conf[$chiave])
    }
}

# Gli indirizzi da cui l'interfaccia risultera' raggiungibile, per non farli cercare.
$suRete = @()
if (-not $SenzaProxy) {
    $suRete = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
        Select-Object -ExpandProperty IPAddress | Sort-Object -Unique
}

Write-Host ''
if ($SenzaProxy) {
    Write-Host ("  Interfaccia:  http://127.0.0.1:{0}   (solo da questa macchina)" -f $Port) -ForegroundColor Cyan
} else {
    Write-Host ("  Interfaccia:  https://127.0.0.1:5510   (proxy TLS -> loopback {0})" -f $Port) -ForegroundColor Cyan
    foreach ($indirizzo in $suRete) {
        Write-Host ("                https://{0}:5510" -f $indirizzo) -ForegroundColor Cyan
    }
    Write-Host '  Prima password: riavviare con -PrimaPassword, poi' -ForegroundColor DarkGray
    Write-Host '                  http://127.0.0.1:5511/primo-accesso da QUESTA macchina' -ForegroundColor DarkGray
}
Write-Host '  Archivio:     127.0.0.1:5532 (in contenitore)' -ForegroundColor DarkGray
if ($PrimaPassword) {
    Write-Host ''
    Write-Host ("  MODALITA' PRIMA PASSWORD: aprire http://127.0.0.1:{0}/primo-accesso" -f $Port) -ForegroundColor Yellow
    Write-Host '  da QUESTA macchina, scegliere la password, poi fermare (Ctrl+C) e' -ForegroundColor Yellow
    Write-Host '  riavviare senza -PrimaPassword.' -ForegroundColor Yellow
}
Write-Host '  Ctrl+C per fermare' -ForegroundColor DarkGray
Write-Host ''

# DUE PROCESSI, NON UNO. L'interfaccia web e i trentadue lavoratori di scansione
# vivevano nello stesso interprete Python, che esegue un thread per volta (GIL):
# mentre la scansione lavorava, la pagina aspettava. Misurato sulla pagina di accesso,
# che non tocca nemmeno l'archivio:
#
#     scansioni attive   3-6 secondi, e oltre i 120 s del proxy sotto il carico di un
#                        browser (decine di richieste in parallelo) -> 504 Gateway Timeout
#     scansioni sospese  0,46-0,73 secondi
#
# Ora l'AGENTE (scansioni, controlli, conferimento) gira in un processo suo e
# l'INTERFACCIA in un altro. Condividono l'archivio PostgreSQL, che e' fatto per
# questo. Fermando questa finestra si fermano entrambi.
Push-Location (Join-Path $Radice 'probe')
try {
    $agente = Start-Process -FilePath $python -ArgumentList 'run.py', '--headless' `
                            -NoNewWindow -PassThru
    Write-Host ("  agente di raccolta avviato (processo {0})" -f $agente.Id) `
               -ForegroundColor DarkGray
    Write-Host ''
    try {
        # L'interfaccia resta in primo piano: e' quella che si guarda, ed e' la sua
        # uscita che si vuole vedere in questa finestra.
        & $python run.py --host '127.0.0.1' --port $Port --solo-interfaccia
    } finally {
        # L'agente e' un processo figlio ma non muore da se': se restasse in vita
        # dopo la chiusura di questa finestra, il prossimo avvio troverebbe DUE
        # agenti sullo stesso archivio -- che si contendono le prenotazioni dei
        # bersagli, esattamente il guasto che lo script verifica all'avvio.
        if ($agente -and -not $agente.HasExited) {
            Write-Host '  arresto dell''agente di raccolta...' -ForegroundColor DarkGray
            Stop-Process -Id $agente.Id -Force -ErrorAction SilentlyContinue
        }
    }
} finally {
    Pop-Location
}
