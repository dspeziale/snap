# -----------------------------------------------------------------
# start.ps1 — avvia i container del SERVER snap (console + SIEM + PostgreSQL)
# Autore: Daniele Speziale
# Data creazione: 2026-09-09
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
# Uso:
#   .\start.ps1                 avvia (ricostruendo l'immagine se il codice e' cambiato)
#   .\start.ps1 -NoBuild        avvia senza ricostruire
#   .\start.ps1 -Logs           avvia e resta in ascolto sui log
#
# Lo script controlla PRIMA le condizioni che fanno fallire un avvio in modo
# incomprensibile (daemon spento, .env mancante, certificato assente): un messaggio
# chiaro adesso vale piu' di un errore di compose fra dieci righe di YAML.

param(
    [switch]$NoBuild,
    [switch]$Logs
)

# NON si usa 'Stop': docker scrive su stderr anche quando fa il proprio lavoro
# (l'avanzamento della build) e, con 'Stop', PowerShell 5.1 trasforma ogni riga di
# stderr di un comando NATIVO in un errore terminante (NativeCommandError). Lo script
# morirebbe con una traccia illeggibile proprio dove deve dare il suo messaggio. Gli
# esiti si controllano dove contano, sul codice di uscita ($LASTEXITCODE).
$ErrorActionPreference = 'Continue'

# Si lavora nella cartella dello script: il compose e i percorsi relativi
# (./certs, ./nginx.conf) sono riferiti a questa.
Set-Location -Path $PSScriptRoot

function Fermati($Messaggio) {
    Write-Host ''
    Write-Host "ERRORE: $Messaggio" -ForegroundColor Red
    Write-Host ''
    exit 1
}

function Test-DaemonDocker {
    <# Il daemon risponde? Interessa SOLO il codice di uscita: lo stderro del comando
       si scarta, e la preferenza locale alla funzione evita che diventi un errore. #>
    $ErrorActionPreference = 'SilentlyContinue'
    $null = docker info --format '{{.ServerVersion}}' 2>&1
    return ($LASTEXITCODE -eq 0)
}

Write-Host ''
Write-Host '=== snap server: avvio dei container ===' -ForegroundColor Cyan

# 1. Docker c'e' ed e' in ascolto?
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Fermati 'docker non e'' installato (o non e'' nel PATH).'
}
if (-not (Test-DaemonDocker)) {
    Fermati 'il daemon Docker non risponde: avviare Docker Desktop (o il servizio docker) e riprovare.'
}

# 2. La configurazione: senza .env il compose si fermerebbe sui segreti obbligatori.
if (-not (Test-Path '.env')) {
    Fermati 'manca il file .env. Copiarlo e compilarlo:  cp .env.example .env'
}
$mancanti = @()
foreach ($chiave in @('SNAP_SERVER_SECRET_KEY', 'POSTGRES_PASSWORD', 'SNAP_PG_APP_PASSWORD')) {
    # Vuoto o assente: il compose li dichiara obbligatori, meglio dirlo qui.
    $riga = Select-String -Path '.env' -Pattern "^\s*$chiave\s*=\s*\S+" -Quiet
    if (-not $riga) { $mancanti += $chiave }
}
if ($mancanti.Count -gt 0) {
    Fermati ("da compilare in .env: {0}`n  Generare i segreti con:`n  python -c ""import secrets; print(secrets.token_urlsafe(48))""" -f ($mancanti -join ', '))
}

# 3. Il certificato TLS: si monta, non sta nell'immagine.
if (-not ((Test-Path 'certs\server.crt') -and (Test-Path 'certs\server.key'))) {
    Write-Host ''
    Write-Host 'Manca il certificato in .\certs\ (server.crt e server.key).' -ForegroundColor Yellow
    Write-Host 'Per una prova interna se ne genera uno autofirmato (in esercizio usare' -ForegroundColor DarkGray
    Write-Host 'un certificato della propria CA, altrimenti il browser avvisa ogni volta):' -ForegroundColor DarkGray
    Write-Host '  mkdir certs' -ForegroundColor Cyan
    Write-Host '  openssl req -x509 -newkey rsa:4096 -sha256 -days 730 -nodes `' -ForegroundColor Cyan
    Write-Host '    -keyout certs/server.key -out certs/server.crt `' -ForegroundColor Cyan
    Write-Host '    -subj "/CN=snap.example.local" `' -ForegroundColor Cyan
    Write-Host '    -addext "subjectAltName=DNS:snap.example.local,IP:10.20.10.42"' -ForegroundColor Cyan
    Fermati 'certificato assente.'
}

# 4. Avvio.
$argomenti = @('compose', 'up', '-d')
if (-not $NoBuild) { $argomenti += '--build' }
Write-Host ("docker {0}" -f ($argomenti -join ' ')) -ForegroundColor DarkGray
& docker @argomenti
if ($LASTEXITCODE -ne 0) { Fermati 'avvio non riuscito: vedere l''esito qui sopra.' }

Write-Host ''
& docker compose ps

# La porta pubblicata puo' essere stata cambiata in .env: si legge da la', non si
# indovina.
$porta = (Select-String -Path '.env' -Pattern '^\s*SNAP_HTTPS_PORT\s*=\s*(\d+)' |
          Select-Object -First 1).Matches.Groups[1].Value
if (-not $porta) { $porta = '5500' }
Write-Host ''
Write-Host ("Console: https://<indirizzo-del-server>:{0}/" -f $porta) -ForegroundColor Green
Write-Host 'Ricordarsi, nella console: Amministrazione > Impostazioni Sistema >' -ForegroundColor DarkGray
Write-Host 'Indirizzo pubblico del server, con https:// (entra nei pacchetti delle sonde,' -ForegroundColor DarkGray
Write-Host 'nelle email ai nuovi utenti e nelle copertine dei report).' -ForegroundColor DarkGray
Write-Host ''
Write-Host 'Log:      docker compose logs -f' -ForegroundColor DarkGray
Write-Host 'Arresto:  .\stop.ps1' -ForegroundColor DarkGray

if ($Logs) {
    Write-Host ''
    & docker compose logs -f
}
