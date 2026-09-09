# -----------------------------------------------------------------
# stop.ps1 — arresta i container della SONDA snap
# Autore: Daniele Speziale
# Data creazione: 2026-09-09
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
# Uso:
#   .\stop.ps1                arresta e rimuove i container. I DATI RESTANO.
#   .\stop.ps1 -KeepRunning   solo ferma i container, senza rimuoverli
#   .\stop.ps1 -RemoveData    rimuove ANCHE il volume: cancella l'archivio locale.
#
# Il volume della sonda contiene la REGISTRAZIONE al server (chiavi di sessione del
# canale cifrato) e la coda dei conferimenti non ancora spediti. Cancellarlo significa
# dover registrare di nuovo la sonda dalla console e perdere la coda: per questo la
# cancellazione e' esplicita e con conferma scritta.

param(
    [switch]$KeepRunning,
    [switch]$RemoveData
)

# Vedi start.ps1: con 'Stop' lo stderr dei comandi nativi diventerebbe un errore
# terminante e lo script morirebbe invece di dare il proprio messaggio.
$ErrorActionPreference = 'Continue'
Set-Location -Path $PSScriptRoot

function Test-DaemonDocker {
    $ErrorActionPreference = 'SilentlyContinue'
    $null = docker info --format '{{.ServerVersion}}' 2>&1
    return ($LASTEXITCODE -eq 0)
}

Write-Host ''
Write-Host '=== snap probe: arresto dei container ===' -ForegroundColor Cyan

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host 'ERRORE: docker non e'' installato (o non e'' nel PATH).' -ForegroundColor Red
    exit 1
}
if (-not (Test-DaemonDocker)) {
    Write-Host 'ERRORE: il daemon Docker non risponde: niente da arrestare.' -ForegroundColor Red
    exit 1
}

if ($KeepRunning) {
    & docker compose stop
    Write-Host ''
    Write-Host 'Container fermati (non rimossi). Riavvio: docker compose start' -ForegroundColor Green
    Write-Host 'Con la sonda ferma la rete non viene scansionata: la copertura si ferma.' -ForegroundColor Yellow
    exit 0
}

if ($RemoveData) {
    Write-Host ''
    Write-Host 'ATTENZIONE: con -RemoveData vengono cancellati i volumi della sonda:' -ForegroundColor Red
    Write-Host '  - la REGISTRAZIONE al server (andra'' rifatta dalla console)' -ForegroundColor Red
    Write-Host '  - la coda dei conferimenti non ancora spediti' -ForegroundColor Red
    Write-Host '  - la password dell''interfaccia e le impostazioni locali' -ForegroundColor Red
    Write-Host '  - la base dati PostgreSQL, utenze comprese: alla ricreazione lo' -ForegroundColor Red
    Write-Host '    script di inizializzazione rigira e le password saranno quelle' -ForegroundColor Red
    Write-Host '    scritte in .env in quel momento' -ForegroundColor Red
    Write-Host 'L''operazione NON e'' reversibile.' -ForegroundColor Red
    Write-Host ''
    $conferma = Read-Host 'Scrivere CANCELLA per procedere'
    if ($conferma -ne 'CANCELLA') {
        Write-Host 'Annullato: nessun dato e'' stato cancellato.' -ForegroundColor Yellow
        exit 0
    }
    & docker compose down --volumes
    Write-Host ''
    Write-Host 'Container e volume rimossi: la sonda va registrata di nuovo.' -ForegroundColor Yellow
    exit $LASTEXITCODE
}

& docker compose down
Write-Host ''
Write-Host 'Container arrestati e rimossi. Registrazione e coda restano nel volume.' -ForegroundColor Green
Write-Host 'Riavvio: .\start.ps1' -ForegroundColor DarkGray
Write-Host 'Nota: a sonda ferma il server la vedra'' non raggiungibile e, se le' -ForegroundColor DarkGray
Write-Host 'scansioni erano attive, avvisera'' che la copertura si e'' fermata.' -ForegroundColor DarkGray
