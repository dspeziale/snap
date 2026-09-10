# -----------------------------------------------------------------
# stop.ps1 — arresta i container del SERVER snap
# Autore: Daniele Speziale
# Data creazione: 2026-09-09
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
# Uso:
#   .\stop.ps1                arresta e rimuove i container. I DATI RESTANO.
#   .\stop.ps1 -KeepRunning   solo ferma i container, senza rimuoverli (riavvio rapido)
#   .\stop.ps1 -RemoveData    rimuove ANCHE i volumi: cancella la base dati. Chiede conferma.
#
# Per difetto i volumi NON si toccano: `docker compose down -v` cancellerebbe
# l'archivio, i report e la base dati PostgreSQL. Un arresto non deve poter
# distruggere i dati per distrazione, quindi la cancellazione e' un'opzione esplicita
# e con conferma scritta.

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
Write-Host '=== snap server: arresto dei container ===' -ForegroundColor Cyan

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host 'ERRORE: docker non e'' installato (o non e'' nel PATH).' -ForegroundColor Red
    exit 1
}
if (-not (Test-DaemonDocker)) {
    Write-Host 'ERRORE: il daemon Docker non risponde: niente da arrestare.' -ForegroundColor Red
    exit 1
}

if ($KeepRunning) {
    # `stop` lascia i container in piedi ma fermi: il riavvio e' immediato.
    & docker compose stop
    Write-Host ''
    Write-Host 'Container fermati (non rimossi). Riavvio: docker compose start' -ForegroundColor Green
    exit 0
}

if ($RemoveData) {
    Write-Host ''
    Write-Host 'ATTENZIONE: con -RemoveData vengono cancellati anche i VOLUMI:' -ForegroundColor Red
    Write-Host '  - la base dati PostgreSQL' -ForegroundColor Red
    Write-Host '  - l''archivio del server, i report e le copie di sicurezza' -ForegroundColor Red
    Write-Host 'L''operazione NON e'' reversibile.' -ForegroundColor Red
    Write-Host ''
    $conferma = Read-Host 'Scrivere CANCELLA per procedere'
    if ($conferma -ne 'CANCELLA') {
        Write-Host 'Annullato: nessun dato e'' stato cancellato.' -ForegroundColor Yellow
        exit 0
    }
    & docker compose down --volumes
    Write-Host ''
    Write-Host 'Container e volumi rimossi.' -ForegroundColor Yellow
    exit $LASTEXITCODE
}

& docker compose down
Write-Host ''
Write-Host 'Container arrestati e rimossi. I dati restano nei volumi.' -ForegroundColor Green
Write-Host 'Riavvio: .\start.ps1' -ForegroundColor DarkGray
