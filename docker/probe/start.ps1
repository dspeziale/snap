# -----------------------------------------------------------------
# start.ps1 — avvia i container della SONDA snap
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
# ATTENZIONE: la sonda usa la RETE HOST perche' deve vedere la rete del cliente. Su
# Docker Desktop (Windows/Mac) la rete host e' limitata e la sonda NON vedrebbe la
# LAN: scoprirebbe se stessa e nient'altro. In esercizio la sonda va su Linux.

param(
    [switch]$NoBuild,
    [switch]$Logs
)

# NON si usa 'Stop': docker scrive su stderr anche quando riesce e, con 'Stop',
# PowerShell 5.1 trasforma lo stderr di un comando NATIVO in un errore terminante
# (NativeCommandError). Gli esiti si controllano sul codice di uscita.
$ErrorActionPreference = 'Continue'
Set-Location -Path $PSScriptRoot

function Fermati($Messaggio) {
    Write-Host ''
    Write-Host "ERRORE: $Messaggio" -ForegroundColor Red
    Write-Host ''
    exit 1
}

function Test-DaemonDocker {
    $ErrorActionPreference = 'SilentlyContinue'
    $null = docker info --format '{{.ServerVersion}}' 2>&1
    return ($LASTEXITCODE -eq 0)
}

function Get-TipoMotoreDocker {
    <# 'linux', 'windows' oppure '' se non si riesce a saperlo. #>
    $ErrorActionPreference = 'SilentlyContinue'
    $tipo = docker info --format '{{.OSType}}' 2>&1
    if ($LASTEXITCODE -ne 0) { return '' }
    return ("$tipo").Trim()
}

Write-Host ''
Write-Host '=== snap probe: avvio dei container ===' -ForegroundColor Cyan

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Fermati 'docker non e'' installato (o non e'' nel PATH).'
}
if (-not (Test-DaemonDocker)) {
    Fermati 'il daemon Docker non risponde: avviare Docker Desktop (o il servizio docker) e riprovare.'
}

# La rete host: il limite va detto PRIMA, non scoperto dopo con un inventario vuoto.
$sistema = Get-TipoMotoreDocker
if ($sistema -and $sistema -ne 'linux') {
    Write-Host ''
    Write-Host ("Il motore Docker non e'' Linux ({0}): la rete host non funziona come" -f $sistema) -ForegroundColor Yellow
    Write-Host 'in esercizio e la sonda NON vedra'' la rete del cliente.' -ForegroundColor Yellow
    Write-Host 'Va bene per provare l''interfaccia; per scansionare davvero serve Linux.' -ForegroundColor Yellow
}
elseif ($env:OS -eq 'Windows_NT') {
    # Motore Linux ma host Windows: e' Docker Desktop con WSL2, stesso limite.
    Write-Host ''
    Write-Host 'Docker Desktop su Windows: la rete host passa da WSL2 e la sonda vede la' -ForegroundColor Yellow
    Write-Host 'rete della macchina virtuale, non quella del cliente. In esercizio: Linux.' -ForegroundColor Yellow
}

if (-not (Test-Path '.env')) {
    Fermati 'manca il file .env. Copiarlo e compilarlo:  cp .env.example .env'
}
if (-not (Select-String -Path '.env' -Pattern '^\s*SNAP_PROBE_SECRET_KEY\s*=\s*\S+' -Quiet)) {
    Fermati ("da compilare in .env: SNAP_PROBE_SECRET_KEY`n  python -c ""import secrets; print(secrets.token_urlsafe(48))""")
}

if (-not ((Test-Path 'certs\probe.crt') -and (Test-Path 'certs\probe.key'))) {
    Write-Host ''
    Write-Host 'Manca il certificato in .\certs\ (probe.crt e probe.key).' -ForegroundColor Yellow
    Write-Host '  mkdir certs' -ForegroundColor Cyan
    Write-Host '  openssl req -x509 -newkey rsa:4096 -sha256 -days 730 -nodes `' -ForegroundColor Cyan
    Write-Host '    -keyout certs/probe.key -out certs/probe.crt `' -ForegroundColor Cyan
    Write-Host '    -subj "/CN=sonda.example.local" `' -ForegroundColor Cyan
    Write-Host '    -addext "subjectAltName=DNS:sonda.example.local,IP:127.0.0.1"' -ForegroundColor Cyan
    Fermati 'certificato assente.'
}

$argomenti = @('compose', 'up', '-d')
if (-not $NoBuild) { $argomenti += '--build' }
Write-Host ("docker {0}" -f ($argomenti -join ' ')) -ForegroundColor DarkGray
& docker @argomenti
if ($LASTEXITCODE -ne 0) { Fermati 'avvio non riuscito: vedere l''esito qui sopra.' }

Write-Host ''
& docker compose ps

Write-Host ''
Write-Host 'Prima apertura: DALLA MACCHINA della sonda, aprire' -ForegroundColor Green
Write-Host '  https://127.0.0.1:5510/primo-accesso' -ForegroundColor Green
Write-Host 'per scegliere la password. Dalla rete la PRIMA impostazione e'' rifiutata' -ForegroundColor DarkGray
Write-Host '(due barriere: il controllo della sonda e una regola nel proxy): cosi'' la' -ForegroundColor DarkGray
Write-Host 'sonda appartiene a chi l''ha installata.' -ForegroundColor DarkGray
Write-Host ''
Write-Host 'Poi si incolla il pacchetto SNAP1-... generato dalla console del server.' -ForegroundColor DarkGray
Write-Host ''
Write-Host 'Log:      docker compose logs -f' -ForegroundColor DarkGray
Write-Host 'Arresto:  .\stop.ps1' -ForegroundColor DarkGray

if ($Logs) {
    Write-Host ''
    & docker compose logs -f
}
