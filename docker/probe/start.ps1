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

function Get-IndirizzoMacchina {
    <# IPv4 dell'interfaccia che porta al gateway: e' l'indirizzo con cui gli altri
       vedono questa macchina. Stringa vuota se non si riesce a determinarlo. #>
    $ErrorActionPreference = 'SilentlyContinue'
    $configurazione = Get-NetIPConfiguration |
        Where-Object { $_.IPv4DefaultGateway -and $_.IPv4Address } |
        Select-Object -First 1
    if ($configurazione) { return $configurazione.IPv4Address[0].IPAddress }
    return ''
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
#
# E c'e' di piu' di un limite di scansione: su Docker Desktop i container non stanno
# sull'host ma in una macchina virtuale, quindi con la rete host le porte 5510/5512
# vengono legate DENTRO quella macchina e da Windows non risulta nulla in ascolto (il
# browser dice ERR_CONNECTION_REFUSED anche con i container "healthy"). Per questo
# qui si passa alla variante che PUBBLICA le porte.
$sistema = Get-TipoMotoreDocker
$desktop = $false
if ($sistema -and $sistema -ne 'linux') {
    $desktop = $true
    Write-Host ''
    Write-Host ("Il motore Docker non e'' Linux ({0}): la rete host non funziona come" -f $sistema) -ForegroundColor Yellow
    Write-Host 'in esercizio e la sonda NON vedra'' la rete del cliente.' -ForegroundColor Yellow
    Write-Host 'Va bene per provare l''interfaccia; per scansionare davvero serve Linux.' -ForegroundColor Yellow
}
elseif ($env:OS -eq 'Windows_NT') {
    # Motore Linux ma host Windows: e' Docker Desktop con WSL2, stesso limite.
    $desktop = $true
    Write-Host ''
    Write-Host 'Docker Desktop su Windows: la rete host passa da WSL2 e la sonda vede la' -ForegroundColor Yellow
    Write-Host 'rete della macchina virtuale, non quella del cliente. In esercizio: Linux.' -ForegroundColor Yellow
}

if ($desktop) {
    Write-Host ''
    Write-Host 'Si usa docker-compose.desktop.yml: le porte 5510/5512 vengono PUBBLICATE,' -ForegroundColor Cyan
    Write-Host 'altrimenti con la rete host resterebbero dentro la macchina virtuale e' -ForegroundColor Cyan
    Write-Host 'l''interfaccia risulterebbe irraggiungibile da Windows.' -ForegroundColor Cyan
}

if (-not (Test-Path '.env')) {
    Fermati 'manca il file .env. Copiarlo e compilarlo:  cp .env.example .env'
}
if (-not (Select-String -Path '.env' -Pattern '^\s*SNAP_PROBE_SECRET_KEY\s*=\s*\S+' -Quiet)) {
    Fermati ("da compilare in .env: SNAP_PROBE_SECRET_KEY`n  python -c ""import secrets; print(secrets.token_urlsafe(48))""")
}

# Le password della base dati: senza, il contenitore non parte affatto (sono
# dichiarate obbligatorie nel compose). Meglio dirlo qui che leggere un errore di
# variabile mancante in mezzo all'avvio.
$mancanti = @()
foreach ($chiave in @('PROBE_POSTGRES_PASSWORD', 'PROBE_PG_APP_PASSWORD')) {
    if (-not (Select-String -Path '.env' -Pattern ("^\s*{0}\s*=\s*\S+" -f $chiave) -Quiet)) {
        $mancanti += $chiave
    }
}
if ($mancanti.Count -gt 0) {
    Write-Host ''
    Write-Host ('Da compilare in .env: ' + ($mancanti -join ', ')) -ForegroundColor Yellow
    Write-Host '  python -c "import secrets; print(secrets.token_urlsafe(32))"' -ForegroundColor Cyan
    Write-Host 'Due password DIVERSE: proprietario della base dati e utente applicativo' -ForegroundColor DarkGray
    Write-Host 'sono due livelli di accesso distinti.' -ForegroundColor DarkGray
    Fermati 'configurazione della base dati incompleta.'
}

if (-not ((Test-Path 'certs\probe.crt') -and (Test-Path 'certs\probe.key'))) {
    Write-Host ''
    Write-Host 'Manca il certificato in .\certs\ (probe.crt e probe.key).' -ForegroundColor Yellow
    Write-Host '  mkdir certs' -ForegroundColor Cyan
    Write-Host '  openssl req -x509 -newkey rsa:4096 -sha256 -days 730 -nodes `' -ForegroundColor Cyan
    Write-Host '    -keyout certs/probe.key -out certs/probe.crt `' -ForegroundColor Cyan
    Write-Host '    -subj "/CN=sonda.example.local" `' -ForegroundColor Cyan
    Write-Host '    -addext "subjectAltName=DNS:sonda.example.local,IP:127.0.0.1,IP:<ip-macchina>"' -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'Elencare nel SAN anche l''IP con cui si aprira'' l''interfaccia: un' -ForegroundColor DarkGray
    Write-Host 'certificato valido solo per 127.0.0.1 fa avvisare il browser sull''IP.' -ForegroundColor DarkGray
    Fermati 'certificato assente.'
}

$argomenti = @('compose')
if ($desktop) { $argomenti += @('-f', 'docker-compose.yml', '-f', 'docker-compose.desktop.yml') }
$argomenti += @('up', '-d')
if (-not $NoBuild) { $argomenti += '--build' }
Write-Host ("docker {0}" -f ($argomenti -join ' ')) -ForegroundColor DarkGray
& docker @argomenti
if ($LASTEXITCODE -ne 0) { Fermati 'avvio non riuscito: vedere l''esito qui sopra.' }

Write-Host ''
& docker compose ps

$indirizzo = Get-IndirizzoMacchina

Write-Host ''
Write-Host 'Prima apertura, per scegliere la password:' -ForegroundColor Green
if ($indirizzo) {
    Write-Host ("  https://{0}:5510/primo-accesso" -f $indirizzo) -ForegroundColor Green
}
Write-Host '  https://127.0.0.1:5510/primo-accesso' -ForegroundColor Green
Write-Host ''
if ($desktop) {
    Write-Host 'In questa variante di prova la prima impostazione e'' ammessa dalle reti' -ForegroundColor DarkGray
    Write-Host 'private (dietro il NAT di Docker il chiamante non e'' il loopback).' -ForegroundColor DarkGray
}
else {
    Write-Host 'Dalla rete la PRIMA impostazione e'' rifiutata (due barriere: il controllo' -ForegroundColor DarkGray
    Write-Host 'della sonda e una regola nel proxy): cosi'' la sonda appartiene a chi l''ha' -ForegroundColor DarkGray
    Write-Host 'installata. Per configurarla puntando l''IP, aggiungere la propria' -ForegroundColor DarkGray
    Write-Host 'postazione in allow-primo-accesso.conf e in SNAP_PROBE_FIRST_ACCESS_FROM.' -ForegroundColor DarkGray
}
Write-Host ''
Write-Host 'Il certificato vale per gli indirizzi elencati nel suo campo SAN: aprendo' -ForegroundColor DarkGray
Write-Host 'un indirizzo non elencato il browser avvisa (avviso di nome, non di cifratura).' -ForegroundColor DarkGray
Write-Host ''
Write-Host 'Poi si incolla il pacchetto SNAP1-... generato dalla console del server.' -ForegroundColor DarkGray
Write-Host ''
Write-Host 'Log:      docker compose logs -f' -ForegroundColor DarkGray
Write-Host 'Arresto:  .\stop.ps1' -ForegroundColor DarkGray

if ($Logs) {
    Write-Host ''
    & docker compose logs -f
}
