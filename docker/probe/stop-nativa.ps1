# -----------------------------------------------------------------
# stop-nativa.ps1 — ferma la sonda avviata sulla macchina (fuori dal contenitore)
# Autore: Daniele Speziale
# Data creazione: 2026-09-12
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
#
# PERCHE' ESISTE. Con l'avvio senza finestra (start-nativa.ps1 -Nascosta) non c'e'
# piu' un Ctrl+C da premere: la sonda gira come un servizio, e un servizio si ferma
# con un comando, non chiudendo qualcosa.
#
# COSA FERMA, E IN CHE ORDINE. Prima l'AGENTE, poi l'interfaccia: fermando prima
# l'interfaccia si resterebbe con un agente che continua a prenotare bersagli e a
# scrivere nell'archivio senza che nessuno possa vedere che cosa sta facendo.
#
# Non tocca i contenitori (archivio PostgreSQL e proxy TLS): quelli si fermano con
# docker compose, e di norma restano su -- il proxy senza la sonda dietro risponde
# 502, che e' l'informazione giusta, non un guasto.

[CmdletBinding()]
param(
    # Ferma anche il proxy TLS e l'archivio in contenitore.
    [switch]$ConIContenitori
)

$ErrorActionPreference = 'Stop'
$Qui = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ''
Write-Host 'Sonda snap - arresto della sonda sulla macchina'
Write-Host '----------------------------------------------'

# PRIMA IL REGISTRO, POI LA RIGA DI COMANDO.
#
# L'avvio scrive in `probe\sonda-nativa.pid` i processi che ha creato. Serve perche'
# la riga di comando di un processo Windows non e' sempre leggibile -- una sessione
# chiusa basta a nasconderla -- e un arresto che cerca solo li' lascerebbe in vita
# cio' che non riesce a vedere: un agente vecchio che continua a battere, e due
# agenti sullo stesso archivio si contendono le prenotazioni dei bersagli.
#
# La ricerca per riga di comando resta come rete: prende anche cio' che e' stato
# avviato a mano, fuori dallo script. Cercare per nome ("python") no: fermerebbe
# qualunque altra cosa stia girando sulla macchina.
$Radice = Resolve-Path (Join-Path $Qui '..\..')
$registro = Join-Path $Radice 'probe\sonda-nativa.pid'
$daRegistro = @()
if (Test-Path $registro) {
    $daRegistro = @(Get-Content $registro | Where-Object { $_ -match '^\d+$' } |
        ForEach-Object { [int]$_ })
    Write-Host ("  registro dei processi: {0}" -f ($daRegistro -join ', ')) `
               -ForegroundColor DarkGray
}

$processi = @(Get-CimInstance Win32_Process -Filter "Name like 'python%'" |
    Where-Object {
        ($_.CommandLine -and $_.CommandLine -match 'run\.py') -or
        ($daRegistro -contains $_.ProcessId) -or
        ($daRegistro -contains $_.ParentProcessId)
    })

if (-not $processi) {
    Write-Host '  nessuna sonda in esecuzione su questa macchina' -ForegroundColor DarkGray
} else {
    # L'agente per primo: vedi la nota in testa.
    $ordinati = @($processi | Where-Object { $_.CommandLine -match '--headless' }) +
                @($processi | Where-Object { $_.CommandLine -notmatch '--headless' })
    foreach ($processo in $ordinati) {
        $ruolo = if ($processo.CommandLine -match '--headless') { 'agente di raccolta' }
                 else { 'interfaccia' }
        try {
            Stop-Process -Id $processo.ProcessId -Force -ErrorAction Stop
            Write-Host ("  fermato: {0} (processo {1})" -f $ruolo, $processo.ProcessId) `
                       -ForegroundColor Green
        } catch {
            # Un processo puo' essere gia' uscito fra l'elenco e l'arresto: non e' un
            # errore, ma va detto invece che taciuto.
            Write-Host ("  {0} (processo {1}) non fermato: {2}" -f `
                        $ruolo, $processo.ProcessId, $_.Exception.Message) `
                       -ForegroundColor Yellow
        }
    }
}

# Anche la finestra nascosta che li ospitava: se restasse, il prossimo avvio
# troverebbe due padri sullo stesso archivio. Si riconosce dal registro o dalla
# propria riga di comando.
$ospiti = @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" |
    Where-Object {
        ($daRegistro -contains $_.ProcessId) -or
        ($_.CommandLine -and $_.CommandLine -match 'start-nativa\.ps1' -and
         $_.CommandLine -match 'SonoIlProcessoNascosto')
    })
foreach ($ospite in $ospiti) {
    try {
        Stop-Process -Id $ospite.ProcessId -Force -ErrorAction Stop
        Write-Host ("  fermato: avvio senza finestra (processo {0})" -f $ospite.ProcessId) `
                   -ForegroundColor Green
    } catch {
        Write-Host ("  avvio senza finestra non fermato: {0}" -f $_.Exception.Message) `
                   -ForegroundColor Yellow
    }
}

if ($ConIContenitori) {
    Write-Host ''
    Write-Host '  arresto di proxy TLS e archivio...' -ForegroundColor DarkGray
    Push-Location $Qui
    try {
        & docker compose -f docker-compose.nativa.yml down
    } finally {
        Pop-Location
    }
}

if (Test-Path $registro) { Remove-Item $registro -Force -ErrorAction SilentlyContinue }

# VERIFICA, non fiducia: se qualcosa e' sopravvissuto va detto, perche' al prossimo
# avvio ci sarebbero due agenti sullo stesso archivio.
Start-Sleep -Milliseconds 800
$rimasti = @(Get-CimInstance Win32_Process -Filter "Name like 'python%'" |
    Where-Object {
        ($_.CommandLine -and $_.CommandLine -match 'run\.py') -or
        ($daRegistro -contains $_.ProcessId)
    })
if ($rimasti) {
    Write-Host ''
    Write-Host ("  ATTENZIONE: {0} processi non si sono fermati ({1})." -f `
                $rimasti.Count, (($rimasti | ForEach-Object { $_.ProcessId }) -join ', ')) `
               -ForegroundColor Yellow
    Write-Host '  Succede quando appartengono a una sessione chiusa: fermarli da una' -ForegroundColor Yellow
    Write-Host '  finestra AMMINISTRATORE prima di riavviare, o si avranno due agenti' -ForegroundColor Yellow
    Write-Host '  sullo stesso archivio.' -ForegroundColor Yellow
}

Write-Host ''
Write-Host '  Fatto. Per riavviare: .\start-nativa.ps1 -Nascosta' -ForegroundColor Cyan
Write-Host ''
