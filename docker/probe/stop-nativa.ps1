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

# I processi si riconoscono dalla riga di comando: sono i soli `run.py` di questo
# prodotto. Cercarli per nome ("python") fermerebbe qualunque altra cosa l'utente
# stia eseguendo, ed e' un modo di rompere il lavoro di qualcun altro.
$processi = @(Get-CimInstance Win32_Process -Filter "Name like 'python%'" |
    Where-Object { $_.CommandLine -and $_.CommandLine -match 'run\.py' })

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
# troverebbe due padri sullo stesso archivio.
$ospiti = @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" |
    Where-Object { $_.CommandLine -and $_.CommandLine -match 'start-nativa\.ps1' -and
                   $_.CommandLine -match 'SonoIlProcessoNascosto' })
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

Write-Host ''
Write-Host '  Fatto. Per riavviare: .\start-nativa.ps1 -Nascosta' -ForegroundColor Cyan
Write-Host ''
