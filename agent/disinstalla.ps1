# -----------------------------------------------------------------
# disinstalla.ps1 — toglie l'agente snap da una macchina Windows
# Autore: Daniele Speziale
# Data creazione: 2026-09-13
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
#
# Toglie l'attivita' pianificata e i file. NON revoca la macchina sulla sonda: quello
# si fa dalla console della sonda, ed e' voluto che siano due gesti distinti --
# disinstallare e' una manutenzione, revocare una credenziale e' una decisione.

[CmdletBinding()]
param(
    [string]$Destinazione = "$env:ProgramData\snap-agent",
    [string]$NomeAttivita = "snap-agent"
)

$ErrorActionPreference = "Stop"

$amministratore = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $amministratore) {
    Write-Host "  serve una finestra di PowerShell come amministratore." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "snap agent - disinstallazione"
Write-Host "-----------------------------"

$attivita = Get-ScheduledTask -TaskName $NomeAttivita -ErrorAction SilentlyContinue
if ($attivita) {
    Stop-ScheduledTask -TaskName $NomeAttivita -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $NomeAttivita -Confirm:$false
    Write-Host "  attivita' pianificata rimossa"
}

# Il processo puo' sopravvivere all'attivita': si guarda, invece di fidarsi.
Get-Process -Name python -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -like "$Destinazione*" } |
    ForEach-Object {
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        Write-Host "  processo $($_.Id) fermato"
    }

if (Test-Path $Destinazione) {
    Remove-Item $Destinazione -Recurse -Force
    Write-Host "  file rimossi da $Destinazione (chiave compresa)"
}

Write-Host ""
Write-Host "  Fatto. La macchina risulta ancora REGISTRATA sulla sonda e smettera'"
Write-Host "  semplicemente di riferire: per chiuderla del tutto, revocarla dalla"
Write-Host "  console della sonda, pagina Agenti."
Write-Host ""
