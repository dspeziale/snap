# -----------------------------------------------------------------
# installa.ps1 — installa l'agente snap su una macchina Windows
# Autore: Daniele Speziale
# Data creazione: 2026-09-13
# Copyright (c) 2024-26 DS Consulting
# Licenza: MIT
# -----------------------------------------------------------------
#
# CHE COSA FA, IN ORDINE
#   1. verifica Python e psutil (dal pacchetto, se c'e', o da pip)
#   2. copia l'agente in C:\ProgramData\snap-agent
#   3. registra la macchina sulla sonda con il token del pacchetto
#   4. crea l'attivita' pianificata che lo avvia all'accensione
#   5. VERIFICA che stia davvero girando, e lo dice
#
# I PRIVILEGI, DICHIARATI
# Su Windows l'attivita' gira come SYSTEM. Serve: senza, non si vede il processo che
# tiene aperta una porta, non si leggono gli accessi falliti nel registro di sicurezza
# e non si leggono le utenze locali -- cioe' proprio le cose per cui l'agente esiste.
# Con `-UtenteDiServizio` si usa invece l'utenza di rete, con meno privilegi: cio' che
# non si riesce a leggere viene DICHIARATO alla sonda, non taciuto.
#
# In nessun caso l'agente legge contenuti di file, righe di comando, traffico o
# messaggi: vedi l'intestazione di snap_agent.py.

[CmdletBinding()]
param(
    # Dove installare. ProgramData e non Programmi: qui l'agente scrive il proprio
    # stato, e Programmi e' di sola lettura per disegno.
    [string]$Destinazione = "$env:ProgramData\snap-agent",
    # Che cosa inviare, senza domande: elenco separato da virgole oppure
    # tutti | consigliato | minimo
    [string]$Gruppi = "",
    # Accetta il certificato della sonda senza verificarlo (sonde con certificato
    # proprio, non firmato da un'autorita' pubblica).
    [switch]$SenzaVerificaTls,
    # Esegui con l'utenza di rete invece che come SYSTEM: meno privilegi, meno dati.
    [switch]$UtenteDiServizio,
    [string]$NomeAttivita = "snap-agent"
)

$ErrorActionPreference = "Stop"
$Qui = Split-Path -Parent $MyInvocation.MyCommand.Path

function Dire($testo) { Write-Host "  $testo" }
function Errore($testo) { Write-Host ""; Write-Host "  ERRORE: $testo" -ForegroundColor Red; Write-Host ""; exit 1 }

Write-Host ""
Write-Host "snap agent - installazione"
Write-Host "--------------------------"

# --- 1. le condizioni ------------------------------------------------------ #
$amministratore = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $amministratore) {
    Errore "serve una finestra di PowerShell come amministratore."
}
if (-not (Test-Path "$Qui\pacchetto.json")) { Errore "manca pacchetto.json accanto a questo script." }
if (-not (Test-Path "$Qui\snap_agent.py")) { Errore "manca snap_agent.py accanto a questo script." }

$python = $null
foreach ($candidato in @("py", "python")) {
    $trovato = Get-Command $candidato -ErrorAction SilentlyContinue
    if ($trovato) {
        $argomenti = if ($candidato -eq "py") { @("-3", "--version") } else { @("--version") }
        try {
            $versione = & $trovato.Source @argomenti 2>&1
            if ($versione -match "Python 3\.(\d+)" -and [int]$Matches[1] -ge 9) {
                $python = $trovato.Source
                if ($candidato -eq "py") { $pythonArgs = @("-3") } else { $pythonArgs = @() }
                Dire "python: $versione"
                break
            }
        } catch { }
    }
}
if (-not $python) {
    Errore "serve Python 3.9 o successivo. Si installa da python.org o dal Microsoft Store."
}

$pacchetto = Get-Content "$Qui\pacchetto.json" -Raw | ConvertFrom-Json
$sonda = $pacchetto.sonda
$token = $pacchetto.token
if ($pacchetto.PSObject.Properties.Name -contains "verifica_tls" -and -not $pacchetto.verifica_tls) {
    $SenzaVerificaTls = $true
}
Dire "sonda:  $sonda"
Dire "token:  valido fino al $($pacchetto.scade_at) (una volta sola)"

# --- 2. l'ambiente --------------------------------------------------------- #
Dire "installo in $Destinazione"
New-Item -ItemType Directory -Force -Path $Destinazione | Out-Null
Copy-Item "$Qui\snap_agent.py" "$Destinazione\snap_agent.py" -Force

$venv = Join-Path $Destinazione "venv"
if (-not (Test-Path "$venv\Scripts\python.exe")) {
    & $python @pythonArgs -m venv $venv
    if ($LASTEXITCODE -ne 0) { Errore "non riesco a creare l'ambiente virtuale." }
}
$pythonVenv = Join-Path $venv "Scripts\python.exe"
$pipVenv = Join-Path $venv "Scripts\pip.exe"

# I pacchetti dal PACCHETTO, se ci sono: in una rete senza accesso a Internet -- che
# nella PA e' la norma, non l'eccezione -- pip non raggiungerebbe nulla.
if (Test-Path "$Qui\wheels\*.whl") {
    Dire "psutil dal pacchetto (senza rete)"
    & $pipVenv install --quiet --no-index --find-links "$Qui\wheels" psutil
} else {
    Dire "psutil da pip"
    & $pipVenv install --quiet -r "$Qui\requirements.txt"
}
if ($LASTEXITCODE -ne 0) {
    Errore "installazione di psutil non riuscita: senza accesso a Internet, rigenerare il pacchetto includendo le wheel (vedi LEGGIMI.md)."
}

# --- 3. la registrazione --------------------------------------------------- #
$config = Join-Path $Destinazione "snap-agent.json"
$argomentiTls = @()
if ($SenzaVerificaTls) { $argomentiTls += "--senza-verifica-tls" }

$giaRegistrata = $false
if (Test-Path $config) {
    try {
        $precedente = Get-Content $config -Raw | ConvertFrom-Json
        if ($precedente.agent) { $giaRegistrata = $true }
    } catch { }
}

if ($giaRegistrata) {
    Dire "gia' registrata: la registrazione esistente si conserva"
} else {
    Dire "registro la macchina sulla sonda..."
    $argomentiGruppi = @()
    if ($Gruppi) { $argomentiGruppi = @("--gruppi", $Gruppi) }
    & $pythonVenv "$Destinazione\snap_agent.py" --configurazione $config `
        @argomentiTls registra $sonda $token @argomentiGruppi
    if ($LASTEXITCODE -ne 0) {
        Errore "registrazione non riuscita. Il token vale UNA VOLTA SOLA e un'ora: se e' scaduto o e' gia' stato usato, emetterne un altro dalla console della sonda."
    }
}

# La chiave sta nel file di configurazione: la si toglie dalla portata di chi non
# amministra la macchina. Su Windows i permessi sono ACL, non chmod.
icacls $config /inheritance:r /grant:r "SYSTEM:(F)" "Administrators:(F)" | Out-Null

# IL TOKEN NON RESTA SULLA MACCHINA. Ha gia' fatto il suo lavoro -- in cambio c'e' la
# chiave -- e una credenziale che sopravvive al proprio scopo e' una credenziale che
# qualcuno trovera' fra sei mesi.
Remove-Item "$Qui\pacchetto.json" -Force -ErrorAction SilentlyContinue
Dire "token rimosso dalla macchina: ha gia' fatto il suo lavoro"

# --- 4. l'attivita' pianificata -------------------------------------------- #
# Un'attivita' pianificata e non un servizio: un servizio Windows vero richiede un
# involucro (pywin32, nssm) cioe' una dipendenza in piu' su ogni macchina, per ottenere
# la stessa cosa -- parte all'accensione, riparte se cade.
$utente = if ($UtenteDiServizio) { "NT AUTHORITY\NetworkService" } else { "SYSTEM" }
Dire "esecuzione come $utente"
if ($UtenteDiServizio) {
    Dire "  con meno privilegi non si vedranno: processo dietro le porte in ascolto,"
    Dire "  accessi falliti, utenze locali. Verranno DICHIARATI come non misurati."
}

$azione = New-ScheduledTaskAction -Execute $pythonVenv `
    -Argument "`"$Destinazione\snap_agent.py`" --configurazione `"$config`" servizio" `
    -WorkingDirectory $Destinazione
$avvio = New-ScheduledTaskTrigger -AtStartup
$principale = New-ScheduledTaskPrincipal -UserId $utente -LogonType ServiceAccount -RunLevel Highest
# Se cade, riparte: la macchina va sorvegliata anche dopo un guasto, e soprattutto
# dopo un guasto.
$impostazioni = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero)

Unregister-ScheduledTask -TaskName $NomeAttivita -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $NomeAttivita -Action $azione -Trigger $avvio `
    -Principal $principale -Settings $impostazioni `
    -Description "Agente snap: misura questa macchina e riferisce alla sonda." | Out-Null
Start-ScheduledTask -TaskName $NomeAttivita

# --- 5. la verifica -------------------------------------------------------- #
# NON SI DICE "FATTO" SENZA AVER GUARDATO. Un installatore che stampa un esito
# positivo su un processo che non e' partito fa perdere piu' tempo di uno che fallisce.
Start-Sleep -Seconds 5
$stato = (Get-ScheduledTask -TaskName $NomeAttivita).State
$vivo = Get-Process -Name python -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -eq $pythonVenv }

Write-Host ""
if ($stato -eq "Running" -or $vivo) {
    Dire "FATTO. L'attivita' '$NomeAttivita' e' in esecuzione."
    Dire "  che cosa manda:   & '$pythonVenv' '$Destinazione\snap_agent.py' --configurazione '$config' prova --riassunto"
    Dire "  scegliere cosa:   & '$pythonVenv' '$Destinazione\snap_agent.py' --configurazione '$config' configura"
    Dire "  stato:            Get-ScheduledTask -TaskName $NomeAttivita"
    Write-Host ""
} else {
    Dire "L'attivita' risulta '$stato': non e' partita."
    Dire "Ultimo esito: $((Get-ScheduledTaskInfo -TaskName $NomeAttivita).LastTaskResult)"
    Dire "Provare a mano per vedere l'errore:"
    Dire "  & '$pythonVenv' '$Destinazione\snap_agent.py' --configurazione '$config' servizio"
    Write-Host ""
    exit 1
}
