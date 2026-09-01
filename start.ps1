<#
    snap - Avvio completo di server e sonda (Windows PowerShell).

    Esempi:
        .\start.ps1                 avvia server (5500) e sonda (5510) in due finestre
        .\start.ps1 -Only server    avvia solo il server
        .\start.ps1 -Only probe     avvia solo la sonda
        .\start.ps1 -Setup          crea l'ambiente virtuale, installa le dipendenze
                                    e inizializza il database, senza avviare
        .\start.ps1 -Test           esegue la suite di test
        .\start.ps1 -DevMode        avvio in modalita' di sviluppo
        .\start.ps1 -Stop           arresta i processi avviati da questo script
        .\start.ps1 -ShowCommand    mostra i comandi di avvio senza eseguirli
        .\start.ps1 -ServerHost 10.20.10.42
                                    console raggiungibile da quell'indirizzo di rete
        .\start.ps1 -ServerHost 10.20.10.42 -ProbeHost 10.20.10.42
                                    anche l'interfaccia della sonda (senza
                                    autenticazione: leggere l'avviso)

    remarks: Autore: Daniele Speziale - Data: 2026-08-26
    copyright: (c) 2024-26 DS Consulting
    license: MIT
#>

[CmdletBinding()]
param(
    [ValidateSet('all', 'server', 'probe')]
    [string]$Only = 'all',

    [int]$ServerPort = 5500,
    [int]$ProbePort = 5510,

    # Indirizzo con cui la console va raggiunta dalla rete (es. 10.20.10.42). Il
    # valore predefinito e' il solo indirizzo locale: la console non e'
    # raggiungibile da fuori finche' non viene chiesto esplicitamente.
    #
    # Quando si indica un indirizzo di rete il server ascolta su TUTTE le
    # interfacce, non solo su quella: legandosi al solo indirizzo di rete,
    # 127.0.0.1 smetterebbe di rispondere e la sonda installata sulla stessa
    # postazione -- che conferisce proprio su 127.0.0.1 -- resterebbe muta. Il
    # difetto e' stato misurato, non ipotizzato.
    #
    [string]$ServerHost = '127.0.0.1',

    # Indirizzo con cui raggiungere l'interfaccia della SONDA dalla rete.
    #
    # Predefinito locale: l'interfaccia serve anzitutto a chi installa la sonda,
    # sulla macchina stessa. Da quando si puo' aprire alla rete (DEC-05a) e'
    # protetta da password (DEC-11), la cui PRIMA impostazione e' ammessa solo
    # dall'indirizzo locale: se la sonda e' gia' esposta, il primo che arriva non
    # deve poter scegliere la credenziale. Restano due limiti che lo script
    # dichiara a ogni avvio: il canale e' in chiaro e chi ha la password puo'
    # riconfigurare la sonda.
    [string]$ProbeHost = '127.0.0.1',

    [switch]$Setup,
    [switch]$Test,
    [switch]$Stop,
    [switch]$NoVenv,
    [switch]$DevMode,

    # Mostra i comandi che verrebbero eseguiti nelle finestre dei componenti, senza
    # avviare nulla: serve a verificare percorsi e apici quando qualcosa non parte.
    [switch]$ShowCommand
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvDir = Join-Path $Root '.venv'
$PidFile = Join-Path $Root '.snap-pids.json'

function Write-Section($Text) {
    Write-Host ''
    Write-Host ('=' * 68) -ForegroundColor DarkGray
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host ('=' * 68) -ForegroundColor DarkGray
}

function Get-PythonPath {
    # Preferisce l'interprete dell'ambiente virtuale, se presente.
    $venvPython = Join-Path $VenvDir 'Scripts\python.exe'
    if ((-not $NoVenv) -and (Test-Path $venvPython)) {
        return $venvPython
    }
    $command = Get-Command python -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        throw 'Interprete Python non trovato nel PATH. Installare Python 3.10 o superiore.'
    }
    return $command.Source
}

function Initialize-Environment {
    Write-Section 'Preparazione ambiente'

    if (-not $NoVenv) {
        if (-not (Test-Path $VenvDir)) {
            Write-Host 'Creazione ambiente virtuale .venv ...' -ForegroundColor Yellow
            & python -m venv $VenvDir
        } else {
            Write-Host 'Ambiente virtuale gia presente.' -ForegroundColor DarkGray
        }
    }

    $python = Get-PythonPath
    Write-Host ("Interprete: {0}" -f $python) -ForegroundColor DarkGray

    Write-Host 'Installazione dipendenze del server ...' -ForegroundColor Yellow
    & $python -m pip install --disable-pip-version-check -q -r (Join-Path $Root 'server\requirements.txt')
    Write-Host 'Installazione dipendenze della sonda ...' -ForegroundColor Yellow
    & $python -m pip install --disable-pip-version-check -q -r (Join-Path $Root 'probe\requirements.txt')

    Write-Host 'Inizializzazione del database del server ...' -ForegroundColor Yellow
    Push-Location (Join-Path $Root 'server')
    try {
        & $python run.py --init
    } finally {
        Pop-Location
    }
    Write-Host 'Ambiente pronto.' -ForegroundColor Green
}

function Invoke-Tests {
    Write-Section 'Esecuzione della suite di test'
    $python = Get-PythonPath
    Push-Location $Root
    try {
        & $python -m pytest tests -v
    } finally {
        Pop-Location
    }
}

function Read-PidRegistry {
    # Restituisce sempre un array: ConvertFrom-Json su un solo elemento produce un
    # oggetto. Si tengono solo le voci con i campi attesi: un registro scritto male
    # -- e' successo -- non deve impedire ad -Stop di fermare cio' che e' in piedi.
    if (-not (Test-Path $PidFile)) { return @() }
    try {
        $voci = @(Get-Content $PidFile -Raw | ConvertFrom-Json)
    } catch {
        Write-Host 'Registro dei processi illeggibile: verra ricreato.' -ForegroundColor DarkGray
        return @()
    }
    $valide = @($voci | Where-Object {
        $null -ne $_ -and $null -ne $_.PSObject.Properties['port'] -and
        $null -ne $_.PSObject.Properties['pid']
    })
    if ($valide.Count -lt $voci.Count) {
        Write-Host 'Registro dei processi con voci non valide: verranno ignorate.' -ForegroundColor DarkGray
    }
    return $valide
}

function Write-PidRegistry($Entries) {
    # Appiattimento esplicito. In PowerShell 5.1 un array che finisce dentro un altro
    # array non si srotola da solo, e ConvertTo-Json lo serializza come
    # {"value": [...], "Count": n}: il registro diventa illeggibile e -Stop non
    # ferma piu' nulla. Difetto misurato durante un avvio con -Only.
    $piatto = @()
    foreach ($voce in @($Entries)) {
        if ($null -eq $voce) { continue }
        if ($voce -is [System.Collections.IEnumerable] -and $voce -isnot [string]) {
            foreach ($interna in $voce) { if ($null -ne $interna) { $piatto += $interna } }
        } else {
            $piatto += $voce
        }
    }
    $piatto = @($piatto | Where-Object { $null -ne $_.PSObject.Properties['port'] })

    # -InputObject e NON il pipeline: in PowerShell 5.1 un array passato per pipeline
    # arriva a ConvertTo-Json come oggetto singolo e viene serializzato come
    # {"value": [...], "Count": n}. Era questa la causa del registro illeggibile:
    # -Stop non trovava piu' un elenco e non fermava nulla.
    $json = ConvertTo-Json -InputObject $piatto -Depth 5
    if ($piatto.Count -eq 1) { $json = "[" + $json + "]" }  # un elemento resta un elenco
    $json | Out-File -FilePath $PidFile -Encoding utf8
}

function Test-PortInUse([int]$Port) {
    <#
        Difetto misurato, e non da poco: si provava a legare 127.0.0.1 sulla porta, ma
        su Windows un ascolto su 0.0.0.0 NON impedisce di legare il loopback. Con il
        server avviato su tutte le interfacce, la porta risultava LIBERA: l'avvio
        successivo "riusciva", il processo Python nuovo moriva subito perche' la
        porta era davvero occupata, e lo script registrava come proprio il PID del
        processo VECCHIO -- che continuava a servire il codice precedente. Effetto
        visibile: modifiche applicate al codice e invisibili nel browser.

        L'elenco degli ascolti dice la verita' su qualunque indirizzo: si guarda
        quello, e il tentativo di legare resta solo come ricaduta dove
        Get-NetTCPConnection non e' disponibile.
    #>
    if ($null -ne (Get-ListenerPid $Port)) { return $true }

    $listener = $null
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
        $listener.Start()
        return $false
    } catch {
        return $true
    } finally {
        if ($null -ne $listener) { $listener.Stop() }
    }
}

function Get-ListenerPid([int]$Port) {
    try {
        $connection = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop |
            Select-Object -First 1
        if ($connection) { return [int]$connection.OwningProcess }
    } catch {
        # Get-NetTCPConnection non disponibile: si resta al PID del processo avviato.
    }
    return $null
}

function Get-LocalAddresses {
    <# Indirizzi IPv4 reali della postazione, esclusi loopback, link-local e le
       interfacce virtuali di WSL e Hyper-V: in un elenco di dodici indirizzi
       quello che serve non si trova. #>
    try {
        return @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object {
                $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and
                $_.InterfaceAlias -notlike '*WSL*' -and $_.InterfaceAlias -notlike '*Default Switch*'
            } | Select-Object -ExpandProperty IPAddress)
    } catch {
        return @()
    }
}

function Show-NetworkAccess {
    param([string]$BindHost, [int]$Port)

    if ($BindHost -eq '127.0.0.1' -or $BindHost -eq 'localhost') {
        Write-Host ''
        Write-Host 'La console risponde solo su questa postazione.' -ForegroundColor DarkGray
        Write-Host ("Per aprirla alla rete: .\start.ps1 -Stop; .\start.ps1 -ServerHost <indirizzo>" ) -ForegroundColor DarkGray
        $indirizzi = Get-LocalAddresses
        if ($indirizzi.Count -gt 0) {
            Write-Host ("  indirizzi di questa postazione: {0}" -f ($indirizzi -join ', ')) -ForegroundColor DarkGray
        }
        return
    }

    # @() sull'ASSEGNAZIONE: senza, un solo indirizzo resta una stringa e [0] ne
    # prende la prima cifra invece del primo elemento.
    # @() sull'ASSEGNAZIONE: senza, un solo indirizzo resta una stringa e [0] ne
    # prende la prima cifra invece del primo elemento.
    $raggiungibili = @($BindHost)
    Write-Host ''
    Write-Host 'Console raggiungibile:' -ForegroundColor Green
    foreach ($indirizzo in $raggiungibili) {
        Write-Host ("  http://{0}:{1}/   <- dalla rete" -f $indirizzo, $Port)
    }
    Write-Host ("  http://127.0.0.1:{0}/   <- da questa postazione (e dalla sonda locale)" -f $Port)
    $altri = @(Get-LocalAddresses | Where-Object { $_ -ne $BindHost })
    if ($altri.Count -gt 0) {
        Write-Host ''
        Write-Host ("Il server ascolta su tutte le interfacce: risponde anche su {0}." -f ($altri -join ', ')) -ForegroundColor DarkGray
        Write-Host 'E la condizione perche 127.0.0.1 continui a rispondere, e con esso la sonda locale.' -ForegroundColor DarkGray
    }

    # Il trade-off va detto, non nascosto: senza TLS le credenziali attraversano
    # la rete in chiaro. Per una dimostrazione in rete controllata e' una scelta
    # accettabile; per l'esercizio serve un proxy inverso con TLS.
    Write-Host ''
    Write-Host 'Attenzione: il canale e HTTP, non HTTPS.' -ForegroundColor Yellow
    Write-Host '  Credenziali e contenuti attraversano la rete in chiaro: ammissibile in una' -ForegroundColor Yellow
    Write-Host '  rete controllata per una dimostrazione, non in esercizio. In esercizio il' -ForegroundColor Yellow
    Write-Host '  server va dietro un proxy inverso con TLS (vedi docs/05, capitolo 3).' -ForegroundColor Yellow
    if ($BindHost -eq '0.0.0.0') {
        Write-Host '  0.0.0.0 apre la console su OGNI interfaccia, comprese quelle virtuali:' -ForegroundColor Yellow
        Write-Host '  indicare l indirizzo della scheda di rete e piu prudente.' -ForegroundColor Yellow
    }

    # Il firewall di Windows blocca per difetto le connessioni in ingresso: senza
    # una regola la console risulta muta da fuori, e la causa non e il prodotto.
    $regola = $null
    try {
        $regola = Get-NetFirewallRule -DisplayName ("snap server {0}" -f $Port) -ErrorAction Stop
    } catch {
        $regola = $null
    }
    if ($null -eq $regola) {
        Write-Host ''
        Write-Host 'Il firewall di Windows non ha una regola per questa porta.' -ForegroundColor Yellow
        Write-Host 'Se da un altro computer la pagina non si apre, eseguire UNA VOLTA come amministratore:' -ForegroundColor DarkGray
        Write-Host ("  New-NetFirewallRule -DisplayName 'snap server {0}' -Direction Inbound ``" -f $Port) -ForegroundColor Cyan
        Write-Host ("    -Action Allow -Protocol TCP -LocalPort {0} -Profile Private,Domain" -f $Port) -ForegroundColor Cyan
        Write-Host '  (profili Private e Domain: la porta non viene aperta sulle reti pubbliche)' -ForegroundColor DarkGray
    }

    Write-Host ''
    Write-Host 'Da fare una volta nella console (Amministrazione > Impostazioni Sistema):' -ForegroundColor DarkGray
    Write-Host ("  indirizzo pubblico = http://{0}:{1}   -- entra nei pacchetti di registrazione" -f $BindHost, $Port) -ForegroundColor DarkGray
    Write-Host '  delle sonde e nelle copertine dei report.' -ForegroundColor DarkGray
}

function Show-ProbeAccess {
    param([string]$BindHost, [int]$Port)

    if ($BindHost -eq '127.0.0.1' -or $BindHost -eq 'localhost') {
        Write-Host ''
        Write-Host ("Interfaccia della sonda: http://127.0.0.1:{0}/ (solo da questa postazione)." -f $Port) -ForegroundColor DarkGray
        return
    }

    Write-Host ''
    Write-Host ("Interfaccia della sonda raggiungibile dalla rete: http://{0}:{1}/" -f $BindHost, $Port) -ForegroundColor Green
    Write-Host ''
    Write-Host 'L interfaccia e protetta da password (una sola credenziale, nessun ruolo).' -ForegroundColor DarkGray
    Write-Host '  Prima apertura: la password si scegle DALLA POSTAZIONE DELLA SONDA, su' -ForegroundColor Yellow
    Write-Host ("  http://127.0.0.1:{0}/  -- dalla rete la scelta iniziale e rifiutata, cosi' la" -f $Port) -ForegroundColor Yellow
    Write-Host '  sonda appartiene a chi l ha installata e non al primo che la trova in rete.' -ForegroundColor Yellow
    Write-Host '  Password dimenticata: si reimposta dal dispositivo (vedi docs/05, cap. 6).' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host 'Restano due limiti da conoscere:' -ForegroundColor Yellow
    Write-Host '  - il canale e HTTP: la password attraversa la rete in chiaro;' -ForegroundColor Yellow
    Write-Host '  - chi ha la password puo riconfigurare la sonda e sospendere le scansioni.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'Mitigazione consigliata: consentire un solo indirizzo di origine.' -ForegroundColor Yellow
    Write-Host ("  New-NetFirewallRule -DisplayName 'snap probe {0}' -Direction Inbound ``" -f $Port) -ForegroundColor Cyan
    Write-Host ("    -Action Allow -Protocol TCP -LocalPort {0} -Profile Private,Domain ``" -f $Port) -ForegroundColor Cyan
    Write-Host "    -RemoteAddress <indirizzo del computer da cui si amministra>" -ForegroundColor Cyan
    Write-Host '  Per richiuderla: .\start.ps1 -Stop e riavvio senza -ProbeHost.' -ForegroundColor DarkGray
}

function Get-ComponentCommand {
    <#
        Comando eseguito dentro la finestra di un componente.

        Sta in una funzione a se' perche' e' la parte piu' facile da sbagliare --
        percorsi con spazi, dollari da non interpolare, apici -- e in una funzione
        si puo' leggere e provare senza avviare niente:

            .\start.ps1 -ShowCommand
    #>
    param(
        [string]$Name, [string]$Directory, [int]$Port, [string]$Python,
        [string]$LogVariable, [string]$LogFile, [switch]$DebugMode,
        [string]$BindHost = '127.0.0.1'
    )

    # Il dollaro va protetto con il backtick: senza, "$Host" e "$env:..." sarebbero
    # espansi QUI, nella finestra che avvia, invece che in quella avviata.
    $righe = @(
        ("`$Host.UI.RawUI.WindowTitle = '{0} - porta {1}'" -f $Name, $Port),
        # Senza questo l'uscita di Python compare a blocchi e la finestra sembra
        # ferma proprio nei primi secondi, che sono quelli in cui la si guarda.
        "`$env:PYTHONUNBUFFERED = '1'",
        ("`$env:{0} = '{1}'" -f $LogVariable, $LogFile),
        ("Set-Location '{0}'" -f $Directory),
        ("& '{0}' run.py --host {1} --port {2}{3}" -f $Python, $BindHost, $Port,
            $(if ($DebugMode) { ' --debug' } else { '' })),
        # -NoExit da solo lascerebbe una finestra muta dopo un'uscita immediata:
        # queste righe dicono che il processo e' finito e con quale codice, mentre
        # il motivo resta scritto sopra.
        "Write-Host ''",
        ("Write-Host ('{0}: processo terminato (codice ' + [string]`$LASTEXITCODE + '). Il motivo e'' scritto qui sopra.') -ForegroundColor Yellow" -f $Name)
    )
    return ($righe -join '; ')
}

function Start-Component {
    param([string]$Name, [string]$Directory, [int]$Port,
          [string]$BindHost = '127.0.0.1')

    if (Test-PortInUse $Port) {
        throw ("Porta {0} gia in uso: {1} non avviato. Eseguire .\start.ps1 -Stop oppure indicare un'altra porta." -f $Port, $Name)
    }

    $python = Get-PythonPath

    # Il diario resta su file per la diagnosi a posteriori, ma NON al posto di
    # quello a schermo: con entrambi i flussi rediretti, la finestra che Windows
    # apre per un processo di console non puo' mostrare niente, e due finestre
    # vuote fanno credere che il prodotto non sia partito. Difetto segnalato e
    # corretto: la finestra esegue l'interprete in primo piano, il file lo scrive
    # l'applicazione (variabile SNAP_*_LOG_FILE).
    $logDir = Join-Path $Root 'logs'
    if (-not (Test-Path $logDir)) { $null = New-Item -ItemType Directory -Path $logDir }
    $logFile = Join-Path $logDir ((($Name -replace '\s+', '-') + '.log').ToLower())
    $variabileLog = if ($Name -like '*probe*') { 'SNAP_PROBE_LOG_FILE' } else { 'SNAP_SERVER_LOG_FILE' }

    $comando = Get-ComponentCommand -Name $Name -Directory $Directory -Port $Port `
        -Python $python -LogVariable $variabileLog -LogFile $logFile -DebugMode:$DevMode `
        -BindHost $BindHost

    Write-Host ("Avvio {0} sulla porta {1} ..." -f $Name, $Port) -ForegroundColor Yellow
    $process = Start-Process -FilePath 'powershell.exe' -PassThru `
        -ArgumentList @('-NoExit', '-NoLogo', '-ExecutionPolicy', 'Bypass', '-Command', $comando)

    # Attesa dell'ascolto effettivo. L'alias di esecuzione di Microsoft Store
    # avvia uno stub che lancia l'interprete reale come processo figlio: il PID
    # restituito da Start-Process non e' quello che apre la porta, per cui si
    # registra anche il proprietario del socket in ascolto.
    $listenerPid = $null
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        $listenerPid = Get-ListenerPid $Port
        if ($null -ne $listenerPid) { break }
        Start-Sleep -Milliseconds 250
    }

    if ($null -eq $listenerPid -and $process.HasExited) {
        throw ("{0} terminato immediatamente (codice {1}). Eseguire .\start.ps1 -Setup." -f $Name, $process.ExitCode)
    }
    if ($null -eq $listenerPid) {
        # La finestra del componente e' aperta e mostra il motivo: si indirizza
        # l'operatore a quella, invece di lasciarlo senza indicazioni.
        Write-Host ("  {0}: porta {1} non ancora in ascolto. Leggere la finestra del componente oppure {2}." -f $Name, $Port, $logFile) -ForegroundColor Yellow
    }

    return [pscustomobject]@{
        name        = $Name
        pid         = $process.Id
        listenerPid = $listenerPid
        port        = $Port
    }
}

function Stop-ProcessTree([int]$ProcessId) {
    # Termina prima i figli: lo stub di Microsoft Store ospita l'interprete reale.
    $children = @(Get-CimInstance Win32_Process -Filter ("ParentProcessId = {0}" -f $ProcessId) -ErrorAction SilentlyContinue)
    foreach ($child in $children) { $null = Stop-ProcessTree ([int]$child.ProcessId) }

    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($null -ne $process) {
        Stop-Process -Id $ProcessId -Force -Confirm:$false -ErrorAction SilentlyContinue
        return $true
    }
    return $false
}

function Stop-ByCommandLine([int]$Port) {
    # Ricaduta: individua il processo del componente dalla sua riga di comando.
    $filter = "CommandLine like '%run.py --port {0}%'" -f $Port
    $found = @(Get-CimInstance Win32_Process -Filter $filter -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'python*' })
    foreach ($item in $found) { $null = Stop-ProcessTree ([int]$item.ProcessId) }
    return $found.Count
}

function Stop-Components {
    Write-Section 'Arresto dei componenti'
    if (-not (Test-Path $PidFile)) {
        Write-Host 'Nessun processo registrato da questo script.' -ForegroundColor DarkGray
        return
    }

    $entries = Read-PidRegistry

    # Le porte dei componenti si fermano SEMPRE dalla porta, non solo quando il
    # registro le nomina: un registro superato non deve lasciare in piedi un
    # processo che continua a servire codice vecchio.
    foreach ($porta in @($ServerPort, $ProbePort)) {
        $proprietario = Get-ListenerPid $porta
        if ($null -ne $proprietario -and
            -not (@($entries | ForEach-Object { $_.listenerPid }) -contains $proprietario)) {
            Write-Host ("Porta {0}: in ascolto il processo {1}, non registrato: arresto." -f $porta, $proprietario) -ForegroundColor Yellow
            $null = Stop-ProcessTree ([int]$proprietario)
        }
    }

    foreach ($entry in $entries) {
        $stopped = $false
        foreach ($candidate in @($entry.listenerPid, $entry.pid)) {
            if ($null -ne $candidate -and $candidate -gt 0) {
                if (Stop-ProcessTree ([int]$candidate)) { $stopped = $true }
            }
        }

        # Ricaduta: il registro puo' riportare PID superati (avvio manuale del
        # componente, oppure stub di avvio sostituito). Si cerca allora il
        # processo dalla porta e dalla riga di comando.
        $residual = 0
        if ($null -ne $entry.port -and (Test-PortInUse ([int]$entry.port))) {
            $residual = Stop-ByCommandLine ([int]$entry.port)
        }

        if ($stopped -or $residual -gt 0) {
            $note = if ($stopped) { '' } else { ' (individuato dalla porta)' }
            Write-Host ("Arrestato {0} (porta {1}){2}." -f $entry.name, $entry.port, $note) -ForegroundColor Yellow
        } else {
            Write-Host ("{0} (porta {1}) non era in esecuzione." -f $entry.name, $entry.port) -ForegroundColor DarkGray
        }
    }

    Remove-Item $PidFile -Force
    Start-Sleep -Milliseconds 500

    $busy = @($entries | Where-Object { $null -ne $_.port -and (Test-PortInUse ([int]$_.port)) })
    if ($busy.Count -gt 0) {
        foreach ($entry in $busy) {
            Write-Host ("Attenzione: la porta {0} risulta ancora occupata." -f $entry.port) -ForegroundColor Red
        }
    } else {
        Write-Host 'Componenti arrestati.' -ForegroundColor Green
    }
}

# --------------------------------------------------------------------------- #
# Flusso principale
# --------------------------------------------------------------------------- #
if ($ShowCommand) {
    Write-Section 'Comandi di avvio (nessun componente avviato)'
    $python = Get-PythonPath
    $logDir = Join-Path $Root 'logs'
    foreach ($componente in @(
        @{ Name = 'snap server'; Directory = (Join-Path $Root 'server'); Port = $ServerPort; Var = 'SNAP_SERVER_LOG_FILE' },
        @{ Name = 'snap probe';  Directory = (Join-Path $Root 'probe');  Port = $ProbePort;  Var = 'SNAP_PROBE_LOG_FILE' })) {
        $logFile = Join-Path $logDir ((($componente.Name -replace '\s+', '-') + '.log').ToLower())
        Write-Host ("{0}:" -f $componente.Name) -ForegroundColor Cyan
        Write-Host (Get-ComponentCommand -Name $componente.Name -Directory $componente.Directory `
            -Port $componente.Port -Python $python -LogVariable $componente.Var `
            -LogFile $logFile -DebugMode:$DevMode)
        Write-Host ''
    }
    return
}
if ($Stop) { Stop-Components; return }
if ($Setup) { Initialize-Environment; return }
if ($Test) { Invoke-Tests; return }

# Primo avvio: se il database non esiste si prepara l'ambiente automaticamente.
if (-not (Test-Path (Join-Path $Root 'server\data\snap_server.sqlite3'))) {
    Write-Host 'Database non presente: preparazione automatica dell ambiente.' -ForegroundColor Yellow
    Initialize-Environment
}

Write-Section 'Avvio di snap'

# Avvio incrementale (-Only): si mantengono le voci dei componenti gia attivi,
# altrimenti un secondo avvio renderebbe -Stop incapace di fermare il primo.
$registry = @(Read-PidRegistry | Where-Object {
    $null -ne (Get-Process -Id $_.pid -ErrorAction SilentlyContinue)
})
$started = @()

if ($Only -eq 'all' -or $Only -eq 'server') {
    # Vedi il commento del parametro: aprire alla rete non deve chiudere il locale.
    $ascolto = if ($ServerHost -eq '127.0.0.1' -or $ServerHost -eq 'localhost') { $ServerHost } else { '0.0.0.0' }
    $started += Start-Component -Name 'snap server' -Directory (Join-Path $Root 'server') `
        -Port $ServerPort -BindHost $ascolto
}
if ($Only -eq 'all' -or $Only -eq 'probe') {
    $ascoltoSonda = if ($ProbeHost -eq '127.0.0.1' -or $ProbeHost -eq 'localhost') { $ProbeHost } else { '0.0.0.0' }
    $started += Start-Component -Name 'snap probe' -Directory (Join-Path $Root 'probe') `
        -Port $ProbePort -BindHost $ascoltoSonda
}

$registry = @($registry | Where-Object { $_.name -notin $started.name }) + $started
Write-PidRegistry $registry

Write-Host ''
Write-Host 'Componenti attivi:' -ForegroundColor Green
foreach ($entry in $registry) {
    # Si mostra il PID del processo che ascolta, non quello dello stub di avvio.
    $shownPid = if ($entry.listenerPid) { $entry.listenerPid } else { $entry.pid }
    # La sonda ascolta sempre in locale; il server sull'indirizzo richiesto.
    $indirizzo = if ($entry.name -like '*probe*') { $ProbeHost } else { $ServerHost }
    Write-Host ("  {0,-12} http://{1}:{2}/   (PID {3})" -f $entry.name, $indirizzo, $entry.port, $shownPid)
}
Write-Host ''
Write-Host 'Credenziali iniziali del server:' -ForegroundColor Cyan
Write-Host '  Amministratore di sistema : admin@snap.local / Snap!Admin2026'
Write-Host '  Amministratore tenant     : admin@ised.local / Snap!Tenant2026'
Write-Host ''
Write-Host 'Sequenza consigliata:' -ForegroundColor Cyan
Write-Host '  1. Accedere al server e creare la sonda (Sonde & Discovery > Registra sonda)'
Write-Host '  2. Copiare il pacchetto SNAP1-...'
Write-Host '  3. Aprire l interfaccia della sonda e incollarlo nella pagina di registrazione'
Write-Host ''
Show-NetworkAccess -BindHost $ServerHost -Port $ServerPort
Show-ProbeAccess -BindHost $ProbeHost -Port $ProbePort

Write-Host ''
Write-Host 'Ogni componente ha una finestra propria: mostra l avvio e il diario in tempo reale.' -ForegroundColor DarkGray
Write-Host ("Lo stesso diario resta su file in: {0}" -f (Join-Path $Root 'logs')) -ForegroundColor DarkGray
Write-Host 'Per arrestare: .\start.ps1 -Stop  (oppure Ctrl+C nella finestra del componente)' -ForegroundColor DarkGray
