param([string]$Directory = 'C:\SkewerDev\flow-test',
      [string]$ClientDirectory = '', [string]$StoredEndpoint = '',
      [string]$GuiTestDirectory = '')
$ErrorActionPreference = 'Stop'
# Disposable elevated VM only. Fixed false WinDivert filter, public test key.
$name = 'SkewerRoutingTest-' + [guid]::NewGuid().ToString('N')
$root = Join-Path $env:ProgramFiles $name
$null = New-Item -ItemType Directory -Path $root
$exe = Join-Path $root 'routing_service_test.exe'
Copy-Item (Join-Path $Directory 'routing_service_test.exe') $exe
$hashes = @{
    'WinDivert.dll' = 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'
    'WinDivert64.sys' = '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'
}
foreach ($file in $hashes.Keys) {
    Copy-Item (Join-Path $Directory $file) (Join-Path $root $file)
    if ((Get-FileHash (Join-Path $root $file)).Hash -ne $hashes[$file]) { throw 'Unverified driver fixture' }
}
if ((Get-AuthenticodeSignature (Join-Path $root 'WinDivert64.sys')).Status -ne 'Valid') { throw 'Invalid signature' }
function Command([int]$op, [uint64]$generation) {
    if ($ClientDirectory) {
        $client = Join-Path $ClientDirectory 'skewer-routing-control.exe'
        $action = @('status', 'start', 'stop')[$op]
        if ($op -eq 0) { $text = & $client $action $name }
        else { $text = & $client $action $name $generation }
        # Busy/Stale are valid structured rejections with exit status 1.
        if ($LASTEXITCODE -gt 1 -or !$text) { throw 'Routing client failed' }
    } else {
        $text = & $exe --client $name $op $generation
        if ($LASTEXITCODE -ne 0) { throw 'Routing command failed' }
    }
    return ($text | ConvertFrom-Json)
}
function AwaitPhase([int]$phase) {
    for ($i = 0; $i -lt 30; ++$i) {
        $value = Command 0 0
        if ($value.phase -eq $phase) { return $value }
        Start-Sleep -Milliseconds 100
    }
    throw "Expected phase $phase; got $($value.phase)"
}
function StartDirect([uint64]$generation) {
    if ($ClientDirectory) {
        $text = & (Join-Path $ClientDirectory 'skewer-routing-control.exe') `
            start-direct $name $generation '192.0.2.1' --exempt '198.51.100.0/24'
    } else {
        $text = & $exe --direct $name $generation '192.0.2.1' '198.51.100.0/24'
    }
    if ($LASTEXITCODE -ne 0 -or !$text) { throw 'Direct routing client failed' }
    return ($text | ConvertFrom-Json)
}
$created = $false
try {
    $ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $command = '"' + $exe + '" --service ' + $name + ' ' + $ownerSid
    $result = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
        Name=$name; DisplayName=$name; PathName=$command; ServiceType=[byte]16
        ErrorControl=[byte]1; StartMode='Manual'; StartName='LocalSystem'
    }
    if ($result.ReturnValue -ne 0) { throw 'Create service failed' }
    $created = $true
    Start-Service $name
    $initial = AwaitPhase 0
    $direct = StartDirect $initial.generation
    if ($direct.result -ne 0 -or $direct.scope -ne 1 -or $direct.transport -ne 2 -or $direct.paired -or
        @($direct.exemptions).Count -ne 1 -or $direct.exemptions[0] -ne '198.51.100.0/24') {
        throw 'Unpaired direct whole-host start was not represented accurately'
    }
    $activeDirect = AwaitPhase 2
    if ($activeDirect.scope -ne 1 -or $activeDirect.transport -ne 2 -or
        @($activeDirect.exemptions).Count -ne 1 -or $activeDirect.exemptions[0] -ne '198.51.100.0/24') {
        throw 'Direct whole-host generation did not become Active'
    }
    $null = Command 2 $activeDirect.generation
    $initial = AwaitPhase 0
    if ($GuiTestDirectory) {
        $previousPlatform = $env:QT_QPA_PLATFORM
        $previousPath = $env:PATH
        try {
            $offscreen = Join-Path $GuiTestDirectory 'platforms\qoffscreen.dll'
            $env:QT_QPA_PLATFORM = if (Test-Path $offscreen) { 'offscreen' } else { 'windows' }
            $env:PATH = "$GuiTestDirectory;$previousPath"
            & (Join-Path $GuiTestDirectory 'routing_panel_test.exe') `
                --live-direct $name '192.0.2.1'
            if ($LASTEXITCODE -ne 0) { throw 'GUI Auto direct start failed' }
        } finally {
            $env:QT_QPA_PLATFORM = $previousPlatform
            $env:PATH = $previousPath
        }
        $activeDirect = AwaitPhase 2
        if ($activeDirect.scope -ne 1 -or $activeDirect.transport -ne 2 -or $activeDirect.paired -or
            @($activeDirect.exemptions).Count -ne 1 -or $activeDirect.exemptions[0] -ne '198.51.100.0/24') {
            throw 'GUI Auto direct state was not retained after panel close'
        }
        $null = Command 2 $activeDirect.generation
        $initial = AwaitPhase 0
    }
    & $exe --client $name 1 $initial.generation
    if ($LASTEXITCODE -eq 0) { throw 'Unpaired service accepted Start' }
    $unpaired = Command 0 0
    if ($unpaired.phase -ne 0 -or $unpaired.paired) { throw 'Rejected Start changed service state' }
    if ($StoredEndpoint) {
        if (!$ClientDirectory) { throw 'Stored pairing test requires ClientDirectory' }
        & (Join-Path $ClientDirectory 'skewer-routing-control.exe') pair $name $StoredEndpoint
        if ($LASTEXITCODE -ne 0) { throw 'Stored pairing handoff failed' }
        if ((Command 0 0).phase -ne 0) { throw 'Pairing handoff started routing' }
        # The next public fixture handoff replaces it while idle. The service
        # never opens a real tunnel or writes the user's credentials to disk.
    }
    $paired = $false
    for ($i = 0; $i -lt 20; ++$i) {
        & $exe --pair $name
        if ($LASTEXITCODE -eq 0) { $paired = $true; break }
        Start-Sleep -Milliseconds 100
    }
    if (!$paired) { throw 'Fixture pairing handoff failed' }
    $initial = Command 0 0
    if ($initial.phase -ne 0 -or !$initial.paired) { throw 'Not paired and idle before start' }
    $started = Command 1 $initial.generation
    if ($started.result -ne 0 -or $started.generation -eq $initial.generation) { throw 'Start rejected' }
    $blocked = AwaitPhase 3
    & $exe --pair $name
    if ($LASTEXITCODE -eq 0) { throw 'Active generation accepted replacement pairing' }
    if ((Command 0 0).phase -ne 3) { throw 'Rejected pairing disturbed the active generation' }
    # Every command runs in a fresh process. The START client is already gone.
    if ((Get-Service $name).Status -ne 'Running') { throw 'Client exit stopped service' }
    $busy = Command 1 $started.generation
    if ($busy.result -ne 2) { throw 'Duplicate start launched another session' }
    $stale = Command 2 $initial.generation
    if ($stale.result -ne 1 -or $stale.phase -ne 3) { throw 'Stale stop altered current session' }
    $null = Command 2 $started.generation
    $null = AwaitPhase 0
    $second = Command 1 $started.generation
    if ($second.generation -eq $started.generation) { throw 'Restart reused generation' }
    $null = AwaitPhase 3
    $stale = Command 2 $started.generation
    if ($stale.result -ne 1 -or $stale.generation -ne $second.generation) { throw 'Old stop reached new session' }
    # SCM STOP must also cancel/join an active blocked runtime.
    Stop-Service $name
    $service = Get-Service $name
    try { $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(10)) } finally { $service.Dispose() }
    if ((Get-CimInstance Win32_Service -Filter "Name='$name'").ExitCode -ne 0) { throw 'Unclean service shutdown' }
    # Persistent owner configuration has no launcher PID/birth dependency.
    Start-Service $name
    $restarted = AwaitPhase 0
    if ($restarted.generation -eq $second.generation -or $restarted.paired) {
        throw 'SCM restart reused generation or retained memory-only pairing'
    }
    & $exe --pair $name
    if ($LASTEXITCODE -ne 0) { throw 'Owner could not reconnect after SCM restart' }
    $self = Get-Process -Id $PID
    $birth = $self.StartTime.ToUniversalTime().ToFileTimeUtc()
    $text = & $exe --select $name $restarted.generation $PID ($birth + 1)
    if ($LASTEXITCODE -eq 0) { throw 'Stale process birth accepted' }
    if ((Command 0 0).phase -ne 0) { throw 'Rejected target changed service state' }
    $text = & $exe --select $name $restarted.generation $PID $birth '203.0.113.0/24'
    if ($LASTEXITCODE -ne 0) { throw 'Authorized selected start rejected' }
    $selected = $text | ConvertFrom-Json
    if ($selected.result -ne 0 -or @($selected.exemptions).Count -ne 1 -or
        $selected.exemptions[0] -ne '203.0.113.0/24') { throw 'Selected start not accepted' }
    $selectedBlocked = AwaitPhase 3
    if (@($selectedBlocked.exemptions).Count -ne 1 -or
        $selectedBlocked.exemptions[0] -ne '203.0.113.0/24') {
        throw 'Selected generation lost its destination exemption'
    }
    $text = & $exe --select $name $selected.generation $PID $birth
    if ($LASTEXITCODE -ne 0 -or ($text | ConvertFrom-Json).result -ne 2) {
        throw 'Duplicate selected start not rejected as busy'
    }
    $null = Command 2 $selected.generation
    $null = AwaitPhase 0
    $text = & $exe --select $name $restarted.generation $PID $birth
    if ($LASTEXITCODE -ne 0 -or ($text | ConvertFrom-Json).result -ne 1) {
        throw 'Stale selected start not rejected'
    }
    Stop-Service $name
    Write-Output 'PASS: owner-bound direct host and selected target, stale birth/generation, busy and explicit stop'
    Write-Output 'PASS: pairing -> authenticated start/status/stop -> guard; client exit, duplicate start, stale stop, restart and SCM cleanup'
} finally {
    if ($created) {
        $service = Get-Service $name
        try {
            if ($service.Status -ne 'Stopped') { Stop-Service $name }
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(10))
        } finally { $service.Dispose() }
        $state = Get-CimInstance Win32_Service -Filter "Name='$name'"
        if ((Invoke-CimMethod -InputObject $state -MethodName Delete).ReturnValue -ne 0) { throw 'Cleanup failed' }
    }
    Write-Output "Fixture retained at $root"
}
