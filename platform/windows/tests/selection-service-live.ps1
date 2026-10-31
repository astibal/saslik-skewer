param([string]$Directory = 'C:\SkewerDev\flow-test', [switch]$Handoff, [switch]$WrongOwner)
$ErrorActionPreference = 'Stop'
if ($WrongOwner) { $Handoff = $true }
# Elevated disposable VM only. LocalSystem is required here to query the
# launcher's token; no routing, driver, firewall or production service changes.
$name = 'SkewerSelectionTest-' + [guid]::NewGuid().ToString('N')
if ($Handoff) { $name += '-handoff' }
if ($WrongOwner) { $name += '-denied' }
$root = Join-Path $env:ProgramFiles $name
$null = New-Item -ItemType Directory -Path $root
$exe = Join-Path $root 'selection_service_test.exe'
Copy-Item (Join-Path $Directory 'selection_service_test.exe') $exe
$birth = (Get-Process -Id $PID).StartTime.ToUniversalTime().ToFileTimeUtc()
$command = '"' + $exe + '" --service ' + $name + ' ' + $PID + ' ' + $birth
$created = $false
try {
    $result = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
        Name = $name; DisplayName = $name; PathName = $command
        ServiceType = [byte]16; ErrorControl = [byte]1
        StartMode = 'Manual'; StartName = 'LocalSystem'
    }
    if ($result.ReturnValue -ne 0) { throw "Create failed: $($result.ReturnValue)" }
    $created = $true
    Start-Service $name
    # SCM RUNNING precedes endpoint readiness. Retry only this stateless fixture.
    $ok = $false
    for ($attempt = 0; $attempt -lt 20; ++$attempt) {
        & $exe --client $name
        if ($LASTEXITCODE -eq 0) { $ok = $true; break }
        Start-Sleep -Milliseconds 100
    }
    if (-not $ok) { throw 'SCM selection exchange failed' }
    # A second client exercises disconnect/reaccept while keeping the endpoint.
    Start-Sleep -Milliseconds 100
    & $exe --client $name
    if ($LASTEXITCODE -ne 0) { throw 'Second selection exchange failed' }
    if (!$Handoff) {
    foreach ($scope in @('--scope-applications', '--scope-host')) {
        Start-Sleep -Milliseconds 100
        & $exe $scope $name
        if ($LASTEXITCODE -ne 0) { throw "Authenticated scope probe failed: $scope" }
    }
    # The short-lived IPC client selects this long-lived launcher, then exits.
    # Its disconnect must not erase the service-owned, pinned selection.
    Start-Sleep -Milliseconds 100
    & $exe --client-target $name $PID $birth
    if ($LASTEXITCODE -ne 0) { throw 'Retained target selection failed' }
    Start-Sleep -Milliseconds 700
    $status = Join-Path $root ($name + '.status')
    if ((Get-Content $status -Tail 1) -ne 'after_disconnect live=1 routing_ready=false') {
        throw 'Service lost the selected target after its IPC client disconnected'
    }
    Write-Output 'PASS: service retains selected process after selecting client exits; no routing claim'
    } else {
        $status = Join-Path $root ($name + '.status')
        $received = (Get-Content $status -Raw) -match 'handoff_received routing_ready=false'
        if ($received -eq [bool]$WrongOwner) {
            throw 'Service did not validate the public fixture credentials'
        }
        if ($WrongOwner) { Write-Output 'PASS: foreign owner rejected before credential transfer' }
        else { Write-Output 'PASS: LocalSystem receives user-bound credentials without user storage or secret argv' }
    }
    Stop-Service $name
    $service = Get-Service $name
    try { $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(10)) }
    finally { $service.Dispose() }
    $state = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if ($state.ExitCode -ne 0) { throw "Service failed: $($state.ExitCode)" }
    Write-Output 'PASS: repeated authenticated SCM exchanges and clean stop'
} finally {
    if ($created) {
        $service = Get-Service $name
        try {
            if ($service.Status -ne 'Stopped') { Stop-Service $name }
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(10))
        } finally { $service.Dispose() }
        $state = Get-CimInstance Win32_Service -Filter "Name='$name'"
        $result = Invoke-CimMethod -InputObject $state -MethodName Delete
        if ($result.ReturnValue -ne 0) { throw 'Fixture cleanup failed' }
    }
    Write-Output "Fixture retained at $exe"
}
