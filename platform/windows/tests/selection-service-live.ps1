param([string]$Directory = 'C:\SkewerDev\flow-test')
$ErrorActionPreference = 'Stop'
# Elevated disposable VM only. LocalSystem is required here to query the
# launcher's token; no routing, driver, firewall or production service changes.
$name = 'SkewerSelectionTest-' + [guid]::NewGuid().ToString('N')
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
