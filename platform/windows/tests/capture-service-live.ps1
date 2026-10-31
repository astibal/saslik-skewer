param([string]$Directory = 'C:\SkewerDev\flow-test')
$ErrorActionPreference = 'Stop'
# Temporary LocalSystem fixture to test the existing signed WinDivert driver
# from session zero. Static false filter only; no traffic or routes are changed.
$hashes = @{
    'WinDivert.dll' = 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'
    'WinDivert64.sys' = '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'
}
$id = [guid]::NewGuid().ToString('N')
$root = Join-Path $env:ProgramFiles ('SkewerCapture-' + $id)
$null = New-Item -ItemType Directory -Path $root
$exe = Join-Path $root 'capture_service_test.exe'
Copy-Item (Join-Path $Directory 'capture_service_test.exe') $exe
foreach ($file in $hashes.Keys) {
    $target = Join-Path $root $file
    Copy-Item (Join-Path $Directory $file) $target
    if ((Get-FileHash $target -Algorithm SHA256).Hash -ne $hashes[$file]) { throw "Unverified $file" }
}
if ((Get-AuthenticodeSignature (Join-Path $root 'WinDivert64.sys')).Status -ne 'Valid') {
    throw 'Invalid WinDivert driver signature'
}
$created = @()
try {
    foreach ($mode in @('stop', 'failure', 'session-failure')) {
        $failure = $mode -eq 'failure'
        $sessionFailure = $mode -eq 'session-failure'
        $name = 'SkewerCapture-' + $id + '-' + $mode
        $command = '"' + $exe + '" ' + $name + $(if ($failure) { ' --missing-dll' } elseif ($sessionFailure) { ' --session-failure' } else { '' })
        $result = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
            Name = $name; DisplayName = $name; PathName = $command
            ServiceType = [byte]16; ErrorControl = [byte]1; StartMode = 'Manual'; StartName = 'LocalSystem'
        }
        if ($result.ReturnValue -ne 0) { throw "Create service failed: $($result.ReturnValue)" }
        $created += $name
        # WMI StartService starts asynchronously; a deliberately failed worker
        # may already be stopped when a synchronous Start-Service returns.
        $state = Get-CimInstance Win32_Service -Filter "Name='$name'"
        $result = Invoke-CimMethod -InputObject $state -MethodName StartService
        if ($result.ReturnValue -ne 0) { throw "Start request failed: $($result.ReturnValue)" }
        $log = Join-Path $root ($name + '.status')
        $deadline = (Get-Date).AddSeconds(10)
        do {
            $text = if (Test-Path $log) { Get-Content $log -Raw } else { '' }
            if (($sessionFailure -and $text -match 'session_failed_guard_retained') -or
                (!$sessionFailure -and $text -match 'capture_ready|failed')) { break }
            Start-Sleep -Milliseconds 100
        } while ((Get-Date) -lt $deadline)
        if ($failure) {
            if ($text -notmatch 'failed' -or $text -match 'capture_ready') { throw 'False capture readiness' }
        } else {
            if ($text -notmatch 'capture_ready') { throw 'Capture never became ready' }
            if ($sessionFailure) {
                if ($text -notmatch 'session_failed_guard_retained') { throw 'Session failure was not observed' }
                Start-Sleep -Seconds 1
                if ((Get-Service $name).Status -ne 'Running') { throw 'Tunnel failure stopped the guard service' }
                Write-Output 'PASS: failed tunnel session leaves SCM service and guard alive until explicit stop'
            }
            Stop-Service $name
        }
        $service = Get-Service $name
        try { $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(10)) } finally { $service.Dispose() }
        $state = Get-CimInstance Win32_Service -Filter "Name='$name'"
        $text = Get-Content $log -Raw
        if ($text -match 'routing_ready=true') { throw 'Fixture claimed working routing' }
        if ($failure) {
            if ($state.ExitCode -ne 1066 -or $state.ServiceSpecificExitCode -ne 51) { throw 'Lost capture failure' }
            Write-Output 'PASS: DLL failure never claims capture readiness and reaches SCM'
        } else {
            if ($state.ExitCode -ne 0 -or $text -notmatch 'stopped routing_ready=false captured=0 injected=0') {
                throw 'Unclean capture shutdown or unexpected traffic'
            }
            Write-Output 'PASS: session-zero capture opens, waits and stops; routing stays unavailable'
        }
    }
} finally {
    foreach ($name in $created) {
        $service = Get-Service $name -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            try {
                if ($service.Status -ne 'Stopped') { Stop-Service $name }
                $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
            } finally { $service.Dispose() }
            $state = Get-CimInstance Win32_Service -Filter "Name='$name'"
            $result = Invoke-CimMethod -InputObject $state -MethodName Delete
            if ($result.ReturnValue -ne 0) { throw "Fixture cleanup failed: $name" }
        }
    }
    # Do not stop/delete the shared WinDivert driver. Keep protected artifacts.
    Write-Output "Capture fixture artifacts retained at $root"
}
