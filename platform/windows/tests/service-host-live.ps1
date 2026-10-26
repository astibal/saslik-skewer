param([string]$Directory = 'C:\SkewerDev\flow-test')
$ErrorActionPreference = 'Stop'
# Elevated development VM only. Unique, demand-start LocalService fixtures;
# no production service, routing, filter, driver or automatic recovery changes.
$id = [guid]::NewGuid().ToString('N')
$root = Join-Path $env:ProgramFiles ('SkewerLifecycle-' + $id)
$null = New-Item -ItemType Directory -Path $root
$exe = Join-Path $root 'service_host_test.exe'
Copy-Item (Join-Path $Directory 'service_host_test.exe') $exe
$created = @()
try {
    foreach ($failure in @($false, $true)) {
        $name = 'SkewerLifecycle-' + $id + $(if ($failure) { '-failure' } else { '-stop' })
        $command = '"' + $exe + '" ' + $name + $(if ($failure) { ' --fail' } else { '' })
        $result = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
            Name = $name; DisplayName = $name; PathName = $command
            ServiceType = [byte]16; ErrorControl = [byte]1
            StartMode = 'Manual'; StartName = 'NT AUTHORITY\LocalService'
        }
        if ($result.ReturnValue -ne 0) { throw "Create service failed: $($result.ReturnValue)" }
        $created += $name
        Start-Service $name
        $service = Get-Service $name
        try {
            $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(10))
            if (-not $failure) {
                # Run as the invoking user against the LocalService fixture.
                # A privileged caller still must not select another user's PID.
                $running = Get-CimInstance Win32_Service -Filter "Name='$name'"
                & (Join-Path $Directory 'selection_auth_test.exe') --foreign $running.ProcessId
                if ($LASTEXITCODE -ne 0) { throw 'Foreign-user selection authorization failed' }
                Stop-Service $name
            }
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
        } finally { $service.Dispose() }
        $state = Get-CimInstance Win32_Service -Filter "Name='$name'"
        if ($state.StartName -ne 'NT AUTHORITY\LocalService') { throw 'Unexpected service identity' }
        if ($failure) {
            if ($state.ExitCode -ne 1066 -or $state.ServiceSpecificExitCode -ne 42) {
                throw "Worker failure was not reported: $($state.ExitCode)/$($state.ServiceSpecificExitCode)"
            }
            Write-Output 'PASS: worker failure reaches SCM as service-specific code 42'
        } else {
            if ($state.ExitCode -ne 0) { throw 'Normal stop reported failure' }
            Write-Output 'PASS: demand-start LocalService runs independently and stops cleanly'
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
            if ($result.ReturnValue -ne 0) { throw "Fixture service cleanup failed: $name" }
        }
    }
    # Keep the administrator-owned executable for audit, without any service.
    Write-Output "Fixture binary retained at $exe"
}
