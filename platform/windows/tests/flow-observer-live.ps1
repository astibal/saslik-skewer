param([string]$Directory = 'C:\SkewerDev\flow-test')

$ErrorActionPreference = 'Stop'
$runId = [guid]::NewGuid().ToString('N')
# Explicit elevated VM-only test. Never relax signature or antivirus policy.
$expected = @{
    'WinDivert.dll' = 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'
    'WinDivert64.sys' = '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'
}
foreach ($name in $expected.Keys) {
    $file = Join-Path $Directory $name
    if ((Get-FileHash -Algorithm SHA256 $file).Hash -ne $expected[$name]) {
        throw "Unexpected official WinDivert 2.2.2-A x64 file: $name"
    }
}
$signature = Get-AuthenticodeSignature (Join-Path $Directory 'WinDivert64.sys')
if ($signature.Status -ne 'Valid') {
    throw "WinDivert driver signature is not valid: $($signature.Status)"
}
Write-Output "Driver signature: $($signature.SignerCertificate.Subject)"

& (Join-Path $Directory 'flow_tracking_test.exe')
if ($LASTEXITCODE -ne 0) { throw 'Flow tracking normalization test failed' }

$stdout = Join-Path $Directory ('flow-test-' + $runId + '.stdout.log')
$stderr = Join-Path $Directory ('flow-test-' + $runId + '.stderr.log')
$dll = Join-Path $Directory 'WinDivert.dll'
$test = Start-Process -FilePath (Join-Path $Directory 'flow_observer_test.exe') `
    -ArgumentList @('--live', ('"' + $dll + '"')) -PassThru -NoNewWindow `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr
# Retain the native process handle before exit; Windows PowerShell otherwise
# may lose ExitCode for a short-lived Start-Process child.
$null = $test.Handle
try {
    if (-not $test.WaitForExit(60000)) {
        $test.Kill()
        $test.WaitForExit()
        throw 'Passive flow test exceeded its deadline'
    }
    Get-Content $stdout
    Get-Content $stderr
    if ($test.ExitCode -ne 0) {
        throw "Passive flow test failed: $($test.ExitCode)"
    }
} finally {
    $test.Dispose()
}
# Closing observer handles removes their filters. Do not stop/delete the shared
# WinDivert driver service: another application might be using it.

& (Join-Path $Directory 'skewer-flow-watch.exe') --self-test
if ($LASTEXITCODE -ne 0) { throw 'Flow watcher input validation failed' }

# Exercise the actual command against the same isolated traffic fixture. Named
# events ensure observation is ready before the fixture opens any sockets.
$prefix = 'Local\SkewerWatchTest-' + [guid]::NewGuid().ToString()
$go = [Threading.EventWaitHandle]::new($false, 'ManualReset', $prefix + '-go')
$done = [Threading.EventWaitHandle]::new($false, 'ManualReset', $prefix + '-done')
$release = [Threading.EventWaitHandle]::new($false, 'ManualReset', $prefix + '-release')
$child = $null
$watch = $null
try {
    $child = Start-Process -FilePath (Join-Path $Directory 'flow_observer_test.exe') `
        -ArgumentList @('--child', $prefix) -PassThru -NoNewWindow
    $null = $child.Handle
    # Never reuse files: readiness/output must belong to this exact child,
    # including when another test runs concurrently or a prior run was killed.
    $watchOut = Join-Path $Directory ('watch-' + $runId + '.stdout.log')
    $watchErr = Join-Path $Directory ('watch-' + $runId + '.stderr.log')
    $watch = Start-Process -FilePath (Join-Path $Directory 'skewer-flow-watch.exe') `
        -ArgumentList @($child.Id, ('"' + $dll + '"')) -PassThru -NoNewWindow `
        -RedirectStandardOutput $watchOut -RedirectStandardError $watchErr
    $null = $watch.Handle
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        if ($watch.HasExited) { throw 'Flow watcher exited before readiness' }
        $ready = (Test-Path $watchErr) -and
            ((Get-Content $watchErr -Raw) -match 'Watching PID')
        if (-not $ready) { Start-Sleep -Milliseconds 50 }
    } until ($ready -or [DateTime]::UtcNow -ge $deadline)
    if (-not $ready) { throw 'Flow watcher readiness deadline' }
    $null = $go.Set()
    if (-not $done.WaitOne(5000)) { throw 'Watcher fixture traffic failed' }
    # Wait for all four output classes before allowing the selected PID to exit.
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        $output = Get-Content $watchOut -Raw
        $complete = $true
        foreach ($kind in @('TCP IPv4', 'UDP IPv4', 'TCP IPv6', 'UDP IPv6')) {
            $complete = $complete -and ($output -match $kind)
        }
        if (-not $complete) { Start-Sleep -Milliseconds 50 }
    } until ($complete -or [DateTime]::UtcNow -ge $deadline)
    if (-not $complete) { throw 'Watcher omitted a traffic class' }
    if ($output -notmatch 'correlation=observed' -or $output -match 'correlation=unreliable') {
        throw "Watcher did not correlate the live fixture events reliably. Snapshot:`n$output"
    }
    $null = $release.Set()
    if (-not $child.WaitForExit(5000) -or $child.ExitCode -ne 0) {
        throw 'Watcher fixture did not finish successfully'
    }
    if (-not $watch.WaitForExit(5000) -or $watch.ExitCode -ne 0) {
        throw 'Watcher did not stop on target exit'
    }
    if ((Get-Content $watchErr -Raw) -notmatch 'Target exited') {
        throw 'Watcher omitted target exit feedback'
    }
    Write-Output 'PASS: flow watcher command, traffic output and automatic stop on target exit'
} finally {
    $null = $release.Set()
    foreach ($process in @($watch, $child)) {
        if ($null -ne $process) {
            if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
            $process.Dispose()
        }
    }
    $go.Dispose()
    $done.Dispose()
    $release.Dispose()
}
