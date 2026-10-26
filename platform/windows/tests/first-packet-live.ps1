param([string]$Directory = 'C:\SkewerDev\flow-test')
$ErrorActionPreference = 'Stop'
# Disposable elevated VM only. No host routes or persistent WFP rules are changed.
$hashes = @{
    'WinDivert.dll' = 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'
    'WinDivert64.sys' = '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'
}
foreach ($name in $hashes.Keys) {
    if ((Get-FileHash (Join-Path $Directory $name) -Algorithm SHA256).Hash -ne $hashes[$name]) {
        throw "Unverified WinDivert file: $name"
    }
}
if ((Get-AuthenticodeSignature (Join-Path $Directory 'WinDivert64.sys')).Status -ne 'Valid') {
    throw 'Driver signature is not valid'
}
$prefix = 'Local\SkewerFirstPacket-' + [guid]::NewGuid().ToString()
$go = [Threading.EventWaitHandle]::new($false, 'ManualReset', $prefix + '-go')
$done = [Threading.EventWaitHandle]::new($false, 'ManualReset', $prefix + '-done')
$ready = [Threading.EventWaitHandle]::new($false, 'ManualReset', $prefix + '-ready')
$fixture = Join-Path $Directory 'app_egress_guard_test.exe'
$output = Join-Path $Directory 'first-packet.stdout.log'
$errors = Join-Path $Directory 'first-packet.stderr.log'
$child = $guard = $other = $null
function Run-Round {
    $null = $done.Reset()
    $null = $go.Set()
    if (-not $done.WaitOne(10000)) {
        if (Test-Path $errors) { Get-Content $errors }
        throw 'First-packet fixture failed or timed out'
    }
}
try {
    $child = Start-Process $fixture -ArgumentList @('--probe-sequence', $prefix) `
        -PassThru -NoNewWindow -RedirectStandardOutput $output -RedirectStandardError $errors
    $null = $child.Handle
    Run-Round
    Write-Output 'PASS: selected fixture baseline allowed'

    $dll = Join-Path $Directory 'WinDivert.dll'
    $guard = Start-Process (Join-Path $Directory 'first_packet_test.exe') `
        -ArgumentList @($child.Id, ('"' + $dll + '"'), ($prefix + '-ready')) -PassThru -NoNewWindow
    $null = $guard.Handle
    if (-not $ready.WaitOne(10000) -or $guard.HasExited) { throw 'SOCKET filter did not arm' }
    Run-Round
    Write-Output 'PASS: new TCP attempts denied and first UDP datagrams not delivered (IPv4/IPv6)'

    $other = Start-Process $fixture -ArgumentList @('--probe', 'allowed') -PassThru -NoNewWindow
    $null = $other.Handle
    if (-not $other.WaitForExit(10000) -or $other.ExitCode -ne 0) {
        throw 'Unselected instance of the same executable was affected'
    }
    Write-Output 'PASS: same executable, different PID remains allowed'

    $guard.Kill()
    $guard.WaitForExit()
    Run-Round
    if (-not $child.WaitForExit(5000) -or $child.ExitCode -ne 0) { throw 'Final probe round failed' }
    Get-Content $output
    Get-Content $errors
    Write-Output 'CONFIRMED LIMITATION: after filter-owner kill, NEW connections are allowed again'
    Write-Output 'NOT a persistent kill switch and NOT a suspend/resume connect mechanism'
} finally {
    # Only our retained process objects are terminated; never kill by executable name.
    foreach ($process in @($guard, $other, $child)) {
        if ($null -ne $process) {
            if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
            $process.Dispose()
        }
    }
    $go.Dispose(); $done.Dispose(); $ready.Dispose()
}
