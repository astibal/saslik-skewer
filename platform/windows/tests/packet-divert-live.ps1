param(
    [string]$Directory = 'C:\SkewerDev\flow-test',
    [string]$RuntimeDirectory = 'C:\SkewerDev\skewer-windows-app'
)
$ErrorActionPreference = 'Stop'
# Elevated disposable VM only. Match bound loopback ports, never host routes.
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
$child = $null
try {
    $dll = Join-Path $Directory 'WinDivert.dll'
    $child = Start-Process (Join-Path $Directory 'packet_divert_test.exe') `
        -ArgumentList ('"' + $dll + '"') -PassThru -NoNewWindow
    $null = $child.Handle
    if (-not $child.WaitForExit(45000)) { throw 'Packet diversion fixture timed out' }
if ($child.ExitCode -ne 0) { throw "Packet diversion fixture failed: $($child.ExitCode)" }
& (Join-Path $RuntimeDirectory 'selected_reconnect_live.exe')
if ($LASTEXITCODE -ne 0) { throw 'Selected reconnect fixture failed' }
& (Join-Path $RuntimeDirectory 'selected_reconnect_live.exe') --pause-recovery
if ($LASTEXITCODE -ne 0) { throw 'Selected pause/reconnect fixture failed' }
} finally {
    # Retained child only; closing its handles removes its narrowly scoped filters.
    if ($null -ne $child) {
        if (-not $child.HasExited) { $child.Kill(); $child.WaitForExit() }
        $child.Dispose()
    }
}
