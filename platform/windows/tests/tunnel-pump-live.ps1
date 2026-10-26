param([Parameter(Mandatory=$true)][string]$Directory, [string]$RemotePeer = '')
$ErrorActionPreference = 'Stop'
$executable = Join-Path $Directory 'tunnel_pump_live.exe'
$dll = Join-Path $Directory 'wintun.dll'
if ((Get-AuthenticodeSignature $dll).Status -ne 'Valid') { throw 'Untrusted Wintun DLL' }
function DefaultRoutes {
    @(Get-NetRoute | Where-Object DestinationPrefix -In @('0.0.0.0/0', '::/0') |
        Sort-Object AddressFamily,InterfaceIndex,NextHop |
        Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric) | ConvertTo-Json -Compress
}
$before = DefaultRoutes
$selected = Find-NetRoute -RemoteIPAddress '198.18.254.2' |
    Where-Object { $_.PSObject.Properties.Name -contains 'DestinationPrefix' }
if (@($selected).Count -ne 1 -or $selected.DestinationPrefix -ne '0.0.0.0/0') {
    throw 'Test destination already has a non-default route; refusing to override it'
}
$runId = [guid]::NewGuid().ToString('N')
$stdout = Join-Path $Directory "live-$runId.out"
$stderr = Join-Path $Directory "live-$runId.err"
$arguments = @('--live', "`"$dll`"")
if ($RemotePeer) {
    $parsedPeer = $null
    if (![System.Net.IPAddress]::TryParse($RemotePeer, [ref]$parsedPeer) -or
        $parsedPeer.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'Remote peer must be a numeric IPv4 address'
    }
    if ($env:TUNTOM_SECRET -notmatch '^[0-9a-fA-F]{32}$') { throw 'Missing test TUNTOM_SECRET' }
    $arguments = @('--remote', "`"$dll`"", $parsedPeer.ToString())
}
$process = Start-Process -FilePath $executable -ArgumentList $arguments `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
# Keep the native handle open: Windows PowerShell may otherwise lose ExitCode
# when a short-lived child exits before it opens the handle lazily.
$null = $process.Handle
$name = "SkewerLive-$($process.Id)"
try {
    $deadline = (Get-Date).AddSeconds(15)
    do {
        $adapter = Get-NetAdapter -Name $name -ErrorAction SilentlyContinue
        if ($adapter) { break }
        if ($process.HasExited) { throw 'Probe exited before creating adapter' }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    if (!$adapter) { throw 'Test adapter did not appear' }
    # All configuration belongs to this fresh adapter, in ActiveStore only.
    Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 `
        -NlMtuBytes 1280 -Dhcp Disabled -PolicyStore ActiveStore
    New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress '198.18.254.1' `
        -PrefixLength 30 -PolicyStore ActiveStore | Out-Null
    $addressDeadline = (Get-Date).AddSeconds(10)
    do {
        $address = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress '198.18.254.1'
        if ($address.AddressState -eq 'Preferred') { break }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $addressDeadline)
    if ($address.AddressState -ne 'Preferred') { throw 'Test address did not finish DAD' }
    # Cross the pump's health deadline before data traffic. A Linux peer's
    # slower unsolicited keepalive must not make an idle tunnel unusable.
    if ($RemotePeer) { Start-Sleep -Seconds 7 }
    # A freshly configured adapter may still be converging in the Windows stack.
    # Count three individually successful requests, not ping's partial-success exit.
    $successes = 0
    for ($attempt = 0; $attempt -lt 8 -and $successes -lt 3; ++$attempt) {
        & ping.exe -4 -S 198.18.254.1 -n 1 -w 1000 198.18.254.2
        if ($LASTEXITCODE -eq 0) { ++$successes }
        if ($successes -lt 3) { Start-Sleep -Milliseconds 250 }
    }
    if ($successes -ne 3) { throw 'Live Wintun ping failed' }
    if (!$process.WaitForExit(15000)) { throw 'Probe failed to finish after ping' }
    if ($process.ExitCode -ne 0) { throw "Probe failed: $($process.ExitCode)" }
} finally {
    # Allow normal destruction even on failure. Only this exact spawned process
    # may be stopped if its bounded 45-second probe unexpectedly hangs.
    if (!$process.HasExited -and !$process.WaitForExit(50000)) { $process.Kill(); $process.WaitForExit() }
    Get-Content $stdout
    Get-Content $stderr
    if ((DefaultRoutes) -ne $before) { throw 'Default routing changed' }
    if (Get-NetAdapter -Name $name -IncludeHidden -ErrorAction SilentlyContinue) {
        throw "Test adapter remains: $name"
    }
    if (Get-NetRoute -DestinationPrefix '198.18.254.0/30' -ErrorAction SilentlyContinue) {
        throw 'Test route remains'
    }
}
Write-Output 'PASS: Windows ping traversed Wintun/session/UDP and cleanup preserved default routes'
