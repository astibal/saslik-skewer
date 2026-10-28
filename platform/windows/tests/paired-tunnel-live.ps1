param(
    [Parameter(Mandatory=$true)][string]$Directory,
    [Parameter(Mandatory=$true)][string]$WintunDll,
    [Parameter(Mandatory=$true)][string]$Endpoint,
    [Parameter(Mandatory=$true)][string]$Peer,
    [ValidateRange(0,65535)][int]$ConnectPort = 0,
    [switch]$WholeHostTest,
    [string]$WinDivertDirectory = '',
    [string]$Management = ''
)
$ErrorActionPreference = 'Stop'
# Pair separately via stdin. Never put an invitation/PSK into child argv or logs.
if ($Endpoint -notmatch '^skewer://[A-Za-z0-9.-]+:[0-9]+/pair$') { throw 'Expected a paired endpoint without a secret' }
$ip = $null
if (![System.Net.IPAddress]::TryParse($Peer, [ref]$ip) -or
    $ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { throw 'Expected numeric IPv4 peer' }
if ((Get-AuthenticodeSignature $WintunDll).Status -ne 'Valid') { throw 'Untrusted Wintun DLL' }
function DefaultRoutes {
    @(Get-NetRoute | Where-Object DestinationPrefix -In @('0.0.0.0/0', '::/0') |
        Sort-Object AddressFamily,InterfaceIndex,NextHop |
        Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric) | ConvertTo-Json -Compress
}
$before = DefaultRoutes
$ownedRoutes = @()
$guard = $readyEvent = $stopEvent = $null
if ($WholeHostTest) {
    if ($ConnectPort) { throw 'Whole-host test must not use an explicit proxy' }
    $managementIp = $null
    if (![System.Net.IPAddress]::TryParse($Management, [ref]$managementIp) -or
        $managementIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'Whole-host test requires numeric IPv4 SSH management address'
    }
    $hashes = @{
        'WinDivert.dll' = 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'
        'WinDivert64.sys' = '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'
    }
    foreach ($file in $hashes.Keys) {
        if ((Get-FileHash (Join-Path $WinDivertDirectory $file)).Hash -ne $hashes[$file]) {
            throw "Unverified WinDivert file: $file"
        }
    }
    if ((Get-AuthenticodeSignature (Join-Path $WinDivertDirectory 'WinDivert64.sys')).Status -ne 'Valid') {
        throw 'Untrusted WinDivert driver'
    }
    $testIp = (Resolve-DnsName example.com -Type A -DnsOnly |
        Where-Object Type -EQ A | Select-Object -First 1).IPAddress
    if (!$testIp) { throw 'Cannot resolve test destination before routing changes' }
    # Pre-resolve test traffic: DNS routing is a separate acceptance case.
    $underlay = @(Find-NetRoute -RemoteIPAddress $Peer |
        Where-Object { $_.PSObject.Properties.Name -contains 'DestinationPrefix' })
    if ($underlay.Count -ne 1) { throw 'Ambiguous underlay route' }
    foreach ($prefix in @('0.0.0.0/1', '128.0.0.0/1', "$Peer/32")) {
        if (Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue) {
            throw "Existing route conflicts with fixture: $prefix"
        }
    }
}
$runId = [guid]::NewGuid().ToString('N')
$stdout = Join-Path $Directory "paired-$runId.out"
$stderr = Join-Path $Directory "paired-$runId.err"
$binary = Join-Path $Directory 'paired_tunnel_live.exe'
$process = Start-Process -FilePath $binary -ArgumentList @('--live', "`"$WintunDll`"", $Endpoint, $Peer) `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
$null = $process.Handle
$name = "SkewerPaired-$($process.Id)"
try {
    $deadline = (Get-Date).AddSeconds(20)
    $metadata = $null
    do {
        $line = Get-Content $stdout | Where-Object { $_.StartsWith('ENDPOINT ') } | Select-Object -Last 1
        if ($line) { $metadata = $line.Substring(9) | ConvertFrom-Json; break }
        if ($process.HasExited) { throw 'Probe exited before authenticated endpoint setup' }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    if (!$metadata) { throw 'No authenticated endpoint metadata' }
    # Independently verify the native client's authenticated address setup.
    if ($metadata.server_address -notmatch '^10\.([0-9]+)\.([0-9]+)\.([0-9]+)/30$' -or
        $metadata.client_address -notmatch '^10\.([0-9]+)\.([0-9]+)\.([0-9]+)/30$') { throw 'Invalid tunnel prefix' }
    $server = ([System.Net.IPAddress]::Parse($metadata.server_address.Split('/')[0]))
    $client = ([System.Net.IPAddress]::Parse($metadata.client_address.Split('/')[0]))
    $s = $server.GetAddressBytes(); $c = $client.GetAddressBytes()
    if ($s[1] -ne $c[1] -or $s[2] -ne $c[2] -or $s[3] % 4 -ne 1 -or $c[3] -ne $s[3] + 1) {
        throw 'Invalid tunnel address pair'
    }
    $adapter = Get-NetAdapter -Name $name
    $address = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $client.ToString() -PolicyStore ActiveStore
    $interface = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -PolicyStore ActiveStore
    if ($address.AddressState -ne 'Preferred' -or $address.PrefixLength -ne 30 -or
        $interface.NlMtu -ne 1280) {
        throw "Native tunnel setup is incorrect: state=$($address.AddressState), prefix=$($address.PrefixLength), MTU=$($interface.NlMtu)"
    }
    $selected = @(Find-NetRoute -RemoteIPAddress $server.ToString() |
        Where-Object { $_.PSObject.Properties.Name -contains 'DestinationPrefix' })
    if ($selected.Count -ne 1 -or $selected[0].InterfaceIndex -ne $adapter.ifIndex) {
        throw 'Native tunnel subnet route does not use the owned adapter'
    }
    $successes = 0
    for ($attempt = 0; $attempt -lt 6 -and $successes -lt 3; ++$attempt) {
        & ping.exe -4 -S $client.ToString() -n 1 -w 1000 $server.ToString()
        if ($LASTEXITCODE -eq 0) { ++$successes }
    }
    if ($successes -ne 3) { throw 'Paired Wintun path did not carry three successful pings' }
    if ($WholeHostTest) {
        $eventPrefix = 'Local\SkewerHost-' + $runId
        $readyEvent = [Threading.EventWaitHandle]::new($false, 'ManualReset', $eventPrefix + '-ready')
        $stopEvent = [Threading.EventWaitHandle]::new($false, 'ManualReset', $eventPrefix + '-stop')
        $guard = Start-Process (Join-Path $Directory 'host_guard_live.exe') -ArgumentList @(
            ('"' + (Join-Path $WinDivertDirectory 'WinDivert.dll') + '"'), $adapter.ifIndex, $Peer,
            (40000 + [int]$metadata.id), ([Uri]$Endpoint).Port, $Management,
            ($eventPrefix + '-ready'), ($eventPrefix + '-stop')) -PassThru -NoNewWindow
        $null = $guard.Handle
        if (!$readyEvent.WaitOne(5000) -or $guard.HasExited) { throw 'Host egress guard did not arm' }
        $ownedRoutes += New-NetRoute -DestinationPrefix "$Peer/32" -InterfaceIndex $underlay[0].InterfaceIndex `
            -NextHop $underlay[0].NextHop -RouteMetric 1 -PolicyStore ActiveStore
        foreach ($prefix in @('0.0.0.0/1', '128.0.0.0/1')) {
            $ownedRoutes += New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $adapter.ifIndex `
                -NextHop $server.ToString() -RouteMetric 1 -PolicyStore ActiveStore
        }
        $route = @(Find-NetRoute -RemoteIPAddress $testIp |
            Where-Object { $_.PSObject.Properties.Name -contains 'DestinationPrefix' })
        if ($route.Count -ne 1 -or $route[0].InterfaceIndex -ne $adapter.ifIndex) {
            throw 'Test destination is not routed through Wintun'
        }
        foreach ($scheme in @('http', 'https')) {
            $port = if ($scheme -eq 'https') { 443 } else { 80 }
            $body = & curl.exe -4 --silent --show-error --fail --insecure --noproxy '*' `
                --resolve "example.com:${port}:$testIp" --connect-timeout 3 --max-time 7 "${scheme}://example.com/"
            if ($LASTEXITCODE -ne 0 -or ($body -join "`n") -notmatch 'Example Domain') {
                throw "Whole-host $scheme failed"
            }
            Write-Output "PASS: host routes -> Wintun/Tuntom -> $scheme, no proxy or source binding"
        }
    }
    if ($ConnectPort) {
        # Explicit lab-only TLS trust bypass; never installed as browser policy.
        # CONNECT resolves the public destination on Smithproxy, not Windows DNS.
        $body = & curl.exe --silent --show-error --fail --insecure --noproxy localhost `
            --interface $client.ToString() --proxy "http://$($server.ToString()):$ConnectPort" `
            --proxytunnel --connect-timeout 5 --max-time 10 https://example.com/
        if ($LASTEXITCODE -ne 0 -or ($body -join "`n") -notmatch 'Example Domain') {
            throw 'HTTPS through paired tunnel and Smithproxy CONNECT failed'
        }
        Write-Output 'PASS: Windows curl -> paired Wintun/Tuntom -> Smithproxy CONNECT -> HTTPS'
    }
    if (!$process.WaitForExit(50000)) { throw 'Paired probe exceeded its lifetime' }
    if ($process.ExitCode -ne 0) { throw "Paired probe failed: $($process.ExitCode)" }
    if ($WholeHostTest) {
        if ($guard.HasExited) { throw 'Host guard exited before tunnel-loss check' }
        & curl.exe -4 --silent --show-error --noproxy '*' --resolve "example.com:80:$testIp" `
            --connect-timeout 2 --max-time 3 http://example.com/ | Out-Null
        if ($LASTEXITCODE -eq 0 -or $guard.HasExited) { throw 'Direct fallback succeeded or guard was lost' }
        Write-Output 'PASS: public HTTP fails after tunnel teardown while egress guard remains alive'
    }
} finally {
    # Retire only our exact route objects before allowing ordinary egress again.
    # Wintun teardown also removes its /1 routes if the script is interrupted.
    foreach ($route in $ownedRoutes) {
        $present = Get-NetRoute -DestinationPrefix $route.DestinationPrefix -InterfaceIndex $route.InterfaceIndex `
            -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -eq $route.NextHop -and $_.RouteMetric -eq $route.RouteMetric }
        if ($present) { $present | Remove-NetRoute -Confirm:$false }
    }
    if ($stopEvent) { $null = $stopEvent.Set() }
    if ($guard -and !$guard.HasExited -and !$guard.WaitForExit(5000)) { $guard.Kill(); $guard.WaitForExit() }
    if ($readyEvent) { $readyEvent.Dispose() }
    if ($stopEvent) { $stopEvent.Dispose() }
    # Let the bounded owner close its lease and adapter. Kill only this exact
    # retained child handle if the probe fails to honor its lifetime.
    if (!$process.HasExited -and !$process.WaitForExit(60000)) { $process.Kill(); $process.WaitForExit() }
    Get-Content $stdout
    Get-Content $stderr
    if ((DefaultRoutes) -ne $before) { throw 'Default routing changed' }
    if (Get-NetAdapter -Name $name -IncludeHidden -ErrorAction SilentlyContinue) {
        throw "Paired test adapter remains: $name"
    }
}
Write-Output 'PASS: paired tunnel probe and adapter cleanup; default routes unchanged'
