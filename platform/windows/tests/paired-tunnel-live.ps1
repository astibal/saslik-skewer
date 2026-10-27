param(
    [Parameter(Mandatory=$true)][string]$Directory,
    [Parameter(Mandatory=$true)][string]$WintunDll,
    [Parameter(Mandatory=$true)][string]$Endpoint,
    [Parameter(Mandatory=$true)][string]$Peer,
    [ValidateRange(0,65535)][int]$ConnectPort = 0
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
    # Validate again before privileged configuration, even though the C++ control
    # client already validates the authenticated address contract.
    if ($metadata.server_address -notmatch '^10\.([0-9]+)\.([0-9]+)\.([0-9]+)/30$' -or
        $metadata.client_address -notmatch '^10\.([0-9]+)\.([0-9]+)\.([0-9]+)/30$') { throw 'Invalid tunnel prefix' }
    $server = ([System.Net.IPAddress]::Parse($metadata.server_address.Split('/')[0]))
    $client = ([System.Net.IPAddress]::Parse($metadata.client_address.Split('/')[0]))
    $s = $server.GetAddressBytes(); $c = $client.GetAddressBytes()
    if ($s[1] -ne $c[1] -or $s[2] -ne $c[2] -or $s[3] % 4 -ne 1 -or $c[3] -ne $s[3] + 1) {
        throw 'Invalid tunnel address pair'
    }
    foreach ($destination in @($server, $client)) {
        $selected = @(Find-NetRoute -RemoteIPAddress $destination.ToString() |
            Where-Object { $_.PSObject.Properties.Name -contains 'DestinationPrefix' })
        if ($selected.Count -ne 1 -or $selected[0].DestinationPrefix -ne '0.0.0.0/0') {
            throw 'Tunnel subnet overlaps an existing route; refusing to override it'
        }
    }
    $adapter = Get-NetAdapter -Name $name
    Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -NlMtuBytes 1280 `
        -Dhcp Disabled -PolicyStore ActiveStore
    New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $client.ToString() `
        -PrefixLength 30 -PolicyStore ActiveStore | Out-Null
    $deadline = (Get-Date).AddSeconds(8)
    do {
        $address = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $client.ToString()
        if ($address.AddressState -eq 'Preferred') { break }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    if ($address.AddressState -ne 'Preferred') { throw 'Tunnel address did not complete DAD' }
    $successes = 0
    for ($attempt = 0; $attempt -lt 6 -and $successes -lt 3; ++$attempt) {
        & ping.exe -4 -S $client.ToString() -n 1 -w 1000 $server.ToString()
        if ($LASTEXITCODE -eq 0) { ++$successes }
    }
    if ($successes -ne 3) { throw 'Paired Wintun path did not carry three successful pings' }
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
} finally {
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
