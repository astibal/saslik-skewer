param(
    [Parameter(Mandatory=$true)][string]$Directory,
    [Parameter(Mandatory=$true)][string]$WinDivertDirectory,
    [Parameter(Mandatory=$true)][string]$WintunDll,
    [Parameter(Mandatory=$true)][string]$Endpoint,
    [Parameter(Mandatory=$true)][string]$Peer,
    [Parameter(Mandatory=$true)][string]$Management,
    [string]$DnsServer = '1.1.1.1',
    [switch]$TestTunnelLoss,
    [switch]$GuiClient
)
$ErrorActionPreference = 'Stop'
# Elevated disposable VM only. Real whole-host routing, explicit SSH return-path
# allowance. DNS is pre-resolved because resolver policy is a separate work item.
$name = 'SkewerNative-' + [guid]::NewGuid().ToString('N')
$root = Join-Path $env:ProgramFiles $name
$null = New-Item -ItemType Directory -Path $root
$exe = Join-Path $root 'skewer-routing-service.exe'
$client = Join-Path $Directory 'skewer-routing-control.exe'
Copy-Item (Join-Path $Directory 'skewer-routing-service.exe') $exe
Get-ChildItem $Directory -Filter '*.dll' | Copy-Item -Destination $root
Copy-Item $WintunDll (Join-Path $root 'wintun.dll')
if ((Get-AuthenticodeSignature (Join-Path $root 'wintun.dll')).Status -ne 'Valid') { throw 'Invalid Wintun signature' }
$hashes = @{
    'WinDivert.dll' = 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'
    'WinDivert64.sys' = '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'
}
foreach ($file in $hashes.Keys) {
    Copy-Item (Join-Path $WinDivertDirectory $file) (Join-Path $root $file)
    if ((Get-FileHash (Join-Path $root $file)).Hash -ne $hashes[$file]) { throw 'Unverified WinDivert' }
}
if ((Get-AuthenticodeSignature (Join-Path $root 'WinDivert64.sys')).Status -ne 'Valid') { throw 'Invalid driver signature' }
foreach ($address in @($Peer, $Management, $DnsServer)) {
    $ip = $null
    if (![Net.IPAddress]::TryParse($address, [ref]$ip) -or $ip.AddressFamily -ne 'InterNetwork') {
        throw 'Numeric IPv4 peer and management addresses required'
    }
}
if ($Endpoint -notmatch '^skewer://[A-Za-z0-9.-]+:[0-9]+/pair$') { throw 'Invalid paired endpoint' }
$prefixes = @('0.0.0.0/1', '128.0.0.0/1', "$Peer/32")
foreach ($prefix in $prefixes) {
    if (Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue) { throw "Existing route: $prefix" }
}
function Defaults {
    @(Get-NetRoute | Where-Object DestinationPrefix -In @('0.0.0.0/0','::/0') |
      Sort-Object InterfaceIndex,DestinationPrefix | Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric) |
      ConvertTo-Json -Compress
}
function DnsState {
    @(Get-DnsClientServerAddress | Sort-Object InterfaceIndex,AddressFamily |
      Select-Object InterfaceIndex,AddressFamily,ServerAddresses) | ConvertTo-Json -Compress -Depth 4
}
function Status {
    $output = & $client status $name
    if ($LASTEXITCODE -ne 0) { throw 'Service status failed' }
    $output | ConvertFrom-Json
}
function Await([int]$phase) {
    for ($i = 0; $i -lt 300; ++$i) {
        $state = Status
        if ($state.phase -eq $phase) { return $state }
        if ($state.phase -eq 5) { throw 'Service worker failed' }
        Start-Sleep -Milliseconds 100
    }
    throw "Expected phase $phase, got $($state.phase): $($state.detail)"
}
$before = Defaults
$dnsBefore = DnsState
$testIp = (Resolve-DnsName example.com -Type A -DnsOnly | Where-Object Type -EQ A | Select-Object -First 1).IPAddress
if (!$testIp) { throw 'Cannot pre-resolve HTTPS destination' }
$created = $false
$firewallRule = $null
try {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $command = '"' + $exe + '" --service ' + $name + ' ' + $sid + ' ' + $Endpoint + ' ' + $Peer + ' ' + $DnsServer + ' ' + $Management
    $result = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
        Name=$name; DisplayName=$name; PathName=$command; ServiceType=[byte]16
        ErrorControl=[byte]1; StartMode='Manual'; StartName='LocalSystem'
    }
    if ($result.ReturnValue -ne 0) { throw 'Create native routing service failed' }
    $created = $true
    Start-Service $name
    $state = Await 0
    if (!$state.tunnelAvailable -or !$state.directAvailable) {
        throw 'Tunnel-ready service did not report both routing capabilities'
    }
    if ($GuiClient) {
        & (Join-Path $Directory 'routing_panel_test.exe') --live $name $Endpoint
        if ($LASTEXITCODE -ne 0) { throw 'GUI pairing/start test failed' }
    } else {
        & $client pair $name $Endpoint
        if ($LASTEXITCODE -ne 0) { throw 'Stored pairing handoff failed' }
        & $client start $name $state.generation
        if ($LASTEXITCODE -ne 0) { throw 'Start failed' }
    }
    $active = Await 2
    $adapter = Get-NetAdapter -Name "Skewer-$name"
    $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4
    if ($dns.ServerAddresses -notcontains $DnsServer) { throw 'Native tunnel DNS was not configured' }
    foreach ($prefix in $prefixes[0..1]) {
        $route = Get-NetRoute -DestinationPrefix $prefix -InterfaceIndex $adapter.ifIndex
        if (!$route) { throw "Missing native route: $prefix" }
    }
    $pin = Get-NetRoute -DestinationPrefix "$Peer/32"
    if ($pin.InterfaceIndex -eq $adapter.ifIndex) { throw 'Transport peer routed into its own tunnel' }
    foreach ($scheme in @('http','https')) {
        $port = if ($scheme -eq 'http') { 80 } else { 443 }
        $body = & curl.exe -4 --silent --show-error --fail --insecure --noproxy '*' `
            --resolve "example.com:$($port):$testIp" --connect-timeout 5 --max-time 10 "$($scheme)://example.com/"
        if ($LASTEXITCODE -ne 0 -or ($body -join "`n") -notmatch 'Example Domain') { throw "$scheme routing failed" }
    }
    Write-Output 'PASS: real SCM service -> Wintun/Tuntom -> Smithproxy -> HTTP/HTTPS, without explicit proxy'
    Clear-DnsClientCache
    $resolved = Resolve-DnsName example.com -Type A -DnsOnly -ErrorAction Stop
    if (!$resolved) { throw 'System DNS resolution failed through the tunnel' }
    $body = & curl.exe -4 --silent --show-error --fail --insecure --noproxy '*' `
        --connect-timeout 5 --max-time 15 https://example.com/
    if ($LASTEXITCODE -ne 0 -or ($body -join "`n") -notmatch 'Example Domain') { throw 'HTTPS with system DNS failed' }
    Write-Output 'PASS: system DNS and HTTPS without --resolve through the tunnel'
    if ($TestTunnelLoss) {
        # Remove only this service's authenticated UDP transport. The owned
        # Wintun device stays intact, so this tests remote/path loss rather
        # than administratively deleting the local packet device.
        $firewallRule = 'SkewerTunnelLoss-' + [guid]::NewGuid().ToString('N')
        New-NetFirewallRule -Name $firewallRule -DisplayName $firewallRule -Direction Outbound `
            -Action Block -Protocol UDP -RemoteAddress $Peer -RemotePort '40001-40255' `
            -Program $exe | Out-Null
        $null = Await 3
        if ((Get-Service $name).Status -ne 'Running') { throw 'Tunnel failure stopped the service guard' }
        & curl.exe -4 --silent --show-error --noproxy '*' --resolve "example.com:80:$testIp" `
            --connect-timeout 2 --max-time 3 http://example.com/ | Out-Null
        if ($LASTEXITCODE -eq 0) { throw 'Direct fallback succeeded after tunnel loss' }
        Write-Output 'PASS: lost tunnel stays Blocked and public HTTP cannot fall back directly'
        Remove-NetFirewallRule -Name $firewallRule
        $firewallRule = $null
        $active = Await 2
        $body = & curl.exe -4 --silent --show-error --fail --insecure --noproxy '*' `
            --resolve "example.com:443:$testIp" --connect-timeout 5 --max-time 15 https://example.com/
        if ($LASTEXITCODE -ne 0 -or ($body -join "`n") -notmatch 'Example Domain') {
            throw 'Recovered whole-host tunnel did not carry HTTPS'
        }
        Write-Output 'PASS: replacement lease returns Blocked routing to Active without direct fallback'
    }
    & $client stop $name $active.generation
    if ($LASTEXITCODE -ne 0) { throw 'Stop failed' }
    $null = Await 0
} finally {
    if ($firewallRule) {
        Remove-NetFirewallRule -Name $firewallRule -ErrorAction SilentlyContinue
    }
    if ($created) {
        Stop-Service $name
        $service = Get-Service $name
        try { $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20)) } finally { $service.Dispose() }
        $state = Get-CimInstance Win32_Service -Filter "Name='$name'"
        if ((Invoke-CimMethod -InputObject $state -MethodName Delete).ReturnValue -ne 0) { throw 'Service cleanup failed' }
    }
    if ((Defaults) -ne $before) { throw 'Default routing changed' }
    if ((DnsState) -ne $dnsBefore) { throw 'DNS settings of pre-existing adapters changed' }
    foreach ($prefix in $prefixes) {
        if (Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue) { throw "Owned route remains: $prefix" }
    }
    if (Get-NetAdapter -Name "Skewer-$name" -IncludeHidden -ErrorAction SilentlyContinue) { throw 'Owned adapter remains' }
    Write-Output "Fixture binaries retained at $root"
}
Write-Output 'PASS: native service Stop, retained failure outcome if injected, SCM cleanup, routes and adapter removed'
