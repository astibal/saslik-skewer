param(
    [string]$Directory = 'C:\SkewerDev\skewer-windows-app',
    [string]$DriverDirectory = 'C:\SkewerDev\flow-test',
    [string]$WintunDll = 'C:\SkewerDev\wintun-test\wintun.dll',
    [Parameter(Mandatory=$true)][string]$Gateway,
    [string]$Endpoint = 'skewer://172.30.1.73:8766/pair',
    [string]$Peer = '172.30.1.73'
)

$ErrorActionPreference = 'Stop'
$name = 'SkewerRouting-Test-' + [Guid]::NewGuid().ToString('N')
$client = Join-Path $Directory 'skewer-routing-control.exe'
$created = $false

function NetworkState {
    @{
        Routes = @(Get-NetRoute | Sort-Object InterfaceIndex,DestinationPrefix,NextHop |
            Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)
        Dns = @(Get-DnsClientServerAddress | Sort-Object InterfaceIndex,AddressFamily |
            Select-Object InterfaceIndex,AddressFamily,ServerAddresses)
    } | ConvertTo-Json -Depth 6 -Compress
}

function Status {
    $value = & $client status $name | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Direct routing status failed' }
    return $value
}

function AwaitPhase([int]$phase) {
    $deadline = (Get-Date).AddSeconds(15)
    do {
        $value = Status
        if ($value.phase -eq $phase) { return $value }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    throw "Expected routing phase $phase; got $($value.phase)"
}

$before = NetworkState
try {
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & (Join-Path $Directory 'install-routing-service.ps1') -PackageDirectory $Directory `
        -WinDivertDirectory $DriverDirectory -WintunDll $WintunDll -OwnerSid $owner `
        -Endpoint $Endpoint -Peer $Peer -Name $name
    $created = $true
    $initial = AwaitPhase 0
    if ($initial.paired) { throw 'Fresh direct fixture unexpectedly retained pairing' }
    $started = & $client start-direct $name $initial.generation $Gateway | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $started.scope -ne 1 -or $started.transport -ne 2) {
        throw 'Direct whole-host start was rejected or misreported'
    }
    $active = AwaitPhase 2
    if ($active.scope -ne 1 -or $active.transport -ne 2 -or $active.paired) {
        throw 'Direct whole-host generation did not become Active without pairing'
    }
    $owned = @(Get-NetRoute -AddressFamily IPv4 | Where-Object {
        $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1') -and $_.NextHop -eq $Gateway
    })
    if ($owned.Count -ne 2) { throw 'Direct routing did not install both covering routes' }
    & curl.exe --noproxy '*' -4 --fail --silent --show-error --max-time 12 `
        --output NUL 'http://example.com/'
    if ($LASTEXITCODE -ne 0) { throw 'Plain HTTP failed through direct whole-host routing' }
    & curl.exe --noproxy '*' -4 --fail --silent --show-error --max-time 12 `
        --output NUL 'https://example.com/'
    if ($LASTEXITCODE -ne 0) { throw 'HTTPS failed through direct whole-host routing' }
    $null = & $client stop $name $active.generation | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Direct whole-host Stop failed' }
    $null = AwaitPhase 0
} finally {
    if ($created -or (Get-Service -Name $name -ErrorAction SilentlyContinue)) {
        $service = Get-Service $name
        try {
            if ($service.Status -ne 'Stopped') { Stop-Service $name }
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
        } finally { $service.Dispose() }
        $entry = Get-CimInstance Win32_Service -Filter "Name='$name'"
        if ((Invoke-CimMethod -InputObject $entry -MethodName Delete).ReturnValue -ne 0) {
            throw 'Direct fixture service cleanup failed'
        }
    }
    Write-Output "Fixture files retained in Program Files\$name"
}

if ((NetworkState) -cne $before) { throw 'Direct fixture changed persistent routes or DNS' }
Write-Output 'PASS: direct whole-host HTTP/HTTPS, authoritative status and owned-route cleanup'
