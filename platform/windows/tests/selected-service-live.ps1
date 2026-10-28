param(
    [string]$Directory='C:\SkewerDev\skewer-windows-app',
    [string]$DriverDirectory='C:\SkewerDev\flow-test',
    [string]$WintunDll='C:\SkewerDev\wintun-test\wintun.dll',
    [string]$Endpoint='skewer://172.30.1.73:8766/pair',
    [string]$Peer='172.30.1.73',
    [string]$Destination='172.66.147.243',
    [string]$HostName='example.com'
)
$ErrorActionPreference='Stop'
# Elevated disposable VM only. Broad IPv4 TCP capture, no route/DNS changes.
$name='SkewerRouting-Test-'+[Guid]::NewGuid().ToString('N')
$client=Join-Path $Directory 'skewer-routing-control.exe'
$created=$false
function NetworkState {
    @{
        Routes=@(Get-NetRoute | Sort-Object InterfaceIndex,DestinationPrefix,NextHop |
            Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)
        Dns=@(Get-DnsClientServerAddress | Sort-Object InterfaceIndex,AddressFamily |
            Select-Object InterfaceIndex,AddressFamily,ServerAddresses)
    } | ConvertTo-Json -Depth 6 -Compress
}
$before=NetworkState
try {
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & (Join-Path $Directory 'install-routing-service.ps1') -PackageDirectory $Directory `
        -WinDivertDirectory $DriverDirectory -WintunDll $WintunDll -OwnerSid $owner `
        -Endpoint $Endpoint -Peer $Peer -Name $name
    $created=$true
    $installed=Get-CimInstance Win32_Service -Filter "Name='$name'"
    if ($installed.StartMode -ne 'Auto' -or $installed.State -ne 'Running') {
        throw "Installed routing service is not an automatic idle service"
    }
    & (Join-Path $Directory 'routed_launch_test.exe') $name
    if ($LASTEXITCODE -ne 0) { throw 'Rejected routed launch executed child code' }
    & $client pair $name $Endpoint
    if ($LASTEXITCODE -ne 0) { throw 'Selected fixture pairing failed' }
    Set-Content 'C:\SkewerDev\routed-service-name.txt' $name
    & (Join-Path $Directory 'run-routed-application-smoke.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'GUI routed launch test failed' }
    & (Join-Path $Directory 'selected_process_live.exe') $Endpoint $Peer $Destination $HostName $name
    if ($LASTEXITCODE -ne 0) { throw 'SCM selected process test failed' }
    & curl.exe --noproxy '*' -4 -k --fail --silent --show-error --max-time 12 `
        --resolve "${HostName}:443:${Destination}" --output NUL "https://${HostName}/"
    if ($LASTEXITCODE -ne 0) { throw 'Unrelated HTTPS unavailable after selected session' }
} finally {
    Remove-Item 'C:\SkewerDev\routed-service-name.txt' -ErrorAction SilentlyContinue
    if ($created -or (Get-Service -Name $name -ErrorAction SilentlyContinue)) {
        Stop-Service $name
        $service=Get-Service $name
        try { $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(15)) }
        finally { $service.Dispose() }
        $entry=Get-CimInstance Win32_Service -Filter "Name='$name'"
        if ((Invoke-CimMethod -InputObject $entry -MethodName Delete).ReturnValue -ne 0) {
            throw 'Selected fixture service cleanup failed'
        }
    }
    Write-Output "Fixture files retained in Program Files\$name"
}
if ((NetworkState) -cne $before) { throw 'Selected fixture changed routes or DNS' }
Write-Output 'PASS: paired SCM selected HTTPS, explicit cleanup, unchanged routes and DNS'
