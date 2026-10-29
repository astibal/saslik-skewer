param(
    [string]$Directory='C:\SkewerDev\skewer-windows-app',
    [string]$FixtureDirectory=$Directory,
    [string]$DriverDirectory='C:\SkewerDev\flow-test',
    [string]$WintunDll='C:\SkewerDev\wintun-test\wintun.dll',
    [string]$Endpoint='skewer://172.30.1.73:8766/pair',
    [string]$Peer='172.30.1.73',
    [string]$Destination='',
    [string]$HostName='example.com',
    [switch]$SkipGuiSmoke
)
$ErrorActionPreference='Stop'
# Elevated disposable VM only. Broad IPv4 TCP capture, no route/DNS changes.
if (!$Destination) {
    $Destination = (Resolve-DnsName $HostName -Type A -DnsOnly |
        Where-Object Type -EQ A | Select-Object -First 1).IPAddress
}
if (!$Destination) { throw 'Cannot pre-resolve selected HTTPS destination' }
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
    & (Join-Path $FixtureDirectory 'routed_launch_test.exe') $name
    if ($LASTEXITCODE -ne 0) { throw 'Rejected routed launch executed child code' }
    & $client pair $name $Endpoint
    if ($LASTEXITCODE -ne 0) { throw 'Selected fixture pairing failed' }
    if (!$SkipGuiSmoke) {
        Set-Content 'C:\SkewerDev\routed-service-name.txt' $name
        & (Join-Path $FixtureDirectory 'run-routed-application-smoke.ps1') `
            -Directory $Directory -FixtureDirectory $FixtureDirectory
        if ($LASTEXITCODE -ne 0) { throw 'GUI routed launch test failed' }
    }
    & (Join-Path $FixtureDirectory 'selected_process_live.exe') $Endpoint $Peer $Destination $HostName $name
    if ($LASTEXITCODE -ne 0) { throw 'SCM selected process test failed' }
    & (Join-Path $FixtureDirectory 'selected_process_live.exe') $Endpoint $Peer $Destination $HostName $name '--descendant'
    if ($LASTEXITCODE -ne 0) { throw 'SCM selected descendant test failed' }
    & (Join-Path $FixtureDirectory 'selected_process_live.exe') $Endpoint $Peer $Destination $HostName $name '--existing-descendant'
    if ($LASTEXITCODE -ne 0) { throw 'SCM pre-existing descendant test failed' }
    & (Join-Path $FixtureDirectory 'selected_process_live.exe') $Endpoint $Peer $Destination $HostName $name '--existing-tcp'
    if ($LASTEXITCODE -ne 0) { throw 'SCM pre-Attach TCP cleanup test failed' }
    & (Join-Path $FixtureDirectory 'selected_process_live.exe') $Endpoint $Peer '1.1.1.1' $HostName $name '--existing-udp'
    if ($LASTEXITCODE -ne 0) { throw 'SCM pre-Attach UDP tunnel test failed' }
    & (Join-Path $FixtureDirectory 'selected_process_live.exe') $Endpoint $Peer '1.1.1.1' $HostName $name '--udp'
    if ($LASTEXITCODE -ne 0) { throw 'SCM selected UDP process test failed' }
    & (Join-Path $FixtureDirectory 'selected_process_live.exe') $Endpoint $Peer '1.1.1.1' $HostName $name '--descendant-udp'
    if ($LASTEXITCODE -ne 0) { throw 'SCM selected descendant UDP test failed' }
    & curl.exe --noproxy '*' -4 -k --fail --silent --show-error --max-time 12 `
        --resolve "${HostName}:443:${Destination}" --output NUL "https://${HostName}/"
    if ($LASTEXITCODE -ne 0) { throw 'Unrelated HTTPS unavailable after selected session' }
} catch {
    Write-Warning "Selected service fixture failed: $($_.Exception.Message)"
    $state = & $client status $name 2>&1
    Write-Warning "Routing status: $state"
    $installed = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
    if ($installed -and $installed.ProcessId) {
        $connections = Get-NetTCPConnection -OwningProcess $installed.ProcessId -ErrorAction SilentlyContinue |
            Select-Object State,LocalAddress,LocalPort,RemoteAddress,RemotePort
        Write-Warning "Service PID $($installed.ProcessId) TCP: $($connections | ConvertTo-Json -Compress)"
    }
    throw
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
Write-Output 'PASS: paired SCM selected root/descendant HTTPS and DNS UDP, pre-Attach TCP reset, unique pre-Attach UDP routed, explicit cleanup, unchanged routes and DNS'
