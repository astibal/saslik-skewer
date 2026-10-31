param([Parameter(Mandatory=$true)][string]$Directory,
      [Parameter(Mandatory=$true)][string]$Service,
      [string]$HostName='example.com',
      [string]$RecoveryPeer='')
$ErrorActionPreference='Stop'
# Elevated disposable paired service only. Select this fixture process and its
# curl children, never the SSH server or unrelated interactive applications.
$client=Join-Path $Directory 'skewer-routing-control.exe'
$address=(Resolve-DnsName $HostName -Type A -DnsOnly | Where-Object Type -eq A | Select-Object -First 1).IPAddress
if (!$address) { throw 'Cannot resolve HTTPS fixture before selection' }
function AwaitActive {
    for ($i=0; $i -lt 100; ++$i) {
        $state=& $client status $Service | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0) { throw 'Status failed' }
        if ($state.phase -eq 2) { return $state }
        Start-Sleep -Milliseconds 100
    }
    throw 'Active timeout'
}
function Https {
    & curl.exe --noproxy '*' -4 -k --silent --max-time 5 --resolve "${HostName}:443:$address" --output NUL "https://${HostName}/"
    return $LASTEXITCODE
}
$firewallRule=$null
if ($RecoveryPeer) {
    $ip=$null
    if (![Net.IPAddress]::TryParse($RecoveryPeer, [ref]$ip) -or $ip.AddressFamily -ne 'InterNetwork') {
        throw 'RecoveryPeer must be a numeric IPv4 address'
    }
    if ($Service -notmatch '^SkewerRouting-Test-[a-f0-9]{32}$') {
        throw 'Recovery injection requires a disposable fixture service'
    }
    $entry=Get-CimInstance Win32_Service -Filter "Name='$Service'"
    if ($entry.PathName -notmatch '^"([^"]+)" --service ') { throw 'Cannot identify fixture service executable' }
    $serviceExe=$Matches[1]
}
$initial=& $client status $Service | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $initial.phase -ne 0 -or !$initial.paired) {
    throw 'Pause fixture requires a paired idle service'
}
try {
    $birth=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToFileTimeUtc()
    & $client attach $Service $initial.generation $PID $birth
    if ($LASTEXITCODE -ne 0) { throw 'Attach failed' }
    $active=AwaitActive
    if ((Https) -ne 0) { throw 'Baseline HTTPS failed' }
    if ($RecoveryPeer) {
        # Isolate only this disposable service's data transport, not SSH or the
        # appliance control endpoint. The lab allocates UDP ports in this range.
        $firewallRule='SkewerPauseRecovery-'+[Guid]::NewGuid().ToString('N')
        New-NetFirewallRule -Name $firewallRule -DisplayName $firewallRule -Direction Outbound `
            -Action Block -Protocol UDP -RemoteAddress $RecoveryPeer -RemotePort '40001-40255' `
            -Program $serviceExe | Out-Null
        $deadline=(Get-Date).AddSeconds(45)
        do {
            $lost=& $client status $Service | ConvertFrom-Json
            if ($LASTEXITCODE -ne 0) { throw 'Recovery status failed' }
            if ($lost.phase -eq 3) { break }
            Start-Sleep -Milliseconds 200
        } while ((Get-Date) -lt $deadline)
        if ($lost.phase -ne 3 -or $lost.generation -ne $active.generation) {
            throw 'Transport loss did not retain a blocked routing generation'
        }
        if ((Https) -eq 0) { throw 'HTTPS escaped after transport loss' }
    }
    $paused=& $client pause $Service $active.generation | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or !$paused.pauseAvailable -or !$paused.paused -or
        $paused.phase -ne 3 -or $paused.generation -ne $active.generation) {
        throw 'Pause not acknowledged'
    }
    if ((Https) -eq 0) { throw 'HTTPS escaped protected pause' }
    if ($RecoveryPeer) {
        Remove-NetFirewallRule -Name $firewallRule
        $firewallRule=$null
        # A restored path must not undo explicit user intent. Observe the same
        # generation repeatedly rather than accepting a single transient sample.
        for ($i=0; $i -lt 50; ++$i) {
            $held=& $client status $Service | ConvertFrom-Json
            if ($LASTEXITCODE -ne 0 -or !$held.paused -or $held.phase -ne 3 -or
                $held.generation -ne $active.generation) { throw 'Path recovery lost protected pause' }
            Start-Sleep -Milliseconds 200
        }
        if ((Https) -eq 0) { throw 'Restored transport bypassed pause' }
    }
    $stale=& $client resume $Service ([uint64]$active.generation-1) | ConvertFrom-Json
    if ($stale.result -ne 1 -or $stale.phase -ne 3) { throw 'Stale resume changed pause' }
    & $client resume $Service $active.generation
    if ($LASTEXITCODE -ne 0) { throw 'Resume failed' }
    $resumed=AwaitActive
    if ($resumed.paused -or $resumed.generation -ne $active.generation -or (Https) -ne 0) {
        throw 'Resume did not preserve healthy routing'
    }
    'PASS: selected HTTPS blocked during acknowledged pause; stale resume rejected; same-generation HTTPS restored'
    if ($RecoveryPeer) { 'PASS: live transport loss, paused path recovery and explicit Resume retain the selected generation' }
} finally {
    if ($firewallRule) { Remove-NetFirewallRule -Name $firewallRule }
    # Scope cleanup to this exact root, including a partially successful Attach.
    $state=& $client status $Service | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect pause fixture cleanup' }
    if ($state.selections | Where-Object { $_.pid -eq $PID -and $_.birth -eq "$birth" }) {
        & $client remove $Service $state.generation $PID $birth
        if ($LASTEXITCODE -ne 0) { throw 'Pause fixture Release failed' }
    }
}
