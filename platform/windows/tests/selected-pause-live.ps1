param([Parameter(Mandatory=$true)][string]$Directory,
      [Parameter(Mandatory=$true)][string]$Service,
      [string]$HostName='example.com')
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
    $paused=& $client pause $Service $active.generation | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $paused.phase -ne 3 -or $paused.generation -ne $active.generation) {
        throw 'Pause not acknowledged'
    }
    if ((Https) -eq 0) { throw 'HTTPS escaped protected pause' }
    $stale=& $client resume $Service ([uint64]$active.generation-1) | ConvertFrom-Json
    if ($stale.result -ne 1 -or $stale.phase -ne 3) { throw 'Stale resume changed pause' }
    & $client resume $Service $active.generation
    if ($LASTEXITCODE -ne 0) { throw 'Resume failed' }
    $resumed=AwaitActive
    if ($resumed.generation -ne $active.generation -or (Https) -ne 0) {
        throw 'Resume did not preserve healthy routing'
    }
    'PASS: selected HTTPS blocked during acknowledged pause; stale resume rejected; same-generation HTTPS restored'
} finally {
    # Scope cleanup to this exact root, including a partially successful Attach.
    $state=& $client status $Service | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect pause fixture cleanup' }
    if ($state.selections | Where-Object { $_.pid -eq $PID -and $_.birth -eq "$birth" }) {
        & $client remove $Service $state.generation $PID $birth
        if ($LASTEXITCODE -ne 0) { throw 'Pause fixture Release failed' }
    }
}
