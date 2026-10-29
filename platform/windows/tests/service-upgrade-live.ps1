param(
    [Parameter(Mandatory=$true)][string]$Directory,
    [Parameter(Mandatory=$true)][string]$Endpoint,
    [Parameter(Mandatory=$true)][string]$Peer
)

$ErrorActionPreference = 'Stop'
$name = 'SkewerRouting-Test-' + [Guid]::NewGuid().ToString('N')
$root = Join-Path $env:ProgramFiles $name
$installer = Join-Path $Directory 'install-routing-service.ps1'
$remover = Join-Path $Directory 'remove-routing-service.ps1'
$client = Join-Path $Directory 'skewer-routing-control.exe'
$owner = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$installed = $false

function Status {
    $value = & $client status $name | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Routing service status failed' }
    return $value
}

try {
    if ((Get-Service $name -ErrorAction SilentlyContinue) -or (Test-Path $root)) {
        throw 'Disposable upgrade target already exists'
    }
    & $installer -PackageDirectory $Directory -OwnerSid $owner -Name $name
    $installed = $true
    $direct = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if ($direct.PathName -match 'skewer://' -or $direct.State -ne 'Running') {
        throw 'Initial service is not running in Direct-only configuration'
    }
    $state = Status
    if ($state.phase -ne 0 -or $state.paired) {
        throw 'Initial Direct-only service is not unpaired and Idle'
    }

    & $installer -PackageDirectory $Directory -OwnerSid $owner -Name $name `
        -Endpoint $Endpoint -Peer $Peer -Upgrade
    $tunnel = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if ($tunnel.PathName -notmatch [regex]::Escape($Endpoint) -or
        $tunnel.PathName -notmatch [regex]::Escape($Peer) -or
        $tunnel.State -ne 'Running' -or $tunnel.StartMode -ne 'Auto') {
        throw 'Upgrade did not install the tunnel-ready automatic service configuration'
    }
    $state = Status
    if ($state.phase -ne 0 -or $state.paired) {
        throw 'Upgraded service did not restart unpaired and Idle'
    }
    # Credentials stay in the user's DPAPI store, not the SYSTEM runtime.
    # A service restart clears its borrowed in-memory pairing; re-handoff must
    # work without requesting another invitation or implicitly starting traffic.
    & $client pair $name $Endpoint
    if ($LASTEXITCODE -ne 0 -or !(Status).paired) { throw 'Initial stored pairing handoff failed' }
    & $installer -PackageDirectory $Directory -OwnerSid $owner -Name $name `
        -Endpoint $Endpoint -Peer $Peer -Upgrade
    $state = Status
    if ($state.phase -ne 0 -or $state.paired) { throw 'Upgrade retained runtime credentials or started routing' }
    & $client pair $name $Endpoint
    if ($LASTEXITCODE -ne 0) { throw 'Stored pairing was unavailable after service upgrade' }
    $state = Status
    if ($state.phase -ne 0 -or !$state.paired) { throw 'Pairing restoration changed routing state' }
    if ((Get-FileHash (Join-Path $root 'skewer-routing-service.exe')).Hash -ne
        (Get-FileHash (Join-Path $Directory 'skewer-routing-service.exe')).Hash) {
        throw 'Upgraded service binary differs from the requested package'
    }
    if (Get-Command Start-Service -CommandType Function -ErrorAction SilentlyContinue) {
        throw 'Refusing to shadow an existing Start-Service test function'
    }
    foreach ($failRollback in @($false,$true)) {
        $beforeBackups=@(Get-ChildItem ([IO.Path]::GetTempPath()) -Directory -Filter 'skewer-upgrade-*' |
            ForEach-Object FullName)
        $failStarts=[Collections.Generic.Queue[bool]]::new()
        $failStarts.Enqueue($true)
        $failStarts.Enqueue($failRollback)
        # Script-scoped fault injection affects only this disposable installer
        # invocation. Always restore the real cmdlet before fixture cleanup.
        function Start-Service {
            param([string]$Name)
            if ($failStarts.Dequeue()) { throw 'Injected service-start failure' }
            Microsoft.PowerShell.Management\Start-Service -Name $Name
        }
        $failed=$false
        try {
            & $installer -PackageDirectory $Directory -OwnerSid $owner -Name $name `
                -Endpoint $Endpoint -Peer $Peer -Upgrade
        } catch {
            $failed=$true
        } finally {
            Remove-Item Function:\Start-Service
        }
        if (!$failed -or $failStarts.Count -ne 0) { throw 'Upgrade did not exercise both start and rollback' }
        $retained=@(Get-ChildItem ([IO.Path]::GetTempPath()) -Directory -Filter 'skewer-upgrade-*' |
            Where-Object { $_.FullName -notin $beforeBackups })
        if (!$failRollback -and $retained.Count -ne 0) { throw 'Successful rollback retained redundant backup' }
        if ($failRollback) {
            if ($retained.Count -ne 1) { throw 'Failed rollback lost its recovery backup' }
            if (!(Get-Acl -LiteralPath $retained[0].FullName).AreAccessRulesProtected) {
                throw 'Recovery backup inherits untrusted directory access'
            }
            $recovery=Get-Content -LiteralPath (Join-Path $retained[0].FullName 'service.json') -Raw | ConvertFrom-Json
            if ($recovery.Service -ne $name -or $recovery.StartMode -ne 'Automatic' -or
                $recovery.PathName -ne (Get-CimInstance Win32_Service -Filter "Name='$name'").PathName) {
                throw 'Recovery backup lost the original service configuration'
            }
            $backupBinary=Join-Path $retained[0].FullName 'skewer-routing-service.exe'
            if ((Get-FileHash $backupBinary).Hash -ne
                (Get-FileHash (Join-Path $Directory 'skewer-routing-service.exe')).Hash) {
                throw 'Retained recovery backup is invalid'
            }
            Start-Service $name
        }
        $state=Status
        if ($state.phase -ne 0) { throw 'Recovered service started routing implicitly' }
        # The injected failure is resolved and the verified original service
        # runs again. Remove only the backup created by this test invocation.
        if ($failRollback) { Remove-Item -LiteralPath $retained[0].FullName -Recurse -Force }
    }
} finally {
    if ($installed) {
        & $remover -Name $name -Confirm:$false
    }
}

if ((Get-Service $name -ErrorAction SilentlyContinue) -or (Test-Path $root)) {
    throw 'Upgrade fixture cleanup left service or protected runtime behind'
}
Write-Output 'PASS: install, upgrade, pairing restoration, failed-upgrade rollback, protected recovery backup and clean removal'
