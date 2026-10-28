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
} finally {
    if ($installed) {
        & $remover -Name $name -Confirm:$false
    }
}

if ((Get-Service $name -ErrorAction SilentlyContinue) -or (Test-Path $root)) {
    throw 'Upgrade fixture cleanup left service or protected runtime behind'
}
Write-Output 'PASS: Direct-only install -> tunnel-ready upgrade -> clean removal'
