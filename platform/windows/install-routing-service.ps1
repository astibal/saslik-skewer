[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)][string]$PackageDirectory,
    [string]$WinDivertDirectory = '',
    [string]$WintunDll = '',
    [Parameter(Mandatory=$true)][string]$OwnerSid,
    [string]$Endpoint = '',
    [string]$Peer = '',
    [string]$DnsServer = '1.1.1.1',
    [string]$Management = '',
    [switch]$Upgrade,
    [ValidatePattern('^SkewerRouting(?:-Test-[a-f0-9]{32})?$')][string]$Name = 'SkewerRouting'
)
$ErrorActionPreference = 'Stop'
$PackageDirectory = (Resolve-Path -LiteralPath $PackageDirectory).Path
if (!$WinDivertDirectory) { $WinDivertDirectory = $PackageDirectory }
if (!$WintunDll) { $WintunDll = Join-Path $PackageDirectory 'wintun.dll' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer elevated. The desktop application itself must remain unelevated.'
}
$sid = [Security.Principal.SecurityIdentifier]::new($OwnerSid)
if ($sid.Value -cne $OwnerSid) { throw 'OwnerSid must be canonical' }
$tunnelConfigured = !!$Endpoint -or !!$Peer
if (!!$Endpoint -ne !!$Peer) { throw 'Endpoint and Peer must be configured together' }
if ($tunnelConfigured) {
    if ($Endpoint -notmatch '^skewer://[A-Za-z0-9.-]+:[0-9]{1,5}/pair$') { throw 'Expected paired endpoint, never an invitation or secret' }
    $uri = [Uri]$Endpoint
    if ($uri.Port -lt 1 -or $uri.Port -gt 65535) { throw 'Invalid endpoint port' }
}
foreach ($address in @($Peer,$DnsServer) + @($Management | Where-Object { $_ }) |
         Where-Object { $_ }) {
    $ip = $null
    if (![Net.IPAddress]::TryParse($address, [ref]$ip) -or $ip.AddressFamily -ne 'InterNetwork' -or $ip.ToString() -ne $address) {
        throw 'Peer, DNS and optional SSH management must be canonical IPv4 addresses'
    }
}
$root = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) $Name
$existingRoot = Test-Path -LiteralPath $root
$existingService = $null -ne (Get-Service -Name $Name -ErrorAction SilentlyContinue)
if ($existingRoot -ne $existingService) {
    throw 'Inconsistent installation: service and protected runtime directory must either both exist or both be absent'
}
if (($existingRoot -or $existingService) -and !$Upgrade) {
    throw 'Service already exists; use -Upgrade for an explicit stopped-service update'
}
if ($Upgrade -and !$existingService) { throw 'Cannot upgrade a service that is not installed' }
$files = @('skewer-routing-service.exe','skewer-routing-control.exe','Qt6Core.dll','Qt6Network.dll',
           'libgcc_s_seh-1.dll','libstdc++-6.dll','libwinpthread-1.dll','libssp-0.dll')
$sources = @{}
foreach ($file in $files) { $sources[$file] = Join-Path $PackageDirectory $file }
$sources['wintun.dll'] = $WintunDll
$sources['WinDivert.dll'] = Join-Path $WinDivertDirectory 'WinDivert.dll'
$sources['WinDivert64.sys'] = Join-Path $WinDivertDirectory 'WinDivert64.sys'
foreach ($source in $sources.Values) {
    $item = Get-Item -LiteralPath $source
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Expected a regular installation file: $source"
    }
}
function Get-Sha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    try {
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            return ([BitConverter]::ToString($sha256.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
        } finally {
            $sha256.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}
function Set-DirectoryAcl([string]$Path, [Security.AccessControl.DirectorySecurity]$Acl) {
    # Invoke the .NET Framework API directly. Silent setup can inherit a
    # PowerShell module path from its parent that cannot load Set-Acl.
    [IO.DirectoryInfo]::new($Path).SetAccessControl($Acl)
}
function VerifyDrivers([string]$Directory, [hashtable]$Paths) {
    # Pin the exact, reviewed upstream artifacts. This is both stricter and
    # more reliable than loading Authenticode cmdlets from a silent installer,
    # where the inherited PowerShell module path is not under our control.
    $hashes = @{
        'wintun.dll' = 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce'
        'WinDivert.dll' = 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'
        'WinDivert64.sys' = '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'
    }
    foreach ($file in $hashes.Keys) {
        $path = if ($Directory) { Join-Path $Directory $file } else { $Paths[$file] }
        if ((Get-Sha256 $path) -ne $hashes[$file]) { throw "Unverified driver artifact: $file" }
    }
}
function CopyRuntimeFile([string]$Source, [string]$Destination) {
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try {
            Copy-Item -LiteralPath $Source -Destination $Destination -Force
            return
        } catch [IO.IOException] {
            if ($attempt -eq 29) { throw }
            Start-Sleep -Milliseconds 100
        }
    }
}
function SetRecoveryPolicy([string]$ServiceName) {
    & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot configure routing service restart actions' }
    # Also apply the actions when the service exits with a service-specific
    # error instead of crashing the process outright.
    & sc.exe failureflag $ServiceName 1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot enable routing service non-crash recovery' }
}
VerifyDrivers '' $sources
$exe = Join-Path $root 'skewer-routing-service.exe'
$command = '"' + $exe + '" --service ' + $Name + ' ' + $OwnerSid
if ($tunnelConfigured) {
    $command += ' ' + $Endpoint + ' ' + $Peer + ' ' + $DnsServer
    if ($Management) { $command += ' ' + $Management }
} elseif ($Management) {
    throw 'SSH management exemption requires tunnel configuration'
}
$operation = if ($Upgrade) { "Stop and upgrade $Name, then restart it without routing" } else { "Install automatic idle $Name service for $OwnerSid without starting routing" }
if (!$PSCmdlet.ShouldProcess($root, $operation)) { return }
if ($Upgrade) {
    $oldService = Get-CimInstance Win32_Service -Filter "Name='$Name'"
    $oldStartMode = switch ($oldService.StartMode) {
        'Auto' { 'Automatic' }
        'Manual' { 'Manual' }
        'Disabled' { 'Disabled' }
        default { throw "Unsupported existing service start mode: $($oldService.StartMode)" }
    }
    $backup = Join-Path ([IO.Path]::GetTempPath()) ('skewer-upgrade-' + [Guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $backup
    $backupAcl = [Security.AccessControl.DirectorySecurity]::new()
    $backupAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-DirectoryAcl $backup $backupAcl
    $retainBackup = $false
    try {
        [pscustomobject]@{ Service=$Name; PathName=$oldService.PathName; StartMode=$oldStartMode } |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $backup 'service.json') -Encoding UTF8
        foreach ($file in $files + @('wintun.dll','WinDivert.dll','WinDivert64.sys')) {
            Copy-Item -LiteralPath (Join-Path $root $file) -Destination (Join-Path $backup $file)
        }
        # Do not interrupt a working service until its complete rollback set exists.
        Stop-Service $Name -Force
        $retainBackup = $true
        try {
            foreach ($file in $sources.Keys) { CopyRuntimeFile $sources[$file] (Join-Path $root $file) }
            VerifyDrivers $root $sources
            $changed = Invoke-CimMethod -InputObject $oldService -MethodName Change -Arguments @{
                PathName=$command
                StartMode='Automatic'
            }
            if ($changed.ReturnValue -ne 0) { throw "Service configuration update failed ($($changed.ReturnValue))" }
            SetRecoveryPolicy $Name
            Start-Service $Name
            $retainBackup = $false
        } catch {
            foreach ($file in $files + @('wintun.dll','WinDivert.dll','WinDivert64.sys')) {
                CopyRuntimeFile (Join-Path $backup $file) (Join-Path $root $file)
            }
            $restored = Invoke-CimMethod -InputObject $oldService -MethodName Change -Arguments @{
                PathName=$oldService.PathName
                StartMode=$oldStartMode
            }
            if ($restored.ReturnValue -ne 0) { throw "Service configuration rollback failed ($($restored.ReturnValue)); backup: $backup" }
            Start-Service $Name
            $retainBackup = $false
            throw
        }
    } finally {
        if ($retainBackup) {
            Write-Warning "Routing service recovery was not completed. Runtime backup retained at: $backup"
        } else {
            Remove-Item -LiteralPath $backup -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    [pscustomobject]@{ Service=$Name; OwnerSid=$OwnerSid; Directory=$root; Routing='Not started'; Startup='Automatic'; Updated=$true }
    return
}
$null = New-Item -ItemType Directory -Path $root
# Protected ACL: user may execute/read but never replace SYSTEM-loaded DLLs.
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)')
Set-DirectoryAcl $root $acl
foreach ($file in $sources.Keys) { Copy-Item -LiteralPath $sources[$file] -Destination (Join-Path $root $file) }
VerifyDrivers $root $sources
$result = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
    Name=$Name; DisplayName='Skewer routing service'; PathName=$command; ServiceType=[byte]16
    ErrorControl=[byte]1; StartMode='Automatic'; StartName='LocalSystem'
}
if ($result.ReturnValue -ne 0) { throw "Service creation failed ($($result.ReturnValue)); files retained at $root" }
# SCM RUNNING is not routing Active. Explicit Start is always required; tunnel
# routing additionally requires a tunnel-ready installation and pairing.
try {
    SetRecoveryPolicy $Name
    Start-Service $Name
} catch {
    $service = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
    if ($service) { $null = Invoke-CimMethod -InputObject $service -MethodName Delete }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    throw
}
[pscustomobject]@{ Service=$Name; OwnerSid=$OwnerSid; Directory=$root; Routing='Not started'; Startup='Automatic' }
