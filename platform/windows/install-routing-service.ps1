[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)][string]$PackageDirectory,
    [Parameter(Mandatory=$true)][string]$WinDivertDirectory,
    [Parameter(Mandatory=$true)][string]$WintunDll,
    [Parameter(Mandatory=$true)][string]$OwnerSid,
    [Parameter(Mandatory=$true)][string]$Endpoint,
    [Parameter(Mandatory=$true)][string]$Peer,
    [string]$DnsServer = '1.1.1.1',
    [string]$Management = '',
    [ValidatePattern('^SkewerRouting(?:-Test-[a-f0-9]{32})?$')][string]$Name = 'SkewerRouting'
)
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer elevated. The desktop application itself must remain unelevated.'
}
$sid = [Security.Principal.SecurityIdentifier]::new($OwnerSid)
if ($sid.Value -cne $OwnerSid) { throw 'OwnerSid must be canonical' }
if ($Endpoint -notmatch '^skewer://[A-Za-z0-9.-]+:[0-9]{1,5}/pair$') { throw 'Expected paired endpoint, never an invitation or secret' }
$uri = [Uri]$Endpoint
if ($uri.Port -lt 1 -or $uri.Port -gt 65535) { throw 'Invalid endpoint port' }
foreach ($address in @($Peer,$DnsServer) + @($Management | Where-Object { $_ })) {
    $ip = $null
    if (![Net.IPAddress]::TryParse($address, [ref]$ip) -or $ip.AddressFamily -ne 'InterNetwork' -or $ip.ToString() -ne $address) {
        throw 'Peer, DNS and optional SSH management must be canonical IPv4 addresses'
    }
}
$root = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) $Name
if (Test-Path -LiteralPath $root) { throw "Installation directory already exists; refusing to overwrite: $root" }
if (Get-Service -Name $Name -ErrorAction SilentlyContinue) { throw 'Service already exists; stop and explicitly upgrade it' }
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
function VerifyDrivers([string]$Directory, [hashtable]$Paths) {
    $hashes = @{
        'WinDivert.dll' = 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'
        'WinDivert64.sys' = '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'
    }
    foreach ($file in $hashes.Keys) {
        $path = if ($Directory) { Join-Path $Directory $file } else { $Paths[$file] }
        if ((Get-FileHash -LiteralPath $path).Hash -ne $hashes[$file]) { throw "Unverified driver artifact: $file" }
    }
    foreach ($file in @('wintun.dll','WinDivert64.sys')) {
        $path = if ($Directory) { Join-Path $Directory $file } else { $Paths[$file] }
        if ((Get-AuthenticodeSignature -LiteralPath $path).Status -ne 'Valid') { throw "Invalid driver signature: $file" }
    }
}
VerifyDrivers '' $sources
if (!$PSCmdlet.ShouldProcess($root, "Install demand-start $Name service for $OwnerSid without starting routing")) { return }
$null = New-Item -ItemType Directory -Path $root
# Protected ACL: user may execute/read but never replace SYSTEM-loaded DLLs.
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)')
Set-Acl -LiteralPath $root -AclObject $acl
foreach ($file in $sources.Keys) { Copy-Item -LiteralPath $sources[$file] -Destination (Join-Path $root $file) }
VerifyDrivers $root $sources
$exe = Join-Path $root 'skewer-routing-service.exe'
$command = '"' + $exe + '" --service ' + $Name + ' ' + $OwnerSid + ' ' + $Endpoint + ' ' + $Peer + ' ' + $DnsServer
if ($Management) { $command += ' ' + $Management }
$result = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
    Name=$Name; DisplayName='Skewer routing service'; PathName=$command; ServiceType=[byte]16
    ErrorControl=[byte]1; StartMode='Manual'; StartName='LocalSystem'
}
if ($result.ReturnValue -ne 0) { throw "Service creation failed ($($result.ReturnValue)); files retained at $root" }
# SCM RUNNING is not routing Active. Pairing and explicit Start are still required.
Start-Service $Name
[pscustomobject]@{ Service=$Name; OwnerSid=$OwnerSid; Directory=$root; Routing='Not started'; Startup='Manual' }
