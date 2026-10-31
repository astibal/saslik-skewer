[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param([ValidatePattern('^SkewerRouting(?:-Test-[a-f0-9]{32})?$')][string]$Name = 'SkewerRouting')
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this remover elevated. The desktop application itself must remain unelevated.'
}
$root = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) $Name
$exe = Join-Path $root 'skewer-routing-service.exe'
$service = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
if (!$service) {
    if (Test-Path -LiteralPath $root) {
        throw 'Protected runtime exists without its service; refusing ambiguous removal'
    }
    [pscustomobject]@{ Service=$Name; Removed=$false; Reason='Not installed' }
    return
}
$prefix = '"' + $exe + '" --service ' + $Name + ' '
if (!$service.PathName.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Service command does not identify the expected protected Skewer runtime'
}
if (!$PSCmdlet.ShouldProcess($Name, 'Stop and remove the routing service and its protected runtime')) { return }

if ($service.State -ne 'Stopped') {
    Stop-Service -Name $Name -Force
    $handle = Get-Service -Name $Name
    try { $handle.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }
    finally { $handle.Dispose() }
}
$result = Invoke-CimMethod -InputObject $service -MethodName Delete
if ($result.ReturnValue -ne 0) { throw "Service removal failed ($($result.ReturnValue))" }
for ($attempt = 0; $attempt -lt 100 -and (Get-Service -Name $Name -ErrorAction SilentlyContinue); $attempt++) {
    Start-Sleep -Milliseconds 100
}
if (Get-Service -Name $Name -ErrorAction SilentlyContinue) { throw 'Service removal did not complete' }
if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
[pscustomobject]@{ Service=$Name; Removed=$true; Settings='Preserved' }
