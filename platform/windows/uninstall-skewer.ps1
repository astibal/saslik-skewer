[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [string]$Destination = $PSScriptRoot,
    [ValidatePattern('^Skewer(?:-Test-[a-f0-9]{32})?$')][string]$RegistrationName = 'Skewer'
)
$ErrorActionPreference = 'Stop'

$Destination = [IO.Path]::GetFullPath($Destination)
$running = Get-Process -Name skewer -ErrorAction SilentlyContinue | Where-Object {
    try { $_.Path -and [IO.Path]::GetFullPath($_.Path).StartsWith($Destination + '\',
            [StringComparison]::OrdinalIgnoreCase) } catch { $false }
}
if ($running) { throw 'Close Skewer before uninstalling it' }
if (!$PSCmdlet.ShouldProcess($Destination, 'Remove the per-user application; preserve pairing and settings')) {
    return
}

foreach ($shortcut in @(
    (Join-Path ([Environment]::GetFolderPath('Programs')) ($RegistrationName + '.lnk')),
    (Join-Path ([Environment]::GetFolderPath('Desktop')) ($RegistrationName + '.lnk')))) {
    if (Test-Path -LiteralPath $shortcut) { Remove-Item -LiteralPath $shortcut -Force }
}
$uninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\' + $RegistrationName
if (Test-Path -LiteralPath $uninstallKey) { Remove-Item -LiteralPath $uninstallKey -Recurse -Force }

# Pairing, CA decisions and preferences live outside the program directory and
# are deliberately retained. The separately privileged routing service is also
# retained; remove or upgrade it explicitly from an elevated administration flow.
if (Test-Path -LiteralPath $Destination) {
    Remove-Item -LiteralPath $Destination -Recurse -Force
}
[pscustomobject]@{ Removed=$Destination; RoutingService='Preserved'; Settings='Preserved' }
