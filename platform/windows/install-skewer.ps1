[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [string]$PackageDirectory = $PSScriptRoot,
    [string]$Destination = (Join-Path $env:LOCALAPPDATA 'Programs\Skewer'),
    [ValidatePattern('^Skewer(?:-Test-[a-f0-9]{32})?$')][string]$RegistrationName = 'Skewer',
    [switch]$DesktopShortcut
)
$ErrorActionPreference = 'Stop'

$PackageDirectory = (Resolve-Path -LiteralPath $PackageDirectory).Path
$sourceExe = Join-Path $PackageDirectory 'skewer.exe'
if (!(Test-Path -LiteralPath $sourceExe -PathType Leaf)) {
    throw 'PackageDirectory does not contain skewer.exe'
}
$Destination = [IO.Path]::GetFullPath($Destination)
if ($Destination -eq $PackageDirectory) {
    throw 'Install destination must differ from the extracted package directory'
}
$version = (Get-Item -LiteralPath $sourceExe).VersionInfo.ProductVersion
if ($version -notmatch '^[0-9]+(?:\.[0-9]+){3}$') { throw 'Package has no valid Skewer version' }

# Updating loaded DLLs is unreliable and can leave a mixed runtime. The routing
# service is installed separately in Program Files and is intentionally ignored.
$running = Get-Process -Name skewer -ErrorAction SilentlyContinue | Where-Object {
    try { $_.Path -and [IO.Path]::GetFullPath($_.Path).StartsWith($Destination + '\',
            [StringComparison]::OrdinalIgnoreCase) } catch { $false }
}
if ($running) { throw 'Close the installed Skewer application before updating it' }

$parent = Split-Path -Parent $Destination
$stage = Join-Path $parent ('.skewer-stage-' + [Guid]::NewGuid().ToString('N'))
$backup = Join-Path $parent ('.skewer-backup-' + [Guid]::NewGuid().ToString('N'))
$startMenu = Join-Path ([Environment]::GetFolderPath('Programs')) ($RegistrationName + '.lnk')
$desktop = Join-Path ([Environment]::GetFolderPath('Desktop')) ($RegistrationName + '.lnk')
$uninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\' + $RegistrationName

function New-SkewerShortcut([string]$Path, [string]$Target) {
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($Path)
    $shortcut.TargetPath = $Target
    $shortcut.WorkingDirectory = Split-Path -Parent $Target
    $shortcut.IconLocation = "$Target,0"
    $shortcut.Description = 'Route selected applications through Saslik'
    $shortcut.Save()
}

$operation = if (Test-Path -LiteralPath $Destination) { 'Update per-user Skewer application' }
             else { 'Install per-user Skewer application' }
if (!$PSCmdlet.ShouldProcess($Destination, $operation)) { return }

$null = New-Item -ItemType Directory -Path $parent -Force
try {
    $null = New-Item -ItemType Directory -Path $stage
    Get-ChildItem -LiteralPath $PackageDirectory -Force | ForEach-Object {
        if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Package contains a reparse point: $($_.Name)"
        }
        Copy-Item -LiteralPath $_.FullName -Destination $stage -Recurse
    }
    if (!(Test-Path -LiteralPath (Join-Path $stage 'skewer.exe') -PathType Leaf)) {
        throw 'Staged application is incomplete'
    }
    if (Test-Path -LiteralPath $Destination) { Move-Item -LiteralPath $Destination -Destination $backup }
    try {
        Move-Item -LiteralPath $stage -Destination $Destination
    } catch {
        if (Test-Path -LiteralPath $backup) { Move-Item -LiteralPath $backup -Destination $Destination }
        throw
    }
    Remove-Item -LiteralPath $backup -Recurse -Force -ErrorAction SilentlyContinue

    $installedExe = Join-Path $Destination 'skewer.exe'
    New-SkewerShortcut $startMenu $installedExe
    if ($DesktopShortcut) { New-SkewerShortcut $desktop $installedExe }
    elseif (Test-Path -LiteralPath $desktop) { Remove-Item -LiteralPath $desktop -Force }

    $null = New-Item -Path $uninstallKey -Force
    $uninstall = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' +
                 (Join-Path $Destination 'uninstall-skewer.ps1') + '" -RegistrationName ' + $RegistrationName
    New-ItemProperty -Path $uninstallKey -Name DisplayName -Value 'Skewer' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name DisplayVersion -Value $version -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name Publisher -Value 'Smithproxy' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name InstallLocation -Value $Destination -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name DisplayIcon -Value "$installedExe,0" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name UninstallString -Value $uninstall -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name NoModify -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name NoRepair -Value 1 -PropertyType DWord -Force | Out-Null
    [pscustomobject]@{ Version=$version; Directory=$Destination; Routing='Not started'; Settings='Preserved' }
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
