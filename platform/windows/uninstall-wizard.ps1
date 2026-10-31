[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$InstallDirectory,
    [switch]$RemoveSettings
)
$ErrorActionPreference = 'Stop'
$nativeModuleRoot = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\Modules'
$moduleRoots = @($env:PSModulePath -split ';' | Where-Object { $_ })
if ((Test-Path -LiteralPath $nativeModuleRoot -PathType Container) -and
    $nativeModuleRoot -notin $moduleRoots) {
    # Keep the elevated uninstaller independent of its parent shell's module
    # search path, just like the installation path.
    $env:PSModulePath = (@($nativeModuleRoot) + $moduleRoots) -join ';'
}
$logDirectory = Join-Path $env:ProgramData 'Skewer'
$logFile = Join-Path $logDirectory 'setup.log'
$null = New-Item -ItemType Directory -Path $logDirectory -Force
Add-Content -LiteralPath $logFile -Value ('{0:o} Uninstall orchestration started.' -f [DateTime]::UtcNow) -Encoding UTF8

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The Skewer uninstaller must run as administrator.'
}

$running = Get-Process -Name skewer -ErrorAction SilentlyContinue
if ($running) { throw 'Close Skewer before uninstalling it.' }

$name = 'SkewerRouting'
$control = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) "$Name\skewer-routing-control.exe"
if (Test-Path -LiteralPath $control -PathType Leaf) {
    $status = & $control status $name | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Cannot query the installed routing service.' }
    if ($status.phase -ne 0) {
        throw 'Disable Skewer routing before uninstalling the application.'
    }
}

$remover = Join-Path $InstallDirectory 'remove-routing-service.ps1'
if (Test-Path -LiteralPath $remover -PathType Leaf) {
    & $remover -Name $name -Confirm:$false
} elseif (Get-Service -Name $name -ErrorAction SilentlyContinue) {
    throw 'The routing service exists but its verified remover is unavailable.'
}

if ($RemoveSettings) {
    # UAC may use a separate administrator account. Remove data from the active
    # desktop user's loaded hive and profile, never from the elevated token's
    # HKCU merely because it approved uninstall.
    $account = (Get-CimInstance Win32_ComputerSystem).UserName
    if (!$account) { throw 'Cannot identify the interactive desktop user.' }
    $sid = ([Security.Principal.NTAccount]::new($account)).Translate(
        [Security.Principal.SecurityIdentifier]).Value
    $profile = Get-CimInstance Win32_UserProfile -Filter "SID='$sid'"
    if (!$profile -or !$profile.LocalPath) { throw 'Cannot locate the interactive user profile.' }
    Remove-Item -LiteralPath "Registry::HKEY_USERS\$sid\Software\Saslik\Skewer" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path $profile.LocalPath 'AppData\Local\skewer') -Recurse -Force -ErrorAction SilentlyContinue
}
Add-Content -LiteralPath $logFile -Value ('{0:o} Uninstall orchestration completed.' -f [DateTime]::UtcNow) -Encoding UTF8
