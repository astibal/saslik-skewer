[CmdletBinding()]
param([string]$PackageDirectory = $PSScriptRoot)
$ErrorActionPreference = 'Stop'
$PackageDirectory = (Resolve-Path -LiteralPath $PackageDirectory).Path

$required = @(
    'skewer.exe', 'skewer-routing-service.exe', 'skewer-routing-control.exe',
    'install-skewer.ps1', 'uninstall-skewer.ps1', 'install-routing-service.ps1',
    'remove-routing-service.ps1', 'install-wizard.ps1', 'uninstall-wizard.ps1',
    'wintun.dll', 'WinDivert.dll', 'WinDivert64.sys',
    'Qt6Core.dll', 'Qt6Gui.dll', 'Qt6Network.dll', 'Qt6Widgets.dll',
    'libgcc_s_seh-1.dll', 'libstdc++-6.dll', 'libwinpthread-1.dll', 'libssp-0.dll',
    'platforms\qwindows.dll', 'styles\qmodernwindowsstyle.dll',
    'networkinformation\qnetworklistmanager.dll', 'imageformats\qsvg.dll',
    'imageformats\qico.dll', 'licenses\Wintun-LICENSE.txt',
    'licenses\WinDivert-LICENSE.txt', 'licenses\README.md'
)
foreach ($relative in $required) {
    $path = Join-Path $PackageDirectory $relative
    $item = Get-Item -LiteralPath $path
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Package entry is not a regular file: $relative"
    }
}

$expected = @{
    'WinDivert.dll' = 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'
    'WinDivert64.sys' = '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'
}
foreach ($name in $expected.Keys) {
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $PackageDirectory $name)).Hash -ne
        $expected[$name]) { throw "Unexpected official runtime: $name" }
}
foreach ($name in @('wintun.dll', 'WinDivert64.sys')) {
    $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $PackageDirectory $name)
    if ($signature.Status -ne 'Valid') { throw "Invalid driver signature: $name ($($signature.Status))" }
}

$executable = Get-Item -LiteralPath (Join-Path $PackageDirectory 'skewer.exe')
$version = $executable.VersionInfo.ProductVersion
if ($version -notmatch '^[0-9]+(?:\.[0-9]+){3}$') { throw "Invalid executable version: $version" }
function Assert-Starts([string]$Relative, [string[]]$Arguments, [int]$ExpectedExit) {
    # skewer.exe uses the Windows GUI subsystem, so PowerShell does not reliably
    # capture its stdout even for --version. Exit status still proves that the PE
    # loader found every required runtime dependency.
    $start = @{ FilePath=(Join-Path $PackageDirectory $Relative); Wait=$true; PassThru=$true }
    if ($Arguments.Count) { $start.ArgumentList = $Arguments }
    $process = Start-Process @start
    if ($process.ExitCode -ne $ExpectedExit) {
        throw "$Relative did not start (expected $ExpectedExit, got $($process.ExitCode))"
    }
}
Assert-Starts 'skewer.exe' @('--version') 0
Assert-Starts 'skewer-routing-service.exe' @() 2
Assert-Starts 'skewer-routing-control.exe' @() 2
[pscustomobject]@{ Package=$PackageDirectory; Version=$version; Drivers='Signed'; Runtime='Complete' }
