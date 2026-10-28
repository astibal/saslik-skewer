param(
    [Parameter(Mandatory=$true)][string]$Archive,
    [string]$ExpectedVersion = '0.9.50.6',
    [string]$TestRoot = 'C:\SkewerDev\release-smoke'
)
$ErrorActionPreference = 'Stop'
$desktopTask = 'SkewerDevelopmentDesktop'
$process = $null
$installedProcess = $null
$installed = $null
$registration = $null
try {
    Stop-ScheduledTask -TaskName $desktopTask -ErrorAction SilentlyContinue
    Stop-Process -Name skewer -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $TestRoot) { Remove-Item -LiteralPath $TestRoot -Recurse -Force }
    Expand-Archive -LiteralPath $Archive -DestinationPath $TestRoot
    $package = Join-Path $TestRoot "skewer-windows-amd64-$ExpectedVersion"
    $executable = Join-Path $package 'skewer.exe'
    $expected = @{
        'WinDivert.dll' = 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'
        'WinDivert64.sys' = '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'
        'wintun.dll' = 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce'
    }
    foreach ($name in $expected.Keys) {
        $path = Join-Path $package $name
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $expected[$name]) {
            throw "Unexpected packaged dependency: $name"
        }
    }
    foreach ($name in @('WinDivert64.sys', 'wintun.dll')) {
        if ((Get-AuthenticodeSignature -LiteralPath (Join-Path $package $name)).Status -ne 'Valid') {
            throw "Invalid packaged driver signature: $name"
        }
    }
    foreach ($name in @('Wintun-LICENSE.txt', 'WinDivert-LICENSE.txt')) {
        if (!(Test-Path -LiteralPath (Join-Path $package "licenses\$name"))) {
            throw "Missing packaged dependency license: $name"
        }
    }
    $resourceVersion = (Get-Item -LiteralPath $executable).VersionInfo.ProductVersion
    if ($resourceVersion -ne $ExpectedVersion) { throw "Unexpected PE product version: $resourceVersion" }
    $registration = 'Skewer-Test-' + [Guid]::NewGuid().ToString('N')
    $installed = Join-Path $TestRoot 'installed'
    $installer = Join-Path $package 'install-skewer.ps1'
    & $installer -PackageDirectory $package -Destination $installed -RegistrationName $registration -WhatIf
    if (Test-Path -LiteralPath $installed) { throw 'Per-user installer WhatIf changed state' }
    & $installer -PackageDirectory $package -Destination $installed -RegistrationName $registration
    $installedExe = Join-Path $installed 'skewer.exe'
    $shortcut = Join-Path ([Environment]::GetFolderPath('Programs')) ($registration + '.lnk')
    $uninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\' + $registration
    if (!(Test-Path -LiteralPath $installedExe) -or !(Test-Path -LiteralPath $shortcut) -or
        !(Test-Path -LiteralPath $uninstallKey)) { throw 'Per-user installation is incomplete' }
    $installedProcess = Start-Process -FilePath $installedExe -WorkingDirectory $installed -PassThru
    Start-Sleep -Seconds 2
    $rejected = $false
    try { & $installer -PackageDirectory $package -Destination $installed -RegistrationName $registration }
    catch { $rejected = $true }
    if (!$rejected) { throw 'Installer updated a running application' }
    Stop-Process -Id $installedProcess.Id -Force
    $installedProcess.WaitForExit()
    & $installer -PackageDirectory $package -Destination $installed -RegistrationName $registration
    & (Join-Path $installed 'uninstall-skewer.ps1') -Destination $installed -RegistrationName $registration
    if ((Test-Path -LiteralPath $installed) -or (Test-Path -LiteralPath $shortcut) -or
        (Test-Path -LiteralPath $uninstallKey)) { throw 'Per-user uninstall left registered application state' }
    $versionProbe = Start-Process -FilePath $executable -ArgumentList '--version' -Wait -PassThru
    if ($versionProbe.ExitCode -ne 0) { throw "Version probe failed: $($versionProbe.ExitCode)" }
    $process = Start-Process -FilePath $executable -WorkingDirectory $package -PassThru
    Start-Sleep -Seconds 4
    if ($process.HasExited) { throw "Packaged GUI exited: $($process.ExitCode)" }
    Write-Output 'PASS: clean ZIP, dependencies, per-user install/uninstall, version and GUI startup'
} finally {
    if ($process -and !$process.HasExited) { Stop-Process -Id $process.Id -Force }
    if ($installedProcess -and !$installedProcess.HasExited) { Stop-Process -Id $installedProcess.Id -Force }
    if ($installed -and $registration -and (Test-Path -LiteralPath (Join-Path $installed 'uninstall-skewer.ps1'))) {
        & (Join-Path $installed 'uninstall-skewer.ps1') -Destination $installed -RegistrationName $registration
    }
    Start-ScheduledTask -TaskName $desktopTask -ErrorAction SilentlyContinue
}
