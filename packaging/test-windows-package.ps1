param(
    [Parameter(Mandatory=$true)][string]$Archive,
    [string]$ExpectedVersion = '0.9.50.6',
    [string]$TestRoot = 'C:\SkewerDev\release-smoke'
)
$ErrorActionPreference = 'Stop'
$desktopTask = 'SkewerDevelopmentDesktop'
$process = $null
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
    $versionProbe = Start-Process -FilePath $executable -ArgumentList '--version' -Wait -PassThru
    if ($versionProbe.ExitCode -ne 0) { throw "Version probe failed: $($versionProbe.ExitCode)" }
    $process = Start-Process -FilePath $executable -WorkingDirectory $package -PassThru
    Start-Sleep -Seconds 4
    if ($process.HasExited) { throw "Packaged GUI exited: $($process.ExitCode)" }
    Write-Output 'PASS: clean ZIP extraction, signed pinned drivers, licenses, version and GUI startup'
} finally {
    if ($process -and !$process.HasExited) { Stop-Process -Id $process.Id -Force }
    Start-ScheduledTask -TaskName $desktopTask -ErrorAction SilentlyContinue
}
