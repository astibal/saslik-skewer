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
    $versionProbe = Start-Process -FilePath $executable -ArgumentList '--version' -Wait -PassThru
    if ($versionProbe.ExitCode -ne 0) { throw "Version probe failed: $($versionProbe.ExitCode)" }
    $process = Start-Process -FilePath $executable -WorkingDirectory $package -PassThru
    Start-Sleep -Seconds 4
    if ($process.HasExited) { throw "Packaged GUI exited: $($process.ExitCode)" }
    Write-Output 'PASS: clean ZIP extraction, version and packaged GUI startup'
} finally {
    if ($process -and !$process.HasExited) { Stop-Process -Id $process.Id -Force }
    Start-ScheduledTask -TaskName $desktopTask -ErrorAction SilentlyContinue
}
