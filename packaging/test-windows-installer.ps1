param(
    [Parameter(Mandatory=$true)][string]$Installer,
    [string]$ExpectedVersion = '0.9.50.6'
)
$ErrorActionPreference = 'Stop'
$installDirectory = Join-Path $env:ProgramFiles 'Skewer'
$serviceDirectory = Join-Path $env:ProgramFiles 'SkewerRouting'
$uninstallKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Skewer'
$startMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Skewer\Skewer.lnk'
$settingsSentinel = Join-Path $env:LOCALAPPDATA 'skewer\installer-preserve-test.txt'
$setupLog = Join-Path $env:ProgramData 'Skewer\setup.log'

function Get-SetupPhase {
    if (!(Test-Path -LiteralPath $setupLog -PathType Leaf)) { return 'setup did not start' }
    $phases = @(
        'Setup orchestration started.',
        'Checking the existing routing service.',
        'Installing the routing service.',
        'Updating the routing service.',
        'Routing service is installed and Idle.',
        'Staging the desktop application.',
        'Desktop application files are installed.',
        'Setup orchestration completed.',
        'Uninstall orchestration started.',
        'Uninstall orchestration completed.'
    )
    $last = 'setup log contains no recognized phase'
    foreach ($line in Get-Content -LiteralPath $setupLog) {
        if ($line -match 'Routing service detail: (.+)$') {
            $last = "Routing service detail: $($Matches[1])"
            continue
        }
        if ($line -match 'Routing service installation failed: ([a-z ]+)$') {
            $last = "Routing service installation failed: $($Matches[1])"
            continue
        }
        foreach ($phase in $phases) {
            if ($line.EndsWith($phase, [StringComparison]::Ordinal)) { $last = $phase }
        }
    }
    $runtime = if (Test-Path -LiteralPath $serviceDirectory) { 'present' } else { 'absent' }
    $service = Get-Service SkewerRouting -ErrorAction SilentlyContinue
    $serviceState = if ($service) { $service.Status.ToString() } else { 'absent' }
    return "$last; runtime=$runtime; service=$serviceState"
}

function Run-Bounded([string]$File, [string[]]$Arguments, [int]$Seconds = 180) {
    $process = Start-Process -FilePath $File -ArgumentList $Arguments -PassThru
    if (!$process.WaitForExit($Seconds * 1000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw "Timed out: $File $Arguments"
    }
    if ($process.ExitCode -ne 0) {
        throw "Command failed ($($process.ExitCode)): $File $Arguments; last setup phase: $(Get-SetupPhase)"
    }
}

try {
    Run-Bounded $Installer @('/S')
    $exe = Join-Path $installDirectory 'skewer.exe'
    $uninstaller = Join-Path $installDirectory 'Uninstall.exe'
    foreach ($path in @($exe, $uninstaller, $startMenu, $uninstallKey,
                        (Join-Path $serviceDirectory 'skewer-routing-service.exe'))) {
        if (!(Test-Path -LiteralPath $path)) { throw "Installer omitted: $path" }
    }
    $registration = Get-ItemProperty -LiteralPath $uninstallKey
    if ($registration.DisplayVersion -ne $ExpectedVersion -or
        $registration.InstallLocation -ne $installDirectory) {
        throw 'Unexpected uninstall registration'
    }
    $service = Get-Service SkewerRouting
    if ($service.Status -ne 'Running') { throw 'Routing service is not running' }
    $status = & (Join-Path $serviceDirectory 'skewer-routing-control.exe') status SkewerRouting |
        ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $status.phase -ne 0) {
        throw 'Freshly installed routing service is not Idle'
    }

    $process = Start-Process -FilePath $exe -PassThru
    Start-Sleep -Seconds 3
    if ($process.HasExited) { throw "Installed GUI exited: $($process.ExitCode)" }
    Stop-Process -Id $process.Id -Force

    # Exercise the upgrade path and confirm that user state remains external to
    # the application directory.
    $null = New-Item -ItemType Directory -Path (Split-Path -Parent $settingsSentinel) -Force
    Set-Content -LiteralPath $settingsSentinel -Value 'preserve'
    Run-Bounded $Installer @('/S')
    if (!(Test-Path -LiteralPath $settingsSentinel)) { throw 'Upgrade removed user state' }
    if ((& (Join-Path $serviceDirectory 'skewer-routing-control.exe') status SkewerRouting |
            ConvertFrom-Json).phase -ne 0) {
        throw 'Upgrade did not return the service to Idle'
    }

    Run-Bounded $uninstaller @('/S')
    foreach ($path in @($installDirectory, $serviceDirectory, $startMenu, $uninstallKey)) {
        if (Test-Path -LiteralPath $path) { throw "Uninstall retained: $path" }
    }
    if (!(Test-Path -LiteralPath $settingsSentinel)) {
        throw 'Default uninstall removed preserved user state'
    }
    Write-Output 'PASS: wizard install, Idle service, GUI, upgrade, registration, shortcuts and uninstall'
} finally {
    Stop-Process -Name skewer -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath (Join-Path $installDirectory 'Uninstall.exe')) {
        Start-Process -FilePath (Join-Path $installDirectory 'Uninstall.exe') -ArgumentList '/S' -Wait
    }
    Remove-Item -LiteralPath $settingsSentinel -Force -ErrorAction SilentlyContinue
}
