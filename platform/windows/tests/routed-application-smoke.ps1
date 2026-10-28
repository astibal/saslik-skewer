$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$directory='C:\SkewerDev\skewer-windows-app'
$service=(Get-Content 'C:\SkewerDev\routed-service-name.txt' -Raw).Trim()
$log=Join-Path $env:USERPROFILE 'skewer-routed-application-smoke.log'
$settings='HKCU:\Software\Saslik\Skewer\windows'
$old=(Get-ItemProperty $settings -Name routingService -ErrorAction SilentlyContinue).routingService
$launchedPid=0
function FindWindow {
    $condition=[System.Windows.Automation.PropertyCondition]::new(
        [System.Windows.Automation.AutomationElement]::NameProperty, 'Skewer')
    [System.Windows.Automation.AutomationElement]::RootElement.FindFirst(
        [System.Windows.Automation.TreeScope]::Children, $condition)
}
function FindNamed($window, $name) {
    try {
        $condition=[System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::NameProperty, $name)
        $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
    } catch { $null }
}
function WindowText($window) {
    try {
        $all=$window.FindAll([System.Windows.Automation.TreeScope]::Descendants,
                             [System.Windows.Automation.Condition]::TrueCondition)
        ($all | ForEach-Object { $_.Current.Name }) -join "`n"
    } catch { '' }
}
try {
    "Starting routed GUI smoke against $service" | Out-File $log
    New-Item $settings -Force | Out-Null
    Set-ItemProperty $settings -Name routingService -Value $service
    $window=FindWindow
    if (!$window) {
        Start-Process (Join-Path $directory 'skewer.exe')
        $deadline=(Get-Date).AddSeconds(10)
        do { Start-Sleep -Milliseconds 200; $window=FindWindow } while (!$window -and (Get-Date) -lt $deadline)
    }
    if (!$window) { throw 'Skewer window missing' }
    $edit=FindNamed $window 'Application executable'
    $button=FindNamed $window 'Launch through Skewer'
    if (!$edit -or !$button -or !$button.Current.IsEnabled) { throw 'Routed launcher controls unavailable' }
    $edit.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).SetValue(
        'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')
    $button.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
    $deadline=(Get-Date).AddSeconds(35)
    do {
        Start-Sleep -Milliseconds 100
        $text=WindowText $window
        $match=[regex]::Match($text, 'PID (\d+) is routed through Skewer \(generation (\d+)\)')
    } while (!$match.Success -and $text -notmatch 'Routed launch failed' -and (Get-Date) -lt $deadline)
    if (!$match.Success) { throw "Routed GUI launch did not become ready: $text" }
    $launchedPid=[int]$match.Groups[1].Value
    $generation=[UInt64]$match.Groups[2].Value
    if (!(Get-Process -Id $launchedPid -ErrorAction SilentlyContinue)) { throw 'Routed child already exited' }
    $window.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern).Close()
    $deadline=(Get-Date).AddSeconds(8)
    do {
        Start-Sleep -Milliseconds 100
        $window=FindWindow
    } while ($window -and (Get-Date) -lt $deadline)
    if ($window) { throw 'Skewer window did not hide before activation test' }
    if (!(Get-Process -Id $launchedPid -ErrorAction SilentlyContinue)) {
        throw 'Closing Skewer terminated the routed child'
    }
    $reply=& (Join-Path $directory 'skewer-routing-control.exe') status $service | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $reply.phase -ne 2 -or $reply.scope -ne 2 -or
        [UInt64]$reply.generation -ne $generation -or [int]$reply.selected.pid -ne $launchedPid) {
        throw 'Closing Skewer stopped or replaced the selected routing generation'
    }
    Start-Process (Join-Path $directory 'skewer.exe')
    $deadline=(Get-Date).AddSeconds(12)
    do {
        Start-Sleep -Milliseconds 200
        $window=FindWindow
        if ($window) {
            $text=WindowText $window
            $release=FindNamed $window 'Release'
        }
    } while ((!$window -or $text -notmatch "PID $launchedPid is selected for routing" -or
              $text -notmatch 'Routed' -or !$release -or !$release.Current.IsEnabled) -and
             (Get-Date) -lt $deadline)
    if (!$window -or $text -notmatch "PID $launchedPid is selected for routing" -or
        $text -notmatch 'Routed' -or !$release.Current.IsEnabled) {
        $releaseEnabled=if ($release) { $release.Current.IsEnabled } else { $false }
        "Recovered window text:`n$text`nRelease present: $([bool]$release); enabled: $releaseEnabled" |
            Out-File $log -Append
        throw 'Reopened GUI did not recover authoritative selected routing state'
    }
    "PASS: GUI routed PID $launchedPid only after Active; closing and reopening retained generation $generation and restored Routed/Release" |
        Out-File $log -Append
    'Exit: 0' | Out-File $log -Append
} catch {
    "FAIL: $_" | Out-File $log -Append
    'Exit: 1' | Out-File $log -Append
} finally {
    if ($launchedPid) { Stop-Process -Id $launchedPid -Force -ErrorAction SilentlyContinue }
    if ($null -eq $old) { Remove-ItemProperty $settings -Name routingService -ErrorAction SilentlyContinue }
    else { Set-ItemProperty $settings -Name routingService -Value $old }
    if (!(FindWindow)) { Start-Process (Join-Path $directory 'skewer.exe') }
}
