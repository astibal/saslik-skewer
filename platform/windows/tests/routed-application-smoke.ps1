$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type @'
using System.Runtime.InteropServices;
public static class SkewerMouse {
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, System.UIntPtr extra);
}
'@
$directory='C:\SkewerDev\skewer-windows-app'
$service=(Get-Content 'C:\SkewerDev\routed-service-name.txt' -Raw).Trim()
$log=Join-Path $env:USERPROFILE 'skewer-routed-application-smoke.log'
$settings='HKCU:\Software\Saslik\Skewer\windows'
$old=(Get-ItemProperty $settings -Name routingService -ErrorAction SilentlyContinue).routingService
$launchedPid=0
$manualPid=0
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
    $release.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
    $deadline=(Get-Date).AddSeconds(12)
    do {
        Start-Sleep -Milliseconds 100
        $reply=& (Join-Path $directory 'skewer-routing-control.exe') status $service | ConvertFrom-Json
    } while ($reply.phase -notin @(0,5) -and (Get-Date) -lt $deadline)
    if ($reply.phase -notin @(0,5) -or $reply.scope -ne 0) {
        throw 'Release did not retire selected routing'
    }
    if (!(Get-Process -Id $launchedPid -ErrorAction SilentlyContinue)) {
        throw 'Release terminated the selected application'
    }
    $deadline=(Get-Date).AddSeconds(12)
    do {
        Start-Sleep -Milliseconds 200
        $processCell=FindNamed $window 'skewer.exe'
    } while (!$processCell -and (Get-Date) -lt $deadline)
    if (!$processCell) {
        "Application tree after Release:`n$(WindowText $window)" | Out-File $log -Append
        throw 'Skewer process is missing from its own application tree'
    }
    $candidate=$processCell
    $selected=$false
    for ($i=0; $i -lt 4 -and $candidate; ++$i) {
        try {
            $candidate.GetCurrentPattern(
                [System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
            $selected=$true
            break
        } catch {
            $candidate=[System.Windows.Automation.TreeWalker]::ControlViewWalker.GetParent($candidate)
        }
    }
    if (!$selected) { throw 'Application tree row does not expose selection automation' }
    $bounds=$processCell.Current.BoundingRectangle
    if ($bounds.Width -le 0 -or $bounds.Height -le 0) { throw 'Selected application row is not visible' }
    [SkewerMouse]::SetCursorPos([int]($bounds.X+$bounds.Width/2),[int]($bounds.Y+$bounds.Height/2)) | Out-Null
    [SkewerMouse]::mouse_event(0x0002,0,0,0,[UIntPtr]::Zero)
    [SkewerMouse]::mouse_event(0x0004,0,0,0,[UIntPtr]::Zero)
    $deadline=(Get-Date).AddSeconds(8)
    do {
        Start-Sleep -Milliseconds 100
        $attach=FindNamed $window 'Attach to Skewer'
    } while ((!$attach -or !$attach.Current.IsEnabled) -and (Get-Date) -lt $deadline)
    if (!$attach -or !$attach.Current.IsEnabled) { throw 'Attach did not enable for selected process' }
    $attach.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
    $deadline=(Get-Date).AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 100
        $reply=& (Join-Path $directory 'skewer-routing-control.exe') status $service | ConvertFrom-Json
    } while (($reply.phase -ne 2 -or $reply.scope -ne 2) -and (Get-Date) -lt $deadline)
    if ($reply.phase -ne 2 -or $reply.scope -ne 2 -or !$reply.selected.pid) {
        throw 'Manual Attach did not activate routing for the selected process'
    }
    $manualPid=[int]$reply.selected.pid
    $release=FindNamed $window 'Release'
    if (!$release -or !$release.Current.IsEnabled) { throw 'Manual Attach did not enable Release' }
    $release.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
    $deadline=(Get-Date).AddSeconds(12)
    do {
        Start-Sleep -Milliseconds 100
        $reply=& (Join-Path $directory 'skewer-routing-control.exe') status $service | ConvertFrom-Json
    } while ($reply.phase -notin @(0,5) -and (Get-Date) -lt $deadline)
    if ($reply.scope -ne 0 -or !(Get-Process -Id $manualPid -ErrorAction SilentlyContinue)) {
        throw 'Release after manual Attach did not preserve the application'
    }
    "PASS: routed launch, activation recovery, Release and manual Attach all retained the selected application" |
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
