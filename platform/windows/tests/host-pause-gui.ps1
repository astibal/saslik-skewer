param(
    [Parameter(Mandatory=$true)][string]$Directory,
    [Parameter(Mandatory=$true)][string]$Service,
    [Parameter(Mandatory=$true)][string]$ResultFile
)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$gui=$null
$previousGui=$null
$client=Join-Path $Directory 'skewer-routing-control.exe'
function Status {
    $state=& $client status $Service | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read host routing status' }
    return $state
}
function Named($window, [string]$name) {
    $condition=[System.Windows.Automation.PropertyCondition]::new(
        [System.Windows.Automation.AutomationElement]::NameProperty,$name)
    $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants,$condition)
}
function RoutingTab($window) {
    # The process table also has a column named Routing. Never select it as a tab.
    $condition=[System.Windows.Automation.AndCondition]::new(
        [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::NameProperty,'Routing'),
        [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::ControlTypeProperty,[System.Windows.Automation.ControlType]::TabItem))
    $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants,$condition)
}
function OpenWindow {
    $script:gui=Start-Process (Join-Path $Directory 'skewer.exe') -ArgumentList "--routing-service=$Service" -PassThru
    $until=(Get-Date).AddSeconds(15)
    do {
        $gui.Refresh()
        if ($gui.HasExited) { throw 'Host test GUI exited unexpectedly' }
        $handle=$gui.MainWindowHandle
        if ($handle -ne [IntPtr]::Zero) {
            $window=[System.Windows.Automation.AutomationElement]::FromHandle($handle)
            $tab=RoutingTab $window
            if ($tab) {
                $tab.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
                return $window
            }
        }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $until)
    throw 'Host test GUI window missing'
}
function WaitButton($window, [string]$name) {
    $until=(Get-Date).AddSeconds(15)
    do {
        # Keep the expected page selected while waiting for asynchronous status.
        $tab=RoutingTab $window
        if ($tab) {
            $selection=$tab.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)
            if (!$selection.Current.IsSelected) { $selection.Select() }
        }
        $button=Named $window $name
        if ($button -and $button.Current.IsEnabled) { return $button }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $until)
    $items=$window.FindAll([System.Windows.Automation.TreeScope]::Descendants,
        [System.Windows.Automation.Condition]::TrueCondition)
    $summary=($items | ForEach-Object { "$($_.Current.Name) [enabled=$($_.Current.IsEnabled)]" }) -join '; '
    throw "Enabled button missing: $name; UI: $summary"
}
function AwaitPause([bool]$paused, [string]$generation) {
    $until=(Get-Date).AddSeconds(15)
    do {
        $state=Status
        if ($state.generation -ne $generation) { throw 'GUI action changed routing generation' }
        if ($state.paused -eq $paused -and $state.phase -eq $(if ($paused) {3} else {2})) { return }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $until)
    throw 'GUI action did not reach expected pause state'
}
try {
    # Skewer is single-instance per user. Temporarily close only an identified
    # development GUI in our desktop session, then restore it after the test.
    $existing=@(Get-Process skewer -ErrorAction SilentlyContinue | Where-Object SessionId -eq (Get-Process -Id $PID).SessionId)
    if ($existing.Count -gt 1) { throw 'Ambiguous existing Skewer desktop processes' }
    if ($existing.Count -eq 1) {
        $previousGui=$existing[0].Path
        if ($previousGui -notlike 'C:\Temp\skewer-release-check-*\skewer.exe' -and
            $previousGui -ne (Join-Path $Directory 'skewer.exe')) {
            $previousGui=$null
            throw 'Refusing to close an unrelated Skewer installation'
        }
        Stop-Process -Id $existing[0].Id -Force
        $existing[0].WaitForExit()
    }
    $before=Status
    if ($before.scope -ne 1 -or $before.transport -ne 1 -or $before.phase -ne 2) {
        throw 'Fixture requires an active whole-host tunnel'
    }
    $window=OpenWindow
    (WaitButton $window 'Pause host').GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
    AwaitPause $true $before.generation
    $null=WaitButton $window 'Resume host'
    $null=WaitButton $window 'Release host'
    # Terminate only the GUI owned by this fixture, never the service.
    Stop-Process -Id $gui.Id -Force
    $gui.WaitForExit()
    $gui=$null
    AwaitPause $true $before.generation
    $window=OpenWindow
    (WaitButton $window 'Resume host').GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
    AwaitPause $false $before.generation
    $null=WaitButton $window 'Pause host'
    @{passed=$true; detail='Host Pause/Resume buttons, GUI termination and state restoration passed'} |
        ConvertTo-Json | Set-Content -LiteralPath $ResultFile
} catch {
    @{passed=$false; detail=$_.Exception.Message} | ConvertTo-Json | Set-Content -LiteralPath $ResultFile
    exit 1
} finally {
    if ($gui -and !$gui.HasExited) { Stop-Process -Id $gui.Id -Force }
    if ($previousGui) { Start-Process -FilePath $previousGui | Out-Null }
}
