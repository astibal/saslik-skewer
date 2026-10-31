# Run in the development desktop after configuring an already paired endpoint.
# This checks presence only; it never enables routing or installs certificates.
param([string]$Log = "$env:USERPROFILE\skewer-report-smoke.log")
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
function FindNamed($root, $name) {
    $condition = [System.Windows.Automation.PropertyCondition]::new(
        [System.Windows.Automation.AutomationElement]::NameProperty, $name)
    return $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
}
function ReportText($window) {
    $elements = $window.FindAll([System.Windows.Automation.TreeScope]::Descendants,
        [System.Windows.Automation.Condition]::TrueCondition)
    return @($elements | ForEach-Object { $_.Current.Name } |
        Where-Object { $_ -like 'Report accepted at *' }) -join ''
}
try {
    $window = FindNamed ([System.Windows.Automation.AutomationElement]::RootElement) 'Skewer'
    if (!$window) { throw 'Skewer window not found' }
    $tab = FindNamed $window 'Saslik'
    if (!$tab) { throw 'Saslik tab missing' }
    $tab.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
    $first = ''
    for ($i = 0; $i -lt 20 -and !$first; $i++) {
        Start-Sleep -Seconds 1
        $first = ReportText $window
    }
    if (!$first) { throw 'First report was not accepted' }
    $pattern = $window.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern)
    $pattern.SetWindowVisualState([System.Windows.Automation.WindowVisualState]::Minimized)
    Start-Sleep -Seconds 12
    $pattern.SetWindowVisualState([System.Windows.Automation.WindowVisualState]::Normal)
    $second = ReportText $window
    if (!$second -or $first -eq $second) { throw 'Reporting did not renew while minimized' }
    (FindNamed $window 'Stop reporting').GetCurrentPattern(
        [System.Windows.Automation.InvokePattern]::Pattern).Invoke()
    Start-Sleep -Seconds 1
    if (!(FindNamed $window 'Start reporting')) { throw 'Stop reporting failed' }
    (FindNamed $window 'Start reporting').GetCurrentPattern(
        [System.Windows.Automation.InvokePattern]::Pattern).Invoke()
    "PASS: accepted reports, minimized renewal and stop/start controls" | Set-Content $Log
} catch {
    "FAIL: $_" | Set-Content $Log
    exit 1
}
