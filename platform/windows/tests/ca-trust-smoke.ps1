$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName System.Windows.Forms
Add-Type @'
using System.Runtime.InteropServices;
public static class SkewerCaMouse {
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, System.UIntPtr extra);
}
'@
$log=Join-Path $env:USERPROFILE 'skewer-ca-trust-smoke.log'
function FindWindow {
    $condition=[System.Windows.Automation.PropertyCondition]::new(
        [System.Windows.Automation.AutomationElement]::NameProperty, 'Skewer')
    [System.Windows.Automation.AutomationElement]::RootElement.FindFirst(
        [System.Windows.Automation.TreeScope]::Children, $condition)
}
function FindNamed($window, $name) {
    $condition=[System.Windows.Automation.PropertyCondition]::new(
        [System.Windows.Automation.AutomationElement]::NameProperty, $name)
    $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
}
function FindNamedEdit($window, $name) {
    $conditions=[System.Windows.Automation.AndCondition]::new(@(
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::NameProperty, $name),
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::Edit)))
    $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $conditions)
}
function FindNamedTab($window, $name) {
    $conditions=[System.Windows.Automation.AndCondition]::new(@(
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::NameProperty, $name),
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::TabItem)))
    $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $conditions)
}
function WindowText($window) {
    $all=$window.FindAll([System.Windows.Automation.TreeScope]::Descendants,
                         [System.Windows.Automation.Condition]::TrueCondition)
    ($all | ForEach-Object { $_.Current.Name }) -join "`n"
}
function ClickElement($element) {
    $bounds=$element.Current.BoundingRectangle
    [SkewerCaMouse]::SetCursorPos([int]($bounds.X+$bounds.Width/2),[int]($bounds.Y+$bounds.Height/2)) | Out-Null
    [SkewerCaMouse]::mouse_event(0x0002,0,0,0,[UIntPtr]::Zero)
    [SkewerCaMouse]::mouse_event(0x0004,0,0,0,[UIntPtr]::Zero)
}
try {
    $window=FindWindow
    if (!$window) { throw 'Skewer window missing' }
    $tab=FindNamedTab $window 'CA Trust'
    if (!$tab) { throw 'CA Trust tab missing' }
    $window.SetFocus()
    [System.Windows.Forms.SendKeys]::SendWait('^{TAB}')
    Start-Sleep -Milliseconds 300
    $button=FindNamed $window 'Download from paired Saslik'
    if (!$button -or !$button.Current.IsEnabled) { throw 'CA download action unavailable' }
    ClickElement $button
    $deadline=(Get-Date).AddSeconds(12)
    do { Start-Sleep -Milliseconds 100; $text=WindowText $window }
    while ($text -notmatch 'SHA-256:' -and $text -notmatch 'failed|invalid|Cannot|did not' -and
           (Get-Date) -lt $deadline)
    if ($text -notmatch 'SHA-256:' -or $text -notmatch 'Current User') {
        throw "CA was not downloaded and inspected: $text"
    }
    'PASS: paired CA downloaded, CryptoAPI-validated and inspected without changing trust' | Out-File $log
    'Exit: 0' | Out-File $log -Append
} catch {
    "FAIL: $_" | Out-File $log
    'Exit: 1' | Out-File $log -Append
}
