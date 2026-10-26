# Run unelevated in the disposable development desktop, with Skewer open.
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$log = "$env:USERPROFILE\skewer-application-smoke.log"
$ErrorActionPreference = 'Stop'
function FindWindow {
    $condition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::NameProperty, 'Skewer')
    return [System.Windows.Automation.AutomationElement]::RootElement.FindFirst([System.Windows.Automation.TreeScope]::Children, $condition)
}
function FindNamed($window, $name) {
    $condition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::NameProperty, $name)
    return $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
}
function WindowText($window) {
    $elements = $window.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
    return ($elements | ForEach-Object { $_.Current.Name }) -join "`n"
}
try {
    'Starting interactive Windows smoke test' | Out-File $log
    $window = FindWindow
    if (!$window) { throw 'Shared Skewer window missing' }
    $skewerId = $window.Current.ProcessId
    $exe = (Get-Process -Id $skewerId).Path
    # Window enumeration must be tested on the desktop, not only through SSH.
    $probe = Join-Path (Split-Path $exe) 'skewer-process-probe.exe'
    $nativeOutput = & $probe --self-test 2>&1
    $nativeOutput | Out-File $log -Append
    if ($LASTEXITCODE -ne 0) {
        throw 'Native backend self-test failed'
    }
    $attach = FindNamed $window 'Attach to Skewer'
    $release = FindNamed $window 'Release'
    if (!$attach -or !$release -or $attach.Current.IsEnabled -or $release.Current.IsEnabled) { throw 'Unsupported routing actions exposed' }
    'PASS: unsupported routing stays disabled' | Out-File $log -Append
    foreach ($tab in @('Applications', 'CA Trust', 'Runtime Trust', 'Connections')) {
        if (!(FindNamed $window $tab)) { throw "Missing tab: $tab" }
    }
    'PASS: shared application tabs' | Out-File $log -Append
    $edit = FindNamed $window 'Application executable'
    $value = $edit.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
    $invoke = (FindNamed $window 'Launch').GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
    $value.SetValue('C:\SkewerDev\does-not-exist.exe')
    $invoke.Invoke()
    Start-Sleep -Seconds 2
    if ((WindowText $window) -notmatch 'Launch failed:') { throw 'Missing failure feedback' }
    'PASS: failed launch feedback' | Out-File $log -Append
    $value.SetValue('C:\Windows\System32\notepad.exe')
    $invoke.Invoke()
    Start-Sleep -Seconds 6
    if ((WindowText $window) -notmatch 'Started PID.*NOT routed') { throw 'Missing unrouted launch feedback' }
    $notepadIds = @(Get-Process notepad -ErrorAction SilentlyContinue).Id
    if (!$notepadIds) { throw 'No launched Notepad' }
    'PASS: launch feedback and application start' | Out-File $log -Append
    $search = (FindNamed $window 'Find application').GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
    $search.SetValue('Notepad')
    Start-Sleep -Seconds 1
    $search.SetValue('')
    'PASS: shared search field accepts and clears filter' | Out-File $log -Append
    $second = Start-Process -FilePath $exe -PassThru
    if (!$second.WaitForExit(5000) -or $second.ExitCode -ne 0) { throw 'Second invocation failed to activate existing window' }
    if ((FindWindow).Current.ProcessId -ne $skewerId) { throw 'Second invocation created another main window' }
    'PASS: single-instance activation' | Out-File $log -Append
    $window.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern).Close()
    Start-Sleep -Seconds 2
    foreach ($processId in $notepadIds) {
        if (!(Get-Process -Id $processId -ErrorAction SilentlyContinue)) { throw 'Closing Skewer terminated a launched application' }
    }
    'PASS: close leaves launched programs running' | Out-File $log -Append
    Start-Process -FilePath $exe | Out-Null
    Start-Sleep -Seconds 2
    if (!(FindWindow)) { throw 'Could not reopen Skewer' }
    'PASS: window restored after close' | Out-File $log -Append
    'Exit: 0' | Out-File $log -Append
} catch {
    "FAIL: $_" | Out-File $log -Append
    'Exit: 1' | Out-File $log -Append
}
