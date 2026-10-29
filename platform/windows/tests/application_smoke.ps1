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
function FindAutomationId($window, $id) {
    $condition = [System.Windows.Automation.PropertyCondition]::new(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty, $id)
    return $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
}
function WindowText($window) {
    $elements = $window.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
    return ($elements | ForEach-Object { $_.Current.Name }) -join "`n"
}
function SelectTab($window, $name) {
    $tab = FindNamed $window $name
    if (!$tab) { throw "Missing tab: $name" }
    try {
        $tab.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
    } catch {
        $tab.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
    }
}
try {
    'Starting interactive Windows smoke test' | Out-File $log
    $deadline=(Get-Date).AddSeconds(10)
    do {
        $window = FindWindow
        if (!$window) { Start-Sleep -Milliseconds 200 }
    } while (!$window -and (Get-Date) -lt $deadline)
    if (!$window) { throw 'Shared Skewer window missing' }
    SelectTab $window 'Applications'
    Start-Sleep -Milliseconds 300
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
    if (!$attach -or !$release -or ($attach.Current.IsEnabled -and $release.Current.IsEnabled)) {
        throw "Routing actions do not reflect one authoritative service state (Attach=$($attach.Current.IsEnabled), Release=$($release.Current.IsEnabled))"
    }
    'PASS: authoritative Attach/Release controls' | Out-File $log -Append
    $routingStatus = FindNamed $window 'Windows routing status'
    if (!$routingStatus -or [string]::IsNullOrWhiteSpace($routingStatus.Current.Name)) {
        throw 'Authoritative routing status is not visible outside the Routing tab'
    }
    if ((WindowText $window) -match 'Whole-host routing: see Routing tab') {
        throw 'Obsolete duplicate routing status is still visible'
    }
    'PASS: persistent routing status indicator' | Out-File $log -Append
    foreach ($tab in @('Applications', 'CA Trust', 'Runtime Trust', 'Connections', 'Saslik', 'Routing')) {
        if (!(FindNamed $window $tab)) { throw "Missing tab: $tab" }
    }
    'PASS: shared application tabs' | Out-File $log -Append
    SelectTab $window 'Runtime Trust'
    Start-Sleep -Milliseconds 300
    foreach ($control in @('Prepare managed bundle', 'Remove managed bundle', 'Copy PowerShell setup')) {
        if (!(FindNamed $window $control)) { throw "Missing native Runtime Trust control: $control" }
    }
    if ((WindowText $window) -notmatch 'Only new programs launched by Skewer') {
        throw 'Runtime Trust scope is not explained in the native panel'
    }
    'PASS: native managed runtime-trust controls' | Out-File $log -Append
    SelectTab $window 'Saslik'
    Start-Sleep -Milliseconds 300
    $pairedStatus = FindNamed $window 'Authenticated lab status'
    foreach ($control in @('Open Saslik', 'Open Spider')) {
        if (!(FindNamed $window $control)) { throw "Missing paired lab link control: $control" }
    }
    if (!$pairedStatus) { throw 'Missing selectable authenticated lab status panel' }
    'PASS: authenticated paired lab status and safe link controls' | Out-File $log -Append
    $invitation = FindNamed $window 'Saslik pairing invitation'
    $pair = FindNamed $window 'Pair with Saslik'
    if (!$invitation -or !$invitation.Current.IsPassword -or !$pair -or !$pair.Current.IsEnabled) {
        throw 'Native protected pairing controls are unavailable'
    }
    $invitation.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).SetValue(
        'not-a-pairing-invitation')
    $pair.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
    $deadline = (Get-Date).AddSeconds(5)
    do {
        Start-Sleep -Milliseconds 100
        $text = WindowText $window
    } while ($text -notmatch 'Pairing failed' -and (Get-Date) -lt $deadline)
    $genericFailure = $text -match 'Pairing failed'
    $inputExposed = $text -match 'not-a-pairing-invitation'
    if (!$genericFailure -or $inputExposed) {
        throw "Pairing failure feedback invalid (generic=$genericFailure, inputExposed=$inputExposed, buttonEnabled=$($pair.Current.IsEnabled))"
    }
    'PASS: protected in-GUI pairing with generic failure feedback' | Out-File $log -Append
    SelectTab $window 'Connections'
    Start-Sleep -Seconds 4
    if ((WindowText $window) -notmatch '[0-9]+ TCP sockets and [0-9]+ UDP binds from the Windows owner tables') {
        throw 'Native Windows connection inventory did not populate'
    }
    'PASS: native Windows TCP/UDP connection inventory' | Out-File $log -Append
    SelectTab $window 'Routing'
    Start-Sleep -Milliseconds 500
    $transport = FindAutomationId $window 'routingTransport'
    if (!$transport) { $transport = FindNamed $window 'Whole-host transport' }
    $gateway = FindAutomationId $window 'routingGateway'
    if (!$gateway) { $gateway = FindNamed $window 'Direct gateway' }
    if (!$transport -or !$gateway) {
        throw 'Missing whole-host transport or direct-gateway control'
    }
    if ($transport.Current.ControlType -ne [System.Windows.Automation.ControlType]::ComboBox -or
        $gateway.Current.ControlType -ne [System.Windows.Automation.ControlType]::Edit) {
        throw 'Whole-host transport controls expose unexpected accessibility roles'
    }
    # Qt does not expose a QLabel objectName as a UIA AutomationId. Capture
    # the exact visible status while the authoritative Routing panel is open.
    $routingPanelText = WindowText $window
    $routingReady = $routingPanelText -match '(?m)^Idle . paired control ready\r?$'
    'PASS: whole-host Auto/tunnel/direct transport controls' | Out-File $log -Append
    $package = Split-Path $exe
    $completeRuntime = @('install-routing-service.ps1','remove-routing-service.ps1',
                         'wintun.dll','WinDivert.dll','WinDivert64.sys') |
        ForEach-Object { Test-Path (Join-Path $package $_) } | Where-Object { !$_ }
    if (!$completeRuntime) {
        $buttons = $window.FindAll([System.Windows.Automation.TreeScope]::Descendants,
            [System.Windows.Automation.PropertyCondition]::new(
                [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
                [System.Windows.Automation.ControlType]::Button))
        $install = $buttons | Where-Object { $_.Current.Name -like '*routing service*' } | Select-Object -First 1
        if (!$install -or !$install.Current.IsEnabled) {
            throw "Complete package did not enable service installation:`n$(WindowText $window)"
        }
        $remove = $buttons | Where-Object { $_.Current.Name -like 'Remove service*' } | Select-Object -First 1
        if (!$remove) { throw 'Missing explicit routing service removal control' }
        'PASS: complete package enables explicit UAC service management' | Out-File $log -Append
    }
    SelectTab $window 'Applications'
    $edit = FindNamed $window 'Application executable'
    $value = $edit.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
    $normal = FindNamed $window 'Launch normally'
    $routed = FindNamed $window 'Launch through Skewer'
    if (!$normal -or !$routed -or !$normal.Current.IsEnabled) {
        throw 'Missing launcher routing choice'
    }
    if ($routed.Current.IsEnabled -ne $routingReady) {
        throw "Routed launch disagrees with authoritative Routing panel state:`n$routingPanelText"
    }
    'PASS: normal and routed launch actions are explicit' | Out-File $log -Append
    $invoke = $normal.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
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
