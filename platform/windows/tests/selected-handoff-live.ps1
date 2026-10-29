param(
    [string]$Directory='C:\SkewerDev\skewer-windows-app',
    [string]$Service='SkewerRouting',
    [string]$Url='https://example.com/',
    [ValidateSet('Parent','Broker','Launcher')][string]$Role='Parent',
    [string]$Prefix=''
)
$ErrorActionPreference='Stop'
if ($Role -ne 'Parent') {
    $go=[Threading.EventWaitHandle]::OpenExisting($Prefix+'-go')
    $done=[Threading.EventWaitHandle]::OpenExisting($Prefix+'-done')
    $release=[Threading.EventWaitHandle]::OpenExisting($Prefix+'-release')
    try {
        if ($Role -eq 'Launcher') {
            $null=$go.Set()
            if (!$release.WaitOne(60000)) { throw 'Launcher release timed out' }
        } else {
            if (!$go.WaitOne(60000)) { throw 'Broker received no handoff' }
            & curl.exe --noproxy '*' -4 -k --fail --silent --max-time 10 --output NUL $Url
            if ($LASTEXITCODE -ne 0) { throw 'Existing broker could not complete HTTP(S)' }
            $null=$done.Set()
            if (!$release.WaitOne(60000)) { throw 'Broker release timed out' }
        }
    } finally { $go.Dispose(); $done.Dispose(); $release.Dispose() }
    exit 0
}
$client=Join-Path $Directory 'skewer-routing-control.exe'
function Status {
    $state=& $client status $Service | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read authoritative routing state' }
    return $state
}
$initial=Status
if ($initial.phase -ne 0 -or !$initial.paired) { throw 'Handoff fixture requires a paired idle service' }
$Prefix='Local\SkewerHandoff-'+[Guid]::NewGuid().ToString('N')
$go=[Threading.EventWaitHandle]::new($false,'ManualReset',$Prefix+'-go')
$done=[Threading.EventWaitHandle]::new($false,'ManualReset',$Prefix+'-done')
$release=[Threading.EventWaitHandle]::new($false,'ManualReset',$Prefix+'-release')
$broker=$null
$launcher=$null
$launched=$null
try {
    $shell=Join-Path $PSHOME 'powershell.exe'
    $common=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',
        "`"$PSCommandPath`"",'-Prefix',"`"$Prefix`"",'-Url',"`"$Url`"")
    # Start the singleton outside the selected tree. The later launcher can
    # signal it, but that IPC relationship must not grant routing membership.
    $broker=Start-Process $shell -ArgumentList ($common+@('-Role','Broker')) -PassThru -NoNewWindow
    $null=$broker.Handle
    $brokerBirth=$broker.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
    $launcher=[Diagnostics.Process]::new()
    $launcher.StartInfo.FileName=$client
    $launcher.StartInfo.Arguments=(@('run',$Service,"`"$shell`"")+$common+@('-Role','Launcher')) -join ' '
    $launcher.StartInfo.UseShellExecute=$false
    $launcher.StartInfo.RedirectStandardOutput=$true
    if (!$launcher.Start() -or !$launcher.WaitForExit(45000) -or $launcher.ExitCode -ne 0) {
        throw 'Selected handoff launch failed'
    }
    $launched=$launcher.StandardOutput.ReadLine() | ConvertFrom-Json
    if (!$done.WaitOne(15000)) { throw 'Existing broker did not complete handoff work' }
    $state=Status
    if ($state.phase -ne 2 -or $state.generation -ne $launched.generation -or $state.membersTruncated) {
        throw 'Handoff did not retain an authoritative active selection'
    }
    if (!($state.members | Where-Object { $_.pid -eq $launched.pid -and $_.birth -eq $launched.birth })) {
        throw 'Selected launcher missing from membership'
    }
    if ($state.members | Where-Object { $_.pid -eq $broker.Id -and $_.birth -eq $brokerBirth }) {
        throw 'Existing singleton silently acquired a routed badge'
    }
    if ($broker.HasExited) { throw 'Existing broker exited prematurely' }
    $null=$release.Set()
    if (!$broker.WaitForExit(5000) -or $broker.ExitCode -ne 0) { throw 'Broker cleanup failed' }
    $deadline=(Get-Date).AddSeconds(10)
    do {
        $state=Status
        if ($state.phase -eq 0) { break }
        if ($state.phase -eq 5) { throw 'Normal launcher exit was reported as a routing failure' }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    if ($state.phase -ne 0) { throw 'Completed selected group did not return to Idle' }
    'PASS: selected launcher hands work to existing unselected broker; HTTP(S) succeeds without false membership; normal exit returns Idle'
} finally {
    $null=$release.Set()
    if ($launched) {
        $state=Status
        if ($state.generation -eq $launched.generation -and $state.phase -ne 0) {
            & $client stop $Service $state.generation | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Cannot stop the fixture generation' }
        }
    }
    if ($broker) {
        if (!$broker.HasExited -and !$broker.WaitForExit(5000)) { $broker.Kill(); $broker.WaitForExit() }
        $broker.Dispose()
    }
    if ($launcher) { $launcher.Dispose() }
    $go.Dispose(); $done.Dispose(); $release.Dispose()
}
