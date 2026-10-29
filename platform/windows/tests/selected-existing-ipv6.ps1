param([string]$Directory='C:\SkewerDev\skewer-windows-app',
      [Parameter(Mandatory=$true)][string]$Service,
      [Parameter(Mandatory=$true)][string]$Address,
      [int]$Port=18082, [string]$Scratch='', [switch]$Child)
$ErrorActionPreference='Stop'
function ConnectPeer {
    $socket=[Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetworkV6)
    $task=$socket.ConnectAsync([Net.IPAddress]::Parse($Address),$Port)
    if (!$task.Wait(5000)) { $socket.Dispose(); throw 'IPv6 peer connect timed out' }
    $socket.ReceiveTimeout=3000
    $socket.SendTimeout=3000
    return $socket
}
function WaitFile([string]$name) {
    $deadline=(Get-Date).AddSeconds(40)
    while (!(Test-Path (Join-Path $Scratch $name))) {
        if (!$Child -and $process -and $process.HasExited) {
            throw "Child exited before $name; see $Scratch\child.stderr"
        }
        if ((Get-Date) -gt $deadline) { throw "Timed out waiting for $name" }
        Start-Sleep -Milliseconds 50
    }
}
if ($Child) {
    $socket=ConnectPeer
    try {
        $stream=$socket.GetStream()
        $stream.WriteByte(65)
        if ($stream.ReadByte() -ne 65) { throw 'Baseline echo failed' }
        Set-Content (Join-Path $Scratch 'ready') 'ok'
        WaitFile 'probe'
        $stream.WriteByte(66)
        Set-Content (Join-Path $Scratch 'sent') 'ok'
        WaitFile 'release'
        $stream.WriteByte(82)
        $deadline=(Get-Date).AddSeconds(20)
        $restored=$false
        while ((Get-Date) -lt $deadline) {
            try { if ($stream.ReadByte() -eq 82) { $restored=$true; break } } catch [IO.IOException] {}
        }
        if (!$restored) { throw 'Original IPv6 connection did not recover' }
        Set-Content (Join-Path $Scratch 'restored') 'ok'
    } finally { $socket.Dispose() }
    exit 0
}
$client=Join-Path $Directory 'skewer-routing-control.exe'
function Command([string[]]$arguments) {
    $reply=& $client @arguments
    if ($LASTEXITCODE -ne 0) { throw "Routing command failed: $reply" }
    return $reply | ConvertFrom-Json
}
$initial=Command @('status',$Service)
if ($initial.phase -ne 0 -or !$initial.paired) { throw 'Need idle paired service' }
$Scratch=Join-Path $env:TEMP ('skewer-existing-ipv6-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $Scratch | Out-Null
$process=$null
$generation=$null
try {
    $process=Start-Process (Join-Path $PSHOME 'powershell.exe') -PassThru -RedirectStandardOutput (Join-Path $Scratch 'child.stdout') -RedirectStandardError (Join-Path $Scratch 'child.stderr') -ArgumentList @(
        '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"",
        '-Child','-Service',$Service,'-Address',$Address,'-Port',$Port,'-Scratch',"`"$Scratch`"")
    # Retain a native handle before a short-lived child exits; PowerShell's
    # Start-Process wrapper otherwise may not retain its exit-code state.
    $null=$process.Handle
    WaitFile 'ready'
    $birth=$process.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
    $attached=Command @('attach',$Service,$initial.generation,$process.Id,$birth)
    $generation=$attached.generation
    $deadline=(Get-Date).AddSeconds(30)
    do {
        $state=Command @('status',$Service)
        if ($state.generation -ne $generation -or $state.phase -notin @(1,2,3)) { throw 'Selected generation retired' }
        if ($state.phase -eq 2) { break }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    if ($state.phase -ne 2) { throw 'Attach never became Active' }
    Set-Content (Join-Path $Scratch 'probe') 'ok'
    WaitFile 'sent'
    Start-Sleep -Seconds 3
    # Query the independent listener from this unselected parent. This checks
    # real outbound delivery, not merely absence of a reply at the client.
    $control=ConnectPeer
    try {
        $stream=$control.GetStream()
        $stream.WriteByte(63)
        $reader=[IO.StreamReader]::new($stream)
        if ($reader.ReadLine() -ne '0') { throw 'Protected IPv6 byte reached external listener' }
    } finally { $control.Dispose() }
    $state=Command @('status',$Service)
    if ($state.phase -ne 2 -or $state.generation -ne $generation) { throw 'Protection was not Active' }
    $null=Command @('remove',$Service,$generation,$process.Id,$birth)
    $deadline=(Get-Date).AddSeconds(10)
    do { $state=Command @('status',$Service); Start-Sleep -Milliseconds 100 } while ($state.phase -ne 0 -and (Get-Date) -lt $deadline)
    if ($state.phase -ne 0) { throw 'Release did not finish' }
    $generation=$null
    Set-Content (Join-Path $Scratch 'release') 'ok'
    WaitFile 'restored'
    if (!$process.WaitForExit(5000)) { throw 'Child did not exit after Release' }
    $process.Refresh()
    if ($process.ExitCode -ne 0) { throw "Child failed after Release: $($process.ExitCode)" }
    Write-Output 'PASS: pre-existing external IPv6 socket blocked at peer, unrelated control unaffected, same socket recovers after Release'
} finally {
    if ($generation) { & $client stop $Service $generation | Out-Null }
    if ($process -and !$process.HasExited) { $process.Kill(); $process.WaitForExit(5000) | Out-Null }
    if ($process) { $process.Dispose() }
    Write-Output "Results retained at $Scratch"
}
