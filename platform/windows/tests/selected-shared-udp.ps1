param([string]$Directory='C:\SkewerDev\skewer-windows-app',
      [Parameter(Mandatory=$true)][string]$Service,
      [Parameter(Mandatory=$true)][string]$Address,
      [int]$Port=18083, [string]$Scratch='', [switch]$Child)
$ErrorActionPreference='Stop'
function WaitFile([string]$name) {
    $deadline=(Get-Date).AddSeconds(40)
    while (!(Test-Path (Join-Path $Scratch $name))) {
        if (!$Child -and $process -and $process.HasExited) { throw "Child exited before $name" }
        if ((Get-Date) -gt $deadline) { throw "Timed out waiting for $name" }
        Start-Sleep -Milliseconds 50
    }
}
if ($Child) {
    $sockets=@()
    try {
        $localPort=0
        foreach ($index in 0..1) {
            $socket=[Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork,
                [Net.Sockets.SocketType]::Dgram,[Net.Sockets.ProtocolType]::Udp)
            $sockets+=,$socket
            $socket.ExclusiveAddressUse=$false
            $socket.SetSocketOption([Net.Sockets.SocketOptionLevel]::Socket,
                [Net.Sockets.SocketOptionName]::ReuseAddress,$true)
            $socket.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Any,$localPort))
            $localPort=$socket.LocalEndPoint.Port
        }
        $peer=[Net.IPEndPoint]::new([Net.IPAddress]::Parse($Address),$Port)
        foreach ($socket in $sockets) { $null=$socket.SendTo([byte[]]@(65),$peer) }
        Set-Content (Join-Path $Scratch 'ready') $localPort
        WaitFile 'probe'
        # The observer sees this bind, but missed the two pre-Attach binds.
        # One observed socket must not override ambiguous owner-table evidence.
        $socket=[Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork,
            [Net.Sockets.SocketType]::Dgram,[Net.Sockets.ProtocolType]::Udp)
        $sockets+=,$socket
        $socket.ExclusiveAddressUse=$false
        $socket.SetSocketOption([Net.Sockets.SocketOptionLevel]::Socket,
            [Net.Sockets.SocketOptionName]::ReuseAddress,$true)
        $socket.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Any,$localPort))
        foreach ($socket in $sockets) { $null=$socket.SendTo([byte[]]@(66),$peer) }
        Set-Content (Join-Path $Scratch 'sent') 'ok'
        WaitFile 'release'
        foreach ($socket in $sockets) { $null=$socket.SendTo([byte[]]@(82),$peer) }
        Set-Content (Join-Path $Scratch 'restored') 'ok'
    } finally { foreach ($socket in $sockets) { $socket.Dispose() } }
    exit 0
}
$client=Join-Path $Directory 'skewer-routing-control.exe'
function Command([string[]]$arguments) {
    $reply=& $client @arguments
    if ($LASTEXITCODE -ne 0) { throw "Routing command failed: $reply" }
    return $reply | ConvertFrom-Json
}
function PeerCounts {
    $socket=[Net.Sockets.TcpClient]::new()
    try {
        if (!$socket.ConnectAsync($Address,$Port).Wait(5000)) { throw 'Peer query timed out' }
        $socket.ReceiveTimeout=3000
        $reader=[IO.StreamReader]::new($socket.GetStream())
        return $reader.ReadLine() | ConvertFrom-Json
    } finally { $socket.Dispose() }
}
$initial=Command @('status',$Service)
if ($initial.phase -ne 0 -or !$initial.paired) { throw 'Need idle paired service' }
if ((PeerCounts).B -ne 0) { throw 'Peer must have fresh counters' }
$Scratch=Join-Path $env:TEMP ('skewer-shared-udp-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $Scratch | Out-Null
$process=$null
$generation=$null
try {
    $process=Start-Process (Join-Path $PSHOME 'powershell.exe') -PassThru -RedirectStandardOutput (Join-Path $Scratch 'child.stdout') -RedirectStandardError (Join-Path $Scratch 'child.stderr') -ArgumentList @(
        '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"",
        '-Child','-Service',$Service,'-Address',$Address,'-Port',$Port,'-Scratch',"`"$Scratch`"")
    $null=$process.Handle
    WaitFile 'ready'
    Start-Sleep -Milliseconds 200
    if ((PeerCounts).A -ne 2) { throw 'Both shared sockets must reach the external peer before Attach' }
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
    # Query actual delivery from an unselected process, not a missing UDP reply.
    if ((PeerCounts).B -ne 0) { throw 'Ambiguous selected UDP reached the external peer' }
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
    if ($process.ExitCode -ne 0) { throw "Child failed: $($process.ExitCode)" }
    if ((PeerCounts).R -ne 3) { throw 'All original and new sockets must recover after Release' }
    Write-Output 'PASS: old/new shared UDP blocked at external peer, unrelated control works, all sockets recover after Release'
} finally {
    if ($generation) { & $client stop $Service $generation | Out-Null }
    if ($process -and !$process.HasExited) { $process.Kill(); $process.WaitForExit(5000) | Out-Null }
    if ($process) { $process.Dispose() }
    Write-Output "Results retained at $Scratch"
}
