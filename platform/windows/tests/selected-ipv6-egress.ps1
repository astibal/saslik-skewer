param(
    [string]$Directory='C:\SkewerDev\skewer-windows-app',
    [string]$Service='SkewerRouting',
    [Parameter(Mandatory=$true)][string]$Url,
    [string]$ExpectedNextHop='',
    [string]$ResultDirectory='',
    [switch]$Child
)
$ErrorActionPreference='Stop'
# Explicit VM fixture: provide an IPv6 HTTP listener on another machine.
# A successful baseline is mandatory; an unreachable peer is never a pass.
function Probe {
    & curl.exe --noproxy '*' -6 --fail --silent --max-time 4 --output NUL $Url
    return $LASTEXITCODE
}
if ($Child) {
    $code=Probe
    Set-Content (Join-Path $ResultDirectory 'result') $code
    # Keep the exact selected root alive for the unrelated-process control.
    $deadline=(Get-Date).AddSeconds(120)
    while (!(Test-Path (Join-Path $ResultDirectory 'release')) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 50
    }
    if (Test-Path (Join-Path $ResultDirectory 'release')) {
        Set-Content (Join-Path $ResultDirectory 'restored') (Probe)
    }
    exit 0
}
if ($Url -notmatch '^http://\[') { throw 'Expected an explicit IPv6 HTTP URL' }
if ($ExpectedNextHop) {
    # An explicit /128 route makes the routed fixture distinct from an on-link
    # control. Do not silently accept a topology that never exercises a router.
    $destination=[Net.IPAddress]::Parse(([Uri]$Url).DnsSafeHost.Trim('[',']')).ToString()
    $routes=@(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix "$destination/128" -ErrorAction SilentlyContinue)
    if ($ExpectedNextHop -eq '::' -or $routes.Count -ne 1 -or $routes[0].NextHop -ne $ExpectedNextHop) {
        throw 'Expected a unique routed IPv6 host route through the requested next hop'
    }
}
$client=Join-Path $Directory 'skewer-routing-control.exe'
$state=& $client status $Service | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $state.phase -ne 0 -or !$state.paired) {
    throw 'Fixture requires an idle, paired service'
}
if ((Probe) -ne 0) { throw 'IPv6 peer is not reachable before selection' }
$scratch=Join-Path $env:TEMP ('skewer-ipv6-egress-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $scratch | Out-Null
$launched=$null
try {
    $shell=Join-Path $PSHOME 'powershell.exe'
    # Do not capture a console process tree in a PowerShell pipeline: inherited
    # standard streams can keep that pipeline open after the launcher exits.
    $arguments=@('run',$Service,"`"$shell`"",'-NoProfile','-NonInteractive',
        '-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"",'-Child',
        '-Url',"`"$Url`"",'-ResultDirectory',"`"$scratch`"")
    $launcher=New-Object System.Diagnostics.Process
    $launcher.StartInfo.FileName=$client
    $launcher.StartInfo.Arguments=$arguments -join ' '
    $launcher.StartInfo.UseShellExecute=$false
    $launcher.StartInfo.RedirectStandardOutput=$true
    try {
        if (!$launcher.Start()) { throw 'Cannot start routing launcher' }
        if (!$launcher.WaitForExit(45000) -or $launcher.ExitCode -ne 0) {
            throw 'Selected IPv6 probe launch failed'
        }
        $launched=$launcher.StandardOutput.ReadLine() | ConvertFrom-Json
    } finally { $launcher.Dispose() }
    $deadline=(Get-Date).AddSeconds(15)
    while (!(Test-Path (Join-Path $scratch 'result')) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 50
    }
    if (!(Test-Path (Join-Path $scratch 'result'))) { throw 'Selected probe did not report a result' }
    $code=[int](Get-Content (Join-Path $scratch 'result'))
    if ($code -notin @(7,28)) { throw "Expected connection rejection/timeout, got curl exit $code" }
    $state=& $client status $Service | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $state.phase -ne 2 -or $state.generation -ne $launched.generation) {
        throw 'Selection was not active during the blocked probe'
    }
    if ((Probe) -ne 0) { throw 'Selection disrupted an unrelated IPv6 process' }
    $released=& $client remove $Service $launched.generation $launched.pid $launched.birth
    if ($LASTEXITCODE -ne 0) { throw "Cannot release IPv6 probe: $released" }
    $deadline=(Get-Date).AddSeconds(10)
    do {
        Start-Sleep -Milliseconds 100
        $state=& $client status $Service | ConvertFrom-Json
    } while ($state.phase -ne 0 -and (Get-Date) -lt $deadline)
    if ($state.phase -ne 0) { throw 'IPv6 fixture did not return service to idle' }
    New-Item -ItemType File (Join-Path $scratch 'release') | Out-Null
    $deadline=(Get-Date).AddSeconds(15)
    while (!(Test-Path (Join-Path $scratch 'restored')) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 50
    }
    if (!(Test-Path (Join-Path $scratch 'restored')) -or
        [int](Get-Content (Join-Path $scratch 'restored')) -ne 0) {
        throw 'Released application did not regain IPv6 connectivity'
    }
    if ((Probe) -ne 0) { throw 'IPv6 peer unavailable after Release' }
    Write-Output 'PASS: external IPv6 blocked for selected descendant, unrelated IPv6 unaffected, Release restores idle'
} finally {
    if ($launched) {
        & $client stop $Service $launched.generation | Out-Null
    }
    New-Item -ItemType File (Join-Path $scratch 'release') -Force | Out-Null
    Write-Output "Fixture results retained at $scratch"
}
