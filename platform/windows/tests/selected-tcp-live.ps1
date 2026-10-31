param(
    [string]$Directory='C:\SkewerDev\skewer-windows-app',
    [string]$Endpoint='skewer://172.30.1.73:8766/pair',
    [string]$Peer='172.30.1.73',
    [string]$Destination='172.66.147.243',
    [string]$HostName='example.com'
)
$ErrorActionPreference='Stop'
$logRoot=Join-Path ([IO.Path]::GetTempPath()) ('skewer-selected-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $logRoot
$stdout=Join-Path $logRoot 'probe.out'
$stderr=Join-Path $logRoot 'probe.err'
$process=$null
try {
    $process=Start-Process -FilePath (Join-Path $Directory 'selected_tcp_live.exe') `
        -ArgumentList @($Endpoint,$Peer,$Destination,$HostName,'--tls','--broad') `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -NoNewWindow
    # Retain the native process handle before exit; Windows PowerShell may
    # otherwise lose ExitCode when Start-Process releases its temporary handle.
    $null=$process.Handle
    $deadline=[DateTime]::UtcNow.AddSeconds(15)
    while ((Get-Content -LiteralPath $stdout -Raw) -notmatch 'CAPTURE READY:') {
        if ($process.HasExited -or [DateTime]::UtcNow -ge $deadline) { throw 'Capture did not become ready' }
        Start-Sleep -Milliseconds 100
    }
    # A separate executable/process must remain usable on its ordinary route.
    & curl.exe --noproxy '*' -4 -k --resolve "${HostName}:443:${Destination}" `
        --max-time 12 --silent --show-error --output NUL "https://${HostName}/"
    if ($LASTEXITCODE -ne 0) { throw 'Unselected curl failed during selected routing' }
    if (!$process.WaitForExit(35000)) { throw 'Selected probe exceeded its bounded lifetime' }
    $output=Get-Content -LiteralPath $stdout -Raw
    if ($process.ExitCode -ne 0 -or $output -notmatch 'PASS: selected HTTPS' -or
        $output -notmatch 'direct=([1-9][0-9]*)') {
        throw "Selected routing/direct bypass not proven. Inspect $logRoot"
    }
    Write-Output $output
    Write-Output 'PASS: concurrent unselected curl and selected HTTPS with explicit direct decisions'
} finally {
    if ($process -and !$process.HasExited) { Stop-Process -Id $process.Id -Force }
    Write-Output "Diagnostic logs retained: $logRoot"
}
