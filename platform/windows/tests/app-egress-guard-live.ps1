param([Parameter(Mandatory=$true)][string]$Directory)
$ErrorActionPreference = 'Stop'
# VM-only fixture. Never targets a browser, shell, service or user application.
$id = [guid]::NewGuid().ToString()
$selected = Join-Path $Directory "guard-selected-$id.exe"
$unselected = Join-Path $Directory "guard-unselected-$id.exe"
$stdout = Join-Path $Directory "guard-$id.out"
$stderr = Join-Path $Directory "guard-$id.err"
$binary = Join-Path $Directory 'app_egress_guard_test.exe'
Copy-Item $binary $selected
Copy-Item $binary $unselected
function Probe([string]$Image, [string]$Expected) {
    & $Image --probe $Expected
    if ($LASTEXITCODE -ne 0) { throw "Probe failed: $Image ($Expected)" }
}
$owner = $null
try {
    Probe $selected allowed
    Probe $unselected allowed
    $owner = Start-Process -FilePath $selected -ArgumentList @('--live-arm-wait', $id) `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    $null = $owner.Handle
    $deadline = (Get-Date).AddSeconds(15)
    do {
        if ((Test-Path $stdout) -and (Get-Content $stdout -Raw) -match 'ARMED') { break }
        if ($owner.HasExited) { throw 'Guard owner failed before arming' }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    if ((Get-Content $stdout -Raw) -notmatch 'ARMED') { throw 'Guard did not arm' }
    Probe $selected blocked
    Probe $unselected allowed
    # A different image must not be able to reuse/release this policy ID.
    & $unselected --live-release $id
    if ($LASTEXITCODE -eq 0) { throw 'Conflicting application released the guard' }
    $owner.Kill()
    $owner.WaitForExit()
    & $selected --live-status $id
    if ($LASTEXITCODE -ne 0) { throw 'Guard disappeared with owner process' }
    Probe $selected blocked
    Probe $unselected allowed
} finally {
    if ($owner -and !$owner.HasExited) { $owner.Kill(); $owner.WaitForExit() }
    & $selected --live-release $id
    if ($LASTEXITCODE -ne 0) {
        throw "Cleanup failed. Keep fixture and release explicitly: $selected --live-release $id"
    }
    if (Test-Path $stdout) { Get-Content $stdout }
    if (Test-Path $stderr) { Get-Content $stderr }
}
Probe $selected allowed
Probe $unselected allowed
Write-Output 'PASS: persistent image guard survived owner kill; IPv4/IPv6 TCP/UDP and explicit release verified'
