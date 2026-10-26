param([string]$Directory = 'C:\SkewerDev\flow-test')

$ErrorActionPreference = 'Stop'
# Explicit elevated VM-only test. Never relax signature or antivirus policy.
$expected = @{
    'WinDivert.dll' = 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'
    'WinDivert64.sys' = '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'
}
foreach ($name in $expected.Keys) {
    $file = Join-Path $Directory $name
    if ((Get-FileHash -Algorithm SHA256 $file).Hash -ne $expected[$name]) {
        throw "Unexpected official WinDivert 2.2.2-A x64 file: $name"
    }
}
$signature = Get-AuthenticodeSignature (Join-Path $Directory 'WinDivert64.sys')
if ($signature.Status -ne 'Valid') {
    throw "WinDivert driver signature is not valid: $($signature.Status)"
}
Write-Output "Driver signature: $($signature.SignerCertificate.Subject)"

$stdout = Join-Path $Directory 'flow-test.stdout.log'
$stderr = Join-Path $Directory 'flow-test.stderr.log'
$dll = Join-Path $Directory 'WinDivert.dll'
$test = Start-Process -FilePath (Join-Path $Directory 'flow_observer_test.exe') `
    -ArgumentList @('--live', ('"' + $dll + '"')) -PassThru -NoNewWindow `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr
# Retain the native process handle before exit; Windows PowerShell otherwise
# may lose ExitCode for a short-lived Start-Process child.
$null = $test.Handle
try {
    if (-not $test.WaitForExit(60000)) {
        $test.Kill()
        $test.WaitForExit()
        throw 'Passive flow test exceeded its deadline'
    }
    Get-Content $stdout
    Get-Content $stderr
    if ($test.ExitCode -ne 0) {
        throw "Passive flow test failed: $($test.ExitCode)"
    }
} finally {
    $test.Dispose()
}
# Closing observer handles removes their filters. Do not stop/delete the shared
# WinDivert driver service: another application might be using it.
