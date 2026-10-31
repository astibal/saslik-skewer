param([Parameter(Mandatory = $true)][string]$Directory)
$ErrorActionPreference = 'Stop'

# Forward localhost:18767 to pairing-peer.py before invoking this fixture.
# Public fixture credentials must never be used with a real Saslik endpoint.
$storage = Join-Path $Directory 'pairing_storage_test.exe'
$control = Join-Path $Directory 'tuntom_control_test.exe'
& $storage
if ($LASTEXITCODE -ne 0) { throw 'DPAPI storage test failed' }

$endpoint = 'skewer://127.0.0.1:18767/pair'
$wrong = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(('w' * 32))).TrimEnd('=')
"${endpoint}#v=1&id=fixture-invitation&psk=$wrong" | & $control $endpoint
if ($LASTEXITCODE -ne 3) { throw 'Invalid PSK was not rejected during enrollment' }

$key = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(('p' * 32))).TrimEnd('=')
"${endpoint}#v=1&id=fixture-invitation&psk=$key" | & $control $endpoint
if ($LASTEXITCODE -ne 0) { throw 'TLS-PSK control lifecycle failed' }
Write-Output 'PASS: DPAPI, invalid PSK, enrollment and tunnel control lifecycle'
