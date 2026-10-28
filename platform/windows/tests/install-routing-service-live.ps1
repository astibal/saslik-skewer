param(
    [string]$Directory = 'C:\SkewerDev\skewer-windows-app',
    [string]$WinDivertDirectory = 'C:\SkewerDev\flow-test',
    [string]$WintunDll = 'C:\SkewerDev\wintun-test\wintun.dll'
)
$ErrorActionPreference = 'Stop'
$name = 'SkewerRouting-Test-' + [Guid]::NewGuid().ToString('N')
$root = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) $name
$installer = Join-Path $Directory 'install-routing-service.ps1'
$arguments = @{
    PackageDirectory=$Directory; WinDivertDirectory=$WinDivertDirectory; WintunDll=$WintunDll
    OwnerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    Endpoint='skewer://127.0.0.1:8766/pair'; Peer='127.0.0.1'; Name=$name
}
try {
    & $installer @arguments -WhatIf
    if ((Test-Path -LiteralPath $root) -or (Get-Service $name -ErrorAction SilentlyContinue)) {
        throw 'WhatIf changed installation state'
    }
    & $installer @arguments
    $service = Get-CimInstance Win32_Service | Where-Object Name -eq $name
    if ($service.StartMode -ne 'Manual' -or $service.StartName -ne 'LocalSystem' -or $service.State -ne 'Running') {
        throw 'Unexpected service installation state'
    }
    $control = Join-Path $root 'skewer-routing-control.exe'
    $status = & $control status $name
    if ($LASTEXITCODE -ne 0 -or ($status | ConvertFrom-Json).phase -ne 0) {
        throw 'Fresh installation must be reachable and Idle'
    }
    # Check the inherited file ACL, not just the enclosing directory.
    $users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $acl = Get-Acl -LiteralPath (Join-Path $root 'Qt6Core.dll')
    $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    $userRules = @($rules | Where-Object { $_.IdentityReference -eq $users })
    if ($userRules.Count -ne 1 -or $userRules[0].AccessControlType -ne 'Allow' -or
        [int]$userRules[0].FileSystemRights -ne 0x1200a9) {
        throw 'Users must have read/execute access only'
    }
    $rejected = $false
    try { & $installer @arguments } catch { $rejected = $true }
    if (!$rejected) { throw 'Installer overwrote an existing installation' }
    Write-Output 'PASS: dry-run, protected installation, Idle IPC, overwrite rejection'
} finally {
    if (Get-Service $name -ErrorAction SilentlyContinue) {
        Stop-Service $name
        & sc.exe delete $name
        if ($LASTEXITCODE -ne 0) { throw 'Test service removal failed' }
    }
    # Retain only this test's binaries for inspection; never recursively erase Program Files.
    Write-Output "Test artifacts retained: $root"
}
