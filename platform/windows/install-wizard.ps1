[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PackageDirectory,
    [Parameter(Mandatory=$true)][string]$Destination
)
$ErrorActionPreference = 'Stop'
$nativeModuleRoot = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\Modules'
$moduleRoots = @($env:PSModulePath -split ';' | Where-Object { $_ })
if ((Test-Path -LiteralPath $nativeModuleRoot -PathType Container) -and
    $nativeModuleRoot -notin $moduleRoots) {
    # A caller such as GitHub's pwsh runner can pass a PowerShell Core-only
    # module path to Windows PowerShell. Restore its native system modules.
    $env:PSModulePath = (@($nativeModuleRoot) + $moduleRoots) -join ';'
}
$logDirectory = Join-Path $env:ProgramData 'Skewer'
$logFile = Join-Path $logDirectory 'setup.log'
$null = New-Item -ItemType Directory -Path $logDirectory -Force

function Write-SetupLog([string]$Message) {
    $line = '{0:o} {1}' -f [DateTime]::UtcNow, $Message
    Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8
}

function Assert-Administrator {
    $principal = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The Skewer setup must run as administrator.'
    }
}

function Split-NativeCommandLine([string]$CommandLine) {
    # SCM paths contain one quoted executable followed by whitespace-delimited
    # Skewer arguments. None of those arguments may contain whitespace.
    $tokens = @([regex]::Matches($CommandLine, '"[^"]*"|\S+') | ForEach-Object {
        $_.Value.Trim('"')
    })
    if (!$tokens.Count) { throw 'The routing service has an empty command line.' }
    return $tokens
}

function Get-InteractiveUserSid {
    $account = (Get-CimInstance Win32_ComputerSystem).UserName
    if (!$account) { throw 'Cannot identify the interactive desktop user.' }
    return ([Security.Principal.NTAccount]::new($account)).Translate(
        [Security.Principal.SecurityIdentifier]).Value
}

function Read-ServiceConfiguration([string]$Name) {
    $service = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
    if (!$service) { return $null }

    $control = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) "$Name\skewer-routing-control.exe"
    if (!(Test-Path -LiteralPath $control -PathType Leaf)) {
        throw 'The installed routing service is incomplete.'
    }
    $status = & $control status $Name | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Cannot query the installed routing service.' }
    if ($status.phase -ne 0) {
        throw 'Disable Skewer routing before updating or uninstalling the application.'
    }

    $tokens = Split-NativeCommandLine $service.PathName
    $marker = [Array]::IndexOf($tokens, '--service')
    if ($marker -lt 0 -or $tokens.Count -lt $marker + 3 -or $tokens[$marker + 1] -ne $Name) {
        throw 'The installed routing service has an unexpected command line.'
    }
    $result = @{
        OwnerSid = $tokens[$marker + 2]
        Endpoint = ''
        Peer = ''
        DnsServer = '1.1.1.1'
        Management = ''
    }
    $remaining = $tokens.Count - ($marker + 3)
    if ($remaining -notin @(0, 3, 4)) {
        throw 'The installed routing service has unsupported arguments.'
    }
    if ($remaining -ge 3) {
        $result.Endpoint = $tokens[$marker + 3]
        $result.Peer = $tokens[$marker + 4]
        $result.DnsServer = $tokens[$marker + 5]
    }
    if ($remaining -eq 4) { $result.Management = $tokens[$marker + 6] }
    return $result
}

Assert-Administrator
Write-SetupLog 'Setup orchestration started.'
$PackageDirectory = (Resolve-Path -LiteralPath $PackageDirectory).Path
$Destination = [IO.Path]::GetFullPath($Destination)
$sourceExe = Join-Path $PackageDirectory 'skewer.exe'
if (!(Test-Path -LiteralPath $sourceExe -PathType Leaf)) {
    throw 'The setup payload does not contain skewer.exe.'
}

$running = Get-Process -Name skewer -ErrorAction SilentlyContinue
if ($running) { throw 'Close Skewer before installing or updating it.' }

$name = 'SkewerRouting'
Write-SetupLog 'Checking the existing routing service.'
$configuration = Read-ServiceConfiguration $name
$owner = if ($configuration) {
    $configuration.OwnerSid
} else {
    Get-InteractiveUserSid
}

$serviceArguments = @{
    PackageDirectory = $PackageDirectory
    OwnerSid = $owner
    Name = $name
}
if ($configuration) {
    $serviceArguments.Upgrade = $true
    if ($configuration.Endpoint) {
        $serviceArguments.Endpoint = $configuration.Endpoint
        $serviceArguments.Peer = $configuration.Peer
        $serviceArguments.DnsServer = $configuration.DnsServer
        if ($configuration.Management) {
            $serviceArguments.Management = $configuration.Management
        }
    }
}

# The service installer is independently transactional and returns to Idle.
# Updating it first prevents a newly installed GUI from speaking an older IPC
# protocol. Pairing secrets remain in the user's DPAPI-protected store.
Write-SetupLog $(if ($configuration) { 'Updating the routing service.' } else { 'Installing the routing service.' })
try {
    & (Join-Path $PackageDirectory 'install-routing-service.ps1') @serviceArguments
} catch {
    $message = $_.Exception.Message
    $category = switch -Regex ($message) {
        'Run this installer elevated' { 'not elevated'; break }
        'OwnerSid must be canonical' { 'invalid owner SID'; break }
        'Inconsistent installation' { 'inconsistent existing installation'; break }
        'Expected a regular installation file' { 'invalid payload file'; break }
        'Unverified driver artifact' { 'driver hash verification'; break }
        'Invalid driver signature' { 'driver signature verification'; break }
        'Service creation failed' { 'service creation'; break }
        'Cannot configure routing service restart actions' { 'service recovery policy'; break }
        'Cannot enable routing service non-crash recovery' { 'service recovery flag'; break }
        'Cannot start service' { 'service startup'; break }
        'service cannot be started' { 'service startup'; break }
        default { 'uncategorized service installation failure' }
    }
    Write-SetupLog "Routing service installation failed: $category"
    $detail = $message -replace "(?i)'[A-Z]:\\[^']*'", '[path]'
    $detail = $detail -replace '(?i)\b[A-Z]:\\\S+', '[path]'
    $detail = $detail -replace '\bS-1-(?:\d+-){1,14}\d+\b', '[sid]'
    $detail = $detail -replace '(?i)(?:skewer|https?)://\S+', '[endpoint]'
    $detail = ($detail -replace '[\r\n]+', ' ').Trim()
    Write-SetupLog "Routing service detail: $($detail.Substring(0, [Math]::Min(300, $detail.Length)))"
    throw
}
Write-SetupLog 'Routing service is installed and Idle.'

$parent = Split-Path -Parent $Destination
$stage = Join-Path $parent ('.skewer-stage-' + [Guid]::NewGuid().ToString('N'))
$backup = Join-Path $parent ('.skewer-backup-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $parent -Force
try {
    Write-SetupLog 'Staging the desktop application.'
    $null = New-Item -ItemType Directory -Path $stage
    Get-ChildItem -LiteralPath $PackageDirectory -Force | ForEach-Object {
        if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Setup payload contains a reparse point: $($_.Name)"
        }
        Copy-Item -LiteralPath $_.FullName -Destination $stage -Recurse
    }
    if (Test-Path -LiteralPath $Destination) {
        Move-Item -LiteralPath $Destination -Destination $backup
    }
    try {
        Move-Item -LiteralPath $stage -Destination $Destination
    } catch {
        if (Test-Path -LiteralPath $backup) {
            Move-Item -LiteralPath $backup -Destination $Destination
        }
        throw
    }
    Remove-Item -LiteralPath $backup -Recurse -Force -ErrorAction SilentlyContinue
    Write-SetupLog 'Desktop application files are installed.'
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
Write-SetupLog 'Setup orchestration completed.'

[pscustomobject]@{
    Version = (Get-Item -LiteralPath (Join-Path $Destination 'skewer.exe')).VersionInfo.ProductVersion
    Directory = $Destination
    RoutingService = if ($configuration) { 'Updated, Idle' } else { 'Installed, Idle' }
    Settings = 'Preserved'
}
