param(
    [string]$BuildTools = 'C:\SkewerDev\BuildTools',
    [string]$Wdk = 'C:\SkewerDev\driver-tools\wdk\c',
    [string]$Sdk = "${env:ProgramFiles(x86)}\Windows Kits\10",
    [string]$KitVersion = '10.0.26100.0',
    [string]$Output = 'C:\SkewerDev\ale-build'
)
$ErrorActionPreference = 'Stop'
# Compile/link only. No service creation, filter installation, signing or reboot.
$msvc = Get-ChildItem (Join-Path $BuildTools 'VC\Tools\MSVC') -Directory |
    Sort-Object Name -Descending | Select-Object -First 1
if (-not $msvc) { throw 'MSVC build tools are missing' }
$compiler = Join-Path $msvc.FullName 'bin\Hostx64\x64\cl.exe'
$linker = Join-Path $msvc.FullName 'bin\Hostx64\x64\link.exe'
$includes = @(
    (Join-Path $msvc.FullName 'include'),
    (Join-Path $Wdk "Include\$KitVersion\km"),
    (Join-Path $Sdk "Include\$KitVersion\shared"),
    (Join-Path $Sdk "Include\$KitVersion\ucrt")
)
$libraries = Join-Path $Wdk "Lib\$KitVersion\km\x64"
foreach ($path in @($compiler, $linker, $libraries) + $includes) {
    if (-not (Test-Path $path)) { throw "Missing build prerequisite: $path" }
}
New-Item -ItemType Directory -Force $Output | Out-Null
$object = Join-Path $Output 'ale_guard.obj'
$image = Join-Path $Output 'skewer-ale.sys'
$arguments = @('/nologo', '/c', '/kernel', '/GS', '/Zl', '/GR-', '/EHs-c-', '/W4', '/WX',
    '/std:c++17', '/Z7', '/D_AMD64_', '/DAMD64', '/D_WIN64', '/D_WIN32_WINNT=0x0A00',
    '/DNTDDI_VERSION=0x0A000000', '/DNDIS630=1', "/Fo$object")
foreach ($include in $includes) { $arguments += "/I$include" }
$arguments += Join-Path $PSScriptRoot 'ale_guard.cpp'
& $compiler @arguments
if ($LASTEXITCODE -ne 0) { throw "Driver compile failed: $LASTEXITCODE" }
& $linker /nologo /driver /subsystem:native /entry:GsDriverEntry /nodefaultlib `
    /integritycheck /dynamicbase /nxcompat /machine:x64 /opt:ref /opt:icf /debug `
    "/pdb:$(Join-Path $Output 'skewer-ale.pdb')" "/out:$image" "/libpath:$libraries" `
    $object ntoskrnl.lib fwpkclnt.lib BufferOverflowK.lib
if ($LASTEXITCODE -ne 0) { throw "Driver link failed: $LASTEXITCODE" }
Get-FileHash $image -Algorithm SHA256
Write-Output 'BUILD ONLY: unsigned driver. Nothing was installed or loaded.'
