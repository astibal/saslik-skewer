# Windows routing service installation

## Desktop application

Extract the release ZIP and run the per-user installer without elevation:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install-skewer.ps1
```

It installs under `%LOCALAPPDATA%\Programs\Skewer`, creates a Start Menu
shortcut and registers a per-user uninstall entry. Add `-DesktopShortcut` if
wanted. Updates are transactional and require the installed GUI to be closed.
Uninstall preserves pairing, preferences, CA decisions and the separately
privileged routing service.

## Routing service

This is a development installer, not yet a signed release package.
Use a trusted build directory: driver verification does not authenticate the
application binaries or their Qt runtime.

Run `install-routing-service.ps1` from elevated PowerShell. Keep the GUI running
as the ordinary user. Supply that user's canonical SID as `OwnerSid`, especially
when elevation uses a different administrator account.

```powershell
# Read this in the ordinary user's session, before elevation:
[Security.Principal.WindowsIdentity]::GetCurrent().User.Value

# Run elevated, using the SID obtained above:
.\install-routing-service.ps1 `
    -PackageDirectory C:\SkewerPackage `
    -WinDivertDirectory C:\WinDivert\x64 `
    -WintunDll C:\Wintun\bin\amd64\wintun.dll `
    -OwnerSid S-1-5-21-REPLACE-WITH-USER-SID `
    -Endpoint skewer://192.0.2.10:8766/pair `
    -Peer 192.0.2.10
```

`Endpoint` is the public paired endpoint, never the invitation containing a key.
`Peer` is its numeric IPv4 address. `DnsServer` defaults to `1.1.1.1` and is set
only on the tunnel adapter when routing starts. The optional `Management`
address permits SSH return traffic to a test host while whole-host routing is
active; omit it for normal use.

When all three dependency files are beside the script, `WinDivertDirectory` and
`WintunDll` may be omitted. The installer validates the pinned WinDivert 2.2.2-A artifacts and driver
signatures before and after copying. It installs only the required service
runtime under `Program Files\SkewerRouting`, with Users read/execute access and
SYSTEM/Administrators write access. An existing directory or service is rejected
unless `-Upgrade` is explicit. Upgrade stops routing, backs up the exact runtime,
updates and revalidates it, updates the SCM command line and starts in Idle. A
failed update restores both runtime files and the previous command line.

For a packaged CMake install, configure both `WINTUN_RUNTIME_DLL` and
`WINDIVERT_RUNTIME_DIR`. CMake then installs the service, control client,
installer and the three signed driver runtime files beside the desktop client;
the Routing tab enables its standard UAC install/upgrade action only when that
complete set is present.

`packaging/package-windows.sh` creates the equivalent portable release ZIP
from an already verified cross-build. It stages an allowlisted file set rather
than archiving a development directory, so test logs, pairing state and local
credentials cannot enter the artifact accidentally.

The LocalSystem service starts automatically with Windows in **Idle**, never
routing. This keeps authenticated IPC available after reboot without silently
changing network policy. In the GUI Routing tab, send the stored pairing and
explicitly start routing. Closing the GUI does not stop the service or routing.
Credentials are handed over through authenticated IPC and remain memory-only in
the service. A service restart requires sending pairing again.

The installer configures bounded SCM recovery: restart after 5, 15 and 60
seconds, resetting the failure count after 24 hours. Service-specific failures
also trigger this policy. A restarted service always returns to Idle and never
silently resumes routing. WinDivert filters disappear with their owner, so this
improves availability but cannot eliminate the documented direct-connectivity
window after a service crash.

The Routing tab can explicitly remove an idle service through UAC. Removal
stops the service and deletes only `%ProgramFiles%\SkewerRouting`; pairing and
desktop preferences remain intact. Active routing must be stopped first.

Use `-WhatIf` to validate without installation. The elevated regression script
`tests/install-routing-service-live.ps1` checks dry-run behavior, ACLs, Idle IPC,
overwrite rejection, upgrade and complete removal of its unique test service.

Current routing supports whole-host IPv4 or one explicitly selected process's
fresh corroborated IPv4 TCP and UDP traffic. Ambiguous ownership remains blocked.
A tunnel failure keeps the live guard blocking until explicit
Stop; a WinDivert owner/driver failure cannot provide that guarantee. This is a
lab tool, not a security boundary against an administrator or driver failure.

Headless application routing uses the same authenticated service as the GUI:

```powershell
.\skewer-routing-control.exe status SkewerRouting
.\skewer-routing-control.exe run SkewerRouting C:\Path\Application.exe --argument
.\skewer-routing-control.exe attach SkewerRouting GENERATION PID BIRTH
.\skewer-routing-control.exe release SkewerRouting GENERATION
```

Use the opaque generation returned by `status` or `run`. `run` is authoritative
because the child remains suspended until routing is Active. `attach` installs
guards before resetting the adopted tree's existing IPv4 TCP connections;
existing UDP and IPv6 sockets cannot be retroactively rerouted.
