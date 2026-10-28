# Windows routing service installation

This is a development installer, not yet a signed release package or updater.
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

The installer validates the pinned WinDivert 2.2.2-A artifacts and driver
signatures before and after copying. It installs only the required service
runtime under `Program Files\SkewerRouting`, with Users read/execute access and
SYSTEM/Administrators write access. An existing directory or service is rejected;
in-place upgrades and automatic replacement are deliberately not implemented.

The LocalSystem service uses Manual startup. Installation starts its IPC server
in **Idle**, not routing. In the GUI Routing tab, send the stored pairing and
explicitly start routing. Closing the GUI does not stop the service or routing.
Credentials are handed over through authenticated IPC and remain memory-only in
the service. A service restart requires sending pairing again.

Use `-WhatIf` to validate without installation. The elevated regression script
`tests/install-routing-service-live.ps1` checks dry-run behavior, ACLs, Idle IPC
and overwrite rejection. It removes its uniquely named service but retains that
test's installation directory for inspection.

Current routing is whole-host IPv4. Selected-application routing is not enabled
by this installer. A tunnel failure keeps the live guard blocking until explicit
Stop; a WinDivert owner/driver failure cannot provide that guarantee. This is a
lab tool, not a security boundary against an administrator or driver failure.
