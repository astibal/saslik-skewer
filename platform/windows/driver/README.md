# Build-only ALE guard prototype

This is **not installed, loaded, production-ready, or a verified kill switch**.
The first artifact is an unsigned x64 WDM `.sys`, built with Microsoft MSVC/WDK.
The standard MinGW application build does not compile or package this driver.
It only runs the portable `ale_decision` test for the actual pure decision function.

## Implemented boundary

- Register IPv4/IPv6 ALE authorization callouts, without adding any WFP filters.
- Select one process at DriverEntry using `TargetPid` and `TargetCreationTime`
  REG_QWORD values under the driver's service `Parameters` key. Creation time
  uses the Windows FILETIME value returned by GetProcessTimes. These parameters
  are administrator-controlled prototype inputs, not a user-facing IPC API.
- Reference the kernel process object and validate its creation time. Exit
  notification retires this instance; a post-registration exit-status check
  closes the initialization race. No lookup by process name or delayed flow tuple.
- Reject selected authorization requests, preserve an existing decision when
  action-write rights are absent, and CONTINUE (never PERMIT) other instances.
  Missing PID metadata/wrong layer blocks within the management filter's scope.
- Keep the target in kernel state independently of the controller process. The
  intended controller-crash behavior is **not yet live-tested**.
- No global mutex, user-mode wait, allocation or pageable lookup in classify.

No filter installer exists yet. A later test installer must use narrowly scoped
image/layer conditions; never point an unrestricted terminating filter at this
prototype. An unregistered terminating callout can cause its filters to block
the entire matching image, not just the selected PID. This unload/restart scope
must be tested and resolved before any production persistence claim.

There is deliberately no DriverUnload callback. Dynamic filter/callback removal
needs a separate lifecycle protocol. Initialization attempts rollback; if a
callback cannot be unregistered, the image and referenced state remain resident
instead of returning an error that would unload still-referenced code. That rare
case prints a kernel error and requires reboot. A running service alone therefore
cannot serve as a readiness signal. Use a disposable VM only when load testing
is explicitly approved; the current build script never loads anything.

## Verified build environment

Development VM toolchain:

- Visual Studio 2022 Build Tools, MSVC directory `14.44.35207`.
- Windows SDK headers `10.0.26100.0`.
- Official NuGet `Microsoft.Windows.WDK.x64` version `10.0.26100.6584`, extracted
  at `C:\SkewerDev\driver-tools\wdk` with its license retained.

Run `build.ps1`; parameters allow overriding those installation paths.
The script performs compilation and linking only, producing
`C:\SkewerDev\ale-build\skewer-ale.sys` and its PDB. It uses `/kernel`, `/GS`,
`/W4 /WX`, `GsDriverEntry`, native subsystem, NX/ASLR and integrity checking.
The intentional WDK alignment warning is disabled only around WDK includes.
No driver binaries, downloaded kits or licenses are vendored into this repository.
PE inspection found only `ntoskrnl.exe` and `fwpkclnt.sys` imports, no user CRT.

Build Tools and SDK were installed without reboot. Secure Boot remains enabled;
test-signing was not enabled. The artifact is unsigned and no service or WFP
management filter was created for it.

## Still required before live validation

1. Obtain approval for an isolated snapshot/clone and its explicit signing policy;
   do not weaken the existing VM's boot security implicitly.
2. Add a constrained fixture-only filter installer and independent cleanup plan.
3. Test missing metadata, PID reuse/exit, another instance of the same EXE,
   controller termination, startup rollback, and IPv4/IPv6 first TCP/UDP attempts.
4. Capture physical egress; test existing sockets, DNS, descendants and recovery.
5. Design authenticated selection IPC, dynamic release/unload and subsequent
   packet enforcement before adding any tunnel permit/redirect path.

The portable decision test covers truth-table combinations only; it does not
exercise kernel scheduling, registration, PID lifetime or actual network blocking.

References: [WDK acquisition](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk),
[callout registration/lifetime](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscalloutregister0),
[classification action rights](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_callout_classify_fn0).
