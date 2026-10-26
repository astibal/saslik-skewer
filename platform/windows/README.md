# Windows backend and shared application UI

This directory is part of Skewer, not a separate product or GUI fork. It is a
native backend selected by the root CMake build on Windows. Both platforms
use `src/ui/application_shell.hpp` and `src/ui/application_page.hpp`: the same
window lifecycle, tray/menu, geometry, version, tabs and Applications layout.
Linux retains its existing controllers and application model; Windows supplies
its native scanner and the portable process browser. There is no Windows
routing implementation yet, and unsupported operations are explicitly disabled.
The former separate preview executable has been replaced by `skewer.exe`.

Implemented:

- Current-user process enumeration using token SIDs, not account names.
- PID + creation-time identity; parent links reject newer reused PIDs.
- Executable paths, session IDs and visible top-level window titles.
- Window-bearing processes sort before background processes.
- Process launch without a command shell or handle inheritance.
- Unicode and Windows argument quoting; no administrator elevation requested.
- RAII handle ownership and runtime regression tests.

This is a process inventory, not yet application grouping. A process may vanish
during collection. Access-denied entries are counted, not shown as owned.
Window enumeration is scoped to the caller's desktop: a probe run through SSH
cannot see the interactive desktop's windows. The GUI gathers window
metadata in its own desktop session, not in a system service. The helper should
receive verified process identities, not blindly trust arbitrary PIDs.

## Build from Linux

Install CMake, Ninja and the POSIX-threaded x86-64 MinGW C++ toolchain, or use an
isolated container. No Windows SDK or proprietary compiler is required here.

```sh
cmake -S platform/windows -B /tmp/skewer-windows-build -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$PWD/platform/windows/mingw-toolchain.cmake" \
  -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/skewer-windows-build
```

Run `skewer-process-probe.exe --self-test` on real Windows. Cross compilation
alone does not validate Win32 behavior. `--json` emits a diagnostic inventory;
window titles can be sensitive, so do not publish captures indiscriminately.

## Shared GUI

The programmatic widget in `platform/common` contains no operating-system APIs.
It separates window-bearing processes from background roots, retains process
ancestry, and never merges applications merely because executable names match.
Selection/expansion survive refresh; PID reuse invalidates old selection.
The shared page supplies search and routing action controls on both platforms.
Linux keeps its richer model, CA/connection handling and routing controllers.
Windows shows explanatory pages for CA Trust, Runtime Trust and Connections;
these are capability notices, not implemented backends.

The Windows application polls on a worker thread every three seconds by default, with no
overlapping scans and no polling while minimized. It exposes launch progress,
errors and the returned PID, and learns name/path completions from the inventory.
Visible application names take precedence over renderer/helper labels. Distinct
executable paths remain separate even when their names match. Up to 256 entries
are retained in memory for the current session, including exited applications;
this history is not written to disk. Selecting a completion inserts its actual
executable path, never its display label. The initial launcher accepts an
executable path only, not arguments.
It never edits browser profiles or requests elevation. Successful process
creation does not prove that a singleton application opened a new instance.
Closing the window does not terminate applications it launched. The shared
close-to-tray setting and explicit Quit behave like Linux. Reopening activates
the existing per-user window. Windows Preferences exposes only implemented
options: process refresh interval and tree font size.

To cross-build the application, install Qt target libraries and matching Linux
host tools (including ICU) and build from the repository root:

```sh
aqt install-qt windows desktop 6.8.3 win64_mingw -O /tmp/qt-target --archives qtbase qtsvg
aqt install-qt linux desktop 6.8.3 linux_gcc_64 -O /tmp/qt-host --archives qtbase icu
export LD_LIBRARY_PATH=/tmp/qt-host/6.8.3/gcc_64/lib
cmake -S . -B /tmp/skewer-windows-app-build -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$PWD/platform/windows/mingw-toolchain.cmake" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=/tmp/qt-target/6.8.3/mingw_64 \
  -DQT_HOST_PATH=/tmp/qt-host/6.8.3/gcc_64
cmake --build /tmp/skewer-windows-app-build
```

The result is `platform/windows/skewer.exe` in the build directory, using the
root project's version. Native Linux `rcc` compiles the shared SVG resource;
no layout editor is used. `cross.Dockerfile` supplies the isolated compiler and
host runtime dependencies. The tested build uses Debian 12 POSIX MinGW GCC 12,
Qt 6.8.3 and Qt's MinGW 13.1 runtime DLLs.

For the private test directory, deploy the executable alongside `Qt6Core.dll`,
`Qt6Gui.dll`, `Qt6Widgets.dll`, `Qt6Concurrent.dll`, `Qt6Network.dll`, `Qt6Svg.dll`, matching `libstdc++-6.dll`,
`libgcc_s_seh-1.dll`, `libwinpthread-1.dll`, and the cross-compiler's
`libssp-0.dll`. Include `platforms/qwindows.dll` and
`styles/qmodernwindowsstyle.dll`, `iconengines/qsvgicon.dll` and
`imageformats/qsvg.dll` from Qt. This is a development deployment,
not a signed installer or a complete redistribution/license bundle.

## Tests

The portable model suite runs without Linux services:

```sh
cmake -S platform/common -B /tmp/skewer-portable-ui
cmake --build /tmp/skewer-portable-ui
ctest --test-dir /tmp/skewer-portable-ui --output-on-failure
```

The Windows build also produces tests under `platform/windows/portable-ui`.
Run it on Windows with `QT_QPA_PLATFORM=offscreen`, `Qt6Test.dll` and
`platforms/qoffscreen.dll`. It checks the Qt model contract, distinct instances,
parent cycles, reused PIDs, refresh state, search and launcher suggestions.
`application_shell_test.exe` covers shared tabs, disabled action defaults,
version, preferences hook, resizing and geometry persistence.
`launch_catalog_test.exe` covers name/path matching, keyboard selection, distinct
installations, stable refresh and bounded session-only history.

`tests/application_smoke.ps1` must run in an interactive desktop session with
Skewer already open. It launches Notepad, checks error/success feedback,
single-instance activation, close and reopen, and verifies Notepad remains running. Use only a disposable
development VM; it intentionally leaves the test application running.
Results are written to the user's `skewer-application-smoke.log`.

Native validation on 2026-10-26: MinGW cross-build succeeded; Windows 11
Enterprise Evaluation on RHINO passed the self-test in an unelevated desktop
session, including visible/hidden window association. SSH passed the remaining
tests and explicitly skipped desktop tests. JSON parsing with PowerShell passed.
`windowEnumerationAvailable` distinguishes a noninteractive window station
from an interactive desktop with no matching windows. This is not yet coverage
of multi-user isolation, application grouping or networking.

The portable Qt model and shared-shell suites passed on both Linux and Windows.
Linux's existing application-model and Saslik-status integration tests also
passed after adopting the shared shell and page. The desktop
launcher/close smoke test passed on Windows; the application rendered with the
native Qt Windows style. No routing or full functional parity is claimed.

## Next milestones

### Wintun OS boundary (experimental, not connected to routing)

`wintun_device` provides RAII adapter/session ownership, nonblocking packet I/O,
backpressure and cancellable waits. It uses the official Wintun SDK dynamically;
the library remains loaded until its last device is destroyed. Reads release
their ring slots even when the caller's buffer is too small. The Wintun read
event is borrowed and is never closed by Skewer. Stop and join all I/O workers
before destroying a device.

This library does **not** yet port the Tuntom transport, install a kill switch,
assign IP addresses, configure DNS or change routes. It is deliberately not
linked into the GUI. No production Windows routing is enabled by this step.

Obtain the official Wintun 0.14.1 SDK from
[wintun.net](https://www.wintun.net/). The archive SHA-256 is
`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`.
Keep the SDK's license with the DLL; this repository does not redistribute it.
Add these options to the Windows cross-build configuration (paths must be
visible inside the build environment):

```sh
-DSKEWER_WINDOWS_TUN=ON -DWINTUN_INCLUDE_DIR=/path/to/wintun/include
```

`wintun_device_test.exe` runs deterministic tests with an injected API and no
driver or elevation. The explicit live probe requires administrator rights and
creates a uniquely named test adapter, then closes it:

```powershell
.\wintun_device_test.exe --live C:\TrustedInstall\wintun.dll
```

Run the live probe only in the development VM. Verify the DLL's Authenticode
signature first; the loader restricts search paths but does not authenticate the
binary itself. A future privileged service must use an administrator-controlled
installation path, never a DLL path supplied by an untrusted GUI request. Closing
the probe removes its adapter but does not uninstall the shared Wintun driver.

### UDP transport foundation

`skewer-windows-udp` provides nonblocking Winsock datagrams for numeric IPv4
and IPv6 endpoints. It owns Winsock/socket/event lifetime, prevents inherited
socket handles and duplicate local binds, preserves source addresses, and treats
truncation as an error. Empty datagrams are distinct from an empty receive queue.
There is no implicit DNS lookup, peer migration, authentication or route setup.

The wait operation combines cancellation, network events and an optional borrowed
packet-device event. Stop wins over simultaneous readiness. Network readiness is
advisory (including write readiness); callers must handle would-block and use
bounded receive batches so other work is not starved. Socket events are reset
atomically using Winsock's event enumeration, not `ResetEvent`. One I/O worker
owns the endpoint; stop and join it before destruction. A future Wintun supervisor
must keep any borrowed packet-device event alive throughout each wait.

`udp_endpoint_test.exe` needs neither elevation nor a driver. It uses IPv4 and
IPv6 loopback to test packet/reply integrity, empty/truncated/oversized datagrams,
readiness, cancellation priority, duplicate binds and handle cleanup. It does
not alter addresses or routes. Scoped IPv6 address parsing, PMTU policy, socket
buffer tuning and the actual Tuntom protocol integration remain separate work.

### Remaining integration

1. Port additional controllers behind explicit platform capability interfaces;
   do not expose Linux-specific helpers or settings as working Windows features.
2. Add desktop application identity/icons, launcher completion, and explicit
   launch feedback (new process vs singleton handoff).
3. Implement and test a separate Windows traffic-policy backend. Until then,
   attach/routing controls must be unavailable, never report simulated success.
4. Add a Windows CI runner and versioned ZIP/installer release artifacts.

The Linux executable uses the shared shell/page with its existing controllers.
Existing Linux release packaging is unchanged; Windows packaging is not ready.
