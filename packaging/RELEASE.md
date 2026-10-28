Skewer for Debian 12/13, Ubuntu / Kubuntu 24.04/26.04 LTS and Windows 11
(amd64).

### 0.9.50.6

- Windows 11 now ships the native Qt application, per-user pairing and CA trust,
  managed runtime trust, process browser, selected-process routing and explicit
  whole-host routing through either Tuntom or a directly reachable Saslik.
- The privileged Windows routing service is independent of the GUI, starts in
  Idle, retains fail-closed routing during tunnel loss, and uses bounded SCM
  crash recovery without automatically reactivating routing.
- Windows release verification covers the signed Wintun/WinDivert dependencies,
  41 native tests, route ownership, package install/uninstall, GUI startup and a
  real service crash/restart/upgrade/removal lifecycle.
- Shell status recognizes active Tuntom routes instead of comparing their
  gateway with Saslik's direct gateway. Missing routes and inactive tunnel
  interfaces still fail the status check.
- The Saslik information panel follows the selected connection, ignoring empty
  or stale legacy status URLs. Its endpoint is read-only while following a lab.
- Regression coverage for tunnel route detection and status endpoint selection.
- Disconnect process callbacks during window teardown to avoid accessing
  widgets being destroyed while discovery is still running.

### 0.9.50.5

- Tuntom integration uses a shared authorized helper session, with transport
  recovery, configurable binary selection and compact traffic counters.
- Expanded TUI controls for pairing, tunnels, CA/Runtime Trust, connections and
  shared settings. Startup and Enable authorize independently of routing state.
- Clearer terminal diagnostics distinguish an unavailable lab, helper failures
  and inactive routing; retry countdowns replace blinking status warnings.
- The GUI status bar now displays the application version.
- Saslik Portal connections now require HTTPS and use explicit SHA-256
  certificate pinning without modifying the system trust store.
- Changed portal certificates require a fresh, visible confirmation.
- Persisted VM/interface routing is restored when Saslik recreates its lab
  uplink, alongside the existing process-routing recovery.

### 0.9.50.1

- Dedicated CA Trust tab with exact-certificate installation/removal, Snap
  revision filters, sortable compact rows and application trust indicators.
- Background CA discovery and trust reporting to Saslik.
- Close-to-tray preference (enabled by default), dark-mode monochrome icon
  and live routing status in the tray tooltip. Use Quit to exit the UI.
- Package smoke tests also verify the isolated NSS helper.

Download `skewer-linux-amd64.deb`, then install it with:

```sh
sudo apt install ./skewer-linux-amd64.deb
skewer
```

For a terminal interface, use `skewer --tui`. A systemd user session and cgroup
v2 are required. Desktop routing authorization requires a running polkit agent.
The package installs the routing helper, polkit action, icon and `skewer://`
desktop handler. Qt and networking dependencies are installed by apt.

The launcher and process list select applications for IPv4 policy routing to a
directly reachable next hop. Existing sockets retain their previous cgroup;
applications that delegate startup to another process may escape selection.
Closing Skewer leaves applications attached. Direct routing remains in place;
exiting the frontend stops its owned tunnel without falling back to direct
routing. Use Disable and Release
explicitly to undo them. IPv6 is not routed by this version.

Verify the download with `sha256sum -c SHA256SUMS`.

Windows releases provide a versioned ZIP and `skewer-windows-amd64.zip` for the
stable `releases/latest/download/` link. Verify the adjacent `.sha256`, expand
the archive and run `verify-windows-package.ps1` before installation. The
per-user application and privileged routing service are installed separately.
