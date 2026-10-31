Skewer for Debian 12/13, Ubuntu / Kubuntu 24.04/26.04 LTS and Windows 11
(amd64).

### 0.9.50.10

- Adds configurable IPv4 destination exemptions to Windows Selected Apps,
  Whole Host and Direct routing.
- Persists exemptions in the Windows GUI, exposes them through the CLI and
  keeps the active set visible in authoritative routing-service status.
- Preserves fail-closed routing for non-exempt traffic while exempt
  destinations continue directly outside the lab path.

### 0.9.50.9

- Fixes the Windows wizard installation of the privileged routing service.
- Makes upgrade and uninstall cleanup reliable across supported PowerShell and
  Windows registry environments.

### 0.9.50.8

- Adds the native Windows 11 client with selected-application and whole-host
  IPv4 routing through paired Tuntom, plus explicit whole-host Direct mode.
- Adds the independent authenticated routing service, WinDivert interception,
  Wintun transport, process browser, pairing, CA trust and managed runtime trust.
- Adds a conventional UAC wizard with Start Menu integration, optional desktop
  shortcut, in-place upgrade, state-preserving uninstall and Idle-by-default
  service installation.
- Integrates the Windows package with the Linux diagnostics, support export and
  Tuntom discovery changes introduced in 0.9.50.7.
- Selected IPv6, ambiguous/shared UDP ownership and orphaned process handoffs
  remain explicit lab-tool limitations; no custom kernel driver is installed.

### 0.9.50.7

- Linux Whole Host routing for local IPv4 traffic through a direct next hop or
  Tuntom, with persistent fail-closed protection, explicit host release and
  blocking of unsupported IPv6. Selected Apps remains available separately.
- Preferences > Troubleshoot provides Download logs and Download full support
  package. Local ZIP exports include rotated logs and, optionally, version,
  configuration, routing and DNS diagnostics. Nothing is uploaded automatically.
- Diagnostic logs use bounded rotation and redact sensitive values. Pairing
  files, private keys and credential-bearing helper protocol frames are excluded
  from support collection.
- Tunnel connection phases and actionable errors are shown in GUI and TUI.
  Invalid local transport configuration and missing pairing stop retries until
  corrected; transient failures retain automatic recovery.
- Expanded tests cover support archive integrity and redaction, transport
  preflight and DNS packet routing across host-guard loss and recovery.
- Updated build dependency documentation and roadmap. DNS monitoring and IPv6
  forwarding are not part of this release.

### 0.9.50.6

- Windows now provides a conventional UAC wizard installer with Start Menu and
  optional desktop shortcuts, an Idle routing service, in-place upgrade and a
  standard Windows uninstall entry. Pairing and preferences are preserved by
  default and can be removed through an explicit uninstall component.
- Installer regression coverage verifies install, GUI startup, Idle service,
  upgrade, registration, shortcuts, state preservation and clean uninstall.
- Windows 11 now ships the native Qt application, per-user pairing and CA trust,
  managed runtime trust, process browser, selected-process routing and explicit
  whole-host routing through either Tuntom or a directly reachable Saslik.
- The privileged Windows routing service is independent of the GUI, starts in
  Idle, retains fail-closed routing during tunnel loss, and uses bounded SCM
  crash recovery without automatically reactivating routing.
- Windows release verification covers the signed Wintun/WinDivert dependencies,
  42 native tests, route ownership, package install/uninstall, GUI startup and a
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

Windows releases provide `SkewerSetup-VERSION.exe` as the normal installer and
a versioned ZIP for verification, development and recovery. Verify the adjacent
`.sha256` file before use. The wizard installs the application and privileged
routing service together; it leaves the service Idle until routing is explicitly
enabled.
