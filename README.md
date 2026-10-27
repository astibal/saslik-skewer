# Saslik Skewer

Skewer discovers desktop applications and user process trees and places selected
applications into a stable cgroup that can be routed through a Saslik lab.

## Current capabilities

### Guarded shell and launcher

`skewer shell` opens your normal interactive shell inside the routed cgroup;
`skewer run -- PROGRAM ARGS...` runs a single command the same way. The GUI's
Shell button and TUI's `!` key use that session layer too. `exit` returns from
the shell without disabling routing or terminating its background applications.
Routing must already be configured; cgroup membership alone is not connectivity.

Every newly observed descendant receives a five-second correction window with
a 10 ms target polling interval. The guard checks UID and process start time,
then asks the user systemd manager to return escaped processes to the session
scope. Slow systemd calls or a busy scheduler can extend the polling interval.
It reads the known process subtree, not the whole machine. Short-lived parents,
daemonization before discovery and handoffs to existing applications can evade
detection. Already-open sockets are not repaired. This is not a security boundary.

New sessions inherit your working directory and environment. Preparing a bundle
in Trusted Environments selects it for subsequent shell/run and GUI/TUI launches;
CA variables are set only in those sessions. Missing selected bundle files cause
launch to fail, rather than silently launch with different trust. A normal Python
venv can be activated inside the shell. `SKEWER_SESSION=1` identifies the session;
shell rc files may override environment settings. Guard messages also go to
`~/.local/share/skewer/session.log` (or the corresponding XDG data directory).

The Bash prompt shows a cached status symbol: green `──∈` means the configured
policy route matches the gateway and Saslik's API reports an available lab;
red `─×∈` means a detected routing/API/lab failure; yellow `┄┄∈` means unknown,
stale, or routing-only mode without API health verification. This is not an
end-to-end traffic test. A separate background worker checks approximately every
two seconds. The prompt uses only a local cache, expires results after six seconds,
and updates when the next prompt is drawn, without disturbing typed commands.

### Application management

- groups processes by their systemd application scope;
- reconstructs the process tree inside every application;
- resolves names, icons and launch commands from freedesktop desktop entries;
- learns launcher suggestions from running and installed applications;
- moves existing applications into `skewer-routed.slice` using the user systemd
  manager, without running the GUI as root;
- launches new applications directly in that slice;
- provides both a Qt 6 desktop interface and an ncurses headless interface;
- rejects processes that do not belong to the current user;
- can mark traffic from `skewer-routed.slice` and policy-route it through a
  directly reachable IPv4 next hop without changing unrelated host traffic.
- downloads the active workspace CA and manages supported local NSS and system
  trust stores, including removal.
- inventories the effective CA sources of fresh Python, Node.js and Java
  processes and checks the selected workspace CA without modifying runtimes.

Moving applications and configuring networking are deliberately separate.
`Attached` means that an application is in the Skewer cgroup. `Routing active`
means that nftables marking and the dedicated policy-routing table are also
installed. No remote transport is provided yet.

**Destination exemptions…** accepts up to 256 IPv4 addresses or CIDR ranges.
They bypass Skewer marking for every attached application and follow the host's
ordinary routing (which may itself include a VPN). The list is saved and used
by GUI and TUI routing starts. Live changes replace the nftables set atomically;
existing connections may break and need reconnecting. No DNS expansion or IPv6
exceptions are provided. After upgrading an already active older ruleset,
disable and enable routing once to create the exemption set.

## CA Trust

The separate **CA Trust** tab fetches a public CA from Saslik or opens a saved
PEM file for offline cleanup. Verify the displayed SHA-256 fingerprint out of
band before granting trust, especially when downloading over plain HTTP.
Discovery never installs a certificate. Installation targets one selected NSS
profile or the shared system store and requires explicit confirmation.
Shared NSS/system stores can affect corporate clients such as Teams; application
discovery is only a heuristic inventory, not a claim that each application has
its own supported store. Certificate pinning is not bypassed.

**Scan and remove this CA from all…** rescans first and previews matching
nicknames and local system anchor paths. Removal rechecks the exact certificate
fingerprint, never just its name. System changes use Polkit. Each target reports
success or failure; inaccessible NSS records remain unverified.
The isolated NSS helper selects the exact DER certificate, including when
multiple certificates share the same subject or nickname.
Close affected applications before changing their databases and restart them
afterward; existing TLS sessions cannot be revoked by deleting a trust anchor.

Scanning is bounded to the current user's Mozilla, Thunderbird, LibreWolf,
Snap, Flatpak, `.config` and shared NSS directories, without following symlinks
or entering caches. System removal covers root-owned local `.crt` anchors under
`/usr/local/share/ca-certificates`, not distribution-managed roots, other users,
Java stores or arbitrary application-specific certificate formats. Save the CA
before switching labs if you will need to remove it later.

Snap stores show the application name/icon, revision and `current`,
`retained (not current)` or `common (shared)` classification. Classification is
read again on each scan from the validated `current` symlink; revision numbers
are not interpreted as chronological order. Missing or invalid links are shown
as `current unknown`. A current revision is not proof that no older process is
running. Symlink aliases are not scanned twice, and mutations always target the
explicit real database path shown in the confirmation.

The **Runtime Trust** tab is intentionally read-only. It reports Python's
OpenSSL/certifi paths, Node's bundled roots and `NODE_EXTRA_CA_CERTS`, and the
default Java `cacerts` selected by the installed JVM. These probes describe a
fresh process launched in Skewer's environment; individual applications,
virtual environments and build tools may override every one of those sources.
For Python, requests, pip, curl and Node, Skewer can prepare user-owned managed
PEM files and copy an explicit shell environment. It never edits `certifi` or
language package directories, so a package update cannot silently erase the
CA. Java remains inspection-only until a particular JDK truststore is selected.

The next networking milestone is intentionally smaller: route traffic from the
Skewer cgroup toward a configurable, directly reachable next-hop IP. A dynamic
authenticated tuntom client is a later transport option, planned for the Saslik
VM/appliance phase; see [TODO.md](TODO.md).

Existing sockets retain the routing context in which they were created. For a
reliable test, launch the application through Skewer instead of attaching an
already-running process tree.

## Install a release

Debian 12/13 and Ubuntu / Kubuntu 24.04/26.04 LTS, amd64
(for upcoming releases; the original 0.9.50 asset targets Ubuntu 26.04 only):

```sh
curl -fLO https://github.com/astibal/saslik-skewer/releases/latest/download/skewer-linux-amd64.deb
sudo apt install ./skewer-linux-amd64.deb
```

Release tags use the shared ecosystem version without a prefix, e.g. `0.9.50`.
An optional fourth number denotes a stable hotfix, e.g. `0.9.50.1` and
`0.9.50.2`. Set the complete version in CMake before tagging: the tag,
application and DEB version must match exactly. Hotfixes are ordinary stable
releases eligible for `latest`. Prefixes and suffixes are rejected.
The GitHub release workflow builds one DEB on Debian 12 with Qt 6.4, then
installs the exact same artifact in every distribution listed in its `install`
matrix: Debian 12/13 and Ubuntu 24.04/26.04. Every entry must pass dependency
resolution, installed-file checks, dynamic library resolution and an offscreen
GUI startup before publication. No forced dependencies or per-distribution
rebuilds are used. The matrix runs on main, pull requests and release tags.
Only tags publish releases. Published assets are not retroactively replaced.

Container checks do not cover a real desktop polkit prompt, user systemd session
or privileged packet forwarding. The real cgroup movement test requires a local
user systemd session and is run separately before tagging.

## Build from source

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

Run the native desktop interface:

```sh
./build/skewer
```

Run the terminal interface, for example inside `screen` or `tmux`:

```sh
./build/skewer --tui
```

Without a graphical session, Skewer selects the TUI automatically. `--gui`
forces the desktop interface.

The TUI is a supported frontend, not a reduced-privilege or reduced-safety mode.
It shares settings, pairing credentials, CA-store operations, runtime trust
services, socket discovery and the tunnel controller/helper protocol with GUI.
Terminal authorization uses sudo; desktop authorization uses polkit.

| Key | Terminal action |
| --- | --- |
| E / X | Enable or disable routing |
| S / P / Z | Select paired Saslik / pair using a hidden invitation / disconnect |
| T / I | Auto, Direct or Enforced tunnel / capability and diagnostics |
| C / U | CA Trust (retained CAs, download, import, export, install/remove) / Runtime Trust |
| V | User connections or selected application's connections; optional TCP cleanup |
| O | Shared settings, Tuntom path and destination exemptions |
| A / D | Attach / release selected application or interface |
| N / ! | Launch a command / open a routed shell |

Menus and command editing continue servicing tunnel IPC. Quitting stops the
owned tunnel without silently switching traffic to a direct route. Previously
opened sockets and existing runtime-trust exports retain their original state.
Privileged end-to-end terminal workflows require a separate isolated lab check;
unit tests do not substitute for that check.

## Routing

### Experimental tuntom transport

**Settings → Preferences** groups window behavior, startup routing resume,
TCP cleanup-on-attach, tree font size and UI refresh intervals. Changes apply
immediately; tunnel executable changes apply only to the next tunnel start.
Security deadlines, transport probes and helper recovery intervals are not UI
tuning parameters. Cancel leaves stored settings unchanged.

The **Tunnel** preferences page selects the local Tuntom executable (default
`/usr/libexec/saslik/tuntom`). It must be named `tuntom`, root-owned and executable;
neither the file nor its canonical parent directories may be group/world-writable.
The privileged worker repeats validation before execution. A missing absolute
path may be saved ahead of installation; Preferences explains why it
cannot yet run. A source-tree build in a user-writable directory is not accepted
for privileged execution in production builds.

Only an explicitly configured **Debug** build permits a development exception:
acknowledge “I understand security risks” for the selected path in Preferences.
The chosen executable may then run directly from the build tree after normal
administrative authorization. Editing the path clears the acknowledgment;
changing the saved path also invalidates it. The executable must still be an
existing regular executable file. This deliberately trusts code that can change
between launches. Release, RelWithDebInfo, MinSizeRel and unspecified builds
cannot enable the exception, even via edited settings or a forged helper request.
The privileged worker enforces its own build policy independently of the GUI.

The GUI's **Routing** group offers **Auto / Direct / Enforced tunnel** when using a
paired Saslik URL. Auto selects a directly reachable gateway at activation,
otherwise it starts Tuntom. Direct opts out of tunneling; Enforced tunnel forces
it even when Saslik is directly connected. Neither a failure nor loss of the
tunnel silently enables a direct fallback in this mode.

Disable routing before changing modes. A selected tunnel never silently falls
back to Direct. Failed tunnel controllers are retried after 5, 10, 20 and then
30 seconds, including failures before transport startup. Verification resets
that backoff. Click the countdown to retry immediately (Enter/Space also work).
Disable, disconnect or exit cancels pending recovery. Authorization is acquired
before the first remote request; if it is lost, automatic retries cannot open a
password prompt. Clicking retry or Restore routing can authorize a new session.
The control client runs in a transient user service under
`app.slice`, outside the routed slice even when Skewer itself was launched from
a routed shell. Blocking application traffic therefore cannot block its own
control-plane recovery. The Saslik panel shows compact tunnel status and TX/RX
counters, with capability, license and failure details in its tooltip.

The privileged tunnel worker opens application routing only after transport
confirmation and a successful data-path probe. Lost verification closes the
guard; restored verification can repair the route. A separate route watchdog
cannot reopen unverified tunnel routing. Marked tunnel traffic is SNATed to the
client TUN address so replies have a return path. Explicit Disable also fences
out stale workers. Detection uses periodic probes, not instantaneous failure
notification; a disappearing route still has an unreachable policy fallback.

Closing to the tray keeps the tunnel alive. Exiting Skewer ends the tunnel and
leaves attached applications guarded. A subsequent start resumes the selected
tunnel mode. Interface/VM ingress through tunnels is not supported yet: release
those selections first. Existing application sockets may need reconnecting.

`skewer tunnel skewer://HOST:PORT/pair` starts a foreground diagnostic tunnel
using an existing TLS-PSK pairing. It does **not** change application routing or
enable automatic tunneling yet. Ctrl-C closes the client and requests server
cleanup; an interrupted control connection is covered by lease expiry.

The privileged helper uses a transient systemd service, a root-owned executable
at `/usr/libexec/saslik/tuntom`, and the `tuntom` runtime account. The transport
key travels over stdin, never argv. The helper rejects conflicting interfaces
and overlapping subnets. `verified` requires fresh confirmed-session statistics
and a successful ping through the TUN; `prepared` only means the interface exists.

Both endpoints need the tuntom transport installed; transport packaging remains
separate. Do not interpret a successful diagnostic tunnel as evidence that
existing application connections use it. The GUI shows Tuntom active only when
the worker reports verification and the corresponding policy route exists.

Enter an IPv4 address that is directly reachable on one of the host's links.
Enabling routing creates one nftables output table and one policy-routing table
for the invoking UID. Packets from other users and processes outside
`skewer-routed.slice` are not marked. The next-hop address itself is explicitly
excluded to prevent recursive routing.

The graphical interface authorizes the narrow `skewer-net-helper` through
polkit. The TUI invokes the same helper through `sudo`. Disable routing before
the next-hop machine disappears; repeating enable or disable is safe.

## Interface ingress (IPv4)

The **Interfaces** root in Applications lists host interfaces, with bridge ports
nested beneath their bridge. Attach/Release also work in the TUI (`A` / `D`).
Selecting a whole bridge attaches its **current** ports; new ports are not
silently adopted. A disappeared selection remains visible until released.
Readable local libvirt runtime metadata supplies VM names when available;
Skewer never requests hypervisor credentials just to populate this list.
When `virsh` is available, a background lookup also queries explicit local
read-only libvirt sockets every 30 seconds. Each command has a timeout and the
lookup has a three-second command budget. No read/write socket fallback,
sudo, or daemon autostart is used. Exact domain XML interface targets determine
the VM name; `vnetN` by itself is not treated as proof of VM ownership.

This is ingress policy routing, **not** moving interfaces into a cgroup. Bridge
ports mark frames addressed to their host bridge gateway, retaining normal
bridge-local delivery into IPv4. They do not force broute onto unnumbered TAP
devices, where reverse-path validation can drop traffic. Non-exempt traffic
addressed to an external gateway MAC is currently blocked, not transparently
rerouted. Standalone interfaces use IPv4 prerouting marks. Rules use both the interface name and index. Per-user
interface tables are separate from application/cgroup routing. Closing the UI
does not remove them; Release removes a selection, and Disable removes both
interface and application routing.

- Saslik must be an on-link IPv4 next hop. Shared uplink bridges and unsupported
  master types are refused rather than guessed. Tunneling remains future work.
- IPv4 forwarding must already be enabled. Existing firewall policy, bridges,
  NAT and return routes are not rewritten. The remote side must have a valid
  return path to the guest; an existing forwarding firewall can still block it.
- IPv6 is blocked on selected ingress. Bridge frames other than IPv4 and ARP
  are blocked too (including VLAN-tagged traffic). DHCP, host-local addresses,
  multicast and configured destination exemptions are not redirected.
- Release interfaces before changing the gateway or destination exemptions.
- **Attached describes installed selection, not verified interception.** Guest
  CA trust is unknown: install the CA inside the guest separately. Neither
  guest processes nor their certificate stores are visible from the host.

`interface_routing` tests selection and rule generation. `interface_packets`
creates disposable user/network/mount namespaces, tests actual forwarded
packets on a real TAP and a standalone interface, with `rp_filter=2`, a
libvirt-style forwarding filter, and a return packet to the guest. It never modifies host
networking. It is explicitly skipped when user namespaces/tools are unavailable.

## Design rules

- The UI is defined exclusively in C++ code. Qt Designer files and generated
  `.ui` sources are not used.
- The graphical process always runs as the desktop user.
- Process movement uses the delegated user cgroup tree. Future system-wide
  network setup will be isolated in a narrow polkit-authorized helper.
- A request must never move a process owned by another UID.
# Shell scripting

Inside `skewer shell`, use `skewer status`, `skewer env`, and `skewer check`.
All three accept `--json`; `check` returns a nonzero status when the current
process is not routed or the configured control-plane checks fail.
These checks do not prove end-to-end interception and are not leak prevention.
Session variables describe launch-time configuration, not live health.

See `man skewer-shell-scripting` after installation, or
`man ./data/skewer-shell-scripting.1` from the source checkout.
Bash prints the manual reference on exit unless an existing user EXIT trap
needs to be preserved. Startup remains quiet.

## Fail-closed process routing

Routing changes use one authorized root helper session per running Skewer
client, over inherited private pipes. The GUI stays unprivileged; the helper
accepts a bounded whitelist of network operations, not shell commands or a
caller-supplied UID. No sudo ticket renewal or password storage is involved.
After Enable/Restore succeeds, the helper reconciles the saved next hop every
two seconds. It restores missing process routes after a lab interface restart,
without asking for the password again. While the interface is unavailable,
the fail-closed guard remains in force. Disable cancels the shared desired
state so another open Skewer cannot undo that choice. Closing the client ends
its helper, but does not dismantle routing or the guard. Every GUI startup
requests authorization once, independently of routing intent or lab availability.
The authorized helper stays alive for the application lifetime (including the
system tray), without relying on a sudo timestamp. The GUI then automatically
resumes saved routing intent when startup resume is enabled. Disabled or
explicitly disconnected clients do not resume. Cancellation is not retried by
polling; use **Restore routing** or **Maintain routing** to retry explicitly.
Missing root-owned intent requires explicit Enable/Restore, so stale GUI
settings cannot resurrect routing disabled by another client.

Before attaching or launching a process, Skewer installs a persistent output
guard for its routed cgroup. Disabling routing leaves that guard in place:
attached sockets are dropped instead of falling back to the host's default
route. Restoring routing allows IPv4 only through the configured next hop;
explicit destination exceptions apply only while routing is enabled. IPv6 is
blocked. The GUI displays **Dropped** and a red blinking routing status when
attached applications have no routing; **Unprotected** means the guard has not
yet been installed (for example, after upgrading a running older version).

This protects sockets created in the routed slice, not old sockets created
before Attach. Release also does not change an existing socket's cgroup;
reconnect or restart the application when necessary. A privileged external
firewall flush is outside this guarantee. Closing Skewer does not remove the
guard. Installation requires authorization, but status polling never does.

## Linux whole-host routing

Select **Whole Host** in the scope box left of the connection settings, then
**Enable**. In the TUI,
press **H** to choose scope and **E** to enable it. The choice is independent of
Set gateway / Saslik URL and Auto / Direct / Enforced tunnel. The default remains
**Selected Apps**. An empty application selection never enables host routing.
The existing privileged helper authorization also covers the explicit host request.

Host scope captures locally generated IPv4 from every user and service, including
normal external DNS. It uses Skewer's policy table; it does not replace the system
main/default routes. Direct traffic is masqueraded on the selected next-hop
interface; tunnel traffic uses the tunnel client address for replies. Forwarded
VM/interface traffic still has its separate selection and is not included by host
scope. IPv6 is blocked (apart from local `::1`); this is visible in the scope
selector tooltip and TUI. Local loopback, IPv4 DHCP and explicit destination
exemptions bypass host routing. Private subnets are not automatically exempt.

Tunnel UDP and readiness probes bypass only from the worker's system cgroup;
TLS control bypass is restricted to the initiating UID, peer IP and control port.
They retain the underlying system route, which Skewer never redirects into TUN.
Control and UDP use the same resolved IPv4 address. Reconnect reuses that address
while the host is blocked, so recovery does not require an external DNS bypass.
If the server changes address during an outage, use **Release host**, then Enable
to resolve it again. Competing VPN policy may prevent connectivity; marked host
packets are dropped if its rules select an interface other than the Saslik egress.

Tunnel loss or GUI/controller closure keeps host traffic blocked until recovery
or an explicit **Release host** (TUI **X**). A killed worker can leave installed
routes and the persistent guard behind; it does not intentionally restore direct
egress. Loss of the dedicated route is caught by the unreachable policy rule.
Only one UID owns the global host guard. Release removes its owned host rules and
restores the existing selected-application guard; attached application sockets
remain protected until released separately. Change scope or destination exemptions
only after releasing host routing. Existing connections may need reconnection when
changing routing or NAT. Privileged external firewall changes remain outside these
guarantees.

`host_routing_packets` exercises real OUTPUT egress, DNS, IPv6 blocking, NAT,
exemptions, competing policy routing, loss and release in private user/network/mount
namespaces. `tuntom_routing` also exercises the privileged host-scope lifecycle and
real marked packets through a simulated tunnel interface. These do not replace
an end-to-end test against a remote Saslik with the real Tuntom transport.
