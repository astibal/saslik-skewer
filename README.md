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

## Routing

Enter an IPv4 address that is directly reachable on one of the host's links.
Enabling routing creates one nftables output table and one policy-routing table
for the invoking UID. Packets from other users and processes outside
`skewer-routed.slice` are not marked. The next-hop address itself is explicitly
excluded to prevent recursive routing.

The graphical interface authorizes the narrow `skewer-net-helper` through
polkit. The TUI invokes the same helper through `sudo`. Disable routing before
the next-hop machine disappears; repeating enable or disable is safe.

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
