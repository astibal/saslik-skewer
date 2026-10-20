# Saslik Skewer

Skewer discovers desktop applications and user process trees and places selected
applications into a stable cgroup that can be routed through a Saslik lab.

## Current capabilities

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

Moving applications and configuring networking are deliberately separate.
`Attached` means that an application is in the Skewer cgroup. `Routing active`
means that nftables marking and the dedicated policy-routing table are also
installed. No remote transport is provided yet.

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
