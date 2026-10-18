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
- rejects processes that do not belong to the current user.

Skewer currently establishes the process-selection boundary only. It does not
yet install nftables policy-routing rules or provide a remote transport. Until a
transport backend is configured, `attached` means that an application is in the
Skewer cgroup, not that its packets are already leaving through Saslik.

Existing sockets retain the routing context in which they were created. For a
reliable test, launch the application through Skewer instead of attaching an
already-running process tree.

## Build and test

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

## Design rules

- The UI is defined exclusively in C++ code. Qt Designer files and generated
  `.ui` sources are not used.
- The graphical process always runs as the desktop user.
- Process movement uses the delegated user cgroup tree. Future system-wide
  network setup will be isolated in a narrow polkit-authorized helper.
- A request must never move a process owned by another UID.
