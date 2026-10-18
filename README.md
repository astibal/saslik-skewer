# Saslik Skewer

Skewer is a desktop application browser for selectively routing applications
through a Saslik lab.

The first development slice discovers processes belonging to the current user,
reconstructs their process trees, presents likely applications first, and can
launch a new command. Cgroup management and routing live behind a future
privileged helper; the graphical application always runs as the desktop user.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
./build/skewer
```

The UI is defined exclusively in C++ code. The project does not use Qt Designer
or generated `.ui` files.
