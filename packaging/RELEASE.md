Skewer for Debian 12/13 and Ubuntu / Kubuntu 24.04/26.04 LTS (amd64).

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
Closing Skewer leaves applications and routing running. Use Disable and Release
explicitly to undo them. IPv6 is not routed by this version.

Verify the download with `sha256sum -c SHA256SUMS`.
