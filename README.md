# pico-init

A small, systemd-compatible init system for constrained embedded Linux
boards: 200 MHz-class CPUs with around 64 MiB of RAM. It is written in C,
needs nothing at runtime beyond the C library, and is built for
OpenEmbedded images whose packages expect systemd.

pico-init keeps systemd's architecture -- declarative unit files,
dependency-ordered jobs, one cgroup v2 per service -- and the file formats
packages already ship, and reimplements the rest at a much smaller scale.
Parts of the PID 1 core are quarried from early (2011-era) systemd source;
the DHCP and SNTP code in `netd` is lifted from current systemd.

## What is in the box

- **`pico-init`** (PID 1). Mounts the API filesystems, restores the wall
  clock, checks and remounts the root filesystem, processes `/etc/fstab`
  (including swap and UBI/ubifs), activates Discoverable Partitions swap,
  creates `/etc/machine-id` and applies presets on first boot, then loads
  units and runs the boot transaction on an `sd_event` main loop. It feeds
  a hardware watchdog when one exists, listens for `sd_notify()`, and
  re-reads unit files on `SIGHUP`.
- **`picoctl`**, the `systemctl` equivalent: `status`, `list-units`,
  `list-unit-files`, `show`, `cat`, `is-active`, `is-failed`,
  `is-enabled`, `is-system-running`, `enable`, `disable`, `reenable`,
  `preset`, `mask`, `unmask`, `start`, `stop`, `restart`, `try-restart`,
  `reload-or-restart`, `kill`, `reset-failed`, `daemon-reload`, `reboot`,
  `poweroff`, `halt`. Output and colours follow `systemctl`. The read verbs
  work from state files under `/run/pico-init` and keep working when PID 1
  is wedged; `--root` works for the file verbs.
- **`netd`**, a network daemon reading `.network` files from the
  `systemd-networkd` directories: static addresses, a DHCPv4 client and
  server, DNS into `/etc/resolv.conf`, an SNTP client, the time zone from
  DHCP, and LLDP. **`netctl`** is its `networkctl`-style client (`status`,
  `list`, `lldp`, `reload`).
- **`logd`**, a log daemon collecting service stdout/stderr, `/dev/log` and
  `/dev/kmsg` into a 2 MiB ring in `/run/logd` (journal export format, not
  the binary journal). **`picolog`** is its `journalctl`-style reader.
- **`devd`**, a device daemon for devtmpfs-only images: maintains
  `/dev/disk/by-*` links, mounts GPT data partitions of removable media
  under `/media`, loads modules by `MODALIAS`, classifies input devices like
  udev's `input_id` builtin, and runs a subset of real udev rules files.
- **`pico-tmpfiles`**: `systemd-tmpfiles --create`, `--clean` and
  `--remove` over the `tmpfiles.d` files packages install.
- **`libsystemd.so.0`** and **`libudev.so.1`**, compatibility libraries
  with the symbol versions and `pkg-config` files of systemd v259. A
  function is real where pico-init has a real mechanism (`sd-daemon`,
  `sd-event`, `sd-id128`, `sd-journal` over `logd`, `sd-device` and
  `libudev` over sysfs and devd's udev database, the cgroup half of
  `sd-login`) and returns an error where it has none (`sd-bus`
  never connects, there is no hwdb, no logind data). An image that runs a
  real D-Bus daemon needs real libsystemd.
- **`pico-unit-lint`**, PID 1's own unit parser run over an installed unit
  tree, so a build log shows which directives a booted system would drop.

## systemd compatibility

Unit files are read unmodified from `/etc/systemd/system` and
`/usr/lib/systemd/system`; presets from the matching `system-preset`
directories are applied on first boot. Service, socket and target units are
supported, with templates, the `%n %N %p %i %I` specifiers, aliases,
masking, and `.wants`/`.requires` directories.

Directives that are honoured:

- `[Unit]`: `Description=`, `Requires=`, `Wants=`, `Before=`, `After=`,
  `Conflicts=`, `ConditionPathExists=`, `ConditionPathIsDirectory=`.
- `[Service]`: `Type=` (`simple`, `exec`, `oneshot`, `forking`,
  `notify`), `ExecCondition=`, `ExecStartPre=`, `ExecStart=`, `ExecStop=`,
  `ExecStopPost=`, `Environment=`, `EnvironmentFile=`, `User=`, `Group=`,
  `SupplementaryGroups=`, `PIDFile=`, `GuessMainPID=`, `Restart=`,
  `RestartSec=`, `RemainAfterExit=`, `TimeoutStartSec=`,
  `TimeoutStopSec=`, `StandardInput=` (`socket`, `tty`, `tty-force`,
  `tty-fail`), `TTYPath=`, `StandardOutput=`/`StandardError=` (`inherit`,
  `journal`, `syslog`, `null`), `Delegate=`, `DelegateSubgroup=`, `KillMode=`,
  `KillSignal=`, `SendSIGHUP=`, `SendSIGKILL=`.
- `[Socket]`: `ListenStream=`, `ListenDatagram=`, `Service=`, `Accept=`,
  `SocketMode=`, `Backlog=`, `MaxConnections=`.
- `[Install]`: `WantedBy=`, `RequiredBy=`.

Anything else does not stop a unit from loading. Every directive pico-init
cannot honour is recorded on the unit: PID 1 logs one warning per unit at
load and a summary once the boot has settled, `picoctl show` lists the
drops as `Degraded-Directives=`, and `pico-unit-lint [--warn-only] DIR...`
reports the same record at build time. Some values degrade rather than
drop: `Type=dbus` and `Type=idle` run as `simple`, `Type=notify-reload` as
`notify`, and a dependency on a unit type pico-init does not have
(`.mount`, `.timer`, ...) is recorded rather than followed. An unknown
`Type=` fails the unit, because running it as `simple` would report it
started too early.

## cgroups

pico-init uses the unified cgroup v2 hierarchy only. Each service runs in
`/sys/fs/cgroup/system.slice/<unit>`, a stop kills the whole cgroup
(through `cgroup.kill` where the kernel has it), and cgroup emptiness is
watched rather than polled. At boot PID 1 enables the `cpu` and `memory`
controllers in the root and in `system.slice`, so unit cgroups have
`cpu.weight`, `memory.high` and the rest; a controller the kernel refuses
is a warning, not a boot failure.

`Delegate=` follows systemd: a boolean or a list of controllers, where an
empty value delegates with no controllers and `no` clears it. With a
non-root `User=`, the unit cgroup is handed to that user. With `Delegate=`
set, `DelegateSubgroup=` starts the main process in `<unit cgroup>/<name>`
and every other process of the unit in `<unit cgroup>/.control`, so the
unit cgroup holds no process and the service can enable controllers in it.
Child cgroups are removed depth-first when the unit stops, and a stale,
empty unit cgroup is reset before the next start. `picoctl show` prints
`Delegate=`, `DelegateControllers=` and `DelegateSubgroup=`.

`KillMode=process` and `none` leave the rest of a unit's cgroup running when
its main process exits or the unit stops, which is how a login through a
socket-activated `dropbear@` keeps `screen` and `tmux` alive. Such a cgroup
is kept until its processes exit, and at reboot and poweroff everything left
gets SIGTERM, then SIGKILL.

## Networking and time

`netd` reads `.network` files from `/etc/systemd/network`,
`/run/systemd/network` and `/usr/lib/systemd/network`. It implements
`[Match] Name=`, `[Network] DHCP=` (IPv4; `ipv6` is accepted and ignored),
`Address=`, `Gateway=`, `DNS=`, `NTP=`, `DHCPServer=`, `LLDP=`,
`EmitLLDP=`, and `[DHCPv4] UseDNS=`, `UseNTP=`, `UseTimezone=`; other
directives are ignored. NTP servers come from `NTP=` or DHCP option 42, the
time zone from DHCP option 101. A link with a random kernel MAC address is
given a stable one, and `netd` sets a modern default qdisc and TCP
congestion control where the kernel offers them.

`LLDP=` (`yes` or `routers-only`) receives neighbour announcements and
`EmitLLDP=` sends them; both are off unless set. The neighbour table of
each link is bounded, the frame parser rejects malformed frames whole, and
`netctl lldp` lists what was heard.

For boards whose RTC is dead or reset by a reboot, PID 1 restores the wall
clock from `/etc/timestamp` (the OpenEmbedded `YYYYMMDDHHMMSS` UTC file)
before any service starts and saves it two minutes after boot, every ten
minutes and at shutdown. The clock only ever moves forward, to the latest
of the saved time, the file's mtime and a build epoch; NTP corrects the
rest.

## Not implemented

- Mount, swap, timer, path, device, scope and slice units. `/etc/fstab` is
  handled by PID 1 at boot instead.
- Running `ExecReload=`: it is parsed and recorded as degraded, and
  `picoctl reload` refuses. `isolate`, `get-default` and `set-default` are
  not available.
- Resource-control directives (`CPUWeight=`, `MemoryHigh=`, `MemoryMax=`,
  `TasksMax=`, ...) and sandboxing directives (`ProtectSystem=`,
  `PrivateTmp=`, `NoNewPrivileges=`, ...).
- `WatchdogSec=` and the `WATCHDOG=` notify keys, `NotifyAccess=`.
- D-Bus: no bus, no logind, no hwdb.
- DHCPv6 and IPv6 router advertisements in `netd`.

## Building and testing

pico-init builds with meson (0.62 or newer) and ninja on Linux:

```sh
meson setup build
ninja -C build
sudo -E meson test -C build --print-errorlogs
```

CI runs the tests as root, because the PID 1 tests create real cgroups and
the `netd` tests create network devices.

CI also checks formatting with `clang-format-18 --dry-run --Werror` over
`src/` and license compliance with `reuse lint`.

## License

pico-init as a whole is GPL-2.0-or-later (see [`LICENSE`](LICENSE)); the
PID 1 core is derived from systemd source that predates its relicensing to
LGPL-2.1-or-later. Every file carries an SPDX identifier or is covered by
[`REUSE.toml`](REUSE.toml), and the license texts are in
[`LICENSES/`](LICENSES/). The DHCPv4 code under `src/netd/dhcp/`, the SNTP
and time code in `src/netd/`, and the vendored systemd symbol and
`pkg-config` files are LGPL-2.1-or-later; `siphash24` is CC0-1.0 and
`sparse-endian.h` is MIT.

## Contributing and security

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and the
[code of conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as
described in [`SECURITY.md`](SECURITY.md), not in a public issue.
