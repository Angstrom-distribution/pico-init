# Distribution porting

This document lists what a distribution or OpenEmbedded layer has to provide
to boot with pico-init as `/sbin/init`: what the build installs and where,
how to split it into packages, which units and targets the image must bring
itself, how presets are applied, and what to run at image build time. Pico-init
reads unmodified systemd unit files, so most packages need no changes; the
work is in the image-level glue. For the overall design see
[ARCHITECTURE.md](ARCHITECTURE.md).

## Building

Pico-init builds with meson (0.62 or newer) and ninja, as a C project with
`c_std=gnu17`, `warning_level=3` and `werror=true`:

```sh
meson setup build --prefix=/usr
ninja -C build
DESTDIR=/path/to/image meson install -C build
```

`meson.build` defines no project options of its own. Install paths come from
the standard meson directory options (`prefix`, `bindir`, `sbindir`,
`libdir`, `includedir`, `sysconfdir`). The version string comes from
`git describe` at build time (`vcs_tag()`), with the fallback `unknown` for
a source tree without `.git`, such as a release tarball.

The test suite is part of the meson project. Run it as root, as CI does:
tests that need cgroups, mounts or network namespaces skip (exit status 77)
when they lack the privilege. See [HACKING.md](HACKING.md).

## Installed files

Binaries and libraries follow `bindir`, `sbindir` and `libdir`. Units, udev
rules and tmpfiles integration use fixed `$prefix/lib` paths, not `libdir`,
so a multilib layout keeps them in `/usr/lib`.

| File | Directory | Notes |
|------|-----------|-------|
| `pico-init` | `sbindir` | PID 1 |
| `picoctl` | `sbindir` | `systemctl` equivalent |
| `netd` | `sbindir` | network daemon |
| `logd` | `sbindir` | log daemon |
| `devd` | `sbindir` | device daemon |
| `netctl` | `bindir` | `networkctl` equivalent |
| `picolog` | `bindir` | `journalctl` equivalent |
| `pico-tmpfiles` | `bindir` | `systemd-tmpfiles` equivalent |
| `pico-unit-lint` | `bindir` | build-time unit checker |
| `libsystemd.so.0.45.0`, `libsystemd.so.0` | `libdir` | compatibility library |
| `libudev.so.1.7.15`, `libudev.so.1` | `libdir` | compatibility library |
| `systemd/*.h`, `libudev.h` | `includedir` | public headers |
| `libsystemd.pc`, `systemd.pc`, `libudev.pc`, `udev.pc` | `libdir/pkgconfig` | |
| `netd.service`, `network.target` | `$prefix/lib/systemd/system` | |
| `logd.service`, `logd.socket` | `$prefix/lib/systemd/system` | |
| `devd.service` | `$prefix/lib/systemd/system` | |
| `pico-tmpfiles.service` | `$prefix/lib/systemd/system` | |
| `60-pico-serial.rules` | `$prefix/lib/udev/rules.d` | read by `devd` |

The build installs no `/sbin/init` link. The kernel starts `/sbin/init`, so
the layer must provide it, for example as a symlink to `pico-init`.

The `.pc` files report systemd release 262, because consumers gate on
`systemd >= N`, and `systemd.pc` carries the directory variables recipes ask
for (`systemdsystemunitdir`, `systemdsystempresetdir`, `tmpfilesdir`,
`udevdir` through `udev.pc`). The shared libraries carry upstream's symbol
versions; see [COMPATIBILITY_LIBRARIES.md](COMPATIBILITY_LIBRARIES.md).

## Package split

The build does not define packages. The files above fall into groups that
can be packaged independently, because `netd`, `logd` and `devd` are
separate processes supervised by PID 1 rather than parts of it:

| Group | Contents | Needs |
|-------|----------|-------|
| `pico-init` | `pico-init`, `picoctl`, `pico-tmpfiles`, `pico-tmpfiles.service` | libc |
| `pico-init-netd` | `netd`, `netctl`, `netd.service`, `network.target` | libc |
| `pico-init-logd` | `logd`, `picolog`, `logd.service`, `logd.socket` | libc |
| `pico-init-devd` | `devd`, `devd.service`, `60-pico-serial.rules` | libc |
| libsystemd, libudev | the two `.so` files | libc |
| `-dev` | headers and `.pc` files | |
| `pico-unit-lint` | `pico-unit-lint` | libc |

`libudev.so.1` is linked against `libsystemd.so.0`, so the two ship
together. `logd.socket` makes `logd` socket-activated: PID 1 binds and holds
`/dev/log` and `/run/logd/stdout`, so a `logd` crash does not sever any
service's stdout. `netd`, `logd` and `devd` ship `WantedBy=default.target` and
rely on the preset file to decide whether they run.

## Units the image must provide

The build ships four service units (`netd`, `logd`, `devd`, `pico-tmpfiles`),
`logd.socket` and `network.target`.
It ships no `default.target`, `sysinit.target`, `sockets.target`,
`multi-user.target` or `basic.target`. The shipped units and PID 1 refer to
these names:

| Unit | Why |
|------|-----|
| `default.target` | Root of the boot transaction. If it cannot be loaded, startup fails; PID 1 still enters its event loop so the console stays usable. |
| `sockets.target` | `.socket` units install with `WantedBy=sockets.target`, and PID 1 adds `After=sockets.target` to every service when the target exists. |
| `sysinit.target` | `pico-tmpfiles.service` installs `WantedBy=sysinit.target` and runs `Before=` it. |

`default.target` can be an alias, as OpenEmbedded produces it:

```sh
ln -s multi-user.target /etc/systemd/system/default.target
```

Aliases are resolved when a name is loaded, so the symlink needs no
`Alias=` in the target. PID 1 also orders every target `After=` each unit it
`Wants=` or `Requires=`, so a target marks a point in the boot without
needing explicit `After=` lines.

`multi-user.target`, `basic.target` and the other targets that packages
name in `WantedBy=` or `After=` are ordinary target units, and the image has
to supply whichever of them its packages reference.
`network.target` is passive and `netd.service` orders itself before it;
`network-online.target` is not provided.

Pico-init has no mount, swap, timer, path, device, scope or slice units.
`/etc/fstab` is processed by PID 1 itself, before any unit loads. A
dependency on a unit type pico-init does not have is recorded as degraded
rather than followed.

## Unit search paths

PID 1 searches, in this order:

1. `/etc/systemd/system`
2. `/usr/lib/systemd/system`

and presets in `/etc/systemd/system-preset` and
`/usr/lib/systemd/system-preset`. The layout assumes a merged `/usr`;
`/lib/systemd/system` is not searched. `systemd.pc` reports
`$prefix/lib/systemd/system` as `systemdsystemunitdir`, so packages that
ask pkg-config install there.

A literal instance unit wins over the template across all directories, so
`serial-getty@ttyGS0.service` in `/etc/systemd/system` beats
`serial-getty@.service` in `/usr/lib/systemd/system`.

## Presets

Pico-init applies presets itself, on first boot only:

- First boot means `/etc/machine-id` is missing, empty, unparseable or
  contains `uninitialized`. PID 1 writes a new id and applies presets to every unit
  that no `.wants/` or `.requires/` symlink already enabled and that has an
  `[Install]` section.
- The result is written as real symlinks under the target's `.wants/` or
  `.requires/` directory. Later boots read the symlinks and do not read
  presets again, so `picoctl disable` stays disabled.
- Only `.preset` files are read. The first file with a given basename in the
  preset path wins, and within the sorted set of files the first matching
  line wins, as in `systemd.preset(5)`.
- A unit that no line matches is enabled, as `systemctl preset` does. An
  image that wants the opposite ships a catch-all `disable *` line.

For a read-only root, either enable units at image build time by creating
the `.wants/` symlinks, or make `/etc` writable before PID 1 runs. If
`/etc` is read-only, PID 1 binds a tmpfs-backed `/run/machine-id` over
`/etc/machine-id` and still reports a first boot, but the id does not
persist. The bind needs `/etc/machine-id` to exist in the image as an empty
file. See [PRESET.md](PRESET.md) for the file format.

A typical image ships a preset file that enables the daemons it wants and
disables the rest:

```
enable netd.service
enable logd.service
enable devd.service
enable pico-tmpfiles.service
disable *
```

## Getty and login units

Pico-init ships no getty units. Take `getty@.service` or
`serial-getty@.service` from the distribution; they load unmodified.
Supported pieces that these units use:

- `StandardInput=tty`, `tty-force` and `tty-fail`, with `TTYPath=`
  (default `/dev/console`).
- Template instances such as `serial-getty@ttyS0.service` load from the
  template when no literal file exists.
- `Restart=`, `KillMode=`, `ExecStartPre=` and `ExecCondition=`.

`ConditionPathExists=` is not specifier-expanded, so a template cannot use
`ConditionPathExists=/dev/%I`. Instances are enabled with a `.wants/`
symlink for the instance.

An unprivileged login needs nothing from pico-init beyond a service with
`User=` and `Group=`; there is no logind. `KillMode=process` and `none`
leave the rest of the cgroup running when the main process exits, which
keeps `screen` and `tmux` alive after an `ssh` session ends.

## Command names

The build installs `picoctl`, `picolog` and `netctl` under their own names
and creates no `systemctl`, `journalctl` or `networkctl`. Recipes and
scripts that call the upstream names need links, normally managed with
`update-alternatives` so a real systemd package can coexist:

| Upstream name | pico-init binary |
|---------------|------------------|
| `systemctl` | `picoctl` |
| `journalctl` | `picolog` |
| `networkctl` | `netctl` |
| `systemd-tmpfiles` | `pico-tmpfiles` |

`picoctl` also dispatches on `argv[0]`: when invoked as `reboot`,
`poweroff`, `halt` or `shutdown` it behaves as that command and takes no
verb. `reboot` signals PID 1 with `SIGINT`, `poweroff` with `SIGRTMIN+4`
and `halt` with `SIGRTMIN+3`. Provide those four names as links to
`picoctl` to get this. Error hints printed by `picoctl`
mention `systemctl status` and `journalctl -xeu`, which is only correct
advice when those links exist.

`picolog` writes journal export format with `-o export`; piping it to
`systemd-journal-remote` on another machine gives full `journalctl` access.
The binary journal format is not implemented.

## Runtime requirements outside pico-init

Everything below is looked up by absolute path or `PATH` at run time.

| Need | Used for |
|------|----------|
| `/usr/sbin/fsck.ext4` | Root filesystem check, only when the ext superblock reports errors. A missing checker still ends in a remount. |
| `fsck.<type>` in `/usr/sbin` | `/etc/fstab` pass checks |
| `/sbin/modprobe` | `devd` runs it for every `MODALIAS` |
| `/usr/share/zoneinfo` | `netd` sets `/etc/localtime` from DHCP option 101 when the zone file exists; install tzdata |
| `/etc/hostname` | Applied with `sethostname(2)` by PID 1 |
| `/etc/fstab` | Parsed by PID 1; `UUID=`, `LABEL=`, `PARTUUID=` and `PARTLABEL=` sources resolve through sysfs |
| `/etc/os-release` | Source of the greeting PID 1 prints on the console |
| `/etc/timestamp` | Saved wall clock on boards without a working RTC (OpenEmbedded `YYYYMMDDHHMMSS` UTC format) |
| `/etc/systemd/network/*.network` | `netd` configuration; also read from `/run/systemd/network` and `/usr/lib/systemd/network` |

Services started by PID 1 find executables without a path in
`/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin` and `/usr/bin`, in that
order.

PID 1 mounts `/proc`, `/sys`, `/dev` (devtmpfs), `/dev/pts`, `/dev/shm`,
`/run`, `/sys/fs/cgroup` (cgroup2 with `nsdelegate`) and
`/sys/kernel/config` itself, and creates `/dev/core`, `/dev/fd`,
`/dev/stdin`, `/dev/stdout` and `/dev/stderr`; `/etc/fstab` need not list
these. Supervision needs a kernel with cgroup v2. An initramfs that already
mounted any of them is left alone. See
[API_FILE_SYSTEMS.md](API_FILE_SYSTEMS.md).

The wall-clock floor is fixed in `clock-persist.h` as 1767225600 seconds
(2026-01-01 00:00:00 UTC). The clock is set forward to the latest of
`/etc/timestamp`, that file's mtime and the floor.

## Checking units at image build time

`pico-unit-lint` runs PID 1's own unit parser over an installed tree and
prints what a booted pico-init would drop, so a compatibility gap appears
in the build log instead of on the board:

```sh
pico-unit-lint [--warn-only] [--verbose] DIR...
```

```
<unit>: <n> dropped: <directive> [<directive> ...]
<unit>: FAILED TO LOAD
pico-unit-lint: <n> units in tree, <d> degraded (<k> directives dropped), <f> failed to load
```

| Exit status | Meaning |
|-------------|---------|
| 0 | No findings |
| 1 | Findings, unless `--warn-only` is given |
| 2 | The tree could not be scanned |

Each template is loaded once under the instance name `lint` and reported
under its own name. In a recipe, run the host-built or native binary over
the rootfs unit directories after package installation, for example in a
`ROOTFS_POSTPROCESS_COMMAND`, with `--warn-only` first and without it once
the findings are triaged:

```sh
pico-unit-lint ${IMAGE_ROOTFS}/usr/lib/systemd/system \
               ${IMAGE_ROOTFS}/etc/systemd/system
```

Dropped directives are not errors by themselves: resource-control and
sandboxing directives are dropped by design. An unknown `Type=` fails the
unit, as does a unit file the parser rejects, and those are the findings to
act on. The same record is visible on a running system as
`Degraded-Directives=` in `picoctl show UNIT`. See [DEBUGGING.md](DEBUGGING.md)
and [INCOMPATIBILITIES.md](INCOMPATIBILITIES.md) for the list of dropped
directives.

## Checklist

- `/sbin/init` points at `pico-init`.
- `default.target`, `sockets.target` and `sysinit.target` exist, directly or
  as aliases.
- A preset file enables the daemons the image wants.
- `/etc/machine-id` is empty or absent in the image, and `/etc` is writable
  on first boot, or the `.wants/` links are created at build time and an
  empty `/etc/machine-id` exists for the transient bind.
- Getty units are installed and enabled.
- `fsck.ext4`, `modprobe` and tzdata are installed.
- `systemctl`, `journalctl`, `networkctl` and `reboot`-family links exist.
- `pico-unit-lint` runs over the final unit tree.
