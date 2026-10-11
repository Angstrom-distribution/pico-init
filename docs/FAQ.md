# Frequently asked questions

Short answers to what users of pico-init ask first. Each answer points at the
mechanism in the tree; the other documents in this set have the detail. The
overview is in [the README](../README.md).

## Why not systemd?

Pico-init targets boards with a CPU in the 200 MHz class and around 64 MiB of
RAM, where the full systemd does not fit. It keeps systemd's unit files,
dependency-ordered jobs and one cgroup v2 per service, so packages that ship
systemd units work unmodified, and drops what a small board does not use: no
D-Bus, no logind, no timer, mount, path or slice units. See
[INCOMPATIBILITIES.md](INCOMPATIBILITIES.md) for the full list of what is
missing and [ARCHITECTURE.md](ARCHITECTURE.md) for how the parts fit.

## What does it need at run time?

A Linux kernel with the unified cgroup v2 hierarchy, and the C library. The
only `dependency()` in `meson.build` is `dl`, used by a test; there is no
D-Bus, libmount or libudev dependency. PID 1 mounts `/proc`, `/sys`, `/dev`,
`/run` and `/sys/fs/cgroup` itself, among others. When cgroup v2 is missing,
PID 1 warns and keeps booting, but service supervision depends on it.

## Does it run on a desktop?

Not as a replacement init. `pico-init` exits immediately with "not running as
PID 1, exiting" when it is started as a normal process, so it can only be
tried as the init of a VM, a board, or another environment in which it really
is PID 1. The tooling is different: `picoctl --root DIR` runs the file-based
verbs (such as `enable`, `disable` and `preset`) against an image tree on a
development machine, and `pico-unit-lint DIR` checks an installed unit tree at
build time.

## How do I enable a service?

```sh
picoctl enable foo.service
picoctl start foo.service
```

`enable` writes the `.wants`/`.requires` symlinks named by the unit's
`[Install]` section (`WantedBy=`, `RequiredBy=`) under `/etc/systemd/system`;
it does not start the unit, and there is no `--now`. A unit without an
`[Install]` section is not an error: `enable` prints a notice and exits 0. On
first boot, when `/etc/machine-id` is missing, empty or `uninitialized`, PID 1
applies the presets during startup; see [PRESET.md](PRESET.md).

## Why does my unit show Degraded-Directives?

The unit uses directives pico-init does not implement, and it loaded anyway
with those directives dropped. `picoctl show UNIT` prints them space-separated
in `Degraded-Directives=`; the line is empty when every directive was
honoured. PID 1 logs one warning per unit at load, and once the boot has
settled it logs a summary of how many units and directives were affected. At
build time, `pico-unit-lint [--warn-only] DIR...` reports the same record over
an installed unit tree. The honoured directives are listed in the README;
resource-control and sandboxing directives such as `MemoryMax=` and
`PrivateTmp=` are the usual cause, and they are not enforced.

## Can screen or tmux survive an ssh logout?

Yes, if the unit that holds the login session sets `KillMode=process`. Then,
when the main process exits or the unit stops, the rest of the unit's cgroup
is left running instead of being killed (the default, `control-group`, kills
it). The cgroup is kept until its remaining processes exit. A socket-activated
per-connection unit with `StandardInput=socket` is the usual shape for an ssh
login. At reboot and poweroff, PID 1 sends everything still running SIGTERM,
waits up to five seconds, then sends SIGKILL, so these processes do not
outlive the shutdown. `KillMode=none` behaves the same way except that it also
sends no signal on stop.

## Where are the logs?

`logd` collects service stdout and stderr, `/dev/log` and `/dev/kmsg` into a
two-file ring under `/run/logd` (an active and a rotated file, in journal
export format). The default size is 2 MiB, and `/run` is tmpfs, so the log is
held in RAM, never written to flash, and gone after a reboot. Read it with
`picolog`:

```sh
picolog -u foo.service -n 50
picolog -f
picolog -k
picolog -p warning -o export
```

The options are `-f` (follow), `-u UNIT`, `-p PRIO`, `-k` (kernel messages
only), `-n LINES`, `-o short|export` and `-a`. See [LOGD.md](LOGD.md).

## How do I reboot?

```sh
picoctl reboot
picoctl poweroff
picoctl halt
```

Each sends a signal to PID 1 (`SIGINT` for reboot, `SIGRTMIN+4` for poweroff,
`SIGRTMIN+3` for halt) and acts immediately; there is no scheduler or wall
message, and `-f`/`--force` is accepted and ignored. `shutdown [-r|-h|-P]
[now]` is not a `picoctl` verb. `picoctl` dispatches on its own name when it
is invoked as `reboot`, `poweroff`, `halt` or `shutdown`, so those names work
once the packaging provides symlinks to the binary; the build installs none.
