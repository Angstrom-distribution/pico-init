# Debugging pico-init

This document covers where pico-init writes diagnostics, how to read unit
state when PID 1 is slow or stuck, how to find out which unit directives
were ignored, how to run the test suite, and what to do when PID 1 freezes.
The tools are `picoctl`, `picolog` and `pico-unit-lint`; see
[ARCHITECTURE.md](ARCHITECTURE.md) for how the pieces fit together.

## Where output goes

PID 1 has two output channels.

| Channel | Destination | Content |
|---------|-------------|---------|
| Console status | `/dev/console` (stdout if it cannot be opened) | The greeting and per-unit progress lines |
| Log records | `/dev/kmsg` once PID 1 has set it up, stderr before that | Everything written with `pico_log()` |

Log records carry a prefix of the form `pico-init[LEVEL]: `, where LEVEL is
one of `err`, `warning`, `info`, `debug`. On `/dev/kmsg` the record also
carries the matching syslog priority (3, 4, 6, 7), so the kernel ring keeps
the level. The first record PID 1 logs after switching to `/dev/kmsg` is the
version line:

```
pico-init[info]: pico-init <version> (<git description>) running as PID 1
```

There is no log-level setting. `pico_log()` has no runtime filter, and PID 1
does not parse the kernel command line or read any environment variable to
change its logging. Every record is written; `debug` records appear in the
ring along with the rest. To see only the important ones, filter when
reading (`picolog -p warning`, below).

Only PID 1 redirects to `/dev/kmsg`. `logd` and `netd` are supervised
services; their stdout is connected to `logd`, so their records arrive with
the unit name attached. `picoctl`, `picolog` and `pico-unit-lint` log to the
caller's stderr.

Because `logd` reads `/dev/kmsg` from the start of the ring, everything PID 1
logged before `logd` started is in the log once `logd` is up. Before that,
read it on the console or with `dmesg`.

### Kernel command line

PID 1 does not read `/proc/cmdline` for its own options. What the kernel
command line controls is what the kernel does with the init process:

- `init=/path` selects the binary the kernel runs as PID 1.
- Console selection (`console=`) decides where `/dev/console` leads, and so
  where the console status channel appears.

The only consumer of `/proc/cmdline` in PID 1 is the `/etc/fstab` pass
(`fstab-mount.c`), which reads the `ubi.mtd=` parameters from it to attach UBI
volumes before mounting.

## Reading unit state

`picoctl` read verbs (`status`, `list-units`, `list-unit-files`, `show`,
`cat`, `is-active`, `is-failed`, `is-enabled`, `is-system-running`) read files
rather than asking PID 1. PID 1 publishes one `Property=value` file per unit
under `/run/pico-init/units/`, plus `/run/pico-init/manager`, rewriting each
file atomically (temporary file, then `rename()`) on every state transition.
These verbs therefore still answer when the event loop is wedged. The control
verbs (`start`, `stop`, `restart`, `kill`, `reset-failed`, `daemon-reload`,
...) go through the control socket `/run/pico-init/control` and need a live
PID 1.

```
picoctl                          # same as list-units
picoctl status foo.service
picoctl show foo.service
picoctl cat foo.service
picoctl is-system-running
```

A bare unit name gets `.service` appended, as with `systemctl`.

`show` prints the unit's state file as it is, with `UnitFileState` recomputed
from disk. The fields include `ActiveState`, `SubState`, `LoadState`,
`FragmentPath`, `Description`, `MainPID`, `Result`, `ExecMainCode`,
`ExecMainStatus`, `NRestarts`, `Job` and the `Delegate*`, `Kill*` and
`SendSIG*` settings. For a service that has called `sd_notify()` it also shows
`NotifyReady`, `StatusText` and `StatusErrno`. A unit that was never published
reads as `LoadState=not-found`, `ActiveState=inactive`.

`is-system-running` prints one of `running`, `starting`, `degraded` or
`offline`. The system is `degraded` when a unit has failed or when
`/etc/fstab` lines were skipped or failed to mount; the per-line outcomes are
recorded in `/run/pico-init/fstab`.

`--root DIR` makes the file-based verbs (`cat`, `enable`, `disable`,
`is-enabled`, `preset`, `mask`, `unmask`) operate on an unpacked image
instead of the running system.

### Degraded-Directives

pico-init implements a subset of systemd's unit directives. A directive it
does not implement is dropped at load time rather than treated as an error,
and the unit records it. `show` prints the record as one space-separated
field:

```
$ picoctl show iiotool.service
...
Degraded-Directives=PrivateTmp DynamicUser ProtectSystem
```

An empty value (`Degraded-Directives=`) means every directive in the unit
was honoured. The same list is logged once per unit, at `warning`, when the
unit file is parsed:

```
pico-init[warning]: foo.service: 2 directives not implemented by pico-init dropped: PrivateTmp DynamicUser
```

Once the boot transaction settles, PID 1 logs one summary line, at
`warning` when any unit is degraded and at `info` otherwise:

```
pico-init[warning]: boot settled: 3 of 41 units degraded, 5 directives dropped (see 'picoctl show <unit>' Degraded-Directives=)
pico-init[info]: boot settled: 41 units loaded, none degraded
```

If a service behaves differently from the same unit under systemd, check
this field first: a sandboxing, resource or ordering directive that was
dropped has no effect.

## picolog

`picolog` reads the `logd` ring files in `/run/logd` directly and does not
need the daemon to be running. The ring holds the current boot only
(`active.export` and `rotated.export`, 2 MiB in total by default), so there
is no `-b`.

```
picolog                    # dump the ring
picolog -f                 # follow
picolog -u foo.service     # one unit
picolog -p warning         # warning and more severe
picolog -k                 # kernel records only
picolog -n 50              # last 50 records
picolog -o export          # journal export format
picolog -a                 # print binary-safe messages, escaped
```

`-p` accepts the names `emerg`, `alert`, `crit`, `err`, `warning`,
`notice`, `info`, `debug` or a number from 0 to 7. `LOGD_RUNTIME_DIR` in the
environment overrides the ring location; the test suite uses this to point
`picolog` at fixtures. See [LOGD.md](LOGD.md) for the daemon.

## pico-unit-lint

`pico-unit-lint` runs PID 1's own unit parser over a directory tree without
booting anything and reports what would be dropped. Run it on the unit tree
of a built image to find compatibility gaps before flashing:

```
pico-unit-lint [--warn-only] [--verbose] DIR...
```

Output is one line per finding, then a summary:

```
foo.service: 3 dropped: PrivateTmp DynamicUser ProtectSystem
bar.service: FAILED TO LOAD
pico-unit-lint: 120 units in tree, 14 degraded (31 directives dropped), 1 failed to load
```

Template units (`foo@.service`) are loaded under the instance name `lint`
and reported under the template's own name. The exit status is 0 with no
findings, 1 with findings (0 with `--warn-only`), and 2 if the tree could not
be scanned. `--verbose` also lists units that are honoured in full.

## Running the tests

The tests are registered with meson. Warnings are errors in this tree
(`werror=true`), so a test build that warns fails.

```
meson setup build
meson compile -C build
meson test -C build
meson test -C build test-unit-load     # one test
meson test -C build --verbose test-picoctl
```

Most tests are programs linked against the core library (`pico-init-core`)
and drive the manager directly, with a temporary unit tree and runtime
directory instead of the real `/run`. `main.c` is not part of that library;
`m0-link-and-symbols` runs the `pico-init` binary outside PID 1 (it prints a
message and exits 0) and checks that the expected symbols are linked.
`unit-lint` runs `pico-unit-lint` against a fixture tree and checks each
expected output line and the three exit statuses. `test-machine-id-setup`
enters a private user and mount namespace for its read-only `/etc` check and
skips that check where unprivileged namespaces are unavailable.

For hacking guidelines see [HACKING.md](HACKING.md).

## Running a unit by hand

When a service fails at start, reproduce it outside PID 1 to separate the
unit's configuration from the manager's behaviour.

Print the unit as PID 1 sees it, including drop-ins:

```
picoctl cat foo.service
```

Run the `ExecStart=` line from a shell with a minimal environment, as PID 1
inherits almost none:

```
env -i /usr/sbin/foo --option
```

Then compare with what the manager does. Read `Result`, `ExecMainCode` and
`ExecMainStatus` from `picoctl show`, and the service's own output with
`picolog -u foo.service`.

After editing a unit file, `picoctl daemon-reload` (or `SIGHUP` to PID 1)
re-reads unit files. `picoctl reset-failed foo.service` clears a failed
state before the next attempt.

If a service dies on start and `Restart=` loops, `NRestarts` counts the
restarts and `Result=start-limit-hit` means the start limit stopped them.

## When PID 1 freezes

PID 1 must not exit: the kernel would panic with "Attempted to kill init".
When PID 1 reaches a state it cannot continue from, `main()` calls
`freeze()`, which logs

```
pico-init[err]: <reason> -- freezing, as PID 1 must not return
```

and then sleeps forever in `pause()`. The reasons are:

| Reason | Meaning |
|--------|---------|
| could not mount the API filesystems | `mount_setup()` failed |
| could not create the manager | `manager_new()` failed |
| event loop failed | `manager_loop()` returned an error |
| event loop asked to exit, which PID 1 cannot do | `MANAGER_EXIT` as PID 1 |
| `reboot()` returned / `reboot(RB_POWER_OFF)` returned | the syscall failed |

The last line on the console is the reason. If the board has a hardware
watchdog and the manager had opened it, a freeze after `manager_free()`
leaves it armed and unfed, so the board resets once the watchdog timeout
expires; without a watchdog it stays frozen until power-cycled.

A failed boot transaction is not a freeze. If `manager_startup()` returns an
error, PID 1 logs `startup failed: <error>, entering the event loop anyway`
and keeps running, so there is a manager to inspect. Likewise a failed `/dev`
symlink setup, hostname setup, `/etc/fstab` line or machine-id step only logs
a warning.

If PID 1 appears hung rather than frozen (no new console output, control
verbs time out):

1. Run `picoctl list-units` and `picoctl is-system-running`. These read
   files and still work. Look for units stuck in `activating` and for
   units with a pending `Job`.
2. Run `picolog -n 100` for the most recent records, and `dmesg` for
   PID 1's records in the kernel ring.
3. Check `/run/pico-init/manager` for `NJobs` (jobs currently installed) to
   see whether the boot transaction is still in progress.
4. Check the kernel log for the root filesystem check and `/etc/fstab`
   results, which happen before the manager exists; skipped lines are in
   `/run/pico-init/fstab`.

Started from a shell, `pico-init` prints `not running as PID 1, exiting`
and does nothing else; it only acts as PID 1.

See [BOOT.md](BOOT.md) for the order of boot steps and which of them can
block, and [FAQ.md](FAQ.md) for common failure patterns.
