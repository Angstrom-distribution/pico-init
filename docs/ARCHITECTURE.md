# Architecture

Pico-init is a PID 1 that reads systemd unit files, plus a small set of
companion programs that replace the parts of systemd an embedded image
usually needs: a control tool, a network daemon, a log daemon, a device
hotplug daemon, tmpfiles handling and ABI-compatible `libsystemd.so.0` and
`libudev.so.1`. PID 1 is a single-threaded program built around an
`sd_event` loop. Everything else is either a client of PID 1 or an ordinary
service that PID 1 supervises. This document describes the pieces, how they
talk to each other and the data structures inside PID 1.

## Components

| Program        | Installed in | Role                                       |
|----------------|--------------|--------------------------------------------|
| `pico-init`    | `sbin`       | PID 1                                      |
| `picoctl`      | `sbin`       | `systemctl` equivalent, also `reboot` etc. |
| `netd`         | `sbin`       | Network daemon, replaces networkd/timesyncd|
| `netctl`       | `bin`        | `networkctl` equivalent, client of `netd`  |
| `logd`         | `sbin`       | Log daemon, replaces journald              |
| `picolog`      | `bin`        | `journalctl` equivalent, reads the log ring|
| `devd`         | `sbin`       | Device hotplug daemon, replaces udevd      |
| `pico-tmpfiles`| `bin`        | `systemd-tmpfiles --create/--clean/--remove`|
| `pico-unit-lint`| `bin`       | Reports directives PID 1 would drop        |
| `libsystemd.so.0` | `libdir`  | Compatibility library, systemd's ABI       |
| `libudev.so.1` | `libdir`     | Compatibility library, thin layer over the above |

Only `pico-init` is PID 1. `netd`, `logd`, `devd` and `pico-tmpfiles` are
units: each ships a `.service` file under `/usr/lib/systemd/system` and is
started, ordered and restarted like any other service. A crash in one of
them costs a unit restart, not the machine. `netd` and `devd` do not talk to
PID 1 at all. `logd` receives its sockets from PID 1 (see
[Logging](#logging)). The service files carry `WantedBy=default.target`
(`pico-tmpfiles.service` uses `sysinit.target`, `logd.socket` uses
`sockets.target`); whether they are enabled is decided by the preset files,
see [PRESET.md](PRESET.md).

The per-daemon documents are [NETD.md](NETD.md), [LOGD.md](LOGD.md) and
[DEVD.md](DEVD.md); [COMPATIBILITY_LIBRARIES.md](COMPATIBILITY_LIBRARIES.md)
covers the two shared libraries.

The code is organised as static libraries that the tests and the programs
both link: `pico-init-core` (everything in PID 1 except `main.c`),
`netd-core`, `devd-core`, `tmpfiles-core`, `logd-core`. The daemons link
`pico-init-core` only for `util.c` (logging), `timer.c` and `signal.c`.
`picoctl` and `pico-unit-lint` link all of `pico-init-core`, so they use the
same unit parser and the same enablement code as PID 1.

## Boot sequence in PID 1

`main()` returns only if it is not PID 1. When it is, it does the following
in order, before any unit exists:

1. `mount_setup()` mounts `/proc`, `/sys`, `/dev` (devtmpfs, if not already
   mounted), `/dev/pts`, `/dev/shm`, `/run`, the cgroup2 hierarchy at
   `/sys/fs/cgroup` and configfs at `/sys/kernel/config`.
2. `dev_setup()` creates the `/dev/fd` and `/dev/std{in,out,err}` links,
   `hostname_setup()` applies `/etc/hostname`, and the system clock is moved
   forward from the persisted timestamp (`clock_persist_restore()`).
3. `sysctl_setup()` runs, then log output is redirected to `/dev/kmsg`.
   `logd` backfills these lines from the kernel ring when it starts.
4. The console greeting is printed, `/etc/fstab` is read, the root
   filesystem is checked (a reboot may be requested here), and the remaining
   fstab entries are mounted.
5. Swap partitions are discovered from the partition table, unless fstab
   names swap.
6. `machine_id_setup()` decides whether this is a first boot.
7. `manager_new()` creates the manager and its event loop.
   `manager_startup()` loads units and queues the start job for
   `default.target`. A failed startup is logged and the event loop is
   entered anyway, so a board that cannot reach its default target still has
   a console and a working `picoctl`.
8. `manager_loop()` runs until a shutdown objective is set. Reboot and
   poweroff objectives kill the remaining processes (SIGTERM, up to five
   seconds, then SIGKILL), save the clock, `sync()` and call `reboot(2)`.
   PID 1 never returns: any failure path ends in `freeze()`.

`manager_startup()` itself proceeds as follows:

1. Arm the hardware watchdog, then create the state directory, the control
   socket and the notify socket. None of the four is fatal when it fails.
2. Load every unit file in the search path and drain the load queue.
3. Read `.wants/` and `.requires/` directories and turn them into
   dependency edges.
4. On first boot only, apply preset files. The result is stored as real
   symlinks, so later boots read only the symlinks.
5. Order every target after the units it wants or requires, and every
   service after `sockets.target`, unless the unit files already order the
   two.
6. Log ordering cycles anywhere in the unit graph.
7. Load `default.target` (or the target passed in) and queue a start job
   for it.

Unit files are looked up in `/etc/systemd/system`, then
`/usr/lib/systemd/system`. A unit file that is a symlink to a differently
named unit becomes an alias of that unit; a symlink to a device node (or an
empty file) yields a masked unit. An instance such as `getty@tty1.service`
with no file of its own loads through its template. Enablement is read from
`<name>.wants/` and `<name>.requires/` directories in the same search path.

## Units

Every unit embeds a `Unit` as its first member and supplies a `UnitVTable`
with `init`, `done`, `start`, `stop` and `active_state`. Three types exist:

| Suffix     | Source        | State machine                                  |
|------------|---------------|------------------------------------------------|
| `.service` | `service.c`, `service-exec.c` | A process, optionally with control processes |
| `.target`  | `target.c`    | `DEAD`, `ACTIVE`; no process                   |
| `.socket`  | `socket.c`    | `DEAD`, `LISTENING`, `RUNNING`, `FAILED`       |

Any other suffix (`.mount`, `.timer`, `.device` and so on) is not a unit
type. A dependency on such a name is recorded as a degradation, not an
error. Which directives are honoured and which are dropped is documented in
[INCOMPATIBILITIES.md](INCOMPATIBILITIES.md).

Each unit has a load state (`stub`, `loaded`, `error`, `masked`) and an
active state (`inactive`, `activating`, `active`, `deactivating`, `failed`).
The dependency graph uses six edge types: `Requires=`, `Wants=`, `Before=`,
`After=`, `Conflicts=` and the inverse of `Conflicts=`. `Before=` and
`After=` are stored in both directions. The unit table is a flat array.

Loading is queued: a unit is created, put on the load queue and the queue is
drained iteratively, so a long dependency chain or a cycle cannot recurse.
Directives the parser drops are recorded per unit and published as
`Degraded-Directives=`; `pico-unit-lint` runs the same parser over a unit
tree and prints that record without booting anything:

```
$ pico-unit-lint /usr/lib/systemd/system
```

### Services

A service is `Type=simple`, `exec`, `oneshot`, `notify` or `forking`. The
types differ in when the start job completes: `simple` when the process is
forked, `exec` once `execve()` has succeeded (reported over a pipe that the
child closes on exec), `notify` on `READY=1`, `oneshot` when the process has
exited successfully, `forking` when the parent has exited and the main pid
has been found through `PIDFile=` or as the only process left in the
cgroup. A service with `Restart=` set goes through an `auto-restart` state
and a start-rate limit applies.

PID 1 forks the process in `service-exec.c`. The environment, credentials,
file descriptors and the cgroup are prepared in the parent where possible,
because the region between `fork()` and `execve()` may not allocate. A
setup failure in the child is reported through an exit code in the 200 range
(the numbers of `systemd.exec(5)`) and maps to a resources failure.

Service stdout and stderr are connected to `logd` through
`/run/logd/stdout`, except that they follow stdin when that is a tty or a
socket and `StandardOutput=` is not set. If the socket cannot be created,
output goes to the console.

### Sockets

A `.socket` unit supports `ListenStream=` and `ListenDatagram=` for a path
or a port, `Service=`, `Accept=`, `MaxConnections=`, `SocketMode=` and
`Backlog=`. PID 1
binds the sockets and watches them with `sd_event` io sources. On a wakeup
it queues a start job for the paired service. With `Accept=no` PID 1 never
`accept()`s: the pending connection stays in the backlog and the service
inherits the listening sockets through `LISTEN_FDS`/`LISTEN_PID`. With
`Accept=yes` PID 1 accepts one connection per wakeup and starts an instance
`prefix@<nr>-<local>-<remote>.service` (for `AF_UNIX`, `<nr>-<pid>-<uid>`
of the peer), which is dropped from the unit table again when
it has finished. The socket stays in `LISTENING` throughout. See
[DAEMON_SOCKET_ACTIVATION.md](DAEMON_SOCKET_ACTIVATION.md).

### Targets

A target has no process. Starting one completes when everything it pulls in
has been started. Because PID 1 adds an `After=` on each unit a target wants
or requires, reaching `default.target` means the whole boot transaction has
finished. When that job finishes PID 1 logs one summary line with the number
of units that carry a degradation record.

## Jobs and transactions

A job is a start, stop or restart request for one unit. A request first
becomes a transaction: the requested job is the anchor, and
`Requires=` and `Wants=` pull in start jobs for dependencies,
`Requires=` in reverse pulls in stop jobs, and `Conflicts=` pulls in stops.
Jobs for the same unit merge using a fixed table of job types. A job
reached through `Requires=` matters to the anchor; one reached only through
`Wants=` does not, and only jobs that do not matter may be dropped to break
a cycle.

`transaction_activate()` then drops redundant jobs, checks the ordering for
cycles (breaking them by removing a job that does not matter, or failing
with `-ELOOP`), and installs the jobs onto the run queue in a topological
order. Once installed, a job is attached to its unit and is the manager's
responsibility. A job runs when every job that must precede it has finished;
a stop job always precedes, whatever direction the ordering edge points.
Unit state changes call `unit_notify()`, which completes or fails the job
the unit was waiting for. A job result is one of `done`, `failed`,
`canceled`, `timeout` or `dependency`.

A restart job runs as a stop and is converted to a start only when the stop
finishes, so ordering is preserved. A start job whose unit has an unmet
`ConditionPathExists=` or `ConditionPathIsDirectory=` finishes as done and
leaves the unit inactive.

Not implemented: job modes, `isolate`, job timeouts, `Requisite=`,
`BindsTo=`, `OnFailure=`, and carrying jobs across a reload.

## The event loop

The manager owns one `sd_event` created with `sd_event_new()`, from the same
`sd-event` implementation that is exported in `libsystemd.so.0`. The loop
is `while (objective == RUNNING) sd_event_run()`. Sources and their
priorities (lower is dispatched first):

| Priority offset | Source                                              |
|-----------------|-----------------------------------------------------|
| -20             | Hardware watchdog feed                              |
| -10             | Per-service `cgroup.events` (verify and queue only) |
| -5              | `sd_notify()` datagrams; `Type=exec` confirmation   |
| -4              | `signalfd` (SIGCHLD reaping and attribution)        |
| -3              | Socket unit io sources; control socket              |
| -2              | cgroup-empty queue                                  |
| 0               | Timers (timeouts, `RestartSec=`, clock save)        |
| idle + 1        | Job run queue                                       |
| idle + 2        | Shutdown check                                      |
| idle + 3        | Reaping of finished `Accept=yes` instances          |

The offsets are relative to `SD_EVENT_PRIORITY_NORMAL`. The order is
what makes exit status handling correct. A cgroup becoming empty carries no
exit status, and the process that empties it need not be the service's main
process, so cgroup-empty must never be acted on before the SIGCHLD that
accompanies it. A service's final `sd_notify()` message must be applied
before the SIGCHLD that clears its main pid. The run queue is a deferred
source that is armed whenever a job becomes runnable.

Source callbacks return 0 in all but fatal cases, because `sd_event`
disables a source whose callback fails and PID 1 cannot afford to lose its
signal handling.

SIGCHLD is handled by peeking with `waitid(WNOWAIT)`, attributing the pid
to a unit while it still cannot be recycled, and only then reaping it.
Processes that belong to no unit (PID 1 inherits every orphan) are reaped
and ignored. Signals handled:

| Signal                | Effect                                        |
|-----------------------|-----------------------------------------------|
| SIGCHLD               | Reap and attribute                            |
| SIGHUP                | Reload all loaded units from their fragments  |
| SIGINT                | Reboot (Ctrl-Alt-Del is routed here)          |
| SIGRTMIN+3, SIGRTMIN+4| Poweroff                                      |
| SIGTERM               | Ignored when PID 1 (logged)                   |

A shutdown request does not leave the loop at once. It cancels queued start
and restart jobs, queues a stop job for every unit that is not inactive and
records a pending objective with a 30 second deadline. The loop adopts the
objective when all jobs have finished or the deadline passes. The watchdog
feed keeps running across the drain and the watchdog device is left armed
when PID 1 exits.

## State files and the control socket

`picoctl` reads state from files and sends commands over one socket. Both
live in `/run/pico-init`.

### State files

PID 1 writes one `Property=value` file per unit to
`/run/pico-init/units/<unit>` and one file `/run/pico-init/manager`. Writes
go through a temporary file and `rename()`, so a reader never sees a partial
file, and they happen at the points where state changes: `unit_notify()` for
unit state, `job_install()` and `job_finish_full()` for job state, and
`manager-notify.c` when an `sd_notify()` message changes something. The
files reflect the last transition even when the event loop is wedged, which
is when a query that needs the loop would hang. An alias is published as a
symlink to the unit's file. If `/run` is not writable, `picoctl` loses its
read verbs; the boot is not affected.

Unit file properties:

| Property                    | Meaning                                       |
|-----------------------------|-----------------------------------------------|
| `ActiveState`, `SubState`   | Active state and service/socket/target state  |
| `LoadState`                 | `stub`, `loaded`, `error` or `masked`         |
| `FragmentPath`, `Description` | From the unit file                          |
| `UnitFileState`             | `static`, `enabled` or `disabled`             |
| `MainPID`, `Result`, `ExecMainCode`, `ExecMainStatus`, `NRestarts` | Service process and result |
| `Job`                       | Installed job as `<id> <type>`, empty if none |
| `Delegate`, `DelegateControllers`, `DelegateSubgroup` | Cgroup delegation   |
| `KillMode`, `KillSignal`, `SendSIGKILL`, `SendSIGHUP` | Services only      |
| `Degraded-Directives`       | Directives the parser dropped                 |
| `NotifyReady`, `StatusText`, `StatusErrno` | From `sd_notify()`, services only |

Manager file properties: `Objective`, `DefaultTarget`, `NUnits`, `NJobs`
(jobs currently installed) and `NInstalledJobs` (installs since boot). The
last two are the raw inputs of a boot progress fraction; PID 1 does not
compute one. The fstab pass writes its outcome to `/run/pico-init/fstab`.

### Control socket

`/run/pico-init/control` is an `AF_UNIX` `SOCK_SEQPACKET` socket, mode 0600,
owned and bound by PID 1 itself (it cannot be socket-activated). Each
connection carries one request line and receives one reply line:

```
PICO1 start dropbear.service
PICO1 restart dropbear.service --no-block
PICO1 daemon-reload
```

| Verb            | Action                                                   |
|-----------------|----------------------------------------------------------|
| `start`, `stop`, `restart` | Queue a job through `manager_add_job()`       |
| `reset-failed`  | Clear a failed unit directly, no job                     |
| `daemon-reload` | Call `manager_reload()`, the same as SIGHUP              |

Replies are `ok ...` or `err <reason>`. For job verbs the reply is held
until the job finishes, so `picoctl`'s exit status is the job's result;
`--no-block` replies `ok queued` at once. Pending replies are keyed by job
id, never by job pointer. PID 1 never blocks on a client: connections are
non-blocking, at most 16 are tracked and further ones are rejected, and
requests are parsed out of a fixed 512-byte buffer. During a pending
shutdown, `start` and `restart` are refused.

Reboot and poweroff do not use the socket. `picoctl reboot` sends SIGINT to
PID 1, `poweroff` and `halt` send SIGRTMIN+4 and SIGRTMIN+3. When invoked
as `reboot`, `poweroff`, `halt` or `shutdown`, `picoctl` behaves as that
command.

### picoctl

`picoctl` is the `systemctl` equivalent. Each verb takes its data from one
of these sources:

| Verbs | Source of truth |
|-------|-----------------|
| `status`, `show`, `list-units`, `is-active`, `is-failed`, `is-system-running`, `cat`, `list-unit-files` | State files and unit files; no IPC |
| `enable`, `disable`, `reenable`, `is-enabled`, `preset`, `mask`, `unmask` | The `.wants`/`.requires` symlinks and preset files, using the same code as boot |
| `start`, `stop`, `restart`, `try-restart`, `reload-or-restart`, `reset-failed`, `daemon-reload` | Control socket |
| `kill` | `kill(2)` on `MainPID` from the state file, or on every pid in the unit's `cgroup.procs` |
| `reboot`, `poweroff`, `halt` | Signal to PID 1, see above |
| `reload` | Always fails: `ExecReload=` and reload jobs do not exist |

`picoctl status` also prints the last log lines of the unit by reading
`logd`'s ring directly. `--root DIR` prefixes every path it touches, which
is how the symlink verbs are tested. Verbs without a backing here (for
example `isolate`, `list-dependencies`, `edit`) report `Unknown command
verb`.

## Cgroups

Supervision uses the unified (v2) hierarchy only. `mount_setup()` mounts it
at `/sys/fs/cgroup` with `nsdelegate`. PID 1 enables `+cpu +memory` in the
root and in `system.slice` at startup, best effort.

Each service gets one cgroup, `/sys/fs/cgroup/system.slice/<unit>`, created
when it first starts. The child process attaches itself by writing to
`cgroup.procs` between `fork()` and `execve()`. `cgroup.events` is watched
by an `sd_event` io source, so service exit needs no polling: a
`populated 0` notification is verified, queued and delivered after the
SIGCHLDs of the same batch, and cancelled again if the cgroup has been
populated in the meantime. Arming the watch is followed by one immediate
read, because an already-empty cgroup produces no event.

Killing a unit's processes writes `1` to `cgroup.kill` where the kernel has
it (Linux 5.14 and later), and otherwise falls back to a bounded
read-`cgroup.procs`-and-SIGKILL loop. `KillMode=control-group`, `mixed`,
`process` and `none` are implemented. A cgroup whose unit has gone while
processes remained (for example under `KillMode=process`) is adopted by the
manager and removed by a slow timer after it empties.

`Delegate=yes` hands the cgroup to the service's `User=`; with
`DelegateSubgroup=` the main process goes into that subgroup and every
other process of the unit into `.control`. Details are in
[CGROUP_DELEGATION.md](CGROUP_DELEGATION.md).

The hardware watchdog is separate from cgroups: PID 1 opens
`/dev/watchdog0` (or `/dev/watchdog`) and feeds it from the highest
priority source in the loop. There is no per-service watchdog.

## Logging

PID 1 writes its own log output to `/dev/kmsg`. `logd` is the log daemon and
is itself socket-activated by PID 1: `logd.socket` holds
`/run/logd/stdout` and `/dev/log`, so a `logd` crash neither loses queued
output nor disconnects a service's stdout. `logd` also reads `/dev/kmsg`,
which gives it the whole kernel ring and everything PID 1 logged before it
started. Records are kept in journald's plain-text export format in a
two-file ring in `/run/logd`, 2 MiB by default; the binary journal format is
not implemented. Records are attributed from kernel-verified credentials and
the sender's cgroup. `picolog` reads the ring and can emit
`-o export` for conversion on a host. See [LOGD.md](LOGD.md).

## Networking, devices and tmpfiles

`netd` is a plain `Type=simple` service with its own epoll loop. It reads
`.network` files, runs the DHCPv4 client and server, an SNTP client and
LLDP, and talks to the kernel over rtnetlink. It publishes
`/run/netd/links/<ifindex>` and `/run/netd/leases/<ifindex>`. `netctl`
reads those files, sysfs and rtnetlink directly, so `status` works without
`netd` running; only `reload` needs it, and sends it SIGHUP.
`netd.service` is ordered `Before=network.target`; `network.target` is a
passive target and there is no `network-online.target`. See
[NETD.md](NETD.md).

`devd` listens for kernel uevents and coldplugs from `/sys`. It maintains
the `/dev/disk/by-*` links, mounts removable media, runs `udev` rules files
from `/usr/lib/udev/rules.d` (a supported subset; a rule it only partly
understands is skipped whole), loads modules from `MODALIAS`, and writes
input device classification to `/run/udev/data` where the compatibility
`libsystemd.so.0` reads it back. A restarted `devd` re-derives everything
from `/sys`. See [DEVD.md](DEVD.md).

`pico-tmpfiles` is a `Type=oneshot` that applies `tmpfiles.d` snippets
(`--create --remove --boot`) before `sysinit.target`. Line types it does not
implement are logged and skipped.

## Compatibility libraries

`libsystemd.so.0` carries systemd's SONAME, symbol versions (from the
`libsystemd-v259.sym` file vendored from the systemd v259 tag) and
`libsystemd.pc`/`systemd.pc`, so recipes built for systemd link and run
unchanged. It is built from the same `sd-event`, `sd-daemon` and `sd-id128`
code that PID 1 uses, an `sd-journal` over `logd`, `sd-login` cgroup, unit
and slice getters, `sd-hwdb`, `sd-device` and `sd-network` over `/sys`,
`/run/udev/data` and `/run/netd`, and `sd-bus`. The bus has no wire
protocol: the validation, path and error helpers work, and every call that
would need a connection fails. `libudev.so.1` is a thin layer over
`sd_device`, as upstream's is, and links `libsystemd.so.0`. Only symbols
named in the version scripts are exported.
[COMPATIBILITY_LIBRARIES.md](COMPATIBILITY_LIBRARIES.md) lists what is real,
what is a stub and what is absent.

## Source layout

| Path                    | Content                                           |
|-------------------------|---------------------------------------------------|
| `src/main.c`            | PID 1 entry and shutdown                          |
| `src/manager*.c`        | Unit table, loop, startup, shutdown, state, control socket, notify, watchdog |
| `src/unit*.c`           | Names, loading, parsing, dependencies, enablement, reload |
| `src/service*.c`, `socket.c`, `target.c` | Unit types                       |
| `src/job.c`             | Jobs and transactions                             |
| `src/cgroups-v2.c`      | Cgroup layer; independent of `Unit` and `Manager` |
| `src/picoctl.c`         | `picoctl`                                         |
| `src/netd/`, `src/logd/`, `src/devd/`, `src/tmpfiles/` | The companion programs |
| `src/compat/libsystemd/`, `src/compat/libudev/` | The compatibility libraries |

Further reading: [BOOT.md](BOOT.md) for the boot order in detail,
[HACKING.md](HACKING.md) for building and testing, and
[../README.md](../README.md) for an overview.
