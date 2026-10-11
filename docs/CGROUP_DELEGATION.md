# Control Group APIs and Delegation

pico-init uses the cgroup v2 unified hierarchy only. Every service gets one
cgroup, and PID 1 is the sole writer of the hierarchy above it. A service
that wants to manage a subtree of its own, for example a container runtime
or a supervisor that spawns workers, sets `Delegate=` and takes over the
cgroup below it. This document describes the layout PID 1 creates, what
`Delegate=`, `DelegateSubgroup=` and `KillMode=` do, and what happens to
processes and cgroups that outlive their service. The unit settings are the
systemd ones.

## Layout

`/sys/fs/cgroup` is mounted as `cgroup2` with the `nsdelegate` option
during early boot. There is no v1 or hybrid mode.

```
/sys/fs/cgroup                      root; +cpu +memory enabled for children
`-- system.slice                    created at boot; +cpu +memory enabled
    |-- foo.service                 one cgroup per service unit
    |   |-- <DelegateSubgroup=>     main process (only with Delegate=)
    |   `-- .control                other processes (only with Delegate=)
    `-- bar.service
```

- The cgroup of a service is `/sys/fs/cgroup/system.slice/<unit name>`. It
  is created when the service is first started and kept, with its control
  files open, until the unit is freed.
- There is no `user.slice`, `machine.slice` or per-target slice: the path
  is always `system.slice/<unit name>`. `picoctl status` prints the cgroup
  path of a service.
- At boot, and only when running as PID 1, pico-init creates
  `system.slice` and writes `+cpu` and `+memory` to `cgroup.subtree_control`
  of the root and of `system.slice`. Only controllers listed in the
  directory's `cgroup.controllers` and not yet enabled are written. A
  controller the kernel refuses is logged and skipped; boot continues. No
  other controller (`io`, `pids`, `cpuset`) is enabled by PID 1.
- `system.slice` never holds processes itself, so enabling controllers in it
  does not run into the kernel's no-internal-process rule.
- If the cgroup of a service cannot be created or opened, the service is
  started anyway, without process supervision. The warning in the log reads
  `could not set up a cgroup ... starting without process supervision`.

Each child process attaches itself by writing its own PID to `cgroup.procs`
of the target directory after `fork()` and before `exec()`. If that write
fails, the child exits with the cgroup exit status and the start fails.

## Supervision

PID 1 watches `cgroup.events` of every service cgroup. A `populated 0` there
queues a cgroup-empty event for the unit; the event is re-verified when it
is dispatched, because notifications coalesce and the cgroup may have been
populated again. Emptiness is always read from the `populated` field, which
is recursive, never from `cgroup.procs`, which lists only the processes of
that one cgroup.

Killing a cgroup writes `1` to `cgroup.kill` where the file exists (Linux
5.14 and later), which is atomic and recursive. On older kernels pico-init
falls back to reading `cgroup.procs` and sending `SIGKILL` to each PID, up
to 16 passes, ignoring PID 1 and itself. The fallback is not atomic, and it
only visits the cgroup it is called on, not its children. A service with
`DelegateSubgroup=` on such a kernel is therefore not fully covered by the
fallback; the kernel does offer `cgroup.kill` on anything recent enough to
run a modern container runtime.

## Delegate=

`Delegate=` is parsed as in systemd: a boolean, a list of controller names,
or an empty assignment.

| Value             | Effect                                                    |
|-------------------|-----------------------------------------------------------|
| `yes`             | delegation on, controller set reported as all five names  |
| `no`              | delegation off                                            |
| `cpu memory ...`  | delegation on, names recorded and reported                |
| empty             | delegation on with an empty controller set                |

The names pico-init knows are `cpu`, `cpuset`, `io`, `memory` and `pids`;
others (for example `bpf-*`) are ignored. A value with characters outside
lower-case letters, digits, `-`, `_` and space is rejected with a warning.

`DelegateControllers=` is not a unit file setting in pico-init. The
controller set from `Delegate=` is only reported by `picoctl show` under
`Delegate=` and `DelegateControllers=`. PID 1 never writes
`cgroup.subtree_control` of a service cgroup, so the controllers a delegate
can use are the ones enabled in `system.slice` (`cpu` and `memory`, if the
kernel offers them), and the service enables them for its own children
itself:

```sh
echo +memory > /sys/fs/cgroup/system.slice/foo.service/cgroup.subtree_control
```

Without `Delegate=` the cgroup of a service belongs to PID 1. Services must
not create children in it or move processes out of it.

### Ownership

When `Delegate=` is on and the service has a `User=` other than root, PID 1
changes the owner and group of the cgroup directory and of `cgroup.procs`,
`cgroup.subtree_control` and `cgroup.threads` in it to the service's user
and group. This happens in the parent before every spawn of the unit's
commands (`ExecStartPre=`, `ExecStart=` and so on), so the files are owned
correctly by the time the process runs. A failure is logged as
`Delegate=: cannot hand ... to uid ...` and the service is still started.
For root services nothing is changed.

### DelegateSubgroup=

The kernel does not allow a cgroup to hold processes and also enable
controllers for its children. With `DelegateSubgroup=name` PID 1 therefore
keeps the unit cgroup itself free of processes:

- the main process (`ExecStart=`) is placed in `<unit cgroup>/<name>`;
- every other command the manager starts for the unit (`ExecStartPre=`,
  `ExecStop=`, `ExecStopPost=`) is placed in
  `<unit cgroup>/.control`.

Both directories are created with mode 0755 if missing. The main
process's subgroup is handed to `User=` like the unit cgroup. If a subgroup
cannot be created, a warning is logged and the process stays in the unit
cgroup. The setting only has an effect together with `Delegate=`.

A valid name is a single path component of at most 64 characters, not
starting with `.` or `_`, not starting with `cgroup.`, and without `/`.
Anything else is ignored with a warning. An empty assignment clears the
setting.

When listing the processes of a unit (for `PIDFile=` validation and for the
stop signal), PID 1 reads `cgroup.procs` of the unit cgroup and of the
`DelegateSubgroup=` directory. Processes in `.control` or in cgroups the
service created itself are not listed there; they are still reached by
`cgroup.kill` because it is recursive.

## Cleanup and stale cgroups

### Child cgroups

When a unit is freed (at shutdown), PID 1
removes its cgroup directory and every empty cgroup below it, depth first,
with a nesting limit of 32. A cgroup that still holds processes cannot be
removed; removal never kills anything. Child cgroups a delegated service
created are not removed when the service merely stops or restarts; they are
removed with the unit cgroup.

### Reset of a stale cgroup

When the cgroup of a unit is created and the directory already exists, PID 1
checks
`cgroup.events`. If the cgroup is empty (`populated 0`), it removes all
descendants and switches off every controller listed in its
`cgroup.subtree_control`. Otherwise a new main process could not be added,
since a cgroup that enables controllers for children cannot hold processes.
A cgroup that still has members is not touched.

### Leftover processes before a start

Before the first command of a start (`ExecStartPre=`, and `ExecStart=`),
PID 1 checks the cgroup. If it is populated and `KillMode=` is
`control-group` or `mixed`, the remaining processes are killed with
`cgroup.kill` and a warning is logged. With `KillMode=process` or `none`
they are left alone and a warning is logged.

## KillMode=

| `KillMode=`     | stop                                      | main process exits on its own |
|-----------------|-------------------------------------------|-------------------------------|
| `control-group` | `KillSignal=` to main, control and all other cgroup members | rest of the cgroup killed |
| `mixed`         | `KillSignal=` to main and control process only, then `SIGKILL` to the whole cgroup once the main process is gone (with `SendSIGKILL=yes`) | rest of the cgroup killed |
| `process`       | `KillSignal=` to main and control process | cgroup left alone |
| `none`          | no signal                                 | cgroup left alone |

Details:

- `SendSIGHUP=yes` adds `SIGHUP` after the stop signal for the main and
  control process.
- `SendSIGKILL=yes` (the default) makes the stop timeout escalate: with
  `control-group` or `mixed` the whole cgroup is killed; with `process` the
  main and control PIDs are sent `SIGKILL`. With `KillMode=none` or
  `SendSIGKILL=no` nothing is killed on timeout, the unit moves on and the
  processes are left running.
- When the main process exits while the cgroup is still populated, a
  `control-group` or `mixed` service has the rest killed: with `cgroup.kill`
  if `SendSIGKILL=yes`, otherwise by sending `KillSignal=` to each member.
  `RemainAfterExit=yes` suppresses this; the processes stay and a message is
  logged.
- For `process` and `none` the stop does not wait for the cgroup to become
  empty.

The default is `control-group`.

## Orphaned cgroups

If a unit is freed while its cgroup is still populated (typically because
of `KillMode=process` or `none`), the cgroup is not removed. PID 1 stops
watching it, stores it on an orphan list and logs
`processes are still running in it, leaving the cgroup until they exit`. A
timer then checks every 30 seconds whether the cgroup has become empty. Once
it has, the cgroup and its empty children are removed and
`orphaned cgroup is empty, removing it` is logged. This is the only
cleanup of such a cgroup; nothing signals its processes.

## Shutdown sweep

On reboot and power-off the manager loop ends, units are freed, and the
manager is freed. Freeing a unit removes its cgroup, or puts a populated one
on the orphan list; freeing the manager drops that list with a last removal
attempt and no waiting. Then, before the final `sync()`:

1. `kill(-1, SIGTERM)` followed by `SIGCONT` to every process PID 1 may
   signal;
2. up to 5 seconds (50 checks, 100 ms apart) while reaping, for all of them
   to exit;
3. `kill(-1, SIGKILL)` for what is left, with a warning
   `processes ignored SIGTERM, sending SIGKILL`.

This sweep does not look at cgroups. It is what ends processes that
`KillMode=process` or `none` units left behind. A service that needs a clean
shutdown of such processes has to stop them in `ExecStop=`.

## Rules for service authors

- Set `Delegate=` only for services that really create cgroups. It is the
  signal that PID 1 hands over ownership to a non-root `User=`.
- Enable the controllers you need in your own `cgroup.subtree_control`;
  only `cpu` and `memory` are available from the parent, and only if the
  kernel offers them.
- If you want controllers on a subtree of the unit cgroup, use
  `DelegateSubgroup=` so the unit cgroup itself holds no process, or move
  your own processes into a child before writing `cgroup.subtree_control`.
- Do not move processes in or out of the unit cgroup from the outside, and
  do not touch cgroups of other units.
- Use `cgroup.kill` or the stop mechanism instead of walking PIDs when you
  need to end a subtree.

## Differences from systemd

- One flat slice, `system.slice`; no slice hierarchy.
- `DelegateControllers=` is not accepted as a setting, and the controller
  set of `Delegate=` is only reported, not applied.
- Only `cpu` and `memory` are enabled by PID 1, in the root and in
  `system.slice`.

See also [ARCHITECTURE.md](ARCHITECTURE.md) and [../README.md](../README.md).
