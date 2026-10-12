# Incompatibilities with systemd

Pico-init reads systemd unit files unmodified, but it implements a small
subset of what they can say. This document is for the author of a unit file
or the maintainer of a package that ships one: it lists the unit types
pico-init has, every directive it honours, what happens to everything else,
and the places where a directive it does honour behaves differently from
systemd. The directive tables are taken from the handler table in
`src/unit-parse.c`; a directive that is not in them is not implemented.

## Unit types

| Type       | Supported | Notes                                             |
|------------|-----------|---------------------------------------------------|
| `.service` | yes       | Templates and instances included.                 |
| `.socket`  | yes       | `Accept=yes` and `Accept=no`.                     |
| `.target`  | yes       | `[Unit]` and `[Install]` only.                    |
| `.mount`, `.swap`, `.timer`, `.path`, `.device`, `.scope`, `.slice`, `.automount` | no | Not loaded. |

A file with an unsupported suffix is never loaded as a unit. `/etc/fstab` is
handled by PID 1 itself at boot instead of through generated mount units.

A dependency on a unit of an unsupported type is not followed. A valid
unit name with such a suffix is logged as ignored and recorded as degraded
(see below), for example as `Wants=.mount`.

A `[Service]` directive in a non-service unit, or a `[Socket]` directive in a
non-socket unit, is logged as misplaced and ignored. It is not recorded as
degraded.

Drop-in directories (`foo.service.d/*.conf`) are not read. A unit is exactly
one fragment, found by name in `/etc/systemd/system` and then
`/usr/lib/systemd/system`; the first directory that has the name decides.
Overrides have to replace the whole file.

Masking works as in systemd: a symlink to `/dev/null` (or any device node)
or an empty regular file masks the unit and shadows a fragment in a later
directory. A symlink to a differently named unit of the same type is an
alias. An instance without a fragment of its own, such as
`serial-getty@ttyUSB0.service`, loads through its template.

## How an unsupported directive is handled

An unknown directive does not stop a unit from loading. The parser drops it
and adds its name, exactly as written and without the section, to the unit's
degradation record. The record is deduplicated and kept in order of
appearance. A directive is also "unknown" when it is spelled correctly but in
a section where pico-init has no handler for it, and every directive inside
an unrecognised section (`[Timer]`, `[Mount]`, `[Path]`) is recorded the
same way.

The record is visible in three places:

- PID 1 logs one warning per unit when the unit is loaded:
  `<unit>: <n> directives not implemented by pico-init dropped: <list>`.
  The `file:line` message for an unknown directive is at debug level; a
  known directive that degrades (such as `Type=dbus`) also logs its own
  warning.
- After the boot settles, PID 1 logs one summary line with the number of
  degraded units and dropped directives, or that none were degraded.
- `picoctl show <unit>` prints the record as a space-separated
  `Degraded-Directives=` line, empty when every directive was honoured.

```
$ picoctl show foo.service | grep Degraded
Degraded-Directives=Type=dbus BusName ProtectSystem
```

The same parser is available at build time as `pico-unit-lint`, which loads
every unit under the given directories without booting anything:

```sh
pico-unit-lint [--warn-only] [--verbose] DIR...
```

It prints one line per finding and a summary:

```
foo.service: 2 dropped: ProtectSystem PrivateTmp
bar.service: FAILED TO LOAD
pico-unit-lint: 31 units in tree, 1 degraded (2 directives dropped), 1 failed to load
```

Templates are loaded as `foo@lint.service` and reported under the template's
own name. `--verbose` also lists units with nothing dropped. The exit status
is 0 with no findings, 1 with any finding unless `--warn-only` is given, and
2 when a directory could not be scanned or the command line is wrong. A
masked unit does not load and is reported as `FAILED TO LOAD`.

A drop is silent in one respect that matters: a dropped directive is treated
as absent. An unrecognised `Condition*=` or `Assert*=` line is not
evaluated, so the unit starts as if the condition held. A dropped sandboxing
or resource-control directive leaves the service unconfined.

## Directives that are honoured

### [Unit]

| Directive                   | Notes                                           |
|-----------------------------|-------------------------------------------------|
| `Description=`              | Specifiers expanded, `%I` included.             |
| `Requires=`, `Wants=`       | Whitespace-separated names.                     |
| `Before=`, `After=`         |                                                 |
| `Conflicts=`                |                                                 |
| `ConditionPathExists=`      | See [Conditions](#conditions).                  |
| `ConditionPathIsDirectory=` | See [Conditions](#conditions).                  |

Dependency tokens are expanded with `%n %N %p %i` per token. `%I` is not
available in dependency names. A token that is not a valid unit name is
logged and skipped.

### [Service]

| Directive               | Values and notes                                |
|-------------------------|-------------------------------------------------|
| `Type=`                 | `simple`, `exec`, `oneshot`, `forking`, `notify`; `dbus`, `idle` and `notify-reload` degrade. |
| `ExecStart=`            | One command. A second line replaces the first.  |
| `ExecStartPre=`         | List; each line appends, an empty value resets. |
| `ExecCondition=`        | List.                                           |
| `ExecStop=`             | List.                                           |
| `ExecStopPost=`         | List.                                           |
| `ExecReload=`           | Stored, recorded as degraded, never run.        |
| `Environment=`          | Quoting and C escapes as in `ExecStart=`; accumulates. |
| `EnvironmentFile=`      | Absolute path, optional leading `-`; accumulates. Values are unquoted as by the shell; a file over 4 MiB is refused. |
| `User=`, `Group=`       | Name or numeric id, resolved at each start.     |
| `SupplementaryGroups=`  | List; accumulates.                              |
| `PIDFile=`              | Relative paths are taken under `/run/`.         |
| `GuessMainPID=`         | Boolean.                                        |
| `Restart=`              | `no`, `on-success`, `on-failure`, `on-abnormal`, `on-watchdog`, `on-abort`, `always`. |
| `RestartSec=`           | Time span.                                      |
| `RemainAfterExit=`      | Boolean.                                        |
| `TimeoutStartSec=`      | Time span or `infinity`.                        |
| `TimeoutStopSec=`       | Time span or `infinity`.                        |
| `StandardInput=`        | `socket`, `tty`, `tty-force`, `tty-fail`.       |
| `StandardOutput=`, `StandardError=` | `inherit`, `journal`, `syslog`, `null`, and the `+console` spellings. |
| `TTYPath=`              | Absolute path; full specifiers.                 |
| `Delegate=`             | Boolean or controller list.                     |
| `DelegateSubgroup=`     | Valid cgroup name.                              |
| `KillMode=`             | `control-group`, `mixed`, `process`, `none`.    |
| `KillSignal=`           | Signal name, with or without `SIG`, or number.  |
| `SendSIGHUP=`           | Boolean.                                        |
| `SendSIGKILL=`          | Boolean.                                        |

### [Socket]

| Directive          | Values and notes                                        |
|--------------------|---------------------------------------------------------|
| `ListenStream=`    | An absolute path (AF_UNIX) or a bare port number.       |
| `ListenDatagram=`  | Same.                                                   |
| `Service=`         | A `.service` name. Not allowed with `Accept=yes`.       |
| `Accept=`          | Boolean.                                                |
| `SocketMode=`      | Octal, at most `7777`.                                  |
| `Backlog=`         | Positive integer.                                       |
| `MaxConnections=`  | Positive integer; used with `Accept=yes`, default 64.   |

### [Install]

| Directive      | Notes                                                    |
|----------------|----------------------------------------------------------|
| `WantedBy=`    | Applied by `picoctl enable` and by presets.              |
| `RequiredBy=`  | Same.                                                    |

`Alias=`, `Also=` and `DefaultInstance=` are recorded as degraded.

### Specifiers

`%n`, `%N`, `%p`, `%i`, `%I` and `%%` are expanded. Any other specifier
(`%t`, `%u`, `%H`, `%f`, ...) is passed through literally, including the
percent sign. `%I` is available where the value is free text or a path:
`Description=`, the words of `Exec*=` lines, `Environment=`,
`EnvironmentFile=`, `SupplementaryGroups=`, `PIDFile=` and `TTYPath=`.

## Directives that degrade

These are handled, but not completely. Each one adds an entry to the
degradation record.

| Written                    | Behaviour                                       | Record |
|----------------------------|-------------------------------------------------|--------|
| `Type=dbus`                | Runs as `simple`. There is no bus, so readiness is never waited for. | `Type=dbus` |
| `Type=idle`                | Runs as `simple`; the start delay is not implemented. | `Type=idle` |
| `Type=notify-reload`       | Runs as `notify`; there is no reload protocol.  | `Type=notify-reload` |
| `ExecReload=`              | Parsed and stored; nothing runs it.             | `ExecReload` |
| `StandardInput=` other than the four above (`null`, `file:`, `data`, ...) | Ignored. | `StandardInput` |
| `StandardOutput=`, `StandardError=` with another value (`console`, `tty`, `kmsg`, `file:`, `socket`, ...) | Ignored. | the directive name |
| `TTYPath=` not absolute    | Ignored.                                        | `TTYPath` |
| `RestartSec=`, `TimeoutStartSec=`, `TimeoutStopSec=` that do not parse | Ignored, default kept. | `RestartSec=`, `TimeoutStartSec=`, `TimeoutStopSec=` |
| A second `ExecStart=`      | Replaces the first.                             | `ExecStart=multiple` |
| `Exec*=` with a `@`, `+`, `!` or `:` prefix | The whole line is ignored.      | `ExecStart=@` (and so on, with the directive and prefix) |
| `Condition*=|...`          | Triggering conditions are dropped.              | `ConditionPathExists=|` |
| `Requires=`, `Wants=`, `Before=`, `After=`, `Conflicts=` naming an unsupported unit type | Dependency not followed. | `Wants=.mount` (and so on) |

A `StandardInput=` degradation has one further effect: a socket with
`Accept=yes` refuses connections for an instance of a service whose
`StandardInput=` degraded, because the instance would otherwise run with the
console on stdin instead of the connection.

Some invalid values are logged and ignored without being recorded:
`KillMode=`, `KillSignal=`, `SendSIGHUP=`, `SendSIGKILL=`, `RemainAfterExit=`,
`GuessMainPID=`, `Delegate=`, `DelegateSubgroup=`, `User=`, `Group=`, a
`ConditionPath*=` that is not absolute, a socket `Service=`, `Accept=`,
`SocketMode=`, `Backlog=`, `MaxConnections=`, a `ListenStream=` or
`ListenDatagram=` that is neither a path nor a port, an
`EnvironmentFile=` that is not absolute, and an `Exec*=` path that is neither
absolute nor a plain executable name. A bad `Restart=` value falls back to
`no`. For `Exec*=`, a rejected line leaves the previous list as it was, and
an `ExecStart=` that never parses leaves the unit without a command, which
is a load failure (below).

## Values that change meaning

- **Time spans** accept one number with an optional unit of `us`, `ms`, `s`,
  `min`, `m` or `h`, or `infinity`. A plain number is seconds. Compound
  spans such as `1min 30s` and other unit names such as `sec` or `d` are
  not accepted and trip the degradation above.
- **`TimeoutStartSec=0` and `TimeoutStopSec=0`** mean `infinity`, as in
  systemd. `RestartSec=0` means restart immediately.
- **Defaults** are 90 seconds for both timeouts and 100 ms for
  `RestartSec=`. The start limit is fixed at 5 starts in 10 seconds and
  cannot be changed: `StartLimitIntervalSec=` and `StartLimitBurst=` are
  recorded as dropped.
- **`Delegate=`** with a list of controllers is parsed, with names pico-init
  does not know skipped. An empty value delegates with no controllers.
  `DelegateSubgroup=` is honoured as described in
  [CGROUP_DELEGATION.md](CGROUP_DELEGATION.md).
- **`StandardOutput=syslog`, `journal+console` and `syslog+console`** all
  behave as `journal`; there is no console copy.
- **`Restart=on-watchdog`** parses and never fires, because there is no
  per-service watchdog. `Restart=on-abnormal` also restarts on pico-init's
  own setup failures (exit codes 200 to 222, for example a missing
  `ExecStart=` binary), which systemd treats as an ordinary exit code.
- **`Exec*=` command lines** take only the `-` prefix, and it must be glued
  to the path: `ExecStart=- /bin/true` is rejected. A bare executable name
  without a slash is accepted and searched at start time; a relative path
  containing a slash is rejected. An empty `ExecStart=` is logged and
  ignored; it does not reset the command.
- **`ExecCondition=`** exit status 1 to 254 skips the start cleanly and does
  not trigger `Restart=`; 255, a signal or a setup failure fails the unit.
- **`ListenStream=`/`ListenDatagram=`** take a path or a decimal port from 1
  to 65535 only. `host:port`, `[::]:port`, abstract (`@name`) addresses and
  the other `Listen*=` directives are not accepted. A bare port is bound
  dual-stack when the kernel has IPv6 and IPv4 otherwise.
- **Socket activation limits** are fixed: 20 activations per 2 seconds, 200
  with `Accept=yes`. `Backlog=` defaults to the largest value, which the
  kernel clamps to `net.core.somaxconn`.
- **`SocketMode=`** is applied exactly; the umask does not alter it.
- **A socket's `AF_UNIX` path is unlinked when the socket stops**, if it is
  the file the unit created.

### Conditions

Only `ConditionPathExists=` and `ConditionPathIsDirectory=` exist. Values
are single absolute paths, not lists. A leading `!` negates one entry;
repeated lines accumulate and all must hold; an empty value resets the list.
They are evaluated when the unit is about to start, not when it is loaded,
and a failed condition completes the start job successfully without running
anything. Specifiers are not expanded in the path, so a template cannot use
`ConditionPathExists=/dev/%I`.

## Behaviours that differ

### A unit fails to load

These are refused at load time and the unit is left in the `error` load
state; `pico-unit-lint` reports them as `FAILED TO LOAD`.

- `Type=` is any value other than `simple`, `exec`, `oneshot`, `forking`,
  `notify`, `notify-reload`, `dbus` or `idle`. It is a failure and not a
  fallback to `simple` because any other type changes when the service
  counts as started, and everything ordered after it would start too early.
- A service has no usable `ExecStart=`: none was given, or every line was
  rejected by the rules above.
- `Type=oneshot` with `Restart=always` or `Restart=on-success`. Other
  `Restart=` values are allowed with `oneshot`.
- A socket without any `ListenStream=` or `ListenDatagram=`.
- A socket whose paired service cannot be resolved. The pairing is by
  suffix swap, or `Service=`.
- `Accept=yes` combined with `Service=`, or with any `ListenDatagram=`.

### Reload

`picoctl daemon-reload` and `SIGHUP` re-read the fragments of loaded units
and find new unit files and new `.wants`/`.requires` symlinks. They do not
start anything, and they skip:

- socket units;
- a unit with a job or a control process in flight, which picks the change
  up at the next reload;
- the `Requires=`, `Wants=`, `Before=`, `After=` and `Conflicts=` lines of a
  changed unit, whose edges stay as loaded;
- a unit whose file is now gone, masked or invalid, which keeps its current
  configuration and logs a warning.

Presets are not re-evaluated by a reload.

### Presets

Presets from `/etc/systemd/system-preset` and
`/usr/lib/systemd/system-preset` are applied by PID 1 on the first boot
only, which is the boot that has to create `/etc/machine-id` because it is
missing, empty or unparseable. After that the decision lives in the
`.wants` and `.requires` symlinks, which the first boot writes, and presets
are not consulted again. systemd applies presets in `systemctl preset-all`
at image build time or provisioning time; here the first boot does it
because there is no other time.

Rules are matched as in `systemd.preset(5)`, the first matching line wins,
and a preset file hides a file of the same name in a later directory.
Two points differ from what the manual page might suggest to an image
builder:

- A unit that no rule matches is enabled. An image that wants the opposite
  ships a `disable *` rule.
- Only units that have `WantedBy=` or `RequiredBy=` and no symlink already
  deciding them are considered.
- An `ignore` rule leaves the unit untouched at boot and under `picoctl preset`; `list-unit-files` shows `ignored` in the preset column.

### Service environment

Like systemd's system manager, pico-init starts services with a clean
environment instead of its own: `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin`
and nothing else. What the kernel hands PID 1 (`HOME=/`, `TERM=linux` and
every unrecognised `name=value` boot-command-line word) does not reach
services; a unit that needs a variable sets it with `Environment=`. A unit
with `StandardInput=tty*` also receives `TERM`.

A unit with `User=` whose account exists in the passwd database gets `USER`,
`LOGNAME`, `HOME` and `SHELL` for that account (`SHELL` falls back to
`/bin/sh`). `Environment=` and `EnvironmentFile=` override all of them.

### Other differences

- An unknown escape such as `\q` in `Exec*=` or `Environment=` is kept as
  written; systemd refuses `Environment=` with one.
- A line in a unit file has no length limit; systemd refuses a line over
  1 MiB.
- There is no D-Bus. `BusName=` is recorded as dropped, and `Type=dbus`
  degrades as above.
- Only `Requires=`, `Wants=`, `Before=`, `After=` and `Conflicts=` are
  dependency directives. `Requisite=`, `BindsTo=`, `PartOf=`, `Upholds=`,
  `OnFailure=`, `OnSuccess=`, `PropagatesStopTo=` and `DefaultDependencies=`
  are recorded as dropped.

## See also

- [ARCHITECTURE.md](ARCHITECTURE.md) for the unit model and the job engine.
- [CGROUP_DELEGATION.md](CGROUP_DELEGATION.md) for `Delegate=` and
  `DelegateSubgroup=`.
- [DAEMON_SOCKET_ACTIVATION.md](DAEMON_SOCKET_ACTIVATION.md) for socket
  activation.
- [PRESET.md](PRESET.md) for preset handling.
- [../README.md](../README.md) for the overview.
