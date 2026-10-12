# picoctl

picoctl is pico-init's `systemctl`. It takes the verbs, options and output
formats of systemd 262's `systemctl` where pico-init has something behind
them, and refuses the rest by name instead of pretending. It is also the
program behind `reboot`, `poweroff`, `halt` and `shutdown` when it is invoked
under those names. For how it gets its data see
[ARCHITECTURE.md](ARCHITECTURE.md); for what unit files may contain see
[INCOMPATIBILITIES.md](INCOMPATIBILITIES.md).

Every part of the interface falls into one of three groups:

- **Real**: it does what `systemctl` does.
- **Accepted**: there is nothing for it to act on in pico-init, so it is
  parsed and has no effect. This is only done where doing nothing is the
  correct outcome, such as `--no-pager` with no pager, `--no-wall` with no
  wall message or `-i` with no inhibitors. The exit status is what
  `systemctl` gives for "nothing to do".
- **Refused**: a one-line diagnostic on stderr, exit status 1 and no change
  of state. This is how everything is handled whose silent acceptance would
  let a script believe something happened: queueing, enabling, shutting down
  or reconfiguring.

```
$ picoctl isolate rescue.target
Verb 'isolate' is not supported by pico-init: the boot target is fixed, no unit can be isolated.
$ picoctl --runtime enable foo.service
--runtime is not supported: there is no runtime unit file directory
```

A verb that systemctl does not have either is `Unknown command verb`.

## Verbs

| Verb | Source | Notes |
|------|--------|-------|
| `list-units [PATTERN...]` | state files | Hides inactive units without a job unless `--all` or `--state=` is given, as `systemctl` does |
| `list-unit-files [PATTERN...]` | unit files | |
| `list-jobs [PATTERN...]` | state files | A job is `running` once its unit is activating or deactivating, `waiting` before that |
| `list-timers`, `list-paths`, `list-automounts` | none | Always empty: those unit types do not exist |
| `status`, `show`, `cat` | state files, unit files | `show` without a unit prints the manager's properties |
| `is-active`, `is-failed`, `is-enabled`, `is-system-running` | state files, symlinks | `is-system-running --wait` polls while the state is `starting` |
| `get-default` | state files | The default target is fixed at boot |
| `whoami [PID...]` | `/proc/PID/cgroup` | The unit a process belongs to |
| `enable`, `disable`, `reenable`, `preset`, `mask`, `unmask` | symlinks | `--now` also starts or stops the unit |
| `preset-all` | symlinks, preset files | Every unit file through the preset rules |
| `link PATH...`, `add-wants TARGET UNIT...`, `add-requires TARGET UNIT...` | symlinks | |
| `start`, `stop`, `restart`, `try-restart`, `reload-or-restart`, `try-reload-or-restart`, `reset-failed`, `daemon-reload` | control socket | |
| `kill` | `kill(2)` or `sigqueue(3)` | |
| `reboot`, `poweroff`, `halt` | signal to PID 1 | |
| `reload` | | Refused: there is no `ExecReload=` |

The legacy spellings `check`, `condstop`, `condrestart`, `condreload`,
`force-reload` and `reload-or-try-restart` work as they do in `systemctl`.

Refused by name, with the reason in the message: `isolate`, `default`,
`rescue`, `emergency`, `exit`, `set-default`, `kexec`, `soft-reboot`,
`switch-root`, `sleep`, `suspend`, `hibernate`, `hybrid-sleep`,
`suspend-then-hibernate`, `list-dependencies`, `list-sockets`,
`list-machines`, `cancel`, `clear-jobs`, `enqueue-marked`, `edit`, `revert`,
`help`, `show-environment`, `set-environment`, `unset-environment`,
`import-environment`, `daemon-reexec`, `log-level`, `log-target`,
`service-log-level`, `service-log-target`, `service-watchdogs`,
`set-property`, `bind`, `mount-image`, `clean`, `freeze` and `thaw`.

## Options

| Option | |
|--------|---|
| `-t`, `--type=`, `--state=`, `--failed`, `-a`, `--all` | Real. Filters of the list verbs, matched against the LOAD, ACTIVE and SUB state |
| `-p`, `--property=`, `-P`, `--value` | Real, for `show`. The properties are the ones in the state file |
| `-n`, `--lines=` | Real. Log lines in `status` |
| `-o`, `--output=` | `json`, `json-pretty`, `json-sse` and `json-seq` format the list verbs; `cat` strips the log lines of `status` to the message. The other names are valid and leave the output as it is, since `status` is the only verb that prints log entries. `help` lists the names |
| `--legend=BOOL`, `--no-legend`, `-q` | Real. `-q` switches the legend off unless `--legend=yes` says otherwise |
| `--timestamp=` | Real. `pretty`, `unix`, `us`, `utc` and `us+utc` for the `Since:` row of `status`; the boot time has whole seconds only |
| `-s`, `--signal=` | Real. Any Linux signal name or number and `SIGRTMIN+n`/`SIGRTMAX-n`; `help` lists them |
| `--kill-whom=`, `--kill-who=` | Real. `main` or `all`; `control` is refused |
| `--kill-value=` | Real. Queues the signal with an integer value |
| `--kill-subgroup=` | Real. Signals a cgroup below the unit's |
| `--now` | Real, for `enable`, `reenable`, `disable`, `preset` and `mask` |
| `--preset-mode=` | Real. `full`, `enable-only` or `disable-only` for `preset` and `preset-all` |
| `--dry-run` | Real, for `reboot`, `poweroff` and `halt`: nothing is signalled and the status is 0 |
| `--wait` | Real, for `is-system-running`. Refused with any other verb, as is the combination with `--no-block` |
| `--no-block` | Real. The reply is `queued` as soon as the job is |
| `--root=PATH` | Real. See below |
| `--job-mode=`, `--fail` | `replace` and `fail` are accepted: the manager has one queueing mode. The other modes, `--irreversible` and `--ignore-dependencies` are refused |
| `--no-pager`, `--no-wall`, `--message=`, `--no-ask-password`, `--no-warn`, `--no-reload`, `-v`, `-T`, `-i`, `--check-inhibitors=`, `--ignore-inhibitors`, `-f`, `-l`, `--plain`, `--system` | Accepted |
| `--show-types`, `--reverse`, `--before`, `--after`, `--what`, `--read-only`, `--mkdir`, `--drop-in`, `--stdin` | Accepted: only verbs pico-init lacks read them, and those are refused |
| `--user`, `--global`, `-H`, `-M`, `-C`, `-r`, `--image`, `--image-policy`, `--runtime`, `--with-dependencies`, `--marked`, `--when`, `--firmware-setup`, `--boot-loader-menu`, `--boot-loader-entry`, `--reboot-argument`, `--kernel-cmdline`, `--kernel-cmdline-reuse` | Refused |

`--root=PATH` is an extension of the offline meaning `systemctl` gives it:
the read verbs read the state files under `PATH/run/pico-init` and the file
verbs work below `PATH`, which is how the tests run picoctl without a
manager. `systemctl` refuses `is-system-running` and the other online verbs
with `--root`.

## Output formats

The list verbs print the table `systemctl` prints, with the legend and the
count after it. The JOB column appears only when a listed unit has a job.
With `-o json` they print an array of objects whose keys are the lower-cased
column headings (`unit`, `load`, `active`, `sub`, `job`, `description`;
`unit_file`, `state`, `preset`; `job`, `unit`, `type`, `state`), an empty
cell being `null`.

```
$ picoctl -o json list-unit-files 'foo*'
[{"unit_file":"foo.service","state":"disabled","preset":"enabled"}]
```

`json-pretty` indents with tabs and writes `"key" : value`, `json-sse`
prefixes `data: ` and ends with an empty line, and `json-seq` prefixes the
record separator, all as `systemctl` does. A JSON mode implies `--no-legend`.

## reboot, poweroff, halt and shutdown

Invoked under one of those names, picoctl takes the options that name has
in systemd 262 and acts at once.

| Name | Real | Accepted | Refused |
|------|------|----------|---------|
| `halt`, `poweroff`, `reboot` | `--halt`, `-p`/`--poweroff`, `--reboot`, `-w` (does nothing, successfully), `--help` | `-f`, `-d`, `-n`, `-i`, `-h`, `--no-wall` | `reboot ARG` with a non-empty argument, more than one argument |
| `shutdown` | `-H`, `-P`, `-r`, `-h`, `-k` (does nothing, successfully), `-c` and `--show` (nothing is ever scheduled), `now` and `+0`, `--help` | `-a`, `-f`, `-F`, `-t`, `--no-wall`, a wall message | `-K`, any other time such as `+5` or `10:30`, which would need a scheduler |

Without a time argument `shutdown` is immediate, where systemd waits a
minute.

## Exit status

The statuses follow `systemctl`: `is-active` returns 0, 3 or 4 and
`is-failed` 0, 1 or 4, as the LSB init scripts do, `status` returns 3 for a unit that is not active
and 4 for one that is unknown, `is-enabled` returns 4 for an unknown unit, and
`is-system-running` returns 0 only for `running`. Everything refused returns
1.
