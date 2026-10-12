# logd and picolog

`logd` is pico-init's log daemon. It collects the stdout and stderr of
services, datagrams sent to `/dev/log`, and the kernel ring from
`/dev/kmsg`, and appends them to a size-capped two-file ring under
`/run/logd` in the journal export format. `picolog` is the reader, the
`journalctl` equivalent. There is no binary journal: the ring is plain
export-format text on tmpfs, and nothing is written to persistent storage.

## Processes and units

| Binary | Installed to | Role |
|--------|--------------|------|
| `logd` | `sbindir` | Receiver and ring writer |
| `picolog` | `bindir` | Ring reader, runs as any user that can read `/run/logd` |

`logd.service` is a service with `Restart=on-failure` and `RestartSec=2`,
wanted by `default.target`. `logd.socket` is wanted by
`sockets.target`:

```ini
[Socket]
ListenDatagram=/run/logd/stdout
ListenDatagram=/dev/log
SocketMode=0666
```

PID 1 binds and holds both sockets, so they outlive `logd`. Datagrams sent
while `logd` is down queue in the socket receive buffer, and a restarted
`logd` receives the same descriptors and drains the backlog. The sockets are
handed over through `LISTEN_FDS`; `logd` expects the `/run/logd/stdout`
socket as the first descriptor and `/dev/log` as the second. `LISTEN_FDNAMES`
is not used, so the order of the `ListenDatagram=` lines in `logd.socket`
must not change.

`SocketMode=0666` applies to both sockets because the setting is per unit.
It is needed for `/dev/log`, which any `syslog(3)` client opens by path.
Attribution never depends on what the sender claims (see
[Attribution](#attribution)).

When `logd` is started without `LISTEN_PID` matching its own PID or with
fewer than two descriptors in `LISTEN_FDS`, it binds its own sockets:
`/run/logd/stdout` with mode `0600` and `/dev/log` with mode `0666`,
unlinking a stale socket first. Failure to bind one socket is a warning;
`logd` exits with status 1 if neither is available.

## Command line

`logd` takes two options, both of the form `--option=value`:

| Option | Effect |
|--------|--------|
| `--runtime-dir=DIR` | Ring directory instead of `/run/logd`. In standalone mode the stdout socket moves to `DIR/stdout` too; `/dev/log` stays fixed. |
| `--max-bytes=N` | Ring cap in bytes instead of 2 MiB. Values of 0 or less are ignored. |

There is no configuration file and no `logd.conf`. `SIGTERM` and `SIGINT`
flush the pending line tails (see below) and end `logd` with status 0.

## Inputs

### Service stdout and stderr

For every start of every service command (not only `ExecStart=`), PID 1
creates an `AF_UNIX`/`SOCK_DGRAM` socket in the parent before `fork()`,
binds it to a unique abstract-namespace name of the form
`pico-init-stdout/<unit>/<counter>`, connects it to `/run/logd/stdout`, and
sets `SO_SNDBUF` to 212992. The child dup2()s that socket onto fd 1 and
fd 2. Each invocation therefore has its own source address, which `logd`
uses as the stream identity.

The default is chosen by `StandardInput=` and `StandardOutput=`:

| Situation | stdout and stderr |
|-----------|-------------------|
| Default, stdin not a tty | logd socket |
| `StandardInput=socket` | the accepted connection |
| `StandardInput=tty*` with no explicit `journal` | the terminal (stdin) |
| `StandardOutput=journal`, `journal+console`, `syslog`, `syslog+console` | logd socket, even with a tty on stdin; the `+console` copy is not made |
| `StandardOutput=null` | `/dev/null` |
| `StandardError=` unset | follows an explicit `StandardOutput=` |
| logd socket cannot be created or connected | `/dev/console` |

`StandardOutput=kmsg` and other values are not implemented and are recorded
as dropped directives by the unit parser. PID 1's own output is not sent
to `logd`; it goes to `/dev/kmsg`, which `logd` reads, or to stderr when
`/dev/kmsg` cannot be opened.

All records from this input get `PRIORITY=6` and `_TRANSPORT=stdout`. The
socket has no handshake, so a service cannot choose a priority or
identifier for its stdout. `<N>` prefixes in the text are not interpreted
(`SyslogLevelPrefix=` has no effect).

Line handling, per stream:

- A line ends at `\n`, or at a NUL byte, whichever comes first. An ordinary
  newline adds no `_LINE_BREAK` field; a NUL adds `_LINE_BREAK=nul`.
- A line longer than 8192 bytes (`LOGD_LINE_MAX`) is split and the leading
  part is tagged `_LINE_BREAK=line-max`.
- Bytes after the last break are kept as a tail and prepended to the next
  datagram of the same stream.
- The tail is flushed, tagged `_LINE_BREAK=pid-change`, when the sending PID
  on the stream changes, or when the same PID shows a different start time
  in `/proc/<pid>/stat` (PID reuse).
- The tail is flushed, tagged `_LINE_BREAK=eof`, when the stream is evicted
  from the table or when `logd` exits.
- The table holds 64 streams (`LOGD_MAX_STREAMS`). When it is full the
  least recently seen stream is evicted.
- A datagram without a source address (an unbound sender) gets no tail
  carry-over; any unterminated remainder is emitted at once with
  `_LINE_BREAK=eof`.

The receive buffer is 65536 bytes. A longer datagram is truncated and a
warning is logged.

### /dev/log

Each datagram is one record; the stream table is not involved. The parser
follows `journald-syslog.c`:

- An optional `<N>` prefix of one to three decimal digits. Only `N & 7`
  becomes `PRIORITY`; there is no `SYSLOG_FACILITY`. Without a valid prefix
  `PRIORITY` is 6.
- An optional RFC 3164 stamp (`Mmm dd hh:mm:ss `, as `syslog(3)` sends it)
  follows the prefix and is stored as `SYSLOG_TIMESTAMP` without its trailing
  space. Text that is not exactly that shape stays in `MESSAGE`.
- An optional `identifier[pid]: ` or `identifier: ` tag becomes
  `SYSLOG_IDENTIFIER`. A bracketed suffix is stripped and discarded. A tag
  longer than 255 bytes is removed from `MESSAGE` but sets no identifier. `_PID` always comes from the
  kernel credentials, never from the text.
- The rest is `MESSAGE`, taken up to the first NUL byte.
- `_TRANSPORT=syslog`.

An empty datagram is ignored.

libsystemd's `sd_journal_send()` family converts to a `syslog(3)`-shaped
datagram on `/dev/log`. Only `MESSAGE`, `PRIORITY`, `SYSLOG_FACILITY` and
`SYSLOG_IDENTIFIER` are carried, and `logd` then discards the facility; other
application fields are dropped
(see [COMPATIBILITY_LIBRARIES.md](COMPATIBILITY_LIBRARIES.md)).
`sd_journal_stream_fd()` connects to `/run/logd/stdout`; its `priority`,
`identifier` and `level_prefix` arguments are validated but not transported.

### /dev/kmsg

`logd` opens `/dev/kmsg` non-blocking at startup, before it binds or
accepts any socket, and drains it. A fresh open starts at the oldest record
in the kernel ring, so the first drain backfills everything the kernel and
PID 1 logged before `logd` started. Later records are read when the
descriptor becomes readable.

Per record:

- The severity is `prefix & 7`; the facility is not stored. An unparseable
  prefix yields priority 0.
- `MESSAGE` is the text after the first `;` up to the first newline, with
  the kernel's `\xNN` escapes decoded. The `KEY=VALUE` continuation lines of
  the kmsg record are not stored.
- A record with a non-kernel facility was written by a userspace process;
  a leading `identifier[pid]: ` tag is split off into `SYSLOG_IDENTIFIER`.
- The fields are `MESSAGE`, `PRIORITY` and `_TRANSPORT=kernel`. The kernel
  timestamp is not stored: the entry's
  `__REALTIME_TIMESTAMP` and `__MONOTONIC_TIMESTAMP` are the time `logd`
  wrote it, so backfilled records all carry roughly the same time.
- A record without `;` is discarded and ends the current drain pass; the next
  readiness event continues with the following record.
- The next expected sequence number is kept in `kmsg-seqnum` beside the
  ring and updated after each drain. After a `logd` restart in the same boot,
  records below it are skipped instead of being logged again. A jump in the
  sequence (the reader fell behind and the kernel dropped records) logs a
  warning with the number of missed messages.

If `/dev/kmsg` cannot be opened (missing node, no `CAP_SYSLOG`), `logd`
logs a warning and runs without the kernel transport.

## Attribution

For stdout records `logd` reads `SCM_CREDENTIALS` (`SO_PASSCRED` is set on
both sockets, also on inherited ones), and adds `_PID`, `_UID`, `_GID`,
`_COMM` and `_SYSTEMD_UNIT`. For stdout, `_COMM` and `_SYSTEMD_UNIT` are
looked up once per stream and cached, because the process can exit while
the stream lives on; the lookup is repeated after a PID change. For
`/dev/log` the lookup is done per datagram.

- `_COMM` is `/proc/<pid>/comm`.
- `_SYSTEMD_UNIT` comes from the `0::` line of `/proc/<pid>/cgroup`. Leading
  `*.slice` components are skipped and the first remaining component is the
  unit if it ends in `.service`, `.socket`, `.target`, `.mount`, `.swap`,
  `.device`, `.timer`, `.path` or `.scope`. Only cgroup v2 is parsed.
- If the process is gone or the cgroup has no unit component, the record is
  still written without those fields.
- A datagram whose credential carries PID 0 is treated as having none.

Kernel records carry no `_PID`, `_COMM` or `_SYSTEMD_UNIT`.

## The ring

The ring is two files in `/run/logd`:

| File | Content |
|------|---------|
| `active.export` | Entries being appended |
| `rotated.export` | The previous complete `active.export` |

The default cap is 2 MiB (`LOGD_DEFAULT_MAX_BYTES`), changeable only with
`--max-bytes=` at `logd` start. After each append, if `active.export` has
reached half the cap, it is renamed over `rotated.export` and a new empty
`active.export` is opened. The oldest data is thus dropped a whole file at
a time. Since the check follows the write, each file can exceed half the
cap by up to one entry, so the two files together stay near the cap.

An entry that alone exceeds the cap is refused with `-EMSGSIZE` and not
stored; the sender is not told. A field name that is not `[A-Z0-9_]{1,64}`
or starts with a digit refuses the whole entry.

Every `write()` carries one complete entry. If a write fails partway, the
file is truncated back to its previous size, so a file always ends on an
entry boundary. If `logd` is restarted within a boot it resumes appending to
the existing `active.export`. The directory is created with mode 0755 and
the files with mode 0644. `/run` is tmpfs: the ring is lost on reboot and
no flash is written.

## Stored format

Entries are in the journal export format. Each entry starts with three
fields the writer always emits, then the receiver's fields, then an empty
line:

```
__REALTIME_TIMESTAMP=1760000000123456
__MONOTONIC_TIMESTAMP=4821000123
_BOOT_ID=0123456789abcdef0123456789abcdef
MESSAGE=Started netd.
PRIORITY=6
_TRANSPORT=stdout
_PID=123
_UID=0
_GID=0
_COMM=netd
_SYSTEMD_UNIT=netd.service

```

`_BOOT_ID` is read from `/proc/sys/kernel/random/boot_id`, with a
`getrandom()` value as fallback. A field value that is not valid UTF-8
without control characters (other than TAB), or that contains a newline or
NUL, is written in the binary-safe form: `NAME`, a newline, a 64-bit
little-endian length, the data, and a newline.

The fields a reader can expect:

| Field | Source |
|-------|--------|
| `__REALTIME_TIMESTAMP`, `__MONOTONIC_TIMESTAMP`, `_BOOT_ID` | writer, all transports |
| `MESSAGE`, `PRIORITY`, `_TRANSPORT` | all transports; `_TRANSPORT` is `stdout`, `syslog` or `kernel` |
| `SYSLOG_IDENTIFIER` | `/dev/log` tag |
| `_PID`, `_UID`, `_GID`, `_COMM`, `_SYSTEMD_UNIT` | credentials and cgroup, when available |
| `_LINE_BREAK` | stdout only: `nul`, `line-max`, `pid-change`, `eof` |

The output of `picolog -o export` can be piped to upstream
`systemd-journal-remote` to build a binary journal off the device.

## picolog

```
picolog [OPTIONS...] [MATCHES...]
```

`picolog` reads the ring files directly, rotated file first and then the
active one, and does not talk to `logd`. Its options follow `journalctl` from
systemd 262. A missing ring yields no entries and success; an incomplete
trailing entry is dropped.

Every option is one of three kinds. *Real* options work on the stored fields.
*No-op* options are accepted and do nothing, where doing nothing is the right
outcome for a log that lives in RAM. *Refused* options print a one-line
`picolog: ...` message on stderr and exit with status 1, because accepting
them silently would let a script believe that a rotation, a sync or a
verification had happened.

A ring in `/run` holds the current boot only. The boot filter that
`journalctl` implies for `-k`, `-f` and `-e` is therefore not applied, `-b`
selects by an explicit boot ID, and a boot offset other than 0 prints
`Specifying boot ID or boot offset has no effect, no persistent journal was
found.` and shows nothing, which is what `journalctl` does for a runtime-only
journal.

### Sources

| Option | Kind | Meaning |
|--------|------|---------|
| `-D`, `--directory=PATH` | real | Ring files in `PATH` instead of `/run/logd`. |
| `-i`, `--file=PATH` | real | Read an export-format file, repeatable. The output of `picolog -o export` can be read back this way; `-` (stdin) is refused. |
| `--root=PATH` | real | Ring at `PATH/run/logd`; also locates `/etc/machine-id` for `--list-namespaces`. |
| `--namespace=NAME` | real | Only the default namespace has entries. An empty name, `*` and `+NAME` read the ring; any other name reads nothing. |
| `--system`, `-m`, `--merge` | no-op | There is one ring. `-m` still conflicts with `-b` and `--list-boots`, as upstream. |
| `--user`, `--user-unit=`, `-M`, `--image=`, `--image-policy=` | refused | No per-user journals, no container transport, no disk images. |

`LOGD_RUNTIME_DIR` in the environment replaces `/run/logd` when none of the
above is given; the test suite uses this.

### Filters

| Option | Kind | Meaning |
|--------|------|---------|
| `-u`, `--unit=UNIT` | real | `_SYSTEMD_UNIT` equals `UNIT`; repeatable, any match counts. A name without a unit suffix gets `.service`; a name with `*`, `?` or `[` is a glob. |
| `-t`, `--identifier=ID` | real | `SYSLOG_IDENTIFIER` equals `ID`; repeatable. |
| `-T`, `--exclude-identifier=ID` | real | Hide entries with that identifier; repeatable. |
| `-p`, `--priority=RANGE` | real | `LEVEL` is that level and everything more severe; `FROM..TO` is the inclusive range in either order. Levels are `emerg`, `alert`, `crit`, `err`, `warning`, `notice`, `info`, `debug` or 0 to 7. Entries without a parseable `PRIORITY` do not match. |
| `-k`, `--dmesg` | real | `_TRANSPORT=kernel`. |
| `-g`, `--grep=PATTERN` | real | `MESSAGE` matches a POSIX extended regular expression. Case-insensitive unless the pattern has an upper-case letter or `--case-sensitive[=BOOL]` says otherwise. Exits 1 when nothing matches. With `-n N` and no `-f`, as in `journalctl`, the last N matches are printed newest first. |
| `-S`, `--since=DATE`, `-U`, `--until=DATE` | real | Entries within the range, by `__REALTIME_TIMESTAMP`. Dates: `now`, `today`, `yesterday`, `tomorrow`, `@EPOCH`, `+5min`, `-1h`, `5min ago`, `5min left`, `[WEEKDAY] YYYY-MM-DD [HH:MM[:SS[.FRAC]]] [UTC\|Z\|+HH:MM]` or a bare `HH:MM[:SS]`. Local time unless a zone is given. |
| `-b`, `--boot[=ID]`, `--this-boot` | real | See above: `ID` selects by `_BOOT_ID` and fails if the ring has no such boot; `all`, no argument and `0` select everything. |
| `-c`, `--cursor=C`, `--after-cursor=C`, `--cursor-file=FILE` | real | Start at, or after, the entry named by a cursor. `--cursor-file` starts after the cursor in `FILE` (everything if it is missing) and rewrites it on exit. |
| `--facility=LIST` | real | `SYSLOG_FACILITY` is one of the listed facilities. `logd` does not store the facility, so nothing matches. `--facility=help` lists the names. |
| `FIELD=VALUE ...` | real | Matches: terms on the same field are alternatives, different fields must all match, and a `+` word starts an alternative group. |
| `/path/to/executable` | real | Matches the executable's `_COMM` (its first 15 characters). `_EXE` is not stored, so unlike upstream this can also match other programs of the same name. A device node is refused: `_KERNEL_DEVICE` is not stored. |
| `-I`, `--invocation=ID` | refused | Invocation IDs are not stored. The lookup fails the way an unknown ID does in `journalctl`: `No journal entry found for the invocation (...)`, status 1. |

Cursors are `b=BOOTID;m=MONOTONIC-HEX;t=REALTIME-HEX`. The ring has no
sequence numbers, so they are not interchangeable with cursors from a binary
journal.

### Output

| Option | Kind | Meaning |
|--------|------|---------|
| `-o`, `--output=MODE` | real | `short` (default), `short-iso`, `short-iso-precise`, `short-precise`, `short-monotonic`, `short-delta`, `short-unix`, `short-full`, `verbose`, `export`, `json`, `json-pretty`, `json-sse`, `json-seq`, `cat`, `with-unit`. `-o help` lists them. |
| `--output-fields=LIST` | real | Fields shown by `verbose`, `export`, `json*` and `cat`. The timestamps and `_BOOT_ID` stay in `export` and `json*`. |
| `-n`, `--lines[=[+]N]` | real | The last `N` entries (default 10 with a bare `-n`), or the first `N` with `+N`. `all` shows everything, `0` nothing. With `-f` and no `-n` or `--since`, 10. `-e` makes the default 1000. |
| `--no-tail` | real | All entries, even with `-f`. |
| `-r`, `--reverse` | real | Newest first. |
| `-f`, `--follow` | real | Print the last `-n` entries, then new ones as they arrive (polled every 200 ms). `SIGINT` and `SIGTERM` end it with status 0. Not combinable with `-r`, `-i`. |
| `--show-cursor` | real | Print `-- cursor: C` after the last entry. |
| `--utc` | real | UTC instead of local time. |
| `-W`, `--no-hostname` | real | Drop the host name column. |
| `-a`, `--all` | real | Show long and unprintable fields. Characters that are not printable text are written as `\xNN`. |
| `-l`, `--full`, `--no-full` | real | Without `--no-full`, long lines are never cut. `--no-full` ellipsizes to the terminal width, to 3 lines and to 300 characters. The ellipsis is ASCII `...`. |
| `--truncate-newline` | real | In `short` modes, cut a message at its first newline. |
| `-q`, `--quiet` | real | No `-- No entries --`, `-- Boot ... --`, table headers or notices. Implied by `export`, `json*` and `cat`. |
| `-x`, `--catalog` | no-op | There is no message catalog. |
| `--no-pager`, `-e`, `--synchronize-on-exit=BOOL` | no-op | There is no pager and nothing to synchronize (`-e` still sets the line default). |

Details of the `short` family:

- The host name is `_HOSTNAME` when the entry has one, else that of the
  machine running `picolog`; `logd` does not store it.
- The identifier is `SYSLOG_IDENTIFIER`, else `_COMM`, else `unknown`
  (`with-unit` prefers `_SYSTEMD_UNIT`). As kernel records have neither, they
  print as `unknown`. `[pid]` follows when the entry has `_PID` or
  `SYSLOG_PID`.
- Lines after the first of a multi-line message are indented under the
  first. TAB becomes 8 spaces and ANSI colour sequences are removed, unless
  `-a`.
- A message that is not valid printable text prints as `[NB blob data]`,
  with `N` the size in `journalctl`'s units (`7B`, `1.5K`).
- Only the message text is coloured, by priority as `journalctl` does: red
  for 0 to 3, yellow for 4, bold for 5, grey for 7, none for 6. A `--grep`
  match is highlighted inside it. Colour is off when `NO_COLOR` is set,
  stdout is not a terminal or `TERM` is unset or `dumb`; `SYSTEMD_COLORS`
  overrides all of these.
- Entries without a valid `__REALTIME_TIMESTAMP` are skipped.

`export` passes the stored bytes of each entry through unchanged, so a
filtered subset still feeds `systemd-journal-remote`; it carries no
`__CURSOR`, `__SEQNUM` or `__SEQNUM_ID`, which the ring does not have.
`json*` has `__CURSOR` but no sequence number either. Values that are not
text are arrays of byte values, and values of 4096 bytes or more are `null`,
unless `-a`. JSON output is not coloured.

### Commands

| Command | Kind | Meaning |
|---------|------|---------|
| `-h`, `--help`, `--version` | real | |
| `-N`, `--fields` | real | Field names present in the ring. |
| `-F`, `--field=FIELD` | real | Distinct values of a field, in order of first appearance; `-n` limits. Neither accepts filters. |
| `--list-boots` | real | One row per `_BOOT_ID` with first and last entry. `-n` and `-r` as upstream. |
| `--list-namespaces` | real | Namespaces under `/var/log/journal` and `/run/log/journal`. |
| `--disk-usage` | real | Disk usage of the ring files. |
| `--vacuum-size=`, `--vacuum-files=`, `--vacuum-time=` | real | Remove the rotated file (the only archived one) when the total size, the file count or its age is over the limit. The active file stays. Needs write access to the ring directory. |
| `--new-id128` | real | A new random ID in `journalctl`'s four notations. |
| `--flush`, `--relinquish-var`, `--smart-relinquish-var` | no-op | Nothing is stored on disk. |
| `--list-invocations` | refused | As `-I`. |
| `--sync`, `--rotate` | refused | `logd` has no control interface. Upstream's versions also fail when `journald` is not running. |
| `--header`, `--verify` | refused | The ring has no journal header and nothing to verify. |
| `--interval=`, `--verify-key=`, `--force`, `--setup-keys` | refused | `Compiled without forward-secure sealing support.`, as an upstream build without OpenSSL says. |
| `--list-catalog`, `--dump-catalog`, `--update-catalog` | refused | There is no catalog database. |

`picoctl status UNIT` uses the same reader for its per-unit log tail.

## Limits and rate control

There is no rate limiting. `logd` has no `RateLimitIntervalSec=` or
`RateLimitBurst=` equivalent, no per-service quota and no suppression
message. The bounds are structural:

- ring size: the 2 MiB cap bounds memory, and the oldest half is dropped on
  rotation;
- line length: 8192 bytes;
- stream table: 64 entries;
- datagram size: 65536 bytes;
- entry size: one entry cannot exceed the ring cap.

A service that logs faster than `logd` drains fills the socket queue; the
queue depth of a Unix datagram socket is governed by
`net.unix.max_dgram_qlen`, which PID 1 sets to 64 at boot, and `logd` does
not report overflow. Because the ring is half-rotated, a noisy service can
push every other service's older records out of it.

## Not implemented compared to journald

- The binary journal file format, `journalctl` itself, and
  `systemd-journald` as a name or D-Bus/varlink service. The sockets
  `/run/systemd/journal/socket`, `/run/systemd/journal/stdout` and
  `/run/systemd/journal/dev-log` do not exist; the native protocol
  (`sd_journal_send()` with arbitrary fields) is reduced to `/dev/log`.
- Persistent storage (`/var/log/journal`), `Storage=`, `SystemMaxUse=`,
  `MaxRetentionSec=`, sealing and compression. There is no `journald.conf`.
- Rate limiting, `Forward*=` (syslog, kmsg, console, wall) and
  `LineMax=`/`MaxLevelStore=` settings. The unit parser has no
  `LogLevelMax=`, `LogExtraFields=`, `LogNamespace=`, `SyslogIdentifier=`
  or `SyslogLevelPrefix=`, so they cannot influence what is stored.
- Per-stream handshake on the stdout socket: no per-service identifier,
  priority or level prefix; all stdout is `PRIORITY=6`.
- `SYSLOG_FACILITY`, `SYSLOG_PID`, `_CMDLINE`, `_EXE`, `_CAP_EFFECTIVE`,
  `_SELINUX_CONTEXT`, `_SYSTEMD_CGROUP`, `_SYSTEMD_SLICE`,
  `_SYSTEMD_INVOCATION_ID`, `_MACHINE_ID`, `_HOSTNAME`, `MESSAGE_ID`,
  `CODE_FILE` and `__CURSOR`/`__SEQNUM`; audit records.
- Kernel timestamps and sequence numbers on `_TRANSPORT=kernel` entries.
- What `picolog` cannot do, for lack of data or a daemon to ask: header
  display, verification, sync and rotate requests, invocation IDs, per-user
  journals, catalogs, and sequence numbers in cursors and `export`. The
  tables in [picolog](#picolog) say what each such option does instead.
