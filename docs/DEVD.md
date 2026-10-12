# devd

`devd` is the device hotplug daemon of pico-init, installed as
`/usr/sbin/devd`. It is meant for images that run devtmpfs only and have no
udev. devtmpfs creates and removes the device nodes itself; devd reacts to
the uevents: it maintains `/dev/disk/by-*` links, mounts data partitions of
removable media, loads modules from `MODALIAS`, classifies input devices,
and evaluates a subset of udev rules files. It is a separate supervised
daemon and does not talk to PID 1.

## Running devd

devd has no configuration file. Its command line is udevd's; see
[Command line](#command-line). The shipped unit is:

```ini
[Unit]
Description=pico device hotplug daemon

[Service]
ExecStart=/usr/sbin/devd
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
```

Whether the unit is enabled is decided by the preset files, see
[PRESET.md](PRESET.md). `SIGTERM` and `SIGINT` make devd exit; other signals
are ignored. There is no reload: a restarted devd re-derives its state from
`/sys` (see Coldplug below), so there is nothing to reload or to lose.

## Command line

The options of systemd-udevd v262:

| Option | Effect |
|--------|--------|
| `-d`, `--daemon` | Real: fork, `setsid()`, `chdir("/")`, stdio to `/dev/null`, then run. |
| `-h`, `--help`; `-V`, `--version` | Print and exit 0. |
| `-D`, `--debug` | Accepted, no effect: every record is already written. |
| `-c`, `--children-max=` | Accepted, no effect: events run in the one loop. |
| `-e`, `--exec-delay=` | Accepted, no effect. |
| `-t`, `--event-timeout=` | Accepted, no effect. |
| `-N`, `--resolve-names=early\|late\|never` | Accepted, no effect. |
| `--timeout-signal=` | Accepted, no effect. |

A value that does not parse is a warning, as in udevd. An unknown option
exits 1.

The kernel parameters `udev.log_level=`, `udev.log_priority=`,
`udev.children_max=`, `udev.exec_delay=`, `udev.event_timeout=`,
`udev.timeout_signal=` and `udev.trace` (with the `rd.` prefix) are read and
ignored. `udev.blockdev_read_only` is a safety setting that devd does not
implement; when it is on, devd logs a warning at start and block devices stay
writable.

## Startup and coldplug

At startup devd:

1. Works out which whole disk holds the root filesystem (from
   `/proc/self/mountinfo`). Nothing on that disk is ever mounted under
   `/media`.
2. Loads the udev rules files (see Rules below).
3. Opens the kernel uevent socket.
4. Walks `/sys` to pick up devices that already exist.

The socket is opened before the walk, so a device appearing in between is
seen by at least one of the two. If the socket reports that events were
dropped (`ENOBUFS`), devd logs it and repeats the walk.

The walk, in order:

| Step | What it does |
| --- | --- |
| reconcile | removes dangling links under `/dev/disk/by-*` and under every directory a loaded `SYMLINK+=` rule names |
| modalias | for each `/sys/bus/*/devices/*/modalias`, runs `modprobe` on the value |
| input | classifies every device under `/sys/class/input`, then runs the rules on it |
| rules | runs the rules over `/sys/class/block` and `/sys/bus/usb/devices` |
| block | records every entry under `/sys/class/block`, then handles all disks as settled |

Only block, USB and input devices are replayed through the rules. Other
subsystems see rules only for events received after devd started. The input
walk runs even when no rules are loaded.

## Uevents

devd listens on the kernel's own multicast group 1 of
`NETLINK_KOBJECT_UEVENT`. Messages from group 2 (udev's rebroadcast, carrying
the `libudev` magic) are rejected. A message is dropped unless it was sent by
the kernel (`nl_pid` is 0 and it arrived by multicast), because devd acts as
root on what it reads.

Only `add` and `remove` are distinguished. `change`, `move`, `bind`,
`unbind`, `online` and `offline` are all treated as "other": the rules still
run for them, but block, mount and modalias handling ignore them. Input
classification re-runs for every action except `remove`.

For each received uevent devd does the following, in this order:

1. Builds the device context and, for the `input` subsystem, classifies the
   device (Input devices below).
2. Runs the rules (Rules below).
3. For `add` with a `MODALIAS` property, runs `/sbin/modprobe <modalias>`.
4. Passes the event to the block handling.

## Device links

devd maintains the following links in `/dev/disk/`, always as relative
symlinks of the form `../../<name>`:

| Directory | Source | Applies to |
| --- | --- | --- |
| `by-partuuid` | GPT partition GUID | partitions |
| `by-partlabel` | GPT partition name | partitions |
| `by-uuid` | ext superblock UUID | partitions with an ext filesystem |
| `by-label` | ext superblock label | partitions with an ext filesystem |
| `by-id` | bus identity plus `-partN` | disks and partitions |

The `by-id` stem is built from sysfs by walking up from the block device to
the first ancestor that identifies itself: `usb-<manufacturer>_<product>_<serial>`
for USB (from `idVendor`/`idProduct` and the descriptor strings) and
`mmc-<name>_<serial>` for MMC. Components are passed through udev's
whitespace replacement and character whitelist
(`[0-9A-Za-z#+-.:=@_]`; everything else becomes `_`). A device with no
descriptor strings gets no `by-id` link. A disk gets the bare stem; each
partition gets `<stem>-part<N>`.

Link names are escaped in the style of udev's `blkid_encode_string()`: bytes
outside the same whitelist become `\xNN`.

A link with the same name as an existing one replaces it. When a device goes
away, devd removes every `by-*` link pointing at it by scanning the
directory, not from memory, so links left behind by an earlier devd are
removed too.

Partition links come from the GPT entry, so a partition on a disk without a
GPT gets none; only the whole-disk `by-id` link is created for such a disk.
Not provided: `by-path`, MBR and FAT identities (the ext superblock and GPT
are the only sources). Virtual block devices (`/devices/virtual/`: ramdisks,
loop, device-mapper) are not tracked at all, so they get no links. MTD flash
(`/mtd/` in the sysfs path) is tracked but never read, so it gets no links
either.

## Block devices and media

A card insertion produces an `add` for the disk followed by one per
partition, with nothing marking the end. devd therefore does not react per
event. A disk's arrival opens a settle window of 250 ms, each partition
event extends it, and the window never lasts longer than 2 s from the first
event. When it closes, devd reads the GPT once and handles every partition.
A partition arriving after its disk has settled is handled immediately by
itself. Up to 32 disks with 16 partitions each are tracked; more are logged
and dropped.

For each partition devd creates the links above, then mounts it if all of
these hold:

- the disk is not the boot disk;
- the GPT entry does not have the "no auto" attribute;
- the partition type is Linux filesystem data
  (`0fc63daf-8483-4772-8e79-3d69d8477de4`) or Microsoft basic data
  (`ebd0a0a2-b9e5-4433-87c0-68b6b72699c7`);
- the partition carries an ext filesystem (anything else is logged and left
  alone);
- the device is not already mounted somewhere else according to
  `/proc/self/mountinfo`.

The mount point is `/media/<partlabel>`, with the label reduced to a single
safe path component, or `/media/<devname>` if there is no usable label. The
filesystem is mounted as `ext4` with `nosuid,nodev`, plus `ro` if the GPT
entry has the read-only attribute. A device already mounted at exactly this
directory (by an earlier devd) is adopted instead of mounted again.

When a partition disappears, devd unmounts its mount point lazily
(`MNT_DETACH`) and removes the directory. When a disk disappears, every
partition devd recorded for it is handled this way, whether or not the
kernel sent the per-partition removals. At most 32 mounts are tracked.

The mount call runs in the event loop and can block it for as long as the
kernel takes to reject bad media. Swap and root partition discovery is not
done here; PID 1 does it at boot, for the boot disk only.

## Module loading

For an `add` uevent with a `MODALIAS` property, and at coldplug for every
`/sys/bus/*/devices/*/modalias` file, devd runs `/sbin/modprobe <modalias>`
as a child process. It does not track what is already loaded and relies on
modprobe doing nothing for an already-loaded or built-in module. The call is
independent of the rules: it happens with no rules files installed. The
child is not waited for; at most 16 children run at once and further
requests are dropped.

## Input devices

For every device of the `input` subsystem, devd computes the same
`ID_INPUT*` properties as upstream udev's `input_id` builtin, from the
capability bitmaps in sysfs. The bitmaps are read from the device itself or
the nearest ancestor of the `input` subsystem (an `eventN` node has no
`capabilities/` directory, its parent `inputN` does). A device without such
an ancestor, such as `/sys/class/input/mice`, gets no classification.

The properties, in the order they are emitted:

`ID_INPUT`, `ID_INPUT_ACCELEROMETER`, `ID_INPUT_POINTINGSTICK`,
`ID_INPUT_MOUSE`, `ID_INPUT_TOUCHPAD`, `ID_INPUT_TOUCHSCREEN`,
`ID_INPUT_JOYSTICK`, `ID_INPUT_TABLET`, `ID_INPUT_TABLET_PAD`,
`ID_INPUT_KEY`, `ID_INPUT_KEYBOARD`, `ID_INPUT_SWITCH`

All set properties have the value `1`. The result is made available in two
ways:

- It is added to the device's property table before the rules run, so a rule
  can match `ENV{ID_INPUT_TOUCHSCREEN}=="1"` and a `RUN+=` child sees it in
  its environment.
- It is written to the udev database under `/run/udev/data`, which the
  libsystemd compatibility library overlays onto the uevent properties (see
  [COMPATIBILITY_LIBRARIES.md](COMPATIBILITY_LIBRARIES.md)). This is what
  Xorg's `config/udev` and libinput read.

A plain resistive touchscreen (`BTN_TOUCH` only) is classified as a
touchscreen and not as a key device. `ID_INPUT_WIDTH_MM` and
`ID_INPUT_HEIGHT_MM` are not set, as devd reads sysfs only and not the event
node.

No rule is needed to trigger the classification. The `IMPORT{builtin}` key
is not implemented, so rules files calling `input_id` that way are skipped
and devd classifies unconditionally.

## The udev database

`/run/udev/data/` is created on first write. Each file is named after the
device ID, using the same three forms as `sd_device_get_device_id()`:

| Form | Used when | Example |
| --- | --- | --- |
| `c<major>:<minor>` | `MAJOR` and `MINOR` present (`b` instead of `c` for the block subsystem) | `c13:67` |
| `n<ifindex>` | `IFINDEX` present | `n2` |
| `+<subsystem>:<sysname>` | otherwise | `+input:input3` |

A file contains three kinds of line, in this order:

```
I:<CLOCK_MONOTONIC usec the device was processed at>
E:ID_INPUT=1
E:ID_INPUT_TOUCHSCREEN=1
V:1
```

The file is written to a temporary name in the same directory and renamed
into place, with mode 0644. It is removed on `remove`, and also when a
re-classification finds no capabilities. A property list of zero entries
deletes the file instead of writing an empty one.

Records devd does not write: `S:` (devlinks, the compatibility library scans
`/dev` instead), `L:`, `G:`, `Q:` and `W:`. devd also never creates
`/run/udev/control`, `/run/udev/queue` or `/run/udev/tags/`, since software
treats `control` as proof that udevd is running.

## Rules

devd reads udev rules files unmodified, so files shipped by other packages
(for example `usb-modeswitch-data`) work as they are. It does not use a
separate format.

### Files

Rules are loaded once at startup from three directories, in increasing
precedence:

```
/usr/lib/udev/rules.d
/run/udev/rules.d
/etc/udev/rules.d
```

Files must end in `.rules`. They are sorted by basename; a file in a later
directory shadows a file with the same basename in an earlier one, so
`/etc/udev/rules.d/NN-name.rules` replaces the vendor copy. A missing
directory is not an error. At most 128 files are read, each under 1 MiB, with names shorter than 96
bytes. A file
that fails to load is logged and skipped without affecting the others.

devd ships one rules file of its own, `60-pico-serial.rules`, written in the
same subset. It skips removed devices and names USB serial adapters:

```
ACTION=="remove", GOTO="pico_serial_end"
SUBSYSTEM!="tty", GOTO="pico_serial_end"
KERNEL!="ttyUSB*|ttyACM*", GOTO="pico_serial_end"
...
LABEL="pico_serial_end"
```

The link is `serial/by-id/usb-<manufacturer>_<product>[_<serial>]-if<N>`, with a
`-port<N>` suffix on `ttyUSB` devices (not `ttyACM`). A missing manufacturer
or product is replaced by `idVendor` or `idProduct`, and the serial component
is left out when the adapter has none. An adapter without an interface number
gets no link.

### Syntax understood

Lines are `KEY{attr}OP"value"` clauses separated by commas. Comments (`#`),
blank lines and backslash line continuation are understood. Values must be
plain double-quoted strings; the `e"..."` escape form is not accepted.

| Key | Operators | Meaning |
| --- | --- | --- |
| `ACTION` | `==` `!=` | the uevent action |
| `SUBSYSTEM` | `==` `!=` | the subsystem |
| `KERNEL` | `==` `!=` | the sysname, the last component of `DEVPATH` |
| `ENV{key}` | `==` `!=` | a device property; an unset property is the empty string |
| `ENV{key}` | `=` `+=` | set a property, or append to it with a space (names starting with `.` are private and not exported to `RUN+=` children) |
| `ATTR{file}` | `==` `!=` | one read of `/sys<devpath>/<file>` |
| `ATTRS{file}` | `==` `!=` | the same read, walked up the parent chain (at most 12 levels) |
| `MODE` | `=` | permission bits of the device node, octal |
| `OWNER`, `GROUP` | `=` | owner or group of the device node |
| `SYMLINK` | `=` `+=` `-=` | link names relative to `/dev` |
| `RUN`, `RUN{program}` | `=` `+=` | commands to start |
| `GOTO`, `LABEL` | `=` | skip forward to a label |

The assignment operator `:=` is accepted and treated as `=`.

Match values are shell globs evaluated with `fnmatch(3)`, with `|` as
alternation (`ttyUSB*|ttyACM*`). The split on `|` is aware of bracket
expressions, so `c70[345abce]|c71[34bc]` works. There are no regular
expressions.

Behaviour that differs from a literal reading and matches udev:

- All `ATTRS{}` clauses of one rule must match the same ancestor, and that
  ancestor is what `%b` expands to.
- A missing attribute fails `==` and satisfies `!=`.
- Rules are evaluated in order and every matching rule contributes; there
  is no first-match-wins.
- `GOTO` only jumps forward, to a `LABEL` in the same file. A `GOTO` whose
  label is not ahead of it makes devd refuse the whole file.
- A rule consisting only of a `LABEL` is a jump target, not a match.

### Substitutions

| Form | Expands to |
| --- | --- |
| `%k`, `$kernel` | the sysname |
| `%n`, `$number` | the trailing digits of the sysname |
| `%p`, `$devpath` | the device path |
| `%b`, `$id` | the sysname of the ancestor matched by `ATTRS{}` |
| `%E{K}`, `$env{K}` | a device property |
| `%s{F}`, `$attr{F}` | a sysfs attribute (see below) |
| `%%`, `$$` | a literal `%` or `$` |

An unknown escape is copied through unchanged. `$attr{}` looks first at the
ancestor matched by `ATTRS{}`, then walks up from the device, and runs the
value through the same sanitiser as the `by-id` links (whitespace runs and
disallowed characters become `_`). Upstream only strips trailing whitespace
here.

### Actions

Rule results are collected first and carried out afterwards:

- `MODE`, `OWNER` and `GROUP` are applied with `chmod(2)` and `chown(2)` to
  the device node on `add`. `OWNER` and `GROUP` are looked up in
  `/etc/passwd` and `/etc/group`; a purely numeric value needs neither file.
  An unknown name is logged and the node is left alone.
- `SYMLINK` creates relative links under `/dev`, including missing
  directories (`serial/by-id/...`). A name may not start with `/` or contain
  a `..` component. At most 8 links per device. They are removed on
  `remove`.
- `RUN` starts the command, see below.

On `remove` the node is already gone, so permissions and new links are not
applied; the links devd made are dropped and `RUN` still fires.

### RUN

The value is split into arguments as udev does: whitespace separated, single
and double quotes group and are removed. A relative program name is looked up
in `/usr/lib/udev`. The child gets the device's non-private properties as its
environment, with `ACTION`, `DEVPATH` and `SUBSYSTEM` added if missing and a
`PATH`, and has its signal mask reset and stdin redirected. devd never waits
for a child; exited children are collected on `SIGCHLD` and failures are
logged. At most 16 children run at once, up to 8 `RUN` entries per device and
16 arguments per command; excess is dropped with a warning.

### Rules that are skipped

A rule using anything devd does not implement is skipped whole and not
partially applied, because the unsupported clause is usually the one that
narrows the match. The reasons are:

- an unimplemented key (`PROGRAM`, `IMPORT`, `TEST`, `TAG`, `OPTIONS`,
  `NAME`, `SECLABEL`, `DRIVER`, `DRIVERS`, `SUBSYSTEMS`, `KERNELS`,
  `TAGS`, `ATTR{}=` and so on);
- an operator the key does not take (`ACTION="add"`, `ATTR{x}="y"`);
- a missing `{attribute}` where one is required, or one where it is not
  allowed;
- `RUN{builtin}`, or any `RUN{...}` other than `program`;
- a clause that cannot be parsed, a line over 4096 bytes, or more than 16
  clauses;
- an `{attribute}` of 64 bytes or more, or a value of 256 bytes or more.

Each skipped rule is logged once at load, for the first 16, followed by a
summary of loaded and skipped counts. A skipped rule that contained a `GOTO`
no longer jumps, so the rules after it are reached where udev would have
skipped them.

## Not implemented compared to udev

| udev feature | devd |
| --- | --- |
| `udevadm`, `udevd` control socket, `/run/udev/control` | none |
| libudev monitor events (group 2) | not produced and not read |
| `PROGRAM`, `IMPORT{...}`, builtins (`blkid`, `usb_id`, `path_id`, `net_id`, `kmod`, ...) | skipped; the `by-id` and input logic are native C |
| `TEST`, `TAG`, `TAGS`, `OPTIONS`, `NAME`, `DRIVER`, `DRIVERS`, `SUBSYSTEMS`, `KERNELS`, `SECLABEL` | skipped |
| `ATTR{}=` (sysfs writes) | skipped |
| `e"..."` strings, backward `GOTO`, labels across files | not supported |
| `by-path` links | not created |
| MBR and FAT/exFAT filesystems | not identified, not mounted |
| tags (`G:`, `Q:`), device link priorities (`L:`), inotify watches (`W:`) | not recorded |
| rules reload on change | none; restart the unit |

Limits are fixed in the source: 32 properties per device, 32 tracked mounts,
32 tracked rule-created links, 32 disks, 16 partitions per disk. Exceeding a
limit is logged and the item is dropped, not grown.

## Related

- [ARCHITECTURE.md](ARCHITECTURE.md) for the daemons around devd.
- [../README.md](../README.md) for the overview.
