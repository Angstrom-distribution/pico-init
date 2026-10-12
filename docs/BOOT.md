# Boot

This document describes what pico-init does as PID 1, from the moment the
kernel executes it until `default.target` is reached. The sequence is
hard-coded in `main()` (`src/main.c`) and `manager_startup()`
(`src/manager-startup.c`). Everything before the manager exists is a plain
function call executed in order, not a unit. There is no initramfs stage, no
generator pass and no `systemd-fsck-root.service`: those jobs are done
in-process, and the unit graph only starts once the root filesystem and
`/etc/fstab` are settled.

Unless noted, a failing step is logged and the boot continues. The exceptions
are listed under [Failure handling](#failure-handling).

## Overview

| Step | What                                            | Source               |
|------|-------------------------------------------------|----------------------|
| 1    | API filesystems                                 | `mount-setup.c`      |
| 2    | `/dev` symlinks                                 | `mount-setup.c`      |
| 3    | Hostname                                        | `hostname-setup.c`   |
| 4    | Clock restore                                   | `clock-persist.c`    |
| 5    | Sysctl                                          | `mount-setup.c`      |
| 6    | Log to `/dev/kmsg`, version line                | `main.c`             |
| 7    | Console greeting                                | `status.c`           |
| 8    | Read `/etc/fstab`, check and remount root       | `root-check.c`       |
| 9    | Mount the rest of `/etc/fstab`, activate swap   | `fstab-mount.c`      |
| 10   | Swap discovery from the GPT (if fstab has none) | `gpt-scan.c`         |
| 11   | First-boot detection, `/etc/machine-id`         | `machine-id-setup.c` |
| 12   | Create the manager                              | `manager.c`          |
| 13   | Watchdog, state, control and notify sockets     | `manager-startup.c`  |
| 14   | Load units, enablement, presets, ordering       | `manager-startup.c`  |
| 15   | Boot transaction rooted at `default.target`     | `manager-startup.c`  |

If `getpid() != 1` the binary prints a one-line message and exits with
success without touching the system.

## API filesystems

`mount_setup()` runs first, before anything else, because the kernel mounts
only the root filesystem. For each entry in its table it skips the mount if
the path already has a different `st_dev` than its parent (so it works before
`/proc` exists), creates the directory, and calls `mount(2)`. `EBUSY` counts
as success.

| Mount point           | Type       | Options                | Flags                          | Required |
|-----------------------|------------|------------------------|--------------------------------|----------|
| `/proc`               | `proc`     |                        | nosuid, noexec, nodev          | yes      |
| `/sys`                | `sysfs`    |                        | nosuid, noexec, nodev          | yes      |
| `/dev`                | `devtmpfs` | `mode=0755`            | nosuid, strictatime            | no       |
| `/dev/pts`            | `devpts`   | `gid=5,mode=620`       | nosuid, noexec                 | no       |
| `/dev/shm`            | `tmpfs`    | `mode=1777`            | nosuid, nodev, strictatime     | no       |
| `/run`                | `tmpfs`    | `mode=0755`            | nosuid, nodev, strictatime     | no       |
| `/sys/fs/cgroup`      | `cgroup2`  | `nsdelegate`           | nosuid, noexec, nodev          | no       |
| `/sys/kernel/config`  | `configfs` |                        | nosuid, noexec, nodev          | no       |

`/dev` is normally already mounted by the kernel (`CONFIG_DEVTMPFS_MOUNT`)
or an initramfs and is then left alone. A failure on `/proc` or `/sys`, or on
creating their mount points, is the only mount failure that stops the boot:
`main()` calls `freeze()`. Every other entry that fails is logged at warning
level and skipped.

The nosuid, noexec and nodev flags in this table are also a floor for the
fstab pass: a `/etc/fstab` line for one of these mount points can reapply
options but cannot clear them (see [fstab](#etcfstab)).

`dev_setup()` then creates the symlinks `/dev/fd`, `/dev/stdin`,
`/dev/stdout` and `/dev/stderr` into `/proc/self/fd`, and `/dev/core` to
`/proc/kcore` when the kernel has that file. A link pointing elsewhere is
replaced atomically; an existing non-symlink is left alone with a warning.
A failure here is a warning only.

`sysctl_setup()` writes `64` to `/proc/sys/net/unix/max_dgram_qlen`, before
the first service exists to open a log socket. Failure is logged at debug
level.

## Hostname

`hostname_setup()` reads the first line of `/etc/hostname`, strips the line
ending and trailing blanks, and calls `sethostname(2)`. A missing or empty
file is not an error and leaves the kernel's value in place. The root
filesystem is read as the kernel mounted it, so this runs before the root
check.

## Clock

The boards pico-init targets often have no RTC battery, so the clock starts
in 1970. `clock_persist_restore()` moves it forward, never backward, to the
largest of:

- the build epoch compiled into the binary (`CLOCK_PERSIST_EPOCH_SEC`,
  1767225600, 2026-01-01 00:00:00 UTC),
- the time stored in `/etc/timestamp`,
- the modification time of `/etc/timestamp`.

The stored time and the mtime are only candidates when they are positive and
not later than `CLOCK_PERSIST_MAX_SEC` (4102444800, 2100-01-01). If the
current time is already at or past the chosen value nothing is changed.

`/etc/timestamp` holds one line of `YYYYMMDDHHMMSS` in UTC. The restore runs
before the kmsg log sink exists, so its result is logged afterwards as
`clock moved forward to <stamp> UTC from /etc/timestamp`.

The file is written by `clock_persist_save()`: write to `/etc/timestamp.tmp`,
`fsync`, `rename`. It does nothing if the stored value is already at or past
the current time, or if the current time is outside the epoch-to-max range.
It is called:

- once, 120 seconds after the manager is created (a timer on the manager's
  event loop), so netd has had time to correct the clock from NTP,
- every 600 seconds after that,
- on reboot and poweroff, before `sync()`.

Failures in the periodic save are logged at debug level, in the final save
at warning level.

## Logging and the console

Two output channels exist and are independent (`src/status.h`).

`pico_log_to_kmsg()` redirects PID 1's own log records to `/dev/kmsg`. logd,
when it starts, reads the ring from the beginning and so also holds every
record emitted before it existed. The first record is
`pico-init <version> (<git description>) running as PID 1`.

`status_enable()` opens `/dev/console` for write (falling back to stdout) and
`status_welcome()` prints the greeting. The greeting is the systemd one:
a blank line, `Welcome to <name>!`, a blank line, where the name is
`PRETTY_NAME` from os-release (`/etc/os-release`, else `/usr/lib/os-release`), else `NAME`, else `Linux`. If the console is
colourable the name uses the SGR parameters of `ANSI_COLOR=` (bold when
absent or when the value contains anything other than digits and `;`).
Colour is on unless `TERM` is literally `dumb`; `$NO_COLOR` and
`$SYSTEMD_COLORS` are not consulted.

Per-unit progress lines are written to the console by `job.c` when a start
or stop job finishes, in addition to the log record. They are not copied to
`/dev/kmsg`.

| Word     | Colour        | Text                                    |
|----------|---------------|-----------------------------------------|
| `  OK  ` | green         | `Started <description>.`                |
| `  OK  ` | green         | `Reached target <description>.`         |
| `  OK  ` | green         | `Listening on <description>.`           |
| `  OK  ` | green         | `Stopped <description>.`                |
| `FAILED` | bold red      | `Failed to start <description>.`        |
| `FAILED` | bold red      | `Stopped <description> with error.`     |
| ` TIME ` | bold red      | `Timed out starting <description>.`     |
| `DEPEND` | bold yellow   | `Dependency failed for <description>.`  |

`<description>` is `Description=` of the unit, or its name when unset. A
failed start is followed by an unbracketed line
`See 'systemctl status <unit>' for details.`. A unit skipped because a
`Condition*=` was not met gets no line, and a cancelled job prints nothing.

## Root filesystem

`/etc/fstab` is parsed first, from the root as the kernel mounted it,
because its `/` line decides how the root check ends. A missing file is
silent; any other read error is a warning.

`pico_root_check()` then proceeds as follows.

1. It reads `/proc/self/mountinfo` for the root mount. If root is mounted
   read-write there is nothing to check. If the `/` line in fstab carries
   options that a plain read-write root lacks, they are reapplied with a
   remount; otherwise the root is recorded as "read-write, not checked".
2. If root is read-only, the partition device is identified from mountinfo
   and sysfs. If it cannot be identified, or the superblock cannot be read,
   or the device holds no ext filesystem, the root is remounted without a
   check.
3. For an ext filesystem the superblock is read and a verdict taken
   (`pico_root_verdict()`):

   | Superblock                                                        | Verdict | Action                          |
   |-------------------------------------------------------------------|---------|---------------------------------|
   | error flag set                                                    | check   | run the checker                 |
   | clean (valid, no recovery flag, no orphan flag, no last orphan)   | clean   | remount                         |
   | not clean, journal present                                        | replay  | remount; the kernel replays it  |
   | not clean, no journal                                             | check   | run the checker                 |

4. The checker is `/usr/sbin/fsck.ext4 -a <partition>`. Preen mode is the default; `fsck.repair=yes` or `fsck.repair=no` on the kernel command line select `-y` or `-n`. `fsck.mode=force` runs the checker (with `-f`) whatever the superblock says, and `fsck.mode=skip` remounts without checking. If the binary is missing a warning is logged and the root is remounted unchecked.
5. The exit status is a bitmask (`pico_fsck_verdict()`):

   | Exit status                  | Result    | Action                                 |
   |------------------------------|-----------|----------------------------------------|
   | 0, or 1 only                 | ok        | remount                                |
   | bit 2 set                    | reboot    | `sync()`, `reboot(RB_AUTOBOOT)`        |
   | bit 4 set (bit 2 clear)      | uncorrected | root stays read-only, boot continues |
   | anything else                | failed    | remount anyway                         |

   If the checker is killed by a signal, or cannot be forked, the root is
   remounted unchecked.

The remount (`pico_root_remount()`) applies the options of the `/` line in
fstab. With no `/` line, root becomes read-write. A line that asks for `ro`
leaves it read-only. If the kernel refuses the options and the line did not
ask for read-only, the remount is retried as plain read-write and the line is
recorded as failed.

The reboot path has no guard against a loop: `/run` is a tmpfs, so a
filesystem that returns the same verdict on every boot reboots on every
boot. The log line `... asks for a reboot (exit N) -- rebooting` shows it in
the kernel ring.

## /etc/fstab

`fstab_pass()` mounts the remaining lines, once, in PID 1, before the manager
exists. This guarantees that no unit, whatever its ordering, can see an fstab
path before it is mounted. The cost is that PID 1 blocks on each mount in
turn. It uses the kernel's new mount API (`fsopen`/`fsconfig`/`fsmount`,
`fspick`/`FSCONFIG_CMD_RECONFIGURE`, `mount_setattr`), so a failed mount
reports the filesystem's own error message in the log and the record.

What happens to each line:

| Line                                            | Outcome                                                   |
|-------------------------------------------------|-----------------------------------------------------------|
| `/`                                             | handled by the root check                                 |
| `noauto`                                        | left alone, recorded `noauto`                             |
| a mount point of PID 1's API table              | options reapplied to the existing mount, never mounted twice; the table's nosuid, nodev, noexec cannot be cleared |
| already mounted                                 | left as is                                                |
| swap                                            | `swapon(2)` after all mounts, with `pri=` and `discard`   |
| network filesystem, `_netdev`, `x-systemd.automount`, loop, `ID=` source | recorded `skipped`, warning |
| anything else                                   | mount point created with `mkdir -p`, then mounted         |

Lines are processed in mount order: a stable sort by mount point depth, so a
parent is mounted before its children and equal depths keep file order.
Sources given as a device node or as a `UUID=`, `LABEL=`, `PARTUUID=` or
`PARTLABEL=` tag are first resolved and waited for. The wait
is bounded: `x-systemd.device-timeout=` if present, else 5 seconds. A device
that does not appear is skipped with a warning, or recorded `absent` when the
line has `nofail`. A line with a non-zero pass number gets the same
superblock gate and `fsck.<type> -a` as the root.

For `ubifs` lines, every MTD device named by `ubi.mtd=` on the kernel command
line is attached first. The line waits for its UBI volume, takes its source
as written, and is not checked (there is no `fsck.ubifs`).

The outcomes are written to `/run/pico-init/fstab`. If any line ended
`skipped` or `failed`, `main()` logs `N /etc/fstab line(s) not mounted, see
/run/pico-init/fstab`, and `picoctl is-system-running` reports `degraded`.
`absent` does not count.

## Swap

If `/etc/fstab` has any swap line, `noauto` ones included, swap discovery is
skipped and `/etc/fstab names swap, not discovering swap partitions` is
logged. This is the same rule as the upstream gpt-auto generator.

Otherwise `dps_scan()` locates the disk holding the root filesystem from
mountinfo, reads its GPT (header and entry array, both CRC-checked) and calls
`swapon(2)` on every partition whose type GUID is the Discoverable Partitions
Specification Linux swap GUID `0657fd6d-a4ab-43c4-84e5-0933c84b4f4f`.

- Only the boot disk is scanned, so a removable card carrying a swap
  partition is not used.
- Partitions with the no-auto attribute (bit 63) are skipped.
- A partition with the read-only attribute (bit 60) is warned about and then
  attempted anyway; the kernel decides.
- The device node comes from sysfs, matched by partition number, because
  there is no udev to supply `ID_PART_ENTRY_TYPE`.
- No block device under root (initramfs), no GPT, or an unreadable table
  ends the scan without error.

Swap is activated before the manager exists so that it is available to the
first services on low-memory boards.

## First boot

`machine_id_setup()` reads `/etc/machine-id`. If it is missing, empty,
all-zero, the literal `uninitialized`, or unparseable, this is first boot: a
new id is generated with `getrandom()` and written to `/etc/machine-id.pico-tmp`,
`fsync`ed and renamed into place with mode 0444.

If `/etc` is read-only (`EROFS`), the id is written to `/run/machine-id` and
bind-mounted over `/etc/machine-id`, then remounted read-only. This needs
`/etc/machine-id` to exist as a regular file in the image, so images with a
read-only root ship it as an empty file. First boot is still reported. If
the fallback fails too, a warning is logged and the id is kept only in
memory for this boot. Only a failing `getrandom()` makes `machine_id_setup()`
return an error, and `main()` logs it and goes on.

The first-boot flag is passed to the manager with `manager_set_first_boot()`
and gates preset application below. The id of the current boot is available
in-process through `machine_id_setup_get()`.

## Manager startup

After `manager_new()`:

- `RB_DISABLE_CAD` is set when the manager is PID 1, so Ctrl-Alt-Del
  delivers SIGINT instead of an immediate unsynced reboot. The manager turns
  SIGINT into an orderly reboot.
- A failed `manager_new()` ends in `freeze()`.

`manager_startup()` then does, in order:

1. **Watchdog.** `manager_watchdog_setup()`, see [Watchdog](#watchdog).
2. **Runtime state.** `manager_state_setup()` publishes per-unit and manager
   state under `/run/pico-init` for picoctl; `manager_ctrl_setup()` opens the
   picoctl control socket; `manager_notify_setup()` opens the `sd_notify()`
   listener. Each is optional: a failure is a warning and costs picoctl its
   verbs, or `sd_notify()` its listener, but never the boot. They are set up
   before any unit is loaded so the first state change is already published.
3. **Load units.** Every fragment in the search path becomes a node:
   `/etc/systemd/system` first, then `/usr/lib/systemd/system`. Only files
   whose suffix names a unit type are loaded; `.wants`, `.requires` and drop-in
   `.d` directories are not units. Dependency resolution may queue more
   units, which are loaded in the next step.
4. **Drain the load queue.**
5. **Enablement by symlink.** For each loaded unit the `.wants/` and
   `.requires/` directories are scanned.
6. **Presets, first boot only.** If the first-boot flag is set,
   `manager_apply_presets()` runs. Preset files are read from
   `/etc/systemd/system-preset` and `/usr/lib/systemd/system-preset`; the
   earliest filename (across both directories) with a matching line wins. A
   unit that already has a `.wants/` or `.requires/` symlink, or has no
   `[Install]` data, is skipped. A unit no rule mentions is enabled; an image
   that wants the opposite ships a `disable *` rule. Enablements are written as
   real symlinks under `/etc/systemd/system`, so later boots read them as
   ordinary enablement and do not run presets again. On other boots only
   a debug line is logged. See [PRESET.md](PRESET.md).
7. **Default ordering.** Every loaded target gets `After=` on each unit in
   its `Wants=` and `Requires=`, so `default.target` is reached only after
   what it pulls in. Every service gets `After=sockets.target`, when that
   target is loaded. An explicit `Before=` or `After=` between the same two
   units in either direction suppresses the default.
8. **Cycle check.** `unit_dependency_detect_cycles()` walks every loaded
   unit and logs a warning; it is diagnostic only. A cycle inside the boot
   transaction is broken when the transaction is activated.
9. **Boot transaction.** `default.target` is loaded and a start job is queued
   for it. If it cannot be loaded, `manager_startup()` returns an error. The
   line `startup: N units loaded, default.target queued` is logged.

`main()` treats a failed startup as non-fatal: it logs
`startup failed: <error>, entering the event loop anyway` and runs
`manager_loop()`, so a board whose default target is broken still has a
running manager and a console.

## Boot transaction

The start job for `default.target` expands through `Requires=` (hard,
failure propagates) and `Wants=` (soft), together with the ordering added
above, into a transaction (`src/job.c`). Jobs run as ordering allows. Each
job that finishes logs a record and prints a console status line (see
[Logging and the console](#logging-and-the-console)). A failed required
dependency makes the dependents' jobs end with `DEPEND`.

When the start job of the default target finishes, in either outcome,
`manager_log_degradation_summary()` logs once:

```
boot settled: 42 units loaded, none degraded
```

at info level, or `boot settled: N of M units degraded, K directives dropped
(see 'picoctl show <unit>' Degraded-Directives=)` at warning level when any
unit had directives it could not honour.

## Watchdog

`manager_watchdog_setup()` is the first thing `manager_startup()` does, so
unit loading, presets and the cycle check are all covered.

- The device is `/dev/watchdog0`, else `/dev/watchdog`. If neither exists
  (qemu, CI images) an info line is logged and the boot goes on unprotected.
- It requests a 30 second timeout with `WDIOC_SETTIMEOUT` and reads the
  actual value back with `WDIOC_GETTIMEOUT`; the driver may clamp it. If
  the read-back fails or is not positive, 30 is assumed.
- The card is enabled and one keepalive is sent.
- A timer on the event loop feeds it every quarter of the timeout, at the
  loop's highest priority (`EVENT_PRIORITY_WATCHDOG`), so a busy loop
  cannot starve the feed, and a hung PID 1 lets the hardware reset the board.
- The log line is
  `watchdog armed: <device>, timeout <N>s, feeding every <M>ms`.

The timeout and device path are not configurable at run time. There is no
per-service `WatchdogSec=` supervision: `WATCHDOG=` keys sent over
`sd_notify()` are logged and otherwise ignored.

The feed timer keeps running during shutdown. `manager_free()` on the PID 1
manager closes the device without disarming it (no `WDIOS_DISABLECARD`, no
magic close), so the watchdog remains armed across `sync()` and
`reboot()`.

## Shutdown

When the event loop ends, `main()` frees the manager and, for reboot or
poweroff, does in order:

1. `kill_remaining_processes()`: `SIGTERM` and `SIGCONT` to everything,
   wait up to 5 seconds for it to exit (polling every 100 ms), then `SIGKILL`.
   Units have been stopped by then, so what is left is what a `KillMode=process`
   or `KillMode=none` unit left behind.
2. The final clock save.
3. `sync()`.
4. `reboot(RB_AUTOBOOT)` or `reboot(RB_POWER_OFF)`.

## Failure handling

PID 1 must not return: the kernel panics with "Attempted to kill init".
Where `main()` would otherwise return, it calls `freeze()`, which logs the
reason and `pause()`s forever, leaving the log on the console.

| Condition                                              | Result            |
|--------------------------------------------------------|-------------------|
| `/proc` or `/sys` cannot be mounted                    | freeze            |
| `manager_new()` fails                                  | freeze            |
| `reboot()` returns                                     | freeze            |
| event loop fails, or asks to exit                      | freeze            |
| root check says reboot (fsck exit bit 2)               | sync, reboot      |
| fsck leaves errors uncorrected                         | boot, root read-only |
| any other setup step above                             | log, boot on      |
| `manager_startup()` fails                              | log, event loop   |
