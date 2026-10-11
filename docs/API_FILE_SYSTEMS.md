# API File Systems

The kernel mounts the root file system and starts `/sbin/init`; nothing else
is mounted. pico-init, as PID 1, therefore mounts the API virtual file
systems itself before it does anything else, creates the five `/dev`
symlinks that devtmpfs does not provide, and sets one kernel tunable. This
document lists what is mounted, with which options, in which order, and what
happens when a mount already exists. The code is in `src/mount-setup.c`; the
call sites are in `main()` in `src/main.c`.

## Mounts

`mount_setup()` walks a fixed table in this order:

| Mount point          | Type       | Options                | Flags                                 | Required |
|----------------------|------------|------------------------|---------------------------------------|----------|
| `/proc`              | `proc`     |                        | nosuid, noexec, nodev                 | yes      |
| `/sys`               | `sysfs`    |                        | nosuid, noexec, nodev                 | yes      |
| `/dev`               | `devtmpfs` | `mode=0755`            | nosuid, strictatime                   | no       |
| `/dev/pts`           | `devpts`   | `gid=5,mode=620`       | nosuid, noexec                        | no       |
| `/dev/shm`           | `tmpfs`    | `mode=1777`            | nosuid, nodev, strictatime            | no       |
| `/run`               | `tmpfs`    | `mode=0755`            | nosuid, nodev, strictatime            | no       |
| `/sys/fs/cgroup`     | `cgroup2`  | `nsdelegate`           | nosuid, noexec, nodev                 | no       |
| `/sys/kernel/config` | `configfs` |                        | nosuid, noexec, nodev                 | no       |

The ordering follows the same constraint as systemd's early mount table:
`/proc` and `/sys` first, `/dev` before its subdirectories, and
`/sys/fs/cgroup` and `/sys/kernel/config` after `/sys` because they live
inside it. The source name passed to `mount(2)` is the type name (`proc`,
`sysfs`, `devtmpfs`, `devpts`, `tmpfs`, `cgroup2`, `configfs`).

There is no `/tmp` entry. `/run` is a tmpfs with no size limit option, so it
gets the kernel default.

`/sys/kernel/config` is mounted so that configfs consumers such as the USB
gadget tree (`/sys/kernel/config/usb_gadget`) work; without the mount that
path is an empty sysfs directory.

### Failure handling

A mount is either required or best-effort:

- `/proc` and `/sys` are required. If creating the mount point or the
  mount itself fails, `mount_setup()` returns `-errno` and `main()` logs
  `mount_setup: <error>` and calls `freeze()`.
- Everything else is best-effort. A failure is logged as a warning
  (`<where>: mount <type> failed: <error>`) and the next entry is
  processed. A board without `/dev/shm` still reaches a console.
- `/sys/fs/cgroup` is best-effort at this stage, but the cgroup supervision
  layer depends on it and reports when it is missing.

The return value of `mount_setup()` is the number of file systems it mounted
itself, which does not include those it found already mounted.

## Existing mounts

`mount_setup()` is idempotent. Before each entry it asks whether the mount
point is already a mount point by comparing `st_dev` of the path with
`st_dev` of its parent directory. This works before `/proc` exists, which
parsing `/proc/self/mountinfo` would not. If the devices differ, the entry is
logged at debug level (`<where> is already mounted, leaving it alone`) and
skipped: nothing is stacked on top of, remounted, or re-optioned.

The usual case is `/dev`, which the kernel mounts itself with
`CONFIG_DEVTMPFS_MOUNT` or an initramfs mounts before handing over. Its table
entry exists only for images where that did not happen. A `/run` or
`/dev/shm` mounted by an initramfs is likewise left as it is, with whatever
options it was given.

If the path is not yet a mount point, the directory is created with mode
`0755` (an existing directory is fine) and then mounted. If `mount(2)` fails
with `EBUSY`, something mounted there between the check and the call; this is
treated as success and logged at debug level.

The check compares device numbers only. A bind mount of a directory from the
same device is not detected as a mount point.

## Interaction with /etc/fstab

`/etc/fstab` is processed later, by `fstab_pass()`, after the root file
system check and before swap discovery and the manager. A line whose mount
point is one of the table entries above is never mounted a second time. If
the line has non-trivial options, they are reapplied to the existing mount
(reconfigure of the superblock plus `mount_setattr()` for the per-mount
attributes). If its options are trivial, nothing is done and the outcome is
recorded as already mounted by pico-init.

The nosuid, nodev and noexec bits that the table gives a mount point are a
floor for that reapplication. An fstab line cannot clear them: a `defaults`
line, which would otherwise reset those attributes on a remount, leaves them
set. The floor is derived from the table flags by `mount_setup_api_floor()`
and covers only those three attributes and only the paths in the table. For any
other path, such as `/run/lock` or `/var/volatile`, an fstab line is an
ordinary mount and the mount point is created if missing. For table paths
the fstab pass does not create the mount point.

## /dev symlinks

`dev_setup()` runs immediately after `mount_setup()`. devtmpfs creates device
nodes but never symlinks, so without this call `/dev/fd` and
`/dev/std{in,out,err}` do not exist and shell constructs such as
`foo >/dev/stderr` fail.

| Link          | Target            | Condition                             |
|---------------|-------------------|---------------------------------------|
| `/dev/core`   | `/proc/kcore`     | only if `/proc/kcore` exists          |
| `/dev/fd`     | `/proc/self/fd`   |                                       |
| `/dev/stdin`  | `/proc/self/fd/0` |                                       |
| `/dev/stdout` | `/proc/self/fd/1` |                                       |
| `/dev/stderr` | `/proc/self/fd/2` |                                       |

The links point into `/proc`, so `/proc` must be mounted first; the
`/dev/core` condition reads it.

For each link:

- If it does not exist, it is created.
- If it exists as a symlink with the right target, nothing is done.
- If it exists as a symlink with a different target, it is replaced
  atomically: a new link is created as `<link>.pico-tmp` and renamed over the
  old one, so the path never disappears.
- If it exists and is not a symlink, it is left alone and a warning is
  logged.

A link that cannot be created is logged as a warning and skipped; `dev_setup()`
returns the number of links correctly in place. Failure is never fatal to the
boot.

## Kernel tunable

`sysctl_setup()` runs after `/proc` is available and before the first
service starts. It writes `64` to `/proc/sys/net/unix/max_dgram_qlen`, which
bounds the AF_UNIX datagram receive queue. It is best-effort: an open or
write failure is logged at debug level and ignored.

## Order in main()

1. `mount_setup()`: the table above. Fatal on failure of a required entry.
2. `dev_setup()`: the `/dev` symlinks. A warning on failure.
3. Hostname, wall clock restore.
4. `sysctl_setup()`.
5. Root file system check, then `fstab_pass()` (see [BOOT.md](BOOT.md)).
6. Swap discovery, first-boot detection, then the manager starts and
   units run.

All of this happens in PID 1 before the manager exists, so no unit can
observe these paths before they are mounted.

## See also

- [BOOT.md](BOOT.md)
- [CGROUP_DELEGATION.md](CGROUP_DELEGATION.md)
- [../README.md](../README.md)
