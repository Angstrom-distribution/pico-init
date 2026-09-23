/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The boot-time fstab pass: PID 1 mounting what /etc/fstab describes, once,
 * before the manager exists.
 *
 * Why PID 1, and why here. main() runs this after pico_root_check() and before
 * dps_scan() and manager_new(): root has settled read-write so mount points can
 * be created, the kmsg sink is installed so every outcome survives into logd,
 * and no unit -- whatever its ordering -- can observe an fstab path before it
 * is mounted. That is the invariant pico-tmpfiles.service already assumes when
 * it says there are no .mount units to wait for. A oneshot unit in the
 * systemd-remount-fs.service shape would race ordinary services, which get no
 * implicit After=sysinit.target here; devd starts unordered and is optional.
 * The cost is that PID 1 blocks on each mount in turn, the same trade the root
 * check already makes.
 *
 * Mounts use the kernel's new mount API rather than mount(2), for the reasons
 * util-linux's libmount switched to it by default: every option is its own
 * fsconfig() call, so there is no shared option string to size or escape; a
 * remount is FSCONFIG_CMD_RECONFIGURE on the superblock and, separately,
 * mount_setattr() on the mount, where mount(MS_REMOUNT) conflates the two; and
 * a failed fsconfig() leaves the filesystem's own error message readable off the
 * context fd, which goes into the record instead of a bare errno.
 *
 * What the pass does with each line, in mount order (fstab_mount_order()):
 *
 *  - "/" is the root check's (root-check.h), which consults the same line.
 *  - Swap lines are activated after every mount line, since a swap file may
 *    live on a filesystem the pass mounts: the device resolved and waited for
 *    like any other, then swapon() with pri= and discard. Any swap line at all
 *    stands DPS swap discovery down, which is upstream's rule (main.c).
 *  - noauto lines are left alone and recorded as such.
 *  - Lines for PID 1's own API mounts (mount-setup.c's table; oe-core's stock
 *    fstab names /proc, /dev/pts and /run) are never mounted twice. The line's
 *    options are reapplied to the existing mount, upstream's remount-fs
 *    behaviour, with the table's nosuid/nodev/noexec as a floor fstab cannot
 *    lower.
 *  - Anything already mounted is left as it is.
 *  - Everything else gets its mount point created (mkdir -p) and is mounted.
 *
 * A line whose source is a device -- a /dev path, or a UUID=/LABEL=/PARTUUID=/
 * PARTLABEL= tag, which fstab-resolve.h turns into one -- first waits for that
 * device, boundedly (fstab-resolve.h has the bounds). One that never appears is
 * skipped with a WARNING, or recorded as absent for a nofail line; the boot
 * goes on either way, where upstream would drop to emergency mode. A non-zero
 * pass number then gets the root check's filesystem check before the mount:
 * the ext superblock gate, fsck.<type> -a, and the same verdicts.
 *
 * ubifs lines name a UBI volume (ubi0:rootfs, ubi0_1, /dev/ubi0_1), which only
 * exists once its MTD device is attached. Before any line is mounted, the pass
 * attaches every MTD device the kernel command line's ubi.mtd= names
 * (ubi-attach.h), within the device wait's default bound. A ubifs line then
 * waits for its volume as a device line waits for its device, and fails at
 * once when its UBI device is attached without it or an attach for that
 * device number failed. Its source goes to the kernel as written, and it gets
 * no filesystem check: there is no fsck.ubifs, UBIFS recovers on mount.
 *
 * Out of scope, recorded as "skipped" with a WARNING rather than attempted:
 * network filesystems and _netdev (they need ordering after the network, which
 * nothing pre-manager has), x-systemd.automount, loop mounts, and ID= sources.
 *
 * Nothing here can stop a boot. Every failure is one line in the log and one
 * line in the record, and the record makes `picoctl is-system-running` report
 * "degraded" for as long as any line is skipped or failed.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "fstab.h"
#include "util.h"

struct ubi_attach_req;

typedef struct FstabPassConfig {
        const char *mountinfo;   /* default "/proc/self/mountinfo" */
        const char *filesystems; /* default "/proc/filesystems" */
        const char *record;      /* default PICO_FSTAB_RECORD */

        /* Which mount points are PID 1's own API mounts, and their floor.
         * Default mount_setup_api_floor(). */
        bool (*api_floor)(const char *where, uint64_t *ret_floor);

        const char *sys_root; /* default "/sys", where block devices are listed */
        const char *dev_root; /* default "/dev", where their nodes are */
        const char *fsck_dir; /* default "/usr/sbin", where fsck.<type> lives */

        /* The wait for a line's device without x-systemd.device-timeout=;
         * 0 means FSTAB_DEVICE_TIMEOUT_DEFAULT. */
        usec_t device_timeout;

        /* swapon(2); tests substitute their own, having no CAP_SYS_ADMIN
         * in the initial namespace, which swap needs. */
        int (*swapon)(const char *path, int flags);

        /* Called before every re-look while waiting for a device; tests. */
        void (*poll_hook)(void *userdata, unsigned attempt);
        void *poll_userdata;

        /* Where ubi.mtd= is read from; default "/proc/cmdline". */
        const char *cmdline;

        /* UBI_IOCATT (ubi-attach.h); tests substitute a fake kernel. */
        int (*ubi_attach)(const char *ctrl, struct ubi_attach_req *req, void *userdata);
        void *ubi_attach_userdata;
} FstabPassConfig;

/*
 * Run the pass over `t`, recording an outcome on every entry that does not
 * already carry one, then write the record. `cfg` NULL, or any member of it
 * NULL, means the production default.
 *
 * Returns the number of entries left skipped or failed, or -errno when the pass
 * could not run at all.
 */
int fstab_pass(FstabTable *t, const FstabPassConfig *cfg);

/*
 * Mount `e` fresh at `where` (canonicalized by the caller), with `floor`
 * MOUNT_ATTR_* bits forced on. Type "auto" tries every non-nodev type in
 * `filesystems` in turn. bind/rbind lines clone `e->what` with open_tree().
 *
 * 0, or -errno with a one-line description of what failed -- which call, and
 * the filesystem's own message when it left one -- in `err`.
 */
int fstab_mount(const FstabEntry *e,
                const char *where,
                uint64_t floor,
                const char *filesystems,
                char *err,
                size_t err_size);

/* The same with `source` in place of e->what: the device a tag resolved to.
 * NULL means e->what. */
int fstab_mount_from(
                const FstabEntry *e,
                const char *source,
                const char *where,
                uint64_t floor,
                const char *filesystems,
                char *err,
                size_t err_size);

/*
 * Apply `o` to the mount already at `where`: fspick() + fsconfig() +
 * FSCONFIG_CMD_RECONFIGURE for the superblock (always stating ro or rw, as
 * libmount does), then mount_setattr() for the per-mount attributes.
 *
 * Remount semantics are mount(8)'s, emulated as libmount emulates them on the
 * new API: read-only, nosuid, nodev, noexec and nosymfollow are cleared unless
 * `o` asks for them, and the atime mode is kept unless `o` names one. `floor`
 * is never cleared. `o` NULL means a bare "rw".
 *
 * 0, or -errno with a description in `err`.
 */
int fstab_remount(const char *where, const FstabOptions *o, uint64_t floor, char *err, size_t err_size);

/*
 * swapon(2) flags for a swap line's options, as swapon(8) maps them: pri=N
 * (0-32767) as SWAP_FLAG_PREFER plus the priority, "discard" as
 * SWAP_FLAG_DISCARD, "discard=once" and "discard=pages" adding the flag that
 * limits it to one or the other. Anything else is ignored. 0, or -EINVAL for a
 * priority that is not one.
 */
int fstab_swap_flags(const FstabOptions *o, int *ret_flags);

/* The mount_setattr()/fsmount() masks for a fresh mount and for a remount.
 * Split out so the remount-reset and floor rules can be tested as values. */
void fstab_fresh_attrs(const FstabOptions *o, uint64_t floor, uint64_t *ret_set, uint64_t *ret_clr);
void fstab_remount_attrs(const FstabOptions *o, uint64_t floor, uint64_t *ret_set, uint64_t *ret_clr);

/* Is something mounted exactly at `where`, per `mountinfo`? 1, 0, or -errno.
 * Compares the unescaped mount point field, so unlike an st_dev comparison it
 * sees a bind mount of a directory onto its own filesystem too. */
int fstab_is_mounted(const char *mountinfo, const char *where);

/*
 * Is the device at `node` mounted anywhere, per `mountinfo`? Matched by its
 * device number when `node` is a block device, and by the mount source
 * otherwise -- which also catches btrfs, whose mountinfo lines carry an
 * anonymous device number rather than the block device's. 1 with the first
 * mount point in `ret_where` (may be NULL), 0, or -errno.
 */
int fstab_device_mounted(const char *mountinfo, const char *node, char *ret_where, size_t size);

/* mkdir -p. An existing path of any type is success, so a bind mount's file
 * target is left alone. 0 or -errno. */
int fstab_mkdir_p(const char *path, mode_t mode);
