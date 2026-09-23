/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The boot-time fstab pass and the new-mount-API calls under it. fstab-mount.h
 * has where it runs, why, and what it does with each kind of line.
 */

/* AT_EMPTY_PATH and AT_RECURSIVE are glibc extensions to <fcntl.h>. */
#define _GNU_SOURCE

#include "fstab-mount.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

#include "ext-super.h"
#include "fsid.h"
#include "fstab-resolve.h"
#include "manager.h"
#include "mount-setup.h"
#include "root-check.h"
#include "ubi-attach.h"
#include "util.h"

#ifndef AT_RECURSIVE
#        define AT_RECURSIVE 0x8000
#endif

/* The kernel's (linux/swap.h); older glibc <sys/swap.h> stops at DISCARD. */
#ifndef SWAP_FLAG_DISCARD_ONCE
#        define SWAP_FLAG_DISCARD_ONCE 0x20000
#endif
#ifndef SWAP_FLAG_DISCARD_PAGES
#        define SWAP_FLAG_DISCARD_PAGES 0x40000
#endif

/* The attributes a mount(8) remount resets unless the options name them.
 * Everything but the atime mode, which a remount keeps. */
#define REMOUNT_RESET_ATTRS                                                             \
        (MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC | \
         MOUNT_ATTR_NOSYMFOLLOW)

void fstab_fresh_attrs(const FstabOptions *o, uint64_t floor, uint64_t *ret_set, uint64_t *ret_clr) {
        uint64_t set = (o ? o->attr_set : 0) | floor;
        uint64_t clr = (o ? o->attr_clr : 0) & ~(uint64_t) MOUNT_ATTR__ATIME;

        /* Never clear what is being set; the floor always wins. */
        clr &= ~set;

        /* The atime field travels whole: mount_setattr() takes a mode in
         * attr_set only alongside all of MOUNT_ATTR__ATIME in attr_clr. */
        if (o && (o->attr_clr & MOUNT_ATTR__ATIME))
                clr |= MOUNT_ATTR__ATIME;

        *ret_set = set;
        *ret_clr = clr;
}

void fstab_remount_attrs(const FstabOptions *o, uint64_t floor, uint64_t *ret_set, uint64_t *ret_clr) {
        uint64_t set, clr;

        fstab_fresh_attrs(o, floor, &set, &clr);

        clr |= REMOUNT_RESET_ATTRS & ~set;

        *ret_set = set;
        *ret_clr = clr;
}

/*
 * Describe a failed call in `err`: which step, the errno, and whatever the
 * filesystem wrote into the context's message log. Returns -errno, captured
 * before anything here could clobber it.
 */
static int describe_failure(int fsfd, const char *step, char *err, size_t err_size) {
        int r = errno > 0 ? -errno : -EIO;
        size_t off;
        int n;

        n = snprintf(err, err_size, "%s: %s", step, strerror(-r));
        off = n < 0 ? 0 : (size_t) n >= err_size ? err_size - 1 : (size_t) n;

        /* Each read() returns one message ("e ...", "w ...", "i ..."); an
         * empty log answers ENODATA. Messages beyond what fits are dropped. */
        while (fsfd >= 0 && off + 4 < err_size) {
                char msg[256];
                ssize_t len = read(fsfd, msg, sizeof(msg) - 1);

                if (len <= 0)
                        break;
                while (len > 0 && msg[len - 1] == '\n')
                        len--;
                msg[len] = '\0';

                n = snprintf(err + off, err_size - off, " [%s]", msg);
                if (n < 0 || (size_t) n >= err_size - off)
                        break;
                off += (size_t) n;
        }

        return r;
}

/* The fsconfig() calls a line's options turn into, shared by mount and
 * remount. `rwro` also states rw when not read-only, which a reconfigure
 * needs and a fresh superblock does not. */
static int configure_superblock(int fsfd, const FstabOptions *o, bool rwro, char *err, size_t err_size) {
        char **s;

        if (o && (o->attr_set & MOUNT_ATTR_RDONLY)) {
                if (fsconfig(fsfd, FSCONFIG_SET_FLAG, "ro", NULL, 0) < 0)
                        return describe_failure(fsfd, "fsconfig(ro)", err, err_size);
        } else if (rwro && fsconfig(fsfd, FSCONFIG_SET_FLAG, "rw", NULL, 0) < 0)
                return describe_failure(fsfd, "fsconfig(rw)", err, err_size);

        for (s = o ? o->sb_flags : NULL; s && *s; s++)
                if (fsconfig(fsfd, FSCONFIG_SET_FLAG, *s, NULL, 0) < 0) {
                        char step[128];

                        snprintf(step, sizeof(step), "fsconfig(%s)", *s);
                        return describe_failure(fsfd, step, err, err_size);
                }

        for (s = o ? o->data : NULL; s && *s; s++) {
                char *eq = strchr(*s, '=');
                char step[128];
                int r;

                if (eq) {
                        char key[128];
                        size_t klen = (size_t) (eq - *s);

                        if (klen >= sizeof(key)) {
                                snprintf(err, err_size, "option name too long: %s", *s);
                                return -ENAMETOOLONG;
                        }
                        memcpy(key, *s, klen);
                        key[klen] = '\0';

                        r = fsconfig(fsfd, FSCONFIG_SET_STRING, key, eq + 1, 0);
                } else
                        r = fsconfig(fsfd, FSCONFIG_SET_FLAG, *s, NULL, 0);

                if (r < 0) {
                        snprintf(step, sizeof(step), "fsconfig(%s)", *s);
                        return describe_failure(fsfd, step, err, err_size);
                }
        }

        return 0;
}

static int
                mount_one_type(const FstabEntry *e,
                               const char *source,
                               const char *type,
                               const char *where,
                               uint64_t floor,
                               char *err,
                               size_t err_size) {

        uint64_t set, clr;
        int fsfd, mfd, r;

        fsfd = fsopen(type, FSOPEN_CLOEXEC);
        if (fsfd < 0) {
                char step[128];

                snprintf(step, sizeof(step), "fsopen(%s)", type);
                return describe_failure(-1, step, err, err_size);
        }

        if (fsconfig(fsfd, FSCONFIG_SET_STRING, "source", source, 0) < 0) {
                r = describe_failure(fsfd, "fsconfig(source)", err, err_size);
                close(fsfd);
                return r;
        }

        r = configure_superblock(fsfd, &e->opts, false, err, err_size);
        if (r < 0) {
                close(fsfd);
                return r;
        }

        if (fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) < 0) {
                r = describe_failure(fsfd, "fsconfig(create)", err, err_size);
                close(fsfd);
                return r;
        }

        fstab_fresh_attrs(&e->opts, floor, &set, &clr);

        mfd = fsmount(fsfd, FSMOUNT_CLOEXEC, (unsigned) set);
        if (mfd < 0) {
                r = describe_failure(fsfd, "fsmount", err, err_size);
                close(fsfd);
                return r;
        }
        close(fsfd);

        if (move_mount(mfd, "", AT_FDCWD, where, MOVE_MOUNT_F_EMPTY_PATH) < 0) {
                r = describe_failure(-1, "move_mount", err, err_size);
                close(mfd);
                return r;
        }

        close(mfd);
        return 0;
}

static int mount_bind(const FstabEntry *e, const char *where, uint64_t floor, char *err, size_t err_size) {
        unsigned rec = e->opts.rbind ? AT_RECURSIVE : 0;
        struct mount_attr attr = { 0 };
        uint64_t set, clr;
        int tfd, r;

        tfd = open_tree(AT_FDCWD, e->what, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | rec);
        if (tfd < 0)
                return describe_failure(-1, "open_tree", err, err_size);

        /* Through locals: glibc's struct mount_attr may be the kernel's own,
         * whose __u64 is not uint64_t on every ABI. */
        fstab_fresh_attrs(&e->opts, floor, &set, &clr);
        attr.attr_set = set;
        attr.attr_clr = clr;

        if ((attr.attr_set || attr.attr_clr) &&
            mount_setattr(tfd, "", AT_EMPTY_PATH | rec, &attr, sizeof(attr)) < 0) {
                r = describe_failure(-1, "mount_setattr", err, err_size);
                close(tfd);
                return r;
        }

        if (move_mount(tfd, "", AT_FDCWD, where, MOVE_MOUNT_F_EMPTY_PATH) < 0) {
                r = describe_failure(-1, "move_mount", err, err_size);
                close(tfd);
                return r;
        }

        close(tfd);
        return 0;
}

/* busybox mount's answer to type "auto": every type the kernel has that
 * needs a device, in the order the kernel lists them, first success wins. */
static int
                mount_auto(const FstabEntry *e,
                           const char *source,
                           const char *where,
                           uint64_t floor,
                           const char *filesystems,
                           char *err,
                           size_t err_size) {

        char *line = NULL, last[384] = "";
        size_t cap = 0;
        int r = -ENODEV;
        FILE *f;

        f = fopen(filesystems, "re");
        if (!f)
                return describe_failure(-1, filesystems, err, err_size);

        while (getline(&line, &cap, f) >= 0) {
                char *type = line;
                size_t len;

                if (strncmp(line, "nodev", 5) == 0)
                        continue;

                type += strspn(type, " \t");
                len = strcspn(type, " \t\n");
                if (len == 0)
                        continue;
                type[len] = '\0';

                r = mount_one_type(e, source, type, where, floor, last, sizeof(last));
                if (r == 0)
                        break;
        }

        free(line);
        fclose(f);

        if (r < 0)
                snprintf(err, err_size, "no filesystem type could mount it%s%s", last[0] ? ", last: " : "", last);

        return r;
}

int fstab_mount_from(
                const FstabEntry *e,
                const char *source,
                const char *where,
                uint64_t floor,
                const char *filesystems,
                char *err,
                size_t err_size) {

        if (e->opts.bind || e->opts.rbind)
                return mount_bind(e, where, floor, err, err_size);

        if (!source)
                source = e->what;

        if (strcmp(e->type, "auto") == 0)
                return mount_auto(
                                e,
                                source,
                                where,
                                floor,
                                filesystems ? filesystems : "/proc/filesystems",
                                err,
                                err_size);

        return mount_one_type(e, source, e->type, where, floor, err, err_size);
}

int fstab_mount(const FstabEntry *e,
                const char *where,
                uint64_t floor,
                const char *filesystems,
                char *err,
                size_t err_size) {

        return fstab_mount_from(e, NULL, where, floor, filesystems, err, err_size);
}

int fstab_remount(const char *where, const FstabOptions *o, uint64_t floor, char *err, size_t err_size) {
        struct mount_attr attr = { 0 };
        uint64_t set, clr;
        int fsfd, r;

        fsfd = fspick(AT_FDCWD, where, FSPICK_CLOEXEC | FSPICK_NO_AUTOMOUNT);
        if (fsfd < 0)
                return describe_failure(-1, "fspick", err, err_size);

        r = configure_superblock(fsfd, o, true, err, err_size);
        if (r < 0) {
                close(fsfd);
                return r;
        }

        if (fsconfig(fsfd, FSCONFIG_CMD_RECONFIGURE, NULL, NULL, 0) < 0) {
                r = describe_failure(fsfd, "fsconfig(reconfigure)", err, err_size);
                close(fsfd);
                return r;
        }
        close(fsfd);

        fstab_remount_attrs(o, floor, &set, &clr);
        attr.attr_set = set;
        attr.attr_clr = clr;

        if (mount_setattr(AT_FDCWD, where, 0, &attr, sizeof(attr)) < 0)
                return describe_failure(-1, "mount_setattr", err, err_size);

        return 0;
}

/* Split `line` into its first `n` whitespace-separated fields, in place. */
static int split_fields(char *line, char **field, size_t n) {
        char *p = line;
        size_t i;

        for (i = 0; i < n; i++) {
                p += strspn(p, " \t");
                if (*p == '\0' || *p == '\n')
                        return -EINVAL;

                field[i] = p;
                p += strcspn(p, " \t\n");
                if (*p != '\0')
                        *p++ = '\0';
        }

        return 0;
}

int fstab_is_mounted(const char *mountinfo, const char *where) {
        char *line = NULL;
        size_t cap = 0;
        int found = 0;
        FILE *f;

        f = fopen(mountinfo, "re");
        if (!f)
                return -errno;

        while (!found && getline(&line, &cap, f) >= 0) {
                char *field[5];

                if (split_fields(line, field, 5) < 0)
                        continue;

                fstab_unescape(field[4]);
                found = strcmp(field[4], where) == 0;
        }

        free(line);
        fclose(f);

        return found;
}

int fstab_device_mounted(const char *mountinfo, const char *node, char *ret_where, size_t size) {
        char real[PATH_MAX], *line = NULL;
        bool by_devnum = false;
        unsigned maj = 0, min = 0;
        size_t cap = 0;
        struct stat st;
        int found = 0;
        FILE *f;

        if (!mountinfo || !node)
                return -EINVAL;

        if (stat(node, &st) == 0 && S_ISBLK(st.st_mode)) {
                by_devnum = true;
                maj = major(st.st_rdev);
                min = minor(st.st_rdev);
        }
        if (!realpath(node, real))
                snprintf(real, sizeof(real), "%s", node);

        f = fopen(mountinfo, "re");
        if (!f)
                return -errno;

        while (!found && getline(&line, &cap, f) >= 0) {
                char *field[5], *sep, *rest[2];
                unsigned a, b;

                sep = strstr(line, " - ");
                if (!sep)
                        continue;
                *sep = '\0';

                if (split_fields(line, field, 5) < 0 || split_fields(sep + 3, rest, 2) < 0)
                        continue;

                fstab_unescape(field[4]);
                fstab_unescape(rest[1]);

                if (by_devnum && sscanf(field[2], "%u:%u", &a, &b) == 2 && a == maj && b == min)
                        found = 1;
                else if (strcmp(rest[1], real) == 0 || strcmp(rest[1], node) == 0)
                        found = 1;

                if (found && ret_where)
                        snprintf(ret_where, size, "%s", field[4]);
        }

        free(line);
        fclose(f);

        return found;
}

int fstab_mkdir_p(const char *path, mode_t mode) {
        char buf[PATH_MAX];
        struct stat st;
        size_t len;
        char *p;

        if (!path || path[0] != '/')
                return -EINVAL;

        if (stat(path, &st) == 0)
                return 0;

        len = strlen(path);
        if (len >= sizeof(buf))
                return -ENAMETOOLONG;
        memcpy(buf, path, len + 1);

        for (p = buf + 1; *p; p++) {
                if (*p != '/')
                        continue;

                *p = '\0';
                if (mkdir(buf, mode) < 0 && errno != EEXIST)
                        return -errno;
                *p = '/';
        }

        if (mkdir(buf, mode) < 0 && errno != EEXIST)
                return -errno;

        return 0;
}

/* util-linux's mnt_fstype_is_netfs() list, which is also what systemd's
 * fstab-generator goes by. */
static bool type_is_network(const char *type) {
        static const char * const exact[] = {
                "cifs", "smb3", "smbfs", "afs", "ncpfs", "glusterfs", "fuse.curlftpfs", "fuse.sshfs",
        };
        size_t i;

        if (strncmp(type, "nfs", 3) == 0 || strncmp(type, "9p", 2) == 0)
                return true;

        for (i = 0; i < sizeof(exact) / sizeof(exact[0]); i++)
                if (strcmp(type, exact[i]) == 0)
                        return true;

        return false;
}

/* The lines the pass does not attempt, each with the reason it gives. NULL
 * when the line is one to mount. */
static const char *skip_reason(const FstabEntry *e) {
        if (type_is_network(e->type) || e->opts.netdev)
                return "network filesystem: nothing orders it after the network";
        if (e->opts.automount)
                return "x-systemd.automount is not supported";
        if (e->opts.loop)
                return "loop mounts are not supported";
        /* systemd's by-id tag: a device's bus identity, which nothing
         * pre-manager can read. */
        if (strncmp(e->what, "ID=", 3) == 0)
                return "ID= sources are not supported";

        return NULL;
}

/*
 * The device behind a line: its tag resolved, or its /dev path waited for,
 * within the line's device timeout. True with the node in `node`; false with
 * the line's outcome recorded -- absent for a nofail line whose device never
 * appeared, skipped for any other, failed when no amount of waiting helps.
 */
static bool resolve_source(FstabEntry *e, PicoFsKind hint, const FstabPassConfig *cfg, char *node, size_t size) {
        FstabResolver res = { .sys_root = cfg->sys_root, .dev_root = cfg->dev_root };
        bool clamped;
        usec_t timeout;
        int r;

        timeout = fstab_device_timeout(&e->opts, cfg->device_timeout, &clamped);
        if (clamped)
                pico_log(PICO_LOG_WARNING,
                         "fstab: waiting at most %llus for %s, not forever",
                         (unsigned long long) (timeout / USEC_PER_SEC),
                         e->what);

        r = fstab_wait_device(&res, e->what, hint, timeout, cfg->poll_hook, cfg->poll_userdata, node, size);
        if (r > 0) {
                if (strcmp(node, e->what) != 0)
                        pico_log(PICO_LOG_DEBUG, "fstab: %s is %s", e->what, node);
                return true;
        }

        if (r == -EOPNOTSUPP) {
                pico_log(PICO_LOG_WARNING,
                         "fstab: cannot resolve %s: pico-init cannot read a %s filesystem's UUID or label",
                         e->what,
                         e->type);
                fstab_entry_set_outcome(e, FSTAB_FAILED, "no UUID/LABEL reader for %s", e->type);
                return false;
        }

        if (r < 0) {
                pico_log(PICO_LOG_WARNING, "fstab: cannot look for %s: %s", e->what, strerror(-r));
                fstab_entry_set_outcome(e, FSTAB_FAILED, "cannot look for the device: %s", strerror(-r));
                return false;
        }

        if (e->opts.nofail) {
                pico_log(PICO_LOG_INFO,
                         "fstab: %s did not appear within %llums, and its line is nofail",
                         e->what,
                         (unsigned long long) (timeout / USEC_PER_MSEC));
                fstab_entry_set_outcome(
                                e,
                                FSTAB_ABSENT,
                                "no device after %llums",
                                (unsigned long long) (timeout / USEC_PER_MSEC));
                return false;
        }

        pico_log(PICO_LOG_WARNING,
                 "fstab: %s did not appear within %llums, skipping its line",
                 e->what,
                 (unsigned long long) (timeout / USEC_PER_MSEC));
        fstab_entry_set_outcome(
                        e,
                        FSTAB_SKIPPED,
                        "no device after %llums",
                        (unsigned long long) (timeout / USEC_PER_MSEC));
        return false;
}

static void sleep_usec(usec_t u) {
        struct timespec ts = {
                .tv_sec = (time_t) (u / USEC_PER_SEC),
                .tv_nsec = (long) ((u % USEC_PER_SEC) * 1000),
        };

        while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
                ;
}

/*
 * A ubifs line's volume. Failed at once when the attach for its UBI device
 * number failed, or when that device is attached without the volume -- its
 * volumes are all there the moment it is attached. Otherwise waited for
 * within the line's device timeout, as a device is, since the kernel may have
 * attached it rather than PID 1. True when it is there to mount.
 */
static bool
                resolve_ubi(FstabEntry *e,
                            const UbiSource *s,
                            const FstabPassConfig *cfg,
                            const UbiAttach *ubi,
                            size_t n_ubi) {

        const UbiAttach *failed = NULL;
        char vol[UBI_MAX_VOLUME_NAME + 32], dev[32];
        usec_t timeout, deadline;
        unsigned attempt;
        struct stat st;
        bool clamped;
        int r;

        ubi_source_describe(s, vol, sizeof(vol));
        snprintf(dev, sizeof(dev), "ubi%d", s->ubi_num);

        for (size_t i = 0; i < n_ubi; i++)
                if (ubi[i].state != UBI_ATTACH_DONE && ubi[i].param.ubi_num == s->ubi_num)
                        failed = &ubi[i];

        if (failed && ubi_volume_present(cfg->sys_root, s) == -ENODEV) {
                pico_log(PICO_LOG_WARNING,
                         "fstab: not mounting %s: %s is not attached: %s",
                         e->where,
                         dev,
                         failed->reason);
                if (failed->state == UBI_ATTACH_TIMEOUT && e->opts.nofail)
                        fstab_entry_set_outcome(e, FSTAB_ABSENT, "%s not attached: %s", dev, failed->reason);
                else
                        fstab_entry_set_outcome(
                                        e,
                                        failed->state == UBI_ATTACH_TIMEOUT ? FSTAB_SKIPPED : FSTAB_FAILED,
                                        "%s not attached: %s",
                                        dev,
                                        failed->reason);
                return false;
        }

        timeout = fstab_device_timeout(&e->opts, cfg->device_timeout, &clamped);
        if (clamped)
                pico_log(PICO_LOG_WARNING,
                         "fstab: waiting at most %llus for %s, not forever",
                         (unsigned long long) (timeout / USEC_PER_SEC),
                         vol);
        deadline = usec_add(now_monotonic(), timeout);

        for (attempt = 0;; attempt++) {
                usec_t now;

                if (attempt > 0 && cfg->poll_hook)
                        cfg->poll_hook(cfg->poll_userdata, attempt);

                r = ubi_volume_present(cfg->sys_root, s);
                if (r == 0) {
                        pico_log(PICO_LOG_WARNING, "fstab: not mounting %s: there is no %s", e->where, vol);
                        fstab_entry_set_outcome(e, FSTAB_FAILED, "%s is attached without that volume", dev);
                        return false;
                }
                if (r < 0 && r != -ENODEV) {
                        pico_log(PICO_LOG_WARNING, "fstab: cannot look for %s: %s", vol, strerror(-r));
                        fstab_entry_set_outcome(
                                        e, FSTAB_FAILED, "cannot look for the volume: %s", strerror(-r));
                        return false;
                }
                if (r > 0 && (!s->path || stat(e->what, &st) == 0))
                        return true;

                now = now_monotonic();
                if (now >= deadline)
                        break;
                sleep_usec(deadline - now < FSTAB_DEVICE_POLL ? deadline - now : FSTAB_DEVICE_POLL);
        }

        /* Attached, but its volume's node never appeared; or never attached. */
        if (r > 0)
                snprintf(vol, sizeof(vol), "no %s", e->what);
        else
                snprintf(vol, sizeof(vol), "%s not attached", dev);

        pico_log(e->opts.nofail ? PICO_LOG_INFO : PICO_LOG_WARNING,
                 "fstab: %s after %llums, not mounting %s",
                 vol,
                 (unsigned long long) (timeout / USEC_PER_MSEC),
                 e->where);
        fstab_entry_set_outcome(
                        e,
                        e->opts.nofail ? FSTAB_ABSENT : FSTAB_SKIPPED,
                        "%s after %llums",
                        vol,
                        (unsigned long long) (timeout / USEC_PER_MSEC));
        return false;
}

typedef enum CheckAction {
        CHECK_MOUNT,
        CHECK_MOUNT_RO,
        CHECK_DONT_MOUNT,
} CheckAction;

/*
 * fs_passno > 0: the root check's gate and verdicts, applied to a line's
 * device before it is mounted. An ext filesystem is only handed to its
 * checker when its own superblock says something is wrong; any other type
 * gets fsck.<type> -a whenever it is installed, as upstream's systemd-fsck
 * runs it. A device already mounted somewhere is never checked.
 *
 * The verdicts follow the root check's, divergence included: a checker that
 * could not correct the damage leaves the filesystem mounted read-only rather
 * than not at all, and a checker that itself failed does not stop the mount.
 * "Reboot" -- which for a filesystem not in use should not happen -- leaves it
 * unmounted rather than rebooting a machine over a data partition.
 */
static CheckAction check_filesystem(FstabEntry *e, const char *node, const FstabPassConfig *cfg) {
        char checker[PATH_MAX], elsewhere[PATH_MAX];
        const char *type = e->type;
        PicoFsId id;
        int code = 0, r;

        if (e->passno <= 0)
                return CHECK_MOUNT;

        if (fstab_device_mounted(cfg->mountinfo, node, elsewhere, sizeof(elsewhere)) > 0) {
                pico_log(PICO_LOG_DEBUG, "fstab: %s is mounted on %s already, not checking it", node, elsewhere);
                return CHECK_MOUNT;
        }

        if (strcmp(type, "auto") == 0) {
                if (pico_fs_probe(node, PICO_FS_NONE, &id) <= 0) {
                        pico_log(PICO_LOG_INFO, "fstab: %s: unknown filesystem, not checking it", node);
                        return CHECK_MOUNT;
                }
                type = pico_fs_kind_to_string(id.kind);
        }

        if (pico_fs_kind_from_type(type) == PICO_FS_EXT) {
                PicoExtInfo fs;

                r = ext_super_read(node, &fs);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "fstab: %s: cannot read its superblock: %s, not checking it",
                                 node,
                                 strerror(-r));
                        return CHECK_MOUNT;
                }
                if (r == 0) {
                        pico_log(PICO_LOG_WARNING, "fstab: %s carries no ext filesystem, not checking it", node);
                        return CHECK_MOUNT;
                }
                if (pico_root_verdict(&fs) != PICO_ROOT_CHECK) {
                        pico_log(PICO_LOG_DEBUG, "fstab: %s is clean or only needs its journal, no check", node);
                        return CHECK_MOUNT;
                }
                pico_log(PICO_LOG_WARNING, "fstab: %s is not clean (state 0x%04x), checking it", node, fs.state);
        }

        if ((size_t) snprintf(checker, sizeof(checker), "%s/fsck.%s", cfg->fsck_dir, type) >= sizeof(checker) ||
            access(checker, X_OK) < 0) {
                pico_log(PICO_LOG_INFO, "fstab: %s is not installed, not checking %s", checker, node);
                return CHECK_MOUNT;
        }

        r = pico_fsck_run(checker, node, &code);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING, "fstab: could not run %s on %s: %s", checker, node, strerror(-r));
                return CHECK_MOUNT;
        }

        switch (pico_fsck_verdict(code)) {
        case PICO_FSCK_OK:
                pico_log(PICO_LOG_INFO, "fstab: %s checked%s", node, code ? " and repaired" : "");
                return CHECK_MOUNT;

        case PICO_FSCK_REBOOT:
                pico_log(PICO_LOG_WARNING,
                         "fstab: %s asks for a reboot after repairing %s (exit %d), not mounting it",
                         checker,
                         node,
                         code);
                fstab_entry_set_outcome(e, FSTAB_FAILED, "fsck.%s asks for a reboot (exit %d)", type, code);
                return CHECK_DONT_MOUNT;

        case PICO_FSCK_UNCORRECTED:
                pico_log(PICO_LOG_ERR,
                         "fstab: %s left errors on %s uncorrected (exit %d), mounting it read-only",
                         checker,
                         node,
                         code);
                return CHECK_MOUNT_RO;

        case PICO_FSCK_FAILED:
        default:
                pico_log(PICO_LOG_WARNING,
                         "fstab: %s failed on %s (exit %d), which says nothing about it -- mounting anyway",
                         checker,
                         node,
                         code);
                return CHECK_MOUNT;
        }
}

static void process_entry(FstabEntry *e, const FstabPassConfig *cfg, const UbiAttach *ubi, size_t n_ubi) {
        char where[PATH_MAX], err[512], node[PATH_MAX];
        const char *reason, *source = e->what;
        CheckAction check = CHECK_MOUNT;
        FstabEntry ro;
        UbiSource us;
        uint64_t floor = 0;
        bool api;
        int r;

        if (strcmp(e->where, "/") == 0) {
                /* The root check owns this line and has normally recorded
                 * what it did already. */
                fstab_entry_set_outcome(e, FSTAB_PRESENT, "the root filesystem");
                return;
        }

        if (e->opts.noauto) {
                pico_log(PICO_LOG_DEBUG, "fstab: %s is noauto, leaving it alone", e->where);
                fstab_entry_set_outcome(e, FSTAB_NOAUTO, NULL);
                return;
        }

        reason = skip_reason(e);
        if (reason) {
                pico_log(PICO_LOG_WARNING, "fstab: not mounting %s: %s", e->where, reason);
                fstab_entry_set_outcome(e, FSTAB_SKIPPED, "%s", reason);
                return;
        }

        if (e->where[0] != '/') {
                pico_log(PICO_LOG_WARNING, "fstab: %s is not an absolute path, ignoring the line", e->where);
                fstab_entry_set_outcome(e, FSTAB_FAILED, "the mount point is not an absolute path");
                return;
        }

        if (e->opts.propagation)
                pico_log(PICO_LOG_WARNING, "fstab: %s: ignoring mount propagation options", e->where);

        api = cfg->api_floor(e->where, &floor);

        if (!api) {
                r = fstab_mkdir_p(e->where, 0755);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "fstab: cannot create mount point %s: %s",
                                 e->where,
                                 strerror(-r));
                        fstab_entry_set_outcome(e, FSTAB_FAILED, "mkdir: %s", strerror(-r));
                        return;
                }
        }

        /* The kernel's name for it, which is what mountinfo lists and what
         * move_mount() must be handed: it does not follow a final symlink. */
        if (!realpath(e->where, where))
                snprintf(where, sizeof(where), "%s", e->where);

        /* Not knowing is not the same as not mounted: guessing wrong would
         * stack a second mount on top of the first. */
        r = fstab_is_mounted(cfg->mountinfo, where);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING,
                         "fstab: cannot read %s: %s, not mounting %s",
                         cfg->mountinfo,
                         strerror(-r),
                         where);
                fstab_entry_set_outcome(e, FSTAB_FAILED, "cannot tell whether it is mounted: %s", strerror(-r));
                return;
        }

        if (r > 0) {
                if (!api) {
                        pico_log(PICO_LOG_DEBUG, "fstab: %s is already mounted, leaving it alone", where);
                        fstab_entry_set_outcome(e, FSTAB_PRESENT, "already mounted");
                        return;
                }

                if (fstab_options_trivial(&e->opts)) {
                        fstab_entry_set_outcome(e, FSTAB_PRESENT, "mounted by pico-init, nothing to reapply");
                        return;
                }

                r = fstab_remount(where, &e->opts, floor, err, sizeof(err));
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING, "fstab: cannot reapply %s to %s: %s", e->options, where, err);
                        fstab_entry_set_outcome(e, FSTAB_FAILED, "remount: %s", err);
                        return;
                }

                pico_log(PICO_LOG_INFO, "fstab: reapplied %s to %s", e->options, where);
                fstab_entry_set_outcome(e, FSTAB_REMOUNTED, "%s", e->options);
                return;
        }

        if (strcmp(e->type, "ubifs") == 0 && ubi_source_parse(e->what, &us)) {
                if (!resolve_ubi(e, &us, cfg, ubi, n_ubi))
                        return;
        } else if (!e->opts.bind && !e->opts.rbind && fstab_source_needs_device(e->what)) {
                if (!resolve_source(e, pico_fs_kind_from_type(e->type), cfg, node, sizeof(node)))
                        return;
                source = node;

                check = check_filesystem(e, node, cfg);
                if (check == CHECK_DONT_MOUNT)
                        return;
        }

        /* A shallow copy whose options say read-only: the arrays inside are
         * still e's, and are neither changed nor freed through it. */
        ro = *e;
        if (check == CHECK_MOUNT_RO) {
                ro.opts.attr_set |= MOUNT_ATTR_RDONLY;
                ro.opts.attr_clr &= ~(uint64_t) MOUNT_ATTR_RDONLY;
        }

        r = fstab_mount_from(&ro, source, where, floor, cfg->filesystems, err, sizeof(err));
        if (r < 0) {
                pico_log(PICO_LOG_WARNING, "fstab: cannot mount %s on %s: %s", source, where, err);
                fstab_entry_set_outcome(e, FSTAB_FAILED, "%s", err);
                return;
        }

        pico_log(PICO_LOG_INFO, "fstab: mounted %s on %s (%s)", source, where, e->type);

        if (check == CHECK_MOUNT_RO)
                fstab_entry_set_outcome(e, FSTAB_FAILED, "fsck left errors uncorrected, mounted read-only");
        else if (source != e->what)
                fstab_entry_set_outcome(e, FSTAB_MOUNTED, "%s %s from %s", e->type, e->options, source);
        else
                fstab_entry_set_outcome(e, FSTAB_MOUNTED, "%s %s", e->type, e->options);
}

int fstab_swap_flags(const FstabOptions *o, int *ret_flags) {
        int flags = 0;
        char **d;

        for (d = o ? o->data : NULL; d && *d; d++) {
                if (strncmp(*d, "pri=", 4) == 0) {
                        char *end;
                        long pri;

                        errno = 0;
                        pri = strtol(*d + 4, &end, 10);
                        if (errno != 0 || end == *d + 4 || *end != '\0' || pri < 0 || pri > SWAP_FLAG_PRIO_MASK)
                                return -EINVAL;
                        flags = (flags & ~(SWAP_FLAG_PREFER | SWAP_FLAG_PRIO_MASK)) | SWAP_FLAG_PREFER |
                                        (((int) pri << SWAP_FLAG_PRIO_SHIFT) & SWAP_FLAG_PRIO_MASK);
                } else if (strcmp(*d, "discard") == 0)
                        flags = (flags & ~(SWAP_FLAG_DISCARD_ONCE | SWAP_FLAG_DISCARD_PAGES)) |
                                        SWAP_FLAG_DISCARD;
                else if (strcmp(*d, "discard=once") == 0)
                        flags = (flags & ~SWAP_FLAG_DISCARD_PAGES) | SWAP_FLAG_DISCARD |
                                        SWAP_FLAG_DISCARD_ONCE;
                else if (strcmp(*d, "discard=pages") == 0)
                        flags = (flags & ~SWAP_FLAG_DISCARD_ONCE) | SWAP_FLAG_DISCARD |
                                        SWAP_FLAG_DISCARD_PAGES;
                else
                        pico_log(PICO_LOG_DEBUG, "fstab: ignoring swap option %s", *d);
        }

        *ret_flags = flags;
        return 0;
}

/*
 * A swap line: its device resolved and waited for exactly as a mount line's
 * is (a swap file, not being a device, is looked for once), then swapon()
 * with the line's priority and discard policy. An area already active is
 * the outcome asked for, not a failure.
 */
static void process_swap(FstabEntry *e, const FstabPassConfig *cfg) {
        char node[PATH_MAX];
        struct stat st;
        int flags, r;

        if (e->opts.noauto) {
                pico_log(PICO_LOG_DEBUG, "fstab: swap %s is noauto, leaving it alone", e->what);
                fstab_entry_set_outcome(e, FSTAB_NOAUTO, NULL);
                return;
        }

        if (fstab_swap_flags(&e->opts, &flags) < 0) {
                pico_log(PICO_LOG_WARNING, "fstab: swap %s: bad priority in %s", e->what, e->options);
                fstab_entry_set_outcome(e, FSTAB_FAILED, "bad pri= in %s", e->options);
                return;
        }

        if (fstab_source_needs_device(e->what)) {
                if (!resolve_source(e, PICO_FS_SWAP, cfg, node, sizeof(node)))
                        return;
        } else {
                if (stat(e->what, &st) < 0) {
                        r = -errno;
                        pico_log(PICO_LOG_WARNING, "fstab: swap file %s: %s", e->what, strerror(-r));
                        fstab_entry_set_outcome(e, FSTAB_FAILED, "%s", strerror(-r));
                        return;
                }
                snprintf(node, sizeof(node), "%s", e->what);
        }

        if (cfg->swapon(node, flags) < 0) {
                r = -errno;

                if (r == -EBUSY) {
                        pico_log(PICO_LOG_DEBUG, "fstab: swap on %s is already active", node);
                        fstab_entry_set_outcome(e, FSTAB_PRESENT, "already active");
                        return;
                }

                pico_log(PICO_LOG_WARNING, "fstab: swapon %s: %s", node, strerror(-r));
                fstab_entry_set_outcome(e, FSTAB_FAILED, "swapon: %s", strerror(-r));
                return;
        }

        pico_log(PICO_LOG_INFO, "fstab: swap on %s activated", node);
        fstab_entry_set_outcome(e, FSTAB_ACTIVE, "%s", node);
}

static bool is_swap_line(const FstabEntry *e) {
        return strcmp(e->type, "swap") == 0;
}

/* mkdir -p of the directory `path` lives in. */
static int ensure_parent(const char *path) {
        char dir[PATH_MAX];
        char *slash;

        if (strlen(path) >= sizeof(dir))
                return -ENAMETOOLONG;
        snprintf(dir, sizeof(dir), "%s", path);

        slash = strrchr(dir, '/');
        if (!slash || slash == dir)
                return 0;
        *slash = '\0';

        return fstab_mkdir_p(dir, 0755);
}

int fstab_pass(FstabTable *t, const FstabPassConfig *cfg) {
        FstabPassConfig c = {
                .mountinfo = "/proc/self/mountinfo",
                .filesystems = "/proc/filesystems",
                .record = PICO_FSTAB_RECORD,
                .api_floor = mount_setup_api_floor,
                .sys_root = "/sys",
                .dev_root = "/dev",
                .fsck_dir = "/usr/sbin",
                .device_timeout = FSTAB_DEVICE_TIMEOUT_DEFAULT,
                .swapon = swapon,
                .cmdline = "/proc/cmdline",
        };
        UbiMtdParam params[UBI_ATTACH_MAX];
        FstabEntry **order = NULL;
        UbiAttach *ubi = NULL;
        size_t i, n_ubi = 0;
        int degraded = 0;
        int r;

        if (cfg) {
                if (cfg->mountinfo)
                        c.mountinfo = cfg->mountinfo;
                if (cfg->filesystems)
                        c.filesystems = cfg->filesystems;
                if (cfg->record)
                        c.record = cfg->record;
                if (cfg->api_floor)
                        c.api_floor = cfg->api_floor;
                if (cfg->sys_root)
                        c.sys_root = cfg->sys_root;
                if (cfg->dev_root)
                        c.dev_root = cfg->dev_root;
                if (cfg->fsck_dir)
                        c.fsck_dir = cfg->fsck_dir;
                if (cfg->device_timeout)
                        c.device_timeout = cfg->device_timeout;
                if (cfg->swapon)
                        c.swapon = cfg->swapon;
                c.poll_hook = cfg->poll_hook;
                c.poll_userdata = cfg->poll_userdata;
                if (cfg->cmdline)
                        c.cmdline = cfg->cmdline;
                c.ubi_attach = cfg->ubi_attach;
                c.ubi_attach_userdata = cfg->ubi_attach_userdata;
        }

        r = fstab_mount_order(t, &order);
        if (r < 0)
                return r;

        /* UBI before any line: the kernel would have attached it before PID
         * 1 ran, had UBI been built in. */
        r = ubi_cmdline_load(c.cmdline, params, UBI_ATTACH_MAX);
        if (r < 0 && r != -ENOENT)
                pico_log(PICO_LOG_WARNING, "fstab: cannot read %s: %s", c.cmdline, strerror(-r));
        if (r > 0 && !(ubi = calloc((size_t) r, sizeof(*ubi))))
                pico_log(PICO_LOG_WARNING, "fstab: out of memory, not attaching UBI");
        if (ubi) {
                UbiEnv env = {
                        .sys_root = c.sys_root,
                        .dev_root = c.dev_root,
                        .attach = c.ubi_attach,
                        .attach_userdata = c.ubi_attach_userdata,
                        .poll_hook = c.poll_hook,
                        .poll_userdata = c.poll_userdata,
                };

                n_ubi = (size_t) r;
                for (i = 0; i < n_ubi; i++)
                        ubi_attach_init(&ubi[i], &params[i]);
                (void) ubi_attach_run(ubi, n_ubi, &env, c.device_timeout);
        }

        for (i = 0; i < t->n; i++)
                if (order[i]->outcome == FSTAB_PENDING && !is_swap_line(order[i]))
                        process_entry(order[i], &c, ubi, n_ubi);

        /* Swap last, in file order: a swap file lives on a filesystem the
         * loop above may just have mounted. */
        for (i = 0; i < t->n; i++)
                if (t->entries[i].outcome == FSTAB_PENDING && is_swap_line(&t->entries[i]))
                        process_swap(&t->entries[i], &c);

        free(order);
        free(ubi);

        for (i = 0; i < t->n; i++)
                if (fstab_outcome_is_degraded(t->entries[i].outcome))
                        degraded++;

        r = ensure_parent(c.record);
        if (r >= 0)
                r = fstab_record_write(t, c.record);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "fstab: cannot write %s: %s", c.record, strerror(-r));

        return degraded;
}
