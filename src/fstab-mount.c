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
#include <unistd.h>

#include "manager.h"
#include "mount-setup.h"
#include "util.h"

#ifndef AT_RECURSIVE
#        define AT_RECURSIVE 0x8000
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

        if (fsconfig(fsfd, FSCONFIG_SET_STRING, "source", e->what, 0) < 0) {
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

                r = mount_one_type(e, type, where, floor, last, sizeof(last));
                if (r == 0)
                        break;
        }

        free(line);
        fclose(f);

        if (r < 0)
                snprintf(err, err_size, "no filesystem type could mount it%s%s", last[0] ? ", last: " : "", last);

        return r;
}

int fstab_mount(const FstabEntry *e,
                const char *where,
                uint64_t floor,
                const char *filesystems,
                char *err,
                size_t err_size) {

        if (e->opts.bind || e->opts.rbind)
                return mount_bind(e, where, floor, err, err_size);

        if (strcmp(e->type, "auto") == 0)
                return mount_auto(e, where, floor, filesystems ? filesystems : "/proc/filesystems", err, err_size);

        return mount_one_type(e, e->type, where, floor, err, err_size);
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

/* A source that names a device by an identifier rather than a path. The
 * name before '=' goes into the record. */
static bool source_is_tag(const char *what, char *tag, size_t size) {
        static const char * const tags[] = { "UUID=", "LABEL=", "PARTUUID=", "PARTLABEL=", "ID=" };
        size_t i;

        for (i = 0; i < sizeof(tags) / sizeof(tags[0]); i++)
                if (strncmp(what, tags[i], strlen(tags[i])) == 0) {
                        snprintf(tag, size, "%s", tags[i]);
                        return true;
                }

        return false;
}

/* The lines the pass does not attempt, each with the reason it gives. NULL
 * when the line is one to mount. */
static const char *skip_reason(const FstabEntry *e, char *buf, size_t size) {
        char tag[16];

        if (strcmp(e->type, "swap") == 0)
                return "swap lines are not activated by pico-init";
        if (type_is_network(e->type) || e->opts.netdev)
                return "network filesystem: nothing orders it after the network";
        if (e->opts.automount)
                return "x-systemd.automount is not supported";
        if (e->opts.loop)
                return "loop mounts are not supported";
        if (source_is_tag(e->what, tag, sizeof(tag))) {
                snprintf(buf, size, "%s sources are not resolved by pico-init yet", tag);
                return buf;
        }

        return NULL;
}

static void process_entry(FstabEntry *e, const FstabPassConfig *cfg) {
        char where[PATH_MAX], err[512], buf[128];
        const char *reason;
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

        reason = skip_reason(e, buf, sizeof(buf));
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

        r = fstab_mount(e, where, floor, cfg->filesystems, err, sizeof(err));
        if (r < 0) {
                pico_log(PICO_LOG_WARNING, "fstab: cannot mount %s on %s: %s", e->what, where, err);
                fstab_entry_set_outcome(e, FSTAB_FAILED, "%s", err);
                return;
        }

        pico_log(PICO_LOG_INFO, "fstab: mounted %s on %s (%s)", e->what, where, e->type);
        fstab_entry_set_outcome(e, FSTAB_MOUNTED, "%s %s", e->type, e->options);
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
        };
        FstabEntry **order = NULL;
        int degraded = 0;
        size_t i;
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
        }

        r = fstab_mount_order(t, &order);
        if (r < 0)
                return r;

        for (i = 0; i < t->n; i++)
                if (order[i]->outcome == FSTAB_PENDING)
                        process_entry(order[i], &c);

        free(order);

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
