/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Mounting the API virtual filesystems. See mount-setup.h for why this is
 * PID 1's job and nobody else's.
 *
 * The table and its ordering follow systemd's own mount_setup_early() rather
 * than being invented here: /proc and /sys first because everything else
 * (including the is-it-already-mounted test) wants them, /dev before its own
 * subdirectories, and /sys/fs/cgroup last because it lives inside /sys.
 *
 * The mount flags are not decoration. nosuid/noexec/nodev on the pseudo
 * filesystems is what stops a writable API mount from being a place to stage a
 * setuid binary; systemd carries exactly these and dropping them because
 * "it is only /proc" would be a real weakening.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mount-setup.h"
#include "util.h"

typedef struct MountPoint {
        const char *what;
        const char *where;
        const char *type;
        const char *options;
        unsigned long flags;

        /*
         * Whether booting can continue without it. /proc and /sys are not
         * negotiable -- almost nothing works without them, and continuing
         * would only postpone the failure into somewhere harder to diagnose.
         * The rest are best-effort: a board that reaches a console with a
         * missing /dev/shm is still a board someone can debug.
         */
        bool required;
} MountPoint;

static const MountPoint mount_table[] = {
        {     "proc",          "/proc",     "proc",             NULL,      MS_NOSUID | MS_NOEXEC | MS_NODEV,  true },
        {    "sysfs",           "/sys",    "sysfs",             NULL,      MS_NOSUID | MS_NOEXEC | MS_NODEV,  true },

        /* Usually already mounted by the kernel (CONFIG_DEVTMPFS_MOUNT) or by
         * an initramfs; mounted here only for the case where it is not. */
        { "devtmpfs",           "/dev", "devtmpfs",      "mode=0755",            MS_NOSUID | MS_STRICTATIME, false },

        {   "devpts",       "/dev/pts",   "devpts", "gid=5,mode=620",                 MS_NOSUID | MS_NOEXEC, false },
        {    "tmpfs",       "/dev/shm",    "tmpfs",      "mode=1777", MS_NOSUID | MS_NODEV | MS_STRICTATIME, false },
        {    "tmpfs",           "/run",    "tmpfs",      "mode=0755", MS_NOSUID | MS_NODEV | MS_STRICTATIME, false },

        /*
         * The unified cgroup hierarchy this project's whole supervision layer
         * is built on. Not marked required only because a board with no
         * console is worse than a board with unsupervised services -- but
         * cgroups-v2.c degrades loudly when it is missing, and that warning in
         * the boot log is the thing to chase.
         */
        {  "cgroup2", "/sys/fs/cgroup",  "cgroup2",     "nsdelegate",      MS_NOSUID | MS_NOEXEC | MS_NODEV, false },
};

/*
 * Is `where` already a mount point?
 *
 * Compares the st_dev of the path against that of its parent: a mount point is
 * precisely a path whose device differs from the directory containing it. This
 * works before /proc exists, which /proc/self/mountinfo parsing obviously does
 * not -- and /proc is the first thing this file mounts.
 *
 * The root directory is its own parent, so it would report "not a mount
 * point"; that is fine, nothing in the table is "/".
 */
static bool is_mount_point(const char *where) {
        char parent[PATH_MAX];
        struct stat a, b;
        char *slash;
        size_t len;

        if (stat(where, &a) < 0)
                return false;

        len = strlen(where);
        if (len == 0 || len >= sizeof(parent))
                return false;

        memcpy(parent, where, len + 1);

        slash = strrchr(parent, '/');
        if (!slash)
                return false;

        if (slash == parent)
                parent[1] = '\0'; /* "/foo" -> "/" */
        else
                *slash = '\0';

        if (stat(parent, &b) < 0)
                return false;

        return a.st_dev != b.st_dev;
}

/* Create the mount point if it is missing. Failure is the caller's problem. */
static int make_dir(const char *where) {
        if (mkdir(where, 0755) < 0 && errno != EEXIST)
                return -errno;

        return 0;
}

int mount_setup(void) {
        size_t i;
        int n = 0;

        for (i = 0; i < sizeof(mount_table) / sizeof(mount_table[0]); i++) {
                const MountPoint *p = &mount_table[i];
                int r;

                if (is_mount_point(p->where)) {
                        pico_log(PICO_LOG_DEBUG, "%s is already mounted, leaving it alone", p->where);
                        continue;
                }

                r = make_dir(p->where);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING, "%s: cannot create mount point: %s", p->where, strerror(-r));
                        if (p->required)
                                return r;
                        continue;
                }

                if (mount(p->what, p->where, p->type, p->flags, p->options) < 0) {
                        /* EBUSY means something got there first, which is a
                         * success for our purposes rather than a failure. */
                        if (errno == EBUSY) {
                                pico_log(PICO_LOG_DEBUG, "%s was mounted concurrently, continuing", p->where);
                                continue;
                        }

                        pico_log(PICO_LOG_WARNING, "%s: mount %s failed: %s", p->where, p->type, strerror(errno));

                        if (p->required)
                                return -errno;

                        continue;
                }

                pico_log(PICO_LOG_DEBUG, "mounted %s on %s", p->type, p->where);
                n++;
        }

        return n;
}

/*
 * dev_setup(): the five /dev symlinks, from scratch.
 *
 * PROVENANCE. This is a from-scratch reimplementation, not a quarry -- written
 * after reading the real upstream function and its whole history, but copying
 * none of it. Two reasons, both concrete. Upstream's dev_setup()
 * (src/shared/dev-setup.c, LGPL-2.1-or-later today) is a NULSTR_FOREACH_PAIR
 * over a packed string literal calling symlink_label(), which is a
 * mac_selinux_create_file_prepare()/mac_smack_fix() sandwich -- carrying it
 * would mean carrying the label layer or gutting it until nothing of the
 * original remained. And what is actually being reused is a five-entry table
 * of well-known paths, which is interface, not implementation. The file stays
 * GPL-2.0-or-later with only this project's own copyright, on the same footing
 * as netd-rtnl.c, which reads sd-netlink's message constructors as a design
 * reference and lifts nothing.
 *
 * The history was reviewed the way the quarrying discipline requires, and the
 * enumeration itself has a trap worth recording: the code was split out of
 * src/core/mount-setup.c into src/shared/dev-setup.c by 5ba2dc259f rather than
 * renamed, so `git log --follow -- src/shared/dev-setup.c` gives 46 commits and
 * silently drops everything before 2012. The real window is the union with
 * src/mount-setup.c + src/core/mount-setup.c back to the table's origin in
 * 5c0532d1cc (2010-10-27): 85 commits, of which most touched licence headers,
 * includes, or the other functions that later joined that file.
 *
 * Adopted from that history, each for its own reason:
 *
 *  - 5c0532d1cc "mounts: automatically create /dev/stderr and friends early on
 *    boot" -- the table itself and the fact that PID 1 owns it, because
 *    scripts running before any device manager need these.
 *  - 8f0e73f250 "dev-setup: allow a path prefix for use in chroots" -- the
 *    prefix parameter. mount-setup.c's own functions take no test root (they
 *    mount real filesystems, so there is nothing to point elsewhere), so the
 *    pattern followed here is the one the Manager's settable unit/preset/
 *    runtime paths use: the caller supplies the root, and production passes
 *    the real one.
 *  - 01ed0e2307 "dev-setup: make NULL as parameter for dev_setup() equivalent
 *    to ''" -- NULL prefix means no prefix, rather than composing a path with
 *    a literal "(null)" in it.
 *  - 696fee7d95 "dev-setup: do not create a dangling /proc/kcore symlink" --
 *    /dev/core is skipped when the kernel has no CONFIG_PROC_KCORE. It is the
 *    only conditional entry; the other four sources are always present.
 *  - 2b85f4e19c "core: Beef up PrivateDevices=" -- the explicit `access() < 0`
 *    spelling. Worth naming even though the bare-truth-test version happened
 *    to behave the same, because `if (access(...))` reads as "if it exists"
 *    and means the opposite.
 *  - 7f112f50fe "exec: introduce PrivateDevices=" and 03cfe0d514 "nspawn:
 *    finish user namespace support" -- between them these turned dev_setup()
 *    from void into int and gave it any error handling at all. Before that
 *    every failure was silent.
 *
 * Deliberately NOT adopted, each a real behavioural difference:
 *
 *  - symlink_label() and the MAC layer under it. No SELinux, no SMACK.
 *  - The uid/gid parameters and their lchown(). Those exist only for nspawn's
 *    user namespaces (03cfe0d514); PID 1 here is real root and upstream itself
 *    passes UID_INVALID/GID_INVALID on that path, skipping the chown.
 *  - Upstream's "return 0 whatever happened" contract. Its own two callers
 *    discard the result -- one bare, one explicitly (void)-cast -- so the
 *    return value carries no information. This one counts.
 *  - Upstream's non-idempotence. This is the sharpest difference, and it is a
 *    divergence rather than a gap: upstream calls symlink() and logs EEXIST at
 *    debug, so a /dev/stdout that already points somewhere wrong stays wrong
 *    forever -- first boot wins. symlink_idempotent() exists in the tree and
 *    dev_setup() has never used it. Repair is cheap here and is what makes
 *    "idempotent" mean more than "the second call fails quietly", so a link
 *    whose target is wrong is replaced atomically.
 *
 * The one thing that is deliberately kept exactly as upstream has it, because
 * changing it would be a silent behaviour change: an existing NON-symlink at
 * one of these paths is left alone and warned about, never unlinked. /dev/core
 * being a real file is somebody's decision, not this function's to reverse --
 * the same reasoning socket.c's S_ISSOCK guard already applies to unlinking a
 * stale bind path.
 */
typedef struct DevSymlink {
        const char *target; /* what the link points at; never prefixed */
        const char *link;   /* absolute path of the link itself */

        /*
         * Skip the entry when the target does not exist. Only /proc/kcore
         * needs it (696fee7d95): a kernel built without CONFIG_PROC_KCORE
         * would otherwise get a dangling /dev/core.
         */
        bool optional;
} DevSymlink;

/*
 * Upstream's order, kept: core, fd, stdin, stdout, stderr. Nothing depends on
 * it -- these are five independent symlinks -- but matching it costs nothing
 * and keeps a listing of /dev comparable against a systemd image.
 */
static const DevSymlink dev_symlinks[] = {
        {     "/proc/kcore",   "/dev/core",  true },
        {   "/proc/self/fd",     "/dev/fd", false },
        { "/proc/self/fd/0",  "/dev/stdin", false },
        { "/proc/self/fd/1", "/dev/stdout", false },
        { "/proc/self/fd/2", "/dev/stderr", false },
};

/*
 * Create `link` -> `target`, or leave it alone if it is already right.
 *
 * Returns 1 when the link is now correct, 0 when it was left as something else
 * on purpose, or -errno.
 */
static int symlink_idempotent(const char *target, const char *link) {
        char buf[PATH_MAX];
        struct stat st;
        ssize_t n;

        if (symlink(target, link) == 0)
                return 1;

        if (errno != EEXIST)
                return -errno;

        /*
         * Something is there. lstat, not stat: the question is what the entry
         * itself is, and stat() would follow a symlink and answer about
         * /proc/self/fd instead.
         */
        if (lstat(link, &st) < 0)
                return -errno;

        if (!S_ISLNK(st.st_mode)) {
                pico_log(PICO_LOG_WARNING, "%s exists and is not a symlink, leaving it alone", link);
                return 0;
        }

        n = readlink(link, buf, sizeof(buf) - 1);
        if (n < 0)
                return -errno;

        buf[n] = '\0';

        if (strcmp(buf, target) == 0)
                return 1; /* already exactly right */

        /*
         * A symlink pointing somewhere else. Replace it atomically rather than
         * unlink-then-symlink: a reader between the two would find nothing at
         * a path that is supposed to always resolve. rename() over an existing
         * symlink is atomic, so there is no such window.
         */
        {
                char tmp[PATH_MAX];
                int len;

                len = snprintf(tmp, sizeof(tmp), "%s.pico-tmp", link);
                if (len < 0 || (size_t) len >= sizeof(tmp))
                        return -ENAMETOOLONG;

                (void) unlink(tmp); /* a leftover from an interrupted earlier run */

                if (symlink(target, tmp) < 0)
                        return -errno;

                if (rename(tmp, link) < 0) {
                        int r = -errno;
                        (void) unlink(tmp);
                        return r;
                }
        }

        pico_log(PICO_LOG_DEBUG, "%s pointed at %s, repointed at %s", link, buf, target);
        return 1;
}

int dev_setup(const char *prefix) {
        size_t i;
        int n = 0;

        for (i = 0; i < sizeof(dev_symlinks) / sizeof(dev_symlinks[0]); i++) {
                const DevSymlink *s = &dev_symlinks[i];
                char path[PATH_MAX];
                const char *link;
                int r;

                /*
                 * The target is checked unprefixed on purpose, and this is the
                 * one place the prefix is deliberately asymmetric. The link
                 * this creates says "/proc/kcore" literally whatever the
                 * prefix is, so what decides whether that link would dangle is
                 * the running kernel's own /proc, not anything under the test
                 * root. Upstream has the same asymmetry without saying so.
                 */
                if (s->optional && access(s->target, F_OK) < 0) {
                        pico_log(PICO_LOG_DEBUG, "%s does not exist, skipping %s", s->target, s->link);
                        continue;
                }

                if (prefix) {
                        int len = snprintf(path, sizeof(path), "%s%s", prefix, s->link);

                        if (len < 0 || (size_t) len >= sizeof(path))
                                return -ENAMETOOLONG;

                        link = path;
                } else
                        link = s->link;

                r = symlink_idempotent(s->target, link);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING, "%s: cannot create symlink: %s", link, strerror(-r));
                        continue;
                }

                n += r;
        }

        return n;
}

void sysctl_setup(void) {
        static const struct {
                const char *path;
                const char *value;
        } tunables[] = {
                { "/proc/sys/net/unix/max_dgram_qlen", "64\n" },
        };
        size_t i;

        for (i = 0; i < sizeof(tunables) / sizeof(tunables[0]); i++) {
                ssize_t len = (ssize_t) strlen(tunables[i].value);
                int fd;

                fd = open(tunables[i].path, O_WRONLY | O_CLOEXEC);
                if (fd < 0) {
                        pico_log(PICO_LOG_DEBUG, "%s: %s", tunables[i].path, strerror(errno));
                        continue;
                }

                if (write(fd, tunables[i].value, (size_t) len) != len)
                        pico_log(PICO_LOG_DEBUG, "%s: write: %s", tunables[i].path, strerror(errno));

                close(fd);
        }
}
