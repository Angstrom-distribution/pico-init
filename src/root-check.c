/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The root filesystem check, and the remount that ends it. root-check.h has the
 * reasoning, the three divergences from upstream, and the exit-code table.
 */

#include "root-check.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>

#include "fstab-mount.h"
#include "gpt-scan.h"
#include "util.h"

/*
 * The checker, by absolute path rather than through $PATH: this runs as PID 1
 * with whatever environment the kernel handed it, and a filesystem repair tool
 * is not a thing to go looking for.
 *
 * e2fsprogs-e2fsck is not installed on any image this project builds today, so
 * the access() below is the branch every current boot takes. That is a
 * deliberate ordering -- this code lands first and warns, the package lands
 * separately -- and not an oversight.
 */
#define PICO_FSCK_EXT4 "/usr/sbin/fsck.ext4"

/* fsck(8)'s exit bits. They OR together, so every test below is a mask. */
#define FSCK_CORRECTED 1
#define FSCK_SYSTEM_SHOULD_REBOOT 2
#define FSCK_ERRORS_LEFT_UNCORRECTED 4
#define FSCK_OPERATIONAL_ERROR 8

PicoRootVerdict pico_root_verdict(const PicoExtInfo *fs) {
        bool dirty;

        if (!fs)
                return PICO_ROOT_CHECK;

        /*
         * The kernel's own record that it hit an inconsistency on this
         * filesystem. Nothing else here outranks it, and in particular a
         * journal does not: replaying a journal onto a filesystem already known
         * to be inconsistent is not a repair.
         */
        if (fs->state & EXT_STATE_ERROR_FS)
                return PICO_ROOT_CHECK;

        /*
         * Four separate ways of saying "this was not cleanly unmounted", and
         * all four have to be asked. VALID_FS clear is the ordinary one;
         * RECOVER is the journal saying it holds unreplayed transactions;
         * ORPHAN_FS and a non-zero s_last_orphan are inodes that were being
         * deleted when it stopped.
         */
        dirty = !(fs->state & EXT_STATE_VALID_FS) || (fs->feature_incompat & EXT_FEATURE_INCOMPAT_RECOVER) ||
                        (fs->state & EXT_STATE_ORPHAN_FS) || fs->last_orphan != 0;

        if (!dirty)
                return PICO_ROOT_CLEAN;

        /*
         * Dirty but journalled, and with no error recorded. The kernel replays
         * the journal and cleans the orphan list itself when the filesystem is
         * mounted read-write, which the remount below is about to do -- and it
         * does it in a fraction of the time a full check would take, to the
         * same end. Running e2fsck here would be slower and no safer.
         */
        if (fs->feature_compat & EXT_FEATURE_COMPAT_HAS_JOURNAL)
                return PICO_ROOT_REPLAY;

        /* Dirty with no journal to recover from: nothing but a checker can
         * make this filesystem consistent again. */
        return PICO_ROOT_CHECK;
}

PicoFsckVerdict pico_fsck_verdict(int code) {
        if (code < 0)
                return PICO_FSCK_FAILED;

        /* Clean, or corrected. Bit 0 on its own is a repair that succeeded. */
        if ((code & ~FSCK_CORRECTED) == 0)
                return PICO_FSCK_OK;

        /* Tested before "uncorrected", following upstream's own ordering in
         * src/fsck.c: of the two things a combined status can be saying, a
         * kernel running on stale cached metadata is the more urgent. */
        if (code & FSCK_SYSTEM_SHOULD_REBOOT)
                return PICO_FSCK_REBOOT;

        if (code & FSCK_ERRORS_LEFT_UNCORRECTED)
                return PICO_FSCK_UNCORRECTED;

        /* 8, 16, 32, 128, and anything nobody has documented: the checker
         * failed, which says nothing at all about the filesystem. */
        return PICO_FSCK_FAILED;
}

/*
 * Run `checker` over `node` and hand back its exit code.
 *
 * `-a` is preen mode: repair what can be repaired without asking, and give up
 * rather than guess at anything else. Never `-y` -- an appliance with no
 * session in front of it must not be answering "yes" to questions about
 * destroying data on its own root filesystem.
 *
 * No `-M`, which means "skip mounted filesystems" and would make this whole
 * step a no-op: root genuinely is mounted, read-only, which is exactly the
 * state this is checking it in. Upstream accepts the same hazard on the same
 * path and calls it "ugly, but it is how it is"; the superblock gate above is
 * what keeps it to the cases where doing nothing is worse.
 *
 * No `-T` either, despite it appearing in every description of the upstream
 * invocation: `-T` is a flag of the fsck(8) dispatcher, not of e2fsck. Passing
 * it to fsck.ext4 directly is a usage error and exits 16 -- verified against
 * e2fsprogs 1.47, where `fsck.ext4 -a -T <image>` fails on every filesystem,
 * clean or not.
 *
 * Returns 0 with *ret_code set, or -errno when the checker could not be run or
 * did not exit normally at all.
 */
int pico_fsck_run(const char *checker, const char *node, int *ret_code) {
        const char *name;
        pid_t pid;
        int status;

        if (!checker || !node || !ret_code)
                return -EINVAL;

        name = strrchr(checker, '/');
        name = name ? name + 1 : checker;

        pid = fork();
        if (pid < 0)
                return -errno;

        if (pid == 0) {
                execl(checker, name, "-a", node, (char *) NULL);

                /* An exec that did not happen is an operational error in
                 * fsck(8)'s own vocabulary, which is what the parent's mapping
                 * already knows how to read. */
                _exit(FSCK_OPERATIONAL_ERROR);
        }

        while (waitpid(pid, &status, 0) < 0) {
                if (errno == EINTR)
                        continue;

                return -errno;
        }

        if (!WIFEXITED(status)) {
                pico_log(PICO_LOG_WARNING,
                         "%s on %s was killed by signal %d",
                         name,
                         node,
                         WIFSIGNALED(status) ? WTERMSIG(status) : 0);
                return -EIO;
        }

        *ret_code = WEXITSTATUS(status);
        return 0;
}

int pico_root_remount(const char *where, FstabEntry *root_line) {
        const FstabOptions *o = root_line ? &root_line->opts : NULL;
        bool want_ro = o && (o->attr_set & MOUNT_ATTR_RDONLY);
        char err[512];
        int r;

        r = fstab_remount(where, o, 0, err, sizeof(err));
        if (r < 0 && o && !want_ro) {
                /* What the line asks for is not worth a read-only root. */
                pico_log(PICO_LOG_WARNING,
                         "cannot apply /etc/fstab's options (%s) to the root filesystem: %s -- "
                         "remounting it read-write without them",
                         root_line->options,
                         err);
                fstab_entry_set_outcome(root_line, FSTAB_FAILED, "options not applied: %s", err);

                r = fstab_remount(where, NULL, 0, err, sizeof(err));
                if (r == 0) {
                        pico_log(PICO_LOG_INFO, "the root filesystem is now mounted read-write");
                        return PICO_ROOT_CONTINUE;
                }
        }

        if (r < 0) {
                pico_log(PICO_LOG_ERR,
                         "could not remount the root filesystem %s: %s",
                         want_ro ? "with its /etc/fstab options" : "read-write",
                         err);
                fstab_entry_set_outcome(root_line, FSTAB_FAILED, "%s", err);
                return r;
        }

        if (want_ro)
                pico_log(PICO_LOG_INFO, "the root filesystem stays read-only, as /etc/fstab asks");
        else
                pico_log(PICO_LOG_INFO, "the root filesystem is now mounted read-write");

        fstab_entry_set_outcome(root_line, FSTAB_REMOUNTED, "%s", root_line ? root_line->options : "rw");
        return PICO_ROOT_CONTINUE;
}

int pico_root_check(FstabEntry *root_line) {
        char part[PATH_MAX];
        PicoExtInfo fs;
        bool read_only = false;
        int code = 0;
        int r;

        r = gpt_boot_root("/proc/self/mountinfo", NULL, 0, NULL, 0, part, sizeof(part), &read_only);

        /*
         * The branch every image built today takes, because nothing has flipped
         * `rw` to `ro` on any of these kernel command lines yet. It has to be
         * correct and cheap on an ordinary boot, and it is: one file read, no
         * device opened, and no remount unless fstab's "/" line asks for one.
         *
         * `read_only` is answered by the mountinfo line alone, so it is
         * trustworthy even when the call went on to fail for want of a block
         * device -- and false when there was no line to read at all, which is
         * the case the r < 0 arm below distinguishes.
         */
        if (!read_only) {
                /* Nothing to check on a root already in use read-write, but
                 * fstab may still ask for "ro" or an option it lacks. */
                if (root_line && !fstab_options_trivial(&root_line->opts)) {
                        pico_log(PICO_LOG_INFO,
                                 "the root filesystem is read-write, applying /etc/fstab's options (%s)",
                                 root_line->options);
                        return pico_root_remount("/", root_line);
                }

                fstab_entry_set_outcome(root_line, FSTAB_PRESENT, "read-write, not checked");

                if (r < 0)
                        pico_log(r == -ENOENT ? PICO_LOG_DEBUG : PICO_LOG_WARNING,
                                 "the root filesystem has no block device under it (%s), nothing to check",
                                 strerror(-r));
                else
                        pico_log(PICO_LOG_INFO,
                                 "the root filesystem is already mounted read-write, not checking it");

                return PICO_ROOT_CONTINUE;
        }

        /*
         * From here root IS read-only, so this function owes the rest of the
         * boot either the root fstab asks for -- read-write, unless its "/"
         * line says "ro" -- or a logged reason why not. An
         * unidentifiable device is not such a reason -- a machine sitting at a
         * console with a writable root is worth more than one that is right
         * about which node it is on.
         */
        if (r < 0) {
                pico_log(PICO_LOG_WARNING,
                         "the root filesystem is read-only but its device could not be identified (%s), "
                         "remounting it unchecked",
                         strerror(-r));
                return pico_root_remount("/", root_line);
        }

        r = ext_super_read(part, &fs);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING,
                         "%s: cannot read the filesystem superblock: %s, remounting it unchecked",
                         part,
                         strerror(-r));
                return pico_root_remount("/", root_line);
        }

        if (r == 0) {
                pico_log(PICO_LOG_INFO, "%s carries no ext filesystem, nothing here can check it", part);
                return pico_root_remount("/", root_line);
        }

        switch (pico_root_verdict(&fs)) {
        case PICO_ROOT_CLEAN:
                pico_log(PICO_LOG_DEBUG, "%s is marked clean, no check needed", part);
                return pico_root_remount("/", root_line);

        case PICO_ROOT_REPLAY:
                pico_log(PICO_LOG_INFO,
                         "%s has an unreplayed journal; the kernel will recover it on the remount",
                         part);
                return pico_root_remount("/", root_line);

        case PICO_ROOT_CHECK:
                break;
        }

        pico_log(PICO_LOG_WARNING,
                 "%s is not clean (state 0x%04x, orphan inode %u), checking it",
                 part,
                 (unsigned) fs.state,
                 (unsigned) fs.last_orphan);

        /*
         * The other branch every image takes today: e2fsprogs-e2fsck is not
         * installed anywhere yet. Warn and go on -- refusing to boot over a
         * missing tool would be a worse outcome than mounting a filesystem the
         * kernel was going to mount anyway.
         */
        if (access(PICO_FSCK_EXT4, X_OK) < 0) {
                pico_log(PICO_LOG_WARNING, "%s is not installed, remounting %s unchecked", PICO_FSCK_EXT4, part);
                return pico_root_remount("/", root_line);
        }

        r = pico_fsck_run(PICO_FSCK_EXT4, part, &code);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING,
                         "could not run %s on %s: %s, remounting unchecked",
                         PICO_FSCK_EXT4,
                         part,
                         strerror(-r));
                return pico_root_remount("/", root_line);
        }

        switch (pico_fsck_verdict(code)) {
        case PICO_FSCK_OK:
                pico_log(PICO_LOG_INFO, "%s checked%s", part, code ? " and repaired" : "");
                return pico_root_remount("/", root_line);

        case PICO_FSCK_REBOOT:
                /*
                 * The repair happened underneath a kernel holding the old
                 * metadata, so nothing may use this filesystem until the
                 * machine restarts. Left to main(), which owns the one
                 * sync()/reboot() path this init has.
                 *
                 * Not guarded against repeating: /run is a tmpfs and survives
                 * nothing, so there is no marker to leave. A filesystem that
                 * comes back with the same verdict every boot would loop, and
                 * the honest state of this is that the guard is an open design
                 * question (plans/29 §10, open item 6c) rather than something
                 * to invent here. What is here instead is a log line naming the
                 * reason on every pass, so a loop is legible in the kernel ring
                 * rather than silent.
                 */
                pico_log(PICO_LOG_ERR,
                         "%s was repaired and %s asks for a reboot (exit %d) -- rebooting",
                         part,
                         PICO_FSCK_EXT4,
                         code);
                return PICO_ROOT_REBOOT;

        case PICO_FSCK_UNCORRECTED:
                /*
                 * The deliberate divergence from upstream's emergency.target.
                 * The rest of the boot goes ahead with root read-only, which on
                 * a machine with no session to act from is strictly more useful
                 * than an emergency shell nobody is sitting in front of.
                 */
                pico_log(PICO_LOG_ERR,
                         "%s has errors %s could not correct (exit %d) -- leaving the root filesystem "
                         "read-only and booting on",
                         part,
                         PICO_FSCK_EXT4,
                         code);
                fstab_entry_set_outcome(
                                root_line,
                                FSTAB_FAILED,
                                "%s left errors uncorrected, kept read-only",
                                PICO_FSCK_EXT4);
                return PICO_ROOT_CONTINUE;

        case PICO_FSCK_FAILED:
        default:
                pico_log(PICO_LOG_WARNING,
                         "%s failed on %s (exit %d), which says nothing about the filesystem -- "
                         "remounting anyway",
                         PICO_FSCK_EXT4,
                         part,
                         code);
                return pico_root_remount("/", root_line);
        }
}
