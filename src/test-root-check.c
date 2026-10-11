/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The root check: its two decision tables as values, and its remount -- the
 * part that honours /etc/fstab's "/" line -- against real mounts.
 *
 * The decision tables are pure functions -- a superblock in, a verdict out; an
 * exit code in, a verdict out. Getting the superblock gate wrong means either
 * never checking a damaged root or checking a healthy one on every boot;
 * getting the exit-code table wrong means remounting a filesystem e2fsck just
 * said it could not repair.
 *
 * The remount runs inside a private user + mount namespace (test-util.h),
 * against a tmpfs standing in for the root. pico_root_remount() is driven
 * directly on it, and pico_root_check() itself is driven end to end by a child
 * chroot()ed into that tmpfs with /proc bound in, where the tmpfs IS "/" in the
 * child's mountinfo: no block device under it, so the check takes the
 * "device could not be identified" arm on a read-only root and the early arm on
 * a read-write one -- both of which end in the remount under test. The fsck
 * half still needs a damaged ext4 filesystem and is left to booting on a target
 * through the read-only window.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ext-super.h"
#include "fstab.h"
#include "root-check.h"
#include "test-util.h"

/* A superblock as mke2fs leaves one: cleanly unmounted, journalled, nothing
 * outstanding. Every case below starts here and breaks exactly one thing. */
static PicoExtInfo clean_fs(void) {
        PicoExtInfo fs;

        memset(&fs, 0, sizeof(fs));
        fs.state = EXT_STATE_VALID_FS;
        fs.feature_compat = EXT_FEATURE_COMPAT_HAS_JOURNAL;

        return fs;
}

static void test_root_verdict(void) {
        PicoExtInfo fs;

        /* The case that must cost nothing: a clean filesystem never reaches a
         * checker at all. */
        fs = clean_fs();
        ASSERT_EQ_INT(pico_root_verdict(&fs), PICO_ROOT_CLEAN);

        /* The kernel's own error record outranks everything, journal
         * included -- replaying a journal onto a filesystem already known to
         * be inconsistent is not a repair. */
        fs = clean_fs();
        fs.state |= EXT_STATE_ERROR_FS;
        ASSERT_EQ_INT(pico_root_verdict(&fs), PICO_ROOT_CHECK);

        /* ...including when VALID_FS is still set alongside it, which is what
         * a kernel that remounted read-only on error leaves behind. An
         * equality test on s_state would read this as clean. */
        fs = clean_fs();
        fs.state = EXT_STATE_VALID_FS | EXT_STATE_ERROR_FS;
        ASSERT_EQ_INT(pico_root_verdict(&fs), PICO_ROOT_CHECK);

        /* Not cleanly unmounted, but journalled: the kernel's own recovery on
         * the remount does this faster and to the same end. */
        fs = clean_fs();
        fs.state = 0;
        ASSERT_EQ_INT(pico_root_verdict(&fs), PICO_ROOT_REPLAY);

        /* The journal saying so itself, with VALID_FS still set. */
        fs = clean_fs();
        fs.feature_incompat |= EXT_FEATURE_INCOMPAT_RECOVER;
        ASSERT_EQ_INT(pico_root_verdict(&fs), PICO_ROOT_REPLAY);

        /* Orphan inodes, by either of the two fields that record them. */
        fs = clean_fs();
        fs.state |= EXT_STATE_ORPHAN_FS;
        ASSERT_EQ_INT(pico_root_verdict(&fs), PICO_ROOT_REPLAY);

        fs = clean_fs();
        fs.last_orphan = 12;
        ASSERT_EQ_INT(pico_root_verdict(&fs), PICO_ROOT_REPLAY);

        /* Dirty with no journal to recover from -- an ext2 filesystem, or an
         * ext4 one built without one. Nothing but a checker can fix this. */
        fs = clean_fs();
        fs.state = 0;
        fs.feature_compat = 0;
        ASSERT_EQ_INT(pico_root_verdict(&fs), PICO_ROOT_CHECK);

        fs = clean_fs();
        fs.feature_compat = 0;
        fs.last_orphan = 12;
        ASSERT_EQ_INT(pico_root_verdict(&fs), PICO_ROOT_CHECK);

        /* A clean unjournalled filesystem is still clean. */
        fs = clean_fs();
        fs.feature_compat = 0;
        ASSERT_EQ_INT(pico_root_verdict(&fs), PICO_ROOT_CLEAN);

        /* Unrelated feature bits in the same words change nothing. The real
         * 0x3c/0x2c2 pair a default mke2fs writes is the case this stands
         * for, and a mask confused for an equality test is what it catches. */
        fs = clean_fs();
        fs.feature_compat = 0x0000003cU;
        fs.feature_incompat = 0x000002c2U;
        ASSERT_EQ_INT(pico_root_verdict(&fs), PICO_ROOT_CLEAN);

        fs.feature_incompat = 0x000002c6U; /* the same, plus needs_recovery */
        ASSERT_EQ_INT(pico_root_verdict(&fs), PICO_ROOT_REPLAY);

        /* No superblock at all is not an excuse to skip a check. */
        ASSERT_EQ_INT(pico_root_verdict(NULL), PICO_ROOT_CHECK);
}

static void test_fsck_verdict(void) {
        /* The two codes that mean the filesystem is usable. */
        ASSERT_EQ_INT(pico_fsck_verdict(0), PICO_FSCK_OK);
        ASSERT_EQ_INT(pico_fsck_verdict(1), PICO_FSCK_OK);

        /* The two that are about the filesystem and are not. */
        ASSERT_EQ_INT(pico_fsck_verdict(2), PICO_FSCK_REBOOT);
        ASSERT_EQ_INT(pico_fsck_verdict(4), PICO_FSCK_UNCORRECTED);

        /* Everything else says the checker failed, not the filesystem:
         * operational error, usage error, cancelled, shared-library error. */
        ASSERT_EQ_INT(pico_fsck_verdict(8), PICO_FSCK_FAILED);
        ASSERT_EQ_INT(pico_fsck_verdict(16), PICO_FSCK_FAILED);
        ASSERT_EQ_INT(pico_fsck_verdict(32), PICO_FSCK_FAILED);
        ASSERT_EQ_INT(pico_fsck_verdict(128), PICO_FSCK_FAILED);

        /*
         * The codes OR together, and the combinations are what a table written
         * as a switch would get wrong. 3 is the one e2fsck really returns for
         * "repaired, now reboot" -- corrected AND should-reboot -- so a test
         * for equality against 2 would miss every real occurrence of it.
         */
        ASSERT_EQ_INT(pico_fsck_verdict(1 | 2), PICO_FSCK_REBOOT);
        ASSERT_EQ_INT(pico_fsck_verdict(1 | 4), PICO_FSCK_UNCORRECTED);

        /* "Should reboot" outranks "uncorrected", following upstream's own
         * ordering: a kernel on stale cached metadata is the more urgent of
         * the two things a combined status can be saying. */
        ASSERT_EQ_INT(pico_fsck_verdict(2 | 4), PICO_FSCK_REBOOT);
        ASSERT_EQ_INT(pico_fsck_verdict(1 | 2 | 4), PICO_FSCK_REBOOT);

        /* An operational error alongside a real verdict does not downgrade
         * it: the filesystem half of the status is still what it says. */
        ASSERT_EQ_INT(pico_fsck_verdict(4 | 8), PICO_FSCK_UNCORRECTED);
        ASSERT_EQ_INT(pico_fsck_verdict(2 | 8), PICO_FSCK_REBOOT);

        /* Nonsense in, no crash out, and never a verdict that would lead to a
         * remount of something unchecked. */
        ASSERT_EQ_INT(pico_fsck_verdict(-1), PICO_FSCK_FAILED);
        ASSERT_EQ_INT(pico_fsck_verdict(64), PICO_FSCK_FAILED);
        ASSERT_EQ_INT(pico_fsck_verdict(255), PICO_FSCK_REBOOT);
}

static char scratch[PATH_MAX];

/* A tmpfs at <scratch>/<name>, read-only or not, standing in for the root. The
 * scaffolding uses plain mount(2) on purpose: it must not share a bug with the
 * code under test. With `proc`, /proc is bound in first so a chroot there
 * still has a mountinfo to read. */
static void make_root(char *where, size_t size, const char *name, bool ro, bool proc) {
        char p[PATH_MAX + 8];
        int n;

        n = snprintf(where, size, "%s/%s", scratch, name);
        ASSERT_TRUE(n > 0 && (size_t) n < size);
        ASSERT_TRUE(mkdir(where, 0755) == 0);
        ASSERT_TRUE(mount("tmpfs", where, "tmpfs", 0, "size=1m") == 0);

        if (proc) {
                snprintf(p, sizeof(p), "%s/proc", where);
                ASSERT_TRUE(mkdir(p, 0755) == 0);
                ASSERT_TRUE(mount("/proc", p, NULL, MS_BIND | MS_REC, NULL) == 0);
        }

        if (ro)
                ASSERT_TRUE(mount(NULL, where, NULL, MS_REMOUNT | MS_RDONLY, "size=1m") == 0);
}

/* The stock root line with its options field replaced. */
static void root_line(FstabEntry *e, const char *options) {
        char line[256];

        snprintf(line, sizeof(line), "/dev/root / auto %s 1 1", options);
        ASSERT_EQ_INT(fstab_parse_line(line, e), 1);
}

static bool is_rw(const char *where) {
        char vfs[1024], sb[1024];

        ASSERT_TRUE(test_mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        /* Both halves or neither: a writable mount of a read-only superblock
         * (or the reverse) is still a read-only root. */
        ASSERT_EQ_INT(test_has_opt(vfs, "rw"), test_has_opt(sb, "rw"));
        return test_has_opt(vfs, "rw");
}

static void test_root_remount(void) {
        char where[PATH_MAX], vfs[1024], sb[1024];
        FstabEntry e;

        /* No "/" line: read-write, exactly what the check always did. */
        make_root(where, sizeof(where), "no-line", true, false);
        ASSERT_TRUE(!is_rw(where));
        ASSERT_EQ_INT(pico_root_remount(where, NULL), PICO_ROOT_CONTINUE);
        ASSERT_TRUE(is_rw(where));

        /* The stock line: read-write, and the outcome recorded on it. */
        make_root(where, sizeof(where), "defaults", true, false);
        root_line(&e, "defaults");
        ASSERT_EQ_INT(pico_root_remount(where, &e), PICO_ROOT_CONTINUE);
        ASSERT_TRUE(is_rw(where));
        ASSERT_EQ_INT(e.outcome, FSTAB_REMOUNTED);
        ASSERT_STREQ(e.reason, "defaults");
        fstab_entry_done(&e);

        /* The change this hook exists for: a root fstab declares read-only
         * is not made writable behind its back. */
        make_root(where, sizeof(where), "ro", true, false);
        root_line(&e, "ro");
        ASSERT_EQ_INT(pico_root_remount(where, &e), PICO_ROOT_CONTINUE);
        ASSERT_TRUE(!is_rw(where));
        ASSERT_EQ_INT(test_write_file(where, "probe", "x"), -EROFS);
        ASSERT_EQ_INT(e.outcome, FSTAB_REMOUNTED);
        fstab_entry_done(&e);

        /* Options reach the right half: noatime/nosuid the mount, size the
         * filesystem. */
        make_root(where, sizeof(where), "options", true, false);
        root_line(&e, "noatime,nosuid,size=2m");
        ASSERT_EQ_INT(pico_root_remount(where, &e), PICO_ROOT_CONTINUE);
        ASSERT_TRUE(is_rw(where));
        ASSERT_TRUE(test_mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(test_has_opt(vfs, "noatime") && test_has_opt(vfs, "nosuid"));
        ASSERT_TRUE(test_has_opt(sb, "size=2048k"));
        fstab_entry_done(&e);

        /* Options the kernel refuses do not cost the boot a writable root,
         * but they do cost the line its "remounted". */
        make_root(where, sizeof(where), "bad", true, false);
        root_line(&e, "no_such_option");
        ASSERT_EQ_INT(pico_root_remount(where, &e), PICO_ROOT_CONTINUE);
        ASSERT_TRUE(is_rw(where));
        ASSERT_EQ_INT(e.outcome, FSTAB_FAILED);
        ASSERT_TRUE(strstr(e.reason, "options not applied: fsconfig(no_such_option)") != NULL);
        fstab_entry_done(&e);

        /* ...unless the line asked for read-only, in which case there is no
         * writable root to fall back to on its behalf. */
        make_root(where, sizeof(where), "bad-ro", true, false);
        root_line(&e, "ro,no_such_option");
        ASSERT_TRUE(pico_root_remount(where, &e) < 0);
        ASSERT_TRUE(!is_rw(where));
        ASSERT_EQ_INT(e.outcome, FSTAB_FAILED);
        fstab_entry_done(&e);
}

/*
 * pico_root_check() end to end, in a child chroot()ed into `root`. The child
 * asserts on the result and the outcome; the parent reads the mount state back
 * from outside. `options` NULL means no fstab "/" line.
 */
static void check_in_chroot(const char *root, const char *options, FstabOutcome want) {
        int status;
        pid_t pid;

        pid = fork();
        ASSERT_TRUE(pid >= 0);

        if (pid == 0) {
                FstabEntry e, *line = NULL;

                if (options) {
                        root_line(&e, options);
                        line = &e;
                }

                ASSERT_TRUE(chroot(root) == 0 && chdir("/") == 0);
                ASSERT_EQ_INT(pico_root_check(line), PICO_ROOT_CONTINUE);
                if (line)
                        ASSERT_EQ_INT(line->outcome, want);
                _exit(0);
        }

        ASSERT_TRUE(waitpid(pid, &status, 0) == pid);
        ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void test_root_check(void) {
        char root[PATH_MAX];

        /* A read-only root with no fstab line comes up read-write. */
        make_root(root, sizeof(root), "chroot-ro", true, true);
        check_in_chroot(root, NULL, FSTAB_PENDING);
        ASSERT_TRUE(is_rw(root));

        /* ...and with a read-only line, stays read-only. */
        make_root(root, sizeof(root), "chroot-ro-ro", true, true);
        check_in_chroot(root, "ro", FSTAB_REMOUNTED);
        ASSERT_TRUE(!is_rw(root));

        /* A read-write root the line declares read-only is made so, which is
         * the remount-fs behaviour the unconditional read-write never had. */
        make_root(root, sizeof(root), "chroot-rw-ro", false, true);
        check_in_chroot(root, "ro", FSTAB_REMOUNTED);
        ASSERT_TRUE(!is_rw(root));

        /* A read-write root with nothing to apply is not touched at all. */
        make_root(root, sizeof(root), "chroot-rw", false, true);
        check_in_chroot(root, "defaults", FSTAB_PRESENT);
        ASSERT_TRUE(is_rw(root));
}

/* A stand-in checker that records its arguments and exits 4. */
static void test_fsck_run(void) {
        char *dir, checker[PATH_MAX], args[PATH_MAX + 8], got[256];
        int code = -1;
        FILE *f;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        snprintf(args, sizeof(args), "%s/args", dir);

        {
                char script[PATH_MAX * 2];

                snprintf(script, sizeof(script), "#!/bin/sh\necho \"$*\" > %s\nexit 4\n", args);
                ASSERT_EQ_INT(test_write_file(dir, "fsck.vfat", script), 0);
        }
        snprintf(checker, sizeof(checker), "%s/fsck.vfat", dir);
        ASSERT_EQ_INT(chmod(checker, 0755), 0);

        ASSERT_EQ_INT(pico_fsck_run(checker, "/dev/sdz9", &code), 0);
        ASSERT_EQ_INT(code, 4);
        ASSERT_EQ_INT(pico_fsck_verdict(code), PICO_FSCK_UNCORRECTED);

        /* Preen mode and the node, nothing else. */
        f = fopen(args, "re");
        ASSERT_TRUE(f != NULL);
        ASSERT_TRUE(fgets(got, sizeof(got), f) != NULL);
        fclose(f);
        ASSERT_STREQ(got, "-a /dev/sdz9\n");

        /* A checker that is not there is fsck's own operational error. */
        snprintf(checker, sizeof(checker), "%s/fsck.missing", dir);
        ASSERT_EQ_INT(pico_fsck_run(checker, "/dev/sdz9", &code), 0);
        ASSERT_EQ_INT(code, 8);
        ASSERT_EQ_INT(pico_fsck_verdict(code), PICO_FSCK_FAILED);

        ASSERT_EQ_INT(pico_fsck_run(NULL, "/dev/sdz9", &code), -EINVAL);

        test_rm_rf(dir);
        free(dir);
}

int main(void) {
        char *dir;

        test_root_verdict();
        test_fsck_verdict();
        test_fsck_run();

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        snprintf(scratch, sizeof(scratch), "%s", dir);

        if (!test_enter_mount_namespace()) {
                test_rm_rf(dir);
                free(dir);
                printf("test-root-check: no user namespace here, skipping the remount checks\n");
                return 77;
        }

        ASSERT_TRUE(mount("tmpfs", scratch, "tmpfs", 0, "size=16m") == 0);

        test_root_remount();
        test_root_check();

        ASSERT_TRUE(umount2(scratch, MNT_DETACH) == 0);
        test_rm_rf(dir);
        free(dir);

        printf("test-root-check: all checks passed\n");
        return 0;
}
