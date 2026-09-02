/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The two decisions the root check is made of, tested as decisions.
 *
 * pico_root_check() itself cannot be unit-tested and should not pretend
 * otherwise: it remounts "/" on the machine running it. So the parts worth
 * being sure about are split out as pure functions -- a superblock in, a
 * verdict out; an exit code in, a verdict out -- and everything left in the
 * caller is I/O whose behaviour belongs to the kernel and to e2fsck. That is
 * the same split test-gpt-scan.c makes for swapon(2) and test-dev-setup.c makes
 * for the /dev symlinks, and the remaining half is proven the same way: by a
 * qemuarmv5 boot through the read-only window, not by a test that would have to
 * damage a filesystem on the build host.
 *
 * Both tables are worth this much care for the same reason. Getting the
 * superblock gate wrong means either never checking a damaged root or checking
 * a healthy one on every boot; getting the exit-code table wrong means
 * remounting a filesystem e2fsck just said it could not repair.
 */

#include <stdio.h>
#include <string.h>

#include "ext-super.h"
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

int main(void) {
        test_root_verdict();
        test_fsck_verdict();

        printf("test-root-check: all checks passed\n");
        return 0;
}
