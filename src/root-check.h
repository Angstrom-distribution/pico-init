/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Root filesystem integrity, before anything is allowed to write to it.
 *
 * The classic mount-ro / fsck / remount-rw boot, done in PID 1 itself rather
 * than in an initramfs, because the machines this init boots go straight from
 * the kernel's own `root=` to a mounted root with no initramfs in between. The
 * shape is upstream systemd's -- systemd-fsck-root.service, the `-a` preen
 * invocation, the fsck(8) exit-code table -- reached by reading it rather than
 * by lifting it, since almost all of what upstream's src/fsck.c spends its
 * lines on (D-Bus, a plymouth progress pipe, /forcefsck marker files, a
 * different read-only detection) is machinery this project does not have and
 * does not want.
 *
 * Three deliberate divergences from upstream, each one a decision rather than a
 * simplification:
 *
 *  - **Read-only is read, not probed.** Upstream decides whether root is
 *    read-only by trying to write to it (a utimensat() on "/"). This asks the
 *    kernel instead, through the mountinfo option list gpt_boot_root() already
 *    parses -- which is both a truthful answer and one that touches nothing on
 *    a filesystem whose integrity is the open question.
 *  - **A superblock gate in front of the checker.** ext4 records its own
 *    cleanliness in fields sitting inside a buffer that costs one pread() to
 *    fetch (ext-super.h). A clean filesystem never pays for a checker at all,
 *    and an unreplayed journal is handed to the kernel's own recovery on the
 *    remount rather than to e2fsck. Only a filesystem that has said in its own
 *    superblock that something is wrong costs time.
 *  - **"Errors left uncorrected" keeps booting, read-only.** Upstream escalates
 *    to emergency.target. On an appliance with no session to act from, a
 *    read-only boot that reaches a getty is strictly more useful than an
 *    emergency shell nobody is sitting in front of.
 *
 * Everything here is best-effort in mount-setup.c's sense, with exactly one
 * exception: a filesystem the checker says it could not repair does NOT get
 * remounted read-write. Every other failure -- an unidentifiable device, an
 * unreadable superblock, a checker that is not installed, a checker that itself
 * failed -- ends in the remount, because a machine that reaches a console is
 * worth more than one that is right about a filesystem.
 *
 * The remount honours /etc/fstab's "/" line, as upstream's
 * systemd-remount-fs.service does and as its v30 ancestor did with a bare
 * `mount / -o remount` that let mount(8) consult fstab. The line's options are
 * reapplied -- "ro" included, so a root fstab declares read-only stays that way
 * after its check -- and with no "/" line the root goes read-write, as it
 * always has. An already read-write root is remounted only when the line asks
 * for something a read-write root might not have. Options the kernel refuses do
 * not cost the boot its writable root: the remount is retried as a plain
 * read-write one, and the line is recorded as failed.
 */

#pragma once

#include <stdbool.h>

#include "ext-super.h"
#include "fstab.h"

/*
 * What pico_root_check() concluded. Deliberately a return value and not an
 * action: the reboot belongs to main(), which already owns the one
 * sync()/reboot() path this init has, and PID 1's "must never return" rule is
 * that file's to enforce rather than this one's to duplicate.
 */
typedef enum PicoRootResult {
        /* Boot on. Root is read-write, or is deliberately staying read-only. */
        PICO_ROOT_CONTINUE = 0,

        /* The checker repaired a filesystem the running kernel has cached
         * metadata for, and says the machine must be restarted before anything
         * uses it. */
        PICO_ROOT_REBOOT = 1,
} PicoRootResult;

/*
 * Check the root filesystem and leave it mounted as /etc/fstab's "/" line asks
 * -- `root_line`, NULL when there is none, which means read-write. The outcome
 * is recorded on `root_line` for the fstab pass's record.
 *
 * Called from main() after status_enable()/status_welcome() -- it needs /proc
 * for the mountinfo, /sys for the block topology, /dev for the node to check,
 * and the kmsg sink already installed so its records survive into logd's
 * backfill -- and before dps_scan() and manager_startup(), because root
 * integrity has to be settled ahead of swap activation and ahead of the first
 * service that could write anything.
 *
 * Returns a PicoRootResult, or -errno for a failure worth a line in the log
 * (which the caller also treats as "carry on booting").
 */
int pico_root_check(FstabEntry *root_line);

/*
 * The remount that ends the check, on `where` ("/" in production; a test's own
 * mount otherwise): `root_line`'s options through fstab_remount(), falling back
 * to a plain read-write remount when the kernel refuses them and the line did
 * not ask for read-only. Records the outcome on `root_line`.
 *
 * Returns PICO_ROOT_CONTINUE, or -errno when not even the fallback worked.
 */
int pico_root_remount(const char *where, FstabEntry *root_line);

/*
 * The two decisions above, split out as pure functions so they can be tested
 * against values rather than against a machine with a damaged disk in it.
 * Everything else pico_root_check() does is I/O whose behaviour is the kernel's.
 */

/* What the superblock gate concluded about a filesystem. */
typedef enum PicoRootVerdict {
        /* Cleanly unmounted, no errors, no orphans, nothing to replay. */
        PICO_ROOT_CLEAN,

        /* The journal holds transactions nobody has replayed, and nothing else
         * is wrong. The kernel replays these itself on the remount; running a
         * checker would be slower and would do the same thing. */
        PICO_ROOT_REPLAY,

        /* The filesystem has recorded an error, or is not marked valid and has
         * no journal to explain why. This is the only case worth a checker. */
        PICO_ROOT_CHECK,
} PicoRootVerdict;

PicoRootVerdict pico_root_verdict(const PicoExtInfo *fs);

/* What a checker's exit status means. */
typedef enum PicoFsckVerdict {
        /* Nothing was wrong, or what was wrong is now fixed. */
        PICO_FSCK_OK,

        /* Repairs were made underneath a kernel that has the old metadata
         * cached. Nothing may use this filesystem until the machine restarts. */
        PICO_FSCK_REBOOT,

        /* The checker gave up on damage it could not repair unattended. */
        PICO_FSCK_UNCORRECTED,

        /* The checker itself failed -- an operational error, a usage error, a
         * cancellation, a shared-library error. This says nothing about the
         * filesystem, so it must not be treated as if it did. */
        PICO_FSCK_FAILED,
} PicoFsckVerdict;

/*
 * Map an fsck(8)/e2fsck(8) exit code. The codes are a bitmask that ORs
 * together, so this tests bits and never compares for equality:
 *
 *   0    no errors            8    operational error
 *   1    errors corrected     16   usage or syntax error
 *   2    system should reboot 32   cancelled by user request
 *   4    errors uncorrected   128  shared-library error
 *
 * Verified against the real e2fsprogs 1.47 binary rather than only its manual:
 * a clean image exits 0, an error-flagged one repaired by `-a` exits 1, and a
 * device that is not there exits 8.
 *
 * "Should reboot" is tested before "uncorrected", following upstream's own
 * ordering in src/fsck.c: a kernel running on stale cached metadata is the more
 * urgent of the two things a combined status can be saying.
 */
PicoFsckVerdict pico_fsck_verdict(int code);

/*
 * Run `checker` (an absolute path: PID 1 goes looking for no repair tool
 * through $PATH) as `<checker> -a <node>` -- preen, never -y -- and wait for
 * it. The root check runs fsck.ext4 through this; the fstab pass runs
 * fsck.<type> for any line with a non-zero pass number.
 *
 * 0 with *ret_code set to the exit status (8, fsck's own "operational error",
 * when the exec itself failed), or -errno when the checker could not be
 * forked or did not exit normally.
 */
int pico_fsck_run(const char *checker, const char *node, int *ret_code);
