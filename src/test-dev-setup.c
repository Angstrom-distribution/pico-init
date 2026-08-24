/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * D0's acceptance test (plan §1.8): dev_setup() creates all five /dev symlinks
 * as correct symlinks, and running it twice is safe.
 *
 * Everything here runs against a test root rather than the real /dev, which is
 * the whole reason dev_setup() takes a prefix -- the assertions are about
 * paths this test owns, so it needs neither root nor a container-wide mutation
 * to mean anything.
 *
 * Note what is asserted about /dev/core: its presence is conditional on the
 * running kernel having CONFIG_PROC_KCORE, deliberately, and the check is made
 * against the real /proc/kcore rather than one under the prefix because the
 * link's target is the literal string either way (see mount-setup.c). So this
 * file asks the same question dev_setup() asks rather than hardcoding an
 * answer -- a test that assumed /dev/core always appears would fail on a
 * kernel that simply does not have kcore, and one that assumed it never
 * appears would assert nothing at all on the kernels that do.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mount-setup.h"
#include "test-util.h"

static bool have_kcore(void) {
        return access("/proc/kcore", F_OK) == 0;
}

/* Number of the five dev_setup() can create on this kernel. */
static int expected_links(void) {
        return have_kcore() ? 5 : 4;
}

/* Assert <root><link> is a symlink whose target is exactly `target`. */
static void assert_symlink(const char *root, const char *link, const char *target) {
        char path[512], buf[512];
        struct stat st;
        ssize_t n;

        snprintf(path, sizeof(path), "%s%s", root, link);

        /* lstat, not stat: stat() would follow the link and report on
         * /proc/self/fd, which is true of a correct link and of a wrong one. */
        if (lstat(path, &st) < 0) {
                fprintf(stderr, "%s: %s\n", path, strerror(errno));
                exit(1);
        }

        ASSERT_TRUE(S_ISLNK(st.st_mode));

        n = readlink(path, buf, sizeof(buf) - 1);
        ASSERT_TRUE(n > 0);
        buf[n] = '\0';

        ASSERT_STREQ(buf, target);
}

static void assert_all_five(const char *root) {
        assert_symlink(root, "/dev/fd", "/proc/self/fd");
        assert_symlink(root, "/dev/stdin", "/proc/self/fd/0");
        assert_symlink(root, "/dev/stdout", "/proc/self/fd/1");
        assert_symlink(root, "/dev/stderr", "/proc/self/fd/2");

        if (have_kcore())
                assert_symlink(root, "/dev/core", "/proc/kcore");
}

/*
 * The D0 criterion itself: an empty /dev gains all five, asserted through
 * readlink() rather than through mere existence -- a symlink pointing at the
 * wrong place exists just as hard as a correct one.
 */
static void test_creates_all_five(void) {
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_mkdir(dir, "dev"), 0);

        ASSERT_EQ_INT(dev_setup(dir), expected_links());
        assert_all_five(dir);

        test_rm_rf(dir);
        free(dir);
}

/*
 * The run-twice case. PID 1 calls this once per boot, but "idempotent" is a
 * property of the function and not of how often it happens to be called: an
 * initramfs or an image that already ships these links reaches exactly this
 * path on a first boot.
 */
static void test_run_twice_is_safe(void) {
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_mkdir(dir, "dev"), 0);

        ASSERT_EQ_INT(dev_setup(dir), expected_links());
        assert_all_five(dir);

        /* Same count, same links: the second run must report the links as in
         * place rather than counting only what it newly created, or "how many
         * of the five are right" would silently become "how many did I make
         * just now". */
        ASSERT_EQ_INT(dev_setup(dir), expected_links());
        assert_all_five(dir);

        test_rm_rf(dir);
        free(dir);
}

/*
 * A link pointing somewhere wrong is repaired.
 *
 * This is the deliberate divergence from upstream, which calls symlink(),
 * takes the EEXIST, logs it at debug and leaves the wrong target in place
 * forever. Testing it is the only thing that keeps the divergence real:
 * without this case the repair branch could be deleted and everything else
 * here would still pass.
 */
static void test_wrong_target_is_repaired(void) {
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_mkdir(dir, "dev"), 0);

        ASSERT_EQ_INT(test_symlink(dir, "dev/stdout", "/proc/self/fd/9"), 0);
        assert_symlink(dir, "/dev/stdout", "/proc/self/fd/9"); /* really wrong first */

        ASSERT_EQ_INT(dev_setup(dir), expected_links());
        assert_all_five(dir);

        test_rm_rf(dir);
        free(dir);
}

/*
 * An existing non-symlink is left alone.
 *
 * The opposite call from the one above, and the more important of the two: a
 * regular file or a device node at /dev/stderr is somebody's decision, and PID
 * 1 unlinking it to install a symlink would be destroying data to satisfy a
 * convenience. socket.c's S_ISSOCK guard exists for the same reason on the
 * stale-bind-path unlink.
 */
static void test_existing_non_symlink_is_left_alone(void) {
        char path[512];
        struct stat st;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_mkdir(dir, "dev"), 0);

        ASSERT_EQ_INT(test_write_file(dir, "dev/stderr", "not a symlink\n"), 0);

        /* One short of the full set: the other four are made, this one is not
         * counted because it was not made correct. */
        ASSERT_EQ_INT(dev_setup(dir), expected_links() - 1);

        snprintf(path, sizeof(path), "%s/dev/stderr", dir);
        ASSERT_EQ_INT(lstat(path, &st), 0);
        ASSERT_TRUE(S_ISREG(st.st_mode)); /* still the file, untouched */

        /* and the rest were still created around it */
        assert_symlink(dir, "/dev/fd", "/proc/self/fd");
        assert_symlink(dir, "/dev/stdout", "/proc/self/fd/1");

        test_rm_rf(dir);
        free(dir);
}

/*
 * The one case deliberately NOT tested here is dev_setup(NULL) -- the real
 * boot path, where upstream needed an actual fix so a NULL prefix did not
 * compose "(null)/dev/fd" (01ed0e2307). The only way to exercise it is to let
 * it write to the host's own /dev, and this suite runs as root in a build
 * container, so a test for it would repair or create symlinks in the machine
 * running the test. Mutating the host to assert a string-formatting property
 * is a worse trade than leaving it to the place it is genuinely exercised: PID
 * 1 calls exactly dev_setup(NULL) on every boot, and D0's booted-guest check
 * (`ls /dev/fd/`, `echo x >/dev/stderr`) is what proves that path works.
 */

int main(void) {
        test_creates_all_five();
        test_run_twice_is_safe();
        test_wrong_target_is_repaired();
        test_existing_non_symlink_is_left_alone();

        printf("test-dev-setup: all checks passed\n");
        return 0;
}
