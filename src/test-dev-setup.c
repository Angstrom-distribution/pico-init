/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * dev_setup() creates all five /dev symlinks as correct symlinks, and running
 * it twice is safe.
 *
 * Everything runs against a test root rather than the real /dev (dev_setup()
 * takes a prefix for this), so no root privileges are needed.
 *
 * /dev/core exists only if the running kernel has CONFIG_PROC_KCORE. The check
 * is made against the real /proc/kcore, not one under the prefix, because the
 * link target is the literal string either way (see mount-setup.c). The test
 * asks the same question dev_setup() asks instead of hardcoding an answer.
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
 * An empty /dev gains all five, asserted through
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
 * This diverges from upstream, which calls symlink(),
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
 * dev_setup(NULL), the real boot path, is not tested: upstream needed a fix so
 * a NULL prefix did not compose "(null)/dev/fd" (01ed0e2307), but exercising it
 * would create or repair symlinks in the host's own /dev. PID 1 calls exactly
 * dev_setup(NULL) on every boot, so a booted guest (`ls /dev/fd/`,
 * `echo x >/dev/stderr`) proves that path.
 */

int main(void) {
        test_creates_all_five();
        test_run_twice_is_safe();
        test_wrong_target_is_repaired();
        test_existing_non_symlink_is_left_alone();

        printf("test-dev-setup: all checks passed\n");
        return 0;
}
