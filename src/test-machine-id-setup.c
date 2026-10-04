/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * First-boot detection and /etc/machine-id fill-in: missing/empty/
 * "uninitialized" all read as first boot and get a freshly generated id, an
 * already-valid id is left alone and read back as-is, and a read-only /etc/
 * fixture falls back to the transient bind mount instead of crashing or
 * failing the boot.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

#include "id128-internal.h"
#include "machine-id-setup.h"
#include "test-util.h"

/* machine_id_setup() assumes /etc already exists -- true for every real
 * rootfs, and the one upstream behaviour (creating /etc itself) this
 * project's shim does not carry, per machine-id-setup.h's deviation note. */
static char *fixture_with_etc(void) {
        char *dir = test_tmpdir_new();

        if (!dir)
                return NULL;
        if (test_mkdir(dir, "etc") < 0) {
                test_rm_rf(dir);
                free(dir);
                return NULL;
        }
        return dir;
}

/* Reads <root>/etc/machine-id with the exact parser sd_id128_get_machine()
 * uses, proving the file machine_id_setup() wrote is readable by it with no
 * change. 0 with *ret set, or the id128_read_fd() error. */
static int read_etc_machine_id(const char *root, sd_id128_t *ret) {
        char path[PATH_MAX];
        int fd, r;

        snprintf(path, sizeof(path), "%s/etc/machine-id", root);

        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return -errno;

        r = id128_read_fd(fd, false, ret);
        close(fd);
        return r;
}

static void test_missing_file_is_first_boot(void) {
        char *dir;
        sd_id128_t id, reread;
        bool first_boot = false;

        dir = fixture_with_etc();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(machine_id_setup(dir, &id, &first_boot), 0);
        ASSERT_TRUE(first_boot);
        ASSERT_TRUE(!sd_id128_is_null(id));

        /* readable by sd_id128_get_machine()'s own parser, unmodified */
        ASSERT_EQ_INT(read_etc_machine_id(dir, &reread), 0);
        ASSERT_TRUE(sd_id128_equal(id, reread));

        ASSERT_TRUE(sd_id128_equal(machine_id_setup_get(), id));

        test_rm_rf(dir);
        free(dir);
}

static void test_empty_file_is_first_boot(void) {
        char *dir;
        sd_id128_t id;
        bool first_boot = false;

        dir = fixture_with_etc();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "etc/machine-id", ""), 0);

        ASSERT_EQ_INT(machine_id_setup(dir, &id, &first_boot), 0);
        ASSERT_TRUE(first_boot);
        ASSERT_TRUE(!sd_id128_is_null(id));

        test_rm_rf(dir);
        free(dir);
}

static void test_uninitialized_is_first_boot(void) {
        char *dir;
        sd_id128_t id;
        bool first_boot = false;

        dir = fixture_with_etc();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "etc/machine-id", "uninitialized\n"), 0);

        ASSERT_EQ_INT(machine_id_setup(dir, &id, &first_boot), 0);
        ASSERT_TRUE(first_boot);
        ASSERT_TRUE(!sd_id128_is_null(id));

        test_rm_rf(dir);
        free(dir);
}

/* A real, already-initialized id is read back exactly, and never rewritten:
 * not first boot, and the id returned is the one on disk, not a new one. */
static void test_existing_valid_id_is_not_first_boot(void) {
        char *dir;
        sd_id128_t written, got;
        bool first_boot = true;

        dir = fixture_with_etc();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(sd_id128_randomize(&written), 0);
        {
                char text[SD_ID128_STRING_MAX];
                char line[SD_ID128_STRING_MAX + 1];

                sd_id128_to_string(written, text);
                snprintf(line, sizeof(line), "%s\n", text);
                ASSERT_EQ_INT(test_write_file(dir, "etc/machine-id", line), 0);
        }

        ASSERT_EQ_INT(machine_id_setup(dir, &got, &first_boot), 0);
        ASSERT_TRUE(!first_boot);
        ASSERT_TRUE(sd_id128_equal(got, written));

        test_rm_rf(dir);
        free(dir);
}

/*
 * A tmpfs standing in for the root, with its own separately-mounted /run
 * (so remounting the outer tmpfs read-only, below, does not also lock
 * /run) -- same shape as test-root-check.c's make_root(), narrowed to
 * what this test needs.
 */
static void test_read_only_etc_falls_back_without_crashing(void) {
        char *dir;
        sd_id128_t id, reread;
        bool first_boot = false;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        if (!test_enter_mount_namespace()) {
                printf("test-machine-id-setup: no user namespace here, skipping the read-only check\n");
                test_rm_rf(dir);
                free(dir);
                exit(77);
        }

        ASSERT_TRUE(mount("tmpfs", dir, "tmpfs", 0, "size=4m") == 0);
        ASSERT_EQ_INT(test_mkdir(dir, "etc"), 0);
        ASSERT_EQ_INT(test_mkdir(dir, "run"), 0);
        ASSERT_EQ_INT(test_write_file(dir, "etc/machine-id", ""), 0);

        /* /run as its own mount: a later remount of `dir` only changes
         * `dir`'s own mount flags, never a mount nested under it. */
        {
                char run[PATH_MAX];

                snprintf(run, sizeof(run), "%s/run", dir);
                ASSERT_TRUE(mount("tmpfs", run, "tmpfs", 0, "size=1m") == 0);
        }

        ASSERT_TRUE(mount(NULL, dir, NULL, MS_REMOUNT | MS_RDONLY, "size=4m") == 0);

        ASSERT_EQ_INT(test_write_file(dir, "probe", "x"), -EROFS); /* sanity: dir really is read-only */

        ASSERT_EQ_INT(machine_id_setup(dir, &id, &first_boot), 0); /* must not crash or fail the boot */
        ASSERT_TRUE(first_boot);
        ASSERT_TRUE(!sd_id128_is_null(id));

        /* the bind mount makes /etc/machine-id readable despite the
         * read-only backing filesystem, with the exact id just generated */
        ASSERT_EQ_INT(read_etc_machine_id(dir, &reread), 0);
        ASSERT_TRUE(sd_id128_equal(id, reread));
        ASSERT_TRUE(sd_id128_equal(machine_id_setup_get(), id));

        test_rm_rf(dir);
        free(dir);
}

int main(void) {
        test_missing_file_is_first_boot();
        test_empty_file_is_first_boot();
        test_uninitialized_is_first_boot();
        test_existing_valid_id_is_not_first_boot();
        test_read_only_etc_falls_back_without_crashing();

        printf("test-machine-id-setup: all checks passed\n");
        return 0;
}
