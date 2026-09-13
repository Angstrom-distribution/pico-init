/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Test scaffolding. See test-util.h for why these tests use a real directory
 * tree rather than a mocked filesystem.
 */

#include "test-util.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

char *test_tmpdir_new(void) {
        char template[] = "/tmp/pico-init-test-XXXXXX";
        char resolved[PATH_MAX];
        char *dir;

        dir = mkdtemp(template);
        if (!dir)
                return NULL;

        /*
         * realpath(), not a plain strdup(): whenever /tmp (or any ancestor)
         * is itself a symlink -- never true locally, routine on at least
         * one real CI runner, confirmed by reproducing device-new.c's own
         * syspath mismatch this way -- every device/sd_device test that
         * builds an expected path by hand from this string and every
         * production code path that canonicalizes the syspath it is fed
         * (device_new_from_syspath_internal()) must agree on the same
         * spelling. Canonicalizing once here, at the one place every such
         * test's fixture root is minted, is cheaper than teaching each of
         * them to do it themselves. The directory this mkdtemp() just
         * created always exists, so realpath() cannot fail on it.
         */
        if (!realpath(dir, resolved))
                return strdup(dir);

        return strdup(resolved);
}

static int join(char *buf, size_t size, const char *dir, const char *name) {
        int n = snprintf(buf, size, "%s/%s", dir, name);

        if (n < 0 || (size_t) n >= size)
                return -ENAMETOOLONG;

        return 0;
}

int test_write_file(const char *dir, const char *name, const char *content) {
        char path[PATH_MAX];
        FILE *f;
        int r;

        r = join(path, sizeof(path), dir, name);
        if (r < 0)
                return r;

        f = fopen(path, "we");
        if (!f)
                return -errno;

        if (fputs(content, f) == EOF) {
                fclose(f);
                return -EIO;
        }

        if (fclose(f) != 0)
                return -EIO;

        return 0;
}

int test_mkdir(const char *dir, const char *name) {
        char path[PATH_MAX];
        int r;

        r = join(path, sizeof(path), dir, name);
        if (r < 0)
                return r;

        if (mkdir(path, 0755) < 0 && errno != EEXIST)
                return -errno;

        return 0;
}

int test_symlink(const char *dir, const char *name, const char *target) {
        char path[PATH_MAX];
        int r;

        r = join(path, sizeof(path), dir, name);
        if (r < 0)
                return r;

        if (symlink(target, path) < 0 && errno != EEXIST)
                return -errno;

        return 0;
}

void test_rm_rf(const char *path) {
        struct dirent *de;
        DIR *d;

        if (!path)
                return;

        d = opendir(path);
        if (!d) {
                unlink(path);
                return;
        }

        while ((de = readdir(d))) {
                char child[PATH_MAX];
                struct stat st;

                if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                        continue;

                if (join(child, sizeof(child), path, de->d_name) < 0)
                        continue;

                /* lstat, not stat: a .wants/ entry is a symlink, and following
                 * it would delete the target rather than the link. */
                if (lstat(child, &st) < 0)
                        continue;

                if (S_ISDIR(st.st_mode))
                        test_rm_rf(child);
                else
                        unlink(child);
        }

        closedir(d);
        rmdir(path);
}
