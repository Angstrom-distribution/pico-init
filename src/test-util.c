/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Test scaffolding. See test-util.h for why these tests use a real directory
 * tree rather than a mocked filesystem.
 */

/* unshare() and CLONE_NEWUSER, for test_enter_mount_namespace(). */
#define _GNU_SOURCE

#include "test-util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
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
         * one real CI runner -- every device/sd_device test that
         * builds an expected path by hand from this string and every
         * production code path that canonicalizes the syspath it is fed
         * (device_new_from_syspath_internal()) must agree on the same
         * spelling. Canonicalizing once here, at the one place every such
         * test's fixture root is minted, is cheaper than teaching each of
         * them to do it. The directory this mkdtemp() just
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

static int write_proc(const char *path, const char *s) {
        ssize_t len = (ssize_t) strlen(s);
        int fd, r = 0;

        fd = open(path, O_WRONLY | O_CLOEXEC);
        if (fd < 0)
                return -errno;
        if (write(fd, s, (size_t) len) != len)
                r = -errno;
        close(fd);
        return r;
}

bool test_enter_mount_namespace(void) {
        char map[64];
        uid_t uid = getuid();
        gid_t gid = getgid();

        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0) {
                fprintf(stderr, "unshare(CLONE_NEWUSER|CLONE_NEWNS): %s\n", strerror(errno));
                return false;
        }

        /* Map this process's own ids to root inside, which is what makes it
         * the owner of the new mount namespace's mounts. */
        if (write_proc("/proc/self/setgroups", "deny") < 0)
                return false;
        snprintf(map, sizeof(map), "0 %u 1", (unsigned) uid);
        if (write_proc("/proc/self/uid_map", map) < 0)
                return false;
        snprintf(map, sizeof(map), "0 %u 1", (unsigned) gid);
        if (write_proc("/proc/self/gid_map", map) < 0)
                return false;

        /* Nothing mounted from here on may propagate anywhere, whatever the
         * host's own propagation settings are. */
        return mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0;
}

/* mountinfo's \ooo escapes, undone in place. Local rather than borrowed from
 * the code under test: this file is linked into tests that do not link it. */
static void unescape(char *s) {
        char *r = s, *w = s;

        while (*r) {
                if (r[0] == '\\' && r[1] >= '0' && r[1] <= '7' && r[2] >= '0' && r[2] <= '7' &&
                    r[3] >= '0' && r[3] <= '7') {
                        *w++ = (char) (((r[1] - '0') << 6) | ((r[2] - '0') << 3) | (r[3] - '0'));
                        r += 4;
                } else
                        *w++ = *r++;
        }
        *w = '\0';
}

bool test_mount_options(const char *where, char *vfs, size_t vfs_size, char *sb, size_t sb_size) {
        char line[4096];
        bool found = false;
        FILE *f;

        f = fopen("/proc/self/mountinfo", "re");
        if (!f)
                return false;

        while (fgets(line, sizeof(line), f)) {
                char mp[PATH_MAX], opts[1024], type[64], src[PATH_MAX], sopts[1024];
                char *sep;

                if (sscanf(line, "%*s %*s %*s %*s %4095s %1023s", mp, opts) != 2)
                        continue;
                unescape(mp);
                if (strcmp(mp, where) != 0)
                        continue;

                sep = strstr(line, " - ");
                if (!sep || sscanf(sep + 3, "%63s %4095s %1023s", type, src, sopts) != 3)
                        continue;

                snprintf(vfs, vfs_size, ",%s,", opts);
                snprintf(sb, sb_size, ",%s,", sopts);
                found = true;
        }
        fclose(f);

        return found;
}

bool test_has_opt(const char *list, const char *opt) {
        char tok[128];

        snprintf(tok, sizeof(tok), ",%s,", opt);
        return strstr(list, tok) != NULL;
}

static int mkdir_p(const char *path) {
        char buf[PATH_MAX];

        if (snprintf(buf, sizeof(buf), "%s", path) >= (int) sizeof(buf))
                return -ENAMETOOLONG;

        for (char *p = buf + 1; *p; p++) {
                if (*p != '/')
                        continue;
                *p = '\0';
                if (mkdir(buf, 0755) < 0 && errno != EEXIST)
                        return -errno;
                *p = '/';
        }

        if (mkdir(buf, 0755) < 0 && errno != EEXIST)
                return -errno;
        return 0;
}

int test_block_device(
                const char *sys_root,
                const char *name,
                const char *parent,
                unsigned partno,
                unsigned long long size) {
        char dir[PATH_MAX], link[PATH_MAX], val[32];
        int r;

        if (partno > 0)
                r = snprintf(dir, sizeof(dir), "%s/devices/virtual/block/%s/%s", sys_root, parent, name);
        else
                r = snprintf(dir, sizeof(dir), "%s/devices/virtual/block/%s", sys_root, name);
        if (r < 0 || (size_t) r >= sizeof(dir))
                return -ENAMETOOLONG;

        r = mkdir_p(dir);
        if (r < 0)
                return r;

        snprintf(val, sizeof(val), "%llu\n", size);
        r = test_write_file(dir, "size", val);
        if (r < 0)
                return r;

        if (partno > 0) {
                snprintf(val, sizeof(val), "%u\n", partno);
                r = test_write_file(dir, "partition", val);
                if (r < 0)
                        return r;
        }

        if (snprintf(link, sizeof(link), "%s/class/block", sys_root) >= (int) sizeof(link))
                return -ENAMETOOLONG;
        r = mkdir_p(link);
        if (r < 0)
                return r;

        return test_symlink(link, name, dir);
}

int test_image_write(const char *path, unsigned long long size, const void *data, size_t n, unsigned long long at) {
        int fd, r = 0;

        fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (fd < 0)
                return -errno;

        if (ftruncate(fd, (off_t) size) < 0 || (n > 0 && pwrite(fd, data, n, (off_t) at) != (ssize_t) n))
                r = -errno ? -errno : -EIO;

        close(fd);
        return r;
}

int test_ext_image(const char *path, const uint8_t uuid[16], const char *label) {
        uint8_t sb[1024] = { 0 };

        sb[56] = 0x53; /* s_magic 0xef53 */
        sb[57] = 0xef;
        sb[58] = 0x01; /* s_state: cleanly unmounted */
        sb[92] = 0x04; /* s_feature_compat: has_journal */
        memcpy(sb + 104, uuid, 16);
        if (label)
                memcpy(sb + 120, label, strlen(label) > 16 ? 16 : strlen(label));

        return test_image_write(path, 1 << 20, sb, sizeof(sb), 1024);
}
