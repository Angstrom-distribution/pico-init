/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Test scaffolding: a throwaway unit tree on disk, plus assertions.
 *
 * Unit loading, enablement and preset application are all filesystem
 * behaviour, so testing them honestly means giving the manager a real
 * directory to read -- not a mock. These helpers build one in /tmp and tear it
 * down again, which is what lets the search path be exercised without root and
 * without touching the host's own /etc.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

/* Print file/line/expression and exit non-zero. meson reports the exit code. */
#define ASSERT_TRUE(expr)                                                                            \
        do {                                                                                         \
                if (!(expr)) {                                                                       \
                        fprintf(stderr, "%s:%d: assertion failed: %s\n", __FILE__, __LINE__, #expr); \
                        exit(1);                                                                     \
                }                                                                                    \
        } while (0)

#define ASSERT_EQ_INT(a, b)                                                           \
        do {                                                                          \
                long long a_ = (long long) (a);                                       \
                long long b_ = (long long) (b);                                       \
                if (a_ != b_) {                                                       \
                        fprintf(stderr,                                               \
                                "%s:%d: assertion failed: %s == %s (%lld != %lld)\n", \
                                __FILE__,                                             \
                                __LINE__,                                             \
                                #a,                                                   \
                                #b,                                                   \
                                a_,                                                   \
                                b_);                                                  \
                        exit(1);                                                      \
                }                                                                     \
        } while (0)

#define ASSERT_STREQ(a, b)                                                                \
        do {                                                                              \
                const char *a_ = (a);                                                     \
                const char *b_ = (b);                                                     \
                if (!a_ || !b_ || strcmp(a_, b_) != 0) {                                  \
                        fprintf(stderr,                                                   \
                                "%s:%d: assertion failed: %s == %s (\"%s\" != \"%s\")\n", \
                                __FILE__,                                                 \
                                __LINE__,                                                 \
                                #a,                                                       \
                                #b,                                                       \
                                a_ ? a_ : "(null)",                                       \
                                b_ ? b_ : "(null)");                                      \
                        exit(1);                                                          \
                }                                                                         \
        } while (0)

/* Create a unique temporary directory. Returns a malloc'd path, or NULL. */
char *test_tmpdir_new(void);

/* Write `content` to <dir>/<name>, creating it. Returns 0 or -errno. */
int test_write_file(const char *dir, const char *name, const char *content);

/* Create <dir>/<name> as a directory. Returns 0 or -errno. */
int test_mkdir(const char *dir, const char *name);

/* Create <dir>/<name> as a symlink pointing at `target` (not resolved).
 * Real .wants/.requires entries are symlinks, and enablement code cares only
 * about the entry name, not the link target -- this exercises that path
 * honestly instead of substituting a regular file. Returns 0 or -errno. */
int test_symlink(const char *dir, const char *name, const char *target);

/* Recursively remove `path` and free nothing; caller still owns the string. */
void test_rm_rf(const char *path);

/*
 * Move this process into a private user + mount namespace, root inside it, with
 * every mount private. An unprivileged process there owns its own mount table
 * and may mount tmpfs, reconfigure it and change its per-mount attributes, so
 * mount code can be tested against the real kernel without touching the host.
 * False, with the reason on stderr, when the host refuses user namespaces --
 * callers SKIP (exit 77) on that. Single-threaded processes only.
 */
bool test_enter_mount_namespace(void);

/* The mount at exactly `where`, per /proc/self/mountinfo: its per-mount option
 * field into `vfs` and its superblock option field into `sb`, each wrapped as
 * ",a,b,c," for test_has_opt(). The last matching line, the mount a lookup
 * lands on. False when nothing is mounted there. */
bool test_mount_options(const char *where, char *vfs, size_t vfs_size, char *sb, size_t sb_size);

/* Whole-token membership in a list test_mount_options() built. */
bool test_has_opt(const char *list, const char *opt);
