/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The cgroup plumbing behind Delegate=: enabling controllers for children,
 * removing a unit's child cgroups depth-first, resetting a stale unit cgroup
 * before its next start, and handing the cgroup to a User=.
 *
 * Most of it runs on a fake tree in a temp directory (control files are plain
 * files there, so a write to cgroup.subtree_control replaces the start of the
 * file instead of behaving like the kernel's); that is enough for the token
 * handling, the order of operations and the "never fatal" paths. The last test
 * uses the real hierarchy when it is writable and is skipped quietly when not.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cgroups-v2.h"
#include "test-util.h"
#include "util.h"

static void path_in(char *out, size_t size, const char *dir, const char *name) {
        ASSERT_TRUE(snprintf(out, size, "%s/%s", dir, name) < (int) size);
}

static void mkdir_in(const char *dir, const char *name) {
        char path[PATH_MAX];

        path_in(path, sizeof(path), dir, name);
        ASSERT_EQ_INT(mkdir(path, 0755), 0);
}

static void read_in(const char *dir, const char *name, char *buf, size_t size) {
        char path[PATH_MAX];
        FILE *f;
        size_t n;

        path_in(path, sizeof(path), dir, name);
        f = fopen(path, "r");
        ASSERT_TRUE(f != NULL);
        n = fread(buf, 1, size - 1, f);
        fclose(f);
        buf[n] = '\0';
}

static bool exists_in(const char *dir, const char *name) {
        char path[PATH_MAX];
        struct stat st;

        path_in(path, sizeof(path), dir, name);
        return stat(path, &st) == 0;
}

/* A directory that looks like a cgroup to the controller functions. */
static char *fake_cgroup(const char *controllers, const char *subtree_control) {
        char *dir = test_tmpdir_new();

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "cgroup.controllers", controllers), 0);
        ASSERT_EQ_INT(test_write_file(dir, "cgroup.subtree_control", subtree_control), 0);
        return dir;
}

static void done(char *dir) {
        test_rm_rf(dir);
        free(dir);
}

static void test_enable(void) {
        char buf[64];
        char *dir;
        int err;

        /* One offered, not yet enabled: +cpu is written. */
        dir = fake_cgroup("cpuset cpu io memory\n", "");
        ASSERT_EQ_INT(cgroup_v2_enable_controllers(dir, "cpu", &err), 1);
        ASSERT_EQ_INT(err, 0);
        read_in(dir, "cgroup.subtree_control", buf, sizeof(buf));
        ASSERT_STREQ(buf, "+cpu");
        done(dir);

        /* Already enabled is skipped, the other is written. */
        dir = fake_cgroup("cpuset cpu io memory\n", "cpu\n");
        ASSERT_EQ_INT(cgroup_v2_enable_controllers(dir, "cpu memory", &err), 1);
        read_in(dir, "cgroup.subtree_control", buf, sizeof(buf));
        ASSERT_TRUE(strstr(buf, "+memory") != NULL);
        ASSERT_TRUE(strstr(buf, "+cpu") == NULL);
        done(dir);

        /* Both missing: two writes. */
        dir = fake_cgroup("cpu memory\n", "");
        ASSERT_EQ_INT(cgroup_v2_enable_controllers(dir, "cpu memory", &err), 2);
        done(dir);

        /* A controller the kernel does not offer is skipped without a write or an error. */
        dir = fake_cgroup("cpu memory\n", "");
        ASSERT_EQ_INT(cgroup_v2_enable_controllers(dir, "pids", &err), 0);
        ASSERT_EQ_INT(err, 0);
        read_in(dir, "cgroup.subtree_control", buf, sizeof(buf));
        ASSERT_STREQ(buf, "");
        done(dir);

        /* Names that are not whole words do not match: "cp" is not "cpu". */
        dir = fake_cgroup("cpu memory\n", "");
        ASSERT_EQ_INT(cgroup_v2_enable_controllers(dir, "cp  mem", &err), 0);
        done(dir);

        /* Not a cgroup directory at all. */
        dir = test_tmpdir_new();
        ASSERT_EQ_INT(cgroup_v2_enable_controllers(dir, "cpu", &err), -ENOENT);
        done(dir);

        /* The kernel refusing the write is reported in *ret_errno, not as a failure of the call:
         * /dev/full stands in for a file that reads empty and cannot be written. */
        dir = fake_cgroup("cpu memory\n", "");
        {
                char path[PATH_MAX];

                path_in(path, sizeof(path), dir, "cgroup.subtree_control");
                ASSERT_EQ_INT(unlink(path), 0);
                ASSERT_EQ_INT(symlink("/dev/full", path), 0);
        }
        ASSERT_EQ_INT(cgroup_v2_enable_controllers(dir, "cpu memory", &err), 0);
        ASSERT_EQ_INT(err, ENOSPC);
        done(dir);

        /* A NULL errno pointer is fine. */
        dir = fake_cgroup("cpu\n", "");
        ASSERT_EQ_INT(cgroup_v2_enable_controllers(dir, "cpu", NULL), 1);
        done(dir);
}

static void test_disable(void) {
        char buf[64];
        char *dir;
        int err;

        dir = fake_cgroup("cpu memory\n", "cpu memory\n");
        ASSERT_EQ_INT(cgroup_v2_disable_controllers(dir, &err), 2);
        ASSERT_EQ_INT(err, 0);
        read_in(dir, "cgroup.subtree_control", buf, sizeof(buf));
        ASSERT_TRUE(strncmp(buf, "-memory", 7) == 0); /* the last of the two writes */
        done(dir);

        dir = fake_cgroup("cpu memory\n", "");
        ASSERT_EQ_INT(cgroup_v2_disable_controllers(dir, &err), 0);
        done(dir);

        dir = test_tmpdir_new();
        ASSERT_EQ_INT(cgroup_v2_disable_controllers(dir, &err), -ENOENT);
        done(dir);
}

static void test_prepare_root(void) {
        char slice[PATH_MAX], buf[64];
        char *root;

        /* A root and a system.slice that both offer controllers: both are written. */
        root = fake_cgroup("cpu memory\n", "");
        mkdir_in(root, "system.slice");
        path_in(slice, sizeof(slice), root, "system.slice");
        ASSERT_EQ_INT(test_write_file(slice, "cgroup.controllers", "cpu memory\n"), 0);
        ASSERT_EQ_INT(test_write_file(slice, "cgroup.subtree_control", ""), 0);
        ASSERT_EQ_INT(cgroup_v2_prepare_root(root), 0);
        read_in(root, "cgroup.subtree_control", buf, sizeof(buf));
        ASSERT_TRUE(strstr(buf, "+memory") != NULL);
        read_in(slice, "cgroup.subtree_control", buf, sizeof(buf));
        ASSERT_TRUE(strstr(buf, "+memory") != NULL);
        done(root);

        /* No cgroup interface in the root: nothing to enable, system.slice is still created, and it is not an error. */
        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);
        ASSERT_EQ_INT(cgroup_v2_prepare_root(root), 0);
        ASSERT_TRUE(exists_in(root, "system.slice"));
        done(root);

        /* system.slice cannot be created. */
        ASSERT_EQ_INT(cgroup_v2_prepare_root("/nonexistent/cgroup-root"), -ENOENT);
}

static void test_remove_below(void) {
        char path[PATH_MAX];
        char *root;
        int i;

        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);
        mkdir_in(root, "a");
        path_in(path, sizeof(path), root, "a");
        mkdir_in(path, "b");
        path_in(path, sizeof(path), root, "a/b");
        mkdir_in(path, "c");
        path_in(path, sizeof(path), root, "a");
        mkdir_in(path, "d");
        mkdir_in(root, "e");

        /* Children go, the directory itself stays. */
        ASSERT_EQ_INT(cgroup_v2_prune_children(root), 0);
        ASSERT_TRUE(!exists_in(root, "a"));
        ASSERT_TRUE(!exists_in(root, "e"));
        ASSERT_TRUE(exists_in(root, "."));

        /* A child that still has "members" (a file here, a process on a real cgroup) is left, with its parents. */
        mkdir_in(root, "x");
        path_in(path, sizeof(path), root, "x");
        mkdir_in(path, "y");
        path_in(path, sizeof(path), root, "x/y");
        ASSERT_EQ_INT(test_write_file(path, "busy", "1"), 0);
        mkdir_in(root, "z");
        ASSERT_TRUE(cgroup_v2_prune_children(root) < 0);
        ASSERT_TRUE(exists_in(root, "x/y"));
        ASSERT_TRUE(!exists_in(root, "z")); /* an independent sibling is still removed */
        ASSERT_TRUE(cgroup_v2_remove_tree(root) < 0);
        ASSERT_TRUE(exists_in(root, "."));

        /* A symlink is not followed: the directory it points to, outside the tree, survives. */
        test_rm_rf(root);
        free(root);
        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);
        {
                char *outside = test_tmpdir_new();
                char target[PATH_MAX];

                ASSERT_TRUE(outside != NULL);
                mkdir_in(outside, "keep");
                path_in(path, sizeof(path), root, "link");
                ASSERT_EQ_INT(symlink(outside, path), 0);
                ASSERT_EQ_INT(cgroup_v2_prune_children(root), 0);
                path_in(target, sizeof(target), outside, "keep");
                ASSERT_TRUE(access(target, F_OK) == 0);
                unlink(path);
                done(outside);
        }

        /* remove_tree takes the directory too, and a missing one is fine. */
        mkdir_in(root, "m");
        ASSERT_EQ_INT(cgroup_v2_remove_tree(root), 0);
        ASSERT_TRUE(!exists_in(root, "."));
        ASSERT_EQ_INT(cgroup_v2_remove_tree(root), 0);
        free(root);

        /* Nesting deeper than any real cgroup tree stops with an error instead of recursing without bound. */
        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);
        {
                char deep[PATH_MAX];
                size_t len = (size_t) snprintf(deep, sizeof(deep), "%s", root);

                for (i = 0; i < 40; i++) {
                        ASSERT_TRUE(len + 3 < sizeof(deep));
                        len += (size_t) snprintf(deep + len, sizeof(deep) - len, "/d");
                        ASSERT_EQ_INT(mkdir(deep, 0755), 0);
                }
        }
        ASSERT_TRUE(cgroup_v2_prune_children(root) < 0);
        test_rm_rf(root);
        free(root);
}

/* A unit cgroup directory with the control files cgroup_v2_new() opens. */
static char *fake_unit(const char *events, const char *subtree_control) {
        char *dir = test_tmpdir_new();

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "cgroup.procs", ""), 0);
        ASSERT_EQ_INT(test_write_file(dir, "cgroup.events", events), 0);
        ASSERT_EQ_INT(test_write_file(dir, "cgroup.subtree_control", subtree_control), 0);
        return dir;
}

static void test_stale_unit_cgroup(void) {
        struct pico_cgroup *cg = NULL;
        char buf[64];
        char *dir;

        /* Empty, with a child and controllers still enabled for it: the child goes, the controllers are switched off. */
        dir = fake_unit("populated 0\nfrozen 0\n", "cpu memory\n");
        mkdir_in(dir, "compositor");
        mkdir_in(dir, "apps");
        ASSERT_EQ_INT(cgroup_v2_new(dir, &cg), 0);
        ASSERT_TRUE(!exists_in(dir, "compositor"));
        ASSERT_TRUE(!exists_in(dir, "apps"));
        read_in(dir, "cgroup.subtree_control", buf, sizeof(buf));
        ASSERT_TRUE(buf[0] == '-');
        cgroup_v2_free(cg);
        done(dir);

        /* Still populated: nothing is touched. */
        dir = fake_unit("populated 1\n", "cpu memory\n");
        mkdir_in(dir, "compositor");
        ASSERT_EQ_INT(cgroup_v2_new(dir, &cg), 0);
        ASSERT_TRUE(exists_in(dir, "compositor"));
        read_in(dir, "cgroup.subtree_control", buf, sizeof(buf));
        ASSERT_STREQ(buf, "cpu memory\n");
        cgroup_v2_free(cg);
        done(dir);

        /* A freshly created cgroup (no stale one) is not "reset". */
        {
                char *base = test_tmpdir_new();
                char path[PATH_MAX];

                ASSERT_TRUE(base != NULL);
                path_in(path, sizeof(path), base, "fresh");
                /* mkdir succeeds, so the control files the open needs are missing: an error, with no directory work done first. */
                ASSERT_TRUE(cgroup_v2_new(path, &cg) < 0);
                done(base);
        }
}

static void test_delegate_to(void) {
        char *dir = test_tmpdir_new();

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "cgroup.procs", ""), 0);
        ASSERT_EQ_INT(test_write_file(dir, "cgroup.subtree_control", ""), 0);
        /* cgroup.threads is missing: skipped. The caller's own ids are always allowed. */
        ASSERT_EQ_INT(cgroup_v2_delegate_to(dir, getuid(), getgid()), 0);
        ASSERT_EQ_INT(cgroup_v2_delegate_to("/nonexistent/cgroup", getuid(), getgid()), -ENOENT);
        done(dir);
}

/* The real hierarchy: a unit cgroup with nested children is removed whole. Skipped where there is no writable cgroup2. */
static void test_real_hierarchy(void) {
        struct pico_cgroup *cg = NULL;
        char path[PATH_MAX], sub[PATH_MAX];
        struct stat st;

        snprintf(path, sizeof(path), "/sys/fs/cgroup/pico-test-delegate-%d", (int) getpid());
        if (cgroup_v2_new(path, &cg) < 0) {
                printf("test-cgroup-delegate: no writable cgroup2 here, real-hierarchy test skipped\n");
                return;
        }

        mkdir_in(path, "compositor");
        mkdir_in(path, "apps");
        path_in(sub, sizeof(sub), path, "apps");
        mkdir_in(sub, "a");

        /* rmdir of the parent alone fails while children exist; the tree removal succeeds. */
        ASSERT_TRUE(rmdir(path) < 0 && errno == EBUSY);
        cgroup_v2_free(cg);
        ASSERT_TRUE(stat(path, &st) < 0 && errno == ENOENT);
}

/* DelegateSubgroup= names, the subgroup mkdir and pid listing by directory. */
static void test_subgroup(void) {
        char *dir;
        char path[PATH_MAX];
        char tiny[8], tiny2[PATH_MAX];
        pid_t pids[4];
        size_t n = 99;
        struct stat st;

        ASSERT_TRUE(cgroup_v2_subgroup_name_valid("main"));
        ASSERT_TRUE(cgroup_v2_subgroup_name_valid("init.scope"));
        ASSERT_TRUE(!cgroup_v2_subgroup_name_valid(NULL));
        ASSERT_TRUE(!cgroup_v2_subgroup_name_valid(""));
        ASSERT_TRUE(!cgroup_v2_subgroup_name_valid("."));
        ASSERT_TRUE(!cgroup_v2_subgroup_name_valid(".control"));
        ASSERT_TRUE(!cgroup_v2_subgroup_name_valid("_x"));
        ASSERT_TRUE(!cgroup_v2_subgroup_name_valid("a/b"));
        ASSERT_TRUE(!cgroup_v2_subgroup_name_valid("cgroup.procs"));

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(cgroup_v2_make_subgroup(dir, "main", path, sizeof(path)), 0);
        ASSERT_TRUE(stat(path, &st) == 0 && S_ISDIR(st.st_mode));
        ASSERT_EQ_INT(cgroup_v2_make_subgroup(dir, "main", path, sizeof(path)), 0); /* again: fine */
        ASSERT_EQ_INT(cgroup_v2_make_subgroup(dir, "main", tiny, sizeof(tiny)), -ENAMETOOLONG);
        ASSERT_EQ_INT(cgroup_v2_make_subgroup("/nonexistent-pico", "main", tiny2, sizeof(tiny2)), -ENOENT);

        ASSERT_EQ_INT(cgroup_v2_get_pids_in(path, pids, 4, &n), -ENOENT); /* no cgroup.procs */
        ASSERT_EQ_INT(test_write_file(path, "cgroup.procs", "11\n22\n"), 0);
        ASSERT_EQ_INT(cgroup_v2_get_pids_in(path, pids, 4, &n), 0);
        ASSERT_EQ_INT((int) n, 2);
        ASSERT_EQ_INT((int) pids[0], 11);
        ASSERT_EQ_INT((int) pids[1], 22);
        ASSERT_EQ_INT(cgroup_v2_get_pids_in(path, pids, 1, &n), 0); /* more than fit: n is the full count */
        ASSERT_EQ_INT((int) n, 2);

        test_rm_rf(dir);
        free(dir);
}

int main(void) {
        test_enable();
        test_disable();
        test_prepare_root();
        test_remove_below();
        test_stale_unit_cgroup();
        test_delegate_to();
        test_subgroup();
        test_real_hierarchy();
        printf("test-cgroup-delegate: all checks passed\n");
        return 0;
}
