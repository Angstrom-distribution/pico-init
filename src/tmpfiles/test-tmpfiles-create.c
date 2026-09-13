/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Real fixtures, real inodes: a tmpfiles.d tree under a --root, applied, and
 * every result read back with lstat()/readlink()/read(). The override case
 * is asserted on the filesystem too -- the /usr/lib line's directory must
 * not exist afterwards, which is what distinguishes an override from a
 * merge once and for all.
 *
 * Ownership assertions need CAP_CHOWN; they run when the test is root (the
 * verification container) and are skipped, not faked, otherwise.
 *
 * The last case runs the built pico-tmpfiles binary itself, found next to
 * this test via /proc/self/exe as test-picoctl.c does, so the command line
 * and exit codes the unit file relies on are covered end to end.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../test-util.h"
#include "../util.h"
#include "tmpfiles.h"

static char *root;
static bool is_root;

#define TEST_UID 65534
#define TEST_GID 65534

static void fullpath(const char *rel, char *buf, size_t size) {
        ASSERT_TRUE(snprintf(buf, size, "%s%s", root, rel) < (int) size);
}

static int lstat_rel(const char *rel, struct stat *st) {
        char p[PATH_MAX];

        fullpath(rel, p, sizeof(p));
        return lstat(p, st) < 0 ? -errno : 0;
}

static void assert_dir(const char *rel, mode_t mode) {
        struct stat st;

        ASSERT_EQ_INT(lstat_rel(rel, &st), 0);
        ASSERT_TRUE(S_ISDIR(st.st_mode));
        ASSERT_EQ_INT(st.st_mode & 07777, mode);
}

static void assert_absent(const char *rel) {
        struct stat st;

        ASSERT_EQ_INT(lstat_rel(rel, &st), -ENOENT);
}

static void assert_file_content(const char *rel, const char *content) {
        char p[PATH_MAX], buf[256];
        int fd;
        ssize_t n;

        fullpath(rel, p, sizeof(p));
        fd = open(p, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        ASSERT_TRUE(fd >= 0);
        n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        ASSERT_TRUE(n >= 0);
        buf[n] = '\0';
        ASSERT_STREQ(buf, content);
}

static void assert_symlink(const char *rel, const char *target) {
        char p[PATH_MAX], buf[PATH_MAX];
        struct stat st;
        ssize_t n;

        ASSERT_EQ_INT(lstat_rel(rel, &st), 0);
        ASSERT_TRUE(S_ISLNK(st.st_mode));
        fullpath(rel, p, sizeof(p));
        n = readlink(p, buf, sizeof(buf) - 1);
        ASSERT_TRUE(n >= 0);
        buf[n] = '\0';
        ASSERT_STREQ(buf, target);
}

static void assert_owner(const char *rel, uid_t uid, gid_t gid) {
        struct stat st;

        if (!is_root)
                return;
        ASSERT_EQ_INT(lstat_rel(rel, &st), 0);
        ASSERT_EQ_INT(st.st_uid, uid);
        ASSERT_EQ_INT(st.st_gid, gid);
}

static void write_conf(const char *rel, const char *content) {
        ASSERT_EQ_INT(test_write_file(root, rel, content), 0);
}

static void setup_tree(void) {
        ASSERT_EQ_INT(test_mkdir(root, "etc"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "etc/tmpfiles.d"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "usr"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "usr/lib"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "usr/lib/tmpfiles.d"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "usr/share"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "usr/share/factory"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "usr/share/factory/etc"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "run"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "var"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "tmp"), 0);
}

static int apply(bool boot) {
        PicoTmpfiles *t = NULL;
        int r;

        ASSERT_EQ_INT(pico_tmpfiles_new(&t), 0);
        ASSERT_EQ_INT(pico_tmpfiles_set_root(t, root), 0);
        t->boot = boot;
        ASSERT_EQ_INT(pico_tmpfiles_read_config(t), 0);
        ASSERT_TRUE(!t->invalid_config);
        r = pico_tmpfiles_create(t);
        pico_tmpfiles_free(t);
        return r;
}

/* The acceptance fixture: one vendor file with the line types that matter. */
static void test_vendor_fixture(void) {
        char conf[1024];

        /* copy sources, and a factory tree for the argument-less C and L */
        ASSERT_EQ_INT(test_mkdir(root, "usr/share/skel"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "usr/share/skel/sub"), 0);
        write_conf("usr/share/skel/a.txt", "alpha");
        write_conf("usr/share/skel/sub/b.txt", "beta");
        ASSERT_EQ_INT(test_symlink(root, "usr/share/skel/lnk", "a.txt"), 0);
        write_conf("usr/share/factory/etc/issue", "factory issue");

        ASSERT_TRUE(snprintf(conf,
                             sizeof(conf),
                             "# a vendor snippet, the shapes oe-core packages really ship\n"
                             "d /run/named 0750 %u %u - -\n"
                             "d /var/lib/iptraf-ng 0755 root root -\n"
                             "D! /tmp/.X11-unix 1777 root root 10d\n"
                             "f /run/motd 0640 %u root - Welcome\\n\n"
                             "F /run/truncated 0600 - - - fresh\n"
                             "L /run/link - - - - /dev/null\n"
                             "L /etc/os-release - - - - ../usr/lib/os-release\n"
                             "L+ /run/forced - - - - /run/named\n"
                             "C /var/lib/skel 0700 %u %u - /usr/share/skel\n"
                             "C! /etc/issue - - - -\n"
                             "d /run/deep/parent/child 0700 - -\n"
                             "z /run/named 2750 - %u\n"
                             "Z /var/lib/skel - %u -\n"
                             "x /run/named/*\n"
                             "w /run/motd - - - - overwritten\n",
                             TEST_UID,
                             TEST_GID,
                             TEST_UID,
                             TEST_UID,
                             TEST_GID,
                             TEST_GID,
                             TEST_GID) < (int) sizeof(conf));
        write_conf("usr/lib/tmpfiles.d/vendor.conf", conf);

        /* pre-existing state the lines must cope with */
        write_conf("run/truncated", "stale content that must go");
        write_conf("run/forced", "a regular file where a symlink belongs");

        ASSERT_EQ_INT(apply(true), 0);

        assert_dir("/run/named", 02750); /* d created it 0750, z then set 2750 */
        assert_owner("/run/named", TEST_UID, TEST_GID);
        assert_dir("/var/lib/iptraf-ng", 0755);
        assert_dir("/tmp/.X11-unix", 01777);
        assert_file_content("/run/motd", "Welcome\n");
        assert_owner("/run/motd", TEST_UID, 0);
        {
                struct stat st;

                ASSERT_EQ_INT(lstat_rel("/run/motd", &st), 0);
                ASSERT_EQ_INT(st.st_mode & 07777, 0640);
        }
        assert_file_content("/run/truncated", "fresh");
        assert_symlink("/run/link", "/dev/null");
        assert_symlink("/etc/os-release", "../usr/lib/os-release");
        assert_symlink("/run/forced", "/run/named");
        assert_file_content("/var/lib/skel/a.txt", "alpha");
        assert_file_content("/var/lib/skel/sub/b.txt", "beta");
        assert_symlink("/var/lib/skel/lnk", "a.txt");
        assert_dir("/var/lib/skel", 0700);
        assert_owner("/var/lib/skel", TEST_UID, TEST_GID);
        assert_owner("/var/lib/skel/sub/b.txt", TEST_UID, TEST_GID); /* Z recursed */
        assert_file_content("/etc/issue", "factory issue");
        assert_dir("/run/deep/parent/child", 0700);
        assert_dir("/run/deep/parent", 0755); /* implicit parents are 0755 */
        assert_dir("/run/deep", 0755);

        /* a second run is idempotent: nothing changes, nothing fails */
        write_conf("run/truncated", "written since boot");
        ASSERT_EQ_INT(apply(true), 0);
        assert_file_content("/run/motd", "Welcome\n");  /* f never rewrites */
        assert_file_content("/run/truncated", "fresh"); /* F always does */
        assert_dir("/run/named", 02750);

        /* and without --boot the ! lines are skipped, everything else applies */
        test_rm_rf(root);
        ASSERT_EQ_INT(mkdir(root, 0755), 0);
        setup_tree();
        write_conf("usr/lib/tmpfiles.d/vendor.conf", conf);
        ASSERT_EQ_INT(test_mkdir(root, "usr/share/skel"), 0);
        write_conf("usr/share/skel/a.txt", "alpha");
        ASSERT_EQ_INT(apply(false), 0);
        assert_absent("/tmp/.X11-unix");
        assert_absent("/etc/issue");
        assert_dir("/run/named", 02750);
}

/* /etc/tmpfiles.d/<name>.conf replaces /usr/lib/tmpfiles.d/<name>.conf entirely. */
static void test_etc_overrides_usr_lib(void) {
        test_rm_rf(root);
        ASSERT_EQ_INT(mkdir(root, 0755), 0);
        setup_tree();

        write_conf("usr/lib/tmpfiles.d/foo.conf",
                   "d /run/from-lib 0755 root root -\n"
                   "d /run/shared 0700 root root -\n"
                   "f /run/lib-only-file 0644 root root - from lib\n");
        write_conf("etc/tmpfiles.d/foo.conf",
                   "d /run/from-etc 0755 root root -\n"
                   "d /run/shared 0750 root root -\n");

        ASSERT_EQ_INT(apply(true), 0);

        assert_dir("/run/from-etc", 0755);
        assert_dir("/run/shared", 0750);
        /* the two lines only the vendor file had must not have run */
        assert_absent("/run/from-lib");
        assert_absent("/run/lib-only-file");
}

/* A /dev/null symlink in /etc masks the vendor file of the same name. */
static void test_dev_null_mask(void) {
        test_rm_rf(root);
        ASSERT_EQ_INT(mkdir(root, 0755), 0);
        setup_tree();

        write_conf("usr/lib/tmpfiles.d/etc.conf", "d /run/masked 0755 root root -\n");
        write_conf("usr/lib/tmpfiles.d/other.conf", "d /run/unmasked 0755 root root -\n");
        ASSERT_EQ_INT(test_symlink(root, "etc/tmpfiles.d/etc.conf", "/dev/null"), 0);

        ASSERT_EQ_INT(apply(true), 0);

        assert_absent("/run/masked");
        assert_dir("/run/unmasked", 0755);
}

/* The details of a second boot: existing inodes, ':' prefixes, L vs L+. */
static void test_existing_inodes(void) {
        test_rm_rf(root);
        ASSERT_EQ_INT(mkdir(root, 0755), 0);
        setup_tree();

        ASSERT_EQ_INT(test_mkdir(root, "run/existing"), 0);
        {
                char p[PATH_MAX];

                fullpath("/run/existing", p, sizeof(p));
                ASSERT_EQ_INT(chmod(p, 0755), 0);
        }
        write_conf("run/keepme", "keep");
        write_conf("run/inway", "a file, not a link");

        write_conf("usr/lib/tmpfiles.d/x.conf",
                   "d /run/existing :0700 - -\n"        /* only on create: stays as found */
                   "d /run/existing2 0700 - -\n"        /* adjusted even when present */
                   "f /run/keepme 0600 - - - new\n"     /* content kept, mode applied */
                   "L /run/inway - - - - /dev/null\n"   /* left alone */
                   "L+ /run/inway2 - - - - /dev/null\n" /* replaced */
                   "d /run/child-first/leaf 0700 - -\n"
                   "d /run/child-first :0710 - -\n"); /* parent line applies before the child's mkdir */

        write_conf("run/inway2", "a file, not a link");
        ASSERT_EQ_INT(test_mkdir(root, "run/existing2"), 0);

        ASSERT_EQ_INT(apply(true), 0);

        assert_dir("/run/existing", 0755);
        assert_dir("/run/existing2", 0700);
        assert_file_content("/run/keepme", "keep");
        {
                struct stat st;

                ASSERT_EQ_INT(lstat_rel("/run/keepme", &st), 0);
                ASSERT_EQ_INT(st.st_mode & 07777, 0600);
                ASSERT_EQ_INT(lstat_rel("/run/inway", &st), 0);
                ASSERT_TRUE(S_ISREG(st.st_mode));
        }
        assert_symlink("/run/inway2", "/dev/null");
        assert_dir("/run/child-first", 0710);
        assert_dir("/run/child-first/leaf", 0700);
}

/* A path that cannot be honoured fails the run unless the line says '-'. */
static void test_failure_reporting(void) {
        test_rm_rf(root);
        ASSERT_EQ_INT(mkdir(root, 0755), 0);
        setup_tree();

        write_conf("run/notadir", "x");
        write_conf("usr/lib/tmpfiles.d/f.conf",
                   "d /run/notadir 0755 - -\n"
                   "d /run/still-created 0755 - -\n");
        ASSERT_EQ_INT(apply(true), -EEXIST);
        assert_dir("/run/still-created", 0755);

        write_conf("usr/lib/tmpfiles.d/f.conf", "d- /run/notadir 0755 - -\n");
        ASSERT_EQ_INT(apply(true), 0);
}

/* --- the binary itself ---------------------------------------------------- */

static int sibling_binary_path(const char *name, char *out, size_t out_size) {
        char self[PATH_MAX];
        ssize_t n;
        char *slash;

        n = readlink("/proc/self/exe", self, sizeof(self) - 1);
        if (n < 0)
                return -errno;
        self[n] = '\0';

        slash = strrchr(self, '/');
        if (!slash)
                return -ENOENT;
        *slash = '\0';

        n = snprintf(out, out_size, "%s/%s", self, name);
        if (n < 0 || (size_t) n >= out_size)
                return -ENAMETOOLONG;
        return 0;
}

static int run_binary(char * const args[]) {
        pid_t pid;
        int status;

        pid = fork();
        if (pid < 0)
                return -errno;
        if (pid == 0) {
                execv(args[0], args);
                _exit(127);
        }
        if (waitpid(pid, &status, 0) < 0)
                return -errno;
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void test_cli(void) {
        char bin[PATH_MAX], rootarg[PATH_MAX];

        ASSERT_EQ_INT(sibling_binary_path("pico-tmpfiles", bin, sizeof(bin)), 0);
        ASSERT_TRUE(snprintf(rootarg, sizeof(rootarg), "--root=%s", root) < (int) sizeof(rootarg));

        test_rm_rf(root);
        ASSERT_EQ_INT(mkdir(root, 0755), 0);
        setup_tree();
        write_conf("usr/lib/tmpfiles.d/cli.conf",
                   "d /run/cli 0755 root root -\n"
                   "d! /run/cli-boot 0755 root root -\n"
                   "L /run/cli-link - - - - /run/cli\n");
        write_conf("usr/lib/tmpfiles.d/other.conf", "d /run/cli-other 0755 root root -\n");

        /* the unit's own invocation */
        {
                char *args[] = { bin, "--create", "--boot", rootarg, NULL };

                ASSERT_EQ_INT(run_binary(args), 0);
        }
        assert_dir("/run/cli", 0755);
        assert_dir("/run/cli-boot", 0755);
        assert_symlink("/run/cli-link", "/run/cli");
        assert_dir("/run/cli-other", 0755);

        /* a named file restricts the run to that file; a bare name is found */
        test_rm_rf(root);
        ASSERT_EQ_INT(mkdir(root, 0755), 0);
        setup_tree();
        write_conf("usr/lib/tmpfiles.d/cli.conf", "d /run/cli 0755 root root -\n");
        write_conf("usr/lib/tmpfiles.d/other.conf", "d /run/cli-other 0755 root root -\n");
        {
                char *args[] = { bin, "--create", rootarg, "cli.conf", NULL };

                ASSERT_EQ_INT(run_binary(args), 0);
        }
        assert_dir("/run/cli", 0755);
        assert_absent("/run/cli-other");

        /* invalid configuration is EX_DATAERR, the good lines still apply */
        write_conf("usr/lib/tmpfiles.d/bad.conf",
                   "k /run/unknown-type\n"
                   "d /run/good 0755 root root -\n");
        {
                char *args[] = { bin, "--create", rootarg, NULL };

                ASSERT_EQ_INT(run_binary(args), PICO_TMPFILES_EX_DATAERR);
        }
        assert_dir("/run/good", 0755);

        /* a creation failure is EX_CANTCREAT */
        write_conf("usr/lib/tmpfiles.d/bad.conf", "d /run/good/notadir/x 0755 root root -\n");
        write_conf("run/good/notadir", "file");
        {
                char *args[] = { bin, "--create", rootarg, NULL };

                ASSERT_EQ_INT(run_binary(args), PICO_TMPFILES_EX_CANTCREAT);
        }

        /* the deferred half is refused, not silently accepted */
        {
                char *args[] = { bin, "--clean", rootarg, NULL };

                ASSERT_EQ_INT(run_binary(args), EXIT_FAILURE);
        }
        {
                char *args[] = { bin, rootarg, NULL };

                ASSERT_EQ_INT(run_binary(args), EXIT_FAILURE);
        }
}

int main(void) {
        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);
        is_root = geteuid() == 0;
        if (!is_root)
                fprintf(stderr, "not root: ownership assertions skipped\n");

        setup_tree();
        test_vendor_fixture();
        test_etc_overrides_usr_lib();
        test_dev_null_mask();
        test_existing_inodes();
        test_failure_reporting();
        test_cli();

        test_rm_rf(root);
        free(root);
        printf("test-tmpfiles-create: all passed\n");
        return 0;
}
