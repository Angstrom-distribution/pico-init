/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * --clean and --remove against real inodes of controlled ages under a
 * --root. Ages are set with utimensat(), which moves atime and mtime but
 * not ctime, so the cases that must delete use an explicit "am:" age-by,
 * and the default age-by (which includes ctime for files) is asserted to
 * keep such a file -- that is the rule protecting a file somebody just
 * chmod()ed, not an artefact of the fixture.
 *
 * The exceptions a running system depends on are each exercised: x and X
 * lines, an entry with a line of its own, the sticky bit, a listening
 * AF_UNIX socket, a BSD-locked file, and ~ keeping the first level. The
 * last case runs the pico-tmpfiles binary itself (found next to this test
 * via /proc/self/exe), including --remove before --create in one call.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../test-util.h"
#include "../util.h"
#include "tmpfiles.h"

static char *root;

#define OLD (2 * 3600) /* seconds; every aged line below says 1h */

static void fullpath(const char *rel, char *buf, size_t size) {
        ASSERT_TRUE(snprintf(buf, size, "%s%s", root, rel) < (int) size);
}

static bool exists(const char *rel) {
        char p[PATH_MAX];
        struct stat st;

        fullpath(rel, p, sizeof(p));
        return lstat(p, &st) == 0;
}

static void mkdir_rel(const char *rel) {
        char p[PATH_MAX];

        fullpath(rel, p, sizeof(p));
        ASSERT_EQ_INT(mkdir(p, 0755), 0);
}

static void file_rel(const char *rel) {
        ASSERT_EQ_INT(test_write_file(root, rel + 1, "x"), 0);
}

/* atime and mtime `ago` seconds in the past; call children before parents */
static void age_rel(const char *rel, time_t ago) {
        char p[PATH_MAX];
        struct timespec ts[2];

        fullpath(rel, p, sizeof(p));
        ts[0].tv_sec = time(NULL) - ago;
        ts[0].tv_nsec = 0;
        ts[1] = ts[0];
        ASSERT_EQ_INT(utimensat(AT_FDCWD, p, ts, AT_SYMLINK_NOFOLLOW), 0);
}

static void fresh_root(void) {
        test_rm_rf(root);
        ASSERT_EQ_INT(mkdir(root, 0755), 0);
        mkdir_rel("/etc");
        mkdir_rel("/etc/tmpfiles.d");
        mkdir_rel("/run");
        mkdir_rel("/var");
        mkdir_rel("/var/tmp");
}

static void write_conf(const char *content) {
        ASSERT_EQ_INT(test_write_file(root, "etc/tmpfiles.d/test.conf", content), 0);
}

static int run(unsigned operations) {
        PicoTmpfiles *t = NULL;
        int r;

        ASSERT_EQ_INT(pico_tmpfiles_new(&t), 0);
        ASSERT_EQ_INT(pico_tmpfiles_set_root(t, root), 0);
        ASSERT_EQ_INT(pico_tmpfiles_read_config(t), 0);
        ASSERT_TRUE(!t->invalid_config);
        r = pico_tmpfiles_remove_and_clean(t, operations);
        pico_tmpfiles_free(t);
        return r;
}

/* a bound AF_UNIX socket at `rel`; listening (kept open) or left behind (closed) */
static int unix_socket_rel(const char *rel, bool listening) {
        struct sockaddr_un sa = { .sun_family = AF_UNIX };
        int fd;

        fullpath(rel, sa.sun_path, sizeof(sa.sun_path));
        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        ASSERT_TRUE(fd >= 0);
        ASSERT_EQ_INT(bind(fd, (struct sockaddr *) &sa, sizeof(sa)), 0);
        if (!listening) {
                close(fd);
                return -1;
        }
        ASSERT_EQ_INT(listen(fd, 1), 0);
        return fd;
}

static void test_clean_by_age(void) {
        char p[PATH_MAX];
        struct stat st;
        time_t top_mtime;
        int sock, lockfd;

        fresh_root();
        write_conf("d /var/tmp/c 0755 - - am:1h\n"
                   "x /var/tmp/c/keep*\n"
                   "X /var/tmp/c/xdir\n"
                   "d /var/tmp/c/own 0755 - - -\n"
                   "d /var/tmp/noage 0755 - - -\n"
                   "d /var/tmp/dflt 0755 - - 1h\n"
                   "d /var/tmp/first 0755 - - ~am:1h\n"
                   "e /var/tmp/e* - - - am:1h\n");

        mkdir_rel("/var/tmp/c");
        file_rel("/var/tmp/c/old.txt");
        age_rel("/var/tmp/c/old.txt", OLD);
        file_rel("/var/tmp/c/new.txt");
        file_rel("/var/tmp/c/keepme.txt");
        age_rel("/var/tmp/c/keepme.txt", OLD);
        file_rel("/var/tmp/c/sticky.txt");
        fullpath("/var/tmp/c/sticky.txt", p, sizeof(p));
        ASSERT_EQ_INT(chmod(p, 01644), 0);
        age_rel("/var/tmp/c/sticky.txt", OLD);
        mkdir_rel("/var/tmp/c/oldsub");
        file_rel("/var/tmp/c/oldsub/f");
        age_rel("/var/tmp/c/oldsub/f", OLD);
        age_rel("/var/tmp/c/oldsub", OLD);
        mkdir_rel("/var/tmp/c/newsub");
        file_rel("/var/tmp/c/newsub/f");
        age_rel("/var/tmp/c/newsub/f", OLD);
        mkdir_rel("/var/tmp/c/xdir");
        file_rel("/var/tmp/c/xdir/f");
        age_rel("/var/tmp/c/xdir/f", OLD);
        file_rel("/var/tmp/c/xdir/g");
        age_rel("/var/tmp/c/xdir", OLD);
        mkdir_rel("/var/tmp/c/own");
        file_rel("/var/tmp/c/own/f");
        age_rel("/var/tmp/c/own/f", OLD);
        age_rel("/var/tmp/c/own", OLD);
        sock = unix_socket_rel("/var/tmp/c/live.sock", true);
        age_rel("/var/tmp/c/live.sock", OLD);
        (void) unix_socket_rel("/var/tmp/c/dead.sock", false);
        age_rel("/var/tmp/c/dead.sock", OLD);
        file_rel("/var/tmp/c/locked.txt");
        age_rel("/var/tmp/c/locked.txt", OLD);
        fullpath("/var/tmp/c/locked.txt", p, sizeof(p));
        lockfd = open(p, O_RDONLY | O_CLOEXEC);
        ASSERT_TRUE(lockfd >= 0);
        ASSERT_EQ_INT(flock(lockfd, LOCK_EX), 0);
        age_rel("/var/tmp/c", OLD);
        fullpath("/var/tmp/c", p, sizeof(p));
        ASSERT_EQ_INT(stat(p, &st), 0);
        top_mtime = st.st_mtime;

        mkdir_rel("/var/tmp/noage");
        file_rel("/var/tmp/noage/old.txt");
        age_rel("/var/tmp/noage/old.txt", OLD);

        mkdir_rel("/var/tmp/dflt");
        file_rel("/var/tmp/dflt/old.txt");
        age_rel("/var/tmp/dflt/old.txt", OLD);
        mkdir_rel("/var/tmp/dflt/emptyold");
        age_rel("/var/tmp/dflt/emptyold", OLD);

        mkdir_rel("/var/tmp/first");
        file_rel("/var/tmp/first/old.txt");
        age_rel("/var/tmp/first/old.txt", OLD);
        mkdir_rel("/var/tmp/first/sub");
        file_rel("/var/tmp/first/sub/f");
        age_rel("/var/tmp/first/sub/f", OLD);
        age_rel("/var/tmp/first/sub", OLD);

        mkdir_rel("/var/tmp/e1");
        file_rel("/var/tmp/e1/old.txt");
        age_rel("/var/tmp/e1/old.txt", OLD);
        file_rel("/var/tmp/e1/new.txt");

        /* --remove alone touches none of this: no r/R/D lines */
        ASSERT_EQ_INT(run(PICO_TMPFILES_REMOVE), 0);
        ASSERT_TRUE(exists("/var/tmp/c/old.txt"));

        ASSERT_EQ_INT(run(PICO_TMPFILES_CLEAN), 0);

        ASSERT_TRUE(!exists("/var/tmp/c/old.txt"));
        ASSERT_TRUE(exists("/var/tmp/c/new.txt"));
        ASSERT_TRUE(exists("/var/tmp/c/keepme.txt")); /* x */
        ASSERT_TRUE(exists("/var/tmp/c/sticky.txt"));
        ASSERT_TRUE(!exists("/var/tmp/c/oldsub/f"));
        ASSERT_TRUE(!exists("/var/tmp/c/oldsub"));
        ASSERT_TRUE(!exists("/var/tmp/c/newsub/f"));
        ASSERT_TRUE(exists("/var/tmp/c/newsub"));  /* its own times were new */
        ASSERT_TRUE(exists("/var/tmp/c/xdir"));    /* X: the directory stays... */
        ASSERT_TRUE(!exists("/var/tmp/c/xdir/f")); /* ...its old content does not */
        ASSERT_TRUE(exists("/var/tmp/c/xdir/g"));
        ASSERT_TRUE(exists("/var/tmp/c/own/f")); /* a line of its own, no age */
        ASSERT_TRUE(exists("/var/tmp/c/live.sock"));
        ASSERT_TRUE(!exists("/var/tmp/c/dead.sock"));
        ASSERT_TRUE(exists("/var/tmp/c/locked.txt"));
        ASSERT_TRUE(exists("/var/tmp/c"));

        /* deleting from it must not make the directory look freshly used */
        ASSERT_EQ_INT(stat(p, &st), 0);
        ASSERT_EQ_INT(st.st_mtime, top_mtime);

        ASSERT_TRUE(exists("/var/tmp/noage/old.txt"));

        /* default age-by: a file's new ctime keeps it, a directory's does not count */
        ASSERT_TRUE(exists("/var/tmp/dflt/old.txt"));
        ASSERT_TRUE(!exists("/var/tmp/dflt/emptyold"));

        /* ~: nothing at the first level goes, deeper levels are cleaned */
        ASSERT_TRUE(exists("/var/tmp/first/old.txt"));
        ASSERT_TRUE(exists("/var/tmp/first/sub"));
        ASSERT_TRUE(!exists("/var/tmp/first/sub/f"));

        ASSERT_TRUE(!exists("/var/tmp/e1/old.txt"));
        ASSERT_TRUE(exists("/var/tmp/e1/new.txt"));

        /* once the lock is gone, the file is old enough like any other */
        close(lockfd);
        ASSERT_EQ_INT(run(PICO_TMPFILES_CLEAN), 0);
        ASSERT_TRUE(!exists("/var/tmp/c/locked.txt"));
        close(sock);
}

/* r/R lines that carry an age are cleaned by it; --clean ignores those without */
static void test_clean_remove_lines(void) {
        fresh_root();
        write_conf("r /run/oldr - - - am:1h\n"
                   "r /run/newr - - - am:1h\n"
                   "r /run/noage\n"
                   "R /run/oldtree - - - am:1h\n"
                   "R /run/oldtree2 - - - am:1h\n"
                   "R /run/newtree - - - am:1h\n");

        file_rel("/run/oldr");
        age_rel("/run/oldr", OLD);
        file_rel("/run/newr");
        file_rel("/run/noage");
        age_rel("/run/noage", OLD);
        mkdir_rel("/run/oldtree");
        file_rel("/run/oldtree/f");
        age_rel("/run/oldtree/f", OLD);
        file_rel("/run/oldtree/g");
        age_rel("/run/oldtree", OLD);
        mkdir_rel("/run/oldtree2");
        file_rel("/run/oldtree2/f");
        age_rel("/run/oldtree2/f", OLD);
        age_rel("/run/oldtree2", OLD);
        mkdir_rel("/run/newtree");
        file_rel("/run/newtree/f");
        age_rel("/run/newtree/f", OLD);

        ASSERT_EQ_INT(run(PICO_TMPFILES_CLEAN), 0);

        ASSERT_TRUE(!exists("/run/oldr"));
        ASSERT_TRUE(exists("/run/newr"));
        ASSERT_TRUE(exists("/run/noage"));
        ASSERT_TRUE(!exists("/run/oldtree/f"));
        ASSERT_TRUE(exists("/run/oldtree/g"));
        ASSERT_TRUE(exists("/run/oldtree")); /* not empty */
        ASSERT_TRUE(!exists("/run/oldtree2"));
        ASSERT_TRUE(!exists("/run/newtree/f"));
        ASSERT_TRUE(exists("/run/newtree")); /* emptied, but itself too new */
}

/* A filesystem mounted below a cleaned directory is never walked into. */
static void test_clean_stops_at_mounts(void) {
        pid_t pid;
        int status;

        fresh_root();
        write_conf("d /var/tmp/m 0755 - - am:1h\n");
        mkdir_rel("/var/tmp/m");
        mkdir_rel("/var/tmp/m/mnt");

        pid = fork();
        ASSERT_TRUE(pid >= 0);
        if (pid == 0) {
                char p[PATH_MAX];

                if (!test_enter_mount_namespace())
                        _exit(77);
                fullpath("/var/tmp/m/mnt", p, sizeof(p));
                ASSERT_EQ_INT(mount("tmpfs", p, "tmpfs", 0, NULL), 0);
                file_rel("/var/tmp/m/mnt/old");
                age_rel("/var/tmp/m/mnt/old", OLD);
                age_rel("/var/tmp/m/mnt", OLD);

                ASSERT_EQ_INT(run(PICO_TMPFILES_CLEAN), 0);
                ASSERT_TRUE(exists("/var/tmp/m/mnt/old"));
                _exit(0);
        }

        ASSERT_TRUE(waitpid(pid, &status, 0) == pid);
        ASSERT_TRUE(WIFEXITED(status));
        if (WEXITSTATUS(status) == 77) {
                fprintf(stderr, "no user namespaces: mount boundary case skipped\n");
                return;
        }
        ASSERT_EQ_INT(WEXITSTATUS(status), 0);
}

/* --remove deletes r/R targets whatever their age, and empties D directories */
static void test_remove(void) {
        fresh_root();
        write_conf("r /run/rfile\n"
                   "r /run/rglob-*\n"
                   "r /run/rempty\n"
                   "r /run/aged - - - 10d\n"
                   "r /run/missing\n"
                   "R /run/tree\n"
                   "x /run/tree/keep\n"
                   "R /run/tree2\n"
                   "D /run/dd 0755 - - -\n"
                   "d /run/plain 0755 - - -\n");

        file_rel("/run/rfile");
        file_rel("/run/rglob-a");
        file_rel("/run/rglob-b");
        file_rel("/run/rglob");
        mkdir_rel("/run/rempty");
        file_rel("/run/aged");
        mkdir_rel("/run/tree");
        file_rel("/run/tree/a");
        mkdir_rel("/run/tree/sub");
        file_rel("/run/tree/sub/b");
        file_rel("/run/tree/keep");
        mkdir_rel("/run/tree2");
        mkdir_rel("/run/tree2/sub");
        mkdir_rel("/run/tree2/sub/deeper");
        file_rel("/run/tree2/sub/deeper/c");
        mkdir_rel("/run/dd");
        file_rel("/run/dd/stale");
        mkdir_rel("/run/dd/sub");
        file_rel("/run/dd/sub/stale");
        mkdir_rel("/run/plain");
        file_rel("/run/plain/kept");

        /* --clean alone removes none of it: the one aged line's file is new */
        ASSERT_EQ_INT(run(PICO_TMPFILES_CLEAN), 0);
        ASSERT_TRUE(exists("/run/rfile"));
        ASSERT_TRUE(exists("/run/aged"));

        ASSERT_EQ_INT(run(PICO_TMPFILES_REMOVE), 0);

        ASSERT_TRUE(!exists("/run/rfile"));
        ASSERT_TRUE(!exists("/run/rglob-a"));
        ASSERT_TRUE(!exists("/run/rglob-b"));
        ASSERT_TRUE(exists("/run/rglob"));
        ASSERT_TRUE(!exists("/run/rempty"));
        ASSERT_TRUE(!exists("/run/aged")); /* new, but --remove ignores age */
        ASSERT_TRUE(!exists("/run/tree/a"));
        ASSERT_TRUE(!exists("/run/tree/sub"));
        ASSERT_TRUE(exists("/run/tree/keep")); /* x */
        ASSERT_TRUE(exists("/run/tree"));      /* so not empty, and kept */
        ASSERT_TRUE(!exists("/run/tree2"));
        ASSERT_TRUE(exists("/run/dd"));
        ASSERT_TRUE(!exists("/run/dd/stale"));
        ASSERT_TRUE(!exists("/run/dd/sub"));
        ASSERT_TRUE(exists("/run/plain/kept"));

        /* r never recurses: a populated directory is a failure, left intact */
        fresh_root();
        write_conf("r /run/full\n");
        mkdir_rel("/run/full");
        file_rel("/run/full/f");
        ASSERT_EQ_INT(run(PICO_TMPFILES_REMOVE), -ENOTEMPTY);
        ASSERT_TRUE(exists("/run/full/f"));
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

        /* --clean on its own */
        fresh_root();
        write_conf("d /var/tmp/c 0755 - - am:1h\n");
        mkdir_rel("/var/tmp/c");
        file_rel("/var/tmp/c/old");
        age_rel("/var/tmp/c/old", OLD);
        file_rel("/var/tmp/c/new");
        {
                char *args[] = { bin, "--clean", rootarg, NULL };

                ASSERT_EQ_INT(run_binary(args), 0);
        }
        ASSERT_TRUE(!exists("/var/tmp/c/old"));
        ASSERT_TRUE(exists("/var/tmp/c/new"));

        /* --remove runs before --create: D is emptied, then its f line refills it */
        fresh_root();
        write_conf("D /run/dd 0755 - - -\n"
                   "f /run/dd/fresh 0644 - - - made\n"
                   "R /run/gone\n");
        mkdir_rel("/run/dd");
        file_rel("/run/dd/stale");
        mkdir_rel("/run/gone");
        file_rel("/run/gone/f");
        {
                char *args[] = { bin, "--create", "--remove", rootarg, NULL };

                ASSERT_EQ_INT(run_binary(args), 0);
        }
        ASSERT_TRUE(!exists("/run/dd/stale"));
        ASSERT_TRUE(exists("/run/dd/fresh"));
        ASSERT_TRUE(!exists("/run/gone"));

        /* a removal failure is EX_CANTCREAT, as upstream */
        fresh_root();
        write_conf("r /run/full\n");
        mkdir_rel("/run/full");
        file_rel("/run/full/f");
        {
                char *args[] = { bin, "--remove", rootarg, NULL };

                ASSERT_EQ_INT(run_binary(args), PICO_TMPFILES_EX_CANTCREAT);
        }
}

int main(void) {
        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);

        test_clean_by_age();
        test_clean_remove_lines();
        test_clean_stops_at_mounts();
        test_remove();
        test_cli();

        test_rm_rf(root);
        free(root);
        printf("test-tmpfiles-clean: all passed\n");
        return 0;
}
