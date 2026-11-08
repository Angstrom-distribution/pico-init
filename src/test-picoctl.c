/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * picoctl's file and symlink half: golden-output tests per verb against fixture state trees,
 * systemctl-matching exit codes, and symlink layouts byte-identical to systemctl --root on the same fixtures.
 *
 * This program is linked against pico-init-core, not picoctl.c (picoctl has
 * its own main() and there is no picoctl-core library). So every case runs the
 * built `picoctl` binary as a subprocess, found next to this test binary via
 * /proc/self/exe, and asserts its stdout and exit code.
 *
 * The oracle test (test_oracle_symlinks_byte_identical) compares against the
 * real `systemctl --root`. It SKIPs (exit 77) when systemctl is not on PATH,
 * so `meson test` stays green on hosts without systemd.
 */

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "manager.h"
#include "service.h"
#include "target.h"
#include "test-util.h"
#include "timer.h"
#include "unit.h"

/* --- running the real picoctl/systemctl binaries as subprocesses --- */

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

struct run_result {
        char out[16384];
        char err[4096];
        int exit_code;
};

/*
 * Fork/exec `path` with `args` (NULL-terminated, args[0] reused as argv[0]),
 * stdout captured into res->out and stderr into res->err, exit code decoded
 * from waitpid(). The two streams stay apart because they are separate
 * contracts: real systemctl keeps its state words on stdout and its
 * diagnostics on stderr, and golden-output comparisons of stdout must not
 * depend on diagnostic wording. The captured stderr is replayed to this
 * process's own stderr, so a failing assertion's context is still visible
 * under `meson test -v`.
 */
static int run_binary(const char *path, char * const args[], struct run_result *res) {
        int outfd[2], errfd[2];
        pid_t pid;
        int status;
        size_t out_total = 0, err_total = 0;
        bool out_open = true, err_open = true;

        res->out[0] = '\0';
        res->err[0] = '\0';
        res->exit_code = -1;

        if (pipe(outfd) < 0)
                return -errno;
        if (pipe(errfd) < 0) {
                close(outfd[0]);
                close(outfd[1]);
                return -errno;
        }

        pid = fork();
        if (pid < 0) {
                close(outfd[0]);
                close(outfd[1]);
                close(errfd[0]);
                close(errfd[1]);
                return -errno;
        }

        if (pid == 0) {
                close(outfd[0]);
                close(errfd[0]);
                dup2(outfd[1], STDOUT_FILENO);
                dup2(errfd[1], STDERR_FILENO);
                close(outfd[1]);
                close(errfd[1]);
                execv(path, args);
                _exit(127);
        }

        close(outfd[1]);
        close(errfd[1]);
        while (out_open || err_open) {
                struct pollfd pfd[2] = {
                        { .fd = out_open ? outfd[0] : -1, .events = POLLIN },
                        { .fd = err_open ? errfd[0] : -1, .events = POLLIN },
                };
                char buf[1024];
                ssize_t r;

                if (poll(pfd, 2, -1) < 0 && errno != EINTR)
                        break;

                if (out_open && pfd[0].revents) {
                        r = read(outfd[0], buf, sizeof(buf));
                        if (r <= 0)
                                out_open = false;
                        else if (out_total + (size_t) r < sizeof(res->out) - 1) {
                                memcpy(res->out + out_total, buf, (size_t) r);
                                out_total += (size_t) r;
                        }
                }
                if (err_open && pfd[1].revents) {
                        r = read(errfd[0], buf, sizeof(buf));
                        if (r <= 0)
                                err_open = false;
                        else if (err_total + (size_t) r < sizeof(res->err) - 1) {
                                memcpy(res->err + err_total, buf, (size_t) r);
                                err_total += (size_t) r;
                        }
                }
        }
        res->out[out_total] = '\0';
        res->err[err_total] = '\0';
        close(outfd[0]);
        close(errfd[0]);
        if (err_total > 0)
                fputs(res->err, stderr);

        if (waitpid(pid, &status, 0) < 0)
                return -errno;

        res->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        return 0;
}

/* Variadic-ish convenience: build argv from a NULL-terminated ... list. */
#define RUN_PICOCTL(res, ...)                                                                         \
        do {                                                                                          \
                char picoctl_path[PATH_MAX];                                                          \
                char *args[] = { picoctl_path, __VA_ARGS__, NULL };                                   \
                ASSERT_EQ_INT(sibling_binary_path("picoctl", picoctl_path, sizeof(picoctl_path)), 0); \
                ASSERT_EQ_INT(run_binary(picoctl_path, args, (res)), 0);                              \
        } while (0)

static bool has_systemctl(void) {
        return access("/usr/bin/systemctl", X_OK) == 0 || access("/bin/systemctl", X_OK) == 0;
}

static void run_systemctl(char * const rest_args[], int expect_ok) {
        char *args[16];
        size_t i, n = 0;
        struct run_result res;
        const char *path = access("/usr/bin/systemctl", X_OK) == 0 ? "/usr/bin/systemctl" : "/bin/systemctl";

        args[n++] = (char *) path;
        for (i = 0; rest_args[i] && n < 15; i++)
                args[n++] = rest_args[i];
        args[n] = NULL;

        ASSERT_EQ_INT(run_binary(path, args, &res), 0);
        if (expect_ok)
                ASSERT_EQ_INT(res.exit_code, 0);
}

/* --- symlink-tree dump, for the oracle comparison --- */

struct link_entry {
        char relpath[600]; /* "<target>.wants/<unit>" */
        char target[512];  /* readlink() result */
};

static int link_entry_cmp(const void *a, const void *b) {
        const struct link_entry *la = a;
        const struct link_entry *lb = b;

        return strcmp(la->relpath, lb->relpath);
}

/* Walk <root>/etc/systemd/system's .wants/.requires directories, recording
 * (relative-path, symlink-target) pairs. Two levels deep is exactly the
 * layout unit-enable.c reads and picoctl/systemctl --root write -- no
 * deeper recursion is needed or correct here. */
static int dump_symlink_tree(const char *root, struct link_entry *entries, int max_entries) {
        char base[PATH_MAX];
        DIR *d;
        struct dirent *de;
        int n = 0;

        snprintf(base, sizeof(base), "%s%s", root, PICO_UNIT_DIR);

        d = opendir(base);
        if (!d)
                return 0;

        while ((de = readdir(d))) {
                char subpath[PATH_MAX + 512];
                struct stat st;
                DIR *d2;
                struct dirent *de2;

                if (de->d_name[0] == '.')
                        continue;

                snprintf(subpath, sizeof(subpath), "%s/%s", base, de->d_name);
                if (lstat(subpath, &st) < 0 || !S_ISDIR(st.st_mode))
                        continue;

                d2 = opendir(subpath);
                if (!d2)
                        continue;

                while ((de2 = readdir(d2))) {
                        char linkpath[PATH_MAX + 1024];
                        char target[512];
                        ssize_t rl;
                        int ln;

                        if (de2->d_name[0] == '.')
                                continue;
                        if (n >= max_entries)
                                break;

                        ln = snprintf(linkpath, sizeof(linkpath), "%s/%s", subpath, de2->d_name);
                        if (ln < 0 || (size_t) ln >= sizeof(linkpath))
                                continue;
                        rl = readlink(linkpath, target, sizeof(target) - 1);
                        if (rl < 0)
                                continue;
                        target[rl] = '\0';

                        snprintf(entries[n].relpath, sizeof(entries[n].relpath), "%s/%s", de->d_name, de2->d_name);
                        snprintf(entries[n].target, sizeof(entries[n].target), "%s", target);
                        n++;
                }
                closedir(d2);
        }
        closedir(d);

        qsort(entries, (size_t) n, sizeof(struct link_entry), link_entry_cmp);
        return n;
}

static void assert_same_symlink_tree(const char *root_a, const char *root_b) {
        struct link_entry a[64], b[64];
        int na, nb, i;

        na = dump_symlink_tree(root_a, a, 64);
        nb = dump_symlink_tree(root_b, b, 64);

        ASSERT_EQ_INT(na, nb);
        for (i = 0; i < na; i++) {
                ASSERT_STREQ(a[i].relpath, b[i].relpath);
                ASSERT_STREQ(a[i].target, b[i].target);
        }
}

/* --- fixture construction --- */

static const char *foo_service =
                "[Unit]\n"
                "Description=Foo\n"
                "\n"
                "[Service]\n"
                "Type=simple\n"
                "ExecStart=/bin/sleep 100\n"
                "\n"
                "[Install]\n"
                "WantedBy=multi-user.target\n";

static const char *bar_service =
                "[Unit]\n"
                "Description=Bar\n"
                "\n"
                "[Service]\n"
                "Type=simple\n"
                "ExecStart=/bin/sleep 100\n"
                "\n"
                "[Install]\n"
                "WantedBy=multi-user.target\n"
                "WantedBy=graphical.target\n";

static const char *static_service =
                "[Unit]\n"
                "Description=Static, no install section\n"
                "\n"
                "[Service]\n"
                "Type=oneshot\n"
                "ExecStart=/bin/true\n";

/*
 * test-util.h's test_mkdir() is single-level only (it exists to build
 * .wants/.requires directories one level under an existing tmpdir); the
 * fixture roots here need several levels created fresh under a tmpdir
 * (<root>/etc/systemd/system, <root>/usr/lib/systemd/system-preset, ...).
 * A local recursive mkdir keeps that need out of test-util.c.
 */
static int fixture_mkdir_p(const char *path) {
        char buf[PATH_MAX];
        size_t len = strlen(path);
        char *p;

        if (len == 0 || len >= sizeof(buf))
                return -ENAMETOOLONG;
        memcpy(buf, path, len + 1);

        for (p = buf + 1; *p; p++) {
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

/* Build <root>/etc/systemd/system(-preset) and <root>/usr/lib/systemd/system(-preset),
 * matching the exact layout PICO_UNIT_DIR/PICO_PACKAGED_UNIT_DIR/PICO_PRESET_DIR/
 * PICO_PACKAGED_PRESET_DIR (manager.h) name -- both picoctl and the oracle read
 * this same shape. */
static void make_fixture_root(const char *root) {
        char path[PATH_MAX];

        snprintf(path, sizeof(path), "%s%s", root, PICO_UNIT_DIR);
        ASSERT_EQ_INT(fixture_mkdir_p(path), 0);
        snprintf(path, sizeof(path), "%s%s", root, PICO_PACKAGED_UNIT_DIR);
        ASSERT_EQ_INT(fixture_mkdir_p(path), 0);
        snprintf(path, sizeof(path), "%s%s", root, PICO_PRESET_DIR);
        ASSERT_EQ_INT(fixture_mkdir_p(path), 0);
        snprintf(path, sizeof(path), "%s%s", root, PICO_PACKAGED_PRESET_DIR);
        ASSERT_EQ_INT(fixture_mkdir_p(path), 0);

        snprintf(path, sizeof(path), "%s%s", root, PICO_PACKAGED_UNIT_DIR);
        ASSERT_EQ_INT(test_write_file(path, "foo.service", foo_service), 0);
        ASSERT_EQ_INT(test_write_file(path, "bar.service", bar_service), 0);
        ASSERT_EQ_INT(test_write_file(path, "static.service", static_service), 0);
}

/* --- tests: symlink verbs, golden output against fixtures --- */

static void test_enable_disable_is_enabled(void) {
        char *root = test_tmpdir_new();
        struct run_result res;

        ASSERT_TRUE(root != NULL);
        make_fixture_root(root);

        RUN_PICOCTL(&res, "--root", root, "is-enabled", "foo.service");
        ASSERT_STREQ(res.out, "disabled\n");
        ASSERT_EQ_INT(res.exit_code, 1);

        RUN_PICOCTL(&res, "--root", root, "is-enabled", "static.service");
        ASSERT_STREQ(res.out, "static\n");
        ASSERT_EQ_INT(res.exit_code, 0);

        RUN_PICOCTL(&res, "--root", root, "is-enabled", "nonexistent.service");
        ASSERT_STREQ(res.out, "not-found\n");
        ASSERT_EQ_INT(res.exit_code, 4);

        RUN_PICOCTL(&res, "--root", root, "enable", "foo.service");
        ASSERT_EQ_INT(res.exit_code, 0);
        {
                char linkpath[PATH_MAX];
                char target[512];
                ssize_t rl;

                snprintf(linkpath,
                         sizeof(linkpath),
                         "%s%s/multi-user.target.wants/foo.service",
                         root,
                         PICO_UNIT_DIR);
                rl = readlink(linkpath, target, sizeof(target) - 1);
                ASSERT_TRUE(rl > 0);
                target[rl] = '\0';
                ASSERT_STREQ(target, "/usr/lib/systemd/system/foo.service"); /* absolute, root stripped */
        }

        RUN_PICOCTL(&res, "--root", root, "is-enabled", "foo.service");
        ASSERT_STREQ(res.out, "enabled\n");
        ASSERT_EQ_INT(res.exit_code, 0);

        /* idempotent: enabling an already-enabled unit is still success */
        RUN_PICOCTL(&res, "--root", root, "enable", "foo.service");
        ASSERT_EQ_INT(res.exit_code, 0);

        RUN_PICOCTL(&res, "--root", root, "disable", "foo.service");
        ASSERT_EQ_INT(res.exit_code, 0);

        RUN_PICOCTL(&res, "--root", root, "is-enabled", "foo.service");
        ASSERT_STREQ(res.out, "disabled\n");
        ASSERT_EQ_INT(res.exit_code, 1);

        /* multiple WantedBy=: enable creates one symlink per target */
        RUN_PICOCTL(&res, "--root", root, "enable", "bar.service");
        ASSERT_EQ_INT(res.exit_code, 0);
        {
                char p1[PATH_MAX], p2[PATH_MAX];
                struct stat st;

                snprintf(p1, sizeof(p1), "%s%s/multi-user.target.wants/bar.service", root, PICO_UNIT_DIR);
                snprintf(p2, sizeof(p2), "%s%s/graphical.target.wants/bar.service", root, PICO_UNIT_DIR);
                ASSERT_TRUE(lstat(p1, &st) == 0);
                ASSERT_TRUE(lstat(p2, &st) == 0);
        }
        RUN_PICOCTL(&res, "--root", root, "disable", "bar.service");
        ASSERT_EQ_INT(res.exit_code, 0);
        {
                char p1[PATH_MAX], p2[PATH_MAX];
                struct stat st;

                snprintf(p1, sizeof(p1), "%s%s/multi-user.target.wants/bar.service", root, PICO_UNIT_DIR);
                snprintf(p2, sizeof(p2), "%s%s/graphical.target.wants/bar.service", root, PICO_UNIT_DIR);
                ASSERT_TRUE(lstat(p1, &st) < 0);
                ASSERT_TRUE(lstat(p2, &st) < 0);
        }

        /* enabling a unit with no [Install] section is NOT a failure in
         * current upstream (verb_enable()'s own carries_install_info == 0
         * case, systemctl-enable.c): it succeeds, exit 0, and only explains
         * why on stderr (not captured by RUN_PICOCTL, by design -- see its
         * own header). */
        RUN_PICOCTL(&res, "--root", root, "enable", "static.service");
        ASSERT_EQ_INT(res.exit_code, 0);

        /* a genuinely missing unit fails, both verbs */
        RUN_PICOCTL(&res, "--root", root, "enable", "nonexistent.service");
        ASSERT_EQ_INT(res.exit_code, 1);
        RUN_PICOCTL(&res, "--root", root, "disable", "nonexistent.service");
        ASSERT_EQ_INT(res.exit_code, 1);

        test_rm_rf(root);
        free(root);
}

static void test_preset(void) {
        char *root = test_tmpdir_new();
        char presetdir[PATH_MAX];
        struct run_result res;

        ASSERT_TRUE(root != NULL);
        make_fixture_root(root);

        snprintf(presetdir, sizeof(presetdir), "%s%s", root, PICO_PRESET_DIR);
        ASSERT_EQ_INT(test_write_file(presetdir, "10-test.preset", "disable foo.service\nenable bar.service\n"),
                      0);

        RUN_PICOCTL(&res, "--root", root, "preset", "foo.service", "bar.service", "static.service");
        ASSERT_EQ_INT(res.exit_code, 0);

        RUN_PICOCTL(&res, "--root", root, "is-enabled", "foo.service");
        ASSERT_STREQ(res.out, "disabled\n"); /* preset rule: disable */

        RUN_PICOCTL(&res, "--root", root, "is-enabled", "bar.service");
        ASSERT_STREQ(res.out, "enabled\n"); /* preset rule: enable */

        /* no [Install] data: preset is a no-op, not an error */
        ASSERT_EQ_INT(res.exit_code, 0);

        test_rm_rf(root);
        free(root);
}

/* An ignore rule is a terminating no-op: the later catch-all enable must not
 * reach the unit. */
static void test_preset_ignore(void) {
        char *root = test_tmpdir_new();
        char presetdir[PATH_MAX];
        struct run_result res;

        ASSERT_TRUE(root != NULL);
        make_fixture_root(root);

        snprintf(presetdir, sizeof(presetdir), "%s%s", root, PICO_PRESET_DIR);
        ASSERT_EQ_INT(test_write_file(presetdir, "10-test.preset", "ignore foo.service\nenable *\n"), 0);

        RUN_PICOCTL(&res, "--root", root, "preset", "foo.service", "bar.service");
        ASSERT_EQ_INT(res.exit_code, 0);

        RUN_PICOCTL(&res, "--root", root, "is-enabled", "foo.service");
        ASSERT_STREQ(res.out, "disabled\n");
        RUN_PICOCTL(&res, "--root", root, "is-enabled", "bar.service");
        ASSERT_STREQ(res.out, "enabled\n");

        test_rm_rf(root);
        free(root);
}

/* No preset file at all: manager_preset_query()'s own -ENOENT-means-enable
 * default, exercised through picoctl rather than re-asserted against
 * unit-enable.c directly (that is unit-enable.c's own test's job) -- this is
 * about picoctl calling it correctly. */
static void test_preset_default_enable(void) {
        char *root = test_tmpdir_new();
        struct run_result res;

        ASSERT_TRUE(root != NULL);
        make_fixture_root(root);

        RUN_PICOCTL(&res, "--root", root, "preset", "foo.service");
        ASSERT_EQ_INT(res.exit_code, 0);

        RUN_PICOCTL(&res, "--root", root, "is-enabled", "foo.service");
        ASSERT_STREQ(res.out, "enabled\n");

        test_rm_rf(root);
        free(root);
}

/*
 * mask/unmask: a /dev/null symlink directly in PICO_UNIT_DIR, is-enabled
 * reporting "masked" rather than conflating it with "not-found", and `cat`
 * giving upstream's own "is a mask" line rather than trying to cat
 * /dev/null as a unit file.
 */
static void test_mask_unmask(void) {
        char *root = test_tmpdir_new();
        char linkpath[PATH_MAX];
        struct run_result res;

        ASSERT_TRUE(root != NULL);
        make_fixture_root(root);

        RUN_PICOCTL(&res, "--root", root, "mask", "foo.service");
        ASSERT_EQ_INT(res.exit_code, 0);

        snprintf(linkpath, sizeof(linkpath), "%s%s/foo.service", root, PICO_UNIT_DIR);
        {
                char target[32];
                ssize_t rl = readlink(linkpath, target, sizeof(target) - 1);

                ASSERT_TRUE(rl > 0);
                target[rl] = '\0';
                ASSERT_STREQ(target, "/dev/null");
        }

        RUN_PICOCTL(&res, "--root", root, "is-enabled", "foo.service");
        ASSERT_STREQ(res.out, "masked\n");
        ASSERT_EQ_INT(res.exit_code, 1);

        RUN_PICOCTL(&res, "--root", root, "cat", "foo.service");
        ASSERT_TRUE(strstr(res.out, "is a mask.") != NULL);
        ASSERT_EQ_INT(res.exit_code, 0);

        /* idempotent: masking an already-masked unit is still success */
        RUN_PICOCTL(&res, "--root", root, "mask", "foo.service");
        ASSERT_EQ_INT(res.exit_code, 0);

        RUN_PICOCTL(&res, "--root", root, "unmask", "foo.service");
        ASSERT_EQ_INT(res.exit_code, 0);
        {
                struct stat st;

                ASSERT_TRUE(lstat(linkpath, &st) < 0); /* symlink really gone */
        }

        RUN_PICOCTL(&res, "--root", root, "is-enabled", "foo.service");
        ASSERT_STREQ(res.out, "disabled\n"); /* back to its real [Install] state */

        /* unmasking an already-unmasked unit is still success */
        RUN_PICOCTL(&res, "--root", root, "unmask", "foo.service");
        ASSERT_EQ_INT(res.exit_code, 0);

        /* `cat` on an ordinary unit: upstream's exact "# /path" header */
        RUN_PICOCTL(&res, "--root", root, "cat", "foo.service");
        ASSERT_TRUE(strstr(res.out, "# ") != NULL);
        ASSERT_TRUE(strstr(res.out, "ExecStart=/bin/sleep 100") != NULL);
        ASSERT_EQ_INT(res.exit_code, 0);

        /* with drop-ins: each one after the unit file, behind its own header */
        {
                char dropdir[PATH_MAX], mark[2 * PATH_MAX];

                snprintf(dropdir, sizeof(dropdir), "%s%s/foo.service.d", root, PICO_UNIT_DIR);
                ASSERT_EQ_INT(mkdir(dropdir, 0755), 0);
                ASSERT_EQ_INT(test_write_file(dropdir, "20-b.conf", "[Service]\nEnvironment=B=2\n"), 0);
                ASSERT_EQ_INT(test_write_file(dropdir, "10-a.conf", "[Service]\nEnvironment=A=1\n"), 0);

                RUN_PICOCTL(&res, "--root", root, "cat", "foo.service");
                ASSERT_EQ_INT(res.exit_code, 0);
                snprintf(mark, sizeof(mark), "\n\n# %s/10-a.conf\n[Service]\nEnvironment=A=1\n", dropdir);
                ASSERT_TRUE(strstr(res.out, mark) != NULL);
                snprintf(mark,
                         sizeof(mark),
                         "Environment=A=1\n\n# %s/20-b.conf\n[Service]\nEnvironment=B=2\n",
                         dropdir);
                ASSERT_TRUE(strstr(res.out, mark) != NULL);
        }

        test_rm_rf(root);
        free(root);
}

/* list-unit-files: every fixture unit present, STATE reflecting mask and
 * [Install] data, and the "%d unit files listed." footer. */
static void test_list_unit_files(void) {
        char *root = test_tmpdir_new();
        struct run_result res;

        ASSERT_TRUE(root != NULL);
        make_fixture_root(root);

        RUN_PICOCTL(&res, "--root", root, "mask", "bar.service");
        ASSERT_EQ_INT(res.exit_code, 0);

        RUN_PICOCTL(&res, "--root", root, "list-unit-files");
        ASSERT_EQ_INT(res.exit_code, 0);
        ASSERT_TRUE(strstr(res.out, "UNIT FILE") != NULL); /* header */
        ASSERT_TRUE(strstr(res.out, "foo.service") != NULL);
        ASSERT_TRUE(strstr(res.out, "static.service") != NULL);
        {
                char *bar_line = strstr(res.out, "bar.service");

                ASSERT_TRUE(bar_line != NULL);
                ASSERT_TRUE(strstr(bar_line, "masked") != NULL);
        }
        ASSERT_TRUE(strstr(res.out, "unit files listed.") != NULL);

        RUN_PICOCTL(&res, "--root", root, "list-unit-files", "--no-legend");
        ASSERT_TRUE(strstr(res.out, "UNIT FILE") == NULL);
        ASSERT_TRUE(strstr(res.out, "unit files listed.") == NULL);
        ASSERT_TRUE(strstr(res.out, "foo.service") != NULL);

        test_rm_rf(root);
        free(root);
}

/* --- test: the compliance oracle, byte-identical symlink layouts --- */

static void test_oracle_symlinks_byte_identical(void) {
        char *root_picoctl, *root_systemctl;

        if (!has_systemctl()) {
                printf("test-picoctl: systemctl not found, skipping oracle comparison\n");
                exit(77);
        }

        root_picoctl = test_tmpdir_new();
        root_systemctl = test_tmpdir_new();
        ASSERT_TRUE(root_picoctl != NULL && root_systemctl != NULL);
        make_fixture_root(root_picoctl);
        make_fixture_root(root_systemctl);

        /* enable, single and multiple WantedBy= */
        {
                struct run_result res;
                char *sc_args[] = { (char *) "--root",      root_systemctl,         (char *) "enable",
                                    (char *) "foo.service", (char *) "bar.service", NULL };

                run_systemctl(sc_args, 1);
                RUN_PICOCTL(&res, "--root", root_picoctl, "enable", "foo.service", "bar.service");
                ASSERT_EQ_INT(res.exit_code, 0);
        }
        assert_same_symlink_tree(root_systemctl, root_picoctl);

        /* disable */
        {
                struct run_result res;
                char *sc_args[] = {
                        (char *) "--root", root_systemctl, (char *) "disable", (char *) "bar.service", NULL
                };

                run_systemctl(sc_args, 1);
                RUN_PICOCTL(&res, "--root", root_picoctl, "disable", "bar.service");
                ASSERT_EQ_INT(res.exit_code, 0);
        }
        assert_same_symlink_tree(root_systemctl, root_picoctl);

        /* preset, with a rule file identical on both sides */
        {
                struct run_result res;
                char presetdir[PATH_MAX];
                char *sc_args[] = { (char *) "--root",      root_systemctl,         (char *) "preset",
                                    (char *) "foo.service", (char *) "bar.service", NULL };

                snprintf(presetdir, sizeof(presetdir), "%s%s", root_systemctl, PICO_PRESET_DIR);
                ASSERT_EQ_INT(test_write_file(presetdir,
                                              "10-test.preset",
                                              "disable foo.service\nenable bar.service\n"),
                              0);
                snprintf(presetdir, sizeof(presetdir), "%s%s", root_picoctl, PICO_PRESET_DIR);
                ASSERT_EQ_INT(test_write_file(presetdir,
                                              "10-test.preset",
                                              "disable foo.service\nenable bar.service\n"),
                              0);

                run_systemctl(sc_args, 1);
                RUN_PICOCTL(&res, "--root", root_picoctl, "preset", "foo.service", "bar.service");
                ASSERT_EQ_INT(res.exit_code, 0);
        }
        assert_same_symlink_tree(root_systemctl, root_picoctl);

        printf("test-picoctl: symlink layouts byte-identical to systemctl --root (enable/disable/preset)\n");

        test_rm_rf(root_picoctl);
        test_rm_rf(root_systemctl);
        free(root_picoctl);
        free(root_systemctl);
}

/* --- tests: read verbs, against a real fixture boot --- */

static void stop_the_loop(void *userdata, usec_t now) {
        Manager *m = userdata;

        (void) now;
        m->objective = MANAGER_EXIT;
}

/*
 * Real cgroup v2 control files only exist under an actual cgroupfs mount --
 * a plain mkdir() under a test tmpdir does not give cgroup_v2_new() anything
 * real to open -- so this cannot be relocated under --root the way /etc and
 * /run are. A pid-tagged real path is still needed to avoid colliding with
 * test-manager-state.c's own real-boot fixtures when `meson test` runs both
 * binaries concurrently.
 *
 * Consequence: picoctl's --root in this test cannot reach the real cgroup
 * path (it only prefixes /etc and /run), so print_cgroup_procs()'s
 * cgroup.procs read is exercised by inspection here, not by an assertion on
 * picoctl's "CGroup:" status output -- a known, narrow gap, not a silent one.
 */
static void use_private_cgroup_root(Manager *m, char *out, size_t out_size) {
        int n = snprintf(out, out_size, "/sys/fs/cgroup/pico-picoctl-test-%lld", (long long) getpid());

        ASSERT_TRUE(n > 0 && (size_t) n < out_size);
        if (mkdir(out, 0755) < 0)
                ASSERT_TRUE(errno == EEXIST);
        ASSERT_EQ_INT(manager_set_cgroup_root(m, out), 0);
}

static void free_private_cgroup_root(const char *root) {
        char slice[PATH_MAX];
        int n;

        /* Checked rather than ignored: under optimisation gcc can prove `root`
         * may itself approach PATH_MAX, so appending can truncate -- and a
         * truncated path here would rmdir() some other directory, which is far
         * worse than leaving a test fixture behind. */
        n = snprintf(slice, sizeof(slice), "%s/system.slice", root);
        if (n > 0 && (size_t) n < sizeof(slice))
                rmdir(slice);

        rmdir(root);
}

static void test_read_verbs_against_real_boot(void) {
        char *unitdir, *root;
        char rtdir[PATH_MAX];
        char cgroup_root[PATH_MAX];
        Manager *m = NULL;
        struct run_result res;
        int objective;

        unitdir = test_tmpdir_new();
        root = test_tmpdir_new();
        ASSERT_TRUE(unitdir != NULL && root != NULL);

        ASSERT_EQ_INT(test_write_file(unitdir, "default.target", "[Unit]\nDescription=Default\n"), 0);
        /* PrivateTmp=/DynamicUser= are dropped at parse time and must show up
         * in `show`, which is the only place a board's operator can read the
         * degradation record from. User= is honoured and must not. */
        ASSERT_EQ_INT(test_write_file(unitdir,
                                      "console.service",
                                      "[Unit]\nDescription=Console\n[Service]\nType=simple\n"
                                      "PrivateTmp=yes\nUser=nobody\nDynamicUser=no\n"
                                      "ExecStart=/bin/sleep 300\n[Install]\nWantedBy=default.target\n"),
                      0);

        /* runtime_dir must equal <root>PICO_RUNTIME_DIR exactly, so picoctl's
         * own --root computation finds what this boot published. */
        snprintf(rtdir, sizeof(rtdir), "%s%s", root, PICO_RUNTIME_DIR);
        ASSERT_EQ_INT(fixture_mkdir_p(rtdir), 0);

        ASSERT_EQ_INT(manager_new(&m), 0);
        {
                const char * const up[] = { unitdir, NULL };
                const char * const pd[] = { NULL };

                ASSERT_EQ_INT(manager_set_unit_path(m, up), 0);
                ASSERT_EQ_INT(manager_set_preset_path(m, pd), 0);
        }
        ASSERT_EQ_INT(manager_set_runtime_dir(m, rtdir), 0);
        use_private_cgroup_root(m, cgroup_root, sizeof(cgroup_root));
        /* a first boot: presets, not symlinks, enable these fixture units */
        manager_set_first_boot(m, true);
        ASSERT_EQ_INT(manager_startup(m, NULL), 0);

        ASSERT_EQ_INT(pico_timer_add(m->timer, now_monotonic() + 3 * USEC_PER_SEC, stop_the_loop, m, NULL), 0);
        objective = manager_loop(m);
        ASSERT_EQ_INT(objective, MANAGER_EXIT);

        /* is-active: the running service */
        RUN_PICOCTL(&res, "--root", root, "is-active", "console.service");
        ASSERT_STREQ(res.out, "active\n");
        ASSERT_EQ_INT(res.exit_code, 0);

        /* is-active: a name the manager never published */
        RUN_PICOCTL(&res, "--root", root, "is-active", "never-published.service");
        ASSERT_STREQ(res.out, "inactive\n");
        ASSERT_EQ_INT(res.exit_code, 4); /* not-found, LSB 4 */

        /* is-failed: nothing failed yet */
        RUN_PICOCTL(&res, "--root", root, "is-failed", "console.service");
        ASSERT_STREQ(res.out, "active\n");
        ASSERT_EQ_INT(res.exit_code, 1); /* LSB 1: dead/not-failed */

        /* is-system-running: real boot, settled, nothing failed */
        RUN_PICOCTL(&res, "--root", root, "is-system-running");
        ASSERT_STREQ(res.out, "running\n");
        ASSERT_EQ_INT(res.exit_code, 0);

        /* show: Id= plus the real published properties */
        RUN_PICOCTL(&res, "--root", root, "show", "console.service");
        ASSERT_TRUE(strstr(res.out, "Id=console.service\n") != NULL);
        ASSERT_TRUE(strstr(res.out, "ActiveState=active\n") != NULL);
        ASSERT_TRUE(strstr(res.out, "SubState=running\n") != NULL);
        ASSERT_TRUE(strstr(res.out, "Description=Console\n") != NULL);
        ASSERT_TRUE(strstr(res.out, "Degraded-Directives=PrivateTmp DynamicUser\n") != NULL);
        {
                char expect[64];

                snprintf(expect,
                         sizeof(expect),
                         "MainPID=%d\n",
                         (int) SERVICE(manager_get_unit(m, "console.service"))->main_pid);
                ASSERT_TRUE(strstr(res.out, expect) != NULL);
        }
        ASSERT_EQ_INT(res.exit_code, 0);

        /* show: a unit honoured in full publishes the field empty */
        RUN_PICOCTL(&res, "--root", root, "show", "default.target");
        ASSERT_TRUE(strstr(res.out, "Degraded-Directives=\n") != NULL);
        ASSERT_EQ_INT(res.exit_code, 0);

        /* show: never-published unit reads as not-found, not an error */
        RUN_PICOCTL(&res, "--root", root, "show", "never-published.service");
        ASSERT_TRUE(strstr(res.out, "LoadState=not-found\n") != NULL);
        ASSERT_EQ_INT(res.exit_code, 0);

        /* status: human-readable, real content, exit reflects ActiveState */
        RUN_PICOCTL(&res, "--root", root, "status", "console.service");
        ASSERT_TRUE(strstr(res.out, "console.service - Console\n") != NULL);
        ASSERT_TRUE(strstr(res.out, "Active: active (running)") != NULL);
        ASSERT_TRUE(strstr(res.out, "Main PID:") != NULL);
        ASSERT_EQ_INT(res.exit_code, 0);

        RUN_PICOCTL(&res, "--root", root, "status", "never-published.service");
        ASSERT_EQ_INT(res.exit_code, 4);

        /* list-units: both real units present, sorted */
        RUN_PICOCTL(&res, "--root", root, "list-units");
        {
                char *console_pos = strstr(res.out, "console.service");
                char *target_pos = strstr(res.out, "default.target");

                ASSERT_TRUE(console_pos != NULL && target_pos != NULL);
                ASSERT_TRUE(console_pos < target_pos); /* alphabetical: "console" before "default" */
        }
        ASSERT_EQ_INT(res.exit_code, 0);

        /* --- kill the service, prove FAILED shows up through picoctl too ---
         * Real signalfd reap, the same pattern test-manager-state.c and
         * test-service.c already use: not a mocked transition. */
        {
                Service *console = SERVICE(manager_get_unit(m, "console.service"));
                pid_t main_pid = console->main_pid;
                struct pollfd pfd = { .fd = pico_signal_fd(m->signal), .events = POLLIN };
                bool reaped = false;
                int tries;

                ASSERT_TRUE(main_pid > 0);
                ASSERT_TRUE(kill(main_pid, SIGKILL) == 0);

                for (tries = 0; tries < 50 && !reaped; tries++) {
                        int r = poll(&pfd, 1, 100);

                        if (r <= 0)
                                continue;

                        for (;;) {
                                int signo;
                                int rr = pico_signal_read(m->signal, &signo);

                                if (rr == -EAGAIN)
                                        break;
                                ASSERT_TRUE(rr >= 0);
                                if (signo != SIGCHLD)
                                        continue;

                                for (;;) {
                                        siginfo_t info;

                                        memset(&info, 0, sizeof(info));
                                        if (waitid(P_ALL, 0, &info, WEXITED | WNOHANG) < 0 || info.si_pid == 0)
                                                break;
                                        if (info.si_pid != main_pid)
                                                continue;

                                        service_sigchld_event(
                                                        console, info.si_pid, info.si_code, info.si_status);
                                        reaped = true;
                                }
                        }
                }
                ASSERT_TRUE(reaped);
                ASSERT_EQ_INT(console->state, SERVICE_FAILED);
        }

        RUN_PICOCTL(&res, "--root", root, "is-failed", "console.service");
        ASSERT_STREQ(res.out, "failed\n");
        ASSERT_EQ_INT(res.exit_code, 0);

        /* is-system-running: a real failed unit now on the books */
        RUN_PICOCTL(&res, "--root", root, "is-system-running");
        ASSERT_STREQ(res.out, "degraded\n");
        ASSERT_EQ_INT(res.exit_code, 1);

        RUN_PICOCTL(&res, "--root", root, "status", "console.service");
        ASSERT_TRUE(strstr(res.out, "Active: failed (failed)") != NULL);
        ASSERT_TRUE(strstr(res.out, "Result: signal") != NULL);
        /* exit code/status is a parenthetical on Main PID: itself upstream,
         * never a standalone "Main Exit:" field (systemctl-show.c). */
        ASSERT_TRUE(strstr(res.out, "(code=killed, status=9)") != NULL);
        ASSERT_EQ_INT(res.exit_code, 3); /* LSB 3: not running */

        manager_free(m);
        free_private_cgroup_root(cgroup_root);
        test_rm_rf(unitdir);
        test_rm_rf(root);
        free(unitdir);
        free(root);
}

/*
 * --- status's log tail ---
 *
 * This test program links pico-init-core only, not logd-core; the `picoctl`
 * binary under test links logd-core and is what exercises logd_ring_read_
 * filtered(). So the fixture ring file below is hand-written to match
 * logd-write.c's on-disk encoding byte for byte (plain "NAME=value\n", or
 * the binary-safe "NAME\n<8-byte-LE-len><data>\n" form) rather than built
 * via logd_writer_append(). "/run/logd" below
 * is LOGD_RUNTIME_DIR (src/logd/logd.h), inlined for the same reason.
 */
static void write_plain_field(FILE *f, const char *name, const char *value) {
        fprintf(f, "%s=%s\n", name, value);
}

static void write_binary_field(FILE *f, const char *name, const void *value, size_t len) {
        unsigned char len_le[8];
        size_t i;

        fputs(name, f);
        fputc('\n', f);
        for (i = 0; i < sizeof(len_le); i++)
                len_le[i] = (unsigned char) ((len >> (8 * i)) & 0xff);
        fwrite(len_le, 1, sizeof(len_le), f);
        fwrite(value, 1, len, f);
        fputc('\n', f);
}

/* One entry: the three fields logd_writer_append() always emits, plus a
 * caller-chosen unit/ident/pid/message, plus the blank-line separator. */
static void write_fixture_log_entry(FILE *f, const char *unit, const char *message, bool message_binary) {
        write_plain_field(f, "__REALTIME_TIMESTAMP", "1700000000000000");
        write_plain_field(f, "__MONOTONIC_TIMESTAMP", "1000000");
        write_plain_field(f, "_BOOT_ID", "0123456789abcdef0123456789abcdef");
        write_plain_field(f, "SYSLOG_IDENTIFIER", "demo");
        write_plain_field(f, "_PID", "4242");
        write_plain_field(f, "_SYSTEMD_UNIT", unit);
        if (message_binary)
                write_binary_field(f, "MESSAGE", message, strlen(message));
        else
                write_plain_field(f, "MESSAGE", message);
        fputc('\n', f);
}

static void test_status_log_tail(void) {
        char *root;
        char rtdir[PATH_MAX], unitsdir[PATH_MAX + 16], logdir[PATH_MAX + 16], logpath[PATH_MAX + 32];
        FILE *f;
        struct run_result res;

        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);

        /* A published unit-state file: cmd_status() skips the log tail
         * entirely for a unit it never found (see picoctl.c), so this has
         * to exist for the tail to be exercised at all. */
        snprintf(rtdir, sizeof(rtdir), "%s%s", root, PICO_RUNTIME_DIR);
        snprintf(unitsdir, sizeof(unitsdir), "%s/units", rtdir);
        ASSERT_EQ_INT(fixture_mkdir_p(unitsdir), 0);
        ASSERT_EQ_INT(test_write_file(unitsdir,
                                      "demo.service",
                                      "ActiveState=active\nSubState=running\n"
                                      "LoadState=loaded\nDescription=Demo\n"),
                      0);

        snprintf(logdir, sizeof(logdir), "%s/run/logd", root);
        ASSERT_EQ_INT(fixture_mkdir_p(logdir), 0);
        snprintf(logpath, sizeof(logpath), "%s/active.export", logdir);
        f = fopen(logpath, "wb");
        ASSERT_TRUE(f != NULL);
        write_fixture_log_entry(f, "other.service", "not this unit's line", false);
        write_fixture_log_entry(f, "demo.service", "hello from demo", false);
        write_fixture_log_entry(f, "demo.service", "bad\x01byte", true);
        fclose(f);

        RUN_PICOCTL(&res, "--root", root, "status", "demo.service");
        ASSERT_EQ_INT(res.exit_code, 0);
        /* filtered to _SYSTEMD_UNIT == demo.service: the other unit's line
         * must never appear */
        ASSERT_TRUE(strstr(res.out, "not this unit's line") == NULL);
        ASSERT_TRUE(strstr(res.out, "demo[4242]: hello from demo") != NULL);
        /* binary-safe MESSAGE prints the blob-data placeholder (real's
         * FORMAT_BYTES() wording, byte count included), never the raw
         * control byte */
        /* "bad\x01byte"'s \x escape is greedy and swallows the following
         * hex digit 'b' too (\x01b = 0x1b, ESC), so the literal is 7 bytes
         * ('b','a','d',ESC,'y','t','e'), not the 8 its spelling suggests. */
        ASSERT_TRUE(strstr(res.out, "demo[4242]: [7 bytes blob data]") != NULL);
        ASSERT_TRUE(strstr(res.out, "bad\x01byte") == NULL);

        /* an image with no logd at all -- no /run/logd whatsoever -- must
         * degrade to no log lines, not an error */
        {
                char root2dir[PATH_MAX], units2dir[PATH_MAX + 16];
                char *root2 = test_tmpdir_new();

                ASSERT_TRUE(root2 != NULL);
                snprintf(root2dir, sizeof(root2dir), "%s%s", root2, PICO_RUNTIME_DIR);
                snprintf(units2dir, sizeof(units2dir), "%s/units", root2dir);
                ASSERT_EQ_INT(fixture_mkdir_p(units2dir), 0);
                ASSERT_EQ_INT(test_write_file(units2dir,
                                              "demo.service",
                                              "ActiveState=active\nSubState=running\n"
                                              "LoadState=loaded\nDescription=Demo\n"),
                              0);

                RUN_PICOCTL(&res, "--root", root2, "status", "demo.service");
                ASSERT_EQ_INT(res.exit_code, 0);
                ASSERT_TRUE(strstr(res.out, "Demo") != NULL); /* the status block itself still works */

                test_rm_rf(root2);
                free(root2);
        }

        test_rm_rf(root);
        free(root);
}

/*
 * is-system-running and the fstab pass's record: a skipped or failed fstab line
 * degrades the system even with every unit healthy; noauto and mounted lines,
 * and no record at all, do not.
 */
static void test_is_system_running_fstab(void) {
        char *root;
        char rtdir[PATH_MAX], unitsdir[PATH_MAX + 16];
        struct run_result res;

        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);

        snprintf(rtdir, sizeof(rtdir), "%s%s", root, PICO_RUNTIME_DIR);
        snprintf(unitsdir, sizeof(unitsdir), "%s/units", rtdir);
        ASSERT_EQ_INT(fixture_mkdir_p(unitsdir), 0);
        ASSERT_EQ_INT(test_write_file(rtdir, "manager", "Objective=running\nNJobs=0\n"), 0);
        ASSERT_EQ_INT(test_write_file(unitsdir, "demo.service", "ActiveState=active\nSubState=running\n"), 0);

        RUN_PICOCTL(&res, "--root", root, "is-system-running");
        ASSERT_STREQ(res.out, "running\n");
        ASSERT_EQ_INT(res.exit_code, 0);

        ASSERT_EQ_INT(test_write_file(rtdir,
                                      "fstab",
                                      "/ present read-write, not checked\n"
                                      "/var/volatile mounted tmpfs defaults\n"
                                      "/media/card noauto -\n"),
                      0);
        RUN_PICOCTL(&res, "--root", root, "is-system-running");
        ASSERT_STREQ(res.out, "running\n");
        ASSERT_EQ_INT(res.exit_code, 0);

        ASSERT_EQ_INT(test_write_file(rtdir,
                                      "fstab",
                                      "/var/volatile mounted tmpfs defaults\n"
                                      "/mnt/nfs skipped network filesystem: nothing orders it after the network\n"),
                      0);
        RUN_PICOCTL(&res, "--root", root, "is-system-running");
        ASSERT_STREQ(res.out, "degraded\n");
        ASSERT_EQ_INT(res.exit_code, 1);

        /* Jobs still running outrank it, exactly as they outrank a failed
         * unit. */
        ASSERT_EQ_INT(test_write_file(rtdir, "manager", "Objective=running\nNJobs=2\n"), 0);
        RUN_PICOCTL(&res, "--root", root, "is-system-running");
        ASSERT_STREQ(res.out, "starting\n");

        test_rm_rf(root);
        free(root);
}

/*
 * main()'s getopt_long() pass (picoctl.c picoctl_parse_options()): an
 * option is global and may sit before, between or after the verb and unit
 * arguments, repeated options keep the last value, "--" ends option
 * parsing, both "--opt=value" and "--opt value" work, and an unrecognised
 * option is a hard failure -- the exact bug a live 'systemctl --no-block
 * restart X' and 'systemctl is-active X --no-block' use.
 */
static void test_cli_option_parsing(void) {
        char *root;
        char rtdir[PATH_MAX], unitsdir[PATH_MAX + 16];
        char root_opt[PATH_MAX + 8];
        struct run_result res;

        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);

        snprintf(rtdir, sizeof(rtdir), "%s%s", root, PICO_RUNTIME_DIR);
        snprintf(unitsdir, sizeof(unitsdir), "%s/units", rtdir);
        ASSERT_EQ_INT(fixture_mkdir_p(unitsdir), 0);
        ASSERT_EQ_INT(test_write_file(unitsdir,
                                      "demo.service",
                                      "ActiveState=active\nSubState=running\n"
                                      "LoadState=loaded\nDescription=Demo\n"),
                      0);

        /* a global option before the verb */
        RUN_PICOCTL(&res, "--root", root, "--no-legend", "list-units");
        ASSERT_EQ_INT(res.exit_code, 0);
        ASSERT_TRUE(strstr(res.out, "UNIT") == NULL);
        ASSERT_TRUE(strstr(res.out, "demo.service") != NULL);

        /* a unit verb's own "--no-block" sitting
         * AFTER the unit name must not be swallowed as a second unit --
         * exactly one ActiveState line comes out, not two. */
        RUN_PICOCTL(&res, "--root", root, "is-active", "demo.service", "--no-block");
        ASSERT_STREQ(res.out, "active\n");
        ASSERT_EQ_INT(res.exit_code, 0);
        ASSERT_TRUE(strchr(res.out, '\n') == strrchr(res.out, '\n')); /* exactly one line */

        /* an option sandwiched BETWEEN two unit arguments: still consumed
         * as the global option, never counted as a third unit name */
        RUN_PICOCTL(&res, "--root", root, "is-active", "demo.service", "--no-block", "demo.service");
        ASSERT_STREQ(res.out, "active\nactive\n");
        ASSERT_EQ_INT(res.exit_code, 0);

        /* an option BEFORE the verb (the shape
         * stock systemd.bbclass postinsts use, e.g. "--no-block
         * restart X") must not be looked up as if it were the verb itself. */
        RUN_PICOCTL(&res, "--root", root, "--no-block", "is-active", "demo.service");
        ASSERT_STREQ(res.out, "active\n");
        ASSERT_EQ_INT(res.exit_code, 0);

        /* "--root=DIR" (attached), not just the two-token "--root DIR" form
         * every other test in this file already exercises */
        snprintf(root_opt, sizeof(root_opt), "--root=%s", root);
        RUN_PICOCTL(&res, root_opt, "is-active", "demo.service");
        ASSERT_STREQ(res.out, "active\n");
        ASSERT_EQ_INT(res.exit_code, 0);

        /* repeated --root: getopt_long keeps the last value, same as real
         * systemctl would */
        RUN_PICOCTL(&res, "--root", "/nonexistent-does-not-exist", "--root", root, "list-units");
        ASSERT_EQ_INT(res.exit_code, 0);
        ASSERT_TRUE(strstr(res.out, "demo.service") != NULL);

        /* "--" ends option parsing: a *literal* unit named "--no-block"
         * (never mangled -- mangle_unit_arg() already refuses anything
         * starting with '-') is looked up and, being unpublished, reads as
         * not-found/inactive -- it must NOT have been consumed as the
         * global --no-block option, which would instead leave is-active
         * with zero unit arguments and fail outright. */
        RUN_PICOCTL(&res, "--root", root, "is-active", "--", "--no-block");
        ASSERT_STREQ(res.out, "inactive\n");
        ASSERT_EQ_INT(res.exit_code, 4);

        /* a bare "--no-block" with no verb at all: still defaults to
         * list-units, same as no arguments whatsoever */
        RUN_PICOCTL(&res, "--root", root, "--no-block");
        ASSERT_EQ_INT(res.exit_code, 0);
        ASSERT_TRUE(strstr(res.out, "demo.service") != NULL);

        /* an unrecognised option is a hard failure, getopt_long's own
         * message (stderr, not captured here -- see run_binary()'s own
         * comment) plus exit 1, never a silent ignore */
        RUN_PICOCTL(&res, "--this-option-does-not-exist", "list-units");
        ASSERT_EQ_INT(res.exit_code, 1);

        test_rm_rf(root);
        free(root);
}

/*
 * show's UnitFileState= must come from the same live, on-disk enablement
 * check is-enabled uses, not from the manager's published state file --
 * that file only ever reflects enablement as of this unit's *load* time,
 * and `picoctl disable` never rewrites it (manager-notify.c publishes it
 * once, at unit_notify() time, not on every enablement change). The
 * fixture's units/foo.service file is deliberately never rewritten below,
 * so this fails if "show" ever goes back to trusting it.
 */
static void test_show_unit_file_state_live(void) {
        char *root;
        char rtdir[PATH_MAX], unitsdir[PATH_MAX + 16];
        struct run_result res;

        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);
        make_fixture_root(root);

        snprintf(rtdir, sizeof(rtdir), "%s%s", root, PICO_RUNTIME_DIR);
        snprintf(unitsdir, sizeof(unitsdir), "%s/units", rtdir);
        ASSERT_EQ_INT(fixture_mkdir_p(unitsdir), 0);
        ASSERT_EQ_INT(test_write_file(unitsdir,
                                      "foo.service",
                                      "ActiveState=active\nSubState=running\n"
                                      "LoadState=loaded\nDescription=Foo\n"
                                      "UnitFileState=enabled\n"),
                      0);

        RUN_PICOCTL(&res, "--root", root, "enable", "foo.service");
        ASSERT_EQ_INT(res.exit_code, 0);

        RUN_PICOCTL(&res, "--root", root, "show", "foo.service");
        ASSERT_EQ_INT(res.exit_code, 0);
        ASSERT_TRUE(strstr(res.out, "UnitFileState=enabled\n") != NULL);

        /* disable touches only the .wants symlink -- the fixture manager's
         * own units/foo.service file above is never rewritten, simulating
         * a disable with no daemon restart in between */
        RUN_PICOCTL(&res, "--root", root, "disable", "foo.service");
        ASSERT_EQ_INT(res.exit_code, 0);

        RUN_PICOCTL(&res, "--root", root, "show", "foo.service");
        ASSERT_EQ_INT(res.exit_code, 0);
        ASSERT_TRUE(strstr(res.out, "UnitFileState=disabled\n") != NULL);
        ASSERT_TRUE(strstr(res.out, "UnitFileState=enabled\n") == NULL);
        /* every other field still comes verbatim from the stale file */
        ASSERT_TRUE(strstr(res.out, "ActiveState=active\n") != NULL);

        test_rm_rf(root);
        free(root);
}

/*
 * `systemctl status` with no unit name shows the manager's own overview
 * (systemctl-show.c show_system_status()), not an error.
 * One active and one failed unit, exactly as the fixture name says, so
 * State/Units/Jobs/Failed all have a real, assertable answer.
 */
static void test_status_no_argument_system_overview(void) {
        char *root;
        char rtdir[PATH_MAX], unitsdir[PATH_MAX + 16];
        struct run_result res;

        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);

        snprintf(rtdir, sizeof(rtdir), "%s%s", root, PICO_RUNTIME_DIR);
        snprintf(unitsdir, sizeof(unitsdir), "%s/units", rtdir);
        ASSERT_EQ_INT(fixture_mkdir_p(unitsdir), 0);
        ASSERT_EQ_INT(test_write_file(rtdir, "manager", "Objective=running\nNUnits=2\nNJobs=0\n"), 0);
        ASSERT_EQ_INT(test_write_file(unitsdir, "demo.service", "ActiveState=active\nSubState=running\n"), 0);
        ASSERT_EQ_INT(test_write_file(unitsdir,
                                      "broken.service",
                                      "ActiveState=failed\nSubState=failed\nResult=exit-code\n"),
                      0);

        RUN_PICOCTL(&res, "--root", root, "status");
        ASSERT_EQ_INT(res.exit_code, 0); /* never an error, same as upstream */

        ASSERT_TRUE(strstr(res.out, "State: degraded\n") != NULL); /* the failed unit above */
        ASSERT_TRUE(strstr(res.out, "Units: 2 loaded (incl. loaded aliases)\n") != NULL);
        ASSERT_TRUE(strstr(res.out, "Jobs: 0 queued\n") != NULL);
        ASSERT_TRUE(strstr(res.out, "Failed: 1 units\n") != NULL);

        test_rm_rf(root);
        free(root);
}

/* --- test: colouring, forced on via SYSTEMD_COLORS=true ---
 *
 * The literal byte sequences below are deliberately re-typed from pico-
 * color.c's own PICO_ANSI_* #defines rather than #include-ing that header:
 * this test is the thing that would catch an accidental change to those
 * literals breaking real systemctl-compatibility, so it must not share the
 * one definition it is checking.
 *
 * RUN_PICOCTL's pipe (run_binary()) makes picoctl's own stdout a non-tty,
 * which is normally "colours off" -- these tests force colours on the one
 * way that overrides tty detection entirely (pico_colors_enabled()'s own
 * $SYSTEMD_COLORS=true branch), the same override real systemctl honours.
 */
#define TEST_ANSI_NORMAL "\x1B[0m"
#define TEST_ANSI_HIGHLIGHT_RED "\x1B[0;1;31m"
#define TEST_ANSI_HIGHLIGHT_GREEN "\x1B[0;1;32m"

/*
 * status prints the applied drop-ins as systemctl's Drop-In: block between
 * Loaded: and Active:, files grouped by directory; a unit without any prints
 * no such block. The same text as systemctl-show.c print_status_info().
 */
static void test_status_dropins(void) {
        static const char * const GLYPH = "\xe2\x94\x94\xe2\x94\x80";
        char *root;
        char rtdir[PATH_MAX], unitsdir[PATH_MAX + 16], want[1024];
        struct run_result res;

        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);

        snprintf(rtdir, sizeof(rtdir), "%s%s", root, PICO_RUNTIME_DIR);
        snprintf(unitsdir, sizeof(unitsdir), "%s/units", rtdir);
        ASSERT_EQ_INT(fixture_mkdir_p(unitsdir), 0);

        ASSERT_EQ_INT(test_write_file(unitsdir,
                                      "a.service",
                                      "ActiveState=active\nSubState=running\nLoadState=loaded\n"
                                      "FragmentPath=/usr/lib/systemd/system/a.service\n"
                                      "DropInPaths=/etc/systemd/system/a.service.d/10-a.conf "
                                      "/etc/systemd/system/a.service.d/20-b.conf "
                                      "/usr/lib/systemd/system/service.d/30-c.conf "
                                      "/etc/systemd/system/a.service.d/40-d.conf\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(unitsdir,
                                      "b.service",
                                      "ActiveState=active\nSubState=running\nLoadState=loaded\n"
                                      "DropInPaths=\n"),
                      0);

        snprintf(want,
                 sizeof(want),
                 "    Drop-In: /etc/systemd/system/a.service.d\n"
                 "             %s10-a.conf, 20-b.conf\n"
                 "             /usr/lib/systemd/system/service.d\n"
                 "             %s30-c.conf\n"
                 "             /etc/systemd/system/a.service.d\n"
                 "             %s40-d.conf\n"
                 "     Active: active (running)\n",
                 GLYPH,
                 GLYPH,
                 GLYPH);

        RUN_PICOCTL(&res, "--root", root, "status", "a.service");
        ASSERT_EQ_INT(res.exit_code, 0);
        ASSERT_TRUE(strstr(res.out, "     Loaded: loaded (/usr/lib/systemd/system/a.service; n/a)\n") != NULL);
        ASSERT_TRUE(strstr(res.out, want) != NULL);

        RUN_PICOCTL(&res, "--root", root, "status", "b.service");
        ASSERT_EQ_INT(res.exit_code, 0);
        ASSERT_TRUE(strstr(res.out, "Drop-In:") == NULL);

        RUN_PICOCTL(&res, "--root", root, "show", "-p", "DropInPaths", "a.service");
        ASSERT_TRUE(strstr(res.out,
                           "DropInPaths=/etc/systemd/system/a.service.d/10-a.conf "
                           "/etc/systemd/system/a.service.d/20-b.conf ") != NULL);

        test_rm_rf(root);
        free(root);
}

/*
 * status <unit>: active (green Active: line), failed (red Active: line,
 * with the Result parenthetical left outside -- hence plain -- the colour),
 * and inactive (format_active_state()'s own "else" case: no colour for
 * inactive, not even with colours forced on -- the negative half of this
 * test matters as much as the positive two).
 */
static void test_status_colors(void) {
        char *root;
        char rtdir[PATH_MAX], unitsdir[PATH_MAX + 16];
        struct run_result res;

        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);

        snprintf(rtdir, sizeof(rtdir), "%s%s", root, PICO_RUNTIME_DIR);
        snprintf(unitsdir, sizeof(unitsdir), "%s/units", rtdir);
        ASSERT_EQ_INT(fixture_mkdir_p(unitsdir), 0);

        ASSERT_EQ_INT(test_write_file(unitsdir,
                                      "active.service",
                                      "ActiveState=active\nSubState=running\nLoadState=loaded\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(unitsdir,
                                      "failed.service",
                                      "ActiveState=failed\nSubState=failed\nResult=exit-code\nLoadState=loaded\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(unitsdir,
                                      "inactive.service",
                                      "ActiveState=inactive\nSubState=dead\nLoadState=loaded\n"),
                      0);

        setenv("SYSTEMD_COLORS", "true", 1);

        RUN_PICOCTL(&res, "--root", root, "status", "active.service");
        ASSERT_EQ_INT(res.exit_code, 0);
        ASSERT_TRUE(strstr(res.out,
                           "     Active: " TEST_ANSI_HIGHLIGHT_GREEN "active (running)" TEST_ANSI_NORMAL
                           "\n") != NULL);

        RUN_PICOCTL(&res, "--root", root, "status", "failed.service");
        ASSERT_EQ_INT(res.exit_code, 3); /* LSB "not running", same as unforced */
        ASSERT_TRUE(strstr(res.out,
                           "     Active: " TEST_ANSI_HIGHLIGHT_RED "failed (failed)" TEST_ANSI_NORMAL
                           " (Result: exit-code)\n") != NULL);

        RUN_PICOCTL(&res, "--root", root, "status", "inactive.service");
        ASSERT_EQ_INT(res.exit_code, 3);
        ASSERT_TRUE(strstr(res.out, "     Active: inactive (dead)\n") != NULL);
        /* the negative case: forcing colours on must not invent one for a
         * state upstream's own format_active_state() leaves plain */
        ASSERT_TRUE(strstr(res.out, "\x1B[") == NULL);

        unsetenv("SYSTEMD_COLORS");

        test_rm_rf(root);
        free(root);
}

/*
 * list-units: one row, failed -- on_active (red) wraps both the UNIT and
 * ACTIVE columns, on_sub (red too, failed's own case) wraps SUB; LOAD stays
 * plain ("loaded" is not one of list_units_row_colors()'s coloured
 * load_state values). Built with the exact field widths cmd_list_units()
 * itself prints with, so a width regression there would also fail this.
 */
static void test_list_units_colors(void) {
        char *root;
        char rtdir[PATH_MAX], unitsdir[PATH_MAX + 16];
        struct run_result res;
        char expected_row[256];

        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);

        snprintf(rtdir, sizeof(rtdir), "%s%s", root, PICO_RUNTIME_DIR);
        snprintf(unitsdir, sizeof(unitsdir), "%s/units", rtdir);
        ASSERT_EQ_INT(fixture_mkdir_p(unitsdir), 0);
        ASSERT_EQ_INT(test_write_file(unitsdir,
                                      "demo.service",
                                      "ActiveState=failed\nSubState=failed\nLoadState=loaded\nDescription=Demo\n"),
                      0);

        snprintf(expected_row,
                 sizeof(expected_row),
                 "%s%-32s%s %-8s %s%-10s%s %s%-13s%s %s\n",
                 TEST_ANSI_HIGHLIGHT_RED,
                 "demo.service",
                 TEST_ANSI_NORMAL,
                 "loaded",
                 TEST_ANSI_HIGHLIGHT_RED,
                 "failed",
                 TEST_ANSI_NORMAL,
                 TEST_ANSI_HIGHLIGHT_RED,
                 "failed",
                 TEST_ANSI_NORMAL,
                 "Demo");

        setenv("SYSTEMD_COLORS", "true", 1);

        RUN_PICOCTL(&res, "--root", root, "list-units");
        ASSERT_EQ_INT(res.exit_code, 0);
        ASSERT_TRUE(strstr(res.out, expected_row) != NULL);

        unsetenv("SYSTEMD_COLORS");

        test_rm_rf(root);
        free(root);
}

/* --- systemctl 262 option and verb set --- */

static void fixture_unit_state(const char *root, const char *name, const char *content) {
        char unitsdir[PATH_MAX + 16];

        snprintf(unitsdir, sizeof(unitsdir), "%s%s/units", root, PICO_RUNTIME_DIR);
        ASSERT_EQ_INT(fixture_mkdir_p(unitsdir), 0);
        ASSERT_EQ_INT(test_write_file(unitsdir, name, content), 0);
}

static void fixture_manager_state(const char *root, const char *content) {
        char rtdir[PATH_MAX];

        snprintf(rtdir, sizeof(rtdir), "%s%s", root, PICO_RUNTIME_DIR);
        ASSERT_EQ_INT(fixture_mkdir_p(rtdir), 0);
        ASSERT_EQ_INT(test_write_file(rtdir, "manager", content), 0);
}

static void test_list_units_filters_and_legend(void) {
        char *root = test_tmpdir_new();
        struct run_result res;

        ASSERT_TRUE(root != NULL);
        fixture_unit_state(
                        root,
                        "demo.service",
                        "ActiveState=active\nSubState=running\nLoadState=loaded\nDescription=Demo\n");
        fixture_unit_state(
                        root,
                        "idle.service",
                        "ActiveState=inactive\nSubState=dead\nLoadState=loaded\nDescription=Idle\n");
        fixture_unit_state(
                        root,
                        "bad.service",
                        "ActiveState=failed\nSubState=failed\nLoadState=loaded\nDescription=Bad\n");
        fixture_unit_state(
                        root,
                        "busy.service",
                        "ActiveState=inactive\nSubState=dead\nLoadState=loaded\nDescription=Busy\nJob=7 start\n");

        /* inactive units stay hidden unless --all, they have a job, or --state asks */
        RUN_PICOCTL(&res, "--root", root, "list-units");
        ASSERT_EQ_INT(res.exit_code, 0);
        ASSERT_TRUE(strstr(res.out, "demo.service") != NULL);
        ASSERT_TRUE(strstr(res.out, "idle.service") == NULL);
        ASSERT_TRUE(strstr(res.out, "busy.service") != NULL);
        ASSERT_TRUE(strstr(res.out, " JOB ") != NULL);
        ASSERT_TRUE(strstr(res.out, "3 loaded units listed. ") != NULL);
        ASSERT_TRUE(strstr(res.out, "Pass --all to see loaded but inactive units, too.") != NULL);
        ASSERT_TRUE(strstr(res.out, "JOB    \xe2\x86\x92 Pending job for the unit.") != NULL);

        RUN_PICOCTL(&res, "--root", root, "list-units", "--all");
        ASSERT_TRUE(strstr(res.out, "idle.service") != NULL);
        ASSERT_TRUE(strstr(res.out, "4 loaded units listed.\n") != NULL);
        ASSERT_TRUE(strstr(res.out, "Pass --all") == NULL);

        RUN_PICOCTL(&res, "--root", root, "list-units", "--failed");
        ASSERT_TRUE(strstr(res.out, "bad.service") != NULL);
        ASSERT_TRUE(strstr(res.out, "demo.service") == NULL);
        ASSERT_TRUE(strstr(res.out, "1 loaded units listed.\n") != NULL);

        RUN_PICOCTL(&res, "--root", root, "--state=inactive", "list-units", "i*");
        ASSERT_TRUE(strstr(res.out, "idle.service") != NULL);
        ASSERT_TRUE(strstr(res.out, "busy.service") == NULL);

        /* no job pending: the JOB column goes away, as upstream hides it */
        RUN_PICOCTL(&res, "--root", root, "list-units", "demo*");
        ASSERT_TRUE(strstr(res.out, "JOB") == NULL);
        ASSERT_TRUE(strstr(res.out, "1 loaded units listed.") != NULL);

        /* -q and --legend=no drop headers and footers, --legend=yes keeps them */
        RUN_PICOCTL(&res, "--root", root, "-q", "list-units", "demo*");
        ASSERT_TRUE(strstr(res.out, "UNIT") == NULL && strstr(res.out, "listed") == NULL);
        RUN_PICOCTL(&res, "--root", root, "--legend=no", "list-units", "demo*");
        ASSERT_TRUE(strstr(res.out, "UNIT") == NULL && strstr(res.out, "listed") == NULL);
        RUN_PICOCTL(&res, "--root", root, "-q", "--legend=yes", "list-units", "demo*");
        ASSERT_TRUE(strstr(res.out, "1 loaded units listed.") != NULL);
        RUN_PICOCTL(&res, "--root", root, "--legend=maybe", "list-units");
        ASSERT_EQ_INT(res.exit_code, 1);

        /* options with nothing to act on are accepted */
        RUN_PICOCTL(&res,
                    "--root",
                    root,
                    "--no-ask-password",
                    "--no-warn",
                    "--no-pager",
                    "-l",
                    "--plain",
                    "-T",
                    "--check-inhibitors=no",
                    "list-units");
        ASSERT_EQ_INT(res.exit_code, 0);

        test_rm_rf(root);
        free(root);
}

static void test_json_output(void) {
        char *root = test_tmpdir_new();
        struct run_result res;

        ASSERT_TRUE(root != NULL);
        fixture_unit_state(
                        root,
                        "demo.service",
                        "ActiveState=active\nSubState=running\nLoadState=loaded\nDescription=A \"Demo\"\n");

        RUN_PICOCTL(&res, "--root", root, "-o", "json", "list-units");
        ASSERT_EQ_INT(res.exit_code, 0);
        ASSERT_STREQ(res.out,
                     "[{\"unit\":\"demo.service\",\"load\":\"loaded\",\"active\":\"active\",\"sub\":\"running\","
                     "\"description\":\"A \\\"Demo\\\"\"}]\n");

        RUN_PICOCTL(&res, "--root", root, "--output=json-pretty", "list-units");
        ASSERT_STREQ(res.out,
                     "[\n"
                     "\t{\n"
                     "\t\t\"unit\" : \"demo.service\",\n"
                     "\t\t\"load\" : \"loaded\",\n"
                     "\t\t\"active\" : \"active\",\n"
                     "\t\t\"sub\" : \"running\",\n"
                     "\t\t\"description\" : \"A \\\"Demo\\\"\"\n"
                     "\t}\n"
                     "]\n");

        RUN_PICOCTL(&res, "--root", root, "-o", "json-seq", "list-timers");
        ASSERT_STREQ(res.out, "\x1e[]\n");
        RUN_PICOCTL(&res, "--root", root, "-o", "json-sse", "list-timers");
        ASSERT_STREQ(res.out, "data: []\n\n");

        RUN_PICOCTL(&res, "--root", root, "-o", "help");
        ASSERT_TRUE(strstr(res.out, "json-pretty\n") != NULL);
        RUN_PICOCTL(&res, "--root", root, "-o", "bogus", "list-units");
        ASSERT_EQ_INT(res.exit_code, 1);

        /* the other modes only matter to journal entries and keep the table */
        RUN_PICOCTL(&res, "--root", root, "-o", "verbose", "list-units");
        ASSERT_TRUE(strstr(res.out, "demo.service") != NULL && res.out[0] != '[');

        test_rm_rf(root);
        free(root);
}

static void test_json_unit_files(void) {
        char *root = test_tmpdir_new();
        struct run_result res;

        ASSERT_TRUE(root != NULL);
        make_fixture_root(root);

        RUN_PICOCTL(&res, "--root", root, "-o", "json", "list-unit-files", "static*");
        ASSERT_STREQ(res.out, "[{\"unit_file\":\"static.service\",\"state\":\"static\",\"preset\":null}]\n");

        RUN_PICOCTL(&res, "--root", root, "-o", "json", "list-unit-files", "foo*");
        ASSERT_STREQ(res.out,
                     "[{\"unit_file\":\"foo.service\",\"state\":\"disabled\",\"preset\":\"enabled\"}]\n");

        RUN_PICOCTL(&res, "--root", root, "--state=static", "--no-legend", "list-unit-files");
        ASSERT_TRUE(strstr(res.out, "static.service") != NULL && strstr(res.out, "foo.service") == NULL);

        RUN_PICOCTL(&res, "--root", root, "-t", "target", "--no-legend", "list-unit-files");
        ASSERT_STREQ(res.out, "");

        test_rm_rf(root);
        free(root);
}

static void test_empty_unit_types(void) {
        char *root = test_tmpdir_new();
        struct run_result res;

        ASSERT_TRUE(root != NULL);
        fixture_manager_state(root, "DefaultTarget=default.target\nNUnits=0\nNJobs=0\n");

        RUN_PICOCTL(&res, "--root", root, "list-timers");
        ASSERT_EQ_INT(res.exit_code, 0);
        ASSERT_TRUE(strstr(res.out, "NEXT LEFT LAST PASSED UNIT ACTIVATES\n") != NULL);
        ASSERT_TRUE(strstr(res.out, "0 timers listed.") != NULL);
        ASSERT_TRUE(strstr(res.out, "Pass --all to see loaded but inactive timers, too.") != NULL);

        RUN_PICOCTL(&res, "--root", root, "list-paths", "--no-legend");
        ASSERT_STREQ(res.out, "");
        RUN_PICOCTL(&res, "--root", root, "list-automounts");
        ASSERT_TRUE(strstr(res.out, "0 automounts listed.") != NULL);

        test_rm_rf(root);
        free(root);
}

static void test_show_properties_and_manager(void) {
        char *root = test_tmpdir_new();
        struct run_result res;

        ASSERT_TRUE(root != NULL);
        fixture_unit_state(
                        root,
                        "demo.service",
                        "ActiveState=active\nSubState=running\nLoadState=loaded\nDescription=Demo\nMainPID=42\n");
        fixture_manager_state(root, "Objective=run\nDefaultTarget=multi-user.target\nNUnits=1\nNJobs=0\n");

        RUN_PICOCTL(&res, "--root", root, "show", "-p", "ActiveState,SubState", "demo.service");
        ASSERT_STREQ(res.out, "ActiveState=active\nSubState=running\n");

        RUN_PICOCTL(&res, "--root", root, "show", "-p", "MainPID", "--property=Id", "demo.service");
        ASSERT_STREQ(res.out, "Id=demo.service\nMainPID=42\n");

        RUN_PICOCTL(&res, "--root", root, "show", "-P", "ActiveState", "demo.service");
        ASSERT_STREQ(res.out, "active\n");

        RUN_PICOCTL(&res, "--root", root, "show", "--value", "-p", "Description", "demo.service");
        ASSERT_STREQ(res.out, "Demo\n");

        /* no unit: the manager's own properties */
        RUN_PICOCTL(&res, "--root", root, "show", "-p", "DefaultTarget");
        ASSERT_STREQ(res.out, "DefaultTarget=multi-user.target\n");

        RUN_PICOCTL(&res, "--root", root, "get-default");
        ASSERT_STREQ(res.out, "multi-user.target\n");

        test_rm_rf(root);
        free(root);

        /* nothing published: show says so, get-default falls back to the built-in name */
        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);
        RUN_PICOCTL(&res, "--root", root, "show");
        ASSERT_EQ_INT(res.exit_code, 1);
        RUN_PICOCTL(&res, "--root", root, "get-default");
        ASSERT_STREQ(res.out, "default.target\n");
        ASSERT_EQ_INT(res.exit_code, 0);
        test_rm_rf(root);
        free(root);
}

static void test_list_jobs(void) {
        char *root = test_tmpdir_new();
        struct run_result res;

        ASSERT_TRUE(root != NULL);
        fixture_unit_state(
                        root,
                        "a.service",
                        "ActiveState=activating\nSubState=start\nLoadState=loaded\nJob=3 start\n");
        fixture_unit_state(
                        root,
                        "b.service",
                        "ActiveState=inactive\nSubState=dead\nLoadState=loaded\nJob=2 restart\n");
        fixture_unit_state(root, "c.service", "ActiveState=active\nSubState=running\nLoadState=loaded\n");

        RUN_PICOCTL(&res, "--root", root, "list-jobs");
        ASSERT_EQ_INT(res.exit_code, 0);
        ASSERT_TRUE(strstr(res.out, "JOB  UNIT") == res.out);
        {
                char *b = strstr(res.out, "b.service");
                char *a = strstr(res.out, "a.service");

                ASSERT_TRUE(a != NULL && b != NULL && b < a); /* by job id */
                ASSERT_TRUE(strstr(b, "restart") != NULL && strstr(b, "waiting") != NULL);
                ASSERT_TRUE(strstr(a, "start") != NULL && strstr(a, "running") != NULL);
        }
        ASSERT_TRUE(strstr(res.out, "2 jobs listed.") != NULL);

        RUN_PICOCTL(&res, "--root", root, "-o", "json", "list-jobs", "a*");
        ASSERT_STREQ(res.out,
                     "[{\"job\":3,\"unit\":\"a.service\",\"type\":\"start\",\"state\":\"running\"}]\n");

        RUN_PICOCTL(&res, "--root", root, "list-jobs", "c*");
        ASSERT_STREQ(res.out, "No jobs running.\n");

        test_rm_rf(root);
        free(root);
}

static void test_is_system_running_options(void) {
        char *root = test_tmpdir_new();
        struct run_result res;

        ASSERT_TRUE(root != NULL);
        fixture_manager_state(root, "NUnits=1\nNJobs=0\n");
        fixture_unit_state(root, "bad.service", "ActiveState=failed\nSubState=failed\nLoadState=loaded\n");

        RUN_PICOCTL(&res, "--root", root, "is-system-running");
        ASSERT_STREQ(res.out, "degraded\n");
        ASSERT_EQ_INT(res.exit_code, 1);

        /* -q drops the word, never the exit status */
        RUN_PICOCTL(&res, "--root", root, "-q", "is-system-running");
        ASSERT_STREQ(res.out, "");
        ASSERT_EQ_INT(res.exit_code, 1);

        /* --wait returns at once when startup is not in progress */
        RUN_PICOCTL(&res, "--root", root, "--wait", "is-system-running");
        ASSERT_STREQ(res.out, "degraded\n");

        RUN_PICOCTL(&res, "--root", root, "--wait", "--no-block", "is-system-running");
        ASSERT_EQ_INT(res.exit_code, 1);
        ASSERT_STREQ(res.out, "");

        /* no other verb can wait for a job to end */
        RUN_PICOCTL(&res, "--root", root, "--wait", "start", "bad.service");
        ASSERT_EQ_INT(res.exit_code, 1);

        test_rm_rf(root);
        free(root);
}

static void test_refused_options_and_verbs(void) {
        char *root = test_tmpdir_new();
        struct run_result res;
        static const char * const refused_opts[] = {
                "--user",
                "--global",
                "-H",
                "-M",
                "-C",
                "-r",
                "--runtime",
                "--with-dependencies",
                "--irreversible",
                "--ignore-dependencies",
                "--marked",
                "--firmware-setup",
                "--image",
                "--when",
                "--reboot-argument",
                "--kernel-cmdline",
        };
        static const char * const refused_verbs[] = {
                "isolate",          "set-default", "rescue", "suspend", "list-dependencies", "edit", "kexec",
                "show-environment", "freeze",      "revert", "cancel",
        };
        size_t i;

        ASSERT_TRUE(root != NULL);
        fixture_unit_state(root, "x.service", "ActiveState=active\nSubState=running\nLoadState=loaded\n");

        for (i = 0; i < sizeof(refused_opts) / sizeof(refused_opts[0]); i++) {
                /* every option that takes an argument gets one, so only the refusal can fail it */
                RUN_PICOCTL(&res, "--root", root, (char *) refused_opts[i], "x", "list-units");
                ASSERT_EQ_INT(res.exit_code, 1);
        }
        for (i = 0; i < sizeof(refused_verbs) / sizeof(refused_verbs[0]); i++) {
                RUN_PICOCTL(&res, "--root", root, (char *) refused_verbs[i], "x.service");
                ASSERT_EQ_INT(res.exit_code, 1);
                ASSERT_STREQ(res.out, "");
        }

        RUN_PICOCTL(&res, "--root", root, "--job-mode=isolate", "list-units");
        ASSERT_EQ_INT(res.exit_code, 1);
        RUN_PICOCTL(&res, "--root", root, "--job-mode=fail", "list-units");
        ASSERT_EQ_INT(res.exit_code, 0);
        RUN_PICOCTL(&res, "--root", root, "--fail", "list-units");
        ASSERT_EQ_INT(res.exit_code, 0);
        RUN_PICOCTL(&res, "--root", root, "--kill-whom=control", "kill", "x.service");
        ASSERT_EQ_INT(res.exit_code, 1);
        RUN_PICOCTL(&res, "--root", root, "--timestamp=bogus", "list-units");
        ASSERT_EQ_INT(res.exit_code, 1);
        RUN_PICOCTL(&res, "--root", root, "--preset-mode=bogus", "list-units");
        ASSERT_EQ_INT(res.exit_code, 1);
        RUN_PICOCTL(&res, "--root", root, "-s", "NOSUCH", "kill", "x.service");
        ASSERT_EQ_INT(res.exit_code, 1);
        RUN_PICOCTL(&res, "--root", root, "--kill-subgroup=../x", "kill", "x.service");
        ASSERT_EQ_INT(res.exit_code, 1);

        /* a verb that does not exist at all is still the upstream message and status */
        RUN_PICOCTL(&res, "--root", root, "no-such-verb");
        ASSERT_EQ_INT(res.exit_code, 1);

        test_rm_rf(root);
        free(root);
}

static void test_signal_names(void) {
        struct run_result res;

        RUN_PICOCTL(&res, "-s", "help");
        ASSERT_EQ_INT(res.exit_code, 0);
        ASSERT_TRUE(strstr(res.out, "SIGTERM\n") != NULL && strstr(res.out, "SIGPWR\n") != NULL);
        RUN_PICOCTL(&res, "--timestamp=help");
        ASSERT_TRUE(strstr(res.out, "us+utc\n") != NULL);
        RUN_PICOCTL(&res, "--preset-mode=help");
        ASSERT_TRUE(strstr(res.out, "enable-only\n") != NULL);
}

/*
 * kill: a real child takes a real signal. SIGRTMIN+1 with --kill-value=5
 * exercises both the name parser and the sigqueue() path; the child has no
 * handler, so it dies of that exact signal.
 */
static void test_kill_signal_and_value(void) {
        char *root = test_tmpdir_new();
        struct run_result res;
        char content[128];
        pid_t pid;
        int status;

        ASSERT_TRUE(root != NULL);

        pid = fork();
        ASSERT_TRUE(pid >= 0);
        if (pid == 0) {
                for (;;)
                        pause();
        }

        snprintf(content,
                 sizeof(content),
                 "ActiveState=active\nSubState=running\nLoadState=loaded\nMainPID=%d\n",
                 (int) pid);
        fixture_unit_state(root, "sleeper.service", content);

        RUN_PICOCTL(&res, "--root", root, "kill", "--kill-whom=main", "-s", "SIGRTMIN+1", "--kill-value", "5", "sleeper");
        ASSERT_EQ_INT(res.exit_code, 0);
        ASSERT_EQ_INT(waitpid(pid, &status, 0), pid);
        ASSERT_TRUE(WIFSIGNALED(status));
        ASSERT_EQ_INT(WTERMSIG(status), SIGRTMIN + 1);

        pid = fork();
        ASSERT_TRUE(pid >= 0);
        if (pid == 0) {
                for (;;)
                        pause();
        }
        snprintf(content,
                 sizeof(content),
                 "ActiveState=active\nSubState=running\nLoadState=loaded\nMainPID=%d\n",
                 (int) pid);
        fixture_unit_state(root, "sleeper.service", content);

        RUN_PICOCTL(&res, "--root", root, "kill", "--kill-whom=main", "-s", "9", "sleeper.service");
        ASSERT_EQ_INT(res.exit_code, 0);
        ASSERT_EQ_INT(waitpid(pid, &status, 0), pid);
        ASSERT_TRUE(WIFSIGNALED(status));
        ASSERT_EQ_INT(WTERMSIG(status), SIGKILL);

        test_rm_rf(root);
        free(root);
}

/* --now acts on the unit after the symlinks, so without a manager it fails where plain enable does not. */
static void test_enable_now(void) {
        char *root = test_tmpdir_new();
        struct run_result res;

        ASSERT_TRUE(root != NULL);
        make_fixture_root(root);

        RUN_PICOCTL(&res, "--root", root, "enable", "foo.service");
        ASSERT_EQ_INT(res.exit_code, 0);
        RUN_PICOCTL(&res, "--root", root, "disable", "--now", "foo.service");
        ASSERT_EQ_INT(res.exit_code, 1); /* stop could not reach a manager */
        RUN_PICOCTL(&res, "--root", root, "is-enabled", "foo.service");
        ASSERT_STREQ(res.out, "disabled\n"); /* but the symlinks went first */

        RUN_PICOCTL(&res, "--root", root, "enable", "--now", "foo.service");
        ASSERT_EQ_INT(res.exit_code, 1);
        RUN_PICOCTL(&res, "--root", root, "is-enabled", "foo.service");
        ASSERT_STREQ(res.out, "enabled\n");

        /* mask --now stops the unit once it is masked */
        RUN_PICOCTL(&res, "--root", root, "mask", "--now", "bar.service");
        ASSERT_EQ_INT(res.exit_code, 1);
        RUN_PICOCTL(&res, "--root", root, "is-enabled", "bar.service");
        ASSERT_STREQ(res.out, "masked\n");

        test_rm_rf(root);
        free(root);
}

static void test_preset_all_and_mode(void) {
        char *root = test_tmpdir_new();
        char presetdir[PATH_MAX];
        struct run_result res;

        ASSERT_TRUE(root != NULL);
        make_fixture_root(root);
        snprintf(presetdir, sizeof(presetdir), "%s%s", root, PICO_PRESET_DIR);
        ASSERT_EQ_INT(test_write_file(presetdir, "10-test.preset", "disable foo.service\nenable bar.service\n"),
                      0);

        /* disable-only leaves bar alone although the rule enables it */
        RUN_PICOCTL(&res, "--root", root, "--preset-mode=disable-only", "preset-all");
        ASSERT_EQ_INT(res.exit_code, 0);
        RUN_PICOCTL(&res, "--root", root, "is-enabled", "bar.service");
        ASSERT_STREQ(res.out, "disabled\n");

        RUN_PICOCTL(&res, "--root", root, "preset-all");
        ASSERT_EQ_INT(res.exit_code, 0);
        RUN_PICOCTL(&res, "--root", root, "is-enabled", "bar.service");
        ASSERT_STREQ(res.out, "enabled\n");
        RUN_PICOCTL(&res, "--root", root, "is-enabled", "foo.service");
        ASSERT_STREQ(res.out, "disabled\n");

        /* enable-only does not undo what an enable rule does not cover */
        RUN_PICOCTL(&res, "--root", root, "enable", "foo.service");
        RUN_PICOCTL(&res, "--root", root, "--preset-mode=enable-only", "preset", "foo.service");
        RUN_PICOCTL(&res, "--root", root, "is-enabled", "foo.service");
        ASSERT_STREQ(res.out, "enabled\n");
        RUN_PICOCTL(&res, "--root", root, "preset", "foo.service");
        RUN_PICOCTL(&res, "--root", root, "is-enabled", "foo.service");
        ASSERT_STREQ(res.out, "disabled\n");

        test_rm_rf(root);
        free(root);
}

static void test_add_dependency_and_link(void) {
        char *root = test_tmpdir_new();
        char path[PATH_MAX + 64], outside[PATH_MAX];
        struct run_result res;
        ssize_t n;
        char target[PATH_MAX];

        ASSERT_TRUE(root != NULL);
        make_fixture_root(root);

        RUN_PICOCTL(&res, "--root", root, "add-wants", "multi-user", "static.service");
        ASSERT_EQ_INT(res.exit_code, 0);
        ASSERT_TRUE(strstr(res.out, "multi-user.target.wants/static.service") != NULL);
        snprintf(path, sizeof(path), "%s%s/multi-user.target.wants/static.service", root, PICO_UNIT_DIR);
        n = readlink(path, target, sizeof(target) - 1);
        ASSERT_TRUE(n > 0);
        target[n] = '\0';
        ASSERT_TRUE(strstr(target, PICO_PACKAGED_UNIT_DIR "/static.service") != NULL);

        RUN_PICOCTL(&res, "--root", root, "add-requires", "foo.target", "static.service");
        ASSERT_EQ_INT(res.exit_code, 0);
        snprintf(path, sizeof(path), "%s%s/foo.target.requires/static.service", root, PICO_UNIT_DIR);
        ASSERT_TRUE(readlink(path, target, sizeof(target)) > 0);

        RUN_PICOCTL(&res, "--root", root, "add-wants", "multi-user.target", "nonexistent.service");
        ASSERT_EQ_INT(res.exit_code, 1);
        RUN_PICOCTL(&res, "--root", root, "add-wants", "multi-user.target");
        ASSERT_EQ_INT(res.exit_code, 1);

        /* link: an absolute file outside the search path */
        snprintf(outside, sizeof(outside), "%s", root);
        ASSERT_EQ_INT(test_write_file(outside, "ext.service", static_service), 0);
        snprintf(path, sizeof(path), "%s/ext.service", root);
        RUN_PICOCTL(&res, "--root", root, "link", path);
        ASSERT_EQ_INT(res.exit_code, 0);
        snprintf(path, sizeof(path), "%s%s/ext.service", root, PICO_UNIT_DIR);
        n = readlink(path, target, sizeof(target) - 1);
        ASSERT_TRUE(n > 0);
        target[n] = '\0';
        ASSERT_TRUE(strstr(target, "/ext.service") != NULL);

        RUN_PICOCTL(&res, "--root", root, "link", "relative.service");
        ASSERT_EQ_INT(res.exit_code, 1);
        RUN_PICOCTL(&res, "--root", root, "link", "/nonexistent/x.service");
        ASSERT_EQ_INT(res.exit_code, 1);

        test_rm_rf(root);
        free(root);
}

/* The personalities, run through a symlink so argv[0] names them. --dry-run, -w and -k
 * succeed without signalling PID 1, which this unprivileged test could not do anyway. */
static void run_as(const char *dir, const char *name, char * const rest[], struct run_result *res) {
        char link[PATH_MAX], self[PATH_MAX];
        char *args[8];
        size_t i, n = 0;

        ASSERT_EQ_INT(sibling_binary_path("picoctl", self, sizeof(self)), 0);
        snprintf(link, sizeof(link), "%s/%s", dir, name);
        unlink(link);
        ASSERT_EQ_INT(symlink(self, link), 0);

        args[n++] = link;
        for (i = 0; rest[i] && n < 7; i++)
                args[n++] = rest[i];
        args[n] = NULL;
        ASSERT_EQ_INT(run_binary(link, args, res), 0);
}

static void test_power_personalities(void) {
        char *dir = test_tmpdir_new();
        struct run_result res;

        ASSERT_TRUE(dir != NULL);

        {
                char * const a[] = { "-w", NULL };
                run_as(dir, "halt", a, &res);
                ASSERT_EQ_INT(res.exit_code, 0);
        }
        {
                char * const a[] = { "--reboot", "-w", "-f", "--no-wall", "-n", "-d", NULL };
                run_as(dir, "poweroff", a, &res);
                ASSERT_EQ_INT(res.exit_code, 0);
        }
        {
                char * const a[] = { "--help", NULL };
                run_as(dir, "reboot", a, &res);
                ASSERT_EQ_INT(res.exit_code, 0);
                ASSERT_TRUE(strstr(res.out, "reboot [OPTIONS...] [ARG]") != NULL);
        }
        {
                char * const a[] = { "-w", "arg", NULL };
                run_as(dir, "reboot", a, &res);
                ASSERT_EQ_INT(res.exit_code, 1); /* a reboot argument has nowhere to go */
        }
        {
                char * const a[] = { "-w", "extra", NULL };
                run_as(dir, "halt", a, &res);
                ASSERT_EQ_INT(res.exit_code, 1);
        }
        {
                char * const a[] = { "--bogus", NULL };
                run_as(dir, "halt", a, &res);
                ASSERT_EQ_INT(res.exit_code, 1);
        }

        {
                char * const a[] = { "-k", "now", "going", "down", NULL };
                run_as(dir, "shutdown", a, &res);
                ASSERT_EQ_INT(res.exit_code, 0);
        }
        {
                char * const a[] = { "-r", "-k", "+0", NULL };
                run_as(dir, "shutdown", a, &res);
                ASSERT_EQ_INT(res.exit_code, 0);
        }
        {
                char * const a[] = { "--show", NULL };
                run_as(dir, "shutdown", a, &res);
                ASSERT_STREQ(res.out, "No scheduled shutdown.\n");
                ASSERT_EQ_INT(res.exit_code, 0);
        }
        {
                char * const a[] = { "-c", NULL };
                run_as(dir, "shutdown", a, &res);
                ASSERT_EQ_INT(res.exit_code, 0);
        }
        {
                char * const a[] = { "-k", "+5", NULL };
                run_as(dir, "shutdown", a, &res);
                ASSERT_EQ_INT(res.exit_code, 1); /* no scheduler */
        }
        {
                char * const a[] = { "-k", "10:30", NULL };
                run_as(dir, "shutdown", a, &res);
                ASSERT_EQ_INT(res.exit_code, 1);
        }
        {
                char * const a[] = { "-k", "tomorrow", NULL };
                run_as(dir, "shutdown", a, &res);
                ASSERT_EQ_INT(res.exit_code, 1);
        }
        {
                char * const a[] = { "-K", NULL };
                run_as(dir, "shutdown", a, &res);
                ASSERT_EQ_INT(res.exit_code, 1);
        }

        /* the verbs: --dry-run does nothing, successfully; extra arguments are an error */
        RUN_PICOCTL(&res, "--dry-run", "reboot");
        ASSERT_EQ_INT(res.exit_code, 0);
        RUN_PICOCTL(&res, "--dry-run", "poweroff");
        ASSERT_EQ_INT(res.exit_code, 0);
        RUN_PICOCTL(&res, "--dry-run", "halt", "x");
        ASSERT_EQ_INT(res.exit_code, 1);

        test_rm_rf(dir);
        free(dir);
}

static void test_whoami(void) {
        struct run_result res;

        RUN_PICOCTL(&res, "whoami", "notapid");
        ASSERT_EQ_INT(res.exit_code, 1);
        RUN_PICOCTL(&res, "whoami", "0");
        ASSERT_EQ_INT(res.exit_code, 1);
        /* the test runs outside any unit's cgroup */
        RUN_PICOCTL(&res, "whoami", "999999999");
        ASSERT_EQ_INT(res.exit_code, 1);
}

/* --- reload verbs against a stand-in control socket --- */

/*
 * A stand-in for PID 1's control socket under --root: `restart` gets
 * restart_reply, every other verb other_reply, and each request line is
 * appended to <root>/requests. Bound before the fork, so picoctl never
 * races its startup.
 */
static pid_t fake_ctrl_start(const char *root, const char *other_reply, const char *restart_reply) {
        struct sockaddr_un addr;
        char rtdir[PATH_MAX], log[PATH_MAX + 16];
        pid_t pid;
        int fd, n;

        snprintf(rtdir, sizeof(rtdir), "%s%s", root, PICO_RUNTIME_DIR);
        ASSERT_EQ_INT(fixture_mkdir_p(rtdir), 0);
        snprintf(log, sizeof(log), "%s/requests", root);

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        n = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/control", rtdir);
        ASSERT_TRUE(n > 0 && (size_t) n < sizeof(addr.sun_path));
        unlink(addr.sun_path);

        fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
        ASSERT_TRUE(fd >= 0);
        ASSERT_EQ_INT(bind(fd, (struct sockaddr *) &addr, sizeof(addr)), 0);
        ASSERT_EQ_INT(listen(fd, 4), 0);

        pid = fork();
        ASSERT_TRUE(pid >= 0);
        if (pid == 0) {
                for (;;) {
                        char buf[600];
                        const char *reply;
                        ssize_t r;
                        FILE *f;
                        int c = accept(fd, NULL, NULL);

                        if (c < 0)
                                continue;
                        r = recv(c, buf, sizeof(buf) - 1, 0);
                        if (r > 0) {
                                buf[r] = '\0';
                                f = fopen(log, "ae");
                                if (f) {
                                        fprintf(f, "%s\n", buf);
                                        fclose(f);
                                }
                                reply = strncmp(buf, "PICO1 restart ", 14) == 0 ? restart_reply : other_reply;
                                (void) send(c, reply, strlen(reply), MSG_NOSIGNAL);
                        }
                        close(c);
                }
        }

        close(fd);
        return pid;
}

static void fake_ctrl_stop(pid_t pid) {
        kill(pid, SIGKILL);
        ASSERT_EQ_INT(waitpid(pid, NULL, 0), pid);
}

/* The requests the stand-in recorded since the last call, which clears them. */
static void assert_requests(const char *root, const char *want) {
        char path[PATH_MAX + 16], buf[1024];
        size_t n = 0;
        FILE *f;

        snprintf(path, sizeof(path), "%s/requests", root);
        f = fopen(path, "re");
        if (f) {
                n = fread(buf, 1, sizeof(buf) - 1, f);
                fclose(f);
        }
        buf[n] = '\0';
        ASSERT_STREQ(buf, want);
        unlink(path);
}

/*
 * A new picoctl against a PID 1 that predates the reload verbs ("err
 * unknown-verb"): reload is refused as before, reload-or-restart restarts,
 * try-reload-or-restart (and force-reload) restarts only a unit that is up.
 */
static void test_ctrl_compat_with_old_pid1(void) {
        char *root = test_tmpdir_new();
        struct run_result res;
        pid_t server;

        ASSERT_TRUE(root != NULL);
        server = fake_ctrl_start(root, "err unknown-verb\n", "ok done\n");

        RUN_PICOCTL(&res, "--root", root, "reload", "x.service");
        ASSERT_EQ_INT(res.exit_code, 1);
        assert_requests(root, "PICO1 reload x.service\n");

        RUN_PICOCTL(&res, "--root", root, "reload-or-restart", "x.service");
        ASSERT_EQ_INT(res.exit_code, 0);
        assert_requests(root, "PICO1 reload-or-restart x.service\nPICO1 restart x.service\n");

        fixture_unit_state(root, "x.service", "ActiveState=inactive\nSubState=dead\nLoadState=loaded\n");
        RUN_PICOCTL(&res, "--root", root, "try-reload-or-restart", "x.service");
        ASSERT_EQ_INT(res.exit_code, 0);
        assert_requests(root, "PICO1 try-reload-or-restart x.service\n");

        fixture_unit_state(root, "x.service", "ActiveState=active\nSubState=running\nLoadState=loaded\n");
        RUN_PICOCTL(&res, "--root", root, "force-reload", "x.service");
        ASSERT_EQ_INT(res.exit_code, 0);
        assert_requests(root, "PICO1 try-reload-or-restart x.service\nPICO1 restart x.service\n");

        fake_ctrl_stop(server);
        test_rm_rf(root);
        free(root);
}

/* The new PID 1's reload replies map to exit codes, and a try-* verb on a
 * unit PID 1 does not know stays silent. */
static void test_reload_replies_from_new_pid1(void) {
        static const struct {
                const char *reply, *verb, *wire;
                int exit_code;
        } cases[] = {
                {        "err invalid\n",                "reload",                "reload", 1 },
                { "err not-applicable\n",                "reload",                "reload", 1 },
                {            "ok done\n",                "reload",                "reload", 0 },
                {          "ok queued\n",     "reload-or-restart",     "reload-or-restart", 0 },
                {         "err failed\n",     "reload-or-restart",     "reload-or-restart", 1 },
                {   "err no-such-unit\n",                "reload",                "reload", 5 },
                {   "err no-such-unit\n", "try-reload-or-restart", "try-reload-or-restart", 0 },
                {   "err no-such-unit\n",            "condreload", "try-reload-or-restart", 0 },
        };
        size_t i;

        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
                char *root = test_tmpdir_new();
                char want[128];
                struct run_result res;
                pid_t server;

                ASSERT_TRUE(root != NULL);
                server = fake_ctrl_start(root, cases[i].reply, "err unexpected-restart\n");

                RUN_PICOCTL(&res, "--root", root, (char *) cases[i].verb, "x.service");
                ASSERT_EQ_INT(res.exit_code, cases[i].exit_code);
                snprintf(want, sizeof(want), "PICO1 %s x.service\n", cases[i].wire);
                assert_requests(root, want);

                fake_ctrl_stop(server);
                test_rm_rf(root);
                free(root);
        }
}

/* is-active counts a reloading unit as active, as upstream's verb_is_active(). */
static void test_is_active_accepts_reloading(void) {
        char *root = test_tmpdir_new();
        struct run_result res;

        ASSERT_TRUE(root != NULL);
        fixture_unit_state(root, "r.service", "ActiveState=reloading\nSubState=reload\nLoadState=loaded\n");

        RUN_PICOCTL(&res, "--root", root, "is-active", "r.service");
        ASSERT_STREQ(res.out, "reloading\n");
        ASSERT_EQ_INT(res.exit_code, 0);

        RUN_PICOCTL(&res, "--root", root, "is-failed", "r.service");
        ASSERT_EQ_INT(res.exit_code, 1);

        test_rm_rf(root);
        free(root);
}

/*
 * A unit that does not exist, verb by verb, against systemctl's text, stream
 * and status: status prints only the "could not be found" line on stderr and
 * exits 4, the job verbs exit 5 (EXIT_NOTINSTALLED), is-active and
 * is-enabled keep their word on stdout and exit 4, show is not an error.
 */
static void test_unknown_unit(void) {
        static const char * const job_verbs[] = { "start", "stop", "restart", "reload" };
        char *root = test_tmpdir_new();
        struct run_result res;
        size_t i;
        pid_t server;

        ASSERT_TRUE(root != NULL);
        make_fixture_root(root);
        fixture_unit_state(root, "up.service", "ActiveState=active\nSubState=running\nLoadState=loaded\n");
        fixture_unit_state(root, "down.service", "ActiveState=inactive\nSubState=dead\nLoadState=loaded\n");

        RUN_PICOCTL(&res, "--root", root, "status", "nosuch.service");
        ASSERT_STREQ(res.out, "");
        ASSERT_STREQ(res.err, "Unit nosuch.service could not be found.\n");
        ASSERT_EQ_INT(res.exit_code, 4);

        /* a bare name is a .service, in the message too */
        RUN_PICOCTL(&res, "--root", root, "status", "nosuch");
        ASSERT_STREQ(res.out, "");
        ASSERT_STREQ(res.err, "Unit nosuch.service could not be found.\n");
        ASSERT_EQ_INT(res.exit_code, 4);

        /* no blank separator for the missing unit, and the first non-zero
         * status wins, as in verb_show() */
        RUN_PICOCTL(&res, "--root", root, "status", "nosuch.service", "up.service");
        ASSERT_TRUE(strncmp(res.out, "up.service\n", 11) == 0);
        ASSERT_STREQ(res.err, "Unit nosuch.service could not be found.\n");
        ASSERT_EQ_INT(res.exit_code, 4);

        RUN_PICOCTL(&res, "--root", root, "status", "down.service", "nosuch.service", "up.service");
        ASSERT_TRUE(strstr(res.out, "\n\n\n") == NULL);
        ASSERT_TRUE(strstr(res.out, "\n\nup.service\n") != NULL);
        ASSERT_STREQ(res.err, "Unit nosuch.service could not be found.\n");
        ASSERT_EQ_INT(res.exit_code, 3);

        RUN_PICOCTL(&res, "--root", root, "is-active", "nosuch.service");
        ASSERT_STREQ(res.out, "inactive\n");
        ASSERT_STREQ(res.err, "");
        ASSERT_EQ_INT(res.exit_code, 4);

        RUN_PICOCTL(&res, "-q", "--root", root, "is-active", "nosuch.service");
        ASSERT_STREQ(res.out, "");
        ASSERT_EQ_INT(res.exit_code, 4);

        RUN_PICOCTL(&res, "--root", root, "is-failed", "nosuch.service");
        ASSERT_STREQ(res.out, "inactive\n");
        ASSERT_EQ_INT(res.exit_code, 4);

        RUN_PICOCTL(&res, "--root", root, "is-enabled", "nosuch.service");
        ASSERT_STREQ(res.out, "not-found\n");
        ASSERT_STREQ(res.err, "");
        ASSERT_EQ_INT(res.exit_code, 4);

        RUN_PICOCTL(&res, "-q", "--root", root, "is-enabled", "nosuch.service");
        ASSERT_STREQ(res.out, "");
        ASSERT_EQ_INT(res.exit_code, 4);

        /* show logs the missing unit at debug level only */
        RUN_PICOCTL(&res, "--root", root, "show", "nosuch.service");
        ASSERT_TRUE(strstr(res.out, "Id=nosuch.service\n") != NULL);
        ASSERT_TRUE(strstr(res.out, "LoadState=not-found\n") != NULL);
        ASSERT_TRUE(strstr(res.out, "ActiveState=inactive\n") != NULL);
        ASSERT_STREQ(res.err, "");
        ASSERT_EQ_INT(res.exit_code, 0);

        RUN_PICOCTL(&res, "--root", root, "enable", "nosuch.service");
        ASSERT_STREQ(res.out, "");
        ASSERT_STREQ(res.err, "Failed to enable unit: Unit nosuch.service does not exist\n");
        ASSERT_EQ_INT(res.exit_code, 1);

        RUN_PICOCTL(&res, "--root", root, "reenable", "nosuch.service");
        ASSERT_STREQ(res.err, "Failed to reenable unit: Unit nosuch.service does not exist\n");
        ASSERT_EQ_INT(res.exit_code, 1);

        RUN_PICOCTL(&res, "--root", root, "disable", "nosuch.service");
        ASSERT_STREQ(res.out, "");
        ASSERT_STREQ(res.err, "Failed to disable unit: Unit nosuch.service does not exist\n");
        ASSERT_EQ_INT(res.exit_code, 1);

        RUN_PICOCTL(&res, "--root", root, "preset", "nosuch.service");
        ASSERT_STREQ(res.err, "Failed to preset unit: Unit nosuch.service does not exist\n");
        ASSERT_EQ_INT(res.exit_code, 1);

        server = fake_ctrl_start(root, "err no-such-unit\n", "err no-such-unit\n");
        for (i = 0; i < sizeof(job_verbs) / sizeof(job_verbs[0]); i++) {
                char want[128];

                RUN_PICOCTL(&res, "--root", root, (char *) job_verbs[i], "nosuch");
                ASSERT_STREQ(res.out, "");
                snprintf(want,
                         sizeof(want),
                         "Failed to %s nosuch.service: Unit nosuch.service %s.\n",
                         job_verbs[i],
                         strcmp(job_verbs[i], "stop") == 0 ? "not loaded" : "not found");
                ASSERT_STREQ(res.err, want);
                ASSERT_EQ_INT(res.exit_code, 5);
                snprintf(want, sizeof(want), "PICO1 %s nosuch.service\n", job_verbs[i]);
                assert_requests(root, want);
        }

        RUN_PICOCTL(&res, "--root", root, "reset-failed", "nosuch");
        ASSERT_STREQ(res.out, "");
        ASSERT_STREQ(res.err,
                     "Failed to reset failed state of unit nosuch.service: Unit nosuch.service not loaded.\n");
        ASSERT_EQ_INT(res.exit_code, 1);
        assert_requests(root, "PICO1 reset-failed nosuch.service\n");

        /* every unit is tried, the status is the first failure's */
        RUN_PICOCTL(&res, "--root", root, "start", "one.service", "two.service");
        ASSERT_STREQ(res.err,
                     "Failed to start one.service: Unit one.service not found.\n"
                     "Failed to start two.service: Unit two.service not found.\n");
        ASSERT_EQ_INT(res.exit_code, 5);
        assert_requests(root, "PICO1 start one.service\nPICO1 start two.service\n");
        fake_ctrl_stop(server);

        /* a refusal that is not "no such unit" stays status 1 */
        server = fake_ctrl_start(root, "err shutting-down\n", "err shutting-down\n");
        RUN_PICOCTL(&res, "--root", root, "start", "up.service");
        ASSERT_STREQ(res.err, "Failed to start up.service: shutting-down\n");
        ASSERT_EQ_INT(res.exit_code, 1);
        fake_ctrl_stop(server);

        test_rm_rf(root);
        free(root);
}

int main(void) {
        test_enable_disable_is_enabled();
        test_preset();
        test_preset_ignore();
        test_preset_default_enable();
        test_mask_unmask();
        test_list_unit_files();
        test_read_verbs_against_real_boot();
        test_status_log_tail();
        test_is_system_running_fstab();
        test_cli_option_parsing();
        test_show_unit_file_state_live();
        test_status_no_argument_system_overview();
        test_status_dropins();
        test_status_colors();
        test_list_units_colors();
        test_list_units_filters_and_legend();
        test_json_output();
        test_json_unit_files();
        test_empty_unit_types();
        test_show_properties_and_manager();
        test_list_jobs();
        test_is_system_running_options();
        test_refused_options_and_verbs();
        test_signal_names();
        test_kill_signal_and_value();
        test_enable_now();
        test_preset_all_and_mode();
        test_add_dependency_and_link();
        test_power_personalities();
        test_whoami();
        test_ctrl_compat_with_old_pid1();
        test_reload_replies_from_new_pid1();
        test_is_active_accepts_reloading();
        test_unknown_unit();
        /* Last: it exit(77)s on a host without systemctl, and a SKIP must not
         * hide the in-process checks above. */
        test_oracle_symlinks_byte_identical();

        printf("test-picoctl: all checks passed\n");
        return 0;
}
