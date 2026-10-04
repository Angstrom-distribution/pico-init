/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * picoctl's file and symlink half (plan §1.7, C1): golden-output tests per verb against fixture state trees,
 * systemctl-matching exit codes, and symlink layouts byte-identical to systemctl --root on the same fixtures.
 *
 * meson.build (frozen for this milestone) links this program against
 * pico-init-core, not against picoctl.c itself -- picoctl is its own
 * executable with its own main(), and there is no picoctl-core library to
 * link. So every case here runs the REAL built `picoctl` binary as a
 * subprocess (found next to this test binary via /proc/self/exe, since both
 * land in the same meson build root) and asserts its actual stdout and exit
 * code -- the same end-to-end discipline the oracle comparison itself needs
 * (real systemctl --root vs. real picoctl, never an in-process shortcut).
 *
 * The oracle test (test_oracle_symlinks_byte_identical) shells out to the
 * real `systemctl` this project's verification container installs
 * specifically for it. It SKIPs (exit 77) rather than fails when systemctl
 * is not on PATH, so `meson test` stays green in an environment that
 * legitimately has no systemd (e.g. an OE build sandbox) -- but it is a
 * real, required comparison whenever systemctl is available, which it is in
 * this project's own verification container.
 */

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
        int exit_code;
};

/*
 * Fork/exec `path` with `args` (NULL-terminated, args[0] reused as argv[0]),
 * *stdout only* captured into res->out, exit code decoded from waitpid().
 * stderr is deliberately left inherited (not captured): picoctl's own
 * pico_log() diagnostics go there (see util.c's pico_log_internal()), and
 * mixing them into res->out would make every golden-output comparison
 * fragile against log wording rather than against the real stdout contract
 * -- exactly the split real systemctl itself keeps between its state-word
 * stdout and its diagnostic stderr. Inheriting stderr rather than
 * discarding it also means a failing assertion's context is visible in the
 * test's own output when this runs under `meson test -v`.
 */
static int run_binary(const char *path, char * const args[], struct run_result *res) {
        int pipefd[2];
        pid_t pid;
        int status;
        size_t total = 0;

        res->out[0] = '\0';
        res->exit_code = -1;

        if (pipe(pipefd) < 0)
                return -errno;

        pid = fork();
        if (pid < 0) {
                close(pipefd[0]);
                close(pipefd[1]);
                return -errno;
        }

        if (pid == 0) {
                close(pipefd[0]);
                dup2(pipefd[1], STDOUT_FILENO);
                close(pipefd[1]);
                execv(path, args);
                _exit(127);
        }

        close(pipefd[1]);
        for (;;) {
                char buf[1024];
                ssize_t r = read(pipefd[0], buf, sizeof(buf));

                if (r <= 0)
                        break;
                if (total + (size_t) r < sizeof(res->out) - 1) {
                        memcpy(res->out + total, buf, (size_t) r);
                        total += (size_t) r;
                }
        }
        res->out[total] = '\0';
        close(pipefd[0]);

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
 * A local recursive mkdir keeps that need out of test-util.c, which this
 * milestone does not own.
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

        /* enabling a unit with no [Install] section fails cleanly */
        RUN_PICOCTL(&res, "--root", root, "enable", "static.service");
        ASSERT_EQ_INT(res.exit_code, 1);

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
 * binaries concurrently (the actual bug this pattern was added to fix).
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
 * --- status's log tail (the slot this milestone fills in cmd_status()) ---
 *
 * meson.build (frozen for this milestone) links this test program against
 * pico-init-core only, not logd-core -- the real `picoctl` binary under
 * test links logd-core and is what actually exercises logd_ring_read_
 * filtered(). So the fixture ring file below is hand-written to match
 * logd-write.c's on-disk encoding byte for byte (plain "NAME=value\n", or
 * the binary-safe "NAME\n<8-byte-LE-len><data>\n" form), rather than built
 * via logd_writer_append(), which is the only way to exercise the read
 * side here without a link_with change to a frozen file. "/run/logd" below
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

int main(void) {
        test_enable_disable_is_enabled();
        test_preset();
        test_preset_default_enable();
        test_read_verbs_against_real_boot();
        test_status_log_tail();
        test_is_system_running_fstab();
        /* Last: it exit(77)s on a host without systemctl, and a SKIP must not
         * hide the in-process checks above. */
        test_oracle_symlinks_byte_identical();

        printf("test-picoctl: all checks passed\n");
        return 0;
}
