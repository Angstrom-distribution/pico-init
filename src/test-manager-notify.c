/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The sd_notify() listener (manager-notify.c): end-to-end wire protocol,
 * attribution and its CALLBACK CONTRACT drop-then-keep-listening property,
 * per-datagram malformed-input rejection, the child-environment injection
 * and scrub, teardown, and the not-fatal-to-boot setup-failure policy.
 *
 * No manager_startup()/default.target boilerplate here (unlike
 * test-manager-ctrl.c): every case either drives service_start() directly
 * (test-service.c's own pattern) or sets Service.main_pid as a plain field
 * write, so nothing needs a booted transaction and nothing needs root.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "manager-notify.h"
#include "manager-state.h"
#include "manager.h"
#include "sd-daemon.h"
#include "service.h"
#include "test-util.h"
#include "timer.h"
#include "unit.h"
#include "util.h"

/* --- manager_loop() driver, duplicated from test-manager-ctrl.c's own --- */

static Manager *g_drive_m;
static bool (*g_drive_done)(void *userdata);
static void *g_drive_ctx;
static int g_drive_ticks;
static int g_drive_max_ticks;

static void drive_tick(void *userdata, usec_t now) {
        (void) userdata;
        (void) now;

        g_drive_ticks++;

        if (g_drive_done(g_drive_ctx) || g_drive_ticks >= g_drive_max_ticks)
                g_drive_m->objective = MANAGER_EXIT;
        else
                ASSERT_EQ_INT(pico_timer_add(g_drive_m->timer,
                                             now_monotonic() + 5 * USEC_PER_MSEC,
                                             drive_tick,
                                             NULL,
                                             NULL),
                              0);
}

static bool drive_until(Manager *m, bool (*done)(void *), void *ctx, int max_ticks) {
        g_drive_m = m;
        g_drive_done = done;
        g_drive_ctx = ctx;
        g_drive_ticks = 0;
        g_drive_max_ticks = max_ticks;

        m->objective = MANAGER_RUNNING;

        ASSERT_EQ_INT(pico_timer_add(m->timer, now_monotonic() + 5 * USEC_PER_MSEC, drive_tick, NULL, NULL),
                      0);
        manager_loop(m);

        return done(ctx);
}

static bool always_true(void *userdata) {
        (void) userdata;
        return true;
}

static bool notify_ready_done(void *userdata) {
        return ((Service *) userdata)->notify_ready;
}

static bool notify_n_unattributed_ge1(void *userdata) {
        return manager_notify_debug_n_unattributed((Manager *) userdata) >= 1;
}

/* --- fixture: no manager_startup(), no default.target -- see this file's header --- */

/*
 * A pid-tagged real cgroup path, duplicated from test-manager-ctrl.c's own
 * use_private_cgroup_root() (that file's comment explains why: real cgroup
 * v2 control files only exist under an actual cgroupfs mount, so this can't
 * be relocated under the fixture tree, and the pid tag is what keeps two
 * test binaries booting a same-named unit from colliding under a parallel
 * `meson test` run). Needed here because service_start() unconditionally
 * calls service_ensure_cgroup(), which mkdir()s under m->cgroup_root -- the
 * PICO_CGROUP_ROOT default is the real system-wide /sys/fs/cgroup.
 */
static void use_private_cgroup_root(Manager *m, char *out, size_t out_size) {
        int n = snprintf(out, out_size, "/sys/fs/cgroup/pico-notify-test-%lld", (long long) getpid());

        ASSERT_TRUE(n > 0 && (size_t) n < out_size);
        if (mkdir(out, 0755) < 0)
                ASSERT_TRUE(errno == EEXIST);
        ASSERT_EQ_INT(manager_set_cgroup_root(m, out), 0);
}

static void free_private_cgroup_root(const char *root) {
        char slice[PATH_MAX];

        snprintf(slice, sizeof(slice), "%s/system.slice", root);
        rmdir(slice);
        rmdir(root);
}

struct notify_fixture {
        char *unitdir;
        char *rtdir;
        char cgroup_root[PATH_MAX];
        Manager *m;
};

static void notify_fixture_setup(struct notify_fixture *f) {
        f->unitdir = test_tmpdir_new();
        f->rtdir = test_tmpdir_new();
        ASSERT_TRUE(f->unitdir != NULL && f->rtdir != NULL);

        ASSERT_EQ_INT(manager_new(&f->m), 0);
        {
                const char * const up[] = { f->unitdir, NULL };

                ASSERT_EQ_INT(manager_set_unit_path(f->m, up), 0);
        }
        ASSERT_EQ_INT(manager_set_runtime_dir(f->m, f->rtdir), 0);
        use_private_cgroup_root(f->m, f->cgroup_root, sizeof(f->cgroup_root));
        ASSERT_EQ_INT(manager_state_setup(f->m), 0); /* only test_notify_end_to_end_attributed reads it back */
        ASSERT_EQ_INT(manager_notify_setup(f->m), 0);
}

static void notify_fixture_teardown(struct notify_fixture *f) {
        manager_free(f->m); /* frees ctrl/state/notify too */
        free_private_cgroup_root(f->cgroup_root);
        test_rm_rf(f->unitdir);
        test_rm_rf(f->rtdir);
        free(f->unitdir);
        free(f->rtdir);
}

static Service *load_service(Manager *m, const char *dir, const char *name, const char *contents) {
        Unit *u;

        ASSERT_EQ_INT(test_write_file(dir, name, contents), 0);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        u = manager_get_unit(m, name);
        ASSERT_TRUE(u != NULL);
        ASSERT_EQ_INT(u->type, UNIT_SERVICE);
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);

        return SERVICE(u);
}

/* --- a raw notify-socket client: one ephemeral socket per send --- */

static void notify_send(const char *rt, const void *data, size_t len) {
        struct sockaddr_un addr;
        char path[PATH_MAX];
        int fd, n;

        n = snprintf(path, sizeof(path), "%s/notify", rt);
        ASSERT_TRUE(n > 0 && (size_t) n < sizeof(path));

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        ASSERT_TRUE(strlen(path) < sizeof(addr.sun_path));
        memcpy(addr.sun_path, path, strlen(path) + 1);

        fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        ASSERT_TRUE(fd >= 0);
        ASSERT_EQ_INT((int) sendto(fd, data, len, 0, (struct sockaddr *) &addr, sizeof(addr)), (int) len);
        close(fd);
}

static void notify_send_str(const char *rt, const char *s) {
        notify_send(rt, s, strlen(s));
}

/* --- tests --- */

/* Sends two real datagrams through the shim's own sd_notify() from a real
 * fork()ed child, attributed via kernel-filled SO_PASSCRED credentials for
 * a genuinely different pid. The second datagram pins the drain property
 * (manager-loop.c's zero-timeout re-poll): the done-predicate only becomes
 * true once BOTH have been processed, so a regression that stops draining
 * after the first would hang out to the tick budget instead of passing. */
static bool notify_second_status_done(void *userdata) {
        Service *s = userdata;

        return s->status_text != NULL && strcmp(s->status_text, "still running") == 0;
}

static void test_notify_end_to_end_attributed(void) {
        struct notify_fixture f;
        Service *s;
        pid_t child;
        char path[PATH_MAX];
        FILE *fp;
        char line[256];
        bool found_ready = false;

        notify_fixture_setup(&f);
        s = load_service(f.m, f.unitdir, "demo.service", "[Unit]\n[Service]\nType=simple\nExecStart=/bin/true\n");

        child = fork();
        ASSERT_TRUE(child >= 0);
        if (child == 0) {
                setenv("NOTIFY_SOCKET", manager_notify_socket_path(f.m), 1);
                sd_notify(0, "READY=1\nSTATUS=up and running");
                sd_notify(0, "STATUS=still running");
                _exit(0);
        }

        /* Plain field write: no service_spawn() involved, so no root or real
         * ExecStart= is needed to test attribution itself. */
        s->main_pid = child;

        ASSERT_TRUE(drive_until(f.m, notify_second_status_done, s, 400));
        ASSERT_EQ_INT(s->notify_ready, true);
        ASSERT_STREQ(s->status_text, "still running");

        snprintf(path, sizeof(path), "%s/units/demo.service", f.rtdir);
        fp = fopen(path, "r");
        ASSERT_TRUE(fp != NULL);
        while (fgets(line, sizeof(line), fp))
                if (strcmp(line, "NotifyReady=yes\n") == 0)
                        found_ready = true;
        fclose(fp);
        ASSERT_TRUE(found_ready);

        waitpid(child, NULL, 0);
        notify_fixture_teardown(&f);
}

/* A sender no unit claims: dropped, counted, and -- the CALLBACK CONTRACT
 * proof -- the source keeps working afterward for a datagram that IS
 * attributed. */
static void test_notify_unattributed_harmless(void) {
        struct notify_fixture f;
        Service *s;

        notify_fixture_setup(&f);
        s = load_service(f.m, f.unitdir, "demo.service", "[Unit]\n[Service]\nType=simple\nExecStart=/bin/true\n");

        notify_send_str(f.rtdir, "READY=1"); /* nobody's pid, sent as our own */

        ASSERT_TRUE(drive_until(f.m, notify_n_unattributed_ge1, f.m, 200));
        ASSERT_EQ_INT(manager_notify_debug_n_unattributed(f.m), 1);
        ASSERT_EQ_INT(s->notify_ready, false);

        s->main_pid = getpid();
        notify_send_str(f.rtdir, "READY=1");

        ASSERT_TRUE(drive_until(f.m, notify_ready_done, s, 200));
        ASSERT_EQ_INT(s->notify_ready, true);
        ASSERT_EQ_INT(manager_notify_debug_n_unattributed(f.m), 1); /* unchanged: this one attributed fine */

        notify_fixture_teardown(&f);
}

/* An unknown prefix ahead of a real key changes nothing but the real key. */
static void test_notify_unknown_key_harmless(void) {
        struct notify_fixture f;
        Service *s;

        notify_fixture_setup(&f);
        s = load_service(f.m, f.unitdir, "demo.service", "[Unit]\n[Service]\nType=simple\nExecStart=/bin/true\n");
        s->main_pid = getpid();

        notify_send_str(f.rtdir, "FROBNICATE=1\nREADY=1");

        ASSERT_TRUE(drive_until(f.m, notify_ready_done, s, 200));
        ASSERT_EQ_INT(s->notify_ready, true);
        ASSERT_TRUE(s->status_text == NULL);
        ASSERT_EQ_INT(s->status_errno, 0);

        notify_fixture_teardown(&f);
}

/* An embedded-NUL datagram and an empty one are both dropped without
 * attribution or a crash, and a well-formed datagram sent right after is
 * still processed -- the drops are per-datagram, never sticky. */
static void test_notify_malformed_dropped(void) {
        struct notify_fixture f;
        Service *s;
        char embedded_nul[7] = { 'R', 'E', 'A', '\0', 'Y', '=', '1' };

        notify_fixture_setup(&f);
        s = load_service(f.m, f.unitdir, "demo.service", "[Unit]\n[Service]\nType=simple\nExecStart=/bin/true\n");
        s->main_pid = getpid();

        notify_send(f.rtdir, embedded_nul, sizeof(embedded_nul));
        notify_send(f.rtdir, "", 0);
        notify_send_str(f.rtdir, "READY=1");

        ASSERT_TRUE(drive_until(f.m, notify_ready_done, s, 200));
        ASSERT_EQ_INT(s->notify_ready, true);

        notify_fixture_teardown(&f);
}

/* A real service_start(), a real fork/exec of a shell that echoes back
 * $NOTIFY_SOCKET -- proving injection happens, an inherited bogus value is
 * scrubbed rather than merely shadowed (getenv-first-match would hide
 * that), and the envp survives execve() intact. */
static bool notify_file_exists_done(void *userdata) {
        return access((const char *) userdata, F_OK) == 0;
}

static void test_notify_env_injection_and_scrub(void) {
        struct notify_fixture f;
        Service *s;
        char *outdir;
        char outpath[PATH_MAX];
        char contents[PATH_MAX + 128];
        char want[PATH_MAX];
        char got[PATH_MAX];
        FILE *fp;

        setenv("NOTIFY_SOCKET", "/bogus", 1); /* pollute the manager's own environ first */

        notify_fixture_setup(&f);

        outdir = test_tmpdir_new();
        ASSERT_TRUE(outdir != NULL);
        snprintf(outpath, sizeof(outpath), "%s/out", outdir);

        snprintf(contents,
                 sizeof(contents),
                 "[Unit]\n[Service]\nType=oneshot\nExecStart=/bin/sh -c \"printf %%s $NOTIFY_SOCKET > %s\"\n",
                 outpath);
        s = load_service(f.m, f.unitdir, "demo.service", contents);

        ASSERT_EQ_INT(service_start(s), 0);
        ASSERT_TRUE(drive_until(f.m, notify_file_exists_done, outpath, 400));

        fp = fopen(outpath, "r");
        ASSERT_TRUE(fp != NULL);
        ASSERT_TRUE(fgets(got, sizeof(got), fp) != NULL);
        fclose(fp);

        snprintf(want, sizeof(want), "%s/notify", f.rtdir);
        ASSERT_STREQ(got, want);

        unsetenv("NOTIFY_SOCKET");
        test_rm_rf(outdir);
        free(outdir);
        notify_fixture_teardown(&f);
}

/* Teardown really unlinks the socket, is idempotent, leaves nothing a
 * sender can still reach, and manager_free() completes cleanly after. */
static void test_notify_teardown_clean(void) {
        struct notify_fixture f;
        char path[PATH_MAX];
        struct stat st;
        struct sockaddr_un addr;
        int fd;

        notify_fixture_setup(&f);
        snprintf(path, sizeof(path), "%s/notify", f.rtdir);

        manager_notify_done(f.m);
        ASSERT_TRUE(stat(path, &st) < 0 && errno == ENOENT);
        ASSERT_TRUE(manager_notify_socket_path(f.m) == NULL);

        manager_notify_done(f.m); /* idempotent */

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        memcpy(addr.sun_path, path, strlen(path) + 1);
        fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        ASSERT_TRUE(fd >= 0);
        ASSERT_TRUE(sendto(fd, "x", 1, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0);
        ASSERT_TRUE(errno == ENOENT || errno == ECONNREFUSED);
        close(fd);

        manager_free(f.m); /* nothing left behind to crash on */
        test_rm_rf(f.unitdir);
        test_rm_rf(f.rtdir);
        free(f.unitdir);
        free(f.rtdir);
}

/* runtime_dir pointing inside a nonexistent parent: setup fails, the socket
 * path stays NULL, and the manager still boots and spawns regardless --
 * the not-fatal-to-boot policy is real behavior, not just a comment.
 * Mirrors test-manager-state.c's own bogus-runtime fixture. */
static void test_notify_setup_failure_not_fatal(void) {
        Manager *m = NULL;
        char *unitdir, *blockdir;
        char bogus_runtime[PATH_MAX];
        char cgroup_root[PATH_MAX];
        Service *s;

        unitdir = test_tmpdir_new();
        blockdir = test_tmpdir_new();
        ASSERT_TRUE(unitdir != NULL && blockdir != NULL);

        ASSERT_EQ_INT(test_write_file(blockdir, "not-a-directory", ""), 0);
        snprintf(bogus_runtime, sizeof(bogus_runtime), "%s/not-a-directory", blockdir);

        ASSERT_EQ_INT(manager_new(&m), 0);
        {
                const char * const up[] = { unitdir, NULL };

                ASSERT_EQ_INT(manager_set_unit_path(m, up), 0);
        }
        ASSERT_EQ_INT(manager_set_runtime_dir(m, bogus_runtime), 0);
        use_private_cgroup_root(
                        m, cgroup_root, sizeof(cgroup_root)); /* service_start() below mkdirs a real cgroup */

        ASSERT_TRUE(manager_notify_setup(m) < 0);
        ASSERT_TRUE(manager_notify_socket_path(m) == NULL);

        s = load_service(m, unitdir, "demo.service", "[Unit]\n[Service]\nType=simple\nExecStart=/bin/true\n");
        ASSERT_EQ_INT(service_start(s), 0);
        ASSERT_TRUE(s->main_pid > 0); /* Type=simple: started the moment it forked */

        ASSERT_TRUE(drive_until(m, always_true, NULL, 5)); /* the loop itself still runs fine */

        manager_free(m);
        free_private_cgroup_root(cgroup_root);
        test_rm_rf(unitdir);
        test_rm_rf(blockdir);
        free(unitdir);
        free(blockdir);
}

/* MAINPID= moves main_pid (what a stop signals) for a root sender; ERRNO=
 * is stored. Malformed values of either change nothing. */
static bool notify_errno_is_5_done(void *userdata) {
        return ((Service *) userdata)->status_errno == 5;
}

static void test_notify_mainpid_and_errno(void) {
        struct notify_fixture f;
        Service *s;
        pid_t other;
        char msg[128];

        notify_fixture_setup(&f);
        s = load_service(f.m, f.unitdir, "demo.service", "[Unit]\n[Service]\nType=simple\nExecStart=/bin/true\n");
        s->main_pid = getpid();

        other = fork();
        ASSERT_TRUE(other >= 0);
        if (other == 0) {
                pause();
                _exit(0);
        }

        /* malformed first: nothing may change */
        notify_send_str(f.rtdir, "MAINPID=0\nMAINPID=12x\nERRNO=-1\nERRNO=abc");
        snprintf(msg, sizeof(msg), "MAINPID=%d\nERRNO=5", (int) other);
        notify_send_str(f.rtdir, msg);

        ASSERT_TRUE(drive_until(f.m, notify_errno_is_5_done, s, 200));
        ASSERT_EQ_INT(s->status_errno, 5);
        if (getuid() == 0)
                ASSERT_EQ_INT(s->main_pid, other);
        else
                ASSERT_EQ_INT(s->main_pid, getpid()); /* uid-gated */

        s->main_pid = 0; /* not ours to reap through the service */
        kill(other, SIGKILL);
        waitpid(other, NULL, 0);
        notify_fixture_teardown(&f);
}

/* BARRIER=1: the fd sent along is closed by the manager, which is the ack
 * sd_notify_barrier() waits for -- attributed or not. The barrier call
 * blocks, so it runs in a child that reports its return value on a pipe. */
static bool fd_readable_done(void *userdata) {
        struct pollfd pfd = { .fd = *(int *) userdata, .events = POLLIN };

        return poll(&pfd, 1, 0) == 1;
}

static void test_notify_barrier_acked(void) {
        struct notify_fixture f;
        int result_pipe[2];
        pid_t child;
        char r = 0;

        notify_fixture_setup(&f);
        ASSERT_EQ_INT(pipe(result_pipe), 0);

        child = fork();
        ASSERT_TRUE(child >= 0);
        if (child == 0) {
                char ok;

                close(result_pipe[0]);
                setenv("NOTIFY_SOCKET", manager_notify_socket_path(f.m), 1);
                ok = sd_notify_barrier(0, 2 * USEC_PER_SEC) >= 0 ? 'y' : 'n';
                /* Not `(void) write(...)`: a void cast does not suppress
                 * warn_unused_result -- see pico_log_internal(). */
                if (write(result_pipe[1], &ok, 1) < 0) {
                        /* Parent's read() below will time out instead. */
                }
                _exit(0);
        }
        close(result_pipe[1]);

        ASSERT_TRUE(drive_until(f.m, fd_readable_done, &result_pipe[0], 400));
        ASSERT_EQ_INT((int) read(result_pipe[0], &r, 1), 1);
        ASSERT_EQ_INT(r, 'y');

        close(result_pipe[0]);
        waitpid(child, NULL, 0);
        notify_fixture_teardown(&f);
}

static bool notify_errno_is_7_done(void *userdata) {
        return ((Service *) userdata)->status_errno == 7;
}

/* A datagram larger than the receive buffer arrives MSG_TRUNC: dropped
 * whole, never applied as its truncated head. */
static void test_notify_oversized_dropped(void) {
        struct notify_fixture f;
        Service *s;
        size_t len = 8192;
        char *big;

        notify_fixture_setup(&f);
        s = load_service(f.m, f.unitdir, "demo.service", "[Unit]\n[Service]\nType=simple\nExecStart=/bin/true\n");
        s->main_pid = getpid();

        big = malloc(len);
        ASSERT_TRUE(big != NULL);
        memset(big, 'x', len);
        memcpy(big, "READY=1\nSTATUS=", 15);
        notify_send(f.rtdir, big, len);
        free(big);
        notify_send_str(f.rtdir, "ERRNO=7");

        ASSERT_TRUE(drive_until(f.m, notify_errno_is_7_done, s, 200));
        ASSERT_EQ_INT(s->notify_ready, false);
        ASSERT_TRUE(s->status_text == NULL);

        notify_fixture_teardown(&f);
}

int main(void) {
        test_notify_end_to_end_attributed();
        test_notify_unattributed_harmless();
        test_notify_unknown_key_harmless();
        test_notify_malformed_dropped();
        test_notify_mainpid_and_errno();
        test_notify_barrier_acked();
        test_notify_oversized_dropped();
        test_notify_env_injection_and_scrub();
        test_notify_teardown_clean();
        test_notify_setup_failure_not_fatal();

        printf("test-manager-notify: all checks passed\n");
        return 0;
}
