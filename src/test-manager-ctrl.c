/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The control socket (plan §1.7, C2): deferred replies driven through the real manager loop, reset-failed,
 * early-disconnect leak checks, and oversized/malformed/unknown-verb rejection without allocation.
 *
 * Every case here talks the real wire protocol over a real AF_UNIX
 * SOCK_SEQPACKET socket to a real Manager running its real manager_loop() --
 * never a mock of manager-ctrl.c's own internals. A request is sent (a raw
 * client, not picoctl itself: test-picoctl.c already covers the CLI half end
 * to end, and driving the protocol directly here keeps this file's failure
 * output about the protocol, not about an extra subprocess layer), then the
 * real loop is pumped via a repeating timer tick (test-socket.c's own S1/S2
 * pattern, duplicated rather than shared -- see drive_until() below) until
 * either a reply arrives or a generous tick budget runs out as a safety net
 * against a genuine regression hanging the suite.
 */

/* struct sockaddr_un/SOCK_SEQPACKET are POSIX, but SOCK_CLOEXEC folded into
 * socket()'s type argument is a Linux extension; -std=gnu17 alone does not
 * imply _GNU_SOURCE (socket.c's own note, same reasoning here). */
#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "manager-ctrl.h"
#include "manager.h"
#include "service.h"
#include "test-util.h"
#include "timer.h"
#include "unit.h"

/* --- manager_loop() driver: pump the real loop until `done` or budget --- */

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

/* Returns whether `done` was actually satisfied (false means the tick
 * budget ran out first, which every caller here treats as a hard failure
 * via the ASSERT_TRUE wrapping the call, not as a valid outcome). */
static bool drive_until(Manager *m, bool (*done)(void *), void *ctx, int max_ticks) {
        g_drive_m = m;
        g_drive_done = done;
        g_drive_ctx = ctx;
        g_drive_ticks = 0;
        g_drive_max_ticks = max_ticks;

        /* A previous call on this Manager left objective at whatever it
         * stopped the loop with (MANAGER_EXIT); the loop only runs while it
         * is MANAGER_RUNNING. */
        m->objective = MANAGER_RUNNING;

        ASSERT_EQ_INT(pico_timer_add(m->timer, now_monotonic() + 5 * USEC_PER_MSEC, drive_tick, NULL, NULL),
                      0);
        manager_loop(m);

        return done(ctx);
}

/* --- a raw control-socket client (deliberately not picoctl itself) --- */

struct ctrl_client {
        int fd;
        char reply[600];
        ssize_t reply_len; /* -1: nothing yet; >= 0: a reply of this length arrived; -2: recv() error */
};

static void ctrl_client_connect(struct ctrl_client *c, const char *rt) {
        struct sockaddr_un addr;
        char path[PATH_MAX];
        int n;

        memset(c, 0, sizeof(*c));
        c->reply_len = -1;

        n = snprintf(path, sizeof(path), "%s/control", rt);
        ASSERT_TRUE(n > 0 && (size_t) n < sizeof(path));

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        ASSERT_TRUE(strlen(path) < sizeof(addr.sun_path));
        memcpy(addr.sun_path, path, strlen(path) + 1);

        c->fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        ASSERT_TRUE(c->fd >= 0);
        ASSERT_EQ_INT(connect(c->fd, (struct sockaddr *) &addr, sizeof(addr)), 0);
}

static void ctrl_client_send(struct ctrl_client *c, const void *data, size_t len) {
        ASSERT_EQ_INT((int) send(c->fd, data, len, 0), (int) len);
}

static void ctrl_client_send_str(struct ctrl_client *c, const char *s) {
        ctrl_client_send(c, s, strlen(s));
}

static void ctrl_client_close(struct ctrl_client *c) {
        if (c->fd >= 0)
                close(c->fd);
        c->fd = -1;
}

/* A drive_until() done-callback: non-blocking recv() each tick, latching
 * the first result (a reply, EOF, or a real error) so later ticks are a
 * cheap no-op rather than a second, meaningless recv() call. */
static bool ctrl_client_recv_done(void *userdata) {
        struct ctrl_client *c = userdata;
        ssize_t n;

        if (c->reply_len != -1)
                return true;

        n = recv(c->fd, c->reply, sizeof(c->reply) - 1, MSG_DONTWAIT);
        if (n >= 0) {
                c->reply[n] = '\0';
                c->reply_len = n;
                return true;
        }
        if (errno != EAGAIN) {
                c->reply_len = -2;
                return true;
        }
        return false;
}

/* Connect, send `request` verbatim (no trailing newline -- SOCK_SEQPACKET
 * preserves the message boundary, matching picoctl.c's own client), drive
 * the real loop until a reply arrives, assert it equals `want_reply`
 * exactly, close. */
static void ctrl_roundtrip_assert(
                Manager *m, const char *rt, const char *request, const char *want_reply, int max_ticks) {
        struct ctrl_client c;

        ctrl_client_connect(&c, rt);
        ctrl_client_send_str(&c, request);

        ASSERT_TRUE(drive_until(m, ctrl_client_recv_done, &c, max_ticks));
        ASSERT_TRUE(c.reply_len >= 0);
        ASSERT_STREQ(c.reply, want_reply);

        ctrl_client_close(&c);
}

static bool ctrl_no_leaks_done(void *userdata) {
        Manager *m = userdata;

        return manager_ctrl_debug_n_conns(m) == 0 && manager_ctrl_debug_n_pending(m) == 0;
}

static bool ctrl_unit_active_done(void *userdata) {
        Unit *u = userdata;

        return unit_active_state(u) == UNIT_ACTIVE;
}

struct ctrl_two_clients {
        struct ctrl_client *a, *b;
};

static bool ctrl_two_clients_done(void *userdata) {
        struct ctrl_two_clients *tc = userdata;
        bool da = ctrl_client_recv_done(tc->a);
        bool db = ctrl_client_recv_done(tc->b);

        return da && db;
}

static const char *basename_of(const char *path) {
        const char *slash = strrchr(path, '/');

        return slash ? slash + 1 : path;
}

/* --- fixture plumbing --- */

/*
 * A pid-tagged real cgroup path, matching test-picoctl.c's own use_private_
 * cgroup_root() exactly (duplicated rather than shared, same reasoning as
 * that file's own comment): real cgroup v2 control files only exist under
 * an actual cgroupfs mount, so this cannot be relocated under a --root-style
 * fixture tree the way /etc and /run are, and the pid tag is what keeps two
 * test binaries booting a same-named unit from colliding when `meson test`
 * runs them concurrently.
 */
static void use_private_cgroup_root(Manager *m, char *out, size_t out_size) {
        int n = snprintf(out, out_size, "/sys/fs/cgroup/pico-ctrl-test-%lld", (long long) getpid());

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

struct ctrl_fixture {
        char *unitdir;
        char *rtdir;
        char cgroup_root[PATH_MAX];
        Manager *m;
};

/* default.target is boilerplate manager_startup() requires to succeed at
 * all (it is the boot transaction's root); nothing in these tests cares
 * about its own state. */
static void ctrl_fixture_setup(struct ctrl_fixture *f) {
        f->unitdir = test_tmpdir_new();
        f->rtdir = test_tmpdir_new();
        ASSERT_TRUE(f->unitdir != NULL && f->rtdir != NULL);

        ASSERT_EQ_INT(test_write_file(f->unitdir, "default.target", "[Unit]\nDescription=Default\n"), 0);

        ASSERT_EQ_INT(manager_new(&f->m), 0);
        {
                const char * const up[] = { f->unitdir, NULL };
                const char * const pd[] = { NULL };

                ASSERT_EQ_INT(manager_set_unit_path(f->m, up), 0);
                ASSERT_EQ_INT(manager_set_preset_path(f->m, pd), 0);
        }
        ASSERT_EQ_INT(manager_set_runtime_dir(f->m, f->rtdir), 0);
        use_private_cgroup_root(f->m, f->cgroup_root, sizeof(f->cgroup_root));
}

/* Called after ctrl_fixture_setup() and after any extra unit fragments have
 * been written into f->unitdir -- manager_startup() is what actually loads
 * them and binds the control socket. */
static void ctrl_fixture_boot(struct ctrl_fixture *f) {
        ASSERT_EQ_INT(manager_startup(f->m, NULL), 0);
}

static void ctrl_fixture_teardown(struct ctrl_fixture *f) {
        ASSERT_EQ_INT(manager_ctrl_debug_n_conns(f->m), 0);
        ASSERT_EQ_INT(manager_ctrl_debug_n_pending(f->m), 0);

        manager_free(f->m);
        free_private_cgroup_root(f->cgroup_root);
        test_rm_rf(f->unitdir);
        test_rm_rf(f->rtdir);
        free(f->unitdir);
        free(f->rtdir);
}

/* --- tests --- */

/*
 * The core acceptance case, and the one the plan explicitly warns not to
 * shortcut: every verb driven against BOTH an active and an inactive unit,
 * because a recent real bug in the job engine survived exactly because a
 * test covered only the combination that obviously worked. None of the six
 * combinations is special-cased in manager-ctrl.c -- job.c's own fixes are
 * what make all six terminate correctly, and this is what proves it end to
 * end through the socket rather than at job.c's own internal API.
 */
static void test_start_stop_restart_active_and_inactive(void) {
        struct ctrl_fixture f;
        Unit *u;
        Service *s;
        pid_t pid_before;

        ctrl_fixture_setup(&f);
        ASSERT_EQ_INT(test_write_file(f.unitdir,
                                      "demo.service",
                                      "[Unit]\n[Service]\nType=simple\nExecStart=/bin/sleep 300\n"),
                      0);
        ctrl_fixture_boot(&f);

        u = manager_get_unit(f.m, "demo.service");
        ASSERT_TRUE(u != NULL);
        s = SERVICE(u);
        ASSERT_EQ_INT(unit_active_state(u), UNIT_INACTIVE);

        /* start: inactive -> active */
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 start demo.service", "ok done\n", 400);
        ASSERT_EQ_INT(unit_active_state(u), UNIT_ACTIVE);

        /* start: already active -- the redundant-anchor fix, not a hang */
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 start demo.service", "ok done\n", 400);
        ASSERT_EQ_INT(unit_active_state(u), UNIT_ACTIVE);

        /* restart: active -- genuinely cycles the process, not a no-op */
        pid_before = s->main_pid;
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 restart demo.service", "ok done\n", 800);
        ASSERT_EQ_INT(unit_active_state(u), UNIT_ACTIVE);
        ASSERT_TRUE(s->main_pid > 0 && s->main_pid != pid_before);

        /* stop: active -> inactive */
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 stop demo.service", "ok done\n", 800);
        ASSERT_EQ_INT(unit_active_state(u), UNIT_INACTIVE);

        /* stop: already inactive -- the other redundant-anchor fix */
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 stop demo.service", "ok done\n", 400);
        ASSERT_EQ_INT(unit_active_state(u), UNIT_INACTIVE);

        /* restart: inactive -- the stop half is a no-op, the conversion to
         * a start must still happen (JOB_RESTART's own fixed bug) */
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 restart demo.service", "ok done\n", 800);
        ASSERT_EQ_INT(unit_active_state(u), UNIT_ACTIVE);

        /* leave it stopped before tearing the manager down */
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 stop demo.service", "ok done\n", 800);

        ctrl_fixture_teardown(&f);
}

/*
 * A start whose ExecStart= cannot even exec must reply with the real job
 * result, not "ok" -- and the unit must actually be FAILED, not merely
 * "not active".
 *
 * Type=oneshot, deliberately, not simple: Type=simple counts as started the
 * moment fork() returns (service.h's own header says so), which happens
 * before the child's execve() can fail -- so a Type=simple start against a
 * nonexistent ExecStart= genuinely replies "ok done" and only fails
 * asynchronously afterward, with no job left in flight to notify. That was
 * this test's own first draft and it failed for exactly that reason, caught
 * by running it rather than by reasoning about it. Type=oneshot only
 * completes its start job once the process exits, so the exec failure is
 * still synchronous with the job here.
 */
static void test_start_failing_unit_replies_with_real_result(void) {
        struct ctrl_fixture f;
        Unit *u;

        ctrl_fixture_setup(&f);
        ASSERT_EQ_INT(test_write_file(f.unitdir,
                                      "broken.service",
                                      "[Unit]\n[Service]\nType=oneshot\n"
                                      "ExecStart=/nonexistent/does-not-exist\n"),
                      0);
        ctrl_fixture_boot(&f);

        u = manager_get_unit(f.m, "broken.service");
        ASSERT_TRUE(u != NULL);

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 start broken.service", "err failed\n", 400);
        ASSERT_EQ_INT(unit_active_state(u), UNIT_FAILED);

        ctrl_fixture_teardown(&f);
}

/* A unit whose Requires= dependency fails to start finishes its own job as
 * "dependency", not "failed": upstream's JOB_DEPENDENCY, which picoctl turns
 * into "A dependency job for X failed." */
static void test_start_with_failed_dependency_replies_dependency(void) {
        struct ctrl_fixture f;

        ctrl_fixture_setup(&f);
        ASSERT_EQ_INT(test_write_file(f.unitdir,
                                      "broken.service",
                                      "[Unit]\n[Service]\nType=oneshot\n"
                                      "ExecStart=/nonexistent/does-not-exist\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(f.unitdir,
                                      "needs-broken.service",
                                      "[Unit]\nRequires=broken.service\nAfter=broken.service\n"
                                      "[Service]\nType=oneshot\nExecStart=/bin/true\n"),
                      0);
        ctrl_fixture_boot(&f);

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 start needs-broken.service", "err dependency\n", 400);

        ctrl_fixture_teardown(&f);
}

/* A successful Type=oneshot without RemainAfterExit= ends INACTIVE, never
 * ACTIVE; the deferred reply must still arrive, as "ok done". */
static void test_start_oneshot_replies_done(void) {
        struct ctrl_fixture f;
        Unit *u;

        ctrl_fixture_setup(&f);
        ASSERT_EQ_INT(test_write_file(f.unitdir,
                                      "oneshot.service",
                                      "[Unit]\n[Service]\nType=oneshot\nExecStart=/bin/true\n"),
                      0);
        ctrl_fixture_boot(&f);

        u = manager_get_unit(f.m, "oneshot.service");
        ASSERT_TRUE(u != NULL);

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 start oneshot.service", "ok done\n", 400);
        ASSERT_EQ_INT(unit_active_state(u), UNIT_INACTIVE);
        ASSERT_TRUE(u->job == NULL);

        ctrl_fixture_teardown(&f);
}

static bool ctrl_service_state_done(void *userdata) {
        void **args = userdata;

        return SERVICE((Unit *) args[0])->state == *(ServiceState *) args[1];
}

static void drive_until_service_state(Manager *m, Unit *u, ServiceState state) {
        void *args[2] = { u, &state };

        ASSERT_TRUE(drive_until(m, ctrl_service_state_done, args, 400));
}

/*
 * Stop and restart of a unit whose stop ends in FAILED -- a running oneshot
 * killed by SIGTERM, a unit waiting out RestartSec= after a crash. The unit
 * is down either way, so both jobs are done (v30 unit_notify()); failing them
 * replied "err failed" and left a restart never starting the unit again.
 */
static void test_stop_and_restart_ending_failed_reply_done(void) {
        struct ctrl_fixture f;
        Unit *oneshot, *crashy;

        ctrl_fixture_setup(&f);
        ASSERT_EQ_INT(test_write_file(f.unitdir,
                                      "long-oneshot.service",
                                      "[Unit]\n[Service]\nType=oneshot\nExecStart=/bin/sleep 30\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(f.unitdir,
                                      "crashy.service",
                                      "[Unit]\n[Service]\nType=simple\nExecStart=/bin/false\n"
                                      "Restart=on-failure\nRestartSec=10\n"),
                      0);
        ctrl_fixture_boot(&f);

        oneshot = manager_get_unit(f.m, "long-oneshot.service");
        crashy = manager_get_unit(f.m, "crashy.service");
        ASSERT_TRUE(oneshot != NULL && crashy != NULL);

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 start long-oneshot.service --no-block", "ok queued\n", 100);
        drive_until_service_state(f.m, oneshot, SERVICE_EXEC_START);
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 stop long-oneshot.service", "ok done\n", 400);
        ASSERT_EQ_INT(unit_active_state(oneshot), UNIT_FAILED);

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 start crashy.service", "ok done\n", 400);
        drive_until_service_state(f.m, crashy, SERVICE_AUTO_RESTART);
        ASSERT_EQ_INT(SERVICE(crashy)->n_restarts, 1);
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 restart crashy.service", "ok done\n", 400);

        /* started again, so it crashed again */
        drive_until_service_state(f.m, crashy, SERVICE_AUTO_RESTART);
        ASSERT_EQ_INT(SERVICE(crashy)->n_restarts, 2);
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 stop crashy.service", "ok done\n", 400);

        ctrl_fixture_teardown(&f);
}

/*
 * A start that arrives while the service is still stopping waits for the stop
 * to finish and then starts it (v30 job_run_and_invalidate() on -EAGAIN),
 * rather than failing because service_start() said "not yet".
 */
static void test_start_while_stopping_waits(void) {
        struct ctrl_fixture f;
        char unit[PATH_MAX + 64];
        Unit *u;
        pid_t old_pid;

        ctrl_fixture_setup(&f);
        ASSERT_EQ_INT(test_write_file(f.unitdir,
                                      "slow-term.sh",
                                      "trap 'sleep 0.3; exit 0' TERM\nwhile :; do sleep 0.1; done\n"),
                      0);
        snprintf(unit, sizeof(unit), "[Service]\nType=simple\nExecStart=/bin/sh %s/slow-term.sh\n", f.unitdir);
        ASSERT_EQ_INT(test_write_file(f.unitdir, "slow.service", unit), 0);
        ctrl_fixture_boot(&f);

        u = manager_get_unit(f.m, "slow.service");
        ASSERT_TRUE(u != NULL);

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 start slow.service", "ok done\n", 400);
        old_pid = SERVICE(u)->main_pid;
        usleep(200 * 1000); /* let the shell install its trap */

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 stop slow.service --no-block", "ok queued\n", 100);
        drive_until_service_state(f.m, u, SERVICE_STOP);

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 start slow.service", "ok done\n", 400);
        ASSERT_EQ_INT(unit_active_state(u), UNIT_ACTIVE);
        ASSERT_TRUE(SERVICE(u)->main_pid > 0 && SERVICE(u)->main_pid != old_pid);

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 stop slow.service", "ok done\n", 400);
        ctrl_fixture_teardown(&f);
}

/* Once a shutdown is pending, nothing new may be started behind its back;
 * stop still works. */
static void test_start_refused_while_shutting_down(void) {
        struct ctrl_fixture f;
        Unit *u, *hold;

        ctrl_fixture_setup(&f);
        ASSERT_EQ_INT(test_write_file(f.unitdir,
                                      "demo.service",
                                      "[Unit]\n[Service]\nType=simple\nExecStart=/bin/sleep 300\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(f.unitdir,
                                      "hold.service",
                                      "[Unit]\n[Service]\nType=oneshot\nExecStart=/bin/sleep 30\n"),
                      0);
        ctrl_fixture_boot(&f);

        u = manager_get_unit(f.m, "demo.service");
        hold = manager_get_unit(f.m, "hold.service");
        ASSERT_TRUE(u != NULL && hold != NULL);

        /* A start job that stays RUNNING, and a far deadline, keep the loop
         * from adopting the pending objective while requests are sent. */
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 start hold.service --no-block", "ok queued\n", 100);
        drive_until_service_state(f.m, hold, SERVICE_EXEC_START);
        f.m->pending_objective = MANAGER_POWEROFF;
        f.m->shutdown_deadline = now_monotonic() + 60 * USEC_PER_SEC;

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 start demo.service", "err shutting-down\n", 100);
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 restart demo.service", "err shutting-down\n", 100);
        ASSERT_EQ_INT(unit_active_state(u), UNIT_INACTIVE);
        ASSERT_TRUE(u->job == NULL);
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 stop demo.service", "ok done\n", 100);
        ASSERT_EQ_INT(f.m->objective, MANAGER_EXIT); /* stopped by the driver, not adopted */

        f.m->pending_objective = MANAGER_RUNNING;
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 stop hold.service", "ok done\n", 400);
        ctrl_fixture_teardown(&f);
}

/* reset-failed: a FAILED unit returns to inactive; an already-non-FAILED
 * unit is a harmless no-op success (real systemctl's own behaviour); an
 * unknown unit is a real error, not a silent no-op. */
static void test_reset_failed(void) {
        struct ctrl_fixture f;
        Unit *u;
        Service *s;

        ctrl_fixture_setup(&f);
        /* Type=oneshot -- see test_start_failing_unit_replies_with_real_result()'s
         * header for why Type=simple would not reach FAILED synchronously
         * with the job here. */
        ASSERT_EQ_INT(test_write_file(f.unitdir,
                                      "broken.service",
                                      "[Unit]\n[Service]\nType=oneshot\n"
                                      "ExecStart=/nonexistent/does-not-exist\n"),
                      0);
        ctrl_fixture_boot(&f);

        u = manager_get_unit(f.m, "broken.service");
        s = SERVICE(u);

        /* no-op on a unit that has never failed */
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 reset-failed broken.service", "ok\n", 100);
        ASSERT_EQ_INT(unit_active_state(u), UNIT_INACTIVE);

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 start broken.service", "err failed\n", 400);
        ASSERT_EQ_INT(unit_active_state(u), UNIT_FAILED);

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 reset-failed broken.service", "ok\n", 100);
        ASSERT_EQ_INT(unit_active_state(u), UNIT_INACTIVE);
        ASSERT_EQ_INT(s->result, SERVICE_SUCCESS);

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 reset-failed typo.service", "err no-such-unit\n", 100);

        ctrl_fixture_teardown(&f);
}

/*
 * daemon-reload (manager-ctrl.c's own addition for the picoctl verb):
 * synchronous, no unit token, and -- the actual point of this test --
 * drives manager_reload()'s full-rescan extension (unit-reload.c) through
 * the real wire, not just unit-reload.c's own in-process test: a unit file
 * dropped in after boot, plus a .wants/ symlink naming it, both take effect
 * from one "PICO1 daemon-reload" round trip.
 */
static void test_daemon_reload(void) {
        struct ctrl_fixture f;

        ctrl_fixture_setup(&f);
        ctrl_fixture_boot(&f);

        ASSERT_TRUE(manager_get_unit(f.m, "newcomer.service") == NULL);

        ASSERT_EQ_INT(test_write_file(f.unitdir, "newcomer.service", "[Service]\nExecStart=/bin/true\n"), 0);
        ASSERT_EQ_INT(test_mkdir(f.unitdir, "default.target.wants"), 0);
        ASSERT_EQ_INT(test_symlink(f.unitdir, "default.target.wants/newcomer.service", "../newcomer.service"),
                      0);

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 daemon-reload", "ok\n", 100);

        {
                Unit *newcomer = manager_get_unit(f.m, "newcomer.service");
                Unit *target = manager_get_unit(f.m, "default.target");

                ASSERT_TRUE(newcomer != NULL);
                ASSERT_EQ_INT(newcomer->load_state, UNIT_LOADED);
                ASSERT_TRUE(target != NULL);
                ASSERT_TRUE(unit_has_dependency(target, UNIT_WANTS, newcomer));
                /* Known and enabled, but never started -- a daemon-reload
                 * makes a unit startable, it does not start it. */
                ASSERT_EQ_INT(unit_active_state(newcomer), UNIT_INACTIVE);
        }

        /* A grammar daemon-reload never carries -- there is no unit to
         * name, so a stray token after the verb is simply malformed. */
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 daemon-reload extra.service", "err malformed\n", 100);

        ctrl_fixture_teardown(&f);
}

/* --no-block replies the instant the job is enqueued, distinguishably from
 * the blocking path's "ok done" -- proving this is not just a fast blocking
 * reply is exactly why the two use different reply text. */
static void test_no_block_replies_immediately(void) {
        struct ctrl_fixture f;
        Unit *u;

        ctrl_fixture_setup(&f);
        ASSERT_EQ_INT(test_write_file(f.unitdir,
                                      "demo.service",
                                      "[Unit]\n[Service]\nType=simple\nExecStart=/bin/sleep 300\n"),
                      0);
        ctrl_fixture_boot(&f);

        u = manager_get_unit(f.m, "demo.service");

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 start demo.service --no-block", "ok queued\n", 400);

        /* the job still really runs -- --no-block skips the wait, not the work */
        ASSERT_TRUE(drive_until(f.m, ctrl_unit_active_done, u, 400));
        ASSERT_EQ_INT(unit_active_state(u), UNIT_ACTIVE);

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 stop demo.service", "ok done\n", 800);
        ctrl_fixture_teardown(&f);
}

static void test_early_disconnect_leaks_nothing(void) {
        struct ctrl_fixture f;
        struct ctrl_client c;
        Unit *u;

        ctrl_fixture_setup(&f);
        ASSERT_EQ_INT(test_write_file(f.unitdir,
                                      "demo.service",
                                      "[Unit]\n[Service]\nType=simple\nExecStart=/bin/sleep 300\n"),
                      0);
        ctrl_fixture_boot(&f);
        u = manager_get_unit(f.m, "demo.service");

        ctrl_client_connect(&c, f.rtdir);
        ctrl_client_send_str(&c, "PICO1 start demo.service");
        ctrl_client_close(&c); /* never reads the reply */

        /* Measured, not assumed: drive until the tracked connection/pending
         * counts both genuinely reach zero (or the budget runs out, which
         * ASSERT_TRUE below turns into a hard failure), rather than merely
         * asserting the job's own happy path. */
        ASSERT_TRUE(drive_until(f.m, ctrl_no_leaks_done, f.m, 400));
        ASSERT_EQ_INT(manager_ctrl_debug_n_conns(f.m), 0);
        ASSERT_EQ_INT(manager_ctrl_debug_n_pending(f.m), 0);

        /* the job was never cancelled by the disconnect -- it ran to completion */
        ASSERT_EQ_INT(unit_active_state(u), UNIT_ACTIVE);

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 stop demo.service", "ok done\n", 800);
        ctrl_fixture_teardown(&f);
}

/* Two start requests for the same unit, both queued before the loop ever
 * runs, so both get installed as jobs within the same manager_loop() pass:
 * job_install()'s displacement path finishes the loser as JOB_CANCELED,
 * which must map to an honest "err canceled" reply, never "ok". */
static void test_displaced_job_gets_canceled_reply(void) {
        struct ctrl_fixture f;
        struct ctrl_client c1, c2;
        struct ctrl_two_clients tc;
        int n_canceled;
        const char *winner;

        ctrl_fixture_setup(&f);
        ASSERT_EQ_INT(test_write_file(f.unitdir,
                                      "demo.service",
                                      "[Unit]\n[Service]\nType=simple\nExecStart=/bin/sleep 300\n"),
                      0);
        ctrl_fixture_boot(&f);

        ctrl_client_connect(&c1, f.rtdir);
        ctrl_client_send_str(&c1, "PICO1 start demo.service");
        ctrl_client_connect(&c2, f.rtdir);
        ctrl_client_send_str(&c2, "PICO1 start demo.service");

        /* both requests are already queued in the kernel before the loop
         * ever runs, so both get installed as jobs on the SAME unit within
         * the same manager_loop() pass -- job_install()'s displacement path
         * cancels whichever loses the race. */
        tc.a = &c1;
        tc.b = &c2;
        ASSERT_TRUE(drive_until(f.m, ctrl_two_clients_done, &tc, 400));

        ASSERT_TRUE(c1.reply_len >= 0 && c2.reply_len >= 0);

        n_canceled = (strcmp(c1.reply, "err canceled\n") == 0) + (strcmp(c2.reply, "err canceled\n") == 0);
        ASSERT_EQ_INT(n_canceled, 1);

        winner = strcmp(c1.reply, "err canceled\n") == 0 ? c2.reply : c1.reply;
        ASSERT_STREQ(winner, "ok done\n");

        ctrl_client_close(&c1);
        ctrl_client_close(&c2);

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 stop demo.service", "ok done\n", 800);
        ctrl_fixture_teardown(&f);
}

/* Every rejection reachable without a real unit, plus the two that do need
 * one (bad-unit, no-such-unit) -- each checked to leave nothing tracked
 * behind, and none of it via a code path that allocates from the bytes
 * themselves (manager-ctrl.c's own PICO_CTRL_LINE_MAX/MSG_TRUNC handling). */
static void test_malformed_requests_rejected_without_allocating(void) {
        struct ctrl_fixture f;
        struct ctrl_client c;

        ctrl_fixture_setup(&f);
        ASSERT_EQ_INT(test_write_file(f.unitdir,
                                      "demo.service",
                                      "[Unit]\n[Service]\nType=simple\nExecStart=/bin/sleep 300\n"),
                      0);
        ctrl_fixture_boot(&f);

        ctrl_roundtrip_assert(f.m, f.rtdir, "HELLO start demo.service", "err bad-magic\n", 100);
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 frobnicate demo.service", "err unknown-verb\n", 100);
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 start", "err missing-unit\n", 100);
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 start ../evil.service", "err bad-unit\n", 100);
        ctrl_roundtrip_assert(
                        f.m, f.rtdir, "PICO1 start demo.service --no-block extra", "err malformed\n", 100);
        ctrl_roundtrip_assert(
                        f.m, f.rtdir, "PICO1 reset-failed demo.service --no-block", "err malformed\n", 100);
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 start typo.service", "err no-such-unit\n", 100);

        /* oversized: a single message whose real length (reported via
         * MSG_TRUNC even though only PICO_CTRL_LINE_MAX bytes were copied)
         * exceeds the fixed buffer -- rejected without ever allocating or
         * even fully reading the request. */
        {
                char big[700];

                memset(big, 'a', sizeof(big));
                memcpy(big, "PICO1 start ", 12);

                ctrl_client_connect(&c, f.rtdir);
                ctrl_client_send(&c, big, sizeof(big));
                ASSERT_TRUE(drive_until(f.m, ctrl_client_recv_done, &c, 100));
                ASSERT_TRUE(c.reply_len >= 0);
                ASSERT_STREQ(c.reply, "err too-long\n");
                ctrl_client_close(&c);
        }

        /* embedded NUL mid-message */
        {
                char buf[24];
                size_t n = 0;

                memcpy(buf, "PICO1 start ", 12);
                n = 12;
                buf[n++] = 'x';
                buf[n++] = '\0';
                buf[n++] = 'y';

                ctrl_client_connect(&c, f.rtdir);
                ctrl_client_send(&c, buf, n);
                ASSERT_TRUE(drive_until(f.m, ctrl_client_recv_done, &c, 100));
                ASSERT_TRUE(c.reply_len >= 0);
                ASSERT_STREQ(c.reply, "err embedded-nul\n");
                ctrl_client_close(&c);
        }

        /* a connection closed without ever sending anything: the server
         * must drop it cleanly, never wait on it forever */
        {
                ctrl_client_connect(&c, f.rtdir);
                ctrl_client_close(&c);
                ASSERT_TRUE(drive_until(f.m, ctrl_no_leaks_done, f.m, 100));
        }

        ASSERT_EQ_INT(manager_ctrl_debug_n_conns(f.m), 0);
        ASSERT_EQ_INT(manager_ctrl_debug_n_pending(f.m), 0);

        ctrl_fixture_teardown(&f);
}

/*
 * G2: the ctrl-side instancing fallback. Every case here needs a template
 * (foo@.service) in the fixture tree so req.unit can name an instance
 * nothing ever shipped a fragment for -- exactly the "picoctl start
 * serial-getty@ttyUSB0.service" shape manager-ctrl.c's own header comment
 * on the fallback describes.
 */

static void ctrl_fixture_write_template(struct ctrl_fixture *f) {
        ASSERT_EQ_INT(test_write_file(f->unitdir, "foo@.service", "[Service]\nExecStart=/bin/sleep 300\n"), 0);
}

/* The headline capability: a unit never in the table at all, loaded and
 * started in one round trip. */
static void test_start_loads_an_uninstantiated_template(void) {
        struct ctrl_fixture f;
        Unit *u;

        ctrl_fixture_setup(&f);
        ctrl_fixture_write_template(&f);
        ctrl_fixture_boot(&f);

        ASSERT_TRUE(manager_get_unit(f.m, "foo@ttyUSB0.service") == NULL);

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 start foo@ttyUSB0.service", "ok done\n", 400);

        u = manager_get_unit(f.m, "foo@ttyUSB0.service");
        ASSERT_TRUE(u != NULL);
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(u->instance, "ttyUSB0");
        ASSERT_STREQ(basename_of(u->fragment_path), "foo@.service");
        ASSERT_EQ_INT(unit_active_state(u), UNIT_ACTIVE);

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 stop foo@ttyUSB0.service", "ok done\n", 800);
        ctrl_fixture_teardown(&f);
}

static void test_restart_also_falls_back(void) {
        struct ctrl_fixture f;
        Unit *u;

        ctrl_fixture_setup(&f);
        ctrl_fixture_write_template(&f);
        ctrl_fixture_boot(&f);

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 restart foo@ttyUSB1.service", "ok done\n", 400);

        u = manager_get_unit(f.m, "foo@ttyUSB1.service");
        ASSERT_TRUE(u != NULL);
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_EQ_INT(unit_active_state(u), UNIT_ACTIVE);

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 stop foo@ttyUSB1.service", "ok done\n", 800);
        ctrl_fixture_teardown(&f);
}

/* The deliberate asymmetry: stopping or resetting a unit that was never
 * running must stay a plain lookup miss, never an implicit load -- checked
 * on both the wire reply and the table, since a silent table growth on
 * every stop of a typo'd name would be invisible from the reply alone. */
static void test_stop_does_not_fall_back(void) {
        struct ctrl_fixture f;
        size_t n_before;

        ctrl_fixture_setup(&f);
        ctrl_fixture_write_template(&f);
        ctrl_fixture_boot(&f);

        n_before = f.m->n_units;
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 stop foo@ttyUSB2.service", "err no-such-unit\n", 100);
        ASSERT_EQ_INT((long long) f.m->n_units, (long long) n_before);

        ctrl_fixture_teardown(&f);
}

static void test_reset_failed_does_not_fall_back(void) {
        struct ctrl_fixture f;
        size_t n_before;

        ctrl_fixture_setup(&f);
        ctrl_fixture_write_template(&f);
        ctrl_fixture_boot(&f);

        n_before = f.m->n_units;
        ctrl_roundtrip_assert(
                        f.m, f.rtdir, "PICO1 reset-failed foo@ttyUSB3.service", "err no-such-unit\n", 100);
        ASSERT_EQ_INT((long long) f.m->n_units, (long long) n_before);

        ctrl_fixture_teardown(&f);
}

/* The manager_remove_unit() test: without it, a start against a name that
 * genuinely does not exist (no literal file, no template) would leave a
 * permanent UNIT_ERROR node behind on every single miss. */
static void test_start_unknown_name_leaves_no_junk_unit(void) {
        struct ctrl_fixture f;
        size_t n_before;

        ctrl_fixture_setup(&f);
        ctrl_fixture_boot(&f); /* no template in this tree at all */

        n_before = f.m->n_units;
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 start nope.service", "err no-such-unit\n", 100);
        ASSERT_EQ_INT((long long) f.m->n_units, (long long) n_before);
        ASSERT_TRUE(manager_get_unit(f.m, "nope.service") == NULL);

        ctrl_fixture_teardown(&f);
}

static bool unit_in_table(Manager *m, Unit *u) {
        size_t i;

        for (i = 0; i < m->n_units; i++)
                if (m->units[i] == u)
                        return true;

        return false;
}

/*
 * A fragment added after boot that parses but fails validation (here: no
 * ExecStart=) still had its After= applied while it was parsed, and that
 * wrote the inverse Before= edge into default.target. Freeing the unit left
 * default.target pointing at freed memory; every later job on it read it.
 */
static void test_start_invalid_unit_leaves_no_dangling_edge(void) {
        struct ctrl_fixture f;
        Unit *target;
        size_t i;

        ctrl_fixture_setup(&f);
        ctrl_fixture_boot(&f);

        target = manager_get_unit(f.m, "default.target");
        ASSERT_TRUE(target != NULL);

        ASSERT_EQ_INT(test_write_file(f.unitdir,
                                      "new.service",
                                      "[Unit]\nAfter=default.target\n[Service]\nType=simple\n"),
                      0);

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 start new.service", "err no-such-unit\n", 100);

        for (i = 0; i < target->n_dependencies[UNIT_BEFORE]; i++)
                ASSERT_TRUE(unit_in_table(f.m, target->dependencies[UNIT_BEFORE][i]));

        /* a job on the peer walks its Before= neighbours when it finishes */
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 restart default.target", "ok done\n", 400);

        ctrl_fixture_teardown(&f);
}

/*
 * Trigger B from units-ctrl-remove-partial-unit-uaf: since bf41120,
 * manager_load_unit() resolves an unseen name as an alias and hands back an
 * *existing* unit -- which can be a boot-time UNIT_ERROR unit with incoming
 * Wants= from a target, not one this ctrl call created at all. The generic
 * "only remove while nothing has an edge to it" check above must catch this
 * the same way it catches a freshly-parsed-and-failed fragment.
 */
static void test_start_alias_to_referenced_error_unit_leaves_no_dangling_edge(void) {
        struct ctrl_fixture f;
        Unit *target;
        size_t i;

        ctrl_fixture_setup(&f);

        /* Overwrites ctrl_fixture_setup()'s own boilerplate default.target:
         * broken.service has no ExecStart=, so it fails validation into
         * UNIT_ERROR while default.target's own parse is still what adds
         * the Wants= edge onto it (manager_load_unit() succeeds
         * structurally even though the unit it loads does not). */
        ASSERT_EQ_INT(test_write_file(f.unitdir,
                                      "default.target",
                                      "[Unit]\nDescription=Default\nWants=broken.service\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(f.unitdir, "broken.service", "[Unit]\n[Service]\nType=simple\n"), 0);

        ctrl_fixture_boot(&f);

        target = manager_get_unit(f.m, "default.target");
        ASSERT_TRUE(target != NULL);
        ASSERT_TRUE(manager_get_unit(f.m, "broken.service") != NULL);
        ASSERT_EQ_INT(manager_get_unit(f.m, "broken.service")->load_state, UNIT_ERROR);
        ASSERT_TRUE(unit_has_dependency(target, UNIT_WANTS, manager_get_unit(f.m, "broken.service")));

        /* An alias created after boot, resolving to the already-loaded,
         * already-referenced broken.service -- never a node this ctrl call
         * itself created. */
        ASSERT_EQ_INT(test_symlink(f.unitdir, "alias.service", "broken.service"), 0);

        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 start alias.service", "err no-such-unit\n", 100);

        for (i = 0; i < target->n_dependencies[UNIT_WANTS]; i++)
                ASSERT_TRUE(unit_in_table(f.m, target->dependencies[UNIT_WANTS][i]));

        /* a job on default.target walks its Wants= neighbours when it starts */
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 restart default.target", "ok done\n", 400);

        ctrl_fixture_teardown(&f);
}

/* A template id is rejected by manager_load_unit() itself before the
 * fallback ever gets a fragment to find -- covered here as the ctrl-visible
 * consequence, not a retest of manager.c's own rejection. */
static void test_start_template_is_refused(void) {
        struct ctrl_fixture f;
        size_t n_before;

        ctrl_fixture_setup(&f);
        ctrl_fixture_write_template(&f);
        ctrl_fixture_boot(&f);

        n_before = f.m->n_units;
        ctrl_roundtrip_assert(f.m, f.rtdir, "PICO1 start foo@.service", "err no-such-unit\n", 100);
        ASSERT_EQ_INT((long long) f.m->n_units, (long long) n_before);

        ctrl_fixture_teardown(&f);
}

int main(void) {
        test_start_stop_restart_active_and_inactive();
        test_start_failing_unit_replies_with_real_result();
        test_start_with_failed_dependency_replies_dependency();
        test_start_oneshot_replies_done();
        test_stop_and_restart_ending_failed_reply_done();
        test_start_while_stopping_waits();
        test_start_refused_while_shutting_down();
        test_reset_failed();
        test_daemon_reload();
        test_no_block_replies_immediately();
        test_early_disconnect_leaks_nothing();
        test_displaced_job_gets_canceled_reply();
        test_malformed_requests_rejected_without_allocating();

        test_start_loads_an_uninstantiated_template();
        test_restart_also_falls_back();
        test_stop_does_not_fall_back();
        test_reset_failed_does_not_fall_back();
        test_start_unknown_name_leaves_no_junk_unit();
        test_start_invalid_unit_leaves_no_dangling_edge();
        test_start_alias_to_referenced_error_unit_leaves_no_dangling_edge();
        test_start_template_is_refused();

        printf("test-manager-ctrl: all checks passed\n");
        return 0;
}
