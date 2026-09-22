/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * M3's acceptance test: a lifecycle test walks every state, a timeout
 * produces FAILED, and a crash triggers auto-restart -- plus the two
 * regressions this milestone's own quarrying review flagged by name (B2's
 * signal-amnesty asymmetry, B7's start-rate limiting) and one bug this
 * review found on its own (see test_bug_running_timer_not_cancelled()).
 *
 * Real fork()/execve() is used throughout -- these are not mocked processes.
 * Reaping goes through the manager's own signalfd (pico_signal_fd()) rather
 * than a raw waitpid() poll loop, so this exercises the real SIGCHLD path
 * service_sigchld_event() expects, just without depending on
 * manager-loop.c's (separately owned, in-flight) epoll dispatch of it.
 *
 * cgroup v2 operations are opportunistic: service_ensure_cgroup() in
 * service.c is designed to degrade gracefully (s->cgroup stays NULL) when
 * the process lacks privilege to create one, which is expected running as a
 * normal user in a container rather than as PID 1. Where this test can say
 * something extra when a cgroup is available, it does; nothing here is
 * skipped outright (exit 77) because none of the required assertions
 * actually depend on cgroups being writable.
 */

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "job.h"
#include "manager-notify.h"
#include "manager.h"
#include "service.h"
#include "test-util.h"
#include "timer.h"
#include "unit.h"
#include "util.h"

static void test_sleep_ms(int ms) {
        struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (long) (ms % 1000) * 1000000L };

        nanosleep(&ts, NULL);
}

/* --- manager_loop() driver, test-manager-notify.c's own --- */

/*
 * The Type=exec/notify tests below need the real loop: the exec fd and the
 * notify socket are sd_event io sources, and reap_for()'s hand-driven
 * signalfd would bypass exactly the dispatch order those tests are about.
 */
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

static bool service_running_done(void *userdata) {
        return ((Service *) userdata)->state == SERVICE_RUNNING;
}

static bool service_settled_done(void *userdata) {
        Service *s = userdata;

        return s->state == SERVICE_DEAD || s->state == SERVICE_FAILED;
}

/* test-notify-helper, built next to this binary (test-picoctl.c's idiom). */
static void notify_helper_path(char *out, size_t out_size) {
        char self[PATH_MAX];
        ssize_t n;
        char *slash;

        n = readlink("/proc/self/exe", self, sizeof(self) - 1);
        ASSERT_TRUE(n > 0);
        self[n] = '\0';
        slash = strrchr(self, '/');
        ASSERT_TRUE(slash != NULL);
        *slash = '\0';

        n = snprintf(out, out_size, "%s/test-notify-helper", self);
        ASSERT_TRUE(n > 0 && (size_t) n < out_size);
        ASSERT_EQ_INT(access(out, X_OK), 0);
}

static Manager *manager_for(const char *dir) {
        const char * const path[] = { dir, NULL };
        Manager *m = NULL;

        ASSERT_EQ_INT(manager_new(&m), 0);
        ASSERT_TRUE(m != NULL);
        ASSERT_EQ_INT(manager_set_unit_path(m, path), 0);

        return m;
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

/*
 * Waits for SIGCHLD via the manager's real signalfd, fully draining every
 * ready child on each wakeup and routing each one to its actual owner via
 * manager_get_unit_by_pid() -- the way manager-loop.c's own SIGCHLD dispatch
 * will, once its (in flight, separately owned) epoll wiring lands. This is
 * not a simplification for one Service: with two services' processes both
 * mid-death (see test_b2_signal_amnesty_differs_by_type()), routing
 * unconditionally to whichever Service* the caller passed in would
 * misattribute the wrong pid's exit to the wrong service -- caught in
 * review before this test would have been flaky rather than wrong.
 *
 * Returns true once `s`'s own pid has been reaped and routed, false on
 * timeout -- never blocks past timeout_ms, so a state-machine regression
 * fails an assertion instead of hanging the suite.
 */
static bool reap_for(Service *s, int timeout_ms) {
        Manager *m = UNIT(s)->manager;
        struct pollfd pfd = { .fd = pico_signal_fd(m->signal), .events = POLLIN };

        /*
         * Already settled: a previous reap_for() call for a *different*
         * service can drain this one too in the same wakeup (two services'
         * processes dying close together, e.g. test_b2_signal_amnesty_
         * differs_by_type()'s pair of SIGTERMs), since the inner loop below
         * keeps draining until waitid() has nothing left, not just until it
         * finds the one pid a given call happens to care about. Nothing left
         * to wait for in that case.
         */
        if (s->main_pid == 0 && s->control_pid == 0)
                return true;

        for (;;) {
                bool got_target = false;
                int r = poll(&pfd, 1, timeout_ms);

                if (r <= 0)
                        return false;

                for (;;) {
                        int signo;
                        int rr = pico_signal_read(m->signal, &signo);

                        if (rr == -EAGAIN)
                                break;
                        if (rr < 0)
                                return false;
                        if (signo != SIGCHLD)
                                continue;

                        for (;;) {
                                siginfo_t info;
                                Unit *owner;

                                memset(&info, 0, sizeof(info));
                                if (waitid(P_ALL, 0, &info, WEXITED | WNOHANG) < 0 || info.si_pid == 0)
                                        break;

                                owner = manager_get_unit_by_pid(m, info.si_pid);
                                if (!owner || owner->type != UNIT_SERVICE)
                                        continue; /* reaped by us but not ours -- ignore */

                                service_sigchld_event(
                                                SERVICE(owner), info.si_pid, info.si_code, info.si_status);
                                if (SERVICE(owner) == s)
                                        got_target = true;
                        }
                }

                if (got_target)
                        return true;
        }
}

/* Blocks until the manager's timerfd fires or timeout_ms elapses, then
 * dispatches it. Returns whether a timer actually fired -- false is the
 * correct, assertable answer for "no timer was pending", not a failure. */
static bool wait_for_timer(Manager *m, int timeout_ms) {
        struct pollfd pfd = { .fd = pico_timer_fd(m->timer), .events = POLLIN };

        if (poll(&pfd, 1, timeout_ms) <= 0)
                return false;

        pico_timer_dispatch(m->timer);
        return true;
}

/*
 * M3's "done when": DEAD -> EXEC_START -> RUNNING -> STOP -> DEAD for
 * Type=simple. EXEC_START is entered and left again synchronously inside
 * service_start() itself for Type=simple ("started the moment it is
 * forked") so it is never separately observable here -- that is exactly the
 * property test_oneshot_completes_only_on_exit() below asserts directly for
 * the type that DOES make it observable.
 */
static void test_lifecycle_simple(void) {
        Manager *m;
        Service *s;
        char *dir;
        pid_t pid1;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        s = load_service(
                        m,
                        dir,
                        "simple.service",
                        "[Unit]\nDescription=simple\n"
                        "[Service]\nType=simple\nExecStart=/bin/sleep 100\n");

        ASSERT_EQ_INT(s->state, SERVICE_DEAD);
        ASSERT_EQ_INT(unit_active_state(UNIT(s)), UNIT_INACTIVE);

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);

        /* "the moment it is forked": already RUNNING, not still EXEC_START,
         * by the time service_start() returns. */
        ASSERT_EQ_INT(s->state, SERVICE_RUNNING);
        ASSERT_EQ_INT(unit_active_state(UNIT(s)), UNIT_ACTIVE);
        ASSERT_TRUE(s->main_pid > 0);
        pid1 = s->main_pid;

        if (s->cgroup) {
                /*
                 * service_spawn() returns to the parent as soon as fork()
                 * does; the child still has real work left (signal reset, fd
                 * sweep, setsid, THEN the cgroup.procs write) before it is
                 * actually a cgroup member, so checking immediately is a
                 * race against our own child, not against service.c. Poll
                 * briefly rather than asserting on the very first read.
                 */
                int empty = -1;
                int tries;

                printf("test-service: cgroup available, checking membership\n");
                for (tries = 0; tries < 200; tries++) {
                        empty = cgroup_v2_is_empty(s->cgroup);
                        if (empty == 0)
                                break;
                        test_sleep_ms(1);
                }
                ASSERT_EQ_INT(empty, 0); /* sleep is in it */
        } else {
                printf("test-service: no cgroup privilege in this container, skipping membership check\n");
        }

        ASSERT_EQ_INT(unit_stop(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_STOP);
        ASSERT_EQ_INT(unit_active_state(UNIT(s)), UNIT_DEACTIVATING);

        ASSERT_TRUE(reap_for(s, 3000));

        /* B2, half of it: our own SIGTERM killing a Type=simple daemon is a
         * clean, successful stop -- DEAD, not FAILED. */
        ASSERT_EQ_INT(s->state, SERVICE_DEAD);
        ASSERT_EQ_INT(s->result, SERVICE_SUCCESS);
        ASSERT_EQ_INT(unit_active_state(UNIT(s)), UNIT_INACTIVE);
        ASSERT_EQ_INT(s->main_pid, 0);
        ASSERT_TRUE(pid1 > 0); /* the pid we forked was a real one */

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * The property the milestone brief calls out by name: a oneshot's start job
 * completes only once the process has exited, never merely because it was
 * forked. Asserted directly by checking state immediately after
 * service_start() returns (still EXEC_START/ACTIVATING) and again only
 * after the process has actually exited (DEAD/INACTIVE, since
 * RemainAfterExit defaults to no).
 */
static void test_oneshot_completes_only_on_exit(void) {
        Manager *m;
        Service *s;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        s = load_service(
                        m,
                        dir,
                        "oneshot.service",
                        "[Unit]\nDescription=oneshot\n"
                        "[Service]\nType=oneshot\nExecStart=/bin/sleep 1\n");

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);

        /* Forked, but NOT yet counted as started: still activating. */
        ASSERT_EQ_INT(s->state, SERVICE_EXEC_START);
        ASSERT_EQ_INT(unit_active_state(UNIT(s)), UNIT_ACTIVATING);
        ASSERT_TRUE(s->main_pid > 0);

        ASSERT_TRUE(reap_for(s, 3000));

        /* Only now, once /bin/sleep 1 has actually exited, does completion
         * happen -- and since RemainAfterExit=no (default), that lands on
         * DEAD/INACTIVE, not EXITED/ACTIVE (see the RemainAfterExit=yes
         * test below for the other half of that distinction). */
        ASSERT_EQ_INT(s->state, SERVICE_DEAD);
        ASSERT_EQ_INT(s->result, SERVICE_SUCCESS);
        ASSERT_EQ_INT(unit_active_state(UNIT(s)), UNIT_INACTIVE);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

static void test_remain_after_exit(void) {
        Manager *m;
        Service *s;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        s = load_service(
                        m,
                        dir,
                        "remain.service",
                        "[Unit]\nDescription=remain\n"
                        "[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n");

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_TRUE(reap_for(s, 3000));

        ASSERT_EQ_INT(s->state, SERVICE_EXITED);
        ASSERT_EQ_INT(s->result, SERVICE_SUCCESS);
        ASSERT_EQ_INT(unit_active_state(UNIT(s)), UNIT_ACTIVE);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * B2, made explicit: same signal (SIGTERM), opposite verdicts, depending on
 * whether the process it killed was a long-running daemon's main process
 * (clean) or a oneshot/control command (never clean). v30 amnestied both
 * alike; a Type=oneshot boot-plumbing unit killed at its start timeout
 * would have silently reported success under that rule.
 */
static void test_b2_signal_amnesty_differs_by_type(void) {
        Manager *m;
        Service *daemon, *oneshot;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        daemon = load_service(
                        m, dir, "daemon.service", "[Unit]\n[Service]\nType=simple\nExecStart=/bin/sleep 100\n");
        oneshot = load_service(
                        m, dir, "cmd.service", "[Unit]\n[Service]\nType=oneshot\nExecStart=/bin/sleep 100\n");

        ASSERT_EQ_INT(unit_start(UNIT(daemon)), 0);
        ASSERT_EQ_INT(unit_start(UNIT(oneshot)), 0);

        ASSERT_EQ_INT(unit_stop(UNIT(daemon)), 0);  /* SIGTERM, daemon */
        ASSERT_EQ_INT(unit_stop(UNIT(oneshot)), 0); /* SIGTERM, oneshot's still-running main command */

        ASSERT_TRUE(reap_for(daemon, 3000));
        ASSERT_TRUE(reap_for(oneshot, 3000));

        ASSERT_EQ_INT(daemon->state, SERVICE_DEAD);
        ASSERT_EQ_INT(daemon->result, SERVICE_SUCCESS); /* SIGTERM on a daemon: success */

        ASSERT_EQ_INT(oneshot->state, SERVICE_FAILED);
        ASSERT_EQ_INT(oneshot->result, SERVICE_FAILURE_SIGNAL); /* SIGTERM on a command: failure */

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * A start timeout must produce FAILED with SERVICE_FAILURE_TIMEOUT, and
 * B3's write-once rule must protect that cause from being overwritten by
 * the SIGTERM-death classification the timeout's own kill triggers a
 * moment later (the "watchdog reports the cause, not the effect" case).
 */
static void test_start_timeout(void) {
        Manager *m;
        Service *s;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        /* oneshot: does not reach RUNNING (and so does not cancel its start
         * timer) until /bin/sleep 5 actually exits, which will not happen
         * inside a 150ms TimeoutStartSec=. */
        s = load_service(
                        m,
                        dir,
                        "timeout.service",
                        "[Unit]\n[Service]\nType=oneshot\nExecStart=/bin/sleep 5\nTimeoutStartSec=150ms\n");

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_EXEC_START);

        ASSERT_TRUE(wait_for_timer(m, 3000)); /* the start timeout itself */
        ASSERT_EQ_INT(s->state, SERVICE_STOP);
        ASSERT_EQ_INT(s->result, SERVICE_FAILURE_TIMEOUT); /* set before the SIGTERM that follows */

        ASSERT_TRUE(reap_for(s, 3000)); /* the SIGTERM the timeout sent lands here */

        ASSERT_EQ_INT(s->state, SERVICE_FAILED);
        /* Not SERVICE_FAILURE_SIGNAL: the write-once rule kept the real
         * cause even though the process's own death looks like a signal. */
        ASSERT_EQ_INT(s->result, SERVICE_FAILURE_TIMEOUT);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* A crash with Restart=on-failure restarts; the same crash with Restart=no
 * does not. */
static void test_crash_restart(void) {
        Manager *m;
        Service *restart, *no_restart;
        char *dir;
        pid_t first_pid;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        restart = load_service(
                        m,
                        dir,
                        "crash-restart.service",
                        "[Unit]\n[Service]\nType=simple\nExecStart=/bin/sh -c \"exit 1\"\n"
                        "Restart=on-failure\nRestartSec=50ms\n");
        no_restart = load_service(
                        m,
                        dir,
                        "crash-norestart.service",
                        "[Unit]\n[Service]\nType=simple\nExecStart=/bin/sh -c \"exit 1\"\n");

        /* Restart=on-failure: crash, then a real second fork. */
        ASSERT_EQ_INT(unit_start(UNIT(restart)), 0);
        ASSERT_EQ_INT(restart->state, SERVICE_RUNNING);
        first_pid = restart->main_pid;

        ASSERT_TRUE(reap_for(restart, 3000));
        ASSERT_EQ_INT(restart->state, SERVICE_AUTO_RESTART);
        ASSERT_EQ_INT(restart->result, SERVICE_FAILURE_EXIT_CODE);
        ASSERT_EQ_INT(restart->n_restarts, 1);

        ASSERT_TRUE(wait_for_timer(m, 3000));           /* RestartSec= elapses */
        ASSERT_EQ_INT(restart->state, SERVICE_RUNNING); /* actually restarted */
        ASSERT_TRUE(restart->main_pid > 0);
        ASSERT_TRUE(restart->main_pid != first_pid);

        ASSERT_TRUE(reap_for(restart, 3000)); /* let the second one finish too */

        /* Restart=no (default): crash, and stay down. */
        ASSERT_EQ_INT(unit_start(UNIT(no_restart)), 0);
        ASSERT_TRUE(reap_for(no_restart, 3000));

        ASSERT_EQ_INT(no_restart->state, SERVICE_FAILED);
        ASSERT_EQ_INT(no_restart->result, SERVICE_FAILURE_EXIT_CODE);
        ASSERT_TRUE(no_restart->timer_event == NULL); /* nothing scheduled */

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * B7's regression, made concrete: without start-rate limiting, a
 * nonexistent ExecStart= with Restart=on-failure and a tiny RestartSec=
 * spins fork/execve/ENOENT forever. Bounded to at most start_limit_burst+1
 * real attempts so a regression here fails the assertion below rather than
 * hanging the suite.
 */
static void test_b7_start_limit_stops_the_loop(void) {
        Manager *m;
        Service *s;
        char *dir;
        unsigned iterations;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        s = load_service(
                        m,
                        dir,
                        "loop.service",
                        "[Unit]\n[Service]\nType=simple\nExecStart=/nonexistent/does-not-exist\n"
                        "Restart=on-failure\nRestartSec=5ms\n");

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);

        /*
         * Each real attempt costs two actions (reap the failed exec, then
         * wait for the restart timer that schedules the next one), and the
         * initial unit_start() above already consumed attempt #1 -- so
         * reaching the rate limit takes up to 2*start_limit_burst actions
         * before the final, fork-free rejection. Bound generously (double
         * that) rather than tightly: this is testing that it terminates at
         * all, not exact timing.
         */
        for (iterations = 0; iterations < s->start_limit_burst * 4 && s->state != SERVICE_FAILED;
             iterations++) {
                if (s->main_pid > 0)
                        ASSERT_TRUE(reap_for(s, 2000));
                else if (s->state == SERVICE_AUTO_RESTART)
                        ASSERT_TRUE(wait_for_timer(m, 2000));
                else
                        break;
        }

        ASSERT_EQ_INT(s->state, SERVICE_FAILED);
        ASSERT_EQ_INT(s->result, SERVICE_FAILURE_START_LIMIT);
        ASSERT_TRUE(s->timer_event == NULL); /* the loop is genuinely over */
        ASSERT_TRUE(s->start_limit_num > s->start_limit_burst);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * Bug found during this milestone's own review, not upstream: every branch
 * of service_enter_running() leaves the start attempt behind for good, so
 * the start timeout that got the service there must be cancelled on every
 * one of those branches -- not just the failure path, which is the one
 * service_enter_stop() already covers. A Type=simple daemon that forked
 * cleanly and is happily RUNNING must not get SIGTERM'd out from under
 * itself the moment its (otherwise irrelevant, by then) TimeoutStartSec=
 * elapses. Proven here with a short timeout and by asserting no timer ever
 * fires again once RUNNING is reached.
 */
static void test_bug_running_timer_not_cancelled(void) {
        Manager *m;
        Service *s;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        s = load_service(
                        m,
                        dir,
                        "longrun.service",
                        "[Unit]\n[Service]\nType=simple\nExecStart=/bin/sleep 100\nTimeoutStartSec=80ms\n");

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_RUNNING);

        /* Wait well past the (now irrelevant) 80ms start timeout: no timer
         * should fire at all -- if it does, this is the bug, and it would
         * SIGTERM a perfectly healthy /bin/sleep. */
        ASSERT_TRUE(!wait_for_timer(m, 300));
        ASSERT_EQ_INT(s->state, SERVICE_RUNNING);
        ASSERT_TRUE(s->main_pid > 0);

        ASSERT_EQ_INT(unit_stop(UNIT(s)), 0);
        ASSERT_TRUE(reap_for(s, 3000));
        ASSERT_EQ_INT(s->state, SERVICE_DEAD);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* B9/CVE-2021-4034-class: a unit with no ExecStart= at all must refuse to
 * load rather than becoming a service with an empty argv. */
static void test_b9_service_verify_refuses_no_execstart(void) {
        Manager *m;
        Unit *u;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        ASSERT_EQ_INT(test_write_file(dir, "noexec.service", "[Unit]\nDescription=nothing to run\n"), 0);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        u = manager_get_unit(m, "noexec.service");
        ASSERT_TRUE(u != NULL);
        ASSERT_EQ_INT(u->load_state, UNIT_ERROR); /* refused, not silently loaded */

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* B1: TimeoutStartSec=0 means "never", not "immediately" -- opposite of
 * RestartSec=0. A service with a real, slow-to-exit ExecStart= and
 * TimeoutStartSec=0 must not be killed by a phantom zero-length timeout. */
static void test_b1_zero_timeout_means_infinity(void) {
        Manager *m;
        Service *s;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        s = load_service(
                        m,
                        dir,
                        "notimeout.service",
                        "[Unit]\n[Service]\nType=oneshot\nExecStart=/bin/sleep 1\nTimeoutStartSec=0\n");

        ASSERT_EQ_INT(s->timeout_start_usec, USEC_INFINITY);

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_EXEC_START);
        ASSERT_TRUE(s->timer_event == NULL); /* never armed at all */

        ASSERT_TRUE(reap_for(s, 3000)); /* the sleep exits on its own */
        ASSERT_EQ_INT(s->state, SERVICE_DEAD);
        ASSERT_EQ_INT(s->result, SERVICE_SUCCESS);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * unit_start()'s condition check (unit.c) is evaluated at start time, not
 * load time -- the same unit gets a different answer on the same call site
 * once the path it names shows up, exactly like ConditionPathExists=/dev/
 * ttyGS0 only becoming true once usb-multi-gadget.service has run. Also
 * covers the ConditionPathIsDirectory= trap a plain stat() would miss: an
 * existing regular file is not a directory.
 */
static void test_condition_skips_start_without_failing(void) {
        Manager *m;
        Service *cond;
        Service *isdir;
        Service *isdir_ok;
        char *dir;
        char svc[PATH_MAX + 128];

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        snprintf(svc,
                 sizeof(svc),
                 "[Unit]\nDescription=cond\nConditionPathExists=%s/marker\n"
                 "[Service]\nType=simple\nExecStart=/bin/sleep 100\n",
                 dir);
        cond = load_service(m, dir, "cond.service", svc);

        snprintf(svc,
                 sizeof(svc),
                 "[Unit]\nDescription=isdir\nConditionPathIsDirectory=%s/marker\n"
                 "[Service]\nType=simple\nExecStart=/bin/sleep 100\n",
                 dir);
        isdir = load_service(m, dir, "isdir.service", svc);

        snprintf(svc,
                 sizeof(svc),
                 "[Unit]\nDescription=isdir-ok\nConditionPathIsDirectory=%s\n"
                 "[Service]\nType=simple\nExecStart=/bin/sleep 100\n",
                 dir);
        isdir_ok = load_service(m, dir, "isdir-ok.service", svc);

        /* Phase 1: marker absent. */
        ASSERT_EQ_INT(unit_start(UNIT(cond)), -EALREADY);
        ASSERT_EQ_INT(cond->state, SERVICE_DEAD);
        ASSERT_EQ_INT(unit_active_state(UNIT(cond)), UNIT_INACTIVE);
        ASSERT_TRUE(cond->main_pid == 0);
        ASSERT_TRUE(!UNIT(cond)->condition_result);

        /* An existing directory passes on the very first check. */
        ASSERT_EQ_INT(unit_start(UNIT(isdir_ok)), 0);
        ASSERT_EQ_INT(isdir_ok->state, SERVICE_RUNNING);
        ASSERT_TRUE(isdir_ok->main_pid > 0);
        ASSERT_TRUE(UNIT(isdir_ok)->condition_result);

        /* Phase 2: the marker now exists. */
        ASSERT_EQ_INT(test_write_file(dir, "marker", "x"), 0);

        /* Same unit, same call -- a different answer because the check runs
         * at start time, not load time. */
        ASSERT_EQ_INT(unit_start(UNIT(cond)), 0);
        ASSERT_EQ_INT(cond->state, SERVICE_RUNNING);
        ASSERT_TRUE(cond->main_pid > 0);
        ASSERT_TRUE(UNIT(cond)->condition_result);

        /* The marker exists now, but as a regular file -- proves S_ISDIR()
         * is actually tested rather than mere existence. */
        ASSERT_EQ_INT(unit_start(UNIT(isdir)), -EALREADY);
        ASSERT_EQ_INT(isdir->state, SERVICE_DEAD);
        ASSERT_TRUE(!UNIT(isdir)->condition_result);

        ASSERT_EQ_INT(unit_stop(UNIT(cond)), 0);
        ASSERT_TRUE(reap_for(cond, 3000));
        ASSERT_EQ_INT(unit_stop(UNIT(isdir_ok)), 0);
        ASSERT_TRUE(reap_for(isdir_ok, 3000));

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * The kernel's own view of a process's ids -- /proc/<pid>/status Uid:/Gid:
 * (real ids, the first field) and the Groups: line verbatim -- rather than
 * anything pico-init believes it set. false when the process is gone.
 */
static bool read_proc_ids(pid_t pid, uid_t *uid, gid_t *gid, char *groups, size_t groups_len) {
        char path[64], line[512];
        bool have_uid = false, have_gid = false, have_groups = false;
        FILE *f;

        snprintf(path, sizeof(path), "/proc/%d/status", (int) pid);
        f = fopen(path, "re");
        if (!f)
                return false;

        while (fgets(line, sizeof(line), f)) {
                unsigned long v;

                if (sscanf(line, "Uid:\t%lu", &v) == 1) {
                        *uid = (uid_t) v;
                        have_uid = true;
                } else if (sscanf(line, "Gid:\t%lu", &v) == 1) {
                        *gid = (gid_t) v;
                        have_gid = true;
                } else if (strncmp(line, "Groups:", 7) == 0) {
                        size_t n = strlen(line + 7);

                        if (n >= groups_len)
                                n = groups_len - 1;
                        memcpy(groups, line + 7, n);
                        groups[n] = '\0';
                        have_groups = true;
                }
        }
        fclose(f);

        return have_uid && have_gid && have_groups;
}

/* Whether the Groups: line (space-separated, leading tab, trailing space)
 * names `g` as a whole token. */
static bool groups_line_has(const char *groups, gid_t g) {
        char want[32];
        const char *p = groups;
        size_t n;

        snprintf(want, sizeof(want), "%lu", (unsigned long) g);
        n = strlen(want);

        while (*p) {
                while (*p == ' ' || *p == '\t' || *p == '\n')
                        p++;
                if (strncmp(p, want, n) == 0 && (p[n] == ' ' || p[n] == '\n' || p[n] == '\0'))
                        return true;
                while (*p && *p != ' ' && *p != '\t' && *p != '\n')
                        p++;
        }
        return false;
}

/*
 * The drop happens in the child right before execve(), after
 * service_spawn() has already returned to the parent -- so the very first
 * read can still see root. Polls until the real uid AND gid are the expected
 * ones or the deadline passes; returns whether they were.
 */
static bool wait_for_ids(pid_t pid, uid_t want_uid, gid_t want_gid, char *groups, size_t groups_len) {
        int tries;

        for (tries = 0; tries < 2000; tries++) {
                uid_t uid;
                gid_t gid;

                if (!read_proc_ids(pid, &uid, &gid, groups, groups_len))
                        return false;
                if (uid == want_uid && gid == want_gid)
                        return true;
                test_sleep_ms(1);
        }
        return false;
}

/*
 * §9.2's acceptance test: a unit with User=/Group= naming real unprivileged
 * accounts actually runs as those ids, proven by the kernel's own
 * /proc/<pid>/status for the exec'd /bin/sleep, and root's supplementary
 * group is gone from the exec'd process. Group= alone keeps uid 0 and
 * changes only the gid; a numeric User= resolves through the passwd
 * database for its primary group.
 *
 * Only root can drop to another account. Unprivileged, the same unit must
 * still never run as the caller: the child's setgroups() fails, it
 * _exit()s PICO_EXIT_GROUP, and the parent reports a resources failure --
 * that branch is what gets proven instead.
 */
static void test_user_group_drops_privilege(void) {
        Manager *m;
        Service *s;
        char *dir;
        char groups[256];
        struct passwd *pw;
        struct group *gr;
        uid_t nobody_uid;
        gid_t nobody_gid, daemon_gid;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        s = load_service(
                        m,
                        dir,
                        "drop.service",
                        "[Unit]\n[Service]\nType=simple\nUser=nobody\nGroup=daemon\n"
                        "ExecStart=/bin/sleep 100\n");
        ASSERT_STREQ(s->user, "nobody");
        ASSERT_STREQ(s->group, "daemon");

        if (getuid() != 0) {
                printf("test-service: not root, checking the fatal-drop path instead\n");

                ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
                ASSERT_EQ_INT(s->state, SERVICE_RUNNING); /* forked; the child fails on its own */
                ASSERT_TRUE(reap_for(s, 3000));

                ASSERT_EQ_INT(s->state, SERVICE_FAILED);
                ASSERT_EQ_INT(s->result, SERVICE_FAILURE_RESOURCES); /* PICO_EXIT_GROUP, ours */
                ASSERT_EQ_INT(s->main_exit_code, CLD_EXITED);
                ASSERT_EQ_INT(s->main_exit_status, PICO_EXIT_GROUP);

                manager_free(m);
                test_rm_rf(dir);
                free(dir);
                return;
        }

        pw = getpwnam("nobody");
        ASSERT_TRUE(pw != NULL);
        nobody_uid = pw->pw_uid;
        nobody_gid = pw->pw_gid;
        gr = getgrnam("daemon");
        ASSERT_TRUE(gr != NULL);
        daemon_gid = gr->gr_gid;
        ASSERT_TRUE(nobody_uid != 0);
        ASSERT_TRUE(daemon_gid != 0);

        /* User= + Group=: both real, Group= overrides the primary group,
         * root's own group 0 is not left behind in the supplementary set. */
        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_RUNNING);
        ASSERT_TRUE(s->main_pid > 0);
        ASSERT_TRUE(wait_for_ids(s->main_pid, nobody_uid, daemon_gid, groups, sizeof(groups)));
        ASSERT_TRUE(groups_line_has(groups, daemon_gid));
        ASSERT_TRUE(!groups_line_has(groups, 0));

        ASSERT_EQ_INT(unit_stop(UNIT(s)), 0);
        ASSERT_TRUE(reap_for(s, 3000));
        ASSERT_EQ_INT(s->state, SERVICE_DEAD);
        ASSERT_EQ_INT(s->result, SERVICE_SUCCESS);

        /* Group= alone: uid stays 0, gid changes. */
        s = load_service(
                        m,
                        dir,
                        "group-only.service",
                        "[Unit]\n[Service]\nType=simple\nGroup=daemon\nExecStart=/bin/sleep 100\n");
        ASSERT_TRUE(s->user == NULL);
        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_TRUE(wait_for_ids(s->main_pid, 0, daemon_gid, groups, sizeof(groups)));
        ASSERT_TRUE(groups_line_has(groups, daemon_gid));
        ASSERT_TRUE(!groups_line_has(groups, 0));
        ASSERT_EQ_INT(unit_stop(UNIT(s)), 0);
        ASSERT_TRUE(reap_for(s, 3000));
        ASSERT_EQ_INT(s->state, SERVICE_DEAD);

        /* Numeric User=: the id as written, primary group from passwd. */
        {
                char unit[256];

                snprintf(unit,
                         sizeof(unit),
                         "[Unit]\n[Service]\nType=simple\nUser=%lu\nExecStart=/bin/sleep 100\n",
                         (unsigned long) nobody_uid);
                s = load_service(m, dir, "numeric.service", unit);
        }
        ASSERT_TRUE(s->group == NULL);
        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_TRUE(wait_for_ids(s->main_pid, nobody_uid, nobody_gid, groups, sizeof(groups)));
        ASSERT_TRUE(!groups_line_has(groups, 0));
        ASSERT_EQ_INT(unit_stop(UNIT(s)), 0);
        ASSERT_TRUE(reap_for(s, 3000));
        ASSERT_EQ_INT(s->state, SERVICE_DEAD);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * A User= or Group= that does not exist fails the start attempt cleanly in
 * the parent: nothing is forked, the unit is FAILED with a resources result,
 * and -- the actual requirement -- nothing ever ran as root instead.
 * ExecStartPre= is covered too: resolution is per spawn, not per main
 * command, so a control command never runs with more privilege than
 * ExecStart= would have.
 */
static void test_user_unknown_fails_start_cleanly(void) {
        Manager *m;
        Service *s;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        s = load_service(
                        m,
                        dir,
                        "nouser.service",
                        "[Unit]\n[Service]\nType=simple\nUser=pico-no-such-user-5f\n"
                        "ExecStart=/bin/sleep 100\n");
        ASSERT_EQ_INT(UNIT(s)->load_state, UNIT_LOADED); /* an unknown account is not a load error */
        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_FAILED);
        ASSERT_EQ_INT(s->result, SERVICE_FAILURE_RESOURCES);
        ASSERT_EQ_INT(s->main_pid, 0);
        ASSERT_TRUE(s->timer_event == NULL);

        s = load_service(
                        m,
                        dir,
                        "nogroup.service",
                        "[Unit]\n[Service]\nType=oneshot\nGroup=pico-no-such-group-5f\n"
                        "ExecStartPre=/bin/true\nExecStart=/bin/true\n");
        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_FAILED);
        ASSERT_EQ_INT(s->result, SERVICE_FAILURE_RESOURCES);
        ASSERT_EQ_INT(s->main_pid, 0);
        ASSERT_EQ_INT(s->control_pid, 0);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * Type=exec versus Type=simple, observed through ordering rather than
 * through the state field alone: b is After= (and Requires=) a, so b's
 * start job is runnable exactly when a's has finished. For simple that is
 * inside the same manager_dispatch_run_queue() call that forked a; for exec
 * it is not until the loop has seen a's execve() go through.
 */
static void test_exec_completes_only_after_execve(void) {
        Manager *m;
        Service *a, *b;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        a = load_service(m, dir, "exec-a.service", "[Unit]\n[Service]\nType=exec\nExecStart=/bin/sleep 100\n");
        b = load_service(
                        m,
                        dir,
                        "exec-b.service",
                        "[Unit]\nRequires=exec-a.service\nAfter=exec-a.service\n"
                        "[Service]\nType=simple\nExecStart=/bin/sleep 100\n");

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, UNIT(b), NULL), 0);
        ASSERT_EQ_INT(manager_dispatch_run_queue(m), 1); /* only a ran */

        /* Forked, exec fd armed, and NOT started: a's job is still open,
         * so b -- ordered after it -- has not been touched. */
        ASSERT_EQ_INT(a->state, SERVICE_EXEC_START);
        ASSERT_EQ_INT(unit_active_state(UNIT(a)), UNIT_ACTIVATING);
        ASSERT_TRUE(a->main_pid > 0);
        ASSERT_TRUE(a->exec_fd >= 0);
        ASSERT_TRUE(UNIT(a)->job != NULL);
        ASSERT_EQ_INT(b->state, SERVICE_DEAD);
        ASSERT_EQ_INT(b->main_pid, 0);

        ASSERT_TRUE(drive_until(m, service_running_done, b, 400));

        ASSERT_EQ_INT(a->state, SERVICE_RUNNING);
        ASSERT_EQ_INT(unit_active_state(UNIT(a)), UNIT_ACTIVE);
        ASSERT_TRUE(a->exec_fd < 0); /* consumed: the EOF was the signal */
        ASSERT_TRUE(a->exec_fd_source == NULL);
        ASSERT_TRUE(UNIT(a)->job == NULL);
        ASSERT_TRUE(b->main_pid > 0);

        ASSERT_EQ_INT(unit_stop(UNIT(b)), 0);
        ASSERT_EQ_INT(unit_stop(UNIT(a)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, a, 400));
        ASSERT_TRUE(drive_until(m, service_settled_done, b, 400));
        ASSERT_EQ_INT(a->state, SERVICE_DEAD);
        ASSERT_EQ_INT(a->result, SERVICE_SUCCESS);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* The other half of the exec contract: an execve() that fails is a start
 * that never completed. Under simple the same unit reports ACTIVE first
 * and its dependent starts; under exec it goes straight to FAILED, the
 * dependent's job is cancelled with it, and nothing After= it ever forks. */
static void test_exec_failed_execve_never_active(void) {
        Manager *m;
        Service *a, *b;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        a = load_service(
                        m,
                        dir,
                        "exec-fail-a.service",
                        "[Unit]\n[Service]\nType=exec\nExecStart=/nonexistent/pico-init-no-such-binary\n");
        b = load_service(
                        m,
                        dir,
                        "exec-fail-b.service",
                        "[Unit]\nRequires=exec-fail-a.service\nAfter=exec-fail-a.service\n"
                        "[Service]\nType=simple\nExecStart=/bin/sleep 100\n");

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, UNIT(b), NULL), 0);
        ASSERT_EQ_INT(manager_dispatch_run_queue(m), 1);
        ASSERT_EQ_INT(a->state, SERVICE_EXEC_START);

        ASSERT_TRUE(drive_until(m, service_settled_done, a, 400));

        ASSERT_EQ_INT(a->state, SERVICE_FAILED);
        ASSERT_EQ_INT(a->result, SERVICE_FAILURE_RESOURCES); /* PICO_EXIT_EXEC, our setup, not the workload */
        ASSERT_TRUE(a->exec_fd < 0);
        ASSERT_TRUE(UNIT(a)->job == NULL);
        ASSERT_EQ_INT(b->state, SERVICE_DEAD);
        ASSERT_EQ_INT(b->main_pid, 0);
        ASSERT_TRUE(UNIT(b)->job == NULL); /* cancelled along with a's failure */

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* A manager with the notify listener up: Type=notify needs a real socket
 * for the real sd_notify() in test-notify-helper to reach. */
static Manager *notify_manager_for(const char *dir, char **ret_rtdir) {
        Manager *m = manager_for(dir);
        char *rtdir = test_tmpdir_new();

        ASSERT_TRUE(rtdir != NULL);
        ASSERT_EQ_INT(manager_set_runtime_dir(m, rtdir), 0);
        ASSERT_EQ_INT(manager_notify_setup(m), 0);

        *ret_rtdir = rtdir;
        return m;
}

/*
 * Type=notify: the start job stays open, and so does everything After= it,
 * until the main process itself sends READY=1 -- here through the real
 * sd_notify() over the $NOTIFY_SOCKET service-exec.c injected, after a
 * deliberate delay the elapsed time proves was waited out.
 */
static void test_notify_ready_gates_activation(void) {
        Manager *m;
        Service *a, *b;
        char *dir, *rtdir;
        char helper[PATH_MAX];
        char unit[PATH_MAX + 128];
        usec_t t0;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = notify_manager_for(dir, &rtdir);
        notify_helper_path(helper, sizeof(helper));

        snprintf(unit, sizeof(unit), "[Unit]\n[Service]\nType=notify\nExecStart=%s 300\n", helper);
        a = load_service(m, dir, "notify-a.service", unit);
        b = load_service(
                        m,
                        dir,
                        "notify-b.service",
                        "[Unit]\nRequires=notify-a.service\nAfter=notify-a.service\n"
                        "[Service]\nType=simple\nExecStart=/bin/sleep 100\n");

        t0 = now_monotonic();
        ASSERT_EQ_INT(manager_add_job(m, JOB_START, UNIT(b), NULL), 0);
        ASSERT_EQ_INT(manager_dispatch_run_queue(m), 1);

        ASSERT_EQ_INT(a->state, SERVICE_EXEC_START);
        ASSERT_EQ_INT(unit_active_state(UNIT(a)), UNIT_ACTIVATING);
        ASSERT_TRUE(a->main_pid > 0);
        ASSERT_TRUE(a->exec_fd < 0); /* the exec fd is Type=exec's, not notify's */
        ASSERT_EQ_INT(a->notify_ready, false);
        ASSERT_EQ_INT(b->state, SERVICE_DEAD);

        ASSERT_TRUE(drive_until(m, service_running_done, b, 800));

        /* Not before the helper's own 300ms sleep, whatever the scheduler did. */
        ASSERT_TRUE(now_monotonic() - t0 >= 300 * USEC_PER_MSEC);
        ASSERT_EQ_INT(a->notify_ready, true);
        ASSERT_EQ_INT(a->state, SERVICE_RUNNING);
        ASSERT_EQ_INT(unit_active_state(UNIT(a)), UNIT_ACTIVE);
        ASSERT_TRUE(UNIT(a)->job == NULL);
        ASSERT_TRUE(b->main_pid > 0);

        ASSERT_EQ_INT(unit_stop(UNIT(b)), 0);
        ASSERT_EQ_INT(unit_stop(UNIT(a)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, a, 400));
        ASSERT_TRUE(drive_until(m, service_settled_done, b, 400));
        ASSERT_EQ_INT(a->state, SERVICE_DEAD);
        ASSERT_EQ_INT(a->result, SERVICE_SUCCESS); /* SIGTERM on a daemon's main process: clean */

        manager_free(m);
        test_rm_rf(dir);
        test_rm_rf(rtdir);
        free(dir);
        free(rtdir);
}

/* READY=1 never comes: TimeoutStartSec= ends the wait as a timeout
 * failure, and the process that never spoke is gone with it. */
static void test_notify_timeout_without_ready(void) {
        Manager *m;
        Service *s;
        char *dir, *rtdir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = notify_manager_for(dir, &rtdir);

        s = load_service(
                        m,
                        dir,
                        "notify-mute.service",
                        "[Unit]\n[Service]\nType=notify\nExecStart=/bin/sleep 100\nTimeoutStartSec=200ms\n");

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_EXEC_START);

        ASSERT_TRUE(drive_until(m, service_settled_done, s, 800));

        ASSERT_EQ_INT(s->state, SERVICE_FAILED);
        ASSERT_EQ_INT(s->result, SERVICE_FAILURE_TIMEOUT);
        ASSERT_EQ_INT(s->notify_ready, false);
        ASSERT_EQ_INT(s->main_pid, 0);

        manager_free(m);
        test_rm_rf(dir);
        test_rm_rf(rtdir);
        free(dir);
        free(rtdir);
}

/* A Type=notify main process that exits 0 without ever sending READY=1
 * was never active: a protocol failure, not a success -- and not a
 * RemainAfterExit=yes EXITED either, since there is nothing to remain. */
static void test_notify_exit_before_ready_is_protocol_failure(void) {
        Manager *m;
        Service *s;
        char *dir, *rtdir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = notify_manager_for(dir, &rtdir);

        s = load_service(
                        m,
                        dir,
                        "notify-quit.service",
                        "[Unit]\n[Service]\nType=notify\nRemainAfterExit=yes\nExecStart=/bin/true\n");

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, s, 400));

        ASSERT_EQ_INT(s->state, SERVICE_FAILED);
        ASSERT_EQ_INT(s->result, SERVICE_FAILURE_PROTOCOL);
        ASSERT_EQ_INT(unit_active_state(UNIT(s)), UNIT_FAILED);

        manager_free(m);
        test_rm_rf(dir);
        test_rm_rf(rtdir);
        free(dir);
        free(rtdir);
}

/* --- Type=forking --- */

/*
 * A stand-in for a daemonizing service: forks a long-lived child and exits,
 * optionally writing a pid to $1 first. A script rather than an inline
 * sh -c so the unit file stays a plain ExecStart= with no quoting in play.
 *
 * The child is started under setsid, as daemon(3) and start-stop-daemon
 * --background do: pico-init hands every service the console as its
 * controlling tty (service-exec.c, step 9), so a forking parent is a
 * session leader and its exit SIGHUPs whatever it left in its own session.
 * A daemon that does not detach from the session it was started in is
 * broken under a real getty too; this is not the case being tested.
 */
static void write_forkd(const char *dir, const char *name, const char *body) {
        char path[PATH_MAX];

        ASSERT_EQ_INT(test_write_file(dir, name, body), 0);
        snprintf(path, sizeof(path), "%s/%s", dir, name);
        ASSERT_EQ_INT(chmod(path, 0755), 0);
}

static pid_t read_pid_file(const char *path) {
        FILE *f = fopen(path, "r");
        long v = 0;

        ASSERT_TRUE(f != NULL);
        ASSERT_EQ_INT(fscanf(f, "%ld", &v), 1);
        fclose(f);
        return (pid_t) v;
}

/*
 * The forking contract, PIDFile= flavour: the start job (and everything
 * After= it) stays open until the ExecStart= parent exits, and its exit is
 * the start completing rather than the service dying. The daemon it left
 * behind is then the main pid, read from the file, and is what a stop
 * signals.
 */
static void test_forking_pidfile_gates_activation(void) {
        Manager *m;
        Service *a, *b;
        char *dir;
        char unit[PATH_MAX * 3 + 128]; /* three paths go in */
        char pidfile[PATH_MAX];

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        write_forkd(dir, "forkd.sh", "#!/bin/sh\nsetsid sleep 100 &\necho $! > \"$1\"\nexit 0\n");
        snprintf(pidfile, sizeof(pidfile), "%s/a.pid", dir);
        snprintf(unit,
                 sizeof(unit),
                 "[Unit]\n[Service]\nType=forking\nPIDFile=%s\nExecStart=%s/forkd.sh %s\n",
                 pidfile,
                 dir,
                 pidfile);
        a = load_service(m, dir, "fork-a.service", unit);
        b = load_service(
                        m,
                        dir,
                        "fork-b.service",
                        "[Unit]\nRequires=fork-a.service\nAfter=fork-a.service\n"
                        "[Service]\nType=simple\nExecStart=/bin/sleep 100\n");

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, UNIT(b), NULL), 0);
        ASSERT_EQ_INT(manager_dispatch_run_queue(m), 1);

        /* The parent is a control process, not the main one, and nothing
         * is started yet. */
        ASSERT_EQ_INT(a->state, SERVICE_EXEC_START);
        ASSERT_EQ_INT(unit_active_state(UNIT(a)), UNIT_ACTIVATING);
        ASSERT_TRUE(a->control_pid > 0);
        ASSERT_EQ_INT(a->main_pid, 0);
        ASSERT_TRUE(UNIT(a)->job != NULL);
        ASSERT_EQ_INT(b->state, SERVICE_DEAD);

        ASSERT_TRUE(drive_until(m, service_running_done, b, 400));

        ASSERT_EQ_INT(a->state, SERVICE_RUNNING);
        ASSERT_EQ_INT(unit_active_state(UNIT(a)), UNIT_ACTIVE);
        ASSERT_EQ_INT(a->control_pid, 0);
        ASSERT_TRUE(a->main_pid > 0);
        ASSERT_EQ_INT(a->main_pid, read_pid_file(pidfile));
        ASSERT_EQ_INT(a->main_pid_alien, true);
        ASSERT_TRUE(UNIT(a)->job == NULL);
        ASSERT_TRUE(b->main_pid > 0);

        ASSERT_EQ_INT(unit_stop(UNIT(b)), 0);
        ASSERT_EQ_INT(unit_stop(UNIT(a)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, a, 400));
        ASSERT_TRUE(drive_until(m, service_settled_done, b, 400));
        ASSERT_EQ_INT(a->state, SERVICE_DEAD);
        ASSERT_EQ_INT(a->result, SERVICE_SUCCESS); /* SIGTERM on the daemon: clean, alien or not */
        ASSERT_EQ_INT(a->main_pid, 0);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* No PIDFile=: GuessMainPID= (default yes) takes the one process left in
 * the cgroup once the parent is gone. */
static void test_forking_guess_main_pid_from_cgroup(void) {
        Manager *m;
        Service *s;
        char *dir;
        char unit[PATH_MAX * 2];
        char comm_path[64];
        char comm[32] = "";
        FILE *f;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        write_forkd(dir, "forkd.sh", "#!/bin/sh\nsetsid sleep 100 &\nexit 0\n");
        snprintf(unit, sizeof(unit), "[Unit]\n[Service]\nType=forking\nExecStart=%s/forkd.sh\n", dir);
        s = load_service(m, dir, "fork-guess.service", unit);

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_EXEC_START);
        ASSERT_TRUE(drive_until(m, service_running_done, s, 400));

        ASSERT_TRUE(s->main_pid > 0);
        ASSERT_EQ_INT(s->main_pid_alien, true);
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", (int) s->main_pid);
        /*
         * setsid(1) itself forks and execs into the command given to it, so
         * there is a real, if usually brief, window right after the cgroup
         * gains this pid where /proc/<pid>/comm still reads "setsid" rather
         * than "sleep" -- a fixture race, not a GuessMainPID= bug (it
         * correctly named the one live process in the cgroup at that
         * instant). Poll rather than reading once: this only ever needs
         * more than one iteration under CI-runner-level scheduling
         * pressure, never locally.
         */
        for (int i = 0; i < 20; i++) {
                f = fopen(comm_path, "r");
                ASSERT_TRUE(f != NULL);
                ASSERT_TRUE(fgets(comm, sizeof(comm), f) != NULL);
                fclose(f);
                if (strcmp(comm, "sleep\n") == 0)
                        break;
                test_sleep_ms(25);
        }
        ASSERT_STREQ(comm, "sleep\n");

        ASSERT_EQ_INT(unit_stop(UNIT(s)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, s, 400));
        ASSERT_EQ_INT(s->state, SERVICE_DEAD);
        ASSERT_EQ_INT(s->result, SERVICE_SUCCESS);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* The parent exiting non-zero is the one way a forking start fails: the
 * unit goes FAILED, the dependent's job is cancelled, nothing After= it
 * ever forks. */
static void test_forking_parent_failure_fails_start(void) {
        Manager *m;
        Service *a, *b;
        char *dir;
        char unit[PATH_MAX * 2];

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        write_forkd(dir, "failfork.sh", "#!/bin/sh\nexit 3\n");
        snprintf(unit, sizeof(unit), "[Unit]\n[Service]\nType=forking\nExecStart=%s/failfork.sh\n", dir);
        a = load_service(m, dir, "fork-fail.service", unit);
        b = load_service(
                        m,
                        dir,
                        "fork-dep.service",
                        "[Unit]\nRequires=fork-fail.service\nAfter=fork-fail.service\n"
                        "[Service]\nType=simple\nExecStart=/bin/sleep 100\n");

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, UNIT(b), NULL), 0);
        ASSERT_EQ_INT(manager_dispatch_run_queue(m), 1);
        ASSERT_TRUE(drive_until(m, service_settled_done, a, 400));

        ASSERT_EQ_INT(a->state, SERVICE_FAILED);
        ASSERT_EQ_INT(a->result, SERVICE_FAILURE_EXIT_CODE);
        ASSERT_EQ_INT(a->main_pid, 0);
        ASSERT_EQ_INT(a->control_pid, 0);
        ASSERT_EQ_INT(b->state, SERVICE_DEAD);
        ASSERT_EQ_INT(b->main_pid, 0);
        ASSERT_TRUE(UNIT(b)->job == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * A PIDFile= naming a pid outside the unit's cgroup is refused (pid 1 here:
 * alive, root-owned, and exactly what a confused or hostile daemon would
 * love PID 1 to SIGTERM on stop). With GuessMainPID=no there is then no main
 * pid at all -- and the unit is still running, because its cgroup is, and a
 * stop still reaches the daemon through the cgroup rather than declaring
 * the unit dead with the daemon alive.
 */
static void test_forking_pidfile_outside_cgroup_refused(void) {
        Manager *m;
        Service *s;
        char *dir;
        char unit[PATH_MAX * 3 + 128]; /* three paths go in */
        char pidfile[PATH_MAX];

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        write_forkd(dir, "liar.sh", "#!/bin/sh\nsetsid sleep 100 &\necho 1 > \"$1\"\nexit 0\n");
        snprintf(pidfile, sizeof(pidfile), "%s/liar.pid", dir);
        snprintf(unit,
                 sizeof(unit),
                 "[Unit]\n[Service]\nType=forking\nGuessMainPID=no\nPIDFile=%s\nExecStart=%s/liar.sh %s\n",
                 pidfile,
                 dir,
                 pidfile);
        s = load_service(m, dir, "fork-liar.service", unit);

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_TRUE(drive_until(m, service_running_done, s, 400));

        ASSERT_EQ_INT(s->state, SERVICE_RUNNING);
        ASSERT_EQ_INT(s->main_pid, 0);
        ASSERT_EQ_INT(s->main_pid_alien, false);
        ASSERT_TRUE(s->cgroup != NULL);
        ASSERT_EQ_INT(cgroup_v2_is_empty(s->cgroup), 0);

        ASSERT_EQ_INT(unit_stop(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_STOP); /* not DEAD: the daemon is still there to stop */
        ASSERT_TRUE(drive_until(m, service_settled_done, s, 400));
        ASSERT_EQ_INT(s->state, SERVICE_DEAD);
        ASSERT_EQ_INT(s->result, SERVICE_SUCCESS);
        ASSERT_EQ_INT(cgroup_v2_is_empty(s->cgroup), 1);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* A daemon that writes its pid *before* forking names the very process
 * that has just exited. That is refused rather than adopting a zombie, and
 * the guess then finds the real daemon. */
static void test_forking_pidfile_of_parent_refused(void) {
        Manager *m;
        Service *s;
        char *dir;
        char unit[PATH_MAX * 3 + 128]; /* three paths go in */
        char pidfile[PATH_MAX];

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        write_forkd(dir, "early.sh", "#!/bin/sh\necho $$ > \"$1\"\nsetsid sleep 100 &\nexit 0\n");
        snprintf(pidfile, sizeof(pidfile), "%s/early.pid", dir);
        snprintf(unit,
                 sizeof(unit),
                 "[Unit]\n[Service]\nType=forking\nPIDFile=%s\nExecStart=%s/early.sh %s\n",
                 pidfile,
                 dir,
                 pidfile);
        s = load_service(m, dir, "fork-early.service", unit);

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_TRUE(drive_until(m, service_running_done, s, 400));

        ASSERT_TRUE(s->main_pid > 0);
        ASSERT_TRUE(s->main_pid != read_pid_file(pidfile));

        ASSERT_EQ_INT(unit_stop(UNIT(s)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, s, 400));
        ASSERT_EQ_INT(s->state, SERVICE_DEAD);
        ASSERT_EQ_INT(s->result, SERVICE_SUCCESS);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* --- Environment=/EnvironmentFile= (plans/41 E2) --- */

/* util.c's quarried helpers directly: merge order and in-place override,
 * lookup, and the env-file line grammar. */
static void test_env_helpers(void) {
        char *base[] = { "A=1", "B=2", NULL };
        char *over[] = { "B=3", "C=4", "A=", NULL };
        char **m, **l = NULL;
        char *dir;
        char path[PATH_MAX];

        m = pico_strv_env_merge(3, base, NULL, over);
        ASSERT_TRUE(m != NULL);
        ASSERT_EQ_INT((int) pico_strv_length(m), 3);
        ASSERT_STREQ(m[0], "A="); /* overridden in place, empty value kept */
        ASSERT_STREQ(m[1], "B=3");
        ASSERT_STREQ(m[2], "C=4");
        ASSERT_STREQ(pico_strv_env_get(m, "B"), "3");
        ASSERT_STREQ(pico_strv_env_get(m, "A"), "");
        ASSERT_TRUE(pico_strv_env_get(m, "D") == NULL);
        ASSERT_TRUE(pico_strv_env_get(NULL, "A") == NULL);
        pico_strv_free(m);

        m = pico_strv_env_merge(1, NULL);
        ASSERT_TRUE(m != NULL && m[0] == NULL);
        pico_strv_free(m);

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "vars",
                                      "# comment\n"
                                      "; also a comment\n"
                                      "\n"
                                      "FOO=bar\n"
                                      "  SPACED = ' padded '  \n"
                                      "QUOTED=\"a b\"\n"
                                      "HALF=\"open\n"
                                      "NOEQUALS\n"
                                      "=novalue\n"
                                      "EMPTY=\n"
                                      "FOO=again"),
                      0);
        snprintf(path, sizeof(path), "%s/vars", dir);
        ASSERT_EQ_INT(pico_load_env_file(path, &l), 0);
        ASSERT_EQ_INT((int) pico_strv_length(l), 6);
        ASSERT_STREQ(l[0], "FOO=bar");
        ASSERT_STREQ(l[1], "SPACED= padded ");
        ASSERT_STREQ(l[2], "QUOTED=a b");
        ASSERT_STREQ(l[3], "HALF=\"open");
        ASSERT_STREQ(l[4], "EMPTY=");
        ASSERT_STREQ(l[5], "FOO=again"); /* the merge, not the loader, dedups */
        pico_strv_free(l);

        l = NULL;
        ASSERT_EQ_INT(test_write_file(dir, "blank", "# nothing\n"), 0);
        snprintf(path, sizeof(path), "%s/blank", dir);
        ASSERT_EQ_INT(pico_load_env_file(path, &l), 0);
        ASSERT_TRUE(l == NULL);

        snprintf(path, sizeof(path), "%s/missing", dir);
        ASSERT_EQ_INT(pico_load_env_file(path, &l), -ENOENT);

        test_rm_rf(dir);
        free(dir);
}

/* The line in `path` starting with `name=`, value only; "" when absent. */
static void read_env_line(const char *path, const char *name, char *out, size_t out_size) {
        char line[512];
        size_t n = strlen(name);
        FILE *f;

        out[0] = '\0';
        f = fopen(path, "re");
        ASSERT_TRUE(f != NULL);
        while (fgets(line, sizeof(line), f))
                if (strncmp(line, name, n) == 0 && line[n] == '=') {
                        line[strcspn(line, "\n")] = '\0';
                        snprintf(out, out_size, "%s", line + n + 1);
                        break;
                }
        fclose(f);
}

/*
 * The child sees, in v30's merge order: inherited environ, overridden by
 * Environment=, overridden by EnvironmentFile= contents (a later file beating
 * an earlier one). The files are read per spawn, so a file ExecStartPre=
 * writes reaches ExecStart=; a missing '-' file is skipped.
 */
static void test_environment_reaches_child(void) {
        Manager *m;
        Service *s;
        char *dir;
        char unit[4 * PATH_MAX], out[PATH_MAX], v[256];

        setenv("PICO_TEST_INHERITED", "inherited", 1);
        setenv("PICO_TEST_OVERRIDDEN", "inherited", 1);

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "static.env",
                                      "# defaults\n"
                                      "FOO=file-wins\n"
                                      "QUOTED=\"a b\"\n"
                                      "ORDER=first\n"
                                      "NOEQUALS\n"),
                      0);
        snprintf(out, sizeof(out), "%s/out", dir);
        snprintf(unit,
                 sizeof(unit),
                 "[Unit]\n[Service]\nType=oneshot\n"
                 "Environment=FOO=unit BAR=unit-only PICO_TEST_OVERRIDDEN=unit\n"
                 "EnvironmentFile=%s/static.env\n"
                 "EnvironmentFile=-%s/missing.env\n"
                 "EnvironmentFile=-%s/pre.env\n"
                 "ExecStartPre=/bin/sh -c \"echo ORDER=second > %s/pre.env\"\n"
                 "ExecStart=/bin/sh -c \"env > %s.tmp && mv %s.tmp %s\"\n",
                 dir,
                 dir,
                 dir,
                 dir,
                 out,
                 out,
                 out);
        s = load_service(m, dir, "env.service", unit);

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, s, 1000));
        ASSERT_EQ_INT(s->state, SERVICE_DEAD);
        ASSERT_EQ_INT(s->result, SERVICE_SUCCESS);

        read_env_line(out, "FOO", v, sizeof(v));
        ASSERT_STREQ(v, "file-wins");
        read_env_line(out, "BAR", v, sizeof(v));
        ASSERT_STREQ(v, "unit-only");
        read_env_line(out, "QUOTED", v, sizeof(v));
        ASSERT_STREQ(v, "a b");
        read_env_line(out, "ORDER", v, sizeof(v));
        ASSERT_STREQ(v, "second");
        read_env_line(out, "PICO_TEST_OVERRIDDEN", v, sizeof(v));
        ASSERT_STREQ(v, "unit");
        read_env_line(out, "PICO_TEST_INHERITED", v, sizeof(v));
        ASSERT_STREQ(v, "inherited");

        unsetenv("PICO_TEST_INHERITED");
        unsetenv("PICO_TEST_OVERRIDDEN");
        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* A required EnvironmentFile= that cannot be read fails the start in the
 * parent, before anything is forked -- ExecStartPre= included. */
static void test_environment_file_missing_fails_start(void) {
        Manager *m;
        Service *s;
        char *dir;
        char unit[PATH_MAX + 256];

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        snprintf(unit,
                 sizeof(unit),
                 "[Unit]\n[Service]\nType=oneshot\nEnvironmentFile=%s/nope.env\n"
                 "ExecStartPre=/bin/true\nExecStart=/bin/true\n",
                 dir);
        s = load_service(m, dir, "noenv.service", unit);
        ASSERT_EQ_INT(UNIT(s)->load_state, UNIT_LOADED);
        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_FAILED);
        ASSERT_EQ_INT(s->result, SERVICE_FAILURE_RESOURCES);
        ASSERT_EQ_INT(s->main_pid, 0);
        ASSERT_EQ_INT(s->control_pid, 0);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* --- $VAR/${VAR} in exec lines (plans/41 E3) --- */

/* util.c's quarried replace_env()/replace_env_argv() directly. */
static void test_replace_env_helpers(void) {
        char *env[] = { "FOO=a b", "Q=x \"y z\"", "EMPTY=", "BAD=\"open", NULL };
        char *argv[] = { "$FOO",    "$UNSET", "pre${FOO}post", "${UNSET}", "$$",     "cost:$$5",
                         "$${FOO}", "$FOO/x", "${FOO",         "$Q",       "$EMPTY", "$",
                         NULL };
        char *bad[] = { "$BAD", NULL };
        char **r = NULL, *x;

        x = pico_replace_env("<${FOO}|${UNSET}|$$|$FOO>", env);
        ASSERT_STREQ(x, "<a b||$|$FOO>");
        free(x);

        ASSERT_EQ_INT(pico_replace_env_argv(argv, env, &r), 0);
        ASSERT_EQ_INT((int) pico_strv_length(r), 12);
        ASSERT_STREQ(r[0], "a"); /* $FOO split into two words */
        ASSERT_STREQ(r[1], "b");
        /* $UNSET: no word at all */
        ASSERT_STREQ(r[2], "prea bpost"); /* ${FOO} embedded: one word, unsplit */
        ASSERT_STREQ(r[3], "");           /* ${UNSET} alone: an empty word */
        ASSERT_STREQ(r[4], "$");
        ASSERT_STREQ(r[5], "cost:$5");
        ASSERT_STREQ(r[6], "${FOO}");
        ASSERT_STREQ(r[7], "$FOO/x"); /* not a whole-word name: literal */
        ASSERT_STREQ(r[8], "${FOO");  /* unterminated: literal */
        ASSERT_STREQ(r[9], "x");      /* quoted value: same tokenizer as ExecStart= */
        ASSERT_STREQ(r[10], "y z");
        /* $EMPTY: no word */
        ASSERT_STREQ(r[11], "$");
        r = pico_strv_free(r);

        ASSERT_EQ_INT(pico_replace_env_argv(bad, env, &r), -EINVAL);
        pico_strv_free(r);
}

/* `path`'s whole contents, NUL-terminated. */
static void read_file(const char *path, char *out, size_t out_size) {
        size_t n;
        FILE *f = fopen(path, "re");

        ASSERT_TRUE(f != NULL);
        n = fread(out, 1, out_size - 1, f);
        out[n] = '\0';
        fclose(f);
}

/*
 * End to end, ExecStartPre= and ExecStart= alike: a bare $FOO splits into
 * several arguments, an unset one adds none, ${FOO} is substituted inside a
 * longer word after %-specifiers, $$ is a literal $, and argv[0] (the exec
 * path) is never expanded. The values come from the E2 merge, a file
 * overriding Environment=.
 */
static void test_exec_line_expansion(void) {
        Manager *m;
        Service *s;
        char *dir;
        char unit[4 * PATH_MAX], v[512];
        const char *script = "\"for a; do echo \\\"[$a]\\\"; done > %s/%s\"";
        char pre_script[PATH_MAX + 64], main_script[PATH_MAX + 64];

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        ASSERT_EQ_INT(test_write_file(dir, "argv.env", "SPLIT=\"one two  three\"\n"), 0);
        snprintf(pre_script, sizeof(pre_script), script, dir, "pre.out");
        snprintf(main_script, sizeof(main_script), script, dir, "main.out");
        snprintf(unit,
                 sizeof(unit),
                 "[Unit]\n[Service]\nType=oneshot\n"
                 "Environment=SPLIT=overridden BRACED=val\n"
                 "EnvironmentFile=%s/argv.env\n"
                 "ExecStartPre=/bin/sh -c %s sh $SPLIT\n"
                 "ExecStart=/bin/sh -c %s sh $SPLIT $UNSET %%N-${BRACED} x${UNSET}y literal$$dollar\n",
                 dir,
                 pre_script,
                 main_script);
        s = load_service(m, dir, "argv.service", unit);

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, s, 1000));
        ASSERT_EQ_INT(s->state, SERVICE_DEAD);
        ASSERT_EQ_INT(s->result, SERVICE_SUCCESS);

        /* The stored argv is untouched: expansion is per spawn, on a copy. */
        ASSERT_STREQ(s->exec_start[4], "$SPLIT");

        snprintf(unit, sizeof(unit), "%s/pre.out", dir);
        read_file(unit, v, sizeof(v));
        ASSERT_STREQ(v, "[one]\n[two]\n[three]\n");

        snprintf(unit, sizeof(unit), "%s/main.out", dir);
        read_file(unit, v, sizeof(v));
        ASSERT_STREQ(v, "[one]\n[two]\n[three]\n[argv-val]\n[xy]\n[literal$dollar]\n");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * The hazard E3 names: service_spawn() recognizes the main command by
 * pointer identity, and the expanded argv is a different pointer. A Type=exec
 * unit whose ExecStart= uses $VAR must still get its readiness pipe, and the
 * process must really run the expanded command line.
 */
static void test_exec_type_with_expanded_argv(void) {
        Manager *m;
        Service *a;
        static const char want[] = "/bin/sleep\000100"; /* \000 then "100" */
        char *dir, path[64], cmdline[256];
        ssize_t n;
        int fd;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        a = load_service(
                        m,
                        dir,
                        "exec-var.service",
                        "[Unit]\n[Service]\nType=exec\nEnvironment=SECS=100\nExecStart=/bin/sleep $SECS\n");

        ASSERT_EQ_INT(unit_start(UNIT(a)), 0);
        ASSERT_EQ_INT(a->state, SERVICE_EXEC_START);
        ASSERT_TRUE(a->main_pid > 0);
        ASSERT_TRUE(a->exec_fd >= 0);

        ASSERT_TRUE(drive_until(m, service_running_done, a, 400));
        ASSERT_EQ_INT(a->state, SERVICE_RUNNING);
        ASSERT_TRUE(a->exec_fd < 0);

        snprintf(path, sizeof(path), "/proc/%d/cmdline", (int) a->main_pid);
        fd = open(path, O_RDONLY | O_CLOEXEC);
        ASSERT_TRUE(fd >= 0);
        n = read(fd, cmdline, sizeof(cmdline));
        close(fd);
        ASSERT_EQ_INT((int) n, (int) sizeof(want));
        ASSERT_EQ_INT(memcmp(cmdline, want, sizeof(want)), 0);

        ASSERT_EQ_INT(unit_stop(UNIT(a)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, a, 400));
        ASSERT_EQ_INT(a->state, SERVICE_DEAD);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

int main(void) {
        test_lifecycle_simple();
        test_oneshot_completes_only_on_exit();
        test_remain_after_exit();
        test_b2_signal_amnesty_differs_by_type();
        test_start_timeout();
        test_crash_restart();
        test_b7_start_limit_stops_the_loop();
        test_bug_running_timer_not_cancelled();
        test_b9_service_verify_refuses_no_execstart();
        test_b1_zero_timeout_means_infinity();
        test_condition_skips_start_without_failing();
        test_user_group_drops_privilege();
        test_user_unknown_fails_start_cleanly();
        test_exec_completes_only_after_execve();
        test_exec_failed_execve_never_active();
        test_notify_ready_gates_activation();
        test_notify_timeout_without_ready();
        test_notify_exit_before_ready_is_protocol_failure();
        test_forking_pidfile_gates_activation();
        test_forking_guess_main_pid_from_cgroup();
        test_forking_parent_failure_fails_start();
        test_forking_pidfile_outside_cgroup_refused();
        test_forking_pidfile_of_parent_refused();
        test_env_helpers();
        test_environment_reaches_child();
        test_environment_file_missing_fails_start();
        test_replace_env_helpers();
        test_exec_line_expansion();
        test_exec_type_with_expanded_argv();

        printf("test-service: all checks passed\n");
        return 0;
}
