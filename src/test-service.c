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
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

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

        printf("test-service: all checks passed\n");
        return 0;
}
