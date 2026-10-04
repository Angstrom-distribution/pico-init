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

/*
 * units-exec-dash-prefix-ignored: a "-"-prefixed ExecStartPre= that fails
 * must not fail the unit or skip ExecStart= (v30 service.c:2669-2670 sets
 * success=true when the exiting control_command->ignore is set).
 */
static void test_exec_start_pre_dash_ignores_failure(void) {
        Manager *m;
        Service *s;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        s = load_service(
                        m,
                        dir,
                        "dash-pre.service",
                        "[Unit]\nDescription=dash-pre\n"
                        "[Service]\nType=oneshot\nExecStartPre=-/bin/false\nExecStart=/bin/true\n");

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_START_PRE);
        ASSERT_TRUE(s->control_pid > 0);

        ASSERT_TRUE(drive_until(m, service_settled_done, s, 1000));

        /* Reached DEAD (default RemainAfterExit=no), not FAILED: the '-' on
         * ExecStartPre= means /bin/false's exit 1 never counted. */
        ASSERT_EQ_INT(s->state, SERVICE_DEAD);
        ASSERT_EQ_INT(s->result, SERVICE_SUCCESS);
        ASSERT_EQ_INT(unit_active_state(UNIT(s)), UNIT_INACTIVE);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* The unit text is built from a temp dir path of unknown length; the buffers
 * are far larger than any real path, which -Wformat-truncation cannot know. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"

/* Reads a whole small file into a static buffer; "" when it does not exist. */
static const char *slurp(const char *path) {
        static char buf[256];
        FILE *f = fopen(path, "r");
        size_t n = 0;

        if (f) {
                n = fread(buf, 1, sizeof(buf) - 1, f);
                fclose(f);
        }
        buf[n] = '\0';
        return buf;
}

/*
 * Every ExecStartPre= line runs, in file order, before ExecStart=; a "-"
 * line that fails is skipped over and the chain carries on. systemd does the
 * same; a unit shipping `mkdir` then a second step used to lose the first.
 */
static void test_exec_start_pre_runs_every_line_in_order(void) {
        Manager *m;
        Service *s;
        char *dir;
        char out[512], unit[1536];

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        snprintf(out, sizeof out, "%s/order", dir);
        snprintf(unit,
                 sizeof unit,
                 "[Unit]\nDescription=pre-order\n"
                 "[Service]\nType=oneshot\n"
                 "ExecStartPre=/bin/sh -c \"echo one >> %s\"\n"
                 "ExecStartPre=/bin/sh -c \"echo two >> %s\"\n"
                 "ExecStartPre=-/bin/false\n"
                 "ExecStartPre=/bin/sh -c \"echo three >> %s\"\n"
                 "ExecStart=/bin/sh -c \"echo start >> %s\"\n",
                 out,
                 out,
                 out,
                 out);

        m = manager_for(dir);
        s = load_service(m, dir, "pre-order.service", unit);
        ASSERT_EQ_INT(s->n_exec_start_pre, 4);

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_START_PRE);
        ASSERT_TRUE(drive_until(m, service_settled_done, s, 2000));

        ASSERT_EQ_INT(s->state, SERVICE_DEAD);
        ASSERT_EQ_INT(s->result, SERVICE_SUCCESS);
        ASSERT_STREQ(slurp(out), "one\ntwo\nthree\nstart\n");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* The first failing line without "-" ends the chain: later lines and ExecStart= never run. */
static void test_exec_start_pre_failure_stops_the_chain(void) {
        Manager *m;
        Service *s;
        char *dir;
        char out[512], unit[1536];

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        snprintf(out, sizeof out, "%s/stop", dir);
        snprintf(unit,
                 sizeof unit,
                 "[Unit]\nDescription=pre-stop\n"
                 "[Service]\nType=oneshot\n"
                 "ExecStartPre=/bin/sh -c \"echo one >> %s\"\n"
                 "ExecStartPre=/bin/false\n"
                 "ExecStartPre=/bin/sh -c \"echo two >> %s\"\n"
                 "ExecStart=/bin/sh -c \"echo start >> %s\"\n",
                 out,
                 out,
                 out);

        m = manager_for(dir);
        s = load_service(m, dir, "pre-stop.service", unit);

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, s, 2000));

        ASSERT_EQ_INT(s->state, SERVICE_FAILED);
        ASSERT_EQ_INT(s->result, SERVICE_FAILURE_EXIT_CODE);
        ASSERT_STREQ(slurp(out), "one\n");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

#pragma GCC diagnostic pop

/*
 * StandardOutput=null really discards, and StandardError= follows an explicit
 * StandardOutput= when it is not set itself. The child checks its own
 * descriptors through /proc: `$$$$` reaches the shell as `$$`, its own pid.
 */
static void test_standard_output_null_and_error_follows(void) {
        static const struct {
                const char *name;
                const char *settings;
                const char *check;
        } cases[] = {
                { "so-null.service",
                 "StandardOutput=null\n", "test \"$(readlink /proc/$$$$/fd/1)\" = /dev/null && test \"$(readlink /proc/$$$$/fd/2)\" = /dev/null"                   },
                { "se-null.service", "StandardError=null\n",                                                     "test \"$(readlink /proc/$$$$/fd/2)\" = /dev/null" },
        };
        Manager *m;
        char *dir;
        size_t i;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
                char unit[512];
                Service *s;

                snprintf(unit,
                         sizeof unit,
                         "[Unit]\nDescription=stdio\n[Service]\nType=oneshot\n%s"
                         "ExecStart=/bin/sh -c '%s'\n",
                         cases[i].settings,
                         cases[i].check);
                s = load_service(m, dir, cases[i].name, unit);

                ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
                ASSERT_TRUE(drive_until(m, service_settled_done, s, 2000));
                ASSERT_EQ_INT(s->state, SERVICE_DEAD);
                ASSERT_EQ_INT(s->result, SERVICE_SUCCESS);
        }

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

static bool jobs_idle_done(void *userdata) {
        return ((Manager *) userdata)->n_jobs == 0;
}

/*
 * The start limit hit from FAILED: the refusal leaves the state where it
 * was, so no state change finishes the job. Each start goes through a real
 * job, the way a socket trigger or `picoctl start` reaches it; the sixth
 * must still finish, failed, and leave nothing installed.
 */
static void test_start_limit_from_failed_finishes_job(void) {
        Manager *m;
        Service *s;
        char *dir;
        unsigned i;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        s = load_service(m, dir, "limit-job.service", "[Service]\nType=simple\nExecStart=/nonexistent/limit-job\n");

        for (i = 0; i < s->start_limit_burst; i++) {
                ASSERT_EQ_INT(manager_add_job(m, JOB_START, UNIT(s), NULL), 0);
                ASSERT_TRUE(drive_until(m, jobs_idle_done, m, 400));
                ASSERT_TRUE(drive_until(m, service_settled_done, s, 400));
                ASSERT_EQ_INT(s->state, SERVICE_FAILED);
                ASSERT_TRUE(s->result != SERVICE_FAILURE_START_LIMIT);
        }

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, UNIT(s), NULL), 0);
        ASSERT_TRUE(drive_until(m, jobs_idle_done, m, 400));

        ASSERT_TRUE(UNIT(s)->job == NULL);
        ASSERT_EQ_INT(m->n_jobs, 0);
        ASSERT_EQ_INT(s->state, SERVICE_FAILED);
        ASSERT_EQ_INT(s->result, SERVICE_FAILURE_START_LIMIT);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* Alive and not a zombie. */
static bool pid_is_running(pid_t pid) {
        char path[64], buf[512];
        char *rp;
        ssize_t n;
        int fd;

        snprintf(path, sizeof(path), "/proc/%d/stat", (int) pid);
        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return false;
        n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0)
                return false;
        buf[n] = '\0';

        rp = strrchr(buf, ')');
        return rp && rp[1] == ' ' && rp[2] != 'Z' && rp[2] != 'X';
}

/*
 * A stop covers the whole cgroup, not just the main pid (v30's default
 * KillMode=control-group, service_enter_signal()). Here the main process is
 * a shell that dies of SIGTERM and leaves its backgrounded child behind; the
 * unit must not report inactive while that child still runs. SIGHUP is
 * ignored so the shell's exit as session leader of the console cannot kill
 * the child on the stop's behalf.
 */
static void test_stop_signals_whole_cgroup(void) {
        Manager *m;
        Service *s;
        char *dir;
        pid_t pids[8], child = 0;
        size_t n = 0, i;
        int tries;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        s = load_service(
                        m,
                        dir,
                        "stop-tree.service",
                        "[Service]\nType=simple\nExecStart=/bin/sh -c \"trap '' HUP; sleep 100 & wait\"\n");

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_RUNNING);

        if (!s->cgroup) {
                printf("test-service: no cgroup, skipping the whole-cgroup stop check\n");
                ASSERT_EQ_INT(unit_stop(UNIT(s)), 0);
                ASSERT_TRUE(drive_until(m, service_settled_done, s, 400));
                manager_free(m);
                test_rm_rf(dir);
                free(dir);
                return;
        }

        for (tries = 0; tries < 1000 && child == 0; tries++) {
                ASSERT_EQ_INT(cgroup_v2_get_pids(s->cgroup, pids, 8, &n), 0);
                for (i = 0; i < n && i < 8; i++)
                        if (pids[i] != s->main_pid)
                                child = pids[i];
                if (child == 0)
                        test_sleep_ms(2);
        }
        ASSERT_TRUE(child > 0);

        ASSERT_EQ_INT(unit_stop(UNIT(s)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, s, 600));

        ASSERT_EQ_INT(s->state, SERVICE_DEAD);
        ASSERT_EQ_INT(cgroup_v2_is_empty(s->cgroup), 1);
        ASSERT_TRUE(!pid_is_running(child));

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* ExecStart=- on the main process, the '-' most shipped units use (oe-core
 * sshd.service, psplash-systemd.service); a control case without it fails. */
static void test_exec_start_dash_ignores_main_failure(void) {
        Manager *m;
        Service *s, *plain;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        s = load_service(
                        m,
                        dir,
                        "dash-main.service",
                        "[Service]\nType=oneshot\nRemainAfterExit=yes\n"
                        "ExecStartPre=-/bin/false\nExecStart=-/bin/sh -c \"exit 7\"\n");
        plain = load_service(
                        m,
                        dir,
                        "nodash-main.service",
                        "[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sh -c \"exit 7\"\n");

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, UNIT(s), NULL), 0);
        ASSERT_EQ_INT(manager_add_job(m, JOB_START, UNIT(plain), NULL), 0);
        ASSERT_TRUE(drive_until(m, jobs_idle_done, m, 600));

        ASSERT_EQ_INT(s->state, SERVICE_EXITED);
        ASSERT_EQ_INT(s->result, SERVICE_SUCCESS);
        ASSERT_EQ_INT(unit_active_state(UNIT(s)), UNIT_ACTIVE);

        ASSERT_EQ_INT(plain->state, SERVICE_FAILED);
        ASSERT_EQ_INT(plain->result, SERVICE_FAILURE_EXIT_CODE);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* A oneshot that leaves a background child behind: the exit reaps the rest
 * of the cgroup and the stop waits for it to empty, and the start job must
 * still finish (ACTIVATING -> DEACTIVATING -> INACTIVE) so that whatever is
 * ordered after it runs. */
static void test_oneshot_with_leftover_child_finishes_job(void) {
        Manager *m;
        Service *a, *b;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        a = load_service(
                        m,
                        dir,
                        "leftover-a.service",
                        "[Service]\nType=oneshot\nExecStart=/bin/sh -c \"trap '' HUP; sleep 100 & exit 0\"\n");
        b = load_service(
                        m,
                        dir,
                        "leftover-b.service",
                        "[Unit]\nAfter=leftover-a.service\nWants=leftover-a.service\n"
                        "[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n");

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, UNIT(b), NULL), 0);
        ASSERT_TRUE(drive_until(m, jobs_idle_done, m, 600));

        ASSERT_EQ_INT(a->state, SERVICE_DEAD);
        ASSERT_EQ_INT(a->result, SERVICE_SUCCESS);
        ASSERT_EQ_INT(b->state, SERVICE_EXITED);
        ASSERT_EQ_INT(m->n_jobs, 0);
        if (a->cgroup)
                ASSERT_EQ_INT(cgroup_v2_is_empty(a->cgroup), 1);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* TimeoutStopSec= is the only bound on a wedged stop: a service ignoring
 * SIGTERM is killed through its cgroup and ends FAILED with result=timeout. */
static void test_stop_timeout_escalates_to_kill(void) {
        Manager *m;
        Service *s;
        char *dir;
        pid_t pid;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        s = load_service(
                        m,
                        dir,
                        "stop-wedged.service",
                        "[Service]\nType=simple\nTimeoutStopSec=200ms\n"
                        "ExecStart=/bin/sh -c \"trap '' TERM HUP; while :; do sleep 0.05; done\"\n");

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_RUNNING);
        pid = s->main_pid;
        test_sleep_ms(50); /* past the shell's trap */

        ASSERT_EQ_INT(unit_stop(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_STOP);
        ASSERT_TRUE(drive_until(m, service_settled_done, s, 600));

        ASSERT_EQ_INT(s->state, SERVICE_FAILED);
        ASSERT_EQ_INT(s->result, SERVICE_FAILURE_TIMEOUT);
        ASSERT_EQ_INT(s->main_pid, 0);
        ASSERT_TRUE(!pid_is_running(pid));
        ASSERT_TRUE(s->timer_event == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* A restart whose stop half ends FAILED (a daemon exiting non-zero on
 * SIGTERM) is still a restart: the unit comes back under a new pid. */
static void test_restart_of_daemon_failing_on_sigterm(void) {
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
                        "restart-exit3.service",
                        "[Service]\nType=simple\n"
                        "ExecStart=/bin/sh -c \"trap 'exit 3' TERM; while :; do sleep 0.05; done\"\n");

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, UNIT(s), NULL), 0);
        ASSERT_TRUE(drive_until(m, jobs_idle_done, m, 400));
        ASSERT_EQ_INT(s->state, SERVICE_RUNNING);
        pid1 = s->main_pid;
        test_sleep_ms(50); /* past the shell's trap */

        ASSERT_EQ_INT(manager_add_job(m, JOB_RESTART, UNIT(s), NULL), 0);
        ASSERT_TRUE(drive_until(m, jobs_idle_done, m, 600));

        ASSERT_EQ_INT(s->state, SERVICE_RUNNING);
        ASSERT_TRUE(s->main_pid > 0);
        ASSERT_TRUE(s->main_pid != pid1);
        ASSERT_EQ_INT(s->result, SERVICE_SUCCESS);

        ASSERT_EQ_INT(unit_stop(UNIT(s)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, s, 600));

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
 * wait_for_ids() alone races SupplementaryGroups=-only units (no User=/
 * Group=, root keeps uid/gid 0/0): setgroups()/setgid()/setuid() in
 * child_exec() step 10 are then all no-ops on uid/gid, so the very first
 * read already matches want_uid/want_gid, before setgroups() has actually
 * run. Poll until the target gid shows up in Groups: too.
 */
static bool wait_for_ids_and_group(
                pid_t pid, uid_t want_uid, gid_t want_gid, gid_t want_in_groups, char *groups, size_t groups_len) {
        int tries;

        for (tries = 0; tries < 2000; tries++) {
                uid_t uid;
                gid_t gid;

                if (!read_proc_ids(pid, &uid, &gid, groups, groups_len))
                        return false;
                if (uid == want_uid && gid == want_gid && groups_line_has(groups, want_in_groups))
                        return true;
                test_sleep_ms(1);
        }
        return false;
}

/*
 * find_in_default_path() (service-exec.c, systemd since v239): a bare
 * ExecStart= name really execve()s via the search path, not relative to
 * this process's cwd -- proven by actually running it, not just by the
 * parser accepting the directive (test_bare_exec_name_is_accepted() in
 * test-unit-parse.c covers that half). 'true' is chosen because it ships at
 * /usr/bin/true on every Linux this project tests on (oe-core's own
 * usrmerge included) and exits 0 doing nothing, so a wrong resolution --
 * execve() failing ENOENT on "true" relative to cwd, which is always "/"
 * here -- is unambiguous: SERVICE_FAILED, never a false pass from some
 * unrelated file that happens to be named "true" in the cwd.
 */
static void test_bare_exec_name_resolves_via_search_path(void) {
        Manager *m;
        Service *s;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        s = load_service(
                        m,
                        dir,
                        "bareexec.service",
                        "[Unit]\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=true\n");
        ASSERT_STREQ(s->exec_start[0], "true"); /* kept bare -- see unit-parse.c */

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_TRUE(reap_for(s, 3000));

        ASSERT_EQ_INT(s->state, SERVICE_EXITED);
        ASSERT_EQ_INT(s->result, SERVICE_SUCCESS);
        ASSERT_EQ_INT(s->main_exit_code, CLD_EXITED);
        ASSERT_EQ_INT(s->main_exit_status, 0);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * The failure half of the same mechanism: a bare name that is not anywhere
 * in find_in_default_path()'s list must fail exactly the way an absolute
 * missing path already does (PICO_EXIT_EXEC via a failed execve()), not
 * some earlier, different-shaped failure -- see service-exec.c's own
 * comment on child_exec() step 11 for why no special-case code exists for
 * this at all.
 */
static void test_bare_exec_name_not_found_fails_like_missing_absolute(void) {
        Manager *m;
        Service *s;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        s = load_service(
                        m,
                        dir,
                        "bareexec-missing.service",
                        "[Unit]\n[Service]\nType=simple\nExecStart=pico-no-such-binary-5f\n");

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_RUNNING); /* forked; the child fails on its own */
        ASSERT_TRUE(reap_for(s, 3000));

        ASSERT_EQ_INT(s->state, SERVICE_FAILED);
        ASSERT_EQ_INT(s->result, SERVICE_FAILURE_RESOURCES); /* PICO_EXIT_EXEC, our setup, not the workload */
        ASSERT_EQ_INT(s->main_exit_code, CLD_EXITED);
        ASSERT_EQ_INT(s->main_exit_status, PICO_EXIT_EXEC);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
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
 * SupplementaryGroups= (plans/30 R6 extension, upstream's
 * get_supplementary_groups()/enforce_groups()): a name or a numeric gid is
 * appended to the exec'd process's group list, independent of User=/Group=
 * -- picowl.service's own real shape (SupplementaryGroups=video, no
 * User=/Group= at all). Proven the same way test_user_group_drops_privilege()
 * above proves User=/Group=: a real /proc/<pid>/status Groups: line.
 */
static void test_supplementary_groups_applied(void) {
        Manager *m;
        Service *s;
        char *dir;
        char groups[256];
        struct group *gr;
        struct passwd *pw;
        gid_t daemon_gid;
        uid_t want_uid;
        gid_t want_gid;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        gr = getgrnam("daemon");
        ASSERT_TRUE(gr != NULL);
        daemon_gid = gr->gr_gid;

        /* SupplementaryGroups=<name> alone, no User=/Group=: real uid/gid
         * untouched (this process's own), the named group added on top. */
        s = load_service(
                        m,
                        dir,
                        "suppgroups.service",
                        "[Unit]\n[Service]\nType=simple\nSupplementaryGroups=daemon\n"
                        "ExecStart=/bin/sleep 100\n");
        ASSERT_TRUE(s->supplementary_groups != NULL);
        ASSERT_STREQ(s->supplementary_groups[0], "daemon");

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

        want_uid = geteuid();
        want_gid = getegid();

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_RUNNING);
        ASSERT_TRUE(s->main_pid > 0);
        /* want_uid/want_gid are this process's own (no User=/Group=), so
         * they never change -- wait_for_ids() would match instantly,
         * before setgroups() runs. Wait for the group too. */
        ASSERT_TRUE(wait_for_ids_and_group(
                        s->main_pid, want_uid, want_gid, daemon_gid, groups, sizeof(groups)));
        ASSERT_TRUE(groups_line_has(groups, daemon_gid));
        ASSERT_EQ_INT(unit_stop(UNIT(s)), 0);
        ASSERT_TRUE(reap_for(s, 3000));
        ASSERT_EQ_INT(s->state, SERVICE_DEAD);

        /* Numeric form, combined with User=: the account's own membership
         * (initgroups-style, from exec_creds_resolve()'s base list) stays in
         * the group list, SupplementaryGroups= just adds to it. */
        pw = getpwnam("nobody");
        ASSERT_TRUE(pw != NULL);
        {
                char unit[256];

                snprintf(unit,
                         sizeof(unit),
                         "[Unit]\n[Service]\nType=simple\nUser=nobody\nSupplementaryGroups=%lu\n"
                         "ExecStart=/bin/sleep 100\n",
                         (unsigned long) daemon_gid);
                s = load_service(m, dir, "suppgroups-numeric.service", unit);
        }
        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_TRUE(s->main_pid > 0);
        ASSERT_TRUE(wait_for_ids(s->main_pid, pw->pw_uid, pw->pw_gid, groups, sizeof(groups)));
        ASSERT_TRUE(groups_line_has(groups, daemon_gid));
        ASSERT_EQ_INT(unit_stop(UNIT(s)), 0);
        ASSERT_TRUE(reap_for(s, 3000));
        ASSERT_EQ_INT(s->state, SERVICE_DEAD);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* An unknown group name in SupplementaryGroups= fails the start cleanly, the
 * same resources-failure shape test_user_unknown_fails_start_cleanly() above
 * proves for an unknown User=/Group=: nothing is forked, FAILED/RESOURCES. */
static void test_supplementary_groups_unknown_fails_cleanly(void) {
        Manager *m;
        Service *s;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        s = load_service(
                        m,
                        dir,
                        "nosuppgroup.service",
                        "[Unit]\n[Service]\nType=simple\n"
                        "SupplementaryGroups=pico-no-such-group-5f\n"
                        "ExecStart=/bin/sleep 100\n");
        ASSERT_EQ_INT(UNIT(s)->load_state, UNIT_LOADED); /* an unknown group is not a load error */
        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_FAILED);
        ASSERT_EQ_INT(s->result, SERVICE_FAILURE_RESOURCES);
        ASSERT_EQ_INT(s->main_pid, 0);

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
 *
 * setsid(1) only detaches once it has been exec'd, though, and the parent
 * may exit first: the child is still in the leader's process group then
 * and takes the SIGHUP. The fixtures ignore SIGHUP (inherited across fork
 * and exec) so that race cannot kill the daemon. It is why these tests
 * failed intermittently, most often when test-service ran alone and so
 * was the only process holding the console.
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

        write_forkd(dir, "forkd.sh", "#!/bin/sh\ntrap '' HUP\nsetsid sleep 100 &\necho $! > \"$1\"\nexit 0\n");
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

        write_forkd(dir, "forkd.sh", "#!/bin/sh\ntrap '' HUP\nsetsid sleep 100 &\nexit 0\n");
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

        write_forkd(dir, "liar.sh", "#!/bin/sh\ntrap '' HUP\nsetsid sleep 100 &\necho 1 > \"$1\"\nexit 0\n");
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

        write_forkd(dir, "early.sh", "#!/bin/sh\ntrap '' HUP\necho $$ > \"$1\"\nsetsid sleep 100 &\nexit 0\n");
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

/*
 * The spawn-time fd sweep must keep every fd it is handed. child_exec()
 * passes up to PICO_MAX_SOCKET_FDS socket fds plus logd's stdout socket plus
 * the Type=exec pipe; losing the last one closes the exec pipe and a healthy
 * Type=exec daemon is never confirmed started. Run in a child, since it
 * closes most of the process's fds.
 */
static void test_close_all_except_keeps_every_fd(void) {
        enum { N_KEEP = PICO_MAX_SOCKET_FDS + 2, N_OPEN = N_KEEP + 4 };
        pid_t pid;
        int status = 0;

        pid = fork();
        ASSERT_TRUE(pid >= 0);
        if (pid == 0) {
                int fds[N_OPEN], keep[N_KEEP];
                unsigned i, n_keep = 0;

                for (i = 0; i < N_OPEN; i++) {
                        fds[i] = open("/dev/null", O_RDONLY);
                        if (fds[i] < 0)
                                _exit(10);
                }
                /* four fds dropped from among the low ones, the highest kept
                 * last in the list */
                for (i = 0; i < N_OPEN; i++)
                        if (!(i % 5 == 1 && i / 5 < 4))
                                keep[n_keep++] = fds[i];
                if (n_keep != N_KEEP)
                        _exit(11);

                pico_close_all_except(keep, n_keep, 4096);

                for (i = 0; i < n_keep; i++)
                        if (fcntl(keep[i], F_GETFD) < 0)
                                _exit(20 + (int) i);
                for (i = 1; i < 20; i += 5)
                        if (fcntl(fds[i], F_GETFD) >= 0)
                                _exit(12);
                _exit(0);
        }

        ASSERT_EQ_INT(waitpid(pid, &status, 0), pid);
        ASSERT_TRUE(WIFEXITED(status));
        ASSERT_EQ_INT(WEXITSTATUS(status), 0);
}

/*
 * ExecStop=, the normal stop: every line runs, in order, as the control
 * process, while the main process is still alive and before anything is
 * signalled. The daemon's own TERM trap appends after both lines, so the
 * file's order is the proof. The oneshot + RemainAfterExit=yes half is the
 * case with nothing to signal at all, where ExecStop= is the only teardown
 * there is (plans/29's usb-multi-gadget).
 */
static void test_exec_stop_runs_before_signal(void) {
        Manager *m;
        Service *s, *o;
        char *dir;
        char unit[4 * PATH_MAX], path[PATH_MAX], v[256];
        pid_t main_pid;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        snprintf(unit,
                 sizeof(unit),
                 "[Service]\nType=simple\n"
                 "ExecStart=/bin/sh -c \"trap 'echo term >> %s/order; exit 0' TERM; "
                 "while :; do sleep 0.05; done\"\n"
                 "ExecStop=/bin/sh -c \"echo stop-one >> %s/order\"\n"
                 "ExecStop=/bin/sh -c \"echo stop-two >> %s/order\"\n",
                 dir,
                 dir,
                 dir);
        s = load_service(m, dir, "stop-cmd.service", unit);

        snprintf(unit,
                 sizeof(unit),
                 "[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n"
                 "ExecStop=/bin/sh -c \"echo down > %s/oneshot\"\n",
                 dir);
        o = load_service(m, dir, "stop-oneshot.service", unit);

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_RUNNING);
        main_pid = s->main_pid;
        test_sleep_ms(100); /* past the shell's trap */

        ASSERT_EQ_INT(unit_stop(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_EXEC_STOP);
        ASSERT_EQ_INT(unit_active_state(UNIT(s)), UNIT_DEACTIVATING);
        ASSERT_TRUE(s->control_pid > 0);
        ASSERT_EQ_INT(s->main_pid, main_pid); /* not signalled, not reaped */
        ASSERT_EQ_INT(unit_stop(UNIT(s)), 0); /* already stopping */
        ASSERT_EQ_INT(unit_start(UNIT(s)), -EAGAIN);

        ASSERT_TRUE(drive_until(m, service_settled_done, s, 600));
        ASSERT_EQ_INT(s->state, SERVICE_DEAD);
        ASSERT_EQ_INT(s->result, SERVICE_SUCCESS);
        ASSERT_EQ_INT(s->main_pid, 0);
        ASSERT_EQ_INT(s->control_pid, 0);
        ASSERT_TRUE(!pid_is_running(main_pid));

        snprintf(path, sizeof(path), "%s/order", dir);
        read_file(path, v, sizeof(v));
        ASSERT_STREQ(v, "stop-one\nstop-two\nterm\n");

        ASSERT_EQ_INT(unit_start(UNIT(o)), 0);
        ASSERT_TRUE(reap_for(o, 3000));
        ASSERT_EQ_INT(o->state, SERVICE_EXITED);

        ASSERT_EQ_INT(unit_stop(UNIT(o)), 0);
        ASSERT_EQ_INT(o->state, SERVICE_EXEC_STOP);
        ASSERT_TRUE(drive_until(m, service_settled_done, o, 600));
        ASSERT_EQ_INT(o->state, SERVICE_DEAD);
        ASSERT_EQ_INT(o->result, SERVICE_SUCCESS);

        snprintf(path, sizeof(path), "%s/oneshot", dir);
        read_file(path, v, sizeof(v));
        ASSERT_STREQ(v, "down\n");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * No ExecStop=: exactly the old stop path. A daemon goes straight to
 * SERVICE_STOP with SIGTERM already sent and no control process, and an
 * exited oneshot goes straight to DEAD.
 */
static void test_no_exec_stop_is_unchanged(void) {
        Manager *m;
        Service *s, *o;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        s = load_service(m, dir, "plain-stop.service", "[Service]\nType=simple\nExecStart=/bin/sleep 100\n");
        o = load_service(
                        m,
                        dir,
                        "plain-oneshot.service",
                        "[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n");
        ASSERT_EQ_INT(s->n_exec_stop, 0);

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_EQ_INT(unit_stop(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_STOP);
        ASSERT_EQ_INT(s->control_pid, 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, s, 600));
        ASSERT_EQ_INT(s->state, SERVICE_DEAD);
        ASSERT_EQ_INT(s->result, SERVICE_SUCCESS);

        ASSERT_EQ_INT(unit_start(UNIT(o)), 0);
        ASSERT_TRUE(reap_for(o, 3000));
        ASSERT_EQ_INT(o->state, SERVICE_EXITED);
        ASSERT_EQ_INT(unit_stop(UNIT(o)), 0);
        ASSERT_EQ_INT(o->state, SERVICE_DEAD);
        ASSERT_EQ_INT(o->result, SERVICE_SUCCESS);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * A failing ExecStop= line ends the chain and fails the unit, but never
 * keeps it up: the daemon is still signalled and the unit still reaches a
 * stopped state. With '-' the failure does not count and the chain goes on.
 */
static void test_exec_stop_failure_still_stops(void) {
        Manager *m;
        Service *s, *d;
        char *dir;
        char unit[2 * PATH_MAX], path[PATH_MAX], v[64];
        pid_t main_pid;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        snprintf(unit,
                 sizeof(unit),
                 "[Service]\nType=simple\nExecStart=/bin/sleep 100\n"
                 "ExecStop=/bin/false\nExecStop=/bin/sh -c \"echo x > %s/skipped\"\n",
                 dir);
        s = load_service(m, dir, "stop-fails.service", unit);

        snprintf(unit,
                 sizeof(unit),
                 "[Service]\nType=simple\nExecStart=/bin/sleep 100\n"
                 "ExecStop=-/bin/false\nExecStop=/bin/sh -c \"echo ran > %s/after-dash\"\n",
                 dir);
        d = load_service(m, dir, "stop-dash.service", unit);

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        main_pid = s->main_pid;
        ASSERT_EQ_INT(unit_stop(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_EXEC_STOP);
        ASSERT_TRUE(drive_until(m, service_settled_done, s, 600));
        ASSERT_EQ_INT(s->state, SERVICE_FAILED);
        ASSERT_EQ_INT(s->result, SERVICE_FAILURE_EXIT_CODE);
        ASSERT_EQ_INT(s->main_pid, 0);
        ASSERT_TRUE(!pid_is_running(main_pid));
        snprintf(path, sizeof(path), "%s/skipped", dir);
        ASSERT_TRUE(access(path, F_OK) < 0);

        ASSERT_EQ_INT(unit_start(UNIT(d)), 0);
        ASSERT_EQ_INT(unit_stop(UNIT(d)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, d, 600));
        ASSERT_EQ_INT(d->state, SERVICE_DEAD);
        ASSERT_EQ_INT(d->result, SERVICE_SUCCESS);
        snprintf(path, sizeof(path), "%s/after-dash", dir);
        read_file(path, v, sizeof(v));
        ASSERT_STREQ(v, "ran\n");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * The other entry points, each upstream's: a clean exit without
 * RemainAfterExit= runs ExecStop= too; a stop mid-start skips it and
 * signals at once; and TimeoutStopSec= bounds a wedged ExecStop=, then
 * SIGTERM reaches both it and the daemon.
 */
static void test_exec_stop_entry_points(void) {
        Manager *m;
        Service *e, *mid, *w;
        char *dir;
        char unit[2 * PATH_MAX], path[PATH_MAX], v[64];
        pid_t main_pid;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        snprintf(unit,
                 sizeof(unit),
                 "[Service]\nType=oneshot\nExecStart=/bin/true\n"
                 "ExecStop=/bin/sh -c \"echo after > %s/exited\"\n",
                 dir);
        e = load_service(m, dir, "stop-exited.service", unit);

        snprintf(unit,
                 sizeof(unit),
                 "[Service]\nType=oneshot\nExecStart=/bin/sleep 100\n"
                 "ExecStop=/bin/sh -c \"echo wrong > %s/midstart\"\n",
                 dir);
        mid = load_service(m, dir, "stop-midstart.service", unit);

        w = load_service(
                        m,
                        dir,
                        "stop-wedged-cmd.service",
                        "[Service]\nType=simple\nTimeoutStopSec=200ms\nExecStart=/bin/sleep 100\n"
                        "ExecStop=/bin/sleep 100\n");

        ASSERT_EQ_INT(unit_start(UNIT(e)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, e, 600));
        ASSERT_EQ_INT(e->state, SERVICE_DEAD);
        ASSERT_EQ_INT(e->result, SERVICE_SUCCESS);
        snprintf(path, sizeof(path), "%s/exited", dir);
        read_file(path, v, sizeof(v));
        ASSERT_STREQ(v, "after\n");

        ASSERT_EQ_INT(unit_start(UNIT(mid)), 0);
        ASSERT_EQ_INT(mid->state, SERVICE_EXEC_START);
        ASSERT_EQ_INT(unit_stop(UNIT(mid)), 0);
        ASSERT_EQ_INT(mid->state, SERVICE_STOP);
        ASSERT_EQ_INT(mid->control_pid, 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, mid, 600));
        snprintf(path, sizeof(path), "%s/midstart", dir);
        ASSERT_TRUE(access(path, F_OK) < 0);

        ASSERT_EQ_INT(unit_start(UNIT(w)), 0);
        main_pid = w->main_pid;
        ASSERT_EQ_INT(unit_stop(UNIT(w)), 0);
        ASSERT_EQ_INT(w->state, SERVICE_EXEC_STOP);
        ASSERT_TRUE(drive_until(m, service_settled_done, w, 600));
        ASSERT_EQ_INT(w->state, SERVICE_FAILED);
        ASSERT_EQ_INT(w->result, SERVICE_FAILURE_TIMEOUT);
        ASSERT_EQ_INT(w->main_pid, 0);
        ASSERT_EQ_INT(w->control_pid, 0);
        ASSERT_TRUE(!pid_is_running(main_pid));
        ASSERT_TRUE(w->timer_event == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

static bool service_stop_post_done(void *userdata) {
        return ((Service *) userdata)->state == SERVICE_STOP_POST;
}

static bool service_exited_done(void *userdata) {
        return ((Service *) userdata)->state == SERVICE_EXITED;
}

/* A SIGKILLed pid is gone within a second, zombie included once reaped. */
static bool pid_dies_within(pid_t pid, int timeout_ms) {
        int waited;

        for (waited = 0; waited < timeout_ms; waited += 10) {
                if (!pid_is_running(pid))
                        return true;
                test_sleep_ms(10);
        }

        return !pid_is_running(pid);
}

/*
 * ExecStopPost=, the normal stop: it runs after ExecStop= and after the
 * daemon has exited, every line in order, and the unit reaches DEAD only
 * once the last line has. The daemon's own TERM trap writes between the two
 * phases, so the file's order is the proof; the first line sleeps so the
 * STOP_POST state itself can be observed with the main pid already gone.
 */
static void test_exec_stop_post_runs_last(void) {
        Manager *m;
        Service *s;
        char *dir;
        char unit[4 * PATH_MAX], path[PATH_MAX], v[256];
        pid_t main_pid;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        snprintf(unit,
                 sizeof(unit),
                 "[Service]\nType=simple\n"
                 "ExecStart=/bin/sh -c \"trap 'echo term >> %s/order; exit 0' TERM; "
                 "while :; do sleep 0.05; done\"\n"
                 "ExecStop=/bin/sh -c \"echo stop >> %s/order\"\n"
                 "ExecStopPost=/bin/sh -c \"echo post-one >> %s/order; sleep 0.2\"\n"
                 "ExecStopPost=/bin/sh -c \"echo post-two >> %s/order\"\n",
                 dir,
                 dir,
                 dir,
                 dir);
        s = load_service(m, dir, "stop-post.service", unit);
        ASSERT_EQ_INT(s->n_exec_stop_post, 2);

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_RUNNING);
        main_pid = s->main_pid;
        test_sleep_ms(100); /* past the shell's trap */

        ASSERT_EQ_INT(unit_stop(UNIT(s)), 0);
        ASSERT_EQ_INT(s->state, SERVICE_EXEC_STOP);

        ASSERT_TRUE(drive_until(m, service_stop_post_done, s, 600));
        ASSERT_EQ_INT(unit_active_state(UNIT(s)), UNIT_DEACTIVATING);
        ASSERT_STREQ(service_state_to_string(s->state), "stop-post");
        ASSERT_EQ_INT(s->main_pid, 0);
        ASSERT_TRUE(s->control_pid > 0);
        ASSERT_TRUE(!pid_is_running(main_pid));
        ASSERT_EQ_INT(unit_stop(UNIT(s)), 0); /* already stopping */
        ASSERT_EQ_INT(unit_start(UNIT(s)), -EAGAIN);

        ASSERT_TRUE(drive_until(m, service_settled_done, s, 600));
        ASSERT_EQ_INT(s->state, SERVICE_DEAD);
        ASSERT_EQ_INT(s->result, SERVICE_SUCCESS);
        ASSERT_EQ_INT(s->control_pid, 0);
        ASSERT_TRUE(s->timer_event == NULL);

        snprintf(path, sizeof(path), "%s/order", dir);
        read_file(path, v, sizeof(v));
        ASSERT_STREQ(v, "stop\nterm\npost-one\npost-two\n");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * ExecStopPost= is the cleanup for a start that never got anywhere too: a
 * failed ExecStartPre= and a crashed daemon both run it, and both still end
 * FAILED with the original result. Whatever it leaves behind in the cgroup
 * is killed before the unit is declared dead.
 */
static void test_exec_stop_post_after_failure(void) {
        Manager *m;
        Service *pre, *crash, *leak;
        char *dir;
        char unit[2 * PATH_MAX], path[PATH_MAX], v[64];
        pid_t leftover;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        snprintf(unit,
                 sizeof(unit),
                 "[Service]\nType=oneshot\nExecStartPre=/bin/false\n"
                 "ExecStart=/bin/sh -c \"echo wrong > %s/started\"\n"
                 "ExecStopPost=/bin/sh -c \"echo cleaned > %s/pre-cleaned\"\n",
                 dir,
                 dir);
        pre = load_service(m, dir, "post-pre-fails.service", unit);

        snprintf(unit,
                 sizeof(unit),
                 "[Service]\nType=simple\nExecStart=/bin/sh -c \"sleep 0.1; exit 3\"\n"
                 "ExecStopPost=/bin/sh -c \"echo cleaned > %s/crash-cleaned\"\n",
                 dir);
        crash = load_service(m, dir, "post-crash.service", unit);

        write_forkd(dir, "leak.sh", "#!/bin/sh\ntrap '' HUP\nsleep 100 &\necho $! > \"$1\"\n");
        snprintf(unit,
                 sizeof(unit),
                 "[Service]\nType=simple\nExecStart=/bin/sleep 100\n"
                 "ExecStopPost=%s/leak.sh %s/leftover\n",
                 dir,
                 dir);
        leak = load_service(m, dir, "post-leak.service", unit);

        ASSERT_EQ_INT(unit_start(UNIT(pre)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, pre, 600));
        ASSERT_EQ_INT(pre->state, SERVICE_FAILED);
        ASSERT_EQ_INT(pre->result, SERVICE_FAILURE_EXIT_CODE);
        snprintf(path, sizeof(path), "%s/pre-cleaned", dir);
        read_file(path, v, sizeof(v));
        ASSERT_STREQ(v, "cleaned\n");
        snprintf(path, sizeof(path), "%s/started", dir);
        ASSERT_TRUE(access(path, F_OK) < 0);

        ASSERT_EQ_INT(unit_start(UNIT(crash)), 0);
        ASSERT_EQ_INT(crash->state, SERVICE_RUNNING);
        ASSERT_TRUE(drive_until(m, service_settled_done, crash, 600));
        ASSERT_EQ_INT(crash->state, SERVICE_FAILED);
        ASSERT_EQ_INT(crash->result, SERVICE_FAILURE_EXIT_CODE);
        snprintf(path, sizeof(path), "%s/crash-cleaned", dir);
        read_file(path, v, sizeof(v));
        ASSERT_STREQ(v, "cleaned\n");

        ASSERT_EQ_INT(unit_start(UNIT(leak)), 0);
        ASSERT_EQ_INT(unit_stop(UNIT(leak)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, leak, 600));
        ASSERT_EQ_INT(leak->state, SERVICE_DEAD);
        ASSERT_EQ_INT(leak->result, SERVICE_SUCCESS);
        snprintf(path, sizeof(path), "%s/leftover", dir);
        leftover = read_pid_file(path);
        ASSERT_TRUE(leftover > 0);
        ASSERT_TRUE(pid_dies_within(leftover, 1000));

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * A failing ExecStopPost= line fails the unit and ends the chain; with '-'
 * it does neither. TimeoutStopSec= bounds a wedged line: it is killed, no
 * further line runs, and the unit ends FAILED with result=timeout.
 */
static void test_exec_stop_post_failure_and_timeout(void) {
        Manager *m;
        Service *s, *d, *w;
        char *dir;
        char unit[2 * PATH_MAX], path[PATH_MAX], v[64];

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        snprintf(unit,
                 sizeof(unit),
                 "[Service]\nType=simple\nExecStart=/bin/sleep 100\n"
                 "ExecStopPost=/bin/false\nExecStopPost=/bin/sh -c \"echo x > %s/skipped\"\n",
                 dir);
        s = load_service(m, dir, "post-fails.service", unit);

        snprintf(unit,
                 sizeof(unit),
                 "[Service]\nType=simple\nExecStart=/bin/sleep 100\n"
                 "ExecStopPost=-/bin/false\nExecStopPost=/bin/sh -c \"echo ran > %s/after-dash\"\n",
                 dir);
        d = load_service(m, dir, "post-dash.service", unit);

        snprintf(unit,
                 sizeof(unit),
                 "[Service]\nType=simple\nTimeoutStopSec=200ms\nExecStart=/bin/sleep 100\n"
                 "ExecStopPost=-/bin/sleep 100\nExecStopPost=/bin/sh -c \"echo x > %s/after-timeout\"\n",
                 dir);
        w = load_service(m, dir, "post-wedged.service", unit);

        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);
        ASSERT_EQ_INT(unit_stop(UNIT(s)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, s, 600));
        ASSERT_EQ_INT(s->state, SERVICE_FAILED);
        ASSERT_EQ_INT(s->result, SERVICE_FAILURE_EXIT_CODE);
        snprintf(path, sizeof(path), "%s/skipped", dir);
        ASSERT_TRUE(access(path, F_OK) < 0);

        ASSERT_EQ_INT(unit_start(UNIT(d)), 0);
        ASSERT_EQ_INT(unit_stop(UNIT(d)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, d, 600));
        ASSERT_EQ_INT(d->state, SERVICE_DEAD);
        ASSERT_EQ_INT(d->result, SERVICE_SUCCESS);
        snprintf(path, sizeof(path), "%s/after-dash", dir);
        read_file(path, v, sizeof(v));
        ASSERT_STREQ(v, "ran\n");

        ASSERT_EQ_INT(unit_start(UNIT(w)), 0);
        ASSERT_EQ_INT(unit_stop(UNIT(w)), 0);
        ASSERT_TRUE(drive_until(m, service_stop_post_done, w, 600));
        ASSERT_TRUE(w->control_pid > 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, w, 600));
        ASSERT_EQ_INT(w->state, SERVICE_FAILED);
        ASSERT_EQ_INT(w->result, SERVICE_FAILURE_TIMEOUT);
        ASSERT_EQ_INT(w->control_pid, 0);
        ASSERT_TRUE(w->timer_event == NULL);
        snprintf(path, sizeof(path), "%s/after-timeout", dir);
        ASSERT_TRUE(access(path, F_OK) < 0);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * ExecCondition= exiting 1-254 skips the start: nothing after it runs, the
 * unit ends DEAD with Result=exec-condition rather than FAILED,
 * Restart=on-failure does not fire, ExecStopPost= still cleans up, and the
 * start job completes -- a unit that Requires= it still starts, as it would
 * not after a failure.
 */
static void test_exec_condition_skips_start(void) {
        Manager *m;
        Service *a, *b;
        char *dir;
        char unit[4 * PATH_MAX], path[PATH_MAX], v[256];

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        snprintf(unit,
                 sizeof(unit),
                 "[Service]\nType=oneshot\nRemainAfterExit=yes\nRestart=on-failure\nRestartSec=0\n"
                 "ExecCondition=/bin/sh -c \"echo cond >> %s/order; exit 1\"\n"
                 "ExecStartPre=/bin/sh -c \"echo pre >> %s/order\"\n"
                 "ExecStart=/bin/sh -c \"echo start >> %s/order\"\n"
                 "ExecStopPost=/bin/sh -c \"echo post >> %s/order\"\n",
                 dir,
                 dir,
                 dir,
                 dir);
        a = load_service(m, dir, "cond-a.service", unit);
        b = load_service(
                        m,
                        dir,
                        "cond-b.service",
                        "[Unit]\nRequires=cond-a.service\nAfter=cond-a.service\n"
                        "[Service]\nType=simple\nExecStart=/bin/sleep 100\n");
        ASSERT_EQ_INT(a->n_exec_condition, 1);

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, UNIT(b), NULL), 0);
        ASSERT_EQ_INT(manager_dispatch_run_queue(m), 1); /* only a ran */
        ASSERT_EQ_INT(a->state, SERVICE_CONDITION);
        ASSERT_EQ_INT(unit_active_state(UNIT(a)), UNIT_ACTIVATING);
        ASSERT_TRUE(a->control_pid > 0);
        ASSERT_EQ_INT(unit_start(UNIT(a)), 0); /* already starting */

        ASSERT_TRUE(drive_until(m, jobs_idle_done, m, 600));
        ASSERT_EQ_INT(a->state, SERVICE_DEAD);
        ASSERT_EQ_INT(unit_active_state(UNIT(a)), UNIT_INACTIVE);
        ASSERT_EQ_INT(a->result, SERVICE_SKIP_CONDITION);
        ASSERT_STREQ(service_result_to_string(a->result), "exec-condition");
        ASSERT_EQ_INT(a->n_restarts, 0);
        ASSERT_TRUE(!UNIT(a)->condition_result);
        ASSERT_EQ_INT(b->state, SERVICE_RUNNING);

        snprintf(path, sizeof(path), "%s/order", dir);
        read_file(path, v, sizeof(v));
        ASSERT_STREQ(v, "cond\npost\n");

        ASSERT_EQ_INT(unit_stop(UNIT(b)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, b, 600));

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * ExecCondition='s exit space, line by line. Every line must pass, '-'
 * makes a line pass whatever it returns, and the first line that does not
 * pass ends the chain (254 still skips). 255, a signal, and a condition
 * binary that cannot be exec'd at all (pico-init's own exit 203, inside
 * 1-254 but never the command's answer) fail the unit instead.
 */
static void test_exec_condition_exit_space(void) {
        Manager *m;
        Service *pass, *skip, *hard, *sig, *missing;
        char *dir;
        char unit[2 * PATH_MAX], path[PATH_MAX], v[64];

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        snprintf(unit,
                 sizeof(unit),
                 "[Service]\nType=oneshot\nRemainAfterExit=yes\n"
                 "ExecCondition=/bin/true\nExecCondition=-/bin/false\n"
                 "ExecCondition=/bin/sh -c \"echo third >> %s/pass\"\n"
                 "ExecStart=/bin/sh -c \"echo start >> %s/pass\"\n",
                 dir,
                 dir);
        pass = load_service(m, dir, "cond-pass.service", unit);

        snprintf(unit,
                 sizeof(unit),
                 "[Service]\nType=oneshot\nExecCondition=/bin/sh -c \"exit 254\"\n"
                 "ExecCondition=/bin/sh -c \"echo wrong > %s/second\"\n"
                 "ExecStart=/bin/true\n",
                 dir);
        skip = load_service(m, dir, "cond-254.service", unit);

        hard = load_service(
                        m,
                        dir,
                        "cond-255.service",
                        "[Service]\nType=oneshot\nExecCondition=/bin/sh -c \"exit 255\"\n"
                        "ExecStart=/bin/true\n");
        sig = load_service(
                        m,
                        dir,
                        "cond-signal.service",
                        "[Service]\nType=oneshot\nExecCondition=/bin/sh -c \"kill -KILL $$$$\"\n"
                        "ExecStart=/bin/true\n");
        missing = load_service(
                        m,
                        dir,
                        "cond-missing.service",
                        "[Service]\nType=oneshot\nExecCondition=/nonexistent/pico-init-no-such-condition\n"
                        "ExecStart=/bin/true\n");

        ASSERT_EQ_INT(unit_start(UNIT(pass)), 0);
        ASSERT_TRUE(drive_until(m, service_exited_done, pass, 600));
        ASSERT_EQ_INT(pass->state, SERVICE_EXITED);
        ASSERT_EQ_INT(pass->result, SERVICE_SUCCESS);
        snprintf(path, sizeof(path), "%s/pass", dir);
        read_file(path, v, sizeof(v));
        ASSERT_STREQ(v, "third\nstart\n");

        ASSERT_EQ_INT(unit_start(UNIT(skip)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, skip, 600));
        ASSERT_EQ_INT(skip->state, SERVICE_DEAD);
        ASSERT_EQ_INT(skip->result, SERVICE_SKIP_CONDITION);
        snprintf(path, sizeof(path), "%s/second", dir);
        ASSERT_TRUE(access(path, F_OK) < 0);

        ASSERT_EQ_INT(unit_start(UNIT(hard)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, hard, 600));
        ASSERT_EQ_INT(hard->state, SERVICE_FAILED);
        ASSERT_EQ_INT(hard->result, SERVICE_FAILURE_EXIT_CODE);

        ASSERT_EQ_INT(unit_start(UNIT(sig)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, sig, 600));
        ASSERT_EQ_INT(sig->state, SERVICE_FAILED);
        ASSERT_EQ_INT(sig->result, SERVICE_FAILURE_SIGNAL);

        ASSERT_EQ_INT(unit_start(UNIT(missing)), 0);
        ASSERT_TRUE(drive_until(m, service_settled_done, missing, 600));
        ASSERT_EQ_INT(missing->state, SERVICE_FAILED);
        ASSERT_EQ_INT(missing->result, SERVICE_FAILURE_RESOURCES);

        ASSERT_EQ_INT(unit_stop(UNIT(pass)), 0);
        ASSERT_EQ_INT(pass->state, SERVICE_DEAD);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

int main(void) {
        test_close_all_except_keeps_every_fd();
        test_lifecycle_simple();
        test_oneshot_completes_only_on_exit();
        test_exec_start_pre_dash_ignores_failure();
        test_exec_start_pre_runs_every_line_in_order();
        test_exec_start_pre_failure_stops_the_chain();
        test_standard_output_null_and_error_follows();
        test_remain_after_exit();
        test_b2_signal_amnesty_differs_by_type();
        test_start_timeout();
        test_crash_restart();
        test_b7_start_limit_stops_the_loop();
        test_start_limit_from_failed_finishes_job();
        test_stop_signals_whole_cgroup();
        test_exec_start_dash_ignores_main_failure();
        test_oneshot_with_leftover_child_finishes_job();
        test_stop_timeout_escalates_to_kill();
        test_restart_of_daemon_failing_on_sigterm();
        test_bug_running_timer_not_cancelled();
        test_b9_service_verify_refuses_no_execstart();
        test_b1_zero_timeout_means_infinity();
        test_condition_skips_start_without_failing();
        test_bare_exec_name_resolves_via_search_path();
        test_bare_exec_name_not_found_fails_like_missing_absolute();
        test_user_group_drops_privilege();
        test_user_unknown_fails_start_cleanly();
        test_supplementary_groups_applied();
        test_supplementary_groups_unknown_fails_cleanly();
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
        test_exec_stop_runs_before_signal();
        test_no_exec_stop_is_unchanged();
        test_exec_stop_failure_still_stops();
        test_exec_stop_entry_points();
        test_exec_stop_post_runs_last();
        test_exec_stop_post_after_failure();
        test_exec_stop_post_failure_and_timeout();
        test_exec_condition_skips_start();
        test_exec_condition_exit_space();

        printf("test-service: all checks passed\n");
        return 0;
}
