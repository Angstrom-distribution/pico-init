/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Orderly shutdown (manager-shutdown.c), driven through the real
 * manager_loop(): which stop jobs a shutdown waits for, what it does with
 * start jobs still queued when it arrives, the signal-to-objective mapping,
 * and the deadline that bounds a wedged unit.
 *
 * Every loop run here carries a safety timer that forces MANAGER_EXIT, so a
 * regression fails an assertion on the returned objective instead of hanging
 * the suite.
 */

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "job.h"
#include "manager.h"
#include "sd-event.h"
#include "service.h"
#include "test-util.h"
#include "timer.h"
#include "unit.h"

static void use_private_cgroup_root(Manager *m, const char *tag, char *out, size_t out_size) {
        int n = snprintf(out, out_size, "/sys/fs/cgroup/pico-shutdown-test-%s-%lld", tag, (long long) getpid());

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

static Manager *manager_for(const char *dir, const char *tag, char *cgroup_root, size_t cgroup_root_size) {
        const char * const path[] = { dir, NULL };
        Manager *m = NULL;

        ASSERT_EQ_INT(manager_new(&m), 0);
        ASSERT_TRUE(m != NULL);
        ASSERT_EQ_INT(manager_set_unit_path(m, path), 0);
        use_private_cgroup_root(m, tag, cgroup_root, cgroup_root_size);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        return m;
}

static void force_exit(void *userdata, usec_t now) {
        Manager *m = userdata;

        (void) now;
        m->objective = MANAGER_EXIT;
}

/* Run the loop until it adopts an objective by itself, or `budget_usec`
 * passes and force_exit() ends it with MANAGER_EXIT. */
static int loop_with_budget(Manager *m, usec_t budget_usec) {
        m->objective = MANAGER_RUNNING;
        ASSERT_EQ_INT(pico_timer_add(m->timer, now_monotonic() + budget_usec, force_exit, m, NULL), 0);

        return manager_loop(m);
}

/* A Type=simple unit running `/bin/sh <dir>/<script>`, plus `extra` lines in
 * [Service]. A script file sidesteps nested quoting in ExecStart=. */
static void write_unit_running_script(const char *dir, const char *unit, const char *script, const char *extra) {
        char text[PATH_MAX + 256];
        int n;

        n = snprintf(text, sizeof(text), "[Service]\nType=simple\nExecStart=/bin/sh %s/%s\n%s", dir, script, extra);
        ASSERT_TRUE(n > 0 && (size_t) n < sizeof(text));
        ASSERT_EQ_INT(test_write_file(dir, unit, text), 0);
}

/* Bring `u` up and let every job settle. */
static void start_and_settle(Manager *m, Unit *u) {
        ASSERT_EQ_INT(manager_add_job(m, JOB_START, u, NULL), 0);
        ASSERT_EQ_INT(manager_dispatch_run_queue(m) > 0, 1);
        ASSERT_EQ_INT(m->n_jobs, 0);
}

/*
 * A stop job whose unit_stop() only sent SIGTERM is RUNNING and off the run
 * queue. With nothing else queued behind it, a shutdown that only watched the
 * run queue declared itself finished at once and returned while the service
 * was still handling SIGTERM.
 */
static void test_shutdown_waits_for_running_stop_job(void) {
        char cgroup_root[PATH_MAX];
        Manager *m;
        char *dir;
        Unit *a;
        pid_t pid;
        int objective;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        /* Takes about half a second to honour SIGTERM. */
        ASSERT_EQ_INT(test_write_file(dir,
                                      "slow-term.sh",
                                      "trap 'sleep 0.5; exit 0' TERM\nwhile :; do sleep 0.1; done\n"),
                      0);
        write_unit_running_script(dir, "a.service", "slow-term.sh", "");

        m = manager_for(dir, "running-stop", cgroup_root, sizeof(cgroup_root));
        a = manager_get_unit(m, "a.service");
        ASSERT_TRUE(a != NULL);

        start_and_settle(m, a);
        ASSERT_EQ_INT(SERVICE(a)->state, SERVICE_RUNNING);
        pid = SERVICE(a)->main_pid;
        ASSERT_TRUE(pid > 0);

        /* let the shell install its trap before it is signalled */
        usleep(200 * 1000);

        ASSERT_EQ_INT(manager_shutdown(m, MANAGER_POWEROFF), 0);
        objective = loop_with_budget(m, 5 * USEC_PER_SEC);

        ASSERT_EQ_INT(objective, MANAGER_POWEROFF);
        ASSERT_EQ_INT(m->n_jobs, 0);
        ASSERT_EQ_INT(unit_active_state(a), UNIT_INACTIVE);

        /* reaped by the loop, not merely signalled */
        ASSERT_TRUE(kill(pid, 0) < 0);

        manager_free(m);
        free_private_cgroup_root(cgroup_root);
        test_rm_rf(dir);
        free(dir);
}

/*
 * A shutdown arriving mid-boot: y's start job is still WAITING behind x. The
 * stop sweep skipped y because it is inactive, so once x's stop finished y
 * was started, during the shutdown, and left running at reboot.
 */
static void test_shutdown_cancels_waiting_start_jobs(void) {
        char cgroup_root[PATH_MAX];
        Manager *m;
        char *dir;
        Unit *t, *x, *y;
        pid_t y_pid;
        int objective;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "x.service", "[Service]\nType=oneshot\nExecStart=/bin/sleep 5\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "y.service",
                                      "[Unit]\nAfter=x.service\n[Service]\nType=simple\nExecStart=/bin/sleep 300\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir, "t.target", "[Unit]\nWants=x.service y.service\n"), 0);

        m = manager_for(dir, "cancel-starts", cgroup_root, sizeof(cgroup_root));
        t = manager_get_unit(m, "t.target");
        x = manager_get_unit(m, "x.service");
        y = manager_get_unit(m, "y.service");
        ASSERT_TRUE(t != NULL && x != NULL && y != NULL);

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, t, NULL), 0);
        ASSERT_TRUE(manager_dispatch_run_queue(m) > 0);
        ASSERT_EQ_INT(SERVICE(x)->state, SERVICE_EXEC_START);
        ASSERT_TRUE(y->job != NULL);
        ASSERT_EQ_INT(y->job->state, JOB_WAITING);

        ASSERT_EQ_INT(manager_shutdown(m, MANAGER_POWEROFF), 0);
        objective = loop_with_budget(m, 5 * USEC_PER_SEC);

        y_pid = SERVICE(y)->main_pid;
        if (y_pid > 0)
                kill(y_pid, SIGKILL);

        ASSERT_EQ_INT(objective, MANAGER_POWEROFF);
        ASSERT_TRUE(y->job == NULL);
        ASSERT_EQ_INT(y_pid, 0); /* never spawned */
        ASSERT_EQ_INT(SERVICE(y)->state, SERVICE_DEAD);
        ASSERT_TRUE(unit_active_state(x) == UNIT_INACTIVE || unit_active_state(x) == UNIT_FAILED);

        manager_free(m);
        free_private_cgroup_root(cgroup_root);
        test_rm_rf(dir);
        free(dir);
}

/*
 * The signals PID 1 answers: SIGINT (ctrl-alt-del) reboots, SIGRTMIN+3/+4
 * power off, SIGHUP is a no-op for now, and SIGTERM is ignored by a system
 * manager. A second request only changes where the shutdown ends up; it does
 * not restart the deadline.
 */
static void test_signal_to_objective_mapping(void) {
        Manager *m = NULL;
        usec_t deadline;

        ASSERT_EQ_INT(manager_new(&m), 0);
        ASSERT_TRUE(!m->is_system);

        ASSERT_EQ_INT(manager_dispatch_signal(m, SIGHUP), 0);
        ASSERT_EQ_INT(m->pending_objective, MANAGER_RUNNING);

        m->is_system = true;
        ASSERT_EQ_INT(manager_dispatch_signal(m, SIGTERM), 0);
        ASSERT_EQ_INT(m->pending_objective, MANAGER_RUNNING);
        m->is_system = false;

        ASSERT_EQ_INT(manager_dispatch_signal(m, SIGINT), 0);
        ASSERT_EQ_INT(m->pending_objective, MANAGER_REBOOT);
        deadline = m->shutdown_deadline;
        ASSERT_TRUE(deadline > now_monotonic());
        ASSERT_TRUE(m->shutdown_deadline_source != NULL);

        usleep(10 * 1000);
        ASSERT_EQ_INT(manager_dispatch_signal(m, SIGRTMIN + 4), 0);
        ASSERT_EQ_INT(m->pending_objective, MANAGER_POWEROFF);
        ASSERT_EQ_INT(m->shutdown_deadline, deadline);

        ASSERT_EQ_INT(manager_dispatch_signal(m, SIGRTMIN + 3), 0);
        ASSERT_EQ_INT(m->pending_objective, MANAGER_POWEROFF);

        /* not a system manager: SIGTERM means exit */
        ASSERT_EQ_INT(manager_dispatch_signal(m, SIGTERM), 0);
        ASSERT_EQ_INT(m->pending_objective, MANAGER_EXIT);
        ASSERT_EQ_INT(m->shutdown_deadline, deadline);

        /* nothing to stop, so the loop adopts it straight away */
        ASSERT_EQ_INT(m->objective, MANAGER_RUNNING);
        ASSERT_EQ_INT(loop_with_budget(m, 2 * USEC_PER_SEC), MANAGER_EXIT);
        ASSERT_EQ_INT(m->objective, MANAGER_EXIT);

        manager_free(m);
}

/*
 * A unit that ignores SIGTERM, with TimeoutStopSec= well past the shutdown
 * deadline: the deadline, not the unit, decides when the machine goes down.
 * The deadline is pulled in from 30s so the test stays fast; the path taken
 * is the real one, the deadline time source waking the loop.
 */
static void test_shutdown_deadline_bounds_a_wedged_unit(void) {
        char cgroup_root[PATH_MAX];
        Manager *m;
        char *dir;
        Unit *a;
        pid_t pid;
        usec_t started;
        int objective;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "deaf.sh", "trap '' TERM\nwhile :; do sleep 0.1; done\n"), 0);
        write_unit_running_script(dir, "a.service", "deaf.sh", "TimeoutStopSec=60\n");

        m = manager_for(dir, "deadline", cgroup_root, sizeof(cgroup_root));
        a = manager_get_unit(m, "a.service");
        ASSERT_TRUE(a != NULL);

        start_and_settle(m, a);
        pid = SERVICE(a)->main_pid;
        ASSERT_TRUE(pid > 0);
        usleep(200 * 1000); /* let the shell install its trap */

        ASSERT_EQ_INT(manager_shutdown(m, MANAGER_POWEROFF), 0);
        ASSERT_TRUE(m->shutdown_deadline_source != NULL);

        started = now_monotonic();
        m->shutdown_deadline = started + 300 * USEC_PER_MSEC;
        ASSERT_TRUE(sd_event_source_set_time(m->shutdown_deadline_source, m->shutdown_deadline) >= 0);

        objective = loop_with_budget(m, 5 * USEC_PER_SEC);

        ASSERT_EQ_INT(objective, MANAGER_POWEROFF);
        ASSERT_TRUE(now_monotonic() - started < 3 * USEC_PER_SEC);
        ASSERT_EQ_INT(m->n_jobs, 1); /* gave up on the stop, did not finish it */
        ASSERT_EQ_INT(SERVICE(a)->state, SERVICE_STOP);

        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);

        manager_free(m);
        free_private_cgroup_root(cgroup_root);
        test_rm_rf(dir);
        free(dir);
}

int main(void) {
        test_signal_to_objective_mapping();
        test_shutdown_deadline_bounds_a_wedged_unit();
        test_shutdown_waits_for_running_stop_job();
        test_shutdown_cancels_waiting_start_jobs();

        printf("test-manager-shutdown: all checks passed\n");
        return 0;
}
