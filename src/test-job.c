/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * M2's acceptance test: "A-after-B-after-C queues as [C,B,A] with no deadlock
 * across multi-job transactions", plus regressions for the backports in job.c.
 *
 * Targets are used throughout rather than services. A target reaches its state
 * synchronously with no process involved, which is exactly what makes the job
 * engine testable on its own: every assertion here is about ordering,
 * deduplication and ownership, none of it about forking.
 */

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

#include "job.h"
#include "manager.h"
#include "service.h"
#include "test-util.h"
#include "timer.h"
#include "unit.h"

static Manager *manager_for(const char *dir) {
        const char * const path[] = { dir, NULL };
        Manager *m = NULL;

        ASSERT_EQ_INT(manager_new(&m), 0);
        ASSERT_TRUE(m != NULL);
        ASSERT_EQ_INT(manager_set_unit_path(m, path), 0);

        return m;
}

/*
 * A per-test cgroup root, pid- and tag-qualified: meson runs test binaries
 * concurrently, and two of them spawning a same-named unit under the default
 * root would share /sys/fs/cgroup/system.slice/<unit>.
 */
static void use_private_cgroup_root(Manager *m, const char *tag, char *out, size_t out_size) {
        int n = snprintf(out, out_size, "/sys/fs/cgroup/pico-job-test-%s-%lld", tag, (long long) getpid());

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

/* --- drive the real manager_loop() until a condition holds, or a budget --- */

static Manager *g_drive_m;
static bool (*g_drive_done)(Manager *m, void *ctx);
static void *g_drive_ctx;
static int g_drive_ticks;
static int g_drive_max_ticks;

static void drive_tick(void *userdata, usec_t now) {
        (void) userdata;
        (void) now;

        if (g_drive_done(g_drive_m, g_drive_ctx) || ++g_drive_ticks >= g_drive_max_ticks)
                g_drive_m->objective = MANAGER_EXIT;
        else
                ASSERT_EQ_INT(pico_timer_add(g_drive_m->timer,
                                             now_monotonic() + 10 * USEC_PER_MSEC,
                                             drive_tick,
                                             NULL,
                                             NULL),
                              0);
}

/* 10ms ticks: max_ticks = 300 bounds the wait at about 3s. Returns whether
 * `done` held when the loop stopped. */
static bool drive_until(Manager *m, bool (*done)(Manager *m, void *ctx), void *ctx, int max_ticks) {
        g_drive_m = m;
        g_drive_done = done;
        g_drive_ctx = ctx;
        g_drive_ticks = 0;
        g_drive_max_ticks = max_ticks;

        m->objective = MANAGER_RUNNING;
        ASSERT_EQ_INT(pico_timer_add(m->timer, now_monotonic() + 10 * USEC_PER_MSEC, drive_tick, NULL, NULL),
                      0);
        manager_loop(m);

        return done(m, ctx);
}

static bool no_jobs(Manager *m, void *ctx) {
        (void) ctx;
        return m->n_jobs == 0;
}

static bool drive_until_idle(Manager *m, int max_ticks) {
        return drive_until(m, no_jobs, NULL, max_ticks);
}

/* Read the run queue back as a list of unit ids, in order. */
static size_t run_queue_ids(Manager *m, const char **out, size_t max) {
        size_t n = 0;
        Job *j;

        for (j = m->run_queue; j && n < max; j = j->run_queue_next)
                out[n++] = j->unit->id;

        return n;
}

/*
 * M1's "Done when", at the job layer: a.target is ordered after b.target which
 * is ordered after c.target, so a start job for a must queue them c, b, a.
 */
static void test_ordering_c_b_a(void) {
        const char *ids[8];
        Manager *m;
        Unit *a;
        char *dir;
        size_t n;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "a.target", "[Unit]\nRequires=b.target\nAfter=b.target\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir, "b.target", "[Unit]\nRequires=c.target\nAfter=c.target\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir, "c.target", "[Unit]\nDescription=C\n"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        a = manager_get_unit(m, "a.target");
        ASSERT_TRUE(a != NULL);
        ASSERT_EQ_INT(a->load_state, UNIT_LOADED);

        ASSERT_EQ_INT(unit_dependency_detect_cycles(m), 0);
        ASSERT_EQ_INT(manager_add_job(m, JOB_START, a, NULL), 0);

        n = run_queue_ids(m, ids, 8);
        ASSERT_EQ_INT(n, 3);
        ASSERT_STREQ(ids[0], "c.target");
        ASSERT_STREQ(ids[1], "b.target");
        ASSERT_STREQ(ids[2], "a.target");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * Deduplication across a diamond: a wants b and c, both of which require d.
 * d must get exactly one job, not two.
 */
static void test_transaction_dedup(void) {
        const char *ids[16];
        size_t n_d = 0;
        Manager *m;
        char *dir;
        size_t n;
        size_t i;
        Unit *a;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "a.target", "[Unit]\nRequires=b.target c.target\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir, "b.target", "[Unit]\nRequires=d.target\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir, "c.target", "[Unit]\nRequires=d.target\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir, "d.target", "[Unit]\nDescription=D\n"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        a = manager_get_unit(m, "a.target");
        ASSERT_TRUE(a != NULL);

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, a, NULL), 0);

        n = run_queue_ids(m, ids, 16);
        ASSERT_EQ_INT(n, 4); /* a, b, c, d -- exactly four, not five */

        for (i = 0; i < n; i++)
                if (strcmp(ids[i], "d.target") == 0)
                        n_d++;

        ASSERT_EQ_INT(n_d, 1);

        /* and the unit itself carries exactly one installed job */
        ASSERT_TRUE(manager_get_unit(m, "d.target")->job != NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * A cyclic ordering graph must not deadlock and must not livelock. The cycle
 * is reachable only through Wants=, so every job in it is sacrificeable and
 * the engine is expected to break it and still return.
 *
 * The value of this test is that it RETURNS: a livelock here would hang the
 * suite, which is why the cycle-break retry in transaction_activate() is
 * bounded rather than "loop until verified".
 */
static void test_cycle_does_not_deadlock(void) {
        Manager *m;
        char *dir;
        Unit *root;
        int r;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "root.target", "[Unit]\nWants=x.target\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir, "x.target", "[Unit]\nWants=y.target\nAfter=y.target\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir, "y.target", "[Unit]\nWants=z.target\nAfter=z.target\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir, "z.target", "[Unit]\nWants=x.target\nAfter=x.target\n"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        /* the graph really is cyclic */
        ASSERT_EQ_INT(unit_dependency_detect_cycles(m), -ELOOP);

        root = manager_get_unit(m, "root.target");
        ASSERT_TRUE(root != NULL);

        /* Either it breaks the cycle and succeeds, or it refuses with -ELOOP.
         * What it must not do is fail to return. */
        r = manager_add_job(m, JOB_START, root, NULL);
        ASSERT_TRUE(r == 0 || r == -ELOOP);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * Ownership: a transaction that never activates must free its own jobs, and
 * must leave no unit pointing at freed memory. Built by hand rather than
 * through manager_add_job(), because the point is the transaction's own
 * lifecycle.
 */
static void test_transaction_ownership(void) {
        Transaction *tx = NULL;
        Manager *m;
        char *dir;
        Unit *a;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "a.target", "[Unit]\nRequires=b.target\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir, "b.target", "[Unit]\nDescription=B\n"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        a = manager_get_unit(m, "a.target");
        ASSERT_TRUE(a != NULL);

        ASSERT_EQ_INT(transaction_new(m, &tx), 0);
        ASSERT_EQ_INT(transaction_add_job(tx, JOB_START, a, true), 0);
        ASSERT_EQ_INT(transaction_n_jobs(tx), 2); /* a and its required b */

        /* nothing installed yet: the transaction still owns both */
        ASSERT_TRUE(a->job == NULL);
        ASSERT_TRUE(manager_get_unit(m, "b.target")->job == NULL);

        /* dropping it without activating must not leak and must not install */
        transaction_free(tx);

        ASSERT_TRUE(a->job == NULL);
        ASSERT_TRUE(manager_get_unit(m, "b.target")->job == NULL);
        ASSERT_TRUE(m->run_queue == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * Regression for 6530407524: a restart is a stop first and a start after, so
 * it must pull in the start-side dependency set too. v30 walked it only for
 * JOB_START, so restarting a unit did not start its requirements.
 */
static void test_restart_pulls_start_deps(void) {
        Transaction *tx = NULL;
        Manager *m;
        char *dir;
        Unit *a;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "a.target", "[Unit]\nRequires=b.target\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir, "b.target", "[Unit]\nDescription=B\n"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        a = manager_get_unit(m, "a.target");
        ASSERT_TRUE(a != NULL);

        ASSERT_EQ_INT(transaction_new(m, &tx), 0);
        ASSERT_EQ_INT(transaction_add_job(tx, JOB_RESTART, a, true), 0);

        /* b must have been pulled in, exactly as a plain start would */
        ASSERT_EQ_INT(transaction_n_jobs(tx), 2);

        transaction_free(tx);
        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * A start and a stop for the same unit cannot be merged. The transaction must
 * say so rather than silently picking one.
 */
static void test_conflicting_job_types(void) {
        Transaction *tx = NULL;
        Manager *m;
        char *dir;
        Unit *a;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "a.target", "[Unit]\nDescription=A\n"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        a = manager_get_unit(m, "a.target");
        ASSERT_TRUE(a != NULL);

        ASSERT_EQ_INT(transaction_new(m, &tx), 0);
        ASSERT_EQ_INT(transaction_add_job(tx, JOB_START, a, false), 0);
        ASSERT_EQ_INT(transaction_add_job(tx, JOB_STOP, a, false), -EDEADLK);
        ASSERT_EQ_INT(transaction_n_jobs(tx), 1);

        transaction_free(tx);
        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* Starting a target actually reaches it, and the job completes. */
static void test_target_start_completes(void) {
        Manager *m;
        char *dir;
        Unit *a;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "a.target", "[Unit]\nRequires=b.target\nAfter=b.target\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir, "b.target", "[Unit]\nDescription=B\n"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        a = manager_get_unit(m, "a.target");
        ASSERT_TRUE(a != NULL);

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, a, NULL), 0);
        ASSERT_TRUE(manager_dispatch_run_queue(m) > 0);

        /* both reached, in the right order, and every job is gone again */
        ASSERT_EQ_INT(unit_active_state(manager_get_unit(m, "b.target")), UNIT_ACTIVE);
        ASSERT_EQ_INT(unit_active_state(a), UNIT_ACTIVE);
        ASSERT_TRUE(a->job == NULL);
        ASSERT_TRUE(m->run_queue == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* A start job for an already-active unit is redundant and gets dropped. */
static void test_redundant_job_dropped(void) {
        Manager *m;
        char *dir;
        Unit *a;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "a.target", "[Unit]\nDescription=A\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir, "b.target", "[Unit]\nRequires=a.target\n"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        a = manager_get_unit(m, "a.target");
        ASSERT_TRUE(a != NULL);

        /* bring a up */
        ASSERT_EQ_INT(manager_add_job(m, JOB_START, a, NULL), 0);
        manager_dispatch_run_queue(m);
        ASSERT_EQ_INT(unit_active_state(a), UNIT_ACTIVE);

        /* now b's transaction should not re-queue a */
        ASSERT_EQ_INT(manager_add_job(m, JOB_START, manager_get_unit(m, "b.target"), NULL), 0);
        ASSERT_TRUE(a->job == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * A redundant ANCHOR job must still finish. transaction_drop_redundant()
 * deliberately exempts the anchor, and a unit type's start/stop returns 0
 * without a state change when it is already in the state asked for -- so
 * nothing called unit_notify() and nothing finished the job. It sat in
 * JOB_RUNNING forever, and everything waiting on its result waited with it.
 *
 * Not an exotic path: this is `picoctl start` on a running unit and
 * `picoctl stop` on a dead one, the two commonest things anyone asks.
 */
static void test_redundant_anchor_job_finishes(void) {
        Manager *m;
        char *dir;
        Unit *a;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "a.target", "[Unit]\nDescription=A\n"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        a = manager_get_unit(m, "a.target");
        ASSERT_TRUE(a != NULL);

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, a, NULL), 0);
        manager_dispatch_run_queue(m);
        ASSERT_EQ_INT(unit_active_state(a), UNIT_ACTIVE);

        /* Already active: redundant, but it is the anchor so it is not dropped. */
        ASSERT_EQ_INT(manager_add_job(m, JOB_START, a, NULL), 0);
        manager_dispatch_run_queue(m);
        ASSERT_TRUE(a->job == NULL); /* stuck in JOB_RUNNING before the fix */
        ASSERT_EQ_INT(unit_active_state(a), UNIT_ACTIVE);

        ASSERT_EQ_INT(manager_add_job(m, JOB_STOP, a, NULL), 0);
        manager_dispatch_run_queue(m);
        ASSERT_EQ_INT(unit_active_state(a), UNIT_INACTIVE);

        /* The mirror case: stop on an already-inactive unit. */
        ASSERT_EQ_INT(manager_add_job(m, JOB_STOP, a, NULL), 0);
        manager_dispatch_run_queue(m);
        ASSERT_TRUE(a->job == NULL); /* stuck here too */

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * Installing a job on a unit that already has one must finish the displaced
 * job rather than overwrite the pointer. The old job stayed installed, stayed
 * on the run queue and became unreachable: never finished, never freed.
 *
 * Reachable from manager_shutdown()'s stop sweep landing on a unit with a
 * start job in flight, and from any second request for the same unit.
 */
static void test_superseded_job_is_finished(void) {
        Manager *m;
        char *dir;
        Unit *a;
        Job *first = NULL;
        uint32_t first_id;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        /* A service, so the start job stays in flight rather than completing
         * synchronously the way a target does. */
        ASSERT_EQ_INT(test_write_file(dir, "a.service", "[Service]\nExecStart=/bin/sleep 30\n"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        a = manager_get_unit(m, "a.service");
        ASSERT_TRUE(a != NULL);

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, a, &first), 0);
        ASSERT_TRUE(first != NULL);
        first_id = first->id;
        ASSERT_TRUE(a->job != NULL);
        ASSERT_EQ_INT(m->n_jobs, 1);
        ASSERT_EQ_INT(m->n_installed_jobs, 1);

        /* Supersede it before it ran. The old job's cancel (job_finish_full()
         * -> job_uninstall()) must decrement n_jobs before the new job's
         * install increments it, so n_jobs stays exact (1, not 2) while
         * n_installed_jobs counts both installs ever made (2). */
        ASSERT_EQ_INT(manager_add_job(m, JOB_STOP, a, NULL), 0);
        ASSERT_TRUE(a->job != NULL);
        ASSERT_TRUE(a->job->id != first_id); /* genuinely a different job */
        ASSERT_EQ_INT(a->job->type, JOB_STOP);
        ASSERT_EQ_INT(m->n_jobs, 1);
        ASSERT_EQ_INT(m->n_installed_jobs, 2);

        /* At most one job for this unit may remain queued: if the displaced
         * one were still on the run queue the manager would run a freed job. */
        {
                const char *ids[8];
                size_t n = run_queue_ids(m, ids, 8);

                ASSERT_TRUE(n <= 1);
        }

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * A restart must actually restart. unit_notify()'s JOB_RESTART arm was a bare
 * break, so nothing ever reported the stop half reaching INACTIVE, so
 * job_finish_full()'s restart-conversion block -- carefully written, carefully
 * commented -- was unreachable dead code. A restart stopped the unit and left
 * the job in JOB_RUNNING forever.
 *
 * Invisible to every test that existed, because none of them ever finished a
 * restart job: test_restart_pulls_start_deps() only checks what a restart
 * transaction pulls in, never that it completes.
 */
static void test_restart_completes(void) {
        Manager *m;
        char *dir;
        Unit *a;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "a.target", "[Unit]\nDescription=A\n"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        a = manager_get_unit(m, "a.target");
        ASSERT_TRUE(a != NULL);

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, a, NULL), 0);
        manager_dispatch_run_queue(m);
        ASSERT_EQ_INT(unit_active_state(a), UNIT_ACTIVE);
        ASSERT_EQ_INT(m->n_jobs, 0);
        ASSERT_EQ_INT(m->n_installed_jobs, 1);

        ASSERT_EQ_INT(manager_add_job(m, JOB_RESTART, a, NULL), 0);
        ASSERT_EQ_INT(m->n_jobs, 1);
        ASSERT_EQ_INT(m->n_installed_jobs, 2);

        /*
         * A target completes synchronously, so manager_dispatch_run_queue()
         * drains both the stop half and the conversion's start half in this
         * one call (it loops until the queue is empty -- see its own
         * comment) -- there is no dispatch boundary at which to observe the
         * mid-conversion state here. test_restart_conversion_counters()
         * below uses a real service instead, precisely to get that
         * boundary: an async unit_stop() leaves the job in JOB_RUNNING
         * until the process is actually reaped.
         *
         * Two dispatches: harmless if the first already finished
         * everything; before the fix the unit stayed INACTIVE and a->job
         * never cleared regardless. */
        manager_dispatch_run_queue(m);
        manager_dispatch_run_queue(m);

        ASSERT_EQ_INT(m->n_jobs, 0);
        ASSERT_EQ_INT(m->n_installed_jobs, 2);

        ASSERT_EQ_INT(unit_active_state(a), UNIT_ACTIVE);
        ASSERT_TRUE(a->job == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * test_restart_completes() above uses a target, which reaches its target
 * state synchronously -- so a single manager_dispatch_run_queue() drains a
 * restart's stop half AND the conversion's start half in one call, with no
 * dispatch boundary at which to observe the mid-conversion counters.
 *
 * A real service gives that boundary: unit_stop() only sends SIGTERM and
 * returns, so the job sits in JOB_RUNNING -- still installed, uncounted as
 * done -- until the process is actually reaped and unit_notify() drives
 * job_finish_full()'s JOB_RESTART/JOB_DONE conversion. This is the plan's
 * "n_jobs/n_installed_jobs unchanged across the conversion" case.
 */
static void test_restart_conversion_counters(void) {
        char cgroup_root[PATH_MAX];
        Manager *m;
        char *dir;
        Unit *a;
        Service *s;
        pid_t first_pid;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        /* Restart=no: this is a job-driven restart, not the service's own
         * auto-restart engine, so no crash-loop bookkeeping should fire. */
        ASSERT_EQ_INT(test_write_file(dir,
                                      "a.service",
                                      "[Service]\nType=simple\nExecStart=/bin/sleep 300\nRestart=no\n"),
                      0);

        m = manager_for(dir);

        /* A private cgroup root: meson test runs binaries concurrently, and
         * this unit's id would otherwise collide with another test binary's
         * own /sys/fs/cgroup/system.slice/a.service, exactly the flake
         * test-manager-state.c's use_private_cgroup_root() exists to avoid. */
        {
                int n = snprintf(
                                cgroup_root,
                                sizeof(cgroup_root),
                                "/sys/fs/cgroup/pico-job-test-restart-%lld",
                                (long long) getpid());

                ASSERT_TRUE(n > 0 && (size_t) n < sizeof(cgroup_root));
                if (mkdir(cgroup_root, 0755) < 0)
                        ASSERT_TRUE(errno == EEXIST);
                ASSERT_EQ_INT(manager_set_cgroup_root(m, cgroup_root), 0);
        }

        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);
        a = manager_get_unit(m, "a.service");
        ASSERT_TRUE(a != NULL);
        s = SERVICE(a);

        /* Start: Type=simple reaches RUNNING synchronously with the fork, so
         * this job finishes within the one dispatch. */
        ASSERT_EQ_INT(manager_add_job(m, JOB_START, a, NULL), 0);
        manager_dispatch_run_queue(m);
        ASSERT_EQ_INT(s->state, SERVICE_RUNNING);
        ASSERT_TRUE(s->main_pid > 0);
        first_pid = s->main_pid;
        ASSERT_EQ_INT(m->n_jobs, 0);
        ASSERT_EQ_INT(m->n_installed_jobs, 1);

        /* Restart: installed, not yet run. */
        ASSERT_EQ_INT(manager_add_job(m, JOB_RESTART, a, NULL), 0);
        ASSERT_EQ_INT(m->n_jobs, 1);
        ASSERT_EQ_INT(m->n_installed_jobs, 2);

        /* Dispatch the stop half: unit_stop() sends SIGTERM and returns --
         * the real process is still alive, so the job cannot have finished. */
        manager_dispatch_run_queue(m);
        ASSERT_TRUE(a->job != NULL);
        ASSERT_EQ_INT(a->job->type, JOB_RESTART); /* not yet converted */
        ASSERT_EQ_INT(a->job->state, JOB_RUNNING);
        ASSERT_EQ_INT(m->n_jobs, 1);
        ASSERT_EQ_INT(m->n_installed_jobs, 2);

        /* Reap the real SIGTERM exit -- same signalfd + waitid() pattern
         * test-manager-state.c's test_killed_service_shows_failure() uses --
         * which drives service_sigchld_event() -> unit_notify() ->
         * job_finish_full()'s restart conversion. */
        {
                struct pollfd pfd = { .fd = pico_signal_fd(m->signal), .events = POLLIN };
                bool reaped = false;
                int tries;

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
                                        if (info.si_pid != first_pid)
                                                continue;

                                        service_sigchld_event(s, info.si_pid, info.si_code, info.si_status);
                                        reaped = true;
                                }
                        }
                }
                ASSERT_TRUE(reaped);
        }

        /* The conversion happened: same job, now a start, still installed --
         * neither counter moved. */
        ASSERT_TRUE(a->job != NULL);
        ASSERT_EQ_INT(a->job->type, JOB_START);
        ASSERT_EQ_INT(a->job->state, JOB_WAITING);
        ASSERT_EQ_INT(m->n_jobs, 1);
        ASSERT_EQ_INT(m->n_installed_jobs, 2);

        /* Dispatch the converted start: Type=simple forks and reaches
         * RUNNING synchronously again, finishing the job -- only now does
         * n_jobs drop. */
        manager_dispatch_run_queue(m);
        ASSERT_EQ_INT(s->state, SERVICE_RUNNING);
        ASSERT_TRUE(a->job == NULL);
        ASSERT_EQ_INT(m->n_jobs, 0);
        ASSERT_EQ_INT(m->n_installed_jobs, 2);

        manager_free(m);
        rmdir(cgroup_root); /* system.slice/a.service leaf is gone via manager_free() */
        test_rm_rf(dir);
        free(dir);
}

/*
 * Every verb against every starting state must terminate. Six combinations,
 * because covering only the ones that obviously work is what let a real bug
 * through: the first version of this file tested restart on an ACTIVE unit --
 * which genuinely stops, so unit_notify() fires and the conversion runs -- and
 * never tested restart on an INACTIVE one, where unit_stop() is a silent
 * no-op, nothing notifies, and the job hung forever.
 *
 * Three dispatches each: enough for a restart's stop half, its conversion and
 * its start half, and harmless for the cases that finish sooner.
 */
static void test_all_verb_state_combinations(void) {
        static const struct {
                JobType type;
                bool start_active;
                UnitActiveState want;
                const char *what;
        } cases[] = {
                {   JOB_START, false,   UNIT_ACTIVE,                   "start on inactive" },
                {   JOB_START,  true,   UNIT_ACTIVE,  "start on active (redundant anchor)" },
                {    JOB_STOP, false, UNIT_INACTIVE, "stop on inactive (redundant anchor)" },
                {    JOB_STOP,  true, UNIT_INACTIVE,                      "stop on active" },
                { JOB_RESTART, false,   UNIT_ACTIVE,                 "restart on inactive" },
                { JOB_RESTART,  true,   UNIT_ACTIVE,                   "restart on active" },
        };
        size_t c;

        for (c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
                Manager *m;
                char *dir;
                Unit *a;
                int d;

                dir = test_tmpdir_new();
                ASSERT_TRUE(dir != NULL);
                ASSERT_EQ_INT(test_write_file(dir, "a.target", "[Unit]\nDescription=A\n"), 0);

                m = manager_for(dir);
                ASSERT_EQ_INT(manager_load_units(m, NULL), 0);
                a = manager_get_unit(m, "a.target");
                ASSERT_TRUE(a != NULL);

                if (cases[c].start_active) {
                        ASSERT_EQ_INT(manager_add_job(m, JOB_START, a, NULL), 0);
                        manager_dispatch_run_queue(m);
                        ASSERT_EQ_INT(unit_active_state(a), UNIT_ACTIVE);
                }

                ASSERT_EQ_INT(manager_add_job(m, cases[c].type, a, NULL), 0);
                for (d = 0; d < 3; d++)
                        manager_dispatch_run_queue(m);

                if (a->job != NULL || unit_active_state(a) != cases[c].want)
                        fprintf(stderr,
                                "%s: job=%s state=%d want=%d\n",
                                cases[c].what,
                                a->job ? "STUCK" : "clear",
                                (int) unit_active_state(a),
                                (int) cases[c].want);

                ASSERT_TRUE(a->job == NULL);
                ASSERT_EQ_INT(unit_active_state(a), cases[c].want);

                manager_free(m);
                test_rm_rf(dir);
                free(dir);
        }
}

/*
 * Drop a unit from the manager's table the way a SIGHUP reload will have to.
 *
 * The reload path does not exist yet (manager-loop.c still carries its TODO),
 * so the removal is done here rather than through it -- but the thing under
 * test is unit_free() itself, which is the call reload will make, unchanged.
 */
static void manager_forget_unit(Manager *m, Unit *u) {
        size_t i;

        for (i = 0; i < m->n_units; i++)
                if (m->units[i] == u) {
                        memmove(&m->units[i], &m->units[i + 1], (m->n_units - i - 1) * sizeof(Unit *));
                        m->n_units--;
                        return;
                }

        ASSERT_TRUE(false); /* not in the table at all */
}

/*
 * Freeing a unit that still has a job must not leave the job behind.
 *
 * unit_free() used to ignore u->job entirely, so the job stayed installed --
 * queued, and holding a borrowed j->unit pointing straight at the freed
 * allocation. The next manager_dispatch_run_queue() would then run it and
 * dispatch unit_start() through a dangling pointer.
 *
 * Two cases, because they fail differently. A WAITING job is observable
 * directly: it is still linked on the run queue, so the plain assertion below
 * catches it (verified by reverting the fix and watching it fail). A RUNNING
 * job has already been unlinked from the queue, so nothing in-process can see
 * it any more -- with the fix reverted it shows up only under
 * -Db_sanitize=address,undefined, as the still-installed job leaking with its
 * unit freed underneath it. That is the same measured-rather-than-asserted
 * check C2's connection leak uses, and the reason both cases are here: the
 * observable half proves the mechanism, the sanitizer half covers the state
 * the observable half cannot reach.
 */
static void test_unit_free_cancels_its_job(void) {
        Manager *m;
        char *dir;
        Unit *a, *b;
        Job *j = NULL;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        /* Services, not targets: a target completes its job synchronously, so
         * there would be no live job left to dangle. */
        ASSERT_EQ_INT(test_write_file(dir, "a.service", "[Service]\nExecStart=/bin/sleep 30\n"), 0);

        /* Type=oneshot for the second case specifically: a Type=simple unit
         * counts as started the instant fork() returns, so its start job would
         * finish during the very dispatch meant to leave it RUNNING. Oneshot
         * keeps the job in flight for as long as the process lives, which is
         * the state this case needs to exist at all. */
        ASSERT_EQ_INT(test_write_file(dir, "b.service", "[Service]\nType=oneshot\nExecStart=/bin/sleep 30\n"),
                      0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        /* Case one: the job is still WAITING on the run queue. */
        a = manager_get_unit(m, "a.service");
        ASSERT_TRUE(a != NULL);

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, a, &j), 0);
        ASSERT_TRUE(j != NULL);
        ASSERT_TRUE(a->job == j);
        ASSERT_EQ_INT(j->state, JOB_WAITING);
        ASSERT_TRUE(m->run_queue == j);

        manager_forget_unit(m, a);
        unit_free(a);

        /* The queue held exactly that one job, and it must be gone with the
         * unit. Before the fix it was still linked here, pointing at freed
         * memory. */
        ASSERT_TRUE(m->run_queue == NULL);

        /* And running the queue must not reach it. */
        ASSERT_EQ_INT(manager_dispatch_run_queue(m), 0);

        /* Case two: the job is RUNNING, so it is off the queue already and
         * only the freed j->unit would be left to find. */
        b = manager_get_unit(m, "b.service");
        ASSERT_TRUE(b != NULL);

        j = NULL;
        ASSERT_EQ_INT(manager_add_job(m, JOB_START, b, &j), 0);
        ASSERT_TRUE(j != NULL);
        ASSERT_EQ_INT(manager_dispatch_run_queue(m), 1);
        ASSERT_TRUE(b->job == j);
        ASSERT_EQ_INT(j->state, JOB_RUNNING);
        ASSERT_TRUE(m->run_queue == NULL);

        manager_forget_unit(m, b);
        unit_free(b);

        ASSERT_TRUE(m->run_queue == NULL);
        ASSERT_EQ_INT(manager_dispatch_run_queue(m), 0);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * The job-layer half of "condition-failed is not failure", proven with
 * targets so nothing here forks: a Requires=/After= dependent of a unit
 * whose condition is unmet still reaches ACTIVE, and the skipped unit's own
 * job completes DONE rather than sitting in JOB_RUNNING forever -- the
 * regression job.c's job_run() -EALREADY mapping guards. This is the direct
 * analogue of usb-multi-gadget-dhcp-fallback.service's real Requires= on
 * usb-multi-gadget.service on a UDC-less machine.
 */
static void test_condition_skipped_job_completes_done(void) {
        Manager *m;
        char *dir;
        Unit *a;
        Unit *b;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "a.target", "[Unit]\nRequires=b.target\nAfter=b.target\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "b.target",
                                      "[Unit]\nDescription=B\nConditionPathExists=/nonexistent/pico-init-test\n"),
                      0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        a = manager_get_unit(m, "a.target");
        ASSERT_TRUE(a != NULL);
        b = manager_get_unit(m, "b.target");
        ASSERT_TRUE(b != NULL);

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, a, NULL), 0);
        ASSERT_TRUE(manager_dispatch_run_queue(m) > 0);

        /* b was skipped, left inactive */
        ASSERT_EQ_INT(unit_active_state(b), UNIT_INACTIVE);
        ASSERT_TRUE(!b->condition_result);

        /* its job completed rather than hanging in JOB_RUNNING forever */
        ASSERT_TRUE(b->job == NULL);

        /* the skip did not propagate as a failure, and did not deadlock the
         * ordering: a Requires=/After= dependent still ran to completion */
        ASSERT_EQ_INT(unit_active_state(a), UNIT_ACTIVE);
        ASSERT_TRUE(a->job == NULL);

        ASSERT_TRUE(m->run_queue == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * E2.5: a '!'-negated ConditionPathExists= inverts the stat() result, proven
 * both ways through the same job-dispatch path as the un-negated case above
 * -- the direct analogue of oe-core's dropbearkey.service, whose
 * "ConditionPathExists=!/etc/dropbear/dropbear_rsa_host_key" is meant to skip
 * regeneration once a host key already exists.
 */
static void test_negated_condition_inverts_result(void) {
        Manager *m;
        char *dir;
        char existing[PATH_MAX];
        char missing[PATH_MAX];
        char unit_text[PATH_MAX + 128];
        Unit *b;
        FILE *f;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        snprintf(existing, sizeof(existing), "%s/exists", dir);
        f = fopen(existing, "w");
        ASSERT_TRUE(f != NULL);
        fclose(f);

        snprintf(missing, sizeof(missing), "%s/does-not-exist", dir);

        /* negated against an existing path: the raw test is true, negation
         * flips it to false, so the unit is skipped */
        snprintf(unit_text, sizeof(unit_text), "[Unit]\nDescription=B\nConditionPathExists=!%s\n", existing);
        ASSERT_EQ_INT(test_write_file(dir, "b.target", unit_text), 0);
        ASSERT_EQ_INT(test_write_file(dir, "a.target", "[Unit]\nRequires=b.target\nAfter=b.target\n"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        b = manager_get_unit(m, "b.target");
        ASSERT_TRUE(b != NULL);

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, manager_get_unit(m, "a.target"), NULL), 0);
        ASSERT_TRUE(manager_dispatch_run_queue(m) > 0);

        ASSERT_EQ_INT(unit_active_state(b), UNIT_INACTIVE);
        ASSERT_TRUE(!b->condition_result);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);

        /* negated against a missing path: the raw test is false, negation
         * flips it to true, so the unit runs */
        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        snprintf(unit_text, sizeof(unit_text), "[Unit]\nDescription=B\nConditionPathExists=!%s\n", missing);
        ASSERT_EQ_INT(test_write_file(dir, "b.target", unit_text), 0);
        ASSERT_EQ_INT(test_write_file(dir, "a.target", "[Unit]\nRequires=b.target\nAfter=b.target\n"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        b = manager_get_unit(m, "b.target");
        ASSERT_TRUE(b != NULL);

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, manager_get_unit(m, "a.target"), NULL), 0);
        ASSERT_TRUE(manager_dispatch_run_queue(m) > 0);

        ASSERT_EQ_INT(unit_active_state(b), UNIT_ACTIVE);
        ASSERT_TRUE(b->condition_result);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * A Type=oneshot without RemainAfterExit= goes ACTIVATING -> INACTIVE on a
 * clean exit and never passes through ACTIVE. Its start job must still finish
 * DONE, or it stays installed forever and everything ordered After= it never
 * runs -- the picosplash-quit.service hang.
 */
static void test_oneshot_start_job_finishes(void) {
        char cgroup_root[PATH_MAX];
        Manager *m;
        char *dir;
        Unit *a, *b;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "a.service", "[Service]\nType=oneshot\nExecStart=/bin/true\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir, "b.target", "[Unit]\nWants=a.service\nAfter=a.service\n"), 0);

        m = manager_for(dir);
        use_private_cgroup_root(m, "oneshot", cgroup_root, sizeof(cgroup_root));
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        a = manager_get_unit(m, "a.service");
        b = manager_get_unit(m, "b.target");
        ASSERT_TRUE(a != NULL && b != NULL);

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, b, NULL), 0);
        ASSERT_TRUE(drive_until_idle(m, 300));

        ASSERT_TRUE(a->job == NULL);
        ASSERT_EQ_INT(SERVICE(a)->result, SERVICE_SUCCESS);
        ASSERT_EQ_INT(unit_active_state(a), UNIT_INACTIVE);
        ASSERT_EQ_INT(unit_active_state(b), UNIT_ACTIVE);
        ASSERT_EQ_INT(m->n_jobs, 0);

        manager_free(m);
        free_private_cgroup_root(cgroup_root);
        test_rm_rf(dir);
        free(dir);
}

struct restarted_ctx {
        Unit *u;
        pid_t old_pid;
};

/* The restart's start half is running a new process. */
static bool restarted(Manager *m, void *userdata) {
        struct restarted_ctx *c = userdata;
        Service *s = SERVICE(c->u);

        (void) m;
        return c->u->job && c->u->job->type == JOB_START && c->u->job->state == JOB_RUNNING &&
                        s->state == SERVICE_EXEC_START && s->main_pid > 0 && s->main_pid != c->old_pid;
}

/*
 * SIGTERM ends a running oneshot as FAILED (a signal death), so the stop half
 * of a restart lands in UNIT_FAILED. The unit is down either way: v30 finishes
 * stop and restart jobs DONE on inactive-or-failed. Finishing it FAILED
 * skipped the restart-to-start conversion, so the unit was never started
 * again.
 */
static void test_restart_of_unit_that_stops_failed(void) {
        char cgroup_root[PATH_MAX];
        struct restarted_ctx ctx;
        Manager *m;
        char *dir;
        Unit *a;
        pid_t pid;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "a.service", "[Service]\nType=oneshot\nExecStart=/bin/sleep 30\n"),
                      0);

        m = manager_for(dir);
        use_private_cgroup_root(m, "restart-failed", cgroup_root, sizeof(cgroup_root));
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        a = manager_get_unit(m, "a.service");
        ASSERT_TRUE(a != NULL);

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, a, NULL), 0);
        ASSERT_EQ_INT(manager_dispatch_run_queue(m), 1);
        ASSERT_EQ_INT(SERVICE(a)->state, SERVICE_EXEC_START);

        ctx.u = a;
        ctx.old_pid = SERVICE(a)->main_pid;
        ASSERT_TRUE(ctx.old_pid > 0);

        ASSERT_EQ_INT(manager_add_job(m, JOB_RESTART, a, NULL), 0);
        ASSERT_TRUE(drive_until(m, restarted, &ctx, 300));

        pid = SERVICE(a)->main_pid;
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);

        manager_free(m);
        free_private_cgroup_root(cgroup_root);
        test_rm_rf(dir);
        free(dir);
}

/*
 * A Requires= failure fails the whole requirement chain, not just the direct
 * requirer: c fails, so b (Requires=c) never starts, so a (Requires=b) must
 * not start either. v30's job_finish_and_invalidate() re-enters propagation
 * for every requirer it fails.
 */
static void test_requires_failure_propagates_transitively(void) {
        char cgroup_root[PATH_MAX];
        Manager *m;
        char *dir;
        Unit *a, *b, *c;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "c.service",
                                      "[Service]\nType=oneshot\nExecStart=/nonexistent/pico-init-test\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir, "b.target", "[Unit]\nRequires=c.service\nAfter=c.service\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir, "a.target", "[Unit]\nRequires=b.target\nAfter=b.target\n"), 0);

        m = manager_for(dir);
        use_private_cgroup_root(m, "propagate", cgroup_root, sizeof(cgroup_root));
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        a = manager_get_unit(m, "a.target");
        b = manager_get_unit(m, "b.target");
        c = manager_get_unit(m, "c.service");
        ASSERT_TRUE(a != NULL && b != NULL && c != NULL);

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, a, NULL), 0);
        ASSERT_TRUE(drive_until_idle(m, 300));

        ASSERT_EQ_INT(unit_active_state(c), UNIT_FAILED);
        ASSERT_EQ_INT(unit_active_state(b), UNIT_INACTIVE);
        ASSERT_EQ_INT(unit_active_state(a), UNIT_INACTIVE);

        manager_free(m);
        free_private_cgroup_root(cgroup_root);
        test_rm_rf(dir);
        free(dir);
}

/*
 * b is active but has a stop job installed, so it is about to go down. A start
 * pulled in for it by a's Requires= is not redundant: dropping it let b's stop
 * run and a start without its requirement. v30 transaction_drop_redundant()
 * keeps a job that conflicts with the one installed.
 */
static void test_start_not_dropped_over_installed_stop(void) {
        Manager *m;
        char *dir;
        Unit *a, *b;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "b.target", "[Unit]\nDescription=B\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir, "a.target", "[Unit]\nRequires=b.target\nAfter=b.target\n"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        a = manager_get_unit(m, "a.target");
        b = manager_get_unit(m, "b.target");
        ASSERT_TRUE(a != NULL && b != NULL);

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, a, NULL), 0);
        manager_dispatch_run_queue(m);
        ASSERT_EQ_INT(unit_active_state(a), UNIT_ACTIVE);
        ASSERT_EQ_INT(unit_active_state(b), UNIT_ACTIVE);

        /* not dispatched: b's stop stays installed and WAITING */
        ASSERT_EQ_INT(manager_add_job(m, JOB_STOP, b, NULL), 0);
        ASSERT_TRUE(b->job != NULL && b->job->type == JOB_STOP);

        ASSERT_EQ_INT(manager_add_job(m, JOB_START, a, NULL), 0);
        ASSERT_TRUE(b->job != NULL);
        ASSERT_EQ_INT(b->job->type, JOB_START);

        manager_dispatch_run_queue(m);
        ASSERT_EQ_INT(unit_active_state(b), UNIT_ACTIVE);
        ASSERT_EQ_INT(unit_active_state(a), UNIT_ACTIVE);
        ASSERT_EQ_INT(m->n_jobs, 0);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * The picosplash-quit.service shape, booted end to end: oe-core's
 * /etc/systemd/system/default.target -> multi-user.target, a oneshot that
 * fails, and a oneshot WantedBy=default.target ordered After= both
 * multi-user.target and the failing one. Every job must complete and the
 * boot must settle; the quit unit's start job used to stay installed forever.
 */
static void test_alias_boot_runs_ordered_oneshot(void) {
        char path[PATH_MAX], text[PATH_MAX + 256], cgroup_root[PATH_MAX];
        char *etc, *lib, *presets, *rt;
        Unit *multi, *splash, *quit;
        Manager *m = NULL;

        etc = test_tmpdir_new();
        lib = test_tmpdir_new();
        presets = test_tmpdir_new();
        rt = test_tmpdir_new();
        ASSERT_TRUE(etc && lib && presets && rt);

        ASSERT_EQ_INT(test_write_file(lib, "default.target", "[Unit]\nDescription=Packaged default\n"), 0);
        ASSERT_EQ_INT(test_write_file(lib, "multi-user.target", "[Unit]\nDescription=Multi-User System\n"), 0);
        ASSERT_EQ_INT(test_write_file(lib,
                                      "picosplash.service",
                                      "[Service]\nType=oneshot\nExecStart=/bin/false\n"
                                      "[Install]\nWantedBy=default.target\n"),
                      0);
        snprintf(text,
                 sizeof(text),
                 "[Unit]\nAfter=multi-user.target picosplash.service\n"
                 "[Service]\nType=oneshot\nExecStart=/bin/touch %s/quit-ran\n"
                 "[Install]\nWantedBy=default.target\n",
                 rt);
        ASSERT_EQ_INT(test_write_file(lib, "picosplash-quit.service", text), 0);

        snprintf(path, sizeof(path), "%s/multi-user.target", lib);
        ASSERT_EQ_INT(test_symlink(etc, "default.target", path), 0);

        ASSERT_EQ_INT(test_write_file(presets,
                                      "10-test.preset",
                                      "enable picosplash.service\nenable picosplash-quit.service\n"),
                      0);

        ASSERT_EQ_INT(manager_new(&m), 0);
        {
                const char * const up[] = { etc, lib, NULL };
                const char * const pd[] = { presets, NULL };

                ASSERT_EQ_INT(manager_set_unit_path(m, up), 0);
                ASSERT_EQ_INT(manager_set_preset_path(m, pd), 0);
        }
        ASSERT_EQ_INT(manager_set_runtime_dir(m, rt), 0);
        use_private_cgroup_root(m, "alias-boot", cgroup_root, sizeof(cgroup_root));

        /* a first boot: presets, not symlinks, enable these fixture units */
        manager_set_first_boot(m, true);
        ASSERT_EQ_INT(manager_startup(m, NULL), 0);

        multi = manager_get_unit(m, "multi-user.target");
        splash = manager_get_unit(m, "picosplash.service");
        quit = manager_get_unit(m, "picosplash-quit.service");
        ASSERT_TRUE(multi != NULL && splash != NULL && quit != NULL);
        ASSERT_TRUE(manager_get_unit(m, "default.target") == multi);

        ASSERT_TRUE(drive_until_idle(m, 300));

        ASSERT_EQ_INT(unit_active_state(multi), UNIT_ACTIVE);
        ASSERT_EQ_INT(unit_active_state(splash), UNIT_FAILED);
        ASSERT_TRUE(quit->job == NULL);
        ASSERT_EQ_INT(SERVICE(quit)->result, SERVICE_SUCCESS);
        snprintf(path, sizeof(path), "%s/quit-ran", rt);
        ASSERT_EQ_INT(access(path, F_OK), 0);
        ASSERT_TRUE(m->degradation_summary_logged);

        manager_free(m);
        free_private_cgroup_root(cgroup_root);
        test_rm_rf(etc);
        test_rm_rf(lib);
        test_rm_rf(presets);
        test_rm_rf(rt);
        free(etc);
        free(lib);
        free(presets);
        free(rt);
}

int main(void) {
        test_oneshot_start_job_finishes();
        test_alias_boot_runs_ordered_oneshot();
        test_start_not_dropped_over_installed_stop();
        test_requires_failure_propagates_transitively();
        test_restart_of_unit_that_stops_failed();
        test_ordering_c_b_a();
        test_unit_free_cancels_its_job();
        test_all_verb_state_combinations();
        test_redundant_anchor_job_finishes();
        test_superseded_job_is_finished();
        test_restart_completes();
        test_restart_conversion_counters();
        test_transaction_dedup();
        test_cycle_does_not_deadlock();
        test_transaction_ownership();
        test_restart_pulls_start_deps();
        test_conflicting_job_types();
        test_target_start_completes();
        test_redundant_job_dropped();
        test_condition_skipped_job_completes_done();
        test_negated_condition_inverts_result();

        printf("test-job: all checks passed\n");
        return 0;
}
