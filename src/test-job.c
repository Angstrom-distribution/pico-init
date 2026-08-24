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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "job.h"
#include "manager.h"
#include "test-util.h"
#include "unit.h"

static Manager *manager_for(const char *dir) {
        const char * const path[] = { dir, NULL };
        Manager *m = NULL;

        ASSERT_EQ_INT(manager_new(&m), 0);
        ASSERT_TRUE(m != NULL);
        ASSERT_EQ_INT(manager_set_unit_path(m, path), 0);

        return m;
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

        /* Supersede it before it ran. */
        ASSERT_EQ_INT(manager_add_job(m, JOB_STOP, a, NULL), 0);
        ASSERT_TRUE(a->job != NULL);
        ASSERT_TRUE(a->job->id != first_id); /* genuinely a different job */
        ASSERT_EQ_INT(a->job->type, JOB_STOP);

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

        ASSERT_EQ_INT(manager_add_job(m, JOB_RESTART, a, NULL), 0);

        /* Two dispatches: one for the stop half, one for the start half the
         * conversion queues. Before the fix the unit stayed INACTIVE and
         * a->job never cleared. */
        manager_dispatch_run_queue(m);
        manager_dispatch_run_queue(m);

        ASSERT_EQ_INT(unit_active_state(a), UNIT_ACTIVE);
        ASSERT_TRUE(a->job == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

int main(void) {
        test_ordering_c_b_a();
        test_redundant_anchor_job_finishes();
        test_superseded_job_is_finished();
        test_restart_completes();
        test_transaction_dedup();
        test_cycle_does_not_deadlock();
        test_transaction_ownership();
        test_restart_pulls_start_deps();
        test_conflicting_job_types();
        test_target_start_completes();
        test_redundant_job_dropped();

        printf("test-job: all checks passed\n");
        return 0;
}
