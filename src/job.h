/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Jobs: units of queued work applied to units (WAITING -> RUNNING ->
 * DONE/FAILED), plus the transaction API that turns one requested job into
 * a consistent, cycle-free set of jobs across its dependencies.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct Job Job;
typedef struct Transaction Transaction;

/* forward declarations; full definitions in unit.h / manager.h */
typedef struct Unit Unit;
typedef struct Manager Manager;

typedef enum JobType {
        JOB_START,
        JOB_STOP,
        JOB_RESTART,
        _JOB_TYPE_MAX,
        _JOB_TYPE_INVALID = -1,
} JobType;

typedef enum JobState {
        JOB_WAITING, /* queued, blocked on ordering dependencies */
        JOB_RUNNING, /* unit operation in flight */
        _JOB_STATE_MAX,
} JobState;

typedef enum JobResult {
        JOB_DONE,
        JOB_FAILED,
        JOB_CANCELED,
        JOB_TIMEOUT,
        JOB_DEPENDENCY, /* a required dependency job did not result in JOB_DONE, byte for byte systemd's
                         * own src/core/job.h comment for the same value */
        _JOB_RESULT_MAX,
        _JOB_RESULT_INVALID =
                        -1, /* a fresh job has no result yet; don't let 0 (JOB_DONE) mean that by accident */
} JobResult;

struct Job {
        Manager *manager;
        Unit *unit; /* borrowed; unit->job points back while installed */

        uint32_t id;
        JobType type;
        JobState state;
        JobResult result; /* _JOB_RESULT_INVALID until finished */

        /* intrusive run-queue link (see manager.h) */
        Job *run_queue_next;
        bool in_run_queue;

        /*
         * DFS marker/backtrack pointer for transaction_activate()'s ordering-
         * cycle check (job.c, transaction_verify_order_one()). generation is
         * compared against a per-sweep counter rather than a plain visited
         * bool so a stale mark from an earlier sweep can never be confused
         * with "visited this sweep" -- see the transaction_activate() note in
         * job.c about resetting every installed job's generation first.
         * marker points back along the DFS path so a detected cycle can be
         * walked to find a job actually worth deleting.
         */
        unsigned generation;
        Job *marker;

        /*
         * True once the job has been handed to the manager: attached to its
         * unit as unit->job and linked onto the run queue. It is the whole of
         * the ownership question -- a transaction frees exactly those of its
         * jobs that are not installed, and job_free() refuses to free one that
         * is. Upstream spent six commits removing the case where a job could
         * be both in a transaction and installed; keeping the two disjoint by
         * construction is what avoids all of it.
         */
        bool installed;

        /*
         * Whether dropping this job would defeat the request the transaction
         * was built for. Set by propagation from the anchor along Requires=
         * edges only: a Wants= dependency is by definition sacrificeable,
         * which is the entire difference between the two in this model. Cycle
         * breaking may only ever delete a job for which this is false.
         */
        bool matters_to_anchor;
};

/* --- job.c --- */
int job_new(Manager *m, JobType type, Unit *u, Job **ret);
Job *job_free(Job *j); /* uninstalls from unit + queues; returns NULL */

/* Start executing a WAITING job whose ordering dependencies are satisfied. 0 or -errno. */
int job_run(Job *j);

/* Record the result, uninstall, unblock dependent jobs. Equivalent to
 * job_finish_full(j, result, true). 0 or -errno. */
int job_finish(Job *j, JobResult result);

/*
 * As job_finish(), with an explicit recursion flag. `recursive` gates the
 * dependency-failure-propagation step: a job whose Requires= depended on this
 * one is itself failed only when recursive is true. Transaction
 * activation/installation already walks every job it touches, so it always
 * passes false here -- without that, a long Requires= chain finishing during
 * transaction_apply() would recurse back into code already iterating the
 * transaction and could double-finish a job. Anything reached from outside a
 * transaction (a job's own unit reporting a state change) wants the default,
 * recursive job_finish(). 0 or -errno.
 */
int job_finish_full(Job *j, JobResult result, bool recursive);

/* True when every job this one is ordered after has already finished. */
bool job_is_runnable(Job *j);

/* Queue a WAITING job to be tried again, and arm the run-queue dispatch. */
void job_add_to_run_queue(Job *j);

const char *job_type_to_string(JobType t);
const char *job_state_to_string(JobState s);
const char *job_result_to_string(JobResult r);

/* --- transaction building (job.c) --- */
/*
 * OWNERSHIP. A transaction owns every job it creates, from transaction_add_job()
 * until transaction_activate() succeeds and transfers them to the manager (each
 * installed on its unit as unit->job and linked onto the run queue).
 *
 * So transaction_free() must free every job the transaction still owns -- an
 * uninstalled job, i.e. one whose unit->job is not that job -- and must leave
 * installed jobs alone. Freeing only the array, as an early draft did, leaks
 * every job of a transaction that failed to activate; freeing all of them
 * unconditionally would instead tear down the jobs a successful activation had
 * just handed to the manager. This is systemd's model and the reason its
 * transaction code keeps the two sets distinct.
 */
int transaction_new(Manager *m, Transaction **ret);
Transaction *transaction_free(Transaction *tx); /* returns NULL */

/* Add a job for u; with_dependencies pulls in Requires/Wants recursively.
 * Adding a job for a unit that already has one in this transaction merges into
 * the existing job rather than creating a second: that deduplication is what
 * keeps a diamond dependency from queueing the same unit twice. 0 or -errno. */
int transaction_add_job(Transaction *tx, JobType type, Unit *u, bool with_dependencies);

/*
 * Verify and install. Ordering cycles among the transaction's jobs are an
 * -ELOOP; nothing is installed and the caller's transaction_free() cleans up.
 *
 * On success the jobs are installed onto the run queue in an order consistent
 * with their After=/Before= edges -- a topological order, so a job is never
 * placed ahead of one it must follow. The run queue is therefore directly
 * readable as "what will happen, in what order", which is also what makes the
 * ordering testable without running any process.
 */
int transaction_activate(Transaction *tx);

/* How many jobs the transaction currently holds. For tests and logging. */
size_t transaction_n_jobs(Transaction *tx);
