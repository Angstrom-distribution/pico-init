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
        _JOB_RESULT_MAX,
} JobResult;

struct Job {
        Manager *manager;
        Unit *unit; /* borrowed; unit->job points back while installed */

        uint32_t id;
        JobType type;
        JobState state;
        JobResult result; /* valid once finished */

        /* intrusive run-queue link (see manager.h) */
        Job *run_queue_next;
        bool in_run_queue;
};

/* --- job.c --- */
int job_new(Manager *m, JobType type, Unit *u, Job **ret);
Job *job_free(Job *j); /* uninstalls from unit + queues; returns NULL */

/* Start executing a WAITING job whose ordering dependencies are satisfied. 0 or -errno. */
int job_run(Job *j);

/* Record the result, uninstall, unblock dependent jobs. 0 or -errno. */
int job_finish(Job *j, JobResult result);

/* True when every job this one is ordered after has already finished. */
bool job_is_runnable(Job *j);

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
