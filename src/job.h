/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Jobs: units of queued work applied to units (WAITING -> RUNNING ->
 * DONE/FAILED), plus the transaction API that turns one requested job into
 * a consistent, cycle-free set of jobs across its dependencies.
 */

#pragma once

#include <stdbool.h>
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

const char *job_type_to_string(JobType t);
const char *job_state_to_string(JobState s);
const char *job_result_to_string(JobResult r);

/* --- transaction building (job.c) --- */
int transaction_new(Manager *m, Transaction **ret);
Transaction *transaction_free(Transaction *tx); /* returns NULL */

/* Add a job for u; with_dependencies pulls in Requires/Wants recursively. 0 or -errno. */
int transaction_add_job(Transaction *tx, JobType type, Unit *u, bool with_dependencies);

/* Verify (ordering cycles -> -ELOOP, conflicts) and install jobs onto the run queue. */
int transaction_activate(Transaction *tx);
