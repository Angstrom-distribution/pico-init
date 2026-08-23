/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * M0 placeholder: allocation/teardown and run-queue linkage are real (the
 * skeleton the job/transaction API is built on); job_run, job_finish, and
 * the transaction-building calls are stub bodies returning -ENOSYS. Real
 * dependency-walk and ordering logic lands in M2 per the plan.
 */

#include <errno.h>
#include <stdlib.h>

#include "job.h"
#include "manager.h"
#include "unit.h"

struct Transaction {
        Manager *manager;
        Job **jobs; /* owned array of borrowed Job* */
        size_t n_jobs;
};

static void job_unlink_run_queue(Job *j) {
        Job **cur;

        if (!j->in_run_queue)
                return;

        for (cur = &j->manager->run_queue; *cur; cur = &(*cur)->run_queue_next)
                if (*cur == j) {
                        *cur = j->run_queue_next;
                        break;
                }

        j->run_queue_next = NULL;
        j->in_run_queue = false;
}

int job_new(Manager *m, JobType type, Unit *u, Job **ret) {
        Job *j;

        if (!m || !u || !ret)
                return -EINVAL;

        j = calloc(1, sizeof(Job));
        if (!j)
                return -ENOMEM;

        j->manager = m;
        j->unit = u;
        j->id = m->next_job_id++;
        j->type = type;
        j->state = JOB_WAITING;

        *ret = j;
        return 0;
}

Job *job_free(Job *j) {
        if (!j)
                return NULL;

        if (j->unit && j->unit->job == j)
                j->unit->job = NULL;

        job_unlink_run_queue(j);

        free(j);
        return NULL;
}

int job_run(Job *j) {
        (void) j;
        return -ENOSYS;
}

int job_finish(Job *j, JobResult result) {
        (void) j;
        (void) result;
        return -ENOSYS;
}

static const char * const job_type_table[_JOB_TYPE_MAX] = {
        [JOB_START] = "start",
        [JOB_STOP] = "stop",
        [JOB_RESTART] = "restart",
};

const char *job_type_to_string(JobType t) {
        if (t < 0 || t >= _JOB_TYPE_MAX)
                return "invalid";

        return job_type_table[t];
}

static const char * const job_state_table[_JOB_STATE_MAX] = {
        [JOB_WAITING] = "waiting",
        [JOB_RUNNING] = "running",
};

const char *job_state_to_string(JobState s) {
        if (s < 0 || s >= _JOB_STATE_MAX)
                return "invalid";

        return job_state_table[s];
}

static const char * const job_result_table[_JOB_RESULT_MAX] = {
        [JOB_DONE] = "done",
        [JOB_FAILED] = "failed",
        [JOB_CANCELED] = "canceled",
        [JOB_TIMEOUT] = "timeout",
};

const char *job_result_to_string(JobResult r) {
        if (r < 0 || r >= _JOB_RESULT_MAX)
                return "invalid";

        return job_result_table[r];
}

int transaction_new(Manager *m, Transaction **ret) {
        Transaction *tx;

        if (!m || !ret)
                return -EINVAL;

        tx = calloc(1, sizeof(Transaction));
        if (!tx)
                return -ENOMEM;

        tx->manager = m;

        *ret = tx;
        return 0;
}

Transaction *transaction_free(Transaction *tx) {
        if (!tx)
                return NULL;

        free(tx->jobs);
        free(tx);
        return NULL;
}

int transaction_add_job(Transaction *tx, JobType type, Unit *u, bool with_dependencies) {
        (void) tx;
        (void) type;
        (void) u;
        (void) with_dependencies;
        return -ENOSYS;
}

int transaction_activate(Transaction *tx) {
        (void) tx;
        return -ENOSYS;
}
