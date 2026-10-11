/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Orderly shutdown.
 *
 * The objective is not set here. Setting it directly would end
 * the event loop on its very next iteration -- before a single one of the stop
 * jobs this function just queued had a chance to run -- so "orderly shutdown"
 * would stop nothing at all. Instead a pending objective is recorded and the
 * loop adopts it once every job has finished, or once the deadline passes.
 */

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include "job.h"
#include "manager.h"
#include "util.h"

/*
 * How long to wait for stop jobs to finish before going anyway. Generous
 * enough for a service to shut down properly, short enough that one wedged
 * service cannot keep a machine powered up indefinitely -- which on a battery
 * powered target is a real failure, not an inconvenience.
 */
#define PICO_SHUTDOWN_TIMEOUT_USEC (30 * USEC_PER_SEC)

int manager_shutdown(Manager *m, ManagerObjective objective) {
        size_t i;

        if (!m)
                return -EINVAL;

        if (objective == MANAGER_RUNNING)
                return -EINVAL;

        if (m->pending_objective != MANAGER_RUNNING) {
                /* Already shutting down. A second request does not restart the
                 * clock; it only escalates where we end up. */
                if (objective != m->pending_objective)
                        pico_log(PICO_LOG_INFO,
                                 "shutdown already pending (%s), now heading for %s",
                                 manager_objective_to_string(m->pending_objective),
                                 manager_objective_to_string(objective));

                m->pending_objective = objective;
                return 0;
        }

        pico_log(PICO_LOG_INFO, "shutting down: %s", manager_objective_to_string(objective));

        m->pending_objective = objective;
        m->shutdown_deadline = now_monotonic() + PICO_SHUTDOWN_TIMEOUT_USEC;
        manager_arm_shutdown_deadline(m);

        /*
         * Cancel every start and restart still queued. The stop sweep below
         * skips inactive units, so a start job waiting there would otherwise
         * run as soon as whatever it is ordered after has stopped. v30 gets
         * the same effect by isolating to the shutdown target.
         * Non-recursive: cancelling is not a failure of the unit.
         */
        for (i = 0; i < m->n_units; i++) {
                Job *j = m->units[i]->job;

                if (j && (j->type == JOB_START || j->type == JOB_RESTART))
                        job_finish_full(j, JOB_CANCELED, false);
        }

        /*
         * Queue a stop for everything still up. Ordering is the job engine's
         * problem, not this function's: stop jobs run before start jobs and in
         * reverse dependency order, which is exactly what transaction
         * activation already arranges.
         *
         * Best-effort per unit -- a unit that cannot be queued must not stop
         * the rest of the machine from coming down.
         */
        for (i = 0; i < m->n_units; i++) {
                Unit *u = m->units[i];
                int r;

                if (unit_active_state(u) == UNIT_INACTIVE)
                        continue;

                r = manager_add_job(m, JOB_STOP, u, NULL);
                if (r < 0)
                        pico_log(PICO_LOG_WARNING, "%s: could not queue stop job: %s", u->id, strerror(-r));
        }

        return 0;
}

bool manager_shutdown_finished(Manager *m) {
        if (!m || m->pending_objective == MANAGER_RUNNING)
                return false;

        /* Installed jobs, not the run queue: a stop job that has sent
         * SIGTERM is RUNNING and already off the queue, and is exactly
         * what a shutdown has to wait for. */
        if (m->n_jobs == 0)
                return true;

        if (now_monotonic() >= m->shutdown_deadline) {
                pico_log(PICO_LOG_WARNING, "shutdown timed out with jobs still queued, proceeding anyway");
                return true;
        }

        return false;
}

const char *manager_objective_to_string(ManagerObjective o) {
        static const char * const table[_MANAGER_OBJECTIVE_MAX] = {
                [MANAGER_RUNNING] = "running",
                [MANAGER_EXIT] = "exit",
                [MANAGER_REBOOT] = "reboot",
                [MANAGER_POWEROFF] = "poweroff",
        };

        if (o < 0 || o >= _MANAGER_OBJECTIVE_MAX)
                return "invalid";

        return table[o];
}
