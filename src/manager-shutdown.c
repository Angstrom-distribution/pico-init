/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Orderly shutdown. M0: queues a stop job for every unit and sets the
 * objective immediately -- M1+ should hold the objective at
 * MANAGER_RUNNING until every stop job has actually finished, once the
 * run queue can report full drain.
 */

#include <errno.h>
#include <stddef.h>

#include "manager.h"

int manager_shutdown(Manager *m, ManagerObjective objective) {
        if (!m)
                return -EINVAL;

        for (size_t i = 0; i < m->n_units; i++)
                manager_add_job(m, JOB_STOP, m->units[i], NULL); /* best-effort */

        m->objective = objective;
        return 0;
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
