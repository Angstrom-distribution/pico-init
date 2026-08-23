/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * M0 placeholder: state-machine transitions (service_start/stop, the
 * SIGCHLD and cgroup-empty event hooks) are stub bodies returning -ENOSYS.
 * Real logic (ExecStartPre/ExecStart sequencing, Restart=/timeouts) lands
 * in M3 per the plan.
 */

#include <errno.h>

#include "service.h"

int service_start(Service *s) {
        (void) s;
        return -ENOSYS;
}

int service_stop(Service *s) {
        (void) s;
        return -ENOSYS;
}

void service_sigchld_event(Service *s, pid_t pid, int status) {
        (void) s;
        (void) pid;
        (void) status;
}

void service_cgroup_empty_event(Service *s) {
        (void) s;
}

static const char * const service_state_table[_SERVICE_STATE_MAX] = {
        [SERVICE_DEAD] = "dead",
        [SERVICE_START_PRE] = "start-pre",
        [SERVICE_EXEC_START] = "exec-start",
        [SERVICE_RUNNING] = "running",
        [SERVICE_EXITED] = "exited",
        [SERVICE_FAILED] = "failed",
};

const char *service_state_to_string(ServiceState s) {
        if (s < 0 || s >= _SERVICE_STATE_MAX)
                return "invalid";

        return service_state_table[s];
}

static const char * const service_restart_table[_SERVICE_RESTART_MAX] = {
        [SERVICE_RESTART_NO] = "no",
        [SERVICE_RESTART_ON_FAILURE] = "on-failure",
};

const char *service_restart_to_string(ServiceRestart r) {
        if (r < 0 || r >= _SERVICE_RESTART_MAX)
                return "invalid";

        return service_restart_table[r];
}
