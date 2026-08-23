/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * M0 placeholder: fork/exec + fd/env/cgroup setup is a stub returning
 * -ENOSYS. Real logic lands in M3/M4 per the plan.
 */

#include <errno.h>

#include "service.h"

int service_spawn(Service *s, char **argv, pid_t *ret_pid) {
        (void) s;
        (void) argv;

        if (ret_pid)
                *ret_pid = 0;

        return -ENOSYS;
}
