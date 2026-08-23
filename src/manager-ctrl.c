/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The picoctl control socket (plan §1.7, C2) -- scaffolding. See
 * manager-ctrl.h for the contract; C2 owns this file and lands the real
 * bodies.
 *
 * Until then manager_ctrl_setup() returns 0 without binding anything: an
 * image with no control socket is a supported configuration (C0+C1's read and
 * symlink verbs are useful with no socket existing at all), so the no-op is
 * the real fallback behaviour rather than a placeholder that has to be
 * removed.
 */

#include <errno.h>

#include "job.h"
#include "manager-ctrl.h"

int manager_ctrl_setup(Manager *m) {
        (void) m;
        return 0;
}

void manager_ctrl_done(Manager *m) {
        (void) m;
}

int manager_ctrl_dispatch(Manager *m, struct pico_epoll_tag *tag) {
        (void) m;
        (void) tag;
        return -ENOSYS;
}

void manager_ctrl_notify_job_finished(Job *j, JobResult result) {
        (void) j;
        (void) result;
}
