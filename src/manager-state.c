/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The state publisher (plan §1.7, C0) -- scaffolding. See manager-state.h for
 * the contract; C0 owns this file and lands the real bodies.
 *
 * The hooks in unit.c and job.c already call every function here, so C0 adds
 * code to a file that is already wired into every transition path instead of
 * editing those two files while another milestone is also editing them. Until
 * then every call is a no-op, which is exactly the behaviour of an image
 * whose /run is unwritable -- the degradation path C0 has to support anyway.
 */

#include <errno.h>

#include "job.h"
#include "manager-state.h"
#include "unit.h"

int manager_state_setup(Manager *m) {
        (void) m;
        return 0;
}

void manager_state_done(Manager *m) {
        (void) m;
}

void manager_state_notify_unit(Unit *u) {
        (void) u;
}

void manager_state_notify_job(Job *j) {
        (void) j;
}

void manager_state_forget_unit(Unit *u) {
        (void) u;
}

void manager_state_notify_manager(Manager *m) {
        (void) m;
}
