/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Socket units (plan §1.6). Scaffolding only at this point: the real type,
 * its state machine and its quarried body land with milestones S0-S2, which
 * own this file. What is fixed here is the contract manager-loop.c and unit.c
 * are already written against, so neither has to be edited again to land it.
 */

#pragma once

#include "unit.h"
#include "util.h"

typedef struct Manager Manager;

/*
 * EPOLLIN on a .socket unit's listening fd. Under Accept=no PID 1 never
 * accept()s -- the connection stays queued in the backlog and is handed to
 * the paired service, which is what makes the socket survive a service
 * restart. `tag` is the registration's data.ptr; the implementation casts it
 * back to its own containing struct. 0 or -errno.
 */
int socket_dispatch_io(Manager *m, struct pico_epoll_tag *tag);

/*
 * Collect the fds a starting service should inherit from its paired
 * .socket unit, if any. Called on ANY service start, not just a
 * socket-triggered one: a service started at boot with its socket already
 * listening must get the same fds the same way (the journald arrangement,
 * and the one logd relies on).
 *
 * Returns the number of fds written to `fds` (0 when the service has no
 * paired socket), or -errno. `fds` is caller-owned, `n_fds` its capacity.
 */
int socket_collect_fds(Unit *service, int *fds, size_t n_fds);

/* The paired service died: re-arm RUNNING -> LISTENING so the next
 * connection triggers it again. */
void socket_notify_service_dead(Unit *service);
