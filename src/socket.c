/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Socket units (plan §1.6) -- scaffolding.
 *
 * The real implementation is quarried from systemd v30 (commit 501c92c)
 * src/socket.c and lands with S0-S2, which own this file. Registering it in
 * the build now, with the vtable and the epoll entry point already wired up,
 * means those milestones add code to a file that already exists and is
 * already built rather than editing meson.build, unit.c and manager-loop.c
 * while other milestones are also editing them.
 *
 * The upstream attribution header (Copyright 2010 Lennart Poettering, the
 * quarry citation and the per-fix backport record) arrives with the quarried
 * body -- it is deliberately absent here, because nothing has been quarried
 * yet and claiming otherwise would be a false provenance record.
 */

#include <errno.h>
#include <stddef.h>

#include "socket.h"
#include "unit.h"

static UnitActiveState socket_active_state(Unit *u) {
        (void) u;
        return UNIT_INACTIVE;
}

static int socket_start(Unit *u) {
        (void) u;
        return -ENOSYS;
}

static int socket_stop(Unit *u) {
        (void) u;
        return -ENOSYS;
}

/*
 * object_size is sizeof(Unit) until S0 defines the real Socket struct.
 * unit_new() allocates exactly this many bytes, so it must never claim to be
 * larger than what actually exists.
 */
const UnitVTable socket_vtable = {
        .object_size = sizeof(Unit),
        .start = socket_start,
        .stop = socket_stop,
        .active_state = socket_active_state,
};

int socket_dispatch_io(Manager *m, struct pico_epoll_tag *tag) {
        (void) m;
        (void) tag;
        return -ENOSYS;
}

int socket_collect_fds(Unit *service, int *fds, size_t n_fds) {
        (void) service;
        (void) fds;
        (void) n_fds;
        return 0; /* no paired socket: the pre-S1 behaviour, and the fallback */
}

void socket_notify_service_dead(Unit *service) {
        (void) service;
}
