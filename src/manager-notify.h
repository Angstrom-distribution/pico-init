/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The sd_notify() listener: one AF_UNIX SOCK_DGRAM socket at
 * <runtime_dir>/notify, bound by PID 1, closing the loop on
 * sd-daemon.c's already-real notify_internal() SENDER.
 *
 * Mode 0666, unlike the control socket's 0600: any service must be able to
 * sendto() here, and with SO_PASSCRED set the kernel -- not this socket's
 * permissions -- is what stops an unprivileged sender from claiming a
 * foreign pid's credentials (sd-daemon.c's own comment on notify_internal()
 * says the same).
 *
 * READY=1 from a Type=notify service's main pid completes its start
 * (service_notify_ready(), service.c); for every other type it is a flag
 * picoctl reports. Not implemented: NotifyAccess= (the sender
 * check is fixed at upstream's =main default), STOPPING=1 as a stop path,
 * RELOADING=1 (no reload machinery exists to drive), the watchdog keys.
 */

#pragma once

#include <stddef.h>

typedef struct Manager Manager;

/* Opaque; defined in manager-notify.c so manager.h need not know its shape. */
struct pico_manager_notify;

/* Bind <runtime_dir>/notify, join the epoll set. 0 or -errno. Failure is not
 * fatal to boot -- sd_notify() degrades to notify_internal()'s own
 * documented no-op, exactly as on an image without this listener. */
int manager_notify_setup(Manager *m);

/* Close the socket and unlink its path. */
void manager_notify_done(Manager *m);

/* NULL when the listener is not up -- service-exec.c's gate for whether to
 * inject NOTIFY_SOCKET= into a child's environment at all. */
const char *manager_notify_socket_path(Manager *m);

/* Test-only: how many validated-but-unattributed datagrams have been
 * dropped (no unit's main/control pid matched the sender). 0 when the
 * listener is not up. */
size_t manager_notify_debug_n_unattributed(Manager *m);
