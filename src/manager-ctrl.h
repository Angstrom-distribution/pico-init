/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The picoctl control socket (plan §1.7, milestone C2): one root-only
 * AF_UNIX SOCK_SEQPACKET socket at <runtime_dir>/control, owned and bound by
 * PID 1 directly.
 *
 * Deliberately NOT a .socket unit -- PID 1 cannot socket-activate itself --
 * but the listener and every accepted connection each get their own io
 * source on the manager's own m->event, at EVENT_PRIORITY_CTRL (manager.h).
 *
 * It carries exactly what nothing else can: start/stop/restart (which need
 * manager_add_job()) and reset-failed. Every read verb stays on the state
 * files (manager-state.h), daemon-reload stays SIGHUP, and reboot/poweroff
 * stay on the existing signals -- all three keep working when the socket or
 * the loop is wedged, which is the point.
 *
 * Replies for start/stop/restart are DEFERRED until the job finishes, so
 * picoctl's exit code reports the real job result rather than mere
 * enqueueing (systemctl's own default wait behaviour).
 */

#pragma once

#include <stddef.h>

#include "job.h"
#include "util.h"

typedef struct Manager Manager;

/* Opaque; defined in manager-ctrl.c so manager.h need not know its shape. */
struct pico_manager_ctrl;

/* Bind <runtime_dir>/control mode 0600, listen, join the epoll set.
 * 0 or -errno. Failure is not fatal to boot -- picoctl's mutating verbs are
 * simply unavailable, exactly as they are on an image without the socket. */
int manager_ctrl_setup(Manager *m);

/* Close the socket, unlink its path, drop every pending reply. */
void manager_ctrl_done(Manager *m);

/* Resolve any deferred reply waiting on this job. Called from
 * job_finish_full(), which is the only place a job result becomes final.
 *
 * This can retire the client's connection from deep inside a dispatch of
 * some OTHER event source (a SIGCHLD, typically); safe to do immediately --
 * the connection's own io source, if it holds no other reference right now,
 * is unlinked from the event's live source list on the spot, so a later
 * dispatch in the same batch that might still name it (its own EPOLLHUP)
 * simply never finds it (see manager-ctrl.c's ctrl_conn_free()). */
void manager_ctrl_notify_job_finished(Job *j, JobResult result);

/*
 * Test-only introspection: the number of currently-tracked connections and
 * deferred-reply records. 0 (never an error) when ctrl is not set up at
 * all. Production code never calls these -- they exist so a test can prove
 * an early-disconnecting client leaks nothing, rather than merely asserting
 * the happy path (plan §1.7, C2's own "done when").
 */
size_t manager_ctrl_debug_n_conns(Manager *m);
size_t manager_ctrl_debug_n_pending(Manager *m);
