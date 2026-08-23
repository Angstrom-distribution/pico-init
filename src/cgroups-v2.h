/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * cgroups v2 (unified hierarchy) supervision layer. One cgroup per unit at
 * <cgroup root>/system.slice/<unit>; cgroup.events is epoll-watchable so
 * service-exit detection needs no polling.
 */

#pragma once

#include <stdbool.h>
#include <sys/types.h>

#include "util.h"

struct pico_cgroup {
        /* First member, so cgroup_v2_monitor()'s epoll registration can hand
         * out &cg->epoll_tag and manager-loop.c's dispatch can cast it back
         * to struct pico_cgroup * -- see the PicoEpollSource comment in
         * util.h for why this must be tagged rather than registered by fd. */
        struct pico_epoll_tag epoll_tag;
        char *path;     /* absolute path under the cgroup root */
        int procs_fd;   /* cgroup.procs, opened O_RDWR: written to add pids, read by the SIGKILL fallback */
        int events_fd;  /* cgroup.events, kept open for epoll registration */
        int kill_fd;    /* cgroup.kill, or -1 on kernels older than 5.14 */
        int events_efd; /* fd registered in the manager's epoll for events changes */

        /* The owning Unit, set by whoever created the cgroup, so a
         * PICO_EPOLL_CGROUP wakeup can be routed back to a Service. Opaque
         * here on purpose: this layer must not depend on unit.h. */
        void *userdata;
};

/* Create the cgroup directory and open its control files. 0 or -errno.
 *
 * cgroup.kill (Linux >= 5.14) is opened best-effort: its absence is not
 * fatal and leaves kill_fd == -1, so cgroup_v2_kill() falls back to the
 * SIGKILL-and-poll loop below. Making that open fatal would fail every
 * service start on exactly the kernels the fallback exists for. */
int cgroup_v2_new(const char *path, struct pico_cgroup **ret);

/* Write pid into cgroup.procs. 0 or -errno. */
int cgroup_v2_add_process(struct pico_cgroup *cg, pid_t pid);

/*
 * Register events_efd on epoll_fd so "populated" transitions wake the loop.
 * Returns 1 if the cgroup is already empty at the moment monitoring starts,
 * 0 if it is populated and monitoring is now armed, or -errno.
 *
 * That tri-state return is arm-then-poll-once (systemd 3a11183858,
 * a5a8776ae5, 869f52f218 -- three independent rediscoveries of the same
 * bug): the cgroup can go from populated to empty in the window between
 * opening cgroup.events and this epoll_ctl() call, and EPOLLPRI only fires
 * on a *transition* -- a cgroup that was already empty before registration
 * produces no wakeup, ever. Reading emptiness once, unconditionally, right
 * after arming catches that case synchronously instead of hanging forever
 * waiting for an edge that already happened.
 */
int cgroup_v2_monitor(struct pico_cgroup *cg, int epoll_fd);

/* True when the kernel offers cgroup.kill for this cgroup (Linux >= 5.14). */
bool cgroup_v2_kill_is_atomic(struct pico_cgroup *cg);

/*
 * Kill every member of the cgroup. 0 or -errno.
 *
 * Fast path: write "1" to cgroup.kill -- atomic and race-free, nothing can
 * fork its way out from under it. That file only exists on Linux >= 5.14.
 *
 * The value is "1", not "all". cgroup.kill takes a boolean; "all" is rejected
 * with EIO. (plans/29-pico-init.md §1.2 says "all" -- it is wrong, verified
 * against a real 6.18 kernel: writing "all" fails every time, writing "1"
 * kills the members and flips cgroup.events to populated 0.)
 *
 * Fallback, when it does not: read cgroup.procs and SIGKILL each pid, then
 * re-read until the cgroup is empty (bounded, so a pathological forker cannot
 * hang the manager). This is what cgroup-v1 supervisors always did -- not
 * atomic, hence the loop. It exists so pico-init's minimum kernel stays at the
 * cgroup-v2 unified-hierarchy floor rather than jumping to 5.14, which matters
 * on old ARM targets where a vendor kernel is exactly what you get.
 */
int cgroup_v2_kill(struct pico_cgroup *cg);

/* 1 if populated=0, 0 if still populated, -errno on error. */
int cgroup_v2_is_empty(struct pico_cgroup *cg);

/* Close fds, remove the cgroup directory, free. Returns NULL. */
struct pico_cgroup *cgroup_v2_free(struct pico_cgroup *cg);
