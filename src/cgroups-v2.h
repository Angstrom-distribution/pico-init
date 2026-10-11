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

#include "sd-event.h"
#include "util.h"

struct pico_cgroup {
        char *path;    /* absolute path under the cgroup root */
        int procs_fd;  /* cgroup.procs, opened O_RDWR: written to add pids, read by the SIGKILL fallback */
        int events_fd; /* cgroup.events, opened O_RDONLY and read directly; also the events_source's fd */

        /* io source on events_fd, EVENT_PRIORITY_CGROUP_EVENTS (manager.h) --
         * NULL until cgroup_v2_monitor() runs. Does not own events_fd
         * (set_io_fd_own is never set): cgroup_v2_free() closes it, after
         * the caller has disabled this source, same ordering the old
         * epoll_ctl(DEL)-before-close discipline required. */
        sd_event_source *events_source;

        int kill_fd; /* cgroup.kill, or -1 on kernels older than 5.14 */

        /* The owning Unit, set by whoever created the cgroup, so an
         * events_source wakeup can be routed back to a Service. Opaque here
         * on purpose: this layer must not depend on unit.h or manager.h
         * (manager.h itself pulls in unit.h via job.h). */
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
 * Create events_source (EVENT_PRIORITY_CGROUP_EVENTS, manager.h) on `e` so
 * "populated" transitions wake the loop. Returns 1 if the cgroup is already
 * empty at the moment monitoring starts, 0 if it is populated and monitoring
 * is now armed, or -errno.
 *
 * That tri-state return is arm-then-poll-once (systemd 3a11183858,
 * a5a8776ae5, 869f52f218 -- three independent rediscoveries of the same
 * bug): the cgroup can go from populated to empty in the window between
 * opening cgroup.events and the source's own registration, and EPOLLPRI
 * only fires on a *transition* -- a cgroup that was already empty before
 * registration produces no wakeup, ever. Reading emptiness once,
 * unconditionally, right after arming catches that case synchronously
 * instead of hanging forever waiting for an edge that already happened.
 */
int cgroup_v2_monitor(struct pico_cgroup *cg, sd_event *e);

/*
 * The events_source io callback. Defined in manager-loop.c, declared here
 * rather than pulled in transitively: this layer stays unaware of
 * Unit/Manager (see struct pico_cgroup's own comment), reaching the owning
 * Manager only via cg->userdata (a Unit*) -> u->manager once dispatched.
 */
int manager_dispatch_cgroup_events(sd_event_source *s, int fd, uint32_t revents, void *userdata);

/* True when the kernel offers cgroup.kill for this cgroup (Linux >= 5.14). */
bool cgroup_v2_kill_is_atomic(struct pico_cgroup *cg);

/*
 * Kill every member of the cgroup. 0 or -errno.
 *
 * Fast path: write "1" to cgroup.kill -- atomic and race-free, nothing can
 * fork its way out from under it. That file only exists on Linux >= 5.14.
 *
 * The value is "1", not "all". cgroup.kill takes a boolean; "all" is rejected
 * with EIO; writing "1" kills the members and flips cgroup.events to
 * populated 0.
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

/*
 * Every pid listed in cgroup.procs (this cgroup only, not descendants),
 * minus pid 1 and the caller itself. Up to `max` are stored; *ret_n is the
 * full count, so *ret_n > max means the array was too small. Zombies are
 * still members until reaped, so a pid returned here may be one the
 * manager's SIGCHLD path is about to reap. 0 or -errno.
 */
int cgroup_v2_get_pids(struct pico_cgroup *cg, pid_t *pids, size_t max, size_t *ret_n);

/*
 * One pass of kill(sig) over every pid in cgroup.procs. Returns how many
 * were signalled, or -errno. Not atomic and not repeated: a process forking
 * as the pass runs can escape it, which is why this is the *first* step of a
 * stop and cgroup_v2_kill() above the escalation, never the other way round.
 */
int cgroup_v2_signal(struct pico_cgroup *cg, int sig);

/*
 * Controller plumbing (cgroup.subtree_control). A child cgroup only has a
 * controller's files (cpu.weight, memory.high, ...) when every ancestor
 * enables it for its children, and a cgroup that enables controllers for its
 * children cannot hold processes of its own (the no-internal-process rule).
 *
 * `wanted` is a space-separated list. A controller the kernel does not offer in
 * the directory's cgroup.controllers, or one that is already enabled, is
 * skipped quietly; each remaining one is a separate write, so one the kernel
 * refuses does not stop the others. Returns how many were enabled (>= 0), or
 * -errno when cgroup.controllers / cgroup.subtree_control cannot be read
 * (not a cgroup directory, no such controller interface). *ret_errno, when
 * not NULL, is the first write error, 0 if there was none.
 */
int cgroup_v2_enable_controllers(const char *dir, const char *wanted, int *ret_errno);

/* The inverse: "-name" for every controller cgroup.subtree_control lists.
 * Same return convention. */
int cgroup_v2_disable_controllers(const char *dir, int *ret_errno);

/*
 * Create <root>/system.slice and enable +cpu +memory in the root and in the
 * slice, so unit cgroups get cpu.weight, memory.high and friends. Best effort
 * and never fatal: a controller the kernel refuses is logged and skipped.
 * system.slice holds no processes of its own, so the no-internal-process rule
 * does not apply to it. 0, or -errno when system.slice cannot be created.
 */
int cgroup_v2_prepare_root(const char *root);

/*
 * Remove every descendant cgroup of `path` depth-first, leaving `path`
 * itself. A cgroup that still has processes cannot be removed (EBUSY) and
 * stays, with everything above it. 0 when nothing is left below `path`, else
 * the first error. Never kills anything.
 */
int cgroup_v2_prune_children(const char *path);

/* prune_children, then remove `path` itself. 0 (also when it is already gone) or -errno. */
int cgroup_v2_remove_tree(const char *path);

/*
 * Hand the cgroup to uid/gid, as Delegate=yes does for a User= service: the
 * directory and the files the kernel's delegation rules say the delegatee
 * must own (cgroup.procs, cgroup.subtree_control, cgroup.threads). A file
 * that does not exist is skipped. 0 or -errno of the first real failure.
 */
int cgroup_v2_delegate_to(const char *path, uid_t uid, gid_t gid);

/* The cgroup the manager puts a unit's control processes in when a
 * DelegateSubgroup= is set, so the unit cgroup itself holds no process. */
#define CGROUP_CONTROL_SUBGROUP ".control"

/*
 * True for a name DelegateSubgroup= may use: one path component that the
 * kernel's own files cannot collide with (systemd's rule: no leading '.' or
 * '_', no "cgroup." prefix, no '/', not empty).
 */
bool cgroup_v2_subgroup_name_valid(const char *name);

/*
 * mkdir <parent>/<name> (an existing one is fine) and copy the path to buf.
 * `name` is not checked here: callers pass CGROUP_CONTROL_SUBGROUP or a name
 * cgroup_v2_subgroup_name_valid() accepted. 0 or -errno.
 */
int cgroup_v2_make_subgroup(const char *parent, const char *name, char *buf, size_t size);

/* cgroup_v2_get_pids() for the cgroup directory `dir`, without a struct pico_cgroup. */
int cgroup_v2_get_pids_in(const char *dir, pid_t *pids, size_t max, size_t *ret_n);

/* Close fds, remove the cgroup directory and any empty cgroups below it, free. Returns NULL. */
struct pico_cgroup *cgroup_v2_free(struct pico_cgroup *cg);
