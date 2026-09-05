/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The Manager: owns the unit table, the load queue, the job run queue, and the
 * single epoll loop multiplexing signalfd + per-service cgroup.events + one
 * timerfd. Implemented across manager.c (lifecycle, unit table, load queue,
 * jobs), manager-loop.c (the epoll loop), manager-startup.c (the boot
 * sequence), manager-shutdown.c (orderly teardown).
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "job.h"
#include "signal.h"
#include "timer.h"
#include "unit.h"
#include "util.h"

/* angstrom-pico-init adopts usrmerge (see plans/29-pico-init.md §4), so
 * this matches oe-core's real systemd_system_unitdir for that distro:
 * /etc overrides admin-placed units, /usr/lib is where packages install
 * theirs -- same two-entry order real systemd searches. */
#define PICO_UNIT_DIR "/etc/systemd/system"
#define PICO_PACKAGED_UNIT_DIR "/usr/lib/systemd/system"

/* Preset files, searched in the same override order. Presets are applied at
 * boot rather than at package-install time: nothing runs `systemctl preset` on
 * an image-built read-only rootfs, so the enablement decision has to be made
 * by whoever reads the units. See unit-enable.h. */
#define PICO_PRESET_DIR "/etc/systemd/system-preset"
#define PICO_PACKAGED_PRESET_DIR "/usr/lib/systemd/system-preset"

/* The root of the boot transaction, matching upstream naming. */
#define PICO_DEFAULT_TARGET "default.target"

/* Upstream .socket units install with WantedBy=sockets.target, so the target
 * must exist for drop-in enablement to resolve at all; ordinary services are
 * ordered After= it so none can race a socket it may be activated by. */
#define PICO_SOCKETS_TARGET "sockets.target"

#define PICO_CGROUP_ROOT "/sys/fs/cgroup"

/*
 * Where PID 1 publishes its own runtime state: per-unit `Property=value`
 * files under units/, one manager file, and the picoctl control socket.
 * Settable on the Manager for the same reason the search paths are -- so a
 * test can point it at a temporary directory instead of the host's real /run.
 * See manager-state.h and manager-ctrl.h (plan §1.7).
 */
#define PICO_RUNTIME_DIR "/run/pico-init"

/* Why the loop ended; main.c maps these to reboot(), poweroff, or a plain
 * return. MANAGER_EXIT is only legal when the manager is not PID 1 -- see
 * manager_dispatch_signal() and main(). */
typedef enum ManagerObjective {
        MANAGER_RUNNING, /* keep looping */
        MANAGER_EXIT,    /* leave the loop without a system state change (tests, non-PID1) */
        MANAGER_REBOOT,
        MANAGER_POWEROFF,
        _MANAGER_OBJECTIVE_MAX,
} ManagerObjective;

struct Manager {
        /* unit table: flat array for now, replace with the quarried hashmap later */
        Unit **units;
        size_t n_units;

        /*
         * Search paths, NULL-terminated and owned. Defaults are the PICO_*
         * macros above; they are settable so tests can point at a temporary
         * tree instead of the host's real /etc and /usr, which is the only way
         * unit loading, enablement and preset application can be tested
         * without root or a container-wide filesystem mutation.
         */
        char **unit_path;
        char **preset_path;
        char *cgroup_root;
        char *runtime_dir;

        /* What manager_startup() was actually asked to boot into, recorded
         * because the published state file must report the real target rather
         * than re-assert the compile-time default. NULL before startup;
         * PICO_DEFAULT_TARGET once startup ran without an override. */
        char *default_target;

        /* State publisher and control socket (plan §1.7). Both are opaque
         * here: manager-state.c and manager-ctrl.c own their shapes, so
         * landing either does not mean editing this header. NULL until the
         * corresponding setup() has run, and NULL is a supported state --
         * an unwritable /run costs picoctl its verbs, never the boot. */
        struct pico_manager_state *state;
        struct pico_manager_ctrl *ctrl;

        /* units waiting for unit_load(), linked via unit->load_queue_next */
        Unit *load_queue;
        bool dispatching_load_queue; /* re-entrancy guard, see manager_load_unit() */

        /* units whose cgroup was observed empty, linked via
         * unit->cgroup_empty_queue_next. Deliberately a queue rather than a
         * direct call: emptiness must not be acted on until every SIGCHLD in
         * the same epoll batch has been reaped, or the exit status is lost.
         * See manager-loop.c. */
        Unit *cgroup_empty_queue;
        bool dispatching_cgroup_empty_queue;

        /* runnable jobs, linked via job->run_queue_next */
        Job *run_queue;
        uint32_t next_job_id;
        unsigned n_jobs;           /* jobs currently installed */
        unsigned n_installed_jobs; /* cumulative installs since boot; see job_install() */

        int epoll_fd;
        PicoSignal *signal;
        PicoTimer *timer;
        struct pico_epoll_tag signal_tag; /* data.ptr for signal's epoll registration */
        struct pico_epoll_tag timer_tag;  /* data.ptr for timer's epoll registration */

        /* true when running as PID 1. Decides whether MANAGER_EXIT is even a
         * legal outcome: returning from main() as PID 1 is a kernel panic. */
        bool is_system;

        ManagerObjective objective;

        /*
         * Where we are heading once the stop jobs have drained.
         * manager_shutdown() sets this rather than `objective` directly: a
         * shutdown that switched objective immediately would leave the loop
         * before any of the stop jobs it just queued had run, so nothing would
         * actually be stopped. MANAGER_RUNNING here means "no shutdown
         * pending".
         */
        ManagerObjective pending_objective;

        /* When to stop waiting for the drain and go anyway. A service that
         * will not die must not be able to keep the machine up forever. */
        usec_t shutdown_deadline;
};

/* --- manager.c --- */
/* Allocate, create epoll/signalfd/timerfd, install the default search paths. 0 or -errno. */
int manager_new(Manager **ret);
Manager *manager_free(Manager *m); /* frees all units and jobs; returns NULL */

/* Replace a search path with a NULL-terminated copy of `path`. For tests. 0 or -errno. */
int manager_set_unit_path(Manager *m, const char * const *path);
int manager_set_preset_path(Manager *m, const char * const *path);
int manager_set_cgroup_root(Manager *m, const char *root);
int manager_set_runtime_dir(Manager *m, const char *dir);

/* Scan every unit_path entry (or just `dir` when non-NULL) for files whose
 * suffix names a known unit type, creating and loading each. 0 or -errno. */
int manager_load_units(Manager *m, const char *dir);

/* Look up a unit by id, NULL if not present. */
Unit *manager_get_unit(Manager *m, const char *id);

/* The service whose main pid is `pid`, or NULL. Used to route SIGCHLD. */
Unit *manager_get_unit_by_pid(Manager *m, pid_t pid);

/*
 * Look up, or create and load, a unit by id. 0 or -errno.
 *
 * Loading is queued, not recursive: the unit is created, pushed onto the load
 * queue and the queue is then drained. A fragment's own Requires=/Wants= call
 * back into this function while its parser is running, and a recursive
 * implementation would blow the stack on a long dependency chain and recurse
 * forever on a dependency cycle. The dispatching_load_queue guard makes those
 * re-entrant calls enqueue and return instead, so the outermost call drains
 * everything iteratively.
 *
 * `id` naming a template ("foo@.service") is rejected with -EINVAL before
 * any of that: a template has no startable identity. See unit-name.h's
 * unit_name_is_template() and manager.c's boot scan, which has its own skip
 * for the same reason.
 */
int manager_load_unit(Manager *m, const char *id, Unit **ret);

/* Append u to the unit table (ownership transfers to the manager). 0 or -errno. */
int manager_add_unit(Manager *m, Unit *u);

/*
 * Drop u from the table and free it. ONLY for a unit that never loaded and
 * so has no fragment, no edges and nothing pointing at it -- see
 * manager.c's own header comment on this function for why that is the one
 * safe condition. 0, or -ENOENT if u is not in the table.
 */
int manager_remove_unit(Manager *m, Unit *u);

/* Push u onto the load queue if it is not already there. */
void manager_enqueue_load(Manager *m, Unit *u);

/* Drain the load queue, calling unit_load() on each entry. Number loaded, or -errno. */
int manager_dispatch_load_queue(Manager *m);

/*
 * Queue u as having a confirmed-empty cgroup, or take it back off again.
 *
 * Dequeue exists because cgroup.events notifications coalesce: a cgroup can go
 * empty and be repopulated before the queue is drained, and acting on the
 * stale notification would declare a running service dead.
 */
void manager_enqueue_cgroup_empty(Manager *m, Unit *u);
void manager_dequeue_cgroup_empty(Manager *m, Unit *u);

/* Drain it, delivering each unit's cgroup-empty event. Number delivered. */
int manager_dispatch_cgroup_empty_queue(Manager *m);

/* Build a transaction for (type, unit) + dependencies and activate it.
 * Installed job via ret (may be NULL). 0 or -errno. */
int manager_add_job(Manager *m, JobType type, Unit *u, Job **ret);

/* Run every runnable job on the run queue. Number started, or -errno. */
int manager_dispatch_run_queue(Manager *m);

/* --- manager-startup.c --- */
/*
 * The boot sequence: load every unit in the search path, resolve enablement
 * (.wants/.requires directories, then presets for whatever they did not
 * cover), check the ordering graph for cycles, and queue a start job for
 * `default_target` (PICO_DEFAULT_TARGET when NULL). 0 or -errno.
 */
int manager_startup(Manager *m, const char *default_target);

/* --- manager-loop.c --- */
/* The epoll loop; blocks until objective != MANAGER_RUNNING.
 * Returns the final ManagerObjective (>= 0), or -errno. */
int manager_loop(Manager *m);

/*
 * Synchronous signal handling. SIGCHLD -> waitpid WNOHANG reap loop routed to
 * the owning service; SIGHUP -> unit reload.
 *
 * Shutdown signals follow the init convention rather than the daemon one,
 * because as PID 1 there is no such thing as "just exit":
 *   SIGINT       (ctrl-alt-del)   -> MANAGER_REBOOT
 *   SIGRTMIN+3                    -> MANAGER_POWEROFF
 *   SIGRTMIN+4                    -> MANAGER_POWEROFF
 *   SIGTERM      as PID 1         -> logged and ignored
 *   SIGTERM      not PID 1        -> MANAGER_EXIT (how tests stop the loop)
 *
 * 0 or -errno.
 */
int manager_dispatch_signal(Manager *m, int signo);

/* --- manager-shutdown.c --- */
/* Queue stop jobs for everything and record where to go once they drain. 0 or -errno. */
int manager_shutdown(Manager *m, ManagerObjective objective);

/* True when a pending shutdown may now be acted on: the run queue has drained,
 * or the deadline passed and a wedged unit is not going to be waited for. */
bool manager_shutdown_finished(Manager *m);

const char *manager_objective_to_string(ManagerObjective o);
