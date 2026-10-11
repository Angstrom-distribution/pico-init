/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The Manager: owns the unit table, the load queue, the job run queue, and
 * PID 1's own main loop -- one sd_event (src/compat/libsystemd/sd-event.h)
 * embedded as m->event, the same architecture as modern systemd's PID 1.
 * Implemented across manager.c (lifecycle, unit table, load queue, jobs),
 * manager-loop.c (event source setup and the loop itself), manager-startup.c
 * (the boot sequence), manager-shutdown.c (orderly teardown).
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "job.h"
#include "sd-event.h"
#include "signal.h"
#include "timer.h"
#include "unit.h"
#include "util.h"

/*
 * Dispatch priorities for every PID1 event source, mirroring the load-
 * bearing order manager-loop.c's own header lays out (cgroup verify, then
 * signals, then cgroup-empty, then timers, then the run queue) --
 * as int64 priorities the shim's sd_event_dispatch() enforces: strictly
 * lowest-priority-first, one source per dispatch, re-
 * polling with a zero timeout between dispatches while anything stays
 * pending. Patterned on real systemd's own table (src/core/manager.h).
 */
enum {
        EVENT_PRIORITY_WATCHDOG = SD_EVENT_PRIORITY_NORMAL -
                        20, /* hardware watchdog feed: must outrank everything, see manager-loop.c */
        EVENT_PRIORITY_CGROUP_EVENTS = SD_EVENT_PRIORITY_NORMAL - 10, /* verify + queue only, never acts */
        EVENT_PRIORITY_NOTIFY = SD_EVENT_PRIORITY_NORMAL -
                        5, /* before SIGCHLD: attribution needs main_pid still set */
        EVENT_PRIORITY_EXEC_FD = SD_EVENT_PRIORITY_NORMAL -
                        5, /* before SIGCHLD: a Type=exec process that exec'd and died in one batch
                            * went RUNNING first, so its exit is judged as a running daemon's */
        EVENT_PRIORITY_SIGNALS = SD_EVENT_PRIORITY_NORMAL - 4, /* SIGCHLD reaped + attributed here */
        EVENT_PRIORITY_SOCKET = SD_EVENT_PRIORITY_NORMAL - 3,
        EVENT_PRIORITY_CTRL = SD_EVENT_PRIORITY_NORMAL - 3,
        EVENT_PRIORITY_CGROUP_EMPTY = SD_EVENT_PRIORITY_NORMAL - 2,
        EVENT_PRIORITY_PICO_TIMER = SD_EVENT_PRIORITY_NORMAL,
        EVENT_PRIORITY_RUN_QUEUE = SD_EVENT_PRIORITY_IDLE + 1,
        EVENT_PRIORITY_SHUTDOWN_CHECK = SD_EVENT_PRIORITY_IDLE + 2,
        EVENT_PRIORITY_SOCKET_REAP = SD_EVENT_PRIORITY_IDLE + 3, /* last: frees units other sources name */
};

/* Assumes a usrmerged rootfs: /etc overrides admin-placed units, /usr/lib is
 * where packages install theirs -- same two-entry order real systemd
 * searches. */
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
 * See manager-state.h and manager-ctrl.h.
 */
#define PICO_RUNTIME_DIR "/run/pico-init"

/* The fstab pass's outcome record (fstab.h), beside the unit state it is read
 * together with. Written pre-manager, so it cannot follow a runtime_dir a test
 * sets on the Manager; the pass takes its own path instead. */
#define PICO_FSTAB_RECORD PICO_RUNTIME_DIR "/fstab"

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
        /* unit table: flat array; a hashmap would replace it if the unit count ever warranted */
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

        /* Device path override for manager_watchdog_setup(); NULL means the
         * real default probe (/dev/watchdog0 then /dev/watchdog). For tests
         * only -- see manager_set_watchdog_device(). */
        char *watchdog_device;

        /* What manager_startup() was actually asked to boot into, recorded
         * because the published state file must report the real target rather
         * than re-assert the compile-time default. NULL before startup;
         * PICO_DEFAULT_TARGET once startup ran without an override. */
        char *default_target;

        /* State publisher, control socket, sd_notify() listener, and the
         * hardware watchdog feeder (manager-state.h,
         * manager-ctrl.h, manager-notify.h, manager-watchdog.h). All four are
         * opaque here: their own .c files own their shapes.
         * NULL until the corresponding setup() has run, and NULL is a
         * supported state -- an unwritable /run costs picoctl its verbs and
         * sd_notify() its listener, an absent /dev/watchdog costs only
         * watchdog protection, never the boot. */
        struct pico_manager_state *state;
        struct pico_manager_ctrl *ctrl;
        struct pico_manager_notify *notify;
        struct pico_manager_watchdog *watchdog;

        /* units waiting for unit_load(), linked via unit->load_queue_next */
        Unit *load_queue;
        bool dispatching_load_queue; /* re-entrancy guard, see manager_load_unit() */

        /* units whose cgroup was observed empty, linked via
         * unit->cgroup_empty_queue_next. A queue rather than a
         * direct call: emptiness must not be acted on until every SIGCHLD in
         * the same epoll batch has been reaped, or the exit status is lost.
         * See manager-loop.c. */
        Unit *cgroup_empty_queue;
        bool dispatching_cgroup_empty_queue;

        /* cgroups whose unit is gone while processes were still running in
         * them (KillMode=process or none, an ssh login's screen or tmux).
         * A slow timer removes each one once it has emptied. */
        struct pico_cgroup_orphan *orphan_cgroups;
        PicoTimerEvent *orphan_timer;

        /* runnable jobs, linked via job->run_queue_next */
        Job *run_queue;
        uint32_t next_job_id;
        unsigned n_jobs;           /* jobs currently installed */
        unsigned n_installed_jobs; /* cumulative installs since boot; see job_install() */

        sd_event *event; /* the main loop; PID 1 is a real sd_event consumer, systemd-style */
        PicoSignal *signal;
        PicoTimer *timer;
        sd_event_source *signal_source;         /* io on pico_signal_fd(), EVENT_PRIORITY_SIGNALS */
        sd_event_source *timer_source;          /* io on pico_timer_fd(), EVENT_PRIORITY_PICO_TIMER */
        sd_event_source *run_queue_source;      /* defer, ONESHOT-gated by manager_trigger_run_queue() */
        sd_event_source *cgroup_empty_source;   /* defer, ONESHOT-gated by manager_enqueue_cgroup_empty() */
        sd_event_source *shutdown_check_source; /* post, always ON; adopts pending_objective */
        sd_event_source *shutdown_deadline_source; /* time; NULL unless a shutdown is pending */

        /* true when running as PID 1. Decides whether MANAGER_EXIT is even a
         * legal outcome: returning from main() as PID 1 is a kernel panic. */
        bool is_system;

        /*
         * Whether /etc/machine-id was missing, empty or "uninitialized" this
         * boot (main.c's machine_id_setup() call, before manager_new() --
         * see machine-id-setup.h). False by default, so a test that builds a
         * Manager directly never applies presets without asking for that
         * explicitly, matching upstream's own manager_set_first_boot(): the
         * one thing manager_startup() consults it for is whether to apply
         * presets at all (unit-enable.h's own header comment says why that
         * is a once-ever, not every-boot, decision).
         */
        bool first_boot;

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

        /* set once manager_log_degradation_summary() has logged its one line */
        bool degradation_summary_logged;
};

/* --- manager.c --- */
/* Allocate, create the sd_event loop + signalfd/timerfd and their event
 * sources, install the default search paths. 0 or -errno. */
int manager_new(Manager **ret);
Manager *manager_free(Manager *m); /* frees all units and jobs; returns NULL */

/* Replace a search path with a NULL-terminated copy of `path`. For tests. 0 or -errno. */
int manager_set_unit_path(Manager *m, const char * const *path);
int manager_set_preset_path(Manager *m, const char * const *path);
int manager_set_cgroup_root(Manager *m, const char *root);
int manager_set_runtime_dir(Manager *m, const char *dir);
int manager_set_watchdog_device(Manager *m, const char *path);

/* Record whether this boot is a first boot (main.c's machine_id_setup()
 * result) -- see Manager.first_boot above for what that gates. A no-op
 * setter, not fallible: there is nothing to allocate. */
void manager_set_first_boot(Manager *m, bool first_boot);

/* Scan every unit_path entry (or just `dir` when non-NULL) for files whose
 * suffix names a known unit type, creating and loading each. 0 or -errno. */
int manager_load_units(Manager *m, const char *dir);

/* Look up a unit by id, NULL if not present. */
Unit *manager_get_unit(Manager *m, const char *id);

/* The service whose main pid is `pid`, or NULL. Used to route SIGCHLD. */
Unit *manager_get_unit_by_pid(Manager *m, pid_t pid);

/* Units carrying a degradation record (unit.h). */
size_t manager_count_degraded_units(Manager *m);

/* The one boot-time summary line naming how many loaded units carry a
 * degradation record. job.c calls it when the default target's start job
 * finishes; a second call is a no-op. */
void manager_log_degradation_summary(Manager *m);

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

/* SIGHUP: unit_reload() every unit in the table (unit-reload.c). Number
 * reloaded, or -EINVAL. */
int manager_reload(Manager *m);

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

/* Take over a cgroup that still has processes in it: no unit owns it any
 * more, the manager removes it when it empties. 0 and the manager owns cg, or
 * -errno and the caller still does. */
struct pico_cgroup;
int manager_adopt_cgroup(Manager *m, struct pico_cgroup *cg);
void manager_reap_orphan_cgroups(Manager *m);

/* Build a transaction for (type, unit) + dependencies and activate it.
 * Installed job via ret (may be NULL). 0 or -errno. */
int manager_add_job(Manager *m, JobType type, Unit *u, Job **ret);

/* Run every runnable job on the run queue. Number started, or -errno. */
int manager_dispatch_run_queue(Manager *m);

/* --- manager-startup.c --- */
/*
 * The boot sequence: load every unit in the search path, resolve enablement
 * (.wants/.requires directories always; presets too, but ONLY when
 * m->first_boot -- see manager_set_first_boot() and unit-enable.h's own
 * comment on manager_apply_presets() for why that is a once-ever decision),
 * check the ordering graph for cycles, and queue a start job for
 * `default_target` (PICO_DEFAULT_TARGET when NULL). 0 or -errno.
 */
int manager_startup(Manager *m, const char *default_target);

/* --- manager-loop.c --- */

/*
 * Create every PID1 event source on m->event at its EVENT_PRIORITY_* and
 * wire it to the right dispatch callback: signal_source, timer_source,
 * run_queue_source, cgroup_empty_source, shutdown_check_source. Called once
 * from manager_new(), after pico_signal_new()/pico_timer_new(). 0 or -errno.
 */
int manager_events_setup(Manager *m);

/* The main loop; blocks until objective != MANAGER_RUNNING.
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

/*
 * A job just became (or may have become) runnable: arm the run-queue defer
 * source ONESHOT so the next sd_event_run() drains it. Called unconditionally
 * from job_add_to_run_queue(), before its in_run_queue early-return -- the
 * queue can hold jobs that never left it (a neighbour re-add), so a trigger
 * gated on insertion would never fire for those and the boot would hang. A
 * NULL m->run_queue_source (not yet set up) is a silent no-op.
 */
void manager_trigger_run_queue(Manager *m);

/*
 * Arm the shutdown-deadline time source at m->shutdown_deadline. Called only
 * by manager_shutdown()'s first-request branch. If arming fails (OOM), the
 * objective is adopted immediately rather than risking an unbounded wait
 * with no deadline wakeup at all.
 */
void manager_arm_shutdown_deadline(Manager *m);

/* --- manager-shutdown.c --- */
/* Queue stop jobs for everything and record where to go once they drain. 0 or -errno. */
int manager_shutdown(Manager *m, ManagerObjective objective);

/* True when a pending shutdown may now be acted on: every installed job has
 * finished, or the deadline passed and a wedged unit is not going to be waited for. */
bool manager_shutdown_finished(Manager *m);

const char *manager_objective_to_string(ManagerObjective o);
