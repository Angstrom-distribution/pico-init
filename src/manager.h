/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The Manager: owns the unit table, the job run queue, and the single
 * epoll loop multiplexing signalfd + per-service cgroup.events + one
 * timerfd. Implemented across manager.c (lifecycle, unit table, jobs),
 * manager-loop.c (the epoll loop), manager-shutdown.c (orderly teardown).
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

/* Why the loop ended; main.c maps these to exit(), reboot(), poweroff. */
typedef enum ManagerObjective {
        MANAGER_RUNNING, /* keep looping */
        MANAGER_EXIT,    /* leave the loop without a system state change (tests, non-PID1) */
        MANAGER_REBOOT,
        MANAGER_POWEROFF,
        _MANAGER_OBJECTIVE_MAX,
} ManagerObjective;

struct Manager {
        /* unit table: flat array for M0, replace with the quarried hashmap later */
        Unit **units;
        size_t n_units;

        /* units waiting for unit_load(), linked via unit->load_queue_next */
        Unit *load_queue;

        /* runnable jobs, linked via job->run_queue_next */
        Job *run_queue;
        uint32_t next_job_id;

        int epoll_fd;
        PicoSignal *signal;
        PicoTimer *timer;
        struct pico_epoll_tag signal_tag; /* data.ptr for signal's epoll registration */
        struct pico_epoll_tag timer_tag;  /* data.ptr for timer's epoll registration */

        ManagerObjective objective;
};

/* --- manager.c --- */
/* Allocate, create epoll/signalfd/timerfd. 0 or -errno. */
int manager_new(Manager **ret);
Manager *manager_free(Manager *m); /* frees all units and jobs; returns NULL */

/* Scan dir (default PICO_UNIT_DIR) for *.service, create + load each unit. 0 or -errno. */
int manager_load_units(Manager *m, const char *dir);

/* Look up a unit by id, NULL if not present. */
Unit *manager_get_unit(Manager *m, const char *id);

/* Look up or create+load a unit by id. 0 or -errno. */
int manager_load_unit(Manager *m, const char *id, Unit **ret);

/* Build a transaction for (type, unit) + dependencies and activate it.
 * Installed job via ret (may be NULL). 0 or -errno. */
int manager_add_job(Manager *m, JobType type, Unit *u, Job **ret);

/* Run every runnable job on the run queue. Number started, or -errno. */
int manager_dispatch_run_queue(Manager *m);

/* --- manager-loop.c --- */
/* The epoll loop; blocks until objective != MANAGER_RUNNING.
 * Returns the final ManagerObjective (>= 0), or -errno. */
int manager_loop(Manager *m);

/* Synchronous signal handling: SIGCHLD -> waitpid WNOHANG reap loop,
 * SIGTERM -> orderly shutdown, SIGHUP -> unit reload. 0 or -errno. */
int manager_dispatch_signal(Manager *m, int signo);

/* --- manager-shutdown.c --- */
/* Queue stop jobs for everything, set the objective for after teardown. 0 or -errno. */
int manager_shutdown(Manager *m, ManagerObjective objective);

const char *manager_objective_to_string(ManagerObjective o);
