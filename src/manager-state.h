/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The state publisher (plan §1.7, milestone C0): PID 1 writes one
 * `Property=value` text file per unit under <runtime_dir>/units/<id>, plus one
 * <runtime_dir>/manager file, so picoctl's read verbs need no IPC at all.
 *
 * This is the s6-svstat / OpenRC pattern rather than an invention: status is
 * files, control is one tiny channel. The property it buys is that the files
 * reflect the last transition even when PID 1's loop is wedged -- exactly when
 * a live query would hang instead of answering.
 *
 * Every write goes through the two choke points that already see every
 * transition: unit_notify() for unit/service state, job_finish_full() and
 * job_install() for job state. Nothing else calls in here, so a new transition
 * path cannot silently forget to publish.
 *
 * Updates are atomic tmp+rename(): a reader polling during transition churn
 * must never observe a partial file.
 *
 * The <runtime_dir>/manager file also carries NJobs (jobs currently
 * installed) and NInstalledJobs (cumulative installs since boot): the raw
 * inputs to a boot-progress fraction, published for a separate consumer to
 * turn into a percentage -- PID 1 itself never computes one.
 */

#pragma once

#include "unit.h"

typedef struct Job Job;
typedef struct Manager Manager;

/* Create <runtime_dir>/units/. 0 or -errno. Failure is not fatal to boot:
 * an unwritable /run costs picoctl its read verbs, never the boot itself. */
int manager_state_setup(Manager *m);

/* Remove the published state and free anything the publisher owns. */
void manager_state_done(Manager *m);

/* Re-publish u's file. Called from unit_notify() on every state change, and
 * from manager-notify.c whenever an sd_notify() datagram changes something. */
void manager_state_notify_unit(Unit *u);

/* Re-publish the unit a job applies to, so Job= tracks reality. Called from
 * job_install() and job_finish_full(). */
void manager_state_notify_job(Job *j);

/* Drop u's file. Called from unit_free(): the file must not outlive the unit. */
void manager_state_forget_unit(Unit *u);

/* Re-write <runtime_dir>/manager (objective, default target, unit count,
 * and the NJobs/NInstalledJobs boot-progress counters). */
void manager_state_notify_manager(Manager *m);
