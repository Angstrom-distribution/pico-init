/* SPDX-FileCopyrightText: 2010 Lennart Poettering */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Jobs and transactions, quarried from systemd's ~2011-era src/job.c and the
 * transaction logic then living in src/manager.c (tag v30, commit 501c92c,
 * copyright 2010 Lennart Poettering, GPL-2.0-or-later -- the LGPL relicense
 * 5430f7f2bc came nine months later). Upstream split that logic out into
 * src/core/transaction.c in 75778e21df and made the transaction a heap object
 * in 7527cb5275, which is the API shape job.h describes.
 *
 * v30's ten-step transaction_activate() pipeline is preserved, including its
 * step numbering, because fourteen years of upstream churn did not change it.
 * Steps that cannot do anything in this much smaller model are kept as
 * numbered no-ops with the reason stated, rather than silently dropped.
 *
 * Backported fixes, each with its upstream hash:
 *
 *  - e602f15282 + dfd79eca55 "extract job ordering logic" / "check transaction
 *    against execution cycles" -- the important one. v30 hand-codes the
 *    ordering rule in several places and its cycle checker walks only Before=
 *    edges, assuming execution order always follows declared order. It does
 *    not: a stop job always runs first. Both job_is_runnable() and the cycle
 *    DFS here route through one job_compare() primitive instead, and the DFS
 *    traverses both directions.
 *  - dd17d38879 "fix loss of ordering with restart jobs" -- job_run() must not
 *    peek at unit state and rewrite a restart into a start in place; that
 *    bypasses the runnability check. The conversion happens only in
 *    job_finish_full().
 *  - 57981b9812 "after converting a job from restart to start readd it to the
 *    run queue" -- and that conversion must not return early, or every job
 *    ordered around the restarting unit waits forever. Hence the goto.
 *  - 563ba9ea6e + 1abc85b8d0 "cancel jobs non-recursively" -- job_finish_full()
 *    takes an explicit recursion flag so completion inside transaction
 *    activation cannot re-enter the transaction code that is still iterating.
 *  - 4e7bd268ae "fix detection of cycles involving installed jobs" -- every
 *    installed job's generation is reset before the sweep. A stale marker
 *    reads as "already visited, loop-free" and the deadlock goes undetected.
 *  - 375ae4aa4d "fix cycle break attempts outside transaction" -- the victim
 *    must be a job in this transaction, or the delete is a no-op and the
 *    -EAGAIN retry loop livelocks.
 *  - 6530407524 "add starting requirements for JOB_RESTART" -- a restart pulls
 *    in both the start-side and the stop-side dependency sets.
 *  - 656bbffc6c + 3c956cfee2 + d6a093d098 "a job is never both in a
 *    transaction and installed" -- job_install()/job_uninstall()/job_free()
 *    keep the two sets disjoint by construction.
 *  - dc06321fe3 "don't discard propagated restart jobs when unit is
 *    activating" -- job_type_is_redundant()'s restart arm is flatly false.
 *  - 348e27fedf "use a lookup table for merging of job types".
 *  - 3e1aec3036 "handle job ID overflow or conflict more sanely".
 *  - 143126cbcd "properly initialize all enum fields" -- a fresh job's result
 *    is _JOB_RESULT_INVALID, not 0 (which is JOB_DONE).
 *  - 66aa6f7fbb + 735a8b6d38 "only jobs on the runqueue can be run" / coverity
 *    -- in_run_queue is set only on a successful insertion.
 *  - da8e178296 "make the run queue order deterministic" -- FIFO append and a
 *    stable install order. Upstream measured ~100ms of boot jitter from
 *    getting this wrong on small embedded devices, which is this project's
 *    exact target.
 *  - 097537f07a -> cc479760b4 is not taken: upstream's "cleverer"
 *    redundancy test was reverted by every major distro and then by upstream
 *    itself. v30's naive state test is what it returned to.
 *
 * Not taken: JOB_NOP and job-type collapsing (e0209d83e7), try-restart and
 * reload types, job modes and the destructiveness check, isolate, job
 * timeouts, job garbage collection (only device units are collectable), the
 * Requisite=/BindsTo=/OnFailure= dependency families, every
 * D-Bus/Varlink job object, and serialization across daemon-reload.
 *
 * Conflicts= follows current upstream rather than v30: a start or restart
 * pulls in a stop of every Conflicts=/ConflictedBy= peer
 * (transaction_add_conflict_deps()), and an activation that bypassed the
 * transaction stops active peers retroactively (unit_stop_conflicting(),
 * called from service.c's state change).
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "job.h"
#include "manager-ctrl.h"
#include "manager-state.h"
#include "manager.h"
#include "socket.h"
#include "status.h"
#include "unit.h"
#include "util.h"

struct Transaction {
        Manager *manager;
        Job **jobs; /* owned array; the jobs are owned until activation */
        size_t n_jobs;
        Job *anchor_job; /* the request this transaction exists to satisfy */
};

/* --- run queue --- */

static void job_unlink_run_queue(Job *j) {
        Job **cur;

        if (!j->in_run_queue)
                return;

        for (cur = &j->manager->run_queue; *cur; cur = &(*cur)->run_queue_next)
                if (*cur == j) {
                        *cur = j->run_queue_next;
                        break;
                }

        j->run_queue_next = NULL;
        j->in_run_queue = false;
}

/* Append, never prepend: the run queue is meant to read as "what happens, in
 * what order", and prepending onto a list fed by an enumeration reverses it. */
void job_add_to_run_queue(Job *j) {
        Job **cur;

        if (!j)
                return;

        /*
         * Unconditional, BEFORE the in_run_queue early-return below: the
         * queue can hold a job that never left it (this same function's
         * neighbour-wakeup callers re-add a job still sitting there waiting
         * on another unit), and a trigger gated on insertion would never
         * fire for that job once it actually becomes runnable -- deadlocking
         * the boot rather than costing one extra dispatch. See
         * manager_trigger_run_queue()'s own contract note in manager-loop.c.
         */
        manager_trigger_run_queue(j->manager);

        if (j->in_run_queue)
                return;

        for (cur = &j->manager->run_queue; *cur; cur = &(*cur)->run_queue_next)
                ;

        *cur = j;
        j->run_queue_next = NULL;
        j->in_run_queue = true; /* only on a successful insertion */
}

/* --- job type algebra --- */

/*
 * Lower triangle of the merge table: what a job of type `a` becomes when a
 * request of type `b` arrives for the same unit. _JOB_TYPE_INVALID means the
 * two conflict and cannot be merged. Three types make this small, but keeping
 * it a table rather than three hand-written predicates is the point -- the
 * predicates below are all derived from this one place.
 */
static JobType job_type_merge_table[_JOB_TYPE_MAX][_JOB_TYPE_MAX] = {
        /*                 START               STOP                RESTART      */
        [JOB_START] = {         JOB_START, _JOB_TYPE_INVALID,       JOB_RESTART },
        [JOB_STOP] = { _JOB_TYPE_INVALID,          JOB_STOP, _JOB_TYPE_INVALID },
        [JOB_RESTART] = {       JOB_RESTART, _JOB_TYPE_INVALID,       JOB_RESTART },
};

static JobType job_type_lookup_merge(JobType a, JobType b) {
        if (a < 0 || a >= _JOB_TYPE_MAX || b < 0 || b >= _JOB_TYPE_MAX)
                return _JOB_TYPE_INVALID;

        return job_type_merge_table[a][b];
}

static bool job_type_is_mergeable(JobType a, JobType b) {
        return job_type_lookup_merge(a, b) != _JOB_TYPE_INVALID;
}

static bool job_type_is_conflicting(JobType a, JobType b) {
        return !job_type_is_mergeable(a, b);
}

/* Is `a` already at least as strong a request as `b`? */
static bool job_type_is_superset(JobType a, JobType b) {
        return job_type_lookup_merge(a, b) == a;
}

/* Would this job be a no-op given the unit's current state? */
static bool job_type_is_redundant(JobType t, UnitActiveState s) {
        switch (t) {
        case JOB_START:
                return s == UNIT_ACTIVE;

        case JOB_STOP:
                return s == UNIT_INACTIVE || s == UNIT_FAILED;

        case JOB_RESTART:
                /*
                 * Never redundant. v30 returns "activating", reasoning that a
                 * unit already coming up need not restart -- but it may have
                 * captured stale state from the dependency that just
                 * restarted, so the restart still has to happen (dc06321fe3).
                 */
                return false;

        default:
                return false;
        }
}

/* --- ordering --- */

/*
 * Which of two jobs runs first, given a declared ordering edge between their
 * units. Negative means `a` runs before `b`.
 *
 * The whole subtlety is the stop case: a stop job runs first regardless of
 * which way the declared edge points, because tearing something down happens
 * in the opposite order to bringing it up. v30 assumed execution order always
 * equals declared order, which is what made its cycle checker report cycles
 * that would in fact have executed fine.
 */
static int job_compare(Job *a, Job *b, UnitDependency dep) {
        if (!a || !b)
                return 0;

        if (dep == UNIT_AFTER)
                return -job_compare(b, a, UNIT_BEFORE);

        /* dep == UNIT_BEFORE: a is declared before b */
        if (b->type == JOB_STOP || b->type == JOB_RESTART)
                return 1; /* b tears down first, so a runs after */

        return -1;
}

bool job_is_runnable(Job *j) {
        size_t i;

        if (!j || !j->unit)
                return false;

        /* Everything this unit is declared to run After= must have finished. */
        for (i = 0; i < j->unit->n_dependencies[UNIT_AFTER]; i++) {
                Unit *other = j->unit->dependencies[UNIT_AFTER][i];

                if (other->job && job_compare(j, other->job, UNIT_AFTER) > 0)
                        return false;
        }

        /* And anything declared Before= this unit that must nonetheless go
         * first -- which is exactly the stop case job_compare() encodes. */
        for (i = 0; i < j->unit->n_dependencies[UNIT_BEFORE]; i++) {
                Unit *other = j->unit->dependencies[UNIT_BEFORE][i];

                if (other->job && job_compare(j, other->job, UNIT_BEFORE) > 0)
                        return false;
        }

        return true;
}

/* --- job lifecycle --- */

/* Is this id already taken by a live job? */
static bool job_id_in_use(Manager *m, uint32_t id) {
        size_t i;

        for (i = 0; i < m->n_units; i++)
                if (m->units[i]->job && m->units[i]->job->id == id)
                        return true;

        return false;
}

int job_new(Manager *m, JobType type, Unit *u, Job **ret) {
        unsigned wrapped = 0;
        Job *j;

        if (!m || !u || !ret)
                return -EINVAL;

        j = calloc(1, sizeof(Job));
        if (!j)
                return -ENOMEM;

        j->manager = m;
        j->unit = u;
        j->type = type;
        j->state = JOB_WAITING;

        /* Explicitly, not by relying on calloc: 0 is JOB_DONE, and a fresh job
         * has no result at all (143126cbcd). */
        j->result = _JOB_RESULT_INVALID;

        /* Skip ids already in use, and survive the wrap at UINT32_MAX rather
         * than colliding with a live job (3e1aec3036). */
        for (;;) {
                j->id = m->next_job_id;

                if (m->next_job_id == UINT32_MAX) {
                        m->next_job_id = 1;
                        wrapped++;
                } else
                        m->next_job_id++;

                if (!job_id_in_use(m, j->id))
                        break;

                if (wrapped > 1) {
                        /* every id taken: cannot happen with a sane unit count */
                        free(j);
                        return -EBUSY;
                }
        }

        *ret = j;
        return 0;
}

/* Hand the job to the manager: attach to the unit and queue it. */
static void job_install(Job *j) {
        Job *old;

        if (!j || j->installed)
                return;

        /*
         * A job already installed on this unit is superseded, not silently
         * discarded. Overwriting unit->job left the old one installed, still
         * on the run queue and unreachable: it never finished, never freed,
         * and anything waiting on its result waited forever. Three real
         * callers reach it -- a second control-socket request for one unit,
         * manager_shutdown()'s stop sweep landing on a unit with a start job
         * in flight, and any transaction pulling the unit in as a dependency.
         *
         * recursive = false: this runs inside transaction_activate(), which is
         * still iterating the transaction -- the same reason
         * job_propagate_failure() passes false (563ba9ea6e, 1abc85b8d0).
         */
        old = j->unit->job;
        if (old && old != j)
                job_finish_full(old, JOB_CANCELED, false);

        j->unit->job = j;
        j->installed = true;

        /*
         * Quarried shape: v30 src/manager.c:1238 increments n_installed_jobs
         * at exactly this point in transaction_apply()'s install loop (tag
         * v30, commit 501c92c); pico's job_install() is that loop's body.
         *
         * Ordering note -- do not move these above the superseded-job cancel
         * a few lines up: that job_finish_full() runs job_uninstall() on the
         * OLD job first, so its decrement lands before this increment and
         * n_jobs stays exact.
         */
        j->manager->n_jobs++;
        j->manager->n_installed_jobs++;

        job_add_to_run_queue(j);

        /* A unit with a job enqueued must report it (Job= in the published
         * state file) before the job runs, not after it finishes. */
        manager_state_notify_job(j);
}

static void job_uninstall(Job *j) {
        if (!j || !j->installed)
                return;

        if (j->unit && j->unit->job == j)
                j->unit->job = NULL;

        job_unlink_run_queue(j);
        j->installed = false;

        /* Defensive guard rather than an assert: job_uninstall() is already
         * gated on !j->installed above so double-decrement cannot happen in
         * practice, but a zero-initialized manager in a unit test should not
         * be able to underflow this. */
        if (j->manager->n_jobs > 0)
                j->manager->n_jobs--;
}

Job *job_free(Job *j) {
        if (!j)
                return NULL;

        /* An installed job belongs to the manager, not to whoever is freeing.
         * Uninstall first rather than leaving unit->job dangling -- this is the
         * invariant that makes transaction ownership unambiguous. */
        if (j->installed)
                job_uninstall(j);

        free(j);
        return NULL;
}

int job_run(Job *j) {
        Unit *u;
        int r;

        if (!j)
                return -EINVAL;

        if (j->state != JOB_WAITING)
                return -EAGAIN;

        if (!job_is_runnable(j))
                return -EAGAIN;

        /* Only the run-queue dispatcher gets here (66aa6f7fbb). */
        job_unlink_run_queue(j);

        j->state = JOB_RUNNING;
        u = j->unit;

        switch (j->type) {
        case JOB_START:
                r = unit_start(u);
                break;

        case JOB_STOP:
        case JOB_RESTART:
                /*
                 * A restart is a stop until job_finish_full() converts it.
                 * v30 peeked at the unit's state here and rewrote the job into
                 * a start on the spot, which skipped the runnability check
                 * above and silently lost the ordering (dd17d38879).
                 */
                r = unit_stop(u);
                break;

        default:
                r = -EINVAL;
                break;
        }

        /*
         * The unit may have reached its target state synchronously -- a Target
         * always does -- in which case unit_notify() already finished this job
         * and freed it. Ask the unit, not the job: `j` may be dangling, but
         * comparing the pointer is fine and u is certainly alive.
         */
        if (u->job != j)
                return 0;

        /*
         * An unmet start condition (unit.c). The unit is still
         * inactive, so the redundancy check below would not fire and nothing
         * called unit_notify() -- without this the job would sit in
         * JOB_RUNNING forever with everything ordered after it blocked.
         */
        if (r == -EALREADY) {
                job_finish_full(j, JOB_DONE, true);
                return 0;
        }

        /* Not now, e.g. a start while the service is still stopping: wait,
         * and unit_notify() re-queues the job on the unit's next state
         * change (v30 job_run_and_invalidate()). */
        if (r == -EAGAIN) {
                j->state = JOB_WAITING;
                return 0;
        }

        if (r < 0) {
                job_finish_full(j, JOB_FAILED, true);
                return r;
        }

        /*
         * The unit was already in the state the job wanted, so unit_start() /
         * unit_stop() was a no-op: no state changed, so nothing called
         * unit_notify(), so nothing above finished this job and it would have
         * sat in JOB_RUNNING forever with everything waiting on it waiting
         * forever too.
         *
         * transaction_drop_redundant() cannot have caught this, because it
         * exempts the anchor job, which is what a direct request produces:
         * `picoctl start` on an already-active unit and `picoctl stop` on an
         * already-dead one are both this case.
         */
        /*
         * A restart is asked about its STOP half, not about itself.
         * job_run() dispatched it through unit_stop() above, and
         * job_type_is_redundant() answers false for JOB_RESTART
         * unconditionally and correctly -- a restart is never redundant as a
         * whole. Testing the whole type here left `restart` on an
         * already-inactive or failed unit hanging in exactly the way the two
         * cases above did, because unit_stop() on a dead unit is a silent
         * no-op. Finishing the stop half as JOB_DONE is what
         * job_finish_full()'s conversion block then turns into the start.
         */
        if (job_type_is_redundant(j->type == JOB_RESTART ? JOB_STOP : j->type, unit_active_state(u)))
                job_finish_full(j, JOB_DONE, true);

        return 0;
}

/* Fail the start job of every unit that hard-requires `failed`, directly or
 * through a chain of Requires= (v30 job_finish_and_invalidate() recurses per
 * requirer). A worklist rather than recursion, since this runs in PID 1. */
static void job_propagate_failure(Manager *m, Unit *failed, JobResult result) {
        Unit **work;
        size_t n_work = 0;
        size_t i;

        /* Each unit is pushed at most once: pushing it finishes its only job. */
        work = malloc((m->n_units + 1) * sizeof(Unit *));
        if (!work) {
                pico_log(PICO_LOG_ERR, "%s: out of memory propagating its failure", failed->id);
                return;
        }

        work[n_work++] = failed;

        while (n_work > 0) {
                Unit *f = work[--n_work];

                for (i = 0; i < m->n_units; i++) {
                        Unit *w = m->units[i];

                        if (w == f || !w->job || w->job->type != JOB_START)
                                continue;

                        if (!unit_has_dependency(w, UNIT_REQUIRES, f))
                                continue;

                        pico_log(PICO_LOG_WARNING,
                                 "%s: required unit %s failed, failing its job too",
                                 w->id,
                                 f->id);
                        job_finish_full(w->job, result, false);
                        work[n_work++] = w;
                }
        }

        free(work);
}

int job_finish_full(Job *j, JobResult result, bool recursive) {
        JobType type;
        Manager *m;
        Unit *u;
        size_t i;

        if (!j)
                return -EINVAL;

        u = j->unit;
        m = j->manager;
        type = j->type;

        j->result = result;

        /*
         * A completed restart is only half done: the unit is now down, and the
         * same job becomes the start. Converting it here rather than in
         * job_run() is what keeps the ordering intact (dd17d38879), and
         * falling through to the neighbour wakeup below rather than returning
         * is what keeps everything ordered around this unit from waiting
         * forever (57981b9812).
         */
        if (j->type == JOB_RESTART && result == JOB_DONE) {
                pico_log(PICO_LOG_DEBUG, "%s: restart stopped the unit, now starting it", u->id);

                j->type = JOB_START;
                j->state = JOB_WAITING;
                j->result = _JOB_RESULT_INVALID;
                job_add_to_run_queue(j);

                goto finish;
        }

        if (result != JOB_DONE)
                pico_log(PICO_LOG_WARNING, "%s: job finished, result=%s", u->id, job_result_to_string(result));
        else
                pico_log(PICO_LOG_DEBUG, "%s: job finished, result=done", u->id);

        /*
         * The console's own progress line, systemd's "[  OK  ] Started foo."
         * and its less happy relatives. The log record above stays exactly
         * as it was: upstream emits both too, and they are read by different
         * people at different times (see status.h).
         *
         * One line (occasionally two) per JobType x JobResult combination
         * upstream's job_emit_done_message() and job_done_messages[]
         * (src/core/job.c) actually send to the console; nothing for any
         * other combination, which is what upstream does for JOB_CANCELED
         * (no word in that table) and is also all there is to do for a
         * JobResult this project's smaller enum has no counterpart for
         * (upstream's JOB_SKIPPED/JOB_COLLECTED/JOB_INVALID/...). A restart
         * reaches this function twice, but its first pass was converted into
         * a start above and left through `finish`, so only the second pass
         * -- JOB_START or, if the stop half itself failed, JOB_STOP's table
         * (upstream shares one table between the two; see below) -- ever
         * gets here.
         */
        if (j->type == JOB_START) {
                const char *name = u->description ? u->description : u->id;

                switch (result) {
                case JOB_DONE:
                        /*
                         * A unit skipped by an unmet condition never started,
                         * so it gets no line at all -- unit.c already logged
                         * which condition and why.
                         *
                         * The verb otherwise follows the unit type, the way
                         * upstream's per-type finished_start_job[JOB_DONE]
                         * formats do: "Reached target %s." (src/core/target.c),
                         * "Listening on %s." (src/core/socket.c), and the
                         * generic "Started %s." (src/core/job.c) for the rest.
                         */
                        if (u->condition_result) {
                                const char *verb = u->type == UNIT_TARGET ? "Reached target" :
                                                u->type == UNIT_SOCKET    ? "Listening on" :
                                                                            "Started";

                                status_printf(STATUS_WORD_OK, STATUS_COLOR_OK, "%s %s.", verb, name);
                        }
                        break;

                case JOB_FAILED:
                        status_printf(STATUS_WORD_FAILED, STATUS_COLOR_FAILED, "Failed to start %s.", name);

                        /*
                         * The follow-up hint, upstream's job_emit_done_message()
                         * again: plain text, no bracket word, and only for this
                         * one combination (JOB_START + JOB_FAILED) -- upstream's
                         * own `if (t == JOB_START && result == JOB_FAILED)`
                         * guard, not a general "every failure gets a hint" rule.
                         * The name in it is always the unit id, never
                         * Description=, matching upstream's use of u->id rather
                         * than ident there. The tool is named systemctl, as upstream
                         * prints it: picoctl is installed under that name here.
                         * Upstream shell-quotes the id for its shell hint;
                         * unit ids need no quoting.
                         */
                        status_printf(NULL, NULL, "See 'systemctl status %s' for details.", u->id);
                        break;

                case JOB_TIMEOUT:
                        status_printf(STATUS_WORD_TIMEOUT, STATUS_COLOR_TIMEOUT, "Timed out starting %s.", name);
                        break;

                case JOB_DEPENDENCY:
                        status_printf(STATUS_WORD_DEPENDENCY,
                                      STATUS_COLOR_DEPENDENCY,
                                      "Dependency failed for %s.",
                                      name);
                        break;

                default:
                        /* JOB_CANCELED: upstream prints nothing for it either. */
                        break;
                }
        } else if (j->type == JOB_STOP || j->type == JOB_RESTART) {
                /*
                 * Upstream's generic_finished_stop_job[] (src/core/job.c) is
                 * shared between JOB_STOP and JOB_RESTART -- `case JOB_STOP:
                 * case JOB_RESTART: return generic_finished_stop_job;` -- and
                 * only ever reached here for JOB_RESTART when its stop half
                 * itself failed, since a successful one was converted into a
                 * start above before reaching this point.
                 */
                const char *name = u->description ? u->description : u->id;

                switch (result) {
                case JOB_DONE:
                        status_printf(STATUS_WORD_OK, STATUS_COLOR_OK, "Stopped %s.", name);
                        break;

                case JOB_FAILED:
                        /* Upstream's actual string, not the shorter "Failed to
                         * stop" a START failure gets -- the job table
                         * (job_done_message_format()) spells these two
                         * differently on purpose. */
                        status_printf(STATUS_WORD_FAILED, STATUS_COLOR_FAILED, "Stopped %s with error.", name);
                        break;

                default:
                        break;
                }
        }

        /* The default target's start job ending, either way, is when the boot
         * has settled: everything it pulled in has been loaded and tried, so
         * the degradation count is final. */
        if (j->type == JOB_START && m->default_target && unit_has_name(u, m->default_target))
                manager_log_degradation_summary(m);

        /*
         * Resolve any deferred picoctl reply BEFORE the job is freed -- this
         * is the only point at which a job result becomes final, and it is
         * what makes `picoctl start`'s exit code the real job result rather
         * than a confirmation that it was enqueued. The RESTART conversion
         * above does not reach here: a restart that has only
         * stopped the unit is not finished, and replying there would report
         * success halfway through.
         */
        manager_ctrl_notify_job_finished(j, result);

        job_uninstall(j);
        job_free(j);

        /* j is gone; republish from the unit so Job= clears. */
        manager_state_notify_unit(u);

        /* A paired socket may be waiting on this job to re-arm. */
        socket_notify_service_job_finished(u);

        /*
         * Propagation is gated on `recursive` so a job completing inside
         * transaction activation cannot re-enter code that is still iterating
         * the transaction (563ba9ea6e, 1abc85b8d0). Only a failed start
         * means a requirement is missing (v30 job_finish_and_invalidate());
         * a restart that failed in its stop half is not one.
         *
         * JOB_DEPENDENCY, not this job's own `result`: upstream's job.h is
         * explicit that JOB_DEPENDENCY means "a required dependency job did
         * not result in JOB_DONE", which is what every job this reaches
         * is: `u` itself already got its own real result (JOB_FAILED,
         * JOB_TIMEOUT, ...), so passing `result` through would give a
         * dependent's job a result that was never its own.
         */
        if (result != JOB_DONE && recursive && type == JOB_START)
                job_propagate_failure(m, u, JOB_DEPENDENCY);

finish:
        /*
         * Whatever was blocked on this unit's ordering may now be runnable.
         * Re-queueing is enough; job_run() re-checks runnability itself.
         */
        for (i = 0; i < u->n_dependencies[UNIT_BEFORE]; i++)
                if (u->dependencies[UNIT_BEFORE][i]->job)
                        job_add_to_run_queue(u->dependencies[UNIT_BEFORE][i]->job);

        for (i = 0; i < u->n_dependencies[UNIT_AFTER]; i++)
                if (u->dependencies[UNIT_AFTER][i]->job)
                        job_add_to_run_queue(u->dependencies[UNIT_AFTER][i]->job);

        return 0;
}

int job_finish(Job *j, JobResult result) {
        return job_finish_full(j, result, true);
}

/* --- string tables --- */

static const char * const job_type_table[_JOB_TYPE_MAX] = {
        [JOB_START] = "start",
        [JOB_STOP] = "stop",
        [JOB_RESTART] = "restart",
};

const char *job_type_to_string(JobType t) {
        if (t < 0 || t >= _JOB_TYPE_MAX)
                return "invalid";

        return job_type_table[t];
}

static const char * const job_state_table[_JOB_STATE_MAX] = {
        [JOB_WAITING] = "waiting",
        [JOB_RUNNING] = "running",
};

const char *job_state_to_string(JobState s) {
        if (s < 0 || s >= _JOB_STATE_MAX)
                return "invalid";

        return job_state_table[s];
}

static const char * const job_result_table[_JOB_RESULT_MAX] = {
        [JOB_DONE] = "done",       [JOB_FAILED] = "failed",         [JOB_CANCELED] = "canceled",
        [JOB_TIMEOUT] = "timeout", [JOB_DEPENDENCY] = "dependency",
};

const char *job_result_to_string(JobResult r) {
        if (r < 0 || r >= _JOB_RESULT_MAX)
                return "invalid";

        return job_result_table[r];
}

/* --- transactions --- */

int transaction_new(Manager *m, Transaction **ret) {
        Transaction *tx;

        if (!m || !ret)
                return -EINVAL;

        tx = calloc(1, sizeof(Transaction));
        if (!tx)
                return -ENOMEM;

        tx->manager = m;

        *ret = tx;
        return 0;
}

Transaction *transaction_free(Transaction *tx) {
        size_t i;

        if (!tx)
                return NULL;

        /*
         * Free exactly the jobs the transaction still owns. An installed job
         * was transferred to the manager by transaction_activate() and is not
         * ours to touch; an uninstalled one would otherwise leak on every
         * failed activation. See the ownership note in job.h.
         */
        for (i = 0; i < tx->n_jobs; i++)
                if (tx->jobs[i] && !tx->jobs[i]->installed)
                        job_free(tx->jobs[i]);

        free(tx->jobs);
        free(tx);
        return NULL;
}

size_t transaction_n_jobs(Transaction *tx) {
        return tx ? tx->n_jobs : 0;
}

static Job *transaction_find_job(Transaction *tx, Unit *u) {
        size_t i;

        for (i = 0; i < tx->n_jobs; i++)
                if (tx->jobs[i] && tx->jobs[i]->unit == u)
                        return tx->jobs[i];

        return NULL;
}

static int transaction_attach(Transaction *tx, Job *j) {
        Job **jobs;

        jobs = realloc(tx->jobs, (tx->n_jobs + 1) * sizeof(Job *));
        if (!jobs)
                return -ENOMEM;

        tx->jobs = jobs;
        tx->jobs[tx->n_jobs++] = j;

        return 0;
}

static void transaction_detach(Transaction *tx, Job *j) {
        size_t i;

        for (i = 0; i < tx->n_jobs; i++)
                if (tx->jobs[i] == j) {
                        memmove(&tx->jobs[i], &tx->jobs[i + 1], (tx->n_jobs - i - 1) * sizeof(Job *));
                        tx->n_jobs--;
                        return;
                }
}

static int transaction_add_job_full(Transaction *tx, JobType type, Unit *u, bool with_dependencies, bool matters);

/* Pull in u's Requires=/Wants= as start jobs. Requires= matters to the anchor,
 * Wants= does not -- that single distinction is the whole of the
 * hard-versus-soft dependency semantics in this model. */
static int transaction_add_start_deps(Transaction *tx, Unit *u) {
        size_t i;
        int r;

        for (i = 0; i < u->n_dependencies[UNIT_REQUIRES]; i++) {
                r = transaction_add_job_full(tx, JOB_START, u->dependencies[UNIT_REQUIRES][i], true, true);
                if (r < 0) {
                        /*
                         * A hard requirement that could not be added means this
                         * job must not survive either, or the transaction
                         * activates with its requirement missing (89e9df12b3).
                         */
                        Job *self = transaction_find_job(tx, u);

                        pico_log(PICO_LOG_WARNING,
                                 "%s: required unit %s could not be added: %s",
                                 u->id,
                                 u->dependencies[UNIT_REQUIRES][i]->id,
                                 strerror(-r));

                        if (self && !self->installed) {
                                transaction_detach(tx, self);
                                job_free(self);
                        }
                        return r;
                }
        }

        for (i = 0; i < u->n_dependencies[UNIT_WANTS]; i++) {
                r = transaction_add_job_full(tx, JOB_START, u->dependencies[UNIT_WANTS][i], true, false);
                if (r < 0)
                        /* Soft by definition: log and carry on. */
                        pico_log(PICO_LOG_DEBUG,
                                 "%s: wanted unit %s could not be added: %s",
                                 u->id,
                                 u->dependencies[UNIT_WANTS][i]->id,
                                 strerror(-r));
        }

        return 0;
}

/* Stopping a unit must stop whatever hard-requires it. */
static int transaction_add_stop_deps(Transaction *tx, Unit *u) {
        Manager *m = tx->manager;
        size_t i;

        for (i = 0; i < m->n_units; i++) {
                Unit *w = m->units[i];

                if (w == u)
                        continue;

                if (unit_has_dependency(w, UNIT_REQUIRES, u)) {
                        int r = transaction_add_job_full(tx, JOB_STOP, w, true, false);

                        if (r < 0)
                                pico_log(PICO_LOG_DEBUG, "%s: could not queue stop for %s", u->id, w->id);
                }
        }

        return 0;
}

/*
 * Starting u stops whatever it conflicts with, as upstream's transaction
 * (transaction.c, the PULL_IN_STOP / PULL_IN_STOP_IGNORED atoms): a
 * Conflicts= peer's stop matters to the anchor, a ConflictedBy= peer's does
 * not and a failure there is only logged. No ordering is implied; with an
 * After=/Before= edge between the two, job_compare() already runs the stop
 * first.
 *
 * A peer this same transaction is starting is turned into a stop in place
 * when that start does not matter (a Wants= pull-in). When it does matter,
 * upstream's merge rule decides: both matter, the transaction fails; only
 * the start matters, the stop is the job that gets dropped. The anchor
 * itself always matters, so it is never rewritten. Upstream
 * would then GC the start jobs the peer had already pulled in; pico has no
 * job GC (step 5), so those stay and start on their own, which is
 * harmless. Termination: the jobs added here are STOPs, and a STOP walks only
 * transaction_add_stop_deps(), never conflicts, so mutual Conflicts= ends
 * after one hop.
 */
static int transaction_add_conflict_deps(Transaction *tx, Unit *u) {
        static const UnitDependency deps[] = { UNIT_CONFLICTS, UNIT_CONFLICTED_BY };
        size_t d, i;
        int r;

        for (d = 0; d < sizeof(deps) / sizeof(deps[0]); d++) {
                bool matters = deps[d] == UNIT_CONFLICTS;

                for (i = 0; i < u->n_dependencies[deps[d]]; i++) {
                        Unit *other = u->dependencies[deps[d]][i];
                        Job *existing = transaction_find_job(tx, other);

                        if (existing && (existing->type == JOB_START || existing->type == JOB_RESTART)) {
                                if (existing == tx->anchor_job || existing->matters_to_anchor) {
                                        pico_log(matters ? PICO_LOG_ERR : PICO_LOG_DEBUG,
                                                 "%s conflicts with %s, which this transaction also starts",
                                                 u->id,
                                                 other->id);
                                        if (matters)
                                                return -EDEADLK;
                                        continue;
                                }

                                pico_log(PICO_LOG_DEBUG,
                                         "%s: conflicts with %s, turning its %s job into a stop",
                                         u->id,
                                         other->id,
                                         job_type_to_string(existing->type));
                                existing->type = JOB_STOP;
                                if (matters)
                                        existing->matters_to_anchor = true;
                                continue;
                        }

                        r = transaction_add_job_full(tx, JOB_STOP, other, true, matters);
                        if (r < 0) {
                                if (matters)
                                        return r;
                                pico_log(PICO_LOG_DEBUG,
                                         "%s: could not queue stop for conflicting %s: %s",
                                         u->id,
                                         other->id,
                                         strerror(-r));
                        }
                }
        }

        return 0;
}

static int transaction_add_job_full(Transaction *tx, JobType type, Unit *u, bool with_dependencies, bool matters) {
        bool is_anchor;
        Job *existing;
        Job *j;
        int r;

        if (!tx || !u)
                return -EINVAL;

        if (type < 0 || type >= _JOB_TYPE_MAX)
                return -EINVAL;

        is_anchor = tx->n_jobs == 0;

        /*
         * Deduplicate. A diamond -- A wants B and C, both of which want D --
         * must queue exactly one job for D, and a second request for the same
         * unit merges into the existing job rather than creating a rival.
         */
        existing = transaction_find_job(tx, u);
        if (existing) {
                JobType merged;

                if (job_type_is_conflicting(existing->type, type)) {
                        pico_log(PICO_LOG_ERR,
                                 "%s: cannot %s and %s in one transaction",
                                 u->id,
                                 job_type_to_string(existing->type),
                                 job_type_to_string(type));
                        return -EDEADLK;
                }

                merged = job_type_lookup_merge(existing->type, type);
                existing->type = merged;

                if (matters)
                        existing->matters_to_anchor = true;

                /* already walked from here if it was added with dependencies */
                if (!job_type_is_superset(existing->type, type))
                        return 0;

                return 0;
        }

        r = job_new(tx->manager, type, u, &j);
        if (r < 0)
                return r;

        j->matters_to_anchor = matters;

        r = transaction_attach(tx, j);
        if (r < 0) {
                job_free(j);
                return r;
        }

        if (is_anchor) {
                /* The request itself. Never garbage-collected, never chosen as
                 * a cycle-breaking victim (38809d9dfe). */
                tx->anchor_job = j;
                j->matters_to_anchor = true;
        }

        if (!with_dependencies)
                return 0;

        /*
         * A restart is a stop first and a start after, so it pulls in BOTH
         * dependency sets. v30 only walked the start side for JOB_START, so
         * `systemctl restart foo` did not start foo's requirements even though
         * `systemctl start foo` did (6530407524).
         */
        if (type == JOB_START || type == JOB_RESTART) {
                /*
                 * Conflicts first: a later Wants= start of a unit stopped
                 * here then hits the merge conflict above and is soft-dropped,
                 * a later Requires= start of it fails hard -- both right. On a
                 * failure this job leaves the transaction too, mirroring the
                 * Requires= self-removal in transaction_add_start_deps(): a
                 * Wants=-pulled unit whose conflict could not be resolved must
                 * not start alongside the unit it conflicts with. A stop
                 * already queued for an earlier peer of the same unit stays;
                 * that needs two Conflicts= targets of one unit both being
                 * started by the same transaction, and is only a stop.
                 */
                r = transaction_add_conflict_deps(tx, u);
                if (r < 0) {
                        if (j != tx->anchor_job && !j->installed) {
                                transaction_detach(tx, j);
                                job_free(j);
                        }
                        return r;
                }

                r = transaction_add_start_deps(tx, u);
                if (r < 0)
                        return r;
        }

        if (type == JOB_STOP || type == JOB_RESTART) {
                r = transaction_add_stop_deps(tx, u);
                if (r < 0)
                        return r;
        }

        return 0;
}

int transaction_add_job(Transaction *tx, JobType type, Unit *u, bool with_dependencies) {
        return transaction_add_job_full(tx, type, u, with_dependencies, true);
}

/* --- step 3: drop jobs that would do nothing --- */

static void transaction_drop_redundant(Transaction *tx) {
        size_t i = 0;

        while (i < tx->n_jobs) {
                Job *j = tx->jobs[i];

                /* Not redundant while a conflicting job is installed: a unit
                 * that is active now but has a stop queued is about to go
                 * down (v30 transaction_drop_redundant()). */
                if (j != tx->anchor_job && job_type_is_redundant(j->type, unit_active_state(j->unit)) &&
                    !(j->unit->job && job_type_is_conflicting(j->type, j->unit->job->type))) {
                        pico_log(PICO_LOG_DEBUG,
                                 "%s: %s job is redundant, dropping",
                                 j->unit->id,
                                 job_type_to_string(j->type));
                        transaction_detach(tx, j);
                        job_free(j);
                        continue; /* index now points at the next entry */
                }

                i++;
        }
}

/* --- step 4: ordering cycles --- */

/*
 * DFS over execution order, not declared order. `generation` marks the current
 * sweep and `marker` is the backtrack pointer, so a detected cycle can be
 * walked to pick a victim. Returns 0, -EAGAIN when a cycle was broken (the
 * caller retries), or -ELOOP when it could not be.
 */
static int transaction_verify_order_one(Transaction *tx, Job *j, Job *from, unsigned generation) {
        UnitDependency directions[2] = { UNIT_BEFORE, UNIT_AFTER };
        size_t d;

        /*
         * Seen this sweep and already fully explored: not a cycle, just a
         * diamond or a second root reaching the same node. `marker` is what
         * distinguishes the two -- it is non-NULL only while the node is on
         * the current DFS stack, and cleared on the way back out. Testing
         * generation alone reports a false cycle on any graph where two paths
         * meet, which is most real boot graphs.
         */
        if (j->generation == generation && !j->marker)
                return 0;

        if (j->generation == generation) {
                Job *k;
                Job *victim = NULL;

                /* Still on this sweep's stack: `from` closed a real cycle. */
                pico_log(PICO_LOG_ERR, "found ordering cycle involving %s", j->unit->id);

                /* Walk back along the markers looking for something we may
                 * legitimately sacrifice. */
                for (k = from; k; k = ((k->marker == k) ? NULL : k->marker)) {
                        pico_log(PICO_LOG_ERR, "  cycle: %s/%s", k->unit->id, job_type_to_string(k->type));

                        /*
                         * The victim must be in THIS transaction, or deleting
                         * it is a no-op and the retry loop spins forever
                         * (375ae4aa4d). And it must not matter to the anchor,
                         * or breaking the cycle defeats the request.
                         */
                        if (!victim && !k->matters_to_anchor && transaction_find_job(tx, k->unit) == k)
                                victim = k;

                        if (k == j)
                                break;
                }

                if (victim) {
                        pico_log(PICO_LOG_WARNING,
                                 "breaking ordering cycle by dropping %s/%s",
                                 victim->unit->id,
                                 job_type_to_string(victim->type));
                        transaction_detach(tx, victim);
                        job_free(victim);
                        return -EAGAIN;
                }

                pico_log(PICO_LOG_ERR, "ordering cycle is unbreakable, every job in it is required");
                return -ELOOP;
        }

        j->generation = generation;
        j->marker = from ? from : j;

        for (d = 0; d < 2; d++) {
                UnitDependency dep = directions[d];
                size_t i;

                for (i = 0; i < j->unit->n_dependencies[dep]; i++) {
                        Unit *other = j->unit->dependencies[dep][i];
                        Job *o = transaction_find_job(tx, other);
                        int r;

                        if (!o)
                                o = other->job; /* an already-installed job counts too */
                        if (!o)
                                continue;

                        /*
                         * Only follow edges that are genuinely "j before o" in
                         * EXECUTION order. v30 walked Before= unconditionally
                         * and so reported cycles on graphs that would have run
                         * fine (dfd79eca55).
                         */
                        if (job_compare(j, o, dep) >= 0)
                                continue;

                        r = transaction_verify_order_one(tx, o, j, generation);
                        if (r < 0)
                                return r;
                }
        }

        j->marker = NULL;
        return 0;
}

static int transaction_verify_order(Transaction *tx, unsigned *generation) {
        size_t i;
        int r;

        /*
         * Reset every installed job's generation before the sweep. A stale
         * marker left from an earlier transaction reads as "already visited,
         * loop-free", and a cycle formed over installed jobs then goes
         * undetected and deadlocks (4e7bd268ae).
         */
        for (i = 0; i < tx->manager->n_units; i++)
                if (tx->manager->units[i]->job) {
                        tx->manager->units[i]->job->generation = 0;
                        tx->manager->units[i]->job->marker = NULL;
                }

        for (i = 0; i < tx->n_jobs; i++) {
                tx->jobs[i]->generation = 0;
                tx->jobs[i]->marker = NULL;
        }

        (*generation)++;

        for (i = 0; i < tx->n_jobs; i++) {
                r = transaction_verify_order_one(tx, tx->jobs[i], NULL, *generation);
                if (r < 0)
                        return r;
        }

        return 0;
}

/* --- step 10: apply --- */

/*
 * Install in an order consistent with the ordering edges: Kahn's algorithm
 * over the transaction's jobs, breaking ties by unit id so the result is
 * reproducible boot to boot. Upstream measured real boot-time jitter from
 * leaving it to hash iteration order (da8e178296).
 */
static int transaction_apply(Transaction *tx) {
        size_t remaining = tx->n_jobs;
        bool *done;
        size_t i;

        if (tx->n_jobs == 0)
                return 0;

        done = calloc(tx->n_jobs, sizeof(bool));
        if (!done)
                return -ENOMEM;

        while (remaining > 0) {
                size_t pick = tx->n_jobs;
                bool progress = false;

                for (i = 0; i < tx->n_jobs; i++) {
                        Job *j = tx->jobs[i];
                        bool blocked = false;
                        size_t k;

                        if (done[i])
                                continue;

                        /* blocked while any not-yet-placed job must run first */
                        for (k = 0; k < tx->n_jobs && !blocked; k++) {
                                Job *o = tx->jobs[k];

                                if (done[k] || o == j)
                                        continue;

                                if (unit_has_dependency(j->unit, UNIT_AFTER, o->unit) &&
                                    job_compare(j, o, UNIT_AFTER) > 0)
                                        blocked = true;
                                else if (unit_has_dependency(j->unit, UNIT_BEFORE, o->unit) &&
                                         job_compare(j, o, UNIT_BEFORE) > 0)
                                        blocked = true;
                        }

                        if (blocked)
                                continue;

                        /* stable tie-break, so the order is reproducible */
                        if (pick == tx->n_jobs || strcmp(j->unit->id, tx->jobs[pick]->unit->id) < 0)
                                pick = i;

                        progress = true;
                }

                if (!progress) {
                        /* verify_order() should have caught this already */
                        free(done);
                        return -ELOOP;
                }

                job_install(tx->jobs[pick]);
                done[pick] = true;
                remaining--;
        }

        free(done);
        return 0;
}

int transaction_activate(Transaction *tx) {
        static unsigned generation = 0;
        unsigned attempts = 0;
        int r;

        if (!tx)
                return -EINVAL;

        if (tx->n_jobs == 0)
                return 0;

        /*
         * v30's ten-step pipeline, preserved including the numbering. Steps
         * that cannot do anything in this model are kept as no-ops with the
         * reason, rather than dropped -- so a later reader can tell "not
         * applicable here" from "forgotten".
         */

        /* 1. Find the jobs that matter to the anchor.
         *    Done incrementally: matters_to_anchor is propagated along
         *    Requires= at add time, since there is only ever one anchor. */

        /* 2. Minimise impact -- done at add time instead: the one source of
         *    an unmergeable start/stop pair for one unit is Conflicts=, and
         *    transaction_add_conflict_deps() resolves each pair as it is
         *    created (rewrite the non-mattering start, or fail when both
         *    matter), so none survives to this point. */

        /* 3. Drop redundant jobs. */
        transaction_drop_redundant(tx);

        /* 4. Verify ordering, breaking sacrificeable cycles and retrying.
         *    Bounded: an unbounded retry here is precisely how upstream
         *    livelocked (375ae4aa4d). */
        for (;;) {
                r = transaction_verify_order(tx, &generation);
                if (r == 0)
                        break;

                if (r != -EAGAIN)
                        return r;

                if (++attempts > tx->n_jobs + 1) {
                        pico_log(PICO_LOG_ERR, "gave up breaking ordering cycles after %u attempts", attempts);
                        return -ELOOP;
                }

                /* 5. Collect garbage -- not implemented. The one way to
                 *    orphan a job here is a Conflicts= rewrite of a start
                 *    into a stop, leaving the start jobs it pulled in; they
                 *    start on their own, which is harmless. */
        }

        /* 6-7. Merge jobs / collect garbage again -- N/A: merging happens at
         *      add time in transaction_add_job_full(), because dedup is keyed
         *      on the unit and there is never a second job to merge later. */

        /* 8. Drop redundant again, now that cycle breaking may have changed
         *    what is reachable. */
        transaction_drop_redundant(tx);

        /* 9. Destructiveness check -- N/A: needs job modes (JOB_FAIL etc.),
         *    which transaction_activate() takes no argument for. */

        /* 10. Apply. */
        return transaction_apply(tx);
}
