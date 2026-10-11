/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The state publisher. See manager-state.h for the
 * contract; this is the real body.
 *
 * Every write is tmp-file-then-rename() within <runtime_dir>/units/: rename()
 * within one directory is atomic at the filesystem level, so a reader's
 * open() either resolves to the fully-written old file or the fully-written
 * new one, never a half-written one. A fixed per-unit tmp name is safe
 * without O_EXCL/mkstemp because the manager loop is single-threaded -- only
 * one publish for a given unit is ever in flight at a time.
 *
 * Every function but manager_state_setup() returns void and fails silently
 * (logged at DEBUG) by design: an unwritable /run must cost picoctl its read
 * verbs, never the boot. manager_state_setup() itself still returns an
 * -errno so manager_startup() can log it once, at WARNING, rather than the
 * per-transition DEBUG spam every subsequent no-op write would otherwise
 * produce.
 *
 * The manager file also carries NJobs/NInstalledJobs, the two boot-progress
 * counters Manager.n_jobs/n_installed_jobs -- see manager_state_notify_manager()
 * for what they mean and who consumes them.
 */

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "job.h"
#include "manager-state.h"
#include "manager.h"
#include "service.h"
#include "target.h"
#include "unit.h"
#include "util.h"

struct pico_manager_state {
        char *units_dir;    /* <runtime_dir>/units, owned */
        char *manager_path; /* <runtime_dir>/manager, owned */
};

/*
 * Best-effort single-level mkdir: EEXIST is success. Not mkdir -p --
 * PICO_RUNTIME_DIR's parent (/run) is tmpfs mounted by mount_setup() long
 * before manager_startup() runs, matching every other PICO_* directory this
 * project creates on demand (see service_ensure_cgroup()'s system.slice).
 */
static int ensure_dir(const char *path) {
        if (mkdir(path, 0755) == 0 || errno == EEXIST)
                return 0;
        return -errno;
}

int manager_state_setup(Manager *m) {
        struct pico_manager_state *st;
        char units_dir[PATH_MAX];
        char manager_path[PATH_MAX];
        int r, n;

        if (!m || !m->runtime_dir)
                return -EINVAL;

        r = ensure_dir(m->runtime_dir);
        if (r < 0)
                return r;

        n = snprintf(units_dir, sizeof(units_dir), "%s/units", m->runtime_dir);
        if (n < 0 || (size_t) n >= sizeof(units_dir))
                return -ENAMETOOLONG;

        r = ensure_dir(units_dir);
        if (r < 0)
                return r;

        n = snprintf(manager_path, sizeof(manager_path), "%s/manager", m->runtime_dir);
        if (n < 0 || (size_t) n >= sizeof(manager_path))
                return -ENAMETOOLONG;

        st = calloc(1, sizeof(*st));
        if (!st)
                return -ENOMEM;

        st->units_dir = pico_strdup(units_dir);
        st->manager_path = pico_strdup(manager_path);
        if (!st->units_dir || !st->manager_path) {
                free(st->units_dir);
                free(st->manager_path);
                free(st);
                return -ENOMEM;
        }

        m->state = st;

        /* First publish now, rather than waiting for the first unit
         * transition: a reader polling immediately after boot deserves a
         * real NUnits= rather than ENOENT. */
        manager_state_notify_manager(m);

        return 0;
}

void manager_state_done(Manager *m) {
        struct pico_manager_state *st;
        DIR *d;

        if (!m || !m->state)
                return;

        st = m->state;

        d = opendir(st->units_dir);
        if (d) {
                struct dirent *de;

                while ((de = readdir(d))) {
                        char path[PATH_MAX];
                        int n;

                        if (de->d_name[0] == '.')
                                continue; /* ".", "..", and our own dotfile tmp names */

                        n = snprintf(path, sizeof(path), "%s/%s", st->units_dir, de->d_name);
                        if (n > 0 && (size_t) n < sizeof(path))
                                unlink(path);
                }
                closedir(d);
        }

        rmdir(st->units_dir);
        unlink(st->manager_path);

        free(st->units_dir);
        free(st->manager_path);
        free(st);
        m->state = NULL;
}

/* SubState, per unit type -- mirrors upstream's own split between the
 * generic ActiveState and a type-specific substate string. */
static const char *unit_substate(Unit *u) {
        switch (u->type) {
        case UNIT_SERVICE:
                return service_state_to_string(SERVICE(u)->state);
        case UNIT_TARGET:
                return target_state_to_string(TARGET(u)->state);
        case UNIT_SOCKET:
                /* Sockets publish only target's coarse dead/active shape, not
                 * SocketState. */
                return unit_active_state(u) == UNIT_ACTIVE ? "active" : "dead";
        default:
                return "dead";
        }
}

/*
 * ExecMainCode as service.c's own sigchld_code_to_string() renders it
 * (exited/killed/dumped), not the bare siginfo_t.si_code integer -- the raw
 * number would be meaningless in a published state file. main_exit_code is 0 before
 * the main process has ever exited, which is not a valid CLD_* value; that
 * case renders as the empty string, matching systemd's own ExecMainCode=
 * before a unit has ever run.
 */
static const char *exec_main_code_to_string(int code) {
        switch (code) {
        case CLD_EXITED:
                return "exited";
        case CLD_KILLED:
                return "killed";
        case CLD_DUMPED:
                return "dumped";
        default:
                return "";
        }
}

/*
 * UnitFileState. Real systemd's unit_file_get_state() re-derives this by
 * re-scanning symlinks on disk at query time; picoctl's read verbs deriving
 * it that way from the state file would need to duplicate unit-enable.c's
 * scan. This instead publishes the decision unit-enable.c already made at
 * boot -- u->enabled -- which is authoritative for what actually happened,
 * and distinguishes "static" (no [Install] data at all) from "disabled" (has
 * [Install] data, but no symlink/preset enabled it), matching upstream's own
 * distinction between the two.
 */
static const char *unit_file_state(Unit *u) {
        if (!u->wanted_by && !u->required_by)
                return "static";
        return u->enabled ? "enabled" : "disabled";
}

/* Each alias gets a relative symlink to the unit's own file, so reading
 * units/default.target answers for the unit it is an alias of -- what
 * `systemctl show default.target` does. Created once; EEXIST is the common
 * case on every later republish. */
static void publish_unit_aliases(Unit *u, struct pico_manager_state *st) {
        char **a;

        for (a = u->aliases; a && *a; a++) {
                char link[PATH_MAX];
                int n;

                n = snprintf(link, sizeof(link), "%s/%s", st->units_dir, *a);
                if (n < 0 || (size_t) n >= sizeof(link))
                        continue;

                if (symlink(u->id, link) < 0 && errno != EEXIST)
                        pico_log(PICO_LOG_DEBUG,
                                 "%s: could not publish alias %s: %s",
                                 u->id,
                                 *a,
                                 strerror(errno));
        }
}

/* Write u's file to a fixed tmp name under units_dir, then rename() it into
 * place. Every failure is logged at DEBUG and swallowed -- see the file
 * header for why this must never propagate. */
static void publish_unit_file(Unit *u) {
        struct pico_manager_state *st;
        char tmp[PATH_MAX];
        char final[PATH_MAX];
        char job_buf[80] = "";
        char notify_buf[192] = "";
        char *degraded;
        char delegate_buf[64];
        char kill_buf[128];
        Service *s = NULL;
        FILE *f;
        int n;

        if (!u || !u->manager || !u->manager->state || !u->id)
                return;

        st = u->manager->state;

        n = snprintf(final, sizeof(final), "%s/%s", st->units_dir, u->id);
        if (n < 0 || (size_t) n >= sizeof(final))
                return;

        n = snprintf(tmp, sizeof(tmp), "%s/.%s.tmp", st->units_dir, u->id);
        if (n < 0 || (size_t) n >= sizeof(tmp))
                return;

        f = fopen(tmp, "we");
        if (!f) {
                pico_log(PICO_LOG_DEBUG, "%s: could not write state file: %s", u->id, strerror(errno));
                return;
        }

        if (u->type == UNIT_SERVICE)
                s = SERVICE(u);

        if (u->job)
                snprintf(job_buf,
                         sizeof(job_buf),
                         "%u %s",
                         (unsigned) u->job->id,
                         job_type_to_string(u->job->type));

        /* NotifyReady=/StatusText=/StatusErrno=: sd_notify()-derived fields
         * (manager-notify.c), UNIT_SERVICE only. StatusText/StatusErrno are
         * appended only when set -- unlike the fields above, absence is
         * meaningful (no sd_notify() has arrived yet), not just a default. */
        if (s) {
                int w;

                w = snprintf(notify_buf, sizeof(notify_buf), "NotifyReady=%s\n", s->notify_ready ? "yes" : "no");
                if (w > 0 && (size_t) w < sizeof(notify_buf)) {
                        size_t off = (size_t) w;

                        if (s->status_text) {
                                w = snprintf(notify_buf + off,
                                             sizeof(notify_buf) - off,
                                             "StatusText=%s\n",
                                             s->status_text);
                                if (w > 0 && (size_t) w < sizeof(notify_buf) - off)
                                        off += (size_t) w;
                        }
                        if (s->status_errno != 0)
                                snprintf(notify_buf + off,
                                         sizeof(notify_buf) - off,
                                         "StatusErrno=%d\n",
                                         s->status_errno);
                }
        }

        /* Degraded-Directives=: the unit's degradation record (unit.h),
         * space-separated, empty when pico-init honoured every directive. */
        degraded = unit_degraded_directives_string(u);

        /* Delegate=/DelegateControllers=: systemctl show's pair; the controller
         * list is empty unless the unit named some. */
        kill_buf[0] = '\0';
        if (s)
                snprintf(kill_buf,
                         sizeof(kill_buf),
                         "KillMode=%s\nKillSignal=%d\nSendSIGKILL=%s\nSendSIGHUP=%s\n",
                         kill_mode_to_string(s->kill_mode),
                         s->kill_signal,
                         s->send_sigkill ? "yes" : "no",
                         s->send_sighup ? "yes" : "no");
        delegate_buf[0] = '\0';
        if (s && s->delegate)
                service_delegate_controllers_to_string(
                                s->delegate_controllers, delegate_buf, sizeof(delegate_buf));

        fprintf(f,
                "ActiveState=%s\n"
                "SubState=%s\n"
                "LoadState=%s\n"
                "FragmentPath=%s\n"
                "Description=%s\n"
                "UnitFileState=%s\n"
                "MainPID=%d\n"
                "Result=%s\n"
                "ExecMainCode=%s\n"
                "ExecMainStatus=%d\n"
                "NRestarts=%u\n"
                "Job=%s\n"
                "Delegate=%s\n"
                "DelegateControllers=%s\n"
                "DelegateSubgroup=%s\n"
                "%s"
                "Degraded-Directives=%s\n"
                "%s",
                unit_active_state_to_string(unit_active_state(u)),
                unit_substate(u),
                unit_load_state_to_string(u->load_state),
                u->fragment_path ? u->fragment_path : "",
                u->description ? u->description : "",
                unit_file_state(u),
                /* exec_main_pid, not the live main_pid: it stays set after
                 * the process is reaped and main_pid goes back to 0, which
                 * is what lets status still show the PID alongside
                 * ExecMainCode/Status for a unit that has since failed. */
                s ? (int) s->exec_main_pid : 0,
                s ? service_result_to_string(s->result) : "success",
                s ? exec_main_code_to_string(s->main_exit_code) : "",
                s ? s->main_exit_status : 0,
                s ? s->n_restarts : 0u,
                job_buf,
                s && s->delegate ? "yes" : "no",
                delegate_buf,
                s && s->delegate_subgroup ? s->delegate_subgroup : "",
                kill_buf,
                degraded ? degraded : "",
                notify_buf);
        pico_mfree(degraded);

        if (fclose(f) != 0) {
                pico_log(PICO_LOG_DEBUG, "%s: could not finish writing state file: %s", u->id, strerror(errno));
                unlink(tmp);
                return;
        }

        if (rename(tmp, final) < 0) {
                pico_log(PICO_LOG_DEBUG, "%s: could not publish state file: %s", u->id, strerror(errno));
                unlink(tmp);
                return;
        }

        publish_unit_aliases(u, st);
}

void manager_state_notify_unit(Unit *u) {
        if (!u || !u->manager || !u->manager->state)
                return;

        publish_unit_file(u);

        /* Keep NUnits= (and, best-effort, Objective=) fresh without a
         * dedicated hook: nothing else calls
         * manager_state_notify_manager() on a schedule, and every unit
         * transition is a frequent-enough point to refresh it from. */
        manager_state_notify_manager(u->manager);
}

void manager_state_notify_job(Job *j) {
        if (!j || !j->unit)
                return;

        /* j->unit->job is already this job (job_install() sets it before
         * calling here), so republishing the unit is exactly "add Job= to
         * its file" -- no separate job-shaped write exists. */
        manager_state_notify_unit(j->unit);
}

void manager_state_forget_unit(Unit *u) {
        struct pico_manager_state *st;
        char path[PATH_MAX];
        char **a;
        int n;

        if (!u || !u->manager || !u->manager->state || !u->id)
                return;

        st = u->manager->state;

        n = snprintf(path, sizeof(path), "%s/%s", st->units_dir, u->id);
        if (n < 0 || (size_t) n >= sizeof(path))
                return;

        unlink(path);

        for (a = u->aliases; a && *a; a++) {
                n = snprintf(path, sizeof(path), "%s/%s", st->units_dir, *a);
                if (n > 0 && (size_t) n < sizeof(path))
                        unlink(path);
        }
}

void manager_state_notify_manager(Manager *m) {
        struct pico_manager_state *st;
        char tmp[PATH_MAX];
        FILE *f;
        int n;

        if (!m || !m->state)
                return;

        st = m->state;

        n = snprintf(tmp, sizeof(tmp), "%s/.manager.tmp", m->runtime_dir);
        if (n < 0 || (size_t) n >= sizeof(tmp))
                return;

        f = fopen(tmp, "we");
        if (!f) {
                pico_log(PICO_LOG_DEBUG, "manager: could not write state file: %s", strerror(errno));
                return;
        }

        /*
         * DefaultTarget reports the actual target this boot is using,
         * which is stored by manager_startup() in m->default_target.
         * Fall back to the macro only if default_target is somehow NULL.
         *
         * NJobs/NInstalledJobs are the inputs to systemd's Manager.Progress
         * (v30 src/dbus-manager.c bus_manager_append_progress(): 1.0 minus
         * jobs/installed). PID 1 publishes the raw counters only -- the
         * percentage arithmetic lives in the consumer
         * (a separate binary), so the fraction's semantics can change
         * without touching PID 1.
         */
        fprintf(f,
                "Objective=%s\n"
                "DefaultTarget=%s\n"
                "NUnits=%zu\n"
                "NJobs=%u\n"
                "NInstalledJobs=%u\n",
                manager_objective_to_string(m->objective),
                m->default_target ? m->default_target : PICO_DEFAULT_TARGET,
                m->n_units,
                m->n_jobs,
                m->n_installed_jobs);

        if (fclose(f) != 0) {
                pico_log(PICO_LOG_DEBUG, "manager: could not finish writing state file: %s", strerror(errno));
                unlink(tmp);
                return;
        }

        if (rename(tmp, st->manager_path) < 0) {
                pico_log(PICO_LOG_DEBUG, "manager: could not publish state file: %s", strerror(errno));
                unlink(tmp);
        }
}
