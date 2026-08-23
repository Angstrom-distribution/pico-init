/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Manager lifecycle, search paths, the unit table and the load queue. The
 * epoll loop lives in manager-loop.c, the boot sequence in manager-startup.c,
 * orderly shutdown in manager-shutdown.c.
 */

#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "manager-ctrl.h"
#include "manager-state.h"
#include "manager.h"
#include "service.h"

static const char * const default_unit_path[] = {
        PICO_UNIT_DIR,
        PICO_PACKAGED_UNIT_DIR,
        NULL,
};

static const char * const default_preset_path[] = {
        PICO_PRESET_DIR,
        PICO_PACKAGED_PRESET_DIR,
        NULL,
};

/* tag->fd must already be set; tag is registered via data.ptr, never data.fd
 * -- see the PicoEpollSource comment in util.h for why the two must not mix. */
static int manager_epoll_add(Manager *m, struct pico_epoll_tag *tag) {
        struct epoll_event ev = {
                .events = EPOLLIN,
                .data.ptr = tag,
        };

        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, tag->fd, &ev) < 0)
                return -errno;

        return 0;
}

/* Deep-copy a NULL-terminated path vector. An empty vector is legal and
 * returns a one-element array holding only the terminator. */
static char **path_copy(const char * const *src) {
        char **dst = NULL;
        size_t i;

        for (i = 0; src && src[i]; i++)
                if (pico_strv_extend(&dst, src[i]) < 0) {
                        pico_strv_free(dst);
                        return NULL;
                }

        if (!dst)
                dst = calloc(1, sizeof(char *));

        return dst;
}

static int manager_set_path(char ***slot, const char * const *path) {
        char **copy;

        copy = path_copy(path);
        if (!copy)
                return -ENOMEM;

        pico_strv_free(*slot);
        *slot = copy;

        return 0;
}

int manager_set_unit_path(Manager *m, const char * const *path) {
        if (!m)
                return -EINVAL;

        return manager_set_path(&m->unit_path, path);
}

int manager_set_preset_path(Manager *m, const char * const *path) {
        if (!m)
                return -EINVAL;

        return manager_set_path(&m->preset_path, path);
}

int manager_set_cgroup_root(Manager *m, const char *root) {
        char *copy;

        if (!m || !root)
                return -EINVAL;

        copy = pico_strdup(root);
        if (!copy)
                return -ENOMEM;

        pico_mfree(m->cgroup_root);
        m->cgroup_root = copy;

        return 0;
}

int manager_set_runtime_dir(Manager *m, const char *dir) {
        char *copy;

        if (!m || !dir)
                return -EINVAL;

        copy = pico_strdup(dir);
        if (!copy)
                return -ENOMEM;

        pico_mfree(m->runtime_dir);
        m->runtime_dir = copy;

        return 0;
}

int manager_new(Manager **ret) {
        Manager *m;
        int r;

        if (!ret)
                return -EINVAL;

        m = calloc(1, sizeof(Manager));
        if (!m)
                return -ENOMEM;

        m->next_job_id = 1;
        m->objective = MANAGER_RUNNING;
        m->epoll_fd = -1;

        /* Real init behaviour is gated on this rather than on getpid() being
         * re-checked all over the place; it also decides whether leaving the
         * loop is even a legal outcome (see main.c). */
        m->is_system = getpid() == 1;

        r = manager_set_unit_path(m, default_unit_path);
        if (r < 0)
                goto fail;

        r = manager_set_preset_path(m, default_preset_path);
        if (r < 0)
                goto fail;

        r = manager_set_cgroup_root(m, PICO_CGROUP_ROOT);
        if (r < 0)
                goto fail;

        r = manager_set_runtime_dir(m, PICO_RUNTIME_DIR);
        if (r < 0)
                goto fail;

        m->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (m->epoll_fd < 0) {
                r = -errno;
                goto fail;
        }

        r = pico_signal_new(&m->signal);
        if (r < 0)
                goto fail;

        m->signal_tag = (struct pico_epoll_tag){ .source = PICO_EPOLL_SIGNAL, .fd = pico_signal_fd(m->signal) };
        r = manager_epoll_add(m, &m->signal_tag);
        if (r < 0)
                goto fail;

        r = pico_timer_new(&m->timer);
        if (r < 0)
                goto fail;

        m->timer_tag = (struct pico_epoll_tag){ .source = PICO_EPOLL_TIMER, .fd = pico_timer_fd(m->timer) };
        r = manager_epoll_add(m, &m->timer_tag);
        if (r < 0)
                goto fail;

        *ret = m;
        return 0;

fail:
        manager_free(m);
        return r;
}

Manager *manager_free(Manager *m) {
        size_t i;

        if (!m)
                return NULL;

        /*
         * Tear the control socket down before any unit is freed: an accepted
         * connection may still hold a deferred reply keyed by a job, and
         * resolving one against a half-freed unit table would be a
         * use-after-free. The state files go with it.
         */
        manager_ctrl_done(m);
        manager_state_done(m);

        /* Jobs first: each one points at a unit and unlinks itself from the
         * run queue as it goes, so this terminates. Freeing units first would
         * leave those pointers dangling for the duration of the loop. */
        while (m->run_queue)
                job_free(m->run_queue);

        for (i = 0; i < m->n_units; i++)
                unit_free(m->units[i]);
        free(m->units);

        m->unit_path = pico_strv_free(m->unit_path);
        m->preset_path = pico_strv_free(m->preset_path);
        m->cgroup_root = pico_mfree(m->cgroup_root);
        m->runtime_dir = pico_mfree(m->runtime_dir);

        m->timer = pico_timer_free(m->timer);
        m->signal = pico_signal_free(m->signal);

        if (m->epoll_fd >= 0)
                close(m->epoll_fd);

        free(m);
        return NULL;
}

int manager_add_unit(Manager *m, Unit *u) {
        Unit **units;

        if (!m || !u)
                return -EINVAL;

        units = realloc(m->units, (m->n_units + 1) * sizeof(Unit *));
        if (!units)
                return -ENOMEM;

        m->units = units;
        m->units[m->n_units++] = u;

        return 0;
}

void manager_enqueue_load(Manager *m, Unit *u) {
        if (!m || !u || u->in_load_queue)
                return;

        u->load_queue_next = m->load_queue;
        m->load_queue = u;
        u->in_load_queue = true;
}

int manager_dispatch_load_queue(Manager *m) {
        int n = 0;

        if (!m)
                return -EINVAL;

        /*
         * A while loop over a queue that the loop body itself extends: parsing
         * a fragment resolves its Requires=/Wants=, each of which calls
         * manager_load_unit() and pushes another unit onto this same queue.
         * That is the whole point of having a queue instead of recursion.
         */
        while (m->load_queue) {
                Unit *u = m->load_queue;

                m->load_queue = u->load_queue_next;
                u->load_queue_next = NULL;
                u->in_load_queue = false;

                /* A fragment that is missing or malformed leaves the unit in
                 * UNIT_ERROR, which is recorded on the unit itself; it is not
                 * an error for the queue as a whole, so the return is ignored
                 * deliberately rather than by omission. */
                (void) unit_load(u);
                n++;
        }

        return n;
}

void manager_enqueue_cgroup_empty(Manager *m, Unit *u) {
        if (!m || !u || u->in_cgroup_empty_queue)
                return;

        u->cgroup_empty_queue_next = m->cgroup_empty_queue;
        m->cgroup_empty_queue = u;
        u->in_cgroup_empty_queue = true;
}

void manager_dequeue_cgroup_empty(Manager *m, Unit *u) {
        Unit **cur;

        if (!m || !u || !u->in_cgroup_empty_queue)
                return;

        for (cur = &m->cgroup_empty_queue; *cur; cur = &(*cur)->cgroup_empty_queue_next)
                if (*cur == u) {
                        *cur = u->cgroup_empty_queue_next;
                        break;
                }

        u->cgroup_empty_queue_next = NULL;
        u->in_cgroup_empty_queue = false;
}

int manager_dispatch_cgroup_empty_queue(Manager *m) {
        int n = 0;

        if (!m)
                return -EINVAL;

        /* The handler can start or stop units, which can queue more emptiness
         * events; the guard keeps a re-entrant drain from running underneath
         * this one, exactly as the load queue does. */
        if (m->dispatching_cgroup_empty_queue)
                return 0;

        m->dispatching_cgroup_empty_queue = true;

        while (m->cgroup_empty_queue) {
                Unit *u = m->cgroup_empty_queue;

                /* unlink before dispatching: the handler may free u */
                m->cgroup_empty_queue = u->cgroup_empty_queue_next;
                u->cgroup_empty_queue_next = NULL;
                u->in_cgroup_empty_queue = false;

                if (u->type == UNIT_SERVICE)
                        service_cgroup_empty_event(SERVICE(u));

                n++;
        }

        m->dispatching_cgroup_empty_queue = false;

        return n;
}

Unit *manager_get_unit(Manager *m, const char *id) {
        size_t i;

        if (!m || !id)
                return NULL;

        for (i = 0; i < m->n_units; i++)
                if (strcmp(m->units[i]->id, id) == 0)
                        return m->units[i];

        return NULL;
}

Unit *manager_get_unit_by_pid(Manager *m, pid_t pid) {
        size_t i;

        if (!m || pid <= 0)
                return NULL;

        for (i = 0; i < m->n_units; i++) {
                Unit *u = m->units[i];
                Service *s;

                if (u->type != UNIT_SERVICE)
                        continue;

                s = SERVICE(u);
                if (s->main_pid == pid || s->control_pid == pid)
                        return u;
        }

        return NULL;
}

int manager_load_unit(Manager *m, const char *id, Unit **ret) {
        Unit *u;
        int r;

        if (!m || !id)
                return -EINVAL;

        if (ret)
                *ret = NULL;

        if (!unit_name_is_valid(id))
                return -EINVAL;

        u = manager_get_unit(m, id);
        if (!u) {
                UnitType type = unit_type_from_name(id);

                r = unit_new(m, type, id, &u);
                if (r < 0)
                        return r;

                r = manager_add_unit(m, u);
                if (r < 0) {
                        unit_free(u);
                        return r;
                }

                manager_enqueue_load(m, u);
        }

        /*
         * Hand the caller the node before draining. A re-entrant caller gets a
         * unit still in UNIT_STUB, and that is correct: what a Requires= line
         * needs is the graph node to attach an edge to, not a parsed fragment.
         */
        if (ret)
                *ret = u;

        /*
         * Re-entrant call, i.e. a fragment's own Requires= resolving while
         * that fragment's parser is running. Enqueue and return; the outermost
         * caller's drain will reach it. Recursing here instead would blow
         * PID1's stack on a long dependency chain and would never terminate on
         * a dependency cycle.
         */
        if (m->dispatching_load_queue)
                return 0;

        m->dispatching_load_queue = true;
        r = manager_dispatch_load_queue(m);
        m->dispatching_load_queue = false;

        return r < 0 ? r : 0;
}

static int manager_load_units_one_dir(Manager *m, const char *dir) {
        struct dirent *de;
        int ret = 0;
        DIR *d;

        d = opendir(dir);
        if (!d) {
                /* A missing search directory is normal, not a failure: an
                 * image may legitimately ship no /etc/systemd/system at all. */
                if (errno == ENOENT)
                        return 0;

                return -errno;
        }

        while ((de = readdir(d))) {
                int r;

                /*
                 * One check does the whole filter: it rejects "." and "..",
                 * anything with a suffix naming no unit type (so ".wants" and
                 * ".requires" directories and drop-in ".d" dirs are skipped),
                 * and anything containing a path separator.
                 */
                if (!unit_name_is_valid(de->d_name))
                        continue;

                r = manager_load_unit(m, de->d_name, NULL);
                if (r < 0 && ret == 0)
                        ret = r; /* keep loading the rest, report the first failure */
        }

        closedir(d);
        return ret;
}

int manager_load_units(Manager *m, const char *dir) {
        int ret = 0;
        int r;

        if (!m)
                return -EINVAL;

        if (dir)
                ret = manager_load_units_one_dir(m, dir);
        else {
                size_t i;

                for (i = 0; m->unit_path && m->unit_path[i]; i++) {
                        r = manager_load_units_one_dir(m, m->unit_path[i]);
                        if (r < 0 && ret == 0)
                                ret = r;
                }
        }

        r = manager_dispatch_load_queue(m);
        if (r < 0 && ret == 0)
                ret = r;

        return ret;
}

int manager_add_job(Manager *m, JobType type, Unit *u, Job **ret) {
        Transaction *tx = NULL;
        int r;

        if (!m || !u)
                return -EINVAL;

        r = transaction_new(m, &tx);
        if (r < 0)
                return r;

        r = transaction_add_job(tx, type, u, true);
        if (r < 0) {
                tx = transaction_free(tx);
                return r;
        }

        r = transaction_activate(tx);
        tx = transaction_free(tx);
        if (r < 0)
                return r;

        if (ret)
                *ret = u->job;
        return 0;
}

int manager_dispatch_run_queue(Manager *m) {
        int n = 0;

        if (!m)
                return -EINVAL;

        /*
         * Rescan from the head after every job that runs, rather than walking
         * the list once. job_run() can finish not just this job but others --
         * a Target completes synchronously, which finishes its job, which
         * re-queues every neighbour -- so any pointer into the list taken
         * before the call may be stale afterwards. Quadratic in the worst
         * case, over a queue that is a handful of entries on a real boot.
         */
        for (;;) {
                Job *j;
                bool ran = false;

                for (j = m->run_queue; j; j = j->run_queue_next)
                        if (j->state == JOB_WAITING && job_is_runnable(j)) {
                                job_run(j);
                                n++;
                                ran = true;
                                break;
                        }

                if (!ran)
                        break;
        }

        return n;
}
