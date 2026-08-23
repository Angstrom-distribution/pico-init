/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Manager lifecycle, unit table and job dispatch. The epoll loop itself
 * lives in manager-loop.c, orderly shutdown in manager-shutdown.c.
 */

#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "manager.h"

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

int manager_new(Manager **ret) {
        if (!ret)
                return -EINVAL;

        Manager *m = calloc(1, sizeof(Manager));
        if (!m)
                return -ENOMEM;

        m->next_job_id = 1;
        m->objective = MANAGER_RUNNING;

        m->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (m->epoll_fd < 0) {
                int r = -errno;
                manager_free(m);
                return r;
        }

        int r = pico_signal_new(&m->signal);
        if (r < 0) {
                manager_free(m);
                return r;
        }

        m->signal_tag = (struct pico_epoll_tag){ .source = PICO_EPOLL_SIGNAL, .fd = pico_signal_fd(m->signal) };
        r = manager_epoll_add(m, &m->signal_tag);
        if (r < 0) {
                manager_free(m);
                return r;
        }

        r = pico_timer_new(&m->timer);
        if (r < 0) {
                manager_free(m);
                return r;
        }

        m->timer_tag = (struct pico_epoll_tag){ .source = PICO_EPOLL_TIMER, .fd = pico_timer_fd(m->timer) };
        r = manager_epoll_add(m, &m->timer_tag);
        if (r < 0) {
                manager_free(m);
                return r;
        }

        *ret = m;
        return 0;
}

Manager *manager_free(Manager *m) {
        if (!m)
                return NULL;

        for (size_t i = 0; i < m->n_units; i++)
                unit_free(m->units[i]);
        free(m->units);

        m->timer = pico_timer_free(m->timer);
        m->signal = pico_signal_free(m->signal);

        if (m->epoll_fd >= 0)
                close(m->epoll_fd);

        free(m);
        return NULL;
}

int manager_load_units(Manager *m, const char *dir) {
        if (!m)
                return -EINVAL;
        if (!dir)
                dir = PICO_UNIT_DIR;

        DIR *d = opendir(dir);
        if (!d)
                return -errno;

        static const char suffix[] = ".service";
        const size_t suffix_len = sizeof(suffix) - 1;

        int ret = 0;
        struct dirent *de;
        while ((de = readdir(d))) {
                size_t len = strlen(de->d_name);
                if (len <= suffix_len || strcmp(de->d_name + len - suffix_len, suffix) != 0)
                        continue;

                int r = manager_load_unit(m, de->d_name, NULL);
                if (r < 0 && ret == 0)
                        ret = r; /* keep loading the rest, report the first failure */
        }

        closedir(d);
        return ret;
}

Unit *manager_get_unit(Manager *m, const char *id) {
        if (!m || !id)
                return NULL;

        for (size_t i = 0; i < m->n_units; i++)
                if (strcmp(m->units[i]->id, id) == 0)
                        return m->units[i];

        return NULL;
}

int manager_load_unit(Manager *m, const char *id, Unit **ret) {
        if (!m || !id)
                return -EINVAL;

        Unit *u = manager_get_unit(m, id);
        if (u) {
                if (ret)
                        *ret = u;
                return 0;
        }

        UnitType type = unit_type_from_name(id);
        if (type == _UNIT_TYPE_INVALID)
                return -EINVAL;

        int r = unit_new(m, type, id, &u);
        if (r < 0)
                return r;

        Unit **units = realloc(m->units, (m->n_units + 1) * sizeof(Unit *));
        if (!units) {
                unit_free(u);
                return -ENOMEM;
        }
        m->units = units;
        m->units[m->n_units++] = u;

        /* fragment problems leave u in UNIT_ERROR; not fatal to the caller here */
        unit_load(u);

        if (ret)
                *ret = u;
        return 0;
}

int manager_add_job(Manager *m, JobType type, Unit *u, Job **ret) {
        if (!m || !u)
                return -EINVAL;

        Transaction *tx = NULL;
        int r = transaction_new(m, &tx);
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
        if (!m)
                return -EINVAL;

        int n = 0;
        Job *j = m->run_queue;
        while (j) {
                Job *next = j->run_queue_next; /* job_run()/job_finish() may unlink j */
                if (j->state == JOB_WAITING && job_run(j) == 0)
                        n++;
                j = next;
        }

        return n;
}
