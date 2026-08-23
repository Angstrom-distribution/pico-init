/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cgroups-v2.h"
#include "util.h"

static int write_all(int fd, const char *s) {
        size_t len = strlen(s);
        size_t off = 0;

        while (off < len) {
                ssize_t n = write(fd, s + off, len - off);

                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }
                off += (size_t) n;
        }

        return 0;
}

static int open_ctrl_file(const char *dir, const char *name, int flags) {
        char path[PATH_MAX];
        int fd;

        snprintf(path, sizeof(path), "%s/%s", dir, name);

        fd = open(path, flags | O_CLOEXEC);
        if (fd < 0)
                return -errno;

        return fd;
}

int cgroup_v2_new(const char *path, struct pico_cgroup **ret) {
        struct pico_cgroup *cg;
        int r;

        if (!path || !ret)
                return -EINVAL;

        /* No real cgroupfs (test/CI): mkdir fails ENOENT/EACCES/EROFS, propagate cleanly. */
        if (mkdir(path, 0755) < 0 && errno != EEXIST)
                return -errno;

        cg = calloc(1, sizeof(*cg));
        if (!cg)
                return -ENOMEM;

        /* calloc() zero-inits epoll_tag.source to PICO_EPOLL_SIGNAL (enum
         * value 0) -- set it explicitly so an un-monitored cgroup can never
         * be mistaken for one if its pointer ever ends up read as a tag. */
        cg->epoll_tag.source = PICO_EPOLL_CGROUP;
        cg->epoll_tag.fd = -1;
        cg->procs_fd = cg->events_fd = cg->kill_fd = cg->events_efd = -1;

        cg->path = pico_strdup(path);
        if (!cg->path) {
                free(cg);
                return -ENOMEM;
        }

        cg->procs_fd = open_ctrl_file(path, "cgroup.procs", O_WRONLY);
        if (cg->procs_fd < 0) {
                r = cg->procs_fd;
                goto fail;
        }

        cg->events_fd = open_ctrl_file(path, "cgroup.events", O_RDONLY);
        if (cg->events_fd < 0) {
                r = cg->events_fd;
                goto fail;
        }

        cg->kill_fd = open_ctrl_file(path, "cgroup.kill", O_WRONLY);
        if (cg->kill_fd < 0) {
                r = cg->kill_fd;
                goto fail;
        }

        *ret = cg;
        return 0;

fail:
        cgroup_v2_free(cg);
        return r;
}

int cgroup_v2_add_process(struct pico_cgroup *cg, pid_t pid) {
        char buf[32];

        if (!cg)
                return -EINVAL;

        snprintf(buf, sizeof(buf), "%lld", (long long) pid);

        return write_all(cg->procs_fd, buf);
}

int cgroup_v2_monitor(struct pico_cgroup *cg, int epoll_fd) {
        struct epoll_event ev = { 0 };

        if (!cg)
                return -EINVAL;

        cg->epoll_tag.fd = cg->events_fd;

        ev.events = EPOLLPRI;
        ev.data.ptr = &cg->epoll_tag; /* first member of *cg, so dispatch casts it straight back */

        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, cg->events_fd, &ev) < 0)
                return -errno;

        cg->events_efd = cg->events_fd;
        return 0;
}

int cgroup_v2_kill(struct pico_cgroup *cg) {
        if (!cg)
                return -EINVAL;

        return write_all(cg->kill_fd, "all");
}

int cgroup_v2_is_empty(struct pico_cgroup *cg) {
        char buf[128];
        ssize_t n;

        if (!cg)
                return -EINVAL;

        n = pread(cg->events_fd, buf, sizeof(buf) - 1, 0);
        if (n < 0)
                return -errno;

        buf[n] = '\0';

        if (strstr(buf, "populated 0"))
                return 1;
        if (strstr(buf, "populated 1"))
                return 0;

        return -EINVAL;
}

struct pico_cgroup *cgroup_v2_free(struct pico_cgroup *cg) {
        if (!cg)
                return NULL;

        if (cg->procs_fd >= 0)
                close(cg->procs_fd);
        if (cg->events_fd >= 0)
                close(cg->events_fd);
        if (cg->kill_fd >= 0)
                close(cg->kill_fd);

        if (cg->path) {
                rmdir(cg->path); /* best-effort: fails harmlessly if still populated */
                free(cg->path);
        }

        free(cg);
        return NULL;
}
