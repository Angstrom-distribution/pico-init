/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * cgroups v2 (unified hierarchy) supervision layer. One cgroup per unit at
 * /sys/fs/cgroup/system.slice/<unit>.service; cgroup.events is epoll-watchable
 * so service-exit detection needs no polling; cgroup.kill gives an atomic
 * kill-all on stop timeout.
 */

#pragma once

#include <sys/types.h>

struct pico_cgroup {
        char *path;     /* absolute path under /sys/fs/cgroup */
        int procs_fd;   /* cgroup.procs */
        int events_fd;  /* cgroup.events */
        int kill_fd;    /* cgroup.kill */
        int events_efd; /* fd registered in the manager's epoll for events changes */
};

/* Create the cgroup directory and open its control files. 0 or -errno. */
int cgroup_v2_new(const char *path, struct pico_cgroup **ret);

/* Write pid into cgroup.procs. 0 or -errno. */
int cgroup_v2_add_process(struct pico_cgroup *cg, pid_t pid);

/* Register events_efd on epoll_fd so "populated" transitions wake the loop. 0 or -errno. */
int cgroup_v2_monitor(struct pico_cgroup *cg, int epoll_fd);

/* Write "all" to cgroup.kill: atomic, race-free kill of every member. 0 or -errno. */
int cgroup_v2_kill(struct pico_cgroup *cg);

/* 1 if populated=0, 0 if still populated, -errno on error. */
int cgroup_v2_is_empty(struct pico_cgroup *cg);

/* Close fds, remove the cgroup directory, free. Returns NULL. */
struct pico_cgroup *cgroup_v2_free(struct pico_cgroup *cg);
